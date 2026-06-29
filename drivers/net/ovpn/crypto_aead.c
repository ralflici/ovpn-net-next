// SPDX-License-Identifier: GPL-2.0
/*  OpenVPN data channel offload
 *
 *  Copyright (C) 2020-2025 OpenVPN, Inc.
 *
 *  Author:	James Yonan <james@openvpn.net>
 *		Antonio Quartulli <antonio@openvpn.net>
 */

#include <crypto/aead.h>
#include <linux/skbuff.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/udp.h>

#include "ovpnpriv.h"
#include "main.h"
#include "io.h"
#include "pktid.h"
#include "crypto_aead.h"
#include "crypto.h"
#include "netlink.h"
#include "peer.h"
#include "proto.h"
#include "skb.h"

#define OVPN_AEAD_DECRYPT_FAILURE_NOTIFY	BIT_ULL(35)
#define OVPN_AEAD_DECRYPT_FAILURE_LIMIT		BIT_ULL(36)

static bool
ovpn_aead_decrypt_failure_exceeded(const struct ovpn_crypto_key_slot *ks)
{
	return atomic64_read(&ks->decrypt_failures) >
	       OVPN_AEAD_DECRYPT_FAILURE_LIMIT;
}

bool ovpn_aead_decrypt_failure_record(struct ovpn_crypto_key_slot *ks)
{
	u64 failures = atomic64_inc_return(&ks->decrypt_failures);

	return failures > OVPN_AEAD_DECRYPT_FAILURE_NOTIFY &&
	       atomic_cmpxchg(&ks->decrypt_failure_notified, 0, 1) == 0;
}

static int ovpn_aead_encap_overhead(const struct ovpn_crypto_key_slot *ks)
{
	return OVPN_AEAD_DIRECT_AAD_SIZE + crypto_aead_authsize(ks->encrypt);
}

/**
 * ovpn_aead_crypto_tmp_size - compute the size of a temporary object containing
 *			       an AEAD request structure with extra space for SG
 *			       and IV.
 * @tfm: the AEAD cipher handle
 * @nents: the number of scatterlist entries
 *
 * This function calculates the size of a contiguous memory block that includes
 * the initialization vector (IV), the AEAD request, and an array of scatterlist
 * entries. For alignment considerations, the IV is placed first, followed by
 * the request, and then the scatterlist.
 * Additional alignment is applied according to the requirements of the
 * underlying structures.
 *
 * Return: the size of the temporary memory that needs to be allocated
 */
static unsigned int ovpn_aead_crypto_tmp_size(struct crypto_aead *tfm,
					      const unsigned int nents)
{
	unsigned int len = OVPN_NONCE_SIZE;

	DEBUG_NET_WARN_ON_ONCE(crypto_aead_ivsize(tfm) != OVPN_NONCE_SIZE);

	/* min size for a buffer of ivsize, aligned to alignmask */
	len += crypto_aead_alignmask(tfm) & ~(crypto_tfm_ctx_alignment() - 1);
	/* round up to the next multiple of the crypto ctx alignment */
	len = ALIGN(len, crypto_tfm_ctx_alignment());

	/* reserve space for the AEAD request */
	len += sizeof(struct aead_request) + crypto_aead_reqsize(tfm);
	/* round up to the next multiple of the scatterlist alignment */
	len = ALIGN(len, __alignof__(struct scatterlist));

	/* add enough space for the scatterlist entries */
	len += array_size(sizeof(struct scatterlist), nents);
	return len;
}

/**
 * ovpn_aead_crypto_tmp_iv - retrieve the pointer to the IV within a temporary
 *			     buffer allocated using ovpn_aead_crypto_tmp_size
 * @aead: the AEAD cipher handle
 * @tmp: a pointer to the beginning of the temporary buffer
 *
 * This function retrieves a pointer to the initialization vector (IV) in the
 * temporary buffer. If the AEAD cipher specifies an IV size, the pointer is
 * adjusted using the AEAD's alignment mask to ensure proper alignment.
 *
 * Returns: a pointer to the IV within the temporary buffer
 */
static u8 *ovpn_aead_crypto_tmp_iv(struct crypto_aead *aead, void *tmp)
{
	return likely(crypto_aead_ivsize(aead)) ?
		      PTR_ALIGN((u8 *)tmp, crypto_aead_alignmask(aead) + 1) :
		      tmp;
}

/**
 * ovpn_aead_crypto_tmp_req - retrieve the pointer to the AEAD request structure
 *			      within a temporary buffer allocated using
 *			      ovpn_aead_crypto_tmp_size
 * @aead: the AEAD cipher handle
 * @iv: a pointer to the initialization vector in the temporary buffer
 *
 * This function computes the location of the AEAD request structure that
 * immediately follows the IV in the temporary buffer and it ensures the request
 * is aligned to the crypto transform context alignment.
 *
 * Returns: a pointer to the AEAD request structure
 */
static struct aead_request *ovpn_aead_crypto_tmp_req(struct crypto_aead *aead,
						     const u8 *iv)
{
	return (void *)PTR_ALIGN(iv + crypto_aead_ivsize(aead),
				 crypto_tfm_ctx_alignment());
}

/**
 * ovpn_aead_crypto_req_sg - locate the scatterlist following the AEAD request
 *			     within a temporary buffer allocated using
 *			     ovpn_aead_crypto_tmp_size
 * @aead: the AEAD cipher handle
 * @req: a pointer to the AEAD request structure in the temporary buffer
 *
 * This function computes the starting address of the scatterlist that is
 * allocated immediately after the AEAD request structure. It aligns the pointer
 * based on the alignment requirements of the scatterlist structure.
 *
 * Returns: a pointer to the scatterlist
 */
static struct scatterlist *ovpn_aead_crypto_req_sg(struct crypto_aead *aead,
						   struct aead_request *req)
{
	return (void *)ALIGN((unsigned long)(req + 1) +
			     crypto_aead_reqsize(aead),
			     __alignof__(struct scatterlist));
}

static struct aead_request *ovpn_aead_request_alloc(struct crypto_aead *aead,
						    struct sk_buff *skb,
						    unsigned int nents,
						    unsigned int extra, u8 **iv)
{
	struct aead_request *req;
	void *tmp;

	/* allocate IV, request, scatterlist entries and caller scratch space
	 * in one block
	 */
	tmp = kmalloc(ovpn_aead_crypto_tmp_size(aead, nents) + extra,
		      GFP_ATOMIC);
	if (unlikely(!tmp))
		return ERR_PTR(-ENOMEM);

	ovpn_skb_cb(skb)->crypto_tmp = tmp;
	*iv = ovpn_aead_crypto_tmp_iv(aead, tmp);
	req = ovpn_aead_crypto_tmp_req(aead, *iv);

	return req;
}

static void ovpn_aead_encrypt_header(struct ovpn_peer *peer,
				     struct ovpn_crypto_key_slot *ks,
				     u32 pktid, u8 *iv, u8 *data)
{
	u32 op;

	/* concat 4 bytes packet id and 8 bytes nonce tail into 12 bytes
	 * nonce
	 */
	ovpn_pktid_aead_write(pktid, ks->nonce_tail_xmit, iv);

	/* add the packet opcode and wire nonce as associated data */
	op = ovpn_opcode_compose(OVPN_DATA_V2, ks->key_id, peer->tx_id);
	BUILD_BUG_ON(sizeof(op) != OVPN_OPCODE_SIZE);
	*(__force __be32 *)data = htonl(op);
	memcpy(data + OVPN_OPCODE_SIZE, iv, OVPN_NONCE_WIRE_SIZE);
}

int ovpn_aead_encrypt(struct ovpn_peer *peer, struct ovpn_crypto_key_slot *ks,
		      struct sk_buff *skb)
{
	const unsigned int tag_size = crypto_aead_authsize(ks->encrypt);
	unsigned int plaintext_len;
	struct aead_request *req;
	struct sk_buff *trailer;
	struct scatterlist *sg;
	bool notify = false;
	int nfrags, ret;
	u64 aead_blocks;
	u32 pktid;
	u8 *iv;

	ovpn_skb_cb(skb)->peer = peer;
	ovpn_skb_cb(skb)->ks = ks;
	plaintext_len = skb->len;

	/* Sample AEAD header format:
	 * 48000001 00000005 7e7046bd 444a7e28 cc6387b1 64a4d6c1 380275a...
	 * [ OP32 ] [seq # ] [             auth tag            ] [ payload ... ]
	 *          [4-byte
	 *          IV head]
	 */

	/* check that there's enough headroom in the skb for packet
	 * encapsulation
	 */
	if (unlikely(skb_cow_head(skb, OVPN_HEAD_ROOM)))
		return -ENOBUFS;

	/* get number of skb frags and ensure that packet data is writable */
	nfrags = skb_cow_data(skb, 0, &trailer);
	if (unlikely(nfrags < 0))
		return nfrags;

	if (unlikely(nfrags > MAX_SKB_FRAGS)) {
		ret = skb_linearize(skb);
		if (unlikely(ret))
			return ret;
		nfrags = 1;
	}

	req = ovpn_aead_request_alloc(ks->encrypt, skb, nfrags + 2, 0, &iv);
	if (IS_ERR(req))
		return PTR_ERR(req);
	sg = ovpn_aead_crypto_req_sg(ks->encrypt, req);

	/* sg table:
	 * 0: op, wire nonce (AD, len=OVPN_AEAD_DIRECT_AAD_SIZE),
	 * 1, 2, 3, ..., n: payload,
	 * n+1: auth_tag (len=tag_size)
	 */
	sg_init_table(sg, nfrags + 2);

	/* build scatterlist to encrypt packet payload */
	ret = skb_to_sgvec_nomark(skb, sg + 1, 0, skb->len);
	if (unlikely(ret < 0)) {
		netdev_err(peer->ovpn->dev,
			   "encrypt: cannot map skb to sg: %d\n", ret);
		return ret;
	}

	/* append auth_tag onto scatterlist */
	__skb_push(skb, tag_size);
	sg_set_buf(sg + ret + 1, skb->data, tag_size);

	/* make space for the additional data and push it to the front */
	__skb_push(skb, OVPN_AEAD_DIRECT_AAD_SIZE);
	aead_blocks = ovpn_aead_limit_blocks(ks->cipher_alg,
					     OVPN_AEAD_DIRECT_AAD_SIZE,
					     plaintext_len);
	/* obtain the packet ID used by both the nonce and associated data */
	ret = ovpn_pktid_xmit_next(&ks->pid_xmit, &pktid);
	if (unlikely(ret < 0))
		return ret;
	notify = ret > 0;

	ret = ovpn_key_usage_xmit(&ks->xmit_usage, &ks->xmit_limit,
				  aead_blocks);
	if (unlikely(ret < 0))
		return ret;
	notify |= ret > 0;

	/* packet-ID space and AEAD usage have independent soft limits;
	 * notify userspace once when either is crossed
	 */
	if (unlikely(notify) && !atomic_xchg(&ks->xmit_rekey_notified, 1))
		ovpn_nl_key_swap_notify(peer, ks->key_id);
	ovpn_aead_encrypt_header(peer, ks, pktid, iv, skb->data);

	/* AEAD Additional data */
	sg_set_buf(sg, skb->data, OVPN_AEAD_DIRECT_AAD_SIZE);

	/* setup async crypto operation */
	aead_request_set_tfm(req, ks->encrypt);
	aead_request_set_callback(req, 0, ovpn_encrypt_post, skb);
	aead_request_set_crypt(req, sg, sg,
			       skb->len - ovpn_aead_encap_overhead(ks), iv);
	aead_request_set_ad(req, OVPN_AEAD_DIRECT_AAD_SIZE);

	/* encrypt it */
	return crypto_aead_encrypt(req);
}

int ovpn_aead_encrypt_gso(struct ovpn_peer *peer,
			  struct ovpn_crypto_key_slot *ks, struct sk_buff *skb,
			  struct sk_buff *gso_skb, unsigned int offset,
			  u32 pktid)
{
	const unsigned int dst_nents = skb_shinfo(gso_skb)->nr_frags + 4;
	const unsigned int src_nents = skb_shinfo(skb)->nr_frags + 2;
	struct scatterlist *src, *dst;
	struct aead_request *req;
	unsigned int payload_off;
	int dst_idx, mapped, ret;
	u8 *aad, *iv;

	/* each input records the shared peer and key for the common completion
	 * path but their references remain owned by the output aggregate
	 */
	ovpn_skb_cb(skb)->peer = peer;
	ovpn_skb_cb(skb)->ks = ks;

	req = ovpn_aead_request_alloc(ks->encrypt, skb, src_nents + dst_nents,
				      OVPN_AEAD_DIRECT_AAD_SIZE, &iv);
	if (IS_ERR(req))
		return PTR_ERR(req);
	src = ovpn_aead_crypto_req_sg(ks->encrypt, req);
	dst = src + src_nents;
	aad = (u8 *)(dst + dst_nents);

	ovpn_aead_encrypt_header(peer, ks, pktid, iv, aad);

	ret = skb_store_bits(gso_skb, offset, aad,
			     OVPN_AEAD_DIRECT_AAD_SIZE);
	if (unlikely(ret < 0))
		return ret;

	/* encrypt out of place from the original segmented skb directly into
	 * its final range in the UDP GSO skb
	 */
	sg_init_table(src, src_nents);
	sg_set_buf(src, aad, OVPN_AEAD_DIRECT_AAD_SIZE);
	mapped = skb_to_sgvec_nomark(skb, src + 1, 0, skb->len);
	if (unlikely(mapped < 0))
		return mapped;
	sg_mark_end(&src[mapped]);

	sg_init_table(dst, dst_nents);
	dst_idx = skb_to_sgvec_nomark(gso_skb, dst, offset,
				      OVPN_AEAD_DIRECT_AAD_SIZE);
	if (unlikely(dst_idx < 0))
		return dst_idx;

	payload_off = offset + OVPN_AEAD_DIRECT_OVERHEAD;
	mapped = skb_to_sgvec_nomark(gso_skb, dst + dst_idx, payload_off,
				     skb->len);
	if (unlikely(mapped < 0))
		return mapped;
	dst_idx += mapped;

	mapped = skb_to_sgvec_nomark(gso_skb, dst + dst_idx,
				     offset + OVPN_AEAD_DIRECT_AAD_SIZE,
				     OVPN_AEAD_TAG_SIZE);
	if (unlikely(mapped < 0))
		return mapped;
	dst_idx += mapped;
	sg_mark_end(&dst[dst_idx - 1]);

	aead_request_set_tfm(req, ks->encrypt);
	aead_request_set_callback(req, 0, ovpn_encrypt_post, skb);
	aead_request_set_crypt(req, src, dst, skb->len, iv);
	aead_request_set_ad(req, OVPN_AEAD_DIRECT_AAD_SIZE);

	return crypto_aead_encrypt(req);
}

int ovpn_aead_decrypt(struct ovpn_peer *peer, struct ovpn_crypto_key_slot *ks,
		      struct sk_buff *skb)
{
	const unsigned int tag_size = crypto_aead_authsize(ks->decrypt);
	int ret, payload_len, nfrags;
	unsigned int payload_offset;
	struct aead_request *req;
	struct sk_buff *trailer;
	struct scatterlist *sg;
	void *tmp;
	u8 *iv;

	payload_offset = ovpn_aead_direct_payload_offset(tag_size);
	payload_len = skb->len - payload_offset;

	ovpn_skb_cb(skb)->payload_offset = payload_offset;
	ovpn_skb_cb(skb)->peer = peer;
	ovpn_skb_cb(skb)->ks = ks;

	/* sanity check on packet size, payload size must be >= 0 */
	if (unlikely(payload_len < 0))
		return -EINVAL;

	if (unlikely(ovpn_aead_decrypt_failure_exceeded(ks)))
		return -EKEYREJECTED;

	/* Prepare the skb data buffer to be accessed up until the auth tag.
	 * This is required because this area is directly mapped into the sg
	 * list.
	 */
	if (unlikely(!pskb_may_pull(skb, payload_offset)))
		return -ENODATA;

	/* get number of skb frags and ensure that packet data is writable */
	nfrags = skb_cow_data(skb, 0, &trailer);
	if (unlikely(nfrags < 0))
		return nfrags;

	if (unlikely(nfrags + 2 > (MAX_SKB_FRAGS + 2)))
		return -ENOSPC;

	/* allocate temporary memory for iv, sg and req */
	tmp = kmalloc(ovpn_aead_crypto_tmp_size(ks->decrypt, nfrags + 2),
		      GFP_ATOMIC);
	if (unlikely(!tmp))
		return -ENOMEM;

	ovpn_skb_cb(skb)->crypto_tmp = tmp;

	iv = ovpn_aead_crypto_tmp_iv(ks->decrypt, tmp);
	req = ovpn_aead_crypto_tmp_req(ks->decrypt, iv);
	sg = ovpn_aead_crypto_req_sg(ks->decrypt, req);

	/* sg table:
	 * 0: op, wire nonce (AD, len=OVPN_AEAD_DIRECT_AAD_SIZE),
	 * 1, 2, 3, ..., n: payload,
	 * n+1: auth_tag (len=tag_size)
	 */
	sg_init_table(sg, nfrags + 2);

	/* packet op is head of additional data */
	sg_set_buf(sg, skb->data, OVPN_AEAD_DIRECT_AAD_SIZE);

	/* build scatterlist to decrypt packet payload */
	ret = skb_to_sgvec_nomark(skb, sg + 1, payload_offset, payload_len);
	if (unlikely(ret < 0)) {
		netdev_err(peer->ovpn->dev,
			   "decrypt: cannot map skb to sg: %d\n", ret);
		return ret;
	}

	/* append auth_tag onto scatterlist */
	sg_set_buf(sg + ret + 1, skb->data + OVPN_AEAD_DIRECT_TAG_OFFSET,
		   tag_size);

	/* copy nonce into IV buffer */
	memcpy(iv, ovpn_aead_direct_wire_nonce(skb), OVPN_NONCE_WIRE_SIZE);
	memcpy(iv + OVPN_NONCE_WIRE_SIZE, ks->nonce_tail_recv,
	       OVPN_NONCE_TAIL_SIZE);

	/* setup async crypto operation */
	aead_request_set_tfm(req, ks->decrypt);
	aead_request_set_callback(req, 0, ovpn_decrypt_post, skb);
	aead_request_set_crypt(req, sg, sg, payload_len + tag_size, iv);

	aead_request_set_ad(req, OVPN_AEAD_DIRECT_AAD_SIZE);

	/* decrypt it */
	return crypto_aead_decrypt(req);
}
