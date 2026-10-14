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
#include <linux/workqueue.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/udp.h>

#include "ovpnpriv.h"
#include "main.h"
#include "io.h"
#include "pktid.h"
#include "crypto_aead.h"
#include "crypto.h"
#include "peer.h"
#include "proto.h"
#include "skb.h"

#define ALG_NAME_AES		"gcm(aes)"
#define ALG_NAME_CHACHAPOLY	"rfc7539(chacha20,poly1305)"

static int ovpn_aead_encap_overhead(const struct ovpn_crypto_key_slot *ks)
{
	return  OVPN_OPCODE_SIZE +			/* OP header size */
		sizeof(u32) +				/* Packet ID */
		crypto_aead_authsize(ks->encrypt);	/* Auth Tag */
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

/* Prepare the TCP prefix in reserved headroom so it participates in AEAD.
 * The send path pushes these bytes without changing the authenticated values.
 */
static int ovpn_aead_encrypt_tcp_header(struct sk_buff *skb, u16 gso_size)
{
	struct ovpn_tcp_hdr *hdr = (void *)(skb->data - sizeof(*hdr));

	BUILD_BUG_ON(sizeof(*hdr) != 4);
	if (unlikely(skb->len > OVPN_TCP_MAX_RECORD))
		return -EMSGSIZE;

	hdr->len = htons(skb->len + sizeof(hdr->gso_size));
	hdr->gso_size = htons(gso_size);
	return 0;
}

int ovpn_aead_encrypt(struct ovpn_peer *peer, struct ovpn_crypto_key_slot *ks,
		      struct sk_buff *skb)
{
	const unsigned int tag_size = crypto_aead_authsize(ks->encrypt);
	struct aead_request *req;
	struct sk_buff *trailer;
	struct scatterlist *sg;
	unsigned int aad_len = OVPN_AAD_SIZE;
	int nfrags, ret;
	u32 pktid;
	u8 *aad, *iv;

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
	 * 0: optional TCP prefix, op, wire nonce (AD),
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
	__skb_push(skb, OVPN_AAD_SIZE);
	aad = skb->data;
	if (ovpn_skb_cb(skb)->tcp_packets) {
		ret = ovpn_aead_encrypt_tcp_header(skb, 0);
		if (unlikely(ret))
			return ret;
		aad -= sizeof(struct ovpn_tcp_hdr);
		aad_len = OVPN_TCP_AAD_SIZE;
	}

	/* obtain the packet ID used by both the nonce and associated data */
	ret = ovpn_pktid_xmit_next(&ks->pid_xmit, &pktid);
	if (unlikely(ret < 0))
		return ret;
	ovpn_aead_encrypt_header(peer, ks, pktid, iv, skb->data);

	/* AEAD Additional data */
	sg_set_buf(sg, aad, aad_len);

	/* setup async crypto operation */
	aead_request_set_tfm(req, ks->encrypt);
	aead_request_set_callback(req, 0, ovpn_encrypt_post, skb);
	aead_request_set_crypt(req, sg, sg,
			       skb->len - ovpn_aead_encap_overhead(ks), iv);
	aead_request_set_ad(req, aad_len);

	/* encrypt it */
	return crypto_aead_encrypt(req);
}

int ovpn_aead_encrypt_udp_gso(struct ovpn_peer *peer,
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
				      OVPN_AAD_SIZE, &iv);
	if (IS_ERR(req))
		return PTR_ERR(req);
	src = ovpn_aead_crypto_req_sg(ks->encrypt, req);
	dst = src + src_nents;
	aad = (u8 *)(dst + dst_nents);

	ovpn_aead_encrypt_header(peer, ks, pktid, iv, aad);

	ret = skb_store_bits(gso_skb, offset, aad, OVPN_AAD_SIZE);
	if (unlikely(ret < 0))
		return ret;

	/* encrypt out of place from the original segmented skb directly into
	 * its final range in the UDP GSO skb
	 */
	sg_init_table(src, src_nents);
	sg_set_buf(src, aad, OVPN_AAD_SIZE);
	mapped = skb_to_sgvec_nomark(skb, src + 1, 0, skb->len);
	if (unlikely(mapped < 0))
		return mapped;
	sg_mark_end(&src[mapped]);

	sg_init_table(dst, dst_nents);
	dst_idx = skb_to_sgvec_nomark(gso_skb, dst, offset, OVPN_AAD_SIZE);
	if (unlikely(dst_idx < 0))
		return dst_idx;

	payload_off = offset + OVPN_AAD_SIZE + OVPN_AUTH_TAG_SIZE;
	mapped = skb_to_sgvec_nomark(gso_skb, dst + dst_idx, payload_off,
				     skb->len);
	if (unlikely(mapped < 0))
		return mapped;
	dst_idx += mapped;

	mapped = skb_to_sgvec_nomark(gso_skb, dst + dst_idx,
				     offset + OVPN_AAD_SIZE,
				     OVPN_AUTH_TAG_SIZE);
	if (unlikely(mapped < 0))
		return mapped;
	dst_idx += mapped;
	sg_mark_end(&dst[dst_idx - 1]);

	aead_request_set_tfm(req, ks->encrypt);
	aead_request_set_callback(req, 0, ovpn_encrypt_post, skb);
	aead_request_set_crypt(req, src, dst, skb->len, iv);
	aead_request_set_ad(req, OVPN_AAD_SIZE);

	return crypto_aead_encrypt(req);
}

/* Count read-only payload storage, including ordinary GRO frag lists. Match
 * skb_to_sgvec_nomark()'s nesting limit before allocating its scatterlist.
 */
static int ovpn_skb_nsg(const struct sk_buff *skb, unsigned int depth)
{
	unsigned int nents = !!skb_headlen(skb) + skb_shinfo(skb)->nr_frags;
	const struct sk_buff *frag;
	int ret;

	if (unlikely(depth >= 24))
		return -EMSGSIZE;

	skb_walk_frags(skb, frag) {
		ret = ovpn_skb_nsg(frag, depth + 1);
		if (unlikely(ret < 0))
			return ret;
		nents += ret;
	}

	return nents;
}

int ovpn_aead_encrypt_tcp_gso(struct ovpn_peer *peer,
			      struct ovpn_crypto_key_slot *ks,
			      struct sk_buff *skb, struct sk_buff *gso_skb)
{
	const unsigned int dst_nents = skb_shinfo(gso_skb)->nr_frags + 2;
	struct scatterlist *src, *dst;
	struct aead_request *req;
	int src_nents, mapped, ret;
	u8 *aad, *iv;
	u32 pktid;

	ret = ovpn_aead_encrypt_tcp_header(gso_skb, skb_shinfo(skb)->gso_size);
	if (unlikely(ret))
		return ret;
	aad = gso_skb->data - sizeof(struct ovpn_tcp_hdr);

	src_nents = ovpn_skb_nsg(skb, 0);
	if (unlikely(src_nents < 0))
		return src_nents;
	/* TCP prefix, opcode and packet ID as AAD */
	src_nents++;
	req = ovpn_aead_request_alloc(ks->encrypt, skb, src_nents + dst_nents,
				      0, &iv);
	if (IS_ERR(req))
		return PTR_ERR(req);
	src = ovpn_aead_crypto_req_sg(ks->encrypt, req);
	dst = src + src_nents;

	/* Read the original GSO skb without COW, checksum completion or
	 * segmentation. Its pages may still belong to the inner TCP sender.
	 */
	sg_init_table(src, src_nents);
	sg_set_buf(src, aad, OVPN_TCP_AAD_SIZE);
	mapped = skb_to_sgvec_nomark(skb, src + 1, 0, skb->len);
	if (unlikely(mapped < 0))
		return mapped;
	sg_mark_end(src + mapped);

	/* Keep AAD/tag in the linear head and write the encrypted inner packet
	 * directly into pages sent by MSG_SPLICE_PAGES.
	 */
	sg_init_table(dst, dst_nents);
	sg_set_buf(dst, aad, OVPN_TCP_AAD_SIZE);
	mapped = skb_to_sgvec_nomark(gso_skb, dst + 1, OVPN_DATA_V2_OVERHEAD,
				     skb->len);
	if (unlikely(mapped < 0))
		return mapped;
	sg_set_buf(dst + mapped + 1, gso_skb->data + OVPN_AAD_SIZE,
		   OVPN_AUTH_TAG_SIZE);
	sg_mark_end(dst + mapped + 1);

	ret = ovpn_pktid_xmit_next(&ks->pid_xmit, &pktid);
	if (unlikely(ret))
		return ret;
	ovpn_aead_encrypt_header(peer, ks, pktid, iv, gso_skb->data);

	aead_request_set_tfm(req, ks->encrypt);
	aead_request_set_callback(req, 0, ovpn_encrypt_tcp_gso_post, skb);
	aead_request_set_crypt(req, src, dst, skb->len, iv);
	aead_request_set_ad(req, OVPN_TCP_AAD_SIZE);

	return crypto_aead_encrypt(req);
}

int ovpn_aead_decrypt(struct ovpn_peer *peer, struct ovpn_crypto_key_slot *ks,
		      struct sk_buff *skb, bool tcp)
{
	const unsigned int tag_size = crypto_aead_authsize(ks->decrypt);
	unsigned int aad_len = OVPN_AAD_SIZE;
	int ret, payload_len, nfrags;
	unsigned int payload_offset;
	struct aead_request *req;
	struct sk_buff *trailer;
	struct scatterlist *sg;
	void *tmp;
	u8 *aad, *iv;

	payload_offset = OVPN_AAD_SIZE + tag_size;
	payload_len = skb->len - payload_offset;

	ovpn_skb_cb(skb)->payload_offset = payload_offset;
	ovpn_skb_cb(skb)->peer = peer;
	ovpn_skb_cb(skb)->ks = ks;

	/* sanity check on packet size, payload size must be >= 0 */
	if (unlikely(payload_len < 0))
		return -EINVAL;

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
	 * 0: optional TCP prefix, op, wire nonce (AD),
	 * 1, 2, 3, ..., n: payload,
	 * n+1: auth_tag (len=tag_size)
	 */
	sg_init_table(sg, nfrags + 2);

	/* TCP framing is contiguous with the opcode and packet ID. Save its
	 * segment size, but do not use it until authentication succeeds.
	 */
	aad = skb->data;
	if (tcp) {
		const struct ovpn_tcp_hdr *hdr;

		aad -= sizeof(*hdr);
		hdr = (const struct ovpn_tcp_hdr *)aad;
		aad_len = OVPN_TCP_AAD_SIZE;
		ovpn_skb_cb(skb)->gso_size = ntohs(hdr->gso_size);
	}
	sg_set_buf(sg, aad, aad_len);

	/* build scatterlist to decrypt packet payload */
	ret = skb_to_sgvec_nomark(skb, sg + 1, payload_offset, payload_len);
	if (unlikely(ret < 0)) {
		netdev_err(peer->ovpn->dev,
			   "decrypt: cannot map skb to sg: %d\n", ret);
		return ret;
	}

	/* append auth_tag onto scatterlist */
	sg_set_buf(sg + ret + 1, skb->data + OVPN_AAD_SIZE, tag_size);

	/* copy nonce into IV buffer */
	memcpy(iv, skb->data + OVPN_OPCODE_SIZE, OVPN_NONCE_WIRE_SIZE);
	memcpy(iv + OVPN_NONCE_WIRE_SIZE, ks->nonce_tail_recv,
	       OVPN_NONCE_TAIL_SIZE);

	/* setup async crypto operation */
	aead_request_set_tfm(req, ks->decrypt);
	aead_request_set_callback(req, 0, ovpn_decrypt_post, skb);
	aead_request_set_crypt(req, sg, sg, payload_len + tag_size, iv);

	aead_request_set_ad(req, aad_len);

	/* decrypt it */
	return crypto_aead_decrypt(req);
}

int ovpn_aead_decrypt_tcp(struct ovpn_peer *peer,
			  struct ovpn_crypto_key_slot *ks, struct sk_buff *skb,
			  struct sk_buff *source, unsigned int offset)
{
	const unsigned int tag_size = crypto_aead_authsize(ks->decrypt);
	const unsigned int payload_offset = OVPN_AAD_SIZE + tag_size;
	const unsigned int payload_len = skb->len - payload_offset;
	const struct ovpn_tcp_hdr *hdr;
	struct scatterlist *src, *dst;
	struct aead_request *req;
	int nents, mapped = 0, ret;
	u8 *aad, *iv;

	ovpn_skb_cb(skb)->payload_offset = payload_offset;
	ovpn_skb_cb(skb)->peer = peer;
	ovpn_skb_cb(skb)->ks = ks;

	aad = skb->data - sizeof(*hdr);
	hdr = (const struct ovpn_tcp_hdr *)aad;
	ovpn_skb_cb(skb)->gso_size = ntohs(hdr->gso_size);

	/* The source can contain parts of adjacent records. Counting all its
	 * storage bounds the SG, but map only this record's ciphertext range.
	 * Keep the copy path for shapes beyond the SG mapper's nesting limit.
	 */
	nents = ovpn_skb_nsg(source, 0);
	if (unlikely(nents < 0)) {
		ret = skb_copy_bits(source, offset + payload_offset,
				    skb->data + payload_offset, payload_len);
		if (ret)
			return ret;
		return ovpn_aead_decrypt(peer, ks, skb, true);
	}

	req = ovpn_aead_request_alloc(ks->decrypt, skb, nents + 4, 0, &iv);
	if (IS_ERR(req))
		return PTR_ERR(req);
	src = ovpn_aead_crypto_req_sg(ks->decrypt, req);
	dst = src + nents + 2;

	/* AEAD reads AAD, ciphertext, tag. The small header and tag are already
	 * private; ciphertext stays read-only in the retained stream skb.
	 */
	sg_init_table(src, nents + 2);
	sg_set_buf(src, aad, OVPN_TCP_AAD_SIZE);
	if (payload_len) {
		mapped = skb_to_sgvec_nomark(source, src + 1,
					     offset + payload_offset, payload_len);
		if (unlikely(mapped < 0))
			return mapped;
	}
	sg_set_buf(src + mapped + 1, skb->data + OVPN_AAD_SIZE, tag_size);
	sg_mark_end(src + mapped + 1);

	sg_init_table(dst, payload_len ? 2 : 1);
	sg_set_buf(dst, aad, OVPN_TCP_AAD_SIZE);
	if (payload_len)
		sg_set_buf(dst + 1, skb->data + payload_offset, payload_len);

	memcpy(iv, skb->data + OVPN_OPCODE_SIZE, OVPN_NONCE_WIRE_SIZE);
	memcpy(iv + OVPN_NONCE_WIRE_SIZE, ks->nonce_tail_recv,
	       OVPN_NONCE_TAIL_SIZE);

	aead_request_set_tfm(req, ks->decrypt);
	aead_request_set_callback(req, 0, ovpn_decrypt_post, skb);
	aead_request_set_crypt(req, src, dst, payload_len + tag_size, iv);
	aead_request_set_ad(req, OVPN_TCP_AAD_SIZE);

	return crypto_aead_decrypt(req);
}

/* Initialize a struct crypto_aead object */
static struct crypto_aead *ovpn_aead_init(const char *title,
					  const char *alg_name,
					  const unsigned char *key,
					  unsigned int keylen)
{
	struct crypto_aead *aead;
	int ret;

	aead = crypto_alloc_aead(alg_name, 0, 0);
	if (IS_ERR(aead)) {
		ret = PTR_ERR(aead);
		pr_err("%s crypto_alloc_aead failed, err=%d\n", title, ret);
		aead = NULL;
		goto error;
	}

	ret = crypto_aead_setkey(aead, key, keylen);
	if (ret) {
		pr_err("%s crypto_aead_setkey size=%u failed, err=%d\n", title,
		       keylen, ret);
		goto error;
	}

	ret = crypto_aead_setauthsize(aead, OVPN_AUTH_TAG_SIZE);
	if (ret) {
		pr_err("%s crypto_aead_setauthsize failed, err=%d\n", title,
		       ret);
		goto error;
	}

	/* basic AEAD assumption
	 * all current algorithms use OVPN_NONCE_SIZE.
	 * ovpn_aead_crypto_tmp_size and ovpn_aead_encrypt/decrypt
	 * expect this.
	 */
	if (crypto_aead_ivsize(aead) != OVPN_NONCE_SIZE) {
		pr_err("%s IV size must be %d\n", title, OVPN_NONCE_SIZE);
		ret = -EINVAL;
		goto error;
	}

	pr_debug("********* Cipher %s (%s)\n", alg_name, title);
	pr_debug("*** IV size=%u\n", crypto_aead_ivsize(aead));
	pr_debug("*** req size=%u\n", crypto_aead_reqsize(aead));
	pr_debug("*** block size=%u\n", crypto_aead_blocksize(aead));
	pr_debug("*** auth size=%u\n", crypto_aead_authsize(aead));
	pr_debug("*** alignmask=0x%x\n", crypto_aead_alignmask(aead));

	return aead;

error:
	crypto_free_aead(aead);
	return ERR_PTR(ret);
}

static void ovpn_aead_crypto_key_slot_free(struct ovpn_crypto_key_slot *ks)
{
	crypto_free_aead(ks->encrypt);
	crypto_free_aead(ks->decrypt);
}

static void ovpn_aead_crypto_key_slot_free_work(struct work_struct *work)
{
	struct ovpn_crypto_key_slot *ks;

	ks = container_of(to_rcu_work(work), struct ovpn_crypto_key_slot,
			  free_work);
	ovpn_aead_crypto_key_slot_free(ks);
	kfree(ks);
}

struct ovpn_crypto_key_slot *
ovpn_aead_crypto_key_slot_new(const struct ovpn_key_config *kc)
{
	struct ovpn_crypto_key_slot *ks = NULL;
	const char *alg_name;
	int ret;

	/* validate crypto alg */
	switch (kc->cipher_alg) {
	case OVPN_CIPHER_ALG_AES_GCM:
		alg_name = ALG_NAME_AES;
		break;
	case OVPN_CIPHER_ALG_CHACHA20_POLY1305:
		alg_name = ALG_NAME_CHACHAPOLY;
		break;
	default:
		return ERR_PTR(-EOPNOTSUPP);
	}

	if (kc->encrypt.nonce_tail_size != OVPN_NONCE_TAIL_SIZE ||
	    kc->decrypt.nonce_tail_size != OVPN_NONCE_TAIL_SIZE)
		return ERR_PTR(-EINVAL);

	/* build the key slot */
	ks = kmalloc_obj(*ks);
	if (!ks)
		return ERR_PTR(-ENOMEM);

	ks->encrypt = NULL;
	ks->decrypt = NULL;
	INIT_RCU_WORK(&ks->free_work, ovpn_aead_crypto_key_slot_free_work);
	kref_init(&ks->refcount);
	ks->key_id = kc->key_id;

	ks->encrypt = ovpn_aead_init("encrypt", alg_name,
				     kc->encrypt.cipher_key,
				     kc->encrypt.cipher_key_size);
	if (IS_ERR(ks->encrypt)) {
		ret = PTR_ERR(ks->encrypt);
		ks->encrypt = NULL;
		goto destroy_ks;
	}

	ks->decrypt = ovpn_aead_init("decrypt", alg_name,
				     kc->decrypt.cipher_key,
				     kc->decrypt.cipher_key_size);
	if (IS_ERR(ks->decrypt)) {
		ret = PTR_ERR(ks->decrypt);
		ks->decrypt = NULL;
		goto destroy_ks;
	}

	memcpy(ks->nonce_tail_xmit, kc->encrypt.nonce_tail,
	       OVPN_NONCE_TAIL_SIZE);
	memcpy(ks->nonce_tail_recv, kc->decrypt.nonce_tail,
	       OVPN_NONCE_TAIL_SIZE);

	/* init packet ID generation/validation */
	ovpn_pktid_xmit_init(&ks->pid_xmit);
	ovpn_pktid_recv_init(&ks->pid_recv);

	return ks;

destroy_ks:
	ovpn_aead_crypto_key_slot_free(ks);
	kfree(ks);
	return ERR_PTR(ret);
}

enum ovpn_cipher_alg ovpn_aead_crypto_alg(struct ovpn_crypto_key_slot *ks)
{
	const char *alg_name;

	if (!ks->encrypt)
		return OVPN_CIPHER_ALG_NONE;

	alg_name = crypto_tfm_alg_name(crypto_aead_tfm(ks->encrypt));

	if (!strcmp(alg_name, ALG_NAME_AES))
		return OVPN_CIPHER_ALG_AES_GCM;
	else if (!strcmp(alg_name, ALG_NAME_CHACHAPOLY))
		return OVPN_CIPHER_ALG_CHACHA20_POLY1305;
	else
		return OVPN_CIPHER_ALG_NONE;
}
