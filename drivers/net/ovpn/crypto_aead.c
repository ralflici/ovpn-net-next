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
ovpn_aead_decrypt_failure_exceeded(const struct ovpn_key_ctx *key)
{
	return atomic64_read(&key->decrypt_failures) >
	       OVPN_AEAD_DECRYPT_FAILURE_LIMIT;
}

bool ovpn_aead_decrypt_failure_record(struct ovpn_key_ctx *key)
{
	u64 failures = atomic64_inc_return(&key->decrypt_failures);

	return failures > OVPN_AEAD_DECRYPT_FAILURE_NOTIFY &&
	       atomic_cmpxchg(&key->decrypt_failure_notified, 0, 1) == 0;
}

/**
 * ovpn_aead_crypto_tmp_size - compute the size of a temporary object containing
 *			       an AEAD request structure with extra space for SG
 *			       and IV.
 * @tfm: the AEAD cipher handle
 * @sg_nents: the number of scatterlist entries
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
					      const unsigned int sg_nents)
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
	len += array_size(sizeof(struct scatterlist), sg_nents);
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
				     const struct ovpn_key_ctx *key,
				     u16 epoch, u64 seq, u8 *iv, u8 *data)
{
	u64 pktid;
	u32 op;

	pktid = ovpn_pktid_aead_write(epoch, seq, key->implicit_iv, iv);

	/* add the packet opcode and wire nonce as associated data */
	op = ovpn_opcode_compose(OVPN_DATA_V2, ks->key_id, peer->tx_id);
	BUILD_BUG_ON(sizeof(op) != OVPN_OPCODE_SIZE);
	*(__force __be32 *)data = htonl(op);
	ovpn_pktid_wire_write(data + OVPN_OPCODE_SIZE, ks->epoch_format,
			      pktid);
}

/**
 * ovpn_advance_encrypt_key - promote TX to a target epoch
 * @ks: key slot containing TX epoch state
 * @target_epoch: epoch to promote TX to
 *
 * TX promotion consumes prederived future keys up to @target_epoch. If another
 * context is already updating TX state or refill has not caught up, the caller
 * decides whether to keep using the current key or stop processing the packet.
 *
 * Return:
 * - 0 if TX reached or already passed @target_epoch,
 * - -EBUSY if the TX lock is busy,
 * - -ENOKEY if the future ring cannot provide @target_epoch,
 * - another negative error code otherwise.
 */
int ovpn_advance_encrypt_key(struct ovpn_crypto_key_slot *ks, u16 target_epoch)
{
	u16 stale_count = 0, advance, count, index, stale_index, i;
	struct ovpn_key_ctx *stale[OVPN_EPOCH_FUTURE_KEYS_COUNT];
	struct ovpn_key_ctx *old_encrypt, *new_encrypt, *future;
	struct ovpn_key_ctx __rcu **slot;

	/* concurrent promotion or refill means another context is moving tx */
	if (unlikely(!spin_trylock_bh(&ks->tx_lock)))
		return -EBUSY;
	lockdep_assert_held(&ks->tx_lock);

	old_encrypt = rcu_dereference_protected(ks->encrypt, 1);
	if (unlikely(old_encrypt->epoch >= target_epoch)) {
		spin_unlock_bh(&ks->tx_lock);
		return 0;
	}

	count = ovpn_epoch_future_keys_count(&ks->future_tx_keys);
	advance = target_epoch - old_encrypt->epoch;
	/* refill can lag behind packet processing under pressure */
	if (unlikely(count < advance)) {
		spin_unlock_bh(&ks->tx_lock);
		ovpn_schedule_refill(ks, true);
		return -ENOKEY;
	}

	index = (ks->future_tx_keys.tail + advance - 1) %
		OVPN_EPOCH_FUTURE_KEYS_COUNT;
	slot = &ks->future_tx_keys.keys[index];
	new_encrypt = rcu_dereference_protected(*slot, 1);
	if (WARN_ON_ONCE(!new_encrypt ||
			 new_encrypt->epoch != target_epoch)) {
		spin_unlock_bh(&ks->tx_lock);
		return -ENOKEY;
	}

	for (i = 0; i < advance; i++) {
		/* drop skipped future keys when advancing past them */
		stale_index = (ks->future_tx_keys.tail + i) %
			      OVPN_EPOCH_FUTURE_KEYS_COUNT;
		slot = &ks->future_tx_keys.keys[stale_index];
		future = rcu_dereference_protected(*slot, 1);
		if (future != new_encrypt)
			stale[stale_count++] = future;
		RCU_INIT_POINTER(*slot, NULL);
	}

	/* each concrete key carries fresh packet-ID state */
	rcu_assign_pointer(ks->encrypt, new_encrypt);
	ks->future_tx_keys.tail = (ks->future_tx_keys.tail + advance) %
				  OVPN_EPOCH_FUTURE_KEYS_COUNT;
	ks->future_tx_keys.full = false;
	spin_unlock_bh(&ks->tx_lock);

	ovpn_key_ctx_kill(old_encrypt);
	for (i = 0; i < stale_count; i++)
		ovpn_key_ctx_kill(stale[i]);

	ovpn_schedule_refill(ks, true);

	return 0;
}

void ovpn_request_encrypt_epoch(struct ovpn_crypto_key_slot *ks,
				unsigned int target_epoch)
{
	int requested = atomic_read(&ks->tx_epoch_request);

	/* concurrent requests can only move the target epoch forward */
	while (requested < target_epoch &&
	       !atomic_try_cmpxchg_relaxed(&ks->tx_epoch_request, &requested,
					    target_epoch))
		;
}

/**
 * ovpn_aead_encrypt_reserve - reserve packet IDs and cipher usage
 * @peer: peer that owns the key slot
 * @ks: key slot used for encryption
 * @encrypt: concrete transmit key context
 * @packets: number of equal-sized packets in the reservation
 * @plaintext_len: plaintext length charged for each packet
 * @first_seq: location where the first reserved packet ID is stored
 *
 * Return: 0 on success, -EAGAIN after promoting an epoch key so the caller can
 * retry with the new context, or another negative error code on failure
 */
int ovpn_aead_encrypt_reserve(struct ovpn_peer *peer,
			      struct ovpn_crypto_key_slot *ks,
			      struct ovpn_key_ctx *encrypt,
			      unsigned int packets, unsigned int plaintext_len,
			      u64 *first_seq)
{
	unsigned int target_epoch;
	bool must_rotate = false;
	bool notify = false;
	u64 aead_blocks;
	int ret;

	/* reserve every nonce before charging the cipher usage budget */
	ret = ovpn_pktid_xmit_reserve(&encrypt->pktid_xmit, packets, first_seq);
	if (unlikely(ret < 0)) {
		if (!ks->epoch_format)
			return ret;
		must_rotate = true;
	} else {
		notify = ret > 0;
		aead_blocks = packets * ovpn_aead_limit_blocks(ks->cipher_alg,
							       ks->aad_size,
							       plaintext_len);
		ret = ovpn_key_usage_xmit(&encrypt->xmit_usage, &ks->xmit_limit,
					  packets, aead_blocks);
		if (unlikely(ret < 0)) {
			/* epoch keys rotate at the hard limit */
			if (!ks->epoch_format)
				return ret;
			must_rotate = true;
		} else {
			notify |= ret > 0;
		}
	}

	if (!ks->epoch_format) {
		/* packet-ID space and AEAD usage have independent soft limits;
		 * userspace must be notified once when either is crossed
		 */
		if (unlikely(notify) &&
		    !atomic_xchg(&encrypt->xmit_rekey_notified, 1))
			ovpn_nl_key_swap_notify(peer, ks->key_id);
		return 0;
	}

	if (unlikely(must_rotate || notify))
		ovpn_request_encrypt_epoch(ks, encrypt->epoch + 1);

	target_epoch = atomic_read(&ks->tx_epoch_request);
	if (likely(target_epoch <= encrypt->epoch))
		return 0;

	/* hard exhaustion only requires the immediately following key */
	if (must_rotate)
		target_epoch = encrypt->epoch + 1;

	/* keep enough epoch space for the future-key ring after promotion */
	if (unlikely(target_epoch + OVPN_EPOCH_FUTURE_KEYS_COUNT >=
		     OVPN_MAX_EPOCH))
		return -ERANGE;

	ret = ovpn_advance_encrypt_key(ks, target_epoch);
	if (unlikely(ret == -EBUSY || ret == -ENOKEY))
		return must_rotate ? ret : 0;
	if (unlikely(ret < 0))
		return ret;

	return -EAGAIN;
}

int ovpn_aead_encrypt(struct ovpn_peer *peer, struct ovpn_crypto_key_slot *ks,
		      struct sk_buff *skb)
{
	unsigned int plaintext_len, payload_sg_len, sg_nents, tag_size;
	struct ovpn_key_ctx *key = NULL;
	struct aead_request *req;
	struct sk_buff *trailer;
	struct scatterlist *sg;
	int nfrags, ret;
	u64 pktid, seq;
	void *tmp;
	u32 op;
	u8 *iv;

	ovpn_skb_cb(skb)->peer = peer;
	ovpn_skb_cb(skb)->ks = ks;
	plaintext_len = skb->len;

	/* direct-key DATA_V2 wire format:
	 * 48000001 00000005 7e7046bd 444a7e28 cc6387b1 64a4d6c1 380275a...
	 * [ OP32 ] [seq # ] [             auth tag            ] [ payload ... ]
	 *          [4-byte
	 *          IV head]
	 *
	 * epoch-key DATA_V2 wire format:
	 * 48000001 0001 000000000005 38.. 7e7046bd 444a7e28 cc6387b1 64a4d6c1
	 * [ OP32 ] [ep] [  seq #   ] [pl] [             auth tag            ]
	 *          [ 8B packet ID  ]
	 */

retry:
	ret = ovpn_key_ctx_get(&key, &ks->encrypt);
	if (unlikely(ret))
		return ret;
	ovpn_skb_cb(skb)->key = key;

	tag_size = crypto_aead_authsize(key->tfm);

	ret = ovpn_aead_encrypt_reserve(peer, ks, key, 1, plaintext_len, &seq);
	if (unlikely(ret == -EAGAIN)) {
		/* retry with the promoted epoch key */
		ovpn_skb_cb(skb)->key = NULL;
		ovpn_key_ctx_put(key);
		key = NULL;
		goto retry;
	}
	if (unlikely(ret < 0))
		return ret;

	/* check that there's enough headroom in the skb for packet
	 * encapsulation
	 */
	if (unlikely(skb_cow_head(skb, OVPN_HEAD_ROOM)))
		return -ENOBUFS;

	/* ensure packet data is writable and epoch tag tailroom exists */
	nfrags = skb_cow_data(skb, ks->tail_tag_size, &trailer);
	if (unlikely(nfrags < 0))
		return nfrags;

	sg_nents = nfrags + 1 + !ks->tail_tag_size;
	if (unlikely(sg_nents > MAX_SKB_FRAGS + 2))
		return -ENOSPC;

	/* epoch packets place the authentication tag after payload */
	if (ks->tail_tag_size)
		pskb_put(skb, trailer, ks->tail_tag_size);
	payload_sg_len = plaintext_len + ks->tail_tag_size;

	/* allocate temporary memory for iv, sg and req */
	tmp = kmalloc(ovpn_aead_crypto_tmp_size(key->tfm, sg_nents),
		      GFP_ATOMIC);
	if (unlikely(!tmp))
		return -ENOMEM;

	ovpn_skb_cb(skb)->crypto_tmp = tmp;

	iv = ovpn_aead_crypto_tmp_iv(key->tfm, tmp);
	req = ovpn_aead_crypto_tmp_req(key->tfm, iv);
	sg = ovpn_aead_crypto_req_sg(key->tfm, req);

	/* sg table:
	 * 0: op, packet ID (AD, len=ks->aad_size),
	 * 1, 2, 3, ..., n: payload and epoch auth_tag,
	 * n+1: direct auth_tag (len=tag_size)
	 */
	sg_init_table(sg, sg_nents);

	/* build scatterlist to encrypt packet payload */
	ret = skb_to_sgvec_nomark(skb, sg + 1, 0, payload_sg_len);
	if (unlikely(ret < 0)) {
		netdev_err(peer->ovpn->dev,
			   "encrypt: cannot map skb to sg: %d\n", ret);
		return ret;
	}

	if (!ks->tail_tag_size) {
		/* direct packets prepend the tag before payload */
		__skb_push(skb, tag_size);
		sg_set_buf(sg + ret + 1, skb->data, tag_size);
	}
	sg_mark_end(sg + ret + !ks->tail_tag_size);

	/* create the AEAD IV from packet ID and implicit IV */
	pktid = ovpn_pktid_aead_write(key->epoch, seq, key->implicit_iv, iv);

	/* prepend the associated data */
	__skb_push(skb, ks->aad_size);
	op = ovpn_opcode_compose(OVPN_DATA_V2, ks->key_id, peer->tx_id);
	BUILD_BUG_ON(sizeof(op) != OVPN_OPCODE_SIZE);
	*((__force __be32 *)skb->data) = htonl(op);
	/* packet ID is 64 bits for epoch packets and 32 bits otherwise */
	ovpn_pktid_wire_write(skb->data + OVPN_OPCODE_SIZE,
			      ks->epoch_format, pktid);

	/* AEAD Additional data */
	sg_set_buf(sg, skb->data, ks->aad_size);

	/* setup async crypto operation */
	aead_request_set_tfm(req, key->tfm);
	aead_request_set_callback(req, 0, ovpn_encrypt_post, skb);
	aead_request_set_crypt(req, sg, sg, plaintext_len, iv);
	aead_request_set_ad(req, ks->aad_size);

	/* encrypt it */
	return crypto_aead_encrypt(req);
}

int ovpn_aead_encrypt_gso(struct ovpn_peer *peer,
			  struct ovpn_crypto_key_slot *ks,
			  struct ovpn_key_ctx *key, struct sk_buff *skb,
			  struct sk_buff *gso_skb, unsigned int offset,
			  u64 pktid)
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

	req = ovpn_aead_request_alloc(key->tfm, skb, src_nents + dst_nents,
				      ks->aad_size, &iv);
	if (IS_ERR(req))
		return PTR_ERR(req);
	src = ovpn_aead_crypto_req_sg(key->tfm, req);
	dst = src + src_nents;
	aad = (u8 *)(dst + dst_nents);

	ovpn_aead_encrypt_header(peer, ks, key, key->epoch, pktid, iv, aad);

	ret = skb_store_bits(gso_skb, offset, aad, ks->aad_size);
	if (unlikely(ret < 0))
		return ret;

	/* encrypt out of place from the original segmented skb directly into
	 * its final range in the UDP GSO skb
	 */
	sg_init_table(src, src_nents);
	sg_set_buf(src, aad, ks->aad_size);
	mapped = skb_to_sgvec_nomark(skb, src + 1, 0, skb->len);
	if (unlikely(mapped < 0))
		return mapped;
	sg_mark_end(&src[mapped]);

	sg_init_table(dst, dst_nents);
	dst_idx = skb_to_sgvec_nomark(gso_skb, dst, offset, ks->aad_size);
	if (unlikely(dst_idx < 0))
		return dst_idx;

	/* direct packets store the tag before the payload, while epoch packets
	 * append it to the payload and can map both as one contiguous range
	 */
	payload_off = offset + ks->payload_offset;
	mapped = skb_to_sgvec_nomark(gso_skb, dst + dst_idx, payload_off,
				     skb->len + ks->tail_tag_size);
	if (unlikely(mapped < 0))
		return mapped;
	dst_idx += mapped;

	if (!ks->tail_tag_size) {
		mapped = skb_to_sgvec_nomark(gso_skb, dst + dst_idx,
					     offset + ks->aad_size,
					     OVPN_AEAD_TAG_SIZE);
		if (unlikely(mapped < 0))
			return mapped;
		dst_idx += mapped;
	}
	sg_mark_end(&dst[dst_idx - 1]);

	aead_request_set_tfm(req, key->tfm);
	aead_request_set_callback(req, 0, ovpn_encrypt_post, skb);
	aead_request_set_crypt(req, src, dst, skb->len, iv);
	aead_request_set_ad(req, ks->aad_size);

	return crypto_aead_encrypt(req);
}

/**
 * ovpn_aead_decrypt_key - get the decrypt key matching a packet epoch
 * @ks: key slot containing RX epoch state
 * @pkt_epoch: epoch decoded from the packet ID
 *
 * Direct-key packets must carry epoch 0. Epoch RX first tries the current key,
 * then the retiring key for reordered packets, and finally the future ring. A
 * future key is returned only for authentication; promotion happens after the
 * packet has authenticated.
 *
 * Return: referenced key context or an error pointer.
 */
static struct ovpn_key_ctx *
ovpn_aead_decrypt_key(struct ovpn_crypto_key_slot *ks, u16 pkt_epoch)
{
	u16 current_epoch, epoch_diff, index;
	struct ovpn_key_ctx *key;
	unsigned int sequence;

	/* direct packet decoding always reports epoch 0 */
	if (!ks->epoch_format) {
		if (unlikely(ovpn_key_ctx_get(&key, &ks->decrypt)))
			return ERR_PTR(-ENOKEY);
		return key;
	}

	/* current epoch needs no multi-pointer snapshot */
	if (!ovpn_key_ctx_get(&key, &ks->decrypt)) {
		if (likely(key->epoch == pkt_epoch))
			return key;
		ovpn_key_ctx_put(key);
	}

	/* RCU protects candidates while the seqcount validates the snapshot */
	rcu_read_lock();
retry:
	sequence = read_seqcount_begin(&ks->rx_seqcount);
	key = rcu_dereference(ks->decrypt);
	if (unlikely(!key)) {
		key = ERR_PTR(-ENOKEY);
		goto validate;
	}
	/* current key is the expected RX path */
	if (likely(key->epoch == pkt_epoch))
		goto validate;
	current_epoch = key->epoch;

	key = rcu_dereference(ks->retiring_key);
	/* retiring key accepts late packets from the previous epoch */
	if (unlikely(key && key->epoch == pkt_epoch))
		goto validate;

	key = ERR_PTR(-ERANGE);
	if (unlikely(pkt_epoch < current_epoch))
		goto validate;
	/* stay away from the epoch range where future refill wraps */
	if (unlikely(pkt_epoch >
		     OVPN_MAX_EPOCH - OVPN_EPOCH_FUTURE_KEYS_COUNT - 1))
		goto validate;

	epoch_diff = pkt_epoch - current_epoch;
	if (unlikely(epoch_diff > OVPN_EPOCH_FUTURE_KEYS_COUNT))
		goto validate;

	/* future keys start at tail/current_epoch + 1 */
	index = (ks->future_rx_keys.tail + epoch_diff - 1) %
		OVPN_EPOCH_FUTURE_KEYS_COUNT;
	key = rcu_dereference(ks->future_rx_keys.keys[index]);
	if (unlikely(!key || key->epoch != pkt_epoch))
		key = ERR_PTR(-ENOKEY);

validate:
	if (read_seqcount_retry(&ks->rx_seqcount, sequence))
		goto retry;
	/* the candidate may have been retired after validating the snapshot */
	if (!IS_ERR(key) &&
	    unlikely(!percpu_ref_tryget_live_rcu(&key->refcount)))
		goto retry;

	rcu_read_unlock();
	return key;
}

int ovpn_aead_decrypt(struct ovpn_peer *peer, struct ovpn_crypto_key_slot *ks,
		      struct sk_buff *skb)
{
	unsigned int payload_offset, payload_sg_len, sg_nents, tag_size;
	int ret, payload_len, nfrags;
	struct ovpn_key_ctx *key;
	struct aead_request *req;
	struct sk_buff *trailer;
	struct scatterlist *sg;
	u16 pkt_epoch;
	u64 pkt_seq;
	void *tmp;
	u8 *iv;

	payload_offset = ks->payload_offset;
	ovpn_skb_cb(skb)->payload_offset = payload_offset;
	ovpn_skb_cb(skb)->peer = peer;
	ovpn_skb_cb(skb)->ks = ks;

	if (unlikely(skb->len < payload_offset))
		return -EINVAL;
	payload_len = skb->len - payload_offset;
	if (ks->tail_tag_size) {
		if (unlikely(payload_len < ks->tail_tag_size))
			return -EINVAL;
		payload_len -= ks->tail_tag_size;
	}

	/* sanity check on packet size, payload size must be >= 0 */
	if (unlikely(payload_len < 0))
		return -EINVAL;

	/* make additional data contiguous for sg[0] */
	if (unlikely(!pskb_may_pull(skb, payload_offset)))
		return -ENODATA;

	/* epoch packet ID includes both epoch and per-epoch counter */
	pkt_seq = ovpn_pktid_read(skb->data + OVPN_OPCODE_SIZE,
				  ks->epoch_format, &pkt_epoch);
	key = ovpn_aead_decrypt_key(ks, pkt_epoch);
	if (IS_ERR(key))
		return PTR_ERR(key);
	ovpn_skb_cb(skb)->key = key;

	if (unlikely(ovpn_aead_decrypt_failure_exceeded(key)))
		return -EKEYREJECTED;

	tag_size = crypto_aead_authsize(key->tfm);
	/* epoch tag is at the tail and remains in the crypto input */
	payload_sg_len = payload_len + ks->tail_tag_size;

	/* get number of skb frags and ensure that packet data is writable */
	nfrags = skb_cow_data(skb, 0, &trailer);
	if (unlikely(nfrags < 0))
		return nfrags;

	sg_nents = nfrags + 1 + !ks->tail_tag_size;
	if (unlikely(sg_nents > MAX_SKB_FRAGS + 2))
		return -ENOSPC;

	/* allocate temporary memory for iv, sg and req */
	tmp = kmalloc(ovpn_aead_crypto_tmp_size(key->tfm, sg_nents),
		      GFP_ATOMIC);
	if (unlikely(!tmp))
		return -ENOMEM;

	ovpn_skb_cb(skb)->crypto_tmp = tmp;

	iv = ovpn_aead_crypto_tmp_iv(key->tfm, tmp);
	req = ovpn_aead_crypto_tmp_req(key->tfm, iv);
	sg = ovpn_aead_crypto_req_sg(key->tfm, req);

	/* sg table:
	 * 0: op, packet ID (AD, len=ks->aad_size),
	 * 1, 2, 3, ..., n: payload and epoch auth_tag,
	 * n+1: direct auth_tag (len=tag_size)
	 */
	sg_init_table(sg, sg_nents);

	/* packet op is head of additional data */
	sg_set_buf(sg, skb->data, ks->aad_size);

	/* build scatterlist to decrypt packet payload */
	ret = skb_to_sgvec_nomark(skb, sg + 1, payload_offset,
				  payload_sg_len);
	if (unlikely(ret < 0)) {
		netdev_err(peer->ovpn->dev,
			   "decrypt: cannot map skb to sg: %d\n", ret);
		return ret;
	}

	if (!ks->tail_tag_size) {
		/* direct tag is prepended; epoch tag is in payload sg */
		sg_set_buf(sg + ret + 1,
			   skb->data + OVPN_AEAD_DIRECT_TAG_OFFSET,
			   tag_size);
	}
	sg_mark_end(sg + ret + !ks->tail_tag_size);

	/* rebuild the AEAD IV from packet ID and implicit IV */
	ovpn_pktid_aead_write(pkt_epoch, pkt_seq, key->implicit_iv, iv);

	/* setup async crypto operation */
	aead_request_set_tfm(req, key->tfm);
	aead_request_set_callback(req, 0, ovpn_decrypt_post, skb);
	aead_request_set_crypt(req, sg, sg, payload_len + tag_size, iv);

	aead_request_set_ad(req, ks->aad_size);

	/* decrypt it */
	return crypto_aead_decrypt(req);
}
