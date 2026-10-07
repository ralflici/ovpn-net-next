/* SPDX-License-Identifier: GPL-2.0-only */
/*  OpenVPN data channel offload
 *
 *  Copyright (C) 2020-2025 OpenVPN, Inc.
 *
 *  Author:	James Yonan <james@openvpn.net>
 *		Antonio Quartulli <antonio@openvpn.net>
 */

#ifndef _NET_OVPN_OVPNCRYPTO_H_
#define _NET_OVPN_OVPNCRYPTO_H_

#include <linux/percpu-refcount.h>
#include <linux/rcupdate.h>
#include <linux/seqlock.h>
#include <linux/workqueue.h>

#include "crypto_epoch.h"
#include "crypto_limits.h"
#include "pktid.h"
#include "proto.h"

/* info needed for both encrypt and decrypt directions */
struct ovpn_key_direction {
	const u8 *cipher_key;
	size_t cipher_key_size;
	const u8 *nonce_tail; /* only needed for GCM modes */
	size_t nonce_tail_size; /* only needed for GCM modes */
};

/* PRK material imported from userspace to derive epoch data keys */
struct ovpn_epoch_prk {
	const u8 *key;
	size_t key_size;
	unsigned int cipher_key_len;
};

/* key material for a primary or secondary slot */
struct ovpn_key_config {
	enum ovpn_cipher_alg cipher_alg;
	u8 key_id;
	bool use_epoch_keys;
	union {
		struct {
			struct ovpn_key_direction encrypt;
			struct ovpn_key_direction decrypt;
		} direct;
		struct {
			struct ovpn_epoch_prk encrypt;
			struct ovpn_epoch_prk decrypt;
		} epoch;
	};
};

/* used to pass settings from netlink to the crypto engine */
struct ovpn_peer_key_reset {
	enum ovpn_key_slot slot;
	struct ovpn_key_config key;
};

/* state for one concrete AEAD key direction */
struct ovpn_key_ctx {
	struct crypto_aead *tfm;
	u8 implicit_iv[OVPN_NONCE_SIZE];
	u16 epoch;
	/* RCU state recorded when this context is unpublished */
	unsigned long rcu_state;
	struct percpu_ref refcount;

	/* allocated after an RX key first authenticates a packet */
	struct ovpn_pktid_recv *pktid_recv;
	struct ovpn_pktid_xmit pktid_xmit ____cacheline_aligned_in_smp;

	atomic64_t xmit_usage;
	/* whether userspace was notified that TX should rekey */
	atomic_t xmit_rekey_notified;
	/* whether userspace was notified of excessive decrypt failures */
	atomic_t decrypt_failure_notified;
	atomic64_t decrypt_failures;

	struct work_struct free_work;
};

struct ovpn_crypto_key_slot {
	__cacheline_group_begin_aligned(fast_path);
	u8 key_id;
	bool epoch_format;
	u16 aad_size;
	u16 payload_offset;
	u16 tail_tag_size;
	enum ovpn_cipher_alg cipher_alg;
	/* highest epoch requested by either the TX or RX path */
	atomic_t tx_epoch_request;

	struct percpu_ref refcount;
	struct ovpn_key_ctx __rcu *encrypt;
	struct ovpn_key_ctx __rcu *decrypt;
	struct ovpn_limit xmit_limit;
	__cacheline_group_end_aligned(fast_path);

	const char *alg_name;
	unsigned long rcu_state;

	struct ovpn_key_ctx __rcu *retiring_key;

	struct ovpn_future_keys future_rx_keys;
	struct ovpn_epoch_key epoch_key_recv;

	struct ovpn_future_keys future_tx_keys;
	struct ovpn_epoch_key epoch_key_send;

	struct work_struct tx_refill;
	struct work_struct rx_refill;

	/* protects encrypt and future_tx_keys */
	spinlock_t tx_lock;
	/* serializes updates to decrypt, retiring_key and future_rx_keys */
	spinlock_t rx_lock;
	/* detects concurrent updates during lockless RX key lookup */
	seqcount_spinlock_t rx_seqcount;

	struct work_struct free_work;
};

static_assert(offsetofend(struct ovpn_crypto_key_slot, xmit_limit) <=
	      SMP_CACHE_BYTES);

struct ovpn_crypto_state {
	struct ovpn_crypto_key_slot __rcu *slots[2];
	u8 primary_idx;
	u8 rx_lane_bits;

	/* protects primary and secondary slots */
	spinlock_t lock;
};

static inline bool ovpn_crypto_key_slot_hold(struct ovpn_crypto_key_slot *ks)
{
	return percpu_ref_tryget_live_rcu(&ks->refcount);
}

static inline void ovpn_crypto_state_init(struct ovpn_crypto_state *cs)
{
	RCU_INIT_POINTER(cs->slots[0], NULL);
	RCU_INIT_POINTER(cs->slots[1], NULL);
	cs->primary_idx = 0;
	cs->rx_lane_bits = 0;
	spin_lock_init(&cs->lock);
}

static inline struct ovpn_crypto_key_slot *
ovpn_crypto_key_id_to_slot(const struct ovpn_crypto_state *cs, u8 key_id)
{
	struct ovpn_crypto_key_slot *ks;
	u8 idx;

	if (unlikely(!cs))
		return NULL;

	rcu_read_lock();
	idx = READ_ONCE(cs->primary_idx);
	ks = rcu_dereference(cs->slots[idx]);
	if (ks && ks->key_id == key_id) {
		if (unlikely(!ovpn_crypto_key_slot_hold(ks)))
			ks = NULL;
		goto out;
	}

	ks = rcu_dereference(cs->slots[!idx]);
	if (ks && ks->key_id == key_id) {
		if (unlikely(!ovpn_crypto_key_slot_hold(ks)))
			ks = NULL;
		goto out;
	}

	/* when both key slots are occupied but no matching key ID is found, ks
	 * has to be reset to NULL to avoid carrying a stale pointer
	 */
	ks = NULL;
out:
	rcu_read_unlock();

	return ks;
}

static inline struct ovpn_crypto_key_slot *
ovpn_crypto_key_slot_primary(const struct ovpn_crypto_state *cs)
{
	struct ovpn_crypto_key_slot *ks;

	rcu_read_lock();
	ks = rcu_dereference(cs->slots[cs->primary_idx]);
	if (unlikely(ks && !ovpn_crypto_key_slot_hold(ks)))
		ks = NULL;
	rcu_read_unlock();

	return ks;
}

void ovpn_crypto_key_slot_release(struct percpu_ref *ref);

static inline void ovpn_crypto_key_slot_put(struct ovpn_crypto_key_slot *ks)
{
	percpu_ref_put(&ks->refcount);
}

/**
 * ovpn_crypto_key_slot_kill - stop new users and drop the initial reference
 * @ks: key slot which has already been unpublished
 *
 * percpu_ref does not guarantee an RCU grace period before release. Record
 * the RCU state after unpublishing the key so the final worker can synchronize
 * with lockless readers without unconditionally starting another grace period.
 */
static inline void ovpn_crypto_key_slot_kill(struct ovpn_crypto_key_slot *ks)
{
	ks->rcu_state = get_state_synchronize_rcu();
	percpu_ref_kill(&ks->refcount);
}

void ovpn_key_ctx_release(struct percpu_ref *ref);

static inline void ovpn_key_ctx_put(struct ovpn_key_ctx *key)
{
	if (key)
		percpu_ref_put(&key->refcount);
}

/**
 * ovpn_key_ctx_kill - stop new users and drop the initial reference
 * @key: key context which has already been unpublished
 *
 * Save the current RCU state so the final worker only waits when readers that
 * could still have seen this context have not completed yet.
 */
static inline void ovpn_key_ctx_kill(struct ovpn_key_ctx *key)
{
	key->rcu_state = get_state_synchronize_rcu();
	percpu_ref_kill(&key->refcount);
}

static inline int ovpn_key_ctx_get(struct ovpn_key_ctx **out,
				   struct ovpn_key_ctx __rcu **rcu_ptr)
{
	struct ovpn_key_ctx *key;

	rcu_read_lock();
	key = rcu_dereference(*rcu_ptr);
	if (unlikely(!key || !percpu_ref_tryget_live_rcu(&key->refcount))) {
		rcu_read_unlock();
		return -ENOKEY;
	}
	rcu_read_unlock();

	*out = key;
	return 0;
}

void ovpn_crypto_key_slot_kill_contexts(struct ovpn_crypto_key_slot *ks);
struct ovpn_pktid_recv *ovpn_key_ctx_replay_state(struct ovpn_key_ctx *key);

int ovpn_crypto_state_reset(struct ovpn_crypto_state *cs,
			    const struct ovpn_peer_key_reset *pkr);

struct ovpn_crypto_key_slot *
ovpn_crypto_key_slot_new(const struct ovpn_key_config *kc);

enum ovpn_cipher_alg ovpn_crypto_key_slot_alg(struct ovpn_crypto_key_slot *ks);

void ovpn_crypto_key_slot_delete(struct ovpn_crypto_state *cs,
				 enum ovpn_key_slot slot);

void ovpn_crypto_state_release(struct ovpn_crypto_state *cs);

void ovpn_crypto_key_slots_swap(struct ovpn_crypto_state *cs);

int ovpn_crypto_config_get(struct ovpn_crypto_state *cs,
			   enum ovpn_key_slot slot,
			   struct ovpn_key_config *keyconf);

bool ovpn_crypto_kill_key(struct ovpn_crypto_state *cs, u8 key_id);

void ovpn_schedule_refill(struct ovpn_crypto_key_slot *ks, bool encrypt);

struct ovpn_key_ctx *
ovpn_key_ctx_create_direct(bool encrypt, const char *alg_name,
			   const struct ovpn_key_direction *dir);

struct ovpn_key_ctx *
ovpn_key_ctx_create_epoch(bool encrypt, const char *alg_name,
			  struct ovpn_epoch_key *epoch_key);

#endif /* _NET_OVPN_OVPNCRYPTO_H_ */
