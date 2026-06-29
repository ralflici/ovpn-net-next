// SPDX-License-Identifier: GPL-2.0
/*  OpenVPN data channel offload
 *
 *  Copyright (C) 2026 OpenVPN, Inc.
 *
 *  Author:	Ralf Lici <ralf@mandelbit.com>
 *		Antonio Quartulli <antonio@openvpn.net>
 */

#include <crypto/aead.h>
#include <crypto/hash.h>
#include <linux/workqueue.h>

#include "ovpnpriv.h"
#include "crypto.h"
#include "crypto_epoch.h"
#include "pktid.h"
#include "proto.h"

#define ALG_NAME_AES		"gcm(aes)"
#define ALG_NAME_CHACHAPOLY	"rfc7539(chacha20,poly1305)"

/* initialize a struct crypto_aead object */
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

	ret = crypto_aead_setauthsize(aead, OVPN_AEAD_TAG_SIZE);
	if (ret) {
		pr_err("%s crypto_aead_setauthsize failed, err=%d\n", title,
		       ret);
		goto error;
	}

	/* Basic AEAD assumption: all current algorithms use OVPN_NONCE_SIZE.
	 * ovpn_aead_crypto_tmp_size and ovpn_aead_encrypt/decrypt expect this.
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

static void ovpn_key_ctx_free_state(struct ovpn_key_ctx *key)
{
	kfree(key->pktid_recv);
	if (key->tfm)
		crypto_free_aead(key->tfm);
	memzero_explicit(key->implicit_iv, sizeof(key->implicit_iv));
}

static void ovpn_key_ctx_free(struct ovpn_key_ctx *key)
{
	if (!key)
		return;

	ovpn_key_ctx_free_state(key);
	kfree(key);
}

static void ovpn_key_ctx_free_work(struct work_struct *work)
{
	struct ovpn_key_ctx *key;

	key = container_of(work, struct ovpn_key_ctx, free_work);
	/* the context may have been replaced independently of its key slot */
	cond_synchronize_rcu(key->rcu_state);
	percpu_ref_exit(&key->refcount);
	ovpn_key_ctx_free_state(key);
	kfree(key);
}

void ovpn_key_ctx_release(struct percpu_ref *ref)
{
	struct ovpn_key_ctx *key;

	key = container_of(ref, struct ovpn_key_ctx, refcount);
	queue_work(ovpn_wq, &key->free_work);
}

/**
 * ovpn_key_ctx_replay_state - return replay state for an authenticated packet
 * @key: receive key context that authenticated the packet
 *
 * Replay state is allocated only after a receive key authenticates traffic.
 * Concurrent completions can reach this function for the same key, so only
 * the first allocation is installed and the others are discarded.
 *
 * Return: replay state on success or NULL if allocation failed
 */
struct ovpn_pktid_recv *
ovpn_key_ctx_replay_state(struct ovpn_key_ctx *key)
{
	struct ovpn_pktid_recv *new, *recv;

	/* pairs with the cmpxchg below */
	recv = READ_ONCE(key->pktid_recv);
	if (likely(recv))
		return recv;

	/* this key has no replay state yet so allocate it now */
	new = kmalloc_obj(*new, GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(!new))
		return NULL;

	ovpn_pktid_recv_init(new);
	/* another completion may have installed state while this one
	 * allocated
	 */
	recv = cmpxchg(&key->pktid_recv, NULL, new);
	if (recv)
		kfree(new);
	else
		recv = new;

	return recv;
}

static struct ovpn_key_ctx *
ovpn_key_ctx_new(const char *title, const char *alg_name,
		 const u8 *cipher_key, unsigned int cipher_key_len,
		 const u8 *implicit_iv, u16 epoch, bool encrypt)
{
	struct ovpn_limit pktid_limit;
	struct ovpn_key_ctx *key;
	int ret;

	key = kmalloc_obj(*key);
	if (!key)
		return ERR_PTR(-ENOMEM);
	key->pktid_recv = NULL;

	/* create the concrete AEAD transform first */
	key->tfm = ovpn_aead_init(title, alg_name, cipher_key, cipher_key_len);
	if (IS_ERR(key->tfm)) {
		ret = PTR_ERR(key->tfm);
		key->tfm = NULL;
		ovpn_key_ctx_free(key);
		return ERR_PTR(ret);
	}

	/* store the implicit IV in a full nonce-sized buffer */
	key->epoch = epoch;
	memcpy(key->implicit_iv, implicit_iv, sizeof(key->implicit_iv));

	INIT_WORK(&key->free_work, ovpn_key_ctx_free_work);
	if (encrypt) {
		ovpn_pktid_xmit_limit_init(&pktid_limit, false);
		ovpn_pktid_xmit_init(&key->pktid_xmit, &pktid_limit);
		atomic64_set(&key->xmit_usage, 0);
		atomic_set(&key->xmit_rekey_notified, 0);
	} else {
		atomic64_set(&key->decrypt_failures, 0);
		atomic_set(&key->decrypt_failure_notified, 0);
	}

	ret = percpu_ref_init(&key->refcount, ovpn_key_ctx_release, 0,
			      GFP_KERNEL);
	if (ret) {
		ovpn_key_ctx_free(key);
		return ERR_PTR(ret);
	}

	return key;
}

/* destroy an initialized context which has never been published */
static void ovpn_key_ctx_destroy(struct ovpn_key_ctx *key)
{
	percpu_ref_exit(&key->refcount);
	ovpn_key_ctx_free(key);
}

struct ovpn_key_ctx *
ovpn_key_ctx_create_direct(bool encrypt, const char *alg_name,
			   const struct ovpn_key_direction *dir)
{
	u8 implicit_iv[OVPN_NONCE_SIZE];
	struct ovpn_key_ctx *key;
	size_t tail_offset;

	tail_offset = OVPN_NONCE_SIZE - dir->nonce_tail_size;
	memset(implicit_iv, 0, sizeof(implicit_iv));
	memcpy(implicit_iv + tail_offset, dir->nonce_tail,
	       dir->nonce_tail_size);

	key = ovpn_key_ctx_new(encrypt ? "encrypt" : "decrypt", alg_name,
			       dir->cipher_key, dir->cipher_key_size,
			       implicit_iv, 0, encrypt);
	memzero_explicit(implicit_iv, sizeof(implicit_iv));

	return key;
}

struct ovpn_key_ctx *
ovpn_key_ctx_create_epoch(bool encrypt, const char *alg_name,
			  struct ovpn_epoch_key *epoch_key)
{
	u8 cipher_key[OVPN_EPOCH_PRK_SIZE], implicit_iv[OVPN_NONCE_SIZE];
	struct ovpn_key_ctx *key;
	int ret;

	ret = ovpn_epoch_derive_key(epoch_key, cipher_key, implicit_iv);
	if (ret) {
		key = ERR_PTR(ret);
		goto out;
	}

	key = ovpn_key_ctx_new(encrypt ? "encrypt" : "decrypt", alg_name,
			       cipher_key, epoch_key->cipher_key_len,
			       implicit_iv, epoch_key->epoch, encrypt);

out:
	memzero_explicit(cipher_key, sizeof(cipher_key));
	memzero_explicit(implicit_iv, sizeof(implicit_iv));

	return key;
}

static int
ovpn_epoch_init_future_keys(bool encrypt, const char *alg_name,
			    struct ovpn_epoch_key *epoch_key,
			    struct ovpn_future_keys *future_keys)
{
	struct ovpn_key_ctx *key;
	int ret;
	u16 i;

	future_keys->head = 0;
	future_keys->tail = 0;
	future_keys->full = false;

	/* each generated key advances the PRK and stores the next epoch */
	for (i = 0; i < OVPN_EPOCH_FUTURE_KEYS_COUNT; i++) {
		ret = ovpn_epoch_iterate(epoch_key);
		if (ret)
			goto err;

		key = ovpn_key_ctx_create_epoch(encrypt, alg_name, epoch_key);
		if (IS_ERR(key)) {
			ret = PTR_ERR(key);
			goto err;
		}

		RCU_INIT_POINTER(future_keys->keys[future_keys->head], key);
		future_keys->head = (future_keys->head + 1) %
				    OVPN_EPOCH_FUTURE_KEYS_COUNT;
	}

	future_keys->full = true;
	return 0;

err:
	for (i = 0; i < OVPN_EPOCH_FUTURE_KEYS_COUNT; i++) {
		key = rcu_access_pointer(future_keys->keys[i]);
		RCU_INIT_POINTER(future_keys->keys[i], NULL);
		if (key)
			ovpn_key_ctx_destroy(key);
	}
	future_keys->head = 0;
	future_keys->tail = 0;
	future_keys->full = false;

	return ret;
}

void ovpn_schedule_refill(struct ovpn_crypto_key_slot *ks, bool encrypt)
{
	struct work_struct *work = encrypt ? &ks->tx_refill : &ks->rx_refill;

	if (!ovpn_crypto_key_slot_hold(ks))
		return;

	if (!queue_work(ovpn_wq, work))
		ovpn_crypto_key_slot_put(ks);
}

static void ovpn_refill_future_buffer(struct ovpn_crypto_key_slot *ks,
				      bool encrypt)
{
	struct ovpn_key_ctx *new_futures[OVPN_EPOCH_FUTURE_KEYS_COUNT];
	struct ovpn_key_ctx *old_futures[OVPN_EPOCH_FUTURE_KEYS_COUNT];
	u16 replaced = 0, created = 0, free_slots, i;
	const struct ovpn_epoch_key *source_key;
	struct ovpn_epoch_key scratch_key = {};
	size_t prk_size = OVPN_EPOCH_PRK_SIZE;
	struct ovpn_future_keys *future_keys;
	struct ovpn_epoch_key *epoch_key;
	struct ovpn_key_ctx __rcu **slot;
	u8 next_prk[OVPN_EPOCH_PRK_SIZE];
	/* selected tx/rx future-key ring lock */
	spinlock_t *lock;
	bool full;
	int ret;

	/* select the tx or rx future-key state */
	if (encrypt) {
		future_keys = &ks->future_tx_keys;
		epoch_key = &ks->epoch_key_send;
		lock = &ks->tx_lock;
	} else {
		future_keys = &ks->future_rx_keys;
		epoch_key = &ks->epoch_key_recv;
		lock = &ks->rx_lock;
	}

	/* calculate how many keys are needed to refill the ring */
	spin_lock_bh(lock);
	free_slots = OVPN_EPOCH_FUTURE_KEYS_COUNT -
		     ovpn_epoch_future_keys_count(future_keys);
	spin_unlock_bh(lock);

	if (!free_slots)
		return;

	/* derive new keys without holding the ring lock */
	scratch_key.cipher_key_len = epoch_key->cipher_key_len;
	for (created = 0; created < free_slots; created++) {
		source_key = scratch_key.shash ? &scratch_key : epoch_key;
		ret = ovpn_epoch_derive_next_prk(source_key, next_prk);
		if (ret)
			goto err;

		if (!scratch_key.shash) {
			scratch_key.shash = ovpn_epoch_init_key(next_prk,
								prk_size);
			if (IS_ERR(scratch_key.shash)) {
				ret = PTR_ERR(scratch_key.shash);
				scratch_key.shash = NULL;
				goto err;
			}
			scratch_key.epoch = epoch_key->epoch + 1;
		} else {
			ret = ovpn_epoch_set_prk(&scratch_key, next_prk,
						 scratch_key.epoch + 1);
			if (ret)
				goto err;
		}

		new_futures[created] =
			ovpn_key_ctx_create_epoch(encrypt, ks->alg_name,
						  &scratch_key);
		if (IS_ERR(new_futures[created])) {
			ret = PTR_ERR(new_futures[created]);
			goto err;
		}
	}

	ret = ovpn_epoch_set_prk(epoch_key, next_prk, scratch_key.epoch);
	if (ret)
		goto err;

	/* insert generated keys under the selected ring lock */
	spin_lock_bh(lock);
	if (!encrypt)
		write_seqcount_begin(&ks->rx_seqcount);
	for (replaced = 0; replaced < created; replaced++) {
		if (WARN_ON_ONCE(future_keys->full))
			break;

		/* the ring remains monotonic and consecutive */
		slot = &future_keys->keys[future_keys->head];
		old_futures[replaced] =
			rcu_dereference_protected(*slot, lockdep_is_held(lock));
		rcu_assign_pointer(*slot, new_futures[replaced]);
		future_keys->head = (future_keys->head + 1) %
				    OVPN_EPOCH_FUTURE_KEYS_COUNT;
		if (future_keys->head == future_keys->tail)
			future_keys->full = true;
	}
	full = future_keys->full;
	if (!encrypt)
		write_seqcount_end(&ks->rx_seqcount);
	spin_unlock_bh(lock);

	for (i = 0; i < replaced; i++) {
		if (old_futures[i])
			ovpn_key_ctx_kill(old_futures[i]);
	}
	for (i = replaced; i < created; i++)
		ovpn_key_ctx_destroy(new_futures[i]);

	crypto_free_shash(scratch_key.shash);
	memzero_explicit(next_prk, sizeof(next_prk));

	/* keep refilling until the ring is full */
	if (!full)
		ovpn_schedule_refill(ks, encrypt);

	return;

err:
	for (i = 0; i < created; i++)
		ovpn_key_ctx_destroy(new_futures[i]);
	if (scratch_key.shash)
		crypto_free_shash(scratch_key.shash);
	memzero_explicit(next_prk, sizeof(next_prk));
}

static void ovpn_refill_future_buffer_tx(struct work_struct *work)
{
	struct ovpn_crypto_key_slot *ks;

	ks = container_of(work, struct ovpn_crypto_key_slot, tx_refill);
	ovpn_refill_future_buffer(ks, true);
	ovpn_crypto_key_slot_put(ks);
}

static void ovpn_refill_future_buffer_rx(struct work_struct *work)
{
	struct ovpn_crypto_key_slot *ks;

	ks = container_of(work, struct ovpn_crypto_key_slot, rx_refill);
	ovpn_refill_future_buffer(ks, false);
	ovpn_crypto_key_slot_put(ks);
}

static void ovpn_crypto_key_slot_free_state(struct ovpn_crypto_key_slot *ks)
{
	if (ks->epoch_format) {
		if (ks->epoch_key_send.shash)
			crypto_free_shash(ks->epoch_key_send.shash);
		if (ks->epoch_key_recv.shash)
			crypto_free_shash(ks->epoch_key_recv.shash);
	}
}

/* destroy contexts while unwinding a slot which was never published */
static void ovpn_crypto_key_slot_destroy(struct ovpn_crypto_key_slot *ks)
{
	struct ovpn_key_ctx *key;
	u8 i;

	key = rcu_access_pointer(ks->encrypt);
	if (key)
		ovpn_key_ctx_destroy(key);
	key = rcu_access_pointer(ks->decrypt);
	if (key)
		ovpn_key_ctx_destroy(key);

	if (ks->epoch_format) {
		key = rcu_access_pointer(ks->retiring_key);
		if (key)
			ovpn_key_ctx_destroy(key);
		for (i = 0; i < OVPN_EPOCH_FUTURE_KEYS_COUNT; i++) {
			key = rcu_access_pointer(ks->future_tx_keys.keys[i]);
			if (key)
				ovpn_key_ctx_destroy(key);
			key = rcu_access_pointer(ks->future_rx_keys.keys[i]);
			if (key)
				ovpn_key_ctx_destroy(key);
		}
	}

	ovpn_crypto_key_slot_free_state(ks);
}

/* the slot's final release proves that no context users remain */
void ovpn_crypto_key_slot_kill_contexts(struct ovpn_crypto_key_slot *ks)
{
	struct ovpn_key_ctx *key;
	u8 i;

	ovpn_key_ctx_kill(rcu_access_pointer(ks->encrypt));
	ovpn_key_ctx_kill(rcu_access_pointer(ks->decrypt));

	if (!ks->epoch_format)
		return;

	key = rcu_access_pointer(ks->retiring_key);
	if (key)
		ovpn_key_ctx_kill(key);
	for (i = 0; i < OVPN_EPOCH_FUTURE_KEYS_COUNT; i++) {
		key = rcu_access_pointer(ks->future_tx_keys.keys[i]);
		if (key)
			ovpn_key_ctx_kill(key);
		key = rcu_access_pointer(ks->future_rx_keys.keys[i]);
		if (key)
			ovpn_key_ctx_kill(key);
	}
}

static void ovpn_crypto_key_slot_free_work(struct work_struct *work)
{
	struct ovpn_crypto_key_slot *ks;

	ks = container_of(work, struct ovpn_crypto_key_slot, free_work);
	/* Reaching this worker means every reference held by packet processing
	 * and asynchronous crypto has been returned. Separately wait for any
	 * RCU-only reader which observed the slot before it was unpublished.
	 */
	cond_synchronize_rcu(ks->rcu_state);
	percpu_ref_exit(&ks->refcount);
	ovpn_crypto_key_slot_free_state(ks);
	kfree(ks);
}

static int ovpn_epoch_key_init(struct ovpn_epoch_key *epoch_key,
			       const struct ovpn_epoch_prk *prk)
{
	int ret;

	epoch_key->shash = ovpn_epoch_init_key(prk->key, prk->key_size);
	if (IS_ERR(epoch_key->shash)) {
		ret = PTR_ERR(epoch_key->shash);
		epoch_key->shash = NULL;
		return ret;
	}

	/* epoch 0 is reserved for direct keys, so epoch keys start at 1 */
	epoch_key->epoch = 1;
	epoch_key->cipher_key_len = prk->cipher_key_len;

	return 0;
}

struct ovpn_crypto_key_slot *
ovpn_crypto_key_slot_new(const struct ovpn_key_config *kc)
{
	struct ovpn_crypto_key_slot *ks = NULL;
	unsigned int direct_payload_offset;
	struct ovpn_key_ctx *key;
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

	if (!kc->use_epoch_keys) {
		if (kc->direct.encrypt.nonce_tail_size !=
		    OVPN_NONCE_TAIL_SIZE ||
		    kc->direct.decrypt.nonce_tail_size !=
		    OVPN_NONCE_TAIL_SIZE)
			return ERR_PTR(-EINVAL);
	} else if (!kc->epoch.encrypt.cipher_key_len ||
		   kc->epoch.encrypt.cipher_key_len > OVPN_EPOCH_PRK_SIZE ||
		   kc->epoch.decrypt.cipher_key_len !=
		   kc->epoch.encrypt.cipher_key_len) {
		return ERR_PTR(-EINVAL);
	}
	/* build the key slot */
	ks = kzalloc(sizeof(*ks), GFP_KERNEL);
	if (!ks)
		return ERR_PTR(-ENOMEM);

	direct_payload_offset =
		ovpn_aead_direct_payload_offset(OVPN_AEAD_TAG_SIZE);

	RCU_INIT_POINTER(ks->encrypt, NULL);
	RCU_INIT_POINTER(ks->decrypt, NULL);
	INIT_WORK(&ks->free_work, ovpn_crypto_key_slot_free_work);
	ks->key_id = kc->key_id;
	ks->cipher_alg = kc->cipher_alg;
	ks->alg_name = alg_name;
	ks->epoch_format = kc->use_epoch_keys;
	ks->aad_size = kc->use_epoch_keys ? OVPN_AEAD_EPOCH_AAD_SIZE :
					     OVPN_AEAD_DIRECT_AAD_SIZE;
	ks->payload_offset = kc->use_epoch_keys ?
			     OVPN_AEAD_EPOCH_AAD_SIZE :
			     direct_payload_offset;
	ks->tail_tag_size = kc->use_epoch_keys ? OVPN_AEAD_TAG_SIZE : 0;
	ovpn_key_usage_limit_init(&ks->xmit_limit, kc->cipher_alg);

	if (kc->use_epoch_keys) {
		/* tx and rx PRKs advance independently */
		ret = ovpn_epoch_key_init(&ks->epoch_key_send,
					  &kc->epoch.encrypt);
		if (ret)
			goto destroy_ks;

		INIT_WORK(&ks->tx_refill, ovpn_refill_future_buffer_tx);
		spin_lock_init(&ks->tx_lock);
		key = ovpn_key_ctx_create_epoch(true, alg_name,
						&ks->epoch_key_send);
	} else {
		key = ovpn_key_ctx_create_direct(true, alg_name,
						 &kc->direct.encrypt);
	}
	if (IS_ERR(key)) {
		ret = PTR_ERR(key);
		goto destroy_ks;
	}
	RCU_INIT_POINTER(ks->encrypt, key);

	if (kc->use_epoch_keys) {
		ret = ovpn_epoch_key_init(&ks->epoch_key_recv,
					  &kc->epoch.decrypt);
		if (ret)
			goto destroy_ks;

		INIT_WORK(&ks->rx_refill, ovpn_refill_future_buffer_rx);
		spin_lock_init(&ks->rx_lock);
		seqcount_spinlock_init(&ks->rx_seqcount, &ks->rx_lock);
		key = ovpn_key_ctx_create_epoch(false, alg_name,
						&ks->epoch_key_recv);
	} else {
		key = ovpn_key_ctx_create_direct(false, alg_name,
						 &kc->direct.decrypt);
	}
	if (IS_ERR(key)) {
		ret = PTR_ERR(key);
		goto destroy_ks;
	}
	RCU_INIT_POINTER(ks->decrypt, key);

	RCU_INIT_POINTER(ks->retiring_key, NULL);
	if (kc->use_epoch_keys) {
		/* prederive future keys outside the fast path */
		ret = ovpn_epoch_init_future_keys(true, alg_name,
						  &ks->epoch_key_send,
						  &ks->future_tx_keys);
		if (ret)
			goto destroy_ks;

		ret = ovpn_epoch_init_future_keys(false, alg_name,
						  &ks->epoch_key_recv,
						  &ks->future_rx_keys);
		if (ret)
			goto destroy_ks;
	}

	ret = percpu_ref_init(&ks->refcount, ovpn_crypto_key_slot_release, 0,
			      GFP_KERNEL);
	if (ret < 0)
		goto destroy_ks;

	return ks;

destroy_ks:
	ovpn_crypto_key_slot_destroy(ks);
	kfree(ks);
	return ERR_PTR(ret);
}

enum ovpn_cipher_alg ovpn_crypto_key_slot_alg(struct ovpn_crypto_key_slot *ks)
{
	if (!ks)
		return OVPN_CIPHER_ALG_NONE;

	return ks->cipher_alg;
}
