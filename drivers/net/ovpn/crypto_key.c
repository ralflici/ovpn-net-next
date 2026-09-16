// SPDX-License-Identifier: GPL-2.0
/*  OpenVPN data channel offload
 *
 *  Copyright (C) 2026 OpenVPN, Inc.
 *
 *  Author:	Ralf Lici <ralf@mandelbit.com>
 *		Antonio Quartulli <antonio@openvpn.net>
 */

#include <crypto/aead.h>
#include <linux/workqueue.h>

#include "ovpnpriv.h"
#include "crypto.h"
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
		 const struct ovpn_key_direction *dir, bool encrypt)
{
	struct ovpn_limit pktid_limit;
	struct ovpn_key_ctx *key;
	size_t tail_offset;
	int ret;

	key = kmalloc_obj(*key);
	if (!key)
		return ERR_PTR(-ENOMEM);
	key->pktid_recv = NULL;

	/* create the concrete AEAD transform first */
	key->tfm = ovpn_aead_init(title, alg_name, dir->cipher_key,
				  dir->cipher_key_size);
	if (IS_ERR(key->tfm)) {
		ret = PTR_ERR(key->tfm);
		key->tfm = NULL;
		ovpn_key_ctx_free(key);
		return ERR_PTR(ret);
	}

	/* store the implicit IV in a full nonce-sized buffer */
	tail_offset = OVPN_NONCE_SIZE - dir->nonce_tail_size;
	memset(key->implicit_iv, 0, sizeof(key->implicit_iv));
	memcpy(key->implicit_iv + tail_offset, dir->nonce_tail,
	       dir->nonce_tail_size);

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

/* destroy initialized contexts while unwinding an unpublished slot */
static void ovpn_crypto_key_slot_destroy(struct ovpn_crypto_key_slot *ks)
{
	struct ovpn_key_ctx *key;

	key = rcu_access_pointer(ks->encrypt);
	if (key) {
		percpu_ref_exit(&key->refcount);
		ovpn_key_ctx_free(key);
	}

	key = rcu_access_pointer(ks->decrypt);
	if (key) {
		percpu_ref_exit(&key->refcount);
		ovpn_key_ctx_free(key);
	}
}

/* the slot's final release proves that no context users remain */
void ovpn_crypto_key_slot_kill_contexts(struct ovpn_crypto_key_slot *ks)
{
	ovpn_key_ctx_kill(rcu_access_pointer(ks->encrypt));
	ovpn_key_ctx_kill(rcu_access_pointer(ks->decrypt));
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
	kfree(ks);
}

struct ovpn_crypto_key_slot *
ovpn_crypto_key_slot_new(const struct ovpn_key_config *kc)
{
	struct ovpn_crypto_key_slot *ks = NULL;
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

	if (kc->encrypt.nonce_tail_size != OVPN_NONCE_TAIL_SIZE ||
	    kc->decrypt.nonce_tail_size != OVPN_NONCE_TAIL_SIZE)
		return ERR_PTR(-EINVAL);

	/* build the key slot */
	ks = kmalloc_obj(*ks);
	if (!ks)
		return ERR_PTR(-ENOMEM);

	RCU_INIT_POINTER(ks->encrypt, NULL);
	RCU_INIT_POINTER(ks->decrypt, NULL);
	INIT_WORK(&ks->free_work, ovpn_crypto_key_slot_free_work);
	ks->key_id = kc->key_id;
	ks->cipher_alg = kc->cipher_alg;
	ks->epoch_format = false;
	ks->aad_size = OVPN_AEAD_DIRECT_AAD_SIZE;
	ks->pktid_size = OVPN_NONCE_WIRE_SIZE;
	ovpn_key_usage_limit_init(&ks->xmit_limit, kc->cipher_alg);

	key = ovpn_key_ctx_new("encrypt", alg_name, &kc->encrypt, true);
	if (IS_ERR(key)) {
		ret = PTR_ERR(key);
		goto destroy_ks;
	}
	RCU_INIT_POINTER(ks->encrypt, key);

	key = ovpn_key_ctx_new("decrypt", alg_name, &kc->decrypt, false);
	if (IS_ERR(key)) {
		ret = PTR_ERR(key);
		goto destroy_ks;
	}
	RCU_INIT_POINTER(ks->decrypt, key);

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
