// SPDX-License-Identifier: GPL-2.0
/*  OpenVPN data channel offload
 *
 *  Copyright (C) 2026 OpenVPN, Inc.
 *
 *  Author:	Ralf Lici <ralf@mandelbit.com>
 *		Antonio Quartulli <antonio@openvpn.net>
 */

#include <crypto/hash.h>
#include <linux/unaligned.h>

#include "crypto_epoch.h"
#include "proto.h"

#define OVPN_EPOCH_DATA_KEY_LABEL "data_key"
#define OVPN_EPOCH_DATA_IV_LABEL "data_iv"
#define OVPN_EPOCH_UPDATE_LABEL "datakey upd"
#define OVPN_EPOCH_LABEL_PREFIX "ovpn "
#define OVPN_EPOCH_INFO_MAX_SIZE 21

#define OVPN_EPOCH_HASH_ALG "hmac(sha256)"

static int ovpn_hkdf_expand(struct crypto_shash *shash, const u8 *info,
			    size_t info_len, u8 *okm, size_t okm_len)
{
	unsigned int prev_len = 0, digest_len;
	SHASH_DESC_ON_STACK(desc, shash);
	u8 prev[OVPN_EPOCH_PRK_SIZE];
	size_t copied = 0, todo;
	u8 counter = 1;
	int ret = 0;

	digest_len = crypto_shash_digestsize(shash);
	if (WARN_ON_ONCE(digest_len != sizeof(prev)))
		return -EINVAL;

	desc->tfm = shash;

	/* T(0) is the empty string */
	while (copied < okm_len) {
		/* T(n) = HMAC-Hash(PRK, T(n-1) | info | n) */
		ret = crypto_shash_init(desc);
		if (ret)
			goto out;
		ret = crypto_shash_update(desc, prev, prev_len);
		if (ret)
			goto out;
		ret = crypto_shash_update(desc, info, info_len);
		if (ret)
			goto out;
		ret = crypto_shash_update(desc, &counter, sizeof(counter));
		if (ret)
			goto out;
		ret = crypto_shash_final(desc, prev);
		if (ret)
			goto out;

		prev_len = digest_len;
		/* copy a full digest block or the final partial block */
		todo = min_t(size_t, digest_len, okm_len - copied);
		memcpy(okm + copied, prev, todo);
		copied += todo;
		counter++;
	}

out:
	memzero_explicit(prev, sizeof(prev));
	shash_desc_zero(desc);
	return ret;
}

struct crypto_shash *ovpn_epoch_init_key(const u8 *key, size_t key_size)
{
	struct crypto_shash *shash;
	int ret;

	shash = crypto_alloc_shash(OVPN_EPOCH_HASH_ALG, 0, 0);
	if (IS_ERR(shash))
		return shash;

	if (key_size != crypto_shash_digestsize(shash)) {
		crypto_free_shash(shash);
		return ERR_PTR(-EINVAL);
	}

	/* store the PRK as the shash key so it can be advanced in place */
	ret = crypto_shash_setkey(shash, key, key_size);
	if (ret) {
		crypto_free_shash(shash);
		return ERR_PTR(ret);
	}

	return shash;
}

static int ovpn_expand_label(struct crypto_shash *shash, const u8 *label,
			     size_t label_len, u8 *okm, u16 okm_len)
{
	static const u8 label_prefix[] = OVPN_EPOCH_LABEL_PREFIX;
	u8 prefix_len = sizeof(label_prefix) - 1, full_len;
	u8 info[OVPN_EPOCH_INFO_MAX_SIZE];
	u16 info_len;
	int ret;

	if (WARN_ON_ONCE(!label_len || label_len > 250))
		return -EINVAL;

	full_len = prefix_len + label_len;
	info_len = sizeof(okm_len) + full_len + 2;
	if (WARN_ON_ONCE(info_len > sizeof(info)))
		return -EINVAL;

	/* encode length, "ovpn " label and empty context */
	put_unaligned_be16(okm_len, info);
	info[2] = full_len;
	memcpy(&info[3], label_prefix, prefix_len);
	memcpy(&info[3 + prefix_len], label, label_len);
	info[3 + full_len] = 0;

	ret = ovpn_hkdf_expand(shash, info, info_len, okm, okm_len);
	memzero_explicit(info, info_len);

	return ret;
}

/**
 * ovpn_epoch_derive_next_prk - derive the next epoch PRK
 * @epoch_key: PRK derivation state
 * @next_prk: destination for the next PRK
 *
 * Epoch data keys are derived from a per-direction PRK. Advancing from E_N to
 * E_N+1 uses OVPN-Expand-Label(E_N, "datakey upd", "", 32).
 *
 * Return: 0 on success or a negative error code otherwise.
 */
int ovpn_epoch_derive_next_prk(const struct ovpn_epoch_key *epoch_key,
			       u8 next_prk[])
{
	if (unlikely(epoch_key->epoch == OVPN_MAX_EPOCH))
		return -ERANGE;

	if (WARN_ON_ONCE(OVPN_EPOCH_PRK_SIZE !=
			 crypto_shash_digestsize(epoch_key->shash)))
		return -EINVAL;

	return ovpn_expand_label(epoch_key->shash, OVPN_EPOCH_UPDATE_LABEL,
				 sizeof(OVPN_EPOCH_UPDATE_LABEL) - 1,
				 next_prk, OVPN_EPOCH_PRK_SIZE);
}

int ovpn_epoch_set_prk(struct ovpn_epoch_key *epoch_key, const u8 prk[],
		       u16 epoch)
{
	int ret;

	ret = crypto_shash_setkey(epoch_key->shash, prk, OVPN_EPOCH_PRK_SIZE);
	if (ret)
		return ret;

	epoch_key->epoch = epoch;

	return 0;
}

/**
 * ovpn_epoch_iterate - advance an epoch PRK to the next epoch
 * @epoch_key: PRK derivation state
 *
 * Epoch data keys are derived from a per-direction PRK. Advancing from E_N to
 * E_N+1 uses OVPN-Expand-Label(E_N, "datakey upd", "", 32).
 *
 * Return: 0 on success or a negative error code otherwise.
 */
int ovpn_epoch_iterate(struct ovpn_epoch_key *epoch_key)
{
	u8 key[OVPN_EPOCH_PRK_SIZE];
	int ret;

	ret = ovpn_epoch_derive_next_prk(epoch_key, key);
	if (ret)
		goto out;

	/* expose the next epoch only after its PRK is installed */
	ret = ovpn_epoch_set_prk(epoch_key, key, epoch_key->epoch + 1);

out:
	memzero_explicit(key, sizeof(key));
	return ret;
}

/**
 * ovpn_epoch_derive_key - derive the concrete AEAD key for an epoch
 * @epoch_key: PRK derivation state
 * @cipher_key: destination for the AEAD cipher key
 * @implicit_iv: destination for the AEAD implicit IV
 *
 * K_i is OVPN-Expand-Label(E_i, "data_key", "", key_size), while the implicit
 * IV is OVPN-Expand-Label(E_i, "data_iv", "", OVPN_NONCE_SIZE).
 *
 * Return: 0 on success or a negative error code otherwise.
 */
int ovpn_epoch_derive_key(const struct ovpn_epoch_key *epoch_key,
			  u8 cipher_key[], u8 implicit_iv[])
{
	int ret;

	if (WARN_ON_ONCE(!epoch_key->cipher_key_len ||
			 epoch_key->cipher_key_len > OVPN_EPOCH_PRK_SIZE))
		return -EINVAL;

	/* derive the concrete AEAD key for the current epoch */
	ret = ovpn_expand_label(epoch_key->shash, OVPN_EPOCH_DATA_KEY_LABEL,
				sizeof(OVPN_EPOCH_DATA_KEY_LABEL) - 1,
				cipher_key, epoch_key->cipher_key_len);
	if (ret)
		return ret;

	/* derive the implicit IV paired with that AEAD key */
	return ovpn_expand_label(epoch_key->shash, OVPN_EPOCH_DATA_IV_LABEL,
				 sizeof(OVPN_EPOCH_DATA_IV_LABEL) - 1,
				 implicit_iv, OVPN_NONCE_SIZE);
}
