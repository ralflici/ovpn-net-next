/* SPDX-License-Identifier: GPL-2.0-only */
/*  OpenVPN data channel offload
 *
 *  Copyright (C) 2026 OpenVPN, Inc.
 *
 *  Author:	Ralf Lici <ralf@mandelbit.com>
 *		Antonio Quartulli <antonio@openvpn.net>
 */

#ifndef _NET_OVPN_CRYPTO_LIMITS_H_
#define _NET_OVPN_CRYPTO_LIMITS_H_

#include <crypto/aes.h>
#include <linux/atomic.h>
#include <linux/limits.h>
#include <linux/math.h>
#include <linux/types.h>
#include <uapi/linux/ovpn.h>

/* use the OpenVPN/SP 800-38D AES-GCM invocation limit */
#define OVPN_AES_GCM_USAGE_LIMIT ((1ULL << 36) - 1)

/* notify userspace at 7/8 of the AES-GCM hard limit */
#define OVPN_AES_GCM_USAGE_NOTIFY (OVPN_AES_GCM_USAGE_LIMIT / 8 * 7)

struct ovpn_limit {
	u64 soft;
	u64 hard;
};

static inline void
ovpn_key_usage_limit_init(struct ovpn_limit *limit,
			  enum ovpn_cipher_alg cipher_alg)
{
	limit->soft = U64_MAX;
	limit->hard = U64_MAX;

	switch (cipher_alg) {
	case OVPN_CIPHER_ALG_AES_GCM:
		limit->soft = OVPN_AES_GCM_USAGE_NOTIFY;
		limit->hard = OVPN_AES_GCM_USAGE_LIMIT;
		break;
	case OVPN_CIPHER_ALG_CHACHA20_POLY1305:
	default:
		break;
	}
}

static inline int ovpn_key_usage_xmit(atomic64_t *usage,
				      const struct ovpn_limit *limit,
				      unsigned int packets, u64 blocks)
{
	u64 total;

	/* count protected packets and their plaintext blocks */
	total = atomic64_add_return(packets + blocks, usage);

	/* tx must stop before the hard limit is crossed */
	if (unlikely(total > limit->hard))
		return -ERANGE;

	/* soft limits ask the caller to rekey before tx must stop */
	return total > limit->soft;
}

static inline u64 ovpn_aead_limit_blocks(enum ovpn_cipher_alg cipher_alg,
					 unsigned int aad,
					 unsigned int bytes)
{
	switch (cipher_alg) {
	case OVPN_CIPHER_ALG_AES_GCM:
		return DIV_ROUND_UP_ULL(aad, AES_BLOCK_SIZE) +
		       DIV_ROUND_UP_ULL(bytes, AES_BLOCK_SIZE);
	case OVPN_CIPHER_ALG_CHACHA20_POLY1305:
	default:
		return 0;
	}
}

#endif /* _NET_OVPN_CRYPTO_LIMITS_H_ */
