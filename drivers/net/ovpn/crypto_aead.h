/* SPDX-License-Identifier: GPL-2.0-only */
/*  OpenVPN data channel offload
 *
 *  Copyright (C) 2020-2025 OpenVPN, Inc.
 *
 *  Author:	James Yonan <james@openvpn.net>
 *		Antonio Quartulli <antonio@openvpn.net>
 */

#ifndef _NET_OVPN_OVPNAEAD_H_
#define _NET_OVPN_OVPNAEAD_H_

#include "crypto.h"

#include <asm/types.h>
#include <linux/skbuff.h>

int ovpn_advance_encrypt_key(struct ovpn_crypto_key_slot *ks, u16 target_epoch);
void ovpn_request_encrypt_epoch(struct ovpn_crypto_key_slot *ks,
				unsigned int target_epoch);

int ovpn_aead_encrypt(struct ovpn_peer *peer, struct ovpn_crypto_key_slot *ks,
		      struct sk_buff *skb);
int ovpn_aead_encrypt_gso(struct ovpn_peer *peer,
			  struct ovpn_crypto_key_slot *ks,
			  struct ovpn_key_ctx *key, struct sk_buff *skb,
			  struct sk_buff *gso_skb,
			  unsigned int offset, u64 pktid);
int ovpn_aead_decrypt(struct ovpn_peer *peer, struct ovpn_crypto_key_slot *ks,
		      struct sk_buff *skb);

bool ovpn_aead_decrypt_failure_record(struct ovpn_key_ctx *key);

#endif /* _NET_OVPN_OVPNAEAD_H_ */
