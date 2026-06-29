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

int ovpn_aead_encrypt(struct ovpn_peer *peer, struct ovpn_crypto_key_slot *ks,
		      struct sk_buff *skb);
int ovpn_aead_encrypt_gso(struct ovpn_peer *peer,
			  struct ovpn_crypto_key_slot *ks,
			  struct sk_buff *skb, struct sk_buff *gso_skb,
			  unsigned int offset, u32 pktid);
int ovpn_aead_decrypt(struct ovpn_peer *peer, struct ovpn_crypto_key_slot *ks,
		      struct sk_buff *skb);

bool ovpn_aead_decrypt_failure_record(struct ovpn_crypto_key_slot *ks);

#endif /* _NET_OVPN_OVPNAEAD_H_ */
