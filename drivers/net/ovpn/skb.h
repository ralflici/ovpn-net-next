/* SPDX-License-Identifier: GPL-2.0-only */
/*  OpenVPN data channel offload
 *
 *  Copyright (C) 2020-2025 OpenVPN, Inc.
 *
 *  Author:	Antonio Quartulli <antonio@openvpn.net>
 *		James Yonan <james@openvpn.net>
 */

#ifndef _NET_OVPN_SKB_H_
#define _NET_OVPN_SKB_H_

#include <linux/atomic.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <linux/types.h>

/**
 * struct ovpn_cb - ovpn skb control block
 * @crypto_tmp: pointer to temporary memory used for crypto operations
 *		containing the IV, the scatter gather list and the aead request
 * @peer: peer used by this crypto operation or owned by this aggregate
 * @ks: crypto key slot used by this operation or owned by this aggregate
 * @tcp_packets: packet count for TCP output, one for ordinary TCP, zero for UDP
 * @payload_offset: offset in the skb where the payload starts
 * @gso_size: received TCP segment payload size, used only after authentication
 * @decrypt_src: TCP stream skb owned until out-of-place decryption completes
 * @nosignal: whether this skb should be sent with the MSG_NOSIGNAL flag (TCP)
 * @batch: UDP GSO aggregate receiving this input skb's encrypted payload
 * @tcp_gso: output skb owned by a single TCP GSO encryption request
 * @batch_state: completion state owned by a UDP GSO aggregate
 */
struct ovpn_cb {
	void *crypto_tmp;
	struct ovpn_peer *peer;
	struct ovpn_crypto_key_slot *ks;
	unsigned int tcp_packets;

	/* Ordinary encryption leaves this union zeroed. A GSO input stores its
	 * output skb; UDP outputs use the same space to coordinate completions.
	 * Decryption and TCP sending use their ordinary fields.
	 */
	union {
		struct {
			unsigned int payload_offset;
			u16 gso_size;
			bool nosignal;
			struct sk_buff *decrypt_src;
		};
		struct sk_buff *batch;
		struct sk_buff *tcp_gso;
		struct {
			atomic_t pending;
			atomic_t failed;
		} batch_state;
	};
};

static inline struct ovpn_cb *ovpn_skb_cb(struct sk_buff *skb)
{
	BUILD_BUG_ON(sizeof(struct ovpn_cb) > sizeof(skb->cb));
	return (struct ovpn_cb *)skb->cb;
}

/* Return IP protocol version from skb header.
 * Return 0 if protocol is not IPv4/IPv6 or cannot be read.
 */
static inline __be16 ovpn_ip_check_protocol(struct sk_buff *skb)
{
	__be16 proto = 0;

	/* skb could be non-linear,
	 * make sure IP header is in non-fragmented part
	 */
	if (!pskb_network_may_pull(skb, sizeof(struct iphdr)))
		return 0;

	if (ip_hdr(skb)->version == 4) {
		proto = htons(ETH_P_IP);
	} else if (ip_hdr(skb)->version == 6) {
		if (!pskb_network_may_pull(skb, sizeof(struct ipv6hdr)))
			return 0;
		proto = htons(ETH_P_IPV6);
	}

	return proto;
}

#endif /* _NET_OVPN_SKB_H_ */
