/* SPDX-License-Identifier: GPL-2.0-only */
/*  OpenVPN data channel offload
 *
 *  Copyright (C) 2020-2025 OpenVPN, Inc.
 *
 *  Author:	Antonio Quartulli <antonio@openvpn.net>
 *		James Yonan <james@openvpn.net>
 */

#ifndef _NET_OVPN_OVPNPKTID_H_
#define _NET_OVPN_OVPNPKTID_H_

#include "crypto_limits.h"
#include "proto.h"

/* If no packets received for this length of time, set a backtrack floor
 * at highest received packet ID thus far.
 */
#define PKTID_RECV_EXPIRE (30 * HZ)

/* notify userspace when the packet ID space is close to wrapping */
#define PKTID_XMIT_REKEY_NOTIFY 0xff000000U

/* Packet-ID state for transmitter */
struct ovpn_pktid_xmit {
	atomic_t seq_num;
};

/* replay window sizing in bytes = 2^REPLAY_WINDOW_ORDER */
#define REPLAY_WINDOW_ORDER 8

#define REPLAY_WINDOW_BYTES BIT(REPLAY_WINDOW_ORDER)
#define REPLAY_WINDOW_SIZE  (REPLAY_WINDOW_BYTES * 8)
#define REPLAY_INDEX(base, i) (((base) + (i)) & (REPLAY_WINDOW_SIZE - 1))

/* Packet-ID state for receiver.
 * Other than lock member, can be zeroed to initialize.
 */
struct ovpn_pktid_recv {
	/* "sliding window" bitmask of recent packet IDs received */
	DECLARE_BITMAP(history, REPLAY_WINDOW_SIZE);
	/* bit position of deque base in history */
	unsigned int base;
	/* extent (in bits) of deque in history */
	unsigned int extent;
	/* expiration of history in jiffies */
	unsigned long expire;
	/* highest sequence number received */
	u32 id;
	/* highest time stamp received */
	u32 time;
	/* we will only accept backtrack IDs > id_floor */
	u32 id_floor;
	unsigned int max_backtrack;
	/* protects entire pktd ID state */
	spinlock_t lock;
};

/**
 * ovpn_pktid_xmit_next - allocate a transmit packet ID
 * @pid: transmit packet ID state
 * @pktid: location where the generated packet ID is stored
 *
 * The returned packet ID becomes part of the AEAD nonce, so the helper rejects
 * the packet before the 32-bit packet-ID space wraps.
 *
 * Crossing the soft threshold does not reject the packet. It returns 1 so the
 * caller can request a rekey while packet-ID space remains.
 *
 * Return: 1 if userspace should be notified, 0 if no notification is needed,
 * or a negative error code otherwise.
 */
static inline int ovpn_pktid_xmit_next(struct ovpn_pktid_xmit *pid, u32 *pktid)
{
	const u32 seq_num = atomic_fetch_add_unless(&pid->seq_num, 1, 0);

	/* packet IDs are used to create cipher IVs and must not wrap */
	if (unlikely(!seq_num))
		return -ERANGE;

	*pktid = seq_num;

	return seq_num >= PKTID_XMIT_REKEY_NOTIFY;
}

/**
 * ovpn_pktid_xmit_range - reserve consecutive packet IDs
 * @pid: transmit packet-ID state
 * @count: non-zero number of IDs to reserve
 * @pktid: first reserved packet ID
 *
 * The reservation is all-or-nothing. If the requested range would cross the
 * end of the 32-bit packet-ID space, exhaust the state without returning the
 * unused tail. Packet IDs can be skipped but never reused as an AEAD IV.
 *
 * Return: 0 on success or -ERANGE when no complete range remains
 */
static inline int ovpn_pktid_xmit_range(struct ovpn_pktid_xmit *pid,
					unsigned int count, u32 *pktid)
{
	int old = atomic_read(&pid->seq_num);
	u32 first, next;
	bool fits;

	for (;;) {
		first = (u32)old;
		next = first + count;

		/* space is already exhausted */
		if (unlikely(!first))
			return -ERANGE;

		fits = count - 1 <= U32_MAX - first;
		/* if it doesn't fit we still have to publish exhaustion (0)
		 * so concurrent allocators stop using this key
		 */
		if (unlikely(!fits))
			next = 0;

		/* if another CPU changed the state, we retry using the new
		 * seq_num value
		 */
		if (!atomic_try_cmpxchg(&pid->seq_num, &old, (int)next))
			continue;

		if (unlikely(!fits))
			return -ERANGE;

		*pktid = first;
		return 0;
	}
}

/* Write 12-byte AEAD IV to dest */
static inline void ovpn_pktid_aead_write(const u32 pktid,
					 const u8 nt[],
					 unsigned char *dest)
{
	*(__force __be32 *)(dest) = htonl(pktid);
	BUILD_BUG_ON(4 + OVPN_NONCE_TAIL_SIZE != OVPN_NONCE_SIZE);
	memcpy(dest + 4, nt, OVPN_NONCE_TAIL_SIZE);
}

void ovpn_pktid_xmit_init(struct ovpn_pktid_xmit *pid);
void ovpn_pktid_recv_init(struct ovpn_pktid_recv *pr);

int ovpn_pktid_recv(struct ovpn_pktid_recv *pr, u32 pkt_id, u32 pkt_time);

#endif /* _NET_OVPN_OVPNPKTID_H_ */
