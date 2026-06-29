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

#include <linux/bitfield.h>
#include <linux/unaligned.h>

/* If no packets received for this length of time, set a backtrack floor
 * at highest received packet ID thus far.
 */
#define PKTID_RECV_EXPIRE (30 * HZ)

/* notify userspace when the packet ID space is close to wrapping */
#define PKTID_XMIT_REKEY_NOTIFY 0xff000000U
#define PKTID_DIRECT_MAX U32_MAX
#define PKTID_EPOCH_SEQ_MAX GENMASK_ULL(47, 0)
#define PKTID_EPOCH_MASK GENMASK_ULL(63, 48)
#define PKTID_EPOCH_SEQ_MASK GENMASK_ULL(47, 0)

/* Packet-ID state for transmitter */
struct ovpn_pktid_xmit {
	atomic64_t seq_num;
	struct ovpn_limit limit;
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
	u64 id;
	/* highest time stamp received */
	u32 time;
	/* we will only accept backtrack IDs > id_floor */
	u64 id_floor;
	u64 max_backtrack;
	/* protects entire pktd ID state */
	spinlock_t lock;
};

static inline void ovpn_pktid_xmit_limit_init(struct ovpn_limit *limit,
					      bool epoch_format)
{
	if (epoch_format) {
		limit->soft = U64_MAX;
		limit->hard = PKTID_EPOCH_SEQ_MAX;
	} else {
		limit->soft = PKTID_XMIT_REKEY_NOTIFY;
		limit->hard = PKTID_DIRECT_MAX;
	}
}

/**
 * ovpn_pktid_xmit_next - allocate a transmit packet ID
 * @pid: transmit packet ID state
 * @pktid: location where the generated packet ID is stored
 *
 * The returned packet ID becomes part of the AEAD nonce. Reusing it would
 * reuse an IV, so the helper rejects the packet before the configured packet-ID
 * space wraps.
 *
 * The hard limit stops TX. Crossing the soft limit returns 1 so the caller can
 * arrange a fresh key before that happens.
 *
 * Return: 1 if userspace should be notified, 0 if no notification is needed,
 * or a negative error code otherwise.
 */
static inline int ovpn_pktid_xmit_next(struct ovpn_pktid_xmit *pid, u64 *pktid)
{
	s64 seq_num = atomic64_read(&pid->seq_num);

	for (;;) {
		/* packet IDs create cipher IVs and must not wrap */
		if (unlikely(!seq_num || (u64)seq_num > pid->limit.hard))
			return -ERANGE;

		/* ID allocation only requires atomicity, not ordering */
		if (atomic64_try_cmpxchg_relaxed(&pid->seq_num, &seq_num,
						 seq_num + 1))
			break;
	}

	*pktid = seq_num;

	return (u64)seq_num >= pid->limit.soft;
}

/**
 * ovpn_pktid_xmit_range - reserve consecutive packet IDs
 * @pid: transmit packet-ID state
 * @count: non-zero number of IDs to reserve
 * @pktid: first reserved packet ID
 *
 * The reservation is all-or-nothing. If the requested range would cross the
 * configured packet-ID space, exhaust the state without returning the unused
 * tail. Packet IDs can be skipped but never reused as an AEAD IV.
 *
 * Return: 1 if the range crosses the soft packet-ID threshold, 0 if it does
 * not, or -ERANGE when no complete range remains
 */
static inline int ovpn_pktid_xmit_range(struct ovpn_pktid_xmit *pid,
					unsigned int count, u64 *pktid)
{
	s64 old = atomic64_read(&pid->seq_num);
	u64 first, next;
	bool fits;

	for (;;) {
		first = (u64)old;
		next = first + count;

		/* space is already exhausted */
		if (unlikely(!old || first > pid->limit.hard))
			return -ERANGE;

		fits = count - 1 <= pid->limit.hard - first;
		/* if it doesn't fit we still have to publish exhaustion (0)
		 * so concurrent allocators stop using this key
		 */
		if (unlikely(!fits))
			next = 0;

		/* if another CPU changed the state, we retry using the new
		 * seq_num value
		 */
		if (!atomic64_try_cmpxchg_relaxed(&pid->seq_num, &old,
						  (s64)next))
			continue;

		if (unlikely(!fits))
			return -ERANGE;

		*pktid = first;
		return first <= pid->limit.soft &&
		       pid->limit.soft - first < count;
	}
}

/* write the AEAD IV to dest */
static inline u64 ovpn_pktid_aead_write(u16 epoch, u64 seq,
					const u8 implicit_iv[],
					unsigned char *dest)
{
	/* epoch packets carry a 16-bit epoch and 48-bit counter */
	u64 pktid = FIELD_PREP(PKTID_EPOCH_MASK, epoch) |
		    FIELD_PREP(PKTID_EPOCH_SEQ_MASK, seq);

	if (epoch) {
		u64 iv_head = get_unaligned_be64(implicit_iv);

		put_unaligned_be64(pktid ^ iv_head, dest);
		memcpy(dest + OVPN_EPOCH_NONCE_WIRE_SIZE,
		       implicit_iv + OVPN_EPOCH_NONCE_WIRE_SIZE,
		       OVPN_NONCE_SIZE - OVPN_EPOCH_NONCE_WIRE_SIZE);
		return pktid;
	}

	put_unaligned_be32(seq, dest);
	memcpy(dest + OVPN_NONCE_WIRE_SIZE,
	       implicit_iv + OVPN_NONCE_WIRE_SIZE, OVPN_NONCE_TAIL_SIZE);

	return seq;
}

static inline u64 ovpn_pktid_read(const u8 *buf, bool epoch_format,
				  u16 *epoch)
{
	u64 pktid;

	if (epoch_format) {
		pktid = get_unaligned_be64(buf);
		*epoch = FIELD_GET(PKTID_EPOCH_MASK, pktid);
		return FIELD_GET(PKTID_EPOCH_SEQ_MASK, pktid);
	}

	*epoch = 0;
	return get_unaligned_be32(buf);
}

static inline void ovpn_pktid_wire_write(u8 *buf, bool epoch_format,
					 u64 pktid)
{
	if (epoch_format)
		put_unaligned_be64(pktid, buf);
	else
		put_unaligned_be32(pktid, buf);
}

void ovpn_pktid_xmit_init(struct ovpn_pktid_xmit *pid,
			  const struct ovpn_limit *limit);
void ovpn_pktid_recv_init(struct ovpn_pktid_recv *pr);

int ovpn_pktid_recv(struct ovpn_pktid_recv *pr, u64 pkt_id, u32 pkt_time);

#endif /* _NET_OVPN_OVPNPKTID_H_ */
