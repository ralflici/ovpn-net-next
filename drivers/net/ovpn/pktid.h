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
#include <linux/cache.h>
#include <linux/unaligned.h>

/* If no packets received for this length of time, set a backtrack floor
 * at highest received packet ID thus far.
 */
#define PKTID_RECV_EXPIRE (30 * HZ)

/* notify userspace when the packet ID space is close to wrapping */
#define PKTID_XMIT_REKEY_NOTIFY 0xff000000U
#define PKTID_DIRECT_MAX U32_MAX
#define PKTID_EPOCH_MASK GENMASK_ULL(63, 48)
#define PKTID_EPOCH_COUNTER_MASK GENMASK_ULL(47, 0)
#define PKTID_EPOCH_COUNTER_MAX FIELD_MAX(PKTID_EPOCH_COUNTER_MASK)

/* A lane-enabled epoch counter uses the upper 12 bits as a lane ID and
 * leaves a 36-bit sequence in each lane. Keep this split independent of the
 * cipher so every negotiated lane format has the same packet-ID layout.
 */
#define PKTID_EPOCH_LANE_BITS 12
#define PKTID_EPOCH_LANE_MASK GENMASK_ULL(47, 36)
#define PKTID_EPOCH_LANE_MAX FIELD_MAX(PKTID_EPOCH_LANE_MASK)
#define PKTID_EPOCH_LANE_SEQ_MASK GENMASK_ULL(35, 0)
#define PKTID_EPOCH_LANE_SEQ_MAX FIELD_MAX(PKTID_EPOCH_LANE_SEQ_MASK)

/* Packet-ID state for transmitter */
struct ovpn_pktid_xmit {
	atomic64_t seq_num;
	struct ovpn_limit limit;
};

/* keep independently updated transmit lanes on separate cache lines */
struct ovpn_xmit_lane {
	atomic64_t seq_num;
	atomic64_t usage_credit;
} ____cacheline_aligned_in_smp;

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
		limit->hard = PKTID_EPOCH_COUNTER_MAX;
	} else {
		limit->soft = PKTID_XMIT_REKEY_NOTIFY;
		limit->hard = PKTID_DIRECT_MAX;
	}
}

static inline u64 ovpn_pktid_epoch_lane_compose(u16 lane, u64 seq)
{
	return FIELD_PREP(PKTID_EPOCH_LANE_MASK, lane) |
	       FIELD_PREP(PKTID_EPOCH_LANE_SEQ_MASK, seq);
}

static inline u16 ovpn_pktid_epoch_lane(u64 counter)
{
	return FIELD_GET(PKTID_EPOCH_LANE_MASK, counter);
}

static inline u64 ovpn_pktid_epoch_lane_seq(u64 counter)
{
	return FIELD_GET(PKTID_EPOCH_LANE_SEQ_MASK, counter);
}

static inline bool ovpn_pktid_epoch_lane_valid(u64 counter, u8 lane_bits)
{
	u16 lane;

	if (!lane_bits)
		return true;

	lane = ovpn_pktid_epoch_lane(counter);
	return lane < BIT(lane_bits) && ovpn_pktid_epoch_lane_seq(counter);
}

/**
 * ovpn_pktid_xmit_reserve - reserve consecutive transmit packet IDs
 * @seq_num: atomic counter to reserve from
 * @soft: threshold that requests a key change
 * @hard: last usable counter value
 * @count: non-zero number of IDs to reserve
 * @pktid: location where the first reserved packet ID is stored
 *
 * The returned packet IDs become part of AEAD nonces. Reusing them would reuse
 * IVs, so the reservation is all-or-nothing and exhausts the state if the
 * complete range does not fit in the configured packet-ID space.
 *
 * The hard limit stops TX. Crossing the soft limit returns 1 so the caller can
 * arrange fresh key material before that happens.
 *
 * Return: 1 when the reservation crosses the soft limit, 0 otherwise, or
 * -ERANGE when the complete range cannot be reserved
 */
static inline int ovpn_pktid_xmit_reserve(atomic64_t *seq_num, u64 soft,
					  u64 hard, unsigned int count,
					  u64 *pktid)
{
	s64 old = atomic64_read(seq_num);
	u64 first, next;
	bool fits;

	for (;;) {
		first = (u64)old;
		next = first + count;

		/* packet IDs create cipher IVs and must not wrap */
		if (unlikely(!old || first > hard))
			return -ERANGE;

		fits = count - 1 <= hard - first;
		/* publish exhaustion if the complete range does not fit so
		 * concurrent allocators stop using this key
		 */
		if (unlikely(!fits))
			next = 0;

		/* ID allocation only requires atomicity, not ordering */
		if (!atomic64_try_cmpxchg_relaxed(seq_num, &old, (s64)next))
			continue;

		if (unlikely(!fits))
			return -ERANGE;

		*pktid = first;
		return first <= soft && soft - first < count;
	}
}

static inline void
ovpn_xmit_lane_init(struct ovpn_xmit_lane *lane)
{
	atomic64_set(&lane->seq_num, 1);
	atomic64_set(&lane->usage_credit, 0);
}

/* write the AEAD IV to dest */
static inline u64 ovpn_pktid_aead_write(u16 epoch, u64 seq,
					const u8 implicit_iv[],
					unsigned char *dest)
{
	/* epoch packets carry a 16-bit epoch and 48-bit counter */
	u64 pktid = FIELD_PREP(PKTID_EPOCH_MASK, epoch) |
		    FIELD_PREP(PKTID_EPOCH_COUNTER_MASK, seq);

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
		return FIELD_GET(PKTID_EPOCH_COUNTER_MASK, pktid);
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
