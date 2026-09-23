/* SPDX-License-Identifier: GPL-2.0-only */
/*  OpenVPN data channel offload
 *
 *  Copyright (C) 2020-2025 OpenVPN, Inc.
 *
 *  Author:	James Yonan <james@openvpn.net>
 *		Antonio Quartulli <antonio@openvpn.net>
 *		Lev Stipakov <lev@openvpn.net>
 */

#ifndef _NET_OVPN_OVPNSTATS_H_
#define _NET_OVPN_OVPNSTATS_H_

#include <linux/netdevice.h>

static inline void
ovpn_peer_stats_increment_rx(struct pcpu_sw_netstats __percpu *stats,
			     const unsigned int n)
{
	struct pcpu_sw_netstats *s;

	lockdep_assert_in_softirq();
	s = this_cpu_ptr(stats);
	u64_stats_update_begin(&s->syncp);
	u64_stats_add(&s->rx_bytes, n);
	u64_stats_inc(&s->rx_packets);
	u64_stats_update_end(&s->syncp);
}

static inline void
ovpn_peer_stats_add_tx(struct pcpu_sw_netstats __percpu *stats,
		       const unsigned int bytes, unsigned int packets)
{
	struct pcpu_sw_netstats *s;

	lockdep_assert_in_softirq();
	s = this_cpu_ptr(stats);
	u64_stats_update_begin(&s->syncp);
	u64_stats_add(&s->tx_bytes, bytes);
	u64_stats_add(&s->tx_packets, packets);
	u64_stats_update_end(&s->syncp);
}

static inline void
ovpn_peer_stats_increment_tx(struct pcpu_sw_netstats __percpu *stats,
			     const unsigned int n)
{
	ovpn_peer_stats_add_tx(stats, n, 1);
}

static inline void ovpn_dev_dstats_tx_dropped(struct net_device *dev,
					      unsigned int packets)
{
	local_bh_disable();
	while (packets--)
		dev_dstats_tx_dropped(dev);
	local_bh_enable();
}

static inline void ovpn_dev_dstats_rx_dropped(struct net_device *dev)
{
	local_bh_disable();
	dev_dstats_rx_dropped(dev);
	local_bh_enable();
}

#endif /* _NET_OVPN_OVPNSTATS_H_ */
