// SPDX-License-Identifier: GPL-2.0
/*  OpenVPN data channel offload
 *
 *  Copyright (C) 2019-2025 OpenVPN, Inc.
 *
 *  Author:	James Yonan <james@openvpn.net>
 *		Antonio Quartulli <antonio@openvpn.net>
 */

#include <crypto/aead.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <net/gro_cells.h>
#include <net/gso.h>
#include <net/ip.h>
#include <net/sock.h>
#include <net/udp.h>

#include "ovpnpriv.h"
#include "peer.h"
#include "io.h"
#include "bind.h"
#include "crypto.h"
#include "crypto_aead.h"
#include "netlink.h"
#include "proto.h"
#include "tcp.h"
#include "udp.h"
#include "skb.h"
#include "socket.h"

const unsigned char ovpn_keepalive_message[OVPN_KEEPALIVE_SIZE] = {
	0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb,
	0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48
};

/* Leave room for the largest outer network header. The strict inequality in
 * is_skb_forwardable also requires staying one byte below gso_max_size.
 */
#define OVPN_UDP_GSO_MAX_PAYLOAD	(GSO_LEGACY_MAX_SIZE -		\
					 sizeof(struct ipv6hdr) -	\
					 sizeof(struct udphdr) - 1)
/**
 * ovpn_is_keepalive - check if skb contains a keepalive message
 * @skb: packet to check
 *
 * Assumes that the first byte of skb->data is defined.
 *
 * Return: true if skb contains a keepalive or false otherwise
 */
static bool ovpn_is_keepalive(struct sk_buff *skb)
{
	if (*skb->data != ovpn_keepalive_message[0])
		return false;

	if (skb->len != OVPN_KEEPALIVE_SIZE)
		return false;

	if (!pskb_may_pull(skb, OVPN_KEEPALIVE_SIZE))
		return false;

	return !memcmp(skb->data, ovpn_keepalive_message, OVPN_KEEPALIVE_SIZE);
}

/* Called after decrypt to write the IP packet to the device.
 * This method is expected to manage/free the skb.
 */
static void ovpn_netdev_write(struct ovpn_peer *peer, struct sk_buff *skb)
{
	unsigned int pkt_len;
	int ret;

	/* the transport encapsulation and its GSO metadata do not describe the
	 * decrypted inner packet
	 */
	skb->encapsulation = 0;
	skb_gso_reset(skb);

	/* we can't guarantee the packet wasn't corrupted before entering the
	 * VPN, therefore we give other layers a chance to check that
	 */
	skb->ip_summed = CHECKSUM_NONE;

	/* skb hash for transport packet no longer valid after decapsulation */
	skb_clear_hash(skb);

	/* post-decrypt scrub -- prepare to inject encapsulated packet onto the
	 * interface, based on __skb_tunnel_rx() in dst.h
	 */
	skb->dev = peer->ovpn->dev;
	skb_set_queue_mapping(skb, 0);
	skb_scrub_packet(skb, true);

	/* network header reset in ovpn_decrypt_post() */
	skb_reset_mac_header(skb);
	skb_reset_transport_header(skb);
	skb_reset_inner_headers(skb);

	/* cause packet to be "received" by the interface */
	pkt_len = skb->len;
	/* we may get here in process context in case of TCP connections,
	 * therefore we have to disable BHs to ensure gro_cells_receive()
	 * and dev_dstats_rx_add() do not get corrupted or enter deadlock
	 */
	local_bh_disable();
	ret = gro_cells_receive(&peer->ovpn->gro_cells, skb);
	if (likely(ret == NET_RX_SUCCESS)) {
		/* update RX stats with the size of decrypted packet */
		ovpn_peer_stats_increment_rx(peer->vpn_stats, pkt_len);
		dev_dstats_rx_add(peer->ovpn->dev, pkt_len);
	}
	local_bh_enable();
}

static void ovpn_rx_request_tx_rotation(struct ovpn_crypto_key_slot *ks,
					const struct ovpn_key_ctx *decrypt)
{
	struct ovpn_key_ctx *current_decrypt, *encrypt;

	rcu_read_lock();
	current_decrypt = rcu_dereference(ks->decrypt);
	encrypt = rcu_dereference(ks->encrypt);
	/* only current rx key usage can ask the peer to move forward */
	if (decrypt == current_decrypt &&
	    (!encrypt || decrypt->epoch >= encrypt->epoch))
		ovpn_request_encrypt_epoch(ks, decrypt->epoch + 1);
	rcu_read_unlock();
}

/**
 * ovpn_advance_decrypt_key - promote RX to a target epoch
 * @ks: key slot containing RX epoch state
 * @target_epoch: authenticated epoch to promote RX to
 *
 * RX promotion consumes future keys up to @target_epoch, moves the closest
 * previous epoch to the retiring slot for reordered packets, and schedules
 * refill for the consumed future-key slots. Local TX is advanced as well so
 * outbound packets signal the peer to leave older epochs.
 *
 * Return: 0 on success, -EINPROGRESS if the RX lock is busy, -EALREADY if RX
 * is already at or beyond @target_epoch, or -EINVAL if the future ring cannot
 * provide @target_epoch.
 */
static int ovpn_advance_decrypt_key(struct ovpn_crypto_key_slot *ks,
				    u16 target_epoch)
{
	u16 stale_count = 0, advance, count, index, stale_index, i;
	struct ovpn_key_ctx *stale[OVPN_EPOCH_FUTURE_KEYS_COUNT];
	struct ovpn_key_ctx *old_decrypt, *new_decrypt, *future;
	struct ovpn_key_ctx *old_retiring, *new_retiring;
	struct ovpn_key_ctx __rcu **retire_slot, **slot;
	u16 retire_index;

	/* concurrent promotion or refill means another context is moving rx */
	if (unlikely(!spin_trylock_bh(&ks->rx_lock)))
		return -EINPROGRESS;
	lockdep_assert_held(&ks->rx_lock);

	old_retiring = rcu_dereference_protected(ks->retiring_key, 1);
	old_decrypt = rcu_dereference_protected(ks->decrypt, 1);
	/* current decrypt key is always installed while the slot is alive */
	if (unlikely(target_epoch <= old_decrypt->epoch)) {
		spin_unlock_bh(&ks->rx_lock);
		return -EALREADY;
	}

	count = ovpn_epoch_future_keys_count(&ks->future_rx_keys);
	advance = target_epoch - old_decrypt->epoch;
	/* authenticated epoch must be available in the future ring */
	if (unlikely(count < advance)) {
		spin_unlock_bh(&ks->rx_lock);
		return -EINVAL;
	}

	/* get the authenticated future key from the ring */
	index = (ks->future_rx_keys.tail + advance - 1) %
		OVPN_EPOCH_FUTURE_KEYS_COUNT;
	slot = &ks->future_rx_keys.keys[index];
	new_decrypt = rcu_dereference_protected(*slot, 1);
	if (WARN_ON_ONCE(!new_decrypt ||
			 new_decrypt->epoch != target_epoch)) {
		spin_unlock_bh(&ks->rx_lock);
		return -EINVAL;
	}

	new_retiring = old_decrypt;
	if (unlikely(advance > 1)) {
		/* keep target_epoch - 1 for reordered packets after jumps */
		retire_index = (ks->future_rx_keys.tail + advance - 2) %
			       OVPN_EPOCH_FUTURE_KEYS_COUNT;
		retire_slot = &ks->future_rx_keys.keys[retire_index];
		new_retiring = rcu_dereference_protected(*retire_slot, 1);
		if (WARN_ON_ONCE(!new_retiring ||
				 new_retiring->epoch != target_epoch - 1)) {
			spin_unlock_bh(&ks->rx_lock);
			return -EINVAL;
		}
	}

	write_seqcount_begin(&ks->rx_seqcount);
	for (i = 0; i < advance; i++) {
		/* drop skipped future keys when advancing past them */
		stale_index = (ks->future_rx_keys.tail + i) %
			      OVPN_EPOCH_FUTURE_KEYS_COUNT;
		slot = &ks->future_rx_keys.keys[stale_index];
		future = rcu_dereference_protected(*slot, 1);
		if (future != new_decrypt && future != new_retiring)
			stale[stale_count++] = future;
		RCU_INIT_POINTER(*slot, NULL);
	}

	/* keep the nearest previous rx key for reordered packets */
	rcu_assign_pointer(ks->retiring_key, new_retiring);
	rcu_assign_pointer(ks->decrypt, new_decrypt);
	ks->future_rx_keys.tail = (ks->future_rx_keys.tail + advance) %
				  OVPN_EPOCH_FUTURE_KEYS_COUNT;
	ks->future_rx_keys.full = false;
	write_seqcount_end(&ks->rx_seqcount);
	spin_unlock_bh(&ks->rx_lock);

	ovpn_schedule_refill(ks, false);
	if (old_retiring)
		ovpn_key_ctx_kill(old_retiring);
	if (new_retiring != old_decrypt)
		ovpn_key_ctx_kill(old_decrypt);
	for (i = 0; i < stale_count; i++)
		ovpn_key_ctx_kill(stale[i]);

	/* remember the target so tx can retry if promotion cannot complete */
	ovpn_request_encrypt_epoch(ks, target_epoch);
	/* move local tx forward to signal the peer to advance as well */
	ovpn_advance_encrypt_key(ks, target_epoch);

	return 0;
}

/**
 * ovpn_check_rotate_keys - promote RX after authenticating a future epoch
 * @peer: peer that supplied the authenticated packet
 * @ks: key slot containing RX epoch state
 * @decrypt: key that authenticated the packet
 *
 * Current and retiring keys do not move RX state. A future key is promoted only
 * after authentication has completed, which prevents unauthenticated packets
 * from forcing epoch advancement.
 *
 * Return: 0 if no fatal rotation error occurred, -ERANGE if epoch space is
 * exhausted and userspace must install fresh key material.
 */
static int ovpn_check_rotate_keys(struct ovpn_peer *peer,
				  struct ovpn_crypto_key_slot *ks,
				  struct ovpn_key_ctx *decrypt)
{
	struct ovpn_key_ctx *current_decrypt;
	u16 target_epoch;
	int ret;

	if (!ks->epoch_format)
		return 0;

	/* current key means no promotion is needed */
	current_decrypt = rcu_access_pointer(ks->decrypt);
	if (likely(decrypt == current_decrypt))
		return 0;

	/* take a stable reference to distinguish retiring from future keys */
	if (unlikely(ovpn_key_ctx_get(&current_decrypt, &ks->decrypt)))
		return 0;
	/* retiring or older packets do not move rx forward */
	if (likely(decrypt->epoch <= current_decrypt->epoch)) {
		ovpn_key_ctx_put(current_decrypt);
		return 0;
	}
	ovpn_key_ctx_put(current_decrypt);

	target_epoch = decrypt->epoch;
	/* keep enough epoch space for the future-key ring after promotion */
	if (unlikely(target_epoch + OVPN_EPOCH_FUTURE_KEYS_COUNT >=
		     OVPN_MAX_EPOCH))
		return -ERANGE;

	/* a future key is promoted only after successful authentication */
	ret = ovpn_advance_decrypt_key(ks, target_epoch);
	if (unlikely(ret == -EALREADY || ret == -EINPROGRESS))
		return 0;
	if (unlikely(ret))
		net_warn_ratelimited("%s: decrypt: cannot advance key to epoch %u\n",
				     netdev_name(peer->ovpn->dev),
				     target_epoch);

	return 0;
}

void ovpn_decrypt_post(void *data, int ret)
{
	struct ovpn_pktid_recv *pktid_recv;
	struct ovpn_crypto_key_slot *ks;
	unsigned int payload_offset = 0;
	struct sk_buff *skb = data;
	struct ovpn_socket *sock;
	struct ovpn_key_ctx *key;
	u64 pktid;
	struct ovpn_peer *peer;
	int payload_len;
	u16 pkt_epoch;
	__be16 proto;

	/* crypto is happening asynchronously. this function will be called
	 * again later by the crypto callback with a proper return code
	 */
	if (unlikely(ret == -EINPROGRESS))
		return;

	payload_offset = ovpn_skb_cb(skb)->payload_offset;
	ks = ovpn_skb_cb(skb)->ks;
	key = ovpn_skb_cb(skb)->key;
	peer = ovpn_skb_cb(skb)->peer;

	/* crypto is done, cleanup skb CB and its members */
	kfree(ovpn_skb_cb(skb)->crypto_tmp);

	if (unlikely(ret == -EBADMSG)) {
		if (key && unlikely(ovpn_aead_decrypt_failure_record(key))) {
			if (!ks->epoch_format)
				ovpn_nl_key_swap_notify(peer, ks->key_id);
			else
				ovpn_rx_request_tx_rotation(ks, key);
		}
		goto drop;
	}

	if (unlikely(ret < 0))
		goto drop;

	/* retrieve or allocate the replay state */
	pktid_recv = ovpn_key_ctx_replay_state(key);
	if (unlikely(!pktid_recv))
		goto drop;

	pktid = ovpn_pktid_read(skb->data + OVPN_OPCODE_SIZE,
				ks->epoch_format, &pkt_epoch);
	ret = ovpn_pktid_recv(pktid_recv, pktid, 0);
	if (unlikely(ret < 0)) {
		net_err_ratelimited("%s: PKT ID RX error for peer %u: %d\n",
				    netdev_name(peer->ovpn->dev), peer->id,
				    ret);
		goto drop;
	}

	if (unlikely(skb->len < payload_offset))
		goto drop;
	payload_len = skb->len - payload_offset;
	if (ks->tail_tag_size) {
		if (unlikely(payload_len < ks->tail_tag_size))
			goto drop;
		payload_len -= ks->tail_tag_size;
	}
	if (unlikely(payload_len < 0))
		goto drop;

	if (unlikely(ovpn_check_rotate_keys(peer, ks, key) < 0)) {
		if (ovpn_crypto_kill_key(&peer->crypto, ks->key_id))
			ovpn_nl_key_swap_notify(peer, ks->key_id);
		goto drop;
	}

	if (ks->tail_tag_size &&
	    unlikely(pskb_trim(skb, skb->len - ks->tail_tag_size)))
		goto drop;
	/* keep track of last received authenticated packet for keepalive */
	WRITE_ONCE(peer->last_recv, ktime_get_boottime_seconds());

	rcu_read_lock();
	sock = rcu_dereference(peer->sock);
	if (sock && sock->sk->sk_protocol == IPPROTO_UDP)
		/* check if this peer changed local or remote endpoint */
		ovpn_peer_endpoints_update(peer, skb);
	rcu_read_unlock();

	/* point to encapsulated IP packet */
	__skb_pull(skb, payload_offset);

	/* check if this is a valid datapacket that has to be delivered to the
	 * ovpn interface
	 */
	skb_reset_network_header(skb);
	proto = ovpn_ip_check_protocol(skb);
	if (unlikely(!proto)) {
		/* check if null packet */
		if (unlikely(!pskb_may_pull(skb, 1))) {
			net_info_ratelimited("%s: NULL packet received from peer %u\n",
					     netdev_name(peer->ovpn->dev),
					     peer->id);
			goto drop;
		}

		if (ovpn_is_keepalive(skb)) {
			net_dbg_ratelimited("%s: ping received from peer %u\n",
					    netdev_name(peer->ovpn->dev),
					    peer->id);
			/* we drop the packet, but this is not a failure */
			consume_skb(skb);
			goto drop_nocount;
		}

		net_info_ratelimited("%s: unsupported protocol received from peer %u\n",
				     netdev_name(peer->ovpn->dev), peer->id);
		goto drop;
	}
	skb->protocol = proto;

	/* perform Reverse Path Filtering (RPF) */
	if (unlikely(!ovpn_peer_check_by_src(peer->ovpn, skb, peer))) {
		if (skb->protocol == htons(ETH_P_IPV6))
			net_dbg_ratelimited("%s: RPF dropped packet from peer %u, src: %pI6c\n",
					    netdev_name(peer->ovpn->dev),
					    peer->id, &ipv6_hdr(skb)->saddr);
		else
			net_dbg_ratelimited("%s: RPF dropped packet from peer %u, src: %pI4\n",
					    netdev_name(peer->ovpn->dev),
					    peer->id, &ip_hdr(skb)->saddr);
		goto drop;
	}

	ovpn_netdev_write(peer, skb);
	/* skb is passed to upper layer - don't free it */
	skb = NULL;
drop:
	if (unlikely(skb))
		ovpn_dev_dstats_rx_dropped(peer->ovpn->dev);
	kfree_skb(skb);
drop_nocount:
	ovpn_key_ctx_put(key);
	if (likely(ks))
		ovpn_crypto_key_slot_put(ks);
	if (likely(peer))
		ovpn_peer_put(peer);
}

/* RX path entry point: decrypt packet and forward it to the device */
void ovpn_recv(struct ovpn_peer *peer, struct sk_buff *skb)
{
	struct ovpn_crypto_key_slot *ks;
	u8 key_id;

	local_bh_disable();
	ovpn_peer_stats_increment_rx(peer->link_stats, skb->len);
	local_bh_enable();

	/* get the key slot matching the key ID in the received packet */
	key_id = ovpn_key_id_from_skb(skb);
	ks = ovpn_crypto_key_id_to_slot(&peer->crypto, key_id);
	if (unlikely(!ks)) {
		net_info_ratelimited("%s: no available key for peer %u, key-id: %u\n",
				     netdev_name(peer->ovpn->dev), peer->id,
				     key_id);
		ovpn_dev_dstats_rx_dropped(peer->ovpn->dev);
		kfree_skb(skb);
		ovpn_peer_put(peer);
		return;
	}

	memset(ovpn_skb_cb(skb), 0, sizeof(struct ovpn_cb));
	ovpn_decrypt_post(skb, ovpn_aead_decrypt(peer, ks, skb));
}

static void ovpn_encrypt_key_exhausted(struct ovpn_peer *peer,
				       struct ovpn_crypto_key_slot *ks)
{
	netdev_warn(peer->ovpn->dev, "killing key %u for peer %u\n",
		    ks->key_id, peer->id);
	if (ovpn_crypto_kill_key(&peer->crypto, ks->key_id))
		/* let userspace know so that a new key must be negotiated */
		ovpn_nl_key_swap_notify(peer, ks->key_id);
}

void ovpn_encrypt_post(void *data, int ret)
{
	unsigned int orig_len, packets = 1;
	struct ovpn_crypto_key_slot *ks;
	struct sk_buff *skb = data;
	struct ovpn_socket *sock;
	struct ovpn_cb *batch_cb;
	struct ovpn_key_ctx *key;
	struct ovpn_peer *peer;
	struct sk_buff *batch;

	/* encryption is happening asynchronously. This function will be
	 * called later by the crypto callback with a proper return value
	 */
	if (unlikely(ret == -EINPROGRESS))
		return;

	/* ordinary encryption leaves batch zeroed; a GSO input uses it to find
	 * the aggregate whose lifetime is shared by all segment requests
	 */
	batch = ovpn_skb_cb(skb)->batch;
	peer = ovpn_skb_cb(skb)->peer;
	ks = ovpn_skb_cb(skb)->ks;
	key = batch ? ovpn_skb_cb(batch)->key : ovpn_skb_cb(skb)->key;

	/* crypto is done, cleanup skb CB and its members */
	kfree(ovpn_skb_cb(skb)->crypto_tmp);

	if (unlikely(ret == -ERANGE)) {
		/* we ran out of IVs and we must kill the key as it can't be
		 * used anymore
		 */
		ovpn_encrypt_key_exhausted(peer, ks);
	}

	if (batch) {
		batch_cb = ovpn_skb_cb(batch);
		/* every segment publishes its result before releasing its
		 * pending count and only the final completion continues with
		 * the aggregate
		 */
		if (unlikely(ret < 0))
			atomic_set(&batch_cb->batch_state.failed, 1);

		kfree_skb(skb);
		if (!atomic_dec_and_test(&batch_cb->batch_state.pending))
			return;

		skb = batch;
		packets = skb_shinfo(batch)->gso_segs;
		if (unlikely(atomic_read(&batch_cb->batch_state.failed)))
			goto err;

		/* reaching the final callback with no sticky failure means
		 * every segment completed successfully
		 */
		ret = 0;
	}

	if (unlikely(ret < 0))
		goto err;

	skb_mark_not_on_list(skb);
	orig_len = skb->len;

	rcu_read_lock();
	sock = rcu_dereference(peer->sock);
	if (unlikely(!sock))
		goto err_unlock;

	switch (sock->sk->sk_protocol) {
	case IPPROTO_UDP:
		ovpn_udp_send_skb(peer, sock->sk, skb);
		break;
	case IPPROTO_TCP:
		ovpn_tcp_send_skb(peer, sock->sk, skb);
		break;
	default:
		/* no transport configured yet */
		goto err_unlock;
	}

	ovpn_peer_stats_add_tx(peer->link_stats, orig_len, packets);
	/* keep track of last sent packet for keepalive */
	WRITE_ONCE(peer->last_sent, ktime_get_boottime_seconds());
	/* skb passed down the stack - don't free it */
	skb = NULL;
err_unlock:
	rcu_read_unlock();
err:
	if (unlikely(skb))
		ovpn_dev_dstats_tx_dropped(peer->ovpn->dev, packets);
	kfree_skb(skb);
	ovpn_key_ctx_put(key);
	if (likely(ks))
		ovpn_crypto_key_slot_put(ks);
	if (likely(peer))
		ovpn_peer_put(peer);
}

/* Hold the peer and its primary key for one encryption submission.
 * The returned key and the peer each carry one reference which completion must
 * release.
 */
static struct ovpn_crypto_key_slot *
ovpn_encrypt_refs_get(struct ovpn_peer *peer)
{
	struct ovpn_crypto_key_slot *ks;

	/* get primary key to be used for encrypting data */
	ks = ovpn_crypto_key_slot_primary(&peer->crypto);
	if (unlikely(!ks))
		return NULL;

	/* the caller already owns a peer reference, so it can extend that
	 * ownership across crypto completion
	 */
	ovpn_peer_hold(peer);

	return ks;
}

static bool ovpn_encrypt_one(struct ovpn_peer *peer, struct sk_buff *skb)
{
	struct ovpn_crypto_key_slot *ks;

	ks = ovpn_encrypt_refs_get(peer);
	if (unlikely(!ks))
		return false;

	memset(ovpn_skb_cb(skb), 0, sizeof(struct ovpn_cb));
	ovpn_encrypt_post(skb, ovpn_aead_encrypt(peer, ks, skb));
	return true;
}

static void ovpn_skb_prefetch_frag(const struct sk_buff *skb)
{
	unsigned long addr, end;
	const skb_frag_t *frag;

	if (!skb_shinfo(skb)->nr_frags)
		return;

	frag = &skb_shinfo(skb)->frags[0];
	/* prefetch requires a directly accessible kernel virtual address */
	addr = (unsigned long)skb_frag_address_safe(frag);
	if (!addr)
		return;

	end = addr + skb_frag_size(frag);
	/* the linear head was just touched by segmentation, so prefetch the
	 * first shared payload frag without repeating crypto's full sg walk
	 */
	for (; addr < end; addr = ALIGN(addr + 1, L1_CACHE_BYTES))
		prefetch((void *)addr);
}

static struct sk_buff *ovpn_udp_gso_alloc(const struct sk_buff *first_segment,
					  unsigned int batch_len,
					  unsigned int gso_size,
					  unsigned int segments)
{
	struct sk_buff *gso_skb;
	int ret;

	gso_skb = alloc_skb_with_frags(OVPN_HEAD_ROOM, batch_len,
				       SKB_FRAG_PAGE_ORDER, &ret, GFP_ATOMIC);
	if (unlikely(!gso_skb))
		return NULL;

	skb_reserve(gso_skb, OVPN_HEAD_ROOM);
	gso_skb->len = batch_len;
	gso_skb->data_len = batch_len;
	gso_skb->priority = first_segment->priority;

	/* Segments retain the originating socket so we keep its send-buffer
	 * accounting active until the UDP GSO is transmitted. This also
	 * preserves its cached TX queue.
	 */
	if (first_segment->sk && is_skb_wmem(first_segment))
		skb_set_owner_w(gso_skb, first_segment->sk);
	skb_copy_hash(gso_skb, first_segment);
#ifdef CONFIG_XPS
	/* keep the aggregate on the TX queue selected for the original flow
	 * otherwise async crypto completion on another CPU could move the flow
	 * to a different queue and cause delay or reordering
	 */
	gso_skb->sender_cpu = first_segment->sender_cpu;
#endif

	skb_shinfo(gso_skb)->gso_type = SKB_GSO_UDP_L4;
	skb_shinfo(gso_skb)->gso_size = gso_size;
	skb_shinfo(gso_skb)->gso_segs = segments;

	return gso_skb;
}

static bool ovpn_encrypt_gso_queue(struct sk_buff_head *skbs,
				   struct ovpn_peer *peer)
{
	unsigned int segments, seg_len, i, len, offset = 0;
	unsigned int batch_len, max_segs, record_overhead;
	struct ovpn_crypto_key_slot *ks;
	struct ovpn_key_ctx *key = NULL;
	struct sk_buff *batch, *skb;
	u64 first_pktid;
	int ret;

	/* acquire the slot before calculating its wire-format overhead */
	ks = ovpn_encrypt_refs_get(peer);
	if (unlikely(!ks))
		return false;

	record_overhead = ks->aad_size + OVPN_AEAD_TAG_SIZE;
	seg_len = skb_peek(skbs)->len + record_overhead;
	max_segs = min_t(unsigned int, UDP_MAX_SEGMENTS,
			 OVPN_UDP_GSO_MAX_PAYLOAD / seg_len);
	if (unlikely(max_segs < 2))
		goto err_refs;

	segments = min_t(unsigned int, skb_queue_len(skbs), max_segs);
	/* only the final input skb may be shorter than the nominal GSO size */
	batch_len = segments * seg_len;
	if (segments == skb_queue_len(skbs))
		batch_len -= skb_peek(skbs)->len - skb_peek_tail(skbs)->len;

	/* allocate before consuming packet IDs so allocation failure can fall
	 * back to ordinary per-segment encryption without leaving a gap
	 */
	batch = ovpn_udp_gso_alloc(skb_peek(skbs), batch_len, seg_len,
				   segments);
	if (unlikely(!batch))
		goto err_refs;

retry:
	ret = ovpn_key_ctx_get(&key, &ks->encrypt);
	if (unlikely(ret))
		goto err_batch;

	/* charge every record as a full-sized segment; the possible shorter
	 * tail is conservatively overcounted without another list inspection
	 */
	ret = ovpn_aead_encrypt_reserve(peer, ks, key, segments,
					skb_peek(skbs)->len, &first_pktid);
	if (unlikely(ret == -EAGAIN)) {
		/* keys have rotated so try reserving again with the new key */
		ovpn_key_ctx_put(key);
		key = NULL;
		goto retry;
	}
	if (unlikely(ret < 0)) {
		if (ret == -ERANGE)
			ovpn_encrypt_key_exhausted(peer, ks);
		goto err_key;
	}

	/* the aggregate owns these references until every sync or async crypto
	 * completion has finished
	 */
	memset(ovpn_skb_cb(batch), 0, sizeof(struct ovpn_cb));
	ovpn_skb_cb(batch)->peer = peer;
	ovpn_skb_cb(batch)->ks = ks;
	ovpn_skb_cb(batch)->key = key;
	atomic_set(&ovpn_skb_cb(batch)->batch_state.pending, segments);
	atomic_set(&ovpn_skb_cb(batch)->batch_state.failed, 0);

	for (i = 0; i < segments; i++) {
		skb = __skb_dequeue(skbs);
		len = skb->len + record_overhead;

		/* overlap fetching the next segment's shared payload with
		 * encryption of the current segment
		 */
		if (i + 1 < segments)
			ovpn_skb_prefetch_frag(skb_peek(skbs));

		memset(ovpn_skb_cb(skb), 0, sizeof(struct ovpn_cb));
		ovpn_skb_cb(skb)->batch = batch;
		ovpn_encrypt_post(skb, ovpn_aead_encrypt_gso(peer, ks, key,
							     skb, batch,
							     offset,
							     first_pktid + i));
		offset += len;
	}

	return true;

err_key:
	ovpn_key_ctx_put(key);
err_batch:
	kfree_skb(batch);
err_refs:
	ovpn_crypto_key_slot_put(ks);
	ovpn_peer_put(peer);
	return false;
}

/* send skb to connected peer, if any */
static void ovpn_send(struct ovpn_priv *ovpn, struct sk_buff *skb,
		      struct ovpn_peer *peer)
{
	struct sk_buff *curr, *next;

	/* this might be a GSO-segmented skb list: process each skb
	 * independently
	 */
	skb_list_walk_safe(skb, curr, next) {
		/* encrypting this segment can hide the cost of fetching the
		 * next segment's data into the cache
		 */
		if (next)
			ovpn_skb_prefetchw_linear(next);

		if (unlikely(!ovpn_encrypt_one(peer, curr))) {
			ovpn_dev_dstats_tx_dropped(ovpn->dev, 1);
			kfree_skb(curr);
		}
	}

	ovpn_peer_put(peer);
}

/* encrypt fixed-size input segments into one or more UDP GSO aggregates */
static void ovpn_send_gso(struct sk_buff_head *skbs, struct ovpn_peer *peer)
{
	/* An input GSO skb might produce more records than one UDP GSO skb can
	 * hold, so consume one aggregate at a time. A final single skb, or the
	 * whole remainder after a failure, stays queued and falls back to the
	 * ordinary transmit path.
	 */
	while (skb_queue_len(skbs) > 1) {
		if (!ovpn_encrypt_gso_queue(skbs, peer))
			break;
	}
}

static bool ovpn_peer_supports_udp_gso(struct ovpn_peer *peer)
{
	struct ovpn_socket *sock;
	bool udp_gso;

	rcu_read_lock();
	sock = rcu_dereference(peer->sock);
	/* UDP GSO requires checksums. These socket settings can change after
	 * we decide to batch, but an already-built batch remains checksummed.
	 * Linux's ordinary UDP GSO path makes the same choice.
	 */
	udp_gso = sock && sock->sk->sk_protocol == IPPROTO_UDP &&
		  !sock->sk->sk_no_check_tx && !udp_get_no_check6_tx(sock->sk);
	rcu_read_unlock();

	return udp_gso;
}

/* Send user data to the network
 */
netdev_tx_t ovpn_net_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct ovpn_priv *ovpn = netdev_priv(dev);
	struct sk_buff *segments, *curr, *next;
	const bool gso_in = skb_is_gso(skb);
	struct sk_buff_head skb_list;
	netdev_features_t features;
	unsigned int tx_bytes = 0;
	struct ovpn_peer *peer;
	bool gso_out;
	__be16 proto;
	int ret;

	/* A frag-list GSO skb already stores complete segments as child skbs.
	 * Keep those children on the ordinary in-place encryption path instead
	 * of copying them into a replacement UDP GSO skb.
	 *
	 * GSO_BY_FRAGS input must remain on that path too because its variable
	 * segment sizes cannot be represented by one UDP GSO output size.
	 */
	gso_out = gso_in &&
		  !(skb_shinfo(skb)->gso_type & SKB_GSO_FRAGLIST) &&
		  skb_shinfo(skb)->gso_size != GSO_BY_FRAGS;

	/* reset netfilter state */
	nf_reset_ct(skb);

	/* verify IP header size in network packet */
	proto = ovpn_ip_check_protocol(skb);
	if (unlikely(!proto || skb->protocol != proto))
		goto drop_no_peer;

	/* retrieve peer serving the destination IP of this packet */
	peer = ovpn_peer_get_by_dst(ovpn, skb);
	if (unlikely(!peer)) {
		switch (skb->protocol) {
		case htons(ETH_P_IP):
			net_dbg_ratelimited("%s: no peer to send data to dst=%pI4\n",
					    netdev_name(ovpn->dev),
					    &ip_hdr(skb)->daddr);
			break;
		case htons(ETH_P_IPV6):
			net_dbg_ratelimited("%s: no peer to send data to dst=%pI6c\n",
					    netdev_name(ovpn->dev),
					    &ipv6_hdr(skb)->daddr);
			break;
		}
		goto drop_no_peer;
	}
	/* dst was needed for peer selection - it can now be dropped */
	skb_dst_drop(skb);

	if (gso_in) {
		/* force software segmentation and calculate each checksum
		 * while allowing safe page-backed payload fragments to remain
		 * non-linear
		 */
		features = netif_skb_features(skb);
		features &= ~(NETIF_F_GSO_MASK | NETIF_F_CSUM_MASK);
		segments = skb_gso_segment(skb, features);
		if (IS_ERR_OR_NULL(segments)) {
			ret = PTR_ERR(segments);
			net_err_ratelimited("%s: cannot segment payload packet: %d\n",
					    netdev_name(dev), ret);
			goto drop;
		}

		consume_skb(skb);
		skb = segments;
	}

	/* from this moment on, "skb" might be a list */

	__skb_queue_head_init(&skb_list);
	skb_list_walk_safe(skb, curr, next) {
		skb_mark_not_on_list(curr);

		curr = skb_share_check(curr, GFP_ATOMIC);
		if (unlikely(!curr)) {
			net_err_ratelimited("%s: skb_share_check failed for payload packet\n",
					    netdev_name(dev));
			ovpn_dev_dstats_tx_dropped(ovpn->dev, 1);
			gso_out = false;
			continue;
		}

		/* NETIF_F_HW_CSUM requires completing partial checksums */
		if (unlikely(curr->ip_summed == CHECKSUM_PARTIAL &&
			     skb_checksum_help(curr) < 0)) {
			net_err_ratelimited("%s: skb_checksum_help failed for payload packet\n",
					    netdev_name(dev));
			ovpn_dev_dstats_tx_dropped(ovpn->dev, 1);
			kfree_skb(curr);
			gso_out = false;
			continue;
		}

		/* only count what we actually send */
		tx_bytes += curr->len;
		__skb_queue_tail(&skb_list, curr);
	}

	/* no segments survived: don't jump to 'drop' because we already
	 * incremented the counter for each failure in the loop
	 */
	if (unlikely(skb_queue_empty(&skb_list))) {
		ovpn_peer_put(peer);
		return NETDEV_TX_OK;
	}

	ovpn_peer_stats_increment_tx(peer->vpn_stats, tx_bytes);

	if (gso_out && skb_queue_len(&skb_list) > 1 &&
	    ovpn_peer_supports_udp_gso(peer))
		ovpn_send_gso(&skb_list, peer);

	skb_list.prev->next = NULL;
	ovpn_send(ovpn, skb_list.next, peer);

	return NETDEV_TX_OK;

drop:
	ovpn_peer_put(peer);
drop_no_peer:
	ovpn_dev_dstats_tx_dropped(ovpn->dev, 1);
	skb_tx_error(skb);
	kfree_skb_list(skb);
	return NETDEV_TX_OK;
}

/**
 * ovpn_xmit_special - encrypt and transmit an out-of-band message to peer
 * @peer: peer to send the message to
 * @data: message content
 * @len: message length
 *
 * Assumes that caller holds a reference to peer, which will be
 * passed to ovpn_send()
 */
void ovpn_xmit_special(struct ovpn_peer *peer, const void *data,
		       const unsigned int len)
{
	struct ovpn_priv *ovpn;
	struct sk_buff *skb;

	ovpn = peer->ovpn;
	if (unlikely(!ovpn)) {
		ovpn_peer_put(peer);
		return;
	}

	skb = alloc_skb(256 + len, GFP_ATOMIC);
	if (unlikely(!skb)) {
		ovpn_peer_put(peer);
		return;
	}

	skb_reserve(skb, 128);
	skb->priority = TC_PRIO_BESTEFFORT;
	__skb_put_data(skb, data, len);

	ovpn_send(ovpn, skb, peer);
}
