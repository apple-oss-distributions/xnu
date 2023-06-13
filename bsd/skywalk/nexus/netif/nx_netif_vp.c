/*
 * Copyright (c) 2019-2022 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#include <skywalk/os_skywalk_private.h>
#include <skywalk/nexus/netif/nx_netif.h>
#include <net/if_vlan_var.h>
#include <sys/sdt.h>

#define NETIF_DEMUX_ALLOC_SLOTS 128

#define OUTBOUND_CHECK_OFF      0
#define OUTBOUND_CHECK_ON       1
#define OUTBOUND_CHECK_FORCED   2

/* Turning this off allows packets to be spoofed for testing purposes */
static uint32_t outbound_check = OUTBOUND_CHECK_ON;

/* This controls the per-NA pool size of custom ether and llw NAs */
static uint32_t vp_pool_size = 2048;

/* This enables zerocopy on llw NAs */
static uint32_t vp_zerocopy = 0;

/* TX Ring size */
static uint32_t vp_tx_slots = 0;

/* RX Ring size */
static uint32_t vp_rx_slots = 0;

/*
 * Disable all packet validation
 */
uint32_t nx_netif_vp_accept_all = 0;

static uint16_t nx_netif_vpna_gencnt = 0;

#if (DEVELOPMENT || DEBUG)
SYSCTL_UINT(_kern_skywalk_netif, OID_AUTO, outbound_check,
    CTLFLAG_RW | CTLFLAG_LOCKED, &outbound_check, 0,
    "netif outbound packet validation");
SYSCTL_UINT(_kern_skywalk_netif, OID_AUTO, vp_pool_size,
    CTLFLAG_RW | CTLFLAG_LOCKED, &vp_pool_size, 0,
    "netif virtual port pool size");
SYSCTL_UINT(_kern_skywalk_netif, OID_AUTO, vp_zerocopy,
    CTLFLAG_RW | CTLFLAG_LOCKED, &vp_zerocopy, 0,
    "netif virtual port zero copy");
SYSCTL_UINT(_kern_skywalk_netif, OID_AUTO, vp_tx_slots,
    CTLFLAG_RW | CTLFLAG_LOCKED, &vp_tx_slots, 0,
    "netif virtual port tx slots");
SYSCTL_UINT(_kern_skywalk_netif, OID_AUTO, vp_rx_slots,
    CTLFLAG_RW | CTLFLAG_LOCKED, &vp_rx_slots, 0,
    "netif virtual port rx slots");
SYSCTL_UINT(_kern_skywalk_netif, OID_AUTO, vp_accept_all,
    CTLFLAG_RW | CTLFLAG_LOCKED, &nx_netif_vp_accept_all, 0,
    "netif accept all");
#endif /* (DEVELOPMENT || DEBUG) */

static int
netif_vp_na_channel_event_notify(struct nexus_adapter *,
    struct __kern_channel_event *, uint16_t);

static void
netif_vp_dump_packet(struct __kern_packet *pkt)
{
	uint8_t *baddr;

	MD_BUFLET_ADDR_ABS(pkt, baddr);
	ASSERT(baddr != NULL);
	baddr += pkt->pkt_headroom;

	DTRACE_SKYWALK2(dump__packet, struct __kern_packet *,
	    pkt, uint8_t *, baddr);
}

static int
netif_copy_or_attach_pkt(struct __kern_channel_ring *ring,
    kern_channel_slot_t slot, struct __kern_packet *pkt)
{
	kern_packet_t ph;
	struct __kern_packet *dpkt;
	errno_t err;

	if (pkt->pkt_qum.qum_pp == ring->ckr_pp) {
		DTRACE_SKYWALK2(attach__pkt, struct __kern_channel_ring *, ring,
		    struct __kern_packet *, pkt);
		ph = SK_PKT2PH(pkt);
		err = kern_packet_finalize(ph);
		VERIFY(err == 0);
	} else {
		DTRACE_SKYWALK2(copy__pkt, struct __kern_channel_ring *, ring,
		    struct __kern_packet *, pkt);
		dpkt = nx_netif_pkt_to_pkt(NIFNA(ring->ckr_na), pkt,
		    ring->ckr_na->na_type == NA_NETIF_VP ? NETIF_CONVERT_RX :
		    NETIF_CONVERT_TX);
		if (__improbable(dpkt == NULL)) {
			return ENOMEM;
		}
		ph = SK_PKT2PH(dpkt);
	}
	err = kern_channel_slot_attach_packet(ring, slot, ph);
	VERIFY(err == 0);
	return 0;
}

static errno_t
netif_deliver_pkt(struct nexus_adapter *na, struct __kern_packet *pkt_chain,
    uint32_t flags)
{
#pragma unused(flags)
	struct __kern_channel_ring *ring = &na->na_rx_rings[0];
	struct __kern_packet *pkt = pkt_chain, *next;
	kern_channel_slot_t last_slot = NULL, slot = NULL;
	struct nexus_netif_adapter *nifna = NIFNA(na);
	struct nx_netif *nif = nifna->nifna_netif;
	struct netif_stats *nifs = &nif->nif_stats;
	sk_protect_t protect;
	int cnt = 0, dropcnt = 0, err;

	(void) kr_enter(ring, TRUE);
	protect = sk_sync_protect();

	if (__improbable(KR_DROP(ring))) {
		nx_netif_free_packet_chain(pkt, &dropcnt);
		STATS_ADD(nifs,
		    NETIF_STATS_VP_DROP_USER_RING_DISABLED, dropcnt);
		STATS_ADD(nifs, NETIF_STATS_DROP, dropcnt);
		DTRACE_SKYWALK2(ring__drop, struct __kern_channel_ring *, ring,
		    int, dropcnt);
		sk_sync_unprotect(protect);
		kr_exit(ring);
		return ENXIO;
	}
	while (pkt != NULL) {
		slot = kern_channel_get_next_slot(ring, last_slot, NULL);
		if (slot == NULL) {
			break;
		}
		next = pkt->pkt_nextpkt;
		pkt->pkt_nextpkt = NULL;
		netif_vp_dump_packet(pkt);
		err = netif_copy_or_attach_pkt(ring, slot, pkt);
		if (__probable(err == 0)) {
			last_slot = slot;
		}
		pkt = next;
		cnt++;
	}
	if (NETIF_IS_LOW_LATENCY(nif)) {
		STATS_ADD(nifs, NETIF_STATS_VP_LL_DELIVERED, cnt);
	} else {
		STATS_ADD(nifs, NETIF_STATS_VP_DELIVERED, cnt);
	}
	DTRACE_SKYWALK4(delivered, struct nexus_adapter *, na,
	    struct __kern_channel_ring *, ring, struct __kern_packet *, pkt,
	    int, cnt);

	if (pkt != NULL) {
		nx_netif_free_packet_chain(pkt, &dropcnt);
		STATS_ADD(nifs,
		    NETIF_STATS_VP_DROP_USER_RING_NO_SPACE, dropcnt);
		STATS_ADD(nifs, NETIF_STATS_DROP, dropcnt);
		DTRACE_SKYWALK2(deliver__drop, struct nexus_adapter *, na,
		    int, dropcnt);
	}
	if (last_slot != NULL) {
		kern_channel_advance_slot(ring, last_slot);
	}
	sk_sync_unprotect(protect);
	kr_exit(ring);
	if (cnt > 0) {
		(void) kern_channel_notify(ring, 0);
	}
	return 0;
}

static errno_t
netif_deliver_cb(void *arg, void *chain, uint32_t flags)
{
	return netif_deliver_pkt(arg, chain, flags);
}

static int
netif_hwna_rx_get_pkts(struct __kern_channel_ring *ring, struct proc *p,
    uint32_t flags, struct __kern_packet **chain)
{
	int err, cnt = 0;
	sk_protect_t protect;
	slot_idx_t ktail, idx;
	struct __kern_packet *pkt_chain = NULL, **tailp = &pkt_chain;
	struct netif_stats *nifs = &NIFNA(KRNA(ring))->nifna_netif->nif_stats;

	err = kr_enter(ring, ((flags & NA_NOTEF_CAN_SLEEP) != 0 ||
	    (ring->ckr_flags & CKRF_HOST) != 0));
	if (err != 0) {
		SK_DF(SK_VERB_VP,
		    "hwna \"%s\" (0x%llx) kr \"%s\" (0x%llx) krflags 0x%b "
		    "(%d)", KRNA(ring)->na_name, SK_KVA(KRNA(ring)),
		    ring->ckr_name, SK_KVA(ring), ring->ckr_flags,
		    CKRF_BITS, err);
		STATS_INC(nifs, NETIF_STATS_VP_KR_ENTER_FAIL);
		return err;
	}
	if (__improbable(KR_DROP(ring))) {
		kr_exit(ring);
		STATS_INC(nifs, NETIF_STATS_VP_DEV_RING_DISABLED);
		return ENODEV;
	}
	protect = sk_sync_protect();

	err = ring->ckr_na_sync(ring, p, 0);
	if (err != 0 && err != EAGAIN) {
		STATS_INC(nifs, NETIF_STATS_VP_SYNC_UNKNOWN_ERR);
		goto out;
	}
	ktail = ring->ckr_ktail;
	if (__improbable(ring->ckr_khead == ktail)) {
		SK_DF(SK_VERB_VP,
		    "spurious wakeup on hwna %s (0x%llx)", KRNA(ring)->na_name,
		    SK_KVA(KRNA(ring)));
		STATS_INC(nifs, NETIF_STATS_VP_SPURIOUS_NOTIFY);
		err = ENOENT;
		goto out;
	}
	/* get all packets from the ring */
	idx = ring->ckr_rhead;
	while (idx != ktail) {
		struct __kern_slot_desc *ksd = KR_KSD(ring, idx);
		struct __kern_packet *pkt = ksd->sd_pkt;

		ASSERT(pkt->pkt_nextpkt == NULL);
		KR_SLOT_DETACH_METADATA(ring, ksd);
		cnt++;
		*tailp = pkt;
		tailp = &pkt->pkt_nextpkt;
		idx = SLOT_NEXT(idx, ring->ckr_lim);
	}
	ring->ckr_rhead = ktail;
	ring->ckr_rtail = ring->ckr_ktail;

	DTRACE_SKYWALK2(rx__notify, struct __kern_channel_ring *, ring,
	    int, cnt);
	*chain = pkt_chain;
out:
	sk_sync_unprotect(protect);
	kr_exit(ring);
	return err;
}

int
netif_llw_rx_notify_fast(struct __kern_channel_ring *ring, struct proc *p,
    uint32_t flags)
{
#pragma unused (p, flags)
	struct nexus_adapter *hwna;
	uint32_t count;
	int i, err;

	hwna = KRNA(ring);
	count = na_get_nslots(hwna, NR_RX);
	err = nx_rx_sync_packets(ring, ring->ckr_scratch, &count);
	if (__improbable(err != 0)) {
		SK_ERR("nx_rx_sync_packets failed: %d", err);
		DTRACE_SKYWALK2(rx__sync__packets__failed,
		    struct __kern_channel_ring *, ring, int, err);
		return err;
	}
	DTRACE_SKYWALK1(chain__count, uint32_t, count);
	for (i = 0; i < count; i++) {
		struct __kern_packet *pkt_chain;

		pkt_chain = SK_PTR_ADDR_KPKT(ring->ckr_scratch[i]);
		ASSERT(pkt_chain != NULL);
		(void) nx_netif_demux(NIFNA(KRNA(ring)), pkt_chain, NULL,
		    NETIF_FLOW_SOURCE);
	}
	return 0;
}

int
netif_llw_rx_notify_default(struct __kern_channel_ring *ring, struct proc *p,
    uint32_t flags)
{
	int err;
	struct __kern_packet *pkt_chain = NULL;

	err = netif_hwna_rx_get_pkts(ring, p, flags, &pkt_chain);
	if (err != 0) {
		return err;
	}
	return nx_netif_demux(NIFNA(KRNA(ring)), pkt_chain, NULL,
	           NETIF_FLOW_SOURCE);
}

static errno_t
netif_hwna_setup(struct nx_netif *nif)
{
	struct kern_channel *ch;
	struct kern_nexus *nx = nif->nif_nx;
	struct chreq chr;
	int err;

	SK_LOCK_ASSERT_HELD();
	ASSERT(NETIF_IS_LOW_LATENCY(nif));
	if (nif->nif_hw_ch != NULL) {
		nif->nif_hw_ch_refcnt++;
		SK_DF(SK_VERB_VP, "%s: hw channel already open, refcnt %d",
		    if_name(nif->nif_ifp), nif->nif_hw_ch_refcnt);
		return 0;
	}
	ASSERT(nif->nif_hw_ch_refcnt == 0);
	bzero(&chr, sizeof(chr));
	uuid_copy(chr.cr_spec_uuid, nx->nx_uuid);
	chr.cr_ring_id = 0;
	chr.cr_port = NEXUS_PORT_NET_IF_DEV;
	chr.cr_mode |= CHMODE_CONFIG;

	err = 0;
	ch = ch_open_special(nx, &chr, FALSE, &err);
	if (ch == NULL) {
		SK_ERR("%s: failed to open nx 0x%llx (err %d)",
		    if_name(nif->nif_ifp), SK_KVA(nx), err);
		return err;
	}
	netif_hwna_set_mode(ch->ch_na, NETIF_MODE_LLW, NULL);
	na_start_spec(nx, ch);
	nif->nif_hw_ch_refcnt = 1;
	nif->nif_hw_ch = ch;
	SK_DF(SK_VERB_VP, "%s: hw channel opened 0x%llx, %s:%s",
	    if_name(nif->nif_ifp), SK_KVA(ch), NX_DOM(nx)->nxdom_name,
	    NX_DOM_PROV(nx)->nxdom_prov_name);
	return 0;
}

static void
netif_hwna_teardown(struct nx_netif *nif)
{
	struct kern_nexus *nx = nif->nif_nx;
	struct kern_channel *ch = nif->nif_hw_ch;

	SK_LOCK_ASSERT_HELD();
	ASSERT(NETIF_IS_LOW_LATENCY(nif));
	ASSERT(ch != NULL);
	if (--nif->nif_hw_ch_refcnt > 0) {
		SK_DF(SK_VERB_VP, "%s: hw channel still open, refcnt %d",
		    if_name(nif->nif_ifp), nif->nif_hw_ch_refcnt);
		return;
	}
	SK_DF(SK_VERB_VP, "%s: hw channel closing 0x%llx, %s:%s",
	    if_name(nif->nif_ifp), SK_KVA(ch), NX_DOM(nx)->nxdom_name,
	    NX_DOM_PROV(nx)->nxdom_prov_name);

	na_stop_spec(nx, ch);
	netif_hwna_clear_mode(ch->ch_na);
	ch_close_special(ch);
	(void) ch_release_locked(ch);
	nif->nif_hw_ch = NULL;
	SK_DF(SK_VERB_VP, "%s: hw channel closed, %s:%s",
	    if_name(nif->nif_ifp), NX_DOM(nx)->nxdom_name,
	    NX_DOM_PROV(nx)->nxdom_prov_name);
}

static int
netif_vp_na_activate_on(struct nexus_adapter *na)
{
	errno_t err;
	struct netif_flow *nf;
	struct netif_port_info npi;
	struct nexus_netif_adapter *nifna;
	struct nx_netif *nif;
	boolean_t hwna_setup = FALSE;

	nifna = NIFNA(na);
	nif = nifna->nifna_netif;

	/* lock needed to protect against nxdom_unbind_port */
	NETIF_WLOCK(nif);
	err = nx_port_get_info(nif->nif_nx, na->na_nx_port,
	    NX_PORT_INFO_TYPE_NETIF, &npi, sizeof(npi));
	NETIF_WUNLOCK(nif);
	if (err != 0) {
		SK_ERR("port info not found: %d", err);
		return err;
	}
	if (NETIF_IS_LOW_LATENCY(nif)) {
		err = netif_hwna_setup(nif);
		if (err != 0) {
			return err;
		}
		hwna_setup = TRUE;
	}
	err = nx_netif_flow_add(nif, na->na_nx_port, &npi.npi_fd, na,
	    netif_deliver_cb, &nf);
	if (err != 0) {
		if (hwna_setup) {
			netif_hwna_teardown(nif);
		}
		return err;
	}
	nifna->nifna_flow = nf;
	atomic_add_16(&nx_netif_vpna_gencnt, 1);
	nifna->nifna_gencnt = nx_netif_vpna_gencnt;
	atomic_bitset_32(&na->na_flags, NAF_ACTIVE);
	return 0;
}

static int
netif_vp_na_activate_off(struct nexus_adapter *na)
{
	errno_t err;
	struct nexus_netif_adapter *nifna;
	struct nx_netif *nif;

	if (!NA_IS_ACTIVE(na)) {
		DTRACE_SKYWALK1(already__off, struct nexus_adapter *, na);
		return 0;
	}
	nifna = NIFNA(na);
	nif = nifna->nifna_netif;
	err = nx_netif_flow_remove(nif, nifna->nifna_flow);
	VERIFY(err == 0);

	nifna->nifna_flow = NULL;
	if (NETIF_IS_LOW_LATENCY(nif)) {
		netif_hwna_teardown(nif);
	}
	atomic_bitclear_32(&na->na_flags, NAF_ACTIVE);
	return 0;
}

static int
netif_vp_na_activate(struct nexus_adapter *na, na_activate_mode_t mode)
{
	errno_t err;

	ASSERT(na->na_type == NA_NETIF_VP);
	if (mode == NA_ACTIVATE_MODE_ON) {
		err = netif_vp_na_activate_on(na);
	} else {
		err = netif_vp_na_activate_off(na);
	}
	SK_DF(SK_VERB_VP, "na \"%s\" (0x%llx) %s err %d", na->na_name,
	    SK_KVA(na), na_activate_mode2str(mode), err);
	return err;
}

/*
 * XXX
 * The native path sends to the dev ring directly, bypassing aqm.
 * This is ok since this is only used by llw now. This will need to
 * change when we add native support for filters.
 */
static int
netif_vp_send_pkt_chain_low_latency(struct nexus_netif_adapter *dev_nifna,
    struct __kern_packet *pkt_chain, struct proc *p)
{
	struct __kern_packet *pkt = pkt_chain, *next;
	struct nexus_adapter *na = &dev_nifna->nifna_up;
	struct __kern_channel_ring *ring = &na->na_tx_rings[0];
	struct netif_stats *nifs = &dev_nifna->nifna_netif->nif_stats;
	sk_protect_t protect;
	slot_idx_t ktail, idx;
	uint32_t cnt;
	int err_stat = -1;
	errno_t err;

	(void) kr_enter(ring, TRUE);
	protect = sk_sync_protect();
	if (__improbable(KR_DROP(ring))) {
		SK_ERR("ring is not ready");
		DTRACE_SKYWALK1(ring__drop, struct __kern_channel_ring *, ring);
		err_stat = NETIF_STATS_VP_DROP_DEV_RING_DISABLED;
		err = ENXIO;
		goto done;
	}
	idx = ring->ckr_rhead;
	ktail = ring->ckr_ktail;
	if (idx == ktail) {
		SK_ERR("no space to send");
		DTRACE_SKYWALK1(no__space, struct __kern_channel_ring *, ring);
		err_stat = NETIF_STATS_VP_DROP_DEV_RING_NO_SPACE;
		goto sync;
	}
	cnt = 0;
	while (pkt != NULL && idx != ktail) {
		struct __slot_desc *slot = &ring->ckr_ksds[idx];

		next = pkt->pkt_nextpkt;
		pkt->pkt_nextpkt = NULL;
		netif_vp_dump_packet(pkt);
		err = netif_copy_or_attach_pkt(ring, slot, pkt);
		if (__probable(err == 0)) {
			cnt++;
			idx = SLOT_NEXT(idx, ring->ckr_lim);
		}
		pkt = next;
	}
	ring->ckr_rhead = idx;
	STATS_ADD(nifs, NETIF_STATS_VP_LL_ENQUEUED, cnt);
	DTRACE_SKYWALK2(ll__enqueued, struct __kern_channel_ring *, ring,
	    uint32_t, cnt);
sync:
	ring->ckr_khead_pre = ring->ckr_khead;
	err = ring->ckr_na_sync(ring, p, NA_SYNCF_SYNC_ONLY);
	if (err != 0 && err != EAGAIN) {
		SK_ERR("unexpected sync err %d", err);
		DTRACE_SKYWALK1(sync__failed, struct __kern_channel_ring *,
		    ring);
		err_stat = NETIF_STATS_VP_DROP_UNEXPECTED_ERR;
		goto done;
	}
	/*
	 * Verify that the driver has detached packets from the consumed slots.
	 */
	idx = ring->ckr_khead_pre;
	cnt = 0;
	while (idx != ring->ckr_khead) {
		struct __kern_slot_desc *ksd = KR_KSD(ring, idx);

		cnt++;
		VERIFY(!KSD_VALID_METADATA(ksd));
		idx = SLOT_NEXT(idx, ring->ckr_lim);
	}
	ring->ckr_khead_pre = ring->ckr_khead;
	STATS_ADD(nifs, NETIF_STATS_VP_LL_SENT, cnt);
	DTRACE_SKYWALK2(ll__sent, struct __kern_channel_ring *, ring,
	    uint32_t, cnt);
	err = 0;

done:
	sk_sync_unprotect(protect);
	kr_exit(ring);

	/*
	 * Free all unsent packets.
	 */
	if (pkt != NULL) {
		int dropcnt;

		nx_netif_free_packet_chain(pkt, &dropcnt);
		if (err_stat != -1) {
			STATS_ADD(nifs, err_stat, dropcnt);
		}
		STATS_ADD(nifs, NETIF_STATS_DROP, dropcnt);
	}
	return err;
}

static int
netif_vp_send_pkt_chain_common(struct nexus_netif_adapter *dev_nifna,
    struct __kern_packet *pkt_chain, boolean_t compat)
{
	struct __kern_packet *pkt = pkt_chain, *next, *p;
	struct nx_netif *nif = dev_nifna->nifna_netif;
	struct netif_stats *nifs = &nif->nif_stats;
	ifnet_t ifp = nif->nif_ifp;
	struct mbuf *m;
	boolean_t drop;
	int cnt = 0;
	errno_t err;

	while (pkt != NULL) {
		next = pkt->pkt_nextpkt;
		pkt->pkt_nextpkt = NULL;
		drop = FALSE;

		if (compat) {
			m = nx_netif_pkt_to_mbuf(dev_nifna, pkt, NETIF_CONVERT_TX);
			if (m == NULL) {
				pkt = next;
				continue;
			}
			err = ifnet_enqueue_mbuf(ifp, m, FALSE, &drop);
		} else {
			p = nx_netif_pkt_to_pkt(dev_nifna, pkt, NETIF_CONVERT_TX);
			if (p == NULL) {
				pkt = next;
				continue;
			}
			err = ifnet_enqueue_pkt(ifp, p, FALSE, &drop);
		}
		if (err != 0) {
			SK_ERR("enqueue failed: %d", err);
			STATS_INC(nifs, NETIF_STATS_VP_ENQUEUE_FAILED);
			if (drop) {
				STATS_INC(nifs, NETIF_STATS_DROP);
			}
			DTRACE_SKYWALK2(enqueue__failed,
			    struct nexus_netif_adapter *, dev_nifna,
			    boolean_t, drop);
		} else {
			STATS_INC(nifs, NETIF_STATS_VP_ENQUEUED);
			cnt++;
		}
		pkt = next;
	}
	if (cnt > 0) {
		ifnet_start(ifp);
	}
	return 0;
}

static int
netif_vp_send_pkt_chain(struct nexus_netif_adapter *dev_nifna,
    struct __kern_packet *pkt_chain, struct proc *p)
{
	struct nexus_adapter *na = &dev_nifna->nifna_up;

	if (NETIF_IS_LOW_LATENCY(dev_nifna->nifna_netif)) {
		return netif_vp_send_pkt_chain_low_latency(dev_nifna,
		           pkt_chain, p);
	}
	if (na->na_type == NA_NETIF_DEV) {
		return netif_vp_send_pkt_chain_common(dev_nifna, pkt_chain, FALSE);
	}
	ASSERT(na->na_type == NA_NETIF_COMPAT_DEV);
	return netif_vp_send_pkt_chain_common(dev_nifna, pkt_chain, TRUE);
}

SK_NO_INLINE_ATTRIBUTE
static boolean_t
validate_packet(struct nexus_netif_adapter *nifna, struct __kern_packet *pkt)
{
	struct nx_netif *nif = nifna->nifna_netif;

	VERIFY(pkt->pkt_nextpkt == NULL);

	if (nx_netif_vp_accept_all != 0) {
		return TRUE;
	}
	if (outbound_check == 0 ||
	    (NETIF_IS_LOW_LATENCY(nif) &&
	    outbound_check != OUTBOUND_CHECK_FORCED)) {
		return TRUE;
	}
	if (!nx_netif_validate_macaddr(nif, pkt, NETIF_FLOW_OUTBOUND)) {
		return FALSE;
	}
	if (!nx_netif_flow_match(nif, pkt, nifna->nifna_flow,
	    NETIF_FLOW_OUTBOUND)) {
		return FALSE;
	}
	return TRUE;
}

static int
netif_vp_na_txsync(struct __kern_channel_ring *kring, struct proc *p,
    uint32_t flags)
{
#pragma unused(flags)
	kern_channel_slot_t last_slot = NULL, slot = NULL;
	struct __kern_packet *head = NULL, **tailp = &head, *pkt;
	struct nexus_netif_adapter *nifna, *dev_nifna;
	struct nx_netif *nif;
	struct netif_stats *nifs;
	kern_packet_t ph;
	errno_t err;
	int cnt = 0;

	nifna = NIFNA(KRNA(kring));
	nif = nifna->nifna_netif;
	nifs = &nif->nif_stats;
	for (;;) {
		slot = kern_channel_get_next_slot(kring, slot, NULL);
		if (slot == NULL) {
			break;
		}
		ph = kern_channel_slot_get_packet(kring, slot);
		if (__improbable(ph == 0)) {
			SK_ERR("packet got dropped by internalize");
			STATS_INC(nifs, NETIF_STATS_VP_DROP_INTERNALIZE_FAIL);
			DTRACE_SKYWALK2(bad__slot, struct __kern_channel_ring *,
			    kring, kern_channel_slot_t, slot);
			last_slot = slot;
			continue;
		}
		pkt = SK_PTR_ADDR_KPKT(ph);
		if (__improbable(pkt->pkt_length == 0)) {
			SK_ERR("dropped zero length packet");
			STATS_INC(nifs, NETIF_STATS_VP_BAD_PKT_LEN);
			DTRACE_SKYWALK2(bad__slot, struct __kern_channel_ring *,
			    kring, kern_channel_slot_t, slot);
			last_slot = slot;
			continue;
		}
		err = kern_channel_slot_detach_packet(kring, slot, ph);
		VERIFY(err == 0);

		/* packet needs to be finalized after detach */
		err = kern_packet_finalize(ph);
		VERIFY(err == 0);
		last_slot = slot;

		if (NA_CHANNEL_EVENT_ATTACHED(KRNA(kring))) {
			__packet_set_tx_nx_port(SK_PKT2PH(pkt),
			    KRNA(kring)->na_nx_port, nifna->nifna_gencnt);
		}

		if (validate_packet(nifna, pkt)) {
			nx_netif_snoop(nif, pkt, FALSE);
			cnt++;
			*tailp = pkt;
			tailp = &pkt->pkt_nextpkt;
		} else {
			nx_netif_free_packet(pkt);
		}
	}
	if (cnt == 0) {
		STATS_INC(nifs, NETIF_STATS_VP_SYNC_NO_PKTS);
		DTRACE_SKYWALK2(no__data, struct nexus_netif_adapter *, nifna,
		    struct __kern_channel_ring *, kring);
		return 0;
	}
	DTRACE_SKYWALK4(injected, struct nexus_netif_adapter *, nifna,
	    struct __kern_channel_ring *, kring, struct __kern_packet *, head,
	    int, cnt);
	if (last_slot != NULL) {
		kern_channel_advance_slot(kring, last_slot);
	}

	dev_nifna = NIFNA(nx_port_get_na(KRNA(kring)->na_nx,
	    NEXUS_PORT_NET_IF_DEV));

	err = netif_vp_send_pkt_chain(dev_nifna, head, p);
	if (err != 0) {
		SK_ERR("send failed: %d\n", err);
	}
	return 0;
}

static int
netif_vp_na_rxsync(struct __kern_channel_ring *kring, struct proc *p,
    uint32_t flags)
{
#pragma unused(p, flags)
	(void) kr_reclaim(kring);
	return 0;
}

static int
netif_vp_na_krings_create(struct nexus_adapter *na, struct kern_channel *ch)
{
	ASSERT(na->na_type == NA_NETIF_VP);
	return na_rings_mem_setup(na, FALSE, ch);
}


/* na_krings_delete callback for flow switch ports. */
static void
netif_vp_na_krings_delete(struct nexus_adapter *na, struct kern_channel *ch,
    boolean_t defunct)
{
	ASSERT(na->na_type == NA_NETIF_VP);
	na_rings_mem_teardown(na, ch, defunct);
}

static int
netif_vp_region_params_setup(struct nexus_adapter *na,
    struct skmem_region_params *srp, struct kern_pbufpool **tx_pp)
{
#pragma unused (tx_pp)
	uint32_t max_mtu;
	uint32_t buf_sz, buf_cnt, nslots, afslots, evslots, totalrings;
	struct nexus_adapter *devna;
	struct kern_nexus *nx;
	struct nx_netif *nif;
	int err, i;

	for (i = 0; i < SKMEM_REGIONS; i++) {
		srp[i] = *skmem_get_default(i);
	}
	totalrings = na_get_nrings(na, NR_TX) + na_get_nrings(na, NR_RX) +
	    na_get_nrings(na, NR_A) + na_get_nrings(na, NR_F) +
	    na_get_nrings(na, NR_EV);

	srp[SKMEM_REGION_SCHEMA].srp_r_obj_size =
	    (uint32_t)CHANNEL_SCHEMA_SIZE(totalrings);
	srp[SKMEM_REGION_SCHEMA].srp_r_obj_cnt = totalrings;
	skmem_region_params_config(&srp[SKMEM_REGION_SCHEMA]);

	srp[SKMEM_REGION_RING].srp_r_obj_size =
	    sizeof(struct __user_channel_ring);
	srp[SKMEM_REGION_RING].srp_r_obj_cnt = totalrings;
	skmem_region_params_config(&srp[SKMEM_REGION_RING]);

	/* USD regions need to be writable to support user packet pool */
	srp[SKMEM_REGION_TXAUSD].srp_cflags &= ~SKMEM_REGION_CR_UREADONLY;
	srp[SKMEM_REGION_RXFUSD].srp_cflags &= ~SKMEM_REGION_CR_UREADONLY;

	nslots = na_get_nslots(na, NR_TX);
	afslots = na_get_nslots(na, NR_A);
	evslots = na_get_nslots(na, NR_EV);
	srp[SKMEM_REGION_TXAKSD].srp_r_obj_size =
	    MAX(MAX(nslots, afslots), evslots) * SLOT_DESC_SZ;
	srp[SKMEM_REGION_TXAKSD].srp_r_obj_cnt =
	    na_get_nrings(na, NR_TX) + na_get_nrings(na, NR_A) +
	    na_get_nrings(na, NR_EV);
	skmem_region_params_config(&srp[SKMEM_REGION_TXAKSD]);

	/* USD and KSD objects share the same size and count */
	srp[SKMEM_REGION_TXAUSD].srp_r_obj_size =
	    srp[SKMEM_REGION_TXAKSD].srp_r_obj_size;
	srp[SKMEM_REGION_TXAUSD].srp_r_obj_cnt =
	    srp[SKMEM_REGION_TXAKSD].srp_r_obj_cnt;
	skmem_region_params_config(&srp[SKMEM_REGION_TXAUSD]);

	/*
	 * Since the rx/free slots share the same region and cache,
	 * we will use the same object size for both types of slots.
	 */
	nslots = na_get_nslots(na, NR_RX);
	afslots = na_get_nslots(na, NR_F);
	srp[SKMEM_REGION_RXFKSD].srp_r_obj_size =
	    MAX(nslots, afslots) * SLOT_DESC_SZ;
	srp[SKMEM_REGION_RXFKSD].srp_r_obj_cnt =
	    na_get_nrings(na, NR_RX) + na_get_nrings(na, NR_F);
	skmem_region_params_config(&srp[SKMEM_REGION_RXFKSD]);

	/* USD and KSD objects share the same size and count */
	srp[SKMEM_REGION_RXFUSD].srp_r_obj_size =
	    srp[SKMEM_REGION_RXFKSD].srp_r_obj_size;
	srp[SKMEM_REGION_RXFUSD].srp_r_obj_cnt =
	    srp[SKMEM_REGION_RXFKSD].srp_r_obj_cnt;
	skmem_region_params_config(&srp[SKMEM_REGION_RXFUSD]);

	/*
	 * No need to create our own buffer pool if we can share the device's
	 * pool. We don't support sharing split pools to user space.
	 */
	nx = na->na_nx;
	nif = nx->nx_arg;
	if (vp_zerocopy != 0 && NETIF_IS_LOW_LATENCY(nif) &&
	    nx->nx_tx_pp != NULL && (nx->nx_rx_pp == NULL ||
	    nx->nx_tx_pp == nx->nx_rx_pp) && !PP_KERNEL_ONLY(nx->nx_tx_pp)) {
		struct kern_pbufpool *pp = nx->nx_tx_pp;

		if (nif->nif_hw_ch_refcnt != 0) {
			SK_ERR("only one channel is supported for zero copy");
			return ENOTSUP;
		}
		SK_DF(SK_VERB_VP, "sharing %s's pool", if_name(na->na_ifp));

		/*
		 * These types need to be initialized otherwise some assertions
		 * skmem_arena_create_for_nexus() will fail.
		 */
		srp[SKMEM_REGION_UMD].srp_md_type = pp->pp_md_type;
		srp[SKMEM_REGION_UMD].srp_md_subtype = pp->pp_md_subtype;
		srp[SKMEM_REGION_KMD].srp_md_type = pp->pp_md_type;
		srp[SKMEM_REGION_KMD].srp_md_subtype = pp->pp_md_subtype;
		*tx_pp = nx->nx_tx_pp;
		return 0;
	}

	devna = nx_port_get_na(nx, NEXUS_PORT_NET_IF_DEV);
	ASSERT(devna != NULL);
	if (devna->na_type == NA_NETIF_DEV) {
		/*
		 * For native devices, use the driver's buffer size
		 */
		ASSERT(nx->nx_rx_pp != NULL);
		ASSERT(nx->nx_tx_pp != NULL);
		buf_sz = PP_BUF_SIZE_DEF(nx->nx_tx_pp);
	} else {
		if ((err = nx_netif_get_max_mtu(na->na_ifp, &max_mtu)) != 0) {
			/*
			 * If the driver doesn't support SIOCGIFDEVMTU, use the
			 * default MTU size.
			 */
			max_mtu = ifnet_mtu(na->na_ifp);
			err = 0;
		}
		/* max_mtu does not include the L2 header */
		buf_sz = MAX(max_mtu + sizeof(struct ether_vlan_header), 2048);
	}
	buf_cnt = vp_pool_size;
	pp_regions_params_adjust(srp, NEXUS_META_TYPE_PACKET,
	    NEXUS_META_SUBTYPE_RAW, buf_cnt, 1, buf_sz, 0, buf_cnt, 0,
	    PP_REGION_CONFIG_BUF_IODIR_BIDIR |
	    PP_REGION_CONFIG_MD_MAGAZINE_ENABLE);

	nx_netif_vp_region_params_adjust(na, srp);
	return 0;
}

static int
netif_vp_na_mem_new(struct kern_nexus *nx, struct nexus_adapter *na)
{
#pragma unused(nx)
	struct skmem_region_params srp[SKMEM_REGIONS];
	struct kern_pbufpool *tx_pp = NULL;
	int err;

	err = netif_vp_region_params_setup(na, srp, &tx_pp);
	if (err != 0) {
		return err;
	}
	na->na_arena = skmem_arena_create_for_nexus(na, srp,
	    tx_pp != NULL ? &tx_pp : NULL, NULL,
	    0, &nx->nx_adv, &err);
	ASSERT(na->na_arena != NULL || err != 0);
	return err;
}

static void
netif_vp_na_dtor(struct nexus_adapter *na)
{
	struct kern_nexus *nx = na->na_nx;
	struct nx_netif *nif = NX_NETIF_PRIVATE(nx);
	struct nexus_netif_adapter *nifna = NIFNA(na);

	NETIF_WLOCK(nif);
	(void) nx_port_unbind(nx, na->na_nx_port);
	nx_port_free(nx, na->na_nx_port);
	nif->nif_vp_cnt--;
	if (na->na_ifp != NULL) {
		ifnet_decr_iorefcnt(na->na_ifp);
		na->na_ifp = NULL;
	}
	if (nifna->nifna_netif != NULL) {
		nx_netif_release(nifna->nifna_netif);
		nifna->nifna_netif = NULL;
	}
	NETIF_WUNLOCK(nif);
	SK_DF(SK_VERB_VP, "na \"%s\" (0x%llx)", na->na_name, SK_KVA(na));
}

int
netif_vp_na_create(struct kern_nexus *nx, struct chreq *chr,
    struct nexus_adapter **nap)
{
	struct nx_netif *nif = NX_NETIF_PRIVATE(nx);
	struct nxprov_params *nxp = NX_PROV(nx)->nxprov_params;
	struct nexus_adapter *na = NULL;
	struct nexus_netif_adapter *nifna;
	uint32_t slots;
	int err;

	NETIF_WLOCK_ASSERT_HELD(nif);
	if (nif->nif_ifp == NULL) {
		SK_ERR("ifnet not yet attached");
		return ENXIO;
	}
	ASSERT((chr->cr_mode & CHMODE_KERNEL) == 0);
	if ((chr->cr_mode & CHMODE_USER_PACKET_POOL) == 0) {
		SK_ERR("user packet pool required");
		return EINVAL;
	}
	/*
	 * No locking needed while checking for the initialized bit because
	 * if this were not set, no other codepaths would modify the flags.
	 */
	if ((nif->nif_flow_flags & NETIF_FLOW_FLAG_INITIALIZED) == 0) {
		SK_ERR("demux vp not supported");
		return ENOTSUP;
	}
	na = (struct nexus_adapter *)na_netif_alloc(Z_WAITOK);
	nifna = NIFNA(na);
	nifna->nifna_netif = nif;
	nx_netif_retain(nif);
	nifna->nifna_flow = NULL;

	(void) snprintf(na->na_name, sizeof(na->na_name),
	    "netif_vp:%d", chr->cr_port);
	uuid_generate_random(na->na_uuid);

	na_set_nrings(na, NR_TX, nxp->nxp_tx_rings);
	na_set_nrings(na, NR_RX, nxp->nxp_rx_rings);
	/*
	 * If the packet pool is configured to be multi-buflet, then we
	 * need 2 pairs of alloc/free rings(for packet and buflet).
	 */
	na_set_nrings(na, NR_A, ((nxp->nxp_max_frags > 1) &&
	    (sk_channel_buflet_alloc != 0)) ? 2 : 1);

	slots = vp_tx_slots != 0 ? vp_tx_slots :
	    NX_DOM(nx)->nxdom_tx_slots.nb_def;
	na_set_nslots(na, NR_TX, slots);

	slots = vp_rx_slots != 0 ? vp_rx_slots :
	    NX_DOM(nx)->nxdom_rx_slots.nb_def;
	na_set_nslots(na, NR_RX, slots);

	na_set_nslots(na, NR_A, NETIF_DEMUX_ALLOC_SLOTS);
	ASSERT(na_get_nrings(na, NR_TX) <= NX_DOM(nx)->nxdom_tx_rings.nb_max);
	ASSERT(na_get_nrings(na, NR_RX) <= NX_DOM(nx)->nxdom_rx_rings.nb_max);
	ASSERT(na_get_nslots(na, NR_TX) <= NX_DOM(nx)->nxdom_tx_slots.nb_max);
	ASSERT(na_get_nslots(na, NR_RX) <= NX_DOM(nx)->nxdom_rx_slots.nb_max);

	atomic_bitset_32(&na->na_flags, NAF_USER_PKT_POOL);

	if (chr->cr_mode & CHMODE_EVENT_RING) {
		na_set_nrings(na, NR_EV, NX_NETIF_EVENT_RING_NUM);
		na_set_nslots(na, NR_EV, NX_NETIF_EVENT_RING_SIZE);
		atomic_bitset_32(&na->na_flags, NAF_EVENT_RING);
		na->na_channel_event_notify = netif_vp_na_channel_event_notify;
	}

	na->na_nx_port = chr->cr_port;
	na->na_type = NA_NETIF_VP;
	na->na_free = na_netif_free;
	na->na_dtor = netif_vp_na_dtor;
	na->na_activate = netif_vp_na_activate;
	na->na_txsync = netif_vp_na_txsync;
	na->na_rxsync = netif_vp_na_rxsync;
	na->na_krings_create = netif_vp_na_krings_create;
	na->na_krings_delete = netif_vp_na_krings_delete;
	na->na_special = NULL;
	na->na_ifp = nif->nif_ifp;
	ifnet_incr_iorefcnt(na->na_ifp);

	*(nexus_stats_type_t *)(uintptr_t)&na->na_stats_type =
	    NEXUS_STATS_TYPE_INVALID;

	/* other fields are set in the common routine */
	na_attach_common(na, nx, &nx_netif_prov_s);

	err = netif_vp_na_mem_new(nx, na);
	if (err != 0) {
		ASSERT(na->na_arena == NULL);
		goto err;
	}

	*(uint32_t *)(uintptr_t)&na->na_flowadv_max = nxp->nxp_flowadv_max;
	ASSERT(na->na_flowadv_max == 0 ||
	    skmem_arena_nexus(na->na_arena)->arn_flowadv_obj != NULL);

	nif->nif_vp_cnt++;
	*nap = na;
	return 0;

err:
	if (na != NULL) {
		if (na->na_ifp != NULL) {
			ifnet_decr_iorefcnt(na->na_ifp);
			na->na_ifp = NULL;
		}
		if (na->na_arena != NULL) {
			skmem_arena_release(na->na_arena);
			na->na_arena = NULL;
		}
		if (nifna->nifna_netif != NULL) {
			nx_netif_release(nifna->nifna_netif);
			nifna->nifna_netif = NULL;
		}
		NA_FREE(na);
	}
	SK_ERR("VP NA creation failed, err(%d)", err);
	return err;
}

static int
netif_vp_na_channel_event_notify(struct nexus_adapter *vpna,
    struct __kern_channel_event *ev, uint16_t ev_len)
{
	int err;
	char *baddr;
	kern_packet_t ph;
	kern_buflet_t buf;
	sk_protect_t protect;
	kern_channel_slot_t slot;
	struct __kern_packet *vpna_pkt = NULL;
	struct __kern_channel_event_metadata *emd;
	struct __kern_channel_ring *ring = &vpna->na_event_rings[0];
	struct netif_stats *nifs = &NIFNA(vpna)->nifna_netif->nif_stats;

	if (__improbable(!NA_IS_ACTIVE(vpna))) {
		STATS_INC(nifs, NETIF_STATS_EV_DROP_NA_INACTIVE);
		err = ENXIO;
		goto error;
	}
	if (__improbable(NA_IS_DEFUNCT(vpna))) {
		STATS_INC(nifs, NETIF_STATS_EV_DROP_NA_DEFUNCT);
		err = ENXIO;
		goto error;
	}
	if (!NA_CHANNEL_EVENT_ATTACHED(vpna)) {
		STATS_INC(nifs, NETIF_STATS_EV_DROP_KEVENT_INACTIVE);
		err = ENXIO;
		goto error;
	}
	if (__improbable(KR_DROP(ring))) {
		STATS_INC(nifs, NETIF_STATS_EV_DROP_KRDROP_MODE);
		err = ENXIO;
		goto error;
	}
	vpna_pkt = nx_netif_alloc_packet(ring->ckr_pp, ev_len, &ph);
	if (__improbable(vpna_pkt == NULL)) {
		STATS_INC(nifs, NETIF_STATS_EV_DROP_NOMEM_PKT);
		err = ENOMEM;
		goto error;
	}
	buf = __packet_get_next_buflet(ph, NULL);
	baddr = __buflet_get_data_address(buf);
	emd = (struct __kern_channel_event_metadata *)(void *)baddr;
	emd->emd_etype = CHANNEL_EVENT_PACKET_TRANSMIT_STATUS;
	emd->emd_nevents = 1;
	bcopy(ev, (baddr + __KERN_CHANNEL_EVENT_OFFSET), ev_len);
	err = __buflet_set_data_length(buf,
	    (ev_len + __KERN_CHANNEL_EVENT_OFFSET));
	VERIFY(err == 0);
	err = __packet_finalize(ph);
	VERIFY(err == 0);
	kr_enter(ring, TRUE);
	protect = sk_sync_protect();
	slot = kern_channel_get_next_slot(ring, NULL, NULL);
	if (slot == NULL) {
		sk_sync_unprotect(protect);
		kr_exit(ring);
		STATS_INC(nifs, NETIF_STATS_EV_DROP_KRSPACE);
		err = ENOSPC;
		goto error;
	}
	err = kern_channel_slot_attach_packet(ring, slot, ph);
	VERIFY(err == 0);
	vpna_pkt = NULL;
	kern_channel_advance_slot(ring, slot);
	sk_sync_unprotect(protect);
	kr_exit(ring);
	kern_channel_event_notify(&vpna->na_tx_rings[0]);
	STATS_INC(nifs, NETIF_STATS_EV_SENT);
	return 0;

error:
	ASSERT(err != 0);
	if (vpna_pkt != NULL) {
		nx_netif_free_packet(vpna_pkt);
	}
	STATS_INC(nifs, NETIF_STATS_EV_DROP);
	return err;
}

static inline struct nexus_adapter *
nx_netif_find_port_vpna(struct nx_netif *netif, uint32_t nx_port_id)
{
	struct kern_nexus *nx = netif->nif_nx;
	struct nexus_adapter *na = NULL;
	nexus_port_t port;
	uint16_t gencnt;

	PKT_DECOMPOSE_NX_PORT_ID(nx_port_id, port, gencnt);
	if (port < NEXUS_PORT_NET_IF_CLIENT) {
		SK_ERR("non VPNA port");
		return NULL;
	}
	if (__improbable(!nx_port_is_valid(nx, port))) {
		SK_ERR("%s[%d] port no longer valid",
		    if_name(netif->nif_ifp), port);
		return NULL;
	}
	na = nx_port_get_na(nx, port);
	if (na != NULL && NIFNA(na)->nifna_gencnt != gencnt) {
		return NULL;
	}
	return na;
}

errno_t
netif_vp_na_channel_event(struct nx_netif *nif, uint32_t nx_port_id,
    struct __kern_channel_event *event, uint16_t event_len)
{
	int err = 0;
	struct nexus_adapter *netif_vpna;
	struct netif_stats *nifs = &nif->nif_stats;

	NETIF_RLOCK(nif);
	if (!NETIF_IS_LOW_LATENCY(nif)) {
		err = ENOTSUP;
		goto error;
	}
	if (__improbable(nif->nif_vp_cnt == 0)) {
		STATS_INC(nifs, NETIF_STATS_EV_DROP_NO_VPNA);
		err = ENXIO;
		goto error;
	}
	netif_vpna = nx_netif_find_port_vpna(nif, nx_port_id);
	if (__improbable(netif_vpna == NULL)) {
		err = ENXIO;
		STATS_INC(nifs, NETIF_STATS_EV_DROP_DEMUX_ERR);
		goto error;
	}
	if (__improbable(netif_vpna->na_channel_event_notify == NULL)) {
		err = ENOTSUP;
		STATS_INC(nifs, NETIF_STATS_EV_DROP_EV_VPNA_NOTSUP);
		goto error;
	}
	err = netif_vpna->na_channel_event_notify(netif_vpna, event, event_len);
	NETIF_RUNLOCK(nif);
	return err;

error:
	STATS_INC(nifs, NETIF_STATS_EV_DROP);
	NETIF_RUNLOCK(nif);
	return err;
}
