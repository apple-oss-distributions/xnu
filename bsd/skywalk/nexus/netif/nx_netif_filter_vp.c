/*
 * Copyright (c) 2019-2021 Apple Inc. All rights reserved.
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

#define NETIF_FILTER_RX_RINGS 2 /* ring[0] for ingress, ring[1] for egress */
#define NETIF_FILTER_TX_RINGS 2 /* ring[0] for ingress, ring[1] for egress */
#define NETIF_FILTER_ALLOC_SLOTS 128 /* alloc ring size */
#define NETIF_FILTER_RING_INBOUND 0
#define NETIF_FILTER_RING_OUTBOUND 1

/* 0 means the buffer size is derived from the device MTU */
static uint32_t filter_buf_sz = 0;
static uint32_t filter_pool_size = 8192;
static uint32_t filter_tx_slots = 0;
static uint32_t filter_rx_slots = 0;

#if (DEVELOPMENT || DEBUG)
SYSCTL_UINT(_kern_skywalk_netif, OID_AUTO, filter_buf_sz,
    CTLFLAG_RW | CTLFLAG_LOCKED, &filter_buf_sz, 0,
    "filter buffer size");
SYSCTL_UINT(_kern_skywalk_netif, OID_AUTO, filter_pool_size,
    CTLFLAG_RW | CTLFLAG_LOCKED, &filter_pool_size, 0,
    "filter pool size");
SYSCTL_UINT(_kern_skywalk_netif, OID_AUTO, filter_tx_slots,
    CTLFLAG_RW | CTLFLAG_LOCKED, &filter_tx_slots, 0,
    "filter tx slots");
SYSCTL_UINT(_kern_skywalk_netif, OID_AUTO, filter_rx_slots,
    CTLFLAG_RW | CTLFLAG_LOCKED, &filter_rx_slots, 0,
    "filter rx slots");
#endif /* (DEVELOPMENT || DEBUG) */

static void
netif_filter_dump_packet(struct __kern_packet *pkt)
{
	uint8_t *baddr;

	MD_BUFLET_ADDR_ABS(pkt, baddr);
	ASSERT(baddr != NULL);
	baddr += pkt->pkt_headroom;

	DTRACE_SKYWALK2(dump__packet, struct __kern_packet *,
	    pkt, uint8_t *, baddr);
}

SK_NO_INLINE_ATTRIBUTE
static errno_t
netif_filter_deliver(struct nexus_adapter *na, struct __kern_channel_ring *ring,
    struct __kern_packet *pkt_chain, uint32_t flags)
{
#pragma unused(flags)
	struct __kern_packet *pkt = pkt_chain, *next;
	kern_channel_slot_t last_slot = NULL, slot = NULL;
	struct nexus_netif_adapter *nifna = NIFNA(na);
	struct netif_stats *nifs = &nifna->nifna_netif->nif_stats;
	sk_protect_t protect;
	kern_packet_t ph;
	int cnt = 0, dropcnt = 0;
	errno_t err;

	kr_enter(ring, TRUE);
	protect = sk_sync_protect();

	if (__improbable(KR_DROP(ring))) {
		nx_netif_free_packet_chain(pkt, &dropcnt);
		STATS_ADD(nifs, NETIF_STATS_FILTER_DROP_DISABLED_RING, dropcnt);
		STATS_ADD(nifs, NETIF_STATS_DROP, dropcnt);
		DTRACE_SKYWALK2(ring__drop, struct __kern_channel_ring *, ring,
		    int, dropcnt);
		sk_sync_unprotect(protect);
		kr_exit(ring);
		return ENXIO;
	}
	while (pkt != NULL) {
		slot = kern_channel_get_next_slot(ring, slot, NULL);
		if (slot == NULL) {
			break;
		}

		next = pkt->pkt_nextpkt;
		pkt->pkt_nextpkt = NULL;
		netif_filter_dump_packet(pkt);

		ph = SK_PKT2PH(pkt);
		err = kern_channel_slot_attach_packet(ring, slot, ph);
		VERIFY(err == 0);

		last_slot = slot;
		pkt = next;
		cnt++;
	}
	if (ring->ckr_ring_id == NETIF_FILTER_RING_INBOUND) {
		STATS_ADD(nifs, NETIF_STATS_FILTER_RX_DELIVER, cnt);
	} else {
		STATS_ADD(nifs, NETIF_STATS_FILTER_TX_DELIVER, cnt);
	}
	DTRACE_SKYWALK4(delivered, struct nexus_adapter *, na,
	    struct __kern_channel_ring *, ring, struct __kern_packet *, pkt,
	    int, cnt);

	if (pkt != NULL) {
		nx_netif_free_packet_chain(pkt, &dropcnt);
		STATS_ADD(nifs, NETIF_STATS_FILTER_DROP_NO_SPACE, dropcnt);
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
netif_filter_rx_cb(void *arg, struct __kern_packet *pkt_chain, uint32_t flags)
{
	struct nexus_adapter *na = arg;
	struct __kern_channel_ring *ring =
	    &na->na_rx_rings[NETIF_FILTER_RING_INBOUND];
	return netif_filter_deliver(na, ring, pkt_chain, flags);
}

static errno_t
netif_filter_tx_cb(void *arg, struct __kern_packet *pkt_chain, uint32_t flags)
{
	struct nexus_adapter *na = arg;
	struct __kern_channel_ring *ring =
	    &na->na_rx_rings[NETIF_FILTER_RING_OUTBOUND];
	return netif_filter_deliver(na, ring, pkt_chain, flags);
}

static errno_t
netif_filter_cb(void *arg, struct __kern_packet *pkt_chain, uint32_t flags)
{
	errno_t err;

	if ((flags & NETIF_FILTER_RX) != 0) {
		err = netif_filter_rx_cb(arg, pkt_chain, flags);
	} else {
		err = netif_filter_tx_cb(arg, pkt_chain, flags);
	}
	return err;
}

static int
netif_filter_na_activate(struct nexus_adapter *na, na_activate_mode_t mode)
{
	errno_t err;
	struct netif_filter *nf;
	struct nexus_netif_adapter *nifna;

	ASSERT(na->na_type == NA_NETIF_FILTER);
	nifna = NIFNA(na);
	if (mode == NA_ACTIVATE_MODE_ON) {
		err = nx_netif_filter_add(nifna->nifna_netif, na->na_nx_port,
		    na, netif_filter_cb, &nf);
		if (err != 0) {
			return err;
		}
		nifna->nifna_filter = nf;
		atomic_bitset_32(&na->na_flags, NAF_ACTIVE);
	} else {
		err = nx_netif_filter_remove(nifna->nifna_netif,
		    nifna->nifna_filter);
		VERIFY(err == 0);
		nifna->nifna_filter = NULL;
		atomic_bitclear_32(&na->na_flags, NAF_ACTIVE);
	}

	SK_DF(SK_VERB_FILTER, "na \"%s\" (0x%llx) %s", na->na_name,
	    SK_KVA(na), na_activate_mode2str(mode));
	return 0;
}

static int
netif_filter_na_krings_create(struct nexus_adapter *na, struct kern_channel *ch)
{
	ASSERT(na->na_type == NA_NETIF_FILTER);
	return na_rings_mem_setup(na, 0, FALSE, ch);
}

static void
netif_filter_na_krings_delete(struct nexus_adapter *na, struct kern_channel *ch,
    boolean_t defunct)
{
	ASSERT(na->na_type == NA_NETIF_FILTER);
	na_rings_mem_teardown(na, ch, defunct);
}

static int
netif_filter_region_params_setup(struct nexus_adapter *na,
    struct skmem_region_params *srp)
{
	uint32_t max_mtu;
	uint32_t buf_sz, buf_cnt, nslots, afslots, totalrings;
	int err, i;

	if ((err = nx_netif_get_max_mtu(na->na_ifp, &max_mtu)) != 0) {
		/*
		 * Use a default mtu if the driver doesn't support this
		 * ioctl.
		 */
		max_mtu = ETHERMTU;
	}
	for (i = 0; i < SKMEM_REGIONS; i++) {
		srp[i] = *skmem_get_default(i);
	}
	totalrings = na_get_nrings(na, NR_TX) + na_get_nrings(na, NR_RX) +
	    na_get_nrings(na, NR_A) + na_get_nrings(na, NR_F);

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
	srp[SKMEM_REGION_TXAKSD].srp_r_obj_size =
	    MAX(nslots, afslots) * SLOT_DESC_SZ;
	srp[SKMEM_REGION_TXAKSD].srp_r_obj_cnt =
	    na_get_nrings(na, NR_TX) +
	    na_get_nrings(na, NR_A);
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
	    na_get_nrings(na, NR_RX) +
	    na_get_nrings(na, NR_F);
	skmem_region_params_config(&srp[SKMEM_REGION_RXFKSD]);

	/* USD and KSD objects share the same size and count */
	srp[SKMEM_REGION_RXFUSD].srp_r_obj_size =
	    srp[SKMEM_REGION_RXFKSD].srp_r_obj_size;
	srp[SKMEM_REGION_RXFUSD].srp_r_obj_cnt =
	    srp[SKMEM_REGION_RXFKSD].srp_r_obj_cnt;
	skmem_region_params_config(&srp[SKMEM_REGION_RXFUSD]);

	/* max_mtu does not include the L2 header */
	buf_sz = (filter_buf_sz != 0) ? filter_buf_sz :
	    MAX(max_mtu + sizeof(struct ether_vlan_header), 2048);
	buf_cnt = filter_pool_size;
	pp_regions_params_adjust(srp, NEXUS_META_TYPE_PACKET,
	    NEXUS_META_SUBTYPE_RAW, buf_cnt, 1, buf_sz, 0, buf_cnt, 0,
	    (PP_REGION_CONFIG_BUF_IODIR_BIDIR |
	    PP_REGION_CONFIG_MD_MAGAZINE_ENABLE |
	    PP_REGION_CONFIG_BUF_UREADONLY));

	nx_netif_vp_region_params_adjust(na, srp);
	return 0;
}

static int
netif_filter_na_mem_new(struct nexus_adapter *na)
{
	struct kern_nexus *nx = na->na_nx;
	struct nx_netif *nif = nx->nx_arg;
	struct skmem_region_params srp[SKMEM_REGIONS];
	int err;

	NETIF_WLOCK_ASSERT_HELD(nif);
	ASSERT(nif->nif_ifp != NULL);

	err = netif_filter_region_params_setup(na, srp);
	if (err != 0) {
		return err;
	}
	/*
	 * Create buffer pool on first use.
	 * No locks held because no one will be using this until
	 * nif_filter_cnt > 0.
	 */
	if (nif->nif_filter_pp == NULL) {
		struct kern_pbufpool *pp = NULL;
		uint32_t pp_flags = 0;
		char pp_name[64];

		snprintf(pp_name, sizeof(pp_name), "%s_netif_filter_pp",
		    if_name(nif->nif_ifp));
		if (srp[SKMEM_REGION_KMD].srp_max_frags > 1) {
			pp_flags |= PPCREATEF_ONDEMAND_BUF;
		}
		pp = pp_create(pp_name, srp, NULL, NULL, NULL, NULL, NULL,
		    pp_flags);
		if (pp == NULL) {
			SK_ERR("failed to create filter pp");
			return ENOMEM;
		}
		nif->nif_filter_pp = pp;
	}
	na->na_arena = skmem_arena_create_for_nexus(na, srp,
	    &nif->nif_filter_pp, NULL, 0, NULL, &err);
	ASSERT(na->na_arena != NULL || err != 0);
	ASSERT(nx->nx_tx_pp == NULL || (nx->nx_tx_pp->pp_md_type ==
	    NX_DOM(nx)->nxdom_md_type && nx->nx_tx_pp->pp_md_subtype ==
	    NX_DOM(nx)->nxdom_md_subtype));

	return 0;
}

static int
netif_filter_na_rxsync(struct __kern_channel_ring *kring, struct proc *p,
    uint32_t flags)
{
#pragma unused(p, flags)
	(void) kr_reclaim(kring);
	return 0;
}

struct filter_pktq {
	struct __kern_packet *fp_head;
	struct __kern_packet **fp_tailp;
};

static int
netif_filter_na_txsync(struct __kern_channel_ring *kring, struct proc *p,
    uint32_t flags)
{
#pragma unused(p, flags)
	kern_channel_slot_t last_slot = NULL, slot = NULL;
	struct filter_pktq pktq[KPKT_TC_MAX], *q;
	struct __kern_packet *pkt;
	struct nexus_netif_adapter *dev_nifna;
	struct nexus_netif_adapter *nifna;
	struct netif_stats *nifs;
	uint32_t ringid, iflags = 0;
	kern_packet_traffic_class_t tc;
	kern_packet_t ph;
	errno_t err;
	int cnt = 0, i;

	dev_nifna = NIFNA(nx_port_get_na(KRNA(kring)->na_nx,
	    NEXUS_PORT_NET_IF_DEV));
	nifna = NIFNA(KRNA(kring));
	nifs = &nifna->nifna_netif->nif_stats;

	ringid = kring->ckr_ring_id;
	ASSERT(ringid == NETIF_FILTER_RING_INBOUND ||
	    ringid == NETIF_FILTER_RING_OUTBOUND);
	iflags = (ringid == NETIF_FILTER_RING_INBOUND) ? NETIF_FILTER_RX :
	    NETIF_FILTER_TX;
	iflags |= NETIF_FILTER_INJECT;

	for (i = 0; i < KPKT_TC_MAX; i++) {
		pktq[i].fp_head = NULL;
		pktq[i].fp_tailp = &pktq[i].fp_head;
	}
	for (;;) {
		slot = kern_channel_get_next_slot(kring, slot, NULL);
		if (slot == NULL) {
			break;
		}
		ph = kern_channel_slot_get_packet(kring, slot);
		if (__improbable(ph == 0)) {
			SK_ERR("packet got dropped by internalize");
			STATS_INC(nifs, NETIF_STATS_FILTER_DROP_INTERNALIZE);
			DTRACE_SKYWALK2(bad__slot, struct __kern_channel_ring *,
			    kring, kern_channel_slot_t, slot);
			last_slot = slot;
			continue;
		}
		pkt = SK_PTR_ADDR_KPKT(ph);
		if (__improbable(pkt->pkt_length == 0)) {
			SK_ERR("dropped zero length packet");
			STATS_INC(nifs, NETIF_STATS_FILTER_BAD_PKT_LEN);
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

		cnt++;
		netif_filter_dump_packet(pkt);
		VERIFY(pkt->pkt_nextpkt == NULL);

		/*
		 * This returns a valid value even if the packet doesn't have a
		 * traffic class.
		 */
		tc = kern_packet_get_traffic_class(ph);
		VERIFY(tc < KPKT_TC_MAX);
		q = &pktq[tc];

		*q->fp_tailp = pkt;
		q->fp_tailp = &pkt->pkt_nextpkt;
	}
	if (cnt == 0) {
		STATS_ADD(nifs, NETIF_STATS_FILTER_SYNC_NO_PKTS, cnt);
		DTRACE_SKYWALK2(no__data, struct nexus_netif_adapter *, nifna,
		    struct __kern_channel_ring *, kring);
		return 0;
	}
	if (kring->ckr_ring_id == NETIF_FILTER_RING_INBOUND) {
		STATS_ADD(nifs, NETIF_STATS_FILTER_RX_INJECT, cnt);
	} else {
		STATS_ADD(nifs, NETIF_STATS_FILTER_TX_INJECT, cnt);
	}
	DTRACE_SKYWALK4(injected, struct nexus_netif_adapter *, nifna,
	    struct __kern_channel_ring *, kring, int, cnt, uint32_t, iflags);

	if (last_slot != NULL) {
		kern_channel_advance_slot(kring, last_slot);
	}
	for (i = 0; i < KPKT_TC_MAX; i++) {
		q = &pktq[i];
		if (q->fp_head == NULL) {
			continue;
		}
		err = nx_netif_filter_inject(dev_nifna, nifna->nifna_filter,
		    q->fp_head, iflags);
		if (err != 0) {
			DTRACE_SKYWALK3(inject__failed,
			    struct nexus_netif_adapter *, nifna,
			    struct __kern_channel_ring *, kring, int, err);
		}
	}
	return 0;
}

static void
netif_filter_na_dtor(struct nexus_adapter *na)
{
	struct kern_nexus *nx = na->na_nx;
	struct nx_netif *nif = NX_NETIF_PRIVATE(nx);
	struct nexus_netif_adapter *nifna = NIFNA(na);

	NETIF_WLOCK(nif);
	/*
	 * XXX port free does not belong here as this is not symmetrical
	 * with na_create below.
	 */
	(void) nx_port_unbind(nx, na->na_nx_port);
	nx_port_free(nx, na->na_nx_port);
	nif->nif_filter_vp_cnt--;

	/*
	 * TODO
	 * Move back the buffer pool free to here when we have the proper
	 * fix.
	 */
	if (na->na_ifp != NULL) {
		ifnet_decr_iorefcnt(na->na_ifp);
		na->na_ifp = NULL;
	}
	if (nifna->nifna_netif != NULL) {
		nx_netif_release(nifna->nifna_netif);
		nifna->nifna_netif = NULL;
	}
	NETIF_WUNLOCK(nif);
	SK_DF(SK_VERB_FILTER, "na \"%s\" (0x%llx)", na->na_name, SK_KVA(na));
}

int
netif_filter_na_create(struct kern_nexus *nx, struct chreq *chr,
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
	ASSERT((chr->cr_mode & CHMODE_FILTER) != 0);
	if ((chr->cr_mode & CHMODE_USER_PACKET_POOL) == 0) {
		SK_ERR("user packet pool required");
		return EINVAL;
	}
	if ((chr->cr_mode & CHMODE_EVENT_RING) != 0) {
		SK_ERR("event ring is not supported for netif filter channel");
		return ENOTSUP;
	}
	/*
	 * No locking needed while checking for the initialized bit because
	 * if this were not set, no other codepaths would modify the flags.
	 */
	if ((nif->nif_filter_flags & NETIF_FILTER_FLAG_INITIALIZED) == 0) {
		SK_ERR("filter vp not supported");
		return ENOTSUP;
	}

	/*
	 * XXX
	 * We should not be allocating from na_netif_alloc() because
	 * most fields are irrelevant. The filter adapter needs
	 * its own zone.
	 */
	na = (struct nexus_adapter *)na_netif_alloc(Z_WAITOK);
	nifna = NIFNA(na);
	nifna->nifna_netif = nif;
	nx_netif_retain(nif);
	nifna->nifna_filter = NULL;

	(void) snprintf(na->na_name, sizeof(na->na_name), "%s_filter:%d",
	    if_name(nif->nif_ifp), chr->cr_port);
	uuid_generate_random(na->na_uuid);

	na_set_nrings(na, NR_RX, NETIF_FILTER_RX_RINGS);
	na_set_nrings(na, NR_TX, NETIF_FILTER_TX_RINGS);
	/*
	 * If the packet pool is configured to be multi-buflet, then we
	 * need 2 pairs of alloc/free rings(for packet and buflet).
	 */
	na_set_nrings(na, NR_A, ((nxp->nxp_max_frags > 1) &&
	    (sk_channel_buflet_alloc != 0)) ? 2 : 1);
	ASSERT(na_get_nrings(na, NR_TX) <= NX_DOM(nx)->nxdom_tx_rings.nb_max);
	ASSERT(na_get_nrings(na, NR_RX) <= NX_DOM(nx)->nxdom_rx_rings.nb_max);

	slots = MAX(NX_DOM(nx)->nxdom_tx_slots.nb_def,
	    NX_DOM(nx)->nxdom_rx_slots.nb_def);

	na_set_nslots(na, NR_TX, filter_tx_slots != 0 ?
	    filter_tx_slots : slots);
	na_set_nslots(na, NR_RX, filter_rx_slots != 0 ?
	    filter_rx_slots : slots);

	na_set_nslots(na, NR_A, NETIF_FILTER_ALLOC_SLOTS);
	ASSERT(na_get_nslots(na, NR_TX) <= NX_DOM(nx)->nxdom_tx_slots.nb_max);
	ASSERT(na_get_nslots(na, NR_RX) <= NX_DOM(nx)->nxdom_rx_slots.nb_max);

	atomic_bitset_32(&na->na_flags, NAF_USER_PKT_POOL);

	na->na_nx_port = chr->cr_port;
	na->na_type = NA_NETIF_FILTER;
	na->na_free = na_netif_free;
	na->na_dtor = netif_filter_na_dtor;
	na->na_activate = netif_filter_na_activate;
	na->na_txsync = netif_filter_na_txsync;
	na->na_rxsync = netif_filter_na_rxsync;
	na->na_krings_create = netif_filter_na_krings_create;
	na->na_krings_delete = netif_filter_na_krings_delete;
	na->na_special = NULL;
	na->na_ifp = nif->nif_ifp;
	ifnet_incr_iorefcnt(na->na_ifp);

	*(nexus_stats_type_t *)(uintptr_t)&na->na_stats_type =
	    NEXUS_STATS_TYPE_INVALID;

	/* other fields are set in the common routine */
	na_attach_common(na, nx, &nx_netif_prov_s);

	err = netif_filter_na_mem_new(na);
	if (err != 0) {
		ASSERT(na->na_arena == NULL);
		goto err;
	}

	*(uint32_t *)(uintptr_t)&na->na_flowadv_max = nxp->nxp_flowadv_max;
	ASSERT(na->na_flowadv_max == 0 ||
	    skmem_arena_nexus(na->na_arena)->arn_flowadv_obj != NULL);

	/*
	 * This is different from nif->nif_filter_cnt. This tracks the number
	 * of filter NAs created. nif->nif_filter_cnt tracks how many are
	 * attached to the datapath.
	 */
	nif->nif_filter_vp_cnt++;
	*nap = na;

	SK_DF(SK_VERB_FILTER, "%s created", na->na_name);
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
	SK_ERR("filter NA creation failed, err(%d)", err);
	return err;
}
