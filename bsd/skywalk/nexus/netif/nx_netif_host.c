/*
 * Copyright (c) 2015-2022 Apple Inc. All rights reserved.
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
#define _IP_VHL
#include <skywalk/os_skywalk_private.h>
#include <skywalk/nexus/netif/nx_netif.h>
#include <skywalk/nexus/flowswitch/nx_flowswitch.h>
#include <net/ethernet.h>
#include <net/pktap.h>
#include <sys/kdebug.h>
#include <sys/sdt.h>

#define DBG_FUNC_NX_NETIF_HOST_ENQUEUE  \
	SKYWALKDBG_CODE(DBG_SKYWALK_NETIF, 2)

static void nx_netif_host_catch_tx(struct nexus_adapter *, bool);
static inline struct __kern_packet*
nx_netif_mbuf_to_kpkt(struct nexus_adapter *, struct mbuf *);

#define SK_IFCAP_CSUM   (IFCAP_HWCSUM|IFCAP_CSUM_PARTIAL|IFCAP_CSUM_ZERO_INVERT)

static void
nx_netif_host_adjust_if_capabilities(struct nexus_adapter *na, bool activate)
{
	struct nx_netif *nif = ((struct nexus_netif_adapter *)na)->nifna_netif;
	struct ifnet *ifp = na->na_ifp;

	ifnet_lock_exclusive(ifp);

	if (activate) {
		/* XXX: adi@apple.com - disable TSO and LRO for now */
		nif->nif_hwassist = ifp->if_hwassist;
		nif->nif_capabilities = ifp->if_capabilities;
		nif->nif_capenable = ifp->if_capenable;
		ifp->if_hwassist &= ~(IFNET_CHECKSUMF | IFNET_TSOF);
		ifp->if_capabilities &= ~(SK_IFCAP_CSUM | IFCAP_TSO);
		ifp->if_capenable &= ~(SK_IFCAP_CSUM | IFCAP_TSO);

		/*
		 * Re-enable the capabilities which Skywalk layer provides:
		 *
		 * Native driver: a copy from packet to mbuf always occurs
		 * for each inbound and outbound packet; we leverage combined
		 * and copy checksum, and thus advertise the capabilities.
		 * We also always enable 16KB jumbo mbuf support.
		 *
		 * Compat driver: inbound and outbound mbufs don't incur a
		 * copy, and so leave the driver advertised flags alone.
		 */
		if (NA_KERNEL_ONLY(na)) {
			if (na->na_type == NA_NETIF_HOST) {     /* native */
				ifp->if_hwassist |= (IFNET_CSUM_TCP |
				    IFNET_CSUM_UDP | IFNET_CSUM_TCPIPV6 |
				    IFNET_CSUM_UDPIPV6 | IFNET_CSUM_PARTIAL |
				    IFNET_CSUM_ZERO_INVERT | IFNET_MULTIPAGES);
				ifp->if_capabilities |= SK_IFCAP_CSUM;
				ifp->if_capenable |= SK_IFCAP_CSUM;
				if (sk_fsw_tx_agg_tcp != 0) {
					ifp->if_hwassist |= IFNET_TSOF;
					ifp->if_capabilities |= IFCAP_TSO;
					ifp->if_capenable |= IFCAP_TSO;
				}
			} else {                                /* compat */
				ifp->if_hwassist |=
				    (nif->nif_hwassist &
				    (IFNET_CHECKSUMF | IFNET_TSOF));
				ifp->if_capabilities |=
				    (nif->nif_capabilities &
				    (SK_IFCAP_CSUM | IFCAP_TSO));
				ifp->if_capenable |=
				    (nif->nif_capenable &
				    (SK_IFCAP_CSUM | IFCAP_TSO));
			}
		}
	} else {
		/* Unset any capabilities previously set by Skywalk */
		ifp->if_hwassist &= ~(IFNET_CHECKSUMF | IFNET_MULTIPAGES);
		ifp->if_capabilities &= ~SK_IFCAP_CSUM;
		ifp->if_capenable &= ~SK_IFCAP_CSUM;
		if ((sk_fsw_tx_agg_tcp != 0) &&
		    (na->na_type == NA_NETIF_HOST)) {
			ifp->if_hwassist &= ~IFNET_TSOF;
			ifp->if_capabilities &= ~IFCAP_TSO;
			ifp->if_capenable &= ~IFCAP_TSO;
		}
		/* Restore driver original flags */
		ifp->if_hwassist |= (nif->nif_hwassist &
		    (IFNET_CHECKSUMF | IFNET_TSOF | IFNET_MULTIPAGES));
		ifp->if_capabilities |=
		    (nif->nif_capabilities & (SK_IFCAP_CSUM | IFCAP_TSO));
		ifp->if_capenable |=
		    (nif->nif_capenable & (SK_IFCAP_CSUM | IFCAP_TSO));
	}

	ifnet_lock_done(ifp);
}

static  bool
nx_netif_host_is_gso_needed(struct nexus_adapter *na)
{
	struct nx_netif *nif = ((struct nexus_netif_adapter *)na)->nifna_netif;

	/*
	 * Don't enable for Compat netif.
	 */
	if (na->na_type != NA_NETIF_HOST) {
		return false;
	}
	/*
	 * Don't enable if netif is not plumbed under a flowswitch.
	 */
	if (!NA_KERNEL_ONLY(na)) {
		return false;
	}
	/*
	 * Don't enable If HW TSO is enabled.
	 */
	if (((nif->nif_hwassist & IFNET_TSO_IPV4) != 0) ||
	    ((nif->nif_hwassist & IFNET_TSO_IPV6) != 0)) {
		return false;
	}
	/*
	 * Don't enable if TX aggregation is disabled.
	 */
	if (sk_fsw_tx_agg_tcp == 0) {
		return false;
	}
	return true;
}

int
nx_netif_host_na_activate(struct nexus_adapter *na, na_activate_mode_t mode)
{
	struct ifnet *ifp = na->na_ifp;
	int error = 0;

	ASSERT(na->na_type == NA_NETIF_HOST ||
	    na->na_type == NA_NETIF_COMPAT_HOST);
	ASSERT(na->na_flags & NAF_HOST_ONLY);

	SK_DF(SK_VERB_NETIF, "na \"%s\" (0x%llx) %s", na->na_name,
	    SK_KVA(na), na_activate_mode2str(mode));

	switch (mode) {
	case NA_ACTIVATE_MODE_ON:
		VERIFY(SKYWALK_CAPABLE(ifp));

		nx_netif_host_adjust_if_capabilities(na, true);
		/*
		 * Make skywalk control the packet steering
		 * Don't intercept tx packets if this is a netif compat
		 * adapter attached to a flowswitch
		 */
		nx_netif_host_catch_tx(na, true);

		atomic_bitset_32(&na->na_flags, NAF_ACTIVE);
		break;

	case NA_ACTIVATE_MODE_DEFUNCT:
		VERIFY(SKYWALK_CAPABLE(ifp));
		break;

	case NA_ACTIVATE_MODE_OFF:
		/* Release packet steering control. */
		nx_netif_host_catch_tx(na, false);

		/*
		 * Note that here we cannot assert SKYWALK_CAPABLE()
		 * as we're called in the destructor path.
		 */
		atomic_bitclear_32(&na->na_flags, NAF_ACTIVE);

		nx_netif_host_adjust_if_capabilities(na, false);
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	return error;
}

/* na_krings_create callback for netif host adapters */
int
nx_netif_host_krings_create(struct nexus_adapter *na, struct kern_channel *ch)
{
	int ret;

	SK_LOCK_ASSERT_HELD();
	ASSERT(na->na_type == NA_NETIF_HOST ||
	    na->na_type == NA_NETIF_COMPAT_HOST);
	ASSERT(na->na_flags & NAF_HOST_ONLY);

	ret = na_rings_mem_setup(na, FALSE, ch);
	if (ret == 0) {
		struct __kern_channel_ring *kring;
		uint32_t i;

		/* drop by default until fully bound */
		if (NA_KERNEL_ONLY(na)) {
			na_kr_drop(na, TRUE);
		}

		for (i = 0; i < na_get_nrings(na, NR_RX); i++) {
			kring = &NAKR(na, NR_RX)[i];
			/* initialize the nx_mbq for the sw rx ring */
			nx_mbq_safe_init(kring, &kring->ckr_rx_queue,
			    NX_MBQ_NO_LIMIT, &nexus_mbq_lock_group,
			    &nexus_lock_attr);
			SK_DF(SK_VERB_NETIF,
			    "na \"%s\" (0x%llx) initialized host kr \"%s\" "
			    "(0x%llx) krflags 0x%b", na->na_name, SK_KVA(na),
			    kring->ckr_name, SK_KVA(kring), kring->ckr_flags,
			    CKRF_BITS);
		}
	}
	return ret;
}

/*
 * Destructor for netif host adapters; they also have an mbuf queue
 * on the rings connected to the host so we need to purge them first.
 */
void
nx_netif_host_krings_delete(struct nexus_adapter *na, struct kern_channel *ch,
    boolean_t defunct)
{
	struct __kern_channel_ring *kring;
	uint32_t i;

	SK_LOCK_ASSERT_HELD();
	ASSERT(na->na_type == NA_NETIF_HOST ||
	    na->na_type == NA_NETIF_COMPAT_HOST);
	ASSERT(na->na_flags & NAF_HOST_ONLY);

	if (NA_KERNEL_ONLY(na)) {
		na_kr_drop(na, TRUE);
	}

	for (i = 0; i < na_get_nrings(na, NR_RX); i++) {
		struct nx_mbq *q;

		kring = &NAKR(na, NR_RX)[i];
		q = &kring->ckr_rx_queue;
		SK_DF(SK_VERB_NETIF,
		    "na \"%s\" (0x%llx) destroy host kr \"%s\" (0x%llx) "
		    "krflags 0x%b with qlen %u", na->na_name, SK_KVA(na),
		    kring->ckr_name, SK_KVA(kring), kring->ckr_flags,
		    CKRF_BITS, nx_mbq_len(q));
		nx_mbq_purge(q);
		if (!defunct) {
			nx_mbq_safe_destroy(q);
		}
	}

	na_rings_mem_teardown(na, ch, defunct);
}

/* kring->ckr_na_sync callback for the host rx ring */
int
nx_netif_host_na_rxsync(struct __kern_channel_ring *kring,
    struct proc *p, uint32_t flags)
{
#pragma unused(kring, p, flags)
	return 0;
}

/*
 * kring->ckr_na_sync callback for the host tx ring.
 */
int
nx_netif_host_na_txsync(struct __kern_channel_ring *kring, struct proc *p,
    uint32_t flags)
{
#pragma unused(kring, p, flags)
	return 0;
}

int
nx_netif_host_na_special(struct nexus_adapter *na, struct kern_channel *ch,
    struct chreq *chr, nxspec_cmd_t spec_cmd)
{
	ASSERT(na->na_type == NA_NETIF_HOST ||
	    na->na_type == NA_NETIF_COMPAT_HOST);
	return nx_netif_na_special_common(na, ch, chr, spec_cmd);
}

/*
 * Intercept the packet steering routine in the tx path,
 * so that we can decide which queue is used for an mbuf.
 * Second argument is TRUE to intercept, FALSE to restore.
 */
static void
nx_netif_host_catch_tx(struct nexus_adapter *na, bool activate)
{
	struct ifnet *ifp = na->na_ifp;
	int err = 0;

	ASSERT(na->na_type == NA_NETIF_HOST ||
	    na->na_type == NA_NETIF_COMPAT_HOST);
	ASSERT(na->na_flags & NAF_HOST_ONLY);

	/*
	 * Common case is NA_KERNEL_ONLY: if the netif is plumbed
	 * below the flowswitch.  For TXSTART compat driver and legacy:
	 * don't intercept DLIL output handler, since in this model
	 * packets from both BSD stack and flowswitch are directly
	 * enqueued to the classq via ifnet_enqueue().
	 *
	 * Otherwise, it's the uncommon case where a user channel is
	 * opened directly to the netif.  Here we either intercept
	 * or restore the DLIL output handler.
	 */
	if (activate) {
		if (__improbable(!NA_KERNEL_ONLY(na))) {
			return;
		}
		/*
		 * For native drivers only, intercept if_output();
		 * for compat, leave it alone since we don't need
		 * to perform any mbuf-pkt conversion.
		 */
		if (na->na_type == NA_NETIF_HOST) {
			err = ifnet_set_output_handler(ifp,
			    nx_netif_host_is_gso_needed(na) ?
			    netif_gso_dispatch : nx_netif_host_output);
			VERIFY(err == 0);
		}
	} else {
		if (__improbable(!NA_KERNEL_ONLY(na))) {
			return;
		}
		/*
		 * Restore original if_output() for native drivers.
		 */
		if (na->na_type == NA_NETIF_HOST) {
			ifnet_reset_output_handler(ifp);
		}
	}
}

static int
get_af_from_mbuf(struct mbuf *m)
{
	uint8_t *pkt_hdr;
	uint8_t ipv;
	struct mbuf *m0;
	int af;

	pkt_hdr = m->m_pkthdr.pkt_hdr;
	for (m0 = m; m0 != NULL; m0 = m0->m_next) {
		if (pkt_hdr >= (uint8_t *)m0->m_data &&
		    pkt_hdr < (uint8_t *)m0->m_data + m0->m_len) {
			break;
		}
	}
	if (m0 == NULL) {
		DTRACE_SKYWALK1(bad__pkthdr, struct mbuf *, m);
		af = AF_UNSPEC;
		goto done;
	}
	ipv = IP_VHL_V(*pkt_hdr);
	if (ipv == 4) {
		af = AF_INET;
	} else if (ipv == 6) {
		af = AF_INET6;
	} else {
		af = AF_UNSPEC;
	}
done:
	DTRACE_SKYWALK2(mbuf__af, int, af, struct mbuf *, m);
	return af;
}

/*
 * if_output() callback called by dlil_output() to handle mbufs coming out
 * of the host networking stack.  The mbuf will get converted to a packet,
 * and enqueued to the classq of a Skywalk native interface.
 */
int
nx_netif_host_output(struct ifnet *ifp, struct mbuf *m)
{
	struct nx_netif *nif = NA(ifp)->nifna_netif;
	struct kern_nexus *nx = nif->nif_nx;
	struct nexus_adapter *hwna = nx_port_get_na(nx, NEXUS_PORT_NET_IF_DEV);
	struct nexus_adapter *hostna = nx_port_get_na(nx, NEXUS_PORT_NET_IF_HOST);
	struct __kern_channel_ring *kring;
	uint32_t sc_idx = MBUF_SCIDX(m_get_service_class(m));
	struct netif_stats *nifs = &NX_NETIF_PRIVATE(hwna->na_nx)->nif_stats;
	struct __kern_packet *kpkt;
	uint64_t qset_id;
	errno_t error = ENOBUFS;
	boolean_t pkt_drop = FALSE;

	/*
	 * nx_netif_host_catch_tx() must only be steering the output
	 * packets here only for native interfaces, otherwise we must
	 * not get here for compat.
	 */
	ASSERT(ifp->if_eflags & IFEF_SKYWALK_NATIVE);
	ASSERT(m->m_nextpkt == NULL);
	ASSERT(hostna->na_type == NA_NETIF_HOST);
	ASSERT(sc_idx < KPKT_SC_MAX_CLASSES);

	kring = &hwna->na_tx_rings[hwna->na_kring_svc_lut[sc_idx]];
	KDBG((SK_KTRACE_NETIF_HOST_ENQUEUE | DBG_FUNC_START), SK_KVA(kring));
	if (__improbable(!NA_IS_ACTIVE(hwna) || !NA_IS_ACTIVE(hostna))) {
		STATS_INC(nifs, NETIF_STATS_DROP_NA_INACTIVE);
		SK_ERR("\"%s\" (0x%llx) not in skywalk mode anymore",
		    hwna->na_name, SK_KVA(hwna));
		error = ENXIO;
		pkt_drop = TRUE;
		goto done;
	}
	/*
	 * Drop if the kring no longer accepts packets.
	 */
	if (__improbable(KR_DROP(&hostna->na_rx_rings[0]) || KR_DROP(kring))) {
		STATS_INC(nifs, NETIF_STATS_DROP_KRDROP_MODE);
		/* not a serious error, so no need to be chatty here */
		SK_DF(SK_VERB_NETIF,
		    "kr \"%s\" (0x%llx) krflags 0x%b or %s in drop mode",
		    kring->ckr_name, SK_KVA(kring), kring->ckr_flags,
		    CKRF_BITS, ifp->if_xname);
		error = ENXIO;
		pkt_drop = TRUE;
		goto done;
	}
	if (__improbable(((unsigned)m_pktlen(m) + ifp->if_tx_headroom) >
	    kring->ckr_max_pkt_len)) { /* too long for us */
		STATS_INC(nifs, NETIF_STATS_DROP_BADLEN);
		SK_ERR("\"%s\" (0x%llx) from_host, drop packet size %u > %u",
		    hwna->na_name, SK_KVA(hwna), m_pktlen(m),
		    kring->ckr_max_pkt_len);
		pkt_drop = TRUE;
		goto done;
	}
	/*
	 * Convert mbuf to packet and enqueue it.
	 */
	kpkt = nx_netif_mbuf_to_kpkt(hwna, m);
	if (__probable(kpkt != NULL)) {
		if ((m->m_pkthdr.pkt_flags & PKTF_SKIP_PKTAP) == 0 &&
		    pktap_total_tap_count != 0) {
			int af = get_af_from_mbuf(m);

			if (af != AF_UNSPEC) {
				nx_netif_pktap_output(ifp, af, kpkt);
			}
		}
		if (NX_LLINK_PROV(nif->nif_nx) &&
		    ifp->if_traffic_rule_count > 0 &&
		    nxctl_inet_traffic_rule_find_qset_id_with_pkt(ifp->if_xname,
		    kpkt, &qset_id) == 0) {
			struct netif_qset *qset;

			/*
			 * This always returns a qset because if the qset id
			 * is invalid the default qset is returned.
			 */
			qset = nx_netif_find_qset(nif, qset_id);
			ASSERT(qset != NULL);
			kpkt->pkt_qset_idx = qset->nqs_idx;
			error = ifnet_enqueue_ifcq_pkt(ifp, qset->nqs_ifcq, kpkt,
			    false, &pkt_drop);
			nx_netif_qset_release(&qset);
		} else {
			/* callee consumes packet */
			error = ifnet_enqueue_pkt(ifp, kpkt, false, &pkt_drop);
		}
		netif_transmit(ifp, NETIF_XMIT_FLAG_HOST);
		if (pkt_drop) {
			STATS_INC(nifs, NETIF_STATS_TX_DROP_ENQ_AQM);
		}
	} else {
		error = ENOBUFS;
		pkt_drop = TRUE;
	}
done:
	/* always free mbuf (even in the success case) */
	m_freem(m);
	if (__improbable(pkt_drop)) {
		STATS_INC(nifs, NETIF_STATS_DROP);
	}

	KDBG((SK_KTRACE_NETIF_HOST_ENQUEUE | DBG_FUNC_END), SK_KVA(kring),
	    error);

	return error;
}

static inline int
get_l2_hlen(struct mbuf *m, uint8_t *l2len)
{
	char *pkt_hdr;
	struct mbuf *m0;
	uint64_t len = 0;

	pkt_hdr = m->m_pkthdr.pkt_hdr;
	for (m0 = m; m0 != NULL; m0 = m0->m_next) {
		if (pkt_hdr >= m0->m_data && pkt_hdr < m0->m_data + m0->m_len) {
			break;
		}
		len += m0->m_len;
	}
	if (m0 == NULL) {
		DTRACE_SKYWALK2(bad__pkthdr, struct mbuf *, m, char *, pkt_hdr);
		return EINVAL;
	}
	len += (pkt_hdr - m0->m_data);
	if (len > UINT8_MAX) {
		DTRACE_SKYWALK2(bad__l2len, struct mbuf *, m, uint64_t, len);
		return EINVAL;
	}
	*l2len = (uint8_t)len;
	return 0;
}

#if SK_LOG
/* Hoisted out of line to reduce kernel stack footprint */
SK_LOG_ATTRIBUTE
static void
nx_netif_mbuf_to_kpkt_log(struct __kern_packet *kpkt, uint32_t len,
    uint32_t poff)
{
	uint8_t *baddr;
	MD_BUFLET_ADDR_ABS(kpkt, baddr);
	SK_DF(SK_VERB_HOST | SK_VERB_TX, "mlen %u dplen %u"
	    " hr %u l2 %u poff %u", len, kpkt->pkt_length,
	    kpkt->pkt_headroom, kpkt->pkt_l2_len, poff);
	SK_DF(SK_VERB_HOST | SK_VERB_TX | SK_VERB_DUMP, "%s",
	    sk_dump("buf", baddr, kpkt->pkt_length, 128, NULL, 0));
}
#endif /* SK_LOG */

static inline struct __kern_packet *
nx_netif_mbuf_to_kpkt(struct nexus_adapter *na, struct mbuf *m)
{
	struct netif_stats *nifs = &NX_NETIF_PRIVATE(na->na_nx)->nif_stats;
	struct nexus_netif_adapter *nifna = NIFNA(na);
	struct nx_netif *nif = nifna->nifna_netif;
	uint16_t poff = na->na_ifp->if_tx_headroom;
	uint32_t len;
	struct kern_pbufpool *pp;
	struct __kern_packet *kpkt;
	kern_packet_t ph;
	boolean_t copysum;
	uint8_t l2hlen;
	int err;

	pp = skmem_arena_nexus(na->na_arena)->arn_tx_pp;
	ASSERT((pp != NULL) && (pp->pp_md_type == NEXUS_META_TYPE_PACKET) &&
	    (pp->pp_md_subtype == NEXUS_META_SUBTYPE_RAW));
	ASSERT(!PP_HAS_TRUNCATED_BUF(pp));

	len = m_pktlen(m);
	VERIFY((poff + len) <= (PP_BUF_SIZE_DEF(pp) * pp->pp_max_frags));

	/* alloc packet */
	ph = pp_alloc_packet_by_size(pp, poff + len, SKMEM_NOSLEEP);
	if (__improbable(ph == 0)) {
		STATS_INC(nifs, NETIF_STATS_DROP_NOMEM_PKT);
		SK_DF(SK_VERB_MEM,
		    "%s(%d) pp \"%s\" (0x%llx) has no more "
		    "packet for %s", sk_proc_name_address(current_proc()),
		    sk_proc_pid(current_proc()), pp->pp_name, SK_KVA(pp),
		    if_name(na->na_ifp));
		return NULL;
	}

	copysum = ((m->m_pkthdr.csum_flags & (CSUM_DATA_VALID |
	    CSUM_PARTIAL)) == (CSUM_DATA_VALID | CSUM_PARTIAL));

	STATS_INC(nifs, NETIF_STATS_TX_COPY_MBUF);
	if (copysum) {
		STATS_INC(nifs, NETIF_STATS_TX_COPY_SUM);
	}

	kpkt = SK_PTR_ADDR_KPKT(ph);
	kpkt->pkt_link_flags = 0;
	nif->nif_pkt_copy_from_mbuf(NR_TX, ph, poff, m, 0, len,
	    copysum, m->m_pkthdr.csum_tx_start);

	kpkt->pkt_headroom = (uint8_t)poff;
	if ((err = get_l2_hlen(m, &l2hlen)) == 0) {
		kpkt->pkt_l2_len = l2hlen;
	} else {
		kpkt->pkt_l2_len = 0;
	}
	/* finalize the packet */
	METADATA_ADJUST_LEN(kpkt, 0, poff);
	err = __packet_finalize(ph);
	VERIFY(err == 0);

#if SK_LOG
	if (__improbable((sk_verbose & SK_VERB_HOST) != 0) && kpkt != NULL) {
		nx_netif_mbuf_to_kpkt_log(kpkt, len, poff);
	}
#endif /* SK_LOG */

	return kpkt;
}
