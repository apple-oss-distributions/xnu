/*
 * Copyright (c) 2016-2020 Apple Inc. All rights reserved.
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
#include <skywalk/nexus/flowswitch/nx_flowswitch.h>
#include <skywalk/nexus/flowswitch/fsw_var.h>
#include <netinet/in_arp.h>
#include <netinet/ip6.h>
#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>
#include <net/ethernet.h>
#include <net/route.h>
#include <sys/eventhandler.h>

#define FSW_ETHER_LEN_PADDED     16
#define FSW_ETHER_PADDING        (FSW_ETHER_LEN_PADDED - ETHER_HDR_LEN)
#define FSW_ETHER_FRAME_HEADROOM FSW_ETHER_LEN_PADDED

static void fsw_ethernet_ctor(struct nx_flowswitch *, struct flow_route *);
static int fsw_ethernet_resolve(struct nx_flowswitch *, struct flow_route *,
    struct __kern_packet *);
static void fsw_ethernet_frame(struct nx_flowswitch *, struct flow_route *,
    struct __kern_packet *);
static sa_family_t fsw_ethernet_demux(struct nx_flowswitch *,
    struct __kern_packet *);

extern struct rtstat rtstat;

int
fsw_ethernet_setup(struct nx_flowswitch *fsw, struct ifnet *ifp)
{
	struct ifaddr *lladdr = ifp->if_lladdr;

	if (SDL(lladdr->ifa_addr)->sdl_alen != ETHER_ADDR_LEN ||
	    SDL(lladdr->ifa_addr)->sdl_type != IFT_ETHER) {
		return ENOTSUP;
	}

	ifnet_lladdr_copy_bytes(ifp, fsw->fsw_ether_shost, ETHER_ADDR_LEN);
	fsw->fsw_ctor = fsw_ethernet_ctor;
	fsw->fsw_resolve = fsw_ethernet_resolve;
	fsw->fsw_frame = fsw_ethernet_frame;
	fsw->fsw_frame_headroom = FSW_ETHER_FRAME_HEADROOM;
	fsw->fsw_demux = fsw_ethernet_demux;

	return 0;
}

static void
fsw_ethernet_ctor(struct nx_flowswitch *fsw, struct flow_route *fr)
{
	ASSERT(fr->fr_af == AF_INET || fr->fr_af == AF_INET6);

	fr->fr_llhdr.flh_gencnt = fsw->fsw_src_lla_gencnt;
	bcopy(fsw->fsw_ether_shost, fr->fr_eth.ether_shost, ETHER_ADDR_LEN);
	fr->fr_eth.ether_type = ((fr->fr_af == AF_INET) ?
	    htons(ETHERTYPE_IP) : htons(ETHERTYPE_IPV6));

	/* const override */
	_CASSERT(sizeof(fr->fr_llhdr.flh_off) == sizeof(uint8_t));
	_CASSERT(sizeof(fr->fr_llhdr.flh_len) == sizeof(uint8_t));
	*(uint8_t *)(uintptr_t)&fr->fr_llhdr.flh_off = 2;
	*(uint8_t *)(uintptr_t)&fr->fr_llhdr.flh_len = ETHER_HDR_LEN;

	SK_DF(SK_VERB_FLOW_ROUTE,
	    "fr 0x%llx eth_type 0x%x eth_src %x:%x:%x:%x:%x:%x",
	    SK_KVA(fr), ntohs(fr->fr_eth.ether_type),
	    fr->fr_eth.ether_shost[0], fr->fr_eth.ether_shost[1],
	    fr->fr_eth.ether_shost[2], fr->fr_eth.ether_shost[3],
	    fr->fr_eth.ether_shost[4], fr->fr_eth.ether_shost[5]);
}

static int
fsw_ethernet_resolve(struct nx_flowswitch *fsw, struct flow_route *fr,
    struct __kern_packet *pkt)
{
#if SK_LOG
	char dst_s[MAX_IPv6_STR_LEN];
#endif /* SK_LOG */
	struct ifnet *ifp = fsw->fsw_ifp;
	struct rtentry *tgt_rt = NULL;
	struct sockaddr *tgt_sa = NULL;
	struct mbuf *m = NULL;
	boolean_t reattach_mbuf = FALSE;
	boolean_t probing;
	int err = 0;

	ASSERT(fr != NULL);
	ASSERT(ifp != NULL);

	FR_LOCK(fr);
	/*
	 * If the destination is on-link, we use the final destination
	 * address as target.  If it's off-link, we use the gateway
	 * address instead.  Point tgt_rt to the the destination or
	 * gateway route accordingly.
	 */
	if (fr->fr_flags & FLOWRTF_ONLINK) {
		tgt_sa = SA(&fr->fr_faddr);
		tgt_rt = fr->fr_rt_dst;
	} else if (fr->fr_flags & FLOWRTF_GATEWAY) {
		tgt_sa = SA(&fr->fr_gaddr);
		tgt_rt = fr->fr_rt_gw;
	}

	/*
	 * Perform another routing table lookup if necessary.
	 */
	if (tgt_rt == NULL || !(tgt_rt->rt_flags & RTF_UP) ||
	    fr->fr_want_configure) {
		if (fr->fr_want_configure == 0) {
			os_atomic_inc(&fr->fr_want_configure, relaxed);
		}
		err = flow_route_configure(fr, ifp, NULL);
		if (err != 0) {
			SK_ERR("failed to configure route to %s on %s (err %d)",
			    sk_sa_ntop(SA(&fr->fr_faddr), dst_s,
			    sizeof(dst_s)), ifp->if_xname, err);
			goto done;
		}

		/* refresh pointers */
		if (fr->fr_flags & FLOWRTF_ONLINK) {
			tgt_sa = SA(&fr->fr_faddr);
			tgt_rt = fr->fr_rt_dst;
		} else if (fr->fr_flags & FLOWRTF_GATEWAY) {
			tgt_sa = SA(&fr->fr_gaddr);
			tgt_rt = fr->fr_rt_gw;
		}
	}

	if (__improbable(!(fr->fr_flags & (FLOWRTF_ONLINK | FLOWRTF_GATEWAY)))) {
		err = EHOSTUNREACH;
		SK_ERR("invalid route for %s on %s (err %d)",
		    sk_sa_ntop(SA(&fr->fr_faddr), dst_s,
		    sizeof(dst_s)), ifp->if_xname, err);
		goto done;
	}

	ASSERT(tgt_sa != NULL);
	ASSERT(tgt_rt != NULL);

	/*
	 * Attempt to convert kpkt to mbuf before acquiring the
	 * rt lock so that the lock won't be held if we need to do
	 * blocked a mbuf allocation.
	 */
	if (!(fr->fr_flags & FLOWRTF_HAS_LLINFO)) {
		/*
		 * We need to resolve; if caller passes in a kpkt,
		 * convert the kpkt within to mbuf.  Caller is then
		 * reponsible for freeing kpkt.  In future, we could
		 * optimize this by having the ARP/ND lookup routines
		 * understand kpkt and perform the conversion only
		 * when it is needed.
		 */
		if (__probable(pkt != NULL)) {
			if (pkt->pkt_pflags & PKT_F_MBUF_DATA) {
				reattach_mbuf = TRUE;
				m = pkt->pkt_mbuf;
				KPKT_CLEAR_MBUF_DATA(pkt);
			} else {
				m = fsw_classq_kpkt_to_mbuf(fsw, pkt);
			}
			if (m == NULL) {
				/* not a fatal error; move on */
				SK_ERR("failed to allocate mbuf while "
				    "resolving %s on %s",
				    sk_sa_ntop(SA(&fr->fr_faddr), dst_s,
				    sizeof(dst_s)), ifp->if_xname);
			}
		} else {
			m = NULL;
		}
	}

	RT_LOCK(tgt_rt);

	if (__improbable(!IS_DIRECT_HOSTROUTE(tgt_rt) ||
	    tgt_rt->rt_gateway->sa_family != AF_LINK ||
	    SDL(tgt_rt->rt_gateway)->sdl_type != IFT_ETHER)) {
		rtstat.rts_badrtgwroute++;
		err = ENETUNREACH;
		RT_UNLOCK(tgt_rt);
		SK_ERR("bad gateway route %s on %s (err %d)",
		    sk_sa_ntop(tgt_sa, dst_s, sizeof(dst_s)),
		    ifp->if_xname, err);
		goto done;
	}

	/*
	 * If already resolved, grab the link-layer address and mark the
	 * flow route accordingly.  Given that we will use the cached
	 * link-layer info, there's no need to convert and enqueue the
	 * packet to ARP/ND (i.e. no need to return EJUSTRETURN).
	 */
	if (__probable((fr->fr_flags & FLOWRTF_HAS_LLINFO) &&
	    SDL(tgt_rt->rt_gateway)->sdl_alen == ETHER_ADDR_LEN)) {
		VERIFY(m == NULL);
		FLOWRT_UPD_ETH_DST(fr, LLADDR(SDL(tgt_rt->rt_gateway)));
		os_atomic_or(&fr->fr_flags, (FLOWRTF_RESOLVED | FLOWRTF_HAS_LLINFO), relaxed);
		/* if we're not probing, then we're done */
		if (!(probing = (fr->fr_want_probe != 0))) {
			VERIFY(err == 0);
			RT_UNLOCK(tgt_rt);
			goto done;
		}
		os_atomic_store(&fr->fr_want_probe, 0, release);
	} else {
		probing = FALSE;
		os_atomic_andnot(&fr->fr_flags, (FLOWRTF_RESOLVED | FLOWRTF_HAS_LLINFO), relaxed);
	}

	SK_DF(SK_VERB_FLOW_ROUTE, "%s %s on %s", (probing ?
	    "probing" : "resolving"), sk_sa_ntop(tgt_sa, dst_s,
	    sizeof(dst_s)), ifp->if_xname);

	/*
	 * Trigger ARP/NDP resolution or probing.
	 */
	switch (tgt_sa->sa_family) {
	case AF_INET: {
		struct sockaddr_dl sdl;

		RT_UNLOCK(tgt_rt);
		/*
		 * Note we pass NULL as "hint" parameter, as tgt_sa
		 * is already refererring to the target address.
		 */
		bzero(&sdl, sizeof(sdl));
		err = arp_lookup_ip(ifp, SIN(tgt_sa), &sdl, sizeof(sdl),
		    NULL, m);

		/*
		 * If we're resolving (not probing), and it's now resolved,
		 * grab the link-layer address and update the flow route.
		 * If we get EJUSTRETURN, the mbuf (if any) would have
		 * been added to the hold queue.  Any other return values
		 * including 0 means that we need to free it.
		 *
		 * If we're probing, we won't have any mbuf to deal with,
		 * and since we already have the cached llinfo we'll just
		 * return success even if we get EJUSTRETURN.
		 */
		if (!probing) {
			if (err == 0 && sdl.sdl_alen == ETHER_ADDR_LEN) {
				SK_DF(SK_VERB_FLOW_ROUTE,
				    "fast-resolve %s on %s",
				    sk_sa_ntop(SA(&fr->fr_faddr), dst_s,
				    sizeof(dst_s)), ifp->if_xname);
				FLOWRT_UPD_ETH_DST(fr, LLADDR(&sdl));
				os_atomic_or(&fr->fr_flags, (FLOWRTF_RESOLVED | FLOWRTF_HAS_LLINFO), relaxed);
			}
			if (err == EJUSTRETURN && m != NULL) {
				SK_DF(SK_VERB_FLOW_ROUTE, "packet queued "
				    "while resolving %s on %s",
				    sk_sa_ntop(SA(&fr->fr_faddr), dst_s,
				    sizeof(dst_s)), ifp->if_xname);
				m = NULL;
			}
		} else {
			VERIFY(m == NULL);
			if (err == EJUSTRETURN) {
				err = 0;
			}
		}
		break;
	}

	case AF_INET6: {
		struct llinfo_nd6 *ln = tgt_rt->rt_llinfo;

		/*
		 * Check if the route is down.  RTF_LLINFO is set during
		 * RTM_{ADD,RESOLVE}, and is never cleared until the route
		 * is deleted from the routing table.
		 */
		if ((tgt_rt->rt_flags & (RTF_UP | RTF_LLINFO)) !=
		    (RTF_UP | RTF_LLINFO) || ln == NULL) {
			err = EHOSTUNREACH;
			SK_ERR("route unavailable for %s on %s (err %d)",
			    sk_sa_ntop(SA(&fr->fr_faddr), dst_s,
			    sizeof(dst_s)), ifp->if_xname, err);
			RT_UNLOCK(tgt_rt);
			break;
		}

		/*
		 * If we're probing and IPv6 ND cache entry is STALE,
		 * use it anyway but also mark it for delayed probe
		 * and update the expiry.
		 */
		if (probing) {
			VERIFY(m == NULL);
			VERIFY(ln->ln_state > ND6_LLINFO_INCOMPLETE);
			if (ln->ln_state == ND6_LLINFO_STALE) {
				ln->ln_asked = 0;
				ND6_CACHE_STATE_TRANSITION(ln,
				    ND6_LLINFO_DELAY);
				ln_setexpire(ln, net_uptime() + nd6_delay);
				RT_UNLOCK(tgt_rt);

				lck_mtx_lock(rnh_lock);
				nd6_sched_timeout(NULL, NULL);
				lck_mtx_unlock(rnh_lock);

				SK_DF(SK_VERB_FLOW_ROUTE,
				    "NUD probe scheduled for %s on %s",
				    sk_sa_ntop(tgt_sa, dst_s,
				    sizeof(dst_s)), ifp->if_xname);
			} else {
				RT_UNLOCK(tgt_rt);
			}
			VERIFY(err == 0);
			break;
		}

		/*
		 * If this is a permanent ND entry, we're done.
		 */
		if (ln->ln_expire == 0 &&
		    ln->ln_state == ND6_LLINFO_REACHABLE) {
			if (SDL(tgt_rt->rt_gateway)->sdl_alen !=
			    ETHER_ADDR_LEN) {
				err = EHOSTUNREACH;
				SK_ERR("invalid permanent route %s on %s"
				    "ln 0x%llx (err %d)",
				    sk_sa_ntop(rt_key(tgt_rt), dst_s,
				    sizeof(dst_s)), ifp->if_xname,
				    SK_KVA(ln), err);
			} else {
				SK_DF(SK_VERB_FLOW_ROUTE, "fast-resolve "
				    "permanent route %s on %s",
				    sk_sa_ntop(SA(&fr->fr_faddr), dst_s,
				    sizeof(dst_s)), ifp->if_xname);
				/* copy permanent address into the flow route */
				FLOWRT_UPD_ETH_DST(fr,
				    LLADDR(SDL(tgt_rt->rt_gateway)));
				os_atomic_or(&fr->fr_flags, (FLOWRTF_RESOLVED | FLOWRTF_HAS_LLINFO), relaxed);
				VERIFY(err == 0);
			}
			RT_UNLOCK(tgt_rt);
			break;
		}

		if (ln->ln_state == ND6_LLINFO_NOSTATE) {
			ND6_CACHE_STATE_TRANSITION(ln, ND6_LLINFO_INCOMPLETE);
		}

		if (ln->ln_state == ND6_LLINFO_INCOMPLETE && (!ln->ln_asked ||
		    !(fr->fr_flags & FLOWRTF_HAS_LLINFO))) {
			struct nd_ifinfo *ndi = ND_IFINFO(tgt_rt->rt_ifp);
			/*
			 * There is a neighbor cache entry, but no Ethernet
			 * address response yet.  Replace the held mbuf
			 * (if any) with this the one we have (if any),
			 * else leave it alone.
			 *
			 * This code conforms to the rate-limiting rule
			 * described in Section 7.2.2 of RFC 4861, because
			 * the timer is set correctly after sending an
			 * NS below.
			 */
			if (m != NULL) {
				if (ln->ln_hold != NULL) {
					m_freem_list(ln->ln_hold);
				}
				ln->ln_hold = m;
				m = NULL;

				SK_DF(SK_VERB_FLOW_ROUTE,
				    "packet queued while resolving %s on %s",
				    sk_sa_ntop(SA(&fr->fr_faddr), dst_s,
				    sizeof(dst_s)), ifp->if_xname);
			}
			VERIFY(ndi != NULL && ndi->initialized);
			ln->ln_asked++;
			ln_setexpire(ln, net_uptime() + ndi->retrans / 1000);
			RT_UNLOCK(tgt_rt);

			SK_DF(SK_VERB_FLOW_ROUTE, "soliciting for %s on %s"
			    "ln 0x%llx state %u", sk_sa_ntop(rt_key(tgt_rt),
			    dst_s, sizeof(dst_s)), ifp->if_xname, SK_KVA(ln),
			    ln->ln_state);

			/* XXX Refactor this to use same src ip */
			nd6_ns_output(tgt_rt->rt_ifp, NULL,
			    &SIN6(rt_key(tgt_rt))->sin6_addr, NULL, NULL);

			lck_mtx_lock(rnh_lock);
			nd6_sched_timeout(NULL, NULL);
			lck_mtx_unlock(rnh_lock);
			err = EJUSTRETURN;
		} else {
			SK_DF(SK_VERB_FLOW_ROUTE, "fast-resolve %s on %s",
			    sk_sa_ntop(SA(&fr->fr_faddr), dst_s,
			    sizeof(dst_s)), ifp->if_xname);
			/*
			 * The neighbor cache entry has been resolved;
			 * copy the address into the flow route.
			 */
			FLOWRT_UPD_ETH_DST(fr, LLADDR(SDL(tgt_rt->rt_gateway)));
			os_atomic_or(&fr->fr_flags, (FLOWRTF_RESOLVED | FLOWRTF_HAS_LLINFO), relaxed);
			RT_UNLOCK(tgt_rt);
			VERIFY(err == 0);
		}
		/*
		 * XXX Need to optimize for the NDP garbage
		 * collection.  It would be even better to unify
		 * BSD/SK NDP management through the completion
		 * of L2/L3 split.
		 */
		break;
	}

	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}
	RT_LOCK_ASSERT_NOTHELD(tgt_rt);

done:
	if (m != NULL) {
		if (reattach_mbuf) {
			pkt->pkt_mbuf = m;
			pkt->pkt_pflags |= PKT_F_MBUF_DATA;
		} else {
			m_freem_list(m);
		}
		m = NULL;
	}

	if (__improbable(err != 0 && err != EJUSTRETURN)) {
		SK_ERR("route to %s on %s can't be resolved (err %d)",
		    sk_sa_ntop(SA(&fr->fr_faddr), dst_s, sizeof(dst_s)),
		    ifp->if_xname, err);
		/* keep FLOWRTF_HAS_LLINFO as llinfo is still useful */
		os_atomic_andnot(&fr->fr_flags, FLOWRTF_RESOLVED, relaxed);
		flow_route_cleanup(fr);
	}

	FR_UNLOCK(fr);

	return err;
}

static void
fsw_ethernet_frame(struct nx_flowswitch *fsw, struct flow_route *fr,
    struct __kern_packet *pkt)
{
	/* in the event the source MAC address changed, update our copy */
	if (__improbable(fr->fr_llhdr.flh_gencnt != fsw->fsw_src_lla_gencnt)) {
		uint8_t old_shost[ETHER_ADDR_LEN];

		bcopy(&fr->fr_eth.ether_shost, &old_shost, ETHER_ADDR_LEN);
		fsw_ethernet_ctor(fsw, fr);

		SK_ERR("fr 0x%llx source MAC address updated on %s, "
		    "was %x:%x:%x:%x:%x:%x now %x:%x:%x:%x:%x:%x",
		    SK_KVA(fr), fsw->fsw_ifp,
		    old_shost[0], old_shost[1],
		    old_shost[2], old_shost[3],
		    old_shost[4], old_shost[5],
		    fr->fr_eth.ether_shost[0], fr->fr_eth.ether_shost[1],
		    fr->fr_eth.ether_shost[2], fr->fr_eth.ether_shost[3],
		    fr->fr_eth.ether_shost[4], fr->fr_eth.ether_shost[5]);
	}

	_CASSERT(sizeof(fr->fr_eth_padded) == FSW_ETHER_LEN_PADDED);

	if ((fr->fr_flags & FLOWRTF_DST_LL_MCAST) != 0) {
		pkt->pkt_link_flags |= PKT_LINKF_MCAST;
	} else if ((fr->fr_flags & FLOWRTF_DST_LL_BCAST) != 0) {
		pkt->pkt_link_flags |= PKT_LINKF_BCAST;
	}

	ASSERT(pkt->pkt_headroom >= FSW_ETHER_LEN_PADDED);

	char *pkt_buf;
	MD_BUFLET_ADDR_ABS(pkt, pkt_buf);
	sk_copy64_16((uint64_t *)(void *)&fr->fr_eth_padded,
	    (uint64_t *)(void *)(pkt_buf + pkt->pkt_headroom - FSW_ETHER_LEN_PADDED));

	pkt->pkt_headroom -= ETHER_HDR_LEN;
	pkt->pkt_l2_len = ETHER_HDR_LEN;

	if ((pkt->pkt_pflags & PKT_F_MBUF_DATA) != 0) {
		/* frame and fix up mbuf */
		struct mbuf *m = pkt->pkt_mbuf;
		sk_copy64_16((uint64_t *)(void *)&fr->fr_eth_padded,
		    (uint64_t *)(void *)(m->m_data - FSW_ETHER_LEN_PADDED));
		ASSERT((uintptr_t)m->m_data ==
		    (uintptr_t)mbuf_datastart(m) + FSW_ETHER_FRAME_HEADROOM);
		m->m_data -= ETHER_HDR_LEN;
		m->m_len += ETHER_HDR_LEN;
		m_pktlen(m) += ETHER_HDR_LEN;
		ASSERT(m->m_len == m_pktlen(m));
		pkt->pkt_length = m_pktlen(m);
	} else {
		METADATA_ADJUST_LEN(pkt, ETHER_HDR_LEN, pkt->pkt_headroom);
	}
}

static sa_family_t
fsw_ethernet_demux(struct nx_flowswitch *fsw, struct __kern_packet *pkt)
{
#pragma unused(fsw)
	const struct ether_header *eh;
	sa_family_t af = AF_UNSPEC;
	uint32_t bdlen, bdlim, bdoff;
	uint8_t *baddr;

	MD_BUFLET_ADDR_ABS_DLEN(pkt, baddr, bdlen, bdlim, bdoff);
	baddr += pkt->pkt_headroom;
	eh = (struct ether_header *)(void *)baddr;

	if (__improbable(sizeof(*eh) > pkt->pkt_length)) {
		STATS_INC(&fsw->fsw_stats, FSW_STATS_RX_DEMUX_ERR);
		SK_ERR("unrecognized pkt, len %u", pkt->pkt_length);
		return AF_UNSPEC;
	}

	if (__improbable(pkt->pkt_headroom + sizeof(*eh) > bdlim)) {
		SK_ERR("ethernet header overrun 1st buflet");
		STATS_INC(&fsw->fsw_stats, FSW_STATS_RX_DEMUX_ERR);
		return AF_UNSPEC;
	}

	if (__improbable((pkt->pkt_link_flags & PKT_LINKF_ETHFCS) != 0)) {
		pkt->pkt_length -= ETHER_CRC_LEN;
		pkt->pkt_link_flags &= ~PKT_LINKF_ETHFCS;
		if (pkt->pkt_pflags & PKT_F_MBUF_DATA) {
			ASSERT((pkt->pkt_mbuf->m_flags & M_HASFCS) != 0);
			m_adj(pkt->pkt_mbuf, -ETHER_CRC_LEN);
			pkt->pkt_mbuf->m_flags &= ~M_HASFCS;
		}
	}
	pkt->pkt_l2_len = ETHER_HDR_LEN;
	if ((eh->ether_dhost[0] & 1) == 0) {
		/*
		 * When the driver is put into promiscuous mode we may receive
		 * unicast frames that are not intended for our interfaces.
		 * They are marked here as being promiscuous so the caller may
		 * dispose of them after passing the packets to any interface
		 * filters.
		 */
		if (_ether_cmp(eh->ether_dhost, IF_LLADDR(fsw->fsw_ifp))) {
			pkt->pkt_pflags |= PKT_F_PROMISC;
			STATS_INC(&fsw->fsw_stats, FSW_STATS_RX_DEMUX_PROMISC);
			return AF_UNSPEC;
		}
	}
	uint16_t ether_type = ntohs(eh->ether_type);
	switch (ether_type) {
	case ETHERTYPE_IP:
		af = AF_INET;
		break;
	case ETHERTYPE_IPV6:
		af = AF_INET6;
		break;
	default:
		STATS_INC(&fsw->fsw_stats, FSW_STATS_RX_DEMUX_UNSPEC);
		break;
	}

	return af;
}
