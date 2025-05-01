/*
 * Copyright (c) 1999-2024 Apple Inc. All rights reserved.
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

#include <net/if_var.h>
#include <net/dlil_var_private.h>
#include <net/dlil.h>
#include <net/dlil_sysctl.h>


static void dlil_count_chain_len(mbuf_t m, struct chain_len_stats *cls);

static int dlil_interface_filters_output(struct ifnet *ifp, struct mbuf **m_p,
    protocol_family_t protocol_family);

static void dlil_output_cksum_dbg(struct ifnet *ifp, struct mbuf *m, uint32_t hoff,
    protocol_family_t pf);

#if CONFIG_DTRACE
static void dlil_output_dtrace(ifnet_t ifp, protocol_family_t proto_family, mbuf_t  m);
#endif /* CONFIG_DTRACE */

/*
 * dlil_output
 *
 * Caller should have a lock on the protocol domain if the protocol
 * doesn't support finer grained locking. In most cases, the lock
 * will be held from the socket layer and won't be released until
 * we return back to the socket layer.
 *
 * This does mean that we must take a protocol lock before we take
 * an interface lock if we're going to take both. This makes sense
 * because a protocol is likely to interact with an ifp while it
 * is under the protocol lock.
 *
 * An advisory code will be returned if adv is not null. This
 * can be used to provide feedback about interface queues to the
 * application.
 */
errno_t
dlil_output(ifnet_t ifp, protocol_family_t proto_family, mbuf_t packetlist,
    void *route, const struct sockaddr *dest, int flags, struct flowadv *adv)
{
	char *frame_type = NULL;
	char *dst_linkaddr = NULL;
	int retval = 0;
	char frame_type_buffer[IFNET_MAX_FRAME_TYPE_BUFFER_SIZE];
	char dst_linkaddr_buffer[IFNET_MAX_LINKADDR_BUFFER_SIZE];
	if_proto_ref_t proto = NULL;
	mbuf_ref_t m = NULL;
	mbuf_ref_t send_head = NULL;
	mbuf_ref_ptr_t send_tail = &send_head;
	int iorefcnt = 0;
	u_int32_t pre = 0, post = 0;
	u_int32_t fpkts = 0, fbytes = 0;
	int32_t flen = 0;
	struct timespec now;
	u_int64_t now_nsec;
	boolean_t did_clat46 = FALSE;
	protocol_family_t old_proto_family = proto_family;
	struct sockaddr_in6 dest6;
	rtentry_ref_t rt = NULL;
	u_int16_t m_loop_set = 0;
	bool raw = (flags & DLIL_OUTPUT_FLAGS_RAW) != 0;

	KERNEL_DEBUG(DBG_FNC_DLIL_OUTPUT | DBG_FUNC_START, 0, 0, 0, 0, 0);

	/*
	 * Get an io refcnt if the interface is attached to prevent ifnet_detach
	 * from happening while this operation is in progress
	 */
	if (!ifnet_datamov_begin(ifp)) {
		retval = ENXIO;
		goto cleanup;
	}
	iorefcnt = 1;

	VERIFY(ifp->if_output_dlil != NULL);

	/* update the driver's multicast filter, if needed */
	if (ifp->if_updatemcasts > 0) {
		if_mcasts_update_async(ifp);
		ifp->if_updatemcasts = 0;
	}

	frame_type = frame_type_buffer;
	dst_linkaddr = dst_linkaddr_buffer;

	if (flags == DLIL_OUTPUT_FLAGS_NONE) {
		ifnet_lock_shared(ifp);
		/* callee holds a proto refcnt upon success */
		proto = find_attached_proto(ifp, proto_family);
		if (proto == NULL) {
			ifnet_lock_done(ifp);
			retval = ENXIO;
			goto cleanup;
		}
		ifnet_lock_done(ifp);
	}

preout_again:
	if (packetlist == NULL) {
		goto cleanup;
	}

	m = packetlist;
	packetlist = packetlist->m_nextpkt;
	m->m_nextpkt = NULL;

	m_add_crumb(m, PKT_CRUMB_DLIL_OUTPUT);

	/*
	 * Perform address family translation for the first
	 * packet outside the loop in order to perform address
	 * lookup for the translated proto family.
	 */
	if (proto_family == PF_INET && IS_INTF_CLAT46(ifp) &&
	    (ifp->if_type == IFT_CELLULAR ||
	    dlil_is_clat_needed(proto_family, m))) {
		retval = dlil_clat46(ifp, &proto_family, &m);
		/*
		 * Go to the next packet if translation fails
		 */
		if (retval != 0) {
			m_drop(m, DROPTAP_FLAG_DIR_OUT, DROP_REASON_DLIL_CLAT64, NULL, 0);
			m = NULL;
			ip6stat.ip6s_clat464_out_drop++;
			/* Make sure that the proto family is PF_INET */
			ASSERT(proto_family == PF_INET);
			goto preout_again;
		}
		/*
		 * Free the old one and make it point to the IPv6 proto structure.
		 *
		 * Change proto for the first time we have successfully
		 * performed address family translation.
		 */
		if (!did_clat46 && proto_family == PF_INET6) {
			did_clat46 = TRUE;

			if (proto != NULL) {
				if_proto_free(proto);
			}
			ifnet_lock_shared(ifp);
			/* callee holds a proto refcnt upon success */
			proto = find_attached_proto(ifp, proto_family);
			if (proto == NULL) {
				ifnet_lock_done(ifp);
				retval = ENXIO;
				m_drop(m, DROPTAP_FLAG_DIR_OUT, DROP_REASON_DLIL_CLAT64, NULL, 0);
				m = NULL;
				goto cleanup;
			}
			ifnet_lock_done(ifp);
			if (ifp->if_type == IFT_ETHER) {
				/* Update the dest to translated v6 address */
				dest6.sin6_len = sizeof(struct sockaddr_in6);
				dest6.sin6_family = AF_INET6;
				dest6.sin6_addr = (mtod(m, struct ip6_hdr *))->ip6_dst;
				dest = SA(&dest6);

				/*
				 * Lookup route to the translated destination
				 * Free this route ref during cleanup
				 */
				rt = rtalloc1_scoped(SA(&dest6),
				    0, 0, ifp->if_index);

				route = rt;
			}
		}
	}

	/*
	 * This path gets packet chain going to the same destination.
	 * The pre output routine is used to either trigger resolution of
	 * the next hop or retrieve the next hop's link layer addressing.
	 * For ex: ether_inet(6)_pre_output routine.
	 *
	 * If the routine returns EJUSTRETURN, it implies that packet has
	 * been queued, and therefore we have to call preout_again for the
	 * following packet in the chain.
	 *
	 * For errors other than EJUSTRETURN, the current packet is freed
	 * and the rest of the chain (pointed by packetlist is freed as
	 * part of clean up.
	 *
	 * Else if there is no error the retrieved information is used for
	 * all the packets in the chain.
	 */
	if (flags == DLIL_OUTPUT_FLAGS_NONE) {
		proto_media_preout preoutp = (proto->proto_kpi == kProtoKPI_v1 ?
		    proto->kpi.v1.pre_output : proto->kpi.v2.pre_output);
		retval = 0;
		if (preoutp != NULL) {
			retval = preoutp(ifp, proto_family, &m, dest, route,
			    frame_type, dst_linkaddr);

			if (retval != 0) {
				if (retval == EJUSTRETURN) {
					goto preout_again;
				}
				m_drop(m, DROPTAP_FLAG_DIR_OUT, DROP_REASON_DLIL_PRE_OUTPUT, NULL, 0);
				m = NULL;
				goto cleanup;
			}
		}
	}

	nanouptime(&now);
	net_timernsec(&now, &now_nsec);

	do {
		m_add_hdr_crumb_interface_output(m, ifp->if_index, false);
		/*
		 * pkt_hdr is set here to point to m_data prior to
		 * calling into the framer. This value of pkt_hdr is
		 * used by the netif gso logic to retrieve the ip header
		 * for the TCP packets, offloaded for TSO processing.
		 */
		if (raw && (ifp->if_family == IFNET_FAMILY_ETHERNET)) {
			uint8_t vlan_encap_len = 0;

			if ((m->m_pkthdr.csum_flags & CSUM_VLAN_ENCAP_PRESENT) != 0) {
				vlan_encap_len = ETHER_VLAN_ENCAP_LEN;
			}
			m->m_pkthdr.pkt_hdr = mtod(m, char *) + ETHER_HDR_LEN + vlan_encap_len;
		} else {
			m->m_pkthdr.pkt_hdr = mtod(m, void *);
		}

		/*
		 * Perform address family translation if needed.
		 * For now we only support stateless 4 to 6 translation
		 * on the out path.
		 *
		 * The routine below translates IP header, updates protocol
		 * checksum and also translates ICMP.
		 *
		 * We skip the first packet as it is already translated and
		 * the proto family is set to PF_INET6.
		 */
		if (proto_family == PF_INET && IS_INTF_CLAT46(ifp) &&
		    (ifp->if_type == IFT_CELLULAR ||
		    dlil_is_clat_needed(proto_family, m))) {
			retval = dlil_clat46(ifp, &proto_family, &m);
			/* Goto the next packet if the translation fails */
			if (retval != 0) {
				m_drop(m, DROPTAP_FLAG_DIR_OUT, DROP_REASON_DLIL_CLAT64, NULL, 0);
				m = NULL;
				ip6stat.ip6s_clat464_out_drop++;
				goto next;
			}
		}

#if CONFIG_DTRACE
		if (flags == DLIL_OUTPUT_FLAGS_NONE) {
			dlil_output_dtrace(ifp, proto_family, m);
		}
#endif /* CONFIG_DTRACE */

		if (flags == DLIL_OUTPUT_FLAGS_NONE && ifp->if_framer != NULL) {
			int rcvif_set = 0;

			/*
			 * If this is a broadcast packet that needs to be
			 * looped back into the system, set the inbound ifp
			 * to that of the outbound ifp.  This will allow
			 * us to determine that it is a legitimate packet
			 * for the system.  Only set the ifp if it's not
			 * already set, just to be safe.
			 */
			if ((m->m_flags & (M_BCAST | M_LOOP)) &&
			    m->m_pkthdr.rcvif == NULL) {
				m->m_pkthdr.rcvif = ifp;
				rcvif_set = 1;
			}
			m_loop_set = m->m_flags & M_LOOP;
			retval = ifp->if_framer(ifp, &m, dest, dst_linkaddr,
			    frame_type, &pre, &post);
			if (retval != 0) {
				if (retval != EJUSTRETURN) {
					m_drop(m, DROPTAP_FLAG_DIR_OUT, DROP_REASON_DLIL_IF_FRAMER, NULL, 0);
				}
				goto next;
			}

			/*
			 * For partial checksum offload, adjust the start
			 * and stuff offsets based on the prepended header.
			 */
			if ((m->m_pkthdr.csum_flags &
			    (CSUM_DATA_VALID | CSUM_PARTIAL)) ==
			    (CSUM_DATA_VALID | CSUM_PARTIAL)) {
				m->m_pkthdr.csum_tx_stuff += pre;
				m->m_pkthdr.csum_tx_start += pre;
			}

			if (hwcksum_dbg != 0 && !(ifp->if_flags & IFF_LOOPBACK)) {
				dlil_output_cksum_dbg(ifp, m, pre,
				    proto_family);
			}

			/*
			 * Clear the ifp if it was set above, and to be
			 * safe, only if it is still the same as the
			 * outbound ifp we have in context.  If it was
			 * looped back, then a copy of it was sent to the
			 * loopback interface with the rcvif set, and we
			 * are clearing the one that will go down to the
			 * layer below.
			 */
			if (rcvif_set && m->m_pkthdr.rcvif == ifp) {
				m->m_pkthdr.rcvif = NULL;
			}
		}

		/*
		 * Let interface filters (if any) do their thing ...
		 */
		if ((flags & DLIL_OUTPUT_FLAGS_SKIP_IF_FILTERS) == 0) {
			retval = dlil_interface_filters_output(ifp, &m, proto_family);
			if (retval != 0) {
				if (retval != EJUSTRETURN) {
					m_drop(m, DROPTAP_FLAG_DIR_OUT, DROP_REASON_DLIL_IF_FILTER, NULL, 0);
				}
				goto next;
			}
		}
		/*
		 * Strip away M_PROTO1 bit prior to sending packet
		 * to the driver as this field may be used by the driver
		 */
		m->m_flags &= ~M_PROTO1;

		/*
		 * If the underlying interface is not capable of handling a
		 * packet whose data portion spans across physically disjoint
		 * pages, we need to "normalize" the packet so that we pass
		 * down a chain of mbufs where each mbuf points to a span that
		 * resides in the system page boundary.  If the packet does
		 * not cross page(s), the following is a no-op.
		 */
		if (!(ifp->if_hwassist & IFNET_MULTIPAGES)) {
			if ((m = m_normalize(m)) == NULL) {
				goto next;
			}
		}

		/*
		 * If this is a TSO packet, make sure the interface still
		 * advertise TSO capability.
		 */
		if (TSO_IPV4_NOTOK(ifp, m) || TSO_IPV6_NOTOK(ifp, m)) {
			retval = EMSGSIZE;
			m_drop(m, DROPTAP_FLAG_DIR_OUT, DROP_REASON_DLIL_TSO_NOT_OK, NULL, 0);
			goto cleanup;
		}

		ifp_inc_traffic_class_out(ifp, m);

#if SKYWALK
		/*
		 * For native skywalk devices, packets will be passed to pktap
		 * after GSO or after the mbuf to packet conversion.
		 * This is done for IPv4/IPv6 packets only because there is no
		 * space in the mbuf to pass down the proto family.
		 */
		if (dlil_is_native_netif_nexus(ifp)) {
			if (raw || m->m_pkthdr.pkt_proto == 0) {
				pktap_output(ifp, proto_family, m, pre, post);
				m->m_pkthdr.pkt_flags |= PKTF_SKIP_PKTAP;
			}
		} else {
			pktap_output(ifp, proto_family, m, pre, post);
		}
#else /* SKYWALK */
		pktap_output(ifp, proto_family, m, pre, post);
#endif /* SKYWALK */

		/*
		 * Count the number of elements in the mbuf chain
		 */
		if (tx_chain_len_count) {
			dlil_count_chain_len(m, &tx_chain_len_stats);
		}

		/*
		 * Discard partial sum information if this packet originated
		 * from another interface; the packet would already have the
		 * final checksum and we shouldn't recompute it.
		 */
		if ((m->m_pkthdr.pkt_flags & PKTF_FORWARDED) &&
		    (m->m_pkthdr.csum_flags & (CSUM_DATA_VALID | CSUM_PARTIAL)) ==
		    (CSUM_DATA_VALID | CSUM_PARTIAL)) {
			m->m_pkthdr.csum_flags &= ~CSUM_TX_FLAGS;
			m->m_pkthdr.csum_data = 0;
		}

		/*
		 * Finally, call the driver.
		 */
		if (ifp->if_eflags & (IFEF_SENDLIST | IFEF_ENQUEUE_MULTI)) {
			if (m->m_pkthdr.pkt_flags & PKTF_FORWARDED) {
				flen += (m_pktlen(m) - (pre + post));
				m->m_pkthdr.pkt_flags &= ~PKTF_FORWARDED;
			}
			(void) mbuf_set_timestamp(m, now_nsec, TRUE);

			*send_tail = m;
			send_tail = &m->m_nextpkt;
		} else {
			/*
			 * Record timestamp; ifnet_enqueue() will use this info
			 * rather than redoing the work.
			 */
			nanouptime(&now);
			net_timernsec(&now, &now_nsec);
			(void) mbuf_set_timestamp(m, now_nsec, TRUE);

			if (m->m_pkthdr.pkt_flags & PKTF_FORWARDED) {
				flen = (m_pktlen(m) - (pre + post));
				m->m_pkthdr.pkt_flags &= ~PKTF_FORWARDED;
			} else {
				flen = 0;
			}
			KERNEL_DEBUG(DBG_FNC_DLIL_IFOUT | DBG_FUNC_START,
			    0, 0, 0, 0, 0);
			retval = (*ifp->if_output_dlil)(ifp, m);
			if (retval == EQFULL || retval == EQSUSPENDED) {
				if (adv != NULL && adv->code == FADV_SUCCESS) {
					adv->code = (retval == EQFULL ?
					    FADV_FLOW_CONTROLLED :
					    FADV_SUSPENDED);
				}
				retval = 0;
			}
			if (retval == 0 && flen > 0) {
				fbytes += flen;
				fpkts++;
			}
			if (retval != 0 && dlil_verbose) {
				DLIL_PRINTF("%s: output error on %s retval = %d\n",
				    __func__, if_name(ifp),
				    retval);
			}
			KERNEL_DEBUG(DBG_FNC_DLIL_IFOUT | DBG_FUNC_END,
			    0, 0, 0, 0, 0);
		}
		KERNEL_DEBUG(DBG_FNC_DLIL_IFOUT | DBG_FUNC_END, 0, 0, 0, 0, 0);

next:
		m = packetlist;
		if (m != NULL) {
			m->m_flags |= m_loop_set;
			packetlist = packetlist->m_nextpkt;
			m->m_nextpkt = NULL;
		}
		/* Reset the proto family to old proto family for CLAT */
		if (did_clat46) {
			proto_family = old_proto_family;
		}
	} while (m != NULL);

	if (send_head != NULL) {
		KERNEL_DEBUG(DBG_FNC_DLIL_IFOUT | DBG_FUNC_START,
		    0, 0, 0, 0, 0);
		if (ifp->if_eflags & IFEF_SENDLIST) {
			retval = (*ifp->if_output_dlil)(ifp, send_head);
			if (retval == EQFULL || retval == EQSUSPENDED) {
				if (adv != NULL) {
					adv->code = (retval == EQFULL ?
					    FADV_FLOW_CONTROLLED :
					    FADV_SUSPENDED);
				}
				retval = 0;
			}
			if (retval == 0 && flen > 0) {
				fbytes += flen;
				fpkts++;
			}
			if (retval != 0 && dlil_verbose) {
				DLIL_PRINTF("%s: output error on %s retval = %d\n",
				    __func__, if_name(ifp), retval);
			}
		} else {
			struct mbuf *send_m;
			int enq_cnt = 0;
			VERIFY(ifp->if_eflags & IFEF_ENQUEUE_MULTI);
			while (send_head != NULL) {
				send_m = send_head;
				send_head = send_m->m_nextpkt;
				send_m->m_nextpkt = NULL;
				retval = (*ifp->if_output_dlil)(ifp, send_m);
				if (retval == EQFULL || retval == EQSUSPENDED) {
					if (adv != NULL) {
						adv->code = (retval == EQFULL ?
						    FADV_FLOW_CONTROLLED :
						    FADV_SUSPENDED);
					}
					retval = 0;
				}
				if (retval == 0) {
					enq_cnt++;
					if (flen > 0) {
						fpkts++;
					}
				}
				if (retval != 0 && dlil_verbose) {
					DLIL_PRINTF("%s: output error on %s "
					    "retval = %d\n",
					    __func__, if_name(ifp), retval);
				}
			}
			if (enq_cnt > 0) {
				fbytes += flen;
				ifnet_start(ifp);
			}
		}
		KERNEL_DEBUG(DBG_FNC_DLIL_IFOUT | DBG_FUNC_END, 0, 0, 0, 0, 0);
	}

	KERNEL_DEBUG(DBG_FNC_DLIL_OUTPUT | DBG_FUNC_END, 0, 0, 0, 0, 0);

cleanup:
	if (fbytes > 0) {
		ifp->if_fbytes += fbytes;
	}
	if (fpkts > 0) {
		ifp->if_fpackets += fpkts;
	}
	if (proto != NULL) {
		if_proto_free(proto);
	}
	if (packetlist) { /* if any packets are left, clean up */
		mbuf_freem_list(packetlist);
	}
	if (retval == EJUSTRETURN) {
		retval = 0;
	}
	if (iorefcnt == 1) {
		ifnet_datamov_end(ifp);
	}
	if (rt != NULL) {
		rtfree(rt);
		rt = NULL;
	}

	return retval;
}


/*
 * Static function implementations.
 */
static void
dlil_count_chain_len(mbuf_t m, struct chain_len_stats *cls)
{
	mbuf_t  n = m;
	int chainlen = 0;

	while (n != NULL) {
		chainlen++;
		n = n->m_next;
	}
	switch (chainlen) {
	case 0:
		break;
	case 1:
		os_atomic_inc(&cls->cls_one, relaxed);
		break;
	case 2:
		os_atomic_inc(&cls->cls_two, relaxed);
		break;
	case 3:
		os_atomic_inc(&cls->cls_three, relaxed);
		break;
	case 4:
		os_atomic_inc(&cls->cls_four, relaxed);
		break;
	case 5:
	default:
		os_atomic_inc(&cls->cls_five_or_more, relaxed);
		break;
	}
}


__attribute__((noinline))
static int
dlil_interface_filters_output(struct ifnet *ifp, struct mbuf **m_p,
    protocol_family_t protocol_family)
{
	boolean_t               is_vlan_packet;
	struct ifnet_filter     *filter;
	struct mbuf             *m = *m_p;

	if (TAILQ_EMPTY(&ifp->if_flt_head)) {
		return 0;
	}
	is_vlan_packet = packet_has_vlan_tag(m);

	/*
	 * Pass the outbound packet to the interface filters
	 */
	lck_mtx_lock_spin(&ifp->if_flt_lock);
	/* prevent filter list from changing in case we drop the lock */
	if_flt_monitor_busy(ifp);
	TAILQ_FOREACH(filter, &ifp->if_flt_head, filt_next) {
		int result;

		/* exclude VLAN packets from external filters PR-3586856 */
		if (is_vlan_packet &&
		    (filter->filt_flags & DLIL_IFF_INTERNAL) == 0) {
			continue;
		}

		if (!filter->filt_skip && filter->filt_output != NULL &&
		    (filter->filt_protocol == 0 ||
		    filter->filt_protocol == protocol_family)) {
			lck_mtx_unlock(&ifp->if_flt_lock);

			result = filter->filt_output(filter->filt_cookie, ifp,
			    protocol_family, m_p);

			lck_mtx_lock_spin(&ifp->if_flt_lock);
			if (result != 0) {
				/* we're done with the filter list */
				if_flt_monitor_unbusy(ifp);
				lck_mtx_unlock(&ifp->if_flt_lock);
				return result;
			}
		}
	}
	/* we're done with the filter list */
	if_flt_monitor_unbusy(ifp);
	lck_mtx_unlock(&ifp->if_flt_lock);

	return 0;
}

__attribute__((noinline))
static void
dlil_output_cksum_dbg(struct ifnet *ifp, struct mbuf *m, uint32_t hoff,
    protocol_family_t pf)
{
#pragma unused(ifp)
	uint32_t did_sw;

	if (!(hwcksum_dbg_mode & HWCKSUM_DBG_FINALIZE_FORCED) ||
	    (m->m_pkthdr.csum_flags & (CSUM_TSO_IPV4 | CSUM_TSO_IPV6))) {
		return;
	}

	switch (pf) {
	case PF_INET:
		did_sw = in_finalize_cksum(m, hoff, m->m_pkthdr.csum_flags);
		if (did_sw & CSUM_DELAY_IP) {
			hwcksum_dbg_finalized_hdr++;
		}
		if (did_sw & CSUM_DELAY_DATA) {
			hwcksum_dbg_finalized_data++;
		}
		break;
	case PF_INET6:
		/*
		 * Checksum offload should not have been enabled when
		 * extension headers exist; that also means that we
		 * cannot force-finalize packets with extension headers.
		 * Indicate to the callee should it skip such case by
		 * setting optlen to -1.
		 */
		did_sw = in6_finalize_cksum(m, hoff, -1, -1,
		    m->m_pkthdr.csum_flags);
		if (did_sw & CSUM_DELAY_IPV6_DATA) {
			hwcksum_dbg_finalized_data++;
		}
		break;
	default:
		return;
	}
}

#if CONFIG_DTRACE
__attribute__((noinline))
static void
dlil_output_dtrace(ifnet_t ifp, protocol_family_t proto_family, mbuf_t  m)
{
	if (proto_family == PF_INET) {
		struct ip *ip = mtod(m, struct ip *);
		DTRACE_IP6(send, struct mbuf *, m, struct inpcb *, NULL,
		    struct ip *, ip, struct ifnet *, ifp,
		    struct ip *, ip, struct ip6_hdr *, NULL);
	} else if (proto_family == PF_INET6) {
		struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr *);
		DTRACE_IP6(send, struct mbuf *, m, struct inpcb *, NULL,
		    struct ip6_hdr *, ip6, struct ifnet *, ifp,
		    struct ip *, NULL, struct ip6_hdr *, ip6);
	}
}
#endif /* CONFIG_DTRACE */
