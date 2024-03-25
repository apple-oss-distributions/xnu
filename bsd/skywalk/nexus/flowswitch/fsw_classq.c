/*
 * Copyright (c) 2016-2021 Apple Inc. All rights reserved.
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

#include <skywalk/nexus/flowswitch/nx_flowswitch.h>
#include <skywalk/nexus/flowswitch/fsw_var.h>
#include <skywalk/nexus/netif/nx_netif.h>

void
fsw_classq_setup(struct nx_flowswitch *fsw, struct nexus_adapter *hostna)
{
	FSW_WLOCK_ASSERT_HELD(fsw);
	ASSERT(hostna->na_ifp->if_snd->ifcq_type != PKTSCHEDT_NONE);
	ASSERT(hostna->na_ifp->if_eflags & IFEF_TXSTART);
	if (hostna->na_type == NA_NETIF_COMPAT_HOST) {
		fsw->fsw_classq_enq_ptype = QP_MBUF;
	} else {
		ASSERT(hostna->na_type == NA_NETIF_HOST);
		fsw->fsw_classq_enq_ptype = QP_PACKET;
	}
}

void
fsw_classq_teardown(struct nx_flowswitch *fsw, struct nexus_adapter *hostna)
{
#if !(DEVELOPMENT || DEBUG)
#pragma unused(fsw)
#endif
	FSW_WLOCK_ASSERT_HELD(fsw);
	ASSERT(hostna->na_ifp->if_snd->ifcq_type != PKTSCHEDT_NONE);
	ASSERT(hostna->na_ifp->if_eflags & IFEF_TXSTART);
	if (hostna->na_type == NA_NETIF_COMPAT_HOST) {
		ASSERT(fsw->fsw_classq_enq_ptype == QP_MBUF);
	} else {
		ASSERT(hostna->na_type == NA_NETIF_HOST);
		ASSERT(fsw->fsw_classq_enq_ptype == QP_PACKET);
	}
	/* flush the interface queues */
	if_qflush_snd(hostna->na_ifp, false);
}

struct mbuf *
fsw_classq_kpkt_to_mbuf(struct nx_flowswitch *fsw, struct __kern_packet *pkt)
{
	struct mbuf *m = NULL;
	unsigned int one = 1;
	int error;

	error = mbuf_allocpacket(MBUF_WAITOK, pkt->pkt_length, &one, &m);
	VERIFY(error == 0);

	STATS_INC(&fsw->fsw_stats, FSW_STATS_TX_COPY_PKT2MBUF);
	if (PACKET_HAS_PARTIAL_CHECKSUM(pkt)) {
		STATS_INC(&fsw->fsw_stats, FSW_STATS_TX_COPY_SUM);
	}

	/* copy packet data */
	fsw->fsw_pkt_copy_to_mbuf(NR_TX, SK_PTR_ENCODE(pkt,
	    METADATA_TYPE(pkt), METADATA_SUBTYPE(pkt)), pkt->pkt_headroom,
	    m, 0, pkt->pkt_length, PACKET_HAS_PARTIAL_CHECKSUM(pkt),
	    pkt->pkt_csum_tx_start_off);

	_CASSERT(sizeof(m->m_pkthdr.pkt_flowid) ==
	    sizeof(pkt->pkt_flow_token));
	_CASSERT(sizeof(m->m_pkthdr.pkt_mpriv_srcid) ==
	    sizeof(pkt->pkt_flowsrc_token));
	_CASSERT(sizeof(m->m_pkthdr.pkt_mpriv_fidx) ==
	    sizeof(pkt->pkt_flowsrc_fidx));
	_CASSERT(sizeof(m->m_pkthdr.comp_gencnt) ==
	    sizeof(pkt->pkt_comp_gencnt));

	m->m_pkthdr.pkt_flowid = pkt->pkt_flow_token;
	m->m_pkthdr.comp_gencnt = pkt->pkt_comp_gencnt;
	m->m_pkthdr.pkt_mpriv_srcid = pkt->pkt_flowsrc_token;
	m->m_pkthdr.pkt_mpriv_fidx = pkt->pkt_flowsrc_fidx;

	SK_DF(SK_VERB_TX | SK_VERB_DUMP, "%s(%d) %s",
	    sk_proc_name_address(current_proc()), sk_proc_pid(current_proc()),
	    sk_dump("buf", m_mtod_current(m), m->m_pkthdr.len, 128, NULL, 0));

	if (__improbable((error != 0))) {
		if (m != NULL) {
			m_freem(m);
			m = NULL;
		}
	}
	return m;
}
