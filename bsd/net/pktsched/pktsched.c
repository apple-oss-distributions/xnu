/*
 * Copyright (c) 2011-2021 Apple Inc. All rights reserved.
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

#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/errno.h>
#include <sys/mcache.h>
#include <sys/sysctl.h>

#include <dev/random/randomdev.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/net_osdep.h>
#include <net/pktsched/pktsched.h>
#include <net/pktsched/pktsched_fq_codel.h>
#include <net/pktsched/pktsched_netem.h>

#define _IP_VHL
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include <pexpert/pexpert.h>

#if SKYWALK
#include <skywalk/os_skywalk_private.h>
#endif /* SKYWALK */

u_int32_t machclk_freq = 0;
u_int64_t machclk_per_sec = 0;
u_int32_t pktsched_verbose = 0; /* more noise if greater than 1 */

static void init_machclk(void);

SYSCTL_NODE(_net, OID_AUTO, pktsched, CTLFLAG_RW | CTLFLAG_LOCKED, 0, "pktsched");

SYSCTL_UINT(_net_pktsched, OID_AUTO, verbose, CTLFLAG_RW | CTLFLAG_LOCKED,
    &pktsched_verbose, 0, "Packet scheduler verbosity level");

void
pktsched_init(void)
{
	init_machclk();
	if (machclk_freq == 0) {
		panic("%s: no CPU clock available!", __func__);
		/* NOTREACHED */
	}
	pktsched_fq_init();
}

static void
init_machclk(void)
{
	/*
	 * Initialize machclk_freq using the timerbase frequency
	 * value from device specific info.
	 */
	machclk_freq = (uint32_t)gPEClockFrequencyInfo.timebase_frequency_hz;

	clock_interval_to_absolutetime_interval(1, NSEC_PER_SEC,
	    &machclk_per_sec);
}

u_int64_t
pktsched_abs_to_nsecs(u_int64_t abstime)
{
	u_int64_t nsecs;

	absolutetime_to_nanoseconds(abstime, &nsecs);
	return nsecs;
}

u_int64_t
pktsched_nsecs_to_abstime(u_int64_t nsecs)
{
	u_int64_t abstime;

	nanoseconds_to_absolutetime(nsecs, &abstime);
	return abstime;
}

int
pktsched_setup(struct ifclassq *ifq, u_int32_t scheduler, u_int32_t sflags,
    classq_pkt_type_t ptype)
{
	int error = 0;
	u_int32_t rflags;

	IFCQ_LOCK_ASSERT_HELD(ifq);

	VERIFY(machclk_freq != 0);

	/* Nothing to do unless the scheduler type changes */
	if (ifq->ifcq_type == scheduler) {
		return 0;
	}

	/*
	 * Remember the flags that need to be restored upon success, as
	 * they may be cleared when we tear down existing scheduler.
	 */
	rflags = (ifq->ifcq_flags & IFCQF_ENABLED);

	if (ifq->ifcq_type != PKTSCHEDT_NONE) {
		pktsched_teardown(ifq);

		/* Teardown should have succeeded */
		VERIFY(ifq->ifcq_type == PKTSCHEDT_NONE);
		VERIFY(ifq->ifcq_disc == NULL);
	}

	error = fq_if_setup_ifclassq(ifq, sflags, ptype);
	if (error == 0) {
		ifq->ifcq_flags |= rflags;
	}

	return error;
}

void
pktsched_teardown(struct ifclassq *ifq)
{
	IFCQ_LOCK_ASSERT_HELD(ifq);
	if_qflush(ifq->ifcq_ifp, ifq, true);
	VERIFY(IFCQ_IS_EMPTY(ifq));
	ifq->ifcq_flags &= ~IFCQF_ENABLED;
	if (ifq->ifcq_type == PKTSCHEDT_FQ_CODEL) {
		/* Could be PKTSCHEDT_NONE */
		fq_if_teardown_ifclassq(ifq);
	}
	return;
}

int
pktsched_getqstats(struct ifclassq *ifq, u_int32_t gid, u_int32_t qid,
    struct if_ifclassq_stats *ifqs)
{
	int error = 0;

	IFCQ_LOCK_ASSERT_HELD(ifq);

	if (ifq->ifcq_type == PKTSCHEDT_FQ_CODEL) {
		/* Could be PKTSCHEDT_NONE */
		error = fq_if_getqstats_ifclassq(ifq, (uint8_t)gid, qid, ifqs);
	}

	return error;
}

void
pktsched_pkt_encap(pktsched_pkt_t *pkt, classq_pkt_t *cpkt)
{
	pkt->pktsched_pkt = *cpkt;
	pkt->pktsched_tail = *cpkt;
	pkt->pktsched_pcnt = 1;

	switch (cpkt->cp_ptype) {
	case QP_MBUF:
		pkt->pktsched_plen =
		    (uint32_t)m_pktlen(pkt->pktsched_pkt_mbuf);
		break;

#if SKYWALK
	case QP_PACKET:
		pkt->pktsched_plen = pkt->pktsched_pkt_kpkt->pkt_length;
		break;
#endif /* SKYWALK */

	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}
}

void
pktsched_pkt_encap_chain(pktsched_pkt_t *pkt, classq_pkt_t *cpkt,
    classq_pkt_t *tail, uint32_t cnt, uint32_t bytes)
{
	pkt->pktsched_pkt = *cpkt;
	pkt->pktsched_tail = *tail;
	pkt->pktsched_pcnt = cnt;
	pkt->pktsched_plen = bytes;

	switch (cpkt->cp_ptype) {
	case QP_MBUF:
		break;

#if SKYWALK
	case QP_PACKET:
		break;
#endif /* SKYWALK */

	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}
}

int
pktsched_clone_pkt(pktsched_pkt_t *pkt1, pktsched_pkt_t *pkt2)
{
	struct mbuf *m1, *m2;
#if SKYWALK
	struct __kern_packet *p1;
	kern_packet_t ph2;
	int err;
#endif /* SKYWALK */

	ASSERT(pkt1 != NULL);
	ASSERT(pkt1->pktsched_pkt_mbuf != NULL);
	ASSERT(pkt1->pktsched_pcnt == 1);

	/* allow in place clone, but make sure pkt2->pktsched_pkt won't leak */
	ASSERT((pkt1 == pkt2 && pkt1->pktsched_pkt_mbuf ==
	    pkt2->pktsched_pkt_mbuf) || (pkt1 != pkt2 &&
	    pkt2->pktsched_pkt_mbuf == NULL));

	switch (pkt1->pktsched_ptype) {
	case QP_MBUF:
		m1 = (struct mbuf *)pkt1->pktsched_pkt_mbuf;
		m2 = m_dup(m1, M_NOWAIT);
		if (__improbable(m2 == NULL)) {
			return ENOBUFS;
		}
		pkt2->pktsched_pkt_mbuf = m2;
		break;

#if SKYWALK
	case QP_PACKET:
		p1 = (struct __kern_packet *)pkt1->pktsched_pkt_kpkt;
		err = kern_packet_clone_nosleep(SK_PTR_ENCODE(p1,
		    METADATA_TYPE(p1), METADATA_SUBTYPE(p1)), &ph2,
		    KPKT_COPY_HEAVY);
		if (__improbable(err != 0)) {
			return err;
		}
		ASSERT(ph2 != 0);
		VERIFY(kern_packet_finalize(ph2) == 0);
		pkt2->pktsched_pkt_kpkt = SK_PTR_ADDR_KPKT(ph2);
		break;
#endif /* SKYWALK */

	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	pkt2->pktsched_plen = pkt1->pktsched_plen;
	pkt2->pktsched_ptype = pkt1->pktsched_ptype;
	pkt2->pktsched_tail = pkt2->pktsched_pkt;
	pkt2->pktsched_pcnt = 1;
	return 0;
}

void
pktsched_corrupt_packet(pktsched_pkt_t *pkt)
{
	struct mbuf *m = NULL;
	uint8_t *data = NULL;
	uint32_t data_len = 0;
	uint32_t rand32, rand_off, rand_bit;
#if SKYWALK
	struct __kern_packet *p = NULL;
#endif /* SKYWALK */

	switch (pkt->pktsched_ptype) {
	case QP_MBUF:
		m = pkt->pktsched_pkt_mbuf;
		data = mtod(m, uint8_t *);
		data_len = m->m_pkthdr.len;
		break;
#if SKYWALK
	case QP_PACKET:
		p = pkt->pktsched_pkt_kpkt;
		if (p->pkt_pflags & PKT_F_MBUF_DATA) {
			m = p->pkt_mbuf;
			data = mtod(m, uint8_t *);
			data_len = m->m_pkthdr.len;
		} else {
			MD_BUFLET_ADDR_DLEN(p, data, data_len);
		}
		break;
#endif /* SKYWALK */

	default:
		/* NOTREACHED */
		VERIFY(0);
		__builtin_unreachable();
	}

	read_frandom(&rand32, sizeof(rand32));
	rand_bit = rand32 & 0x8;
	rand_off = (rand32 >> 3) % data_len;
	data[rand_off] ^= 1 << rand_bit;
}

void
pktsched_free_pkt(pktsched_pkt_t *pkt)
{
	uint32_t cnt = pkt->pktsched_pcnt;
	ASSERT(cnt != 0);

	switch (pkt->pktsched_ptype) {
	case QP_MBUF: {
		struct mbuf *m;

		m = pkt->pktsched_pkt_mbuf;
		if (cnt == 1) {
			VERIFY(m->m_nextpkt == NULL);
		} else {
			VERIFY(m->m_nextpkt != NULL);
		}
		m_freem_list(m);
		break;
	}
#if SKYWALK
	case QP_PACKET: {
		struct __kern_packet *kpkt;
		int pcnt = 0;

		kpkt = pkt->pktsched_pkt_kpkt;
		if (cnt == 1) {
			VERIFY(kpkt->pkt_nextpkt == NULL);
		} else {
			VERIFY(kpkt->pkt_nextpkt != NULL);
		}
		pp_free_packet_chain(kpkt, &pcnt);
		VERIFY(cnt == (uint32_t)pcnt);
		break;
	}
#endif /* SKYWALK */

	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}
	pkt->pktsched_pkt = CLASSQ_PKT_INITIALIZER(pkt->pktsched_pkt);
	pkt->pktsched_tail = CLASSQ_PKT_INITIALIZER(pkt->pktsched_tail);
	pkt->pktsched_plen = 0;
	pkt->pktsched_pcnt = 0;
}

mbuf_svc_class_t
pktsched_get_pkt_svc(pktsched_pkt_t *pkt)
{
	mbuf_svc_class_t svc = MBUF_SC_UNSPEC;

	switch (pkt->pktsched_ptype) {
	case QP_MBUF:
		svc = m_get_service_class(pkt->pktsched_pkt_mbuf);
		break;

#if SKYWALK
	case QP_PACKET:
		svc = pkt->pktsched_pkt_kpkt->pkt_svc_class;
		break;
#endif /* SKYWALK */

	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	return svc;
}

void
pktsched_get_pkt_vars(pktsched_pkt_t *pkt, volatile uint32_t **flags,
    uint64_t **timestamp, uint32_t *flowid, uint8_t *flowsrc, uint8_t *proto,
    uint32_t *comp_gencnt)
{
	switch (pkt->pktsched_ptype) {
	case QP_MBUF: {
		struct pkthdr *pkth = &(pkt->pktsched_pkt_mbuf->m_pkthdr);

		if (flags != NULL) {
			*flags = &pkth->pkt_flags;
		}
		if (timestamp != NULL) {
			*timestamp = &pkth->pkt_timestamp;
		}
		if (flowid != NULL) {
			*flowid = pkth->pkt_flowid;
		}
		if (flowsrc != NULL) {
			*flowsrc = pkth->pkt_flowsrc;
		}
		if (proto != NULL) {
			*proto = pkth->pkt_proto;
		}
		if (comp_gencnt != NULL) {
			*comp_gencnt = pkth->comp_gencnt;
		}

		break;
	}

#if SKYWALK
	case QP_PACKET: {
		struct __kern_packet *kp = pkt->pktsched_pkt_kpkt;

		if (flags != NULL) {
			/* use lower-32 bit for common flags */
			*flags = &kp->pkt_pflags32;
		}
		if (timestamp != NULL) {
			*timestamp = &kp->pkt_timestamp;
		}
		if (flowid != NULL) {
			*flowid = kp->pkt_flow_token;
		}
		if (flowsrc != NULL) {
			*flowsrc = (uint8_t)kp->pkt_flowsrc_type;
		}
		if (proto != NULL) {
			*proto = kp->pkt_transport_protocol;
		}
		if (comp_gencnt != NULL) {
			*comp_gencnt = kp->pkt_comp_gencnt;
		}

		break;
	}
#endif /* SKYWALK */

	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}
}

struct flowadv_fcentry *
pktsched_alloc_fcentry(pktsched_pkt_t *pkt, struct ifnet *ifp, int how)
{
#pragma unused(ifp)
	struct flowadv_fcentry *fce = NULL;

	switch (pkt->pktsched_ptype) {
	case QP_MBUF: {
		struct mbuf *m = pkt->pktsched_pkt_mbuf;

		fce = flowadv_alloc_entry(how);
		if (fce == NULL) {
			break;
		}

		_CASSERT(sizeof(m->m_pkthdr.pkt_flowid) ==
		    sizeof(fce->fce_flowid));

		fce->fce_flowsrc_type = m->m_pkthdr.pkt_flowsrc;
		fce->fce_flowid = m->m_pkthdr.pkt_flowid;
#if SKYWALK
		_CASSERT(sizeof(m->m_pkthdr.pkt_mpriv_srcid) ==
		    sizeof(fce->fce_flowsrc_token));
		_CASSERT(sizeof(m->m_pkthdr.pkt_mpriv_fidx) ==
		    sizeof(fce->fce_flowsrc_fidx));

		if (fce->fce_flowsrc_type == FLOWSRC_CHANNEL) {
			fce->fce_flowsrc_fidx = m->m_pkthdr.pkt_mpriv_fidx;
			fce->fce_flowsrc_token = m->m_pkthdr.pkt_mpriv_srcid;
			fce->fce_ifp = ifp;
		}
#endif /* SKYWALK */
		break;
	}

#if SKYWALK
	case QP_PACKET: {
		struct __kern_packet *kp = pkt->pktsched_pkt_kpkt;

		fce = flowadv_alloc_entry(how);
		if (fce == NULL) {
			break;
		}

		_CASSERT(sizeof(fce->fce_flowid) ==
		    sizeof(kp->pkt_flow_token));
		_CASSERT(sizeof(fce->fce_flowsrc_fidx) ==
		    sizeof(kp->pkt_flowsrc_fidx));
		_CASSERT(sizeof(fce->fce_flowsrc_token) ==
		    sizeof(kp->pkt_flowsrc_token));

		ASSERT(kp->pkt_pflags & PKT_F_FLOW_ADV);
		fce->fce_flowsrc_type = kp->pkt_flowsrc_type;
		fce->fce_flowid = kp->pkt_flow_token;
		fce->fce_flowsrc_fidx = kp->pkt_flowsrc_fidx;
		fce->fce_flowsrc_token = kp->pkt_flowsrc_token;
		fce->fce_ifp = ifp;
		break;
	}
#endif /* SKYWALK */

	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	return fce;
}

uint32_t *
pktsched_get_pkt_sfb_vars(pktsched_pkt_t *pkt, uint32_t **sfb_flags)
{
	uint32_t *hashp = NULL;

	switch (pkt->pktsched_ptype) {
	case QP_MBUF: {
		struct pkthdr *pkth = &(pkt->pktsched_pkt_mbuf->m_pkthdr);

		_CASSERT(sizeof(pkth->pkt_mpriv_hash) == sizeof(uint32_t));
		_CASSERT(sizeof(pkth->pkt_mpriv_flags) == sizeof(uint32_t));
		*sfb_flags = &pkth->pkt_mpriv_flags;
		hashp = &pkth->pkt_mpriv_hash;
		break;
	}

#if SKYWALK
	case QP_PACKET: {
		struct __kern_packet *kp = pkt->pktsched_pkt_kpkt;

		_CASSERT(sizeof(kp->pkt_classq_hash) == sizeof(uint32_t));
		_CASSERT(sizeof(kp->pkt_classq_flags) == sizeof(uint32_t));
		*sfb_flags = &kp->pkt_classq_flags;
		hashp = &kp->pkt_classq_hash;
		break;
	}
#endif /* SKYWALK */

	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	return hashp;
}
