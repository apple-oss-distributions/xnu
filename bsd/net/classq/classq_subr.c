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
#include <sys/mbuf.h>
#include <sys/errno.h>
#include <sys/random.h>
#include <sys/kernel_types.h>
#include <sys/sysctl.h>

#include <kern/zalloc.h>

#include <net/if.h>
#include <net/net_osdep.h>
#include <net/classq/classq.h>
#include <pexpert/pexpert.h>
#include <net/classq/classq_sfb.h>
#include <net/classq/classq_fq_codel.h>
#include <net/pktsched/pktsched.h>
#include <net/pktsched/pktsched_fq_codel.h>
#include <net/flowadv.h>

#include <libkern/libkern.h>

#if SKYWALK
#include <skywalk/os_skywalk_private.h>
#include <skywalk/nexus/netif/nx_netif.h>
#endif /* SKYWALK */

static errno_t ifclassq_dequeue_common(struct ifclassq *, mbuf_svc_class_t,
    u_int32_t, u_int32_t, classq_pkt_t *, classq_pkt_t *, u_int32_t *,
    u_int32_t *, boolean_t, u_int8_t);
static void ifclassq_tbr_dequeue_common(struct ifclassq *, mbuf_svc_class_t,
    boolean_t, classq_pkt_t *, u_int8_t);

static uint64_t ifclassq_def_c_target_qdelay = 0;
SYSCTL_QUAD(_net_classq, OID_AUTO, def_c_target_qdelay, CTLFLAG_RW | CTLFLAG_LOCKED,
    &ifclassq_def_c_target_qdelay, "def classic target queue delay in nanoseconds");

static uint64_t ifclassq_def_c_update_interval = 0;
SYSCTL_QUAD(_net_classq, OID_AUTO, def_c_update_interval,
    CTLFLAG_RW | CTLFLAG_LOCKED, &ifclassq_def_c_update_interval,
    "def classic update interval in nanoseconds");

static uint64_t ifclassq_def_l4s_target_qdelay = 0;
SYSCTL_QUAD(_net_classq, OID_AUTO, def_l4s_target_qdelay, CTLFLAG_RW | CTLFLAG_LOCKED,
    &ifclassq_def_l4s_target_qdelay, "def L4S target queue delay in nanoseconds");

static uint64_t ifclassq_def_l4s_update_interval = 0;
SYSCTL_QUAD(_net_classq, OID_AUTO, def_l4s_update_interval,
    CTLFLAG_RW | CTLFLAG_LOCKED, &ifclassq_def_l4s_update_interval,
    "def L4S update interval in nanoseconds");

static uint64_t ifclassq_ll_c_target_qdelay = 0;
SYSCTL_QUAD(_net_classq, OID_AUTO, ll_c_target_qdelay, CTLFLAG_RW | CTLFLAG_LOCKED,
    &ifclassq_ll_c_target_qdelay, "low latency classic target queue delay in nanoseconds");

static uint64_t ifclassq_ll_c_update_interval = 0;
SYSCTL_QUAD(_net_classq, OID_AUTO, ll_c_update_interval,
    CTLFLAG_RW | CTLFLAG_LOCKED, &ifclassq_ll_c_update_interval,
    "low latency classic update interval in nanoseconds");

static uint64_t ifclassq_ll_l4s_target_qdelay = 0;
SYSCTL_QUAD(_net_classq, OID_AUTO, ll_l4s_target_qdelay, CTLFLAG_RW | CTLFLAG_LOCKED,
    &ifclassq_ll_l4s_target_qdelay, "low latency L4S target queue delay in nanoseconds");

static uint64_t ifclassq_ll_l4s_update_interval = 0;
SYSCTL_QUAD(_net_classq, OID_AUTO, ll_l4s_update_interval,
    CTLFLAG_RW | CTLFLAG_LOCKED, &ifclassq_ll_l4s_update_interval,
    "low latency L4S update interval in nanoseconds");

uint32_t ifclassq_enable_l4s = 0;
SYSCTL_UINT(_net_classq, OID_AUTO, enable_l4s,
    CTLFLAG_RW | CTLFLAG_LOCKED, &ifclassq_enable_l4s, 0,
    "enable/disable L4S");

#if DEBUG || DEVELOPMENT
uint32_t ifclassq_flow_control_adv = 1; /* flow control advisory */
SYSCTL_UINT(_net_classq, OID_AUTO, flow_control_adv,
    CTLFLAG_RW | CTLFLAG_LOCKED, &ifclassq_flow_control_adv, 1,
    "enable/disable flow control advisory");

uint16_t fq_codel_quantum = 0;
#endif /* DEBUG || DEVELOPMENT */

static KALLOC_TYPE_DEFINE(ifcq_zone, struct ifclassq, NET_KT_DEFAULT);
LCK_ATTR_DECLARE(ifcq_lock_attr, 0, 0);
static LCK_GRP_DECLARE(ifcq_lock_group, "ifclassq locks");

void
classq_init(void)
{
	_CASSERT(MBUF_TC_BE == 0);
	_CASSERT(MBUF_SC_BE == 0);
	_CASSERT(IFCQ_SC_MAX == MBUF_SC_MAX_CLASSES);
#if DEBUG || DEVELOPMENT
	PE_parse_boot_argn("fq_codel_quantum", &fq_codel_quantum,
	    sizeof(fq_codel_quantum));
	PE_parse_boot_argn("ifclassq_def_c_target_qdelay", &ifclassq_def_c_target_qdelay,
	    sizeof(ifclassq_def_c_target_qdelay));
	PE_parse_boot_argn("ifclassq_def_c_update_interval",
	    &ifclassq_def_c_update_interval, sizeof(ifclassq_def_c_update_interval));
	PE_parse_boot_argn("ifclassq_def_l4s_target_qdelay", &ifclassq_def_l4s_target_qdelay,
	    sizeof(ifclassq_def_l4s_target_qdelay));
	PE_parse_boot_argn("ifclassq_def_l4s_update_interval",
	    &ifclassq_def_l4s_update_interval, sizeof(ifclassq_def_l4s_update_interval));
	PE_parse_boot_argn("ifclassq_ll_c_target_qdelay", &ifclassq_ll_c_target_qdelay,
	    sizeof(ifclassq_ll_c_target_qdelay));
	PE_parse_boot_argn("ifclassq_ll_c_update_interval",
	    &ifclassq_ll_c_update_interval, sizeof(ifclassq_ll_c_update_interval));
	PE_parse_boot_argn("ifclassq_ll_l4s_target_qdelay", &ifclassq_ll_l4s_target_qdelay,
	    sizeof(ifclassq_ll_l4s_target_qdelay));
	PE_parse_boot_argn("ifclassq_ll_l4s_update_interval",
	    &ifclassq_ll_l4s_update_interval, sizeof(ifclassq_ll_l4s_update_interval));
#endif /* DEBUG || DEVELOPMENT */
	fq_codel_init();
}

int
ifclassq_setup(struct ifclassq *ifq, struct ifnet *ifp, uint32_t sflags)
{
	int err = 0;

	IFCQ_LOCK(ifq);
	VERIFY(IFCQ_IS_EMPTY(ifq));
	ifq->ifcq_ifp = ifp;
	IFCQ_LEN(ifq) = 0;
	IFCQ_BYTES(ifq) = 0;
	bzero(&ifq->ifcq_xmitcnt, sizeof(ifq->ifcq_xmitcnt));
	bzero(&ifq->ifcq_dropcnt, sizeof(ifq->ifcq_dropcnt));

	VERIFY(!IFCQ_TBR_IS_ENABLED(ifq));
	VERIFY(ifq->ifcq_type == PKTSCHEDT_NONE);
	VERIFY(ifq->ifcq_flags == 0);
	VERIFY(ifq->ifcq_sflags == 0);
	VERIFY(ifq->ifcq_disc == NULL);

	if (ifp->if_eflags & IFEF_TXSTART) {
		u_int32_t maxlen = 0;

		if ((maxlen = IFCQ_MAXLEN(ifq)) == 0) {
			maxlen = if_sndq_maxlen;
		}
		IFCQ_SET_MAXLEN(ifq, maxlen);

		if (IFCQ_MAXLEN(ifq) != if_sndq_maxlen &&
		    IFCQ_TARGET_QDELAY(ifq) == 0) {
			/*
			 * Choose static queues because the interface has
			 * maximum queue size set
			 */
			sflags &= ~PKTSCHEDF_QALG_DELAYBASED;
		}
		ifq->ifcq_sflags = sflags;
		err = ifclassq_pktsched_setup(ifq);
		if (err == 0) {
			ifq->ifcq_flags = (IFCQF_READY | IFCQF_ENABLED);
		}
	}
	IFCQ_UNLOCK(ifq);
	return err;
}

void
ifclassq_teardown(struct ifclassq *ifq)
{
	IFCQ_LOCK(ifq);
	if (IFCQ_IS_DESTROYED(ifq)) {
		ASSERT((ifq->ifcq_flags & ~IFCQF_DESTROYED) == 0);
		goto done;
	}
	if (IFCQ_IS_READY(ifq)) {
		if (IFCQ_TBR_IS_ENABLED(ifq)) {
			struct tb_profile tb =
			{ .rate = 0, .percent = 0, .depth = 0 };
			(void) ifclassq_tbr_set(ifq, &tb, FALSE);
		}
		pktsched_teardown(ifq);
		ifq->ifcq_flags &= ~IFCQF_READY;
	}
	ifq->ifcq_sflags = 0;
	VERIFY(IFCQ_IS_EMPTY(ifq));
	VERIFY(!IFCQ_TBR_IS_ENABLED(ifq));
	VERIFY(ifq->ifcq_type == PKTSCHEDT_NONE);
	VERIFY(ifq->ifcq_flags == 0);
	VERIFY(ifq->ifcq_sflags == 0);
	VERIFY(ifq->ifcq_disc == NULL);
	IFCQ_LEN(ifq) = 0;
	IFCQ_BYTES(ifq) = 0;
	IFCQ_MAXLEN(ifq) = 0;
	bzero(&ifq->ifcq_xmitcnt, sizeof(ifq->ifcq_xmitcnt));
	bzero(&ifq->ifcq_dropcnt, sizeof(ifq->ifcq_dropcnt));
	ifq->ifcq_flags |= IFCQF_DESTROYED;
done:
	IFCQ_UNLOCK(ifq);
}

int
ifclassq_pktsched_setup(struct ifclassq *ifq)
{
	struct ifnet *ifp = ifq->ifcq_ifp;
	classq_pkt_type_t ptype = QP_MBUF;
	int err = 0;

	IFCQ_LOCK_ASSERT_HELD(ifq);
	VERIFY(ifp->if_eflags & IFEF_TXSTART);
#if SKYWALK
	ptype = ((ifp->if_eflags & IFEF_SKYWALK_NATIVE) != 0) ? QP_PACKET :
	    QP_MBUF;
#endif /* SKYWALK */

	err = pktsched_setup(ifq, PKTSCHEDT_FQ_CODEL, ifq->ifcq_sflags, ptype);

	return err;
}

void
ifclassq_set_maxlen(struct ifclassq *ifq, u_int32_t maxqlen)
{
	IFCQ_LOCK(ifq);
	if (maxqlen == 0) {
		maxqlen = if_sndq_maxlen;
	}
	IFCQ_SET_MAXLEN(ifq, maxqlen);
	IFCQ_UNLOCK(ifq);
}

u_int32_t
ifclassq_get_maxlen(struct ifclassq *ifq)
{
	return IFCQ_MAXLEN(ifq);
}

int
ifclassq_get_len(struct ifclassq *ifq, mbuf_svc_class_t sc, u_int8_t grp_idx,
    u_int32_t *packets, u_int32_t *bytes)
{
	int err = 0;

	IFCQ_LOCK(ifq);
	if ((ifq->ifcq_flags & (IFCQF_READY | IFCQF_ENABLED)) !=
	    (IFCQF_READY | IFCQF_ENABLED)) {
		return ENXIO;
	}
	if (sc == MBUF_SC_UNSPEC && grp_idx == IF_CLASSQ_ALL_GRPS) {
		VERIFY(packets != NULL);
		*packets = IFCQ_LEN(ifq);
	} else {
		cqrq_stat_sc_t req = { sc, grp_idx, 0, 0 };

		VERIFY(MBUF_VALID_SC(sc) || sc == MBUF_SC_UNSPEC);

		err = fq_if_request_classq(ifq, CLASSQRQ_STAT_SC, &req);
		if (packets != NULL) {
			*packets = req.packets;
		}
		if (bytes != NULL) {
			*bytes = req.bytes;
		}
	}
	IFCQ_UNLOCK(ifq);

#if SKYWALK
	struct ifnet *ifp = ifq->ifcq_ifp;

	if (__improbable(ifp->if_na_ops != NULL &&
	    ifp->if_na_ops->ni_get_len != NULL)) {
		err = ifp->if_na_ops->ni_get_len(ifp->if_na, sc, packets,
		    bytes, err);
	}
#endif /* SKYWALK */

	return err;
}

inline void
ifclassq_set_packet_metadata(struct ifclassq *ifq, struct ifnet *ifp,
    classq_pkt_t *p)
{
	if (!IFNET_IS_CELLULAR(ifp)) {
		return;
	}

	switch (p->cp_ptype) {
	case QP_MBUF: {
		struct mbuf *m = p->cp_mbuf;
		m->m_pkthdr.pkt_flags |= PKTF_VALID_UNSENT_DATA;
		m->m_pkthdr.bufstatus_if = IFCQ_BYTES(ifq);
		m->m_pkthdr.bufstatus_sndbuf = (uint32_t)ifp->if_sndbyte_unsent;
		break;
	}

#if SKYWALK
	case QP_PACKET:
		/*
		 * Support for equivalent of mbuf_get_unsent_data_bytes()
		 * is not needed in the Skywalk architecture.
		 */
		break;
#endif /* SKYWALK */

	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}
}

errno_t
ifclassq_enqueue(struct ifclassq *ifq, classq_pkt_t *head, classq_pkt_t *tail,
    u_int32_t cnt, u_int32_t bytes, boolean_t *pdrop)
{
	return fq_if_enqueue_classq(ifq, head, tail, cnt, bytes, pdrop);
}

errno_t
ifclassq_dequeue(struct ifclassq *ifq, u_int32_t pkt_limit,
    u_int32_t byte_limit, classq_pkt_t *head, classq_pkt_t *tail,
    u_int32_t *cnt, u_int32_t *len, u_int8_t grp_idx)
{
	return ifclassq_dequeue_common(ifq, MBUF_SC_UNSPEC, pkt_limit,
	           byte_limit, head, tail, cnt, len, FALSE, grp_idx);
}

errno_t
ifclassq_dequeue_sc(struct ifclassq *ifq, mbuf_svc_class_t sc,
    u_int32_t pkt_limit, u_int32_t byte_limit, classq_pkt_t *head,
    classq_pkt_t *tail, u_int32_t *cnt, u_int32_t *len, u_int8_t grp_idx)
{
	return ifclassq_dequeue_common(ifq, sc, pkt_limit, byte_limit,
	           head, tail, cnt, len, TRUE, grp_idx);
}

static errno_t
ifclassq_dequeue_common_default(struct ifclassq *ifq, mbuf_svc_class_t sc,
    u_int32_t pkt_limit, u_int32_t byte_limit, classq_pkt_t *head,
    classq_pkt_t *tail, u_int32_t *cnt, u_int32_t *len, boolean_t drvmgt,
    u_int8_t grp_idx)
{
	struct ifnet *ifp = ifq->ifcq_ifp;
	u_int32_t i = 0, l = 0;
	classq_pkt_t first = CLASSQ_PKT_INITIALIZER(first);
	classq_pkt_t last = CLASSQ_PKT_INITIALIZER(last);

	VERIFY(!drvmgt || MBUF_VALID_SC(sc));

	if (IFCQ_TBR_IS_ENABLED(ifq)) {
		goto dequeue_loop;
	}

	/*
	 * If the scheduler support dequeueing multiple packets at the
	 * same time, call that one instead.
	 */
	if (drvmgt) {
		int err;

		IFCQ_LOCK_SPIN(ifq);
		err = fq_if_dequeue_sc_classq_multi(ifq, sc, pkt_limit,
		    byte_limit, head, tail, cnt, len, grp_idx);
		IFCQ_UNLOCK(ifq);

		if (err == 0 && head->cp_mbuf == NULL) {
			err = EAGAIN;
		}
		return err;
	} else {
		int err;

		IFCQ_LOCK_SPIN(ifq);
		err = fq_if_dequeue_classq_multi(ifq, pkt_limit, byte_limit,
		    head, tail, cnt, len, grp_idx);
		IFCQ_UNLOCK(ifq);

		if (err == 0 && head->cp_mbuf == NULL) {
			err = EAGAIN;
		}
		return err;
	}

dequeue_loop:
	VERIFY(IFCQ_TBR_IS_ENABLED(ifq));
	IFCQ_LOCK_SPIN(ifq);

	while (i < pkt_limit && l < byte_limit) {
		if (drvmgt) {
			IFCQ_TBR_DEQUEUE_SC(ifq, sc, head, grp_idx);
		} else {
			IFCQ_TBR_DEQUEUE(ifq, head, grp_idx);
		}

		if (head->cp_mbuf == NULL) {
			break;
		}

		if (first.cp_mbuf == NULL) {
			first = *head;
		}

		switch (head->cp_ptype) {
		case QP_MBUF:
			head->cp_mbuf->m_nextpkt = NULL;
			l += head->cp_mbuf->m_pkthdr.len;
			ifclassq_set_packet_metadata(ifq, ifp, head);
			if (last.cp_mbuf != NULL) {
				last.cp_mbuf->m_nextpkt = head->cp_mbuf;
			}
			break;

#if SKYWALK
		case QP_PACKET:
			head->cp_kpkt->pkt_nextpkt = NULL;
			l += head->cp_kpkt->pkt_length;
			ifclassq_set_packet_metadata(ifq, ifp, head);
			if (last.cp_kpkt != NULL) {
				last.cp_kpkt->pkt_nextpkt = head->cp_kpkt;
			}
			break;
#endif /* SKYWALK */

		default:
			VERIFY(0);
			/* NOTREACHED */
			__builtin_unreachable();
		}

		last = *head;
		i++;
	}

	IFCQ_UNLOCK(ifq);

	if (tail != NULL) {
		*tail = last;
	}
	if (cnt != NULL) {
		*cnt = i;
	}
	if (len != NULL) {
		*len = l;
	}

	*head = first;
	return (first.cp_mbuf != NULL) ? 0 : EAGAIN;
}

static errno_t
ifclassq_dequeue_common(struct ifclassq *ifq, mbuf_svc_class_t sc,
    u_int32_t pkt_limit, u_int32_t byte_limit, classq_pkt_t *head,
    classq_pkt_t *tail, u_int32_t *cnt, u_int32_t *len, boolean_t drvmgt,
    u_int8_t grp_idx)
{
#if SKYWALK
	struct ifnet *ifp = ifq->ifcq_ifp;

	if (__improbable(ifp->if_na_ops != NULL &&
	    ifp->if_na_ops->ni_dequeue != NULL)) {
		/*
		 * TODO:
		 * We should be changing the pkt/byte limit to the
		 * available space in the next filter. But this is not
		 * useful until we can flow control the whole chain of
		 * filters.
		 */
		errno_t err = ifclassq_dequeue_common_default(ifq, sc,
		    pkt_limit, byte_limit, head, tail, cnt, len, drvmgt, grp_idx);

		return ifp->if_na_ops->ni_dequeue(ifp->if_na, sc, pkt_limit,
		           byte_limit, head, tail, cnt, len, drvmgt, err);
	}
#endif /* SKYWALK */
	return ifclassq_dequeue_common_default(ifq, sc,
	           pkt_limit, byte_limit, head, tail, cnt, len, drvmgt, grp_idx);
}

void
ifclassq_update(struct ifclassq *ifq, cqev_t ev)
{
	IFCQ_LOCK_ASSERT_HELD(ifq);
	VERIFY(IFCQ_IS_READY(ifq));
	fq_if_request_classq(ifq, CLASSQRQ_EVENT, (void *)ev);
}

int
ifclassq_attach(struct ifclassq *ifq, u_int32_t type, void *discipline)
{
	IFCQ_LOCK_ASSERT_HELD(ifq);
	VERIFY(ifq->ifcq_disc == NULL);
	ifq->ifcq_type = type;
	ifq->ifcq_disc = discipline;
	return 0;
}

void
ifclassq_detach(struct ifclassq *ifq)
{
	IFCQ_LOCK_ASSERT_HELD(ifq);
	VERIFY(ifq->ifcq_disc == NULL);
	ifq->ifcq_type = PKTSCHEDT_NONE;
}

int
ifclassq_getqstats(struct ifclassq *ifq, u_int8_t gid, u_int32_t qid, void *ubuf,
    u_int32_t *nbytes)
{
	struct if_ifclassq_stats *ifqs;
	int err;

	if (*nbytes < sizeof(*ifqs)) {
		return EINVAL;
	}

	ifqs = kalloc_type(struct if_ifclassq_stats,
	    Z_WAITOK | Z_ZERO | Z_NOFAIL);

	IFCQ_LOCK(ifq);
	if (!IFCQ_IS_READY(ifq)) {
		IFCQ_UNLOCK(ifq);
		kfree_type(struct if_ifclassq_stats, ifqs);
		return ENXIO;
	}

	ifqs->ifqs_len = IFCQ_LEN(ifq);
	ifqs->ifqs_maxlen = IFCQ_MAXLEN(ifq);
	*(&ifqs->ifqs_xmitcnt) = *(&ifq->ifcq_xmitcnt);
	*(&ifqs->ifqs_dropcnt) = *(&ifq->ifcq_dropcnt);
	ifqs->ifqs_scheduler = ifq->ifcq_type;

	err = pktsched_getqstats(ifq, gid, qid, ifqs);
	IFCQ_UNLOCK(ifq);

	if (err == 0 && (err = copyout((caddr_t)ifqs,
	    (user_addr_t)(uintptr_t)ubuf, sizeof(*ifqs))) == 0) {
		*nbytes = sizeof(*ifqs);
	}

	kfree_type(struct if_ifclassq_stats, ifqs);

	return err;
}

const char *
ifclassq_ev2str(cqev_t ev)
{
	const char *c;

	switch (ev) {
	case CLASSQ_EV_LINK_BANDWIDTH:
		c = "LINK_BANDWIDTH";
		break;

	case CLASSQ_EV_LINK_LATENCY:
		c = "LINK_LATENCY";
		break;

	case CLASSQ_EV_LINK_MTU:
		c = "LINK_MTU";
		break;

	case CLASSQ_EV_LINK_UP:
		c = "LINK_UP";
		break;

	case CLASSQ_EV_LINK_DOWN:
		c = "LINK_DOWN";
		break;

	default:
		c = "UNKNOWN";
		break;
	}

	return c;
}

/*
 * internal representation of token bucket parameters
 *	rate:	byte_per_unittime << 32
 *		(((bits_per_sec) / 8) << 32) / machclk_freq
 *	depth:	byte << 32
 *
 */
#define TBR_SHIFT       32
#define TBR_SCALE(x)    ((int64_t)(x) << TBR_SHIFT)
#define TBR_UNSCALE(x)  ((x) >> TBR_SHIFT)

void
ifclassq_tbr_dequeue(struct ifclassq *ifq, classq_pkt_t *pkt, u_int8_t grp_idx)
{
	ifclassq_tbr_dequeue_common(ifq, MBUF_SC_UNSPEC, FALSE, pkt, grp_idx);
}

void
ifclassq_tbr_dequeue_sc(struct ifclassq *ifq, mbuf_svc_class_t sc,
    classq_pkt_t *pkt, u_int8_t grp_idx)
{
	ifclassq_tbr_dequeue_common(ifq, sc, TRUE, pkt, grp_idx);
}

static void
ifclassq_tbr_dequeue_common(struct ifclassq *ifq, mbuf_svc_class_t sc,
    boolean_t drvmgt, classq_pkt_t *pkt, u_int8_t grp_idx)
{
	struct tb_regulator *tbr;
	int64_t interval;
	u_int64_t now;

	IFCQ_LOCK_ASSERT_HELD(ifq);

	VERIFY(!drvmgt || MBUF_VALID_SC(sc));
	VERIFY(IFCQ_TBR_IS_ENABLED(ifq));

	*pkt = CLASSQ_PKT_INITIALIZER(*pkt);
	tbr = &ifq->ifcq_tbr;
	/* update token only when it is negative */
	if (tbr->tbr_token <= 0) {
		now = read_machclk();
		interval = now - tbr->tbr_last;
		if (interval >= tbr->tbr_filluptime) {
			tbr->tbr_token = tbr->tbr_depth;
		} else {
			tbr->tbr_token += interval * tbr->tbr_rate;
			if (tbr->tbr_token > tbr->tbr_depth) {
				tbr->tbr_token = tbr->tbr_depth;
			}
		}
		tbr->tbr_last = now;
	}
	/* if token is still negative, don't allow dequeue */
	if (tbr->tbr_token <= 0) {
		return;
	}

	/*
	 * ifclassq takes precedence over ALTQ queue;
	 * ifcq_drain count is adjusted by the caller.
	 */
	if (drvmgt) {
		fq_if_dequeue_sc_classq(ifq, sc, pkt, grp_idx);
	} else {
		fq_if_dequeue_classq(ifq, pkt, grp_idx);
	}

	if (pkt->cp_mbuf != NULL) {
		switch (pkt->cp_ptype) {
		case QP_MBUF:
			tbr->tbr_token -= TBR_SCALE(m_pktlen(pkt->cp_mbuf));
			break;

#if SKYWALK
		case QP_PACKET:
			tbr->tbr_token -=
			    TBR_SCALE(pkt->cp_kpkt->pkt_length);
			break;
#endif /* SKYWALK */

		default:
			VERIFY(0);
			/* NOTREACHED */
		}
	}
}

/*
 * set a token bucket regulator.
 * if the specified rate is zero, the token bucket regulator is deleted.
 */
int
ifclassq_tbr_set(struct ifclassq *ifq, struct tb_profile *profile,
    boolean_t update)
{
	struct tb_regulator *tbr;
	struct ifnet *ifp = ifq->ifcq_ifp;
	u_int64_t rate, old_rate;

	IFCQ_LOCK_ASSERT_HELD(ifq);
	VERIFY(IFCQ_IS_READY(ifq));

	VERIFY(machclk_freq != 0);

	tbr = &ifq->ifcq_tbr;
	old_rate = tbr->tbr_rate_raw;

	rate = profile->rate;
	if (profile->percent > 0) {
		u_int64_t eff_rate;

		if (profile->percent > 100) {
			return EINVAL;
		}
		if ((eff_rate = ifp->if_output_bw.eff_bw) == 0) {
			return ENODEV;
		}
		rate = (eff_rate * profile->percent) / 100;
	}

	if (rate == 0) {
		if (!IFCQ_TBR_IS_ENABLED(ifq)) {
			return 0;
		}

		if (pktsched_verbose) {
			printf("%s: TBR disabled\n", if_name(ifp));
		}

		/* disable this TBR */
		ifq->ifcq_flags &= ~IFCQF_TBR;
		bzero(tbr, sizeof(*tbr));
		ifnet_set_start_cycle(ifp, NULL);
		if (update) {
			ifclassq_update(ifq, CLASSQ_EV_LINK_BANDWIDTH);
		}
		return 0;
	}

	if (pktsched_verbose) {
		printf("%s: TBR %s (rate %llu bps depth %u)\n", if_name(ifp),
		    (ifq->ifcq_flags & IFCQF_TBR) ? "reconfigured" :
		    "enabled", rate, profile->depth);
	}

	/* set the new TBR */
	bzero(tbr, sizeof(*tbr));
	tbr->tbr_rate_raw = rate;
	tbr->tbr_percent = profile->percent;
	ifq->ifcq_flags |= IFCQF_TBR;

	/*
	 * Note that the TBR fill up time (hence the ifnet restart time)
	 * is directly related to the specified TBR depth.  The ideal
	 * depth value should be computed such that the interval time
	 * between each successive wakeup is adequately spaced apart,
	 * in order to reduce scheduling overheads.  A target interval
	 * of 10 ms seems to provide good performance balance.  This can be
	 * overridden by specifying the depth profile.  Values smaller than
	 * the ideal depth will reduce delay at the expense of CPU cycles.
	 */
	tbr->tbr_rate = TBR_SCALE(rate / 8) / machclk_freq;
	if (tbr->tbr_rate > 0) {
		u_int32_t mtu = ifp->if_mtu;
		int64_t ival, idepth = 0;
		int i;

		if (mtu < IF_MINMTU) {
			mtu = IF_MINMTU;
		}

		ival = pktsched_nsecs_to_abstime(10 * NSEC_PER_MSEC); /* 10ms */

		for (i = 1;; i++) {
			idepth = TBR_SCALE(i * mtu);
			if ((idepth / tbr->tbr_rate) > ival) {
				break;
			}
		}
		VERIFY(idepth > 0);

		tbr->tbr_depth = TBR_SCALE(profile->depth);
		if (tbr->tbr_depth == 0) {
			tbr->tbr_filluptime = idepth / tbr->tbr_rate;
			/* a little fudge factor to get closer to rate */
			tbr->tbr_depth = idepth + (idepth >> 3);
		} else {
			tbr->tbr_filluptime = tbr->tbr_depth / tbr->tbr_rate;
		}
	} else {
		tbr->tbr_depth = TBR_SCALE(profile->depth);
		tbr->tbr_filluptime = 0xffffffffffffffffLL;
	}
	tbr->tbr_token = tbr->tbr_depth;
	tbr->tbr_last = read_machclk();

	if (tbr->tbr_rate > 0 && (ifp->if_flags & IFF_UP)) {
		struct timespec ts =
		{ 0, (long)pktsched_abs_to_nsecs(tbr->tbr_filluptime) };
		if (pktsched_verbose) {
			printf("%s: TBR calculated tokens %lld "
			    "filluptime %llu ns\n", if_name(ifp),
			    TBR_UNSCALE(tbr->tbr_token),
			    pktsched_abs_to_nsecs(tbr->tbr_filluptime));
		}
		ifnet_set_start_cycle(ifp, &ts);
	} else {
		if (pktsched_verbose) {
			if (tbr->tbr_rate == 0) {
				printf("%s: TBR calculated tokens %lld "
				    "infinite filluptime\n", if_name(ifp),
				    TBR_UNSCALE(tbr->tbr_token));
			} else if (!(ifp->if_flags & IFF_UP)) {
				printf("%s: TBR suspended (link is down)\n",
				    if_name(ifp));
			}
		}
		ifnet_set_start_cycle(ifp, NULL);
	}
	if (update && tbr->tbr_rate_raw != old_rate) {
		ifclassq_update(ifq, CLASSQ_EV_LINK_BANDWIDTH);
	}

	return 0;
}

void
ifclassq_calc_target_qdelay(struct ifnet *ifp, uint64_t *if_target_qdelay,
    uint32_t flags)
{
	uint64_t qdelay = 0, qdelay_configed = 0, qdely_default = 0;
	if (flags == IF_CLASSQ_DEF) {
		qdelay = IFCQ_TARGET_QDELAY(ifp->if_snd);
	}

	switch (flags) {
	case IF_CLASSQ_DEF:
		qdelay_configed = ifclassq_def_c_target_qdelay;
		qdely_default = IFQ_DEF_C_TARGET_DELAY;
		break;
	case IF_CLASSQ_L4S:
		qdelay_configed = ifclassq_def_l4s_target_qdelay;
		qdely_default = IFQ_DEF_L4S_TARGET_DELAY;
		break;
	case IF_CLASSQ_LOW_LATENCY:
		qdelay_configed = ifclassq_ll_c_target_qdelay;
		qdely_default = IFQ_LL_C_TARGET_DELAY;
		break;
	case (IF_CLASSQ_LOW_LATENCY | IF_CLASSQ_L4S):
		qdelay_configed = ifclassq_ll_l4s_target_qdelay;
		qdely_default = IFQ_LL_L4S_TARGET_DELAY;
		break;
	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	if (qdelay_configed != 0) {
		qdelay = qdelay_configed;
	}

	/*
	 * If we do not know the effective bandwidth, use the default
	 * target queue delay.
	 */
	if (qdelay == 0) {
		qdelay = qdely_default;
	}

	/*
	 * If a delay has been added to ifnet start callback for
	 * coalescing, we have to add that to the pre-set target delay
	 * because the packets can be in the queue longer.
	 */
	if ((ifp->if_eflags & IFEF_ENQUEUE_MULTI) &&
	    ifp->if_start_delay_timeout > 0) {
		qdelay += ifp->if_start_delay_timeout;
	}

	*(if_target_qdelay) = qdelay;
}

void
ifclassq_calc_update_interval(uint64_t *update_interval, uint32_t flags)
{
	uint64_t interval = 0, interval_configed = 0, interval_default = 0;

	switch (flags) {
	case IF_CLASSQ_DEF:
		interval_configed = ifclassq_def_c_update_interval;
		interval_default = IFQ_DEF_C_UPDATE_INTERVAL;
		break;
	case IF_CLASSQ_L4S:
		interval_configed = ifclassq_def_l4s_update_interval;
		interval_default = IFQ_DEF_L4S_UPDATE_INTERVAL;
		break;
	case IF_CLASSQ_LOW_LATENCY:
		interval_configed = ifclassq_ll_c_update_interval;
		interval_default = IFQ_LL_C_UPDATE_INTERVAL;
		break;
	case (IF_CLASSQ_LOW_LATENCY | IF_CLASSQ_L4S):
		interval_configed = ifclassq_ll_l4s_update_interval;
		interval_default = IFQ_LL_L4S_UPDATE_INTERVAL;
		break;
	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	/* If the system level override is set, use it */
	if (interval_configed != 0) {
		interval = interval_configed;
	}

	/* Otherwise use the default value */
	if (interval == 0) {
		interval = interval_default;
	}

	*update_interval = interval;
}

struct ifclassq *
ifclassq_alloc(void)
{
	struct ifclassq *ifcq;

	ifcq = zalloc_flags(ifcq_zone, Z_WAITOK | Z_ZERO | Z_NOFAIL);
	os_ref_init(&ifcq->ifcq_refcnt, NULL);
	os_ref_retain(&ifcq->ifcq_refcnt);
	lck_mtx_init(&ifcq->ifcq_lock, &ifcq_lock_group, &ifcq_lock_attr);
	return ifcq;
}

void
ifclassq_retain(struct ifclassq *ifcq)
{
	os_ref_retain(&ifcq->ifcq_refcnt);
}

void
ifclassq_release(struct ifclassq **pifcq)
{
	struct ifclassq *ifcq = *pifcq;

	*pifcq = NULL;
	if (os_ref_release(&ifcq->ifcq_refcnt) == 0) {
		ifclassq_teardown(ifcq);
		zfree(ifcq_zone, ifcq);
	}
}

int
ifclassq_setup_group(struct ifclassq *ifcq, uint8_t grp_idx, uint8_t flags)
{
	int err;

	IFCQ_LOCK(ifcq);
	VERIFY(ifcq->ifcq_disc != NULL);
	VERIFY(ifcq->ifcq_type == PKTSCHEDT_FQ_CODEL);

	err = fq_if_create_grp(ifcq, grp_idx, flags);
	IFCQ_UNLOCK(ifcq);

	return err;
}

void
ifclassq_set_grp_combined(struct ifclassq *ifcq, uint8_t grp_idx)
{
	IFCQ_LOCK(ifcq);
	VERIFY(ifcq->ifcq_disc != NULL);
	VERIFY(ifcq->ifcq_type == PKTSCHEDT_FQ_CODEL);

	fq_if_set_grp_combined(ifcq, grp_idx);
	IFCQ_UNLOCK(ifcq);
}

void
ifclassq_set_grp_separated(struct ifclassq *ifcq, uint8_t grp_idx)
{
	IFCQ_LOCK(ifcq);
	VERIFY(ifcq->ifcq_disc != NULL);
	VERIFY(ifcq->ifcq_type == PKTSCHEDT_FQ_CODEL);

	fq_if_set_grp_separated(ifcq, grp_idx);
	IFCQ_UNLOCK(ifcq);
}
