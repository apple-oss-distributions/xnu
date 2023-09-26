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

/*
 * The migration of flow queue between the different states is summarised in
 * the below state diagram. (RFC 8290)
 *
 * +-----------------+                +------------------+
 * |                 |     Empty      |                  |
 * |     Empty       |<---------------+       Old        +----+
 * |                 |                |                  |    |
 * +-------+---------+                +------------------+    |
 *         |                             ^            ^       |Credits
 *         |Arrival                      |            |       |Exhausted
 *         v                             |            |       |
 * +-----------------+                   |            |       |
 * |                 |      Empty or     |            |       |
 * |      New        +-------------------+            +-------+
 * |                 | Credits Exhausted
 * +-----------------+
 *
 * In this implementation of FQ-CODEL, flow queue is a dynamically allocated
 * object. An active flow queue goes through the above cycle of state
 * transitions very often. To avoid the cost of frequent flow queue object
 * allocation/free, this implementation retains the flow queue object in
 * [Empty] state on an Empty flow queue list with an active reference in flow
 * queue hash table. The flow queue objects on the Empty flow queue list have
 * an associated age and are purged accordingly.
 */

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/systm.h>
#include <sys/syslog.h>
#include <sys/proc.h>
#include <sys/errno.h>
#include <sys/kernel.h>
#include <sys/kauth.h>
#include <sys/sdt.h>
#include <kern/zalloc.h>
#include <netinet/in.h>

#include <net/classq/classq.h>
#include <net/classq/if_classq.h>
#include <net/pktsched/pktsched.h>
#include <net/pktsched/pktsched_fq_codel.h>
#include <net/classq/classq_fq_codel.h>

#include <netinet/tcp_var.h>

#define FQ_ZONE_MAX     (32 * 1024)     /* across all interfaces */

#define DTYPE_NODROP    0       /* no drop */
#define DTYPE_FORCED    1       /* a "forced" drop */
#define DTYPE_EARLY     2       /* an "unforced" (early) drop */

static uint32_t pkt_compressor = 1;
static uint64_t l4s_ce_threshold = 0; /* in usec */
static uint32_t l4s_local_ce_report = 0;
static uint64_t pkt_pacing_leeway = 0; /* in usec */
static uint64_t max_pkt_pacing_interval = 3 * NSEC_PER_SEC;
static uint64_t l4s_min_delay_threshold = 20 * NSEC_PER_MSEC; /* 20 ms */
#if (DEBUG || DEVELOPMENT)
SYSCTL_NODE(_net_classq, OID_AUTO, flow_q, CTLFLAG_RW | CTLFLAG_LOCKED,
    0, "FQ-CODEL parameters");

SYSCTL_UINT(_net_classq_flow_q, OID_AUTO, pkt_compressor,
    CTLFLAG_RW | CTLFLAG_LOCKED, &pkt_compressor, 0, "enable pkt compression");

SYSCTL_QUAD(_net_classq, OID_AUTO, l4s_ce_threshold,
    CTLFLAG_RW | CTLFLAG_LOCKED, &l4s_ce_threshold,
    "L4S CE threshold");

SYSCTL_UINT(_net_classq_flow_q, OID_AUTO, l4s_local_ce_report,
    CTLFLAG_RW | CTLFLAG_LOCKED, &l4s_local_ce_report, 0,
    "enable L4S local CE report");

SYSCTL_QUAD(_net_classq_flow_q, OID_AUTO, pkt_pacing_leeway,
    CTLFLAG_RW | CTLFLAG_LOCKED, &pkt_pacing_leeway, "packet pacing leeway");

SYSCTL_QUAD(_net_classq_flow_q, OID_AUTO, max_pkt_pacing_interval,
    CTLFLAG_RW | CTLFLAG_LOCKED, &max_pkt_pacing_interval, "max packet pacing interval");

SYSCTL_QUAD(_net_classq_flow_q, OID_AUTO, l4s_min_delay_threshold,
    CTLFLAG_RW | CTLFLAG_LOCKED, &l4s_min_delay_threshold, "l4s min delay threshold");
#endif /* (DEBUG || DEVELOPMENT) */

void
fq_codel_init(void)
{
	_CASSERT(AQM_KTRACE_AON_FLOW_HIGH_DELAY == 0x8300004);
	_CASSERT(AQM_KTRACE_AON_THROTTLE == 0x8300008);
	_CASSERT(AQM_KTRACE_AON_FLOW_OVERWHELMING == 0x830000c);
	_CASSERT(AQM_KTRACE_AON_FLOW_DQ_STALL == 0x8300010);

	_CASSERT(AQM_KTRACE_STATS_FLOW_ENQUEUE == 0x8310004);
	_CASSERT(AQM_KTRACE_STATS_FLOW_DEQUEUE == 0x8310008);
	_CASSERT(AQM_KTRACE_STATS_FLOW_CTL == 0x831000c);
	_CASSERT(AQM_KTRACE_STATS_FLOW_ALLOC == 0x8310010);
	_CASSERT(AQM_KTRACE_STATS_FLOW_DESTROY == 0x8310014);
	_CASSERT(AQM_KTRACE_STATS_FLOW_REPORT_CE == 0x8310018);
	_CASSERT(AQM_KTRACE_STATS_GET_QLEN == 0x831001c);
}

fq_t *
fq_alloc(classq_pkt_type_t ptype)
{
	fq_t *fq = NULL;

	fq = kalloc_type(fq_t, Z_WAITOK_ZERO);
	if (ptype == QP_MBUF) {
		MBUFQ_INIT(&fq->fq_mbufq);
	}
#if SKYWALK
	else {
		VERIFY(ptype == QP_PACKET);
		KPKTQ_INIT(&fq->fq_kpktq);
	}
#endif /* SKYWALK */
	CLASSQ_PKT_INIT(&fq->fq_dq_head);
	CLASSQ_PKT_INIT(&fq->fq_dq_tail);
	fq->fq_in_dqlist = false;

	return fq;
}

void
fq_destroy(fq_t *fq, classq_pkt_type_t ptype)
{
	VERIFY(!fq->fq_in_dqlist);
	VERIFY(fq_empty(fq, ptype));
	VERIFY(!(fq->fq_flags & (FQF_NEW_FLOW | FQF_OLD_FLOW |
	    FQF_EMPTY_FLOW)));
	VERIFY(fq->fq_bytes == 0);
	kfree_type(fq_t, fq);
}

static inline void
fq_detect_dequeue_stall(fq_if_t *fqs, fq_t *flowq, fq_if_classq_t *fq_cl,
    u_int64_t *now)
{
	u_int64_t maxgetqtime, update_interval;
	if (FQ_IS_DELAY_HIGH(flowq) || flowq->fq_getqtime == 0 ||
	    fq_empty(flowq, fqs->fqs_ptype) ||
	    flowq->fq_bytes < FQ_MIN_FC_THRESHOLD_BYTES) {
		return;
	}

	update_interval = FQ_UPDATE_INTERVAL(flowq);
	maxgetqtime = flowq->fq_getqtime + update_interval;
	if ((*now) > maxgetqtime) {
		/*
		 * there was no dequeue in an update interval worth of
		 * time. It means that the queue is stalled.
		 */
		FQ_SET_DELAY_HIGH(flowq);
		fq_cl->fcl_stat.fcl_dequeue_stall++;
		os_log_error(OS_LOG_DEFAULT, "%s:num: %d, "
		    "scidx: %d, flow: 0x%x, iface: %s grp: %hhu", __func__,
		    fq_cl->fcl_stat.fcl_dequeue_stall, flowq->fq_sc_index,
		    flowq->fq_flowhash, if_name(fqs->fqs_ifq->ifcq_ifp),
		    FQ_GROUP(flowq)->fqg_index);
		KDBG(AQM_KTRACE_AON_FLOW_DQ_STALL, flowq->fq_flowhash,
		    AQM_KTRACE_FQ_GRP_SC_IDX(flowq), flowq->fq_bytes,
		    (*now) - flowq->fq_getqtime);
	}
}

void
fq_head_drop(fq_if_t *fqs, fq_t *fq)
{
	pktsched_pkt_t pkt;
	volatile uint32_t *pkt_flags;
	uint64_t *pkt_timestamp;
	struct ifclassq *ifq = fqs->fqs_ifq;

	_PKTSCHED_PKT_INIT(&pkt);
	fq_getq_flow_internal(fqs, fq, &pkt);
	if (pkt.pktsched_pkt_mbuf == NULL) {
		return;
	}

	pktsched_get_pkt_vars(&pkt, &pkt_flags, &pkt_timestamp, NULL, NULL,
	    NULL, NULL, NULL);

	*pkt_timestamp = 0;
	switch (pkt.pktsched_ptype) {
	case QP_MBUF:
		*pkt_flags &= ~PKTF_PRIV_GUARDED;
		break;
#if SKYWALK
	case QP_PACKET:
		/* sanity check */
		ASSERT((*pkt_flags & ~PKT_F_COMMON_MASK) == 0);
		break;
#endif /* SKYWALK */
	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	IFCQ_DROP_ADD(ifq, 1, pktsched_get_pkt_len(&pkt));
	IFCQ_CONVERT_LOCK(ifq);
	pktsched_free_pkt(&pkt);
}


static int
fq_compressor(fq_if_t *fqs, fq_t *fq, fq_if_classq_t *fq_cl,
    pktsched_pkt_t *pkt)
{
	classq_pkt_type_t ptype = fqs->fqs_ptype;
	uint32_t comp_gencnt = 0;
	uint64_t *pkt_timestamp;
	uint64_t old_timestamp = 0;
	uint32_t old_pktlen = 0;
	struct ifclassq *ifq = fqs->fqs_ifq;

	if (__improbable(pkt_compressor == 0)) {
		return 0;
	}

	pktsched_get_pkt_vars(pkt, NULL, &pkt_timestamp, NULL, NULL, NULL,
	    &comp_gencnt, NULL);

	if (comp_gencnt == 0) {
		return 0;
	}

	fq_cl->fcl_stat.fcl_pkts_compressible++;

	if (fq_empty(fq, fqs->fqs_ptype)) {
		return 0;
	}

	if (ptype == QP_MBUF) {
		struct mbuf *m = MBUFQ_LAST(&fq->fq_mbufq);

		if (comp_gencnt != m->m_pkthdr.comp_gencnt) {
			return 0;
		}

		/* If we got until here, we should merge/replace the segment */
		MBUFQ_REMOVE(&fq->fq_mbufq, m);
		old_pktlen = m_pktlen(m);
		old_timestamp = m->m_pkthdr.pkt_timestamp;

		IFCQ_CONVERT_LOCK(fqs->fqs_ifq);
		m_freem(m);
	}
#if SKYWALK
	else {
		struct __kern_packet *kpkt = KPKTQ_LAST(&fq->fq_kpktq);

		if (comp_gencnt != kpkt->pkt_comp_gencnt) {
			return 0;
		}

		/* If we got until here, we should merge/replace the segment */
		KPKTQ_REMOVE(&fq->fq_kpktq, kpkt);
		old_pktlen = kpkt->pkt_length;
		old_timestamp = kpkt->pkt_timestamp;

		IFCQ_CONVERT_LOCK(fqs->fqs_ifq);
		pp_free_packet(*(struct kern_pbufpool **)(uintptr_t)&
		    (((struct __kern_quantum *)kpkt)->qum_pp),
		    (uint64_t)kpkt);
	}
#endif /* SKYWALK */

	fq->fq_bytes -= old_pktlen;
	fq_cl->fcl_stat.fcl_byte_cnt -= old_pktlen;
	fq_cl->fcl_stat.fcl_pkt_cnt--;
	IFCQ_DEC_LEN(ifq);
	IFCQ_DEC_BYTES(ifq, old_pktlen);

	FQ_GRP_DEC_LEN(fq);
	FQ_GRP_DEC_BYTES(fq, old_pktlen);

	*pkt_timestamp = old_timestamp;

	return CLASSQEQ_COMPRESSED;
}

int
fq_addq(fq_if_t *fqs, fq_if_group_t *fq_grp, pktsched_pkt_t *pkt,
    fq_if_classq_t *fq_cl)
{
	int droptype = DTYPE_NODROP, fc_adv = 0, ret = CLASSQEQ_SUCCESS;
	u_int64_t now;
	fq_t *fq = NULL;
	uint64_t *pkt_timestamp;
	volatile uint32_t *pkt_flags;
	uint32_t pkt_flowid, cnt;
	uint8_t pkt_proto, pkt_flowsrc;
	fq_tfc_type_t tfc_type = FQ_TFC_C;

	cnt = pkt->pktsched_pcnt;
	pktsched_get_pkt_vars(pkt, &pkt_flags, &pkt_timestamp, &pkt_flowid,
	    &pkt_flowsrc, &pkt_proto, NULL, NULL);

	/*
	 * XXX Not walking the chain to set this flag on every packet.
	 * This flag is only used for debugging. Nothing is affected if it's
	 * not set.
	 */
	switch (pkt->pktsched_ptype) {
	case QP_MBUF:
		/* See comments in <rdar://problem/14040693> */
		VERIFY(!(*pkt_flags & PKTF_PRIV_GUARDED));
		*pkt_flags |= PKTF_PRIV_GUARDED;
		break;
#if SKYWALK
	case QP_PACKET:
		/* sanity check */
		ASSERT((*pkt_flags & ~PKT_F_COMMON_MASK) == 0);
		break;
#endif /* SKYWALK */
	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	if (ifclassq_enable_l4s) {
		tfc_type = pktsched_is_pkt_l4s(pkt) ? FQ_TFC_L4S : FQ_TFC_C;
	}

	/*
	 * Timestamps for every packet must be set prior to entering this path.
	 */
	now = *pkt_timestamp;
	ASSERT(now > 0);

	/* find the flowq for this packet */
	fq = fq_if_hash_pkt(fqs, fq_grp, pkt_flowid, pktsched_get_pkt_svc(pkt),
	    now, true, tfc_type);
	if (__improbable(fq == NULL)) {
		DTRACE_IP1(memfail__drop, fq_if_t *, fqs);
		/* drop the packet if we could not allocate a flow queue */
		fq_cl->fcl_stat.fcl_drop_memfailure += cnt;
		return CLASSQEQ_DROP;
	}
	VERIFY(fq->fq_group == fq_grp);
	VERIFY(fqs->fqs_ptype == pkt->pktsched_ptype);

	KDBG(AQM_KTRACE_STATS_FLOW_ENQUEUE, fq->fq_flowhash,
	    AQM_KTRACE_FQ_GRP_SC_IDX(fq),
	    fq->fq_bytes, pktsched_get_pkt_len(pkt));

	fq_detect_dequeue_stall(fqs, fq, fq_cl, &now);

	/*
	 * Skip the dropping part if it's L4S. Flow control or ECN marking decision
	 * will be made at dequeue time.
	 */
	if (ifclassq_enable_l4s && tfc_type == FQ_TFC_L4S) {
		fq_cl->fcl_stat.fcl_l4s_pkts++;
		droptype = DTYPE_NODROP;
	}

	if (__improbable(FQ_IS_DELAY_HIGH(fq) || FQ_IS_OVERWHELMING(fq))) {
		if ((fq->fq_flags & FQF_FLOWCTL_CAPABLE) &&
		    (*pkt_flags & PKTF_FLOW_ADV)) {
			fc_adv = 1;
			/*
			 * If the flow is suspended or it is not
			 * TCP/QUIC, drop the chain.
			 */
			if ((pkt_proto != IPPROTO_TCP) &&
			    (pkt_proto != IPPROTO_QUIC)) {
				droptype = DTYPE_EARLY;
				fq_cl->fcl_stat.fcl_drop_early += cnt;
				IFCQ_DROP_ADD(fqs->fqs_ifq, cnt, pktsched_get_pkt_len(pkt));
			}
			DTRACE_IP6(flow__adv, fq_if_t *, fqs,
			    fq_if_classq_t *, fq_cl, fq_t *, fq,
			    int, droptype, pktsched_pkt_t *, pkt,
			    uint32_t, cnt);
		} else {
			/*
			 * Need to drop packets to make room for the new
			 * ones. Try to drop from the head of the queue
			 * instead of the latest packets.
			 */
			if (!fq_empty(fq, fqs->fqs_ptype)) {
				uint32_t i;

				for (i = 0; i < cnt; i++) {
					fq_head_drop(fqs, fq);
				}
				droptype = DTYPE_NODROP;
			} else {
				droptype = DTYPE_EARLY;
			}
			fq_cl->fcl_stat.fcl_drop_early += cnt;

			DTRACE_IP6(no__flow__adv, fq_if_t *, fqs,
			    fq_if_classq_t *, fq_cl, fq_t *, fq,
			    int, droptype, pktsched_pkt_t *, pkt,
			    uint32_t, cnt);
		}
	}

	/* Set the return code correctly */
	if (__improbable(fc_adv == 1 && droptype != DTYPE_FORCED)) {
		if (fq_if_add_fcentry(fqs, pkt, pkt_flowsrc, fq, fq_cl)) {
			fq->fq_flags |= FQF_FLOWCTL_ON;
			/* deliver flow control advisory error */
			if (droptype == DTYPE_NODROP) {
				ret = CLASSQEQ_SUCCESS_FC;
			} else {
				/* dropped due to flow control */
				ret = CLASSQEQ_DROP_FC;
			}
		} else {
			/*
			 * if we could not flow control the flow, it is
			 * better to drop
			 */
			droptype = DTYPE_FORCED;
			ret = CLASSQEQ_DROP_FC;
			fq_cl->fcl_stat.fcl_flow_control_fail++;
		}
		DTRACE_IP3(fc__ret, fq_if_t *, fqs, int, droptype, int, ret);
	}

	/*
	 * If the queue length hits the queue limit, drop a chain with the
	 * same number of packets from the front of the queue for a flow with
	 * maximum number of bytes. This will penalize heavy and unresponsive
	 * flows. It will also avoid a tail drop.
	 */
	if (__improbable(droptype == DTYPE_NODROP &&
	    fq_if_at_drop_limit(fqs))) {
		uint32_t i;

		if (fqs->fqs_large_flow == fq) {
			/*
			 * Drop from the head of the current fq. Since a
			 * new packet will be added to the tail, it is ok
			 * to leave fq in place.
			 */
			DTRACE_IP5(large__flow, fq_if_t *, fqs,
			    fq_if_classq_t *, fq_cl, fq_t *, fq,
			    pktsched_pkt_t *, pkt, uint32_t, cnt);

			for (i = 0; i < cnt; i++) {
				fq_head_drop(fqs, fq);
			}
			fq_cl->fcl_stat.fcl_drop_overflow += cnt;

			/*
			 * TCP and QUIC will react to the loss of those head dropped pkts
			 * and adjust send rate.
			 */
			if ((fq->fq_flags & FQF_FLOWCTL_CAPABLE) &&
			    (*pkt_flags & PKTF_FLOW_ADV) &&
			    (pkt_proto != IPPROTO_TCP) &&
			    (pkt_proto != IPPROTO_QUIC)) {
				if (fq_if_add_fcentry(fqs, pkt, pkt_flowsrc, fq, fq_cl)) {
					fq->fq_flags |= FQF_FLOWCTL_ON;
					FQ_SET_OVERWHELMING(fq);
					fq_cl->fcl_stat.fcl_overwhelming++;
					/* deliver flow control advisory error */
					ret = CLASSQEQ_SUCCESS_FC;
				}
			}
		} else {
			if (fqs->fqs_large_flow == NULL) {
				droptype = DTYPE_FORCED;
				fq_cl->fcl_stat.fcl_drop_overflow += cnt;
				ret = CLASSQEQ_DROP;

				DTRACE_IP5(no__large__flow, fq_if_t *, fqs,
				    fq_if_classq_t *, fq_cl, fq_t *, fq,
				    pktsched_pkt_t *, pkt, uint32_t, cnt);

				/*
				 * if this fq was freshly created and there
				 * is nothing to enqueue, move it to empty list
				 */
				if (fq_empty(fq, fqs->fqs_ptype) &&
				    !(fq->fq_flags & (FQF_NEW_FLOW |
				    FQF_OLD_FLOW))) {
					fq_if_move_to_empty_flow(fqs, fq_cl,
					    fq, now);
					fq = NULL;
				}
			} else {
				DTRACE_IP5(different__large__flow,
				    fq_if_t *, fqs, fq_if_classq_t *, fq_cl,
				    fq_t *, fq, pktsched_pkt_t *, pkt,
				    uint32_t, cnt);

				for (i = 0; i < cnt; i++) {
					fq_if_drop_packet(fqs, now);
				}
			}
		}
	}

	fq_cl->fcl_flags &= ~FCL_PACED;

	if (__probable(droptype == DTYPE_NODROP)) {
		uint32_t chain_len = pktsched_get_pkt_len(pkt);
		int ret_compress = 0;

		/*
		 * We do not compress if we are enqueuing a chain.
		 * Traversing the chain to look for acks would defeat the
		 * purpose of batch enqueueing.
		 */
		if (cnt == 1) {
			ret_compress = fq_compressor(fqs, fq, fq_cl, pkt);
			if (ret_compress == CLASSQEQ_COMPRESSED) {
				fq_cl->fcl_stat.fcl_pkts_compressed++;
			}
		}
		DTRACE_IP5(fq_enqueue, fq_if_t *, fqs, fq_if_classq_t *, fq_cl,
		    fq_t *, fq, pktsched_pkt_t *, pkt, uint32_t, cnt);
		fq_enqueue(fq, pkt->pktsched_pkt, pkt->pktsched_tail, cnt,
		    pkt->pktsched_ptype);

		fq->fq_bytes += chain_len;
		fq_cl->fcl_stat.fcl_byte_cnt += chain_len;
		fq_cl->fcl_stat.fcl_pkt_cnt += cnt;

		/*
		 * check if this queue will qualify to be the next
		 * victim queue
		 */
		fq_if_is_flow_heavy(fqs, fq);
	} else {
		DTRACE_IP3(fq_drop, fq_if_t *, fqs, int, droptype, int, ret);
		return (ret != CLASSQEQ_SUCCESS) ? ret : CLASSQEQ_DROP;
	}

	/*
	 * If the queue is not currently active, add it to the end of new
	 * flows list for that service class.
	 */
	if ((fq->fq_flags & (FQF_NEW_FLOW | FQF_OLD_FLOW)) == 0) {
		VERIFY(STAILQ_NEXT(fq, fq_actlink) == NULL);
		STAILQ_INSERT_TAIL(&fq_cl->fcl_new_flows, fq, fq_actlink);
		fq->fq_flags |= FQF_NEW_FLOW;

		fq_cl->fcl_stat.fcl_newflows_cnt++;

		fq->fq_deficit = fq_cl->fcl_quantum;
	}
	return ret;
}

void
fq_getq_flow_internal(fq_if_t *fqs, fq_t *fq, pktsched_pkt_t *pkt)
{
	classq_pkt_t p = CLASSQ_PKT_INITIALIZER(p);
	uint32_t plen;
	fq_if_classq_t *fq_cl;
	struct ifclassq *ifq = fqs->fqs_ifq;

	fq_dequeue(fq, &p, fqs->fqs_ptype);
	if (p.cp_ptype == QP_INVALID) {
		VERIFY(p.cp_mbuf == NULL);
		return;
	}

	fq->fq_next_tx_time = FQ_INVALID_TX_TS;

	pktsched_pkt_encap(pkt, &p);
	plen = pktsched_get_pkt_len(pkt);

	VERIFY(fq->fq_bytes >= plen);
	fq->fq_bytes -= plen;

	fq_cl = &FQ_CLASSQ(fq);
	fq_cl->fcl_stat.fcl_byte_cnt -= plen;
	fq_cl->fcl_stat.fcl_pkt_cnt--;
	fq_cl->fcl_flags &= ~FCL_PACED;

	IFCQ_DEC_LEN(ifq);
	IFCQ_DEC_BYTES(ifq, plen);

	FQ_GRP_DEC_LEN(fq);
	FQ_GRP_DEC_BYTES(fq, plen);

	/* Reset getqtime so that we don't count idle times */
	if (fq_empty(fq, fqs->fqs_ptype)) {
		fq->fq_getqtime = 0;
	}
}

/*
 * fq_get_next_tx_time returns FQ_INVALID_TX_TS when there is no tx time in fq
 */
static uint64_t
fq_get_next_tx_time(fq_if_t *fqs, fq_t *fq)
{
	uint64_t tx_time = FQ_INVALID_TX_TS;

	/*
	 * Check the cached value in fq
	 */
	if (fq->fq_next_tx_time != FQ_INVALID_TX_TS) {
		return fq->fq_next_tx_time;
	}

	switch (fqs->fqs_ptype) {
	case QP_MBUF: {
		struct mbuf *m;
		if ((m = MBUFQ_FIRST(&fq->fq_mbufq)) != NULL) {
			struct m_tag *tag;
			tag = m_tag_locate(m, KERNEL_MODULE_TAG_ID,
			    KERNEL_TAG_TYPE_AQM);
			if (tag != NULL) {
				tx_time = *(uint64_t *)tag->m_tag_data;
			}
		}
		break;
	}
	case QP_PACKET: {
		struct __kern_packet *p = KPKTQ_FIRST(&fq->fq_kpktq);
		if (__probable(p != NULL && (p->pkt_pflags & PKT_F_OPT_TX_TIMESTAMP) != 0)) {
			tx_time = p->pkt_com_opt->__po_pkt_tx_time;
		}
		break;
	}
	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	/*
	 * Cache the tx time in fq. The cache will be clear after dequeue or drop
	 * from the fq.
	 */
	fq->fq_next_tx_time = tx_time;

	return tx_time;
}

/*
 * fq_tx_time_ready returns true if the fq is empty so that it doesn't
 * affect caller logics that handles empty flow.
 */
boolean_t
fq_tx_time_ready(fq_if_t *fqs, fq_t *fq, uint64_t now, uint64_t *ready_time)
{
	uint64_t pkt_tx_time;
	fq_if_classq_t *fq_cl = &FQ_CLASSQ(fq);

	if (!ifclassq_enable_pacing || !ifclassq_enable_l4s || fq->fq_tfc_type != FQ_TFC_L4S) {
		return TRUE;
	}

	pkt_tx_time = fq_get_next_tx_time(fqs, fq);
	if (ready_time != NULL) {
		*ready_time = pkt_tx_time;
	}

	if (pkt_tx_time <= now + pkt_pacing_leeway ||
	    pkt_tx_time == FQ_INVALID_TX_TS) {
		return TRUE;
	}

	/*
	 * Ignore the tx time if it's scheduled too far in the future
	 */
	if (pkt_tx_time > max_pkt_pacing_interval + now) {
		fq_cl->fcl_stat.fcl_ignore_tx_time++;
		return TRUE;
	}

	ASSERT(pkt_tx_time != FQ_INVALID_TX_TS);
	return FALSE;
}

void
fq_getq_flow(fq_if_t *fqs, fq_t *fq, pktsched_pkt_t *pkt, uint64_t now)
{
	fq_if_classq_t *fq_cl = &FQ_CLASSQ(fq);
	int64_t qdelay = 0;
	volatile uint32_t *pkt_flags;
	uint64_t *pkt_timestamp, pkt_tx_time = 0, pacing_delay = 0;
	uint64_t fq_min_delay_threshold = FQ_TARGET_DELAY(fq);
	uint8_t pkt_flowsrc;
	boolean_t l4s_pkt;

	fq_getq_flow_internal(fqs, fq, pkt);
	if (pkt->pktsched_ptype == QP_INVALID) {
		VERIFY(pkt->pktsched_pkt_mbuf == NULL);
		return;
	}

	pktsched_get_pkt_vars(pkt, &pkt_flags, &pkt_timestamp, NULL, &pkt_flowsrc,
	    NULL, NULL, &pkt_tx_time);
	l4s_pkt = pktsched_is_pkt_l4s(pkt);
	if (ifclassq_enable_pacing && ifclassq_enable_l4s) {
		if (pkt_tx_time > *pkt_timestamp) {
			pacing_delay = pkt_tx_time - *pkt_timestamp;
			fq_cl->fcl_stat.fcl_paced_pkts++;
			DTRACE_SKYWALK3(aqm__pacing__delta, uint64_t, now - pkt_tx_time,
			    fq_if_t *, fqs, fq_t *, fq);
		}
#if (DEVELOPMENT || DEBUG)
		else {
			DTRACE_SKYWALK5(aqm__miss__pacing__delay, uint64_t, *pkt_timestamp,
			    uint64_t, pkt_tx_time, uint64_t, now, fq_if_t *,
			    fqs, fq_t *, fq);
		}
#endif // (DEVELOPMENT || DEBUG)
	}

	/* this will compute qdelay in nanoseconds */
	if (now > *pkt_timestamp) {
		qdelay = now - *pkt_timestamp;
	}

	/* Update min/max/avg qdelay for the respective class */
	if (fq_cl->fcl_stat.fcl_min_qdelay == 0 ||
	    (qdelay > 0 && (u_int64_t)qdelay < fq_cl->fcl_stat.fcl_min_qdelay)) {
		fq_cl->fcl_stat.fcl_min_qdelay = qdelay;
	}

	if (fq_cl->fcl_stat.fcl_max_qdelay == 0 ||
	    (qdelay > 0 && (u_int64_t)qdelay > fq_cl->fcl_stat.fcl_max_qdelay)) {
		fq_cl->fcl_stat.fcl_max_qdelay = qdelay;
	}

	uint64_t num_dequeues = fq_cl->fcl_stat.fcl_dequeue;

	if (num_dequeues == 0) {
		fq_cl->fcl_stat.fcl_avg_qdelay = qdelay;
	} else if (qdelay > 0) {
		uint64_t res = 0;
		if (os_add_overflow(num_dequeues, 1, &res)) {
			/* Reset the dequeue num and dequeue bytes */
			fq_cl->fcl_stat.fcl_dequeue = num_dequeues = 0;
			fq_cl->fcl_stat.fcl_dequeue_bytes = 0;
			fq_cl->fcl_stat.fcl_avg_qdelay = qdelay;
			os_log_info(OS_LOG_DEFAULT, "%s: dequeue num overflow, "
			    "flow: 0x%x, iface: %s", __func__, fq->fq_flowhash,
			    if_name(fqs->fqs_ifq->ifcq_ifp));
		} else {
			uint64_t product = 0;
			if (os_mul_overflow(fq_cl->fcl_stat.fcl_avg_qdelay,
			    num_dequeues, &product) || os_add_overflow(product, qdelay, &res)) {
				fq_cl->fcl_stat.fcl_avg_qdelay = qdelay;
			} else {
				fq_cl->fcl_stat.fcl_avg_qdelay = res /
				    (num_dequeues + 1);
			}
		}
	}

	fq->fq_pkts_since_last_report++;
	if (ifclassq_enable_l4s && l4s_pkt) {
		/*
		 * A safe guard to make sure that L4S is not going to build a huge
		 * queue if we encounter unexpected problems (for eg., if ACKs don't
		 * arrive in timely manner due to congestion in reverse path).
		 */
		fq_min_delay_threshold = l4s_min_delay_threshold;

		if ((l4s_ce_threshold != 0 && qdelay > l4s_ce_threshold + pacing_delay) ||
		    (l4s_ce_threshold == 0 && qdelay > FQ_TARGET_DELAY(fq) + pacing_delay)) {
			DTRACE_SKYWALK4(aqm__mark__ce, uint64_t, qdelay, uint64_t, pacing_delay,
			    fq_if_t *, fqs, fq_t *, fq);
			KDBG(AQM_KTRACE_STATS_FLOW_REPORT_CE, fq->fq_flowhash,
			    AQM_KTRACE_FQ_GRP_SC_IDX(fq), qdelay, pacing_delay);
			/*
			 * The packet buffer that pktsched_mark_ecn writes to can be pageable.
			 * Since it is not safe to write to pageable memory while preemption
			 * is disabled, convert the spin lock into mutex.
			 */
			IFCQ_CONVERT_LOCK(fqs->fqs_ifq);
			if (__improbable(l4s_local_ce_report != 0) &&
			    (*pkt_flags & PKTF_FLOW_ADV) != 0 &&
			    fq_if_report_ce(fqs, pkt, 1, fq->fq_pkts_since_last_report)) {
				fq->fq_pkts_since_last_report = 0;
				fq_cl->fcl_stat.fcl_ce_reported++;
			} else if (pktsched_mark_ecn(pkt) == 0) {
				fq_cl->fcl_stat.fcl_ce_marked++;
			} else {
				fq_cl->fcl_stat.fcl_ce_mark_failures++;
			}
		}
	}

	ASSERT(pacing_delay <= INT64_MAX);
	qdelay = MAX(0, qdelay - (int64_t)pacing_delay);
	if (fq->fq_min_qdelay == 0 ||
	    (u_int64_t)qdelay < fq->fq_min_qdelay) {
		fq->fq_min_qdelay = qdelay;
	}

	if (now >= fq->fq_updatetime) {
		if (fq->fq_min_qdelay > fq_min_delay_threshold) {
			if (!FQ_IS_DELAY_HIGH(fq)) {
				FQ_SET_DELAY_HIGH(fq);
				os_log_error(OS_LOG_DEFAULT,
				    "%s: scidx: %d, %llu, flow: 0x%x, "
				    "iface: %s, grp: %hhu\n", __func__, fq->fq_sc_index,
				    fq->fq_min_qdelay, fq->fq_flowhash,
				    if_name(fqs->fqs_ifq->ifcq_ifp),
				    FQ_GROUP(fq)->fqg_index);
			}
		} else {
			FQ_CLEAR_DELAY_HIGH(fq);
		}
		/* Reset measured queue delay and update time */
		fq->fq_updatetime = now + FQ_UPDATE_INTERVAL(fq);
		fq->fq_min_qdelay = 0;
	}

	if (fqs->fqs_large_flow != fq || !fq_if_almost_at_drop_limit(fqs)) {
		FQ_CLEAR_OVERWHELMING(fq);
	}
	if (!FQ_IS_DELAY_HIGH(fq) || fq_empty(fq, fqs->fqs_ptype)) {
		FQ_CLEAR_DELAY_HIGH(fq);
	}

	if ((fq->fq_flags & FQF_FLOWCTL_ON) &&
	    !FQ_IS_DELAY_HIGH(fq) && !FQ_IS_OVERWHELMING(fq)) {
		fq_if_flow_feedback(fqs, fq, fq_cl);
	}

	if (fq_empty(fq, fqs->fqs_ptype)) {
		/* Reset getqtime so that we don't count idle times */
		fq->fq_getqtime = 0;
	} else {
		fq->fq_getqtime = now;
	}
	fq_if_is_flow_heavy(fqs, fq);

	*pkt_timestamp = 0;
	switch (pkt->pktsched_ptype) {
	case QP_MBUF:
		*pkt_flags &= ~PKTF_PRIV_GUARDED;
		break;
#if SKYWALK
	case QP_PACKET:
		/* sanity check */
		ASSERT((*pkt_flags & ~PKT_F_COMMON_MASK) == 0);
		break;
#endif /* SKYWALK */
	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}
}
