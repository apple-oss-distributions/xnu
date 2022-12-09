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

#include <sys/types.h>
#include <sys/param.h>
#include <kern/zalloc.h>
#include <net/ethernet.h>
#include <net/if_var.h>
#include <net/if.h>
#include <net/classq/classq.h>
#include <net/classq/classq_fq_codel.h>
#include <net/pktsched/pktsched_fq_codel.h>
#include <os/log.h>
#include <pexpert/pexpert.h>    /* for PE_parse_boot_argn */

#define FQ_CODEL_DEFAULT_QUANTUM 1500

#define FQ_CODEL_QUANTUM_BK_SYS(_q)    (_q)
#define FQ_CODEL_QUANTUM_BK(_q)        (_q)
#define FQ_CODEL_QUANTUM_BE(_q)        (_q)
#define FQ_CODEL_QUANTUM_RD(_q)        (_q)
#define FQ_CODEL_QUANTUM_OAM(_q)       (_q)
#define FQ_CODEL_QUANTUM_AV(_q)        (_q * 2)
#define FQ_CODEL_QUANTUM_RV(_q)        (_q * 2)
#define FQ_CODEL_QUANTUM_VI(_q)        (_q * 2)
#define FQ_CODEL_QUANTUM_VO(_q)        ((_q * 2) / 5)
#define FQ_CODEL_QUANTUM_CTL(_q)       ((_q * 2) / 5)

static ZONE_DEFINE_TYPE(fq_if_zone, "pktsched_fq_if", fq_if_t, ZC_ZFREE_CLEARMEM);
static ZONE_DEFINE_TYPE(fq_if_grp_zone, "pktsched_fq_if_grp", fq_if_group_t, ZC_ZFREE_CLEARMEM);

static uint64_t fq_empty_purge_delay = FQ_EMPTY_PURGE_DELAY;
#if (DEVELOPMENT || DEBUG)
SYSCTL_NODE(_net_classq, OID_AUTO, fq_codel, CTLFLAG_RW | CTLFLAG_LOCKED,
    0, "FQ-CODEL parameters");

SYSCTL_QUAD(_net_classq_fq_codel, OID_AUTO, fq_empty_purge_delay, CTLFLAG_RW |
    CTLFLAG_LOCKED, &fq_empty_purge_delay, "Empty flow queue purge delay (ns)");
#endif /* !DEVELOPMENT && !DEBUG */

typedef STAILQ_HEAD(, flowq) flowq_dqlist_t;

static fq_if_t *fq_if_alloc(struct ifclassq *, classq_pkt_type_t);
static void fq_if_destroy(fq_if_t *fqs);
static void fq_if_classq_init(fq_if_group_t *fqg, uint32_t priority,
    uint32_t quantum, uint32_t drr_max, uint32_t svc_class);
static void fq_if_dequeue(fq_if_t *, fq_if_classq_t *, uint32_t,
    int64_t, classq_pkt_t *, classq_pkt_t *, uint32_t *,
    uint32_t *, flowq_dqlist_t *, bool, uint64_t now);
void fq_if_stat_sc(fq_if_t *fqs, cqrq_stat_sc_t *stat);
static void fq_if_purge(fq_if_t *);
static void fq_if_purge_classq(fq_if_t *, fq_if_classq_t *);
static void fq_if_purge_flow(fq_if_t *, fq_t *, uint32_t *, uint32_t *,
    uint64_t);
static void fq_if_empty_new_flow(fq_t *fq, fq_if_classq_t *fq_cl);
static void fq_if_empty_old_flow(fq_if_t *fqs, fq_if_classq_t *fq_cl,
    fq_t *fq, uint64_t now);
static void fq_if_purge_empty_flow(fq_if_t *fqs, fq_t *fq);
static void fq_if_purge_empty_flow_list(fq_if_t *fqs, uint64_t now,
    bool purge_all);
static inline void fq_if_reuse_empty_flow(fq_if_t *fqs, fq_t *fq, uint64_t now);
static int fq_if_dequeue_sc_classq_multi_separate(struct ifclassq *ifq,
    mbuf_svc_class_t svc, u_int32_t maxpktcnt, u_int32_t maxbytecnt,
    classq_pkt_t *first_packet, classq_pkt_t *last_packet, u_int32_t *retpktcnt,
    u_int32_t *retbytecnt, uint8_t grp_idx);
static void fq_if_grp_stat_sc(fq_if_t *fqs, fq_if_group_t *grp,
    cqrq_stat_sc_t *stat);
static void fq_if_purge_grp(fq_if_t *fqs, fq_if_group_t *grp);
static inline boolean_t fq_if_is_grp_combined(fq_if_t *fqs, uint8_t grp_idx);
static void fq_if_destroy_grps(fq_if_t *fqs);

uint32_t fq_codel_drr_max_values[FQ_IF_MAX_CLASSES] = {
	[FQ_IF_CTL_INDEX]       = 8,
	[FQ_IF_VO_INDEX]        = 8,
	[FQ_IF_VI_INDEX]        = 6,
	[FQ_IF_RV_INDEX]        = 6,
	[FQ_IF_AV_INDEX]        = 6,
	[FQ_IF_OAM_INDEX]       = 4,
	[FQ_IF_RD_INDEX]        = 4,
	[FQ_IF_BE_INDEX]        = 4,
	[FQ_IF_BK_INDEX]        = 2,
	[FQ_IF_BK_SYS_INDEX]    = 2,
};

#define FQ_CODEL_DRR_MAX(_s)    fq_codel_drr_max_values[FQ_IF_##_s##_INDEX]

static boolean_t fq_if_grps_bitmap_zeros(fq_grp_tailq_t *grp_list, int pri,
    fq_if_state state);
static void fq_if_grps_bitmap_cpy(fq_grp_tailq_t *grp_list, int pri,
    fq_if_state dst_state, fq_if_state src_state);
static void fq_if_grps_bitmap_clr(fq_grp_tailq_t *grp_list, int pri,
    fq_if_state state);
static int fq_if_grps_bitmap_ffs(fq_grp_tailq_t *grp_list, int pri,
    fq_if_state state, fq_if_group_t **selected_grp);

static boolean_t fq_if_grps_sc_bitmap_zeros(fq_grp_tailq_t *grp_list, int pri,
    fq_if_state state);
static void fq_if_grps_sc_bitmap_cpy(fq_grp_tailq_t *grp_list, int pri,
    fq_if_state dst_state, fq_if_state src_state);
static void fq_if_grps_sc_bitmap_clr(fq_grp_tailq_t *grp_list, int pri,
    fq_if_state state);
static int fq_if_grps_sc_bitmap_ffs(fq_grp_tailq_t *grp_list, int pri,
    fq_if_state state, fq_if_group_t **selected_grp);

bitmap_ops_t fq_if_grps_bitmap_ops =
{
	.ffs    = fq_if_grps_bitmap_ffs,
	.zeros  = fq_if_grps_bitmap_zeros,
	.cpy    = fq_if_grps_bitmap_cpy,
	.clr    = fq_if_grps_bitmap_clr,
};

bitmap_ops_t fq_if_grps_sc_bitmap_ops =
{
	.ffs    = fq_if_grps_sc_bitmap_ffs,
	.zeros  = fq_if_grps_sc_bitmap_zeros,
	.cpy    = fq_if_grps_sc_bitmap_cpy,
	.clr    = fq_if_grps_sc_bitmap_clr,
};

void
pktsched_fq_init(void)
{
	// format looks like ifcq_drr_max=8,8,6
	char buf[(FQ_IF_MAX_CLASSES) * 3];
	size_t i, len, pri_index = 0;
	uint32_t drr = 0;
	if (!PE_parse_boot_arg_str("ifcq_drr_max", buf, sizeof(buf))) {
		return;
	}

	len = strlen(buf);
	for (i = 0; i < len + 1 && pri_index < FQ_IF_MAX_CLASSES; i++) {
		if (buf[i] != ',' && buf[i] != '\0') {
			VERIFY(buf[i] >= '0' && buf[i] <= '9');
			drr = drr * 10 + buf[i] - '0';
			continue;
		}
		fq_codel_drr_max_values[pri_index] = drr;
		pri_index += 1;
		drr = 0;
	}
}

#define FQ_IF_FLOW_HASH_ID(_flowid_) \
	(((_flowid_) >> FQ_IF_HASH_TAG_SHIFT) & FQ_IF_HASH_TAG_MASK)

#define FQ_IF_CLASSQ_IDLE(_fcl_) \
	(STAILQ_EMPTY(&(_fcl_)->fcl_new_flows) && \
	STAILQ_EMPTY(&(_fcl_)->fcl_old_flows))

typedef void (* fq_if_append_pkt_t)(classq_pkt_t *, classq_pkt_t *);
typedef boolean_t (* fq_getq_flow_t)(fq_if_t *, fq_if_classq_t *, fq_t *,
    int64_t, uint32_t, classq_pkt_t *, classq_pkt_t *, uint32_t *,
    uint32_t *, boolean_t *, uint32_t, uint64_t);

static void
fq_if_append_mbuf(classq_pkt_t *pkt, classq_pkt_t *next_pkt)
{
	pkt->cp_mbuf->m_nextpkt = next_pkt->cp_mbuf;
}

static inline uint64_t
fq_codel_get_time(void)
{
	struct timespec ts;
	uint64_t now;

	nanouptime(&ts);
	now = ((uint64_t)ts.tv_sec * NSEC_PER_SEC) + ts.tv_nsec;
	return now;
}

#if SKYWALK
static void
fq_if_append_pkt(classq_pkt_t *pkt, classq_pkt_t *next_pkt)
{
	pkt->cp_kpkt->pkt_nextpkt = next_pkt->cp_kpkt;
}
#endif /* SKYWALK */

#if SKYWALK
static boolean_t
fq_getq_flow_kpkt(fq_if_t *fqs, fq_if_classq_t *fq_cl, fq_t *fq,
    int64_t byte_limit, uint32_t pkt_limit, classq_pkt_t *head,
    classq_pkt_t *tail, uint32_t *byte_cnt, uint32_t *pkt_cnt,
    boolean_t *qempty, uint32_t pflags, uint64_t now)
{
	uint32_t plen;
	pktsched_pkt_t pkt;
	boolean_t limit_reached = FALSE;
	struct ifclassq *ifq = fqs->fqs_ifq;
	struct ifnet *ifp = ifq->ifcq_ifp;

	/*
	 * Assert to make sure pflags is part of PKT_F_COMMON_MASK;
	 * all common flags need to be declared in that mask.
	 */
	ASSERT((pflags & ~PKT_F_COMMON_MASK) == 0);

	while (fq->fq_deficit > 0 && limit_reached == FALSE &&
	    !KPKTQ_EMPTY(&fq->fq_kpktq)) {
		_PKTSCHED_PKT_INIT(&pkt);
		fq_getq_flow(fqs, fq, &pkt, now);
		ASSERT(pkt.pktsched_ptype == QP_PACKET);

		plen = pktsched_get_pkt_len(&pkt);
		fq->fq_deficit -= plen;
		pkt.pktsched_pkt_kpkt->pkt_pflags |= pflags;

		if (head->cp_kpkt == NULL) {
			*head = pkt.pktsched_pkt;
		} else {
			ASSERT(tail->cp_kpkt != NULL);
			ASSERT(tail->cp_kpkt->pkt_nextpkt == NULL);
			tail->cp_kpkt->pkt_nextpkt = pkt.pktsched_pkt_kpkt;
		}
		*tail = pkt.pktsched_pkt;
		tail->cp_kpkt->pkt_nextpkt = NULL;
		fq_cl->fcl_stat.fcl_dequeue++;
		fq_cl->fcl_stat.fcl_dequeue_bytes += plen;
		*pkt_cnt += 1;
		*byte_cnt += plen;

		ifclassq_set_packet_metadata(ifq, ifp, &pkt.pktsched_pkt);

		/* Check if the limit is reached */
		if (*pkt_cnt >= pkt_limit || *byte_cnt >= byte_limit) {
			limit_reached = TRUE;
		}
	}
	KDBG(AQM_KTRACE_STATS_FLOW_DEQUEUE, fq->fq_flowhash,
	    AQM_KTRACE_FQ_GRP_SC_IDX(fq),
	    fq->fq_bytes, fq->fq_min_qdelay);

	*qempty = KPKTQ_EMPTY(&fq->fq_kpktq);
	return limit_reached;
}
#endif /* SKYWALK */

static boolean_t
fq_getq_flow_mbuf(fq_if_t *fqs, fq_if_classq_t *fq_cl, fq_t *fq,
    int64_t byte_limit, uint32_t pkt_limit, classq_pkt_t *head,
    classq_pkt_t *tail, uint32_t *byte_cnt, uint32_t *pkt_cnt,
    boolean_t *qempty, uint32_t pflags, uint64_t now)
{
	u_int32_t plen;
	pktsched_pkt_t pkt;
	boolean_t limit_reached = FALSE;
	struct ifclassq *ifq = fqs->fqs_ifq;
	struct ifnet *ifp = ifq->ifcq_ifp;

	while (fq->fq_deficit > 0 && limit_reached == FALSE &&
	    !MBUFQ_EMPTY(&fq->fq_mbufq)) {
		_PKTSCHED_PKT_INIT(&pkt);
		fq_getq_flow(fqs, fq, &pkt, now);
		ASSERT(pkt.pktsched_ptype == QP_MBUF);

		plen = pktsched_get_pkt_len(&pkt);
		fq->fq_deficit -= plen;
		pkt.pktsched_pkt_mbuf->m_pkthdr.pkt_flags |= pflags;

		if (head->cp_mbuf == NULL) {
			*head = pkt.pktsched_pkt;
		} else {
			ASSERT(tail->cp_mbuf != NULL);
			ASSERT(tail->cp_mbuf->m_nextpkt == NULL);
			tail->cp_mbuf->m_nextpkt = pkt.pktsched_pkt_mbuf;
		}
		*tail = pkt.pktsched_pkt;
		tail->cp_mbuf->m_nextpkt = NULL;
		fq_cl->fcl_stat.fcl_dequeue++;
		fq_cl->fcl_stat.fcl_dequeue_bytes += plen;
		*pkt_cnt += 1;
		*byte_cnt += plen;

		ifclassq_set_packet_metadata(ifq, ifp, &pkt.pktsched_pkt);

		/* Check if the limit is reached */
		if (*pkt_cnt >= pkt_limit || *byte_cnt >= byte_limit) {
			limit_reached = TRUE;
		}
	}
	KDBG(AQM_KTRACE_STATS_FLOW_DEQUEUE, fq->fq_flowhash,
	    AQM_KTRACE_FQ_GRP_SC_IDX(fq),
	    fq->fq_bytes, fq->fq_min_qdelay);

	*qempty = MBUFQ_EMPTY(&fq->fq_mbufq);
	return limit_reached;
}

fq_if_t *
fq_if_alloc(struct ifclassq *ifq, classq_pkt_type_t ptype)
{
	fq_if_t *fqs;

	fqs = zalloc_flags(fq_if_zone, Z_WAITOK | Z_ZERO);
	fqs->fqs_ifq = ifq;
	fqs->fqs_ptype = ptype;

	/* Configure packet drop limit across all queues */
	fqs->fqs_pkt_droplimit = IFCQ_PKT_DROP_LIMIT(ifq);
	STAILQ_INIT(&fqs->fqs_fclist);
	TAILQ_INIT(&fqs->fqs_empty_list);
	TAILQ_INIT(&fqs->fqs_combined_grp_list);

	return fqs;
}

void
fq_if_destroy(fq_if_t *fqs)
{
	fq_if_purge(fqs);
	fq_if_destroy_grps(fqs);

	fqs->fqs_ifq = NULL;
	zfree(fq_if_zone, fqs);
}

static inline uint8_t
fq_if_service_to_priority(fq_if_t *fqs, mbuf_svc_class_t svc)
{
	uint8_t pri;

	if (fqs->fqs_flags & FQS_DRIVER_MANAGED) {
		switch (svc) {
		case MBUF_SC_BK_SYS:
		case MBUF_SC_BK:
			pri = FQ_IF_BK_INDEX;
			break;
		case MBUF_SC_BE:
		case MBUF_SC_RD:
		case MBUF_SC_OAM:
			pri = FQ_IF_BE_INDEX;
			break;
		case MBUF_SC_AV:
		case MBUF_SC_RV:
		case MBUF_SC_VI:
		case MBUF_SC_SIG:
			pri = FQ_IF_VI_INDEX;
			break;
		case MBUF_SC_VO:
		case MBUF_SC_CTL:
			pri = FQ_IF_VO_INDEX;
			break;
		default:
			pri = FQ_IF_BE_INDEX; /* Use best effort by default */
			break;
		}
		return pri;
	}

	/* scheduler is not managed by the driver */
	switch (svc) {
	case MBUF_SC_BK_SYS:
		pri = FQ_IF_BK_SYS_INDEX;
		break;
	case MBUF_SC_BK:
		pri = FQ_IF_BK_INDEX;
		break;
	case MBUF_SC_BE:
		pri = FQ_IF_BE_INDEX;
		break;
	case MBUF_SC_RD:
		pri = FQ_IF_RD_INDEX;
		break;
	case MBUF_SC_OAM:
		pri = FQ_IF_OAM_INDEX;
		break;
	case MBUF_SC_AV:
		pri = FQ_IF_AV_INDEX;
		break;
	case MBUF_SC_RV:
		pri = FQ_IF_RV_INDEX;
		break;
	case MBUF_SC_VI:
		pri = FQ_IF_VI_INDEX;
		break;
	case MBUF_SC_SIG:
		pri = FQ_IF_SIG_INDEX;
		break;
	case MBUF_SC_VO:
		pri = FQ_IF_VO_INDEX;
		break;
	case MBUF_SC_CTL:
		pri = FQ_IF_CTL_INDEX;
		break;
	default:
		pri = FQ_IF_BE_INDEX; /* Use best effort by default */
		break;
	}
	return pri;
}

void
fq_if_classq_init(fq_if_group_t *fqg, uint32_t pri, uint32_t quantum,
    uint32_t drr_max, uint32_t svc_class)
{
	fq_if_classq_t *fq_cl;
	VERIFY(pri < FQ_IF_MAX_CLASSES);
	fq_cl = &fqg->fqg_classq[pri];

	VERIFY(fq_cl->fcl_quantum == 0);
	VERIFY(quantum != 0);
	fq_cl->fcl_quantum = quantum;
	fq_cl->fcl_pri = pri;
	fq_cl->fcl_drr_max = drr_max;
	fq_cl->fcl_service_class = svc_class;
	STAILQ_INIT(&fq_cl->fcl_new_flows);
	STAILQ_INIT(&fq_cl->fcl_old_flows);
}

int
fq_if_enqueue_classq(struct ifclassq *ifq, classq_pkt_t *head,
    classq_pkt_t *tail, uint32_t cnt, uint32_t bytes, boolean_t *pdrop)
{
	uint8_t pri, grp_idx = 0;
	fq_if_t *fqs;
	fq_if_classq_t *fq_cl;
	fq_if_group_t *fq_group;
	int ret;
	mbuf_svc_class_t svc;
	pktsched_pkt_t pkt;

	pktsched_pkt_encap_chain(&pkt, head, tail, cnt, bytes);

	fqs = (fq_if_t *)ifq->ifcq_disc;
	svc = pktsched_get_pkt_svc(&pkt);
#if SKYWALK
	if (head->cp_ptype == QP_PACKET) {
		grp_idx = head->cp_kpkt->pkt_qset_idx;
	}
#endif /* SKYWALK */
	pri = fq_if_service_to_priority(fqs, svc);
	VERIFY(pri < FQ_IF_MAX_CLASSES);

	IFCQ_LOCK_SPIN(ifq);
	fq_group = fq_if_find_grp(fqs, grp_idx);
	fq_cl = &fq_group->fqg_classq[pri];

	if (__improbable(svc == MBUF_SC_BK_SYS && fqs->fqs_throttle == 1)) {
		IFCQ_UNLOCK(ifq);
		/* BK_SYS is currently throttled */
		atomic_add_32(&fq_cl->fcl_stat.fcl_throttle_drops, 1);
		pktsched_free_pkt(&pkt);
		*pdrop = TRUE;
		ret = EQSUSPENDED;
		goto done;
	}

	ASSERT(pkt.pktsched_ptype == fqs->fqs_ptype);
	ret = fq_addq(fqs, fq_group, &pkt, fq_cl);
	if (!FQ_IF_CLASSQ_IDLE(fq_cl)) {
		if (((fq_group->fqg_bitmaps[FQ_IF_ER] | fq_group->fqg_bitmaps[FQ_IF_EB]) &
		    (1 << pri)) == 0) {
			/*
			 * this group is not in ER or EB groups,
			 * mark it as IB
			 */
			pktsched_bit_set(pri, &fq_group->fqg_bitmaps[FQ_IF_IB]);
		}
	}

	if (__improbable(ret != 0)) {
		if (ret == CLASSQEQ_SUCCESS_FC) {
			/* packet enqueued, return advisory feedback */
			ret = EQFULL;
			*pdrop = FALSE;
		} else if (ret == CLASSQEQ_COMPRESSED) {
			ret = 0;
			*pdrop = FALSE;
		} else {
			IFCQ_UNLOCK(ifq);
			*pdrop = TRUE;
			pktsched_free_pkt(&pkt);
			switch (ret) {
			case CLASSQEQ_DROP:
				ret = ENOBUFS;
				goto done;
			case CLASSQEQ_DROP_FC:
				ret = EQFULL;
				goto done;
			case CLASSQEQ_DROP_SP:
				ret = EQSUSPENDED;
				goto done;
			default:
				VERIFY(0);
				/* NOTREACHED */
				__builtin_unreachable();
			}
			/* NOTREACHED */
			__builtin_unreachable();
		}
	} else {
		*pdrop = FALSE;
	}
	IFCQ_ADD_LEN(ifq, cnt);
	IFCQ_INC_BYTES(ifq, bytes);


	FQS_GRP_ADD_LEN(fqs, grp_idx, cnt);
	FQS_GRP_INC_BYTES(fqs, grp_idx, bytes);

	IFCQ_UNLOCK(ifq);
done:
#if DEBUG || DEVELOPMENT
	if (__improbable((ret == EQFULL) && (ifclassq_flow_control_adv == 0))) {
		ret = 0;
	}
#endif /* DEBUG || DEVELOPMENT */
	return ret;
}

void
fq_if_dequeue_classq(struct ifclassq *ifq, classq_pkt_t *pkt, uint8_t grp_idx)
{
	(void) fq_if_dequeue_classq_multi(ifq, 1,
	    CLASSQ_DEQUEUE_MAX_BYTE_LIMIT, pkt, NULL, NULL, NULL, grp_idx);
}

void
fq_if_dequeue_sc_classq(struct ifclassq *ifq, mbuf_svc_class_t svc,
    classq_pkt_t *pkt, uint8_t grp_idx)
{
	(void) fq_if_dequeue_sc_classq_multi(ifq, svc, 1,
	    CLASSQ_DEQUEUE_MAX_BYTE_LIMIT, pkt, NULL, NULL, NULL, grp_idx);
}

static inline void
fq_dqlist_add(flowq_dqlist_t *fq_dqlist_head, fq_t *fq)
{
	ASSERT(fq->fq_dq_head.cp_mbuf == NULL);
	ASSERT(!fq->fq_in_dqlist);
	STAILQ_INSERT_TAIL(fq_dqlist_head, fq, fq_dqlink);
	fq->fq_in_dqlist = true;
}

static inline void
fq_dqlist_remove(flowq_dqlist_t *fq_dqlist_head, fq_t *fq, classq_pkt_t *head,
    classq_pkt_t *tail, classq_pkt_type_t ptype)
{
	ASSERT(fq->fq_in_dqlist);
	if (fq->fq_dq_head.cp_mbuf == NULL) {
		goto done;
	}

	if (head->cp_mbuf == NULL) {
		*head = fq->fq_dq_head;
	} else {
		ASSERT(tail->cp_mbuf != NULL);

		switch (ptype) {
		case QP_MBUF:
			ASSERT(tail->cp_mbuf->m_nextpkt == NULL);
			tail->cp_mbuf->m_nextpkt = fq->fq_dq_head.cp_mbuf;
			ASSERT(fq->fq_dq_tail.cp_mbuf->m_nextpkt == NULL);
			break;
#if SKYWALK
		case QP_PACKET:
			ASSERT(tail->cp_kpkt->pkt_nextpkt == NULL);
			tail->cp_kpkt->pkt_nextpkt = fq->fq_dq_head.cp_kpkt;
			ASSERT(fq->fq_dq_tail.cp_kpkt->pkt_nextpkt == NULL);
			break;
#endif /* SKYWALK */
		default:
			VERIFY(0);
			/* NOTREACHED */
			__builtin_unreachable();
		}
	}
	*tail = fq->fq_dq_tail;
done:
	STAILQ_REMOVE(fq_dqlist_head, fq, flowq, fq_dqlink);
	CLASSQ_PKT_INIT(&fq->fq_dq_head);
	CLASSQ_PKT_INIT(&fq->fq_dq_tail);
	fq->fq_in_dqlist = false;
}

static inline void
fq_dqlist_get_packet_list(flowq_dqlist_t *fq_dqlist_head, classq_pkt_t *head,
    classq_pkt_t *tail, classq_pkt_type_t ptype)
{
	fq_t *fq, *tfq;

	STAILQ_FOREACH_SAFE(fq, fq_dqlist_head, fq_dqlink, tfq) {
		fq_dqlist_remove(fq_dqlist_head, fq, head, tail, ptype);
	}
}

static int
fq_if_grps_bitmap_ffs(fq_grp_tailq_t *grp_list, int pri, fq_if_state state,
    fq_if_group_t **selected_grp)
{
	#pragma unused(pri)

	fq_if_group_t *grp;
	uint32_t highest_pri = FQ_IF_MAX_CLASSES;
	int ret_pri = 0;

	TAILQ_FOREACH(grp, grp_list, fqg_grp_link) {
		uint32_t cur_pri = pktsched_ffs(grp->fqg_bitmaps[state]);
		/* bitmap is empty in this case */
		if (cur_pri == 0) {
			continue;
		}
		if (cur_pri <= highest_pri) {
			highest_pri = cur_pri;
			ret_pri = cur_pri;
			*selected_grp = grp;
		}
	}
	return ret_pri;
}

static boolean_t
fq_if_grps_bitmap_zeros(fq_grp_tailq_t *grp_list, int pri, fq_if_state state)
{
    #pragma unused(pri)

	fq_if_group_t *grp;

	TAILQ_FOREACH(grp, grp_list, fqg_grp_link) {
		if (grp->fqg_bitmaps[state] != 0) {
			return FALSE;
		}
	}
	return TRUE;
}

static void
fq_if_grps_bitmap_cpy(fq_grp_tailq_t *grp_list, int pri, fq_if_state dst_state,
    fq_if_state src_state)
{
    #pragma unused(pri)

	fq_if_group_t *grp;
	TAILQ_FOREACH(grp, grp_list, fqg_grp_link) {
		grp->fqg_bitmaps[dst_state] = grp->fqg_bitmaps[src_state];
	}
}

static void
fq_if_grps_bitmap_clr(fq_grp_tailq_t *grp_list, int pri, fq_if_state state)
{
    #pragma unused(pri)

	fq_if_group_t *grp;
	TAILQ_FOREACH(grp, grp_list, fqg_grp_link) {
		grp->fqg_bitmaps[state] = 0;
	}
}

static int
fq_if_grps_sc_bitmap_ffs(fq_grp_tailq_t *grp_list, int pri, fq_if_state state,
    fq_if_group_t **selected_grp)
{
	fq_if_group_t *grp;
	int ret_pri = 0;

	TAILQ_FOREACH(grp, grp_list, fqg_grp_link) {
		if (pktsched_bit_tst(pri, &grp->fqg_bitmaps[state])) {
			/* +1 to match the semantics of pktsched_ffs */
			ret_pri = pri + 1;
			*selected_grp = grp;
			break;
		}
	}

	return ret_pri;
}

static boolean_t
fq_if_grps_sc_bitmap_zeros(fq_grp_tailq_t *grp_list, int pri, fq_if_state state)
{
	fq_if_group_t *grp;

	TAILQ_FOREACH(grp, grp_list, fqg_grp_link) {
		if (pktsched_bit_tst(pri, &grp->fqg_bitmaps[state])) {
			return FALSE;
		}
	}
	return TRUE;
}

static void
fq_if_grps_sc_bitmap_cpy(fq_grp_tailq_t *grp_list, int pri, fq_if_state dst_state,
    fq_if_state src_state)
{
	fq_if_group_t *grp;

	TAILQ_FOREACH(grp, grp_list, fqg_grp_link) {
		pktsched_bit_cpy(pri, &grp->fqg_bitmaps[dst_state],
		    &grp->fqg_bitmaps[src_state]);
	}
}

static void
fq_if_grps_sc_bitmap_clr(fq_grp_tailq_t *grp_list, int pri, fq_if_state state)
{
	fq_if_group_t *grp;

	TAILQ_FOREACH(grp, grp_list, fqg_grp_link) {
		pktsched_bit_clr(pri, &grp->fqg_bitmaps[state]);
	}
}

static int
fq_if_dequeue_classq_multi_common(struct ifclassq *ifq, mbuf_svc_class_t svc,
    u_int32_t maxpktcnt, u_int32_t maxbytecnt, classq_pkt_t *first_packet,
    classq_pkt_t *last_packet, u_int32_t *retpktcnt, u_int32_t *retbytecnt,
    uint8_t grp_idx)
{
	uint32_t total_pktcnt = 0, total_bytecnt = 0;
	classq_pkt_t first = CLASSQ_PKT_INITIALIZER(fisrt);
	classq_pkt_t last = CLASSQ_PKT_INITIALIZER(last);
	classq_pkt_t tmp = CLASSQ_PKT_INITIALIZER(tmp);
	fq_if_append_pkt_t append_pkt;
	flowq_dqlist_t fq_dqlist_head;
	fq_if_classq_t *fq_cl;
	fq_grp_tailq_t *grp_list, tmp_grp_list;
	fq_if_group_t *fq_grp = NULL;
	fq_if_t *fqs;
	uint64_t now;
	int pri = 0, svc_pri = 0;

	IFCQ_LOCK_ASSERT_HELD(ifq);

	fqs = (fq_if_t *)ifq->ifcq_disc;
	STAILQ_INIT(&fq_dqlist_head);

	switch (fqs->fqs_ptype) {
	case QP_MBUF:
		append_pkt = fq_if_append_mbuf;
		break;

#if SKYWALK
	case QP_PACKET:
		append_pkt = fq_if_append_pkt;
		break;
#endif /* SKYWALK */

	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	now = fq_codel_get_time();
	if (fqs->fqs_flags & FQS_DRIVER_MANAGED) {
		svc_pri = fq_if_service_to_priority(fqs, svc);
	} else {
		VERIFY(svc == MBUF_SC_UNSPEC);
	}

	if (fq_if_is_grp_combined(fqs, grp_idx)) {
		grp_list = &fqs->fqs_combined_grp_list;
		VERIFY(!TAILQ_EMPTY(grp_list));
	} else {
		grp_list = &tmp_grp_list;
		fq_grp = fq_if_find_grp(fqs, grp_idx);
		TAILQ_INIT(grp_list);
		TAILQ_INSERT_TAIL(grp_list, fq_grp, fqg_grp_link);
	}

	for (;;) {
		uint32_t pktcnt = 0, bytecnt = 0;
		classq_pkt_t head = CLASSQ_PKT_INITIALIZER(head);
		classq_pkt_t tail = CLASSQ_PKT_INITIALIZER(tail);

		if (fqs->grp_bitmaps_zeros(grp_list, svc_pri, FQ_IF_ER) &&
		    fqs->grp_bitmaps_zeros(grp_list, svc_pri, FQ_IF_EB)) {
			fqs->grp_bitmaps_cpy(grp_list, svc_pri, FQ_IF_EB, FQ_IF_IB);
			fqs->grp_bitmaps_clr(grp_list, svc_pri, FQ_IF_IB);
			if (fqs->grp_bitmaps_zeros(grp_list, svc_pri, FQ_IF_EB)) {
				break;
			}
		}
		pri = fqs->grp_bitmaps_ffs(grp_list, svc_pri, FQ_IF_ER, &fq_grp);
		if (pri == 0) {
			/*
			 * There are no ER flows, move the highest
			 * priority one from EB if there are any in that
			 * category
			 */
			pri = fqs->grp_bitmaps_ffs(grp_list, svc_pri, FQ_IF_EB, &fq_grp);
			VERIFY(pri > 0);
			VERIFY(fq_grp != NULL);
			pktsched_bit_clr((pri - 1), &fq_grp->fqg_bitmaps[FQ_IF_EB]);
			pktsched_bit_set((pri - 1), &fq_grp->fqg_bitmaps[FQ_IF_ER]);
		}
		VERIFY(fq_grp != NULL);
		pri--; /* index starts at 0 */
		fq_cl = &fq_grp->fqg_classq[pri];

		if (fq_cl->fcl_budget <= 0) {
			/* Update the budget */
			fq_cl->fcl_budget += (min(fq_cl->fcl_drr_max,
			    fq_cl->fcl_stat.fcl_flows_cnt) *
			    fq_cl->fcl_quantum);
			if (fq_cl->fcl_budget <= 0) {
				goto state_change;
			}
		}
		fq_if_dequeue(fqs, fq_cl, (maxpktcnt - total_pktcnt),
		    (maxbytecnt - total_bytecnt), &head, &tail, &pktcnt,
		    &bytecnt, &fq_dqlist_head, true, now);
		if (head.cp_mbuf != NULL) {
			ASSERT(STAILQ_EMPTY(&fq_dqlist_head));
			if (first.cp_mbuf == NULL) {
				first = head;
			} else {
				ASSERT(last.cp_mbuf != NULL);
				append_pkt(&last, &head);
			}
			last = tail;
			append_pkt(&last, &tmp);
		}
		fq_cl->fcl_budget -= bytecnt;
		total_pktcnt += pktcnt;
		total_bytecnt += bytecnt;

		/*
		 * If the class has exceeded the budget but still has data
		 * to send, move it to IB
		 */
state_change:
		VERIFY(fq_grp != NULL);
		if (!FQ_IF_CLASSQ_IDLE(fq_cl)) {
			if (fq_cl->fcl_budget <= 0) {
				pktsched_bit_set(pri, &fq_grp->fqg_bitmaps[FQ_IF_IB]);
				pktsched_bit_clr(pri, &fq_grp->fqg_bitmaps[FQ_IF_ER]);
			}
		} else {
			pktsched_bit_clr(pri, &fq_grp->fqg_bitmaps[FQ_IF_ER]);
			VERIFY(((fq_grp->fqg_bitmaps[FQ_IF_ER] |
			    fq_grp->fqg_bitmaps[FQ_IF_EB] |
			    fq_grp->fqg_bitmaps[FQ_IF_IB]) & (1 << pri)) == 0);
			fq_cl->fcl_budget = 0;
		}
		if (total_pktcnt >= maxpktcnt || total_bytecnt >= maxbytecnt) {
			break;
		}
	}

	if (!fq_if_is_grp_combined(fqs, grp_idx)) {
		TAILQ_REMOVE(grp_list, fq_grp, fqg_grp_link);
		VERIFY(TAILQ_EMPTY(grp_list));
	}

	fq_dqlist_get_packet_list(&fq_dqlist_head, &first, &last,
	    fqs->fqs_ptype);

	if (__probable(first_packet != NULL)) {
		*first_packet = first;
	}
	if (last_packet != NULL) {
		*last_packet = last;
	}
	if (retpktcnt != NULL) {
		*retpktcnt = total_pktcnt;
	}
	if (retbytecnt != NULL) {
		*retbytecnt = total_bytecnt;
	}

	IFCQ_XMIT_ADD(ifq, total_pktcnt, total_bytecnt);
	fq_if_purge_empty_flow_list(fqs, now, false);
	return 0;
}

int
fq_if_dequeue_classq_multi(struct ifclassq *ifq, u_int32_t maxpktcnt,
    u_int32_t maxbytecnt, classq_pkt_t *first_packet,
    classq_pkt_t *last_packet, u_int32_t *retpktcnt,
    u_int32_t *retbytecnt, uint8_t grp_idx)
{
	return fq_if_dequeue_classq_multi_common(ifq, MBUF_SC_UNSPEC, maxpktcnt, maxbytecnt,
	           first_packet, last_packet, retpktcnt, retbytecnt, grp_idx);
}

int
fq_if_dequeue_sc_classq_multi(struct ifclassq *ifq, mbuf_svc_class_t svc,
    u_int32_t maxpktcnt, u_int32_t maxbytecnt, classq_pkt_t *first_packet,
    classq_pkt_t *last_packet, u_int32_t *retpktcnt, u_int32_t *retbytecnt,
    uint8_t grp_idx)
{
	fq_if_t *fqs = (fq_if_t *)ifq->ifcq_disc;

	if (fq_if_is_grp_combined(fqs, grp_idx)) {
		return fq_if_dequeue_classq_multi_common(ifq, svc, maxpktcnt, maxbytecnt,
		           first_packet, last_packet, retpktcnt, retbytecnt, grp_idx);
	} else {
		/*
		 * take a shortcut here since there is no need to schedule
		 * one single service class.
		 */
		return fq_if_dequeue_sc_classq_multi_separate(ifq, svc, maxpktcnt, maxbytecnt,
		           first_packet, last_packet, retpktcnt, retbytecnt, grp_idx);
	}
}

static int
fq_if_dequeue_sc_classq_multi_separate(struct ifclassq *ifq, mbuf_svc_class_t svc,
    u_int32_t maxpktcnt, u_int32_t maxbytecnt, classq_pkt_t *first_packet,
    classq_pkt_t *last_packet, u_int32_t *retpktcnt, u_int32_t *retbytecnt,
    uint8_t grp_idx)
{
	fq_if_t *fqs = (fq_if_t *)ifq->ifcq_disc;
	uint8_t pri;
	u_int32_t total_pktcnt = 0, total_bytecnt = 0;
	fq_if_classq_t *fq_cl;
	classq_pkt_t first = CLASSQ_PKT_INITIALIZER(fisrt);
	classq_pkt_t last = CLASSQ_PKT_INITIALIZER(last);
	fq_if_append_pkt_t append_pkt;
	flowq_dqlist_t fq_dqlist_head;
	fq_if_group_t *fq_grp;
	uint64_t now;

	switch (fqs->fqs_ptype) {
	case QP_MBUF:
		append_pkt = fq_if_append_mbuf;
		break;

#if SKYWALK
	case QP_PACKET:
		append_pkt = fq_if_append_pkt;
		break;
#endif /* SKYWALK */

	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	STAILQ_INIT(&fq_dqlist_head);
	now = fq_codel_get_time();

	pri = fq_if_service_to_priority(fqs, svc);
	fq_grp = fq_if_find_grp(fqs, grp_idx);
	fq_cl = &fq_grp->fqg_classq[pri];

	/*
	 * Now we have the queue for a particular service class. We need
	 * to dequeue as many packets as needed, first from the new flows
	 * and then from the old flows.
	 */
	while (total_pktcnt < maxpktcnt && total_bytecnt < maxbytecnt &&
	    fq_cl->fcl_stat.fcl_pkt_cnt > 0) {
		classq_pkt_t head = CLASSQ_PKT_INITIALIZER(head);
		classq_pkt_t tail = CLASSQ_PKT_INITIALIZER(tail);
		u_int32_t pktcnt = 0, bytecnt = 0;

		fq_if_dequeue(fqs, fq_cl, (maxpktcnt - total_pktcnt),
		    (maxbytecnt - total_bytecnt), &head, &tail, &pktcnt,
		    &bytecnt, &fq_dqlist_head, false, now);
		if (head.cp_mbuf != NULL) {
			if (first.cp_mbuf == NULL) {
				first = head;
			} else {
				ASSERT(last.cp_mbuf != NULL);
				append_pkt(&last, &head);
			}
			last = tail;
		}
		total_pktcnt += pktcnt;
		total_bytecnt += bytecnt;
	}

	/*
	 * Mark classq as IB if it's not idle, so that we can
	 * start without re-init the bitmaps when it's switched
	 * to combined mode.
	 */
	if (!FQ_IF_CLASSQ_IDLE(fq_cl)) {
		pktsched_bit_set(pri, &fq_grp->fqg_bitmaps[FQ_IF_IB]);
		pktsched_bit_clr(pri, &fq_grp->fqg_bitmaps[FQ_IF_ER]);
		pktsched_bit_clr(pri, &fq_grp->fqg_bitmaps[FQ_IF_EB]);
	} else {
		pktsched_bit_clr(pri, &fq_grp->fqg_bitmaps[FQ_IF_IB]);
		VERIFY(((fq_grp->fqg_bitmaps[FQ_IF_ER] |
		    fq_grp->fqg_bitmaps[FQ_IF_EB] |
		    fq_grp->fqg_bitmaps[FQ_IF_IB]) & (1 << pri)) == 0);
	}

	fq_dqlist_get_packet_list(&fq_dqlist_head, &first, &last, fqs->fqs_ptype);

	if (__probable(first_packet != NULL)) {
		*first_packet = first;
	}
	if (last_packet != NULL) {
		*last_packet = last;
	}
	if (retpktcnt != NULL) {
		*retpktcnt = total_pktcnt;
	}
	if (retbytecnt != NULL) {
		*retbytecnt = total_bytecnt;
	}

	IFCQ_XMIT_ADD(ifq, total_pktcnt, total_bytecnt);
	fq_if_purge_empty_flow_list(fqs, now, false);
	return 0;
}

static void
fq_if_purge_flow(fq_if_t *fqs, fq_t *fq, uint32_t *pktsp,
    uint32_t *bytesp, uint64_t now)
{
	fq_if_classq_t *fq_cl;
	u_int32_t pkts, bytes;
	pktsched_pkt_t pkt;
	fq_if_group_t *grp;

	fq_cl = &FQ_CLASSQ(fq);
	grp = FQ_GROUP(fq);
	pkts = bytes = 0;
	_PKTSCHED_PKT_INIT(&pkt);
	for (;;) {
		fq_getq_flow(fqs, fq, &pkt, now);
		if (pkt.pktsched_pkt_mbuf == NULL) {
			VERIFY(pkt.pktsched_ptype == QP_INVALID);
			break;
		}
		pkts++;
		bytes += pktsched_get_pkt_len(&pkt);
		pktsched_free_pkt(&pkt);
	}
	KDBG(AQM_KTRACE_STATS_FLOW_DEQUEUE, fq->fq_flowhash,
	    AQM_KTRACE_FQ_GRP_SC_IDX(fq), fq->fq_bytes, fq->fq_min_qdelay);

	IFCQ_DROP_ADD(fqs->fqs_ifq, pkts, bytes);

	/* move through the flow queue states */
	VERIFY((fq->fq_flags & (FQF_NEW_FLOW | FQF_OLD_FLOW | FQF_EMPTY_FLOW)));
	if (fq->fq_flags & FQF_NEW_FLOW) {
		fq_if_empty_new_flow(fq, fq_cl);
	}
	if (fq->fq_flags & FQF_OLD_FLOW) {
		fq_if_empty_old_flow(fqs, fq_cl, fq, now);
	}
	if (fq->fq_flags & FQF_EMPTY_FLOW) {
		fq_if_purge_empty_flow(fqs, fq);
		fq = NULL;
	}

	if (FQ_IF_CLASSQ_IDLE(fq_cl)) {
		int i;
		for (i = FQ_IF_ER; i < FQ_IF_MAX_STATE; i++) {
			pktsched_bit_clr(fq_cl->fcl_pri, &grp->fqg_bitmaps[i]);
		}
	}

	if (pktsp != NULL) {
		*pktsp = pkts;
	}
	if (bytesp != NULL) {
		*bytesp = bytes;
	}
}

static void
fq_if_purge_classq(fq_if_t *fqs, fq_if_classq_t *fq_cl)
{
	fq_t *fq, *tfq;
	uint64_t now;

	now = fq_codel_get_time();
	/*
	 * Take each flow from new/old flow list and flush mbufs
	 * in that flow
	 */
	STAILQ_FOREACH_SAFE(fq, &fq_cl->fcl_new_flows, fq_actlink, tfq) {
		fq_if_purge_flow(fqs, fq, NULL, NULL, now);
	}
	STAILQ_FOREACH_SAFE(fq, &fq_cl->fcl_old_flows, fq_actlink, tfq) {
		fq_if_purge_flow(fqs, fq, NULL, NULL, now);
	}
	VERIFY(STAILQ_EMPTY(&fq_cl->fcl_new_flows));
	VERIFY(STAILQ_EMPTY(&fq_cl->fcl_old_flows));

	STAILQ_INIT(&fq_cl->fcl_new_flows);
	STAILQ_INIT(&fq_cl->fcl_old_flows);
	fq_cl->fcl_budget = 0;
}

static void
fq_if_purge(fq_if_t *fqs)
{
	uint64_t now;
	fq_if_group_t *grp;
	int i;

	IFCQ_CONVERT_LOCK(fqs->fqs_ifq);
	for (uint8_t grp_idx = 0; grp_idx < FQ_IF_MAX_GROUPS; grp_idx++) {
		if (fqs->fqs_classq_groups[grp_idx] == NULL) {
			continue;
		}

		grp = fq_if_find_grp(fqs, grp_idx);
		fq_if_purge_grp(fqs, grp);
	}

	now = fq_codel_get_time();
	fq_if_purge_empty_flow_list(fqs, now, true);

	VERIFY(STAILQ_EMPTY(&fqs->fqs_fclist));
	VERIFY(TAILQ_EMPTY(&fqs->fqs_empty_list));

	fqs->fqs_large_flow = NULL;
	for (i = 0; i < FQ_IF_HASH_TABLE_SIZE; i++) {
		VERIFY(SLIST_EMPTY(&fqs->fqs_flows[i]));
	}

	IFCQ_LEN(fqs->fqs_ifq) = 0;
	IFCQ_BYTES(fqs->fqs_ifq) = 0;
}

static void
fq_if_purge_sc(fq_if_t *fqs, cqrq_purge_sc_t *req)
{
	fq_t *fq;
	uint64_t now;
	fq_if_group_t *grp;

	IFCQ_LOCK_ASSERT_HELD(fqs->fqs_ifq);
	req->packets = req->bytes = 0;
	VERIFY(req->flow != 0);

	now = fq_codel_get_time();

	for (uint8_t grp_idx = 0; grp_idx < FQ_IF_MAX_GROUPS; grp_idx++) {
		if (fqs->fqs_classq_groups[grp_idx] == NULL) {
			continue;
		}
		uint32_t bytes = 0, pkts = 0;

		grp = fq_if_find_grp(fqs, grp_idx);
		/*
		 * Packet and traffic type are needed only if we want
		 * to create a flow queue.
		 */
		fq = fq_if_hash_pkt(fqs, grp, req->flow, req->sc, 0, false, FQ_TFC_C);
		if (fq != NULL) {
			fq_if_purge_flow(fqs, fq, &pkts, &bytes, now);
			req->bytes += bytes;
			req->packets += pkts;
		}
	}
}

static uint16_t
fq_if_calc_quantum(struct ifnet *ifp)
{
	uint16_t quantum;

	switch (ifp->if_family) {
	case IFNET_FAMILY_ETHERNET:
		VERIFY((ifp->if_mtu + ETHER_HDR_LEN) <= UINT16_MAX);
		quantum = (uint16_t)ifp->if_mtu + ETHER_HDR_LEN;
		break;

	case IFNET_FAMILY_CELLULAR:
	case IFNET_FAMILY_IPSEC:
	case IFNET_FAMILY_UTUN:
		VERIFY(ifp->if_mtu <= UINT16_MAX);
		quantum = (uint16_t)ifp->if_mtu;
		break;

	default:
		quantum = FQ_CODEL_DEFAULT_QUANTUM;
		break;
	}

	if ((ifp->if_hwassist & IFNET_TSOF) != 0) {
		VERIFY(ifp->if_tso_v4_mtu <= UINT16_MAX);
		VERIFY(ifp->if_tso_v6_mtu <= UINT16_MAX);
		quantum = (uint16_t)MAX(ifp->if_tso_v4_mtu, ifp->if_tso_v6_mtu);
		quantum = (quantum != 0) ? quantum : IF_MAXMTU;
	}

	quantum = MAX(FQ_CODEL_DEFAULT_QUANTUM, quantum);
#if DEBUG || DEVELOPMENT
	quantum = (fq_codel_quantum != 0) ? fq_codel_quantum : quantum;
#endif /* DEBUG || DEVELOPMENT */
	VERIFY(quantum != 0);
	return quantum;
}

static void
fq_if_mtu_update(fq_if_t *fqs)
{
#define _FQ_CLASSQ_UPDATE_QUANTUM(_grp, _s, _q)                     \
	(_grp)->fqg_classq[FQ_IF_ ## _s ## _INDEX].fcl_quantum =        \
	    FQ_CODEL_QUANTUM_ ## _s(_q)                                 \

	uint32_t quantum;
	fq_if_group_t *grp;

	quantum = fq_if_calc_quantum(fqs->fqs_ifq->ifcq_ifp);

	for (uint8_t grp_idx = 0; grp_idx < FQ_IF_MAX_GROUPS; grp_idx++) {
		if (fqs->fqs_classq_groups[grp_idx] == NULL) {
			continue;
		}

		grp = fq_if_find_grp(fqs, grp_idx);

		if ((fqs->fqs_flags & FQS_DRIVER_MANAGED) != 0) {
			_FQ_CLASSQ_UPDATE_QUANTUM(grp, BK, quantum);
			_FQ_CLASSQ_UPDATE_QUANTUM(grp, BE, quantum);
			_FQ_CLASSQ_UPDATE_QUANTUM(grp, VI, quantum);
			_FQ_CLASSQ_UPDATE_QUANTUM(grp, VO, quantum);
		} else {
			_FQ_CLASSQ_UPDATE_QUANTUM(grp, BK_SYS, quantum);
			_FQ_CLASSQ_UPDATE_QUANTUM(grp, BK, quantum);
			_FQ_CLASSQ_UPDATE_QUANTUM(grp, BE, quantum);
			_FQ_CLASSQ_UPDATE_QUANTUM(grp, RD, quantum);
			_FQ_CLASSQ_UPDATE_QUANTUM(grp, OAM, quantum);
			_FQ_CLASSQ_UPDATE_QUANTUM(grp, AV, quantum);
			_FQ_CLASSQ_UPDATE_QUANTUM(grp, RV, quantum);
			_FQ_CLASSQ_UPDATE_QUANTUM(grp, VI, quantum);
			_FQ_CLASSQ_UPDATE_QUANTUM(grp, VO, quantum);
			_FQ_CLASSQ_UPDATE_QUANTUM(grp, CTL, quantum);
		}
	}
#undef _FQ_CLASSQ_UPDATE_QUANTUM
}

static void
fq_if_event(fq_if_t *fqs, cqev_t ev)
{
	IFCQ_LOCK_ASSERT_HELD(fqs->fqs_ifq);

	switch (ev) {
	case CLASSQ_EV_LINK_UP:
	case CLASSQ_EV_LINK_DOWN:
		fq_if_purge(fqs);
		break;
	case CLASSQ_EV_LINK_MTU:
		fq_if_mtu_update(fqs);
		break;
	default:
		break;
	}
}

static void
fq_if_classq_suspend(fq_if_t *fqs, fq_if_classq_t *fq_cl)
{
	fq_if_purge_classq(fqs, fq_cl);
	fqs->fqs_throttle = 1;
	fq_cl->fcl_stat.fcl_throttle_on++;
	KDBG(AQM_KTRACE_AON_THROTTLE | DBG_FUNC_START,
	    fqs->fqs_ifq->ifcq_ifp->if_index, 0, 0, 0);
}

static void
fq_if_classq_resume(fq_if_t *fqs, fq_if_classq_t *fq_cl)
{
	VERIFY(FQ_IF_CLASSQ_IDLE(fq_cl));
	fqs->fqs_throttle = 0;
	fq_cl->fcl_stat.fcl_throttle_off++;
	KDBG(AQM_KTRACE_AON_THROTTLE | DBG_FUNC_END,
	    fqs->fqs_ifq->ifcq_ifp->if_index, 0, 0, 0);
}


static int
fq_if_throttle(fq_if_t *fqs, cqrq_throttle_t *tr)
{
	struct ifclassq *ifq = fqs->fqs_ifq;
	uint8_t index;
	fq_if_group_t *grp;

#if !MACH_ASSERT
#pragma unused(ifq)
#endif
	IFCQ_LOCK_ASSERT_HELD(ifq);

	if (!tr->set) {
		tr->level = fqs->fqs_throttle;
		return 0;
	}

	if (tr->level == fqs->fqs_throttle) {
		return EALREADY;
	}

	/* Throttling is allowed on BK_SYS class only */
	index = fq_if_service_to_priority(fqs, MBUF_SC_BK_SYS);

	for (uint8_t grp_idx = 0; grp_idx < FQ_IF_MAX_GROUPS; grp_idx++) {
		if (fqs->fqs_classq_groups[grp_idx] == NULL) {
			continue;
		}
		grp = fq_if_find_grp(fqs, grp_idx);
		switch (tr->level) {
		case IFNET_THROTTLE_OFF:
			fq_if_classq_resume(fqs, &grp->fqg_classq[index]);
			break;
		case IFNET_THROTTLE_OPPORTUNISTIC:
			fq_if_classq_suspend(fqs, &grp->fqg_classq[index]);
			break;
		default:
			break;
		}
	}
	return 0;
}

static void
fq_if_grp_stat_sc(fq_if_t *fqs, fq_if_group_t *grp, cqrq_stat_sc_t *stat)
{
	uint8_t pri;
	fq_if_classq_t *fq_cl;

	if (stat == NULL) {
		return;
	}

	pri = fq_if_service_to_priority(fqs, stat->sc);

	fq_cl = &grp->fqg_classq[pri];
	stat->packets = (uint32_t)fq_cl->fcl_stat.fcl_pkt_cnt;
	stat->bytes = (uint32_t)fq_cl->fcl_stat.fcl_byte_cnt;
}

void
fq_if_stat_sc(fq_if_t *fqs, cqrq_stat_sc_t *stat)
{
	cqrq_stat_sc_t grp_sc_stat;
	fq_if_group_t *grp;

	if (stat == NULL) {
		return;
	}
	grp_sc_stat.sc = stat->sc;

	if (stat->grp_idx == IF_CLASSQ_ALL_GRPS) {
		if (stat->sc == MBUF_SC_UNSPEC) {
			stat->packets = IFCQ_LEN(fqs->fqs_ifq);
			stat->bytes = IFCQ_BYTES(fqs->fqs_ifq);
		} else {
			for (uint8_t grp_idx = 0; grp_idx < FQ_IF_MAX_GROUPS; grp_idx++) {
				grp = fqs->fqs_classq_groups[grp_idx];
				if (grp == NULL) {
					continue;
				}

				fq_if_grp_stat_sc(fqs, grp, &grp_sc_stat);
				stat->packets += grp_sc_stat.packets;
				stat->bytes += grp_sc_stat.bytes;
			}
		}
		return;
	}

	if (stat->sc == MBUF_SC_UNSPEC) {
		if (fq_if_is_grp_combined(fqs, stat->grp_idx)) {
			TAILQ_FOREACH(grp, &fqs->fqs_combined_grp_list, fqg_grp_link) {
				stat->packets += FQG_LEN(grp);
				stat->bytes += FQG_BYTES(grp);
			}
		} else {
			grp = fq_if_find_grp(fqs, stat->grp_idx);
			stat->packets = FQG_LEN(grp);
			stat->bytes = FQG_BYTES(grp);
		}
	} else {
		if (fq_if_is_grp_combined(fqs, stat->grp_idx)) {
			TAILQ_FOREACH(grp, &fqs->fqs_combined_grp_list, fqg_grp_link) {
				fq_if_grp_stat_sc(fqs, grp, &grp_sc_stat);
				stat->packets += grp_sc_stat.packets;
				stat->bytes += grp_sc_stat.bytes;
			}
		} else {
			grp = fq_if_find_grp(fqs, stat->grp_idx);
			fq_if_grp_stat_sc(fqs, grp, stat);
		}
	}
}

int
fq_if_request_classq(struct ifclassq *ifq, cqrq_t rq, void *arg)
{
	int err = 0;
	fq_if_t *fqs = (fq_if_t *)ifq->ifcq_disc;

	IFCQ_LOCK_ASSERT_HELD(ifq);

	/*
	 * These are usually slow operations, convert the lock ahead of time
	 */
	IFCQ_CONVERT_LOCK(fqs->fqs_ifq);
	switch (rq) {
	case CLASSQRQ_PURGE:
		fq_if_purge(fqs);
		break;
	case CLASSQRQ_PURGE_SC:
		fq_if_purge_sc(fqs, (cqrq_purge_sc_t *)arg);
		break;
	case CLASSQRQ_EVENT:
		fq_if_event(fqs, (cqev_t)arg);
		break;
	case CLASSQRQ_THROTTLE:
		fq_if_throttle(fqs, (cqrq_throttle_t *)arg);
		break;
	case CLASSQRQ_STAT_SC:
		fq_if_stat_sc(fqs, (cqrq_stat_sc_t *)arg);
		break;
	}
	return err;
}

int
fq_if_setup_ifclassq(struct ifclassq *ifq, u_int32_t flags,
    classq_pkt_type_t ptype)
{
	fq_if_t *fqs = NULL;
	int err = 0;

	IFCQ_LOCK_ASSERT_HELD(ifq);
	VERIFY(ifq->ifcq_disc == NULL);
	VERIFY(ifq->ifcq_type == PKTSCHEDT_NONE);

	fqs = fq_if_alloc(ifq, ptype);
	if (fqs == NULL) {
		return ENOMEM;
	}
	if (flags & PKTSCHEDF_QALG_DRIVER_MANAGED) {
		fqs->fqs_flags |= FQS_DRIVER_MANAGED;
		fqs->fqs_bm_ops = &fq_if_grps_sc_bitmap_ops;
	} else {
		fqs->fqs_bm_ops = &fq_if_grps_bitmap_ops;
	}

	err = ifclassq_attach(ifq, PKTSCHEDT_FQ_CODEL, fqs);
	if (err != 0) {
		os_log_error(OS_LOG_DEFAULT, "%s: error from ifclassq_attach, "
		    "failed to attach fq_if: %d\n", __func__, err);
		fq_if_destroy(fqs);
		return err;
	}

	/*
	 * Always create one group. If qset 0 is added later,
	 * this group will be updated.
	 */
	err = fq_if_create_grp(ifq, 0, IF_CLASSQ_DEF);
	if (err != 0) {
		os_log_error(OS_LOG_DEFAULT, "%s: error from fq_if_create_grp, "
		    "failed to create a fq group: %d\n", __func__, err);
		fq_if_destroy(fqs);
	}
	return err;
}

fq_t *
fq_if_hash_pkt(fq_if_t *fqs, fq_if_group_t *fq_grp, u_int32_t flowid,
    mbuf_svc_class_t svc_class, u_int64_t now, bool create,
    fq_tfc_type_t tfc_type)
{
	fq_t *fq = NULL;
	flowq_list_t *fq_list;
	fq_if_classq_t *fq_cl;
	u_int8_t fqs_hash_id;
	u_int8_t scidx;

	scidx = fq_if_service_to_priority(fqs, svc_class);

	fqs_hash_id = FQ_IF_FLOW_HASH_ID(flowid);

	fq_list = &fqs->fqs_flows[fqs_hash_id];

	SLIST_FOREACH(fq, fq_list, fq_hashlink) {
		if (fq->fq_flowhash == flowid &&
		    fq->fq_sc_index == scidx &&
		    fq->fq_tfc_type == tfc_type &&
		    fq->fq_group == fq_grp) {
			break;
		}
	}
	if (fq == NULL && create) {
		/* If the flow is not already on the list, allocate it */
		IFCQ_CONVERT_LOCK(fqs->fqs_ifq);
		fq = fq_alloc(fqs->fqs_ptype);
		if (fq != NULL) {
			fq->fq_flowhash = flowid;
			fq->fq_sc_index = scidx;
			fq->fq_group = fq_grp;
			fq->fq_tfc_type = tfc_type;
			fq_cl = &FQ_CLASSQ(fq);
			fq->fq_flags = FQF_FLOWCTL_CAPABLE;
			fq->fq_updatetime = now + FQ_UPDATE_INTERVAL(fq);
			SLIST_INSERT_HEAD(fq_list, fq, fq_hashlink);
			fq_cl->fcl_stat.fcl_flows_cnt++;
		}
		KDBG(AQM_KTRACE_STATS_FLOW_ALLOC,
		    fqs->fqs_ifq->ifcq_ifp->if_index, fq->fq_flowhash,
		    AQM_KTRACE_FQ_GRP_SC_IDX(fq), 0);
	} else if ((fq != NULL) && (fq->fq_flags & FQF_EMPTY_FLOW)) {
		fq_if_reuse_empty_flow(fqs, fq, now);
	}

	/*
	 * If getq time is not set because this is the first packet or after
	 * idle time, set it now so that we can detect a stall.
	 */
	if (fq != NULL && fq->fq_getqtime == 0) {
		fq->fq_getqtime = now;
	}

	return fq;
}

void
fq_if_destroy_flow(fq_if_t *fqs, fq_if_classq_t *fq_cl, fq_t *fq)
{
	u_int8_t hash_id;

	ASSERT((fq->fq_flags & FQF_EMPTY_FLOW) == 0);
	hash_id = FQ_IF_FLOW_HASH_ID(fq->fq_flowhash);
	SLIST_REMOVE(&fqs->fqs_flows[hash_id], fq, flowq,
	    fq_hashlink);
	IFCQ_CONVERT_LOCK(fqs->fqs_ifq);
	if (__improbable(fq->fq_flags & FQF_FLOWCTL_ON)) {
		fq_if_flow_feedback(fqs, fq, fq_cl);
	}
	KDBG(AQM_KTRACE_STATS_FLOW_DESTROY,
	    fqs->fqs_ifq->ifcq_ifp->if_index, fq->fq_flowhash,
	    AQM_KTRACE_FQ_GRP_SC_IDX(fq), 0);
	fq_destroy(fq, fqs->fqs_ptype);
}

inline boolean_t
fq_if_at_drop_limit(fq_if_t *fqs)
{
	return (IFCQ_LEN(fqs->fqs_ifq) >= fqs->fqs_pkt_droplimit) ?
	       TRUE : FALSE;
}

inline boolean_t
fq_if_almost_at_drop_limit(fq_if_t *fqs)
{
	/*
	 * Whether we are above 90% of the queue limit. This is used to tell if we
	 * can stop flow controlling the largest flow.
	 */
	return IFCQ_LEN(fqs->fqs_ifq) >= fqs->fqs_pkt_droplimit * 9 / 10;
}

static inline void
fq_if_reuse_empty_flow(fq_if_t *fqs, fq_t *fq, uint64_t now)
{
	ASSERT(fq->fq_flags & FQF_EMPTY_FLOW);
	TAILQ_REMOVE(&fqs->fqs_empty_list, fq, fq_empty_link);
	STAILQ_NEXT(fq, fq_actlink) = NULL;
	fq->fq_flags &= ~FQF_FLOW_STATE_MASK;
	fq->fq_empty_purge_time = 0;
	fq->fq_getqtime = 0;
	fq->fq_updatetime = now + FQ_UPDATE_INTERVAL(fq);
	fqs->fqs_empty_list_cnt--;
	fq_if_classq_t *fq_cl = &FQ_CLASSQ(fq);
	fq_cl->fcl_stat.fcl_flows_cnt++;
}

inline void
fq_if_move_to_empty_flow(fq_if_t *fqs, fq_if_classq_t *fq_cl, fq_t *fq,
    uint64_t now)
{
	ASSERT(fq->fq_flags & ~(FQF_NEW_FLOW | FQF_OLD_FLOW | FQF_FLOWCTL_ON));
	fq->fq_empty_purge_time = now + fq_empty_purge_delay;
	TAILQ_INSERT_TAIL(&fqs->fqs_empty_list, fq, fq_empty_link);
	fq->fq_flags |= FQF_EMPTY_FLOW;
	FQ_CLEAR_OVERWHELMING(fq);
	fqs->fqs_empty_list_cnt++;
	/*
	 * fcl_flows_cnt is used in budget determination for the class.
	 * empty flow shouldn't contribute to the budget.
	 */
	fq_cl->fcl_stat.fcl_flows_cnt--;
}

static void
fq_if_purge_empty_flow(fq_if_t *fqs, fq_t *fq)
{
	fq_if_classq_t *fq_cl;
	fq_cl = &FQ_CLASSQ(fq);

	ASSERT((fq->fq_flags & FQF_EMPTY_FLOW) != 0);
	TAILQ_REMOVE(&fqs->fqs_empty_list, fq, fq_empty_link);
	fq->fq_flags &= ~FQF_EMPTY_FLOW;
	fqs->fqs_empty_list_cnt--;
	/* Remove from the hash list and free the flow queue */
	fq_if_destroy_flow(fqs, fq_cl, fq);
}

static void
fq_if_purge_empty_flow_list(fq_if_t *fqs, uint64_t now, bool purge_all)
{
	fq_t *fq, *tmp;
	int i = 0;

	if (fqs->fqs_empty_list_cnt == 0) {
		ASSERT(TAILQ_EMPTY(&fqs->fqs_empty_list));
		return;
	}

	TAILQ_FOREACH_SAFE(fq, &fqs->fqs_empty_list, fq_empty_link, tmp) {
		if (!purge_all && ((now < fq->fq_empty_purge_time) ||
		    (i++ == FQ_EMPTY_PURGE_MAX))) {
			break;
		}
		fq_if_purge_empty_flow(fqs, fq);
	}

	if (__improbable(purge_all)) {
		VERIFY(fqs->fqs_empty_list_cnt == 0);
		VERIFY(TAILQ_EMPTY(&fqs->fqs_empty_list));
	}
}

static void
fq_if_empty_old_flow(fq_if_t *fqs, fq_if_classq_t *fq_cl, fq_t *fq,
    uint64_t now)
{
	/*
	 * Remove the flow queue from the old flows list.
	 */
	STAILQ_REMOVE(&fq_cl->fcl_old_flows, fq, flowq, fq_actlink);
	fq->fq_flags &= ~FQF_OLD_FLOW;
	fq_cl->fcl_stat.fcl_oldflows_cnt--;
	VERIFY(fq->fq_bytes == 0);

	/* release any flow control */
	if (__improbable(fq->fq_flags & FQF_FLOWCTL_ON)) {
		fq_if_flow_feedback(fqs, fq, fq_cl);
	}

	/* move the flow queue to empty flows list */
	fq_if_move_to_empty_flow(fqs, fq_cl, fq, now);
}

static void
fq_if_empty_new_flow(fq_t *fq, fq_if_classq_t *fq_cl)
{
	/* Move to the end of old queue list */
	STAILQ_REMOVE(&fq_cl->fcl_new_flows, fq,
	    flowq, fq_actlink);
	fq->fq_flags &= ~FQF_NEW_FLOW;
	fq_cl->fcl_stat.fcl_newflows_cnt--;

	STAILQ_INSERT_TAIL(&fq_cl->fcl_old_flows, fq, fq_actlink);
	fq->fq_flags |= FQF_OLD_FLOW;
	fq_cl->fcl_stat.fcl_oldflows_cnt++;
}

inline void
fq_if_drop_packet(fq_if_t *fqs, uint64_t now)
{
	fq_t *fq = fqs->fqs_large_flow;
	fq_if_classq_t *fq_cl;
	pktsched_pkt_t pkt;
	volatile uint32_t *pkt_flags;
	uint64_t *pkt_timestamp;

	if (fq == NULL) {
		return;
	}
	/* queue can not be empty on the largest flow */
	VERIFY(!fq_empty(fq, fqs->fqs_ptype));

	fq_cl = &FQ_CLASSQ(fq);
	_PKTSCHED_PKT_INIT(&pkt);
	fq_getq_flow_internal(fqs, fq, &pkt);
	ASSERT(pkt.pktsched_ptype != QP_INVALID);

	pktsched_get_pkt_vars(&pkt, &pkt_flags, &pkt_timestamp, NULL, NULL,
	    NULL, NULL);

	IFCQ_CONVERT_LOCK(fqs->fqs_ifq);
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

	if (fq_empty(fq, fqs->fqs_ptype)) {
		fqs->fqs_large_flow = NULL;
		if (fq->fq_flags & FQF_OLD_FLOW) {
			fq_if_empty_old_flow(fqs, fq_cl, fq, now);
		} else {
			VERIFY(fq->fq_flags & FQF_NEW_FLOW);
			fq_if_empty_new_flow(fq, fq_cl);
		}
	}
	IFCQ_DROP_ADD(fqs->fqs_ifq, 1, pktsched_get_pkt_len(&pkt));

	pktsched_free_pkt(&pkt);
	fq_cl->fcl_stat.fcl_drop_overflow++;
}

inline void
fq_if_is_flow_heavy(fq_if_t *fqs, fq_t *fq)
{
	fq_t *prev_fq;

	if (fqs->fqs_large_flow != NULL &&
	    fqs->fqs_large_flow->fq_bytes < FQ_IF_LARGE_FLOW_BYTE_LIMIT) {
		fqs->fqs_large_flow = NULL;
	}

	if (fq == NULL || fq->fq_bytes < FQ_IF_LARGE_FLOW_BYTE_LIMIT) {
		return;
	}

	prev_fq = fqs->fqs_large_flow;
	if (prev_fq == NULL) {
		if (!fq_empty(fq, fqs->fqs_ptype)) {
			fqs->fqs_large_flow = fq;
		}
		return;
	} else if (fq->fq_bytes > prev_fq->fq_bytes) {
		fqs->fqs_large_flow = fq;
	}
}

boolean_t
fq_if_add_fcentry(fq_if_t *fqs, pktsched_pkt_t *pkt, uint8_t flowsrc,
    fq_t *fq, fq_if_classq_t *fq_cl)
{
	struct flowadv_fcentry *fce;

#if DEBUG || DEVELOPMENT
	if (__improbable(ifclassq_flow_control_adv == 0)) {
		os_log(OS_LOG_DEFAULT, "%s: skipped flow control", __func__);
		return TRUE;
	}
#endif /* DEBUG || DEVELOPMENT */

	ASSERT(fq->fq_tfc_type != FQ_TFC_L4S);
	STAILQ_FOREACH(fce, &fqs->fqs_fclist, fce_link) {
		if ((uint8_t)fce->fce_flowsrc_type == flowsrc &&
		    fce->fce_flowid == fq->fq_flowhash) {
			/* Already on flowcontrol list */
			return TRUE;
		}
	}
	IFCQ_CONVERT_LOCK(fqs->fqs_ifq);
	fce = pktsched_alloc_fcentry(pkt, fqs->fqs_ifq->ifcq_ifp, M_WAITOK);
	if (fce != NULL) {
		/* XXX Add number of bytes in the queue */
		STAILQ_INSERT_TAIL(&fqs->fqs_fclist, fce, fce_link);
		fq_cl->fcl_stat.fcl_flow_control++;
		os_log(OS_LOG_DEFAULT, "%s: num: %d, scidx: %d, flowsrc: %d, "
		    "flow: 0x%x, iface: %s\n", __func__,
		    fq_cl->fcl_stat.fcl_flow_control,
		    fq->fq_sc_index, fce->fce_flowsrc_type, fq->fq_flowhash,
		    if_name(fqs->fqs_ifq->ifcq_ifp));
		KDBG(AQM_KTRACE_STATS_FLOW_CTL | DBG_FUNC_START,
		    fq->fq_flowhash, AQM_KTRACE_FQ_GRP_SC_IDX(fq),
		    fq->fq_bytes, fq->fq_min_qdelay);
	}
	return (fce != NULL) ? TRUE : FALSE;
}

static void
fq_if_remove_fcentry(fq_if_t *fqs, struct flowadv_fcentry *fce)
{
	STAILQ_REMOVE(&fqs->fqs_fclist, fce, flowadv_fcentry, fce_link);
	STAILQ_NEXT(fce, fce_link) = NULL;
	flowadv_add_entry(fce);
}

void
fq_if_flow_feedback(fq_if_t *fqs, fq_t *fq, fq_if_classq_t *fq_cl)
{
	struct flowadv_fcentry *fce = NULL;

	if (fq->fq_tfc_type == FQ_TFC_L4S) {
		return;
	}

	IFCQ_CONVERT_LOCK(fqs->fqs_ifq);
	STAILQ_FOREACH(fce, &fqs->fqs_fclist, fce_link) {
		if (fce->fce_flowid == fq->fq_flowhash) {
			break;
		}
	}
	if (fce != NULL) {
		fq_cl->fcl_stat.fcl_flow_feedback++;
		os_log(OS_LOG_DEFAULT, "%s: num: %d, scidx: %d, flowsrc: %d, "
		    "flow: 0x%x, iface: %s\n", __func__,
		    fq_cl->fcl_stat.fcl_flow_feedback, fq->fq_sc_index,
		    fce->fce_flowsrc_type, fce->fce_flowid,
		    if_name(fqs->fqs_ifq->ifcq_ifp));
		fq_if_remove_fcentry(fqs, fce);
		KDBG(AQM_KTRACE_STATS_FLOW_CTL | DBG_FUNC_END,
		    fq->fq_flowhash, AQM_KTRACE_FQ_GRP_SC_IDX(fq),
		    fq->fq_bytes, fq->fq_min_qdelay);
	}
	fq->fq_flags &= ~FQF_FLOWCTL_ON;
}

void
fq_if_dequeue(fq_if_t *fqs, fq_if_classq_t *fq_cl, uint32_t pktlimit,
    int64_t bytelimit, classq_pkt_t *top, classq_pkt_t *bottom,
    uint32_t *retpktcnt, uint32_t *retbytecnt, flowq_dqlist_t *fq_dqlist,
    bool budget_restricted, uint64_t now)
{
	fq_t *fq = NULL, *tfq = NULL;
	flowq_stailq_t temp_stailq;
	uint32_t pktcnt, bytecnt;
	boolean_t qempty, limit_reached = FALSE;
	classq_pkt_t last = CLASSQ_PKT_INITIALIZER(last);
	fq_getq_flow_t fq_getq_flow_fn;
	classq_pkt_t *head, *tail;

	switch (fqs->fqs_ptype) {
	case QP_MBUF:
		fq_getq_flow_fn = fq_getq_flow_mbuf;
		break;

#if SKYWALK
	case QP_PACKET:
		fq_getq_flow_fn = fq_getq_flow_kpkt;
		break;
#endif /* SKYWALK */

	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	/*
	 * maximum byte limit should not be greater than the budget for
	 * this class
	 */
	if (bytelimit > fq_cl->fcl_budget && budget_restricted) {
		bytelimit = fq_cl->fcl_budget;
	}

	VERIFY(pktlimit > 0 && bytelimit > 0 && top != NULL);
	pktcnt = bytecnt = 0;
	STAILQ_INIT(&temp_stailq);

	STAILQ_FOREACH_SAFE(fq, &fq_cl->fcl_new_flows, fq_actlink, tfq) {
		ASSERT((fq->fq_flags & (FQF_NEW_FLOW | FQF_OLD_FLOW)) ==
		    FQF_NEW_FLOW);

		if (fq_dqlist != NULL) {
			if (!fq->fq_in_dqlist) {
				fq_dqlist_add(fq_dqlist, fq);
			}
			head = &fq->fq_dq_head;
			tail = &fq->fq_dq_tail;
		} else {
			ASSERT(!fq->fq_in_dqlist);
			head = top;
			tail = &last;
		}

		limit_reached = fq_getq_flow_fn(fqs, fq_cl, fq, bytelimit,
		    pktlimit, head, tail, &bytecnt, &pktcnt, &qempty,
		    PKTF_NEW_FLOW, now);

		/*
		 * From RFC 8290:
		 * if that queue has a negative number of credits (i.e., it has already
		 * dequeued at least a quantum of bytes), it is given an additional
		 * quantum of credits, the queue is put onto _the end of_ the list of
		 * old queues, and the routine selects the next queue and starts again.
		 */
		if (fq->fq_deficit <= 0 || qempty) {
			fq->fq_deficit += fq_cl->fcl_quantum;
			fq_if_empty_new_flow(fq, fq_cl);
		}

		if (limit_reached) {
			goto done;
		}
	}

	STAILQ_FOREACH_SAFE(fq, &fq_cl->fcl_old_flows, fq_actlink, tfq) {
		VERIFY((fq->fq_flags & (FQF_NEW_FLOW | FQF_OLD_FLOW)) ==
		    FQF_OLD_FLOW);
		bool destroy = true;

		if (fq_dqlist != NULL) {
			if (!fq->fq_in_dqlist) {
				fq_dqlist_add(fq_dqlist, fq);
			}
			head = &fq->fq_dq_head;
			tail = &fq->fq_dq_tail;
			destroy = false;
		} else {
			ASSERT(!fq->fq_in_dqlist);
			head = top;
			tail = &last;
		}

		limit_reached = fq_getq_flow_fn(fqs, fq_cl, fq, bytelimit,
		    pktlimit, head, tail, &bytecnt, &pktcnt, &qempty, 0, now);

		if (qempty) {
			fq_if_empty_old_flow(fqs, fq_cl, fq, now);
		} else if (fq->fq_deficit <= 0) {
			STAILQ_REMOVE(&fq_cl->fcl_old_flows, fq,
			    flowq, fq_actlink);
			/*
			 * Move to the end of the old queues list. We do not
			 * need to update the flow count since this flow
			 * will be added to the tail again
			 */
			STAILQ_INSERT_TAIL(&temp_stailq, fq, fq_actlink);
			fq->fq_deficit += fq_cl->fcl_quantum;
		}
		if (limit_reached) {
			break;
		}
	}

done:
	if (!STAILQ_EMPTY(&fq_cl->fcl_old_flows)) {
		STAILQ_CONCAT(&fq_cl->fcl_old_flows, &temp_stailq);
	} else if (!STAILQ_EMPTY(&temp_stailq)) {
		fq_cl->fcl_old_flows = temp_stailq;
	}
	if (last.cp_mbuf != NULL) {
		VERIFY(top->cp_mbuf != NULL);
		if (bottom != NULL) {
			*bottom = last;
		}
	}
	if (retpktcnt != NULL) {
		*retpktcnt = pktcnt;
	}
	if (retbytecnt != NULL) {
		*retbytecnt = bytecnt;
	}
}

void
fq_if_teardown_ifclassq(struct ifclassq *ifq)
{
	fq_if_t *fqs = (fq_if_t *)ifq->ifcq_disc;

	IFCQ_LOCK_ASSERT_HELD(ifq);
	VERIFY(fqs != NULL && ifq->ifcq_type == PKTSCHEDT_FQ_CODEL);
	fq_if_destroy(fqs);
	ifq->ifcq_disc = NULL;
	ifclassq_detach(ifq);
}

static void
fq_export_flowstats(fq_if_t *fqs, fq_t *fq,
    struct fq_codel_flowstats *flowstat)
{
	bzero(flowstat, sizeof(*flowstat));
	flowstat->fqst_min_qdelay = (uint32_t)fq->fq_min_qdelay;
	flowstat->fqst_bytes = fq->fq_bytes;
	flowstat->fqst_flowhash = fq->fq_flowhash;
	if (fq->fq_flags & FQF_NEW_FLOW) {
		flowstat->fqst_flags |= FQ_FLOWSTATS_NEW_FLOW;
	}
	if (fq->fq_flags & FQF_OLD_FLOW) {
		flowstat->fqst_flags |= FQ_FLOWSTATS_OLD_FLOW;
	}
	if (fq->fq_flags & FQF_DELAY_HIGH) {
		flowstat->fqst_flags |= FQ_FLOWSTATS_DELAY_HIGH;
	}
	if (fq->fq_flags & FQF_FLOWCTL_ON) {
		flowstat->fqst_flags |= FQ_FLOWSTATS_FLOWCTL_ON;
	}
	if (fqs->fqs_large_flow == fq) {
		flowstat->fqst_flags |= FQ_FLOWSTATS_LARGE_FLOW;
	}
}

int
fq_if_getqstats_ifclassq(struct ifclassq *ifq, uint8_t gid, u_int32_t qid,
    struct if_ifclassq_stats *ifqs)
{
	struct fq_codel_classstats *fcls;
	fq_if_classq_t *fq_cl;
	fq_if_t *fqs;
	fq_t *fq = NULL;
	fq_if_group_t *grp;
	u_int32_t i, flowstat_cnt;

	if (qid >= FQ_IF_MAX_CLASSES || gid >= FQ_IF_MAX_GROUPS) {
		return EINVAL;
	}

	fqs = (fq_if_t *)ifq->ifcq_disc;
	if (fqs->fqs_classq_groups[gid] == NULL) {
		return ENXIO;
	}

	fcls = &ifqs->ifqs_fq_codel_stats;

	fq_cl = &FQS_CLASSQ(fqs, gid, qid);
	grp = fq_if_find_grp(fqs, gid);

	fcls->fcls_pri = fq_cl->fcl_pri;
	fcls->fcls_service_class = fq_cl->fcl_service_class;
	fcls->fcls_quantum = fq_cl->fcl_quantum;
	fcls->fcls_drr_max = fq_cl->fcl_drr_max;
	fcls->fcls_budget = fq_cl->fcl_budget;
	fcls->fcls_l4s_target_qdelay = grp->fqg_target_qdelays[FQ_TFC_L4S];
	fcls->fcls_target_qdelay = grp->fqg_target_qdelays[FQ_TFC_C];
	fcls->fcls_update_interval = grp->fqg_update_intervals[FQ_TFC_C];
	fcls->fcls_flow_control = fq_cl->fcl_stat.fcl_flow_control;
	fcls->fcls_flow_feedback = fq_cl->fcl_stat.fcl_flow_feedback;
	fcls->fcls_dequeue_stall = fq_cl->fcl_stat.fcl_dequeue_stall;
	fcls->fcls_drop_overflow = fq_cl->fcl_stat.fcl_drop_overflow;
	fcls->fcls_drop_early = fq_cl->fcl_stat.fcl_drop_early;
	fcls->fcls_drop_memfailure = fq_cl->fcl_stat.fcl_drop_memfailure;
	fcls->fcls_flows_cnt = fq_cl->fcl_stat.fcl_flows_cnt;
	fcls->fcls_newflows_cnt = fq_cl->fcl_stat.fcl_newflows_cnt;
	fcls->fcls_oldflows_cnt = fq_cl->fcl_stat.fcl_oldflows_cnt;
	fcls->fcls_pkt_cnt = fq_cl->fcl_stat.fcl_pkt_cnt;
	fcls->fcls_flow_control_fail = fq_cl->fcl_stat.fcl_flow_control_fail;
	fcls->fcls_flow_control_fail = fq_cl->fcl_stat.fcl_flow_control_fail;
	fcls->fcls_dequeue = fq_cl->fcl_stat.fcl_dequeue;
	fcls->fcls_dequeue_bytes = fq_cl->fcl_stat.fcl_dequeue_bytes;
	fcls->fcls_byte_cnt = fq_cl->fcl_stat.fcl_byte_cnt;
	fcls->fcls_throttle_on = fq_cl->fcl_stat.fcl_throttle_on;
	fcls->fcls_throttle_off = fq_cl->fcl_stat.fcl_throttle_off;
	fcls->fcls_throttle_drops = fq_cl->fcl_stat.fcl_throttle_drops;
	fcls->fcls_dup_rexmts = fq_cl->fcl_stat.fcl_dup_rexmts;
	fcls->fcls_pkts_compressible = fq_cl->fcl_stat.fcl_pkts_compressible;
	fcls->fcls_pkts_compressed = fq_cl->fcl_stat.fcl_pkts_compressed;
	fcls->fcls_min_qdelay = fq_cl->fcl_stat.fcl_min_qdelay;
	fcls->fcls_max_qdelay = fq_cl->fcl_stat.fcl_max_qdelay;
	fcls->fcls_avg_qdelay = fq_cl->fcl_stat.fcl_avg_qdelay;
	fcls->fcls_overwhelming = fq_cl->fcl_stat.fcl_overwhelming;
	fcls->fcls_ce_marked = fq_cl->fcl_stat.fcl_ce_marked;
	fcls->fcls_ce_mark_failures = fq_cl->fcl_stat.fcl_ce_mark_failures;
	fcls->fcls_l4s_pkts = fq_cl->fcl_stat.fcl_l4s_pkts;

	/* Gather per flow stats */
	flowstat_cnt = min((fcls->fcls_newflows_cnt +
	    fcls->fcls_oldflows_cnt), FQ_IF_MAX_FLOWSTATS);
	i = 0;
	STAILQ_FOREACH(fq, &fq_cl->fcl_new_flows, fq_actlink) {
		if (i >= fcls->fcls_newflows_cnt || i >= flowstat_cnt) {
			break;
		}

		/* leave space for a few old flows */
		if ((flowstat_cnt - i) < fcls->fcls_oldflows_cnt &&
		    i >= (FQ_IF_MAX_FLOWSTATS >> 1)) {
			break;
		}
		fq_export_flowstats(fqs, fq, &fcls->fcls_flowstats[i]);
		i++;
	}
	STAILQ_FOREACH(fq, &fq_cl->fcl_old_flows, fq_actlink) {
		if (i >= flowstat_cnt) {
			break;
		}
		fq_export_flowstats(fqs, fq, &fcls->fcls_flowstats[i]);
		i++;
	}
	VERIFY(i <= flowstat_cnt);
	fcls->fcls_flowstats_cnt = i;
	return 0;
}

int
fq_if_create_grp(struct ifclassq *ifcq, uint8_t grp_idx, uint8_t flags)
{
#define _FQ_CLASSQ_INIT(_grp, _s, _q)                      \
    fq_if_classq_init(_grp, FQ_IF_ ## _s ##_INDEX,         \
	FQ_CODEL_QUANTUM_ ## _s(_q), FQ_CODEL_DRR_MAX(_s),     \
	MBUF_SC_ ## _s );

	fq_if_group_t *grp;
	fq_if_t *fqs;
	uint32_t quantum, calc_flags = IF_CLASSQ_DEF;
	struct ifnet *ifp = ifcq->ifcq_ifp;

	VERIFY(grp_idx < FQ_IF_MAX_GROUPS);

	fqs = (fq_if_t *)ifcq->ifcq_disc;

	if (grp_idx == 0 && fqs->fqs_classq_groups[grp_idx] != NULL) {
		grp = fqs->fqs_classq_groups[grp_idx];
		goto update;
	}

	if (fqs->fqs_classq_groups[grp_idx] != NULL) {
		return EINVAL;
	}

	grp = zalloc_flags(fq_if_grp_zone, Z_WAITOK | Z_ZERO);
	if (grp == NULL) {
		return ENOMEM;
	}

	fqs->fqs_classq_groups[grp_idx] = grp;
	grp->fqg_index = grp_idx;

	quantum = fq_if_calc_quantum(ifp);
	if (fqs->fqs_flags & FQS_DRIVER_MANAGED) {
		_FQ_CLASSQ_INIT(grp, BK, quantum);
		_FQ_CLASSQ_INIT(grp, BE, quantum);
		_FQ_CLASSQ_INIT(grp, VI, quantum);
		_FQ_CLASSQ_INIT(grp, VO, quantum);
	} else {
		/* SIG shares same INDEX with VI */
		_CASSERT(SCIDX_SIG == SCIDX_VI);
		_CASSERT(FQ_IF_SIG_INDEX == FQ_IF_VI_INDEX);

		_FQ_CLASSQ_INIT(grp, BK_SYS, quantum);
		_FQ_CLASSQ_INIT(grp, BK, quantum);
		_FQ_CLASSQ_INIT(grp, BE, quantum);
		_FQ_CLASSQ_INIT(grp, RD, quantum);
		_FQ_CLASSQ_INIT(grp, OAM, quantum);
		_FQ_CLASSQ_INIT(grp, AV, quantum);
		_FQ_CLASSQ_INIT(grp, RV, quantum);
		_FQ_CLASSQ_INIT(grp, VI, quantum);
		_FQ_CLASSQ_INIT(grp, VO, quantum);
		_FQ_CLASSQ_INIT(grp, CTL, quantum);
	}

update:
	if (flags & IF_DEFAULT_GRP) {
		fq_if_set_grp_combined(ifcq, grp_idx);
		grp->fqg_flags |= FQ_IF_DEFAULT_GRP;
	} else {
		fq_if_set_grp_separated(ifcq, grp_idx);
		grp->fqg_flags &= ~FQ_IF_DEFAULT_GRP;
	}

	calc_flags |= (flags & IF_CLASSQ_LOW_LATENCY);
	ifclassq_calc_target_qdelay(ifp, &grp->fqg_target_qdelays[FQ_TFC_C],
	    calc_flags);
	ifclassq_calc_target_qdelay(ifp, &grp->fqg_target_qdelays[FQ_TFC_L4S],
	    calc_flags | IF_CLASSQ_L4S);

	ifclassq_calc_update_interval(&grp->fqg_update_intervals[FQ_TFC_C],
	    calc_flags);
	ifclassq_calc_update_interval(&grp->fqg_update_intervals[FQ_TFC_L4S],
	    calc_flags | IF_CLASSQ_L4S);

	return 0;
#undef _FQ_CLASSQ_INIT
}

fq_if_group_t *
fq_if_find_grp(fq_if_t *fqs, uint8_t grp_idx)
{
	fq_if_group_t *grp;

	IFCQ_LOCK_ASSERT_HELD(fqs->fqs_ifq);
	VERIFY(grp_idx < FQ_IF_MAX_GROUPS);

	grp = fqs->fqs_classq_groups[grp_idx];
	VERIFY(grp != NULL);

	return grp;
}

static void
fq_if_purge_grp(fq_if_t *fqs, fq_if_group_t *grp)
{
	for (uint8_t i = 0; i < FQ_IF_MAX_CLASSES; i++) {
		fq_if_purge_classq(fqs, &grp->fqg_classq[i]);
	}

	bzero(&grp->fqg_bitmaps, sizeof(grp->fqg_bitmaps));
	grp->fqg_len = 0;
	grp->fqg_bytes = 0;
	fq_if_set_grp_separated(fqs->fqs_ifq, grp->fqg_index);
}

void
fq_if_destroy_grps(fq_if_t *fqs)
{
	fq_if_group_t *grp;

	IFCQ_LOCK_ASSERT_HELD(fqs->fqs_ifq);

	for (uint8_t grp_idx = 0; grp_idx < FQ_IF_MAX_GROUPS; grp_idx++) {
		if (fqs->fqs_classq_groups[grp_idx] == NULL) {
			continue;
		}

		grp = fq_if_find_grp(fqs, grp_idx);
		fq_if_purge_grp(fqs, grp);
		zfree(fq_if_grp_zone, grp);
		fqs->fqs_classq_groups[grp_idx] = NULL;
	}
}

static inline boolean_t
fq_if_is_grp_combined(fq_if_t *fqs, uint8_t grp_idx)
{
	return pktsched_bit_tst(grp_idx, &fqs->fqs_combined_grp_bitmap);
}

void
fq_if_set_grp_combined(struct ifclassq *ifcq, uint8_t grp_idx)
{
	fq_if_t *fqs;
	fq_if_group_t *grp;

	IFCQ_LOCK_ASSERT_HELD(ifcq);

	fqs = (fq_if_t *)ifcq->ifcq_disc;
	grp = fq_if_find_grp(fqs, grp_idx);

	if (fq_if_is_grp_combined(fqs, grp_idx)) {
		return;
	}

	/*
	 * We keep the current fq_deficit and fcl_budget when combining a group.
	 * That might disrupt the AQM but only for a moment.
	 */
	pktsched_bit_set(grp_idx, &fqs->fqs_combined_grp_bitmap);
	TAILQ_INSERT_TAIL(&fqs->fqs_combined_grp_list, grp, fqg_grp_link);
}

void
fq_if_set_grp_separated(struct ifclassq *ifcq, uint8_t grp_idx)
{
	fq_if_t *fqs;
	fq_if_group_t *grp;

	IFCQ_LOCK_ASSERT_HELD(ifcq);

	fqs = (fq_if_t *)ifcq->ifcq_disc;
	grp = fq_if_find_grp(fqs, grp_idx);

	if (!fq_if_is_grp_combined(fqs, grp_idx)) {
		return;
	}

	pktsched_bit_clr(grp_idx, &fqs->fqs_combined_grp_bitmap);
	TAILQ_REMOVE(&fqs->fqs_combined_grp_list, grp, fqg_grp_link);
}
