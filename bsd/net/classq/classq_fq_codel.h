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

#ifndef _NET_CLASSQ_CLASSQ_FQ_CODEL_H
#define _NET_CLASSQ_CLASSQ_FQ_CODEL_H
#ifdef PRIVATE
#ifdef BSD_KERNEL_PRIVATE
#include <stdbool.h>
#include <sys/time.h>
#include <net/flowadv.h>
#include <net/classq/if_classq.h>
#if SKYWALK
#include <skywalk/os_skywalk_private.h>
#endif /* SKYWALK */

#ifdef __cplusplus
extern "C" {
#endif

#define AQM_KTRACE_AON_FLOW_HIGH_DELAY    AQMDBG_CODE(DBG_AQM_ALWAYSON, 0x001)
#define AQM_KTRACE_AON_THROTTLE           AQMDBG_CODE(DBG_AQM_ALWAYSON, 0x002)
#define AQM_KTRACE_AON_FLOW_OVERWHELMING  AQMDBG_CODE(DBG_AQM_ALWAYSON, 0x003)
#define AQM_KTRACE_AON_FLOW_DQ_STALL      AQMDBG_CODE(DBG_AQM_ALWAYSON, 0x004)

#define AQM_KTRACE_STATS_FLOW_ENQUEUE   AQMDBG_CODE(DBG_AQM_STATS, 0x001)
#define AQM_KTRACE_STATS_FLOW_DEQUEUE   AQMDBG_CODE(DBG_AQM_STATS, 0x002)
#define AQM_KTRACE_STATS_FLOW_CTL       AQMDBG_CODE(DBG_AQM_STATS, 0x003)
#define AQM_KTRACE_STATS_FLOW_ALLOC     AQMDBG_CODE(DBG_AQM_STATS, 0x004)
#define AQM_KTRACE_STATS_FLOW_DESTROY   AQMDBG_CODE(DBG_AQM_STATS, 0x005)

#define AQM_KTRACE_FQ_GRP_SC_IDX(_fq_) \
	((_fq_)->fq_group->fqg_index << 4 | (_fq_)->fq_sc_index)

#define FQ_MIN_FC_THRESHOLD_BYTES       7500
#define FQ_IS_DELAY_HIGH(_fq_)   ((_fq_)->fq_flags & FQF_DELAY_HIGH)
#define FQ_SET_DELAY_HIGH(_fq_) do {                          \
    if (!FQ_IS_DELAY_HIGH(_fq_)) {                              \
	KDBG(AQM_KTRACE_AON_FLOW_HIGH_DELAY | DBG_FUNC_START, \
	    (_fq_)->fq_flowhash, AQM_KTRACE_FQ_GRP_SC_IDX((_fq_)),    \
	    (_fq_)->fq_bytes, (_fq_)->fq_min_qdelay);                 \
    }                                                                 \
    (_fq_)->fq_flags |= FQF_DELAY_HIGH; \
    } while (0)
#define FQ_CLEAR_DELAY_HIGH(_fq_) do { \
    if (FQ_IS_DELAY_HIGH(_fq_)) {        \
	    KDBG(AQM_KTRACE_AON_FLOW_HIGH_DELAY | DBG_FUNC_END, \
	            (_fq_)->fq_flowhash, AQM_KTRACE_FQ_GRP_SC_IDX((_fq_)),  \
	            (_fq_)->fq_bytes, (_fq_)->fq_min_qdelay);               \
    }                                                       \
    (_fq_)->fq_flags &= ~FQF_DELAY_HIGH;                    \
} while (0)

#define FQ_IS_OVERWHELMING(_fq_)   ((_fq_)->fq_flags & FQF_OVERWHELMING)
#define FQ_SET_OVERWHELMING(_fq_) do { \
	if (!FQ_IS_OVERWHELMING(_fq_)) {                              \
	        KDBG(AQM_KTRACE_AON_FLOW_OVERWHELMING | DBG_FUNC_START, \
	                        (_fq_)->fq_flowhash, AQM_KTRACE_FQ_GRP_SC_IDX((_fq_)),    \
	                        (_fq_)->fq_bytes, (_fq_)->fq_min_qdelay);                 \
	}                                                                                                                                         \
	(_fq_)->fq_flags |= FQF_OVERWHELMING; \
} while (0)
#define FQ_CLEAR_OVERWHELMING(_fq_) do { \
	if (FQ_IS_OVERWHELMING(_fq_)) {                              \
	        KDBG(AQM_KTRACE_AON_FLOW_OVERWHELMING | DBG_FUNC_END,  \
	                        (_fq_)->fq_flowhash, AQM_KTRACE_FQ_GRP_SC_IDX((_fq_)),    \
	                        (_fq_)->fq_bytes, (_fq_)->fq_min_qdelay);                 \
	}                                                                                     \
	(_fq_)->fq_flags &= ~FQF_OVERWHELMING; \
} while (0)

/*
 * time (in ns) the flow queue can stay in empty state.
 */
#define FQ_EMPTY_PURGE_DELAY    (3ULL * 1000 * 1000 * 1000)

/*
 * maximum number of flow queues which can be purged during a dequeue.
 */
#define FQ_EMPTY_PURGE_MAX      4

struct flowq {
#pragma pack(push,1)
	union {
		MBUFQ_HEAD(mbufq_head) __mbufq; /* mbuf packet queue */
#if SKYWALK
		KPKTQ_HEAD(kpktq_head) __kpktq; /* skywalk packet queue */
#endif /* SKYWALK */
	} __fq_pktq_u;
#pragma pack(pop)
	uint32_t       fq_flowhash;    /* Flow hash */
	uint32_t       fq_bytes;       /* Number of bytes in the queue */
	int32_t        fq_deficit;     /* Deficit for scheduling */
	fq_if_group_t  *fq_group;          /* Back pointer to the group */
#define FQF_FLOWCTL_CAPABLE 0x01 /* Use flow control instead of drop */
#define FQF_DELAY_HIGH  0x02    /* Min delay is greater than target */
#define FQF_NEW_FLOW    0x04    /* Currently on new flows queue */
#define FQF_OLD_FLOW    0x08    /* Currently on old flows queue */
#define FQF_FLOWCTL_ON  0x10    /* Currently flow controlled */
#define FQF_EMPTY_FLOW  0x20    /* Currently on empty flows queue */
#define FQF_OVERWHELMING  0x40  /* The largest flow when AQM hits queue limit */
	uint8_t        fq_flags;       /* flags */
	uint8_t        fq_sc_index; /* service_class index */
	bool           fq_in_dqlist;
	fq_tfc_type_t  fq_tfc_type;
	uint8_t        __fq_pad_uint8[4];
	uint64_t       fq_min_qdelay; /* min queue delay for Codel */
	uint64_t       fq_getqtime;    /* last dequeue time */
	union {
		uint64_t   fq_updatetime; /* next update interval */
		/* empty list purge time (in nanoseconds) */
		uint64_t   fq_empty_purge_time;
	};
	SLIST_ENTRY(flowq) fq_hashlink; /* for flow queue hash table */
	/*
	 * flow queue will only be on either one of the lists.
	 */
	union {
		STAILQ_ENTRY(flowq) fq_actlink; /* for new/old flow queues */
		/* entry on empty flow queue list */
		TAILQ_ENTRY(flowq) fq_empty_link;
	};
	/* entry on dequeue flow list */
	STAILQ_ENTRY(flowq) fq_dqlink;
	/* temporary packet queue for dequeued packets */
	classq_pkt_t   fq_dq_head;
	classq_pkt_t   fq_dq_tail;
};

typedef struct flowq fq_t;

#define FQF_FLOW_STATE_MASK    (FQF_DELAY_HIGH | FQF_NEW_FLOW | \
    FQF_OLD_FLOW | FQF_FLOWCTL_ON | FQF_EMPTY_FLOW)

#define fq_mbufq        __fq_pktq_u.__mbufq
#if SKYWALK
#define fq_kpktq        __fq_pktq_u.__kpktq
#endif /* SKYWALK */

#if SKYWALK
#define fq_empty(_q, _ptype)    (((_ptype) == QP_MBUF) ?  \
    MBUFQ_EMPTY(&(_q)->fq_mbufq) : KPKTQ_EMPTY(&(_q)->fq_kpktq))
#else /* !SKYWALK */
#define fq_empty(_q, _ptype)    MBUFQ_EMPTY(&(_q)->fq_mbufq)
#endif /* !SKYWALK */

#if SKYWALK
#define fq_enqueue(_q, _h, _t, _c, _ptype) do {                         \
	switch (_ptype) {                                               \
	case QP_MBUF:                                                   \
	        ASSERT((_h).cp_ptype == QP_MBUF);                       \
	        ASSERT((_t).cp_ptype == QP_MBUF);                       \
	        MBUFQ_ENQUEUE_MULTI(&(_q)->fq_mbufq, (_h).cp_mbuf,      \
	            (_t).cp_mbuf);                                      \
	        MBUFQ_ADD_CRUMB_MULTI(&(_q)->fq_mbufq, (_h).cp_mbuf,    \
	            (_t).cp_mbuf, PKT_CRUMB_FQ_ENQUEUE);                \
	        break;                                                  \
	case QP_PACKET:                                                 \
	        ASSERT((_h).cp_ptype == QP_PACKET);                     \
	        ASSERT((_t).cp_ptype == QP_PACKET);                     \
	        KPKTQ_ENQUEUE_MULTI(&(_q)->fq_kpktq, (_h).cp_kpkt,      \
	            (_t).cp_kpkt, (_c));                                \
	        break;                                                  \
	default:                                                        \
	        VERIFY(0);                                              \
	        __builtin_unreachable();                                \
	        break;                                                  \
	}                                                               \
} while (0)
#else /* !SKYWALK */
#define fq_enqueue(_q, _h, _t, _c, _ptype) {                            \
    MBUFQ_ENQUEUE_MULTI(&(_q)->fq_mbufq, (_h).cp_mbuf, (_t).cp_mbuf);   \
    MBUFQ_ADD_CRUMB_MULTI(&(_q)->fq_mbufq, (_h).cp_mbuf,                \
	    (_t).cp_mbuf, PKT_CRUMB_FQ_ENQUEUE);                        \
} while (0)
#endif /* !SKYWALK */

#if SKYWALK
#define fq_dequeue(_q, _p, _ptype) do {                                 \
	switch (_ptype) {                                               \
	case QP_MBUF: {                                                 \
	        MBUFQ_DEQUEUE(&(_q)->fq_mbufq, (_p)->cp_mbuf);          \
	        if (__probable((_p)->cp_mbuf != NULL)) {                \
	                CLASSQ_PKT_INIT_MBUF((_p), (_p)->cp_mbuf);      \
	                m_add_crumb((_p)->cp_mbuf,                      \
	                    PKT_CRUMB_FQ_DEQUEUE);                      \
	        }                                                       \
	        break;                                                  \
	}                                                               \
	case QP_PACKET: {                                               \
	        KPKTQ_DEQUEUE(&(_q)->fq_kpktq, (_p)->cp_kpkt);          \
	        if (__probable((_p)->cp_kpkt != NULL)) {                \
	                CLASSQ_PKT_INIT_PACKET((_p), (_p)->cp_kpkt);    \
	        }                                                       \
	        break;                                                  \
	}                                                               \
	default:                                                        \
	        VERIFY(0);                                              \
	        __builtin_unreachable();                                \
	        break;                                                  \
	}                                                               \
} while (0)
#else /* !SKYWALK */
#define fq_dequeue(_q, _p, _ptype) do {                                 \
	MBUFQ_DEQUEUE(&(_q)->fq_mbufq, (_p)->cp_mbuf);                  \
	if (__probable((_p)->cp_mbuf != NULL)) {                        \
	        CLASSQ_PKT_INIT_MBUF((_p), (_p)->cp_mbuf);              \
	        m_add_crumb((_p)->cp_mbuf, PKT_CRUMB_FQ_DEQUEUE);       \
	}                                                               \
} while (0)
#endif /* !SKYWALK */

struct fq_codel_sched_data;
struct fq_if_classq;

/* Function definitions */
extern void fq_codel_init(void);
extern void fq_codel_reap_caches(boolean_t);
extern fq_t *fq_alloc(classq_pkt_type_t);
extern void fq_destroy(fq_t *, classq_pkt_type_t);
extern int fq_addq(struct fq_codel_sched_data *, fq_if_group_t *,
    pktsched_pkt_t *, struct fq_if_classq *);
extern void fq_getq_flow(struct fq_codel_sched_data *, fq_t *,
    pktsched_pkt_t *, uint64_t now);
extern void fq_codel_dequeue(fq_if_t *fqs, fq_t *fq,
    pktsched_pkt_t *pkt, uint64_t now);
extern void fq_getq_flow_internal(struct fq_codel_sched_data *,
    fq_t *, pktsched_pkt_t *);
extern void fq_head_drop(struct fq_codel_sched_data *, fq_t *);

#ifdef __cplusplus
}
#endif
#endif /* BSD_KERNEL_PRIVATE */
#endif /* PRIVATE */
#endif /* _NET_CLASSQ_CLASSQ_FQ_CODEL_H */
