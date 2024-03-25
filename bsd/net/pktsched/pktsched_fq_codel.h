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

#ifndef _NET_PKTSCHED_FQ_CODEL_H_
#define _NET_PKTSCHED_FQ_CODEL_H_

#ifdef PRIVATE
#include <sys/types.h>
#include <sys/param.h>

#ifdef BSD_KERNEL_PRIVATE
#include <net/flowadv.h>
#include <net/pktsched/pktsched.h>
#endif /* BSD_KERNEL_PRIVATE */

#ifdef __cplusplus
extern "C" {
#endif

#ifdef BSD_KERNEL_PRIVATE
struct fcl_stat {
	u_int32_t fcl_flow_control;
	u_int32_t fcl_flow_feedback;
	u_int32_t fcl_dequeue_stall;
	u_int32_t fcl_flow_control_fail;
	u_int64_t fcl_drop_overflow;
	u_int64_t fcl_drop_early;
	u_int32_t fcl_drop_memfailure;
	u_int32_t fcl_flows_cnt;
	u_int32_t fcl_newflows_cnt;
	u_int32_t fcl_oldflows_cnt;
	u_int64_t fcl_pkt_cnt;
	u_int64_t fcl_dequeue;
	u_int64_t fcl_dequeue_bytes;
	u_int64_t fcl_byte_cnt;
	u_int32_t fcl_throttle_on;
	u_int32_t fcl_throttle_off;
	u_int32_t fcl_throttle_drops;
	u_int32_t fcl_dup_rexmts;
	u_int32_t fcl_pkts_compressible;
	u_int32_t fcl_pkts_compressed;
	uint64_t fcl_min_qdelay;
	uint64_t fcl_max_qdelay;
	uint64_t fcl_avg_qdelay;
	uint32_t fcl_overwhelming;
	uint64_t fcl_ce_marked;
	uint64_t fcl_ce_reported;
	uint64_t fcl_ce_mark_failures;
	uint64_t fcl_l4s_pkts;
	uint64_t fcl_ignore_tx_time;
	uint64_t fcl_paced_pkts;
	uint64_t fcl_fcl_pacemaker_needed;
};

/*
 * Use 8 bits from the flow id as the tag for set associative
 * hashing
 * NOTE: The first 2 bits of the flow id is being used to encode the flow
 * domain information, so don't use the top 8 bits as it won't have a uniform
 * distribution.
 */

#define FQ_IF_HASH_TAG_SIZE     8
#define FQ_IF_HASH_TAG_SHIFT    16
#define FQ_IF_HASH_TAG_MASK     0xFF
#define FQ_IF_HASH_TABLE_SIZE   (1 << FQ_IF_HASH_TAG_SIZE)

/* Set the quantum to be one MTU */
#define FQ_IF_DEFAULT_QUANTUM   1500

/* Max number of service classes currently supported */
#define FQ_IF_MAX_CLASSES       10
_Static_assert(FQ_IF_MAX_CLASSES < 127,
    "maximum number of classes needs to fit in a single byte");

#define FQ_IF_LARGE_FLOW_BYTE_LIMIT     15000

/* Max number of classq groups currently supported */
#define FQ_IF_MAX_GROUPS                16

typedef enum : uint8_t {
	FQ_TFC_C            = 0, /* classic traffic */
	FQ_TFC_L4S          = 1, /* L4S traffic */
	FQ_TFC_CNT          = 2,
} fq_tfc_type_t;

struct flowq;
typedef u_int32_t pktsched_bitmap_t;
struct if_ifclassq_stats;

typedef enum : uint8_t {
	FQ_IF_ER = 0,           /* eligible, ready */
	FQ_IF_IR = 1,           /* ineligible, ready */
	FQ_IF_EB = 2,           /* eligible blocked */
	FQ_IF_IB = 3,           /* ineligible, blocked */
	FQ_IF_MAX_STATE
} fq_if_state;

/*
 * This priority index is used for QFQ state bitmaps, lower index gets
 * higher priority
 */
#define FQ_IF_BK_SYS_INDEX      9
#define FQ_IF_BK_INDEX  8
#define FQ_IF_BE_INDEX  7
#define FQ_IF_RD_INDEX  6
#define FQ_IF_OAM_INDEX 5
#define FQ_IF_AV_INDEX  4
#define FQ_IF_RV_INDEX  3
#define FQ_IF_VI_INDEX  2
#define FQ_IF_SIG_INDEX 2
#define FQ_IF_VO_INDEX  1
#define FQ_IF_CTL_INDEX 0

typedef SLIST_HEAD(, flowq) flowq_list_t;
typedef STAILQ_HEAD(, flowq) flowq_stailq_t;
typedef struct fq_if_classq {
	uint32_t fcl_pri;      /* class priority, lower the better */
	uint32_t fcl_service_class;    /* service class */
	uint32_t fcl_quantum;          /* quantum in bytes */
	uint32_t fcl_drr_max;          /* max flows per class for DRR */
	int64_t  fcl_budget;             /* budget for this classq */
	uint64_t fcl_next_tx_time;      /* next time a packet is ready */
	flowq_stailq_t fcl_new_flows;   /* List of new flows */
	flowq_stailq_t fcl_old_flows;   /* List of old flows */
	struct fcl_stat fcl_stat;
#define FCL_PACED               0x1
	uint8_t fcl_flags;
} fq_if_classq_t;
typedef struct fq_codel_classq_group {
	/* Target queue delays (ns) */
	uint64_t                fqg_target_qdelays[FQ_TFC_CNT];
	/* update intervals (ns) */
	uint64_t                fqg_update_intervals[FQ_TFC_CNT];
	/* classq bitmaps */
	pktsched_bitmap_t       fqg_bitmaps[FQ_IF_MAX_STATE];
	TAILQ_ENTRY(fq_codel_classq_group) fqg_grp_link;
	uint32_t                fqg_bytes;     /* bytes count */
	uint32_t                fqg_len;       /* pkts count */
	uint8_t                 fqg_flags;     /* flags */
#define FQ_IF_DEFAULT_GRP                   0x1
	uint8_t                 fqg_index;     /* group index */
	fq_if_classq_t          fqg_classq[FQ_IF_MAX_CLASSES]; /* class queues */
	struct flowq            *fqg_large_flow; /* flow has highest number of bytes */
} fq_if_group_t;

#define FQG_LEN(_fqg)           ((_fqg)->fqg_len)
#define FQG_IS_EMPTY(_fqg)      (FQG_LEN(_fqg) == 0)
#define FQG_INC_LEN(_fqg)       (FQG_LEN(_fqg)++)
#define FQG_DEC_LEN(_fqg)       (FQG_LEN(_fqg)--)
#define FQG_ADD_LEN(_fqg, _len) (FQG_LEN(_fqg) += (_len))
#define FQG_SUB_LEN(_fqg, _len) (FQG_LEN(_fqg) -= (_len))
#define FQG_BYTES(_fqg)         ((_fqg)->fqg_bytes)

#define FQG_INC_BYTES(_fqg, _len)     \
    ((_fqg)->fqg_bytes = (_fqg)->fqg_bytes + (_len))
#define FQG_DEC_BYTES(_fqg, _len)     \
    ((_fqg)->fqg_bytes = (_fqg)->fqg_bytes - (_len))

typedef TAILQ_HEAD(, fq_codel_classq_group) fq_grp_tailq_t;

typedef int (* fq_if_bitmaps_ffs)(fq_grp_tailq_t *, int, fq_if_state, fq_if_group_t **);
typedef boolean_t (* fq_if_bitmaps_zeros)(fq_grp_tailq_t *, int, fq_if_state);
typedef void (* fq_if_bitmaps_cpy)(fq_grp_tailq_t *, int, fq_if_state, fq_if_state);
typedef void (* fq_if_bitmaps_clr)(fq_grp_tailq_t *, int, fq_if_state);
typedef void (* fq_if_bitmaps_move)(fq_grp_tailq_t *, int, fq_if_state, fq_if_state);

/*
 * Functions that are used to look at groups'
 * bitmaps and decide which pri and group are the
 * next one to dequeue from.
 */
typedef struct fq_if_bitmap_ops {
	fq_if_bitmaps_ffs       ffs;
	fq_if_bitmaps_zeros     zeros;
	fq_if_bitmaps_cpy       cpy;
	fq_if_bitmaps_clr       clr;
	fq_if_bitmaps_move      move;
} bitmap_ops_t;

typedef struct fq_codel_sched_data {
	struct ifclassq         *fqs_ifq;       /* back pointer to ifclassq */
	flowq_list_t            fqs_flows[FQ_IF_HASH_TABLE_SIZE]; /* flows table */
	uint32_t                fqs_pkt_droplimit;  /* drop limit */
	uint8_t                 fqs_throttle;   /* throttle on or off */
	uint8_t                 fqs_flags;      /* flags */
#define FQS_DRIVER_MANAGED      0x1
	struct flowadv_fclist   fqs_fclist; /* flow control state */
	struct flowq            *fqs_large_flow; /* flow has highest number of bytes */
	TAILQ_HEAD(, flowq)     fqs_empty_list; /* list of empty flows */
	/* list of groups in combined mode */
	fq_grp_tailq_t          fqs_combined_grp_list;
	uint32_t                fqs_empty_list_cnt;
	/* bitmap indicating which grp is in combined mode */
	pktsched_bitmap_t       fqs_combined_grp_bitmap;
	classq_pkt_type_t       fqs_ptype;
	thread_call_t           fqs_pacemaker_tcall;
	bitmap_ops_t            *fqs_bm_ops;
#define grp_bitmaps_ffs     fqs_bm_ops->ffs
#define grp_bitmaps_zeros   fqs_bm_ops->zeros
#define grp_bitmaps_cpy     fqs_bm_ops->cpy
#define grp_bitmaps_clr     fqs_bm_ops->clr
#define grp_bitmaps_move    fqs_bm_ops->move
	fq_if_group_t           *fqs_classq_groups[FQ_IF_MAX_GROUPS];
} fq_if_t;

#define FQS_GROUP(_fqs, _group_idx)                                      \
	(fq_if_find_grp((_fqs), (_group_idx)))

#define FQS_CLASSQ(_fqs, _group_idx, _sc_idx)                            \
    (FQS_GROUP((_fqs), (_group_idx))->fqg_classq[_sc_idx])

#define FQ_GROUP(_fq)                                      \
	((_fq)->fq_group)

#define FQ_GRP_LEN(_fq)                                    \
	(FQ_GROUP((_fq))->fqg_len)
#define FQ_GRP_IS_EMPTY(_fq)                               \
	(FQ_GRP_LEN((_fq)) == 0)
#define FQ_GRP_INC_LEN(_fq)                                \
    (FQ_GRP_LEN((_fq))++)
#define FQ_GRP_DEC_LEN(_fq)                                \
    (FQ_GRP_LEN((_fq))--)
#define FQ_GRP_ADD_LEN(_fq, _len)                          \
	(FQ_GRP_LEN((_fq)) += (_len))
#define FQ_GRP_SUB_LEN(_fq, _len)                          \
	(FQ_GRP_LEN((_fq)) -= (_len))

#define FQS_GRP_ADD_LEN(_fqs, _grp_idx, _len)              \
	(FQS_GROUP(_fqs, grp_idx)->fqg_len += (_len))


#define FQ_GRP_BYTES(_fq)                     \
	(FQ_GROUP((_fq))->fqg_bytes)
#define FQ_GRP_INC_BYTES(_fq, _len)           \
    (FQ_GRP_BYTES((_fq)) += (_len))
#define FQ_GRP_DEC_BYTES(_fq, _len)           \
    (FQ_GRP_BYTES((_fq)) -= (_len))

#define FQS_GRP_INC_BYTES(_fqs, grp_idx, _len)           \
	(FQS_GROUP(_fqs, grp_idx)->fqg_bytes += (_len))

#define FQ_CLASSQ(_fq)                                   \
	(FQ_GROUP((_fq))->fqg_classq[(_fq)->fq_sc_index])

#define FQ_TARGET_DELAY(_fq)              \
	(FQ_GROUP((_fq))->fqg_target_qdelays[(_fq)->fq_tfc_type])
#define FQ_UPDATE_INTERVAL(_fq)           \
	(FQ_GROUP((_fq))->fqg_update_intervals[(_fq)->fq_tfc_type])

#endif /* BSD_KERNEL_PRIVATE */

struct fq_codel_flowstats {
	u_int32_t       fqst_min_qdelay;
#define FQ_FLOWSTATS_OLD_FLOW   0x1
#define FQ_FLOWSTATS_NEW_FLOW   0x2
#define FQ_FLOWSTATS_LARGE_FLOW 0x4
#define FQ_FLOWSTATS_DELAY_HIGH 0x8
#define FQ_FLOWSTATS_FLOWCTL_ON 0x10
	u_int32_t       fqst_flags;
	u_int32_t       fqst_bytes;
	u_int32_t       fqst_flowhash;
};

#define FQ_IF_MAX_FLOWSTATS     20
#define FQ_IF_STATS_MAX_GROUPS  16

struct fq_codel_classstats {
	u_int32_t       fcls_pri;
	u_int32_t       fcls_service_class;
	u_int32_t       fcls_quantum;
	u_int32_t       fcls_drr_max;
	int64_t         fcls_budget;
	u_int64_t       fcls_target_qdelay;
	u_int64_t       fcls_l4s_target_qdelay;
	u_int64_t       fcls_update_interval;
	u_int32_t       fcls_flow_control;
	u_int32_t       fcls_flow_feedback;
	u_int32_t       fcls_dequeue_stall;
	u_int32_t       fcls_flow_control_fail;
	u_int64_t       fcls_drop_overflow;
	u_int64_t       fcls_drop_early;
	u_int32_t       fcls_drop_memfailure;
	u_int32_t       fcls_flows_cnt;
	u_int32_t       fcls_newflows_cnt;
	u_int32_t       fcls_oldflows_cnt;
	u_int64_t       fcls_pkt_cnt;
	u_int64_t       fcls_dequeue;
	u_int64_t       fcls_dequeue_bytes;
	u_int64_t       fcls_byte_cnt;
	u_int32_t       fcls_throttle_on;
	u_int32_t       fcls_throttle_off;
	u_int32_t       fcls_throttle_drops;
	u_int32_t       fcls_dup_rexmts;
	u_int32_t       fcls_flowstats_cnt;
	struct fq_codel_flowstats fcls_flowstats[FQ_IF_MAX_FLOWSTATS];
	u_int32_t       fcls_pkts_compressible;
	u_int32_t       fcls_pkts_compressed;
	uint64_t        fcls_min_qdelay;
	uint64_t        fcls_max_qdelay;
	uint64_t        fcls_avg_qdelay;
	uint32_t        fcls_overwhelming;
	uint64_t        fcls_ce_marked;
	uint64_t        fcls_ce_reported;
	uint64_t        fcls_ce_mark_failures;
	uint64_t        fcls_l4s_pkts;
	uint64_t        fcls_ignore_tx_time;
	uint64_t        fcls_paced_pkts;
	uint64_t        fcls_fcl_pacing_needed;
};

#ifdef BSD_KERNEL_PRIVATE

_Static_assert(FQ_IF_STATS_MAX_GROUPS == FQ_IF_MAX_GROUPS,
    "max group counts do not match");

extern void pktsched_fq_init(void);
extern void fq_codel_scheduler_init(void);
extern int fq_if_enqueue_classq(struct ifclassq *ifq, classq_pkt_t *h,
    classq_pkt_t *t, uint32_t cnt, uint32_t bytes, boolean_t *pdrop);
extern void fq_if_dequeue_classq(struct ifclassq *ifq, classq_pkt_t *pkt,
    uint8_t grp_idx);
extern void fq_if_dequeue_sc_classq(struct ifclassq *ifq, mbuf_svc_class_t svc,
    classq_pkt_t *pkt, uint8_t grp_idx);
extern int fq_if_dequeue_classq_multi(struct ifclassq *ifq, u_int32_t maxpktcnt,
    u_int32_t maxbytecnt, classq_pkt_t *first_packet, classq_pkt_t *last_packet,
    u_int32_t *retpktcnt, u_int32_t *retbytecnt, uint8_t grp_idx);
extern int fq_if_dequeue_sc_classq_multi(struct ifclassq *ifq,
    mbuf_svc_class_t svc, u_int32_t maxpktcnt, u_int32_t maxbytecnt,
    classq_pkt_t *first_packet, classq_pkt_t *last_packet, u_int32_t *retpktcnt,
    u_int32_t *retbytecnt, uint8_t grp_idx);
extern int fq_if_request_classq(struct ifclassq *ifq, cqrq_t rq, void *arg);
extern struct flowq *fq_if_hash_pkt(fq_if_t *, fq_if_group_t *,
    u_int32_t, mbuf_svc_class_t, u_int64_t, bool, fq_tfc_type_t);
extern boolean_t fq_if_at_drop_limit(fq_if_t *);
extern boolean_t fq_if_almost_at_drop_limit(fq_if_t *fqs);
extern void fq_if_drop_packet(fq_if_t *, uint64_t);
extern void fq_if_is_flow_heavy(fq_if_t *, struct flowq *);
extern boolean_t fq_if_add_fcentry(fq_if_t *, pktsched_pkt_t *, uint8_t,
    struct flowq *, fq_if_classq_t *);
extern void fq_if_flow_feedback(fq_if_t *, struct flowq *, fq_if_classq_t *);
extern boolean_t fq_if_report_ce(fq_if_t *, pktsched_pkt_t *, uint32_t, uint32_t);
extern int fq_if_setup_ifclassq(struct ifclassq *ifq, u_int32_t flags,
    classq_pkt_type_t ptype);
extern void fq_if_teardown_ifclassq(struct ifclassq *ifq);
extern int fq_if_getqstats_ifclassq(struct ifclassq *ifq, uint8_t gid,
    u_int32_t qid, struct if_ifclassq_stats *ifqs);
extern void fq_if_destroy_flow(fq_if_t *, fq_if_classq_t *, struct flowq *);
extern void fq_if_move_to_empty_flow(fq_if_t *, fq_if_classq_t *,
    struct flowq *, uint64_t);
extern int fq_if_create_grp(struct ifclassq *ifcq, uint8_t qset_idx, uint8_t flags);
extern void fq_if_set_grp_combined(struct ifclassq *ifcq, uint8_t qset_idx);
extern void fq_if_set_grp_separated(struct ifclassq *ifcq, uint8_t qset_idx);
extern fq_if_group_t *fq_if_find_grp(fq_if_t *fqs, uint8_t grp_idx);
extern boolean_t fq_if_is_all_paced(struct ifclassq *ifq);
#endif /* BSD_KERNEL_PRIVATE */

#ifdef __cplusplus
}
#endif

#endif /* PRIVATE */
#endif /* _NET_PKTSCHED_PKTSCHED_FQ_CODEL_H_ */
