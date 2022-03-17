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

#ifndef _SKYWALK_PACKET_PBUFPOOLVAR_H_
#define _SKYWALK_PACKET_PBUFPOOLVAR_H_

#ifdef BSD_KERNEL_PRIVATE
#include <skywalk/core/skywalk_var.h>

struct __kern_quantum;
struct __kern_packet;

/*
 * User packet pool hash bucket.  Packets allocated by user space are
 * kept in the hash table.  This allows the kernel to validate whether
 * or not a given packet object is valid or is already-freed, and thus
 * take the appropriate measure during internalize.
 */
struct kern_pbufpool_u_bkt {
	SLIST_HEAD(, __kern_quantum) upp_head;
};

struct kern_pbufpool_u_bft_bkt {
	SLIST_HEAD(, __kern_buflet_ext) upp_head;
};

struct kern_pbufpool {
	decl_lck_mtx_data(, pp_lock);
	uint32_t                pp_refcnt;
	uint32_t                pp_flags;
	uint16_t                pp_buflet_size;
	uint16_t                pp_max_frags;

	/*
	 * Caches
	 */
	struct skmem_cache      *pp_buf_cache;
	struct skmem_cache      *pp_kmd_cache;
	struct skmem_cache      *pp_kbft_cache;

	/*
	 * Regions
	 */
	struct skmem_region     *pp_buf_region;
	struct skmem_region     *pp_kmd_region;
	struct skmem_region     *pp_umd_region;
	struct skmem_region     *pp_ubft_region;
	struct skmem_region     *pp_kbft_region;

	/*
	 * User packet pool: packet metadata hash table
	 */
	struct kern_pbufpool_u_bkt *pp_u_hash_table;
	uint64_t                pp_u_bufinuse;

	/*
	 * User packet pool: buflet hash table
	 */
	struct kern_pbufpool_u_bft_bkt *pp_u_bft_hash_table;
	uint64_t                pp_u_bftinuse;

	void                    *pp_ctx;
	pbuf_ctx_retain_fn_t    pp_ctx_retain;
	pbuf_ctx_release_fn_t   pp_ctx_release;
	nexus_meta_type_t       pp_md_type;
	nexus_meta_subtype_t    pp_md_subtype;
	uint32_t                pp_midx_start;
	uint32_t                pp_bidx_start;
	pbufpool_name_t         pp_name;
	pbuf_seg_ctor_fn_t      pp_pbuf_seg_ctor;
	pbuf_seg_dtor_fn_t      pp_pbuf_seg_dtor;
};

/* valid values for pp_flags */
#define PPF_EXTERNAL            0x1     /* externally configured */
#define PPF_CLOSED              0x2     /* closed; awaiting final destruction */
#define PPF_MONOLITHIC          0x4     /* non slab-based buffer region */
/* buflet is truncated and may not contain the full payload */
#define PPF_TRUNCATED_BUF       0x8
#define PPF_KERNEL              0x10    /* kernel only, no user region(s) */
#define PPF_BUFFER_ON_DEMAND    0x20    /* attach buffers to packet on demand */
#define PPF_BATCH               0x40    /* capable of batch alloc/free */
#define PPF_DYNAMIC             0x80    /* capable of magazine resizing */

#define PP_KERNEL_ONLY(_pp)             \
	(((_pp)->pp_flags & PPF_KERNEL) != 0)

#define PP_HAS_TRUNCATED_BUF(_pp)               \
	(((_pp)->pp_flags & PPF_TRUNCATED_BUF) != 0)

#define PP_HAS_BUFFER_ON_DEMAND(_pp)            \
	(((_pp)->pp_flags & PPF_BUFFER_ON_DEMAND) != 0)

#define PP_BATCH_CAPABLE(_pp)           \
	(((_pp)->pp_flags & PPF_BATCH) != 0)

#define PP_DYNAMIC(_pp)                 \
	(((_pp)->pp_flags & PPF_DYNAMIC) != 0)

#define PP_LOCK(_pp)                    \
	lck_mtx_lock(&_pp->pp_lock)
#define PP_LOCK_ASSERT_HELD(_pp)        \
	LCK_MTX_ASSERT(&_pp->pp_lock, LCK_MTX_ASSERT_OWNED)
#define PP_LOCK_ASSERT_NOTHELD(_pp)     \
	LCK_MTX_ASSERT(&_pp->pp_lock, LCK_MTX_ASSERT_NOTOWNED)
#define PP_UNLOCK(_pp)                  \
	lck_mtx_unlock(&_pp->pp_lock)

__BEGIN_DECLS
extern int pp_init(void);
extern void pp_fini(void);
extern void pp_close(struct kern_pbufpool *);

/* create flags for pp_create() */
#define PPCREATEF_EXTERNAL      0x1     /* externally requested */
#define PPCREATEF_KERNEL_ONLY   0x2     /* kernel-only */
#define PPCREATEF_TRUNCATED_BUF 0x4     /* compat-only (buf is short) */
#define PPCREATEF_ONDEMAND_BUF  0x8     /* buf alloc/free is decoupled */
#define PPCREATEF_DYNAMIC       0x10    /* dynamic per-CPU magazines */

extern struct kern_pbufpool *pp_create(const char *name,
    struct skmem_region_params *buf_srp, struct skmem_region_params *kmd_srp,
    struct skmem_region_params *kbft_srp, struct skmem_region_params *ubft_srp,
    struct skmem_region_params *umd_srp, pbuf_seg_ctor_fn_t buf_seg_ctor,
    pbuf_seg_dtor_fn_t buf_seg_dtor, const void *ctx,
    pbuf_ctx_retain_fn_t ctx_retain, pbuf_ctx_release_fn_t ctx_release,
    uint32_t ppcreatef);
extern void pp_destroy(struct kern_pbufpool *);

extern int pp_init_upp(struct kern_pbufpool *, boolean_t);
extern void pp_insert_upp(struct kern_pbufpool *, struct __kern_quantum *,
    pid_t);
extern void pp_insert_upp_locked(struct kern_pbufpool *,
    struct __kern_quantum *, pid_t);
extern void pp_insert_upp_batch(struct kern_pbufpool *pp, pid_t pid,
    uint64_t *array, uint32_t num);
extern struct __kern_quantum *pp_remove_upp(struct kern_pbufpool *, obj_idx_t,
    int *);
extern struct __kern_quantum *pp_remove_upp_locked(struct kern_pbufpool *,
    obj_idx_t, int *);
extern struct __kern_quantum *pp_find_upp(struct kern_pbufpool *, obj_idx_t);
extern void pp_purge_upp(struct kern_pbufpool *, pid_t);
extern struct __kern_buflet *pp_remove_upp_bft(struct kern_pbufpool *,
    obj_idx_t, int *);
extern void pp_insert_upp_bft(struct kern_pbufpool *, struct __kern_buflet *,
    pid_t);
extern boolean_t pp_isempty_upp(struct kern_pbufpool *);

extern void pp_retain_locked(struct kern_pbufpool *);
extern void pp_retain(struct kern_pbufpool *);
extern boolean_t pp_release_locked(struct kern_pbufpool *);
extern boolean_t pp_release(struct kern_pbufpool *);

extern void pp_regions_params_adjust(struct skmem_region_params *,
    struct skmem_region_params *, struct skmem_region_params *,
    struct skmem_region_params *, struct skmem_region_params *,
    nexus_meta_type_t, nexus_meta_subtype_t, uint32_t, uint16_t,
    uint32_t, uint32_t);

extern uint64_t pp_alloc_packet(struct kern_pbufpool *, uint16_t, uint32_t);
extern uint64_t pp_alloc_packet_by_size(struct kern_pbufpool *, uint32_t,
    uint32_t);
extern int pp_alloc_packet_batch(struct kern_pbufpool *, uint16_t, uint64_t *,
    uint32_t *, boolean_t, alloc_cb_func_t, const void *, uint32_t);
extern int pp_alloc_pktq(struct kern_pbufpool *, uint16_t, struct pktq *,
    uint32_t, alloc_cb_func_t, const void *, uint32_t);
extern void pp_free_packet(struct kern_pbufpool *, uint64_t);
extern void pp_free_packet_batch(struct kern_pbufpool *, uint64_t *, uint32_t);
extern void pp_free_packet_single(struct __kern_packet *);
extern void pp_free_packet_chain(struct __kern_packet *, int *);
extern void pp_free_pktq(struct pktq *);
extern errno_t pp_alloc_buffer(const kern_pbufpool_t, mach_vm_address_t *,
    kern_segment_t *, kern_obj_idx_seg_t *, uint32_t);
extern void pp_free_buffer(const kern_pbufpool_t, mach_vm_address_t);
extern errno_t pp_alloc_buflet(struct kern_pbufpool *pp, kern_buflet_t *kbft,
    uint32_t skmflag);
extern errno_t pp_alloc_buflet_batch(struct kern_pbufpool *pp, uint64_t *array,
    uint32_t *size, uint32_t skmflag);
extern void pp_free_buflet(const kern_pbufpool_t, kern_buflet_t);

extern void pp_reap_caches(boolean_t);
__END_DECLS
#endif /* BSD_KERNEL_PRIVATE */
#endif /* !_SKYWALK_PACKET_PBUFPOOLVAR_H_ */
