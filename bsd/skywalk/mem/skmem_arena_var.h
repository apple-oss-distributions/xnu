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

#ifndef _SKYWALK_MEM_SKMEMARENAVAR_H
#define _SKYWALK_MEM_SKMEMARENAVAR_H

#ifdef BSD_KERNEL_PRIVATE
#include <skywalk/core/skywalk_var.h>

/*
 * Arena types.
 */
typedef enum {
	SKMEM_ARENA_TYPE_NEXUS,                 /* skmem_arena_nexus */
	SKMEM_ARENA_TYPE_NECP,                  /* skmem_arena_necp */
	SKMEM_ARENA_TYPE_SYSTEM,                /* skmem_arena_system */
} skmem_arena_type_t;

struct skmem_arena_mmap_info;

/*
 * Structure common to all arena types.
 */
struct skmem_arena {
	decl_lck_mtx_data(, ar_lock);           /* arena lock */
	uint32_t                ar_refcnt;      /* reference count */

	/*
	 * Arena properties.
	 */
	TAILQ_ENTRY(skmem_arena) ar_link;       /* skmem_region linkage */
	char                    ar_name[64];    /* arena name */
	skmem_arena_type_t      ar_type;        /* arena type */
	uint32_t                ar_flags;       /* ARF_* */
	size_t                  ar_zsize;       /* zone object size */
	struct zone             *ar_zone;       /* owning zone */
	IOSKArenaRef            ar_ar;          /* backing IOSKArena */

	/*
	 * Regions.
	 */
	struct skmem_region     *ar_regions[SKMEM_REGIONS]; /* arena regions */

	/*
	 * ar_mapsize gets set the first time the arena is mapped to a task;
	 * it is an estimate since we don't update it on subsequent mappings.
	 * We use it only for statistics purposes.
	 */
	mach_vm_size_t          ar_mapsize;     /* estimated mmap size */
	uint32_t                ar_mapcnt;      /* # of active mmap on arena */
	uint32_t                ar_maprdrcnt;   /* # of redirected mmap */
	SLIST_HEAD(, skmem_arena_mmap_info) ar_map_head; /* list of mmap info */
};

/* valid values for ar_flags */
#define ARF_ACTIVE              0x1             /* arena is active */
#define ARF_DEFUNCT             (1U << 31)      /* arena is defunct */

#define ARF_BITS                "\020\01ACTIVE\040DEFUNCT"

#define AR_LOCK(_ar)                    \
	lck_mtx_lock(&(_ar)->ar_lock)
#define AR_LOCK_ASSERT_HELD(_ar)        \
	LCK_MTX_ASSERT(&(_ar)->ar_lock, LCK_MTX_ASSERT_OWNED)
#define AR_LOCK_ASSERT_NOTHELD(_ar)     \
	LCK_MTX_ASSERT(&(_ar)->ar_lock, LCK_MTX_ASSERT_NOTOWNED)
#define AR_UNLOCK(_ar)                  \
	lck_mtx_unlock(&(_ar)->ar_lock)

#define AR_MEM_TOTAL(_ar, _id)          \
	((_ar)->ar_regions[_id]->skr_memtotal)
#define AR_MEM_INUSE(_ar, _id)          \
	((_ar)->ar_regions[_id]->skr_meminuse)
#define AR_MEM_WIRED_INUSE(_ar, _id)    \
	((_ar)->ar_regions[_id]->skr_w_meminuse)
#define AR_MEM_SEGSIZE(_ar, _id)        \
	((_ar)->ar_regions[_id]->skr_seg_size)
#define AR_MEM_SEGCNT(_ar, _id)         \
	((_ar)->ar_regions[_id]->skr_seg_max_cnt)
#define AR_MEM_OBJCNT_R(_ar, _id)       \
	((_ar)->ar_regions[_id]->skr_r_obj_cnt)
#define AR_MEM_OBJCNT_C(_ar, _id)       \
	((_ar)->ar_regions[_id]->skr_c_obj_cnt)
#define AR_MEM_OBJSIZE_R(_ar, _id)      \
	((_ar)->ar_regions[_id]->skr_r_obj_size)
#define AR_MEM_OBJSIZE_C(_ar, _id)      \
	((_ar)->ar_regions[_id]->skr_c_obj_size)

/*
 * Arena Task Map Information.
 */
struct skmem_arena_mmap_info {
	SLIST_ENTRY(skmem_arena_mmap_info)      ami_link;
	struct skmem_arena      *ami_arena;     /* backing arena */
	IOSKMapperRef           ami_mapref;     /* IOSKMapper handle */
	task_t                  ami_maptask;    /* task where it's mapped to */
	mach_vm_address_t       ami_mapaddr;    /* start address in task */
	mach_vm_size_t          ami_mapsize;    /* size of memory map */
	boolean_t               ami_redirect;   /* map is redirected */
};

/*
 * Nexus Adapter Arena.
 */
struct skmem_arena_nexus {
	struct skmem_arena      arn_cmn;        /* common arena struct */

	struct kern_pbufpool    *arn_rx_pp;     /* rx ppool handle */
	struct kern_pbufpool    *arn_tx_pp;     /* tx ppool handle */
	uint32_t                arn_mode;       /* mode flags */
	nexus_meta_type_t       arn_md_type;    /* mdata regions type */
	nexus_meta_subtype_t    arn_md_subtype; /* mdata regions subtype */
	/*
	 * For arenas used by adapters with external ring, slot callbacks or
	 * invocations via KPIs accessing kernel slot descriptors, we need to
	 * make sure the ksd region is kept intact during defunct.  A non-zero
	 * value indicates that we leave ksd region alone, until the time when
	 * the arena is torn down for good.
	 */
	int                     arn_ksd_nodefunct;

	/*
	 * Caches.
	 */
	struct skmem_cache      *arn_schema_cache; /* schema object cache */
	struct skmem_cache      *arn_ring_cache;   /* ring object cache */
	struct skmem_cache      *arn_txaksd_cache; /* tx/alloc slots cache */
	struct skmem_cache      *arn_rxfksd_cache; /* rx/free slots cache */

	/*
	 * Statistics.
	 *
	 * This may be NULL if the arena was created without a statistics
	 * region.  Otherwise, this value contains the segment address of
	 * the object that we allocate from that region.  An arena contains
	 * at most one monolithic stats region.
	 */
	void                    *arn_stats_obj; /* adapter stats object */

	/*
	 * Flow advisory.
	 *
	 * This may be NULL if the arena was created without a flow advisory
	 * region.  Otherwise, this value contains the segment address of
	 * the object that we allocate from that region.  An arena contains
	 * at most one monolithic flow advisory region.
	 */
	struct __flowadv_entry  *arn_flowadv_obj;

	/*
	 * Nexus advisory.
	 *
	 * This may be NULL if the arena was created without a nexus advisory
	 * region.  Otherwise, this value contains the segment address of
	 * the object that we allocate from that region.  An arena contains
	 * at most one monolithic nexus advisory region, that is nexus-wide.
	 */
	void                    *arn_nexusadv_obj;
};

/* valid flags for arn_mode */
#define AR_NEXUS_MODE_EXTERNAL_PPOOL    0x1     /* external packet pool */

/*
 * Given an arena, return its nexus variant (if applicable).
 */
__attribute__((always_inline))
static inline struct skmem_arena_nexus *
skmem_arena_nexus(struct skmem_arena *ar)
{
	if (__improbable(ar->ar_type != SKMEM_ARENA_TYPE_NEXUS)) {
		return NULL;
	}

	return (struct skmem_arena_nexus *)ar;
}

/*
 * NECP Arena.
 */
struct skmem_arena_necp {
	struct skmem_arena      arc_cmn;        /* common arena struct */

	/*
	 * Caches.
	 */
	/* stats cache (kernel master mirrored with slave ustats) */
	struct skmem_cache      *arc_kstats_cache;
};

/*
 * System Arena.
 */
struct skmem_arena_system {
	struct skmem_arena      ars_cmn;        /* common arena struct */

	/*
	 * sysctls.
	 *
	 * This value contains the kernel virtual address of the system-wide
	 * sysctls object.  This object is persistent, i.e. it does not get
	 * allocated or freed along with the arena.
	 */
	void                    *ars_sysctls_obj;
	size_t                  ars_sysctls_objsize;
};

struct kern_nexus_advisory;

__BEGIN_DECLS
extern void skmem_arena_init(void);
extern void skmem_arena_fini(void);
extern struct skmem_arena *skmem_arena_create_for_nexus(
	const struct nexus_adapter *, struct skmem_region_params[SKMEM_REGIONS],
	struct kern_pbufpool **, struct kern_pbufpool **, boolean_t, boolean_t,
	struct kern_nexus_advisory *, int *);
extern void skmem_arena_nexus_sd_set_noidle(struct skmem_arena_nexus *, int);
extern boolean_t skmem_arena_nexus_sd_idle(struct skmem_arena_nexus *);

extern struct skmem_arena *skmem_arena_create_for_necp(const char *,
    struct skmem_region_params *, struct skmem_region_params *, int *);
extern struct skmem_arena_necp *skmem_arena_necp(struct skmem_arena *);

extern struct skmem_arena *skmem_arena_create_for_system(const char *, int *);
extern struct skmem_arena_system *skmem_arena_system(struct skmem_arena *);
extern void *skmem_arena_system_sysctls_obj_addr(struct skmem_arena *);
extern size_t skmem_arena_system_sysctls_obj_size(struct skmem_arena *);

extern void skmem_arena_retain(struct skmem_arena *);
extern boolean_t skmem_arena_release(struct skmem_arena *);
extern int skmem_arena_mmap(struct skmem_arena *, struct proc *,
    struct skmem_arena_mmap_info *);
extern void skmem_arena_munmap(struct skmem_arena *,
    struct skmem_arena_mmap_info *);
extern void skmem_arena_munmap_channel(struct skmem_arena *,
    struct kern_channel *);
extern int skmem_arena_mredirect(struct skmem_arena *,
    struct skmem_arena_mmap_info *, struct proc *, boolean_t *);
extern int skmem_arena_defunct(struct skmem_arena *);
extern void skmem_arena_get_stats(struct skmem_arena *, uint64_t *,
    uint64_t *);
extern mach_vm_offset_t skmem_arena_get_region_offset(struct skmem_arena *,
    skmem_region_id_t);
extern void skmem_arena_reap(struct skmem_arena *, boolean_t);
__END_DECLS
#endif /* BSD_KERNEL_PRIVATE */
#endif /* _SKYWALK_MEM_SKMEMARENAVAR_H */
