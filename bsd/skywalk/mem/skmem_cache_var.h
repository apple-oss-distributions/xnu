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

#ifndef _SKYWALK_MEM_SKMEMCACHEVAR_H
#define _SKYWALK_MEM_SKMEMCACHEVAR_H

#ifdef BSD_KERNEL_PRIVATE
#include <skywalk/core/skywalk_var.h>
#include <skywalk/os_channel_private.h>
#include <kern/cpu_number.h>

/*
 * Buffer control.
 */
struct skmem_bufctl {
	SLIST_ENTRY(skmem_bufctl) bc_link;      /* bufctl linkage */
	void                    *bc_addr;       /* buffer obj address */
	void                    *bc_addrm;      /* mirrored buffer obj addr */
	struct skmem_slab       *bc_slab;       /* controlling slab */
	uint32_t                bc_lim;         /* buffer obj limit */
	uint32_t                bc_flags;       /* SKMEM_BUFCTL_* flags */
	uint32_t                bc_idx;         /* buffer index within slab */
	volatile uint32_t       bc_usecnt;      /* outstanding use */
};

#define SKMEM_BUFCTL_SHAREOK    0x1             /* supports sharing */

#define SKMEM_STACK_DEPTH       16              /* maximum audit stack depth */

#define SKMEM_CACHE_ALIGN       8               /* min guaranteed alignment */

/*
 * Alternative buffer control if SKM_MODE_AUDIT is set.
 */
struct skmem_bufctl_audit {
	SLIST_ENTRY(skmem_bufctl) bc_link;      /* bufctl linkage */
	void                    *bc_addr;       /* buffer address */
	void                    *bc_addrm;      /* mirrored buffer address */
	struct skmem_slab       *bc_slab;       /* controlling slab */
	uint32_t                bc_flags;       /* SKMEM_BUFCTL_* flags */
	uint32_t                bc_idx;         /* buffer index within slab */
	volatile uint32_t       bc_usecnt;      /* outstanding use */
	struct thread           *bc_thread;     /* thread doing transaction */
	uint32_t                bc_timestamp;   /* transaction time */
	uint32_t                bc_depth;       /* stack depth */
	void                    *bc_stack[SKMEM_STACK_DEPTH]; /* stack */
};

/*
 * Buffer control hash bucket.
 */
struct skmem_bufctl_bkt {
	SLIST_HEAD(, skmem_bufctl) bcb_head;    /* bufctl allocated list */
};

/*
 * Slab.
 */
struct skmem_slab {
	TAILQ_ENTRY(skmem_slab) sl_link;        /* slab freelist linkage */
	struct skmem_cache      *sl_cache;      /* controlling cache */
	void                    *sl_base;       /* base of allocated memory */
	void                    *sl_basem;      /* base of mirrored memory */
	struct sksegment        *sl_seg;        /* backing segment */
	struct sksegment        *sl_segm;       /* backing mirrored segment */
	SLIST_HEAD(, skmem_bufctl) sl_head;     /* bufctl free list */
	uint32_t                sl_refcnt;      /* outstanding allocations */
	uint32_t                sl_chunks;      /* # of buffers in slab */
};

#define SKMEM_SLAB_IS_PARTIAL(sl)       \
	((sl)->sl_refcnt > 0 && (sl)->sl_refcnt < (sl)->sl_chunks)

#define SKMEM_SLAB_MEMBER(sl, buf)      \
	(((size_t)(buf) - (size_t)(sl)->sl_base) < (sl)->sl_cache->skm_slabsize)

/*
 * Magazine type.
 */
struct skmem_magtype {
	int                     mt_magsize;     /* magazine size (# of objs) */
	int                     mt_align;       /* magazine alignment */
	size_t                  mt_minbuf;      /* all smaller bufs qualify */
	size_t                  mt_maxbuf;      /* no larger bufs qualify */
	struct skmem_cache      *mt_cache;      /* magazine cache */
	char                    mt_cname[64];   /* magazine cache name */
};

/*
 * Magazine.
 */
struct skmem_mag {
	SLIST_ENTRY(skmem_mag)  mg_link;        /* magazine linkage */
	struct skmem_magtype    *mg_magtype;    /* magazine type */
	void                    *mg_round[1];   /* one or more objs */
};

#define SKMEM_MAG_SIZE(n)       \
	offsetof(struct skmem_mag, mg_round[n])

/*
 * Magazine depot.
 */
struct skmem_maglist {
	SLIST_HEAD(, skmem_mag) ml_list;        /* magazine list */
	uint32_t                ml_total;       /* number of magazines */
	uint32_t                ml_min;         /* min since last update */
	uint32_t                ml_reaplimit;   /* max reapable magazines */
	uint64_t                ml_alloc;       /* allocations from this list */
};

/*
 * Per-CPU cache structure.
 */
struct skmem_cpu_cache {
	decl_lck_mtx_data(, cp_lock);
	struct skmem_mag        *cp_loaded;     /* currently filled magazine */
	struct skmem_mag        *cp_ploaded;    /* previously filled magazine */
	uint64_t                cp_alloc;       /* allocations from this cpu */
	uint64_t                cp_free;        /* frees to this cpu */
	int                     cp_rounds;      /* # of objs in filled mag */
	int                     cp_prounds;     /* # of objs in previous mag */
	int                     cp_magsize;     /* # of objs in a full mag */
} __attribute__((aligned(CHANNEL_CACHE_ALIGN_MAX)));

/*
 * Object's region information.
 *
 * This info is provided to skmem_ctor_fn_t() to assist master and
 * slave objects construction.  It is also provided separately via
 * skmem_cache_get_obj_info() when called on an object that's been
 * allocated from skmem_cache.  Information about slave object is
 * available only at constructor time.
 */
struct skmem_obj_info {
	void                    *oi_addr;       /* object address */
	struct skmem_bufctl     *oi_bc;         /* buffer control (master) */
	uint32_t                oi_size;        /* actual object size */
	obj_idx_t               oi_idx_reg;     /* object idx within region */
	obj_idx_t               oi_idx_seg;     /* object idx within segment */
} __attribute__((__packed__));

/*
 * Generic one-way linked list element structure.  This is used to
 * handle skmem_cache_batch_alloc() requests in order to chain the
 * allocated objects together before returning them to the caller.
 * It is also used when freeing a batch of packets by the caller of
 * skmem_cache_batch_free().  Note that this requires the region's
 * object to be at least the size of struct skmem_obj, as we store
 * this information at the beginning of each object in the chain.
 */
struct skmem_obj {
	/*
	 * Given that we overlay this structure on top of whatever
	 * structure that the object represents, the constructor must
	 * ensure that it reserves at least the size of a pointer
	 * at the top for the linkage.
	 */
	struct skmem_obj        *mo_next;       /* next object in the list */
	/*
	 * The following are used only for raw (unconstructed) objects
	 * coming out of the slab layer during allocations.  They are
	 * not touched otherwise by skmem_cache when the object resides
	 * in the magazine.  By utilizing this space, we avoid having
	 * to allocate temporary storage elsewhere.
	 */
	struct skmem_obj_info   mo_info;        /* object's info */
	struct skmem_obj_info   mo_minfo;       /* mirrored object's info */
};

#define SKMEM_OBJ_ADDR(_oi)     (_oi)->oi_addr
#define SKMEM_OBJ_BUFCTL(_oi)   (_oi)->oi_bc
#define SKMEM_OBJ_SIZE(_oi)     (_oi)->oi_size
#define SKMEM_OBJ_IDX_REG(_oi)  (_oi)->oi_idx_reg
#define SKMEM_OBJ_IDX_SEG(_oi)  (_oi)->oi_idx_seg
/* segment the object belongs to (only for master) */
#define SKMEM_OBJ_SEG(_oi)      (_oi)->oi_bc->bc_slab->sl_seg
/* offset of object relative to the object's own region */
#define SKMEM_OBJ_ROFF(_oi)     \
	((mach_vm_offset_t)(SKMEM_OBJ_SIZE(_oi) * SKMEM_OBJ_IDX_REG(_oi)))

typedef int (*skmem_ctor_fn_t)(struct skmem_obj_info *,
    struct skmem_obj_info *, void *, uint32_t);
typedef void (*skmem_dtor_fn_t)(void *, void *);
typedef void (*skmem_reclaim_fn_t)(void *);
typedef int (*skmem_slab_alloc_fn_t)(struct skmem_cache *,
    struct skmem_obj_info *, struct skmem_obj_info *, uint32_t);
typedef void (*skmem_slab_free_fn_t)(struct skmem_cache *, void *);

/*
 * Cache.
 */
struct skmem_cache {
	/*
	 * Commonly-accessed elements during alloc and free.
	 */
	uint32_t        skm_mode;               /* cache mode flags */
	skmem_ctor_fn_t skm_ctor;               /* object constructor */
	skmem_dtor_fn_t skm_dtor;               /* object destructor */
	skmem_reclaim_fn_t skm_reclaim;         /* cache reclaim */
	void            *skm_private;           /* opaque arg to callbacks */

	/*
	 * Depot.
	 */
	decl_lck_mtx_data(, skm_dp_lock);       /* protects depot layer */
	struct skmem_magtype *skm_magtype;      /* magazine type */
	struct skmem_maglist skm_full;          /* full magazines */
	struct skmem_maglist skm_empty;         /* empty magazines */

	/*
	 * Slab.
	 */
	decl_lck_mtx_data(, skm_sl_lock);       /* protects slab layer */
	skmem_slab_alloc_fn_t skm_slab_alloc;   /* slab allocate */
	skmem_slab_free_fn_t skm_slab_free;     /* slab free */
	size_t          skm_chunksize;          /* bufsize + alignment */
	size_t          skm_objsize;            /* actual obj size in slab */
	size_t          skm_slabsize;           /* size of a slab */
	size_t          skm_hash_initial;       /* initial hash table size */
	size_t          skm_hash_limit;         /* hash table size limit */
	size_t          skm_hash_shift;         /* get to interesting bits */
	size_t          skm_hash_mask;          /* hash table mask */
	struct skmem_bufctl_bkt *skm_hash_table; /* alloc'd buffer htable */
	TAILQ_HEAD(, skmem_slab) skm_sl_partial_list; /* partially-allocated */
	TAILQ_HEAD(, skmem_slab) skm_sl_empty_list;   /* fully-allocated */
	struct skmem_region *skm_region;        /* region source for slabs */

	/*
	 * Statistics.
	 */
	uint32_t        skm_cpu_mag_size;       /* current magazine size */
	uint32_t        skm_cpu_mag_resize;     /* # of magazine resizes */
	uint32_t        skm_cpu_mag_purge;      /* # of magazine purges */
	uint32_t        skm_cpu_mag_reap;       /* # of magazine reaps */
	uint64_t        skm_depot_contention;   /* mutex contention count */
	uint64_t        skm_depot_contention_prev; /* previous snapshot */
	uint32_t        skm_depot_full;         /* # of full magazines */
	uint32_t        skm_depot_empty;        /* # of empty magazines */
	uint32_t        skm_depot_ws_zero;      /* # of working set flushes */
	uint32_t        skm_sl_rescale;         /* # of hash table rescales */
	uint32_t        skm_sl_create;          /* slab creates */
	uint32_t        skm_sl_destroy;         /* slab destroys */
	uint32_t        skm_sl_alloc;           /* slab layer allocations */
	uint32_t        skm_sl_free;            /* slab layer frees */
	uint32_t        skm_sl_partial;         /* # of partial slabs */
	uint32_t        skm_sl_empty;           /* # of empty slabs */
	uint64_t        skm_sl_alloc_fail;      /* total failed allocations */
	uint64_t        skm_sl_bufinuse;        /* total unfreed buffers */
	uint64_t        skm_sl_bufmax;          /* max buffers ever */

	/*
	 * Cache properties.
	 */
	TAILQ_ENTRY(skmem_cache) skm_link;      /* cache linkage */
	char            skm_name[64];           /* cache name */
	uuid_t          skm_uuid;               /* cache uuid */
	size_t          skm_bufsize;            /* buffer size */
	size_t          skm_bufalign;           /* buffer alignment */
	size_t          skm_objalign;           /* object alignment */

	/*
	 * CPU layer, aligned at (maximum) cache line boundary.
	 */
	decl_lck_mtx_data(, skm_rs_lock);       /* protects resizing */
	struct thread    *skm_rs_owner;         /* resize owner */
	uint32_t        skm_rs_busy;            /* prevent resizing */
	uint32_t        skm_rs_want;            /* # of threads blocked */
	struct skmem_cpu_cache  skm_cpu_cache[1]
	__attribute__((aligned(CHANNEL_CACHE_ALIGN_MAX)));
};

#define SKMEM_CACHE_SIZE(n)     \
	offsetof(struct skmem_cache, skm_cpu_cache[n])

#define SKMEM_CPU_CACHE(c)                                      \
	((struct skmem_cpu_cache *)((void *)((char *)(c) +      \
	SKMEM_CACHE_SIZE(cpu_number()))))

/* valid values for skm_mode, set only by skmem_cache_create() */
#define SKM_MODE_NOMAGAZINES    0x00000001      /* disable magazines layer */
#define SKM_MODE_AUDIT          0x00000002      /* audit transactions */
#define SKM_MODE_NOREDIRECT     0x00000004      /* unaffected by defunct */
#define SKM_MODE_BATCH          0x00000008      /* supports batch alloc/free */
#define SKM_MODE_DYNAMIC        0x00000010      /* enable magazine resizing */
#define SKM_MODE_CLEARONFREE    0x00000020      /* zero-out upon slab free */
#define SKM_MODE_PSEUDO         0x00000040      /* external backing store */

#define SKM_MODE_BITS \
	"\020\01NOMAGAZINES\02AUDIT\03NOREDIRECT\04BATCH\05DYNAMIC"     \
	"\06CLEARONFREE\07PSEUDO"

/*
 * Valid flags for sk{mem,region}_alloc().  SKMEM_FAILOK is valid only if
 * SKMEM_SLEEP is set, i.e. SKMEM_{NOSLEEP,FAILOK} are mutually exclusive.
 * If set, SKMEM_FAILOK indicates that the segment allocation may fail,
 * and that the cache layer would handle the retries rather than blocking
 * inside the region allocator.
 */
#define SKMEM_SLEEP             0x0     /* can block for memory; won't fail */
#define SKMEM_NOSLEEP           0x1     /* cannot block for memory; may fail */
#define SKMEM_PANIC             0x2     /* panic upon allocation failure */
#define SKMEM_FAILOK            0x4     /* can fail for blocking alloc */

/* valid flag values for skmem_cache_create() */
#define SKMEM_CR_NOMAGAZINES    0x1     /* disable magazines layer */
#define SKMEM_CR_BATCH          0x2     /* support batch alloc/free */
#define SKMEM_CR_DYNAMIC        0x4     /* enable magazine resizing */
#define SKMEM_CR_CLEARONFREE    0x8     /* zero-out upon slab free */

__BEGIN_DECLS
/*
 * Given a buffer control, add a use count to it.
 */
__attribute__((always_inline))
static inline void
skmem_bufctl_use(struct skmem_bufctl *bc)
{
	uint32_t old, new;

	os_atomic_rmw_loop(&bc->bc_usecnt, old, new, relaxed, {
		new = old + 1;
		VERIFY(new != 0);
		ASSERT(new == 1 || (bc->bc_flags & SKMEM_BUFCTL_SHAREOK));
	});
}

/*
 * Given a buffer control, remove a use count from it (returns new value).
 */
__attribute__((always_inline))
static inline uint32_t
skmem_bufctl_unuse(struct skmem_bufctl *bc)
{
	uint32_t old, new;

	os_atomic_rmw_loop(&bc->bc_usecnt, old, new, relaxed, {
		new = old - 1;
		VERIFY(old != 0);
		ASSERT(old == 1 || (bc->bc_flags & SKMEM_BUFCTL_SHAREOK));
	});

	return new;
}

extern void skmem_cache_pre_init(void);
extern void skmem_cache_init(void);
extern void skmem_cache_fini(void);
extern struct skmem_cache *skmem_cache_create(const char *, size_t, size_t,
    skmem_ctor_fn_t, skmem_dtor_fn_t, skmem_reclaim_fn_t, void *,
    struct skmem_region *, uint32_t);
extern void skmem_cache_destroy(struct skmem_cache *);
extern void *skmem_cache_alloc(struct skmem_cache *, uint32_t);
extern uint32_t skmem_cache_batch_alloc(struct skmem_cache *,
    struct skmem_obj **list, uint32_t, uint32_t);
extern void skmem_cache_free(struct skmem_cache *, void *);
extern void skmem_cache_batch_free(struct skmem_cache *, struct skmem_obj *);
extern void skmem_cache_reap_now(struct skmem_cache *, boolean_t);
extern void skmem_cache_reap(void);
extern void skmem_reap_caches(boolean_t);
extern void skmem_cache_get_obj_info(struct skmem_cache *, void *,
    struct skmem_obj_info *, struct skmem_obj_info *);
extern uint32_t skmem_cache_magazine_max(uint32_t);
extern boolean_t skmem_allow_magazines(void);
#if (DEVELOPMENT || DEBUG)
extern void skmem_cache_test_start(uint32_t);
extern void skmem_cache_test_stop(void);
#endif /* (DEVELOPMENT || DEBUG) */
__END_DECLS
#endif /* BSD_KERNEL_PRIVATE */
#endif /* _SKYWALK_MEM_SKMEMCACHEVAR_H */
