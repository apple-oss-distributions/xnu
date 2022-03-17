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

#ifndef _SKYWALK_MEM_SKMEMREGIONVAR_H
#define _SKYWALK_MEM_SKMEMREGIONVAR_H

#ifdef BSD_KERNEL_PRIVATE
#include <skywalk/core/skywalk_var.h>
#include <skywalk/os_nexus_private.h>

/*
 * Segment types.
 */
typedef enum {
	SKSEG_TYPE_INVALID = 0,
	SKSEG_TYPE_ALLOC,               /* segment is in skr_hash_table */
	SKSEG_TYPE_FREE,                /* segment is in skr_segfree */
	SKSEG_TYPE_DESTROYED            /* in process of being destroyed */
} sksegment_type_t;

/*
 * Segment memory states.
 */
typedef enum {
	SKSEG_STATE_INVALID = 0,
	SKSEG_STATE_DETACHED,           /* not backed by a IOBMD */
	SKSEG_STATE_MAPPED,             /* mapped (IOBMD non-volatile) */
	SKSEG_STATE_MAPPED_WIRED,       /* mapped (IOBMD non-volatile+wired) */
} sksegment_state_t;

struct skmem_region;

/*
 * Segment.
 *
 * Segments that are available for use can be found in the doubly-linked
 * list (skr_seg_free) as well as the red-black tree (skr_seg_tfree).
 * The latter is used to faciliate finding a segment by its index, which
 * is required when allocating a segment from a mirrored region.
 *
 * Allocated segments are inserted into the allocated-address hash chain;
 * they don't exist in any tree at that point.
 */
struct sksegment {
	TAILQ_ENTRY(sksegment)  sg_link;        /* sksegment linkage */
	RB_ENTRY(sksegment)     sg_node;        /* sksegment node in tree */
	struct skmem_region     *sg_region;     /* controlling region */

	/*
	 * If attached to a IOBMD, sg_{start,end} will be valid.
	 */
	IOSKMemoryBufferRef     sg_md;          /* backing IOBMD */
	mach_vm_address_t       sg_start;       /* start address (inclusive) */
	mach_vm_address_t       sg_end;         /* end address (exclusive) */

	uint32_t                sg_index;       /* index in skr_seg[] */
	sksegment_type_t        sg_type;        /* segment type */
	sksegment_state_t       sg_state;       /* segment state */
};

#define SKSEGMENT_IN_FREELIST(_sg)                              \
	((_sg)->sg_link.tqe_next != NULL ||                     \
	(_sg)->sg_link.tqe_prev != NULL)

/*
 * Segment hash bucket.
 */
struct sksegment_bkt {
	TAILQ_HEAD(, sksegment) sgb_head;       /* sksegment allocated list */
};

/*
 * Region IDs.
 *
 * When adding or removing regions, adjust the templates in skmem.c
 * accordingly.  Do not reorder regions without making the appropriate
 * changes in the code that relies on the existing arena layout.
 */
typedef enum {
	/*
	 * The following are user task mappable.
	 *
	 * XXX: When adding new ones, ensure that they get added before
	 * SKMEM_REGION_GUARD_TAIL, and make the appropriate changes in
	 * skmem_region_init().
	 */
	SKMEM_REGION_GUARD_HEAD = 0,    /* leading guard page(s) */
	SKMEM_REGION_SCHEMA,            /* channel layout */
	SKMEM_REGION_RING,              /* rings */
	SKMEM_REGION_BUF,               /* rx/tx buffer */
	SKMEM_REGION_RXBUF,             /* rx only buffers */
	SKMEM_REGION_TXBUF,             /* tx only buffers */
	SKMEM_REGION_UMD,               /* userland metadata */
	SKMEM_REGION_TXAUSD,            /* tx/alloc/event user slot descriptors */
	SKMEM_REGION_RXFUSD,            /* rx/free user slot descriptors */
	SKMEM_REGION_UBFT,              /* userland buflet metadata */
	SKMEM_REGION_USTATS,            /* statistics */
	SKMEM_REGION_FLOWADV,           /* flow advisories */
	SKMEM_REGION_NEXUSADV,          /* nexus advisories */
	SKMEM_REGION_SYSCTLS,           /* sysctl */
	SKMEM_REGION_GUARD_TAIL,        /* trailing guard page(s) */

	/*
	 * The following are NOT user task mappable.
	 */
	SKMEM_REGION_KMD,               /* rx/tx kernel metadata */
	SKMEM_REGION_RXKMD,             /* rx only kernel metadata */
	SKMEM_REGION_TXKMD,             /* tx only kernel metadata */
	SKMEM_REGION_KBFT,              /* rx/tx kernel buflet metadata */
	SKMEM_REGION_RXKBFT,            /* rx only kernel buflet metadata */
	SKMEM_REGION_TXKBFT,            /* tx only kernel buflet metadata */
	SKMEM_REGION_TXAKSD,            /* tx/alloc/event kernel slot descriptors */
	SKMEM_REGION_RXFKSD,            /* rx/free kernel slot descriptors */
	SKMEM_REGION_KSTATS,            /* kernel statistics snapshot */
	SKMEM_REGION_INTRINSIC,         /* intrinsic objects */

	SKMEM_REGIONS                   /* max */
} skmem_region_id_t;

#define SKMEM_PP_REGIONS 11
extern const skmem_region_id_t skmem_pp_region_ids[SKMEM_PP_REGIONS];

/*
 * Region parameters structure.  Based on requested object parameters,
 * skmem_region_params_config() will compute the segment parameters as
 * well as the configured object parameters.
 */
struct skmem_region_params {
	/*
	 * Region parameters.
	 */
	const char              *srp_name;      /* (i) region name */
	skmem_region_id_t       srp_id;         /* (i) region identifier */
	uint32_t                srp_cflags;     /* (i) region creation flags */
	uint32_t                srp_r_seg_size; /* (i) requested seg size */
	uint32_t                srp_c_seg_size; /* (o) configured seg size */
	uint32_t                srp_seg_cnt;    /* (o) number of segments */

	/*
	 * Object parameters.
	 */
	uint32_t                srp_r_obj_size; /* (i) requested obj size */
	uint32_t                srp_r_obj_cnt;  /* (i) requested obj count */
	uint32_t                srp_c_obj_size; /* (o) configured obj size */
	uint32_t                srp_c_obj_cnt;  /* (o) configured obj count */
	size_t                  srp_align;      /* (i) object alignment */

	/*
	 * SKMEM_REGION_{UMD,KMD} specific parameters.
	 */
	nexus_meta_type_t       srp_md_type;    /* (i) metadata type */
	nexus_meta_subtype_t    srp_md_subtype; /* (i) metadata subtype */
	uint16_t                srp_max_frags;  /* (i) max frags per packet */
};

typedef void (*sksegment_ctor_fn_t)(struct sksegment *,
    IOSKMemoryBufferRef, void *);
typedef void (*sksegment_dtor_fn_t)(struct sksegment *,
    IOSKMemoryBufferRef, void *);

/*
 * Region.
 */
struct skmem_region {
	decl_lck_mtx_data(, skr_lock);          /* region lock */

	/*
	 * Statistics.
	 */
	uint64_t                skr_meminuse;   /* memory in use */
	uint64_t                skr_w_meminuse; /* wired memory in use */
	uint64_t                skr_memtotal;   /* total memory in region */
	uint64_t                skr_alloc;      /* number of allocations */
	uint64_t                skr_free;       /* number of frees */
	uint32_t                skr_seginuse;   /* total unfreed segments */
	uint32_t                skr_rescale;    /* # of hash table rescales */

	/*
	 * Region properties.
	 */
	struct skmem_region_params skr_params;  /* region parameters */
#define skr_id          skr_params.srp_id       /* region ID */
#define skr_cflags      skr_params.srp_cflags   /* creation flags */
	TAILQ_ENTRY(skmem_region) skr_link;     /* skmem_region linkage */
	char                    skr_name[64];   /* region name */
	uuid_t                  skr_uuid;       /* region uuid */
	uint32_t                skr_mode;       /* skmem_region mode flags */
	uint32_t                skr_size;       /* total region size */
	IOSKMemoryBufferSpec    skr_bufspec;    /* IOSKMemoryBuffer spec */
	IOSKRegionSpec          skr_regspec;    /* IOSKRegion spec */
	IOSKRegionRef           skr_reg;        /* backing IOSKRegion */
	struct zone             *skr_zreg;      /* backing zone (pseudo mode) */
	void                    *skr_private;   /* opaque arg to callbacks */
	struct skmem_cache      *skr_cache;     /* client slab/cache layer */

	/*
	 * Objects.
	 */
#define skr_r_obj_size  skr_params.srp_r_obj_size /* requested obj size */
#define skr_r_obj_cnt   skr_params.srp_r_obj_cnt  /* requested obj count */
#define skr_c_obj_size  skr_params.srp_c_obj_size /* configured obj size */
#define skr_c_obj_cnt   skr_params.srp_c_obj_cnt  /* configured obj count */
#define skr_align       skr_params.srp_align      /* object alignment */
#define skr_md_type     skr_params.srp_md_type    /* metadata type */
#define skr_md_subtype  skr_params.srp_md_subtype /* metadata subtype */
#define skr_max_frags   skr_params.srp_max_frags  /* max number of buflets */

	/*
	 * Segment.
	 */
	sksegment_ctor_fn_t     skr_seg_ctor;   /* segment constructor */
	sksegment_dtor_fn_t     skr_seg_dtor;   /* segment destructor */
	uint32_t                skr_seg_objs;   /* # of objects per segment */
#define skr_seg_size    skr_params.srp_c_seg_size /* configured segment size */
#define skr_seg_max_cnt skr_params.srp_seg_cnt  /* max # of segments */
	uint32_t                skr_seg_bmap_len; /* # of skr_seg_bmap */
	bitmap_t                *skr_seg_bmap;  /* segment bitmaps */
	uint32_t                skr_seg_free_cnt; /* # of free segments */
	uint32_t                skr_hash_initial; /* initial hash table size */
	uint32_t                skr_hash_limit; /* hash table size limit */
	uint32_t                skr_hash_shift; /* get to interesting bits */
	uint32_t                skr_hash_mask;  /* hash table mask */
	struct sksegment_bkt    *skr_hash_table; /* alloc'd segment htable */
	TAILQ_HEAD(segfreehead, sksegment) skr_seg_free; /* free segment list */
	RB_HEAD(segtfreehead, sksegment) skr_seg_tfree; /* free tree */
	uint32_t                skr_seg_waiters; /* # of waiter threads */

	/*
	 * Region.
	 */
	uint32_t                skr_refcnt;     /* reference count */

	/*
	 * Mirror.
	 */
	struct skmem_region     *skr_mirror;
};

#define SKR_LOCK(_skr)                  \
	lck_mtx_lock(&(_skr)->skr_lock)
#define SKR_LOCK_ASSERT_HELD(_skr)      \
	LCK_MTX_ASSERT(&(_skr)->skr_lock, LCK_MTX_ASSERT_OWNED)
#define SKR_LOCK_ASSERT_NOTHELD(_skr)   \
	LCK_MTX_ASSERT(&(_skr)->skr_lock, LCK_MTX_ASSERT_NOTOWNED)
#define SKR_UNLOCK(_skr)                \
	lck_mtx_unlock(&(_skr)->skr_lock)

/* valid values for skr_mode */
#define SKR_MODE_NOREDIRECT     0x1     /* unaffect by defunct */
#define SKR_MODE_MMAPOK         0x2     /* can be mapped to user task */
#define SKR_MODE_KREADONLY      0x4     /* kernel read only */
#define SKR_MODE_UREADONLY      0x8     /* if user map, map it read-only */
#define SKR_MODE_PERSISTENT     0x10    /* memory stays non-volatile */
#define SKR_MODE_MONOLITHIC     0x20    /* monolithic region */
#define SKR_MODE_NOMAGAZINES    0x40    /* disable magazines layer */
#define SKR_MODE_NOCACHE        0x80    /* caching-inhibited */
#define SKR_MODE_SEGPHYSCONTIG  0x100   /* phys. contiguous segment */
#define SKR_MODE_SHAREOK        0x200   /* allow object sharing */
#define SKR_MODE_IODIR_IN       0x400   /* I/O direction In */
#define SKR_MODE_IODIR_OUT      0x800   /* I/O direction Out */
#define SKR_MODE_GUARD          0x1000  /* guard pages region */
#define SKR_MODE_PUREDATA       0x2000  /* purely data; no pointers */
#define SKR_MODE_PSEUDO         0x4000  /* external backing store */
#define SKR_MODE_SLAB           (1U << 30) /* backend for slab layer */
#define SKR_MODE_MIRRORED       (1U << 31) /* controlled by another region */

#define SKR_MODE_BITS           \
	"\020\01NOREDIRECT\02MMAPOK\03KREADONLY\04UREADONLY"    \
	"\05PERSISTENT\06MONOLITHIC\07NOMAGAZINES\10NOCACHE"    \
	"\11SEGPHYSCONTIG\012SHAREOK\013IODIR_IN\014IODIR_OUT"  \
	"\015GUARD\016PUREDATA\017PSEUDO\037SLAB\040MIRRORED"

/* valid values for skmem_region_create() */
#define SKMEM_REGION_CR_NOREDIRECT      0x1     /* unaffected by defunct */
#define SKMEM_REGION_CR_MMAPOK          0x2     /* can be mapped to user task */
#define SKMEM_REGION_CR_KREADONLY       0x4     /* kernel space readonly */
#define SKMEM_REGION_CR_UREADONLY       0x8     /* if user map, map it RO */
#define SKMEM_REGION_CR_PERSISTENT      0x10    /* memory stays non-volatile */
#define SKMEM_REGION_CR_MONOLITHIC      0x20    /* monolithic region */
#define SKMEM_REGION_CR_NOMAGAZINES     0x40    /* disable magazines layer */
#define SKMEM_REGION_CR_NOCACHE         0x80    /* caching-inhibited */
#define SKMEM_REGION_CR_SEGPHYSCONTIG   0x100   /* phys. contiguous segment */
#define SKMEM_REGION_CR_SHAREOK         0x200   /* allow object sharing */
#define SKMEM_REGION_CR_IODIR_IN        0x400   /* I/O direction in */
#define SKMEM_REGION_CR_IODIR_OUT       0x800   /* I/O direction out */
#define SKMEM_REGION_CR_GUARD           0x1000  /* guard pages region */
#define SKMEM_REGION_CR_PUREDATA        0x2000  /* purely data; no pointers */
#define SKMEM_REGION_CR_PSEUDO          0x4000  /* external backing store */

#define SKMEM_REGION_CR_BITS    \
	"\020\01NOREDIRECT\02MMAPOK\03KREADONLY\04UREADONLY"    \
	"\05PERSISTENT\06MONOLITHIC\07NOMAGAZINES\10NOCACHE"    \
	"\11SEGPHYSCONTIG\012SHAREOK\013IODIR_IN\014IODIR_OUT"  \
	"\015GUARD\016PUREDATA\017PSEUDO"

__BEGIN_DECLS
extern void skmem_region_init(void);
extern void skmem_region_fini(void);
extern void skmem_region_reap_caches(boolean_t);
extern void skmem_region_params_config(struct skmem_region_params *);
extern struct skmem_region *skmem_region_create(const char *,
    struct skmem_region_params *, sksegment_ctor_fn_t, sksegment_dtor_fn_t,
    void *);
extern void skmem_region_mirror(struct skmem_region *, struct skmem_region *);
extern void skmem_region_slab_config(struct skmem_region *,
    struct skmem_cache *);
extern void *skmem_region_alloc(struct skmem_region *, void **,
    struct sksegment **, struct sksegment **, uint32_t);
extern void skmem_region_free(struct skmem_region *, void *, void *);
extern void skmem_region_retain(struct skmem_region *);
extern boolean_t skmem_region_release(struct skmem_region *);
extern mach_vm_address_t skmem_region_obj_lookup(struct skmem_region *,
    uint32_t);
extern int skmem_region_get_info(struct skmem_region *, uint32_t *,
    struct sksegment **);
extern boolean_t skmem_region_for_pp(skmem_region_id_t);
extern void skmem_region_get_stats(struct skmem_region *,
    struct sk_stats_region *);
#if (DEVELOPMENT || DEBUG)
extern uint64_t skmem_region_get_mtbf(void);
/*
 * Reasonable boundaries for MTBF that would make sense for testing,
 * in milliseconds; why not pick a couple of Mersenne p numbers?
 */
#define SKMEM_REGION_MTBF_MIN           2       /* almost 2 msec */
#define SKMEM_REGION_MTBF_MAX           3021377 /* almost 1 hour */
extern void skmem_region_set_mtbf(uint64_t);
#endif /* (DEVELOPMENT || DEBUG) */
#if SK_LOG
extern const char *skmem_region_id2name(skmem_region_id_t);
#endif /* SK_LOG */
__END_DECLS
#endif /* BSD_KERNEL_PRIVATE */
#endif /* _SKYWALK_MEM_SKMEMVAR_H */
