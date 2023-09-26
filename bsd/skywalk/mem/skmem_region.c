/*
 * Copyright (c) 2016-2022 Apple Inc. All rights reserved.
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

/* BEGIN CSTYLED */
/*
 * A region represents a collection of one or more similarly-sized memory
 * segments, each of which is a contiguous range of integers.  A segment
 * is either allocated or free, and is treated as disjoint from all other
 * segments.  That is, the contiguity applies only at the segment level,
 * and a region with multiple segments is not contiguous at the region level.
 * A segment always belongs to the segment freelist, or the allocated-address
 * hash chain, as described below.
 *
 * The optional SKMEM_REGION_CR_NOREDIRECT flag indicates that the region
 * stays intact even after a defunct.  Otherwise, the segments belonging
 * to the region will be freed at defunct time, and the span covered by
 * the region will be redirected to zero-filled anonymous memory.
 *
 * Memory for a region is always created as pageable and purgeable.  It is
 * the client's responsibility to prepare (wire) it, and optionally insert
 * it to the IOMMU, at segment construction time.  When the segment is
 * freed, the client is responsible for removing it from IOMMU (if needed),
 * and complete (unwire) it.
 *
 * When the region is created with SKMEM_REGION_CR_PERSISTENT, the memory
 * is immediately wired upon allocation (segment removed from freelist).
 * It gets unwired when memory is discarded (segment inserted to freelist).
 *
 * The chronological life cycle of a segment is as such:
 *
 *    SKSEG_STATE_DETACHED
 *        SKSEG_STATE_{MAPPED,MAPPED_WIRED}
 *            [segment allocated, useable by client]
 *              ...
 *            [client frees segment]
 *        SKSEG_STATE_{MAPPED,MAPPED_WIRED}
 *	  [reclaim]
 *    SKSEG_STATE_DETACHED
 *
 * The region can also be marked as user-mappable (SKMEM_REGION_CR_MMAPOK);
 * this allows it to be further marked with SKMEM_REGION_CR_UREADONLY to
 * prevent modifications by the user task.  Only user-mappable regions will
 * be considered for inclusion during skmem_arena_mmap().
 *
 * Every skmem allocator has a region as its slab supplier.  Each slab is
 * exactly a segment.  The allocator uses skmem_region_{alloc,free}() to
 * create and destroy slabs.
 *
 * A region may be mirrored by another region; the latter acts as the master
 * controller for both regions.  Mirrored (slave) regions cannot be used
 * directly by the skmem allocator.  Region mirroring technique is used for
 * managing shadow objects {umd,kmd} and {usd,ksd}, where an object in one
 * region has the same size and lifetime as its shadow counterpart.
 *
 * CREATION/DESTRUCTION:
 *
 *   At creation time, all segments are allocated and are immediately inserted
 *   into the freelist.  Allocating a purgeable segment has very little cost,
 *   as it is not backed by physical memory until it is accessed.  Immediate
 *   insertion into the freelist causes the mapping to be further torn down.
 *
 *   At destruction time, the freelist is emptied, and each segment is then
 *   destroyed.  The system will assert if it detects there are outstanding
 *   segments not yet returned to the region (not freed by the client.)
 *
 * ALLOCATION:
 *
 *   Allocating involves searching the freelist for a segment; if found, the
 *   segment is removed from the freelist and is inserted into the allocated-
 *   address hash chain.  The address of the memory object represented by
 *   the segment is used as hash key.  The use of allocated-address hash chain
 *   is needed since we return the address of the memory object, and not the
 *   segment's itself, to the client.
 *
 * DEALLOCATION:
 *
 *   Freeing a memory object causes the chain to be searched for a matching
 *   segment.  The system will assert if a segment cannot be found, since
 *   that indicates that the memory object address is invalid.  Once found,
 *   the segment is removed from the allocated-address hash chain, and is
 *   inserted to the freelist.
 *
 * Segment allocation and deallocation can be expensive.  Because of this,
 * we expect that most clients will utilize the skmem_cache slab allocator
 * as the frontend instead.
 */
/* END CSTYLED */

#include <skywalk/os_skywalk_private.h>
#define _FN_KPRINTF             /* don't redefine kprintf() */
#include <pexpert/pexpert.h>    /* for PE_parse_boot_argn */

static void skmem_region_destroy(struct skmem_region *skr);
static void skmem_region_depopulate(struct skmem_region *);
static int sksegment_cmp(const struct sksegment *, const struct sksegment *);
static struct sksegment *sksegment_create(struct skmem_region *, uint32_t);
static void sksegment_destroy(struct skmem_region *, struct sksegment *);
static void sksegment_freelist_insert(struct skmem_region *,
    struct sksegment *, boolean_t);
static struct sksegment *sksegment_freelist_remove(struct skmem_region *,
    struct sksegment *, uint32_t, boolean_t);
static struct sksegment *sksegment_freelist_grow(struct skmem_region *);
static struct sksegment *sksegment_alloc_with_idx(struct skmem_region *,
    uint32_t);
static void *skmem_region_alloc_common(struct skmem_region *,
    struct sksegment *);
static void *skmem_region_mirror_alloc(struct skmem_region *,
    struct sksegment *, struct sksegment **);
static void skmem_region_applyall(void (*)(struct skmem_region *));
static void skmem_region_update(struct skmem_region *);
static void skmem_region_update_func(thread_call_param_t, thread_call_param_t);
static inline void skmem_region_retain_locked(struct skmem_region *);
static inline boolean_t skmem_region_release_locked(struct skmem_region *);
static int skmem_region_mib_get_sysctl SYSCTL_HANDLER_ARGS;

RB_PROTOTYPE_PREV(segtfreehead, sksegment, sg_node, sksegment_cmp);
RB_GENERATE_PREV(segtfreehead, sksegment, sg_node, sksegment_cmp);

SYSCTL_PROC(_kern_skywalk_stats, OID_AUTO, region,
    CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_LOCKED,
    0, 0, skmem_region_mib_get_sysctl, "S,sk_stats_region",
    "Skywalk region statistics");

static LCK_ATTR_DECLARE(skmem_region_lock_attr, 0, 0);
static LCK_GRP_DECLARE(skmem_region_lock_grp, "skmem_region");
static LCK_MTX_DECLARE_ATTR(skmem_region_lock, &skmem_region_lock_grp,
    &skmem_region_lock_attr);

/* protected by skmem_region_lock */
static TAILQ_HEAD(, skmem_region) skmem_region_head;

static thread_call_t skmem_region_update_tc;

#define SKMEM_REGION_UPDATE_INTERVAL    13      /* 13 seconds */
static uint32_t skmem_region_update_interval = SKMEM_REGION_UPDATE_INTERVAL;

#define SKMEM_WDT_MAXTIME               30      /* # of secs before watchdog */
#define SKMEM_WDT_PURGE                 3       /* retry purge threshold */

#if (DEVELOPMENT || DEBUG)
/* Mean Time Between Failures (ms) */
static volatile uint64_t skmem_region_mtbf;

static int skmem_region_mtbf_sysctl(struct sysctl_oid *, void *, int,
    struct sysctl_req *);

SYSCTL_PROC(_kern_skywalk_mem, OID_AUTO, region_mtbf,
    CTLTYPE_QUAD | CTLFLAG_RW | CTLFLAG_LOCKED, NULL, 0,
    skmem_region_mtbf_sysctl, "Q", "Region MTBF (ms)");

SYSCTL_UINT(_kern_skywalk_mem, OID_AUTO, region_update_interval,
    CTLFLAG_RW | CTLFLAG_LOCKED, &skmem_region_update_interval,
    SKMEM_REGION_UPDATE_INTERVAL, "Region update interval (sec)");
#endif /* (DEVELOPMENT || DEBUG) */

#define SKMEM_REGION_LOCK()                     \
	lck_mtx_lock(&skmem_region_lock)
#define SKMEM_REGION_LOCK_ASSERT_HELD()         \
	LCK_MTX_ASSERT(&skmem_region_lock, LCK_MTX_ASSERT_OWNED)
#define SKMEM_REGION_LOCK_ASSERT_NOTHELD()      \
	LCK_MTX_ASSERT(&skmem_region_lock, LCK_MTX_ASSERT_NOTOWNED)
#define SKMEM_REGION_UNLOCK()                   \
	lck_mtx_unlock(&skmem_region_lock)

/*
 * Hash table bounds.  Start with the initial value, and rescale up to
 * the specified limit.  Ideally we don't need a limit, but in practice
 * this helps guard against runaways.  These values should be revisited
 * in future and be adjusted as needed.
 */
#define SKMEM_REGION_HASH_INITIAL       32      /* initial hash table size */
#define SKMEM_REGION_HASH_LIMIT         4096    /* hash table size limit */

#define SKMEM_REGION_HASH_INDEX(_a, _s, _m)     \
	(((_a) + ((_a) >> (_s)) + ((_a) >> ((_s) << 1))) & (_m))
#define SKMEM_REGION_HASH(_skr, _addr)                                     \
	(&(_skr)->skr_hash_table[SKMEM_REGION_HASH_INDEX((uintptr_t)_addr, \
	    (_skr)->skr_hash_shift, (_skr)->skr_hash_mask)])

static SKMEM_TYPE_DEFINE(skr_zone, struct skmem_region);

static unsigned int sg_size;                    /* size of zone element */
static struct skmem_cache *skmem_sg_cache;      /* cache for sksegment */

static uint32_t skmem_seg_size = SKMEM_SEG_SIZE;
static uint32_t skmem_md_seg_size = SKMEM_MD_SEG_SIZE;
static uint32_t skmem_drv_buf_seg_size = SKMEM_DRV_BUF_SEG_SIZE;
static uint32_t skmem_drv_buf_seg_eff_size = SKMEM_DRV_BUF_SEG_SIZE;
uint32_t skmem_usr_buf_seg_size = SKMEM_USR_BUF_SEG_SIZE;

#define SKMEM_TAG_SEGMENT_BMAP  "com.apple.skywalk.segment.bmap"
static SKMEM_TAG_DEFINE(skmem_tag_segment_bmap, SKMEM_TAG_SEGMENT_BMAP);

#define SKMEM_TAG_SEGMENT_HASH  "com.apple.skywalk.segment.hash"
static SKMEM_TAG_DEFINE(skmem_tag_segment_hash, SKMEM_TAG_SEGMENT_HASH);

#define SKMEM_TAG_REGION_MIB     "com.apple.skywalk.region.mib"
static SKMEM_TAG_DEFINE(skmem_tag_region_mib, SKMEM_TAG_REGION_MIB);

#define BMAPSZ  64

/* 64-bit mask with range */
#define BMASK64(_beg, _end)     \
	((((uint64_t)-1) >> ((BMAPSZ - 1) - (_end))) & ~((1ULL << (_beg)) - 1))

static int __skmem_region_inited = 0;

void
skmem_region_init(void)
{
	boolean_t randomize_seg_size;

	_CASSERT(sizeof(bitmap_t) == sizeof(uint64_t));
	_CASSERT(BMAPSZ == (sizeof(bitmap_t) << 3));
	_CASSERT((SKMEM_SEG_SIZE % SKMEM_PAGE_SIZE) == 0);
	_CASSERT(SKMEM_REGION_HASH_LIMIT >= SKMEM_REGION_HASH_INITIAL);
	ASSERT(!__skmem_region_inited);

	/* enforce the ordering here */
	_CASSERT(SKMEM_REGION_GUARD_HEAD == 0);
	_CASSERT(SKMEM_REGION_SCHEMA == 1);
	_CASSERT(SKMEM_REGION_RING == 2);
	_CASSERT(SKMEM_REGION_BUF_DEF == 3);
	_CASSERT(SKMEM_REGION_BUF_LARGE == 4);
	_CASSERT(SKMEM_REGION_RXBUF_DEF == 5);
	_CASSERT(SKMEM_REGION_RXBUF_LARGE == 6);
	_CASSERT(SKMEM_REGION_TXBUF_DEF == 7);
	_CASSERT(SKMEM_REGION_TXBUF_LARGE == 8);
	_CASSERT(SKMEM_REGION_UMD == 9);
	_CASSERT(SKMEM_REGION_TXAUSD == 10);
	_CASSERT(SKMEM_REGION_RXFUSD == 11);
	_CASSERT(SKMEM_REGION_UBFT == 12);
	_CASSERT(SKMEM_REGION_USTATS == 13);
	_CASSERT(SKMEM_REGION_FLOWADV == 14);
	_CASSERT(SKMEM_REGION_NEXUSADV == 15);
	_CASSERT(SKMEM_REGION_SYSCTLS == 16);
	_CASSERT(SKMEM_REGION_GUARD_TAIL == 17);
	_CASSERT(SKMEM_REGION_KMD == 18);
	_CASSERT(SKMEM_REGION_RXKMD == 19);
	_CASSERT(SKMEM_REGION_TXKMD == 20);
	_CASSERT(SKMEM_REGION_KBFT == 21);
	_CASSERT(SKMEM_REGION_RXKBFT == 22);
	_CASSERT(SKMEM_REGION_TXKBFT == 23);
	_CASSERT(SKMEM_REGION_TXAKSD == 24);
	_CASSERT(SKMEM_REGION_RXFKSD == 25);
	_CASSERT(SKMEM_REGION_KSTATS == 26);
	_CASSERT(SKMEM_REGION_INTRINSIC == 27);

	_CASSERT(SREG_GUARD_HEAD == SKMEM_REGION_GUARD_HEAD);
	_CASSERT(SREG_SCHEMA == SKMEM_REGION_SCHEMA);
	_CASSERT(SREG_RING == SKMEM_REGION_RING);
	_CASSERT(SREG_BUF_DEF == SKMEM_REGION_BUF_DEF);
	_CASSERT(SREG_BUF_LARGE == SKMEM_REGION_BUF_LARGE);
	_CASSERT(SREG_RXBUF_DEF == SKMEM_REGION_RXBUF_DEF);
	_CASSERT(SREG_RXBUF_LARGE == SKMEM_REGION_RXBUF_LARGE);
	_CASSERT(SREG_TXBUF_DEF == SKMEM_REGION_TXBUF_DEF);
	_CASSERT(SREG_TXBUF_LARGE == SKMEM_REGION_TXBUF_LARGE);
	_CASSERT(SREG_UMD == SKMEM_REGION_UMD);
	_CASSERT(SREG_TXAUSD == SKMEM_REGION_TXAUSD);
	_CASSERT(SREG_RXFUSD == SKMEM_REGION_RXFUSD);
	_CASSERT(SREG_UBFT == SKMEM_REGION_UBFT);
	_CASSERT(SREG_USTATS == SKMEM_REGION_USTATS);
	_CASSERT(SREG_FLOWADV == SKMEM_REGION_FLOWADV);
	_CASSERT(SREG_NEXUSADV == SKMEM_REGION_NEXUSADV);
	_CASSERT(SREG_SYSCTLS == SKMEM_REGION_SYSCTLS);
	_CASSERT(SREG_GUARD_TAIL == SKMEM_REGION_GUARD_TAIL);
	_CASSERT(SREG_KMD == SKMEM_REGION_KMD);
	_CASSERT(SREG_RXKMD == SKMEM_REGION_RXKMD);
	_CASSERT(SREG_TXKMD == SKMEM_REGION_TXKMD);
	_CASSERT(SREG_KBFT == SKMEM_REGION_KBFT);
	_CASSERT(SREG_RXKBFT == SKMEM_REGION_RXKBFT);
	_CASSERT(SREG_TXKBFT == SKMEM_REGION_TXKBFT);
	_CASSERT(SREG_TXAKSD == SKMEM_REGION_TXAKSD);
	_CASSERT(SREG_RXFKSD == SKMEM_REGION_RXFKSD);
	_CASSERT(SREG_KSTATS == SKMEM_REGION_KSTATS);

	_CASSERT(SKR_MODE_NOREDIRECT == SREG_MODE_NOREDIRECT);
	_CASSERT(SKR_MODE_MMAPOK == SREG_MODE_MMAPOK);
	_CASSERT(SKR_MODE_UREADONLY == SREG_MODE_UREADONLY);
	_CASSERT(SKR_MODE_KREADONLY == SREG_MODE_KREADONLY);
	_CASSERT(SKR_MODE_PERSISTENT == SREG_MODE_PERSISTENT);
	_CASSERT(SKR_MODE_MONOLITHIC == SREG_MODE_MONOLITHIC);
	_CASSERT(SKR_MODE_NOMAGAZINES == SREG_MODE_NOMAGAZINES);
	_CASSERT(SKR_MODE_NOCACHE == SREG_MODE_NOCACHE);
	_CASSERT(SKR_MODE_IODIR_IN == SREG_MODE_IODIR_IN);
	_CASSERT(SKR_MODE_IODIR_OUT == SREG_MODE_IODIR_OUT);
	_CASSERT(SKR_MODE_GUARD == SREG_MODE_GUARD);
	_CASSERT(SKR_MODE_SEGPHYSCONTIG == SREG_MODE_SEGPHYSCONTIG);
	_CASSERT(SKR_MODE_SHAREOK == SREG_MODE_SHAREOK);
	_CASSERT(SKR_MODE_PUREDATA == SREG_MODE_PUREDATA);
	_CASSERT(SKR_MODE_PSEUDO == SREG_MODE_PSEUDO);
	_CASSERT(SKR_MODE_THREADSAFE == SREG_MODE_THREADSAFE);
	_CASSERT(SKR_MODE_SLAB == SREG_MODE_SLAB);
	_CASSERT(SKR_MODE_MIRRORED == SREG_MODE_MIRRORED);

	(void) PE_parse_boot_argn("skmem_seg_size", &skmem_seg_size,
	    sizeof(skmem_seg_size));
	if (skmem_seg_size < SKMEM_MIN_SEG_SIZE) {
		skmem_seg_size = SKMEM_MIN_SEG_SIZE;
	}
	skmem_seg_size = (uint32_t)P2ROUNDUP(skmem_seg_size,
	    SKMEM_MIN_SEG_SIZE);
	VERIFY(skmem_seg_size != 0 && (skmem_seg_size % SKMEM_PAGE_SIZE) == 0);

	(void) PE_parse_boot_argn("skmem_md_seg_size", &skmem_md_seg_size,
	    sizeof(skmem_md_seg_size));
	if (skmem_md_seg_size < skmem_seg_size) {
		skmem_md_seg_size = skmem_seg_size;
	}
	skmem_md_seg_size = (uint32_t)P2ROUNDUP(skmem_md_seg_size,
	    SKMEM_MIN_SEG_SIZE);
	VERIFY((skmem_md_seg_size % SKMEM_PAGE_SIZE) == 0);

	/*
	 * If set via boot-args, honor it and don't randomize.
	 */
	randomize_seg_size = !PE_parse_boot_argn("skmem_drv_buf_seg_size",
	    &skmem_drv_buf_seg_size, sizeof(skmem_drv_buf_seg_size));
	if (skmem_drv_buf_seg_size < skmem_seg_size) {
		skmem_drv_buf_seg_size = skmem_seg_size;
	}
	skmem_drv_buf_seg_size = skmem_drv_buf_seg_eff_size =
	    (uint32_t)P2ROUNDUP(skmem_drv_buf_seg_size, SKMEM_MIN_SEG_SIZE);
	VERIFY((skmem_drv_buf_seg_size % SKMEM_PAGE_SIZE) == 0);

	/*
	 * Randomize the driver buffer segment size; here we choose
	 * a SKMEM_MIN_SEG_SIZE multiplier to bump up the value to.
	 * Set this as the effective driver buffer segment size.
	 */
	if (randomize_seg_size) {
		uint32_t sm;
		read_frandom(&sm, sizeof(sm));
		skmem_drv_buf_seg_eff_size +=
		    (SKMEM_MIN_SEG_SIZE * (sm % SKMEM_DRV_BUF_SEG_MULTIPLIER));
		VERIFY((skmem_drv_buf_seg_eff_size % SKMEM_MIN_SEG_SIZE) == 0);
	}
	VERIFY(skmem_drv_buf_seg_eff_size >= skmem_drv_buf_seg_size);

	(void) PE_parse_boot_argn("skmem_usr_buf_seg_size",
	    &skmem_usr_buf_seg_size, sizeof(skmem_usr_buf_seg_size));
	if (skmem_usr_buf_seg_size < skmem_seg_size) {
		skmem_usr_buf_seg_size = skmem_seg_size;
	}
	skmem_usr_buf_seg_size = (uint32_t)P2ROUNDUP(skmem_usr_buf_seg_size,
	    SKMEM_MIN_SEG_SIZE);
	VERIFY((skmem_usr_buf_seg_size % SKMEM_PAGE_SIZE) == 0);

	SK_ERR("seg_size %u, md_seg_size %u, drv_buf_seg_size %u [eff %u], "
	    "usr_buf_seg_size %u", skmem_seg_size, skmem_md_seg_size,
	    skmem_drv_buf_seg_size, skmem_drv_buf_seg_eff_size,
	    skmem_usr_buf_seg_size);

	TAILQ_INIT(&skmem_region_head);

	skmem_region_update_tc =
	    thread_call_allocate_with_options(skmem_region_update_func,
	    NULL, THREAD_CALL_PRIORITY_KERNEL, THREAD_CALL_OPTIONS_ONCE);
	if (skmem_region_update_tc == NULL) {
		panic("%s: thread_call_allocate failed", __func__);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	sg_size = sizeof(struct sksegment);
	skmem_sg_cache = skmem_cache_create("sg", sg_size,
	    sizeof(uint64_t), NULL, NULL, NULL, NULL, NULL, 0);

	/* and start the periodic region update machinery */
	skmem_dispatch(skmem_region_update_tc, NULL,
	    (skmem_region_update_interval * NSEC_PER_SEC));

	__skmem_region_inited = 1;
}

void
skmem_region_fini(void)
{
	if (__skmem_region_inited) {
		ASSERT(TAILQ_EMPTY(&skmem_region_head));

		if (skmem_region_update_tc != NULL) {
			(void) thread_call_cancel_wait(skmem_region_update_tc);
			(void) thread_call_free(skmem_region_update_tc);
			skmem_region_update_tc = NULL;
		}

		if (skmem_sg_cache != NULL) {
			skmem_cache_destroy(skmem_sg_cache);
			skmem_sg_cache = NULL;
		}

		__skmem_region_inited = 0;
	}
}

/*
 * Reap internal caches.
 */
void
skmem_region_reap_caches(boolean_t purge)
{
	skmem_cache_reap_now(skmem_sg_cache, purge);
}

/*
 * Configure and compute the parameters of a region.
 */
void
skmem_region_params_config(struct skmem_region_params *srp)
{
	uint32_t cache_line_size = skmem_cpu_cache_line_size();
	size_t seglim, segsize, segcnt;
	size_t objsize, objcnt;

	ASSERT(srp->srp_id < SKMEM_REGIONS);

	/*
	 * If magazines layer is disabled system-wide, override
	 * the region parameter here.  This will effectively reduce
	 * the number of requested objects computed below.  Note that
	 * the region may have already been configured to exclude
	 * magazines in the default skmem_regions[] array.
	 */
	if (!skmem_allow_magazines()) {
		srp->srp_cflags |= SKMEM_REGION_CR_NOMAGAZINES;
	}

	objsize = srp->srp_r_obj_size;
	ASSERT(objsize != 0);
	objcnt = srp->srp_r_obj_cnt;
	ASSERT(objcnt != 0);

	if (srp->srp_cflags & SKMEM_REGION_CR_PSEUDO) {
		size_t align = srp->srp_align;

		VERIFY(align != 0 && (align % SKMEM_CACHE_ALIGN) == 0);
		VERIFY(powerof2(align));
		objsize = MAX(objsize, sizeof(uint64_t));
#if KASAN
		/*
		 * When KASAN is enabled, the zone allocator adjusts the
		 * element size to include the redzone regions, in which
		 * case we assume that the elements won't start on the
		 * alignment boundary and thus need to do some fix-ups.
		 * These include increasing the effective object size
		 * which adds at least 16 bytes to the original size.
		 */
		objsize += sizeof(uint64_t) + align;
#endif /* KASAN */
		objsize = P2ROUNDUP(objsize, align);

		segsize = objsize;
		srp->srp_r_seg_size = (uint32_t)segsize;
		segcnt = objcnt;
		goto done;
	} else {
		/* objects are always aligned at CPU cache line size */
		srp->srp_align = cache_line_size;
	}

	/*
	 * Start with default segment size for the region, and compute the
	 * effective segment size (to nearest SKMEM_MIN_SEG_SIZE).  If the
	 * object size is greater, then we adjust the segment size to next
	 * multiple of the effective size larger than the object size.
	 */
	if (srp->srp_r_seg_size == 0) {
		switch (srp->srp_id) {
		case SKMEM_REGION_UMD:
		case SKMEM_REGION_KMD:
		case SKMEM_REGION_RXKMD:
		case SKMEM_REGION_TXKMD:
			srp->srp_r_seg_size = skmem_md_seg_size;
			break;

		case SKMEM_REGION_BUF_DEF:
		case SKMEM_REGION_RXBUF_DEF:
		case SKMEM_REGION_TXBUF_DEF:
			/*
			 * Use the effective driver buffer segment size,
			 * since it reflects any randomization done at
			 * skmem_region_init() time.
			 */
			srp->srp_r_seg_size = skmem_drv_buf_seg_eff_size;
			break;

		default:
			srp->srp_r_seg_size = skmem_seg_size;
			break;
		}
	} else {
		srp->srp_r_seg_size = (uint32_t)P2ROUNDUP(srp->srp_r_seg_size,
		    SKMEM_MIN_SEG_SIZE);
	}

	seglim = srp->srp_r_seg_size;
	VERIFY(seglim != 0 && (seglim % SKMEM_PAGE_SIZE) == 0);

	SK_DF(SK_VERB_MEM, "%s: seglim %zu objsize %zu objcnt %zu",
	    srp->srp_name, seglim, objsize, objcnt);

	/*
	 * Make sure object size is multiple of CPU cache line
	 * size, and that we can evenly divide the segment size.
	 */
	if (!((objsize < cache_line_size) && (objsize < seglim) &&
	    ((cache_line_size % objsize) == 0) && ((seglim % objsize) == 0))) {
		objsize = P2ROUNDUP(objsize, cache_line_size);
		while (objsize < seglim && (seglim % objsize) != 0) {
			SK_DF(SK_VERB_MEM, "%s: objsize %zu -> %zu",
			    srp->srp_name, objsize, objsize + cache_line_size);
			objsize += cache_line_size;
		}
	}

	/* segment must be larger than object */
	while (objsize > seglim) {
		SK_DF(SK_VERB_MEM, "%s: seglim %zu -> %zu", srp->srp_name,
		    seglim, seglim + SKMEM_MIN_SEG_SIZE);
		seglim += SKMEM_MIN_SEG_SIZE;
	}

	/*
	 * Take into account worst-case per-CPU cached
	 * objects if this region is configured for it.
	 */
	if (!(srp->srp_cflags & SKMEM_REGION_CR_NOMAGAZINES)) {
		uint32_t magazine_max_objs =
		    skmem_cache_magazine_max((uint32_t)objsize);
		SK_DF(SK_VERB_MEM, "%s: objcnt %zu -> %zu", srp->srp_name,
		    objcnt, objcnt + magazine_max_objs);
		objcnt += magazine_max_objs;
	}

	SK_DF(SK_VERB_MEM, "%s: seglim %zu objsize %zu "
	    "objcnt %zu", srp->srp_name, seglim, objsize, objcnt);

	segsize = P2ROUNDUP(objsize * objcnt, SKMEM_MIN_SEG_SIZE);
	if (seglim > segsize) {
		/*
		 * If the segment limit is larger than what we need,
		 * avoid memory wastage by shrinking it.
		 */
		while (seglim > segsize && seglim > SKMEM_MIN_SEG_SIZE) {
			VERIFY(seglim >= SKMEM_MIN_SEG_SIZE);
			SK_DF(SK_VERB_MEM,
			    "%s: segsize %zu (%zu*%zu) seglim [-] %zu -> %zu",
			    srp->srp_name, segsize, objsize, objcnt, seglim,
			    P2ROUNDUP(seglim - SKMEM_MIN_SEG_SIZE,
			    SKMEM_MIN_SEG_SIZE));
			seglim = P2ROUNDUP(seglim - SKMEM_MIN_SEG_SIZE,
			    SKMEM_MIN_SEG_SIZE);
		}

		/* adjust segment size */
		segsize = seglim;
	} else if (seglim < segsize) {
		size_t oseglim = seglim;
		/*
		 * If the segment limit is less than the segment size,
		 * see if increasing it slightly (up to 1.5x the segment
		 * size) would allow us to avoid allocating too many
		 * extra objects (due to excessive segment count).
		 */
		while (seglim < segsize && (segsize % seglim) != 0) {
			SK_DF(SK_VERB_MEM,
			    "%s: segsize %zu (%zu*%zu) seglim [+] %zu -> %zu",
			    srp->srp_name, segsize, objsize, objcnt, seglim,
			    (seglim + SKMEM_MIN_SEG_SIZE));
			seglim += SKMEM_MIN_SEG_SIZE;
			if (seglim >= (oseglim + (oseglim >> 1))) {
				break;
			}
		}

		/* can't use P2ROUNDUP since seglim may not be power of 2 */
		segsize = SK_ROUNDUP(segsize, seglim);
	}
	ASSERT(segsize != 0 && (segsize % seglim) == 0);

	SK_DF(SK_VERB_MEM, "%s: segsize %zu seglim %zu",
	    srp->srp_name, segsize, seglim);

	/* compute segment count, and recompute segment size */
	if (srp->srp_cflags & SKMEM_REGION_CR_MONOLITHIC) {
		segcnt = 1;
	} else {
		/*
		 * The adjustments above were done in increments of
		 * SKMEM_MIN_SEG_SIZE.  If the object size is greater
		 * than that, ensure that the segment size is a multiple
		 * of the object size.
		 */
		if (objsize > SKMEM_MIN_SEG_SIZE) {
			ASSERT(seglim >= objsize);
			if ((seglim % objsize) != 0) {
				seglim += (seglim - objsize);
			}
			/* recompute segsize; see SK_ROUNDUP comment above */
			segsize = SK_ROUNDUP(segsize, seglim);
		}

		segcnt = MAX(1, (segsize / seglim));
		segsize /= segcnt;
	}

	SK_DF(SK_VERB_MEM, "%s: segcnt %zu segsize %zu",
	    srp->srp_name, segcnt, segsize);

	/* recompute object count to avoid wastage */
	objcnt = (segsize * segcnt) / objsize;
	ASSERT(objcnt != 0);
done:
	srp->srp_c_obj_size = (uint32_t)objsize;
	srp->srp_c_obj_cnt = (uint32_t)objcnt;
	srp->srp_c_seg_size = (uint32_t)segsize;
	srp->srp_seg_cnt = (uint32_t)segcnt;

	SK_DF(SK_VERB_MEM, "%s: objsize %zu objcnt %zu segcnt %zu segsize %zu",
	    srp->srp_name, objsize, objcnt, segcnt, segsize);

#if SK_LOG
	if (__improbable(sk_verbose != 0)) {
		char label[32];
		(void) snprintf(label, sizeof(label), "REGION_%s:",
		    skmem_region_id2name(srp->srp_id));
		SK_D("%-16s o:[%4u x %6u -> %4u x %6u]", label,
		    (uint32_t)srp->srp_r_obj_cnt,
		    (uint32_t)srp->srp_r_obj_size,
		    (uint32_t)srp->srp_c_obj_cnt,
		    (uint32_t)srp->srp_c_obj_size);
	}
#endif /* SK_LOG */
}

/*
 * Create a region.
 */
struct skmem_region *
skmem_region_create(const char *name, struct skmem_region_params *srp,
    sksegment_ctor_fn_t ctor, sksegment_dtor_fn_t dtor, void *private)
{
	boolean_t pseudo = (srp->srp_cflags & SKMEM_REGION_CR_PSEUDO);
	uint32_t cflags = srp->srp_cflags;
	struct skmem_region *skr;
	uint32_t i;

	ASSERT(srp->srp_id < SKMEM_REGIONS);
	ASSERT(srp->srp_c_seg_size != 0 &&
	    (pseudo || (srp->srp_c_seg_size % SKMEM_PAGE_SIZE) == 0));
	ASSERT(srp->srp_seg_cnt != 0);
	ASSERT(srp->srp_c_obj_cnt == 1 ||
	    (srp->srp_c_seg_size % srp->srp_c_obj_size) == 0);
	ASSERT(srp->srp_c_obj_size <= srp->srp_c_seg_size);

	skr = zalloc_flags(skr_zone, Z_WAITOK | Z_ZERO);
	skr->skr_params.srp_r_seg_size = srp->srp_r_seg_size;
	skr->skr_seg_size = srp->srp_c_seg_size;
	skr->skr_size = (srp->srp_c_seg_size * srp->srp_seg_cnt);
	skr->skr_seg_objs = (srp->srp_c_seg_size / srp->srp_c_obj_size);

	if (!pseudo) {
		skr->skr_seg_max_cnt = srp->srp_seg_cnt;

		/* set alignment to CPU cache line size */
		skr->skr_params.srp_align = skmem_cpu_cache_line_size();

		/* allocate the allocated-address hash chain */
		skr->skr_hash_initial = SKMEM_REGION_HASH_INITIAL;
		skr->skr_hash_limit = SKMEM_REGION_HASH_LIMIT;
		skr->skr_hash_table = sk_alloc_type_array(struct sksegment_bkt,
		    skr->skr_hash_initial, Z_WAITOK | Z_NOFAIL,
		    skmem_tag_segment_hash);
		skr->skr_hash_mask = (skr->skr_hash_initial - 1);
		skr->skr_hash_shift = flsll(srp->srp_c_seg_size) - 1;

		for (i = 0; i < (skr->skr_hash_mask + 1); i++) {
			TAILQ_INIT(&skr->skr_hash_table[i].sgb_head);
		}
	} else {
		/* this upper bound doesn't apply */
		skr->skr_seg_max_cnt = 0;

		/* pick up value set by skmem_regions_params_config() */
		skr->skr_params.srp_align = srp->srp_align;
	}

	skr->skr_r_obj_size = srp->srp_r_obj_size;
	skr->skr_r_obj_cnt = srp->srp_r_obj_cnt;
	skr->skr_c_obj_size = srp->srp_c_obj_size;
	skr->skr_c_obj_cnt = srp->srp_c_obj_cnt;

	skr->skr_params.srp_md_type = srp->srp_md_type;
	skr->skr_params.srp_md_subtype = srp->srp_md_subtype;
	skr->skr_params.srp_max_frags = srp->srp_max_frags;

	skr->skr_seg_ctor = ctor;
	skr->skr_seg_dtor = dtor;
	skr->skr_private = private;

	lck_mtx_init(&skr->skr_lock, &skmem_region_lock_grp,
	    &skmem_region_lock_attr);

	TAILQ_INIT(&skr->skr_seg_free);
	RB_INIT(&skr->skr_seg_tfree);

	skr->skr_id = srp->srp_id;
	uuid_generate_random(skr->skr_uuid);
	(void) snprintf(skr->skr_name, sizeof(skr->skr_name),
	    "%s.%s.%s", SKMEM_REGION_PREFIX, srp->srp_name, name);

	SK_DF(SK_VERB_MEM_REGION, "\"%s\": skr 0x%llx ",
	    skr->skr_name, SK_KVA(skr));

	/* sanity check */
	ASSERT(!(cflags & SKMEM_REGION_CR_GUARD) ||
	    !(cflags & (SKMEM_REGION_CR_KREADONLY | SKMEM_REGION_CR_UREADONLY |
	    SKMEM_REGION_CR_PERSISTENT | SKMEM_REGION_CR_SHAREOK |
	    SKMEM_REGION_CR_IODIR_IN | SKMEM_REGION_CR_IODIR_OUT |
	    SKMEM_REGION_CR_PUREDATA)));

	skr->skr_cflags = cflags;
	if (cflags & SKMEM_REGION_CR_NOREDIRECT) {
		skr->skr_mode |= SKR_MODE_NOREDIRECT;
	}
	if (cflags & SKMEM_REGION_CR_MMAPOK) {
		skr->skr_mode |= SKR_MODE_MMAPOK;
	}
	if ((cflags & SKMEM_REGION_CR_MMAPOK) &&
	    (cflags & SKMEM_REGION_CR_UREADONLY)) {
		skr->skr_mode |= SKR_MODE_UREADONLY;
	}
	if (cflags & SKMEM_REGION_CR_KREADONLY) {
		skr->skr_mode |= SKR_MODE_KREADONLY;
	}
	if (cflags & SKMEM_REGION_CR_PERSISTENT) {
		skr->skr_mode |= SKR_MODE_PERSISTENT;
	}
	if (cflags & SKMEM_REGION_CR_MONOLITHIC) {
		skr->skr_mode |= SKR_MODE_MONOLITHIC;
	}
	if (cflags & SKMEM_REGION_CR_NOMAGAZINES) {
		skr->skr_mode |= SKR_MODE_NOMAGAZINES;
	}
	if (cflags & SKMEM_REGION_CR_NOCACHE) {
		skr->skr_mode |= SKR_MODE_NOCACHE;
	}
	if (cflags & SKMEM_REGION_CR_SEGPHYSCONTIG) {
		skr->skr_mode |= SKR_MODE_SEGPHYSCONTIG;
	}
	if (cflags & SKMEM_REGION_CR_SHAREOK) {
		skr->skr_mode |= SKR_MODE_SHAREOK;
	}
	if (cflags & SKMEM_REGION_CR_IODIR_IN) {
		skr->skr_mode |= SKR_MODE_IODIR_IN;
	}
	if (cflags & SKMEM_REGION_CR_IODIR_OUT) {
		skr->skr_mode |= SKR_MODE_IODIR_OUT;
	}
	if (cflags & SKMEM_REGION_CR_GUARD) {
		skr->skr_mode |= SKR_MODE_GUARD;
	}
	if (cflags & SKMEM_REGION_CR_PUREDATA) {
		skr->skr_mode |= SKR_MODE_PUREDATA;
	}
	if (cflags & SKMEM_REGION_CR_PSEUDO) {
		skr->skr_mode |= SKR_MODE_PSEUDO;
	}
	if (cflags & SKMEM_REGION_CR_THREADSAFE) {
		skr->skr_mode |= SKR_MODE_THREADSAFE;
	}
	if (cflags & SKMEM_REGION_CR_MEMTAG) {
		skr->skr_mode |= SKR_MODE_MEMTAG;
	}

#if XNU_TARGET_OS_OSX
	/*
	 * Mark all regions as persistent except for the guard and Intrinsic
	 * regions.
	 * This is to ensure that kernel threads won't be faulting-in while
	 * accessing these memory regions. We have observed various kinds of
	 * kernel panics due to kernel threads faulting on non-wired memory
	 * access when the VM subsystem is not in a state to swap-in the page.
	 */
	if (!((skr->skr_mode & SKR_MODE_PSEUDO) ||
	    (skr->skr_mode & SKR_MODE_GUARD))) {
		skr->skr_mode |= SKR_MODE_PERSISTENT;
	}
#endif /* XNU_TARGET_OS_OSX */

	/* SKR_MODE_UREADONLY only takes effect for user task mapping */
	skr->skr_bufspec.user_writable = !(skr->skr_mode & SKR_MODE_UREADONLY);
	skr->skr_bufspec.kernel_writable = !(skr->skr_mode & SKR_MODE_KREADONLY);
	skr->skr_bufspec.purgeable = TRUE;
	skr->skr_bufspec.inhibitCache = !!(skr->skr_mode & SKR_MODE_NOCACHE);
	skr->skr_bufspec.physcontig = (skr->skr_mode & SKR_MODE_SEGPHYSCONTIG);
	skr->skr_bufspec.iodir_in = !!(skr->skr_mode & SKR_MODE_IODIR_IN);
	skr->skr_bufspec.iodir_out = !!(skr->skr_mode & SKR_MODE_IODIR_OUT);
	skr->skr_bufspec.puredata = !!(skr->skr_mode & SKR_MODE_PUREDATA);
	skr->skr_bufspec.threadSafe = !!(skr->skr_mode & SKR_MODE_THREADSAFE);
	skr->skr_regspec.noRedirect = !!(skr->skr_mode & SKR_MODE_NOREDIRECT);

	/* allocate segment bitmaps */
	if (!(skr->skr_mode & SKR_MODE_PSEUDO)) {
		ASSERT(skr->skr_seg_max_cnt != 0);
		skr->skr_seg_bmap_len = BITMAP_LEN(skr->skr_seg_max_cnt);
		skr->skr_seg_bmap = sk_alloc_data(BITMAP_SIZE(skr->skr_seg_max_cnt),
		    Z_WAITOK | Z_NOFAIL, skmem_tag_segment_bmap);
		ASSERT(BITMAP_SIZE(skr->skr_seg_max_cnt) ==
		    (skr->skr_seg_bmap_len * sizeof(*skr->skr_seg_bmap)));

		/* mark all bitmaps as free (bit set) */
		bitmap_full(skr->skr_seg_bmap, skr->skr_seg_max_cnt);
	}

	/*
	 * Populate the freelist by allocating all segments for the
	 * region, which will be mapped but not faulted-in, and then
	 * immediately insert each to the freelist.  That will in
	 * turn unmap the segment's memory object.
	 */
	SKR_LOCK(skr);
	if (skr->skr_mode & SKR_MODE_PSEUDO) {
		char zone_name[64];
		(void) snprintf(zone_name, sizeof(zone_name), "%s.reg.%s",
		    SKMEM_ZONE_PREFIX, name);
		skr->skr_zreg = zone_create(zone_name, skr->skr_c_obj_size,
		    ZC_ZFREE_CLEARMEM | ZC_DESTRUCTIBLE);
	} else {
		/* create a backing IOSKRegion object */
		if ((skr->skr_reg = IOSKRegionCreate(&skr->skr_regspec,
		    (IOSKSize)skr->skr_seg_size,
		    (IOSKCount)skr->skr_seg_max_cnt)) == NULL) {
			SK_ERR("\%s\": [%u * %u] cflags 0x%b skr_reg failed",
			    skr->skr_name, (uint32_t)skr->skr_seg_size,
			    (uint32_t)skr->skr_seg_max_cnt, skr->skr_cflags,
			    SKMEM_REGION_CR_BITS);
			goto failed;
		}
	}

	ASSERT(skr->skr_seg_objs != 0);

	++skr->skr_refcnt;      /* for caller */
	SKR_UNLOCK(skr);

	SKMEM_REGION_LOCK();
	TAILQ_INSERT_TAIL(&skmem_region_head, skr, skr_link);
	SKMEM_REGION_UNLOCK();

	SK_DF(SK_VERB_MEM_REGION,
	    "  [TOTAL] seg (%u*%u) obj (%u*%u) cflags 0x%b",
	    (uint32_t)skr->skr_seg_size, (uint32_t)skr->skr_seg_max_cnt,
	    (uint32_t)skr->skr_c_obj_size, (uint32_t)skr->skr_c_obj_cnt,
	    skr->skr_cflags, SKMEM_REGION_CR_BITS);

	return skr;

failed:
	SKR_LOCK_ASSERT_HELD(skr);
	skmem_region_destroy(skr);

	return NULL;
}

/*
 * Destroy a region.
 */
static void
skmem_region_destroy(struct skmem_region *skr)
{
	struct skmem_region *mskr;

	SKR_LOCK_ASSERT_HELD(skr);

	SK_DF(SK_VERB_MEM_REGION, "\"%s\": skr 0x%llx",
	    skr->skr_name, SK_KVA(skr));

	/*
	 * Panic if we detect there are unfreed segments; the caller
	 * destroying this region is responsible for ensuring that all
	 * allocated segments have been freed prior to getting here.
	 */
	ASSERT(skr->skr_refcnt == 0);
	if (skr->skr_seginuse != 0) {
		panic("%s: '%s' (%p) not empty (%u unfreed)",
		    __func__, skr->skr_name, (void *)skr, skr->skr_seginuse);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	if (skr->skr_link.tqe_next != NULL || skr->skr_link.tqe_prev != NULL) {
		SKR_UNLOCK(skr);
		SKMEM_REGION_LOCK();
		TAILQ_REMOVE(&skmem_region_head, skr, skr_link);
		SKMEM_REGION_UNLOCK();
		SKR_LOCK(skr);
		ASSERT(skr->skr_refcnt == 0);
	}

	/*
	 * Undo what's done earlier at region creation time.
	 */
	skmem_region_depopulate(skr);
	ASSERT(TAILQ_EMPTY(&skr->skr_seg_free));
	ASSERT(RB_EMPTY(&skr->skr_seg_tfree));
	ASSERT(skr->skr_seg_free_cnt == 0);

	if (skr->skr_reg != NULL) {
		ASSERT(!(skr->skr_mode & SKR_MODE_PSEUDO));
		IOSKRegionDestroy(skr->skr_reg);
		skr->skr_reg = NULL;
	}

	if (skr->skr_zreg != NULL) {
		ASSERT(skr->skr_mode & SKR_MODE_PSEUDO);
		zdestroy(skr->skr_zreg);
		skr->skr_zreg = NULL;
	}

	if (skr->skr_seg_bmap != NULL) {
		ASSERT(!(skr->skr_mode & SKR_MODE_PSEUDO));
#if (DEBUG || DEVELOPMENT)
		ASSERT(skr->skr_seg_bmap_len != 0);
		/* must have been set to vacant (bit set) by now */
		assert(bitmap_is_full(skr->skr_seg_bmap, skr->skr_seg_max_cnt));
#endif /* DEBUG || DEVELOPMENT */

		sk_free_data(skr->skr_seg_bmap, BITMAP_SIZE(skr->skr_seg_max_cnt));
		skr->skr_seg_bmap = NULL;
		skr->skr_seg_bmap_len = 0;
	}
	ASSERT(skr->skr_seg_bmap_len == 0);

	if (skr->skr_hash_table != NULL) {
		ASSERT(!(skr->skr_mode & SKR_MODE_PSEUDO));
#if (DEBUG || DEVELOPMENT)
		for (uint32_t i = 0; i < (skr->skr_hash_mask + 1); i++) {
			ASSERT(TAILQ_EMPTY(&skr->skr_hash_table[i].sgb_head));
		}
#endif /* DEBUG || DEVELOPMENT */

		sk_free_type_array(struct sksegment_bkt, skr->skr_hash_mask + 1,
		    skr->skr_hash_table);
		skr->skr_hash_table = NULL;
	}
	if ((mskr = skr->skr_mirror) != NULL) {
		ASSERT(!(skr->skr_mode & SKR_MODE_PSEUDO));
		skr->skr_mirror = NULL;
		mskr->skr_mode &= ~SKR_MODE_MIRRORED;
	}
	SKR_UNLOCK(skr);

	if (mskr != NULL) {
		skmem_region_release(mskr);
	}

	lck_mtx_destroy(&skr->skr_lock, &skmem_region_lock_grp);

	zfree(skr_zone, skr);
}

/*
 * Mirror mskr (slave) to skr (master).
 */
void
skmem_region_mirror(struct skmem_region *skr, struct skmem_region *mskr)
{
	SK_DF(SK_VERB_MEM_REGION, "skr master 0x%llx, slave 0x%llx ",
	    SK_KVA(skr), SK_KVA(mskr));

	SKR_LOCK(skr);
	ASSERT(!(skr->skr_mode & SKR_MODE_MIRRORED));
	ASSERT(!(mskr->skr_mode & SKR_MODE_MIRRORED));
	ASSERT(skr->skr_mirror == NULL);

	/* both regions must share identical parameters */
	ASSERT(skr->skr_size == mskr->skr_size);
	ASSERT(skr->skr_seg_size == mskr->skr_seg_size);
	ASSERT(skr->skr_seg_free_cnt == mskr->skr_seg_free_cnt);

	skr->skr_mirror = mskr;
	skmem_region_retain(mskr);
	mskr->skr_mode |= SKR_MODE_MIRRORED;
	SKR_UNLOCK(skr);
}

void
skmem_region_slab_config(struct skmem_region *skr, struct skmem_cache *skm,
    bool attach)
{
	int i;

	SKR_LOCK(skr);
	if (attach) {
		for (i = 0; i < SKR_MAX_CACHES && skr->skr_cache[i] != NULL;
		    i++) {
			;
		}
		VERIFY(i < SKR_MAX_CACHES);
		ASSERT(skr->skr_cache[i] == NULL);
		skr->skr_mode |= SKR_MODE_SLAB;
		skr->skr_cache[i] = skm;
		skmem_region_retain_locked(skr);
		SKR_UNLOCK(skr);
	} else {
		ASSERT(skr->skr_mode & SKR_MODE_SLAB);
		for (i = 0; i < SKR_MAX_CACHES && skr->skr_cache[i] != skm;
		    i++) {
			;
		}
		VERIFY(i < SKR_MAX_CACHES);
		ASSERT(skr->skr_cache[i] == skm);
		skr->skr_cache[i] = NULL;
		for (i = 0; i < SKR_MAX_CACHES && skr->skr_cache[i] == NULL;
		    i++) {
			;
		}
		if (i == SKR_MAX_CACHES) {
			skr->skr_mode &= ~SKR_MODE_SLAB;
		}
		if (!skmem_region_release_locked(skr)) {
			SKR_UNLOCK(skr);
		}
	}
}

/*
 * Common routines for skmem_region_{alloc,mirror_alloc}.
 */
static void *
skmem_region_alloc_common(struct skmem_region *skr, struct sksegment *sg)
{
	struct sksegment_bkt *sgb;
	void *addr;

	SKR_LOCK_ASSERT_HELD(skr);

	ASSERT(sg->sg_md != NULL);
	ASSERT(sg->sg_start != 0 && sg->sg_end != 0);
	addr = (void *)sg->sg_start;
	sgb = SKMEM_REGION_HASH(skr, addr);
	ASSERT(sg->sg_link.tqe_next == NULL);
	ASSERT(sg->sg_link.tqe_prev == NULL);
	TAILQ_INSERT_HEAD(&sgb->sgb_head, sg, sg_link);

	skr->skr_seginuse++;
	skr->skr_meminuse += skr->skr_seg_size;
	if (sg->sg_state == SKSEG_STATE_MAPPED_WIRED) {
		skr->skr_w_meminuse += skr->skr_seg_size;
	}
	skr->skr_alloc++;

	return addr;
}

/*
 * Allocate a segment from the region.
 */
void *
skmem_region_alloc(struct skmem_region *skr, void **maddr,
    struct sksegment **retsg, struct sksegment **retsgm, uint32_t skmflag)
{
	struct sksegment *sg = NULL;
	struct sksegment *sg1 = NULL;
	void *addr = NULL, *addr1 = NULL;
	uint32_t retries = 0;

	VERIFY(!(skr->skr_mode & SKR_MODE_GUARD));

	if (retsg != NULL) {
		*retsg = NULL;
	}
	if (retsgm != NULL) {
		*retsgm = NULL;
	}

	/* SKMEM_NOSLEEP and SKMEM_FAILOK are mutually exclusive */
	VERIFY((skmflag & (SKMEM_NOSLEEP | SKMEM_FAILOK)) !=
	    (SKMEM_NOSLEEP | SKMEM_FAILOK));

	SKR_LOCK(skr);
	while (sg == NULL) {
		/* see if there's a segment in the freelist */
		sg = TAILQ_FIRST(&skr->skr_seg_free);
		if (sg == NULL) {
			/* see if we can grow the freelist */
			sg = sksegment_freelist_grow(skr);
			if (sg != NULL) {
				break;
			}

			if (skr->skr_mode & SKR_MODE_SLAB) {
				SKR_UNLOCK(skr);
				/*
				 * None found; it's possible that the slab
				 * layer is caching extra amount, so ask
				 * skmem_cache to reap/purge its caches.
				 */
				for (int i = 0; i < SKR_MAX_CACHES; i++) {
					if (skr->skr_cache[i] == NULL) {
						continue;
					}
					skmem_cache_reap_now(skr->skr_cache[i],
					    TRUE);
				}
				SKR_LOCK(skr);
				/*
				 * If we manage to get some freed, try again.
				 */
				if (TAILQ_FIRST(&skr->skr_seg_free) != NULL) {
					continue;
				}
			}

			/*
			 * Give up if this is a non-blocking allocation,
			 * or if this is a blocking allocation but the
			 * caller is willing to retry.
			 */
			if (skmflag & (SKMEM_NOSLEEP | SKMEM_FAILOK)) {
				break;
			}

			/* otherwise we wait until one is available */
			++skr->skr_seg_waiters;
			(void) msleep(&skr->skr_seg_free, &skr->skr_lock,
			    (PZERO - 1), skr->skr_name, NULL);
		}
	}

	SKR_LOCK_ASSERT_HELD(skr);

	if (sg != NULL) {
retry:
		/*
		 * We have a segment; remove it from the freelist and
		 * insert it into the allocated-address hash chain.
		 * Note that this may return NULL if we can't allocate
		 * the memory descriptor.
		 */
		if (sksegment_freelist_remove(skr, sg, skmflag,
		    FALSE) == NULL) {
			ASSERT(sg->sg_state == SKSEG_STATE_DETACHED);
			ASSERT(sg->sg_md == NULL);
			ASSERT(sg->sg_start == 0 && sg->sg_end == 0);

			/*
			 * If it's non-blocking allocation, simply just give
			 * up and let the caller decide when to retry.  Else,
			 * it gets a bit complicated due to the contract we
			 * have for blocking allocations with the client; the
			 * most sensible thing to do here is to retry the
			 * allocation ourselves.  Note that we keep using the
			 * same segment we originally got, since we only need
			 * the memory descriptor to be allocated for it; thus
			 * we make sure we don't release the region lock when
			 * retrying allocation.  Doing so is crucial when the
			 * region is mirrored, since the segment indices on
			 * both regions need to match.
			 */
			if (skmflag & SKMEM_NOSLEEP) {
				SK_ERR("\"%s\": failed to allocate segment "
				    "(non-sleeping mode)", skr->skr_name);
				sg = NULL;
			} else {
				if (++retries > SKMEM_WDT_MAXTIME) {
					panic_plain("\"%s\": failed to "
					    "allocate segment (sleeping mode) "
					    "after %u retries\n\n%s",
					    skr->skr_name, SKMEM_WDT_MAXTIME,
					    skmem_dump(skr));
					/* NOTREACHED */
					__builtin_unreachable();
				} else {
					SK_ERR("\"%s\": failed to allocate "
					    "segment (sleeping mode): %u "
					    "retries", skr->skr_name, retries);
				}
				if (skr->skr_mode & SKR_MODE_SLAB) {
					/*
					 * We can't get any memory descriptor
					 * for this segment; reap extra cached
					 * objects from the slab layer and hope
					 * that we get lucky next time around.
					 *
					 * XXX adi@apple.com: perhaps also
					 * trigger the zone allocator to do
					 * its garbage collection here?
					 */
					skmem_cache_reap();
				}
				delay(1 * USEC_PER_SEC);        /* 1 sec */
				goto retry;
			}
		}

		if (sg != NULL) {
			/* insert to allocated-address hash chain */
			addr = skmem_region_alloc_common(skr, sg);
		}
	}

	if (sg == NULL) {
		VERIFY(skmflag & (SKMEM_NOSLEEP | SKMEM_FAILOK));
		if (skmflag & SKMEM_PANIC) {
			VERIFY((skmflag & (SKMEM_NOSLEEP | SKMEM_FAILOK)) ==
			    SKMEM_NOSLEEP);
			/*
			 * If is a failed non-blocking alloc and the caller
			 * insists that it must be successful, then panic.
			 */
			panic_plain("\"%s\": skr 0x%p unable to satisfy "
			    "mandatory allocation\n", skr->skr_name, skr);
			/* NOTREACHED */
			__builtin_unreachable();
		} else {
			/*
			 * Give up if this is a non-blocking allocation,
			 * or one where the caller is willing to handle
			 * allocation failures.
			 */
			goto done;
		}
	}

	ASSERT((mach_vm_address_t)addr == sg->sg_start);

#if SK_LOG
	SK_DF(SK_VERB_MEM_REGION, "skr 0x%llx sg 0x%llx",
	    SK_KVA(skr), SK_KVA(sg));
	if (skr->skr_mirror == NULL ||
	    !(skr->skr_mirror->skr_mode & SKR_MODE_MIRRORED)) {
		SK_DF(SK_VERB_MEM_REGION, "  [%u] [0x%llx-0x%llx)",
		    sg->sg_index, SK_KVA(sg->sg_start), SK_KVA(sg->sg_end));
	} else {
		SK_DF(SK_VERB_MEM_REGION, "  [%u] [0x%llx-0x%llx) mirrored",
		    sg->sg_index, SK_KVA(sg), SK_KVA(sg->sg_start),
		    SK_KVA(sg->sg_end));
	}
#endif /* SK_LOG */

	/*
	 * If mirroring, allocate shadow object from slave region.
	 */
	if (skr->skr_mirror != NULL) {
		ASSERT(skr->skr_mirror != skr);
		ASSERT(!(skr->skr_mode & SKR_MODE_MIRRORED));
		ASSERT(skr->skr_mirror->skr_mode & SKR_MODE_MIRRORED);
		addr1 = skmem_region_mirror_alloc(skr->skr_mirror, sg, &sg1);
		ASSERT(addr1 != NULL);
		ASSERT(sg1 != NULL && sg1 != sg);
		ASSERT(sg1->sg_index == sg->sg_index);
	}

done:
	SKR_UNLOCK(skr);

	/* return segment metadata to caller if asked (reference not needed) */
	if (addr != NULL) {
		if (retsg != NULL) {
			*retsg = sg;
		}
		if (retsgm != NULL) {
			*retsgm = sg1;
		}
	}

	if (maddr != NULL) {
		*maddr = addr1;
	}

	return addr;
}

/*
 * Allocate a segment from a mirror region at the same index.  While it
 * is somewhat a simplified variant of skmem_region_alloc, keeping it
 * separate allows us to avoid further convoluting that routine.
 */
static void *
skmem_region_mirror_alloc(struct skmem_region *skr, struct sksegment *sg0,
    struct sksegment **retsg)
{
	struct sksegment sg_key = { .sg_index = sg0->sg_index };
	struct sksegment *sg = NULL;
	void *addr = NULL;

	ASSERT(skr->skr_mode & SKR_MODE_MIRRORED);
	ASSERT(skr->skr_mirror == NULL);
	ASSERT(sg0->sg_type == SKSEG_TYPE_ALLOC);

	if (retsg != NULL) {
		*retsg = NULL;
	}

	SKR_LOCK(skr);

	/*
	 * See if we can find one in the freelist first.  Otherwise,
	 * create a new segment of the same index and add that to the
	 * freelist.  We would always get a segment since both regions
	 * are synchronized when it comes to the indices of allocated
	 * segments.
	 */
	sg = RB_FIND(segtfreehead, &skr->skr_seg_tfree, &sg_key);
	if (sg == NULL) {
		sg = sksegment_alloc_with_idx(skr, sg0->sg_index);
		VERIFY(sg != NULL);
	}
	VERIFY(sg->sg_index == sg0->sg_index);

	/*
	 * We have a segment; remove it from the freelist and insert
	 * it into the allocated-address hash chain.  This either
	 * succeeds or panics (SKMEM_PANIC) when a memory descriptor
	 * can't be allocated.
	 *
	 * TODO: consider retrying IOBMD allocation attempts if needed.
	 */
	sg = sksegment_freelist_remove(skr, sg, SKMEM_PANIC, FALSE);
	VERIFY(sg != NULL);

	/* insert to allocated-address hash chain */
	addr = skmem_region_alloc_common(skr, sg);

#if SK_LOG
	SK_DF(SK_VERB_MEM_REGION, "skr 0x%llx sg 0x%llx",
	    SK_KVA(skr), SK_KVA(sg));
	SK_DF(SK_VERB_MEM_REGION, "  [%u] [0x%llx-0x%llx)",
	    sg->sg_index, SK_KVA(sg->sg_start), SK_KVA(sg->sg_end));
#endif /* SK_LOG */

	SKR_UNLOCK(skr);

	/* return segment metadata to caller if asked (reference not needed) */
	if (retsg != NULL) {
		*retsg = sg;
	}

	return addr;
}

/*
 * Free a segment to the region.
 */
void
skmem_region_free(struct skmem_region *skr, void *addr, void *maddr)
{
	struct sksegment_bkt *sgb;
	struct sksegment *sg, *tsg;

	VERIFY(!(skr->skr_mode & SKR_MODE_GUARD));

	/*
	 * Search the hash chain to find a matching segment for the
	 * given address.  If found, remove the segment from the
	 * hash chain and insert it into the freelist.  Otherwise,
	 * we panic since the caller has given us a bogus address.
	 */
	SKR_LOCK(skr);
	sgb = SKMEM_REGION_HASH(skr, addr);
	TAILQ_FOREACH_SAFE(sg, &sgb->sgb_head, sg_link, tsg) {
		ASSERT(sg->sg_start != 0 && sg->sg_end != 0);
		if (sg->sg_start == (mach_vm_address_t)addr) {
			TAILQ_REMOVE(&sgb->sgb_head, sg, sg_link);
			sg->sg_link.tqe_next = NULL;
			sg->sg_link.tqe_prev = NULL;
			break;
		}
	}

	ASSERT(sg != NULL);
	if (sg->sg_state == SKSEG_STATE_MAPPED_WIRED) {
		ASSERT(skr->skr_w_meminuse >= skr->skr_seg_size);
		skr->skr_w_meminuse -= skr->skr_seg_size;
	}
	sksegment_freelist_insert(skr, sg, FALSE);

	ASSERT(skr->skr_seginuse != 0);
	skr->skr_seginuse--;
	skr->skr_meminuse -= skr->skr_seg_size;
	skr->skr_free++;

#if SK_LOG
	SK_DF(SK_VERB_MEM_REGION, "skr 0x%llx sg 0x%llx",
	    SK_KVA(skr), SK_KVA(sg));
	if (skr->skr_mirror == NULL ||
	    !(skr->skr_mirror->skr_mode & SKR_MODE_MIRRORED)) {
		SK_DF(SK_VERB_MEM_REGION, "  [%u] [0x%llx-0x%llx)",
		    sg->sg_index, SK_KVA(addr),
		    SK_KVA((uintptr_t)addr + skr->skr_seg_size));
	} else {
		SK_DF(SK_VERB_MEM_REGION, "  [%u] [0x%llx-0x%llx) mirrored",
		    sg->sg_index, SK_KVA(sg), SK_KVA(addr),
		    SK_KVA((uintptr_t)addr + skr->skr_seg_size));
	}
#endif /* SK_LOG */

	/*
	 * If mirroring, also free shadow object in slave region.
	 */
	if (skr->skr_mirror != NULL) {
		ASSERT(maddr != NULL);
		ASSERT(skr->skr_mirror != skr);
		ASSERT(!(skr->skr_mode & SKR_MODE_MIRRORED));
		ASSERT(skr->skr_mirror->skr_mode & SKR_MODE_MIRRORED);
		skmem_region_free(skr->skr_mirror, maddr, NULL);
	}

	/* wake up any blocked threads waiting for a segment */
	if (skr->skr_seg_waiters != 0) {
		SK_DF(SK_VERB_MEM_REGION,
		    "sg 0x%llx waking up %u waiters", SK_KVA(sg),
		    skr->skr_seg_waiters);
		skr->skr_seg_waiters = 0;
		wakeup(&skr->skr_seg_free);
	}
	SKR_UNLOCK(skr);
}

__attribute__((always_inline))
static inline void
skmem_region_retain_locked(struct skmem_region *skr)
{
	SKR_LOCK_ASSERT_HELD(skr);
	skr->skr_refcnt++;
	ASSERT(skr->skr_refcnt != 0);
}

/*
 * Retain a segment.
 */
void
skmem_region_retain(struct skmem_region *skr)
{
	SKR_LOCK(skr);
	skmem_region_retain_locked(skr);
	SKR_UNLOCK(skr);
}

__attribute__((always_inline))
static inline boolean_t
skmem_region_release_locked(struct skmem_region *skr)
{
	SKR_LOCK_ASSERT_HELD(skr);
	ASSERT(skr->skr_refcnt != 0);
	if (--skr->skr_refcnt == 0) {
		skmem_region_destroy(skr);
		return TRUE;
	}
	return FALSE;
}

/*
 * Release (and potentially destroy) a segment.
 */
boolean_t
skmem_region_release(struct skmem_region *skr)
{
	boolean_t lastref;

	SKR_LOCK(skr);
	if (!(lastref = skmem_region_release_locked(skr))) {
		SKR_UNLOCK(skr);
	}

	return lastref;
}

/*
 * Depopulate the segment freelist.
 */
static void
skmem_region_depopulate(struct skmem_region *skr)
{
	struct sksegment *sg, *tsg;

	SK_DF(SK_VERB_MEM_REGION, "\"%s\": skr 0x%llx ",
	    skr->skr_name, SK_KVA(skr));

	SKR_LOCK_ASSERT_HELD(skr);
	ASSERT(skr->skr_seg_bmap_len != 0 || (skr->skr_mode & SKR_MODE_PSEUDO));

	TAILQ_FOREACH_SAFE(sg, &skr->skr_seg_free, sg_link, tsg) {
		struct sksegment *sg0;
		uint32_t i;

		i = sg->sg_index;
		sg0 = sksegment_freelist_remove(skr, sg, 0, TRUE);
		VERIFY(sg0 == sg);

		sksegment_destroy(skr, sg);
		ASSERT(bit_test(skr->skr_seg_bmap[i / BMAPSZ], i % BMAPSZ));
	}
}

/*
 * Free tree segment compare routine.
 */
static int
sksegment_cmp(const struct sksegment *sg1, const struct sksegment *sg2)
{
	return sg1->sg_index - sg2->sg_index;
}

/*
 * Create a segment.
 *
 * Upon success, clear the bit for the segment's index in skr_seg_bmap bitmap.
 */
static struct sksegment *
sksegment_create(struct skmem_region *skr, uint32_t i)
{
	struct sksegment *sg = NULL;
	bitmap_t *bmap;

	SKR_LOCK_ASSERT_HELD(skr);

	ASSERT(!(skr->skr_mode & SKR_MODE_PSEUDO));
	ASSERT(i < skr->skr_seg_max_cnt);
	ASSERT(skr->skr_reg != NULL);
	ASSERT(skr->skr_seg_size == round_page(skr->skr_seg_size));

	bmap = &skr->skr_seg_bmap[i / BMAPSZ];
	ASSERT(bit_test(*bmap, i % BMAPSZ));

	sg = skmem_cache_alloc(skmem_sg_cache, SKMEM_SLEEP);
	bzero(sg, sg_size);

	sg->sg_region = skr;
	sg->sg_index = i;
	sg->sg_state = SKSEG_STATE_DETACHED;

	/* claim it (clear bit) */
	bit_clear(*bmap, i % BMAPSZ);

	SK_DF(SK_VERB_MEM_REGION, "  [%u] [0x%llx-0x%llx) 0x%b", i,
	    SK_KVA(sg->sg_start), SK_KVA(sg->sg_end), skr->skr_mode,
	    SKR_MODE_BITS);

	return sg;
}

/*
 * Destroy a segment.
 *
 * Set the bit for the segment's index in skr_seg_bmap bitmap,
 * indicating that it is now vacant.
 */
static void
sksegment_destroy(struct skmem_region *skr, struct sksegment *sg)
{
	uint32_t i = sg->sg_index;
	bitmap_t *bmap;

	SKR_LOCK_ASSERT_HELD(skr);

	ASSERT(!(skr->skr_mode & SKR_MODE_PSEUDO));
	ASSERT(skr == sg->sg_region);
	ASSERT(skr->skr_reg != NULL);
	ASSERT(sg->sg_type == SKSEG_TYPE_DESTROYED);
	ASSERT(i < skr->skr_seg_max_cnt);

	bmap = &skr->skr_seg_bmap[i / BMAPSZ];
	ASSERT(!bit_test(*bmap, i % BMAPSZ));

	SK_DF(SK_VERB_MEM_REGION, "  [%u] [0x%llx-0x%llx) 0x%b",
	    i, SK_KVA(sg->sg_start), SK_KVA(sg->sg_end),
	    skr->skr_mode, SKR_MODE_BITS);

	/*
	 * Undo what's done earlier at segment creation time.
	 */

	ASSERT(sg->sg_md == NULL);
	ASSERT(sg->sg_start == 0 && sg->sg_end == 0);
	ASSERT(sg->sg_state == SKSEG_STATE_DETACHED);

	/* release it (set bit) */
	bit_set(*bmap, i % BMAPSZ);

	skmem_cache_free(skmem_sg_cache, sg);
}

/*
 * Insert a segment into freelist (freeing the segment).
 */
static void
sksegment_freelist_insert(struct skmem_region *skr, struct sksegment *sg,
    boolean_t populating)
{
	SKR_LOCK_ASSERT_HELD(skr);

	ASSERT(!(skr->skr_mode & SKR_MODE_PSEUDO));
	ASSERT(sg->sg_type != SKSEG_TYPE_FREE);
	ASSERT(skr == sg->sg_region);
	ASSERT(skr->skr_reg != NULL);
	ASSERT(sg->sg_index < skr->skr_seg_max_cnt);

	/*
	 * If the region is being populated, then we're done.
	 */
	if (__improbable(populating)) {
		ASSERT(sg->sg_md == NULL);
		ASSERT(sg->sg_start == 0 && sg->sg_end == 0);
		ASSERT(sg->sg_state == SKSEG_STATE_DETACHED);
	} else {
		IOSKMemoryBufferRef md;
		IOReturn err;

		ASSERT(sg->sg_md != NULL);
		ASSERT(sg->sg_start != 0 && sg->sg_end != 0);

		/*
		 * Let the client remove the memory from IOMMU, and unwire it.
		 */
		if (skr->skr_seg_dtor != NULL) {
			skr->skr_seg_dtor(sg, sg->sg_md, skr->skr_private);
		}

		ASSERT(sg->sg_state == SKSEG_STATE_MAPPED ||
		    sg->sg_state == SKSEG_STATE_MAPPED_WIRED);

		IOSKRegionClearBufferDebug(skr->skr_reg, sg->sg_index, &md);
		VERIFY(sg->sg_md == md);

		/* if persistent, unwire this memory now */
		if (skr->skr_mode & SKR_MODE_PERSISTENT) {
			err = IOSKMemoryUnwire(md);
			if (err != kIOReturnSuccess) {
				panic("Fail to unwire md %p, err %d", md, err);
			}
		}

		/* mark memory as empty/discarded for consistency */
		err = IOSKMemoryDiscard(md);
		if (err != kIOReturnSuccess) {
			panic("Fail to discard md %p, err %d", md, err);
		}

		IOSKMemoryDestroy(md);
		sg->sg_md = NULL;
		sg->sg_start = sg->sg_end = 0;
		sg->sg_state = SKSEG_STATE_DETACHED;

		ASSERT(skr->skr_memtotal >= skr->skr_seg_size);
		skr->skr_memtotal -= skr->skr_seg_size;
	}

	sg->sg_type = SKSEG_TYPE_FREE;
	ASSERT(sg->sg_link.tqe_next == NULL);
	ASSERT(sg->sg_link.tqe_prev == NULL);
	TAILQ_INSERT_TAIL(&skr->skr_seg_free, sg, sg_link);
	ASSERT(sg->sg_node.rbe_left == NULL);
	ASSERT(sg->sg_node.rbe_right == NULL);
	ASSERT(sg->sg_node.rbe_parent == NULL);
	RB_INSERT(segtfreehead, &skr->skr_seg_tfree, sg);
	++skr->skr_seg_free_cnt;
	ASSERT(skr->skr_seg_free_cnt <= skr->skr_seg_max_cnt);
}

/*
 * Remove a segment from the freelist (allocating the segment).
 */
static struct sksegment *
sksegment_freelist_remove(struct skmem_region *skr, struct sksegment *sg,
    uint32_t skmflag, boolean_t purging)
{
#pragma unused(skmflag)
	mach_vm_address_t segstart;
	IOReturn err;

	SKR_LOCK_ASSERT_HELD(skr);

	ASSERT(!(skr->skr_mode & SKR_MODE_PSEUDO));
	ASSERT(sg != NULL);
	ASSERT(skr == sg->sg_region);
	ASSERT(skr->skr_reg != NULL);
	ASSERT(sg->sg_type == SKSEG_TYPE_FREE);
	ASSERT(sg->sg_index < skr->skr_seg_max_cnt);

#if (DEVELOPMENT || DEBUG)
	uint64_t mtbf = skmem_region_get_mtbf();
	/*
	 * MTBF doesn't apply when SKMEM_PANIC is set as caller would assert.
	 */
	if (__improbable(mtbf != 0 && !purging &&
	    (net_uptime_ms() % mtbf) == 0 &&
	    !(skmflag & SKMEM_PANIC))) {
		SK_ERR("skr \"%s\" 0x%llx sg 0x%llx MTBF failure",
		    skr->skr_name, SK_KVA(skr), SK_KVA(sg));
		net_update_uptime();
		return NULL;
	}
#endif /* (DEVELOPMENT || DEBUG) */

	TAILQ_REMOVE(&skr->skr_seg_free, sg, sg_link);
	sg->sg_link.tqe_next = NULL;
	sg->sg_link.tqe_prev = NULL;
	RB_REMOVE(segtfreehead, &skr->skr_seg_tfree, sg);
	sg->sg_node.rbe_left = NULL;
	sg->sg_node.rbe_right = NULL;
	sg->sg_node.rbe_parent = NULL;

	ASSERT(skr->skr_seg_free_cnt != 0);
	--skr->skr_seg_free_cnt;

	/*
	 * If the region is being depopulated, then we're done.
	 */
	if (__improbable(purging)) {
		ASSERT(sg->sg_md == NULL);
		ASSERT(sg->sg_start == 0 && sg->sg_end == 0);
		ASSERT(sg->sg_state == SKSEG_STATE_DETACHED);
		sg->sg_type = SKSEG_TYPE_DESTROYED;
		return sg;
	}

	ASSERT(sg->sg_md == NULL);
	ASSERT(sg->sg_start == 0 && sg->sg_end == 0);
	ASSERT(sg->sg_state == SKSEG_STATE_DETACHED);

	/* created as non-volatile (mapped) upon success */
	if ((sg->sg_md = IOSKMemoryBufferCreate(skr->skr_seg_size,
	    &skr->skr_bufspec, &segstart)) == NULL) {
		ASSERT(sg->sg_type == SKSEG_TYPE_FREE);
		if (skmflag & SKMEM_PANIC) {
			/* if the caller insists for a success then panic */
			panic_plain("\"%s\": skr 0x%p sg 0x%p (idx %u) unable "
			    "to satisfy mandatory allocation\n", skr->skr_name,
			    skr, sg, sg->sg_index);
			/* NOTREACHED */
			__builtin_unreachable();
		}
		/* reinsert this segment to freelist */
		ASSERT(sg->sg_link.tqe_next == NULL);
		ASSERT(sg->sg_link.tqe_prev == NULL);
		TAILQ_INSERT_HEAD(&skr->skr_seg_free, sg, sg_link);
		ASSERT(sg->sg_node.rbe_left == NULL);
		ASSERT(sg->sg_node.rbe_right == NULL);
		ASSERT(sg->sg_node.rbe_parent == NULL);
		RB_INSERT(segtfreehead, &skr->skr_seg_tfree, sg);
		++skr->skr_seg_free_cnt;
		return NULL;
	}

	sg->sg_start = segstart;
	sg->sg_end = (segstart + skr->skr_seg_size);
	ASSERT(sg->sg_start != 0 && sg->sg_end != 0);

	/* mark memory as non-volatile just to be consistent */
	err = IOSKMemoryReclaim(sg->sg_md);
	if (err != kIOReturnSuccess) {
		panic("Fail to reclaim md %p, err %d", sg->sg_md, err);
	}

	/* if persistent, wire down its memory now */
	if (skr->skr_mode & SKR_MODE_PERSISTENT) {
		err = IOSKMemoryWire(sg->sg_md);
		if (err != kIOReturnSuccess) {
			panic("Fail to wire md %p, err %d", sg->sg_md, err);
		}
	}

	err = IOSKRegionSetBuffer(skr->skr_reg, sg->sg_index, sg->sg_md);
	if (err != kIOReturnSuccess) {
		panic("Fail to set md %p, err %d", sg->sg_md, err);
	}

	/*
	 * Let the client wire it and insert to IOMMU, if applicable.
	 * Try to find out if it's wired and set the right state.
	 */
	if (skr->skr_seg_ctor != NULL) {
		skr->skr_seg_ctor(sg, sg->sg_md, skr->skr_private);
	}

	sg->sg_state = IOSKBufferIsWired(sg->sg_md) ?
	    SKSEG_STATE_MAPPED_WIRED : SKSEG_STATE_MAPPED;

	skr->skr_memtotal += skr->skr_seg_size;

	ASSERT(sg->sg_md != NULL);
	ASSERT(sg->sg_start != 0 && sg->sg_end != 0);

	sg->sg_type = SKSEG_TYPE_ALLOC;
	return sg;
}

/*
 * Find the first available index and allocate a segment at that index.
 */
static struct sksegment *
sksegment_freelist_grow(struct skmem_region *skr)
{
	struct sksegment *sg = NULL;
	uint32_t i, j, idx;

	SKR_LOCK_ASSERT_HELD(skr);

	ASSERT(!(skr->skr_mode & SKR_MODE_PSEUDO));
	ASSERT(skr->skr_seg_bmap_len != 0);
	ASSERT(skr->skr_seg_max_cnt != 0);

	for (i = 0; i < skr->skr_seg_bmap_len; i++) {
		bitmap_t *bmap, mask;
		uint32_t end = (BMAPSZ - 1);

		if (i == (skr->skr_seg_bmap_len - 1)) {
			end = (skr->skr_seg_max_cnt - 1) % BMAPSZ;
		}

		bmap = &skr->skr_seg_bmap[i];
		mask = BMASK64(0, end);

		j = ffsll((*bmap) & mask);
		if (j == 0) {
			continue;
		}

		--j;
		idx = (i * BMAPSZ) + j;

		sg = sksegment_alloc_with_idx(skr, idx);

		/* we're done */
		break;
	}

	ASSERT((sg != NULL) || (skr->skr_seginuse == skr->skr_seg_max_cnt));
	return sg;
}

/*
 * Create a single segment at a specific index and add it to the freelist.
 */
static struct sksegment *
sksegment_alloc_with_idx(struct skmem_region *skr, uint32_t idx)
{
	struct sksegment *sg;

	SKR_LOCK_ASSERT_HELD(skr);

	if (!bit_test(skr->skr_seg_bmap[idx / BMAPSZ], idx % BMAPSZ)) {
		panic("%s: '%s' (%p) idx %u (out of %u) is already allocated",
		    __func__, skr->skr_name, (void *)skr, idx,
		    (skr->skr_seg_max_cnt - 1));
		/* NOTREACHED */
		__builtin_unreachable();
	}

	/* must not fail, blocking alloc */
	sg = sksegment_create(skr, idx);
	VERIFY(sg != NULL);
	VERIFY(!bit_test(skr->skr_seg_bmap[idx / BMAPSZ], idx % BMAPSZ));

	/* populate the freelist */
	sksegment_freelist_insert(skr, sg, TRUE);
	ASSERT(sg == TAILQ_LAST(&skr->skr_seg_free, segfreehead));
#if (DEVELOPMENT || DEBUG)
	struct sksegment sg_key = { .sg_index = sg->sg_index };
	ASSERT(sg == RB_FIND(segtfreehead, &skr->skr_seg_tfree, &sg_key));
#endif /* (DEVELOPMENT || DEBUG) */

	SK_DF(SK_VERB_MEM_REGION, "sg %u/%u", (idx + 1), skr->skr_seg_max_cnt);

	return sg;
}

/*
 * Rescale the regions's allocated-address hash table.
 */
static void
skmem_region_hash_rescale(struct skmem_region *skr)
{
	struct sksegment_bkt *old_table, *new_table;
	size_t old_size, new_size;
	uint32_t i, moved = 0;

	if (skr->skr_mode & SKR_MODE_PSEUDO) {
		ASSERT(skr->skr_hash_table == NULL);
		/* this is no-op for pseudo region */
		return;
	}

	ASSERT(skr->skr_hash_table != NULL);
	/* insist that we are executing in the update thread call context */
	ASSERT(sk_is_region_update_protected());

	/*
	 * To get small average lookup time (lookup depth near 1.0), the hash
	 * table size should be roughly the same (not necessarily equivalent)
	 * as the region size.
	 */
	new_size = MAX(skr->skr_hash_initial,
	    (1 << (flsll(3 * skr->skr_seginuse + 4) - 2)));
	new_size = MIN(skr->skr_hash_limit, new_size);
	old_size = (skr->skr_hash_mask + 1);

	if ((old_size >> 1) <= new_size && new_size <= (old_size << 1)) {
		return;
	}

	new_table = sk_alloc_type_array(struct sksegment_bkt, new_size,
	    Z_NOWAIT, skmem_tag_segment_hash);
	if (__improbable(new_table == NULL)) {
		return;
	}

	for (i = 0; i < new_size; i++) {
		TAILQ_INIT(&new_table[i].sgb_head);
	}

	SKR_LOCK(skr);

	old_size = (skr->skr_hash_mask + 1);
	old_table = skr->skr_hash_table;

	skr->skr_hash_mask = (uint32_t)(new_size - 1);
	skr->skr_hash_table = new_table;
	skr->skr_rescale++;

	for (i = 0; i < old_size; i++) {
		struct sksegment_bkt *sgb = &old_table[i];
		struct sksegment_bkt *new_sgb;
		struct sksegment *sg;

		while ((sg = TAILQ_FIRST(&sgb->sgb_head)) != NULL) {
			TAILQ_REMOVE(&sgb->sgb_head, sg, sg_link);
			ASSERT(sg->sg_start != 0 && sg->sg_end != 0);
			new_sgb = SKMEM_REGION_HASH(skr, sg->sg_start);
			TAILQ_INSERT_TAIL(&new_sgb->sgb_head, sg, sg_link);
			++moved;
		}
		ASSERT(TAILQ_EMPTY(&sgb->sgb_head));
	}

	SK_DF(SK_VERB_MEM_REGION,
	    "skr 0x%llx old_size %u new_size %u [%u moved]", SK_KVA(skr),
	    (uint32_t)old_size, (uint32_t)new_size, moved);

	SKR_UNLOCK(skr);

	sk_free_type_array(struct sksegment_bkt, old_size, old_table);
}

/*
 * Apply a function to operate on all regions.
 */
static void
skmem_region_applyall(void (*func)(struct skmem_region *))
{
	struct skmem_region *skr;

	net_update_uptime();

	SKMEM_REGION_LOCK();
	TAILQ_FOREACH(skr, &skmem_region_head, skr_link) {
		func(skr);
	}
	SKMEM_REGION_UNLOCK();
}

static void
skmem_region_update(struct skmem_region *skr)
{
	SKMEM_REGION_LOCK_ASSERT_HELD();

	/* insist that we are executing in the update thread call context */
	ASSERT(sk_is_region_update_protected());

	SKR_LOCK(skr);
	/*
	 * If there are threads blocked waiting for an available
	 * segment, wake them up periodically so they can issue
	 * another skmem_cache_reap() to reclaim resources cached
	 * by skmem_cache.
	 */
	if (skr->skr_seg_waiters != 0) {
		SK_DF(SK_VERB_MEM_REGION,
		    "waking up %u waiters to reclaim", skr->skr_seg_waiters);
		skr->skr_seg_waiters = 0;
		wakeup(&skr->skr_seg_free);
	}
	SKR_UNLOCK(skr);

	/*
	 * Rescale the hash table if needed.
	 */
	skmem_region_hash_rescale(skr);
}

/*
 * Thread call callback for update.
 */
static void
skmem_region_update_func(thread_call_param_t dummy, thread_call_param_t arg)
{
#pragma unused(dummy, arg)
	sk_protect_t protect;

	protect = sk_region_update_protect();
	skmem_region_applyall(skmem_region_update);
	sk_region_update_unprotect(protect);

	skmem_dispatch(skmem_region_update_tc, NULL,
	    (skmem_region_update_interval * NSEC_PER_SEC));
}

boolean_t
skmem_region_for_pp(skmem_region_id_t id)
{
	int i;

	for (i = 0; i < SKMEM_PP_REGIONS; i++) {
		if (id == skmem_pp_region_ids[i]) {
			return TRUE;
		}
	}
	return FALSE;
}

void
skmem_region_get_stats(struct skmem_region *skr, struct sk_stats_region *sreg)
{
	bzero(sreg, sizeof(*sreg));

	(void) snprintf(sreg->sreg_name, sizeof(sreg->sreg_name),
	    "%s", skr->skr_name);
	uuid_copy(sreg->sreg_uuid, skr->skr_uuid);
	sreg->sreg_id = (sk_stats_region_id_t)skr->skr_id;
	sreg->sreg_mode = skr->skr_mode;

	sreg->sreg_r_seg_size = skr->skr_params.srp_r_seg_size;
	sreg->sreg_c_seg_size = skr->skr_seg_size;
	sreg->sreg_seg_cnt = skr->skr_seg_max_cnt;
	sreg->sreg_seg_objs = skr->skr_seg_objs;
	sreg->sreg_r_obj_size = skr->skr_r_obj_size;
	sreg->sreg_r_obj_cnt = skr->skr_r_obj_cnt;
	sreg->sreg_c_obj_size = skr->skr_c_obj_size;
	sreg->sreg_c_obj_cnt = skr->skr_c_obj_cnt;
	sreg->sreg_align = skr->skr_align;
	sreg->sreg_max_frags = skr->skr_max_frags;

	sreg->sreg_meminuse = skr->skr_meminuse;
	sreg->sreg_w_meminuse = skr->skr_w_meminuse;
	sreg->sreg_memtotal = skr->skr_memtotal;
	sreg->sreg_seginuse = skr->skr_seginuse;
	sreg->sreg_rescale = skr->skr_rescale;
	sreg->sreg_hash_size = (skr->skr_hash_mask + 1);
	sreg->sreg_alloc = skr->skr_alloc;
	sreg->sreg_free = skr->skr_free;
}

static size_t
skmem_region_mib_get_stats(struct skmem_region *skr, void *out, size_t len)
{
	size_t actual_space = sizeof(struct sk_stats_region);
	struct sk_stats_region *sreg = out;

	if (out == NULL || len < actual_space) {
		goto done;
	}

	skmem_region_get_stats(skr, sreg);

done:
	return actual_space;
}

static int
skmem_region_mib_get_sysctl SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2, oidp)
	struct skmem_region *skr;
	size_t actual_space;
	size_t buffer_space;
	size_t allocated_space;
	caddr_t buffer = NULL;
	caddr_t scan;
	int error = 0;

	if (!kauth_cred_issuser(kauth_cred_get())) {
		return EPERM;
	}

	net_update_uptime();
	buffer_space = req->oldlen;
	if (req->oldptr != USER_ADDR_NULL && buffer_space != 0) {
		if (buffer_space > SK_SYSCTL_ALLOC_MAX) {
			buffer_space = SK_SYSCTL_ALLOC_MAX;
		}
		allocated_space = buffer_space;
		buffer = sk_alloc_data(allocated_space, Z_WAITOK, skmem_tag_region_mib);
		if (__improbable(buffer == NULL)) {
			return ENOBUFS;
		}
	} else if (req->oldptr == USER_ADDR_NULL) {
		buffer_space = 0;
	}
	actual_space = 0;
	scan = buffer;

	SKMEM_REGION_LOCK();
	TAILQ_FOREACH(skr, &skmem_region_head, skr_link) {
		size_t size = skmem_region_mib_get_stats(skr, scan, buffer_space);
		if (scan != NULL) {
			if (buffer_space < size) {
				/* supplied buffer too small, stop copying */
				error = ENOMEM;
				break;
			}
			scan += size;
			buffer_space -= size;
		}
		actual_space += size;
	}
	SKMEM_REGION_UNLOCK();

	if (actual_space != 0) {
		int out_error = SYSCTL_OUT(req, buffer, actual_space);
		if (out_error != 0) {
			error = out_error;
		}
	}
	if (buffer != NULL) {
		sk_free_data(buffer, allocated_space);
	}

	return error;
}

#if SK_LOG
const char *
skmem_region_id2name(skmem_region_id_t id)
{
	const char *name;
	switch (id) {
	case SKMEM_REGION_SCHEMA:
		name = "SCHEMA";
		break;

	case SKMEM_REGION_RING:
		name = "RING";
		break;

	case SKMEM_REGION_BUF_DEF:
		name = "BUF_DEF";
		break;

	case SKMEM_REGION_BUF_LARGE:
		name = "BUF_LARGE";
		break;

	case SKMEM_REGION_RXBUF_DEF:
		name = "RXBUF_DEF";
		break;

	case SKMEM_REGION_RXBUF_LARGE:
		name = "RXBUF_LARGE";
		break;

	case SKMEM_REGION_TXBUF_DEF:
		name = "TXBUF_DEF";
		break;

	case SKMEM_REGION_TXBUF_LARGE:
		name = "TXBUF_LARGE";
		break;

	case SKMEM_REGION_UMD:
		name = "UMD";
		break;

	case SKMEM_REGION_TXAUSD:
		name = "TXAUSD";
		break;

	case SKMEM_REGION_RXFUSD:
		name = "RXFUSD";
		break;

	case SKMEM_REGION_USTATS:
		name = "USTATS";
		break;

	case SKMEM_REGION_FLOWADV:
		name = "FLOWADV";
		break;

	case SKMEM_REGION_NEXUSADV:
		name = "NEXUSADV";
		break;

	case SKMEM_REGION_SYSCTLS:
		name = "SYSCTLS";
		break;

	case SKMEM_REGION_GUARD_HEAD:
		name = "HEADGUARD";
		break;

	case SKMEM_REGION_GUARD_TAIL:
		name = "TAILGUARD";
		break;

	case SKMEM_REGION_KMD:
		name = "KMD";
		break;

	case SKMEM_REGION_RXKMD:
		name = "RXKMD";
		break;

	case SKMEM_REGION_TXKMD:
		name = "TXKMD";
		break;

	case SKMEM_REGION_TXAKSD:
		name = "TXAKSD";
		break;

	case SKMEM_REGION_RXFKSD:
		name = "RXFKSD";
		break;

	case SKMEM_REGION_KSTATS:
		name = "KSTATS";
		break;

	case SKMEM_REGION_KBFT:
		name = "KBFT";
		break;

	case SKMEM_REGION_UBFT:
		name = "UBFT";
		break;

	case SKMEM_REGION_RXKBFT:
		name = "RXKBFT";
		break;

	case SKMEM_REGION_TXKBFT:
		name = "TXKBFT";
		break;

	case SKMEM_REGION_INTRINSIC:
		name = "INTRINSIC";
		break;

	default:
		name = "UNKNOWN";
		break;
	}

	return name;
}
#endif /* SK_LOG */

#if (DEVELOPMENT || DEBUG)
uint64_t
skmem_region_get_mtbf(void)
{
	return skmem_region_mtbf;
}

void
skmem_region_set_mtbf(uint64_t newval)
{
	if (newval < SKMEM_REGION_MTBF_MIN) {
		if (newval != 0) {
			newval = SKMEM_REGION_MTBF_MIN;
		}
	} else if (newval > SKMEM_REGION_MTBF_MAX) {
		newval = SKMEM_REGION_MTBF_MAX;
	}

	if (skmem_region_mtbf != newval) {
		os_atomic_store(&skmem_region_mtbf, newval, release);
		SK_ERR("MTBF set to %llu msec", skmem_region_mtbf);
	}
}

static int
skmem_region_mtbf_sysctl(struct sysctl_oid *oidp, void *arg1, int arg2,
    struct sysctl_req *req)
{
#pragma unused(oidp, arg1, arg2)
	int changed, error;
	uint64_t newval;

	_CASSERT(sizeof(skmem_region_mtbf) == sizeof(uint64_t));
	if ((error = sysctl_io_number(req, skmem_region_mtbf,
	    sizeof(uint64_t), &newval, &changed)) == 0) {
		if (changed) {
			skmem_region_set_mtbf(newval);
		}
	}
	return error;
}
#endif /* (DEVELOPMENT || DEBUG) */
