/*
 * Copyright (c) 2000-2021 Apple Computer, Inc. All rights reserved.
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
 * @OSF_COPYRIGHT@
 */
/*
 * Mach Operating System
 * Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University
 * All Rights Reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */
/*
 */
/*
 *	File:	kern/kalloc.c
 *	Author:	Avadis Tevanian, Jr.
 *	Date:	1985
 *
 *	General kernel memory allocator.  This allocator is designed
 *	to be used by the kernel to manage dynamic memory fast.
 */

#include <mach/boolean.h>
#include <mach/sdt.h>
#include <mach/machine/vm_types.h>
#include <mach/vm_param.h>
#include <kern/misc_protos.h>
#include <kern/counter.h>
#include <kern/zalloc_internal.h>
#include <kern/kalloc.h>
#include <kern/ledger.h>
#include <kern/backtrace.h>
#include <vm/vm_kern.h>
#include <vm/vm_object.h>
#include <vm/vm_map.h>
#include <sys/kdebug.h>

#include <os/hash.h>
#include <san/kasan.h>
#include <libkern/section_keywords.h>
#include <libkern/prelink.h>

SCALABLE_COUNTER_DEFINE(kalloc_large_count);
SCALABLE_COUNTER_DEFINE(kalloc_large_total);

#pragma mark initialization

/*
 * All allocations of size less than KHEAP_MAX_SIZE are rounded to the next nearest
 * sized zone.  This allocator is built on top of the zone allocator.  A zone
 * is created for each potential size that we are willing to get in small
 * blocks.
 *
 * Allocations of size greater than KHEAP_MAX_SIZE, are allocated from the VM.
 */

/*
 * The k_zone_cfg table defines the configuration of zones on various platforms.
 * The currently defined list of zones and their per-CPU caching behavior are as
 * follows
 *
 *     X:zone not present
 *     N:zone present no cpu-caching
 *     Y:zone present with cpu-caching
 *
 * Size       macOS(64-bit)       embedded(32-bit)    embedded(64-bit)
 *--------    ----------------    ----------------    ----------------
 *
 * 8          X                    Y                   X
 * 16         Y                    Y                   Y
 * 24         X                    Y                   X
 * 32         Y                    Y                   Y
 * 40         X                    Y                   X
 * 48         Y                    Y                   Y
 * 64         Y                    Y                   Y
 * 72         X                    Y                   X
 * 80         Y                    X                   Y
 * 88         X                    Y                   X
 * 96         Y                    X                   Y
 * 112        X                    Y                   X
 * 128        Y                    Y                   Y
 * 160        Y                    X                   Y
 * 192        Y                    Y                   Y
 * 224        Y                    X                   Y
 * 256        Y                    Y                   Y
 * 288        Y                    Y                   Y
 * 368        Y                    X                   Y
 * 384        X                    Y                   X
 * 400        Y                    X                   Y
 * 440        X                    Y                   X
 * 512        Y                    Y                   Y
 * 576        Y                    N                   N
 * 768        Y                    N                   N
 * 1024       Y                    Y                   Y
 * 1152       N                    N                   N
 * 1280       N                    N                   N
 * 1536       X                    N                   X
 * 1664       N                    X                   N
 * 2048       Y                    N                   N
 * 2128       X                    N                   X
 * 3072       X                    N                   X
 * 4096       Y                    N                   N
 * 6144       N                    N                   N
 * 8192       Y                    N                   N
 * 12288      N                    X                   X
 * 16384      N                    X                   N
 * 32768      X                    X                   N
 *
 */
struct kalloc_zone_cfg {
	bool kzc_caching;
	uint32_t kzc_size;
	char kzc_name[MAX_ZONE_NAME];
};

#define KZC_ENTRY(SIZE, caching) { \
	.kzc_caching = (caching), \
	.kzc_size = (SIZE), \
	.kzc_name = "kalloc." #SIZE \
}
static SECURITY_READ_ONLY_LATE(struct kalloc_zone_cfg) k_zone_cfg[] = {
#if !defined(XNU_TARGET_OS_OSX)

#if KALLOC_MINSIZE == 16 && KALLOC_LOG2_MINALIGN == 4
	/* Zone config for embedded 64-bit platforms */
	KZC_ENTRY(16, true),
	KZC_ENTRY(32, true),
	KZC_ENTRY(48, true),
	KZC_ENTRY(64, true),
	KZC_ENTRY(80, true),
	KZC_ENTRY(96, true),
	KZC_ENTRY(128, true),
	KZC_ENTRY(160, true),
	KZC_ENTRY(192, true),
	KZC_ENTRY(224, true),
	KZC_ENTRY(256, true),
	KZC_ENTRY(288, true),
	KZC_ENTRY(368, true),
	KZC_ENTRY(400, true),
	KZC_ENTRY(512, true),
	KZC_ENTRY(576, false),
	KZC_ENTRY(768, false),
	KZC_ENTRY(1024, true),
	KZC_ENTRY(1152, false),
	KZC_ENTRY(1280, false),
	KZC_ENTRY(1664, false),
	KZC_ENTRY(2048, false),
	KZC_ENTRY(4096, false),
	KZC_ENTRY(6144, false),
	KZC_ENTRY(8192, false),
	KZC_ENTRY(16384, false),
	KZC_ENTRY(32768, false),

#elif KALLOC_MINSIZE == 8 && KALLOC_LOG2_MINALIGN == 3
	/* Zone config for embedded 32-bit platforms */
	KZC_ENTRY(8, true),
	KZC_ENTRY(16, true),
	KZC_ENTRY(24, true),
	KZC_ENTRY(32, true),
	KZC_ENTRY(40, true),
	KZC_ENTRY(48, true),
	KZC_ENTRY(64, true),
	KZC_ENTRY(72, true),
	KZC_ENTRY(88, true),
	KZC_ENTRY(112, true),
	KZC_ENTRY(128, true),
	KZC_ENTRY(192, true),
	KZC_ENTRY(256, true),
	KZC_ENTRY(288, true),
	KZC_ENTRY(384, true),
	KZC_ENTRY(440, true),
	KZC_ENTRY(512, true),
	KZC_ENTRY(576, false),
	KZC_ENTRY(768, false),
	KZC_ENTRY(1024, true),
	KZC_ENTRY(1152, false),
	KZC_ENTRY(1280, false),
	KZC_ENTRY(1536, false),
	KZC_ENTRY(2048, false),
	KZC_ENTRY(2128, false),
	KZC_ENTRY(3072, false),
	KZC_ENTRY(4096, false),
	KZC_ENTRY(6144, false),
	KZC_ENTRY(8192, false),
	/* To limit internal fragmentation, only add the following zones if the
	 * page size is greater than 4K.
	 * Note that we use ARM_PGBYTES here (instead of one of the VM macros)
	 * since it's guaranteed to be a compile time constant.
	 */
#if ARM_PGBYTES > 4096
	KZC_ENTRY(16384, false),
	KZC_ENTRY(32768, false),
#endif /* ARM_PGBYTES > 4096 */

#else
#error missing or invalid zone size parameters for kalloc
#endif

#else /* !defined(XNU_TARGET_OS_OSX) */

	/* Zone config for macOS 64-bit platforms */
	KZC_ENTRY(16, true),
	KZC_ENTRY(32, true),
	KZC_ENTRY(48, true),
	KZC_ENTRY(64, true),
	KZC_ENTRY(80, true),
	KZC_ENTRY(96, true),
	KZC_ENTRY(128, true),
	KZC_ENTRY(160, true),
	KZC_ENTRY(192, true),
	KZC_ENTRY(224, true),
	KZC_ENTRY(256, true),
	KZC_ENTRY(288, true),
	KZC_ENTRY(368, true),
	KZC_ENTRY(400, true),
	KZC_ENTRY(512, true),
	KZC_ENTRY(576, true),
	KZC_ENTRY(768, true),
	KZC_ENTRY(1024, true),
	KZC_ENTRY(1152, false),
	KZC_ENTRY(1280, false),
	KZC_ENTRY(1664, false),
	KZC_ENTRY(2048, true),
	KZC_ENTRY(4096, true),
	KZC_ENTRY(6144, false),
	KZC_ENTRY(8192, true),
#if __x86_64__
	KZC_ENTRY(12288, false),
#endif /* __x86_64__ */
	KZC_ENTRY(16384, false),
#if __arm64__
	KZC_ENTRY(32768, false),
#endif
#endif /* !defined(XNU_TARGET_OS_OSX) */
};


static SECURITY_READ_ONLY_LATE(struct kalloc_zone_cfg) k_zone_cfg_data[] = {
	KZC_ENTRY(16, true),
	KZC_ENTRY(32, true),
	KZC_ENTRY(48, true),
	KZC_ENTRY(64, true),
	KZC_ENTRY(96, true),
	KZC_ENTRY(128, true),
	KZC_ENTRY(160, true),
	KZC_ENTRY(192, true),
	KZC_ENTRY(256, true),
	KZC_ENTRY(368, true),
	KZC_ENTRY(512, true),
	KZC_ENTRY(768, false),
	KZC_ENTRY(1024, true),
	KZC_ENTRY(1152, false),
	KZC_ENTRY(1664, false),
	KZC_ENTRY(2048, false),
	KZC_ENTRY(4096, false),
	KZC_ENTRY(6144, false),
	KZC_ENTRY(8192, false),
	KZC_ENTRY(16384, false),
#if __arm64__
	KZC_ENTRY(32768, false),
#endif
};
#undef KZC_ENTRY

#define MAX_K_ZONE(kzc) (uint32_t)(sizeof(kzc) / sizeof(kzc[0]))

/*
 * Many kalloc() allocations are for small structures containing a few
 * pointers and longs - the dlut[] direct lookup table, indexed by
 * size normalized to the minimum alignment, finds the right zone index
 * for them in one dereference.
 */

#define INDEX_ZDLUT(size)  (((size) + KALLOC_MINALIGN - 1) / KALLOC_MINALIGN)
#define MAX_SIZE_ZDLUT     ((KALLOC_DLUT_SIZE - 1) * KALLOC_MINALIGN)

static SECURITY_READ_ONLY_LATE(zone_t) k_zone_default[MAX_K_ZONE(k_zone_cfg)];
static SECURITY_READ_ONLY_LATE(zone_t) k_zone_data[MAX_K_ZONE(k_zone_cfg_data)];

#if VM_TAG_SIZECLASSES
static_assert(VM_TAG_SIZECLASSES >= MAX_K_ZONE(k_zone_cfg));
#endif

const char * const kalloc_heap_names[] = {
	[KHEAP_ID_NONE]          = "",
	[KHEAP_ID_DEFAULT]       = "default.",
	[KHEAP_ID_DATA_BUFFERS]  = "data.",
	[KHEAP_ID_KT_VAR]        = "",
};

/*
 * Default kalloc heap configuration
 */
static SECURITY_READ_ONLY_LATE(struct kheap_zones) kalloc_zones_default = {
	.cfg         = k_zone_cfg,
	.heap_id     = KHEAP_ID_DEFAULT,
	.k_zone      = k_zone_default,
	.max_k_zone  = MAX_K_ZONE(k_zone_cfg)
};
SECURITY_READ_ONLY_LATE(struct kalloc_heap) KHEAP_DEFAULT[1] = {
	{
		.kh_zones    = &kalloc_zones_default,
		.kh_name     = "default.",
		.kh_heap_id  = KHEAP_ID_DEFAULT,
		.kh_tag      = VM_KERN_MEMORY_KALLOC
	}
};


/*
 * Bag of bytes heap configuration
 */
static SECURITY_READ_ONLY_LATE(struct kheap_zones) kalloc_zones_data = {
	.cfg         = k_zone_cfg_data,
	.heap_id     = KHEAP_ID_DATA_BUFFERS,
	.k_zone      = k_zone_data,
	.max_k_zone  = MAX_K_ZONE(k_zone_cfg_data)
};
SECURITY_READ_ONLY_LATE(struct kalloc_heap) KHEAP_DATA_BUFFERS[1] = {
	{
		.kh_zones    = &kalloc_zones_data,
		.kh_name     = "data.",
		.kh_heap_id  = KHEAP_ID_DATA_BUFFERS,
		.kh_tag      = VM_KERN_MEMORY_KALLOC_DATA,
	}
};

/*
 * Configuration of variable kalloc type heaps
 */
SECURITY_READ_ONLY_LATE(struct kt_heap_zones)
kalloc_type_heap_array[KT_VAR_MAX_HEAPS] = {};
SECURITY_READ_ONLY_LATE(struct kalloc_heap) KHEAP_KT_VAR[1] = {
	{
		.kh_name     = "kalloc.type.var",
		.kh_heap_id  = KHEAP_ID_KT_VAR,
		.kh_tag      = VM_KERN_MEMORY_KALLOC_TYPE
	}
};

/*
 * Initialize kalloc heap: Create zones, generate direct lookup table and
 * do a quick test on lookups
 */
__startup_func
static void
kalloc_zones_init(struct kalloc_heap *kheap)
{
	struct kheap_zones *zones = kheap->kh_zones;
	struct kalloc_zone_cfg *cfg = zones->cfg;
	zone_t *k_zone = zones->k_zone;
	vm_size_t size;

	/*
	 * Allocate a zone for each size we are going to handle.
	 */
	assert(zones->cfg[zones->max_k_zone - 1].kzc_size == KHEAP_MAX_SIZE);

	for (uint32_t i = 0; i < zones->max_k_zone &&
	    (size = cfg[i].kzc_size) <= KHEAP_MAX_SIZE; i++) {
		zone_create_flags_t flags = ZC_KASAN_NOREDZONE |
		    ZC_KASAN_NOQUARANTINE | ZC_KALLOC_HEAP | ZC_PGZ_USE_GUARDS;
		if (cfg[i].kzc_caching) {
			flags |= ZC_CACHING;
		}

		k_zone[i] = zone_create_ext(cfg[i].kzc_name, size, flags,
		    ZONE_ID_ANY, ^(zone_t z){
			zone_security_array[zone_index(z)].z_kheap_id = (uint8_t)zones->heap_id;
		});
	}

	/*
	 * Count all the "raw" views for zones in the heap.
	 */
	zone_view_count += zones->max_k_zone;

	/*
	 * Build the Direct LookUp Table for small allocations
	 * As k_zone_cfg is shared between the heaps the
	 * Direct LookUp Table is also shared and doesn't need to
	 * be rebuilt per heap.
	 */
	size = 0;
	for (int i = 0; i <= KALLOC_DLUT_SIZE; i++, size += KALLOC_MINALIGN) {
		uint8_t zindex = 0;

		while ((vm_size_t)(cfg[zindex].kzc_size) < size) {
			zindex++;
		}

		if (i == KALLOC_DLUT_SIZE) {
			zones->k_zindex_start = zindex;
			break;
		}
		zones->dlut[i] = zindex;
	}
}

__startup_func
static void
kalloc_init(void)
{
	/* Initialize kalloc default heap */
	kalloc_zones_init(KHEAP_DEFAULT);
	static_assert(KHEAP_MAX_SIZE >= KALLOC_SAFE_ALLOC_SIZE);

#if ZSECURITY_CONFIG(SUBMAP_USER_DATA)
	/* Initialize kalloc data buffers heap */
	kalloc_zones_init(KHEAP_DATA_BUFFERS);
#else
	*KHEAP_DATA_BUFFERS = *KHEAP_DEFAULT;
#endif
}
STARTUP(ZALLOC, STARTUP_RANK_THIRD, kalloc_init);

#define KEXT_ALIGN_SHIFT           6
#define KEXT_ALIGN_BYTES           (1<< KEXT_ALIGN_SHIFT)
#define KEXT_ALIGN_MASK            (KEXT_ALIGN_BYTES-1)
#define kt_scratch_size            (256ul << 10)
#define KALLOC_TYPE_SECTION(type) \
	(type == KTV_FIXED? "__kalloc_type": "__kalloc_var")

/*
 * Enum to specify the kalloc_type variant being used.
 */
__options_decl(kalloc_type_variant_t, uint16_t, {
	KTV_FIXED     = 0x0001,
	KTV_VAR       = 0x0002,
});

/*
 * Macros that generate the appropriate kalloc_type variant (i.e fixed or
 * variable) of the desired variable/function.
 */
#define kalloc_type_var(type, var)              \
	((type) == KTV_FIXED?                       \
	(vm_offset_t) kalloc_type_##var##_fixed:    \
	(vm_offset_t) kalloc_type_##var##_var)
#define kalloc_type_func(type, func, ...)       \
	((type) == KTV_FIXED?                       \
	kalloc_type_##func##_fixed(__VA_ARGS__):    \
	kalloc_type_##func##_var(__VA_ARGS__))

/*
 * Fields of kalloc_type views that are required to make a redirection
 * decision i.e VM or data-only
 */
struct kalloc_type_atom {
	kalloc_type_flags_t  kt_flags;
	vm_size_t            kt_size;
	const char          *kt_sig_hdr;
	const char          *kt_sig_type;
};

TUNABLE(kalloc_type_options_t, kt_options, "kt", KT_OPTIONS_LOOSE_FREE);
TUNABLE(uint16_t, kt_var_heaps, "kt_var_heaps",
    ZSECURITY_CONFIG_KT_VAR_BUDGET);
/*
 * Section start/end for fixed kalloc_type views
 */
extern struct kalloc_type_view kalloc_type_sec_start_fixed[]
__SECTION_START_SYM(KALLOC_TYPE_SEGMENT, "__kalloc_type");

extern struct kalloc_type_view kalloc_type_sec_end_fixed[]
__SECTION_END_SYM(KALLOC_TYPE_SEGMENT, "__kalloc_type");

/*
 * Section start/end for variable kalloc_type views
 */
extern struct kalloc_type_var_view kalloc_type_sec_start_var[]
__SECTION_START_SYM(KALLOC_TYPE_SEGMENT, "__kalloc_var");

extern struct kalloc_type_var_view kalloc_type_sec_end_var[]
__SECTION_END_SYM(KALLOC_TYPE_SEGMENT, "__kalloc_var");

typedef union kalloc_type_views {
	struct kalloc_type_view     *ktv_fixed;
	struct kalloc_type_var_view *ktv_var;
} kalloc_type_views_t;

__startup_data
static kalloc_type_views_t *kt_buffer = NULL;
__startup_data
static uint64_t kt_count;
__startup_data
uint32_t kalloc_type_hash_seed;

_Static_assert(__builtin_popcount(KT_SUMMARY_MASK_TYPE_BITS) == (KT_GRANULE_MAX + 1),
    "KT_SUMMARY_MASK_TYPE_BITS doesn't match KT_GRANULE_MAX");

#if DEBUG || DEVELOPMENT
/*
 * For use by lldb to iterate over kalloc types
 */
uint64_t num_kt_sizeclass = MAX_K_ZONE(k_zone_cfg);
SECURITY_READ_ONLY_LATE(zone_t) kalloc_type_zarray[MAX_K_ZONE(k_zone_cfg)];
#endif

#define KT_GET_HASH(flags) (uint16_t)((flags & KT_HASH) >> 16)
static_assert(KT_HASH >> 16 == (KMEM_RANGE_MASK | KMEM_HASH_SET |
    KMEM_DIRECTION_MASK),
    "Insufficient bits to represent range and dir for VM allocations");
static_assert(MAX_K_ZONE(k_zone_cfg) < KALLOC_TYPE_IDX_MASK,
    "validate idx mask");
/* qsort routines */
typedef int (*cmpfunc_t)(const void *a, const void *b);
extern void qsort(void *a, size_t n, size_t es, cmpfunc_t cmp);

static inline uint16_t
kalloc_type_get_idx(uint32_t kt_size)
{
	return (uint16_t) (kt_size >> KALLOC_TYPE_IDX_SHIFT);
}

static inline uint32_t
kalloc_type_set_idx(uint32_t kt_size, uint16_t idx)
{
	return kt_size | ((uint32_t) idx << KALLOC_TYPE_IDX_SHIFT);
}

static uint32_t
kalloc_idx_for_size(kalloc_heap_t kheap, uint32_t size)
{
	struct kheap_zones *khz = kheap->kh_zones;
	uint16_t idx;

	assert(size <= KHEAP_MAX_SIZE);

	if (size < MAX_SIZE_ZDLUT) {
		idx = khz->dlut[INDEX_ZDLUT(size)];
		return kalloc_type_set_idx(size, idx);
	}

	idx = khz->k_zindex_start;
	while (khz->cfg[idx].kzc_size < size) {
		idx++;
	}
	return kalloc_type_set_idx(size, idx);
}

static zone_t
kalloc_heap_zone_for_idx(kalloc_heap_t kheap, uint16_t zindex)
{
	struct kheap_zones *khz = kheap->kh_zones;
	return khz->k_zone[zindex];
}

static void
kalloc_type_assign_zone_fixed(kalloc_type_view_t *cur, kalloc_type_view_t *end,
    zone_t z)
{
	/*
	 * Assign the zone created for every kalloc_type_view
	 * of the same unique signature
	 */
	bool need_raw_view = false;
	while (cur < end) {
		kalloc_type_view_t kt = *cur;
		struct zone_view *zv = &kt->kt_zv;
		zv->zv_zone = z;
		kalloc_type_flags_t kt_flags = kt->kt_flags;

		if (kt_flags & KT_SLID) {
			kt->kt_signature -= vm_kernel_slide;
			kt->kt_zv.zv_name -= vm_kernel_slide;
		}

		if ((kt_flags & KT_PRIV_ACCT) ||
		    ((kt_options & KT_OPTIONS_ACCT) && (kt_flags & KT_DEFAULT))) {
			zv->zv_stats = zalloc_percpu_permanent_type(
				struct zone_stats);
			need_raw_view = true;
			zone_view_count += 1;
		} else {
			zv->zv_stats = z->z_stats;
		}
		zv->zv_next = (zone_view_t) z->z_views;
		zv->zv_zone->z_views = (zone_view_t) kt;
		cur++;
	}
	if (need_raw_view) {
		zone_view_count += 1;
	}
}

__startup_func
static void
kalloc_type_assign_zone_var(kalloc_type_var_view_t *cur,
    kalloc_type_var_view_t *end, uint32_t heap_idx)
{
	struct kt_heap_zones *cfg = &kalloc_type_heap_array[heap_idx];
	while (cur < end) {
		kalloc_type_var_view_t kt = *cur;
		zone_id_t zid = cfg->kh_zstart;
		kt->kt_heap_start = zid;
		kalloc_type_flags_t kt_flags = kt->kt_flags;

		if (kt_flags & KT_SLID) {
			if (kt->kt_sig_hdr) {
				kt->kt_sig_hdr -= vm_kernel_slide;
			}
			kt->kt_sig_type -= vm_kernel_slide;
			kt->kt_name -= vm_kernel_slide;
		}

		if ((kt_flags & KT_PRIV_ACCT) ||
		    ((kt_options & KT_OPTIONS_ACCT) && (kt_flags & KT_DEFAULT))) {
			kt->kt_stats = zalloc_percpu_permanent_type(struct zone_stats);
			zone_view_count += 1;
		}

		kt->kt_next = (zone_view_t) cfg->views;
		cfg->views = kt;
		cur++;
	}
}

static inline char
kalloc_type_granule_to_char(kt_granule_t granule)
{
	return (char) (granule + '0');
}

static bool
kalloc_type_sig_check(const char *sig, const kt_granule_t gr)
{
	while (*sig == kalloc_type_granule_to_char(gr & KT_GRANULE_PADDING) ||
	    *sig == kalloc_type_granule_to_char(gr & KT_GRANULE_POINTER) ||
	    *sig == kalloc_type_granule_to_char(gr & KT_GRANULE_DATA) ||
	    *sig == kalloc_type_granule_to_char(gr & KT_GRANULE_PAC)) {
		sig++;
	}
	return *sig == '\0';
}

/*
 * Check if signature of type is made up of only the specified granules
 */
static bool
kalloc_type_check(struct kalloc_type_atom kt_atom,
    kalloc_type_flags_t change_flag, kalloc_type_flags_t check_flag,
    const kt_granule_t check_gr)
{
	kalloc_type_flags_t flags = kt_atom.kt_flags;
	if (flags & change_flag) {
		return flags & check_flag;
	} else {
		bool kt_hdr_check = kt_atom.kt_sig_hdr?
		    kalloc_type_sig_check(kt_atom.kt_sig_hdr, check_gr): true;
		bool kt_type_check = kalloc_type_sig_check(kt_atom.kt_sig_type, check_gr);
		return kt_hdr_check && kt_type_check;
	}
}

/*
 * Check if signature of type is made up of only data and padding
 */
static bool
kalloc_type_is_data(struct kalloc_type_atom kt_atom)
{
	return kalloc_type_check(kt_atom, KT_CHANGED, KT_DATA_ONLY,
	           KT_GRANULE_DATA);
}

/*
 * Use this version after early boot as sites from kexts that haven't yet
 * been recompiled with the latest kalloc type defintions, have been fixed
 * up.
 */
static bool
kalloc_type_is_data_fast(struct kalloc_type_atom kt_atom)
{
	return kt_atom.kt_flags & KT_DATA_ONLY;
}

/*
 * Check if signature of type is made up of only pointers
 */
static bool
kalloc_type_is_ptr_array(struct kalloc_type_atom kt_atom)
{
	return kalloc_type_check(kt_atom, KT_CHANGED2, KT_PTR_ARRAY,
	           KT_GRANULE_POINTER | KT_GRANULE_PAC);
}

static bool
kalloc_type_from_vm(struct kalloc_type_atom kt_atom)
{
	kalloc_type_flags_t flags = kt_atom.kt_flags;
	if (flags & KT_CHANGED) {
		return flags & KT_VM;
	} else {
		return kt_atom.kt_size > KHEAP_MAX_SIZE;
	}
}

__startup_func
static inline vm_size_t
kalloc_type_view_sz_fixed(void)
{
	return sizeof(struct kalloc_type_view);
}

__startup_func
static inline vm_size_t
kalloc_type_view_sz_var(void)
{
	return sizeof(struct kalloc_type_var_view);
}

__startup_func
static inline uint64_t
kalloc_type_view_count(kalloc_type_variant_t type, vm_offset_t start,
    vm_offset_t end)
{
	return (end - start) / kalloc_type_func(type, view_sz);
}

static inline struct kalloc_type_atom
kalloc_type_get_atom_fixed(vm_offset_t addr, bool slide)
{
	struct kalloc_type_atom kt_atom = {};
	kalloc_type_view_t ktv = (struct kalloc_type_view *) addr;
	kt_atom.kt_flags = ktv->kt_flags;
	kt_atom.kt_size = ktv->kt_size;
	if (slide) {
		ktv->kt_signature += vm_kernel_slide;
		ktv->kt_zv.zv_name += vm_kernel_slide;
		ktv->kt_flags |= KT_SLID;
	}
	kt_atom.kt_sig_type = ktv->kt_signature;
	return kt_atom;
}

static inline struct kalloc_type_atom
kalloc_type_get_atom_var(vm_offset_t addr, bool slide)
{
	struct kalloc_type_atom kt_atom = {};
	kalloc_type_var_view_t ktv = (struct kalloc_type_var_view *) addr;
	kt_atom.kt_flags = ktv->kt_flags;
	kt_atom.kt_size = ktv->kt_size_hdr + ktv->kt_size_type;
	if (slide) {
		if (ktv->kt_sig_hdr) {
			ktv->kt_sig_hdr += vm_kernel_slide;
		}
		ktv->kt_sig_type += vm_kernel_slide;
		ktv->kt_name += vm_kernel_slide;
		ktv->kt_flags |= KT_SLID;
	}
	kt_atom.kt_sig_hdr = ktv->kt_sig_hdr;
	kt_atom.kt_sig_type = ktv->kt_sig_type;
	return kt_atom;
}

__startup_func
static inline void
kalloc_type_buffer_copy_fixed(kalloc_type_views_t *buffer, vm_offset_t ktv)
{
	buffer->ktv_fixed = (kalloc_type_view_t) ktv;
}

__startup_func
static inline void
kalloc_type_buffer_copy_var(kalloc_type_views_t *buffer, vm_offset_t ktv)
{
	buffer->ktv_var = (kalloc_type_var_view_t) ktv;
}

__startup_func
static void
kalloc_type_handle_data_view_fixed(vm_offset_t addr)
{
	kalloc_type_view_t cur_data_view = (kalloc_type_view_t) addr;
	cur_data_view->kt_size = kalloc_idx_for_size(KHEAP_DATA_BUFFERS,
	    cur_data_view->kt_size);
	uint16_t kt_idx = kalloc_type_get_idx(cur_data_view->kt_size);
	zone_t z = kalloc_heap_zone_for_idx(KHEAP_DATA_BUFFERS, kt_idx);
	kalloc_type_assign_zone_fixed(&cur_data_view, &cur_data_view + 1, z);
}

__startup_func
static void
kalloc_type_handle_data_view_var(vm_offset_t addr)
{
	kalloc_type_var_view_t ktv = (kalloc_type_var_view_t) addr;
	kalloc_type_flags_t kt_flags = ktv->kt_flags;

	/*
	 * To avoid having to recompute this until rdar://85182551 lands
	 * in the build and kexts are rebuilt.
	 */
	if (!(kt_flags & KT_CHANGED)) {
		ktv->kt_flags |= (KT_CHANGED | KT_DATA_ONLY);
	}

	kalloc_type_assign_zone_var(&ktv, &ktv + 1, KT_VAR_DATA_HEAP);
}

__startup_func
static void
kalloc_type_handle_parray_var(vm_offset_t addr)
{
	kalloc_type_var_view_t ktv = (kalloc_type_var_view_t) addr;
	kalloc_type_assign_zone_var(&ktv, &ktv + 1, KT_VAR_PTR_HEAP);
}

__startup_func
static uint32_t
kalloc_hash_adjust(uint32_t hash, uint32_t shift)
{
	/*
	 * Limit range_id to ptr ranges
	 */
	uint32_t range_id = kmem_adjust_range_id(hash);
	uint32_t direction = hash & 0x8000;
	return (range_id | KMEM_HASH_SET | direction) << shift;
}

__startup_func
static void
kalloc_type_set_type_hash(const char *sig_ty, const char *sig_hdr,
    kalloc_type_flags_t *kt_flags)
{
	uint32_t hash = 0;

	assert(sig_ty != NULL);
	hash = os_hash_jenkins_update(sig_ty, strlen(sig_ty),
	    kalloc_type_hash_seed);
	if (sig_hdr) {
		hash = os_hash_jenkins_update(sig_hdr, strlen(sig_hdr), hash);
	}
	os_hash_jenkins_finish(hash);
	hash &= (KMEM_RANGE_MASK | KMEM_DIRECTION_MASK);

	*kt_flags = *kt_flags | kalloc_hash_adjust(hash, 16);
}

__startup_func
static void
kalloc_type_set_type_hash_fixed(vm_offset_t addr)
{
	/*
	 * Use backtraces on fixed as we don't have signatures for types that go
	 * to the VM due to rdar://85182551.
	 */
	(void) addr;
}

__startup_func
static void
kalloc_type_set_type_hash_var(vm_offset_t addr)
{
	kalloc_type_var_view_t ktv = (kalloc_type_var_view_t) addr;
	kalloc_type_set_type_hash(ktv->kt_sig_type, ktv->kt_sig_hdr,
	    &ktv->kt_flags);
}

__startup_func
static void
kalloc_type_mark_processed_fixed(vm_offset_t addr)
{
	kalloc_type_view_t ktv = (kalloc_type_view_t) addr;
	ktv->kt_flags |= KT_PROCESSED;
}

__startup_func
static void
kalloc_type_mark_processed_var(vm_offset_t addr)
{
	kalloc_type_var_view_t ktv = (kalloc_type_var_view_t) addr;
	ktv->kt_flags |= KT_PROCESSED;
}

__startup_func
static void
kalloc_type_update_view_fixed(vm_offset_t addr)
{
	kalloc_type_view_t ktv = (kalloc_type_view_t) addr;
	ktv->kt_size = kalloc_idx_for_size(KHEAP_DEFAULT, ktv->kt_size);
}

__startup_func
static void
kalloc_type_update_view_var(vm_offset_t addr)
{
	(void) addr;
}

__startup_func
static void
kalloc_type_view_copy(const kalloc_type_variant_t type, vm_offset_t start,
    vm_offset_t end, uint64_t *cur_count, bool slide)
{
	uint64_t count = kalloc_type_view_count(type, start, end);
	if (count + *cur_count >= kt_count) {
		panic("kalloc_type_view_copy: Insufficient space in scratch buffer");
	}
	vm_offset_t cur = start;
	while (cur < end) {
		struct kalloc_type_atom kt_atom = kalloc_type_func(type, get_atom, cur,
		    slide);
		kalloc_type_func(type, mark_processed, cur);
		/*
		 * Skip views that go to the VM
		 */
		if (kalloc_type_from_vm(kt_atom)) {
			cur += kalloc_type_func(type, view_sz);
			continue;
		}

		/*
		 * If signature indicates that the entire allocation is data move it to
		 * KHEAP_DATA_BUFFERS. Note that KT_VAR_DATA_HEAP is a fake "data" heap,
		 * variable kalloc_type handles the actual redirection in the entry points
		 * kalloc/kfree_type_var_impl.
		 */
		if (kalloc_type_is_data(kt_atom)) {
			kalloc_type_func(type, handle_data_view, cur);
			cur += kalloc_type_func(type, view_sz);
			continue;
		}

		/*
		 * Set type hash that is used by kmem_*_guard
		 */
		kalloc_type_func(type, set_type_hash, cur);

		/*
		 * Redirect variable sized pointer arrays to KT_VAR_PTR_HEAP
		 */
		if (type == KTV_VAR && kalloc_type_is_ptr_array(kt_atom)) {
			kalloc_type_handle_parray_var(cur);
			cur += kalloc_type_func(type, view_sz);
			continue;
		}

		kalloc_type_func(type, update_view, cur);
		kalloc_type_func(type, buffer_copy, &kt_buffer[*cur_count], cur);
		cur += kalloc_type_func(type, view_sz);
		*cur_count = *cur_count + 1;
	}
}

__startup_func
static uint64_t
kalloc_type_view_parse(const kalloc_type_variant_t type)
{
	kc_format_t kc_format;
	uint64_t cur_count = 0;

	if (!PE_get_primary_kc_format(&kc_format)) {
		panic("kalloc_type_view_parse: wasn't able to determine kc format");
	}

	if (kc_format == KCFormatStatic) {
		/*
		 * If kc is static or KCGEN, __kalloc_type sections from kexts and
		 * xnu are coalesced.
		 */
		kalloc_type_view_copy(type,
		    kalloc_type_var(type, sec_start),
		    kalloc_type_var(type, sec_end),
		    &cur_count, 0);
	} else if (kc_format == KCFormatFileset) {
		/*
		 * If kc uses filesets, traverse __kalloc_type section for each
		 * macho in the BootKC.
		 */
		kernel_mach_header_t *kc_mh = NULL;
		kernel_mach_header_t *kext_mh = NULL;

		kc_mh = (kernel_mach_header_t *)PE_get_kc_header(KCKindPrimary);
		struct load_command *lc =
		    (struct load_command *)((vm_offset_t)kc_mh + sizeof(*kc_mh));
		for (uint32_t i = 0; i < kc_mh->ncmds;
		    i++, lc = (struct load_command *)((vm_offset_t)lc + lc->cmdsize)) {
			if (lc->cmd != LC_FILESET_ENTRY) {
				continue;
			}
			struct fileset_entry_command *fse =
			    (struct fileset_entry_command *)(vm_offset_t)lc;
			kext_mh = (kernel_mach_header_t *)fse->vmaddr;
			kernel_section_t *sect = (kernel_section_t *)getsectbynamefromheader(
				kext_mh, KALLOC_TYPE_SEGMENT, KALLOC_TYPE_SECTION(type));
			if (sect != NULL) {
				kalloc_type_view_copy(type, sect->addr, sect->addr + sect->size,
				    &cur_count, false);
			}
		}
	} else if (kc_format == KCFormatKCGEN) {
		/*
		 * Parse __kalloc_type section from xnu
		 */
		kalloc_type_view_copy(type,
		    kalloc_type_var(type, sec_start),
		    kalloc_type_var(type, sec_end), &cur_count, false);

#if defined(__LP64__)
		/*
		 * Parse __kalloc_type section for kexts
		 *
		 * Note: We don't process the kalloc_type_views for kexts on armv7
		 * as this platform has insufficient memory for type based
		 * segregation. kalloc_type_impl_external will direct callsites
		 * based on their size.
		 */
		kernel_mach_header_t *xnu_mh = &_mh_execute_header;
		vm_offset_t cur = 0;
		vm_offset_t end = 0;

		/*
		 * Kext machos are in the __PRELINK_TEXT segment. Extract the segment
		 * and traverse it.
		 */
		kernel_section_t *prelink_sect = getsectbynamefromheader(
			xnu_mh, kPrelinkTextSegment, kPrelinkTextSection);
		assert(prelink_sect);
		cur = prelink_sect->addr;
		end = prelink_sect->addr + prelink_sect->size;

		while (cur < end) {
			uint64_t kext_text_sz = 0;
			kernel_mach_header_t *kext_mh = (kernel_mach_header_t *) cur;

			if (kext_mh->magic == 0) {
				/*
				 * Assert that we have processed all kexts and all that is left
				 * is padding
				 */
				assert(memcmp_zero_ptr_aligned((void *)kext_mh, end - cur) == 0);
				break;
			} else if (kext_mh->magic != MH_MAGIC_64 &&
			    kext_mh->magic != MH_CIGAM_64) {
				panic("kalloc_type_view_parse: couldn't find kext @ offset:%lx",
				    cur);
			}

			/*
			 * Kext macho found, iterate through its segments
			 */
			struct load_command *lc =
			    (struct load_command *)(cur + sizeof(kernel_mach_header_t));
			bool isSplitKext = false;

			for (uint32_t i = 0; i < kext_mh->ncmds && (vm_offset_t)lc < end;
			    i++, lc = (struct load_command *)((vm_offset_t)lc + lc->cmdsize)) {
				if (lc->cmd == LC_SEGMENT_SPLIT_INFO) {
					isSplitKext = true;
					continue;
				} else if (lc->cmd != LC_SEGMENT_64) {
					continue;
				}

				kernel_segment_command_t *seg_cmd =
				    (struct segment_command_64 *)(vm_offset_t)lc;
				/*
				 * Parse kalloc_type section
				 */
				if (strcmp(seg_cmd->segname, KALLOC_TYPE_SEGMENT) == 0) {
					kernel_section_t *kt_sect = getsectbynamefromseg(seg_cmd,
					    KALLOC_TYPE_SEGMENT, KALLOC_TYPE_SECTION(type));
					if (kt_sect) {
						kalloc_type_view_copy(type, kt_sect->addr + vm_kernel_slide,
						    kt_sect->addr + kt_sect->size + vm_kernel_slide, &cur_count,
						    true);
					}
				}
				/*
				 * If the kext has a __TEXT segment, that is the only thing that
				 * will be in the special __PRELINK_TEXT KC segment, so the next
				 * macho is right after.
				 */
				if (strcmp(seg_cmd->segname, "__TEXT") == 0) {
					kext_text_sz = seg_cmd->filesize;
				}
			}
			/*
			 * If the kext did not have a __TEXT segment (special xnu kexts with
			 * only a __LINKEDIT segment) then the next macho will be after all the
			 * header commands.
			 */
			if (!kext_text_sz) {
				kext_text_sz = kext_mh->sizeofcmds;
			} else if (!isSplitKext) {
				panic("kalloc_type_view_parse: No support for non-split seg KCs");
				break;
			}

			cur += ((kext_text_sz + (KEXT_ALIGN_BYTES - 1)) & (~KEXT_ALIGN_MASK));
		}

#endif
	} else {
		/*
		 * When kc_format is KCFormatDynamic or KCFormatUnknown, we don't handle
		 * parsing kalloc_type_view structs during startup.
		 */
		panic("kalloc_type_view_parse: couldn't parse kalloc_type_view structs"
		    " for kc_format = %d\n", kc_format);
	}
	return cur_count;
}

__startup_func
static int
kalloc_type_cmp_fixed(const void *a, const void *b)
{
	const kalloc_type_view_t ktA = *(const kalloc_type_view_t *)a;
	const kalloc_type_view_t ktB = *(const kalloc_type_view_t *)b;

	const uint16_t idxA = kalloc_type_get_idx(ktA->kt_size);
	const uint16_t idxB = kalloc_type_get_idx(ktB->kt_size);
	/*
	 * If the kalloc_type_views are in the same kalloc bucket, sort by
	 * signature else sort by size
	 */
	if (idxA == idxB) {
		int result = strcmp(ktA->kt_signature, ktB->kt_signature);
		/*
		 * If the kalloc_type_views have the same signature sort by site
		 * name
		 */
		if (result == 0) {
			return strcmp(ktA->kt_zv.zv_name, ktB->kt_zv.zv_name);
		}
		return result;
	}
	const uint32_t sizeA = kalloc_type_get_size(ktA->kt_size);
	const uint32_t sizeB = kalloc_type_get_size(ktB->kt_size);
	return (int)(sizeA - sizeB);
}

__startup_func
static int
kalloc_type_cmp_var(const void *a, const void *b)
{
	const kalloc_type_var_view_t ktA = *(const kalloc_type_var_view_t *)a;
	const kalloc_type_var_view_t ktB = *(const kalloc_type_var_view_t *)b;

	const char *ktA_hdr = ktA->kt_sig_hdr ?: "";
	const char *ktB_hdr = ktB->kt_sig_hdr ?: "";

	int result = strcmp(ktA->kt_sig_type, ktB->kt_sig_type);
	if (result == 0) {
		return strcmp(ktA_hdr, ktB_hdr);
	}
	return result;
}

__startup_func
static uint16_t *
kalloc_type_create_iterators_fixed(uint16_t *kt_skip_list_start,
    uint16_t *kt_freq_list, uint16_t *kt_freq_list_total, uint64_t count)
{
	uint16_t *kt_skip_list = kt_skip_list_start;
	/*
	 * cur and prev kalloc size bucket
	 */
	uint16_t p_idx = 0;
	uint16_t c_idx = 0;

	/*
	 * Init values
	 */
	uint16_t unique_sig = 1;
	uint16_t total_sig = 0;
	kt_skip_list++;
	const char *p_sig = "";
	const char *p_name = "";

	/*
	 * Walk over each kalloc_type_view
	 */
	for (uint16_t i = 0; i < count; i++) {
		kalloc_type_view_t kt = kt_buffer[i].ktv_fixed;
		c_idx = kalloc_type_get_idx(kt->kt_size);
		/*
		 * When current kalloc_type_view is in a different kalloc size
		 * bucket than the previous, it means we have processed all in
		 * the previous size bucket, so store the accumulated values
		 * and advance the indices.
		 */
		if (c_idx != p_idx) {
			/*
			 * Updates for frequency lists
			 */
			kt_freq_list[p_idx] = unique_sig;
			unique_sig = 1;
			kt_freq_list_total[p_idx] = total_sig;
			total_sig = 1;
			p_idx = c_idx;

			/*
			 * Updates to signature skip list
			 */
			*kt_skip_list = i;
			kt_skip_list++;
			p_sig = kt->kt_signature;
			continue;
		}

		/*
		 * When current kalloc_type_views is in the kalloc size bucket as
		 * previous, analyze the siganture to see if it is unique.
		 *
		 * Signatures are collapsible if one is a substring of the next.
		 */
		const char *c_sig = kt->kt_signature;
		if (strncmp(c_sig, p_sig, strlen(p_sig)) != 0) {
			/*
			 * Unique signature detected. Update counts and advance index
			 */
			unique_sig++;
			*kt_skip_list = i;
			kt_skip_list++;
		}

		/*
		 * Check if current kalloc_type_view corresponds to a new type
		 */
		const char *c_name = kt->kt_zv.zv_name;
		if (strlen(p_name) != strlen(c_name) || strcmp(p_name, c_name) != 0) {
			total_sig++;
		}
		p_name = c_name;
		p_sig = c_sig;
	}
	/*
	 * Final update
	 */
	assert(c_idx == p_idx);
	assert(kt_freq_list[c_idx] == 0);
	kt_freq_list[c_idx] = unique_sig;
	kt_freq_list_total[c_idx] = (uint16_t) total_sig;
	*kt_skip_list = (uint16_t) count;
	return ++kt_skip_list;
}

#if ZSECURITY_CONFIG(KALLOC_TYPE)
__startup_func
static uint32_t
kalloc_type_create_iterators_var(uint32_t *kt_skip_list_start)
{
	uint32_t *kt_skip_list = kt_skip_list_start;
	uint32_t n = 0;
	kt_skip_list[n] = 0;
	assert(kt_count > 1);
	for (uint32_t i = 1; i < kt_count; i++) {
		kalloc_type_var_view_t ktA = kt_buffer[i - 1].ktv_var;
		kalloc_type_var_view_t ktB = kt_buffer[i].ktv_var;
		const char *ktA_hdr = ktA->kt_sig_hdr ?: "";
		const char *ktB_hdr = ktB->kt_sig_hdr ?: "";
		if (strcmp(ktA_hdr, ktB_hdr) != 0 ||
		    strcmp(ktA->kt_sig_type, ktB->kt_sig_type) != 0) {
			n++;
			kt_skip_list[n] = i;
		}
	}
	/*
	 * Final update
	 */
	n++;
	kt_skip_list[n] = (uint32_t) kt_count;
	return n;
}

__startup_func
static uint16_t
kalloc_type_apply_policy(uint16_t *kt_freq_list, uint16_t *kt_zones,
    uint16_t zone_budget)
{
	uint16_t total_sig = 0;
	uint16_t min_sig = 0;
	uint16_t assigned_zones = 0;
	uint16_t remaining_zones = zone_budget;
	uint16_t min_zones_per_size = 2;

#if DEBUG || DEVELOPMENT
	if (startup_phase < STARTUP_SUB_LOCKDOWN) {
		uint16_t current_zones = os_atomic_load(&num_zones, relaxed);
		assert(zone_budget + current_zones <= MAX_ZONES);
	}
#endif

	for (uint16_t i = 0; i < MAX_K_ZONE(k_zone_cfg); i++) {
		uint16_t sig_freq = kt_freq_list[i];
		uint16_t min_zones = min_zones_per_size;
		if (sig_freq < min_zones_per_size) {
			min_zones = sig_freq;
		}
		total_sig += sig_freq;
		kt_zones[i] = min_zones;
		min_sig += min_zones;
	}
	if (remaining_zones > total_sig) {
		remaining_zones = total_sig;
	}
	assert(remaining_zones >= min_sig);
	remaining_zones -= min_sig;
	total_sig -= min_sig;
	assigned_zones += min_sig;
	uint16_t modulo = 0;
	for (uint16_t i = 0; i < MAX_K_ZONE(k_zone_cfg); i++) {
		uint16_t freq = kt_freq_list[i];
		if (freq < min_zones_per_size) {
			continue;
		}
		uint32_t numer = (freq - min_zones_per_size) * remaining_zones;
		uint16_t n_zones = (uint16_t) numer / total_sig;

		/*
		 * Accumulate remainder and increment n_zones when it goes above
		 * denominator
		 */
		modulo += numer % total_sig;
		if (modulo >= total_sig) {
			n_zones++;
			modulo -= total_sig;
		}

		/*
		 * Cap the total number of zones to the unique signatures
		 */
		if ((n_zones + min_zones_per_size) > freq) {
			uint16_t extra_zones = n_zones + min_zones_per_size - freq;
			modulo += (extra_zones * total_sig);
			n_zones -= extra_zones;
		}
		kt_zones[i] += n_zones;
		assigned_zones += n_zones;
	}

	if (kt_options & KT_OPTIONS_DEBUG) {
		printf("kalloc_type_apply_policy: assigned %u zones wasted %u zones\n",
		    assigned_zones, remaining_zones + min_sig - assigned_zones);
	}
	return remaining_zones + min_sig - assigned_zones;
}

__startup_func
static void
kalloc_type_create_zone_for_size(zone_t *kt_zones_for_size,
    uint16_t kt_zones, vm_size_t z_size)
{
	zone_t p_zone = NULL;

	for (uint16_t i = 0; i < kt_zones; i++) {
		char *z_name = zalloc_permanent(MAX_ZONE_NAME, ZALIGN_NONE);
		snprintf(z_name, MAX_ZONE_NAME, "kalloc.type%u.%zu", i,
		    (size_t) z_size);
		zone_t z = zone_create(z_name, z_size, ZC_KALLOC_TYPE);
#if DEBUG || DEVELOPMENT
		if (i != 0) {
			p_zone->z_kt_next = z;
		}
#endif
		p_zone = z;
		kt_zones_for_size[i] = z;
	}
}
#endif /* ZSECURITY_CONFIG(KALLOC_TYPE) */

__startup_func
static void
kalloc_type_create_zones_fixed(uint16_t *kt_skip_list_start,
    uint16_t *kt_freq_list, uint16_t *kt_freq_list_total,
    uint16_t *kt_shuffle_buf)
{
	uint16_t *kt_skip_list = kt_skip_list_start;
	uint16_t p_j = 0;

	uint16_t kt_zones[MAX_K_ZONE(k_zone_cfg)] = {};

#if DEBUG || DEVELOPMENT
	uint64_t kt_shuffle_count = ((vm_address_t) kt_shuffle_buf -
	    (vm_address_t) kt_buffer) / sizeof(uint16_t);
#endif
	/*
	 * Apply policy to determine how many zones to create for each size
	 * class.
	 */
#if ZSECURITY_CONFIG(KALLOC_TYPE)
	kalloc_type_apply_policy(kt_freq_list, kt_zones,
	    ZSECURITY_CONFIG_KT_BUDGET);
	/*
	 * Print stats when KT_OPTIONS_DEBUG boot-arg present
	 */
	if (kt_options & KT_OPTIONS_DEBUG) {
		printf("Size\ttotal_sig\tunique_signatures\tzones\n");
		for (uint32_t i = 0; i < MAX_K_ZONE(k_zone_cfg); i++) {
			printf("%u\t%u\t%u\t%u\n", k_zone_cfg[i].kzc_size,
			    kt_freq_list_total[i], kt_freq_list[i], kt_zones[i]);
		}
	}
#else /* ZSECURITY_CONFIG(KALLOC_TYPE) */
#pragma unused(kt_freq_list_total)
#endif /* !ZSECURITY_CONFIG(KALLOC_TYPE) */

	for (uint16_t i = 0; i < MAX_K_ZONE(k_zone_cfg); i++) {
		uint16_t n_unique_sig = kt_freq_list[i];
		vm_size_t z_size = k_zone_cfg[i].kzc_size;
		uint16_t n_zones = kt_zones[i];

		if (n_unique_sig == 0) {
			continue;
		}

		assert(n_zones <= 20);
		zone_t kt_zones_for_size[20] = {};
#if ZSECURITY_CONFIG(KALLOC_TYPE)
		kalloc_type_create_zone_for_size(kt_zones_for_size,
		    n_zones, z_size);
#else /* ZSECURITY_CONFIG(KALLOC_TYPE) */
		/*
		 * Default to using KHEAP_DEFAULT if this feature is off
		 */
		n_zones = 1;
		kt_zones_for_size[0] = kalloc_heap_zone_for_size(
			KHEAP_DEFAULT, z_size);
#endif /* !ZSECURITY_CONFIG(KALLOC_TYPE) */

#if DEBUG || DEVELOPMENT
		kalloc_type_zarray[i] = kt_zones_for_size[0];
		/*
		 * Ensure that there is enough space to shuffle n_unique_sig
		 * indices
		 */
		assert(n_unique_sig < kt_shuffle_count);
#endif

		/*
		 * Get a shuffled set of signature indices
		 */
		*kt_shuffle_buf = 0;
		if (n_unique_sig > 1) {
			kmem_shuffle(kt_shuffle_buf, n_unique_sig);
		}

		for (uint16_t j = 0; j < n_unique_sig; j++) {
			/*
			 * For every size that has unique types
			 */
			uint16_t shuffle_idx = kt_shuffle_buf[j];
			uint16_t cur = kt_skip_list[shuffle_idx + p_j];
			uint16_t end = kt_skip_list[shuffle_idx + p_j + 1];
			zone_t zone = kt_zones_for_size[j % n_zones];
			kalloc_type_assign_zone_fixed(&kt_buffer[cur].ktv_fixed,
			    &kt_buffer[end].ktv_fixed, zone);
		}
		p_j += n_unique_sig;
	}
}

#if ZSECURITY_CONFIG(KALLOC_TYPE)
__startup_func
static void
kalloc_type_create_zones_var(void)
{
	size_t kheap_zsize[KHEAP_NUM_ZONES] = {};
	size_t step = KHEAP_STEP_START;
	uint32_t start = 0;
	/*
	 * Manually initialize extra initial zones
	 */
#if !__LP64__
	kheap_zsize[start] = 8;
	start++;
#endif
	kheap_zsize[start] = 16;
	kheap_zsize[start + 1] = KHEAP_START_SIZE;

	/*
	 * Compute sizes for remaining zones
	 */
	for (uint32_t i = 0; i < KHEAP_NUM_STEPS; i++) {
		uint32_t step_idx = (i * 2) + KHEAP_EXTRA_ZONES;
		kheap_zsize[step_idx] = kheap_zsize[step_idx - 1] + step;
		kheap_zsize[step_idx + 1] = kheap_zsize[step_idx] + step;
		step *= 2;
	}

	/*
	 * Create zones
	 */
	assert(kt_var_heaps + 1 <= KT_VAR_MAX_HEAPS);
	for (uint32_t i = KT_VAR_PTR_HEAP; i < kt_var_heaps + 1; i++) {
		for (uint32_t j = 0; j < KHEAP_NUM_ZONES; j++) {
			char *z_name = zalloc_permanent(MAX_ZONE_NAME, ZALIGN_NONE);
			snprintf(z_name, MAX_ZONE_NAME, "%s%u.%zu", KHEAP_KT_VAR->kh_name, i,
			    kheap_zsize[j]);
			zone_create_flags_t flags = ZC_KASAN_NOREDZONE |
			    ZC_KASAN_NOQUARANTINE | ZC_KALLOC_TYPE |
			    ZC_PGZ_USE_GUARDS;

			zone_t z_ptr = zone_create_ext(z_name, kheap_zsize[j], flags,
			    ZONE_ID_ANY, ^(zone_t z){
				zone_security_array[zone_index(z)].z_kheap_id = KHEAP_ID_KT_VAR;
			});
			if (j == 0) {
				kalloc_type_heap_array[i].kh_zstart = zone_index(z_ptr);
			}
		}
	}

	/*
	 * All variable kalloc type allocations are collapsed into a single
	 * stat. Individual accounting can be requested via KT_PRIV_ACCT
	 */
	KHEAP_KT_VAR->kh_stats = zalloc_percpu_permanent_type(struct zone_stats);
	zone_view_count += 1;
}
#endif /* !ZSECURITY_CONFIG(KALLOC_TYPE) */


__startup_func
static void
kalloc_type_view_init_fixed(void)
{
	kalloc_type_hash_seed = (uint32_t) early_random();
	/*
	 * Parse __kalloc_type sections and build array of pointers to
	 * all kalloc type views in kt_buffer.
	 */
	kt_count = kalloc_type_view_parse(KTV_FIXED);
	assert(kt_count < KALLOC_TYPE_SIZE_MASK);

#if DEBUG || DEVELOPMENT
	vm_size_t sig_slist_size = (size_t) kt_count * sizeof(uint16_t);
	vm_size_t kt_buffer_size = (size_t) kt_count * sizeof(kalloc_type_view_t);
	assert(kt_scratch_size >= kt_buffer_size + sig_slist_size);
#endif

	/*
	 * Sort based on size class and signature
	 */
	qsort(kt_buffer, (size_t) kt_count, sizeof(kalloc_type_view_t),
	    kalloc_type_cmp_fixed);

	/*
	 * Build a skip list that holds starts of unique signatures and a
	 * frequency list of number of unique and total signatures per kalloc
	 * size class
	 */
	uint16_t *kt_skip_list_start = (uint16_t *)(kt_buffer + kt_count);
	uint16_t kt_freq_list[MAX_K_ZONE(k_zone_cfg)] = { 0 };
	uint16_t kt_freq_list_total[MAX_K_ZONE(k_zone_cfg)] = { 0 };
	uint16_t *kt_shuffle_buf = kalloc_type_create_iterators_fixed(
		kt_skip_list_start, kt_freq_list, kt_freq_list_total, kt_count);

	/*
	 * Create zones based on signatures
	 */
	kalloc_type_create_zones_fixed(kt_skip_list_start, kt_freq_list,
	    kt_freq_list_total, kt_shuffle_buf);
}

#if ZSECURITY_CONFIG(KALLOC_TYPE)
__startup_func
static void
kalloc_type_view_init_var(void)
{
	/*
	 * Zones are created prior to parsing the views as zone budget is fixed
	 * per sizeclass and special types identified while parsing are redirected
	 * as they are discovered.
	 */
	kalloc_type_create_zones_var();

	/*
	 * Parse __kalloc_var sections and build array of pointers to views that
	 * aren't rediected in kt_buffer.
	 */
	kt_count = kalloc_type_view_parse(KTV_VAR);
	assert(kt_count < UINT32_MAX);

#if DEBUG || DEVELOPMENT
	vm_size_t sig_slist_size = (size_t) kt_count * sizeof(uint32_t);
	vm_size_t kt_buffer_size = (size_t) kt_count * sizeof(kalloc_type_views_t);
	assert(kt_scratch_size >= kt_buffer_size + sig_slist_size);
#endif

	/*
	 * Sort based on size class and signature
	 */
	qsort(kt_buffer, (size_t) kt_count, sizeof(kalloc_type_var_view_t),
	    kalloc_type_cmp_var);

	/*
	 * Build a skip list that holds starts of unique signatures
	 */
	uint32_t *kt_skip_list_start = (uint32_t *)(kt_buffer + kt_count);
	uint32_t unique_sig = kalloc_type_create_iterators_var(kt_skip_list_start);
	uint16_t fixed_heaps = KT_VAR__FIRST_FLEXIBLE_HEAP;
	/*
	 * If we have only one heap then other elements share heap with pointer
	 * arrays
	 */
	if (kt_var_heaps < KT_VAR__FIRST_FLEXIBLE_HEAP) {
		fixed_heaps = KT_VAR_PTR_HEAP;
	}

	for (uint32_t i = 1; i <= unique_sig; i++) {
		uint32_t heap_id = kmem_get_random16(kt_var_heaps - fixed_heaps) +
		    fixed_heaps;
		uint32_t start = kt_skip_list_start[i - 1];
		uint32_t end = kt_skip_list_start[i];
		kalloc_type_assign_zone_var(&kt_buffer[start].ktv_var,
		    &kt_buffer[end].ktv_var, heap_id);
	}
}
#else /* ZSECURITY_CONFIG(KALLOC_TYPE) */
__startup_func
static void
kalloc_type_view_init_var(void)
{
	*KHEAP_KT_VAR = *KHEAP_DEFAULT;
}
#endif /* !ZSECURITY_CONFIG(KALLOC_TYPE) */

__startup_func
static void
kalloc_type_views_init(void)
{
	/*
	 * Allocate scratch space to parse kalloc_type_views and create
	 * other structures necessary to process them.
	 */
	uint64_t max_count = kt_count = kt_scratch_size / sizeof(kalloc_type_views_t);

	kmem_alloc(kernel_map, (vm_offset_t *)&kt_buffer, kt_scratch_size,
	    KMA_NOFAIL | KMA_ZERO | KMA_KOBJECT, VM_KERN_MEMORY_KALLOC);

	/*
	 * Handle fixed size views
	 */
	kalloc_type_view_init_fixed();

	/*
	 * Reset
	 */
	bzero(kt_buffer, kt_scratch_size);
	kt_count = max_count;

	/*
	 * Handle variable size views
	 */
	kalloc_type_view_init_var();

	/*
	 * Free resources used
	 */
	kmem_free(kernel_map, (vm_offset_t) kt_buffer, kt_scratch_size);
}
STARTUP(ZALLOC, STARTUP_RANK_FOURTH, kalloc_type_views_init);

#pragma mark accessors

#define KFREE_ABSURD_SIZE \
	((VM_MAX_KERNEL_ADDRESS - VM_MIN_KERNEL_AND_KEXT_ADDRESS) / 2)

/*
 * This is used to sanitize size for kasan or OOB adjustments.
 * It assumes that size is [0, KFREE_ABSURD_SIZE) valued.
 */
__header_always_inline vm_size_t
K_SANE_SIZE(vm_size_t size)
{
	return MAX(size, 1);
}

static void
KALLOC_ZINFO_SALLOC(vm_size_t bytes)
{
	thread_t thr = current_thread();
	ledger_debit_thread(thr, thr->t_ledger, task_ledgers.tkm_shared, bytes);
}

static void
KALLOC_ZINFO_SFREE(vm_size_t bytes)
{
	thread_t thr = current_thread();
	ledger_credit_thread(thr, thr->t_ledger, task_ledgers.tkm_shared, bytes);
}

zone_t
kalloc_heap_zone_for_size(kalloc_heap_t kheap, vm_size_t size)
{
	struct kheap_zones *khz = kheap->kh_zones;
	zone_t z = ZONE_NULL;

	if (size < MAX_SIZE_ZDLUT) {
		z = khz->k_zone[khz->dlut[INDEX_ZDLUT(size)]];
		__builtin_assume(z != ZONE_NULL);
	} else if (size <= KHEAP_MAX_SIZE) {
		uint32_t zindex = khz->k_zindex_start;
		while (khz->cfg[zindex].kzc_size < size) {
			zindex++;
		}
		z = khz->k_zone[zindex];
		__builtin_assume(z != ZONE_NULL);
	}

	return z;
}

static zone_t
kalloc_type_zone_for_size(kalloc_type_var_view_t kt_view, size_t size)
{
	uint32_t zid = kt_view->kt_heap_start, idx;

	if (size <= KHEAP_START_SIZE) {
#if !__LP64__
		zid  += (size > 8);
#endif
		zid  += (size > 16);
	} else if (size <= KHEAP_MAX_SIZE) {
		/*
		 * . log2down(size - 1) is log2up(size) - 1
		 * . (size - 1) >> (log2down(size - 1) - 1) is either 0x2 or 0x3
		 */
		size -= 1;
		idx   = kmem_log2down((uint32_t)size);
		zid  += KHEAP_EXTRA_ZONES +
		    2 * (idx - KHEAP_START_IDX) +
		    ((uint32_t)size >> (idx - 1)) - 2;
	} else {
		return ZONE_NULL;
	}

	return zone_array + zid;
}

static zone_t
kalloc_zone_for_size(
	kalloc_heap_t           kheap,
	kalloc_type_var_view_t  kt_view,
	vm_size_t               size,
	bool                    forcopyin)
{
	vm_size_t max_size = KHEAP_MAX_SIZE;

	if (kt_view && kheap->kh_heap_id == KHEAP_ID_KT_VAR) {
		return kalloc_type_zone_for_size(kt_view, size);
	}

	if (forcopyin) {
#if __x86_64__
		/*
		 * On Intel, the OSData() ABI used to allocate
		 * from the kernel map starting at PAGE_SIZE.
		 *
		 * If only vm_map_copyin() or a wrapper is used,
		 * then everything will work fine because vm_map_copy_t
		 * will perform an actual copy if the data is smaller
		 * than msg_ool_size_small (== KHEAP_MAX_SIZE).
		 *
		 * However, if anyone is trying to call mach_vm_remap(),
		 * then bad things (TM) happen.
		 *
		 * Avoid this by preserving the ABI and moving
		 * to kalloc_large() earlier.
		 *
		 * Any recent code really ought to use IOMemoryDescriptor
		 * for this purpose however.
		 */
		max_size = PAGE_SIZE - 1;
#endif
	}

	if (size <= max_size) {
		return kalloc_heap_zone_for_size(kheap, size);
	}

	return ZONE_NULL;
}

static inline bool
kheap_size_from_zone(void *addr, vm_size_t size, bool forcopyin)
{
	vm_size_t max_size = KHEAP_MAX_SIZE;

#if __x86_64__
	/*
	 * If Z_FULLSIZE is used, then due to kalloc_zone_for_size()
	 * behavior, then the element could have a PAGE_SIZE reported size,
	 * yet still be from a zone for Z_MAY_COPYINMAP.
	 */
	if (forcopyin) {
		if (size == PAGE_SIZE &&
		    zone_id_for_element(addr, size) != ZONE_ID_INVALID) {
			return true;
		}

		max_size = PAGE_SIZE - 1;
	}
#else
#pragma unused(addr, forcopyin)
#endif

	return size <= max_size;
}


static kmem_guard_t
kalloc_guard(vm_tag_t tag, uint16_t type_hash, const void *owner)
{
	kmem_guard_t guard = {
		.kmg_atomic      = true,
		.kmg_tag         = tag,
		.kmg_type_hash   = type_hash,
		.kmg_context     = os_hash_kernel_pointer(owner),
	};

	/*
	 * TODO: this use is really not sufficiently smart.
	 */

	return guard;
}

#pragma mark kalloc

static inline kalloc_heap_t
kalloc_type_get_heap(kalloc_type_var_view_t kt_view, bool kt_free __unused)
{
	kalloc_heap_t fallback = KHEAP_DEFAULT;

	/*
	 * Redirect data-only views
	 */
	if (kalloc_type_is_data_fast(kalloc_type_func(KTV_VAR, get_atom,
	    (vm_offset_t) kt_view, false))) {
		return KHEAP_DATA_BUFFERS;
	}

	if (kt_view->kt_flags & KT_PROCESSED) {
		return KHEAP_KT_VAR;
	}

	/*
	 * Views from kexts not in BootKC on macOS
	 */
#if !ZSECURITY_CONFIG(STRICT_IOKIT_FREE)
	if (kt_free) {
		fallback = KHEAP_ANY;
	}
#endif

	return fallback;
}

__attribute__((noinline))
static struct kalloc_result
kalloc_large(
	kalloc_heap_t         kheap,
	vm_size_t             req_size,
	zalloc_flags_t        flags,
	uint16_t              kt_hash,
	void                 *owner __unused)
{
	int kma_flags = KMA_NONE;
	vm_tag_t tag;
	vm_offset_t addr, size;

	if (flags & Z_NOFAIL) {
		panic("trying to kalloc(Z_NOFAIL) with a large size (%zd)",
		    (size_t)req_size);
	}

	/*
	 * kmem_alloc could block so we return if noblock
	 *
	 * also, reject sizes larger than our address space is quickly,
	 * as kt_size or IOMallocArraySize() expect this.
	 */
	if ((flags & Z_NOWAIT) ||
	    (req_size >> VM_KERNEL_POINTER_SIGNIFICANT_BITS)) {
		return (struct kalloc_result){ };
	}

#ifndef __x86_64__
	/*
	 * (73465472) on Intel we didn't use to pass this flag,
	 * which in turned allowed kalloc_large() memory to be shared
	 * with user directly.
	 *
	 * We're bound by this unfortunate ABI.
	 */
	if ((flags & Z_MAY_COPYINMAP) == 0) {
		kma_flags |= KMA_KOBJECT;
	} else {
		assert(kheap == KHEAP_DATA_BUFFERS);
	}
#endif
	if (flags & Z_NOPAGEWAIT) {
		kma_flags |= KMA_NOPAGEWAIT;
	}
	if (flags & Z_ZERO) {
		kma_flags |= KMA_ZERO;
	}
	if (kheap == KHEAP_DATA_BUFFERS) {
		kma_flags |= KMA_DATA;
	}

	tag = zalloc_flags_get_tag(flags);
	if (flags & Z_VM_TAG_BT_BIT) {
		tag = vm_tag_bt() ?: tag;
	}
	if (tag == VM_KERN_MEMORY_NONE) {
		tag = kheap->kh_tag;
	}

#if KASAN_KALLOC
	/* large allocation - use guard pages instead of small redzones */
	size = round_page(kasan_alloc_resize(req_size) + ptoa(2));
#else
	size = round_page(req_size);
	if (flags & Z_FULLSIZE) {
		req_size = size;
	}
#endif

	addr = kmem_alloc_guard(kernel_map, size, 0,
	    kma_flags, kalloc_guard(tag, kt_hash, owner)).kmr_address;

	if (addr != 0) {
		counter_inc(&kalloc_large_count);
		counter_add(&kalloc_large_total, size);
		KALLOC_ZINFO_SALLOC(size);
#if KASAN_KALLOC
		/* fixup the return address to skip the redzone */
		addr = kasan_alloc(addr, size, req_size, PAGE_SIZE);
#else
#endif
	} else {
		addr = 0;
	}

	DTRACE_VM3(kalloc, vm_size_t, size, vm_size_t, req_size, void*, addr);
	return (struct kalloc_result){ .addr = (void *)addr, .size = req_size };
}

static inline struct kalloc_result
kalloc_zone(
	zone_t                  z,
	zone_stats_t            zstats,
	zalloc_flags_t          flags,
	vm_size_t               req_size)
{
	struct kalloc_result kr;
	vm_size_t esize;

	esize   = zone_elem_size(z);
	kr.addr = zalloc_ext(z, zstats ?: z->z_stats, flags | Z_SKIP_KASAN, esize);
	kr.size = req_size;

	if (__probable(kr.addr)) {
#if !KASAN_KALLOC
		if (flags & Z_FULLSIZE) {
			kr.size = req_size = esize;
		}
#endif /* !KASAN_KALLOC */
#if ZSECURITY_CONFIG(PGZ_OOB_ADJUST)
		kr.addr = zone_element_pgz_oob_adjust(kr, esize);
#endif /* !ZSECURITY_CONFIG(PGZ_OOB_ADJUST) */
#if KASAN_KALLOC
		kr.addr = (void *)kasan_alloc((vm_offset_t)kr.addr, esize,
		    kr.size, KASAN_GUARD_SIZE);
		__nosan_bzero((char *)kr.addr, kr.size);
#endif /* KASAN_KALLOC */
#if CONFIG_KERNEL_TBI && KASAN_TBI
		/*
		 * Kasan-TBI at least needs to tag one byte so that
		 * we can prove the allocation was live at kfree_ext()
		 * time by doing a manual __asan_loadN check.
		 */
		kr.addr = (void *)kasan_tbi_tag_zalloc((vm_offset_t)kr.addr,
		    esize, K_SANE_SIZE(kr.size), false);
#endif /* CONFIG_KERNEL_TBI && KASAN_TBI */
	}

	DTRACE_VM3(kalloc, vm_size_t, kr.size, vm_size_t, req_size, void*, kr.addr);
	return kr;
}

struct kalloc_result
kalloc_ext(
	void                   *kheap_or_kt_view,
	vm_size_t               req_size,
	zalloc_flags_t          flags,
	void                   *owner)
{
	kalloc_type_var_view_t kt_view;
	kalloc_heap_t kheap;
	zone_stats_t zstats = NULL;
	vm_size_t size;
	zone_t z;
	uint16_t kt_hash;

	if (kt_is_var_view(kheap_or_kt_view)) {
		kt_view = kt_demangle_var_view(kheap_or_kt_view);
		kheap   = kalloc_type_get_heap(kt_view, false);
		/*
		 * Use stats from view if present, else use stats from kheap.
		 * KHEAP_KT_VAR accumulates stats for all allocations going to
		 * kalloc.type.var zones, while KHEAP_DEFAULT and KHEAP_DATA_BUFFERS
		 * use stats from the respective zones.
		 */
		zstats  = kt_view->kt_stats;
		kt_hash = (uint16_t) KT_GET_HASH(kt_view->kt_flags);
	} else {
		kt_view = NULL;
		kheap   = kheap_or_kt_view;
		kt_hash = kheap->kh_type_hash;
	}

	if (!zstats) {
		zstats = kheap->kh_stats;
	}

#if KASAN_KALLOC
	/*
	 * Kasan for kalloc heaps will put the redzones *inside*
	 * the allocation, and hence augment its size.
	 *
	 * kalloc heaps do not use zone_t::z_kasan_redzone.
	 */
	size = kasan_alloc_resize(req_size);
#else
	size = req_size;
#endif

	z = kalloc_zone_for_size(kheap, kt_view, size, flags & Z_MAY_COPYINMAP);
	if (z) {
		return kalloc_zone(z, zstats, flags, req_size);
	} else {
		return kalloc_large(kheap, req_size, flags, kt_hash, owner);
	}
}

void *
kalloc_external(vm_size_t size);
void *
kalloc_external(vm_size_t size)
{
	zalloc_flags_t flags = Z_VM_TAG_BT(Z_WAITOK, VM_KERN_MEMORY_KALLOC);
	return kheap_alloc(KHEAP_DEFAULT, size, flags);
}

void *
kalloc_data_external(vm_size_t size, zalloc_flags_t flags);
void *
kalloc_data_external(vm_size_t size, zalloc_flags_t flags)
{
	flags = Z_VM_TAG_BT(flags & Z_KPI_MASK, VM_KERN_MEMORY_KALLOC_DATA);
	return kheap_alloc(KHEAP_DATA_BUFFERS, size, flags);
}

#if ZSECURITY_CONFIG(SUBMAP_USER_DATA)

__abortlike
static void
kalloc_data_require_panic(void *addr, vm_size_t size)
{
	zone_id_t zid = zone_id_for_element(addr, size);

	if (zid != ZONE_ID_INVALID) {
		zone_t z = &zone_array[zid];
		zone_security_flags_t zsflags = zone_security_array[zid];

		if (zsflags.z_kheap_id != KHEAP_ID_DATA_BUFFERS) {
			panic("kalloc_data_require failed: address %p in [%s%s]",
			    addr, zone_heap_name(z), zone_name(z));
		}

		panic("kalloc_data_require failed: address %p in [%s%s], "
		    "size too large %zd > %zd", addr,
		    zone_heap_name(z), zone_name(z),
		    (size_t)size, (size_t)zone_elem_size(z));
	} else {
		panic("kalloc_data_require failed: address %p not in zone native map",
		    addr);
	}
}

__abortlike
static void
kalloc_non_data_require_panic(void *addr, vm_size_t size)
{
	zone_id_t zid = zone_id_for_element(addr, size);

	if (zid != ZONE_ID_INVALID) {
		zone_t z = &zone_array[zid];
		zone_security_flags_t zsflags = zone_security_array[zid];

		switch (zsflags.z_kheap_id) {
		case KHEAP_ID_NONE:
		case KHEAP_ID_DATA_BUFFERS:
		case KHEAP_ID_KT_VAR:
			panic("kalloc_non_data_require failed: address %p in [%s%s]",
			    addr, zone_heap_name(z), zone_name(z));
		default:
			break;
		}

		panic("kalloc_non_data_require failed: address %p in [%s%s], "
		    "size too large %zd > %zd", addr,
		    zone_heap_name(z), zone_name(z),
		    (size_t)size, (size_t)zone_elem_size(z));
	} else {
		panic("kalloc_non_data_require failed: address %p not in zone native map",
		    addr);
	}
}

#endif /* ZSECURITY_CONFIG(SUBMAP_USER_DATA) */

void
kalloc_data_require(void *addr, vm_size_t size)
{
#if ZSECURITY_CONFIG(SUBMAP_USER_DATA)
	zone_id_t zid = zone_id_for_element(addr, size);

	if (zid != ZONE_ID_INVALID) {
		zone_t z = &zone_array[zid];
		zone_security_flags_t zsflags = zone_security_array[zid];
		if (zsflags.z_kheap_id == KHEAP_ID_DATA_BUFFERS &&
		    size <= zone_elem_size(z)) {
			return;
		}
	} else if (kmem_range_id_contains(KMEM_RANGE_ID_DATA,
	    (vm_address_t)pgz_decode(addr, size), size)) {
		return;
	}

	kalloc_data_require_panic(addr, size);
#else
#pragma unused(addr, size)
#endif
}

void
kalloc_non_data_require(void *addr, vm_size_t size)
{
#if ZSECURITY_CONFIG(SUBMAP_USER_DATA)
	zone_id_t zid = zone_id_for_element(addr, size);

	if (zid != ZONE_ID_INVALID) {
		zone_t z = &zone_array[zid];
		zone_security_flags_t zsflags = zone_security_array[zid];
		switch (zsflags.z_kheap_id) {
		case KHEAP_ID_NONE:
			if (!zsflags.z_kalloc_type) {
				break;
			}
			OS_FALLTHROUGH;
		case KHEAP_ID_DEFAULT:
		case KHEAP_ID_KT_VAR:
			if (size < zone_elem_size(z)) {
				return;
			}
			break;
		default:
			break;
		}
	} else if (!kmem_range_id_contains(KMEM_RANGE_ID_DATA,
	    (vm_address_t)pgz_decode(addr, size), size)) {
		return;
	}

	kalloc_non_data_require_panic(addr, size);
#else
#pragma unused(addr, size)
#endif
}

void *
kalloc_type_impl_external(kalloc_type_view_t kt_view, zalloc_flags_t flags)
{
	/*
	 * Callsites from a kext that aren't in the BootKC on macOS or
	 * any callsites on armv7 are not processed during startup,
	 * default to using kheap_alloc
	 *
	 * Additionally when size is greater KHEAP_MAX_SIZE zone is left
	 * NULL as we need to use the vm for the allocation
	 *
	 */
	if (__improbable(kt_view->kt_zv.zv_zone == ZONE_NULL)) {
		vm_size_t size = kalloc_type_get_size(kt_view->kt_size);
		flags = Z_VM_TAG_BT(flags & Z_KPI_MASK, VM_KERN_MEMORY_KALLOC);
		return kalloc_ext(KHEAP_DEFAULT, size, flags, NULL).addr;
	}

	flags = Z_VM_TAG_BT(flags & Z_KPI_MASK, VM_KERN_MEMORY_KALLOC);
	return zalloc_flags(kt_view, flags);
}

void *
kalloc_type_var_impl_external(
	kalloc_type_var_view_t  kt_view,
	vm_size_t               size,
	zalloc_flags_t          flags,
	void                   *owner);
void *
kalloc_type_var_impl_external(
	kalloc_type_var_view_t  kt_view,
	vm_size_t               size,
	zalloc_flags_t          flags,
	void                   *owner)
{
	flags = Z_VM_TAG_BT(flags & Z_KPI_MASK, VM_KERN_MEMORY_KALLOC);
	return kalloc_type_var_impl(kt_view, size, flags, owner);
}

#pragma mark kfree

__abortlike
static void
kfree_heap_confusion_panic(kalloc_heap_t kheap, void *data, size_t size, zone_t z)
{
	zone_security_flags_t zsflags = zone_security_config(z);
	const char *kheap_name = "";

	if (kheap == KHEAP_ANY) {
		kheap_name = "KHEAP_ANY (default/kalloc type var/data)";
	} else {
		kheap_name = kalloc_heap_names[kheap->kh_heap_id];
	}

	if (zsflags.z_kalloc_type) {
		panic_include_kalloc_types = true;
		kalloc_type_src_zone = z;
		panic("kfree: addr %p found in kalloc type zone '%s'"
		    "but being freed to %s heap", data, z->z_name, kheap_name);
	}

	if (zsflags.z_kheap_id == KHEAP_ID_NONE) {
		panic("kfree: addr %p, size %zd found in regular zone '%s%s'",
		    data, size, zone_heap_name(z), z->z_name);
	} else {
		panic("kfree: addr %p, size %zd found in heap %s* instead of %s*",
		    data, size, zone_heap_name(z), kheap_name);
	}
}

__abortlike
static void
kfree_size_confusion_panic(zone_t z, void *data,
    size_t oob_offs, size_t size, size_t zsize)
{
	if (z) {
		panic("kfree: addr %p, size %zd (offs:%zd) found in zone '%s%s' "
		    "with elem_size %zd",
		    data, size, oob_offs, zone_heap_name(z), z->z_name, zsize);
	} else {
		panic("kfree: addr %p, size %zd (offs:%zd) not found in any zone",
		    data, size, oob_offs);
	}
}

__abortlike
static void
kfree_size_invalid_panic(void *data, size_t size)
{
	panic("kfree: addr %p trying to free with nonsensical size %zd",
	    data, size);
}

__abortlike
static void
kfree_size_require_panic(void *data, size_t size, size_t min_size,
    size_t max_size)
{
	panic("kfree: addr %p has size %zd, not in specified bounds [%zd - %zd]",
	    data, size, min_size, max_size);
}

static void
kfree_size_require(
	kalloc_heap_t kheap,
	void *addr,
	vm_size_t min_size,
	vm_size_t max_size)
{
	assert3u(min_size, <=, max_size);
#if KASAN_KALLOC
	max_size = kasan_alloc_resize(max_size);
#endif
	zone_t max_zone = kalloc_heap_zone_for_size(kheap, max_size);
	vm_size_t max_zone_size = max_zone->z_elem_size;
	vm_size_t elem_size = zone_element_size(addr, NULL, false, NULL);
	if (elem_size > max_zone_size || elem_size < min_size) {
		kfree_size_require_panic(addr, elem_size, min_size, max_zone_size);
	}
}

static void
kfree_large(
	vm_offset_t             addr,
	vm_size_t               size,
	kmf_flags_t             flags,
	void                   *owner)
{
#if KASAN_KALLOC
	/* TODO: quarantine for kasan large that works with guards */
	kasan_poison_range(addr, size, ASAN_VALID);
#endif

	size = kmem_free_guard(kernel_map, addr, size, flags,
	    kalloc_guard(VM_KERN_MEMORY_NONE, 0, owner));

	counter_dec(&kalloc_large_count);
	counter_add(&kalloc_large_total, -(uint64_t)size);
	KALLOC_ZINFO_SFREE(size);
	DTRACE_VM3(kfree, vm_size_t, size, vm_size_t, size, void*, addr);
}

static void
kfree_zone(
	void                   *kheap_or_kt_view __unsafe_indexable,
	void                   *data,
	vm_size_t               size,
	zone_t                  z,
	vm_size_t               zsize)
{
	zone_security_flags_t zsflags = zone_security_config(z);
	kalloc_type_var_view_t kt_view;
	kalloc_heap_t kheap;
	zone_stats_t zstats;

	if (kt_is_var_view(kheap_or_kt_view)) {
		kt_view = kt_demangle_var_view(kheap_or_kt_view);
		kheap   = kalloc_type_get_heap(kt_view, true);
		zstats  = kt_view->kt_stats;
	} else {
		kt_view = NULL;
		kheap   = kheap_or_kt_view;
		zstats  = kheap ? kheap->kh_stats : NULL;
	}

	zsflags = zone_security_config(z);
	if (kheap != KHEAP_ANY && kheap != KHEAP_KT_VAR) {
		if (kheap->kh_heap_id != zsflags.z_kheap_id) {
			kfree_heap_confusion_panic(kheap, data, size, z);
		}
	} else if (zsflags.z_kheap_id == KHEAP_ID_KT_VAR) {
		/*
		 * Allocations from kalloc.type.var zones use stats from KHEAP_KT_VAR
		 * if they don't have private accounting. We need to use the kheap_id here
		 * as we allow cross frees between default and KT_VAR and we may use
		 * KHEAP_ANY which will skew the stats if we relie on stats from kheap.
		 */
		if (zstats == NULL) {
			zstats = KHEAP_KT_VAR->kh_stats;
		}
	} else if (zsflags.z_kheap_id != KHEAP_ID_DEFAULT &&
	    (kt_options & KT_OPTIONS_LOOSE_FREE &&
	    zsflags.z_kheap_id != KHEAP_ID_DATA_BUFFERS)) {
		kfree_heap_confusion_panic(kheap, data, size, z);
	}

	DTRACE_VM3(kfree, vm_size_t, size, vm_size_t, zsize, void*, data);

#if KASAN_KALLOC
	/*
	 * Hand the allocation to the quarantine, data might become NULL.
	 * FIXME: this breaks accounting because we do not remember `zstats`
	 */
	kasan_free(&data, &zsize, KASAN_HEAP_KALLOC, &z, size);
	if (data == NULL) {
		return;
	}
#else
	/* needs to be __nosan because the user size might be partial */
	__nosan_bzero(data, zsize);
#endif /* !KASAN_ZALLOC */
	zfree_ext(z, zstats ?: z->z_stats, data, zsize);
}

void
kfree_ext(
	void                   *kheap_or_kt_view,
	void                   *data,
	vm_size_t               size)
{
	vm_size_t adj_size, bucket_size;
	zone_t z;

	if (data == NULL) {
		return;
	}

	if (size > KFREE_ABSURD_SIZE) {
		kfree_size_invalid_panic(data, size);
	}

#if KASAN_KALLOC
	adj_size = kasan_alloc_resize(size);
	kasan_check_free((vm_address_t)data, size, KASAN_HEAP_KALLOC);
#else
	adj_size = size;
#if CONFIG_KERNEL_TBI && KASAN_TBI
	__asan_loadN((vm_offset_t)data, K_SANE_SIZE(size));
#endif /* CONFIG_KERNEL_TBI && KASAN_TBI */
#endif /* KASAN_KALLOC */

	if (adj_size <= KHEAP_MAX_SIZE) {
		vm_size_t oob_offs;

		bucket_size = zone_element_size(data, &z, true, &oob_offs);
		if (size + oob_offs > bucket_size || bucket_size == 0) {
			kfree_size_confusion_panic(z, data,
			    oob_offs, size, bucket_size);
		}

		data = (char *)data - oob_offs;
		__builtin_assume(z != ZONE_NULL);
	} else {
		z = ZONE_NULL;
	}

#if KASAN_KALLOC
	/*
	 * Resize back to the real allocation size.
	 */
	vm_size_t real_size = size;
	data = (void *)kasan_dealloc((vm_address_t)data, &real_size);
	if (z) {
		bucket_size = real_size;
	} else {
		size = real_size;
	}
#endif /* KASAN_KALLOC */

	if (z) {
		kfree_zone(kheap_or_kt_view, data, size, z, bucket_size);
	} else {
		kfree_large((vm_offset_t)data, size, KMF_NONE, NULL);
	}
}

void
kfree_addr_ext(kalloc_heap_t kheap, void *data)
{
	if (data == NULL) {
		return;
	}

#if KASAN_KALLOC
	kfree_ext(kheap, data, kasan_user_size((vm_offset_t)data));
#else
	vm_offset_t oob_offs;
	vm_size_t size;
	zone_t z;

#if CONFIG_KERNEL_TBI && KASAN_TBI
	__asan_loadN((vm_offset_t)data, KALLOC_MINSIZE);
#endif /* CONFIG_KERNEL_TBI && KASAN_TBI */

	size = zone_element_size(data, &z, true, &oob_offs);
	if (size) {
		data = (char *)data - oob_offs;
		kfree_zone(kheap, data, size - oob_offs, z, size);
	} else {
		kfree_large((vm_offset_t)data, 0, KMF_GUESS_SIZE, NULL);
	}
#endif /* !KASAN_KALLOC */
}

void
kfree_external(void *addr, vm_size_t size);
void
kfree_external(void *addr, vm_size_t size)
{
	kfree_ext(KHEAP_ANY, addr, size);
}

void
(kheap_free_bounded)(kalloc_heap_t kheap, void *addr,
    vm_size_t min_sz, vm_size_t max_sz)
{
	if (__improbable(addr == NULL)) {
		return;
	}
	kfree_size_require(kheap, addr, min_sz, max_sz);
	kfree_addr_ext(kheap, addr);
}

void
kfree_type_impl_external(kalloc_type_view_t kt_view, void *ptr)
{
	/*
	 * If callsite is from a kext that isn't in the BootKC, it wasn't
	 * processed during startup so default to using kheap_alloc
	 *
	 * Additionally when size is greater KHEAP_MAX_SIZE zone is left
	 * NULL as we need to use the vm for the allocation/free
	 */
	if (kt_view->kt_zv.zv_zone == ZONE_NULL) {
		return kheap_free(KHEAP_DEFAULT, ptr,
		           kalloc_type_get_size(kt_view->kt_size));
	}
	if (__improbable(ptr == NULL)) {
		return;
	}
	return zfree(kt_view, ptr);
}

void
kfree_type_var_impl_external(
	kalloc_type_var_view_t  kt_view,
	void                   *ptr,
	vm_size_t               size);
void
kfree_type_var_impl_external(
	kalloc_type_var_view_t  kt_view,
	void                   *ptr,
	vm_size_t               size)
{
	return kfree_type_var_impl(kt_view, ptr, size);
}

void
kfree_data_external(void *ptr, vm_size_t size);
void
kfree_data_external(void *ptr, vm_size_t size)
{
	return kheap_free(KHEAP_DATA_BUFFERS, ptr, size);
}

void
kfree_data_addr_external(void *ptr);
void
kfree_data_addr_external(void *ptr)
{
	return kheap_free_addr(KHEAP_DATA_BUFFERS, ptr);
}

#pragma mark krealloc

__abortlike
static void
krealloc_size_invalid_panic(void *data, size_t size)
{
	panic("krealloc: addr %p trying to free with nonsensical size %zd",
	    data, size);
}

__attribute__((noinline))
static struct kalloc_result
krealloc_large(
	kalloc_heap_t         kheap,
	vm_offset_t           addr,
	vm_size_t             old_size,
	vm_size_t             new_size,
	zalloc_flags_t        flags,
	uint16_t              kt_hash,
	void                 *owner __unused)
{
	int kmr_flags = KMR_FREEOLD;
	vm_size_t new_req_size = new_size;
	vm_size_t old_req_size = old_size;
	uint64_t delta;
	kmem_return_t kmr;
	vm_tag_t tag;

	if (flags & Z_NOFAIL) {
		panic("trying to kalloc(Z_NOFAIL) with a large size (%zd)",
		    (size_t)new_req_size);
	}

	/*
	 * kmem_alloc could block so we return if noblock
	 *
	 * also, reject sizes larger than our address space is quickly,
	 * as kt_size or IOMallocArraySize() expect this.
	 */
	if ((flags & Z_NOWAIT) ||
	    (new_req_size >> VM_KERNEL_POINTER_SIGNIFICANT_BITS)) {
		return (struct kalloc_result){ };
	}

#ifndef __x86_64__
	/*
	 * (73465472) on Intel we didn't use to pass this flag,
	 * which in turned allowed kalloc_large() memory to be shared
	 * with user directly.
	 *
	 * We're bound by this unfortunate ABI.
	 */
	if ((flags & Z_MAY_COPYINMAP) == 0) {
		kmr_flags |= KMR_KOBJECT;
	} else {
		assert(kheap == KHEAP_DATA_BUFFERS);
	}
#endif
	if (flags & Z_NOPAGEWAIT) {
		kmr_flags |= KMR_NOPAGEWAIT;
	}
	if (flags & Z_ZERO) {
		kmr_flags |= KMR_ZERO;
	}
	if (kheap == KHEAP_DATA_BUFFERS) {
		kmr_flags |= KMR_DATA;
	}
	if (flags & Z_REALLOCF) {
		kmr_flags |= KMR_REALLOCF;
	}

	tag = zalloc_flags_get_tag(flags);
	if (flags & Z_VM_TAG_BT_BIT) {
		tag = vm_tag_bt() ?: tag;
	}
	if (tag == VM_KERN_MEMORY_NONE) {
		tag = kheap->kh_tag;
	}

#if KASAN_KALLOC
	/* large allocation - use guard pages instead of small redzones */
	if (addr) {
		addr = kasan_dealloc(addr, &old_size);
		kasan_poison_range(addr, old_size, ASAN_VALID);
	}
	new_size = round_page(kasan_alloc_resize(new_req_size) + ptoa(2));
#else
	new_size = round_page(new_req_size);
	old_size = round_page(old_req_size);
#endif

	kmr = kmem_realloc_guard(kernel_map, addr, old_size, new_size,
	    kmr_flags, kalloc_guard(tag, kt_hash, owner));

	if (kmr.kmr_address != 0) {
		delta = (uint64_t)(new_size - old_size);
	} else if (flags & Z_REALLOCF) {
		counter_dec(&kalloc_large_count);
		delta = (uint64_t)(-old_size);
	} else {
		delta = 0;
	}

	counter_add(&kalloc_large_total, delta);
	KALLOC_ZINFO_SALLOC((vm_offset_t)delta);

	if (addr != 0) {
		DTRACE_VM3(kfree, vm_size_t, old_size, vm_size_t, old_req_size,
		    void*, addr);
	}
	if (__improbable(kmr.kmr_address == 0)) {
		return (struct kalloc_result){ };
	}

#if KASAN_KALLOC
	/* fixup the return address to skip the redzone */
	kmr.kmr_address = kasan_alloc(kmr.kmr_address,
	    new_size, new_req_size, PAGE_SIZE);

	/*
	 * kasan stores backtraces in the page in the right red-zone,
	 * if we realloced, kmem dutifully preserved it, so we need
	 * to clear it.
	 */
	if ((flags & Z_ZERO) && old_req_size < new_req_size) {
		vm_size_t needs_zero_end = PAGE_SIZE + round_page(old_req_size);

		__nosan_bzero((char *)kmr.kmr_address + old_req_size,
		    MIN(needs_zero_end, new_req_size) - old_req_size);
	}
#endif

	DTRACE_VM3(kalloc, vm_size_t, new_size, vm_size_t, new_req_size,
	    void*, kmr.kmr_address);
	return (struct kalloc_result){ .addr = kmr.kmr_ptr, .size = new_req_size };
}

struct kalloc_result
krealloc_ext(
	void                   *kheap_or_kt_view __unsafe_indexable,
	void                   *addr,
	vm_size_t               old_size,
	vm_size_t               new_size,
	zalloc_flags_t          flags,
	void                   *owner)
{
	vm_size_t old_bucket_size, new_bucket_size, min_size;
	vm_size_t adj_new_size, adj_old_size;
	kalloc_type_var_view_t kt_view;
	kalloc_heap_t kheap;
	zone_stats_t zstats = NULL;
	struct kalloc_result kr;
	vm_offset_t oob_offs = 0;
	bool forcopyin = flags & Z_MAY_COPYINMAP;
	zone_t old_z, new_z;
	uint16_t kt_hash = 0;

	if (old_size > KFREE_ABSURD_SIZE) {
		krealloc_size_invalid_panic(addr, old_size);
	}

	if (addr == NULL && new_size == 0) {
		return (struct kalloc_result){ };
	}

#if KASAN_KALLOC
	/*
	 * Adjust sizes to account for kasan redzones
	 */
	adj_new_size = kasan_alloc_resize(new_size);
	adj_old_size = kasan_alloc_resize(old_size);
	if (addr) {
		kasan_check_free((vm_address_t)addr, old_size, KASAN_HEAP_KALLOC);
	}
#else
	adj_old_size = old_size;
	adj_new_size = new_size;
#if CONFIG_KERNEL_TBI && KASAN_TBI
	if (addr) {
		__asan_loadN((vm_offset_t)addr, K_SANE_SIZE(old_size));
	}
#endif /* CONFIG_KERNEL_TBI && KASAN_TBI */
#endif /* KASAN_KALLOC */

	if (kt_is_var_view(kheap_or_kt_view)) {
		kt_view = kt_demangle_var_view(kheap_or_kt_view);
		kheap   = kalloc_type_get_heap(kt_view, false);
		/*
		 * Similar to kalloc_ext: Use stats from view if present, else use stats
		 * from kheap. krealloc_type isn't exposed to kexts, so we don't need to
		 * handle cross frees or KHEAP_ANY for typed allocations and can relie on
		 * stats from view or kheap.
		 */
		zstats  = kt_view->kt_stats;
		kt_hash = KT_GET_HASH(kt_view->kt_flags);
	} else {
		kt_view = NULL;
		kheap   = kheap_or_kt_view;
		kt_hash = kheap->kh_type_hash;
	}

	if (!zstats && kheap) {
		zstats = kheap->kh_stats;
	}
	/*
	 * Find out the size of the bucket in which the new sized allocation
	 * would land. If it matches the bucket of the original allocation,
	 * simply return the same address.
	 */
	if (new_size == 0) {
		new_z = ZONE_NULL;
		new_bucket_size = adj_new_size = 0;
	} else {
		new_z = kalloc_zone_for_size(kheap, kt_view, adj_new_size, forcopyin);
		new_bucket_size = new_z ? zone_elem_size(new_z) : round_page(adj_new_size);
	}
#if !KASAN_KALLOC
	if (flags & Z_FULLSIZE) {
		adj_new_size = new_size = new_bucket_size;
	}
#endif /* !KASAN_KALLOC */

	if (addr == NULL) {
		old_z = ZONE_NULL;
		old_size = old_bucket_size = adj_old_size = 0;
	} else if (kheap_size_from_zone(addr, adj_old_size, forcopyin)) {
		old_bucket_size = zone_element_size(addr, &old_z, true, &oob_offs);
		if (old_size + oob_offs > old_bucket_size || old_bucket_size == 0) {
			kfree_size_confusion_panic(old_z, addr,
			    oob_offs, old_size, old_bucket_size);
		}
		__builtin_assume(old_z != ZONE_NULL);
	} else {
		old_z = ZONE_NULL;
		old_bucket_size = round_page(adj_old_size);
	}
	min_size = MIN(old_size, new_size);

	if (old_bucket_size == new_bucket_size) {
		kr.addr = (char *)addr - oob_offs;
		kr.size = new_size;
#if ZSECURITY_CONFIG(PGZ_OOB_ADJUST)
		if (old_z) {
			kr.addr = zone_element_pgz_oob_adjust(kr, new_bucket_size);
			if (kr.addr != addr) {
				memmove(kr.addr, addr, min_size);
				bzero((char *)kr.addr + min_size,
				    kr.size - min_size);
			}
		}
#endif /* !ZSECURITY_CONFIG(PGZ_OOB_ADJUST) */
#if KASAN_KALLOC
		/*
		 * Adjust right redzone in the element and poison it correctly
		 */
		kr.addr = (void *)kasan_realloc((vm_offset_t)addr,
		    new_bucket_size + ptoa(old_z ? 0 : 2), kr.size,
		    old_z ? KASAN_GUARD_SIZE : PAGE_SIZE);
		__nosan_bzero((char *)kr.addr + min_size, kr.size - min_size);
#endif /* KASAN_KALLOC */
#if CONFIG_KERNEL_TBI && KASAN_TBI
		/*
		 * Validate the current buffer, then generate a new tag,
		 * even if the address is stable, it's a "new" allocation.
		 */
		kr.addr = (void *)kasan_tbi_tag_zalloc((vm_offset_t)kr.addr,
		    kr.size, new_bucket_size, false);
#endif /* CONFIG_KERNEL_TBI && KASAN_TBI */
		return kr;
	}

	if (addr && !old_z && new_size && !new_z) {
		return krealloc_large(kheap, (vm_offset_t)addr,
		           old_size, new_size, flags, kt_hash, owner);
	}

	if (!new_size) {
		kr.addr = NULL;
		kr.size = 0;
	} else if (new_z) {
		kr = kalloc_zone(new_z, zstats, flags, new_size);
	} else if (old_z || addr == NULL) {
		kr = kalloc_large(kheap, new_size, flags, kt_hash, owner);
	}

	if (addr && kr.addr) {
		__nosan_memcpy(kr.addr, addr, min_size);
	}

	if (addr && (kr.addr || (flags & Z_REALLOCF) || !new_size)) {
#if KASAN_KALLOC
		/*
		 * Resize back to the real allocation size.
		 */
		vm_size_t real_size = old_size;
		addr = (void *)kasan_dealloc((vm_address_t)addr, &real_size);
		if (old_z) {
			old_bucket_size = real_size;
		} else {
			old_size = real_size;
		}
#endif /* KASAN_KALLOC */

		if (old_z) {
			kfree_zone(kheap_or_kt_view,
			    (char *)addr - oob_offs, old_size,
			    old_z, old_bucket_size);
		} else {
			kfree_large((vm_offset_t)addr, old_size, KMF_NONE, owner);
		}
	}
	return kr;
}

void *
krealloc_data_external(
	void               *ptr,
	vm_size_t           old_size,
	vm_size_t           new_size,
	zalloc_flags_t      flags);
void *
krealloc_data_external(
	void               *ptr,
	vm_size_t           old_size,
	vm_size_t           new_size,
	zalloc_flags_t      flags)
{
	flags = Z_VM_TAG_BT(flags & Z_KPI_MASK, VM_KERN_MEMORY_KALLOC_DATA);
	return krealloc_ext(KHEAP_DATA_BUFFERS, ptr, old_size, new_size, flags, NULL).addr;
}

__startup_func
void
kheap_startup_init(kalloc_heap_t kheap)
{
	struct kheap_zones *zones;
	vm_tag_t tag;

	switch (kheap->kh_heap_id) {
	case KHEAP_ID_DEFAULT:
		zones = KHEAP_DEFAULT->kh_zones;
		tag = KHEAP_DEFAULT->kh_tag;
		break;
	case KHEAP_ID_DATA_BUFFERS:
		zones = KHEAP_DATA_BUFFERS->kh_zones;
		tag = KHEAP_DATA_BUFFERS->kh_tag;
		break;
	default:
		panic("kalloc_heap_startup_init: invalid KHEAP_ID: %d",
		    kheap->kh_heap_id);
	}

	kheap->kh_heap_id = zones->heap_id;
	kheap->kh_zones = zones;
	kheap->kh_stats = zalloc_percpu_permanent_type(struct zone_stats);
	kheap->kh_next = zones->views;
	zones->views = kheap;
	kheap->kh_tag = tag;
	zone_view_count += 1;

#if PLATFORM_MacOSX
	if (kheap == KERN_OS_MALLOC) {
		kheap->kh_type_hash = (uint16_t) kalloc_hash_adjust(
			(uint32_t) early_random(), 0);
	}
#endif
}

#pragma mark IOKit/libkern helpers

#if PLATFORM_MacOSX

void *
kern_os_malloc_external(size_t size);
void *
kern_os_malloc_external(size_t size)
{
	if (size == 0) {
		return NULL;
	}

	return kheap_alloc(KERN_OS_MALLOC, size,
	           Z_VM_TAG_BT(Z_WAITOK_ZERO, VM_KERN_MEMORY_LIBKERN));
}

void
kern_os_free_external(void *addr);
void
kern_os_free_external(void *addr)
{
	kheap_free_addr(KERN_OS_MALLOC, addr);
}

void *
kern_os_realloc_external(void *addr, size_t nsize);
void *
kern_os_realloc_external(void *addr, size_t nsize)
{
	zalloc_flags_t flags = Z_VM_TAG_BT(Z_WAITOK_ZERO, VM_KERN_MEMORY_LIBKERN);
	vm_size_t osize, oob_offs = 0;

	if (addr == NULL) {
		return kern_os_malloc_external(nsize);
	}

#if KASAN_KALLOC
	osize = kasan_user_size((vm_offset_t)addr);
#else
	osize = zone_element_size(addr, NULL, false, &oob_offs);
	if (osize == 0) {
		osize = kmem_size_guard(kernel_map, (vm_offset_t)addr,
		    kalloc_guard(VM_KERN_MEMORY_LIBKERN, 0, NULL));
	}
#endif
	return __kheap_realloc(KERN_OS_MALLOC, addr, osize - oob_offs, nsize, flags, NULL);
}

#endif /* PLATFORM_MacOSX */

void
kern_os_zfree(zone_t zone, void *addr, vm_size_t size)
{
#if ZSECURITY_CONFIG(STRICT_IOKIT_FREE)
#pragma unused(size)
	zfree(zone, addr);
#else
	if (zone_owns(zone, addr)) {
		zfree(zone, addr);
	} else {
		/*
		 * Third party kexts might not know about the operator new
		 * and be allocated from the default heap
		 */
		printf("kern_os_zfree: kheap_free called for object from zone %s\n",
		    zone->z_name);
		kheap_free(KHEAP_DEFAULT, addr, size);
	}
#endif
}

bool
IOMallocType_from_vm(kalloc_type_view_t ktv)
{
	struct kalloc_type_atom kt_atom = kalloc_type_func(KTV_FIXED, get_atom,
	    (vm_offset_t)ktv, false);
	return kalloc_type_from_vm(kt_atom);
}

void
kern_os_typed_free(kalloc_type_view_t ktv, void *addr, vm_size_t esize)
{
#if ZSECURITY_CONFIG(STRICT_IOKIT_FREE) || !ZSECURITY_CONFIG(KALLOC_TYPE)
#pragma unused(esize)
#else
	/*
	 * For third party kexts that have been compiled with sdk pre macOS 11,
	 * an allocation of an OSObject that is defined in xnu or first pary
	 * kexts, by directly calling new will lead to using the default heap
	 * as it will call OSObject_operator_new_external. If this object
	 * is freed by xnu, it panics as xnu uses the typed free which
	 * requires the object to have been allocated in a kalloc.type zone.
	 * To workaround this issue, detect if the allocation being freed is
	 * from the default heap and allow freeing to it.
	 */
	zone_id_t zid = zone_id_for_element(addr, esize);
	if (__probable(zid < MAX_ZONES)) {
		zone_security_flags_t zsflags = zone_security_array[zid];
		if (zsflags.z_kheap_id == KHEAP_ID_DEFAULT) {
			return kheap_free(KHEAP_DEFAULT, addr, esize);
		}
	}
#endif
	kfree_type_impl_external(ktv, addr);
}

#pragma mark tests
#if DEBUG || DEVELOPMENT

#include <sys/random.h>
/*
 * Ensure that the feature is on when the ZSECURITY_CONFIG is present.
 *
 * Note: Presence of zones with name kalloc.type* is used to
 * determine if the feature is on.
 */
static int
kalloc_type_feature_on(void)
{
	/*
	 * ZSECURITY_CONFIG not present
	 */
#if !ZSECURITY_CONFIG(KALLOC_TYPE)
	return 1;
#endif /* !ZSECURITY_CONFIG(KALLOC_TYPE) */

	boolean_t zone_found = false;
	const char kalloc_type_str[] = "kalloc.type";
	for (uint16_t i = 0; i < MAX_K_ZONE(k_zone_cfg); i++) {
		zone_t z = kalloc_type_zarray[i];
		while (z != NULL) {
			zone_found = true;
			if (strncmp(z->z_name, kalloc_type_str,
			    strlen(kalloc_type_str)) != 0) {
				return 0;
			}
			z = z->z_kt_next;
		}
	}

	if (!zone_found) {
		return 0;
	}

	return 1;
}

/*
 * Ensure that the policy uses the zone budget completely
 */
#if ZSECURITY_CONFIG(KALLOC_TYPE)
static int
kalloc_type_test_policy(int64_t in)
{
	uint16_t zone_budget = (uint16_t) in;
	uint16_t max_bucket_freq = 25;
	uint16_t freq_list[MAX_K_ZONE(k_zone_cfg)] = {};
	uint16_t zones_per_bucket[MAX_K_ZONE(k_zone_cfg)] = {};
	uint16_t random[MAX_K_ZONE(k_zone_cfg)];
	int ret = 0;

	/*
	 * Need a minimum of 2 zones per size class
	 */
	if (zone_budget < MAX_K_ZONE(k_zone_cfg) * 2) {
		return ret;
	}
	read_random((void *)&random[0], sizeof(random));
	for (uint16_t i = 0; i < MAX_K_ZONE(k_zone_cfg); i++) {
		freq_list[i] = random[i] % max_bucket_freq;
	}
	uint16_t wasted_zone_budget = kalloc_type_apply_policy(freq_list,
	    zones_per_bucket, zone_budget);
	if (wasted_zone_budget == 0) {
		ret = 1;
	}
	return ret;
}
#else /* ZSECURITY_CONFIG(KALLOC_TYPE) */
static int
kalloc_type_test_policy(int64_t in)
{
#pragma unused(in)
	return 1;
}
#endif /* !ZSECURITY_CONFIG(KALLOC_TYPE) */

/*
 * Ensure that size of adopters of kalloc_type fit in the zone
 * they have been assigned.
 */
static int
kalloc_type_check_size(zone_t z)
{
	uint16_t elem_size = z->z_elem_size;
	kalloc_type_view_t kt_cur = (kalloc_type_view_t) z->z_views;
	const char site_str[] = "site.";
	const size_t site_str_len = strlen(site_str);
	while (kt_cur != NULL) {
		/*
		 * Process only kalloc_type_views and skip the zone_views when
		 * feature is off.
		 */
#if !ZSECURITY_CONFIG(KALLOC_TYPE)
		if (strncmp(kt_cur->kt_zv.zv_name, site_str, site_str_len) != 0) {
			kt_cur = (kalloc_type_view_t) kt_cur->kt_zv.zv_next;
			continue;
		}
#else /* !ZSECURITY_CONFIG(KALLOC_TYPE) */
#pragma unused(site_str, site_str_len)
#endif /* ZSECURITY_CONFIG(KALLOC_TYPE) */
		if (kalloc_type_get_size(kt_cur->kt_size) > elem_size) {
			return 0;
		}
		kt_cur = (kalloc_type_view_t) kt_cur->kt_zv.zv_next;
	}
	return 1;
}

struct test_kt_data {
	int a;
};

static int
kalloc_type_test_data_redirect()
{
	struct kalloc_type_view ktv_data = {
		.kt_signature = __builtin_xnu_type_signature(struct test_kt_data)
	};
	if (!kalloc_type_is_data(kalloc_type_func(KTV_FIXED, get_atom,
	    (vm_offset_t)&ktv_data, false))) {
		printf("%s: data redirect failed\n", __func__);
		return 0;
	}
	return 1;
}

static int
run_kalloc_type_test(int64_t in, int64_t *out)
{
	*out = 0;
	for (uint16_t i = 0; i < MAX_K_ZONE(k_zone_cfg); i++) {
		zone_t z = kalloc_type_zarray[i];
		while (z != NULL) {
			if (!kalloc_type_check_size(z)) {
				printf("%s: size check failed\n", __func__);
				return 0;
			}
			z = z->z_kt_next;
		}
	}

	if (!kalloc_type_test_policy(in)) {
		printf("%s: policy check failed\n", __func__);
		return 0;
	}

	if (!kalloc_type_feature_on()) {
		printf("%s: boot-arg is on but feature isn't\n", __func__);
		return 0;
	}

	if (!kalloc_type_test_data_redirect()) {
		printf("%s: kalloc_type redirect for all data signature failed\n",
		    __func__);
		return 0;
	}

	printf("%s: test passed\n", __func__);

	*out = 1;
	return 0;
}
SYSCTL_TEST_REGISTER(kalloc_type, run_kalloc_type_test);

static vm_size_t
test_bucket_size(kalloc_heap_t kheap, vm_size_t size)
{
	zone_t z = kalloc_heap_zone_for_size(kheap, size);

	return z ? zone_elem_size(z) : round_page(size);
}

static int
run_kalloc_test(int64_t in __unused, int64_t *out)
{
	*out = 0;
	uint64_t * data_ptr;
	size_t alloc_size, old_alloc_size;

	printf("%s: test running\n", __func__);

	alloc_size = 3544;
	data_ptr = kalloc_ext(KHEAP_DATA_BUFFERS, alloc_size,
	    Z_WAITOK, &data_ptr).addr;
	if (!data_ptr) {
		printf("%s: kalloc 3544 returned not null\n", __func__);
		return 0;
	}

	data_ptr = krealloc_ext(KHEAP_DATA_BUFFERS, data_ptr, alloc_size,
	    PAGE_SIZE, Z_REALLOCF | Z_WAITOK, &data_ptr).addr;
	*data_ptr = 0;
	if (!data_ptr) {
		printf("%s: krealoc -> 2pgs returned not null\n", __func__);
		return 0;
	}

	data_ptr = krealloc_ext(KHEAP_DATA_BUFFERS, data_ptr, PAGE_SIZE,
	    KHEAP_MAX_SIZE * 2, Z_REALLOCF | Z_WAITOK, &data_ptr).addr;
	if (!data_ptr) {
		printf("%s: krealoc -> VM1 returned not null\n", __func__);
		return 0;
	}
	*data_ptr = 0;

	data_ptr = krealloc_ext(KHEAP_DATA_BUFFERS, data_ptr, KHEAP_MAX_SIZE * 2,
	    KHEAP_MAX_SIZE * 4, Z_REALLOCF | Z_WAITOK, &data_ptr).addr;
	*data_ptr = 0;
	if (!data_ptr) {
		printf("%s: krealoc -> VM2 returned not null\n", __func__);
		return 0;
	}

	krealloc_ext(KHEAP_DATA_BUFFERS, data_ptr, KHEAP_MAX_SIZE * 4,
	    0, Z_REALLOCF | Z_WAITOK, &data_ptr);

	alloc_size = sizeof(uint64_t) + 1;
	data_ptr = kalloc_ext(KHEAP_DEFAULT, alloc_size, Z_WAITOK, NULL).addr;
	if (!data_ptr) {
		printf("%s: kalloc sizeof(uint64_t) returned null\n", __func__);
		return 0;
	}

	struct kalloc_result kr = {};
	old_alloc_size = alloc_size;
	alloc_size++;
	kr = krealloc_ext(KHEAP_DEFAULT, data_ptr, old_alloc_size, alloc_size,
	    Z_WAITOK | Z_NOFAIL, NULL);
	if (!kr.addr || kr.addr != data_ptr ||
	    test_bucket_size(KHEAP_DEFAULT, kr.size) !=
	    test_bucket_size(KHEAP_DEFAULT, old_alloc_size)) {
		printf("%s: same size class realloc failed\n", __func__);
		return 0;
	}

	old_alloc_size = alloc_size;
	alloc_size *= 2;
	kr = krealloc_ext(KHEAP_DEFAULT, kr.addr, old_alloc_size, alloc_size,
	    Z_WAITOK | Z_NOFAIL, NULL);
	if (!kr.addr || test_bucket_size(KHEAP_DEFAULT, kr.size) ==
	    test_bucket_size(KHEAP_DEFAULT, old_alloc_size)) {
		printf("%s: new size class realloc failed\n", __func__);
		return 0;
	}

	old_alloc_size = alloc_size;
	alloc_size *= 2;
	data_ptr = krealloc_ext(KHEAP_DEFAULT, kr.addr, old_alloc_size,
	    alloc_size, Z_WAITOK | Z_NOFAIL, NULL).addr;
	if (!data_ptr) {
		printf("%s: realloc without old size returned null\n", __func__);
		return 0;
	}
	kheap_free(KHEAP_DEFAULT, data_ptr, alloc_size);

	printf("%s: test passed\n", __func__);
	*out = 1;
	return 0;
}
SYSCTL_TEST_REGISTER(kalloc, run_kalloc_test);

#endif
