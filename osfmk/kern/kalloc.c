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
#include <kern/zalloc_internal.h>
#include <kern/kalloc.h>
#include <kern/ledger.h>
#include <kern/backtrace.h>
#include <vm/vm_kern.h>
#include <vm/vm_object.h>
#include <vm/vm_map.h>
#include <sys/kdebug.h>

#include <san/kasan.h>
#include <libkern/section_keywords.h>
#include <libkern/prelink.h>

/* #define KALLOC_DEBUG            1 */

#define KiB(x) (1024 * (x))
#define MeB(x) (1024 * 1024 * (x))

#define KALLOC_MAP_SIZE_MIN  MeB(16)
#define KALLOC_MAP_SIZE_MAX  MeB(128)

#if __LP64__
#define KALLOC_KERNMAP_ALLOC_THRESHOLD     (MeB(1))
#else
#define KALLOC_KERNMAP_ALLOC_THRESHOLD     (KiB(256))
#endif

#define EMPTY_RANGE (struct zone_map_range){0,0}

static SECURITY_READ_ONLY_LATE(struct zone_map_range) kernel_data_map_range;
static SECURITY_READ_ONLY_LATE(struct zone_map_range) kalloc_data_or_kernel_data_range;
static SECURITY_READ_ONLY_LATE(vm_size_t) kalloc_map_size;
SECURITY_READ_ONLY_LATE(vm_size_t) kalloc_max_prerounded;
static SECURITY_READ_ONLY_LATE(struct zone_map_range) kalloc_large_range[KHEAP_ID_COUNT];

/* size of kallocs that can come from kernel map */
static SECURITY_READ_ONLY_LATE(vm_map_t)  kernel_data_map;
static SECURITY_READ_ONLY_LATE(vm_map_t)  kalloc_large_map;
static SECURITY_READ_ONLY_LATE(vm_map_t)  kalloc_large_data_map;

/* how many times we couldn't allocate out of kalloc_large_map and fell back to kernel_map */
unsigned long kalloc_fallback_count;

uint_t     kalloc_large_inuse;
vm_size_t  kalloc_large_total;
vm_size_t  kalloc_large_max;
vm_size_t  kalloc_largest_allocated = 0;
uint64_t   kalloc_large_sum;

LCK_GRP_DECLARE(kalloc_lck_grp, "kalloc.large");
LCK_SPIN_DECLARE(kalloc_lock, &kalloc_lck_grp);

#define kalloc_spin_lock()      lck_spin_lock(&kalloc_lock)
#define kalloc_unlock()         lck_spin_unlock(&kalloc_lock)

#pragma mark initialization

/*
 * All allocations of size less than kalloc_max are rounded to the next nearest
 * sized zone.  This allocator is built on top of the zone allocator.  A zone
 * is created for each potential size that we are willing to get in small
 * blocks.
 *
 * kalloc_max_prerounded, which is equivalent to kheap->kalloc_max, is the
 * smallest allocation size, before rounding, for which no zone exists.
 *
 * Also if the allocation size is more than KALLOC_KERNMAP_ALLOC_THRESHOLD then allocate
 * from kernel map rather than kalloc_large_map.
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
static SECURITY_READ_ONLY_LATE(zone_t) k_zone_kext[MAX_K_ZONE(k_zone_cfg)];

#if VM_TAG_SIZECLASSES
static_assert(VM_TAG_SIZECLASSES >= MAX_K_ZONE(k_zone_cfg));
#endif

const char * const kalloc_heap_names[] = {
	[KHEAP_ID_NONE]          = "",
	[KHEAP_ID_DEFAULT]       = "default.",
	[KHEAP_ID_DATA_BUFFERS]  = "data.",
	[KHEAP_ID_KEXT]          = "kext.",
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
	}
};


/*
 * Kext heap configuration
 */
static SECURITY_READ_ONLY_LATE(struct kheap_zones) kalloc_zones_kext = {
	.cfg         = k_zone_cfg,
	.heap_id     = KHEAP_ID_KEXT,
	.k_zone      = k_zone_kext,
	.max_k_zone  = MAX_K_ZONE(k_zone_cfg)
};
SECURITY_READ_ONLY_LATE(struct kalloc_heap) KHEAP_KEXT[1] = {
	{
		.kh_zones    = &kalloc_zones_kext,
		.kh_name     = "kext.",
		.kh_heap_id  = KHEAP_ID_KEXT,
	}
};

KALLOC_HEAP_DEFINE(KERN_OS_MALLOC, "kern_os_malloc", KHEAP_ID_KEXT);

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
	zones->kalloc_max = (zones->cfg[zones->max_k_zone - 1].kzc_size) + 1;
	for (uint32_t i = 0; i < zones->max_k_zone &&
	    (size = cfg[i].kzc_size) < zones->kalloc_max; i++) {
		zone_create_flags_t flags = ZC_KASAN_NOREDZONE |
		    ZC_KASAN_NOQUARANTINE | ZC_KALLOC_HEAP;
		if (cfg[i].kzc_caching) {
			flags |= ZC_CACHING;
		}

		k_zone[i] = zone_create_ext(cfg[i].kzc_name, size, flags,
		    ZONE_ID_ANY, ^(zone_t z){
			zone_security_array[zone_index(z)].z_kheap_id = (uint8_t)zones->heap_id;
		});
		/*
		 * Set the updated elem size back to the config
		 */
		uint32_t elem_size = k_zone[i]->z_elem_size;
		if (cfg[i].kzc_size != elem_size) {
			cfg[i].kzc_size = elem_size;
			snprintf(cfg[i].kzc_name, MAX_ZONE_NAME, "kalloc.%u", elem_size);
		}
	}

	/*
	 * Set large maps and fallback maps for each zone
	 */
	if ((zsecurity_options & ZSECURITY_OPTIONS_KERNEL_DATA_MAP) &&
	    kheap == KHEAP_DATA_BUFFERS) {
		kheap->kh_large_map = kalloc_large_data_map;
		kheap->kh_fallback_map = kernel_data_map;
		kheap->kh_tag = VM_KERN_MEMORY_KALLOC_DATA;
	} else {
		kheap->kh_large_map = kalloc_large_map;
		kheap->kh_fallback_map = kernel_map;
		kheap->kh_tag = VM_KERN_MEMORY_KALLOC;
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

#ifdef KALLOC_DEBUG
	printf("kalloc_init: k_zindex_start %d\n", zones->k_zindex_start);

	/*
	 * Do a quick synthesis to see how well/badly we can
	 * find-a-zone for a given size.
	 * Useful when debugging/tweaking the array of zone sizes.
	 * Cache misses probably more critical than compare-branches!
	 */
	for (uint32_t i = 0; i < zones->max_k_zone; i++) {
		vm_size_t testsize = (vm_size_t)(cfg[i].kzc_size - 1);
		int compare = 0;
		uint8_t zindex;

		if (testsize < MAX_SIZE_ZDLUT) {
			compare += 1;   /* 'if' (T) */

			long dindex = INDEX_ZDLUT(testsize);
			zindex = (int)zones->dlut[dindex];
		} else if (testsize < zones->kalloc_max) {
			compare += 2;   /* 'if' (F), 'if' (T) */

			zindex = zones->k_zindex_start;
			while ((vm_size_t)(cfg[zindex].kzc_size) < testsize) {
				zindex++;
				compare++;      /* 'while' (T) */
			}
			compare++;      /* 'while' (F) */
		} else {
			break;  /* not zone-backed */
		}
		zone_t z = k_zone[zindex];
		printf("kalloc_init: req size %4lu: %8s.%16s took %d compare%s\n",
		    (unsigned long)testsize, kalloc_heap_names[zones->heap_id],
		    z->z_name, compare, compare == 1 ? "" : "s");
	}
#endif
}

/*
 *	Initialize the memory allocator.  This should be called only
 *	once on a system wide basis (i.e. first processor to get here
 *	does the initialization).
 *
 *	This initializes all of the zones.
 */

__startup_func
void
kalloc_init_maps(vm_address_t min_address)
{
	kern_return_t retval;
	vm_map_kernel_flags_t vmk_flags;
	vm_size_t data_map_size;
	struct zone_map_range range, *cur;

	/*
	 * Scale the kalloc_map_size to physical memory size: stay below
	 * 1/8th the total zone map size, or 128 MB (for a 32-bit kernel).
	 */
	kalloc_map_size = round_page((vm_size_t)((sane_size >> 2) / 10));
#if !__LP64__
	if (kalloc_map_size > KALLOC_MAP_SIZE_MAX) {
		kalloc_map_size = KALLOC_MAP_SIZE_MAX;
	}
#endif /* !__LP64__ */
	if (kalloc_map_size < KALLOC_MAP_SIZE_MIN) {
		kalloc_map_size = KALLOC_MAP_SIZE_MIN;
	}

	vmk_flags = VM_MAP_KERNEL_FLAGS_NONE;
	vmk_flags.vmkf_permanent = TRUE;

	/* map for large allocations */

	retval = kmem_suballoc(kernel_map, &range.min_address, kalloc_map_size,
	    FALSE, VM_FLAGS_ANYWHERE, vmk_flags,
	    VM_KERN_MEMORY_KALLOC, &kalloc_large_map);
	if (retval != KERN_SUCCESS) {
		panic("kalloc_large_data_map: kmem_suballoc failed %d", retval);
	}
	range.max_address = range.min_address + kalloc_map_size;
#if DEBUG || DEVELOPMENT
	printf("kalloc:    deflt map %p:%p (%zuM)\n",
	    (void *)range.min_address, (void *)range.max_address,
	    (size_t)zone_range_size(&range) >> 20);
#endif /* DEBUG || DEVELOPMENT */

	/* unless overridden below, all kalloc heaps share the same range */
	kalloc_large_range[KHEAP_ID_DEFAULT] = range;
	kalloc_large_range[KHEAP_ID_KEXT] = range;
	kalloc_large_range[KHEAP_ID_DATA_BUFFERS] = range;

	min_address = MAX(min_address, range.max_address);

	if (zsecurity_options & ZSECURITY_OPTIONS_KERNEL_DATA_MAP) {
		vm_map_size_t largest_free_size;

		vm_map_sizes(kernel_map, NULL, NULL, &largest_free_size);
		data_map_size = (vm_size_t)(largest_free_size / 2);
		data_map_size -= (data_map_size % MeB(1));

		kalloc_data_or_kernel_data_range = (struct zone_map_range){
			.min_address = min_address,
			.max_address = min_address + data_map_size,
		};

		/* map for large user controlled data allocations */

		cur = &kalloc_large_range[KHEAP_ID_DATA_BUFFERS];
		cur->min_address = min_address;
		cur->max_address = min_address + kalloc_map_size;
#if DEBUG || DEVELOPMENT
		printf("kalloc:    data map  %p:%p (%zuM)\n",
		    (void *)cur->min_address, (void *)cur->max_address,
		    (size_t)zone_range_size(cur) >> 20);
#endif /* DEBUG || DEVELOPMENT */

		retval = kmem_suballoc(kernel_map, &cur->min_address,
		    kalloc_map_size, FALSE, VM_FLAGS_FIXED, vmk_flags,
		    VM_KERN_MEMORY_KALLOC_DATA, &kalloc_large_data_map);
		if (retval != KERN_SUCCESS) {
			panic("kalloc_large_data_map: kmem_suballoc failed %d",
			    retval);
		}


		/* kernel data map for user controlled data */

		cur = &kernel_data_map_range;
		cur->min_address = min_address + kalloc_map_size;
		cur->max_address = min_address + data_map_size;
#if DEBUG || DEVELOPMENT
		printf("kernel:    data map  %p:%p (%zuM)\n",
		    (void *)cur->min_address, (void *)cur->max_address,
		    (size_t)zone_range_size(cur) >> 20);
#endif /* DEBUG || DEVELOPMENT */

		retval = kmem_suballoc(kernel_map, &cur->min_address,
		    data_map_size - kalloc_map_size,
		    FALSE, VM_FLAGS_FIXED, vmk_flags,
		    VM_KERN_MEMORY_KALLOC_DATA, &kernel_data_map);
		if (retval != KERN_SUCCESS) {
			panic("kalloc_large_data_map: kmem_suballoc failed %d",
			    retval);
		}
	}
}

__startup_func
static void
kalloc_init(void)
{
	/* allocations larger than 16 times kalloc_max go directly to kernel map */
	kalloc_largest_allocated = KALLOC_KERNMAP_ALLOC_THRESHOLD;

	/* Initialize kalloc default heap */
	kalloc_zones_init(KHEAP_DEFAULT);
	kalloc_max_prerounded = KHEAP_DEFAULT->kh_zones->kalloc_max;
	assert(kalloc_max_prerounded > KALLOC_SAFE_ALLOC_SIZE);

	/* Initialize kalloc data buffers heap */
	if (ZSECURITY_OPTIONS_SUBMAP_USER_DATA & zsecurity_options) {
		kalloc_zones_init(KHEAP_DATA_BUFFERS);
	} else {
		*KHEAP_DATA_BUFFERS = *KHEAP_DEFAULT;
	}

	/* Initialize kalloc kext heap */
	if (ZSECURITY_OPTIONS_SEQUESTER_KEXT_KALLOC & zsecurity_options) {
		kalloc_zones_init(KHEAP_KEXT);
	} else {
		*KHEAP_KEXT = *KHEAP_DEFAULT;
	}
}
STARTUP(ZALLOC, STARTUP_RANK_THIRD, kalloc_init);

#define KEXT_ALIGN_SHIFT       6
#define KEXT_ALIGN_BYTES       (1<< KEXT_ALIGN_SHIFT)
#define KEXT_ALIGN_MASK        (KEXT_ALIGN_BYTES-1)
#define kt_scratch_size        (256ul << 10)

#if XNU_TARGET_OS_WATCH
#define KT_ZBUDGET 85
#else
#define KT_ZBUDGET 200
#endif

TUNABLE(kalloc_type_options_t, kt_options, "kt", KT_OPTIONS_ON);
TUNABLE(uint16_t, kt_zone_budget, "kt_zbudget", KT_ZBUDGET);

extern struct kalloc_type_view kalloc_types[]
__SECTION_START_SYM(KALLOC_TYPE_SEGMENT, "__kalloc_type");

extern struct kalloc_type_view kalloc_types_end[]
__SECTION_END_SYM(KALLOC_TYPE_SEGMENT, "__kalloc_type");

__startup_data
static kalloc_type_view_t *kt_buffer = NULL;
__startup_data
static uint64_t kt_count;

#if DEBUG || DEVELOPMENT
/*
 * For use by lldb to iterate over kalloc types
 */
uint64_t num_kt_sizeclass = MAX_K_ZONE(k_zone_cfg);
SECURITY_READ_ONLY_LATE(zone_t) kalloc_type_zarray[MAX_K_ZONE(k_zone_cfg)];
#endif

static_assert(KT_VM_TAG_MASK == Z_VM_TAG_MASK, "validate vm tag mask");
static_assert(MAX_K_ZONE(k_zone_cfg) < KALLOC_TYPE_IDX_MASK,
    "validate idx mask");
/* qsort routines */
typedef int (*cmpfunc_t)(const void *a, const void *b);
extern void qsort(void *a, size_t n, size_t es, cmpfunc_t cmp);

static uint32_t
kalloc_idx_for_size(kalloc_heap_t kheap, uint32_t size)
{
	struct kheap_zones *khz = kheap->kh_zones;
	uint16_t idx;
	if (size >= khz->kalloc_max) {
		assert(size <= KALLOC_TYPE_SIZE_MASK);
		return kalloc_type_set_idx(size, KALLOC_TYPE_IDX_MASK);
	}

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
kalloc_type_assign_zone(kalloc_type_view_t *cur, kalloc_type_view_t *end,
    zone_t z, vm_tag_t type_tag __unused)
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
		if (kt_flags & KT_PRIV_ACCT ||
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
#if VM_TAG_SIZECLASSES
		/*
		 * If there isn't a tag provided at the callsite
		 * collapse into VM_KERN_MEMORY_KALLOC_TYPE or
		 * VM_KERN_MEMORY_KALLOC_DATA respectively.
		 */
		if (__improbable(z->z_uses_tags)) {
			vm_tag_t tag = zalloc_flags_get_tag((zalloc_flags_t) kt->kt_flags);
			if (tag == VM_KERN_MEMORY_NONE) {
				kt->kt_flags |= Z_VM_TAG(type_tag);
			}
		}
#endif
		cur++;
	}
	if (need_raw_view) {
		zone_view_count += 1;
	}
}

/*
 * Check if signature of type is made up of only data and padding
 */
static bool
kalloc_type_is_data(const char *kt_signature)
{
	while ((*kt_signature == '2') || (*kt_signature == '0')) {
		kt_signature++;
	}
	return *kt_signature == '\0';
}

__startup_func
static void
kalloc_type_view_copy(kalloc_type_view_t start, kalloc_type_view_t end,
    uint64_t *cur_count, vm_offset_t slide)
{
	struct kalloc_type_view *cur = start;
	uint64_t count = end - start;
	if (count + *cur_count >= kt_count) {
		panic("kalloc_type_view_copy: Insufficient space in scratch buffer");
	}
	while (cur < end) {
		cur->kt_signature += slide;
		cur->kt_zv.zv_name += slide;
		/*
		 * If signature indicates that the entire allocation is data move it to
		 * KHEAP_DATA_BUFFERS
		 */
		if (kalloc_type_is_data(cur->kt_signature)) {
			cur->kt_size = kalloc_idx_for_size(KHEAP_DATA_BUFFERS, cur->kt_size);
			uint16_t kt_idx = kalloc_type_get_idx(cur->kt_size);
			if (kt_idx != KALLOC_TYPE_IDX_MASK) {
				zone_t z = kalloc_heap_zone_for_idx(KHEAP_DATA_BUFFERS, kt_idx);
				kalloc_type_assign_zone(&cur, &cur + 1, z, VM_KERN_MEMORY_KALLOC_DATA);
			}
			cur++;
			continue;
		}

		cur->kt_size = kalloc_idx_for_size(KHEAP_DEFAULT, cur->kt_size);

		kt_buffer[*cur_count] = cur;
		cur++;
		*cur_count = *cur_count + 1;
	}
}

__startup_func
static uint64_t
kalloc_type_view_parse(void)
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
		kalloc_type_view_copy(kalloc_types, kalloc_types_end, &cur_count, 0);
	} else if (kc_format == KCFormatFileset) {
		/*
		 * If kc uses filesets, traverse __kalloc_type section for each
		 * macho in the BootKC.
		 */
		kernel_mach_header_t *kc_mh = NULL;
		kernel_mach_header_t *kext_mh = NULL;
		char *fse_name = NULL;
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
			fse_name = (char *)((vm_offset_t)fse +
			    (vm_offset_t)(fse->entry_id.offset));
			kext_mh = (kernel_mach_header_t *)fse->vmaddr;
			kernel_section_t *sect = (kernel_section_t *)getsectbynamefromheader(
				kext_mh, KALLOC_TYPE_SEGMENT, "__kalloc_type");
			if (sect != NULL) {
				kalloc_type_view_copy((kalloc_type_view_t) sect->addr,
				    (kalloc_type_view_t)(sect->addr + sect->size), &cur_count, 0);
			}
		}
	} else if (kc_format == KCFormatKCGEN) {
		/*
		 * Parse __kalloc_type section from xnu
		 */
		kalloc_type_view_copy(kalloc_types, kalloc_types_end, &cur_count, 0);

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
		vm_offset_t kext_slide = vm_kernel_slide;

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
					    KALLOC_TYPE_SEGMENT, "__kalloc_type");
					if (kt_sect) {
						kalloc_type_view_copy(
							(kalloc_type_view_t) (kt_sect->addr + kext_slide),
							(kalloc_type_view_t)(kt_sect->addr +
							kt_sect->size + kext_slide), &cur_count, kext_slide);
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

static int
kalloc_type_cmp(const void *a, const void *b)
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

static uint16_t *
kalloc_type_create_iterators(uint16_t *kt_skip_list_start,
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
		kalloc_type_view_t kt = kt_buffer[i];
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
	/*
	 * Update iterators only if size fits in zone. When size is larger
	 * than kalloc_max, idx is set to KALLOC_TYPE_IDX_MASK. These
	 * allocations will be serviced by kalloc_large when
	 * kalloc_type_impl_external is called.
	 */
	if (c_idx != KALLOC_TYPE_IDX_MASK) {
		assert(kt_freq_list[c_idx] == 0);
		kt_freq_list[c_idx] = unique_sig;
		kt_freq_list_total[c_idx] = (uint16_t) total_sig;
		*kt_skip_list = (uint16_t) count;
	}
	return ++kt_skip_list;
}

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

#define KT_ENTROPY_SHIFT 16
#define KT_ENTROPY_MASK 0xFFFF

/*
 * Returns a 16bit random number between 0 and
 * upper_limit (inclusive)
 */
static uint16_t
kalloc_type_get_random(uint16_t upper_limit)
{
	assert(upper_limit < KT_ENTROPY_MASK);
	static uint64_t random_entropy;
	if (random_entropy == 0) {
		random_entropy = early_random();
	}
	uint16_t result = random_entropy & KT_ENTROPY_MASK;
	random_entropy >>= KT_ENTROPY_SHIFT;
	return result % (upper_limit + 1);
}

/*
 * Generate a randomly shuffled array of indices from 0 to count - 1
 */
static void
kalloc_type_shuffle(uint16_t *shuffle_buf, uint16_t count)
{
	for (uint16_t i = 0; i < count; i++) {
		uint16_t j = kalloc_type_get_random(i);
		if (j != i) {
			shuffle_buf[i] = shuffle_buf[j];
		}
		shuffle_buf[j] = i;
	}
}

static void
kalloc_type_create_zones(uint16_t *kt_skip_list_start,
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
	if (kt_options & KT_OPTIONS_ON) {
		kalloc_type_apply_policy(kt_freq_list, kt_zones, kt_zone_budget);
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
	}

	for (uint16_t i = 0; i < MAX_K_ZONE(k_zone_cfg); i++) {
		uint16_t n_unique_sig = kt_freq_list[i];
		vm_size_t z_size = k_zone_cfg[i].kzc_size;
		uint16_t n_zones = kt_zones[i];

		if (n_unique_sig == 0) {
			continue;
		}

		assert(n_zones <= 20);
		zone_t kt_zones_for_size[20] = {};
		if (kt_options & KT_OPTIONS_ON) {
			kalloc_type_create_zone_for_size(kt_zones_for_size,
			    n_zones, z_size);
		} else {
			/*
			 * Default to using KHEAP_DEFAULT if this feature is off
			 */
			n_zones = 1;
			kt_zones_for_size[0] = kalloc_heap_zone_for_size(
				KHEAP_DEFAULT, z_size);
		}

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
			kalloc_type_shuffle(kt_shuffle_buf, n_unique_sig);
		}

		for (uint16_t j = 0; j < n_unique_sig; j++) {
			/*
			 * For every size that has unique types
			 */
			uint16_t shuffle_idx = kt_shuffle_buf[j];
			uint16_t cur = kt_skip_list[shuffle_idx + p_j];
			uint16_t end = kt_skip_list[shuffle_idx + p_j + 1];
			zone_t zone = kt_zones_for_size[j % n_zones];
			kalloc_type_assign_zone(&kt_buffer[cur], &kt_buffer[end], zone,
			    VM_KERN_MEMORY_KALLOC_TYPE);
		}
		p_j += n_unique_sig;
	}
}

__startup_func
static void
kalloc_type_view_init(void)
{
	/*
	 * Turn off this feature on armv7 and kasan
	 */
#if !defined(__LP64__) || KASAN_ZALLOC
	kt_options &= ~KT_OPTIONS_ON;
#endif

	/*
	 * Allocate scratch space to parse kalloc_type_views and create
	 * other structures necessary to process them.
	 */
	kt_count = kt_scratch_size / sizeof(kalloc_type_view_t);
	if (kmem_alloc_flags(kernel_map, (vm_offset_t *) &kt_buffer,
	    kt_scratch_size,
	    VM_KERN_MEMORY_KALLOC, KMA_ZERO) != KERN_SUCCESS) {
		panic("kalloc_type_view_init: Couldn't create scratch space");
	}
	/*
	 * Parse __kalloc_type sections and build array of pointers to
	 * all kalloc type views in kt_buffer.
	 */
	kt_count = kalloc_type_view_parse();
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
	    kalloc_type_cmp);

	/*
	 * Build a skip list that holds starts of unique signatures and a
	 * frequency list of number of unique and total signatures per kalloc
	 * size class
	 */
	uint16_t *kt_skip_list_start = (uint16_t *)(kt_buffer + kt_count);
	uint16_t kt_freq_list[MAX_K_ZONE(k_zone_cfg)] = { 0 };
	uint16_t kt_freq_list_total[MAX_K_ZONE(k_zone_cfg)] = { 0 };
	uint16_t *kt_shuffle_buf = kalloc_type_create_iterators(
		kt_skip_list_start, kt_freq_list, kt_freq_list_total, kt_count);

	/*
	 * Create zones based on signatures
	 */
	kalloc_type_create_zones(kt_skip_list_start, kt_freq_list,
	    kt_freq_list_total, kt_shuffle_buf);

	/*
	 * Free resources used
	 */
	kmem_free(kernel_map, (vm_offset_t) kt_buffer, kt_scratch_size);
}
STARTUP(ZALLOC, STARTUP_RANK_LAST, kalloc_type_view_init);

#pragma mark accessors

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

static inline vm_map_t
kalloc_guess_map_for_addr(kalloc_heap_t kheap, vm_address_t addr)
{
	/* kheap is NULL when KHEAP_ANY */
	if (kheap == KHEAP_ANY) {
		kheap = KHEAP_DEFAULT;
	}

	if (zone_range_contains(&kalloc_large_range[kheap->kh_heap_id], addr)) {
		return kheap->kh_large_map;
	} else {
		return kheap->kh_fallback_map;
	}
}

static inline vm_map_t
kalloc_map_for_size(kalloc_heap_t kheap, vm_size_t size)
{
	if (size < KALLOC_KERNMAP_ALLOC_THRESHOLD) {
		return kheap->kh_large_map;
	}
	return kheap->kh_fallback_map;
}

zone_t
kalloc_heap_zone_for_size(kalloc_heap_t kheap, vm_size_t size)
{
	struct kheap_zones *khz = kheap->kh_zones;

	if (size < MAX_SIZE_ZDLUT) {
		uint32_t zindex = khz->dlut[INDEX_ZDLUT(size)];
		return khz->k_zone[zindex];
	}

	if (size < khz->kalloc_max) {
		uint32_t zindex = khz->k_zindex_start;
		while (khz->cfg[zindex].kzc_size < size) {
			zindex++;
		}
		assert(zindex < khz->max_k_zone);
		return khz->k_zone[zindex];
	}

	return ZONE_NULL;
}

static vm_size_t
vm_map_lookup_kalloc_entry_locked(vm_map_t map, void *addr)
{
	vm_map_entry_t vm_entry = NULL;

	if (!vm_map_lookup_entry(map, (vm_map_offset_t)addr, &vm_entry)) {
		panic("address %p not allocated via kalloc, map %p",
		    addr, map);
	}
	if (vm_entry->vme_start != (vm_map_offset_t)addr) {
		panic("address %p inside vm entry %p [%p:%p), map %p",
		    addr, vm_entry, (void *)vm_entry->vme_start,
		    (void *)vm_entry->vme_end, map);
	}
	if (!vm_entry->vme_atomic) {
		panic("address %p not managed by kalloc (entry %p, map %p)",
		    addr, vm_entry, map);
	}
	return vm_entry->vme_end - vm_entry->vme_start;
}

#if KASAN_KALLOC
/*
 * KASAN kalloc stashes the original user-requested size away in the poisoned
 * area. Return that directly.
 */
vm_size_t
kheap_alloc_size(__unused kalloc_heap_t kheap, void *addr)
{
	(void)vm_map_lookup_kalloc_entry_locked; /* silence warning */
	return kasan_user_size((vm_offset_t)addr);
}
#else
vm_size_t
kheap_alloc_size(kalloc_heap_t kheap, void *addr)
{
	vm_map_t  map;
	vm_size_t size;

	size = zone_element_size(addr, NULL);
	if (size) {
		return size;
	}

	map = kalloc_guess_map_for_addr(kheap, (vm_offset_t)addr);
	vm_map_lock_read(map);
	size = vm_map_lookup_kalloc_entry_locked(map, addr);
	vm_map_unlock_read(map);
	return size;
}
#endif

static vm_size_t
kalloc_bucket_size(kalloc_heap_t kheap, vm_size_t size)
{
	zone_t   z   = kalloc_heap_zone_for_size(kheap, size);
	vm_map_t map = kalloc_map_for_size(kheap, size);

	if (z) {
		return zone_elem_size(z);
	}
	return vm_map_round_page(size, VM_MAP_PAGE_MASK(map));
}

bool
kalloc_owned_map(vm_map_t map)
{
	return map && (map == kalloc_large_map ||
	       map == kalloc_large_data_map ||
	       map == kernel_data_map);
}

vm_map_t
kalloc_large_map_get(void)
{
	return kalloc_large_map;
}

vm_map_t
kalloc_large_data_map_get(void)
{
	return kalloc_large_data_map;
}

vm_map_t
kernel_data_map_get(void)
{
	return kernel_data_map;
}

#pragma mark kalloc

__attribute__((noinline))
static struct kalloc_result
kalloc_large(
	kalloc_heap_t         kheap,
	vm_size_t             req_size,
	vm_size_t             size,
	zalloc_flags_t        flags,
	vm_allocation_site_t  *site)
{
	int kma_flags = KMA_ATOMIC;
	vm_tag_t tag;
	vm_map_t alloc_map;
	vm_offset_t addr;

	if (flags & Z_NOFAIL) {
		panic("trying to kalloc(Z_NOFAIL) with a large size (%zd)",
		    (size_t)size);
	}
	/*
	 * kmem_alloc could block so we return if noblock
	 *
	 * also, reject sizes larger than our address space is quickly,
	 * as kt_size or IOMallocArraySize() expect this.
	 */
	if ((flags & Z_NOWAIT) || (size >> VM_KERNEL_POINTER_SIGNIFICANT_BITS)) {
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
	kma_flags |= KMA_KOBJECT;
#endif
	if (flags & Z_NOPAGEWAIT) {
		kma_flags |= KMA_NOPAGEWAIT;
	}
	if (flags & Z_ZERO) {
		kma_flags |= KMA_ZERO;
	}

#if KASAN_KALLOC
	/* large allocation - use guard pages instead of small redzones */
	size = round_page(req_size + 2 * PAGE_SIZE);
	assert(size >= MAX_SIZE_ZDLUT && size >= kalloc_max_prerounded);
#else
	size = round_page(size);
#endif

	alloc_map = kalloc_map_for_size(kheap, size);

	tag = zalloc_flags_get_tag(flags);
	if (tag == VM_KERN_MEMORY_NONE) {
		if (site) {
			tag = vm_tag_alloc(site);
		} else if (kheap->kh_heap_id == KHEAP_ID_DATA_BUFFERS) {
			tag = VM_KERN_MEMORY_KALLOC_DATA;
		} else {
			tag = VM_KERN_MEMORY_KALLOC;
		}
	}

	if (kmem_alloc_flags(alloc_map, &addr, size, tag, kma_flags) != KERN_SUCCESS) {
		if (alloc_map != kheap->kh_fallback_map) {
			if (kalloc_fallback_count++ == 0) {
				printf("%s: falling back to kernel_map\n", __func__);
			}
			if (kmem_alloc_flags(kheap->kh_fallback_map, &addr, size,
			    tag, kma_flags) != KERN_SUCCESS) {
				addr = 0;
			}
		} else {
			addr = 0;
		}
	}

	if (addr != 0) {
		kalloc_spin_lock();
		/*
		 * Thread-safe version of the workaround for 4740071
		 * (a double FREE())
		 */
		if (size > kalloc_largest_allocated) {
			kalloc_largest_allocated = size;
		}

		kalloc_large_inuse++;
		assert(kalloc_large_total + size >= kalloc_large_total); /* no wrap around */
		kalloc_large_total += size;
		kalloc_large_sum += size;

		if (kalloc_large_total > kalloc_large_max) {
			kalloc_large_max = kalloc_large_total;
		}

		kalloc_unlock();

		KALLOC_ZINFO_SALLOC(size);
	}
#if KASAN_KALLOC
	/* fixup the return address to skip the redzone */
	addr = kasan_alloc(addr, size, req_size, PAGE_SIZE);
#else
	req_size = size;
#endif

	DTRACE_VM3(kalloc, vm_size_t, size, vm_size_t, req_size, void*, addr);
	return (struct kalloc_result){ .addr = (void *)addr, .size = req_size };
}

struct kalloc_result
kalloc_ext(
	kalloc_heap_t         kheap,
	vm_size_t             req_size,
	zalloc_flags_t        flags,
	vm_allocation_site_t  *site)
{
	vm_size_t size;
	void *addr;
	zone_t z;

	/*
	 * Kasan for kalloc heaps will put the redzones *inside*
	 * the allocation, and hence augment its size.
	 *
	 * kalloc heaps do not use zone_t::z_kasan_redzone.
	 */
#if KASAN_KALLOC
	size = kasan_alloc_resize(req_size);
#else
	size = req_size;
#endif
	z = kalloc_heap_zone_for_size(kheap, size);
	if (__improbable(z == ZONE_NULL)) {
		return kalloc_large(kheap, req_size, size, flags, site);
	}

#ifdef KALLOC_DEBUG
	if (size > zone_elem_size(z)) {
		panic("%s: z %p (%s%s) but requested size %lu", __func__, z,
		    kalloc_heap_names[kheap->kh_zones->heap_id], z->z_name,
		    (unsigned long)size);
	}
#endif
	assert(size <= zone_elem_size(z));

#if VM_TAG_SIZECLASSES
	if (__improbable(z->z_uses_tags)) {
		vm_tag_t tag = zalloc_flags_get_tag(flags);
		if (tag == VM_KERN_MEMORY_NONE && site) {
			tag = vm_tag_alloc(site);
		}
		if (tag != VM_KERN_MEMORY_NONE) {
			tag = vm_tag_will_update_zone(tag, z->z_tags_sizeclass,
			    flags & (Z_WAITOK | Z_NOWAIT | Z_NOPAGEWAIT));
		}
		flags |= Z_VM_TAG(tag);
	}
#endif
	addr = zalloc_ext(z, kheap->kh_stats ?: z->z_stats, flags);

#if KASAN_KALLOC
	addr = (void *)kasan_alloc((vm_offset_t)addr, zone_elem_size(z),
	    req_size, KASAN_GUARD_SIZE);
#else
	req_size = zone_elem_size(z);
#endif

	DTRACE_VM3(kalloc, vm_size_t, size, vm_size_t, req_size, void*, addr);
	return (struct kalloc_result){ .addr = addr, .size = req_size };
}

void *
kalloc_external(vm_size_t size);
void *
kalloc_external(vm_size_t size)
{
	return kheap_alloc_tag_bt(KHEAP_KEXT, size, Z_WAITOK, VM_KERN_MEMORY_KALLOC);
}

void *
kalloc_data_external(
	vm_size_t           size,
	zalloc_flags_t      flags);
void *
kalloc_data_external(
	vm_size_t size,
	zalloc_flags_t flags)
{
	return kheap_alloc_tag_bt(KHEAP_DATA_BUFFERS, size, flags,
	           VM_KERN_MEMORY_KALLOC_DATA);
}

__abortlike
static void
kalloc_data_require_panic(void *addr, vm_size_t size)
{
	zone_id_t zid = zone_id_for_native_element(addr, size);

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

void
kalloc_data_require(void *addr, vm_size_t size)
{
	if (zsecurity_options & ZSECURITY_OPTIONS_SUBMAP_USER_DATA) {
		zone_id_t zid = zone_id_for_native_element(addr, size);

		if (zid != ZONE_ID_INVALID) {
			zone_t z = &zone_array[zid];
			zone_security_flags_t zsflags = zone_security_array[zid];
			if (zsflags.z_kheap_id == KHEAP_ID_DATA_BUFFERS &&
			    size <= zone_elem_size(z)) {
				return;
			}
		} else if (!(zsecurity_options & ZSECURITY_OPTIONS_KERNEL_DATA_MAP)) {
			return;
		} else if (zone_range_contains(&kalloc_data_or_kernel_data_range,
		    (vm_address_t)addr, size)) {
			return;
		}

		kalloc_data_require_panic(addr, size);
	}
}

__abortlike
static void
kalloc_non_data_require_panic(void *addr, vm_size_t size)
{
	zone_id_t zid = zone_id_for_native_element(addr, size);

	if (zid != ZONE_ID_INVALID) {
		zone_t z = &zone_array[zid];
		zone_security_flags_t zsflags = zone_security_array[zid];

		switch (zsflags.z_kheap_id) {
		case KHEAP_ID_NONE:
		case KHEAP_ID_DATA_BUFFERS:
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

void
kalloc_non_data_require(void *addr, vm_size_t size)
{
	if (zsecurity_options & ZSECURITY_OPTIONS_SUBMAP_USER_DATA) {
		zone_id_t zid = zone_id_for_native_element(addr, size);

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
			case KHEAP_ID_KEXT:
				if (size < zone_elem_size(z)) {
					return;
				}
				break;
			default:
				break;
			}
		} else if (!(zsecurity_options & ZSECURITY_OPTIONS_KERNEL_DATA_MAP)) {
			return;
		} else if (!zone_range_contains(&kalloc_data_or_kernel_data_range,
		    (vm_address_t)addr, size)) {
			return;
		}

		kalloc_non_data_require_panic(addr, size);
	}
}

void *
kalloc_type_impl_external(
	kalloc_type_view_t      kt_view,
	zalloc_flags_t          flags)
{
	/*
	 * Callsites from a kext that aren't in the BootKC on macOS or
	 * any callsites on armv7 are not processed during startup,
	 * default to using kheap_alloc
	 *
	 * Additionally when size is greater kalloc_max zone is left
	 * NULL as we need to use the vm for the allocation
	 *
	 */
	if (kt_view->kt_zv.zv_zone == ZONE_NULL) {
		return kheap_alloc_tag_bt(KHEAP_KEXT,
		           kalloc_type_get_size(kt_view->kt_size), flags,
		           VM_KERN_MEMORY_KALLOC);
	}
#if VM_TAG_SIZECLASSES
	zone_t kt_zone = kt_view->kt_zv.zv_zone;
	if (__improbable(kt_zone->z_uses_tags)) {
		vm_tag_t type_tag = zalloc_flags_get_tag(
			(zalloc_flags_t) kt_view->kt_flags);
		vm_tag_t tag = 0;
		/*
		 * kalloc_type_tag isn't exposed to kexts, therefore the only
		 * possible values for type_tag is VM_KERN_MEMORY_KALLOC_TYPE
		 * or VM_KERN_MEMORY_KALLOC_DATA
		 */
		if (type_tag == VM_KERN_MEMORY_KALLOC_TYPE) {
			VM_ALLOC_SITE_STATIC(VM_TAG_BT, VM_KERN_MEMORY_KALLOC_TYPE);
			tag = vm_tag_alloc(&site);
		} else {
			VM_ALLOC_SITE_STATIC(VM_TAG_BT, VM_KERN_MEMORY_KALLOC_DATA);
			tag = vm_tag_alloc(&site);
		}
		assert(tag != VM_KERN_MEMORY_NONE);
		tag = vm_tag_will_update_zone(tag,
		    kt_zone->z_tags_sizeclass,
		    flags & (Z_WAITOK | Z_NOWAIT | Z_NOPAGEWAIT));
		flags |= Z_VM_TAG(tag);
	}
#endif
	return zalloc_flags(kt_view, flags);
}

#pragma mark kfree

__attribute__((noinline))
static void
kfree_large(kalloc_heap_t kheap, vm_offset_t addr, vm_size_t size)
{
	vm_map_t map = kalloc_guess_map_for_addr(kheap, addr);
	kern_return_t ret;
	vm_offset_t end;

	if (addr < VM_MIN_KERNEL_AND_KEXT_ADDRESS ||
	    os_add_overflow(addr, size, &end) ||
	    end > VM_MAX_KERNEL_ADDRESS) {
		panic("kfree: address range (%p, %ld) doesn't belong to the kernel",
		    (void *)addr, (uintptr_t)size);
	}

	if (size == 0) {
		vm_map_lock(map);
		size = vm_map_lookup_kalloc_entry_locked(map, (void *)addr);
		ret = vm_map_remove_locked(map,
		    vm_map_trunc_page(addr, VM_MAP_PAGE_MASK(map)),
		    vm_map_round_page(addr + size, VM_MAP_PAGE_MASK(map)),
		    VM_MAP_REMOVE_KUNWIRE);
		if (ret != KERN_SUCCESS) {
			panic("kfree: vm_map_remove_locked() failed for "
			    "addr: %p, map: %p ret: %d", (void *)addr, map, ret);
		}
		vm_map_unlock(map);
	} else {
		size = round_page(size);

		if (size > kalloc_largest_allocated) {
			panic("kfree: size %lu > kalloc_largest_allocated %lu",
			    (uintptr_t)size, (uintptr_t)kalloc_largest_allocated);
		}
		kmem_free(map, addr, size);
	}

	kalloc_spin_lock();

	assert(kalloc_large_total >= size);
	kalloc_large_total -= size;
	kalloc_large_inuse--;

	kalloc_unlock();

#if !KASAN_KALLOC
	DTRACE_VM3(kfree, vm_size_t, size, vm_size_t, size, void*, addr);
#endif

	KALLOC_ZINFO_SFREE(size);
	return;
}

__abortlike
static void
kfree_heap_confusion_panic(kalloc_heap_t kheap, void *data, size_t size, zone_t z)
{
	zone_security_flags_t zsflags = zone_security_config(z);
	const char *kheap_name = "";

	if (kheap == KHEAP_ANY) {
		kheap_name = "KHEAP_ANY (default/kext)";
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
kfree_size_confusion_panic(zone_t z, void *data, size_t size, size_t zsize)
{
	if (z) {
		panic("kfree: addr %p, size %zd found in zone '%s%s' "
		    "with elem_size %zd",
		    data, size, zone_heap_name(z), z->z_name, zsize);
	} else {
		panic("kfree: addr %p, size %zd not found in any zone",
		    data, size);
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
krealloc_size_invalid_panic(void *data, size_t size)
{
	panic("krealloc: addr %p trying to free with nonsensical size %zd",
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
	vm_size_t elem_size = zone_element_size(addr, NULL);
	if (elem_size > max_zone_size || elem_size < min_size) {
		kfree_size_require_panic(addr, elem_size, min_size, max_zone_size);
	}
}

/* used to implement kheap_free_addr() */
#define KFREE_UNKNOWN_SIZE  ((vm_size_t)~0)
#define KFREE_ABSURD_SIZE \
	((VM_MAX_KERNEL_ADDRESS - VM_MIN_KERNEL_AND_KEXT_ADDRESS) / 2)

static void
kfree_ext(kalloc_heap_t kheap, void *data, vm_size_t size)
{
	zone_stats_t zs = NULL;
	zone_t z;
	vm_size_t zsize;
	zone_security_flags_t zsflags;

	if (__improbable(data == NULL)) {
		return;
	}

#if KASAN_KALLOC
	/*
	 * Resize back to the real allocation size and hand off to the KASan
	 * quarantine. `data` may then point to a different allocation.
	 */
	vm_size_t user_size = size;
	if (size == KFREE_UNKNOWN_SIZE) {
		user_size = size = kheap_alloc_size(kheap, data);
	}
	kasan_check_free((vm_address_t)data, size, KASAN_HEAP_KALLOC);
	data = (void *)kasan_dealloc((vm_address_t)data, &size);
	kasan_free(&data, &size, KASAN_HEAP_KALLOC, NULL, user_size, true);
	if (!data) {
		return;
	}
#endif

	if (size >= kalloc_max_prerounded && size != KFREE_UNKNOWN_SIZE) {
		return kfree_large(kheap, (vm_offset_t)data, size);
	}

	zsize = zone_element_size(data, &z);
	if (size == KFREE_UNKNOWN_SIZE) {
		if (zsize == 0) {
			return kfree_large(kheap, (vm_offset_t)data, 0);
		}
		size = zsize;
	} else if (size > zsize) {
		kfree_size_confusion_panic(z, data, size, zsize);
	}
	zsflags = zone_security_config(z);
	if (kheap != KHEAP_ANY) {
		if (kheap->kh_heap_id != zsflags.z_kheap_id) {
			kfree_heap_confusion_panic(kheap, data, size, z);
		}
		zs = kheap->kh_stats;
	} else if (zsflags.z_kheap_id != KHEAP_ID_DEFAULT &&
	    zsflags.z_kheap_id != KHEAP_ID_KEXT) {
		kfree_heap_confusion_panic(kheap, data, size, z);
	}

#if !KASAN_KALLOC
	DTRACE_VM3(kfree, vm_size_t, size, vm_size_t, zsize, void*, data);
#endif
	zfree_ext(z, zs ?: z->z_stats, data);
}

void
(kfree)(void *addr, vm_size_t size)
{
	if (size > KFREE_ABSURD_SIZE) {
		kfree_size_invalid_panic(addr, size);
	}
	kfree_ext(KHEAP_ANY, addr, size);
}

void
(kheap_free)(kalloc_heap_t kheap, void *addr, vm_size_t size)
{
	if (size > KFREE_ABSURD_SIZE) {
		kfree_size_invalid_panic(addr, size);
	}
	kfree_ext(kheap, addr, size);
}

void
(kheap_free_addr)(kalloc_heap_t kheap, void *addr)
{
	kfree_ext(kheap, addr, KFREE_UNKNOWN_SIZE);
}

void
(kheap_free_bounded)(kalloc_heap_t kheap, void *addr,
    vm_size_t min_sz, vm_size_t max_sz)
{
	if (__improbable(addr == NULL)) {
		return;
	}
	kfree_size_require(kheap, addr, min_sz, max_sz);
	kfree_ext(kheap, addr, KFREE_UNKNOWN_SIZE);
}

static struct kalloc_result
_krealloc_ext(
	kalloc_heap_t           kheap,
	void                   *addr,
	vm_size_t               old_size,
	vm_size_t               new_size,
	zalloc_flags_t          flags,
	vm_allocation_site_t   *site)
{
	vm_size_t old_bucket_size, new_bucket_size, min_size;
	vm_size_t adj_new_size, adj_old_size;
	struct kalloc_result kr;

	if (new_size == 0) {
		kfree_ext(kheap, addr, old_size);
		return (struct kalloc_result){ };
	}

	if (addr == NULL) {
		return kalloc_ext(kheap, new_size, flags, site);
	}

	adj_old_size = old_size;
	adj_new_size = new_size;
#if KASAN_KALLOC
	/*
	 * Adjust sizes to account kasan for redzones
	 */
	adj_new_size = kasan_alloc_resize(new_size);

	if (old_size != KFREE_UNKNOWN_SIZE) {
		adj_old_size = kasan_alloc_resize(old_size);
	}
#endif

	/*
	 * Find out the size of the bucket in which the new sized allocation
	 * would land. If it matches the bucket of the original allocation,
	 * simply return the same address.
	 */
	new_bucket_size = kalloc_bucket_size(kheap, adj_new_size);
	if (old_size == KFREE_UNKNOWN_SIZE) {
		old_size = old_bucket_size = kheap_alloc_size(kheap, addr);
	} else {
		old_bucket_size = kalloc_bucket_size(kheap, adj_old_size);
	}
	min_size = MIN(old_size, new_size);

	if (old_bucket_size == new_bucket_size) {
		kr.addr = addr;
#if KASAN_KALLOC
		kr.size = new_size;
		/*
		 * Adjust right redzone in the element and poison it correctly
		 */
		addr = (void *)kasan_realloc((vm_offset_t)addr, new_bucket_size,
		    new_size, KASAN_GUARD_SIZE);
#else
		kr.size = new_bucket_size;
#endif
	} else {
		kr = kalloc_ext(kheap, new_size, flags & ~Z_ZERO, site);
		if (kr.addr == NULL) {
			return kr;
		}

		memcpy(kr.addr, addr, min_size);
		kfree_ext(kheap, addr, old_size);
	}
	if ((flags & Z_ZERO) && kr.size > min_size) {
		bzero((void *)((uintptr_t)kr.addr + min_size), kr.size - min_size);
	}
	return kr;
}

void
kfree_type_impl_external(
	kalloc_type_view_t  kt_view,
	void               *ptr)
{
	/*
	 * If callsite is from a kext that isn't in the BootKC, it wasn't
	 * processed during startup so default to using kheap_alloc
	 *
	 * Additionally when size is greater kalloc_max zone is left
	 * NULL as we need to use the vm for the allocation/free
	 */
	if (kt_view->kt_zv.zv_zone == ZONE_NULL) {
		return kheap_free(KHEAP_KEXT, ptr,
		           kalloc_type_get_size(kt_view->kt_size));
	}
	if (__improbable(ptr == NULL)) {
		return;
	}
	return zfree(kt_view, ptr);
}

void
kfree_data_external(
	void               *ptr,
	vm_size_t           size);
void
kfree_data_external(
	void               *ptr,
	vm_size_t           size)
{
	return kheap_free(KHEAP_DATA_BUFFERS, ptr, size);
}

void
kfree_data_addr_external(
	void               *ptr);
void
kfree_data_addr_external(
	void               *ptr)
{
	return kheap_free_addr(KHEAP_DATA_BUFFERS, ptr);
}

struct kalloc_result
krealloc_ext(
	kalloc_heap_t           kheap,
	void                   *addr,
	vm_size_t               old_size,
	vm_size_t               new_size,
	zalloc_flags_t          flags,
	vm_allocation_site_t   *site)
{
	if (old_size > KFREE_ABSURD_SIZE) {
		krealloc_size_invalid_panic(addr, old_size);
	}
	return _krealloc_ext(kheap, addr, old_size, new_size, flags, site);
}

struct kalloc_result
kheap_realloc_addr(
	kalloc_heap_t           kheap,
	void                   *addr,
	vm_size_t               size,
	zalloc_flags_t          flags,
	vm_allocation_site_t   *site)
{
	return _krealloc_ext(kheap, addr, KFREE_UNKNOWN_SIZE, size, flags, site);
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
	VM_ALLOC_SITE_STATIC(VM_TAG_BT, VM_KERN_MEMORY_KALLOC_DATA);
	return krealloc_ext(KHEAP_DATA_BUFFERS, ptr, old_size, new_size,
	           flags, &site).addr;
}

void *
krealloc_data_addr_external(
	void               *ptr,
	vm_size_t           new_size,
	zalloc_flags_t      flags);
void *
krealloc_data_addr_external(
	void               *ptr,
	vm_size_t           new_size,
	zalloc_flags_t      flags)
{
	VM_ALLOC_SITE_STATIC(VM_TAG_BT, VM_KERN_MEMORY_KALLOC_DATA);
	return kheap_realloc_addr(KHEAP_DATA_BUFFERS, ptr, new_size,
	           flags, &site).addr;
}

__startup_func
void
kheap_startup_init(kalloc_heap_t kheap)
{
	struct kheap_zones *zones;
	vm_map_t kalloc_map;
	vm_map_t fb_map;
	vm_tag_t tag;

	switch (kheap->kh_heap_id) {
	case KHEAP_ID_DEFAULT:
		zones = KHEAP_DEFAULT->kh_zones;
		kalloc_map = KHEAP_DEFAULT->kh_large_map;
		fb_map = KHEAP_DEFAULT->kh_fallback_map;
		tag = KHEAP_DEFAULT->kh_tag;
		break;
	case KHEAP_ID_DATA_BUFFERS:
		zones = KHEAP_DATA_BUFFERS->kh_zones;
		kalloc_map = KHEAP_DATA_BUFFERS->kh_large_map;
		fb_map = KHEAP_DATA_BUFFERS->kh_fallback_map;
		tag = KHEAP_DATA_BUFFERS->kh_tag;
		break;
	case KHEAP_ID_KEXT:
		zones = KHEAP_KEXT->kh_zones;
		kalloc_map = KHEAP_KEXT->kh_large_map;
		fb_map = KHEAP_KEXT->kh_fallback_map;
		tag = KHEAP_KEXT->kh_tag;
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
	kheap->kh_large_map = kalloc_map;
	kheap->kh_fallback_map = fb_map;
	kheap->kh_tag = tag;
	zone_view_count += 1;
}

#pragma mark OSMalloc
/*
 * This is a deprecated interface, here only for legacy reasons.
 * There is no internal variant of any of these symbols on purpose.
 */
#define OSMallocDeprecated
#include <libkern/OSMalloc.h>

static KALLOC_HEAP_DEFINE(OSMALLOC, "osmalloc", KHEAP_ID_KEXT);
static queue_head_t OSMalloc_tag_list = QUEUE_HEAD_INITIALIZER(OSMalloc_tag_list);
static LCK_GRP_DECLARE(OSMalloc_tag_lck_grp, "OSMalloc_tag");
static LCK_SPIN_DECLARE(OSMalloc_tag_lock, &OSMalloc_tag_lck_grp);

#define OSMalloc_tag_spin_lock()        lck_spin_lock(&OSMalloc_tag_lock)
#define OSMalloc_tag_unlock()           lck_spin_unlock(&OSMalloc_tag_lock)

extern typeof(OSMalloc_Tagalloc) OSMalloc_Tagalloc_external;
OSMallocTag
OSMalloc_Tagalloc_external(const char *str, uint32_t flags)
{
	OSMallocTag OSMTag;

	OSMTag = kalloc_type(struct _OSMallocTag_, Z_WAITOK | Z_ZERO);

	if (flags & OSMT_PAGEABLE) {
		OSMTag->OSMT_attr = OSMT_ATTR_PAGEABLE;
	}

	OSMTag->OSMT_refcnt = 1;

	strlcpy(OSMTag->OSMT_name, str, OSMT_MAX_NAME);

	OSMalloc_tag_spin_lock();
	enqueue_tail(&OSMalloc_tag_list, (queue_entry_t)OSMTag);
	OSMalloc_tag_unlock();
	OSMTag->OSMT_state = OSMT_VALID;
	return OSMTag;
}

static void
OSMalloc_Tagref(OSMallocTag tag)
{
	if (!((tag->OSMT_state & OSMT_VALID_MASK) == OSMT_VALID)) {
		panic("OSMalloc_Tagref():'%s' has bad state 0x%08X",
		    tag->OSMT_name, tag->OSMT_state);
	}

	os_atomic_inc(&tag->OSMT_refcnt, relaxed);
}

static void
OSMalloc_Tagrele(OSMallocTag tag)
{
	if (!((tag->OSMT_state & OSMT_VALID_MASK) == OSMT_VALID)) {
		panic("OSMalloc_Tagref():'%s' has bad state 0x%08X",
		    tag->OSMT_name, tag->OSMT_state);
	}

	if (os_atomic_dec(&tag->OSMT_refcnt, relaxed) != 0) {
		return;
	}

	if (os_atomic_cmpxchg(&tag->OSMT_state,
	    OSMT_VALID | OSMT_RELEASED, OSMT_VALID | OSMT_RELEASED, acq_rel)) {
		OSMalloc_tag_spin_lock();
		(void)remque((queue_entry_t)tag);
		OSMalloc_tag_unlock();
		kfree_type(struct _OSMallocTag_, tag);
	} else {
		panic("OSMalloc_Tagrele():'%s' has refcnt 0", tag->OSMT_name);
	}
}

extern typeof(OSMalloc_Tagfree) OSMalloc_Tagfree_external;
void
OSMalloc_Tagfree_external(OSMallocTag tag)
{
	if (!os_atomic_cmpxchg(&tag->OSMT_state,
	    OSMT_VALID, OSMT_VALID | OSMT_RELEASED, acq_rel)) {
		panic("OSMalloc_Tagfree():'%s' has bad state 0x%08X",
		    tag->OSMT_name, tag->OSMT_state);
	}

	if (os_atomic_dec(&tag->OSMT_refcnt, relaxed) == 0) {
		OSMalloc_tag_spin_lock();
		(void)remque((queue_entry_t)tag);
		OSMalloc_tag_unlock();
		kfree_type(struct _OSMallocTag_, tag);
	}
}

extern typeof(OSMalloc) OSMalloc_external;
void *
OSMalloc_external(
	uint32_t size, OSMallocTag tag)
{
	void           *addr = NULL;
	kern_return_t   kr;

	OSMalloc_Tagref(tag);
	if ((tag->OSMT_attr & OSMT_PAGEABLE) && (size & ~PAGE_MASK)) {
		if ((kr = kmem_alloc_pageable_external(kernel_map,
		    (vm_offset_t *)&addr, size)) != KERN_SUCCESS) {
			addr = NULL;
		}
	} else {
		addr = kheap_alloc_tag_bt(OSMALLOC, size,
		    Z_WAITOK, VM_KERN_MEMORY_KALLOC);
	}

	if (!addr) {
		OSMalloc_Tagrele(tag);
	}

	return addr;
}

extern typeof(OSMalloc_nowait) OSMalloc_nowait_external;
void *
OSMalloc_nowait_external(uint32_t size, OSMallocTag tag)
{
	void    *addr = NULL;

	if (tag->OSMT_attr & OSMT_PAGEABLE) {
		return NULL;
	}

	OSMalloc_Tagref(tag);
	/* XXX: use non-blocking kalloc for now */
	addr = kheap_alloc_tag_bt(OSMALLOC, (vm_size_t)size,
	    Z_NOWAIT, VM_KERN_MEMORY_KALLOC);
	if (addr == NULL) {
		OSMalloc_Tagrele(tag);
	}

	return addr;
}

extern typeof(OSMalloc_noblock) OSMalloc_noblock_external;
void *
OSMalloc_noblock_external(uint32_t size, OSMallocTag tag)
{
	void    *addr = NULL;

	if (tag->OSMT_attr & OSMT_PAGEABLE) {
		return NULL;
	}

	OSMalloc_Tagref(tag);
	addr = kheap_alloc_tag_bt(OSMALLOC, (vm_size_t)size,
	    Z_NOWAIT, VM_KERN_MEMORY_KALLOC);
	if (addr == NULL) {
		OSMalloc_Tagrele(tag);
	}

	return addr;
}

extern typeof(OSFree) OSFree_external;
void
OSFree_external(void *addr, uint32_t size, OSMallocTag tag)
{
	if ((tag->OSMT_attr & OSMT_PAGEABLE)
	    && (size & ~PAGE_MASK)) {
		kmem_free(kernel_map, (vm_offset_t)addr, size);
	} else {
		kheap_free(OSMALLOC, addr, size);
	}

	OSMalloc_Tagrele(tag);
}

#pragma mark kern_os_malloc

void *
kern_os_malloc_external(size_t size);
void *
kern_os_malloc_external(size_t size)
{
	if (size == 0) {
		return NULL;
	}

	return kheap_alloc_tag_bt(KERN_OS_MALLOC, size, Z_WAITOK | Z_ZERO,
	           VM_KERN_MEMORY_LIBKERN);
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
	VM_ALLOC_SITE_STATIC(VM_TAG_BT, VM_KERN_MEMORY_LIBKERN);

	return kheap_realloc_addr(KERN_OS_MALLOC, addr, nsize,
	           Z_WAITOK | Z_ZERO, &site).addr;
}

void
kern_os_zfree(zone_t zone, void *addr, vm_size_t size)
{
	if (zsecurity_options & ZSECURITY_OPTIONS_STRICT_IOKIT_FREE
	    || zone_owns(zone, addr)) {
		zfree(zone, addr);
	} else {
		/*
		 * Third party kexts might not know about the operator new
		 * and be allocated from the KEXT heap
		 */
		printf("kern_os_zfree: kheap_free called for object from zone %s\n",
		    zone->z_name);
		kheap_free(KHEAP_KEXT, addr, size);
	}
}

void
kern_os_kfree(void *addr, vm_size_t size)
{
	if (zsecurity_options & ZSECURITY_OPTIONS_STRICT_IOKIT_FREE) {
		kheap_free(KHEAP_DEFAULT, addr, size);
	} else {
		/*
		 * Third party kexts may not know about newly added operator
		 * default new/delete. If they call new for any iokit object
		 * it will end up coming from the KEXT heap. If these objects
		 * are freed by calling release() or free(), the internal
		 * version of operator delete is called and the kernel ends
		 * up freeing the object to the DEFAULT heap.
		 */
		kheap_free(KHEAP_ANY, addr, size);
	}
}

bool
IOMallocType_from_vm(uint32_t kt_idx, uint32_t kt_size)
{
#if defined(__x86_64__) || !defined(__LP64__)
	/*
	 * Calliste that aren't in the BootKC for macOS and all callsites
	 * for armv7 are not procesed during startup, so use size to
	 * determine if the allocation will use the VM instead of slab.
	 */
	(void) kt_idx;
	return kt_size >= KHEAP_DEFAULT->kh_zones->kalloc_max;
#else
	(void) kt_size;
	return kt_idx == KALLOC_TYPE_IDX_MASK;
#endif
}

void
kern_os_typed_free(kalloc_type_view_t ktv, void *addr, vm_size_t esize)
{
	if ((zsecurity_options & ZSECURITY_OPTIONS_STRICT_IOKIT_FREE) == 0) {
		/*
		 * For third party kexts that have been compiled with sdk pre macOS 11,
		 * an allocation of an OSObject that is defined in xnu or first pary
		 * kexts, by directly calling new will lead to using the kext heap
		 * as it will call OSObject_operator_new_external. If this object
		 * is freed by xnu, it panics as xnu uses the typed free which
		 * requires the object to have been allocated in a kalloc.type zone.
		 * To workaround this issue, detect if the allocation being freed is
		 * from the kext heap and allow freeing to it.
		 */
		zone_id_t zid = zone_id_for_native_element(addr, esize);
		if (__probable(zid < MAX_ZONES)) {
			zone_security_flags_t zsflags = zone_security_array[zid];
			if (zsflags.z_kheap_id == KHEAP_ID_KEXT) {
				return kheap_free(KHEAP_KEXT, addr, esize);
			}
		}
	}
	kfree_type_impl_external(ktv, addr);
}

#if DEBUG || DEVELOPMENT
#include <sys/random.h>
/*
 * Ensure that the feature is on when the boot-arg is present.
 *
 * Note: Presence of zones with name kalloc.type* is used to
 * determine if the feature is on.
 */
static int
kalloc_type_feature_on(void)
{
	/*
	 * Boot-arg not present
	 */
	if (!(kt_options & KT_OPTIONS_ON)) {
		return 1;
	}

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
static int
kalloc_type_test_policy(int64_t in)
{
	uint16_t zone_budget = (uint16_t) in;
	uint16_t max_bucket_freq = 25;
	uint16_t freq_list[MAX_K_ZONE(k_zone_cfg)] = {};
	uint16_t zones_per_bucket[MAX_K_ZONE(k_zone_cfg)] = {};
	uint16_t random[MAX_K_ZONE(k_zone_cfg)];
	int ret = 0;

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
		if ((kt_options & KT_OPTIONS_ON) ||
		    (strncmp(kt_cur->kt_zv.zv_name, site_str, site_str_len) == 0)) {
			if (kalloc_type_get_size(kt_cur->kt_size) > elem_size) {
				return 0;
			}
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
	const char *kt_data_sig = __builtin_xnu_type_signature(
		struct test_kt_data);
	if (!kalloc_type_is_data(kt_data_sig)) {
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

static int
run_kalloc_test(int64_t in __unused, int64_t *out)
{
	*out = 0;
	uint64_t * data_ptr;
	size_t alloc_size, old_alloc_size;

	printf("%s: test running\n", __func__);

	alloc_size = sizeof(uint64_t) + 1;
	data_ptr = kalloc(alloc_size);
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
	    kalloc_bucket_size(KHEAP_DEFAULT, kr.size)
	    != kalloc_bucket_size(KHEAP_DEFAULT, old_alloc_size)) {
		printf("%s: same size class realloc failed\n", __func__);
		return 0;
	}

	old_alloc_size = alloc_size;
	alloc_size *= 2;
	kr = krealloc_ext(KHEAP_DEFAULT, kr.addr, old_alloc_size, alloc_size,
	    Z_WAITOK | Z_NOFAIL, NULL);
	if (!kr.addr || kalloc_bucket_size(KHEAP_DEFAULT, kr.size)
	    == kalloc_bucket_size(KHEAP_DEFAULT, old_alloc_size)) {
		printf("%s: new size class realloc failed\n", __func__);
		return 0;
	}

	old_alloc_size = alloc_size;
	alloc_size *= 2;
	data_ptr = kheap_realloc_addr(KHEAP_DEFAULT, kr.addr, alloc_size,
	    Z_WAITOK | Z_NOFAIL, NULL).addr;
	if (!data_ptr) {
		printf("%s: realloc without old size returned null\n", __func__);
		return 0;
	}
	kfree(data_ptr, alloc_size);

	alloc_size = 3544;
	data_ptr = kalloc(alloc_size);
	if (!data_ptr) {
		printf("%s: kalloc 3544 returned not null\n", __func__);
		return 0;
	}
	kfree(data_ptr, alloc_size);

	printf("%s: test passed\n", __func__);
	*out = 1;
	return 0;
}
SYSCTL_TEST_REGISTER(kalloc, run_kalloc_test);
#endif
