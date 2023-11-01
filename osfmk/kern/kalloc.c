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

#include "mach/vm_types.h"
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
#include <vm/vm_memtag.h>
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
 * The kt_zone_cfg table defines the configuration of zones on various
 * platforms for kalloc_type fixed size allocations.
 */

#if KASAN_CLASSIC
#define K_SIZE_CLASS(size)    \
	(((size) & PAGE_MASK) == 0 ? (size) : \
	((size) <= 1024 ? (size) : (size) - KASAN_GUARD_SIZE))
#else
#define K_SIZE_CLASS(size)    (size)
#endif
static_assert(K_SIZE_CLASS(KHEAP_MAX_SIZE) == KHEAP_MAX_SIZE);

static const uint16_t kt_zone_cfg[] = {
	K_SIZE_CLASS(16),
	K_SIZE_CLASS(32),
	K_SIZE_CLASS(48),
	K_SIZE_CLASS(64),
	K_SIZE_CLASS(80),
	K_SIZE_CLASS(96),
	K_SIZE_CLASS(128),
	K_SIZE_CLASS(160),
	K_SIZE_CLASS(192),
	K_SIZE_CLASS(224),
	K_SIZE_CLASS(256),
	K_SIZE_CLASS(288),
	K_SIZE_CLASS(368),
	K_SIZE_CLASS(400),
	K_SIZE_CLASS(512),
	K_SIZE_CLASS(576),
	K_SIZE_CLASS(768),
	K_SIZE_CLASS(1024),
	K_SIZE_CLASS(1152),
	K_SIZE_CLASS(1280),
	K_SIZE_CLASS(1664),
	K_SIZE_CLASS(2048),
	K_SIZE_CLASS(4096),
	K_SIZE_CLASS(6144),
	K_SIZE_CLASS(8192),
	K_SIZE_CLASS(12288),
	K_SIZE_CLASS(16384),
#if __arm64__
	K_SIZE_CLASS(24576),
	K_SIZE_CLASS(32768),
#endif /* __arm64__ */
};

#define MAX_K_ZONE(kzc) (uint32_t)(sizeof(kzc) / sizeof(kzc[0]))

/*
 * kalloc_type callsites are assigned a zone during early boot. They
 * use the dlut[] (direct lookup table), indexed by size normalized
 * to the minimum alignment to find the right zone index quickly.
 */
#define INDEX_ZDLUT(size)       (((size) + KALLOC_MINALIGN - 1) / KALLOC_MINALIGN)
#define KALLOC_DLUT_SIZE        (KHEAP_MAX_SIZE / KALLOC_MINALIGN)
#define MAX_SIZE_ZDLUT          ((KALLOC_DLUT_SIZE - 1) * KALLOC_MINALIGN)
static __startup_data uint8_t   kalloc_type_dlut[KALLOC_DLUT_SIZE];
static __startup_data uint32_t  kheap_zsize[KHEAP_NUM_ZONES];

#if VM_TAG_SIZECLASSES
static_assert(VM_TAG_SIZECLASSES >= MAX_K_ZONE(kt_zone_cfg));
#endif

const char * const kalloc_heap_names[] = {
	[KHEAP_ID_NONE]          = "",
	[KHEAP_ID_SHARED]        = "shared.",
	[KHEAP_ID_DATA_BUFFERS]  = "data.",
	[KHEAP_ID_KT_VAR]        = "",
};

/*
 * Shared heap configuration
 */
SECURITY_READ_ONLY_LATE(struct kalloc_heap) KHEAP_SHARED[1] = {
	{
		.kh_name     = "shared.kalloc",
		.kh_heap_id  = KHEAP_ID_SHARED,
		.kh_tag      = VM_KERN_MEMORY_KALLOC_TYPE,
	}
};

/*
 * Bag of bytes heap configuration
 */
SECURITY_READ_ONLY_LATE(struct kalloc_heap) KHEAP_DATA_BUFFERS[1] = {
	{
		.kh_name     = "data.kalloc",
		.kh_heap_id  = KHEAP_ID_DATA_BUFFERS,
		.kh_tag      = VM_KERN_MEMORY_KALLOC_DATA,
	}
};

/*
 * Configuration of variable kalloc type heaps
 */
SECURITY_READ_ONLY_LATE(struct kheap_info)
kalloc_type_heap_array[KT_VAR_MAX_HEAPS] = {};
SECURITY_READ_ONLY_LATE(struct kalloc_heap) KHEAP_KT_VAR[1] = {
	{
		.kh_name     = "kalloc.type.var",
		.kh_heap_id  = KHEAP_ID_KT_VAR,
		.kh_tag      = VM_KERN_MEMORY_KALLOC_TYPE
	}
};

KALLOC_HEAP_DEFINE(KHEAP_DEFAULT, "KHEAP_DEFAULT", KHEAP_ID_KT_VAR);

__startup_func
static void
kalloc_zsize_compute(void)
{
	uint32_t step = KHEAP_STEP_START;
	uint32_t size = KHEAP_START_SIZE;

	/*
	 * Manually initialize extra initial zones
	 */
	kheap_zsize[0] = size / 2;
	kheap_zsize[1] = size;
	static_assert(KHEAP_EXTRA_ZONES == 2);

	/*
	 * Compute sizes for remaining zones
	 */
	for (uint32_t i = 0; i < KHEAP_NUM_STEPS; i++) {
		uint32_t step_idx = (i * 2) + KHEAP_EXTRA_ZONES;

		kheap_zsize[step_idx] = K_SIZE_CLASS(size + step);
		kheap_zsize[step_idx + 1] = K_SIZE_CLASS(size + 2 * step);

		step *= 2;
		size += step;
	}
}

static zone_t
kalloc_zone_for_size_with_flags(
	zone_id_t               zid,
	vm_size_t               size,
	zalloc_flags_t          flags)
{
	vm_size_t max_size = KHEAP_MAX_SIZE;
	bool forcopyin = flags & Z_MAY_COPYINMAP;
	zone_t zone;

	if (flags & Z_KALLOC_ARRAY) {
		size = roundup(size, KALLOC_ARRAY_GRANULE);
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
		uint32_t idx;

		if (size <= KHEAP_START_SIZE) {
			zid  += (size > 16);
		} else {
			/*
			 * . log2down(size - 1) is log2up(size) - 1
			 * . (size - 1) >> (log2down(size - 1) - 1)
			 *   is either 0x2 or 0x3
			 */
			idx   = kalloc_log2down((uint32_t)(size - 1));
			zid  += KHEAP_EXTRA_ZONES +
			    2 * (idx - KHEAP_START_IDX) +
			    ((uint32_t)(size - 1) >> (idx - 1)) - 2;
		}

		zone = zone_by_id(zid);
#if KASAN_CLASSIC
		/*
		 * Under kasan classic, certain size classes are a redzone
		 * away from the mathematical formula above, and we need
		 * to "go to the next zone".
		 *
		 * Because the KHEAP_MAX_SIZE bucket _does_ exist however,
		 * this will never go to an "invalid" zone that doesn't
		 * belong to the kheap.
		 */
		if (size > zone_elem_inner_size(zone)) {
			zone++;
		}
#endif
		return zone;
	}

	return ZONE_NULL;
}

zone_t
kalloc_zone_for_size(zone_id_t zid, size_t size)
{
	return kalloc_zone_for_size_with_flags(zid, size, Z_WAITOK);
}

static inline bool
kheap_size_from_zone(
	void                   *addr,
	vm_size_t               size,
	zalloc_flags_t          flags)
{
	vm_size_t max_size = KHEAP_MAX_SIZE;
	bool forcopyin = flags & Z_MAY_COPYINMAP;

#if __x86_64__
	/*
	 * If Z_FULLSIZE is used, then due to kalloc_zone_for_size_with_flags()
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

/*
 * All data zones shouldn't use shared zone. Therefore set the no share
 * bit right after creation.
 */
__startup_func
static void
kalloc_set_no_share_for_data(
	zone_kheap_id_t       kheap_id,
	zone_stats_t          zstats)
{
	if (kheap_id == KHEAP_ID_DATA_BUFFERS) {
		zpercpu_foreach(zs, zstats) {
			os_atomic_store(&zs->zs_alloc_not_shared, 1, relaxed);
		}
	}
}

__startup_func
static void
kalloc_zone_init(
	const char           *kheap_name,
	zone_kheap_id_t       kheap_id,
	zone_id_t            *kheap_zstart,
	zone_create_flags_t   zc_flags)
{
	zc_flags |= ZC_PGZ_USE_GUARDS;

	for (uint32_t i = 0; i < KHEAP_NUM_ZONES; i++) {
		uint32_t size = kheap_zsize[i];
		char buf[MAX_ZONE_NAME], *z_name;
		int len;

		len = scnprintf(buf, MAX_ZONE_NAME, "%s.%u", kheap_name, size);
		z_name = zalloc_permanent(len + 1, ZALIGN_NONE);
		strlcpy(z_name, buf, len + 1);

		(void)zone_create_ext(z_name, size, zc_flags, ZONE_ID_ANY, ^(zone_t z){
#if __arm64e__ || CONFIG_KERNEL_TAGGING
			uint32_t scale = kalloc_log2down(size / 32);

			if (size == 32 << scale) {
			        z->z_array_size_class = scale;
			} else {
			        z->z_array_size_class = scale | 0x10;
			}
#endif
			zone_security_array[zone_index(z)].z_kheap_id = kheap_id;
			if (i == 0) {
			        *kheap_zstart = zone_index(z);
			}
			kalloc_set_no_share_for_data(kheap_id, z->z_stats);
		});
	}
}

__startup_func
static void
kalloc_heap_init(struct kalloc_heap *kheap)
{
	kalloc_zone_init("kalloc", kheap->kh_heap_id, &kheap->kh_zstart,
	    ZC_NONE);
	/*
	 * Count all the "raw" views for zones in the heap.
	 */
	zone_view_count += KHEAP_NUM_ZONES;
}

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

TUNABLE(kalloc_type_options_t, kt_options, "kt", 0);
TUNABLE(uint16_t, kt_var_heaps, "kt_var_heaps",
    ZSECURITY_CONFIG_KT_VAR_BUDGET);
TUNABLE(uint16_t, kt_fixed_zones, "kt_fixed_zones",
    ZSECURITY_CONFIG_KT_BUDGET);
TUNABLE(uint16_t, kt_var_ptr_heaps, "kt_var_ptr_heaps", 2);
static TUNABLE(bool, kt_shared_fixed, "-kt-shared", true);

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

__startup_data
static kalloc_type_views_t *kt_buffer = NULL;
__startup_data
static uint64_t kt_count;
__startup_data
uint32_t kalloc_type_hash_seed;

__startup_data
static uint16_t kt_freq_list[MAX_K_ZONE(kt_zone_cfg)];
__startup_data
static uint16_t kt_freq_list_total[MAX_K_ZONE(kt_zone_cfg)];

struct nzones_with_idx {
	uint16_t nzones;
	uint16_t idx;
};
int16_t zone_carry = 0;

_Static_assert(__builtin_popcount(KT_SUMMARY_MASK_TYPE_BITS) == (KT_GRANULE_MAX + 1),
    "KT_SUMMARY_MASK_TYPE_BITS doesn't match KT_GRANULE_MAX");

/*
 * For use by lldb to iterate over kalloc types
 */
SECURITY_READ_ONLY_LATE(uint64_t) num_kt_sizeclass = MAX_K_ZONE(kt_zone_cfg);
SECURITY_READ_ONLY_LATE(zone_t) kalloc_type_zarray[MAX_K_ZONE(kt_zone_cfg)];
SECURITY_READ_ONLY_LATE(zone_t) kt_singleton_array[MAX_K_ZONE(kt_zone_cfg)];

#define KT_GET_HASH(flags) (uint16_t)((flags & KT_HASH) >> 16)
static_assert(KT_HASH >> 16 == (KMEM_RANGE_MASK | KMEM_HASH_SET |
    KMEM_DIRECTION_MASK),
    "Insufficient bits to represent range and dir for VM allocations");
static_assert(MAX_K_ZONE(kt_zone_cfg) < KALLOC_TYPE_IDX_MASK,
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

static void
kalloc_type_build_dlut(void)
{
	vm_size_t size = 0;
	for (int i = 0; i < KALLOC_DLUT_SIZE; i++, size += KALLOC_MINALIGN) {
		uint8_t zindex = 0;
		while (kt_zone_cfg[zindex] < size) {
			zindex++;
		}
		kalloc_type_dlut[i] = zindex;
	}
}

static uint32_t
kalloc_type_idx_for_size(uint32_t size)
{
	assert(size <= KHEAP_MAX_SIZE);
	uint16_t idx = kalloc_type_dlut[INDEX_ZDLUT(size)];
	return kalloc_type_set_idx(size, idx);
}

static void
kalloc_type_assign_zone_fixed(
	kalloc_type_view_t     *cur,
	kalloc_type_view_t     *end,
	zone_t                  z,
	zone_t                  sig_zone,
	zone_t                  shared_zone)
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
		zone_security_flags_t zsflags = zone_security_config(z);

		assert(kalloc_type_get_size(kt->kt_size) <= z->z_elem_size);
		if (!shared_zone) {
			assert(zsflags.z_kheap_id == KHEAP_ID_DATA_BUFFERS);
		}

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

		if ((kt_flags & KT_NOSHARED) || !shared_zone) {
			if ((kt_flags & KT_NOSHARED) && !(kt_flags & KT_PRIV_ACCT)) {
				panic("KT_NOSHARED used w/o private accounting for view %s",
				    zv->zv_name);
			}

			zpercpu_foreach(zs, zv->zv_stats) {
				os_atomic_store(&zs->zs_alloc_not_shared, 1, relaxed);
			}
		}

		if (zsflags.z_kheap_id != KHEAP_ID_DATA_BUFFERS) {
			kt->kt_zshared = shared_zone;
			kt->kt_zsig = sig_zone;
			/*
			 * If we haven't yet set the signature equivalance then set it
			 * otherwise validate that the zone has the same signature equivalance
			 * as the sig_zone provided
			 */
			if (!zone_get_sig_eq(z)) {
				zone_set_sig_eq(z, zone_index(sig_zone));
			} else {
				assert(zone_get_sig_eq(z) == zone_get_sig_eq(sig_zone));
			}
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
	struct kheap_info *cfg = &kalloc_type_heap_array[heap_idx];
	while (cur < end) {
		kalloc_type_var_view_t kt = *cur;
		kt->kt_heap_start = cfg->kh_zstart;
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

		kt->kt_next = (zone_view_t) cfg->kt_views;
		cfg->kt_views = kt;
		cur++;
	}
}

__startup_func
static inline void
kalloc_type_slide_fixed(vm_offset_t addr)
{
	kalloc_type_view_t ktv = (struct kalloc_type_view *) addr;
	ktv->kt_signature += vm_kernel_slide;
	ktv->kt_zv.zv_name += vm_kernel_slide;
	ktv->kt_flags |= KT_SLID;
}

__startup_func
static inline void
kalloc_type_slide_var(vm_offset_t addr)
{
	kalloc_type_var_view_t ktv = (struct kalloc_type_var_view *) addr;
	if (ktv->kt_sig_hdr) {
		ktv->kt_sig_hdr += vm_kernel_slide;
	}
	ktv->kt_sig_type += vm_kernel_slide;
	ktv->kt_name += vm_kernel_slide;
	ktv->kt_flags |= KT_SLID;
}

__startup_func
static void
kalloc_type_validate_flags(
	kalloc_type_flags_t   kt_flags,
	const char           *kt_name,
	uuid_string_t         kext_uuid)
{
	if (!(kt_flags & KT_CHANGED) || !(kt_flags & KT_CHANGED2)) {
		panic("kalloc_type_view(%s) from kext(%s) hasn't been rebuilt with "
		    "required xnu headers", kt_name, kext_uuid);
	}
}

static kalloc_type_flags_t
kalloc_type_get_flags_fixed(vm_offset_t addr, uuid_string_t kext_uuid)
{
	kalloc_type_view_t ktv = (kalloc_type_view_t) addr;
	kalloc_type_validate_flags(ktv->kt_flags, ktv->kt_zv.zv_name, kext_uuid);
	return ktv->kt_flags;
}

static kalloc_type_flags_t
kalloc_type_get_flags_var(vm_offset_t addr, uuid_string_t kext_uuid)
{
	kalloc_type_var_view_t ktv = (kalloc_type_var_view_t) addr;
	kalloc_type_validate_flags(ktv->kt_flags, ktv->kt_name, kext_uuid);
	return ktv->kt_flags;
}

/*
 * Check if signature of type is made up of only data and padding
 */
static bool
kalloc_type_is_data(kalloc_type_flags_t kt_flags)
{
	assert(kt_flags & KT_CHANGED);
	return kt_flags & KT_DATA_ONLY;
}

/*
 * Check if signature of type is made up of only pointers
 */
static bool
kalloc_type_is_ptr_array(kalloc_type_flags_t kt_flags)
{
	assert(kt_flags & KT_CHANGED2);
	return kt_flags & KT_PTR_ARRAY;
}

static bool
kalloc_type_from_vm(kalloc_type_flags_t kt_flags)
{
	assert(kt_flags & KT_CHANGED);
	return kt_flags & KT_VM;
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
	zone_t z = kalloc_zone_for_size(KHEAP_DATA_BUFFERS->kh_zstart,
	    cur_data_view->kt_size);
	kalloc_type_assign_zone_fixed(&cur_data_view, &cur_data_view + 1, z, NULL,
	    NULL);
}

__startup_func
static void
kalloc_type_handle_data_view_var(vm_offset_t addr)
{
	kalloc_type_var_view_t ktv = (kalloc_type_var_view_t) addr;
	kalloc_type_assign_zone_var(&ktv, &ktv + 1, KT_VAR_DATA_HEAP);
}

__startup_func
static uint32_t
kalloc_type_handle_parray_var(void)
{
	uint32_t i = 0;
	kalloc_type_var_view_t kt = kt_buffer[0].ktv_var;
	const char *p_name = kt->kt_name;

	/*
	 * The sorted list of variable kalloc_type_view has pointer arrays at the
	 * beginning. Walk through them and assign a random pointer heap to each
	 * type detected by typename.
	 */
	while (kalloc_type_is_ptr_array(kt->kt_flags)) {
		uint32_t heap_id = kmem_get_random16(1) + KT_VAR_PTR_HEAP0;
		const char *c_name = kt->kt_name;
		uint32_t p_i = i;

		while (strcmp(c_name, p_name) == 0) {
			i++;
			kt = kt_buffer[i].ktv_var;
			c_name = kt->kt_name;
		}
		p_name = c_name;
		kalloc_type_assign_zone_var(&kt_buffer[p_i].ktv_var,
		    &kt_buffer[i].ktv_var, heap_id);
	}

	/*
	 * Returns the the index of the first view that isn't a pointer array
	 */
	return i;
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
	ktv->kt_size = kalloc_type_idx_for_size(ktv->kt_size);
}

__startup_func
static void
kalloc_type_update_view_var(vm_offset_t addr)
{
	(void) addr;
}

__startup_func
static void
kalloc_type_view_copy(
	const kalloc_type_variant_t   type,
	vm_offset_t                   start,
	vm_offset_t                   end,
	uint64_t                     *cur_count,
	bool                          slide,
	uuid_string_t                 kext_uuid)
{
	uint64_t count = kalloc_type_view_count(type, start, end);
	if (count + *cur_count >= kt_count) {
		panic("kalloc_type_view_copy: Insufficient space in scratch buffer");
	}
	vm_offset_t cur = start;
	while (cur < end) {
		if (slide) {
			kalloc_type_func(type, slide, cur);
		}
		kalloc_type_flags_t kt_flags = kalloc_type_func(type, get_flags, cur,
		    kext_uuid);
		kalloc_type_func(type, mark_processed, cur);
		/*
		 * Skip views that go to the VM
		 */
		if (kalloc_type_from_vm(kt_flags)) {
			cur += kalloc_type_func(type, view_sz);
			continue;
		}

		/*
		 * If signature indicates that the entire allocation is data move it to
		 * KHEAP_DATA_BUFFERS. Note that KT_VAR_DATA_HEAP is a fake "data" heap,
		 * variable kalloc_type handles the actual redirection in the entry points
		 * kalloc/kfree_type_var_impl.
		 */
		if (kalloc_type_is_data(kt_flags)) {
			kalloc_type_func(type, handle_data_view, cur);
			cur += kalloc_type_func(type, view_sz);
			continue;
		}

		/*
		 * Set type hash that is used by kmem_*_guard
		 */
		kalloc_type_func(type, set_type_hash, cur);
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
		    &cur_count, false, NULL);
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
				unsigned long uuidlen = 0;
				void *kext_uuid = getuuidfromheader(kext_mh, &uuidlen);
				uuid_string_t kext_uuid_str;
				if ((kext_uuid != NULL) && (uuidlen == sizeof(uuid_t))) {
					uuid_unparse_upper(*(uuid_t *)kext_uuid, kext_uuid_str);
				}
				kalloc_type_view_copy(type, sect->addr, sect->addr + sect->size,
				    &cur_count, false, kext_uuid_str);
			}
		}
	} else if (kc_format == KCFormatKCGEN) {
		/*
		 * Parse __kalloc_type section from xnu
		 */
		kalloc_type_view_copy(type,
		    kalloc_type_var(type, sec_start),
		    kalloc_type_var(type, sec_end), &cur_count, false, NULL);

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
						    true, NULL);
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
	bool ktA_ptrArray = kalloc_type_is_ptr_array(ktA->kt_flags);
	bool ktB_ptrArray = kalloc_type_is_ptr_array(ktA->kt_flags);
	int result = 0;

	/*
	 * Switched around (B - A) because we want the pointer arrays to be at the
	 * top
	 */
	result = ktB_ptrArray - ktA_ptrArray;
	if (result == 0) {
		result = strcmp(ktA_hdr, ktB_hdr);
		if (result == 0) {
			result = strcmp(ktA->kt_sig_type, ktB->kt_sig_type);
			if (result == 0) {
				result = strcmp(ktA->kt_name, ktB->kt_name);
			}
		}
	}
	return result;
}

__startup_func
static uint16_t *
kalloc_type_create_iterators_fixed(
	uint16_t           *kt_skip_list_start,
	uint64_t            count)
{
	uint16_t *kt_skip_list = kt_skip_list_start;
	uint16_t p_idx = UINT16_MAX; /* previous size idx */
	uint16_t c_idx = 0; /* current size idx */
	uint16_t unique_sig = 0;
	uint16_t total_sig = 0;
	const char *p_sig = NULL;
	const char *p_name = "";
	const char *c_sig = NULL;
	const char *c_name = NULL;

	/*
	 * Walk over each kalloc_type_view
	 */
	for (uint16_t i = 0; i < count; i++) {
		kalloc_type_view_t kt = kt_buffer[i].ktv_fixed;

		c_idx = kalloc_type_get_idx(kt->kt_size);
		c_sig = kt->kt_signature;
		c_name = kt->kt_zv.zv_name;
		/*
		 * When current kalloc_type_view is in a different kalloc size
		 * bucket than the previous, it means we have processed all in
		 * the previous size bucket, so store the accumulated values
		 * and advance the indices.
		 */
		if (p_idx == UINT16_MAX || c_idx != p_idx) {
			/*
			 * Updates for frequency lists
			 */
			if (p_idx != UINT16_MAX) {
				kt_freq_list[p_idx] = unique_sig;
				kt_freq_list_total[p_idx] = total_sig - unique_sig;
			}
			unique_sig = 1;
			total_sig = 1;

			p_idx = c_idx;
			p_sig = c_sig;
			p_name = c_name;

			/*
			 * Updates to signature skip list
			 */
			*kt_skip_list = i;
			kt_skip_list++;

			continue;
		}

		/*
		 * When current kalloc_type_views is in the kalloc size bucket as
		 * previous, analyze the siganture to see if it is unique.
		 *
		 * Signatures are collapsible if one is a substring of the next.
		 */
		if (strncmp(c_sig, p_sig, strlen(p_sig)) != 0) {
			/*
			 * Unique signature detected. Update counts and advance index
			 */
			unique_sig++;
			total_sig++;

			*kt_skip_list = i;
			kt_skip_list++;
			p_sig = c_sig;
			p_name = c_name;
			continue;
		}
		/*
		 * Need this here as we do substring matching for signatures so you
		 * want to track the longer signature seen rather than the substring
		 */
		p_sig = c_sig;

		/*
		 * Check if current kalloc_type_view corresponds to a new type
		 */
		if (strlen(p_name) != strlen(c_name) || strcmp(p_name, c_name) != 0) {
			total_sig++;
			p_name = c_name;
		}
	}
	/*
	 * Final update
	 */
	assert(c_idx == p_idx);
	assert(kt_freq_list[c_idx] == 0);
	kt_freq_list[c_idx] = unique_sig;
	kt_freq_list_total[c_idx] = total_sig - unique_sig;
	*kt_skip_list = (uint16_t) count;

	return ++kt_skip_list;
}

__startup_func
static uint32_t
kalloc_type_create_iterators_var(
	uint32_t           *kt_skip_list_start,
	uint32_t            buf_start)
{
	uint32_t *kt_skip_list = kt_skip_list_start;
	uint32_t n = 0;

	kt_skip_list[n] = buf_start;
	assert(kt_count > buf_start + 1);
	for (uint32_t i = buf_start + 1; i < kt_count; i++) {
		kalloc_type_var_view_t ktA = kt_buffer[i - 1].ktv_var;
		kalloc_type_var_view_t ktB = kt_buffer[i].ktv_var;
		const char *ktA_hdr = ktA->kt_sig_hdr ?: "";
		const char *ktB_hdr = ktB->kt_sig_hdr ?: "";
		assert(ktA->kt_sig_type != NULL);
		assert(ktB->kt_sig_type != NULL);
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
kalloc_type_distribute_budget(
	uint16_t            freq_list[MAX_K_ZONE(kt_zone_cfg)],
	uint16_t            kt_zones[MAX_K_ZONE(kt_zone_cfg)],
	uint16_t            zone_budget,
	uint16_t            min_zones_per_size)
{
	uint16_t total_sig = 0;
	uint16_t min_sig = 0;
	uint16_t assigned_zones = 0;
	uint16_t remaining_zones = zone_budget;
	uint16_t modulo = 0;

	for (uint16_t i = 0; i < MAX_K_ZONE(kt_zone_cfg); i++) {
		uint16_t sig_freq = freq_list[i];
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

	for (uint16_t i = 0; i < MAX_K_ZONE(kt_zone_cfg); i++) {
		uint16_t freq = freq_list[i];

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
static int
kalloc_type_cmp_type_zones(const void *a, const void *b)
{
	const struct nzones_with_idx A = *(const struct nzones_with_idx *)a;
	const struct nzones_with_idx B = *(const struct nzones_with_idx *)b;

	return (int)(B.nzones - A.nzones);
}

__startup_func
static void
kalloc_type_redistribute_budget(
	uint16_t            freq_total_list[MAX_K_ZONE(kt_zone_cfg)],
	uint16_t            kt_zones[MAX_K_ZONE(kt_zone_cfg)])
{
	uint16_t count = 0, cur_count = 0;
	struct nzones_with_idx sorted_zones[MAX_K_ZONE(kt_zone_cfg)] = {};
	uint16_t top_zone_total = 0;

	for (uint16_t i = 0; i < MAX_K_ZONE(kt_zone_cfg); i++) {
		uint16_t zones = kt_zones[i];

		/*
		 * If a sizeclass got no zones but has types to divide make a note
		 * of it
		 */
		if (zones == 0 && (freq_total_list[i] != 0)) {
			count++;
		}

		sorted_zones[i].nzones = kt_zones[i];
		sorted_zones[i].idx = i;
	}

	qsort(&sorted_zones[0], (size_t) MAX_K_ZONE(kt_zone_cfg),
	    sizeof(struct nzones_with_idx), kalloc_type_cmp_type_zones);

	for (uint16_t i = 0; i < 3; i++) {
		top_zone_total += sorted_zones[i].nzones;
	}

	/*
	 * Borrow zones from the top 3 sizeclasses and redistribute to those
	 * that didn't get a zone but that types to divide
	 */
	cur_count = count;
	for (uint16_t i = 0; i < 3; i++) {
		uint16_t zone_borrow = (sorted_zones[i].nzones * count) / top_zone_total;
		uint16_t zone_available = kt_zones[sorted_zones[i].idx];

		if (zone_borrow > (zone_available / 2)) {
			zone_borrow = zone_available / 2;
		}
		kt_zones[sorted_zones[i].idx] -= zone_borrow;
		cur_count -= zone_borrow;
	}

	for (uint16_t i = 0; i < 3; i++) {
		if (cur_count == 0) {
			break;
		}
		kt_zones[sorted_zones[i].idx]--;
		cur_count--;
	}

	for (uint16_t i = 0; i < MAX_K_ZONE(kt_zone_cfg); i++) {
		if (kt_zones[i] == 0 && (freq_total_list[i] != 0) &&
		    (count > cur_count)) {
			kt_zones[i]++;
			count--;
		}
	}
}

static uint16_t
kalloc_type_apply_policy(
	uint16_t            freq_list[MAX_K_ZONE(kt_zone_cfg)],
	uint16_t            freq_total_list[MAX_K_ZONE(kt_zone_cfg)],
	uint16_t            kt_zones_sig[MAX_K_ZONE(kt_zone_cfg)],
	uint16_t            kt_zones_type[MAX_K_ZONE(kt_zone_cfg)],
	uint16_t            zone_budget)
{
	uint16_t zbudget_sig = (uint16_t) ((7 * zone_budget) / 10);
	uint16_t zbudget_type = zone_budget - zbudget_sig;
	uint16_t wasted_zones = 0;

#if DEBUG || DEVELOPMENT
	if (startup_phase < STARTUP_SUB_LOCKDOWN) {
		uint16_t current_zones = os_atomic_load(&num_zones, relaxed);

		assert(zone_budget + current_zones <= MAX_ZONES);
	}
#endif

	wasted_zones += kalloc_type_distribute_budget(freq_list, kt_zones_sig,
	    zbudget_sig, 2);
	wasted_zones += kalloc_type_distribute_budget(freq_total_list,
	    kt_zones_type, zbudget_type, 0);
	kalloc_type_redistribute_budget(freq_total_list, kt_zones_type);

	/*
	 * Print stats when KT_OPTIONS_DEBUG boot-arg present
	 */
	if (kt_options & KT_OPTIONS_DEBUG) {
		printf("Size\ttotal_sig\tunique_signatures\tzones\tzones_sig\t"
		    "zones_type\n");
		for (uint16_t i = 0; i < MAX_K_ZONE(kt_zone_cfg); i++) {
			printf("%u\t%u\t%u\t%u\t%u\t%u\n", kt_zone_cfg[i],
			    freq_total_list[i] + freq_list[i], freq_list[i],
			    kt_zones_sig[i] + kt_zones_type[i],
			    kt_zones_sig[i], kt_zones_type[i]);
		}
	}

	return wasted_zones;
}


__startup_func
static void
kalloc_type_create_zone_for_size(
	zone_t             *kt_zones_for_size,
	uint16_t            kt_zones,
	vm_size_t           z_size)
{
	zone_t p_zone = NULL;
	char *z_name = NULL;
	zone_t shared_z = NULL;

	for (uint16_t i = 0; i < kt_zones; i++) {
		z_name = zalloc_permanent(MAX_ZONE_NAME, ZALIGN_NONE);
		snprintf(z_name, MAX_ZONE_NAME, "kalloc.type%u.%zu", i,
		    (size_t) z_size);
		zone_t z = zone_create(z_name, z_size, ZC_KALLOC_TYPE);
		if (i != 0) {
			p_zone->z_kt_next = z;
		}
		p_zone = z;
		kt_zones_for_size[i] = z;
	}
	/*
	 * Create shared zone for sizeclass if it doesn't already exist
	 */
	if (kt_shared_fixed) {
		shared_z = kalloc_zone_for_size(KHEAP_SHARED->kh_zstart, z_size);
		if (zone_elem_inner_size(shared_z) != z_size) {
			z_name = zalloc_permanent(MAX_ZONE_NAME, ZALIGN_NONE);
			snprintf(z_name, MAX_ZONE_NAME, "kalloc.%zu",
			    (size_t) z_size);
			shared_z = zone_create_ext(z_name, z_size, ZC_NONE, ZONE_ID_ANY,
			    ^(zone_t zone){
				zone_security_array[zone_index(zone)].z_kheap_id = KHEAP_ID_SHARED;
			});
		}
	}
	kt_zones_for_size[kt_zones] = shared_z;
}

__startup_func
static uint16_t
kalloc_type_zones_for_type(
	uint16_t            zones_total_type,
	uint16_t            unique_types,
	uint16_t            total_types,
	bool                last_sig)
{
	uint16_t zones_for_type = 0, n_mod = 0;

	if (zones_total_type == 0) {
		return 0;
	}

	zones_for_type = (zones_total_type * unique_types) / total_types;
	n_mod = (zones_total_type * unique_types) % total_types;
	zone_carry += n_mod;

	/*
	 * Drain carry opportunistically
	 */
	if (((unique_types > 3) && (zone_carry > 0)) ||
	    (zone_carry >= (int) total_types) ||
	    (last_sig && (zone_carry > 0))) {
		zone_carry -= total_types;
		zones_for_type++;
	}

	if (last_sig) {
		assert(zone_carry == 0);
	}

	return zones_for_type;
}

__startup_func
static uint16_t
kalloc_type_build_skip_list(
	kalloc_type_view_t     *start,
	kalloc_type_view_t     *end,
	uint16_t               *kt_skip_list)
{
	kalloc_type_view_t *cur = start;
	kalloc_type_view_t prev = *start;
	uint16_t i = 0, idx = 0;

	kt_skip_list[idx] = i;
	idx++;

	while (cur < end) {
		kalloc_type_view_t kt_cur = *cur;

		if (strcmp(prev->kt_zv.zv_name, kt_cur->kt_zv.zv_name) != 0) {
			kt_skip_list[idx] = i;

			prev = kt_cur;
			idx++;
		}
		i++;
		cur++;
	}

	/*
	 * Final update
	 */
	kt_skip_list[idx] = i;
	return idx;
}

__startup_func
static void
kalloc_type_init_sig_eq(
	zone_t             *zones,
	uint16_t            n_zones,
	zone_t              sig_zone)
{
	for (uint16_t i = 0; i < n_zones; i++) {
		zone_t z = zones[i];

		assert(!zone_get_sig_eq(z));
		zone_set_sig_eq(z, zone_index(sig_zone));
	}
}

__startup_func
static uint16_t
kalloc_type_distribute_zone_for_type(
	kalloc_type_view_t *start,
	kalloc_type_view_t *end,
	bool                last_sig,
	uint16_t            zones_total_type,
	uint16_t            total_types,
	uint16_t           *kt_skip_list,
	zone_t              kt_zones_for_size[32],
	uint16_t            type_zones_start,
	zone_t              sig_zone,
	zone_t              shared_zone)
{
	uint16_t count = 0, n_zones = 0;
	uint16_t *shuffle_buf = NULL;
	zone_t *type_zones = &kt_zones_for_size[type_zones_start];

	/*
	 * Assert there is space in buffer
	 */
	count = kalloc_type_build_skip_list(start, end, kt_skip_list);
	n_zones = kalloc_type_zones_for_type(zones_total_type, count, total_types,
	    last_sig);
	shuffle_buf = &kt_skip_list[count + 1];

	/*
	 * Initalize signature equivalence zone for type zones
	 */
	kalloc_type_init_sig_eq(type_zones, n_zones, sig_zone);

	if (n_zones == 0) {
		kalloc_type_assign_zone_fixed(start, end, sig_zone, sig_zone,
		    shared_zone);
		return n_zones;
	}

	/*
	 * Don't shuffle in the sig_zone if there is only 1 type in the zone
	 */
	if (count == 1) {
		kalloc_type_assign_zone_fixed(start, end, type_zones[0], sig_zone,
		    shared_zone);
		return n_zones;
	}

	/*
	 * Add the signature based zone to n_zones
	 */
	n_zones++;

	for (uint16_t i = 0; i < count; i++) {
		uint16_t zidx = i % n_zones, shuffled_zidx = 0;
		uint16_t type_start = kt_skip_list[i];
		kalloc_type_view_t *kt_type_start = &start[type_start];
		uint16_t type_end = kt_skip_list[i + 1];
		kalloc_type_view_t *kt_type_end = &start[type_end];
		zone_t zone;

		if (zidx == 0) {
			kmem_shuffle(shuffle_buf, n_zones);
		}

		shuffled_zidx = shuffle_buf[zidx];
		zone = shuffled_zidx == 0 ? sig_zone : type_zones[shuffled_zidx - 1];
		kalloc_type_assign_zone_fixed(kt_type_start, kt_type_end, zone, sig_zone,
		    shared_zone);
	}

	return n_zones - 1;
}

__startup_func
static void
kalloc_type_create_zones_fixed(
	uint16_t           *kt_skip_list_start,
	uint16_t           *kt_shuffle_buf)
{
	uint16_t *kt_skip_list = kt_skip_list_start;
	uint16_t p_j = 0;
	uint16_t kt_zones_sig[MAX_K_ZONE(kt_zone_cfg)] = {};
	uint16_t kt_zones_type[MAX_K_ZONE(kt_zone_cfg)] = {};
#if DEBUG || DEVELOPMENT
	uint64_t kt_shuffle_count = ((vm_address_t) kt_shuffle_buf -
	    (vm_address_t) kt_buffer) / sizeof(uint16_t);
#endif
	/*
	 * Apply policy to determine how many zones to create for each size
	 * class.
	 */
	kalloc_type_apply_policy(kt_freq_list, kt_freq_list_total,
	    kt_zones_sig, kt_zones_type, kt_fixed_zones);

	for (uint16_t i = 0; i < MAX_K_ZONE(kt_zone_cfg); i++) {
		uint16_t n_unique_sig = kt_freq_list[i];
		vm_size_t z_size = kt_zone_cfg[i];
		uint16_t n_zones_sig = kt_zones_sig[i];
		uint16_t n_zones_type = kt_zones_type[i];
		uint16_t total_types = kt_freq_list_total[i];
		uint16_t type_zones_used = 0;

		if (n_unique_sig == 0) {
			continue;
		}

		zone_carry = 0;
		assert(n_zones_sig + n_zones_type + 1 <= 32);
		zone_t kt_zones_for_size[32] = {};
		kalloc_type_create_zone_for_size(kt_zones_for_size,
		    n_zones_sig + n_zones_type, z_size);

		kalloc_type_zarray[i] = kt_zones_for_size[0];
		/*
		 * Ensure that there is enough space to shuffle n_unique_sig
		 * indices
		 */
		assert(n_unique_sig < kt_shuffle_count);

		/*
		 * Get a shuffled set of signature indices
		 */
		*kt_shuffle_buf = 0;
		if (n_unique_sig > 1) {
			kmem_shuffle(kt_shuffle_buf, n_unique_sig);
		}

		for (uint16_t j = 0; j < n_zones_sig; j++) {
			zone_t *z_ptr = &kt_zones_for_size[j];

			kalloc_type_init_sig_eq(z_ptr, 1, *z_ptr);
		}

		for (uint16_t j = 0; j < n_unique_sig; j++) {
			/*
			 * For every size that has unique types
			 */
			uint16_t shuffle_idx = kt_shuffle_buf[j];
			uint16_t cur = kt_skip_list[shuffle_idx + p_j];
			uint16_t end = kt_skip_list[shuffle_idx + p_j + 1];
			zone_t zone = kt_zones_for_size[j % n_zones_sig];
			zone_t shared_zone = kt_zones_for_size[n_zones_sig + n_zones_type];
			bool last_sig;

			last_sig = (j == (n_unique_sig - 1)) ? true : false;
			type_zones_used += kalloc_type_distribute_zone_for_type(
				&kt_buffer[cur].ktv_fixed,
				&kt_buffer[end].ktv_fixed, last_sig,
				n_zones_type, total_types + n_unique_sig,
				&kt_shuffle_buf[n_unique_sig], kt_zones_for_size,
				n_zones_sig + type_zones_used, zone, shared_zone);
		}
		assert(type_zones_used <= n_zones_type);
		p_j += n_unique_sig;
	}
}

__startup_func
static void
kalloc_type_view_init_fixed(void)
{
	kalloc_type_hash_seed = (uint32_t) early_random();
	kalloc_type_build_dlut();
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
	uint16_t *kt_shuffle_buf = kalloc_type_create_iterators_fixed(
		kt_skip_list_start, kt_count);

	/*
	 * Create zones based on signatures
	 */
	kalloc_type_create_zones_fixed(kt_skip_list_start, kt_shuffle_buf);
}

__startup_func
static void
kalloc_type_heap_init(void)
{
	assert(kt_var_heaps + 1 <= KT_VAR_MAX_HEAPS);
	char kh_name[MAX_ZONE_NAME];
	uint32_t last_heap = KT_VAR_PTR_HEAP0 + kt_var_heaps;

	for (uint32_t i = KT_VAR_PTR_HEAP0; i < last_heap; i++) {
		snprintf(&kh_name[0], MAX_ZONE_NAME, "%s%u", KHEAP_KT_VAR->kh_name, i);
		kalloc_zone_init((const char *)&kh_name[0], KHEAP_ID_KT_VAR,
		    &kalloc_type_heap_array[i].kh_zstart, ZC_KALLOC_TYPE);
	}
	/*
	 * All variable kalloc type allocations are collapsed into a single
	 * stat. Individual accounting can be requested via KT_PRIV_ACCT
	 */
	KHEAP_KT_VAR->kh_stats = zalloc_percpu_permanent_type(struct zone_stats);
	zone_view_count += 1;
}

__startup_func
static void
kalloc_type_assign_heap(
	uint32_t            start,
	uint32_t            end,
	uint32_t            heap_id)
{
	bool use_split = kmem_get_random16(1);

	if (use_split) {
		heap_id = kt_var_heaps;
	}
	kalloc_type_assign_zone_var(&kt_buffer[start].ktv_var,
	    &kt_buffer[end].ktv_var, heap_id);
}

__startup_func
static void
kalloc_type_split_heap(
	uint32_t            start,
	uint32_t            end,
	uint32_t            heap_id)
{
	uint32_t count = start;
	const char *p_name = NULL;

	while (count < end) {
		kalloc_type_var_view_t cur = kt_buffer[count].ktv_var;
		const char *c_name = cur->kt_name;

		if (!p_name) {
			assert(count == start);
			p_name = c_name;
		}
		if (strcmp(c_name, p_name) != 0) {
			kalloc_type_assign_heap(start, count, heap_id);
			start = count;
			p_name = c_name;
		}
		count++;
	}
	kalloc_type_assign_heap(start, end, heap_id);
}

__startup_func
static void
kalloc_type_view_init_var(void)
{
	uint32_t buf_start = 0, unique_sig = 0;
	uint32_t *kt_skip_list_start;
	uint16_t *shuffle_buf;
	uint16_t fixed_heaps = KT_VAR__FIRST_FLEXIBLE_HEAP - 1;
	uint16_t flex_heap_count = kt_var_heaps - fixed_heaps - 1;
	/*
	 * Pick a random heap to split
	 */
	uint16_t split_heap = kmem_get_random16(flex_heap_count - 1);

	/*
	 * Zones are created prior to parsing the views as zone budget is fixed
	 * per sizeclass and special types identified while parsing are redirected
	 * as they are discovered.
	 */
	kalloc_type_heap_init();

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

	buf_start = kalloc_type_handle_parray_var();

	/*
	 * Build a skip list that holds starts of unique signatures
	 */
	kt_skip_list_start = (uint32_t *)(kt_buffer + kt_count);
	unique_sig = kalloc_type_create_iterators_var(kt_skip_list_start,
	    buf_start);
	shuffle_buf = (uint16_t *)(kt_skip_list_start + unique_sig + 1);
	/*
	 * If we have only one heap then other elements share heap with pointer
	 * arrays
	 */
	if (kt_var_heaps < KT_VAR__FIRST_FLEXIBLE_HEAP) {
		panic("kt_var_heaps is too small");
	}

	kmem_shuffle(shuffle_buf, flex_heap_count);
	/*
	 * The index of the heap we decide to split is placed twice in the shuffle
	 * buffer so that it gets twice the number of signatures that we split
	 * evenly
	 */
	shuffle_buf[flex_heap_count] = split_heap;
	split_heap += (fixed_heaps + 1);

	for (uint32_t i = 1; i <= unique_sig; i++) {
		uint32_t heap_id = shuffle_buf[i % (flex_heap_count + 1)] +
		    fixed_heaps + 1;
		uint32_t start = kt_skip_list_start[i - 1];
		uint32_t end = kt_skip_list_start[i];

		assert(heap_id <= kt_var_heaps);
		if (heap_id == split_heap) {
			kalloc_type_split_heap(start, end, heap_id);
			continue;
		}
		kalloc_type_assign_zone_var(&kt_buffer[start].ktv_var,
		    &kt_buffer[end].ktv_var, heap_id);
	}
}

__startup_func
static void
kalloc_init(void)
{
	/*
	 * Allocate scratch space to parse kalloc_type_views and create
	 * other structures necessary to process them.
	 */
	uint64_t max_count = kt_count = kt_scratch_size / sizeof(kalloc_type_views_t);

	static_assert(KHEAP_MAX_SIZE >= KALLOC_SAFE_ALLOC_SIZE);
	kalloc_zsize_compute();

	/* Initialize kalloc data buffers heap */
	kalloc_heap_init(KHEAP_DATA_BUFFERS);

	/* Initialize kalloc shared buffers heap */
	kalloc_heap_init(KHEAP_SHARED);

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
STARTUP(ZALLOC, STARTUP_RANK_THIRD, kalloc_init);

#pragma mark accessors

#define KFREE_ABSURD_SIZE \
	((VM_MAX_KERNEL_ADDRESS - VM_MIN_KERNEL_AND_KEXT_ADDRESS) / 2)

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

#if __arm64e__ || CONFIG_KERNEL_TAGGING

#if __arm64e__
#define KALLOC_ARRAY_TYPE_SHIFT (64 - T1SZ_BOOT - 1)

/*
 * Zone encoding is:
 *
 *   <PAC SIG><1><1><PTR value><5 bits of size class>
 *
 * VM encoding is:
 *
 *   <PAC SIG><1><0><PTR value><14 bits of page count>
 *
 * The <1> is precisely placed so that <PAC SIG><1> is T1SZ worth of bits,
 * so that PAC authentication extends the proper sign bit.
 */

static_assert(T1SZ_BOOT + 1 + VM_KERNEL_POINTER_SIGNIFICANT_BITS <= 64);
#else
#define KALLOC_ARRAY_TYPE_SHIFT (64 - 8 - 1)

/*
 * Zone encoding is:
 *
 *   <TBI><1><PTR value><5 bits of size class>
 *
 * VM encoding is:
 *
 *   <TBI><0><PTR value><14 bits of page count>
 */

static_assert(8 + 1 + 1 + VM_KERNEL_POINTER_SIGNIFICANT_BITS <= 64);
#endif

SECURITY_READ_ONLY_LATE(uint32_t) kalloc_array_type_shift = KALLOC_ARRAY_TYPE_SHIFT;

__attribute__((always_inline))
struct kalloc_result
__kalloc_array_decode(vm_address_t ptr)
{
	struct kalloc_result kr;
	vm_address_t zone_mask = 1ul << KALLOC_ARRAY_TYPE_SHIFT;

	if (ptr & zone_mask) {
		kr.size = (32 + (ptr & 0x10)) << (ptr & 0xf);
		ptr &= ~0x1full;
	} else if (__probable(ptr)) {
		kr.size = (ptr & PAGE_MASK) << PAGE_SHIFT;
		ptr &= ~PAGE_MASK;
		ptr |= zone_mask;
	} else {
		kr.size = 0;
	}

	kr.addr = (void *)ptr;
	return kr;
}

static inline void *
__kalloc_array_encode_zone(zone_t z, void *ptr, vm_size_t size __unused)
{
	return (void *)((vm_address_t)ptr | z->z_array_size_class);
}

static inline vm_address_t
__kalloc_array_encode_vm(vm_address_t addr, vm_size_t size)
{
	addr &= ~(0x1ull << KALLOC_ARRAY_TYPE_SHIFT);

	return addr | atop(size);
}

#else

SECURITY_READ_ONLY_LATE(uint32_t) kalloc_array_type_shift = 0;

/*
 * Encoding is:
 * bits  0..46: pointer value
 * bits 47..47: 0: zones, 1: VM
 * bits 48..63: zones: elem size, VM: number of pages
 */

#define KALLOC_ARRAY_TYPE_BIT   47
static_assert(KALLOC_ARRAY_TYPE_BIT > VM_KERNEL_POINTER_SIGNIFICANT_BITS + 1);
static_assert(__builtin_clzll(KHEAP_MAX_SIZE) > KALLOC_ARRAY_TYPE_BIT);

__attribute__((always_inline))
struct kalloc_result
__kalloc_array_decode(vm_address_t ptr)
{
	struct kalloc_result kr;
	uint32_t shift = 64 - KALLOC_ARRAY_TYPE_BIT;

	kr.size = ptr >> (KALLOC_ARRAY_TYPE_BIT + 1);
	if (ptr & (1ull << KALLOC_ARRAY_TYPE_BIT)) {
		kr.size <<= PAGE_SHIFT;
	}
	/* sign extend, so that it also works with NULL */
	kr.addr = (void *)((long)(ptr << shift) >> shift);

	return kr;
}

static inline void *
__kalloc_array_encode_zone(zone_t z __unused, void *ptr, vm_size_t size)
{
	vm_address_t addr = (vm_address_t)ptr;

	addr &= (1ull << KALLOC_ARRAY_TYPE_BIT) - 1; /* clear bit */
	addr |= size << (KALLOC_ARRAY_TYPE_BIT + 1);

	return (void *)addr;
}

static inline vm_address_t
__kalloc_array_encode_vm(vm_address_t addr, vm_size_t size)
{
	addr &= (2ull << KALLOC_ARRAY_TYPE_BIT) - 1; /* keep bit */
	addr |= size << (KALLOC_ARRAY_TYPE_BIT + 1 - PAGE_SHIFT);

	return addr;
}

#endif

vm_size_t
kalloc_next_good_size(vm_size_t size, uint32_t period)
{
	uint32_t scale = kalloc_log2down((uint32_t)size);
	vm_size_t step, size_class;

	if (size < KHEAP_STEP_START) {
		return KHEAP_STEP_START;
	}
	if (size < 2 * KHEAP_STEP_START) {
		return 2 * KHEAP_STEP_START;
	}

	if (size < KHEAP_MAX_SIZE) {
		step = 1ul << (scale - 1);
	} else {
		step = round_page(1ul << (scale - kalloc_log2down(period)));
	}

	size_class = (size + step) & -step;
#if KASAN_CLASSIC
	if (size > K_SIZE_CLASS(size_class)) {
		return kalloc_next_good_size(size_class, period);
	}
	size_class = K_SIZE_CLASS(size_class);
#endif
	return size_class;
}


#pragma mark kalloc

static inline kalloc_heap_t
kalloc_type_get_heap(kalloc_type_var_view_t kt_view, bool kt_free __unused)
{
	/*
	 * Redirect data-only views
	 */
	if (kalloc_type_is_data(kt_view->kt_flags)) {
		return KHEAP_DATA_BUFFERS;
	}

	if (kt_view->kt_flags & KT_PROCESSED) {
		return KHEAP_KT_VAR;
	}

	return KHEAP_DEFAULT;
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
	kma_flags_t kma_flags = KMA_KASAN_GUARD | KMA_TAG;
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

	if ((flags & Z_KALLOC_ARRAY) && req_size > KALLOC_ARRAY_SIZE_MAX) {
		return (struct kalloc_result){ };
	}

	/*
	 * (73465472) on Intel we didn't use to pass this flag,
	 * which in turned allowed kalloc_large() memory to be shared
	 * with user directly.
	 *
	 * We're bound by this unfortunate ABI.
	 */
	if ((flags & Z_MAY_COPYINMAP) == 0) {
#ifndef __x86_64__
		kma_flags |= KMA_KOBJECT;
#endif
	} else {
		assert(kheap == KHEAP_DATA_BUFFERS);
		kma_flags &= ~KMA_TAG;
	}
	if (flags & Z_NOPAGEWAIT) {
		kma_flags |= KMA_NOPAGEWAIT;
	}
	if (flags & Z_ZERO) {
		kma_flags |= KMA_ZERO;
	}
	if (kheap == KHEAP_DATA_BUFFERS) {
		kma_flags |= KMA_DATA;
	} else if (flags & (Z_KALLOC_ARRAY | Z_SPRAYQTN)) {
		kma_flags |= KMA_SPRAYQTN;
	}


	tag = zalloc_flags_get_tag(flags);
	if (flags & Z_VM_TAG_BT_BIT) {
		tag = vm_tag_bt() ?: tag;
	}
	if (tag == VM_KERN_MEMORY_NONE) {
		tag = kheap->kh_tag;
	}

	size = round_page(req_size);
	if (flags & (Z_FULLSIZE | Z_KALLOC_ARRAY)) {
		req_size = round_page(size);
	}

	addr = kmem_alloc_guard(kernel_map, req_size, 0,
	    kma_flags, kalloc_guard(tag, kt_hash, owner)).kmr_address;

	if (addr != 0) {
		counter_inc(&kalloc_large_count);
		counter_add(&kalloc_large_total, size);
		KALLOC_ZINFO_SALLOC(size);
		if (flags & Z_KALLOC_ARRAY) {
			addr = __kalloc_array_encode_vm(addr, req_size);
		}
	} else {
		addr = 0;
	}

	DTRACE_VM3(kalloc, vm_size_t, size, vm_size_t, req_size, void*, addr);
	return (struct kalloc_result){ .addr = (void *)addr, .size = req_size };
}

#if KASAN

static inline void
kalloc_mark_unused_space(void *addr, vm_size_t size, vm_size_t used)
{
#if KASAN_CLASSIC
	/*
	 * On KASAN_CLASSIC, Z_SKIP_KASAN is defined and the entire sanitizer
	 * tagging of the memory region is performed here.
	 */
	kasan_alloc((vm_offset_t)addr, size, used, KASAN_GUARD_SIZE, false,
	    __builtin_frame_address(0));
#endif /* KASAN_CLASSIC */

#if KASAN_TBI
	kasan_tbi_retag_unused_space((vm_offset_t)addr, size, used ? :1);
#endif /* KASAN_TBI */
}
#endif /* KASAN */

static inline struct kalloc_result
kalloc_zone(
	zone_t                  z,
	zone_stats_t            zstats,
	zalloc_flags_t          flags,
	vm_size_t               req_size)
{
	struct kalloc_result kr;
	vm_size_t esize;

	kr = zalloc_ext(z, zstats ?: z->z_stats, flags | Z_SKIP_KASAN);
	esize = kr.size;

	if (__probable(kr.addr)) {
		if (flags & (Z_FULLSIZE | Z_KALLOC_ARRAY)) {
			req_size = esize;
		} else {
			kr.size = req_size;
		}
#if ZSECURITY_CONFIG(PGZ_OOB_ADJUST)
		kr.addr = zone_element_pgz_oob_adjust(kr.addr, req_size, esize);
#endif /* !ZSECURITY_CONFIG(PGZ_OOB_ADJUST) */

#if KASAN
		kalloc_mark_unused_space(kr.addr, esize, kr.size);
#endif /* KASAN */

		if (flags & Z_KALLOC_ARRAY) {
			kr.addr = __kalloc_array_encode_zone(z, kr.addr, kr.size);
		}
	}

	DTRACE_VM3(kalloc, vm_size_t, req_size, vm_size_t, kr.size, void*, kr.addr);
	return kr;
}

static zone_id_t
kalloc_use_shared_heap(
	kalloc_heap_t           kheap,
	zone_stats_t            zstats,
	zone_id_t               zstart,
	zalloc_flags_t         *flags)
{
	if (kheap->kh_heap_id != KHEAP_ID_DATA_BUFFERS) {
		zone_stats_t zstats_cpu = zpercpu_get(zstats);

		if (os_atomic_load(&zstats_cpu->zs_alloc_not_shared, relaxed) == 0) {
			*flags |= Z_SET_NOTSHARED;
			return KHEAP_SHARED->kh_zstart;
		}
	}

	return zstart;
}

#undef kalloc_ext

struct kalloc_result
kalloc_ext(
	void                   *kheap_or_kt_view,
	vm_size_t               size,
	zalloc_flags_t          flags,
	void                   *owner)
{
	kalloc_type_var_view_t kt_view;
	kalloc_heap_t kheap;
	zone_stats_t zstats = NULL;
	zone_t z;
	uint16_t kt_hash;
	zone_id_t zstart;

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
		zstart  = kt_view->kt_heap_start ?: kheap->kh_zstart;
	} else {
		kt_view = NULL;
		kheap   = kheap_or_kt_view;
		kt_hash = kheap->kh_type_hash;
		zstart  = kheap->kh_zstart;
	}

	if (!zstats) {
		zstats = kheap->kh_stats;
	}

	zstart = kalloc_use_shared_heap(kheap, zstats, zstart, &flags);
	z = kalloc_zone_for_size_with_flags(zstart, size, flags);
	if (z) {
		return kalloc_zone(z, zstats, flags, size);
	} else {
		return kalloc_large(kheap, size, flags, kt_hash, owner);
	}
}

#if XNU_PLATFORM_MacOSX
void *
kalloc_external(vm_size_t size);
void *
kalloc_external(vm_size_t size)
{
	zalloc_flags_t flags = Z_VM_TAG_BT(Z_WAITOK, VM_KERN_MEMORY_KALLOC);
	return kheap_alloc(KHEAP_DEFAULT, size, flags);
}
#endif /* XNU_PLATFORM_MacOSX */

void *
kalloc_data_external(vm_size_t size, zalloc_flags_t flags);
void *
kalloc_data_external(vm_size_t size, zalloc_flags_t flags)
{
	flags = Z_VM_TAG_BT(flags & Z_KPI_MASK, VM_KERN_MEMORY_KALLOC_DATA);
	return kheap_alloc(KHEAP_DATA_BUFFERS, size, flags);
}

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
		    (size_t)size, (size_t)zone_elem_inner_size(z));
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
		    (size_t)size, (size_t)zone_elem_inner_size(z));
	} else {
		panic("kalloc_non_data_require failed: address %p not in zone native map",
		    addr);
	}
}

void
kalloc_data_require(void *addr, vm_size_t size)
{
	zone_id_t zid = zone_id_for_element(addr, size);

	if (zid != ZONE_ID_INVALID) {
		zone_t z = &zone_array[zid];
		zone_security_flags_t zsflags = zone_security_array[zid];
		if (zsflags.z_kheap_id == KHEAP_ID_DATA_BUFFERS &&
		    size <= zone_elem_inner_size(z)) {
			return;
		}
	} else if (kmem_range_id_contains(KMEM_RANGE_ID_DATA,
	    (vm_address_t)pgz_decode(addr, size), size)) {
		return;
	}

	kalloc_data_require_panic(addr, size);
}

void
kalloc_non_data_require(void *addr, vm_size_t size)
{
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
		case KHEAP_ID_KT_VAR:
			if (size < zone_elem_inner_size(z)) {
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
	return kalloc_type_impl(kt_view, flags);
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
	const char *kheap_name = kalloc_heap_names[kheap->kh_heap_id];

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
	zone_t max_zone = kalloc_zone_for_size(kheap->kh_zstart, max_size);
	vm_size_t max_zone_size = zone_elem_inner_size(max_zone);
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
	size = kmem_free_guard(kernel_map, addr, size,
	    flags | KMF_TAG | KMF_KASAN_GUARD,
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
	zone_stats_t zstats = NULL;

	if (kt_is_var_view(kheap_or_kt_view)) {
		kt_view = kt_demangle_var_view(kheap_or_kt_view);
		kheap   = kalloc_type_get_heap(kt_view, true);
		/*
		 * Note: If we have cross frees between KHEAP_KT_VAR and KHEAP_DEFAULT
		 * we will end up having incorrect stats. Cross frees may happen on
		 * macOS due to allocation from an unprocessed view and free from
		 * a processed view or vice versa.
		 */
		zstats  = kt_view->kt_stats;
	} else {
		kt_view = NULL;
		kheap   = kheap_or_kt_view;
	}

	if (!zstats) {
		zstats = kheap->kh_stats;
	}

	zsflags = zone_security_config(z);
	if (kheap == KHEAP_DATA_BUFFERS) {
		if (kheap->kh_heap_id != zsflags.z_kheap_id) {
			kfree_heap_confusion_panic(kheap, data, size, z);
		}
	} else {
		if ((kheap->kh_heap_id != zsflags.z_kheap_id) &&
		    (zsflags.z_kheap_id != KHEAP_ID_SHARED)) {
			kfree_heap_confusion_panic(kheap, data, size, z);
		}
	}

	DTRACE_VM3(kfree, vm_size_t, size, vm_size_t, zsize, void*, data);

	/* needs to be __nosan because the user size might be partial */
	__nosan_bzero(data, zsize);
	zfree_ext(z, zstats ?: z->z_stats, data, ZFREE_PACK_SIZE(zsize, size));
}

void
kfree_ext(void *kheap_or_kt_view, void *data, vm_size_t size)
{
	vm_size_t bucket_size;
	zone_t z;

	if (data == NULL) {
		return;
	}

	if (size > KFREE_ABSURD_SIZE) {
		kfree_size_invalid_panic(data, size);
	}

	if (size <= KHEAP_MAX_SIZE) {
		vm_size_t oob_offs;

		bucket_size = zone_element_size(data, &z, true, &oob_offs);
		if (size + oob_offs > bucket_size || bucket_size == 0) {
			kfree_size_confusion_panic(z, data,
			    oob_offs, size, bucket_size);
		}

		data = (char *)data - oob_offs;
		kfree_zone(kheap_or_kt_view, data, size, z, bucket_size);
	} else {
		kfree_large((vm_offset_t)data, size, KMF_NONE, NULL);
	}
}

void
kfree_addr_ext(kalloc_heap_t kheap, void *data)
{
	vm_offset_t oob_offs;
	vm_size_t size, usize = 0;
	zone_t z;

	if (data == NULL) {
		return;
	}

	size = zone_element_size(data, &z, true, &oob_offs);
	if (size) {
#if KASAN_CLASSIC
		usize = kasan_user_size((vm_offset_t)data);
#endif
		data = (char *)data - oob_offs;
		kfree_zone(kheap, data, usize, z, size);
	} else {
		kfree_large((vm_offset_t)data, 0, KMF_GUESS_SIZE, NULL);
	}
}

#if XNU_PLATFORM_MacOSX
void
kfree_external(void *addr, vm_size_t size);
void
kfree_external(void *addr, vm_size_t size)
{
	kalloc_heap_t kheap = KHEAP_DEFAULT;

	kfree_ext(kheap, addr, size);
}
#endif /* XNU_PLATFORM_MacOSX */

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

void *
kalloc_type_impl_internal(kalloc_type_view_t kt_view, zalloc_flags_t flags)
{
	zone_stats_t zs = kt_view->kt_zv.zv_stats;
	zone_t       z  = kt_view->kt_zv.zv_zone;
	zone_stats_t zs_cpu = zpercpu_get(zs);

	if ((flags & Z_SET_NOTSHARED) ||
	    os_atomic_load(&zs_cpu->zs_alloc_not_shared, relaxed)) {
		return zalloc_ext(z, zs, flags).addr;
	}

	assert(zone_security_config(z).z_kheap_id != KHEAP_ID_DATA_BUFFERS);
	return zalloc_ext(kt_view->kt_zshared, zs, flags | Z_SET_NOTSHARED).addr;
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
	return kfree_type_impl(kt_view, ptr);
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
	kmr_flags_t kmr_flags = KMR_FREEOLD | KMR_TAG | KMR_KASAN_GUARD;
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

	/*
	 * (73465472) on Intel we didn't use to pass this flag,
	 * which in turned allowed kalloc_large() memory to be shared
	 * with user directly.
	 *
	 * We're bound by this unfortunate ABI.
	 */
	if ((flags & Z_MAY_COPYINMAP) == 0) {
#ifndef __x86_64__
		kmr_flags |= KMR_KOBJECT;
#endif
	} else {
		assert(kheap == KHEAP_DATA_BUFFERS);
		kmr_flags &= ~KMR_TAG;
	}
	if (flags & Z_NOPAGEWAIT) {
		kmr_flags |= KMR_NOPAGEWAIT;
	}
	if (flags & Z_ZERO) {
		kmr_flags |= KMR_ZERO;
	}
	if (kheap == KHEAP_DATA_BUFFERS) {
		kmr_flags |= KMR_DATA;
	} else if (flags & (Z_KALLOC_ARRAY | Z_SPRAYQTN)) {
		kmr_flags |= KMR_SPRAYQTN;
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

	kmr = kmem_realloc_guard(kernel_map, addr, old_req_size, new_req_size,
	    kmr_flags, kalloc_guard(tag, kt_hash, owner));

	new_size = round_page(new_req_size);
	old_size = round_page(old_req_size);

	if (kmr.kmr_address != 0) {
		delta = (uint64_t)(new_size - old_size);
	} else if (flags & Z_REALLOCF) {
		counter_dec(&kalloc_large_count);
		delta = (uint64_t)(-old_size);
	} else {
		delta = 0;
	}

	counter_add(&kalloc_large_total, delta);
	KALLOC_ZINFO_SALLOC(delta);

	if (addr != 0 || (flags & Z_REALLOCF)) {
		DTRACE_VM3(kfree, vm_size_t, old_size, vm_size_t, old_req_size,
		    void*, addr);
	}
	if (__improbable(kmr.kmr_address == 0)) {
		return (struct kalloc_result){ };
	}

	DTRACE_VM3(kalloc, vm_size_t, new_size, vm_size_t, new_req_size,
	    void*, kmr.kmr_address);

	if (flags & Z_KALLOC_ARRAY) {
		kmr.kmr_address = __kalloc_array_encode_vm(kmr.kmr_address,
		    new_req_size);
	}
	return (struct kalloc_result){ .addr = kmr.kmr_ptr, .size = new_req_size };
}

#undef krealloc_ext

struct kalloc_result
krealloc_ext(
	void                 *kheap_or_kt_view __unsafe_indexable,
	void                 *addr,
	vm_size_t             old_size,
	vm_size_t             new_size,
	zalloc_flags_t        flags,
	void                 *owner)
{
	vm_size_t old_bucket_size, new_bucket_size, min_size;
	kalloc_type_var_view_t kt_view;
	kalloc_heap_t kheap;
	zone_stats_t zstats = NULL;
	struct kalloc_result kr;
	vm_offset_t oob_offs = 0;
	zone_t old_z, new_z;
	uint16_t kt_hash = 0;
	zone_id_t zstart;

	if (old_size > KFREE_ABSURD_SIZE) {
		krealloc_size_invalid_panic(addr, old_size);
	}

	if (addr == NULL && new_size == 0) {
		return (struct kalloc_result){ };
	}

	if (kt_is_var_view(kheap_or_kt_view)) {
		kt_view = kt_demangle_var_view(kheap_or_kt_view);
		kheap   = kalloc_type_get_heap(kt_view, false);
		/*
		 * Similar to kalloc_ext: Use stats from view if present,
		 * else use stats from kheap.
		 *
		 * krealloc_type isn't exposed to kexts, so we don't need to
		 * handle cross frees and can rely on stats from view or kheap.
		 */
		zstats  = kt_view->kt_stats;
		kt_hash = KT_GET_HASH(kt_view->kt_flags);
		zstart  = kt_view->kt_heap_start ?: kheap->kh_zstart;
	} else {
		kt_view = NULL;
		kheap   = kheap_or_kt_view;
		kt_hash = kheap->kh_type_hash;
		zstart  = kheap->kh_zstart;
	}

	if (!zstats) {
		zstats = kheap->kh_stats;
	}
	/*
	 * Find out the size of the bucket in which the new sized allocation
	 * would land. If it matches the bucket of the original allocation,
	 * simply return the same address.
	 */
	if (new_size == 0) {
		new_z = ZONE_NULL;
		new_bucket_size = new_size = 0;
	} else {
		zstart = kalloc_use_shared_heap(kheap, zstats, zstart, &flags);
		new_z = kalloc_zone_for_size_with_flags(zstart, new_size, flags);
		new_bucket_size = new_z ? zone_elem_inner_size(new_z) : round_page(new_size);
	}
#if !KASAN_CLASSIC
	if (flags & Z_FULLSIZE) {
		new_size = new_bucket_size;
	}
#endif /* !KASAN_CLASSIC */

	if (addr == NULL) {
		old_z = ZONE_NULL;
		old_size = old_bucket_size = 0;
	} else if (kheap_size_from_zone(addr, old_size, flags)) {
		old_bucket_size = zone_element_size(addr, &old_z, true, &oob_offs);
		if (old_size + oob_offs > old_bucket_size || old_bucket_size == 0) {
			kfree_size_confusion_panic(old_z, addr,
			    oob_offs, old_size, old_bucket_size);
		}
		__builtin_assume(old_z != ZONE_NULL);
	} else {
		old_z = ZONE_NULL;
		old_bucket_size = round_page(old_size);
	}
	min_size = MIN(old_size, new_size);

	if (old_bucket_size == new_bucket_size && old_z) {
		kr.addr = (char *)addr - oob_offs;
		kr.size = new_size;
#if ZSECURITY_CONFIG(PGZ_OOB_ADJUST)
		kr.addr = zone_element_pgz_oob_adjust(kr.addr,
		    new_size, new_bucket_size);
		if (kr.addr != addr) {
			memmove(kr.addr, addr, min_size);
			bzero((char *)kr.addr + min_size,
			    kr.size - min_size);
		}
#endif /* !ZSECURITY_CONFIG(PGZ_OOB_ADJUST) */
#if KASAN
		/*
		 * On KASAN kernels, treat a reallocation effectively as a new
		 * allocation and add a sanity check around the existing one
		 * w.r.t. the old requested size. On KASAN_CLASSIC this doesn't account
		 * to much extra work, on KASAN_TBI, assign a new tag both to the
		 * buffer and to the potential free space.
		 */
#if KASAN_CLASSIC
		kasan_check_alloc((vm_offset_t)addr, old_bucket_size, old_size);
		kasan_alloc((vm_offset_t)addr, new_bucket_size, kr.size,
		    KASAN_GUARD_SIZE, false, __builtin_frame_address(0));
#endif /* KASAN_CLASSIC */
#if KASAN_TBI
		/*
		 * Validate the current buffer, then generate a new tag,
		 * even if the address is stable, it's a "new" allocation.
		 */
		__asan_loadN((vm_offset_t)addr, old_size);
		kr.addr = (void *)vm_memtag_assign_tag((vm_offset_t)kr.addr, kr.size);
		vm_memtag_set_tag((vm_offset_t)kr.addr, kr.size);
		kasan_tbi_retag_unused_space((vm_offset_t)kr.addr, new_bucket_size, kr.size);
#endif /* KASAN_TBI */
#endif /* KASAN */
		goto out_success;
	}

#if !KASAN
	/*
	 * Fallthrough to krealloc_large() for KASAN,
	 * because we can't use kasan_check_alloc()
	 * on kalloc_large() memory.
	 *
	 * kmem_realloc_guard() will perform all the validations,
	 * and re-tagging.
	 */
	if (old_bucket_size == new_bucket_size) {
		kr.addr = (char *)addr - oob_offs;
		kr.size = new_size;
		goto out_success;
	}
#endif

	if (addr && !old_z && new_size && !new_z) {
		return krealloc_large(kheap, (vm_offset_t)addr,
		           old_size, new_size, flags, kt_hash, owner);
	}

	if (!new_size) {
		kr.addr = NULL;
		kr.size = 0;
	} else if (new_z) {
		kr = kalloc_zone(new_z, zstats,
		    flags & ~Z_KALLOC_ARRAY, new_size);
	} else if (old_z || addr == NULL) {
		kr = kalloc_large(kheap, new_size,
		    flags & ~Z_KALLOC_ARRAY, kt_hash, owner);
	}

	if (addr && kr.addr) {
		__nosan_memcpy(kr.addr, addr, min_size);
	}

	if (addr && (kr.addr || (flags & Z_REALLOCF) || !new_size)) {
		if (old_z) {
			kfree_zone(kheap_or_kt_view,
			    (char *)addr - oob_offs, old_size,
			    old_z, old_bucket_size);
		} else {
			kfree_large((vm_offset_t)addr, old_size, KMF_NONE, owner);
		}
	}

	if (__improbable(kr.addr == NULL)) {
		return kr;
	}

out_success:
	if ((flags & Z_KALLOC_ARRAY) == 0) {
		return kr;
	}

	if (new_z) {
		kr.addr = __kalloc_array_encode_zone(new_z,
		    kr.addr, kr.size);
	} else {
		kr.addr = (void *)__kalloc_array_encode_vm((vm_offset_t)kr.addr,
		    kr.size);
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
static void
kheap_init(kalloc_heap_t parent_heap, kalloc_heap_t kheap)
{
	kheap->kh_zstart      = parent_heap->kh_zstart;
	kheap->kh_heap_id     = parent_heap->kh_heap_id;
	kheap->kh_tag         = parent_heap->kh_tag;
	kheap->kh_stats       = zalloc_percpu_permanent_type(struct zone_stats);
	zone_view_count += 1;
}

__startup_func
static void
kheap_init_data(kalloc_heap_t kheap)
{
	kheap_init(KHEAP_DATA_BUFFERS, kheap);
	kheap->kh_views               = KHEAP_DATA_BUFFERS->kh_views;
	KHEAP_DATA_BUFFERS->kh_views  = kheap;
}

__startup_func
static void
kheap_init_var(kalloc_heap_t kheap)
{
	uint16_t idx;
	struct kheap_info *parent_heap;

	kheap_init(KHEAP_KT_VAR, kheap);
	idx = kmem_get_random16(kt_var_heaps - kt_var_ptr_heaps - 1) +
	    KT_VAR__FIRST_FLEXIBLE_HEAP;
	parent_heap = &kalloc_type_heap_array[idx];
	kheap->kh_zstart = parent_heap->kh_zstart;
	kheap->kh_type_hash = (uint16_t) kalloc_hash_adjust(
		(uint32_t) early_random(), 0);
	kheap->kh_views       = parent_heap->kh_views;
	parent_heap->kh_views = kheap;
}

__startup_func
void
kheap_startup_init(kalloc_heap_t kheap)
{
	switch (kheap->kh_heap_id) {
	case KHEAP_ID_DATA_BUFFERS:
		kheap_init_data(kheap);
		break;
	case KHEAP_ID_KT_VAR:
		kheap_init_var(kheap);
		break;
	default:
		panic("kalloc_heap_startup_init: invalid KHEAP_ID: %d",
		    kheap->kh_heap_id);
	}
}

#pragma mark IOKit/libkern helpers

#if XNU_PLATFORM_MacOSX

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

	osize = zone_element_size(addr, NULL, false, &oob_offs);
	if (osize == 0) {
		osize = kmem_size_guard(kernel_map, (vm_offset_t)addr,
		    kalloc_guard(VM_KERN_MEMORY_LIBKERN, 0, NULL));
#if KASAN_CLASSIC
	} else {
		osize = kasan_user_size((vm_offset_t)addr);
#endif
	}
	return __kheap_realloc(KERN_OS_MALLOC, addr, osize - oob_offs, nsize, flags, NULL);
}

#endif /* XNU_PLATFORM_MacOSX */

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
	return kalloc_type_from_vm(ktv->kt_flags);
}

void
kern_os_typed_free(kalloc_type_view_t ktv, void *addr, vm_size_t esize)
{
#if ZSECURITY_CONFIG(STRICT_IOKIT_FREE)
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
		if (zsflags.z_kheap_id == KHEAP_ID_KT_VAR) {
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
	boolean_t zone_found = false;
	const char kalloc_type_str[] = "kalloc.type";
	for (uint16_t i = 0; i < MAX_K_ZONE(kt_zone_cfg); i++) {
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
	uint16_t freq_list[MAX_K_ZONE(kt_zone_cfg)] = {};
	uint16_t freq_total_list[MAX_K_ZONE(kt_zone_cfg)] = {};
	uint16_t zones_per_sig[MAX_K_ZONE(kt_zone_cfg)] = {};
	uint16_t zones_per_type[MAX_K_ZONE(kt_zone_cfg)] = {};
	uint16_t random[MAX_K_ZONE(kt_zone_cfg) * 2];
	uint16_t wasted_zone_budget = 0, total_types = 0;
	uint16_t n_zones = 0, n_zones_cal = 0;
	int ret = 0;

	/*
	 * Need a minimum of 2 zones per size class
	 */
	if (zone_budget < MAX_K_ZONE(kt_zone_cfg) * 2) {
		return ret;
	}
	read_random((void *)&random[0], sizeof(random));
	for (uint16_t i = 0; i < MAX_K_ZONE(kt_zone_cfg); i++) {
		uint16_t r1 = (random[2 * i] % max_bucket_freq) + 1;
		uint16_t r2 = (random[2 * i + 1] % max_bucket_freq) + 1;

		freq_list[i] = r1 > r2 ? r2 : r1;
		freq_total_list[i] = r1 > r2 ? r1 : r2;
	}
	wasted_zone_budget = kalloc_type_apply_policy(
		freq_list, freq_total_list,
		zones_per_sig, zones_per_type, zone_budget);

	for (uint16_t i = 0; i < MAX_K_ZONE(kt_zone_cfg); i++) {
		total_types += freq_total_list[i];
	}

	n_zones = kmem_get_random16(total_types);
	printf("Dividing %u zones amongst %u types\n", n_zones, total_types);
	for (uint16_t i = 0; i < MAX_K_ZONE(kt_zone_cfg); i++) {
		uint16_t n_zones_for_type = kalloc_type_zones_for_type(n_zones,
		    freq_total_list[i], total_types,
		    (i == MAX_K_ZONE(kt_zone_cfg) - 1) ? true : false);

		n_zones_cal += n_zones_for_type;

		printf("%u\t%u\n", freq_total_list[i], n_zones_for_type);
	}
	printf("-----------------------\n%u\t%u\n", total_types,
	    n_zones_cal);

	if ((wasted_zone_budget == 0) && (n_zones == n_zones_cal)) {
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
	kalloc_type_view_t kt_cur = (kalloc_type_view_t) z->z_views;

	while (kt_cur != NULL) {
		if (kalloc_type_get_size(kt_cur->kt_size) > z->z_elem_size) {
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
kalloc_type_test_data_redirect(void)
{
	struct kalloc_type_view ktv_data = {
		.kt_flags = KALLOC_TYPE_ADJUST_FLAGS(KT_SHARED_ACCT, struct test_kt_data),
		.kt_signature = KALLOC_TYPE_EMIT_SIG(struct test_kt_data),
	};
	if (!kalloc_type_is_data(ktv_data.kt_flags)) {
		printf("%s: data redirect failed\n", __func__);
		return 0;
	}
	return 1;
}

static int
run_kalloc_type_test(int64_t in, int64_t *out)
{
	*out = 0;
	for (uint16_t i = 0; i < MAX_K_ZONE(kt_zone_cfg); i++) {
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
	zone_t z = kalloc_zone_for_size(kheap->kh_zstart, size);

	return z ? zone_elem_inner_size(z) : round_page(size);
}

static int
run_kalloc_test(int64_t in __unused, int64_t *out)
{
	*out = 0;
	uint64_t *data_ptr;
	void *strippedp_old, *strippedp_new;
	size_t alloc_size = 0, old_alloc_size = 0;
	struct kalloc_result kr = {};

	printf("%s: test running\n", __func__);

	/*
	 * Test size 0: alloc, free, realloc
	 */
	data_ptr = kalloc_ext(KHEAP_DATA_BUFFERS, alloc_size, Z_WAITOK | Z_NOFAIL,
	    NULL).addr;
	if (!data_ptr) {
		printf("%s: kalloc 0 returned null\n", __func__);
		return 0;
	}
	kheap_free(KHEAP_DATA_BUFFERS, data_ptr, alloc_size);

	data_ptr = kalloc_ext(KHEAP_DATA_BUFFERS, alloc_size, Z_WAITOK | Z_NOFAIL,
	    NULL).addr;
	alloc_size = sizeof(uint64_t) + 1;
	data_ptr = krealloc_ext(KHEAP_DATA_BUFFERS, kr.addr, old_alloc_size,
	    alloc_size, Z_WAITOK | Z_NOFAIL, NULL).addr;
	if (!data_ptr) {
		printf("%s: krealloc -> old size 0 failed\n", __func__);
		return 0;
	}
	*data_ptr = 0;

	/*
	 * Test krealloc: same sizeclass, different size classes, 2pgs,
	 * VM (with owner)
	 */
	old_alloc_size = alloc_size;
	alloc_size++;
	kr = krealloc_ext(KHEAP_DATA_BUFFERS, data_ptr, old_alloc_size, alloc_size,
	    Z_WAITOK | Z_NOFAIL, NULL);

	strippedp_old = (void *)vm_memtag_canonicalize_address((vm_offset_t)data_ptr);
	strippedp_new = (void *)vm_memtag_canonicalize_address((vm_offset_t)kr.addr);

	if (!kr.addr || (strippedp_old != strippedp_new) ||
	    (test_bucket_size(KHEAP_DATA_BUFFERS, kr.size) !=
	    test_bucket_size(KHEAP_DATA_BUFFERS, old_alloc_size))) {
		printf("%s: krealloc -> same size class failed\n", __func__);
		return 0;
	}
	data_ptr = kr.addr;
	*data_ptr = 0;

	old_alloc_size = alloc_size;
	alloc_size *= 2;
	kr = krealloc_ext(KHEAP_DATA_BUFFERS, data_ptr, old_alloc_size, alloc_size,
	    Z_WAITOK | Z_NOFAIL, NULL);

	strippedp_old = (void *)vm_memtag_canonicalize_address((vm_offset_t)data_ptr);
	strippedp_new = (void *)vm_memtag_canonicalize_address((vm_offset_t)kr.addr);

	if (!kr.addr || (strippedp_old == strippedp_new) ||
	    (test_bucket_size(KHEAP_DATA_BUFFERS, kr.size) ==
	    test_bucket_size(KHEAP_DATA_BUFFERS, old_alloc_size))) {
		printf("%s: krealloc -> different size class failed\n", __func__);
		return 0;
	}
	data_ptr = kr.addr;
	*data_ptr = 0;

	kheap_free(KHEAP_DATA_BUFFERS, kr.addr, alloc_size);

	alloc_size = 3544;
	data_ptr = kalloc_ext(KHEAP_DATA_BUFFERS, alloc_size,
	    Z_WAITOK | Z_FULLSIZE, &data_ptr).addr;
	if (!data_ptr) {
		printf("%s: kalloc 3544 with owner and Z_FULLSIZE returned not null\n",
		    __func__);
		return 0;
	}
	*data_ptr = 0;

	data_ptr = krealloc_ext(KHEAP_DATA_BUFFERS, data_ptr, alloc_size,
	    PAGE_SIZE * 2, Z_REALLOCF | Z_WAITOK, &data_ptr).addr;
	if (!data_ptr) {
		printf("%s: krealloc -> 2pgs returned not null\n", __func__);
		return 0;
	}
	*data_ptr = 0;

	data_ptr = krealloc_ext(KHEAP_DATA_BUFFERS, data_ptr, PAGE_SIZE * 2,
	    KHEAP_MAX_SIZE * 2, Z_REALLOCF | Z_WAITOK, &data_ptr).addr;
	if (!data_ptr) {
		printf("%s: krealloc -> VM1 returned not null\n", __func__);
		return 0;
	}
	*data_ptr = 0;

	data_ptr = krealloc_ext(KHEAP_DATA_BUFFERS, data_ptr, KHEAP_MAX_SIZE * 2,
	    KHEAP_MAX_SIZE * 4, Z_REALLOCF | Z_WAITOK, &data_ptr).addr;
	*data_ptr = 0;
	if (!data_ptr) {
		printf("%s: krealloc -> VM2 returned not null\n", __func__);
		return 0;
	}

	krealloc_ext(KHEAP_DATA_BUFFERS, data_ptr, KHEAP_MAX_SIZE * 4,
	    0, Z_REALLOCF | Z_WAITOK, &data_ptr);

	printf("%s: test passed\n", __func__);
	*out = 1;
	return 0;
}
SYSCTL_TEST_REGISTER(kalloc, run_kalloc_test);

#endif
