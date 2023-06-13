/*
 * Copyright (c) 2000-2020 Apple Inc. All rights reserved.
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

#ifndef _KERN_ZALLOC_INTERNAL_H_
#define _KERN_ZALLOC_INTERNAL_H_

#include <kern/zalloc.h>
#include <kern/locks.h>
#include <kern/simple_lock.h>

#include <os/atomic_private.h>
#include <sys/queue.h>
#include <vm/vm_map_internal.h>

#if KASAN
#include <san/kasan.h>
#include <kern/spl.h>
#endif /* !KASAN */

/*
 * Disable zalloc zero validation under kasan as it is
 * double-duty with what kasan already does.
 */
#if KASAN
#define ZALLOC_ENABLE_ZERO_CHECK        0
#else
#define ZALLOC_ENABLE_ZERO_CHECK        1
#endif

#if KASAN
#define ZALLOC_ENABLE_LOGGING           0
#elif DEBUG || DEVELOPMENT
#define ZALLOC_ENABLE_LOGGING           1
#else
#define ZALLOC_ENABLE_LOGGING           0
#endif

/*!
 * @file <kern/zalloc_internal.h>
 *
 * @abstract
 * Exposes some guts of zalloc to interact with the VM, debugging, copyio and
 * kalloc subsystems.
 */

__BEGIN_DECLS

#pragma GCC visibility push(hidden)

/*
 *	A zone is a collection of fixed size blocks for which there
 *	is fast allocation/deallocation access.  Kernel routines can
 *	use zones to manage data structures dynamically, creating a zone
 *	for each type of data structure to be managed.
 *
 */

/*!
 * @typedef zone_pva_t
 *
 * @brief
 * Type used to point to a page virtual address in the zone allocator.
 *
 * @description
 * - Valid pages have the top bit set.
 * - 0 represents the "NULL" page
 * - non 0 values with the top bit cleared represent queue heads,
 *   indexed from the beginning of the __DATA section of the kernel.
 *   (see zone_pageq_base).
 */
typedef struct zone_packed_virtual_address {
	uint32_t packed_address;
} zone_pva_t;

/*!
 * @struct zone_stats
 *
 * @abstract
 * Per-cpu structure used for basic zone stats.
 *
 * @discussion
 * The values aren't scaled for per-cpu zones.
 */
struct zone_stats {
	uint64_t            zs_mem_allocated;
	uint64_t            zs_mem_freed;
	uint64_t            zs_alloc_fail;
	uint32_t            zs_alloc_rr;     /* allocation rr bias */
};

typedef struct zone_magazine *zone_magazine_t;

/*!
 * @struct zone_depot
 *
 * @abstract
 * Holds a list of full and empty magazines.
 *
 * @discussion
 * The data structure is a "STAILQ" and an "SLIST" combined with counters
 * to know their lengths in O(1). Here is a graphical example:
 *
 *      zd_full = 3
 *      zd_empty = 1
 * ╭─── zd_head
 * │ ╭─ zd_tail
 * │ ╰────────────────────────────────────╮
 * │    ╭───────╮   ╭───────╮   ╭───────╮ v ╭───────╮
 * ╰───>│███████┼──>│███████┼──>│███████┼──>│       ┼─> X
 *      ╰───────╯   ╰───────╯   ╰───────╯   ╰───────╯
 */
struct zone_depot {
	uint32_t            zd_full;
	uint32_t            zd_empty;
	zone_magazine_t     zd_head;
	zone_magazine_t    *zd_tail;
};

/* see https://lemire.me/blog/2019/02/20/more-fun-with-fast-remainders-when-the-divisor-is-a-constant/ */
#define Z_MAGIC_QUO(s)      (((1ull << 32) - 1) / (uint64_t)(s) + 1)
#define Z_MAGIC_ALIGNED(s)  (~0u / (uint32_t)(s) + 1)

/*
 * Returns (offs / size) if offs is small enough
 * and magic = Z_MAGIC_QUO(size)
 */
static inline uint32_t
Z_FAST_QUO(uint64_t offs, uint64_t magic)
{
	return (offs * magic) >> 32;
}

/*
 * Returns (offs % size) if offs is small enough
 * and magic = Z_MAGIC_QUO(size)
 */
static inline uint32_t
Z_FAST_MOD(uint64_t offs, uint64_t magic, uint64_t size)
{
	uint32_t lowbits = (uint32_t)(offs * magic);

	return (lowbits * size) >> 32;
}

/*
 * Returns whether (offs % size) == 0 if offs is small enough
 * and magic = Z_MAGIC_ALIGNED(size)
 */
static inline bool
Z_FAST_ALIGNED(uint64_t offs, uint32_t magic)
{
	return (uint32_t)(offs * magic) < magic;
}

struct zone_size_params {
	uint32_t            z_align_magic;  /* magic to use with Z_FAST_ALIGNED()  */
	uint32_t            z_elem_size;    /* size of an element                  */
};

struct zone_expand {
	struct zone_expand *ze_next;
	thread_t            ze_thread;
	bool                ze_pg_wait;
	bool                ze_vm_priv;
	bool                ze_clear_priv;
};

#define Z_WMA_UNIT (1u << 8)
#define Z_WMA_MIX(base, e)  ((3 * (base) + (e) * Z_WMA_UNIT) / 4)

struct zone {
	/*
	 * Readonly / rarely written fields
	 */

	/*
	 * The first 4 fields match a zone_view.
	 *
	 * z_self points back to the zone when the zone is initialized,
	 * or is NULL else.
	 */
	struct zone        *z_self;
	zone_stats_t        z_stats;
	const char         *z_name;
	struct zone_view   *z_views;
	struct zone_expand *z_expander;

	uint64_t            z_quo_magic;
	uint32_t            z_align_magic;
	uint16_t            z_elem_size;
	uint16_t            z_elem_offs;
	uint16_t            z_chunk_pages;
	uint16_t            z_chunk_elems;

	uint32_t /* 32 bits */
	/*
	 * Lifecycle state (Mutable after creation)
	 */
	    z_destroyed        :1,  /* zone is (being) destroyed */
	    z_async_refilling  :1,  /* asynchronous allocation pending? */
	    z_depot_cleanup    :1,  /* per cpu depots need cleaning */
	    z_expanding_wait   :1,  /* is thread waiting for expansion? */

	/*
	 * Behavior configuration bits
	 */
	    z_percpu           :1,  /* the zone is percpu */
	    z_smr              :1,  /* the zone uses SMR */
	    z_permanent        :1,  /* the zone allocations are permanent */
	    z_nocaching        :1,  /* disallow zone caching for this zone */
	    collectable        :1,  /* garbage collect empty pages */
	    exhaustible        :1,  /* merely return if empty? */
	    no_callout         :1,
	    z_destructible     :1,  /* zone can be zdestroy()ed  */

	    _reserved          :7,

	/*
	 * Debugging features
	 */
	    z_pgz_tracked      :1,  /* this zone is tracked by pgzalloc */
	    z_pgz_use_guards   :1,  /* this zone uses guards with PGZ */
	    z_kasan_fakestacks :1,
	    z_kasan_quarantine :1,  /* whether to use the kasan quarantine */
	    z_tags_sizeclass   :6,  /* idx into zone_tags_sizeclasses to associate
	                             * sizeclass for a particualr kalloc tag */
	    z_uses_tags        :1,
	    z_log_on           :1,  /* zone logging was enabled by boot-arg */
	    z_tbi_tag          :1;  /* Zone supports tbi tagging */

	uint8_t             z_cacheline1[0] __attribute__((aligned(64)));

	/*
	 * Zone caching / recirculation cacheline
	 *
	 * z_recirc* fields are protected by the recirculation lock.
	 *
	 * z_recirc_cont_wma:
	 *   weighted moving average of the number of contentions per second,
	 *   in Z_WMA_UNIT units (fixed point decimal).
	 *
	 * z_recirc_cont_cur:
	 *   count of recorded contentions that will be fused
	 *   in z_recirc_cont_wma at the next period.
	 *
	 *   Note: if caching is disabled,
	 *   this field is used under the zone lock.
	 *
	 * z_elems_free_{min,wma} (overloaded on z_recirc_empty*):
	 *   tracks the history of the minimum values of z_elems_free over time
	 *   with "min" being the minimum it hit for the current period,
	 *   and "wma" the weighted moving average of those value.
	 *
	 *   This field is used if z_pcpu_cache is NULL,
	 *   otherwise it aliases with z_recirc_empty_{min,wma}
	 *
	 * z_recirc_{full,empty}_{min,wma}:
	 *   tracks the history of the the minimum number of full/empty
	 *   magazines in the depot over time, with "min" being the minimum
	 *   it hit for the current period, and "wma" the weighted moving
	 *   average of those value.
	 */
	struct zone_cache  *__zpercpu z_pcpu_cache;
	struct zone_depot   z_recirc;

	hw_lck_ticket_t     z_recirc_lock;
	uint32_t            z_recirc_full_min;
	uint32_t            z_recirc_full_wma;
	union {
		uint32_t    z_recirc_empty_min;
		uint32_t    z_elems_free_min;
	};
	union {
		uint32_t    z_recirc_empty_wma;
		uint32_t    z_elems_free_wma;
	};
	uint32_t            z_recirc_cont_cur;
	uint32_t            z_recirc_cont_wma;

	uint16_t            z_depot_size;
	uint16_t            z_depot_limit;

	uint8_t             z_cacheline2[0] __attribute__((aligned(64)));

	/*
	 * often mutated fields
	 */

	hw_lck_ticket_t     z_lock;

	/*
	 * Page accounting (wired / VA)
	 *
	 * Those numbers are unscaled for z_percpu zones
	 * (zone_scale_for_percpu() needs to be used to find the true value).
	 */
	uint32_t            z_wired_max;    /* how large can this zone grow        */
	uint32_t            z_wired_hwm;    /* z_wired_cur high watermark          */
	uint32_t            z_wired_cur;    /* number of pages used by this zone   */
	uint32_t            z_wired_empty;  /* pages collectable by GC             */
	uint32_t            z_va_cur;       /* amount of VA used by this zone      */

	/*
	 * list of metadata structs, which maintain per-page free element lists
	 */
	zone_pva_t          z_pageq_empty;  /* populated, completely empty pages   */
	zone_pva_t          z_pageq_partial;/* populated, partially filled pages   */
	zone_pva_t          z_pageq_full;   /* populated, completely full pages    */
	zone_pva_t          z_pageq_va;     /* non-populated VA pages              */

	/*
	 * Zone statistics
	 *
	 * z_elems_avail:
	 *   number of elements in the zone (at all).
	 */
	uint32_t            z_elems_free;   /* Number of free elements             */
	uint32_t            z_elems_avail;  /* Number of elements available        */
	uint32_t            z_elems_rsv;
	uint32_t            z_array_size_class;

	struct zone        *z_kt_next;

	uint8_t             z_cacheline3[0] __attribute__((aligned(64)));

#if KASAN_CLASSIC
	uint16_t            z_kasan_redzone;
	spl_t               z_kasan_spl;
#endif
#if ZONE_ENABLE_LOGGING || CONFIG_ZLEAKS || KASAN_TBI
	/*
	 * the allocation logs are used when:
	 *
	 * - zlog<n>= boot-args are used (and then z_log_on is set)
	 *
	 * - the leak detection was triggered for the zone.
	 *   In that case, the log can't ever be freed,
	 *   but it can be enabled/disabled dynamically.
	 */
	struct btlog       *z_btlog;
	struct btlog       *z_btlog_disabled;
#endif
} __attribute__((aligned((64))));

/*!
 * @typedef zone_security_flags_t
 *
 * @brief
 * Type used to store the immutable security properties of a zone.
 *
 * @description
 * These properties influence the security nature of a zone and can't be
 * modified after lockdown.
 */
typedef struct zone_security_flags {
	uint16_t
	/*
	 * Security sensitive configuration bits
	 */
	    z_submap_idx       :8,  /* a Z_SUBMAP_IDX_* value */
	    z_kheap_id         :2,  /* zone_kheap_id_t when part of a kalloc heap */
	    z_kalloc_type      :1,  /* zones that does types based seggregation */
	    z_lifo             :1,  /* depot and recirculation layer are LIFO */
	    z_pgz_use_guards   :1,  /* this zone uses guards with PGZ */
	    z_submap_from_end  :1,  /* allocate from the left or the right ? */
	    z_noencrypt        :1,  /* do not encrypt pages when hibernating */
	    z_unused           :1;
} zone_security_flags_t;


/*
 * Zsecurity config to enable strict free of iokit objects to zone
 * or heap they were allocated from.
 *
 * Turn ZSECURITY_OPTIONS_STRICT_IOKIT_FREE off on x86 so as not
 * not break third party kexts that haven't yet been recompiled
 * to use the new iokit macros.
 */
#if XNU_PLATFORM_MacOSX && __x86_64__
#   define ZSECURITY_CONFIG_STRICT_IOKIT_FREE           OFF
#else
#   define ZSECURITY_CONFIG_STRICT_IOKIT_FREE           ON
#endif

/*
 * Zsecurity config to enable the read-only allocator
 */
#if KASAN_CLASSIC
#   define ZSECURITY_CONFIG_READ_ONLY                   OFF
#else
#   define ZSECURITY_CONFIG_READ_ONLY                   ON
#endif

/*
 * Zsecurity config to enable making heap feng-shui
 * less reliable.
 */
#if KASAN_CLASSIC
#   define ZSECURITY_CONFIG_SAD_FENG_SHUI               OFF
#   define ZSECURITY_CONFIG_GENERAL_SUBMAPS             1
#else
#   define ZSECURITY_CONFIG_SAD_FENG_SHUI               ON
#   define ZSECURITY_CONFIG_GENERAL_SUBMAPS             4
#endif

/*
 * Zsecurity config to enable adjusting of elements
 * with PGZ-OOB to right-align them in their space.
 */
#if KASAN || defined(__x86_64__)
#   define ZSECURITY_CONFIG_PGZ_OOB_ADJUST              OFF
#else
#   define ZSECURITY_CONFIG_PGZ_OOB_ADJUST              ON
#endif

/*
 * Zsecurity config to enable kalloc type segregation
 */
#if XNU_TARGET_OS_WATCH || KASAN_CLASSIC
#   define ZSECURITY_CONFIG_KT_BUDGET                   85
#   define ZSECURITY_CONFIG_KT_VAR_BUDGET               3
#else
#   define ZSECURITY_CONFIG_KT_BUDGET                   200
#   define ZSECURITY_CONFIG_KT_VAR_BUDGET               3
#endif


__options_decl(kalloc_type_options_t, uint64_t, {
	/*
	 * kalloc type option to switch default accounting to private.
	 */
	KT_OPTIONS_ACCT                         = 0x00000001,
	/*
	 * kalloc type option to print additional stats regarding zone
	 * budget distribution and signatures.
	 */
	KT_OPTIONS_DEBUG                        = 0x00000002,
	/*
	 * kalloc type option to allow loose freeing between heaps
	 */
	KT_OPTIONS_LOOSE_FREE                   = 0x00000004,
});

__enum_decl(kt_var_heap_id_t, uint32_t, {
	/*
	 * Fake "data" heap used to link views of data-only allocation that
	 * have been redirected to KHEAP_DATA_BUFFERS
	 */
	KT_VAR_DATA_HEAP,
	/*
	 * Heap for pointer arrays
	 */
	KT_VAR_PTR_HEAP,
	/*
	 * Indicating first additional heap added
	 */
	KT_VAR__FIRST_FLEXIBLE_HEAP,
});

/*
 * Zone submap indices
 *
 * Z_SUBMAP_IDX_VM
 * this map has the special property that its allocations
 * can be done without ever locking the submap, and doesn't use
 * VM entries in the map (which limits certain VM map operations on it).
 *
 * On ILP32 a single zone lives here (the vm_map_entry_reserved_zone).
 *
 * On LP64 it is also used to restrict VM allocations on LP64 lower
 * in the kernel VA space, for pointer packing purposes.
 *
 * Z_SUBMAP_IDX_GENERAL_{0,1,2,3}
 * used for unrestricted allocations
 *
 * Z_SUBMAP_IDX_DATA
 * used to sequester bags of bytes from all other allocations and allow VA reuse
 * within the map
 *
 * Z_SUBMAP_IDX_READ_ONLY
 * used for the read-only allocator
 */
__enum_decl(zone_submap_idx_t, uint32_t, {
	Z_SUBMAP_IDX_VM,
	Z_SUBMAP_IDX_READ_ONLY,
	Z_SUBMAP_IDX_GENERAL_0,
#if ZSECURITY_CONFIG(SAD_FENG_SHUI)
	Z_SUBMAP_IDX_GENERAL_1,
	Z_SUBMAP_IDX_GENERAL_2,
	Z_SUBMAP_IDX_GENERAL_3,
#endif /* ZSECURITY_CONFIG(SAD_FENG_SHUI) */
	Z_SUBMAP_IDX_DATA,

	Z_SUBMAP_IDX_COUNT,
});

#define KALLOC_MINALIGN     (1 << KALLOC_LOG2_MINALIGN)

/*
 * Variable kalloc_type heap config
 */
struct kheap_info {
	zone_id_t             kh_zstart;
	union {
		kalloc_heap_t       kh_views;
		kalloc_type_var_view_t kt_views;
	};
};
typedef union kalloc_type_views {
	struct kalloc_type_view     *ktv_fixed;
	struct kalloc_type_var_view *ktv_var;
} kalloc_type_views_t;

#define KT_VAR_MAX_HEAPS 8
#define MAX_ZONES       650
extern struct kheap_info        kalloc_type_heap_array[KT_VAR_MAX_HEAPS];
extern zone_id_t _Atomic        num_zones;
extern uint32_t                 zone_view_count;
extern struct zone              zone_array[MAX_ZONES];
extern struct zone_size_params  zone_ro_size_params[ZONE_ID__LAST_RO + 1];
extern zone_security_flags_t    zone_security_array[];
extern const char * const       kalloc_heap_names[KHEAP_ID_COUNT];
extern mach_memory_info_t      *panic_kext_memory_info;
extern vm_size_t                panic_kext_memory_size;
extern vm_offset_t              panic_fault_address;
extern uint16_t                 _zc_mag_size;

#define zone_index_foreach(i) \
	for (zone_id_t i = 1, num_zones_##i = os_atomic_load(&num_zones, acquire); \
	    i < num_zones_##i; i++)

#define zone_foreach(z) \
	for (zone_t z = &zone_array[1], \
	    last_zone_##z = &zone_array[os_atomic_load(&num_zones, acquire)]; \
	    z < last_zone_##z; z++)

__abortlike
extern void zone_invalid_panic(zone_t zone);

__pure2
static inline zone_id_t
zone_index(zone_t z)
{
	unsigned long delta;
	uint64_t quo;

	delta = (unsigned long)z - (unsigned long)zone_array;
	if (delta >= MAX_ZONES * sizeof(*z)) {
		zone_invalid_panic(z);
	}
	quo = Z_FAST_QUO(delta, Z_MAGIC_QUO(sizeof(*z)));
	__builtin_assume(quo < MAX_ZONES);
	return (zone_id_t)quo;
}

__pure2
static inline bool
zone_is_ro(zone_t zone)
{
	return zone >= &zone_array[ZONE_ID__FIRST_RO] &&
	       zone <= &zone_array[ZONE_ID__LAST_RO];
}

static inline bool
zone_addr_size_crosses_page(mach_vm_address_t addr, mach_vm_size_t size)
{
	return atop(addr ^ (addr + size - 1)) != 0;
}

__pure2
static inline uint16_t
zone_elem_redzone(zone_t zone)
{
#if KASAN_CLASSIC
	return zone->z_kasan_redzone;
#else
	(void)zone;
	return 0;
#endif
}

__pure2
static inline uint16_t
zone_elem_inner_offs(zone_t zone)
{
	return zone->z_elem_offs;
}

__pure2
static inline uint16_t
zone_elem_outer_offs(zone_t zone)
{
	return zone_elem_inner_offs(zone) - zone_elem_redzone(zone);
}

__pure2
static inline vm_offset_t
zone_elem_inner_size(zone_t zone)
{
	return zone->z_elem_size;
}

__pure2
static inline vm_offset_t
zone_elem_outer_size(zone_t zone)
{
	return zone_elem_inner_size(zone) + zone_elem_redzone(zone);
}

__pure2
static inline zone_security_flags_t
zone_security_config(zone_t z)
{
	zone_id_t zid = zone_index(z);
	return zone_security_array[zid];
}

static inline uint32_t
zone_count_free(zone_t zone)
{
	return zone->z_elems_free + zone->z_recirc.zd_full * _zc_mag_size;
}

static inline uint32_t
zone_count_allocated(zone_t zone)
{
	return zone->z_elems_avail - zone_count_free(zone);
}

static inline vm_size_t
zone_scale_for_percpu(zone_t zone, vm_size_t size)
{
	if (zone->z_percpu) {
		size *= zpercpu_count();
	}
	return size;
}

static inline vm_size_t
zone_size_wired(zone_t zone)
{
	/*
	 * this either require the zone lock,
	 * or to be used for statistics purposes only.
	 */
	vm_size_t size = ptoa(os_atomic_load(&zone->z_wired_cur, relaxed));
	return zone_scale_for_percpu(zone, size);
}

static inline vm_size_t
zone_size_free(zone_t zone)
{
	return zone_scale_for_percpu(zone,
	           zone_elem_inner_size(zone) * zone_count_free(zone));
}

/* Under KASAN builds, this also accounts for quarantined elements. */
static inline vm_size_t
zone_size_allocated(zone_t zone)
{
	return zone_scale_for_percpu(zone,
	           zone_elem_inner_size(zone) * zone_count_allocated(zone));
}

static inline vm_size_t
zone_size_wasted(zone_t zone)
{
	return zone_size_wired(zone) - zone_scale_for_percpu(zone,
	           zone_elem_outer_size(zone) * zone->z_elems_avail);
}

/*
 * For sysctl kern.zones_collectable_bytes used by memory_maintenance to check if a
 * userspace reboot is needed. The only other way to query for this information
 * is via mach_memory_info() which is unavailable on release kernels.
 */
extern uint64_t get_zones_collectable_bytes(void);

/*!
 * @enum zone_gc_level_t
 *
 * @const ZONE_GC_TRIM
 * Request a trimming GC: it will trim allocations in excess
 * of the working set size estimate only.
 *
 * @const ZONE_GC_DRAIN
 * Request a draining GC: this is an aggressive mode that will
 * cause all caches to be drained and all free pages returned to the system.
 *
 * @const ZONE_GC_JETSAM
 * Request to consider a jetsam, and then fallback to @c ZONE_GC_TRIM or
 * @c ZONE_GC_DRAIN depending on the state of the zone map.
 * To avoid deadlocks, only @c vm_pageout_garbage_collect() should ever
 * request a @c ZONE_GC_JETSAM level.
 */
__enum_closed_decl(zone_gc_level_t, uint32_t, {
	ZONE_GC_TRIM,
	ZONE_GC_DRAIN,
	ZONE_GC_JETSAM,
});

/*!
 * @function zone_gc
 *
 * @brief
 * Reduces memory used by zones by trimming caches and freelists.
 *
 * @discussion
 * @c zone_gc() is called:
 * - by the pageout daemon when the system needs more free pages.
 * - by the VM when contiguous page allocation requests get stuck
 *   (see vm_page_find_contiguous()).
 *
 * @param level         The zone GC level requested.
 */
extern void     zone_gc(zone_gc_level_t level);

extern void     zone_gc_trim(void);
extern void     zone_gc_drain(void);

#define ZONE_WSS_UPDATE_PERIOD  15
/*!
 * @function compute_zone_working_set_size
 *
 * @brief
 * Recomputes the working set size for every zone
 *
 * @discussion
 * This runs about every @c ZONE_WSS_UPDATE_PERIOD seconds (10),
 * computing an exponential moving average with a weight of 75%,
 * so that the history of the last minute is the dominating factor.
 */
extern void     compute_zone_working_set_size(void *);

/* Debug logging for zone-map-exhaustion jetsams. */
extern void     get_zone_map_size(uint64_t *current_size, uint64_t *capacity);
extern void     get_largest_zone_info(char *zone_name, size_t zone_name_len, uint64_t *zone_size);

/* Bootstrap zone module (create zone zone) */
extern void     zone_bootstrap(void);

/* Force-enable caching on a zone, generally unsafe to call directly */
extern void     zone_enable_caching(zone_t zone);

/*!
 * @function zone_early_mem_init
 *
 * @brief
 * Steal memory from pmap (prior to initialization of zalloc)
 * for the special vm zones that allow bootstrap memory and store
 * the range so as to facilitate range checking in zfree.
 *
 * @param size              the size to steal (must be a page multiple)
 */
__startup_func
extern vm_offset_t zone_early_mem_init(
	vm_size_t       size);

/*!
 * @function zone_get_early_alloc_size
 *
 * @brief
 * Compute the correct size (greater than @c ptoa(min_pages)) that is a multiple
 * of the allocation granule for the zone with the given creation flags and
 * element size.
 */
__startup_func
extern vm_size_t zone_get_early_alloc_size(
	const char          *name __unused,
	vm_size_t            elem_size,
	zone_create_flags_t  flags,
	vm_size_t            min_elems);

/*!
 * @function zone_cram_early
 *
 * @brief
 * Cram memory allocated with @c zone_early_mem_init() into a zone.
 *
 * @param zone          The zone to cram memory into.
 * @param newmem        The base address for the memory to cram.
 * @param size          The size of the memory to cram into the zone.
 */
__startup_func
extern void     zone_cram_early(
	zone_t          zone,
	vm_offset_t     newmem,
	vm_size_t       size);

extern bool     zone_maps_owned(
	vm_address_t    addr,
	vm_size_t       size);

#if KASAN_LIGHT
extern bool     kasan_zone_maps_owned(
	vm_address_t    addr,
	vm_size_t       size);
#endif /* KASAN_LIGHT */

extern void     zone_map_sizes(
	vm_map_size_t  *psize,
	vm_map_size_t  *pfree,
	vm_map_size_t  *plargest_free);

extern bool
zone_map_nearing_exhaustion(void);

static inline vm_tag_t
zalloc_flags_get_tag(zalloc_flags_t flags)
{
	return (vm_tag_t)((flags & Z_VM_TAG_MASK) >> Z_VM_TAG_SHIFT);
}

extern struct kalloc_result zalloc_ext(
	zone_t          zone,
	zone_stats_t    zstats,
	zalloc_flags_t  flags);

#if KASAN
#define ZFREE_PACK_SIZE(esize, usize)   (((uint64_t)(usize) << 32) | (esize))
#define ZFREE_ELEM_SIZE(combined)       ((uint32_t)(combined))
#define ZFREE_USER_SIZE(combined)       ((combined) >> 32)
#else
#define ZFREE_PACK_SIZE(esize, usize)   (esize)
#define ZFREE_ELEM_SIZE(combined)       (combined)
#endif

extern void     zfree_ext(
	zone_t          zone,
	zone_stats_t    zstats,
	void           *addr,
	uint64_t        combined_size);

extern zone_id_t zone_id_for_element(
	void           *addr,
	vm_size_t       esize);

#if ZSECURITY_CONFIG(PGZ_OOB_ADJUST)
extern void *zone_element_pgz_oob_adjust(
	void           *addr,
	vm_size_t       req_size,
	vm_size_t       elem_size);
#endif /* !ZSECURITY_CONFIG(PGZ_OOB_ADJUST) */

extern void zone_element_bounds_check(
	vm_address_t    addr,
	vm_size_t       len);

extern vm_size_t zone_element_size(
	void           *addr,
	zone_t         *z,
	bool            clear_oob,
	vm_offset_t    *oob_offs);

/*!
 * @function zone_spans_ro_va
 *
 * @abstract
 * This function is used to check whether the specified address range
 * spans through the read-only zone range.
 *
 * @discussion
 * This only checks for the range specified within ZONE_ADDR_READONLY.
 * The parameters addr_start and addr_end are stripped off of PAC bits
 * before the check is made.
 */
extern bool zone_spans_ro_va(
	vm_offset_t     addr_start,
	vm_offset_t     addr_end);

/*!
 * @function __zalloc_ro_mut_atomic
 *
 * @abstract
 * This function is called from the pmap to perform the specified atomic
 * operation on memory from the read-only allocator.
 *
 * @discussion
 * This function is for internal use only and should not be called directly.
 */
static inline uint64_t
__zalloc_ro_mut_atomic(vm_offset_t dst, zro_atomic_op_t op, uint64_t value)
{
#define __ZALLOC_RO_MUT_OP(op, op2) \
	case ZRO_ATOMIC_##op##_8: \
	        return os_atomic_##op2((uint8_t *)dst, (uint8_t)value, seq_cst); \
	case ZRO_ATOMIC_##op##_16: \
	        return os_atomic_##op2((uint16_t *)dst, (uint16_t)value, seq_cst); \
	case ZRO_ATOMIC_##op##_32: \
	        return os_atomic_##op2((uint32_t *)dst, (uint32_t)value, seq_cst); \
	case ZRO_ATOMIC_##op##_64: \
	        return os_atomic_##op2((uint64_t *)dst, (uint64_t)value, seq_cst)

	switch (op) {
		__ZALLOC_RO_MUT_OP(OR, or_orig);
		__ZALLOC_RO_MUT_OP(XOR, xor_orig);
		__ZALLOC_RO_MUT_OP(AND, and_orig);
		__ZALLOC_RO_MUT_OP(ADD, add_orig);
		__ZALLOC_RO_MUT_OP(XCHG, xchg);
	default:
		panic("%s: Invalid atomic operation: %d", __func__, op);
	}

#undef __ZALLOC_RO_MUT_OP
}

/*!
 * @function zone_owns
 *
 * @abstract
 * This function is a soft version of zone_require that checks if a given
 * pointer belongs to the specified zone and should not be used outside
 * allocator code.
 *
 * @discussion
 * Note that zone_owns() can only work with:
 * - zones not allowing foreign memory
 * - zones in the general submap.
 *
 * @param zone          the zone the address needs to belong to.
 * @param addr          the element address to check.
 */
extern bool     zone_owns(
	zone_t          zone,
	void           *addr);

/**!
 * @function zone_submap
 *
 * @param zsflags       the security flags of a specified zone.
 * @returns             the zone (sub)map this zone allocates from.
 */
__pure2
extern vm_map_t zone_submap(
	zone_security_flags_t   zsflags);

#ifndef VM_TAG_SIZECLASSES
#error MAX_TAG_ZONES
#endif
#if VM_TAG_SIZECLASSES

extern uint16_t zone_index_from_tag_index(
	uint32_t        tag_zone_index);

#endif /* VM_TAG_SIZECLASSES */

extern lck_grp_t zone_locks_grp;

static inline void
zone_lock(zone_t zone)
{
#if KASAN_FAKESTACK
	spl_t s = 0;
	if (zone->z_kasan_fakestacks) {
		s = splsched();
	}
#endif /* KASAN_FAKESTACK */
	hw_lck_ticket_lock(&zone->z_lock, &zone_locks_grp);
#if KASAN_FAKESTACK
	zone->z_kasan_spl = s;
#endif /* KASAN_FAKESTACK */
}

static inline void
zone_unlock(zone_t zone)
{
#if KASAN_FAKESTACK
	spl_t s = zone->z_kasan_spl;
	zone->z_kasan_spl = 0;
#endif /* KASAN_FAKESTACK */
	hw_lck_ticket_unlock(&zone->z_lock);
#if KASAN_FAKESTACK
	if (zone->z_kasan_fakestacks) {
		splx(s);
	}
#endif /* KASAN_FAKESTACK */
}

#define MAX_ZONE_NAME   32      /* max length of a zone name we can take from the boot-args */

int track_this_zone(const char *zonename, const char *logname);
extern bool panic_include_kalloc_types;
extern zone_t kalloc_type_src_zone;
extern zone_t kalloc_type_dst_zone;

#if DEBUG || DEVELOPMENT
extern vm_size_t zone_element_info(void *addr, vm_tag_t * ptag);
#endif /* DEBUG || DEVELOPMENT */

#pragma GCC visibility pop

__END_DECLS

#endif  /* _KERN_ZALLOC_INTERNAL_H_ */
