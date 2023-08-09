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
/*
 *	File:	kern/zalloc.c
 *	Author:	Avadis Tevanian, Jr.
 *
 *	Zone-based memory allocator.  A zone is a collection of fixed size
 *	data blocks for which quick allocation/deallocation is possible.
 */

#define ZALLOC_ALLOW_DEPRECATED 1
#if !ZALLOC_TEST
#include <mach/mach_types.h>
#include <mach/vm_param.h>
#include <mach/kern_return.h>
#include <mach/mach_host_server.h>
#include <mach/task_server.h>
#include <mach/machine/vm_types.h>
#include <machine/machine_routines.h>
#include <mach/vm_map.h>
#include <mach/sdt.h>
#if __x86_64__
#include <i386/cpuid.h>
#endif

#include <kern/bits.h>
#include <kern/btlog.h>
#include <kern/startup.h>
#include <kern/kern_types.h>
#include <kern/assert.h>
#include <kern/backtrace.h>
#include <kern/host.h>
#include <kern/macro_help.h>
#include <kern/sched.h>
#include <kern/locks.h>
#include <kern/sched_prim.h>
#include <kern/misc_protos.h>
#include <kern/thread_call.h>
#include <kern/zalloc_internal.h>
#include <kern/kalloc.h>
#include <kern/debug.h>

#include <prng/random.h>

#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <vm/vm_page.h>
#include <vm/vm_pageout.h>
#include <vm/vm_compressor.h> /* C_SLOT_PACKED_PTR* */

#include <pexpert/pexpert.h>

#include <machine/machparam.h>
#include <machine/machine_routines.h>  /* ml_cpu_get_info */

#include <os/atomic.h>

#include <libkern/OSDebug.h>
#include <libkern/OSAtomic.h>
#include <libkern/section_keywords.h>
#include <sys/kdebug.h>
#include <sys/code_signing.h>

#include <san/kasan.h>
#include <libsa/stdlib.h>
#include <sys/errno.h>

#include <IOKit/IOBSD.h>
#include <arm64/amcc_rorgn.h>

#if DEBUG
#define z_debug_assert(expr)  assert(expr)
#else
#define z_debug_assert(expr)  (void)(expr)
#endif

/* Returns pid of the task with the largest number of VM map entries.  */
extern pid_t find_largest_process_vm_map_entries(void);

/*
 * Callout to jetsam. If pid is -1, we wake up the memorystatus thread to do asynchronous kills.
 * For any other pid we try to kill that process synchronously.
 */
extern boolean_t memorystatus_kill_on_zone_map_exhaustion(pid_t pid);

extern zone_t vm_object_zone;
extern zone_t ipc_service_port_label_zone;

ZONE_DEFINE_TYPE(percpu_u64_zone, "percpu.64", uint64_t,
    ZC_PERCPU | ZC_ALIGNMENT_REQUIRED | ZC_KASAN_NOREDZONE);

#if KASAN_TBI
#define ZONE_MIN_ELEM_SIZE      (sizeof(uint64_t) * 2)
#define ZONE_ALIGN_SIZE         ZONE_MIN_ELEM_SIZE
#else /* KASAN_TBI */
#define ZONE_MIN_ELEM_SIZE      sizeof(uint64_t)
#define ZONE_ALIGN_SIZE         ZONE_MIN_ELEM_SIZE
#endif /* KASAN_TBI */

#define ZONE_MAX_ALLOC_SIZE     (32 * 1024)
#if ZSECURITY_CONFIG(SAD_FENG_SHUI)
#define ZONE_CHUNK_ALLOC_SIZE   (256 * 1024)
#define ZONE_GUARD_DENSE        (32  * 1024)
#define ZONE_GUARD_SPARSE       (64  * 1024)
#endif /* ZSECURITY_CONFIG(SAD_FENG_SHUI) */

#if XNU_PLATFORM_MacOSX
#define ZONE_MAP_MAX            (32ULL << 30)
#define ZONE_MAP_VA_SIZE        (128ULL << 30)
#else /* XNU_PLATFORM_MacOSX */
#define ZONE_MAP_MAX            (8ULL << 30)
#define ZONE_MAP_VA_SIZE        (24ULL << 30)
#endif /* !XNU_PLATFORM_MacOSX */

__enum_closed_decl(zm_len_t, uint16_t, {
	ZM_CHUNK_FREE           = 0x0,
	/* 1 through 8 are valid lengths */
	ZM_CHUNK_LEN_MAX        = 0x8,

	/* PGZ magical values */
	ZM_PGZ_FREE             = 0x0,
	ZM_PGZ_ALLOCATED        = 0xa, /* [a]llocated   */
	ZM_PGZ_GUARD            = 0xb, /* oo[b]         */
	ZM_PGZ_DOUBLE_FREE      = 0xd, /* [d]ouble_free */

	/* secondary page markers */
	ZM_SECONDARY_PAGE       = 0xe,
	ZM_SECONDARY_PCPU_PAGE  = 0xf,
});

static_assert(MAX_ZONES < (1u << 10), "MAX_ZONES must fit in zm_index");

struct zone_page_metadata {
	union {
		struct {
			/* The index of the zone this metadata page belongs to */
			zone_id_t       zm_index : 10;

			/*
			 * This chunk ends with a guard page.
			 */
			uint16_t        zm_guarded : 1;

			/*
			 * Whether `zm_bitmap` is an inline bitmap
			 * or a packed bitmap reference
			 */
			uint16_t        zm_inline_bitmap : 1;

			/*
			 * Zones allocate in "chunks" of zone_t::z_chunk_pages
			 * consecutive pages, or zpercpu_count() pages if the
			 * zone is percpu.
			 *
			 * The first page of it has its metadata set with:
			 * - 0 if none of the pages are currently wired
			 * - the number of wired pages in the chunk
			 *   (not scaled for percpu).
			 *
			 * Other pages in the chunk have their zm_chunk_len set
			 * to ZM_SECONDARY_PAGE or ZM_SECONDARY_PCPU_PAGE
			 * depending on whether the zone is percpu or not.
			 * For those, zm_page_index holds the index of that page
			 * in the run, and zm_subchunk_len the remaining length
			 * within the chunk.
			 *
			 * Metadata used for PGZ pages can have 3 values:
			 * - ZM_PGZ_FREE:         slot is free
			 * - ZM_PGZ_ALLOCATED:    slot holds an allocated element
			 *                        at offset (zm_pgz_orig_addr & PAGE_MASK)
			 * - ZM_PGZ_DOUBLE_FREE:  slot detected a double free
			 *                        (will panic).
			 */
			zm_len_t        zm_chunk_len : 4;
		};
		uint16_t zm_bits;
	};

	union {
#define ZM_ALLOC_SIZE_LOCK      1u
		uint16_t zm_alloc_size; /* first page only */
		struct {
			uint8_t zm_page_index;   /* secondary pages only */
			uint8_t zm_subchunk_len; /* secondary pages only */
		};
		uint16_t zm_oob_offs;   /* in guard pages  */
	};
	union {
		uint32_t zm_bitmap;     /* most zones      */
		uint32_t zm_bump;       /* permanent zones */
	};

	union {
		struct {
			zone_pva_t      zm_page_next;
			zone_pva_t      zm_page_prev;
		};
		vm_offset_t zm_pgz_orig_addr;
		struct zone_page_metadata *zm_pgz_slot_next;
	};
};
static_assert(sizeof(struct zone_page_metadata) == 16, "validate packing");

/*!
 * @typedef zone_magazine_t
 *
 * @brief
 * Magazine of cached allocations.
 *
 * @field zm_next       linkage used by magazine depots.
 * @field zm_elems      an array of @c zc_mag_size() elements.
 */
struct zone_magazine {
	zone_magazine_t         zm_next;
	smr_seq_t               zm_seq;
	vm_offset_t             zm_elems[0];
};

/*!
 * @typedef zone_cache_t
 *
 * @brief
 * Magazine of cached allocations.
 *
 * @discussion
 * Below is a diagram of the caching system. This design is inspired by the
 * paper "Magazines and Vmem: Extending the Slab Allocator to Many CPUs and
 * Arbitrary Resources" by Jeff Bonwick and Jonathan Adams and the FreeBSD UMA
 * zone allocator (itself derived from this seminal work).
 *
 * It is divided into 3 layers:
 * - the per-cpu layer,
 * - the recirculation depot layer,
 * - the Zone Allocator.
 *
 * The per-cpu and recirculation depot layer use magazines (@c zone_magazine_t),
 * which are stacks of up to @c zc_mag_size() elements.
 *
 * <h2>CPU layer</h2>
 *
 * The CPU layer (@c zone_cache_t) looks like this:
 *
 *      ╭─ a ─ f ─┬───────── zm_depot ──────────╮
 *      │ ╭─╮ ╭─╮ │ ╭─╮ ╭─╮ ╭─╮ ╭─╮ ╭─╮         │
 *      │ │#│ │#│ │ │#│ │#│ │#│ │#│ │#│         │
 *      │ │#│ │ │ │ │#│ │#│ │#│ │#│ │#│         │
 *      │ │ │ │ │ │ │#│ │#│ │#│ │#│ │#│         │
 *      │ ╰─╯ ╰─╯ │ ╰─╯ ╰─╯ ╰─╯ ╰─╯ ╰─╯         │
 *      ╰─────────┴─────────────────────────────╯
 *
 * It has two pre-loaded magazines (a)lloc and (f)ree which we allocate from,
 * or free to. Serialization is achieved through disabling preemption, and only
 * the current CPU can acces those allocations. This is represented on the left
 * hand side of the diagram above.
 *
 * The right hand side is the per-cpu depot. It consists of @c zm_depot_count
 * full magazines, and is protected by the @c zm_depot_lock for access.
 * The lock is expected to absolutely never be contended, as only the local CPU
 * tends to access the local per-cpu depot in regular operation mode.
 *
 * However unlike UMA, our implementation allows for the zone GC to reclaim
 * per-CPU magazines aggresively, which is serialized with the @c zm_depot_lock.
 *
 *
 * <h2>Recirculation Depot</h2>
 *
 * The recirculation depot layer is a list similar to the per-cpu depot,
 * however it is different in two fundamental ways:
 *
 * - it is protected by the regular zone lock,
 * - elements referenced by the magazines in that layer appear free
 *   to the zone layer.
 *
 *
 * <h2>Magazine circulation and sizing</h2>
 *
 * The caching system sizes itself dynamically. Operations that allocate/free
 * a single element call @c zone_lock_nopreempt_check_contention() which records
 * contention on the lock by doing a trylock and recording its success.
 *
 * This information is stored in the @c z_recirc_cont_cur field of the zone,
 * and a windowed moving average is maintained in @c z_contention_wma.
 * The periodically run function @c compute_zone_working_set_size() will then
 * take this into account to decide to grow the number of buckets allowed
 * in the depot or shrink it based on the @c zc_grow_level and @c zc_shrink_level
 * thresholds.
 *
 * The per-cpu layer will attempt to work with its depot, finding both full and
 * empty magazines cached there. If it can't get what it needs, then it will
 * mediate with the zone recirculation layer. Such recirculation is done in
 * batches in order to amortize lock holds.
 * (See @c {zalloc,zfree}_cached_depot_recirculate()).
 *
 * The recirculation layer keeps a track of what the minimum amount of magazines
 * it had over time was for each of the full and empty queues. This allows for
 * @c compute_zone_working_set_size() to return memory to the system when a zone
 * stops being used as much.
 *
 * <h2>Security considerations</h2>
 *
 * The zone caching layer has been designed to avoid returning elements in
 * a strict LIFO behavior: @c zalloc() will allocate from the (a) magazine,
 * and @c zfree() free to the (f) magazine, and only swap them when the
 * requested operation cannot be fulfilled.
 *
 * The per-cpu overflow depot or the recirculation depots are similarly used
 * in FIFO order.
 *
 * @field zc_depot_lock     a lock to access @c zc_depot, @c zc_depot_cur.
 * @field zc_alloc_cur      denormalized number of elements in the (a) magazine
 * @field zc_free_cur       denormalized number of elements in the (f) magazine
 * @field zc_alloc_elems    a pointer to the array of elements in (a)
 * @field zc_free_elems     a pointer to the array of elements in (f)
 *
 * @field zc_depot          a list of @c zc_depot_cur full magazines
 */
typedef struct zone_cache {
	hw_lck_ticket_t            zc_depot_lock;
	uint16_t                   zc_alloc_cur;
	uint16_t                   zc_free_cur;
	vm_offset_t               *zc_alloc_elems;
	vm_offset_t               *zc_free_elems;
	struct zone_depot          zc_depot;
	smr_t                      zc_smr;
	zone_smr_free_cb_t XNU_PTRAUTH_SIGNED_FUNCTION_PTR("zc_free") zc_free;
} __attribute__((aligned(64))) * zone_cache_t;

#if !__x86_64__
static
#endif
__security_const_late struct {
	struct mach_vm_range       zi_map_range;  /* all zone submaps     */
	struct mach_vm_range       zi_ro_range;   /* read-only range      */
	struct mach_vm_range       zi_meta_range; /* debugging only       */
	struct mach_vm_range       zi_bits_range; /* bits buddy allocator */
	struct mach_vm_range       zi_xtra_range; /* vm tracking metadata */
	struct mach_vm_range       zi_pgz_range;
	struct zone_page_metadata *zi_pgz_meta;

	/*
	 * The metadata lives within the zi_meta_range address range.
	 *
	 * The correct formula to find a metadata index is:
	 *     absolute_page_index - page_index(zi_map_range.min_address)
	 *
	 * And then this index is used to dereference zi_meta_range.min_address
	 * as a `struct zone_page_metadata` array.
	 *
	 * To avoid doing that substraction all the time in the various fast-paths,
	 * zi_meta_base are pre-offset with that minimum page index to avoid redoing
	 * that math all the time.
	 */
	struct zone_page_metadata *zi_meta_base;
} zone_info;

__startup_data static struct mach_vm_range  zone_map_range;
__startup_data static vm_map_size_t         zone_meta_size;
__startup_data static vm_map_size_t         zone_bits_size;
__startup_data static vm_map_size_t         zone_xtra_size;

/*
 * Initial array of metadata for stolen memory.
 *
 * The numbers here have to be kept in sync with vm_map_steal_memory()
 * so that we have reserved enough metadata.
 *
 * After zone_init() has run (which happens while the kernel is still single
 * threaded), the metadata is moved to its final dynamic location, and
 * this array is unmapped with the rest of __startup_data at lockdown.
 */
#define ZONE_EARLY_META_INLINE_COUNT    64
__startup_data
static struct zone_page_metadata
    zone_early_meta_array_startup[ZONE_EARLY_META_INLINE_COUNT];

#if __x86_64__
/*
 * On Intel we can't "free" pmap stolen pages,
 * so instead we use a static array in __KLDDATA
 * which gets reclaimed at lockdown time.
 */
__startup_data __attribute__((aligned(PAGE_SIZE)))
static uint8_t zone_early_pages_to_cram[PAGE_SIZE * 16];
#endif

/*
 *	The zone_locks_grp allows for collecting lock statistics.
 *	All locks are associated to this group in zinit.
 *	Look at tools/lockstat for debugging lock contention.
 */
LCK_GRP_DECLARE(zone_locks_grp, "zone_locks");
static LCK_MTX_DECLARE(zone_metadata_region_lck, &zone_locks_grp);

/*
 *	The zone metadata lock protects:
 *	- metadata faulting,
 *	- VM submap VA allocations,
 *	- early gap page queue list
 */
#define zone_meta_lock()   lck_mtx_lock(&zone_metadata_region_lck);
#define zone_meta_unlock() lck_mtx_unlock(&zone_metadata_region_lck);

/*
 *	Exclude more than one concurrent garbage collection
 */
static LCK_GRP_DECLARE(zone_gc_lck_grp, "zone_gc");
static LCK_MTX_DECLARE(zone_gc_lock, &zone_gc_lck_grp);
static LCK_SPIN_DECLARE(zone_exhausted_lock, &zone_gc_lck_grp);

/*
 * Panic logging metadata
 */
bool panic_include_zprint = false;
bool panic_include_kalloc_types = false;
zone_t kalloc_type_src_zone = ZONE_NULL;
zone_t kalloc_type_dst_zone = ZONE_NULL;
mach_memory_info_t *panic_kext_memory_info = NULL;
vm_size_t panic_kext_memory_size = 0;
vm_offset_t panic_fault_address = 0;

/*
 *      Protects zone_array, num_zones, num_zones_in_use, and
 *      zone_destroyed_bitmap
 */
static SIMPLE_LOCK_DECLARE(all_zones_lock, 0);
static zone_id_t        num_zones_in_use;
zone_id_t _Atomic       num_zones;
SECURITY_READ_ONLY_LATE(unsigned int) zone_view_count;

/*
 * Initial globals for zone stats until we can allocate the real ones.
 * Those get migrated inside the per-CPU ones during zone_init() and
 * this array is unmapped with the rest of __startup_data at lockdown.
 */

/* zone to allocate zone_magazine structs from */
static SECURITY_READ_ONLY_LATE(zone_t) zc_magazine_zone;
/*
 * Until pid1 is made, zone caching is off,
 * until compute_zone_working_set_size() runs for the firt time.
 *
 * -1 represents the "never enabled yet" value.
 */
static int8_t zone_caching_disabled = -1;

__startup_data
static struct zone_stats zone_stats_startup[MAX_ZONES];
struct zone              zone_array[MAX_ZONES];
SECURITY_READ_ONLY_LATE(zone_security_flags_t) zone_security_array[MAX_ZONES] = {
	[0 ... MAX_ZONES - 1] = {
		.z_kheap_id       = KHEAP_ID_NONE,
		.z_noencrypt      = false,
		.z_submap_idx     = Z_SUBMAP_IDX_GENERAL_0,
		.z_kalloc_type    = false,
	},
};
SECURITY_READ_ONLY_LATE(struct zone_size_params) zone_ro_size_params[ZONE_ID__LAST_RO + 1];
SECURITY_READ_ONLY_LATE(zone_cache_ops_t) zcache_ops[ZONE_ID__FIRST_DYNAMIC];

/* Initialized in zone_bootstrap(), how many "copies" the per-cpu system does */
static SECURITY_READ_ONLY_LATE(unsigned) zpercpu_early_count;

/* Used to keep track of destroyed slots in the zone_array */
static bitmap_t zone_destroyed_bitmap[BITMAP_LEN(MAX_ZONES)];

/* number of zone mapped pages used by all zones */
static size_t _Atomic zone_pages_jetsam_threshold = ~0;
size_t zone_pages_wired;
size_t zone_guard_pages;

/* Time in (ms) after which we panic for zone exhaustions */
TUNABLE(int, zone_exhausted_timeout, "zet", 5000);

#if VM_TAG_SIZECLASSES
/*
 * Zone tagging allows for per "tag" accounting of allocations for the kalloc
 * zones only.
 *
 * There are 3 kinds of tags that can be used:
 * - pre-registered VM_KERN_MEMORY_*
 * - dynamic tags allocated per call sites in core-kernel (using vm_tag_alloc())
 * - per-kext tags computed by IOKit (using the magic Z_VM_TAG_BT_BIT marker).
 *
 * The VM tracks the statistics in lazily allocated structures.
 * See vm_tag_will_update_zone(), vm_tag_update_zone_size().
 *
 * If for some reason the requested tag cannot be accounted for,
 * the tag is forced to VM_KERN_MEMORY_KALLOC which is pre-allocated.
 *
 * Each allocated element also remembers the tag it was assigned,
 * which lets zalloc/zfree update statistics correctly.
 */

/* enable tags for zones that ask for it */
static TUNABLE(bool, zone_tagging_on, "-zt", false);

/*
 * Array of all sizeclasses used by kalloc variants so that we can
 * have accounting per size class for each kalloc callsite
 */
static uint16_t zone_tags_sizeclasses[VM_TAG_SIZECLASSES];
#endif /* VM_TAG_SIZECLASSES */

#if DEBUG || DEVELOPMENT
static int zalloc_simulate_vm_pressure;
#endif /* DEBUG || DEVELOPMENT */

#define Z_TUNABLE(t, n, d) \
	TUNABLE(t, _##n, #n, d); \
	__pure2 static inline t n(void) { return _##n; }

/*
 * Zone caching tunables
 *
 * zc_mag_size():
 *   size of magazines, larger to reduce contention at the expense of memory
 *
 * zc_enable_level
 *   number of contentions per second after which zone caching engages
 *   automatically.
 *
 *   0 to disable.
 *
 * zc_grow_level
 *   number of contentions per second x cpu after which the number of magazines
 *   allowed in the depot can grow. (in "Z_WMA_UNIT" units).
 *
 * zc_shrink_level
 *   number of contentions per second x cpu below which the number of magazines
 *   allowed in the depot will shrink. (in "Z_WMA_UNIT" units).
 *
 * zc_pcpu_max
 *   maximum memory size in bytes that can hang from a CPU,
 *   which will affect how many magazines are allowed in the depot.
 *
 *   The alloc/free magazines are assumed to be on average half-empty
 *   and to count for "1" unit of magazines.
 *
 * zc_autotrim_size
 *   Size allowed to hang extra from the recirculation depot before
 *   auto-trim kicks in.
 *
 * zc_autotrim_buckets
 *
 *   How many buckets in excess of the working-set are allowed
 *   before auto-trim kicks in for empty buckets.
 *
 * zc_free_batch_size
 *   The size of batches of frees/reclaim that can be done keeping
 *   the zone lock held (and preemption disabled).
 */
Z_TUNABLE(uint16_t, zc_mag_size, 8);
static Z_TUNABLE(uint32_t, zc_enable_level, 10);
static Z_TUNABLE(uint32_t, zc_grow_level, 5 * Z_WMA_UNIT);
static Z_TUNABLE(uint32_t, zc_shrink_level, Z_WMA_UNIT / 2);
static Z_TUNABLE(uint32_t, zc_pcpu_max, 128 << 10);
static Z_TUNABLE(uint32_t, zc_autotrim_size, 16 << 10);
static Z_TUNABLE(uint32_t, zc_autotrim_buckets, 8);
static Z_TUNABLE(uint32_t, zc_free_batch_size, 256);

static SECURITY_READ_ONLY_LATE(size_t)    zone_pages_wired_max;
static SECURITY_READ_ONLY_LATE(vm_map_t)  zone_submaps[Z_SUBMAP_IDX_COUNT];
static SECURITY_READ_ONLY_LATE(vm_map_t)  zone_meta_map;
static char const * const zone_submaps_names[Z_SUBMAP_IDX_COUNT] = {
	[Z_SUBMAP_IDX_VM]               = "VM",
	[Z_SUBMAP_IDX_READ_ONLY]        = "RO",
#if ZSECURITY_CONFIG(SAD_FENG_SHUI)
	[Z_SUBMAP_IDX_GENERAL_0]        = "GEN0",
	[Z_SUBMAP_IDX_GENERAL_1]        = "GEN1",
	[Z_SUBMAP_IDX_GENERAL_2]        = "GEN2",
	[Z_SUBMAP_IDX_GENERAL_3]        = "GEN3",
#else
	[Z_SUBMAP_IDX_GENERAL_0]        = "GEN",
#endif /* ZSECURITY_CONFIG(SAD_FENG_SHUI) */
	[Z_SUBMAP_IDX_DATA]             = "DATA",
};

#if __x86_64__
#define ZONE_ENTROPY_CNT 8
#else
#define ZONE_ENTROPY_CNT 2
#endif
static struct zone_bool_gen {
	struct bool_gen zbg_bg;
	uint32_t zbg_entropy[ZONE_ENTROPY_CNT];
} zone_bool_gen[MAX_CPUS];

#if CONFIG_PROB_GZALLOC
/*
 * Probabilistic gzalloc
 * =====================
 *
 *
 * Probabilistic guard zalloc samples allocations and will protect them by
 * double-mapping the page holding them and returning the secondary virtual
 * address to its callers.
 *
 * Its data structures are lazily allocated if the `pgz` or `pgz1` boot-args
 * are set.
 *
 *
 * Unlike GZalloc, PGZ uses a fixed amount of memory, and is compatible with
 * most zalloc/kalloc features:
 * - zone_require is functional
 * - zone caching or zone tagging is compatible
 * - non-blocking allocation work (they will always return NULL with gzalloc).
 *
 * PGZ limitations:
 * - VA sequestering isn't respected, as the slots (which are in limited
 *   quantity) will be reused for any type, however the PGZ quarantine
 *   somewhat mitigates the impact.
 * - zones with elements larger than a page cannot be protected.
 *
 *
 * Tunables:
 * --------
 *
 * pgz=1:
 *   Turn on probabilistic guard malloc for all zones
 *
 *   (default on for DEVELOPMENT, off for RELEASE, or if pgz1... are specified)
 *
 * pgz_sample_rate=0 to 2^31
 *   average sample rate between two guarded allocations.
 *   0 means every allocation.
 *
 *   The default is a random number between 1000 and 10,000
 *
 * pgz_slots
 *   how many allocations to protect.
 *
 *   Each costs:
 *   - a PTE in the pmap (when allocated)
 *   - 2 zone page meta's (every other page is a "guard" one, 32B total)
 *   - 64 bytes per backtraces.
 *   On LP64 this is <16K per 100 slots.
 *
 *   The default is ~200 slots per G of physical ram (32k / G)
 *
 *   TODO:
 *   - try harder to allocate elements at the "end" to catch OOB more reliably.
 *
 * pgz_quarantine
 *   how many slots should be free at any given time.
 *
 *   PGZ will round robin through free slots to be reused, but free slots are
 *   important to detect use-after-free by acting as a quarantine.
 *
 *   By default, PGZ will keep 33% of the slots around at all time.
 *
 * pgz1=<name>, pgz2=<name>, ..., pgzn=<name>...
 *   Specific zones for which to enable probabilistic guard malloc.
 *   There must be no numbering gap (names after the gap will be ignored).
 */
#if DEBUG || DEVELOPMENT
static TUNABLE(bool, pgz_all, "pgz", true);
#else
static TUNABLE(bool, pgz_all, "pgz", false);
#endif
static TUNABLE(uint32_t, pgz_sample_rate, "pgz_sample_rate", 0);
static TUNABLE(uint32_t, pgz_slots, "pgz_slots", UINT32_MAX);
static TUNABLE(uint32_t, pgz_quarantine, "pgz_quarantine", 0);
#endif /* CONFIG_PROB_GZALLOC */

static zone_t zone_find_largest(uint64_t *zone_size);

#endif /* !ZALLOC_TEST */
#pragma mark Zone metadata
#if !ZALLOC_TEST

static inline bool
zone_has_index(zone_t z, zone_id_t zid)
{
	return zone_array + zid == z;
}

__abortlike
void
zone_invalid_panic(zone_t zone)
{
	panic("zone %p isn't in the zone_array", zone);
}

__abortlike
static void
zone_metadata_corruption(zone_t zone, struct zone_page_metadata *meta,
    const char *kind)
{
	panic("zone metadata corruption: %s (meta %p, zone %s%s)",
	    kind, meta, zone_heap_name(zone), zone->z_name);
}

__abortlike
static void
zone_invalid_element_addr_panic(zone_t zone, vm_offset_t addr)
{
	panic("zone element pointer validation failed (addr: %p, zone %s%s)",
	    (void *)addr, zone_heap_name(zone), zone->z_name);
}

__abortlike
static void
zone_page_metadata_index_confusion_panic(zone_t zone, vm_offset_t addr,
    struct zone_page_metadata *meta)
{
	zone_security_flags_t zsflags = zone_security_config(zone), src_zsflags;
	zone_id_t zidx;
	zone_t src_zone;

	if (zsflags.z_kalloc_type) {
		panic_include_kalloc_types = true;
		kalloc_type_dst_zone = zone;
	}

	zidx = meta->zm_index;
	if (zidx >= os_atomic_load(&num_zones, relaxed)) {
		panic("%p expected in zone %s%s[%d], but metadata has invalid zidx: %d",
		    (void *)addr, zone_heap_name(zone), zone->z_name, zone_index(zone),
		    zidx);
	}

	src_zone = &zone_array[zidx];
	src_zsflags = zone_security_array[zidx];
	if (src_zsflags.z_kalloc_type) {
		panic_include_kalloc_types = true;
		kalloc_type_src_zone = src_zone;
	}

	panic("%p not in the expected zone %s%s[%d], but found in %s%s[%d]",
	    (void *)addr, zone_heap_name(zone), zone->z_name, zone_index(zone),
	    zone_heap_name(src_zone), src_zone->z_name, zidx);
}

__abortlike
static void
zone_page_metadata_list_corruption(zone_t zone, struct zone_page_metadata *meta)
{
	panic("metadata list corruption through element %p detected in zone %s%s",
	    meta, zone_heap_name(zone), zone->z_name);
}

__abortlike
static void
zone_page_meta_accounting_panic(zone_t zone, struct zone_page_metadata *meta,
    const char *kind)
{
	panic("accounting mismatch (%s) for zone %s%s, meta %p", kind,
	    zone_heap_name(zone), zone->z_name, meta);
}

__abortlike
static void
zone_meta_double_free_panic(zone_t zone, vm_offset_t addr, const char *caller)
{
	panic("%s: double free of %p to zone %s%s", caller,
	    (void *)addr, zone_heap_name(zone), zone->z_name);
}

__abortlike
static void
zone_accounting_panic(zone_t zone, const char *kind)
{
	panic("accounting mismatch (%s) for zone %s%s", kind,
	    zone_heap_name(zone), zone->z_name);
}

#define zone_counter_sub(z, stat, value)  ({ \
	if (os_sub_overflow((z)->stat, value, &(z)->stat)) { \
	    zone_accounting_panic(z, #stat " wrap-around"); \
	} \
	(z)->stat; \
})

static inline uint16_t
zone_meta_alloc_size_add(zone_t z, struct zone_page_metadata *m,
    vm_offset_t esize)
{
	if (os_add_overflow(m->zm_alloc_size, (uint16_t)esize, &m->zm_alloc_size)) {
		zone_page_meta_accounting_panic(z, m, "alloc_size wrap-around");
	}
	return m->zm_alloc_size;
}

static inline uint16_t
zone_meta_alloc_size_sub(zone_t z, struct zone_page_metadata *m,
    vm_offset_t esize)
{
	if (os_sub_overflow(m->zm_alloc_size, esize, &m->zm_alloc_size)) {
		zone_page_meta_accounting_panic(z, m, "alloc_size wrap-around");
	}
	return m->zm_alloc_size;
}

__abortlike
static void
zone_nofail_panic(zone_t zone)
{
	panic("zalloc(Z_NOFAIL) can't be satisfied for zone %s%s (potential leak)",
	    zone_heap_name(zone), zone->z_name);
}

__header_always_inline bool
zone_spans_ro_va(vm_offset_t addr_start, vm_offset_t addr_end)
{
	const struct mach_vm_range *ro_r = &zone_info.zi_ro_range;
	struct mach_vm_range r = { addr_start, addr_end };

	return mach_vm_range_intersects(ro_r, &r);
}

#define from_range(r, addr, size) \
	__builtin_choose_expr(__builtin_constant_p(size) ? (size) == 1 : 0, \
	mach_vm_range_contains(r, (mach_vm_offset_t)(addr)), \
	mach_vm_range_contains(r, (mach_vm_offset_t)(addr), size))

#define from_ro_map(addr, size) \
	from_range(&zone_info.zi_ro_range, addr, size)

#define from_zone_map(addr, size) \
	from_range(&zone_info.zi_map_range, addr, size)

__header_always_inline bool
zone_pva_is_null(zone_pva_t page)
{
	return page.packed_address == 0;
}

__header_always_inline bool
zone_pva_is_queue(zone_pva_t page)
{
	// actual kernel pages have the top bit set
	return (int32_t)page.packed_address > 0;
}

__header_always_inline bool
zone_pva_is_equal(zone_pva_t pva1, zone_pva_t pva2)
{
	return pva1.packed_address == pva2.packed_address;
}

__header_always_inline zone_pva_t *
zone_pageq_base(void)
{
	extern zone_pva_t data_seg_start[] __SEGMENT_START_SYM("__DATA");

	/*
	 * `-1` so that if the first __DATA variable is a page queue,
	 * it gets a non 0 index
	 */
	return data_seg_start - 1;
}

__header_always_inline void
zone_queue_set_head(zone_t z, zone_pva_t queue, zone_pva_t oldv,
    struct zone_page_metadata *meta)
{
	zone_pva_t *queue_head = &zone_pageq_base()[queue.packed_address];

	if (!zone_pva_is_equal(*queue_head, oldv)) {
		zone_page_metadata_list_corruption(z, meta);
	}
	*queue_head = meta->zm_page_next;
}

__header_always_inline zone_pva_t
zone_queue_encode(zone_pva_t *headp)
{
	return (zone_pva_t){ (uint32_t)(headp - zone_pageq_base()) };
}

__header_always_inline zone_pva_t
zone_pva_from_addr(vm_address_t addr)
{
	// cannot use atop() because we want to maintain the sign bit
	return (zone_pva_t){ (uint32_t)((intptr_t)addr >> PAGE_SHIFT) };
}

__header_always_inline vm_address_t
zone_pva_to_addr(zone_pva_t page)
{
	// cause sign extension so that we end up with the right address
	return (vm_offset_t)(int32_t)page.packed_address << PAGE_SHIFT;
}

__header_always_inline struct zone_page_metadata *
zone_pva_to_meta(zone_pva_t page)
{
	return &zone_info.zi_meta_base[page.packed_address];
}

__header_always_inline zone_pva_t
zone_pva_from_meta(struct zone_page_metadata *meta)
{
	return (zone_pva_t){ (uint32_t)(meta - zone_info.zi_meta_base) };
}

__header_always_inline struct zone_page_metadata *
zone_meta_from_addr(vm_offset_t addr)
{
	return zone_pva_to_meta(zone_pva_from_addr(addr));
}

__header_always_inline zone_id_t
zone_index_from_ptr(const void *ptr)
{
	return zone_pva_to_meta(zone_pva_from_addr((vm_offset_t)ptr))->zm_index;
}

__header_always_inline vm_offset_t
zone_meta_to_addr(struct zone_page_metadata *meta)
{
	return ptoa((int32_t)(meta - zone_info.zi_meta_base));
}

__attribute__((overloadable))
__header_always_inline void
zone_meta_validate(zone_t z, struct zone_page_metadata *meta, vm_address_t addr)
{
	if (!zone_has_index(z, meta->zm_index)) {
		zone_page_metadata_index_confusion_panic(z, addr, meta);
	}
}

__attribute__((overloadable))
__header_always_inline void
zone_meta_validate(zone_t z, struct zone_page_metadata *meta)
{
	zone_meta_validate(z, meta, zone_meta_to_addr(meta));
}

__header_always_inline void
zone_meta_queue_push(zone_t z, zone_pva_t *headp,
    struct zone_page_metadata *meta)
{
	zone_pva_t head = *headp;
	zone_pva_t queue_pva = zone_queue_encode(headp);
	struct zone_page_metadata *tmp;

	meta->zm_page_next = head;
	if (!zone_pva_is_null(head)) {
		tmp = zone_pva_to_meta(head);
		if (!zone_pva_is_equal(tmp->zm_page_prev, queue_pva)) {
			zone_page_metadata_list_corruption(z, meta);
		}
		tmp->zm_page_prev = zone_pva_from_meta(meta);
	}
	meta->zm_page_prev = queue_pva;
	*headp = zone_pva_from_meta(meta);
}

__header_always_inline struct zone_page_metadata *
zone_meta_queue_pop(zone_t z, zone_pva_t *headp)
{
	zone_pva_t head = *headp;
	struct zone_page_metadata *meta = zone_pva_to_meta(head);
	struct zone_page_metadata *tmp;

	zone_meta_validate(z, meta);

	if (!zone_pva_is_null(meta->zm_page_next)) {
		tmp = zone_pva_to_meta(meta->zm_page_next);
		if (!zone_pva_is_equal(tmp->zm_page_prev, head)) {
			zone_page_metadata_list_corruption(z, meta);
		}
		tmp->zm_page_prev = meta->zm_page_prev;
	}
	*headp = meta->zm_page_next;

	meta->zm_page_next = meta->zm_page_prev = (zone_pva_t){ 0 };

	return meta;
}

__header_always_inline void
zone_meta_remqueue(zone_t z, struct zone_page_metadata *meta)
{
	zone_pva_t meta_pva = zone_pva_from_meta(meta);
	struct zone_page_metadata *tmp;

	if (!zone_pva_is_null(meta->zm_page_next)) {
		tmp = zone_pva_to_meta(meta->zm_page_next);
		if (!zone_pva_is_equal(tmp->zm_page_prev, meta_pva)) {
			zone_page_metadata_list_corruption(z, meta);
		}
		tmp->zm_page_prev = meta->zm_page_prev;
	}
	if (zone_pva_is_queue(meta->zm_page_prev)) {
		zone_queue_set_head(z, meta->zm_page_prev, meta_pva, meta);
	} else {
		tmp = zone_pva_to_meta(meta->zm_page_prev);
		if (!zone_pva_is_equal(tmp->zm_page_next, meta_pva)) {
			zone_page_metadata_list_corruption(z, meta);
		}
		tmp->zm_page_next = meta->zm_page_next;
	}

	meta->zm_page_next = meta->zm_page_prev = (zone_pva_t){ 0 };
}

__header_always_inline void
zone_meta_requeue(zone_t z, zone_pva_t *headp,
    struct zone_page_metadata *meta)
{
	zone_meta_remqueue(z, meta);
	zone_meta_queue_push(z, headp, meta);
}

/* prevents a given metadata from ever reaching the z_pageq_empty queue */
static inline void
zone_meta_lock_in_partial(zone_t z, struct zone_page_metadata *m, uint32_t len)
{
	uint16_t new_size = zone_meta_alloc_size_add(z, m, ZM_ALLOC_SIZE_LOCK);

	assert(new_size % sizeof(vm_offset_t) == ZM_ALLOC_SIZE_LOCK);
	if (new_size == ZM_ALLOC_SIZE_LOCK) {
		zone_meta_requeue(z, &z->z_pageq_partial, m);
		zone_counter_sub(z, z_wired_empty, len);
	}
}

/* allows a given metadata to reach the z_pageq_empty queue again */
static inline void
zone_meta_unlock_from_partial(zone_t z, struct zone_page_metadata *m, uint32_t len)
{
	uint16_t new_size = zone_meta_alloc_size_sub(z, m, ZM_ALLOC_SIZE_LOCK);

	assert(new_size % sizeof(vm_offset_t) == 0);
	if (new_size == 0) {
		zone_meta_requeue(z, &z->z_pageq_empty, m);
		z->z_wired_empty += len;
	}
}

/*
 * Routine to populate a page backing metadata in the zone_metadata_region.
 * Must be called without the zone lock held as it might potentially block.
 */
static void
zone_meta_populate(vm_offset_t base, vm_size_t size)
{
	struct zone_page_metadata *from = zone_meta_from_addr(base);
	struct zone_page_metadata *to   = from + atop(size);
	vm_offset_t page_addr = trunc_page(from);

	for (; page_addr < (vm_offset_t)to; page_addr += PAGE_SIZE) {
#if !KASAN
		/*
		 * This can race with another thread doing a populate on the same metadata
		 * page, where we see an updated pmap but unmapped KASan shadow, causing a
		 * fault in the shadow when we first access the metadata page. Avoid this
		 * by always synchronizing on the zone_metadata_region lock with KASan.
		 */
		if (pmap_find_phys(kernel_pmap, page_addr)) {
			continue;
		}
#endif

		for (;;) {
			kern_return_t ret = KERN_SUCCESS;

			/*
			 * All updates to the zone_metadata_region are done
			 * under the zone_metadata_region_lck
			 */
			zone_meta_lock();
			if (0 == pmap_find_phys(kernel_pmap, page_addr)) {
				ret = kernel_memory_populate(page_addr,
				    PAGE_SIZE, KMA_NOPAGEWAIT | KMA_KOBJECT | KMA_ZERO,
				    VM_KERN_MEMORY_OSFMK);
			}
			zone_meta_unlock();

			if (ret == KERN_SUCCESS) {
				break;
			}

			/*
			 * We can't pass KMA_NOPAGEWAIT under a global lock as it leads
			 * to bad system deadlocks, so if the allocation failed,
			 * we need to do the VM_PAGE_WAIT() outside of the lock.
			 */
			VM_PAGE_WAIT();
		}
	}
}

__abortlike
static void
zone_invalid_element_panic(zone_t zone, vm_offset_t addr)
{
	struct zone_page_metadata *meta;
	const char *from_cache = "";
	vm_offset_t page;

	if (!from_zone_map(addr, zone_elem_inner_size(zone))) {
		panic("addr %p being freed to zone %s%s%s, isn't from zone map",
		    (void *)addr, zone_heap_name(zone), zone->z_name, from_cache);
	}
	page = trunc_page(addr);
	meta = zone_meta_from_addr(addr);

	if (!zone_has_index(zone, meta->zm_index)) {
		zone_page_metadata_index_confusion_panic(zone, addr, meta);
	}

	if (meta->zm_chunk_len == ZM_SECONDARY_PCPU_PAGE) {
		panic("metadata %p corresponding to addr %p being freed to "
		    "zone %s%s%s, is marked as secondary per cpu page",
		    meta, (void *)addr, zone_heap_name(zone), zone->z_name,
		    from_cache);
	}
	if (meta->zm_chunk_len == ZM_SECONDARY_PAGE) {
		page -= ptoa(meta->zm_page_index);
		meta -= meta->zm_page_index;
	}

	if (meta->zm_chunk_len > ZM_CHUNK_LEN_MAX) {
		panic("metadata %p corresponding to addr %p being freed to "
		    "zone %s%s%s, has chunk len greater than max",
		    meta, (void *)addr, zone_heap_name(zone), zone->z_name,
		    from_cache);
	}

	if ((addr - zone_elem_inner_offs(zone) - page) % zone_elem_outer_size(zone)) {
		panic("addr %p being freed to zone %s%s%s, isn't aligned to "
		    "zone element size", (void *)addr, zone_heap_name(zone),
		    zone->z_name, from_cache);
	}

	zone_invalid_element_addr_panic(zone, addr);
}

__attribute__((always_inline))
static struct zone_page_metadata *
zone_element_resolve(
	zone_t                  zone,
	vm_offset_t             addr,
	vm_offset_t            *idx)
{
	struct zone_page_metadata *meta;
	vm_offset_t offs, eidx;

	meta = zone_meta_from_addr(addr);
	if (!from_zone_map(addr, 1) || !zone_has_index(zone, meta->zm_index)) {
		zone_invalid_element_panic(zone, addr);
	}

	offs = (addr & PAGE_MASK) - zone_elem_inner_offs(zone);
	if (meta->zm_chunk_len == ZM_SECONDARY_PAGE) {
		offs += ptoa(meta->zm_page_index);
		meta -= meta->zm_page_index;
	}

	eidx = Z_FAST_QUO(offs, zone->z_quo_magic);
	if (eidx * zone_elem_outer_size(zone) != offs) {
		zone_invalid_element_panic(zone, addr);
	}

	*idx = eidx;
	return meta;
}

#if ZSECURITY_CONFIG(PGZ_OOB_ADJUST)
void *
zone_element_pgz_oob_adjust(void *ptr, vm_size_t req_size, vm_size_t elem_size)
{
	vm_offset_t addr = (vm_offset_t)ptr;
	vm_offset_t end = addr + elem_size;
	vm_offset_t offs;

	/*
	 * 0-sized allocations in a KALLOC_MINSIZE bucket
	 * would be offset to the next allocation which is incorrect.
	 */
	req_size = MAX(roundup(req_size, KALLOC_MINALIGN), KALLOC_MINALIGN);

	/*
	 * Given how chunks work, for a zone with PGZ guards on,
	 * there's a single element which ends precisely
	 * at the page boundary: the last one.
	 */
	if (req_size == elem_size ||
	    (end & PAGE_MASK) ||
	    !zone_meta_from_addr(addr)->zm_guarded) {
		return ptr;
	}

	offs = elem_size - req_size;
	zone_meta_from_addr(end)->zm_oob_offs = (uint16_t)offs;

	return (char *)addr + offs;
}
#endif /* !ZSECURITY_CONFIG(PGZ_OOB_ADJUST) */

__abortlike
static void
zone_element_bounds_check_panic(vm_address_t addr, vm_size_t len)
{
	struct zone_page_metadata *meta;
	vm_offset_t offs, size, page;
	zone_t      zone;

	page = trunc_page(addr);
	meta = zone_meta_from_addr(addr);
	zone = &zone_array[meta->zm_index];

	if (zone->z_percpu) {
		panic("zone bound checks: address %p is a per-cpu allocation",
		    (void *)addr);
	}

	if (meta->zm_chunk_len == ZM_SECONDARY_PAGE) {
		page -= ptoa(meta->zm_page_index);
		meta -= meta->zm_page_index;
	}

	size = zone_elem_outer_size(zone);
	offs = Z_FAST_MOD(addr - zone_elem_inner_offs(zone) - page + size,
	    zone->z_quo_magic, size);
	panic("zone bound checks: buffer %p of length %zd overflows "
	    "object %p of size %zd in zone %p[%s%s]",
	    (void *)addr, len, (void *)(addr - offs - zone_elem_redzone(zone)),
	    zone_elem_inner_size(zone), zone, zone_heap_name(zone), zone_name(zone));
}

void
zone_element_bounds_check(vm_address_t addr, vm_size_t len)
{
	struct zone_page_metadata *meta;
	vm_offset_t offs, size;
	zone_t      zone;

	if (!from_zone_map(addr, 1)) {
		return;
	}

#if CONFIG_PROB_GZALLOC
	if (__improbable(pgz_owned(addr))) {
		meta = zone_meta_from_addr(addr);
		addr = trunc_page(meta->zm_pgz_orig_addr) + (addr & PAGE_MASK);
	}
#endif /* CONFIG_PROB_GZALLOC */
	meta = zone_meta_from_addr(addr);
	zone = zone_by_id(meta->zm_index);

	if (zone->z_percpu) {
		zone_element_bounds_check_panic(addr, len);
	}

	if (zone->z_permanent) {
		/* We don't know bounds for those */
		return;
	}

	offs = (addr & PAGE_MASK) - zone_elem_inner_offs(zone);
	if (meta->zm_chunk_len == ZM_SECONDARY_PAGE) {
		offs += ptoa(meta->zm_page_index);
	}
	size = zone_elem_outer_size(zone);
	offs = Z_FAST_MOD(offs + size, zone->z_quo_magic, size);
	if (len + zone_elem_redzone(zone) > size - offs) {
		zone_element_bounds_check_panic(addr, len);
	}
}

/*
 * Routine to get the size of a zone allocated address.
 * If the address doesnt belong to the zone maps, returns 0.
 */
vm_size_t
zone_element_size(void *elem, zone_t *z, bool clear_oob, vm_offset_t *oob_offs)
{
	vm_address_t addr = (vm_address_t)elem;
	struct zone_page_metadata *meta;
	vm_size_t esize, offs, end;
	zone_t zone;

	if (from_zone_map(addr, sizeof(void *))) {
		meta  = zone_meta_from_addr(addr);
		zone  = zone_by_id(meta->zm_index);
		esize = zone_elem_inner_size(zone);
		end   = addr + esize;
		offs  = 0;

#if ZSECURITY_CONFIG(PGZ_OOB_ADJUST)
		/*
		 * If the chunk uses guards, and that (addr + esize)
		 * either crosses a page boundary or is at the boundary,
		 * we need to look harder.
		 */
		if (oob_offs && meta->zm_guarded && atop(addr ^ end)) {
			/*
			 * Because in the vast majority of cases the element
			 * size is sub-page, and that meta[1] must be faulted,
			 * we can quickly peek at whether it's a guard.
			 *
			 * For elements larger than a page, finding the guard
			 * page requires a little more effort.
			 */
			if (meta[1].zm_chunk_len == ZM_PGZ_GUARD) {
				offs = meta[1].zm_oob_offs;
				if (clear_oob) {
					meta[1].zm_oob_offs = 0;
				}
			} else if (esize > PAGE_SIZE) {
				struct zone_page_metadata *gmeta;

				if (meta->zm_chunk_len == ZM_SECONDARY_PAGE) {
					gmeta = meta + meta->zm_subchunk_len;
				} else {
					gmeta = meta + zone->z_chunk_pages;
				}
				assert(gmeta->zm_chunk_len == ZM_PGZ_GUARD);

				if (end >= zone_meta_to_addr(gmeta)) {
					offs = gmeta->zm_oob_offs;
					if (clear_oob) {
						gmeta->zm_oob_offs = 0;
					}
				}
			}
		}
#else
#pragma unused(end, clear_oob)
#endif /* ZSECURITY_CONFIG(PGZ_OOB_ADJUST) */

		if (oob_offs) {
			*oob_offs = offs;
		}
		if (z) {
			*z = zone;
		}
		return esize;
	}

	if (oob_offs) {
		*oob_offs = 0;
	}

	return 0;
}

zone_id_t
zone_id_for_element(void *addr, vm_size_t esize)
{
	zone_id_t zid = ZONE_ID_INVALID;
	if (from_zone_map(addr, esize)) {
		zid = zone_index_from_ptr(addr);
		__builtin_assume(zid != ZONE_ID_INVALID);
	}
	return zid;
}

/* This function just formats the reason for the panics by redoing the checks */
__abortlike
static void
zone_require_panic(zone_t zone, void *addr)
{
	uint32_t zindex;
	zone_t other;

	if (!from_zone_map(addr, zone_elem_inner_size(zone))) {
		panic("zone_require failed: address not in a zone (addr: %p)", addr);
	}

	zindex = zone_index_from_ptr(addr);
	other = &zone_array[zindex];
	if (zindex >= os_atomic_load(&num_zones, relaxed) || !other->z_self) {
		panic("zone_require failed: invalid zone index %d "
		    "(addr: %p, expected: %s%s)", zindex,
		    addr, zone_heap_name(zone), zone->z_name);
	} else {
		panic("zone_require failed: address in unexpected zone id %d (%s%s) "
		    "(addr: %p, expected: %s%s)",
		    zindex, zone_heap_name(other), other->z_name,
		    addr, zone_heap_name(zone), zone->z_name);
	}
}

__abortlike
static void
zone_id_require_panic(zone_id_t zid, void *addr)
{
	zone_require_panic(&zone_array[zid], addr);
}

/*
 * Routines to panic if a pointer is not mapped to an expected zone.
 * This can be used as a means of pinning an object to the zone it is expected
 * to be a part of.  Causes a panic if the address does not belong to any
 * specified zone, does not belong to any zone, has been freed and therefore
 * unmapped from the zone, or the pointer contains an uninitialized value that
 * does not belong to any zone.
 */
void
zone_require(zone_t zone, void *addr)
{
	vm_size_t esize = zone_elem_inner_size(zone);

	if (from_zone_map(addr, esize) &&
	    zone_has_index(zone, zone_index_from_ptr(addr))) {
		return;
	}
	zone_require_panic(zone, addr);
}

void
zone_id_require(zone_id_t zid, vm_size_t esize, void *addr)
{
	if (from_zone_map(addr, esize) && zid == zone_index_from_ptr(addr)) {
		return;
	}
	zone_id_require_panic(zid, addr);
}

bool
zone_owns(zone_t zone, void *addr)
{
	vm_size_t esize = zone_elem_inner_size(zone);

	if (from_zone_map(addr, esize)) {
		return zone_has_index(zone, zone_index_from_ptr(addr));
	}
	return false;
}

static inline struct mach_vm_range
zone_kmem_suballoc(
	mach_vm_offset_t        addr,
	vm_size_t               size,
	int                     flags,
	vm_tag_t                tag,
	vm_map_t                *new_map)
{
	struct mach_vm_range r;

	*new_map = kmem_suballoc(kernel_map, &addr, size,
	    VM_MAP_CREATE_NEVER_FAULTS | VM_MAP_CREATE_DISABLE_HOLELIST,
	    flags, KMS_PERMANENT | KMS_NOFAIL, tag).kmr_submap;

	r.min_address = addr;
	r.max_address = addr + size;
	return r;
}

#endif /* !ZALLOC_TEST */
#pragma mark Zone bits allocator

/*!
 * @defgroup Zone Bitmap allocator
 * @{
 *
 * @brief
 * Functions implementing the zone bitmap allocator
 *
 * @discussion
 * The zone allocator maintains which elements are allocated or free in bitmaps.
 *
 * When the number of elements per page is smaller than 32, it is stored inline
 * on the @c zone_page_metadata structure (@c zm_inline_bitmap is set,
 * and @c zm_bitmap used for storage).
 *
 * When the number of elements is larger, then a bitmap is allocated from
 * a buddy allocator (impelemented under the @c zba_* namespace). Pointers
 * to bitmaps are implemented as a packed 32 bit bitmap reference, stored in
 * @c zm_bitmap. The low 3 bits encode the scale (order) of the allocation in
 * @c ZBA_GRANULE units, and hence actual allocations encoded with that scheme
 * cannot be larger than 1024 bytes (8192 bits).
 *
 * This buddy allocator can actually accomodate allocations as large
 * as 8k on 16k systems and 2k on 4k systems.
 *
 * Note: @c zba_* functions are implementation details not meant to be used
 * outside of the allocation of the allocator itself. Interfaces to the rest of
 * the zone allocator are documented and not @c zba_* prefixed.
 */

#define ZBA_CHUNK_SIZE          PAGE_MAX_SIZE
#define ZBA_GRANULE             sizeof(uint64_t)
#define ZBA_GRANULE_BITS        (8 * sizeof(uint64_t))
#define ZBA_MAX_ORDER           (PAGE_MAX_SHIFT - 4)
#define ZBA_MAX_ALLOC_ORDER     7
#define ZBA_SLOTS               (ZBA_CHUNK_SIZE / ZBA_GRANULE)
#define ZBA_HEADS_COUNT         (ZBA_MAX_ORDER + 1)
#define ZBA_PTR_MASK            0x0fffffff
#define ZBA_ORDER_SHIFT         29
#define ZBA_HAS_EXTRA_BIT       0x10000000

static_assert(2ul * ZBA_GRANULE << ZBA_MAX_ORDER == ZBA_CHUNK_SIZE, "chunk sizes");
static_assert(ZBA_MAX_ALLOC_ORDER <= ZBA_MAX_ORDER, "ZBA_MAX_ORDER is enough");

struct zone_bits_chain {
	uint32_t zbc_next;
	uint32_t zbc_prev;
} __attribute__((aligned(ZBA_GRANULE)));

struct zone_bits_head {
	uint32_t zbh_next;
	uint32_t zbh_unused;
} __attribute__((aligned(ZBA_GRANULE)));

static_assert(sizeof(struct zone_bits_chain) == ZBA_GRANULE, "zbc size");
static_assert(sizeof(struct zone_bits_head) == ZBA_GRANULE, "zbh size");

struct zone_bits_allocator_meta {
	uint32_t  zbam_left;
	uint32_t  zbam_right;
	struct zone_bits_head zbam_lists[ZBA_HEADS_COUNT];
	struct zone_bits_head zbam_lists_with_extra[ZBA_HEADS_COUNT];
};

struct zone_bits_allocator_header {
	uint64_t zbah_bits[ZBA_SLOTS / (8 * sizeof(uint64_t))];
};

#if ZALLOC_TEST
static struct zalloc_bits_allocator_test_setup {
	vm_offset_t zbats_base;
	void      (*zbats_populate)(vm_address_t addr, vm_size_t size);
} zba_test_info;

static struct zone_bits_allocator_header *
zba_base_header(void)
{
	return (struct zone_bits_allocator_header *)zba_test_info.zbats_base;
}

static kern_return_t
zba_populate(uint32_t n, bool with_extra __unused)
{
	vm_address_t base = zba_test_info.zbats_base;
	zba_test_info.zbats_populate(base + n * ZBA_CHUNK_SIZE, ZBA_CHUNK_SIZE);

	return KERN_SUCCESS;
}
#else
__startup_data __attribute__((aligned(ZBA_CHUNK_SIZE)))
static uint8_t zba_chunk_startup[ZBA_CHUNK_SIZE];

static SECURITY_READ_ONLY_LATE(uint8_t) zba_xtra_shift;
static LCK_MTX_DECLARE(zba_mtx, &zone_locks_grp);

static struct zone_bits_allocator_header *
zba_base_header(void)
{
	return (struct zone_bits_allocator_header *)zone_info.zi_bits_range.min_address;
}

static void
zba_lock(void)
{
	lck_mtx_lock(&zba_mtx);
}

static void
zba_unlock(void)
{
	lck_mtx_unlock(&zba_mtx);
}

__abortlike
static void
zba_memory_exhausted(void)
{
	uint64_t zsize = 0;
	zone_t z = zone_find_largest(&zsize);
	panic("zba_populate: out of bitmap space, "
	    "likely due to memory leak in zone [%s%s] "
	    "(%u%c, %d elements allocated)",
	    zone_heap_name(z), zone_name(z),
	    mach_vm_size_pretty(zsize), mach_vm_size_unit(zsize),
	    zone_count_allocated(z));
}


static kern_return_t
zba_populate(uint32_t n, bool with_extra)
{
	vm_size_t bits_size = ZBA_CHUNK_SIZE;
	vm_size_t xtra_size = bits_size * CHAR_BIT << zba_xtra_shift;
	vm_address_t bits_addr;
	vm_address_t xtra_addr;
	kern_return_t kr;

	bits_addr = zone_info.zi_bits_range.min_address + n * bits_size;
	xtra_addr = zone_info.zi_xtra_range.min_address + n * xtra_size;

	kr = kernel_memory_populate(bits_addr, bits_size,
	    KMA_ZERO | KMA_KOBJECT | KMA_NOPAGEWAIT,
	    VM_KERN_MEMORY_OSFMK);
	if (kr != KERN_SUCCESS) {
		return kr;
	}


	if (with_extra) {
		kr = kernel_memory_populate(xtra_addr, xtra_size,
		    KMA_ZERO | KMA_KOBJECT | KMA_NOPAGEWAIT,
		    VM_KERN_MEMORY_OSFMK);
		if (kr != KERN_SUCCESS) {
			kernel_memory_depopulate(bits_addr, bits_size,
			    KMA_ZERO | KMA_KOBJECT | KMA_NOPAGEWAIT,
			    VM_KERN_MEMORY_OSFMK);
		}
	}

	return kr;
}
#endif

__pure2
static struct zone_bits_allocator_meta *
zba_meta(void)
{
	return (struct zone_bits_allocator_meta *)&zba_base_header()[1];
}

__pure2
static uint64_t *
zba_slot_base(void)
{
	return (uint64_t *)zba_base_header();
}

__pure2
static struct zone_bits_head *
zba_head(uint32_t order, bool with_extra)
{
	if (with_extra) {
		return &zba_meta()->zbam_lists_with_extra[order];
	} else {
		return &zba_meta()->zbam_lists[order];
	}
}

__pure2
static uint32_t
zba_head_index(struct zone_bits_head *hd)
{
	return (uint32_t)((uint64_t *)hd - zba_slot_base());
}

__pure2
static struct zone_bits_chain *
zba_chain_for_index(uint32_t index)
{
	return (struct zone_bits_chain *)(zba_slot_base() + index);
}

__pure2
static uint32_t
zba_chain_to_index(const struct zone_bits_chain *zbc)
{
	return (uint32_t)((const uint64_t *)zbc - zba_slot_base());
}

__abortlike
static void
zba_head_corruption_panic(uint32_t order, bool with_extra)
{
	panic("zone bits allocator head[%d:%d:%p] is corrupt",
	    order, with_extra, zba_head(order, with_extra));
}

__abortlike
static void
zba_chain_corruption_panic(struct zone_bits_chain *a, struct zone_bits_chain *b)
{
	panic("zone bits allocator freelist is corrupt (%p <-> %p)", a, b);
}

static void
zba_push_block(struct zone_bits_chain *zbc, uint32_t order, bool with_extra)
{
	struct zone_bits_head *hd = zba_head(order, with_extra);
	uint32_t hd_index = zba_head_index(hd);
	uint32_t index = zba_chain_to_index(zbc);
	struct zone_bits_chain *next;

	if (hd->zbh_next) {
		next = zba_chain_for_index(hd->zbh_next);
		if (next->zbc_prev != hd_index) {
			zba_head_corruption_panic(order, with_extra);
		}
		next->zbc_prev = index;
	}
	zbc->zbc_next = hd->zbh_next;
	zbc->zbc_prev = hd_index;
	hd->zbh_next = index;
}

static void
zba_remove_block(struct zone_bits_chain *zbc)
{
	struct zone_bits_chain *prev = zba_chain_for_index(zbc->zbc_prev);
	uint32_t index = zba_chain_to_index(zbc);

	if (prev->zbc_next != index) {
		zba_chain_corruption_panic(prev, zbc);
	}
	if ((prev->zbc_next = zbc->zbc_next)) {
		struct zone_bits_chain *next = zba_chain_for_index(zbc->zbc_next);
		if (next->zbc_prev != index) {
			zba_chain_corruption_panic(zbc, next);
		}
		next->zbc_prev = zbc->zbc_prev;
	}
}

static vm_address_t
zba_try_pop_block(uint32_t order, bool with_extra)
{
	struct zone_bits_head *hd = zba_head(order, with_extra);
	struct zone_bits_chain *zbc;

	if (hd->zbh_next == 0) {
		return 0;
	}

	zbc = zba_chain_for_index(hd->zbh_next);
	zba_remove_block(zbc);
	return (vm_address_t)zbc;
}

static struct zone_bits_allocator_header *
zba_header(vm_offset_t addr)
{
	addr &= -(vm_offset_t)ZBA_CHUNK_SIZE;
	return (struct zone_bits_allocator_header *)addr;
}

static size_t
zba_node_parent(size_t node)
{
	return (node - 1) / 2;
}

static size_t
zba_node_left_child(size_t node)
{
	return node * 2 + 1;
}

static size_t
zba_node_buddy(size_t node)
{
	return ((node - 1) ^ 1) + 1;
}

static size_t
zba_node(vm_offset_t addr, uint32_t order)
{
	vm_offset_t offs = (addr % ZBA_CHUNK_SIZE) / ZBA_GRANULE;
	return (offs >> order) + (1 << (ZBA_MAX_ORDER - order + 1)) - 1;
}

static struct zone_bits_chain *
zba_chain_for_node(struct zone_bits_allocator_header *zbah, size_t node, uint32_t order)
{
	vm_offset_t offs = (node - (1 << (ZBA_MAX_ORDER - order + 1)) + 1) << order;
	return (struct zone_bits_chain *)((vm_offset_t)zbah + offs * ZBA_GRANULE);
}

static void
zba_node_flip_split(struct zone_bits_allocator_header *zbah, size_t node)
{
	zbah->zbah_bits[node / 64] ^= 1ull << (node % 64);
}

static bool
zba_node_is_split(struct zone_bits_allocator_header *zbah, size_t node)
{
	return zbah->zbah_bits[node / 64] & (1ull << (node % 64));
}

static void
zba_free(vm_offset_t addr, uint32_t order, bool with_extra)
{
	struct zone_bits_allocator_header *zbah = zba_header(addr);
	struct zone_bits_chain *zbc;
	size_t node = zba_node(addr, order);

	while (node) {
		size_t parent = zba_node_parent(node);

		zba_node_flip_split(zbah, parent);
		if (zba_node_is_split(zbah, parent)) {
			break;
		}

		zbc = zba_chain_for_node(zbah, zba_node_buddy(node), order);
		zba_remove_block(zbc);
		order++;
		node = parent;
	}

	zba_push_block(zba_chain_for_node(zbah, node, order), order, with_extra);
}

static vm_size_t
zba_chunk_header_size(uint32_t n)
{
	vm_size_t hdr_size = sizeof(struct zone_bits_allocator_header);
	if (n == 0) {
		hdr_size += sizeof(struct zone_bits_allocator_meta);
	}
	return hdr_size;
}

static void
zba_init_chunk(uint32_t n, bool with_extra)
{
	vm_size_t hdr_size = zba_chunk_header_size(n);
	vm_offset_t page = (vm_offset_t)zba_base_header() + n * ZBA_CHUNK_SIZE;
	struct zone_bits_allocator_header *zbah = zba_header(page);
	vm_size_t size = ZBA_CHUNK_SIZE;
	size_t node;

	for (uint32_t o = ZBA_MAX_ORDER + 1; o-- > 0;) {
		if (size < hdr_size + (ZBA_GRANULE << o)) {
			continue;
		}
		size -= ZBA_GRANULE << o;
		node = zba_node(page + size, o);
		zba_node_flip_split(zbah, zba_node_parent(node));
		zba_push_block(zba_chain_for_node(zbah, node, o), o, with_extra);
	}
}

__attribute__((noinline))
static void
zba_grow(bool with_extra)
{
	struct zone_bits_allocator_meta *meta = zba_meta();
	kern_return_t kr = KERN_SUCCESS;
	uint32_t chunk;

#if !ZALLOC_TEST
	if (meta->zbam_left >= meta->zbam_right) {
		zba_memory_exhausted();
	}
#endif

	if (with_extra) {
		chunk = meta->zbam_right - 1;
	} else {
		chunk = meta->zbam_left;
	}

	kr = zba_populate(chunk, with_extra);
	if (kr == KERN_SUCCESS) {
		if (with_extra) {
			meta->zbam_right -= 1;
		} else {
			meta->zbam_left += 1;
		}

		zba_init_chunk(chunk, with_extra);
#if !ZALLOC_TEST
	} else {
		/*
		 * zba_populate() has to be allowed to fail populating,
		 * as we are under a global lock, we need to do the
		 * VM_PAGE_WAIT() outside of the lock.
		 */
		assert(kr == KERN_RESOURCE_SHORTAGE);
		zba_unlock();
		VM_PAGE_WAIT();
		zba_lock();
#endif
	}
}

static vm_offset_t
zba_alloc(uint32_t order, bool with_extra)
{
	struct zone_bits_allocator_header *zbah;
	uint32_t cur = order;
	vm_address_t addr;
	size_t node;

	while ((addr = zba_try_pop_block(cur, with_extra)) == 0) {
		if (__improbable(cur++ >= ZBA_MAX_ORDER)) {
			zba_grow(with_extra);
			cur = order;
		}
	}

	zbah = zba_header(addr);
	node = zba_node(addr, cur);
	zba_node_flip_split(zbah, zba_node_parent(node));
	while (cur > order) {
		cur--;
		zba_node_flip_split(zbah, node);
		node = zba_node_left_child(node);
		zba_push_block(zba_chain_for_node(zbah, node + 1, cur),
		    cur, with_extra);
	}

	return addr;
}

#define zba_map_index(type, n)    (n / (8 * sizeof(type)))
#define zba_map_bit(type, n)      ((type)1 << (n % (8 * sizeof(type))))
#define zba_map_mask_lt(type, n)  (zba_map_bit(type, n) - 1)
#define zba_map_mask_ge(type, n)  ((type)-zba_map_bit(type, n))

#if !ZALLOC_TEST
#if VM_TAG_SIZECLASSES

static void *
zba_extra_ref_ptr(uint32_t bref, vm_offset_t idx)
{
	vm_offset_t base = zone_info.zi_xtra_range.min_address;
	vm_offset_t offs = (bref & ZBA_PTR_MASK) * ZBA_GRANULE * CHAR_BIT;

	return (void *)(base + ((offs + idx) << zba_xtra_shift));
}

#endif /* VM_TAG_SIZECLASSES */

static uint32_t
zba_bits_ref_order(uint32_t bref)
{
	return bref >> ZBA_ORDER_SHIFT;
}

static bitmap_t *
zba_bits_ref_ptr(uint32_t bref)
{
	return zba_slot_base() + (bref & ZBA_PTR_MASK);
}

static vm_offset_t
zba_scan_bitmap_inline(zone_t zone, struct zone_page_metadata *meta,
    zalloc_flags_t flags, vm_offset_t eidx)
{
	size_t i = eidx / 32;
	uint32_t map;

	if (eidx % 32) {
		map = meta[i].zm_bitmap & zba_map_mask_ge(uint32_t, eidx);
		if (map) {
			eidx = __builtin_ctz(map);
			meta[i].zm_bitmap ^= 1u << eidx;
			return i * 32 + eidx;
		}
		i++;
	}

	uint32_t chunk_len = meta->zm_chunk_len;
	if (flags & Z_PCPU) {
		chunk_len = zpercpu_count();
	}
	for (int j = 0; j < chunk_len; j++, i++) {
		if (i >= chunk_len) {
			i = 0;
		}
		if (__probable(map = meta[i].zm_bitmap)) {
			meta[i].zm_bitmap &= map - 1;
			return i * 32 + __builtin_ctz(map);
		}
	}

	zone_page_meta_accounting_panic(zone, meta, "zm_bitmap");
}

static vm_offset_t
zba_scan_bitmap_ref(zone_t zone, struct zone_page_metadata *meta,
    vm_offset_t eidx)
{
	uint32_t bits_size = 1 << zba_bits_ref_order(meta->zm_bitmap);
	bitmap_t *bits = zba_bits_ref_ptr(meta->zm_bitmap);
	size_t i = eidx / 64;
	uint64_t map;

	if (eidx % 64) {
		map = bits[i] & zba_map_mask_ge(uint64_t, eidx);
		if (map) {
			eidx = __builtin_ctzll(map);
			bits[i] ^= 1ull << eidx;
			return i * 64 + eidx;
		}
		i++;
	}

	for (int j = 0; j < bits_size; i++, j++) {
		if (i >= bits_size) {
			i = 0;
		}
		if (__probable(map = bits[i])) {
			bits[i] &= map - 1;
			return i * 64 + __builtin_ctzll(map);
		}
	}

	zone_page_meta_accounting_panic(zone, meta, "zm_bitmap");
}

/*!
 * @function zone_meta_find_and_clear_bit
 *
 * @brief
 * The core of the bitmap allocator: find a bit set in the bitmaps.
 *
 * @discussion
 * This method will round robin through available allocations,
 * with a per-core memory of the last allocated element index allocated.
 *
 * This is done in order to avoid a fully LIFO behavior which makes exploiting
 * double-free bugs way too practical.
 *
 * @param zone          The zone we're allocating from.
 * @param meta          The main metadata for the chunk being allocated from.
 * @param flags         the alloc flags (for @c Z_PCPU).
 */
static vm_offset_t
zone_meta_find_and_clear_bit(
	zone_t                  zone,
	zone_stats_t            zs,
	struct zone_page_metadata *meta,
	zalloc_flags_t          flags)
{
	vm_offset_t eidx = zs->zs_alloc_rr + 1;

	if (meta->zm_inline_bitmap) {
		eidx = zba_scan_bitmap_inline(zone, meta, flags, eidx);
	} else {
		eidx = zba_scan_bitmap_ref(zone, meta, eidx);
	}
	zs->zs_alloc_rr = (uint16_t)eidx;
	return eidx;
}

/*!
 * @function zone_meta_bits_init_inline
 *
 * @brief
 * Initializes the inline zm_bitmap field(s) for a newly assigned chunk.
 *
 * @param meta          The main metadata for the initialized chunk.
 * @param count         The number of elements the chunk can hold
 *                      (which might be partial for partially populated chunks).
 */
static void
zone_meta_bits_init_inline(struct zone_page_metadata *meta, uint32_t count)
{
	/*
	 * We're called with the metadata zm_bitmap fields already zeroed out.
	 */
	for (size_t i = 0; i < count / 32; i++) {
		meta[i].zm_bitmap = ~0u;
	}
	if (count % 32) {
		meta[count / 32].zm_bitmap = zba_map_mask_lt(uint32_t, count);
	}
}

/*!
 * @function zone_meta_bits_alloc_init
 *
 * @brief
 * Allocates a  zm_bitmap field for a newly assigned chunk.
 *
 * @param count         The number of elements the chunk can hold
 *                      (which might be partial for partially populated chunks).
 * @param nbits         The maximum nuber of bits that will be used.
 * @param with_extra    Whether "VM Tracking" metadata needs to be allocated.
 */
static uint32_t
zone_meta_bits_alloc_init(uint32_t count, uint32_t nbits, bool with_extra)
{
	static_assert(ZONE_MAX_ALLOC_SIZE / ZONE_MIN_ELEM_SIZE <=
	    ZBA_GRANULE_BITS << ZBA_MAX_ORDER, "bitmaps will be large enough");

	uint32_t order = flsll((nbits - 1) / ZBA_GRANULE_BITS);
	uint64_t *bits;
	size_t   i = 0;

	assert(order <= ZBA_MAX_ALLOC_ORDER);
	assert(count <= ZBA_GRANULE_BITS << order);

	zba_lock();
	bits = (uint64_t *)zba_alloc(order, with_extra);
	zba_unlock();

	while (i < count / 64) {
		bits[i++] = ~0ull;
	}
	if (count % 64) {
		bits[i++] = zba_map_mask_lt(uint64_t, count);
	}
	while (i < 1u << order) {
		bits[i++] = 0;
	}

	return (uint32_t)(bits - zba_slot_base()) +
	       (order << ZBA_ORDER_SHIFT) +
	       (with_extra ? ZBA_HAS_EXTRA_BIT : 0);
}

/*!
 * @function zone_meta_bits_merge
 *
 * @brief
 * Adds elements <code>[start, end)</code> to a chunk being extended.
 *
 * @param meta          The main metadata for the extended chunk.
 * @param start         The index of the first element to add to the chunk.
 * @param end           The index of the last (exclusive) element to add.
 */
static void
zone_meta_bits_merge(struct zone_page_metadata *meta,
    uint32_t start, uint32_t end)
{
	if (meta->zm_inline_bitmap) {
		while (start < end) {
			size_t s_i = start / 32;
			size_t s_e = end / 32;

			if (s_i == s_e) {
				meta[s_i].zm_bitmap |= zba_map_mask_lt(uint32_t, end) &
				    zba_map_mask_ge(uint32_t, start);
				break;
			}

			meta[s_i].zm_bitmap |= zba_map_mask_ge(uint32_t, start);
			start += 32 - (start % 32);
		}
	} else {
		uint64_t *bits = zba_bits_ref_ptr(meta->zm_bitmap);

		while (start < end) {
			size_t s_i = start / 64;
			size_t s_e = end / 64;

			if (s_i == s_e) {
				bits[s_i] |= zba_map_mask_lt(uint64_t, end) &
				    zba_map_mask_ge(uint64_t, start);
				break;
			}
			bits[s_i] |= zba_map_mask_ge(uint64_t, start);
			start += 64 - (start % 64);
		}
	}
}

/*!
 * @function zone_bits_free
 *
 * @brief
 * Frees a bitmap to the zone bitmap allocator.
 *
 * @param bref
 * A bitmap reference set by @c zone_meta_bits_init() in a @c zm_bitmap field.
 */
static void
zone_bits_free(uint32_t bref)
{
	zba_lock();
	zba_free((vm_offset_t)zba_bits_ref_ptr(bref),
	    zba_bits_ref_order(bref), (bref & ZBA_HAS_EXTRA_BIT));
	zba_unlock();
}

/*!
 * @function zone_meta_is_free
 *
 * @brief
 * Returns whether a given element appears free.
 */
static bool
zone_meta_is_free(struct zone_page_metadata *meta, vm_offset_t eidx)
{
	if (meta->zm_inline_bitmap) {
		uint32_t bit = zba_map_bit(uint32_t, eidx);
		return meta[zba_map_index(uint32_t, eidx)].zm_bitmap & bit;
	} else {
		bitmap_t *bits = zba_bits_ref_ptr(meta->zm_bitmap);
		uint64_t bit = zba_map_bit(uint64_t, eidx);
		return bits[zba_map_index(uint64_t, eidx)] & bit;
	}
}

/*!
 * @function zone_meta_mark_free
 *
 * @brief
 * Marks an element as free and returns whether it was marked as used.
 */
static bool
zone_meta_mark_free(struct zone_page_metadata *meta, vm_offset_t eidx)
{
	if (meta->zm_inline_bitmap) {
		uint32_t bit = zba_map_bit(uint32_t, eidx);
		if (meta[zba_map_index(uint32_t, eidx)].zm_bitmap & bit) {
			return false;
		}
		meta[zba_map_index(uint32_t, eidx)].zm_bitmap ^= bit;
	} else {
		bitmap_t *bits = zba_bits_ref_ptr(meta->zm_bitmap);
		uint64_t bit = zba_map_bit(uint64_t, eidx);
		if (bits[zba_map_index(uint64_t, eidx)] & bit) {
			return false;
		}
		bits[zba_map_index(uint64_t, eidx)] ^= bit;
	}
	return true;
}

#if VM_TAG_SIZECLASSES

__startup_func
void
__zone_site_register(vm_allocation_site_t *site)
{
	if (zone_tagging_on) {
		vm_tag_alloc(site);
	}
}

uint16_t
zone_index_from_tag_index(uint32_t sizeclass_idx)
{
	return zone_tags_sizeclasses[sizeclass_idx];
}

#endif /* VM_TAG_SIZECLASSES */
#endif /* !ZALLOC_TEST */
/*! @} */
#pragma mark zalloc helpers
#if !ZALLOC_TEST

static inline void *
zstack_tbi_fix(vm_offset_t elem)
{
#if KASAN_TBI
	elem = kasan_tbi_fix_address_tag(elem);
#endif
	return (void *)elem;
}

static inline vm_offset_t
zstack_tbi_fill(void *addr)
{
	vm_offset_t elem = (vm_offset_t)addr;

#if KASAN_TBI
	elem = VM_KERNEL_TBI_FILL(elem);
#endif
	return elem;
}

__attribute__((always_inline))
static inline void
zstack_push_no_delta(zstack_t *stack, void *addr)
{
	vm_offset_t elem = zstack_tbi_fill(addr);

	*(vm_offset_t *)addr = stack->z_head - elem;
	stack->z_head = elem;
}

__attribute__((always_inline))
void
zstack_push(zstack_t *stack, void *addr)
{
	zstack_push_no_delta(stack, addr);
	stack->z_count++;
}

__attribute__((always_inline))
static inline void *
zstack_pop_no_delta(zstack_t *stack)
{
	void *addr = zstack_tbi_fix(stack->z_head);

	stack->z_head += *(vm_offset_t *)addr;
	*(vm_offset_t *)addr = 0;

	return addr;
}

__attribute__((always_inline))
void *
zstack_pop(zstack_t *stack)
{
	stack->z_count--;
	return zstack_pop_no_delta(stack);
}

static inline void
zone_recirc_lock_nopreempt_check_contention(zone_t zone)
{
	uint32_t ticket;

	if (__probable(hw_lck_ticket_reserve_nopreempt(&zone->z_recirc_lock,
	    &ticket, &zone_locks_grp))) {
		return;
	}

	hw_lck_ticket_wait(&zone->z_recirc_lock, ticket, NULL, &zone_locks_grp);

	/*
	 * If zone caching has been disabled due to memory pressure,
	 * then recording contention is not useful, give the system
	 * time to recover.
	 */
	if (__probable(!zone_caching_disabled)) {
		zone->z_recirc_cont_cur++;
	}
}

static inline void
zone_recirc_lock_nopreempt(zone_t zone)
{
	hw_lck_ticket_lock_nopreempt(&zone->z_recirc_lock, &zone_locks_grp);
}

static inline void
zone_recirc_unlock_nopreempt(zone_t zone)
{
	hw_lck_ticket_unlock_nopreempt(&zone->z_recirc_lock);
}

static inline void
zone_lock_nopreempt_check_contention(zone_t zone)
{
	uint32_t ticket;
#if KASAN_FAKESTACK
	spl_t s = 0;
	if (zone->z_kasan_fakestacks) {
		s = splsched();
	}
#endif /* KASAN_FAKESTACK */

	if (__probable(hw_lck_ticket_reserve_nopreempt(&zone->z_lock, &ticket,
	    &zone_locks_grp))) {
#if KASAN_FAKESTACK
		zone->z_kasan_spl = s;
#endif /* KASAN_FAKESTACK */
		return;
	}

	hw_lck_ticket_wait(&zone->z_lock, ticket, NULL, &zone_locks_grp);
#if KASAN_FAKESTACK
	zone->z_kasan_spl = s;
#endif /* KASAN_FAKESTACK */

	/*
	 * If zone caching has been disabled due to memory pressure,
	 * then recording contention is not useful, give the system
	 * time to recover.
	 */
	if (__probable(!zone_caching_disabled && !zone->z_pcpu_cache)) {
		zone->z_recirc_cont_cur++;
	}
}

static inline void
zone_lock_nopreempt(zone_t zone)
{
#if KASAN_FAKESTACK
	spl_t s = 0;
	if (zone->z_kasan_fakestacks) {
		s = splsched();
	}
#endif /* KASAN_FAKESTACK */
	hw_lck_ticket_lock_nopreempt(&zone->z_lock, &zone_locks_grp);
#if KASAN_FAKESTACK
	zone->z_kasan_spl = s;
#endif /* KASAN_FAKESTACK */
}

static inline void
zone_unlock_nopreempt(zone_t zone)
{
#if KASAN_FAKESTACK
	spl_t s = zone->z_kasan_spl;
	zone->z_kasan_spl = 0;
#endif /* KASAN_FAKESTACK */
	hw_lck_ticket_unlock_nopreempt(&zone->z_lock);
#if KASAN_FAKESTACK
	if (zone->z_kasan_fakestacks) {
		splx(s);
	}
#endif /* KASAN_FAKESTACK */
}

static inline void
zone_depot_lock_nopreempt(zone_cache_t zc)
{
	hw_lck_ticket_lock_nopreempt(&zc->zc_depot_lock, &zone_locks_grp);
}

static inline void
zone_depot_unlock_nopreempt(zone_cache_t zc)
{
	hw_lck_ticket_unlock_nopreempt(&zc->zc_depot_lock);
}

static inline void
zone_depot_lock(zone_cache_t zc)
{
	hw_lck_ticket_lock(&zc->zc_depot_lock, &zone_locks_grp);
}

static inline void
zone_depot_unlock(zone_cache_t zc)
{
	hw_lck_ticket_unlock(&zc->zc_depot_lock);
}

zone_t
zone_by_id(size_t zid)
{
	return (zone_t)((uintptr_t)zone_array + zid * sizeof(struct zone));
}

static inline bool
zone_supports_vm(zone_t z)
{
	/*
	 * VM_MAP_ENTRY and VM_MAP_HOLES zones are allowed
	 * to overcommit because they're used to reclaim memory
	 * (VM support).
	 */
	return z >= &zone_array[ZONE_ID_VM_MAP_ENTRY] &&
	       z <= &zone_array[ZONE_ID_VM_MAP_HOLES];
}

const char *
zone_name(zone_t z)
{
	return z->z_name;
}

const char *
zone_heap_name(zone_t z)
{
	zone_security_flags_t zsflags = zone_security_config(z);
	if (__probable(zsflags.z_kheap_id < KHEAP_ID_COUNT)) {
		return kalloc_heap_names[zsflags.z_kheap_id];
	}
	return "invalid";
}

static uint32_t
zone_alloc_pages_for_nelems(zone_t z, vm_size_t max_elems)
{
	vm_size_t elem_count, chunks;

	elem_count = ptoa(z->z_percpu ? 1 : z->z_chunk_pages) /
	    zone_elem_outer_size(z);
	chunks = (max_elems + elem_count - 1) / elem_count;

	return (uint32_t)MIN(UINT32_MAX, chunks * z->z_chunk_pages);
}

static inline vm_size_t
zone_submaps_approx_size(void)
{
	vm_size_t size = 0;

	for (unsigned idx = 0; idx < Z_SUBMAP_IDX_COUNT; idx++) {
		if (zone_submaps[idx] != VM_MAP_NULL) {
			size += zone_submaps[idx]->size;
		}
	}

	return size;
}

static inline void
zone_depot_init(struct zone_depot *zd)
{
	*zd = (struct zone_depot){
		.zd_tail = &zd->zd_head,
	};
}

static inline void
zone_depot_insert_head_full(struct zone_depot *zd, zone_magazine_t mag)
{
	if (zd->zd_full++ == 0) {
		zd->zd_tail = &mag->zm_next;
	}
	mag->zm_next = zd->zd_head;
	zd->zd_head = mag;
}

static inline void
zone_depot_insert_tail_full(struct zone_depot *zd, zone_magazine_t mag)
{
	zd->zd_full++;
	mag->zm_next = *zd->zd_tail;
	*zd->zd_tail = mag;
	zd->zd_tail = &mag->zm_next;
}

static inline void
zone_depot_insert_head_empty(struct zone_depot *zd, zone_magazine_t mag)
{
	zd->zd_empty++;
	mag->zm_next = *zd->zd_tail;
	*zd->zd_tail = mag;
}

static inline zone_magazine_t
zone_depot_pop_head_full(struct zone_depot *zd, zone_t z)
{
	zone_magazine_t mag = zd->zd_head;

	assert(zd->zd_full);

	zd->zd_full--;
	if (z && z->z_recirc_full_min > zd->zd_full) {
		z->z_recirc_full_min = zd->zd_full;
	}
	zd->zd_head = mag->zm_next;
	if (zd->zd_full == 0) {
		zd->zd_tail = &zd->zd_head;
	}

	mag->zm_next = NULL;
	return mag;
}

static inline zone_magazine_t
zone_depot_pop_head_empty(struct zone_depot *zd, zone_t z)
{
	zone_magazine_t mag = *zd->zd_tail;

	assert(zd->zd_empty);

	zd->zd_empty--;
	if (z && z->z_recirc_empty_min > zd->zd_empty) {
		z->z_recirc_empty_min = zd->zd_empty;
	}
	*zd->zd_tail = mag->zm_next;

	mag->zm_next = NULL;
	return mag;
}

static inline smr_seq_t
zone_depot_move_full(
	struct zone_depot      *dst,
	struct zone_depot      *src,
	uint32_t                n,
	zone_t                  z)
{
	zone_magazine_t head, last;

	assert(n);
	assert(src->zd_full >= n);

	src->zd_full -= n;
	if (z && z->z_recirc_full_min > src->zd_full) {
		z->z_recirc_full_min = src->zd_full;
	}
	head = last = src->zd_head;
	for (uint32_t i = n; i-- > 1;) {
		last = last->zm_next;
	}

	src->zd_head = last->zm_next;
	if (src->zd_full == 0) {
		src->zd_tail = &src->zd_head;
	}

	if (z && zone_security_array[zone_index(z)].z_lifo) {
		if (dst->zd_full == 0) {
			dst->zd_tail = &last->zm_next;
		}
		last->zm_next = dst->zd_head;
		dst->zd_head = head;
	} else {
		last->zm_next = *dst->zd_tail;
		*dst->zd_tail = head;
		dst->zd_tail = &last->zm_next;
	}
	dst->zd_full += n;

	return last->zm_seq;
}

static inline void
zone_depot_move_empty(
	struct zone_depot      *dst,
	struct zone_depot      *src,
	uint32_t                n,
	zone_t                  z)
{
	zone_magazine_t head, last;

	assert(n);
	assert(src->zd_empty >= n);

	src->zd_empty -= n;
	if (z && z->z_recirc_empty_min > src->zd_empty) {
		z->z_recirc_empty_min = src->zd_empty;
	}
	head = last = *src->zd_tail;
	for (uint32_t i = n; i-- > 1;) {
		last = last->zm_next;
	}

	*src->zd_tail = last->zm_next;

	dst->zd_empty += n;
	last->zm_next = *dst->zd_tail;
	*dst->zd_tail = head;
}

static inline bool
zone_depot_poll(struct zone_depot *depot, smr_t smr)
{
	if (depot->zd_full == 0) {
		return false;
	}

	return smr == NULL || smr_poll(smr, depot->zd_head->zm_seq);
}

static void
zone_cache_swap_magazines(zone_cache_t cache)
{
	uint16_t count_a = cache->zc_alloc_cur;
	uint16_t count_f = cache->zc_free_cur;
	vm_offset_t *elems_a = cache->zc_alloc_elems;
	vm_offset_t *elems_f = cache->zc_free_elems;

	z_debug_assert(count_a <= zc_mag_size());
	z_debug_assert(count_f <= zc_mag_size());

	cache->zc_alloc_cur = count_f;
	cache->zc_free_cur = count_a;
	cache->zc_alloc_elems = elems_f;
	cache->zc_free_elems = elems_a;
}

__pure2
static smr_t
zone_cache_smr(zone_cache_t cache)
{
	return cache->zc_smr;
}

/*!
 * @function zone_magazine_replace
 *
 * @brief
 * Unlod a magazine and load a new one instead.
 */
static zone_magazine_t
zone_magazine_replace(zone_cache_t zc, zone_magazine_t mag, bool empty)
{
	zone_magazine_t old;
	vm_offset_t **elems;

	mag->zm_seq = SMR_SEQ_INVALID;

	if (empty) {
		elems = &zc->zc_free_elems;
		zc->zc_free_cur = 0;
	} else {
		elems = &zc->zc_alloc_elems;
		zc->zc_alloc_cur = zc_mag_size();
	}
	old = (zone_magazine_t)((uintptr_t)*elems -
	    offsetof(struct zone_magazine, zm_elems));
	*elems = mag->zm_elems;

	return old;
}

static zone_magazine_t
zone_magazine_alloc(zalloc_flags_t flags)
{
	return zalloc_flags(zc_magazine_zone, flags | Z_ZERO);
}

static void
zone_magazine_free(zone_magazine_t mag)
{
	(zfree)(zc_magazine_zone, mag);
}

static void
zone_magazine_free_list(struct zone_depot *zd)
{
	zone_magazine_t tmp, mag = *zd->zd_tail;

	while (mag) {
		tmp = mag->zm_next;
		zone_magazine_free(mag);
		mag = tmp;
	}

	*zd->zd_tail = NULL;
	zd->zd_empty = 0;
}

void
zone_enable_caching(zone_t zone)
{
	size_t size_per_mag = zone_elem_inner_size(zone) * zc_mag_size();
	zone_cache_t caches;
	size_t depot_limit;

	depot_limit = zc_pcpu_max() / size_per_mag;
	zone->z_depot_limit = (uint16_t)MIN(depot_limit, INT16_MAX);

	caches = zalloc_percpu_permanent_type(struct zone_cache);
	zpercpu_foreach(zc, caches) {
		zc->zc_alloc_elems = zone_magazine_alloc(Z_WAITOK | Z_NOFAIL)->zm_elems;
		zc->zc_free_elems = zone_magazine_alloc(Z_WAITOK | Z_NOFAIL)->zm_elems;
		zone_depot_init(&zc->zc_depot);
		hw_lck_ticket_init(&zc->zc_depot_lock, &zone_locks_grp);
	}

	zone_lock(zone);
	assert(zone->z_pcpu_cache == NULL);
	zone->z_pcpu_cache = caches;
	zone->z_recirc_cont_cur = 0;
	zone->z_recirc_cont_wma = 0;
	zone->z_elems_free_min = 0; /* becomes z_recirc_empty_min */
	zone->z_elems_free_wma = 0; /* becomes z_recirc_empty_wma */
	zone_unlock(zone);
}

bool
zone_maps_owned(vm_address_t addr, vm_size_t size)
{
	return from_zone_map(addr, size);
}

#if KASAN_LIGHT
bool
kasan_zone_maps_owned(vm_address_t addr, vm_size_t size)
{
	return from_zone_map(addr, size) ||
	       mach_vm_range_size(&zone_info.zi_map_range) == 0;
}
#endif /* KASAN_LIGHT */

void
zone_map_sizes(
	vm_map_size_t    *psize,
	vm_map_size_t    *pfree,
	vm_map_size_t    *plargest_free)
{
	vm_map_size_t size, free, largest;

	vm_map_sizes(zone_submaps[0], psize, pfree, plargest_free);

	for (uint32_t i = 1; i < Z_SUBMAP_IDX_COUNT; i++) {
		vm_map_sizes(zone_submaps[i], &size, &free, &largest);
		*psize += size;
		*pfree += free;
		*plargest_free = MAX(*plargest_free, largest);
	}
}

__attribute__((always_inline))
vm_map_t
zone_submap(zone_security_flags_t zsflags)
{
	return zone_submaps[zsflags.z_submap_idx];
}

unsigned
zpercpu_count(void)
{
	return zpercpu_early_count;
}

#if ZSECURITY_CONFIG(SAD_FENG_SHUI) || CONFIG_PROB_GZALLOC
/*
 * Returns a random number of a given bit-width.
 *
 * DO NOT COPY THIS CODE OUTSIDE OF ZALLOC
 *
 * This uses Intel's rdrand because random() uses FP registers
 * which causes FP faults and allocations which isn't something
 * we can do from zalloc itself due to reentrancy problems.
 *
 * For pre-rdrand machines (which we no longer support),
 * we use a bad biased random generator that doesn't use FP.
 * Such HW is no longer supported, but VM of newer OSes on older
 * bare metal is made to limp along (with reduced security) this way.
 */
static uint64_t
zalloc_random_mask64(uint32_t bits)
{
	uint64_t mask = ~0ull >> (64 - bits);
	uint64_t v;

#if __x86_64__
	if (__probable(cpuid_features() & CPUID_FEATURE_RDRAND)) {
		asm volatile ("1: rdrand %0; jnc 1b\n" : "=r" (v) :: "cc");
		v &= mask;
	} else {
		disable_preemption();
		int cpu = cpu_number();
		v = random_bool_gen_bits(&zone_bool_gen[cpu].zbg_bg,
		    zone_bool_gen[cpu].zbg_entropy,
		    ZONE_ENTROPY_CNT, bits);
		enable_preemption();
	}
#else
	v = early_random() & mask;
#endif

	return v;
}

/*
 * Returns a random number within [bound_min, bound_max)
 *
 * This isn't _exactly_ uniform, but the skew is small enough
 * not to matter for the consumers of this interface.
 *
 * Values within [bound_min, 2^64 % (bound_max - bound_min))
 * will be returned (bound_max - bound_min) / 2^64 more often
 * than values within [2^64 % (bound_max - bound_min), bound_max).
 */
static uint32_t
zalloc_random_uniform32(uint32_t bound_min, uint32_t bound_max)
{
	uint64_t delta = bound_max - bound_min;

	return bound_min + (uint32_t)(zalloc_random_mask64(64) % delta);
}

#endif /* ZSECURITY_CONFIG(SAD_FENG_SHUI) || CONFIG_PROB_GZALLOC */
#if ZALLOC_ENABLE_LOGGING || CONFIG_PROB_GZALLOC
/*
 * Track all kalloc zones of specified size for zlog name
 * kalloc.type.<size> or kalloc.type.var.<size> or kalloc.<size>
 */
static bool
track_kalloc_zones(zone_t z, const char *logname)
{
	const char *prefix;
	size_t len;
	zone_security_flags_t zsflags = zone_security_config(z);

	prefix = "kalloc.type.var.";
	len    = strlen(prefix);
	if (zsflags.z_kalloc_type && zsflags.z_kheap_id == KHEAP_ID_KT_VAR &&
	    strncmp(logname, prefix, len) == 0) {
		vm_size_t sizeclass = strtoul(logname + len, NULL, 0);

		return zone_elem_inner_size(z) == sizeclass;
	}

	prefix = "kalloc.type.";
	len    = strlen(prefix);
	if (zsflags.z_kalloc_type && zsflags.z_kheap_id != KHEAP_ID_KT_VAR &&
	    strncmp(logname, prefix, len) == 0) {
		vm_size_t sizeclass = strtoul(logname + len, NULL, 0);

		return zone_elem_inner_size(z) == sizeclass;
	}

	prefix = "kalloc.";
	len    = strlen(prefix);
	if ((zsflags.z_kheap_id || zsflags.z_kalloc_type) &&
	    strncmp(logname, prefix, len) == 0) {
		vm_size_t sizeclass = strtoul(logname + len, NULL, 0);

		return zone_elem_inner_size(z) == sizeclass;
	}

	return false;
}
#endif

int
track_this_zone(const char *zonename, const char *logname)
{
	unsigned int len;
	const char *zc = zonename;
	const char *lc = logname;

	/*
	 * Compare the strings.  We bound the compare by MAX_ZONE_NAME.
	 */

	for (len = 1; len <= MAX_ZONE_NAME; zc++, lc++, len++) {
		/*
		 * If the current characters don't match, check for a space in
		 * in the zone name and a corresponding period in the log name.
		 * If that's not there, then the strings don't match.
		 */

		if (*zc != *lc && !(*zc == ' ' && *lc == '.')) {
			break;
		}

		/*
		 * The strings are equal so far.  If we're at the end, then it's a match.
		 */

		if (*zc == '\0') {
			return TRUE;
		}
	}

	return FALSE;
}

#if DEBUG || DEVELOPMENT

vm_size_t
zone_element_info(void *addr, vm_tag_t * ptag)
{
	vm_size_t     size = 0;
	vm_tag_t      tag = VM_KERN_MEMORY_NONE;
	struct zone *src_zone;

	if (from_zone_map(addr, sizeof(void *))) {
		src_zone = zone_by_id(zone_index_from_ptr(addr));
		size     = zone_elem_inner_size(src_zone);
#if VM_TAG_SIZECLASSES
		if (__improbable(src_zone->z_uses_tags)) {
			struct zone_page_metadata *meta;
			vm_offset_t eidx;
			vm_tag_t *slot;

			meta = zone_element_resolve(src_zone,
			    (vm_offset_t)addr, &eidx);
			slot = zba_extra_ref_ptr(meta->zm_bitmap, eidx);
			tag  = *slot;
		}
#endif /* VM_TAG_SIZECLASSES */
	}

	*ptag = tag;
	return size;
}

#endif /* DEBUG || DEVELOPMENT */
#if KASAN_CLASSIC

vm_size_t
kasan_quarantine_resolve(vm_address_t addr, zone_t *zonep)
{
	zone_t zone = zone_by_id(zone_index_from_ptr((void *)addr));

	*zonep = zone;
	return zone_elem_inner_size(zone);
}

#endif /* KASAN_CLASSIC */
#endif /* !ZALLOC_TEST */
#pragma mark Zone zeroing and early random
#if !ZALLOC_TEST

/*
 * Zone zeroing
 *
 * All allocations from zones are zeroed on free and are additionally
 * check that they are still zero on alloc. The check is
 * always on, on embedded devices. Perf regression was detected
 * on intel as we cant use the vectorized implementation of
 * memcmp_zero_ptr_aligned due to cyclic dependenices between
 * initization and allocation. Therefore we perform the check
 * on 20% of the allocations.
 */
#if ZALLOC_ENABLE_ZERO_CHECK
#if defined(__x86_64__)
/*
 * Peform zero validation on every 5th allocation
 */
static TUNABLE(uint32_t, zzc_rate, "zzc_rate", 5);
static uint32_t PERCPU_DATA(zzc_decrementer);
#endif /* defined(__x86_64__) */

/*
 * Determine if zero validation for allocation should be skipped
 */
static bool
zalloc_skip_zero_check(void)
{
#if defined(__x86_64__)
	uint32_t *counterp, cnt;

	counterp = PERCPU_GET(zzc_decrementer);
	cnt = *counterp;
	if (__probable(cnt > 0)) {
		*counterp  = cnt - 1;
		return true;
	}
	*counterp = zzc_rate - 1;
#endif /* !defined(__x86_64__) */
	return false;
}

__abortlike
static void
zalloc_uaf_panic(zone_t z, uintptr_t elem, size_t size)
{
	uint32_t esize = (uint32_t)zone_elem_inner_size(z);
	uint32_t first_offs = ~0u;
	uintptr_t first_bits = 0, v;
	char buf[1024];
	int pos = 0;

	buf[0] = '\0';

	for (uint32_t o = 0; o < size; o += sizeof(v)) {
		if ((v = *(uintptr_t *)(elem + o)) == 0) {
			continue;
		}
		pos += scnprintf(buf + pos, sizeof(buf) - pos, "\n"
		    "%5d: 0x%016lx", o, v);
		if (first_offs > o) {
			first_offs = o;
			first_bits = v;
		}
	}

	(panic)("[%s%s]: element modified after free "
	"(off:%d, val:0x%016lx, sz:%d, ptr:%p)%s",
	zone_heap_name(z), zone_name(z),
	first_offs, first_bits, esize, (void *)elem, buf);
}

static void
zalloc_validate_element(
	zone_t                  zone,
	vm_offset_t             elem,
	vm_size_t               size,
	zalloc_flags_t          flags)
{
	if (flags & Z_NOZZC) {
		return;
	}
	if (memcmp_zero_ptr_aligned((void *)elem, size)) {
		zalloc_uaf_panic(zone, elem, size);
	}
	if (flags & Z_PCPU) {
		for (size_t i = zpercpu_count(); --i > 0;) {
			elem += PAGE_SIZE;
			if (memcmp_zero_ptr_aligned((void *)elem, size)) {
				zalloc_uaf_panic(zone, elem, size);
			}
		}
	}
}

#endif /* ZALLOC_ENABLE_ZERO_CHECK */

__attribute__((noinline))
static void
zone_early_scramble_rr(zone_t zone, int cpu, zone_stats_t zs)
{
#if KASAN_FAKESTACK
	/*
	 * This can cause re-entrancy with kasan fakestacks
	 */
#pragma unused(zone, cpu, zs)
#else
	uint32_t bits;

	bits = random_bool_gen_bits(&zone_bool_gen[cpu].zbg_bg,
	    zone_bool_gen[cpu].zbg_entropy, ZONE_ENTROPY_CNT, 8);

	zs->zs_alloc_rr += bits;
	zs->zs_alloc_rr %= zone->z_chunk_elems;
#endif
}

#endif /* !ZALLOC_TEST */
#pragma mark Zone Leak Detection
#if !ZALLOC_TEST
#if ZALLOC_ENABLE_LOGGING || CONFIG_ZLEAKS

/*
 * Zone leak debugging code
 *
 * When enabled, this code keeps a log to track allocations to a particular
 * zone that have not yet been freed.
 *
 * Examining this log will reveal the source of a zone leak.
 *
 * The log is allocated only when logging is enabled (it is off by default),
 * so there is no effect on the system when it's turned off.
 *
 * Zone logging is enabled with the `zlog<n>=<zone>` boot-arg for each
 * zone name to log, with n starting at 1.
 *
 * Leaks debugging utilizes 2 tunables:
 * - zlsize (in kB) which describes how much "size" the record covers
 *   (zones with smaller elements get more records, default is 4M).
 *
 * - zlfreq (in kB) which describes a sample rate in cumulative allocation
 *   size at which automatic leak detection will sample allocations.
 *   (default is 16k)
 *
 *
 * Zone corruption logging
 *
 * Logging can also be used to help identify the source of a zone corruption.
 *
 * First, identify the zone that is being corrupted,
 * then add "-zc zlog<n>=<zone name>" to the boot-args.
 *
 * When -zc is used in conjunction with zlog,
 * it changes the logging style to track both allocations and frees to the zone.
 *
 * When the corruption is detected, examining the log will show you the stack
 * traces of the callers who last allocated and freed any particular element in
 * the zone.
 *
 * Corruption debugging logs will have zrecs records
 * (tuned by the zrecs= boot-arg, 16k elements per G of RAM by default).
 */

#define ZRECORDS_MAX            (256u << 10)
#define ZRECORDS_DEFAULT        (16u  << 10)
static TUNABLE(uint32_t, zrecs, "zrecs", 0);
static TUNABLE(uint32_t, zlsize, "zlsize", 4 * 1024);
static TUNABLE(uint32_t, zlfreq, "zlfreq", 16);

__startup_func
static void
zone_leaks_init_zrecs(void)
{
	/*
	 * Don't allow more than ZRECORDS_MAX records,
	 * even if the user asked for more.
	 *
	 * This prevents accidentally hogging too much kernel memory
	 * and making the system unusable.
	 */
	if (zrecs == 0) {
		zrecs = ZRECORDS_DEFAULT *
		    (uint32_t)((max_mem + (1ul << 30)) >> 30);
	}
	if (zrecs > ZRECORDS_MAX) {
		zrecs = ZRECORDS_MAX;
	}
}
STARTUP(TUNABLES, STARTUP_RANK_MIDDLE, zone_leaks_init_zrecs);

static uint32_t
zone_leaks_record_count(zone_t z)
{
	uint32_t recs = (zlsize << 10) / zone_elem_inner_size(z);

	return MIN(MAX(recs, ZRECORDS_DEFAULT), ZRECORDS_MAX);
}

static uint32_t
zone_leaks_sample_rate(zone_t z)
{
	return (zlfreq << 10) / zone_elem_inner_size(z);
}

#if ZALLOC_ENABLE_LOGGING
/* Log allocations and frees to help debug a zone element corruption */
static TUNABLE(bool, corruption_debug_flag, "-zc", false);

/*
 * A maximum of 10 zlog<n> boot args can be provided (zlog1 -> zlog10)
 */
#define MAX_ZONES_LOG_REQUESTS  10

/**
 * @function zone_setup_logging
 *
 * @abstract
 * Optionally sets up a zone for logging.
 *
 * @discussion
 * We recognized two boot-args:
 *
 *	zlog=<zone_to_log>
 *	zrecs=<num_records_in_log>
 *	zlsize=<memory to cover for leaks>
 *
 * The zlog arg is used to specify the zone name that should be logged,
 * and zrecs/zlsize is used to control the size of the log.
 */
static void
zone_setup_logging(zone_t z)
{
	char zone_name[MAX_ZONE_NAME]; /* Temp. buffer for the zone name */
	char zlog_name[MAX_ZONE_NAME]; /* Temp. buffer to create the strings zlog1, zlog2 etc... */
	char zlog_val[MAX_ZONE_NAME];  /* the zone name we're logging, if any */
	bool logging_on = false;

	/*
	 * Append kalloc heap name to zone name (if zone is used by kalloc)
	 */
	snprintf(zone_name, MAX_ZONE_NAME, "%s%s", zone_heap_name(z), z->z_name);

	/* zlog0 isn't allowed. */
	for (int i = 1; i <= MAX_ZONES_LOG_REQUESTS; i++) {
		snprintf(zlog_name, MAX_ZONE_NAME, "zlog%d", i);

		if (PE_parse_boot_argn(zlog_name, zlog_val, sizeof(zlog_val))) {
			if (track_this_zone(zone_name, zlog_val) ||
			    track_kalloc_zones(z, zlog_val)) {
				logging_on = true;
				break;
			}
		}
	}

	/*
	 * Backwards compat. with the old boot-arg used to specify single zone
	 * logging i.e. zlog Needs to happen after the newer zlogn checks
	 * because the prefix will match all the zlogn
	 * boot-args.
	 */
	if (!logging_on &&
	    PE_parse_boot_argn("zlog", zlog_val, sizeof(zlog_val))) {
		if (track_this_zone(zone_name, zlog_val) ||
		    track_kalloc_zones(z, zlog_val)) {
			logging_on = true;
		}
	}

	/*
	 * If we want to log a zone, see if we need to allocate buffer space for
	 * the log.
	 *
	 * Some vm related zones are zinit'ed before we can do a kmem_alloc, so
	 * we have to defer allocation in that case.
	 *
	 * zone_init() will finish the job.
	 *
	 * If we want to log one of the VM related zones that's set up early on,
	 * we will skip allocation of the log until zinit is called again later
	 * on some other zone.
	 */
	if (logging_on) {
		if (corruption_debug_flag) {
			z->z_btlog = btlog_create(BTLOG_LOG, zrecs, 0);
		} else {
			z->z_btlog = btlog_create(BTLOG_HASH,
			    zone_leaks_record_count(z), 0);
		}
		if (z->z_btlog) {
			z->z_log_on = true;
			printf("zone[%s%s]: logging enabled\n",
			    zone_heap_name(z), z->z_name);
		} else {
			printf("zone[%s%s]: failed to enable logging\n",
			    zone_heap_name(z), z->z_name);
		}
	}
}

#endif /* ZALLOC_ENABLE_LOGGING */
#if KASAN_TBI
static TUNABLE(uint32_t, kasan_zrecs, "kasan_zrecs", 0);

__startup_func
static void
kasan_tbi_init_zrecs(void)
{
	/*
	 * Don't allow more than ZRECORDS_MAX records,
	 * even if the user asked for more.
	 *
	 * This prevents accidentally hogging too much kernel memory
	 * and making the system unusable.
	 */
	if (kasan_zrecs == 0) {
		kasan_zrecs = ZRECORDS_DEFAULT *
		    (uint32_t)((max_mem + (1ul << 30)) >> 30);
	}
	if (kasan_zrecs > ZRECORDS_MAX) {
		kasan_zrecs = ZRECORDS_MAX;
	}
}
STARTUP(TUNABLES, STARTUP_RANK_MIDDLE, kasan_tbi_init_zrecs);

static void
zone_setup_kasan_logging(zone_t z)
{
	if (!z->z_tbi_tag) {
		printf("zone[%s%s]: kasan logging disabled for this zone\n",
		    zone_heap_name(z), z->z_name);
		return;
	}

	z->z_log_on = true;
	z->z_btlog = btlog_create(BTLOG_LOG, kasan_zrecs, 0);
	if (!z->z_btlog) {
		printf("zone[%s%s]: failed to enable kasan logging\n",
		    zone_heap_name(z), z->z_name);
	}
}

#endif /* KASAN_TBI */
#if CONFIG_ZLEAKS

static thread_call_data_t zone_leaks_callout;

/*
 * The zone leak detector, abbreviated 'zleak', keeps track
 * of a subset of the currently outstanding allocations
 * made by the zone allocator.
 *
 * It will engage itself automatically if the zone map usage
 * goes above zleak_pages_global_wired_threshold pages.
 *
 * When that threshold is reached, zones who use more than
 * zleak_pages_per_zone_wired_threshold pages will get
 * a BTLOG_HASH btlog with sampling to minimize perf impact,
 * yet receive statistical data about the backtrace that is
 * the most likely to cause the leak.
 *
 * If the zone goes under the threshold enough, then the log
 * is disabled and backtraces freed. Data can be collected
 * from userspace with the zlog(1) command.
 */

/* whether the zleaks subsystem thinks the map is under pressure */
uint32_t                zleak_active;
SECURITY_READ_ONLY_LATE(vm_size_t) zleak_max_zonemap_size;

/* Size of zone map at which to start collecting data */
static size_t           zleak_pages_global_wired_threshold = ~0;
vm_size_t               zleak_global_tracking_threshold = ~0;

/* Size a zone will have before we will collect data on it */
static size_t           zleak_pages_per_zone_wired_threshold = ~0;
vm_size_t               zleak_per_zone_tracking_threshold = ~0;

static inline bool
zleak_should_enable_for_zone(zone_t z)
{
	if (z->z_log_on) {
		return false;
	}
	if (z->z_btlog) {
		return false;
	}
	if (!zleak_active) {
		return false;
	}
	return z->z_wired_cur >= zleak_pages_per_zone_wired_threshold;
}

static inline bool
zleak_should_disable_for_zone(zone_t z)
{
	if (z->z_log_on) {
		return false;
	}
	if (!z->z_btlog) {
		return false;
	}
	if (!zleak_active) {
		return true;
	}
	return z->z_wired_cur < zleak_pages_per_zone_wired_threshold / 2;
}

static inline bool
zleak_should_activate(size_t pages)
{
	return !zleak_active && pages >= zleak_pages_global_wired_threshold;
}

static inline bool
zleak_should_deactivate(size_t pages)
{
	return zleak_active && pages < zleak_pages_global_wired_threshold / 2;
}

static void
zleaks_enable_async(__unused thread_call_param_t p0, __unused thread_call_param_t p1)
{
	size_t pages = os_atomic_load(&zone_pages_wired, relaxed);
	btlog_t log;

	if (zleak_should_activate(pages)) {
		zleak_active = 1;
	} else if (zleak_should_deactivate(pages)) {
		zleak_active = 0;
	}

	zone_foreach(z) {
		if (zleak_should_disable_for_zone(z)) {
			log = z->z_btlog;
			z->z_btlog = NULL;
			assert(z->z_btlog_disabled == NULL);
			btlog_disable(log);
			z->z_btlog_disabled = log;
		}

		if (zleak_should_enable_for_zone(z)) {
			log = z->z_btlog_disabled;
			if (log == NULL) {
				log = btlog_create(BTLOG_HASH,
				    zone_leaks_record_count(z),
				    zone_leaks_sample_rate(z));
			} else if (btlog_enable(log) == KERN_SUCCESS) {
				z->z_btlog_disabled = NULL;
			} else {
				log = NULL;
			}
			os_atomic_store(&z->z_btlog, log, release);
		}
	}
}

__startup_func
static void
zleak_init(void)
{
	zleak_max_zonemap_size = ptoa(zone_pages_wired_max);

	zleak_update_threshold(&zleak_global_tracking_threshold,
	    zleak_max_zonemap_size / 2);
	zleak_update_threshold(&zleak_per_zone_tracking_threshold,
	    zleak_global_tracking_threshold / 8);

	thread_call_setup_with_options(&zone_leaks_callout,
	    zleaks_enable_async, NULL, THREAD_CALL_PRIORITY_USER,
	    THREAD_CALL_OPTIONS_ONCE);
}
STARTUP(ZALLOC, STARTUP_RANK_SECOND, zleak_init);

kern_return_t
zleak_update_threshold(vm_size_t *arg, uint64_t value)
{
	if (value >= zleak_max_zonemap_size) {
		return KERN_INVALID_VALUE;
	}

	if (arg == &zleak_global_tracking_threshold) {
		zleak_global_tracking_threshold = (vm_size_t)value;
		zleak_pages_global_wired_threshold = atop(value);
		if (startup_phase >= STARTUP_SUB_THREAD_CALL) {
			thread_call_enter(&zone_leaks_callout);
		}
		return KERN_SUCCESS;
	}

	if (arg == &zleak_per_zone_tracking_threshold) {
		zleak_per_zone_tracking_threshold = (vm_size_t)value;
		zleak_pages_per_zone_wired_threshold = atop(value);
		if (startup_phase >= STARTUP_SUB_THREAD_CALL) {
			thread_call_enter(&zone_leaks_callout);
		}
		return KERN_SUCCESS;
	}

	return KERN_INVALID_ARGUMENT;
}

static void
panic_display_zleaks(bool has_syms)
{
	bool did_header = false;
	vm_address_t bt[BTLOG_MAX_DEPTH];
	uint32_t len, count;

	zone_foreach(z) {
		btlog_t log = z->z_btlog;

		if (log == NULL || btlog_get_type(log) != BTLOG_HASH) {
			continue;
		}

		count = btlog_guess_top(log, bt, &len);
		if (count == 0) {
			continue;
		}

		if (!did_header) {
			paniclog_append_noflush("Zone (suspected) leak report:\n");
			did_header = true;
		}

		paniclog_append_noflush("  Zone:    %s%s\n",
		    zone_heap_name(z), zone_name(z));
		paniclog_append_noflush("  Count:   %d (%ld bytes)\n", count,
		    (long)count * zone_scale_for_percpu(z, zone_elem_inner_size(z)));
		paniclog_append_noflush("  Size:    %ld\n",
		    (long)zone_size_wired(z));
		paniclog_append_noflush("  Top backtrace:\n");
		for (uint32_t i = 0; i < len; i++) {
			if (has_syms) {
				paniclog_append_noflush("    %p ", (void *)bt[i]);
				panic_print_symbol_name(bt[i]);
				paniclog_append_noflush("\n");
			} else {
				paniclog_append_noflush("    %p\n", (void *)bt[i]);
			}
		}

		kmod_panic_dump(bt, len);
		paniclog_append_noflush("\n");
	}
}
#endif /* CONFIG_ZLEAKS */

#endif /* ZONE_ENABLE_LOGGING || CONFIG_ZLEAKS */
#if ZONE_ENABLE_LOGGING || CONFIG_ZLEAKS || KASAN_TBI

#if !KASAN_TBI
__cold
#endif
static void
zalloc_log(zone_t zone, vm_offset_t addr, uint32_t count, void *fp)
{
	btlog_t log = zone->z_btlog;
	btref_get_flags_t flags = 0;
	btref_t ref;

#if !KASAN_TBI
	if (!log || !btlog_sample(log)) {
		return;
	}
#endif
	if (get_preemption_level() || zone_supports_vm(zone)) {
		/*
		 * VM zones can be used by btlog, avoid reentrancy issues.
		 */
		flags = BTREF_GET_NOWAIT;
	}

	ref = btref_get(fp, flags);
	while (count-- > 0) {
		if (count) {
			btref_retain(ref);
		}
		btlog_record(log, (void *)addr, ZOP_ALLOC, ref);
		addr += *(vm_offset_t *)addr;
	}
}

#define ZALLOC_LOG(zone, addr, count)  ({ \
	if ((zone)->z_btlog) {                                                 \
	        zalloc_log(zone, addr, count, __builtin_frame_address(0));     \
	}                                                                      \
})

#if !KASAN_TBI
__cold
#endif
static void
zfree_log(zone_t zone, vm_offset_t addr, uint32_t count, void *fp)
{
	btlog_t log = zone->z_btlog;
	btref_get_flags_t flags = 0;
	btref_t ref;

#if !KASAN_TBI
	if (!log) {
		return;
	}
#endif

	/*
	 * See if we're doing logging on this zone.
	 *
	 * There are two styles of logging used depending on
	 * whether we're trying to catch a leak or corruption.
	 */
#if !KASAN_TBI
	if (btlog_get_type(log) == BTLOG_HASH) {
		/*
		 * We're logging to catch a leak.
		 *
		 * Remove any record we might have for this element
		 * since it's being freed.  Note that we may not find it
		 * if the buffer overflowed and that's OK.
		 *
		 * Since the log is of a limited size, old records get
		 * overwritten if there are more zallocs than zfrees.
		 */
		while (count-- > 0) {
			btlog_erase(log, (void *)addr);
			addr += *(vm_offset_t *)addr;
		}
		return;
	}
#endif /* !KASAN_TBI */

	if (get_preemption_level() || zone_supports_vm(zone)) {
		/*
		 * VM zones can be used by btlog, avoid reentrancy issues.
		 */
		flags = BTREF_GET_NOWAIT;
	}

	ref = btref_get(fp, flags);
	while (count-- > 0) {
		if (count) {
			btref_retain(ref);
		}
		btlog_record(log, (void *)addr, ZOP_FREE, ref);
		addr += *(vm_offset_t *)addr;
	}
}

#define ZFREE_LOG(zone, addr, count)  ({ \
	if ((zone)->z_btlog) {                                                 \
	        zfree_log(zone, addr, count, __builtin_frame_address(0));      \
	}                                                                      \
})

#else
#define ZALLOC_LOG(...)         ((void)0)
#define ZFREE_LOG(...)          ((void)0)
#endif /* ZALLOC_ENABLE_LOGGING || CONFIG_ZLEAKS || KASAN_TBI */
#endif /* !ZALLOC_TEST */
#pragma mark zone (re)fill
#if !ZALLOC_TEST

/*!
 * @defgroup Zone Refill
 * @{
 *
 * @brief
 * Functions handling The zone refill machinery.
 *
 * @discussion
 * Zones are refilled based on 2 mechanisms: direct expansion, async expansion.
 *
 * @c zalloc_ext() is the codepath that kicks the zone refill when the zone is
 * dropping below half of its @c z_elems_rsv (0 for most zones) and will:
 *
 * - call @c zone_expand_locked() directly if the caller is allowed to block,
 *
 * - wakeup the asynchroous expansion thread call if the caller is not allowed
 *   to block, or if the reserve becomes depleted.
 *
 *
 * <h2>Synchronous expansion</h2>
 *
 * This mechanism is actually the only one that may refill a zone, and all the
 * other ones funnel through this one eventually.
 *
 * @c zone_expand_locked() implements the core of the expansion mechanism,
 * and will do so while a caller specified predicate is true.
 *
 * Zone expansion allows for up to 2 threads to concurrently refill the zone:
 * - one VM privileged thread,
 * - one regular thread.
 *
 * Regular threads that refill will put down their identity in @c z_expander,
 * so that priority inversion avoidance can be implemented.
 *
 * However, VM privileged threads are allowed to use VM page reserves,
 * which allows for the system to recover from extreme memory pressure
 * situations, allowing for the few allocations that @c zone_gc() or
 * killing processes require.
 *
 * When a VM privileged thread is also expanding, the @c z_expander_vm_priv bit
 * is set. @c z_expander is not necessarily the identity of this VM privileged
 * thread (it is if the VM privileged thread came in first, but wouldn't be, and
 * could even be @c THREAD_NULL otherwise).
 *
 * Note that the pageout-scan daemon might be BG and is VM privileged. To avoid
 * spending a whole pointer on priority inheritance for VM privileged threads
 * (and other issues related to having two owners), we use the rwlock boost as
 * a stop gap to avoid priority inversions.
 *
 *
 * <h2>Chunk wiring policies</h2>
 *
 * Zones allocate memory in chunks of @c zone_t::z_chunk_pages pages at a time
 * to try to minimize fragmentation relative to element sizes not aligning with
 * a chunk size well.  However, this can grow large and be hard to fulfill on
 * a system under a lot of memory pressure (chunks can be as long as 8 pages on
 * 4k page systems).
 *
 * This is why, when under memory pressure the system allows chunks to be
 * partially populated. The metadata of the first page in the chunk maintains
 * the count of actually populated pages.
 *
 * The metadata for addresses assigned to a zone are found of 4 queues:
 * - @c z_pageq_empty has chunk heads with populated pages and no allocated
 *   elements (those can be targeted by @c zone_gc()),
 * - @c z_pageq_partial has chunk heads with populated pages that are partially
 *   used,
 * - @c z_pageq_full has chunk heads with populated pages with no free elements
 *   left,
 * - @c z_pageq_va has either chunk heads for sequestered VA space assigned to
 *   the zone forever, or the first secondary metadata for a chunk whose
 *   corresponding page is not populated in the chunk.
 *
 * When new pages need to be wired/populated, chunks from the @c z_pageq_va
 * queues are preferred.
 *
 *
 * <h2>Asynchronous expansion</h2>
 *
 * This mechanism allows for refilling zones used mostly with non blocking
 * callers. It relies on a thread call (@c zone_expand_callout) which will
 * iterate all zones and refill the ones marked with @c z_async_refilling.
 *
 * NOTE: If the calling thread for zalloc_noblock is lower priority than
 *       the thread_call, then zalloc_noblock to an empty zone may succeed.
 *
 *
 * <h2>Dealing with zone allocations from the mach VM code</h2>
 *
 * The implementation of the mach VM itself uses the zone allocator
 * for things like the vm_map_entry data structure. In order to prevent
 * a recursion problem when adding more pages to a zone, the VM zones
 * use the Z_SUBMAP_IDX_VM submap which doesn't use kmem_alloc()
 * or any VM map functions to allocate.
 *
 * Instead, a really simple coalescing first-fit allocator is used
 * for this submap, and no one else than zalloc can allocate from it.
 *
 * Memory is directly populated which doesn't require allocation of
 * VM map entries, and avoids recursion. The cost of this scheme however,
 * is that `vm_map_lookup_entry` will not function on those addresses
 * (nor any API relying on it).
 */

static thread_call_data_t zone_expand_callout;

__attribute__((overloadable))
static inline bool
zone_submap_is_sequestered(zone_submap_idx_t idx)
{
	return idx != Z_SUBMAP_IDX_DATA;
}

__attribute__((overloadable))
static inline bool
zone_submap_is_sequestered(zone_security_flags_t zsflags)
{
	return zone_submap_is_sequestered(zsflags.z_submap_idx);
}

static inline kma_flags_t
zone_kma_flags(zone_t z, zone_security_flags_t zsflags, zalloc_flags_t flags)
{
	kma_flags_t kmaflags = KMA_KOBJECT | KMA_ZERO;

	if (zsflags.z_noencrypt) {
		kmaflags |= KMA_NOENCRYPT;
	}
	if (flags & Z_NOPAGEWAIT) {
		kmaflags |= KMA_NOPAGEWAIT;
	}
	if (z->z_permanent || (!z->z_destructible &&
	    zone_submap_is_sequestered(zsflags))) {
		kmaflags |= KMA_PERMANENT;
	}
	if (zsflags.z_submap_from_end) {
		kmaflags |= KMA_LAST_FREE;
	}

	return kmaflags;
}

static inline void
zone_add_wired_pages(uint32_t pages)
{
	size_t count = os_atomic_add(&zone_pages_wired, pages, relaxed);

#if CONFIG_ZLEAKS
	if (__improbable(zleak_should_activate(count) &&
	    startup_phase >= STARTUP_SUB_THREAD_CALL)) {
		thread_call_enter(&zone_leaks_callout);
	}
#else
	(void)count;
#endif
}

static inline void
zone_remove_wired_pages(uint32_t pages)
{
	size_t count = os_atomic_sub(&zone_pages_wired, pages, relaxed);

#if CONFIG_ZLEAKS
	if (__improbable(zleak_should_deactivate(count) &&
	    startup_phase >= STARTUP_SUB_THREAD_CALL)) {
		thread_call_enter(&zone_leaks_callout);
	}
#else
	(void)count;
#endif
}

/*!
 * @function zcram_and_lock()
 *
 * @brief
 * Prepare some memory for being usable for allocation purposes.
 *
 * @discussion
 * Prepare memory in <code>[addr + ptoa(pg_start), addr + ptoa(pg_end))</code>
 * to be usable in the zone.
 *
 * This function assumes the metadata is already populated for the range.
 *
 * Calling this function with @c pg_start being 0 means that the memory
 * is either a partial chunk, or a full chunk, that isn't published anywhere
 * and the initialization can happen without locks held.
 *
 * Calling this function with a non zero @c pg_start means that we are extending
 * an existing chunk: the memory in <code>[addr, addr + ptoa(pg_start))</code>,
 * is already usable and published in the zone, so extending it requires holding
 * the zone lock.
 *
 * @param zone          The zone to cram new populated pages into
 * @param addr          The base address for the chunk(s)
 * @param pg_va_new     The number of virtual pages newly assigned to the zone
 * @param pg_start      The first newly populated page relative to @a addr.
 * @param pg_end        The after-last newly populated page relative to @a addr.
 * @param lock          0 or ZM_ALLOC_SIZE_LOCK (used by early crams)
 */
static void
zcram_and_lock(zone_t zone, vm_offset_t addr, uint32_t pg_va_new,
    uint32_t pg_start, uint32_t pg_end, uint16_t lock)
{
	zone_id_t zindex = zone_index(zone);
	vm_offset_t elem_size = zone_elem_outer_size(zone);
	uint32_t free_start = 0, free_end = 0;
	uint32_t oob_offs = zone_elem_outer_offs(zone);

	struct zone_page_metadata *meta = zone_meta_from_addr(addr);
	uint32_t chunk_pages = zone->z_chunk_pages;
	bool guarded = meta->zm_guarded;

	assert(pg_start < pg_end && pg_end <= chunk_pages);

	if (pg_start == 0) {
		uint16_t chunk_len = (uint16_t)pg_end;
		uint16_t secondary_len = ZM_SECONDARY_PAGE;
		bool inline_bitmap = false;

		if (zone->z_percpu) {
			chunk_len = 1;
			secondary_len = ZM_SECONDARY_PCPU_PAGE;
			assert(pg_end == zpercpu_count());
		}
		if (!zone->z_permanent && !zone->z_uses_tags) {
			inline_bitmap = zone->z_chunk_elems <= 32 * chunk_pages;
		}

		free_end = (uint32_t)(ptoa(chunk_len) - oob_offs) / elem_size;

		meta[0] = (struct zone_page_metadata){
			.zm_index         = zindex,
			.zm_guarded       = guarded,
			.zm_inline_bitmap = inline_bitmap,
			.zm_chunk_len     = chunk_len,
			.zm_alloc_size    = lock,
		};

		if (!zone->z_permanent && !inline_bitmap) {
			meta[0].zm_bitmap = zone_meta_bits_alloc_init(free_end,
			    zone->z_chunk_elems, zone->z_uses_tags);
		}

		for (uint16_t i = 1; i < chunk_pages; i++) {
			meta[i] = (struct zone_page_metadata){
				.zm_index          = zindex,
				.zm_guarded        = guarded,
				.zm_inline_bitmap  = inline_bitmap,
				.zm_chunk_len      = secondary_len,
				.zm_page_index     = (uint8_t)i,
				.zm_bitmap         = meta[0].zm_bitmap,
				.zm_subchunk_len   = (uint8_t)(chunk_pages - i),
			};
		}

		if (inline_bitmap) {
			zone_meta_bits_init_inline(meta, free_end);
		}
	} else {
		assert(!zone->z_percpu && !zone->z_permanent);

		free_end = (uint32_t)(ptoa(pg_end) - oob_offs) / elem_size;
		free_start = (uint32_t)(ptoa(pg_start) - oob_offs) / elem_size;
	}

#if KASAN_CLASSIC
	assert(pg_start == 0); /* KASAN_CLASSIC never does partial chunks */
	if (zone->z_permanent) {
		kasan_poison_range(addr, ptoa(pg_end), ASAN_VALID);
	} else if (zone->z_percpu) {
		for (uint32_t i = 0; i < pg_end; i++) {
			kasan_zmem_add(addr + ptoa(i), PAGE_SIZE,
			    zone_elem_outer_size(zone),
			    zone_elem_outer_offs(zone),
			    zone_elem_redzone(zone));
		}
	} else {
		kasan_zmem_add(addr, ptoa(pg_end),
		    zone_elem_outer_size(zone),
		    zone_elem_outer_offs(zone),
		    zone_elem_redzone(zone));
	}
#endif /* KASAN_CLASSIC */

	/*
	 * Insert the initialized pages / metadatas into the right lists.
	 */

	zone_lock(zone);
	assert(zone->z_self == zone);

	if (pg_start != 0) {
		assert(meta->zm_chunk_len == pg_start);

		zone_meta_bits_merge(meta, free_start, free_end);
		meta->zm_chunk_len = (uint16_t)pg_end;

		/*
		 * consume the zone_meta_lock_in_partial()
		 * done in zone_expand_locked()
		 */
		zone_meta_alloc_size_sub(zone, meta, ZM_ALLOC_SIZE_LOCK);
		zone_meta_remqueue(zone, meta);
	}

	if (zone->z_permanent || meta->zm_alloc_size) {
		zone_meta_queue_push(zone, &zone->z_pageq_partial, meta);
	} else {
		zone_meta_queue_push(zone, &zone->z_pageq_empty, meta);
		zone->z_wired_empty += zone->z_percpu ? 1 : pg_end;
	}
	if (pg_end < chunk_pages) {
		/* push any non populated residual VA on z_pageq_va */
		zone_meta_queue_push(zone, &zone->z_pageq_va, meta + pg_end);
	}

	zone->z_elems_free  += free_end - free_start;
	zone->z_elems_avail += free_end - free_start;
	zone->z_wired_cur   += zone->z_percpu ? 1 : pg_end - pg_start;
	if (pg_va_new) {
		zone->z_va_cur += zone->z_percpu ? 1 : pg_va_new;
	}
	if (zone->z_wired_hwm < zone->z_wired_cur) {
		zone->z_wired_hwm = zone->z_wired_cur;
	}

#if CONFIG_ZLEAKS
	if (__improbable(zleak_should_enable_for_zone(zone) &&
	    startup_phase >= STARTUP_SUB_THREAD_CALL)) {
		thread_call_enter(&zone_leaks_callout);
	}
#endif /* CONFIG_ZLEAKS */

	zone_add_wired_pages(pg_end - pg_start);
}

static void
zcram(zone_t zone, vm_offset_t addr, uint32_t pages, uint16_t lock)
{
	uint32_t chunk_pages = zone->z_chunk_pages;

	assert(pages % chunk_pages == 0);
	for (; pages > 0; pages -= chunk_pages, addr += ptoa(chunk_pages)) {
		zcram_and_lock(zone, addr, chunk_pages, 0, chunk_pages, lock);
		zone_unlock(zone);
	}
}

__startup_func
void
zone_cram_early(zone_t zone, vm_offset_t newmem, vm_size_t size)
{
	uint32_t pages = (uint32_t)atop(size);

	assert(from_zone_map(newmem, size));
	assert3u(size % ptoa(zone->z_chunk_pages), ==, 0);
	assert3u(startup_phase, <, STARTUP_SUB_ZALLOC);

	/*
	 * The early pages we move at the pmap layer can't be "depopulated"
	 * because there's no vm_page_t for them.
	 *
	 * "Lock" them so that they never hit z_pageq_empty.
	 */
	bzero((void *)newmem, size);
	zcram(zone, newmem, pages, ZM_ALLOC_SIZE_LOCK);
}

/*!
 * @function zone_submap_alloc_sequestered_va
 *
 * @brief
 * Allocates VA without using vm_find_space().
 *
 * @discussion
 * Allocate VA quickly without using the slower vm_find_space() for cases
 * when the submaps are fully sequestered.
 *
 * The VM submap is used to implement the VM itself so it is always sequestered,
 * as it can't kmem_alloc which needs to always allocate vm entries.
 * However, it can use vm_map_enter() which tries to coalesce entries, which
 * always works, so the VM map only ever needs 2 entries (one for each end).
 *
 * The RO submap is similarly always sequestered if it exists (as a non
 * sequestered RO submap makes very little sense).
 *
 * The allocator is a very simple bump-allocator
 * that allocates from either end.
 */
static kern_return_t
zone_submap_alloc_sequestered_va(zone_security_flags_t zsflags, uint32_t pages,
    vm_offset_t *addrp)
{
	vm_size_t size = ptoa(pages);
	vm_map_t map = zone_submap(zsflags);
	vm_map_entry_t first, last;
	vm_map_offset_t addr;

	vm_map_lock(map);

	first = vm_map_first_entry(map);
	last = vm_map_last_entry(map);

	if (first->vme_end + size > last->vme_start) {
		vm_map_unlock(map);
		return KERN_NO_SPACE;
	}

	if (zsflags.z_submap_from_end) {
		last->vme_start -= size;
		addr = last->vme_start;
		VME_OFFSET_SET(last, addr);
	} else {
		addr = first->vme_end;
		first->vme_end += size;
	}
	map->size += size;

	vm_map_unlock(map);

	*addrp = addr;
	return KERN_SUCCESS;
}

void
zone_fill_initially(zone_t zone, vm_size_t nelems)
{
	kma_flags_t kmaflags = KMA_NOFAIL | KMA_PERMANENT;
	kern_return_t kr;
	vm_offset_t addr;
	uint32_t pages;
	zone_security_flags_t zsflags = zone_security_config(zone);

	assert(!zone->z_permanent && !zone->collectable && !zone->z_destructible);
	assert(zone->z_elems_avail == 0);

	kmaflags |= zone_kma_flags(zone, zsflags, Z_WAITOK);
	pages = zone_alloc_pages_for_nelems(zone, nelems);
	if (zone_submap_is_sequestered(zsflags)) {
		kr = zone_submap_alloc_sequestered_va(zsflags, pages, &addr);
		if (kr != KERN_SUCCESS) {
			panic("zone_submap_alloc_sequestered_va() "
			    "of %u pages failed", pages);
		}
		kernel_memory_populate(addr, ptoa(pages),
		    kmaflags, VM_KERN_MEMORY_ZONE);
	} else {
		assert(zsflags.z_submap_idx != Z_SUBMAP_IDX_READ_ONLY);
		kmem_alloc(zone_submap(zsflags), &addr, ptoa(pages),
		    kmaflags, VM_KERN_MEMORY_ZONE);
	}

	zone_meta_populate(addr, ptoa(pages));
	zcram(zone, addr, pages, 0);
}

#if ZSECURITY_CONFIG(SAD_FENG_SHUI)
__attribute__((noinline))
static void
zone_scramble_va_and_unlock(
	zone_t                      z,
	struct zone_page_metadata  *meta,
	uint32_t                    runs,
	uint32_t                    pages,
	uint32_t                    chunk_pages,
	uint64_t                    guard_mask)
{
	struct zone_page_metadata *arr[ZONE_CHUNK_ALLOC_SIZE / 4096];

	for (uint32_t run = 0, n = 0; run < runs; run++) {
		arr[run] = meta + n;
		n += chunk_pages + ((guard_mask >> run) & 1);
	}

	/*
	 * Fisher–Yates shuffle, for an array with indices [0, n)
	 *
	 * for i from n−1 downto 1 do
	 *     j ← random integer such that 0 ≤ j ≤ i
	 *     exchange a[j] and a[i]
	 *
	 * The point here is that early allocations aren't at a fixed
	 * distance from each other.
	 */
	for (uint32_t i = runs - 1; i > 0; i--) {
		uint32_t j = zalloc_random_uniform32(0, i + 1);

		meta   = arr[j];
		arr[j] = arr[i];
		arr[i] = meta;
	}

	zone_lock(z);

	for (uint32_t i = 0; i < runs; i++) {
		zone_meta_queue_push(z, &z->z_pageq_va, arr[i]);
	}
	z->z_va_cur += z->z_percpu ? runs : pages;
}

static inline uint32_t
dist_u32(uint32_t a, uint32_t b)
{
	return a < b ? b - a : a - b;
}

static uint64_t
zalloc_random_clear_n_bits(uint64_t mask, uint32_t pop, uint32_t n)
{
	for (; n-- > 0; pop--) {
		uint32_t bit = zalloc_random_uniform32(0, pop);
		uint64_t m = mask;

		for (; bit; bit--) {
			m &= m - 1;
		}

		mask ^= 1ull << __builtin_ctzll(m);
	}

	return mask;
}

/**
 * @function zalloc_random_bits
 *
 * @brief
 * Compute a random number with a specified number of bit set in a given width.
 *
 * @discussion
 * This function generates a "uniform" distribution of sets of bits set in
 * a given width, with typically less than width/4 calls to random.
 *
 * @param pop           the target number of bits set.
 * @param width         the number of bits in the random integer to generate.
 */
static uint64_t
zalloc_random_bits(uint32_t pop, uint32_t width)
{
	uint64_t w_mask = (1ull << width) - 1;
	uint64_t mask;
	uint32_t cur;

	if (3 * width / 4 <= pop) {
		mask = w_mask;
		cur  = width;
	} else if (pop <= width / 4) {
		mask = 0;
		cur  = 0;
	} else {
		/*
		 * Chosing a random number this way will overwhelmingly
		 * contain `width` bits +/- a few.
		 */
		mask = zalloc_random_mask64(width);
		cur  = __builtin_popcountll(mask);

		if (dist_u32(cur, pop) > dist_u32(width - cur, pop)) {
			/*
			 * If the opposite mask has a closer popcount,
			 * then start with that one as the seed.
			 */
			cur = width - cur;
			mask ^= w_mask;
		}
	}

	if (cur < pop) {
		/*
		 * Setting `pop - cur` bits is really clearing that many from
		 * the opposite mask.
		 */
		mask ^= w_mask;
		mask = zalloc_random_clear_n_bits(mask, width - cur, pop - cur);
		mask ^= w_mask;
	} else if (pop < cur) {
		mask = zalloc_random_clear_n_bits(mask, cur, cur - pop);
	}

	return mask;
}
#endif

static void
zone_allocate_va_locked(zone_t z, zalloc_flags_t flags)
{
	zone_security_flags_t zsflags = zone_security_config(z);
	struct zone_page_metadata *meta;
	kma_flags_t kmaflags = zone_kma_flags(z, zsflags, flags) | KMA_VAONLY;
	uint32_t chunk_pages = z->z_chunk_pages;
	uint32_t runs, pages, guards, rnum;
	uint64_t guard_mask = 0;
	bool     lead_guard = false;
	kern_return_t kr;
	vm_offset_t addr;

	zone_unlock(z);

	/*
	 * A lot of OOB exploitation techniques rely on precise placement
	 * and interleaving of zone pages. The layout that is sought
	 * by attackers will be C/P/T types, where:
	 * - (C)ompromised is the type for which attackers have a bug,
	 * - (P)adding is used to pad memory,
	 * - (T)arget is the type that the attacker will attempt to corrupt
	 *   by exploiting (C).
	 *
	 * Note that in some cases C==T and P isn't needed.
	 *
	 * In order to make those placement games much harder,
	 * we grow zones by random runs of memory, up to 256k.
	 * This makes predicting the precise layout of the heap
	 * quite more complicated.
	 *
	 * Note: this function makes a very heavy use of random,
	 *       however, it is mostly limited to sequestered zones,
	 *       and eventually the layout will be fixed,
	 *       and the usage of random vastly reduced.
	 *
	 *       For non sequestered zones, there's a single call
	 *       to random in order to decide whether we want
	 *       a guard page or not.
	 */
	pages  = chunk_pages;
	guards = 0;
	runs   = 1;
#if ZSECURITY_CONFIG(SAD_FENG_SHUI)
	if (!z->z_percpu && zone_submap_is_sequestered(zsflags)) {
		pages = atop(ZONE_CHUNK_ALLOC_SIZE);
		runs  = (pages + chunk_pages - 1) / chunk_pages;
		runs  = zalloc_random_uniform32(1, runs + 1);
		pages = runs * chunk_pages;
	}
	static_assert(ZONE_CHUNK_ALLOC_SIZE / 4096 <= 64,
	    "make sure that `runs` will never be larger than 64");
#endif /* !ZSECURITY_CONFIG(SAD_FENG_SHUI) */

	/*
	 * Zones that are suceptible to OOB (kalloc, ZC_PGZ_USE_GUARDS),
	 * guards might be added after each chunk.
	 *
	 * Those guard pages are marked with the ZM_PGZ_GUARD
	 * magical chunk len, and their zm_oob_offs field
	 * is used to remember optional shift applied
	 * to returned elements, in order to right-align-them
	 * as much as possible.
	 *
	 * In an adversarial context, while guard pages
	 * are extremely effective against linear overflow,
	 * using a predictable density of guard pages feels like
	 * a missed opportunity. Which is why we chose to insert
	 * one guard page for about 32k of memory, and place it
	 * randomly.
	 */
#if ZSECURITY_CONFIG(SAD_FENG_SHUI)
	if (z->z_percpu) {
		/*
		 * For per-cpu runs, have a 75% chance to have a guard.
		 */
		rnum = zalloc_random_uniform32(0, 4 * 128);
		guards = rnum >= 128;
	} else if (!zsflags.z_pgz_use_guards && !z->z_pgz_use_guards) {
		vm_offset_t rest;

		/*
		 * For types that are less susceptible to have OOBs,
		 * have a density of 1 guard every 64k, with a uniform
		 * distribution.
		 */
		rnum   = zalloc_random_uniform32(0, ZONE_GUARD_SPARSE);
		guards = (uint32_t)ptoa(pages) / ZONE_GUARD_SPARSE;
		rest   = (uint32_t)ptoa(pages) % ZONE_GUARD_SPARSE;
		guards += rnum < rest;
	} else if (ptoa(chunk_pages) >= ZONE_GUARD_DENSE) {
		/*
		 * For chunks >= 32k, have a 75% chance of guard pages
		 * between chunks.
		 */
		rnum = zalloc_random_uniform32(65, 129);
		guards = runs * rnum / 128;
	} else {
		vm_offset_t rest;

		/*
		 * Otherwise, aim at 1 guard every 32k,
		 * with a uniform distribution.
		 */
		rnum   = zalloc_random_uniform32(0, ZONE_GUARD_DENSE);
		guards = (uint32_t)ptoa(pages) / ZONE_GUARD_DENSE;
		rest   = (uint32_t)ptoa(pages) % ZONE_GUARD_DENSE;
		guards += rnum < rest;
	}
	assert3u(guards, <=, runs);

	guard_mask = 0;

	if (!z->z_percpu && zone_submap_is_sequestered(zsflags)) {
		uint32_t g = 0;

		/*
		 * Several exploitation strategies rely on a C/T (compromised
		 * then target types) ordering of pages with a sub-page reach
		 * from C into T.
		 *
		 * We want to reliably thwart such exploitations
		 * and hence force a guard page between alternating
		 * memory types.
		 */
		guard_mask |= 1ull << (runs - 1);
		g++;

		/*
		 * While we randomize the chunks lengths, an attacker with
		 * precise timing control can guess when overflows happen,
		 * and "measure" the runs, which gives them an indication
		 * of where the next run start offset is.
		 *
		 * In order to make this knowledge unusable, add a guard page
		 * _before_ the new run with a 25% probability, regardless
		 * of whether we had enough guard pages.
		 */
		if ((rnum & 3) == 0) {
			lead_guard = true;
			g++;
		}
		if (guards > g) {
			guard_mask |= zalloc_random_bits(guards - g, runs - 1);
		} else {
			guards = g;
		}
	} else {
		assert3u(runs, ==, 1);
		assert3u(guards, <=, 1);
		guard_mask = guards << (runs - 1);
	}
#else
	(void)rnum;
#endif /* ZSECURITY_CONFIG(SAD_FENG_SHUI) */

	if (zone_submap_is_sequestered(zsflags)) {
		kr = zone_submap_alloc_sequestered_va(zsflags,
		    pages + guards, &addr);
	} else {
		assert(zsflags.z_submap_idx != Z_SUBMAP_IDX_READ_ONLY);
		kr = kmem_alloc(zone_submap(zsflags), &addr,
		    ptoa(pages + guards), kmaflags, VM_KERN_MEMORY_ZONE);
	}

	if (kr != KERN_SUCCESS) {
		uint64_t zone_size = 0;
		zone_t zone_largest = zone_find_largest(&zone_size);
		panic("zalloc[%d]: zone map exhausted while allocating from zone [%s%s], "
		    "likely due to memory leak in zone [%s%s] "
		    "(%u%c, %d elements allocated)",
		    kr, zone_heap_name(z), zone_name(z),
		    zone_heap_name(zone_largest), zone_name(zone_largest),
		    mach_vm_size_pretty(zone_size),
		    mach_vm_size_unit(zone_size),
		    zone_count_allocated(zone_largest));
	}

	meta = zone_meta_from_addr(addr);
	zone_meta_populate(addr, ptoa(pages + guards));

	/*
	 * Handle the leading guard page if any
	 */
	if (lead_guard) {
		meta[0].zm_index = zone_index(z);
		meta[0].zm_chunk_len = ZM_PGZ_GUARD;
		meta[0].zm_guarded = true;
		meta++;
	}

	for (uint32_t run = 0, n = 0; run < runs; run++) {
		bool guarded = (guard_mask >> run) & 1;

		for (uint32_t i = 0; i < chunk_pages; i++, n++) {
			meta[n].zm_index = zone_index(z);
			meta[n].zm_guarded = guarded;
		}
		if (guarded) {
			meta[n].zm_index = zone_index(z);
			meta[n].zm_chunk_len = ZM_PGZ_GUARD;
			n++;
		}
	}
	if (guards) {
		os_atomic_add(&zone_guard_pages, guards, relaxed);
	}

#if ZSECURITY_CONFIG(SAD_FENG_SHUI)
	if (__improbable(zone_caching_disabled < 0)) {
		return zone_scramble_va_and_unlock(z, meta, runs, pages,
		           chunk_pages, guard_mask);
	}
#endif /* ZSECURITY_CONFIG(SAD_FENG_SHUI) */

	zone_lock(z);

	for (uint32_t run = 0, n = 0; run < runs; run++) {
		zone_meta_queue_push(z, &z->z_pageq_va, meta + n);
		n += chunk_pages + ((guard_mask >> run) & 1);
	}
	z->z_va_cur += z->z_percpu ? runs : pages;
}

static bool
zone_expand_pred_nope(__unused zone_t z)
{
	return false;
}

static inline void
ZONE_TRACE_VM_KERN_REQUEST_START(vm_size_t size)
{
#if DEBUG || DEVELOPMENT
	VM_DEBUG_CONSTANT_EVENT(vm_kern_request, VM_KERN_REQUEST, DBG_FUNC_START,
	    size, 0, 0, 0);
#else
	(void)size;
#endif
}

static inline void
ZONE_TRACE_VM_KERN_REQUEST_END(uint32_t pages)
{
#if DEBUG || DEVELOPMENT
	task_t task = current_task_early();
	if (pages && task) {
		ledger_credit(task->ledger, task_ledgers.pages_grabbed_kern, pages);
	}
	VM_DEBUG_CONSTANT_EVENT(vm_kern_request, VM_KERN_REQUEST, DBG_FUNC_END,
	    pages, 0, 0, 0);
#else
	(void)pages;
#endif
}

__attribute__((noinline))
static void
__ZONE_MAP_EXHAUSTED_AND_WAITING_FOR_GC__(zone_t z, uint32_t pgs)
{
	uint64_t wait_start = 0;
	long mapped;

	thread_wakeup(VM_PAGEOUT_GC_EVENT);

	if (zone_supports_vm(z) || (current_thread()->options & TH_OPT_VMPRIV)) {
		return;
	}

	mapped = os_atomic_load(&zone_pages_wired, relaxed);

	/*
	 * If the zone map is really exhausted, wait on the GC thread,
	 * donating our priority (which is important because the GC
	 * thread is at a rather low priority).
	 */
	for (uint32_t n = 1; mapped >= zone_pages_wired_max - pgs; n++) {
		uint32_t wait_ms = n * (n + 1) / 2;
		uint64_t interval;

		if (n == 1) {
			wait_start = mach_absolute_time();
		} else {
			thread_wakeup(VM_PAGEOUT_GC_EVENT);
		}
		if (zone_exhausted_timeout > 0 &&
		    wait_ms > zone_exhausted_timeout) {
			panic("zone map exhaustion: waited for %dms "
			    "(pages: %ld, max: %ld, wanted: %d)",
			    wait_ms, mapped, zone_pages_wired_max, pgs);
		}

		clock_interval_to_absolutetime_interval(wait_ms, NSEC_PER_MSEC,
		    &interval);

		lck_spin_lock(&zone_exhausted_lock);
		lck_spin_sleep_with_inheritor(&zone_exhausted_lock,
		    LCK_SLEEP_UNLOCK, &zone_pages_wired,
		    vm_pageout_gc_thread, THREAD_UNINT, wait_start + interval);

		mapped = os_atomic_load(&zone_pages_wired, relaxed);
	}
}

static bool
zone_expand_wait_for_pages(bool waited)
{
	if (waited) {
		return false;
	}
#if DEBUG || DEVELOPMENT
	if (zalloc_simulate_vm_pressure) {
		return false;
	}
#endif /* DEBUG || DEVELOPMENT */
	return !vm_pool_low();
}

static inline void
zone_expand_async_schedule_if_allowed(zone_t zone)
{
	if (zone->z_async_refilling || zone->no_callout) {
		return;
	}

	if (zone->exhaustible && zone->z_wired_cur >= zone->z_wired_max) {
		return;
	}

	if (__improbable(startup_phase < STARTUP_SUB_EARLY_BOOT)) {
		return;
	}

	if (!vm_pool_low() || zone_supports_vm(zone)) {
		zone->z_async_refilling = true;
		thread_call_enter(&zone_expand_callout);
	}
}

static void
zone_expand_locked(zone_t z, zalloc_flags_t flags, bool (*pred)(zone_t))
{
	zone_security_flags_t zsflags = zone_security_config(z);
	struct zone_expand ze = {
		.ze_thread  = current_thread(),
	};

	if (!(ze.ze_thread->options & TH_OPT_VMPRIV) && zone_supports_vm(z)) {
		ze.ze_thread->options |= TH_OPT_VMPRIV;
		ze.ze_clear_priv = true;
	}

	if (ze.ze_thread->options & TH_OPT_VMPRIV) {
		/*
		 * When the thread is VM privileged,
		 * vm_page_grab() will call VM_PAGE_WAIT()
		 * without our knowledge, so we must assume
		 * it's being called unfortunately.
		 *
		 * In practice it's not a big deal because
		 * Z_NOPAGEWAIT is not really used on zones
		 * that VM privileged threads are going to expand.
		 */
		ze.ze_pg_wait = true;
		ze.ze_vm_priv = true;
	}

	for (;;) {
		if (!pred) {
			/* NULL pred means "try just once" */
			pred = zone_expand_pred_nope;
		} else if (!pred(z)) {
			goto out;
		}

		if (z->z_expander == NULL) {
			z->z_expander = &ze;
			break;
		}

		if (ze.ze_vm_priv && !z->z_expander->ze_vm_priv) {
			change_sleep_inheritor(&z->z_expander, ze.ze_thread);
			ze.ze_next = z->z_expander;
			z->z_expander = &ze;
			break;
		}

		if ((flags & Z_NOPAGEWAIT) && z->z_expander->ze_pg_wait) {
			goto out;
		}

		z->z_expanding_wait = true;
		hw_lck_ticket_sleep_with_inheritor(&z->z_lock, &zone_locks_grp,
		    LCK_SLEEP_DEFAULT, &z->z_expander, z->z_expander->ze_thread,
		    TH_UNINT, TIMEOUT_WAIT_FOREVER);
	}

	do {
		struct zone_page_metadata *meta = NULL;
		uint32_t new_va = 0, cur_pages = 0, min_pages = 0, pages = 0;
		vm_page_t page_list = NULL;
		vm_offset_t addr = 0;
		int waited = 0;

		/*
		 * While we hold the zone lock, look if there's VA we can:
		 * - complete from partial pages,
		 * - reuse from the sequester list.
		 *
		 * When the page is being populated we pretend we allocated
		 * an extra element so that zone_gc() can't attempt to free
		 * the chunk (as it could become empty while we wait for pages).
		 */
		if (zone_pva_is_null(z->z_pageq_va)) {
			zone_allocate_va_locked(z, flags);
		}

		meta = zone_meta_queue_pop(z, &z->z_pageq_va);
		addr = zone_meta_to_addr(meta);
		if (meta->zm_chunk_len == ZM_SECONDARY_PAGE) {
			cur_pages = meta->zm_page_index;
			meta -= cur_pages;
			addr -= ptoa(cur_pages);
			zone_meta_lock_in_partial(z, meta, cur_pages);
		}
		zone_unlock(z);

		/*
		 * And now allocate pages to populate our VA.
		 */
		min_pages = z->z_chunk_pages;
#if !KASAN_CLASSIC
		if (!z->z_percpu) {
			min_pages = (uint32_t)atop(round_page(zone_elem_outer_offs(z) +
			    zone_elem_outer_size(z)));
		}
#endif /* !KASAN_CLASSIC */

		/*
		 * Trigger jetsams via VM_PAGEOUT_GC_EVENT
		 * if we're running out of zone memory
		 */
		if (__improbable(zone_map_nearing_exhaustion())) {
			__ZONE_MAP_EXHAUSTED_AND_WAITING_FOR_GC__(z, min_pages);
		}

		ZONE_TRACE_VM_KERN_REQUEST_START(ptoa(z->z_chunk_pages - cur_pages));

		while (pages < z->z_chunk_pages - cur_pages) {
			vm_page_t m = vm_page_grab();

			if (m) {
				pages++;
				m->vmp_snext = page_list;
				page_list = m;
				vm_page_zero_fill(m);
				continue;
			}

			if (pages >= min_pages &&
			    !zone_expand_wait_for_pages(waited)) {
				break;
			}

			if ((flags & Z_NOPAGEWAIT) == 0) {
				/*
				 * The first time we're about to wait for pages,
				 * mention that to waiters and wake them all.
				 *
				 * Set `ze_pg_wait` in our zone_expand context
				 * so that waiters who care do not wait again.
				 */
				if (!ze.ze_pg_wait) {
					zone_lock(z);
					if (z->z_expanding_wait) {
						z->z_expanding_wait = false;
						wakeup_all_with_inheritor(&z->z_expander,
						    THREAD_AWAKENED);
					}
					ze.ze_pg_wait = true;
					zone_unlock(z);
				}

				waited++;
				VM_PAGE_WAIT();
				continue;
			}

			/*
			 * Undo everything and bail out:
			 *
			 * - free pages
			 * - undo the fake allocation if any
			 * - put the VA back on the VA page queue.
			 */
			vm_page_free_list(page_list, FALSE);
			ZONE_TRACE_VM_KERN_REQUEST_END(pages);

			zone_lock(z);

			zone_expand_async_schedule_if_allowed(z);

			if (cur_pages) {
				zone_meta_unlock_from_partial(z, meta, cur_pages);
			}
			if (meta) {
				zone_meta_queue_push(z, &z->z_pageq_va,
				    meta + cur_pages);
			}
			goto page_shortage;
		}

		vm_object_lock(kernel_object);
		kernel_memory_populate_object_and_unlock(kernel_object,
		    addr + ptoa(cur_pages), addr + ptoa(cur_pages), ptoa(pages), page_list,
		    zone_kma_flags(z, zsflags, flags), VM_KERN_MEMORY_ZONE,
		    (zsflags.z_submap_idx == Z_SUBMAP_IDX_READ_ONLY)
		    ? VM_PROT_READ : VM_PROT_READ | VM_PROT_WRITE);

		ZONE_TRACE_VM_KERN_REQUEST_END(pages);

		zcram_and_lock(z, addr, new_va, cur_pages, cur_pages + pages, 0);

		if (z->z_wired_cur == z->z_wired_max) {
			zone_unlock(z);
			EVENT_INVOKE(ZONE_EXHAUSTED, zone_index(z), z);
			zone_lock(z);
		}
	} while (pred(z));

page_shortage:
	if (z->z_expander == &ze) {
		z->z_expander = ze.ze_next;
	} else {
		assert(z->z_expander->ze_next == &ze);
		z->z_expander->ze_next = NULL;
	}
	if (z->z_expanding_wait) {
		z->z_expanding_wait = false;
		wakeup_all_with_inheritor(&z->z_expander, THREAD_AWAKENED);
	}
out:
	if (ze.ze_clear_priv) {
		ze.ze_thread->options &= ~TH_OPT_VMPRIV;
	}
}

static bool
zalloc_needs_refill(zone_t zone)
{
	if (zone->z_elems_free > zone->z_elems_rsv) {
		return false;
	}
	if (zone->z_wired_cur < zone->z_wired_max) {
		return true;
	}
	return !zone->exhaustible;
}

static void
zone_expand_async(__unused thread_call_param_t p0, __unused thread_call_param_t p1)
{
	zone_foreach(z) {
		if (z->no_callout) {
			/* z_async_refilling will never be set */
			continue;
		}

		if (!z->z_async_refilling) {
			/*
			 * avoid locking all zones, because the one(s)
			 * we're looking for have been set _before_
			 * thread_call_enter() was called, if we fail
			 * to observe the bit, it means the thread-call
			 * has been "dinged" again and we'll notice it then.
			 */
			continue;
		}

		zone_lock(z);
		if (z->z_self && z->z_async_refilling) {
			zone_expand_locked(z, Z_WAITOK, zalloc_needs_refill);
			/*
			 * clearing _after_ we grow is important,
			 * so that we avoid waking up the thread call
			 * while we grow and cause to run a second time.
			 */
			z->z_async_refilling = false;
		}
		zone_unlock(z);
	}
}

#endif /* !ZALLOC_TEST */
#pragma mark zone jetsam integration
#if !ZALLOC_TEST

/*
 * We're being very conservative here and picking a value of 95%. We might need to lower this if
 * we find that we're not catching the problem and are still hitting zone map exhaustion panics.
 */
#define ZONE_MAP_JETSAM_LIMIT_DEFAULT 95

/*
 * Threshold above which largest zones should be included in the panic log
 */
#define ZONE_MAP_EXHAUSTION_PRINT_PANIC 80

/*
 * Trigger zone-map-exhaustion jetsams if the zone map is X% full,
 * where X=zone_map_jetsam_limit.
 *
 * Can be set via boot-arg "zone_map_jetsam_limit". Set to 95% by default.
 */
TUNABLE_WRITEABLE(unsigned int, zone_map_jetsam_limit, "zone_map_jetsam_limit",
    ZONE_MAP_JETSAM_LIMIT_DEFAULT);

kern_return_t
zone_map_jetsam_set_limit(uint32_t value)
{
	if (value <= 0 || value > 100) {
		return KERN_INVALID_VALUE;
	}

	zone_map_jetsam_limit = value;
	os_atomic_store(&zone_pages_jetsam_threshold,
	    zone_pages_wired_max * value / 100, relaxed);
	return KERN_SUCCESS;
}

void
get_zone_map_size(uint64_t *current_size, uint64_t *capacity)
{
	vm_offset_t phys_pages = os_atomic_load(&zone_pages_wired, relaxed);
	*current_size = ptoa_64(phys_pages);
	*capacity = ptoa_64(zone_pages_wired_max);
}

void
get_largest_zone_info(char *zone_name, size_t zone_name_len, uint64_t *zone_size)
{
	zone_t largest_zone = zone_find_largest(zone_size);

	/*
	 * Append kalloc heap name to zone name (if zone is used by kalloc)
	 */
	snprintf(zone_name, zone_name_len, "%s%s",
	    zone_heap_name(largest_zone), largest_zone->z_name);
}

static bool
zone_map_nearing_threshold(unsigned int threshold)
{
	uint64_t phys_pages = os_atomic_load(&zone_pages_wired, relaxed);
	return phys_pages * 100 > zone_pages_wired_max * threshold;
}

bool
zone_map_nearing_exhaustion(void)
{
	vm_size_t pages = os_atomic_load(&zone_pages_wired, relaxed);

	return pages >= os_atomic_load(&zone_pages_jetsam_threshold, relaxed);
}


#define VMENTRY_TO_VMOBJECT_COMPARISON_RATIO 98

/*
 * Tries to kill a single process if it can attribute one to the largest zone. If not, wakes up the memorystatus thread
 * to walk through the jetsam priority bands and kill processes.
 */
static zone_t
kill_process_in_largest_zone(void)
{
	pid_t pid = -1;
	uint64_t zone_size = 0;
	zone_t largest_zone = zone_find_largest(&zone_size);

	printf("zone_map_exhaustion: Zone mapped %lld of %lld, used %lld, capacity %lld [jetsam limit %d%%]\n",
	    ptoa_64(os_atomic_load(&zone_pages_wired, relaxed)),
	    ptoa_64(zone_pages_wired_max),
	    (uint64_t)zone_submaps_approx_size(),
	    (uint64_t)mach_vm_range_size(&zone_info.zi_map_range),
	    zone_map_jetsam_limit);
	printf("zone_map_exhaustion: Largest zone %s%s, size %lu\n", zone_heap_name(largest_zone),
	    largest_zone->z_name, (uintptr_t)zone_size);

	/*
	 * We want to make sure we don't call this function from userspace.
	 * Or we could end up trying to synchronously kill the process
	 * whose context we're in, causing the system to hang.
	 */
	assert(current_task() == kernel_task);

	/*
	 * If vm_object_zone is the largest, check to see if the number of
	 * elements in vm_map_entry_zone is comparable.
	 *
	 * If so, consider vm_map_entry_zone as the largest. This lets us target
	 * a specific process to jetsam to quickly recover from the zone map
	 * bloat.
	 */
	if (largest_zone == vm_object_zone) {
		unsigned int vm_object_zone_count = zone_count_allocated(vm_object_zone);
		unsigned int vm_map_entry_zone_count = zone_count_allocated(vm_map_entry_zone);
		/* Is the VM map entries zone count >= 98% of the VM objects zone count? */
		if (vm_map_entry_zone_count >= ((vm_object_zone_count * VMENTRY_TO_VMOBJECT_COMPARISON_RATIO) / 100)) {
			largest_zone = vm_map_entry_zone;
			printf("zone_map_exhaustion: Picking VM map entries as the zone to target, size %lu\n",
			    (uintptr_t)zone_size_wired(largest_zone));
		}
	}

	/* TODO: Extend this to check for the largest process in other zones as well. */
	if (largest_zone == vm_map_entry_zone) {
		pid = find_largest_process_vm_map_entries();
	} else {
		printf("zone_map_exhaustion: Nothing to do for the largest zone [%s%s]. "
		    "Waking up memorystatus thread.\n", zone_heap_name(largest_zone),
		    largest_zone->z_name);
	}
	if (!memorystatus_kill_on_zone_map_exhaustion(pid)) {
		printf("zone_map_exhaustion: Call to memorystatus failed, victim pid: %d\n", pid);
	}

	return largest_zone;
}

#endif /* !ZALLOC_TEST */
#pragma mark probabilistic gzalloc
#if !ZALLOC_TEST
#if CONFIG_PROB_GZALLOC

extern uint32_t random(void);
struct pgz_backtrace {
	uint32_t  pgz_depth;
	int32_t   pgz_bt[MAX_ZTRACE_DEPTH];
};

static int32_t  PERCPU_DATA(pgz_sample_counter);
static SECURITY_READ_ONLY_LATE(struct pgz_backtrace *) pgz_backtraces;
static uint32_t pgz_uses;       /* number of zones using PGZ */
static int32_t  pgz_slot_avail;
#if OS_ATOMIC_HAS_LLSC
struct zone_page_metadata *pgz_slot_head;
#else
static struct pgz_slot_head {
	uint32_t psh_count;
	uint32_t psh_slot;
} pgz_slot_head;
#endif
struct zone_page_metadata *pgz_slot_tail;
static SECURITY_READ_ONLY_LATE(vm_map_t) pgz_submap;

static struct zone_page_metadata *
pgz_meta(uint32_t index)
{
	return &zone_info.zi_pgz_meta[2 * index + 1];
}

static struct pgz_backtrace *
pgz_bt(uint32_t slot, bool free)
{
	return &pgz_backtraces[2 * slot + free];
}

static void
pgz_backtrace(struct pgz_backtrace *bt, void *fp)
{
	struct backtrace_control ctl = {
		.btc_frame_addr = (uintptr_t)fp,
	};

	bt->pgz_depth = (uint32_t)backtrace_packed(BTP_KERN_OFFSET_32,
	    (uint8_t *)bt->pgz_bt, sizeof(bt->pgz_bt), &ctl, NULL) / 4;
}

static uint32_t
pgz_slot(vm_offset_t addr)
{
	return (uint32_t)((addr - zone_info.zi_pgz_range.min_address) >> (PAGE_SHIFT + 1));
}

static vm_offset_t
pgz_addr(uint32_t slot)
{
	return zone_info.zi_pgz_range.min_address + ptoa(2 * slot + 1);
}

static bool
pgz_sample(vm_offset_t addr, vm_size_t esize)
{
	int32_t *counterp, cnt;

	if (zone_addr_size_crosses_page(addr, esize)) {
		return false;
	}

	/*
	 * Note: accessing pgz_sample_counter is racy but this is
	 *       kind of acceptable given that this is not
	 *       a security load bearing feature.
	 */

	counterp = PERCPU_GET(pgz_sample_counter);
	cnt = *counterp;
	if (__probable(cnt > 0)) {
		*counterp = cnt - 1;
		return false;
	}

	if (pgz_slot_avail <= 0) {
		return false;
	}

	/*
	 * zalloc_random_uniform() might block, so when preemption is disabled,
	 * set the counter to `-1` which will cause the next allocation
	 * that can block to generate a new random value.
	 *
	 * No allocation on this CPU will sample until then.
	 */
	if (get_preemption_level()) {
		*counterp = -1;
	} else {
		*counterp = zalloc_random_uniform32(0, 2 * pgz_sample_rate);
	}

	return cnt == 0;
}

static inline bool
pgz_slot_alloc(uint32_t *slot)
{
	struct zone_page_metadata *m;
	uint32_t tries = 100;

	disable_preemption();

#if OS_ATOMIC_USE_LLSC
	int32_t ov, nv;
	os_atomic_rmw_loop(&pgz_slot_avail, ov, nv, relaxed, {
		if (__improbable(ov <= 0)) {
		        os_atomic_rmw_loop_give_up({
				enable_preemption();
				return false;
			});
		}
		nv = ov - 1;
	});
#else
	if (__improbable(os_atomic_dec_orig(&pgz_slot_avail, relaxed) <= 0)) {
		os_atomic_inc(&pgz_slot_avail, relaxed);
		enable_preemption();
		return false;
	}
#endif

again:
	if (__improbable(tries-- == 0)) {
		/*
		 * Too much contention,
		 * extremely unlikely but do not stay stuck.
		 */
		os_atomic_inc(&pgz_slot_avail, relaxed);
		enable_preemption();
		return false;
	}

#if OS_ATOMIC_HAS_LLSC
	do {
		m = os_atomic_load_exclusive(&pgz_slot_head, dependency);
		if (__improbable(m->zm_pgz_slot_next == NULL)) {
			/*
			 * Either we are waiting for an enqueuer (unlikely)
			 * or we are competing with another core and
			 * are looking at a popped element.
			 */
			os_atomic_clear_exclusive();
			goto again;
		}
	} while (!os_atomic_store_exclusive(&pgz_slot_head,
	    m->zm_pgz_slot_next, relaxed));
#else
	struct zone_page_metadata *base = zone_info.zi_pgz_meta;
	struct pgz_slot_head ov, nv;
	os_atomic_rmw_loop(&pgz_slot_head, ov, nv, dependency, {
		m = &base[ov.psh_slot * 2];
		if (__improbable(m->zm_pgz_slot_next == NULL)) {
		        /*
		         * Either we are waiting for an enqueuer (unlikely)
		         * or we are competing with another core and
		         * are looking at a popped element.
		         */
		        os_atomic_rmw_loop_give_up(goto again);
		}
		nv.psh_count = ov.psh_count + 1;
		nv.psh_slot  = (uint32_t)((m->zm_pgz_slot_next - base) / 2);
	});
#endif

	enable_preemption();

	m->zm_pgz_slot_next = NULL;
	*slot = (uint32_t)((m - zone_info.zi_pgz_meta) / 2);
	return true;
}

static inline bool
pgz_slot_free(uint32_t slot)
{
	struct zone_page_metadata *m = &zone_info.zi_pgz_meta[2 * slot];
	struct zone_page_metadata *t;

	disable_preemption();
	t = os_atomic_xchg(&pgz_slot_tail, m, relaxed);
	os_atomic_store(&t->zm_pgz_slot_next, m, release);
	os_atomic_inc(&pgz_slot_avail, relaxed);
	enable_preemption();

	return true;
}

/*!
 * @function pgz_protect()
 *
 * @brief
 * Try to protect an allocation with PGZ.
 *
 * @param zone          The zone the allocation was made against.
 * @param addr          An allocated element address to protect.
 * @param fp            The caller frame pointer (for the backtrace).
 * @returns             The new address for the element, or @c addr.
 */
__attribute__((noinline))
static vm_offset_t
pgz_protect(zone_t zone, vm_offset_t addr, void *fp)
{
	kern_return_t kr;
	uint32_t slot;

	if (!pgz_slot_alloc(&slot)) {
		return addr;
	}

	/*
	 * Try to double-map the page (may fail if Z_NOWAIT).
	 * we will always find a PA because pgz_init() pre-expanded the pmap.
	 */
	vm_offset_t  new_addr = pgz_addr(slot);
	pmap_paddr_t pa = kvtophys(trunc_page(addr));

	kr = pmap_enter_options_addr(kernel_pmap, new_addr, pa,
	    VM_PROT_READ | VM_PROT_WRITE, VM_PROT_NONE, 0, TRUE,
	    get_preemption_level() ? PMAP_OPTIONS_NOWAIT : 0, NULL);

	if (__improbable(kr != KERN_SUCCESS)) {
		pgz_slot_free(slot);
		return addr;
	}

	struct zone_page_metadata tmp = {
		.zm_chunk_len = ZM_PGZ_ALLOCATED,
		.zm_index     = zone_index(zone),
	};
	struct zone_page_metadata *meta = pgz_meta(slot);

	os_atomic_store(&meta->zm_bits, tmp.zm_bits, relaxed);
	os_atomic_store(&meta->zm_pgz_orig_addr, addr, relaxed);
	pgz_backtrace(pgz_bt(slot, false), fp);

	return new_addr + (addr & PAGE_MASK);
}

/*!
 * @function pgz_unprotect()
 *
 * @brief
 * Release a PGZ slot and returns the original address of a freed element.
 *
 * @param addr          A PGZ protected element address.
 * @param fp            The caller frame pointer (for the backtrace).
 * @returns             The non protected address for the element
 *                      that was passed to @c pgz_protect().
 */
__attribute__((noinline))
static vm_offset_t
pgz_unprotect(vm_offset_t addr, void *fp)
{
	struct zone_page_metadata *meta;
	struct zone_page_metadata tmp;
	uint32_t slot;

	slot = pgz_slot(addr);
	meta = zone_meta_from_addr(addr);
	tmp  = *meta;
	if (tmp.zm_chunk_len != ZM_PGZ_ALLOCATED) {
		goto double_free;
	}

	pmap_remove(kernel_pmap, trunc_page(addr), trunc_page(addr) + PAGE_SIZE);

	pgz_backtrace(pgz_bt(slot, true), fp);

	tmp.zm_chunk_len = ZM_PGZ_FREE;
	tmp.zm_bits = os_atomic_xchg(&meta->zm_bits, tmp.zm_bits, relaxed);
	if (tmp.zm_chunk_len != ZM_PGZ_ALLOCATED) {
		goto double_free;
	}

	pgz_slot_free(slot);
	return tmp.zm_pgz_orig_addr;

double_free:
	panic_fault_address = addr;
	meta->zm_chunk_len = ZM_PGZ_DOUBLE_FREE;
	panic("probabilistic gzalloc double free: %p", (void *)addr);
}

bool
pgz_owned(mach_vm_address_t addr)
{
#if CONFIG_KERNEL_TBI
	addr = VM_KERNEL_TBI_FILL(addr);
#endif /* CONFIG_KERNEL_TBI */

	return mach_vm_range_contains(&zone_info.zi_pgz_range, addr);
}


__attribute__((always_inline))
vm_offset_t
__pgz_decode(mach_vm_address_t addr, mach_vm_size_t size)
{
	struct zone_page_metadata *meta;

	if (__probable(!pgz_owned(addr))) {
		return (vm_offset_t)addr;
	}

	if (zone_addr_size_crosses_page(addr, size)) {
		panic("invalid size for PGZ protected address %p:%p",
		    (void *)addr, (void *)(addr + size));
	}

	meta = zone_meta_from_addr((vm_offset_t)addr);
	if (meta->zm_chunk_len != ZM_PGZ_ALLOCATED) {
		panic_fault_address = (vm_offset_t)addr;
		panic("probabilistic gzalloc use-after-free: %p", (void *)addr);
	}

	return trunc_page(meta->zm_pgz_orig_addr) + (addr & PAGE_MASK);
}

__attribute__((always_inline))
vm_offset_t
__pgz_decode_allow_invalid(vm_offset_t addr, zone_id_t zid)
{
	struct zone_page_metadata *meta;
	struct zone_page_metadata tmp;

	if (__probable(!pgz_owned(addr))) {
		return addr;
	}

	meta = zone_meta_from_addr(addr);
	tmp.zm_bits = os_atomic_load(&meta->zm_bits, relaxed);

	addr = trunc_page(meta->zm_pgz_orig_addr) + (addr & PAGE_MASK);

	if (tmp.zm_chunk_len != ZM_PGZ_ALLOCATED) {
		return 0;
	}

	if (zid != ZONE_ID_ANY && tmp.zm_index != zid) {
		return 0;
	}

	return addr;
}

static void
pgz_zone_init(zone_t z)
{
	char zn[MAX_ZONE_NAME];
	char zv[MAX_ZONE_NAME];
	char key[30];

	if (zone_elem_inner_size(z) > PAGE_SIZE) {
		return;
	}

	if (pgz_all) {
		os_atomic_inc(&pgz_uses, relaxed);
		z->z_pgz_tracked = true;
		return;
	}

	snprintf(zn, sizeof(zn), "%s%s", zone_heap_name(z), zone_name(z));

	for (int i = 1;; i++) {
		snprintf(key, sizeof(key), "pgz%d", i);
		if (!PE_parse_boot_argn(key, zv, sizeof(zv))) {
			break;
		}
		if (track_this_zone(zn, zv) || track_kalloc_zones(z, zv)) {
			os_atomic_inc(&pgz_uses, relaxed);
			z->z_pgz_tracked = true;
			break;
		}
	}
}

__startup_func
static vm_size_t
pgz_get_size(void)
{
	if (pgz_slots == UINT32_MAX) {
		/*
		 * Scale with RAM size: ~200 slots a G
		 */
		pgz_slots = (uint32_t)(sane_size >> 22);
	}

	/*
	 * Make sure that the slot allocation scheme works.
	 * see pgz_slot_alloc() / pgz_slot_free();
	 */
	if (pgz_slots < zpercpu_count() * 4) {
		pgz_slots = zpercpu_count() * 4;
	}
	if (pgz_slots >= UINT16_MAX) {
		pgz_slots = UINT16_MAX - 1;
	}

	/*
	 * Quarantine is 33% of slots by default, no more than 90%.
	 */
	if (pgz_quarantine == 0) {
		pgz_quarantine = pgz_slots / 3;
	}
	if (pgz_quarantine > pgz_slots * 9 / 10) {
		pgz_quarantine = pgz_slots * 9 / 10;
	}
	pgz_slot_avail = pgz_slots - pgz_quarantine;

	return ptoa(2 * pgz_slots + 1);
}

__startup_func
static void
pgz_init(void)
{
	if (!pgz_uses) {
		return;
	}

	if (pgz_sample_rate == 0) {
		/*
		 * If no rate was provided, pick a random one that scales
		 * with the number of protected zones.
		 *
		 * Use a binomal distribution to avoid having too many
		 * really fast sample rates.
		 */
		uint32_t factor = MIN(pgz_uses, 10);
		uint32_t max_rate = 1000 * factor;
		uint32_t min_rate =  100 * factor;

		pgz_sample_rate = (zalloc_random_uniform32(min_rate, max_rate) +
		    zalloc_random_uniform32(min_rate, max_rate)) / 2;
	}

	struct mach_vm_range *r = &zone_info.zi_pgz_range;
	zone_info.zi_pgz_meta = zone_meta_from_addr(r->min_address);
	zone_meta_populate(r->min_address, mach_vm_range_size(r));

	for (size_t i = 0; i < 2 * pgz_slots + 1; i += 2) {
		zone_info.zi_pgz_meta[i].zm_chunk_len = ZM_PGZ_GUARD;
	}

	for (size_t i = 1; i < pgz_slots; i++) {
		zone_info.zi_pgz_meta[2 * i - 1].zm_pgz_slot_next =
		    &zone_info.zi_pgz_meta[2 * i + 1];
	}
#if OS_ATOMIC_HAS_LLSC
	pgz_slot_head = &zone_info.zi_pgz_meta[1];
#endif
	pgz_slot_tail = &zone_info.zi_pgz_meta[2 * pgz_slots - 1];

	pgz_backtraces = zalloc_permanent(sizeof(struct pgz_backtrace) *
	    2 * pgz_slots, ZALIGN_PTR);

	/*
	 * expand the pmap so that pmap_enter_options_addr()
	 * in pgz_protect() never need to call pmap_expand().
	 */
	for (uint32_t slot = 0; slot < pgz_slots; slot++) {
		(void)pmap_enter_options_addr(kernel_pmap, pgz_addr(slot), 0,
		    VM_PROT_NONE, VM_PROT_NONE, 0, FALSE,
		    PMAP_OPTIONS_NOENTER, NULL);
	}

	/* do this last as this will enable pgz */
	percpu_foreach(counter, pgz_sample_counter) {
		*counter = zalloc_random_uniform32(0, 2 * pgz_sample_rate);
	}
}
STARTUP(EARLY_BOOT, STARTUP_RANK_MIDDLE, pgz_init);

static void
panic_display_pgz_bt(bool has_syms, uint32_t slot, bool free)
{
	struct pgz_backtrace *bt = pgz_bt(slot, free);
	const char *what = free ? "Free" : "Allocation";
	uintptr_t buf[MAX_ZTRACE_DEPTH];

	if (!ml_validate_nofault((vm_offset_t)bt, sizeof(*bt))) {
		paniclog_append_noflush("  Can't decode %s Backtrace\n", what);
		return;
	}

	backtrace_unpack(BTP_KERN_OFFSET_32, buf, MAX_ZTRACE_DEPTH,
	    (uint8_t *)bt->pgz_bt, 4 * bt->pgz_depth);

	paniclog_append_noflush("  %s Backtrace:\n", what);
	for (uint32_t i = 0; i < bt->pgz_depth && i < MAX_ZTRACE_DEPTH; i++) {
		if (has_syms) {
			paniclog_append_noflush("    %p ", (void *)buf[i]);
			panic_print_symbol_name(buf[i]);
			paniclog_append_noflush("\n");
		} else {
			paniclog_append_noflush("    %p\n", (void *)buf[i]);
		}
	}
	kmod_panic_dump((vm_offset_t *)buf, bt->pgz_depth);
}

static void
panic_display_pgz_uaf_info(bool has_syms, vm_offset_t addr)
{
	struct zone_page_metadata *meta;
	vm_offset_t elem, esize;
	const char *type;
	const char *prob;
	uint32_t slot;
	zone_t z;

	slot = pgz_slot(addr);
	meta = pgz_meta(slot);
	elem = pgz_addr(slot) + (meta->zm_pgz_orig_addr & PAGE_MASK);

	paniclog_append_noflush("Probabilistic GZAlloc Report:\n");

	if (ml_validate_nofault((vm_offset_t)meta, sizeof(*meta)) &&
	    meta->zm_index &&
	    meta->zm_index < os_atomic_load(&num_zones, relaxed)) {
		z = &zone_array[meta->zm_index];
	} else {
		paniclog_append_noflush("  Zone    : <unknown>\n");
		paniclog_append_noflush("  Address : %p\n", (void *)addr);
		paniclog_append_noflush("\n");
		return;
	}

	esize = zone_elem_inner_size(z);
	paniclog_append_noflush("  Zone    : %s%s\n",
	    zone_heap_name(z), zone_name(z));
	paniclog_append_noflush("  Address : %p\n", (void *)addr);
	paniclog_append_noflush("  Element : [%p, %p) of size %d\n",
	    (void *)elem, (void *)(elem + esize), (uint32_t)esize);

	if (addr < elem) {
		type = "out-of-bounds(underflow) + use-after-free";
		prob = "low";
	} else if (meta->zm_chunk_len == ZM_PGZ_DOUBLE_FREE) {
		type = "double-free";
		prob = "high";
	} else if (addr < elem + esize) {
		type = "use-after-free";
		prob = "high";
	} else if (meta->zm_chunk_len != ZM_PGZ_ALLOCATED) {
		type = "out-of-bounds + use-after-free";
		prob = "low";
	} else {
		type = "out-of-bounds";
		prob = "high";
	}
	paniclog_append_noflush("  Kind    : %s (%s confidence)\n",
	    type, prob);
	if (addr < elem) {
		paniclog_append_noflush("  Access  : %d byte(s) before\n",
		    (uint32_t)(elem - addr) + 1);
	} else if (addr < elem + esize) {
		paniclog_append_noflush("  Access  : %d byte(s) inside\n",
		    (uint32_t)(addr - elem) + 1);
	} else {
		paniclog_append_noflush("  Access  : %d byte(s) past\n",
		    (uint32_t)(addr - (elem + esize)) + 1);
	}

	panic_display_pgz_bt(has_syms, slot, false);
	if (meta->zm_chunk_len != ZM_PGZ_ALLOCATED) {
		panic_display_pgz_bt(has_syms, slot, true);
	}

	paniclog_append_noflush("\n");
}

#endif /* CONFIG_PROB_GZALLOC */
#endif /* !ZALLOC_TEST */
#pragma mark zfree
#if !ZALLOC_TEST

/*!
 * @defgroup zfree
 * @{
 *
 * @brief
 * The codepath for zone frees.
 *
 * @discussion
 * There are 4 major ways to allocate memory that end up in the zone allocator:
 * - @c zfree()
 * - @c zfree_percpu()
 * - @c kfree*()
 * - @c zfree_permanent()
 *
 * While permanent zones have their own allocation scheme, all other codepaths
 * will eventually go through the @c zfree_ext() choking point.
 */

__header_always_inline void
zfree_drop(zone_t zone, vm_offset_t addr)
{
	vm_offset_t esize = zone_elem_outer_size(zone);
	struct zone_page_metadata *meta;
	vm_offset_t eidx;

	meta = zone_element_resolve(zone, addr, &eidx);

	if (!zone_meta_mark_free(meta, eidx)) {
		zone_meta_double_free_panic(zone, addr, __func__);
	}

	vm_offset_t old_size = meta->zm_alloc_size;
	vm_offset_t max_size = ptoa(meta->zm_chunk_len) + ZM_ALLOC_SIZE_LOCK;
	vm_offset_t new_size = zone_meta_alloc_size_sub(zone, meta, esize);

	if (new_size == 0) {
		/* whether the page was on the intermediate or all_used, queue, move it to free */
		zone_meta_requeue(zone, &zone->z_pageq_empty, meta);
		zone->z_wired_empty += meta->zm_chunk_len;
	} else if (old_size + esize > max_size) {
		/* first free element on page, move from all_used */
		zone_meta_requeue(zone, &zone->z_pageq_partial, meta);
	}
}

__attribute__((noinline))
static void
zfree_item(zone_t zone, vm_offset_t addr)
{
	/* transfer preemption count to lock */
	zone_lock_nopreempt_check_contention(zone);

	zfree_drop(zone, addr);
	zone->z_elems_free += 1;

	zone_unlock(zone);
}

static void
zfree_cached_depot_recirculate(
	zone_t                  zone,
	uint32_t                depot_max,
	zone_cache_t            cache)
{
	smr_t smr = zone_cache_smr(cache);
	smr_seq_t seq;
	uint32_t n;

	zone_recirc_lock_nopreempt_check_contention(zone);

	n = cache->zc_depot.zd_full;
	if (n >= depot_max) {
		/*
		 * If SMR is in use, rotate the entire chunk of magazines.
		 *
		 * If the head of the recirculation layer is ready to be
		 * reused, pull them back to refill a little.
		 */
		seq = zone_depot_move_full(&zone->z_recirc,
		    &cache->zc_depot, smr ? n : n - depot_max / 2, NULL);

		if (smr) {
			smr_deferred_advance_commit(smr, seq);
			if (depot_max > 1 && zone_depot_poll(&zone->z_recirc, smr)) {
				zone_depot_move_full(&cache->zc_depot,
				    &zone->z_recirc, depot_max / 2, NULL);
			}
		}
	}

	n = depot_max - cache->zc_depot.zd_full;
	if (n > zone->z_recirc.zd_empty) {
		n = zone->z_recirc.zd_empty;
	}
	if (n) {
		zone_depot_move_empty(&cache->zc_depot, &zone->z_recirc,
		    n, zone);
	}

	zone_recirc_unlock_nopreempt(zone);
}

static zone_cache_t
zfree_cached_recirculate(zone_t zone, zone_cache_t cache)
{
	zone_magazine_t mag = NULL, tmp = NULL;
	smr_t smr = zone_cache_smr(cache);

	if (zone->z_recirc.zd_empty == 0) {
		mag = zone_magazine_alloc(Z_NOWAIT);
	}

	zone_recirc_lock_nopreempt_check_contention(zone);

	if (mag == NULL && zone->z_recirc.zd_empty) {
		mag = zone_depot_pop_head_empty(&zone->z_recirc, zone);
		__builtin_assume(mag);
	}
	if (mag) {
		tmp = zone_magazine_replace(cache, mag, true);
		if (smr) {
			smr_deferred_advance_commit(smr, tmp->zm_seq);
		}
		if (zone_security_array[zone_index(zone)].z_lifo) {
			zone_depot_insert_head_full(&zone->z_recirc, tmp);
		} else {
			zone_depot_insert_tail_full(&zone->z_recirc, tmp);
		}
	}

	zone_recirc_unlock_nopreempt(zone);

	return mag ? cache : NULL;
}

__attribute__((noinline))
static zone_cache_t
zfree_cached_trim(zone_t zone, zone_cache_t cache)
{
	zone_magazine_t mag = NULL, tmp = NULL;
	uint32_t depot_max;

	depot_max = os_atomic_load(&zone->z_depot_size, relaxed);
	if (depot_max) {
		zone_depot_lock_nopreempt(cache);

		if (cache->zc_depot.zd_empty == 0) {
			zfree_cached_depot_recirculate(zone, depot_max, cache);
		}

		if (__probable(cache->zc_depot.zd_empty)) {
			mag = zone_depot_pop_head_empty(&cache->zc_depot, NULL);
			__builtin_assume(mag);
		} else {
			mag = zone_magazine_alloc(Z_NOWAIT);
		}
		if (mag) {
			tmp = zone_magazine_replace(cache, mag, true);
			zone_depot_insert_tail_full(&cache->zc_depot, tmp);
		}
		zone_depot_unlock_nopreempt(cache);

		return mag ? cache : NULL;
	}

	return zfree_cached_recirculate(zone, cache);
}

__attribute__((always_inline))
static inline zone_cache_t
zfree_cached_get_pcpu_cache(zone_t zone, int cpu)
{
	zone_cache_t cache = zpercpu_get_cpu(zone->z_pcpu_cache, cpu);

	if (__probable(cache->zc_free_cur < zc_mag_size())) {
		return cache;
	}

	if (__probable(cache->zc_alloc_cur < zc_mag_size())) {
		zone_cache_swap_magazines(cache);
		return cache;
	}

	return zfree_cached_trim(zone, cache);
}

__attribute__((always_inline))
static inline zone_cache_t
zfree_cached_get_pcpu_cache_smr(zone_t zone, int cpu)
{
	zone_cache_t cache = zpercpu_get_cpu(zone->z_pcpu_cache, cpu);
	size_t idx = cache->zc_free_cur;

	if (__probable(idx + 1 < zc_mag_size())) {
		return cache;
	}

	/*
	 * when SMR is in use, the bucket is tagged early with
	 * @c smr_deferred_advance(), which costs a full barrier,
	 * but performs no store.
	 *
	 * When zones hit the recirculation layer, the advance is commited,
	 * under the recirculation lock (see zfree_cached_recirculate()).
	 *
	 * When done this way, the zone contention detection mechanism
	 * will adjust the size of the per-cpu depots gracefully, which
	 * mechanically reduces the pace of these commits as usage increases.
	 */

	if (__probable(idx + 1 == zc_mag_size())) {
		zone_magazine_t mag;

		mag = (zone_magazine_t)((uintptr_t)cache->zc_free_elems -
		    offsetof(struct zone_magazine, zm_elems));
		mag->zm_seq = smr_deferred_advance(zone_cache_smr(cache));
		return cache;
	}

	return zfree_cached_trim(zone, cache);
}

__attribute__((always_inline))
static inline vm_offset_t
__zcache_mark_invalid(zone_t zone, vm_offset_t elem, uint64_t combined_size)
{
	struct zone_page_metadata *meta;
	vm_offset_t offs;

#pragma unused(combined_size)
#if CONFIG_PROB_GZALLOC
	if (__improbable(pgz_owned(elem))) {
		elem = pgz_unprotect(elem, __builtin_frame_address(0));
	}
#endif /* CONFIG_PROB_GZALLOC */

	meta = zone_meta_from_addr(elem);
	if (!from_zone_map(elem, 1) || !zone_has_index(zone, meta->zm_index)) {
		zone_invalid_element_panic(zone, elem);
	}

	offs = (elem & PAGE_MASK) - zone_elem_inner_offs(zone);
	if (meta->zm_chunk_len == ZM_SECONDARY_PAGE) {
		offs += ptoa(meta->zm_page_index);
	}

	if (!Z_FAST_ALIGNED(offs, zone->z_align_magic)) {
		zone_invalid_element_panic(zone, elem);
	}

#if VM_TAG_SIZECLASSES
	if (__improbable(zone->z_uses_tags)) {
		vm_tag_t *slot;

		slot = zba_extra_ref_ptr(meta->zm_bitmap,
		    Z_FAST_QUO(offs, zone->z_quo_magic));
		vm_tag_update_zone_size(*slot, zone->z_tags_sizeclass,
		    -(long)ZFREE_ELEM_SIZE(combined_size));
		*slot = VM_KERN_MEMORY_NONE;
	}
#endif /* VM_TAG_SIZECLASSES */

#if KASAN_CLASSIC
	kasan_free(elem, ZFREE_ELEM_SIZE(combined_size),
	    ZFREE_USER_SIZE(combined_size), zone_elem_redzone(zone),
	    zone->z_percpu, __builtin_frame_address(0));
#endif
#if KASAN_TBI
	elem = kasan_tbi_tag_zfree(elem, ZFREE_ELEM_SIZE(combined_size),
	    zone->z_percpu);
#endif

	return elem;
}

__attribute__((always_inline))
vm_offset_t
(zcache_mark_invalid)(zone_t zone, vm_offset_t elem)
{
	vm_size_t esize = zone_elem_inner_offs(zone);

	ZFREE_LOG(zone, elem, 1);
	return __zcache_mark_invalid(zone, elem, ZFREE_PACK_SIZE(esize, esize));
}

/*
 *     The function is noinline when zlog can be used so that the backtracing can
 *     reliably skip the zfree_ext() and zfree_log()
 *     boring frames.
 */
#if ZALLOC_ENABLE_LOGGING
__attribute__((noinline))
#endif /* ZALLOC_ENABLE_LOGGING */
void
zfree_ext(zone_t zone, zone_stats_t zstats, void *addr, uint64_t combined_size)
{
	vm_offset_t esize = ZFREE_ELEM_SIZE(combined_size);
	vm_offset_t elem = (vm_offset_t)addr;
	int cpu;

	DTRACE_VM2(zfree, zone_t, zone, void*, elem);

	ZFREE_LOG(zone, elem, 1);
	elem = __zcache_mark_invalid(zone, elem, combined_size);

	disable_preemption();
	cpu = cpu_number();
	zpercpu_get_cpu(zstats, cpu)->zs_mem_freed += esize;

#if KASAN_CLASSIC
	if (zone->z_kasan_quarantine && startup_phase >= STARTUP_SUB_ZALLOC) {
		struct kasan_quarantine_result kqr;

		kqr  = kasan_quarantine(elem, esize);
		elem = kqr.addr;
		zone = kqr.zone;
		if (elem == 0) {
			return enable_preemption();
		}
	}
#endif

	if (zone->z_pcpu_cache) {
		zone_cache_t cache = zfree_cached_get_pcpu_cache(zone, cpu);

		if (__probable(cache)) {
			cache->zc_free_elems[cache->zc_free_cur++] = elem;
			return enable_preemption();
		}
	}

	return zfree_item(zone, elem);
}

__attribute__((always_inline))
static inline zstack_t
zcache_free_stack_to_cpu(
	zone_id_t               zid,
	zone_cache_t            cache,
	zstack_t                stack,
	vm_size_t               esize,
	zone_cache_ops_t        ops,
	bool                    zero)
{
	size_t       n = MIN(zc_mag_size() - cache->zc_free_cur, stack.z_count);
	vm_offset_t *p;

	stack.z_count -= n;
	cache->zc_free_cur += n;
	p = cache->zc_free_elems + cache->zc_free_cur;

	do {
		void *o = zstack_pop_no_delta(&stack);

		if (ops) {
			o = ops->zc_op_mark_invalid(zid, o);
		} else {
			if (zero) {
				bzero(o, esize);
			}
			o = (void *)__zcache_mark_invalid(zone_by_id(zid),
			    (vm_offset_t)o, ZFREE_PACK_SIZE(esize, esize));
		}
		*--p  = (vm_offset_t)o;
	} while (--n > 0);

	return stack;
}

__attribute__((always_inline))
static inline void
zcache_free_1_ext(zone_id_t zid, void *addr, zone_cache_ops_t ops)
{
	vm_offset_t elem = (vm_offset_t)addr;
	zone_cache_t cache;
	vm_size_t esize;
	zone_t zone = zone_by_id(zid);
	int cpu;

	ZFREE_LOG(zone, elem, 1);

	disable_preemption();
	cpu = cpu_number();
	esize = zone_elem_inner_size(zone);
	zpercpu_get_cpu(zone->z_stats, cpu)->zs_mem_freed += esize;
	if (!ops) {
		addr = (void *)__zcache_mark_invalid(zone, elem,
		    ZFREE_PACK_SIZE(esize, esize));
	}
	cache = zfree_cached_get_pcpu_cache(zone, cpu);
	if (__probable(cache)) {
		if (ops) {
			addr = ops->zc_op_mark_invalid(zid, addr);
		}
		cache->zc_free_elems[cache->zc_free_cur++] = elem;
		enable_preemption();
	} else if (ops) {
		enable_preemption();
		os_atomic_dec(&zone_by_id(zid)->z_elems_avail, relaxed);
		ops->zc_op_free(zid, addr);
	} else {
		zfree_item(zone, elem);
	}
}

__attribute__((always_inline))
static inline void
zcache_free_n_ext(zone_id_t zid, zstack_t stack, zone_cache_ops_t ops, bool zero)
{
	zone_t zone = zone_by_id(zid);
	zone_cache_t cache;
	vm_size_t esize;
	int cpu;

	ZFREE_LOG(zone, stack.z_head, stack.z_count);

	disable_preemption();
	cpu = cpu_number();
	esize = zone_elem_inner_size(zone);
	zpercpu_get_cpu(zone->z_stats, cpu)->zs_mem_freed +=
	    stack.z_count * esize;

	for (;;) {
		cache = zfree_cached_get_pcpu_cache(zone, cpu);
		if (__probable(cache)) {
			stack = zcache_free_stack_to_cpu(zid, cache,
			    stack, esize, ops, zero);
			enable_preemption();
		} else if (ops) {
			enable_preemption();
			os_atomic_dec(&zone->z_elems_avail, relaxed);
			ops->zc_op_free(zid, zstack_pop(&stack));
		} else {
			vm_offset_t addr = (vm_offset_t)zstack_pop(&stack);

			if (zero) {
				bzero((void *)addr, esize);
			}
			addr = __zcache_mark_invalid(zone, addr,
			    ZFREE_PACK_SIZE(esize, esize));
			zfree_item(zone, addr);
		}

		if (stack.z_count == 0) {
			break;
		}

		disable_preemption();
		cpu = cpu_number();
	}
}

void
(zcache_free)(zone_id_t zid, void *addr, zone_cache_ops_t ops)
{
	__builtin_assume(ops != NULL);
	zcache_free_1_ext(zid, addr, ops);
}

void
(zcache_free_n)(zone_id_t zid, zstack_t stack, zone_cache_ops_t ops)
{
	__builtin_assume(ops != NULL);
	zcache_free_n_ext(zid, stack, ops, false);
}

void
(zfree_n)(zone_id_t zid, zstack_t stack)
{
	zcache_free_n_ext(zid, stack, NULL, true);
}

void
(zfree_nozero)(zone_id_t zid, void *addr)
{
	zcache_free_1_ext(zid, addr, NULL);
}

void
(zfree_nozero_n)(zone_id_t zid, zstack_t stack)
{
	zcache_free_n_ext(zid, stack, NULL, false);
}

void
(zfree)(union zone_or_view zov, void *addr)
{
	zone_t zone = zov.zov_view->zv_zone;
	zone_stats_t zstats = zov.zov_view->zv_stats;
	vm_offset_t esize = zone_elem_inner_size(zone);

	assert(zone > &zone_array[ZONE_ID__LAST_RO]);
	assert(!zone->z_percpu && !zone->z_permanent && !zone->z_smr);
	bzero(addr, esize);
	zfree_ext(zone, zstats, addr, ZFREE_PACK_SIZE(esize, esize));
}

__attribute__((noinline))
void
zfree_percpu(union zone_or_view zov, void *addr)
{
	zone_t zone = zov.zov_view->zv_zone;
	zone_stats_t zstats = zov.zov_view->zv_stats;
	vm_offset_t esize = zone_elem_inner_size(zone);

	assert(zone > &zone_array[ZONE_ID__LAST_RO]);
	assert(zone->z_percpu);
	addr = (void *)__zpcpu_demangle(addr);
	zpercpu_foreach_cpu(i) {
		bzero((char *)addr + ptoa(i), esize);
	}
	zfree_ext(zone, zstats, addr, ZFREE_PACK_SIZE(esize, esize));
}

void
(zfree_id)(zone_id_t zid, void *addr)
{
	(zfree)(&zone_array[zid], addr);
}

void
(zfree_ro)(zone_id_t zid, void *addr)
{
	assert(zid >= ZONE_ID__FIRST_RO && zid <= ZONE_ID__LAST_RO);
	zone_t zone = zone_by_id(zid);
	zone_stats_t zstats = zone->z_stats;
	vm_offset_t esize = zone_ro_size_params[zid].z_elem_size;

#if ZSECURITY_CONFIG(READ_ONLY)
	assert(zone_security_array[zid].z_submap_idx == Z_SUBMAP_IDX_READ_ONLY);
	pmap_ro_zone_bzero(zid, (vm_offset_t)addr, 0, esize);
#else
	(void)zid;
	bzero(addr, esize);
#endif /* !KASAN_CLASSIC */
	zfree_ext(zone, zstats, addr, ZFREE_PACK_SIZE(esize, esize));
}

__attribute__((noinline))
static void
zfree_item_smr(zone_t zone, vm_offset_t addr)
{
	zone_cache_t cache = zpercpu_get_cpu(zone->z_pcpu_cache, 0);
	vm_size_t esize = zone_elem_inner_size(zone);

	/*
	 * This should be taken extremely rarely:
	 * this happens if we failed allocating an empty bucket.
	 */
	smr_synchronize(zone_cache_smr(cache));

	cache->zc_free((void *)addr, esize);
	addr = __zcache_mark_invalid(zone, addr, ZFREE_PACK_SIZE(esize, esize));

	zfree_item(zone, addr);
}

void
(zfree_smr)(zone_t zone, void *addr)
{
	vm_offset_t elem = (vm_offset_t)addr;
	vm_offset_t esize;
	zone_cache_t cache;
	int cpu;

	ZFREE_LOG(zone, elem, 1);

	disable_preemption();
	cpu   = cpu_number();
#if MACH_ASSERT
	cache = zpercpu_get_cpu(zone->z_pcpu_cache, cpu);
	assert(!smr_entered_cpu(cache->zc_smr, cpu));
#endif
	esize = zone_elem_inner_size(zone);
	zpercpu_get_cpu(zone->z_stats, cpu)->zs_mem_freed += esize;
	cache = zfree_cached_get_pcpu_cache_smr(zone, cpu);
	if (__probable(cache)) {
		cache->zc_free_elems[cache->zc_free_cur++] = elem;
		enable_preemption();
	} else {
		zfree_item_smr(zone, elem);
	}
}

void
(zfree_id_smr)(zone_id_t zid, void *addr)
{
	(zfree_smr)(&zone_array[zid], addr);
}

/*! @} */
#endif /* !ZALLOC_TEST */
#pragma mark zalloc
#if !ZALLOC_TEST

/*!
 * @defgroup zalloc
 * @{
 *
 * @brief
 * The codepath for zone allocations.
 *
 * @discussion
 * There are 4 major ways to allocate memory that end up in the zone allocator:
 * - @c zalloc(), @c zalloc_flags(), ...
 * - @c zalloc_percpu()
 * - @c kalloc*()
 * - @c zalloc_permanent()
 *
 * While permanent zones have their own allocation scheme, all other codepaths
 * will eventually go through the @c zalloc_ext() choking point.
 *
 * @c zalloc_return() is the final function everyone tail calls into,
 * which prepares the element for consumption by the caller and deals with
 * common treatment (zone logging, tags, kasan, validation, ...).
 */

/*!
 * @function zalloc_import
 *
 * @brief
 * Import @c n elements in the specified array, opposite of @c zfree_drop().
 *
 * @param zone          The zone to import elements from
 * @param elems         The array to import into
 * @param n             The number of elements to import. Must be non zero,
 *                      and smaller than @c zone->z_elems_free.
 */
__header_always_inline vm_size_t
zalloc_import(
	zone_t                  zone,
	vm_offset_t            *elems,
	zalloc_flags_t          flags,
	uint32_t                n)
{
	vm_offset_t esize = zone_elem_outer_size(zone);
	vm_offset_t offs  = zone_elem_inner_offs(zone);
	zone_stats_t zs;
	int cpu = cpu_number();
	uint32_t i = 0;

	zs = zpercpu_get_cpu(zone->z_stats, cpu);

	if (__improbable(zone_caching_disabled < 0)) {
		/*
		 * In the first 10s after boot, mess with
		 * the scan position in order to make early
		 * allocations patterns less predictable.
		 */
		zone_early_scramble_rr(zone, cpu, zs);
	}

	do {
		vm_offset_t page, eidx, size = 0;
		struct zone_page_metadata *meta;

		if (!zone_pva_is_null(zone->z_pageq_partial)) {
			meta = zone_pva_to_meta(zone->z_pageq_partial);
			page = zone_pva_to_addr(zone->z_pageq_partial);
		} else if (!zone_pva_is_null(zone->z_pageq_empty)) {
			meta = zone_pva_to_meta(zone->z_pageq_empty);
			page = zone_pva_to_addr(zone->z_pageq_empty);
			zone_counter_sub(zone, z_wired_empty, meta->zm_chunk_len);
		} else {
			zone_accounting_panic(zone, "z_elems_free corruption");
		}

		zone_meta_validate(zone, meta, page);

		vm_offset_t old_size = meta->zm_alloc_size;
		vm_offset_t max_size = ptoa(meta->zm_chunk_len) + ZM_ALLOC_SIZE_LOCK;

		do {
			eidx = zone_meta_find_and_clear_bit(zone, zs, meta, flags);
			elems[i++] = page + offs + eidx * esize;
			size += esize;
		} while (i < n && old_size + size + esize <= max_size);

		vm_offset_t new_size = zone_meta_alloc_size_add(zone, meta, size);

		if (new_size + esize > max_size) {
			zone_meta_requeue(zone, &zone->z_pageq_full, meta);
		} else if (old_size == 0) {
			/* remove from free, move to intermediate */
			zone_meta_requeue(zone, &zone->z_pageq_partial, meta);
		}
	} while (i < n);

	n = zone_counter_sub(zone, z_elems_free, n);
	if (zone->z_pcpu_cache == NULL && zone->z_elems_free_min > n) {
		zone->z_elems_free_min = n;
	}

	return zone_elem_inner_size(zone);
}

__attribute__((always_inline))
static inline vm_offset_t
__zcache_mark_valid(zone_t zone, vm_offset_t addr, zalloc_flags_t flags)
{
#pragma unused(zone, flags)
#if KASAN || CONFIG_PROB_GZALLOC || VM_TAG_SIZECLASSES
	vm_offset_t esize = zone_elem_inner_size(zone);
#endif

#if VM_TAG_SIZECLASSES
	if (__improbable(zone->z_uses_tags)) {
		struct zone_page_metadata *meta;
		vm_offset_t offs;
		vm_tag_t *slot;
		vm_tag_t tag;

		tag  = zalloc_flags_get_tag(flags);
		meta = zone_meta_from_addr(addr);
		offs = (addr & PAGE_MASK) - zone_elem_inner_offs(zone);
		if (meta->zm_chunk_len == ZM_SECONDARY_PAGE) {
			offs += ptoa(meta->zm_page_index);
		}

		slot = zba_extra_ref_ptr(meta->zm_bitmap,
		    Z_FAST_QUO(offs, zone->z_quo_magic));
		*slot = tag;

		vm_tag_update_zone_size(tag, zone->z_tags_sizeclass,
		    (long)esize);
	}
#endif /* VM_TAG_SIZECLASSES */

#if CONFIG_PROB_GZALLOC
	if (zone->z_pgz_tracked && pgz_sample(addr, esize)) {
		addr = pgz_protect(zone, addr, __builtin_frame_address(0));
	}
#endif

	/*
	 * Kasan integration of kalloc heaps are handled by kalloc_ext()
	 */
	if ((flags & Z_SKIP_KASAN) == 0) {
#if KASAN_CLASSIC
		kasan_alloc(addr, esize, esize, zone_elem_redzone(zone),
		    (flags & Z_PCPU), __builtin_frame_address(0));
#endif /* KASAN_CLASSIC */
#if KASAN_TBI
		if (__probable(zone->z_tbi_tag)) {
			addr = kasan_tbi_tag_zalloc(addr, esize, esize,
			    (flags & Z_PCPU));
		} else {
			addr = kasan_tbi_tag_zalloc_default(addr, esize,
			    (flags & Z_PCPU));
		}
#endif /* KASAN_TBI */
	}

	return addr;
}

__attribute__((always_inline))
vm_offset_t
(zcache_mark_valid)(zone_t zone, vm_offset_t addr)
{
	addr = __zcache_mark_valid(zone, addr, 0);
	ZALLOC_LOG(zone, addr, 1);
	return addr;
}

/*!
 * @function zalloc_return
 *
 * @brief
 * Performs the tail-end of the work required on allocations before the caller
 * uses them.
 *
 * @discussion
 * This function is called without any zone lock held,
 * and preemption back to the state it had when @c zalloc_ext() was called.
 *
 * @param zone          The zone we're allocating from.
 * @param addr          The element we just allocated.
 * @param flags         The flags passed to @c zalloc_ext() (for Z_ZERO).
 * @param elem_size     The element size for this zone.
 */
__attribute__((always_inline))
static struct kalloc_result
zalloc_return(
	zone_t                  zone,
	vm_offset_t             addr,
	zalloc_flags_t          flags,
	vm_offset_t             elem_size)
{
	addr = __zcache_mark_valid(zone, addr, flags);
#if ZALLOC_ENABLE_ZERO_CHECK
	zalloc_validate_element(zone, addr, elem_size, flags);
#endif /* ZALLOC_ENABLE_ZERO_CHECK */
	ZALLOC_LOG(zone, addr, 1);

	DTRACE_VM2(zalloc, zone_t, zone, void*, addr);
	return (struct kalloc_result){ (void *)addr, elem_size };
}

__attribute__((noinline))
static struct kalloc_result
zalloc_item(zone_t zone, zone_stats_t zstats, zalloc_flags_t flags)
{
	vm_offset_t esize, addr;

	zone_lock_nopreempt_check_contention(zone);

	if (__improbable(zone->z_elems_free <= zone->z_elems_rsv / 2)) {
		if ((flags & Z_NOWAIT) || zone->z_elems_free) {
			zone_expand_async_schedule_if_allowed(zone);
		} else {
			zone_expand_locked(zone, flags, zalloc_needs_refill);
		}
		if (__improbable(zone->z_elems_free == 0)) {
			zpercpu_get(zstats)->zs_alloc_fail++;
			zone_unlock(zone);
			if (__improbable(flags & Z_NOFAIL)) {
				zone_nofail_panic(zone);
			}
			DTRACE_VM2(zalloc, zone_t, zone, void*, NULL);
			return (struct kalloc_result){ };
		}
	}

	esize = zalloc_import(zone, &addr, flags, 1);
	zpercpu_get(zstats)->zs_mem_allocated += esize;
	zone_unlock(zone);

	return zalloc_return(zone, addr, flags, esize);
}

static void
zalloc_cached_import(
	zone_t                  zone,
	zalloc_flags_t          flags,
	zone_cache_t            cache)
{
	uint16_t n_elems = zc_mag_size();

	zone_lock_nopreempt(zone);

	if (__probable(!zone_caching_disabled &&
	    zone->z_elems_free > zone->z_elems_rsv / 2)) {
		if (__improbable(zone->z_elems_free <= zone->z_elems_rsv)) {
			zone_expand_async_schedule_if_allowed(zone);
		}
		if (zone->z_elems_free < n_elems) {
			n_elems = (uint16_t)zone->z_elems_free;
		}
		zalloc_import(zone, cache->zc_alloc_elems, flags, n_elems);
		cache->zc_alloc_cur = n_elems;
	}

	zone_unlock_nopreempt(zone);
}

static void
zalloc_cached_depot_recirculate(
	zone_t                  zone,
	uint32_t                depot_max,
	zone_cache_t            cache,
	smr_t                   smr)
{
	smr_seq_t seq;
	uint32_t n;

	zone_recirc_lock_nopreempt_check_contention(zone);

	n = cache->zc_depot.zd_empty;
	if (n >= depot_max) {
		zone_depot_move_empty(&zone->z_recirc, &cache->zc_depot,
		    n - depot_max / 2, NULL);
	}

	n = cache->zc_depot.zd_full;
	if (smr && n) {
		/*
		 * if SMR is in use, it means smr_poll() failed,
		 * so rotate the entire chunk of magazines in order
		 * to let the sequence numbers age.
		 */
		seq = zone_depot_move_full(&zone->z_recirc, &cache->zc_depot,
		    n, NULL);
		smr_deferred_advance_commit(smr, seq);
	}

	n = depot_max - cache->zc_depot.zd_empty;
	if (n > zone->z_recirc.zd_full) {
		n = zone->z_recirc.zd_full;
	}

	if (n && zone_depot_poll(&zone->z_recirc, smr)) {
		zone_depot_move_full(&cache->zc_depot, &zone->z_recirc,
		    n, zone);
	}

	zone_recirc_unlock_nopreempt(zone);
}

static void
zalloc_cached_reuse_smr(zone_t z, zone_cache_t cache, zone_magazine_t mag)
{
	zone_smr_free_cb_t zc_free = cache->zc_free;
	vm_size_t esize = zone_elem_inner_size(z);

	for (uint16_t i = 0; i < zc_mag_size(); i++) {
		vm_offset_t elem = mag->zm_elems[i];

		zc_free((void *)elem, zone_elem_inner_size(z));
		elem = __zcache_mark_invalid(z, elem,
		    ZFREE_PACK_SIZE(esize, esize));
		mag->zm_elems[i] = elem;
	}
}

static void
zalloc_cached_recirculate(
	zone_t                  zone,
	zone_cache_t            cache)
{
	zone_magazine_t mag = NULL;

	zone_recirc_lock_nopreempt_check_contention(zone);

	if (zone_depot_poll(&zone->z_recirc, zone_cache_smr(cache))) {
		mag = zone_depot_pop_head_full(&zone->z_recirc, zone);
		if (zone_cache_smr(cache)) {
			zalloc_cached_reuse_smr(zone, cache, mag);
		}
		mag = zone_magazine_replace(cache, mag, false);
		zone_depot_insert_head_empty(&zone->z_recirc, mag);
	}

	zone_recirc_unlock_nopreempt(zone);
}

__attribute__((noinline))
static zone_cache_t
zalloc_cached_prime(
	zone_t                  zone,
	zone_cache_ops_t        ops,
	zalloc_flags_t          flags,
	zone_cache_t            cache)
{
	zone_magazine_t mag = NULL;
	uint32_t depot_max;
	smr_t smr;

	depot_max = os_atomic_load(&zone->z_depot_size, relaxed);
	if (depot_max) {
		smr = zone_cache_smr(cache);

		zone_depot_lock_nopreempt(cache);

		if (!zone_depot_poll(&cache->zc_depot, smr)) {
			zalloc_cached_depot_recirculate(zone, depot_max, cache,
			    smr);
		}

		if (__probable(cache->zc_depot.zd_full)) {
			mag = zone_depot_pop_head_full(&cache->zc_depot, NULL);
			if (zone_cache_smr(cache)) {
				zalloc_cached_reuse_smr(zone, cache, mag);
			}
			mag = zone_magazine_replace(cache, mag, false);
			zone_depot_insert_head_empty(&cache->zc_depot, mag);
		}

		zone_depot_unlock_nopreempt(cache);
	} else if (zone->z_recirc.zd_full) {
		zalloc_cached_recirculate(zone, cache);
	}

	if (__probable(cache->zc_alloc_cur)) {
		return cache;
	}

	if (ops == NULL) {
		zalloc_cached_import(zone, flags, cache);
		if (__probable(cache->zc_alloc_cur)) {
			return cache;
		}
	}

	return NULL;
}

__attribute__((always_inline))
static inline zone_cache_t
zalloc_cached_get_pcpu_cache(
	zone_t                  zone,
	zone_cache_ops_t        ops,
	int                     cpu,
	zalloc_flags_t          flags)
{
	zone_cache_t cache = zpercpu_get_cpu(zone->z_pcpu_cache, cpu);

	if (__probable(cache->zc_alloc_cur != 0)) {
		return cache;
	}

	if (__probable(cache->zc_free_cur != 0 && !cache->zc_smr)) {
		zone_cache_swap_magazines(cache);
		return cache;
	}

	return zalloc_cached_prime(zone, ops, flags, cache);
}


/*!
 * @function zalloc_ext
 *
 * @brief
 * The core implementation of @c zalloc(), @c zalloc_flags(), @c zalloc_percpu().
 */
struct kalloc_result
zalloc_ext(zone_t zone, zone_stats_t zstats, zalloc_flags_t flags)
{
	/*
	 * KASan uses zalloc() for fakestack, which can be called anywhere.
	 * However, we make sure these calls can never block.
	 */
	assertf(startup_phase < STARTUP_SUB_EARLY_BOOT ||
#if KASAN_FAKESTACK
	    zone->z_kasan_fakestacks ||
#endif /* KASAN_FAKESTACK */
	    ml_get_interrupts_enabled() ||
	    ml_is_quiescing() ||
	    debug_mode_active(),
	    "Calling {k,z}alloc from interrupt disabled context isn't allowed");

	/*
	 * Make sure Z_NOFAIL was not obviously misused
	 */
	if (flags & Z_NOFAIL) {
		assert(!zone->exhaustible &&
		    (flags & (Z_NOWAIT | Z_NOPAGEWAIT)) == 0);
	}

#if VM_TAG_SIZECLASSES
	if (__improbable(zone->z_uses_tags)) {
		vm_tag_t tag = zalloc_flags_get_tag(flags);

		if (flags & Z_VM_TAG_BT_BIT) {
			tag = vm_tag_bt() ?: tag;
		}
		if (tag != VM_KERN_MEMORY_NONE) {
			tag = vm_tag_will_update_zone(tag, zone->z_tags_sizeclass,
			    flags & (Z_WAITOK | Z_NOWAIT | Z_NOPAGEWAIT));
		}
		if (tag == VM_KERN_MEMORY_NONE) {
			zone_security_flags_t zsflags = zone_security_config(zone);

			if (zsflags.z_kheap_id == KHEAP_ID_DATA_BUFFERS) {
				tag = VM_KERN_MEMORY_KALLOC_DATA;
			} else if (zsflags.z_kheap_id == KHEAP_ID_KT_VAR ||
			    zsflags.z_kalloc_type) {
				tag = VM_KERN_MEMORY_KALLOC_TYPE;
			} else {
				tag = VM_KERN_MEMORY_KALLOC;
			}
		}
		flags = Z_VM_TAG(flags & ~Z_VM_TAG_MASK, tag);
	}
#endif /* VM_TAG_SIZECLASSES */

	disable_preemption();

#if ZALLOC_ENABLE_ZERO_CHECK
	if (zalloc_skip_zero_check()) {
		flags |= Z_NOZZC;
	}
#endif

	if (zone->z_pcpu_cache) {
		zone_cache_t cache;
		vm_offset_t index, addr, esize;
		int cpu = cpu_number();

		cache = zalloc_cached_get_pcpu_cache(zone, NULL, cpu, flags);
		if (__probable(cache)) {
			esize = zone_elem_inner_size(zone);
			zpercpu_get_cpu(zstats, cpu)->zs_mem_allocated += esize;
			index = --cache->zc_alloc_cur;
			addr  = cache->zc_alloc_elems[index];
			cache->zc_alloc_elems[index] = 0;
			enable_preemption();
			return zalloc_return(zone, addr, flags, esize);
		}
	}

	__attribute__((musttail))
	return zalloc_item(zone, zstats, flags);
}

__attribute__((always_inline))
static inline zstack_t
zcache_alloc_stack_from_cpu(
	zone_id_t               zid,
	zone_cache_t            cache,
	zstack_t                stack,
	uint32_t                n,
	zone_cache_ops_t        ops)
{
	vm_offset_t *p;

	n = MIN(n, cache->zc_alloc_cur);
	p = cache->zc_alloc_elems + cache->zc_alloc_cur;
	cache->zc_alloc_cur -= n;
	stack.z_count += n;

	do {
		vm_offset_t e = *--p;

		*p = 0;
		if (ops) {
			e = (vm_offset_t)ops->zc_op_mark_valid(zid, (void *)e);
		} else {
			e = __zcache_mark_valid(zone_by_id(zid), e, 0);
		}
		zstack_push_no_delta(&stack, (void *)e);
	} while (--n > 0);

	return stack;
}

__attribute__((noinline))
static zstack_t
zcache_alloc_fail(zone_id_t zid, zstack_t stack, uint32_t count)
{
	zone_t zone = zone_by_id(zid);
	zone_stats_t zstats = zone->z_stats;
	int cpu;

	count -= stack.z_count;

	disable_preemption();
	cpu = cpu_number();
	zpercpu_get_cpu(zstats, cpu)->zs_mem_allocated -=
	    count * zone_elem_inner_size(zone);
	zpercpu_get_cpu(zstats, cpu)->zs_alloc_fail += 1;
	enable_preemption();

	return stack;
}

__attribute__((always_inline))
static zstack_t
zcache_alloc_n_ext(
	zone_id_t               zid,
	uint32_t                count,
	zalloc_flags_t          flags,
	zone_cache_ops_t        ops)
{
	zstack_t stack = { };
	zone_cache_t cache;
	zone_t zone;
	int cpu;

	disable_preemption();
	cpu  = cpu_number();
	zone = zone_by_id(zid);
	zpercpu_get_cpu(zone->z_stats, cpu)->zs_mem_allocated +=
	    count * zone_elem_inner_size(zone);

	for (;;) {
		cache = zalloc_cached_get_pcpu_cache(zone, ops, cpu, flags);
		if (__probable(cache)) {
			stack = zcache_alloc_stack_from_cpu(zid, cache, stack,
			    count - stack.z_count, ops);
			enable_preemption();
		} else {
			void *o;

			if (ops) {
				enable_preemption();
				o = ops->zc_op_alloc(zid, flags);
			} else {
				o = zalloc_item(zone, zone->z_stats, flags).addr;
			}
			if (__improbable(o == NULL)) {
				return zcache_alloc_fail(zid, stack, count);
			}
			if (ops) {
				os_atomic_inc(&zone->z_elems_avail, relaxed);
			}
			zstack_push(&stack, o);
		}

		if (stack.z_count == count) {
			break;
		}

		disable_preemption();
		cpu = cpu_number();
	}

	ZALLOC_LOG(zone, stack.z_head, stack.z_count);

	return stack;
}

zstack_t
zalloc_n(zone_id_t zid, uint32_t count, zalloc_flags_t flags)
{
	return zcache_alloc_n_ext(zid, count, flags, NULL);
}

zstack_t
(zcache_alloc_n)(
	zone_id_t               zid,
	uint32_t                count,
	zalloc_flags_t          flags,
	zone_cache_ops_t        ops)
{
	__builtin_assume(ops != NULL);
	return zcache_alloc_n_ext(zid, count, flags, ops);
}

__attribute__((always_inline))
void *
zalloc(union zone_or_view zov)
{
	return zalloc_flags(zov, Z_WAITOK);
}

__attribute__((always_inline))
void *
zalloc_noblock(union zone_or_view zov)
{
	return zalloc_flags(zov, Z_NOWAIT);
}

void *
(zalloc_flags)(union zone_or_view zov, zalloc_flags_t flags)
{
	zone_t zone = zov.zov_view->zv_zone;
	zone_stats_t zstats = zov.zov_view->zv_stats;

	assert(zone > &zone_array[ZONE_ID__LAST_RO]);
	assert(!zone->z_percpu && !zone->z_permanent);
	return zalloc_ext(zone, zstats, flags).addr;
}

__attribute__((always_inline))
void *
(zalloc_id)(zone_id_t zid, zalloc_flags_t flags)
{
	return (zalloc_flags)(zone_by_id(zid), flags);
}

void *
(zalloc_ro)(zone_id_t zid, zalloc_flags_t flags)
{
	assert(zid >= ZONE_ID__FIRST_RO && zid <= ZONE_ID__LAST_RO);
	zone_t zone = zone_by_id(zid);
	zone_stats_t zstats = zone->z_stats;
	struct kalloc_result kr;

	kr = zalloc_ext(zone, zstats, flags);
#if ZSECURITY_CONFIG(READ_ONLY)
	assert(zone_security_array[zid].z_submap_idx == Z_SUBMAP_IDX_READ_ONLY);
	if (kr.addr) {
		zone_require_ro(zid, kr.size, kr.addr);
	}
#endif
	return kr.addr;
}

#if ZSECURITY_CONFIG(READ_ONLY)

__attribute__((always_inline))
static bool
from_current_stack(vm_offset_t addr, vm_size_t size)
{
	vm_offset_t start = (vm_offset_t)__builtin_frame_address(0);
	vm_offset_t end = (start + kernel_stack_size - 1) & -kernel_stack_size;

#if CONFIG_KERNEL_TBI
	addr = VM_KERNEL_TBI_FILL(addr);
#endif /* CONFIG_KERNEL_TBI */

	return (addr >= start) && (addr + size < end);
}

/*
 * Check if an address is from const memory i.e TEXT or DATA CONST segements
 * or the SECURITY_READ_ONLY_LATE section.
 */
#if defined(KERNEL_INTEGRITY_KTRR) || defined(KERNEL_INTEGRITY_CTRR)
__attribute__((always_inline))
static bool
from_const_memory(const vm_offset_t addr, vm_size_t size)
{
	return rorgn_contains(addr, size, true);
}
#else /* defined(KERNEL_INTEGRITY_KTRR) || defined(KERNEL_INTEGRITY_CTRR) */
__attribute__((always_inline))
static bool
from_const_memory(const vm_offset_t addr, vm_size_t size)
{
#pragma unused(addr, size)
	return true;
}
#endif /* defined(KERNEL_INTEGRITY_KTRR) || defined(KERNEL_INTEGRITY_CTRR) */

__abortlike
static void
zalloc_ro_mut_validation_panic(zone_id_t zid, void *elem,
    const vm_offset_t src, vm_size_t src_size)
{
	vm_offset_t stack_start = (vm_offset_t)__builtin_frame_address(0);
	vm_offset_t stack_end = (stack_start + kernel_stack_size - 1) & -kernel_stack_size;
#if defined(KERNEL_INTEGRITY_KTRR) || defined(KERNEL_INTEGRITY_CTRR)
	extern vm_offset_t rorgn_begin;
	extern vm_offset_t rorgn_end;
#else
	vm_offset_t const rorgn_begin = 0;
	vm_offset_t const rorgn_end = 0;
#endif

	if (from_ro_map(src, src_size)) {
		zone_t src_zone = &zone_array[zone_index_from_ptr((void *)src)];
		zone_t dst_zone = &zone_array[zid];
		panic("zalloc_ro_mut failed: source (%p) not from same zone as dst (%p)"
		    " (expected: %s, actual: %s", (void *)src, elem, src_zone->z_name,
		    dst_zone->z_name);
	}

	panic("zalloc_ro_mut failed: source (%p, phys %p) not from RO zone map (%p - %p), "
	    "current stack (%p - %p) or const memory (phys %p - %p)",
	    (void *)src, (void*)kvtophys(src),
	    (void *)zone_info.zi_ro_range.min_address,
	    (void *)zone_info.zi_ro_range.max_address,
	    (void *)stack_start, (void *)stack_end,
	    (void *)rorgn_begin, (void *)rorgn_end);
}

__attribute__((always_inline))
static void
zalloc_ro_mut_validate_src(zone_id_t zid, void *elem,
    const vm_offset_t src, vm_size_t src_size)
{
	if (from_current_stack(src, src_size) ||
	    (from_ro_map(src, src_size) &&
	    zid == zone_index_from_ptr((void *)src)) ||
	    from_const_memory(src, src_size)) {
		return;
	}
	zalloc_ro_mut_validation_panic(zid, elem, src, src_size);
}

#endif /* ZSECURITY_CONFIG(READ_ONLY) */

__attribute__((noinline))
void
zalloc_ro_mut(zone_id_t zid, void *elem, vm_offset_t offset,
    const void *new_data, vm_size_t new_data_size)
{
	assert(zid >= ZONE_ID__FIRST_RO && zid <= ZONE_ID__LAST_RO);

#if ZSECURITY_CONFIG(READ_ONLY)
	bool skip_src_check = false;

	/*
	 * The OSEntitlements RO-zone is a little differently treated. For more
	 * information: rdar://100518485.
	 */
	if (zid == ZONE_ID_AMFI_OSENTITLEMENTS) {
		code_signing_config_t cs_config = 0;

		code_signing_configuration(NULL, &cs_config);
		if (cs_config & CS_CONFIG_CSM_ENABLED) {
			skip_src_check = true;
		}
	}

	if (skip_src_check == false) {
		zalloc_ro_mut_validate_src(zid, elem, (vm_offset_t)new_data,
		    new_data_size);
	}
	pmap_ro_zone_memcpy(zid, (vm_offset_t) elem, offset,
	    (vm_offset_t) new_data, new_data_size);
#else
	(void)zid;
	memcpy((void *)((uintptr_t)elem + offset), new_data, new_data_size);
#endif
}

__attribute__((noinline))
uint64_t
zalloc_ro_mut_atomic(zone_id_t zid, void *elem, vm_offset_t offset,
    zro_atomic_op_t op, uint64_t value)
{
	assert(zid >= ZONE_ID__FIRST_RO && zid <= ZONE_ID__LAST_RO);

#if ZSECURITY_CONFIG(READ_ONLY)
	value = pmap_ro_zone_atomic_op(zid, (vm_offset_t)elem, offset, op, value);
#else
	(void)zid;
	value = __zalloc_ro_mut_atomic((vm_offset_t)elem + offset, op, value);
#endif
	return value;
}

void
zalloc_ro_clear(zone_id_t zid, void *elem, vm_offset_t offset, vm_size_t size)
{
	assert(zid >= ZONE_ID__FIRST_RO && zid <= ZONE_ID__LAST_RO);
#if ZSECURITY_CONFIG(READ_ONLY)
	pmap_ro_zone_bzero(zid, (vm_offset_t)elem, offset, size);
#else
	(void)zid;
	bzero((void *)((uintptr_t)elem + offset), size);
#endif
}

/*
 * This function will run in the PPL and needs to be robust
 * against an attacker with arbitrary kernel write.
 */

#if ZSECURITY_CONFIG(READ_ONLY)

__abortlike
static void
zone_id_require_ro_panic(zone_id_t zid, void *addr)
{
	struct zone_size_params p = zone_ro_size_params[zid];
	vm_offset_t elem = (vm_offset_t)addr;
	uint32_t zindex;
	zone_t other;
	zone_t zone = &zone_array[zid];

	if (!from_ro_map(addr, 1)) {
		panic("zone_require_ro failed: address not in a ro zone (addr: %p)", addr);
	}

	if (!Z_FAST_ALIGNED(PAGE_SIZE - (elem & PAGE_MASK), p.z_align_magic)) {
		panic("zone_require_ro failed: element improperly aligned (addr: %p)", addr);
	}

	zindex = zone_index_from_ptr(addr);
	other = &zone_array[zindex];
	if (zindex >= os_atomic_load(&num_zones, relaxed) || !other->z_self) {
		panic("zone_require_ro failed: invalid zone index %d "
		    "(addr: %p, expected: %s%s)", zindex,
		    addr, zone_heap_name(zone), zone->z_name);
	} else {
		panic("zone_require_ro failed: address in unexpected zone id %d (%s%s) "
		    "(addr: %p, expected: %s%s)",
		    zindex, zone_heap_name(other), other->z_name,
		    addr, zone_heap_name(zone), zone->z_name);
	}
}

#endif /* ZSECURITY_CONFIG(READ_ONLY) */

__attribute__((always_inline))
void
zone_require_ro(zone_id_t zid, vm_size_t elem_size __unused, void *addr)
{
#if ZSECURITY_CONFIG(READ_ONLY)
	struct zone_size_params p = zone_ro_size_params[zid];
	vm_offset_t elem = (vm_offset_t)addr;

	if (!from_ro_map(addr, 1) ||
	    !Z_FAST_ALIGNED(PAGE_SIZE - (elem & PAGE_MASK), p.z_align_magic) ||
	    zid != zone_meta_from_addr(elem)->zm_index) {
		zone_id_require_ro_panic(zid, addr);
	}
#else
#pragma unused(zid, addr)
#endif
}

void *
(zalloc_percpu)(union zone_or_view zov, zalloc_flags_t flags)
{
	zone_t zone = zov.zov_view->zv_zone;
	zone_stats_t zstats = zov.zov_view->zv_stats;

	assert(zone > &zone_array[ZONE_ID__LAST_RO]);
	assert(zone->z_percpu);
	flags |= Z_PCPU;
	return (void *)__zpcpu_mangle(zalloc_ext(zone, zstats, flags).addr);
}

static void *
_zalloc_permanent(zone_t zone, vm_size_t size, vm_offset_t mask)
{
	struct zone_page_metadata *page_meta;
	vm_offset_t offs, addr;
	zone_pva_t pva;

	assert(ml_get_interrupts_enabled() ||
	    ml_is_quiescing() ||
	    debug_mode_active() ||
	    startup_phase < STARTUP_SUB_EARLY_BOOT);

	size = (size + mask) & ~mask;
	assert(size <= PAGE_SIZE);

	zone_lock(zone);
	assert(zone->z_self == zone);

	for (;;) {
		pva = zone->z_pageq_partial;
		while (!zone_pva_is_null(pva)) {
			page_meta = zone_pva_to_meta(pva);
			if (page_meta->zm_bump + size <= PAGE_SIZE) {
				goto found;
			}
			pva = page_meta->zm_page_next;
		}

		zone_expand_locked(zone, Z_WAITOK, NULL);
	}

found:
	offs = (uint16_t)((page_meta->zm_bump + mask) & ~mask);
	page_meta->zm_bump = (uint16_t)(offs + size);
	page_meta->zm_alloc_size += size;
	zone->z_elems_free -= size;
	zpercpu_get(zone->z_stats)->zs_mem_allocated += size;

	if (page_meta->zm_alloc_size >= PAGE_SIZE - sizeof(vm_offset_t)) {
		zone_meta_requeue(zone, &zone->z_pageq_full, page_meta);
	}

	zone_unlock(zone);

	addr = offs + zone_pva_to_addr(pva);

	DTRACE_VM2(zalloc, zone_t, zone, void*, addr);
	return (void *)addr;
}

static void *
_zalloc_permanent_large(size_t size, vm_offset_t mask, vm_tag_t tag)
{
	vm_offset_t addr;

	kernel_memory_allocate(kernel_map, &addr, size, mask,
	    KMA_NOFAIL | KMA_KOBJECT | KMA_PERMANENT | KMA_ZERO, tag);

	return (void *)addr;
}

void *
zalloc_permanent_tag(vm_size_t size, vm_offset_t mask, vm_tag_t tag)
{
	if (size <= PAGE_SIZE) {
		zone_t zone = &zone_array[ZONE_ID_PERMANENT];
		return _zalloc_permanent(zone, size, mask);
	}
	return _zalloc_permanent_large(size, mask, tag);
}

void *
zalloc_percpu_permanent(vm_size_t size, vm_offset_t mask)
{
	zone_t zone = &zone_array[ZONE_ID_PERCPU_PERMANENT];
	return (void *)__zpcpu_mangle(_zalloc_permanent(zone, size, mask));
}

/*! @} */
#endif /* !ZALLOC_TEST */
#pragma mark zone GC / trimming
#if !ZALLOC_TEST

static thread_call_data_t zone_trim_callout;
EVENT_DEFINE(ZONE_EXHAUSTED);

static void
zone_reclaim_chunk(
	zone_t                  z,
	struct zone_page_metadata *meta,
	uint32_t                free_count)
{
	vm_address_t page_addr;
	vm_size_t    size_to_free;
	uint32_t     bitmap_ref;
	uint32_t     page_count;
	zone_security_flags_t zsflags = zone_security_config(z);
	bool         sequester = !z->z_destroyed;
	bool         oob_guard = false;

	if (zone_submap_is_sequestered(zsflags)) {
		/*
		 * If the entire map is sequestered, we can't return the VA.
		 * It stays pinned to the zone forever.
		 */
		sequester = true;
	}

	zone_meta_queue_pop(z, &z->z_pageq_empty);

	page_addr  = zone_meta_to_addr(meta);
	page_count = meta->zm_chunk_len;
	oob_guard  = meta->zm_guarded;

	if (meta->zm_alloc_size) {
		zone_metadata_corruption(z, meta, "alloc_size");
	}
	if (z->z_percpu) {
		if (page_count != 1) {
			zone_metadata_corruption(z, meta, "page_count");
		}
		size_to_free = ptoa(z->z_chunk_pages);
		zone_remove_wired_pages(z->z_chunk_pages);
	} else {
		if (page_count > z->z_chunk_pages) {
			zone_metadata_corruption(z, meta, "page_count");
		}
		if (page_count < z->z_chunk_pages) {
			/* Dequeue non populated VA from z_pageq_va */
			zone_meta_remqueue(z, meta + page_count);
		}
		size_to_free = ptoa(page_count);
		zone_remove_wired_pages(page_count);
	}

	zone_counter_sub(z, z_elems_free, free_count);
	zone_counter_sub(z, z_elems_avail, free_count);
	zone_counter_sub(z, z_wired_empty, page_count);
	zone_counter_sub(z, z_wired_cur, page_count);

	if (z->z_pcpu_cache == NULL) {
		if (z->z_elems_free_min < free_count) {
			z->z_elems_free_min = 0;
		} else {
			z->z_elems_free_min -= free_count;
		}
	}
	if (z->z_elems_free_wma < free_count) {
		z->z_elems_free_wma = 0;
	} else {
		z->z_elems_free_wma -= free_count;
	}

	bitmap_ref = 0;
	if (sequester) {
		if (meta->zm_inline_bitmap) {
			for (int i = 0; i < meta->zm_chunk_len; i++) {
				meta[i].zm_bitmap = 0;
			}
		} else {
			bitmap_ref = meta->zm_bitmap;
			meta->zm_bitmap = 0;
		}
		meta->zm_chunk_len = 0;
	} else {
		if (!meta->zm_inline_bitmap) {
			bitmap_ref = meta->zm_bitmap;
		}
		zone_counter_sub(z, z_va_cur, z->z_percpu ? 1 : z->z_chunk_pages);
		bzero(meta, sizeof(*meta) * (z->z_chunk_pages + oob_guard));
	}

#if CONFIG_ZLEAKS
	if (__improbable(zleak_should_disable_for_zone(z) &&
	    startup_phase >= STARTUP_SUB_THREAD_CALL)) {
		thread_call_enter(&zone_leaks_callout);
	}
#endif /* CONFIG_ZLEAKS */

	zone_unlock(z);

	if (bitmap_ref) {
		zone_bits_free(bitmap_ref);
	}

	/* Free the pages for metadata and account for them */
#if KASAN_CLASSIC
	if (z->z_percpu) {
		for (uint32_t i = 0; i < z->z_chunk_pages; i++) {
			kasan_zmem_remove(page_addr + ptoa(i), PAGE_SIZE,
			    zone_elem_outer_size(z),
			    zone_elem_outer_offs(z),
			    zone_elem_redzone(z));
		}
	} else {
		kasan_zmem_remove(page_addr, size_to_free,
		    zone_elem_outer_size(z),
		    zone_elem_outer_offs(z),
		    zone_elem_redzone(z));
	}
#endif /* KASAN_CLASSIC */

	if (sequester) {
		kernel_memory_depopulate(page_addr, size_to_free,
		    KMA_KOBJECT, VM_KERN_MEMORY_ZONE);
	} else {
		assert(zsflags.z_submap_idx != Z_SUBMAP_IDX_VM);
		kmem_free(zone_submap(zsflags), page_addr,
		    ptoa(z->z_chunk_pages + oob_guard));
		if (oob_guard) {
			os_atomic_dec(&zone_guard_pages, relaxed);
		}
	}

	thread_yield_to_preemption();

	zone_lock(z);

	if (sequester) {
		zone_meta_queue_push(z, &z->z_pageq_va, meta);
	}
}

static void
zone_reclaim_elements(zone_t z, uint16_t n, vm_offset_t *elems)
{
	z_debug_assert(n <= zc_mag_size());

	for (uint16_t i = 0; i < n; i++) {
		vm_offset_t addr = elems[i];
		elems[i] = 0;
		zfree_drop(z, addr);
	}

	z->z_elems_free += n;
}

static void
zcache_reclaim_elements(zone_id_t zid, uint16_t n, vm_offset_t *elems)
{
	z_debug_assert(n <= zc_mag_size());
	zone_cache_ops_t ops = zcache_ops[zid];

	for (uint16_t i = 0; i < n; i++) {
		vm_offset_t addr = elems[i];
		elems[i] = 0;
		addr = (vm_offset_t)ops->zc_op_mark_valid(zid, (void *)addr);
		ops->zc_op_free(zid, (void *)addr);
	}

	os_atomic_sub(&zone_by_id(zid)->z_elems_avail, n, relaxed);
}

static void
zone_depot_trim(zone_t z, uint32_t target, struct zone_depot *zd)
{
	zpercpu_foreach(zc, z->z_pcpu_cache) {
		zone_depot_lock(zc);

		if (zc->zc_depot.zd_full > (target + 1) / 2) {
			uint32_t n = zc->zc_depot.zd_full - (target + 1) / 2;
			zone_depot_move_full(zd, &zc->zc_depot, n, NULL);
		}

		if (zc->zc_depot.zd_empty > target / 2) {
			uint32_t n = zc->zc_depot.zd_empty - target / 2;
			zone_depot_move_empty(zd, &zc->zc_depot, n, NULL);
		}

		zone_depot_unlock(zc);
	}
}

__enum_decl(zone_reclaim_mode_t, uint32_t, {
	ZONE_RECLAIM_TRIM,
	ZONE_RECLAIM_DRAIN,
	ZONE_RECLAIM_DESTROY,
});

static void
zone_reclaim_pcpu(zone_t z, zone_reclaim_mode_t mode, struct zone_depot *zd)
{
	uint32_t depot_max = 0;
	bool cleanup = mode != ZONE_RECLAIM_TRIM;

	if (z->z_depot_cleanup) {
		z->z_depot_cleanup = false;
		depot_max = z->z_depot_size;
		cleanup = true;
	}

	if (cleanup) {
		zone_depot_trim(z, depot_max, zd);
	}

	if (mode == ZONE_RECLAIM_DESTROY) {
		zpercpu_foreach(zc, z->z_pcpu_cache) {
			zone_reclaim_elements(z, zc->zc_alloc_cur,
			    zc->zc_alloc_elems);
			zone_reclaim_elements(z, zc->zc_free_cur,
			    zc->zc_free_elems);
			zc->zc_alloc_cur = zc->zc_free_cur = 0;
		}

		z->z_recirc_empty_min = 0;
		z->z_recirc_empty_wma = 0;
		z->z_recirc_full_min = 0;
		z->z_recirc_full_wma = 0;
		z->z_recirc_cont_cur = 0;
		z->z_recirc_cont_wma = 0;
	}
}

static void
zone_reclaim_recirc(zone_t z, zone_reclaim_mode_t mode, struct zone_depot *zd)
{
	assert(zd->zd_empty == 0);
	assert(zd->zd_full == 0);

	zone_recirc_lock_nopreempt(z);

	if (mode == ZONE_RECLAIM_TRIM) {
		uint32_t count;

		count = MIN(z->z_recirc_empty_wma / Z_WMA_UNIT,
		    z->z_recirc_empty_min);
		assert(count <= z->z_recirc.zd_empty);

		if (count) {
			zone_depot_move_empty(zd, &z->z_recirc, count, NULL);
			z->z_recirc_empty_min -= count;
			z->z_recirc_empty_wma -= count * Z_WMA_UNIT;
		}

		count = MIN(z->z_recirc_full_wma / Z_WMA_UNIT, z->z_recirc_full_min);
		assert(count <= z->z_recirc.zd_full);
		if (count) {
			zone_depot_move_full(zd, &z->z_recirc, count, NULL);
			z->z_recirc_full_min -= count;
			z->z_recirc_full_wma -= count * Z_WMA_UNIT;
		}
	} else {
		*zd = z->z_recirc;
		if (zd->zd_full == 0) {
			zd->zd_tail = &zd->zd_head;
		}
		zone_depot_init(&z->z_recirc);
		z->z_recirc_empty_min = 0;
		z->z_recirc_empty_wma = 0;
		z->z_recirc_full_min = 0;
		z->z_recirc_full_wma = 0;
	}

	zone_recirc_unlock_nopreempt(z);
}

/*!
 * @function zone_reclaim
 *
 * @brief
 * Drains or trim the zone.
 *
 * @discussion
 * Draining the zone will free it from all its elements.
 *
 * Trimming the zone tries to respect the working set size, and avoids draining
 * the depot when it's not necessary.
 *
 * @param z             The zone to reclaim from
 * @param mode          The purpose of this reclaim.
 */
static void
zone_reclaim(zone_t z, zone_reclaim_mode_t mode)
{
	struct zone_depot zd;

	zone_depot_init(&zd);

	zone_lock(z);

	if (mode == ZONE_RECLAIM_DESTROY) {
		if (!z->z_destructible || z->z_elems_rsv) {
			panic("zdestroy: Zone %s%s isn't destructible",
			    zone_heap_name(z), z->z_name);
		}

		if (!z->z_self || z->z_expander ||
		    z->z_async_refilling || z->z_expanding_wait) {
			panic("zdestroy: Zone %s%s in an invalid state for destruction",
			    zone_heap_name(z), z->z_name);
		}

#if !KASAN_CLASSIC
		/*
		 * Unset the valid bit. We'll hit an assert failure on further
		 * operations on this zone, until zinit() is called again.
		 *
		 * Leave the zone valid for KASan as we will see zfree's on
		 * quarantined free elements even after the zone is destroyed.
		 */
		z->z_self = NULL;
#endif
		z->z_destroyed = true;
	} else if (z->z_destroyed) {
		return zone_unlock(z);
	} else if (zone_count_free(z) <= z->z_elems_rsv) {
		/* If the zone is under its reserve level, leave it alone. */
		return zone_unlock(z);
	}

	if (z->z_pcpu_cache) {
		zone_magazine_t mag;
		uint32_t freed = 0;

		/*
		 * This is all done with the zone lock held on purpose.
		 * The work here is O(ncpu), which should still be short.
		 *
		 * We need to keep the lock held until we have reclaimed
		 * at least a few magazines, otherwise if the zone has no
		 * free elements outside of the depot, a thread performing
		 * a concurrent allocatiuon could try to grow the zone
		 * while we're trying to drain it.
		 */
		zone_reclaim_recirc(z, mode, &zd);
		zone_reclaim_pcpu(z, mode, &zd);

		if (z->z_chunk_elems) {
			zone_cache_t cache = zpercpu_get_cpu(z->z_pcpu_cache, 0);
			smr_t smr = zone_cache_smr(cache);

			while (zd.zd_full) {
				mag = zone_depot_pop_head_full(&zd, NULL);
				if (smr) {
					smr_wait(smr, mag->zm_seq);
					zalloc_cached_reuse_smr(z, cache, mag);
					freed += zc_mag_size();
				}
				zone_reclaim_elements(z, zc_mag_size(),
				    mag->zm_elems);
				zone_depot_insert_head_empty(&zd, mag);

				freed += zc_mag_size();
				if (freed >= zc_free_batch_size()) {
					zone_unlock(z);
					zone_magazine_free_list(&zd);
					thread_yield_to_preemption();
					zone_lock(z);
					freed = 0;
				}
			}
		} else {
			zone_id_t zid = zone_index(z);

			zone_unlock(z);

			assert(zid <= ZONE_ID__FIRST_DYNAMIC && zcache_ops[zid]);

			while (zd.zd_full) {
				mag = zone_depot_pop_head_full(&zd, NULL);
				zcache_reclaim_elements(zid, zc_mag_size(),
				    mag->zm_elems);
				zone_magazine_free(mag);
			}

			goto cleanup;
		}
	}

	while (!zone_pva_is_null(z->z_pageq_empty)) {
		struct zone_page_metadata *meta;
		uint32_t count, limit = z->z_elems_rsv * 5 / 4;

		if (mode == ZONE_RECLAIM_TRIM && z->z_pcpu_cache == NULL) {
			limit = MAX(limit, z->z_elems_free -
			    MIN(z->z_elems_free_min, z->z_elems_free_wma));
		}

		meta  = zone_pva_to_meta(z->z_pageq_empty);
		count = (uint32_t)ptoa(meta->zm_chunk_len) / zone_elem_outer_size(z);

		if (zone_count_free(z) - count < limit) {
			break;
		}

		zone_reclaim_chunk(z, meta, count);
	}

	zone_unlock(z);

cleanup:
	zone_magazine_free_list(&zd);
}

void
zone_drain(zone_t zone)
{
	current_thread()->options |= TH_OPT_ZONE_PRIV;
	lck_mtx_lock(&zone_gc_lock);
	zone_reclaim(zone, ZONE_RECLAIM_DRAIN);
	lck_mtx_unlock(&zone_gc_lock);
	current_thread()->options &= ~TH_OPT_ZONE_PRIV;
}

void
zcache_drain(zone_id_t zid)
{
	zone_drain(zone_by_id(zid));
}

static void
zone_reclaim_all(zone_reclaim_mode_t mode)
{
	/*
	 * Start with zcaches, so that they flow into the regular zones.
	 *
	 * Then the zones with VA sequester since depopulating
	 * pages will not need to allocate vm map entries for holes,
	 * which will give memory back to the system faster.
	 */
	for (zone_id_t zid = ZONE_ID__LAST_RO + 1; zid < ZONE_ID__FIRST_DYNAMIC; zid++) {
		zone_t z = zone_by_id(zid);

		if (z->z_self && z->z_chunk_elems == 0) {
			zone_reclaim(z, mode);
		}
	}
	zone_index_foreach(zid) {
		zone_t z = zone_by_id(zid);

		if (z == zc_magazine_zone || z->z_chunk_elems == 0) {
			continue;
		}
		if (zone_submap_is_sequestered(zone_security_array[zid]) &&
		    z->collectable) {
			zone_reclaim(z, mode);
		}
	}

	zone_index_foreach(zid) {
		zone_t z = zone_by_id(zid);

		if (z == zc_magazine_zone || z->z_chunk_elems == 0) {
			continue;
		}
		if (!zone_submap_is_sequestered(zone_security_array[zid]) &&
		    z->collectable) {
			zone_reclaim(z, mode);
		}
	}

	zone_reclaim(zc_magazine_zone, mode);
}

void
zone_userspace_reboot_checks(void)
{
	vm_size_t label_zone_size = zone_size_allocated(ipc_service_port_label_zone);
	if (label_zone_size != 0) {
		panic("Zone %s should be empty upon userspace reboot. Actual size: %lu.",
		    ipc_service_port_label_zone->z_name, (unsigned long)label_zone_size);
	}
}

void
zone_gc(zone_gc_level_t level)
{
	zone_reclaim_mode_t mode;
	zone_t largest_zone = NULL;

	switch (level) {
	case ZONE_GC_TRIM:
		mode = ZONE_RECLAIM_TRIM;
		break;
	case ZONE_GC_DRAIN:
		mode = ZONE_RECLAIM_DRAIN;
		break;
	case ZONE_GC_JETSAM:
		largest_zone = kill_process_in_largest_zone();
		mode = ZONE_RECLAIM_TRIM;
		break;
	}

	current_thread()->options |= TH_OPT_ZONE_PRIV;
	lck_mtx_lock(&zone_gc_lock);

	zone_reclaim_all(mode);

	if (level == ZONE_GC_JETSAM && zone_map_nearing_exhaustion()) {
		/*
		 * If we possibly killed a process, but we're still critical,
		 * we need to drain harder.
		 */
		zone_reclaim(largest_zone, ZONE_RECLAIM_DRAIN);
		zone_reclaim_all(ZONE_RECLAIM_DRAIN);
	}

	lck_mtx_unlock(&zone_gc_lock);
	current_thread()->options &= ~TH_OPT_ZONE_PRIV;
}

void
zone_gc_trim(void)
{
	zone_gc(ZONE_GC_TRIM);
}

void
zone_gc_drain(void)
{
	zone_gc(ZONE_GC_DRAIN);
}

static bool
zone_trim_needed(zone_t z)
{
	if (z->z_depot_cleanup) {
		return true;
	}

	if (z->z_async_refilling) {
		/* Don't fight with refill */
		return false;
	}

	if (z->z_pcpu_cache) {
		uint32_t e_n, f_n;

		e_n = MIN(z->z_recirc_empty_wma, z->z_recirc_empty_min * Z_WMA_UNIT);
		f_n = MIN(z->z_recirc_full_wma, z->z_recirc_full_min * Z_WMA_UNIT);

		if (e_n > zc_autotrim_buckets() * Z_WMA_UNIT) {
			return true;
		}

		if (f_n * zc_mag_size() > z->z_elems_rsv * Z_WMA_UNIT &&
		    f_n * zc_mag_size() * zone_elem_inner_size(z) >
		    zc_autotrim_size() * Z_WMA_UNIT) {
			return true;
		}

		return false;
	}

	if (!zone_pva_is_null(z->z_pageq_empty)) {
		uint32_t n;

		n = MIN(z->z_elems_free_wma, z->z_elems_free_min);

		return n >= z->z_elems_rsv + z->z_chunk_elems;
	}

	return false;
}

static void
zone_trim_async(__unused thread_call_param_t p0, __unused thread_call_param_t p1)
{
	current_thread()->options |= TH_OPT_ZONE_PRIV;

	zone_foreach(z) {
		if (!z->collectable || z == zc_magazine_zone) {
			continue;
		}

		if (zone_trim_needed(z)) {
			lck_mtx_lock(&zone_gc_lock);
			zone_reclaim(z, ZONE_RECLAIM_TRIM);
			lck_mtx_unlock(&zone_gc_lock);
		}
	}

	if (zone_trim_needed(zc_magazine_zone)) {
		lck_mtx_lock(&zone_gc_lock);
		zone_reclaim(zc_magazine_zone, ZONE_RECLAIM_TRIM);
		lck_mtx_unlock(&zone_gc_lock);
	}

	current_thread()->options &= ~TH_OPT_ZONE_PRIV;
}

void
compute_zone_working_set_size(__unused void *param)
{
	uint32_t zc_auto = zc_enable_level();
	bool needs_trim = false;

	/*
	 * Keep zone caching disabled until the first proc is made.
	 */
	if (__improbable(zone_caching_disabled < 0)) {
		return;
	}

	zone_caching_disabled = vm_pool_low();

	if (os_mul_overflow(zc_auto, Z_WMA_UNIT, &zc_auto)) {
		zc_auto = 0;
	}

	zone_foreach(z) {
		uint32_t old, wma, cur;
		bool needs_caching = false;

		if (z->z_self != z) {
			continue;
		}

		zone_lock(z);

		zone_recirc_lock_nopreempt(z);

		if (z->z_pcpu_cache) {
			wma = Z_WMA_MIX(z->z_recirc_empty_wma, z->z_recirc_empty_min);
			z->z_recirc_empty_min = z->z_recirc.zd_empty;
			z->z_recirc_empty_wma = wma;
		} else {
			wma = Z_WMA_MIX(z->z_elems_free_wma, z->z_elems_free_min);
			z->z_elems_free_min = z->z_elems_free;
			z->z_elems_free_wma = wma;
		}

		wma = Z_WMA_MIX(z->z_recirc_full_wma, z->z_recirc_full_min);
		z->z_recirc_full_min = z->z_recirc.zd_full;
		z->z_recirc_full_wma = wma;

		/* fixed point decimal of contentions per second */
		old = z->z_recirc_cont_wma;
		cur = z->z_recirc_cont_cur * Z_WMA_UNIT /
		    (zpercpu_count() * ZONE_WSS_UPDATE_PERIOD);
		cur = (3 * old + cur) / 4;
		zone_recirc_unlock_nopreempt(z);

		if (z->z_pcpu_cache) {
			uint16_t size = z->z_depot_size;

			if (size < z->z_depot_limit && cur > zc_grow_level()) {
				/*
				 * lose history on purpose now
				 * that we just grew, to give
				 * the sytem time to adjust.
				 */
				cur  = (zc_grow_level() + zc_shrink_level()) / 2;
				size = size ? (3 * size + 2) / 2 : 2;
				z->z_depot_size = MIN(z->z_depot_limit, size);
			} else if (size > 0 && cur <= zc_shrink_level()) {
				/*
				 * lose history on purpose now
				 * that we just shrunk, to give
				 * the sytem time to adjust.
				 */
				cur = (zc_grow_level() + zc_shrink_level()) / 2;
				z->z_depot_size = size - 1;
				z->z_depot_cleanup = true;
			}
		} else if (!z->z_nocaching && !z->exhaustible && zc_auto &&
		    old >= zc_auto && cur >= zc_auto) {
			needs_caching = true;
		}

		z->z_recirc_cont_wma = cur;
		z->z_recirc_cont_cur = 0;

		if (!needs_trim && zone_trim_needed(z)) {
			needs_trim = true;
		}

		zone_unlock(z);

		if (needs_caching) {
			zone_enable_caching(z);
		}
	}

	if (needs_trim) {
		thread_call_enter(&zone_trim_callout);
	}
}

#endif /* !ZALLOC_TEST */
#pragma mark vm integration, MIG routines
#if !ZALLOC_TEST

extern unsigned int stack_total;
#if defined (__x86_64__)
extern unsigned int inuse_ptepages_count;
#endif

static const char *
panic_print_get_typename(kalloc_type_views_t cur, kalloc_type_views_t *next,
    bool is_kt_var)
{
	if (is_kt_var) {
		next->ktv_var = (kalloc_type_var_view_t) cur.ktv_var->kt_next;
		return cur.ktv_var->kt_name;
	} else {
		next->ktv_fixed = (kalloc_type_view_t) cur.ktv_fixed->kt_zv.zv_next;
		return cur.ktv_fixed->kt_zv.zv_name;
	}
}

static void
panic_print_types_in_zone(zone_t z, const char* debug_str)
{
	kalloc_type_views_t kt_cur = {};
	const char *prev_type = "";
	size_t skip_over_site = sizeof("site.") - 1;
	zone_security_flags_t zsflags = zone_security_config(z);
	bool is_kt_var = false;

	if (zsflags.z_kheap_id == KHEAP_ID_KT_VAR) {
		uint32_t heap_id = KT_VAR_PTR_HEAP + ((zone_index(z) -
		    kalloc_type_heap_array[KT_VAR_PTR_HEAP].kh_zstart) / KHEAP_NUM_ZONES);
		kt_cur.ktv_var = kalloc_type_heap_array[heap_id].kt_views;
		is_kt_var = true;
	} else {
		kt_cur.ktv_fixed = (kalloc_type_view_t) z->z_views;
	}

	paniclog_append_noflush("kalloc %s in zone, %s (%s):\n",
	    is_kt_var? "type arrays" : "types", debug_str, z->z_name);

	while (kt_cur.ktv_fixed) {
		kalloc_type_views_t kt_next = {};
		const char *typename = panic_print_get_typename(kt_cur, &kt_next,
		    is_kt_var) + skip_over_site;
		if (strcmp(typename, prev_type) != 0) {
			paniclog_append_noflush("\t%-50s\n", typename);
			prev_type = typename;
		}
		kt_cur = kt_next;
	}
	paniclog_append_noflush("\n");
}

static void
panic_display_kalloc_types(void)
{
	if (kalloc_type_src_zone) {
		panic_print_types_in_zone(kalloc_type_src_zone, "addr belongs to");
	}
	if (kalloc_type_dst_zone) {
		panic_print_types_in_zone(kalloc_type_dst_zone,
		    "addr is being freed to");
	}
}

static void
zone_find_n_largest(const uint32_t n, zone_t *largest_zones,
    uint64_t *zone_size)
{
	zone_index_foreach(zid) {
		zone_t z = &zone_array[zid];
		vm_offset_t size = zone_size_wired(z);

		if (zid == ZONE_ID_VM_PAGES) {
			continue;
		}
		for (uint32_t i = 0; i < n; i++) {
			if (size > zone_size[i]) {
				largest_zones[i] = z;
				zone_size[i] = size;
				break;
			}
		}
	}
}

#define NUM_LARGEST_ZONES 5
static void
panic_display_largest_zones(void)
{
	zone_t largest_zones[NUM_LARGEST_ZONES]  = { NULL };
	uint64_t largest_size[NUM_LARGEST_ZONES] = { 0 };

	zone_find_n_largest(NUM_LARGEST_ZONES, (zone_t *) &largest_zones,
	    (uint64_t *) &largest_size);

	paniclog_append_noflush("Largest zones:\n%-28s %10s %10s\n",
	    "Zone Name", "Cur Size", "Free Size");
	for (uint32_t i = 0; i < NUM_LARGEST_ZONES; i++) {
		zone_t z = largest_zones[i];
		paniclog_append_noflush("%-8s%-20s %9u%c %9u%c\n",
		    zone_heap_name(z), z->z_name,
		    mach_vm_size_pretty(largest_size[i]),
		    mach_vm_size_unit(largest_size[i]),
		    mach_vm_size_pretty(zone_size_free(z)),
		    mach_vm_size_unit(zone_size_free(z)));
	}
}

static void
panic_display_zprint(void)
{
	panic_display_largest_zones();
	paniclog_append_noflush("%-20s %10lu\n", "Kernel Stacks",
	    (uintptr_t)(kernel_stack_size * stack_total));
#if defined (__x86_64__)
	paniclog_append_noflush("%-20s %10lu\n", "PageTables",
	    (uintptr_t)ptoa(inuse_ptepages_count));
#endif
	paniclog_append_noflush("%-20s %10lu\n", "Kalloc.Large",
	    (uintptr_t)kalloc_large_total);

	if (panic_kext_memory_info) {
		mach_memory_info_t *mem_info = panic_kext_memory_info;

		paniclog_append_noflush("\n%-5s %10s\n", "Kmod", "Size");
		for (uint32_t i = 0; i < panic_kext_memory_size / sizeof(mem_info[0]); i++) {
			if ((mem_info[i].flags & VM_KERN_SITE_TYPE) != VM_KERN_SITE_KMOD) {
				continue;
			}
			if (mem_info[i].size > (1024 * 1024)) {
				paniclog_append_noflush("%-5lld %10lld\n",
				    mem_info[i].site, mem_info[i].size);
			}
		}
	}
}

static void
panic_display_zone_info(void)
{
	paniclog_append_noflush("Zone info:\n");
	paniclog_append_noflush("  Zone map: %p - %p\n",
	    (void *)zone_info.zi_map_range.min_address,
	    (void *)zone_info.zi_map_range.max_address);
#if CONFIG_PROB_GZALLOC
	if (pgz_submap) {
		paniclog_append_noflush("  . PGZ   : %p - %p\n",
		    (void *)pgz_submap->min_offset,
		    (void *)pgz_submap->max_offset);
	}
#endif /* CONFIG_PROB_GZALLOC */
	for (int i = 0; i < Z_SUBMAP_IDX_COUNT; i++) {
		vm_map_t map = zone_submaps[i];

		if (map == VM_MAP_NULL) {
			continue;
		}
		paniclog_append_noflush("  . %-6s: %p - %p\n",
		    zone_submaps_names[i],
		    (void *)map->min_offset,
		    (void *)map->max_offset);
	}
	paniclog_append_noflush("  Metadata: %p - %p\n"
	    "  Bitmaps : %p - %p\n"
	    "  Extra   : %p - %p\n"
	    "\n",
	    (void *)zone_info.zi_meta_range.min_address,
	    (void *)zone_info.zi_meta_range.max_address,
	    (void *)zone_info.zi_bits_range.min_address,
	    (void *)zone_info.zi_bits_range.max_address,
	    (void *)zone_info.zi_xtra_range.min_address,
	    (void *)zone_info.zi_xtra_range.max_address);
}

static void
panic_display_zone_fault(vm_offset_t addr)
{
	struct zone_page_metadata meta = { };
	vm_map_t map = VM_MAP_NULL;
	vm_offset_t oob_offs = 0, size = 0;
	int map_idx = -1;
	zone_t z = NULL;
	const char *kind = "whild deref";
	bool oob = false;

	/*
	 * First: look if we bumped into guard pages between submaps
	 */
	for (int i = 0; i < Z_SUBMAP_IDX_COUNT; i++) {
		map = zone_submaps[i];
		if (map == VM_MAP_NULL) {
			continue;
		}

		if (addr >= map->min_offset && addr < map->max_offset) {
			map_idx = i;
			break;
		}
	}

	if (map_idx == -1) {
		/* this really shouldn't happen, submaps are back to back */
		return;
	}

	paniclog_append_noflush("Probabilistic GZAlloc Report:\n");

	/*
	 * Second: look if there's just no metadata at all
	 */
	if (ml_nofault_copy((vm_offset_t)zone_meta_from_addr(addr),
	    (vm_offset_t)&meta, sizeof(meta)) != sizeof(meta) ||
	    meta.zm_index == 0 || meta.zm_index >= MAX_ZONES ||
	    zone_array[meta.zm_index].z_self == NULL) {
		paniclog_append_noflush("  Zone    : <unknown>\n");
		kind = "wild deref, missing or invalid metadata";
	} else {
		z = &zone_array[meta.zm_index];
		paniclog_append_noflush("  Zone    : %s%s\n",
		    zone_heap_name(z), zone_name(z));
		if (meta.zm_chunk_len == ZM_PGZ_GUARD) {
			kind = "out-of-bounds (high confidence)";
			oob = true;
			size = zone_element_size((void *)addr,
			    &z, false, &oob_offs);
		} else {
			kind = "use-after-free (medium confidence)";
		}
	}

	paniclog_append_noflush("  Address : %p\n", (void *)addr);
	if (oob) {
		paniclog_append_noflush("  Element : [%p, %p) of size %d\n",
		    (void *)(trunc_page(addr) - (size - oob_offs)),
		    (void *)trunc_page(addr), (uint32_t)(size - oob_offs));
	}
	paniclog_append_noflush("  Submap  : %s [%p; %p)\n",
	    zone_submaps_names[map_idx],
	    (void *)map->min_offset, (void *)map->max_offset);
	paniclog_append_noflush("  Kind    : %s\n", kind);
	if (oob) {
		paniclog_append_noflush("  Access  : %d byte(s) past\n",
		    (uint32_t)(addr & PAGE_MASK) + 1);
	}
	paniclog_append_noflush("  Metadata: zid:%d inl:%d cl:0x%x "
	    "0x%04x 0x%08x 0x%08x 0x%08x\n",
	    meta.zm_index, meta.zm_inline_bitmap, meta.zm_chunk_len,
	    meta.zm_alloc_size, meta.zm_bitmap,
	    meta.zm_page_next.packed_address,
	    meta.zm_page_prev.packed_address);
	paniclog_append_noflush("\n");
}

void
panic_display_zalloc(void)
{
	bool keepsyms = false;

	PE_parse_boot_argn("keepsyms", &keepsyms, sizeof(keepsyms));

	panic_display_zone_info();

	if (panic_fault_address) {
#if CONFIG_PROB_GZALLOC
		if (pgz_owned(panic_fault_address)) {
			panic_display_pgz_uaf_info(keepsyms, panic_fault_address);
		} else
#endif /* CONFIG_PROB_GZALLOC */
		if (zone_maps_owned(panic_fault_address, 1)) {
			panic_display_zone_fault(panic_fault_address);
		}
	}

	if (panic_include_zprint) {
		panic_display_zprint();
	} else if (zone_map_nearing_threshold(ZONE_MAP_EXHAUSTION_PRINT_PANIC)) {
		panic_display_largest_zones();
	}
#if CONFIG_ZLEAKS
	if (zleak_active) {
		panic_display_zleaks(keepsyms);
	}
#endif
	if (panic_include_kalloc_types) {
		panic_display_kalloc_types();
	}
}

/*
 * Creates a vm_map_copy_t to return to the caller of mach_* MIG calls
 * requesting zone information.
 * Frees unused pages towards the end of the region, and zero'es out unused
 * space on the last page.
 */
static vm_map_copy_t
create_vm_map_copy(
	vm_offset_t             start_addr,
	vm_size_t               total_size,
	vm_size_t               used_size)
{
	kern_return_t   kr;
	vm_offset_t             end_addr;
	vm_size_t               free_size;
	vm_map_copy_t   copy;

	if (used_size != total_size) {
		end_addr = start_addr + used_size;
		free_size = total_size - (round_page(end_addr) - start_addr);

		if (free_size >= PAGE_SIZE) {
			kmem_free(ipc_kernel_map,
			    round_page(end_addr), free_size);
		}
		bzero((char *) end_addr, round_page(end_addr) - end_addr);
	}

	kr = vm_map_copyin(ipc_kernel_map, (vm_map_address_t)start_addr,
	    (vm_map_size_t)used_size, TRUE, &copy);
	assert(kr == KERN_SUCCESS);

	return copy;
}

static boolean_t
get_zone_info(
	zone_t                   z,
	mach_zone_name_t        *zn,
	mach_zone_info_t        *zi)
{
	struct zone zcopy;
	vm_size_t cached = 0;

	assert(z != ZONE_NULL);
	zone_lock(z);
	if (!z->z_self) {
		zone_unlock(z);
		return FALSE;
	}
	zcopy = *z;
	if (z->z_pcpu_cache) {
		zpercpu_foreach(zc, z->z_pcpu_cache) {
			cached += zc->zc_alloc_cur + zc->zc_free_cur;
			cached += zc->zc_depot.zd_full * zc_mag_size();
		}
	}
	zone_unlock(z);

	if (zn != NULL) {
		/*
		 * Append kalloc heap name to zone name (if zone is used by kalloc)
		 */
		char temp_zone_name[MAX_ZONE_NAME] = "";
		snprintf(temp_zone_name, MAX_ZONE_NAME, "%s%s",
		    zone_heap_name(z), z->z_name);

		/* assuming here the name data is static */
		(void) __nosan_strlcpy(zn->mzn_name, temp_zone_name,
		    strlen(temp_zone_name) + 1);
	}

	if (zi != NULL) {
		*zi = (mach_zone_info_t) {
			.mzi_count = zone_count_allocated(&zcopy) - cached,
			.mzi_cur_size = ptoa_64(zone_scale_for_percpu(&zcopy, zcopy.z_wired_cur)),
			// max_size for zprint is now high-watermark of pages used
			.mzi_max_size = ptoa_64(zone_scale_for_percpu(&zcopy, zcopy.z_wired_hwm)),
			.mzi_elem_size = zone_scale_for_percpu(&zcopy, zcopy.z_elem_size),
			.mzi_alloc_size = ptoa_64(zcopy.z_chunk_pages),
			.mzi_exhaustible = (uint64_t)zcopy.exhaustible,
		};
		if (zcopy.z_chunk_pages == 0) {
			/* this is a zcache */
			zi->mzi_cur_size = zcopy.z_elems_avail * zcopy.z_elem_size;
		}
		zpercpu_foreach(zs, zcopy.z_stats) {
			zi->mzi_sum_size += zs->zs_mem_allocated;
		}
		if (zcopy.collectable) {
			SET_MZI_COLLECTABLE_BYTES(zi->mzi_collectable,
			    ptoa_64(zone_scale_for_percpu(&zcopy, zcopy.z_wired_empty)));
			SET_MZI_COLLECTABLE_FLAG(zi->mzi_collectable, TRUE);
		}
	}

	return TRUE;
}

/* mach_memory_info entitlement */
#define MEMORYINFO_ENTITLEMENT "com.apple.private.memoryinfo"

/* macro needed to rate-limit mach_memory_info */
#define NSEC_DAY (NSEC_PER_SEC * 60 * 60 * 24)

/* declarations necessary to call kauth_cred_issuser() */
struct ucred;
extern int kauth_cred_issuser(struct ucred *);
extern struct ucred *kauth_cred_get(void);

static kern_return_t
mach_memory_info_internal(
	host_t                  host,
	mach_zone_name_array_t  *namesp,
	mach_msg_type_number_t  *namesCntp,
	mach_zone_info_array_t  *infop,
	mach_msg_type_number_t  *infoCntp,
	mach_memory_info_array_t *memoryInfop,
	mach_msg_type_number_t   *memoryInfoCntp,
	bool                     redact_info);

static kern_return_t
mach_memory_info_security_check(bool redact_info)
{
	/* If not root, only allow redacted calls. */
	if (!kauth_cred_issuser(kauth_cred_get()) && !redact_info) {
		return KERN_NO_ACCESS;
	}

	if (PE_srd_fused) {
		return KERN_SUCCESS;
	}

	/* If does not have the memory entitlement, fail. */
#if CONFIG_DEBUGGER_FOR_ZONE_INFO
	if (!IOTaskHasEntitlement(current_task(), MEMORYINFO_ENTITLEMENT)) {
		return KERN_DENIED;
	}

	/*
	 * On release non-mac arm devices, allow mach_memory_info
	 * to be called twice per day per boot. memorymaintenanced
	 * calls it once per day, which leaves room for a sysdiagnose.
	 * Allow redacted version to be called without rate limit.
	 */

	if (!redact_info) {
		static uint64_t first_call = 0, second_call = 0;
		uint64_t now = 0;
		absolutetime_to_nanoseconds(ml_get_timebase(), &now);

		if (!first_call) {
			first_call = now;
		} else if (!second_call) {
			second_call = now;
		} else if (first_call + NSEC_DAY > now) {
			return KERN_DENIED;
		} else if (first_call + NSEC_DAY < now) {
			first_call = now;
			second_call = 0;
		}
	}
#endif

	return KERN_SUCCESS;
}

kern_return_t
mach_zone_info(
	mach_port_t             host_port,
	mach_zone_name_array_t  *namesp,
	mach_msg_type_number_t  *namesCntp,
	mach_zone_info_array_t  *infop,
	mach_msg_type_number_t  *infoCntp)
{
	return mach_memory_info(host_port, namesp, namesCntp, infop, infoCntp, NULL, NULL);
}

kern_return_t
mach_memory_info(
	mach_port_t             host_port,
	mach_zone_name_array_t  *namesp,
	mach_msg_type_number_t  *namesCntp,
	mach_zone_info_array_t  *infop,
	mach_msg_type_number_t  *infoCntp,
	mach_memory_info_array_t *memoryInfop,
	mach_msg_type_number_t   *memoryInfoCntp)
{
	bool redact_info = false;
	host_t host = HOST_NULL;

	host = convert_port_to_host_priv(host_port);
	if (host == HOST_NULL) {
		redact_info = true;
		host = convert_port_to_host(host_port);
	}

	return mach_memory_info_internal(host, namesp, namesCntp, infop, infoCntp, memoryInfop, memoryInfoCntp, redact_info);
}

static void
zone_info_redact(mach_zone_info_t *zi)
{
	zi->mzi_cur_size = 0;
	zi->mzi_max_size = 0;
	zi->mzi_alloc_size = 0;
	zi->mzi_sum_size = 0;
	zi->mzi_collectable = 0;
}

static bool
zone_info_needs_to_be_coalesced(int zone_index)
{
	zone_security_flags_t zsflags = zone_security_array[zone_index];
	if (zsflags.z_kalloc_type || zsflags.z_kheap_id == KHEAP_ID_DEFAULT ||
	    zsflags.z_kheap_id == KHEAP_ID_KT_VAR) {
		return true;
	}
	return false;
}

static bool
zone_info_find_coalesce_zone(
	mach_zone_info_t *zi,
	mach_zone_info_t *info,
	int              *coalesce,
	int              coalesce_count,
	int              *coalesce_index)
{
	for (int i = 0; i < coalesce_count; i++) {
		if (zi->mzi_elem_size == info[coalesce[i]].mzi_elem_size) {
			*coalesce_index = coalesce[i];
			return true;
		}
	}

	return false;
}

static void
zone_info_coalesce(
	mach_zone_info_t *info,
	int coalesce_index,
	mach_zone_info_t *zi)
{
	info[coalesce_index].mzi_count += zi->mzi_count;
}

static kern_return_t
mach_memory_info_internal(
	host_t                  host,
	mach_zone_name_array_t  *namesp,
	mach_msg_type_number_t  *namesCntp,
	mach_zone_info_array_t  *infop,
	mach_msg_type_number_t  *infoCntp,
	mach_memory_info_array_t *memoryInfop,
	mach_msg_type_number_t   *memoryInfoCntp,
	bool                     redact_info)
{
	mach_zone_name_t        *names;
	vm_offset_t             names_addr;
	vm_size_t               names_size;

	mach_zone_info_t        *info;
	vm_offset_t             info_addr;
	vm_size_t               info_size;

	int                     *coalesce;
	vm_offset_t             coalesce_addr;
	vm_size_t               coalesce_size;
	int                     coalesce_count = 0;

	mach_memory_info_t      *memory_info;
	vm_offset_t             memory_info_addr;
	vm_size_t               memory_info_size;
	vm_size_t               memory_info_vmsize;
	unsigned int            num_info;

	unsigned int            max_zones, used_zones, i;
	mach_zone_name_t        *zn;
	mach_zone_info_t        *zi;
	kern_return_t           kr;

	uint64_t                zones_collectable_bytes = 0;

	if (host == HOST_NULL) {
		return KERN_INVALID_HOST;
	}

	kr = mach_memory_info_security_check(redact_info);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	/*
	 *	We assume that zones aren't freed once allocated.
	 *	We won't pick up any zones that are allocated later.
	 */

	max_zones = os_atomic_load(&num_zones, relaxed);

	names_size = round_page(max_zones * sizeof *names);
	kr = kmem_alloc(ipc_kernel_map, &names_addr, names_size,
	    KMA_PAGEABLE | KMA_DATA, VM_KERN_MEMORY_IPC);
	if (kr != KERN_SUCCESS) {
		return kr;
	}
	names = (mach_zone_name_t *) names_addr;

	info_size = round_page(max_zones * sizeof *info);
	kr = kmem_alloc(ipc_kernel_map, &info_addr, info_size,
	    KMA_PAGEABLE | KMA_DATA, VM_KERN_MEMORY_IPC);
	if (kr != KERN_SUCCESS) {
		kmem_free(ipc_kernel_map,
		    names_addr, names_size);
		return kr;
	}
	info = (mach_zone_info_t *) info_addr;

	if (redact_info) {
		coalesce_size = round_page(max_zones * sizeof *coalesce);
		kr = kmem_alloc(ipc_kernel_map, &coalesce_addr, coalesce_size,
		    KMA_PAGEABLE | KMA_DATA, VM_KERN_MEMORY_IPC);
		if (kr != KERN_SUCCESS) {
			kmem_free(ipc_kernel_map,
			    names_addr, names_size);
			kmem_free(ipc_kernel_map,
			    info_addr, info_size);
			return kr;
		}
		coalesce = (int *)coalesce_addr;
	}

	zn = &names[0];
	zi = &info[0];

	used_zones = 0;
	for (i = 0; i < max_zones; i++) {
		if (!get_zone_info(&(zone_array[i]), zn, zi)) {
			continue;
		}

		if (!redact_info) {
			zones_collectable_bytes += GET_MZI_COLLECTABLE_BYTES(zi->mzi_collectable);
			zn++;
			zi++;
			used_zones++;
			continue;
		}

		zone_info_redact(zi);
		if (!zone_info_needs_to_be_coalesced(i)) {
			zn++;
			zi++;
			used_zones++;
			continue;
		}

		int coalesce_index;
		bool found_coalesce_zone = zone_info_find_coalesce_zone(zi, info,
		    coalesce, coalesce_count, &coalesce_index);

		/* Didn't find a zone to coalesce */
		if (!found_coalesce_zone) {
			/* Updates the zone name */
			__nosan_bzero(zn->mzn_name, MAX_ZONE_NAME);
			snprintf(zn->mzn_name, MAX_ZONE_NAME, "kalloc.%d",
			    (int)zi->mzi_elem_size);

			coalesce[coalesce_count] = used_zones;
			coalesce_count++;
			zn++;
			zi++;
			used_zones++;
			continue;
		}

		zone_info_coalesce(info, coalesce_index, zi);
	}

	if (redact_info) {
		kmem_free(ipc_kernel_map, coalesce_addr, coalesce_size);
	}

	*namesp = (mach_zone_name_t *) create_vm_map_copy(names_addr, names_size, used_zones * sizeof *names);
	*namesCntp = used_zones;

	*infop = (mach_zone_info_t *) create_vm_map_copy(info_addr, info_size, used_zones * sizeof *info);
	*infoCntp = used_zones;

	num_info = 0;
	memory_info_addr = 0;

	if (memoryInfop && memoryInfoCntp) {
		vm_map_copy_t           copy;
		num_info = vm_page_diagnose_estimate();
		memory_info_size = num_info * sizeof(*memory_info);
		memory_info_vmsize = round_page(memory_info_size);
		kr = kmem_alloc(ipc_kernel_map, &memory_info_addr, memory_info_vmsize,
		    KMA_PAGEABLE | KMA_DATA, VM_KERN_MEMORY_IPC);
		if (kr != KERN_SUCCESS) {
			return kr;
		}

		kr = vm_map_wire_kernel(ipc_kernel_map, memory_info_addr, memory_info_addr + memory_info_vmsize,
		    VM_PROT_READ | VM_PROT_WRITE, VM_KERN_MEMORY_IPC, FALSE);
		assert(kr == KERN_SUCCESS);

		memory_info = (mach_memory_info_t *) memory_info_addr;
		vm_page_diagnose(memory_info, num_info, zones_collectable_bytes, redact_info);

		kr = vm_map_unwire(ipc_kernel_map, memory_info_addr, memory_info_addr + memory_info_vmsize, FALSE);
		assert(kr == KERN_SUCCESS);

		kr = vm_map_copyin(ipc_kernel_map, (vm_map_address_t)memory_info_addr,
		    (vm_map_size_t)memory_info_size, TRUE, &copy);
		assert(kr == KERN_SUCCESS);

		*memoryInfop = (mach_memory_info_t *) copy;
		*memoryInfoCntp = num_info;
	}

	return KERN_SUCCESS;
}

kern_return_t
mach_zone_info_for_zone(
	host_priv_t                     host,
	mach_zone_name_t        name,
	mach_zone_info_t        *infop)
{
	zone_t zone_ptr;

	if (host == HOST_NULL) {
		return KERN_INVALID_HOST;
	}

#if CONFIG_DEBUGGER_FOR_ZONE_INFO
	if (!PE_i_can_has_debugger(NULL)) {
		return KERN_INVALID_HOST;
	}
#endif

	if (infop == NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	zone_ptr = ZONE_NULL;
	zone_foreach(z) {
		/*
		 * Append kalloc heap name to zone name (if zone is used by kalloc)
		 */
		char temp_zone_name[MAX_ZONE_NAME] = "";
		snprintf(temp_zone_name, MAX_ZONE_NAME, "%s%s",
		    zone_heap_name(z), z->z_name);

		/* Find the requested zone by name */
		if (track_this_zone(temp_zone_name, name.mzn_name)) {
			zone_ptr = z;
			break;
		}
	}

	/* No zones found with the requested zone name */
	if (zone_ptr == ZONE_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if (get_zone_info(zone_ptr, NULL, infop)) {
		return KERN_SUCCESS;
	}
	return KERN_FAILURE;
}

kern_return_t
mach_zone_info_for_largest_zone(
	host_priv_t                     host,
	mach_zone_name_t        *namep,
	mach_zone_info_t        *infop)
{
	if (host == HOST_NULL) {
		return KERN_INVALID_HOST;
	}

#if CONFIG_DEBUGGER_FOR_ZONE_INFO
	if (!PE_i_can_has_debugger(NULL)) {
		return KERN_INVALID_HOST;
	}
#endif

	if (namep == NULL || infop == NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if (get_zone_info(zone_find_largest(NULL), namep, infop)) {
		return KERN_SUCCESS;
	}
	return KERN_FAILURE;
}

uint64_t
get_zones_collectable_bytes(void)
{
	uint64_t zones_collectable_bytes = 0;
	mach_zone_info_t zi;

	zone_foreach(z) {
		if (get_zone_info(z, NULL, &zi)) {
			zones_collectable_bytes +=
			    GET_MZI_COLLECTABLE_BYTES(zi.mzi_collectable);
		}
	}

	return zones_collectable_bytes;
}

kern_return_t
mach_zone_get_zlog_zones(
	host_priv_t                             host,
	mach_zone_name_array_t  *namesp,
	mach_msg_type_number_t  *namesCntp)
{
#if ZALLOC_ENABLE_LOGGING
	unsigned int max_zones, logged_zones, i;
	kern_return_t kr;
	zone_t zone_ptr;
	mach_zone_name_t *names;
	vm_offset_t names_addr;
	vm_size_t names_size;

	if (host == HOST_NULL) {
		return KERN_INVALID_HOST;
	}

	if (namesp == NULL || namesCntp == NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	max_zones = os_atomic_load(&num_zones, relaxed);

	names_size = round_page(max_zones * sizeof *names);
	kr = kmem_alloc(ipc_kernel_map, &names_addr, names_size,
	    KMA_PAGEABLE | KMA_DATA, VM_KERN_MEMORY_IPC);
	if (kr != KERN_SUCCESS) {
		return kr;
	}
	names = (mach_zone_name_t *) names_addr;

	zone_ptr = ZONE_NULL;
	logged_zones = 0;
	for (i = 0; i < max_zones; i++) {
		zone_t z = &(zone_array[i]);
		assert(z != ZONE_NULL);

		/* Copy out the zone name if zone logging is enabled */
		if (z->z_btlog) {
			get_zone_info(z, &names[logged_zones], NULL);
			logged_zones++;
		}
	}

	*namesp = (mach_zone_name_t *) create_vm_map_copy(names_addr, names_size, logged_zones * sizeof *names);
	*namesCntp = logged_zones;

	return KERN_SUCCESS;

#else /* ZALLOC_ENABLE_LOGGING */
#pragma unused(host, namesp, namesCntp)
	return KERN_FAILURE;
#endif /* ZALLOC_ENABLE_LOGGING */
}

kern_return_t
mach_zone_get_btlog_records(
	host_priv_t             host,
	mach_zone_name_t        name,
	zone_btrecord_array_t  *recsp,
	mach_msg_type_number_t *numrecs)
{
#if ZALLOC_ENABLE_LOGGING
	zone_btrecord_t *recs;
	kern_return_t    kr;
	vm_address_t     addr;
	vm_size_t        size;
	zone_t           zone_ptr;
	vm_map_copy_t    copy;

	if (host == HOST_NULL) {
		return KERN_INVALID_HOST;
	}

	if (recsp == NULL || numrecs == NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	zone_ptr = ZONE_NULL;
	zone_foreach(z) {
		/*
		 * Append kalloc heap name to zone name (if zone is used by kalloc)
		 */
		char temp_zone_name[MAX_ZONE_NAME] = "";
		snprintf(temp_zone_name, MAX_ZONE_NAME, "%s%s",
		    zone_heap_name(z), z->z_name);

		/* Find the requested zone by name */
		if (track_this_zone(temp_zone_name, name.mzn_name)) {
			zone_ptr = z;
			break;
		}
	}

	/* No zones found with the requested zone name */
	if (zone_ptr == ZONE_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	/* Logging not turned on for the requested zone */
	if (!zone_ptr->z_btlog) {
		return KERN_FAILURE;
	}

	kr = btlog_get_records(zone_ptr->z_btlog, &recs, numrecs);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	addr = (vm_address_t)recs;
	size = sizeof(zone_btrecord_t) * *numrecs;

	kr = vm_map_copyin(ipc_kernel_map, addr, size, TRUE, &copy);
	assert(kr == KERN_SUCCESS);

	*recsp = (zone_btrecord_t *)copy;
	return KERN_SUCCESS;

#else /* !ZALLOC_ENABLE_LOGGING */
#pragma unused(host, name, recsp, numrecs)
	return KERN_FAILURE;
#endif /* !ZALLOC_ENABLE_LOGGING */
}


kern_return_t
mach_zone_force_gc(
	host_t host)
{
	if (host == HOST_NULL) {
		return KERN_INVALID_HOST;
	}

#if DEBUG || DEVELOPMENT
	extern boolean_t(*volatile consider_buffer_cache_collect)(int);
	/* Callout to buffer cache GC to drop elements in the apfs zones */
	if (consider_buffer_cache_collect != NULL) {
		(void)(*consider_buffer_cache_collect)(0);
	}
	zone_gc(ZONE_GC_DRAIN);
#endif /* DEBUG || DEVELOPMENT */
	return KERN_SUCCESS;
}

zone_t
zone_find_largest(uint64_t *zone_size)
{
	zone_t    largest_zone  = 0;
	uint64_t  largest_zone_size = 0;
	zone_find_n_largest(1, &largest_zone, &largest_zone_size);
	if (zone_size) {
		*zone_size = largest_zone_size;
	}
	return largest_zone;
}

void
zone_get_stats(
	zone_t                  zone,
	struct zone_basic_stats *stats)
{
	stats->zbs_avail = zone->z_elems_avail;

	stats->zbs_alloc_fail = 0;
	zpercpu_foreach(zs, zone->z_stats) {
		stats->zbs_alloc_fail += zs->zs_alloc_fail;
	}

	stats->zbs_cached = 0;
	if (zone->z_pcpu_cache) {
		zpercpu_foreach(zc, zone->z_pcpu_cache) {
			stats->zbs_cached += zc->zc_alloc_cur +
			    zc->zc_free_cur +
			    zc->zc_depot.zd_full * zc_mag_size();
		}
	}

	stats->zbs_free = zone_count_free(zone) + stats->zbs_cached;

	/*
	 * Since we don't take any locks, deal with possible inconsistencies
	 * as the counters may have changed.
	 */
	if (os_sub_overflow(stats->zbs_avail, stats->zbs_free,
	    &stats->zbs_alloc)) {
		stats->zbs_avail = stats->zbs_free;
		stats->zbs_alloc = 0;
	}
}

#endif /* !ZALLOC_TEST */
#pragma mark zone creation, configuration, destruction
#if !ZALLOC_TEST

static zone_t
zone_init_defaults(zone_id_t zid)
{
	zone_t z = &zone_array[zid];

	z->z_wired_max = ~0u;
	z->collectable = true;

	hw_lck_ticket_init(&z->z_lock, &zone_locks_grp);
	hw_lck_ticket_init(&z->z_recirc_lock, &zone_locks_grp);
	zone_depot_init(&z->z_recirc);
	return z;
}

void
zone_set_exhaustible(zone_t zone, vm_size_t nelems)
{
	zone_lock(zone);
	zone->exhaustible = true;
	zone->z_wired_max = zone_alloc_pages_for_nelems(zone, nelems);
	zone_unlock(zone);
}

void
zone_raise_reserve(union zone_or_view zov, uint16_t min_elements)
{
	zone_t zone = zov.zov_zone;

	if (zone < zone_array || zone > &zone_array[MAX_ZONES]) {
		zone = zov.zov_view->zv_zone;
	} else {
		zone = zov.zov_zone;
	}

	os_atomic_max(&zone->z_elems_rsv, min_elements, relaxed);
}

/**
 * @function zone_create_find
 *
 * @abstract
 * Finds an unused zone for the given name and element size.
 *
 * @param name          the zone name
 * @param size          the element size (including redzones, ...)
 * @param flags         the flags passed to @c zone_create*
 * @param zid_inout     the desired zone ID or ZONE_ID_ANY
 *
 * @returns             a zone to initialize further.
 */
static zone_t
zone_create_find(
	const char             *name,
	vm_size_t               size,
	zone_create_flags_t     flags,
	zone_id_t              *zid_inout)
{
	zone_id_t nzones, zid = *zid_inout;
	zone_t z;

	simple_lock(&all_zones_lock, &zone_locks_grp);

	nzones = (zone_id_t)os_atomic_load(&num_zones, relaxed);
	assert(num_zones_in_use <= nzones && nzones < MAX_ZONES);

	if (__improbable(nzones < ZONE_ID__FIRST_DYNAMIC)) {
		/*
		 * The first time around, make sure the reserved zone IDs
		 * have an initialized lock as zone_index_foreach() will
		 * enumerate them.
		 */
		while (nzones < ZONE_ID__FIRST_DYNAMIC) {
			zone_init_defaults(nzones++);
		}

		os_atomic_store(&num_zones, nzones, release);
	}

	if (zid != ZONE_ID_ANY) {
		if (zid >= ZONE_ID__FIRST_DYNAMIC) {
			panic("zone_create: invalid desired zone ID %d for %s",
			    zid, name);
		}
		if (flags & ZC_DESTRUCTIBLE) {
			panic("zone_create: ID %d (%s) must be permanent", zid, name);
		}
		if (zone_array[zid].z_self) {
			panic("zone_create: creating zone ID %d (%s) twice", zid, name);
		}
		z = &zone_array[zid];
	} else {
		if (flags & ZC_DESTRUCTIBLE) {
			/*
			 * If possible, find a previously zdestroy'ed zone in the
			 * zone_array that we can reuse.
			 */
			for (int i = bitmap_first(zone_destroyed_bitmap, MAX_ZONES);
			    i >= 0; i = bitmap_next(zone_destroyed_bitmap, i)) {
				z = &zone_array[i];

				/*
				 * If the zone name and the element size are the
				 * same, we can just reuse the old zone struct.
				 */
				if (strcmp(z->z_name, name) ||
				    zone_elem_outer_size(z) != size) {
					continue;
				}
				bitmap_clear(zone_destroyed_bitmap, i);
				z->z_destroyed = false;
				z->z_self = z;
				zid = (zone_id_t)i;
				goto out;
			}
		}

		zid = nzones++;
		z = zone_init_defaults(zid);

		/*
		 * The release barrier pairs with the acquire in
		 * zone_index_foreach() and makes sure that enumeration loops
		 * always see an initialized zone lock.
		 */
		os_atomic_store(&num_zones, nzones, release);
	}

out:
	num_zones_in_use++;
	simple_unlock(&all_zones_lock);

	*zid_inout = zid;
	return z;
}

__abortlike
static void
zone_create_panic(const char *name, const char *f1, const char *f2)
{
	panic("zone_create: creating zone %s: flag %s and %s are incompatible",
	    name, f1, f2);
}
#define zone_create_assert_not_both(name, flags, current_flag, forbidden_flag) \
	if ((flags) & forbidden_flag) { \
	        zone_create_panic(name, #current_flag, #forbidden_flag); \
	}

/*
 * Adjusts the size of the element based on minimum size, alignment
 * and kasan redzones
 */
static vm_size_t
zone_elem_adjust_size(
	const char             *name __unused,
	vm_size_t               elem_size,
	zone_create_flags_t     flags __unused,
	uint16_t               *redzone __unused)
{
	vm_size_t size;

	/*
	 * Adjust element size for minimum size and pointer alignment
	 */
	size = (elem_size + ZONE_ALIGN_SIZE - 1) & -ZONE_ALIGN_SIZE;
	if (size < ZONE_MIN_ELEM_SIZE) {
		size = ZONE_MIN_ELEM_SIZE;
	}

#if KASAN_CLASSIC
	/*
	 * Expand the zone allocation size to include the redzones.
	 *
	 * For page-multiple zones add a full guard page because they
	 * likely require alignment.
	 */
	uint16_t redzone_tmp;
	if (flags & (ZC_KASAN_NOREDZONE | ZC_PERCPU | ZC_OBJ_CACHE)) {
		redzone_tmp = 0;
	} else if ((size & PAGE_MASK) == 0) {
		if (size != PAGE_SIZE && (flags & ZC_ALIGNMENT_REQUIRED)) {
			panic("zone_create: zone %s can't provide more than PAGE_SIZE"
			    "alignment", name);
		}
		redzone_tmp = PAGE_SIZE;
	} else if (flags & ZC_ALIGNMENT_REQUIRED) {
		redzone_tmp = 0;
	} else {
		redzone_tmp = KASAN_GUARD_SIZE;
	}
	size += redzone_tmp;
	if (redzone) {
		*redzone = redzone_tmp;
	}
#endif
	return size;
}

/*
 * Returns the allocation chunk size that has least framentation
 */
static vm_size_t
zone_get_min_alloc_granule(
	vm_size_t               elem_size,
	zone_create_flags_t     flags)
{
	vm_size_t alloc_granule = PAGE_SIZE;
	if (flags & ZC_PERCPU) {
		alloc_granule = PAGE_SIZE * zpercpu_count();
		if (PAGE_SIZE % elem_size > 256) {
			panic("zone_create: per-cpu zone has too much fragmentation");
		}
	} else if (flags & ZC_READONLY) {
		alloc_granule = PAGE_SIZE;
	} else if ((elem_size & PAGE_MASK) == 0) {
		/* zero fragmentation by definition */
		alloc_granule = elem_size;
	} else if (alloc_granule % elem_size == 0) {
		/* zero fragmentation by definition */
	} else {
		vm_size_t frag = (alloc_granule % elem_size) * 100 / alloc_granule;
		vm_size_t alloc_tmp = PAGE_SIZE;
		vm_size_t max_chunk_size = ZONE_MAX_ALLOC_SIZE;

#if __arm64__
		/*
		 * Increase chunk size to 48K for sizes larger than 4K on 16k
		 * machines, so as to reduce internal fragementation for kalloc
		 * zones with sizes 12K and 24K.
		 */
		if (elem_size > 4 * 1024 && PAGE_SIZE == 16 * 1024) {
			max_chunk_size = 48 * 1024;
		}
#endif
		while ((alloc_tmp += PAGE_SIZE) <= max_chunk_size) {
			vm_size_t frag_tmp = (alloc_tmp % elem_size) * 100 / alloc_tmp;
			if (frag_tmp < frag) {
				frag = frag_tmp;
				alloc_granule = alloc_tmp;
			}
		}
	}
	return alloc_granule;
}

vm_size_t
zone_get_early_alloc_size(
	const char             *name __unused,
	vm_size_t               elem_size,
	zone_create_flags_t     flags,
	vm_size_t               min_elems)
{
	vm_size_t adjusted_size, alloc_granule, chunk_elems;

	adjusted_size = zone_elem_adjust_size(name, elem_size, flags, NULL);
	alloc_granule = zone_get_min_alloc_granule(adjusted_size, flags);
	chunk_elems   = alloc_granule / adjusted_size;

	return ((min_elems + chunk_elems - 1) / chunk_elems) * alloc_granule;
}

zone_t
zone_create_ext(
	const char             *name,
	vm_size_t               size,
	zone_create_flags_t     flags,
	zone_id_t               zid,
	void                  (^extra_setup)(zone_t))
{
	zone_security_flags_t *zsflags;
	uint16_t redzone;
	zone_t z;

	if (size > ZONE_MAX_ALLOC_SIZE) {
		panic("zone_create: element size too large: %zd", (size_t)size);
	}

	if (size < 2 * sizeof(vm_size_t)) {
		/* Elements are too small for kasan. */
		flags |= ZC_KASAN_NOQUARANTINE | ZC_KASAN_NOREDZONE;
	}

	size = zone_elem_adjust_size(name, size, flags, &redzone);

	/*
	 * Allocate the zone slot, return early if we found an older match.
	 */
	z = zone_create_find(name, size, flags, &zid);
	if (__improbable(z->z_self)) {
		/* We found a zone to reuse */
		return z;
	}
	zsflags = &zone_security_array[zid];

	/*
	 * Initialize the zone properly.
	 */

	/*
	 * If the kernel is post lockdown, copy the zone name passed in.
	 * Else simply maintain a pointer to the name string as it can only
	 * be a core XNU zone (no unloadable kext exists before lockdown).
	 */
	if (startup_phase >= STARTUP_SUB_LOCKDOWN) {
		size_t nsz = MIN(strlen(name) + 1, MACH_ZONE_NAME_MAX_LEN);
		char *buf = zalloc_permanent(nsz, ZALIGN_NONE);
		strlcpy(buf, name, nsz);
		z->z_name = buf;
	} else {
		z->z_name = name;
	}
	if (__probable(zone_array[ZONE_ID_PERCPU_PERMANENT].z_self)) {
		z->z_stats = zalloc_percpu_permanent_type(struct zone_stats);
	} else {
		/*
		 * zone_init() hasn't run yet, use the storage provided by
		 * zone_stats_startup(), and zone_init() will replace it
		 * with the final value once the PERCPU zone exists.
		 */
		z->z_stats = __zpcpu_mangle_for_boot(&zone_stats_startup[zone_index(z)]);
	}

	if (flags & ZC_OBJ_CACHE) {
		zone_create_assert_not_both(name, flags, ZC_OBJ_CACHE, ZC_NOCACHING);
		zone_create_assert_not_both(name, flags, ZC_OBJ_CACHE, ZC_PERCPU);
		zone_create_assert_not_both(name, flags, ZC_OBJ_CACHE, ZC_NOGC);
		zone_create_assert_not_both(name, flags, ZC_OBJ_CACHE, ZC_DESTRUCTIBLE);

		z->z_elem_size   = (uint16_t)size;
		z->z_chunk_pages = 0;
		z->z_quo_magic   = 0;
		z->z_align_magic = 0;
		z->z_chunk_elems = 0;
		z->z_elem_offs   = 0;
		z->no_callout    = true;
		zsflags->z_lifo  = true;
	} else {
		vm_size_t alloc = zone_get_min_alloc_granule(size, flags);

		z->z_elem_size   = (uint16_t)(size - redzone);
		z->z_chunk_pages = (uint16_t)atop(alloc);
		z->z_quo_magic   = Z_MAGIC_QUO(size);
		z->z_align_magic = Z_MAGIC_ALIGNED(size);
		if (flags & ZC_PERCPU) {
			z->z_chunk_elems = (uint16_t)(PAGE_SIZE / size);
			z->z_elem_offs = (uint16_t)(PAGE_SIZE % size) + redzone;
		} else {
			z->z_chunk_elems = (uint16_t)(alloc / size);
			z->z_elem_offs = (uint16_t)(alloc % size) + redzone;
		}
	}

	/*
	 * Handle KPI flags
	 */

	/* ZC_CACHING applied after all configuration is done */
	if (flags & ZC_NOCACHING) {
		z->z_nocaching = true;
	}

	if (flags & ZC_READONLY) {
		zone_create_assert_not_both(name, flags, ZC_READONLY, ZC_VM);
		zone_create_assert_not_both(name, flags, ZC_READONLY, ZC_DATA);
		assert(zid <= ZONE_ID__LAST_RO);
#if ZSECURITY_CONFIG(READ_ONLY)
		zsflags->z_submap_idx = Z_SUBMAP_IDX_READ_ONLY;
#endif
		zone_ro_size_params[zid].z_elem_size = z->z_elem_size;
		zone_ro_size_params[zid].z_align_magic = z->z_align_magic;
		assert(size <= PAGE_SIZE);
		if ((PAGE_SIZE % size) * 10 >= PAGE_SIZE) {
			panic("Fragmentation greater than 10%% with elem size %d zone %s%s",
			    (uint32_t)size, zone_heap_name(z), z->z_name);
		}
	}

	if (flags & ZC_PERCPU) {
		zone_create_assert_not_both(name, flags, ZC_PERCPU, ZC_READONLY);
		zone_create_assert_not_both(name, flags, ZC_PERCPU, ZC_PGZ_USE_GUARDS);
		z->z_percpu = true;
	}
	if (flags & ZC_NOGC) {
		z->collectable = false;
	}
	/*
	 * Handle ZC_NOENCRYPT from xnu only
	 */
	if (startup_phase < STARTUP_SUB_LOCKDOWN && flags & ZC_NOENCRYPT) {
		zsflags->z_noencrypt = true;
	}
	if (flags & ZC_NOCALLOUT) {
		z->no_callout = true;
	}
	if (flags & ZC_DESTRUCTIBLE) {
		zone_create_assert_not_both(name, flags, ZC_DESTRUCTIBLE, ZC_READONLY);
		z->z_destructible = true;
	}
	/*
	 * Handle Internal flags
	 */
#if ZSECURITY_CONFIG(SAD_FENG_SHUI)
	if (flags & ZC_PGZ_USE_GUARDS) {
		/*
		 * Try to turn on guard pages only for zones
		 * with a chance of OOB.
		 */
		if (startup_phase < STARTUP_SUB_LOCKDOWN) {
			zsflags->z_pgz_use_guards = true;
		}
		z->z_pgz_use_guards = true;
	}
#endif /* ZSECURITY_CONFIG(SAD_FENG_SHUI) */
	if (!(flags & ZC_NOTBITAG)) {
		z->z_tbi_tag = true;
	}
	if (flags & ZC_KALLOC_TYPE) {
		zsflags->z_kalloc_type = true;
	}
	if (flags & ZC_VM) {
		zone_create_assert_not_both(name, flags, ZC_VM, ZC_DATA);
		zsflags->z_submap_idx = Z_SUBMAP_IDX_VM;
	}
	if (flags & ZC_DATA) {
		zsflags->z_kheap_id = KHEAP_ID_DATA_BUFFERS;
	}
#if KASAN_CLASSIC
	if (redzone && !(flags & ZC_KASAN_NOQUARANTINE)) {
		z->z_kasan_quarantine = true;
	}
	z->z_kasan_redzone = redzone;
#endif /* KASAN_CLASSIC */
#if KASAN_FAKESTACK
	if (strncmp(name, "fakestack.", sizeof("fakestack.") - 1) == 0) {
		z->z_kasan_fakestacks = true;
	}
#endif /* KASAN_FAKESTACK */

	/*
	 * Then if there's extra tuning, do it
	 */
	if (extra_setup) {
		extra_setup(z);
	}

	/*
	 * Configure debugging features
	 */
#if CONFIG_PROB_GZALLOC
	if ((flags & (ZC_READONLY | ZC_PERCPU | ZC_OBJ_CACHE | ZC_NOPGZ)) == 0) {
		pgz_zone_init(z);
	}
#endif
	if (zc_magazine_zone) { /* proxy for "has zone_init run" */
#if ZALLOC_ENABLE_LOGGING
		/*
		 * Check for and set up zone leak detection
		 * if requested via boot-args.
		 */
		zone_setup_logging(z);
#endif /* ZALLOC_ENABLE_LOGGING */
#if KASAN_TBI
		zone_setup_kasan_logging(z);
#endif /* KASAN_TBI */
	}

#if VM_TAG_SIZECLASSES
	if ((zsflags->z_kheap_id || zsflags->z_kalloc_type) && zone_tagging_on) {
		static uint16_t sizeclass_idx;

		assert(startup_phase < STARTUP_SUB_LOCKDOWN);
		z->z_uses_tags = true;
		if (zsflags->z_kheap_id == KHEAP_ID_DEFAULT) {
			zone_tags_sizeclasses[sizeclass_idx] = (uint16_t)size;
			z->z_tags_sizeclass = sizeclass_idx++;
		} else {
			uint16_t i = 0;
			for (; i < sizeclass_idx; i++) {
				if (size == zone_tags_sizeclasses[i]) {
					z->z_tags_sizeclass = i;
					break;
				}
			}

			/*
			 * Size class wasn't found, add it to zone_tags_sizeclasses
			 */
			if (i == sizeclass_idx) {
				assert(i < VM_TAG_SIZECLASSES);
				zone_tags_sizeclasses[i] = (uint16_t)size;
				z->z_tags_sizeclass = sizeclass_idx++;
			}
		}
		assert(z->z_tags_sizeclass < VM_TAG_SIZECLASSES);
	}
#endif

	/*
	 * Finally, fixup properties based on security policies, boot-args, ...
	 */
	if (zsflags->z_kheap_id == KHEAP_ID_DATA_BUFFERS) {
		/*
		 * We use LIFO in the data map, because workloads like network
		 * usage or similar tend to rotate through allocations very
		 * quickly with sometimes epxloding working-sets and using
		 * a FIFO policy might cause massive TLB trashing with rather
		 * dramatic performance impacts.
		 */
		zsflags->z_submap_idx = Z_SUBMAP_IDX_DATA;
		zsflags->z_lifo = true;
	}

	if ((flags & (ZC_CACHING | ZC_OBJ_CACHE)) && !z->z_nocaching) {
		/*
		 * No zone made before zone_init() can have ZC_CACHING set.
		 */
		assert(zc_magazine_zone);
		zone_enable_caching(z);
	}

	zone_lock(z);
	z->z_self = z;
	zone_unlock(z);

	return z;
}

void
zone_enable_smr(zone_t zone, struct smr *smr, zone_smr_free_cb_t free_cb)
{
	/* moving to SMR must be done before the zone has ever been used */
	assert(zone->z_va_cur == 0 && !zone->z_smr && !zone->z_nocaching);
	assert(!zone_security_array[zone_index(zone)].z_lifo);

	if (!zone->z_pcpu_cache) {
		zone_enable_caching(zone);
	}

	zone_lock(zone);

	zpercpu_foreach(it, zone->z_pcpu_cache) {
		it->zc_smr = smr;
		it->zc_free = free_cb;
	}
	zone->z_smr = true;

	zone_unlock(zone);
}

__startup_func
void
zone_create_startup(struct zone_create_startup_spec *spec)
{
	zone_t z;

	z = zone_create_ext(spec->z_name, spec->z_size,
	    spec->z_flags, spec->z_zid, spec->z_setup);
	if (spec->z_var) {
		*spec->z_var = z;
	}
}

/*
 * The 4 first field of a zone_view and a zone alias, so that the zone_or_view_t
 * union works. trust but verify.
 */
#define zalloc_check_zov_alias(f1, f2) \
    static_assert(offsetof(struct zone, f1) == offsetof(struct zone_view, f2))
zalloc_check_zov_alias(z_self, zv_zone);
zalloc_check_zov_alias(z_stats, zv_stats);
zalloc_check_zov_alias(z_name, zv_name);
zalloc_check_zov_alias(z_views, zv_next);
#undef zalloc_check_zov_alias

__startup_func
void
zone_view_startup_init(struct zone_view_startup_spec *spec)
{
	struct kalloc_heap *heap = NULL;
	zone_view_t zv = spec->zv_view;
	zone_t z;
	zone_security_flags_t zsflags;

	switch (spec->zv_heapid) {
	case KHEAP_ID_DEFAULT:
		panic("%s: Use KALLOC_TYPE_DEFINE for zone view %s instead"
		    "of ZONE_VIEW_DEFINE as it is from default kalloc heap",
		    __func__, zv->zv_name);
		__builtin_unreachable();
	case KHEAP_ID_DATA_BUFFERS:
		heap = KHEAP_DATA_BUFFERS;
		break;
	default:
		heap = NULL;
	}

	if (heap) {
		z = kalloc_zone_for_size(heap->kh_zstart, spec->zv_size);
	} else {
		z = *spec->zv_zone;
		assert(spec->zv_size <= zone_elem_inner_size(z));
	}

	assert(z);

	zv->zv_zone  = z;
	zv->zv_stats = zalloc_percpu_permanent_type(struct zone_stats);
	zv->zv_next  = z->z_views;
	zsflags = zone_security_config(z);
	if (z->z_views == NULL && zsflags.z_kheap_id == KHEAP_ID_NONE) {
		/*
		 * count the raw view for zones not in a heap,
		 * kalloc_heap_init() already counts it for its members.
		 */
		zone_view_count += 2;
	} else {
		zone_view_count += 1;
	}
	z->z_views = zv;
}

zone_t
zone_create(
	const char             *name,
	vm_size_t               size,
	zone_create_flags_t     flags)
{
	return zone_create_ext(name, size, flags, ZONE_ID_ANY, NULL);
}

static_assert(ZONE_ID__LAST_RO_EXT - ZONE_ID__FIRST_RO_EXT == ZC_RO_ID__LAST);

zone_id_t
zone_create_ro(
	const char             *name,
	vm_size_t               size,
	zone_create_flags_t     flags,
	zone_create_ro_id_t     zc_ro_id)
{
	assert(zc_ro_id <= ZC_RO_ID__LAST);
	zone_id_t reserved_zid = ZONE_ID__FIRST_RO_EXT + zc_ro_id;
	(void)zone_create_ext(name, size, ZC_READONLY | flags, reserved_zid, NULL);
	return reserved_zid;
}

zone_t
zinit(
	vm_size_t       size,           /* the size of an element */
	vm_size_t       max,            /* maximum memory to use */
	vm_size_t       alloc __unused, /* allocation size */
	const char      *name)          /* a name for the zone */
{
	zone_t z = zone_create(name, size, ZC_DESTRUCTIBLE);
	z->z_wired_max = zone_alloc_pages_for_nelems(z, max / size);
	return z;
}

void
zdestroy(zone_t z)
{
	unsigned int zindex = zone_index(z);
	zone_security_flags_t zsflags = zone_security_array[zindex];

	current_thread()->options |= TH_OPT_ZONE_PRIV;
	lck_mtx_lock(&zone_gc_lock);

	zone_reclaim(z, ZONE_RECLAIM_DESTROY);

	lck_mtx_unlock(&zone_gc_lock);
	current_thread()->options &= ~TH_OPT_ZONE_PRIV;

	zone_lock(z);

	if (!zone_submap_is_sequestered(zsflags)) {
		while (!zone_pva_is_null(z->z_pageq_va)) {
			struct zone_page_metadata *meta;

			zone_counter_sub(z, z_va_cur, z->z_percpu ? 1 : z->z_chunk_pages);
			meta = zone_meta_queue_pop(z, &z->z_pageq_va);
			assert(meta->zm_chunk_len <= ZM_CHUNK_LEN_MAX);
			bzero(meta, sizeof(*meta) * z->z_chunk_pages);
			zone_unlock(z);
			kmem_free(zone_submap(zsflags), zone_meta_to_addr(meta),
			    ptoa(z->z_chunk_pages));
			zone_lock(z);
		}
	}

#if !KASAN_CLASSIC
	/* Assert that all counts are zero */
	if (z->z_elems_avail || z->z_elems_free || zone_size_wired(z) ||
	    (z->z_va_cur && !zone_submap_is_sequestered(zsflags))) {
		panic("zdestroy: Zone %s%s isn't empty at zdestroy() time",
		    zone_heap_name(z), z->z_name);
	}

	/* consistency check: make sure everything is indeed empty */
	assert(zone_pva_is_null(z->z_pageq_empty));
	assert(zone_pva_is_null(z->z_pageq_partial));
	assert(zone_pva_is_null(z->z_pageq_full));
	if (!zone_submap_is_sequestered(zsflags)) {
		assert(zone_pva_is_null(z->z_pageq_va));
	}
#endif

	zone_unlock(z);

	simple_lock(&all_zones_lock, &zone_locks_grp);

	assert(!bitmap_test(zone_destroyed_bitmap, zindex));
	/* Mark the zone as empty in the bitmap */
	bitmap_set(zone_destroyed_bitmap, zindex);
	num_zones_in_use--;
	assert(num_zones_in_use > 0);

	simple_unlock(&all_zones_lock);
}

#endif /* !ZALLOC_TEST */
#pragma mark zalloc module init
#if !ZALLOC_TEST

/*
 *	Initialize the "zone of zones" which uses fixed memory allocated
 *	earlier in memory initialization.  zone_bootstrap is called
 *	before zone_init.
 */
__startup_func
void
zone_bootstrap(void)
{
#if DEBUG || DEVELOPMENT
#if __x86_64__
	if (PE_parse_boot_argn("kernPOST", NULL, 0)) {
		/*
		 * rdar://79781535 Disable early gaps while running kernPOST on Intel
		 * the fp faulting code gets triggered and deadlocks.
		 */
		zone_caching_disabled = 1;
	}
#endif /* __x86_64__ */
#endif /* DEBUG || DEVELOPMENT */

	/* Validate struct zone_packed_virtual_address expectations */
	static_assert((intptr_t)VM_MIN_KERNEL_ADDRESS < 0, "the top bit must be 1");
	if (VM_KERNEL_POINTER_SIGNIFICANT_BITS - PAGE_SHIFT > 31) {
		panic("zone_pva_t can't pack a kernel page address in 31 bits");
	}

	zpercpu_early_count = ml_early_cpu_max_number() + 1;
	if (!PE_parse_boot_argn("zc_mag_size", NULL, 0)) {
		/*
		 * Scale zc_mag_size() per machine.
		 *
		 * - wide machines get 128B magazines to avoid all false sharing
		 * - smaller machines but with enough RAM get a bit bigger
		 *   buckets (empirically affects networking performance)
		 */
		if (zpercpu_early_count >= 10) {
			_zc_mag_size = 14;
		} else if ((sane_size >> 30) >= 4) {
			_zc_mag_size = 10;
		}
	}

	/*
	 * Initialize random used to scramble early allocations
	 */
	zpercpu_foreach_cpu(cpu) {
		random_bool_init(&zone_bool_gen[cpu].zbg_bg);
	}

#if CONFIG_PROB_GZALLOC
	/*
	 * Set pgz_sample_counter on the boot CPU so that we do not sample
	 * any allocation until PGZ has been properly setup (in pgz_init()).
	 */
	*PERCPU_GET_MASTER(pgz_sample_counter) = INT32_MAX;
#endif /* CONFIG_PROB_GZALLOC */

#if ZSECURITY_CONFIG(SAD_FENG_SHUI)
	/*
	 * Randomly assign zones to one of the 4 general submaps,
	 * and pick whether they allocate from the begining
	 * or the end of it.
	 *
	 * A lot of OOB exploitation relies on precise interleaving
	 * of specific types in the heap.
	 *
	 * Woops, you can't guarantee that anymore.
	 */
	for (zone_id_t i = 1; i < MAX_ZONES; i++) {
		uint32_t r = zalloc_random_uniform32(0,
		    ZSECURITY_CONFIG_GENERAL_SUBMAPS * 2);

		zone_security_array[i].z_submap_from_end = (r & 1);
		zone_security_array[i].z_submap_idx += (r >> 1);
	}
#endif /* ZSECURITY_CONFIG(SAD_FENG_SHUI) */

	thread_call_setup_with_options(&zone_expand_callout,
	    zone_expand_async, NULL, THREAD_CALL_PRIORITY_HIGH,
	    THREAD_CALL_OPTIONS_ONCE);

	thread_call_setup_with_options(&zone_trim_callout,
	    zone_trim_async, NULL, THREAD_CALL_PRIORITY_USER,
	    THREAD_CALL_OPTIONS_ONCE);
}

#define ZONE_GUARD_SIZE                 (64UL << 10)

__startup_func
static void
zone_tunables_fixup(void)
{
	int wdt = 0;

#if CONFIG_PROB_GZALLOC && (DEVELOPMENT || DEBUG)
	if (!PE_parse_boot_argn("pgz", NULL, 0) &&
	    PE_parse_boot_argn("pgz1", NULL, 0)) {
		/*
		 * if pgz1= was used, but pgz= was not,
		 * then the more specific pgz1 takes precedence.
		 */
		pgz_all = false;
	}
#endif

	if (zone_map_jetsam_limit == 0 || zone_map_jetsam_limit > 100) {
		zone_map_jetsam_limit = ZONE_MAP_JETSAM_LIMIT_DEFAULT;
	}
	if (PE_parse_boot_argn("wdt", &wdt, sizeof(wdt)) && wdt == -1 &&
	    !PE_parse_boot_argn("zet", NULL, 0)) {
		zone_exhausted_timeout = -1;
	}
}
STARTUP(TUNABLES, STARTUP_RANK_MIDDLE, zone_tunables_fixup);

__startup_func
static void
zone_submap_init(
	mach_vm_offset_t       *submap_min,
	zone_submap_idx_t       idx,
	uint64_t                zone_sub_map_numer,
	uint64_t               *remaining_denom,
	vm_offset_t            *remaining_size)
{
	vm_map_create_options_t vmco;
	vm_map_address_t addr;
	vm_offset_t submap_start, submap_end;
	vm_size_t submap_size;
	vm_map_t  submap;
	vm_prot_t prot = VM_PROT_DEFAULT;
	vm_prot_t prot_max = VM_PROT_ALL;
	kern_return_t kr;

	submap_size = trunc_page(zone_sub_map_numer * *remaining_size /
	    *remaining_denom);
	submap_start = *submap_min;

	if (idx == Z_SUBMAP_IDX_READ_ONLY) {
		vm_offset_t submap_padding = pmap_ro_zone_align(submap_start) - submap_start;
		submap_start += submap_padding;
		submap_size = pmap_ro_zone_align(submap_size);
		assert(*remaining_size >= (submap_padding + submap_size));
		*remaining_size -= submap_padding;
		*submap_min = submap_start;
	}

	submap_end = submap_start + submap_size;
	if (idx == Z_SUBMAP_IDX_VM) {
		vm_packing_verify_range("vm_compressor",
		    submap_start, submap_end, VM_PACKING_PARAMS(C_SLOT_PACKED_PTR));
		vm_packing_verify_range("vm_page",
		    submap_start, submap_end, VM_PACKING_PARAMS(VM_PAGE_PACKED_PTR));
	}

	vmco = VM_MAP_CREATE_NEVER_FAULTS;
	if (!zone_submap_is_sequestered(idx)) {
		vmco |= VM_MAP_CREATE_DISABLE_HOLELIST;
	}

	vm_map_will_allocate_early_map(&zone_submaps[idx]);
	submap = kmem_suballoc(kernel_map, submap_min, submap_size, vmco,
	    VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, KMS_PERMANENT | KMS_NOFAIL,
	    VM_KERN_MEMORY_ZONE).kmr_submap;

	if (idx == Z_SUBMAP_IDX_READ_ONLY) {
		zone_info.zi_ro_range.min_address = submap_start;
		zone_info.zi_ro_range.max_address = submap_end;
		prot_max = prot = VM_PROT_NONE;
	}

	addr = submap_start;
	kr = vm_map_enter(submap, &addr, ZONE_GUARD_SIZE / 2, 0,
	    VM_MAP_KERNEL_FLAGS_FIXED_PERMANENT(.vm_tag = VM_KERN_MEMORY_ZONE),
	    kernel_object, addr, FALSE, prot, prot_max, VM_INHERIT_NONE);
	if (kr != KERN_SUCCESS) {
		panic("ksubmap[%s]: failed to make first entry (%d)",
		    zone_submaps_names[idx], kr);
	}

	addr = submap_end - ZONE_GUARD_SIZE / 2;
	kr = vm_map_enter(submap, &addr, ZONE_GUARD_SIZE / 2, 0,
	    VM_MAP_KERNEL_FLAGS_FIXED_PERMANENT(.vm_tag = VM_KERN_MEMORY_ZONE),
	    kernel_object, addr, FALSE, prot, prot_max, VM_INHERIT_NONE);
	if (kr != KERN_SUCCESS) {
		panic("ksubmap[%s]: failed to make last entry (%d)",
		    zone_submaps_names[idx], kr);
	}

#if DEBUG || DEVELOPMENT
	printf("zone_init: map %-5s %p:%p (%u%c)\n",
	    zone_submaps_names[idx], (void *)submap_start, (void *)submap_end,
	    mach_vm_size_pretty(submap_size), mach_vm_size_unit(submap_size));
#endif /* DEBUG || DEVELOPMENT */

	zone_submaps[idx] = submap;
	*submap_min       = submap_end;
	*remaining_size  -= submap_size;
	*remaining_denom -= zone_sub_map_numer;
}

static inline void
zone_pva_relocate(zone_pva_t *pva, uint32_t delta)
{
	if (!zone_pva_is_null(*pva) && !zone_pva_is_queue(*pva)) {
		pva->packed_address += delta;
	}
}

/*
 * Allocate metadata array and migrate bootstrap initial metadata and memory.
 */
__startup_func
static void
zone_metadata_init(void)
{
	vm_map_t vm_map = zone_submaps[Z_SUBMAP_IDX_VM];
	vm_map_entry_t first;

	struct mach_vm_range meta_r, bits_r, xtra_r, early_r;
	vm_size_t early_sz;
	vm_offset_t reloc_base;

	/*
	 * Step 1: Allocate the metadata + bitmaps range
	 *
	 * Allocations can't be smaller than 8 bytes, which is 128b / 16B per 1k
	 * of physical memory (16M per 1G).
	 *
	 * Let's preallocate for the worst to avoid weird panics.
	 */
	vm_map_will_allocate_early_map(&zone_meta_map);
	meta_r = zone_kmem_suballoc(zone_info.zi_meta_range.min_address,
	    zone_meta_size + zone_bits_size + zone_xtra_size,
	    VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
	    VM_KERN_MEMORY_ZONE, &zone_meta_map);
	meta_r.min_address += ZONE_GUARD_SIZE;
	meta_r.max_address -= ZONE_GUARD_SIZE;
	if (zone_xtra_size) {
		xtra_r.max_address  = meta_r.max_address;
		meta_r.max_address -= zone_xtra_size;
		xtra_r.min_address  = meta_r.max_address;
	} else {
		xtra_r.min_address  = xtra_r.max_address = 0;
	}
	bits_r.max_address  = meta_r.max_address;
	meta_r.max_address -= zone_bits_size;
	bits_r.min_address  = meta_r.max_address;

#if DEBUG || DEVELOPMENT
	printf("zone_init: metadata  %p:%p (%u%c)\n",
	    (void *)meta_r.min_address, (void *)meta_r.max_address,
	    mach_vm_size_pretty(mach_vm_range_size(&meta_r)),
	    mach_vm_size_unit(mach_vm_range_size(&meta_r)));
	printf("zone_init: metabits  %p:%p (%u%c)\n",
	    (void *)bits_r.min_address, (void *)bits_r.max_address,
	    mach_vm_size_pretty(mach_vm_range_size(&bits_r)),
	    mach_vm_size_unit(mach_vm_range_size(&bits_r)));
	printf("zone_init: extra     %p:%p (%u%c)\n",
	    (void *)xtra_r.min_address, (void *)xtra_r.max_address,
	    mach_vm_size_pretty(mach_vm_range_size(&xtra_r)),
	    mach_vm_size_unit(mach_vm_range_size(&xtra_r)));
#endif /* DEBUG || DEVELOPMENT */

	bits_r.min_address = (bits_r.min_address + ZBA_CHUNK_SIZE - 1) & -ZBA_CHUNK_SIZE;
	bits_r.max_address = bits_r.max_address & -ZBA_CHUNK_SIZE;

	/*
	 * Step 2: Install new ranges.
	 *         Relocate metadata and bits.
	 */
	early_r  = zone_info.zi_map_range;
	early_sz = mach_vm_range_size(&early_r);

	zone_info.zi_map_range  = zone_map_range;
	zone_info.zi_meta_range = meta_r;
	zone_info.zi_bits_range = bits_r;
	zone_info.zi_xtra_range = xtra_r;
	zone_info.zi_meta_base  = (struct zone_page_metadata *)meta_r.min_address -
	    zone_pva_from_addr(zone_map_range.min_address).packed_address;

	vm_map_lock(vm_map);
	first = vm_map_first_entry(vm_map);
	reloc_base = first->vme_end;
	first->vme_end += early_sz;
	vm_map->size += early_sz;
	vm_map_unlock(vm_map);

	struct zone_page_metadata *early_meta = zone_early_meta_array_startup;
	struct zone_page_metadata *new_meta = zone_meta_from_addr(reloc_base);
	vm_offset_t reloc_delta = reloc_base - early_r.min_address;
	/* this needs to sign extend */
	uint32_t pva_delta = (uint32_t)((intptr_t)reloc_delta >> PAGE_SHIFT);

	zone_meta_populate(reloc_base, early_sz);
	memcpy(new_meta, early_meta,
	    atop(early_sz) * sizeof(struct zone_page_metadata));
	for (uint32_t i = 0; i < atop(early_sz); i++) {
		zone_pva_relocate(&new_meta[i].zm_page_next, pva_delta);
		zone_pva_relocate(&new_meta[i].zm_page_prev, pva_delta);
	}

	static_assert(ZONE_ID_VM_MAP_ENTRY == ZONE_ID_VM_MAP + 1);
	static_assert(ZONE_ID_VM_MAP_HOLES == ZONE_ID_VM_MAP + 2);

	for (zone_id_t zid = ZONE_ID_VM_MAP; zid <= ZONE_ID_VM_MAP_HOLES; zid++) {
		zone_pva_relocate(&zone_array[zid].z_pageq_partial, pva_delta);
		zone_pva_relocate(&zone_array[zid].z_pageq_full, pva_delta);
	}

	zba_populate(0, false);
	memcpy(zba_base_header(), zba_chunk_startup, sizeof(zba_chunk_startup));
	zba_meta()->zbam_right = (uint32_t)atop(zone_bits_size);

	/*
	 * Step 3: Relocate the boostrap VM structs
	 *         (including rewriting their content).
	 */

#if __x86_64__
	kernel_memory_populate(reloc_base, early_sz,
	    KMA_KOBJECT | KMA_NOENCRYPT | KMA_NOFAIL,
	    VM_KERN_MEMORY_OSFMK);
	__nosan_memcpy((void *)reloc_base, (void *)early_r.min_address, early_sz);
#else
	for (vm_address_t addr = early_r.min_address;
	    addr < early_r.max_address; addr += PAGE_SIZE) {
		pmap_paddr_t pa = kvtophys(trunc_page(addr));
		__assert_only kern_return_t kr;

		kr = pmap_enter_options_addr(kernel_pmap, addr + reloc_delta,
		    pa, VM_PROT_READ | VM_PROT_WRITE, VM_PROT_NONE, 0, TRUE,
		    0, NULL);
		assert(kr == KERN_SUCCESS);
	}
#endif

#if KASAN
	kasan_notify_address(reloc_base, early_sz);
#if KASAN_TBI
	kasan_tbi_copy_tags(reloc_base, early_r.min_address, early_sz);
#endif /* KASAN_TBI */
#endif /* KASAN */

	vm_map_relocate_early_maps(reloc_delta);

	for (uint32_t i = 0; i < atop(early_sz); i++) {
		zone_id_t zid = new_meta[i].zm_index;
		zone_t z = &zone_array[zid];
		vm_size_t esize = zone_elem_outer_size(z);
		vm_address_t base = reloc_base + ptoa(i) + zone_elem_inner_offs(z);
		vm_address_t addr;

		if (new_meta[i].zm_chunk_len >= ZM_SECONDARY_PAGE) {
			continue;
		}

		for (uint32_t eidx = 0; eidx < z->z_chunk_elems; eidx++) {
			if (zone_meta_is_free(&new_meta[i], eidx)) {
				continue;
			}

			addr = base + eidx * esize;
#if KASAN_CLASSIC
			kasan_alloc(addr,
			    zone_elem_inner_size(z), zone_elem_inner_size(z),
			    zone_elem_redzone(z), false,
			    __builtin_frame_address(0));
#endif
			vm_map_relocate_early_elem(zid, addr, reloc_delta);
		}
	}

#if !__x86_64__
	pmap_remove(kernel_pmap, early_r.min_address, early_r.max_address);
#endif
}

__startup_data
static uint16_t submap_ratios[Z_SUBMAP_IDX_COUNT] = {
#if ZSECURITY_CONFIG(READ_ONLY)
	[Z_SUBMAP_IDX_VM]               = 15,
	[Z_SUBMAP_IDX_READ_ONLY]        =  5,
#else
	[Z_SUBMAP_IDX_VM]               = 20,
#endif /* !ZSECURITY_CONFIG(READ_ONLY) */
#if ZSECURITY_CONFIG(SAD_FENG_SHUI)
	[Z_SUBMAP_IDX_GENERAL_0]        = 15,
	[Z_SUBMAP_IDX_GENERAL_1]        = 15,
	[Z_SUBMAP_IDX_GENERAL_2]        = 15,
	[Z_SUBMAP_IDX_GENERAL_3]        = 15,
	[Z_SUBMAP_IDX_DATA]             = 20,
#else
	[Z_SUBMAP_IDX_GENERAL_0]        = 60,
	[Z_SUBMAP_IDX_DATA]             = 20,
#endif /* ZSECURITY_CONFIG(SAD_FENG_SHUI) */
};

__startup_func
static inline uint16_t
zone_submap_ratios_denom(void)
{
	uint16_t denom = 0;

	for (unsigned idx = 0; idx < Z_SUBMAP_IDX_COUNT; idx++) {
		denom += submap_ratios[idx];
	}

	assert(denom == 100);

	return denom;
}

__startup_func
static inline vm_offset_t
zone_restricted_va_max(void)
{
	vm_offset_t compressor_max = VM_PACKING_MAX_PACKABLE(C_SLOT_PACKED_PTR);
	vm_offset_t vm_page_max    = VM_PACKING_MAX_PACKABLE(VM_PAGE_PACKED_PTR);

	return trunc_page(MIN(compressor_max, vm_page_max));
}

__startup_func
static void
zone_set_map_sizes(void)
{
	vm_size_t zsize;
	vm_size_t zsizearg;

	/*
	 * Compute the physical limits for the zone map
	 */

	if (PE_parse_boot_argn("zsize", &zsizearg, sizeof(zsizearg))) {
		zsize = zsizearg * (1024ULL * 1024);
	} else {
		/* Set target zone size as 1/4 of physical memory */
		zsize = (vm_size_t)(sane_size >> 2);
		zsize += zsize >> 1;
	}

	if (zsize < CONFIG_ZONE_MAP_MIN) {
		zsize = CONFIG_ZONE_MAP_MIN;   /* Clamp to min */
	}
	if (zsize > sane_size >> 1) {
		zsize = (vm_size_t)(sane_size >> 1); /* Clamp to half of RAM max */
	}
	if (zsizearg == 0 && zsize > ZONE_MAP_MAX) {
		/* if zsize boot-arg not present and zsize exceeds platform maximum, clip zsize */
		printf("NOTE: zonemap size reduced from 0x%lx to 0x%lx\n",
		    (uintptr_t)zsize, (uintptr_t)ZONE_MAP_MAX);
		zsize = ZONE_MAP_MAX;
	}

	zone_pages_wired_max = (uint32_t)atop(trunc_page(zsize));


	/*
	 * Declare restrictions on zone max
	 */
	vm_offset_t vm_submap_size = round_page(
		(submap_ratios[Z_SUBMAP_IDX_VM] * ZONE_MAP_VA_SIZE) /
		zone_submap_ratios_denom());

#if CONFIG_PROB_GZALLOC
	vm_submap_size += pgz_get_size();
#endif /* CONFIG_PROB_GZALLOC */
	if (os_sub_overflow(zone_restricted_va_max(), vm_submap_size,
	    &zone_map_range.min_address)) {
		zone_map_range.min_address = 0;
	}

	zone_meta_size = round_page(atop(ZONE_MAP_VA_SIZE) *
	    sizeof(struct zone_page_metadata)) + ZONE_GUARD_SIZE * 2;

	static_assert(ZONE_MAP_MAX / (CHAR_BIT * KALLOC_MINSIZE) <=
	    ZBA_PTR_MASK + 1);
	zone_bits_size = round_page(ptoa(zone_pages_wired_max) /
	    (CHAR_BIT * KALLOC_MINSIZE));

#if VM_TAG_SIZECLASSES
	if (zone_tagging_on) {
		zba_xtra_shift = (uint8_t)fls(sizeof(vm_tag_t) - 1);
	}
	if (zba_xtra_shift) {
		/*
		 * if we need the extra space range, then limit the size of the
		 * bitmaps to something reasonable instead of a theoretical
		 * worst case scenario of all zones being for the smallest
		 * allocation granule, in order to avoid fake VA pressure on
		 * other parts of the system.
		 */
		zone_bits_size = round_page(zone_bits_size / 8);
		zone_xtra_size = round_page(zone_bits_size * CHAR_BIT << zba_xtra_shift);
	}
#endif /* VM_TAG_SIZECLASSES */
}
STARTUP(KMEM, STARTUP_RANK_FIRST, zone_set_map_sizes);

/*
 * Can't use zone_info.zi_map_range at this point as it is being used to
 * store the range of early pmap memory that was stolen to bootstrap the
 * necessary VM zones.
 */
KMEM_RANGE_REGISTER_STATIC(zones, &zone_map_range, ZONE_MAP_VA_SIZE);
KMEM_RANGE_REGISTER_DYNAMIC(zone_meta, &zone_info.zi_meta_range, ^{
	return zone_meta_size + zone_bits_size + zone_xtra_size;
});

/*
 * Global initialization of Zone Allocator.
 * Runs after zone_bootstrap.
 */
__startup_func
static void
zone_init(void)
{
	vm_size_t           remaining_size = ZONE_MAP_VA_SIZE;
	mach_vm_offset_t    submap_min = 0;
	uint64_t            denom = zone_submap_ratios_denom();
	/*
	 * And now allocate the various pieces of VA and submaps.
	 */

	submap_min = zone_map_range.min_address;

#if CONFIG_PROB_GZALLOC
	vm_size_t pgz_size = pgz_get_size();

	vm_map_will_allocate_early_map(&pgz_submap);
	zone_info.zi_pgz_range = zone_kmem_suballoc(submap_min, pgz_size,
	    VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
	    VM_KERN_MEMORY_ZONE, &pgz_submap);

	submap_min     += pgz_size;
	remaining_size -= pgz_size;
#if DEBUG || DEVELOPMENT
	printf("zone_init: pgzalloc  %p:%p (%u%c) [%d slots]\n",
	    (void *)zone_info.zi_pgz_range.min_address,
	    (void *)zone_info.zi_pgz_range.max_address,
	    mach_vm_size_pretty(pgz_size), mach_vm_size_unit(pgz_size),
	    pgz_slots);
#endif /* DEBUG || DEVELOPMENT */
#endif /* CONFIG_PROB_GZALLOC */

	/*
	 * Allocate the submaps
	 */
	for (zone_submap_idx_t idx = 0; idx < Z_SUBMAP_IDX_COUNT; idx++) {
		if (submap_ratios[idx] == 0) {
			zone_submaps[idx] = VM_MAP_NULL;
		} else {
			zone_submap_init(&submap_min, idx, submap_ratios[idx],
			    &denom, &remaining_size);
		}
	}

	zone_metadata_init();

#if VM_TAG_SIZECLASSES
	if (zone_tagging_on) {
		vm_allocation_zones_init();
	}
#endif /* VM_TAG_SIZECLASSES */

	zone_create_flags_t kma_flags = ZC_NOCACHING | ZC_NOGC | ZC_NOCALLOUT |
	    ZC_KASAN_NOQUARANTINE | ZC_KASAN_NOREDZONE | ZC_VM;

	(void)zone_create_ext("vm.permanent", 1, kma_flags,
	    ZONE_ID_PERMANENT, ^(zone_t z) {
		z->z_permanent = true;
		z->z_elem_size = 1;
	});
	(void)zone_create_ext("vm.permanent.percpu", 1,
	    kma_flags | ZC_PERCPU, ZONE_ID_PERCPU_PERMANENT, ^(zone_t z) {
		z->z_permanent = true;
		z->z_elem_size = 1;
	});

	zc_magazine_zone = zone_create("zcc_magazine_zone", sizeof(struct zone_magazine) +
	    zc_mag_size() * sizeof(vm_offset_t),
	    ZC_VM | ZC_NOCACHING | ZC_ZFREE_CLEARMEM | ZC_PGZ_USE_GUARDS);
	zone_raise_reserve(zc_magazine_zone, (uint16_t)(2 * zpercpu_count()));

	/*
	 * Now migrate the startup statistics into their final storage,
	 * and enable logging for early zones (that zone_create_ext() skipped).
	 */
	int cpu = cpu_number();
	zone_index_foreach(idx) {
		zone_t tz = &zone_array[idx];

		if (tz->z_stats == __zpcpu_mangle_for_boot(&zone_stats_startup[idx])) {
			zone_stats_t zs = zalloc_percpu_permanent_type(struct zone_stats);

			*zpercpu_get_cpu(zs, cpu) = *zpercpu_get_cpu(tz->z_stats, cpu);
			tz->z_stats = zs;
		}
		if (tz->z_self == tz) {
#if ZALLOC_ENABLE_LOGGING
			zone_setup_logging(tz);
#endif /* ZALLOC_ENABLE_LOGGING */
#if KASAN_TBI
			zone_setup_kasan_logging(tz);
#endif /* KASAN_TBI */
		}
	}
}
STARTUP(ZALLOC, STARTUP_RANK_FIRST, zone_init);

void
zalloc_first_proc_made(void)
{
	zone_caching_disabled = 0;
}

__startup_func
vm_offset_t
zone_early_mem_init(vm_size_t size)
{
	vm_offset_t mem;

	assert3u(atop(size), <=, ZONE_EARLY_META_INLINE_COUNT);

	/*
	 * The zone that is used early to bring up the VM is stolen here.
	 *
	 * When the zone subsystem is actually initialized,
	 * zone_metadata_init() will be called, and those pages
	 * and the elements they contain, will be relocated into
	 * the VM submap (even for architectures when those zones
	 * do not live there).
	 */
#if __x86_64__
	assert3u(size, <=, sizeof(zone_early_pages_to_cram));
	mem = (vm_offset_t)zone_early_pages_to_cram;
#else
	mem = (vm_offset_t)pmap_steal_memory(size, PAGE_SIZE);
#endif

	zone_info.zi_meta_base = zone_early_meta_array_startup -
	    zone_pva_from_addr(mem).packed_address;
	zone_info.zi_map_range.min_address = mem;
	zone_info.zi_map_range.max_address = mem + size;

	zone_info.zi_bits_range = (struct mach_vm_range){
		.min_address = (mach_vm_offset_t)zba_chunk_startup,
		.max_address = (mach_vm_offset_t)zba_chunk_startup +
	    sizeof(zba_chunk_startup),
	};

	zba_meta()->zbam_left  = 1;
	zba_meta()->zbam_right = 1;
	zba_init_chunk(0, false);

	return mem;
}

#endif /* !ZALLOC_TEST */
#pragma mark - tests
#if DEBUG || DEVELOPMENT

/*
 * Used for sysctl zone tests that aren't thread-safe. Ensure only one
 * thread goes through at a time.
 *
 * Or we can end up with multiple test zones (if a second zinit() comes through
 * before zdestroy()), which could lead us to run out of zones.
 */
static bool any_zone_test_running = FALSE;

static uintptr_t *
zone_copy_allocations(zone_t z, uintptr_t *elems, zone_pva_t page_index)
{
	vm_offset_t elem_size = zone_elem_outer_size(z);
	vm_offset_t base;
	struct zone_page_metadata *meta;

	while (!zone_pva_is_null(page_index)) {
		base  = zone_pva_to_addr(page_index) + zone_elem_inner_offs(z);
		meta  = zone_pva_to_meta(page_index);

		if (meta->zm_inline_bitmap) {
			for (size_t i = 0; i < meta->zm_chunk_len; i++) {
				uint32_t map = meta[i].zm_bitmap;

				for (; map; map &= map - 1) {
					*elems++ = INSTANCE_PUT(base +
					    elem_size * __builtin_clz(map));
				}
				base += elem_size * 32;
			}
		} else {
			uint32_t order = zba_bits_ref_order(meta->zm_bitmap);
			bitmap_t *bits = zba_bits_ref_ptr(meta->zm_bitmap);
			for (size_t i = 0; i < (1u << order); i++) {
				uint64_t map = bits[i];

				for (; map; map &= map - 1) {
					*elems++ = INSTANCE_PUT(base +
					    elem_size * __builtin_clzll(map));
				}
				base += elem_size * 64;
			}
		}

		page_index = meta->zm_page_next;
	}
	return elems;
}

kern_return_t
zone_leaks(const char * zoneName, uint32_t nameLen, leak_site_proc proc)
{
	zone_t        zone = NULL;
	uintptr_t *   array;
	uintptr_t *   next;
	uintptr_t     element;
	uint32_t      idx, count, found;
	uint32_t      nobtcount;
	uint32_t      elemSize;
	size_t        maxElems;

	zone_foreach(z) {
		if (!strncmp(zoneName, z->z_name, nameLen)) {
			zone = z;
			break;
		}
	}
	if (zone == NULL) {
		return KERN_INVALID_NAME;
	}

	elemSize = (uint32_t)zone_elem_inner_size(zone);
	maxElems = (zone->z_elems_avail + 1) & ~1ul;

	array = kalloc_type_tag(vm_offset_t, maxElems, VM_KERN_MEMORY_DIAG);
	if (array == NULL) {
		return KERN_RESOURCE_SHORTAGE;
	}

	zone_lock(zone);

	next = array;
	next = zone_copy_allocations(zone, next, zone->z_pageq_partial);
	next = zone_copy_allocations(zone, next, zone->z_pageq_full);
	count = (uint32_t)(next - array);

	zone_unlock(zone);

	zone_leaks_scan(array, count, (uint32_t)zone_elem_outer_size(zone), &found);
	assert(found <= count);

	for (idx = 0; idx < count; idx++) {
		element = array[idx];
		if (kInstanceFlagReferenced & element) {
			continue;
		}
		element = INSTANCE_PUT(element) & ~kInstanceFlags;
	}

#if ZALLOC_ENABLE_LOGGING
	if (zone->z_btlog && !corruption_debug_flag) {
		// btlog_copy_backtraces_for_elements will set kInstanceFlagReferenced on elements it found
		static_assert(sizeof(vm_address_t) == sizeof(uintptr_t));
		btlog_copy_backtraces_for_elements(zone->z_btlog,
		    (vm_address_t *)array, &count, elemSize, proc);
	}
#endif /* ZALLOC_ENABLE_LOGGING */

	for (nobtcount = idx = 0; idx < count; idx++) {
		element = array[idx];
		if (!element) {
			continue;
		}
		if (kInstanceFlagReferenced & element) {
			continue;
		}
		nobtcount++;
	}
	if (nobtcount) {
		proc(nobtcount, elemSize, BTREF_NULL);
	}

	kfree_type(vm_offset_t, maxElems, array);
	return KERN_SUCCESS;
}

static int
zone_ro_basic_test_run(__unused int64_t in, int64_t *out)
{
	zone_security_flags_t zsflags;
	uint32_t x = 4;
	uint32_t *test_ptr;

	if (os_atomic_xchg(&any_zone_test_running, true, relaxed)) {
		printf("zone_ro_basic_test: Test already running.\n");
		return EALREADY;
	}

	zsflags = zone_security_array[ZONE_ID__FIRST_RO];

	for (int i = 0; i < 3; i++) {
#if ZSECURITY_CONFIG(READ_ONLY)
		/* Basic Test: Create int zone, zalloc int, modify value, free int */
		printf("zone_ro_basic_test: Basic Test iteration %d\n", i);
		printf("zone_ro_basic_test: create a sub-page size zone\n");

		printf("zone_ro_basic_test: verify flags were set\n");
		assert(zsflags.z_submap_idx == Z_SUBMAP_IDX_READ_ONLY);

		printf("zone_ro_basic_test: zalloc an element\n");
		test_ptr = (zalloc_ro)(ZONE_ID__FIRST_RO, Z_WAITOK);
		assert(test_ptr);

		printf("zone_ro_basic_test: verify we can't write to it\n");
		assert(verify_write(&x, test_ptr, sizeof(x)) == EFAULT);

		x = 4;
		printf("zone_ro_basic_test: test zalloc_ro_mut to assign value\n");
		zalloc_ro_mut(ZONE_ID__FIRST_RO, test_ptr, 0, &x, sizeof(uint32_t));
		assert(test_ptr);
		assert(*(uint32_t*)test_ptr == x);

		x = 5;
		printf("zone_ro_basic_test: test zalloc_ro_update_elem to assign value\n");
		zalloc_ro_update_elem(ZONE_ID__FIRST_RO, test_ptr, &x);
		assert(test_ptr);
		assert(*(uint32_t*)test_ptr == x);

		printf("zone_ro_basic_test: verify we can't write to it after assigning value\n");
		assert(verify_write(&x, test_ptr, sizeof(x)) == EFAULT);

		printf("zone_ro_basic_test: free elem\n");
		zfree_ro(ZONE_ID__FIRST_RO, test_ptr);
		assert(!test_ptr);
#else
		printf("zone_ro_basic_test: Read-only allocator n/a on 32bit platforms, test functionality of API\n");

		printf("zone_ro_basic_test: verify flags were set\n");
		assert(zsflags.z_submap_idx != Z_SUBMAP_IDX_READ_ONLY);

		printf("zone_ro_basic_test: zalloc an element\n");
		test_ptr = (zalloc_ro)(ZONE_ID__FIRST_RO, Z_WAITOK);
		assert(test_ptr);

		x = 4;
		printf("zone_ro_basic_test: test zalloc_ro_mut to assign value\n");
		zalloc_ro_mut(ZONE_ID__FIRST_RO, test_ptr, 0, &x, sizeof(uint32_t));
		assert(test_ptr);
		assert(*(uint32_t*)test_ptr == x);

		x = 5;
		printf("zone_ro_basic_test: test zalloc_ro_update_elem to assign value\n");
		zalloc_ro_update_elem(ZONE_ID__FIRST_RO, test_ptr, &x);
		assert(test_ptr);
		assert(*(uint32_t*)test_ptr == x);

		printf("zone_ro_basic_test: free elem\n");
		zfree_ro(ZONE_ID__FIRST_RO, test_ptr);
		assert(!test_ptr);
#endif /* !ZSECURITY_CONFIG(READ_ONLY) */
	}

	printf("zone_ro_basic_test: garbage collection\n");
	zone_gc(ZONE_GC_DRAIN);

	printf("zone_ro_basic_test: Test passed\n");

	*out = 1;
	os_atomic_store(&any_zone_test_running, false, relaxed);
	return 0;
}
SYSCTL_TEST_REGISTER(zone_ro_basic_test, zone_ro_basic_test_run);

static int
zone_basic_test_run(__unused int64_t in, int64_t *out)
{
	static zone_t test_zone_ptr = NULL;

	unsigned int i = 0, max_iter = 5;
	void * test_ptr;
	zone_t test_zone;
	int rc = 0;

	if (os_atomic_xchg(&any_zone_test_running, true, relaxed)) {
		printf("zone_basic_test: Test already running.\n");
		return EALREADY;
	}

	printf("zone_basic_test: Testing zinit(), zalloc(), zfree() and zdestroy() on zone \"test_zone_sysctl\"\n");

	/* zinit() and zdestroy() a zone with the same name a bunch of times, verify that we get back the same zone each time */
	do {
		test_zone = zinit(sizeof(uint64_t), 100 * sizeof(uint64_t), sizeof(uint64_t), "test_zone_sysctl");
		assert(test_zone);

#if KASAN_CLASSIC
		if (test_zone_ptr == NULL && test_zone->z_elems_free != 0)
#else
		if (test_zone->z_elems_free != 0)
#endif
		{
			printf("zone_basic_test: free count is not zero\n");
			rc = EIO;
			goto out;
		}

		if (test_zone_ptr == NULL) {
			/* Stash the zone pointer returned on the fist zinit */
			printf("zone_basic_test: zone created for the first time\n");
			test_zone_ptr = test_zone;
		} else if (test_zone != test_zone_ptr) {
			printf("zone_basic_test: old zone pointer and new zone pointer don't match\n");
			rc = EIO;
			goto out;
		}

		test_ptr = zalloc_flags(test_zone, Z_WAITOK | Z_NOFAIL);
		zfree(test_zone, test_ptr);

		zdestroy(test_zone);
		i++;

		printf("zone_basic_test: Iteration %d successful\n", i);
	} while (i < max_iter);

#if !KASAN_CLASSIC /* because of the quarantine and redzones */
	/* test Z_VA_SEQUESTER */
	{
		zone_t test_pcpu_zone;
		kern_return_t kr;
		int idx, num_allocs = 8;
		vm_size_t elem_size = 2 * PAGE_SIZE / num_allocs;
		void *allocs[num_allocs];
		void **allocs_pcpu;
		vm_offset_t phys_pages = os_atomic_load(&zone_pages_wired, relaxed);

		test_zone = zone_create("test_zone_sysctl", elem_size,
		    ZC_DESTRUCTIBLE);
		assert(test_zone);

		test_pcpu_zone = zone_create("test_zone_sysctl.pcpu", sizeof(uint64_t),
		    ZC_DESTRUCTIBLE | ZC_PERCPU);
		assert(test_pcpu_zone);

		for (idx = 0; idx < num_allocs; idx++) {
			allocs[idx] = zalloc(test_zone);
			assert(NULL != allocs[idx]);
			printf("alloc[%d] %p\n", idx, allocs[idx]);
		}
		for (idx = 0; idx < num_allocs; idx++) {
			zfree(test_zone, allocs[idx]);
		}
		assert(!zone_pva_is_null(test_zone->z_pageq_empty));

		kr = kmem_alloc(kernel_map, (vm_address_t *)&allocs_pcpu, PAGE_SIZE,
		    KMA_ZERO | KMA_KOBJECT, VM_KERN_MEMORY_DIAG);
		assert(kr == KERN_SUCCESS);

		for (idx = 0; idx < PAGE_SIZE / sizeof(uint64_t); idx++) {
			allocs_pcpu[idx] = zalloc_percpu(test_pcpu_zone,
			    Z_WAITOK | Z_ZERO);
			assert(NULL != allocs_pcpu[idx]);
		}
		for (idx = 0; idx < PAGE_SIZE / sizeof(uint64_t); idx++) {
			zfree_percpu(test_pcpu_zone, allocs_pcpu[idx]);
		}
		assert(!zone_pva_is_null(test_pcpu_zone->z_pageq_empty));

		printf("vm_page_wire_count %d, vm_page_free_count %d, p to v %ld%%\n",
		    vm_page_wire_count, vm_page_free_count,
		    100L * phys_pages / zone_pages_wired_max);
		zone_gc(ZONE_GC_DRAIN);
		printf("vm_page_wire_count %d, vm_page_free_count %d, p to v %ld%%\n",
		    vm_page_wire_count, vm_page_free_count,
		    100L * phys_pages / zone_pages_wired_max);

		unsigned int allva = 0;

		zone_foreach(z) {
			zone_lock(z);
			allva += z->z_wired_cur;
			if (zone_pva_is_null(z->z_pageq_va)) {
				zone_unlock(z);
				continue;
			}
			unsigned count = 0;
			uint64_t size;
			zone_pva_t pg = z->z_pageq_va;
			struct zone_page_metadata *page_meta;
			while (pg.packed_address) {
				page_meta = zone_pva_to_meta(pg);
				count += z->z_percpu ? 1 : z->z_chunk_pages;
				if (page_meta->zm_chunk_len == ZM_SECONDARY_PAGE) {
					count -= page_meta->zm_page_index;
				}
				pg = page_meta->zm_page_next;
			}
			size = zone_size_wired(z);
			if (!size) {
				size = 1;
			}
			printf("%s%s: seq %d, res %d, %qd %%\n",
			    zone_heap_name(z), z->z_name, z->z_va_cur - z->z_wired_cur,
			    z->z_wired_cur, zone_size_allocated(z) * 100ULL / size);
			zone_unlock(z);
		}

		printf("total va: %d\n", allva);

		assert(zone_pva_is_null(test_zone->z_pageq_empty));
		assert(zone_pva_is_null(test_zone->z_pageq_partial));
		assert(!zone_pva_is_null(test_zone->z_pageq_va));
		assert(zone_pva_is_null(test_pcpu_zone->z_pageq_empty));
		assert(zone_pva_is_null(test_pcpu_zone->z_pageq_partial));
		assert(!zone_pva_is_null(test_pcpu_zone->z_pageq_va));

		for (idx = 0; idx < num_allocs; idx++) {
			assert(0 == pmap_find_phys(kernel_pmap, (addr64_t)(uintptr_t) allocs[idx]));
		}

		/* make sure the zone is still usable after a GC */

		for (idx = 0; idx < num_allocs; idx++) {
			allocs[idx] = zalloc(test_zone);
			assert(allocs[idx]);
			printf("alloc[%d] %p\n", idx, allocs[idx]);
		}
		for (idx = 0; idx < num_allocs; idx++) {
			zfree(test_zone, allocs[idx]);
		}

		for (idx = 0; idx < PAGE_SIZE / sizeof(uint64_t); idx++) {
			allocs_pcpu[idx] = zalloc_percpu(test_pcpu_zone,
			    Z_WAITOK | Z_ZERO);
			assert(NULL != allocs_pcpu[idx]);
		}
		for (idx = 0; idx < PAGE_SIZE / sizeof(uint64_t); idx++) {
			zfree_percpu(test_pcpu_zone, allocs_pcpu[idx]);
		}

		assert(!zone_pva_is_null(test_pcpu_zone->z_pageq_empty));

		kmem_free(kernel_map, (vm_address_t)allocs_pcpu, PAGE_SIZE);

		zdestroy(test_zone);
		zdestroy(test_pcpu_zone);
	}
#endif /* KASAN_CLASSIC */

	printf("zone_basic_test: Test passed\n");


	*out = 1;
out:
	os_atomic_store(&any_zone_test_running, false, relaxed);
	return rc;
}
SYSCTL_TEST_REGISTER(zone_basic_test, zone_basic_test_run);

struct zone_stress_obj {
	TAILQ_ENTRY(zone_stress_obj) zso_link;
};

struct zone_stress_ctx {
	thread_t  zsc_leader;
	lck_mtx_t zsc_lock;
	zone_t    zsc_zone;
	uint64_t  zsc_end;
	uint32_t  zsc_workers;
};

static void
zone_stress_worker(void *arg, wait_result_t __unused wr)
{
	struct zone_stress_ctx *ctx = arg;
	bool leader = ctx->zsc_leader == current_thread();
	TAILQ_HEAD(zone_stress_head, zone_stress_obj) head = TAILQ_HEAD_INITIALIZER(head);
	struct zone_bool_gen bg = { };
	struct zone_stress_obj *obj;
	uint32_t allocs = 0;

	random_bool_init(&bg.zbg_bg);

	do {
		for (int i = 0; i < 2000; i++) {
			uint32_t what = random_bool_gen_bits(&bg.zbg_bg,
			    bg.zbg_entropy, ZONE_ENTROPY_CNT, 1);
			switch (what) {
			case 0:
			case 1:
				if (allocs < 10000) {
					obj = zalloc(ctx->zsc_zone);
					TAILQ_INSERT_HEAD(&head, obj, zso_link);
					allocs++;
				}
				break;
			case 2:
			case 3:
				if (allocs < 10000) {
					obj = zalloc(ctx->zsc_zone);
					TAILQ_INSERT_TAIL(&head, obj, zso_link);
					allocs++;
				}
				break;
			case 4:
				if (leader) {
					zone_gc(ZONE_GC_DRAIN);
				}
				break;
			case 5:
			case 6:
				if (!TAILQ_EMPTY(&head)) {
					obj = TAILQ_FIRST(&head);
					TAILQ_REMOVE(&head, obj, zso_link);
					zfree(ctx->zsc_zone, obj);
					allocs--;
				}
				break;
			case 7:
				if (!TAILQ_EMPTY(&head)) {
					obj = TAILQ_LAST(&head, zone_stress_head);
					TAILQ_REMOVE(&head, obj, zso_link);
					zfree(ctx->zsc_zone, obj);
					allocs--;
				}
				break;
			}
		}
	} while (mach_absolute_time() < ctx->zsc_end);

	while (!TAILQ_EMPTY(&head)) {
		obj = TAILQ_FIRST(&head);
		TAILQ_REMOVE(&head, obj, zso_link);
		zfree(ctx->zsc_zone, obj);
	}

	lck_mtx_lock(&ctx->zsc_lock);
	if (--ctx->zsc_workers == 0) {
		thread_wakeup(ctx);
	} else if (leader) {
		while (ctx->zsc_workers) {
			lck_mtx_sleep(&ctx->zsc_lock, LCK_SLEEP_DEFAULT, ctx,
			    THREAD_UNINT);
		}
	}
	lck_mtx_unlock(&ctx->zsc_lock);

	if (!leader) {
		thread_terminate_self();
		__builtin_unreachable();
	}
}

static int
zone_stress_test_run(__unused int64_t in, int64_t *out)
{
	struct zone_stress_ctx ctx = {
		.zsc_leader  = current_thread(),
		.zsc_workers = 3,
	};
	kern_return_t kr;
	thread_t th;

	if (os_atomic_xchg(&any_zone_test_running, true, relaxed)) {
		printf("zone_stress_test: Test already running.\n");
		return EALREADY;
	}

	lck_mtx_init(&ctx.zsc_lock, &zone_locks_grp, LCK_ATTR_NULL);
	ctx.zsc_zone = zone_create("test_zone_344", 344,
	    ZC_DESTRUCTIBLE | ZC_NOCACHING);
	assert(ctx.zsc_zone->z_chunk_pages > 1);

	clock_interval_to_deadline(5, NSEC_PER_SEC, &ctx.zsc_end);

	printf("zone_stress_test: Starting (leader %p)\n", current_thread());

	os_atomic_inc(&zalloc_simulate_vm_pressure, relaxed);

	for (uint32_t i = 1; i < ctx.zsc_workers; i++) {
		kr = kernel_thread_start_priority(zone_stress_worker, &ctx,
		    BASEPRI_DEFAULT, &th);
		if (kr == KERN_SUCCESS) {
			printf("zone_stress_test: thread %d: %p\n", i, th);
			thread_deallocate(th);
		} else {
			ctx.zsc_workers--;
		}
	}

	zone_stress_worker(&ctx, 0);

	lck_mtx_destroy(&ctx.zsc_lock, &zone_locks_grp);

	zdestroy(ctx.zsc_zone);

	printf("zone_stress_test: Done\n");

	*out = 1;
	os_atomic_dec(&zalloc_simulate_vm_pressure, relaxed);
	os_atomic_store(&any_zone_test_running, false, relaxed);
	return 0;
}
SYSCTL_TEST_REGISTER(zone_stress_test, zone_stress_test_run);

/*
 * Routines to test that zone garbage collection and zone replenish threads
 * running at the same time don't cause problems.
 */

static int
zone_gc_replenish_test(__unused int64_t in, int64_t *out)
{
	zone_gc(ZONE_GC_DRAIN);
	*out = 1;
	return 0;
}
SYSCTL_TEST_REGISTER(zone_gc_replenish_test, zone_gc_replenish_test);

static int
zone_alloc_replenish_test(__unused int64_t in, int64_t *out)
{
	zone_t z = vm_map_entry_zone;
	struct data { struct data *next; } *node, *list = NULL;

	if (z == NULL) {
		printf("Couldn't find a replenish zone\n");
		return EIO;
	}

	/* big enough to go past replenishment */
	for (uint32_t i = 0; i < 10 * z->z_elems_rsv; ++i) {
		node = zalloc(z);
		node->next = list;
		list = node;
	}

	/*
	 * release the memory we allocated
	 */
	while (list != NULL) {
		node = list;
		list = list->next;
		zfree(z, node);
	}

	*out = 1;
	return 0;
}
SYSCTL_TEST_REGISTER(zone_alloc_replenish_test, zone_alloc_replenish_test);

#endif /* DEBUG || DEVELOPMENT */
