/*
 * Copyright (c) 2020-2021, 2023 Apple Inc. All rights reserved.
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
#include <arm/cpu_data_internal.h>
#include <kern/queue.h>
#include <libkern/OSAtomic.h>
#include <libkern/section_keywords.h>
#include <pexpert/device_tree.h>
#include <os/atomic_private.h>
#include <vm/cpm.h>
#include <vm/vm_kern.h>
#include <vm/vm_protos.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pageout.h>

#include <arm/pmap/pmap_internal.h>

/**
 * Physical Page Attribute Table.
 *
 * Array that contains a set of flags for each kernel-managed physical VM page.
 *
 * @note There can be a disparity between the VM page size and the underlying
 *       hardware page size for a specific address space. In those cases, it's
 *       possible that multiple hardware pages will share the same set of
 *       attributes. The VM operates on regions of memory by the VM page size
 *       and is aware that all hardware pages within each VM page share
 *       attributes.
 */
SECURITY_READ_ONLY_LATE(volatile pp_attr_t*) pp_attr_table = (volatile pp_attr_t*)NULL;

/**
 * Physical to Virtual Table.
 *
 * Data structure that contains a list of virtual mappings for each kernel-
 * managed physical page. Other flags and metadata are also stored in this
 * structure on a per-physical-page basis.
 *
 * This structure is arranged as an array of pointers, where each pointer can
 * point to one of three different types of data (single mapping, multiple
 * mappings, or page table descriptor). Metadata about each page (including the
 * type of pointer) are located in the lower and upper bits of the pointer.
 * These bits need to be set/masked out to be able to dereference the pointer,
 * so it's recommended to use the provided API in pmap_data.h to access the
 * pv_head_table since it handles these details for you.
 */
SECURITY_READ_ONLY_LATE(pv_entry_t * *) pv_head_table = (pv_entry_t**)NULL;

/**
 * Queue chain of userspace page table pages that can be quickly reclaimed by
 * pmap_page_reclaim() in cases where the a page can't easily be allocated
 * the normal way, but the caller needs a page quickly.
 */
static queue_head_t pt_page_list MARK_AS_PMAP_DATA;

/* Lock for pt_page_list. */
static MARK_AS_PMAP_DATA SIMPLE_LOCK_DECLARE(pt_pages_lock, 0);

/* Simple linked-list structure used in various page free lists. */
typedef struct page_free_entry {
	/**
	 * The first word in an empty page on a free list is used as a pointer to
	 * the next free page in the list.
	 */
	struct page_free_entry *next;
} page_free_entry_t;

/* Represents a NULL entry in various page free lists. */
#define PAGE_FREE_ENTRY_NULL ((page_free_entry_t *) 0)

/**
 * pmap_page_reclaim() is called in critical, latency-sensitive code paths when
 * either the VM doesn't have any pages available (on non-PPL systems), or the
 * PPL page free lists are empty (on PPL systems). Before it attempts to reclaim
 * a userspace page table page (which will have performance penalties), it will
 * first try allocating a page from this high-priority free list.
 *
 * When the pmap is starved for memory and starts relying on
 * pmap_page_reclaim() to allocate memory, then the next page being freed will
 * be placed onto this list for usage only by pmap_page_reclaim(). Typically
 * that page will be a userspace page table that was just reclaimed.
 */
static page_free_entry_t *pmap_page_reclaim_list MARK_AS_PMAP_DATA = PAGE_FREE_ENTRY_NULL;

/**
 * Current number of pending requests to reclaim a page table page. This is used
 * as an indicator to pmap_pages_free() to place any freed pages into the high
 * priority pmap_page_reclaim() free list so that the next invocations of
 * pmap_page_reclaim() can use them. Typically this will be a userspace page
 * table that was just reclaimed.
 */
static unsigned int pmap_pages_request_count MARK_AS_PMAP_DATA = 0;

/**
 * Total number of pages that have been requested from pmap_page_reclaim() since
 * cold boot.
 */
static unsigned long long pmap_pages_request_acum MARK_AS_PMAP_DATA = 0;

/* Lock for the pmap_page_reclaim() high-priority free list. */
static MARK_AS_PMAP_DATA SIMPLE_LOCK_DECLARE(pmap_page_reclaim_lock, 0);

#if XNU_MONITOR
/**
 * The PPL cannot invoke the VM in order to allocate memory, so we must maintain
 * a list of free pages that the PPL owns. The kernel can give the PPL
 * additional pages by grabbing pages from the VM and marking them as PPL-owned.
 * See pmap_alloc_page_for_ppl() for more information.
 */
static page_free_entry_t *pmap_ppl_free_page_list MARK_AS_PMAP_DATA = PAGE_FREE_ENTRY_NULL;

/* The current number of pages in the PPL page free list. */
uint64_t pmap_ppl_free_page_count MARK_AS_PMAP_DATA = 0;

/* Lock for the PPL page free list. */
static MARK_AS_PMAP_DATA SIMPLE_LOCK_DECLARE(pmap_ppl_free_page_lock, 0);
#endif /* XNU_MONITOR */

/**
 * This VM object will contain every VM page being used by the pmap. This acts
 * as a convenient place to put pmap pages to keep the VM from reusing them, as
 * well as providing a way for looping over every page being used by the pmap.
 */
struct vm_object pmap_object_store VM_PAGE_PACKED_ALIGNED;

/* Pointer to the pmap's VM object that can't be modified after machine_lockdown(). */
SECURITY_READ_ONLY_LATE(vm_object_t) pmap_object = &pmap_object_store;

/**
 * Global variables strictly used for debugging purposes. These variables keep
 * track of the total number of pages that have been allocated from the VM for
 * pmap usage since cold boot, as well as how many are currently in use by the
 * pmap. Once a page is given back to the VM, then the inuse_pmap_pages_count
 * will be decremented.
 *
 * Even if a page is sitting in one of the pmap's various free lists and hasn't
 * been allocated for usage, these are still considered "used" by the pmap, from
 * the perspective of the VM.
 */
static uint64_t alloc_pmap_pages_count __attribute__((aligned(8))) = 0LL;
unsigned int inuse_pmap_pages_count = 0;

/**
 * Default watermark values used to keep a healthy supply of physical-to-virtual
 * entries (PVEs) always available. These values can be overriden by the device
 * tree (see pmap_compute_pv_targets() for more info).
 */
#if XNU_MONITOR
/*
 * Increase the padding for PPL devices to accommodate increased mapping
 * pressure from IOMMUs. This isn't strictly necessary, but will reduce the need
 * to retry mappings due to PV allocation failure.
 */
#define PV_KERN_LOW_WATER_MARK_DEFAULT (0x400)
#define PV_ALLOC_CHUNK_INITIAL         (0x400)
#define PV_KERN_ALLOC_CHUNK_INITIAL    (0x400)
#else /* XNU_MONITOR */
#define PV_KERN_LOW_WATER_MARK_DEFAULT (0x200)
#define PV_ALLOC_CHUNK_INITIAL         (0x200)
#define PV_KERN_ALLOC_CHUNK_INITIAL    (0x200)
#endif /* XNU_MONITOR */

/**
 * The pv_free array acts as a ring buffer where each entry points to a linked
 * list of PVEs that have a length set by this define.
 */
#define PV_BATCH_SIZE (PAGE_SIZE / sizeof(pv_entry_t))

/* The batch allocation code assumes that a batch can fit within a single page. */
#if defined(__arm64__) && __ARM_16K_PG__
/**
 * PAGE_SIZE is a variable on arm64 systems with 4K VM pages, so no static
 * assert on those systems.
 */
static_assert((PV_BATCH_SIZE * sizeof(pv_entry_t)) <= PAGE_SIZE);
#endif /* defined(__arm64__) && __ARM_16K_PG__ */

/**
 * The number of PVEs to attempt to keep in the kernel-dedicated free list. If
 * the number of entries is below this value, then allocate more.
 */
static uint32_t pv_kern_low_water_mark MARK_AS_PMAP_DATA = PV_KERN_LOW_WATER_MARK_DEFAULT;

/**
 * The initial number of PVEs to allocate during bootstrap (can be overriden in
 * the device tree, see pmap_compute_pv_targets() for more info).
 */
uint32_t pv_alloc_initial_target MARK_AS_PMAP_DATA = PV_ALLOC_CHUNK_INITIAL * MAX_CPUS;
uint32_t pv_kern_alloc_initial_target MARK_AS_PMAP_DATA = PV_KERN_ALLOC_CHUNK_INITIAL;

/**
 * Global variables strictly used for debugging purposes. These variables keep
 * track of the number of pages being used for PVE objects, and the total number
 * of PVEs that have been added to the global or kernel-dedicated free lists
 * respectively.
 */
static uint32_t pv_page_count MARK_AS_PMAP_DATA = 0;
static unsigned pmap_reserve_replenish_stat MARK_AS_PMAP_DATA = 0;
static unsigned pmap_kern_reserve_alloc_stat MARK_AS_PMAP_DATA = 0;

/**
 * Number of linked lists of PVEs ("batches") in the global PV free ring buffer.
 * This must be a power of two for the pv_free_array_n_elems() logic to work.
 */
#define PV_FREE_ARRAY_SIZE (256U)

/**
 * A ring buffer where each entry in the buffer is a linked list of PV entries
 * (called "batches"). Allocations out of this array will always operate on
 * a PV_BATCH_SIZE amount of entries at a time.
 */
static pv_free_list_t pv_free_ring[PV_FREE_ARRAY_SIZE] MARK_AS_PMAP_DATA = {0};

/* Read and write indices for the pv_free ring buffer. */
static uint16_t pv_free_read_idx MARK_AS_PMAP_DATA = 0;
static uint16_t pv_free_write_idx MARK_AS_PMAP_DATA = 0;

/**
 * Make sure the PV free array is small enough so that all elements can be
 * properly indexed by pv_free_[read/write]_idx.
 */
static_assert(PV_FREE_ARRAY_SIZE <= (1 << (sizeof(pv_free_read_idx) * 8)));

/**
 * Return the number of free batches available for allocation out of the PV free
 * ring buffer. Each batch is a linked list of PVEs with length PV_BATCH_SIZE.
 *
 * @note This function requires that PV_FREE_ARRAY_SIZE is a power of two.
 */
static inline uint16_t
pv_free_array_n_elems(void)
{
	return (pv_free_write_idx - pv_free_read_idx) & (PV_FREE_ARRAY_SIZE - 1);
}

/* Free list of PV entries dedicated for usage by the kernel. */
static pv_free_list_t pv_kern_free MARK_AS_PMAP_DATA = {0};

/* Locks for the global and kernel-dedicated PV free lists. */
static MARK_AS_PMAP_DATA SIMPLE_LOCK_DECLARE(pv_free_array_lock, 0);
static MARK_AS_PMAP_DATA SIMPLE_LOCK_DECLARE(pv_kern_free_list_lock, 0);

/* Represents a null page table descriptor (PTD). */
#define PTD_ENTRY_NULL ((pt_desc_t *) 0)

/* Running free list of PTD nodes. */
static pt_desc_t *ptd_free_list MARK_AS_PMAP_DATA = PTD_ENTRY_NULL;

/* The number of free PTD nodes available in the free list. */
static unsigned int ptd_free_count MARK_AS_PMAP_DATA = 0;

/**
 * The number of PTD objects located in each page being used by the PTD
 * allocator. The PTD objects share each page with their associated ptd_info_t
 * objects (with cache-line alignment padding between them). The maximum number
 * of PTDs that can be placed into a single page is calculated once at boot.
 */
static SECURITY_READ_ONLY_LATE(unsigned) ptd_per_page = 0;

/**
 * The offset in bytes from the beginning of a page of PTD objects where you
 * start seeing the associated ptd_info_t objects. This is calculated once
 * during boot to maximize the number of PTD and ptd_info_t objects that can
 * reside within a page without sharing a cache-line.
 */
static SECURITY_READ_ONLY_LATE(unsigned) ptd_info_offset = 0;

/* Lock to protect accesses to the PTD free list. */
static decl_simple_lock_data(, ptd_free_list_lock MARK_AS_PMAP_DATA);

/**
 * Dummy _internal() prototypes so Clang doesn't complain about missing
 * prototypes on a non-static function. These functions can't be marked as
 * static because they need to be called from pmap_ppl_interface.c where the
 * PMAP_SUPPORT_PROTOYPES() macro will auto-generate the prototype implicitly.
 */
kern_return_t mapping_free_prime_internal(void);

#if XNU_MONITOR

/**
 * These types and variables only exist on PPL-enabled systems because those are
 * the only systems that need to allocate and manage ledger/pmap objects
 * themselves. On non-PPL systems, those objects are allocated using a standard
 * zone allocator.
 */

/**
 * Specify that the maximum number of ledgers and pmap objects are to be
 * correlated to the maximum number of tasks allowed on the system (at most,
 * we'll have one pmap object per task). For ledger objects, give a small amount
 * of extra padding to account for allocation differences between pmap objects
 * and ledgers (i.e. ~10% of total number of iOS tasks = 200).
 *
 * These defines are only valid once `pmap_max_asids` is initialized in
 * pmap_bootstrap() (the value can change depending on the device tree).
 */
#define LEDGER_PTR_ARRAY_SIZE (pmap_max_asids + 200)
#define PMAP_PTR_ARRAY_SIZE (pmap_max_asids)

/**
 * Each ledger object consists of a variable number of ledger entries that is
 * determined by the template it's based on. The template used for pmap ledger
 * objects is the task_ledgers template.
 *
 * This define attempts to calculate how large each pmap ledger needs to be
 * based on how many ledger entries exist in the task_ledgers template. This is
 * found by counting how many integers exist in the task_ledgers structure (each
 * integer represents the index for a ledger_entry) and multiplying by the size
 * of a single ledger entry. That value is then added to the other fields in a
 * ledger structure to get the total size of a single pmap ledger.
 *
 * Some of the task ledger's entries use a smaller struct format. TASK_LEDGER_NUM_SMALL_INDICES
 * is used to determine how much memory we need for those entries.
 *
 * This assumed size will get validated when the task_ledgers template is
 * created and the system will panic if this calculation wasn't correct.
 *
 */
#define PMAP_LEDGER_DATA_BYTES \
	(((sizeof(task_ledgers) / sizeof(int) - TASK_LEDGER_NUM_SMALL_INDICES) * sizeof(struct ledger_entry) \
	  + TASK_LEDGER_NUM_SMALL_INDICES * sizeof(struct ledger_entry_small)) \
	  + sizeof(struct ledger))

/**
 * Opaque data structure that contains the exact number of bytes required to
 * hold a single ledger object based off of the task_ledgers template.
 */
typedef struct pmap_ledger_data {
	uint8_t pld_data[PMAP_LEDGER_DATA_BYTES];
} pmap_ledger_data_t;

/**
 * This struct contains the memory needed to hold a single ledger object used by
 * the pmap as well as an index into the pmap_ledger_ptr_array used for
 * validating ledger objects passed into the PPL.
 */
typedef struct pmap_ledger {
	/**
	 * Either contain the memory needed for a ledger object based on the
	 * task_ledgers template (if already allocated) or a pointer to the next
	 * ledger object in the free list if the object hasn't been allocated yet.
	 *
	 * This union has to be the first member of this struct so that the memory
	 * used by this struct can be correctly cast to a ledger_t and used
	 * as a normal ledger object by the standard ledger API.
	 */
	union {
		struct pmap_ledger_data pld_data;
		struct pmap_ledger *next;
	};

	/**
	 * This extra piece of information (not normally associated with generic
	 * ledger_t objects) is used to validate that a ledger passed into the PPL
	 * is indeed a ledger that was allocated by the PPL, and not just random
	 * memory being passed off as a ledger object. See pmap_ledger_validate()
	 * for more information on validating ledger objects.
	 */
	unsigned long array_index;
} pmap_ledger_t;

/**
 * This variable is used to ensure that the size of the ledger objects being
 * allocated by the PPL match up with the actual size of the ledger objects
 * before objects start being allocated.
 */
static SECURITY_READ_ONLY_LATE(bool) pmap_ledger_size_verified = false;

/* Ledger free list lock. */
static MARK_AS_PMAP_DATA SIMPLE_LOCK_DECLARE(pmap_ledger_lock, 0);

/*
 * The pmap_ledger_t contents are allowed to be written outside the PPL,
 * so refcounts must be in a separate PPL-controlled array.
 */
static SECURITY_READ_ONLY_LATE(os_refcnt_t *) pmap_ledger_refcnt = NULL;

/**
 * The number of entries in the pmap ledger pointer and ledger refcnt arrays.
 * This determines the maximum number of pmap ledger objects that can be
 * allocated.
 *
 * This value might be slightly higher than LEDGER_PTR_ARRAY_SIZE because the
 * memory used for the array is rounded up to the nearest page boundary.
 */
static SECURITY_READ_ONLY_LATE(unsigned long) pmap_ledger_ptr_array_count = 0;

/**
 * This array is used to validate that ledger objects passed into the PPL were
 * allocated by the PPL and aren't just random memory being passed off as a
 * ledger object. It does this by associating each ledger object allocated by
 * the PPL with an index into this array. The value at that index will be a
 * pointer to the ledger object itself.
 *
 * Even though the ledger object is kernel-writable, this array is only
 * modifiable by the PPL. If a ledger object is passed into the PPL that has an
 * index into this array that doesn't match up, then the validation will fail.
 */
static SECURITY_READ_ONLY_LATE(pmap_ledger_t * *) pmap_ledger_ptr_array = NULL;

/**
 * The next free index into pmap_ledger_ptr_array to be given to the next
 * allocated ledger object.
 */
static uint64_t pmap_ledger_ptr_array_free_index MARK_AS_PMAP_DATA = 0;

/* Free list of pmap ledger objects. */
static pmap_ledger_t *pmap_ledger_free_list MARK_AS_PMAP_DATA = NULL;

/**
 * This struct contains the memory needed to hold a single pmap object as well
 * as an index into the pmap_ptr_array used for validating pmap objects passed
 * into the PPL.
 */
typedef struct pmap_list_entry {
	/**
	 * Either contain the memory needed for a single pmap object or a pointer to
	 * the next pmap object in the free list if the object hasn't been allocated
	 * yet.
	 *
	 * This union has to be the first member of this struct so that the memory
	 * used by this struct can be correctly cast as either a pmap_list_entry_t
	 * or a pmap_t (depending on whether the array_index is needed).
	 */
	union {
		struct pmap pmap;
		struct pmap_list_entry *next;
	};

	/**
	 * This extra piece of information (not normally associated with generic
	 * pmap objects) is used to validate that a pmap object passed into the PPL
	 * is indeed a pmap object that was allocated by the PPL, and not just random
	 * memory being passed off as a pmap object. See validate_pmap()
	 * for more information on validating pmap objects.
	 */
	unsigned long array_index;
} pmap_list_entry_t;

/* Lock for the pmap free list. */
static MARK_AS_PMAP_DATA SIMPLE_LOCK_DECLARE(pmap_free_list_lock, 0);

/**
 * The number of entries in the pmap pointer array. This determines the maximum
 * number of pmap objects that can be allocated.
 *
 * This value might be slightly higher than PMAP_PTR_ARRAY_SIZE because the
 * memory used for the array is rounded up to the nearest page boundary.
 */
static SECURITY_READ_ONLY_LATE(unsigned long) pmap_ptr_array_count = 0;

/**
 * This array is used to validate that pmap objects passed into the PPL were
 * allocated by the PPL and aren't just random memory being passed off as a pmap
 * object. It does this by associating each pmap object allocated by the PPL
 * with an index into this array. The value at that index will be a pointer to
 * the pmap object itself.
 *
 * If a pmap object is passed into the PPL that has an index into this array
 * that doesn't match up, then the validation will fail.
 */
static SECURITY_READ_ONLY_LATE(pmap_list_entry_t * *) pmap_ptr_array = NULL;

/**
 * The next free index into pmap_ptr_array to be given to the next
 * allocated pmap object.
 */
static unsigned long pmap_ptr_array_free_index MARK_AS_PMAP_DATA = 0;

/* Free list of pmap objects. */
static pmap_list_entry_t *pmap_free_list MARK_AS_PMAP_DATA = NULL;

#endif /* XNU_MONITOR */

/**
 * Sorted representation of the pmap-io-ranges nodes in the device tree. These
 * nodes describe all of the PPL-owned I/O ranges.
 */
SECURITY_READ_ONLY_LATE(pmap_io_range_t*) io_attr_table = (pmap_io_range_t*)0;

/* The number of ranges described by io_attr_table. */
SECURITY_READ_ONLY_LATE(unsigned int) num_io_rgns = 0;

/**
 * Sorted representation of the pmap-io-filter entries in the device tree
 * The entries are sorted and queried by {signature, range}.
 */
SECURITY_READ_ONLY_LATE(pmap_io_filter_entry_t*) io_filter_table = (pmap_io_filter_entry_t*)0;

/* Number of total pmap-io-filter entries. */
SECURITY_READ_ONLY_LATE(unsigned int) num_io_filter_entries = 0;

#if XNU_MONITOR

/**
 * Per-cpu pmap data. On PPL-enabled systems, this memory is only modifiable by
 * the PPL itself and because of that, needs to be managed separately from the
 * generic per-cpu data. The per-cpu pmap data exists on non-PPL systems as
 * well, it's just located within the general machine-specific per-cpu data.
 */
struct pmap_cpu_data_array_entry pmap_cpu_data_array[MAX_CPUS] MARK_AS_PMAP_DATA;

/**
 * The physical address spaces being used for the PPL stacks and PPL register
 * save area are stored in global variables so that their permissions can be
 * updated in pmap_static_allocations_done(). These regions are initialized by
 * pmap_cpu_data_array_init().
 */
SECURITY_READ_ONLY_LATE(pmap_paddr_t) pmap_stacks_start_pa = 0;
SECURITY_READ_ONLY_LATE(pmap_paddr_t) pmap_stacks_end_pa = 0;
SECURITY_READ_ONLY_LATE(pmap_paddr_t) ppl_cpu_save_area_start = 0;
SECURITY_READ_ONLY_LATE(pmap_paddr_t) ppl_cpu_save_area_end = 0;

#if HAS_GUARDED_IO_FILTER
SECURITY_READ_ONLY_LATE(pmap_paddr_t) iofilter_stacks_start_pa = 0;
SECURITY_READ_ONLY_LATE(pmap_paddr_t) iofilter_stacks_end_pa = 0;
#endif /* HAS_GUARDED_IO_FILTER */

#endif /* XNU_MONITOR */

/* Prototypes used by pmap_data_bootstrap(). */
vm_size_t pmap_compute_io_rgns(void);
void pmap_load_io_rgns(void);
void pmap_cpu_data_array_init(void);

#if HAS_GUARDED_IO_FILTER
vm_size_t pmap_compute_io_filters(void);
void pmap_load_io_filters(void);
#endif /* HAS_GUARDED_IO_FILTER */

/**
 * This function is called once during pmap_bootstrap() to allocate and
 * initialize many of the core data structures that are implemented in this
 * file.
 *
 * Memory for these data structures is carved out of `avail_start` which is a
 * global setup by arm_vm_init() that points to a physically contiguous region
 * used for bootstrap allocations.
 *
 * @note There is no guaranteed alignment of `avail_start` when this function
 *       returns. If avail_start needs to be aligned to a specific value then it
 *       must be done so by the caller before they use it for more allocations.
 */
void
pmap_data_bootstrap(void)
{
	/**
	 * Set ptd_per_page to the maximum number of (pt_desc_t + ptd_info_t) we can
	 * fit in a single page. We need to allow for some padding between the two,
	 * so that no ptd_info_t shares a cache line with a pt_desc_t.
	 */
	const unsigned ptd_info_size = sizeof(ptd_info_t) * PT_INDEX_MAX;
	const unsigned l2_cline_bytes = 1 << MAX_L2_CLINE;
	ptd_per_page = (PAGE_SIZE - (l2_cline_bytes - 1)) / (sizeof(pt_desc_t) + ptd_info_size);
	unsigned increment = 0;
	bool try_next = true;

	/**
	 * The current ptd_per_page calculation was done assuming the worst-case
	 * scenario in terms of padding between the two object arrays that reside in
	 * the same page. The following loop attempts to optimize this further by
	 * finding the smallest possible amount of padding while still ensuring that
	 * the two object arrays don't share a cache line.
	 */
	while (try_next) {
		increment++;
		const unsigned pt_desc_total_size =
		    PMAP_ALIGN((ptd_per_page + increment) * sizeof(pt_desc_t), l2_cline_bytes);
		const unsigned ptd_info_total_size = (ptd_per_page + increment) * ptd_info_size;
		try_next = (pt_desc_total_size + ptd_info_total_size) <= PAGE_SIZE;
	}
	ptd_per_page += increment - 1;
	assert(ptd_per_page > 0);

	/**
	 * ptd_info objects reside after the ptd descriptor objects, with some
	 * padding in between if necessary to ensure that they don't co-exist in the
	 * same cache line.
	 */
	const unsigned pt_desc_bytes = ptd_per_page * sizeof(pt_desc_t);
	ptd_info_offset = PMAP_ALIGN(pt_desc_bytes, l2_cline_bytes);

	/* The maximum amount of padding should be (l2_cline_bytes - 1). */
	assert((ptd_info_offset - pt_desc_bytes) < l2_cline_bytes);

	/**
	 * Allocate enough initial PTDs to map twice the available physical memory.
	 *
	 * To do this, start by calculating the number of leaf page tables that are
	 * needed to cover all of kernel-managed physical memory.
	 */
	const uint32_t num_leaf_page_tables =
	    (uint32_t)(mem_size / ((PAGE_SIZE / sizeof(pt_entry_t)) * ARM_PGBYTES));

	/**
	 * There should be one PTD per page table (times 2 since we want twice the
	 * number of required PTDs), plus round the number of PTDs up to the next
	 * `ptd_per_page` value so there's no wasted space.
	 */
	const uint32_t ptd_root_table_n_ptds =
	    (ptd_per_page * ((num_leaf_page_tables * 2) / ptd_per_page)) + ptd_per_page;

	/* Lastly, calculate the number of VM pages and bytes these PTDs take up. */
	const uint32_t num_ptd_pages = ptd_root_table_n_ptds / ptd_per_page;
	vm_size_t ptd_root_table_size = num_ptd_pages * PAGE_SIZE;

	/* Number of VM pages that span all of kernel-managed memory. */
	const unsigned int npages = (unsigned int)atop(mem_size);

	/* The pv_head_table and pp_attr_table both have one entry per VM page. */
	const vm_size_t pp_attr_table_size = npages * sizeof(pp_attr_t);
	const vm_size_t pv_head_size = round_page(npages * sizeof(pv_entry_t *));

	/* Scan the device tree and override heuristics in the PV entry management code. */
	pmap_compute_pv_targets();

	/* Scan the device tree and figure out how many PPL-owned I/O regions there are. */
	const vm_size_t io_attr_table_size = pmap_compute_io_rgns();

#if HAS_GUARDED_IO_FILTER
	/* Scan the device tree for the size of pmap-io-filter entries. */
	const vm_size_t io_filter_table_size = pmap_compute_io_filters();
#endif /* HAS_GUARDED_IO_FILTER */

	/**
	 * Don't make any assumptions about the alignment of avail_start before
	 * execution of this function. Always re-align it to ensure the first
	 * allocated data structure is aligned correctly.
	 */
	avail_start = PMAP_ALIGN(avail_start, __alignof(pp_attr_t));

	/**
	 * Keep track of where the data structures start so we can clear this memory
	 * later.
	 */
	const pmap_paddr_t pmap_struct_start = avail_start;

	pp_attr_table = (pp_attr_t *)phystokv(avail_start);
	avail_start = PMAP_ALIGN(avail_start + pp_attr_table_size, __alignof(pmap_io_range_t));

	io_attr_table = (pmap_io_range_t *)phystokv(avail_start);

 #if HAS_GUARDED_IO_FILTER
	/* Align avail_start to size of I/O filter entry. */
	avail_start = PMAP_ALIGN(avail_start + io_attr_table_size, __alignof(pmap_io_filter_entry_t));

	/* Allocate memory for io_filter_table. */
	if (num_io_filter_entries != 0) {
		io_filter_table = (pmap_io_filter_entry_t *)phystokv(avail_start);
	}

	/* Align avail_start for the next structure to be allocated. */
	avail_start = PMAP_ALIGN(avail_start + io_filter_table_size, __alignof(pv_entry_t *));
#else /* !HAS_GUARDED_IO_FILTER */
	avail_start = PMAP_ALIGN(avail_start + io_attr_table_size, __alignof(pv_entry_t *));
#endif /* HAS_GUARDED_IO_FILTER */

	pv_head_table = (pv_entry_t **)phystokv(avail_start);

	/**
	 * ptd_root_table must start on a page boundary because all of the math for
	 * associating pt_desc_t objects with ptd_info objects assumes the first
	 * pt_desc_t in a page starts at the beginning of the page it resides in.
	 */
	avail_start = round_page(avail_start + pv_head_size);

	pt_desc_t *ptd_root_table = (pt_desc_t *)phystokv(avail_start);
	avail_start = round_page(avail_start + ptd_root_table_size);

	memset((char *)phystokv(pmap_struct_start), 0, avail_start - pmap_struct_start);

	/* This function assumes that ptd_root_table has been zeroed out already. */
	ptd_bootstrap(ptd_root_table, num_ptd_pages);

	/* Load data about the PPL-owned I/O regions into io_attr_table and sort it. */
	pmap_load_io_rgns();

#if HAS_GUARDED_IO_FILTER
	/* Load the I/O filters into io_filter_table and sort them. */
	pmap_load_io_filters();
#endif /* HAS_GUARDED_IO_FILTER */

#if XNU_MONITOR
	/**
	 * Each of these PPL-only data structures are rounded to the nearest page
	 * beyond their predefined size so as to provide a small extra buffer of
	 * objects and to make it easy to perform page-sized operations on them if
	 * the need ever arises.
	 */
	const vm_map_address_t pmap_ptr_array_begin = phystokv(avail_start);
	pmap_ptr_array = (pmap_list_entry_t**)pmap_ptr_array_begin;
	avail_start += round_page(PMAP_PTR_ARRAY_SIZE * sizeof(*pmap_ptr_array));
	const vm_map_address_t pmap_ptr_array_end = phystokv(avail_start);

	pmap_ptr_array_count = ((pmap_ptr_array_end - pmap_ptr_array_begin) / sizeof(*pmap_ptr_array));

	const vm_map_address_t pmap_ledger_ptr_array_begin = phystokv(avail_start);
	pmap_ledger_ptr_array = (pmap_ledger_t**)pmap_ledger_ptr_array_begin;
	avail_start += round_page(LEDGER_PTR_ARRAY_SIZE * sizeof(*pmap_ledger_ptr_array));
	const vm_map_address_t pmap_ledger_ptr_array_end = phystokv(avail_start);
	pmap_ledger_ptr_array_count = ((pmap_ledger_ptr_array_end - pmap_ledger_ptr_array_begin) / sizeof(*pmap_ledger_ptr_array));

	pmap_ledger_refcnt = (os_refcnt_t*)phystokv(avail_start);
	avail_start += round_page(pmap_ledger_ptr_array_count * sizeof(*pmap_ledger_refcnt));
#endif /* XNU_MONITOR */

	/**
	 * Setup the pmap per-cpu data structures (includes the PPL stacks, and PPL
	 * register save area). The pmap per-cpu data is managed separately from the
	 * general machine-specific per-cpu data on PPL systems so it can be made
	 * only writable by the PPL.
	 */
	pmap_cpu_data_array_init();
}

/**
 * Helper function for pmap_page_reclaim (hereby shortened to "ppr") which scans
 * the list of userspace page table pages for one(s) that can be reclaimed. To
 * be eligible, a page table must not have any wired PTEs, must contain at least
 * one valid PTE, can't be nested, and the pmap that owns that page table must
 * not already be locked.
 *
 * @note This should only be called from pmap_page_reclaim().
 *
 * @note If an eligible page table was found, then the pmap which contains that
 *       page table will be locked exclusively.
 *
 * @note On systems where multiple page tables exist within one page, all page
 *       tables within a page have to be eligible for that page to be considered
 *       reclaimable.
 *
 * @param ptdpp Output parameter which will contain a pointer to the page table
 *              descriptor for the page table(s) that can be reclaimed (if any
 *              were found). If no page table was found, this will be set to
 *              NULL.
 *
 * @return True if an eligible table was found, false otherwise. In the case
 *         that a page table was found, ptdpp will be a pointer to the page
 *         table descriptor for the table(s) that can be reclaimed. Otherwise
 *         it'll be set to NULL.
 */
MARK_AS_PMAP_TEXT static bool
ppr_find_eligible_pt_page(pt_desc_t **ptdpp)
{
	assert(ptdpp != NULL);

	pmap_simple_lock(&pt_pages_lock);
	pt_desc_t *ptdp = (pt_desc_t *)queue_first(&pt_page_list);

	while (!queue_end(&pt_page_list, (queue_entry_t)ptdp)) {
		/* Skip this pmap if it's nested or already locked. */
		if ((ptdp->pmap->type != PMAP_TYPE_USER) ||
		    (!pmap_try_lock(ptdp->pmap, PMAP_LOCK_EXCLUSIVE))) {
			ptdp = (pt_desc_t *)queue_next((queue_t)ptdp);
			continue;
		}

		assert(ptdp->pmap != kernel_pmap);

		unsigned refcnt_acc = 0;
		unsigned wiredcnt_acc = 0;
		const pt_attr_t * const pt_attr = pmap_get_pt_attr(ptdp->pmap);

		/**
		 * On systems where the VM page size differs from the hardware
		 * page size, then multiple page tables can exist within one VM page.
		 */
		for (unsigned i = 0; i < (PAGE_SIZE / pt_attr_page_size(pt_attr)); i++) {
			/* Do not attempt to free a page that contains an L2 table. */
			if (ptdp->ptd_info[i].refcnt == PT_DESC_REFCOUNT) {
				refcnt_acc = 0;
				break;
			}

			refcnt_acc += ptdp->ptd_info[i].refcnt;
			wiredcnt_acc += ptdp->ptd_info[i].wiredcnt;
		}

		/**
		 * If we've found a page with no wired entries, but valid PTEs then
		 * choose it for reclamation.
		 */
		if ((wiredcnt_acc == 0) && (refcnt_acc != 0)) {
			*ptdpp = ptdp;
			pmap_simple_unlock(&pt_pages_lock);

			/**
			 * Leave ptdp->pmap locked here. We're about to reclaim a page table
			 * from it, so we don't want anyone else messing with it while we do
			 * that.
			 */
			return true;
		}

		/**
		 * This page table/PTD wasn't eligible, unlock its pmap and move to the
		 * next one in the queue.
		 */
		pmap_unlock(ptdp->pmap, PMAP_LOCK_EXCLUSIVE);
		ptdp = (pt_desc_t *)queue_next((queue_t)ptdp);
	}

	pmap_simple_unlock(&pt_pages_lock);
	*ptdpp = NULL;

	return false;
}

/**
 * Helper function for pmap_page_reclaim (hereby shortened to "ppr") which frees
 * every page table within a page so that that page can get reclaimed.
 *
 * @note This should only be called from pmap_page_reclaim() and is only meant
 *       to delete page tables deemed eligible for reclaiming by
 *       ppr_find_eligible_pt_page().
 *
 * @param ptdp The page table descriptor whose page table(s) will get freed.
 *
 * @return KERN_SUCCESS on success. KERN_RESOURCE_SHORTAGE if the page is not
 *         removed due to pending preemption.
 */
MARK_AS_PMAP_TEXT static kern_return_t
ppr_remove_pt_page(pt_desc_t *ptdp)
{
	assert(ptdp != NULL);

	bool need_strong_sync = false;
	tt_entry_t *ttep = TT_ENTRY_NULL;
	pt_entry_t *ptep = PT_ENTRY_NULL;
	pt_entry_t *begin_pte = PT_ENTRY_NULL;
	pt_entry_t *end_pte = PT_ENTRY_NULL;
	pmap_t pmap = ptdp->pmap;

	/**
	 * The pmap exclusive lock should have gotten locked when the eligible page
	 * table was found in ppr_find_eligible_pt_page().
	 */
	pmap_assert_locked(pmap, PMAP_LOCK_EXCLUSIVE);

	const pt_attr_t * const pt_attr = pmap_get_pt_attr(pmap);
	const uint64_t hw_page_size = pt_attr_page_size(pt_attr);

	/**
	 * On some systems, one page table descriptor can represent multiple page
	 * tables. In that case, remove every table within the wanted page so we
	 * can reclaim it.
	 */
	for (unsigned i = 0; i < (PAGE_SIZE / hw_page_size); i++) {
		const vm_map_address_t va = ptdp->va[i];

		/**
		 * If the VA is bogus, this may represent an unallocated region or one
		 * which is in transition (already being freed or expanded). Don't try
		 * to remove mappings here.
		 */
		if (va == (vm_offset_t)-1) {
			continue;
		}

		/* Get the twig table entry that points to the table to reclaim. */
		ttep = pmap_tte(pmap, va);

		/* If the twig entry is either invalid or a block mapping, skip it. */
		if ((ttep == TT_ENTRY_NULL) ||
		    ((*ttep & ARM_TTE_TYPE_MASK) != ARM_TTE_TYPE_TABLE)) {
			continue;
		}

		ptep = (pt_entry_t *)ttetokv(*ttep);
		begin_pte = &ptep[pte_index(pt_attr, va)];
		end_pte = begin_pte + (hw_page_size / sizeof(pt_entry_t));
		vm_map_address_t eva = 0;

		/**
		 * Remove all mappings in the page table being reclaimed.
		 *
		 * Use PMAP_OPTIONS_REMOVE to clear any "compressed" markers and
		 * update the "compressed" counter in the ledger. This means that
		 * we lose accounting for any compressed pages in this range but the
		 * alternative is to not be able to account for their future
		 * decompression, which could cause the counter to drift more and
		 * more.
		 */
		int pte_changed = pmap_remove_range_options(
			pmap, va, begin_pte, end_pte, &eva, &need_strong_sync, PMAP_OPTIONS_REMOVE);

		const vm_offset_t expected_va_end = va + (size_t)pt_attr_leaf_table_size(pt_attr);

		if (eva == expected_va_end) {
			/**
			 * Free the page table now that all of its mappings have been removed.
			 * Once all page tables within a page have been deallocated, then the
			 * page that contains the table(s) will be freed and made available for
			 * reuse.
			 */
			pmap_tte_deallocate(pmap, va, expected_va_end, need_strong_sync, ttep, pt_attr_twig_level(pt_attr));
			pmap_lock(pmap, PMAP_LOCK_EXCLUSIVE); /* pmap_tte_deallocate() dropped the lock */
		} else {
			/**
			 * pmap_remove_range_options() returned earlier than expected,
			 * indicating there is emergent preemption pending. We should
			 * bail out, despite some of the mappings were removed in vain.
			 * They have to take the penalty of page faults to be brought
			 * back, but we don't want to miss the preemption deadline and
			 * panic.
			 */
			assert(eva < expected_va_end);

			/**
			 * In the normal path, we expect pmap_tte_deallocate() to flush
			 * the TLB for us. However, on the abort path here, we need to
			 * handle it here explicitly. If there is any mapping updated,
			 * update the TLB. */
			if (pte_changed > 0) {
				pmap_get_pt_ops(pmap)->flush_tlb_region_async(va, (size_t) (eva - va), pmap, false, need_strong_sync);
				arm64_sync_tlb(need_strong_sync);
			}

			pmap_unlock(pmap, PMAP_LOCK_EXCLUSIVE);
			return KERN_ABORTED;
		}
	}

	/**
	 * We're done modifying page tables, so undo the lock that was grabbed when
	 * we found the table(s) to reclaim in ppr_find_eligible_pt_page().
	 */
	pmap_unlock(pmap, PMAP_LOCK_EXCLUSIVE);
	return KERN_SUCCESS;
}

/**
 * Attempt to return a page by freeing an active page-table page. To be eligible
 * for reclaiming, a page-table page must be assigned to a non-kernel pmap, it
 * must not have any wired PTEs and must contain at least one valid PTE.
 *
 * @note This function is potentially invoked when PMAP_PAGE_RECLAIM_NOWAIT is
 *       passed as an option to pmap_pages_alloc_zeroed().
 *
 * @note Invocations of this function are only meant to occur in critical paths
 *       that absolutely can't take the latency hit of waiting for the VM or
 *       jumping out of the PPL to allocate more pages. Reclaiming a page table
 *       page can cause a performance hit when one of the removed mappings is
 *       next accessed (forcing the VM to fault and re-insert the mapping).
 *
 * @return The physical address of the page that was allocated, or zero if no
 *         suitable page was found on the page-table list.
 */
MARK_AS_PMAP_TEXT static pmap_paddr_t
pmap_page_reclaim(void)
{
	pmap_simple_lock(&pmap_page_reclaim_lock);
	pmap_pages_request_count++;
	pmap_pages_request_acum++;

	/* This loop will never break out, the function will just return. */
	while (1) {
		/**
		 * Attempt to allocate a page from the page free list reserved for this
		 * function. This free list is managed in tandem with pmap_pages_free()
		 * which will add a page to this list for each call to
		 * pmap_page_reclaim(). Most likely that page will come from a reclaimed
		 * userspace page table, but if there aren't any page tables to reclaim,
		 * then whatever the next freed page is will show up on this list for
		 * the next invocation of pmap_page_reclaim() to use.
		 */
		if (pmap_page_reclaim_list != PAGE_FREE_ENTRY_NULL) {
			page_free_entry_t *page_entry = pmap_page_reclaim_list;
			pmap_page_reclaim_list = pmap_page_reclaim_list->next;
			pmap_simple_unlock(&pmap_page_reclaim_lock);

			return ml_static_vtop((vm_offset_t)page_entry);
		}

		/* Drop the lock to allow pmap_pages_free() to add pages to the list. */
		pmap_simple_unlock(&pmap_page_reclaim_lock);

		/* Attempt to find an elegible page table page to reclaim. */
		pt_desc_t *ptdp = NULL;
		bool found_page = ppr_find_eligible_pt_page(&ptdp);

		if (!found_page) {
			/**
			 * No eligible page table was found. pmap_pages_free() will still
			 * add the next freed page to the reclaim free list, so the next
			 * invocation of this function should have better luck.
			 */
			return (pmap_paddr_t)0;
		}

		/**
		 * If we found a page table to reclaim, then ptdp should point to the
		 * descriptor for that table. Go ahead and remove it.
		 */
		if (ppr_remove_pt_page(ptdp) != KERN_SUCCESS) {
			/* Take the page not found path to bail out on pending preemption. */
			return (pmap_paddr_t)0;
		}

		/**
		 * Now that a page has hopefully been freed (and added to the reclaim
		 * page list), the next iteration of the loop will re-check the reclaim
		 * free list.
		 */
		pmap_simple_lock(&pmap_page_reclaim_lock);
	}
}

#if XNU_MONITOR
/**
 * Helper function for returning a PPL page back to the PPL page free list.
 *
 * @param pa Physical address of the page to add to the PPL page free list.
 *           This address must be aligned to the VM page size.
 */
MARK_AS_PMAP_TEXT static void
pmap_give_free_ppl_page(pmap_paddr_t pa)
{
	if ((pa & PAGE_MASK) != 0) {
		panic("%s: Unaligned address passed in, pa=0x%llx",
		    __func__, pa);
	}

	page_free_entry_t *page_entry = (page_free_entry_t *)phystokv(pa);
	pmap_simple_lock(&pmap_ppl_free_page_lock);

	/* Prepend the passed in page to the PPL page free list. */
	page_entry->next = pmap_ppl_free_page_list;
	pmap_ppl_free_page_list = page_entry;
	pmap_ppl_free_page_count++;

	pmap_simple_unlock(&pmap_ppl_free_page_lock);
}

/**
 * Helper function for getting a PPL page from the PPL page free list.
 *
 * @return The physical address of the page taken from the PPL page free list,
 *         or zero if there are no pages left in the free list.
 */
MARK_AS_PMAP_TEXT static pmap_paddr_t
pmap_get_free_ppl_page(void)
{
	pmap_paddr_t pa = 0;

	pmap_simple_lock(&pmap_ppl_free_page_lock);

	if (pmap_ppl_free_page_list != PAGE_FREE_ENTRY_NULL) {
		/**
		 * Pop a page off the front of the list. The second item in the list
		 * will become the new head.
		 */
		page_free_entry_t *page_entry = pmap_ppl_free_page_list;
		pmap_ppl_free_page_list = pmap_ppl_free_page_list->next;
		pa = kvtophys_nofail((vm_offset_t)page_entry);
		pmap_ppl_free_page_count--;
	} else {
		pa = 0L;
	}

	pmap_simple_unlock(&pmap_ppl_free_page_lock);
	assert((pa & PAGE_MASK) == 0);

	return pa;
}

/**
 * Claim a page on behalf of the PPL by marking it as PPL-owned and only
 * allowing the PPL to write to it. Also can potentially add the page to the
 * PPL page free list (see initially_free parameter).
 *
 * @note The page cannot have any mappings outside of the physical aperture.
 *
 * @param pa The physical address of the page to mark as PPL-owned.
 * @param initially_free Should the page be added to the PPL page free list.
 *                       This is typically "true" if a brand new page was just
 *                       allocated for the PPL's usage, and "false" if this is a
 *                       page already being used by other agents (e.g., IOMMUs).
 */
MARK_AS_PMAP_TEXT void
pmap_mark_page_as_ppl_page_internal(pmap_paddr_t pa, bool initially_free)
{
	pp_attr_t attr = 0;

	if (!pa_valid(pa)) {
		panic("%s: Non-kernel-managed (maybe I/O) address passed in, pa=0x%llx",
		    __func__, pa);
	}

	const unsigned int pai = pa_index(pa);
	pvh_lock(pai);

	/* A page that the PPL already owns can't be given to the PPL. */
	if (ppattr_pa_test_monitor(pa)) {
		panic("%s: page already belongs to PPL, pa=0x%llx", __func__, pa);
	}

	/* The page cannot be mapped outside of the physical aperture. */
	if (!pmap_verify_free((ppnum_t)atop(pa))) {
		panic("%s: page still has mappings, pa=0x%llx", __func__, pa);
	}

	do {
		attr = pp_attr_table[pai];
		if (attr & PP_ATTR_NO_MONITOR) {
			panic("%s: page excluded from PPL, pa=0x%llx", __func__, pa);
		}
	} while (!OSCompareAndSwap16(attr, attr | PP_ATTR_MONITOR, &pp_attr_table[pai]));

	/* Ensure only the PPL has write access to the physical aperture mapping. */
	pmap_set_xprr_perm(pai, XPRR_KERN_RW_PERM, XPRR_PPL_RW_PERM);

	pvh_unlock(pai);

	if (initially_free) {
		pmap_give_free_ppl_page(pa);
	}
}

/**
 * Helper function for converting a PPL page back into a kernel-writable page.
 * This removes the PPL-ownership for that page and updates the physical
 * aperture mapping of that page so it's kernel-writable again.
 *
 * @param pa The physical address of the PPL page to be made kernel-writable.
 */
MARK_AS_PMAP_TEXT void
pmap_mark_page_as_kernel_page(pmap_paddr_t pa)
{
	const unsigned int pai = pa_index(pa);
	pvh_lock(pai);

	if (!ppattr_pa_test_monitor(pa)) {
		panic("%s: page is not a PPL page, pa=%p", __func__, (void *)pa);
	}

	ppattr_pa_clear_monitor(pa);

	/* Ensure the kernel has write access to the physical aperture mapping. */
	pmap_set_xprr_perm(pai, XPRR_PPL_RW_PERM, XPRR_KERN_RW_PERM);

	pvh_unlock(pai);
}

/**
 * PPL Helper function for giving a single page on the PPL page free list back
 * to the kernel.
 *
 * @note This function implements the logic that HAS to run within the PPL for
 *       the pmap_release_ppl_pages_to_kernel() call. This helper function
 *       shouldn't be called directly.
 *
 * @note A minimum amount of pages (set by PMAP_MIN_FREE_PPL_PAGES) will always
 *       be kept on the PPL page free list to ensure that core operations can
 *       occur without having to refill the free list.
 *
 * @return The physical address of the page that's been returned to the kernel,
 *         or zero if no page was returned.
 */
MARK_AS_PMAP_TEXT pmap_paddr_t
pmap_release_ppl_pages_to_kernel_internal(void)
{
	pmap_paddr_t pa = 0;

	if (pmap_ppl_free_page_count <= PMAP_MIN_FREE_PPL_PAGES) {
		return 0;
	}

	pa = pmap_get_free_ppl_page();

	if (!pa) {
		return 0;
	}

	pmap_mark_page_as_kernel_page(pa);

	return pa;
}
#endif /* XNU_MONITOR */

/**
 * Add a queue of VM pages to the pmap's VM object. This informs the VM that
 * these pages are being used by the pmap and shouldn't be reused.
 *
 * This also means that the pmap_object can be used as a convenient way to loop
 * through every page currently being used by the pmap. For instance, this queue
 * of pages is exposed to the debugger through the Low Globals, where it's used
 * to ensure that all pmap data is saved in an active core dump.
 *
 * @param mem The head of the queue of VM pages to add to the pmap's VM object.
 */
void
pmap_enqueue_pages(vm_page_t mem)
{
	vm_page_t m_prev;
	vm_object_lock(pmap_object);
	while (mem != VM_PAGE_NULL) {
		const vm_object_offset_t offset =
		    (vm_object_offset_t) ((ptoa(VM_PAGE_GET_PHYS_PAGE(mem))) - gPhysBase);

		vm_page_insert_wired(mem, pmap_object, offset, VM_KERN_MEMORY_PTE);
		m_prev = mem;
		mem = NEXT_PAGE(m_prev);
		*(NEXT_PAGE_PTR(m_prev)) = VM_PAGE_NULL;
	}
	vm_object_unlock(pmap_object);
}

static inline boolean_t
pmap_is_preemptible(void)
{
	return preemption_enabled() || (startup_phase < STARTUP_SUB_EARLY_BOOT);
}

/**
 * Allocate a page for usage within the pmap and zero it out. If running on a
 * PPL-enabled system, this will allocate pages from the PPL page free list.
 * Otherwise pages are grabbed directly from the VM.
 *
 * @note On PPL-enabled systems, this function can ONLY be called from within
 *       the PPL. If a page needs to be allocated from outside of the PPL on
 *       these systems, then use pmap_alloc_page_for_kern().
 *
 * @param pa Output parameter to store the physical address of the allocated
 *           page if one was able to be allocated (NULL otherwise).
 * @param size The amount of memory to allocate. This has to be PAGE_SIZE on
 *             PPL-enabled systems. On other systems it can be either PAGE_SIZE
 *             or 2*PAGE_SIZE, in which case the two pages are allocated
 *             physically contiguous.
 * @param options The following options can be specified:
 *     - PMAP_PAGES_ALLOCATE_NOWAIT: If the VM or PPL page free list don't have
 *       any free pages available then don't wait for one, just return
 *       immediately without allocating a page. PPL-enabled systems must ALWAYS
 *       pass this flag since allocating memory from within the PPL can't spin
 *       or block due to preemption being disabled (would be a perf hit).
 *
 *     - PMAP_PAGE_RECLAIM_NOWAIT: If memory failed to get allocated the normal
 *       way (either by the PPL page free list on PPL-enabled systems, or
 *       through the VM on other systems), then fall back to attempting to
 *       reclaim a userspace page table. This should only be specified in paths
 *       that absolutely can't take the latency hit of waiting for the VM or
 *       jumping out of the PPL to allocate more pages.
 *
 * @return KERN_SUCCESS if a page was successfully allocated, or
 *         KERN_RESOURCE_SHORTAGE if a page failed to get allocated. This can
 *         also be returned on non-PPL devices if preemption is disabled after
 *         early boot since allocating memory from the VM requires grabbing a
 *         mutex.
 */
MARK_AS_PMAP_TEXT kern_return_t
pmap_pages_alloc_zeroed(pmap_paddr_t *pa, unsigned size, unsigned options)
{
	assert(pa != NULL);

#if XNU_MONITOR
	ASSERT_NOT_HIBERNATING();

	/* The PPL page free list always operates on PAGE_SIZE chunks of memory. */
	if (size != PAGE_SIZE) {
		panic("%s: size != PAGE_SIZE, pa=%p, size=%u, options=%u",
		    __func__, pa, size, options);
	}

	/* Allocating memory in the PPL can't wait since preemption is disabled. */
	assert(options & PMAP_PAGES_ALLOCATE_NOWAIT);

	*pa = pmap_get_free_ppl_page();

	if ((*pa == 0) && (options & PMAP_PAGE_RECLAIM_NOWAIT)) {
		*pa = pmap_page_reclaim();
	}

	if (*pa == 0) {
		return KERN_RESOURCE_SHORTAGE;
	} else {
		bzero((void*)phystokv(*pa), size);
		return KERN_SUCCESS;
	}
#else /* XNU_MONITOR */
	vm_page_t mem = VM_PAGE_NULL;
	thread_t self = current_thread();

	/**
	 * It's not possible to allocate memory from the VM in a preemption disabled
	 * environment except during early boot (since the VM needs to grab a mutex).
	 * In those cases just return a resource shortage error and let the caller
	 * deal with it.
	 */
	if (!pmap_is_preemptible()) {
		return KERN_RESOURCE_SHORTAGE;
	}

	/**
	 * We qualify for allocating reserved memory so set TH_OPT_VMPRIV to inform
	 * the VM of this.
	 *
	 * This field should only be modified by the local thread itself, so no lock
	 * needs to be taken.
	 */
	uint16_t thread_options = self->options;
	self->options |= TH_OPT_VMPRIV;

	if (__probable(size == PAGE_SIZE)) {
		/**
		 * If we're only allocating a single page, just grab one off the VM's
		 * global page free list.
		 */
		while ((mem = vm_page_grab()) == VM_PAGE_NULL) {
			if (options & PMAP_PAGES_ALLOCATE_NOWAIT) {
				break;
			}

			VM_PAGE_WAIT();
		}

		if (mem != VM_PAGE_NULL) {
			vm_page_lock_queues();
			vm_page_wire(mem, VM_KERN_MEMORY_PTE, TRUE);
			vm_page_unlock_queues();
		}
	} else if (size == (2 * PAGE_SIZE)) {
		/**
		 * Allocate two physically contiguous pages. Any random two pages
		 * obtained from the VM's global page free list aren't guaranteed to be
		 * contiguous so we need to use the cpm_allocate() API.
		 */
		while (cpm_allocate(size, &mem, 0, 1, TRUE, 0) != KERN_SUCCESS) {
			if (options & PMAP_PAGES_ALLOCATE_NOWAIT) {
				break;
			}

			VM_PAGE_WAIT();
		}
	} else {
		panic("%s: invalid size %u", __func__, size);
	}

	self->options = thread_options;

	/**
	 * If the normal method of allocating pages failed, then potentially fall
	 * back to attempting to reclaim a userspace page table.
	 */
	if ((mem == VM_PAGE_NULL) && (options & PMAP_PAGE_RECLAIM_NOWAIT)) {
		assert(size == PAGE_SIZE);
		*pa = pmap_page_reclaim();
		if (*pa != 0) {
			bzero((void*)phystokv(*pa), size);
			return KERN_SUCCESS;
		}
	}

	if (mem == VM_PAGE_NULL) {
		return KERN_RESOURCE_SHORTAGE;
	}

	*pa = (pmap_paddr_t)ptoa(VM_PAGE_GET_PHYS_PAGE(mem));

	/* Add the allocated VM page(s) to the pmap's VM object. */
	pmap_enqueue_pages(mem);

	/* Pages are considered "in use" by the pmap until returned to the VM. */
	OSAddAtomic(size >> PAGE_SHIFT, &inuse_pmap_pages_count);
	OSAddAtomic64(size >> PAGE_SHIFT, &alloc_pmap_pages_count);

	bzero((void*)phystokv(*pa), size);
	return KERN_SUCCESS;
#endif /* XNU_MONITOR */
}

#if XNU_MONITOR
/**
 * Allocate a page from the VM. If no pages are available, this function can
 * potentially spin until a page is available (see the `options` parameter).
 *
 * @note This function CANNOT be called from the PPL since it calls into the VM.
 *       If the PPL needs memory, then it'll need to exit the PPL before
 *       allocating more (usually by returning KERN_RESOURCE_SHORTAGE, and then
 *       calling pmap_alloc_page_for_ppl() from outside of the PPL).
 *
 * @param options The following options can be specified:
 *     - PMAP_PAGES_ALLOCATE_NOWAIT: If the VM doesn't have any free pages
 *       available then don't wait for one, just return immediately without
 *       allocating a page.
 *
 * @return The physical address of the page, if one was allocated. Zero,
 *         otherwise.
 */
pmap_paddr_t
pmap_alloc_page_for_kern(unsigned int options)
{
	pmap_paddr_t pa = 0;
	vm_page_t mem = VM_PAGE_NULL;

	/* It's not possible to lock VM page queue lock if not preemptible. */
	if (!pmap_is_preemptible()) {
		return 0;
	}

	while ((mem = vm_page_grab()) == VM_PAGE_NULL) {
		if (options & PMAP_PAGES_ALLOCATE_NOWAIT) {
			return 0;
		}
		VM_PAGE_WAIT();
	}

	/* Automatically wire any pages used by the pmap. */
	vm_page_lock_queues();
	vm_page_wire(mem, VM_KERN_MEMORY_PTE, TRUE);
	vm_page_unlock_queues();

	pa = (pmap_paddr_t)ptoa(VM_PAGE_GET_PHYS_PAGE(mem));

	if (__improbable(pa == 0)) {
		panic("%s: physical address is 0", __func__);
	}

	/**
	 * Add the acquired VM page to the pmap's VM object to notify the VM that
	 * this page is being used.
	 */
	pmap_enqueue_pages(mem);

	/* Pages are considered "in use" by the pmap until returned to the VM. */
	OSAddAtomic(1, &inuse_pmap_pages_count);
	OSAddAtomic64(1, &alloc_pmap_pages_count);

	return pa;
}

/**
 * Allocate a page from the VM, mark it as being PPL-owned, and add it to the
 * PPL page free list.
 *
 * @note This function CANNOT be called from the PPL since it calls into the VM.
 *       If the PPL needs memory, then it'll need to exit the PPL before calling
 *       this function (usually by returning KERN_RESOURCE_SHORTAGE).
 *
 * @param options The following options can be specified:
 *     - PMAP_PAGES_ALLOCATE_NOWAIT: If the VM doesn't have any free pages
 *       available then don't wait for one, just return immediately without
 *       allocating a page.
 */
void
pmap_alloc_page_for_ppl(unsigned int options)
{
	thread_t self = current_thread();

	/**
	 * We qualify for allocating reserved memory so set TH_OPT_VMPRIV to inform
	 * the VM of this.
	 *
	 * This field should only be modified by the local thread itself, so no lock
	 * needs to be taken.
	 */
	uint16_t thread_options = self->options;
	self->options |= TH_OPT_VMPRIV;
	pmap_paddr_t pa = pmap_alloc_page_for_kern(options);
	self->options = thread_options;

	if (pa != 0) {
		pmap_mark_page_as_ppl_page(pa);
	}
}
#endif /* XNU_MONITOR */

/**
 * Free memory previously allocated through pmap_pages_alloc_zeroed() or
 * pmap_alloc_page_for_kern().
 *
 * On PPL-enabled systems, this just adds the page back to the PPL page free
 * list. On other systems, this returns the page(s) back to the VM.
 *
 * @param pa Physical address of the page(s) to free.
 * @param size The size in bytes of the memory region being freed (must be
 *             PAGE_SIZE on PPL-enabled systems).
 */
void
pmap_pages_free(pmap_paddr_t pa, __assert_only unsigned size)
{
	/**
	 * If the pmap is starved for memory to the point that pmap_page_reclaim()
	 * starts getting invoked to allocate memory, then let's take the page being
	 * freed and add it directly to pmap_page_reclaim()'s dedicated free list.
	 * In that case, the page being freed is most likely a userspace page table
	 * that was reclaimed.
	 */
	if (__improbable(pmap_pages_request_count != 0)) {
		pmap_simple_lock(&pmap_page_reclaim_lock);

		if (pmap_pages_request_count != 0) {
			pmap_pages_request_count--;

			/* Prepend the freed page to the pmap_page_reclaim() free list. */
			page_free_entry_t *page_entry = (page_free_entry_t *)phystokv(pa);
			page_entry->next = pmap_page_reclaim_list;
			pmap_page_reclaim_list = page_entry;
			pmap_simple_unlock(&pmap_page_reclaim_lock);

			return;
		}
		pmap_simple_unlock(&pmap_page_reclaim_lock);
	}

#if XNU_MONITOR
	/* The PPL page free list always operates on PAGE_SIZE chunks of memory. */
	assert(size == PAGE_SIZE);

	/* On PPL-enabled systems, just add the page back to the PPL page free list. */
	pmap_give_free_ppl_page(pa);
#else /* XNU_MONITOR */
	vm_page_t mem = VM_PAGE_NULL;
	const pmap_paddr_t pa_max = pa + size;

	/* Pages are considered "in use" until given back to the VM. */
	OSAddAtomic(-(size >> PAGE_SHIFT), &inuse_pmap_pages_count);

	for (; pa < pa_max; pa += PAGE_SIZE) {
		vm_object_lock(pmap_object);

		/**
		 * Remove the page from the pmap's VM object and return it back to the
		 * VM's global free list of pages.
		 */
		mem = vm_page_lookup(pmap_object, (pa - gPhysBase));
		assert(mem != VM_PAGE_NULL);
		assert(VM_PAGE_WIRED(mem));
		vm_page_lock_queues();
		vm_page_free(mem);
		vm_page_unlock_queues();
		vm_object_unlock(pmap_object);
	}
#endif /* XNU_MONITOR */
}

/**
 * Called by the VM to reclaim pages that we can reclaim quickly and cheaply.
 * This will take pages in the pmap's VM object and add them back to the VM's
 * global list of free pages.
 *
 * @return The number of pages returned to the VM.
 */
uint64_t
pmap_release_pages_fast(void)
{
#if XNU_MONITOR
	return pmap_release_ppl_pages_to_kernel();
#else /* XNU_MONITOR */
	return 0;
#endif
}

/**
 * Allocates a batch (list) of pv_entry_t's from the global PV free array.
 *
 * @return A pointer to the head of the newly-allocated batch, or PV_ENTRY_NULL
 *         if empty.
 */
MARK_AS_PMAP_TEXT static pv_entry_t *
pv_free_array_get_batch(void)
{
	pv_entry_t *new_batch = PV_ENTRY_NULL;

	pmap_simple_lock(&pv_free_array_lock);
	if (pv_free_array_n_elems() > 0) {
		/**
		 * The global PV array acts as a ring buffer where each entry points to
		 * a linked list of PVEs of length PV_BATCH_SIZE. Get the next free
		 * batch.
		 */
		const size_t index = pv_free_read_idx++ & (PV_FREE_ARRAY_SIZE - 1);
		pv_free_list_t *free_list = &pv_free_ring[index];

		assert((free_list->count == PV_BATCH_SIZE) && (free_list->list != PV_ENTRY_NULL));
		new_batch = free_list->list;
	}
	pmap_simple_unlock(&pv_free_array_lock);

	return new_batch;
}

/**
 * Frees a batch (list) of pv_entry_t's into the global PV free array.
 *
 * @param batch_head Pointer to the first entry in the batch to be returned to
 *                   the array. This must be a linked list of pv_entry_t's of
 *                   length PV_BATCH_SIZE.
 *
 * @return KERN_SUCCESS, or KERN_FAILURE if the global array is full.
 */
MARK_AS_PMAP_TEXT static kern_return_t
pv_free_array_give_batch(pv_entry_t *batch_head)
{
	assert(batch_head != NULL);

	pmap_simple_lock(&pv_free_array_lock);
	if (pv_free_array_n_elems() == (PV_FREE_ARRAY_SIZE - 1)) {
		pmap_simple_unlock(&pv_free_array_lock);
		return KERN_FAILURE;
	}

	const size_t index = pv_free_write_idx++ & (PV_FREE_ARRAY_SIZE - 1);
	pv_free_list_t *free_list = &pv_free_ring[index];
	free_list->list = batch_head;
	free_list->count = PV_BATCH_SIZE;
	pmap_simple_unlock(&pv_free_array_lock);

	return KERN_SUCCESS;
}

/**
 * Helper function for allocating a single PVE from an arbitrary free list.
 *
 * @param free_list The free list to allocate a node from.
 * @param pvepp Output parameter that will get updated with a pointer to the
 *              allocated node if the free list isn't empty, or a pointer to
 *              NULL if the list is empty.
 */
MARK_AS_PMAP_TEXT static void
pv_free_list_alloc(pv_free_list_t *free_list, pv_entry_t **pvepp)
{
	assert(pvepp != NULL);
	assert(((free_list->list != NULL) && (free_list->count > 0)) ||
	    ((free_list->list == NULL) && (free_list->count == 0)));

	if ((*pvepp = free_list->list) != NULL) {
		pv_entry_t *pvep = *pvepp;
		free_list->list = pvep->pve_next;
		pvep->pve_next = PV_ENTRY_NULL;
		free_list->count--;
	}
}

/**
 * Allocates a PVE from the kernel-dedicated list.
 *
 * @note This is only called when the global free list is empty, so don't bother
 *       trying to allocate more nodes from that list.
 *
 * @param pvepp Output parameter that will get updated with a pointer to the
 *              allocated node if the free list isn't empty, or a pointer to
 *              NULL if the list is empty. This pointer can't already be
 *              pointing to a valid entry before allocation.
 */
MARK_AS_PMAP_TEXT static void
pv_list_kern_alloc(pv_entry_t **pvepp)
{
	assert((pvepp != NULL) && (*pvepp == PV_ENTRY_NULL));
	pmap_simple_lock(&pv_kern_free_list_lock);
	if (pv_kern_free.count > 0) {
		pmap_kern_reserve_alloc_stat++;
	}
	pv_free_list_alloc(&pv_kern_free, pvepp);
	pmap_simple_unlock(&pv_kern_free_list_lock);
}

/**
 * Returns a list of PVEs to the kernel-dedicated free list.
 *
 * @param pve_head Head of the list to be returned.
 * @param pve_tail Tail of the list to be returned.
 * @param pv_cnt Number of elements in the list to be returned.
 */
MARK_AS_PMAP_TEXT static void
pv_list_kern_free(pv_entry_t *pve_head, pv_entry_t *pve_tail, int pv_cnt)
{
	assert((pve_head != PV_ENTRY_NULL) && (pve_tail != PV_ENTRY_NULL));

	pmap_simple_lock(&pv_kern_free_list_lock);
	pve_tail->pve_next = pv_kern_free.list;
	pv_kern_free.list = pve_head;
	pv_kern_free.count += pv_cnt;
	pmap_simple_unlock(&pv_kern_free_list_lock);
}

/**
 * Attempts to allocate from the per-cpu free list of PVEs, and if that fails,
 * then replenish the per-cpu free list with a batch of PVEs from the global
 * PVE free list.
 *
 * @param pvepp Output parameter that will get updated with a pointer to the
 *              allocated node if the free lists aren't empty, or a pointer to
 *              NULL if both the per-cpu and global lists are empty. This
 *              pointer can't already be pointing to a valid entry before
 *              allocation.
 */
MARK_AS_PMAP_TEXT static void
pv_list_alloc(pv_entry_t **pvepp)
{
	assert((pvepp != NULL) && (*pvepp == PV_ENTRY_NULL));

#if !XNU_MONITOR
	/**
	 * Preemption is always disabled in the PPL so it only needs to get disabled
	 * on non-PPL systems. This needs to be disabled while working with per-cpu
	 * data to prevent getting rescheduled onto a different CPU.
	 */
	mp_disable_preemption();
#endif /* !XNU_MONITOR */

	pmap_cpu_data_t *pmap_cpu_data = pmap_get_cpu_data();
	pv_free_list_alloc(&pmap_cpu_data->pv_free, pvepp);

	if (*pvepp != PV_ENTRY_NULL) {
		goto pv_list_alloc_done;
	}

#if !XNU_MONITOR
	if (pv_kern_free.count < pv_kern_low_water_mark) {
		/**
		 * If the kernel reserved pool is low, let non-kernel mappings wait for
		 * a page from the VM.
		 */
		goto pv_list_alloc_done;
	}
#endif /* !XNU_MONITOR */

	/**
	 * Attempt to replenish the local list off the global one, and return the
	 * first element. If the global list is empty, then the allocation failed.
	 */
	pv_entry_t *new_batch = pv_free_array_get_batch();

	if (new_batch != PV_ENTRY_NULL) {
		pmap_cpu_data->pv_free.count = PV_BATCH_SIZE - 1;
		pmap_cpu_data->pv_free.list = new_batch->pve_next;
		assert(pmap_cpu_data->pv_free.list != NULL);

		new_batch->pve_next = PV_ENTRY_NULL;
		*pvepp = new_batch;
	}

pv_list_alloc_done:
#if !XNU_MONITOR
	mp_enable_preemption();
#endif /* !XNU_MONITOR */

	return;
}

/**
 * Adds a list of PVEs to the per-CPU PVE free list. May spill out some entries
 * to the global or the kernel PVE free lists if the per-CPU list contains too
 * many PVEs.
 *
 * @param pve_head Head of the list to be returned.
 * @param pve_tail Tail of the list to be returned.
 * @param pv_cnt Number of elements in the list to be returned.
 */
MARK_AS_PMAP_TEXT void
pv_list_free(pv_entry_t *pve_head, pv_entry_t *pve_tail, int pv_cnt)
{
	assert((pve_head != PV_ENTRY_NULL) && (pve_tail != PV_ENTRY_NULL));

#if !XNU_MONITOR
	/**
	 * Preemption is always disabled in the PPL so it only needs to get disabled
	 * on non-PPL systems. This needs to be disabled while working with per-cpu
	 * data to prevent getting rescheduled onto a different CPU.
	 */
	mp_disable_preemption();
#endif /* !XNU_MONITOR */

	pmap_cpu_data_t *pmap_cpu_data = pmap_get_cpu_data();

	/**
	 * How many more PVEs need to be added to the last allocated batch to get it
	 * back up to a PV_BATCH_SIZE number of objects.
	 */
	const uint32_t available = PV_BATCH_SIZE - (pmap_cpu_data->pv_free.count % PV_BATCH_SIZE);

	/**
	 * The common case is that the number of PVEs to be freed fit in the current
	 * PV_BATCH_SIZE boundary. If that is the case, quickly prepend the whole
	 * list and return.
	 */
	if (__probable((pv_cnt <= available) &&
	    ((pmap_cpu_data->pv_free.count % PV_BATCH_SIZE != 0) || (pmap_cpu_data->pv_free.count == 0)))) {
		pve_tail->pve_next = pmap_cpu_data->pv_free.list;
		pmap_cpu_data->pv_free.list = pve_head;
		pmap_cpu_data->pv_free.count += pv_cnt;
		goto pv_list_free_done;
	}

	/**
	 * In the degenerate case, we need to process PVEs one by one, to make sure
	 * we spill out to the global list, or update the spill marker as
	 * appropriate.
	 */
	while (pv_cnt) {
		/**
		 * Take the node off the top of the passed in list and prepend it to the
		 * per-cpu list.
		 */
		pv_entry_t *pv_next = pve_head->pve_next;
		pve_head->pve_next = pmap_cpu_data->pv_free.list;
		pmap_cpu_data->pv_free.list = pve_head;
		pve_head = pv_next;
		pmap_cpu_data->pv_free.count++;
		pv_cnt--;

		if (__improbable(pmap_cpu_data->pv_free.count == (PV_BATCH_SIZE + 1))) {
			/**
			 * A full batch of entries have been freed to the per-cpu list.
			 * Update the spill marker which is used to remember the end of a
			 * batch (remember, we prepend nodes) to eventually return back to
			 * the global list (we try to only keep one PV_BATCH_SIZE worth of
			 * nodes in any single per-cpu list).
			 */
			pmap_cpu_data->pv_free_spill_marker = pmap_cpu_data->pv_free.list;
		} else if (__improbable(pmap_cpu_data->pv_free.count == (PV_BATCH_SIZE * 2) + 1)) {
			/* Spill out excess PVEs to the global PVE array */
			pv_entry_t *spill_head = pmap_cpu_data->pv_free.list->pve_next;
			pv_entry_t *spill_tail = pmap_cpu_data->pv_free_spill_marker;
			pmap_cpu_data->pv_free.list->pve_next = pmap_cpu_data->pv_free_spill_marker->pve_next;
			spill_tail->pve_next = PV_ENTRY_NULL;
			pmap_cpu_data->pv_free.count -= PV_BATCH_SIZE;
			pmap_cpu_data->pv_free_spill_marker = pmap_cpu_data->pv_free.list;

			if (__improbable(pv_free_array_give_batch(spill_head) != KERN_SUCCESS)) {
				/**
				 * This is extremely unlikely to happen, as it would imply that
				 * we have (PV_FREE_ARRAY_SIZE * PV_BATCH_SIZE) PVEs sitting in
				 * the global array. Just in case, push the excess down to the
				 * kernel PVE free list.
				 */
				pv_list_kern_free(spill_head, spill_tail, PV_BATCH_SIZE);
			}
		}
	}

pv_list_free_done:
#if !XNU_MONITOR
	mp_enable_preemption();
#endif /* !XNU_MONITOR */

	return;
}

/**
 * Adds a single page to the PVE allocation subsystem.
 *
 * @note This function operates under the assumption that a PV_BATCH_SIZE amount
 *       of PVEs can fit within a single page. One page is always allocated for
 *       one batch, so if there's empty space in the page after the batch of
 *       PVEs, it'll go unused (so it's best to keep the batch size at an amount
 *       that utilizes a whole page).
 *
 * @param alloc_flags Allocation flags passed to pmap_pages_alloc_zeroed(). See
 *                    the definition of that function for a detailed description
 *                    of the available flags.
 *
 * @return KERN_SUCCESS, or the value returned by pmap_pages_alloc_zeroed() upon
 *         failure.
 */
MARK_AS_PMAP_TEXT static kern_return_t
pve_feed_page(unsigned alloc_flags)
{
	kern_return_t kr = KERN_FAILURE;

	pv_entry_t *pve_head = PV_ENTRY_NULL;
	pv_entry_t *pve_tail = PV_ENTRY_NULL;
	pmap_paddr_t pa = 0;

	kr = pmap_pages_alloc_zeroed(&pa, PAGE_SIZE, alloc_flags);

	if (kr != KERN_SUCCESS) {
		return kr;
	}

	/* Update statistics globals. See the variables' definitions for more info. */
	pv_page_count++;
	pmap_reserve_replenish_stat += PV_BATCH_SIZE;

	/* Prepare a new list by linking all of the entries in advance. */
	pve_head = (pv_entry_t *)phystokv(pa);
	pve_tail = &pve_head[PV_BATCH_SIZE - 1];

	for (int i = 0; i < PV_BATCH_SIZE; i++) {
		pve_head[i].pve_next = &pve_head[i + 1];
	}
	pve_head[PV_BATCH_SIZE - 1].pve_next = PV_ENTRY_NULL;

	/**
	 * Add the new list to the kernel PVE free list if we are running low on
	 * kernel-dedicated entries or the global free array is full.
	 */
	if ((pv_kern_free.count < pv_kern_low_water_mark) ||
	    (pv_free_array_give_batch(pve_head) != KERN_SUCCESS)) {
		pv_list_kern_free(pve_head, pve_tail, PV_BATCH_SIZE);
	}

	return KERN_SUCCESS;
}

/**
 * Allocate a PV node from one of many different free lists (per-cpu, global, or
 * kernel-specific).
 *
 * @note This function is very tightly coupled with pmap_enter_pv(). If
 *       modifying this code, please ensure that pmap_enter_pv() doesn't break.
 *
 * @note The pmap lock must already be held if the new mapping is a CPU mapping.
 *
 * @note The PVH lock for the physical page that is getting a new mapping
 *       registered must already be held.
 *
 * @param pmap The pmap that owns the new mapping, or NULL if this is tracking
 *             an IOMMU translation.
 * @param pai The physical address index of the page that's getting a new
 *            mapping.
 * @param lock_mode Which state the pmap lock is being held in if the mapping is
 *                  owned by a pmap, otherwise this is a don't care.
 * @param options PMAP_OPTIONS_* family of options passed from the caller.
 * @param pvepp Output parameter that will get updated with a pointer to the
 *              allocated node if none of the free lists are empty, or a pointer
 *              to NULL otherwise. This pointer can't already be pointing to a
 *              valid entry before allocation.
 *
 * @return These are the possible return values:
 *     PV_ALLOC_SUCCESS: A PVE object was successfully allocated.
 *     PV_ALLOC_FAILURE: No objects were available for allocation, and
 *                       allocating a new page failed. On PPL-enabled systems,
 *                       a fresh page needs to be added to the PPL page list
 *                       before retrying this operaton.
 *     PV_ALLOC_RETRY: No objects were available on the free lists, so a new
 *                     page of PVE objects needed to be allocated. To do that,
 *                     the pmap and PVH locks were dropped. The caller may have
 *                     depended on these locks for consistency, so return and
 *                     let the caller retry the PVE allocation with the locks
 *                     held. Note that the locks have already been re-acquired
 *                     before this function exits.
 */
MARK_AS_PMAP_TEXT pv_alloc_return_t
pv_alloc(
	pmap_t pmap,
	unsigned int pai,
	pmap_lock_mode_t lock_mode,
	unsigned int options,
	pv_entry_t **pvepp)
{
	assert((pvepp != NULL) && (*pvepp == PV_ENTRY_NULL));

	if (pmap != NULL) {
		pmap_assert_locked(pmap, lock_mode);
	}
	pvh_assert_locked(pai);

	pv_list_alloc(pvepp);
	if (PV_ENTRY_NULL != *pvepp) {
		return PV_ALLOC_SUCCESS;
	}

#if XNU_MONITOR
	/* PPL can't block so this flag is always required. */
	unsigned alloc_flags = PMAP_PAGES_ALLOCATE_NOWAIT;
#else /* XNU_MONITOR */
	unsigned alloc_flags = 0;
#endif /* XNU_MONITOR */

	/**
	 * We got here because both the per-CPU and the global lists are empty. If
	 * this allocation is for the kernel pmap or an IOMMU kernel driver, we try
	 * to get an entry from the kernel list next.
	 */
	if ((pmap == NULL) || (kernel_pmap == pmap)) {
		pv_list_kern_alloc(pvepp);
		if (PV_ENTRY_NULL != *pvepp) {
			return PV_ALLOC_SUCCESS;
		}
		/**
		 * If the pmap is NULL, this is an allocation outside the normal pmap path,
		 * most likely an IOMMU allocation.  We therefore don't know what other locks
		 * this path may hold or timing constraints it may have, so we should avoid
		 * a potentially expensive call to pmap_page_reclaim() on this path.
		 */
		if (pmap == NULL) {
			alloc_flags = PMAP_PAGES_ALLOCATE_NOWAIT;
		} else {
			alloc_flags = PMAP_PAGES_ALLOCATE_NOWAIT | PMAP_PAGE_RECLAIM_NOWAIT;
		}
	}

	/**
	 * Make sure we have PMAP_PAGES_ALLOCATE_NOWAIT set in alloc_flags when the
	 * input options argument has PMAP_OPTIONS_NOWAIT set.
	 */
	alloc_flags |= (options & PMAP_OPTIONS_NOWAIT) ? PMAP_PAGES_ALLOCATE_NOWAIT : 0;

	/**
	 * We ran out of PV entries all across the board, or this allocation is not
	 * for the kernel. Let's make sure that the kernel list is not too full
	 * (very unlikely), in which case we can rebalance here.
	 */
	if (__improbable(pv_kern_free.count > (PV_BATCH_SIZE * 2))) {
		pmap_simple_lock(&pv_kern_free_list_lock);
		/* Re-check, now that the lock is held. */
		if (pv_kern_free.count > (PV_BATCH_SIZE * 2)) {
			pv_entry_t *pve_head = pv_kern_free.list;
			pv_entry_t *pve_tail = pve_head;

			for (int i = 0; i < (PV_BATCH_SIZE - 1); i++) {
				pve_tail = pve_tail->pve_next;
			}

			pv_kern_free.list = pve_tail->pve_next;
			pv_kern_free.count -= PV_BATCH_SIZE;
			pve_tail->pve_next = PV_ENTRY_NULL;
			pmap_simple_unlock(&pv_kern_free_list_lock);

			/* Return back every node except the first one to the free lists. */
			pv_list_free(pve_head->pve_next, pve_tail, PV_BATCH_SIZE - 1);
			pve_head->pve_next = PV_ENTRY_NULL;
			*pvepp = pve_head;
			return PV_ALLOC_SUCCESS;
		}
		pmap_simple_unlock(&pv_kern_free_list_lock);
	}

	/**
	 * If all else fails, try to get a new pmap page so that the allocation
	 * succeeds once the caller retries it.
	 */
	kern_return_t kr = KERN_FAILURE;
	pv_alloc_return_t pv_status = PV_ALLOC_FAIL;

	/* Drop the lock during page allocation since that can take a while. */
	pvh_unlock(pai);
	if (pmap != NULL) {
		pmap_unlock(pmap, lock_mode);
	}

	if ((kr = pve_feed_page(alloc_flags)) == KERN_SUCCESS) {
		/**
		 * Since the lock was dropped, even though we successfully allocated a
		 * new page to be used for PVE nodes, the code that relies on this
		 * function might have depended on the lock being held for consistency,
		 * so return out early and let them retry the allocation with the lock
		 * re-held.
		 */
		pv_status = PV_ALLOC_RETRY;
	} else {
		pv_status = PV_ALLOC_FAIL;
	}

	if (pmap != NULL) {
		pmap_lock(pmap, lock_mode);
	}
	pvh_lock(pai);

	/* Ensure that no node was created if we're not returning successfully. */
	assert(*pvepp == PV_ENTRY_NULL);

	return pv_status;
}

/**
 * Utility function for freeing a single PVE object back to the free lists.
 *
 * @param pvep Pointer to the PVE object to free.
 */
MARK_AS_PMAP_TEXT void
pv_free(pv_entry_t *pvep)
{
	assert(pvep != PV_ENTRY_NULL);

	pv_list_free(pvep, pvep, 1);
}

/**
 * This function provides a mechanism for the device tree to override the
 * default PV allocation amounts and the watermark level which determines how
 * many PVE objects are kept in the kernel-dedicated free list.
 */
MARK_AS_PMAP_TEXT void
pmap_compute_pv_targets(void)
{
	DTEntry entry = NULL;
	void const *prop = NULL;
	int err = 0;
	unsigned int prop_size = 0;

	err = SecureDTLookupEntry(NULL, "/defaults", &entry);
	assert(err == kSuccess);

	if (kSuccess == SecureDTGetProperty(entry, "pmap-pv-count", &prop, &prop_size)) {
		if (prop_size != sizeof(pv_alloc_initial_target)) {
			panic("pmap-pv-count property is not a 32-bit integer");
		}
		pv_alloc_initial_target = *((uint32_t const *)prop);
	}

	if (kSuccess == SecureDTGetProperty(entry, "pmap-kern-pv-count", &prop, &prop_size)) {
		if (prop_size != sizeof(pv_kern_alloc_initial_target)) {
			panic("pmap-kern-pv-count property is not a 32-bit integer");
		}
		pv_kern_alloc_initial_target = *((uint32_t const *)prop);
	}

	if (kSuccess == SecureDTGetProperty(entry, "pmap-kern-pv-min", &prop, &prop_size)) {
		if (prop_size != sizeof(pv_kern_low_water_mark)) {
			panic("pmap-kern-pv-min property is not a 32-bit integer");
		}
		pv_kern_low_water_mark = *((uint32_t const *)prop);
	}
}

/**
 * This would normally be used to adjust the amount of PVE objects available in
 * the system, but we do that dynamically at runtime anyway so this is unneeded.
 */
void
mapping_adjust(void)
{
	/* Not implemented for arm/arm64. */
}

/**
 * Creates a target number of free pv_entry_t objects for the kernel free list
 * and the general free list.
 *
 * @note This function is called once during early boot, in kernel_bootstrap().
 *
 * @return KERN_SUCCESS if the objects were successfully allocated, or the
 *         return value from pve_feed_page() on failure (could be caused by not
 *         being able to allocate a page).
 */
MARK_AS_PMAP_TEXT kern_return_t
mapping_free_prime_internal(void)
{
	kern_return_t kr = KERN_FAILURE;

#if XNU_MONITOR
	/* PPL can't block so this flag is always required. */
	unsigned alloc_flags = PMAP_PAGES_ALLOCATE_NOWAIT;
#else /* XNU_MONITOR */
	unsigned alloc_flags = 0;
#endif /* XNU_MONITOR */

	/*
	 * We do not need to hold the pv_free_array lock to calculate the number of
	 * elements in it because no other core is running at this point.
	 */
	while (((pv_free_array_n_elems() * PV_BATCH_SIZE) < pv_alloc_initial_target) ||
	    (pv_kern_free.count < pv_kern_alloc_initial_target)) {
		if ((kr = pve_feed_page(alloc_flags)) != KERN_SUCCESS) {
			return kr;
		}
	}

	return KERN_SUCCESS;
}

/**
 * Helper function for pmap_enter_pv (hereby shortened to "pepv") which converts
 * a PVH entry from PVH_TYPE_PTEP to PVH_TYPE_PVEP which will transform the
 * entry into a linked list of mappings.
 *
 * @note This should only be called from pmap_enter_pv().
 *
 * @note The PVH lock for the passed in page must already be held and the type
 *       must be PVH_TYPE_PTEP (wouldn't make sense to call this otherwise).
 *
 * @param pmap Either the pmap that owns the mapping being registered in
 *             pmap_enter_pv(), or NULL if this is an IOMMU mapping.
 * @param pai The physical address index of the page that's getting a second
 *            mapping and needs to be converted from PVH_TYPE_PTEP to
 *            PVH_TYPE_PVEP.
 * @param lock_mode Which state the pmap lock is being held in if the mapping is
 *                  owned by a pmap, otherwise this is a don't care.
 * @param options PMAP_OPTIONS_* family of options.
 *
 * @return PV_ALLOC_SUCCESS if the entry at `pai` was successfully converted
 *         into PVH_TYPE_PVEP, or the return value of pv_alloc() otherwise. See
 *         pv_alloc()'s function header for a detailed explanation of the
 *         possible return values.
 */
MARK_AS_PMAP_TEXT static pv_alloc_return_t
pepv_convert_ptep_to_pvep(
	pmap_t pmap,
	unsigned int pai,
	pmap_lock_mode_t lock_mode,
	unsigned int options)
{
	pvh_assert_locked(pai);

	pv_entry_t **pvh = pai_to_pvh(pai);
	assert(pvh_test_type(pvh, PVH_TYPE_PTEP));

	pv_entry_t *pvep = PV_ENTRY_NULL;
	pv_alloc_return_t ret = pv_alloc(pmap, pai, lock_mode, options, &pvep);
	if (ret != PV_ALLOC_SUCCESS) {
		return ret;
	}

	/* If we've gotten this far then a node should've been allocated. */
	assert(pvep != PV_ENTRY_NULL);

	/* The new PVE should have the same PTE pointer as the previous PVH entry. */
	pve_init(pvep);
	pve_set_ptep(pvep, 0, pvh_ptep(pvh));

	assert(!pve_get_internal(pvep, 0));
	assert(!pve_get_altacct(pvep, 0));
	if (ppattr_is_internal(pai)) {
		/**
		 * Transfer "internal" status from pp_attr to this pve. See the comment
		 * above PP_ATTR_INTERNAL for more information on this.
		 */
		ppattr_clear_internal(pai);
		pve_set_internal(pvep, 0);
	}
	if (ppattr_is_altacct(pai)) {
		/**
		 * Transfer "altacct" status from pp_attr to this pve. See the comment
		 * above PP_ATTR_ALTACCT for more information on this.
		 */
		ppattr_clear_altacct(pai);
		pve_set_altacct(pvep, 0);
	}

	pvh_update_head(pvh, pvep, PVH_TYPE_PVEP);

	return PV_ALLOC_SUCCESS;
}

/**
 * Register a new mapping into the pv_head_table. This is the main data
 * structure used for performing a reverse physical to virtual translation and
 * finding all mappings to a physical page. Whenever a new page table mapping is
 * created (regardless of whether it's for a CPU or an IOMMU), it should be
 * registered with a call to this function.
 *
 * @note The pmap lock must already be held if the new mapping is a CPU mapping.
 *
 * @note The PVH lock for the physical page that is getting a new mapping
 *       registered must already be held.
 *
 * @note This function cannot be called during the hibernation process because
 *       it modifies critical pmap data structures that need to be dumped into
 *       the hibernation image in a consistent state.
 *
 * @param pmap The pmap that owns the new mapping, or NULL if this is tracking
 *             an IOMMU translation.
 * @param ptep The new mapping to register.
 * @param pai The physical address index of the physical page being mapped by
 *            `ptep`.
 * @param options Flags that can potentially be set on a per-page basis:
 *                PMAP_OPTIONS_INTERNAL: If this is the first CPU mapping, then
 *                    mark the page as being "internal". See the definition of
 *                    PP_ATTR_INTERNAL for more info.
 *                PMAP_OPTIONS_REUSABLE: If this is the first CPU mapping, and
 *                    this page is also marked internal, then mark the page as
 *                    being "reusable". See the definition of PP_ATTR_REUSABLE
 *                    for more info.
 * @param lock_mode Which state the pmap lock is being held in if the mapping is
 *                  owned by a pmap, otherwise this is a don't care.
 * @param new_pvepp An output parameter that is updated with a pointer to the
 *                  PVE object where the PTEP was allocated into. In the event
 *                  of failure, or if the pointer passed in is NULL,
 *                  it's not modified.
 * @param new_pve_ptep_idx An output parameter that is updated with the index
 *                  into the PVE object where the PTEP was allocated into.
 *                  In the event of failure, or if new_pvepp in is NULL,
 *                  it's not modified.
 *
 * @return PV_ALLOC_SUCCESS if the entry at `pai` was successfully updated with
 *         the new mapping, or the return value of pv_alloc() otherwise. See
 *         pv_alloc()'s function header for a detailed explanation of the
 *         possible return values.
 */
MARK_AS_PMAP_TEXT pv_alloc_return_t
pmap_enter_pv(
	pmap_t pmap,
	pt_entry_t *ptep,
	int pai,
	unsigned int options,
	pmap_lock_mode_t lock_mode,
	pv_entry_t **new_pvepp,
	int *new_pve_ptep_idx)
{
	assert(ptep != PT_ENTRY_NULL);

	pv_entry_t **pvh = pai_to_pvh(pai);
	bool first_cpu_mapping = false;

	ASSERT_NOT_HIBERNATING();
	pvh_assert_locked(pai);

	if (pmap != NULL) {
		pmap_assert_locked(pmap, lock_mode);
	}

	vm_offset_t pvh_flags = pvh_get_flags(pvh);

#if XNU_MONITOR
	if (__improbable(pvh_flags & PVH_FLAG_LOCKDOWN_MASK)) {
		panic("%d is locked down (%#lx), cannot enter", pai, pvh_flags);
	}
#endif /* XNU_MONITOR */


#ifdef PVH_FLAG_CPU
	/**
	 * An IOMMU mapping may already be present for a page that hasn't yet had a
	 * CPU mapping established, so we use PVH_FLAG_CPU to determine if this is
	 * the first CPU mapping. We base internal/reusable accounting on the
	 * options specified for the first CPU mapping. PVH_FLAG_CPU, and thus this
	 * accounting, will then persist as long as there are *any* mappings of the
	 * page. The accounting for a page should not need to change until the page
	 * is recycled by the VM layer, and we assert that there are no mappings
	 * when a page is recycled. An IOMMU mapping of a freed/recycled page is
	 * considered a security violation & potential DMA corruption path.
	 */
	first_cpu_mapping = ((pmap != NULL) && !(pvh_flags & PVH_FLAG_CPU));
	if (first_cpu_mapping) {
		pvh_flags |= PVH_FLAG_CPU;
	}
#else /* PVH_FLAG_CPU */
	first_cpu_mapping = pvh_test_type(pvh, PVH_TYPE_NULL);
#endif /* PVH_FLAG_CPU */

	/**
	 * Internal/reusable flags are based on the first CPU mapping made to a
	 * page. These will persist until all mappings to the page are removed.
	 */
	if (first_cpu_mapping) {
		if ((options & PMAP_OPTIONS_INTERNAL) &&
		    (options & PMAP_OPTIONS_REUSABLE)) {
			ppattr_set_reusable(pai);
		} else {
			ppattr_clear_reusable(pai);
		}
	}

	/* Visit the definitions for the PVH_TYPEs to learn more about each one. */
	if (pvh_test_type(pvh, PVH_TYPE_NULL)) {
		/* If this is the first mapping, upgrade the type to store a single PTEP. */
		pvh_update_head(pvh, ptep, PVH_TYPE_PTEP);
	} else {
		pv_alloc_return_t ret = PV_ALLOC_FAIL;

		if (pvh_test_type(pvh, PVH_TYPE_PTEP)) {
			/**
			 * There was already a single mapping to the page. Convert the PVH
			 * entry from PVH_TYPE_PTEP to PVH_TYPE_PVEP so that multiple
			 * mappings can be tracked. If PVEs cannot hold more than a single
			 * mapping, a second PVE will be added farther down.
			 *
			 * Also, ensure that the PVH flags (which can possibly contain
			 * PVH_FLAG_CPU) are set before potentially returning or dropping
			 * the locks. We use that flag to lock in the internal/reusable
			 * attributes and we don't want another mapping to jump in while the
			 * locks are dropped, think it's the first CPU mapping, and decide
			 * to clobber those attributes.
			 */
			pvh_set_flags(pvh, pvh_flags);
			if ((ret = pepv_convert_ptep_to_pvep(pmap, pai, lock_mode, options)) != PV_ALLOC_SUCCESS) {
				return ret;
			}

			/**
			 * At this point, the PVH flags have been clobbered due to updating
			 * PTEP->PVEP, but that's ok because the locks are being held and
			 * the flags will get set again below before pv_alloc() is called
			 * and the locks are potentially dropped again.
			 */
		} else if (!pvh_test_type(pvh, PVH_TYPE_PVEP)) {
			panic("%s: unexpected PV head %p, ptep=%p pmap=%p pvh=%p",
			    __func__, *pvh, ptep, pmap, pvh);
		}

		/**
		 * Check if we have room for one more mapping in this PVE
		 */
		pv_entry_t *pvep = pvh_pve_list(pvh);
		assert(pvep != PV_ENTRY_NULL);

		int pve_ptep_idx = pve_find_ptep_index(pvep, PT_ENTRY_NULL);

		if (pve_ptep_idx == -1) {
			/**
			 * Set up the pv_entry for this new mapping and then add it to the list
			 * for this physical page.
			 */
			pve_ptep_idx = 0;
			pvh_set_flags(pvh, pvh_flags);
			pvep = PV_ENTRY_NULL;
			if ((ret = pv_alloc(pmap, pai, lock_mode, options, &pvep)) != PV_ALLOC_SUCCESS) {
				return ret;
			}

			/* If we've gotten this far then a node should've been allocated. */
			assert(pvep != PV_ENTRY_NULL);
			pve_init(pvep);
			pve_add(pvh, pvep);
		}

		pve_set_ptep(pvep, pve_ptep_idx, ptep);

		/*
		 * The PTEP was successfully entered into the PVE object.
		 * If the caller requests it, set new_pvepp and new_pve_ptep_idx
		 * appropriately.
		 */
		if (new_pvepp != NULL) {
			*new_pvepp = pvep;
			*new_pve_ptep_idx = pve_ptep_idx;
		}
	}

	pvh_set_flags(pvh, pvh_flags);

	return PV_ALLOC_SUCCESS;
}

/**
 * Remove a mapping that was registered with the pv_head_table. This needs to be
 * done for every mapping that was previously registered using pmap_enter_pv()
 * when the mapping is removed.
 *
 * @note The PVH lock for the physical page that is getting a new mapping
 *       registered must already be held.
 *
 * @note This function cannot be called during the hibernation process because
 *       it modifies critical pmap data structures that need to be dumped into
 *       the hibernation image in a consistent state.
 *
 * @param pmap The pmap that owns the new mapping, or NULL if this is tracking
 *             an IOMMU translation.
 * @param ptep The mapping that's getting removed.
 * @param pai The physical address index of the physical page being mapped by
 *            `ptep`.
 * @param flush_tlb_async On some systems, removing the last mapping to a page
 *                        that used to be mapped executable will require
 *                        updating the physical aperture mapping of the page.
 *                        This parameter specifies whether the TLB invalidate
 *                        should be synchronized or not if that update occurs.
 * @param is_internal_p The internal bit of the PTE that was removed.
 * @param is_altacct_p The altacct bit of the PTE that was removed.
 */
void
pmap_remove_pv(
	pmap_t pmap,
	pt_entry_t *ptep,
	int pai,
	bool flush_tlb_async __unused,
	bool *is_internal_p,
	bool *is_altacct_p)
{
	ASSERT_NOT_HIBERNATING();
	pvh_assert_locked(pai);

	bool is_internal = false;
	bool is_altacct = false;
	pv_entry_t **pvh = pai_to_pvh(pai);
	const vm_offset_t pvh_flags = pvh_get_flags(pvh);

#if XNU_MONITOR
	if (__improbable(pvh_flags & PVH_FLAG_LOCKDOWN_MASK)) {
		panic("%s: PVH entry at pai %d is locked down (%#lx), cannot remove",
		    __func__, pai, pvh_flags);
	}
#endif /* XNU_MONITOR */


	if (pvh_test_type(pvh, PVH_TYPE_PTEP)) {
		if (__improbable((ptep != pvh_ptep(pvh)))) {
			/**
			 * The only mapping that exists for this page isn't the one we're
			 * unmapping, weird.
			 */
			panic("%s: ptep=%p does not match pvh=%p (%p), pai=0x%x",
			    __func__, ptep, pvh, pvh_ptep(pvh), pai);
		}

		pvh_update_head(pvh, PV_ENTRY_NULL, PVH_TYPE_NULL);
		is_internal = ppattr_is_internal(pai);
		is_altacct = ppattr_is_altacct(pai);
	} else if (pvh_test_type(pvh, PVH_TYPE_PVEP)) {
		pv_entry_t **pvepp = pvh;
		pv_entry_t *pvep = pvh_pve_list(pvh);
		assert(pvep != PV_ENTRY_NULL);
		int pve_pte_idx = 0;
		/* Find the PVE that represents the mapping we're removing. */
		while ((pvep != PV_ENTRY_NULL) && ((pve_pte_idx = pve_find_ptep_index(pvep, ptep)) == -1)) {
			pvepp = pve_next_ptr(pvep);
			pvep = pve_next(pvep);
		}

		if (__improbable((pvep == PV_ENTRY_NULL))) {
			panic("%s: ptep=%p (pai=0x%x) not in pvh=%p", __func__, ptep, pai, pvh);
		}

		is_internal = pve_get_internal(pvep, pve_pte_idx);
		is_altacct = pve_get_altacct(pvep, pve_pte_idx);
		pve_set_ptep(pvep, pve_pte_idx, PT_ENTRY_NULL);

#if MACH_ASSERT
		/**
		 * Ensure that the mapping didn't accidentally have multiple PVEs
		 * associated with it (there should only be one PVE per mapping). This
		 * checking only occurs on configurations that can accept the perf hit
		 * that walking the PVE chain on every unmap entails.
		 *
		 * This is skipped for IOMMU mappings because some IOMMUs don't use
		 * normal page tables (e.g., NVMe) to map pages, so the `ptep` field in
		 * the associated PVE won't actually point to a real page table (see the
		 * definition of PVH_FLAG_IOMMU_TABLE for more info). Because of that,
		 * it's perfectly possible for duplicate IOMMU PVEs to exist.
		 */
		if ((pmap != NULL) && (kern_feature_override(KF_PMAPV_OVRD) == FALSE)) {
			pv_entry_t *check_pvep = pvep;

			do {
				if (pve_find_ptep_index(check_pvep, ptep) != -1) {
					panic_plain("%s: duplicate pve entry ptep=%p pmap=%p, pvh=%p, "
					    "pvep=%p, pai=0x%x", __func__, ptep, pmap, pvh, pvep, pai);
				}
			} while ((check_pvep = pve_next(check_pvep)) != PV_ENTRY_NULL);
		}
#endif /* MACH_ASSERT */

		const bool pve_is_first = (pvepp == pvh);
		const bool pve_is_last = (pve_next(pvep) == PV_ENTRY_NULL);
		const int other_pte_idx = !pve_pte_idx;

		if (pve_is_empty(pvep)) {
			/*
			 * This PVE doesn't contain any mappings. We can get rid of it.
			 */
			pve_remove(pvh, pvepp, pvep);
			pv_free(pvep);
		} else if (!pve_is_first) {
			/*
			 * This PVE contains a single mapping. See if we can coalesce it with the one
			 * at the top of the list.
			 */
			pv_entry_t *head_pvep = pvh_pve_list(pvh);
			int head_pve_pte_empty_idx;
			if ((head_pve_pte_empty_idx = pve_find_ptep_index(head_pvep, PT_ENTRY_NULL)) != -1) {
				pve_set_ptep(head_pvep, head_pve_pte_empty_idx, pve_get_ptep(pvep, other_pte_idx));
				if (pve_get_internal(pvep, other_pte_idx)) {
					pve_set_internal(head_pvep, head_pve_pte_empty_idx);
				}
				if (pve_get_altacct(pvep, other_pte_idx)) {
					pve_set_altacct(head_pvep, head_pve_pte_empty_idx);
				}
				pve_remove(pvh, pvepp, pvep);
				pv_free(pvep);
			} else {
				/*
				 * We could not coalesce it. Move it to the start of the list, so that it
				 * can be coalesced against in the future.
				 */
				*pvepp = pve_next(pvep);
				pve_add(pvh, pvep);
			}
		} else if (pve_is_first && pve_is_last) {
			/*
			 * This PVE contains a single mapping, and it's the last mapping for this PAI.
			 * Collapse this list back into the head, turning it into a PVH_TYPE_PTEP entry.
			 */
			pve_remove(pvh, pvepp, pvep);
			pvh_update_head(pvh, pve_get_ptep(pvep, other_pte_idx), PVH_TYPE_PTEP);
			if (pve_get_internal(pvep, other_pte_idx)) {
				ppattr_set_internal(pai);
			}
			if (pve_get_altacct(pvep, other_pte_idx)) {
				ppattr_set_altacct(pai);
			}
			pv_free(pvep);
		}

		/**
		 * Removing a PVE entry can clobber the PVH flags if the head itself is
		 * updated (when removing the first PVE in the list) so let's re-set the
		 * flags back to what they should be.
		 */
		if (!pvh_test_type(pvh, PVH_TYPE_NULL)) {
			pvh_set_flags(pvh, pvh_flags);
		}
	} else {
		panic("%s: unexpected PV head %p, ptep=%p pmap=%p pvh=%p pai=0x%x",
		    __func__, *pvh, ptep, pmap, pvh, pai);
	}

#ifdef PVH_FLAG_EXEC
	/**
	 * If we're on a system that has extra protections around executable pages,
	 * then removing the last mapping to an executable page means we need to
	 * give write-access back to the physical aperture mapping of this page
	 * (write access is removed when a page is executable for security reasons).
	 */
	if ((pvh_flags & PVH_FLAG_EXEC) && pvh_test_type(pvh, PVH_TYPE_NULL)) {
		pmap_set_ptov_ap(pai, AP_RWNA, flush_tlb_async);
	}
#endif /* PVH_FLAG_EXEC */
	if (__improbable((pvh_flags & PVH_FLAG_FLUSH_NEEDED) && pvh_test_type(pvh, PVH_TYPE_NULL))) {
		pmap_flush_noncoherent_page((pmap_paddr_t)ptoa(pai) + vm_first_phys);
	}

	*is_internal_p = is_internal;
	*is_altacct_p = is_altacct;
}

/**
 * Bootstrap the initial Page Table Descriptor (PTD) node free list.
 *
 * @note It's not safe to allocate PTD nodes until after this function is
 *       invoked.
 *
 * @note The maximum number of PTD objects that can reside within one page
 *       (`ptd_per_page`) must have already been calculated before calling this
 *       function.
 *
 * @param ptdp Pointer to the virtually-contiguous memory used for the initial
 *             free list.
 * @param num_pages The number of virtually-contiguous pages pointed to by
 *                  `ptdp` that will be used to prime the PTD allocator.
 */
MARK_AS_PMAP_TEXT void
ptd_bootstrap(pt_desc_t *ptdp, unsigned int num_pages)
{
	assert(ptd_per_page > 0);
	assert((ptdp != NULL) && (((uintptr_t)ptdp & PAGE_MASK) == 0) && (num_pages > 0));

	queue_init(&pt_page_list);

	/**
	 * Region represented by ptdp should be cleared by pmap_bootstrap().
	 *
	 * Only part of each page is being used for PTD objects (the rest is used
	 * for each PTD's associated ptd_info_t object) so link together the last
	 * PTD element of each page to the first element of the previous page.
	 */
	for (int i = 0; i < num_pages; i++) {
		*((void**)(&ptdp[ptd_per_page - 1])) = (void*)ptd_free_list;
		ptd_free_list = ptdp;
		ptdp = (void *)(((uint8_t *)ptdp) + PAGE_SIZE);
	}

	ptd_free_count = num_pages * ptd_per_page;
	simple_lock_init(&ptd_free_list_lock, 0);
}

/**
 * Allocate a page table descriptor (PTD) object from the PTD free list, but
 * don't add it to the list of reclaimable userspace page table pages just yet
 * and don't associate the PTD with a specific pmap (that's what "unlinked"
 * means here).
 *
 * @note Until a page table's descriptor object is added to the page table list,
 *       that table won't be eligible for reclaiming by pmap_page_reclaim().
 *
 * @return The page table descriptor object if the allocation was successful, or
 *         NULL otherwise (which indicates that a page failed to be allocated
 *         for new nodes).
 */
MARK_AS_PMAP_TEXT pt_desc_t*
ptd_alloc_unlinked(void)
{
	pt_desc_t *ptdp = PTD_ENTRY_NULL;

	pmap_simple_lock(&ptd_free_list_lock);

	assert(ptd_per_page != 0);

	/**
	 * Ensure that we either have a free list with nodes available, or a
	 * completely empty list to allocate and prepend new nodes to.
	 */
	assert(((ptd_free_list != NULL) && (ptd_free_count > 0)) ||
	    ((ptd_free_list == NULL) && (ptd_free_count == 0)));

	if (__improbable(ptd_free_count == 0)) {
		pmap_paddr_t pa = 0;

		/* Drop the lock while allocating pages since that can take a while. */
		pmap_simple_unlock(&ptd_free_list_lock);

		if (pmap_pages_alloc_zeroed(&pa, PAGE_SIZE, PMAP_PAGES_ALLOCATE_NOWAIT) != KERN_SUCCESS) {
			return NULL;
		}
		ptdp = (pt_desc_t *)phystokv(pa);

		pmap_simple_lock(&ptd_free_list_lock);

		/**
		 * Since the lock was dropped while allocating, it's possible another
		 * CPU already allocated a page. To be safe, prepend the current free
		 * list (which may or may not be empty now) to the page of nodes just
		 * allocated and update the head to point to these new nodes.
		 */
		*((void**)(&ptdp[ptd_per_page - 1])) = (void*)ptd_free_list;
		ptd_free_list = ptdp;
		ptd_free_count += ptd_per_page;
	}

	/* There should be available nodes at this point. */
	if (__improbable((ptd_free_count == 0) || (ptd_free_list == PTD_ENTRY_NULL))) {
		panic_plain("%s: out of PTD entries and for some reason didn't "
		    "allocate more %d %p", __func__, ptd_free_count, ptd_free_list);
	}

	/* Grab the top node off of the free list to return later. */
	ptdp = ptd_free_list;

	/**
	 * Advance the free list to the next node.
	 *
	 * Each free pt_desc_t-sized object in this free list uses the first few
	 * bytes of the object to point to the next object in the list. When an
	 * object is deallocated (in ptd_deallocate()) the object is prepended onto
	 * the free list by setting its first few bytes to point to the current free
	 * list head. Then the head is updated to point to that object.
	 *
	 * When a new page is allocated for PTD nodes, it's left zeroed out. Once we
	 * use up all of the previously deallocated nodes, the list will point
	 * somewhere into the last allocated, empty page. We know we're pointing at
	 * this page because the first few bytes of the object will be NULL. In
	 * that case just set the head to this empty object.
	 *
	 * This empty page can be thought of as a "reserve" of empty nodes for the
	 * case where more nodes are being allocated than there are nodes being
	 * deallocated.
	 */
	pt_desc_t *const next_node = (pt_desc_t *)(*(void **)ptd_free_list);

	/**
	 * If the next node in the list is NULL but there are supposed to still be
	 * nodes left, then we've hit the previously allocated empty page of nodes.
	 * Go ahead and advance the free list to the next free node in that page.
	 */
	if ((next_node == PTD_ENTRY_NULL) && (ptd_free_count > 1)) {
		ptd_free_list = ptd_free_list + 1;
	} else {
		ptd_free_list = next_node;
	}

	ptd_free_count--;

	pmap_simple_unlock(&ptd_free_list_lock);

	ptdp->pt_page.next = NULL;
	ptdp->pt_page.prev = NULL;
	ptdp->pmap = NULL;

	/**
	 * Calculate and stash the address of the ptd_info_t associated with this
	 * PTD. This can be done easily because both structures co-exist in the same
	 * page, with ptd_info_t's starting at a given offset from the start of the
	 * page.
	 *
	 * Each PTD is associated with a ptd_info_t of the same index. For example,
	 * the 15th PTD will use the 15th ptd_info_t in the same page.
	 */
	const unsigned ptd_index = ((uintptr_t)ptdp & PAGE_MASK) / sizeof(pt_desc_t);
	assert(ptd_index < ptd_per_page);

	const uintptr_t start_of_page = (uintptr_t)ptdp & ~PAGE_MASK;
	ptd_info_t *first_ptd_info = (ptd_info_t *)(start_of_page + ptd_info_offset);
	ptdp->ptd_info = &first_ptd_info[ptd_index * PT_INDEX_MAX];

	/**
	 * On systems where the VM page size doesn't match the hardware page size,
	 * one PTD might have to manage multiple page tables.
	 */
	for (unsigned int i = 0; i < PT_INDEX_MAX; i++) {
		ptdp->va[i] = (vm_offset_t)-1;
		ptdp->ptd_info[i].refcnt = 0;
		ptdp->ptd_info[i].wiredcnt = 0;
	}

	return ptdp;
}

/**
 * Allocate a single page table descriptor (PTD) object, and if it's meant to
 * keep track of a userspace page table, then add that descriptor object to the
 * list of PTDs that can be reclaimed in pmap_page_reclaim().
 *
 * @param pmap The pmap object that will be owning the page table(s) that this
 *             descriptor object represents.
 *
 * @return The allocated PTD object, or NULL if one failed to get allocated
 *         (which indicates that memory wasn't able to get allocated).
 */
MARK_AS_PMAP_TEXT pt_desc_t*
ptd_alloc(pmap_t pmap)
{
	pt_desc_t *ptdp = ptd_alloc_unlinked();

	if (ptdp == NULL) {
		return NULL;
	}

	ptdp->pmap = pmap;
	if (pmap != kernel_pmap) {
		/**
		 * We should never try to reclaim kernel pagetable pages in
		 * pmap_page_reclaim(), so don't enter them into the list.
		 */
		pmap_simple_lock(&pt_pages_lock);
		queue_enter(&pt_page_list, ptdp, pt_desc_t *, pt_page);
		pmap_simple_unlock(&pt_pages_lock);
	}

	pmap_tt_ledger_credit(pmap, sizeof(*ptdp));
	return ptdp;
}

/**
 * Deallocate a single page table descriptor (PTD) object.
 *
 * @note Ledger statistics are tracked on a per-pmap basis, so for those pages
 *       which are not associated with any specific pmap (e.g., IOMMU pages),
 *       the caller must ensure that the pmap/iommu field in the PTD object is
 *       NULL before calling this function.
 *
 * @param ptdp Pointer to the PTD object to deallocate.
 */
MARK_AS_PMAP_TEXT void
ptd_deallocate(pt_desc_t *ptdp)
{
	pmap_t pmap = ptdp->pmap;

	/**
	 * If this PTD was put onto the reclaimable page table list, then remove it
	 * from that list before deallocating.
	 */
	if (ptdp->pt_page.next != NULL) {
		pmap_simple_lock(&pt_pages_lock);
		queue_remove(&pt_page_list, ptdp, pt_desc_t *, pt_page);
		pmap_simple_unlock(&pt_pages_lock);
	}

	/* Prepend the deallocated node to the free list. */
	pmap_simple_lock(&ptd_free_list_lock);
	(*(void **)ptdp) = (void *)ptd_free_list;
	ptd_free_list = (pt_desc_t *)ptdp;
	ptd_free_count++;
	pmap_simple_unlock(&ptd_free_list_lock);

	/**
	 * If this PTD was being used to represent an IOMMU page then there won't be
	 * an associated pmap, and therefore no ledger statistics to update.
	 */
	if (pmap != NULL) {
		pmap_tt_ledger_debit(pmap, sizeof(*ptdp));
	}
}

/**
 * In address spaces where the VM page size is larger than the underlying
 * hardware page size, one page table descriptor (PTD) object can represent
 * multiple page tables. Some fields (like the reference counts) still need to
 * be tracked on a per-page-table basis. Because of this, those values are
 * stored in a separate array of ptd_info_t objects within the PTD where there's
 * one ptd_info_t for every page table a single PTD can manage.
 *
 * This function initializes the correct ptd_info_t field within a PTD based on
 * the page table it's representing.
 *
 * @param ptdp Pointer to the PTD object which contains the ptd_info_t field to
 *             update. Must match up with the `pmap` and `ptep` parameters.
 * @param pmap The pmap that owns the page table managed by the passed in PTD.
 * @param va Any virtual address that resides within the virtual address space
 *           being mapped by the page table pointed to by `ptep`.
 * @param level The level in the page table hierarchy that the table resides.
 * @param ptep A pointer into a page table that the passed in PTD manages. This
 *             page table must be owned by `pmap` and be the PTE that maps `va`.
 */
MARK_AS_PMAP_TEXT void
ptd_info_init(
	pt_desc_t *ptdp,
	pmap_t pmap,
	vm_map_address_t va,
	unsigned int level,
	pt_entry_t *ptep)
{
	const pt_attr_t * const pt_attr = pmap_get_pt_attr(pmap);

	if (ptdp->pmap != pmap) {
		panic("%s: pmap mismatch, ptdp=%p, pmap=%p, va=%p, level=%u, ptep=%p",
		    __func__, ptdp, pmap, (void*)va, level, ptep);
	}

	/**
	 * Root tables are managed separately, and can be accessed through the
	 * pmap structure itself (there's only one root table per address space).
	 */
	assert(level > pt_attr_root_level(pt_attr));

	/**
	 * Each PTD can represent multiple page tables. Get the correct index to use
	 * with the per-page-table properties.
	 */
	const unsigned pt_index = ptd_get_index(ptdp, ptep);

	/**
	 * The "va" field represents the first virtual address that this page table
	 * is translating for. Naturally, this is dependent on the level the page
	 * table resides at since more VA space is mapped the closer the page
	 * table's level is to the root.
	 */
	ptdp->va[pt_index] = (vm_offset_t) va & ~pt_attr_ln_offmask(pt_attr, level - 1);

	/**
	 * Reference counts are only tracked on CPU leaf tables because those are
	 * the only tables that can be opportunistically deallocated.
	 */
	if (level < pt_attr_leaf_level(pt_attr)) {
		ptdp->ptd_info[pt_index].refcnt = PT_DESC_REFCOUNT;
	}
}

#if XNU_MONITOR

/**
 * Validate that a pointer passed into the PPL is indeed an actual ledger object
 * that was allocated from within the PPL.
 *
 * If this is truly a real PPL-allocated ledger object then the object will have
 * an index into the ledger pointer array located right after it. That index
 * into the ledger pointer array should contain the exact same pointer that
 * we're validating. This works because the ledger array is PPL-owned data, so
 * even if the index was fabricated to try and point to a different ledger
 * object, the pointer inside the array won't match up with the passed in
 * pointer and validation will fail.
 *
 * @note This validation does not need to occur on non-PPL systems because on
 *       those systems the ledger objects are allocated using a zone allocator.
 *
 * @param ledger Pointer to the supposed ledger object that we need to validate.
 *
 * @return The index into the ledger pointer array used to validate the passed
 *         in ledger pointer. If the pointer failed to validate, then the system
 *         will panic.
 */
MARK_AS_PMAP_TEXT uint64_t
pmap_ledger_validate(const volatile void *ledger)
{
	assert(ledger != NULL);

	uint64_t array_index = ((const volatile pmap_ledger_t*)ledger)->array_index;

	if (__improbable(array_index >= pmap_ledger_ptr_array_count)) {
		panic("%s: ledger %p array index invalid, index was %#llx", __func__,
		    ledger, array_index);
	}

	if (__improbable(pmap_ledger_ptr_array[array_index] != ledger)) {
		panic("%s: ledger pointer mismatch, %p != %p", __func__, ledger,
		    pmap_ledger_ptr_array[array_index]);
	}

	return array_index;
}

/**
 * The size of the ledgers being allocated by the PPL need to be large enough
 * to handle ledgers produced by the task_ledgers ledger template. That template
 * is dynamically created at runtime so this function is used to verify that the
 * real size of a ledger based on the task_ledgers template matches up with the
 * amount of space the PPL calculated is required for a single ledger.
 *
 * @note See the definition of PMAP_LEDGER_DATA_BYTES for more information.
 *
 * @note This function needs to be called before any ledgers can be allocated.
 *
 * @param size The actual size that each pmap ledger should be. This is
 *             calculated based on the task_ledgers template which should match
 *             up with PMAP_LEDGER_DATA_BYTES.
 */
MARK_AS_PMAP_TEXT void
pmap_ledger_verify_size_internal(size_t size)
{
	pmap_simple_lock(&pmap_ledger_lock);

	if (pmap_ledger_size_verified) {
		panic("%s: ledger size already verified, size=%lu", __func__, size);
	}

	if ((size == 0) || (size > sizeof(pmap_ledger_data_t)) ||
	    ((sizeof(pmap_ledger_data_t) - size) % sizeof(struct ledger_entry))) {
		panic("%s: size mismatch, expected %lu, size=%lu", __func__,
		    PMAP_LEDGER_DATA_BYTES, size);
	}

	pmap_ledger_size_verified = true;

	pmap_simple_unlock(&pmap_ledger_lock);
}

/**
 * Allocate a ledger object from the pmap ledger free list and associate it with
 * the ledger pointer array so it can be validated when passed into the PPL.
 *
 * @return Pointer to the successfully allocated ledger object, or NULL if we're
 *         out of PPL pages.
 */
MARK_AS_PMAP_TEXT ledger_t
pmap_ledger_alloc_internal(void)
{
	/**
	 * Ensure that we've double checked the size of the ledger objects we're
	 * allocating before we allocate anything.
	 */
	if (!pmap_ledger_size_verified) {
		panic_plain("%s: Attempted to allocate a pmap ledger before verifying "
		    "the ledger size", __func__);
	}

	pmap_simple_lock(&pmap_ledger_lock);
	if (pmap_ledger_free_list == NULL) {
		/* The free list is empty, so allocate a page's worth of objects. */
		const pmap_paddr_t paddr = pmap_get_free_ppl_page();

		if (paddr == 0) {
			pmap_simple_unlock(&pmap_ledger_lock);
			return NULL;
		}

		const vm_map_address_t vstart = phystokv(paddr);
		const uint32_t ledgers_per_page = PAGE_SIZE / sizeof(pmap_ledger_t);
		const vm_map_address_t vend = vstart + (ledgers_per_page * sizeof(pmap_ledger_t));
		assert(vend > vstart);

		/**
		 * Loop through every pmap ledger object within the recently allocated
		 * page and add it to both the ledger free list and the ledger pointer
		 * array (which will be used to validate these objects in the future).
		 */
		for (vm_map_address_t vaddr = vstart; vaddr < vend; vaddr += sizeof(pmap_ledger_t)) {
			/* Get the next free entry in the ledger pointer array. */
			const uint64_t index = pmap_ledger_ptr_array_free_index++;

			if (index >= pmap_ledger_ptr_array_count) {
				panic("%s: pmap_ledger_ptr_array is full, index=%llu",
				    __func__, index);
			}

			pmap_ledger_t *free_ledger = (pmap_ledger_t*)vaddr;

			/**
			 * This association between the just allocated ledger and the
			 * pointer array is what allows this object to be validated in the
			 * future that it's indeed a ledger allocated by this code.
			 */
			pmap_ledger_ptr_array[index] = free_ledger;
			free_ledger->array_index = index;

			/* Prepend this new ledger object to the free list. */
			free_ledger->next = pmap_ledger_free_list;
			pmap_ledger_free_list = free_ledger;
		}

		/**
		 * In an effort to reduce the amount of ledger code that needs to be
		 * called from within the PPL, the ledger objects themselves are made
		 * kernel writable. This way, all of the initialization and checking of
		 * the ledgers can occur outside of the PPL.
		 *
		 * The only modification to these ledger objects that should occur from
		 * within the PPL is when debiting/crediting the ledgers. And those
		 * operations should only occur on validated ledger objects that are
		 * validated using the ledger pointer array (which is wholly contained
		 * in PPL-owned memory).
		 */
		pa_set_range_xprr_perm(paddr, paddr + PAGE_SIZE, XPRR_PPL_RW_PERM, XPRR_KERN_RW_PERM);
	}

	ledger_t new_ledger = (ledger_t)pmap_ledger_free_list;
	pmap_ledger_free_list = pmap_ledger_free_list->next;

	/**
	 * Double check that the array index of the recently allocated object wasn't
	 * tampered with while the object was sitting on the free list.
	 */
	const uint64_t array_index = pmap_ledger_validate(new_ledger);
	os_ref_init(&pmap_ledger_refcnt[array_index], NULL);

	pmap_simple_unlock(&pmap_ledger_lock);

	return new_ledger;
}

/**
 * Free a ledger that was previously allocated by the PPL.
 *
 * @param ledger The ledger to put back onto the pmap ledger free list.
 */
MARK_AS_PMAP_TEXT void
pmap_ledger_free_internal(ledger_t ledger)
{
	/**
	 * A pmap_ledger_t wholly contains a ledger_t as its first member, but also
	 * includes an index into the ledger pointer array used for validation
	 * purposes.
	 */
	pmap_ledger_t *free_ledger = (pmap_ledger_t*)ledger;

	pmap_simple_lock(&pmap_ledger_lock);

	/* Ensure that what we're putting onto the free list is a real ledger. */
	const uint64_t array_index = pmap_ledger_validate(ledger);

	/* Ensure no pmap objects are still using this ledger. */
	if (os_ref_release(&pmap_ledger_refcnt[array_index]) != 0) {
		panic("%s: ledger still referenced, ledger=%p", __func__, ledger);
	}

	/* Prepend the ledger to the free list. */
	free_ledger->next = pmap_ledger_free_list;
	pmap_ledger_free_list = free_ledger;

	pmap_simple_unlock(&pmap_ledger_lock);
}

/**
 * Bump the reference count on a ledger object to denote that is currently in
 * use by a pmap object.
 *
 * @param ledger The ledger whose refcnt to increment.
 */
MARK_AS_PMAP_TEXT void
pmap_ledger_retain(ledger_t ledger)
{
	pmap_simple_lock(&pmap_ledger_lock);
	const uint64_t array_index = pmap_ledger_validate(ledger);
	os_ref_retain(&pmap_ledger_refcnt[array_index]);
	pmap_simple_unlock(&pmap_ledger_lock);
}

/**
 * Decrement the reference count on a ledger object to denote that a pmap object
 * that used to use it now isn't.
 *
 * @param ledger The ledger whose refcnt to decrement.
 */
MARK_AS_PMAP_TEXT void
pmap_ledger_release(ledger_t ledger)
{
	pmap_simple_lock(&pmap_ledger_lock);
	const uint64_t array_index = pmap_ledger_validate(ledger);
	os_ref_release_live(&pmap_ledger_refcnt[array_index]);
	pmap_simple_unlock(&pmap_ledger_lock);
}

/**
 * This function is used to check a ledger that was recently updated (usually
 * from within the PPL) and potentially take actions based on the new ledger
 * balances (e.g., set an AST).
 *
 * @note On non-PPL systems this checking occurs automatically every time a
 *       ledger is credited/debited. Due to that, this function only needs to
 *       get called on PPL-enabled systems.
 *
 * @note This function can ONLY be called from *outside* of the PPL due to its
 *       usage of current_thread(). The TPIDR register is kernel-modifiable, and
 *       hence can't be trusted. This also means we don't need to pull all of
 *       the logic used to check ledger balances into the PPL.
 *
 * @param pmap The pmap whose ledger should be checked.
 */
void
pmap_ledger_check_balance(pmap_t pmap)
{
	/* This function should only be called from outside of the PPL. */
	assert((pmap != NULL) && !pmap_in_ppl());

	ledger_t ledger = pmap->ledger;

	if (ledger == NULL) {
		return;
	}

	thread_t cur_thread = current_thread();
	ledger_check_new_balance(cur_thread, ledger, task_ledgers.alternate_accounting);
	ledger_check_new_balance(cur_thread, ledger, task_ledgers.alternate_accounting_compressed);
	ledger_check_new_balance(cur_thread, ledger, task_ledgers.internal);
	ledger_check_new_balance(cur_thread, ledger, task_ledgers.internal_compressed);
	ledger_check_new_balance(cur_thread, ledger, task_ledgers.page_table);
	ledger_check_new_balance(cur_thread, ledger, task_ledgers.phys_footprint);
	ledger_check_new_balance(cur_thread, ledger, task_ledgers.phys_mem);
	ledger_check_new_balance(cur_thread, ledger, task_ledgers.tkm_private);
	ledger_check_new_balance(cur_thread, ledger, task_ledgers.wired_mem);
}

#endif /* XNU_MONITOR */

/**
 * Credit a specific ledger entry within the passed in pmap's ledger object.
 *
 * @note On PPL-enabled systems this operation will not automatically check the
 *       ledger balances after updating. A call to pmap_ledger_check_balance()
 *       will need to occur outside of the PPL to handle this.
 *
 * @param pmap The pmap whose ledger should be updated.
 * @param entry The specifc ledger entry to update. This needs to be one of the
 *              task_ledger entries.
 * @param amount The amount to credit from the ledger.
 *
 * @return The return value from the credit operation.
 */
kern_return_t
pmap_ledger_credit(pmap_t pmap, int entry, ledger_amount_t amount)
{
	assert(pmap != NULL);

#if XNU_MONITOR
	/**
	 * On PPL-enabled systems the "nocheck" variant MUST be called to ensure
	 * that the ledger balance doesn't automatically get checked after being
	 * updated.
	 *
	 * That checking process is unsafe to perform within the PPL due to its
	 * reliance on current_thread().
	 */
	return ledger_credit_nocheck(pmap->ledger, entry, amount);
#else /* XNU_MONITOR */
	return ledger_credit(pmap->ledger, entry, amount);
#endif /* XNU_MONITOR */
}

/**
 * Debit a specific ledger entry within the passed in pmap's ledger object.
 *
 * @note On PPL-enabled systems this operation will not automatically check the
 *       ledger balances after updating. A call to pmap_ledger_check_balance()
 *       will need to occur outside of the PPL to handle this.
 *
 * @param pmap The pmap whose ledger should be updated.
 * @param entry The specifc ledger entry to update. This needs to be one of the
 *              task_ledger entries.
 * @param amount The amount to debit from the ledger.
 *
 * @return The return value from the debit operation.
 */
kern_return_t
pmap_ledger_debit(pmap_t pmap, int entry, ledger_amount_t amount)
{
	assert(pmap != NULL);

#if XNU_MONITOR
	/**
	 * On PPL-enabled systems the "nocheck" variant MUST be called to ensure
	 * that the ledger balance doesn't automatically get checked after being
	 * updated.
	 *
	 * That checking process is unsafe to perform within the PPL due to its
	 * reliance on current_thread().
	 */
	return ledger_debit_nocheck(pmap->ledger, entry, amount);
#else /* XNU_MONITOR */
	return ledger_debit(pmap->ledger, entry, amount);
#endif /* XNU_MONITOR */
}

#if XNU_MONITOR

/**
 * Allocate a pmap object from the pmap object free list and associate it with
 * the pmap pointer array so it can be validated when passed into the PPL.
 *
 * @param pmap Output parameter that holds the newly allocated pmap object if
 *             the operation was successful, or NULL otherwise. The return value
 *             must be checked to know what this parameter should return.
 *
 * @return KERN_SUCCESS if the allocation was successful, KERN_RESOURCE_SHORTAGE
 *         if out of free PPL pages, or KERN_NO_SPACE if more pmap objects were
 *         trying to be allocated than the pmap pointer array could manage. On
 *         KERN_SUCCESS, the `pmap` output parameter will point to the newly
 *         allocated object.
 */
MARK_AS_PMAP_TEXT kern_return_t
pmap_alloc_pmap(pmap_t *pmap)
{
	pmap_t new_pmap = PMAP_NULL;
	kern_return_t kr = KERN_SUCCESS;

	pmap_simple_lock(&pmap_free_list_lock);

	if (pmap_free_list == NULL) {
		/* If the pmap pointer array is full, then no more objects can be allocated. */
		if (__improbable(pmap_ptr_array_free_index == pmap_ptr_array_count)) {
			kr = KERN_NO_SPACE;
			goto pmap_alloc_cleanup;
		}

		/* The free list is empty, so allocate a page's worth of objects. */
		const pmap_paddr_t paddr = pmap_get_free_ppl_page();

		if (paddr == 0) {
			kr = KERN_RESOURCE_SHORTAGE;
			goto pmap_alloc_cleanup;
		}

		const vm_map_address_t vstart = phystokv(paddr);
		const uint32_t pmaps_per_page = PAGE_SIZE / sizeof(pmap_list_entry_t);
		const vm_map_address_t vend = vstart + (pmaps_per_page * sizeof(pmap_list_entry_t));
		assert(vend > vstart);

		/**
		 * Loop through every pmap object within the recently allocated page and
		 * add it to both the pmap free list and the pmap pointer array (which
		 * will be used to validate these objects in the future).
		 */
		for (vm_map_address_t vaddr = vstart; vaddr < vend; vaddr += sizeof(pmap_list_entry_t)) {
			/* Get the next free entry in the pmap pointer array. */
			const unsigned long index = pmap_ptr_array_free_index++;

			if (__improbable(index >= pmap_ptr_array_count)) {
				panic("%s: pmap array index %lu >= limit %lu; corruption?",
				    __func__, index, pmap_ptr_array_count);
			}
			pmap_list_entry_t *free_pmap = (pmap_list_entry_t*)vaddr;
			os_atomic_init(&free_pmap->pmap.ref_count, 0);

			/**
			 * This association between the just allocated pmap object and the
			 * pointer array is what allows this object to be validated in the
			 * future that it's indeed a pmap object allocated by this code.
			 */
			pmap_ptr_array[index] = free_pmap;
			free_pmap->array_index = index;

			/* Prepend this new pmap object to the free list. */
			free_pmap->next = pmap_free_list;
			pmap_free_list = free_pmap;

			/* Check if we've reached the maximum number of pmap objects. */
			if (__improbable(pmap_ptr_array_free_index == pmap_ptr_array_count)) {
				break;
			}
		}
	}

	new_pmap = &pmap_free_list->pmap;
	pmap_free_list = pmap_free_list->next;

pmap_alloc_cleanup:
	pmap_simple_unlock(&pmap_free_list_lock);
	*pmap = new_pmap;
	return kr;
}

/**
 * Free a pmap object that was previously allocated by the PPL.
 *
 * @note This should only be called on pmap objects that have already been
 *       validated to be real pmap objects.
 *
 * @param pmap The pmap object to put back onto the pmap free.
 */
MARK_AS_PMAP_TEXT void
pmap_free_pmap(pmap_t pmap)
{
	/**
	 * A pmap_list_entry_t wholly contains a struct pmap as its first member,
	 * but also includes an index into the pmap pointer array used for
	 * validation purposes.
	 */
	pmap_list_entry_t *free_pmap = (pmap_list_entry_t*)pmap;
	if (__improbable(free_pmap->array_index >= pmap_ptr_array_count)) {
		panic("%s: pmap %p has index %lu >= limit %lu", __func__, pmap,
		    free_pmap->array_index, pmap_ptr_array_count);
	}

	pmap_simple_lock(&pmap_free_list_lock);

	/* Prepend the pmap object to the free list. */
	free_pmap->next = pmap_free_list;
	pmap_free_list = free_pmap;

	pmap_simple_unlock(&pmap_free_list_lock);
}

#endif /* XNU_MONITOR */

#if XNU_MONITOR

/**
 * Helper function to validate that the pointer passed into this method is truly
 * a userspace pmap object that was allocated through the pmap_alloc_pmap() API.
 * This function will panic if the validation fails.
 *
 * @param pmap The pointer to validate.
 * @param func The stringized function name of the caller that will be printed
 *             in the case that the validation fails.
 */
static void
validate_user_pmap(const volatile struct pmap *pmap, const char *func)
{
	/**
	 * Ensure the array index isn't corrupted. This could happen if an attacker
	 * is trying to pass off random memory as a pmap object.
	 */
	const unsigned long array_index = ((const volatile pmap_list_entry_t*)pmap)->array_index;
	if (__improbable(array_index >= pmap_ptr_array_count)) {
		panic("%s: pmap array index %lu >= limit %lu", func, array_index, pmap_ptr_array_count);
	}

	/**
	 * If the array index is valid, then ensure that the passed in object
	 * matches up with the object in the pmap pointer array for this index. Even
	 * if an attacker passed in random memory with a valid index, there's no way
	 * the pmap pointer array will ever point to anything but the objects
	 * allocated by the pmap free list (it's PPL-owned memory).
	 */
	if (__improbable(pmap_ptr_array[array_index] != (const volatile pmap_list_entry_t*)pmap)) {
		panic("%s: pmap %p does not match array element %p at index %lu", func, pmap,
		    pmap_ptr_array[array_index], array_index);
	}

	/**
	 * Ensure that this isn't just an object sitting on the free list waiting to
	 * be allocated. This also helps protect against a race between validating
	 * and deleting a pmap object.
	 */
	if (__improbable(os_atomic_load(&pmap->ref_count, seq_cst) <= 0)) {
		panic("%s: pmap %p is not in use", func, pmap);
	}
}

#endif /* XNU_MONITOR */

/**
 * Validate that the pointer passed into this method is a valid pmap object and
 * is safe to read from and base PPL decisions off of. This function will panic
 * if the validation fails.
 *
 * @note On non-PPL systems this only checks that the pmap object isn't NULL.
 *
 * @note This validation should only be used on objects that won't be written to
 *       for the duration of the PPL call. If the object is going to be modified
 *       then you must use validate_pmap_mutable().
 *
 * @param pmap The pointer to validate.
 * @param func The stringized function name of the caller that will be printed
 *             in the case that the validation fails.
 */
void
validate_pmap_internal(const volatile struct pmap *pmap, const char *func)
{
#if !XNU_MONITOR
	#pragma unused(pmap, func)
	assert(pmap != NULL);
#else /* !XNU_MONITOR */
	if (pmap != kernel_pmap) {
		validate_user_pmap(pmap, func);
	}
#endif /* !XNU_MONITOR */
}

/**
 * Validate that the pointer passed into this method is a valid pmap object and
 * is safe to both read and write to from within the PPL. This function will
 * panic if the validation fails.
 *
 * @note On non-PPL systems this only checks that the pmap object isn't NULL.
 *
 * @note If you're only going to be reading from the pmap object for the
 *       duration of the PPL call, it'll be faster to use the immutable version
 *       of this validation: validate_pmap().
 *
 * @param pmap The pointer to validate.
 * @param func The stringized function name of the caller that will be printed
 *             in the case that the validation fails.
 */
void
validate_pmap_mutable_internal(const volatile struct pmap *pmap, const char *func)
{
#if !XNU_MONITOR
	#pragma unused(pmap, func)
	assert(pmap != NULL);
#else /* !XNU_MONITOR */
	if (pmap != kernel_pmap) {
		/**
		 * Every time a pmap object is validated to be mutable, we mark it down
		 * as an "inflight" pmap on this CPU. The inflight pmap for this CPU
		 * will be set to NULL automatically when the PPL is exited. The
		 * pmap_destroy() path will ensure that no "inflight" pmaps (on any CPU)
		 * are ever destroyed so as to prevent racy use-after-free attacks.
		 */
		pmap_cpu_data_t *cpu_data = pmap_get_cpu_data();

		/**
		 * As a sanity check (since the inflight pmap should be cleared when
		 * exiting the PPL), ensure that the previous inflight pmap is NULL, or
		 * is the same as the one being validated here (which allows for
		 * validating the same object twice).
		 */
		__assert_only const volatile struct pmap *prev_inflight_pmap =
		    os_atomic_load(&cpu_data->inflight_pmap, relaxed);
		assert((prev_inflight_pmap == NULL) || (prev_inflight_pmap == pmap));

		/**
		 * The release barrier here is intended to pair with the seq_cst load of
		 * ref_count in validate_user_pmap() to ensure that if a pmap is
		 * concurrently destroyed, either this path will observe that it was
		 * destroyed after marking it in-flight and panic, or pmap_destroy will
		 * observe the pmap as in-flight after decrementing ref_count and panic.
		 */
		os_atomic_store(&cpu_data->inflight_pmap, pmap, release);

		validate_user_pmap(pmap, func);
	}
#endif /* !XNU_MONITOR */
}

/**
 * Validate that the passed in pmap pointer is a pmap object that was allocated
 * by the pmap and not just random memory. On PPL-enabled systems, the
 * allocation is done through the pmap_alloc_pmap() API. On all other systems
 * it's allocated through a zone allocator.
 *
 * This function will panic if the validation fails.
 *
 * @param pmap The object to validate.
 */
void
pmap_require(pmap_t pmap)
{
#if XNU_MONITOR
	validate_pmap(pmap);
#else /* XNU_MONITOR */
	if (pmap != kernel_pmap) {
		zone_id_require(ZONE_ID_PMAP, sizeof(struct pmap), pmap);
	}
#endif /* XNU_MONITOR */
}

/**
 * Parse the device tree and determine how many pmap-io-ranges there are and
 * how much memory is needed to store all of that data.
 *
 * @note See the definition of pmap_io_range_t for more information on what a
 *       "pmap-io-range" actually represents.
 *
 * @return The number of bytes needed to store metadata for all PPL-owned I/O
 *         regions.
 */
vm_size_t
pmap_compute_io_rgns(void)
{
	DTEntry entry = NULL;
	__assert_only int err = SecureDTLookupEntry(NULL, "/defaults", &entry);
	assert(err == kSuccess);

	void const *prop = NULL;
	unsigned int prop_size = 0;
	if (kSuccess != SecureDTGetProperty(entry, "pmap-io-ranges", &prop, &prop_size)) {
		return 0;
	}

	/**
	 * The device tree node for pmap-io-ranges maps directly onto an array of
	 * pmap_io_range_t structures.
	 */
	pmap_io_range_t const *ranges = prop;

	/* Determine the number of regions and validate the fields. */
	for (unsigned int i = 0; i < (prop_size / sizeof(*ranges)); ++i) {
		if (ranges[i].addr & PAGE_MASK) {
			panic("%s: %u addr 0x%llx is not page-aligned",
			    __func__, i, ranges[i].addr);
		}

		if (ranges[i].len & PAGE_MASK) {
			panic("%s: %u length 0x%llx is not page-aligned",
			    __func__, i, ranges[i].len);
		}

		uint64_t rgn_end = 0;
		if (os_add_overflow(ranges[i].addr, ranges[i].len, &rgn_end)) {
			panic("%s: %u addr 0x%llx length 0x%llx wraps around",
			    __func__, i, ranges[i].addr, ranges[i].len);
		}

		if (((ranges[i].addr <= gPhysBase) && (rgn_end > gPhysBase)) ||
		    ((ranges[i].addr < avail_end) && (rgn_end >= avail_end)) ||
		    ((ranges[i].addr > gPhysBase) && (rgn_end < avail_end))) {
			panic("%s: %u addr 0x%llx length 0x%llx overlaps physical memory",
			    __func__, i, ranges[i].addr, ranges[i].len);
		}

		++num_io_rgns;
	}

	return num_io_rgns * sizeof(*ranges);
}

/**
 * Helper function used when sorting and searching PPL I/O ranges.
 *
 * @param a The first PPL I/O range to compare.
 * @param b The second PPL I/O range to compare.
 *
 * @return < 0 for a < b
 *           0 for a == b
 *         > 0 for a > b
 */
static int
cmp_io_rgns(const void *a, const void *b)
{
	const pmap_io_range_t *range_a = a;
	const pmap_io_range_t *range_b = b;

	if ((range_b->addr + range_b->len) <= range_a->addr) {
		return 1;
	} else if ((range_a->addr + range_a->len) <= range_b->addr) {
		return -1;
	} else {
		return 0;
	}
}

/**
 * Now that enough memory has been allocated to store all of the pmap-io-ranges
 * device tree nodes in memory, go ahead and do that copy and then sort the
 * resulting array by address for quicker lookup later.
 *
 * @note This function assumes that the amount of memory required to store the
 *       entire pmap-io-ranges device tree node has already been calculated (via
 *       pmap_compute_io_rgns()) and allocated in io_attr_table.
 *
 * @note This function will leave io_attr_table sorted by address to allow for
 *       performing a binary search when doing future range lookups.
 */
void
pmap_load_io_rgns(void)
{
	if (num_io_rgns == 0) {
		return;
	}

	DTEntry entry = NULL;
	int err = SecureDTLookupEntry(NULL, "/defaults", &entry);
	assert(err == kSuccess);

	void const *prop = NULL;
	unsigned int prop_size;
	err = SecureDTGetProperty(entry, "pmap-io-ranges", &prop, &prop_size);
	assert(err == kSuccess);

	pmap_io_range_t const *ranges = prop;
	for (unsigned int i = 0; i < (prop_size / sizeof(*ranges)); ++i) {
		io_attr_table[i] = ranges[i];
	}

	qsort(io_attr_table, num_io_rgns, sizeof(*ranges), cmp_io_rgns);
}

/**
 * Find and return the PPL I/O range that contains the passed in physical
 * address.
 *
 * @note This function performs a binary search on the already sorted
 *       io_attr_table, so it should be reasonably fast.
 *
 * @param paddr The physical address to query a specific I/O range for.
 *
 * @return A pointer to the pmap_io_range_t structure if one of the ranges
 *         contains the passed in physical address. Otherwise, NULL.
 */
pmap_io_range_t*
pmap_find_io_attr(pmap_paddr_t paddr)
{
	unsigned int begin = 0;
	unsigned int end = num_io_rgns - 1;

	/**
	 * If there are no I/O ranges, or the wanted address is below the lowest
	 * range or above the highest range, then there's no point in searching
	 * since it won't be here.
	 */
	if ((num_io_rgns == 0) || (paddr < io_attr_table[begin].addr) ||
	    (paddr >= (io_attr_table[end].addr + io_attr_table[end].len))) {
		return NULL;
	}

	/**
	 * A dummy I/O range to compare against when searching for a range that
	 * includes `paddr`.
	 */
	const pmap_io_range_t wanted_range = {
		.addr = paddr & ~PAGE_MASK,
		.len = PAGE_SIZE
	};

	/* Perform a binary search to find the wanted I/O range. */
	for (;;) {
		const unsigned int middle = (begin + end) / 2;
		const int cmp = cmp_io_rgns(&wanted_range, &io_attr_table[middle]);

		if (cmp == 0) {
			/* Success! Found the wanted I/O range. */
			return &io_attr_table[middle];
		} else if (begin == end) {
			/* We've checked every range and didn't find a match. */
			break;
		} else if (cmp > 0) {
			/* The wanted range is above the middle. */
			begin = middle + 1;
		} else {
			/* The wanted range is below the middle. */
			end = middle;
		}
	}

	return NULL;
}

#if HAS_GUARDED_IO_FILTER
/**
 * Parse the device tree and determine how many pmap-io-filters there are and
 * how much memory is needed to store all of that data.
 *
 * @note See the definition of pmap_io_filter_entry_t for more information on what a
 *       "pmap-io-filter" actually represents.
 *
 * @return The number of bytes needed to store metadata for all I/O filter
 *         entries.
 */
vm_size_t
pmap_compute_io_filters(void)
{
	DTEntry entry = NULL;
	__assert_only int err = SecureDTLookupEntry(NULL, "/defaults", &entry);
	assert(err == kSuccess);

	void const *prop = NULL;
	unsigned int prop_size = 0;
	if (kSuccess != SecureDTGetProperty(entry, "pmap-io-filters", &prop, &prop_size)) {
		return 0;
	}

	pmap_io_filter_entry_t const *entries = prop;

	/* Determine the number of entries. */
	for (unsigned int i = 0; i < (prop_size / sizeof(*entries)); ++i) {
		if (entries[i].offset + entries[i].length > ARM_PGMASK) {
			panic("%s: io filter entry %u offset 0x%hx length 0x%hx crosses page boundary",
			    __func__, i, entries[i].offset, entries[i].length);
		}

		++num_io_filter_entries;
	}

	return num_io_filter_entries * sizeof(*entries);
}

/**
 * Compares two I/O filter entries by signature.
 *
 * @note The numerical comparison of signatures does not carry any meaning
 *       but it does give us a way to order and binary search the entries.
 *
 * @param a The first I/O filter entry to compare.
 * @param b The second I/O filter entry to compare.
 *
 * @return < 0 for a < b
 *           0 for a == b
 *         > 0 for a > b
 */
static int
cmp_io_filter_entries_by_signature(const void *a, const void *b)
{
	const pmap_io_filter_entry_t *entry_a = a;
	const pmap_io_filter_entry_t *entry_b = b;

	if (entry_b->signature < entry_a->signature) {
		return 1;
	} else if (entry_a->signature < entry_b->signature) {
		return -1;
	} else {
		return 0;
	}
}

/**
 * Compares two I/O filter entries by address range.
 *
 * @note The function returns 0 as long as the ranges overlap. It allows
 *       the user not only to detect overlaps across a list of entries,
 *       but also to feed it an address with unit length and a range
 *       to check for inclusion.
 *
 * @param a The first I/O filter entry to compare.
 * @param b The second I/O filter entry to compare.
 *
 * @return < 0 for a < b
 *           0 for a == b
 *         > 0 for a > b
 */
static int
cmp_io_filter_entries_by_addr(const void *a, const void *b)
{
	const pmap_io_filter_entry_t *entry_a = a;
	const pmap_io_filter_entry_t *entry_b = b;

	if ((entry_b->offset + entry_b->length) <= entry_a->offset) {
		return 1;
	} else if ((entry_a->offset + entry_a->length) <= entry_b->offset) {
		return -1;
	} else {
		return 0;
	}
}

/**
 * Compares two I/O filter entries by signature, then by address range.
 *
 * @param a The first I/O filter entry to compare.
 * @param b The second I/O filter entry to compare.
 *
 * @return < 0 for a < b
 *           0 for a == b
 *         > 0 for a > b
 */
static int
cmp_io_filter_entries(const void *a, const void *b)
{
	const int cmp_signature_result = cmp_io_filter_entries_by_signature(a, b);
	return (cmp_signature_result != 0) ? cmp_signature_result : cmp_io_filter_entries_by_addr(a, b);
}

/**
 * Now that enough memory has been allocated to store all of the pmap-io-filters
 * device tree nodes in memory, go ahead and do that copy and then sort the
 * resulting array by address for quicker lookup later.
 *
 * @note This function assumes that the amount of memory required to store the
 *       entire pmap-io-filters device tree node has already been calculated (via
 *       pmap_compute_io_filters()) and allocated in io_filter_table.
 *
 * @note This function will leave io_attr_table sorted by signature and addresss to
 *       allow for performing a binary search when doing future lookups.
 */
void
pmap_load_io_filters(void)
{
	if (num_io_filter_entries == 0) {
		return;
	}

	DTEntry entry = NULL;
	int err = SecureDTLookupEntry(NULL, "/defaults", &entry);
	assert(err == kSuccess);

	void const *prop = NULL;
	unsigned int prop_size;
	err = SecureDTGetProperty(entry, "pmap-io-filters", &prop, &prop_size);
	assert(err == kSuccess);

	pmap_io_filter_entry_t const *entries = prop;
	for (unsigned int i = 0; i < (prop_size / sizeof(*entries)); ++i) {
		io_filter_table[i] = entries[i];
	}

	qsort(io_filter_table, num_io_filter_entries, sizeof(*entries), cmp_io_filter_entries);

	for (unsigned int i = 0; i < num_io_filter_entries - 1; i++) {
		if (io_filter_table[i].signature == io_filter_table[i + 1].signature) {
			if (io_filter_table[i].offset + io_filter_table[i].length > io_filter_table[i + 1].offset) {
				panic("%s: io filter entry %u and %u overlap.",
				    __func__, i, i + 1);
			}
		}
	}
}

/**
 * Find and return the I/O filter entry that contains the passed in physical
 * address.
 *
 * @note This function performs a binary search on the already sorted
 *       io_filter_table, so it should be reasonably fast.
 *
 * @param paddr The physical address to query a specific I/O filter for.
 * @param width The width of the I/O register at paddr, at most 8 bytes.
 * @param io_range_outp If not NULL, this argument is set to the io_attr_table
 *        entry containing paddr.
 *
 * @return A pointer to the pmap_io_range_t structure if one of the ranges
 *         contains the passed in I/O register described by paddr and width.
 *         Otherwise, NULL.
 */
pmap_io_filter_entry_t*
pmap_find_io_filter_entry(pmap_paddr_t paddr, uint64_t width, const pmap_io_range_t **io_range_outp)
{
	/* Don't bother looking for it when we don't have any entries. */
	if (__improbable(num_io_filter_entries == 0)) {
		return NULL;
	}

	if (__improbable(width > 8)) {
		return NULL;
	}

	/* Check if paddr is owned by PPL (Guarded mode SW). */
	const pmap_io_range_t *io_range = pmap_find_io_attr(paddr);

	/**
	 * Just return NULL if paddr is not owned by PPL.
	 */
	if (io_range == NULL) {
		return NULL;
	}

	const uint32_t signature = io_range->signature;
	unsigned int begin = 0;
	unsigned int end = num_io_filter_entries - 1;

	/**
	 * A dummy I/O filter entry to compare against when searching for a range that
	 * includes `paddr`.
	 */
	const pmap_io_filter_entry_t wanted_filter = {
		.signature = signature,
		.offset = (uint16_t) ((paddr & ~0b11) & PAGE_MASK),
		.length = (uint16_t) width // This downcast is safe because width is validated.
	};

	/* Perform a binary search to find the wanted filter entry. */
	for (;;) {
		const unsigned int middle = (begin + end) / 2;
		const int cmp = cmp_io_filter_entries(&wanted_filter, &io_filter_table[middle]);

		if (cmp == 0) {
			/**
			 * We have found a "match" by the definition of cmp_io_filter_entries,
			 * meaning the dummy range and the io_filter_entry are overlapping. Make
			 * sure the dummy range is contained entirely by the entry.
			 */
			const pmap_io_filter_entry_t entry_found = io_filter_table[middle];
			if ((wanted_filter.offset >= entry_found.offset) &&
			    ((wanted_filter.offset + wanted_filter.length) <= (entry_found.offset + entry_found.length))) {
				if (io_range) {
					*io_range_outp = io_range;
				}

				return &io_filter_table[middle];
			} else {
				/**
				 * Under the assumption that there is no overlapping io_filter_entry,
				 * if the dummy range is found overlapping but not contained by an
				 * io_filter_entry, there cannot be another io_filter_entry containing
				 * the dummy range, so return NULL here.
				 */
				return NULL;
			}
		} else if (begin == end) {
			/* We've checked every range and didn't find a match. */
			break;
		} else if (cmp > 0) {
			/* The wanted range is above the middle. */
			begin = middle + 1;
		} else {
			/* The wanted range is below the middle. */
			end = middle;
		}
	}

	return NULL;
}
#endif /* HAS_GUARDED_IO_FILTER */

/**
 * Initialize the pmap per-CPU data structure for a single CPU. This is called
 * once for each CPU in the system, on the CPU whose per-cpu data needs to be
 * initialized.
 *
 * In reality, many of the per-cpu data fields will have either already been
 * initialized or will rely on the fact that the per-cpu data is either zeroed
 * out during allocation (on non-PPL systems), or the data itself is a global
 * variable which will be zeroed by default (on PPL systems).
 *
 * @param cpu_number The number of the CPU whose pmap per-cpu data should be
 *                   initialized. This number should correspond to the CPU
 *                   executing this code.
 */
MARK_AS_PMAP_TEXT void
pmap_cpu_data_init_internal(unsigned int cpu_number)
{
	pmap_cpu_data_t *pmap_cpu_data = pmap_get_cpu_data();

#if XNU_MONITOR
	/* Verify the per-cpu data is cacheline-aligned. */
	assert(((vm_offset_t)pmap_cpu_data & (MAX_L2_CLINE_BYTES - 1)) == 0);

	/**
	 * The CPU number should already have been initialized to
	 * PMAP_INVALID_CPU_NUM when initializing the boot CPU data.
	 */
	if (pmap_cpu_data->cpu_number != PMAP_INVALID_CPU_NUM) {
		panic("%s: pmap_cpu_data->cpu_number=%u, cpu_number=%u",
		    __func__, pmap_cpu_data->cpu_number, cpu_number);
	}
#endif /* XNU_MONITOR */

	/**
	 * At least when operating in the PPL, it's important to duplicate the CPU
	 * number into a PPL-owned location. If we relied strictly on the CPU number
	 * located in the general machine-specific per-cpu data, it could be
	 * modified in a way to affect PPL operation.
	 */
	pmap_cpu_data->cpu_number = cpu_number;
#if __ARM_MIXED_PAGE_SIZE__
	pmap_cpu_data->commpage_page_shift = PAGE_SHIFT;
#endif
}

/**
 * Initialize the pmap per-cpu data for the bootstrap CPU (the other CPUs should
 * just call pmap_cpu_data_init() directly). This code does one of two things
 * depending on whether this is a PPL-enabled system.
 *
 * PPL-enabled: This function will setup the PPL-specific per-cpu data like the
 *              PPL stacks and register save area. This performs the
 *              functionality usually done by cpu_data_init() to setup the pmap
 *              per-cpu data fields. In reality, most fields are not initialized
 *              and are assumed to be zero thanks to this data being global.
 *
 * Non-PPL: Just calls pmap_cpu_data_init() to initialize the bootstrap CPU's
 *          pmap per-cpu data (non-boot CPUs will call that function once they
 *          come out of reset).
 *
 * @note This function will carve out physical pages for the PPL stacks and PPL
 *       register save area from avail_start. It's assumed that avail_start is
 *       on a page boundary before executing this function on PPL-enabled
 *       systems.
 */
void
pmap_cpu_data_array_init(void)
{
#if XNU_MONITOR
	/**
	 * Enough virtual address space to cover all PPL stacks for every CPU should
	 * have already been allocated by arm_vm_init() before pmap_bootstrap() is
	 * called.
	 */
	assert((pmap_stacks_start != NULL) && (pmap_stacks_end != NULL));
	assert(((uintptr_t)pmap_stacks_end - (uintptr_t)pmap_stacks_start) == PPL_STACK_REGION_SIZE);

	/**
	 * Ensure avail_start is aligned to a page boundary before allocating the
	 * stacks and register save area.
	 */
	assert(avail_start == round_page(avail_start));

	/* Each PPL stack contains guard pages before and after. */
	vm_offset_t stack_va = (vm_offset_t)pmap_stacks_start + ARM_PGBYTES;

	/**
	 * Globally save off the beginning of the PPL stacks physical space so that
	 * we can update its physical aperture mappings later in the bootstrap
	 * process.
	 */
	pmap_stacks_start_pa = avail_start;

	/* Map the PPL stacks for each CPU. */
	for (unsigned int cpu_num = 0; cpu_num < MAX_CPUS; cpu_num++) {
		/**
		 * The PPL stack size is based off of the VM page size, which may differ
		 * from the underlying hardware page size.
		 *
		 * Map all of the PPL stack into the kernel's address space.
		 */
		for (vm_offset_t cur_va = stack_va; cur_va < (stack_va + PPL_STACK_SIZE); cur_va += ARM_PGBYTES) {
			assert(cur_va < (vm_offset_t)pmap_stacks_end);

			pt_entry_t *ptep = pmap_pte(kernel_pmap, cur_va);
			assert(*ptep == ARM_PTE_EMPTY);

			pt_entry_t template = pa_to_pte(avail_start) | ARM_PTE_AF | ARM_PTE_SH(SH_OUTER_MEMORY) |
			    ARM_PTE_TYPE | ARM_PTE_ATTRINDX(CACHE_ATTRINDX_DEFAULT) | xprr_perm_to_pte(XPRR_PPL_RW_PERM);

#if __ARM_KERNEL_PROTECT__
			/**
			 * On systems with software based spectre/meltdown mitigations,
			 * kernel mappings are explicitly not made global because the kernel
			 * is unmapped when executing in EL0 (this ensures that kernel TLB
			 * entries won't accidentally be valid in EL0).
			 */
			template |= ARM_PTE_NG;
#endif /* __ARM_KERNEL_PROTECT__ */

			write_pte(ptep, template);
			__builtin_arm_isb(ISB_SY);

			avail_start += ARM_PGBYTES;
		}

#if KASAN
		kasan_map_shadow(stack_va, PPL_STACK_SIZE, false);
#endif /* KASAN */

		/**
		 * Setup non-zero pmap per-cpu data fields. If the default value should
		 * be zero, then you can assume the field is already set to that.
		 */
		pmap_cpu_data_array[cpu_num].cpu_data.cpu_number = PMAP_INVALID_CPU_NUM;
		pmap_cpu_data_array[cpu_num].cpu_data.ppl_state = PPL_STATE_KERNEL;
		pmap_cpu_data_array[cpu_num].cpu_data.ppl_stack = (void*)(stack_va + PPL_STACK_SIZE);

		/**
		 * Get the first VA of the next CPU's PPL stack. Need to skip the guard
		 * page after the stack.
		 */
		stack_va += (PPL_STACK_SIZE + ARM_PGBYTES);
	}

	pmap_stacks_end_pa = avail_start;

	/**
	 * The PPL register save area location is saved into global variables so
	 * that they can be made writable if DTrace support is needed. This is
	 * needed because DTrace will try to update the register state.
	 */
	ppl_cpu_save_area_start = avail_start;
	ppl_cpu_save_area_end = ppl_cpu_save_area_start;
	pmap_paddr_t ppl_cpu_save_area_cur = ppl_cpu_save_area_start;

	/* Carve out space for the PPL register save area for each CPU. */
	for (unsigned int cpu_num = 0; cpu_num < MAX_CPUS; cpu_num++) {
		/* Allocate enough space to cover at least one arm_context_t object. */
		while ((ppl_cpu_save_area_end - ppl_cpu_save_area_cur) < sizeof(arm_context_t)) {
			avail_start += PAGE_SIZE;
			ppl_cpu_save_area_end = avail_start;
		}

		pmap_cpu_data_array[cpu_num].cpu_data.save_area = (arm_context_t *)phystokv(ppl_cpu_save_area_cur);
		ppl_cpu_save_area_cur += sizeof(arm_context_t);
	}

#if HAS_GUARDED_IO_FILTER
	/**
	 * Enough virtual address space to cover all I/O filter stacks for every CPU should
	 * have already been allocated by arm_vm_init() before pmap_bootstrap() is
	 * called.
	 */
	assert((iofilter_stacks_start != NULL) && (iofilter_stacks_end != NULL));
	assert(((uintptr_t)iofilter_stacks_end - (uintptr_t)iofilter_stacks_start) == IOFILTER_STACK_REGION_SIZE);

	/* Each I/O filter stack contains guard pages before and after. */
	vm_offset_t iofilter_stack_va = (vm_offset_t)iofilter_stacks_start + ARM_PGBYTES;

	/**
	 * Globally save off the beginning of the I/O filter stacks physical space so that
	 * we can update its physical aperture mappings later in the bootstrap
	 * process.
	 */
	iofilter_stacks_start_pa = avail_start;

	/* Map the I/O filter stacks for each CPU. */
	for (unsigned int cpu_num = 0; cpu_num < MAX_CPUS; cpu_num++) {
		/**
		 * Map all of the I/O filter stack into the kernel's address space.
		 */
		for (vm_offset_t cur_va = iofilter_stack_va; cur_va < (iofilter_stack_va + IOFILTER_STACK_SIZE); cur_va += ARM_PGBYTES) {
			assert(cur_va < (vm_offset_t)iofilter_stacks_end);

			pt_entry_t *ptep = pmap_pte(kernel_pmap, cur_va);
			assert(*ptep == ARM_PTE_EMPTY);

			pt_entry_t template = pa_to_pte(avail_start) | ARM_PTE_AF | ARM_PTE_SH(SH_OUTER_MEMORY) |
			    ARM_PTE_TYPE | ARM_PTE_ATTRINDX(CACHE_ATTRINDX_DEFAULT) | xprr_perm_to_pte(XPRR_PPL_RW_PERM);

#if __ARM_KERNEL_PROTECT__
			template |= ARM_PTE_NG;
#endif /* __ARM_KERNEL_PROTECT__ */

			write_pte(ptep, template);
			__builtin_arm_isb(ISB_SY);

			avail_start += ARM_PGBYTES;
		}

#if KASAN
		kasan_map_shadow(iofilter_stack_va, IOFILTER_STACK_SIZE, false);
#endif /* KASAN */

		/**
		 * Setup non-zero pmap per-cpu data fields. If the default value should
		 * be zero, then you can assume the field is already set to that.
		 */
		pmap_cpu_data_array[cpu_num].cpu_data.iofilter_stack = (void*)(iofilter_stack_va + IOFILTER_STACK_SIZE);

		/**
		 * Get the first VA of the next CPU's IOFILTER stack. Need to skip the guard
		 * page after the stack.
		 */
		iofilter_stack_va += (IOFILTER_STACK_SIZE + ARM_PGBYTES);
	}

	iofilter_stacks_end_pa = avail_start;
#endif /* HAS_GUARDED_IO_FILTER */

	/* Carve out scratch space for each cpu */
	for (unsigned int cpu_num = 0; cpu_num < MAX_CPUS; cpu_num++) {
		pmap_cpu_data_array[cpu_num].cpu_data.scratch_page = (void*)phystokv(avail_start);
		avail_start += PAGE_SIZE;
	}
#endif /* XNU_MONITOR */

	pmap_cpu_data_init();
}

/**
 * Retrieve the pmap per-cpu data for the current CPU. On PPL-enabled systems
 * this data is managed separately from the general machine-specific per-cpu
 * data to handle the requirement that it must only be PPL-writable.
 *
 * @return The per-cpu pmap data for the current CPU.
 */
pmap_cpu_data_t *
pmap_get_cpu_data(void)
{
	pmap_cpu_data_t *pmap_cpu_data = NULL;

#if XNU_MONITOR
	extern pmap_cpu_data_t* ml_get_ppl_cpu_data(void);
	pmap_cpu_data = ml_get_ppl_cpu_data();
#else /* XNU_MONITOR */
	/**
	 * On non-PPL systems, the pmap per-cpu data is stored in the general
	 * machine-specific per-cpu data.
	 */
	pmap_cpu_data = &getCpuDatap()->cpu_pmap_cpu_data;
#endif /* XNU_MONITOR */

	return pmap_cpu_data;
}

/**
 * Retrieve the pmap per-cpu data for the specified cpu index.
 *
 * @return The per-cpu pmap data for the CPU
 */
pmap_cpu_data_t *
pmap_get_remote_cpu_data(unsigned int cpu)
{
#if XNU_MONITOR
	assert(cpu < MAX_CPUS);
	return &pmap_cpu_data_array[cpu].cpu_data;
#else
	cpu_data_t *cpu_data = cpu_datap((int)cpu);
	if (cpu_data == NULL) {
		return NULL;
	} else {
		return &cpu_data->cpu_pmap_cpu_data;
	}
#endif
}

void
pmap_mark_page_for_cache_flush(pmap_paddr_t pa)
{
	if (!pa_valid(pa)) {
		return;
	}
	const unsigned int pai = pa_index(pa);
	pv_entry_t **pvh = pai_to_pvh(pai);
	pvh_lock(pai);
	pvh_set_flags(pvh, pvh_get_flags(pvh) | PVH_FLAG_FLUSH_NEEDED);
	pvh_unlock(pai);
}

#if HAS_DC_INCPA
void
#else
void __attribute__((noreturn))
#endif
pmap_flush_noncoherent_page(pmap_paddr_t paddr __unused)
{
	assertf((paddr & PAGE_MASK) == 0, "%s: paddr 0x%llx not page-aligned",
	    __func__, (unsigned long long)paddr);

#if HAS_DC_INCPA
	for (unsigned int i = 0; i < (PAGE_SIZE >> 12); ++i) {
		const register uint64_t dc_arg asm("x8") = paddr + (i << 12);
		/**
		 * rdar://problem/106067403
		 * __asm__ __volatile__("dc incpa4k, %0" : : "r"(dc_arg));
		 */
		__asm__ __volatile__ (".long 0x201308" : : "r"(dc_arg));
	}
	__builtin_arm_dsb(DSB_OSH);
#else
	panic("%s called on unsupported configuration", __func__);
#endif /* HAS_DC_INCPA */
}
