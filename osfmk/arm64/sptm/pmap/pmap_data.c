/*
 * Copyright (c) 2020 Apple Inc. All rights reserved.
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

#include <arm64/sptm/pmap/pmap_internal.h>

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
SECURITY_READ_ONLY_LATE(uintptr_t*) pv_head_table = NULL;

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
 * This VM object will contain every VM page being used by the pmap. This acts
 * as a convenient place to put pmap pages to keep the VM from reusing them, as
 * well as providing a way for looping over every page being used by the pmap.
 */
struct vm_object pmap_object_store VM_PAGE_PACKED_ALIGNED;

/* Pointer to the pmap's VM object that can't be modified after machine_lockdown(). */
SECURITY_READ_ONLY_LATE(vm_object_t) pmap_object = &pmap_object_store;

/**
 * This variable, used for debugging purposes only, keeps track of how many pages
 * are currently in use by the pmap layer. Once a page is given back to the VM,
 * then inuse_pmap_pages_count will be decremented.
 *
 * Even if a page is sitting in one of the pmap's various free lists and hasn't
 * been allocated for usage, it is still considered "used" by the pmap, from
 * the perspective of the VM.
 */
unsigned int inuse_pmap_pages_count = 0;

/**
 * Default watermark values used to keep a healthy supply of physical-to-virtual
 * entries (PVEs) always available. These values can be overriden by the device
 * tree (see pmap_compute_pv_targets() for more info).
 */
#define PV_KERN_LOW_WATER_MARK_DEFAULT (0x400)
#define PV_ALLOC_CHUNK_INITIAL         (0x400)
#define PV_KERN_ALLOC_CHUNK_INITIAL    (0x400)

/**
 * The pv_free array acts as a ring buffer where each entry points to a linked
 * list of PVEs that have a length set by this define.
 */
#define PV_BATCH_SIZE (PAGE_SIZE / sizeof(pv_entry_t))

/* The batch allocation code assumes that a batch can fit within a single page. */
#if __ARM_16K_PG__
/**
 * PAGE_SIZE is a variable on arm64 systems with 4K VM pages, so no static
 * assert on those systems.
 */
static_assert((PV_BATCH_SIZE * sizeof(pv_entry_t)) <= PAGE_SIZE);
#endif /* __ARM_16K_PG__ */

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
 * track of the number of pages being used for PVE objects, PTD objects, and the
 * total number of PVEs that have been added to the global or kernel-dedicated
 * free lists respectively.
 */
static _Atomic unsigned int pv_page_count MARK_AS_PMAP_DATA = 0;
static unsigned int ptd_page_count MARK_AS_PMAP_DATA = 0;
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

/**
 * Flag indicating whether any I/O regions that require strong DSB are present.
 * If not, certain TLB maintenance operations can be streamlined.
 */
SECURITY_READ_ONLY_LATE(bool) sdsb_io_rgns_present = false;

/**
 * Sorted representation of the pmap-io-ranges nodes in the device tree. These
 * nodes describe all of the SPTM/PPL-owned I/O ranges.
 */
SECURITY_READ_ONLY_LATE(pmap_io_range_t*) io_attr_table = (pmap_io_range_t*)0;

/* The number of ranges described by io_attr_table. */
SECURITY_READ_ONLY_LATE(unsigned int) num_io_rgns = 0;

/**
 * A list of pages that define the per-cpu scratch areas used by IOMMU drivers
 * when preparing data to be passed into the SPTM. The size allocated per-cpu is
 * defined by PMAP_IOMMU_SCRATCH_SIZE.
 *
 * SPTM TODO: Only have these variables on systems with IOMMU drivers (H11+).
 */
#define PMAP_IOMMU_SCRATCH_SIZE (PMAP_IOMMU_NUM_SCRATCH_PAGES * PAGE_SIZE)
SECURITY_READ_ONLY_LATE(pmap_paddr_t) sptm_cpu_iommu_scratch_start = 0;
SECURITY_READ_ONLY_LATE(pmap_paddr_t) sptm_cpu_iommu_scratch_end = 0;

/* Prototypes used by pmap_data_bootstrap(). */
void pmap_cpu_data_array_init(void);

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
	const vm_size_t pv_head_size = round_page(npages * sizeof(*pv_head_table));

	/* Scan the device tree and override heuristics in the PV entry management code. */
	pmap_compute_pv_targets();

	__assert_only const libsptm_error_t error = sptm_get_io_ranges_address((sptm_vaddr_t *) &io_attr_table, &num_io_rgns);
	assert(error == SPTM_SUCCESS);

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
	avail_start = PMAP_ALIGN(avail_start + pp_attr_table_size, __alignof(pv_entry_t *));

	pv_head_table = (uintptr_t *)phystokv(avail_start);

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

	/* Setup the pmap per-cpu data structures. */
	pmap_cpu_data_array_init();
}

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
 * Allocate a page from the VM for usage within the pmap.
 *
 * @param ppa Output parameter to store the physical address of the allocated
 *           page if one was able to be allocated (NULL otherwise).
 * @param options The following options can be specified:
 *     - PMAP_PAGE_ALLOCATE_NOWAIT: If the VM page free list doesn't have
 *       any free pages available then don't wait for one, just return
 *       immediately without allocating a page.
 *
 *     - PMAP_PAGE_RECLAIM_NOWAIT: If memory can't be allocated from the VM,
 *       then fall back to attempting to reclaim a userspace page table. This
 *       should only be specified in paths that absolutely can't take the
 *       latency hit of waiting for the VM to allocate more pages. This flag
 *       doesn't make much sense unless it's paired with
 *       PMAP_PAGE_ALLOCATE_NOWAIT.
 *
 *     - PMAP_PAGE_NOZEROFILL: don't zero-fill the pages. This should only be
 *       used if you know that something else in the relevant code path will
 *       zero-fill or otherwise fully initialize the page with consistent data.
 *       This is mostly intended for cases in which sptm_retype() is guaranteed
 *       to zero-fill the page for us.
 *
 * @return KERN_SUCCESS if a page was successfully allocated, or
 *         KERN_RESOURCE_SHORTAGE if a page failed to get allocated. This should
 *         only be returned if PMAP_PAGE_ALLOCATE_NOWAIT is passed or if
 *         preemption is disabled after early boot since allocating memory from
 *         the VM requires grabbing a mutex. If PMAP_PAGE_ALLOCATE_NOWAIT is not
 *         passed and the system is in a preemptable state, then the return
 *         value should always be KERN_SUCCESS (as the thread will block until
 *         there are free pages available).
 */
MARK_AS_PMAP_TEXT kern_return_t
pmap_page_alloc(pmap_paddr_t *ppa, unsigned options)
{
	assert(ppa != NULL);
	pmap_paddr_t pa = 0;
	ASSERT_NOT_HIBERNATING();
	vm_page_t mem = VM_PAGE_NULL;
	thread_t self = current_thread();

	/**
	 * It's not possible to allocate memory from the VM in a preemption disabled
	 * environment except during early boot (since the VM needs to grab a mutex).
	 * In those cases just return a resource shortage error and let the caller
	 * deal with it.
	 *
	 * We don't panic here as there are genuinely some cases where pmap_enter()
	 * is called with preemption disabled, and it's better to return an error
	 * to those callers to notify them to try again with preemption enabled.
	 */
	if (!pmap_is_preemptible()) {
		return KERN_RESOURCE_SHORTAGE;
	}

	*ppa = 0;

	/**
	 * We qualify for allocating reserved memory so set TH_OPT_VMPRIV to inform
	 * the VM of this.
	 *
	 * This field should only be modified by the local thread itself, so no lock
	 * needs to be taken.
	 */
	uint16_t thread_options = self->options;
	self->options |= TH_OPT_VMPRIV;

	/**
	 * If we're only allocating a single page, just grab one off the VM's
	 * global page free list.
	 */
	while ((mem = vm_page_grab()) == VM_PAGE_NULL) {
		if (options & PMAP_PAGE_ALLOCATE_NOWAIT) {
			break;
		}

		VM_PAGE_WAIT();
	}

	if (mem != VM_PAGE_NULL) {
		vm_page_lock_queues();
		vm_page_wire(mem, VM_KERN_MEMORY_PTE, TRUE);
		vm_page_unlock_queues();
	}

	self->options = thread_options;

	if (mem == VM_PAGE_NULL) {
		return KERN_RESOURCE_SHORTAGE;
	}

	pa = (pmap_paddr_t)ptoa(VM_PAGE_GET_PHYS_PAGE(mem));

	/* Add the allocated VM page(s) to the pmap's VM object. */
	pmap_enqueue_pages(mem);

	/* Pages are considered "in use" by the pmap until returned to the VM. */
	OSAddAtomic(1, &inuse_pmap_pages_count);

	/* SPTM TODO: assert that the returned page is of type XNU_DEFAULT in frame table */
	if (!(options & PMAP_PAGE_NOZEROFILL)) {
		bzero((void*)phystokv(pa), PAGE_SIZE);
	}
	*ppa = pa;
	return KERN_SUCCESS;
}

/**
 * Free memory previously allocated through pmap_page_alloc() back to the VM.
 *
 * @param pa Physical address of the page(s) to free.
 */
void
pmap_page_free(pmap_paddr_t pa)
{
	/* SPTM TODO: assert that the page to be freed is of type XNU_DEFAULT in frame table */

	/* Pages are considered "in use" until given back to the VM. */
	OSAddAtomic(-1, &inuse_pmap_pages_count);

	vm_page_t mem = VM_PAGE_NULL;
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
	return 0;
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

	/* Disable preemption while working with per-CPU data. */
	mp_disable_preemption();

	pmap_cpu_data_t *pmap_cpu_data = pmap_get_cpu_data();
	pv_free_list_alloc(&pmap_cpu_data->pv_free, pvepp);

	if (*pvepp != PV_ENTRY_NULL) {
		goto pv_list_alloc_done;
	}

	if (pv_kern_free.count < pv_kern_low_water_mark) {
		/**
		 * If the kernel reserved pool is low, let non-kernel mappings wait for
		 * a page from the VM.
		 */
		goto pv_list_alloc_done;
	}

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
	mp_enable_preemption();

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
pv_list_free(pv_entry_t *pve_head, pv_entry_t *pve_tail, unsigned int pv_cnt)
{
	assert((pve_head != PV_ENTRY_NULL) && (pve_tail != PV_ENTRY_NULL));

	/* Disable preemption while working with per-CPU data. */
	disable_preemption();

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

	unsigned int freed_count = 0;

	/**
	 * In the degenerate case, we need to process PVEs one by one, to make sure
	 * we spill out to the global list, or update the spill marker as
	 * appropriate.
	 */
	while (pv_cnt) {
		/**
		 * Check for (and if necessary reenable) preemption every PV_BATCH_SIZE PVEs to
		 * avoid leaving preemption disabled for an excessive duration if we happen to be
		 * processing a very large PV list.
		 */
		if (__improbable(freed_count == PV_BATCH_SIZE)) {
			freed_count = 0;
			if (__improbable(pmap_pending_preemption())) {
				enable_preemption();
				assert(preemption_enabled());
				disable_preemption();
				pmap_cpu_data = pmap_get_cpu_data();
			}
		}

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
		freed_count++;

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
	enable_preemption();

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
 * @param alloc_flags Allocation flags passed to pmap_page_alloc(). See
 *                    the definition of that function for a detailed description
 *                    of the available flags.
 *
 * @return KERN_SUCCESS, or the value returned by pmap_page_alloc() upon
 *         failure.
 */
MARK_AS_PMAP_TEXT static kern_return_t
pve_feed_page(unsigned alloc_flags)
{
	kern_return_t kr = KERN_FAILURE;

	pv_entry_t *pve_head = PV_ENTRY_NULL;
	pv_entry_t *pve_tail = PV_ENTRY_NULL;
	pmap_paddr_t pa = 0;

	kr = pmap_page_alloc(&pa, alloc_flags);

	if (kr != KERN_SUCCESS) {
		return kr;
	}

	/* Update statistics globals. See the variables' definitions for more info. */
	os_atomic_inc(&pv_page_count, relaxed);
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
 * @param lock_mode Which state the pmap lock is being held in if the mapping is
 *                  owned by a pmap, otherwise this is a don't care.
 * @param options PMAP_OPTIONS_* family of options passed from the caller.
 * @param pvepp Output parameter that will get updated with a pointer to the
 *              allocated node if none of the free lists are empty, or a pointer
 *              to NULL otherwise. This pointer can't already be pointing to a
 *              valid entry before allocation.
 * @param locked_pvh Input/output parameter pointing to the wrapped value of the
 *                   pv_head_table entry previously obtained from pvh_lock().
 *                   This value will be updated if [locked_pvh->pai] needs to be
 *                   re-locked.
 * @param refcountp Pointer to a reference count that will be temporarily
 *                  atomically incremented in the event that [pmap]'s lock needs
 *                  to be temporarily dropped in order to satisfy the allocation.
 *                  This is typically used to prevent a page table from being
 *                  reclaimed while the lock is dropped.  May be NULL.
 *
 * @return These are the possible return values:
 *     PV_ALLOC_SUCCESS: A PVE object was successfully allocated.
 *     PV_ALLOC_FAIL: No objects were available for allocation, and
 *                    allocating a new page failed.
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
	pmap_lock_mode_t lock_mode,
	unsigned int options,
	pv_entry_t **pvepp,
	locked_pvh_t *locked_pvh,
	volatile uint16_t *refcountp)
{
	assert((pvepp != NULL) && (*pvepp == PV_ENTRY_NULL));
	assert(locked_pvh != NULL);

	if (pmap != NULL) {
		pmap_assert_locked(pmap, lock_mode);
	}

	pv_list_alloc(pvepp);
	if (PV_ENTRY_NULL != *pvepp) {
		return PV_ALLOC_SUCCESS;
	}

	unsigned alloc_flags = 0;

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
	}

	/**
	 * Make sure we have PMAP_PAGES_ALLOCATE_NOWAIT set in alloc_flags when the
	 * input options argument has PMAP_OPTIONS_NOWAIT set.
	 */
	alloc_flags |= (options & PMAP_OPTIONS_NOWAIT) ? PMAP_PAGE_ALLOCATE_NOWAIT : 0;

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
	const unsigned int pai = locked_pvh->pai;

	/**
	 * Drop the lock during page allocation since that can take a while and
	 * because preemption must be enabled when attempting to allocate memory
	 * from the VM (which requires grabbing a mutex).
	 */
	pvh_unlock(locked_pvh);
	if (pmap != NULL) {
		/**
		 * Bump the provided refcount before we drop the pmap lock in order to prevent
		 * page table reclamation while the lock is dropped.
		 */
		if (__improbable((refcountp != NULL) && (os_atomic_inc_orig(refcountp, relaxed) == UINT16_MAX))) {
			panic("%s: pmap %p refcount %p overflow", __func__, pmap, refcountp);
		}
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
		if (__improbable((refcountp != NULL) && (os_atomic_dec_orig(refcountp, relaxed) == 0))) {
			panic("%s: pmap %p refcount %p underflow", __func__, pmap, refcountp);
		}
	}

	if (__improbable(options & PMAP_OPTIONS_NOPREEMPT)) {
		*locked_pvh = pvh_lock_nopreempt(pai);
	} else {
		*locked_pvh = pvh_lock(pai);
	}

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

	/*
	 * We do not need to hold the pv_free_array lock to calculate the number of
	 * elements in it because no other core is running at this point.
	 */
	while (((pv_free_array_n_elems() * PV_BATCH_SIZE) < pv_alloc_initial_target) ||
	    (pv_kern_free.count < pv_kern_alloc_initial_target)) {
		if ((kr = pve_feed_page(0)) != KERN_SUCCESS) {
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
 * @param lock_mode Which state the pmap lock is being held in if the mapping is
 *                  owned by a pmap, otherwise this is a don't care.
 * @param options PMAP_OPTIONS_* family of options.
 * @param locked_pvh Input/output parameter pointing to the wrapped value of the
 *                   pv_head_table entry previously obtained from pvh_lock().
 *                   This value will be updated if [locked_pvh->pai] needs to be
 *                   re-locked or if the allocation is successful and the PVH
 *                   entry is updated with the new PVE pointer.
 *
 * @return PV_ALLOC_SUCCESS if the entry at `pai` was successfully converted
 *         into PVH_TYPE_PVEP, or the return value of pv_alloc() otherwise. See
 *         pv_alloc()'s function header for a detailed explanation of the
 *         possible return values.
 */
MARK_AS_PMAP_TEXT static pv_alloc_return_t
pepv_convert_ptep_to_pvep(
	pmap_t pmap,
	pmap_lock_mode_t lock_mode,
	unsigned int options,
	locked_pvh_t *locked_pvh)
{
	assert(locked_pvh != NULL);
	assert(pvh_test_type(locked_pvh->pvh, PVH_TYPE_PTEP));

	pv_entry_t *pvep = PV_ENTRY_NULL;
	pv_alloc_return_t ret = pv_alloc(pmap, lock_mode, options, &pvep, locked_pvh, NULL);
	if (ret != PV_ALLOC_SUCCESS) {
		return ret;
	}

	const unsigned int pai = locked_pvh->pai;

	/* If we've gotten this far then a node should've been allocated. */
	assert(pvep != PV_ENTRY_NULL);

	/* The new PVE should have the same PTE pointer as the previous PVH entry. */
	pve_init(pvep);
	pve_set_ptep(pvep, 0, pvh_ptep(locked_pvh->pvh));

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

	pvh_update_head(locked_pvh, pvep, PVH_TYPE_PVEP);

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
 * @param locked_pvh Input/output parameter pointing to the wrapped value of the
 *                   pv_head_table entry previously obtained from pvh_lock().
 *                   If the registration is successful, locked_pvh->pvh will be
 *                   updated to reflect the new PV list head.
 * @param new_pvepp An output parameter that is updated with a pointer to the
 *                  PVE object where the PTEP was allocated into. In the event
 *                  of failure, or if the pointer passed in is NULL,
 *                  it's not modified.
 * @param new_pve_ptep_idx An output parameter that is updated with the index
 *                  into the PVE object where the PTEP was allocated into.
 *                  In the event of failure, or if new_pvepp in is NULL,
 *                  it's not modified.
 *
 * @return PV_ALLOC_SUCCESS if the entry at [locked_pvh->pai] was successfully
 *         updated with the new mapping, or the return value of pv_alloc()
 *         otherwise. See pv_alloc()'s function header for a detailed explanation
 *         of the possible return values.
 */
MARK_AS_PMAP_TEXT pv_alloc_return_t
pmap_enter_pv(
	pmap_t pmap,
	pt_entry_t *ptep,
	unsigned int options,
	pmap_lock_mode_t lock_mode,
	locked_pvh_t *locked_pvh,
	pv_entry_t **new_pvepp,
	int *new_pve_ptep_idx)
{
	assert(ptep != PT_ENTRY_NULL);
	assert(locked_pvh != NULL);

	bool first_cpu_mapping = false;

	ASSERT_NOT_HIBERNATING();

	if (pmap != NULL) {
		pmap_assert_locked(pmap, lock_mode);
	}

	uintptr_t pvh_flags = pvh_get_flags(locked_pvh->pvh);
	const unsigned int pai = locked_pvh->pai;


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
		pvh_set_flags(locked_pvh, pvh_flags);
	}

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
	if (pvh_test_type(locked_pvh->pvh, PVH_TYPE_NULL)) {
		/* If this is the first mapping, upgrade the type to store a single PTEP. */
		pvh_update_head(locked_pvh, ptep, PVH_TYPE_PTEP);
	} else {
		pv_alloc_return_t ret = PV_ALLOC_FAIL;

		if (pvh_test_type(locked_pvh->pvh, PVH_TYPE_PTEP)) {
			/**
			 * There was already a single mapping to the page. Convert the PVH
			 * entry from PVH_TYPE_PTEP to PVH_TYPE_PVEP so that multiple
			 * mappings can be tracked. If PVEs cannot hold more than a single
			 * mapping, a second PVE will be added farther down.
			 */
			if ((ret = pepv_convert_ptep_to_pvep(pmap, lock_mode, options, locked_pvh)) != PV_ALLOC_SUCCESS) {
				return ret;
			}

			/**
			 * At this point, the PVH flags have been clobbered due to updating
			 * PTEP->PVEP, but that's ok because the locks are being held and
			 * the flags will get set again below before pv_alloc() is called
			 * and the locks are potentially dropped again.
			 */
		} else if (__improbable(!pvh_test_type(locked_pvh->pvh, PVH_TYPE_PVEP))) {
			panic("%s: unexpected PV head %p, ptep=%p pmap=%p",
			    __func__, (void*)locked_pvh->pvh, ptep, pmap);
		}

		/**
		 * Check if we have room for one more mapping in this PVE
		 */
		pv_entry_t *pvep = pvh_pve_list(locked_pvh->pvh);
		assert(pvep != PV_ENTRY_NULL);

		int pve_ptep_idx = pve_find_ptep_index(pvep, PT_ENTRY_NULL);

		if (pve_ptep_idx == -1) {
			/**
			 * Set up the pv_entry for this new mapping and then add it to the list
			 * for this physical page.
			 */
			pve_ptep_idx = 0;
			pvep = PV_ENTRY_NULL;
			if ((ret = pv_alloc(pmap, lock_mode, options, &pvep, locked_pvh, NULL)) != PV_ALLOC_SUCCESS) {
				return ret;
			}

			/* If we've gotten this far then a node should've been allocated. */
			assert(pvep != PV_ENTRY_NULL);
			pve_init(pvep);
			pve_add(locked_pvh, pvep);
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
 * @param locked_pvh Input/output parameter pointing to the wrapped value of the
 *                   pv_head_table entry previously obtained from pvh_lock().
 *                   If the removal is successful, locked_pvh->pvh may be updated
 *                   to reflect a new PV list head.
 * @param is_internal_p The internal bit of the PTE that was removed.
 * @param is_altacct_p The altacct bit of the PTE that was removed.
 * @return These are the possible return values:
 *     PV_REMOVE_SUCCESS: A PV entry matching the PTE was found and
 *                        removed.
 *     PV_REMOVE_FAIL: No matching PV entry was found.  This may not be a fatal
 *                        condition; for example, pmap_disconnect() on another
 *                        thread may have removed the PV entry between removal
 *                        of the mapping and acquisition of the PV lock in
 *                        pmap_remove();
 */
pv_remove_return_t
pmap_remove_pv(
	pmap_t pmap __assert_only,
	pt_entry_t *ptep,
	locked_pvh_t *locked_pvh,
	bool *is_internal_p,
	bool *is_altacct_p)
{
	ASSERT_NOT_HIBERNATING();
	assert(locked_pvh != NULL);

	pv_remove_return_t ret = PV_REMOVE_SUCCESS;
	const unsigned int pai = locked_pvh->pai;
	bool is_internal = false;
	bool is_altacct = false;


	if (pvh_test_type(locked_pvh->pvh, PVH_TYPE_PTEP)) {
		if (__improbable((ptep != pvh_ptep(locked_pvh->pvh)))) {
			return PV_REMOVE_FAIL;
		}

		pvh_update_head(locked_pvh, PV_ENTRY_NULL, PVH_TYPE_NULL);
		is_internal = ppattr_is_internal(pai);
		is_altacct = ppattr_is_altacct(pai);
	} else if (pvh_test_type(locked_pvh->pvh, PVH_TYPE_PVEP)) {
		pv_entry_t **pvepp = NULL;
		pv_entry_t *pvep = pvh_pve_list(locked_pvh->pvh);
		assert(pvep != PV_ENTRY_NULL);
		unsigned int npves = 0;
		int pve_pte_idx = 0;
		/* Find the PVE that represents the mapping we're removing. */
		while ((pvep != PV_ENTRY_NULL) && ((pve_pte_idx = pve_find_ptep_index(pvep, ptep)) == -1)) {
			if (__improbable(npves == (SPTM_MAPPING_LIMIT / PTE_PER_PVE))) {
				pvh_lock_enter_sleep_mode(locked_pvh);
			}
			pvepp = pve_next_ptr(pvep);
			pvep = pve_next(pvep);
			npves++;
		}

		if (__improbable((pvep == PV_ENTRY_NULL))) {
			return PV_REMOVE_FAIL;
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
				if (__improbable(npves == (SPTM_MAPPING_LIMIT / PTE_PER_PVE))) {
					pvh_lock_enter_sleep_mode(locked_pvh);
				}
				if (pve_find_ptep_index(check_pvep, ptep) != -1) {
					panic_plain("%s: duplicate pve entry ptep=%p pmap=%p, pvh=%p, "
					    "pvep=%p, pai=0x%x", __func__, ptep, pmap,
					    (void*)locked_pvh->pvh, pvep, pai);
				}
				npves++;
			} while ((check_pvep = pve_next(check_pvep)) != PV_ENTRY_NULL);
		}
#endif /* MACH_ASSERT */

		const bool pve_is_first = (pvepp == NULL);
		const bool pve_is_last = (pve_next(pvep) == PV_ENTRY_NULL);
		const int other_pte_idx = !pve_pte_idx;

		if (pve_is_empty(pvep)) {
			/*
			 * This PVE doesn't contain any mappings. We can get rid of it.
			 */
			pve_remove(locked_pvh, pvepp, pvep);
			pv_free(pvep);
		} else if (!pve_is_first) {
			/*
			 * This PVE contains a single mapping. See if we can coalesce it with the one
			 * at the top of the list.
			 */
			pv_entry_t *head_pvep = pvh_pve_list(locked_pvh->pvh);
			int head_pve_pte_empty_idx;
			if ((head_pve_pte_empty_idx = pve_find_ptep_index(head_pvep, PT_ENTRY_NULL)) != -1) {
				pve_set_ptep(head_pvep, head_pve_pte_empty_idx, pve_get_ptep(pvep, other_pte_idx));
				if (pve_get_internal(pvep, other_pte_idx)) {
					pve_set_internal(head_pvep, head_pve_pte_empty_idx);
				}
				if (pve_get_altacct(pvep, other_pte_idx)) {
					pve_set_altacct(head_pvep, head_pve_pte_empty_idx);
				}
				pve_remove(locked_pvh, pvepp, pvep);
				pv_free(pvep);
			} else {
				/*
				 * We could not coalesce it. Move it to the start of the list, so that it
				 * can be coalesced against in the future.
				 */
				*pvepp = pve_next(pvep);
				pve_add(locked_pvh, pvep);
			}
		} else if (pve_is_first && pve_is_last) {
			/*
			 * This PVE contains a single mapping, and it's the last mapping for this PAI.
			 * Collapse this list back into the head, turning it into a PVH_TYPE_PTEP entry.
			 */
			assertf(pvh_pve_list(locked_pvh->pvh) == pvep, "%s: pvh %p != pvep %p",
			    __func__, (void*)locked_pvh->pvh, pvep);
			pvh_update_head(locked_pvh, pve_get_ptep(pvep, other_pte_idx), PVH_TYPE_PTEP);
			pp_attr_t attrs_to_set = 0;
			if (pve_get_internal(pvep, other_pte_idx)) {
				attrs_to_set |= PP_ATTR_INTERNAL;
			}
			if (pve_get_altacct(pvep, other_pte_idx)) {
				attrs_to_set |= PP_ATTR_ALTACCT;
			}
			if (attrs_to_set != 0) {
				ppattr_modify_bits(pai, 0, attrs_to_set);
			}
			pv_free(pvep);
		}
	} else {
		if (__improbable(!pvh_test_type(locked_pvh->pvh, PVH_TYPE_NULL))) {
			panic("%s: unexpected PV head %p, ptep=%p pmap=%p pai=0x%x",
			    __func__, (void*)locked_pvh->pvh, ptep, pmap, pai);
		}
		return PV_REMOVE_FAIL;
	}

	if (pvh_test_type(locked_pvh->pvh, PVH_TYPE_NULL)) {
		pvh_set_flags(locked_pvh, 0);
		const pmap_paddr_t pa = pai_to_pa(pai);
		pmap_prepare_unmapped_page_for_retype(pa);
		pp_attr_t attrs_to_clear = 0;
		if (is_internal) {
			attrs_to_clear |= PP_ATTR_INTERNAL;
		}
		if (is_altacct) {
			attrs_to_clear |= PP_ATTR_ALTACCT;
		}
		if (attrs_to_clear != 0) {
			ppattr_modify_bits(pai, attrs_to_clear, 0);
		}
		/* If removing the last mapping to a specially-protected page, retype the page back to XNU_DEFAULT. */
		pmap_retype_unmapped_page(pa);
	}

	*is_internal_p = is_internal;
	*is_altacct_p = is_altacct;
	return ret;
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
 * @param alloc_flags Allocation flags passed to pmap_page_alloc(). See the
 *                    definition of that function for a detailed description of
 *                    the available flags.
 *
 * @return The page table descriptor object if the allocation was successful, or
 *         NULL otherwise (which indicates that a page failed to be allocated
 *         for new nodes).
 */
MARK_AS_PMAP_TEXT pt_desc_t*
ptd_alloc_unlinked(unsigned int alloc_flags)
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

		/**
		 * Drop the lock while allocating pages since that can take a while and
		 * because preemption has to be enabled when allocating memory.
		 */
		pmap_simple_unlock(&ptd_free_list_lock);

		if (pmap_page_alloc(&pa, alloc_flags) != KERN_SUCCESS) {
			return NULL;
		}
		ptdp = (pt_desc_t *)phystokv(pa);

		pmap_simple_lock(&ptd_free_list_lock);
		ptd_page_count++;

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
		ptdp->ptd_info[i].wiredcnt = 0;
	}

	return ptdp;
}

/**
 * Allocate a single page table descriptor (PTD) object.
 *
 * @param pmap The pmap object that will be owning the page table(s) that this
 *             descriptor object represents.
 * @param alloc_flags Allocation flags passed to ptd_alloc_unlinked(). See the
 *                    definition of that function for a detailed description of
 *                    the available flags.
 *
 * @return The allocated PTD object, or NULL if one failed to get allocated
 *         (which indicates that memory wasn't able to get allocated).
 */
MARK_AS_PMAP_TEXT pt_desc_t*
ptd_alloc(pmap_t pmap, unsigned int alloc_flags)
{
	pt_desc_t *ptdp = ptd_alloc_unlinked(alloc_flags);

	if (ptdp == NULL) {
		return NULL;
	}

	ptdp->pmap = pmap;

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
	if ((uintptr_t)pmap != IOMMU_INSTANCE_NULL) {
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
	ptdp->va[pt_index] = (vm_offset_t) va & ~pt_attr_ln_pt_offmask(pt_attr, level - 1);
}

/**
 * Credit a specific ledger entry within the passed in pmap's ledger object.
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

	return ledger_credit(pmap->ledger, entry, amount);
}

/**
 * Debit a specific ledger entry within the passed in pmap's ledger object.
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

	return ledger_debit(pmap->ledger, entry, amount);
}

/**
 * Validate that the pointer passed into this method is a valid pmap object.
 *
 * @param pmap The pointer to validate.
 * @param func The stringized function name of the caller that will be printed
 *             in the case that the validation fails.
 */
void
validate_pmap_internal(const volatile struct pmap *pmap, const char *func)
{
	#pragma unused(pmap, func)
	assert(pmap != NULL);
}

/**
 * Validate that the pointer passed into this method is a valid pmap object and
 * is safe to both read and write.
 *
 * @param pmap The pointer to validate.
 * @param func The stringized function name of the caller that will be printed
 *             in the case that the validation fails.
 */
void
validate_pmap_mutable_internal(const volatile struct pmap *pmap, const char *func)
{
	#pragma unused(pmap, func)
	assert(pmap != NULL);
}

/**
 * Validate that the passed in pmap pointer is a pmap object that was allocated
 * by the pmap and not just random memory.
 *
 * This function will panic if the validation fails.
 *
 * @param pmap The object to validate.
 */
void
pmap_require(pmap_t pmap)
{
	if (pmap != kernel_pmap) {
		zone_id_require(ZONE_ID_PMAP, sizeof(struct pmap), pmap);
	}
}

/**
 * Helper function used when sorting and searching SPTM/PPL I/O ranges.
 *
 * @param a The first SPTM/PPL I/O range to compare.
 * @param b The second SPTM/PPL I/O range to compare.
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
 * Find and return the SPTM/PPL I/O range that contains the passed in physical
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

	pmap_cpu_data->cpu_number = cpu_number;

	/* Setup per-cpu fields used when calling into the SPTM. */
	pmap_sptm_percpu_data_t *sptm_pcpu = PERCPU_GET(pmap_sptm_percpu);
	assert(((uintptr_t)sptm_pcpu & (PMAP_SPTM_PCPU_ALIGN - 1)) == 0);
	sptm_pcpu->sptm_ops_pa = kvtophys_nofail((vm_offset_t)sptm_pcpu->sptm_ops);
	sptm_pcpu->sptm_templates_pa = kvtophys_nofail((vm_offset_t)sptm_pcpu->sptm_templates);

	const uint16_t sptm_cpu_number = sptm_cpu_id(ml_get_topology_info()->cpus[cpu_number].phys_id);
	sptm_pcpu->sptm_cpu_id = sptm_cpu_number;

	const pmap_paddr_t iommu_scratch =
	    sptm_cpu_iommu_scratch_start + (sptm_cpu_number * PMAP_IOMMU_SCRATCH_SIZE);
	assert(iommu_scratch <= (sptm_cpu_iommu_scratch_end - PMAP_IOMMU_SCRATCH_SIZE));
	sptm_pcpu->sptm_iommu_scratch = (void*)phystokv(iommu_scratch);
	sptm_pcpu->sptm_prev_ptes = (sptm_pte_t *)((uintptr_t)(SPTMArgs->sptm_prev_ptes) + (PAGE_SIZE * sptm_cpu_number));
}

/**
 * Initialize the pmap per-cpu data for the bootstrap CPU (the other CPUs should
 * just call pmap_cpu_data_init() directly).
 */
void
pmap_cpu_data_array_init(void)
{
	/**
	 * The EL2 portion of the IOMMU drivers need to have some memory they can
	 * use to pass data into the SPTM. To save memory (since most IOMMU drivers
	 * need this) and to preclude the need for IOMMU drivers to dynamically
	 * allocate memory in their mapping/unmapping paths, memory is pre-allocated
	 * here per-cpu for their usage.
	 *
	 * SPTM TODO: Only allocate this memory on systems that have IOMMU drivers.
	 */
	sptm_cpu_iommu_scratch_start = avail_start;
	avail_start += MAX_CPUS * PMAP_IOMMU_SCRATCH_SIZE;
	sptm_cpu_iommu_scratch_end = avail_start;

	pmap_cpu_data_init();
}

/**
 * Retrieve the pmap per-cpu data for the current CPU.
 *
 * @return The per-cpu pmap data for the current CPU.
 */
pmap_cpu_data_t *
pmap_get_cpu_data(void)
{
	pmap_cpu_data_t *pmap_cpu_data = NULL;

	pmap_cpu_data = &getCpuDatap()->cpu_pmap_cpu_data;
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
	cpu_data_t *cpu_data = cpu_datap((int)cpu);
	if (cpu_data == NULL) {
		return NULL;
	} else {
		return &cpu_data->cpu_pmap_cpu_data;
	}
}

/**
 * Define the resources we need for spinning
 * until a paddr is not inflight.
 */
__abortlike
static hw_spin_timeout_status_t
hw_lck_paddr_timeout_panic(void *_lock, hw_spin_timeout_t to, hw_spin_state_t st)
{
	panic("paddr spinlock[%p] " HW_SPIN_TIMEOUT_FMT "; "
	    HW_SPIN_TIMEOUT_DETAILS_FMT,
	    _lock, HW_SPIN_TIMEOUT_ARG(to, st),
	    HW_SPIN_TIMEOUT_DETAILS_ARG(to, st));
}

static const struct hw_spin_policy hw_paddr_inflight_spin_policy = {
	.hwsp_name              = "hw_lck_paddr_lock",
	.hwsp_timeout_atomic    = &LockTimeOut,
	.hwsp_op_timeout        = hw_lck_paddr_timeout_panic,
};

/**
 * Barrier function for spinning until the given physical page is
 * no longer inflight.
 *
 * @param paddr The physical address we want to spin until is not inflight.
 */
static __attribute__((noinline)) void
pmap_paddr_inflight_barrier(pmap_paddr_t paddr)
{
	hw_spin_policy_t  pol = &hw_paddr_inflight_spin_policy;
	hw_spin_timeout_t to;
	hw_spin_state_t   state  = { };

	disable_preemption();
	to  = hw_spin_compute_timeout(pol);
	while (sptm_paddr_is_inflight(paddr) &&
	    hw_spin_should_keep_spinning((void*)paddr, pol, to, &state)) {
		;
	}
	enable_preemption();
}

/**
 * Convenience function for checking if a given physical page is inflight.
 *
 * @param paddr The physical address to query.
 *
 * @return true if the page in question has no mappings, false otherwise.
 */
inline bool
pmap_is_page_free(pmap_paddr_t paddr)
{
	/**
	 * We can't query the paddr refcounts if the physical page
	 * is currently inflight. If it does, we spin until it's not.
	 */
	if (__improbable(sptm_paddr_is_inflight(paddr))) {
		pmap_paddr_inflight_barrier(paddr);
	}

	/**
	 * A barrier from the last inflight operation. This allows us
	 * to have proper visibility for the refcounts. Otherwise,
	 * sptm_frame_is_last_mapping() might see stale values.
	 */
	os_atomic_thread_fence(acquire);

	/**
	 * If SPTM returns TRUE for SPTM_REFCOUNT_NONE, it means
	 * the physical page has no mappings.
	 */
	return sptm_frame_is_last_mapping(paddr, SPTM_REFCOUNT_NONE);
}
