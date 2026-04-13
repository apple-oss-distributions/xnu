/*
 * Copyright (c) 2000-2024 Apple Inc. All rights reserved.
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

#include "mocks/std_safe.h"
#include "mocks/osfmk/unit_test_utils.h"
#include "mocks/osfmk/mock_thread.h"
#include "mocks/mock_mem.h"
#include "mocks/dt_proxy.h"
#include "fibers/fibers.h"

#include <kern/zalloc.h>
#include <kern/kalloc.h>
#include <mach/vm_types.h>
#include <vm/vm_kern_xnu.h>
#include <kern/zalloc_internal.h>

#undef kalloc_ext

/*
 * leakchecker: Detect memory leaks on heap chunks allocated forwarding to the libc allocator instead of using the mempool.
 * For the mempool, see mock_zalloc_check_leaks.
 */

typedef struct allocation_info {
	void *ptr;
	size_t size;
	struct backtrace_array *backtrace;
	bool initial;
	struct allocation_info *next;
} allocation_info_t;

static allocation_info_t *allocation_list = NULL;
static size_t total_allocated = 0;

int leakchecker_enabled = 0;

void
leakchecker_add_allocation(void *ptr, size_t size)
{
	if (!leakchecker_enabled || ptr == NULL) {
		return;
	}

	allocation_info_t *new_allocation;

	new_allocation = (allocation_info_t *)malloc(sizeof(allocation_info_t));
	if (new_allocation == NULL) {
		PT_FAIL("leakchecker: failed to allocate memory for allocation info");
	}

	struct backtrace_array *bt = collect_current_backtrace();
	new_allocation->ptr = ptr;
	new_allocation->size = size;
	new_allocation->backtrace = bt;
	new_allocation->initial = false;
	new_allocation->next = NULL;

	new_allocation->next = allocation_list;
	allocation_list = new_allocation;

	total_allocated += size;
}

void
leakchecker_remove_allocation(void *ptr)
{
	if (!leakchecker_enabled || ptr == NULL) {
		return;
	}

	allocation_info_t *current, *previous;

	current = allocation_list;
	previous = NULL;

	while (current != NULL) {
		if (current->ptr == ptr) {
			if (previous == NULL) {
				allocation_list = current->next;
			} else {
				previous->next = current->next;
			}

			total_allocated -= current->size;

			free(current);
			return;
		}

		previous = current;
		current = current->next;
	}

	raw_printf("leakchecker: attempting to free memory not allocated by tracked allocator (normal if coming from C++ stdlib functions): %p\n", ptr);
	print_current_backtrace();
}

void
leakchecker_mark_initial_allocations(void)
{
	allocation_info_t *current;
	current = allocation_list;

	while (current != NULL) {
		current->initial = true;
		current = current->next;
	}
}

void
leakchecker_check_memory_leaks(void)
{
	allocation_info_t *current;
	bool leaks_found = false;
	size_t total_leaked_bytes = 0;

	current = allocation_list;

	while (current != NULL) {
		if (current->initial) {
			current = current->next;
			continue;
		}
		raw_printf("leak: addr=%p size=%zu allocated at:\n", current->ptr, current->size);
		print_collected_backtrace(current->backtrace);
		total_leaked_bytes += current->size;
		current = current->next;
		leaks_found = true;
	}

	if (leaks_found) {
		char str[PRINT_BUF_SIZE];
		snprintf(str, PRINT_BUF_SIZE, "leakchecker: memory leaks detected, total leaked memory: %zu bytes", total_leaked_bytes);
		PT_FAIL(str);
	}
}


T_MOCK_F(struct kalloc_result,
kalloc_ext, (
	void                   *kheap_or_kt_view,
	vm_size_t               size,
	zalloc_flags_t          flags,
	void                   *owner), (kheap_or_kt_view, size, flags, owner))
{
	void* addr = calloc(1, size);
	leakchecker_add_allocation(addr, size);
	return (struct kalloc_result){ .addr = addr, .size = size };
}


T_MOCK_F(void,
kfree_ext, (void *kheap_or_kt_view, void *data, vm_size_t size), (kheap_or_kt_view, data, size))
{
	leakchecker_remove_allocation(data);
	free(data);
}

T_MOCK_F(void *,
kalloc_type_impl_internal, (kalloc_type_view_t kt_view, zalloc_flags_t flags), (kt_view, flags))
{
	vm_size_t size = kalloc_type_get_size(kt_view->kt_size);
	void *addr = calloc(1, size);
	leakchecker_add_allocation(addr, size);
	return addr;
}

T_MOCK_F(void *,
kalloc_type_impl_external, (kalloc_type_view_t kt_view, zalloc_flags_t flags), (kt_view, flags))
{
	vm_size_t size = kalloc_type_get_size(kt_view->kt_size);
	void *addr = calloc(1, size);
	leakchecker_add_allocation(addr, size);
	return addr;
}

T_MOCK_F(void,
kfree_type_impl_internal, (kalloc_type_view_t kt_view, void *ptr __unsafe_indexable), (kt_view, ptr))
{
	leakchecker_remove_allocation(ptr);
	free(ptr);
}

T_MOCK_F(kmem_return_t,
kmem_alloc_guard, (
	vm_map_t        map,
	vm_size_t       size,
	vm_offset_t     mask,
	kma_flags_t     flags,
	kmem_guard_t    guard), (map, size, mask, flags, guard))
{
	kmem_return_t kmr = { };
	if (mask < PAGE_MASK) {
		mask = PAGE_MASK;
	}
	vm_size_t rounded_size = round_page(size);
	void *addr = checked_alloc_align(rounded_size, mask + 1);
	kmr.kmr_address = (vm_address_t)addr;
	leakchecker_add_allocation((void*)kmr.kmr_address, rounded_size);
	// TODO verify allocation rdar://136915968
	// TODO malloc with guard pages?
	kmr.kmr_return = KERN_SUCCESS;
	return kmr;
}

T_MOCK_F(vm_size_t,
kmem_free_guard, (
	vm_map_t        map,
	vm_offset_t     req_addr,
	vm_size_t       req_size,
	kmf_flags_t     flags,
	kmem_guard_t    guard), (map, req_addr, req_size, flags, guard))
{
	leakchecker_remove_allocation((void *)req_addr);
	free((void *)req_addr);
	// TODO rdar://136915968
	return req_size;
}

T_MOCK_F(kmem_return_t,
kmem_realloc_guard, (
	vm_map_t                map,
	vm_offset_t             req_oldaddr,
	vm_size_t               req_oldsize,
	vm_size_t               req_newsize,
	kmr_flags_t             flags,
	kmem_guard_t            guard), (map, req_oldaddr, req_oldsize, req_newsize, flags, guard)
)
{
	kmem_return_t kmr = { };
	kmr.kmr_return = KERN_SUCCESS;
	if (req_newsize <= req_oldsize) {
		kmr.kmr_address = req_oldaddr;
		return kmr;
	}

	kmr.kmr_address = (vm_address_t)calloc(1, req_newsize);
	leakchecker_add_allocation((void*)kmr.kmr_address, req_newsize);

	memcpy((void*)kmr.kmr_address, (void*)req_oldaddr, req_oldsize);
	leakchecker_remove_allocation((void *)req_oldaddr);
	free((void *)req_oldaddr);
	// TODO rdar://136915968
	return kmr;
}

T_MOCK_F(void *,
zalloc_permanent_tag, (vm_size_t size, vm_offset_t mask, vm_tag_t tag), (size, mask, tag))
{
	// mask is align-1, see ZALIGN()
	void *addr = checked_alloc_align(size, mask + 1);
	leakchecker_add_allocation(addr, size);
	return addr;
}

T_MOCK_F(void *,
zalloc_percpu_permanent, (vm_size_t size, vm_offset_t mask), (size, mask))
{
	// allocate PAGE_SIZE bytes for EACH CPU (critical for zpercpu_get_cpu())
	assert(size <= PAGE_SIZE);
	vm_size_t total_size = PAGE_SIZE * fibers_multicpu.cpu_count;
	void *addr = checked_alloc_align(total_size, mask + 1);
	leakchecker_add_allocation(addr, total_size);
	return addr;
}

T_MOCK_F(void,
zalloc_ro_mut, (zone_id_t zid, void *elem, vm_offset_t offset, const void *new_data, vm_size_t new_data_size),
(zid, elem, offset, new_data, new_data_size))
{
	memcpy((void *)((uintptr_t)elem + offset), new_data, new_data_size);
}

T_MOCK_F(void,
zone_require, (zone_t zone, void *addr), (zone, addr))
{
	// TODO rdar://136915968
}

T_MOCK_F(void,
zone_id_require, (zone_id_t zid, vm_size_t esize, void *addr), (zid, esize, addr))
{
	// TODO rdar://136915968
}

T_MOCK_F(void,
zone_id_require_aligned, (zone_id_t zid, void *addr), (zid, addr))
{
	// TODO rdar://136915968
}

T_MOCK_F(void,
zone_enable_caching, (zone_t zone), (zone))
{
}

static mem_pool_id
get_mem_pool_id(zone_t zone)
{
	zone_id_t zid = zone_index(zone);
	if (zid == ZONE_ID_VM_MAP) {
		return MEM_POOL_VM_MAPS;
	} else if (zid == ZONE_ID_VM_MAP_ENTRY) {
		return MEM_POOL_VM_MAP_ENTRIES;
	} else if (zid == ZONE_ID_VM_MAP_COPY) {
		return MEM_POOL_VM_MAP_COPIES;
	} else if (zid == ZONE_ID_VM_MAP_NODES) {
		return MEM_POOL_VM_MAP_NODES;
	} else if (zid == ZONE_ID_VM_GO_CHUNKS) {
		return MEM_POOL_VM_GO_CHUNKS;
	} else if (strcmp(zone->z_name, "vm objects") == 0) {
		return MEM_POOL_VM_OBJECTS;
	} else {
		return -1;
	}
}

static void
verify_packing(void* addr, mem_pool_id mpid)
{
	switch (mpid) {
	case MEM_POOL_VM_MAPS:
	case MEM_POOL_VM_MAP_ENTRIES:
	case MEM_POOL_VM_MAP_COPIES:
	case MEM_POOL_VM_GO_CHUNKS:
		// needs to fit in VME_PREV
		VM_ASSERT_POINTER_PACKABLE((vm_offset_t)addr, VME_PACKED_PTR);
		break;
	case MEM_POOL_VM_MAP_NODES:
		// needs to fit in vmsn_next_sibling
		VM_ASSERT_POINTER_PACKABLE((vm_offset_t)addr, VMN_PACKED_PTR);
		break;
	case MEM_POOL_VM_OBJECTS:
		// needs to fit in VME_OBJECT
		VM_ASSERT_POINTER_PACKABLE((vm_offset_t)addr, VM_PAGE_PACKED_PTR);
		break;
	default:
		break;
	}
}

static const char *
pool_name(mem_pool_id mpid)
{
	switch (mpid) {
	case MEM_POOL_VM_MAPS: return "maps";
	case MEM_POOL_VM_MAP_ENTRIES: return "entries";
	case MEM_POOL_VM_MAP_COPIES: return "copies";
	case MEM_POOL_VM_MAP_NODES: return "nodes";
	case MEM_POOL_VM_GO_CHUNKS: return "chunks";
	case MEM_POOL_VM_OBJECTS: return "objects";
	default:
		PT_FAIL("unknown mpid");
		return "unknown";
	}
}


T_MOCK_F(struct kalloc_result,
zalloc_ext, (zone_t zone, zone_stats_t zstats, zalloc_flags_t flags), (zone, zstats, flags))
{
	void* addr = NULL;
	mem_pool_id mpid = get_mem_pool_id(zone);
	if (mpid == -1) {
		addr = calloc(1, zone->z_elem_size);
		leakchecker_add_allocation(addr, zone->z_elem_size);
	} else {
		addr = mock_mem_alloc_id(mpid);
		verify_packing(addr, mpid);
	}

	// update per-CPU statistics if provided
	if (zstats && ut_mocks_use_fibers) {
		unsigned int cpu = fibers_current ? fibers_current->assigned_cpu : 0;
		struct zone_stats *cpu_stats = (struct zone_stats *)
		    ((char *)zstats + cpu * sizeof(struct zone_stats));
		cpu_stats->zs_mem_allocated += zone->z_elem_size;
	}

	return (struct kalloc_result){ (void *)addr, zone->z_elem_size };
}

T_MOCK_F(void,
zfree_ext, (zone_t zone, zone_stats_t zstats, void *addr, uint64_t combined_size), (zone, zstats, addr, combined_size))
{
	// update per-CPU statistics if provided
	if (zstats && ut_mocks_use_fibers) {
		unsigned int cpu = fibers_current ? fibers_current->assigned_cpu : 0;
		struct zone_stats *cpu_stats = (struct zone_stats *)
		    ((char *)zstats + cpu * sizeof(struct zone_stats));
		cpu_stats->zs_mem_freed += zone->z_elem_size;
	}

	mem_pool_id mpid = get_mem_pool_id(zone);
	// objects that are not managed by the mock mem pool were allocated by calloc() and
	// should be freed by free(), see enum mem_pool_id.
	if (mpid == -1) {
		leakchecker_remove_allocation(addr);
		free(addr);
	} else {
		mock_mem_free_id(mpid, addr);
	}
}

/*
 * These kalloc_array_[encode,decode] functions are only used
 * by kalloc_array types. The implementation of kalloc_array stores the length
 * of the array and the size of elements in the top bits of the pointer, so
 * encoding and decoding allow you to access those paramaters. Userspace has
 * different guarantees about pointer shape than the kernel making this is
 * fundamentally uninteresting to test in userspace and so we mock it
 * achieving the same behavior using malloc_size instead.
 */
T_MOCK_F(struct kalloc_result,
__kalloc_array_decode, (vm_address_t ptr), (ptr))
{
	if (ptr) {
		return (struct kalloc_result){ (void *)ptr, malloc_size((void *)ptr)};
	}
	return (struct kalloc_result){ (void *)ptr, 0};
}

T_MOCK_F(vm_address_t,
__kalloc_array_encode_vm, (vm_address_t addr, vm_size_t size __unused), (addr, size))
{
	return addr;
}

T_MOCK_F(void *,
__kalloc_array_encode_zone, (zone_t z __unused, void *ptr, vm_size_t size __unused), (z, ptr, size))
{
	return ptr;
}

void
mock_zalloc_counts_sample(mock_zone_counts_t *zc)
{
	// RANGELOCKINGTODO rdar://136915968 do this for non mock_mem zones as well
	for (int i = 0; i < MEM_POOL_COUNT; ++i) {
		zc->mock_mem_counts[i] = mock_mem_count_allocated(i);
	}
}

void
mock_zalloc_check_leaks(mock_zone_counts_t *before)
{
	char str[PRINT_BUF_SIZE];
	for (int i = 0; i < MEM_POOL_COUNT; ++i) {
		uint32_t before_count = before->mock_mem_counts[i];
		uint32_t now_count = mock_mem_count_allocated(i);
		if (before_count != now_count) {
			snprintf(str, PRINT_BUF_SIZE, "found leak of zalloc `%s` object  %u != %u (%d)", pool_name(i),
			    before_count, now_count, now_count - before_count);
			PT_FAIL(str);
		}
#if 0
		snprintf(str, PRINT_BUF_SIZE, "no leak for `%s` object  %u", pool_name(i), before_count);
		PT_LOG(str);
#endif
	}
}

void
mock_zalloc_check_leak_atend(void)
{
	if (!PT_STATE_PASS) {
		// if the test did not pass, don't do the leak analysis to not distract
		// from the real failures
		return;
	}
	// the expected objects are the object that are created on bootstrap which are
	// the 1 vm_map for the kernel_map and a 1 hole owned by it.
	mock_zone_counts_t expect_counts = {0, 1, 0, 0, 1};
	mock_zalloc_check_leaks(&expect_counts);
}

T_MOCK_F(void *,
zalloc_percpu, (
	zone_or_view_t  zov,
	zalloc_flags_t  flags), (zov, flags))
{
	if (!ut_mocks_use_fibers) {
		return zalloc_percpu(zov, flags);
	}

	// allocate contiguous buffer: num_cpus * PAGE_SIZE
	// zpercpu_get_cpu macro will calculate: base + (cpu * PAGE_SIZE)
	vm_size_t total_size = fibers_multicpu.cpu_count * PAGE_SIZE;
	void *addr = calloc(1, total_size);
	leakchecker_add_allocation(addr, total_size);

	return addr;
}

T_MOCK_F(void,
zfree_percpu, (
	zone_or_view_t  zov,
	void           *addr), (zov, addr))
{
	if (!ut_mocks_use_fibers) {
		return zfree_percpu(zov, addr);
	}

	leakchecker_remove_allocation(addr);
	free(addr);
}

T_MOCK_F(unsigned,
zpercpu_count, (void), ())
{
	if (ut_mocks_use_fibers) {
		return fibers_multicpu.cpu_count;
	}
	return 1;
}

T_MOCK_F(void,
zone_enable_smr, (zone_t zone, struct smr *smr, zone_smr_free_cb_t free_cb), (zone, smr, free_cb))
{
}
