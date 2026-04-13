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

#include "mock_mem.h"
#include "mach/arm/vm_types.h"
#include "vm/vm_object_xnu.h"
#include "vm/vm_map_xnu.h"
#include "vm/vm_protos.h"
#include "kern/zalloc_internal.h"
#include "std_safe.h"
#include "dt_proxy.h"
#include "osfmk/unit_test_utils.h"
#include <stdint.h>


void
mock_pool_buffer_init(struct mock_mem_pool_buffer* pb, size_t total_size)
{
	pb->buffer = calloc(1, total_size);
	assert(pb->buffer != NULL);
	pb->size_in_bytes = total_size;
	pb->next_free = pb->buffer;
}

static char *
mock_get_mem_pool(struct mock_mem_pool_buffer* pb, size_t buffer_size_int_bytes, size_t alignment)
{
	assert(pb->size_in_bytes > 0);
	char *ret = (char*)roundup((uintptr_t)pb->next_free, alignment);
	pb->next_free = ret + buffer_size_int_bytes;
	/* check there's space in the superbuffer */
	assert(pb->next_free <= pb->buffer + pb->size_in_bytes);
	return ret;
}

typedef struct mock_mem_elem {
	struct mock_mem_elem *next_free;
} mock_mem_elem_t;



size_t
mock_mem_init(struct mock_mem_pool *mm, size_t elem_sz, size_t align, uint32_t count, const char *name)
{
	mm->name = name;
	size_t elem_sz_aligned = roundup(elem_sz, align);
	mm->elem_size = MAX(elem_sz_aligned, sizeof(mock_mem_elem_t));
	mm->alignment = align;
	mm->free_count = count;
	mm->total_count = count;
	mm->allocated_count = 0;
	// return the number of bytes this pool needs
	// ask for extra + alignemnt in case the starting buffer pointer needs to be adjusted for alignemnt
	return mm->elem_size * count + mm->alignment;
}

void
mock_mem_setup(struct mock_mem_pool *mm, struct mock_mem_pool_buffer* pb)
{
	size_t buf_size = mm->elem_size * mm->total_count;
	mm->buffer = mock_get_mem_pool(pb, buf_size, mm->alignment);
	assert(mm->buffer != NULL);

	mm->free_head = (mock_mem_elem_t *)mm->buffer;

	/* init free list */
	mock_mem_elem_t *curr = (mock_mem_elem_t *)mm->buffer;
	for (uint32_t i = 0; i < mm->total_count - 1; i++) {
		curr->next_free = (mock_mem_elem_t *)((char *)curr + mm->elem_size);
		curr = curr->next_free;
	}
	curr->next_free = NULL;
}

void *
mock_mem_alloc(struct mock_mem_pool *mm)
{
	assert(mm->buffer);
	assert(mm->free_count > 0); /* check there's space left */
	mock_mem_elem_t *ret = mm->free_head;
	assert(ret != NULL);
	mm->free_head = ret->next_free; /* move to next free slot */
	memset(ret, 0, mm->elem_size);
	mm->free_count--;
	mm->allocated_count++;
	return (void *)ret;
}

void
mock_mem_free(struct mock_mem_pool *mm, void *ptr)
{
	assert(mm->buffer != NULL);
	assert(mm->free_count < mm->total_count);
	assert(ptr >= (void *)mm->buffer && ptr < (void *)(mm->buffer + mm->elem_size * mm->total_count));
	uintptr_t offset = (uintptr_t)((char *)ptr - mm->buffer);
	assert(offset % mm->elem_size == 0); /* check alignment */

	mock_mem_elem_t *elem = (mock_mem_elem_t *)ptr;
	elem->next_free = mm->free_head;
	mm->free_head = elem; /* update free_head to point to newly freed block */
	mm->free_count++;
	mm->allocated_count--;

	/* Add if it's needed: 1. add tagging to prevent use-after-free, 2. prevent double free */
}


struct mock_mem_pool mm_pools[MEM_POOL_COUNT];

#define VM_SUBMAP_ALIGNMENT    64
#define VM_MAP_ENTRY_ALIGNMENT 64
#define VM_OBJECT_ALIGNMENT    64
#define VMS_NODE_ALIGNMENT     256
#define VMGO_CHUNK_ALIGNMENT   64

#ifdef __BUILDING_WITH_LIBFUZZER__
// increase the count of mem pools when building for fuzzing
	#define MEM_POOL_VM_OBJECTS_COUNT      (65536 * 2)
	#define MEM_POOL_VM_MAPS_COUNT         65536
	#define MEM_POOL_VM_MAPS_ENTRIES_COUNT (65536 * 2)
	#define MEM_POOL_VM_MAP_COPIES_COUNT   65536
	#define MEM_POOL_VM_MAP_NODES_COUNT    32768
	#define MEM_POOL_VM_GO_CHUNKS_COUNT    32768
#else
	#define MEM_POOL_VM_OBJECTS_COUNT      10240
	#define MEM_POOL_VM_MAPS_COUNT         1024
	#define MEM_POOL_VM_MAPS_ENTRIES_COUNT 10240
	#define MEM_POOL_VM_MAP_COPIES_COUNT   1024
	#define MEM_POOL_VM_MAP_NODES_COUNT    10240
	#define MEM_POOL_VM_GO_CHUNKS_COUNT    10240
#endif

void
mock_mem_init_all()
{
	size_t sz = 0;
	sz += mock_mem_init(&mm_pools[MEM_POOL_VM_OBJECTS], sizeof(struct vm_object), VM_OBJECT_ALIGNMENT, MEM_POOL_VM_OBJECTS_COUNT, "vm_object");
	sz += mock_mem_init(&mm_pools[MEM_POOL_VM_MAPS],
	    sizeof(struct _vm_map), VM_SUBMAP_ALIGNMENT, MEM_POOL_VM_MAPS_COUNT, "vm_map");
	sz += mock_mem_init(&mm_pools[MEM_POOL_VM_MAP_ENTRIES],
	    sizeof(struct vm_map_entry), VM_MAP_ENTRY_ALIGNMENT, MEM_POOL_VM_MAPS_ENTRIES_COUNT, "vm_map_entry");
	sz += mock_mem_init(&mm_pools[MEM_POOL_VM_MAP_COPIES],
	    sizeof(struct vm_map_copy), VM_SUBMAP_ALIGNMENT, MEM_POOL_VM_MAP_COPIES_COUNT, "vm_map_copy");
	sz += mock_mem_init(&mm_pools[MEM_POOL_VM_MAP_NODES],
	    sizeof(struct vm_map_store_node), VMS_NODE_ALIGNMENT, MEM_POOL_VM_MAP_NODES_COUNT, "vm_map_store_node");
	sz += mock_mem_init(&mm_pools[MEM_POOL_VM_GO_CHUNKS],
	    sizeof(struct vm_map_store_node), VMGO_CHUNK_ALIGNMENT, MEM_POOL_VM_GO_CHUNKS_COUNT, "vm_guard_object_chunk");

	struct mock_mem_pool_buffer pb = {0};
	mock_pool_buffer_init(&pb, sz);

	for (int i = 0; i < MEM_POOL_COUNT; ++i) {
		mock_mem_setup(&mm_pools[i], &pb);
	}
}

void *
mock_mem_alloc_id(mem_pool_id mid)
{
	assert(mid >= 0 && mid < MEM_POOL_COUNT);
	return mock_mem_alloc(&mm_pools[mid]);
}

void
mock_mem_free_id(mem_pool_id mid, void *ptr)
{
	assert(mid >= 0 && mid < MEM_POOL_COUNT);
	mock_mem_free(&mm_pools[mid], ptr);
}

uint32_t
mock_mem_count_allocated(mem_pool_id mid)
{
	assert(mid >= 0 && mid < MEM_POOL_COUNT);
	return mm_pools[mid].allocated_count;
}
