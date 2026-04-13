/*
 * Copyright (c) 2000-2025 Apple Inc. All rights reserved.
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

#pragma once
#include <stdint.h>
#include <stddef.h>

typedef enum {
	MEM_POOL_VM_OBJECTS,
	MEM_POOL_VM_MAPS,
	MEM_POOL_VM_MAP_ENTRIES,
	MEM_POOL_VM_MAP_COPIES,
	MEM_POOL_VM_MAP_NODES,
	MEM_POOL_VM_GO_CHUNKS,

	MEM_POOL_COUNT
} mem_pool_id;

extern void mock_mem_init_all();
extern void *mock_mem_alloc_id(mem_pool_id mid);
extern void mock_mem_free_id(mem_pool_id mid, void *ptr);
extern uint32_t mock_mem_count_allocated(mem_pool_id mid);


/*
 * This is an implementation of a simple pool buffer, that will
 * unite all of the below-defined pools (replaces zones) under one array.
 * It allows to mimick the packability of pointers to vm_objects,
 * vm_maps, vm_entries, etc., by ensuring addresses are within a
 * certain range (beyond a certain base, to be percise).
 */
struct mock_mem_pool_buffer {
	char *buffer;
	size_t size_in_bytes;
	char *next_free;
};

void mock_pool_buffer_init(struct mock_mem_pool_buffer* pb, size_t total_size);

/*
 * This is an implementation of simple fixed size same-size objects pool.
 * It has an in-place free list where every free block's first bytes
 * holds a pointer to the next free block.
 */
struct mock_mem_pool {
	const char *name;
	size_t elem_size;
	size_t alignment;
	char *buffer;
	struct mock_mem_elem *free_head;
	uint32_t free_count;
	uint32_t allocated_count;
	uint32_t total_count;
};

size_t mock_mem_init(struct mock_mem_pool *mm, size_t elem_sz, size_t align, uint32_t count, const char *name);
void mock_mem_setup(struct mock_mem_pool *mm, struct mock_mem_pool_buffer* pb);
void *mock_mem_alloc(struct mock_mem_pool *mm);
void mock_mem_free(struct mock_mem_pool *mm, void *ptr);

typedef struct mock_zone_counts {
	uint32_t mock_mem_counts[MEM_POOL_COUNT];
} mock_zone_counts_t;
extern void mock_zalloc_counts_sample(mock_zone_counts_t *zc);
extern void mock_zalloc_check_leaks(mock_zone_counts_t *before);
extern void mock_zalloc_setup_global_check(void);
extern void mock_zalloc_check_leak_atend(void);

/* Leak checker for pool allocated objects
 * Tests that create and destroy objects that are handled by mock_mem_pool (see mem_pool_id enum)
 * can also do leak detection for these objects.
 * To do that for a single test or a single scope, add T_MOCK_ZALLOC_LEAK_CHECK() in the scope.
 * To do it for all tests in a .c file, add T_MOCK_ZALLOC_LEAK_CHECK_GLOBAL() in the global scope.
 */

#define _T_MOCK_ZALLOC_LEAK_CHECK(counter)                                                              \
	__attribute__((cleanup(mock_zalloc_check_leaks))) mock_zone_counts_t _mock_zone_counts_ ## counter; \
	mock_zalloc_counts_sample(&_mock_zone_counts_ ## counter)

#define T_MOCK_ZALLOC_LEAK_CHECK(__COUNTER__)

#define T_MOCK_ZALLOC_LEAK_CHECK_GLOBAL()                              \
	__attribute__((constructor)) void _mock_zone_counts_global(void) { \
	        T_ATEND(mock_zalloc_check_leak_atend);                     \
	}

// memory leacks checker
extern int leakchecker_enabled;
extern void leakchecker_add_allocation(void *ptr, size_t size);
extern void leakchecker_remove_allocation(void *ptr);
extern void leakchecker_mark_initial_allocations(void);
extern void leakchecker_check_memory_leaks(void);
