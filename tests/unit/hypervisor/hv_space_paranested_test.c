/*
 * Copyright (c) 2025 Apple Inc. All rights reserved.
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

#include <darwintest.h>
#include "mocks/osfmk/unit_test_utils.h"
#include "mocks/osfmk/mock_hv.h"
#include "mocks/osfmk/mock_upl.h"
#include "mocks/osfmk/mock_thread.h"

#include <arm64/hv/hv_kern_types.h>
#include <arm64/hv/hv_vm.h>
#include <arm64/hv_hvc.h>
#include <kern/locks.h>
#include <kern/thread.h>
#include <mach/memory_object_types.h>
#include <mach/vm_param.h>
#include <mach/vm_types.h>

#define UT_MODULE osfmk
T_GLOBAL_META(
	T_META_NAMESPACE("xnu.unit.hv_space_paranested_test"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_OWNER("simon_ho")
	);

// Test constants for mock pointers
static upl_page_info_t *kTestUplInternalPageMockPointer = (upl_page_info_t *)0xdeadbeef;
static const upl_t kTestUplMockPointer = (upl_t)0xdeadbeef;
static const upl_t kTestUplMockPointer1 = (upl_t)0xcafebabe;  // For tests needing distinct pointers
static const upl_t kTestUplMockPointer2 = (upl_t)0xfeedface; // For tests needing distinct pointers

// Implement the mock functions.
T_MOCK_CALL_QUEUE(upl_phys_page_call, {
	int expected_page_index;
	ppnum_t return_val;
});

T_MOCK_SET_PERM_FUNC(ppnum_t, upl_phys_page, (upl_page_info_t * upl_info, int page_index)) {
	upl_phys_page_call call = dequeue_upl_phys_page_call();
	T_QUIET; T_ASSERT_EQ(page_index, call.expected_page_index, "page_index");
	return call.return_val;
}

T_MOCK_CALL_QUEUE(hv_call_call, {
	uint64_t expected_fn;
	uint64_t expected_arg0;
	uint64_t expected_arg1;
	uint64_t expected_arg2;
	uint64_t expected_arg3;
	uint64_t expected_arg4;
	uint64_t mock_ret_val;
	hv_return_t ret;
});

T_MOCK_SET_PERM_FUNC(hv_return_t, hv_call, (uint64_t fn, uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t * ret_val)) {
	hv_call_call call = dequeue_hv_call_call();
	T_QUIET; T_ASSERT_EQ(fn, call.expected_fn, "hv_call fn");
	T_QUIET; T_ASSERT_EQ(arg0, call.expected_arg0, "hv_call arg0");
	T_QUIET; T_ASSERT_EQ(arg1, call.expected_arg1, "hv_call arg1");
	T_QUIET; T_ASSERT_EQ(arg2, call.expected_arg2, "hv_call arg2");
	T_QUIET; T_ASSERT_EQ(arg3, call.expected_arg3, "hv_call arg3");
	T_QUIET; T_ASSERT_EQ(arg4, call.expected_arg4, "hv_call arg4");
	if (ret_val) {
		*ret_val = call.mock_ret_val;
	}
	return call.ret;
}

T_MOCK_SET_PERM_FUNC(upl_page_info_t *, upl_get_internal_page_list, (upl_t upl)) {
	return (upl_page_info_t *)kTestUplInternalPageMockPointer;
}

T_MOCK_CALL_QUEUE(vm_map_create_upl_call, {
	vm_map_t expected_map;
	vm_map_address_t expected_offset;
	upl_size_t expected_upl_size_in;
	upl_size_t mock_upl_size_out;
	upl_t mock_upl_out;
	unsigned int mock_count_out;
	upl_control_flags_t expected_flags;
	vm_tag_t expected_tag;
	kern_return_t ret;
});

T_MOCK_SET_PERM_FUNC(kern_return_t, vm_map_create_upl, (vm_map_t map, vm_map_address_t offset, upl_size_t * upl_size, upl_t * upl, __unused upl_page_info_array_t page_list, unsigned int *count, upl_control_flags_t *flags, vm_tag_t tag)) {
	vm_map_create_upl_call call = dequeue_vm_map_create_upl_call();
	T_QUIET; T_ASSERT_EQ((uintptr_t)map, (uintptr_t)call.expected_map, "vm_map_create_upl map");
	T_QUIET; T_ASSERT_EQ(offset, call.expected_offset, "vm_map_create_upl offset");
	T_QUIET; T_ASSERT_EQ(*upl_size, call.expected_upl_size_in, "vm_map_create_upl *upl_size in");
	T_QUIET; T_ASSERT_EQ(*flags, call.expected_flags, "vm_map_create_upl *flags");
	T_QUIET; T_ASSERT_EQ(tag, call.expected_tag, "vm_map_create_upl tag");

	*upl_size = call.mock_upl_size_out;
	*upl = call.mock_upl_out;
	*count = call.mock_count_out;

	return call.ret;
}

T_MOCK_CALL_QUEUE(ubc_upl_commit_call, {
	upl_t expected_upl;
	int ret;
});

T_MOCK_SET_PERM_FUNC(int, ubc_upl_commit, (upl_t upl)) {
	ubc_upl_commit_call call = dequeue_ubc_upl_commit_call();
	T_QUIET; T_ASSERT_EQ((uintptr_t)upl, (uintptr_t)call.expected_upl, "ubc_upl_commit upl");
	return call.ret;
}

static void
test_teardown_assert_queues_empty(void)
{
	assert_empty_vm_map_create_upl_call();
	assert_empty_upl_phys_page_call();
	assert_empty_hv_call_call();
	assert_empty_ubc_upl_commit_call();
}

static void
test_cleanup_vm(hv_vm_t *vm)
{
	hv_map_entry_t *entry, *next;
	LIST_FOREACH_SAFE(entry, &vm->map_list_head, entry_link, next) {
		LIST_REMOVE(entry, entry_link);
		/*
		 * Use free() to deallocate memory allocated with kalloc_type().
		 * The kalloc_type/kfree_type functions require special compiler
		 * handling to assign the type to a zone, which is not supported
		 * in the test code environment.
		 */
		free(entry);
	}
}

// Tests for nested_space_map_block.
extern hv_return_t
nested_space_map_block(uint64_t* size, uint64_t start_offset, upl_page_info_t* physical_memory_info, uint64_t ipa, uint64_t vmid, uint64_t flags);

T_DECL(nested_space_map_block_contiguous, "test nested_space_map_block with contiguous pages")
{
	uint64_t size = 4 * PAGE_SIZE;

	enqueue_upl_phys_page_call(((upl_phys_page_call){
		.expected_page_index = 0,
		.return_val = 0xa001,
	}));
	enqueue_upl_phys_page_call(((upl_phys_page_call){
		.expected_page_index = 1,
		.return_val = 0xa002,
	}));
	enqueue_upl_phys_page_call(((upl_phys_page_call){
		.expected_page_index = 2,
		.return_val = 0xa003,
	}));
	enqueue_upl_phys_page_call(((upl_phys_page_call){
		.expected_page_index = 3,
		.return_val = 0xa004,
	}));

	enqueue_hv_call_call(((hv_call_call) {
		.expected_fn = VMAPPLE_NESTED_SPACE_MAP,
		.expected_arg0 = 0x42, // Non-zero ASID
		.expected_arg1 = ptoa(0xa001),
		.expected_arg3 = 4 * PAGE_SIZE,
		.expected_arg4 = HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC,
		.ret = HV_SUCCESS,
	}));

	hv_return_t map_return = nested_space_map_block(&size, 0, kTestUplInternalPageMockPointer, 0, 0x42, HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC);
	T_EXPECT_EQ(map_return, HV_SUCCESS, "Valid map");
	T_EXPECT_EQ(size, (uint64_t)(4 * PAGE_SIZE), "Size should be unchanged on success");
	test_teardown_assert_queues_empty();
}

T_DECL(nested_space_map_block_non_contiguous, "test nested_space_map_block with non-contiguous pages")
{
	uint64_t size = 4 * PAGE_SIZE;

	// Contiguous block of 2 pages
	enqueue_upl_phys_page_call(((upl_phys_page_call){ .expected_page_index = 0, .return_val = 0xa001, }));
	enqueue_upl_phys_page_call(((upl_phys_page_call){ .expected_page_index = 1, .return_val = 0xa002, }));
	// Non-contiguous page
	enqueue_upl_phys_page_call(((upl_phys_page_call){ .expected_page_index = 2, .return_val = 0xb001, }));
	// Contiguous page to the previous one
	enqueue_upl_phys_page_call(((upl_phys_page_call){ .expected_page_index = 3, .return_val = 0xb002, }));

	// First hv_call for the first contiguous block
	enqueue_hv_call_call(((hv_call_call) {
		.expected_fn = VMAPPLE_NESTED_SPACE_MAP,
		.expected_arg0 = 0x123, // Different non-zero ASID
		.expected_arg1 = ptoa(0xa001),
		.expected_arg3 = 2 * PAGE_SIZE,
		.expected_arg4 = HV_MEMORY_READ | HV_MEMORY_EXEC,
		.ret = HV_SUCCESS,
	}));

	// Second hv_call for the second contiguous block
	enqueue_hv_call_call(((hv_call_call) {
		.expected_fn = VMAPPLE_NESTED_SPACE_MAP,
		.expected_arg0 = 0x123, // Same ASID
		.expected_arg1 = ptoa(0xb001),
		.expected_arg2 = 2 * PAGE_SIZE,
		.expected_arg3 = 2 * PAGE_SIZE,
		.expected_arg4 = HV_MEMORY_READ | HV_MEMORY_EXEC,
		.ret = HV_SUCCESS,
	}));

	hv_return_t map_return = nested_space_map_block(&size, 0, kTestUplInternalPageMockPointer, 0, 0x123, HV_MEMORY_READ | HV_MEMORY_EXEC);
	T_EXPECT_EQ(map_return, HV_SUCCESS, "Valid map");
	T_EXPECT_EQ(size, (uint64_t)(4 * PAGE_SIZE), "Size should be unchanged on success");
	test_teardown_assert_queues_empty();
}

T_DECL(nested_space_map_block_upl_error_first, "test nested_space_map_block with upl_phys_page error on first page")
{
	uint64_t size = 4 * PAGE_SIZE;

	enqueue_upl_phys_page_call(((upl_phys_page_call){
		.expected_page_index = 0,
		.return_val = 0, // Error
	}));

	hv_return_t map_return = nested_space_map_block(&size, 0, kTestUplInternalPageMockPointer, 0, 0, 0);
	T_EXPECT_EQ(map_return, HV_ERROR, "Map should fail");
	T_EXPECT_EQ(size, (uint64_t)0, "Size should be 0 on failure");
	test_teardown_assert_queues_empty();
}

T_DECL(nested_space_map_block_upl_error_middle, "test nested_space_map_block with upl_phys_page error in the middle")
{
	uint64_t size = 4 * PAGE_SIZE;

	enqueue_upl_phys_page_call(((upl_phys_page_call){ .expected_page_index = 0, .return_val = 0xa001, }));
	enqueue_upl_phys_page_call(((upl_phys_page_call){ .expected_page_index = 1, .return_val = 0, })); // Error

	// No hv_call should be made because the first block isn't "finished" by a non-contiguous page or the end of the list
	hv_return_t map_return = nested_space_map_block(&size, 0, kTestUplInternalPageMockPointer, 0, 0, 0);
	T_EXPECT_EQ(map_return, HV_ERROR, "Map should fail");
	T_EXPECT_EQ(size, (uint64_t)0, "Size should be the size of successfully mapped blocks");
	test_teardown_assert_queues_empty();
}

T_DECL(nested_space_map_block_hv_call_error_middle, "test nested_space_map_block with hv_call error in the middle")
{
	uint64_t size = 4 * PAGE_SIZE;

	enqueue_upl_phys_page_call(((upl_phys_page_call){ .expected_page_index = 0, .return_val = 0xa001, }));
	enqueue_upl_phys_page_call(((upl_phys_page_call){ .expected_page_index = 1, .return_val = 0xb001, }));
	enqueue_upl_phys_page_call(((upl_phys_page_call){ .expected_page_index = 2, .return_val = 0xc001, }));

	enqueue_hv_call_call(((hv_call_call) {
		.expected_fn = VMAPPLE_NESTED_SPACE_MAP,
		.expected_arg1 = ptoa(0xa001),
		.expected_arg2 = 0xA0000,
		.expected_arg3 = 1 * PAGE_SIZE,
		.ret = HV_SUCCESS,
	}));
	enqueue_hv_call_call(((hv_call_call) {
		.expected_fn = VMAPPLE_NESTED_SPACE_MAP,
		.expected_arg1 = ptoa(0xb001),
		.expected_arg2 = 0xA0000 + PAGE_SIZE,
		.expected_arg3 = 1 * PAGE_SIZE,
		.ret = HV_DENIED, // Error
	}));

	hv_return_t map_return = nested_space_map_block(&size, 0, kTestUplInternalPageMockPointer, 0xA0000, 0, 0);
	T_EXPECT_EQ(map_return, HV_DENIED, "Map should fail");
	T_EXPECT_EQ(size, (uint64_t)(PAGE_SIZE), "Size should be of previously mapped blocks");
	test_teardown_assert_queues_empty();
}

T_DECL(nested_space_map_block_hv_call_error_final, "test nested_space_map_block with hv_call error on final block")
{
	uint64_t size = 2 * PAGE_SIZE;

	enqueue_upl_phys_page_call(((upl_phys_page_call){ .expected_page_index = 0, .return_val = 0xa001, }));
	enqueue_upl_phys_page_call(((upl_phys_page_call){ .expected_page_index = 1, .return_val = 0xb001, })); // non-contiguous

	enqueue_hv_call_call(((hv_call_call) {
		.expected_fn = VMAPPLE_NESTED_SPACE_MAP,
		.expected_arg1 = ptoa(0xa001),
		.expected_arg2 = 0xc0000,
		.expected_arg3 = 1 * PAGE_SIZE,
		.ret = HV_SUCCESS,
	}));
	enqueue_hv_call_call(((hv_call_call) {
		.expected_fn = VMAPPLE_NESTED_SPACE_MAP,
		.expected_arg1 = ptoa(0xb001),
		.expected_arg2 = 0xc0000 + PAGE_SIZE,
		.expected_arg3 = 1 * PAGE_SIZE,
		.ret = HV_NO_RESOURCES, // Error
	}));

	hv_return_t map_return = nested_space_map_block(&size, 0, kTestUplInternalPageMockPointer, 0xc0000, 0, 0);
	T_EXPECT_EQ(map_return, HV_NO_RESOURCES, "Map should fail");
	T_EXPECT_EQ(size, (uint64_t)(PAGE_SIZE), "Size should be of previously mapped blocks");
	test_teardown_assert_queues_empty();
}

T_DECL(nested_space_map_block_single_page, "test nested_space_map_block with a single page")
{
	uint64_t size = 1 * PAGE_SIZE;

	enqueue_upl_phys_page_call(((upl_phys_page_call){
		.expected_page_index = 0,
		.return_val = 0xa001,
	}));

	enqueue_hv_call_call(((hv_call_call) {
		.expected_fn = VMAPPLE_NESTED_SPACE_MAP,
		.expected_arg1 = ptoa(0xa001),
		.expected_arg3 = 1 * PAGE_SIZE,
		.ret = HV_SUCCESS,
	}));

	hv_return_t map_return = nested_space_map_block(&size, 0, kTestUplInternalPageMockPointer, 0, 0, 0);
	T_EXPECT_EQ(map_return, HV_SUCCESS, "Valid map");
	T_EXPECT_EQ(size, (uint64_t)(PAGE_SIZE), "Size should be unchanged on success");
	test_teardown_assert_queues_empty();
}

T_DECL(nested_space_map_block_panic, "test nested_space_map_block panics")
{
	uint64_t size = PAGE_SIZE;
	T_ASSERT_PANIC({nested_space_map_block(NULL, 0, kTestUplInternalPageMockPointer, 0, 0, 0);},
	    "Should panic on null size");

	size = 0;
	T_ASSERT_PANIC({nested_space_map_block(&size, 0, kTestUplInternalPageMockPointer, 0, 0, 0);},
	    "Should panic on zero size");

	size = PAGE_SIZE;
	T_ASSERT_PANIC({nested_space_map_block(&size, 0, NULL, 0, 0, 0);},
	    "Should panic on null physical_memory_info");

	// Test invalid start_offset (>= PAGE_SIZE should panic)
	size = PAGE_SIZE;
	T_ASSERT_PANIC({nested_space_map_block(&size, PAGE_SIZE, kTestUplInternalPageMockPointer, 0, 0, 0);},
	    "Should panic on start_offset >= PAGE_SIZE");
}

T_DECL(nested_space_map_block_max_start_offset, "test nested_space_map_block with maximum start_offset")
{
	// Test with start_offset = PAGE_SIZE - 1 (last byte of first page)
	uint64_t size = 2 * PAGE_SIZE;
	uint64_t start_offset = PAGE_SIZE - 1; // Maximum valid offset

	// First page contributes only 1 byte, second page contributes full PAGE_SIZE
	// Third page contributes remaining (PAGE_SIZE - 1) bytes
	enqueue_upl_phys_page_call(((upl_phys_page_call){ .expected_page_index = 0, .return_val = 0xa001, }));
	enqueue_upl_phys_page_call(((upl_phys_page_call){ .expected_page_index = 1, .return_val = 0xa002, }));
	enqueue_upl_phys_page_call(((upl_phys_page_call){ .expected_page_index = 2, .return_val = 0xa003, }));

	// Expected hypervisor call should map all 3 contiguous pages as one chunk
	enqueue_hv_call_call(((hv_call_call) {
		.expected_fn = VMAPPLE_NESTED_SPACE_MAP,
		.expected_arg0 = 0xDEF,
		.expected_arg1 = ptoa(0xa001) + start_offset, // Physical address with max offset
		.expected_arg2 = 0x80000, // IPA
		.expected_arg3 = 2 * PAGE_SIZE, // Total size to map
		.expected_arg4 = HV_MEMORY_READ,
		.ret = HV_SUCCESS,
	}));

	hv_return_t map_return = nested_space_map_block(&size, start_offset, kTestUplInternalPageMockPointer, 0x80000, 0xDEF, HV_MEMORY_READ);
	T_EXPECT_EQ(map_return, HV_SUCCESS, "Valid map with maximum start_offset");
	T_EXPECT_EQ(size, (uint64_t)(2 * PAGE_SIZE), "Size should be unchanged on success");
	test_teardown_assert_queues_empty();
}

T_DECL(nested_space_map_block_one_byte, "test nested_space_map_block with 1-byte size")
{
	// Test mapping exactly 1 byte starting from middle of a page
	uint64_t size = 1;
	uint64_t start_offset = 0x800; // Start halfway through first page

	// Only need first page since we're mapping just 1 byte
	enqueue_upl_phys_page_call(((upl_phys_page_call){ .expected_page_index = 0, .return_val = 0xb001, }));

	// Expected hypervisor call should map just 1 byte
	enqueue_hv_call_call(((hv_call_call) {
		.expected_fn = VMAPPLE_NESTED_SPACE_MAP,
		.expected_arg0 = 0x999,
		.expected_arg1 = ptoa(0xb001) + start_offset, // Physical address with offset
		.expected_arg2 = 0x90000, // IPA
		.expected_arg3 = 1, // Map exactly 1 byte
		.expected_arg4 = HV_MEMORY_WRITE | HV_MEMORY_EXEC,
		.ret = HV_SUCCESS,
	}));

	hv_return_t map_return = nested_space_map_block(&size, start_offset, kTestUplInternalPageMockPointer, 0x90000, 0x999, HV_MEMORY_WRITE | HV_MEMORY_EXEC);
	T_EXPECT_EQ(map_return, HV_SUCCESS, "Valid map of 1 byte");
	T_EXPECT_EQ(size, (uint64_t)1, "Size should be unchanged on success");
	test_teardown_assert_queues_empty();
}

T_DECL(nested_space_map_block_alternating_invalid, "test nested_space_map_block with alternating valid/invalid pages")
{
	// Test pattern: valid, non-contiguous valid, invalid - forces hypervisor call then fails
	uint64_t size = 4 * PAGE_SIZE;

	// Set up pattern where first page maps alone, second is non-contiguous (triggers hv_call), third is invalid
	enqueue_upl_phys_page_call(((upl_phys_page_call){ .expected_page_index = 0, .return_val = 0xa001, })); // Valid
	enqueue_upl_phys_page_call(((upl_phys_page_call){ .expected_page_index = 1, .return_val = 0xb001, })); // Valid, non-contiguous
	enqueue_upl_phys_page_call(((upl_phys_page_call){ .expected_page_index = 2, .return_val = 0, }));      // Invalid - causes failure

	// Should make one hypervisor call for the first page, then fail on third invalid page
	enqueue_hv_call_call(((hv_call_call) {
		.expected_fn = VMAPPLE_NESTED_SPACE_MAP,
		.expected_arg0 = 0x777,
		.expected_arg1 = ptoa(0xa001),
		.expected_arg2 = 0xA0000,
		.expected_arg3 = PAGE_SIZE, // First page gets mapped alone
		.expected_arg4 = HV_MEMORY_EXEC,
		.ret = HV_SUCCESS,
	}));

	hv_return_t map_return = nested_space_map_block(&size, 0, kTestUplInternalPageMockPointer, 0xA0000, 0x777, HV_MEMORY_EXEC);
	T_EXPECT_EQ(map_return, HV_ERROR, "Should fail on invalid third page");
	T_EXPECT_EQ(size, (uint64_t)(PAGE_SIZE), "Size should reflect successfully mapped portion");
	test_teardown_assert_queues_empty();
}

T_DECL(nested_space_map_block_mixed_contiguous, "test nested_space_map_block with mixed contiguous and non-contiguous pages")
{
	uint64_t size = 5 * PAGE_SIZE;

	// 1. Contiguous block of 2 pages
	enqueue_upl_phys_page_call(((upl_phys_page_call){ .expected_page_index = 0, .return_val = 0xa001, }));
	enqueue_upl_phys_page_call(((upl_phys_page_call){ .expected_page_index = 1, .return_val = 0xa002, }));
	// 2. Non-contiguous page
	enqueue_upl_phys_page_call(((upl_phys_page_call){ .expected_page_index = 2, .return_val = 0xb001, }));
	// 3. Contiguous block of 2 pages
	enqueue_upl_phys_page_call(((upl_phys_page_call){ .expected_page_index = 3, .return_val = 0xc001, }));
	enqueue_upl_phys_page_call(((upl_phys_page_call){ .expected_page_index = 4, .return_val = 0xc002, }));

	// First hv_call for the first contiguous block
	enqueue_hv_call_call(((hv_call_call) {
		.expected_fn = VMAPPLE_NESTED_SPACE_MAP,
		.expected_arg1 = ptoa(0xa001),
		.expected_arg3 = 2 * PAGE_SIZE,
		.ret = HV_SUCCESS,
	}));

	// Second hv_call for the non-contiguous page
	enqueue_hv_call_call(((hv_call_call) {
		.expected_fn = VMAPPLE_NESTED_SPACE_MAP,
		.expected_arg1 = ptoa(0xb001),
		.expected_arg2 = 2 * PAGE_SIZE,
		.expected_arg3 = 1 * PAGE_SIZE,
		.ret = HV_SUCCESS,
	}));

	// Third hv_call for the second contiguous block
	enqueue_hv_call_call(((hv_call_call) {
		.expected_fn = VMAPPLE_NESTED_SPACE_MAP,
		.expected_arg1 = ptoa(0xc001),
		.expected_arg2 = 3 * PAGE_SIZE,
		.expected_arg3 = 2 * PAGE_SIZE,
		.ret = HV_SUCCESS,
	}));

	hv_return_t map_return = nested_space_map_block(&size, 0, kTestUplInternalPageMockPointer, 0, 0, 0);
	T_EXPECT_EQ(map_return, HV_SUCCESS, "Valid map");
	T_EXPECT_EQ(size, (uint64_t)(5 * PAGE_SIZE), "Size should be unchanged on success");
	test_teardown_assert_queues_empty();
}

T_DECL(nested_space_map_block_with_start_offset, "test nested_space_map_block with non-zero start_offset")
{
	uint64_t size = 3 * PAGE_SIZE;
	uint64_t start_offset = 0x1000; // 4KB offset within first page

	// Set up pages - we need part of 4 pages to cover 3*PAGE_SIZE with start_offset
	// First page contributes (PAGE_SIZE - 0x1000) = 0x3000 bytes
	// Second and third pages contribute full PAGE_SIZE each = 2*PAGE_SIZE
	// Fourth page contributes remaining 0x1000 bytes
	enqueue_upl_phys_page_call(((upl_phys_page_call){ .expected_page_index = 0, .return_val = 0xa001, }));
	enqueue_upl_phys_page_call(((upl_phys_page_call){ .expected_page_index = 1, .return_val = 0xa002, }));
	enqueue_upl_phys_page_call(((upl_phys_page_call){ .expected_page_index = 2, .return_val = 0xa003, }));
	enqueue_upl_phys_page_call(((upl_phys_page_call){ .expected_page_index = 3, .return_val = 0xa004, }));

	// Expected hypervisor call should map all 4 contiguous pages as one chunk
	enqueue_hv_call_call(((hv_call_call) {
		.expected_fn = VMAPPLE_NESTED_SPACE_MAP,
		.expected_arg1 = ptoa(0xa001) + start_offset, // Physical address with offset
		.expected_arg2 = 0x50000, // IPA
		.expected_arg3 = 3 * PAGE_SIZE, // Total size to map
		.ret = HV_SUCCESS,
	}));

	hv_return_t map_return = nested_space_map_block(&size, start_offset, kTestUplInternalPageMockPointer, 0x50000, 0, 0);
	T_EXPECT_EQ(map_return, HV_SUCCESS, "Valid map with start_offset");
	T_EXPECT_EQ(size, (uint64_t)(3 * PAGE_SIZE), "Size should be unchanged on success");
	test_teardown_assert_queues_empty();
}

T_DECL(nested_space_map_block_unaligned_end, "test nested_space_map_block with unaligned ending address")
{
	// Map 2.5 pages (2*PAGE_SIZE + 0x2000) starting from aligned address
	uint64_t size = 2 * PAGE_SIZE + 0x2000; // Ends 0x2000 bytes into the third page
	uint64_t start_offset = 0;

	// Set up pages - we need 3 pages to cover this unaligned size
	// First page contributes full PAGE_SIZE
	// Second page contributes full PAGE_SIZE
	// Third page contributes 0x2000 bytes
	enqueue_upl_phys_page_call(((upl_phys_page_call){ .expected_page_index = 0, .return_val = 0xa001, }));
	enqueue_upl_phys_page_call(((upl_phys_page_call){ .expected_page_index = 1, .return_val = 0xa002, }));
	enqueue_upl_phys_page_call(((upl_phys_page_call){ .expected_page_index = 2, .return_val = 0xa003, }));

	// Expected hypervisor call should map all 3 contiguous pages as one chunk
	enqueue_hv_call_call(((hv_call_call) {
		.expected_fn = VMAPPLE_NESTED_SPACE_MAP,
		.expected_arg1 = ptoa(0xa001), // Physical address aligned
		.expected_arg2 = 0x60000, // IPA
		.expected_arg3 = 2 * PAGE_SIZE + 0x2000, // Total unaligned size to map
		.ret = HV_SUCCESS,
	}));

	hv_return_t map_return = nested_space_map_block(&size, start_offset, kTestUplInternalPageMockPointer, 0x60000, 0, 0);
	T_EXPECT_EQ(map_return, HV_SUCCESS, "Valid map with unaligned end");
	T_EXPECT_EQ(size, (uint64_t)(2 * PAGE_SIZE + 0x2000), "Size should be unchanged on success");
	test_teardown_assert_queues_empty();
}

T_DECL(nested_space_map_block_unaligned_both, "test nested_space_map_block with unaligned start and end")
{
	// Map 2*PAGE_SIZE starting from 0x1000 offset
	// This needs only 3 pages total: part of first, full second, part of third
	uint64_t size = 2 * PAGE_SIZE;
	uint64_t start_offset = 0x1000; // Start 4KB into first page

	// Set up pages - we need 3 pages to cover this range
	// First page contributes (PAGE_SIZE - 0x1000) = 0x3000 bytes
	// Second page contributes full PAGE_SIZE
	// Third page contributes remaining 0x1000 bytes
	enqueue_upl_phys_page_call(((upl_phys_page_call){ .expected_page_index = 0, .return_val = 0xa001, }));
	enqueue_upl_phys_page_call(((upl_phys_page_call){ .expected_page_index = 1, .return_val = 0xa002, }));
	enqueue_upl_phys_page_call(((upl_phys_page_call){ .expected_page_index = 2, .return_val = 0xa003, }));

	// Expected hypervisor call should map all 3 contiguous pages as one chunk
	enqueue_hv_call_call(((hv_call_call) {
		.expected_fn = VMAPPLE_NESTED_SPACE_MAP,
		.expected_arg0 = 0xABC, // Another different non-zero ASID
		.expected_arg1 = ptoa(0xa001) + start_offset, // Physical address with start offset
		.expected_arg2 = 0x70000, // IPA
		.expected_arg3 = 2 * PAGE_SIZE, // Total size to map
		.expected_arg4 = HV_MEMORY_READ | HV_MEMORY_WRITE,
		.ret = HV_SUCCESS,
	}));

	hv_return_t map_return = nested_space_map_block(&size, start_offset, kTestUplInternalPageMockPointer, 0x70000, 0xABC, HV_MEMORY_READ | HV_MEMORY_WRITE);
	T_EXPECT_EQ(map_return, HV_SUCCESS, "Valid map with unaligned start and end");
	T_EXPECT_EQ(size, (uint64_t)(2 * PAGE_SIZE), "Size should be unchanged on success");
	test_teardown_assert_queues_empty();
}

// Tests for _hv_nested_space_map.
extern hv_return_t
_hv_nested_space_map(hv_vm_t* vm, const hv_vm_map_item_t *mi);

T_DECL(nested_space_map_simple, "test _hv_nested_space_map with a simple map")
{
	// Setup
	lck_grp_t grp;
	lck_grp_init(&grp, "test_mutex", LCK_GRP_ATTR_NULL);
	lck_mtx_t mtx;
	lck_mtx_init(&mtx, &grp, LCK_ATTR_NULL);
	hv_vm_t vm = {
		.mtx = &mtx,
		.host_vm_id = 0x42,
	};
	LIST_INIT(&vm.map_list_head);

	const uint64_t MAP_SIZE = 2 * PAGE_SIZE;
	hv_vm_map_item_t mi = {
		.uva = 0x10000,
		.ipa = 0x20000,
		.size = MAP_SIZE,
		.flags = 0,
	};

	enqueue_vm_map_create_upl_call(((vm_map_create_upl_call) {
		.expected_map = current_thread()->map,
		.expected_offset = mi.uva,
		.expected_upl_size_in = MAP_SIZE,
		.mock_upl_size_out = MAP_SIZE,
		.mock_upl_out = kTestUplMockPointer,
		.mock_count_out = 1,
		.expected_flags = UPL_SET_INTERNAL | UPL_SET_IO_WIRE,
		.expected_tag = VM_KERN_MEMORY_HV,
		.ret = KERN_SUCCESS,
	}));

	enqueue_upl_phys_page_call(((upl_phys_page_call){ .expected_page_index = 0, .return_val = 0xa001, }));
	enqueue_upl_phys_page_call(((upl_phys_page_call){ .expected_page_index = 1, .return_val = 0xa002, }));

	enqueue_hv_call_call(((hv_call_call) {
		.expected_fn = VMAPPLE_NESTED_SPACE_MAP,
		.expected_arg0 = vm.host_vm_id,
		.expected_arg1 = ptoa(0xa001),
		.expected_arg2 = mi.ipa,
		.expected_arg3 = MAP_SIZE,
		.expected_arg4 = mi.flags,
		.ret = HV_SUCCESS,
	}));

	// Execution
	hv_return_t ret = _hv_nested_space_map(&vm, &mi);

	// Verification
	T_EXPECT_EQ(ret, HV_SUCCESS, "_hv_nested_space_map should succeed");
	T_EXPECT_FALSE(LIST_EMPTY(&vm.map_list_head), "map list should not be empty");
	hv_map_entry_t* entry = LIST_FIRST(&vm.map_list_head);
	T_EXPECT_EQ((uintptr_t)entry->upl, (uintptr_t)kTestUplMockPointer, "upl should be stored in map entry");
	T_EXPECT_EQ(entry->size, MAP_SIZE, "size should be stored in map entry");
	T_EXPECT_EQ(entry->ipa, mi.ipa, "ipa should be stored in map entry");

	test_cleanup_vm(&vm);
	test_teardown_assert_queues_empty();

	lck_mtx_destroy(&mtx, &grp);
}

T_DECL(nested_space_map_invalid_args, "test _hv_nested_space_map with invalid arguments")
{
	// Setup
	lck_grp_t grp;
	lck_grp_init(&grp, "test_mutex", LCK_GRP_ATTR_NULL);
	lck_mtx_t mtx;
	lck_mtx_init(&mtx, &grp, LCK_ATTR_NULL);
	hv_vm_t vm = {
		.mtx = &mtx,
		.host_vm_id = 0x42,
	};
	LIST_INIT(&vm.map_list_head);

	const uint64_t MAP_SIZE = 2 * PAGE_SIZE;
	hv_vm_map_item_t mi = {
		.uva = 0x10000,
		.ipa = 0x20000,
		.size = MAP_SIZE,
		.flags = 0,
	};

	// uva overflow
	mi.uva = UINT64_MAX - PAGE_SIZE;
	T_EXPECT_EQ(_hv_nested_space_map(&vm, &mi), HV_BAD_ARGUMENT, "should fail with uva overflow");
	mi.uva = 0x10000;

	// ipa overflow
	mi.ipa = UINT64_MAX - PAGE_SIZE;
	T_EXPECT_EQ(_hv_nested_space_map(&vm, &mi), HV_BAD_ARGUMENT, "should fail with ipa overflow");
	mi.ipa = 0x20000;

	test_cleanup_vm(&vm);
	test_teardown_assert_queues_empty();
	lck_mtx_destroy(&mtx, &grp);
}

T_DECL(nested_space_map_zero_size, "test _hv_nested_space_map with zero size")
{
	// Setup
	lck_grp_t grp;
	lck_grp_init(&grp, "test_mutex", LCK_GRP_ATTR_NULL);
	lck_mtx_t mtx;
	lck_mtx_init(&mtx, &grp, LCK_ATTR_NULL);
	hv_vm_t vm = {
		.mtx = &mtx,
		.host_vm_id = 0x42,
	};
	LIST_INIT(&vm.map_list_head);

	hv_vm_map_item_t mi = {
		.uva = 0x10000,
		.ipa = 0x20000,
		.size = 0,
		.flags = 0,
	};

	// Execution
	hv_return_t ret = _hv_nested_space_map(&vm, &mi);

	// Verification
	T_EXPECT_EQ(ret, HV_SUCCESS, "_hv_nested_space_map should succeed with zero size");
	T_EXPECT_TRUE(LIST_EMPTY(&vm.map_list_head), "map list should be empty");

	test_cleanup_vm(&vm);
	test_teardown_assert_queues_empty();
	lck_mtx_destroy(&mtx, &grp);
}

T_DECL(nested_space_map_vm_map_create_upl_fails, "test _hv_nested_space_map when vm_map_create_upl fails")
{
	// Setup
	lck_grp_t grp;
	lck_grp_init(&grp, "test_mutex", LCK_GRP_ATTR_NULL);
	lck_mtx_t mtx;
	lck_mtx_init(&mtx, &grp, LCK_ATTR_NULL);
	hv_vm_t vm = {
		.mtx = &mtx,
		.host_vm_id = 0x42,
	};
	LIST_INIT(&vm.map_list_head);

	const uint64_t MAP_SIZE = 2 * PAGE_SIZE;
	hv_vm_map_item_t mi = {
		.uva = 0x10000,
		.ipa = 0x20000,
		.size = MAP_SIZE,
		.flags = 0,
	};

	enqueue_vm_map_create_upl_call(((vm_map_create_upl_call) {
		.expected_map = current_thread()->map,
		.expected_offset = mi.uva,
		.expected_upl_size_in = MAP_SIZE,
		.expected_flags = UPL_SET_INTERNAL | UPL_SET_IO_WIRE,
		.expected_tag = VM_KERN_MEMORY_HV,
		.ret = KERN_RESOURCE_SHORTAGE,
	}));

	// Execution
	hv_return_t ret = _hv_nested_space_map(&vm, &mi);

	// Verification
	T_EXPECT_EQ(ret, HV_ERROR, "_hv_nested_space_map should fail");
	T_EXPECT_TRUE(LIST_EMPTY(&vm.map_list_head), "map list should be empty");

	test_cleanup_vm(&vm);
	test_teardown_assert_queues_empty();
	lck_mtx_destroy(&mtx, &grp);
}

T_DECL(hv_nested_space_map_nested_space_map_block_fails, "test _hv_nested_space_map when nested_space_map_block fails")
{
	// Setup
	lck_grp_t grp;
	lck_grp_init(&grp, "test_mutex", LCK_GRP_ATTR_NULL);
	lck_mtx_t mtx;
	lck_mtx_init(&mtx, &grp, LCK_ATTR_NULL);
	hv_vm_t vm = {
		.mtx = &mtx,
		.host_vm_id = 0x42,
	};
	LIST_INIT(&vm.map_list_head);

	const uint64_t MAP_SIZE = 4 * PAGE_SIZE;
	hv_vm_map_item_t mi = {
		.uva = 0x10000,
		.ipa = 0x20000,
		.size = MAP_SIZE,
		.flags = 0,
	};

	enqueue_vm_map_create_upl_call(((vm_map_create_upl_call) {
		.expected_map = current_thread()->map,
		.expected_offset = mi.uva,
		.expected_upl_size_in = MAP_SIZE,
		.mock_upl_size_out = MAP_SIZE,
		.mock_upl_out = kTestUplMockPointer,
		.mock_count_out = 1,
		.expected_flags = UPL_SET_INTERNAL | UPL_SET_IO_WIRE,
		.expected_tag = VM_KERN_MEMORY_HV,
		.ret = KERN_SUCCESS,
	}));

	// Make nested_space_map_block fail after mapping the first page.
	enqueue_upl_phys_page_call(((upl_phys_page_call){ .expected_page_index = 0, .return_val = 0xa001, }));
	enqueue_upl_phys_page_call(((upl_phys_page_call){ .expected_page_index = 1, .return_val = 0xa003, }));
	enqueue_upl_phys_page_call(((upl_phys_page_call){ .expected_page_index = 2, .return_val = 0, })); // Error

	// Expect a call to map the first page.
	enqueue_hv_call_call(((hv_call_call) {
		.expected_fn = VMAPPLE_NESTED_SPACE_MAP,
		.expected_arg0 = vm.host_vm_id,
		.expected_arg1 = ptoa(0xa001),
		.expected_arg2 = mi.ipa,
		.expected_arg3 = PAGE_SIZE,
		.expected_arg4 = mi.flags,
		.ret = HV_SUCCESS,
	}));

	// Expect a call to unmap the partially mapped region.
	enqueue_hv_call_call(((hv_call_call) {
		.expected_fn = VMAPPLE_NESTED_SPACE_UNMAP,
		.expected_arg0 = vm.host_vm_id,
		.expected_arg1 = mi.ipa,
		.expected_arg2 = PAGE_SIZE,
		.ret = HV_SUCCESS,
	}));

	enqueue_ubc_upl_commit_call(((ubc_upl_commit_call) {
		.expected_upl = kTestUplMockPointer,
		.ret = 0,
	}));

	// Execution
	hv_return_t ret = _hv_nested_space_map(&vm, &mi);

	// Verification
	T_EXPECT_EQ(ret, HV_ERROR, "_hv_nested_space_map should fail");
	T_EXPECT_TRUE(LIST_EMPTY(&vm.map_list_head), "map list should be empty");

	test_cleanup_vm(&vm);
	test_teardown_assert_queues_empty();
	lck_mtx_destroy(&mtx, &grp);
}

T_DECL(hv_nested_space_map_large_map, "test _hv_nested_space_map with a large map that requires chunking")
{
	// Setup
	lck_grp_t grp;
	lck_grp_init(&grp, "test_mutex", LCK_GRP_ATTR_NULL);
	lck_mtx_t mtx;
	lck_mtx_init(&mtx, &grp, LCK_ATTR_NULL);
	hv_vm_t vm = {
		.mtx = &mtx,
		.host_vm_id = 0x42,
	};
	LIST_INIT(&vm.map_list_head);

	const uint64_t MAP_SIZE = (uint64_t)UPL_SIZE_MAX + PAGE_SIZE;
	hv_vm_map_item_t mi = {
		.uva = 0x10000,
		.ipa = 0x20000,
		.size = MAP_SIZE,
		.flags = 0,
	};

	// First chunk
	enqueue_vm_map_create_upl_call(((vm_map_create_upl_call) {
		.expected_map = current_thread()->map,
		.expected_offset = mi.uva,
		.expected_upl_size_in = UPL_SIZE_MAX,
		.mock_upl_size_out = UPL_SIZE_MAX,
		.mock_upl_out = kTestUplMockPointer1,
		.mock_count_out = 1,
		.expected_flags = UPL_SET_INTERNAL | UPL_SET_IO_WIRE,
		.expected_tag = VM_KERN_MEMORY_HV,
		.ret = KERN_SUCCESS,
	}));
	// Mocking pages for the first chunk
	for (uint64_t i = 0; i < UPL_SIZE_MAX / PAGE_SIZE; i++) {
		enqueue_upl_phys_page_call(((upl_phys_page_call){ .expected_page_index = (int)i, .return_val = (ppnum_t)(0xa001 + i), }));
	}
	enqueue_hv_call_call(((hv_call_call) {
		.expected_fn = VMAPPLE_NESTED_SPACE_MAP,
		.expected_arg0 = vm.host_vm_id,
		.expected_arg1 = ptoa(0xa001),
		.expected_arg2 = mi.ipa,
		.expected_arg3 = UPL_SIZE_MAX,
		.expected_arg4 = mi.flags,
		.ret = HV_SUCCESS,
	}));

	// Second chunk
	enqueue_vm_map_create_upl_call(((vm_map_create_upl_call) {
		.expected_map = current_thread()->map,
		.expected_offset = mi.uva + UPL_SIZE_MAX,
		.expected_upl_size_in = PAGE_SIZE,
		.mock_upl_size_out = PAGE_SIZE,
		.mock_upl_out = kTestUplMockPointer2,
		.mock_count_out = 1,
		.expected_flags = UPL_SET_INTERNAL | UPL_SET_IO_WIRE,
		.expected_tag = VM_KERN_MEMORY_HV,
		.ret = KERN_SUCCESS,
	}));
	enqueue_upl_phys_page_call(((upl_phys_page_call){ .expected_page_index = 0, .return_val = 0xb001, }));
	enqueue_hv_call_call(((hv_call_call) {
		.expected_fn = VMAPPLE_NESTED_SPACE_MAP,
		.expected_arg0 = vm.host_vm_id,
		.expected_arg1 = ptoa(0xb001),
		.expected_arg2 = mi.ipa + UPL_SIZE_MAX,
		.expected_arg3 = PAGE_SIZE,
		.expected_arg4 = mi.flags,
		.ret = HV_SUCCESS,
	}));

	// Execution
	hv_return_t ret = _hv_nested_space_map(&vm, &mi);

	// Verification
	T_EXPECT_EQ(ret, HV_SUCCESS, "_hv_nested_space_map should succeed");

	T_EXPECT_FALSE(LIST_EMPTY(&vm.map_list_head), "map list should not be empty");
	hv_map_entry_t* entry = LIST_FIRST(&vm.map_list_head);
	T_EXPECT_EQ((uintptr_t)entry->upl, (uintptr_t)kTestUplMockPointer1, "upl of first chunk should be stored in map entry");
	T_EXPECT_EQ(entry->size, (uint64_t)UPL_SIZE_MAX, "size of first chunk should be stored in map entry");
	T_EXPECT_EQ(entry->ipa, mi.ipa, "ipa of first chunk should be stored in map entry");
	entry = LIST_NEXT(entry, entry_link);
	T_EXPECT_EQ((uintptr_t)entry->upl, (uintptr_t)kTestUplMockPointer2, "upl of second chunk should be stored in map entry");
	T_EXPECT_EQ(entry->size, (uint64_t)(PAGE_SIZE), "size of second chunk should be stored in map entry");
	T_EXPECT_EQ(entry->ipa, mi.ipa + UPL_SIZE_MAX, "ipa of second chunk should be stored in map entry");

	test_cleanup_vm(&vm);
	test_teardown_assert_queues_empty();

	lck_mtx_destroy(&mtx, &grp);
}

T_DECL(nested_space_map_vm_map_create_upl_fails_second_chunk, "test _hv_nested_space_map when second vm_map_create_upl fails with rollback")
{
	// Setup
	lck_grp_t grp;
	lck_grp_init(&grp, "test_mutex", LCK_GRP_ATTR_NULL);
	lck_mtx_t mtx;
	lck_mtx_init(&mtx, &grp, LCK_ATTR_NULL);
	hv_vm_t vm = {
		.mtx = &mtx,
		.host_vm_id = 0x555,
	};
	LIST_INIT(&vm.map_list_head);

	// Test chunking where first chunk succeeds but second fails
	const uint64_t map_size = 4 * PAGE_SIZE;
	hv_vm_map_item_t mi = {
		.uva = 0x10000,
		.ipa = 0x20000,
		.size = map_size,
		.flags = 0x3,
	};

	// First chunk: vm_map_create_upl returns only 2 pages instead of requested 4
	enqueue_vm_map_create_upl_call(((vm_map_create_upl_call) {
		.expected_map = current_thread()->map,
		.expected_offset = mi.uva,
		.expected_upl_size_in = map_size,
		.mock_upl_size_out = 2 * PAGE_SIZE, // UPL system returns less than requested
		.mock_upl_out = kTestUplMockPointer,
		.mock_count_out = 1,
		.expected_flags = UPL_SET_INTERNAL | UPL_SET_IO_WIRE,
		.expected_tag = VM_KERN_MEMORY_HV,
		.ret = KERN_SUCCESS,
	}));

	// Mock pages for first chunk (2 pages)
	enqueue_upl_phys_page_call(((upl_phys_page_call){ .expected_page_index = 0, .return_val = 0xa001, }));
	enqueue_upl_phys_page_call(((upl_phys_page_call){ .expected_page_index = 1, .return_val = 0xa002, }));

	// First chunk maps successfully
	enqueue_hv_call_call(((hv_call_call) {
		.expected_fn = VMAPPLE_NESTED_SPACE_MAP,
		.expected_arg0 = vm.host_vm_id,
		.expected_arg1 = ptoa(0xa001),
		.expected_arg2 = mi.ipa,
		.expected_arg3 = 2 * PAGE_SIZE,
		.expected_arg4 = mi.flags,
		.ret = HV_SUCCESS,
	}));

	// Second chunk: vm_map_create_upl fails for remaining 2 pages
	enqueue_vm_map_create_upl_call(((vm_map_create_upl_call) {
		.expected_map = current_thread()->map,
		.expected_offset = mi.uva + 2 * PAGE_SIZE,
		.expected_upl_size_in = 2 * PAGE_SIZE,
		.expected_flags = UPL_SET_INTERNAL | UPL_SET_IO_WIRE,
		.expected_tag = VM_KERN_MEMORY_HV,
		.ret = KERN_RESOURCE_SHORTAGE, // Failure
	}));

	// Expect rollback: unmap the successfully mapped first chunk
	enqueue_hv_call_call(((hv_call_call) {
		.expected_fn = VMAPPLE_NESTED_SPACE_UNMAP,
		.expected_arg0 = vm.host_vm_id,
		.expected_arg1 = mi.ipa,
		.expected_arg2 = 2 * PAGE_SIZE, // Size of successfully mapped portion
		.ret = HV_SUCCESS,
	}));

	// Expect cleanup of first chunk UPL
	enqueue_ubc_upl_commit_call(((ubc_upl_commit_call) {
		.expected_upl = kTestUplMockPointer,
		.ret = 0,
	}));

	// Execution
	hv_return_t ret = _hv_nested_space_map(&vm, &mi);

	// Verification
	T_EXPECT_EQ(ret, HV_ERROR, "_hv_nested_space_map should fail");
	T_EXPECT_TRUE(LIST_EMPTY(&vm.map_list_head), "map list should be empty after rollback");

	test_teardown_assert_queues_empty();

	lck_mtx_destroy(&mtx, &grp);
}

T_DECL(nested_space_map_unaligned_start, "test _hv_nested_space_map with unaligned start address")
{
	// Setup
	lck_grp_t grp;
	lck_grp_init(&grp, "test_mutex", LCK_GRP_ATTR_NULL);
	lck_mtx_t mtx;
	lck_mtx_init(&mtx, &grp, LCK_ATTR_NULL);
	hv_vm_t vm = {
		.mtx = &mtx,
		.host_vm_id = 0x123,
	};
	LIST_INIT(&vm.map_list_head);

	// Test unaligned start: 4KB aligned but not 16KB aligned
	const uint64_t map_size = 2 * PAGE_SIZE;
	const uint64_t uva = 0x11000; // 4KB aligned, but not PAGE_SIZE aligned
	hv_vm_map_item_t mi = {
		.uva = uva,
		.ipa = 0x20000, // IPA stays PAGE_SIZE aligned
		.size = map_size,
		.flags = 0x5, // Non-zero flags
	};

	// Expected UPL creation: needs to cover from page boundary (0x10000) to accommodate unaligned start
	// Aligned region: 0x10000 to 0x14000 (3 pages to cover 0x11000 + 2*PAGE_SIZE)
	const uint64_t aligned_start = 0x10000;
	const uint64_t aligned_size = 3 * PAGE_SIZE;
	const uint64_t first_page_offset = uva - aligned_start; // 0x1000 (4KB)

	enqueue_vm_map_create_upl_call(((vm_map_create_upl_call) {
		.expected_map = current_thread()->map,
		.expected_offset = aligned_start,
		.expected_upl_size_in = aligned_size,
		.mock_upl_size_out = aligned_size,
		.mock_upl_out = kTestUplMockPointer,
		.mock_count_out = 1,
		.expected_flags = UPL_SET_INTERNAL | UPL_SET_IO_WIRE,
		.expected_tag = VM_KERN_MEMORY_HV,
		.ret = KERN_SUCCESS,
	}));

	// Mock 3 contiguous pages for the UPL
	enqueue_upl_phys_page_call(((upl_phys_page_call){ .expected_page_index = 0, .return_val = 0xa001, }));
	enqueue_upl_phys_page_call(((upl_phys_page_call){ .expected_page_index = 1, .return_val = 0xa002, }));
	enqueue_upl_phys_page_call(((upl_phys_page_call){ .expected_page_index = 2, .return_val = 0xa003, }));

	// Expected hypervisor call should map with 4KB offset
	enqueue_hv_call_call(((hv_call_call) {
		.expected_fn = VMAPPLE_NESTED_SPACE_MAP,
		.expected_arg0 = vm.host_vm_id,
		.expected_arg1 = ptoa(0xa001) + first_page_offset, // Physical address with 4KB offset
		.expected_arg2 = mi.ipa,
		.expected_arg3 = map_size,
		.expected_arg4 = mi.flags,
		.ret = HV_SUCCESS,
	}));

	// Execution
	hv_return_t ret = _hv_nested_space_map(&vm, &mi);

	// Verification
	T_EXPECT_EQ(ret, HV_SUCCESS, "_hv_nested_space_map should succeed with unaligned start");
	T_EXPECT_FALSE(LIST_EMPTY(&vm.map_list_head), "map list should not be empty");
	hv_map_entry_t* entry = LIST_FIRST(&vm.map_list_head);
	T_EXPECT_EQ((uintptr_t)entry->upl, (uintptr_t)kTestUplMockPointer, "upl should be stored in map entry");
	T_EXPECT_EQ(entry->size, map_size, "size should be stored in map entry");
	T_EXPECT_EQ(entry->ipa, mi.ipa, "ipa should be stored in map entry");

	test_cleanup_vm(&vm);
	test_teardown_assert_queues_empty();

	lck_mtx_destroy(&mtx, &grp);
}

T_DECL(nested_space_map_unaligned_size, "test _hv_nested_space_map with unaligned size")
{
	// Setup
	lck_grp_t grp;
	lck_grp_init(&grp, "test_mutex", LCK_GRP_ATTR_NULL);
	lck_mtx_t mtx;
	lck_mtx_init(&mtx, &grp, LCK_ATTR_NULL);
	hv_vm_t vm = {
		.mtx = &mtx,
		.host_vm_id = 0x456,
	};
	LIST_INIT(&vm.map_list_head);

	// Test aligned start with unaligned size: 4KB aligned but not 16KB aligned
	const uint64_t map_size = PAGE_SIZE + 0x1000; // 16KB + 4KB = 20KB
	const uint64_t uva = 0x10000; // Aligned start
	hv_vm_map_item_t mi = {
		.uva = uva,
		.ipa = 0x30000,
		.size = map_size,
		.flags = 0x3, // Different non-zero flags
	};

	// Expected UPL creation: needs 2 pages to cover 20KB of data
	const uint64_t aligned_size = 2 * PAGE_SIZE;

	enqueue_vm_map_create_upl_call(((vm_map_create_upl_call) {
		.expected_map = current_thread()->map,
		.expected_offset = uva,
		.expected_upl_size_in = aligned_size,
		.mock_upl_size_out = aligned_size,
		.mock_upl_out = kTestUplMockPointer,
		.mock_count_out = 1,
		.expected_flags = UPL_SET_INTERNAL | UPL_SET_IO_WIRE,
		.expected_tag = VM_KERN_MEMORY_HV,
		.ret = KERN_SUCCESS,
	}));

	// Mock 2 contiguous pages for the UPL
	enqueue_upl_phys_page_call(((upl_phys_page_call){ .expected_page_index = 0, .return_val = 0xb001, }));
	enqueue_upl_phys_page_call(((upl_phys_page_call){ .expected_page_index = 1, .return_val = 0xb002, }));

	// Expected hypervisor call should map exact size requested (20KB)
	enqueue_hv_call_call(((hv_call_call) {
		.expected_fn = VMAPPLE_NESTED_SPACE_MAP,
		.expected_arg0 = vm.host_vm_id,
		.expected_arg1 = ptoa(0xb001), // No offset needed since start is aligned
		.expected_arg2 = mi.ipa,
		.expected_arg3 = map_size, // Maps exactly 20KB, not the full 32KB
		.expected_arg4 = mi.flags,
		.ret = HV_SUCCESS,
	}));

	// Execution
	hv_return_t ret = _hv_nested_space_map(&vm, &mi);

	// Verification
	T_EXPECT_EQ(ret, HV_SUCCESS, "_hv_nested_space_map should succeed with unaligned size");
	T_EXPECT_FALSE(LIST_EMPTY(&vm.map_list_head), "map list should not be empty");
	hv_map_entry_t* entry = LIST_FIRST(&vm.map_list_head);
	T_EXPECT_EQ((uintptr_t)entry->upl, (uintptr_t)kTestUplMockPointer, "upl should be stored in map entry");
	T_EXPECT_EQ(entry->size, map_size, "size should be stored in map entry");
	T_EXPECT_EQ(entry->ipa, mi.ipa, "ipa should be stored in map entry");

	test_cleanup_vm(&vm);
	test_teardown_assert_queues_empty();

	lck_mtx_destroy(&mtx, &grp);
}

T_DECL(nested_space_map_unaligned_both, "test _hv_nested_space_map with unaligned start and size")
{
	// Setup
	lck_grp_t grp;
	lck_grp_init(&grp, "test_mutex", LCK_GRP_ATTR_NULL);
	lck_mtx_t mtx;
	lck_mtx_init(&mtx, &grp, LCK_ATTR_NULL);
	hv_vm_t vm = {
		.mtx = &mtx,
		.host_vm_id = 0x789,
	};
	LIST_INIT(&vm.map_list_head);

	// Test both unaligned start and size: 4KB aligned but not 16KB aligned
	const uint64_t map_size = PAGE_SIZE + 0x1000; // 20KB (16KB + 4KB)
	const uint64_t uva = 0x11000; // 4KB aligned, but not PAGE_SIZE aligned
	hv_vm_map_item_t mi = {
		.uva = uva,
		.ipa = 0x40000,
		.size = map_size,
		.flags = 0x7, // Yet another set of flags
	};

	// Calculate aligned region: need 2 pages to cover 0x11000 + 20KB = 0x11000 to 0x16000
	const uint64_t aligned_start = 0x10000;
	const uint64_t aligned_size = 2 * PAGE_SIZE; // 0x10000 to 0x20000 covers the needed range
	const uint64_t first_page_offset = uva - aligned_start; // 0x1000 (4KB)

	enqueue_vm_map_create_upl_call(((vm_map_create_upl_call) {
		.expected_map = current_thread()->map,
		.expected_offset = aligned_start,
		.expected_upl_size_in = aligned_size,
		.mock_upl_size_out = aligned_size, // UPL system returns all requested pages
		.mock_upl_out = kTestUplMockPointer,
		.mock_count_out = 1,
		.expected_flags = UPL_SET_INTERNAL | UPL_SET_IO_WIRE,
		.expected_tag = VM_KERN_MEMORY_HV,
		.ret = KERN_SUCCESS,
	}));

	// Mock 2 contiguous pages for the UPL
	enqueue_upl_phys_page_call(((upl_phys_page_call){ .expected_page_index = 0, .return_val = 0xc001, }));
	enqueue_upl_phys_page_call(((upl_phys_page_call){ .expected_page_index = 1, .return_val = 0xc002, }));

	// Expected hypervisor call should map with 4KB offset and exact size
	enqueue_hv_call_call(((hv_call_call) {
		.expected_fn = VMAPPLE_NESTED_SPACE_MAP,
		.expected_arg0 = vm.host_vm_id,
		.expected_arg1 = ptoa(0xc001) + first_page_offset, // Physical address with 4KB offset
		.expected_arg2 = mi.ipa,
		.expected_arg3 = map_size, // Maps exactly the requested 20KB
		.expected_arg4 = mi.flags,
		.ret = HV_SUCCESS,
	}));

	// Execution
	hv_return_t ret = _hv_nested_space_map(&vm, &mi);

	// Verification
	T_EXPECT_EQ(ret, HV_SUCCESS, "_hv_nested_space_map should succeed with unaligned start and size");
	T_EXPECT_FALSE(LIST_EMPTY(&vm.map_list_head), "map list should not be empty");
	hv_map_entry_t* entry = LIST_FIRST(&vm.map_list_head);
	T_EXPECT_EQ((uintptr_t)entry->upl, (uintptr_t)kTestUplMockPointer, "upl should be stored in map entry");
	T_EXPECT_EQ(entry->size, map_size, "size should be stored in map entry");
	T_EXPECT_EQ(entry->ipa, mi.ipa, "ipa should be stored in map entry");

	test_cleanup_vm(&vm);
	test_teardown_assert_queues_empty();

	lck_mtx_destroy(&mtx, &grp);
}

T_DECL(nested_space_map_unaligned_tiny, "test _hv_nested_space_map with tiny unaligned mapping")
{
	// Setup
	lck_grp_t grp;
	lck_grp_init(&grp, "test_mutex", LCK_GRP_ATTR_NULL);
	lck_mtx_t mtx;
	lck_mtx_init(&mtx, &grp, LCK_ATTR_NULL);
	hv_vm_t vm = {
		.mtx = &mtx,
		.host_vm_id = 0xABC,
	};
	LIST_INIT(&vm.map_list_head);

	// Test mapping just 4KB with unaligned start (4KB aligned)
	const uint64_t map_size = 0x1000; // 4KB
	const uint64_t uva = 0x12000; // 8KB offset into first 16KB page (4KB aligned)
	hv_vm_map_item_t mi = {
		.uva = uva,
		.ipa = 0x50000,
		.size = map_size,
		.flags = 0x1, // Read-only
	};

	// Only need one page to cover this small unaligned region
	const uint64_t aligned_start = 0x10000;
	const uint64_t aligned_size = PAGE_SIZE;
	const uint64_t first_page_offset = uva - aligned_start; // 0x2000 (8KB)

	enqueue_vm_map_create_upl_call(((vm_map_create_upl_call) {
		.expected_map = current_thread()->map,
		.expected_offset = aligned_start,
		.expected_upl_size_in = aligned_size,
		.mock_upl_size_out = aligned_size,
		.mock_upl_out = kTestUplMockPointer,
		.mock_count_out = 1,
		.expected_flags = UPL_SET_INTERNAL | UPL_SET_IO_WIRE,
		.expected_tag = VM_KERN_MEMORY_HV,
		.ret = KERN_SUCCESS,
	}));

	// Mock 1 page for the UPL
	enqueue_upl_phys_page_call(((upl_phys_page_call){ .expected_page_index = 0, .return_val = 0xd001, }));

	// Expected hypervisor call should map tiny region with 8KB offset
	enqueue_hv_call_call(((hv_call_call) {
		.expected_fn = VMAPPLE_NESTED_SPACE_MAP,
		.expected_arg0 = vm.host_vm_id,
		.expected_arg1 = ptoa(0xd001) + first_page_offset, // Physical address with 8KB offset
		.expected_arg2 = mi.ipa,
		.expected_arg3 = map_size, // Maps exactly 4KB
		.expected_arg4 = mi.flags,
		.ret = HV_SUCCESS,
	}));

	// Execution
	hv_return_t ret = _hv_nested_space_map(&vm, &mi);

	// Verification
	T_EXPECT_EQ(ret, HV_SUCCESS, "_hv_nested_space_map should succeed with tiny unaligned mapping");
	T_EXPECT_FALSE(LIST_EMPTY(&vm.map_list_head), "map list should not be empty");
	hv_map_entry_t* entry = LIST_FIRST(&vm.map_list_head);
	T_EXPECT_EQ((uintptr_t)entry->upl, (uintptr_t)kTestUplMockPointer, "upl should be stored in map entry");
	T_EXPECT_EQ(entry->size, map_size, "size should be stored in map entry");
	T_EXPECT_EQ(entry->ipa, mi.ipa, "ipa should be stored in map entry");

	test_cleanup_vm(&vm);
	test_teardown_assert_queues_empty();

	lck_mtx_destroy(&mtx, &grp);
}

// Tests for _hv_nested_space_unmap.
extern hv_return_t
_hv_nested_space_unmap(hv_vm_t* vm, const hv_vm_map_item_t *mi);

T_DECL(nested_space_unmap_simple, "test _hv_nested_space_unmap with a simple unmap")
{
	// Setup
	lck_grp_t grp;
	lck_grp_init(&grp, "test_mutex", LCK_GRP_ATTR_NULL);
	lck_mtx_t mtx;
	lck_mtx_init(&mtx, &grp, LCK_ATTR_NULL);
	hv_vm_t vm = {
		.mtx = &mtx,
		.host_vm_id = 0x42,
	};
	LIST_INIT(&vm.map_list_head);

	// Add entries to the list to test list manipulation.
	hv_map_entry_t* after_entry = kalloc_type(hv_map_entry_t, Z_ZERO | Z_WAITOK);
	after_entry->ipa = 0x30000;
	after_entry->size = PAGE_SIZE;
	after_entry->upl = kTestUplMockPointer2;
	LIST_INSERT_HEAD(&vm.map_list_head, after_entry, entry_link);

	hv_map_entry_t* target_entry = kalloc_type(hv_map_entry_t, Z_ZERO | Z_WAITOK);
	target_entry->ipa = 0x20000;
	target_entry->size = 2 * PAGE_SIZE;
	target_entry->upl = kTestUplMockPointer1;
	LIST_INSERT_HEAD(&vm.map_list_head, target_entry, entry_link);

	hv_map_entry_t* before_entry = kalloc_type(hv_map_entry_t, Z_ZERO | Z_WAITOK);
	before_entry->ipa = 0x10000;
	before_entry->size = PAGE_SIZE;
	before_entry->upl = kTestUplMockPointer;
	LIST_INSERT_HEAD(&vm.map_list_head, before_entry, entry_link);

	hv_vm_map_item_t mi = {
		.ipa = target_entry->ipa,
		.size = target_entry->size,
	};

	enqueue_ubc_upl_commit_call(((ubc_upl_commit_call) {
		.expected_upl = target_entry->upl,
		.ret = 0,
	}));

	enqueue_hv_call_call(((hv_call_call) {
		.expected_fn = VMAPPLE_NESTED_SPACE_UNMAP,
		.expected_arg0 = vm.host_vm_id,
		.expected_arg1 = mi.ipa,
		.expected_arg2 = mi.size,
		.ret = HV_SUCCESS,
	}));

	// Execution
	hv_return_t ret = _hv_nested_space_unmap(&vm, &mi);

	// Verification
	T_EXPECT_EQ(ret, HV_SUCCESS, "_hv_nested_space_unmap should succeed");
	T_EXPECT_FALSE(LIST_EMPTY(&vm.map_list_head), "map list should not be empty");
	hv_map_entry_t* current_entry = LIST_FIRST(&vm.map_list_head);
	T_EXPECT_EQ((uintptr_t)current_entry, (uintptr_t)before_entry, "before_entry should be first");
	current_entry = LIST_NEXT(current_entry, entry_link);
	T_EXPECT_EQ((uintptr_t)current_entry, (uintptr_t)after_entry, "after_entry should be second");
	current_entry = LIST_NEXT(current_entry, entry_link);
	T_EXPECT_NULL(current_entry, "list should only have two entries");

	test_teardown_assert_queues_empty();

	// Clean up remaining entries
	test_cleanup_vm(&vm);

	lck_mtx_destroy(&mtx, &grp);
}

T_DECL(nested_space_unmap_not_found, "test _hv_nested_space_unmap when no matching map is found")
{
	// Setup
	lck_grp_t grp;
	lck_grp_init(&grp, "test_mutex", LCK_GRP_ATTR_NULL);
	lck_mtx_t mtx;
	lck_mtx_init(&mtx, &grp, LCK_ATTR_NULL);
	hv_vm_t vm = {
		.mtx = &mtx,
		.host_vm_id = 0x42,
	};
	LIST_INIT(&vm.map_list_head);

	// Add an entry that won't be unmapped.
	hv_map_entry_t* non_matching_entry = kalloc_type(hv_map_entry_t, Z_ZERO | Z_WAITOK);
	non_matching_entry->ipa = 0x10000;
	non_matching_entry->size = PAGE_SIZE;
	non_matching_entry->upl = kTestUplMockPointer;
	LIST_INSERT_HEAD(&vm.map_list_head, non_matching_entry, entry_link);

	const uint64_t MAP_SIZE = 2 * PAGE_SIZE;
	hv_vm_map_item_t mi = {
		.ipa = 0x20000,
		.size = MAP_SIZE,
	};

	enqueue_hv_call_call(((hv_call_call) {
		.expected_fn = VMAPPLE_NESTED_SPACE_UNMAP,
		.expected_arg0 = vm.host_vm_id,
		.expected_arg1 = mi.ipa,
		.expected_arg2 = mi.size,
		.ret = HV_SUCCESS,
	}));

	// Execution
	hv_return_t ret = _hv_nested_space_unmap(&vm, &mi);

	// Verification
	T_EXPECT_EQ(ret, HV_SUCCESS, "_hv_nested_space_unmap should succeed");
	T_EXPECT_FALSE(LIST_EMPTY(&vm.map_list_head), "map list should not be empty");
	T_EXPECT_EQ((uintptr_t)LIST_FIRST(&vm.map_list_head), (uintptr_t)non_matching_entry, "non-matching entry should remain");

	test_cleanup_vm(&vm);
	test_teardown_assert_queues_empty();

	lck_mtx_destroy(&mtx, &grp);
}
