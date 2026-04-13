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

#include <darwintest.h>

#include <stdint.h>
#include "mocks/osfmk/unit_test_utils.h"
#include "mocks/mock_mem.h"
#include "mocks/osfmk/mock_pmap.h"
#include "mocks/osfmk/mock_vm.h"

#include <kern/lock_rw.h>

#include <vm/vm_object_internal.h>
#include <vm/vm_test_utils_internal.h>
#include <vm/vm_map_lock_internal.h>
#include <vm/vm_map_xnu.h>

#define UT_MODULE osfmk

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.unit.vm.vm_range_lock"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"),
	T_META_OWNER("s_shalom"),
	T_META_RUN_CONCURRENTLY(true)
	);


T_DECL(sysctl_vm_lock_test, "sysctl test locks")
{
	int64_t result = run_sysctl_test("vm_range_lock_test", 0, argc, argv);
	T_ASSERT_EQ(1ull, result, "vm_range_lock_test");
}


T_DECL(sysctl_flags_test, "sysctl flags_test")
{
	uint32_t obj_before = mock_mem_count_allocated(MEM_POOL_VM_OBJECTS);
	uint32_t ent_before = mock_mem_count_allocated(MEM_POOL_VM_MAP_ENTRIES);
	int64_t result = run_sysctl_test("vm_range_lock_flags_test", 0, argc, argv);
	T_ASSERT_EQ(1ull, result, "vm_range_lock_flags_test");
	T_LOG("  obj-count: %u", mock_mem_count_allocated(MEM_POOL_VM_OBJECTS) - obj_before);
	T_LOG("  entry-count: %u", mock_mem_count_allocated(MEM_POOL_VM_MAP_ENTRIES) - ent_before);
}

T_DECL(sysctl_vm_range_lock_preflight_test, "sysctl vm_range_lock_preflight_test")
{
	int64_t result = run_sysctl_test("vm_range_lock_preflight_test", 0, argc, argv);
	T_ASSERT_EQ(1ull, result, "vm_range_lock_preflight_test");
}

T_DECL(sysctl_vm_map_find_locked_entry_test, "Find locked entry test")
{
	int64_t result = run_sysctl_test("vm_map_find_locked_entry_test", 0, argc, argv);
	T_EXPECT_EQ(1ull, result, "vm_map_find_locked_entry_test");
}


#if 0
// run the startup test
// This still doesn't work due to
// - kernel_map allocation
// - some issue in vm_fault
T_DECL(xnupost_vm_tests, "xnupost_vm_tests")
{
	kern_return_t ret = vm_tests();
	T_ASSERT_EQ(ret, KERN_SUCCESS, "startup test: vm_tests");
}
#endif

static int
advance_till_end(vm_map_lock_ctx_t ctx, int expect_count, int expect_sentinel_count)
{
	kern_return_t kr = KERN_SUCCESS;
	vm_map_entry_t entry = vm_map_range_next_with_error(ctx, &kr); // go to first
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "vm_map_lock_ctx_next (first)");
	int entries = 0, sentinels = 0;
	while (entry != NULL) {
		kr = KERN_SUCCESS;
		if (VME_IS_SENTINEL(entry)) {
			++sentinels;
		} else {
			++entries;
		}
		entry = vm_map_range_next_with_error(ctx, &kr);
		T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "vm_map_lock_ctx_next");
	}
	T_QUIET; T_ASSERT_EQ(entries, expect_count, "advanced expected count");
	T_QUIET; T_ASSERT_EQ(sentinels, expect_sentinel_count, "advanced expected count");
	return entries;
}


T_DECL(range_with_hole_test, "range with hole")
{
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, 0xfffffffffffff, 0);

	vm_map_offset_t start1 = 0x10000;
	vm_map_offset_t end1 = start1 + PAGE_SIZE;
	// PAGE_SIZE hole from end1 to start1
	vm_map_offset_t start2 = end1 + PAGE_SIZE;
	vm_map_offset_t end2 = start2 + PAGE_SIZE;
	vm_map_entry_t e1 = vm_test_add_map_entry(map, start1, end1);
	vm_map_entry_t e2 = vm_test_add_map_entry(map, start2, end2);

	// atomic exclusive can't deal with holes
	{
		VM_MAP_LOCK_CTX_DECLARE(ctx);
		kern_return_t kr = vm_map_range_ex_lock(ctx, &map, start1, end2, VMRL_EX_ATOMIC);
		T_ASSERT_EQ(kr, KERN_INVALID_ADDRESS, "holes atomic exclusive");
	}

	// atomic shared can't deal with holes
	{
		VM_MAP_LOCK_CTX_DECLARE(ctx);
		kern_return_t kr = vm_map_range_sh_lock(ctx, &map, start1, end2, VMRL_SH_ATOMIC);
		T_ASSERT_EQ(kr, KERN_INVALID_ADDRESS, "holes atomic shared");
	}

	// stream exclusive can deal with holes
	{
		VM_MAP_LOCK_CTX_DECLARE(ctx);
		kern_return_t kr = vm_map_range_ex_lock(ctx, &map, start1, end2, VMRL_EX_STREAM);
		T_ASSERT_EQ(kr, KERN_SUCCESS, "holes stream exclusive");
		advance_till_end(ctx, 2, 0);
		vm_map_range_ex_unlock(ctx, &map);
	}

	// stream shared can deal with holes
	{
		VM_MAP_LOCK_CTX_DECLARE(ctx);
		kern_return_t kr = vm_map_range_sh_lock(ctx, &map, start1, end2, VMRL_SH_STREAM);
		T_ASSERT_EQ(kr, KERN_SUCCESS, "holes stream shared");
		advance_till_end(ctx, 2, 0);
		vm_map_range_sh_unlock(ctx, &map);
	}

	// -------------------------- now with the flag ----------------------------

	// atomic exclusive with flag should deal with holes and add sentinel
	{
		VM_MAP_LOCK_CTX_DECLARE(ctx);
		kern_return_t kr = vm_map_range_ex_lock(ctx, &map, start1, end2, VMRL_EX_ATOMIC_ALLOW_HOLES);
		T_ASSERT_EQ(kr, KERN_SUCCESS, "holes atomic exclusive with flag");
		T_QUIET; T_ASSERT_EQ(vm_map_lock_ctx_get_map(ctx)->hdr.nentries, 3, "added sentinel");
		advance_till_end(ctx, 2, 1);
		vm_map_range_ex_unlock(ctx, &map);
		T_QUIET; T_ASSERT_EQ(map->hdr.nentries, 2, "added sentinel");
	}

	// atomic shared doesn't have a flag to allow holes
	// stream exclusive with flag should fail with holes
	{
		VM_MAP_LOCK_CTX_DECLARE(ctx);
		kern_return_t kr = vm_map_range_ex_lock(ctx, &map, start1, end2, VMRL_EX_STREAM_NO_HOLES);
		T_ASSERT_EQ(kr, KERN_SUCCESS, "holes stream exclusive with flag");
		vm_map_entry_t entry = vm_map_range_next_with_error(ctx, &kr); // go to first
		T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "vm_map_lock_ctx_next (first)");
		entry = vm_map_range_next_with_error(ctx, &kr); // second should fail
		T_QUIET; T_ASSERT_EQ(kr, KERN_INVALID_ADDRESS, "vm_map_lock_ctx_next (second)");
		vm_map_range_ex_unlock(ctx, &map);
	}

	// stream shared can deal with holes
	{
		VM_MAP_LOCK_CTX_DECLARE(ctx);
		kern_return_t kr = vm_map_range_sh_lock(ctx, &map, start1, end2, VMRL_SH_STREAM_NO_HOLES);
		T_ASSERT_EQ(kr, KERN_SUCCESS, "holes stream exclusive with flag");
		vm_map_entry_t entry = vm_map_range_next_with_error(ctx, &kr); // go to first
		T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "vm_map_lock_ctx_next (first)");
		entry = vm_map_range_next_with_error(ctx, &kr); // second should fail
		T_QUIET; T_ASSERT_EQ(kr, KERN_INVALID_ADDRESS, "vm_map_lock_ctx_next (second)");
		vm_map_range_sh_unlock(ctx, &map);
	}

	// stream shared can't deal with holes, returns an error or panics
	{
		VM_MAP_LOCK_CTX_DECLARE(ctx);
		kern_return_t kr = vm_map_range_sh_lock(ctx, &map, start1, end2, VMRL_SH_STREAM_NO_HOLES);
		T_ASSERT_EQ(kr, KERN_SUCCESS, "holes stream exclusive with flag");
		vm_map_entry_t entry = vm_map_range_next_with_error(ctx, &kr); // go to first
		T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "vm_map_lock_ctx_next (first)");
		T_ASSERT_PANIC_CONTAINS({
			entry = vm_map_range_next(ctx);
		}, "hit an unexpected error", "vm_map_range_next() with error");
		vm_map_range_sh_unlock(ctx, &map);
	}

	T_PASS("ok");
}


vm_map_t
setup_two_contiguous_entry_map(vm_map_offset_t *const start, vm_map_offset_t *const end)
{
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, 0xfffffffffffff, 0);
	vm_map_offset_t start1 = 0x10000;
	vm_map_offset_t end1 = start1 + PAGE_SIZE;
	vm_map_offset_t start2 = end1;
	vm_map_offset_t end2 = start2 + PAGE_SIZE;
	vm_map_entry_t e1 = vm_test_add_map_entry(map, start1, end1);
	vm_map_entry_t e2 = vm_test_add_map_entry(map, start2, end2);
	*start = start1;
	*end = end2;
	return map;
}

void
api_misuse_sh_ex(vmrl_ex_flags_t ex_flags, vmrl_sh_flags_t sh_flags, const char* desc)
{
	T_LOG("api_misuse_sh_ex %s", desc);
	vm_map_offset_t start, end;

	// exclusive lock, shared unlock
	{
		vm_map_t map = setup_two_contiguous_entry_map(&start, &end);
		VM_MAP_LOCK_CTX_DECLARE(ctx);
		kern_return_t kr = vm_map_range_ex_lock(ctx, &map, start, end, ex_flags);
		T_ASSERT_EQ(kr, KERN_SUCCESS, "ex lock");
		advance_till_end(ctx, 2, 0);
		T_ASSERT_PANIC({
			vm_map_range_sh_unlock(ctx, &map);
		}, "sh unlock after ex lock");
		// map remains in an inconsistent state, don't reuse it
		// we still to do the right unlock, otherwise the ctx cleanup is going to panic
		vm_map_range_ex_unlock(ctx, &map);
	}

	// shared lock, exclusive unlock
	{
		vm_map_t map = setup_two_contiguous_entry_map(&start, &end);
		VM_MAP_LOCK_CTX_DECLARE(ctx);
		kern_return_t kr = vm_map_range_sh_lock(ctx, &map, start, end, sh_flags);
		T_ASSERT_EQ(kr, KERN_SUCCESS, "sh lock");
		advance_till_end(ctx, 2, 0);
		T_ASSERT_PANIC({
			vm_map_range_ex_unlock(ctx, &map);
		}, "ex unlock after sh lock");
		vm_map_range_sh_unlock(ctx, &map);
	}

	// shared lock, downgrade exclusive to shared
	{
		vm_map_t map = setup_two_contiguous_entry_map(&start, &end);
		VM_MAP_LOCK_CTX_DECLARE(ctx);
		kern_return_t kr = vm_map_range_sh_lock(ctx, &map, start, end, sh_flags);
		T_ASSERT_EQ(kr, KERN_SUCCESS, "sh lock");
		advance_till_end(ctx, 2, 0);
		T_ASSERT_PANIC({
			vm_map_range_ex_to_sh(ctx);
		}, "downgrade after sh lock");
		vm_map_range_sh_unlock(ctx, &map);
	}

	// exclusive lock, no cleanup
	{
		vm_map_t map = setup_two_contiguous_entry_map(&start, &end);
		T_ASSERT_PANIC({
			// add another level of scope so that ctx destructor is called at it's end
			do {
			        VM_MAP_LOCK_CTX_DECLARE(ctx);
			        kern_return_t kr = vm_map_range_ex_lock(ctx, &map, start, end, ex_flags);
			} while (false);
		}, "ex no unlock");
	}

	// shared lock, no cleanup
	{
		vm_map_t map = setup_two_contiguous_entry_map(&start, &end);
		T_ASSERT_PANIC({
			do {
			        VM_MAP_LOCK_CTX_DECLARE(ctx);
			        kern_return_t kr = vm_map_range_sh_lock(ctx, &map, start, end, sh_flags);
			} while (false);
		}, "sh no unlock");
	}
}

T_DECL(api_misuse_sh_ex, "Test wrong API usage, shared vs exclusive")
{
	api_misuse_sh_ex(VMRL_EX_ATOMIC, VMRL_SH_ATOMIC, "atomic");
	api_misuse_sh_ex(VMRL_EX_STREAM, VMRL_SH_STREAM, "stream");
}


void
api_partial_iter(bool do_one_advance, vmrl_ex_flags_t ex_flags, vmrl_sh_flags_t sh_flags, const char* desc)
{
	T_LOG("api_partial_iter %s", desc);
	vm_map_offset_t start, end;

	// exclusive lock, unlock before iteration finished
	{
		vm_map_t map = setup_two_contiguous_entry_map(&start, &end);
		VM_MAP_LOCK_CTX_DECLARE(ctx);
		kern_return_t kr = vm_map_range_ex_lock(ctx, &map, start, end, ex_flags);
		T_ASSERT_EQ(kr, KERN_SUCCESS, "ex lock");
		if (do_one_advance) {
			vm_map_entry_t entry = vm_map_range_next_with_error(ctx, &kr);
			T_ASSERT_EQ(kr, KERN_SUCCESS, "ctx next");
		}
		vm_map_range_ex_unlock(ctx, &map);
	}

	// shared lock, unlock before iteration finished
	{
		vm_map_t map = setup_two_contiguous_entry_map(&start, &end);
		VM_MAP_LOCK_CTX_DECLARE(ctx);
		kern_return_t kr = vm_map_range_sh_lock(ctx, &map, start, end, sh_flags);
		T_ASSERT_EQ(kr, KERN_SUCCESS, "sh lock");
		if (do_one_advance) {
			vm_map_entry_t entry = vm_map_range_next_with_error(ctx, &kr);
			T_ASSERT_EQ(kr, KERN_SUCCESS, "ctx next");
		}
		vm_map_range_sh_unlock(ctx, &map);
	}
}

T_DECL(api_partial_iter, "API usage - partial iteration should be allowed")
{
	api_partial_iter(false, VMRL_EX_ATOMIC, VMRL_SH_ATOMIC, "no-iter,atomic");
	api_partial_iter(true, VMRL_EX_ATOMIC, VMRL_SH_ATOMIC, "one-iter,atomic");
	api_partial_iter(false, VMRL_EX_STREAM, VMRL_SH_STREAM, "no-iter,stream");
	api_partial_iter(true, VMRL_EX_STREAM, VMRL_SH_STREAM, "one-iter,stream");
}

T_DECL(extend_after_drop, "extend after drop")
{
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, 0xfffffffffffff, 0);
	vm_map_t orig_map = map;
	vm_map_offset_t start1 = 0x10000;
	vm_map_offset_t end1 = start1 + PAGE_SIZE;
	vm_map_offset_t start2 = end1;
	vm_map_offset_t end2 = start2 + PAGE_SIZE * 2;
	vm_map_entry_t e1 = vm_test_add_map_entry(map, start1, end1);
	vm_map_entry_t e2 = vm_test_add_map_entry(map, start2, end2);
	// starting state is
	// |---e1:1 pages----|--------------e2:2 pages------------|
	//                   ^--current iterator
	// first iteration passes e1, drops the lock, then someone else extends e1 and contracts e2 to this state
	// |---e1:2 pages-------------------|-----e2:1 page-------|
	//                   ^--current iterator
	vm_map_offset_t iterator_is_at = start1;
	vm_map_address_t cur_startp = 0, cur_endp = 0;
	vm_map_size_t cur_sizep = 0;

	kern_return_t kr = KERN_SUCCESS;

	VM_MAP_LOCK_CTX_DECLARE(ctx);
	kr = vm_map_range_sh_lock(ctx, &map, start1, end2, VMRL_SH_STREAM);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "sh lock");

	// get the first entry
	vm_map_entry_t entry = vm_map_range_next_with_error(ctx, &kr);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "vm_map_lock_ctx_next (first)");
	T_QUIET; T_ASSERT_EQ_PTR(entry, e1, "first entry is expected");

	vm_map_lock_ctx_bounds(ctx, &cur_startp, &cur_endp, &cur_sizep);
	T_QUIET; T_ASSERT_EQ(cur_startp, iterator_is_at, "expect to be in the middle of e1 (cur_start)");
	T_QUIET; T_ASSERT_EQ(cur_endp, end1, "expect to be in the middle of e1 (cur_endp)");
	T_QUIET; T_ASSERT_EQ(cur_sizep, end1 - iterator_is_at, "expect to be in the middle of e1 (cur_sizep)");

	iterator_is_at = entry->vme_end;

	// drop the lock to the first entry
	vm_map_range_stream_drop(ctx);

	// now change e1 and e2 as if someone else got the entry lock after it dropped and modified it
	vm_map_offset_t new_end1 = end1 + PAGE_SIZE;
	vm_map_offset_t new_start2 = start2 + PAGE_SIZE;

	vm_map_remove(orig_map, start1, end1);
	vm_map_remove(orig_map, start2, end2);
	e1 = vm_test_add_map_entry(orig_map, start1, new_end1);
	e2 = vm_test_add_map_entry(orig_map, new_start2, end2);

	entry = vm_map_range_next_with_error(ctx, &kr);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "vm_map_lock_ctx_next (first)");

	// we expect to get e1 but only the "unconsumed" part of it
	T_QUIET; T_ASSERT_EQ_PTR(entry, e1, "first entry is expected");

	vm_map_lock_ctx_bounds(ctx, &cur_startp, &cur_endp, &cur_sizep);
	T_QUIET; T_ASSERT_EQ(cur_startp, iterator_is_at, "expect to be in the middle of e1 (cur_start)");
	T_QUIET; T_ASSERT_EQ(cur_endp, new_end1, "expect to be in the middle of e1 (cur_endp)");
	T_QUIET; T_ASSERT_EQ(cur_sizep, new_end1 - iterator_is_at, "expect to be in the middle of e1 (cur_sizep)");

	vm_map_range_sh_unlock(ctx, &map);
}

static void
enter_obj_entry(vm_map_t map, vm_map_address_t start, vm_map_size_t size)
{
	kern_return_t kr = vm_map_enter(map, &start, size, 0,
	    VM_MAP_KERNEL_FLAGS_FIXED(),
	    vm_object_allocate(size, map->serial_id),     /* non NULL to avoid coalesce */
	    0, /*needs_copy=*/ true, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "vm_map_enter");
}

static void
enter_copy_none_obj_entry(vm_map_t map, vm_map_address_t start, vm_map_size_t size, vm_prot_t cur_prot)
{
	vm_object_t obj = vm_object_allocate(size, map->serial_id);
	obj->copy_strategy = MEMORY_OBJECT_COPY_DELAY;

	kern_return_t kr = vm_map_enter(map, &start, size, 0,
	    VM_MAP_KERNEL_FLAGS_FIXED(),
	    obj,
	    0, /*needs_copy=*/ false, cur_prot, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "vm_map_enter");
}

vm_map_address_t MAP_BASE = 0x010000000; // avoid the pmap_shared_region

static void
setup_map_with_sealed(vm_map_t *parent_map, vm_map_t *submap)
{
	kern_return_t kr;
	*parent_map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, 0xfffffffffffff, 0);

	pmap_t pmap_nested = pmap_create_options(NULL, 0, PMAP_CREATE_64BIT | PMAP_CREATE_NESTED);
#if defined(__arm64__)
	pmap_set_nested(pmap_nested);
#endif
	*submap = vm_map_create_options(pmap_nested, 0, 0xfffffffffffff, 0);
	(*submap)->is_nested_map = TRUE;
	(*submap)->vmmap_sealed = VM_MAP_WILL_BE_SEALED;

	// submap has 2 multi-page entries in the submap
	vm_map_address_t submap_start = MAP_BASE + 0x10000;
	vm_map_address_t offset = submap_start;
	enter_obj_entry(*submap, offset, PAGE_SIZE * 3);
	offset += PAGE_SIZE * 3;
	enter_obj_entry(*submap, offset, PAGE_SIZE * 3);
	(*submap)->vmmap_sealed = VM_MAP_WILL_BE_SEALED;
	vm_map_seal(*submap, true);
	T_QUIET; T_ASSERT_EQ((*submap)->hdr.nentries, 4, "submap entries"); // 2 added entries, 2 padding the start and end of the map

	// parent map has obj-entry (2 pages), submap-entry (3+3 pages), obj-entry (2 pages)
	offset = MAP_BASE + 0x50000;
	enter_obj_entry(*parent_map, offset, PAGE_SIZE * 2);
	offset += PAGE_SIZE * 2;

	kr = vm_map_enter(*parent_map, &offset, PAGE_SIZE * 3 * 2, 0,
	    VM_MAP_KERNEL_FLAGS_FIXED(.vmkf_submap = TRUE, .vmkf_nested_pmap =  TRUE), (vm_object_t)(uintptr_t) *submap,
	    submap_start, true, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "vm_map_enter submap");
	offset += PAGE_SIZE * 3 * 2; // submap is 2 entries of 3 pages

	enter_obj_entry(*parent_map, offset, PAGE_SIZE * 2);
	T_QUIET; T_ASSERT_EQ((*parent_map)->hdr.nentries, 3, "parent entries");
}

static void
setup_transparent_map(vm_map_t *parent_map, vm_map_t *submap)
{
	kern_return_t kr;

	vm_map_address_t submap_start;
	vm_map_kernel_flags_t submap_enter_flags;

	*submap = vm_map_create_options(kernel_pmap, 0, PAGE_SIZE * 2 * 3, 0);
	vm_map_reference(*submap);
	// offset matches parent
	submap_start = MAP_BASE + 0x50000 + 2 * PAGE_SIZE;
	submap_enter_flags = VM_MAP_KERNEL_FLAGS_FIXED(.vmkf_submap = TRUE, .vmf_permanent = true, .vmkf_submap_atomic = true);

	// parent map has obj-entry (2 pages), submap-entry (2+2+2 pages), obj-entry (2 pages)
	*parent_map = vm_map_create_options(kernel_pmap, 0, 0xfffffffffffff, 0);

	vm_map_address_t offset = MAP_BASE + 0x50000;
	enter_obj_entry(*parent_map, offset, PAGE_SIZE * 2);
	offset += PAGE_SIZE * 2;

	kr = vm_map_enter(*parent_map, &offset, PAGE_SIZE * 2 * 3, 0,
	    submap_enter_flags, (vm_object_t)(uintptr_t) *submap,
	    submap_start, /*needs_copy=*/ false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "vm_map_enter submap");
	offset += PAGE_SIZE * 2 * 3; // submap is 3 entries of 2 pages

	enter_obj_entry(*parent_map, offset, PAGE_SIZE * 2);

	// populate submap
	offset = submap_start;
	enter_copy_none_obj_entry(*submap, offset, PAGE_SIZE * 2, VM_PROT_DEFAULT);
	offset += PAGE_SIZE * 2;
	enter_copy_none_obj_entry(*submap, offset, PAGE_SIZE * 2, VM_PROT_READ);
	offset += PAGE_SIZE * 2;
	enter_copy_none_obj_entry(*submap, offset, PAGE_SIZE * 2, VM_PROT_READ);

	T_QUIET; T_ASSERT_EQ((*submap)->hdr.nentries, 3, "submap entries");

	T_QUIET; T_ASSERT_EQ((*parent_map)->hdr.nentries, 3, "parent entries");
}

/* preflight and the iteration is going into the submap */
T_DECL(preflight_and_descend, "preflight and descend")
{
	vm_map_t parent_map, submap;
	setup_map_with_sealed(&parent_map, &submap);

	vm_map_address_t r_start = MAP_BASE + 0x50000 + PAGE_SIZE; // middle of the first entry
	vm_map_address_t r_end =   MAP_BASE + 0x50000 + 6 * PAGE_SIZE;// middle of the second entry in the submap
	// size of iteration = 5 pages

	kern_return_t kr = KERN_SUCCESS;

	VM_MAP_LOCK_CTX_DECLARE(ctx);

	vm_map_lock_ctx_set_preflight(ctx, ^kern_return_t (vm_map_lock_ctx_t vctx, vm_map_entry_t vme) {
		vm_map_address_t cur_startp = 0, cur_endp = 0;
		vm_map_size_t cur_sizep = 0;
		vm_map_lock_ctx_bounds(vctx, &cur_startp, &cur_endp, &cur_sizep);
		T_QUIET; T_LOG("  preflight map=%p vme=%p   start=%llx  end=%llx  sz=%d  is_submap=%d", vctx->vmlc_map, vme, cur_startp, cur_endp, (int)cur_sizep / PAGE_SIZE, vme->is_sub_map);
		return KERN_SUCCESS;
	});

	// shared-stream
	kr = vm_map_range_sh_lock(ctx, &parent_map, r_start, r_end, VMRL_SH_STREAM | VMRL_SH_DESCEND_INTO_CONSTANT);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "vm_map_range_sh_lock");

	vm_map_address_t cur_offset = r_start;
	vm_map_entry_t entry;
	while ((entry = vm_map_range_next_with_error(ctx, &kr)) != NULL) {
		T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "vm_map_range_next_with_error");
		vm_map_address_t cur_startp = 0, cur_endp = 0;
		vm_map_size_t cur_sizep = 0;
		vm_map_lock_ctx_bounds(ctx, &cur_startp, &cur_endp, &cur_sizep);
		T_QUIET; T_LOG("iter map=%p vme=%p   start=%llx  end=%llx  sz=%d", ctx->vmlc_map, entry, cur_startp, cur_endp, (int)cur_sizep / PAGE_SIZE);

		T_QUIET; T_ASSERT_EQ(vm_map_lock_ctx_to_parent_address(ctx, cur_startp), cur_offset, "offset match");
		cur_offset += cur_sizep;
	}
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "vm_map_range_next_with_error last");
	T_QUIET; T_ASSERT_EQ(cur_offset, r_end, "reached end");

	vm_map_range_sh_unlock(ctx, &parent_map);
}

static void
setup_nested_submap(vm_map_t *parent_map, vm_map_t *submap)
{
	kern_return_t kr;
	*parent_map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, 0xfffffffffffffff, 0);

	pmap_t pmap_nested = pmap_create_options(NULL, 0, PMAP_CREATE_64BIT | PMAP_CREATE_NESTED);
#if defined(__arm64__)
	pmap_set_nested(pmap_nested);
#endif
	*submap = vm_map_create_options(pmap_nested, 0, 0xfffffffffffffff, 0);
	(*submap)->vmmap_sealed = VM_MAP_WILL_BE_SEALED;
	(*submap)->is_nested_map = TRUE;

	// submap has 2 multi-page entries in the submap
	vm_map_address_t submap_start = MAP_BASE + 0x10000;
	vm_map_address_t offset = submap_start;
	enter_obj_entry(*submap, offset, PAGE_SIZE * 3);
	offset += PAGE_SIZE * 3;
	enter_obj_entry(*submap, offset, PAGE_SIZE * 3);
	vm_map_seal(*submap, true);
	T_QUIET; T_ASSERT_EQ((*submap)->hdr.nentries, 4, "submap entries"); // 2 added entries, 2 padding the start and end of the map

	// parent map has obj-entry (2 pages), submap-entry (3+3 pages), obj-entry (2 pages)
	offset = MAP_BASE + 0x50000;
	enter_obj_entry(*parent_map, offset, PAGE_SIZE * 2);
	offset = 0x180000000ULL;

	kr = vm_map_enter(*parent_map, &offset, 0x180000000ULL, 0,
	    VM_MAP_KERNEL_FLAGS_FIXED(.vmkf_submap = TRUE, .vmkf_nested_pmap =  TRUE), (vm_object_t)(uintptr_t) *submap,
	    submap_start, true, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "vm_map_enter submap");
}

static kern_return_t
vm_map_range_lock(
	vm_map_lock_ctx_t ctx,
	vm_map_t *map,
	vm_map_address_t start,
	vm_map_address_t end,
	vmrl_flags_t flags)
{
	if (vmrl_is_exclusive(flags)) {
		return vm_map_range_ex_lock(ctx, map, start, end, (vmrl_ex_flags_t) flags);
	} else {
		return vm_map_range_sh_lock(ctx, map, start, end, (vmrl_sh_flags_t) flags);
	}
}

static void
vm_map_range_unlock(vm_map_lock_ctx_t ctx, vm_map_t *map)
{
	if (vmrl_is_exclusive(ctx)) {
		vm_map_range_ex_unlock(ctx, map);
	} else {
		vm_map_range_sh_unlock(ctx, map);
	}
}

static void
no_pmap_unnest_tests(vmrl_flags_t flags)
{
	vm_map_t parent_map, submap;
	vm_map_address_t obj_entry_start = MAP_BASE + 0x50000;
	vm_map_address_t obj_entry_end = obj_entry_start + PAGE_SIZE * 2;
	vm_map_address_t submap_entry_start =  0x180000000ULL;
	vm_map_address_t submap_entry_end = 0x180000000ULL * 2;
	kern_return_t kr;
	VM_MAP_LOCK_CTX_DECLARE(ctx);


	setup_nested_submap(&parent_map, &submap);
	/*
	 * test normal obj works
	 */
	kr = vm_map_range_lock(ctx, &parent_map, obj_entry_start, obj_entry_end, flags | VMRL_NO_PMAP_UNNEST);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "lock");
	vm_map_entry_t entry = vm_map_range_next(ctx);
	T_QUIET; T_ASSERT_NE_PTR(entry, VM_MAP_ENTRY_NULL, "got an entry");
	entry = vm_map_range_next(ctx);
	T_QUIET; T_ASSERT_EQ_PTR(entry, VM_MAP_ENTRY_NULL, "end of range");
	vm_map_range_unlock(ctx, &parent_map);


	/*
	 * test clipping works (with obj)
	 */
	kr = vm_map_range_lock(ctx, &parent_map, obj_entry_start, obj_entry_start + PAGE_SIZE, flags | VMRL_NO_PMAP_UNNEST);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "lock");
	entry = vm_map_range_next(ctx);
	T_QUIET; T_ASSERT_NE_PTR(entry, VM_MAP_ENTRY_NULL, "got an entry");
	if (vmrl_is_exclusive(ctx)) {
		T_ASSERT_EQ_ULLONG(entry->vme_end, obj_entry_start + PAGE_SIZE, "clipped");
	} else {
		T_ASSERT_EQ_ULLONG(entry->vme_end, obj_entry_end, "didn't clip");
	}
	entry = vm_map_range_next(ctx);
	T_QUIET; T_ASSERT_EQ_PTR(entry, VM_MAP_ENTRY_NULL, "end of range");
	vm_map_range_unlock(ctx, &parent_map);


	vm_map_destroy(parent_map);
	setup_nested_submap(&parent_map, &submap);

	/*
	 * we don't pmap unnest
	 */
	kr = vm_map_range_lock(ctx, &parent_map, submap_entry_start, submap_entry_end, flags | VMRL_NO_PMAP_UNNEST);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "lock");
	entry = vm_map_range_next(ctx);
	T_QUIET; T_ASSERT_NE_PTR(entry, VM_MAP_ENTRY_NULL, "got an entry");
	T_ASSERT_EQ_INT((int)entry->use_pmap, true, "didn't pmap unnest");
	T_QUIET; T_ASSERT_EQ_ULLONG(entry->vme_end, submap_entry_end, "didn't clip");
	entry = vm_map_range_next(ctx);
	T_QUIET; T_ASSERT_EQ_PTR(entry, VM_MAP_ENTRY_NULL, "end of range");
	vm_map_range_unlock(ctx, &parent_map);

	/*
	 * test we do the pmap unnest if we clip
	 */
	kr = vm_map_range_lock(ctx, &parent_map, submap_entry_start, submap_entry_start + PAGE_SIZE, flags | VMRL_NO_PMAP_UNNEST);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "lock");
	entry = vm_map_range_next(ctx);
	T_QUIET; T_ASSERT_NE_PTR(entry, VM_MAP_ENTRY_NULL, "got an entry");
	if (vmrl_is_exclusive(ctx)) {
		T_QUIET; T_ASSERT_EQ_ULLONG(entry->vme_end, submap_entry_start + PAGE_SIZE, "clipped");
		T_ASSERT_EQ_INT((int)entry->use_pmap, false, "pmap unnested");
	} else {
		T_QUIET; T_ASSERT_EQ_ULLONG(entry->vme_end, submap_entry_end, "didn't clip");
		T_ASSERT_EQ_INT((int)entry->use_pmap, true, "pmap unnested");
	}
	entry = vm_map_range_next(ctx);
	T_QUIET; T_ASSERT_EQ_PTR(entry, VM_MAP_ENTRY_NULL, "end of range");
	vm_map_range_unlock(ctx, &parent_map);

	vm_map_destroy(parent_map);
	setup_nested_submap(&parent_map, &submap);

	/*
	 * test we do pmap unnest at all
	 */
	kr = vm_map_range_lock(ctx, &parent_map, submap_entry_start, submap_entry_end, flags);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "lock");
	entry = vm_map_range_next(ctx);
	T_QUIET; T_ASSERT_NE_PTR(entry, VM_MAP_ENTRY_NULL, "got an entry");
	if (vmrl_is_exclusive(ctx)) {
		T_ASSERT_EQ_INT((int)entry->use_pmap, false, "pmap unnested");
	} else {
		T_ASSERT_EQ_INT((int)entry->use_pmap, true, "pmap unnested");
	}
	entry = vm_map_range_next(ctx);
	T_QUIET; T_ASSERT_EQ_PTR(entry, VM_MAP_ENTRY_NULL, "end of range");
	vm_map_range_unlock(ctx, &parent_map);
}

T_DECL(pmap_unnest_tests, "no pmap unnest tests")
{
	no_pmap_unnest_tests(VMRL_EXCLUSIVE | VMRL_ATOMIC);
	no_pmap_unnest_tests(VMRL_EXCLUSIVE | VMRL_STREAM);
	no_pmap_unnest_tests(VMRL_SHARED | VMRL_ATOMIC);
	no_pmap_unnest_tests(VMRL_SHARED | VMRL_STREAM);
}

T_DECL(found_entry_clip_end_basic, "Verify that found_entry_clip_end works for basic cases")
{
	vm_map_address_t start = 0x10000;
	vm_map_address_t end = 0x100000;
	vm_map_address_t increment = 0x10000;

	for (vm_map_address_t clip_loc = (start + increment); clip_loc < end; clip_loc += increment) {
		T_LOG("found_entry_clip_end_basic test at clip_loc = %#llx", clip_loc);
		VM_MAP_FIND_LOCK_CTX_DECLARE(ctx);
		kern_return_t kr;
		vm_map_entry_t entry, new_entry;
		vm_map_t map;

		map = vm_test_alloc_map();
		entry = vm_test_add_map_entry(map, start, end);
		kr = vm_map_find_entry_ex_locked(ctx, &map, start, VMRL_FIND_EX_DEFAULT);
		T_ASSERT_MACH_SUCCESS(kr, "lock entry by addr");
		T_ASSERT_EQ_PTR(entry, vm_map_found_entry_get_entry(ctx), "locked entry is the one expected");

		vm_map_ilk_lock(ctx->vmlc_map);
		new_entry = vm_map_found_entry_clip_end_ilocked(ctx, clip_loc);

		T_EXPECT_EQ(entry->vme_start, start, "original entry start unchanged");
		T_EXPECT_EQ(entry->vme_end, clip_loc, "original entry clipped to clip_loc = %#llx", clip_loc);
		vm_entry_assert_excl_owner(entry);

		T_EXPECT_EQ(new_entry->vme_start, clip_loc, "new entry starts at clip_loc = %#llx", clip_loc);
		T_EXPECT_EQ(new_entry->vme_end, end, "new entry ends at original end");
		vm_entry_assert_excl_owner(new_entry);

		vm_map_found_entry_ex_unlock(ctx, &map);
		vm_entry_assert_not_owner(entry);
		vm_entry_assert_excl_owner(new_entry);
		vm_entry_unlock_exclusive(map, new_entry);
		vm_map_ilk_unlock(map);

		vm_map_destroy(map);
	}
}

T_DECL(found_entry_clip_end_oob, "Verify that found_entry_clip_end panics for out-of-bounds cases")
{
	struct test_case {
		char *name;
		vm_map_address_t clip_loc;
	};

	vm_map_address_t start = 0x10000;
	vm_map_address_t end = 0x100000;
	struct test_case test_cases[] = {
		{ "clip_end endaddr before start", start - PAGE_SIZE },
		{ "clip_end endaddr at start", start },
		{ "clip_end endaddr at end", end },
		{ "clip_end endaddr after end", end + PAGE_SIZE },
	};

	for (size_t i = 0; i < countof(test_cases); i++) {
		char *test_name = test_cases[i].name;
		vm_map_address_t clip_loc = test_cases[i].clip_loc;
		T_LOG("out of bounds clip test %s (clip_loc = %#llx)", test_name, clip_loc);
		VM_MAP_FIND_LOCK_CTX_DECLARE(ctx);
		kern_return_t kr;
		vm_map_entry_t entry, new_entry;
		vm_map_t map;

		map = vm_test_alloc_map();
		entry = vm_test_add_map_entry(map, start, end);
		kr = vm_map_find_entry_ex_locked(ctx, &map, start, VMRL_FIND_EX_DEFAULT);
		T_ASSERT_MACH_SUCCESS(kr, "lock entry by addr");
		T_ASSERT_EQ_PTR(entry, vm_map_found_entry_get_entry(ctx), "locked entry is the one expected");

		vm_map_ilk_lock(ctx->vmlc_map);
		T_ASSERT_PANIC({
			(void)vm_map_found_entry_clip_end_ilocked(ctx, clip_loc);
		}, "%s", test_name);

		vm_map_found_entry_ex_unlock(ctx, &map);
		vm_map_ilk_unlock(map);
		vm_map_destroy(map);
	}
}

T_DECL(found_entry_pop, "Verify that vm_map_found_entry_ex_pop_curr behaves correctly with unlock")
{
	vm_map_t map = vm_test_alloc_map();
	const vm_map_offset_t start = 0x10000, end = 0x20000;
	kern_return_t kr;

	vm_map_entry_t entry = vm_test_add_map_entry(map, start, end);

	VM_MAP_FIND_LOCK_CTX_DECLARE(ctx);

	kr = vm_map_find_entry_ex_locked(ctx, &map, start, VMRL_FIND_EX_DEFAULT);
	T_ASSERT_MACH_SUCCESS(kr, "lock entry by addr");
	T_ASSERT_EQ_PTR(entry, vm_map_found_entry_get_entry(ctx), "locked entry is the one expected");
	vm_entry_assert_excl_owner(entry);

	vm_map_found_entry_ex_pop_curr(ctx);
	vm_map_found_entry_ex_unlock(ctx, &map);
	vm_entry_assert_excl_owner(entry);
	T_PASS("popped entry was not unlocked");

	vm_entry_unlock_exclusive(map, entry);
	vm_entry_assert_not_owner(entry);
	T_PASS("popped entry successfully unlocked manually");
	vm_map_destroy(map);
}

T_DECL(double_pop, "Verify that you can't pop the same entry lock from a range lock twice")
{
	vm_map_t map = vm_test_alloc_map();
	const vm_map_offset_t start = 0x10000, end = 0x20000;
	kern_return_t kr;

	vm_map_entry_t entry = vm_test_add_map_entry(map, start, end);

	VM_MAP_FIND_LOCK_CTX_DECLARE(ctx);

	kr = vm_map_find_entry_ex_locked(ctx, &map, start, VMRL_FIND_EX_DEFAULT);
	T_ASSERT_MACH_SUCCESS(kr, "lock entry by addr");
	T_ASSERT_EQ_PTR(entry, vm_map_found_entry_get_entry(ctx), "locked entry is the one expected");
	vm_entry_assert_excl_owner(entry);

	vm_map_found_entry_ex_pop_curr(ctx);
	T_ASSERT_PANIC({
		vm_map_found_entry_ex_pop_curr(ctx);
	}, "vm_map_found_entry_ex_pop_curr a second time");
	vm_map_found_entry_ex_unlock(ctx, &map);
	vm_entry_unlock_exclusive(map, entry);
	vm_map_destroy(map);
}



void
check_is_entry_of_map(vm_map_entry_t entry, vm_map_t map)
{
	T_QUIET; T_ASSERT_FALSE(entry == vm_map_to_entry(map), "entry is the map itself");
	vm_map_entry_t start_entry = entry;
	while (true) {
		entry = entry->vme_next;
		if (entry == vm_map_to_entry(map)) {
			return; // got to the expected map
		}
		if (start_entry == entry) {
			break;
		}
	}
	T_ASSERT_FAIL("iterating from entry %p did not reach map %p", entry, map);
}

void
test_ex_descend(vm_map_lock_ctx_t ctx,
    vm_map_t parent_map,
    vm_map_address_t r_start, vm_map_address_t r_end,
    vm_object_offset_t obj_offset_start)
{
	T_LOG("start=%llx end=%llx", r_start, r_end);
	vm_map_t orig_parent_map = parent_map;
	kern_return_t kr = vm_map_range_ex_lock(ctx, &parent_map, r_start, r_end, VMRL_EX_STREAM | VMRL_EX_DESCEND_INTO_CONSTANT);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "vm_map_range_ex_lock");

	vm_map_address_t map_iter_offset = r_start;
	vm_object_t cur_obj = NULL;
	vm_object_offset_t obj_iter_offset = obj_offset_start;
	vm_map_entry_t entry;
	while ((entry = vm_map_range_stream_next_with_error(ctx, &kr)) != NULL) {
		T_QUIET; T_ASSERT_FALSE(entry->is_sub_map, "not a submap entry");
		vm_map_t cur_map = vm_map_lock_ctx_get_map(ctx);
		if (cur_map != orig_parent_map) {
			T_QUIET; T_ASSERT_TRUE(vm_map_lock_ctx_is_descended(ctx), "vm_map_lock_ctx_is_descended");
			T_QUIET; T_ASSERT_TRUE(vm_map_lock_ctx_in_constant_submap(ctx), "vm_map_lock_ctx_in_constant_submap");
			check_is_entry_of_map(ctx->__parent_entry, orig_parent_map);
		} else {
			T_QUIET; T_ASSERT_FALSE(vm_map_lock_ctx_is_descended(ctx), "vm_map_lock_ctx_is_descended");
			T_QUIET; T_ASSERT_FALSE(vm_map_lock_ctx_in_constant_submap(ctx), "vm_map_lock_ctx_in_constant_submap");
			T_QUIET; T_ASSERT_NULL(ctx->__parent_entry, "parent map");
		}

		vm_map_address_t cur_startp = 0, cur_endp = 0;
		vm_map_size_t cur_sizep = 0;
		vm_map_lock_ctx_bounds(ctx, &cur_startp, &cur_endp, &cur_sizep);
		vm_object_offset_t cur_obj_offset;
		vm_map_lock_ctx_offset_bounds(ctx, &cur_obj_offset, NULL, NULL);
		vm_object_t obj = VME_OBJECT(entry);

		T_LOG("iter map=%p vme=%p   start=%llx  end=%llx  sz=%d  offset=%llx  obj=%p  in-submap=%d",
		    cur_map, entry, cur_startp, cur_endp, (int)cur_sizep / PAGE_SIZE, cur_obj_offset,
		    obj, (int)vm_map_lock_ctx_is_descended(ctx));
		check_is_entry_of_map(entry, cur_map);

		T_QUIET; T_ASSERT_EQ(vm_map_lock_ctx_to_parent_address(ctx, cur_startp), map_iter_offset, "offset match");
		map_iter_offset += cur_sizep;

		if (obj != cur_obj) {
			if (cur_obj != NULL) {
				obj_iter_offset = 0;
			}
			cur_obj = obj;
		}

		T_QUIET; T_ASSERT_EQ(obj_iter_offset, cur_obj_offset, "obj offset mismatch");
		obj_iter_offset += cur_sizep;
	}
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "vm_map_range_next_with_error last");
	T_QUIET; T_ASSERT_EQ(map_iter_offset, r_end, "reached end");

	vm_map_range_ex_unlock(ctx, &parent_map);
}

static void
print_map(vm_map_t map, const char* desc)
{
	T_LOG("*** %s:", desc);
	vm_map_entry_t entry = vm_map_first_entry(map);
	while (entry != vm_map_to_entry(map)) {
		T_LOG("  vme=%p  start=%llx  end=%llx  sz=%d  is_submap=%d",
		    entry, entry->vme_start, entry->vme_end,
		    (int)(entry->vme_end - entry->vme_start) / PAGE_SIZE, entry->is_sub_map);
		entry = entry->vme_next;
	}
}

T_DECL(ex_descend, "exclusive sealed submap descend")
{
	T_MOCK_pmap_shared_region_size_min_RET_PAGE_SIZE();
	vm_map_t parent_map, submap;
	setup_map_with_sealed(&parent_map, &submap);
	T_LOG("parent=%p  submap=%p", parent_map, submap);

	VM_MAP_LOCK_CTX_DECLARE(ctx);

	// start in parent, end in submap
	{
		vm_map_address_t r_start = MAP_BASE + 0x50000 + 1 * PAGE_SIZE; // middle of the first entry in parent map
		vm_map_address_t r_end =   r_start + 6 * PAGE_SIZE;            // middle of the second entry in the submap
		test_ex_descend(ctx, parent_map, r_start, r_end, PAGE_SIZE);
	}

	// start in submap, end in parent
	{
		vm_map_address_t r_start = MAP_BASE + 0x50000 + 3 * PAGE_SIZE; // middle of the first entry in the submap
		vm_map_address_t r_end =   r_start + 6 * PAGE_SIZE;            // middle of the third entry in the parent map
		test_ex_descend(ctx, parent_map, r_start, r_end, PAGE_SIZE);
	}

	// start in submap, end in submap
	{
		vm_map_address_t r_start = MAP_BASE + 0x50000 + 3 * PAGE_SIZE; // middle of the first entry in the submap
		vm_map_address_t r_end =   r_start + 4 * PAGE_SIZE;            // middle of the second entry in the submap
		test_ex_descend(ctx, parent_map, r_start, r_end, PAGE_SIZE);
	}

	// start in parent, end in parent
	{
		vm_map_address_t r_start = MAP_BASE + 0x50000 + 1 * PAGE_SIZE; // middle of the first entry in the parent map
		vm_map_address_t r_end =   r_start + 8 * PAGE_SIZE;            // middle of the third entry in the parent map
		test_ex_descend(ctx, parent_map, r_start, r_end, PAGE_SIZE);
	}

	print_map(parent_map, "parent");
	print_map(submap, "submap");
}

static void
preflight_on_constant_submap(vm_map_t parent_map, bool skip_submaps, vmrl_flags_t flags)
{
	VM_MAP_LOCK_CTX_DECLARE(ctx);

	vm_map_address_t r_start = MAP_BASE + 0x50000 + 1 * PAGE_SIZE; // middle of the first entry in the parent map
	vm_map_address_t r_end =   r_start + 8 * PAGE_SIZE;            // middle of the third entry in the parent map

	struct {
		vm_map_entry_t preflight_seen[10];
		int preflight_seen_count;
	} pfq, *pfq_ptr = &pfq;

	vm_map_lock_ctx_set_preflight(ctx, ^kern_return_t (vm_map_lock_ctx_t ctx, vm_map_entry_t entry) {
		T_LOG("preflight %d: %p  [%llx : %llx]  IS_submap=%d  IN_submap=%d", pfq_ptr->preflight_seen_count, entry,
		entry->vme_start, entry->vme_end, (int)entry->is_sub_map, (int)vm_map_lock_ctx_is_descended(ctx));
		T_QUIET; T_ASSERT_LE(pfq_ptr->preflight_seen_count, (int)countof(pfq_ptr->preflight_seen), "too many preflight entries");
		pfq_ptr->preflight_seen[pfq_ptr->preflight_seen_count++] = entry;
		return KERN_SUCCESS;
	});

	kern_return_t kr;
	if (vmrl_is_exclusive(flags)) {
		kr = vm_map_range_ex_lock(ctx, &parent_map, r_start, r_end, (vmrl_ex_flags_t) flags);
	} else {
		kr = vm_map_range_sh_lock(ctx, &parent_map, r_start, r_end, (vmrl_sh_flags_t) flags);
	}
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "lock-call");

	// check that the entries that we've seen in the preflight are exactly the same ones we're seeing
	// in the iteration, in the same order
	vm_map_entry_t entry;
	int range_idx = 0;
	while ((entry = vm_map_range_next(ctx)) != VM_MAP_ENTRY_NULL) {
		bool in_submap = vm_map_lock_ctx_is_descended(ctx);
		T_LOG("iter      %d: %p  [%llx : %llx]  IS_submap=%d  IN_submap=%d", range_idx, entry,
		    entry->vme_start, entry->vme_end, (int)entry->is_sub_map, in_submap);
		T_QUIET; T_ASSERT_LT(range_idx, pfq.preflight_seen_count, "too many entries in iteration");
		T_QUIET; T_ASSERT_EQ_PTR(entry, pfq.preflight_seen[range_idx], "same entry ptr");
		++range_idx;
	}
	T_QUIET; T_ASSERT_EQ(range_idx, pfq.preflight_seen_count, "different count in iteration and preflight");

	if (vmrl_is_exclusive(ctx)) {
		vm_map_range_ex_unlock(ctx, &parent_map);
	} else {
		vm_map_range_sh_unlock(ctx, &parent_map);
	}
}

/* verify that the preflight is being run on and only on the expected entries */
T_DECL(preflight_on_constant_submap, "preflight_on_constant_submap")
{
	T_MOCK_pmap_shared_region_size_min_RET_PAGE_SIZE();

	vm_map_t __block parent_map, submap;
	setup_map_with_sealed(&parent_map, &submap);

	T_LOG("\nshared - stream - no descend");
	preflight_on_constant_submap(parent_map, false, (vmrl_flags_t)  VMRL_SH_STREAM);

	T_LOG("\nshared - stream - yes descend");
	preflight_on_constant_submap(parent_map, true, (vmrl_flags_t) (VMRL_SH_STREAM | VMRL_SH_DESCEND_INTO_CONSTANT));

	T_LOG("\nshared - atomic - no descend");
	preflight_on_constant_submap(parent_map, false, (vmrl_flags_t) VMRL_SH_ATOMIC);

	T_LOG("\nshared - atomic - yes descend");
	preflight_on_constant_submap(parent_map, true, (vmrl_flags_t) (VMRL_SH_ATOMIC | VMRL_SH_DESCEND_INTO_CONSTANT));

	T_LOG("\nexclusive - stream - no descend");
	preflight_on_constant_submap(parent_map, false, (vmrl_flags_t) VMRL_EX_STREAM);

	T_LOG("\nexclusive - stream - yes descend");
	preflight_on_constant_submap(parent_map, true, (vmrl_flags_t)  (VMRL_EX_STREAM | VMRL_EX_DESCEND_INTO_CONSTANT));

	T_LOG("\nexclusive - atomic - no descend");
	preflight_on_constant_submap(parent_map, false, (vmrl_flags_t) VMRL_EX_ATOMIC);

	T_LOG("\nexclusive - atomic - yes descend");
	// When locking ATOMIC, the lock iteration doesn't descend in to the constant submap (because there's no
	// need to lock anything ther) but the iteration does descend into it and return the entries from it.
	preflight_on_constant_submap(parent_map, true, VMRL_EX_ATOMIC | VMRL_EX_DESCEND_INTO_CONSTANT);
}

T_DECL(atomic_lock_crossing_transparent_submap, "atomic_lock_crossing_transparent_submap")
{
	kern_return_t kr;

	// cross from parent to transparent submap
	{
		vm_map_t parent_map, submap;
		setup_transparent_map(&parent_map, &submap);

		vm_map_address_t r_start = MAP_BASE + 0x50000 + 1 * PAGE_SIZE; // middle of the first entry in the parent map
		vm_map_address_t r_end =   r_start + 2 * PAGE_SIZE;            // middle of the first entry in the submap

		T_ASSERT_PANIC_CONTAINS({
			VM_MAP_LOCK_CTX_DECLARE(ctx);
			kr = vm_map_range_ex_lock(ctx, &parent_map, r_start, r_end, VMRL_EX_ATOMIC);
		}, "operation not contained within submap", "crossing to submap should panic");
		// map ilock remains locked here
	}

	// cross from transparent submap to parent
	{
		vm_map_t parent_map, submap;
		setup_transparent_map(&parent_map, &submap);

		vm_map_address_t r_start = MAP_BASE + 0x50000 + 7 * PAGE_SIZE; // middle of the third entry in the submap
		vm_map_address_t r_end =   r_start + 2 * PAGE_SIZE;            // middle of the third entry in the parent map

		T_ASSERT_PANIC_CONTAINS({
			VM_MAP_LOCK_CTX_DECLARE(ctx);
			kr = vm_map_range_ex_lock(ctx, &parent_map, r_start, r_end, VMRL_EX_ATOMIC);
		}, "operation not contained within submap", "crossing from submap should panic");
		// map ilock remains locked here
	}
}

__static_testable vm_map_copy_t
vm_map_copy_allocate(uint16_t type, uint32_t pageshift);

__static_testable vm_map_entry_t
vm_map_copy_entry_create(vm_map_copy_t copy);

T_DECL(copy_clip_tests, "copy clip tests")
{
	vm_map_copy_t copy = vm_map_copy_allocate(VM_MAP_COPY_ENTRY_LIST, PAGE_SHIFT);
	copy->cpy_hdr.page_shift = (uint16_t)VM_MAP_PAGE_SHIFT(current_map());


	vm_map_entry_t entry = vm_map_copy_entry_create(copy);

	vm_map_address_t range_start = PAGE_SIZE * 10;
	vm_map_address_t range_end = PAGE_SIZE * 20;


	vm_map_address_t clip_start = PAGE_SIZE * 11;
	vm_map_address_t clip_end = PAGE_SIZE * 19;

	entry->vme_start = range_start;
	entry->vme_end = range_end;
	vm_map_copy_store_insert_tail(copy, entry);

	vm_map_copy_store_clip_start(copy, entry, clip_start);
	vm_map_copy_store_clip_end(copy, entry, clip_end);

	vm_map_entry_t prev = VME_PREV(entry);
	vm_map_entry_t next = entry->vme_next;

	T_ASSERT_EQ_ULLONG(entry->vme_start, clip_start, "start addr");
	T_ASSERT_EQ_ULLONG(entry->vme_end, clip_end, "end addr");

	T_ASSERT_EQ_ULLONG(prev->vme_start, range_start, "prev start");
	T_ASSERT_EQ_ULLONG(prev->vme_end, clip_start, "prev end");

	T_ASSERT_EQ_ULLONG(next->vme_start, clip_end, "next start");
	T_ASSERT_EQ_ULLONG(next->vme_end, range_end, "next end");

	T_ASSERT_EQ_INT(copy->cpy_hdr.nentries, 3, "right number of entries");

	T_ASSERT_PANIC({
		vm_map_copy_store_clip_start(copy, entry, clip_end + PAGE_SIZE);
	}, "clip start after entry end panics");
	T_ASSERT_PANIC({
		vm_map_copy_store_clip_end(copy, entry, clip_start - PAGE_SIZE);
	}, "clip end before entry start panics");
}

T_DECL(vm_map_found_entry_get_entry_tests, "vm_map_found_entry_get_entry tests")
{
	VM_MAP_FIND_LOCK_CTX_DECLARE(ctx);
	kern_return_t kr;
	vm_map_entry_t entry, new_entry;
	vm_map_t map;
	vm_map_address_t start = 0x10000;
	vm_map_address_t end = 0x100000;

	map = vm_test_alloc_map();
	entry = vm_test_add_map_entry(map, start, end);

	/* Check it panics before locking */
	T_ASSERT_PANIC({
		vm_map_found_entry_get_entry(ctx);
	}, "vmlc_locked");

	/* Test exclusive lock */
	kr = vm_map_find_entry_ex_locked(ctx, &map, start, VMRL_FIND_EX_DEFAULT);
	T_ASSERT_MACH_SUCCESS(kr, "lock entry by addr");
	T_ASSERT_EQ_PTR(entry, vm_map_found_entry_get_entry(ctx), "locked entry is the one expected");
	T_ASSERT_EQ_PTR(entry, vm_map_found_entry_get_entry(ctx), "calling it twice still works");
	vm_map_found_entry_ex_unlock(ctx, &map);

	/* And test shared */
	kr = vm_map_find_entry_sh_locked(ctx, &map, start, VMRL_FIND_SH_DEFAULT);
	T_ASSERT_MACH_SUCCESS(kr, "lock entry by addr");
	T_ASSERT_EQ_PTR(entry, vm_map_found_entry_get_entry(ctx), "locked entry is the one expected");
	T_ASSERT_EQ_PTR(entry, vm_map_found_entry_get_entry(ctx), "calling it twice still works");
	vm_map_found_entry_sh_unlock(ctx, &map);

	/* Check it panics after unlocking */
	T_ASSERT_PANIC({
		vm_map_found_entry_get_entry(ctx);
	}, "vmlc_locked");
}

T_DECL(vm_map_entry_sentinel_no_unlock, "Attempting to unlock a sentinel entry should cause a panic")
{
	VM_MAP_LOCK_CTX_DECLARE(ctx);
	kern_return_t kr;
	const vm_map_address_t start = 0x10000;
	const vm_map_address_t end = 0x100000;

	vm_map_t map = vm_test_alloc_map();
	const vm_map_t record_map = map;

	kr = vm_map_range_ex_lock(ctx, &map, start, end, VMRL_EX_ATOMIC_ALLOW_HOLES);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "Locking successful");
	vm_map_t map2 = vm_map_lock_ctx_get_map(ctx);
	T_ASSERT_EQ_PTR(map2, record_map, "map is as expected");
	T_QUIET; T_ASSERT_EQ(map2->hdr.nentries, 1, "Created sentinel");
	vm_map_entry_t sentinel = vm_map_range_ex_pop(ctx);
	T_ASSERT_NE_PTR(VM_MAP_ENTRY_NULL, sentinel, "Got non-null entry");
	T_ASSERT_TRUE(VME_IS_SENTINEL(sentinel), "Got a sentinel entry");
	vm_entry_assert_excl_owner(sentinel); // Sentinel entry is locked by us
	T_ASSERT_PANIC_CONTAINS({
		vm_entry_unlock_exclusive(map2, sentinel);
	}
	    ,
	    "unlock a sentinel entry",
	    "Attempting to unlock a sentinel entry should cause a panic");
	vm_map_range_ex_unlock(ctx, &map);
}

void
vm_map_insert_copy_entry_test(int vmmap_sealed, char *mapname)
{
	vm_map_t map;
	vm_map_copy_t copy;
	vm_map_entry_t entry, copy_entry;
	vm_map_address_t copyout_addr;
	vm_map_size_t copy_size = 0x4000;
	kern_return_t kr;

	/* Test 1: inserting into a normal map should result in a valid lock */
	copy = vm_map_copy_allocate(VM_MAP_COPY_ENTRY_LIST, PAGE_SHIFT);
	copy_entry = vm_map_copy_entry_create(copy);
	VM_ENTRY_ASSERT_LOCK_INVALID(copy_entry, VMEL_INVALID_REASON_COPY_ENTRY);

	entry = vm_map_copy_entry_create(copy);
	entry->vme_start = 0x0;
	entry->vme_end = copy_size;
	vm_map_copy_store_insert_tail(copy, entry);
	copy->size += copy_size;
	map = vm_test_alloc_map();
	map->vmmap_sealed = vmmap_sealed;

	kr = vm_map_copyout(map, &copyout_addr, copy);
	T_ASSERT_MACH_SUCCESS(kr, "copyout into %s", mapname);

	vm_map_ilk_lock(map);
	entry = vm_map_lookup(map, copyout_addr);
	vm_map_ilk_unlock(map);
	T_ASSERT_NOTNULL(entry, "entry found at copyout address in %s", mapname);
	VM_ENTRY_ASSERT_LOCK_VALID(entry);
}

T_DECL(vm_map_insert_copy_entry, "inserting a copy entry should update its lock type appropriately")
{
	vm_map_insert_copy_entry_test(VM_MAP_NOT_SEALED, "normal map");
	vm_map_insert_copy_entry_test(VM_MAP_WILL_BE_SEALED, "will-be-sealed map");
}

T_DECL(vm_map_seal_invalid_lock, "sealing a constant submap should invalidate entry locks")
{
	vm_map_t parent_map, submap;
	kern_return_t kr;

	setup_map_with_sealed(&parent_map, &submap);

	vm_map_entry_t entry;
	for (entry = vm_map_first_entry(submap);
	    entry != vm_map_to_entry(submap);
	    entry = entry->vme_next) {
		VM_ENTRY_ASSERT_LOCK_INVALID(entry, VMEL_INVALID_REASON_SEALED_SUBMAP);
		lck_rw_lock_shared(&submap->ilock);
		T_ASSERT_PANIC_CONTAINS({
			(void)vm_entry_lock_exclusive(submap, LCK_RW_TYPE_SHARED,
			entry, entry->vme_start, THREAD_UNINT);
		}, "invalid", "x-lock sealed submap entry panics");
		T_ASSERT_PANIC_CONTAINS({
			(void)vm_entry_lock_shared(submap, LCK_RW_TYPE_SHARED,
			entry, entry->vme_start, THREAD_UNINT);
		}, "invalid", "s-lock sealed submap entry panics");
		lck_rw_unlock_shared(&submap->ilock);
	}
}

T_DECL(range_lock_sealed_submap, "directly range locking a sealed submap should panic")
{
	vm_map_t parent_map, submap;
	VM_MAP_LOCK_CTX_DECLARE(ctx);

	setup_map_with_sealed(&parent_map, &submap);
	vm_map_address_t start = vm_map_first_entry(submap)->vme_start;
	vm_map_address_t end = vm_map_last_entry(submap)->vme_end;

	T_ASSERT_PANIC({
		(void)vm_map_range_sh_lock(ctx, &submap, start, end,
		VMRL_SH_ATOMIC);
	}, "sh/atomic on sealed submap panics");

	T_ASSERT_PANIC({
		(void)vm_map_range_sh_lock(ctx, &submap, start, end,
		VMRL_SH_STREAM);
	}, "sh/stream on sealed submap panics");

	T_ASSERT_PANIC({
		(void)vm_map_range_ex_lock(ctx, &submap, start, end,
		VMRL_EX_ATOMIC);
	}, "ex/atomic on sealed submap panics");

	T_ASSERT_PANIC({
		(void)vm_map_range_ex_lock(ctx, &submap, start, end,
		VMRL_EX_STREAM);
	}, "ex/stream on sealed submap panics");

	T_ASSERT_PANIC({
		(void)vm_map_range_sh_lock(ctx, &submap, start, end,
		VMRL_SH_ATOMIC | VMRL_SH_TRY_LOCK_ENTRY);
	}, "try-sh/atomic on sealed submap panics");

	T_ASSERT_PANIC({
		(void)vm_map_range_sh_lock(ctx, &submap, start, end,
		VMRL_SH_STREAM | VMRL_SH_TRY_LOCK_ENTRY);
	}, "try-sh/stream on sealed submap panics");

	T_ASSERT_PANIC({
		(void)vm_map_range_ex_lock(ctx, &submap, start, end,
		VMRL_EX_ATOMIC | VMRL_EX_TRY_LOCK_ENTRY);
	}, "try-ex/atomic on sealed submap panics");

	T_ASSERT_PANIC({
		(void)vm_map_range_ex_lock(ctx, &submap, start, end,
		VMRL_EX_STREAM | VMRL_EX_TRY_LOCK_ENTRY);
	}, "try-ex/stream on sealed submap panics");
}

T_DECL(vm_map_header_invalid_lock, "map header entry locks should be invalidated")
{
	vm_map_t map = vm_test_alloc_map();
	vmel_invalid_reason_t reason;

	reason = map->hdr.links.lock.vmel_invalid_reason;
	T_ASSERT_EQ(reason, VMEL_INVALID_REASON_MAP_HEADER,
	    "map header entry lock should be invalidated");

	vm_map_copy_t copy = vm_map_copy_allocate(VM_MAP_COPY_ENTRY_LIST, PAGE_SHIFT);
	reason = copy->c_u.hdr.links.lock.vmel_invalid_reason;
	T_ASSERT_EQ(reason, VMEL_INVALID_REASON_MAP_HEADER,
	    "copy map header entry lock should be invalidated");
}

/*
 * We can't easily make static assertions about bitfields, so we enforce this
 * property via testing.
 */
T_DECL(vm_entry_lock_valid, "vmel_valid and vmel_valid2 must be the same")
{
	struct vm_map_entry entry;
	bzero(&entry, sizeof(entry));
	T_ASSERT_FALSE(entry.links.lock.vmel_valid2, "zeroed lock => vmel_valid2=0");
	entry.links.lock.vmel_valid = 1;
	T_ASSERT_TRUE(entry.links.lock.vmel_valid2, "vmel_valid=1 => vmel_valid2=1");
}

T_DECL(vm_entry_invalid_lock_panic, "locking an invalid entry lock should panic")
{
	for (vmel_invalid_reason_t reason = (vmel_invalid_reason_t)0x1;
	    reason <= VMEL_INVALID_REASON_LAST_VALID;
	    reason <<= 1) {
		vm_map_t map = vm_test_alloc_map();
		vm_map_entry_t entry = vm_test_add_map_entry(map, PAGE_SIZE, PAGE_SIZE * 2);

		vm_map_ilk_lock(map);
		vm_entry_lock_init_invalid(entry, reason);
		T_ASSERT_PANIC({
			(void)vm_entry_lock_exclusive(map, LCK_RW_TYPE_SHARED,
			entry, entry->vme_start, THREAD_UNINT);
		}, "x-locking invalid lock (%#hx) panics", reason);

		vm_entry_lock_init_invalid(entry, reason);
		T_ASSERT_PANIC({
			(void)vm_entry_lock_shared(map, LCK_RW_TYPE_SHARED,
			entry, entry->vme_start, THREAD_UNINT);
		}, "s-locking invalid lock (%#hx) panics", reason);

		vm_entry_lock_init_invalid(entry, reason);
		T_ASSERT_PANIC({
			(void)vm_entry_try_lock_exclusive(entry);
		}, "x-try-locking invalid lock (%#hx) panics", reason);

		vm_entry_lock_init_invalid(entry, reason);
		T_ASSERT_PANIC({
			(void)vm_entry_try_lock_shared(entry);
		}, "s-try-locking invalid lock (%#hx) panics", reason);
	}
}

#define EX_LOCK_ENTRY(map, entry)                                                                       \
	do {                                                                                                \
	    T_QUIET; T_ASSERT_MACH_SUCCESS(                                                                 \
	        vm_entry_lock_exclusive(map, LCK_RW_TYPE_EXCLUSIVE, entry, entry->vme_start, THREAD_UNINT), \
	        "ex-lock entry" #entry);                                                                    \
	} while (0)

#define SH_LOCK_ENTRY(map, entry)                                                                    \
	do {                                                                                             \
	    T_QUIET; T_ASSERT_MACH_SUCCESS(                                                              \
	        vm_entry_lock_shared(map, LCK_RW_TYPE_EXCLUSIVE, entry, entry->vme_start, THREAD_UNINT), \
	        "sh-lock entry" #entry);                                                                 \
	} while (0)

#define CLEANUP_AFTER_PANIC(map, ctx)                                                           \
	do {                                                                                        \
	        lck_rw_unlock_shared_spin(&map->ilock);                                             \
	        *ctx = (struct vm_map_lock_ctx){0};                                                 \
	} while (0)

T_DECL(vm_map_lock_ctx_from_locked_entries_tests, "vm_map_lock_ctx_from_locked_entries tests")
{
	kern_return_t         kr;
	vm_map_entry_t        entry1, entry2, entry3, entry4;
	vm_map_t              map = vm_test_alloc_map();
	entry1 = vm_test_add_map_entry(map, 0x10000, 0x20000);
	entry2 = vm_test_add_map_entry(map, 0x20000, 0x30000);
	entry3 = vm_test_add_map_entry(map, 0x30000, 0x40000);
	entry4 = vm_test_add_map_entry(map, 0x50000, 0x60000);

	/*
	 * Call should succeed when every entry is exclusively locked by this thread.
	 */
	vm_map_ilk_lock(map);
	EX_LOCK_ENTRY(map, entry1);
	EX_LOCK_ENTRY(map, entry2);
	EX_LOCK_ENTRY(map, entry3);
	vm_map_ilk_unlock(map);

	VM_MAP_LOCK_CTX_DECLARE(ctx__test_success);
	T_QUIET; T_ASSERT_MACH_SUCCESS(
		vm_map_lock_ctx_from_locked_entries(ctx__test_success, &map, 0x10000, 0x30000),
		"create lock context from three excl-locked entries");
	vm_map_range_ex_unlock(ctx__test_success, &map);
	T_PASS("Building range from valid entries succeeds");

	/*
	 * Call should panic when entries are share-locked.
	 */
	vm_map_ilk_lock(map);
	SH_LOCK_ENTRY(map, entry1);
	vm_map_ilk_unlock(map);

	VM_MAP_LOCK_CTX_DECLARE(ctx__test_panic_shared);
	T_QUIET; T_ASSERT_PANIC({
		vm_map_lock_ctx_from_locked_entries(ctx__test_panic_shared, &map, 0x10000, 0x10000);
	}, "attempting build context from share-locked entries should panic");
	CLEANUP_AFTER_PANIC(map, ctx__test_panic_shared);
	vm_entry_unlock_shared(map, entry1);
	T_PASS("Building range from share-locked entries panics");

	/*
	 * Call should panic when first entry doesn't start at expected address.
	 */
	vm_map_ilk_lock(map);
	EX_LOCK_ENTRY(map, entry1);
	vm_map_ilk_unlock(map);

	VM_MAP_LOCK_CTX_DECLARE(ctx__test_panic_bad_start);
	T_QUIET; T_ASSERT_PANIC({
		vm_map_lock_ctx_from_locked_entries(ctx__test_panic_bad_start, &map, 0x14000, 0xC000);
	}, "should panic if entry doesn't start at given start address");
	CLEANUP_AFTER_PANIC(map, ctx__test_panic_bad_start);
	vm_entry_unlock_exclusive(map, entry1);
	T_PASS("Building range from entry that doesn't start at expected address should panic");

	/*
	 * Call should panic when last entry doesn't end at expected address.
	 */
	vm_map_ilk_lock(map);
	EX_LOCK_ENTRY(map, entry1);
	EX_LOCK_ENTRY(map, entry2);
	vm_map_ilk_unlock(map);

	VM_MAP_LOCK_CTX_DECLARE(ctx__test_panic_bad_end);
	T_QUIET; T_ASSERT_PANIC({
		vm_map_lock_ctx_from_locked_entries(ctx__test_panic_bad_end, &map, 0x10000, 0x1C000);
	}, "should panic if entry doesn't end at expected address");
	CLEANUP_AFTER_PANIC(map, ctx__test_panic_bad_end);
	vm_entry_unlock_exclusive(map, entry1);
	vm_entry_unlock_exclusive(map, entry2);
	T_PASS("Building range from entry that doesn't end at expected address should panic");

	/*
	 * Call should panic when there's a hole.
	 */
	vm_map_ilk_lock(map);
	EX_LOCK_ENTRY(map, entry3);
	EX_LOCK_ENTRY(map, entry4);
	vm_map_ilk_unlock(map);

	VM_MAP_LOCK_CTX_DECLARE(ctx__test_panic_hole);
	T_QUIET; T_ASSERT_PANIC({
		vm_map_lock_ctx_from_locked_entries(ctx__test_panic_hole, &map, 0x30000, 0x30000);
	}, "should panic if there's a hole");
	CLEANUP_AFTER_PANIC(map, ctx__test_panic_hole);
	vm_entry_unlock_exclusive(map, entry3);
	vm_entry_unlock_exclusive(map, entry4);
	T_PASS("Building range from non-contiguous entries should panic");

	/*
	 * Call should panic when entry is unlocked.
	 */
	VM_MAP_LOCK_CTX_DECLARE(ctx__test_panic_unlocked);
	T_QUIET; T_ASSERT_PANIC({
		vm_map_lock_ctx_from_locked_entries(ctx__test_panic_unlocked, &map, 0x10000, 0x10000);
	}, "should panic if entry is unlocked");
	CLEANUP_AFTER_PANIC(map, ctx__test_panic_unlocked);
	T_PASS("Building range from unlocked entry should panic");

	/*
	 * Call should panic when entry doesn't exist.
	 */
	VM_MAP_LOCK_CTX_DECLARE(ctx__test_panic_no_entry);
	T_QUIET; T_ASSERT_PANIC({
		vm_map_lock_ctx_from_locked_entries(ctx__test_panic_no_entry, &map, 0x80000, 0x10000);
	}, "should panic if entry doesn't exist");
	CLEANUP_AFTER_PANIC(map, ctx__test_panic_no_entry);
	T_PASS("Building range from non-existent entry should panic");
}

#undef EX_LOCK_ENTRY
#undef SH_LOCK_ENTRY
#undef CLEANUP_AFTER_PANIC

T_DECL(atomic_lock_before_vmgo, "Atomically lock a range before a guard object") {
	vm_map_t map;
	vm_map_entry_t entries[2];
	kern_return_t kr;
	vm_map_address_t start = PAGE_SIZE, mid = PAGE_SIZE * 2, end = PAGE_SIZE * 3;
	vm_map_size_t go_size = PAGE_SIZE * 2;

	VM_MAP_LOCK_CTX_DECLARE(ctx);

	assert(go_size > start);

	T_SETUPBEGIN;
	map = vm_test_alloc_map();
	vm_map_guard_object_slab_init(map);

	entries[0] = vm_test_add_map_entry(map, start, mid);
	entries[1] = vm_test_add_map_entry(map, mid, end);

	vm_map_address_t addr;
	kr = vm_map_enter(map, &addr, go_size, 0, VM_MAP_KERNEL_FLAGS_ANYWHERE(),
	    VM_OBJECT_NULL, 0, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
	T_SETUPEND;

	/*
	 * Lock the range containing entries 0 and 1.
	 * This should succeed as it contains no holes.
	 */
	kr = vm_map_range_ex_lock(ctx, &map, start, end, VMRL_EX_ATOMIC);
	T_ASSERT_MACH_SUCCESS(kr, "atomic: success when range contains no holes");
	vm_map_range_ex_unlock(ctx, &map);

	kr = vm_map_range_ex_lock(ctx, &map, start, end, VMRL_EX_ATOMIC_ALLOW_HOLES);
	T_ASSERT_MACH_SUCCESS(kr, "atomic-allow-holes: success when range contains no holes");
	vm_map_range_ex_unlock(ctx, &map);

	/*
	 * Delete entry 1, then try again.
	 * This should be handled according to the holes policy.
	 */
	T_SETUPBEGIN;
	kr = vm_map_remove_guard(map, mid, end, VM_MAP_REMOVE_NO_FLAGS, KMEM_GUARD_NONE);
	T_ASSERT_MACH_SUCCESS(kr, "delete entry 1");
	T_SETUPEND;

	kr = vm_map_range_ex_lock(ctx, &map, start, end, VMRL_EX_ATOMIC);
	T_ASSERT_MACH_ERROR(kr, KERN_INVALID_ADDRESS, "atomic: failure when range contains holes");

	kr = vm_map_range_ex_lock(ctx, &map, start, end, VMRL_EX_ATOMIC_ALLOW_HOLES);
	T_ASSERT_MACH_SUCCESS(kr, "atomic-allow-holes: success when range contains holes");
	vm_map_range_ex_unlock(ctx, &map);

	vm_map_deallocate(map);
}


T_DECL(atomic_lock_in_vmgo, "Atomically lock inside a guard object") {
	const vm_map_size_t slot_size = KiB(128);
	const vm_map_size_t size = slot_size - PAGE_SIZE;
	vm_map_t map;
	kern_return_t kr;

	VM_MAP_LOCK_CTX_DECLARE(ctx);

	T_SETUPBEGIN;
	map = vm_test_alloc_map();
	vm_map_guard_object_slab_init(map);

	/*
	 * Allocate a guard object.
	 */
	T_MOCK_SET_RETVAL(vmgo_chunk_select_random_slot, uint32_t, 0);
	vm_map_address_t addr;
	kr = vm_map_enter(map, &addr, size, 0, VM_MAP_KERNEL_FLAGS_ANYWHERE(),
	    VM_OBJECT_NULL, 0, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
	T_ASSERT_MACH_SUCCESS(kr, "allocate in guard object");
	T_SETUPEND;

	/*
	 * Atomic lock from [addr, addr+size) should succeed
	 */
	kr = vm_map_range_ex_lock(ctx, &map, addr, addr + size, VMRL_EX_ATOMIC);
	T_ASSERT_MACH_SUCCESS(kr, "atomic: lock within allocated slot succeeds");
	vm_map_range_ex_unlock(ctx, &map);

	kr = vm_map_range_ex_lock(ctx, &map, addr, addr + size, VMRL_EX_ATOMIC_ALLOW_HOLES);
	T_ASSERT_MACH_SUCCESS(kr, "atomic-allow-holes: lock within allocated slot succeeds");
	vm_map_range_ex_unlock(ctx, &map);

	/*
	 * Atomic lock from [addr, addr+slot_size) should be handled according
	 * to the holes policy
	 */
	kr = vm_map_range_ex_lock(ctx, &map, addr, addr + slot_size, VMRL_EX_ATOMIC);
	T_ASSERT_MACH_ERROR(kr, KERN_INVALID_ADDRESS,
	    "atomic: failure when range extends beyond allocation within slot");

	kr = vm_map_range_ex_lock(ctx, &map, addr, addr + slot_size, VMRL_EX_ATOMIC_ALLOW_HOLES);
	T_ASSERT_MACH_SUCCESS(kr,
	    "atomic-allow-holes: success when range extends beyond allocation within slot");
	vm_map_range_ex_unlock(ctx, &map);

	/*
	 * Atomic lock from [addr+slot_size, addr+2*slot_size) should fail as
	 * that slot is unallocated.
	 */
	kr = vm_map_range_ex_lock(ctx, &map, addr + slot_size, addr + 2 * slot_size, VMRL_EX_ATOMIC);
	T_ASSERT_MACH_ERROR(kr, KERN_INVALID_GUARD_OBJECT_SLOT,
	    "atomic: failure when range is in unallocated slot");

	kr = vm_map_range_ex_lock(ctx, &map, addr + slot_size, addr + 2 * slot_size, VMRL_EX_ATOMIC_ALLOW_HOLES);
	T_ASSERT_MACH_ERROR(kr, KERN_INVALID_GUARD_OBJECT_SLOT,
	    "atomic-allow-holes: failure when range is in unallocated slot");

	T_SETUPBEGIN;
	/*
	 * Fill in all of slots 0 and 1.
	 */
	kr = vm_map_enter(map, &addr, slot_size, 0,
	    VM_MAP_KERNEL_FLAGS_FIXED(.vmf_overwrite = true),
	    VM_OBJECT_NULL, 0, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
	T_ASSERT_MACH_SUCCESS(kr, "overwrite slot 0 with full slot_size allocation");

	T_MOCK_SET_RETVAL(vmgo_chunk_select_random_slot, uint32_t, 1);
	vm_map_address_t addr2;
	kr = vm_map_enter(map, &addr2, slot_size, 0, VM_MAP_KERNEL_FLAGS_ANYWHERE(),
	    VM_OBJECT_NULL, 0, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
	T_ASSERT_MACH_SUCCESS(kr, "allocate in slot 1");
	T_SETUPEND;

	/*
	 * Atomic lock from [addr, addr+2*slot_size) should fail due to
	 * straddling slot bounds.
	 */
	kr = vm_map_range_ex_lock(ctx, &map, addr, addr + 2 * slot_size, VMRL_EX_ATOMIC);
	T_ASSERT_MACH_ERROR(kr, KERN_INVALID_GUARD_OBJECT_SLOT,
	    "atomic: failure when range straddles slot bounds");

	kr = vm_map_range_ex_lock(ctx, &map, addr, addr + 2 * slot_size, VMRL_EX_ATOMIC_ALLOW_HOLES);
	T_ASSERT_MACH_ERROR(kr, KERN_INVALID_GUARD_OBJECT_SLOT,
	    "atomic-allow-holes: failure when range straddles slot bounds");

	/*
	 * Atomic lock from [addr-slot_size, addr+slot_size) should fail due
	 * to straddling chunk bounds.
	 */
	kr = vm_map_range_ex_lock(ctx, &map, addr - slot_size, addr + slot_size, VMRL_EX_ATOMIC);
	T_ASSERT_MACH_ERROR(kr, KERN_INVALID_GUARD_OBJECT_SLOT,
	    "atomic: failure when range straddles chunk bounds");

	kr = vm_map_range_ex_lock(ctx, &map, addr - slot_size, addr + slot_size, VMRL_EX_ATOMIC_ALLOW_HOLES);
	T_ASSERT_MACH_ERROR(kr, KERN_INVALID_GUARD_OBJECT_SLOT,
	    "atomic-allow-holes: failure when range straddles chunk bounds");

	vm_map_deallocate(map);
}

T_DECL(atomic_lock_into_vmgo,
    "Atomically lock a range containing a hole that starts outside a "
    "guard object chunk but ends inside it") {
	const vm_map_size_t slot_size = KiB(128);
	const vm_map_size_t size = slot_size - PAGE_SIZE;
	vm_map_t map;
	kern_return_t kr;

	VM_MAP_LOCK_CTX_DECLARE(ctx);

	T_SETUPBEGIN;
	map = vm_test_alloc_map();
	vm_map_guard_object_slab_init(map);

	/*
	 * Build the following layout:
	 *   A: an entry before the guard object chunk
	 *   B: a hole between the entry and the chunk
	 *   C: unallocated slot 0 of the guard object chunk
	 *   D: allocated slot 1 of the guard object chunk
	 *
	 * Start by allocating A as two pages. Then allocate the guard
	 * object in slot 1. Finally, delete the second page of A to
	 * create hole B between A and the chunk.
	 */
	vm_map_address_t a_start = PAGE_SIZE;
	vm_map_address_t b_end = PAGE_SIZE * 3;
	vm_test_add_map_entry(map, a_start, b_end);

	T_MOCK_SET_RETVAL(vmgo_chunk_select_random_slot, uint32_t, 1);
	vm_map_address_t addr;
	kr = vm_map_enter(map, &addr, size, 0, VM_MAP_KERNEL_FLAGS_ANYWHERE(),
	    VM_OBJECT_NULL, 0, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
	T_ASSERT_MACH_SUCCESS(kr, "allocate in guard object slot 1");

	/*
	 * Delete the second page of A to create hole B.
	 */
	vm_map_address_t b_start = PAGE_SIZE * 2;
	kr = vm_map_remove_guard(map, b_start, b_end,
	    VM_MAP_REMOVE_NO_FLAGS, KMEM_GUARD_NONE);
	T_ASSERT_MACH_SUCCESS(kr, "delete second page of A to create hole B");
	T_SETUPEND;

	/*
	 * VMRL_EX_ATOMIC[_ALLOW_HOLES] should fail because the sentinel
	 * for the hole would span from outside the chunk into slot 0,
	 * and the operation range crosses slot boundaries.
	 *
	 * We check guard object rules before checking for holes, so this
	 * error code wins for the holes-disallowed case.
	 */
	kr = vm_map_range_ex_lock(ctx, &map, a_start, addr + size,
	    VMRL_EX_ATOMIC);
	T_ASSERT_MACH_ERROR(kr, KERN_INVALID_GUARD_OBJECT_SLOT,
	    "atomic: failure when hole spans into guard object chunk");

	kr = vm_map_range_ex_lock(ctx, &map, a_start, addr + size,
	    VMRL_EX_ATOMIC_ALLOW_HOLES);
	T_ASSERT_MACH_ERROR(kr, KERN_INVALID_GUARD_OBJECT_SLOT,
	    "atomic-allow-holes: failure when hole spans into guard object chunk");

	vm_map_deallocate(map);
}

T_DECL(atomic_lock_at_end, "Atomically lock a range at the end of the map") {
	vm_map_t map;
	vm_map_entry_t entry;
	kern_return_t kr;
	vm_map_address_t start = PAGE_SIZE, end = PAGE_SIZE * 3;

	VM_MAP_LOCK_CTX_DECLARE(ctx);

	T_SETUPBEGIN;
	map = vm_test_alloc_map();
	entry = vm_test_add_map_entry(map, start, end);
	T_SETUPEND;

	kr = vm_map_range_ex_lock(ctx, &map, start, end, VMRL_EX_ATOMIC);
	T_ASSERT_MACH_SUCCESS(kr, "atomic: success when range contains no holes");
	vm_map_range_ex_unlock(ctx, &map);

	kr = vm_map_range_ex_lock(ctx, &map, start, end, VMRL_EX_ATOMIC_ALLOW_HOLES);
	T_ASSERT_MACH_SUCCESS(kr, "atomic-allow-holes: success when range contains no holes");
	vm_map_range_ex_unlock(ctx, &map);

	vm_map_deallocate(map);
}
