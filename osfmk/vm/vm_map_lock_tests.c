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

#include <vm/vm_test_utils_internal.h>

/*
 * Note to test authors:
 * This file is not listed in osfmk/conf/files, so it is not linked in normally
 * with the rest of the kernel.
 *
 * Instead, it is conditionally #included at the bottom of vm_map_lock.c.
 * Therefore, this file is able to access static helpers that are defined inside
 * vm_map_lock.c.
 */
#pragma mark - tests
#pragma clang optimize off

extern u_int32_t random(void);

static vm_map_entry_t
find_entry_ilocked(vm_map_t map, vm_map_offset_t start)
{
	assert_vm_map_ilk_owned_ignore_sealed(map, LCK_RW_TYPE_ANY);

	return vm_map_lookup(map, start) ?: vm_map_to_entry(map);
}

static vm_map_entry_t
find_entry_unlocked(vm_map_t map, vm_map_offset_t start)
{
	__vmrl_ilk_lock_shared_spin(map);
	vm_map_entry_t entry = find_entry_ilocked(map, start);
	__vmrl_ilk_unlock_shared_spin(map);
	return entry;
}

/*
 * Locking asserts
 */
static void
assert_range_is_unlocked_ilocked(vm_map_t map, vm_map_offset_t start, vm_map_offset_t end)
{
	vm_map_entry_t entry = find_entry_ilocked(map, start);

	while (!entry_is_map_end(map, entry) && end >= entry->vme_end) {
		vm_entry_lock_t state = os_atomic_load(&entry->vme_lock, relaxed);
		assert(!state.vmel_excl_locked);
		assert3u(state.vmel_read_count, ==, 0);
		entry = entry->vme_next;
	}
}

static void
assert_range_is_unlocked(vm_map_t map, vm_map_offset_t start, vm_map_offset_t end)
{
	__vmrl_ilk_lock_shared_spin(map);
	assert_range_is_unlocked_ilocked(map, start, end);
	__vmrl_ilk_unlock_shared_spin(map);
}

static void
assert_range_is_excl_locked_ilocked(vm_map_t map, vm_map_offset_t start, vm_map_offset_t end)
{
	vm_map_entry_t entry = find_entry_ilocked(map, start);
	while (!entry_is_map_end(map, entry) && end >= entry->vme_end) {
		vm_entry_assert_excl_owner(entry);
		entry = entry->vme_next;
	}
}

static void
assert_range_is_excl_locked(vm_map_t map, vm_map_offset_t start, vm_map_offset_t end)
{
	__vmrl_ilk_lock_shared_spin(map);
	assert_range_is_excl_locked_ilocked(map, start, end);
	__vmrl_ilk_unlock_shared_spin(map);
}

static void
assert_range_is_shared_locked(vm_map_t map, vm_map_offset_t start, vm_map_offset_t end)
{
	vm_map_entry_t entry = find_entry_unlocked(map, start);
	while (!entry_is_map_end(map, entry) && end >= entry->vme_end) {
		vm_entry_assert_shared_owner(entry);
		entry = entry->vme_next;
	}
}

static wait_result_t
vm_map_entry_lock_shared(vm_map_t map, vm_map_entry_t entry)
{
	kern_return_t kr;

	RANGE_LOCK_ASSERT(!entry_is_map_end(map, entry));

	__vmrl_ilk_lock_shared_spin(map);
	kr = vm_entry_lock_shared(map, LCK_RW_TYPE_SHARED_SPIN,
	    entry, entry->vme_start, THREAD_UNINT);
	__vmrl_ilk_unlock_shared_spin(map);

	return kr == KERN_SUCCESS ? THREAD_NOT_WAITING : THREAD_RESTART;
}

static void
vmrl_test_range_unlock(vm_map_lock_ctx_t ctx, vm_map_t *map)
{
	if (vmrl_is_exclusive(ctx)) {
		vm_map_range_ex_unlock(ctx, map);
	} else {
		vm_map_range_sh_unlock(ctx, map);
	}
}

static void
assert_vme_is_locked(vm_map_lock_ctx_t ctx, vm_map_entry_t entry)
{
	if (vm_map_entry_is_transparent_submap(entry)) {
		vm_entry_assert_not_owner(entry);
	} else if (vmrl_is_exclusive(ctx)) {
		vm_entry_assert_excl_owner(entry);
	} else {
		vm_entry_assert_shared_owner(entry);
	}
}

static void
assert_range_is_locked(
	vm_map_lock_ctx_t       ctx,
	vm_map_t                map,
	vm_map_address_t        start,
	vm_map_address_t        end)
{
	if (vmrl_is_exclusive(ctx)) {
		assert_range_is_excl_locked(map, start, end);
	} else {
		assert_range_is_shared_locked(map, start, end);
	}
}

static void
assert_entry_locked_sucessfully(vm_map_lock_ctx_t ctx, vm_map_t map, kern_return_t kr)
{
	assert3u(kr, ==, KERN_SUCCESS);
	assert3p(ctx->vmlc_vme, !=, NULL);
	assert3p(ctx->__original_map, ==, map);
	assert_vme_is_locked(ctx, ctx->vmlc_vme);
}

static void
assert_range_lock_state(vm_map_lock_ctx_t ctx)
{
	vm_map_offset_t  start = ctx->vmlc_req_start;
	vm_map_offset_t  end   = ctx->vmlc_req_end;
	vm_map_t         map   = ctx->vmlc_map;
	vm_map_entry_t   entry = ctx->vmlc_vme;

	if (vm_map_lock_ctx_in_constant_submap(ctx)) {
		start = ctx->__original_req_start;
		end   = ctx->__original_req_end;
		map   = ctx->__original_map;
		entry = ctx->__parent_entry;
	} else {
		if (vmrl_is_streaming(ctx)) {
			assert3u(start, >=, ctx->__original_req_start);
		} else {
			assert3u(start, ==, ctx->__original_req_start);
		}
		assert3u(end, ==, ctx->__original_req_end);
		assert3p(map, ==, ctx->__original_map);
	}

	assert3p(entry, !=, VM_MAP_ENTRY_NULL);

	if (vmrl_is_streaming(ctx)) {
		assert_range_is_unlocked(map, start, entry->vme_start);
		assert_vme_is_locked(ctx, entry);
		assert_range_is_unlocked(map, entry->vme_end, end);
	} else {
		assert_range_is_locked(ctx, map, start, end);
	}
}

static vm_map_entry_t
assert_next_entry(
	vm_map_lock_ctx_t       ctx,
	vm_map_t                map,
	vm_map_offset_t         start,
	vm_map_offset_t         end)
{
	vm_map_entry_t   entry;
	kern_return_t    kr;
	vm_map_address_t e_start, e_end;

	entry = vm_map_range_next_with_error(ctx, &kr);
	assert3u(kr, ==, KERN_SUCCESS);
	assert3p(entry, !=, VM_MAP_ENTRY_NULL);
	assert3u(entry->vme_start, ==, start);
	assert3u(entry->vme_end, ==, end);

	vm_map_lock_ctx_bounds_in_parent(ctx, &e_start, &e_end, NULL);
	assert3u(ctx->__original_req_start, <=, e_start);
	assert3u(e_end, <=, ctx->__original_req_end);
	if (map) {
		assert3p(ctx->vmlc_map, ==, map);
	}
	assert_range_lock_state(ctx);

	return entry;
}

__attribute__((overloadable))
static void
vmrl_test_range_unlock_assert_done(vm_map_lock_ctx_t ctx, kern_return_t want_kr, vm_map_t *map)
{
	vm_map_entry_t   entry;
	kern_return_t    kr;

	entry = vm_map_range_next_with_error(ctx, &kr);
	assert3u(kr, ==, want_kr);
	assert3p(entry, ==, VM_MAP_ENTRY_NULL);
	vmrl_test_range_unlock(ctx, map);
}

__attribute__((overloadable))
static void
vmrl_test_range_unlock_assert_done(vm_map_lock_ctx_t ctx, vm_map_t *map)
{
	vmrl_test_range_unlock_assert_done(ctx, KERN_SUCCESS, map);
}

static void
vmrl_test_want_n_entries(vm_map_lock_ctx_t ctx, size_t n)
{
	vm_map_offset_t  start = ctx->__original_req_start;
	vm_map_offset_t  end = ctx->__original_req_end;
	vm_map_t         map = ctx->vmlc_map;
	vm_map_entry_t   entry;
	kern_return_t    kr;

	for (size_t i = 0; i < n; i++) {
		entry = vm_map_range_next_with_error(ctx, &kr);
		assert3p(entry, !=, NULL);
		assert3u(kr, ==, KERN_SUCCESS);
		assert_vme_is_locked(ctx, entry);

		if (vmrl_is_streaming(ctx)) {
			assert_range_is_unlocked(map, start, entry->vme_start);
			assert_range_is_unlocked(map, entry->vme_end, end);
		} else {
			assert_range_is_locked(ctx, map, start, end);
		}
	}

	if (n >= 1 && vmrl_is_atomic(ctx) && end != VMRL_END_VA(map)) {
		// in the WHOLE_MAP check we're not expected to reach the end address
		vm_map_address_t e_end;

		vm_map_lock_ctx_bounds_in_parent(ctx, NULL, &e_end, NULL);
		assert3u(end, ==, e_end);
	}

	entry = vm_map_range_next_with_error(ctx, &kr);
	assert3p(entry, ==, NULL);
	assert3p(entry, ==, ctx->vmlc_vme);
	assert3u(kr, ==, KERN_SUCCESS);
}

#pragma mark lock tests

static void
vm_range_lock_test_basic_assumptions(void)
{
	vm_map_offset_t start = PAGE_SIZE, end = start + PAGE_SIZE;
	vm_map_entry_t entry;
	kern_return_t kr;
	vm_map_t map;
	VM_MAP_LOCK_CTX_DECLARE(ctx);

	/*
	 * Check basic assumptions of correctness the testing framework needs
	 * to hold true for it to work.
	 */

	map = vm_test_alloc_map();
	entry = vm_test_add_map_entry(map, start, end);

	printf("%s:    Check locking flags work and stick past unlock\n", __func__);

	kr = vm_map_range_ex_lock(ctx, &map, start, end, VMRL_EX_ATOMIC);
	assert3u(kr, ==, KERN_SUCCESS);
	assert(vmrl_is_exclusive(ctx));
	assert(!vmrl_is_shared(ctx));
	VM_ENTRY_ASSERT_EXCL_OWNER(entry);

	vm_map_range_ex_unlock(ctx, &map);
	VM_ENTRY_ASSERT_NOT_OWNER(entry);
	assert(vmrl_is_exclusive(ctx));
	assert(!vmrl_is_shared(ctx));

	kr = vm_map_range_sh_lock(ctx, &map, start, end, VMRL_SH_ATOMIC);
	assert3u(kr, ==, KERN_SUCCESS);
	assert(vmrl_is_shared(ctx));
	assert(!vmrl_is_exclusive(ctx));
	VM_ENTRY_ASSERT_SHARED_OWNER(entry);

	vm_map_range_sh_unlock(ctx, &map);
	VM_ENTRY_ASSERT_NOT_OWNER(entry);
	assert(vmrl_is_shared(ctx));
	assert(!vmrl_is_exclusive(ctx));
}

static void
vm_range_lock_test_lock_single_entry_shared(void)
{
	vm_map_t map = vm_test_alloc_map();
	vm_map_offset_t start = PAGE_SIZE * 100, end = start + PAGE_SIZE;
	vm_map_offset_t second_start = PAGE_SIZE * 99, second_end = second_start + PAGE_SIZE;

	printf("%s:    Lock the only entry in the map\n", __func__);
	vm_map_entry_t entry = vm_test_add_map_entry(map, start, end);

	wait_result_t wr = vm_map_entry_lock_shared(map, entry);
	assert(wr == THREAD_NOT_WAITING);
	vm_entry_assert_shared_owner(entry);
	vm_entry_unlock_shared(map, entry);
	vm_entry_assert_not_owner(entry);

	printf("%s:    Lock one of two entries in a map\n", __func__);
	vm_test_add_map_entry(map, second_start, second_end);

	wr = vm_map_entry_lock_shared(map, entry);
	assert(wr == THREAD_NOT_WAITING);
	vm_entry_assert_shared_owner(entry);
	vm_entry_unlock_shared(map, entry);
	vm_entry_assert_not_owner(entry);

	vm_map_destroy(map);
}

static void
vm_range_lock_test_lock_distinct_ranges(void)
{
	vm_map_t map = vm_test_alloc_map();
	vm_map_t map2 = map;
	vm_map_offset_t start = PAGE_SIZE, end = start + PAGE_SIZE;
	vm_map_offset_t second_start = end, second_end = end + PAGE_SIZE;
	kern_return_t kr;

	vm_test_add_map_entry(map, second_start, second_end);
	vm_test_add_map_entry(map, start, end);

	VM_MAP_LOCK_CTX_DECLARE(ctx);
	VM_MAP_LOCK_CTX_DECLARE(ctx2);

	printf("%s:    Lock one entry, then lock another while holding the first lock\n", __func__);
	kr = vm_map_range_ex_lock(ctx, &map, start, end, VMRL_EX_ATOMIC);
	assert3u(kr, ==, KERN_SUCCESS);
	kr = vm_map_range_ex_lock(ctx2, &map2, second_start, second_end, VMRL_EX_ATOMIC);
	assert3u(kr, ==, KERN_SUCCESS);
	assert_range_is_excl_locked(ctx->vmlc_map, start, end);
	assert_range_is_excl_locked(ctx2->vmlc_map, second_start, second_end);
	vm_map_range_ex_unlock(ctx, &map);
	vm_map_range_ex_unlock(ctx2, &map2);


	printf("%s:    Try the same thing but with different acquisition order\n", __func__);
	kr = vm_map_range_ex_lock(ctx2, &map2, second_start, second_end, VMRL_EX_ATOMIC);
	assert3u(kr, ==, KERN_SUCCESS);
	kr = vm_map_range_ex_lock(ctx, &map, start, end, VMRL_EX_ATOMIC);
	assert3u(kr, ==, KERN_SUCCESS);
	assert_range_is_excl_locked(ctx->vmlc_map, start, end);
	assert_range_is_excl_locked(ctx2->vmlc_map, second_start, second_end);
	vm_map_range_ex_unlock(ctx, &map);
	vm_map_range_ex_unlock(ctx2, &map2);

	printf("%s:    And with different unlock order\n", __func__);
	kr = vm_map_range_ex_lock(ctx2, &map2, second_start, second_end, VMRL_EX_ATOMIC);
	assert3u(kr, ==, KERN_SUCCESS);
	kr = vm_map_range_ex_lock(ctx, &map, start, end, VMRL_EX_ATOMIC);
	assert3u(kr, ==, KERN_SUCCESS);
	assert_range_is_excl_locked(ctx->vmlc_map, start, end);
	assert_range_is_excl_locked(ctx2->vmlc_map, second_start, second_end);
	vm_map_range_ex_unlock(ctx2, &map2);
	vm_map_range_ex_unlock(ctx, &map);

	vm_map_destroy(map);
}

static void
vm_range_lock_test_API_downgrade(void)
{
	vm_map_t map = vm_test_alloc_map();
	vm_map_offset_t start = PAGE_SIZE, end = start + PAGE_SIZE;
	vm_map_offset_t second_start = end, second_end = end + PAGE_SIZE;
	vm_map_offset_t third_start = second_end, third_end = third_start + PAGE_SIZE;
	vm_map_offset_t fourth_start = third_end + PAGE_SIZE, fourth_end = fourth_start + PAGE_SIZE;

	printf("%s:    Four entries: 1,2,3,GAP,4\n", __func__);
	vm_test_add_map_entry(map, fourth_start, fourth_end);
	vm_test_add_map_entry(map, third_start, third_end);
	vm_test_add_map_entry(map, second_start, second_end);
	vm_test_add_map_entry(map, start, end);

	VM_MAP_LOCK_CTX_DECLARE(ctx);
	kern_return_t kr;

	printf("%s:    Test an excl lock on one entry\n", __func__);
	kr = vm_map_range_ex_lock(ctx, &map, start, end,
	    VMRL_EX_ATOMIC | VMRL_RESOLVE_COW_AND_OBJ);
	assert3u(kr, ==, KERN_SUCCESS);
	vmrl_test_want_n_entries(ctx, 1);
	vm_map_range_ex_to_sh(ctx);
	assert3u(kr, ==, KERN_SUCCESS);
	vmrl_test_want_n_entries(ctx, 1);
	vm_map_range_sh_unlock(ctx, &map);
	assert_range_is_unlocked(map, start, end);

	printf("%s:    Test an excl lock on two neighboring entries, where an entry follows.\n", __func__);
	kr = vm_map_range_ex_lock(ctx, &map, start, second_end,
	    VMRL_EX_ATOMIC | VMRL_RESOLVE_COW_AND_OBJ);
	assert3u(kr, ==, KERN_SUCCESS);
	vmrl_test_want_n_entries(ctx, 2);
	vm_map_range_ex_to_sh(ctx);
	vmrl_test_want_n_entries(ctx, 2);
	vm_map_range_sh_unlock(ctx, &map);
	assert_range_is_unlocked(map, start, end);

	printf("%s:    Test an excl lock on two neighboring entries, where a gap follows.\n", __func__);
	kr = vm_map_range_ex_lock(ctx, &map, second_start, third_end,
	    VMRL_EX_ATOMIC | VMRL_RESOLVE_COW_AND_OBJ);
	assert3u(kr, ==, KERN_SUCCESS);
	vmrl_test_want_n_entries(ctx, 2);
	vm_map_range_ex_to_sh(ctx);
	vmrl_test_want_n_entries(ctx, 2);
	vm_map_range_sh_unlock(ctx, &map);
	assert_range_is_unlocked(map, start, end);

	vm_map_destroy(map);
}

static void
vm_range_lock_test_API_enumeration(vmrl_flags_t flags)
{
	#define DECLARE_A_RANGE(n, start, size) \
	        const vm_map_offset_t n ## _start = start; \
	        const vm_map_offset_t n ## _end = n ## _start + size; \

	DECLARE_A_RANGE(A, 1 * PAGE_SIZE, PAGE_SIZE);
	DECLARE_A_RANGE(B, 2 * PAGE_SIZE, PAGE_SIZE);
	DECLARE_A_RANGE(G, 3 * PAGE_SIZE, PAGE_SIZE);
	DECLARE_A_RANGE(C, 4 * PAGE_SIZE, PAGE_SIZE);
	VM_MAP_LOCK_CTX_DECLARE(ctx);
	kern_return_t kr;
	vm_map_t map;

	/* three entries like so: gap, A, B, gap, C, gap */
	map = vm_test_alloc_map();
	vm_map_t orig_map = map;
	vm_test_add_map_entry(map, C_start, C_end);
	vm_test_add_map_entry(map, B_start, B_end);
	vm_test_add_map_entry(map, A_start, A_end);

	printf("%s(%#x):    Lock a range with no entries\n", __func__, flags);
	kr = __vmrl_lock(ctx, &map, 0, A_start, flags);
	switch (vmrl_mode(flags)) {
	case VMRL_ATOMIC_ALLOW_HOLES:
		assert3u(kr, ==, KERN_SUCCESS);
		assert_next_entry(ctx, orig_map, 0, A_start);
		vmrl_test_range_unlock_assert_done(ctx, &map);
		break;
	default:
		assert3u(kr, ==, KERN_INVALID_ADDRESS);
		assert(ctx->vmlc_vme == NULL);
		assert(ctx->vmlc_map == NULL);
		break;
	}
	assert_range_is_unlocked(map, 0, A_end);

	printf("%s(%#x):    Test a range with [A]\n", __func__, flags);
	kr = __vmrl_lock(ctx, &map, A_start, A_end, flags);
	assert3u(kr, ==, KERN_SUCCESS);
	assert_next_entry(ctx, orig_map, A_start, A_end);
	vmrl_test_range_unlock_assert_done(ctx, &map);
	assert_range_is_unlocked(map, A_start, C_end);

	printf("%s(%#x):    Lock a range with [gap, A]\n", __func__, flags);
	kr = __vmrl_lock(ctx, &map, 0, A_end, flags);
	switch (vmrl_mode(flags)) {
	case VMRL_ATOMIC:
	case VMRL_STREAM_NO_HOLES:
		assert3u(kr, ==, KERN_INVALID_ADDRESS);
		break;
	case VMRL_ATOMIC_ALLOW_HOLES:
		assert3u(kr, ==, KERN_SUCCESS);
		assert_next_entry(ctx, orig_map, 0, A_start);
		assert_next_entry(ctx, orig_map, A_start, A_end);
		vmrl_test_range_unlock_assert_done(ctx, &map);
		break;
	case VMRL_STREAM:
		assert3u(kr, ==, KERN_SUCCESS);
		assert_next_entry(ctx, orig_map, A_start, A_end);
		vmrl_test_range_unlock_assert_done(ctx, &map);
		break;
	}
	assert_range_is_unlocked(map, A_start, C_end);

	printf("%s(%#x):    Lock a range with [B, gap]\n", __func__, flags);
	kr = __vmrl_lock(ctx, &map, B_start, G_end, flags);
	switch (vmrl_mode(flags)) {
	case VMRL_ATOMIC:
		assert3u(kr, ==, KERN_INVALID_ADDRESS);
		break;
	case VMRL_ATOMIC_ALLOW_HOLES:
		assert3u(kr, ==, KERN_SUCCESS);
		assert_next_entry(ctx, orig_map, B_start, B_end);
		assert_next_entry(ctx, orig_map, G_start, G_end);
		vmrl_test_range_unlock_assert_done(ctx, &map);
		break;
	case VMRL_STREAM:
		assert3u(kr, ==, KERN_SUCCESS);
		assert_next_entry(ctx, orig_map, B_start, B_end);
		vmrl_test_range_unlock_assert_done(ctx, &map);
		break;
	case VMRL_STREAM_NO_HOLES:
		assert3u(kr, ==, KERN_SUCCESS);
		assert_next_entry(ctx, orig_map, B_start, B_end);
		vmrl_test_range_unlock_assert_done(ctx, KERN_INVALID_ADDRESS, &map);
		break;
	}
	assert_range_is_unlocked(map, A_start, C_end);

	printf("%s(%#x):    Lock a range with [A, B]\n", __func__, flags);
	kr = __vmrl_lock(ctx, &map, A_start, B_end, flags);
	assert3u(kr, ==, KERN_SUCCESS);
	assert_next_entry(ctx, orig_map, A_start, A_end);
	assert_next_entry(ctx, orig_map, B_start, B_end);
	vmrl_test_range_unlock_assert_done(ctx, &map);
	assert_range_is_unlocked(map, A_start, C_end);

	printf("%s(%#x):    Lock a range with [B, gap, C]\n", __func__, flags);
	kr = __vmrl_lock(ctx, &map, B_start, C_end, flags);
	switch (vmrl_mode(flags)) {
	case VMRL_ATOMIC:
		assert3u(kr, ==, KERN_INVALID_ADDRESS);
		break;
	case VMRL_ATOMIC_ALLOW_HOLES:
		assert3u(kr, ==, KERN_SUCCESS);
		assert_next_entry(ctx, orig_map, B_start, B_end);
		assert_next_entry(ctx, orig_map, G_start, G_end);
		assert_next_entry(ctx, orig_map, C_start, C_end);
		vmrl_test_range_unlock_assert_done(ctx, &map);
		break;
	case VMRL_STREAM:
		assert3u(kr, ==, KERN_SUCCESS);
		assert_next_entry(ctx, orig_map, B_start, B_end);
		assert_next_entry(ctx, orig_map, C_start, C_end);
		vmrl_test_range_unlock_assert_done(ctx, &map);
		break;
	case VMRL_STREAM_NO_HOLES:
		assert3u(kr, ==, KERN_SUCCESS);
		assert_next_entry(ctx, orig_map, B_start, B_end);
		vmrl_test_range_unlock_assert_done(ctx, KERN_INVALID_ADDRESS, &map);
		break;
	}
	assert_range_is_unlocked(map, A_start, C_end);

	printf("%s(%#x):    Lock a range with [A, B], A skip-prepare\n", __func__, flags);
	ctx->vmlc_preflight = ^kern_return_t (vm_map_lock_ctx_t vctx, vm_map_entry_t vme) {
		(void)vctx;
		if (vme->vme_start == A_start) {
			return VMRL_ERR_SKIP_PREPARE;
		}
		return KERN_SUCCESS;
	};
	kr = __vmrl_lock(ctx, &map, A_start, B_end, flags);
	assert_next_entry(ctx, orig_map, A_start, A_end); /* skip-prepare still returns the entry */
	assert_next_entry(ctx, orig_map, B_start, B_end);
	vmrl_test_range_unlock_assert_done(ctx, &map);
	assert_range_is_unlocked(map, A_start, C_end);

	printf("%s(%#x):    Lock a range with [A, B], A denied\n", __func__, flags);
	ctx->vmlc_preflight = ^kern_return_t (vm_map_lock_ctx_t vctx, vm_map_entry_t vme) {
		(void)vctx;
		return vme->vme_start == A_start ? KERN_DENIED : KERN_SUCCESS;
	};
	kr = __vmrl_lock(ctx, &map, A_start, B_end, flags);
	if (vmrl_is_atomic(flags)) {
		assert3u(kr, ==, KERN_DENIED);
	} else {
		vmrl_test_range_unlock_assert_done(ctx, KERN_DENIED, &map);
	}
	ctx->vmlc_preflight = NULL;
	assert_range_is_unlocked(map, A_start, C_end);

	printf("%s(%#x):    Lock a range with [A, B], B denied\n", __func__, flags);
	ctx->vmlc_preflight = ^kern_return_t (vm_map_lock_ctx_t vctx, vm_map_entry_t vme) {
		(void)vctx;
		return vme->vme_start == B_start ? KERN_DENIED : KERN_SUCCESS;
	};
	kr = __vmrl_lock(ctx, &map, A_start, B_end, flags);
	if (vmrl_is_atomic(flags)) {
		assert3u(kr, ==, KERN_DENIED);
	} else {
		assert_next_entry(ctx, orig_map, A_start, A_end);
		vmrl_test_range_unlock_assert_done(ctx, KERN_DENIED, &map);
	}
	ctx->vmlc_preflight = NULL;
	assert_range_is_unlocked(map, A_start, C_end);


	vm_map_destroy(map);

	#undef DECLARE_A_RANGE
}

static void
vm_range_lock_test_clip(bool stream)
{
	vm_map_t map = vm_test_alloc_map();
	vm_map_offset_t start = 0x10000, end = 0x20000;
	vm_map_offset_t second_start = 0x20000, second_end = 0x30000;
	kern_return_t kr;
	vmrl_ex_flags_t flags = stream ? VMRL_EX_STREAM : VMRL_EX_ATOMIC;

	vm_test_add_map_entry(map, second_start, second_end);
	vm_test_add_map_entry(map, start, end);


	VM_MAP_LOCK_CTX_DECLARE(ctx);

	printf("%s(%d):    Test an excl lock that clips end\n", __func__, stream);
	kr = vm_map_range_ex_lock(ctx, &map, start, 0x14000, flags);
	assert3u(kr, ==, KERN_SUCCESS);
	vmrl_test_want_n_entries(ctx, 1);
	vm_map_range_ex_unlock(ctx, &map);
	assert_range_is_unlocked(map, start, second_end);

	printf("%s(%d):    Test an excl lock on range that is now clipped\n", __func__, stream);
	kr = vm_map_range_ex_lock(ctx, &map, start, end, flags);
	assert3u(kr, ==, KERN_SUCCESS);
	vmrl_test_want_n_entries(ctx, 2);
	vm_map_range_ex_unlock(ctx, &map);
	assert_range_is_unlocked(map, start, second_end);

	printf("%s(%d):    Test an excl lock that clips start\n", __func__, stream);
	kr = vm_map_range_ex_lock(ctx, &map, 0x18000, second_end, flags);
	assert3u(kr, ==, KERN_SUCCESS);
	vmrl_test_want_n_entries(ctx, 2);
	vm_map_range_ex_unlock(ctx, &map);
	assert_range_is_unlocked(map, start, second_end);

	printf("%s(%d):    Test an excl lock on the whole range\n", __func__, stream);
	kr = vm_map_range_ex_lock(ctx, &map, start, second_end, flags);
	assert3u(kr, ==, KERN_SUCCESS);
	vmrl_test_want_n_entries(ctx, 4);
	vm_map_range_ex_unlock(ctx, &map);
	assert_range_is_unlocked(map, start, second_end);

	vm_map_destroy(map);
}

static vm_map_t
setup_nested_submap(vm_map_address_t start, vm_map_address_t end, vm_map_t *submap)
{
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, 0xfffffffffffff, 0);

	vm_map_address_t submap_entry_start = 0x1000000000;
	vm_map_address_t submap_entry_end = 0x2000000000;
	vm_map_address_t submap_entry_size = submap_entry_end - submap_entry_start;

	pmap_t pmap_nested = pmap_create_options(NULL, 0, PMAP_CREATE_64BIT | PMAP_CREATE_NESTED);
#if defined(__arm64__)
	pmap_set_nested(pmap_nested);
#endif /* defined(__arm64__) */
#if CODE_SIGNING_MONITOR
	csm_setup_nested_address_space(pmap_nested, start, end - start);
#endif
	pmap_set_shared_region(map->pmap, pmap_nested, start, end - start);
	*submap = vm_map_create_options(pmap_nested, 0, 0xfffffffffffff, 0);
	(*submap)->is_nested_map = TRUE;
	(*submap)->vmmap_sealed = VM_MAP_WILL_BE_SEALED;

	vm_object_t object = vm_object_allocate(submap_entry_size, (*submap)->serial_id);
	object->copy_strategy = MEMORY_OBJECT_COPY_DELAY;
	kern_return_t kr = vm_map_enter(*submap, &submap_entry_start,
	    submap_entry_size, 0,
	    VM_MAP_KERNEL_FLAGS_FIXED(), object, 0,
	    false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
	assert3u(kr, ==, KERN_SUCCESS);

	vm_map_reference(*submap);
	kr = vm_map_enter(map, &start, end - start, 0,
	    VM_MAP_KERNEL_FLAGS_FIXED(.vmkf_submap = TRUE, .vmkf_nested_pmap =  TRUE), (vm_object_t)(uintptr_t) *submap, submap_entry_start,
	    true, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
	assert3u(kr, ==, KERN_SUCCESS);
	return map;
}

static void
vm_range_lock_test_pmap_unnest(bool stream)
{
	vm_map_address_t start = 0x180000000ULL;
	vm_map_address_t end = start + 0x180000000ULL;
	vm_map_t submap;
	vm_map_t map = setup_nested_submap(start, end, &submap);
	kern_return_t kr;
	vmrl_ex_flags_t flags = stream ? VMRL_EX_STREAM : VMRL_EX_ATOMIC;
	vm_map_entry_t entry;

	VM_MAP_LOCK_CTX_DECLARE(ctx);

	printf("%s(%d):    Test an excl lock that clips end (and clips due to pmap unnest, stream)\n", __func__, stream);
	kr = vm_map_range_ex_lock(ctx, &map, start, 0x180004000ULL, flags);
	assert3u(kr, ==, KERN_SUCCESS);
	entry = vm_map_range_next(ctx);
	assert3u(entry->use_pmap, ==, false);

	entry = vm_map_range_next(ctx);
	assert3p(entry, ==, VM_MAP_ENTRY_NULL);

	vm_map_range_ex_unlock(ctx, &map);
	assert_range_is_unlocked(map, start, end);

	printf("%s(%d):    Test ending on a boundary, expecting 3 total entries\n", __func__, stream);
	kr = vm_map_range_ex_lock(ctx, &map, start, 0x184000000, flags);
	assert3u(kr, ==, KERN_SUCCESS);
	int num_unnested_entries = 3;
#ifdef __x86_64__
	num_unnested_entries = 2;
#endif
	for (int i = 0; i < num_unnested_entries; i++) {
		entry = vm_map_range_next(ctx);
		assert3u(entry->use_pmap, ==, false);
	}
	entry = vm_map_range_next(ctx);
	assert3p(entry, ==, VM_MAP_ENTRY_NULL);

	vm_map_range_ex_unlock(ctx, &map);
	assert_range_is_unlocked(map, start, end);

	printf("%s(%d):    Test that we can start in the middle of a range\n", __func__, stream);
	kr = vm_map_range_ex_lock(ctx, &map, 0x184004000, 0x186000000, flags);
	assert3u(kr, ==, KERN_SUCCESS);
	entry = vm_map_range_next(ctx);
	assert3u(entry->use_pmap, ==, false);

	entry = vm_map_range_next(ctx);
	assert3p(entry, ==, VM_MAP_ENTRY_NULL);
	vm_map_range_ex_unlock(ctx, &map);
	assert_range_is_unlocked(map, start, end);

	vm_map_destroy(map);
}

static void
vm_range_lock_test_unlock_midway(vmrl_flags_t flags)
{
	vm_map_t map = vm_test_alloc_map();
	vm_map_t orig_map = map;
	vm_map_offset_t first_start = 0x10000, first_end = 0x20000;
	vm_map_offset_t second_start = 0x20000, second_end = 0x30000;
	kern_return_t kr;
	VM_MAP_LOCK_CTX_DECLARE(ctx);
	vm_map_entry_t entries[2];
	entries[1] = vm_test_add_map_entry(map, second_start, second_end);
	entries[0] = vm_test_add_map_entry(map, first_start, first_end);

	/* Create an object and make the entries needs_copy */
	for (unsigned int i = 0; i < map->hdr.nentries; i++) {
		__vmrl_ilk_lock_exclusive(map);
		kr = vm_entry_lock_exclusive(map, LCK_RW_TYPE_EXCLUSIVE,
		    entries[i], entries[i]->vme_start, THREAD_UNINT);
		assert(kr == KERN_SUCCESS);
		__vmrl_ilk_unlock_exclusive(map);
		VME_OBJECT_SET(entries[i], vm_object_allocate(0x4000, map->serial_id), false, 0);
		vm_entry_unlock_exclusive(map, entries[i]);
		entries[i]->needs_copy = true;
	}

	kr = __vmrl_lock(ctx, &map, first_start, second_end, flags);
	assert3u(kr, ==, KERN_SUCCESS);
	(void)vm_map_range_next_with_error(ctx, &kr);
	assert_entry_locked_sucessfully(ctx, orig_map, kr);
	(void)vm_map_range_next(ctx);
	vmrl_test_range_unlock(ctx, &map);
	assert_range_is_unlocked(map, first_start, second_end);

	/* Make sure no refs leaked */
	for (unsigned int i = 0; i < map->hdr.nentries; i++) {
		vm_object_t object = VME_OBJECT(entries[i]);
		assert(entries[i]->needs_copy);
		assert(object->ref_count == 1);
		vm_object_deallocate(object);
	}
}

static void
vm_range_lock_test_stream_drop_then_advance(vmrl_flags_t how, bool with_advance)
{
	vm_map_t map = vm_test_alloc_map();
	vm_map_t orig_map = map;
	vm_map_offset_t first_start = 0x10000, first_end = 0x20000;
	vm_map_offset_t second_start = 0x20000, second_end = 0x30000;
	vm_map_offset_t third_start = 0x30000, third_end = 0x50000;
	kern_return_t kr;
	VM_MAP_LOCK_CTX_DECLARE(ctx);
	vm_map_entry_t entries[3];

	entries[2] = vm_test_add_map_entry(map, third_start, third_end);
	entries[1] = vm_test_add_map_entry(map, second_start, second_end);
	entries[0] = vm_test_add_map_entry(map, first_start, first_end);

	/* Create an object and make the entries needs_copy */
	for (unsigned int i = 0; i < map->hdr.nentries; i++) {
		__vmrl_ilk_lock_exclusive(map);
		kr = vm_entry_lock_exclusive(map, LCK_RW_TYPE_EXCLUSIVE,
		    entries[i], entries[i]->vme_start, THREAD_UNINT);
		assert(kr == KERN_SUCCESS);
		__vmrl_ilk_unlock_exclusive(map);
		VME_OBJECT_SET(entries[i], vm_object_allocate(0x4000, map->serial_id), false, 0);
		vm_entry_unlock_exclusive(map, entries[i]);
		entries[i]->needs_copy = true;
	}

	kr = __vmrl_lock(ctx, &map, first_start, (third_start + third_end) / 2,
	    how | VMRL_STREAM);
	assert3u(kr, ==, KERN_SUCCESS);

	(void)vm_map_range_stream_next_with_error(ctx, &kr);
	assert_entry_locked_sucessfully(ctx, orig_map, kr);

	if (with_advance) {
		vm_map_range_stream_drop(ctx);
	} else {
		vm_map_range_stream_drop_without_advance(ctx);
	}
	assert(ctx->vmlc_vme == NULL);
	vm_entry_assert_not_owner(entries[0]);

	(void)vm_map_range_stream_next_with_error(ctx, &kr);
	assert_entry_locked_sucessfully(ctx, orig_map, kr);
	if (!with_advance) {
		vm_entry_assert_owner(entries[0]);
		(void)vm_map_range_stream_next_with_error(ctx, &kr);
	}
	vm_entry_assert_not_owner(entries[0]); /* first entry should still be unlocked */
	/* Don't explicitly drop this one to exercise dropped -> (not dropped) and (not dropped) -> dropped. */

	(void)vm_map_range_stream_next_with_error(ctx, &kr);
	assert_entry_locked_sucessfully(ctx, orig_map, kr);
	vm_entry_assert_not_owner(entries[0]); /* first entry should still be unlocked */
	vm_entry_assert_not_owner(entries[1]);

	if (with_advance) {
		vm_map_range_stream_drop(ctx);
	} else {
		vm_map_range_stream_drop_without_advance(ctx);
	}
	assert(ctx->vmlc_vme == NULL);
	vm_entry_assert_not_owner(entries[0]);
	vm_entry_assert_not_owner(entries[1]);
	vm_entry_assert_not_owner(entries[2]);

	(void)vm_map_range_stream_next_with_error(ctx, &kr);
	if (!with_advance) {
		vm_entry_assert_owner(entries[2]);
		(void)vm_map_range_stream_next_with_error(ctx, &kr);
	}
	assert3u(kr, ==, KERN_SUCCESS);
	assert(ctx->vmlc_vme == NULL);
	assert_range_is_unlocked(vm_map_lock_ctx_get_map(ctx), first_start, third_end);

	vmrl_test_range_unlock(ctx, &map);
	assert_range_is_unlocked(map, first_start, third_end);

	/* Make sure no refs leaked */
	int expected_ref_counts[3] = {
		[0] = 1,
		[1] = 1,
		[2] = vmrl_is_exclusive(how) ? 2 : 1, /* Clipping the last entry will add a reference to the object. */
	};
	for (unsigned int i = 0; i < 3; i++) {
		vm_object_t object = VME_OBJECT(entries[i]);
		assert(entries[i]->needs_copy);
		assert(object->ref_count == expected_ref_counts[i]);
		vm_object_deallocate(object);
	}
}

struct submap_entry_spec {
	vm_map_address_t start;
	vm_map_size_t end;
	bool needs_copy;
};
void setup_transparent_submap(vm_map_address_t start, vm_map_address_t end, struct submap_entry_spec *entries,
    int nentries, vm_map_t * parent_map, vm_map_t * submap);

/*
 * Make sure that streaming modes appropriately handle a hole at the end of
 * a transparent submap.
 */
static void
vm_range_lock_test_transparent_submap_hole_at_end(vmrl_flags_t how)
{
	assert(!(how & VMRL_NO_DESCEND_TRANSPARENT));
	assert(how & _VMRL_STREAM_INTERNAL);

	vm_map_t map, orig_map, submap;
	kern_return_t kr;
	vm_map_entry_t parent_entry;
	VM_MAP_LOCK_CTX_DECLARE(ctx);

	vm_map_address_t submap_start = 0x180000000ULL;
	vm_map_address_t submap_end = submap_start * 2;
	vm_map_address_t range_start = submap_start - PAGE_SIZE;
	vm_map_address_t range_end = submap_end + PAGE_SIZE;

	struct submap_entry_spec entry_spec[] = {
		{ .start = submap_start, .end = submap_end - PAGE_SIZE, .needs_copy = false },
		/* intentional PAGE_SIZE hole at the end of the transparent submap */
	};

	setup_transparent_submap(submap_start, submap_end, entry_spec, ARRAY_COUNT(entry_spec), &map, &submap);
	orig_map = map;

	(void)vm_test_add_map_entry(map, range_start, submap_start);
	(void)vm_test_add_map_entry(map, submap_end, range_end);

	kr = __vmrl_lock(ctx, &map, range_start, range_end, how);
	assert3u(kr, ==, KERN_SUCCESS);

	/* Lock the entry before the transparent submap */
	(void)vm_map_range_stream_next_with_error(ctx, &kr);
	assert_entry_locked_sucessfully(ctx, orig_map, kr);

	/* Lock the transparent submap entry  */
	(void)vm_map_range_stream_next_with_error(ctx, &kr);
	assert_entry_locked_sucessfully(ctx, orig_map, kr);
	parent_entry = find_entry_unlocked(orig_map, submap_start);
	vm_entry_assert_not_owner(parent_entry);

	/* When we ascend to lock the next entry, we should handle the hole */
	(void)vm_map_range_stream_next_with_error(ctx, &kr);
	if (how & _VMRL_NO_HOLES) {
		assert3u(kr, ==, KERN_INVALID_ADDRESS);
		vm_entry_assert_not_owner(parent_entry->vme_next);
	} else {
		assert_entry_locked_sucessfully(ctx, orig_map, kr);
	}
	vmrl_test_range_unlock(ctx, &map);
}

/*
 * Make sure that streaming modes appropriately handle holes at the beginning
 * of a transparent submap.
 */
static void
vm_range_lock_test_transparent_submap_hole_at_beginning(vmrl_flags_t how)
{
	assert(!(how & VMRL_NO_DESCEND_TRANSPARENT));
	assert(how & _VMRL_STREAM_INTERNAL);

	vm_map_t map, orig_map, submap;
	kern_return_t kr;
	vm_map_entry_t parent_entry, child_entry;
	VM_MAP_LOCK_CTX_DECLARE(ctx);

	vm_map_address_t submap_start = 0x180000000ULL;
	vm_map_address_t submap_end = submap_start * 2;
	vm_map_address_t range_start = submap_start - PAGE_SIZE;
	vm_map_address_t range_end = submap_end;

	/* Create a transparent submap with a hole at the beginning */
	struct submap_entry_spec entry_spec[] = {
		{ .start = submap_start + PAGE_SIZE, .end = submap_end, .needs_copy = false },
		/* intentional PAGE_SIZE hole at the beginning of the transparent submap */
	};

	setup_transparent_submap(submap_start, submap_end, entry_spec, ARRAY_COUNT(entry_spec), &map, &submap);
	orig_map = map;

	(void)vm_test_add_map_entry(map, range_start, submap_start);

	kr = __vmrl_lock(ctx, &map, range_start, range_end, how);
	assert3u(kr, ==, KERN_SUCCESS);

	/* Lock the entry before the transparent submap */
	(void)vm_map_range_stream_next_with_error(ctx, &kr);
	assert_entry_locked_sucessfully(ctx, orig_map, kr);

	/* Attempt to lock the first entry in the transparent submap */
	(void)vm_map_range_stream_next_with_error(ctx, &kr);
	parent_entry = find_entry_unlocked(orig_map, submap_start);
	vm_entry_assert_not_owner(parent_entry);
	if (how & _VMRL_NO_HOLES) {
		assert3u(kr, ==, KERN_INVALID_ADDRESS);
		child_entry = find_entry_unlocked(submap, submap_start + PAGE_SIZE);
		vm_entry_assert_not_owner(child_entry);
	} else {
		assert_entry_locked_sucessfully(ctx, orig_map, kr);
	}
	vmrl_test_range_unlock(ctx, &map);
}

/*
 * Make sure that streaming modes appropriately handle holes before
 * transparent submap.
 */
static void
vm_range_lock_test_transparent_submap_after_hole(vmrl_flags_t how)
{
	assert(!(how & VMRL_NO_DESCEND_TRANSPARENT));
	assert(how & _VMRL_STREAM_INTERNAL);

	vm_map_t map, orig_map, submap;
	kern_return_t kr;
	vm_map_entry_t parent_entry, child_entry;
	VM_MAP_LOCK_CTX_DECLARE(ctx);

	vm_map_address_t submap_start = 0x180000000ULL;
	vm_map_address_t submap_end = submap_start * 2;
	vm_map_address_t range_start = submap_start - (2 * PAGE_SIZE);
	vm_map_address_t range_end = submap_end;

	struct submap_entry_spec entry_spec[] = {
		{ .start = submap_start, .end = submap_end, .needs_copy = false },
	};

	setup_transparent_submap(submap_start, submap_end, entry_spec, ARRAY_COUNT(entry_spec), &map, &submap);
	orig_map = map;

	(void)vm_test_add_map_entry(map, range_start, submap_start - PAGE_SIZE);

	kr = __vmrl_lock(ctx, &map, range_start, range_end, how);
	assert3u(kr, ==, KERN_SUCCESS);

	/* Lock the entry before the transparent submap */
	(void)vm_map_range_stream_next_with_error(ctx, &kr);
	assert_entry_locked_sucessfully(ctx, orig_map, kr);

	/* Attempt to lock the transparent submap entry */
	(void)vm_map_range_stream_next_with_error(ctx, &kr);
	parent_entry = find_entry_unlocked(orig_map, submap_start);
	vm_entry_assert_not_owner(parent_entry);
	if (how & _VMRL_NO_HOLES) {
		assert3u(kr, ==, KERN_INVALID_ADDRESS);
		child_entry = find_entry_unlocked(submap, submap_start);
		vm_entry_assert_not_owner(child_entry);
	} else {
		assert_entry_locked_sucessfully(ctx, orig_map, kr);
	}
	vmrl_test_range_unlock(ctx, &map);
}

/*
 * Make sure that streaming modes appropriately handle holes after
 * a transparent submap.
 */
static void
vm_range_lock_test_transparent_submap_before_hole(vmrl_flags_t how)
{
	assert(!(how & VMRL_NO_DESCEND_TRANSPARENT));
	assert(how & _VMRL_STREAM_INTERNAL);

	vm_map_t map, orig_map, submap;
	kern_return_t kr;
	vm_map_entry_t parent_entry;
	VM_MAP_LOCK_CTX_DECLARE(ctx);

	vm_map_address_t submap_start = 0x180000000ULL;
	vm_map_address_t submap_end = submap_start * 2;
	vm_map_address_t range_start = submap_start;
	vm_map_address_t range_end = submap_end + (2 * PAGE_SIZE);

	struct submap_entry_spec entry_spec[] = {
		{ .start = submap_start, .end = submap_end, .needs_copy = false },
	};

	setup_transparent_submap(submap_start, submap_end, entry_spec, ARRAY_COUNT(entry_spec), &map, &submap);
	orig_map = map;

	/* Add an entry after the submap with a PAGE_SIZE gap */
	(void)vm_test_add_map_entry(map, submap_end + PAGE_SIZE, range_end);

	kr = __vmrl_lock(ctx, &map, range_start, range_end, how);
	assert3u(kr, ==, KERN_SUCCESS);

	/* Lock the transparent submap entry */
	(void)vm_map_range_stream_next_with_error(ctx, &kr);
	assert_entry_locked_sucessfully(ctx, orig_map, kr);
	parent_entry = find_entry_unlocked(orig_map, submap_start);
	vm_entry_assert_not_owner(parent_entry);

	/* When we ascend to lock the next entry, we should handle the hole */
	(void)vm_map_range_stream_next_with_error(ctx, &kr);
	if (how & _VMRL_NO_HOLES) {
		assert3u(kr, ==, KERN_INVALID_ADDRESS);
		vm_entry_assert_not_owner(parent_entry->vme_next);
	} else {
		assert_entry_locked_sucessfully(ctx, orig_map, kr);
	}
	vmrl_test_range_unlock(ctx, &map);
}

struct test_preflight_result {
	vm_address_t start;
	vm_address_t end;
	vm_map_entry_t entry;
};

struct test_preflight_entry_config {
	vm_map_offset_t start;
	vm_map_offset_t end;
	vm_map_entry_t  entry;
	kern_return_t   preflight_result;

	// Indicates that we should create the vm_entry.  If cleared it's expected that the entry
	// was created as part of a submap setup.
	bool            create;
};

const unsigned int n_preflight_results = 8;

struct test_map_spec {
	const char            *name;
	struct test_preflight_entry_config *entries;
	unsigned int           n_entries;
	vm_map_offset_t        range_start;
	vm_map_offset_t        range_end;

	// Results updated by the test
	struct test_preflight_result    preflight_results[n_preflight_results];
	unsigned int           n_valid_preflight_results;

	// Adjustment for how many preflights were called twice
	int                    preflights_recalled;
};

static void
vm_range_lock_test_unblock_waiters(thread_call_param_t param0, thread_call_param_t param1)
{
	vm_map_t map = (vm_map_t)param0;
	vm_map_entry_t entry = (vm_map_entry_t)param1;
	kern_return_t kr;

	__vmrl_ilk_lock_exclusive(map);
	kr = vm_entry_lock_exclusive(map, LCK_RW_TYPE_EXCLUSIVE,
	    entry, entry->vme_start, THREAD_UNINT);
	assert3u(kr, ==, KERN_SUCCESS);

	vm_entry_wakeup_kunwire_waiters(entry);

	vm_entry_unlock_exclusive(map, entry);
	__vmrl_ilk_unlock_exclusive(map);
}


static kern_return_t
vm_range_lock_test_preflight_preflight(
	struct test_map_spec *spec,
	vm_map_entry_t vme
#ifndef __BUILDING_XNU_LIB_UNITTEST__
	, thread_call_t unblock_waiters
#endif /* __BUILDING_XNU_LIB_UNITTEST__*/
	)
{
	assert3u(spec->n_valid_preflight_results, <, n_preflight_results);
	struct test_preflight_result new_entry = {
		.start = vme->vme_start,
		.end = vme->vme_end,
		.entry = vme,
	};
	spec->preflight_results[spec->n_valid_preflight_results++] = new_entry;

	assert3u(vme->vme_start, !=, 0);
	assert3u(vme->vme_end, !=, 0);

	for (unsigned int i = 0; i < spec->n_entries; i++) {
		if (spec->entries[i].start == vme->vme_start &&
		    spec->entries[i].end == vme->vme_end) {
			kern_return_t result = spec->entries[i].preflight_result;
			// Reset the preflight_result so that we don't end up in an
			// infinite loop of error returns if we retry.
			spec->entries[i].preflight_result = KERN_SUCCESS;
			if (result == VMRL_ERR_WAIT_FOR_KUNWIRE) {
#ifndef __BUILDING_XNU_LIB_UNITTEST__
				// Start the low priority thread call to unblock us
				thread_call_enter1(unblock_waiters,
				    (thread_call_param_t)spec->entries[i].entry);
#else /* __BUILDING_XNU_LIB_UNITTEST__ */
				panic("unexpected VMRL_ERR_WAIT_FOR_KUNWIRE");
#endif /* __BUILDING_XNU_LIB_UNITTEST__ */
				spec->preflights_recalled++;
			}
			return result;
		}
	}

	return KERN_SUCCESS;
}

static void
vm_range_lock_test_preflight(vmrl_flags_t flags, kern_return_t expected_result, struct test_map_spec *spec, vm_map_t map)
{
	printf("%s:    Preflight over %s with flags %#x\n", __func__, spec->name, flags);

	for (unsigned int i = 0; i < spec->n_entries; i++) {
		if (spec->entries[i].create) {
			vm_map_entry_t new_entry;
			new_entry = vm_test_add_map_entry(map, spec->entries[i].start, spec->entries[i].end);
			bool lock_success = vm_entry_try_lock_exclusive(new_entry);
			assert(lock_success);
			VME_OBJECT_SET(new_entry, vm_object_allocate(0x4000, map->serial_id), false, 0);
			if (spec->entries[i].preflight_result != VMRL_ERR_SETUP_SYMMETRIC_COW) {
				new_entry->needs_copy = true;
			}
			vm_entry_unlock_exclusive(map, new_entry);
			spec->entries[i].entry = new_entry;
		}
	}

#ifndef __BUILDING_XNU_LIB_UNITTEST__
	thread_call_t unblock_waiters = thread_call_allocate_with_priority(&vm_range_lock_test_unblock_waiters,
	    (thread_call_param_t)map,
	    THREAD_CALL_PRIORITY_LOW);
#else /* __BUILDING_XNU_LIB_UNITTEST__ */
	(void)vm_range_lock_test_unblock_waiters;
#endif /* __BUILDING_XNU_LIB_UNITTEST__ */

	VM_MAP_LOCK_CTX_DECLARE(ctx);
	vm_map_lock_preflight_t test_preflight = ^kern_return_t (__unused vm_map_lock_ctx_t vctx, vm_map_entry_t vme) {
		return vm_range_lock_test_preflight_preflight(
			spec,
			vme
#ifndef __BUILDING_XNU_LIB_UNITTEST__
			, unblock_waiters
#endif /* __BUILDING_XNU_LIB_UNITTEST__ */
			);
	};
	vm_map_lock_ctx_set_preflight(ctx, test_preflight);

	int entries_returned_by_lock = 0;
	kern_return_t kr = __vmrl_lock(ctx, &map, spec->range_start, spec->range_end, flags);

	if (kr != KERN_SUCCESS) {
		goto done;
	}

	if (vmrl_is_streaming(flags)) {
		while (vm_map_range_next_with_error(ctx, &kr)) {
			assert3u(kr, ==, KERN_SUCCESS);
			entries_returned_by_lock++;
		}
	}

	if (vmrl_is_atomic(flags)) {
		// Check that the whole range is locked
		vm_address_t cursor = spec->range_start;
		vm_map_entry_t entry;
		while ((entry = vm_map_range_next_with_error(ctx, &kr))) {
			assert3u(kr, ==, KERN_SUCCESS);
			if (!vm_map_lock_ctx_in_constant_submap(ctx)) {
				if (!VME_IS_SENTINEL(entry)) {
					assert_vme_is_locked(ctx, entry);
				}

				if (!(flags & VMRL_DESCEND_INTO_CONSTANT)) {
					assert3u(entry->vme_start, ==, cursor);
					cursor = entry->vme_end;
				}
			}
			entries_returned_by_lock++;
		}
		if (!(flags & VMRL_DESCEND_INTO_CONSTANT)) {
			assert3u(cursor, ==, spec->range_end);
		}
	}

	vmrl_test_range_unlock(ctx, &map);

	if (kr == KERN_SUCCESS) {
		assert(entries_returned_by_lock ==
		    spec->n_valid_preflight_results - spec->preflights_recalled);
	}

done:
	assert3u(kr, ==, expected_result);

#ifndef __BUILDING_XNU_LIB_UNITTEST__
	thread_call_free(unblock_waiters);
#endif /* __BUILDING_XNU_LIB_UNITTEST__ */
}

static void
vm_range_lock_test_preflight_empty_range(vmrl_flags_t flags)
{
	kern_return_t expected_result;
	struct test_preflight_entry_config test_map[] = {
		{ .start = 0x10000, .end = 0x40000, .preflight_result = KERN_RPC_TERMINATE_ORPHAN, .create = false },
	};

	if (vmrl_mode(flags) == VMRL_ATOMIC_ALLOW_HOLES) {
		expected_result = test_map[0].preflight_result;
	} else {
		expected_result = KERN_INVALID_ADDRESS;
	}

	struct test_map_spec test_spec = {
		.name = "empty range",
		.entries = test_map,
		.n_entries = 1,
		.range_start = 0x10000,
		.range_end = 0x40000,
		.preflight_results = {},
		.n_valid_preflight_results = 0,
		.preflights_recalled = 0,
	};

	vm_map_t map = vm_test_alloc_map();

	vm_range_lock_test_preflight(flags, expected_result, &test_spec, map);

	vm_map_deallocate(map);

	if (vmrl_mode(flags) == VMRL_ATOMIC_ALLOW_HOLES) {
		assert3u(test_spec.n_valid_preflight_results, ==, 1);
		assert3u(test_spec.preflight_results[0].start, ==, 0x10000);
		assert3u(test_spec.preflight_results[0].end, ==, 0x40000);
	} else {
		assert3u(test_spec.n_valid_preflight_results, ==, 0);
	}
}

static void
vm_range_lock_test_preflight_single_range(vmrl_flags_t flags, kern_return_t expected_result)
{
	struct test_preflight_entry_config test_map[] = {
		{ .start = 0x10000, .end = 0x40000, .preflight_result = KERN_SUCCESS, .create = true },
	};

	struct test_map_spec test_spec = {
		.name = "single range",
		.entries = test_map,
		.n_entries = 1,
		.range_start = 0x10000,
		.range_end = 0x40000,
		.preflight_results = {},
		.n_valid_preflight_results = 0,
		.preflights_recalled = 0,
	};

	vm_map_t map = vm_test_alloc_map();

	vm_range_lock_test_preflight(flags, expected_result, &test_spec, map);

	vm_map_deallocate(map);

	assert3u(test_spec.n_valid_preflight_results, ==, 1);
	assert3u(test_spec.preflight_results[0].start, ==, 0x10000);
	assert3u(test_spec.preflight_results[0].end, ==, 0x40000);
}

static void
vm_range_lock_test_preflight_single_range_unwire(vmrl_flags_t flags, kern_return_t expected_result)
{
#ifndef __BUILDING_XNU_LIB_UNITTEST__ /* disabled for unit-test, see rdar://154654416 */
	struct test_preflight_entry_config test_map[] = {
		{ .start = 0x10000, .end = 0x40000, .preflight_result = VMRL_ERR_WAIT_FOR_KUNWIRE, .create = true },
	};

	struct test_map_spec test_spec = {
		.name = "single range requiring unwire",
		.entries = test_map,
		.n_entries = 1,
		.range_start = 0x10000,
		.range_end = 0x40000,
		.preflight_results = {},
		.n_valid_preflight_results = 0,
		.preflights_recalled = 0,
	};

	vm_map_t map = vm_test_alloc_map();

	vm_range_lock_test_preflight(flags, expected_result, &test_spec, map);

	vm_map_deallocate(map);

	assert3u(test_spec.n_valid_preflight_results, ==, 2);
	assert3u(test_spec.preflight_results[0].start, ==, 0x10000);
	assert3u(test_spec.preflight_results[0].end, ==, 0x40000);
	assert3u(test_spec.preflight_results[1].start, ==, 0x10000);
	assert3u(test_spec.preflight_results[1].end, ==, 0x40000);
#else
#pragma unused(flags, expected_result)
#endif /* __BUILDING_XNU_LIB_UNITTEST__ */
}

static void
vm_range_lock_test_preflight_multiple_disjoint_with_upgrade(vmrl_flags_t flags, kern_return_t expected_result)
{
	struct test_preflight_entry_config test_map[] = {
		{ .start = 0x10000, .end = 0x20000, .preflight_result = KERN_SUCCESS, .create = true },
		{ .start = 0x30000, .end = 0x40000, .preflight_result = VMRL_ERR_SETUP_SYMMETRIC_COW, .create = true },
	};

	struct test_map_spec test_spec = {
		.name = "single range requiring upgrade",
		.entries = test_map,
		.n_entries = 2,
		.range_start = 0x10000,
		.range_end = 0x40000,
		.preflight_results = {},
		.n_valid_preflight_results = 0,
		.preflights_recalled = 0,
	};

	vm_map_t map = vm_test_alloc_map();

	vm_range_lock_test_preflight(flags, expected_result, &test_spec, map);

	vm_map_deallocate(map);

	if (expected_result == KERN_SUCCESS) {
		if (vmrl_is_streaming(flags)) {
			assert3u(test_spec.n_valid_preflight_results, ==, 2);
			assert3u(test_spec.preflight_results[0].start, ==, 0x10000);
			assert3u(test_spec.preflight_results[0].end, ==, 0x20000);
			assert3u(test_spec.preflight_results[1].start, ==, 0x30000);
			assert3u(test_spec.preflight_results[1].end, ==, 0x40000);
		} else {
			assert3u(test_spec.n_valid_preflight_results, ==, 3);
			assert3u(test_spec.preflight_results[0].start, ==, 0x10000);
			assert3u(test_spec.preflight_results[0].end, ==, 0x20000);
			assert3u(test_spec.preflight_results[1].start, ==, 0x20000);
			assert3u(test_spec.preflight_results[1].end, ==, 0x30000);
			assert3u(test_spec.preflight_results[2].start, ==, 0x30000);
			assert3u(test_spec.preflight_results[2].end, ==, 0x40000);
		}
	} else {
		// Even in the failure case we get through the first preflight
		assert3u(test_spec.n_valid_preflight_results, ==, 1);
		assert3u(test_spec.preflight_results[0].start, ==, 0x10000);
		assert3u(test_spec.preflight_results[0].end, ==, 0x20000);
	}
}

static void
vm_range_lock_test_preflight_multiple_contiguous(vmrl_flags_t flags, kern_return_t expected_result)
{
	struct test_preflight_entry_config test_map[] = {
		{ .start = 0x10000, .end = 0x20000, .preflight_result = KERN_SUCCESS, .create = true },
		{ .start = 0x20000, .end = 0x30000, .preflight_result = KERN_SUCCESS, .create = true },
		{ .start = 0x30000, .end = 0x40000, .preflight_result = KERN_SUCCESS, .create = true },
	};

	struct test_map_spec test_spec = {
		.name = "contiguous range",
		.entries = test_map,
		.n_entries = 3,
		.range_start = 0x10000,
		.range_end = 0x40000,
		.preflight_results = {},
		.n_valid_preflight_results = 0,
		.preflights_recalled = 0,
	};

	vm_map_t map = vm_test_alloc_map();

	vm_range_lock_test_preflight(flags, expected_result, &test_spec, map);

	vm_map_deallocate(map);

	assert3u(test_spec.n_valid_preflight_results, ==, 3);
	assert3u(test_spec.preflight_results[0].start, ==, 0x10000);
	assert3u(test_spec.preflight_results[0].end, ==, 0x20000);
	assert3u(test_spec.preflight_results[1].start, ==, 0x20000);
	assert3u(test_spec.preflight_results[1].end, ==, 0x30000);
	assert3u(test_spec.preflight_results[2].start, ==, 0x30000);
	assert3u(test_spec.preflight_results[2].end, ==, 0x40000);
}

static void
vm_range_lock_test_preflight_multiple_disjoint(vmrl_flags_t flags, kern_return_t expected_result)
{
	struct test_preflight_entry_config test_map[] = {
		{ .start = 0x10000, .end = 0x1C000, .preflight_result = KERN_SUCCESS, .create = true },
		{ .start = 0x20000, .end = 0x2C000, .preflight_result = KERN_SUCCESS, .create = true },
		{ .start = 0x30000, .end = 0x40000, .preflight_result = KERN_SUCCESS, .create = true },
	};

	struct test_map_spec test_spec = {
		.name = "disjoint range",
		.entries = test_map,
		.n_entries = 3,
		.range_start = 0x10000,
		.range_end = 0x40000,
		.preflight_results = {},
		.n_valid_preflight_results = 0,
		.preflights_recalled = 0,
	};

	vm_map_t map = vm_test_alloc_map();

	vm_range_lock_test_preflight(flags, expected_result, &test_spec, map);

	vm_map_deallocate(map);

	if (expected_result == KERN_SUCCESS) {
		if (vmrl_is_streaming(flags)) {
			assert3u(test_spec.n_valid_preflight_results, ==, 3);
			assert3u(test_spec.preflight_results[0].start, ==, 0x10000);
			assert3u(test_spec.preflight_results[0].end, ==, 0x1C000);
			assert3u(test_spec.preflight_results[1].start, ==, 0x20000);
			assert3u(test_spec.preflight_results[1].end, ==, 0x2C000);
			assert3u(test_spec.preflight_results[2].start, ==, 0x30000);
			assert3u(test_spec.preflight_results[2].end, ==, 0x40000);
		} else {
			// Sentinels added in the atomic case
			assert3u(test_spec.n_valid_preflight_results, ==, 5);
			assert3u(test_spec.preflight_results[0].start, ==, 0x10000);
			assert3u(test_spec.preflight_results[0].end, ==, 0x1C000);
			assert3u(test_spec.preflight_results[1].start, ==, 0x1C000);
			assert3u(test_spec.preflight_results[1].end, ==, 0x20000);
			assert3u(test_spec.preflight_results[2].start, ==, 0x20000);
			assert3u(test_spec.preflight_results[2].end, ==, 0x2C000);
			assert3u(test_spec.preflight_results[3].start, ==, 0x2C000);
			assert3u(test_spec.preflight_results[3].end, ==, 0x30000);
			assert3u(test_spec.preflight_results[4].start, ==, 0x30000);
			assert3u(test_spec.preflight_results[4].end, ==, 0x40000);
		}
	}
}

static void
vm_range_lock_test_preflight_multiple_disjoint_streaming(vmrl_flags_t flags, kern_return_t expected_result)
{
	struct test_preflight_entry_config test_map[] = {
		{ .start = 0x10000, .end = 0x1C000, .preflight_result = KERN_SUCCESS, .create = true },
		{ .start = 0x20000, .end = 0x2C000, .preflight_result = KERN_SUCCESS, .create = true },
		{ .start = 0x30000, .end = 0x40000, .preflight_result = KERN_SUCCESS, .create = true },
	};

	struct test_map_spec test_spec = {
		.name = "disjoint range \"streaming\"",
		.entries = test_map,
		.n_entries = 3,
		.range_start = 0x10000,
		.range_end = 0x40000,
		.preflight_results = {},
		.n_valid_preflight_results = 0,
		.preflights_recalled = 0,
	};

	vm_map_t map = vm_test_alloc_map();

	vm_range_lock_test_preflight(flags, expected_result, &test_spec, map);

	vm_map_deallocate(map);

	assert3u(test_spec.n_valid_preflight_results, ==, 1);
	assert3u(test_spec.preflight_results[0].start, ==, 0x10000);
	assert3u(test_spec.preflight_results[0].end, ==, 0x1C000);
}

static void
vm_range_lock_test_preflight_contiguous_with_error(vmrl_flags_t flags, kern_return_t expected_result)
{
	struct test_preflight_entry_config test_map[] = {
		{ .start = 0x10000, .end = 0x20000, .preflight_result = KERN_SUCCESS, .create = true },
		{ .start = 0x20000, .end = 0x30000, .preflight_result = KERN_FAILURE, .create = true },
		{ .start = 0x30000, .end = 0x40000, .preflight_result = KERN_SUCCESS, .create = true },
	};

	struct test_map_spec test_spec = {
		.name = "contiguous range with embedded error",
		.entries = test_map,
		.n_entries = 3,
		.range_start = 0x10000,
		.range_end = 0x40000,
		.preflight_results = {},
		.n_valid_preflight_results = 0,
		.preflights_recalled = 0,
	};

	vm_map_t map = vm_test_alloc_map();

	vm_range_lock_test_preflight(flags, expected_result, &test_spec, map);

	vm_map_deallocate(map);

	assert3u(test_spec.n_valid_preflight_results, ==, 2);
	assert3u(test_spec.preflight_results[0].start, ==, 0x10000);
	assert3u(test_spec.preflight_results[0].end, ==, 0x20000);
	assert3u(test_spec.preflight_results[1].start, ==, 0x20000);
	assert3u(test_spec.preflight_results[1].end, ==, 0x30000);
}

static void
vm_range_lock_test_preflight_skip_prepare(vmrl_flags_t flags, kern_return_t expected_result)
{
	struct test_preflight_entry_config test_map[] = {
		{ .start = 0x10000, .end = 0x20000, .preflight_result = KERN_SUCCESS, .create = true },
		{ .start = 0x20000, .end = 0x30000, .preflight_result = VMRL_ERR_SKIP_PREPARE, .create = true },
		{ .start = 0x30000, .end = 0x40000, .preflight_result = KERN_SUCCESS, .create = true },
	};

	struct test_map_spec test_spec = {
		.name = "contiguous range with skip prepare",
		.entries = test_map,
		.n_entries = 3,
		.range_start = 0x10000,
		.range_end = 0x40000,
		.preflight_results = {},
		.n_valid_preflight_results = 0,
		.preflights_recalled = 0,
	};

	vm_map_t map = vm_test_alloc_map();

	vm_range_lock_test_preflight(flags, expected_result, &test_spec, map);

	vm_map_deallocate(map);

	assert3u(test_spec.n_valid_preflight_results, ==, 3);
	assert3u(test_spec.preflight_results[0].start, ==, 0x10000);
	assert3u(test_spec.preflight_results[0].end, ==, 0x20000);
	assert3u(test_spec.preflight_results[1].start, ==, 0x20000);
	assert3u(test_spec.preflight_results[1].end, ==, 0x30000);
	assert3u(test_spec.preflight_results[2].start, ==, 0x30000);
	assert3u(test_spec.preflight_results[2].end, ==, 0x40000);
}

/* address of the first entry inside the submap created by setup_constant_submap */
static const vm_map_address_t constant_submap_entry_start = 0x1000000000;

static void
vm_range_lock_test_preflight_with_constant_submap(vmrl_flags_t flags, kern_return_t expected_result)
{
	// Submaps are required to be aligned to an L(N-1) page table entry
	const vm_map_offset_t submap_start = 0x2000000ULL;
	const vm_map_offset_t submap_end =   0x4000000ULL;
	const unsigned int    n_submap_entries = 3;

	vm_map_t map;
	vm_map_t submap;
	setup_constant_submap(constant_submap_entry_start, submap_start, submap_end, n_submap_entries, &map, &submap);

	static struct test_preflight_entry_config test_map[] = {
		{ .start = 0x10000, .end = 0x20000, .preflight_result = KERN_SUCCESS, .create = true },
		{ .start = submap_end, .end = submap_end + 0x40000, .preflight_result = KERN_SUCCESS, .create = true }
	};

	struct test_map_spec spec = {
		.name = "disjoint range with constant submap",
		.entries = test_map,
		.n_entries = 2,
		.range_start = 0x10000,
		.range_end   = submap_end + 0x40000,
		.preflight_results = {},
		.n_valid_preflight_results = 0,
		.preflights_recalled = 0,
	};

	vm_range_lock_test_preflight(flags, expected_result, &spec, map);

	if (expected_result == KERN_SUCCESS) {
		if (vmrl_is_streaming(flags)) {
			if (flags & VMRL_DESCEND_INTO_CONSTANT) {
				assert3u(spec.n_valid_preflight_results, ==, 6);
				assert3u(spec.preflight_results[1].start, ==, constant_submap_entry_start + PAGE_SIZE * 0);
				assert3u(spec.preflight_results[1].end, ==, constant_submap_entry_start + PAGE_SIZE * 1);
				assert3u(spec.preflight_results[2].start, ==, constant_submap_entry_start + PAGE_SIZE * 1);
				assert3u(spec.preflight_results[2].end, ==, constant_submap_entry_start + PAGE_SIZE * 2);
				assert3u(spec.preflight_results[3].start, ==, constant_submap_entry_start + PAGE_SIZE * 2);
				assert3u(spec.preflight_results[3].end, ==, constant_submap_entry_start + PAGE_SIZE * 3);
				assert3u(spec.preflight_results[4].start, ==, constant_submap_entry_start + PAGE_SIZE * 3);
				assert3u(spec.preflight_results[4].end, ==, vm_map_max(submap));
			} else {
				assert3u(spec.n_valid_preflight_results, ==, 3);
				assert3u(spec.preflight_results[1].start, ==, submap_start);
				assert3u(spec.preflight_results[1].end, ==, submap_end);
			}
			assert3u(spec.preflight_results[0].start, ==, 0x10000);
			assert3u(spec.preflight_results[0].end, ==, 0x20000);
			assert3u(spec.preflight_results[spec.n_valid_preflight_results - 1].start, ==, submap_end);
			assert3u(spec.preflight_results[spec.n_valid_preflight_results - 1].end, ==, submap_end + 0x40000);
		} else {
			assert(flags & VMRL_ATOMIC_ALLOW_HOLES);
			if (flags & VMRL_DESCEND_INTO_CONSTANT) {
				assert3u(spec.n_valid_preflight_results, ==, 7);
				assert3u(spec.preflight_results[2].start, ==, constant_submap_entry_start + PAGE_SIZE * 0);
				assert3u(spec.preflight_results[2].end, ==, constant_submap_entry_start + PAGE_SIZE * 1);
				assert3u(spec.preflight_results[3].start, ==, constant_submap_entry_start + PAGE_SIZE * 1);
				assert3u(spec.preflight_results[3].end, ==, constant_submap_entry_start + PAGE_SIZE * 2);
				assert3u(spec.preflight_results[4].start, ==, constant_submap_entry_start + PAGE_SIZE * 2);
				assert3u(spec.preflight_results[4].end, ==, constant_submap_entry_start + PAGE_SIZE * 3);
				assert3u(spec.preflight_results[5].start, ==, constant_submap_entry_start + PAGE_SIZE * 3);
				assert3u(spec.preflight_results[5].end, ==, vm_map_max(submap));
			} else {
				assert3u(spec.n_valid_preflight_results, ==, 4);
				assert3u(spec.preflight_results[2].start, ==, submap_start);
				assert3u(spec.preflight_results[2].end, ==, submap_end);
			}
			assert3u(spec.preflight_results[0].start, ==, 0x10000);
			assert3u(spec.preflight_results[0].end, ==, 0x20000);
			assert3u(spec.preflight_results[1].start, ==, 0x20000);
			assert3u(spec.preflight_results[1].end, ==, submap_start);
			assert3u(spec.preflight_results[spec.n_valid_preflight_results - 1].start, ==, submap_end);
			assert3u(spec.preflight_results[spec.n_valid_preflight_results - 1].end, ==, submap_end + 0x40000);
		}
	} else {
		assert3u(spec.n_valid_preflight_results, ==, 1);
		assert3u(spec.preflight_results[0].start, ==, 0x10000);
		assert3u(spec.preflight_results[0].end, ==, 0x20000);
	}

	vm_map_destroy(map);
	vm_map_destroy(submap);
}

static void
vm_range_lock_test_preflight_with_constant_submap_and_error(vmrl_flags_t flags, kern_return_t expected_result)
{
	// Submaps are required to be aligned to an L(N-1) page table entry
	const vm_map_offset_t submap_start = 0x2000000ULL;
	const vm_map_offset_t submap_end =   0x4000000ULL;
	const unsigned int    n_submap_entries = 3;

	vm_map_t map;
	vm_map_t submap;
	setup_constant_submap(constant_submap_entry_start, submap_start, submap_end, n_submap_entries, &map, &submap);

	struct test_preflight_entry_config test_map_with_descend[] = {
		{ .start = 0x10000, .end = 0x20000, .preflight_result = KERN_SUCCESS, .create = true },

		{ .start = constant_submap_entry_start + PAGE_SIZE * 0, .end = constant_submap_entry_start + PAGE_SIZE * 1, .preflight_result = KERN_SUCCESS, .create = false },
		{ .start = constant_submap_entry_start + PAGE_SIZE * 1, .end = constant_submap_entry_start + PAGE_SIZE * 2, .preflight_result = KERN_SUCCESS, .create = false },
		{ .start = constant_submap_entry_start + PAGE_SIZE * 2, .end = constant_submap_entry_start + PAGE_SIZE * 3, .preflight_result = KERN_FAILURE, .create = false },
		{ .start = constant_submap_entry_start + PAGE_SIZE * 3, .end = vm_map_max(submap), .preflight_result = KERN_SUCCESS, .create = false },

		{ .start = submap_end, .end = submap_end + 0x40000, .preflight_result = KERN_SUCCESS, .create = true },
	};

	struct test_preflight_entry_config test_map_no_descend[] = {
		{ .start = 0x10000, .end = 0x20000, .preflight_result = KERN_SUCCESS, .create = true },
		{ .start = submap_start, .end = submap_end, .preflight_result = KERN_FAILURE, .create = false },
		{ .start = submap_end, .end = submap_end + 0x40000, .preflight_result = KERN_SUCCESS, .create = true },
	};

	struct test_preflight_entry_config *test_map;
	int entry_count;
	if (flags & VMRL_DESCEND_INTO_CONSTANT) {
		test_map = test_map_with_descend;
		entry_count = 6;
	} else {
		test_map = test_map_no_descend;
		entry_count = 3;
	}

	struct test_map_spec spec = {
		.name = "disjoint range with constant submap reporting error",
		.entries = test_map,
		.n_entries = entry_count,
		.range_start = 0x10000,
		.range_end   = submap_end + 0x40000,
		.preflight_results = {},
		.n_valid_preflight_results = 0,
		.preflights_recalled = 0,
	};

	vm_range_lock_test_preflight(flags, expected_result, &spec, map);

	if (expected_result == KERN_FAILURE) {
		if (vmrl_is_streaming(flags)) {
			if (flags & VMRL_DESCEND_INTO_CONSTANT) {
				assert3u(spec.n_valid_preflight_results, ==, 4);
				assert3u(spec.preflight_results[1].start, ==, constant_submap_entry_start + PAGE_SIZE * 0);
				assert3u(spec.preflight_results[1].end, ==, constant_submap_entry_start + PAGE_SIZE * 1);
				assert3u(spec.preflight_results[2].start, ==, constant_submap_entry_start + PAGE_SIZE * 1);
				assert3u(spec.preflight_results[2].end, ==, constant_submap_entry_start + PAGE_SIZE * 2);
				assert3u(spec.preflight_results[3].start, ==, constant_submap_entry_start + PAGE_SIZE * 2);
				assert3u(spec.preflight_results[3].end, ==, constant_submap_entry_start + PAGE_SIZE * 3);
			} else {
				assert3u(spec.n_valid_preflight_results, ==, 2);
				assert3u(spec.preflight_results[1].start, ==, submap_start);
				assert3u(spec.preflight_results[1].end, ==, submap_end);
			}

			assert3u(spec.preflight_results[0].start, ==, 0x10000);
			assert3u(spec.preflight_results[0].end, ==, 0x20000);
		} else {
			assert(flags & VMRL_ATOMIC_ALLOW_HOLES);
			if (flags & VMRL_DESCEND_INTO_CONSTANT) {
				assert3u(spec.n_valid_preflight_results, ==, 5);

				assert3u(spec.preflight_results[2].start, ==, constant_submap_entry_start + PAGE_SIZE * 0);
				assert3u(spec.preflight_results[2].end, ==, constant_submap_entry_start + PAGE_SIZE * 1);
				assert3u(spec.preflight_results[3].start, ==, constant_submap_entry_start + PAGE_SIZE * 1);
				assert3u(spec.preflight_results[3].end, ==, constant_submap_entry_start + PAGE_SIZE * 2);
				assert3u(spec.preflight_results[4].start, ==, constant_submap_entry_start + PAGE_SIZE * 2);
				assert3u(spec.preflight_results[4].end, ==, constant_submap_entry_start + PAGE_SIZE * 3);
			} else {
				assert3u(spec.n_valid_preflight_results, ==, 3);
				assert3u(spec.preflight_results[2].start, ==, submap_start);
				assert3u(spec.preflight_results[2].end, ==, submap_end);
			}
			assert3u(spec.preflight_results[0].start, ==, 0x10000);
			assert3u(spec.preflight_results[0].end, ==, 0x20000);
			assert3u(spec.preflight_results[1].start, ==, 0x20000);
			assert3u(spec.preflight_results[1].end, ==, submap_start);
		}
	} else {
		assert3u(spec.n_valid_preflight_results, ==, 1);
		assert3u(spec.preflight_results[0].start, ==, 0x10000);
		assert3u(spec.preflight_results[0].end, ==, 0x20000);
	}

	vm_map_destroy(map);
	vm_map_destroy(submap);
}

static void
vm_range_lock_test_preflight_with_transparent_submap(vmrl_flags_t flags, kern_return_t expected_result)
{
	// Submaps are required to be aligned to an L(N-1) page table entry
	vm_map_address_t submap_start = 0x180000000ULL;
	vm_map_address_t submap_end = 0x180000000ULL * 2;
	const unsigned int n_submap_entries = 3;
	bool should_descend_transparent = !(flags & VMRL_SH_NO_DESCEND_TRANSPARENT);

	vm_map_t map;
	vm_map_t submap;
	setup_transparent_submap(submap_start, submap_end, NULL, n_submap_entries, &map, &submap);

	struct test_preflight_entry_config test_map[] = {
	};

	struct test_map_spec spec = {
		.name = "disjoint range with transparent submap",
		.entries = test_map,
		.n_entries = ARRAY_COUNT(test_map),
		.range_start = submap_start,
		.range_end   = submap_start + PAGE_SIZE * n_submap_entries,
		.preflight_results = {},
		.n_valid_preflight_results = 0,
		.preflights_recalled = 0,
	};

	vm_range_lock_test_preflight(flags, expected_result, &spec, map);

	if (expected_result == KERN_SUCCESS) {
		if (should_descend_transparent) {
			assert3u(spec.n_valid_preflight_results, ==, 3);
			assert3u(spec.preflight_results[0].start, ==, submap_start);
			assert3u(spec.preflight_results[0].end, ==, submap_start + PAGE_SIZE);
			assert3u(spec.preflight_results[1].start, ==, submap_start + PAGE_SIZE);
			assert3u(spec.preflight_results[1].end, ==, submap_start + 2 * PAGE_SIZE);
			assert3u(spec.preflight_results[2].start, ==, submap_start + 2 * PAGE_SIZE);
			assert3u(spec.preflight_results[2].end, ==, submap_start + 3 * PAGE_SIZE);
		} else {
			assert3u(spec.n_valid_preflight_results, ==, 1);
			assert3u(spec.preflight_results[0].start, ==, submap_start);
			assert3u(spec.preflight_results[0].end, ==, submap_end);
		}
	} else {
		assert3u(spec.n_valid_preflight_results, ==, 0);
	}

	vm_map_destroy_options(map, VM_MAP_DESTROY_ALLOW_TRANSPARENT_SUBMAP);
	vm_map_destroy(submap);
}

static void
vm_range_lock_test_preflight_with_transparent_submap_with_error(vmrl_flags_t flags, kern_return_t expected_result)
{
	// Submaps are required to be aligned to an L(N-1) page table entry
	vm_map_address_t submap_start = 0x180000000ULL;
	vm_map_address_t submap_end = 0x180000000ULL * 2;
	const unsigned int n_submap_entries = 3;

	vm_map_t map;
	vm_map_t submap;
	setup_transparent_submap(submap_start, submap_end, NULL, n_submap_entries, &map, &submap);

	bool should_descend_transparent = !(flags & VMRL_SH_NO_DESCEND_TRANSPARENT);

	struct test_preflight_entry_config test_map[] = {
		{ .start = submap_start + PAGE_SIZE, .end = submap_start + 2 * PAGE_SIZE, .preflight_result = KERN_FAILURE, .create = false },
	};

	struct test_map_spec spec = {
		.name = "disjoint range with transparent submap and errors",
		.entries = test_map,
		.n_entries = ARRAY_COUNT(test_map),
		.range_start = submap_start,
		.range_end   = submap_start + PAGE_SIZE * n_submap_entries,
		.preflight_results = {},
		.n_valid_preflight_results = 0,
		.preflights_recalled = 0,
	};

	vm_range_lock_test_preflight(flags, expected_result, &spec, map);

	if (should_descend_transparent) {
		assert3u(spec.n_valid_preflight_results, ==, 2);
		assert3u(spec.preflight_results[0].start, ==, submap_start);
		assert3u(spec.preflight_results[0].end, ==, submap_start + PAGE_SIZE);
		assert3u(spec.preflight_results[1].start, ==, submap_start + PAGE_SIZE);
		assert3u(spec.preflight_results[1].end, ==, submap_start + 2 * PAGE_SIZE);
	} else {
		assert3u(spec.n_valid_preflight_results, ==, 1);
		assert3u(spec.preflight_results[0].start, ==, submap_start);
		assert3u(spec.preflight_results[0].end, ==, submap_end);
	}

	vm_map_destroy_options(map, VM_MAP_DESTROY_ALLOW_TRANSPARENT_SUBMAP);
	vm_map_destroy(submap);
}

static void
vm_range_lock_test_preflight_with_transparent_submap_with_initial_error(
	vmrl_flags_t flags,
	kern_return_t expected_result)
{
	const unsigned int n_submap_entries = 3;
	vm_map_address_t submap_start = 0x180000000ULL;
	vm_map_address_t submap_end = 0x180000000ULL * 2;
	bool should_descend_transparent = !(flags & VMRL_SH_NO_DESCEND_TRANSPARENT);

	vm_map_t map;
	vm_map_t submap;
	setup_transparent_submap(submap_start, submap_end, NULL, n_submap_entries, &map, &submap);

	struct test_preflight_entry_config test_map[] = {
		{ .start = submap_start, .end = submap_start + PAGE_SIZE, .preflight_result = KERN_PROTECTION_FAILURE, .create = false },
	};

	struct test_map_spec spec = {
		.name = "disjoint range with transparent submap and error on first entry",
		.entries = test_map,
		.n_entries = ARRAY_COUNT(test_map),
		.range_start = submap_start,
		.range_end = submap_end,
		.preflight_results = {},
		.n_valid_preflight_results = 0,
		.preflights_recalled = 0,
	};

	vm_range_lock_test_preflight(flags, expected_result, &spec, map);

	vm_map_destroy_options(map, VM_MAP_DESTROY_ALLOW_TRANSPARENT_SUBMAP);
	vm_map_destroy(submap);

	assert3u(spec.n_valid_preflight_results, ==, 1);
	assert3u(spec.preflight_results[0].start, ==, submap_start);
	if (should_descend_transparent) {
		assert3u(spec.preflight_results[0].end, ==, submap_start + PAGE_SIZE);
	} else {
		assert3u(spec.preflight_results[0].end, ==, submap_end);
	}
}

static void
vm_range_lock_test_preflight_with_transparent_submap_with_final_error(
	vmrl_flags_t flags,
	kern_return_t expected_result)
{
	const unsigned int n_submap_entries = 3;
	vm_map_address_t submap_start = 0x180000000ULL;
	vm_map_address_t submap_end = 0x180000000ULL * 2;
	bool should_descend_transparent = !(flags & VMRL_SH_NO_DESCEND_TRANSPARENT);

	vm_map_t map;
	vm_map_t submap;
	setup_transparent_submap(submap_start, submap_end, NULL, n_submap_entries, &map, &submap);

	struct test_preflight_entry_config test_map[] = {
		{ .start = submap_start + 2 * PAGE_SIZE, .end = submap_start + 3 * PAGE_SIZE,
		  .preflight_result = KERN_PROTECTION_FAILURE, .create = false },
	};

	struct test_map_spec spec = {
		.name = "disjoint range with transparent submap and error on final entry",
		.entries = test_map,
		.n_entries = ARRAY_COUNT(test_map),
		.range_start = submap_start,
		.range_end = submap_end,
		.preflight_results = {},
		.n_valid_preflight_results = 0,
		.preflights_recalled = 0,
	};

	vm_range_lock_test_preflight(flags, expected_result, &spec, map);

	vm_map_destroy_options(map, VM_MAP_DESTROY_ALLOW_TRANSPARENT_SUBMAP);
	vm_map_destroy(submap);

	assert3u(spec.preflight_results[0].start, ==, submap_start);
	if (should_descend_transparent) {
		assert3u(spec.n_valid_preflight_results, ==, 3);
		assert3u(spec.preflight_results[0].start, ==, submap_start);
		assert3u(spec.preflight_results[0].end, ==, submap_start + PAGE_SIZE);
		assert3u(spec.preflight_results[1].start, ==, submap_start + PAGE_SIZE);
		assert3u(spec.preflight_results[1].end, ==, submap_start + 2 * PAGE_SIZE);
		assert3u(spec.preflight_results[2].start, ==, submap_start + 2 * PAGE_SIZE);
		assert3u(spec.preflight_results[2].end, ==, submap_start + 3 * PAGE_SIZE);
	} else {
		assert3u(spec.n_valid_preflight_results, ==, 1);
		assert3u(spec.preflight_results[0].start, ==, submap_start);
		assert3u(spec.preflight_results[0].end, ==, submap_end);
	}
}

static void
vm_range_lock_test_preflight_with_transparent_submap_descent(
	vmrl_flags_t flags,
	kern_return_t expected_result)
{
	const unsigned int n_submap_entries = 3;
	vm_map_address_t submap_start = 0x180000000ULL;
	vm_map_address_t submap_end = submap_start + (n_submap_entries * PAGE_SIZE);
	bool should_descend_transparent = !(flags & VMRL_SH_NO_DESCEND_TRANSPARENT);

	vm_map_t map;
	vm_map_t submap;
	setup_transparent_submap(submap_start, submap_end, NULL, n_submap_entries, &map, &submap);

	struct test_preflight_entry_config test_map[] = {
	};

	vm_test_add_map_entry(map, submap_start - PAGE_SIZE, submap_start);
	vm_test_add_map_entry(map, submap_end, submap_end + PAGE_SIZE);
	struct test_map_spec spec = {
		.name = "disjoint range including transparent submap",
		.entries = test_map,
		.n_entries = ARRAY_COUNT(test_map),
		.range_start = submap_start - PAGE_SIZE,
		.range_end   = submap_end + PAGE_SIZE,
		.preflight_results = {},
		.n_valid_preflight_results = 0,
		.preflights_recalled = 0,
	};

	vm_range_lock_test_preflight(flags | _VMRL_KERNEL_PMAP, expected_result, &spec, map);

	if (expected_result == KERN_SUCCESS) {
		if (should_descend_transparent) {
			assert3u(spec.n_valid_preflight_results, ==, 5);
			assert3u(spec.preflight_results[0].start, ==, submap_start - PAGE_SIZE);
			assert3u(spec.preflight_results[0].end, ==, submap_start);
			assert3u(spec.preflight_results[1].start, ==, submap_start);
			assert3u(spec.preflight_results[1].end, ==, submap_start + PAGE_SIZE);
			assert3u(spec.preflight_results[2].start, ==, submap_start + PAGE_SIZE);
			assert3u(spec.preflight_results[2].end, ==, submap_start + 2 * PAGE_SIZE);
			assert3u(spec.preflight_results[3].start, ==, submap_start + 2 * PAGE_SIZE);
			assert3u(spec.preflight_results[3].end, ==, submap_start + 3 * PAGE_SIZE);
			assert3u(spec.preflight_results[4].start, ==, submap_end);
			assert3u(spec.preflight_results[4].end, ==, submap_end + PAGE_SIZE);
		} else {
			assert3u(spec.n_valid_preflight_results, ==, 3);
			assert3u(spec.preflight_results[0].start, ==, submap_start - PAGE_SIZE);
			assert3u(spec.preflight_results[0].end, ==, submap_start);
			assert3u(spec.preflight_results[1].start, ==, submap_start);
			assert3u(spec.preflight_results[1].end, ==, submap_end);
			assert3u(spec.preflight_results[2].start, ==, submap_end);
			assert3u(spec.preflight_results[2].end, ==, submap_end + PAGE_SIZE);
		}
	} else {
		assert3u(spec.n_valid_preflight_results, ==, 0);
	}

	vm_map_destroy_options(map, VM_MAP_DESTROY_ALLOW_TRANSPARENT_SUBMAP);
	vm_map_destroy(submap);
}

static void
vm_range_lock_test_preflight_with_single_entry_transparent_submap_descent(
	vmrl_flags_t flags,
	kern_return_t expected_result)
{
	vm_map_address_t submap_start = 0x180000000ULL;
	vm_map_address_t submap_end = submap_start + PAGE_SIZE;
	bool should_descend_transparent = !(flags & VMRL_SH_NO_DESCEND_TRANSPARENT);

	vm_map_t map;
	vm_map_t submap;

	struct submap_entry_spec entry_spec[] = {
		{ .start = submap_start, .end = submap_end, .needs_copy = false },
	};

	setup_transparent_submap(submap_start, submap_end, entry_spec, ARRAY_COUNT(entry_spec), &map, &submap);

	struct test_preflight_entry_config test_map[] = {
	};

	vm_test_add_map_entry(map, submap_start - PAGE_SIZE, submap_start);
	vm_test_add_map_entry(map, submap_end, submap_end + PAGE_SIZE);
	struct test_map_spec spec = {
		.name = "range including single-entry transparent submap",
		.entries = test_map,
		.n_entries = ARRAY_COUNT(test_map),
		.range_start = submap_start - PAGE_SIZE,
		.range_end   = submap_end + PAGE_SIZE,
		.preflight_results = {},
		.n_valid_preflight_results = 0,
		.preflights_recalled = 0,
	};

	vm_range_lock_test_preflight(flags | _VMRL_KERNEL_PMAP, expected_result, &spec, map);

	if (expected_result == KERN_SUCCESS) {
		assert3u(spec.n_valid_preflight_results, ==, 3);
		assert3u(spec.preflight_results[0].start, ==, submap_start - PAGE_SIZE);
		assert3u(spec.preflight_results[0].end, ==, submap_start);
		assert3u(spec.preflight_results[1].start, ==, submap_start);
		assert3u(spec.preflight_results[1].end, ==, submap_end);
		assert3u(spec.preflight_results[2].start, ==, submap_end);
		assert3u(spec.preflight_results[2].end, ==, submap_end + PAGE_SIZE);
		assert(!spec.preflight_results[0].entry->is_sub_map);
		assert(!spec.preflight_results[2].entry->is_sub_map);
		if (should_descend_transparent) {
			assert(!spec.preflight_results[1].entry->is_sub_map);
		} else {
			assert(spec.preflight_results[1].entry->is_sub_map);
		}
	} else {
		assert3u(spec.n_valid_preflight_results, ==, 0);
	}

	vm_map_destroy_options(map, VM_MAP_DESTROY_ALLOW_TRANSPARENT_SUBMAP);
	vm_map_destroy(submap);
}

static void
vm_range_lock_test_preflight_with_transparent_submap_descent_and_clipping(
	vmrl_flags_t flags,
	kern_return_t expected_result)
{
	vm_map_address_t submap_start = 0x180000000ULL;
	vm_map_address_t submap_end = submap_start + 2 * PAGE_SIZE;
	bool should_descend_transparent = !(flags & VMRL_SH_NO_DESCEND_TRANSPARENT);

	mach_error_t submap_return_code = should_descend_transparent ?
	    VMRL_ERR_SETUP_SYMMETRIC_COW : KERN_SUCCESS;

	vm_map_t map;
	vm_map_t submap;

	struct submap_entry_spec entry_spec[] = {
		{ .start = submap_start, .end = submap_end, .needs_copy = false },
	};

	setup_transparent_submap(submap_start, submap_end, entry_spec, ARRAY_COUNT(entry_spec), &map, &submap);

	struct test_preflight_entry_config test_map[] = {
		{ .start = submap_start - 2 * PAGE_SIZE, .end = submap_start,
		  .preflight_result = VMRL_ERR_SETUP_SYMMETRIC_COW, .create = true },
		{ .start = submap_start, .end = submap_start + 2 * PAGE_SIZE,
		  .preflight_result = submap_return_code, .create = false },
	};

	struct test_map_spec spec = {
		.name = "disjoint range including transparent submap descent with clipping of border entries",
		.entries = test_map,
		.n_entries = ARRAY_COUNT(test_map),
		.range_start = submap_start - PAGE_SIZE,
		.range_end   = submap_start + PAGE_SIZE,
		.preflight_results = {},
		.n_valid_preflight_results = 0,
		.preflights_recalled = 0,
	};

	vm_range_lock_test_preflight(flags | _VMRL_KERNEL_PMAP, expected_result, &spec, map);

	if (expected_result == KERN_SUCCESS) {
		assert3u(spec.n_valid_preflight_results, ==, 2);
		assert3u(spec.preflight_results[0].start, ==, submap_start - 2 * PAGE_SIZE);
		assert3u(spec.preflight_results[0].end, ==, submap_start);
		assert(!spec.preflight_results[0].entry->is_sub_map);
		assert3u(spec.preflight_results[1].start, ==, submap_start);
		if (should_descend_transparent) {
			assert3u(spec.preflight_results[1].end, ==, submap_start + 2 * PAGE_SIZE);
			assert(!spec.preflight_results[1].entry->is_sub_map);
		} else {
			assert3u(spec.preflight_results[1].end, ==, submap_end);
			assert(spec.preflight_results[1].entry->is_sub_map);
		}
		/* Now validate that the border entries were clipped as needed. */
		vm_map_address_t entry_start = submap_start - 2 * PAGE_SIZE;
		while (entry_start < submap_start) {
			vm_map_entry_t entry = find_entry_unlocked(map, entry_start);
			assert(entry != NULL);
			entry_start += PAGE_SIZE;
			assert3u(entry->vme_end, ==, entry_start);
		}
		entry_start = submap_start;
		while (entry_start < submap_start + 2 * PAGE_SIZE) {
			vm_map_entry_t entry = find_entry_unlocked(submap, entry_start);
			assert(entry != NULL);
			if (should_descend_transparent) {
				entry_start += PAGE_SIZE;
			} else {
				entry_start += 2 * PAGE_SIZE;
			}
			assert3u(entry->vme_end, ==, entry_start);
		}
	} else {
		assert3u(spec.n_valid_preflight_results, ==, 0);
	}

	vm_map_destroy_options(map, VM_MAP_DESTROY_ALLOW_TRANSPARENT_SUBMAP);
	vm_map_destroy(submap);
}

static void
vm_range_lock_test_preflight_with_transparent_submap_ascent_and_clipping(
	vmrl_flags_t flags,
	kern_return_t expected_result)
{
	vm_map_address_t submap_start = 0x180000000ULL;
	vm_map_address_t submap_end = submap_start + 2 * PAGE_SIZE;
	bool should_descend_transparent = !(flags & VMRL_SH_NO_DESCEND_TRANSPARENT);

	mach_error_t submap_return_code = should_descend_transparent ?
	    VMRL_ERR_SETUP_SYMMETRIC_COW : KERN_SUCCESS;

	vm_map_t map;
	vm_map_t submap;

	struct submap_entry_spec entry_spec[] = {
		{ .start = submap_start, .end = submap_end, .needs_copy = false },
	};

	setup_transparent_submap(submap_start, submap_end, entry_spec, ARRAY_COUNT(entry_spec), &map, &submap);

	struct test_preflight_entry_config test_map[] = {
		{ .start = submap_start, .end = submap_start + 2 * PAGE_SIZE,
		  .preflight_result = submap_return_code, .create = false },
		{ .start = submap_end, .end = submap_end + 2 * PAGE_SIZE,
		  .preflight_result = VMRL_ERR_SETUP_SYMMETRIC_COW, .create = true },
	};

	struct test_map_spec spec = {
		.name = "disjoint range including transparent submap ascent with clipping of border entries",
		.entries = test_map,
		.n_entries = ARRAY_COUNT(test_map),
		.range_start = submap_start + PAGE_SIZE,
		.range_end   = submap_end + PAGE_SIZE,
		.preflight_results = {},
		.n_valid_preflight_results = 0,
		.preflights_recalled = 0,
	};

	vm_range_lock_test_preflight(flags | _VMRL_KERNEL_PMAP, expected_result, &spec, map);

	if (expected_result == KERN_SUCCESS) {
		assert3u(spec.n_valid_preflight_results, ==, 2);
		assert3u(spec.preflight_results[0].start, ==, submap_start);
		if (should_descend_transparent) {
			assert3u(spec.preflight_results[0].end, ==, submap_start + 2 * PAGE_SIZE);
			assert(!spec.preflight_results[0].entry->is_sub_map);
		} else {
			assert3u(spec.preflight_results[0].end, ==, submap_end);
			assert(spec.preflight_results[0].entry->is_sub_map);
		}
		assert3u(spec.preflight_results[1].start, ==, submap_end);
		assert3u(spec.preflight_results[1].end, ==, submap_end + 2 * PAGE_SIZE);
		assert(!spec.preflight_results[1].entry->is_sub_map);
		/* Now validate that the border entries were clipped as needed. */
		vm_map_address_t entry_start = submap_start;
		while (entry_start < submap_start + 2 * PAGE_SIZE) {
			vm_map_entry_t entry = find_entry_unlocked(submap, entry_start);
			assert(entry != NULL);
			if (should_descend_transparent) {
				entry_start += PAGE_SIZE;
			} else {
				entry_start += 2 * PAGE_SIZE;
			}
			assert3u(entry->vme_end, ==, entry_start);
		}
		entry_start = submap_end;
		while (entry_start < submap_end + 2 * PAGE_SIZE) {
			vm_map_entry_t entry = find_entry_unlocked(map, entry_start);
			assert(entry != NULL);
			entry_start += PAGE_SIZE;
			assert3u(entry->vme_end, ==, entry_start);
		}
	} else {
		assert3u(spec.n_valid_preflight_results, ==, 0);
	}

	vm_map_destroy_options(map, VM_MAP_DESTROY_ALLOW_TRANSPARENT_SUBMAP);
	vm_map_destroy(submap);
}

static void
vm_range_lock_test_preflight_with_transparent_submap_descent_and_initial_error(
	vmrl_flags_t flags,
	kern_return_t expected_result)
{
	const unsigned int n_submap_entries = 3;
	vm_map_address_t submap_start = 0x180000000ULL;
	vm_map_address_t submap_end = submap_start + (n_submap_entries * PAGE_SIZE);
	bool should_descend_transparent = !(flags & VMRL_SH_NO_DESCEND_TRANSPARENT);

	vm_map_t map;
	vm_map_t submap;
	setup_transparent_submap(submap_start, submap_end, NULL, n_submap_entries, &map, &submap);

	struct test_preflight_entry_config test_map[] = {
		{ .start = submap_start, .end = submap_start + PAGE_SIZE, .preflight_result = KERN_PROTECTION_FAILURE, .create = false },
	};

	vm_test_add_map_entry(map, submap_start - PAGE_SIZE, submap_start);
	vm_test_add_map_entry(map, submap_end, submap_end + PAGE_SIZE);
	struct test_map_spec spec = {
		.name = "disjoint range including transparent submap with error on first entry",
		.entries = test_map,
		.n_entries = ARRAY_COUNT(test_map),
		.range_start = submap_start - PAGE_SIZE,
		.range_end   = submap_end + PAGE_SIZE,
		.preflight_results = {},
		.n_valid_preflight_results = 0,
		.preflights_recalled = 0,
	};

	vm_range_lock_test_preflight(flags | _VMRL_KERNEL_PMAP, expected_result, &spec, map);

	if (should_descend_transparent) {
		assert3u(spec.n_valid_preflight_results, ==, 2);
		assert3u(spec.preflight_results[0].start, ==, submap_start - PAGE_SIZE);
		assert3u(spec.preflight_results[0].end, ==, submap_start);
		assert3u(spec.preflight_results[1].start, ==, submap_start);
		assert3u(spec.preflight_results[1].end, ==, submap_start + PAGE_SIZE);
	} else {
		assert3u(spec.n_valid_preflight_results, ==, 3);
		assert3u(spec.preflight_results[0].start, ==, submap_start - PAGE_SIZE);
		assert3u(spec.preflight_results[0].end, ==, submap_start);
		assert3u(spec.preflight_results[1].start, ==, submap_start);
		assert3u(spec.preflight_results[1].end, ==, submap_end);
		assert3u(spec.preflight_results[2].start, ==, submap_end);
		assert3u(spec.preflight_results[2].end, ==, submap_end + PAGE_SIZE);
	}

	vm_map_destroy_options(map, VM_MAP_DESTROY_ALLOW_TRANSPARENT_SUBMAP);
	vm_map_destroy(submap);
}

static void
vm_range_lock_test_preflight_with_transparent_submap_descent_and_final_error(
	vmrl_flags_t flags,
	kern_return_t expected_result)
{
	const unsigned int n_submap_entries = 3;
	vm_map_address_t submap_start = 0x180000000ULL;
	vm_map_address_t submap_end = submap_start + (n_submap_entries * PAGE_SIZE);
	bool should_descend_transparent = !(flags & VMRL_SH_NO_DESCEND_TRANSPARENT);

	vm_map_t map;
	vm_map_t submap;
	setup_transparent_submap(submap_start, submap_end, NULL, n_submap_entries, &map, &submap);

	struct test_preflight_entry_config test_map[] = {
		{ .start = submap_start + 2 * PAGE_SIZE, .end = submap_start + 3 * PAGE_SIZE,
		  .preflight_result = KERN_PROTECTION_FAILURE, .create = false },
	};

	vm_test_add_map_entry(map, submap_start - PAGE_SIZE, submap_start);
	vm_test_add_map_entry(map, submap_end, submap_end + PAGE_SIZE);
	struct test_map_spec spec = {
		.name = "disjoint range including transparent submap with error on last entry",
		.entries = test_map,
		.n_entries = ARRAY_COUNT(test_map),
		.range_start = submap_start - PAGE_SIZE,
		.range_end   = submap_end + PAGE_SIZE,
		.preflight_results = {},
		.n_valid_preflight_results = 0,
		.preflights_recalled = 0,
	};

	vm_range_lock_test_preflight(flags | _VMRL_KERNEL_PMAP, expected_result, &spec, map);

	if (should_descend_transparent) {
		assert3u(spec.n_valid_preflight_results, ==, 4);
		assert3u(spec.preflight_results[0].start, ==, submap_start - PAGE_SIZE);
		assert3u(spec.preflight_results[0].end, ==, submap_start);
		assert3u(spec.preflight_results[1].start, ==, submap_start);
		assert3u(spec.preflight_results[1].end, ==, submap_start + PAGE_SIZE);
		assert3u(spec.preflight_results[2].start, ==, submap_start + PAGE_SIZE);
		assert3u(spec.preflight_results[2].end, ==, submap_start + 2 * PAGE_SIZE);
		assert3u(spec.preflight_results[3].start, ==, submap_start + 2 * PAGE_SIZE);
		assert3u(spec.preflight_results[3].end, ==, submap_start + 3 * PAGE_SIZE);
	} else {
		assert3u(spec.n_valid_preflight_results, ==, 3);
		assert3u(spec.preflight_results[0].start, ==, submap_start - PAGE_SIZE);
		assert3u(spec.preflight_results[0].end, ==, submap_start);
		assert3u(spec.preflight_results[1].start, ==, submap_start);
		assert3u(spec.preflight_results[1].end, ==, submap_end);
		assert3u(spec.preflight_results[2].start, ==, submap_end);
		assert3u(spec.preflight_results[2].end, ==, submap_end + PAGE_SIZE);
	}

	vm_map_destroy_options(map, VM_MAP_DESTROY_ALLOW_TRANSPARENT_SUBMAP);
	vm_map_destroy(submap);
}

static void
vm_range_lock_test_preflight_with_transparent_submap_and_clipping(
	vmrl_flags_t flags,
	kern_return_t expected_result)
{
	vm_map_address_t submap_start = 0x180000000ULL;
	vm_map_address_t submap_end = 0x180000000ULL * 2;
	bool should_descend_transparent = !(flags & VMRL_SH_NO_DESCEND_TRANSPARENT);

	vm_map_t map;
	vm_map_t submap;

	struct submap_entry_spec entry_spec[] = {
		{ .start = submap_start, .end = submap_start + 2 * PAGE_SIZE, .needs_copy = false },
		{ .start = submap_start + 2 * PAGE_SIZE, .end = submap_end - 2 * PAGE_SIZE, .needs_copy = false },
		{ .start = submap_end - 2 * PAGE_SIZE, .end = submap_end, .needs_copy = false }
	};

	setup_transparent_submap(submap_start, submap_end, entry_spec, ARRAY_COUNT(entry_spec), &map, &submap);

	struct test_preflight_entry_config test_map[] = {
		{ .start = submap_start, .end = submap_start + 2 * PAGE_SIZE,
		  .preflight_result = VMRL_ERR_SETUP_SYMMETRIC_COW, .create = false },
		{ .start = submap_end - 2 * PAGE_SIZE, .end = submap_end,
		  .preflight_result = VMRL_ERR_SETUP_SYMMETRIC_COW, .create = false },
	};

	struct test_map_spec spec = {
		.name = "disjoint range including transparent submap with clipping of entries",
		.entries = test_map,
		.n_entries = ARRAY_COUNT(test_map),
		.range_start = submap_start + PAGE_SIZE,
		.range_end   = submap_end - PAGE_SIZE,
		.preflight_results = {},
		.n_valid_preflight_results = 0,
		.preflights_recalled = 0,
	};

	vm_range_lock_test_preflight(flags, expected_result, &spec, map);

	if (expected_result == KERN_SUCCESS) {
		if (should_descend_transparent) {
			assert3u(spec.n_valid_preflight_results, ==, 3);
			assert3u(spec.preflight_results[0].start, ==, submap_start);
			assert3u(spec.preflight_results[0].end, ==, submap_start + 2 * PAGE_SIZE);
			assert3u(spec.preflight_results[1].start, ==, submap_start + 2 * PAGE_SIZE);
			assert3u(spec.preflight_results[1].end, ==, submap_end - 2 * PAGE_SIZE);
			assert3u(spec.preflight_results[2].start, ==, submap_end - 2 * PAGE_SIZE);
			assert3u(spec.preflight_results[2].end, ==, submap_end);
		} else {
			assert3u(spec.n_valid_preflight_results, ==, 1);
			assert3u(spec.preflight_results[0].start, ==, submap_start);
			assert3u(spec.preflight_results[0].end, ==, submap_end);
		}

		/* Now validate that the border entries were clipped as needed. */
		vm_map_address_t entry_start = submap_start;
		while (entry_start < submap_end) {
			vm_map_entry_t entry = find_entry_unlocked(submap, entry_start);
			assert(entry != NULL);
			if (should_descend_transparent) {
				entry_start += PAGE_SIZE;
			} else {
				entry_start += 2 * PAGE_SIZE;
			}
			assert3u(entry->vme_end, ==, entry_start);
			if (entry_start == submap_start + 2 * PAGE_SIZE) {
				entry_start = submap_end - 2 * PAGE_SIZE;
			}
		}
	} else {
		assert3u(spec.n_valid_preflight_results, ==, 0);
	}

	vm_map_destroy_options(map, VM_MAP_DESTROY_ALLOW_TRANSPARENT_SUBMAP);
	vm_map_destroy(submap);
}

static void
vm_range_lock_test_preflight_with_transparent_submap_descent_and_parent_clipping(
	vmrl_flags_t flags,
	kern_return_t expected_result)
{
	const unsigned int n_submap_entries = 3;
	vm_map_address_t submap_start = 0x180000000ULL;
	vm_map_address_t submap_end = submap_start + (n_submap_entries * PAGE_SIZE);
	bool should_descend_transparent = !(flags & VMRL_SH_NO_DESCEND_TRANSPARENT);

	vm_map_t map;
	vm_map_t submap;
	setup_transparent_submap(submap_start, submap_end, NULL, n_submap_entries, &map, &submap);

	struct test_preflight_entry_config test_map[] = {
		{ .start = submap_start - 2 * PAGE_SIZE, .end = submap_start,
		  .preflight_result = VMRL_ERR_SETUP_SYMMETRIC_COW, .create = true },
		{ .start = submap_end, .end = submap_end + 2 * PAGE_SIZE,
		  .preflight_result = VMRL_ERR_SETUP_SYMMETRIC_COW, .create = true },
	};

	struct test_map_spec spec = {
		.name = "disjoint range including transparent submap with clipping of adjacent parent map entries",
		.entries = test_map,
		.n_entries = ARRAY_COUNT(test_map),
		.range_start = submap_start - PAGE_SIZE,
		.range_end   = submap_end + PAGE_SIZE,
		.preflight_results = {},
		.n_valid_preflight_results = 0,
		.preflights_recalled = 0,
	};

	vm_range_lock_test_preflight(flags | _VMRL_KERNEL_PMAP, expected_result, &spec, map);

	if (expected_result == KERN_SUCCESS) {
		if (should_descend_transparent) {
			assert3u(spec.n_valid_preflight_results, ==, 5);
			assert3u(spec.preflight_results[0].start, ==, submap_start - 2 * PAGE_SIZE);
			assert3u(spec.preflight_results[0].end, ==, submap_start);
			assert3u(spec.preflight_results[1].start, ==, submap_start);
			assert3u(spec.preflight_results[1].end, ==, submap_start + PAGE_SIZE);
			assert3u(spec.preflight_results[2].start, ==, submap_start + PAGE_SIZE);
			assert3u(spec.preflight_results[2].end, ==, submap_start + 2 * PAGE_SIZE);
			assert3u(spec.preflight_results[3].start, ==, submap_start + 2 * PAGE_SIZE);
			assert3u(spec.preflight_results[3].end, ==, submap_start + 3 * PAGE_SIZE);
			assert3u(spec.preflight_results[4].start, ==, submap_end);
			assert3u(spec.preflight_results[4].end, ==, submap_end + 2 * PAGE_SIZE);
		} else {
			assert3u(spec.n_valid_preflight_results, ==, 3);
			assert3u(spec.preflight_results[0].start, ==, submap_start - 2 * PAGE_SIZE);
			assert3u(spec.preflight_results[0].end, ==, submap_start);
			assert3u(spec.preflight_results[1].start, ==, submap_start);
			assert3u(spec.preflight_results[1].end, ==, submap_end);
			assert3u(spec.preflight_results[2].start, ==, submap_end);
			assert3u(spec.preflight_results[2].end, ==, submap_end + 2 * PAGE_SIZE);
		}

		/* Now validate that the border entries were clipped as needed. */
		vm_map_address_t entry_start = submap_start - 2 * PAGE_SIZE;
		while (entry_start < submap_end + 2 * PAGE_SIZE) {
			vm_map_entry_t entry = find_entry_unlocked(map, entry_start);
			assert(entry != NULL);
			entry_start += PAGE_SIZE;
			assert3u(entry->vme_end, ==, entry_start);
			if (entry_start == submap_start) {
				entry_start = submap_end;
			}
		}
	} else {
		assert3u(spec.n_valid_preflight_results, ==, 0);
	}

	vm_map_destroy_options(map, VM_MAP_DESTROY_ALLOW_TRANSPARENT_SUBMAP);
	vm_map_destroy(submap);
}

/* constant submap can't be empty by definition. vm_map_seal fills holes. */
static void
vm_map_range_lock_empty_transparent_submap_tests(vmrl_flags_t flags)
{
	const vm_map_offset_t start = 0x180000000ULL, submap_end = 0x180000000ULL * 2;
	kern_return_t kr;
	vm_map_t parent_map;
	vm_map_t submap;
	VM_MAP_LOCK_CTX_DECLARE(ctx);

	setup_transparent_submap(start, submap_end, NULL, 0, &parent_map, &submap);
	kr = __vmrl_lock(ctx, &parent_map, start, submap_end, flags);

	/* nothing to lock as it's empty */
	assert3u(kr, ==, KERN_INVALID_ADDRESS);

	if (vmrl_is_streaming(flags)) {
		kr = __vmrl_lock(ctx, &parent_map, start, VMRL_END_VA(parent_map), flags);

		/* nothing to lock as it's empty */
		assert3u(kr, ==, KERN_INVALID_ADDRESS);
	}
}

static int
vm_range_lock_test(__unused int64_t in, int64_t *out)
{
	printf("%s: test running (thread=%p)\n", __func__, current_thread());

	printf("%s: vm_range_lock_test_basic_assumptions()\n", __func__);
	vm_range_lock_test_basic_assumptions();

	printf("%s: vm_range_lock_test_lock_single_entry_shared()\n", __func__);
	vm_range_lock_test_lock_single_entry_shared();

	printf("%s: vm_range_lock_test_lock_distinct_ranges()\n", __func__);
	vm_range_lock_test_lock_distinct_ranges();

	printf("%s: vm_range_lock_test_API_enumeration(*)\n", __func__);
	vm_range_lock_test_API_enumeration(VMRL_SHARED | VMRL_ATOMIC);
	/* VMRL_SHARED | VMRL_ATOMIC_ALLOW_HOLES is not a thing */
	vm_range_lock_test_API_enumeration(VMRL_SHARED | VMRL_STREAM);
	vm_range_lock_test_API_enumeration(VMRL_SHARED | VMRL_STREAM_NO_HOLES);
	vm_range_lock_test_API_enumeration(VMRL_EXCLUSIVE | VMRL_ATOMIC);
	vm_range_lock_test_API_enumeration(VMRL_EXCLUSIVE | VMRL_ATOMIC_ALLOW_HOLES);
	vm_range_lock_test_API_enumeration(VMRL_EXCLUSIVE | VMRL_STREAM);
	vm_range_lock_test_API_enumeration(VMRL_EXCLUSIVE | VMRL_STREAM_NO_HOLES);

	printf("%s: vm_range_lock_test_API_downgrade()\n", __func__);
	vm_range_lock_test_API_downgrade();

	printf("%s: vm_range_lock_test_clip(*)\n", __func__);
	vm_range_lock_test_clip(true);
	vm_range_lock_test_clip(false);

	printf("%s: vm_range_lock_test_pmap_unnest(*)\n", __func__);
	vm_range_lock_test_pmap_unnest(true);
	vm_range_lock_test_pmap_unnest(false);

	printf("%s: vm_range_lock_test_unlock_midway(*)\n", __func__);
	vm_range_lock_test_unlock_midway(VMRL_EXCLUSIVE | VMRL_ATOMIC);
	vm_range_lock_test_unlock_midway(VMRL_EXCLUSIVE | VMRL_STREAM);
	vm_range_lock_test_unlock_midway(VMRL_SHARED | VMRL_ATOMIC);
	vm_range_lock_test_unlock_midway(VMRL_SHARED | VMRL_STREAM);

	printf("%s: vm_range_lock_test_stream_drop_then_advance(*)\n", __func__);
	vm_range_lock_test_stream_drop_then_advance(VMRL_EXCLUSIVE, true);
	vm_range_lock_test_stream_drop_then_advance(VMRL_EXCLUSIVE, false);
	vm_range_lock_test_stream_drop_then_advance(VMRL_SHARED, true);
	vm_range_lock_test_stream_drop_then_advance(VMRL_SHARED, false);

	printf("%s: vm_map_range_lock_empty_transparent_submap_tests(*)\n", __func__);
	vm_map_range_lock_empty_transparent_submap_tests(VMRL_EXCLUSIVE | VMRL_ATOMIC);
	vm_map_range_lock_empty_transparent_submap_tests(VMRL_SHARED | VMRL_ATOMIC);
	vm_map_range_lock_empty_transparent_submap_tests(VMRL_EXCLUSIVE | VMRL_STREAM);
	vm_map_range_lock_empty_transparent_submap_tests(VMRL_SHARED | VMRL_STREAM);

	printf("%s: vm_range_lock_test_transparent_submap_hole_at_beginning(*)\n", __func__);
	vm_range_lock_test_transparent_submap_hole_at_beginning(VMRL_EXCLUSIVE | VMRL_STREAM);
	vm_range_lock_test_transparent_submap_hole_at_beginning(VMRL_EXCLUSIVE | VMRL_STREAM_NO_HOLES);
	vm_range_lock_test_transparent_submap_hole_at_beginning(VMRL_SHARED | VMRL_STREAM);
	vm_range_lock_test_transparent_submap_hole_at_beginning(VMRL_SHARED | VMRL_STREAM_NO_HOLES);

	printf("%s: vm_range_lock_test_transparent_submap_hole_at_end(*)\n", __func__);
	vm_range_lock_test_transparent_submap_hole_at_end(VMRL_EXCLUSIVE | VMRL_STREAM);
	vm_range_lock_test_transparent_submap_hole_at_end(VMRL_EXCLUSIVE | VMRL_STREAM_NO_HOLES);
	vm_range_lock_test_transparent_submap_hole_at_end(VMRL_SHARED | VMRL_STREAM);
	vm_range_lock_test_transparent_submap_hole_at_end(VMRL_SHARED | VMRL_STREAM_NO_HOLES);

	printf("%s: vm_range_lock_test_transparent_submap_after_hole(*)\n", __func__);
	vm_range_lock_test_transparent_submap_after_hole(VMRL_EXCLUSIVE | VMRL_STREAM);
	vm_range_lock_test_transparent_submap_after_hole(VMRL_EXCLUSIVE | VMRL_STREAM_NO_HOLES);
	vm_range_lock_test_transparent_submap_after_hole(VMRL_SHARED | VMRL_STREAM);
	vm_range_lock_test_transparent_submap_after_hole(VMRL_SHARED | VMRL_STREAM_NO_HOLES);

	printf("%s: vm_range_lock_test_transparent_submap_before_hole(*)\n", __func__);
	vm_range_lock_test_transparent_submap_before_hole(VMRL_EXCLUSIVE | VMRL_STREAM);
	vm_range_lock_test_transparent_submap_before_hole(VMRL_EXCLUSIVE | VMRL_STREAM_NO_HOLES);
	vm_range_lock_test_transparent_submap_before_hole(VMRL_SHARED | VMRL_STREAM);
	vm_range_lock_test_transparent_submap_before_hole(VMRL_SHARED | VMRL_STREAM_NO_HOLES);

	printf("%s: test passed\n", __func__);

	*out = 1;
	return 0;
}

static int
vm_range_lock_preflight_test(__unused int64_t in, int64_t *out)
{
	printf("%s: test running (thread=%p)\n", __func__, current_thread());

	vm_range_lock_test_preflight_empty_range(VMRL_EXCLUSIVE | VMRL_ATOMIC);
	vm_range_lock_test_preflight_empty_range(VMRL_EXCLUSIVE | VMRL_ATOMIC_ALLOW_HOLES);
	vm_range_lock_test_preflight_empty_range(VMRL_EXCLUSIVE | VMRL_STREAM);
	vm_range_lock_test_preflight_empty_range(VMRL_EXCLUSIVE | VMRL_STREAM_NO_HOLES);

	vm_range_lock_test_preflight_empty_range(VMRL_SHARED | VMRL_ATOMIC);
	vm_range_lock_test_preflight_empty_range(VMRL_SHARED | VMRL_ATOMIC_ALLOW_HOLES);
	vm_range_lock_test_preflight_empty_range(VMRL_SHARED | VMRL_STREAM);
	vm_range_lock_test_preflight_empty_range(VMRL_SHARED | VMRL_STREAM_NO_HOLES);

	vm_range_lock_test_preflight_single_range(VMRL_EXCLUSIVE | VMRL_ATOMIC, KERN_SUCCESS);
	vm_range_lock_test_preflight_single_range(VMRL_EXCLUSIVE | VMRL_ATOMIC_ALLOW_HOLES, KERN_SUCCESS);
	vm_range_lock_test_preflight_single_range(VMRL_EXCLUSIVE | VMRL_STREAM, KERN_SUCCESS);
	vm_range_lock_test_preflight_single_range(VMRL_EXCLUSIVE | VMRL_STREAM_NO_HOLES, KERN_SUCCESS);

	vm_range_lock_test_preflight_single_range(VMRL_SHARED | VMRL_ATOMIC, KERN_SUCCESS);
	vm_range_lock_test_preflight_single_range(VMRL_SHARED | VMRL_ATOMIC_ALLOW_HOLES, KERN_SUCCESS);
	vm_range_lock_test_preflight_single_range(VMRL_SHARED | VMRL_STREAM, KERN_SUCCESS);
	vm_range_lock_test_preflight_single_range(VMRL_SHARED | VMRL_STREAM_NO_HOLES, KERN_SUCCESS);

	vm_range_lock_test_preflight_multiple_contiguous(VMRL_EXCLUSIVE | VMRL_ATOMIC, KERN_SUCCESS);
	vm_range_lock_test_preflight_multiple_contiguous(VMRL_EXCLUSIVE | VMRL_ATOMIC_ALLOW_HOLES, KERN_SUCCESS);
	vm_range_lock_test_preflight_multiple_contiguous(VMRL_EXCLUSIVE | VMRL_STREAM, KERN_SUCCESS);
	vm_range_lock_test_preflight_multiple_contiguous(VMRL_EXCLUSIVE | VMRL_STREAM_NO_HOLES, KERN_SUCCESS);

	vm_range_lock_test_preflight_multiple_contiguous(VMRL_SHARED | VMRL_ATOMIC, KERN_SUCCESS);
	vm_range_lock_test_preflight_multiple_contiguous(VMRL_SHARED | VMRL_ATOMIC_ALLOW_HOLES, KERN_SUCCESS);
	vm_range_lock_test_preflight_multiple_contiguous(VMRL_SHARED | VMRL_STREAM, KERN_SUCCESS);
	vm_range_lock_test_preflight_multiple_contiguous(VMRL_SHARED | VMRL_STREAM_NO_HOLES, KERN_SUCCESS);

	vm_range_lock_test_preflight_multiple_disjoint(VMRL_EXCLUSIVE | VMRL_ATOMIC, KERN_INVALID_ADDRESS);
	vm_range_lock_test_preflight_multiple_disjoint(VMRL_EXCLUSIVE | VMRL_ATOMIC_ALLOW_HOLES, KERN_SUCCESS);
	vm_range_lock_test_preflight_multiple_disjoint(VMRL_EXCLUSIVE | VMRL_STREAM, KERN_SUCCESS);
	vm_range_lock_test_preflight_multiple_disjoint_streaming(VMRL_EXCLUSIVE | VMRL_STREAM_NO_HOLES, KERN_INVALID_ADDRESS);

	vm_range_lock_test_preflight_multiple_disjoint(VMRL_SHARED | VMRL_ATOMIC, KERN_INVALID_ADDRESS);
	vm_range_lock_test_preflight_multiple_disjoint(VMRL_SHARED | VMRL_ATOMIC_ALLOW_HOLES, KERN_SUCCESS);
	vm_range_lock_test_preflight_multiple_disjoint(VMRL_SHARED | VMRL_STREAM, KERN_SUCCESS);
	vm_range_lock_test_preflight_multiple_disjoint_streaming(VMRL_SHARED | VMRL_STREAM_NO_HOLES, KERN_INVALID_ADDRESS);

	vm_range_lock_test_preflight_contiguous_with_error(VMRL_EXCLUSIVE | VMRL_ATOMIC, KERN_FAILURE);
	vm_range_lock_test_preflight_contiguous_with_error(VMRL_EXCLUSIVE | VMRL_ATOMIC_ALLOW_HOLES, KERN_FAILURE);
	vm_range_lock_test_preflight_contiguous_with_error(VMRL_EXCLUSIVE | VMRL_STREAM, KERN_FAILURE);
	vm_range_lock_test_preflight_contiguous_with_error(VMRL_EXCLUSIVE | VMRL_STREAM_NO_HOLES, KERN_FAILURE);

	vm_range_lock_test_preflight_contiguous_with_error(VMRL_SHARED | VMRL_ATOMIC, KERN_FAILURE);
	vm_range_lock_test_preflight_contiguous_with_error(VMRL_SHARED | VMRL_ATOMIC_ALLOW_HOLES, KERN_FAILURE);
	vm_range_lock_test_preflight_contiguous_with_error(VMRL_SHARED | VMRL_STREAM, KERN_FAILURE);
	vm_range_lock_test_preflight_contiguous_with_error(VMRL_SHARED | VMRL_STREAM_NO_HOLES, KERN_FAILURE);

	vm_range_lock_test_preflight_skip_prepare(VMRL_EXCLUSIVE | VMRL_ATOMIC, KERN_SUCCESS);
	vm_range_lock_test_preflight_skip_prepare(VMRL_EXCLUSIVE | VMRL_ATOMIC_ALLOW_HOLES, KERN_SUCCESS);
	vm_range_lock_test_preflight_skip_prepare(VMRL_EXCLUSIVE | VMRL_STREAM, KERN_SUCCESS);
	vm_range_lock_test_preflight_skip_prepare(VMRL_EXCLUSIVE | VMRL_STREAM_NO_HOLES, KERN_SUCCESS);

	vm_range_lock_test_preflight_skip_prepare(VMRL_SHARED | VMRL_ATOMIC, KERN_SUCCESS);
	vm_range_lock_test_preflight_skip_prepare(VMRL_SHARED | VMRL_ATOMIC_ALLOW_HOLES, KERN_SUCCESS);
	vm_range_lock_test_preflight_skip_prepare(VMRL_SHARED | VMRL_STREAM, KERN_SUCCESS);
	vm_range_lock_test_preflight_skip_prepare(VMRL_SHARED | VMRL_STREAM_NO_HOLES, KERN_SUCCESS);

	vm_range_lock_test_preflight_with_constant_submap(VMRL_EXCLUSIVE | VMRL_ATOMIC, KERN_INVALID_ADDRESS);
	vm_range_lock_test_preflight_with_constant_submap(VMRL_EXCLUSIVE | VMRL_ATOMIC_ALLOW_HOLES, KERN_SUCCESS);
	vm_range_lock_test_preflight_with_constant_submap(VMRL_EXCLUSIVE | VMRL_STREAM_NO_HOLES, KERN_INVALID_ADDRESS);
	vm_range_lock_test_preflight_with_constant_submap(VMRL_EXCLUSIVE | VMRL_STREAM, KERN_SUCCESS);

	vm_range_lock_test_preflight_with_constant_submap(VMRL_SHARED | VMRL_ATOMIC, KERN_INVALID_ADDRESS);
	vm_range_lock_test_preflight_with_constant_submap(VMRL_SHARED | VMRL_ATOMIC_ALLOW_HOLES, KERN_SUCCESS);
	vm_range_lock_test_preflight_with_constant_submap(VMRL_SHARED | VMRL_STREAM_NO_HOLES, KERN_INVALID_ADDRESS);
	vm_range_lock_test_preflight_with_constant_submap(VMRL_SHARED | VMRL_STREAM, KERN_SUCCESS);

	vm_range_lock_test_preflight_with_constant_submap(VMRL_SHARED | VMRL_DESCEND_INTO_CONSTANT | VMRL_ATOMIC, KERN_INVALID_ADDRESS);
	vm_range_lock_test_preflight_with_constant_submap(VMRL_SHARED | VMRL_DESCEND_INTO_CONSTANT | VMRL_ATOMIC_ALLOW_HOLES, KERN_SUCCESS);
	vm_range_lock_test_preflight_with_constant_submap(VMRL_SHARED | VMRL_DESCEND_INTO_CONSTANT | VMRL_STREAM_NO_HOLES, KERN_INVALID_ADDRESS);
	vm_range_lock_test_preflight_with_constant_submap(VMRL_SHARED | VMRL_DESCEND_INTO_CONSTANT | VMRL_STREAM, KERN_SUCCESS);

	vm_range_lock_test_preflight_with_constant_submap_and_error(VMRL_EXCLUSIVE | VMRL_ATOMIC, KERN_INVALID_ADDRESS);
	vm_range_lock_test_preflight_with_constant_submap_and_error(VMRL_EXCLUSIVE | VMRL_ATOMIC_ALLOW_HOLES, KERN_FAILURE);
	vm_range_lock_test_preflight_with_constant_submap_and_error(VMRL_EXCLUSIVE | VMRL_STREAM_NO_HOLES, KERN_INVALID_ADDRESS);
	vm_range_lock_test_preflight_with_constant_submap_and_error(VMRL_EXCLUSIVE | VMRL_STREAM, KERN_FAILURE);

	vm_range_lock_test_preflight_with_constant_submap_and_error(VMRL_SHARED | VMRL_ATOMIC, KERN_INVALID_ADDRESS);
	vm_range_lock_test_preflight_with_constant_submap_and_error(VMRL_SHARED | VMRL_ATOMIC_ALLOW_HOLES, KERN_FAILURE);
	vm_range_lock_test_preflight_with_constant_submap_and_error(VMRL_SHARED | VMRL_STREAM_NO_HOLES, KERN_INVALID_ADDRESS);
	vm_range_lock_test_preflight_with_constant_submap_and_error(VMRL_SHARED | VMRL_STREAM, KERN_FAILURE);

	vm_range_lock_test_preflight_with_constant_submap_and_error(VMRL_SHARED | VMRL_DESCEND_INTO_CONSTANT | VMRL_ATOMIC, KERN_INVALID_ADDRESS);
	vm_range_lock_test_preflight_with_constant_submap_and_error(VMRL_SHARED | VMRL_DESCEND_INTO_CONSTANT | VMRL_ATOMIC_ALLOW_HOLES, KERN_FAILURE);
	vm_range_lock_test_preflight_with_constant_submap_and_error(VMRL_SHARED | VMRL_DESCEND_INTO_CONSTANT | VMRL_STREAM_NO_HOLES, KERN_INVALID_ADDRESS);
	vm_range_lock_test_preflight_with_constant_submap_and_error(VMRL_SHARED | VMRL_DESCEND_INTO_CONSTANT | VMRL_STREAM, KERN_FAILURE);

	vm_range_lock_test_preflight_with_transparent_submap(VMRL_EXCLUSIVE | VMRL_ATOMIC, KERN_SUCCESS);
	vm_range_lock_test_preflight_with_transparent_submap(VMRL_EXCLUSIVE | VMRL_ATOMIC_ALLOW_HOLES, KERN_SUCCESS);
	vm_range_lock_test_preflight_with_transparent_submap(VMRL_EXCLUSIVE | VMRL_STREAM_NO_HOLES, KERN_SUCCESS);
	vm_range_lock_test_preflight_with_transparent_submap(VMRL_EXCLUSIVE | VMRL_STREAM, KERN_SUCCESS);

	vm_range_lock_test_preflight_with_transparent_submap(VMRL_SHARED | VMRL_STREAM, KERN_SUCCESS);
	vm_range_lock_test_preflight_with_transparent_submap(VMRL_SHARED | VMRL_STREAM | VMRL_NO_DESCEND_TRANSPARENT, KERN_SUCCESS);  // This case does not descend
	vm_range_lock_test_preflight_with_transparent_submap(VMRL_SHARED | VMRL_STREAM | VMRL_DESCEND_INTO_CONSTANT, KERN_SUCCESS);

	vm_range_lock_test_preflight_with_transparent_submap_with_error(VMRL_EXCLUSIVE | VMRL_ATOMIC, KERN_FAILURE);
	vm_range_lock_test_preflight_with_transparent_submap_with_error(VMRL_EXCLUSIVE | VMRL_ATOMIC_ALLOW_HOLES, KERN_FAILURE);
	vm_range_lock_test_preflight_with_transparent_submap_with_error(VMRL_EXCLUSIVE | VMRL_STREAM_NO_HOLES, KERN_FAILURE);
	vm_range_lock_test_preflight_with_transparent_submap_with_error(VMRL_EXCLUSIVE | VMRL_STREAM, KERN_FAILURE);

	vm_range_lock_test_preflight_with_transparent_submap_with_error(VMRL_SHARED | VMRL_STREAM | VMRL_SH_NO_DESCEND_TRANSPARENT, KERN_SUCCESS); // This case does not descend
	vm_range_lock_test_preflight_with_transparent_submap_with_error(VMRL_SHARED | VMRL_STREAM, KERN_FAILURE);
	vm_range_lock_test_preflight_with_transparent_submap_with_error(VMRL_SHARED | VMRL_STREAM | VMRL_DESCEND_INTO_CONSTANT, KERN_FAILURE);

	vm_range_lock_test_preflight_with_transparent_submap_with_initial_error(VMRL_EXCLUSIVE | VMRL_ATOMIC, KERN_PROTECTION_FAILURE);
	vm_range_lock_test_preflight_with_transparent_submap_with_initial_error(VMRL_EXCLUSIVE | VMRL_ATOMIC_ALLOW_HOLES, KERN_PROTECTION_FAILURE);
	vm_range_lock_test_preflight_with_transparent_submap_with_initial_error(VMRL_EXCLUSIVE | VMRL_STREAM_NO_HOLES, KERN_PROTECTION_FAILURE);
	vm_range_lock_test_preflight_with_transparent_submap_with_initial_error(VMRL_EXCLUSIVE | VMRL_STREAM, KERN_PROTECTION_FAILURE);

	vm_range_lock_test_preflight_with_transparent_submap_with_initial_error(VMRL_SHARED | VMRL_STREAM, KERN_PROTECTION_FAILURE);
	vm_range_lock_test_preflight_with_transparent_submap_with_initial_error(VMRL_SHARED | VMRL_STREAM | VMRL_SH_NO_DESCEND_TRANSPARENT, KERN_SUCCESS); // This case does not descend
	vm_range_lock_test_preflight_with_transparent_submap_with_initial_error(VMRL_SHARED | VMRL_STREAM | VMRL_DESCEND_INTO_CONSTANT, KERN_PROTECTION_FAILURE);

	vm_range_lock_test_preflight_with_transparent_submap_with_final_error(VMRL_EXCLUSIVE | VMRL_ATOMIC, KERN_PROTECTION_FAILURE);
	vm_range_lock_test_preflight_with_transparent_submap_with_final_error(VMRL_EXCLUSIVE | VMRL_ATOMIC_ALLOW_HOLES, KERN_PROTECTION_FAILURE);
	vm_range_lock_test_preflight_with_transparent_submap_with_final_error(VMRL_EXCLUSIVE | VMRL_STREAM_NO_HOLES, KERN_PROTECTION_FAILURE);
	vm_range_lock_test_preflight_with_transparent_submap_with_final_error(VMRL_EXCLUSIVE | VMRL_STREAM, KERN_PROTECTION_FAILURE);

	vm_range_lock_test_preflight_with_transparent_submap_with_final_error(VMRL_SHARED | VMRL_STREAM, KERN_PROTECTION_FAILURE);
	vm_range_lock_test_preflight_with_transparent_submap_with_final_error(VMRL_SHARED | VMRL_STREAM | VMRL_SH_NO_DESCEND_TRANSPARENT, KERN_SUCCESS); // This case does not descend
	vm_range_lock_test_preflight_with_transparent_submap_with_final_error(VMRL_SHARED | VMRL_STREAM | VMRL_DESCEND_INTO_CONSTANT, KERN_PROTECTION_FAILURE);

	vm_range_lock_test_preflight_with_transparent_submap_descent(VMRL_EXCLUSIVE | VMRL_STREAM_NO_HOLES, KERN_SUCCESS);
	vm_range_lock_test_preflight_with_transparent_submap_descent(VMRL_EXCLUSIVE | VMRL_STREAM, KERN_SUCCESS);

	vm_range_lock_test_preflight_with_transparent_submap_descent(VMRL_SHARED | VMRL_STREAM, KERN_SUCCESS);
	vm_range_lock_test_preflight_with_transparent_submap_descent(VMRL_SHARED | VMRL_STREAM | VMRL_SH_NO_DESCEND_TRANSPARENT, KERN_SUCCESS);
	vm_range_lock_test_preflight_with_transparent_submap_descent(VMRL_SHARED | VMRL_STREAM | VMRL_DESCEND_INTO_CONSTANT, KERN_SUCCESS);

	vm_range_lock_test_preflight_with_single_entry_transparent_submap_descent(VMRL_EXCLUSIVE | VMRL_STREAM_NO_HOLES, KERN_SUCCESS);
	vm_range_lock_test_preflight_with_single_entry_transparent_submap_descent(VMRL_EXCLUSIVE | VMRL_STREAM, KERN_SUCCESS);

	vm_range_lock_test_preflight_with_single_entry_transparent_submap_descent(VMRL_SHARED | VMRL_STREAM, KERN_SUCCESS);
	vm_range_lock_test_preflight_with_single_entry_transparent_submap_descent(VMRL_SHARED | VMRL_STREAM | VMRL_SH_NO_DESCEND_TRANSPARENT, KERN_SUCCESS);
	vm_range_lock_test_preflight_with_single_entry_transparent_submap_descent(VMRL_SHARED | VMRL_STREAM | VMRL_DESCEND_INTO_CONSTANT, KERN_SUCCESS);

	vm_range_lock_test_preflight_with_transparent_submap_descent_and_clipping(VMRL_EXCLUSIVE | VMRL_STREAM_NO_HOLES, KERN_SUCCESS);
	vm_range_lock_test_preflight_with_transparent_submap_descent_and_clipping(VMRL_EXCLUSIVE | VMRL_STREAM, KERN_SUCCESS);

	vm_range_lock_test_preflight_with_transparent_submap_descent_and_clipping(VMRL_SHARED | VMRL_STREAM, KERN_SUCCESS);
	vm_range_lock_test_preflight_with_transparent_submap_descent_and_clipping(VMRL_SHARED | VMRL_STREAM | VMRL_SH_NO_DESCEND_TRANSPARENT, KERN_SUCCESS);
	vm_range_lock_test_preflight_with_transparent_submap_descent_and_clipping(VMRL_SHARED | VMRL_STREAM | VMRL_DESCEND_INTO_CONSTANT, KERN_SUCCESS);

	vm_range_lock_test_preflight_with_transparent_submap_ascent_and_clipping(VMRL_EXCLUSIVE | VMRL_STREAM_NO_HOLES, KERN_SUCCESS);
	vm_range_lock_test_preflight_with_transparent_submap_ascent_and_clipping(VMRL_EXCLUSIVE | VMRL_STREAM, KERN_SUCCESS);

	vm_range_lock_test_preflight_with_transparent_submap_ascent_and_clipping(VMRL_SHARED | VMRL_STREAM, KERN_SUCCESS);
	vm_range_lock_test_preflight_with_transparent_submap_ascent_and_clipping(VMRL_SHARED | VMRL_STREAM | VMRL_SH_NO_DESCEND_TRANSPARENT, KERN_SUCCESS);
	vm_range_lock_test_preflight_with_transparent_submap_ascent_and_clipping(VMRL_SHARED | VMRL_STREAM | VMRL_DESCEND_INTO_CONSTANT, KERN_SUCCESS);

	vm_range_lock_test_preflight_with_transparent_submap_descent_and_initial_error(VMRL_EXCLUSIVE | VMRL_STREAM_NO_HOLES, KERN_PROTECTION_FAILURE);
	vm_range_lock_test_preflight_with_transparent_submap_descent_and_initial_error(VMRL_EXCLUSIVE | VMRL_STREAM, KERN_PROTECTION_FAILURE);

	vm_range_lock_test_preflight_with_transparent_submap_descent_and_initial_error(VMRL_SHARED | VMRL_STREAM | VMRL_SH_NO_DESCEND_TRANSPARENT, KERN_SUCCESS); // This case does not descend
	vm_range_lock_test_preflight_with_transparent_submap_descent_and_initial_error(VMRL_SHARED | VMRL_STREAM, KERN_PROTECTION_FAILURE);
	vm_range_lock_test_preflight_with_transparent_submap_descent_and_initial_error(VMRL_SHARED | VMRL_STREAM | VMRL_DESCEND_INTO_CONSTANT, KERN_PROTECTION_FAILURE);

	vm_range_lock_test_preflight_with_transparent_submap_descent_and_final_error(VMRL_EXCLUSIVE | VMRL_STREAM_NO_HOLES, KERN_PROTECTION_FAILURE);
	vm_range_lock_test_preflight_with_transparent_submap_descent_and_final_error(VMRL_EXCLUSIVE | VMRL_STREAM, KERN_PROTECTION_FAILURE);

	vm_range_lock_test_preflight_with_transparent_submap_descent_and_final_error(VMRL_SHARED | VMRL_STREAM | VMRL_SH_NO_DESCEND_TRANSPARENT, KERN_SUCCESS); // This case does not descend
	vm_range_lock_test_preflight_with_transparent_submap_descent_and_final_error(VMRL_SHARED | VMRL_STREAM, KERN_PROTECTION_FAILURE);
	vm_range_lock_test_preflight_with_transparent_submap_descent_and_final_error(VMRL_SHARED | VMRL_STREAM | VMRL_DESCEND_INTO_CONSTANT, KERN_PROTECTION_FAILURE);

	vm_range_lock_test_preflight_with_transparent_submap_and_clipping(VMRL_EXCLUSIVE | VMRL_ATOMIC, KERN_SUCCESS);
	vm_range_lock_test_preflight_with_transparent_submap_and_clipping(VMRL_EXCLUSIVE | VMRL_ATOMIC_ALLOW_HOLES, KERN_SUCCESS);
	vm_range_lock_test_preflight_with_transparent_submap_and_clipping(VMRL_EXCLUSIVE | VMRL_STREAM_NO_HOLES, KERN_SUCCESS);
	vm_range_lock_test_preflight_with_transparent_submap_and_clipping(VMRL_EXCLUSIVE | VMRL_STREAM, KERN_SUCCESS);

	vm_range_lock_test_preflight_with_transparent_submap_and_clipping(VMRL_SHARED | VMRL_STREAM, KERN_SUCCESS);
	vm_range_lock_test_preflight_with_transparent_submap_and_clipping(VMRL_SHARED | VMRL_STREAM | VMRL_SH_NO_DESCEND_TRANSPARENT, KERN_SUCCESS);
	vm_range_lock_test_preflight_with_transparent_submap_and_clipping(VMRL_SHARED | VMRL_STREAM | VMRL_DESCEND_INTO_CONSTANT, KERN_SUCCESS);

	vm_range_lock_test_preflight_with_transparent_submap_descent_and_parent_clipping(VMRL_EXCLUSIVE | VMRL_STREAM_NO_HOLES, KERN_SUCCESS);
	vm_range_lock_test_preflight_with_transparent_submap_descent_and_parent_clipping(VMRL_EXCLUSIVE | VMRL_STREAM, KERN_SUCCESS);

	vm_range_lock_test_preflight_with_transparent_submap_descent_and_parent_clipping(VMRL_SHARED | VMRL_STREAM, KERN_SUCCESS);
	vm_range_lock_test_preflight_with_transparent_submap_descent_and_parent_clipping(VMRL_SHARED | VMRL_STREAM | VMRL_SH_NO_DESCEND_TRANSPARENT, KERN_SUCCESS);
	vm_range_lock_test_preflight_with_transparent_submap_descent_and_parent_clipping(VMRL_SHARED | VMRL_STREAM | VMRL_DESCEND_INTO_CONSTANT, KERN_SUCCESS);

	vm_range_lock_test_preflight_single_range_unwire(VMRL_EXCLUSIVE | VMRL_ATOMIC, KERN_SUCCESS);
	vm_range_lock_test_preflight_single_range_unwire(VMRL_EXCLUSIVE | VMRL_STREAM, KERN_SUCCESS);

	vm_range_lock_test_preflight_multiple_disjoint_with_upgrade(VMRL_SHARED | VMRL_ATOMIC, KERN_INVALID_ADDRESS);
	vm_range_lock_test_preflight_multiple_disjoint_with_upgrade(VMRL_SHARED | VMRL_ATOMIC_ALLOW_HOLES, KERN_SUCCESS);
	vm_range_lock_test_preflight_multiple_disjoint_with_upgrade(VMRL_SHARED | VMRL_STREAM_NO_HOLES, KERN_INVALID_ADDRESS);
	vm_range_lock_test_preflight_multiple_disjoint_with_upgrade(VMRL_SHARED | VMRL_STREAM, KERN_SUCCESS);

	printf("%s: test passed\n", __func__);

	*out = 1;
	return 0;
}

#pragma mark race tests

#define NUM_CONTIGUOUS_ENTRIES 3
#define NUM_GAP_ENTRIES 5

struct multi_thread_test_ctx {
	vm_map_address_t gap_entry_bounds[NUM_GAP_ENTRIES][2];
	vm_map_address_t contiguous_entry_bounds[NUM_CONTIGUOUS_ENTRIES][2];
	vm_map_t map;
};


static void
setup_ctx(struct multi_thread_test_ctx * ctx, int num_contig_entries, int num_gap_entries)
{
	ctx->map = vm_test_alloc_map();
	vm_map_address_t last_end;

	for (int i = 0; i < num_contig_entries; i++) {
		vm_map_address_t start = PAGE_SIZE * (10 + i);
		vm_map_address_t end = start + PAGE_SIZE;
		vm_map_entry_t entry = vm_test_add_map_entry(ctx->map, start, end);
		entry->protection = 0;
		ctx->contiguous_entry_bounds[i][0] = start;
		ctx->contiguous_entry_bounds[i][1] = end;

		last_end = end;
	}

	for (int i = 0; i < num_gap_entries; i++) {
		vm_map_address_t start = last_end +  PAGE_SIZE * (i * 2);
		vm_map_address_t end = start + PAGE_SIZE;
		vm_map_entry_t entry = vm_test_add_map_entry(ctx->map, start, end);
		entry->protection = 0;
		ctx->gap_entry_bounds[i][0] = start;
		ctx->gap_entry_bounds[i][1] = end;
	}
}

#define MAX_WAIT_ITERS 50
static void
wait_a_bit_to_make_race_window_larger(size_t wait_multiplier)
{
	size_t iterations = random() % (MAX_WAIT_ITERS * wait_multiplier);
	for (volatile size_t i = 0; i < iterations; i++) {
	}
}

/*
 * This works by making sure prot == 1 means the lock is being held. If we observe that without setting that, there's a race.
 *
 * The algorithm to test that works like this:
 * (for iterations testing exclusive locks)
 * Exclusively lock a range
 * Check that all prot start at 0. If not, some race happened.
 * Set all prot to 1.
 * Wait a little (to make the race window larger)
 * Reset all prot to 0
 * Unlock
 *
 * (for iterations testing shared locks)
 * Lock
 * Check that all prot are 0.
 * Unlock
 *
 * In addition, we concurrently set needs_coalesce on the entry to make sure
 * it can be properly changed under its locking domain of the interlock without
 * the protection of the entry.
 */
static void
test_contiguous_race(struct multi_thread_test_ctx * test_ctx, uint32_t num_races_to_test)
{
	bool test_as_exclusive_writer = (random() % 4 == 0);
	bool test_as_shared_reader = (random() % 3 != 0);


	for (uint32_t i = 0; i < num_races_to_test; i++) {
		VM_MAP_LOCK_CTX_DECLARE(ctx);
		vm_map_entry_t entry;
		kern_return_t kr;
		vm_map_t map = test_ctx->map;

		int max_vm_map_entry_to_test = random() % NUM_CONTIGUOUS_ENTRIES;
		int min_vm_map_entry_to_test = random() % (max_vm_map_entry_to_test + 1);

		volatile vm_map_address_t start = test_ctx->contiguous_entry_bounds[min_vm_map_entry_to_test][0];
		volatile vm_map_address_t end = test_ctx->contiguous_entry_bounds[max_vm_map_entry_to_test][1];
		if (test_as_exclusive_writer) {
			/*
			 * Exclusive, set prot = 1, then back to 0
			 */
			kr = vm_map_range_ex_lock(ctx, &map, start, end, VMRL_EX_ATOMIC);
			assert3u(kr, ==, KERN_SUCCESS);
			assert_range_is_excl_locked(ctx->vmlc_map, start, end);

			while ((entry = vm_map_range_atomic_next(ctx))) {
				vm_entry_assert_excl_owner(entry);
				assert(entry->protection == 0);
				entry->protection = 1;
			}

			vm_map_range_atomic_reset(ctx);
			assert_range_is_excl_locked(ctx->vmlc_map, start, end);

			while ((entry = vm_map_range_atomic_next(ctx))) {
				vm_entry_assert_excl_owner(entry);
				assert(entry->protection == 1);
				entry->protection = 0;
			}

			vm_map_range_ex_unlock(ctx, &map);
		} else if (test_as_shared_reader) {
			/*
			 * Reader, check prot == 0
			 */
			kr = vm_map_range_sh_lock(ctx, &map, start, end, VMRL_SH_STREAM);
			assert3u(kr, ==, KERN_SUCCESS);

			while ((entry = vm_map_range_stream_next(ctx))) {
				vm_entry_assert_shared_owner(entry);
				assert(entry->protection == 0);
			}

			vm_map_range_sh_unlock(ctx, &map);
		} else {
			/*
			 * Needs_coalesce setter, just change needs_coalesce
			 * and try to lock the neighboring entry
			 */
			__vmrl_ilk_lock_exclusive(map);
			assert((entry = vm_map_lookup(map, start)));
			kr = vm_entry_lock_exclusive(map, LCK_RW_TYPE_EXCLUSIVE,
			    entry, start, THREAD_UNINT);
			if (kr == KERN_SUCCESS) {
				if (entry_is_map_end(map, entry->vme_next)) {
					/* nothing to do */
				} else if (vm_entry_try_lock_exclusive(entry->vme_next)) {
					vm_entry_update_needs_coalesce(entry->vme_next, false);
					vm_entry_unlock_exclusive(map, entry->vme_next);
				} else {
					vm_entry_update_needs_coalesce(entry->vme_next, true);
				}
			}
			__vmrl_ilk_unlock_exclusive(map);
			vm_entry_unlock_exclusive(map, entry);
		}
	}
}


static void
test_streaming_race(struct multi_thread_test_ctx * test_ctx, uint32_t num_races_to_test)
{
	for (uint32_t i = 0; i < num_races_to_test; i++) {
		VM_MAP_LOCK_CTX_DECLARE(ctx);
		vm_map_entry_t entry;
		kern_return_t kr;

		bool test_as_exclusive_writer = random() % 2;
		int max_vm_map_entry_to_test = random() % NUM_GAP_ENTRIES;
		int min_vm_map_entry_to_test = random() % (max_vm_map_entry_to_test + 1);

		vm_map_t test_ctx_map = test_ctx->map;
		volatile vm_map_address_t start = test_ctx->gap_entry_bounds[min_vm_map_entry_to_test][0];
		volatile vm_map_address_t end = test_ctx->gap_entry_bounds[max_vm_map_entry_to_test][1];
		if (test_as_exclusive_writer) {
			kr = vm_map_range_ex_lock(ctx, &test_ctx_map, start, end, VMRL_EX_STREAM);
			assert3u(kr, ==, KERN_SUCCESS);

			while ((entry = vm_map_range_stream_next(ctx))) {
				vm_entry_assert_excl_owner(entry);
				assert(entry->protection == 0);
				entry->protection = 1;
				wait_a_bit_to_make_race_window_larger(1);
				assert(entry->protection == 1);
				entry->protection = 0;
			}

			vm_map_range_ex_unlock(ctx, &test_ctx_map);
		} else {
			kr = vm_map_range_sh_lock(ctx, &test_ctx_map, start, end, VMRL_SH_STREAM);
			assert3u(kr, ==, KERN_SUCCESS);

			while ((entry = vm_map_range_stream_next(ctx))) {
				vm_entry_assert_shared_owner(entry);
				assert(entry->protection == 0);
			}
			vm_map_range_sh_unlock(ctx, &test_ctx_map);
		}
	}
}

struct multi_thread_test_ctx * global_test_ctx;
int num_contiguous_threads_waiting = 0;
int num_gap_threads_waiting = 0;

static LCK_GRP_DECLARE(_range_lock_test, "range lock test");
static LCK_MTX_DECLARE(range_lock_test_mtx, &_range_lock_test);

static struct multi_thread_test_ctx *
get_test_ctx(void)
{
	lck_mtx_lock(&range_lock_test_mtx);
	if (!global_test_ctx) {
		global_test_ctx = kalloc_type(struct multi_thread_test_ctx, Z_ZERO | Z_WAITOK);
		setup_ctx(global_test_ctx, NUM_CONTIGUOUS_ENTRIES, NUM_GAP_ENTRIES);
	}
	lck_mtx_unlock(&range_lock_test_mtx);
	return global_test_ctx;
}

static int
vm_range_lock_race_wait_for_all_threads_to_be_ready(int * thread_wait_count, int target_wait_count, event_t event)
{
	int ret = assert_wait(event, THREAD_UNINT);
	assert(ret == THREAD_WAITING);
	int waiters = os_atomic_inc(thread_wait_count, release);
	if (waiters == target_wait_count) {
		os_atomic_store(thread_wait_count, 0, release);

		clear_wait(current_thread(), THREAD_AWAKENED);
		thread_wakeup(event);
	} else {
		ret = thread_block(THREAD_CONTINUE_NULL);
		assert(ret == THREAD_AWAKENED);
	}
	return waiters;
}

void
unpack_threads_and_iterations(
	uint64_t  packed_threads_and_iters,
	uint32_t *thread_count,
	uint32_t *iterations);

void
unpack_threads_and_iterations(
	uint64_t  packed_threads_and_iters,
	uint32_t *thread_count,
	uint32_t *iterations)
{
	*thread_count = packed_threads_and_iters >> 32;
	*iterations = packed_threads_and_iters & (UINT32_MAX);
}

static int
vm_range_lock_race_test(int64_t packed_thread_and_iters, int64_t *out)
{
	uint32_t num_threads_to_wait_for;
	uint32_t num_races_to_test;

	unpack_threads_and_iterations((uint64_t) packed_thread_and_iters,
	    &num_threads_to_wait_for, &num_races_to_test);

	if (num_threads_to_wait_for > task_threadmax) {
		return ENOSPC;
	}
	struct multi_thread_test_ctx * test_ctx = get_test_ctx();

	vm_range_lock_race_wait_for_all_threads_to_be_ready(&num_contiguous_threads_waiting, (int) num_threads_to_wait_for, (event_t) test_ctx);
	test_contiguous_race(test_ctx, num_races_to_test);
	vm_range_lock_race_wait_for_all_threads_to_be_ready(&num_gap_threads_waiting, (int) num_threads_to_wait_for, (event_t)(((uintptr_t)test_ctx) + 1));
	test_streaming_race(test_ctx, num_races_to_test);

	*out = 1;
	return 0;
}

#pragma mark lock flags tests

static void
resolve_tests(void)
{
	vm_map_t map = vm_test_alloc_map();

	vm_map_address_t start = 0x4000;
	vm_map_address_t end = 0x8000;
	vm_test_add_map_entry(map, start, end); /* Put an entry that spans the map */

	VM_MAP_LOCK_CTX_DECLARE(ctx);
	kern_return_t kr;

	vm_map_entry_t entry = find_entry_unlocked(map, start);
	entry->use_pmap = true;
	assert(VME_OBJECT(entry) == NULL);

	/* First test null obj alloc */
	kr = vm_map_range_ex_lock(ctx, &map, start, end,
	    VMRL_EX_ATOMIC | VMRL_RESOLVE_COW_AND_OBJ);
	assert3u(kr, ==, KERN_SUCCESS);
	entry = vm_map_range_next_with_error(ctx, &kr);
	assert3u(kr, ==, KERN_SUCCESS);
	assert(VME_OBJECT(entry) != NULL);
	vm_map_range_ex_unlock(ctx, &map);

	/* Now test CoW resolution */
	entry->needs_copy = true;
	kr = vm_map_range_ex_lock(ctx, &map, start, end,
	    VMRL_EX_ATOMIC | VMRL_RESOLVE_COW_AND_OBJ);
	assert3u(kr, ==, KERN_SUCCESS);
	entry = vm_map_range_next_with_error(ctx, &kr);
	assert3u(kr, ==, KERN_SUCCESS);
	assert(VME_OBJECT(entry) != NULL);
	assert(entry->needs_copy == false);
	vm_map_range_ex_unlock(ctx, &map);


	vm_map_destroy(map);

	/* and do it again but for shared */
	map = vm_test_alloc_map();
	vm_test_add_map_entry(map, start, end); /* Put an entry that spans the map */

	entry = find_entry_unlocked(map, start);
	assert(VME_OBJECT(entry) == NULL);
	entry->use_pmap = true;

	/* First test null obj alloc */
	kr = vm_map_range_sh_lock(ctx, &map, start, end,
	    VMRL_SH_STREAM | VMRL_RESOLVE_COW_AND_OBJ);
	assert3u(kr, ==, KERN_SUCCESS);
	entry = vm_map_range_next_with_error(ctx, &kr);
	assert3u(kr, ==, KERN_SUCCESS);
	assert(VME_OBJECT(entry) != NULL);
	vm_map_range_sh_unlock(ctx, &map);

	/* Now test CoW resolution */
	entry->needs_copy = true;
	kr = vm_map_range_sh_lock(ctx, &map, start, end,
	    VMRL_SH_STREAM | VMRL_RESOLVE_COW_AND_OBJ);
	assert3u(kr, ==, KERN_SUCCESS);
	entry = vm_map_range_next_with_error(ctx, &kr);
	assert3u(kr, ==, KERN_SUCCESS);
	assert(VME_OBJECT(entry) != NULL);
	assert(entry->needs_copy == false);
	vm_map_range_sh_unlock(ctx, &map);

	vm_map_destroy(map);
}

static void
any_unlock(vm_map_lock_ctx_t ctx, vm_map_t* map)
{
	if (vmrl_is_shared(ctx)) {
		vm_map_range_sh_unlock(ctx, map);
	} else {
		vm_map_range_ex_unlock(ctx, map);
	}
}

static void
whole_map_tests_for_call(kern_return_t (^lock_call)(vm_map_lock_ctx_t ctx,
    vm_map_t *map,
    vm_map_address_t start,
    vm_map_address_t end,
    vmrl_flags_t flags), vmrl_flags_t in_flags)
{
	vm_map_t map = vm_test_alloc_map();

	vm_map_address_t first_entry_start = 0x4000;
	vm_map_address_t map_start = 0x8000;
	vm_map_address_t map_end = 0xc000;
	vm_map_address_t last_entry_end = 0x10000;

	map->min_offset = map_start;
	map->max_offset = map_end;
	vm_test_add_map_entry(map, map->min_offset, map->max_offset); /* Put an entry that spans the map */
	vm_test_add_map_entry(map, map->max_offset, last_entry_end); /* entry that goes after max offset */
	vm_test_add_map_entry(map, first_entry_start, map->min_offset); /* entry that goes before min offset */

	VM_MAP_LOCK_CTX_DECLARE(ctx);
	kern_return_t kr;

	/* Make sure we can lock a contained entry */
	kr = lock_call(ctx, &map, map->min_offset, map->max_offset, in_flags);
	assert3u(kr, ==, KERN_SUCCESS);
	vmrl_test_want_n_entries(ctx, 1);
	any_unlock(ctx, &map);

	/* Make we cannot lock a starting range before without the flag */
	kr = lock_call(ctx, &map, first_entry_start, map->min_offset, in_flags);
	assert3u(kr, ==, KERN_INVALID_ADDRESS);

	/* Or an end after */
	kr = lock_call(ctx, &map, map->max_offset, last_entry_end, in_flags);
	assert3u(kr, ==, KERN_INVALID_ADDRESS);

	/* Make sure NO_MIN_MAX_CHECK doesn't break a contained entry */
	kr = lock_call(ctx, &map, map->min_offset, map->max_offset, in_flags | VMRL_NO_MIN_MAX_CHECK);
	assert3u(kr, ==, KERN_SUCCESS);
	vmrl_test_want_n_entries(ctx, 1);
	any_unlock(ctx, &map);

	/* Make sure we can lock before start */
	kr = lock_call(ctx, &map, first_entry_start, map->max_offset, in_flags | VMRL_NO_MIN_MAX_CHECK);
	assert3u(kr, ==, KERN_SUCCESS);
	vmrl_test_want_n_entries(ctx, 2);
	any_unlock(ctx, &map);

	/* And after end */
	kr = lock_call(ctx, &map, map->min_offset, last_entry_end, in_flags | VMRL_NO_MIN_MAX_CHECK);
	assert3u(kr, ==, KERN_SUCCESS);
	vmrl_test_want_n_entries(ctx, 2);
	any_unlock(ctx, &map);

	/* The range [VMRL_START_VA, VMRL_END_VA) will be considered to have holes so if the lock call has ATOMIC, don't try that */
	if (!vmrl_is_atomic(in_flags)) {
		/* To the end of the VA space */
		kr = lock_call(ctx, &map, map->min_offset, VMRL_END_VA(map), in_flags | VMRL_NO_MIN_MAX_CHECK);
		assert3u(kr, ==, KERN_SUCCESS);
		vmrl_test_want_n_entries(ctx, 2);
		any_unlock(ctx, &map);

		kr = lock_call(ctx, &map, VMRL_START_VA(map), map->max_offset, in_flags | VMRL_NO_MIN_MAX_CHECK);
		assert3u(kr, ==, KERN_SUCCESS);
		vmrl_test_want_n_entries(ctx, 2);
		any_unlock(ctx, &map);

		/* before start and after end */
		kr = lock_call(ctx, &map, VMRL_WHOLE_MAP_START, VMRL_WHOLE_MAP_END, in_flags | VMRL_WHOLE_MAP);
		assert3u(kr, ==, KERN_SUCCESS);
		vmrl_test_want_n_entries(ctx, 3);
		any_unlock(ctx, &map);

		/* equivalent call using NO_MIN_MAX_CHECK */
		kr = lock_call(ctx, &map, VMRL_START_VA(map), VMRL_END_VA(map), in_flags | VMRL_NO_MIN_MAX_CHECK);
		assert3u(kr, ==, KERN_SUCCESS);
		vmrl_test_want_n_entries(ctx, 3);
		any_unlock(ctx, &map);

		/* using the whole-map start,end when not appropriate */
		kr = lock_call(ctx, &map, VMRL_WHOLE_MAP_START, VMRL_WHOLE_MAP_END, in_flags);
		assert3u(kr, ==, KERN_INVALID_ADDRESS);
		kr = lock_call(ctx, &map, VMRL_WHOLE_MAP_START, VMRL_WHOLE_MAP_END, in_flags | VMRL_NO_MIN_MAX_CHECK);
		assert3u(kr, ==, KERN_INVALID_ADDRESS);
	}

	vm_map_destroy(map);
}

static void
test_start_end_sentinels(void)
{
	vm_map_t map = vm_test_alloc_map();

	vm_map_address_t first_entry_start = 0x4000;
	vm_map_address_t map_start = 0x8000;
	vm_map_address_t map_end = 0xc000;
	vm_map_address_t last_entry_end = 0x10000;

	map->min_offset = map_start;
	map->max_offset = map_end;
	vm_test_add_map_entry(map, map->min_offset, map->max_offset); /* Put an entry that spans the map */
	vm_test_add_map_entry(map, map->max_offset, last_entry_end); /* entry that goes after max offset */
	vm_test_add_map_entry(map, first_entry_start, map->min_offset); /* entry that goes before min offset */

	VM_MAP_LOCK_CTX_DECLARE(ctx);
	kern_return_t kr;

	kr = vm_map_range_ex_lock(ctx, &map, VMRL_START_VA(map), map->max_offset, VMRL_EX_ATOMIC_ALLOW_HOLES | VMRL_NO_MIN_MAX_CHECK);
	assert3u(kr, ==, KERN_SUCCESS);
	vmrl_test_want_n_entries(ctx, 3); // sentinel, entry before min-max, entry in min-max
	vm_map_range_ex_unlock(ctx, &map);

	kr = vm_map_range_ex_lock(ctx, &map, map->min_offset, VMRL_END_VA(map), VMRL_EX_ATOMIC_ALLOW_HOLES | VMRL_NO_MIN_MAX_CHECK);
	assert3u(kr, ==, KERN_SUCCESS);
	vmrl_test_want_n_entries(ctx, 3); // entry in min-max, entry after min-max, sentinel
	vm_map_range_ex_unlock(ctx, &map);

	kr = vm_map_range_ex_lock(ctx, &map, VMRL_WHOLE_MAP_START, VMRL_WHOLE_MAP_END, VMRL_EX_ATOMIC_ALLOW_HOLES | VMRL_WHOLE_MAP);
	assert3u(kr, ==, KERN_SUCCESS);
	vmrl_test_want_n_entries(ctx, 5); // sentinel, entry before min-max, entry in min-max, entry after min-max, sentinel
	vm_map_range_ex_unlock(ctx, &map);


	vm_map_destroy(map);
}

static void
whole_map_tests(void)
{
	whole_map_tests_for_call(^kern_return_t (vm_map_lock_ctx_t ctx, vm_map_t *map, vm_map_address_t start, vm_map_address_t end, vmrl_flags_t flags) {
		// need to allow holes for the calls that go to the start/end of the VA
		return vm_map_range_ex_lock(ctx, map, start, end, (vmrl_ex_flags_t)flags);
	}, (vmrl_flags_t)VMRL_EX_ATOMIC);
	whole_map_tests_for_call(^kern_return_t (vm_map_lock_ctx_t ctx, vm_map_t *map, vm_map_address_t start, vm_map_address_t end, vmrl_flags_t flags) {
		return vm_map_range_ex_lock(ctx, map, start, end, (vmrl_ex_flags_t)flags);
	}, (vmrl_flags_t)VMRL_EX_STREAM);
	whole_map_tests_for_call(^kern_return_t (vm_map_lock_ctx_t ctx, vm_map_t *map, vm_map_address_t start, vm_map_address_t end, vmrl_flags_t flags) {
		return vm_map_range_sh_lock(ctx, map, start, end, (vmrl_sh_flags_t)flags);
	}, (vmrl_flags_t)VMRL_SH_ATOMIC);
	whole_map_tests_for_call(^kern_return_t (vm_map_lock_ctx_t ctx, vm_map_t *map, vm_map_address_t start, vm_map_address_t end, vmrl_flags_t flags) {
		return vm_map_range_sh_lock(ctx, map, start, end, (vmrl_sh_flags_t)flags);
	}, (vmrl_flags_t)VMRL_SH_STREAM);

	test_start_end_sentinels();
}


static void
unnest_tests(vmrl_flags_t flags)
{
	vm_map_address_t start = 0x180000000ULL;
	vm_map_address_t end = start + 0x180000000ULL;
	vm_map_t submap;
	vm_map_t map = setup_nested_submap(start, end, &submap);
	vm_map_seal(submap, true);
	flags |= VMRL_RESOLVE_COW_AND_OBJ;

	VM_MAP_LOCK_CTX_DECLARE(ctx);
	vm_map_entry_t vme;
	kern_return_t kr;


	kr = __vmrl_lock(ctx, &map, start, end, flags);
	assert3u(kr, ==, KERN_SUCCESS);
	int i = 0;

	while ((vme = vm_map_range_next_with_error(ctx, &kr))) {
		assert_vme_is_locked(ctx, vme);
		i++;
	}

	vmrl_test_range_unlock(ctx, &map);
	assert_range_is_unlocked(map, 0, end);


	vm_map_address_t iter = 0;
	vm_map_entry_t entry;

	__vmrl_ilk_lock_exclusive(map);
	vm_map_lookup_or_next(map, iter, &entry);
	__vmrl_ilk_unlock_exclusive(map);

	while (!entry_is_map_end(map, entry)) {
		iter = entry->vme_end;

		__vmrl_ilk_lock_exclusive(map);
		vm_map_lookup_or_next(map, iter, &entry);
		__vmrl_ilk_unlock_exclusive(map);
	}

	assert(map->hdr.nentries > 1);
	vm_map_destroy(map);
}

static vm_map_t
setup_simplify_map(vm_map_address_t start, unsigned int nentries, int vmmap_sealed)
{
	vm_map_t map = vm_test_alloc_map();
	map->vmmap_sealed = vmmap_sealed;
	kern_return_t kr;
	vm_object_t object = vm_object_allocate(PAGE_SIZE * nentries, map->serial_id);

	for (unsigned int i = 0; i < nentries; i++) {
		vm_map_offset_t entry_start = start + i * PAGE_SIZE;
		vm_object_reference(object);
		kr = vm_map_enter(map, &entry_start,
		    PAGE_SIZE, 0,
		    VM_MAP_KERNEL_FLAGS_FIXED(), object, entry_start - start,
		    false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
		assert3u(kr, ==, KERN_SUCCESS);
	}

	return map;
}

static void
simplify_tests(vmrl_flags_t flags, int vmmap_sealed)
{
	vm_map_address_t start = PAGE_SIZE;
	unsigned int nentries = 3;
	vm_map_address_t end = start + PAGE_SIZE * nentries;
	vm_map_t map = setup_simplify_map(start, nentries, vmmap_sealed);
	kern_return_t kr;
	vm_map_entry_t entry;
	VM_MAP_LOCK_CTX_DECLARE(ctx);

	/* simplify all 3 entries */
	kr = __vmrl_lock(ctx, &map, start, end,
	    flags | VMRL_SIMPLIFY);
	assert3u(kr, ==, KERN_SUCCESS);
	vmrl_test_want_n_entries(ctx, 3);
	vmrl_test_range_unlock(ctx, &map);
	assert(map->hdr.nentries == 1);
	vm_map_destroy(map);

	/* range only covers the second two entries, we still simplify with first */
	map = setup_simplify_map(start, nentries, vmmap_sealed);
	kr = __vmrl_lock(ctx, &map, start + PAGE_SIZE, end,
	    flags | VMRL_SIMPLIFY);
	assert3u(kr, ==, KERN_SUCCESS);
	vmrl_test_want_n_entries(ctx, 2);
	vmrl_test_range_unlock(ctx, &map);
	assert(map->hdr.nentries == 1);
	vm_map_destroy(map);

	/* Range only covers second two, lock the first entry, we simplify only second two */
	map = setup_simplify_map(start, nentries, vmmap_sealed);
	__vmrl_ilk_lock_exclusive(map);
	entry = vm_map_lookup(map, start);
	kr = vm_entry_lock_shared(map, LCK_RW_TYPE_EXCLUSIVE,
	    entry, entry->vme_start, 0);
	assert(kr == KERN_SUCCESS);
	__vmrl_ilk_unlock_exclusive(map);

	kr = __vmrl_lock(ctx, &map, start + PAGE_SIZE, end,
	    flags | VMRL_SIMPLIFY);
	assert3u(kr, ==, KERN_SUCCESS);
	vmrl_test_want_n_entries(ctx, 2);
	vmrl_test_range_unlock(ctx, &map);
	assert(map->hdr.nentries == 2);
	vm_entry_unlock_shared(map, entry);
	vm_map_destroy(map);

	/* Range only covers first two, we simplify with next */
	map = setup_simplify_map(start, nentries, vmmap_sealed);
	kr = __vmrl_lock(ctx, &map, start, end - PAGE_SIZE,
	    flags | VMRL_SIMPLIFY);
	assert3u(kr, ==, KERN_SUCCESS);
	vmrl_test_want_n_entries(ctx, 2);
	vmrl_test_range_unlock(ctx, &map);
	assert(map->hdr.nentries == 1);
	vm_map_destroy(map);

	/* Range only covers first two, lock the third entry, we simplify only first two */
	map = setup_simplify_map(start, nentries, vmmap_sealed);
	__vmrl_ilk_lock_exclusive(map);
	entry = vm_map_lookup(map, end - PAGE_SIZE);
	kr = vm_entry_lock_shared(map, LCK_RW_TYPE_EXCLUSIVE,
	    entry, entry->vme_start, 0);
	assert(kr == KERN_SUCCESS);
	__vmrl_ilk_unlock_exclusive(map);

	kr = __vmrl_lock(ctx, &map, start, end - PAGE_SIZE,
	    flags | VMRL_SIMPLIFY);
	assert3u(kr, ==, KERN_SUCCESS);
	vmrl_test_want_n_entries(ctx, 2);
	vmrl_test_range_unlock(ctx, &map);
	assert(map->hdr.nentries == 2);
	vm_entry_unlock_shared(map, entry);
	vm_map_destroy(map);

	/* Lock the entry in the middle, verify we simplify with both neighbors */
	map = setup_simplify_map(start, nentries, vmmap_sealed);
	kr = __vmrl_lock(ctx, &map, start + PAGE_SIZE, start + PAGE_SIZE * 2,
	    flags | VMRL_SIMPLIFY);
	assert3u(kr, ==, KERN_SUCCESS);
	vmrl_test_want_n_entries(ctx, 1);
	vmrl_test_range_unlock(ctx, &map);
	assert(map->hdr.nentries == 1);

	vm_map_destroy(map);
}

static void
simplify_tests_manual()
{
	const unsigned int nentries = 3;
	const vm_map_address_t start = PAGE_SIZE; /* Start of first entry */
	const vm_map_address_t end = start + PAGE_SIZE * nentries; /* End of last entry */
	const vm_map_address_t entry_start = start + PAGE_SIZE; /* Start of middle entry */
	const vm_map_address_t entry_end = end - PAGE_SIZE; /* End of middle entry */
	vm_map_t map;
	kern_return_t kr;
	vm_map_entry_t entry;
	vm_map_entry_t entry_prev;
	vm_map_entry_t entry_next;

	/* simplify all 3 entries */
	map = setup_simplify_map(start, nentries, VM_MAP_NOT_SEALED);
	__vmrl_ilk_lock_exclusive(map);
	entry = vm_map_lookup(map, entry_start);
	entry_next = vm_map_lookup(map, entry_end);
	kr = vm_entry_lock_exclusive(map, LCK_RW_TYPE_EXCLUSIVE, entry, entry_start, 0);
	assert3u(kr, ==, KERN_SUCCESS);
	__vmrl_ilk_unlock_exclusive(map);

	assert3p(vm_map_locked_entry_simplify(map, entry), ==, entry_next);
	vm_entry_assert_excl_owner(entry_next);
	assert3u(entry_next->vme_start, ==, start);
	assert3u(entry_next->vme_end, ==, end);
	assert(map->hdr.nentries == 1);
	vm_entry_unlock_exclusive(map, entry_next);
	vm_map_destroy(map);

	/* Lock the first entry, we simplify only last two */
	map = setup_simplify_map(start, nentries, VM_MAP_NOT_SEALED);
	__vmrl_ilk_lock_exclusive(map);
	entry_prev = vm_map_lookup(map, start);
	entry = vm_map_lookup(map, entry_start);
	entry_next = vm_map_lookup(map, entry_end);
	kr = vm_entry_lock_exclusive(map, LCK_RW_TYPE_EXCLUSIVE, entry_prev, start, 0);
	assert3u(kr, ==, KERN_SUCCESS);
	kr = vm_entry_lock_exclusive(map, LCK_RW_TYPE_EXCLUSIVE, entry, entry_start, 0);
	assert3u(kr, ==, KERN_SUCCESS);
	__vmrl_ilk_unlock_exclusive(map);

	assert3p(vm_map_locked_entry_simplify(map, entry), ==, entry_next);
	vm_entry_assert_excl_owner(entry_next);
	assert3u(entry_next->vme_start, ==, entry_start);
	assert3u(entry_next->vme_end, ==, end);
	assert(map->hdr.nentries == 2);
	vm_entry_unlock_exclusive(map, entry_prev);
	vm_entry_unlock_exclusive(map, entry_next);
	vm_map_destroy(map);

	/* Lock the third entry, we simplify only first two */
	map = setup_simplify_map(start, nentries, VM_MAP_NOT_SEALED);
	__vmrl_ilk_lock_exclusive(map);
	entry = vm_map_lookup(map, entry_start);
	entry_next = vm_map_lookup(map, entry_end);
	kr = vm_entry_lock_exclusive(map, LCK_RW_TYPE_EXCLUSIVE, entry, entry_start, 0);
	assert3u(kr, ==, KERN_SUCCESS);
	kr = vm_entry_lock_exclusive(map, LCK_RW_TYPE_EXCLUSIVE, entry_next, entry_end, 0);
	assert3u(kr, ==, KERN_SUCCESS);
	__vmrl_ilk_unlock_exclusive(map);

	assert3p(vm_map_locked_entry_simplify(map, entry), ==, entry);
	vm_entry_assert_excl_owner(entry);
	assert3u(entry->vme_start, ==, start);
	assert3u(entry->vme_end, ==, entry_end);
	assert(map->hdr.nentries == 2);
	vm_entry_unlock_exclusive(map, entry);
	vm_entry_unlock_exclusive(map, entry_next);
	vm_map_destroy(map);
}

void
setup_transparent_submap(vm_map_address_t start, vm_map_address_t end, struct submap_entry_spec *entries,
    int nentries, vm_map_t * parent_map, vm_map_t * submap)
{
	pmap_t pmap = pmap_create_options(NULL, 0, PMAP_CREATE_64BIT);
	*parent_map = vm_map_create_options(pmap, 0, 0xfffffffffffff, 0);

	*submap = vm_map_create_options(pmap, 0, end - start, 0);

	/*
	 * Take out an additional reference on the pmap to reflect its use by both the parent map and submap.
	 * This allows us to destroy both maps without over-releasing the pmap.
	 */
	pmap_reference(pmap);

	kern_return_t kr;

	vm_map_reference(*submap);
	kr = vm_map_enter(*parent_map, &start, end - start, 0,
	    VM_MAP_KERNEL_FLAGS_FIXED(.vmkf_submap = TRUE, .vmf_permanent = true, .vmkf_submap_atomic = true),
	    (vm_object_t)(uintptr_t) *submap, 0,
	    false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
	assert3u(kr, ==, KERN_SUCCESS);

	for (int i = 0; i < nentries; i++) {
		vm_map_address_t entry_start = ((entries == NULL) ? (start + PAGE_SIZE * i) : entries[i].start);
		vm_map_size_t entry_size = ((entries == NULL) ? PAGE_SIZE : (entries[i].end - entries[i].start));
		bool needs_copy = ((entries == NULL) ? true : entries[i].needs_copy);
		kr = vm_map_enter(*submap, &entry_start,
		    entry_size, 0, VM_MAP_KERNEL_FLAGS_FIXED(),
		    vm_object_allocate(entry_size, (*submap)->serial_id),       /* non NULL to avoid coalesce */
		    0, needs_copy, VM_PROT_DEFAULT,
		    VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
		assert3u(kr, ==, KERN_SUCCESS);
	}
	assert3s((*submap)->hdr.nentries, ==, nentries);
	assert3s((*parent_map)->hdr.nentries, ==, 1);
}

static void
transparent_submap_tests(vmrl_flags_t flags)
{
	VM_MAP_LOCK_CTX_DECLARE(ctx);
	vm_map_address_t start = 0x180000000ULL;
	vm_map_address_t submap_end = 0x180000000ULL * 2;
	vm_map_t parent_map;
	vm_map_t submap;
	int nentries = 2;
	vm_map_address_t submap_entries_end = start + PAGE_SIZE * nentries;
	kern_return_t kr;
	bool should_descend_transparent = !(flags & VMRL_SH_NO_DESCEND_TRANSPARENT);

	setup_transparent_submap(start, submap_end, NULL, 2, &parent_map, &submap);
	assert(vm_map_entry_is_transparent_submap(find_entry_unlocked(parent_map, start)));

	/* First make sure we can lock the entries in the submap directly */
	kr = __vmrl_lock(ctx, &submap, start, submap_entries_end, flags);
	assert3u(kr, ==, KERN_SUCCESS);
	vmrl_test_want_n_entries(ctx, 2);
	vmrl_test_range_unlock(ctx, &submap);

	/* Now try locking them from the parent map perspective */
	if (should_descend_transparent) {
		kr = __vmrl_lock(ctx, &parent_map, start, submap_entries_end, flags);
		assert3u(kr, ==, KERN_SUCCESS);
		vmrl_test_want_n_entries(ctx, 2);
		vmrl_test_range_unlock(ctx, &parent_map);
	} else {
		kr = __vmrl_lock(ctx, &parent_map, start, submap_entries_end, flags);
		assert3u(kr, ==, KERN_SUCCESS);
		vmrl_test_want_n_entries(ctx, 1);
		vmrl_test_range_unlock(ctx, &parent_map);
	}

	if (vmrl_is_streaming(flags)) {
		vm_map_address_t all_entries_end = submap_end + PAGE_SIZE;
		/*
		 * Make sure stream can ascend from transparent submaps.
		 * There is no atomic test here because atomic can not.
		 */
		vm_test_add_map_entry(parent_map, submap_end, all_entries_end);

		if (should_descend_transparent) {
			/* Verify descension and ascension works right */
			kr = __vmrl_lock(ctx, &parent_map, start, all_entries_end, flags);
			assert3u(kr, ==, KERN_SUCCESS);
			vmrl_test_want_n_entries(ctx, 3);
			vmrl_test_range_unlock(ctx, &parent_map);
		} else {
			kr = __vmrl_lock(ctx, &parent_map, start, all_entries_end, flags);
			assert3u(kr, ==, KERN_SUCCESS);
			vmrl_test_want_n_entries(ctx, 2);
			vmrl_test_range_unlock(ctx, &parent_map);
		}
	}

	vm_map_destroy_options(parent_map, VM_MAP_DESTROY_ALLOW_TRANSPARENT_SUBMAP);
	vm_map_destroy(submap);
}

static void
drop_and_change_map_test(vmrl_flags_t flags, bool without_advance)
{
	VM_MAP_LOCK_CTX_DECLARE(ctx);
	vm_map_address_t start = 0x180000000ULL;
	int nentries = 2;
	vm_map_address_t submap_end = 0x180000000ULL * nentries;
	vm_map_t parent_map;
	vm_map_t submap;
	vm_map_address_t submap_entry_length = PAGE_SIZE;
	vm_map_address_t submap_entries_end = start + submap_entry_length * nentries;
	kern_return_t kr;
	mach_vm_address_t entry_start, entry_end, entry_size;

	bool descend = flags & VMRL_DESCEND_INTO_CONSTANT;

	setup_constant_submap(constant_submap_entry_start, start, submap_end, nentries, &parent_map, &submap);
	assert(vm_map_entry_is_constant_submap(find_entry_unlocked(parent_map, start)));
	vm_map_t orig_map = parent_map;

	// Clip the parent map into two entries
	kr = vm_map_range_ex_lock(ctx, &parent_map, start, start + PAGE_SIZE, VMRL_EX_ATOMIC);
	assert3u(kr, ==, KERN_SUCCESS);
	vm_map_entry_t submap_entry1 = vm_map_range_atomic_next(ctx);
	assert3p(vm_map_range_atomic_next(ctx), ==, VM_MAP_ENTRY_NULL);
	vm_map_range_ex_unlock(ctx, &parent_map);

	// find the two top level entries
	vm_map_entry_t submap_entry2;
	__vmrl_ilk_lock_exclusive(orig_map);
	assert((submap_entry1 = vm_map_lookup(orig_map, start)));
	assert((submap_entry2 = vm_map_lookup(orig_map, start + submap_entry_length)));
	assert3p(submap_entry1, !=, submap_entry2);
	__vmrl_ilk_unlock_exclusive(orig_map);

	/* Make sure we get an entry in the submap and not the submap entry itself */
	kr = __vmrl_lock(ctx, &parent_map, start, submap_entries_end, flags);
	assert3u(kr, ==, KERN_SUCCESS);

	(void)vm_map_range_next_with_error(ctx, &kr);
	assert3u(kr, ==, KERN_SUCCESS);
	if (descend) {
		vm_entry_assert_lock_is_invalid(ctx->vmlc_vme, VMEL_INVALID_REASON_SEALED_SUBMAP);
		assert_vme_is_locked(ctx, ctx->__parent_entry);
	} else {
		assert_vme_is_locked(ctx, ctx->vmlc_vme);
	}
	vm_map_lock_ctx_bounds(ctx, &entry_start, &entry_end, &entry_size);

	assert3u(vm_map_lock_ctx_to_parent_address(ctx, entry_start), ==, start);
	assert3u(vm_map_lock_ctx_to_parent_address(ctx, entry_end), ==, start + PAGE_SIZE);
	assert3u(entry_size, ==, entry_end - entry_start);

	// Drop the lock and modify the map
	if (without_advance) {
		vm_map_range_stream_drop_without_advance(ctx);
	} else {
		vm_map_range_stream_drop(ctx);
	}

	// simplify the two entries
	__vmrl_ilk_lock_exclusive(orig_map);
	assert(vm_entry_try_lock_exclusive(submap_entry1));
	assert(vm_entry_try_lock_exclusive(submap_entry2));
	assert(vm_map_simplify_entry_with_prev_locked(orig_map, LCK_RW_TYPE_EXCLUSIVE, submap_entry2));
	vm_entry_unlock_exclusive(orig_map, submap_entry2);
	__vmrl_ilk_unlock_exclusive(orig_map);

	/* And take the entry lock again */
	(void)vm_map_range_next_with_error(ctx, &kr);
	assert3u(kr, ==, KERN_SUCCESS);
	if (descend) {
		vm_entry_assert_lock_is_invalid(ctx->vmlc_vme, VMEL_INVALID_REASON_SEALED_SUBMAP);
		assert_vme_is_locked(ctx, ctx->__parent_entry);
	} else {
		assert_vme_is_locked(ctx, ctx->vmlc_vme);
	}
	vm_map_lock_ctx_bounds(ctx, &entry_start, &entry_end, &entry_size);

	if (without_advance) {
		/* Didn't move cursor. We should get the first entry again */
		assert3u(vm_map_lock_ctx_to_parent_address(ctx, entry_start), ==, start);
	} else {
		// Did move cursor, range should be the second
		assert3u(vm_map_lock_ctx_to_parent_address(ctx, entry_start), ==, start + PAGE_SIZE);
	}

	/*
	 * If we descended without advance, we will get the second submap entry
	 * on the next call to _next().
	 * Otherwise, we should be done with the range.
	 */
	if (without_advance && descend) {
		assert3u(vm_map_lock_ctx_to_parent_address(ctx, entry_end), ==, start + PAGE_SIZE);

		(void)vm_map_range_next_with_error(ctx, &kr);
		assert3u(kr, ==, KERN_SUCCESS);
		if (descend) {
			vm_entry_assert_lock_is_invalid(ctx->vmlc_vme, VMEL_INVALID_REASON_SEALED_SUBMAP);
			assert_vme_is_locked(ctx, ctx->__parent_entry);
		} else {
			assert_vme_is_locked(ctx, ctx->vmlc_vme);
		}
		vm_map_lock_ctx_bounds(ctx, &entry_start, &entry_end, &entry_size);
		assert3u(vm_map_lock_ctx_to_parent_address(ctx, entry_start), ==, start + PAGE_SIZE);
	}

	assert3u(vm_map_lock_ctx_to_parent_address(ctx, entry_end), ==, submap_entries_end);
	assert3u(entry_size, ==, entry_end - entry_start);

	(void)vm_map_range_next_with_error(ctx, &kr);
	assert3u(kr, ==, KERN_SUCCESS);
	assert(ctx->vmlc_vme == NULL);
	vmrl_test_range_unlock(ctx, &parent_map);

	/*
	 * Make sure stream can ascend from constant submaps
	 */
	vm_map_destroy(parent_map);
	vm_map_destroy(submap);
}

static void
constant_submap_tests_drop_and_advance(vm_map_lock_ctx_t ctx, bool drop, vm_map_t parent_map, vm_map_t submap, kern_return_t *kr)
{
	if (drop) {
		vm_map_range_stream_drop(ctx);

		assert_range_is_unlocked(parent_map, 0, VMRL_END_VA(parent_map));
		assert_range_is_unlocked(submap, 0, VMRL_END_VA(submap));
	}
	(void)vm_map_range_next_with_error(ctx, kr);

	vm_map_entry_t entry = ctx->vmlc_vme;

	if (entry) {
		mach_vm_address_t start, end, size;
		vm_map_lock_ctx_bounds(ctx, &start, &end, &size);
		assert3u(entry->vme_start, ==, start);
	}
}


static void
constant_submap_tests(vmrl_flags_t flags, bool drop)
{
	VM_MAP_LOCK_CTX_DECLARE(ctx);
	vm_map_address_t start = 0x180000000ULL;
	int nentries = 2;
	vm_map_address_t submap_end = 0x180000000ULL * nentries;
	vm_map_t parent_map;
	vm_map_t submap;
	vm_map_address_t submap_entry_length = PAGE_SIZE;
	vm_map_address_t submap_entries_end = start + submap_entry_length * nentries;
	kern_return_t kr;

	setup_constant_submap(constant_submap_entry_start, start, submap_end, nentries, &parent_map, &submap);
	assert(vm_map_entry_is_constant_submap(find_entry_unlocked(parent_map, start)));
	vm_map_t parent_map_cpy = parent_map;

	if (!vmrl_is_exclusive(flags)) {
		/* Make sure we get an entry in the submap and not the submap entry itself */
		kr = __vmrl_lock(ctx, &parent_map, start, submap_entries_end,
		    flags | VMRL_DESCEND_INTO_CONSTANT);
		assert3u(kr, ==, KERN_SUCCESS);

		(void)vm_map_range_next_with_error(ctx, &kr);
		assert3u(kr, ==, KERN_SUCCESS);
		vm_entry_assert_lock_is_invalid(ctx->vmlc_vme, VMEL_INVALID_REASON_SEALED_SUBMAP);
		assert(!ctx->vmlc_vme->is_sub_map);
		assert(ctx->vmlc_map == submap);

		constant_submap_tests_drop_and_advance(ctx, drop, parent_map_cpy, submap, &kr);
		assert3u(kr, ==, KERN_SUCCESS);
		vm_entry_assert_lock_is_invalid(ctx->vmlc_vme, VMEL_INVALID_REASON_SEALED_SUBMAP);
		assert(!ctx->vmlc_vme->is_sub_map);
		assert(ctx->vmlc_map == submap);

		constant_submap_tests_drop_and_advance(ctx, drop, parent_map_cpy, submap, &kr);
		assert3u(kr, ==, KERN_SUCCESS);
		assert(ctx->vmlc_vme == NULL);
		vmrl_test_range_unlock(ctx, &parent_map);

		if (vmrl_is_streaming(flags)) {
			/* Doing a streaming lock before the start of the submap should not change behavior */
			kr = __vmrl_lock(ctx, &parent_map, start - PAGE_SIZE, submap_entries_end,
			    flags | VMRL_DESCEND_INTO_CONSTANT);
			assert3u(kr, ==, KERN_SUCCESS);

			(void)vm_map_range_next_with_error(ctx, &kr);
			assert3u(kr, ==, KERN_SUCCESS);
			vm_entry_assert_lock_is_invalid(ctx->vmlc_vme, VMEL_INVALID_REASON_SEALED_SUBMAP);
			assert(!ctx->vmlc_vme->is_sub_map);
			assert(ctx->vmlc_map == submap);

			constant_submap_tests_drop_and_advance(ctx, drop, parent_map_cpy, submap, &kr);
			assert3u(kr, ==, KERN_SUCCESS);
			vm_entry_assert_lock_is_invalid(ctx->vmlc_vme, VMEL_INVALID_REASON_SEALED_SUBMAP);
			assert(!ctx->vmlc_vme->is_sub_map);
			assert(ctx->vmlc_map == submap);

			constant_submap_tests_drop_and_advance(ctx, drop, parent_map_cpy, submap, &kr);
			assert3u(kr, ==, KERN_SUCCESS);
			assert(ctx->vmlc_vme == NULL);
			vmrl_test_range_unlock(ctx, &parent_map);
		}

		/*
		 * Make sure stream can ascend from constant submaps
		 */
		vm_map_destroy(parent_map);
		vm_map_destroy(submap);

		setup_constant_submap(constant_submap_entry_start, start, submap_end, nentries, &parent_map, &submap);
		parent_map_cpy = parent_map;

		vm_map_address_t all_entries_end = submap_end + PAGE_SIZE;
		vm_test_add_map_entry(parent_map, submap_end, all_entries_end);

		kr = __vmrl_lock(ctx, &parent_map, start, all_entries_end,
		    flags | VMRL_DESCEND_INTO_CONSTANT);
		assert3u(kr, ==, KERN_SUCCESS);

		(void)vm_map_range_next_with_error(ctx, &kr);
		assert3u(kr, ==, KERN_SUCCESS);
		vm_entry_assert_lock_is_invalid(ctx->vmlc_vme, VMEL_INVALID_REASON_SEALED_SUBMAP);
		assert(ctx->vmlc_map == submap);
		assert(!ctx->vmlc_vme->is_sub_map);

		constant_submap_tests_drop_and_advance(ctx, drop, parent_map_cpy, submap, &kr);
		assert3u(kr, ==, KERN_SUCCESS);
		vm_entry_assert_lock_is_invalid(ctx->vmlc_vme, VMEL_INVALID_REASON_SEALED_SUBMAP);
		assert(ctx->vmlc_map == submap);
		assert(!ctx->vmlc_vme->is_sub_map);

		constant_submap_tests_drop_and_advance(ctx, drop, parent_map_cpy, submap, &kr);
		assert3u(kr, ==, KERN_SUCCESS);
		vm_entry_assert_lock_is_invalid(ctx->vmlc_vme, VMEL_INVALID_REASON_SEALED_SUBMAP);
		assert(ctx->vmlc_map == submap);
		assert(!ctx->vmlc_vme->is_sub_map);
		constant_submap_tests_drop_and_advance(ctx, drop, parent_map_cpy, submap, &kr);

		assert3u(kr, ==, KERN_SUCCESS);
		vm_entry_assert_shared_owner(ctx->vmlc_vme);
		assert(!vm_map_lock_ctx_is_descended(ctx));
		assert(!ctx->vmlc_vme->is_sub_map);

		constant_submap_tests_drop_and_advance(ctx, drop, parent_map_cpy, submap, &kr);
		assert3u(kr, ==, KERN_SUCCESS);
		assert(ctx->vmlc_vme == NULL);

		vmrl_test_range_unlock(ctx, &parent_map);


		/* reset map */
		vm_map_destroy(parent_map);
		vm_map_destroy(submap);

		setup_constant_submap(constant_submap_entry_start, start, submap_end, nentries, &parent_map, &submap);
		parent_map_cpy = parent_map;
		vm_test_add_map_entry(parent_map, submap_end, all_entries_end);

		/* Add a new entry at the start of parent map. */
		vm_map_address_t new_start = start - PAGE_SIZE;
		kr = vm_map_enter(parent_map, &new_start,
		    PAGE_SIZE, 0, VM_MAP_KERNEL_FLAGS_FIXED(),
		    vm_object_allocate(PAGE_SIZE, parent_map->serial_id),        /* non NULL to avoid coalesce */
		    0, true, VM_PROT_DEFAULT,
		    VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
		assert3u(kr, ==, KERN_SUCCESS);

		/* Verify descension and ascension works right without gaps: descending at advance time */
		kr = __vmrl_lock(ctx, &parent_map, new_start, submap_entries_end,
		    flags | VMRL_DESCEND_INTO_CONSTANT);
		assert3u(kr, ==, KERN_SUCCESS);

		(void)vm_map_range_next_with_error(ctx, &kr);
		assert3u(kr, ==, KERN_SUCCESS);
		vm_entry_assert_shared_owner(ctx->vmlc_vme);
		assert(!vm_map_lock_ctx_is_descended(ctx));
		assert(!ctx->vmlc_vme->is_sub_map);

		/* This advances into a constant submap requiring descent. */
		constant_submap_tests_drop_and_advance(ctx, drop, parent_map_cpy, submap, &kr);
		assert3u(kr, ==, KERN_SUCCESS);
		vm_entry_assert_lock_is_invalid(ctx->vmlc_vme, VMEL_INVALID_REASON_SEALED_SUBMAP);
		assert(ctx->vmlc_map == submap);
		assert(!ctx->vmlc_vme->is_sub_map);

		constant_submap_tests_drop_and_advance(ctx, drop, parent_map_cpy, submap, &kr);
		assert3u(kr, ==, KERN_SUCCESS);
		vm_entry_assert_lock_is_invalid(ctx->vmlc_vme, VMEL_INVALID_REASON_SEALED_SUBMAP);
		assert(ctx->vmlc_map == submap);
		assert(!ctx->vmlc_vme->is_sub_map);

		/* this unlocks midway */
		vmrl_test_range_unlock(ctx, &parent_map);

		assert_range_is_unlocked(parent_map, new_start, submap_entries_end);
	}

	/* reset map */
	vm_map_destroy(parent_map);
	vm_map_destroy(submap);

	setup_constant_submap(constant_submap_entry_start, start, submap_end, nentries, &parent_map, &submap);
	parent_map_cpy = parent_map;

	/* Make sure we get the submap entry */
	kr = __vmrl_lock(ctx, &parent_map, start, submap_entries_end, flags);
	assert3u(kr, ==, KERN_SUCCESS);

	(void)vm_map_range_next_with_error(ctx, &kr);
	assert_entry_locked_sucessfully(ctx, parent_map_cpy, kr);
	assert(ctx->vmlc_vme->is_sub_map);

	vmrl_test_want_n_entries(ctx, 0);
	vmrl_test_range_unlock(ctx, &parent_map);

	vm_map_destroy(parent_map);
	vm_map_destroy(submap);
}

static void __attribute__((optnone))
vm_range_lock_ctx_clip_tests()
{
	vm_map_t map = vm_test_alloc_map();

	vm_map_address_t start = 0x40000;
	vm_map_address_t end = 0x80000;
	vm_map_address_t clip_loc = 0x60000;
	vm_test_add_map_entry(map, start, end); /* Put an entry that spans the map */

	VM_MAP_LOCK_CTX_DECLARE(ctx);
	kern_return_t kr;
	vm_map_entry_t entry;

	kr = vm_map_range_ex_lock(ctx, &map, start, end, VMRL_EX_ATOMIC);
	assert3u(kr, ==, KERN_SUCCESS);
	entry = vm_map_range_next_with_error(ctx, &kr);
	assert3u(kr, ==, KERN_SUCCESS);
	vm_entry_assert_excl_owner(entry);
	vm_map_range_lock_clip_start(ctx, entry, clip_loc);
	vm_entry_assert_excl_owner(entry);
	assert3p(ctx->__vmlc_atomic.first_entry, ==, VME_PREV(entry));
	assert3u(entry->vme_start, ==, clip_loc);
	entry = vm_map_range_next_with_error(ctx, &kr);
	assert3u(kr, ==, KERN_SUCCESS);
	assert3p(entry, ==, VM_MAP_ENTRY_NULL);
	vm_map_range_ex_unlock(ctx, &map);

	assert_range_is_unlocked(map, start, end);
	vm_map_destroy(map);


	map = vm_test_alloc_map();

	vm_test_add_map_entry(map, start, end); /* Put an entry that spans the map */

	kr = vm_map_range_ex_lock(ctx, &map, start, end, VMRL_EX_STREAM);
	assert3u(kr, ==, KERN_SUCCESS);
	entry = vm_map_range_next_with_error(ctx, &kr);
	assert3u(kr, ==, KERN_SUCCESS);
	vm_entry_assert_excl_owner(entry);
	vm_map_range_lock_clip_start(ctx, entry, clip_loc);
	assert3u(entry->vme_start, ==, clip_loc);
	vm_entry_assert_excl_owner(entry);
	entry = vm_map_range_next_with_error(ctx, &kr);
	assert3u(kr, ==, KERN_SUCCESS);
	assert3p(entry, ==, VM_MAP_ENTRY_NULL);
	vm_map_range_ex_unlock(ctx, &map);

	assert_range_is_unlocked(map, start, end);
	vm_map_destroy(map);

	map = vm_test_alloc_map();

	vm_test_add_map_entry(map, start, end); /* Put an entry that spans the map */

	kr = vm_map_range_ex_lock(ctx, &map, start, end, VMRL_EX_STREAM);
	assert3u(kr, ==, KERN_SUCCESS);
	entry = vm_map_range_next_with_error(ctx, &kr);
	assert3u(kr, ==, KERN_SUCCESS);
	vm_entry_assert_excl_owner(entry);
	vm_map_range_lock_clip_end(ctx, entry, clip_loc);
	assert3u(entry->vme_end, ==, clip_loc);
	assert3u(entry->vme_start, ==, start);
	assert(ctx->__vmlc_streaming.last_processed_addr == clip_loc);
	vm_entry_assert_excl_owner(entry);
	entry = vm_map_range_next_with_error(ctx, &kr);
	assert3u(kr, ==, KERN_SUCCESS);
	vm_entry_assert_excl_owner(entry);
	vm_map_range_ex_unlock(ctx, &map);

	assert_range_is_unlocked(map, start, end);
	vm_map_destroy(map);

	map = vm_test_alloc_map();

	vm_test_add_map_entry(map, start, end); /* Put an entry that spans the map */

	kr = vm_map_range_ex_lock(ctx, &map, start, end, VMRL_EX_ATOMIC);
	assert3u(kr, ==, KERN_SUCCESS);
	entry = vm_map_range_next_with_error(ctx, &kr);
	assert3u(kr, ==, KERN_SUCCESS);
	vm_entry_assert_excl_owner(entry);
	vm_map_range_lock_clip_end(ctx, entry, clip_loc);
	assert3u(entry->vme_end, ==, clip_loc);
	assert3u(entry->vme_start, ==, start);
	vm_entry_assert_excl_owner(entry);
	entry = vm_map_range_next_with_error(ctx, &kr);
	assert3u(kr, ==, KERN_SUCCESS);
	vm_entry_assert_excl_owner(entry);
	vm_map_range_ex_unlock(ctx, &map);

	assert_range_is_unlocked(map, start, end);
	vm_map_destroy(map);
}

static void
try_lock_tests(vmrl_flags_t flags)
{
	VM_MAP_LOCK_CTX_DECLARE(ctx);

	vm_map_t map = vm_test_alloc_map();
	vm_map_offset_t first_start = 0x10000, first_end = 0x20000;
	vm_map_offset_t second_start = 0x20000, second_end = 0x30000;
	vm_map_offset_t third_start = 0x30000, third_end = 0x50000;
	kern_return_t kr;
	vm_map_entry_t entries[3];
	vm_map_entry_t entry;

	entries[2] = vm_test_add_map_entry(map, third_start, third_end);
	entries[1] = vm_test_add_map_entry(map, second_start, second_end);
	entries[0] = vm_test_add_map_entry(map, first_start, first_end);

	kr = __vmrl_lock(ctx, &map, first_start, third_end, flags | VMRL_TRY_LOCK_ENTRY);
	assert3u(kr, ==, KERN_SUCCESS);

	vmrl_test_want_n_entries(ctx, 3);
	vmrl_test_range_unlock(ctx, &map);


	/* Lock one entry shared and try again */
	__vmrl_ilk_lock_exclusive(map);
	entry = vm_map_lookup(map, first_start);
	kr = vm_entry_lock_shared(map, LCK_RW_TYPE_EXCLUSIVE,
	    entry, entry->vme_start, THREAD_UNINT);
	assert3u(kr, ==, KERN_SUCCESS);
	__vmrl_ilk_unlock_exclusive(map);

	if (vmrl_is_shared(flags)) {
		kr = __vmrl_lock(ctx, &map, first_start, third_end, flags | VMRL_TRY_LOCK_ENTRY);
		assert3u(kr, ==, KERN_SUCCESS);

		/* unlock that entry so want_n_entries */
		vm_entry_unlock_shared(map, entry);

		vmrl_test_want_n_entries(ctx, 3);
		vmrl_test_range_unlock(ctx, &map);
	} else {
		kr = __vmrl_lock(ctx, &map, first_start, third_end, flags | VMRL_TRY_LOCK_ENTRY);

		if (vmrl_is_streaming(flags)) {
			assert3u(kr, ==, KERN_SUCCESS);

			vm_map_entry_t temp_entry = vm_map_range_next_with_error(ctx, &kr);
			assert3p(temp_entry, ==, NULL);
			assert3u(kr, ==, VMRL_ERR_LOCK_ALREADY_HELD);

			vmrl_test_range_unlock(ctx, &map);
		} else {
			assert3u(kr, ==, VMRL_ERR_LOCK_ALREADY_HELD);
		}

		vm_entry_unlock_shared(map, entry);
	}


	vm_map_destroy(map);
}


static int
vm_range_lock_flags_test(__unused int64_t in, int64_t *out)
{
	printf("%s: test running (thread=%p)\n", __func__, current_thread());

	printf("%s: constant_submap_tests()\n", __func__);
	constant_submap_tests(VMRL_EXCLUSIVE | VMRL_ATOMIC, false);
	constant_submap_tests(VMRL_EXCLUSIVE | VMRL_STREAM, false);
	constant_submap_tests(VMRL_SHARED | VMRL_ATOMIC, false);
	constant_submap_tests(VMRL_SHARED | VMRL_STREAM, false);

	constant_submap_tests(VMRL_EXCLUSIVE | VMRL_STREAM, true);
	constant_submap_tests(VMRL_SHARED | VMRL_STREAM, true);

	printf("%s: simplify_tests()\n", __func__);
	simplify_tests(VMRL_EXCLUSIVE | VMRL_ATOMIC, VM_MAP_NOT_SEALED);
	simplify_tests(VMRL_EXCLUSIVE | VMRL_STREAM, VM_MAP_NOT_SEALED);
	simplify_tests(VMRL_EXCLUSIVE | VMRL_ATOMIC, VM_MAP_WILL_BE_SEALED);
	simplify_tests(VMRL_EXCLUSIVE | VMRL_STREAM, VM_MAP_WILL_BE_SEALED);
	/* Simplify shared not supported */

	printf("Drop and change map tests()\n");
	drop_and_change_map_test(VMRL_EXCLUSIVE | VMRL_STREAM, true);
	drop_and_change_map_test(VMRL_SHARED | VMRL_STREAM, true);
	drop_and_change_map_test(VMRL_EXCLUSIVE | VMRL_STREAM | VMRL_DESCEND_INTO_CONSTANT, true);
	drop_and_change_map_test(VMRL_SHARED | VMRL_STREAM | VMRL_DESCEND_INTO_CONSTANT, true);
	/* drop is not supported for atomic */
	drop_and_change_map_test(VMRL_EXCLUSIVE | VMRL_STREAM, false);
	drop_and_change_map_test(VMRL_SHARED | VMRL_STREAM, false);
	drop_and_change_map_test(VMRL_EXCLUSIVE | VMRL_STREAM | VMRL_DESCEND_INTO_CONSTANT, false);
	drop_and_change_map_test(VMRL_SHARED | VMRL_STREAM | VMRL_DESCEND_INTO_CONSTANT, false);

	printf("%s: simplify_tests_manual()\n", __func__);
	simplify_tests_manual();

	printf("%s: unnest_tests()\n", __func__);
	unnest_tests(VMRL_EXCLUSIVE | VMRL_ATOMIC);
	unnest_tests(VMRL_EXCLUSIVE | VMRL_STREAM);
	unnest_tests(VMRL_SHARED | VMRL_ATOMIC);
	unnest_tests(VMRL_SHARED | VMRL_STREAM);

	printf("%s: whole_map_tests()\n", __func__);
	whole_map_tests();

	printf("%s: resolve_tests()\n", __func__);
	resolve_tests();

	printf("%s: transparent_submap_tests()\n", __func__);
	transparent_submap_tests(VMRL_EXCLUSIVE | VMRL_ATOMIC);
	transparent_submap_tests(VMRL_EXCLUSIVE | VMRL_STREAM);
	transparent_submap_tests(VMRL_SHARED | VMRL_ATOMIC);
	transparent_submap_tests(VMRL_SHARED | VMRL_STREAM);
	transparent_submap_tests(VMRL_SHARED | VMRL_STREAM | VMRL_SH_NO_DESCEND_TRANSPARENT);


	printf("%s: clip_tests()\n", __func__);
	vm_range_lock_ctx_clip_tests();

	printf("%s: try_lock_tests()\n", __func__);
	try_lock_tests(VMRL_EXCLUSIVE | VMRL_ATOMIC);
	try_lock_tests(VMRL_EXCLUSIVE | VMRL_STREAM);
	try_lock_tests(VMRL_SHARED | VMRL_ATOMIC);
	try_lock_tests(VMRL_SHARED | VMRL_STREAM);

	printf("%s: test passed\n", __func__);

	*out = 1;
	return 0;
}

struct multi_thread_test_ctx *fault_bench_ctx;

/*
 * This tests locking/unlocking a single entry for fault
 * and can give a rough idea for if the performance of it has badly regressed
 */
static void
test_fault_bench(struct multi_thread_test_ctx * test_ctx, uint32_t num_races_to_test)
{
	for (size_t i = 0; i < num_races_to_test; i++) {
		VM_MAP_LOCK_CTX_DECLARE(ctx);
		vm_map_entry_t entry;
		kern_return_t kr;
		vm_map_t map = test_ctx->map;

		volatile vm_map_address_t start = test_ctx->contiguous_entry_bounds[0][0];
		volatile vm_map_address_t end = test_ctx->contiguous_entry_bounds[0][1];

		kr = vm_map_range_sh_lock(ctx, &map, start, end, VMRL_SH_STREAM);
		assert3u(kr, ==, KERN_SUCCESS);

		entry = vm_map_range_stream_next_with_error(ctx, &kr);
		assert3u(kr, ==, KERN_SUCCESS);

		vm_entry_assert_shared_owner(entry);
		assert(entry->protection == 0);
		wait_a_bit_to_make_race_window_larger(1);

		vm_map_range_sh_unlock(ctx, &map);
	}
}

static struct multi_thread_test_ctx *
get_fault_bench_ctx(void)
{
	lck_mtx_lock(&range_lock_test_mtx);
	if (!fault_bench_ctx) {
		fault_bench_ctx = kalloc_type(struct multi_thread_test_ctx, Z_ZERO | Z_WAITOK);
		setup_ctx(fault_bench_ctx, 1, 0);
	}
	lck_mtx_unlock(&range_lock_test_mtx);
	return fault_bench_ctx;
}

int num_fault_threads_waiting = 0;

static int
vm_range_lock_fault_bench(int64_t packed_thread_and_iters, int64_t *out)
{
	uint32_t num_threads_to_wait_for;
	uint32_t num_races_to_test;

	unpack_threads_and_iterations((uint64_t) packed_thread_and_iters,
	    &num_threads_to_wait_for, &num_races_to_test);

	if (num_threads_to_wait_for > task_threadmax) {
		return ENOSPC;
	}
	struct multi_thread_test_ctx * fault_test_ctx = get_fault_bench_ctx();

	vm_range_lock_race_wait_for_all_threads_to_be_ready(&num_fault_threads_waiting, (int) num_threads_to_wait_for, (event_t) fault_test_ctx);
	test_fault_bench(fault_test_ctx, num_races_to_test);

	*out = 1;
	return 0;
}

static kern_return_t
call_find_locked_lock(vm_map_lock_ctx_t ctx, vm_map_t map, vm_map_address_t addr, vmrl_flags_t flags, bool excl)
{
	if (excl) {
		return vm_map_find_entry_ex_locked(ctx, &map, addr, (vmrl_find_ex_flags_t)flags);
	}

	return vm_map_find_entry_sh_locked(ctx, &map, addr, (vmrl_find_sh_flags_t)flags);
}

static void
call_find_locked_unlock(vm_map_lock_ctx_t ctx, bool excl)
{
	if (excl) {
		vm_map_found_entry_ex_unlock(ctx, NULL);
	} else {
		vm_map_found_entry_sh_unlock(ctx, NULL);
	}
}

static void
vm_map_find_locked_entry_test_simple(bool excl)
{
	vm_map_t map = vm_test_alloc_map();
	const vm_map_offset_t start = 0x10000, end = 0x20000;
	kern_return_t kr;

	vm_map_entry_t entry = vm_test_add_map_entry(map, start, end);

	VM_MAP_FIND_LOCK_CTX_DECLARE(ctx);

	printf("%s(%d):    Lock an entry by addr\n", __func__, excl);
	kr = call_find_locked_lock(ctx, map, start, 0, excl);
	assert3u(kr, ==, KERN_SUCCESS);
	assert3p(entry, ==, ctx->vmlc_vme);
	if (excl) {
		vm_entry_assert_excl_owner(entry);
	} else {
		vm_entry_assert_shared_owner(entry);
	}

	call_find_locked_unlock(ctx, excl);
	vm_entry_assert_not_owner(entry);

	vm_map_destroy(map);
}

static void
vm_map_find_locked_entry_test_gap(bool excl)
{
	vm_map_t map = vm_test_alloc_map();
	const vm_map_offset_t addr = 0x10000, start = 0x20000, end = 0x30000;
	kern_return_t kr;

	vm_map_entry_t entry = vm_test_add_map_entry(map, start, end);

	VM_MAP_FIND_LOCK_CTX_DECLARE(ctx);

	printf("%s(%d):    Lock by addr with no entry here but entry after\n", __func__, excl);
	kr = call_find_locked_lock(ctx, map, addr, 0, excl);
	assert3u(kr, ==, KERN_INVALID_ADDRESS);
	vm_entry_assert_not_owner(entry);

	printf("%s(%d):    Lock by addr with no entry here or after\n", __func__, excl);
	kr = call_find_locked_lock(ctx, map, end, 0, excl);
	assert3u(kr, ==, KERN_INVALID_ADDRESS);
	vm_entry_assert_not_owner(entry);

	vm_map_destroy(map);
}

#ifndef __BUILDING_XNU_LIB_UNITTEST__
static void
vm_map_find_locked_entry_test_constant_submap(bool excl, bool descend)
{
	const vm_map_offset_t start = 0x180000000ULL, end = 0x180000000ULL * 2;
	kern_return_t kr;
	vm_map_t parent_map;
	vm_map_t submap;
	vmrl_flags_t flags = descend ? VMRL_DESCEND_INTO_CONSTANT : 0;

	setup_constant_submap(constant_submap_entry_start, start, end, 1, &parent_map, &submap);

	vm_map_entry_t parent_entry = find_entry_unlocked(parent_map, start);
	assert(VM_MAP_ENTRY_NULL != parent_entry);
	assert(vm_map_entry_is_constant_submap(parent_entry));

	vm_map_entry_t child_entry = find_entry_unlocked(submap, constant_submap_entry_start);
	assert(VM_MAP_ENTRY_NULL != child_entry);

	VM_MAP_FIND_LOCK_CTX_DECLARE(ctx);

	printf("%s(%d,%d):    Lock by addr in constant submap\n", __func__, excl, descend);
	kr = call_find_locked_lock(ctx, parent_map, start, flags, excl);
	assert3u(kr, ==, KERN_SUCCESS);
	if (descend) {
		assert3p(child_entry, ==, ctx->vmlc_vme);
	} else {
		assert3p(parent_entry, ==, ctx->vmlc_vme);
	}

	if (excl) {
		vm_entry_assert_excl_owner(parent_entry);
	} else {
		vm_entry_assert_shared_owner(parent_entry);
	}
	vm_entry_assert_lock_is_invalid(child_entry, VMEL_INVALID_REASON_SEALED_SUBMAP);

	call_find_locked_unlock(ctx, excl);
	vm_entry_assert_not_owner(parent_entry);
	vm_entry_assert_lock_is_invalid(child_entry, VMEL_INVALID_REASON_SEALED_SUBMAP);

	vm_map_destroy(parent_map);
	vm_map_destroy(submap);
}
#endif


static void
vm_map_find_locked_entry_test_transparent_submap(vmrl_flags_t flags)
{
	const vm_map_offset_t start = 0x180000000ULL, submap_end = 0x180000000ULL * 2;
	vm_map_offset_t child_entry_end = start + PAGE_SIZE;
	kern_return_t kr;
	vm_map_t parent_map;
	vm_map_t submap;
	bool excl = vmrl_is_exclusive(flags);
	bool should_descend_transparent = !(flags & VMRL_SH_NO_DESCEND_TRANSPARENT);

	assert(!(vmrl_is_exclusive(flags) && ((flags & VMRL_DESCEND_INTO_CONSTANT) != 0)));

	setup_transparent_submap(start, submap_end, NULL, 1, &parent_map, &submap);

	vm_map_entry_t parent_entry = find_entry_unlocked(parent_map, start);
	assert(VM_MAP_ENTRY_NULL != parent_entry);
	assert(vm_map_entry_is_transparent_submap(parent_entry));

	vm_map_entry_t child_entry = find_entry_unlocked(submap, start);
	assert(VM_MAP_ENTRY_NULL != child_entry);

	VM_MAP_FIND_LOCK_CTX_DECLARE(ctx);


	printf("%s(%x):    Lock by addr in transparent submap\n", __func__, flags);
	kr = call_find_locked_lock(ctx, parent_map, start, flags, excl);
	assert3u(kr, ==, KERN_SUCCESS);

	if (should_descend_transparent) {
		assert3p(child_entry, ==, ctx->vmlc_vme);
		if (excl) {
			vm_entry_assert_excl_owner(child_entry);
		} else {
			vm_entry_assert_shared_owner(child_entry);
		}
		vm_entry_assert_not_owner(parent_entry);
	} else {
		assert3p(parent_entry, ==, ctx->vmlc_vme);
		vm_entry_assert_not_owner(child_entry);
	}

	call_find_locked_unlock(ctx, excl);
	vm_entry_assert_not_owner(parent_entry);
	vm_entry_assert_not_owner(child_entry);

	printf("%s(%x):    Lock by addr in transparent submap with no entry here or after\n", __func__, flags);
	kr = call_find_locked_lock(ctx, parent_map, child_entry_end, flags, excl);
	if (should_descend_transparent) {
		assert3u(kr, ==, KERN_INVALID_ADDRESS);
		vm_entry_assert_not_owner(parent_entry);
		vm_entry_assert_not_owner(child_entry);
	} else {
		assert3u(kr, ==, KERN_SUCCESS);
		assert3p(parent_entry, ==, ctx->vmlc_vme);
		vm_entry_assert_not_owner(child_entry);
		call_find_locked_unlock(ctx, excl);
		vm_entry_assert_not_owner(parent_entry);
		vm_entry_assert_not_owner(child_entry);
	}


	printf("%s(%x):    Lock by addr in transparent submap with no entry here but entry later in submap\n", __func__, flags);
	vm_map_offset_t other_child_entry_start = child_entry_end + PAGE_SIZE;
	vm_map_offset_t other_child_entry_end = other_child_entry_start + PAGE_SIZE;
	vm_map_entry_t other_child_entry = vm_test_add_map_entry(submap, other_child_entry_start, other_child_entry_end);
	kr = call_find_locked_lock(ctx, parent_map, child_entry_end, flags, excl);
	if (should_descend_transparent) {
		assert3u(kr, ==, KERN_INVALID_ADDRESS);
		vm_entry_assert_not_owner(parent_entry);
		vm_entry_assert_not_owner(child_entry);
	} else {
		assert3u(kr, ==, KERN_SUCCESS);
		assert3p(parent_entry, ==, ctx->vmlc_vme);
		vm_entry_assert_not_owner(child_entry);

		call_find_locked_unlock(ctx, excl);
		vm_entry_assert_not_owner(parent_entry);
		vm_entry_assert_not_owner(child_entry);
		vm_entry_assert_not_owner(other_child_entry);
	}

	vm_map_destroy_options(parent_map, VM_MAP_DESTROY_ALLOW_TRANSPARENT_SUBMAP);
	vm_map_destroy(submap);
}

static void
vm_map_find_locked_entry_test_preflight(bool excl)
{
	vm_map_t map = vm_test_alloc_map();
	const vm_map_offset_t start = 0x10000, end = 0x20000;
	const vm_map_offset_t start2 = end, end2 = 0x30000;
	const vm_map_offset_t start3 = end2, end3 = 0x40000;
	kern_return_t kr;
	__block unsigned int preflight_calls = 0;

	vm_map_entry_t entry = vm_test_add_map_entry(map, start, end);

	VM_MAP_FIND_LOCK_CTX_DECLARE(ctx);

	// case 1 - happy case, preflight returns SUCCESS
	{
		printf("%s(%d):    Lock an entry by addr with preflight\n", __func__, excl);
		vm_map_lock_ctx_set_preflight(ctx, ^kern_return_t (vm_map_lock_ctx_t vctx __unused, vm_map_entry_t vme) {
			preflight_calls++;
			assert3p(entry, ==, vme);
			return KERN_SUCCESS;
		});
		kr = call_find_locked_lock(ctx, map, start, 0, excl);
		assert3u(kr, ==, KERN_SUCCESS);
		assert3p(entry, ==, ctx->vmlc_vme);
		if (excl) {
			vm_entry_assert_excl_owner(entry);
		} else {
			vm_entry_assert_shared_owner(entry);
		}
		assert3u(preflight_calls, ==, 1);

		call_find_locked_unlock(ctx, excl);
		vm_entry_assert_not_owner(entry);
	}

	// case 2 - preflight returns FAILURE
	{
		printf("%s(%d):    Lock an entry by addr with erroring preflight\n", __func__, excl);
		preflight_calls = 0;
		vm_map_lock_ctx_set_preflight(ctx, ^kern_return_t (vm_map_lock_ctx_t vctx __unused, vm_map_entry_t vme) {
			preflight_calls++;
			assert3p(entry, ==, vme);
			return KERN_FAILURE;
		});
		kr = call_find_locked_lock(ctx, map, start, 0, excl);
		assert3u(kr, ==, KERN_FAILURE);
		assert3u(preflight_calls, ==, 1);
		vm_entry_assert_not_owner(entry);
	}

	// case 3 - preflight returns SKIP_PREPARE, object is not created even though we pass VMRL_RESOLVE_COW_AND_OBJ
	printf("%s(%d):    Lock an entry by addr with special preflight return: VMRL_ERR_SKIP_PREPARE\n", __func__, excl);
	vm_map_entry_t entry2 = vm_test_add_map_entry(map, start2, end2);
	assert3p(VME_OBJECT(entry2), ==, VM_OBJECT_NULL);
	preflight_calls = 0;
	vm_map_lock_ctx_set_preflight(ctx, ^kern_return_t (vm_map_lock_ctx_t vctx __unused, vm_map_entry_t vme) {
		preflight_calls++;
		assert3p(entry2, ==, vme);
		return VMRL_ERR_SKIP_PREPARE;
	});
	kr = call_find_locked_lock(ctx, map, start2, VMRL_RESOLVE_COW_AND_OBJ, excl);
	assert3u(kr, ==, KERN_SUCCESS);
	assert3p(entry2, ==, ctx->vmlc_vme);
	if (excl) {
		vm_entry_assert_excl_owner(entry2);
	} else {
		vm_entry_assert_shared_owner(entry2);
	}
	assert3u(preflight_calls, ==, 1);
	/* Confirm that no object was allocated */
	assert3p(VME_OBJECT(entry2), ==, VM_OBJECT_NULL);

	call_find_locked_unlock(ctx, excl);
	vm_entry_assert_not_owner(entry);

	// case 3 - preflight returns SETUP_SYMMETRIC_COW for an entry with an object
	{
		// add an entry with an object
		printf("%s(%d):    Lock an entry by addr with special preflight return: VMRL_ERR_SETUP_SYMMETRIC_COW\n", __func__, excl);

		vm_map_entry_t entry3 = vm_test_add_map_entry(map, start3, end3);
		bool lock_success = vm_entry_try_lock_exclusive(entry3);
		assert(lock_success);
		VME_OBJECT_SET(entry3, vm_object_allocate(0x10000, 0), false, 0);
		vm_entry_unlock_exclusive(map, entry3);

		preflight_calls = 0;
		vm_map_lock_ctx_set_preflight(ctx, ^kern_return_t (vm_map_lock_ctx_t vctx __unused, vm_map_entry_t vme) {
			preflight_calls++;
			assert3p(entry3, ==, vme);
			return VMRL_ERR_SETUP_SYMMETRIC_COW;
		});
		assert3u(entry3->needs_copy, ==, 0);
		kr = call_find_locked_lock(ctx, map, start3, 0, excl);
		assert3u(kr, ==, KERN_SUCCESS);
		assert3p(entry3, ==, ctx->vmlc_vme);
		if (excl) {
			vm_entry_assert_excl_owner(entry3);
		} else {
			vm_entry_assert_shared_owner(entry3);
		}
		assert3u(entry3->needs_copy, ==, 1);
		assert3u(preflight_calls, ==, 1);

		call_find_locked_unlock(ctx, excl);
		vm_entry_assert_not_owner(entry3);
	}

	// RANGELOCKINGTODO add tests for VMRL_ERR_SETUP_SYMMETRIC_COW_NOCLIP, VMRL_ERR_PREPARE_FOR_SHARE_NOCLIP rdar://154930530

	vm_map_destroy(map);
}

static void
vm_map_find_locked_entry_test_no_clip(bool excl)
{
	vm_map_t map = vm_test_alloc_map();
	const vm_map_offset_t start = 0x10000, end = 0x20000, middle = (start + end) / 2;
	kern_return_t kr;

	vm_map_entry_t entry = vm_test_add_map_entry(map, start, end);

	VM_MAP_FIND_LOCK_CTX_DECLARE(ctx);

	printf("%s(%d):    Lock an entry by addr in the middle\n", __func__, excl);
	kr = call_find_locked_lock(ctx, map, middle, 0, excl);
	assert3u(kr, ==, KERN_SUCCESS);
	assert3p(entry, ==, ctx->vmlc_vme);
	if (excl) {
		vm_entry_assert_excl_owner(entry);
	} else {
		vm_entry_assert_shared_owner(entry);
	}
	/* Check that entry bounds are unaffected. */
	assert3u(entry->vme_start, ==, start);
	assert3u(entry->vme_end, ==, end);

	call_find_locked_unlock(ctx, excl);
	vm_entry_assert_not_owner(entry);

	vm_map_destroy(map);
}

static void
vm_map_find_locked_entry_test_flags(bool excl)
{
	vm_map_t map = vm_test_alloc_map();
	const vm_map_offset_t start = 0x10000, end = 0x20000;
	kern_return_t kr;

	vm_map_entry_t entry = vm_test_add_map_entry(map, start, end);

	VM_MAP_FIND_LOCK_CTX_DECLARE(ctx);

	if (!excl) {
		printf("%s(%d):    Lock an entry by addr with flag VMRL_VMO_ALLOCATE\n", __func__, excl);
		assert3p(VME_OBJECT(entry), ==, VM_OBJECT_NULL);
		kr = call_find_locked_lock(ctx, map, start, VMRL_VMO_ALLOCATE, excl);
		assert3u(kr, ==, KERN_SUCCESS);
		assert3p(entry, ==, ctx->vmlc_vme);
		vm_entry_assert_shared_owner(entry);

		call_find_locked_unlock(ctx, excl);
	} else {
		/* VMRL_VMO_ALLOCATE is only valid for shared locks, but we want an object to test VMRL_RESOLVE_COW_AND_OBJ below */
		__vmrl_ilk_lock_exclusive(map);
		kr = vm_entry_lock_exclusive(map, LCK_RW_TYPE_EXCLUSIVE,
		    entry, entry->vme_start, THREAD_UNINT);
		__vmrl_ilk_unlock_exclusive(map);
		assert3u(kr, ==, KERN_SUCCESS);
		vm_map_entry_lock_allocate_object(entry, map->serial_id);
		vm_entry_unlock_exclusive(map, entry);
	}
	vm_entry_assert_not_owner(entry);
	/* Check that an object was allocated. */
	vm_object_t obj1 = VME_OBJECT(entry);
	assert3p(obj1, !=, VM_OBJECT_NULL);

	printf("%s(%d):    Lock an entry by addr with flag VMRL_RESOLVE_COW_AND_OBJ\n", __func__, excl);
	entry->needs_copy = true;
	vm_object_reference(obj1); /* Avoid cleanup */
	kr = call_find_locked_lock(ctx, map, start, VMRL_RESOLVE_COW_AND_OBJ, excl);
	assert3u(kr, ==, KERN_SUCCESS);
	assert3p(entry, ==, ctx->vmlc_vme);
	if (excl) {
		vm_entry_assert_excl_owner(entry);
	} else {
		vm_entry_assert_shared_owner(entry);
	}
	vm_object_t obj2 = VME_OBJECT(entry);
	assert3u(entry->needs_copy, ==, false);
	assert3p(obj1, !=, obj2);
	assert3p(obj1, ==, obj2->shadow);

	call_find_locked_unlock(ctx, excl);
	vm_entry_assert_not_owner(entry);
	vm_object_deallocate(obj1); /* Release earlier ref */

	printf("%s(%d):    Lock an entry by addr with flag VMRL_ILK_LOCKED\n", __func__, excl);
	__vmrl_ilk_lock_exclusive(map);
	kr = call_find_locked_lock(ctx, map, start, VMRL_ILK_LOCKED, excl);
	assert3u(kr, ==, KERN_SUCCESS);
	assert3p(entry, ==, ctx->vmlc_vme);
	if (excl) {
		vm_entry_assert_excl_owner(entry);
	} else {
		vm_entry_assert_shared_owner(entry);
	}

	call_find_locked_unlock(ctx, excl);
	vm_entry_assert_not_owner(entry);

	vm_map_destroy(map);
}

static void
vm_map_find_locked_entry_test_whole_map(bool excl)
{
	kern_return_t kr;
	vm_map_t map;
	const vm_map_address_t map_start = 0x30000, map_end = 0x60000;
	const vm_map_offset_t before_start = 0x10000, before_end = 0x20000;
	const vm_map_offset_t after_start = 0x70000, after_end = 0x80000;
	vm_map_entry_t entry_before, entry_after;

	map = vm_test_alloc_map();
	map->min_offset = map_start;
	map->max_offset = map_end;

	entry_before = vm_test_add_map_entry(map, before_start, before_end);
	entry_after = vm_test_add_map_entry(map, after_start, after_end);

	VM_MAP_FIND_LOCK_CTX_DECLARE(ctx);


	printf("%s(%d):    Lock by addr before map (without NO_MIN_MAX_CHECK)\n", __func__, excl);
	kr = call_find_locked_lock(ctx, map, before_start, 0, excl);
	assert3u(kr, ==, KERN_INVALID_ADDRESS);
	vm_entry_assert_not_owner(entry_before);
	vm_entry_assert_not_owner(entry_after);


	printf("%s(%d):    Lock by addr before map (with NO_MIN_MAX_CHECK)\n", __func__, excl);
	kr = call_find_locked_lock(ctx, map, before_start, VMRL_NO_MIN_MAX_CHECK, excl);
	assert3u(kr, ==, KERN_SUCCESS);
	assert3p(entry_before, ==, ctx->vmlc_vme);
	if (excl) {
		vm_entry_assert_excl_owner(entry_before);
	} else {
		vm_entry_assert_shared_owner(entry_before);
	}
	vm_entry_assert_not_owner(entry_after);

	call_find_locked_unlock(ctx, excl);
	vm_entry_assert_not_owner(entry_before);


	printf("%s(%d):    Lock by addr after map (without NO_MIN_MAX_CHECK)\n", __func__, excl);
	kr = call_find_locked_lock(ctx, map, after_start, 0, excl);
	assert3u(kr, ==, KERN_INVALID_ADDRESS);
	vm_entry_assert_not_owner(entry_before);
	vm_entry_assert_not_owner(entry_after);


	printf("%s(%d):    Lock by addr after map (with NO_MIN_MAX_CHECK)\n", __func__, excl);
	kr = call_find_locked_lock(ctx, map, after_start, VMRL_NO_MIN_MAX_CHECK, excl);
	assert3u(kr, ==, KERN_SUCCESS);
	assert3p(entry_after, ==, ctx->vmlc_vme);
	if (excl) {
		vm_entry_assert_excl_owner(entry_after);
	} else {
		vm_entry_assert_shared_owner(entry_after);
	}
	vm_entry_assert_not_owner(entry_before);

	call_find_locked_unlock(ctx, excl);
	vm_entry_assert_not_owner(entry_after);


	vm_map_destroy(map);
}

static void
vm_map_find_locked_entry_test_4k_map(bool excl)
{
	vm_map_t map = vm_test_alloc_4k_map();
	const vm_map_offset_t addr = 0x10000;
	const vm_map_offset_t entry_start = addr + FOURK_PAGE_SIZE;
	const vm_map_offset_t entry_end = entry_start + FOURK_PAGE_SIZE;
	kern_return_t kr;

	vm_map_entry_t entry = vm_test_add_map_entry(map, entry_start, entry_end);

	VM_MAP_FIND_LOCK_CTX_DECLARE(ctx);

	printf("%s(%d):    Lock by addr before entry on 4k\n", __func__, excl);
	kr = call_find_locked_lock(ctx, map, addr, 0, excl);
	assert3u(kr, ==, KERN_INVALID_ADDRESS);
	vm_entry_assert_not_owner(entry);

	printf("%s(%d):    Lock by addr at same entry on 4k\n", __func__, excl);
	kr = call_find_locked_lock(ctx, map, entry_start, 0, excl);
	assert3u(kr, ==, KERN_SUCCESS);
	if (excl) {
		vm_entry_assert_excl_owner(entry);
	} else {
		vm_entry_assert_shared_owner(entry);
	}
	call_find_locked_unlock(ctx, excl);
	vm_entry_assert_not_owner(entry);

	printf("Add new entry at addr\n");
	vm_map_entry_t entry_at_addr = vm_test_add_map_entry(map, addr, addr + FOURK_PAGE_SIZE);

	printf("%s(%d):    Lock entry at original addr by addr on 4k\n", __func__, excl);
	kr = call_find_locked_lock(ctx, map, addr, 0, excl);
	assert3u(kr, ==, KERN_SUCCESS);
	if (excl) {
		vm_entry_assert_excl_owner(entry_at_addr);
	} else {
		vm_entry_assert_shared_owner(entry_at_addr);
	}
	vm_entry_assert_not_owner(entry);
	call_find_locked_unlock(ctx, excl);
	vm_entry_assert_not_owner(entry_at_addr);
	vm_entry_assert_not_owner(entry);

	vm_map_destroy(map);
}

static int
vm_map_find_locked_entry_test(__unused int64_t in, int64_t *out)
{
	printf("%s: test running (thread=%p)\n", __func__, current_thread());

	printf("%s: vm_map_find_locked_entry_test_simple()\n", __func__);
	vm_map_find_locked_entry_test_simple(false);
	vm_map_find_locked_entry_test_simple(true);

	printf("%s: vm_map_find_locked_entry_test_gap()\n", __func__);
	vm_map_find_locked_entry_test_gap(false);
	vm_map_find_locked_entry_test_gap(true);

#ifndef __BUILDING_XNU_LIB_UNITTEST__
	printf("%s: vm_map_find_locked_entry_test_constant_submap()\n", __func__);
	vm_map_find_locked_entry_test_constant_submap(false, false);
	vm_map_find_locked_entry_test_constant_submap(false, true);
	vm_map_find_locked_entry_test_constant_submap(true, false);
	/* excl + descend is not valid */
#endif

	printf("%s: vm_map_find_locked_entry_test_transparent_submap()\n", __func__);
	vm_map_find_locked_entry_test_transparent_submap(VMRL_EXCLUSIVE);
	vm_map_find_locked_entry_test_transparent_submap(VMRL_SHARED);
	vm_map_find_locked_entry_test_transparent_submap(VMRL_SHARED | VMRL_DESCEND_INTO_CONSTANT);
	vm_map_find_locked_entry_test_transparent_submap(VMRL_SHARED | VMRL_NO_DESCEND_TRANSPARENT);
	/* excl + descend is not valid */

	printf("%s: vm_map_find_locked_entry_test_preflight()\n", __func__);
	vm_map_find_locked_entry_test_preflight(false);
	vm_map_find_locked_entry_test_preflight(true);

	printf("%s: vm_map_find_locked_entry_test_no_clip()\n", __func__);
	vm_map_find_locked_entry_test_no_clip(false);
	vm_map_find_locked_entry_test_no_clip(true);

	printf("%s: vm_map_find_locked_entry_test_flags()\n", __func__);
	vm_map_find_locked_entry_test_flags(false);
	vm_map_find_locked_entry_test_flags(true);

	printf("%s: vm_map_find_locked_entry_test_whole_map()\n", __func__);
	vm_map_find_locked_entry_test_whole_map(false);
	vm_map_find_locked_entry_test_whole_map(true);

	printf("%s: vm_map_find_locked_entry_test_4k_map()\n", __func__);
	vm_map_find_locked_entry_test_4k_map(false);
	vm_map_find_locked_entry_test_4k_map(true);

	printf("%s: test passed\n", __func__);

	*out = 1;
	return 0;
}

#pragma mark test syctls

SYSCTL_TEST_REGISTER(vm_range_lock_test, vm_range_lock_test);
SYSCTL_TEST_REGISTER(vm_range_lock_preflight_test, vm_range_lock_preflight_test);
SYSCTL_TEST_REGISTER(vm_range_lock_race_test, vm_range_lock_race_test);
SYSCTL_TEST_REGISTER(vm_range_lock_flags_test, vm_range_lock_flags_test);
SYSCTL_TEST_REGISTER(vm_range_lock_fault_bench, vm_range_lock_fault_bench);
SYSCTL_TEST_REGISTER(vm_map_find_locked_entry_test, vm_map_find_locked_entry_test);
