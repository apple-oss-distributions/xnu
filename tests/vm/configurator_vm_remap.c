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

/*
 * vm/configurator_vm_remap.c
 *
 * Test vm_remap with many different VM states.
 */

#include "configurator/vm_configurator_tests.h"
#include "configurator/vm_configurator_helpers.h"
#include "exc_guard_helper.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm.configurator"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"),
	T_META_RUN_CONCURRENTLY(true),
	T_META_ASROOT(true),  /* required for vm submap sysctls */
	T_META_ALL_VALID_ARCHS(true)
	);

static bool
call_vm_remap_overwrite_and_expect_result(
	mach_vm_address_t dst_addr,
	mach_vm_address_t src_addr,
	mach_vm_address_t size,
	bool copy,
	kern_return_t expected_kr,
	vm_prot_t expected_cur_prot,
	vm_prot_t expected_max_prot)
{
	const vm_prot_t uninitialized_prot = ~(vm_prot_t)0;
#if workaround_rdar_143341561
	__block mach_vm_address_t dst_addr_out = dst_addr;
	__block vm_prot_t cur_prot = uninitialized_prot, max_prot = uninitialized_prot;
	__block kern_return_t kr;
	exc_guard_helper_info_t exc_info;
	/* BEGIN IGNORE CODESTYLE */
	bool caught_exception = block_raised_exc_guard_of_type_ignoring_translated(GUARD_TYPE_VIRT_MEMORY, &exc_info, ^{
		kr = mach_vm_remap(mach_task_self(), &dst_addr_out, size, 0 /* alignment mask */,
		    VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE | VM_FLAGS_RETURN_DATA_ADDR,
		    mach_task_self(), src_addr, copy,
		    &cur_prot, &max_prot, VM_INHERIT_DEFAULT);
	});
	/* END IGNORE CODESTYLE */
	if (caught_exception) {
		T_LOG("warning: rdar://143341561 mmap(FIXED) should work "
		    "regardless of whether a mapping exists at the addr");
	}
#else  /* not workaround_rdar_143341561 */
	mach_vm_address_t dst_addr_out = dst_addr;
	vm_prot_t cur_prot = uninitialized_prot, max_prot = uninitialized_prot;
	kern_return_t kr;
	kr = mach_vm_remap(mach_task_self(), &dst_addr_out, size, 0 /* alignment mask */,
	    VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE | VM_FLAGS_RETURN_DATA_ADDR,
	    mach_task_self(), src_addr, copy,
	    &cur_prot, &max_prot, VM_INHERIT_DEFAULT);
#endif /* not workaround_rdar_143341561 */

	if (kr != expected_kr) {
		T_EXPECT_MACH_ERROR(kr, expected_kr, "vm_remap");
		return false;
	}

	/* dst_addr_out is unconditionally unchanged */
	if (dst_addr_out != dst_addr) {
		T_EXPECT_EQ(dst_addr_out, dst_addr, "vm_remap(FIXED | OVERWRITE) dest address should not change");
		return false;
	}

	if (kr != KERN_SUCCESS) {
		/* out prots are unchanged on failure */
		expected_cur_prot = uninitialized_prot;
		expected_max_prot = uninitialized_prot;
	}
	if (cur_prot != expected_cur_prot) {
		T_EXPECT_EQ(cur_prot, expected_cur_prot, "vm_remap cur_prot out");
		return false;
	}
	if (max_prot != expected_max_prot) {
		T_EXPECT_EQ(max_prot, expected_max_prot, "vm_remap max_prot out");
		return false;
	}

	return true;
}

/* Scan checkers and accumulate the cur/max prots found among them. */
static void
find_remap_prot_from_checkers(entry_checker_range_t checkers,
    vm_prot_t * const out_cur_prot, vm_prot_t * const out_max_prot)
{
	vm_prot_t cur_prot = VM_PROT_ALL;
	vm_prot_t max_prot = VM_PROT_ALL;
	vm_prot_t submap_cur_prot, submap_max_prot;

	FOREACH_CHECKER(checker, checkers) {
		switch (checker->kind) {
		case Allocation:
			cur_prot &= checker->protection;
			max_prot &= checker->max_protection;
			break;
		case Submap:
			find_remap_prot_from_checkers(
				checker->object->submap_checkers->entries,
				&submap_cur_prot, &submap_max_prot);
			cur_prot &= submap_cur_prot;
			max_prot &= submap_max_prot;
			break;
		case Hole:
		case Guard:
		case EndEntries:
			break;
		}
	}

	*out_cur_prot = cur_prot;
	*out_max_prot = max_prot;
}

/*
 * vm_remap sometimes does not clip its source range normally.
 * Instead we clip the dest entries manually,
 * discarding any removed sections.
 */
static void
clip_manually(vm_entry_checker_t *checker, mach_vm_address_t start, mach_vm_address_t end)
{
	mach_vm_address_t old_address = checker->address;
	clamp_address_size_to_address_size(&checker->address, &checker->size, start, end - start);
	if (checker->address > old_address) {
		mach_vm_size_t removed = checker->address - old_address;
		checker->object_offset += removed;
	}
}

/*
 * Make a new checker that copies or shares a source that is being remapped.
 * src_start and src_size are the bounds of the entire remap call.
 *
 * The new checker is at the same address range as the source
 * (though with src_start/src_size it may not be identical)
 * and will need to be repositioned by the caller.
 * The new checker is not inserted into the checker list.
 *
 * src_checker may be modified to set up or resolve COW as needed.
 */
static vm_entry_checker_t *
clone_checker_for_remap(
	checker_list_t *checker_list,
	vm_entry_checker_t *src_checker,
	mach_vm_address_t src_start,
	mach_vm_size_t src_size,
	bool copy)
{
	/* use clone_submap_for_remap() instead */
	assert(!checker_is_submap(src_checker));

	vm_entry_checker_t *dst_checker;
	if (copy) {
		if (src_checker->max_protection == 0) {
			assert(src_checker->protection == 0);
			/*
			 * Optimization: inaccessible entries short-circuit
			 * before null object resolution
			 */
			dst_checker = checker_clone(src_checker);
		} else if (is_new_vm()) {
			/* new vm: ordinary copy */
			dst_checker = checker_clone_copy(checker_list, src_checker);
		} else {
			/* old vm: vm_map_remap_extract may modify the source before copying it */

			checker_resolve_null_vm_object(checker_list, src_checker);
			if (src_checker->object->copy_strategy == copy_delay) {
				/* nothing to do */
			} else if (src_checker->needs_copy) {
				/*
				 * vm_map_remap_extract always shadows here (changing the
				 * source map entry) instead of making the new entry
				 * needs_copy=true pointing to the same object
				 */
				checker_make_shadow_object(checker_list, src_checker);
				src_checker->needs_copy = false;
				src_checker->object->copy_strategy = copy_delay;
			} else if (src_checker->object->copy_strategy == copy_symmetric) {
				/*
				 * vm_map_remap_extract always changes a single-owner
				 * copy_symmetric object to copy_delay, instead of
				 * making both entries needs_copy=true pointing to
				 * the same object
				 */
				src_checker->object->copy_strategy = copy_delay;
			} else {
				T_FAIL("unimplemented copy_strategy %s",
				    name_for_copy_strategy(src_checker->object->copy_strategy));
			}

			dst_checker = checker_clone_copy(checker_list, src_checker);
		}
	} else {
		/* share */
		dst_checker = checker_clone_share(checker_list, src_checker);
	}

	/*
	 * Source entries were not clipped.
	 * Instead clip the to-be dest checker now
	 * before it is repositioned to the destination address.
	 */
	clip_manually(dst_checker, src_start, src_start + src_size);

	/* Permanent entries are not permanent after remapping. */
	dst_checker->permanent = false;

	if (is_new_vm()) {
		/* new vm: entry with NULL object gets a zero offset */
		if (object_is_null(dst_checker->object)) {
			dst_checker->object_offset = 0;
		}
	}
	return dst_checker;
}


/*
 * Make a new checker that copies or shares a submap that is being remapped.
 * src_start and src_size are the bounds of the entire remap call.
 *
 * The new checker is at the same address range as the source
 * (though with src_start/src_size it may not be identical)
 * and will need to be repositioned by the caller.
 * The new checker is not inserted into the checker list.
 *
 * submap_parent may be modified to set up or resolve COW as needed.
 */
static entry_checker_range_t
clone_submap_for_remap(
	checker_list_t *checker_list __unused,
	vm_entry_checker_t *submap_parent,
	mach_vm_address_t src_start,
	mach_vm_size_t src_size,
	bool copy)
{
	/* use clone_checker_for_remap() for allocations */
	assert(checker_is_submap(submap_parent));

	checker_list_t *submap_contents DEFER_UNSLIDE =
	    checker_get_and_slide_submap_checkers(submap_parent);

	mach_vm_address_t submap_start = MAX(src_start, submap_parent->address);
	mach_vm_address_t submap_end = MIN(src_start + src_size, checker_end_address(submap_parent));

	entry_checker_range_t src_checkers =
	    checker_list_find_range_including_holes(
		submap_contents, submap_start, submap_end - submap_start);
	entry_checker_range_t dst_checkers = { .head = NULL, .tail = NULL };
	FOREACH_CHECKER(src_checker, src_checkers) {
		/*
		 * Can't share submap contents. Copy unconditionally first,
		 * then share that copy if we're sharing.
		 */
		assert(!checker_is_submap(src_checker));
		vm_entry_checker_t *dst_checker = clone_checker_for_remap(submap_contents,
		    src_checker, submap_start, submap_end - submap_start, true /* copy */);
		dst_checker->submap_depth = 0;

		if (!copy && is_new_vm()) {
			/* share the copy and discard the intermediate */
			vm_entry_checker_t *tmp_checker = dst_checker;
			dst_checker = clone_checker_for_remap(submap_contents, tmp_checker,
			    submap_start, submap_end - submap_start, false /* copy */);
			checker_free(tmp_checker);
		}

		checker_range_append(&dst_checkers, dst_checker);
	}

	return dst_checkers;
}

/*
 * Allocate a buffer to act as the source for vm_remap "in".
 * This buffer is shared memory to prevent a behavior difference in
 * remap-overwrite-in between range-locking VM and non-range-locking VM.
 */
static mach_vm_address_t
allocate_remap_source(mach_vm_size_t size)
{
	mach_vm_address_t addr = 0;
	kern_return_t kr = mach_vm_allocate(mach_task_self(), &addr, size, VM_FLAGS_ANYWHERE);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_allocate source buffer");

	return addr;
}

static void
deallocate_remap_source(mach_vm_address_t addr, mach_vm_size_t size)
{
	kern_return_t kr = mach_vm_deallocate(mach_task_self(), addr, size);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_deallocate source buffer");
}

/*
 * Allocate a buffer to act as the destination for vm_remap "out".
 * We use the same allocation technique as the configurator arena
 * for the same reasons as described there (tl;dr holes with Rosetta).
 */
static mach_vm_address_t
allocate_remap_dest(mach_vm_size_t size)
{
	return allocate_at_random_address(size, 0 /* alignment mask */,
	           VM_PROT_DEFAULT, VM_PROT_DEFAULT);
}
static mach_vm_address_t
allocate_remap_dest_with_guards(mach_vm_size_t size)
{
	return allocate_with_guards(size, 0 /* alignment mask */,
	           PAGE_SIZE /* guard page size */, VM_PROT_DEFAULT, VM_PROT_DEFAULT);
}

/*
 * vm_remap source is an anonymous buffer
 * vm_remap destination is the prepared VM state at [start, start + size)
 * vm_remap flags = fixed | overwrite
 * We update the VM state's checkers at the destination.
 */
static test_result_t
successful_vm_remap_overwrite_in(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size,
	bool copy)
{
	test_result_t test_result;
	char old_value = 0x41;
	char new_value = 0x42;

	/*
	 * Allocate source memory to remap at `start`,
	 * add a checker for it to the checker list,
	 * and fill it with old_value.
	 */
	mach_vm_address_t src_addr = allocate_remap_source(size);

	vm_entry_checker_t *src_checker = make_checker_for_vm_allocate(
		checker_list, src_addr, size, 0);
	checker_list_insert(checker_list, src_checker);

	memset((void *)src_addr, old_value, size);
	checker_fault_all(checker_list, src_checker, VM_PROT_WRITE);
	src_checker->object->fill_pattern = fill_pattern_from_char(old_value);

	/* Verify this VM state. */
	TEMP_CSTRING(before_message, "before vm_remap in %s (source 0x%llx, dest 0x%llx)",
	    copy ? "copy" : "share", src_addr, start);
	test_result = verify_vm_state(checker_list, before_message);
	if (test_result != TestSucceeded) {
		return test_result;
	}

	/* Remap overwriting [start, start + size). */
	bool good = call_vm_remap_overwrite_and_expect_result(
		start, src_addr, size, copy, KERN_SUCCESS,
		VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
	if (!good) {
		return TestFailed;
	}

	/*
	 * Checker update: clip and remove the checkers within [start, start+size)
	 * and replace them with one checker that is a copy or share
	 * of the source memory we allocated above.
	 */
	vm_entry_checker_t *dst_checker = clone_checker_for_remap(checker_list,
	    src_checker, src_addr, size, copy);
	dst_checker->address = start;
	dst_checker->size = size;
	entry_checker_range_t overwritten =
	    checker_list_find_and_clip_including_holes(checker_list, start, size);
	checker_list_replace_range_with_checker(checker_list, overwritten, dst_checker);

	/* Verify this VM state. */
	TEMP_CSTRING(after_message, "after vm_remap in %s (source 0x%llx, dest 0x%llx)",
	    copy ? "copy" : "share", src_addr, start);
	test_result = verify_vm_state(checker_list, after_message);
	if (test_result != TestSucceeded) {
		return test_result;
	}

	/*
	 * Modify the source memory.
	 * If the remap is a copy the new mapping will keep the old value.
	 * If the remap is a share the new mapping will also get the new value.
	 */
	memset((void *)src_addr, new_value, size);
	checker_fault_all(checker_list, src_checker, VM_PROT_WRITE);
	src_checker->object->fill_pattern = fill_pattern_from_char(new_value);
	if (!copy) {
		dst_checker->object->fill_pattern = fill_pattern_from_char(new_value);
	}

	/* Verify this VM state. */
	test_result = verify_vm_state(checker_list, "after writing to the source memory");
	if (test_result != TestSucceeded) {
		return test_result;
	}

	return TestSucceeded;
}

/*
 * vm_remap source is the prepared VM state at [start, start + size)
 * vm_remap destination is an anonymous buffer.
 * vm_remap flags = fixed | overwrite
 * We make new checkers to represent and verify the destination memory
 * and update the VM state checkers at the source as necessary.
 *
 * Pass verify_writes=true to test COW and sharing by writing random bytes
 *   to all writeable memory in the source and verifying the destination.
 * Pass verify_writes=false for memory configurations that can't
 *   pass that test (for example the source itself contains shared entries
 *   with partial overlaps so the data expected after these writes is
 *   too complicated for per-object fill patterns to represent).
 */
static test_result_t
successful_vm_remap_overwrite_out_maybe_verify_writes(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size,
	bool copy,
	bool verify_writes)
{
	test_result_t test_result;

	/* Find the source checkers. Holes are allowed. Don't clip the source yet. */
	entry_checker_range_t src_checkers;
	src_checkers = checker_list_find_range_including_holes(checker_list, start, size);

	/*
	 * Read the permissions of the source entries.
	 * vm_remap returns the maximum cur/max permission remapped.
	 */
	vm_prot_t expected_cur_prot, expected_max_prot;
	find_remap_prot_from_checkers(src_checkers,
	    &expected_cur_prot, &expected_max_prot);

	/*
	 * Allocate a destination buffer to remap `start` to.
	 * Also allocate guard pages around it and add checkers for them.
	 */
	mach_vm_address_t dst_addr = allocate_remap_dest_with_guards(size);
	memset((void *)dst_addr, 0x41, size);
	append_checker_for_guard_page(checker_list, dst_addr - PAGE_SIZE, PAGE_SIZE);
	append_checker_for_guard_page(checker_list, dst_addr + size, PAGE_SIZE);

	/* Remap overwriting the destination buffer. */
	bool good = call_vm_remap_overwrite_and_expect_result(
		dst_addr, start, size, copy, KERN_SUCCESS,
		expected_cur_prot, expected_max_prot);
	if (!good) {
		/* Can't deallocate the remap destination. It might have holes now. */
		return TestFailed;
	}

	/* Create destination checkers and update source checkers. */
	mach_vm_address_t next_dst_addr = dst_addr;
	FOREACH_CHECKER(src_checker, src_checkers) {
		entry_checker_range_t dst_checkers;
		switch (src_checker->kind) {
		case Allocation:
		case Hole:
			dst_checkers.head = dst_checkers.tail = clone_checker_for_remap(checker_list,
			    src_checker, start, size, copy);
			break;
		case Submap:
			/*
			 * vm_remap flattens submaps.
			 * Unfortunately this is not the same operation
			 * as submap unnesting. (For example, remap
			 * preserves the user tag of the submap contents,
			 * but submap unnest does not.)
			 */
			dst_checkers =
			    clone_submap_for_remap(checker_list,
			    src_checker, start, size, copy);
			break;
		case Guard:
		case EndEntries:
			break;
		}

		FOREACH_CHECKER(dst_checker, dst_checkers) {
			/* slide destination checker to its new address */
			dst_checker->address = next_dst_addr;
			next_dst_addr += dst_checker->size;
			checker_list_insert(checker_list, dst_checker);
		}
	}

	/* Verify this VM state. */
	TEMP_CSTRING(after_message, "after vm_remap out %s (source 0x%llx, dest 0x%llx)",
	    copy ? "copy" : "share", start, dst_addr);
	test_result = verify_vm_state(checker_list, after_message);
	if (test_result != TestSucceeded) {
		/* Can't deallocate the remap destination. It might have holes now. */
		return test_result;
	}

	/* src address + delta = dst address */
	mach_vm_size_t delta = dst_addr - start;

	if (!verify_writes) {
		/*
		 * TODO make this smarter so that we can verify CoW/share
		 * even with partial overlaps of source sharing
		 */
		T_LOG("note: skipping verify_writes because of confusing topology");
	} else {
		/*
		 * Modify the source memory.
		 * If the remap is a copy the new mapping will keep the old value.
		 * If the remap is a share the new mapping will also get the new value.
		 */
		FOREACH_CHECKER(src_checker, src_checkers) {
			switch (src_checker->kind) {
			case Allocation:
				if (!prot_contains_all(src_checker->protection, VM_PROT_READ | VM_PROT_WRITE)) {
					/* can't write to this entry */
					break;
				}
				/* Re-fill source with a different fill pattern. */
				checker_write_new_fill_pattern(checker_list, src_checker);
				if (copy) {
					/*
					 * Copy: The destination checker will
					 * still expect the old fill pattern,
					 * thus catching any writes that
					 * incorrectly leak through.
					 */
				} else {
					/*
					 * Share: Set the destination checker's
					 * fill pattern to expect what we just
					 * just wrote to the source.
					 */
					mach_vm_address_t src_address = src_checker->address;
					if (src_address < start) {
						/* remap didn't clip source so it might not line up exactly */
						assert(start < checker_end_address(src_checker));
						src_address = start;
					}
					vm_entry_checker_t *dst_checker =
					    checker_list_find_allocation(checker_list, src_address + delta);
					T_QUIET; T_ASSERT_NOTNULL(dst_checker,
					    "no dst checker for src checker?");
					T_QUIET; T_ASSERT_NOTNULL(dst_checker->object,
					    "dst checker after remap share didn't have an object?");
					dst_checker->object->fill_pattern = src_checker->object->fill_pattern;
				}
				break;
			case Submap:
			case Hole:
				/* can't write to holes or submaps */
				break;
			case EndEntries:
			default:
				assert(0);
			}
		}

		/* Verify this VM state. */
		test_result = verify_vm_state(checker_list, "after writing to remap source");
		if (test_result != TestSucceeded) {
			/* Can't deallocate the remap destination. It might have holes now. */
			return test_result;
		}
	} /* verify_writes */

	/*
	 * Don't free the dest buffer. It has been overwritten now.
	 * Don't free the dest checkers. They are part of the
	 * checker list now.
	 */

	return TestSucceeded;
}

static test_result_t
successful_vm_remap_copy_overwrite_in(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	return successful_vm_remap_overwrite_in(checker_list, start, size, true /* copy */);
}

static test_result_t
successful_vm_remap_share_overwrite_in(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	return successful_vm_remap_overwrite_in(checker_list, start, size, false /* copy */);
}

static test_result_t
successful_vm_remap_copy_overwrite_out(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	return successful_vm_remap_overwrite_out_maybe_verify_writes(
		checker_list, start, size,
		true /* copy */, true /* verify writes */);
}

static test_result_t
successful_vm_remap_share_overwrite_out(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	return successful_vm_remap_overwrite_out_maybe_verify_writes(
		checker_list, start, size,
		false /* copy */, true /* verify writes */);
}

static test_result_t
successful_vm_remap_copy_overwrite_out_no_verify_writes(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	return successful_vm_remap_overwrite_out_maybe_verify_writes(
		checker_list, start, size,
		true /* copy */, false /* verify writes */);
}

static test_result_t
successful_vm_remap_share_overwrite_out_no_verify_writes(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	return successful_vm_remap_overwrite_out_maybe_verify_writes(
		checker_list, start, size,
		false /* copy */, false /* verify writes */);
}

static test_result_t
test_remap_overwrite_out_with_holes(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size,
	bool copy)
{
	/* Look up the source checkers inside the remap bounds. Don't clip anything. */
	entry_checker_range_t src_checkers;
	src_checkers = checker_list_find_range_including_holes(checker_list, start, size);

	/*
	 * Read the permissions of the source entries.
	 * vm_remap returns the maximum cur/max permission remapped.
	 */
	vm_prot_t expected_cur_prot, expected_max_prot;
	find_remap_prot_from_checkers(src_checkers,
	    &expected_cur_prot, &expected_max_prot);

	/* Allocate a destination buffer. */
	mach_vm_address_t dst_addr = allocate_remap_dest(size);

	/*
	 * Remap overwriting the destination buffer.
	 * This is expected to fail because the source has holes.
	 */
	bool good = call_vm_remap_overwrite_and_expect_result(
		dst_addr, start, size, copy, KERN_INVALID_ADDRESS,
		expected_cur_prot, expected_max_prot);
	if (!good) {
		/* Can't deallocate the remap destination. It might have holes now. */
		return TestFailed;
	}

	/*
	 * Entries before the first hole are prepared for copy/share,
	 * but then the copy/share is discarded. Other side effects remain.
	 */
	FOREACH_CHECKER(checker, src_checkers) {
		switch (checker->kind) {
		case Hole:
			goto end_loop;
		case Allocation: {
			vm_entry_checker_t *dst_checker;
			dst_checker = clone_checker_for_remap(checker_list,
			    checker, start, size, copy);
			assert(dst_checker->next == NULL && dst_checker->prev == NULL);
			checker_free(dst_checker);
			break;
		}
		case Submap: {
			entry_checker_range_t dst_checkers;
			dst_checkers = clone_submap_for_remap(checker_list,
			    checker, start, size, copy);
			while (dst_checkers.head != NULL) {
				vm_entry_checker_t *dead = dst_checkers.head;
				dst_checkers.head = dst_checkers.head->next;
				dead->prev = dead->next = NULL;
				checker_free(dead);
			}
			break;
		}
		default:
			T_FAIL("unexpected checker kind %s", name_for_entry_kind(checker->kind));
			T_END;
		}
	}
end_loop:
	return TestSucceeded;
}

static test_result_t
test_remap_copy_overwrite_out_with_holes(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	return test_remap_overwrite_out_with_holes(
		checker_list, start, size, true /* copy */);
}

static test_result_t
test_remap_share_overwrite_out_with_holes(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	return test_remap_overwrite_out_with_holes(
		checker_list, start, size, false /* copy */);
}

static test_result_t
test_permanent_entry_overwrite_in_rangelocked(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size,
	bool copy)
{
	assert(is_new_vm());

#if workaround_rdar_143341561
	if (isRosetta()) {
		T_LOG("warning: can't work around rdar://143341561 on Rosetta; just passing instead");
		return TestSucceeded;
	}
#endif
	mach_vm_address_t src_addr = allocate_remap_source(size);
	if (!call_vm_remap_overwrite_and_expect_result(
		    start, src_addr, size, copy, overwrite_permanent_error(), 0, 0)) {
		return TestFailed;
	}
	deallocate_remap_source(src_addr, size);

	/*
	 * No checker updates. Any fixed|overwrite atop a permanent entry
	 * fails during preflight.
	 */

	return verify_vm_state(checker_list, "after vm_remap(FIXED | OVERWRITE)");
}

static test_result_t
test_permanent_entry_copy_overwrite_in_rangelocked(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	return test_permanent_entry_overwrite_in_rangelocked(checker_list, start, size, true /* copy */);
}

static test_result_t
test_permanent_entry_share_overwrite_in_rangelocked(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	return test_permanent_entry_overwrite_in_rangelocked(checker_list, start, size, false /* copy */);
}

static test_result_t
test_permanent_entry_overwrite_in(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size,
	bool copy)
{
#if workaround_rdar_143341561
	if (isRosetta()) {
		T_LOG("warning: can't work around rdar://143341561 on Rosetta; just passing instead");
		return TestSucceeded;
	}
#endif
	mach_vm_address_t src_addr = allocate_remap_source(size);
	if (!call_vm_remap_overwrite_and_expect_result(
		    start, src_addr, size, copy, overwrite_permanent_error(), 0, 0)) {
		return TestFailed;
	}
	deallocate_remap_source(src_addr, size);

	/* one permanent entry, it becomes inaccessible */
	checker_perform_vm_deallocate_permanent(checker_list, start, size);

	return verify_vm_state(checker_list, "after vm_remap(FIXED | OVERWRITE)");
}

static test_result_t
test_permanent_entry_copy_overwrite_in(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	return test_permanent_entry_overwrite_in(checker_list, start, size, true /* copy */);
}

static test_result_t
test_permanent_entry_share_overwrite_in(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	return test_permanent_entry_overwrite_in(checker_list, start, size, false /* copy */);
}

static test_result_t
test_permanent_before_permanent_overwrite_in(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size,
	bool copy)
{
#if workaround_rdar_143341561
	if (isRosetta()) {
		T_LOG("warning: can't work around rdar://143341561 on Rosetta; just passing instead");
		return TestSucceeded;
	}
#endif
	mach_vm_address_t src_addr = allocate_remap_source(size);
	if (!call_vm_remap_overwrite_and_expect_result(
		    start, src_addr, size, copy, overwrite_permanent_error(), 0, 0)) {
		return TestFailed;
	}
	deallocate_remap_source(src_addr, size);

	/* two permanent entries, both become inaccessible */
	checker_perform_vm_deallocate_permanent(checker_list, start, size / 2);
	checker_perform_vm_deallocate_permanent(checker_list, start + size / 2, size / 2);

	return verify_vm_state(checker_list, "after vm_remap(FIXED | OVERWRITE)");
}

static test_result_t
test_permanent_before_permanent_copy_overwrite_in(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	return test_permanent_before_permanent_overwrite_in(checker_list, start, size, true /* copy */);
}

static test_result_t
test_permanent_before_permanent_share_overwrite_in(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	return test_permanent_before_permanent_overwrite_in(checker_list, start, size, false /* copy */);
}

static test_result_t
test_permanent_before_allocation_overwrite_in(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size,
	bool copy)
{
#if workaround_rdar_143341561
	if (isRosetta()) {
		T_LOG("warning: can't work around rdar://143341561 on Rosetta; just passing instead");
		return TestSucceeded;
	}
#endif
	mach_vm_address_t src_addr = allocate_remap_source(size);
	if (!call_vm_remap_overwrite_and_expect_result(
		    start, src_addr, size, copy, overwrite_permanent_error(), 0, 0)) {
		return TestFailed;
	}
	deallocate_remap_source(src_addr, size);

	/*
	 * one permanent entry, becomes inaccessible
	 * one nonpermanent allocation, becomes deallocated
	 * rdar://144128567 this differs from vm_allocate(FIXED | OVERWRITE)
	 */
	checker_perform_vm_deallocate_permanent(checker_list, start, size / 2);
	checker_perform_successful_vm_deallocate(checker_list, start + size / 2, size / 2);

	return verify_vm_state(checker_list, "after vm_remap(FIXED | OVERWRITE)");
}

static test_result_t
test_permanent_before_allocation_copy_overwrite_in(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	return test_permanent_before_allocation_overwrite_in(checker_list, start, size, true /* copy */);
}

static test_result_t
test_permanent_before_allocation_share_overwrite_in(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	return test_permanent_before_allocation_overwrite_in(checker_list, start, size, false /* copy */);
}

static test_result_t
test_permanent_before_allocation_overwrite_in_rdar144128567(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size,
	bool copy)
{
#if workaround_rdar_143341561
	if (isRosetta()) {
		T_LOG("warning: can't work around rdar://143341561 on Rosetta; just passing instead");
		return TestSucceeded;
	}
#endif
	mach_vm_address_t src_addr = allocate_remap_source(size);
	if (!call_vm_remap_overwrite_and_expect_result(
		    start, src_addr, size, copy, overwrite_permanent_error(), 0, 0)) {
		return TestFailed;
	}
	deallocate_remap_source(src_addr, size);

	/*
	 * one permanent entry, becomes inaccessible
	 * one nonpermanent allocation, becomes deallocated (rdar://144128567)
	 */
	checker_perform_vm_deallocate_permanent(checker_list, start, size / 2);
	checker_perform_successful_vm_deallocate(checker_list, start + size / 2, size / 2);

	return verify_vm_state(checker_list, "after vm_remap(FIXED | OVERWRITE)");
}

static test_result_t
test_permanent_before_allocation_copy_overwrite_in_rdar144128567(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	return test_permanent_before_allocation_overwrite_in_rdar144128567(checker_list, start, size, true /* copy */);
}

static test_result_t
test_permanent_before_allocation_share_overwrite_in_rdar144128567(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	return test_permanent_before_allocation_overwrite_in_rdar144128567(checker_list, start, size, false /* copy */);
}

static test_result_t
test_permanent_before_hole_overwrite_in(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size,
	bool copy)
{
#if workaround_rdar_143341561
	if (isRosetta()) {
		T_LOG("warning: can't work around rdar://143341561 on Rosetta; just passing instead");
		return TestSucceeded;
	}
#endif
	mach_vm_address_t src_addr = allocate_remap_source(size);
	if (!call_vm_remap_overwrite_and_expect_result(
		    start, src_addr, size, copy, overwrite_permanent_error(), 0, 0)) {
		return TestFailed;
	}
	deallocate_remap_source(src_addr, size);

	/*
	 * one permanent entry, becomes inaccessible
	 * one hole, unchanged
	 */
	checker_perform_vm_deallocate_permanent(checker_list, start, size / 2);
	/* no change for addresses [start + size / 2, start + size) */

	return verify_vm_state(checker_list, "after vm_remap(FIXED | OVERWRITE)");
}

static test_result_t
test_permanent_before_hole_copy_overwrite_in(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	return test_permanent_before_hole_overwrite_in(checker_list, start, size, true /* copy */);
}

static test_result_t
test_permanent_before_hole_share_overwrite_in(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	return test_permanent_before_hole_overwrite_in(checker_list, start, size, false /* copy */);
}

static test_result_t
test_permanent_after_allocation_overwrite_in(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size,
	bool copy)
{
#if workaround_rdar_143341561
	if (isRosetta()) {
		T_LOG("warning: can't work around rdar://143341561 on Rosetta; just passing instead");
		return TestSucceeded;
	}
#endif
	mach_vm_address_t src_addr = allocate_remap_source(size);
	if (!call_vm_remap_overwrite_and_expect_result(
		    start, src_addr, size, copy, overwrite_permanent_error(), 0, 0)) {
		return TestFailed;
	}
	deallocate_remap_source(src_addr, size);

	/*
	 * one nonpermanent allocation, becomes deallocated
	 * one permanent entry, becomes inaccessible
	 */
	checker_perform_successful_vm_deallocate(checker_list, start, size / 2);
	checker_perform_vm_deallocate_permanent(checker_list, start + size / 2, size / 2);

	return verify_vm_state(checker_list, "after vm_remap(FIXED | OVERWRITE)");
}

static test_result_t
test_permanent_after_allocation_copy_overwrite_in(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	return test_permanent_after_allocation_overwrite_in(checker_list, start, size, true /* copy */);
}

static test_result_t
test_permanent_after_allocation_share_overwrite_in(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	return test_permanent_after_allocation_overwrite_in(checker_list, start, size, false /* copy */);
}

static test_result_t
test_permanent_after_hole_overwrite_in(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size,
	bool copy)
{
#if workaround_rdar_143341561
	if (isRosetta()) {
		T_LOG("warning: can't work around rdar://143341561 on Rosetta; just passing instead");
		return TestSucceeded;
	}
#endif
	mach_vm_address_t src_addr = allocate_remap_source(size);
	if (!call_vm_remap_overwrite_and_expect_result(
		    start, src_addr, size, copy, overwrite_permanent_error(), 0, 0)) {
		return TestFailed;
	}
	deallocate_remap_source(src_addr, size);

	/*
	 * one hole, unchanged
	 * one permanent entry, becomes inaccessible
	 */
	/* no change for addresses [start, start + size / 2) */
	checker_perform_vm_deallocate_permanent(checker_list, start + size / 2, size / 2);

	return verify_vm_state(checker_list, "after vm_remap(FIXED | OVERWRITE)");
}

static test_result_t
test_permanent_after_hole_copy_overwrite_in(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	return test_permanent_after_hole_overwrite_in(checker_list, start, size, true /* copy */);
}

static test_result_t
test_permanent_after_hole_share_overwrite_in(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	return test_permanent_after_hole_overwrite_in(checker_list, start, size, false /* copy */);
}

/*
 * vm_remap source is an anonymous buffer
 * vm_remap destination is the prepared VM state
 * vm_remap flags = fixed | overwrite, copy = true
 */
T_DECL(vm_remap_copy_overwrite_in,
    "run vm_remap(FIXED | OVERWRITE, copy) to write over various vm configurations")
{
#if workaround_rdar_143341561
	enable_non_fatal_vm_exc_guard();
#endif

	vm_tests_t tests = {
		.single_entry_1 = successful_vm_remap_copy_overwrite_in,
		.single_entry_2 = successful_vm_remap_copy_overwrite_in,
		.single_entry_3 = successful_vm_remap_copy_overwrite_in,
		.single_entry_4 = successful_vm_remap_copy_overwrite_in,

		.single_entry_nonnull_1 = successful_vm_remap_copy_overwrite_in,
		.single_entry_nonnull_2 = successful_vm_remap_copy_overwrite_in,
		.single_entry_nonnull_3 = successful_vm_remap_copy_overwrite_in,
		.single_entry_nonnull_4 = successful_vm_remap_copy_overwrite_in,

		.multiple_entries_1 = successful_vm_remap_copy_overwrite_in,
		.multiple_entries_2 = successful_vm_remap_copy_overwrite_in,
		.multiple_entries_3 = successful_vm_remap_copy_overwrite_in,
		.multiple_entries_4 = successful_vm_remap_copy_overwrite_in,
		.multiple_entries_5 = successful_vm_remap_copy_overwrite_in,
		.multiple_entries_6 = successful_vm_remap_copy_overwrite_in,

		.some_holes_1 = successful_vm_remap_copy_overwrite_in,
		.some_holes_2 = successful_vm_remap_copy_overwrite_in,
		.some_holes_3 = successful_vm_remap_copy_overwrite_in,
		.some_holes_4 = successful_vm_remap_copy_overwrite_in,
		.some_holes_5 = successful_vm_remap_copy_overwrite_in,
		.some_holes_6 = successful_vm_remap_copy_overwrite_in,
		.some_holes_7 = successful_vm_remap_copy_overwrite_in,
		.some_holes_8 = successful_vm_remap_copy_overwrite_in,
		.some_holes_9 = successful_vm_remap_copy_overwrite_in,
		.some_holes_10 = successful_vm_remap_copy_overwrite_in,
		.some_holes_11 = successful_vm_remap_copy_overwrite_in,
		.some_holes_12 = successful_vm_remap_copy_overwrite_in,

		.all_holes_1 = successful_vm_remap_copy_overwrite_in,
		.all_holes_2 = successful_vm_remap_copy_overwrite_in,
		.all_holes_3 = successful_vm_remap_copy_overwrite_in,
		.all_holes_4 = successful_vm_remap_copy_overwrite_in,

		.null_entry = successful_vm_remap_copy_overwrite_in,
		.nonresident_entry = successful_vm_remap_copy_overwrite_in,
		.resident_entry = successful_vm_remap_copy_overwrite_in,

		.shared_entry = successful_vm_remap_copy_overwrite_in,
		.shared_entry_discontiguous = successful_vm_remap_copy_overwrite_in,
		.shared_entry_partial = successful_vm_remap_copy_overwrite_in,
		.shared_entry_pairs = successful_vm_remap_copy_overwrite_in,
		.shared_entry_x1000 = successful_vm_remap_copy_overwrite_in,

		.cow_entry = successful_vm_remap_copy_overwrite_in,
		.cow_unreferenced = successful_vm_remap_copy_overwrite_in,
		.cow_nocow = successful_vm_remap_copy_overwrite_in,
		.nocow_cow = successful_vm_remap_copy_overwrite_in,
		.cow_unreadable = successful_vm_remap_copy_overwrite_in,
		.cow_unwriteable = successful_vm_remap_copy_overwrite_in,

		.permanent_entry = is_new_vm() ? test_permanent_entry_copy_overwrite_in_rangelocked : test_permanent_entry_copy_overwrite_in,
		.permanent_before_permanent = is_new_vm() ? test_permanent_entry_copy_overwrite_in_rangelocked : test_permanent_before_permanent_copy_overwrite_in,
		.permanent_before_allocation = is_new_vm() ? test_permanent_entry_copy_overwrite_in_rangelocked : test_permanent_before_allocation_copy_overwrite_in,
		.permanent_before_allocation_2 = is_new_vm() ? test_permanent_entry_copy_overwrite_in_rangelocked : test_permanent_before_allocation_copy_overwrite_in_rdar144128567,
		.permanent_before_hole = is_new_vm() ? test_permanent_entry_copy_overwrite_in_rangelocked : test_permanent_before_hole_copy_overwrite_in,
		.permanent_after_allocation = is_new_vm() ? test_permanent_entry_copy_overwrite_in_rangelocked : test_permanent_after_allocation_copy_overwrite_in,
		.permanent_after_hole = is_new_vm() ? test_permanent_entry_copy_overwrite_in_rangelocked : test_permanent_after_hole_copy_overwrite_in,

		.single_submap_single_entry = successful_vm_remap_copy_overwrite_in,
		.single_submap_single_entry_first_pages = successful_vm_remap_copy_overwrite_in,
		.single_submap_single_entry_last_pages = successful_vm_remap_copy_overwrite_in,
		.single_submap_single_entry_middle_pages = successful_vm_remap_copy_overwrite_in,
		.single_submap_oversize_entry_at_start = successful_vm_remap_copy_overwrite_in,
		.single_submap_oversize_entry_at_end = successful_vm_remap_copy_overwrite_in,
		.single_submap_oversize_entry_at_both = successful_vm_remap_copy_overwrite_in,

		.submap_before_allocation = successful_vm_remap_copy_overwrite_in,
		.submap_after_allocation = successful_vm_remap_copy_overwrite_in,
		.submap_before_hole = successful_vm_remap_copy_overwrite_in,
		.submap_after_hole = successful_vm_remap_copy_overwrite_in,
		.submap_allocation_submap_one_entry = successful_vm_remap_copy_overwrite_in,
		.submap_allocation_submap_two_entries = successful_vm_remap_copy_overwrite_in,
		.submap_allocation_submap_three_entries = successful_vm_remap_copy_overwrite_in,

		.submap_before_allocation_ro = successful_vm_remap_copy_overwrite_in,
		.submap_after_allocation_ro = successful_vm_remap_copy_overwrite_in,
		.submap_before_hole_ro = successful_vm_remap_copy_overwrite_in,
		.submap_after_hole_ro = successful_vm_remap_copy_overwrite_in,
		.submap_allocation_submap_one_entry_ro = successful_vm_remap_copy_overwrite_in,
		.submap_allocation_submap_two_entries_ro = successful_vm_remap_copy_overwrite_in,
		.submap_allocation_submap_three_entries_ro = successful_vm_remap_copy_overwrite_in,

		.protection_single_000_000 = successful_vm_remap_copy_overwrite_in,
		.protection_single_000_r00 = successful_vm_remap_copy_overwrite_in,
		.protection_single_000_0w0 = successful_vm_remap_copy_overwrite_in,
		.protection_single_000_rw0 = successful_vm_remap_copy_overwrite_in,
		.protection_single_r00_r00 = successful_vm_remap_copy_overwrite_in,
		.protection_single_r00_rw0 = successful_vm_remap_copy_overwrite_in,
		.protection_single_0w0_0w0 = successful_vm_remap_copy_overwrite_in,
		.protection_single_0w0_rw0 = successful_vm_remap_copy_overwrite_in,
		.protection_single_rw0_rw0 = successful_vm_remap_copy_overwrite_in,

		.protection_pairs_000_000 = successful_vm_remap_copy_overwrite_in,
		.protection_pairs_000_r00 = successful_vm_remap_copy_overwrite_in,
		.protection_pairs_000_0w0 = successful_vm_remap_copy_overwrite_in,
		.protection_pairs_000_rw0 = successful_vm_remap_copy_overwrite_in,
		.protection_pairs_r00_000 = successful_vm_remap_copy_overwrite_in,
		.protection_pairs_r00_r00 = successful_vm_remap_copy_overwrite_in,
		.protection_pairs_r00_0w0 = successful_vm_remap_copy_overwrite_in,
		.protection_pairs_r00_rw0 = successful_vm_remap_copy_overwrite_in,
		.protection_pairs_0w0_000 = successful_vm_remap_copy_overwrite_in,
		.protection_pairs_0w0_r00 = successful_vm_remap_copy_overwrite_in,
		.protection_pairs_0w0_0w0 = successful_vm_remap_copy_overwrite_in,
		.protection_pairs_0w0_rw0 = successful_vm_remap_copy_overwrite_in,
		.protection_pairs_rw0_000 = successful_vm_remap_copy_overwrite_in,
		.protection_pairs_rw0_r00 = successful_vm_remap_copy_overwrite_in,
		.protection_pairs_rw0_0w0 = successful_vm_remap_copy_overwrite_in,
		.protection_pairs_rw0_rw0 = successful_vm_remap_copy_overwrite_in,
	};

	run_vm_tests("vm_remap_copy_overwrite_in", __FILE__, &tests, argc, argv);
}

/*
 * vm_remap source is an anonymous buffer
 * vm_remap destination is the prepared VM state
 * vm_remap flags = fixed | overwrite, copy = false (i.e. share)
 */
T_DECL(vm_remap_share_overwrite_in,
    "run vm_remap(FIXED | OVERWRITE, !copy) to write over various vm configurations")
{
#if workaround_rdar_143341561
	enable_non_fatal_vm_exc_guard();
#endif

	vm_tests_t tests = {
		.single_entry_1 = successful_vm_remap_share_overwrite_in,
		.single_entry_2 = successful_vm_remap_share_overwrite_in,
		.single_entry_3 = successful_vm_remap_share_overwrite_in,
		.single_entry_4 = successful_vm_remap_share_overwrite_in,

		.single_entry_nonnull_1 = successful_vm_remap_share_overwrite_in,
		.single_entry_nonnull_2 = successful_vm_remap_share_overwrite_in,
		.single_entry_nonnull_3 = successful_vm_remap_share_overwrite_in,
		.single_entry_nonnull_4 = successful_vm_remap_share_overwrite_in,

		.multiple_entries_1 = successful_vm_remap_share_overwrite_in,
		.multiple_entries_2 = successful_vm_remap_share_overwrite_in,
		.multiple_entries_3 = successful_vm_remap_share_overwrite_in,
		.multiple_entries_4 = successful_vm_remap_share_overwrite_in,
		.multiple_entries_5 = successful_vm_remap_share_overwrite_in,
		.multiple_entries_6 = successful_vm_remap_share_overwrite_in,

		.some_holes_1 = successful_vm_remap_share_overwrite_in,
		.some_holes_2 = successful_vm_remap_share_overwrite_in,
		.some_holes_3 = successful_vm_remap_share_overwrite_in,
		.some_holes_4 = successful_vm_remap_share_overwrite_in,
		.some_holes_5 = successful_vm_remap_share_overwrite_in,
		.some_holes_6 = successful_vm_remap_share_overwrite_in,
		.some_holes_7 = successful_vm_remap_share_overwrite_in,
		.some_holes_8 = successful_vm_remap_share_overwrite_in,
		.some_holes_9 = successful_vm_remap_share_overwrite_in,
		.some_holes_10 = successful_vm_remap_share_overwrite_in,
		.some_holes_11 = successful_vm_remap_share_overwrite_in,
		.some_holes_12 = successful_vm_remap_share_overwrite_in,

		.all_holes_1 = successful_vm_remap_share_overwrite_in,
		.all_holes_2 = successful_vm_remap_share_overwrite_in,
		.all_holes_3 = successful_vm_remap_share_overwrite_in,
		.all_holes_4 = successful_vm_remap_share_overwrite_in,

		.null_entry = successful_vm_remap_share_overwrite_in,
		.nonresident_entry = successful_vm_remap_share_overwrite_in,
		.resident_entry = successful_vm_remap_share_overwrite_in,

		.shared_entry = successful_vm_remap_share_overwrite_in,
		.shared_entry_discontiguous = successful_vm_remap_share_overwrite_in,
		.shared_entry_partial = successful_vm_remap_share_overwrite_in,
		.shared_entry_pairs = successful_vm_remap_share_overwrite_in,
		.shared_entry_x1000 = successful_vm_remap_share_overwrite_in,

		.cow_entry = successful_vm_remap_share_overwrite_in,
		.cow_unreferenced = successful_vm_remap_share_overwrite_in,
		.cow_nocow = successful_vm_remap_share_overwrite_in,
		.nocow_cow = successful_vm_remap_share_overwrite_in,
		.cow_unreadable = successful_vm_remap_share_overwrite_in,
		.cow_unwriteable = successful_vm_remap_share_overwrite_in,

		.permanent_entry = is_new_vm() ? test_permanent_entry_share_overwrite_in_rangelocked : test_permanent_entry_share_overwrite_in,
		.permanent_before_permanent = is_new_vm() ? test_permanent_entry_share_overwrite_in_rangelocked : test_permanent_before_permanent_share_overwrite_in,
		.permanent_before_allocation = is_new_vm() ? test_permanent_entry_share_overwrite_in_rangelocked : test_permanent_before_allocation_share_overwrite_in,
		.permanent_before_allocation_2 = is_new_vm() ? test_permanent_entry_share_overwrite_in_rangelocked : test_permanent_before_allocation_share_overwrite_in_rdar144128567,
		.permanent_before_hole = is_new_vm() ? test_permanent_entry_share_overwrite_in_rangelocked : test_permanent_before_hole_share_overwrite_in,
		.permanent_after_allocation = is_new_vm() ? test_permanent_entry_share_overwrite_in_rangelocked : test_permanent_after_allocation_share_overwrite_in,
		.permanent_after_hole = is_new_vm() ? test_permanent_entry_share_overwrite_in_rangelocked : test_permanent_after_hole_share_overwrite_in,

		.single_submap_single_entry = successful_vm_remap_share_overwrite_in,
		.single_submap_single_entry_first_pages = successful_vm_remap_share_overwrite_in,
		.single_submap_single_entry_last_pages = successful_vm_remap_share_overwrite_in,
		.single_submap_single_entry_middle_pages = successful_vm_remap_share_overwrite_in,
		.single_submap_oversize_entry_at_start = successful_vm_remap_share_overwrite_in,
		.single_submap_oversize_entry_at_end = successful_vm_remap_share_overwrite_in,
		.single_submap_oversize_entry_at_both = successful_vm_remap_share_overwrite_in,

		.submap_before_allocation = successful_vm_remap_share_overwrite_in,
		.submap_after_allocation = successful_vm_remap_share_overwrite_in,
		.submap_before_hole = successful_vm_remap_share_overwrite_in,
		.submap_after_hole = successful_vm_remap_share_overwrite_in,
		.submap_allocation_submap_one_entry = successful_vm_remap_share_overwrite_in,
		.submap_allocation_submap_two_entries = successful_vm_remap_share_overwrite_in,
		.submap_allocation_submap_three_entries = successful_vm_remap_share_overwrite_in,

		.submap_before_allocation_ro = successful_vm_remap_share_overwrite_in,
		.submap_after_allocation_ro = successful_vm_remap_share_overwrite_in,
		.submap_before_hole_ro = successful_vm_remap_share_overwrite_in,
		.submap_after_hole_ro = successful_vm_remap_share_overwrite_in,
		.submap_allocation_submap_one_entry_ro = successful_vm_remap_share_overwrite_in,
		.submap_allocation_submap_two_entries_ro = successful_vm_remap_share_overwrite_in,
		.submap_allocation_submap_three_entries_ro = successful_vm_remap_share_overwrite_in,

		.protection_single_000_000 = successful_vm_remap_share_overwrite_in,
		.protection_single_000_r00 = successful_vm_remap_share_overwrite_in,
		.protection_single_000_0w0 = successful_vm_remap_share_overwrite_in,
		.protection_single_000_rw0 = successful_vm_remap_share_overwrite_in,
		.protection_single_r00_r00 = successful_vm_remap_share_overwrite_in,
		.protection_single_r00_rw0 = successful_vm_remap_share_overwrite_in,
		.protection_single_0w0_0w0 = successful_vm_remap_share_overwrite_in,
		.protection_single_0w0_rw0 = successful_vm_remap_share_overwrite_in,
		.protection_single_rw0_rw0 = successful_vm_remap_share_overwrite_in,

		.protection_pairs_000_000 = successful_vm_remap_share_overwrite_in,
		.protection_pairs_000_r00 = successful_vm_remap_share_overwrite_in,
		.protection_pairs_000_0w0 = successful_vm_remap_share_overwrite_in,
		.protection_pairs_000_rw0 = successful_vm_remap_share_overwrite_in,
		.protection_pairs_r00_000 = successful_vm_remap_share_overwrite_in,
		.protection_pairs_r00_r00 = successful_vm_remap_share_overwrite_in,
		.protection_pairs_r00_0w0 = successful_vm_remap_share_overwrite_in,
		.protection_pairs_r00_rw0 = successful_vm_remap_share_overwrite_in,
		.protection_pairs_0w0_000 = successful_vm_remap_share_overwrite_in,
		.protection_pairs_0w0_r00 = successful_vm_remap_share_overwrite_in,
		.protection_pairs_0w0_0w0 = successful_vm_remap_share_overwrite_in,
		.protection_pairs_0w0_rw0 = successful_vm_remap_share_overwrite_in,
		.protection_pairs_rw0_000 = successful_vm_remap_share_overwrite_in,
		.protection_pairs_rw0_r00 = successful_vm_remap_share_overwrite_in,
		.protection_pairs_rw0_0w0 = successful_vm_remap_share_overwrite_in,
		.protection_pairs_rw0_rw0 = successful_vm_remap_share_overwrite_in,
	};

	run_vm_tests("vm_remap_share_overwrite_in", __FILE__, &tests, argc, argv);
}

/*
 * vm_remap sources is the prepared VM state
 * vm_remap destination is an anonymous buffer
 * vm_remap flags = fixed | overwrite, copy = true
 */
T_DECL(vm_remap_copy_overwrite_out,
    "run vm_remap(FIXED | OVERWRITE, copy) to remap from various vm configurations")
{
#if workaround_rdar_143341561
	enable_non_fatal_vm_exc_guard();
#endif

	vm_tests_t tests = {
		.single_entry_1 = successful_vm_remap_copy_overwrite_out,
		.single_entry_2 = successful_vm_remap_copy_overwrite_out,
		.single_entry_3 = successful_vm_remap_copy_overwrite_out,
		.single_entry_4 = successful_vm_remap_copy_overwrite_out,

		.single_entry_nonnull_1 = successful_vm_remap_copy_overwrite_out,
		.single_entry_nonnull_2 = successful_vm_remap_copy_overwrite_out,
		.single_entry_nonnull_3 = successful_vm_remap_copy_overwrite_out,
		.single_entry_nonnull_4 = successful_vm_remap_copy_overwrite_out,

		.multiple_entries_1 = successful_vm_remap_copy_overwrite_out,
		.multiple_entries_2 = successful_vm_remap_copy_overwrite_out,
		.multiple_entries_3 = successful_vm_remap_copy_overwrite_out,
		.multiple_entries_4 = successful_vm_remap_copy_overwrite_out,
		.multiple_entries_5 = successful_vm_remap_copy_overwrite_out,
		.multiple_entries_6 = successful_vm_remap_copy_overwrite_out,

		.some_holes_1 = test_remap_copy_overwrite_out_with_holes,
		.some_holes_2 = test_remap_copy_overwrite_out_with_holes,
		.some_holes_3 = test_remap_copy_overwrite_out_with_holes,
		.some_holes_4 = test_remap_copy_overwrite_out_with_holes,
		.some_holes_5 = test_remap_copy_overwrite_out_with_holes,
		.some_holes_6 = test_remap_copy_overwrite_out_with_holes,
		.some_holes_7 = test_remap_copy_overwrite_out_with_holes,
		.some_holes_8 = test_remap_copy_overwrite_out_with_holes,
		.some_holes_9 = test_remap_copy_overwrite_out_with_holes,
		.some_holes_10 = test_remap_copy_overwrite_out_with_holes,
		.some_holes_11 = test_remap_copy_overwrite_out_with_holes,
		.some_holes_12 = test_remap_copy_overwrite_out_with_holes,

		.all_holes_1 = test_remap_copy_overwrite_out_with_holes,
		.all_holes_2 = test_remap_copy_overwrite_out_with_holes,
		.all_holes_3 = test_remap_copy_overwrite_out_with_holes,
		.all_holes_4 = test_remap_copy_overwrite_out_with_holes,

		.null_entry = successful_vm_remap_copy_overwrite_out,
		.nonresident_entry = successful_vm_remap_copy_overwrite_out,
		.resident_entry = successful_vm_remap_copy_overwrite_out,

		.shared_entry = successful_vm_remap_copy_overwrite_out,
		.shared_entry_discontiguous = successful_vm_remap_copy_overwrite_out_no_verify_writes,
		.shared_entry_partial = successful_vm_remap_copy_overwrite_out_no_verify_writes,
		.shared_entry_pairs = successful_vm_remap_copy_overwrite_out,
		.shared_entry_x1000 = successful_vm_remap_copy_overwrite_out,

		.cow_entry = successful_vm_remap_copy_overwrite_out,
		.cow_unreferenced = successful_vm_remap_copy_overwrite_out,
		.cow_nocow = successful_vm_remap_copy_overwrite_out,
		.nocow_cow = successful_vm_remap_copy_overwrite_out,
		.cow_unreadable = successful_vm_remap_copy_overwrite_out,
		.cow_unwriteable = successful_vm_remap_copy_overwrite_out,

		.permanent_entry = successful_vm_remap_copy_overwrite_out,
		.permanent_before_permanent = successful_vm_remap_copy_overwrite_out,
		.permanent_before_allocation = successful_vm_remap_copy_overwrite_out,
		.permanent_before_allocation_2 = successful_vm_remap_copy_overwrite_out,
		.permanent_before_hole = test_remap_copy_overwrite_out_with_holes,
		.permanent_after_allocation = successful_vm_remap_copy_overwrite_out,
		.permanent_after_hole = test_remap_copy_overwrite_out_with_holes,

		.single_submap_single_entry = successful_vm_remap_copy_overwrite_out,
		.single_submap_single_entry_first_pages = successful_vm_remap_copy_overwrite_out,
		.single_submap_single_entry_last_pages = successful_vm_remap_copy_overwrite_out,
		.single_submap_single_entry_middle_pages = successful_vm_remap_copy_overwrite_out,
		.single_submap_oversize_entry_at_start = successful_vm_remap_copy_overwrite_out,
		.single_submap_oversize_entry_at_end = successful_vm_remap_copy_overwrite_out,
		.single_submap_oversize_entry_at_both = successful_vm_remap_copy_overwrite_out,

		.submap_before_allocation = successful_vm_remap_copy_overwrite_out,
		.submap_after_allocation = successful_vm_remap_copy_overwrite_out,
		.submap_before_hole = test_remap_copy_overwrite_out_with_holes,
		.submap_after_hole = test_remap_copy_overwrite_out_with_holes,
		.submap_allocation_submap_one_entry = successful_vm_remap_copy_overwrite_out,
		.submap_allocation_submap_two_entries = successful_vm_remap_copy_overwrite_out,
		.submap_allocation_submap_three_entries = successful_vm_remap_copy_overwrite_out,

		.submap_before_allocation_ro = successful_vm_remap_copy_overwrite_out,
		.submap_after_allocation_ro = successful_vm_remap_copy_overwrite_out,
		.submap_before_hole_ro = test_remap_copy_overwrite_out_with_holes,
		.submap_after_hole_ro = test_remap_copy_overwrite_out_with_holes,
		.submap_allocation_submap_one_entry_ro = successful_vm_remap_copy_overwrite_out,
		.submap_allocation_submap_two_entries_ro = successful_vm_remap_copy_overwrite_out,
		.submap_allocation_submap_three_entries_ro = successful_vm_remap_copy_overwrite_out,

		.protection_single_000_000 = successful_vm_remap_copy_overwrite_out,
		.protection_single_000_r00 = successful_vm_remap_copy_overwrite_out,
		.protection_single_000_0w0 = successful_vm_remap_copy_overwrite_out,
		.protection_single_000_rw0 = successful_vm_remap_copy_overwrite_out,
		.protection_single_r00_r00 = successful_vm_remap_copy_overwrite_out,
		.protection_single_r00_rw0 = successful_vm_remap_copy_overwrite_out,
		.protection_single_0w0_0w0 = successful_vm_remap_copy_overwrite_out,
		.protection_single_0w0_rw0 = successful_vm_remap_copy_overwrite_out,
		.protection_single_rw0_rw0 = successful_vm_remap_copy_overwrite_out,

		.protection_pairs_000_000 = successful_vm_remap_copy_overwrite_out,
		.protection_pairs_000_r00 = successful_vm_remap_copy_overwrite_out,
		.protection_pairs_000_0w0 = successful_vm_remap_copy_overwrite_out,
		.protection_pairs_000_rw0 = successful_vm_remap_copy_overwrite_out,
		.protection_pairs_r00_000 = successful_vm_remap_copy_overwrite_out,
		.protection_pairs_r00_r00 = successful_vm_remap_copy_overwrite_out,
		.protection_pairs_r00_0w0 = successful_vm_remap_copy_overwrite_out,
		.protection_pairs_r00_rw0 = successful_vm_remap_copy_overwrite_out,
		.protection_pairs_0w0_000 = successful_vm_remap_copy_overwrite_out,
		.protection_pairs_0w0_r00 = successful_vm_remap_copy_overwrite_out,
		.protection_pairs_0w0_0w0 = successful_vm_remap_copy_overwrite_out,
		.protection_pairs_0w0_rw0 = successful_vm_remap_copy_overwrite_out,
		.protection_pairs_rw0_000 = successful_vm_remap_copy_overwrite_out,
		.protection_pairs_rw0_r00 = successful_vm_remap_copy_overwrite_out,
		.protection_pairs_rw0_0w0 = successful_vm_remap_copy_overwrite_out,
		.protection_pairs_rw0_rw0 = successful_vm_remap_copy_overwrite_out,
	};

	run_vm_tests("vm_remap_copy_overwrite_out", __FILE__, &tests, argc, argv);
}

/*
 * vm_remap source is the prepared VM state
 * vm_remap destination is an anonymous buffer
 * vm_remap flags = fixed | overwrite, copy = false (i.e. share)
 */
T_DECL(vm_remap_share_overwrite_out,
    "run vm_remap(FIXED | OVERWRITE, !copy) to remap from various vm configurations")
{
#if workaround_rdar_143341561
	enable_non_fatal_vm_exc_guard();
#endif

	vm_tests_t tests = {
		.single_entry_1 = successful_vm_remap_share_overwrite_out,
		.single_entry_2 = successful_vm_remap_share_overwrite_out,
		.single_entry_3 = successful_vm_remap_share_overwrite_out,
		.single_entry_4 = successful_vm_remap_share_overwrite_out,

		.single_entry_nonnull_1 = successful_vm_remap_share_overwrite_out,
		.single_entry_nonnull_2 = successful_vm_remap_share_overwrite_out,
		.single_entry_nonnull_3 = successful_vm_remap_share_overwrite_out,
		.single_entry_nonnull_4 = successful_vm_remap_share_overwrite_out,

		.multiple_entries_1 = successful_vm_remap_share_overwrite_out,
		.multiple_entries_2 = successful_vm_remap_share_overwrite_out,
		.multiple_entries_3 = successful_vm_remap_share_overwrite_out,
		.multiple_entries_4 = successful_vm_remap_share_overwrite_out,
		.multiple_entries_5 = successful_vm_remap_share_overwrite_out,
		.multiple_entries_6 = successful_vm_remap_share_overwrite_out,

		.some_holes_1 = test_remap_share_overwrite_out_with_holes,
		.some_holes_2 = test_remap_share_overwrite_out_with_holes,
		.some_holes_3 = test_remap_share_overwrite_out_with_holes,
		.some_holes_4 = test_remap_share_overwrite_out_with_holes,
		.some_holes_5 = test_remap_share_overwrite_out_with_holes,
		.some_holes_6 = test_remap_share_overwrite_out_with_holes,
		.some_holes_7 = test_remap_share_overwrite_out_with_holes,
		.some_holes_8 = test_remap_share_overwrite_out_with_holes,
		.some_holes_9 = test_remap_share_overwrite_out_with_holes,
		.some_holes_10 = test_remap_share_overwrite_out_with_holes,
		.some_holes_11 = test_remap_share_overwrite_out_with_holes,
		.some_holes_12 = test_remap_share_overwrite_out_with_holes,

		.all_holes_1 = test_remap_share_overwrite_out_with_holes,
		.all_holes_2 = test_remap_share_overwrite_out_with_holes,
		.all_holes_3 = test_remap_share_overwrite_out_with_holes,
		.all_holes_4 = test_remap_share_overwrite_out_with_holes,

		.null_entry = successful_vm_remap_share_overwrite_out,
		.nonresident_entry = successful_vm_remap_share_overwrite_out,
		.resident_entry = successful_vm_remap_share_overwrite_out,

		.shared_entry = successful_vm_remap_share_overwrite_out,
		.shared_entry_discontiguous = successful_vm_remap_share_overwrite_out_no_verify_writes,
		.shared_entry_partial = successful_vm_remap_share_overwrite_out_no_verify_writes,
		.shared_entry_pairs = successful_vm_remap_share_overwrite_out,
		.shared_entry_x1000 = successful_vm_remap_share_overwrite_out,

		.cow_entry = successful_vm_remap_share_overwrite_out,
		.cow_unreferenced = successful_vm_remap_share_overwrite_out,
		.cow_nocow = successful_vm_remap_share_overwrite_out,
		.nocow_cow = successful_vm_remap_share_overwrite_out,
		.cow_unreadable = successful_vm_remap_share_overwrite_out,
		.cow_unwriteable = successful_vm_remap_share_overwrite_out,

		.permanent_entry = successful_vm_remap_share_overwrite_out,
		.permanent_before_permanent = successful_vm_remap_share_overwrite_out,
		.permanent_before_allocation = successful_vm_remap_share_overwrite_out,
		.permanent_before_allocation_2 = successful_vm_remap_share_overwrite_out,
		.permanent_before_hole = test_remap_share_overwrite_out_with_holes,
		.permanent_after_allocation = successful_vm_remap_share_overwrite_out,
		.permanent_after_hole = test_remap_share_overwrite_out_with_holes,

		.single_submap_single_entry = successful_vm_remap_share_overwrite_out,
		.single_submap_single_entry_first_pages = successful_vm_remap_share_overwrite_out,
		.single_submap_single_entry_last_pages = successful_vm_remap_share_overwrite_out,
		.single_submap_single_entry_middle_pages = successful_vm_remap_share_overwrite_out,
		.single_submap_oversize_entry_at_start = successful_vm_remap_share_overwrite_out,
		.single_submap_oversize_entry_at_end = successful_vm_remap_share_overwrite_out,
		.single_submap_oversize_entry_at_both = successful_vm_remap_share_overwrite_out,

		.submap_before_allocation = successful_vm_remap_share_overwrite_out,
		.submap_after_allocation = successful_vm_remap_share_overwrite_out,
		.submap_before_hole = test_remap_share_overwrite_out_with_holes,
		.submap_after_hole = test_remap_share_overwrite_out_with_holes,
		.submap_allocation_submap_one_entry = successful_vm_remap_share_overwrite_out,
		.submap_allocation_submap_two_entries = successful_vm_remap_share_overwrite_out,
		.submap_allocation_submap_three_entries = successful_vm_remap_share_overwrite_out,

		.submap_before_allocation_ro = successful_vm_remap_share_overwrite_out,
		.submap_after_allocation_ro = successful_vm_remap_share_overwrite_out,
		.submap_before_hole_ro = test_remap_share_overwrite_out_with_holes,
		.submap_after_hole_ro = test_remap_share_overwrite_out_with_holes,
		.submap_allocation_submap_one_entry_ro = successful_vm_remap_share_overwrite_out,
		.submap_allocation_submap_two_entries_ro = successful_vm_remap_share_overwrite_out,
		.submap_allocation_submap_three_entries_ro = successful_vm_remap_share_overwrite_out,

		.protection_single_000_000 = successful_vm_remap_share_overwrite_out,
		.protection_single_000_r00 = successful_vm_remap_share_overwrite_out,
		.protection_single_000_0w0 = successful_vm_remap_share_overwrite_out,
		.protection_single_000_rw0 = successful_vm_remap_share_overwrite_out,
		.protection_single_r00_r00 = successful_vm_remap_share_overwrite_out,
		.protection_single_r00_rw0 = successful_vm_remap_share_overwrite_out,
		.protection_single_0w0_0w0 = successful_vm_remap_share_overwrite_out,
		.protection_single_0w0_rw0 = successful_vm_remap_share_overwrite_out,
		.protection_single_rw0_rw0 = successful_vm_remap_share_overwrite_out,

		.protection_pairs_000_000 = successful_vm_remap_share_overwrite_out,
		.protection_pairs_000_r00 = successful_vm_remap_share_overwrite_out,
		.protection_pairs_000_0w0 = successful_vm_remap_share_overwrite_out,
		.protection_pairs_000_rw0 = successful_vm_remap_share_overwrite_out,
		.protection_pairs_r00_000 = successful_vm_remap_share_overwrite_out,
		.protection_pairs_r00_r00 = successful_vm_remap_share_overwrite_out,
		.protection_pairs_r00_0w0 = successful_vm_remap_share_overwrite_out,
		.protection_pairs_r00_rw0 = successful_vm_remap_share_overwrite_out,
		.protection_pairs_0w0_000 = successful_vm_remap_share_overwrite_out,
		.protection_pairs_0w0_r00 = successful_vm_remap_share_overwrite_out,
		.protection_pairs_0w0_0w0 = successful_vm_remap_share_overwrite_out,
		.protection_pairs_0w0_rw0 = successful_vm_remap_share_overwrite_out,
		.protection_pairs_rw0_000 = successful_vm_remap_share_overwrite_out,
		.protection_pairs_rw0_r00 = successful_vm_remap_share_overwrite_out,
		.protection_pairs_rw0_0w0 = successful_vm_remap_share_overwrite_out,
		.protection_pairs_rw0_rw0 = successful_vm_remap_share_overwrite_out,
	};

	run_vm_tests("vm_remap_share_overwrite_out", __FILE__, &tests, argc, argv);
}
