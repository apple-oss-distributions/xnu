/*
 * Copyright (c) 2024 Apple Inc. All rights reserved.
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
 * vm_configurator_helpers.h
 *
 * Assorted functions used by multiple vm_configurator tests.
 */

#ifndef VM_CONFIGURATOR_HELPERS_H
#define VM_CONFIGURATOR_HELPERS_H

#include "vm_configurator.h"

/*
 * rdar://143341561 FIXED | OVERWRITE sometimes provokes EXC_GUARD
 * Remove this when that bug is fixed.
 *
 * normal workaround: run the function with the EXC_GUARD catcher in place
 *     when the test is expected to hit rdar://143341561
 * Rosetta workaround: EXC_GUARD catcher doesn't work on Rosetta, so don't run
 *     vm_allocate when the test is expected to hit rdar://143341561
 */
#define workaround_rdar_143341561 1

/*
 * Return true if flags has VM_FLAGS_FIXED
 * This is non-trivial because VM_FLAGS_FIXED is zero;
 * the real value is the absence of VM_FLAGS_ANYWHERE.
 */
static inline bool
is_fixed(int flags)
{
	static_assert(VM_FLAGS_FIXED == 0, "this test requires VM_FLAGS_FIXED be zero");
	static_assert(VM_FLAGS_ANYWHERE != 0, "this test requires VM_FLAGS_ANYWHERE be nonzero");
	return !(flags & VM_FLAGS_ANYWHERE);
}

/* Return true if flags has VM_FLAGS_FIXED and VM_FLAGS_OVERWRITE set. */
static inline bool
is_fixed_overwrite(int flags)
{
	return is_fixed(flags) && (flags & VM_FLAGS_OVERWRITE);
}

/*
 * Overwrite of permanent entries provokes a different error
 * with the range locking VM versus the previous VM.
 */
static inline kern_return_t
overwrite_permanent_error(void)
{
	return is_new_vm() ? KERN_PROTECTION_FAILURE : KERN_NO_SPACE;
}

/*
 * Clear some bits from EXC_GUARD behavior, then set some bits.
 * Halt with T_FAIL if task_get/set_exc_guard_behavior() fails.
 */
static inline void
clear_then_set_exc_guard_behavior(
	task_exc_guard_behavior_t clear,
	task_exc_guard_behavior_t set)
{
	task_exc_guard_behavior_t behavior;
	kern_return_t kr = task_get_exc_guard_behavior(mach_task_self(), &behavior);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "get EXC_GUARD behavior");

	behavior &= ~clear;
	behavior |= set;

	kr = task_set_exc_guard_behavior(mach_task_self(), behavior);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "update EXC_GUARD behavior");
}

/*
 * Disable VM EXC_GUARD exceptions.
 * Halt with T_FAIL if they cannot be disabled.
 */
static inline void
disable_vm_exc_guard(void)
{
	clear_then_set_exc_guard_behavior(
		TASK_EXC_GUARD_VM_ALL,  /* clear */
		0 /* set */);
}

/*
 * Enable VM EXC_GUARD fatal exceptions.
 * Halt with T_FAIL if they cannot be enabled.
 */
static inline void
enable_fatal_vm_exc_guard(void)
{
	clear_then_set_exc_guard_behavior(
		TASK_EXC_GUARD_VM_ALL,  /* clear */
		TASK_EXC_GUARD_VM_DELIVER | TASK_EXC_GUARD_VM_FATAL /* set */);
}

/*
 * Enable VM EXC_GUARD non-fatal exceptions.
 * Halt with T_FAIL if they cannot be enabled.
 */
static inline void
enable_non_fatal_vm_exc_guard(void)
{
	clear_then_set_exc_guard_behavior(
		TASK_EXC_GUARD_VM_ALL,  /* clear */
		TASK_EXC_GUARD_VM_DELIVER /* set */);
}

/*
 * Update the checker list after a successful call to vm_deallocate()
 * of any number of ordinary allocations and holes.
 * Don't use this if anything may be permanent entries.
 */
static inline void
checker_perform_successful_vm_deallocate(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	/* this may create adjacent hole checkers, but we don't care */
	entry_checker_range_t limit =
	    checker_list_find_and_clip_including_holes(checker_list, start, size);
	checker_list_free_range(checker_list, limit);
}

/*
 * Update the checker list after a successful call to vm_allocate()
 * of a permanent entry, which makes the memory inaccessible.
 * On entry, the range must be a single checker for a permanent allocation.
 */
static inline void
checker_perform_vm_deallocate_permanent(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	/* Find the checker and verify its address range and permanence. */
	vm_entry_checker_t *checker =
	    checker_list_find_allocation(checker_list, start);
	assert(checker);
	assert(checker->address == start);
	assert(checker->size == size);
	assert(checker->permanent == true);

	/* Mark the memory as inaccessible. */
	checker->protection = VM_PROT_NONE;
	checker->max_protection = VM_PROT_NONE;
}

#endif  /* VM_CONFIGURATOR_HELPERS_H */
