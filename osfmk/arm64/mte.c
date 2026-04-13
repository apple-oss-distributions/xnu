/*
 * Copyright (c) 2024 Apple Computer, Inc. All rights reserved.
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
#include <pexpert/arm64/board_config.h>

/*
 * MTE implements the memtag interface that also KASAN-TBI uses. This file
 * leverages the APIs provided by mte.h to implement memtag interfaces.
 *
 * On top of memtag interfaces a few dedicated helpers for kernel specific
 * MTE consumers (e.g. memory compressor) are implemented here.
 */

#if HAS_MTE

#include <mach/arm/thread_status.h>
#include <mach/machine/vm_types.h>
#include <kern/kern_types.h>
#include <kern/thread.h>
#include <kern/exc_guard.h>

#include <vm/vm_kern.h>
#include <vm/vm_page.h>
#include <vm/vm_memtag.h>
#include <vm/vm_map_xnu.h>
#include <vm/vm_map_lock_internal.h>
#include <vm/pmap.h>

#include <sys/reason.h>

#include <arm64/mte.h>
#include <arm64/mte_xnu.h>

#if DEVELOPMENT || DEBUG
/*
 * PSTATE.TCO sounds mellow, but can be evil. Tag Check Override is meant to be
 * a way to briefly disable tag checking during a trusted path. It must not extend
 * past the path, into unexpected callee/callers. For this reason, we should not incentivize
 * its use. This function adds some enforcing that TCO is at the state we expect
 * whenever we try to manipulate it. We intentionally do not implement any form of
 * save and restore of its state. We don't enable this on release as reading TCO is
 * a slow operation and would impact performance.
 */
void
mte_validate_tco_state(void)
{
	if (!mte_debug_tco_state()) {
		return;
	}

	uint64_t tco_state = 0;

	__asm__ __volatile__ ("mrs %0, TCO" : "=r" (tco_state) ::);

	if (tco_state != 0) {
		panic("[ERROR] Unexpected non-zero PSTATE.TCO state entering a manipulation function");
	}
}
#endif /* DEVELOPMENT || DEBUG */

__attribute__((noinline))
void
mte_report_non_canonical_address(__unused caddr_t address, __unused vm_map_t map, __unused const char *location)
{
#if DEVELOPMENT || DEBUG
	if (mte_panic_on_non_canonical()) {
		panic("MTE: detected canonical address (%p), map(%p) in function %s\n",
		    address, map, location);
	}
#endif /* DEVELOPMENT || DEBUG */
}


/*
 * Generate an exclude mask out of a best effort to hold
 * MTE linear overflow detection guarantees. We don't know anything
 * about the memory layout and organization of who's calling here,
 * so we can just make assumptions on neighbours.
 */
static mte_exclude_mask_t
mte_generate_default_exclude_mask(caddr_t target, size_t size)
{
	mte_exclude_mask_t mask = 0;
	/* Exclude the current pointer from the selection mask */
	mask = mte_update_exclude_mask(target, mask);

	/* kernel canonical tag is covered by GCR_EL1, but doesn't hurt to add it here. */
	mask = mte_update_exclude_mask((caddr_t)-1ULL, mask);

#define mte_page_align(x)   ((uintptr_t)(x) & -(PAGE_SIZE))

	/* Best effort to incorporate boundary objects tags. */
	if (mte_page_align(target) == mte_page_align(target - 16)) {
		mask = mte_update_exclude_mask(mte_load_tag(target - 16), mask);
	}

	if (mte_page_align(target + size - 1) == mte_page_align(target + size)) {
		mask = mte_update_exclude_mask(mte_load_tag(target + size), mask);
	}

	return mask;
}

/*
 * Generate a random tag out of either a default exclude mask or a caller provided
 * exclude mask.
 */
__attribute__((overloadable))
caddr_t
mte_generate_and_store_tag(caddr_t target, size_t size)
{
	mte_exclude_mask_t mask = mte_generate_default_exclude_mask(target, size);

	return mte_generate_and_store_tag(target, size, mask);
}

__attribute__((overloadable))
caddr_t
mte_generate_and_store_tag(caddr_t target, size_t size, mte_exclude_mask_t mask)
{
	target = mte_generate_random_tag(target, mask);
	mte_store_tag(target, size);


	return target;
}

void
mte_bulk_read_tags(caddr_t va, size_t va_size, mte_bulk_taglist_t * buffer, size_t buf_size)
{
	assert((uintptr_t)va % 256 == 0);
	assert((va_size / 256) == (buf_size / sizeof(mte_bulk_taglist_t)));

	if ((va_size / 256) != (buf_size / sizeof(mte_bulk_taglist_t))) {
		panic("Buffer size doesn't match MTE bulk size request\n");
	}

	size_t buf_count = buf_size / sizeof(mte_bulk_taglist_t);

	for (size_t counter = 0; counter < buf_count; counter++, va += 256) {
		buffer[counter] = mte_load_tag_256(va);
	}
}

void
mte_bulk_write_tags(caddr_t va, size_t __unused va_size, mte_bulk_taglist_t * buffer, size_t buf_size)
{
	assert((uintptr_t)va % 256 == 0);
	assert((va_size / 256) == (buf_size / sizeof(mte_bulk_taglist_t)));

	if ((va_size / 256) != (buf_size / sizeof(mte_bulk_taglist_t))) {
		panic("Buffer size doesn't match MTE bulk size request\n");
	}

	size_t buf_count = buf_size / sizeof(mte_bulk_taglist_t);

	for (size_t counter = 0; counter < buf_count; counter++, va += 256) {
		mte_store_tag_256(va, buffer[counter]);
	}
}

void
mte_copy_tags(caddr_t dest, caddr_t source, vm_size_t size)
{
	for (vm_size_t i = 0; i < size; i += 256) {
		mte_bulk_taglist_t tags = mte_load_tag_256(source + i);
		mte_store_tag_256(dest + i, tags);
	}
}

/*
 * During initial adoption we want to detect MTE violations and just
 * fix and continue. This is achieved by clearing SCTLR_ELx.TCF0 for the
 * user thread.
 */
void
mte_disable_user_checking(task_t task)
{
	task_set_sec_never_check(task);
	vm_map_set_sec_disabled(get_task_map(task));
}

#if !KASAN
/* memtag APIs on KASAN are currently provided by KASAN-TBI also on Hidra. */

/*
 * MTE implements the vm_memtag interface.
 */
void
vm_memtag_bzero_fast_checked(void *tagged_buf, vm_size_t n)
{
	if (mte_kern_enabled()) {
		mte_bzero_fast_checked(tagged_buf, n);
	} else {
		bzero(tagged_buf, n);
	}
}

void
vm_memtag_bzero_unchecked(void *tagged_buf, vm_size_t n)
{
	if (mte_kern_enabled()) {
		mte_bzero_unchecked(tagged_buf, n);
	} else {
		bzero(tagged_buf, n);
	}
}

vm_map_address_t
vm_memtag_load_tag(vm_map_address_t naked_address)
{
	if (mte_enabled()) {
		return (vm_map_address_t)mte_load_tag((caddr_t)naked_address);
	} else {
		return naked_address;
	}
}

void
vm_memtag_store_tag(caddr_t tagged_address, vm_size_t size)
{
	if (mte_enabled()) {
		mte_store_tag(tagged_address, size);
	}
}

caddr_t
vm_memtag_generate_and_store_tag(caddr_t address, vm_size_t size)
{
	if (mte_kern_enabled()) {
		return mte_generate_and_store_tag(address, size);
	}

	return address;
}

void
vm_memtag_verify_tag(vm_map_address_t tagged_address)
{
	if (mte_enabled()) {
		asm volatile ("ldrb wzr, [%0]" : : "r"(tagged_address) : "memory");
	}
}

void
vm_memtag_relocate_tags(vm_address_t new_address, vm_address_t old_address, vm_size_t size)
{
	if (!mte_kern_enabled()) {
		return;
	}

	mte_copy_tags((caddr_t)new_address, (caddr_t)old_address, size);
}

void
vm_memtag_disable_checking()
{
	mte_disable_tag_checking();
}

__attribute__((always_inline))
void
vm_memtag_enable_checking()
{
	mte_enable_tag_checking();
}
#endif /* KASAN */
/*
 * MTE exceptions are always synchronous in hardware, but can be conceptually synchronous or asynchronous
 * in software. An asynchronous MTE software exception happens every time the kernel operates on behalf of
 * a user supplied pointer but not directly in the context of the user thread supplying it. We deliver
 * such asynchronous exceptions as GUARD_VM exception, although we'll transition to a dedicated exception
 * type with rdar://150503373 (MTE Exceptions should not overload VM_GUARD exceptions and instead have their own).
 *
 * Both synchronous and asynchronous exceptions can happen on a task that is running in soft-mode. In
 * this case, they are not fatal and a simulated crash is generated.
 */
void
mte_guard_ast(
	thread_t thread,
	mach_exception_data_type_t code,
	mach_exception_data_type_t subcode)
{
	task_t task = get_threadtask(thread);
	assert(task != kernel_task);

	/* Downstream code currently only supports operating on current task/thread/proc. */
	assert(task == current_task());
	assert(thread == current_thread());
	assert(vm_guard_is_mte_fault(EXC_GUARD_DECODE_GUARD_FLAVOR(code)));

	/* For soft-mode we always generate simulated crashes. */
	if (task_has_sec_soft_mode(task)) {
		/* Only softmode guards should be sent down here. */
		assert(EXC_GUARD_DECODE_GUARD_TARGET(code) & kGUARD_EXC_MTE_SOFT_MODE);
		task_violated_guard(code, subcode, NULL, FALSE);
		return;
	}

	/* Perform fatal exception logic. */
	exit_with_fatal_exception_and_notify(current_proc(), OS_REASON_GUARD,
	    EXC_GUARD, code, subcode, PX_FLAGS_NONE);
}


#endif /* HAS_MTE */
