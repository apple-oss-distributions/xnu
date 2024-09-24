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
 * vm_sanitize_error_compat.h
 * Error code rewriting functions to preserve historical error values.
 */

#include <vm/vm_map_xnu.h>
#include <vm/vm_sanitize_internal.h>

/* Don't use errno values in this file. Everything here should be kern_return. */
#undef  EINVAL
#define EINVAL  DONT_USE_EINVAL
#undef  EAGAIN
#define EAGAIN  DONT_USE_EAGAIN
#undef  EACCESS
#define EACCESS DONT_USE_EACCESS
#undef  ENOMEM
#define ENOMEM  DONT_USE_ENOMEM
#undef  EPERM
#define EPERM   DONT_USE_EPERM

/*
 * KERN_SUCCESS is ambiguous here. Don't use it. Instead:
 * VM_ERR_RETURN_NOW: "stop the calling function now and return success"
 * VM_SANITIZE_FALLTHROUGH: "don't stop the calling function"
 * These values are intended for vm_sanitize_get_kr().
 */
#undef KERN_SUCCESS
#define KERN_SUCCESS DONT_USE_KERN_SUCCESS
#define VM_SANITIZE_FALLTHROUGH 0

/* Don't rewrite this result or telemeter anything. */
static inline __result_use_check
vm_sanitize_compat_rewrite_t
vm_sanitize_make_policy_dont_rewrite_err(kern_return_t err)
{
	return (vm_sanitize_compat_rewrite_t) {
		       .compat_kr = err,
		       .should_rewrite = false,
		       .should_telemeter = false
	};
}

/*
 * Telemeter this result. Don't rewrite it.
 * compat_kr is advisory only: telemetry reports it as the value
 * we might return in the future, but we don't use it now.
 */
static inline __result_use_check
vm_sanitize_compat_rewrite_t
vm_sanitize_make_policy_telemeter_dont_rewrite_err(kern_return_t err)
{
	return (vm_sanitize_compat_rewrite_t) {
		       .compat_kr = err,
		       .should_rewrite = false,
		       .should_telemeter = true
	};
}

/* Rewrite and telemeter this result. */
static inline __result_use_check
vm_sanitize_compat_rewrite_t
vm_sanitize_make_policy_telemeter_and_rewrite_err(kern_return_t err)
{
	return (vm_sanitize_compat_rewrite_t) {
		       .compat_kr = err,
		       .should_rewrite = true,
		       .should_telemeter = true
	};
}


/*
 * Similar to vm_map_range_overflows()
 * but size zero is not unconditionally allowed
 */
static bool __unused
vm_sanitize_range_overflows_strict_zero(vm_address_t start, vm_size_t size, vm_offset_t pgmask)
{
	vm_address_t sum;
	if (__builtin_add_overflow(start, size, &sum)) {
		return true;
	}

	vm_address_t aligned_start = vm_map_trunc_page_mask(start, pgmask);
	vm_address_t aligned_end = vm_map_round_page_mask(start + size, pgmask);
	if (aligned_end <= aligned_start) {
		return true;
	}

	return false;
}

/*
 * Similar to vm_map_range_overflows()
 * including unconditional acceptance of zero
 */
static bool __unused
vm_sanitize_range_overflows_allow_zero(vm_address_t start, vm_size_t size, vm_offset_t pgmask)
{
	if (size == 0) {
		return false;
	}

	vm_address_t sum;
	if (__builtin_add_overflow(start, size, &sum)) {
		return true;
	}

	vm_address_t aligned_start = vm_map_trunc_page_mask(start, pgmask);
	vm_address_t aligned_end = vm_map_round_page_mask(start + size, pgmask);
	if (aligned_end <= aligned_start) {
		return true;
	}

	return false;
}


/*
 * Error rewriting functions and the sanitization caller description
 * for each VM API.
 */

/* memory entry */

VM_SANITIZE_DEFINE_CALLER(MACH_MAKE_MEMORY_ENTRY);
VM_SANITIZE_DEFINE_CALLER(MACH_MEMORY_ENTRY_PAGE_OP);
VM_SANITIZE_DEFINE_CALLER(MACH_MEMORY_ENTRY_RANGE_OP);
VM_SANITIZE_DEFINE_CALLER(MACH_MEMORY_ENTRY_MAP_SIZE);
VM_SANITIZE_DEFINE_CALLER(MACH_MEMORY_OBJECT_MEMORY_ENTRY);

/* alloc/dealloc */

static vm_sanitize_compat_rewrite_t
vm_sanitize_err_compat_addr_size_vm_allocate_fixed(
	kern_return_t           initial_kr,
	vm_address_t            start,
	vm_size_t               size,
	vm_offset_t             pgmask)
{
	/*
	 * vm_allocate(VM_FLAGS_FIXED) historically returned
	 * KERN_INVALID_ADDRESS instead of KERN_INVALID_ARGUMENT
	 * for some invalid input ranges.
	 */
	if (vm_sanitize_range_overflows_allow_zero(start, size, pgmask) &&
	    vm_map_round_page_mask(size, pgmask) != 0) {
		return vm_sanitize_make_policy_telemeter_and_rewrite_err(KERN_INVALID_ADDRESS);
	}
	return vm_sanitize_make_policy_dont_rewrite_err(initial_kr);
}

VM_SANITIZE_DEFINE_CALLER(VM_ALLOCATE_FIXED,
    .err_compat_addr_size = &vm_sanitize_err_compat_addr_size_vm_allocate_fixed);

VM_SANITIZE_DEFINE_CALLER(VM_ALLOCATE_ANYWHERE, /* no error compat needed */);

static vm_sanitize_compat_rewrite_t
vm_sanitize_err_compat_addr_size_vm_deallocate(
	kern_return_t           initial_kr,
	vm_address_t            start,
	vm_size_t               size,
	vm_offset_t             pgmask)
{
	/*
	 * vm_deallocate historically did nothing and
	 * returned success for some invalid input ranges.
	 * We currently telemeter this case but
	 * return an error without rewriting it to success.
	 * If we did rewrite it, we would use VM_ERR_RETURN_NOW to return
	 * success immediately and bypass the rest of vm_deallocate.
	 */
	if (vm_sanitize_range_overflows_strict_zero(start, size, pgmask) &&
	    start + size >= start) {
		return vm_sanitize_make_policy_telemeter_dont_rewrite_err(VM_ERR_RETURN_NOW);
	}
	return vm_sanitize_make_policy_dont_rewrite_err(initial_kr);
}

VM_SANITIZE_DEFINE_CALLER(VM_DEALLOCATE,
    .err_compat_addr_size = &vm_sanitize_err_compat_addr_size_vm_deallocate);

VM_SANITIZE_DEFINE_CALLER(MUNMAP, /* no error compat needed */);

/* map/remap */

static vm_sanitize_compat_rewrite_t
vm_sanitize_err_compat_cur_and_max_prots_vm_map(
	kern_return_t           initial_kr,
	vm_prot_t              *cur_prot_inout,
	vm_prot_t              *max_prot_inout,
	vm_prot_t               extra_mask __unused)
{
	/*
	 * Invalid but historically accepted for some APIs: cur and max
	 * each within limits, but max less permissive than cur.
	 * We telemeter this and rewrite away the error and allow
	 * the calling function to proceed after removing
	 * permissions from cur to make it match max.
	 *
	 * We assume the individual prot values are legal
	 * because they were checked individually first.
	 */
	if (__improbable((*cur_prot_inout & *max_prot_inout) != *cur_prot_inout)) {
		*cur_prot_inout &= *max_prot_inout;
		return vm_sanitize_make_policy_telemeter_and_rewrite_err(VM_SANITIZE_FALLTHROUGH);
	}
	return vm_sanitize_make_policy_dont_rewrite_err(initial_kr);
}

/*
 * vm_remap and vm_remap_new do not need cur/max error compat.
 * In all flavors either cur/max is an out parameter only
 * or it has historically already rejected inconsistent cur/max.
 */
VM_SANITIZE_DEFINE_CALLER(VM_MAP_REMAP);

/* mmap has new successes that we can't rewrite or telemeter */
VM_SANITIZE_DEFINE_CALLER(MMAP, /* no error compat needed */);

VM_SANITIZE_DEFINE_CALLER(MAP_WITH_LINKING_NP);

VM_SANITIZE_DEFINE_CALLER(MREMAP_ENCRYPTED, /* no error compat needed */);

/*
 * vm_map does need cur/max compat
 * compat for vm_map_enter_mem_object includes all vm_map flavors
 */
VM_SANITIZE_DEFINE_CALLER(ENTER_MEM_OBJ,
    .err_compat_prot_cur_max = &vm_sanitize_err_compat_cur_and_max_prots_vm_map);
VM_SANITIZE_DEFINE_CALLER(ENTER_MEM_OBJ_CTL,
    .err_compat_prot_cur_max = &vm_sanitize_err_compat_cur_and_max_prots_vm_map);

/* wire/unwire */

static vm_sanitize_compat_rewrite_t
vm_sanitize_err_compat_addr_size_vm_wire_user(
	kern_return_t           initial_kr,
	vm_address_t            start,
	vm_size_t               size,
	vm_offset_t             pgmask)
{
	/*
	 * vm_wire historically did nothing and
	 * returned success for some invalid input ranges.
	 * We currently telemeter this case but
	 * return an error without rewriting it to success.
	 * If we did rewrite it, we would use VM_ERR_RETURN_NOW to return
	 * success immediately and bypass the rest of vm_wire.
	 */
	if (vm_sanitize_range_overflows_strict_zero(start, size, pgmask) &&
	    start + size >= start) {
		return vm_sanitize_make_policy_telemeter_dont_rewrite_err(VM_ERR_RETURN_NOW);
	}
	return vm_sanitize_make_policy_dont_rewrite_err(initial_kr);
}

VM_SANITIZE_DEFINE_CALLER(VM_WIRE_USER,
    .err_compat_addr_size = &vm_sanitize_err_compat_addr_size_vm_wire_user);
VM_SANITIZE_DEFINE_CALLER(VM_UNWIRE_USER,
    .err_compat_addr_size = &vm_sanitize_err_compat_addr_size_vm_wire_user);

VM_SANITIZE_DEFINE_CALLER(VM_MAP_WIRE, /* no error compat needed */);
VM_SANITIZE_DEFINE_CALLER(VM_MAP_UNWIRE, /* no error compat needed */);

#if XNU_PLATFORM_MacOSX
static vm_sanitize_compat_rewrite_t
vm_sanitize_err_compat_addr_size_vslock(
	kern_return_t           initial_kr __unused,
	vm_address_t            start __unused,
	vm_size_t               size __unused,
	vm_offset_t             pgmask __unused)
{
	/*
	 * vslock and vsunlock historically did nothing
	 * and returned success for every start/size value.
	 * We telemeter bogus values and early return success.
	 */
	return vm_sanitize_make_policy_telemeter_and_rewrite_err(VM_ERR_RETURN_NOW);
}

VM_SANITIZE_DEFINE_CALLER(VSLOCK,
    .err_compat_addr_size = &vm_sanitize_err_compat_addr_size_vslock);
VM_SANITIZE_DEFINE_CALLER(VSUNLOCK,
    .err_compat_addr_size = &vm_sanitize_err_compat_addr_size_vslock);
#else /* XNU_PLATFORM_MacOSX */
VM_SANITIZE_DEFINE_CALLER(VSLOCK, /* no error compat needed */);
VM_SANITIZE_DEFINE_CALLER(VSUNLOCK, /* no error compat needed */);
#endif /* XNU_PLATFORM_MacOSX */

/* copyin/copyout */

static vm_sanitize_compat_rewrite_t
vm_sanitize_err_compat_addr_size_vm_map_copyio(
	kern_return_t           initial_kr,
	vm_address_t            start,
	vm_size_t               size,
	vm_offset_t             pgmask)
{
	/*
	 * vm_map_copyin and vm_map_copyout (and functions based on them)
	 * historically returned KERN_INVALID_ADDRESS
	 * instead of KERN_INVALID_ARGUMENT.
	 */
	if (vm_sanitize_range_overflows_allow_zero(start, size, pgmask) &&
	    initial_kr == KERN_INVALID_ARGUMENT) {
		return vm_sanitize_make_policy_telemeter_and_rewrite_err(KERN_INVALID_ADDRESS);
	}

	return vm_sanitize_make_policy_dont_rewrite_err(initial_kr);
}

VM_SANITIZE_DEFINE_CALLER(VM_MAP_COPY_OVERWRITE,
    .err_compat_addr_size = &vm_sanitize_err_compat_addr_size_vm_map_copyio);
VM_SANITIZE_DEFINE_CALLER(VM_MAP_COPYIN,
    .err_compat_addr_size = &vm_sanitize_err_compat_addr_size_vm_map_copyio);
VM_SANITIZE_DEFINE_CALLER(VM_MAP_READ_USER,
    .err_compat_addr_size = &vm_sanitize_err_compat_addr_size_vm_map_copyio);
VM_SANITIZE_DEFINE_CALLER(VM_MAP_WRITE_USER,
    .err_compat_addr_size = &vm_sanitize_err_compat_addr_size_vm_map_copyio);

/* inherit */

/* protect */

/* behavior */

/* msync */

/* machine attribute */

/* page info */

/* test */
VM_SANITIZE_DEFINE_CALLER(TEST);
