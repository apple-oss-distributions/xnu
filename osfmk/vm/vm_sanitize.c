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

/* avoid includes here; we want these pragmas to also affect included inline functions */
#include <mach/machine/vm_param.h> /* to get PAGE_SHIFT without the inline functions from mach/vm_param.h */
/*
 * On 4k-hardware-page arm64 systems, the PAGE_SHIFT macro does not resolve to
 * a constant, but instead a variable whose value is determined on boot depending
 * on the amount of RAM installed.
 *
 * In these cases, actual instructions need to be emitted to compute values like
 * PAGE_SIZE = (1 << PAGE_SHIFT), which means UBSan checks will be generated
 * as well since the values cannot be computed at compile time.
 *
 * Therefore, we disable arithmetic UBSan checks on these configurations. We
 * detect them with PAGE_SHIFT == 0, since (during the preprocessing phase)
 * symbols will resolve to 0, whereas PAGE_SHIFT will resolve to its actual
 * nonzero value if it is defined as a macro.
 */
#if PAGE_SHIFT == 0
#pragma clang attribute push (__attribute__((no_sanitize("signed-integer-overflow", \
        "unsigned-integer-overflow", "shift", "unsigned-shift-base"))), apply_to=function)
#endif

/* Disabling optimizations makes it impossible to optimize out UBSan checks */
#if !__OPTIMIZE__
#pragma clang attribute push (__attribute__((no_sanitize("undefined", \
        "integer", "unsigned-shift-base", "nullability", "bounds"))), apply_to=function)
#endif

#include <vm/vm_map_xnu.h>
#include <vm/vm_sanitize_internal.h>
#include <vm/vm_object_internal.h>

#define VM_SANITIZE_PROT_ALLOWED (VM_PROT_ALL | VM_PROT_ALLEXEC)

// TODO: enable telemetry and ktriage separately?

/* Also send telemetry output to kernel serial console? */
static TUNABLE(bool, vm_sanitize_telemeter_to_serial,
    "vm_sanitize_telemeter_to_serial", false);

/*
 * Arithmetic macros that suppress UBSan. os_xyz_overflow does not generate a
 * UBSan overflow check, since it indicates to the compiler that overflow is
 * (potentially) intentional and well-defined.
 *
 * These macros ignore the value that indicates whether overflow actually,
 * occurred, so a comment should be left explaining why it is unlikely to
 * happen or is otherwise not a concern.
 */
#define vm_add_no_ubsan(a, b) ({ typeof(a+b) TMP; (void) os_add_overflow(a, b, &TMP); TMP; })
#define vm_sub_no_ubsan(a, b) ({ typeof(a+b) TMP; (void) os_sub_overflow(a, b, &TMP); TMP; })

static inline
kern_return_t
vm_sanitize_apply_err_rewrite_policy(kern_return_t initial_kr, vm_sanitize_compat_rewrite_t rewrite)
{
	return rewrite.should_rewrite ? rewrite.compat_kr : initial_kr;
}

__attribute__((always_inline, warn_unused_result))
vm_addr_struct_t
vm_sanitize_wrap_addr(vm_address_t val)
{
	return (vm_addr_struct_t) { .UNSAFE = val };
}

__attribute__((always_inline, warn_unused_result))
vm_size_struct_t
vm_sanitize_wrap_size(vm_size_t val)
{
	return (vm_size_struct_t) { .UNSAFE = val };
}

__attribute__((always_inline, warn_unused_result))
vm32_size_struct_t
vm32_sanitize_wrap_size(vm32_size_t val)
{
	return (vm32_size_struct_t) { .UNSAFE = val };
}

__attribute__((always_inline, warn_unused_result))
vm_prot_ut
vm_sanitize_wrap_prot(vm_prot_t val)
{
	return (vm_prot_ut) { .UNSAFE = val };
}

__attribute__((always_inline, warn_unused_result))
vm_inherit_ut
vm_sanitize_wrap_inherit(vm_inherit_t val)
{
	return (vm_inherit_ut) { .UNSAFE = val };
}

__attribute__((always_inline, warn_unused_result))
vm_behavior_ut
vm_sanitize_wrap_behavior(vm_behavior_t val)
{
	return (vm_behavior_ut) { .UNSAFE = val };
}

#ifdef  MACH_KERNEL_PRIVATE
__attribute__((always_inline, warn_unused_result))
vm_addr_struct_t
vm_sanitize_expand_addr_to_64(vm32_address_ut val)
{
	return (vm_addr_struct_t) { .UNSAFE = val.UNSAFE };
}

__attribute__((always_inline, warn_unused_result))
vm_size_struct_t
vm_sanitize_expand_size_to_64(vm32_size_ut val)
{
	return (vm_size_struct_t) { .UNSAFE = val.UNSAFE };
}

__attribute__((always_inline, warn_unused_result))
vm32_address_ut
vm_sanitize_trunc_addr_to_32(vm_addr_struct_t val)
{
	vm32_address_ut ret;

	ret.UNSAFE = CAST_DOWN_EXPLICIT(vm32_address_t, val.UNSAFE);
	return ret;
}

__attribute__((always_inline, warn_unused_result))
vm32_size_ut
vm_sanitize_trunc_size_to_32(vm_size_struct_t val)
{
	vm32_size_ut ret;

	ret.UNSAFE = CAST_DOWN_EXPLICIT(vm32_size_t, val.UNSAFE);
	return ret;
}

__attribute__((always_inline, warn_unused_result, overloadable))
bool
vm_sanitize_add_overflow(
	vm32_address_ut         addr_u,
	vm32_size_ut            size_u,
	vm32_address_ut        *addr_out_u)
{
	vm32_address_t addr = VM_SANITIZE_UNSAFE_UNWRAP(addr_u);
	vm32_size_t    size = VM_SANITIZE_UNSAFE_UNWRAP(size_u);

	return os_add_overflow(addr, size, &addr_out_u->UNSAFE);
}
#endif  /* MACH_KERNEL_PRIVATE */

__attribute__((always_inline, warn_unused_result, overloadable))
bool
vm_sanitize_add_overflow(
	vm_addr_struct_t        addr_u,
	vm_size_struct_t        size_u,
	vm_addr_struct_t       *addr_out_u)
{
	mach_vm_address_t addr = VM_SANITIZE_UNSAFE_UNWRAP(addr_u);
	mach_vm_size_t    size = VM_SANITIZE_UNSAFE_UNWRAP(size_u);

	return os_add_overflow(addr, size, &addr_out_u->UNSAFE);
}

__attribute__((always_inline, warn_unused_result, overloadable))
bool
vm_sanitize_add_overflow(
	vm_size_struct_t        size1_u,
	vm_size_struct_t        size2_u,
	vm_size_struct_t       *size_out_u)
{
	mach_vm_address_t size1 = VM_SANITIZE_UNSAFE_UNWRAP(size1_u);
	mach_vm_size_t    size2 = VM_SANITIZE_UNSAFE_UNWRAP(size2_u);

	return os_add_overflow(size1, size2, &size_out_u->UNSAFE);
}

/*
 * vm_*_no_ubsan is acceptable in these functions since they operate on unsafe
 * types. The return value is also an unsafe type and must be sanitized before
 * it can be used in other functions.
 */
__attribute__((always_inline, warn_unused_result))
vm_addr_struct_t
vm_sanitize_compute_ut_end(
	vm_addr_struct_t        addr_u,
	vm_size_struct_t        size_u)
{
	vm_addr_struct_t end_u = { 0 };
	vm_address_t addr_local = VM_SANITIZE_UNSAFE_UNWRAP(addr_u);
	vm_size_t size_local = VM_SANITIZE_UNSAFE_UNWRAP(size_u);

	VM_SANITIZE_UT_SET(end_u, vm_add_no_ubsan(addr_local, size_local));
	return end_u;
}

__attribute__((always_inline, warn_unused_result))
vm_size_struct_t
vm_sanitize_compute_ut_size(
	vm_addr_struct_t        addr_u,
	vm_addr_struct_t        end_u)
{
	vm_size_struct_t size_u = { 0 };
	vm_address_t addr_local = VM_SANITIZE_UNSAFE_UNWRAP(addr_u);
	vm_address_t end_local = VM_SANITIZE_UNSAFE_UNWRAP(end_u);

	VM_SANITIZE_UT_SET(size_u, vm_sub_no_ubsan(end_local, addr_local));
	return size_u;
}

__attribute__((always_inline, warn_unused_result))
mach_vm_address_t
vm_sanitize_addr(
	vm_map_t                map,
	vm_addr_struct_t        addr_u)
{
	mach_vm_address_t addr   = VM_SANITIZE_UNSAFE_UNWRAP(addr_u);
	vm_map_offset_t   pgmask = vm_map_page_mask(map);

	return vm_map_trunc_page_mask(addr, pgmask);
}

__attribute__((always_inline, warn_unused_result))
mach_vm_offset_t
vm_sanitize_offset_in_page(
	vm_map_offset_t         mask,
	vm_addr_struct_t        addr_u)
{
	return VM_SANITIZE_UNSAFE_UNWRAP(addr_u) & mask;
}

__attribute__((always_inline, warn_unused_result))
kern_return_t
vm_sanitize_offset(
	vm_addr_struct_t        offset_u,
	vm_sanitize_caller_t    vm_sanitize_caller __unused,
	vm_map_address_t        addr,
	vm_map_address_t        end,
	vm_map_offset_t        *offset)
{
	*offset = VM_SANITIZE_UNSAFE_UNWRAP(offset_u);

	if ((*offset < addr) || (*offset > end)) {
		*offset = 0;
		return KERN_INVALID_ARGUMENT;
	}

	return KERN_SUCCESS;
}

__attribute__((always_inline, warn_unused_result))
kern_return_t
vm_sanitize_mask(
	vm_addr_struct_t        mask_u,
	vm_sanitize_caller_t    vm_sanitize_caller __unused,
	vm_map_offset_t        *mask)
{
	*mask = VM_SANITIZE_UNSAFE_UNWRAP(mask_u);

	/*
	 * Adding validation to mask has high ABI risk and low security value.
	 * The only internal function that deals with mask is vm_map_locate_space
	 * and it currently ensures that addresses are aligned to page boundary
	 * even for weird alignment requests.
	 *
	 * rdar://120445665
	 */

	return KERN_SUCCESS;
}

__attribute__((always_inline, warn_unused_result))
kern_return_t
vm_sanitize_object_size(
	vm_size_struct_t        size_u,
	vm_sanitize_caller_t    vm_sanitize_caller __unused,
	vm_sanitize_flags_t     flags,
	vm_object_offset_t     *size)
{
	mach_vm_size_t  size_aligned;

	*size   = VM_SANITIZE_UNSAFE_UNWRAP(size_u);
	/*
	 * Handle size zero as requested by the caller
	 */
	if (*size == 0) {
		if (flags & VM_SANITIZE_FLAGS_SIZE_ZERO_SUCCEEDS) {
			return VM_ERR_RETURN_NOW;
		} else if (flags & VM_SANITIZE_FLAGS_SIZE_ZERO_FAILS) {
			return KERN_INVALID_ARGUMENT;
		} else {
			/* VM_SANITIZE_FLAGS_SIZE_ZERO_FALLTHROUGH - nothing to do */
			return KERN_SUCCESS;
		}
	}

	size_aligned = vm_map_round_page_mask(*size, PAGE_MASK);
	if (size_aligned == 0) {
		*size = 0;
		return KERN_INVALID_ARGUMENT;
	}

	if (!(flags & VM_SANITIZE_FLAGS_GET_UNALIGNED_VALUES)) {
		*size = size_aligned;
	}
	return KERN_SUCCESS;
}

__attribute__((always_inline, warn_unused_result))
kern_return_t
vm_sanitize_size(
	vm_addr_struct_t        offset_u,
	vm_size_struct_t        size_u,
	vm_sanitize_caller_t    vm_sanitize_caller __unused,
	vm_map_t                map,
	vm_sanitize_flags_t     flags,
	mach_vm_size_t         *size)
{
	mach_vm_size_t  offset = VM_SANITIZE_UNSAFE_UNWRAP(offset_u);
	vm_map_offset_t pgmask = vm_map_page_mask(map);
	mach_vm_size_t  size_aligned;

	*size   = VM_SANITIZE_UNSAFE_UNWRAP(size_u);
	/*
	 * Handle size zero as requested by the caller
	 */
	if (*size == 0) {
		if (flags & VM_SANITIZE_FLAGS_SIZE_ZERO_SUCCEEDS) {
			return VM_ERR_RETURN_NOW;
		} else if (flags & VM_SANITIZE_FLAGS_SIZE_ZERO_FAILS) {
			return KERN_INVALID_ARGUMENT;
		} else {
			/* VM_SANITIZE_FLAGS_SIZE_ZERO_FALLTHROUGH - nothing to do */
			return KERN_SUCCESS;
		}
	}

	/*
	 * Ensure that offset and size don't overflow when refering to the
	 * vm_object
	 */
	if (os_add_overflow(*size, offset, &size_aligned)) {
		*size = 0;
		return KERN_INVALID_ARGUMENT;
	}
	/*
	 * This rounding is a check on the vm_object and thus uses the kernel's PAGE_MASK
	 */
	if (vm_map_round_page_mask(size_aligned, PAGE_MASK) == 0) {
		*size = 0;
		return KERN_INVALID_ARGUMENT;
	}

	/*
	 * Check that a non zero size being mapped doesn't round to 0
	 *
	 * vm_sub_no_ubsan is acceptable here since the subtraction is guaranteed to
	 * not overflow. We know size_aligned = *size + offset, and since that
	 * addition did not overflow and offset >= offset & ~pgmask, this
	 * subtraction also cannot overflow.
	 */
	size_aligned = vm_sub_no_ubsan(size_aligned, offset & ~pgmask);

	/*
	 * This rounding is a check on the specified map and thus uses its pgmask
	 */
	size_aligned  = vm_map_round_page_mask(size_aligned, pgmask);
	if (size_aligned == 0) {
		*size = 0;
		return KERN_INVALID_ARGUMENT;
	}

	if (!(flags & VM_SANITIZE_FLAGS_GET_UNALIGNED_VALUES)) {
		*size = size_aligned;
	}
	return KERN_SUCCESS;
}

static __attribute__((warn_unused_result))
kern_return_t
vm_sanitize_err_compat_addr_size(
	kern_return_t           initial_kr,
	vm_sanitize_caller_t    vm_sanitize_caller,
	vm_addr_struct_t        addr_u,
	vm_size_struct_t        size_u,
	mach_vm_offset_t        pgmask,
	vm_map_t                map_or_null)
{
	vm_sanitize_compat_rewrite_t compat = {initial_kr, false, false};
	if (vm_sanitize_caller->err_compat_addr_size) {
		compat = (vm_sanitize_caller->err_compat_addr_size)
		    (initial_kr, VM_SANITIZE_UNSAFE_UNWRAP(addr_u), VM_SANITIZE_UNSAFE_UNWRAP(size_u),
		    pgmask, map_or_null);
	}

	if (compat.should_telemeter) {
#if DEVELOPMENT || DEBUG
		if (vm_sanitize_telemeter_to_serial) {
			printf("VM API - [%s] unsanitary addr 0x%llx size 0x%llx pgmask "
			    "0x%llx passed to %s; error code %d may become %d\n",
			    proc_best_name(current_proc()),
			    VM_SANITIZE_UNSAFE_UNWRAP(addr_u), VM_SANITIZE_UNSAFE_UNWRAP(size_u), pgmask,
			    vm_sanitize_caller->vmsc_caller_name, initial_kr, compat.compat_kr);
		}
#endif /* DEVELOPMENT || DEBUG */

		vm_sanitize_send_telemetry(
			vm_sanitize_caller->vmsc_telemetry_id,
			VM_SANITIZE_CHECKER_ADDR_SIZE,
			VM_SANITIZE_CHECKER_COUNT_1 /* fixme */,
			vm_sanitize_caller->vmsc_ktriage_id,
			VM_SANITIZE_UNSAFE_UNWRAP(addr_u),
			VM_SANITIZE_UNSAFE_UNWRAP(size_u),
			pgmask,
			0 /* arg4 */,
			initial_kr,
			compat.compat_kr);
	}

	return vm_sanitize_apply_err_rewrite_policy(initial_kr, compat);
}

__attribute__((always_inline, warn_unused_result))
kern_return_t
vm_sanitize_addr_size(
	vm_addr_struct_t        addr_u,
	vm_size_struct_t        size_u,
	vm_sanitize_caller_t    vm_sanitize_caller,
	mach_vm_offset_t        pgmask,
	vm_map_t                map_or_null,
	vm_sanitize_flags_t     flags,
	vm_map_offset_t        *addr,
	vm_map_offset_t        *end,
	vm_map_size_t          *size)
{
	/*
	 * map_or_null is not available from all call sites.
	 * Use pgmask instead of vm_map_page_mask(map) for alignment.
	 */

	vm_map_offset_t addr_aligned = 0;
	vm_map_offset_t end_aligned = 0, end_unaligned = 0;
	kern_return_t kr;

	*addr = VM_SANITIZE_UNSAFE_UNWRAP(addr_u);
	*size = VM_SANITIZE_UNSAFE_UNWRAP(size_u);
	if (flags & VM_SANITIZE_FLAGS_REALIGN_START) {
		assert(!(flags & VM_SANITIZE_FLAGS_GET_UNALIGNED_VALUES));
	}

#if CONFIG_KERNEL_TAGGING
	if (flags & VM_SANITIZE_FLAGS_CANONICALIZE) {
		*addr = vm_memtag_canonicalize_address(*addr);
	}
#endif /* CONFIG_KERNEL_TAGGING */
	addr_aligned = vm_map_trunc_page_mask(*addr, pgmask);

	/*
	 * Ensure that the address is aligned
	 */
	if (__improbable((flags & VM_SANITIZE_FLAGS_CHECK_ALIGNED_START) && (*addr & pgmask))) {
		kr = KERN_INVALID_ARGUMENT;
		goto unsanitary;
	}

	/*
	 * Ensure that the size is aligned
	 */
	if (__improbable((flags & VM_SANITIZE_FLAGS_CHECK_ALIGNED_SIZE) && (*size & pgmask))) {
		kr = KERN_INVALID_ARGUMENT;
		goto unsanitary;
	}

	/*
	 * Handle size zero as requested by the caller
	 */
	if (*size == 0) {
		if (flags & VM_SANITIZE_FLAGS_SIZE_ZERO_SUCCEEDS) {
			*addr = 0;
			*end = 0;
			/* size is already 0 */
			return VM_ERR_RETURN_NOW;
		} else if (flags & VM_SANITIZE_FLAGS_SIZE_ZERO_FAILS) {
			kr = KERN_INVALID_ARGUMENT;
			goto unsanitary;
		} else {
			/* VM_SANITIZE_FLAGS_SIZE_ZERO_FALLTHROUGH - nothing to do */
			if (flags & VM_SANITIZE_FLAGS_GET_UNALIGNED_VALUES) {
				/* addr is already set */
				*end = *addr;
				/* size is already 0 */
				return KERN_SUCCESS;
			} else {
				*addr = addr_aligned;
				*end = addr_aligned;
				/* size is already 0 */
				return KERN_SUCCESS;
			}
		}
	}

	/*
	 * Compute the aligned end now
	 */
	if (flags & VM_SANITIZE_FLAGS_REALIGN_START) {
		*addr = addr_aligned;
	}
	if (__improbable(os_add_overflow(*addr, *size, &end_unaligned))) {
		kr = KERN_INVALID_ARGUMENT;
		goto unsanitary;
	}


	end_aligned = vm_map_round_page_mask(end_unaligned, pgmask);
	if (__improbable(end_aligned <= addr_aligned)) {
		kr = KERN_INVALID_ARGUMENT;
		goto unsanitary;
	}

	if (flags & VM_SANITIZE_FLAGS_GET_UNALIGNED_VALUES) {
		/* addr and size are already set */
		*end = end_unaligned;
	} else {
		*addr = addr_aligned;
		*end = end_aligned;
		/*
		 * vm_sub_no_ubsan is acceptable since the subtraction is guaranteed to
		 * not overflow, as we have already verified end_aligned > addr_aligned.
		 */
		*size = vm_sub_no_ubsan(end_aligned, addr_aligned);
	}
	return KERN_SUCCESS;

unsanitary:
	*addr = 0;
	*end = 0;
	*size = 0;
	return vm_sanitize_err_compat_addr_size(kr, vm_sanitize_caller,
	           addr_u, size_u, pgmask, map_or_null);
}

__attribute__((always_inline, warn_unused_result))
kern_return_t
vm_sanitize_addr_end(
	vm_addr_struct_t        addr_u,
	vm_addr_struct_t        end_u,
	vm_sanitize_caller_t    vm_sanitize_caller,
	mach_vm_offset_t        mask,
	vm_map_t                map_or_null,
	vm_sanitize_flags_t     flags,
	vm_map_offset_t        *start,
	vm_map_offset_t        *end,
	vm_map_size_t          *size)
{
	vm_size_struct_t size_u = vm_sanitize_compute_ut_size(addr_u, end_u);

	return vm_sanitize_addr_size(addr_u, size_u, vm_sanitize_caller, mask,
	           map_or_null, flags, start, end, size);
}

__attribute__((always_inline, warn_unused_result))
kern_return_t
vm_sanitize_prot(
	vm_prot_ut              prot_u,
	vm_sanitize_caller_t    vm_sanitize_caller __unused,
	vm_map_t                map __unused,
	vm_prot_t               extra_mask,
	vm_prot_t              *prot)
{
	*prot = VM_SANITIZE_UNSAFE_UNWRAP(prot_u);

	if (__improbable(*prot & ~(VM_SANITIZE_PROT_ALLOWED | extra_mask))) {
		*prot = VM_PROT_NONE;
		return KERN_INVALID_ARGUMENT;
	}

#if defined(__x86_64__)
	if ((*prot & VM_PROT_UEXEC) &&
	    !pmap_supported_feature(map->pmap, PMAP_FEAT_UEXEC)) {
		*prot = VM_PROT_NONE;
		return KERN_INVALID_ARGUMENT;
	}
#endif

	return KERN_SUCCESS;
}

/*
 * *out_cur and *out_max are modified when there is an err compat rewrite
 * otherwise they are left unchanged
 */
static __attribute__((warn_unused_result))
kern_return_t
vm_sanitize_err_compat_cur_and_max_prots(
	kern_return_t           initial_kr,
	vm_sanitize_caller_t    vm_sanitize_caller,
	vm_prot_ut              cur_prot_u,
	vm_prot_ut              max_prot_u,
	vm_prot_t               extra_mask,
	vm_prot_t              *out_cur,
	vm_prot_t              *out_max)
{
	vm_prot_t initial_cur_prot = VM_SANITIZE_UNSAFE_UNWRAP(cur_prot_u);
	vm_prot_t initial_max_prot = VM_SANITIZE_UNSAFE_UNWRAP(max_prot_u);

	vm_sanitize_compat_rewrite_t compat = {initial_kr, false, false};
	vm_prot_t compat_cur_prot = initial_cur_prot;
	vm_prot_t compat_max_prot = initial_max_prot;
	if (vm_sanitize_caller->err_compat_prot_cur_max) {
		compat = (vm_sanitize_caller->err_compat_prot_cur_max)
		    (initial_kr, &compat_cur_prot, &compat_max_prot, extra_mask);
	}

	if (compat.should_telemeter) {
#if DEVELOPMENT || DEBUG
		if (vm_sanitize_telemeter_to_serial) {
			printf("VM API - [%s] unsanitary vm_prot cur %d max %d "
			    "passed to %s; error code %d may become %d\n",
			    proc_best_name(current_proc()),
			    initial_cur_prot, initial_max_prot,
			    vm_sanitize_caller->vmsc_caller_name,
			    initial_kr, compat.compat_kr);
		}
#endif /* DEVELOPMENT || DEBUG */

		vm_sanitize_send_telemetry(
			vm_sanitize_caller->vmsc_telemetry_id,
			VM_SANITIZE_CHECKER_PROT_CUR_MAX,
			VM_SANITIZE_CHECKER_COUNT_1 /* fixme */,
			vm_sanitize_caller->vmsc_ktriage_id,
			initial_cur_prot,
			initial_max_prot,
			extra_mask,
			0 /* arg4 */,
			initial_kr,
			compat.compat_kr);
	}

	if (compat.should_rewrite) {
		*out_cur = compat_cur_prot;
		*out_max = compat_max_prot;
		return compat.compat_kr;
	} else {
		/* out_cur and out_max unchanged */
		return initial_kr;
	}
}

__attribute__((always_inline, warn_unused_result))
kern_return_t
vm_sanitize_cur_and_max_prots(
	vm_prot_ut              cur_prot_u,
	vm_prot_ut              max_prot_u,
	vm_sanitize_caller_t    vm_sanitize_caller,
	vm_map_t                map,
	vm_prot_t               extra_mask,
	vm_prot_t              *cur_prot,
	vm_prot_t              *max_prot)
{
	kern_return_t kr;

	kr = vm_sanitize_prot(cur_prot_u, vm_sanitize_caller, map, extra_mask, cur_prot);
	if (__improbable(kr != KERN_SUCCESS)) {
		*cur_prot = VM_PROT_NONE;
		*max_prot = VM_PROT_NONE;
		return kr;
	}

	kr = vm_sanitize_prot(max_prot_u, vm_sanitize_caller, map, extra_mask, max_prot);
	if (__improbable(kr != KERN_SUCCESS)) {
		*cur_prot = VM_PROT_NONE;
		*max_prot = VM_PROT_NONE;
		return kr;
	}


	/*
	 * This check needs to be performed on the actual protection bits.
	 * vm_sanitize_prot restricts cur and max prot to
	 * (VM_PROT_ALL | VM_PROT_ALLEXEC | extra_mask), but we don't enforce
	 * ordering on the extra_mask bits.
	 */
	if (__improbable((*cur_prot & *max_prot & VM_SANITIZE_PROT_ALLOWED) !=
	    (*cur_prot & VM_SANITIZE_PROT_ALLOWED))) {
		/* cur is more permissive than max */
		kr = KERN_INVALID_ARGUMENT;
		goto unsanitary;
	}
	return KERN_SUCCESS;

unsanitary:
	*cur_prot = VM_PROT_NONE;
	*max_prot = VM_PROT_NONE;
	/* error compat may set cur/max to something other than 0/0 */
	return vm_sanitize_err_compat_cur_and_max_prots(kr, vm_sanitize_caller,
	           cur_prot_u, max_prot_u, extra_mask, cur_prot, max_prot);
}

__attribute__((always_inline, warn_unused_result))
vm_prot_t
vm_sanitize_prot_bsd(
	vm_prot_ut              prot_u,
	vm_sanitize_caller_t    vm_sanitize_caller __unused)
{
	vm_prot_t prot = VM_SANITIZE_UNSAFE_UNWRAP(prot_u);

	/*
	 * Strip all protections that are not allowed
	 */
	prot &= (VM_PROT_ALL | VM_PROT_TRUSTED | VM_PROT_STRIP_READ);
	return prot;
}

__attribute__((always_inline, warn_unused_result))
kern_return_t
vm_sanitize_memory_entry_perm(
	vm_prot_ut              perm_u,
	vm_sanitize_caller_t    vm_sanitize_caller __unused,
	vm_sanitize_flags_t     flags,
	vm_prot_t               extra_mask,
	vm_prot_t              *perm)
{
	vm_prot_t prot;
	vm_prot_t map_mem_flags;
	vm_prot_t access;

	*perm = VM_SANITIZE_UNSAFE_UNWRAP(perm_u);
	prot = *perm & MAP_MEM_PROT_MASK;
	map_mem_flags = *perm & MAP_MEM_FLAGS_MASK;
	access = GET_MAP_MEM(*perm);

	if ((flags & VM_SANITIZE_FLAGS_CHECK_USER_MEM_MAP_FLAGS) &&
	    (map_mem_flags & ~MAP_MEM_FLAGS_USER)) {
		/*
		 * Unknown flag: reject for forward compatibility.
		 */
		*perm = VM_PROT_NONE;
		return KERN_INVALID_VALUE;
	}

	/*
	 * Clear prot bits in perm and set them to only allowed values
	 */
	*perm &= ~MAP_MEM_PROT_MASK;
	*perm |= (prot & (VM_PROT_ALL | extra_mask));

	/*
	 * No checks on access
	 */
	(void) access;

	return KERN_SUCCESS;
}

__attribute__((always_inline, warn_unused_result))
kern_return_t
vm_sanitize_inherit(
	vm_inherit_ut           inherit_u,
	vm_sanitize_caller_t    vm_sanitize_caller __unused,
	vm_inherit_t           *inherit)
{
	*inherit = VM_SANITIZE_UNSAFE_UNWRAP(inherit_u);

	if (__improbable(*inherit > VM_INHERIT_LAST_VALID)) {
		*inherit = VM_INHERIT_NONE;
		return KERN_INVALID_ARGUMENT;
	}

	return KERN_SUCCESS;
}

__attribute__((always_inline, warn_unused_result))
kern_return_t
vm_sanitize_behavior(
	vm_behavior_ut           behavior_u,
	vm_sanitize_caller_t    vm_sanitize_caller __unused,
	vm_behavior_t           *behavior)
{
	*behavior = VM_SANITIZE_UNSAFE_UNWRAP(behavior_u);

	if (__improbable((*behavior > VM_BEHAVIOR_LAST_VALID)
	    || (*behavior < 0))) {
		*behavior = VM_BEHAVIOR_DEFAULT;
		return KERN_INVALID_ARGUMENT;
	}

	return KERN_SUCCESS;
}

#if DEBUG || DEVELOPMENT

static bool
vm_sanitize_offset_test(void)
{
	kern_return_t kr = KERN_SUCCESS;
	vm_map_offset_t offset;
	vm_map_address_t addr, end;
	vm_addr_struct_t offset_u;

	/*
	 * Offset that is less than lower bound
	 */
	offset_u = vm_sanitize_wrap_addr(0);
	addr = 5;
	end = 10;
	kr = vm_sanitize_offset(offset_u, VM_SANITIZE_CALLER_TEST, addr, end, &offset);

	if (vm_sanitize_get_kr(kr) == KERN_SUCCESS) {
		printf("%s: failed for addr %p end %p offset %p\n",
		    __func__, (void *)addr, (void *)end,
		    (void *)VM_SANITIZE_UNSAFE_UNWRAP(offset_u));
		return false;
	}

	/*
	 * Offset that is less than lower bound
	 */
	offset_u = vm_sanitize_wrap_addr(11);
	addr = 5;
	end = 10;
	kr = KERN_SUCCESS;
	kr = vm_sanitize_offset(offset_u, VM_SANITIZE_CALLER_TEST, addr, end, &offset);

	if (vm_sanitize_get_kr(kr) == KERN_SUCCESS) {
		printf("%s: failed for addr %p end %p offset %p\n",
		    __func__, (void *)addr, (void *)end,
		    (void *)VM_SANITIZE_UNSAFE_UNWRAP(offset_u));
		return false;
	}

	printf("%s: passed\n", __func__);

	return true;
}

static bool
vm_sanitize_size_test(void)
{
	kern_return_t kr = KERN_SUCCESS;
	vm_map_size_t size;
	vm_addr_struct_t offset_u;
	vm_size_struct_t size_u;

	/*
	 * VM_SANITIZE_FLAGS_SIZE_ZERO_SUCCEEDS should return VM_ERR_RETURN_NOW for size = 0
	 * for callers that need to return success early
	 */
	offset_u = vm_sanitize_wrap_addr(PAGE_SIZE + 1);
	size_u = vm_sanitize_wrap_size(0);
	kr = vm_sanitize_size(offset_u, size_u, VM_SANITIZE_CALLER_TEST, current_map(),
	    VM_SANITIZE_FLAGS_SIZE_ZERO_SUCCEEDS, &size);

	if (vm_sanitize_get_kr(kr) != KERN_SUCCESS ||
	    kr != VM_ERR_RETURN_NOW) {
		printf("%s: VM_SANITIZE_FLAGS_SIZE_ZERO_SUCCEEDS failed for offset %p size %p\n",
		    __func__, (void *)VM_SANITIZE_UNSAFE_UNWRAP(offset_u),
		    (void *)VM_SANITIZE_UNSAFE_UNWRAP(size_u));
		return false;
	}

	/*
	 * VM_SANITIZE_FLAGS_SIZE_ZERO_FAILS should return failure for size = 0
	 */
	offset_u = vm_sanitize_wrap_addr(PAGE_SIZE + 1);
	size_u = vm_sanitize_wrap_size(0);
	kr = KERN_SUCCESS;
	kr = vm_sanitize_size(offset_u, size_u, VM_SANITIZE_CALLER_TEST, current_map(),
	    VM_SANITIZE_FLAGS_SIZE_ZERO_FAILS, &size);

	if (vm_sanitize_get_kr(kr) == KERN_SUCCESS) {
		printf("%s: VM_SANITIZE_FLAGS_SIZE_ZERO_FAILS failed for offset %p size %p\n",
		    __func__, (void *)VM_SANITIZE_UNSAFE_UNWRAP(offset_u),
		    (void *)VM_SANITIZE_UNSAFE_UNWRAP(size_u));
		return false;
	}

	/*
	 * VM_SANITIZE_FLAGS_SIZE_ZERO_FALLTHROUGH should return success for size = 0
	 */
	offset_u = vm_sanitize_wrap_addr(PAGE_SIZE + 1);
	size_u = vm_sanitize_wrap_size(0);
	kr = KERN_SUCCESS;
	kr = vm_sanitize_size(offset_u, size_u, VM_SANITIZE_CALLER_TEST, current_map(),
	    VM_SANITIZE_FLAGS_SIZE_ZERO_FALLTHROUGH, &size);

	if (vm_sanitize_get_kr(kr) != KERN_SUCCESS) {
		printf("%s: VM_SANITIZE_FLAGS_SIZE_ZERO_FALLTHROUGH failed for offset %p "
		    "size %p\n", __func__, (void *)VM_SANITIZE_UNSAFE_UNWRAP(offset_u),
		    (void *)VM_SANITIZE_UNSAFE_UNWRAP(size_u));
		return false;
	}

	/*
	 * VM_SANITIZE_FLAGS_GET_UNALIGNED_VALUES should return unaligned values
	 */
	offset_u = vm_sanitize_wrap_addr(PAGE_SIZE + 1);
	size_u = vm_sanitize_wrap_size(PAGE_SIZE + 1);
	kr = KERN_SUCCESS;
	kr = vm_sanitize_size(offset_u, size_u, VM_SANITIZE_CALLER_TEST, current_map(),
	    VM_SANITIZE_FLAGS_GET_UNALIGNED_VALUES | VM_SANITIZE_FLAGS_SIZE_ZERO_FALLTHROUGH,
	    &size);

	if ((vm_sanitize_get_kr(kr) != KERN_SUCCESS) ||
	    (size != PAGE_SIZE + 1)) {
		printf("%s: VM_SANITIZE_FLAGS_GET_UNALIGNED_VALUES failed for offset %p size %p\n",
		    __func__, (void *)VM_SANITIZE_UNSAFE_UNWRAP(offset_u),
		    (void *)VM_SANITIZE_UNSAFE_UNWRAP(size_u));
		return false;
	}

	/*
	 * Values that overflow
	 */
	offset_u = vm_sanitize_wrap_addr(2 * PAGE_SIZE);
	size_u = vm_sanitize_wrap_size(-PAGE_SIZE - 1);
	kr = KERN_SUCCESS;
	kr = vm_sanitize_size(offset_u, size_u, VM_SANITIZE_CALLER_TEST, current_map(),
	    VM_SANITIZE_FLAGS_SIZE_ZERO_FALLTHROUGH, &size);

	if (vm_sanitize_get_kr(kr) == KERN_SUCCESS) {
		printf("%s: failed for offset %p size %p\n",
		    __func__, (void *)VM_SANITIZE_UNSAFE_UNWRAP(offset_u),
		    (void *)VM_SANITIZE_UNSAFE_UNWRAP(size_u));
		return false;
	}

	/*
	 * Values that overflow when rounding
	 */
	offset_u = vm_sanitize_wrap_addr(0);
	size_u = vm_sanitize_wrap_size(-1);
	kr = KERN_SUCCESS;
	kr = vm_sanitize_size(offset_u, size_u, VM_SANITIZE_CALLER_TEST, current_map(),
	    VM_SANITIZE_FLAGS_SIZE_ZERO_FALLTHROUGH, &size);

	if (vm_sanitize_get_kr(kr) == KERN_SUCCESS) {
		printf("%s: failed for offset %p size %p\n",
		    __func__, (void *)VM_SANITIZE_UNSAFE_UNWRAP(offset_u),
		    (void *)VM_SANITIZE_UNSAFE_UNWRAP(size_u));
		return false;
	}

	/*
	 * Values that overflow when rounding
	 */
	offset_u = vm_sanitize_wrap_addr(-2);
	size_u = vm_sanitize_wrap_size(1);
	kr = KERN_SUCCESS;
	kr = vm_sanitize_size(offset_u, size_u, VM_SANITIZE_CALLER_TEST, current_map(),
	    VM_SANITIZE_FLAGS_SIZE_ZERO_FALLTHROUGH, &size);

	if (vm_sanitize_get_kr(kr) == KERN_SUCCESS) {
		printf("%s: failed for offset %p size %p\n",
		    __func__, (void *)VM_SANITIZE_UNSAFE_UNWRAP(offset_u),
		    (void *)VM_SANITIZE_UNSAFE_UNWRAP(size_u));
		return false;
	}

	printf("%s: passed\n", __func__);

	return true;
}

static bool
vm_sanitize_addr_size_test(void)
{
	kern_return_t kr = KERN_SUCCESS;
	vm_map_address_t start, end;
	vm_map_size_t size;
	vm_addr_struct_t offset_u;
	vm_size_struct_t size_u;

	/*
	 * VM_SANITIZE_FLAGS_CHECK_ALIGNED_START should fail on passing unaligned offset
	 */
	offset_u = vm_sanitize_wrap_addr(PAGE_SIZE + 1);
	size_u = vm_sanitize_wrap_size(PAGE_SIZE);

	kr = vm_sanitize_addr_size(offset_u, size_u, VM_SANITIZE_CALLER_TEST, PAGE_MASK,
	    VM_SANITIZE_FLAGS_CHECK_ALIGNED_START | VM_SANITIZE_FLAGS_SIZE_ZERO_FALLTHROUGH,
	    &start, &end, &size);

	if (vm_sanitize_get_kr(kr) == KERN_SUCCESS) {
		printf("%s: VM_SANITIZE_FLAGS_CHECK_ALIGNED_START failed for offset %p size %p\n",
		    __func__, (void *)VM_SANITIZE_UNSAFE_UNWRAP(offset_u),
		    (void *)VM_SANITIZE_UNSAFE_UNWRAP(size_u));
		return false;
	}

	/*
	 * VM_SANITIZE_FLAGS_SIZE_ZERO_SUCCEEDS should return VM_ERR_RETURN_NOW for size = 0
	 * for callers that need to return success early
	 */
	offset_u = vm_sanitize_wrap_addr(PAGE_SIZE + 1);
	size_u = vm_sanitize_wrap_size(0);
	kr = KERN_SUCCESS;
	kr = vm_sanitize_addr_size(offset_u, size_u, VM_SANITIZE_CALLER_TEST, PAGE_MASK,
	    VM_SANITIZE_FLAGS_SIZE_ZERO_SUCCEEDS, &start, &end,
	    &size);

	if (vm_sanitize_get_kr(kr) != KERN_SUCCESS ||
	    kr != VM_ERR_RETURN_NOW) {
		printf("%s: VM_SANITIZE_FLAGS_SIZE_ZERO_SUCCEEDS failed for offset %p size %p\n",
		    __func__, (void *)VM_SANITIZE_UNSAFE_UNWRAP(offset_u),
		    (void *)VM_SANITIZE_UNSAFE_UNWRAP(size_u));
		return false;
	}

	/*
	 * VM_SANITIZE_FLAGS_SIZE_ZERO_FAILS should return failure for size = 0
	 */
	offset_u = vm_sanitize_wrap_addr(PAGE_SIZE + 1);
	size_u = vm_sanitize_wrap_size(0);
	kr = KERN_SUCCESS;
	kr = vm_sanitize_addr_size(offset_u, size_u, VM_SANITIZE_CALLER_TEST, PAGE_MASK,
	    VM_SANITIZE_FLAGS_SIZE_ZERO_FAILS, &start, &end,
	    &size);

	if (vm_sanitize_get_kr(kr) == KERN_SUCCESS) {
		printf("%s: VM_SANITIZE_FLAGS_SIZE_ZERO_FAILS failed for offset %p size %p\n",
		    __func__, (void *)VM_SANITIZE_UNSAFE_UNWRAP(offset_u),
		    (void *)VM_SANITIZE_UNSAFE_UNWRAP(size_u));
		return false;
	}

	/*
	 * VM_SANITIZE_FLAGS_SIZE_ZERO_FALLTHROUGH should return success for size = 0
	 */
	offset_u = vm_sanitize_wrap_addr(PAGE_SIZE + 1);
	size_u = vm_sanitize_wrap_size(0);
	kr = KERN_SUCCESS;
	kr = vm_sanitize_addr_size(offset_u, size_u, VM_SANITIZE_CALLER_TEST, PAGE_MASK,
	    VM_SANITIZE_FLAGS_SIZE_ZERO_FALLTHROUGH, &start,
	    &end, &size);

	if ((vm_sanitize_get_kr(kr) != KERN_SUCCESS) ||
	    (start != PAGE_SIZE) || (end != PAGE_SIZE)) {
		printf("%s: VM_SANITIZE_FLAGS_SIZE_ZERO_FALLTHROUGH failed for offset %p "
		    "size %p\n", __func__, (void *)VM_SANITIZE_UNSAFE_UNWRAP(offset_u),
		    (void *)VM_SANITIZE_UNSAFE_UNWRAP(size_u));
		return false;
	}

	/*
	 * VM_SANITIZE_FLAGS_GET_UNALIGNED_VALUES should return unaligned values
	 */
	offset_u = vm_sanitize_wrap_addr(PAGE_SIZE + 1);
	size_u = vm_sanitize_wrap_size(PAGE_SIZE);
	kr = KERN_SUCCESS;
	kr = vm_sanitize_addr_size(offset_u, size_u, VM_SANITIZE_CALLER_TEST, PAGE_MASK,
	    VM_SANITIZE_FLAGS_GET_UNALIGNED_VALUES | VM_SANITIZE_FLAGS_SIZE_ZERO_FALLTHROUGH,
	    &start, &end, &size);

	if ((vm_sanitize_get_kr(kr) != KERN_SUCCESS) ||
	    (start != PAGE_SIZE + 1) || (end != 2 * PAGE_SIZE + 1)) {
		printf("%s: VM_SANITIZE_FLAGS_GET_UNALIGNED_VALUES failed for offset %p size %p\n",
		    __func__, (void *)VM_SANITIZE_UNSAFE_UNWRAP(offset_u),
		    (void *)VM_SANITIZE_UNSAFE_UNWRAP(size_u));
		return false;
	}


	/*
	 * VM_SANITIZE_FLAGS_REALIGN_START should not use unaligned values for sanitization
	 */
	offset_u = vm_sanitize_wrap_addr(PAGE_SIZE + 1);
	size_u = vm_sanitize_wrap_size(PAGE_SIZE);
	kr = KERN_SUCCESS;
	kr = vm_sanitize_addr_size(offset_u, size_u, VM_SANITIZE_CALLER_TEST, PAGE_MASK,
	    VM_SANITIZE_FLAGS_REALIGN_START | VM_SANITIZE_FLAGS_SIZE_ZERO_FALLTHROUGH,
	    &start, &end, &size);

	if ((vm_sanitize_get_kr(kr) != KERN_SUCCESS) ||
	    (start != PAGE_SIZE) || (end != 2 * PAGE_SIZE)) {
		printf("%s: VM_SANITIZE_FLAGS_REALIGN_START failed for offset %p size %p\n",
		    __func__, (void *)VM_SANITIZE_UNSAFE_UNWRAP(offset_u),
		    (void *)VM_SANITIZE_UNSAFE_UNWRAP(size_u));
		return false;
	}

	/*
	 * Values that overflow
	 */
	offset_u = vm_sanitize_wrap_addr(2 * PAGE_SIZE);
	size_u = vm_sanitize_wrap_size(-PAGE_SIZE - 1);
	kr = KERN_SUCCESS;
	kr = vm_sanitize_addr_size(offset_u, size_u, VM_SANITIZE_CALLER_TEST, PAGE_MASK,
	    VM_SANITIZE_FLAGS_SIZE_ZERO_FALLTHROUGH, &start,
	    &end, &size);

	if (vm_sanitize_get_kr(kr) == KERN_SUCCESS) {
		printf("%s: failed for offset %p size %p\n",
		    __func__, (void *)VM_SANITIZE_UNSAFE_UNWRAP(offset_u),
		    (void *)VM_SANITIZE_UNSAFE_UNWRAP(size_u));
		return false;
	}

	printf("%s: passed\n", __func__);

	return true;
}

static bool
vm_sanitize_prot_test(void)
{
	kern_return_t kr = KERN_SUCCESS;
	vm_prot_ut prot_u;
	vm_prot_t prot;

	prot_u = vm_sanitize_wrap_prot(VM_PROT_NO_CHANGE_LEGACY |
	    VM_PROT_NO_CHANGE |
	    VM_PROT_COPY |
	    VM_PROT_WANTS_COPY |
	    VM_PROT_TRUSTED |
	    VM_PROT_IS_MASK |
	    VM_PROT_STRIP_READ |
	    VM_PROT_EXECUTE_ONLY |
	    VM_PROT_COPY_FAIL_IF_EXECUTABLE |
	    VM_PROT_TPRO);

	kr = vm_sanitize_prot(prot_u, VM_SANITIZE_CALLER_TEST, current_map(),
	    VM_PROT_NONE, &prot);

	if (kr == KERN_SUCCESS) {
		printf("%s: failed for invalid set of permissions\n", __func__);
		return false;
	}

	printf("%s: passed\n", __func__);

	return true;
}

static bool
vm_sanitize_cur_and_max_prots_test(void)
{
	kern_return_t kr = KERN_SUCCESS;
	vm_prot_ut cur_prot_u, max_prot_u;
	vm_prot_t cur_prot, max_prot;

	/*
	 * Validate that incompatible prots are rejected
	 */
	cur_prot_u = vm_sanitize_wrap_prot(VM_PROT_ALL);
	max_prot_u = vm_sanitize_wrap_prot(VM_PROT_READ);
	kr = vm_sanitize_cur_and_max_prots(cur_prot_u, max_prot_u, VM_SANITIZE_CALLER_TEST,
	    current_map(), VM_PROT_NONE, &cur_prot,
	    &max_prot);

	if (kr == KERN_SUCCESS) {
		printf("%s: failed for invalid set of permissions\n", __func__);
		return false;
	}
	printf("%s: passed\n", __func__);

	return true;
}

static bool
vm_sanitize_prot_bsd_test(void)
{
	vm_prot_ut prot_u;
	vm_prot_t prot;

	prot_u = vm_sanitize_wrap_prot(VM_PROT_NO_CHANGE_LEGACY |
	    VM_PROT_NO_CHANGE |
	    VM_PROT_COPY |
	    VM_PROT_WANTS_COPY |
	    VM_PROT_IS_MASK |
	    VM_PROT_COPY_FAIL_IF_EXECUTABLE |
	    VM_PROT_TPRO);

	prot = vm_sanitize_prot_bsd(prot_u, VM_SANITIZE_CALLER_TEST);

	if (prot != VM_PROT_NONE) {
		printf("%s: failed to strip invalid permissions\n", __func__);
		return false;
	}

	printf("%s: passed\n", __func__);

	return true;
}

static bool
vm_sanitize_memory_entry_perm_test(void)
{
	kern_return_t kr = KERN_SUCCESS;
	vm_prot_ut perm_u;
	vm_prot_t perm;

	/*
	 * Ensure invalid map_mem_flags is rejected
	 */
	perm_u = vm_sanitize_wrap_prot(0x001000);
	kr = vm_sanitize_memory_entry_perm(perm_u, VM_SANITIZE_CALLER_TEST,
	    VM_SANITIZE_FLAGS_CHECK_USER_MEM_MAP_FLAGS,
	    VM_PROT_IS_MASK, &perm);

	if (kr == KERN_SUCCESS) {
		printf("%s: failed to reject invalid map_mem_flags\n", __func__);
		return false;
	}

	/*
	 * Ensure invalid prot bits are cleared
	 */
	kr = KERN_SUCCESS;
	perm_u = vm_sanitize_wrap_prot(VM_PROT_NO_CHANGE_LEGACY |
	    VM_PROT_NO_CHANGE |
	    VM_PROT_COPY |
	    VM_PROT_WANTS_COPY |
	    VM_PROT_EXECUTE_ONLY |
	    VM_PROT_COPY_FAIL_IF_EXECUTABLE |
	    VM_PROT_TPRO);
	kr = vm_sanitize_memory_entry_perm(perm_u, VM_SANITIZE_CALLER_TEST,
	    VM_SANITIZE_FLAGS_CHECK_USER_MEM_MAP_FLAGS,
	    VM_PROT_IS_MASK, &perm);

	if (perm != VM_PROT_NONE) {
		printf("%s: failed to clear invalid prot bits\n", __func__);
		return false;
	}

	printf("%s: passed\n", __func__);

	return true;
}

static bool
vm_sanitize_inherit_test(void)
{
	kern_return_t kr = KERN_SUCCESS;
	vm_inherit_ut inherit_u;
	vm_inherit_t inherit;

	/*
	 * Ensure invalid values are rejected
	 */
	inherit_u = vm_sanitize_wrap_inherit(VM_INHERIT_DONATE_COPY);
	kr = vm_sanitize_inherit(inherit_u, VM_SANITIZE_CALLER_TEST, &inherit);

	if (kr == KERN_SUCCESS) {
		printf("%s: failed to reject invalid inherit values\n", __func__);
		return false;
	}
	printf("%s: passed\n", __func__);

	return true;
}

static bool
vm_sanitize_behavior_test(void)
{
	kern_return_t kr = KERN_SUCCESS;
	vm_behavior_ut behavior_u;
	vm_behavior_t behavior;

	/*
	 * Ensure invalid values are rejected
	 */
	behavior_u = vm_sanitize_wrap_behavior(VM_BEHAVIOR_LAST_VALID + 1);
	kr = vm_sanitize_behavior(behavior_u, VM_SANITIZE_CALLER_TEST, &behavior);

	if (kr == KERN_SUCCESS) {
		printf("%s: failed to reject invalid behavior value\n", __func__);
		return false;
	}
	printf("%s: passed\n", __func__);

	return true;
}

/*
 * Verify that u0..u15 == t_arg[0]..t_arg[15], then return ret.
 * If there are ABI problems then the parameters or return
 * value may be passed incorrectly. We use a large number
 * of parameters in order to fill the ABI's parameter
 * registers and spill onto the stack.
 */
#define TEST_UT_TYPE_ABI_UT_CALLEE(type_t, type_ut, equal, t_arg)       \
	static_assert(sizeof(type_ut) == sizeof(type_t));               \
	static_assert(__alignof__(type_ut) == __alignof__(type_t));     \
                                                                        \
	__attribute__((used, noinline))                                 \
	static type_ut                                                  \
	vm_sanitize_test_##type_ut##_callee(                            \
	        type_ut u0,  type_ut u1,  type_ut u2,  type_ut u3,      \
	        type_ut u4,  type_ut u5,  type_ut u6,  type_ut u7,      \
	        type_ut u8,  type_ut u9,  type_ut u10, type_ut u11,     \
	        type_ut u12, type_ut u13, type_ut u14, type_ut u15,     \
	        type_ut ret,                                            \
	        bool *out_params_ok) {                                  \
	        asm("");                                                \
                                                                        \
	        *out_params_ok = (                                      \
	                equal(u0.UNSAFE,  t_arg[0])  && equal(u1.UNSAFE,  t_arg[1])  && \
	                equal(u2.UNSAFE,  t_arg[2])  && equal(u3.UNSAFE,  t_arg[3])  && \
	                equal(u4.UNSAFE,  t_arg[4])  && equal(u5.UNSAFE,  t_arg[5])  && \
	                equal(u6.UNSAFE,  t_arg[6])  && equal(u7.UNSAFE,  t_arg[7])  && \
	                equal(u8.UNSAFE,  t_arg[8])  && equal(u9.UNSAFE,  t_arg[9])  && \
	                equal(u10.UNSAFE, t_arg[10]) && equal(u11.UNSAFE, t_arg[11]) && \
	                equal(u12.UNSAFE, t_arg[12]) && equal(u13.UNSAFE, t_arg[13]) && \
	                equal(u14.UNSAFE, t_arg[14]) && equal(u15.UNSAFE, t_arg[15]) \
	                );                                              \
                                                                        \
	/* return value is checked by the caller */             \
	        return ret;                                             \
}

/*
 * Make a function pointer that points to the function above,
 * but with a function type that has type_t parameters
 * instead of type_ut.
 *
 * This is the same type mismatch that occurs when
 * the call site is outside the trust boundary and
 * the callee is inside it.
 */
#define TEST_UT_TYPE_ABI_T_CALLEE(type_t, type_ut)                      \
	typedef type_t                                                  \
	(*vm_sanitize_test_##type_t##_callee_t)(                        \
	        type_t u0,  type_t u1,  type_t u2,  type_t u3,          \
	        type_t u4,  type_t u5,  type_t u6,  type_t u7,          \
	        type_t u8,  type_t u9,  type_t u10, type_t u11,         \
	        type_t u12, type_t u13, type_t u14, type_t u15,         \
	        type_t ret,                                             \
	        bool *out_params_ok);                                   \
	_Pragma("clang diagnostic push")                                \
	_Pragma("clang diagnostic ignored \"-Wcast-align\"")            \
	_Pragma("clang diagnostic ignored \"-Wcast-function-type\"")    \
	static vm_sanitize_test_##type_t##_callee_t                     \
	volatile vm_sanitize_test_##type_t##_callee =                   \
	    (vm_sanitize_test_##type_t##_callee_t)                      \
	    vm_sanitize_test_##type_ut##_callee;                        \
	_Pragma("clang diagnostic pop")

/* Verify type_t actual parameters passed to type_ut formal parameters */
#define TEST_UT_TYPE_ABI_T_CALLER(type_t, type_ut, equal, t_arg)        \
	static void                                                     \
	vm_sanitize_test_##type_t##_abi(                                \
	        bool *out_params_ok,                                    \
	        bool *out_ret_ok) {                                     \
                                                                        \
	        type_t t_ret = vm_sanitize_test_##type_t##_callee(      \
	                t_arg[0],  t_arg[1],  t_arg[2],  t_arg[3],      \
	                t_arg[4],  t_arg[5],  t_arg[6],  t_arg[7],      \
	                t_arg[8],  t_arg[9],  t_arg[10], t_arg[11],     \
	                t_arg[12], t_arg[13], t_arg[14], t_arg[15],     \
	                t_arg[16],                                      \
	                out_params_ok);                                 \
	        *out_ret_ok = equal(t_ret, t_arg[16]);                  \
	}

/* Verify type_ut actual parameters passed to type_ut formal parameters */
#define TEST_UT_TYPE_ABI_UT_CALLER(type_t, type_ut, equal, t_arg)       \
	static void                                                     \
	vm_sanitize_test_##type_ut##_abi(                               \
	        bool *out_params_ok,                                    \
	        bool *out_ret_ok) {                                     \
                                                                        \
	        type_ut ut_ret = vm_sanitize_test_##type_ut##_callee(   \
	                (type_ut){t_arg[0]},  (type_ut){t_arg[1]},      \
	                (type_ut){t_arg[2]},  (type_ut){t_arg[3]},      \
	                (type_ut){t_arg[4]},  (type_ut){t_arg[5]},      \
	                (type_ut){t_arg[6]},  (type_ut){t_arg[7]},      \
	                (type_ut){t_arg[8]},  (type_ut){t_arg[9]},      \
	                (type_ut){t_arg[10]}, (type_ut){t_arg[11]},     \
	                (type_ut){t_arg[12]}, (type_ut){t_arg[13]},     \
	                (type_ut){t_arg[14]}, (type_ut){t_arg[15]},     \
	                (type_ut){t_arg[16]},                           \
	                out_params_ok);                                 \
	        *out_ret_ok = equal(ut_ret.UNSAFE, t_arg[16]);          \
	}

/*
 * Generate ABI testing functions for one type `type_t`
 * and its unsafe type `type_ut`.
 *
 * `equal(a, b)` is a function or macro that compares two `type_t`.
 */
#define TEST_UT_TYPE_ABI(type_t, type_ut, equal) \
	TEST_UT_TYPE_ABI_UT_CALLEE(type_t, type_ut, equal, vm_sanitize_test_##type_t##_args) \
	TEST_UT_TYPE_ABI_T_CALLEE(type_t, type_ut)                      \
	TEST_UT_TYPE_ABI_T_CALLER(type_t, type_ut, equal, vm_sanitize_test_##type_t##_args) \
	TEST_UT_TYPE_ABI_UT_CALLER(type_t, type_ut, equal, vm_sanitize_test_##type_t##_args) \

/* our test macro requires a single-token type name, not `struct mach_vm_range` */
typedef struct mach_vm_range mach_vm_range_s;

/* mach_vm_range_us does not exist, but we'll create it for this test */
VM_GENERATE_UNSAFE_TYPE(mach_vm_range_s, mach_vm_range_us);

/*
 * Parameter values to test. 16 input values plus 1 return value.
 * These arrays are used inside the macros above under the name `t_arg`.
 */
#define V 0xF89aFb00
static vm_behavior_t vm_sanitize_test_vm_behavior_t_args[17] = {
	V + 0, V + 1, V + 2, V + 3,
	V + 4, V + 5, V + 6, V + 7,
	V + 8, V + 9, V + 10, V + 11,
	V + 12, V + 13, V + 14, V + 15,
	V + 16
};
#undef V
#define V 0xF89aFb00u
static const vm_inherit_t vm_sanitize_test_vm_inherit_t_args[17] = {
	V + 0, V + 1, V + 2, V + 3,
	V + 4, V + 5, V + 6, V + 7,
	V + 8, V + 9, V + 10, V + 11,
	V + 12, V + 13, V + 14, V + 15,
	V + 16
};
#undef V
#define V 0xF1234567F89aFb00ull
static const mach_vm_address_t vm_sanitize_test_mach_vm_address_t_args[17] = {
	V + 0, V + 1, V + 2, V + 3,
	V + 4, V + 5, V + 6, V + 7,
	V + 8, V + 9, V + 10, V + 11,
	V + 12, V + 13, V + 14, V + 15,
	V + 16
};
#undef V
#define V 0xF1234567F89aFb00ull
static const mach_vm_range_s vm_sanitize_test_mach_vm_range_s_args[17] = {
	{V, V + 0x10000000100 * 0}, {V, V + 0x10000000100 * 1},
	{V, V + 0x10000000100 * 2}, {V, V + 0x10000000100 * 3},
	{V, V + 0x10000000100 * 4}, {V, V + 0x10000000100 * 5},
	{V, V + 0x10000000100 * 6}, {V, V + 0x10000000100 * 7},
	{V, V + 0x10000000100 * 8}, {V, V + 0x10000000100 * 9},
	{V, V + 0x10000000100 * 10}, {V, V + 0x10000000100 * 11},
	{V, V + 0x10000000100 * 12}, {V, V + 0x10000000100 * 13},
	{V, V + 0x10000000100 * 14}, {V, V + 0x10000000100 * 15},
	{V, V + 0x10000000100 * 16},
};
#undef V

#define equal_scalar(a, b) (a) == (b)
#define equal_range(a, b) \
	((a).min_address == (b).min_address && (a).max_address == (b).max_address)

/* signed int */
TEST_UT_TYPE_ABI(vm_behavior_t, vm_behavior_ut, equal_scalar);
/* unsigned int */
TEST_UT_TYPE_ABI(vm_inherit_t, vm_inherit_ut, equal_scalar);
/* pointer-size int */
TEST_UT_TYPE_ABI(mach_vm_address_t, mach_vm_address_ut, equal_scalar);
/* struct of two pointer-sized ints */
TEST_UT_TYPE_ABI(mach_vm_range_s, mach_vm_range_us, equal_range);

#undef equal_scalar
#undef equal_struct

/* Call the ABI test function for one type and complain if it failed. */
static bool
vm_sanitize_test_one_abi(void (*test_t)(bool*, bool*), const char *t_name)
{
	bool params_ok, ret_ok;

	test_t(&params_ok, &ret_ok);

	if (!params_ok) {
		printf("vm_sanitize_ut_type_abi_test: mismatched %s parameter\n", t_name);
		return false;
	}
	if (!ret_ok) {
		printf("vm_sanitize_ut_type_abi_test: mismatched %s return\n", t_name);
		return false;
	}
	return true;
}

/*
 * Verify that the ABI conventions of a _ut type and its _t counterpart match.
 *
 * Sanitized types means that external call sites use type_t parameters and
 * internal definitions use type_ut parameters. Any mismatch between
 * type_t and type_ut at the function call ABI level may cause misinterpreted
 * parameter values or data type layouts.
 *
 * - same sizeof
 * - same alignof
 * - type_t actual parameter passed to type_ut formal parameter
 * - type_ut actual return value returned to type_t formal return
 */
static bool
vm_sanitize_ut_type_abi_test(void)
{
	bool passed =
	    vm_sanitize_test_one_abi(vm_sanitize_test_vm_behavior_t_abi, "vm_behavior_t") &&
	    vm_sanitize_test_one_abi(vm_sanitize_test_vm_behavior_ut_abi, "vm_behavior_ut") &&
	    vm_sanitize_test_one_abi(vm_sanitize_test_vm_inherit_t_abi, "vm_inherit_t") &&
	    vm_sanitize_test_one_abi(vm_sanitize_test_vm_inherit_ut_abi, "vm_inherit_ut") &&
	    vm_sanitize_test_one_abi(vm_sanitize_test_mach_vm_address_t_abi, "mach_vm_address_t") &&
	    vm_sanitize_test_one_abi(vm_sanitize_test_mach_vm_address_ut_abi, "mach_vm_address_ut") &&
	    vm_sanitize_test_one_abi(vm_sanitize_test_mach_vm_range_s_abi, "mach_vm_range_s") &&
	    vm_sanitize_test_one_abi(vm_sanitize_test_mach_vm_range_us_abi, "mach_vm_range_us");

	if (passed) {
		printf("%s: passed\n", __func__);
	}
	return passed;
}

static int
vm_sanitize_run_test(int64_t in __unused, int64_t *out)
{
	*out = 0;

	if (!vm_sanitize_offset_test() ||
	    !vm_sanitize_size_test() ||
	    !vm_sanitize_addr_size_test() ||
	    !vm_sanitize_prot_test() ||
	    !vm_sanitize_cur_and_max_prots_test() ||
	    !vm_sanitize_prot_bsd_test() ||
	    !vm_sanitize_memory_entry_perm_test() ||
	    !vm_sanitize_inherit_test() ||
	    !vm_sanitize_behavior_test() ||
	    !vm_sanitize_ut_type_abi_test()) {
		return 0;
	}

	printf("%s: All tests passed\n", __func__);
	*out = 1;
	return 0;
}
SYSCTL_TEST_REGISTER(vm_sanitize_test, vm_sanitize_run_test);
#endif /* DEBUG || DEVELOPMENT */

#if PAGE_SHIFT == 0
#pragma clang attribute pop
#endif

#if !__OPTIMIZE__
#pragma clang attribute pop
#endif
