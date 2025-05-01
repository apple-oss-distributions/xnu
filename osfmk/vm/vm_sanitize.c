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
		*addr = vm_memtag_canonicalize_kernel(*addr);
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
		/*
		 * NOTE: these early returns bypass the VM_SANITIZE_FLAGS_CHECK_ADDR_RANGE
		 * check. Since the size is 0, the range [start, end) is empty and thus
		 * no values within this range can overflow the upper bits.
		 */
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

	if (flags & VM_SANITIZE_FLAGS_CHECK_ADDR_RANGE) {
#if defined(__arm64__) && MACH_ASSERT
		/*
		 * Make sure that this fails noisily if someone adds support for large
		 * VA extensions. With such extensions, this code will have to check
		 * ID_AA64MMFR2_EL1 to get the actual max VA size for the system,
		 * instead of assuming it is 48 bits.
		 */
		assert((__builtin_arm_rsr64("ID_AA64MMFR2_EL1") & ID_AA64MMFR2_EL1_VARANGE_MASK) == 0);
#endif /* defined(__arm64__) && MACH_ASSERT */
		const uint64_t max_va_bits = 48;
		const mach_vm_offset_t va_range_upper_bound = (1ULL << max_va_bits);
		const mach_vm_offset_t va_mask = va_range_upper_bound - 1;

		if ((*addr & ~va_mask) != (*end & ~va_mask)) {
			if (*end == va_range_upper_bound) {
				/*
				 * Since the range is exclusive of `end`, the range [start, end)
				 * does not include any invalid values in this case. Therefore,
				 * we treat this as a success and fall through.
				 */
			} else {
				/*
				 * This means iterating within the range [start, end) may
				 * overflow above the VA bits supported by the system. Since
				 * these bits may be used by the kernel or hardware to store
				 * other values, we should not allow the operation to proceed.
				 */
				kr = KERN_INVALID_ADDRESS;
				goto unsanitary;
			}
		}
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


#if PAGE_SHIFT == 0
#pragma clang attribute pop
#endif

#if !__OPTIMIZE__
#pragma clang attribute pop
#endif
