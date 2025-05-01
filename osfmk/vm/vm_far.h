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

#pragma once
#ifdef KERNEL_PRIVATE
#include <stdint.h>
#include <stddef.h>
#include <sys/cdefs.h>
#include <stdbool.h>
#include <kern/panic_call.h>

#ifdef __arm64__
#include <arm64/speculation.h>
#endif /* __arm64__ */

/*
 * The VM_FAR poison is set in a pointer's top 16 bits when its offset exceeds
 * the VM_FAR bounds.
 */
#define VM_FAR_POISON_VALUE (0x2BADULL)
#define VM_FAR_POISON_SHIFT (48)
#define VM_FAR_POISON_MASK (0xFFFFULL << VM_FAR_POISON_SHIFT)
#define VM_FAR_POISON_BITS (VM_FAR_POISON_VALUE << VM_FAR_POISON_SHIFT)

#define VM_FAR_ACCESSOR

__pure2
__attribute__((always_inline))
static inline void *
vm_far_add_ptr_internal(void *ptr, uint64_t idx, size_t elem_size,
    bool __unused idx_small)
{

	uintptr_t ptr_i = (uintptr_t)(ptr);
	uintptr_t new_ptr_i = ptr_i + (idx * elem_size);


	return __unsafe_forge_single(void *, new_ptr_i);
}

__attribute__((always_inline))
static inline void *
vm_far_add_ptr_bounded_fatal_unsigned_internal(void *ptr, uint64_t idx,
    size_t count, size_t elem_size, bool __unused idx_small)
{
	void *__single new_ptr = vm_far_add_ptr_internal(
		ptr, idx, elem_size,
		/*
		 * Since we're bounds checking the index, we can support small index
		 * optimizations even when the index is large.
		 */
		/* idx_small */ false);

	bool guarded_ptr_valid;
	void *__single guarded_ptr;
#if __arm64__
	/* Guard passes if idx < count */
	SPECULATION_GUARD_ZEROING_XXX(
		/* out */ guarded_ptr, /* out_valid */ guarded_ptr_valid,
		/* value */ new_ptr,
		/* cmp1 */ idx, /* cmp2 */ count,
		/* cc */ "LO");
#else
	/*
	 * We don't support guards on this target, so just perform a normal bounds
	 * check.
	 */
	guarded_ptr_valid = idx < count;
	guarded_ptr = new_ptr;
#endif /* __arm64__ */

	if (__improbable(!guarded_ptr_valid)) {
		panic("vm_far bounds check failed idx=%llu/count=%zu", idx, count);
	}

	return guarded_ptr;
}

__pure2
__attribute__((always_inline))
static inline void *
vm_far_add_ptr_bounded_poison_unsigned_internal(void *ptr, uint64_t idx,
    size_t count, size_t elem_size, bool __unused idx_small)
{
	void *__single new_ptr = vm_far_add_ptr_internal(
		ptr, idx, elem_size,
		/*
		 * Since we're bounds checking the index, we can support small index
		 * optimizations even when the index is large.
		 */
		/* idx_small */ false);

	void *__single guarded_ptr;

	/*
	 * Poison the top 16-bits with a well-known code so that later dereferences
	 * of the poisoned pointer are easy to identify.
	 */
	uintptr_t poisoned_ptr_i = (uintptr_t)new_ptr;
	poisoned_ptr_i &= ~VM_FAR_POISON_MASK;
	poisoned_ptr_i |= VM_FAR_POISON_BITS;

#if __arm64__
	SPECULATION_GUARD_SELECT_XXX(
		/* out  */ guarded_ptr,
		/* cmp1 */ idx, /* cmp2 */ count,
		/* cc   */ "LO", /* value_cc */ (uintptr_t)new_ptr,
		/* n_cc */ "HS", /* value_n_cc */ poisoned_ptr_i);
#else
	/*
	 * We don't support guards on this target, so just perform a normal bounds
	 * check.
	 */
	if (__probable(idx < count)) {
		guarded_ptr = new_ptr;
	} else {
		guarded_ptr = __unsafe_forge_single(void *, poisoned_ptr_i);
	}
#endif /* __arm64__ */

	return guarded_ptr;
}

/**
 * Compute &PTR[IDX] without enforcing VM_FAR.
 *
 * In this variant, IDX will not be bounds checked.
 */
#define VM_FAR_ADD_PTR_UNBOUNDED(ptr, idx) \
	((__typeof__((ptr))) vm_far_add_ptr_internal( \
	        (ptr), (idx), sizeof(__typeof__(*(ptr))), sizeof((idx)) <= 4))

/**
 * Compute &PTR[IDX] without enforcing VM_FAR.
 *
 * If the unsigned IDX value exceeds COUNT, trigger a panic.
 */
#define VM_FAR_ADD_PTR_BOUNDED_FATAL_UNSIGNED(ptr, idx, count) \
	((__typeof__((ptr))) vm_far_add_ptr_bounded_fatal_unsigned_internal( \
	        (ptr), (idx), (count), sizeof(__typeof__(*(ptr))), \
	        sizeof((idx)) <= 4))

/**
 * Compute &PTR[IDX] without enforcing VM_FAR.
 *
 * If the unsigned IDX value exceeds COUNT, poison the pointer such that
 * attempting to dereference it will fault.
 */
#define VM_FAR_ADD_PTR_BOUNDED_POISON_UNSIGNED(ptr, idx, count) \
	((__typeof__((ptr))) vm_far_add_ptr_bounded_poison_unsigned_internal( \
	        (ptr), (idx), (count), sizeof(__typeof__(*(ptr))), \
	        sizeof((idx)) <= 4))

#endif /* KERNEL_PRIVATE */
