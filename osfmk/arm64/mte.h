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

#ifndef _ARM64_MTE_H_
#define _ARM64_MTE_H_

#include <sys/types.h>

#if XNU_KERNEL_PRIVATE
#include <vm/vm_memtag.h>
#if DEVELOPMENT || DEBUG
extern void mte_validate_tco_state(void);
#endif /* DEVELOPMENT || DEBUG */
#else /* XNU_KERNEL_PRIVATE */
#include <assert.h>
#include <strings.h>
#define mte_validate_tco_state()        do { } while(0)
#endif /* XNU_KERNEL_PRIVATE */

#include <arm_acle.h>

__BEGIN_DECLS

/**
 * The interfaces provided here rely on the MTE ISA being available at compile
 * time, and on MTE being enabled in the process being executed at runtime.
 * It is a responsibility of clients of this API to check that to ensure the
 * correct behaviour.
 */

/**
 * @typedef mte_exclude_mask_t
 *
 * @abstract Represent an MTE tag exclusion mask, used in tag generation.
 */
#ifndef MTE_EXCLUDE_MASK_T
#define MTE_EXCLUDE_MASK_T
typedef uint64_t mte_exclude_mask_t;
#endif /* MTE_EXCLUDE_MASK_T */

#define MTE_TAG_SPAN_SIZE              (16)
#define MTE_TAGS_PER_SIZE(s)           (roundup(s, 16) / MTE_TAG_SPAN_SIZE)
#define MTE_SIZE_TO_ATAG_STORAGE(s)    (MTE_TAGS_PER_SIZE(s) / 2)

/*
 * Helpers for MTE intrinsics.
 * Clang provides a basic set of MTE intrinsics which doesn't cover the
 * whole spectrum of ISA instructions. We provide here the complete set,
 * prefixed under mte_
 */

#pragma mark Tag store operations

/*!
 * @function mte_store_tag_16()
 *
 * @brief
 * Sets the tag for the 16-byte memory span starting at the given address.
 *
 * @discussion
 * This function wraps the ARM __arm_mte_set_tag intrinsic.
 *
 * @param addr  The starting address of the 16-byte span to tag.
 */
static inline void
mte_store_tag_16(void *addr)
{
	__arm_mte_set_tag(addr);
}

/*!
 * @function mte_store_tag_32()
 *
 * @brief
 * Sets the tag for the 32-byte memory span starting at the given address.
 *
 * @discussion
 * This function wraps the ARM ST2G instruction.
 *
 * @param addr  The starting address of the 32-byte span to tag.
 */
static inline void
mte_store_tag_32(void *addr)
{
	__asm__ __volatile__ ("st2g %0, [%0]" : : "r" (addr) : "memory");
}

/*!
 * @function mte_store_tag_64()
 *
 * @brief
 * Sets the tag for the 64-byte memory span starting at the given address.
 *
 * @discussion
 * This function wraps the ARM DC GVA instruction.
 *
 * @param addr  The starting address of the 64-byte span to tag.
 */
static inline void
mte_store_tag_64(void *addr)
{
	__asm__ __volatile__ ("dc gva, %0" : : "r" (addr) : "memory");
}

/*!
 * @function mte_store_tag_small()
 *
 * @brief
 * Sets the tag across a contiguous memory buffer of size smaller than 64 bytes.
 *
 * @warning
 * This function is used by mte_store_tag(), and clients should refrain from
 * calling it directly. The function explicitly asserts on the preconditions
 * of the size of the buffer.
 *
 * @param start The starting address of the buffer.
 * @param end   The end of the buffer.
 */
static inline void
mte_store_tag_small(uintptr_t start, uintptr_t end)
{
	/* Optimize STG/ST2G for sub-64 byte sizes. start and end must be 16-byte aligned. */
	size_t size = end - start;
	assert(size < 64 && size % 16 == 0);

	if (size <= 16) {
		__asm__ __volatile__ ("stg %0, [%0], #16" : "+r" (start) : : "memory");
		return;
	}

	/* At least 32 bytes need to be written */
	__asm__ __volatile__ ("st2g %0, [%0], #32" : "+r" (start) : : "memory");

	// Tag the last 16 bytes
	end -= 16;
	__asm__ __volatile__ ("stg %0, [%0], #16" : "+r" (end) : : "memory");
}

/*
 * When setting tags, the common desire for consumers is to pass an address and
 * an arbitrary size and have the whole buffer tagged with the desired value.
 * We provide an optimized generic tag setting function here.
 */

/*!
 * @function mte_store_tag()
 *
 * @brief
 * Sets the tag across a contiguous memory buffer of arbitrary size.
 *
 * @discussion
 * The buffer is tagged with the logical tag embedded in the pointer
 * @c addr. This function handles alignment and size efficiently using a
 * combination of ST2G and DC GVA instructions. It rounds the effective
 * start and end addresses down/up to 16-byte boundaries respectively.
 *
 * @param addr  A pointer containing the desired logical tag.
 *              The address part is used as the starting point for tagging,
 *              rounded down to 16 bytes.
 * @param size  The size of the buffer to tag, in bytes.
 */
static inline void
mte_store_tag(void *__unsafe_indexable addr, size_t size)
{
	uintptr_t end = (uintptr_t)addr + size;

	uintptr_t ptr = ((uintptr_t)addr & -16);  // round down to 16 bytes alignment
	end = (((uintptr_t)end + 15) & -16);  // round up to 16 bytes alignment

	/* "Fast path" for small allocations */
	if (end - ptr < 64) {
		mte_store_tag_small(ptr, end);
		return;
	}

#if XNU_KERNEL_PRIVATE
	/*
	 * STGM is a privileged instruction that allows to tag 256 bytes at the time.
	 * We can take advantage of it for large buffers in kernel space. For simplicity
	 * we capture here only the case where the alignment is on at least 256 bytes,
	 * so that all page aligned operations get covered by this function. Performance
	 * will tell us if we need to further expand this to potentially misaligned
	 * buffers.
	 */
	if ((vm_map_address_t)ptr % 256 == 0 && ptr + 256 <= end) {
		/*
		 * STGM is special and gets a tag list as a separate parameter. Forge a
		 * tag list out of the pointer LTag.
		 */
		uint64_t tag_list = vm_memtag_extract_tag((vm_address_t)ptr) * 0x1111111111111111ul;

		while (ptr + 256 <= end) {
			__asm__ __volatile__ ("stgm %0, [%1]" : "+r" (tag_list) : "r" (ptr) : "memory");
			ptr += 256;
		}

		/* If we were aligned and a multiple of (common case), we are done. */
		if (ptr == end) {
			return;
		}
		/* For small remainder */
		if (end - ptr < 64) {
			mte_store_tag_small(ptr, end);
			return;
		}
	}
#endif /* XNU_KERNEL_PRIVATE */

	// At least 64 bytes need to be tagged
	// Tag 64 bytes to make sure addr can be aligned to 64 bytes
	__asm__ __volatile__ ("st2g %0, [%0], #32" : "+r" (ptr) : : "memory");
	__asm__ __volatile__ ("st2g %0, [%0], #32" : "+r" (ptr) : : "memory");
	if (ptr == end) {
		return;
	}

	/* Optimize for DC GVA usage */
	ptr = (ptr & -64);  // round down to 64 bytes alignment
	while (ptr + 64 < end) {
		__asm__ __volatile__ ("dc gva, %0" : : "r" (ptr) : "memory");
		ptr += 64;
	}

	// tag the last 64 bytes
	end -= 64;
	__asm__ __volatile__ ("st2g %0, [%0], #32" : "+r" (end) : : "memory");
	__asm__ __volatile__ ("st2g %0, [%0], #32" : "+r" (end) : : "memory");
}

#pragma mark Tag load operations

/*!
 * @function mte_load_tag()
 *
 * @brief
 * Loads the tag associated to the memory address @c addr.
 *
 * @discussion
 * This function wraps the ARM __arm_mte_get_tag intrinsic.
 * The returned pointer has the physical tag associated to @c addr
 * applied to the logical address bits of the pointer itself.
 *
 * @param addr  The address from which to load the tag.
 * @returns     A pointer with the tag from the memory location applied.
 */
static inline void *
mte_load_tag(void *addr)
{
	addr = __arm_mte_get_tag(addr);
	return addr;
}

#pragma mark Tag Check Override operations

/*!
 * @function mte_disable_tag_checking()
 *
 * @brief
 * Disable hardware tag checking for the current thread by setting the
 * PSTATE.TCO bit.
 *
 * @discussion
 * Memory accesses performed while tag checking is disabled will not cause
 * tag check faults. This should be used sparingly and only around specific,
 * validated code paths where tag checking is known to be unnecessary and/or
 * performance-prohibitive. Tag checking should be re-enabled as soon as
 * possible.
 */
static inline void
mte_disable_tag_checking()
{
#if DEVELOPMENT || DEBUG
	mte_validate_tco_state();
#endif /* DEVELOPMENT || DEBUG */
	__asm__ __volatile__ ("msr TCO, #1");
}

/*!
 * @function mte_enable_tag_checking()
 *
 * @brief
 * Re-enables hardware tag checking by clearing the PSTATE.TCO bit.
 *
 * @discussion
 * This should be called after a corresponding call to
 * mte_disable_tag_checking().
 */
static inline void
mte_enable_tag_checking()
{
	__asm__ __volatile__ ("msr TCO, #0");
}

#pragma mark Random Tag Generation helpers

/*!
 * @function mte_update_exclude_mask()
 *
 * @brief
 * Updates an exclusion mask based on the tag of the pointer @c src.
 *
 * @discussion
 * This is typically used before generating a random tag to ensure
 * the newly generated tag is different from an existing tag.
 * This function wraps the ARM __arm_mte_exclude_tag intrinsic.
 *
 * @param src           The pointer whose tag should be added to the
 *                      exclusion mask.
 * @param exclude_mask  The current exclusion mask.
 * @returns             The updated exclusion mask including the tag from
 *                      @c src.
 */
static inline mte_exclude_mask_t
mte_update_exclude_mask(void *src, mte_exclude_mask_t exclude_mask)
{
	return __arm_mte_exclude_tag(src, exclude_mask);
}

/*!
 * @function mte_generate_random_tag()
 *
 * @brief
 * Generates a new random tag for @c target_address, excluding tags
 * specified in the @c exclude_mask.
 *
 * @discussion
 * This function wraps the ARM __arm_mte_create_random_tag intrinsic.
 * The returned pointer has the newly generated random tag applied to
 * the logical tag bits of @c target_address.
 *
 * @param target_address    The base address for which to generate a tag.
 * @param exclude_mask      A mask of tags to exclude from the random
 *                          generation.
 * @returns                 A pointer with the newly generated random tag
 *                          applied.
 */
static inline void *
mte_generate_random_tag(void *target_address, mte_exclude_mask_t exclude_mask)
{
	return __arm_mte_create_random_tag(target_address, exclude_mask);
}

# pragma mark Memory Zeroing helpers

/*!
 * @function mte_bzero_unchecked()
 *
 * @brief
 * Performs a bzero operation on the buffer with hardware tag checking
 * temporarily disabled (PSTATE.TCO=1).
 *
 * @discussion
 * This variant does *not* perform any tag checks on the buffer boundaries.
 *
 * @param buf   The buffer to zero.
 * @param n     The number of bytes to zero.
 */
static inline void
mte_bzero_unchecked(void *__unsafe_indexable buf, size_t n)
{
	mte_disable_tag_checking();
	bzero(__unsafe_forge_bidi_indexable(void *, buf, n), n);
	mte_enable_tag_checking();
}

/*!
 * @function mte_bzero_fast_checked()
 *
 * @brief
 * Performs a bzero operation on the buffer with hardware tag checking
 * temporarily disabled (PSTATE.TCO=1).
 *
 * @discussion
 * Before disabling checking, it performs a checked access to the first
 * and last byte of the buffer to ensure those boundaries are valid
 * according to their current tags. This provides a minimal boundary check
 * while still allowing the core bzero operation to run unchecked for
 * performance.
 *
 * @param buf   The buffer to zero.
 * @param n     The number of bytes to zero.
 */
static inline void
mte_bzero_fast_checked(void *__unsafe_indexable buf, size_t n)
{
	/*
	 * Run zeroing operations with tag checking disabled (PSTATE.TCO=1) to not
	 * trash the G$ and to maximize the pipeline usage. This implies that no checks
	 * are performed on the boundary of the bzero() operation. This is generally
	 * fine because such boundaries are static and derived from the type/entity
	 * that is calling bzero, but notwithstanding this, we touch the first and last
	 * line of the buffer, to ensure that the tagged access succeeds. This has
	 * also the effect of prefetching the associated G$ line(s), which is/are going
	 * to be used shortly after to tag set. If the line is in DRAM, the cost of
	 * prefetching will be partially absorbed while the stream of DC ZVAs is
	 * performed.
	 */
	asm volatile ("ldrb wzr, [%0]" : : "r"(buf) : "memory");
	mte_bzero_unchecked(buf, n);
	asm volatile ("ldrb wzr, [%0]" : : "r"((uintptr_t)buf + n - 1) : "memory");
}

__END_DECLS

#endif /* _ARM64_MTE_H_ */
