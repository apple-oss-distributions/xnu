/*
 * Copyright (c) 2022 Apple Computer, Inc. All rights reserved.
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
#ifndef _MACH_VM_MEMTAG_H_
#define _MACH_VM_MEMTAG_H_

#ifdef  KERNEL

#if __arm64__
#include <pexpert/arm64/board_config.h>
#endif /* __arm64__ */

#include <kern/assert.h>
#include <mach/vm_types.h>
#include <sys/_types/_caddr_t.h>


#if KASAN_TBI
#define ENABLE_MEMTAG_INTERFACES        1
#define ENABLE_MEMTAG_MANIPULATION_API  1
#endif




#if defined(ENABLE_MEMTAG_INTERFACES)

__BEGIN_DECLS

/* Zero-out a tagged memory region performing the minimum set of mandatory checks. */
extern void vm_memtag_fast_checked_bzero(void *tagged_buf, vm_size_t n);

/*
 * Given a naked address, extract the metadata from memory and add it to
 * the correct pointer metadata.
 */
extern vm_map_address_t vm_memtag_load_tag(vm_map_address_t naked_address);

/*
 * Given a tagged pointer and a size, update the associated backing metadata
 * to match the pointer metadata.
 */
extern void
vm_memtag_store_tag(caddr_t tagged_address, vm_size_t size);

/* Randomly assign a tag to the current chunk of memory. */
extern caddr_t
vm_memtag_generate_and_store_tag(caddr_t address, vm_size_t size);

/*
 * When passed a tagged pointer, verify that the pointer metadata matches
 * the backing storage metadata.
 */
extern void
vm_memtag_verify_tag(vm_map_address_t tagged_address);

/*
 * Copy metadata between two mappings whenever we are relocating memory.
 */
extern void
vm_memtag_relocate_tags(vm_address_t new_address, vm_address_t old_address, vm_size_t size);

/* Temporarily enable/disable memtag checking. */
extern void
vm_memtag_enable_checking(void);
extern void
vm_memtag_disable_checking(void);

/*
 * Zeroing operations traditionally happen on large amount of memory (often pages)
 * and tend to span over several different regions with different memtags. Implement
 * variants of bzero that capture both performing this operation without checking
 * (vm_memtag_bzero_unchecked) and by optimizing checking behavior (vm_memtag_bzero_fast_checked)
 */
extern void
vm_memtag_bzero_fast_checked(void *tagged_buf, vm_size_t n);
extern void
vm_memtag_bzero_unchecked(void *tagged_buf, vm_size_t n);

__END_DECLS

#else /* ENABLE_MEMTAG_INTERFACES */


#if KASAN_TBI
#error "vm_memtag interfaces should be defined whenever KASAN-TBI is enabled"
#endif /* KASAN_TBI */

#define vm_memtag_fast_checked_bzero(p, s)      bzero(p, s)
#define vm_memtag_load_tag(a)                   (a)
#define vm_memtag_store_tag(a, s)               do { } while (0)
#define vm_memtag_generate_and_store_tag(a, s)  (a)
#define vm_memtag_relocate_tags(n, o, l)        do { } while (0)
#define vm_memtag_enable_checking()             do { } while (0)
#define vm_memtag_disable_checking()            do { } while (0)
#define vm_memtag_bzero_fast_checked(b, n)      bzero(b, n)
#define vm_memtag_bzero_unchecked(b, n)         bzero(b, n)

#endif /* ENABLE_MEMTAG_INTERFACES */

#if defined(ENABLE_MEMTAG_MANIPULATION_API)

__BEGIN_DECLS
/*
 * Helper functions to manipulate tagged pointers. If more implementors of
 * the vm_memtag interface beyond KASAN-TBI were to come, then these definitions
 * should be ifdef guarded properly.
 */

#define VM_MEMTAG_PTR_SIZE         56
#define VM_MEMTAG_TAG_SIZE          4
#define VM_MEMTAG_UPPER_SIZE        4

typedef uint8_t vm_memtag_t;

union vm_memtag_ptr {
	long value;

	struct {
		long ptr_bits:                  VM_MEMTAG_PTR_SIZE;
		vm_memtag_t ptr_tag:            VM_MEMTAG_TAG_SIZE;
		long ptr_upper:                 VM_MEMTAG_UPPER_SIZE;
	};
};

static inline vm_map_address_t
vm_memtag_insert_tag(vm_map_address_t naked_ptr, vm_memtag_t tag)
{
	union vm_memtag_ptr p = {
		.value = (long)naked_ptr,
	};

	p.ptr_tag = tag;
	return (vm_map_address_t)p.value;
}

static inline vm_memtag_t
vm_memtag_extract_tag(vm_map_address_t tagged_ptr)
{
	union vm_memtag_ptr p = {
		.value = (long)tagged_ptr,
	};

	return p.ptr_tag;
}

/*
 * when passed a tagged pointer, strip away the tag bits and return the
 * canonical address. Since it's used in a number of frequently called checks
 * (e.g. when packing VM pointers), the following definition hardcodes the
 * tag value to achieve optimal codegen and no external calls.
 */
#define vm_memtag_canonicalize_kernel(addr)            vm_memtag_insert_tag(addr, 0xF)
#define vm_memtag_canonicalize_user(addr)              vm_memtag_insert_tag(addr, 0x0)

extern vm_map_address_t
vm_memtag_canonicalize(vm_map_t map, vm_map_address_t addr);

__END_DECLS

#else /* ENABLE_MEMTAG_MANIPULATION_API */


#if KASAN_TBI
#error "vm_memtag manipulation APIs should be defined whenever KASAN-TBI is enabled"
#endif /* KASAN_TBI */

#define vm_memtag_insert_tag(p, t)              (p)
#define vm_memtag_extract_tag(p)                (0xF)
#define vm_memtag_canonicalize(m, a)            (a)
#define vm_memtag_canonicalize_user(a)          (a)
#define vm_memtag_canonicalize_kernel(a)        (a)

#endif /* ENABLE_MEMTAG_MANIPULATION_API */

#endif  /* KERNEL */

#endif  /* _MACH_VM_MEMTAG_H_ */
