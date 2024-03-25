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

#include <mach/vm_types.h>

#if CONFIG_KERNEL_TAGGING

/* Zero-out a tagged memory region. */
extern void vm_memtag_bzero(void *tagged_buf, vm_size_t n);

/* Retrieve the tag metadata associated to the target memory address */
extern uint8_t vm_memtag_get_tag(vm_offset_t address);

/*
 * Given a naked address, extract the metadata from memory and add it to
 * the correct pointer metadata.
 */
extern vm_offset_t vm_memtag_fixup_ptr(vm_offset_t naked_address);

/*
 * Given a tagged pointer and a size, update the associated backing metadata
 * to match the pointer metadata.
 */
extern void
vm_memtag_set_tag(vm_offset_t tagged_address, vm_offset_t size);

/*
 * Randomly assign a tag to the current chunk of memory. Memory metadata is
 * not updated yet and must be committed through a call to vm_memtag_set_tag().
 * This helper will implement a basic randomization algorithm that picks a
 * random valid value for the tagging mechanism excluding the current and
 * left/right adjacent metadata value. This approach is fault-conservative and
 * only checks the adjacent memory locations if they fit within the same page.
 */
extern vm_offset_t
vm_memtag_assign_tag(vm_offset_t address, vm_size_t size);

/*
 * When passed a tagged pointer, verify that the pointer metadata matches
 * the backing storage metadata.
 */
extern void
vm_memtag_verify_tag(vm_offset_t tagged_address);

/*
 * Temporarily enable/disable memtag checking.
 */
extern void
vm_memtag_enable_checking(void);
extern void
vm_memtag_disable_checking(void);

/*
 * Helper functions to manipulate tagged pointers. If more implementors of
 * the vm_memtag interface beyond KASAN-TBI were to come, then these definitions
 * should be ifdef guarded properly.
 */
#define VM_MEMTAG_PTR_SIZE         56
#define VM_MEMTAG_TAG_SIZE          4
#define VM_MEMTAG_UPPER_SIZE        4

union vm_memtag_ptr {
	long value;

	struct {
		long ptr_bits:                  VM_MEMTAG_PTR_SIZE;
		uint8_t ptr_tag:                VM_MEMTAG_TAG_SIZE;
		long ptr_upper:                 VM_MEMTAG_UPPER_SIZE;
	};
};

static inline vm_offset_t
vm_memtag_add_ptr_tag(vm_offset_t naked_ptr, uint8_t tag)
{
	union vm_memtag_ptr p = {
		.value = (long)naked_ptr,
	};

	p.ptr_tag = tag;
	return (vm_offset_t)p.value;
}

static inline uint8_t
vm_memtag_extract_tag(vm_offset_t tagged_ptr)
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
#define vm_memtag_canonicalize_address(addr)    vm_memtag_add_ptr_tag(addr, 0xF)
#define vm_memtag_canonicalize_user_address(addr)       vm_memtag_add_ptr_tag(addr, 0x0)

#else /* CONFIG_KERNEL_TAGGING */

#define vm_memtag_bzero(p, s)                   bzero(p, s)
#define vm_memtag_get_tag(a)                    (0xF)
#define vm_memtag_fixup_ptr(a)                  (a)
#define vm_memtag_set_tag(a, s)                 do { } while (0)
#define vm_memtag_assign_tag(a, s)              (a)
#define vm_memtag_add_ptr_tag(p, t)             (p)
#define vm_memtag_extract_tag(p)                (0xF)
#define vm_memtag_canonicalize_address(a)       (a)
#define vm_memtag_enable_checking()             do { } while (0)
#define vm_memtag_disable_checking()            do { } while (0)


#endif /* CONFIG_KERNEL_TAGGING */

#endif  /* KERNEL */

#endif  /* _MACH_VM_MEMTAG_H_ */
