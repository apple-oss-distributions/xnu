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

#ifndef _VM_UNSAFE_TYPES_H_
#define _VM_UNSAFE_TYPES_H_

#include <mach/vm_types.h>

/*
 * Macro to generate a wrapped "struct" that preserves ABI,
 * but prevents direct manipulation of the type.
 *
 * The transparent union is needed because of arm64 which for "Composite"
 * arguments passed on the stack will align them to 8 byte boundaries as per
 * spec:
 *
 *     If the argument is an alignment adjusted type its value is passed as
 *     a copy of the actual value. The copy will have an alignment defined as
 *     follows:
 *
 *     - For a Fundamental Data Type, the alignment is the natural alignment
 *       of that type, after any promotions.
 *     - For a Composite Type, the alignment of the copy will have 8-byte
 *       alignment if its natural alignment is ≤ 8 and 16-byte alignment
 *       if its natural alignment is ≥ 16.
 */
#if defined(__cplusplus)
#define VM_GENERATE_UNSAFE_WRAPPER(_safe_type, _unsafe_type) \
	typedef _safe_type _unsafe_type
#else
#define VM_GENERATE_UNSAFE_WRAPPER(_safe_type, _unsafe_type) \
	typedef union { _safe_type UNSAFE; } _unsafe_type    \
	    __attribute__((transparent_union));              \
	_Static_assert(sizeof(_safe_type) == sizeof(_unsafe_type),            \
	    "Size mismatch between unsafe and safe versions of a type")
#endif

VM_GENERATE_UNSAFE_WRAPPER(uint64_t, vm_addr_struct_t);
VM_GENERATE_UNSAFE_WRAPPER(uint64_t, vm_size_struct_t);
VM_GENERATE_UNSAFE_WRAPPER(uint32_t, vm32_addr_struct_t);
VM_GENERATE_UNSAFE_WRAPPER(uint32_t, vm32_size_struct_t);

/*
 * Macros used to create a struct-wrapped type (called "unsafe" type)
 * around a standard VM type.
 */
#if VM_UNSAFE_TYPES
#if defined(__cplusplus)
/*
 * C++ doesn't support transparent_unions which fortunately isn't something
 * we need, as files who need to see unsafe types as structs are all C code
 */
#error "Can't turn on unsafe types in C++"
#endif

/*
 * For defining a custom unsafe type that doesn't directly follow the
 * transparent union model, and needs to be properly typedef'd outside of
 * the VM subsystem.
 */
#define VM_DEFINE_UNSAFE_TYPE(_safe_type, _unsafe_type, _unsafe_contents) \
	typedef _unsafe_contents _unsafe_type;                            \
	_Static_assert(                                                   \
	(                                                                 \
	        sizeof(_unsafe_type)                                      \
	        == sizeof(_safe_type))                                    \
	&& (                                                              \
	        _Alignof(_unsafe_type)                                    \
	        == _Alignof(_safe_type)),                                 \
	"Unsafe type should be compatible with corresponding safe type.")

#define VM_GENERATE_UNSAFE_TYPE(_safe_type, _unsafe_type) \
	VM_GENERATE_UNSAFE_WRAPPER(_safe_type, _unsafe_type)

#define VM_GENERATE_UNSAFE_BSD_TYPE(_safe_type, _unsafe_type) \
	VM_GENERATE_UNSAFE_WRAPPER(_safe_type, _unsafe_type)

/*
 * Don't use this variant directly. Use VM_GENERATE_UNSAFE_ADDR or
 * VM_GENERATE_UNSAFE_SIZE.
 */
#define VM_GENERATE_UNSAFE_EXT(_safe_type, _unsafe_type, variant, size)       \
	typedef vm ## size ## _ ## variant ## _struct_t _unsafe_type;               \
	_Static_assert(sizeof(_safe_type) == sizeof(_unsafe_type),                  \
	    "Size mismatch between unsafe and safe versions of a type")             \

#define VM_GENERATE_UNSAFE_BSD_EXT(_safe_type, _unsafe_type, variant, size)   \
	typedef vm ## size ## _ ## variant ## _struct_t _unsafe_type;               \
	_Static_assert(sizeof(_safe_type) == sizeof(_unsafe_type),                  \
	    "Size mismatch between unsafe and safe versions of a type")
/*
 * Use these variants for addresses and sizes as some types of addr/size
 * are unsigned longs while others are unsigned long longs. Compiler
 * is unhappy about conversions between unsafe pointers of the two.
 */
#define VM_GENERATE_UNSAFE_ADDR(_safe_type, _unsafe_type)               \
	VM_GENERATE_UNSAFE_EXT(_safe_type, _unsafe_type, addr, )

#define VM_GENERATE_UNSAFE_SIZE(_safe_type, _unsafe_type)               \
	VM_GENERATE_UNSAFE_EXT(_safe_type, _unsafe_type, size, )

#define VM_GENERATE_UNSAFE_BSD_ADDR(_safe_type, _unsafe_type)           \
	VM_GENERATE_UNSAFE_EXT(_safe_type, _unsafe_type, addr, )

#define VM_GENERATE_UNSAFE_BSD_SIZE(_safe_type, _unsafe_type)           \
	VM_GENERATE_UNSAFE_EXT(_safe_type, _unsafe_type, size, )

#define VM_GENERATE_UNSAFE_ADDR32(_safe_type, _unsafe_type)             \
	VM_GENERATE_UNSAFE_EXT(_safe_type, _unsafe_type, addr, 32)

#define VM_GENERATE_UNSAFE_SIZE32(_safe_type, _unsafe_type)             \
	VM_GENERATE_UNSAFE_EXT(_safe_type, _unsafe_type, size, 32)

#else  /* VM_UNSAFE_TYPES */
#define VM_DEFINE_UNSAFE_TYPE(_safe_type, _unsafe_type, _unsafe_contents) \
	typedef _safe_type _unsafe_type

#define VM_GENERATE_UNSAFE_TYPE(_safe_type, _unsafe_type)               \
	VM_DEFINE_UNSAFE_TYPE(_safe_type, _unsafe_type, )

#define VM_GENERATE_UNSAFE_ADDR(_safe_type, _unsafe_type)               \
	VM_GENERATE_UNSAFE_TYPE(_safe_type, _unsafe_type)

#define VM_GENERATE_UNSAFE_SIZE(_safe_type, _unsafe_type)               \
	VM_GENERATE_UNSAFE_TYPE(_safe_type, _unsafe_type)

#define VM_GENERATE_UNSAFE_ADDR32(_safe_type, _unsafe_type)             \
	VM_GENERATE_UNSAFE_TYPE(_safe_type, _unsafe_type)

#define VM_GENERATE_UNSAFE_SIZE32(_safe_type, _unsafe_type)             \
	VM_GENERATE_UNSAFE_TYPE(_safe_type, _unsafe_type)

#endif /* VM_UNSAFE_TYPES */

VM_GENERATE_UNSAFE_ADDR(mach_vm_address_t, mach_vm_address_ut);
VM_GENERATE_UNSAFE_ADDR(mach_vm_offset_t, mach_vm_offset_ut);
VM_GENERATE_UNSAFE_SIZE(mach_vm_size_t, mach_vm_size_ut);

VM_GENERATE_UNSAFE_ADDR(vm_address_t, vm_address_ut);
VM_GENERATE_UNSAFE_ADDR(vm_offset_t, vm_offset_ut);
VM_GENERATE_UNSAFE_SIZE(vm_size_t, vm_size_ut);

VM_GENERATE_UNSAFE_ADDR(vm_map_address_t, vm_map_address_ut);
VM_GENERATE_UNSAFE_ADDR(vm_map_offset_t, vm_map_offset_ut);
VM_GENERATE_UNSAFE_SIZE(vm_map_size_t, vm_map_size_ut);

VM_GENERATE_UNSAFE_ADDR(memory_object_offset_t, memory_object_offset_ut);
VM_GENERATE_UNSAFE_SIZE(memory_object_size_t, memory_object_size_ut);

VM_GENERATE_UNSAFE_ADDR(vm_object_offset_t, vm_object_offset_ut);
VM_GENERATE_UNSAFE_SIZE(vm_object_size_t, vm_object_size_ut);

VM_GENERATE_UNSAFE_ADDR(pointer_t, pointer_ut);

#ifdef  MACH_KERNEL_PRIVATE
VM_GENERATE_UNSAFE_ADDR32(vm32_address_t, vm32_address_ut);
VM_GENERATE_UNSAFE_ADDR32(vm32_offset_t, vm32_offset_ut);
VM_GENERATE_UNSAFE_SIZE32(vm32_size_t, vm32_size_ut);
#endif  /* MACH_KERNEL_PRIVATE */

VM_GENERATE_UNSAFE_TYPE(vm_prot_t, vm_prot_ut);
VM_GENERATE_UNSAFE_TYPE(vm_inherit_t, vm_inherit_ut);
VM_GENERATE_UNSAFE_TYPE(vm_behavior_t, vm_behavior_ut);

#if VM_UNSAFE_TYPES
VM_GENERATE_UNSAFE_BSD_ADDR(caddr_t, caddr_ut);
VM_GENERATE_UNSAFE_BSD_ADDR(user_addr_t, user_addr_ut);
VM_GENERATE_UNSAFE_BSD_SIZE(size_t, size_ut);
VM_GENERATE_UNSAFE_BSD_SIZE(user_size_t, user_size_ut);
#endif /* VM_UNSAFE_TYPES */

VM_DEFINE_UNSAFE_TYPE(struct mach_vm_range, mach_vm_range_ut, struct {
	mach_vm_offset_ut min_address_u;
	mach_vm_offset_ut max_address_u;
});

#pragma pack(1)

VM_DEFINE_UNSAFE_TYPE(mach_vm_range_recipe_v1_t, mach_vm_range_recipe_v1_ut, struct {
	mach_vm_range_flags_t flags: 48;
	mach_vm_range_tag_t   range_tag: 8;
	uint8_t               vm_tag: 8;
	mach_vm_range_ut      range_u;
});

#pragma pack()

#endif /* _VM_UNSAFE_TYPES_H_ */
