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

#ifndef _VM_SANITIZE_INTERNAL_H_
#define _VM_SANITIZE_INTERNAL_H_

#include <mach/vm_types_unsafe.h>
#include <mach/error.h>
#include <stdbool.h>
#include <vm/vm_sanitize_telemetry.h>

__BEGIN_DECLS
#pragma GCC visibility push(hidden)

/*
 * kern_return_t errors used internally by VM
 */

/*!
 * @define VM_ERR_RETURN_NOW
 * @abstract Communicate to a caller that they should
 * return @c KERN_SUCCESS immediately after completing sanitization checks.
 */
#define VM_ERR_RETURN_NOW (err_vm | err_sub(0) | 1)

/*!
 * @function vm_sanitize_get_kr
 * @abstract When a VM sanitizer returns an error, use this to extract
 * the real value that the sanitizers request that you return.
 *
 * @discussion errno-returning callers may need to transform this result further
 *
 * @param kr                error code set by the sanitizers
 * @returns                 a (possibly different) error code
 */
static inline
kern_return_t
vm_sanitize_get_kr(kern_return_t kr)
{
	if (kr == VM_ERR_RETURN_NOW) {
		return KERN_SUCCESS;
	}
	return kr;
}

/*!
 * @enum vm_sanitize_caller_id_t
 *
 * @brief
 * IDs for callers of sanitization functions that have different
 * set of return values.
 */
__enum_closed_decl(vm_sanitize_caller_id_t, uint32_t, {
	VM_SANITIZE_CALLER_ID_NONE,

	/* memory entry */
	VM_SANITIZE_CALLER_ID_MACH_MAKE_MEMORY_ENTRY,
	VM_SANITIZE_CALLER_ID_MACH_MEMORY_ENTRY_PAGE_OP,
	VM_SANITIZE_CALLER_ID_MACH_MEMORY_ENTRY_RANGE_OP,
	VM_SANITIZE_CALLER_ID_MACH_MEMORY_ENTRY_MAP_SIZE,
	VM_SANITIZE_CALLER_ID_MACH_MEMORY_OBJECT_MEMORY_ENTRY,

	/* alloc/dealloc */
	VM_SANITIZE_CALLER_ID_VM_ALLOCATE_FIXED,
	VM_SANITIZE_CALLER_ID_VM_ALLOCATE_ANYWHERE,
	VM_SANITIZE_CALLER_ID_VM_DEALLOCATE,
	VM_SANITIZE_CALLER_ID_MUNMAP,

	/* map/remap */
	VM_SANITIZE_CALLER_ID_VM_MAP_REMAP,
	VM_SANITIZE_CALLER_ID_MMAP,
	VM_SANITIZE_CALLER_ID_MREMAP_ENCRYPTED,
	VM_SANITIZE_CALLER_ID_MAP_WITH_LINKING_NP,
	VM_SANITIZE_CALLER_ID_ENTER_MEM_OBJ,
	VM_SANITIZE_CALLER_ID_ENTER_MEM_OBJ_CTL,

	/* wire/unwire */
	VM_SANITIZE_CALLER_ID_VM_WIRE_USER,
	VM_SANITIZE_CALLER_ID_VM_UNWIRE_USER,
	VM_SANITIZE_CALLER_ID_VM_MAP_WIRE,
	VM_SANITIZE_CALLER_ID_VM_MAP_UNWIRE,
	VM_SANITIZE_CALLER_ID_VSLOCK,
	VM_SANITIZE_CALLER_ID_VSUNLOCK,

	/* copyin/copyout */
	VM_SANITIZE_CALLER_ID_VM_MAP_COPY_OVERWRITE,
	VM_SANITIZE_CALLER_ID_VM_MAP_COPYIN,
	VM_SANITIZE_CALLER_ID_VM_MAP_READ_USER,
	VM_SANITIZE_CALLER_ID_VM_MAP_WRITE_USER,

	/* inherit */
	VM_SANITIZE_CALLER_ID_VM_MAP_INHERIT,
	VM_SANITIZE_CALLER_ID_MINHERIT,

	/* protect */
	VM_SANITIZE_CALLER_ID_VM_MAP_PROTECT,
	VM_SANITIZE_CALLER_ID_MPROTECT,
	VM_SANITIZE_CALLER_ID_USERACC,

	/* behavior */
	VM_SANITIZE_CALLER_ID_VM_BEHAVIOR_SET,
	VM_SANITIZE_CALLER_ID_MADVISE,

	/* msync */
	VM_SANITIZE_CALLER_ID_VM_MAP_MSYNC,
	VM_SANITIZE_CALLER_ID_MSYNC,

	/* machine attribute */
	VM_SANITIZE_CALLER_ID_VM_MAP_MACHINE_ATTRIBUTE,

	/* page info */
	VM_SANITIZE_CALLER_ID_VM_MAP_PAGE_RANGE_INFO,
	VM_SANITIZE_CALLER_ID_VM_MAP_PAGE_RANGE_QUERY,
	VM_SANITIZE_CALLER_ID_MINCORE,

	/* single */
	VM_SANITIZE_CALLER_ID_MACH_VM_DEFERRED_RECLAMATION_BUFFER_INIT,
	VM_SANITIZE_CALLER_ID_MACH_VM_RANGE_CREATE,
	VM_SANITIZE_CALLER_ID_SHARED_REGION_MAP_AND_SLIDE_2_NP,

	/* test */
	VM_SANITIZE_CALLER_ID_TEST
});

/*!
 * @enum vm_sanitize_flags_t
 *
 * @brief
 * Flags that influence the sanitization being performed.
 *
 * @const VM_SANITIZE_FLAGS_NONE
 * Default value.
 *
 * @const VM_SANITIZE_FLAGS_CHECK_ALIGNED_START
 * Checks that the start address is aligned to map page size.
 *
 * @const VM_SANITIZE_FLAGS_SIZE_ZERO_SUCCEEDS
 * In sanitizers that have a @c size parameter, the sanitizer will ask
 * the caller to return @c KERN_SUCCESS when @c size @c == @c 0.
 *
 * Exactly one of @c VM_SANITIZE_FLAGS_SIZE_ZERO_* must be passed to sanitizers
 * that return a sanitized size.
 *
 * @const VM_SANITIZE_FLAGS_SIZE_ZERO_FAILS
 * In sanitizers that have a @c size parameter, the sanitizer will ask
 * the caller to return @c KERN_INVALID_ARGUMENT when @c size @c == @c 0.
 *
 * Exactly one of @c VM_SANITIZE_FLAGS_SIZE_ZERO_* must be passed to sanitizers
 * that return a sanitized size.
 *
 * @const VM_SANITIZE_FLAGS_SIZE_ZERO_FALLTHROUGH
 * In sanitizers that have a @c size parameter, the sanitizer will not ask
 * the caller to return when @c size @c == @c 0, thus falling through into
 * the caller's implementation.
 *
 * Exactly one of @c VM_SANITIZE_FLAGS_SIZE_ZERO_* must be passed to sanitizers
 * that return a sanitized size.
 *
 * @const VM_SANITIZE_FLAGS_GET_UNALIGNED_VALUES
 * Return unaligned start/end/size rather than realigned values.
 *
 * @const VM_SANITIZE_FLAGS_REALIGN_START
 * Ignore the misaligned bits of the start address when sanitizing an address.
 *
 * @const VM_SANITIZE_FLAGS_CHECK_USER_MEM_MAP_FLAGS
 * Reject non user allowed mem map flags for memory entry.
 *
 * @const VM_SANITIZE_FLAGS_CANONICALIZE
 * Canonicalize address for CONFIG_KERNEL_TAGGING
 *
 * @const VM_SANITIZE_FLAGS_CHECK_ALIGNED_SIZE
 * Checks that the size is aligned to map page size.
 *
 * @const VM_SANITIZE_FLAGS_CHECK_ADDR_RANGE
 * Checks that computing values within the range [start, end) does not overflow
 * into bits above the supported VA bits for the system. These bits may be used
 * by the kernel or hardware to store additional values.
 */

__options_closed_decl(vm_sanitize_flags_t, uint32_t, {
	VM_SANITIZE_FLAGS_NONE                     = 0x00000000,
	VM_SANITIZE_FLAGS_CHECK_ALIGNED_START      = 0x00000001,
	VM_SANITIZE_FLAGS_SIZE_ZERO_SUCCEEDS       = 0x00000002,
	VM_SANITIZE_FLAGS_SIZE_ZERO_FAILS          = 0x00000004,
	VM_SANITIZE_FLAGS_SIZE_ZERO_FALLTHROUGH    = 0x00000008,
	VM_SANITIZE_FLAGS_GET_UNALIGNED_VALUES     = 0x00000010,
	VM_SANITIZE_FLAGS_REALIGN_START            = 0x00000020,
	VM_SANITIZE_FLAGS_CHECK_USER_MEM_MAP_FLAGS = 0x00000040,
	VM_SANITIZE_FLAGS_CANONICALIZE             = 0x00000080,
	VM_SANITIZE_FLAGS_CHECK_ALIGNED_SIZE       = 0x00000100,
	VM_SANITIZE_FLAGS_CHECK_ADDR_RANGE         = 0x00000200,
});

#define __vm_sanitize_bits_one_of(flags) \
	((flags) != 0 && ((flags) & ((flags) - 1)) == 0)

#define __vm_sanitize_assert_one_of(arg, mask) \
	__attribute__((diagnose_if(!__vm_sanitize_bits_one_of((arg) & (mask)), \
	    "`" #arg "` must have one of these flags `" #mask "`", "error")))

#define __vm_sanitize_require_size_zero_flag(arg) \
	__vm_sanitize_assert_one_of(arg,          \
	    VM_SANITIZE_FLAGS_SIZE_ZERO_SUCCEEDS | VM_SANITIZE_FLAGS_SIZE_ZERO_FAILS | VM_SANITIZE_FLAGS_SIZE_ZERO_FALLTHROUGH)

/*
 * Error compat rewrite result:
 * compat_kr: the more-compatible return value
 * should_rewrite: true if compat_kr should be returned
 * should_telemeter: true if compat_kr should be telemetered
 */
typedef struct {
	kern_return_t compat_kr;
	bool should_rewrite;
	bool should_telemeter;
} vm_sanitize_compat_rewrite_t;

typedef vm_sanitize_compat_rewrite_t (*vm_sanitize_err_compat_addr_size_fn)(kern_return_t kr,
    vm_address_t addr, vm_size_t size, vm_offset_t pgmask, vm_map_t map_or_null);
typedef vm_sanitize_compat_rewrite_t (*vm_sanitize_err_compat_cur_and_max_prots_fn)(kern_return_t kr,
    vm_prot_t *cur_inout, vm_prot_t *max_inout, vm_prot_t extra_mask);

typedef const struct vm_sanitize_caller {
	vm_sanitize_caller_id_t              vmsc_caller_id;
	const char                          *vmsc_caller_name;
	vm_sanitize_method_t                 vmsc_telemetry_id;
	enum vm_sanitize_subsys_error_codes  vmsc_ktriage_id;

	vm_sanitize_err_compat_addr_size_fn    err_compat_addr_size;
	vm_sanitize_err_compat_cur_and_max_prots_fn err_compat_prot_cur_max;
} *vm_sanitize_caller_t;

/*
 * Macros to declare and define callers of sanitization functions
 */
#define VM_SANITIZE_DECL_CALLER(name) \
	extern vm_sanitize_caller_t const VM_SANITIZE_CALLER_ ## name;

#define VM_SANITIZE_DEFINE_CALLER(name, ... /* error compat functions */)       \
	static const struct vm_sanitize_caller vm_sanitize_caller_storage_ ## name = { \
	    .vmsc_caller_id = VM_SANITIZE_CALLER_ID_ ## name,        \
	    .vmsc_caller_name = #name,                       \
	    .vmsc_telemetry_id = VM_SANITIZE_METHOD_ ## name,     \
	    .vmsc_ktriage_id = KDBG_TRIAGE_VM_SANITIZE_ ## name,  \
	    __VA_ARGS__                                     \
	}; \
	vm_sanitize_caller_t const VM_SANITIZE_CALLER_ ## name = &vm_sanitize_caller_storage_ ## name

/*
 * Declaration of callers of VM sanitization functions
 */
/* memory entry */
VM_SANITIZE_DECL_CALLER(MACH_MAKE_MEMORY_ENTRY);
VM_SANITIZE_DECL_CALLER(MACH_MEMORY_ENTRY_PAGE_OP);
VM_SANITIZE_DECL_CALLER(MACH_MEMORY_ENTRY_RANGE_OP);
VM_SANITIZE_DECL_CALLER(MACH_MEMORY_ENTRY_MAP_SIZE);
VM_SANITIZE_DECL_CALLER(MACH_MEMORY_OBJECT_MEMORY_ENTRY);

/* alloc/dealloc */
VM_SANITIZE_DECL_CALLER(VM_ALLOCATE_FIXED);
VM_SANITIZE_DECL_CALLER(VM_ALLOCATE_ANYWHERE);
VM_SANITIZE_DECL_CALLER(VM_DEALLOCATE);
VM_SANITIZE_DECL_CALLER(MUNMAP);

/* map/remap */
VM_SANITIZE_DECL_CALLER(VM_MAP_REMAP);
VM_SANITIZE_DECL_CALLER(MMAP);
VM_SANITIZE_DECL_CALLER(MREMAP_ENCRYPTED);
VM_SANITIZE_DECL_CALLER(MAP_WITH_LINKING_NP);
VM_SANITIZE_DECL_CALLER(ENTER_MEM_OBJ);
VM_SANITIZE_DECL_CALLER(ENTER_MEM_OBJ_CTL);

/* wire/unwire */
VM_SANITIZE_DECL_CALLER(VM_WIRE_USER);
VM_SANITIZE_DECL_CALLER(VM_UNWIRE_USER);
VM_SANITIZE_DECL_CALLER(VM_MAP_WIRE);
VM_SANITIZE_DECL_CALLER(VM_MAP_UNWIRE);
VM_SANITIZE_DECL_CALLER(VSLOCK);
VM_SANITIZE_DECL_CALLER(VSUNLOCK);

/* copyin/copyout */
VM_SANITIZE_DECL_CALLER(VM_MAP_COPY_OVERWRITE);
VM_SANITIZE_DECL_CALLER(VM_MAP_COPYIN);
VM_SANITIZE_DECL_CALLER(VM_MAP_READ_USER);
VM_SANITIZE_DECL_CALLER(VM_MAP_WRITE_USER);

/* inherit */
VM_SANITIZE_DECL_CALLER(MACH_VM_INHERIT);
VM_SANITIZE_DECL_CALLER(VM_INHERIT);
VM_SANITIZE_DECL_CALLER(VM32_INHERIT);
VM_SANITIZE_DECL_CALLER(VM_MAP_INHERIT);
VM_SANITIZE_DECL_CALLER(MINHERIT);

/* protect */
VM_SANITIZE_DECL_CALLER(MACH_VM_PROTECT);
VM_SANITIZE_DECL_CALLER(VM_PROTECT);
VM_SANITIZE_DECL_CALLER(VM32_PROTECT);
VM_SANITIZE_DECL_CALLER(VM_MAP_PROTECT);
VM_SANITIZE_DECL_CALLER(MPROTECT);
VM_SANITIZE_DECL_CALLER(USERACC);

/* behavior */
VM_SANITIZE_DECL_CALLER(VM_BEHAVIOR_SET);
VM_SANITIZE_DECL_CALLER(MADVISE);

/* msync */
VM_SANITIZE_DECL_CALLER(VM_MAP_MSYNC);
VM_SANITIZE_DECL_CALLER(MSYNC);

/* machine attribute */
VM_SANITIZE_DECL_CALLER(VM_MAP_MACHINE_ATTRIBUTE);

/* page info */
VM_SANITIZE_DECL_CALLER(VM_MAP_PAGE_RANGE_INFO);
VM_SANITIZE_DECL_CALLER(VM_MAP_PAGE_RANGE_QUERY);
VM_SANITIZE_DECL_CALLER(MINCORE);

/* single */
VM_SANITIZE_DECL_CALLER(MACH_VM_DEFERRED_RECLAMATION_BUFFER_INIT);
VM_SANITIZE_DECL_CALLER(MACH_VM_RANGE_CREATE);
VM_SANITIZE_DECL_CALLER(SHARED_REGION_MAP_AND_SLIDE_2_NP);

/* test */
VM_SANITIZE_DECL_CALLER(TEST);

/*
 * Macro that extracts the inner struct member from a wrapped type. Should be
 * used in all cases, including validation functions, when accessing the
 * inner struct member.
 */
#define VM_SANITIZE_UNSAFE_UNWRAP(_val) (_val).UNSAFE

/*
 * Macro to check if unsafe value is a specific safe value
 */
#define VM_SANITIZE_UNSAFE_IS_EQUAL(_var, _val) ((_var).UNSAFE == (_val))

/*
 * Macro to check if unsafe value is zero
 */
#define VM_SANITIZE_UNSAFE_IS_ZERO(_var) VM_SANITIZE_UNSAFE_IS_EQUAL(_var, 0)

/*
 * returns whether a given unsafe value fits a given type
 */
#define VM_SANITIZE_UNSAFE_FITS(_var, type_t) ({ \
	__auto_type __tmp = (_var).UNSAFE; \
	__tmp == (type_t)__tmp;            \
})

/*
 * Macro that sets a value of unsafe type to a value of safe type.
 * This is safe to do because we are only forcing ourselves to perform
 * checks on a value we already have direct access to.
 */
#define VM_SANITIZE_UT_SET(_var, _val) ((_var).UNSAFE) = (_val)

/*!
 * @function vm_sanitize_wrap_addr
 *
 * @abstract
 * Function that wraps unsanitized safe address into unsafe address
 *
 * @param val               safe address
 * @returns                 unsafe address
 */
__attribute__((always_inline, warn_unused_result))
vm_addr_struct_t vm_sanitize_wrap_addr(vm_address_t val);

/*!
 * @function vm_sanitize_wrap_addr_ref
 *
 * @abstract
 * Function that wraps a safe address pointer,
 * into unsafe address pointer.
 *
 * @param val               safe address ref
 * @returns                 unsafe address reference
 */
#define vm_sanitize_wrap_addr_ref(var)  _Generic(var, \
	mach_vm_address_t *: (vm_addr_struct_t *)(var), \
	vm_address_t *:      (vm_addr_struct_t *)(var), \
	default:             (var))

/*!
 * @function vm_sanitize_wrap_size
 *
 * @abstract
 * Function that wraps unsanitized safe size into unsafe size
 *
 * @param val               safe size
 * @returns                 unsafe size
 */
__attribute__((always_inline, warn_unused_result))
vm_size_struct_t vm_sanitize_wrap_size(vm_size_t val);

/*
 * bsd doesn't use 32bit interfaces and the types aren't even defined for them,
 * so we just expose this to MACH.
 */
#ifdef MACH_KERNEL_PRIVATE
/*!
 * @function vm32_sanitize_wrap_size
 *
 * @abstract
 * Function that wraps unsanitized 32bit safe size into 32bit unsafe size
 *
 * @param val               safe size
 * @returns                 unsafe size
 */
__attribute__((always_inline, warn_unused_result))
vm32_size_struct_t vm32_sanitize_wrap_size(vm32_size_t val);
#endif /* MACH_KERNEL_PRIVATE */

/*!
 * @function vm_sanitize_wrap_prot
 *
 * @abstract
 * Function that wraps unsanitized safe protection into unsafe protection
 *
 * @param val               safe protection
 * @returns                 unsafe protection
 */
__attribute__((always_inline, warn_unused_result))
vm_prot_ut vm_sanitize_wrap_prot(vm_prot_t val);

/*!
 * @function vm_sanitize_wrap_prot_ref
 *
 * @abstract
 * Function that wraps a safe protection pointer into unsafe protection pointer.
 *
 * @param val               safe protection pointer
 * @returns                 unsafe protection pointer
 */
__attribute__((always_inline, warn_unused_result))
static inline vm_prot_ut *
vm_sanitize_wrap_prot_ref(vm_prot_t *val)
{
	return (vm_prot_ut *)val;
}

/*!
 * @function vm_sanitize_wrap_inherit
 *
 * @abstract
 * Function that wraps unsanitized safe vm_inherit into unsafe vm_inherit
 *
 * @param val               safe vm_inherit
 * @returns                 unsafe vm_inherit
 */
__attribute__((always_inline, warn_unused_result))
vm_inherit_ut vm_sanitize_wrap_inherit(vm_inherit_t val);

/*!
 * @function vm_sanitize_wrap_behavior
 *
 * @abstract
 * Function that wraps a safe vm_behavior into an unsafe vm_behavior
 *
 * @param val               safe vm_behavior
 * @returns                 unsafe vm_behavior
 */
__attribute__((always_inline, warn_unused_result))
vm_behavior_ut vm_sanitize_wrap_behavior(vm_behavior_t val);

#ifdef  MACH_KERNEL_PRIVATE

/*!
 * @function vm_sanitize_expand_addr_to_64
 *
 * @abstract
 * Function used by the vm32 functions to cast 32bit unsafe address
 * to 64bit unsafe address
 *
 * @param val               32bit unsafe address
 * @returns                 64bit unsafe address
 */
__attribute__((always_inline, warn_unused_result))
vm_addr_struct_t vm_sanitize_expand_addr_to_64(vm32_address_ut val);

/*!
 * @function vm_sanitize_expand_size_to_64
 *
 * @abstract
 * Function used by the vm32 functions to cast 32bit unsafe size
 * to 64bit unsafe size
 *
 * @param val               32bit unsafe size
 * @returns                 64bit unsafe size
 */
__attribute__((always_inline, warn_unused_result))
vm_size_struct_t vm_sanitize_expand_size_to_64(vm32_size_ut val);

/*!
 * @function vm_sanitize_trunc_addr_to_32
 *
 * @abstract
 * Function used by the vm32 functions to cast 64bit unsafe address
 * to 32bit unsafe address
 *
 * @param val               64bit unsafe address
 * @returns                 32bit unsafe address
 */
__attribute__((always_inline, warn_unused_result))
vm32_address_ut vm_sanitize_trunc_addr_to_32(vm_addr_struct_t val);

/*!
 * @function vm_sanitize_trunc_size_to_32
 *
 * @abstract
 * Function used by the vm32 functions to cast 64bit unsafe size
 * to 32bit unsafe size
 *
 * @param val               64bit unsafe size
 * @returns                 32bit unsafe size
 */
__attribute__((always_inline, warn_unused_result))
vm32_size_ut vm_sanitize_trunc_size_to_32(vm_size_struct_t val);

/*!
 * @function vm_sanitize_add_overflow()
 *
 * @abstract
 * Computes the sum of an address and a size checking for overflow,
 * staying in the unsafe world.
 *
 * @param addr_u            unsafe address
 * @param size_u            unsafe size
 * @param addr_out_u        unsafe result
 * @returns whether the operation overflowed
 */
__attribute__((always_inline, warn_unused_result, overloadable))
bool vm_sanitize_add_overflow(
	vm32_address_ut         addr_u,
	vm32_size_ut            size_u,
	vm32_address_ut        *addr_out_u);

#endif  /* MACH_KERNEL_PRIVATE */

/*!
 * @function vm_sanitize_add_overflow()
 *
 * @abstract
 * Computes the sum of an address and a size checking for overflow,
 * staying in the unsafe world.
 *
 * @param addr_u            unsafe address
 * @param size_u            unsafe size
 * @param addr_out_u        unsafe result
 * @returns whether the operation overflowed
 */
__attribute__((always_inline, warn_unused_result, overloadable))
bool vm_sanitize_add_overflow(
	vm_addr_struct_t        addr_u,
	vm_size_struct_t        size_u,
	vm_addr_struct_t       *addr_out_u);

/*!
 * @function vm_sanitize_add_overflow()
 *
 * @abstract
 * Computes the sum of two sizes checking for overflow,
 * staying in the unsafe world.
 *
 * @param size1_u           unsafe size 1
 * @param size2_u           unsafe size 2
 * @param size_out_u        unsafe result
 * @returns whether the operation overflowed
 */
__attribute__((always_inline, warn_unused_result, overloadable))
bool vm_sanitize_add_overflow(
	vm_size_struct_t        size1_u,
	vm_size_struct_t        size2_u,
	vm_size_struct_t       *size_out_u);

/*!
 * @function vm_sanitize_compute_ut_end
 *
 * @abstract
 * Computes and returns unsafe end from unsafe start and size
 *
 * @param addr_u            unsafe start
 * @param size_u            unsafe size
 * @returns                 unsafe end
 */
__attribute__((always_inline, warn_unused_result))
vm_addr_struct_t vm_sanitize_compute_ut_end(
	vm_addr_struct_t        addr_u,
	vm_size_struct_t        size_u);

/*!
 * @function vm_sanitize_compute_ut_size
 *
 * @abstract
 * Computes and returns unsafe size from unsafe start and end
 *
 * @param addr_u            unsafe start
 * @param end_u             unsafe end
 * @returns                 unsafe size
 */
__attribute__((always_inline, warn_unused_result))
vm_size_struct_t vm_sanitize_compute_ut_size(
	vm_addr_struct_t        addr_u,
	vm_addr_struct_t        end_u);

/*!
 * @function vm_sanitize_addr
 *
 * @abstract
 * Sanitization function that takes unsafe address, and returns a truncated
 * address.
 *
 * @param map               map the address belongs to
 * @param addr_u            unsafe address to sanitize
 * @returns                 a sanitized address
 */
__attribute__((always_inline, warn_unused_result))
mach_vm_address_t vm_sanitize_addr(
	vm_map_t                map,
	vm_addr_struct_t        addr_u);

/*!
 * @function vm_sanitize_offset_in_page
 *
 * @abstract
 * Sanitization function that takes unsafe address,
 * and returns the offset in the page for this address.
 *
 * @param mask              page mask to use
 * @param addr_u            unsafe address to sanitize
 * @returns                 a sanitized offset in page
 */
__attribute__((always_inline, warn_unused_result))
mach_vm_offset_t vm_sanitize_offset_in_page(
	vm_map_offset_t         mask,
	vm_addr_struct_t        addr_u);

/*
 * @function vm_sanitize_offset_in_page
 *
 * @abstract
 * Sanitization function that takes unsafe address,
 * and returns the offset in the page for this address.
 *
 * @param map               map the address belongs to
 * @param addr_u            unsafe address to sanitize
 * @returns                 a sanitized offset in page
 */
__attribute__((always_inline, warn_unused_result, overloadable))
static inline mach_vm_offset_t
vm_sanitize_offset_in_page(
	vm_map_t                map,
	vm_addr_struct_t        addr_u)
{
	return vm_sanitize_offset_in_page(vm_map_page_mask(map), addr_u);
}

/*!
 * @function vm_sanitize_offset
 *
 * @abstract
 * Sanitization function that takes unsafe offset and validates
 * that it is within addr and end provided.
 *
 * @param offset_u          unsafe offset to sanitize
 * @param vm_sanitize_caller        caller of the sanitization function
 * @param addr              sanitized start address
 * @param end               sanitized end address
 * @param offset            sanitized offset
 * @returns                 return code indicating success/failure of sanitization
 */
__attribute__((always_inline, warn_unused_result))
kern_return_t vm_sanitize_offset(
	vm_addr_struct_t        offset_u,
	vm_sanitize_caller_t    vm_sanitize_caller,
	vm_map_address_t        addr,
	vm_map_address_t        end,
	vm_map_offset_t        *offset);

/*!
 * @function vm_sanitize_mask
 *
 * @abstract
 * Sanitization function that takes unsafe mask and sanitizes it.
 *
 * @param mask_u            unsafe mask to sanitize
 * @param vm_sanitize_caller        caller of the sanitization function
 * @param mask              sanitized mask
 * @returns                 return code indicating success/failure of sanitization
 */
__attribute__((always_inline, warn_unused_result))
kern_return_t vm_sanitize_mask(
	vm_addr_struct_t        mask_u,
	vm_sanitize_caller_t    vm_sanitize_caller,
	vm_map_offset_t        *mask);

/*!
 * @function vm_sanitize_object_size
 *
 * @abstract
 * Sanitization function that takes unsafe VM object size and safely rounds it
 * up wrt a VM object.
 *
 * @param size_u            unsafe size to sanitize
 * @param vm_sanitize_caller        caller of the sanitization function
 * @param flags             flags that influence sanitization performed
 * @param size              sanitized object size
 * @returns                 return code indicating success/failure of sanitization
 */
__attribute__((always_inline, warn_unused_result))
kern_return_t vm_sanitize_object_size(
	vm_size_struct_t        size_u,
	vm_sanitize_caller_t    vm_sanitize_caller,
	vm_sanitize_flags_t     flags,
	vm_object_offset_t     *size)
__vm_sanitize_require_size_zero_flag(flags);

/*!
 * @function vm_sanitize_size
 *
 * @abstract
 * Sanitization function that takes unsafe size and safely rounds it up.
 *
 * @param offset_u          an offset/address which marks the beginning of the
 *                          memory region of size @c size_u. Overflow checks
 *                          will be performed on @c size_u+offset_u, and the
 *                          low bits of @c offset_u may influence the rounding
 *                          of @c size_u to ensure the returned size covers all
 *                          pages that intersect with the region that starts at
 *                          @c offset_u and has size @c size_u.
 * @param size_u            unsafe size to sanitize
 * @param vm_sanitize_caller        caller of the sanitization function
 * @param map               map the address belongs to
 * @param flags             flags that influence sanitization performed
 * @param size              sanitized size
 * @returns                 return code indicating success/failure of sanitization
 */
__attribute__((always_inline, warn_unused_result))
kern_return_t vm_sanitize_size(
	vm_addr_struct_t        offset_u,
	vm_size_struct_t        size_u,
	vm_sanitize_caller_t    vm_sanitize_caller,
	vm_map_t                map,
	vm_sanitize_flags_t     flags,
	mach_vm_size_t         *size)
__vm_sanitize_require_size_zero_flag(flags);

/*!
 * @function vm_sanitize_addr_size
 *
 * @abstract
 * Sanitization function that takes unsafe address and size and returns
 * sanitized start, end and size via out parameters.
 *
 * @param addr_u            unsafe address to sanitize
 * @param size_u            unsafe size to sanitize
 * @param vm_sanitize_caller        caller of the sanitization function
 * @param mask              page mask to use
 * @param map_or_null       optional map, used for error compat for some callers
 * @param flags             flags that influence sanitization performed
 * @param addr              sanitized start
 * @param end               sanitized end
 * @param size              sanitized size
 * @returns                 return code indicating success/failure of sanitization
 */
__attribute__((always_inline, warn_unused_result))
kern_return_t vm_sanitize_addr_size(
	vm_addr_struct_t        addr_u,
	vm_size_struct_t        size_u,
	vm_sanitize_caller_t    vm_sanitize_caller,
	mach_vm_offset_t        mask,
	vm_map_t                map_or_null,
	vm_sanitize_flags_t     flags,
	vm_map_offset_t        *addr,
	vm_map_offset_t        *end,
	vm_map_size_t          *size)
__vm_sanitize_require_size_zero_flag(flags);

/*!
 * @function vm_sanitize_addr_size
 *
 * @abstract
 * Sanitization function that takes unsafe address and size and returns
 * sanitized start, end and size via out parameters.
 *
 * @param addr_u            unsafe address to sanitize
 * @param size_u            unsafe size to sanitize
 * @param vm_sanitize_caller        caller of the sanitization function
 * @param mask              page mask to use
 * @param flags             flags that influence sanitization performed
 * @param addr              sanitized start
 * @param end               sanitized end
 * @param size              sanitized size
 * @returns                 return code indicating success/failure of sanitization
 */
__attribute__((always_inline, warn_unused_result, overloadable))
static inline kern_return_t
vm_sanitize_addr_size(
	vm_addr_struct_t        addr_u,
	vm_size_struct_t        size_u,
	vm_sanitize_caller_t    vm_sanitize_caller,
	mach_vm_offset_t        mask,
	vm_sanitize_flags_t     flags,
	vm_map_offset_t        *addr,
	vm_map_offset_t        *end,
	vm_map_size_t          *size)
__vm_sanitize_require_size_zero_flag(flags)
{
	return vm_sanitize_addr_size(addr_u, size_u, vm_sanitize_caller, mask,
	           VM_MAP_NULL, flags, addr, end, size);
}


/*!
 * @function vm_sanitize_addr_size
 *
 * @abstract
 * Sanitization function that takes unsafe address and size and returns
 * sanitized start, end and size via out parameters.
 *
 * @param addr_u            unsafe address to sanitize
 * @param size_u            unsafe size to sanitize
 * @param vm_sanitize_caller        caller of the sanitization function
 * @param map               map the address belongs to
 * @param flags             flags that influence sanitization performed
 * @param addr              sanitized start
 * @param end               sanitized end
 * @param size              sanitized size
 * @returns                 return code indicating success/failure of sanitization
 */
__attribute__((always_inline, warn_unused_result, overloadable))
static inline kern_return_t
vm_sanitize_addr_size(
	vm_addr_struct_t        addr_u,
	vm_size_struct_t        size_u,
	vm_sanitize_caller_t    vm_sanitize_caller,
	vm_map_t                map,
	vm_sanitize_flags_t     flags,
	vm_map_offset_t        *addr,
	vm_map_offset_t        *end,
	vm_map_size_t          *size)
__vm_sanitize_require_size_zero_flag(flags)
{
	mach_vm_offset_t mask = vm_map_page_mask(map);

	return vm_sanitize_addr_size(addr_u, size_u, vm_sanitize_caller, mask,
	           map, flags, addr, end, size);
}

/*!
 * @function vm_sanitize_addr_end
 *
 * @abstract
 * Sanitization function that takes unsafe address and end and returns
 * sanitized start, end and size via out parameters.
 *
 * @param addr_u            unsafe address to sanitize
 * @param end_u             unsafe end to sanitize
 * @param vm_sanitize_caller        caller of the sanitization function
 * @param mask              page mask to use
 * @param map_or_null       optional map, used for error compat for some callers
 * @param flags             flags that influence sanitization performed
 * @param start             sanitized start
 * @param end               sanitized end
 * @param size              sanitized size
 * @returns                 return code indicating success/failure of sanitization
 */
__attribute__((always_inline, warn_unused_result))
kern_return_t vm_sanitize_addr_end(
	vm_addr_struct_t        addr_u,
	vm_addr_struct_t        end_u,
	vm_sanitize_caller_t    vm_sanitize_caller,
	mach_vm_offset_t        mask,
	vm_map_t                map_or_null,
	vm_sanitize_flags_t     flags,
	vm_map_offset_t        *start,
	vm_map_offset_t        *end,
	vm_map_size_t          *size)
__vm_sanitize_require_size_zero_flag(flags);

/*!
 * @function vm_sanitize_addr_end
 *
 * @abstract
 * Sanitization function that takes unsafe address and end and returns
 * sanitized start, end and size via out parameters.
 *
 * @param addr_u            unsafe address to sanitize
 * @param end_u             unsafe end to sanitize
 * @param vm_sanitize_caller        caller of the sanitization function
 * @param mask              page mask to use
 * @param flags             flags that influence sanitization performed
 * @param start             sanitized start
 * @param end               sanitized end
 * @param size              sanitized size
 * @returns                 return code indicating success/failure of sanitization
 */
__attribute__((always_inline, warn_unused_result, overloadable))
static inline kern_return_t
vm_sanitize_addr_end(
	vm_addr_struct_t        addr_u,
	vm_addr_struct_t        end_u,
	vm_sanitize_caller_t    vm_sanitize_caller,
	mach_vm_offset_t        mask,
	vm_sanitize_flags_t     flags,
	vm_map_offset_t        *start,
	vm_map_offset_t        *end,
	vm_map_size_t          *size)
__vm_sanitize_require_size_zero_flag(flags)
{
	return vm_sanitize_addr_end(addr_u, end_u, vm_sanitize_caller, mask,
	           VM_MAP_NULL, flags, start, end, size);
}

/*!
 * @function vm_sanitize_addr_end
 *
 * @abstract
 * Sanitization function that takes unsafe address and end and returns
 * sanitized start, end and size via out parameters.
 *
 * @param addr_u            unsafe address to sanitize
 * @param end_u             unsafe end to sanitize
 * @param vm_sanitize_caller        caller of the sanitization function
 * @param map               map the address belongs to
 * @param flags             flags that influence sanitization performed
 * @param start             sanitized start
 * @param end               sanitized end
 * @param size              sanitized size
 * @returns                 return code indicating success/failure of sanitization
 */
__attribute__((always_inline, warn_unused_result, overloadable))
static inline kern_return_t
vm_sanitize_addr_end(
	vm_addr_struct_t        addr_u,
	vm_addr_struct_t        end_u,
	vm_sanitize_caller_t    vm_sanitize_caller,
	vm_map_t                map,
	vm_sanitize_flags_t     flags,
	vm_map_offset_t        *start,
	vm_map_offset_t        *end,
	vm_map_size_t          *size)
__vm_sanitize_require_size_zero_flag(flags)
{
	mach_vm_offset_t mask = vm_map_page_mask(map);

	return vm_sanitize_addr_end(addr_u, end_u, vm_sanitize_caller, mask,
	           map, flags, start, end, size);
}

/*!
 * @function vm_sanitize_prot
 *
 * @abstract
 * Sanitization function that takes unsafe protections and sanitizes it.
 *
 * @param prot_u            unsafe protections
 * @param vm_sanitize_caller        caller of the sanitization function
 * @param map               map in which protections are going to be changed
 * @param extra_mask        extra mask to allow on top of (VM_PROT_ALL | VM_PROT_ALLEXEC)
 * @param prot              sanitized protections
 * @returns                 return code indicating success/failure of sanitization
 */
__attribute__((always_inline, warn_unused_result))
kern_return_t vm_sanitize_prot(
	vm_prot_ut              prot_u,
	vm_sanitize_caller_t    vm_sanitize_caller,
	vm_map_t                map,
	vm_prot_t               extra_mask,
	vm_prot_t              *prot);

__attribute__((always_inline, warn_unused_result, overloadable))
static inline kern_return_t
vm_sanitize_prot(
	vm_prot_ut              prot_u,
	vm_sanitize_caller_t    vm_sanitize_caller,
	vm_map_t                map,
	vm_prot_t              *prot)
{
	return vm_sanitize_prot(prot_u, vm_sanitize_caller, map, VM_PROT_NONE, prot);
}

/*!
 * @function vm_sanitize_cur_and_max_prots
 *
 * @abstract
 * Sanitization function that takes a pair of unsafe current and max protections
 * and sanitizes it.
 *
 * @param cur_prot_u        unsafe current protections
 * @param max_prot_u        unsafe max protections
 * @param vm_sanitize_caller        caller of the sanitization function
 * @param map               map in which protections are going to be changed
 * @param extra_mask        extra mask to allow on top of (VM_PROT_ALL | VM_PROT_ALLEXEC)
 * @param cur_prot          sanitized current protections
 * @param max_prot          sanitized max protections
 * @returns                 return code indicating success/failure of sanitization
 */
__attribute__((always_inline, warn_unused_result))
kern_return_t vm_sanitize_cur_and_max_prots(
	vm_prot_ut              cur_prot_u,
	vm_prot_ut              max_prot_u,
	vm_sanitize_caller_t    vm_sanitize_caller,
	vm_map_t                map,
	vm_prot_t               extra_mask,
	vm_prot_t              *cur_prot,
	vm_prot_t              *max_prot);

__attribute__((always_inline, warn_unused_result, overloadable))
static inline kern_return_t
vm_sanitize_cur_and_max_prots(
	vm_prot_ut              cur_prot_u,
	vm_prot_ut              max_prot_u,
	vm_sanitize_caller_t    vm_sanitize_caller,
	vm_map_t                map,
	vm_prot_t              *cur_prot,
	vm_prot_t              *max_prot)
{
	return vm_sanitize_cur_and_max_prots(cur_prot_u, max_prot_u, vm_sanitize_caller, map,
	           VM_PROT_NONE, cur_prot, max_prot);
}

/*!
 * @function vm_sanitize_memory_entry_perm
 *
 * @abstract
 * Sanitization function that takes unsafe memory entry permissions and
 * sanitizes it.
 *
 * @param perm_u            unsafe permissions to sanitize
 * @param vm_sanitize_caller        caller of the sanitization function
 * @param flags             flags that influence sanitization performed
 * @param extra_mask        extra mask to allow on top of VM_PROT_ALL
 * @param perm              sanitized memory entry permissions
 * @returns                 return code indicating success/failure of sanitization
 */
__attribute__((always_inline, warn_unused_result))
kern_return_t vm_sanitize_memory_entry_perm(
	vm_prot_ut              perm_u,
	vm_sanitize_caller_t    vm_sanitize_caller,
	vm_sanitize_flags_t     flags,
	vm_prot_t               extra_mask,
	vm_prot_t              *perm);

/*!
 * @function vm_sanitize_prot_bsd
 *
 * @abstract
 * Sanitization function that takes unsafe protections and sanitizes it.
 *
 * @discussion
 * Use this function for BSD callers as it strips invalid protections instead
 * of returning an error.
 *
 * @param prot_u            unsafe protections
 * @param vm_sanitize_caller        caller of the sanitization function
 * @returns                 sanitized protections
 */
__attribute__((always_inline, warn_unused_result))
vm_prot_t vm_sanitize_prot_bsd(
	vm_prot_ut              prot_u,
	vm_sanitize_caller_t    vm_sanitize_caller);

/*!
 * @function vm_sanitize_inherit
 *
 * @abstract
 * Sanitization function that takes unsafe vm_inherit and sanitizes it.
 *
 * @param inherit_u         unsafe vm_inherit
 * @param vm_sanitize_caller        caller of the sanitization function
 * @param inherit           sanitized vm_inherit
 * @returns                 return code indicating success/failure of sanitization
 */
__attribute__((always_inline, warn_unused_result))
kern_return_t vm_sanitize_inherit(
	vm_inherit_ut           inherit_u,
	vm_sanitize_caller_t    vm_sanitize_caller,
	vm_inherit_t           *inherit);

/*!
 * @function vm_sanitize_behavior
 *
 * @abstract
 * Sanitization function that takes an unsafe vm_behavior and sanitizes it.
 *
 * @param behavior_u         unsafe vm_behavior
 * @param vm_sanitize_caller caller of the sanitization function
 * @param behavior           sanitized vm_behavior
 * @returns                  return code indicating success/failure of sanitization
 */
__attribute__((always_inline, warn_unused_result))
kern_return_t vm_sanitize_behavior(
	vm_behavior_ut           behavior_u,
	vm_sanitize_caller_t    vm_sanitize_caller __unused,
	vm_behavior_t           *behavior);

#pragma GCC visibility pop
__END_DECLS
#endif /* _VM_SANITIZE_INTERNAL_H_ */
