/*
 * Copyright (c) 2000-2021 Apple Computer, Inc. All rights reserved.
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
 * @OSF_COPYRIGHT@
 */
/*
 * Mach Operating System
 * Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University
 * All Rights Reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */

#ifdef  KERNEL_PRIVATE

#ifndef _KERN_KALLOC_H_
#define _KERN_KALLOC_H_

#include <mach/machine/vm_types.h>
#include <mach/boolean.h>
#include <mach/vm_types.h>
#include <kern/zalloc.h>
#include <libkern/section_keywords.h>
#include <os/alloc_util.h>
#if XNU_KERNEL_PRIVATE
#include <kern/counter.h>
#endif /* XNU_KERNEL_PRIVATE */

__BEGIN_DECLS __ASSUME_PTR_ABI_SINGLE_BEGIN

/*!
 * @const KALLOC_SAFE_ALLOC_SIZE
 *
 * @brief
 * The maximum allocation size that is safe to allocate with Z_NOFAIL in kalloc.
 */
#define KALLOC_SAFE_ALLOC_SIZE  (16u * 1024u)

#if XNU_KERNEL_PRIVATE
/*!
 * @typedef kalloc_heap_t
 *
 * @abstract
 * A kalloc heap view represents a sub-accounting context
 * for a given kalloc heap.
 */
typedef struct kalloc_heap {
	zone_stats_t        kh_stats;
	const char         *__unsafe_indexable kh_name;
	zone_kheap_id_t     kh_heap_id;
	vm_tag_t            kh_tag;
	uint16_t            kh_type_hash;
	zone_id_t           kh_zstart;
	struct kalloc_heap *kh_views;
} *kalloc_heap_t;

/*!
 * @macro KALLOC_HEAP_DECLARE
 *
 * @abstract
 * (optionally) declare a kalloc heap view in a header.
 *
 * @discussion
 * Unlike kernel zones, new full blown heaps cannot be instantiated.
 * However new accounting views of the base heaps can be made.
 */
#define KALLOC_HEAP_DECLARE(var) \
	extern struct kalloc_heap var[1]

/**
 * @const KHEAP_ANY
 *
 * @brief
 * A value that represents either the default or kext heap for codepaths that
 * need to allow @c kheap_free() to either one.
 *
 * @discussion
 * When the memory provenance is not known, this value can be used to free
 * memory indiscriminately.
 *
 * Note: code using this constant can likely be used as a gadget to free
 * arbitrary memory and its use is strongly discouraged.
 */
#define KHEAP_ANY  ((struct kalloc_heap *)NULL)

/**
 * @const KHEAP_DATA_BUFFERS
 *
 * @brief
 * The builtin heap for bags of pure bytes.
 *
 * @discussion
 * This set of kalloc zones should contain pure bags of bytes with no pointers
 * or length/offset fields.
 *
 * The zones forming the heap aren't sequestered from each other, however the
 * entire heap lives in a different submap from any other kernel allocation.
 *
 * The main motivation behind this separation is due to the fact that a lot of
 * these objects have been used by attackers to spray the heap to make it more
 * predictable while exploiting use-after-frees or overflows.
 *
 * Common attributes that make these objects useful for spraying includes
 * control of:
 * - Data in allocation
 * - Time of alloc and free (lifetime)
 * - Size of allocation
 */
KALLOC_HEAP_DECLARE(KHEAP_DATA_BUFFERS);

/**
 * @const KHEAP_DEFAULT
 *
 * @brief
 * The builtin default core kernel kalloc heap.
 *
 * @discussion
 * This set of kalloc zones should contain other objects that don't have their
 * own security mitigations. The individual zones are themselves sequestered.
 */
KALLOC_HEAP_DECLARE(KHEAP_DEFAULT);

/**
 * @const KHEAP_KT_VAR
 *
 * @brief
 * Temporary heap for variable sized kalloc type allocations
 *
 * @discussion
 * This heap will be removed when logic for kalloc_type_var_views is added
 *
 */
KALLOC_HEAP_DECLARE(KHEAP_KT_VAR);

/*!
 * @macro KALLOC_HEAP_DEFINE
 *
 * @abstract
 * Defines a given kalloc heap view and what it points to.
 *
 * @discussion
 * Kalloc heaps are views over one of the pre-defined builtin heaps
 * (such as @c KHEAP_DATA_BUFFERS or @c KHEAP_DEFAULT). Instantiating
 * a new one allows for accounting of allocations through this view.
 *
 * Kalloc heap views are initialized during the @c STARTUP_SUB_ZALLOC phase,
 * as the last rank. If views on zones are created, these must have been
 * created before this stage.
 *
 * @param var           the name for the zone view.
 * @param name          a string describing the zone view.
 * @param heap_id       a @c KHEAP_ID_* constant.
 */
#define KALLOC_HEAP_DEFINE(var, name, heap_id) \
	SECURITY_READ_ONLY_LATE(struct kalloc_heap) var[1] = { { \
	    .kh_name = name, \
	    .kh_heap_id = heap_id, \
	} }; \
	STARTUP_ARG(ZALLOC, STARTUP_RANK_LAST, kheap_startup_init, var)


/*
 * Allocations of type SO_NAME are known to not have pointers for
 * most platforms -- for macOS this is not guaranteed
 */
#if XNU_TARGET_OS_OSX
#define KHEAP_SONAME KHEAP_DEFAULT
#else /* XNU_TARGET_OS_OSX */
#define KHEAP_SONAME KHEAP_DATA_BUFFERS
#endif /* XNU_TARGET_OS_OSX */

#endif /* XNU_KERNEL_PRIVATE */

/*!
 * @enum kalloc_type_flags_t
 *
 * @brief
 * Flags that can be passed to @c KALLOC_TYPE_DEFINE
 *
 * @discussion
 * These flags can be used to request for a specific accounting
 * behavior.
 *
 * @const KT_DEFAULT
 * Passing this flag will provide default accounting behavior
 * i.e shared accounting unless toggled with KT_OPTIONS_ACCT is
 * set in kt boot-arg.
 *
 * @const KT_PRIV_ACCT
 * Passing this flag will provide individual stats for your
 * @c kalloc_type_view that is defined.
 *
 * @const KT_SHARED_ACCT
 * Passing this flag will accumulate stats as a part of the
 * zone that your @c kalloc_type_view points to.
 *
 * @const KT_DATA_ONLY
 * Represents that the type is "data-only". Adopters should not
 * set this flag manually, it is meant for the compiler to set
 * automatically when KALLOC_TYPE_CHECK(DATA) passes.
 *
 * @const KT_VM
 * Represents that the type is large enough to use the VM. Adopters
 * should not set this flag manually, it is meant for the compiler
 * to set automatically when KALLOC_TYPE_VM_SIZE_CHECK passes.
 *
 * @const KT_PTR_ARRAY
 * Represents that the type is an array of pointers. Adopters should not
 * set this flag manually, it is meant for the compiler to set
 * automatically when KALLOC_TYPE_CHECK(PTR) passes.
 *
 * @const KT_CHANGED*
 * Represents a change in the version of the kalloc_type_view. This
 * is required inorder to decouple requiring kexts to be rebuilt to
 * use the new defintions right away. This flags should not be used
 * manually at a callsite, it is meant for internal use only. Future
 * changes to kalloc_type_view defintion should toggle this flag.
 *
 #if XNU_KERNEL_PRIVATE
 *
 * @const KT_SLID
 * To indicate that strings in the view were slid during early boot.
 *
 * @const KT_PROCESSED
 * This flag is set once the view is parse during early boot. Views
 * that are not in BootKC on macOS aren't parsed and therefore will
 * not have this flag set. The runtime can use this as an indication
 * to appropriately redirect the call.
 *
 * @const KT_HASH
 * Hash of signature used by kmem_*_guard to determine range and
 * direction for allocation
 #endif
 */
__options_decl(kalloc_type_flags_t, uint32_t, {
	KT_DEFAULT        = 0x0001,
	KT_PRIV_ACCT      = 0x0002,
	KT_SHARED_ACCT    = 0x0004,
	KT_DATA_ONLY      = 0x0008,
	KT_VM             = 0x0010,
	KT_CHANGED        = 0x0020,
	KT_CHANGED2       = 0x0040,
	KT_PTR_ARRAY      = 0x0080,
#if XNU_KERNEL_PRIVATE
	KT_SLID           = 0x4000,
	KT_PROCESSED      = 0x8000,
	KT_HASH           = 0xffff0000,
#endif
});

/*!
 * @typedef kalloc_type_view_t
 *
 * @abstract
 * A kalloc type view is a structure used to redirect callers
 * of @c kalloc_type to a particular zone based on the signature of
 * their type.
 *
 * @discussion
 * These structures are automatically created under the hood for every
 * @c kalloc_type and @c kfree_type callsite. They are ingested during startup
 * and are assigned zones based on the security policy for their signature.
 *
 * These structs are protected by the kernel lockdown and can't be initialized
 * dynamically. They must be created using @c KALLOC_TYPE_DEFINE() or
 * @c kalloc_type or @c kfree_type.
 *
 */
struct kalloc_type_view {
	struct zone_view        kt_zv;
	const char             *kt_signature __unsafe_indexable;
	kalloc_type_flags_t     kt_flags;
	uint32_t                kt_size;
	void                   *unused1;
	void                   *unused2;
};

typedef struct kalloc_type_view *kalloc_type_view_t;

/*
 * The set of zones used by all kalloc heaps are defined by the constants
 * below.
 *
 * KHEAP_START_SIZE: Size of the first sequential zone.
 * KHEAP_MAX_SIZE  : Size of the last sequential zone.
 * KHEAP_STEP_WIDTH: Number of zones created at every step (power of 2).
 * KHEAP_STEP_START: Size of the first step.
 * We also create some extra initial zones that don't follow the sequence
 * for sizes 8 (on armv7 only), 16 and 32.
 *
 * idx step_increment   zone_elem_size
 * 0       -                  16
 * 1       -                  32
 * 2       16                 48
 * 3       16                 64
 * 4       32                 96
 * 5       32                 128
 * 6       64                 192
 * 7       64                 256
 * 8       128                384
 * 9       128                512
 * 10      256                768
 * 11      256                1024
 * 12      512                1536
 * 13      512                2048
 * 14      1024               3072
 * 15      1024               4096
 * 16      2048               6144
 * 17      2048               8192
 * 18      4096               12288
 * 19      4096               16384
 * 20      8192               24576
 * 21      8192               32768
 */
#define kalloc_log2down(mask)   (31 - __builtin_clz(mask))
#define KHEAP_START_SIZE        32
#if  __x86_64__
#define KHEAP_MAX_SIZE          (16 * 1024)
#define KHEAP_EXTRA_ZONES       2
#else
#define KHEAP_MAX_SIZE          (32 * 1024)
#define KHEAP_EXTRA_ZONES       2
#endif
#define KHEAP_STEP_WIDTH        2
#define KHEAP_STEP_START        16
#define KHEAP_START_IDX         kalloc_log2down(KHEAP_START_SIZE)
#define KHEAP_NUM_STEPS         (kalloc_log2down(KHEAP_MAX_SIZE) - \
	                                kalloc_log2down(KHEAP_START_SIZE))
#define KHEAP_NUM_ZONES         (KHEAP_NUM_STEPS * KHEAP_STEP_WIDTH + \
	                                KHEAP_EXTRA_ZONES)

/*!
 * @enum kalloc_type_version_t
 *
 * @brief
 * Enum that holds versioning information for @c kalloc_type_var_view
 *
 * @const KT_V1
 * Version 1
 *
 */
__options_decl(kalloc_type_version_t, uint16_t, {
	KT_V1             = 0x0001,
});

/*!
 * @typedef kalloc_type_var_view_t
 *
 * @abstract
 * This structure is analoguous to @c kalloc_type_view but handles
 * @c kalloc_type callsites that are variable in size.
 *
 * @discussion
 * These structures are automatically created under the hood for every
 * variable sized @c kalloc_type and @c kfree_type callsite. They are ingested
 * during startup and are assigned zones based on the security policy for
 * their signature.
 *
 * These structs are protected by the kernel lockdown and can't be initialized
 * dynamically. They must be created using @c KALLOC_TYPE_VAR_DEFINE() or
 * @c kalloc_type or @c kfree_type.
 *
 */
struct kalloc_type_var_view {
	kalloc_type_version_t   kt_version;
	uint16_t                kt_size_hdr;
	/*
	 * Temporary: Needs to be 32bits cause we have many structs that use
	 * IONew/Delete that are larger than 32K.
	 */
	uint32_t                kt_size_type;
	zone_stats_t            kt_stats;
	const char             *__unsafe_indexable kt_name;
	zone_view_t             kt_next;
	zone_id_t               kt_heap_start;
	uint8_t                 kt_zones[KHEAP_NUM_ZONES];
	const char             * __unsafe_indexable kt_sig_hdr;
	const char             * __unsafe_indexable kt_sig_type;
	kalloc_type_flags_t     kt_flags;
};

typedef struct kalloc_type_var_view *kalloc_type_var_view_t;

/*!
 * @macro KALLOC_TYPE_DECLARE
 *
 * @abstract
 * (optionally) declares a kalloc type view (in a header).
 *
 * @param var           the name for the kalloc type view.
 */
#define KALLOC_TYPE_DECLARE(var) \
	extern struct kalloc_type_view var[1]

/*!
 * @macro KALLOC_TYPE_DEFINE
 *
 * @abstract
 * Defines a given kalloc type view with prefered accounting
 *
 * @discussion
 * This macro allows you to define a kalloc type with private
 * accounting. The defined kalloc_type_view can be used with
 * kalloc_type_impl/kfree_type_impl to allocate/free memory.
 * zalloc/zfree can also be used from inside xnu. However doing
 * so doesn't handle freeing a NULL pointer or the use of tags.
 *
 * @param var           the name for the kalloc type view.
 * @param type          the type of your allocation.
 * @param flags         a @c KT_* flag.
 */
#define KALLOC_TYPE_DEFINE(var, type, flags) \
	_KALLOC_TYPE_DEFINE(var, type, flags)

/*!
 * @macro KALLOC_TYPE_VAR_DECLARE
 *
 * @abstract
 * (optionally) declares a kalloc type var view (in a header).
 *
 * @param var           the name for the kalloc type var view.
 */
#define KALLOC_TYPE_VAR_DECLARE(var) \
	extern struct kalloc_type_var_view var[1]

/*!
 * @macro KALLOC_TYPE_VAR_DEFINE
 *
 * @abstract
 * Defines a given kalloc type view with prefered accounting for
 * variable sized typed allocations.
 *
 * @discussion
 * As the views aren't yet being ingested, individual stats aren't
 * available. The defined kalloc_type_var_view should be used with
 * kalloc_type_var_impl/kfree_type_var_impl to allocate/free memory.
 *
 * This macro comes in 2 variants:
 *
 * 1. @c KALLOC_TYPE_VAR_DEFINE(var, e_ty, flags)
 * 2. @c KALLOC_TYPE_VAR_DEFINE(var, h_ty, e_ty, flags)
 *
 * @param var           the name for the kalloc type var view.
 * @param h_ty          the type of header in the allocation.
 * @param e_ty          the type of repeating part in the allocation.
 * @param flags         a @c KT_* flag.
 */
#define KALLOC_TYPE_VAR_DEFINE(...) KALLOC_DISPATCH(KALLOC_TYPE_VAR_DEFINE, ##__VA_ARGS__)

#ifdef XNU_KERNEL_PRIVATE

/*
 * These versions allow specifying the kalloc heap to allocate memory
 * from
 */
#define kheap_alloc_tag(kalloc_heap, size, flags, itag) \
	__kheap_alloc(kalloc_heap, size, __zone_flags_mix_tag(flags, itag), NULL)
#define kheap_alloc(kalloc_heap, size, flags) \
	kheap_alloc_tag(kalloc_heap, size, flags, VM_ALLOC_SITE_TAG())

/*
 * These versions should be used for allocating pure data bytes that
 * do not contain any pointers
 */
#define kalloc_data_tag(size, flags, itag) \
	kheap_alloc_tag(KHEAP_DATA_BUFFERS, size, flags, itag)
#define kalloc_data(size, flags) \
	kheap_alloc(KHEAP_DATA_BUFFERS, size, flags)

#define krealloc_data_tag(elem, old_size, new_size, flags, itag) \
	__kheap_realloc(KHEAP_DATA_BUFFERS, elem, old_size, new_size, \
	    __zone_flags_mix_tag(flags, itag), NULL)
#define krealloc_data(elem, old_size, new_size, flags) \
	krealloc_data_tag(elem, old_size, new_size, flags, \
	    VM_ALLOC_SITE_TAG())

#define kfree_data(elem, size) \
	kheap_free(KHEAP_DATA_BUFFERS, elem, size);

#define kfree_data_addr(elem) \
	kheap_free_addr(KHEAP_DATA_BUFFERS, elem);

extern void
kheap_free_bounded(
	kalloc_heap_t heap,
	void         *addr __unsafe_indexable,
	vm_size_t     min_sz,
	vm_size_t     max_sz);

extern void
kalloc_data_require(
	void         *data __unsafe_indexable,
	vm_size_t     size);

extern void
kalloc_non_data_require(
	void         *data __unsafe_indexable,
	vm_size_t     size);

#else /* XNU_KERNEL_PRIVATE */

extern void *__sized_by(size)
kalloc(
	vm_size_t           size) __attribute__((malloc, alloc_size(1)));

extern void *__unsafe_indexable
kalloc_data(
	vm_size_t           size,
	zalloc_flags_t      flags);

__attribute__((malloc, alloc_size(1)))
static inline void *
__sized_by(size)
__kalloc_data(vm_size_t size, zalloc_flags_t flags)
{
	void *addr = (kalloc_data)(size, flags);
	if (flags & Z_NOFAIL) {
		__builtin_assume(addr != NULL);
	}
	return addr;
}

#define kalloc_data(size, fl) __kalloc_data(size, fl)

extern void *__unsafe_indexable
krealloc_data(
	void               *ptr __unsafe_indexable,
	vm_size_t           old_size,
	vm_size_t           new_size,
	zalloc_flags_t      flags);

__attribute__((malloc, alloc_size(3)))
static inline void *
__sized_by(new_size)
__krealloc_data(
	void               *ptr __sized_by(old_size),
	vm_size_t           old_size,
	vm_size_t           new_size,
	zalloc_flags_t      flags)
{
	void *addr = (krealloc_data)(ptr, old_size, new_size, flags);
	if (flags & Z_NOFAIL) {
		__builtin_assume(addr != NULL);
	}
	return addr;
}

#define krealloc_data(ptr, old_size, new_size, fl) \
	__krealloc_data(ptr, old_size, new_size, fl)

extern void
kfree(
	void               *data __unsafe_indexable,
	vm_size_t           size);

extern void
kfree_data(
	void               *ptr __unsafe_indexable,
	vm_size_t           size);

extern void
kfree_data_addr(
	void               *ptr __unsafe_indexable);

#endif /* !XNU_KERNEL_PRIVATE */

/*!
 * @macro kalloc_type
 *
 * @abstract
 * Allocates element of a particular type
 *
 * @discussion
 * This family of allocators segregate kalloc allocations based on their type.
 *
 * This macro comes in 3 variants:
 *
 * 1. @c kalloc_type(type, flags)
 *    Use this macro for fixed sized allocation of a particular type.
 *
 * 2. @c kalloc_type(e_type, count, flags)
 *    Use this macro for variable sized allocations that form an array,
 *    do note that @c kalloc_type(e_type, 1, flags) is not equivalent to
 *    @c kalloc_type(e_type, flags).
 *
 * 3. @c kalloc_type(hdr_type, e_type, count, flags)
 *    Use this macro for variable sized allocations formed with
 *    a header of type @c hdr_type followed by a variable sized array
 *    with elements of type @c e_type, equivalent to this:
 *
 *    <code>
 *    struct {
 *        hdr_type hdr;
 *        e_type   arr[];
 *    }
 *    </code>
 *
 * @param flags         @c zalloc_flags_t that get passed to zalloc_internal
 */
#define kalloc_type(...)  KALLOC_DISPATCH(kalloc_type, ##__VA_ARGS__)

/*!
 * @macro kfree_type
 *
 * @abstract
 * Allocates element of a particular type
 *
 * @discussion
 * This pairs with the @c kalloc_type() that was made to allocate this element.
 * Arguments passed to @c kfree_type() must match the one passed at allocation
 * time precisely.
 *
 * This macro comes in the same 3 variants kalloc_type() does:
 *
 * 1. @c kfree_type(type, elem)
 * 2. @c kfree_type(e_type, count, elem)
 * 3. @c kfree_type(hdr_type, e_type, count, elem)
 *
 * @param elem          The address of the element to free
 */
#define kfree_type(...)  KALLOC_DISPATCH(kfree_type, ##__VA_ARGS__)

#ifdef XNU_KERNEL_PRIVATE
#define kalloc_type_tag(...)     KALLOC_DISPATCH(kalloc_type_tag, ##__VA_ARGS__)
#define krealloc_type_tag(...)   KALLOC_DISPATCH(krealloc_type_tag, ##__VA_ARGS__)
#define krealloc_type(...)       KALLOC_DISPATCH(krealloc_type, ##__VA_ARGS__)

/*
 * kalloc_type_require can't be made available to kexts as the
 * kalloc_type_view's zone could be NULL in the following cases:
 * - Size greater than KALLOC_SAFE_ALLOC_SIZE
 * - On macOS, if call is not in BootKC
 * - All allocations in kext for armv7
 */
#define kalloc_type_require(type, value) ({                                    \
	static KALLOC_TYPE_DEFINE(kt_view_var, type, KT_SHARED_ACCT);          \
	zone_require(kt_view_var->kt_zv.zv_zone, value);                       \
})

#endif

/*!
 * @enum kt_granule_t
 *
 * @brief
 * Granule encodings used by the compiler for the type signature.
 *
 * @discussion
 * Given a type, the XNU signature type system (__builtin_xnu_type_signature)
 * produces a signature by analyzing its memory layout, in chunks of 8 bytes,
 * which we call granules. The encoding produced for each granule is the
 * bitwise or of the encodings of all the types of the members included
 * in that granule.
 *
 * @const KT_GRANULE_PADDING
 * Represents padding inside a record type.
 *
 * @const KT_GRANULE_POINTER
 * Represents a pointer type.
 *
 * @const KT_GRANULE_DATA
 * Represents a scalar type that is not a pointer.
 *
 * @const KT_GRANULE_DUAL
 * Currently unused.
 *
 * @const KT_GRANULE_PAC
 * Represents a pointer which is subject to PAC.
 */
__options_decl(kt_granule_t, uint32_t, {
	KT_GRANULE_PADDING = 0,
	KT_GRANULE_POINTER = 1,
	KT_GRANULE_DATA    = 2,
	KT_GRANULE_DUAL    = 4,
	KT_GRANULE_PAC     = 8
});

#define KT_GRANULE_MAX                                                \
	(KT_GRANULE_PADDING | KT_GRANULE_POINTER | KT_GRANULE_DATA |  \
	    KT_GRANULE_DUAL | KT_GRANULE_PAC)

/*
 * Convert a granule encoding to the index of the bit that
 * represents such granule in the type summary.
 *
 * The XNU type summary (__builtin_xnu_type_summary) produces a 32-bit
 * summary of the type signature of a given type. If the bit at index
 * (1 << G) is set in the summary, that means that the type contains
 * one or more granules with encoding G.
 */
#define KT_SUMMARY_GRANULE_TO_IDX(g)  (1UL << g)

#define KT_SUMMARY_MASK_TYPE_BITS  (0xffff)

#define KT_SUMMARY_MASK_DATA                             \
	(KT_SUMMARY_GRANULE_TO_IDX(KT_GRANULE_PADDING) |  \
	    KT_SUMMARY_GRANULE_TO_IDX(KT_GRANULE_DATA))

#define KT_SUMMARY_MASK_PTR                              \
	(KT_SUMMARY_GRANULE_TO_IDX(KT_GRANULE_PADDING) |     \
	    KT_SUMMARY_GRANULE_TO_IDX(KT_GRANULE_POINTER) |  \
	    KT_SUMMARY_GRANULE_TO_IDX(KT_GRANULE_PAC))

#define KT_SUMMARY_MASK_ALL_GRANULES                        \
	(KT_SUMMARY_GRANULE_TO_IDX(KT_GRANULE_PADDING) |     \
	    KT_SUMMARY_GRANULE_TO_IDX(KT_GRANULE_POINTER) |  \
	    KT_SUMMARY_GRANULE_TO_IDX(KT_GRANULE_DATA) |     \
	    KT_SUMMARY_GRANULE_TO_IDX(KT_GRANULE_DUAL) |     \
	    KT_SUMMARY_GRANULE_TO_IDX(KT_GRANULE_PAC))

/*!
 * @macro KT_SUMMARY_GRANULES
 *
 * @abstract
 * Return the granule type summary for a given type
 *
 * @discussion
 * This macro computes the type summary of a type, and it then extracts the
 * bits which carry information about the granules in the memory layout.
 *
 * Note: you should never have to use __builtin_xnu_type_summary
 * directly, as we reserve the right to use the remaining bits with
 * different semantics.
 *
 * @param type          The type to analyze
 */
#define KT_SUMMARY_GRANULES(type) \
	(__builtin_xnu_type_summary(type) & KT_SUMMARY_MASK_TYPE_BITS)

/*!
 * @macro KALLOC_TYPE_SIG_CHECK
 *
 * @abstract
 * Return whether a given type is only made up of granules specified in mask
 *
 * @param mask          Granules to check for
 * @param type          The type to analyze
 */
#define KALLOC_TYPE_SIG_CHECK(mask, type) \
	((KT_SUMMARY_GRANULES(type) & ~(mask)) == 0)

/*!
 * @macro KALLOC_TYPE_IS_DATA_ONLY
 *
 * @abstract
 * Return whether a given type is considered a data-only type.
 *
 * @param type          The type to analyze
 */
#define KALLOC_TYPE_IS_DATA_ONLY(type) \
	KALLOC_TYPE_SIG_CHECK(KT_SUMMARY_MASK_DATA, type)

/*!
 * @macro KALLOC_TYPE_HAS_OVERLAPS
 *
 * @abstract
 * Return whether a given type has overlapping granules.
 *
 * @discussion
 * This macro returns whether the memory layout for a given type contains
 * overlapping granules. An overlapping granule is a granule which includes
 * members with types that have different encodings under the XNU signature
 * type system.
 *
 * @param type          The type to analyze
 */
#define KALLOC_TYPE_HAS_OVERLAPS(type) \
	((KT_SUMMARY_GRANULES(type) & ~KT_SUMMARY_MASK_ALL_GRANULES) != 0)

/*!
 * @macro KALLOC_TYPE_IS_COMPATIBLE_PTR
 *
 * @abstract
 * Return whether pointer is compatible with a given type, in the XNU
 * signature type system.
 *
 * @discussion
 * This macro returns whether type pointed to by @c ptr is either the same
 * type as @c type, or it has the same signature. The implementation relies
 * on the @c __builtin_xnu_types_compatible builtin, and the value returned
 * can be evaluated at compile time in both C and C++.
 *
 * Note: void pointers are treated as wildcards, and are thus compatible
 * with any given type.
 *
 * @param ptr           the pointer whose type needs to be checked.
 * @param type          the type which the pointer will be checked against.
 */
#define KALLOC_TYPE_IS_COMPATIBLE_PTR(ptr, type)                   \
	_Pragma("clang diagnostic push")                               \
	_Pragma("clang diagnostic ignored \"-Wvoid-ptr-dereference\"") \
	(__builtin_xnu_types_compatible(__typeof__(*ptr), type) ||     \
	    __builtin_xnu_types_compatible(__typeof__(*ptr), void))    \
	_Pragma("clang diagnostic pop")

#define KALLOC_TYPE_ASSERT_COMPATIBLE_POINTER(ptr, type) \
	_Static_assert(KALLOC_TYPE_IS_COMPATIBLE_PTR(ptr, type), \
	    "Pointer type is not compatible with specified type")


/*!
 * @const KALLOC_ARRAY_SIZE_MAX
 *
 * @brief
 * The maximum size that can be allocated with the @c KALLOC_ARRAY interface.
 *
 * @discussion
 * This size is:
 * - ~256M on 4k or PAC systems with 16k pages
 * - ~1G on other 16k systems.
 */
#if __arm64e__
#define KALLOC_ARRAY_SIZE_MAX   ((uint32_t)PAGE_MASK << PAGE_SHIFT)
#define KALLOC_ARRAY_GRANULE    32ul
#else
#define KALLOC_ARRAY_SIZE_MAX   ((uint32_t)UINT16_MAX << PAGE_SHIFT)
#define KALLOC_ARRAY_GRANULE    16ul
#endif

/*!
 * @macro KALLOC_ARRAY_TYPE_DECL
 *
 * @brief
 * Declares a type used as a packed kalloc array type.
 *
 * @discussion
 * This macro comes in two variants
 *
 * - KALLOC_ARRAY_TYPE_DECL(name, e_ty)
 * - KALLOC_ARRAY_TYPE_DECL(name, h_ty, e_ty)
 *
 * The first one defines an array of elements of type @c e_ty,
 * and the second a header of type @c h_ty followed by
 * an array of elements of type @c e_ty.
 *
 * Those macros will then define the type @c ${name}_t as a typedef
 * to a non existent structure type, in order to avoid accidental
 * dereference of those pointers.
 *
 * kalloc array pointers are actually pointers that in addition to encoding
 * the array base pointer, also encode the allocation size (only sizes
 * up to @c KALLOC_ARRAY_SIZE_MAX bytes).
 *
 * Such pointers can be signed with data PAC properly, which will provide
 * integrity of both the base pointer, and its size.
 *
 * kalloc arrays are useful to use instead of embedding the length
 * of the allocation inside of itself, which tends to be driven by:
 *
 * - a desire to not grow the outer structure holding the pointer
 *   to this array with an extra "length" field for optional arrays,
 *   in order to save memory (see the @c ip_requests field in ports),
 *
 * - a need to be able to atomically consult the size of an allocation
 *   with respect to loading its pointer (where address dependencies
 *   traditionally gives this property) for lockless algorithms
 *   (see the IPC space table).
 *
 * Using a kalloc array is preferable for two reasons:
 *
 * - embedding lengths inside the allocation is self-referential
 *   and an appetizing target for post-exploitation strategies,
 *
 * - having a dependent load to get to the length loses out-of-order
 *   opportunities for the CPU and prone to back-to-back cache misses.
 *
 * Holding information such as a level of usage of this array
 * within itself is fine provided those quantities are validated
 * against the "count" (number of elements) or "size" (allocation
 * size in bytes) of the array before use.
 *
 *
 * This macro will define a series of functions:
 *
 * - ${name}_count_to_size() and ${name}_size_to_count()
 *   to convert between memory sizes and array element counts
 *   (taking the header size into account when it exists);
 *
 *   Note that those functions assume the count/size are corresponding
 *   to a valid allocation size within [0, KALLOC_ARRAY_SIZE_MAX].
 *
 * - ${name}_next_size() to build good allocation growth policies;
 *
 * - ${name}_base() returning a (bound-checked indexable) pointer
 *   to the header of the array (or its first element when there is
 *   no header);
 *
 * - ${name}_begin() returning a (bound-checked indexable)
 *   pointer to the first element of the the array;
 *
 * - ${name}_contains() to check if an element index is within
 *   the valid range of this allocation;
 *
 * - ${name}_next_elem() to get the next element of an array.
 *
 * - ${name}_get() and ${name}_get_nocheck() to return a pointer
 *   to a given cell of the array with (resp. without) a bound
 *   check against the array size. The bound-checked variant
 *   returns NULL for invalid indexes.
 *
 * - ${name}_alloc_by_count() and ${name}_alloc_by_size()
 *   to allocate a new array able to hold at least that many elements
 *   (resp. bytes).
 *
 * - ${name}_realloc_by_count() and ${name}_realloc_by_size()
 *   to re-allocate a new array able to hold at least that many elements
 *   (resp. bytes).
 *
 * - ${name}_free() and ${name}_free_noclear() to free such an array
 *   (resp. without nil-ing the pointer). The non-clearing variant
 *   is to be used only when nil-ing out the pointer is otherwise
 *   not allowed by C (const value, unable to take address of, ...),
 *   otherwise the normal ${name}_free() must be used.
 */
#define KALLOC_ARRAY_TYPE_DECL(...) \
	KALLOC_DISPATCH(KALLOC_ARRAY_TYPE_DECL, ##__VA_ARGS__)

#if XNU_KERNEL_PRIVATE

#define KALLOC_ARRAY_TYPE_DECL_(name, h_type_t, h_sz, e_type_t, e_sz) \
	KALLOC_TYPE_VAR_DECLARE(name ## _kt_view);                              \
	typedef struct name * __unsafe_indexable name ## _t;                    \
                                                                                \
	__pure2                                                                 \
	static inline uint32_t                                                  \
	name ## _count_to_size(uint32_t count)                                  \
	{                                                                       \
	        return (uint32_t)((h_sz) + (e_sz) * count);                     \
	}                                                                       \
                                                                                \
	__pure2                                                                 \
	static inline uint32_t                                                  \
	name ## _size_to_count(vm_size_t size)                                  \
	{                                                                       \
	        return (uint32_t)((size - (h_sz)) / (e_sz));                    \
	}                                                                       \
                                                                                \
	__pure2                                                                 \
	static inline uint32_t                                                  \
	name ## _size(name ## _t array)                                         \
	{                                                                       \
	        return __kalloc_array_size((vm_address_t)array);                \
	}                                                                       \
                                                                                \
	__pure2                                                                 \
	static inline uint32_t                                                  \
	name ## _next_size(                                                     \
	        uint32_t                min_count,                              \
	        vm_size_t               cur_size,                               \
	        uint32_t                vm_period)                              \
	{                                                                       \
	        vm_size_t size;                                                 \
                                                                                \
	        if (cur_size) {                                                 \
	                size = cur_size + (e_sz) - 1;                           \
	        } else {                                                        \
	                size = kt_size(h_sz, e_sz, min_count) - 1;              \
	        }                                                               \
	        size &= -KALLOC_ARRAY_GRANULE;                                  \
	        size += KALLOC_ARRAY_GRANULE - 1;                               \
	        size  = kalloc_next_good_size(size, vm_period);                 \
	        if (size <= KALLOC_ARRAY_SIZE_MAX) {                            \
	               return (uint32_t)size;                                   \
	        }                                                               \
	        return 2 * KALLOC_ARRAY_SIZE_MAX; /* will fail */               \
	}                                                                       \
                                                                                \
	__pure2                                                                 \
	static inline uint32_t                                                  \
	name ## _count(name ## _t array)                                        \
	{                                                                       \
	        return name ## _size_to_count(name ## _size(array));            \
	}                                                                       \
                                                                                \
	__pure2                                                                 \
	static inline h_type_t *__header_bidi_indexable                         \
	name ## _base(name ## _t array)                                         \
	{                                                                       \
	        vm_address_t base = __kalloc_array_base((vm_address_t)array);   \
	        uint32_t     size = __kalloc_array_size((vm_address_t)array);   \
                                                                                \
	        (void)size;                                                     \
	        return __unsafe_forge_bidi_indexable(h_type_t *, base, size);   \
	}                                                                       \
                                                                                \
	__pure2                                                                 \
	static inline e_type_t *__header_bidi_indexable                         \
	name ## _begin(name ## _t array)                                        \
	{                                                                       \
	        vm_address_t base = __kalloc_array_base((vm_address_t)array);   \
	        uint32_t     size = __kalloc_array_size((vm_address_t)array);   \
                                                                                \
	        (void)size;                                                     \
	        return __unsafe_forge_bidi_indexable(e_type_t *, base, size);   \
	}                                                                       \
                                                                                \
	__pure2                                                                 \
	static inline e_type_t *                                                \
	name ## _next_elem(name ## _t array, e_type_t *e)                       \
	{                                                                       \
	        vm_address_t end = __kalloc_array_end((vm_address_t)array);     \
	        vm_address_t ptr = (vm_address_t)e + sizeof(e_type_t);          \
                                                                                \
	        if (ptr + sizeof(e_type_t) <= end) {                            \
	                return __unsafe_forge_single(e_type_t *, ptr);          \
	        }                                                               \
	        return NULL;                                                    \
	}                                                                       \
                                                                                \
	__pure2                                                                 \
	static inline bool                                                      \
	name ## _contains(name ## _t array, vm_size_t i)                        \
	{                                                                       \
	        vm_size_t offs = (e_sz) + (h_sz);                               \
	        vm_size_t s;                                                    \
                                                                                \
	        if (__improbable(os_mul_and_add_overflow(i, e_sz, offs, &s))) { \
	                return false;                                           \
	        }                                                               \
	        if (__improbable(s > name ## _size(array))) {                   \
	                return false;                                           \
	        }                                                               \
	        return true;                                                    \
	}                                                                       \
                                                                                \
	__pure2                                                                 \
	static inline e_type_t * __single                                       \
	name ## _get_nocheck(name ## _t array, vm_size_t i)                     \
	{                                                                       \
	        return name ## _begin(array) + i;                               \
	}                                                                       \
                                                                                \
	__pure2                                                                 \
	static inline e_type_t * __single                                       \
	name ## _get(name ## _t array, vm_size_t i)                             \
	{                                                                       \
	        if (__probable(name ## _contains(array, i))) {                  \
	            return name ## _get_nocheck(array, i);                      \
	        }                                                               \
	        return NULL;                                                    \
	}                                                                       \
                                                                                \
	static inline name ## _t                                                \
	name ## _alloc_by_size(vm_size_t size, zalloc_flags_t fl)               \
	{                                                                       \
	        fl |= Z_KALLOC_ARRAY;                                           \
	        fl = __zone_flags_mix_tag(fl, VM_ALLOC_SITE_TAG());             \
	        return (name ## _t)kalloc_type_var_impl(name ## _kt_view,       \
	                        size, fl, NULL);                                \
	}                                                                       \
                                                                                \
	static inline name ## _t                                                \
	name ## _alloc_by_count(uint32_t count, zalloc_flags_t fl)              \
	{                                                                       \
	        return name ## _alloc_by_size(kt_size(h_sz, e_sz, count), fl);  \
	}                                                                       \
                                                                                \
	static inline name ## _t                                                \
	name ## _realloc_by_size(                                               \
	        name ## _t              array,                                  \
	        vm_size_t               new_size,                               \
	        zalloc_flags_t          fl)                                     \
	{                                                                       \
	        vm_address_t base = __kalloc_array_base((vm_address_t)array);   \
	        vm_size_t    size = __kalloc_array_size((vm_address_t)array);   \
                                                                                \
	        fl |= Z_KALLOC_ARRAY;                                           \
	        fl = __zone_flags_mix_tag(fl, VM_ALLOC_SITE_TAG());             \
	        return (name ## _t)(krealloc_ext)(name ## _kt_view,             \
	                        (void *)base, size, new_size, fl, NULL).addr;   \
	}                                                                       \
                                                                                \
	static inline name ## _t                                                \
	name ## _realloc_by_count(                                              \
	        name ## _t              array,                                  \
	        uint32_t                new_count,                              \
	        zalloc_flags_t          fl)                                     \
	{                                                                       \
	        vm_size_t new_size = kt_size(h_sz, e_sz, new_count);            \
                                                                                \
	        return name ## _realloc_by_size(array, new_size, fl);           \
	}                                                                       \
                                                                                \
	static inline void                                                      \
	name ## _free_noclear(name ## _t array)                                 \
	{                                                                       \
	        kfree_type_var_impl(name ## _kt_view,                           \
	            name ## _base(array), name ## _size(array));                \
	}                                                                       \
                                                                                \
	static inline void                                                      \
	name ## _free(name ## _t *arrayp)                                       \
	{                                                                       \
	        name ## _t array = *arrayp;                                     \
                                                                                \
	        *arrayp = NULL;                                                 \
	        kfree_type_var_impl(name ## _kt_view,                           \
	            name ## _base(array), name ## _size(array));                \
	}


/*!
 * @macro KALLOC_ARRAY_TYPE_DEFINE()
 *
 * @description
 * Defines the data structures required to pair with a KALLOC_ARRAY_TYPE_DECL()
 * kalloc array declaration.
 *
 * @discussion
 * This macro comes in two variants
 *
 * - KALLOC_ARRAY_TYPE_DEFINE(name, e_ty, flags)
 * - KALLOC_ARRAY_TYPE_DEFINE(name, h_ty, e_ty, flags)
 *
 * Those must pair with the KALLOC_ARRAY_TYPE_DECL() form being used.
 * The flags must be valid @c kalloc_type_flags_t flags.
 */
#define KALLOC_ARRAY_TYPE_DEFINE(...) \
	KALLOC_DISPATCH(KALLOC_ARRAY_TYPE_DEFINE, ##__VA_ARGS__)

/*!
 * @function kalloc_next_good_size()
 *
 * @brief
 * Allows to implement "allocation growth policies" that work well
 * with the allocator.
 *
 * @discussion
 * Note that if the caller tracks a number of elements for an array,
 * where the elements are of size S, and the current count is C,
 * then it is possible for kalloc_next_good_size(C * S, ..) to hit
 * a fixed point, clients must call with a size at least of ((C + 1) * S).
 *
 * @param size         the current "size" of the allocation (in bytes).
 * @param period       the "period" (power of 2) for the allocation growth
 *                     policy once hitting the VM sized allocations.
 */
extern vm_size_t kalloc_next_good_size(
	vm_size_t               size,
	uint32_t                period);

#pragma mark kalloc_array implementation details

#define KALLOC_ARRAY_TYPE_DECL_2(name, e_type_t) \
	KALLOC_ARRAY_TYPE_DECL_(name, e_type_t, 0, e_type_t, sizeof(e_type_t))

#define KALLOC_ARRAY_TYPE_DECL_3(name, h_type_t, e_type_t) \
	KALLOC_ARRAY_TYPE_DECL_(name, e_type_t, 0, e_type_t, sizeof(e_type_t))

#define KALLOC_ARRAY_TYPE_DEFINE_3(name, e_type_t, flags) \
	KALLOC_TYPE_VAR_DEFINE_3(name ## _kt_view, e_type_t, flags)

#define KALLOC_ARRAY_TYPE_DEFINE_4(name, h_type_t, e_type_t, flags) \
	KALLOC_TYPE_VAR_DEFINE_4(name ## _kt_view, h_type_t, e_type_t, flags)

extern struct kalloc_result __kalloc_array_decode(
	vm_address_t            array) __pure2;

__pure2
static inline uint32_t
__kalloc_array_size(vm_address_t array)
{
	vm_address_t size = __kalloc_array_decode(array).size;

	__builtin_assume(size <= KALLOC_ARRAY_SIZE_MAX);
	return (uint32_t)size;
}

__pure2
static inline vm_address_t
__kalloc_array_base(vm_address_t array)
{
	return (vm_address_t)__kalloc_array_decode(array).addr;
}

__pure2
static inline vm_address_t
__kalloc_array_begin(vm_address_t array, vm_size_t hdr_size)
{
	return (vm_address_t)__kalloc_array_decode(array).addr + hdr_size;
}

__pure2
static inline vm_address_t
__kalloc_array_end(vm_address_t array)
{
	struct kalloc_result kr = __kalloc_array_decode(array);

	return (vm_address_t)kr.addr + kr.size;
}

#else /* !XNU_KERNEL_PRIVATE */

#define KALLOC_ARRAY_TYPE_DECL_(name, h_type_t, h_sz, e_type_t, e_sz) \
	typedef struct name * __unsafe_indexable name ## _t

#endif /* !XNU_KERNEL_PRIVATE */
#pragma mark implementation details


static inline void *__unsafe_indexable
kt_mangle_var_view(kalloc_type_var_view_t kt_view)
{
	return (void *__unsafe_indexable)((uintptr_t)kt_view | 1ul);
}

static inline kalloc_type_var_view_t __unsafe_indexable
kt_demangle_var_view(void *ptr)
{
	return (kalloc_type_var_view_t __unsafe_indexable)((uintptr_t)ptr & ~1ul);
}

#define kt_is_var_view(ptr)  ((uintptr_t)(ptr) & 1)

static inline vm_size_t
kt_size(vm_size_t s1, vm_size_t s2, vm_size_t c2)
{
	/* kalloc_large() will reject this size before even asking the VM  */
	const vm_size_t limit = 1ull << (8 * sizeof(vm_size_t) - 1);

	if (os_mul_and_add_overflow(s2, c2, s1, &s1) || (s1 & limit)) {
		return limit;
	}
	return s1;
}

#ifndef __ZONE_DECLARE_TYPE
#define __ZONE_DECLARE_TYPE(var, type_t)  ((void)0)
#endif

#define kalloc_type_2(type, flags) ({                                          \
	__ZONE_DECLARE_TYPE(kt_view_var, type);                                \
	static KALLOC_TYPE_DEFINE(kt_view_var, type, KT_SHARED_ACCT);          \
	__unsafe_forge_single(type *, kalloc_type_impl(kt_view_var, flags));   \
})

#define kfree_type_2(type, elem) ({                                            \
	KALLOC_TYPE_ASSERT_COMPATIBLE_POINTER(elem, type);                     \
	static KALLOC_TYPE_DEFINE(kt_view_var, type, KT_SHARED_ACCT);          \
	kfree_type_impl(kt_view_var, os_ptr_load_and_erase(elem));             \
})

#define kfree_type_3(type, count, elem) ({                                     \
	KALLOC_TYPE_ASSERT_COMPATIBLE_POINTER(elem, type);                     \
	static KALLOC_TYPE_VAR_DEFINE_3(kt_view_var, type, KT_SHARED_ACCT);    \
	__auto_type __kfree_count = (count);                                   \
	kfree_type_var_impl(kt_view_var, os_ptr_load_and_erase(elem),          \
	    kt_size(0, sizeof(type), __kfree_count));                          \
})

#define kfree_type_4(hdr_ty, e_ty, count, elem) ({                             \
	KALLOC_TYPE_ASSERT_COMPATIBLE_POINTER(elem, hdr_ty);                   \
	static KALLOC_TYPE_VAR_DEFINE_4(kt_view_var, hdr_ty, e_ty,             \
	    KT_SHARED_ACCT);                                                   \
	__auto_type __kfree_count = (count);                                   \
	kfree_type_var_impl(kt_view_var,                                       \
	    os_ptr_load_and_erase(elem),                                       \
	    kt_size(sizeof(hdr_ty), sizeof(e_ty), __kfree_count));             \
})

#ifdef XNU_KERNEL_PRIVATE
#define kalloc_type_tag_3(type, flags, tag) ({                                 \
	static KALLOC_TYPE_DEFINE(kt_view_var, type, KT_SHARED_ACCT);          \
	__unsafe_forge_single(type *, zalloc_flags(kt_view_var,                \
	    Z_VM_TAG(flags, tag)));                                            \
})

#define kalloc_type_tag_4(type, count, flags, tag) ({                          \
	static KALLOC_TYPE_VAR_DEFINE_3(kt_view_var, type, KT_SHARED_ACCT);    \
	(type *)kalloc_type_var_impl(kt_view_var,                              \
	    kt_size(0, sizeof(type), count),                                   \
	    __zone_flags_mix_tag(flags, tag), NULL);                           \
})
#define kalloc_type_3(type, count, flags)  \
	kalloc_type_tag_4(type, count, flags, VM_ALLOC_SITE_TAG())

#define kalloc_type_tag_5(hdr_ty, e_ty, count, flags, tag) ({                  \
	static KALLOC_TYPE_VAR_DEFINE_4(kt_view_var, hdr_ty, e_ty,             \
	    KT_SHARED_ACCT);                                                   \
	(hdr_ty *)kalloc_type_var_impl(kt_view_var,                            \
	    kt_size(sizeof(hdr_ty), sizeof(e_ty), count),                      \
	    __zone_flags_mix_tag(flags, tag), NULL);                           \
})
#define kalloc_type_4(hdr_ty, e_ty, count, flags) \
	kalloc_type_tag_5(hdr_ty, e_ty, count, flags, VM_ALLOC_SITE_TAG())

#define krealloc_type_tag_6(type, old_count, new_count, elem, flags, tag) ({   \
	static KALLOC_TYPE_VAR_DEFINE_3(kt_view_var, type, KT_SHARED_ACCT);    \
	KALLOC_TYPE_ASSERT_COMPATIBLE_POINTER(elem, type);                     \
	(type *)__krealloc_type(kt_view_var, elem,                             \
	    kt_size(0, sizeof(type), old_count),                               \
	    kt_size(0, sizeof(type), new_count),                               \
	    __zone_flags_mix_tag(flags, tag), NULL);                           \
})
#define krealloc_type_5(type, old_count, new_count, elem, flags) \
	krealloc_type_tag_6(type, old_count, new_count, elem, flags, \
	    VM_ALLOC_SITE_TAG())

#define krealloc_type_tag_7(hdr_ty, e_ty, old_count, new_count, elem,          \
	    flags, tag) ({                                                     \
	static KALLOC_TYPE_VAR_DEFINE_4(kt_view_var, hdr_ty, e_ty,             \
	    KT_SHARED_ACCT);                                                   \
	KALLOC_TYPE_ASSERT_COMPATIBLE_POINTER(elem, hdr_ty);                   \
	(hdr_ty *)__krealloc_type(kt_view_var, elem,                           \
	    kt_size(sizeof(hdr_ty), sizeof(e_ty), old_count),                  \
	    kt_size(sizeof(hdr_ty), sizeof(e_ty), new_count),                  \
	    __zone_flags_mix_tag(flags, tag), NULL);                           \
})
#define krealloc_type_6(hdr_ty, e_ty, old_count, new_count, elem, flags) \
	krealloc_type_tag_7(hdr_ty, e_ty, old_count, new_count, elem, flags,   \
	    VM_ALLOC_SITE_TAG())

#else /* XNU_KERNEL_PRIVATE */

#define kalloc_type_3(type, count, flags) ({                                   \
	_Static_assert((flags) == Z_WAITOK, "kexts can only pass Z_WAITOK");   \
	static KALLOC_TYPE_VAR_DEFINE_3(kt_view_var, type, KT_SHARED_ACCT);    \
	(type *)kalloc_type_var_impl(kt_view_var,                              \
	    kt_size(0, sizeof(type), count), flags, NULL);                     \
})

#define kalloc_type_4(hdr_ty, e_ty, count, flags) ({                           \
	_Static_assert((flags) == Z_WAITOK, "kexts can only pass Z_WAITOK");   \
	static KALLOC_TYPE_VAR_DEFINE_4(kt_view_var, hdr_ty, e_ty,             \
	    KT_SHARED_ACCT);                                                   \
	(hdr_ty *)kalloc_type_var_impl(kt_view_var, kt_size(sizeof(hdr_ty),    \
	    sizeof(e_ty), count), flags, NULL);                                \
})

#endif /* !XNU_KERNEL_PRIVATE */

/*
 * All k*free macros set "elem" to NULL on free.
 *
 * Note: all values passed to k*free() might be in the element to be freed,
 *       temporaries must be taken, and the resetting to be done prior to free.
 */
#ifdef XNU_KERNEL_PRIVATE

#define kheap_free(heap, elem, size) ({                                        \
	kalloc_heap_t __kfree_heap = (heap);                                   \
	__auto_type __kfree_size = (size);                                     \
	__builtin_assume(!kt_is_var_view(__kfree_heap));                       \
	kfree_ext((void *)__kfree_heap,                                        \
	    (void *)os_ptr_load_and_erase(elem), __kfree_size);                \
})

#define kheap_free_addr(heap, elem) ({                                         \
	kalloc_heap_t __kfree_heap = (heap);                                   \
	kfree_addr_ext(__kfree_heap, (void *)os_ptr_load_and_erase(elem));     \
})

#define kheap_free_bounded(heap, elem, min_sz, max_sz) ({                      \
	static_assert(max_sz <= KALLOC_SAFE_ALLOC_SIZE);                       \
	kalloc_heap_t __kfree_heap = (heap);                                   \
	__auto_type __kfree_min_sz = (min_sz);                                 \
	__auto_type __kfree_max_sz = (max_sz);                                 \
	(kheap_free_bounded)(__kfree_heap,                                     \
	    (void *)os_ptr_load_and_erase(elem),                               \
	    __kfree_min_sz, __kfree_max_sz);                                   \
})

#else /* XNU_KERNEL_PRIVATE */

#define kfree_data(elem, size) ({                                              \
	__auto_type __kfree_size = (size);                                     \
	(kfree_data)((void *)os_ptr_load_and_erase(elem), __kfree_size);       \
})

#define kfree_data_addr(elem) \
	(kfree_data_addr)((void *)os_ptr_load_and_erase(elem))

#endif /* !XNU_KERNEL_PRIVATE */

#if __has_feature(address_sanitizer)
# define __kalloc_no_kasan __attribute__((no_sanitize("address")))
#else
# define __kalloc_no_kasan
#endif

#define KALLOC_CONCAT(x, y) __CONCAT(x,y)

#define KALLOC_COUNT_ARGS1(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, N, ...) N
#define KALLOC_COUNT_ARGS(...) \
	KALLOC_COUNT_ARGS1(, ##__VA_ARGS__, _9, _8, _7, _6, _5, _4, _3, _2, _1, _0)
#define KALLOC_DISPATCH1(base, N, ...) __CONCAT(base, N)(__VA_ARGS__)
#define KALLOC_DISPATCH(base, ...) \
	KALLOC_DISPATCH1(base, KALLOC_COUNT_ARGS(__VA_ARGS__), ##__VA_ARGS__)
#define KALLOC_DISPATCH1_R(base, N, ...) __CONCAT(base, N)(__VA_ARGS__)
#define KALLOC_DISPATCH_R(base, ...) \
	KALLOC_DISPATCH1_R(base, KALLOC_COUNT_ARGS(__VA_ARGS__), ##__VA_ARGS__)

#define kt_view_var \
	KALLOC_CONCAT(kalloc_type_view_, __LINE__)

#define KALLOC_TYPE_SEGMENT "__DATA_CONST"

/*
 * When kalloc_type_impl is called from xnu, it calls zalloc_flags
 * directly and doesn't redirect zone-less sites to kheap_alloc.
 * Passing a size larger than KHEAP_MAX_SIZE for these allocations will
 * lead to a panic as the zone is null. Therefore assert that size
 * is less than KALLOC_SAFE_ALLOC_SIZE.
 */
#ifdef XNU_KERNEL_PRIVATE
#define KALLOC_TYPE_SIZE_CHECK(size)                           \
	_Static_assert(size <= KALLOC_SAFE_ALLOC_SIZE,             \
	"type is too large");
#else
#define KALLOC_TYPE_SIZE_CHECK(size)
#endif

#define KALLOC_TYPE_CHECK_2(check, type) \
	(KALLOC_TYPE_SIG_CHECK(check, type))

#define KALLOC_TYPE_CHECK_3(check, type1, type2) \
	(KALLOC_TYPE_SIG_CHECK(check, type1) && \
	    KALLOC_TYPE_SIG_CHECK(check, type2))

#define KALLOC_TYPE_CHECK(...) \
	KALLOC_DISPATCH_R(KALLOC_TYPE_CHECK, ##__VA_ARGS__)

#define KALLOC_TYPE_VM_SIZE_CHECK_1(type) \
	(sizeof(type) > KHEAP_MAX_SIZE)

#define KALLOC_TYPE_VM_SIZE_CHECK_2(type1, type2) \
	(sizeof(type1) + sizeof(type2) > KHEAP_MAX_SIZE)

#define KALLOC_TYPE_VM_SIZE_CHECK(...) \
	KALLOC_DISPATCH_R(KALLOC_TYPE_VM_SIZE_CHECK, ##__VA_ARGS__)

#define KALLOC_TYPE_TRAILING_DATA_CHECK(hdr_ty, elem_ty)     \
	_Static_assert((KALLOC_TYPE_IS_DATA_ONLY(hdr_ty) ||  \
	    !KALLOC_TYPE_IS_DATA_ONLY(elem_ty)),             \
	"cannot allocate data-only array of " #elem_ty       \
	" contiguously to " #hdr_ty)

#ifdef __cplusplus
#define KALLOC_TYPE_CAST_FLAGS(flags) static_cast<kalloc_type_flags_t>(flags)
#else
#define KALLOC_TYPE_CAST_FLAGS(flags) (kalloc_type_flags_t)(flags)
#endif

/*
 * Don't emit signature if type is "data-only" or is large enough that it
 * uses the VM.
 *
 * Note: sig_type is the type you want to emit signature for. The variable
 * args can be used to provide other types in the allocation, to make the
 * decision of whether to emit the signature.
 */
#define KALLOC_TYPE_EMIT_SIG(sig_type, ...)                              \
	(KALLOC_TYPE_CHECK(KT_SUMMARY_MASK_DATA, sig_type, ##__VA_ARGS__) || \
	KALLOC_TYPE_VM_SIZE_CHECK(sig_type, ##__VA_ARGS__))?                 \
	"" : __builtin_xnu_type_signature(sig_type)

/*
 * Kalloc type flags are adjusted to indicate if the type is "data-only" or
 * will use the VM or is a pointer array.
 */
#define KALLOC_TYPE_ADJUST_FLAGS(flags, ...)                                 \
	KALLOC_TYPE_CAST_FLAGS((flags | KT_CHANGED | KT_CHANGED2 |               \
	(KALLOC_TYPE_CHECK(KT_SUMMARY_MASK_DATA, __VA_ARGS__)? KT_DATA_ONLY: 0) |\
	(KALLOC_TYPE_CHECK(KT_SUMMARY_MASK_PTR, __VA_ARGS__)? KT_PTR_ARRAY: 0) | \
	(KALLOC_TYPE_VM_SIZE_CHECK(__VA_ARGS__)? KT_VM : 0)))

#define _KALLOC_TYPE_DEFINE(var, type, flags)                       \
	__kalloc_no_kasan                                               \
	__PLACE_IN_SECTION(KALLOC_TYPE_SEGMENT ", __kalloc_type, "      \
	    "regular, live_support")                                    \
	struct kalloc_type_view var[1] = { {                            \
	    .kt_zv.zv_name = "site." #type,                             \
	    .kt_flags = KALLOC_TYPE_ADJUST_FLAGS(flags, type),          \
	    .kt_size = sizeof(type),                                    \
	    .kt_signature = KALLOC_TYPE_EMIT_SIG(type),                 \
	} };                                                            \
	KALLOC_TYPE_SIZE_CHECK(sizeof(type));

#define KALLOC_TYPE_VAR_DEFINE_3(var, type, flags)                  \
	__kalloc_no_kasan                                               \
	__PLACE_IN_SECTION(KALLOC_TYPE_SEGMENT ", __kalloc_var, "       \
	    "regular, live_support")                                    \
	struct kalloc_type_var_view var[1] = { {                        \
	    .kt_version = KT_V1,                                        \
	    .kt_name = "site." #type,                                   \
	    .kt_flags = KALLOC_TYPE_ADJUST_FLAGS(flags, type),          \
	    .kt_size_type = sizeof(type),                               \
	    .kt_sig_type = KALLOC_TYPE_EMIT_SIG(type),                  \
	} };                                                            \
	KALLOC_TYPE_SIZE_CHECK(sizeof(type));

#define KALLOC_TYPE_VAR_DEFINE_4(var, hdr, type, flags)             \
	__kalloc_no_kasan                                               \
	__PLACE_IN_SECTION(KALLOC_TYPE_SEGMENT ", __kalloc_var, "       \
	    "regular, live_support")                                    \
	struct kalloc_type_var_view var[1] = { {                        \
	    .kt_version = KT_V1,                                        \
	    .kt_name = "site." #hdr "." #type,                          \
	    .kt_flags = KALLOC_TYPE_ADJUST_FLAGS(flags, hdr, type),     \
	    .kt_size_hdr = sizeof(hdr),                                 \
	    .kt_size_type = sizeof(type),                               \
	    .kt_sig_hdr = KALLOC_TYPE_EMIT_SIG(hdr, type),              \
	    .kt_sig_type = KALLOC_TYPE_EMIT_SIG(type, hdr),             \
	} };                                                            \
	KALLOC_TYPE_SIZE_CHECK(sizeof(hdr));                            \
	KALLOC_TYPE_SIZE_CHECK(sizeof(type));                           \
	KALLOC_TYPE_TRAILING_DATA_CHECK(hdr, type);

#ifndef XNU_KERNEL_PRIVATE
/*
 * This macro is currently used by AppleImage4
 */
#define KALLOC_TYPE_DEFINE_SITE(var, type, flags)       \
	static _KALLOC_TYPE_DEFINE(var, type, flags)

#endif /* !XNU_KERNEL_PRIVATE */

#ifdef XNU_KERNEL_PRIVATE

#define kalloc_type_impl(kt_view, flags) \
	zalloc_flags(kt_view, flags)

static inline void
kfree_type_impl(kalloc_type_view_t kt_view, void *__unsafe_indexable ptr)
{
	if (NULL == ptr) {
		return;
	}
	zfree(kt_view, ptr);
}

extern struct kalloc_result
kalloc_ext(
	void                   *kheap_or_kt_view __unsafe_indexable,
	vm_size_t               size,
	zalloc_flags_t          flags,
	void                   *site);

static inline struct kalloc_result
__kalloc_ext(
	void                   *kheap_or_kt_view __unsafe_indexable,
	vm_size_t               size,
	zalloc_flags_t          flags,
	void                   *site)
{
	struct kalloc_result kr;

	kr    = (kalloc_ext)(kheap_or_kt_view, size, flags, site);
	if (flags & Z_NOFAIL) {
		__builtin_assume(kr.addr != NULL);
	}
	return kr;
}

#define kalloc_ext(hov, size, fl, site) __kalloc_ext(hov, size, fl, site)

extern void
kfree_ext(
	void                   *kheap_or_kt_view __unsafe_indexable,
	void                   *addr __unsafe_indexable,
	vm_size_t               size);

// rdar://87559422
static inline void *__unsafe_indexable
kalloc_type_var_impl(
	kalloc_type_var_view_t    kt_view,
	vm_size_t                 size,
	zalloc_flags_t            flags,
	void                      *site)
{
	struct kalloc_result kr;

	kr = kalloc_ext(kt_mangle_var_view(kt_view), size, flags, site);
	return kr.addr;
}

static inline void
kfree_type_var_impl(
	kalloc_type_var_view_t      kt_view,
	void                       *ptr __unsafe_indexable,
	vm_size_t                   size)
{
	kfree_ext(kt_mangle_var_view(kt_view), ptr, size);
}

#else /* XNU_KERNEL_PRIVATE */

extern void *__unsafe_indexable
kalloc_type_impl(
	kalloc_type_view_t  kt_view,
	zalloc_flags_t      flags);

static inline void *__unsafe_indexable
__kalloc_type_impl(
	kalloc_type_view_t  kt_view,
	zalloc_flags_t      flags)
{
	void *addr = (kalloc_type_impl)(kt_view, flags);
	if (flags & Z_NOFAIL) {
		__builtin_assume(addr != NULL);
	}
	return addr;
}

#define kalloc_type_impl(ktv, fl) __kalloc_type_impl(ktv, fl)

extern void
kfree_type_impl(
	kalloc_type_view_t  kt_view,
	void                *ptr __unsafe_indexable);

extern void *__unsafe_indexable
kalloc_type_var_impl(
	kalloc_type_var_view_t  kt_view,
	vm_size_t               size,
	zalloc_flags_t          flags,
	void                   *site);

__attribute__((malloc, alloc_size(2)))
static inline void *
__sized_by(size)
__kalloc_type_var_impl(
	kalloc_type_var_view_t  kt_view,
	vm_size_t               size,
	zalloc_flags_t          flags,
	void                   *site)
{
	void *addr = (kalloc_type_var_impl)(kt_view, size, flags, site);
	if (flags & Z_NOFAIL) {
		__builtin_assume(addr != NULL);
	}
	return addr;
}

#define kalloc_type_var_impl(ktv, size, fl, site) \
	__kalloc_type_var_impl(ktv, size, fl, site)

extern void
kfree_type_var_impl(
	kalloc_type_var_view_t  kt_view,
	void                   *ptr __unsafe_indexable,
	vm_size_t               size);

#endif /* !XNU_KERNEL_PRIVATE */

void *
kalloc_type_impl_external(
	kalloc_type_view_t  kt_view,
	zalloc_flags_t      flags);

void
kfree_type_impl_external(
	kalloc_type_view_t  kt_view,
	void               *ptr __unsafe_indexable);

extern void *
OSObject_typed_operator_new(
	kalloc_type_view_t  ktv,
	vm_size_t           size);

extern void
OSObject_typed_operator_delete(
	kalloc_type_view_t  ktv,
	void               *mem __unsafe_indexable,
	vm_size_t           size);

#ifdef XNU_KERNEL_PRIVATE
#pragma GCC visibility push(hidden)

#define KALLOC_TYPE_SIZE_MASK  0xffffff
#define KALLOC_TYPE_IDX_SHIFT  24
#define KALLOC_TYPE_IDX_MASK   0xff

static inline uint32_t
kalloc_type_get_size(uint32_t kt_size)
{
	return kt_size & KALLOC_TYPE_SIZE_MASK;
}

bool
IOMallocType_from_vm(
	kalloc_type_view_t ktv);

/* Used by kern_os_* and operator new */
KALLOC_HEAP_DECLARE(KERN_OS_MALLOC);

extern void
kheap_startup_init(
	kalloc_heap_t heap);

__attribute__((malloc, alloc_size(2)))
static inline void *
__sized_by(size)
__kheap_alloc(
	kalloc_heap_t           kheap,
	vm_size_t               size,
	zalloc_flags_t          flags,
	void                   *site)
{
	struct kalloc_result kr;
	__builtin_assume(!kt_is_var_view(kheap));
	kr = kalloc_ext(kheap, size, flags, site);
	return __unsafe_forge_bidi_indexable(void *, kr.addr, size);
}

extern struct kalloc_result
krealloc_ext(
	void                   *kheap_or_kt_view __unsafe_indexable,
	void                   *addr __unsafe_indexable,
	vm_size_t               old_size,
	vm_size_t               new_size,
	zalloc_flags_t          flags,
	void                   *site);

static inline struct kalloc_result
__krealloc_ext(
	void                   *kheap_or_kt_view __unsafe_indexable,
	void                   *addr __sized_by(old_size),
	vm_size_t               old_size,
	vm_size_t               new_size,
	zalloc_flags_t          flags,
	void                   *site)
{
	struct kalloc_result kr = (krealloc_ext)(kheap_or_kt_view, addr, old_size,
	    new_size, flags, site);
	if (flags & Z_NOFAIL) {
		__builtin_assume(kr.addr != NULL);
	}
	return kr;
}

#define krealloc_ext(hov, addr, old_size, new_size, fl, site) \
	__krealloc_ext(hov, addr, old_size, new_size, fl, site)

__attribute__((malloc, alloc_size(4)))
static inline void *
__sized_by(new_size)
__kheap_realloc(
	kalloc_heap_t           kheap,
	void                   *addr __sized_by(old_size),
	vm_size_t               old_size,
	vm_size_t               new_size,
	zalloc_flags_t          flags,
	void                   *site)
{
	struct kalloc_result kr;
	__builtin_assume(!kt_is_var_view(kheap));
	kr = krealloc_ext(kheap, addr, old_size, new_size, flags, site);
	return __unsafe_forge_bidi_indexable(void *, kr.addr, new_size);
}

__attribute__((malloc, alloc_size(4)))
static inline void *
__sized_by(new_size)
__krealloc_type(
	kalloc_type_var_view_t  kt_view,
	void                   *addr __sized_by(old_size),
	vm_size_t               old_size,
	vm_size_t               new_size,
	zalloc_flags_t          flags,
	void                   *site)
{
	struct kalloc_result kr;
	kr = krealloc_ext(kt_mangle_var_view(kt_view), addr,
	    old_size, new_size, flags, site);
	return __unsafe_forge_bidi_indexable(void *, kr.addr, new_size);
}

extern void
kfree_addr_ext(
	kalloc_heap_t           kheap,
	void                   *addr __unsafe_indexable);

extern zone_t
kalloc_zone_for_size(
	zone_id_t             zid,
	vm_size_t             size);

extern vm_size_t kalloc_large_max;
SCALABLE_COUNTER_DECLARE(kalloc_large_count);
SCALABLE_COUNTER_DECLARE(kalloc_large_total);

extern void
kern_os_typed_free(
	kalloc_type_view_t    ktv,
	void                 *addr __unsafe_indexable,
	vm_size_t             esize);

#pragma GCC visibility pop
#endif  /* !XNU_KERNEL_PRIVATE */

extern void
kern_os_zfree(
	zone_t        zone,
	void         *addr __unsafe_indexable,
	vm_size_t     size);

__ASSUME_PTR_ABI_SINGLE_END __END_DECLS

#endif  /* _KERN_KALLOC_H_ */

#endif  /* KERNEL_PRIVATE */
