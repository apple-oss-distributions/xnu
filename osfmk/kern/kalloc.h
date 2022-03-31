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

__BEGIN_DECLS __ASSUME_PTR_ABI_SINGLE_BEGIN

/*!
 * @const KALLOC_SAFE_ALLOC_SIZE
 *
 * @brief
 * The maximum allocation size that is safe to allocate with Z_NOFAIL in kalloc.
 */
#if __LP64__
#define KALLOC_SAFE_ALLOC_SIZE  (16u * 1024u)
#else
#define KALLOC_SAFE_ALLOC_SIZE  (8u * 1024u)
#endif

#if XNU_KERNEL_PRIVATE
/*!
 * @typedef kalloc_heap_t
 *
 * @abstract
 * A kalloc heap view represents a sub-accounting context
 * for a given kalloc heap.
 */
typedef struct kalloc_heap {
	struct kheap_zones *kh_zones;
	zone_stats_t        kh_stats;
	const char         *kh_name __unsafe_indexable;
	struct kalloc_heap *kh_next;
	zone_kheap_id_t     kh_heap_id;
	vm_map_t            kh_large_map;
	vm_map_t            kh_fallback_map;
	vm_tag_t            kh_tag;
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
 * @const KHEAP_KEXT
 *
 * @brief
 * The builtin heap for allocations made by kexts.
 *
 * @discussion
 * This set of kalloc zones should contain allocations from kexts and the
 * individual zones in this heap are sequestered.
 */
KALLOC_HEAP_DECLARE(KHEAP_KEXT);

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

#endif/* XNU_KERNEL_PRIVATE */

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
 * @const KT_VM_TAG_MASK
 * Represents bits in which a vm_tag_t for the allocation can be passed.
 * (used for the zone tagging debugging feature).
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
	/** used to propagate vm tags for -zt */
	KT_VM_TAG_MASK    = 0xffff0000,
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
 * "Heaps" or sets of zones, used for variable size kalloc_type allocations
 * are defined by the constants below.
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
#if !defined(__LP64__)
#define KHEAP_MAX_SIZE          8 * 1024
#define KHEAP_EXTRA_ZONES       3
#elif  __x86_64__
#define KHEAP_MAX_SIZE          16 * 1024
#define KHEAP_EXTRA_ZONES       2
#else
#define KHEAP_MAX_SIZE          32 * 1024
#define KHEAP_EXTRA_ZONES       2
#endif
#define KHEAP_STEP_WIDTH        2
#define KHEAP_STEP_START        16
#define KHEAP_START_IDX         kalloc_log2down(KHEAP_START_SIZE)
#define KHEAP_NUM_STEPS         (kalloc_log2down(KHEAP_MAX_SIZE) - \
	                                kalloc_log2down(KHEAP_START_SIZE))
#define KHEAP_NUM_ZONES         KHEAP_NUM_STEPS * KHEAP_STEP_WIDTH \
	                                + KHEAP_EXTRA_ZONES

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
	const char             *kt_name __unsafe_indexable;
	zone_view_t             kt_next;
	zone_id_t               kt_heap_start;
	uint8_t                 kt_zones[KHEAP_NUM_ZONES];
	const char             *kt_sig_hdr __unsafe_indexable;
	const char             *kt_sig_type __unsafe_indexable;
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
#define kheap_alloc_site(kalloc_heap, size, flags, site) \
	__kheap_alloc_site(kalloc_heap, size, flags, site)

#define kheap_alloc(kalloc_heap, size, flags) \
	({ VM_ALLOC_SITE_STATIC(0, 0); \
	kheap_alloc_site(kalloc_heap, size, flags, &site); })

#define kheap_alloc_tag(kalloc_heap, size, flags, itag) \
	kheap_alloc_site(kalloc_heap, size, Z_VM_TAG(flags, itag), NULL)

/*
 * These versions should be used for allocating pure data bytes that
 * do not contain any pointers
 */
#define kalloc_data_site(size, flags, site) \
	kheap_alloc_site(KHEAP_DATA_BUFFERS, size, flags, site)

#define kalloc_data(size, flags) \
	kheap_alloc(KHEAP_DATA_BUFFERS, size, flags)

#define kalloc_data_tag(size, flags, itag) \
	kheap_alloc_tag(KHEAP_DATA_BUFFERS, size, flags, itag)

#define krealloc_data_site(elem, old_size, new_size, flags, site) \
	__krealloc_site(KHEAP_DATA_BUFFERS, elem, old_size, new_size, flags, site)

#define krealloc_data(elem, old_size, new_size, flags) \
	({ VM_ALLOC_SITE_STATIC(0, 0); \
	krealloc_data_site(elem, old_size, new_size, flags, &site); })

#define krealloc_data_tag(elem, old_size, new_size, flags, itag) \
	krealloc_data_site(KHEAP_DATA_BUFFERS, elem, old_size, new_size, \
	    Z_VM_TAG(flags, itag), NULL)

#define kfree_data(elem, size) \
	kheap_free(KHEAP_DATA_BUFFERS, elem, size);

#define kfree_data_addr(elem) \
	kheap_free_addr(KHEAP_DATA_BUFFERS, elem);

extern void
kheap_free(
	kalloc_heap_t heap,
	void         *data  __unsafe_indexable,
	vm_size_t     size);

extern void
kheap_free_addr(
	kalloc_heap_t heap,
	void         *addr __unsafe_indexable);

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

extern void *__sized_by(size)
kalloc_data(
	vm_size_t           size,
	zalloc_flags_t      flags) __attribute__((malloc, alloc_size(1)));

extern void *__sized_by(new_size)
krealloc_data(
	void               *ptr __unsafe_indexable,
	vm_size_t           old_size,
	vm_size_t           new_size,
	zalloc_flags_t      flags) __attribute__((malloc, alloc_size(3)));

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
#define kalloc_type_site(...)    KALLOC_DISPATCH(kalloc_type_site, ##__VA_ARGS__)
#define kalloc_type_tag(...)     KALLOC_DISPATCH(kalloc_type_tag, ##__VA_ARGS__)
#define krealloc_type_site(...)  KALLOC_DISPATCH(krealloc_type_site, ##__VA_ARGS__)
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
	zone_require(kt_view_var->kt_zv, value);                               \
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
 * @macro KALLOC_TYPE_IS_DATA_ONLY
 *
 * @abstract
 * Return whether a given type is considered a data-only type.
 *
 * @param type          The type to analyze
 */
#define KALLOC_TYPE_IS_DATA_ONLY(type) \
    ((KT_SUMMARY_GRANULES(type) & ~KT_SUMMARY_MASK_DATA) == 0)

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


#pragma mark implementation details

#ifdef XNU_KERNEL_PRIVATE

#define KFREE_TYPE_ASSERT_COMPATIBLE_POINTER(ptr, type)          \
	_Static_assert(os_is_compatible_ptr(ptr, type),           \
	    "Pointer type is not compatible with specified type")

#else  /* XNU_KERNEL_PRIVATE */

#define KFREE_TYPE_ASSERT_COMPATIBLE_POINTER(ptr, type) do { } while (0)

#endif /* XNU_KERNEL_PRIVATE */

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

#define kalloc_type_2(type, flags) ({                                          \
	static KALLOC_TYPE_DEFINE(kt_view_var, type, KT_SHARED_ACCT);          \
	__unsafe_forge_single(type *, kalloc_type_impl(kt_view_var, flags));   \
})

#define kfree_type_2(type, elem) ({                                            \
	KFREE_TYPE_ASSERT_COMPATIBLE_POINTER(elem, type);                      \
	static KALLOC_TYPE_DEFINE(kt_view_var, type, KT_SHARED_ACCT);          \
	kfree_type_impl(kt_view_var, os_ptr_load_and_erase(elem));             \
})

#define kfree_type_3(type, count, elem) ({                                 \
	KFREE_TYPE_ASSERT_COMPATIBLE_POINTER(elem, type);                      \
	static KALLOC_TYPE_VAR_DEFINE_3(kt_view_var, type, KT_SHARED_ACCT);    \
	__auto_type __kfree_count = (count);                                   \
	kfree_type_var_impl(kt_view_var, os_ptr_load_and_erase(elem),          \
	    kt_size(0, sizeof(type), __kfree_count));                          \
})

#define kfree_type_4(hdr_ty, e_ty, count, elem) ({                         \
	KFREE_TYPE_ASSERT_COMPATIBLE_POINTER(elem, hdr_ty);                    \
	static KALLOC_TYPE_VAR_DEFINE_4(kt_view_var, hdr_ty, e_ty,             \
	    KT_SHARED_ACCT);                                                   \
	__auto_type __kfree_count = (count);                                   \
	kfree_type_var_impl(kt_view_var,                                       \
	    os_ptr_load_and_erase(elem),                                       \
	    kt_size(sizeof(hdr_ty), sizeof(e_ty), __kfree_count));             \
})

#ifdef XNU_KERNEL_PRIVATE
#define kalloc_type_3(type, count, flags) ({                               \
	static KALLOC_TYPE_VAR_DEFINE_3(kt_view_var, type, KT_SHARED_ACCT);    \
	VM_ALLOC_SITE_STATIC(0, 0);                                            \
	(type *)kalloc_type_var_impl(kt_view_var,                              \
	    kt_size(0, sizeof(type), count), flags, &site);                    \
})

#define kalloc_type_4(hdr_ty, e_ty, count, flags) ({                       \
	static KALLOC_TYPE_VAR_DEFINE_4(kt_view_var, hdr_ty, e_ty,             \
	    KT_SHARED_ACCT);                                                   \
	VM_ALLOC_SITE_STATIC(0, 0);                                            \
	(hdr_ty *)kalloc_type_var_impl(kt_view_var, kt_size(sizeof(hdr_ty),    \
	    sizeof(e_ty), count), flags, &site);                               \
})

#define kalloc_type_tag_3(type, flags, tag) ({                             \
	static KALLOC_TYPE_DEFINE(kt_view_var, type,                           \
	    (kalloc_type_flags_t)Z_VM_TAG(KT_SHARED_ACCT, tag));               \
	__unsafe_forge_single(type *, zalloc_flags(kt_view_var,                \
	    Z_VM_TAG(flags, tag)));                                            \
})

#define kalloc_type_site_3(type, flags, site) ({                           \
	static KALLOC_TYPE_DEFINE(kt_view_var, type, KT_SHARED_ACCT);          \
	__unsafe_forge_single(type *, zalloc_flags(kt_view_var,                \
	    __zone_flags_mix_tag(kt_view_var->kt_zv.zv_zone, flags, site)));   \
})

#define kalloc_type_tag_4(type, count, flags, tag) ({                      \
	static KALLOC_TYPE_VAR_DEFINE_3(kt_view_var, type, KT_SHARED_ACCT);    \
	(type *)kalloc_type_var_impl(kt_view_var, kt_size(0, sizeof(type),     \
	    count), Z_VM_TAG(flags, tag), NULL);                               \
})

#define kalloc_type_site_4(type, count, flags, site) ({                    \
	static KALLOC_TYPE_VAR_DEFINE_3(kt_view_var, type, KT_SHARED_ACCT);    \
	(type *)kalloc_type_var_impl(kt_view_var,                              \
	    kt_size(0, sizeof(type), count), flags, site);                     \
})

#define kalloc_type_tag_5(hdr_ty, e_ty, count, flags, tag) ({              \
	static KALLOC_TYPE_VAR_DEFINE_4(kt_view_var, hdr_ty, e_ty,             \
	    KT_SHARED_ACCT);                                                   \
	(hdr_ty *)kalloc_type_var_impl(kt_view_var,                            \
	    kt_size(sizeof(hdr_ty), sizeof(e_ty), count),                      \
	    Z_VM_TAG(flags, tag), NULL);                                       \
})

#define kalloc_type_site_5(hdr_ty, e_ty, count, flags, site) ({            \
	static KALLOC_TYPE_VAR_DEFINE_4(kt_view_var, hdr_ty, e_ty,             \
	    KT_SHARED_ACCT);                                                   \
	(hdr_ty *)kalloc_type_var_impl(kt_view_var, kt_size(sizeof(hdr_ty),    \
	    sizeof(e_ty), count), flags, site);                                \
})

#define krealloc_type_site_6(type, old_count, new_count, elem, flags,      \
	    site) ({                                                           \
	static KALLOC_TYPE_VAR_DEFINE_3(kt_view_var, type, KT_SHARED_ACCT);    \
	((type *)__krealloc_type_site(kt_view_var, elem,                       \
	    kt_size(0, sizeof(type), old_count),                               \
	    kt_size(0, sizeof(type), new_count), flags, site));                \
})

#define krealloc_type_5(type, old_count, new_count, elem, flags) \
	({ VM_ALLOC_SITE_STATIC(0, 0); \
	krealloc_type_site_6(type, old_count, new_count, elem, flags, &site); })

#define krealloc_type_site_7(hdr_ty, e_ty, old_count, new_count, elem,     \
	    flags, site) ({                                                    \
	static KALLOC_TYPE_VAR_DEFINE_4(kt_view_var, hdr_ty, e_ty,             \
	    KT_SHARED_ACCT);                                                   \
	((type *)__krealloc_type_site(kt_view_var, elem,                       \
	    kt_size(sizeof(hdr_ty), sizeof(e_ty), old_count),                  \
	    kt_size(sizeof(hdr_ty), sizeof(e_ty), new_count), flags, site));   \
})

#define krealloc_type_6(hdr_ty, e_ty, old_count, new_count, elem, flags) \
	({ VM_ALLOC_SITE_STATIC(0, 0); \
	krealloc_type_site_7(hdr_ty, e_ty, old_count, new_count, elem, flags, &site); })

#else /* XNU_KERNEL_PRIVATE */
/* for now kexts do not have access to flags */
#define kalloc_type_3(type, count, flags) ({                               \
	_Static_assert((flags) == Z_WAITOK, "kexts can only pass Z_WAITOK");   \
	static KALLOC_TYPE_VAR_DEFINE_3(kt_view_var, type, KT_SHARED_ACCT);    \
	(type *)kalloc_type_var_impl(kt_view_var,                              \
	    kt_size(0, sizeof(type), count), flags, NULL);                     \
})

#define kalloc_type_4(hdr_ty, e_ty, count, flags) ({                       \
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

#define kheap_free(heap, elem, size) ({                        \
	kalloc_heap_t __kfree_heap = (heap);                       \
	__auto_type __kfree_size = (size);                         \
	(kheap_free)(__kfree_heap,                                 \
	(void *)os_ptr_load_and_erase(elem),                       \
	__kfree_size);                                             \
})

#define kheap_free_addr(heap, elem) ({                         \
	kalloc_heap_t __kfree_heap = (heap);                       \
	(kheap_free_addr)(__kfree_heap,                            \
	(void *)os_ptr_load_and_erase(elem));                      \
})

#define kheap_free_bounded(heap, elem, min_sz, max_sz) ({      \
	static_assert(max_sz <= KALLOC_SAFE_ALLOC_SIZE);           \
	kalloc_heap_t __kfree_heap = (heap);                       \
	__auto_type __kfree_min_sz = (min_sz);                     \
	__auto_type __kfree_max_sz = (max_sz);                     \
	(kheap_free_bounded)(__kfree_heap,                         \
	(void *)os_ptr_load_and_erase(elem),                       \
	__kfree_min_sz, __kfree_max_sz);                           \
})

#else /* XNU_KERNEL_PRIVATE */

#define kfree_data(elem, size) ({                              \
	__auto_type __kfree_size = (size);                         \
	(kfree_data)((void *)os_ptr_load_and_erase(elem),          \
	__kfree_size);                                             \
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

#if __LP64__
#define KALLOC_TYPE_SEGMENT "__DATA_CONST"
#else
#define KALLOC_TYPE_SEGMENT "__DATA"
#endif

/*
 * When kalloc_type_impl is called from xnu, it calls zalloc_flags
 * directly and doesn't redirect zone-less sites to kheap_alloc.
 * Passing a size larger than kalloc_max for these allocations will
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
	__PLACE_IN_SECTION(KALLOC_TYPE_SEGMENT ", __kalloc_type")       \
	struct kalloc_type_view var[1] = { {                            \
	    .kt_zv.zv_name = "site." #type,                             \
	    .kt_flags = KALLOC_TYPE_ADJUST_FLAGS(flags, type),          \
	    .kt_size = sizeof(type),                                    \
	    .kt_signature = KALLOC_TYPE_EMIT_SIG(type),                 \
	} };                                                            \
	KALLOC_TYPE_SIZE_CHECK(sizeof(type));

#define KALLOC_TYPE_VAR_DEFINE_3(var, type, flags)                  \
	__kalloc_no_kasan                                               \
	__PLACE_IN_SECTION(KALLOC_TYPE_SEGMENT ", __kalloc_var")        \
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
	__PLACE_IN_SECTION(KALLOC_TYPE_SEGMENT ", __kalloc_var")        \
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
	KALLOC_TYPE_SIZE_CHECK(sizeof(type));

#ifndef XNU_KERNEL_PRIVATE
/*
 * This macro is currently used by AppleImage4
 */
#define KALLOC_TYPE_DEFINE_SITE(var, type, flags)       \
	static _KALLOC_TYPE_DEFINE(var, type, flags)

#endif /* !XNU_KERNEL_PRIVATE */

#ifdef XNU_KERNEL_PRIVATE

#define KT_VM_TAG(var) \
	((var)->kt_flags & KT_VM_TAG_MASK)

#define kalloc_type_impl(kt_view, flags) \
	zalloc_flags(kt_view, (zalloc_flags_t)(KT_VM_TAG(kt_view) | (flags)))

static inline void
kfree_type_impl(kalloc_type_view_t kt_view, void *__unsafe_indexable ptr)
{
	if (NULL == ptr) {
		return;
	}
	zfree(kt_view, ptr);
}

/*
 * This type is used so that kalloc_internal has good calling conventions
 * for callers who want to cheaply both know the allocated address
 * and the actual size of the allocation.
 */
struct kalloc_result {
	void         *addr __sized_by(size);
	vm_size_t     size;
};

extern struct kalloc_result
kalloc_type_var_impl_internal(
	kalloc_type_var_view_t  kt_view,
	vm_size_t               size,
	zalloc_flags_t          flags,
	void                   *site);

#define kalloc_type_var_impl(kt_view, size, flags, site) \
	kalloc_type_var_impl_internal(kt_view, size, flags, site).addr

extern void
kfree_type_var_impl_internal(
	kalloc_type_var_view_t  kt_view,
	void                   *ptr __unsafe_indexable,
	vm_size_t               size);

#define kfree_type_var_impl(kt_view, ptr, size) \
	kfree_type_var_impl_internal(kt_view, ptr, size)

#else /* XNU_KERNEL_PRIVATE */

extern void *__unsafe_indexable
kalloc_type_impl(
	kalloc_type_view_t  kt_view,
	zalloc_flags_t      flags);

extern void
kfree_type_impl(
	kalloc_type_view_t  kt_view,
	void                *ptr __unsafe_indexable);

__attribute__((malloc, alloc_size(2)))
extern void *__sized_by(size)
kalloc_type_var_impl(
	kalloc_type_var_view_t  kt_view,
	vm_size_t               size,
	zalloc_flags_t          flags,
	void                   *site);

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

static inline uint16_t
kalloc_type_get_idx(uint32_t kt_size)
{
	return (uint16_t) (kt_size >> KALLOC_TYPE_IDX_SHIFT);
}

static inline uint32_t
kalloc_type_set_idx(uint32_t kt_size, uint16_t idx)
{
	return kt_size | ((uint32_t) idx << KALLOC_TYPE_IDX_SHIFT);
}

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

extern struct kalloc_result
kalloc_ext(
	kalloc_heap_t           kheap,
	vm_size_t               size,
	zalloc_flags_t          flags,
	vm_allocation_site_t   *site);

__attribute__((malloc, alloc_size(2)))
static inline void *
__sized_by(size)
__kheap_alloc_site(
	kalloc_heap_t           kheap,
	vm_size_t               size,
	zalloc_flags_t          flags,
	vm_allocation_site_t   *site)
{
	struct kalloc_result kr;
	kr = kalloc_ext(kheap, size, flags, site);
	return __unsafe_forge_bidi_indexable(void *, kr.addr, size);
}

extern struct kalloc_result
krealloc_ext(
	kalloc_heap_t           kheap,
	void                   *addr __unsafe_indexable,
	vm_size_t               old_size,
	vm_size_t               new_size,
	zalloc_flags_t          flags,
	vm_allocation_site_t   *site);

__attribute__((malloc, alloc_size(4)))
static inline void *
__sized_by(new_size)
__krealloc_site(
	kalloc_heap_t           kheap,
	void                   *addr __unsafe_indexable,
	vm_size_t               old_size,
	vm_size_t               new_size,
	zalloc_flags_t          flags,
	vm_allocation_site_t   *site)
{
	struct kalloc_result kr;
	kr = krealloc_ext(kheap, addr, old_size, new_size, flags, site);
	return __unsafe_forge_bidi_indexable(void *, kr.addr, new_size);
}

struct kalloc_result
krealloc_type_var_impl(
	kalloc_type_var_view_t  kt_view,
	void                   *addr __unsafe_indexable,
	vm_size_t               old_size,
	vm_size_t               new_size,
	zalloc_flags_t          flags,
	vm_allocation_site_t   *site);

__attribute__((malloc, alloc_size(4)))
static inline void *
__sized_by(new_size)
__krealloc_type_site(
	kalloc_type_var_view_t  kt_view,
	void                   *addr __unsafe_indexable,
	vm_size_t               old_size,
	vm_size_t               new_size,
	zalloc_flags_t          flags,
	vm_allocation_site_t   *site)
{
	struct kalloc_result kr;
	kr = krealloc_type_var_impl(kt_view, addr, old_size, new_size, flags, site);
	return __unsafe_forge_bidi_indexable(void *, kr.addr, new_size);
}

extern bool
kalloc_owned_map(
	vm_map_t      map);

extern vm_map_t
kalloc_large_map_get(void);

extern vm_map_t
kalloc_large_data_map_get(void);

extern vm_map_t
kernel_data_map_get(void);

extern zone_t
kalloc_heap_zone_for_size(
	kalloc_heap_t         heap,
	vm_size_t             size);

extern vm_size_t kalloc_max_prerounded;
extern vm_size_t kalloc_large_total;

extern void
kern_os_kfree(
	void         *addr __unsafe_indexable,
	vm_size_t     size);

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
