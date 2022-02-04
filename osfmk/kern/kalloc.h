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

__BEGIN_DECLS

#if XNU_KERNEL_PRIVATE

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
	const char         *kh_name;
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
 #if XNU_KERNEL_PRIVATE
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
#if XNU_KERNEL_PRIVATE
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
	const char             *kt_signature;
	kalloc_type_flags_t     kt_flags;
	uint32_t                kt_size;
	void                   *kt_site;
	void                   *unused;
};

typedef struct kalloc_type_view *kalloc_type_view_t;

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


#ifdef XNU_KERNEL_PRIVATE

#define kalloc(size) \
	kheap_alloc(KHEAP_DEFAULT, size, Z_WAITOK)

#define kalloc_flags(size, flags) \
	kheap_alloc(KHEAP_DEFAULT, size, flags)

#define kalloc_tag(size, itag) \
	kheap_alloc_tag(KHEAP_DEFAULT, size, Z_WAITOK, itag)

#define kalloc_tag_bt(size, itag) \
	kheap_alloc_tag_bt(KHEAP_DEFAULT, size, Z_WAITOK, itag)

#define krealloc(elem, old_size, new_size, flags) \
	kheap_realloc(KHEAP_DEFAULT, elem, old_size, new_size, flags)

#define krealloc_tag_bt(elem, old_size, new_size, flags, itag) \
	kheap_realloc_tag_bt(KHEAP_DEFAULT, elem, old_size, new_size, flags, itag)

/*
 * These versions allow specifying the kalloc heap to allocate memory
 * from
 */
#define kheap_alloc(kalloc_heap, size, flags)                           \
	({ VM_ALLOC_SITE_STATIC(0, 0);                                  \
	kalloc_ext(kalloc_heap, size, flags, &site).addr; })

#define kheap_alloc_tag(kalloc_heap, size, flags, itag)                 \
	({ VM_ALLOC_SITE_STATIC(0, (itag));                             \
	kalloc_ext(kalloc_heap, size, flags, &site).addr; })

#define kheap_alloc_tag_bt(kalloc_heap, size, flags, itag)              \
	({ VM_ALLOC_SITE_STATIC(VM_TAG_BT, (itag));                     \
	kalloc_ext(kalloc_heap, size, flags, &site).addr; })

#define kheap_realloc(kalloc_heap, elem, old_size, new_size, flags)     \
	({ VM_ALLOC_SITE_STATIC(0, 0);                                  \
	krealloc_ext(kalloc_heap, elem, old_size, new_size, flags, &site).addr; })

#define kheap_realloc_tag_bt(kalloc_heap, elem, old_size, new_size, flags, itag) \
	({ VM_ALLOC_SITE_STATIC(VM_TAG_BT, (itag));                              \
	krealloc_ext(kalloc_heap, elem, old_size, new_size, flags, &site).addr; })

/*
 * These versions should be used for allocating pure data bytes that
 * do not contain any pointers
 */
#define kalloc_data(size, flags) \
	kheap_alloc(KHEAP_DATA_BUFFERS, size, flags)

#define kalloc_data_tag(size, flags, itag) \
	kheap_alloc_tag(KHEAP_DATA_BUFFERS, size, flags, itag)

#define kalloc_data_tag_bt(size, flags, itag) \
	kheap_alloc_tag_bt(KHEAP_DATA_BUFFERS, size, flags, itag)

#define krealloc_data(elem, old_size, new_size, flags) \
	kheap_realloc(KHEAP_DATA_BUFFERS, elem, old_size, new_size, flags)

#define krealloc_data_tag_bt(elem, old_size, new_size, flags, itag) \
	kheap_realloc_tag_bt(KHEAP_DATA_BUFFERS, elem, old_size, new_size, flags, itag)

#define krealloc_data_addr(elem, new_size, flags)                       \
	({ VM_ALLOC_SITE_STATIC(0, 0);                                  \
	kheap_realloc_addr(KHEAP_DATA_BUFFERS, elem, new_size, flags,   \
	&site).addr; })

#define kfree_data(elem, size) \
	kheap_free(KHEAP_DATA_BUFFERS, elem, size);

#define kfree_data_addr(elem) \
	kheap_free_addr(KHEAP_DATA_BUFFERS, elem);

extern void
kfree(
	void         *data,
	vm_size_t     size);

extern void
kheap_free(
	kalloc_heap_t heap,
	void         *data,
	vm_size_t     size);

extern void
kheap_free_addr(
	kalloc_heap_t heap,
	void         *addr);

extern void
kheap_free_bounded(
	kalloc_heap_t heap,
	void         *addr,
	vm_size_t     min_sz,
	vm_size_t     max_sz);

extern void
kalloc_data_require(
	void         *data,
	vm_size_t     size);

extern void
kalloc_non_data_require(
	void         *data,
	vm_size_t     size);

#else /* XNU_KERNEL_PRIVATE */

extern void *
kalloc(
	vm_size_t           size) __attribute__((alloc_size(1)));

extern void *
kalloc_data(
	vm_size_t           size,
	zalloc_flags_t      flags) __attribute__((alloc_size(1)));

extern void *
krealloc_data(
	void               *ptr,
	vm_size_t           old_size,
	vm_size_t           new_size,
	zalloc_flags_t      flags) __attribute__((alloc_size(3)));

extern void *
krealloc_data_addr(
	void               *ptr,
	vm_size_t           new_size,
	zalloc_flags_t      flags) __attribute__((alloc_size(2)));

extern void
kfree(
	void               *data,
	vm_size_t           size);

extern void
kfree_data(
	void               *ptr,
	vm_size_t           size);

extern void
kfree_data_addr(
	void               *ptr);

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
#define kalloc_type_tag_bt(...)  KALLOC_DISPATCH(kalloc_type_tag_bt, ##__VA_ARGS__)
#define kallocp_type_tag_bt(ty, countp, flags, tag) ({                         \
	VM_ALLOC_SITE_STATIC(VM_TAG_BT, (tag));                                \
	(ty *)kallocp_ext(KHEAP_DEFAULT, sizeof(ty), countp, flags, &site);    \
})

/*
 * kalloc_type_require can't be made available to kexts as the
 * kalloc_type_view's zone could be NULL in the following cases:
 * - Size greater than KALLOC_SAFE_ALLOC_SIZE
 * - On macOS, if call is not in BootKC
 * - All allocations in kext for armv7
 */
#define kalloc_type_require(type, value) ({                    \
	static KALLOC_TYPE_DEFINE(kt_view_var, type,               \
	    KT_SHARED_ACCT);                                       \
	zone_require(kt_view_var->kt_zv, value);                   \
})

#endif

#pragma mark implementation details

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
	(type *)kalloc_type_impl(kt_view_var, flags);                          \
})

#define kfree_type_2(type, elem) ({                                            \
	static KALLOC_TYPE_DEFINE(kt_view_var, type, KT_SHARED_ACCT);          \
	kfree_type_impl(kt_view_var, __zalloc_ptr_load_and_erase(elem));       \
})

#define kfree_type_3(type, count, elem) \
	kfree(elem, kt_size(0, sizeof(type), count))

#define kfree_type_4(hdr_ty, e_ty, count, elem) \
	kfree(elem, kt_size(sizeof(hdr_ty), sizeof(e_ty), count))

#ifdef XNU_KERNEL_PRIVATE
#define kalloc_type_3(type, count, flags) \
	((type *)kalloc_flags(kt_size(0, sizeof(type), count), flags))

#define kalloc_type_4(hdr_ty, e_ty, count, flags) \
	((hdr_ty *)kalloc_flags(kt_size(sizeof(hdr_ty), sizeof(e_ty), count), flags))

#define kalloc_type_tag_3(type, flags, tag) ({                                 \
	static KALLOC_TYPE_DEFINE(kt_view_var, type,                           \
	    (kalloc_type_flags_t) (KT_SHARED_ACCT | Z_VM_TAG(tag)));           \
	(type *) kalloc_type_impl(kt_view_var, flags);                         \
})

#define kalloc_type_tag_4(type, count, flags, tag) \
	((type *)kheap_alloc_tag(KHEAP_DEFAULT, kt_size(0, sizeof(type), count), flags, tag))

#define kalloc_type_tag_bt_4(type, count, flags, tag) \
	((type *)kheap_alloc_tag_bt(KHEAP_DEFAULT, kt_size(0, sizeof(type), count), flags, tag))

#define kalloc_type_tag_5(hdr_ty, e_ty, count, flags, tag) \
	((hdr_ty *)kheap_alloc_tag(KHEAP_DEFAULT,kt_size(sizeof(hdr_ty), sizeof(e_ty), count), flags, tag))

#define kalloc_type_tag_bt_5(hdr_ty, e_ty, count, flags, tag) \
	((hdr_ty *)kheap_alloc_tag_bt(KHEAP_DEFAULT,kt_size(sizeof(hdr_ty), sizeof(e_ty), count), flags, tag))

#else /* XNU_KERNEL_PRIVATE */
/* for now kexts do not have access to flags */
#define kalloc_type_3(type, count, flags) ({                                   \
	_Static_assert((flags) == Z_WAITOK, "kexts can only pass Z_WAITOK");   \
	((type *)kalloc(kt_size(0, sizeof(type), count));                      \
})

#define kalloc_type_4(hdr_ty, e_ty, count, flags) ({                           \
	_Static_assert((flags) == Z_WAITOK, "kexts can only pass Z_WAITOK");   \
	((hdr_ty *)kalloc(kt_size(sizeof(hdr_ty), sizeof(e_ty), count)));      \
})
#endif /* !XNU_KERNEL_PRIVATE */

/*
 * All k*free macros set "elem" to NULL on free.
 *
 * Note: all values passed to k*free() might be in the element to be freed,
 *       temporaries must be taken, and the resetting to be done prior to free.
 */
#ifdef XNU_KERNEL_PRIVATE

#define kfree(elem, size) ({                                   \
	__auto_type __kfree_size = (size);                         \
	(kfree)((void *)__zalloc_ptr_load_and_erase(elem),         \
	__kfree_size);                                             \
})

#define kheap_free(heap, elem, size) ({                        \
	__auto_type __kfree_heap = (heap);                         \
	__auto_type __kfree_size = (size);                         \
	(kheap_free)(__kfree_heap,                                 \
	(void *)__zalloc_ptr_load_and_erase(elem),                 \
	__kfree_size);                                             \
})

#define kheap_free_addr(heap, elem) ({                         \
	__auto_type __kfree_heap = (heap);                         \
	(kheap_free_addr)(__kfree_heap,                            \
	(void *)__zalloc_ptr_load_and_erase(elem));                \
})

#define kheap_free_bounded(heap, elem, min_sz, max_sz) ({      \
	static_assert(max_sz <= KALLOC_SAFE_ALLOC_SIZE);           \
	__auto_type __kfree_heap = (heap);                         \
	__auto_type __kfree_min_sz = (min_sz);                     \
	__auto_type __kfree_max_sz = (max_sz);                     \
	(kheap_free_bounded)(__kfree_heap,                         \
	(void *)__zalloc_ptr_load_and_erase(elem),                 \
	__kfree_min_sz, __kfree_max_sz);                           \
})

#else /* XNU_KERNEL_PRIVATE */

#define kfree_data(elem, size) ({                              \
	__auto_type __kfree_size = (size);                         \
	(kfree_data)((void *)__zalloc_ptr_load_and_erase(elem),    \
	__kfree_size);                                             \
})

#define kfree_data_addr(elem) \
	(kfree_data_addr)((void *)__zalloc_ptr_load_and_erase(elem))

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

#define _KALLOC_TYPE_DEFINE(var, type, flags)                       \
	__kalloc_no_kasan                                               \
	__PLACE_IN_SECTION(KALLOC_TYPE_SEGMENT ", __kalloc_type")       \
	struct kalloc_type_view var[1] = { {                            \
	    .kt_zv.zv_name = "site." #type,                             \
	    .kt_flags = flags,                                          \
	    .kt_size = sizeof(type),                                    \
	    .kt_signature = __builtin_xnu_type_signature(type),         \
	} };                                                            \
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

#define kalloc_type_impl(kt_view, flags) ({                    \
	zalloc_flags(kt_view,                                      \
	    (zalloc_flags_t) (KT_VM_TAG(kt_view) | flags));        \
})

static inline void
kfree_type_impl(kalloc_type_view_t kt_view, void *ptr)
{
	if (NULL == ptr) {
		return;
	}
	zfree(kt_view, ptr);
}

#else /* XNU_KERNEL_PRIVATE */

extern void *
kalloc_type_impl(
	kalloc_type_view_t  kt_view,
	zalloc_flags_t      flags);

extern void
kfree_type_impl(
	kalloc_type_view_t  kt_view,
	void                *ptr);

#endif /* !XNU_KERNEL_PRIVATE */

void *
kalloc_type_impl_external(
	kalloc_type_view_t  kt_view,
	zalloc_flags_t      flags);

void
kfree_type_impl_external(
	kalloc_type_view_t  kt_view,
	void               *ptr);

extern void *
OSObject_typed_operator_new(
	kalloc_type_view_t  ktv,
	vm_size_t           size);

extern void
OSObject_typed_operator_delete(
	kalloc_type_view_t  ktv,
	void               *mem,
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
	uint32_t      kt_idx,
	uint32_t      kt_size);

/* Used by kern_os_* and operator new */
KALLOC_HEAP_DECLARE(KERN_OS_MALLOC);

extern void
kheap_startup_init(
	kalloc_heap_t heap);

/*
 * This type is used so that kalloc_internal has good calling conventions
 * for callers who want to cheaply both know the allocated address
 * and the actual size of the allocation.
 */
struct kalloc_result {
	void         *addr;
	vm_size_t     size;
};

extern struct kalloc_result
kalloc_ext(
	kalloc_heap_t           kheap,
	vm_size_t               size,
	zalloc_flags_t          flags,
	vm_allocation_site_t   *site);

extern struct kalloc_result
krealloc_ext(
	kalloc_heap_t           kheap,
	void                   *addr,
	vm_size_t               old_size,
	vm_size_t               new_size,
	zalloc_flags_t          flags,
	vm_allocation_site_t   *site);

extern struct kalloc_result
kheap_realloc_addr(
	kalloc_heap_t           kheap,
	void                   *addr,
	vm_size_t               new_size,
	zalloc_flags_t          flags,
	vm_allocation_site_t   *site);


/* these versions update the size reference with the actual size allocated */

static inline void *
kallocp_ext(
	kalloc_heap_t           kheap,
	vm_size_t               ty_size,
	vm_size_t              *count,
	zalloc_flags_t          flags,
	vm_allocation_site_t   *site)
{
	vm_size_t size = kt_size(0, ty_size, *count);
	struct kalloc_result kar = kalloc_ext(kheap, size, flags, site);
	*count = kar.size / ty_size;
	return kar.addr;
}


#define kallocp_tag_bt(sizep, itag)                     \
	({ VM_ALLOC_SITE_STATIC(VM_TAG_BT, (itag));     \
	kallocp_ext(KHEAP_DEFAULT, sizep, Z_WAITOK, &site); })

extern vm_size_t
kheap_alloc_size(
	kalloc_heap_t         heap,
	void                 *addr);

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
	void         *addr,
	vm_size_t     size);

extern void
kern_os_typed_free(
	kalloc_type_view_t    ktv,
	void                 *addr,
	vm_size_t             esize);

#pragma GCC visibility pop
#endif  /* !XNU_KERNEL_PRIVATE */

extern void
kern_os_zfree(
	zone_t        zone,
	void         *addr,
	vm_size_t     size);

__END_DECLS

#endif  /* _KERN_KALLOC_H_ */

#endif  /* KERNEL_PRIVATE */
