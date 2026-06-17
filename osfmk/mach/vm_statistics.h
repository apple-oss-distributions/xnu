/*
 * Copyright (c) 2000-2020 Apple Inc. All rights reserved.
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
/*
 */
/*
 *	File:	mach/vm_statistics.h
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young, David Golub
 *
 *	Virtual memory statistics structure.
 *
 */

#ifndef _MACH_VM_STATISTICS_H_
#define _MACH_VM_STATISTICS_H_


#include <Availability.h>
#include <os/base.h>
#include <stdbool.h>
#include <sys/cdefs.h>

#include <mach/machine/vm_types.h>
#include <mach/machine/kern_return.h>

__BEGIN_DECLS

#pragma mark VM Statistics

/*
 * vm_statistics
 *
 * History:
 *	rev0 -  original structure.
 *	rev1 -  added purgable info (purgable_count and purges).
 *	rev2 -  added speculative_count.
 *
 * Note: you cannot add any new fields to this structure. Add them below in
 *       vm_statistics64.
 */

struct vm_statistics {
	natural_t       free_count;             /* # of pages free */
	natural_t       active_count;           /* # of pages active */
	natural_t       inactive_count;         /* # of pages inactive */
	natural_t       wire_count;             /* # of pages wired down */
	natural_t       zero_fill_count;        /* # of zero fill pages */
	natural_t       reactivations;          /* # of pages reactivated */
	natural_t       pageins;                /* # of pageins */
	natural_t       pageouts;               /* # of pageouts */
	natural_t       faults;                 /* # of faults */
	natural_t       cow_faults;             /* # of copy-on-writes */
	natural_t       lookups;                /* object cache lookups */
	natural_t       hits;                   /* object cache hits */

	/* added for rev1 */
	natural_t       purgeable_count;        /* # of pages purgeable */
	natural_t       purges;                 /* # of pages purged */

	/* added for rev2 */
	/*
	 * NB: speculative pages are already accounted for in "free_count",
	 * so "speculative_count" is the number of "free" pages that are
	 * used to hold data that was read speculatively from disk but
	 * haven't actually been used by anyone so far.
	 */
	natural_t       speculative_count;      /* # of pages speculative */
};

/* Used by all architectures */
typedef struct vm_statistics    *vm_statistics_t;
typedef struct vm_statistics    vm_statistics_data_t;

/*
 * vm_statistics64
 *
 * History:
 *	rev0 -  original structure.
 *	rev1 -  added purgable info (purgable_count and purges).
 *	rev2 -  added speculative_count.
 *	   ----
 *	rev3 -  changed name to vm_statistics64.
 *		changed some fields in structure to 64-bit on
 *		arm, i386 and x86_64 architectures.
 *	rev4 -  require 64-bit alignment for efficient access
 *		in the kernel. No change to reported data.
 *
 */

struct vm_statistics64 {
	natural_t       free_count;             /* # of pages free */
	natural_t       active_count;           /* # of pages active */
	natural_t       inactive_count;         /* # of pages inactive */
	natural_t       wire_count;             /* # of pages wired down */
	uint64_t        zero_fill_count;        /* # of zero fill pages */
	uint64_t        reactivations;          /* # of pages reactivated */
	uint64_t        pageins;                /* # of pageins (lifetime) */
	uint64_t        pageouts;               /* # of pageouts */
	uint64_t        faults;                 /* # of faults */
	uint64_t        cow_faults;             /* # of copy-on-writes */
	uint64_t        lookups;                /* object cache lookups */
	uint64_t        hits;                   /* object cache hits */
	uint64_t        purges;                 /* # of pages purged */
	natural_t       purgeable_count;        /* # of pages purgeable */
	/*
	 * NB: speculative pages are already accounted for in "free_count",
	 * so "speculative_count" is the number of "free" pages that are
	 * used to hold data that was read speculatively from disk but
	 * haven't actually been used by anyone so far.
	 */
	natural_t       speculative_count;      /* # of pages speculative */

	/* added for rev1 */
	uint64_t        decompressions;         /* # of pages decompressed (lifetime) */
	uint64_t        compressions;           /* # of pages compressed (lifetime) */
	uint64_t        swapins;                /* # of pages swapped in via compressor segments (lifetime) */
	uint64_t        swapouts;               /* # of pages swapped out via compressor segments (lifetime) */
	natural_t       compressor_page_count;  /* # of pages used by the compressed pager to hold all the compressed data */
	natural_t       throttled_count;        /* # of pages throttled */
	natural_t       external_page_count;    /* # of pages that are file-backed (non-swap) */
	natural_t       internal_page_count;    /* # of pages that are anonymous */
	uint64_t        total_uncompressed_pages_in_compressor; /* # of pages (uncompressed) held within the compressor. */
	/* added for rev2 */
	uint64_t        swapped_count;          /* # of compressor-stored pages currently stored in swap */
	/* Added in rev3 */
	/* The total number of physical pages in the tag storage region */
	uint64_t total_tag_storage_pages;
	/*
	 * The number of tag storage pages which hold non-tag data and are pageable
	 */
	uint64_t nontag_pageable_tag_storage_pages;
	/* The number of tag storage pages which hold non-tag data and are wired */
	uint64_t nontag_wired_tag_storage_pages;
	/*
	 * The number of tag storage pages which are being used for neither tags nor
	 * regular memory
	 */
	uint64_t free_tag_storage_pages;
	/* The number of tag storage pages which currently hold tags */
	uint64_t tag_storing_tag_storage_pages;

	/* The total number of virtual pages which are tagged */
	uint64_t total_tagged_pages;
	/* The number of resident, physical pages which are tagged */
	uint64_t resident_tagged_pages;
	/*
	 * The outstanding number of virtual tagged pages whose contents reside in the
	 * compressor
	 */
	uint64_t compressed_tagged_pages;

	/* The number of tagged pages which have been compressed since boot */
	uint64_t tagged_compressions;
	/* The number of tagged pages which have been decompressed since boot */
	uint64_t tagged_decompressions;
	/* The current number of bytes consumed by compressed tag storage data */
	uint64_t compressed_tag_storage_bytes;
} __attribute__((aligned(8)));

typedef struct vm_statistics64  *vm_statistics64_t;
typedef struct vm_statistics64  vm_statistics64_data_t;
#if KERNEL
/*
 * @func vm_stats
 *
 * @brief
 * Get virtual memory statistics for the host machine. Equivalent to system call
 * @c host_statistics64() with flavor @c HOST_VM_INFO64.
 *
 * @param info
 * Out-param of type vm_statistics64_data_t
 *
 * @param count
 * The size of the @c info buffer in words
 *
 * @returns
 * KERN_SUCCESS if successful
 */
kern_return_t vm_stats(void *info, unsigned int *count);
#endif

/*
 * VM_STATISTICS_TRUNCATE_TO_32_BIT
 *
 * This is used by host_statistics() to truncate and peg the 64-bit in-kernel values from
 * vm_statistics64 to the 32-bit values of the older structure above (vm_statistics).
 */
#define VM_STATISTICS_TRUNCATE_TO_32_BIT(value) ((uint32_t)(((value) > UINT32_MAX ) ? UINT32_MAX : (value)))

/*
 * vm_extmod_statistics
 *
 * Structure to record modifications to a task by an
 * external agent.
 *
 * History:
 *	rev0 -  original structure.
 */

struct vm_extmod_statistics {
	int64_t task_for_pid_count;                     /* # of times task port was looked up */
	int64_t task_for_pid_caller_count;      /* # of times this task called task_for_pid */
	int64_t thread_creation_count;          /* # of threads created in task */
	int64_t thread_creation_caller_count;   /* # of threads created by task */
	int64_t thread_set_state_count;         /* # of register state sets in task */
	int64_t thread_set_state_caller_count;  /* # of register state sets by task */
} __attribute__((aligned(8)));

typedef struct vm_extmod_statistics *vm_extmod_statistics_t;
typedef struct vm_extmod_statistics vm_extmod_statistics_data_t;

typedef struct vm_purgeable_stat {
	uint64_t        count;
	uint64_t        size;
}vm_purgeable_stat_t;

struct vm_purgeable_info {
	vm_purgeable_stat_t fifo_data[8];
	vm_purgeable_stat_t obsolete_data;
	vm_purgeable_stat_t lifo_data[8];
};

typedef struct vm_purgeable_info        *vm_purgeable_info_t;

/* included for the vm_map_page_query call */

typedef int32_t vm_page_disposition_t;

#define VM_PAGE_QUERY_PAGE_PRESENT      0x001
#define VM_PAGE_QUERY_PAGE_FICTITIOUS   0x002
#define VM_PAGE_QUERY_PAGE_REF          0x004
#define VM_PAGE_QUERY_PAGE_DIRTY        0x008
#define VM_PAGE_QUERY_PAGE_PAGED_OUT    0x010
#define VM_PAGE_QUERY_PAGE_COPIED       0x020
#define VM_PAGE_QUERY_PAGE_SPECULATIVE  0x040
#define VM_PAGE_QUERY_PAGE_EXTERNAL     0x080
#define VM_PAGE_QUERY_PAGE_CS_VALIDATED 0x100
#define VM_PAGE_QUERY_PAGE_CS_TAINTED   0x200
#define VM_PAGE_QUERY_PAGE_CS_NX        0x400
#define VM_PAGE_QUERY_PAGE_REUSABLE     0x800

#pragma mark User Flags

/*
 * Options for vm_reallocate:
 *
 * VM_REALLOCATE_DEALLOCATE_SOURCE
 *  When the source is relocated, the VA it previously occupied will be unmapped.
 *
 * VM_REALLOCATE_ZERO_FILL_SOURCE
 *  When the source is relocated, the VA it previously occupied will be mapped
 *  by new entries with equivalent protections and inheritance, equivalent to a
 *  fresh zero-filled allocation from vm_allocate().
 */
#define VM_REALLOCATE_DEALLOCATE_SOURCE 0x0
#define VM_REALLOCATE_ZERO_FILL_SOURCE  0x1

/*
 * VM allocation flags:
 *
 * VM_FLAGS_FIXED
 *      (really the absence of VM_FLAGS_ANYWHERE)
 *	Allocate new VM region at the specified virtual address, if possible.
 *
 * VM_FLAGS_ANYWHERE
 *	Allocate new VM region anywhere it would fit in the address space.
 *
 * VM_FLAGS_PURGABLE
 *	Create a purgable VM object for that new VM region.
 *
 * VM_FLAGS_4GB_CHUNK
 *	The new VM region will be chunked up into 4GB sized pieces.
 *
 * VM_FLAGS_NO_PMAP_CHECK
 *	(for DEBUG kernel config only, ignored for other configs)
 *	Do not check that there is no stale pmap mapping for the new VM region.
 *	This is useful for kernel memory allocations at bootstrap when building
 *	the initial kernel address space while some memory is already in use.
 *
 * VM_FLAGS_OVERWRITE
 *	The new VM region can replace existing VM regions if necessary
 *	(to be used in combination with VM_FLAGS_FIXED).
 *
 * VM_FLAGS_NO_CACHE
 *	Pages brought in to this VM region are placed on the speculative
 *	queue instead of the active queue.  In other words, they are not
 *	cached so that they will be stolen first if memory runs low.
 *
 * VM_FLAGS_GUARD_OBJECT_OPTOUT
 *	Opt out this allocation from the guard object allocation policy.
 *	And memory will be allocated in typical first-fit allocation order.
 */

#define VM_FLAGS_FIXED                  0x00000000
#define VM_FLAGS_ANYWHERE               0x00000001
#define VM_FLAGS_PURGABLE               0x00000002
#define VM_FLAGS_4GB_CHUNK              0x00000004
#define VM_FLAGS_RANDOM_ADDR            0x00000008
#define VM_FLAGS_NO_CACHE               0x00000010
#define VM_FLAGS_RESILIENT_CODESIGN     0x00000020
#define VM_FLAGS_RESILIENT_MEDIA        0x00000040
#define VM_FLAGS_PERMANENT              0x00000080
#define VM_FLAGS_TPRO                   0x00001000
#define VM_FLAGS_MTE                    0x00002000
#define VM_FLAGS_OVERWRITE              0x00004000 /* delete any existing mappings first */
/*
 * VM_FLAGS_SUPERPAGE_MASK
 *	3 bits that specify whether large pages should be used instead of
 *	base pages (!=0), as well as the requested page size.
 */
#define VM_FLAGS_SUPERPAGE_MASK         0x00070000 /* bits 0x10000, 0x20000, 0x40000 */
#define VM_FLAGS_RETURN_DATA_ADDR       0x00100000 /* Return address of target data, rather than base of page */
#define VM_FLAGS_GUARD_OBJECT_OPTOUT    0x00400000
#define VM_FLAGS_RETURN_4K_DATA_ADDR    0x00800000 /* Return 4K aligned address of target data */
#define VM_FLAGS_ALIAS_MASK             0xFF000000
#define VM_GET_FLAGS_ALIAS(flags, alias)                        \
	        (alias) = (((flags) >> 24) & 0xff)
#if !XNU_KERNEL_PRIVATE
#define VM_SET_FLAGS_ALIAS(flags, alias)                        \
	        (flags) = (((flags) & ~VM_FLAGS_ALIAS_MASK) |   \
	        (((alias) & ~VM_FLAGS_ALIAS_MASK) << 24))
#endif /* !XNU_KERNEL_PRIVATE */

#if XNU_KERNEL_PRIVATE
/*
 * When making a new VM_FLAG_*:
 * - add it to this mask
 * - add a vmf_* field to vm_map_kernel_flags_t in the right spot
 * - add a check in vm_map_kernel_flags_check_vmflags()
 * - update tests vm_parameter_validation_[user|kern] and their expected
 *     results; they deliberately call VM functions with invalid flag values
 *     and you may be turning one of those invalid flags valid.
 */
#define VM_FLAGS_ANY_MASK       (VM_FLAGS_FIXED |               \
	                         VM_FLAGS_ANYWHERE |            \
	                         VM_FLAGS_PURGABLE |            \
	                         VM_FLAGS_4GB_CHUNK |           \
	                         VM_FLAGS_RANDOM_ADDR |         \
	                         VM_FLAGS_NO_CACHE |            \
	                         VM_FLAGS_RESILIENT_CODESIGN |  \
	                         VM_FLAGS_RESILIENT_MEDIA |     \
	                         VM_FLAGS_PERMANENT |           \
	                         VM_FLAGS_TPRO |                \
	                         VM_FLAGS_MTE |                 \
	                         VM_FLAGS_OVERWRITE |           \
	                         VM_FLAGS_SUPERPAGE_MASK |      \
	                         VM_FLAGS_RETURN_DATA_ADDR |    \
	                         VM_FLAGS_GUARD_OBJECT_OPTOUT | \
	                         VM_FLAGS_RETURN_4K_DATA_ADDR | \
	                         VM_FLAGS_ALIAS_MASK)

#endif /* XNU_KERNEL_PRIVATE */
#define VM_FLAGS_HW             (VM_FLAGS_TPRO |                \
	                         VM_FLAGS_MTE)

/* These are the flags that we accept from user-space */
#define VM_FLAGS_USER_ALLOCATE  (VM_FLAGS_FIXED |               \
	                         VM_FLAGS_ANYWHERE |            \
	                         VM_FLAGS_PURGABLE |            \
	                         VM_FLAGS_4GB_CHUNK |           \
	                         VM_FLAGS_RANDOM_ADDR |         \
	                         VM_FLAGS_NO_CACHE |            \
	                         VM_FLAGS_PERMANENT |           \
	                         VM_FLAGS_OVERWRITE |           \
	                         VM_FLAGS_GUARD_OBJECT_OPTOUT | \
	                         VM_FLAGS_SUPERPAGE_MASK |      \
	                         VM_FLAGS_HW |                  \
	                         VM_FLAGS_ALIAS_MASK)

#define VM_FLAGS_USER_MAP       (VM_FLAGS_USER_ALLOCATE |       \
	                         VM_FLAGS_RETURN_4K_DATA_ADDR | \
	                         VM_FLAGS_RETURN_DATA_ADDR)

#define VM_FLAGS_USER_REMAP     (VM_FLAGS_FIXED |               \
	                         VM_FLAGS_ANYWHERE |            \
	                         VM_FLAGS_RANDOM_ADDR |         \
	                         VM_FLAGS_OVERWRITE|            \
	                         VM_FLAGS_RETURN_DATA_ADDR |    \
	                         VM_FLAGS_RESILIENT_CODESIGN |  \
	                         VM_FLAGS_RESILIENT_MEDIA)

#define VM_FLAGS_SUPERPAGE_SHIFT 16
#define SUPERPAGE_NONE                  0       /* no superpages, if all bits are 0 */
#define SUPERPAGE_SIZE_ANY              1
#define VM_FLAGS_SUPERPAGE_NONE     (SUPERPAGE_NONE     << VM_FLAGS_SUPERPAGE_SHIFT)
#define VM_FLAGS_SUPERPAGE_SIZE_ANY (SUPERPAGE_SIZE_ANY << VM_FLAGS_SUPERPAGE_SHIFT)
#if defined(__x86_64__) || !defined(KERNEL) || defined(__BUILDING_XNU_LIB_UNITTEST__)
#define SUPERPAGE_SIZE_2MB              2
#define VM_FLAGS_SUPERPAGE_SIZE_2MB (SUPERPAGE_SIZE_2MB<<VM_FLAGS_SUPERPAGE_SHIFT)
#endif

/*
 * EXC_GUARD definitions for virtual memory.
 */
#define GUARD_TYPE_VIRT_MEMORY  0x5

/* Reasons for exception for virtual memory */
__enum_decl(virtual_memory_guard_exception_code_t, uint32_t, {
	kGUARD_EXC_DEALLOC_GAP  = 1,
	kGUARD_EXC_RECLAIM_COPYIO_FAILURE = 2,
	kGUARD_EXC_RECLAIM_INDEX_FAILURE = 4,
	kGUARD_EXC_RECLAIM_DEALLOCATE_FAILURE = 8,
	kGUARD_EXC_RECLAIM_ACCOUNTING_FAILURE = 9,
	kGUARD_EXC_SEC_IOPL_ON_EXEC_PAGE = 10,
	kGUARD_EXC_SEC_EXEC_ON_IOPL_PAGE = 11,
	kGUARD_EXC_SEC_UPL_WRITE_ON_EXEC_REGION = 12,
	kGUARD_EXC_LARGE_ALLOCATION_TELEMETRY = 13,
	/*
	 * rdar://151450801 (Remove spurious kGUARD_EXC_SEC_ACCESS_FAULT and kGUARD_EXC_SEC_ASYNC_ACCESS_FAULT once CrashReporter is aligned)
	 */
	kGUARD_EXC_SEC_ACCESS_FAULT = 98,
	kGUARD_EXC_SEC_ASYNC_ACCESS_FAULT = 99,
	/* VM policy decisions */
	kGUARD_EXC_SEC_COPY_DENIED = 100,
	kGUARD_EXC_SEC_SHARING_DENIED = 101,

	/* Fault-related exceptions. */
	kGUARD_EXC_MTE_SYNC_FAULT = 200,
	kGUARD_EXC_MTE_ASYNC_USER_FAULT = 201,
	kGUARD_EXC_MTE_ASYNC_KERN_FAULT = 202,
	kGUARD_EXC_GUARD_OBJECT_ASYNC_USER_FAULT = 203,
	kGUARD_EXC_GUARD_OBJECT_ASYNC_KERN_FAULT = 204,
});

#define kGUARD_EXC_MTE_SOFT_MODE       0x100000

#ifdef XNU_KERNEL_PRIVATE

#if HAS_MTE
static inline bool
vm_guard_is_mte_policy(uint32_t flavor)
{
	return flavor == kGUARD_EXC_SEC_COPY_DENIED || flavor == kGUARD_EXC_SEC_SHARING_DENIED;
}

static inline bool
vm_guard_is_mte_fault(uint32_t flavor)
{
	return flavor == kGUARD_EXC_MTE_SYNC_FAULT ||
	       flavor == kGUARD_EXC_MTE_ASYNC_USER_FAULT ||
	       flavor == kGUARD_EXC_MTE_ASYNC_KERN_FAULT;
}
#endif /* HAS_MTE */

#pragma mark Map Ranges

/*!
 * @enum vm_map_range_id_t
 *
 * @brief
 * Enumerate a particular vm_map range.
 *
 * @discussion
 * The kernel_map VA has been split into the following ranges. Userspace
 * VA for any given process can also optionally be split by the following user
 * ranges.
 *
 * @const KMEM_RANGE_ID_NONE
 * This range is only used for early initialization.
 *
 * @const KMEM_RANGE_ID_PTR_*
 * Range containing general purpose allocations from kalloc, etc that
 * contain pointers.
 *
 * @const KMEM_RANGE_ID_IO
 * Range for MMIO register mappings.
 *
 * @const KMEM_RANGE_ID_DATA_PRIVATE
 * Range containing allocations that are bags of bytes and contain no
 * pointers.
 *
 * @const KMEM_RANGE_ID_DATA_SHARED
 * Range containing allocations that are bags of bytes and contain no
 * pointers and meant to be shared with external domains.
 */
__enum_decl(vm_map_range_id_t, uint8_t, {
	KMEM_RANGE_ID_NONE,
	KMEM_RANGE_ID_PTR_0,
	KMEM_RANGE_ID_PTR_1,
	KMEM_RANGE_ID_PTR_2,
	KMEM_RANGE_ID_IO,
	KMEM_RANGE_ID_DATA_PRIVATE,
	KMEM_RANGE_ID_DATA_SHARED,

	KMEM_RANGE_ID_FIRST   = KMEM_RANGE_ID_PTR_0,
	KMEM_RANGE_ID_NUM_PTR = KMEM_RANGE_ID_PTR_2,
	KMEM_RANGE_ID_MAX     = KMEM_RANGE_ID_DATA_SHARED,

	/* these UMEM_* correspond to the MACH_VM_RANGE_* tags and are ABI */
	UMEM_RANGE_ID_DEFAULT = 0, /* same as MACH_VM_RANGE_DEFAULT */
	UMEM_RANGE_ID_HEAP,        /* same as MACH_VM_RANGE_DATA    */
	UMEM_RANGE_ID_FIXED,       /* same as MACH_VM_RANGE_FIXED   */
	UMEM_RANGE_ID_LARGE_FILE,

	/* these UMEM_* are XNU internal only range IDs, and aren't ABI */
	UMEM_RANGE_ID_MAX     = UMEM_RANGE_ID_LARGE_FILE,

#define KMEM_RANGE_COUNT        (KMEM_RANGE_ID_MAX + 1)
});

typedef vm_map_range_id_t       kmem_range_id_t;

#define kmem_log2down(mask)     (31 - __builtin_clz(mask))
#define KMEM_RANGE_MAX          (UMEM_RANGE_ID_MAX < KMEM_RANGE_ID_MAX \
	                        ? KMEM_RANGE_ID_MAX : UMEM_RANGE_ID_MAX)
#define KMEM_RANGE_BITS         kmem_log2down(2 * KMEM_RANGE_MAX - 1)

#pragma mark Kernel Flags

typedef union {
	struct {
		unsigned long long
		/*
		 * VM_FLAG_* flags
		 */
		    vmf_fixed:1,
		    vmf_purgeable:1,
		    vmf_4gb_chunk:1,
		    vmf_random_addr:1,
		    vmf_no_cache:1,
		    vmf_resilient_codesign:1,
		    vmf_resilient_media:1,
		    vmf_permanent:1,

		    __unused_bit_8:1,
		    __unused_bit_9:1,
		    __unused_bit_10:1,
		    __unused_bit_11:1,
		    vmf_tpro:1,
		    vmf_mte:1,
		    vmf_overwrite:1,
		    __unused_bit_15:1,

		    vmf_superpage_size:3,
		    __unused_bit_19:1,
		    vmf_return_data_addr:1,
		    __unused_bit_21:1,
		    vmf_guard_object_optout:1,
		    vmf_return_4k_data_addr:1,

		/*
		 * VM tag (user or kernel)
		 *
		 * User tags are limited to 8 bits,
		 * kernel tags can use up to 12 bits
		 * with -zt or similar features.
		 */
		    vm_tag : 12, /* same as VME_ALIAS_BITS */

		/*
		 * General kernel flags
		 */
		    vmkf_beyond_max:1,          /* map beyond the map's max offset */
		    vmkf_map_jit:1,             /* mark entry as JIT region */
		    vmkf_iokit_acct:1,          /* IOKit accounting */
		    vmkf_keep_map_ilocked:1,    /* keep map interlocked when returning
		                                 * from vm_map_enter() iff call successful,
		                                 * incompatible with vmf_superpage_size
		                                 */
		    vmkf_keep_entries_locked:1, /* keep entries exclusively locked under
		                                 * ctx when returning from vm_map_enter(),
		                                 * incompatible with vmf_superpage_size
		                                 */
		    vmkf_overwrite_immutable:1, /* can overwrite immutable mappings */
		    vmkf_remap_prot_copy:1,     /* vm_remap for VM_PROT_COPY */
		    vmkf_remap_legacy_mode:1,   /* vm_remap, not vm_remap_new */
		    vmkf_cs_enforcement_override:1,     /* override CS_ENFORCEMENT */
		    vmkf_cs_enforcement:1,      /* new value for CS_ENFORCEMENT */
		    vmkf_nested_pmap:1,         /* use a nested pmap */
		    vmkf_no_copy_on_read:1,     /* do not use copy_on_read */
		    vmkf_copy_single_object:1,  /* vm_map_copy only 1 VM object (more accurately, 1 entry) */
		    vmkf_copy_same_map:1,       /* vm_map_copy to remap in original map */
		    vmkf_translated_allow_execute:1,    /* allow execute in translated processes */
		    vmkf_tpro_enforcement_override:1,   /* override TPRO propagation */
		    vmkf_no_soft_limit:1,       /* override soft allocation size limit */

		/*
		 * Submap creation, altering vm_map_enter() only
		 */
		    vmkf_submap:1,              /* mapping a VM submap */
		    vmkf_submap_atomic:1,       /* keep entry atomic (no splitting/coalescing) */

		/*
		 * MTE Behavior bits.
		 */
		    vmkf_copy_dest:2,           /* See VM_COPY_DESTINATION_* */
		    vmkf_is_iokit:1,            /* creating a memory entry to back an IOMD */

		/*
		 * Flags altering the behavior of vm_map_locate_space_anywhere()
		 */
		    vmkf_32bit_map_va:1,        /* allocate in low 32-bits range */
		    vmkf_guard_before:1,        /* guard page before the mapping */
		    vmkf_last_free:1,           /* find space from the end */
		    vmkf_range_id:KMEM_RANGE_BITS;      /* kmem range to allocate in */
	};

	/*
	 * do not access these directly,
	 * use vm_map_kernel_flags_check_vmflags*()
	 */
	uint32_t __vm_flags : 24;
} vm_map_kernel_flags_t;

/*
 * using this means that vmf_* flags can't be used
 * until vm_map_kernel_flags_set_vmflags() is set,
 * or some manual careful init is done.
 *
 * Prefer VM_MAP_KERNEL_FLAGS_(FIXED,ANYWHERE) instead.
 */
#define VM_MAP_KERNEL_FLAGS_NONE \
	(vm_map_kernel_flags_t){ }

#define VM_MAP_KERNEL_FLAGS_FIXED(...) \
	(vm_map_kernel_flags_t){ .vmf_fixed = true, __VA_ARGS__ }

#define VM_MAP_KERNEL_FLAGS_ANYWHERE(...) \
	(vm_map_kernel_flags_t){ .vmf_fixed = false, __VA_ARGS__ }

#define VM_MAP_KERNEL_FLAGS_FIXED_PERMANENT(...) \
	VM_MAP_KERNEL_FLAGS_FIXED(.vmf_permanent = true, __VA_ARGS__)

#define VM_MAP_KERNEL_FLAGS_ANYWHERE_PERMANENT(...) \
	VM_MAP_KERNEL_FLAGS_ANYWHERE(.vmf_permanent = true, __VA_ARGS__)

#define VM_MAP_KERNEL_FLAGS_DATA_BUFFERS_ANYWHERE(...) \
	VM_MAP_KERNEL_FLAGS_ANYWHERE(.vmkf_range_id = KMEM_RANGE_ID_DATA_PRIVATE, __VA_ARGS__)

#define VM_MAP_KERNEL_FLAGS_DATA_SHARED_ANYWHERE(...) \
	VM_MAP_KERNEL_FLAGS_ANYWHERE(.vmkf_range_id = KMEM_RANGE_ID_DATA_SHARED, __VA_ARGS__)

typedef struct {
	unsigned int
	    vmnekf_ledger_tag:3,
	    vmnekf_ledger_no_footprint:1,
	    vmnekf_is_iokit:1,
	    __vmnekf_unused:27;
} vm_named_entry_kernel_flags_t;
#define VM_NAMED_ENTRY_KERNEL_FLAGS_NONE (vm_named_entry_kernel_flags_t) {    \
	.vmnekf_ledger_tag = 0,                                                \
	.vmnekf_ledger_no_footprint = 0,                                       \
	.vmnekf_is_iokit = 0,                                                  \
	.__vmnekf_unused = 0                                                   \
}

#endif /* XNU_KERNEL_PRIVATE */

#pragma mark Ledger Tags

/* current accounting postmark */
#define __VM_LEDGER_ACCOUNTING_POSTMARK 2019032600

/*
 *  When making a new VM_LEDGER_TAG_* or VM_LEDGER_FLAG_*, update tests
 *  vm_parameter_validation_[user|kern] and their expected results; they
 *  deliberately call VM functions with invalid ledger values and you may
 *  be turning one of those invalid tags/flags valid.
 */
/* discrete values: */
#define VM_LEDGER_TAG_NONE      0x00000000
#define VM_LEDGER_TAG_DEFAULT   0x00000001
#define VM_LEDGER_TAG_NETWORK   0x00000002
#define VM_LEDGER_TAG_MEDIA     0x00000003
#define VM_LEDGER_TAG_GRAPHICS  0x00000004
#define VM_LEDGER_TAG_NEURAL    0x00000005
#define VM_LEDGER_TAG_MAX       0x00000005
#define VM_LEDGER_TAG_UNCHANGED ((int)-1)

/* individual bits: */
#define VM_LEDGER_FLAG_NO_FOOTPRINT              (1 << 0)
#define VM_LEDGER_FLAG_NO_FOOTPRINT_FOR_DEBUG    (1 << 1)
#define VM_LEDGER_FLAG_FROM_KERNEL               (1 << 2)

#define VM_LEDGER_FLAGS_USER (VM_LEDGER_FLAG_NO_FOOTPRINT | VM_LEDGER_FLAG_NO_FOOTPRINT_FOR_DEBUG)
#define VM_LEDGER_FLAGS_ALL (VM_LEDGER_FLAGS_USER | VM_LEDGER_FLAG_FROM_KERNEL)

#pragma mark User Memory Tags

/*
 * These tags may be used to identify memory regions created with
 * `mach_vm_map()` or `mach_vm_allocate()` via the top 8 bits of the `flags`
 * parameter. Users should pass `VM_MAKE_TAG(tag) | flags` (see section
 * "User Flags").
 */
#define VM_MEMORY_MALLOC 1
#define VM_MEMORY_MALLOC_SMALL 2
#define VM_MEMORY_MALLOC_LARGE 3
#define VM_MEMORY_MALLOC_HUGE 4
#define VM_MEMORY_SBRK 5// uninteresting -- no one should call
#define VM_MEMORY_REALLOC 6
#define VM_MEMORY_MALLOC_TINY 7
#define VM_MEMORY_MALLOC_LARGE_REUSABLE 8
#define VM_MEMORY_MALLOC_LARGE_REUSED 9

#define VM_MEMORY_ANALYSIS_TOOL 10

#define VM_MEMORY_MALLOC_NANO 11
#define VM_MEMORY_MALLOC_MEDIUM 12
#define VM_MEMORY_MALLOC_PROB_GUARD 13

#define VM_MEMORY_MACH_MSG 20
#define VM_MEMORY_IOKIT 21
#define VM_MEMORY_VM_RECLAIM 22

#define VM_MEMORY_STACK  30
#define VM_MEMORY_GUARD  31
#define VM_MEMORY_SHARED_PMAP 32
/* memory containing a dylib */
#define VM_MEMORY_DYLIB 33
#define VM_MEMORY_OBJC_DISPATCHERS 34

/* Was a nested pmap (VM_MEMORY_SHARED_PMAP) which has now been unnested */
#define VM_MEMORY_UNSHARED_PMAP 35

/* for libchannel memory, mostly used on visionOS for communication with realtime threads */
#define VM_MEMORY_LIBCHANNEL 36

// Placeholders for now -- as we analyze the libraries and find how they
// use memory, we can make these labels more specific.
#define VM_MEMORY_APPKIT 40
#define VM_MEMORY_FOUNDATION 41
#define VM_MEMORY_COREGRAPHICS 42
#define VM_MEMORY_CORESERVICES 43
#define VM_MEMORY_CARBON VM_MEMORY_CORESERVICES
#define VM_MEMORY_JAVA 44
#define VM_MEMORY_COREDATA 45
#define VM_MEMORY_COREDATA_OBJECTIDS 46

#define VM_MEMORY_ATS 50
#define VM_MEMORY_LAYERKIT 51
#define VM_MEMORY_CGIMAGE 52
#define VM_MEMORY_TCMALLOC 53

/* private raster data (i.e. layers, some images, QGL allocator) */
#define VM_MEMORY_COREGRAPHICS_DATA     54

/* shared image and font caches */
#define VM_MEMORY_COREGRAPHICS_SHARED   55

/* Memory used for virtual framebuffers, shadowing buffers, etc... */
#define VM_MEMORY_COREGRAPHICS_FRAMEBUFFERS     56

/* Window backing stores, custom shadow data, and compressed backing stores */
#define VM_MEMORY_COREGRAPHICS_BACKINGSTORES    57

/* x-alloc'd memory */
#define VM_MEMORY_COREGRAPHICS_XALLOC 58

/* catch-all for other uses, such as the read-only shared data page */
#define VM_MEMORY_COREGRAPHICS_MISC VM_MEMORY_COREGRAPHICS

/* memory allocated by the dynamic loader for itself */
#define VM_MEMORY_DYLD 60
/* malloc'd memory created by dyld */
#define VM_MEMORY_DYLD_MALLOC 61

/* Used for sqlite page cache */
#define VM_MEMORY_SQLITE 62

/* JavaScriptCore heaps */
#define VM_MEMORY_JAVASCRIPT_CORE 63
#define VM_MEMORY_WEBASSEMBLY VM_MEMORY_JAVASCRIPT_CORE
/* memory allocated for the JIT */
#define VM_MEMORY_JAVASCRIPT_JIT_EXECUTABLE_ALLOCATOR 64
#define VM_MEMORY_JAVASCRIPT_JIT_REGISTER_FILE 65

/* memory allocated for GLSL */
#define VM_MEMORY_GLSL  66

/* memory allocated for OpenCL.framework */
#define VM_MEMORY_OPENCL    67

/* memory allocated for QuartzCore.framework */
#define VM_MEMORY_COREIMAGE 68

/* memory allocated for WebCore Purgeable Buffers */
#define VM_MEMORY_WEBCORE_PURGEABLE_BUFFERS 69

/* ImageIO memory */
#define VM_MEMORY_IMAGEIO       70

/* CoreProfile memory */
#define VM_MEMORY_COREPROFILE   71

/* assetsd / MobileSlideShow memory */
#define VM_MEMORY_ASSETSD       72

/* libsystem_kernel os_once_alloc */
#define VM_MEMORY_OS_ALLOC_ONCE 73

/* libdispatch internal allocator */
#define VM_MEMORY_LIBDISPATCH 74

/* Accelerate.framework image backing stores */
#define VM_MEMORY_ACCELERATE 75

/* CoreUI image block data */
#define VM_MEMORY_COREUI 76

/* CoreUI image file */
#define VM_MEMORY_COREUIFILE 77

/* Genealogy buffers */
#define VM_MEMORY_GENEALOGY 78

/* RawCamera VM allocated memory */
#define VM_MEMORY_RAWCAMERA 79

/* corpse info for dead process */
#define VM_MEMORY_CORPSEINFO 80

/* Apple System Logger (ASL) messages */
#define VM_MEMORY_ASL 81

/* Swift runtime */
#define VM_MEMORY_SWIFT_RUNTIME 82

/* Swift metadata */
#define VM_MEMORY_SWIFT_METADATA 83

/* DHMM data */
#define VM_MEMORY_DHMM 84

/* memory needed for DFR related actions */
#define VM_MEMORY_DFR 85

/* memory allocated by SceneKit.framework */
#define VM_MEMORY_SCENEKIT 86

/* memory allocated by skywalk networking */
#define VM_MEMORY_SKYWALK 87

#define VM_MEMORY_IOSURFACE 88

#define VM_MEMORY_LIBNETWORK 89

#define VM_MEMORY_AUDIO 90

#define VM_MEMORY_VIDEOBITSTREAM 91

/* memory allocated by CoreMedia */
#define VM_MEMORY_CM_XPC 92

#define VM_MEMORY_CM_RPC 93

#define VM_MEMORY_CM_MEMORYPOOL 94

#define VM_MEMORY_CM_READCACHE 95

#define VM_MEMORY_CM_CRABS 96

/* memory allocated for QuickLookThumbnailing */
#define VM_MEMORY_QUICKLOOK_THUMBNAILS 97

/* memory allocated by Accounts framework */
#define VM_MEMORY_ACCOUNTS 98

/* memory allocated by Sanitizer runtime libraries */
#define VM_MEMORY_SANITIZER 99

/* Differentiate memory needed by GPU drivers and frameworks from generic IOKit allocations */
#define VM_MEMORY_IOACCELERATOR 100

/* memory allocated by CoreMedia for global image registration of frames */
#define VM_MEMORY_CM_REGWARP 101

/* memory allocated by EmbeddedAcousticRecognition for speech decoder */
#define VM_MEMORY_EAR_DECODER 102

/* CoreUI cached image data */
#define VM_MEMORY_COREUI_CACHED_IMAGE_DATA 103

/* ColorSync is using mmap for read-only copies of ICC profile data */
#define VM_MEMORY_COLORSYNC 104

/* backtrace info for simulated crashes */
#define VM_MEMORY_BTINFO 105

/* memory allocated by CoreMedia */
#define VM_MEMORY_CM_HLS 106

/* memory allocated for CompositorServices */
#define VM_MEMORY_COMPOSITOR_SERVICES 107

/* Reserve 230-239 for Rosetta */
#define VM_MEMORY_ROSETTA 230
#define VM_MEMORY_ROSETTA_THREAD_CONTEXT 231
#define VM_MEMORY_ROSETTA_INDIRECT_BRANCH_MAP 232
#define VM_MEMORY_ROSETTA_RETURN_STACK 233
#define VM_MEMORY_ROSETTA_EXECUTABLE_HEAP 234
#define VM_MEMORY_ROSETTA_USER_LDT 235
#define VM_MEMORY_ROSETTA_ARENA 236
#define VM_MEMORY_ROSETTA_10 239

/* Reserve 240-255 for application */
#define VM_MEMORY_APPLICATION_SPECIFIC_1  240
#define VM_MEMORY_APPLICATION_SPECIFIC_2  241
#define VM_MEMORY_APPLICATION_SPECIFIC_3  242
#define VM_MEMORY_APPLICATION_SPECIFIC_4  243
#define VM_MEMORY_APPLICATION_SPECIFIC_5  244
#define VM_MEMORY_APPLICATION_SPECIFIC_6  245
#define VM_MEMORY_APPLICATION_SPECIFIC_7  246
#define VM_MEMORY_APPLICATION_SPECIFIC_8  247
#define VM_MEMORY_APPLICATION_SPECIFIC_9  248
#define VM_MEMORY_APPLICATION_SPECIFIC_10 249
#define VM_MEMORY_APPLICATION_SPECIFIC_11 250
#define VM_MEMORY_APPLICATION_SPECIFIC_12 251
#define VM_MEMORY_APPLICATION_SPECIFIC_13 252
#define VM_MEMORY_APPLICATION_SPECIFIC_14 253
#define VM_MEMORY_APPLICATION_SPECIFIC_15 254
#define VM_MEMORY_APPLICATION_SPECIFIC_16 255

#define VM_MEMORY_COUNT 256

#if !XNU_KERNEL_PRIVATE
#define VM_MAKE_TAG(tag) ((tag) << 24)
#endif /* XNU_KERNEL_PRIVATE */

#if KERNEL_PRIVATE

#pragma mark Kernel Tags

#if XNU_KERNEL_PRIVATE
/*
 *  When making a new VM_KERN_MEMORY_*, update:
 *   - tests vm_parameter_validation_[user|kern]
 *     and their expected results; they deliberately call VM functions with invalid
 *     kernel tag values and you may be turning one of those invalid tags valid.
 *   - vm_kern_memory_names, which is used to map tags to their string name
 */
#endif /* XNU_KERNEL_PRIVATE */

#define VM_KERN_MEMORY_NONE             0

#define VM_KERN_MEMORY_OSFMK            1
#define VM_KERN_MEMORY_BSD              2
#define VM_KERN_MEMORY_IOKIT            3
#define VM_KERN_MEMORY_LIBKERN          4
#define VM_KERN_MEMORY_OSKEXT           5
#define VM_KERN_MEMORY_KEXT             6
#define VM_KERN_MEMORY_IPC              7
#define VM_KERN_MEMORY_STACK            8
#define VM_KERN_MEMORY_CPU              9
#define VM_KERN_MEMORY_PMAP             10
#define VM_KERN_MEMORY_PTE              11
#define VM_KERN_MEMORY_ZONE             12
#define VM_KERN_MEMORY_KALLOC           13
#define VM_KERN_MEMORY_COMPRESSOR       14
#define VM_KERN_MEMORY_COMPRESSED_DATA  15
#define VM_KERN_MEMORY_PHANTOM_CACHE    16
#define VM_KERN_MEMORY_WAITQ            17
#define VM_KERN_MEMORY_DIAG             18
#define VM_KERN_MEMORY_LOG              19
#define VM_KERN_MEMORY_FILE             20
#define VM_KERN_MEMORY_MBUF             21
#define VM_KERN_MEMORY_UBC              22
#define VM_KERN_MEMORY_SECURITY         23
#define VM_KERN_MEMORY_MLOCK            24
#define VM_KERN_MEMORY_REASON           25
#define VM_KERN_MEMORY_SKYWALK          26
#define VM_KERN_MEMORY_LTABLE           27
#define VM_KERN_MEMORY_HV               28
#define VM_KERN_MEMORY_KALLOC_DATA      29
#define VM_KERN_MEMORY_RETIRED          30
#define VM_KERN_MEMORY_KALLOC_TYPE      31
#define VM_KERN_MEMORY_TRIAGE           32
#define VM_KERN_MEMORY_RECOUNT          33
#define VM_KERN_MEMORY_MTAG             34
#define VM_KERN_MEMORY_EXCLAVES         35
#define VM_KERN_MEMORY_EXCLAVES_SHARED  36
#define VM_KERN_MEMORY_KALLOC_SHARED    37
/* add new tags here and adjust first-dynamic value */
#define VM_KERN_MEMORY_CPUTRACE         38
#define VM_KERN_MEMORY_FIRST_DYNAMIC    39

/* out of tags: */
#define VM_KERN_MEMORY_ANY              255
#define VM_KERN_MEMORY_COUNT            256

#pragma mark Kernel Wired Counts

// mach_memory_info.flags
#define VM_KERN_SITE_TYPE               0x000000FF
#define VM_KERN_SITE_TAG                0x00000000
#define VM_KERN_SITE_KMOD               0x00000001
#define VM_KERN_SITE_KERNEL             0x00000002
#define VM_KERN_SITE_COUNTER            0x00000003
#define VM_KERN_SITE_WIRED              0x00000100      /* add to wired count */
#define VM_KERN_SITE_HIDE               0x00000200      /* no zprint */
#define VM_KERN_SITE_NAMED              0x00000400
#define VM_KERN_SITE_ZONE               0x00000800
#define VM_KERN_SITE_ZONE_VIEW          0x00001000
#define VM_KERN_SITE_KALLOC             0x00002000      /* zone field is size class */

/* Kernel Memory Counters */
#if XNU_KERNEL_PRIVATE
/*
 *  When making a new VM_KERN_COUNT_*, also update vm_kern_count_names
 */
#endif /* XNU_KERNEL_PRIVATE */

#define VM_KERN_COUNT_MANAGED           0
#define VM_KERN_COUNT_RESERVED          1
#define VM_KERN_COUNT_WIRED             2
#define VM_KERN_COUNT_WIRED_MANAGED     3
#define VM_KERN_COUNT_STOLEN            4
#define VM_KERN_COUNT_LOPAGE            5
#define VM_KERN_COUNT_MAP_KERNEL        6
#define VM_KERN_COUNT_MAP_ZONE          7
#define VM_KERN_COUNT_MAP_KALLOC        8

#define VM_KERN_COUNT_WIRED_BOOT    9

#define VM_KERN_COUNT_BOOT_STOLEN       10

/* The number of bytes from the kernel cache that are wired in memory */
#define VM_KERN_COUNT_WIRED_STATIC_KERNELCACHE 11

#define VM_KERN_COUNT_MAP_KALLOC_LARGE  VM_KERN_COUNT_MAP_KALLOC
#define VM_KERN_COUNT_MAP_KALLOC_LARGE_DATA     12
#define VM_KERN_COUNT_MAP_KERNEL_DATA   13

/* The size of the exclaves iboot carveout (exclaves memory not from XNU) in bytes. */
#define VM_KERN_COUNT_EXCLAVES_CARVEOUT 14

/* The number of VM_KERN_COUNT_ stats. New VM_KERN_COUNT_ entries should be less than this. */
#define VM_KERN_COUNTER_COUNT           15

#define VM_COPY_DESTINATION_USER 0
#define VM_COPY_DESTINATION_KERNEL 1
#define VM_COPY_DESTINATION_UNKNOWN 2 /* memory entry */
#define VM_COPY_DESTINATION_INTERNAL 3 /* creating a copy map for internal use which is soon discarded */
#endif /* KERNEL_PRIVATE */

__END_DECLS

#endif  /* _MACH_VM_STATISTICS_H_ */
