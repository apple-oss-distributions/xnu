/*
 * Copyright (c) 2021 Apple Inc. All rights reserved.
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

#include <sys/errno.h>

#include <mach/mach_types.h>
#include <mach/mach_traps.h>
#include <mach/host_priv.h>
#include <mach/kern_return.h>
#include <mach/memory_object_control.h>
#include <mach/memory_object_types.h>
#include <mach/port.h>
#include <mach/policy.h>
#include <mach/upl.h>
#include <mach/thread_act.h>
#include <mach/mach_vm.h>

#include <kern/host.h>
#include <kern/kalloc.h>
#include <kern/thread.h>
#include <kern/ipc_kobject.h>

#include <ipc/ipc_port.h>
#include <ipc/ipc_space.h>

#include <vm/memory_object.h>
#include <vm/vm_kern.h>
#include <vm/vm_fault.h>
#include <vm/vm_map.h>
#include <vm/vm_pageout.h>
#include <vm/vm_protos.h>
#include <vm/vm_dyld_pager.h>

#include <sys/kdebug_triage.h>
#include <mach-o/fixup-chains.h>
#if defined(HAS_APPLE_PAC)
#include <ptrauth.h>
#include <arm/misc_protos.h>
#endif /* defined(HAS_APPLE_PAC) */

/*
 * DYLD page in linking pager.
 *
 * This external memory manager (EMM) applies dyld fixup to data
 * pages, allowing the modified page to appear "clean".
 *
 * The modified pages will never be dirtied, so the memory manager doesn't
 * need to handle page-out requests (from memory_object_data_return()).  The
 * pages are mapped copy-on-write, so that the originals stay clean.
 */

/* forward declarations */
typedef struct dyld_pager *dyld_pager_t;
static void dyld_pager_reference(memory_object_t mem_obj);
static void dyld_pager_deallocate(memory_object_t mem_obj);
static void dyld_pager_deallocate_internal(dyld_pager_t pager, bool locked);
static kern_return_t dyld_pager_init(memory_object_t mem_obj,
    memory_object_control_t control,
    memory_object_cluster_size_t pg_size);
static kern_return_t dyld_pager_terminate(memory_object_t mem_obj);
static void dyld_pager_terminate_internal(dyld_pager_t pager);
static kern_return_t dyld_pager_data_request(memory_object_t mem_obj,
    memory_object_offset_t offset,
    memory_object_cluster_size_t length,
    vm_prot_t protection_required,
    memory_object_fault_info_t fault_info);
static kern_return_t dyld_pager_data_return(memory_object_t mem_obj,
    memory_object_offset_t offset,
    memory_object_cluster_size_t      data_cnt,
    memory_object_offset_t *resid_offset,
    int *io_error,
    boolean_t dirty,
    boolean_t kernel_copy,
    int upl_flags);
static kern_return_t dyld_pager_data_initialize(memory_object_t mem_obj,
    memory_object_offset_t offset,
    memory_object_cluster_size_t data_cnt);
static kern_return_t dyld_pager_map(memory_object_t mem_obj,
    vm_prot_t prot);
static kern_return_t dyld_pager_last_unmap(memory_object_t mem_obj);
static boolean_t dyld_pager_backing_object(
	memory_object_t mem_obj,
	memory_object_offset_t mem_obj_offset,
	vm_object_t *backing_object,
	vm_object_offset_t *backing_offset);
static dyld_pager_t dyld_pager_lookup(memory_object_t  mem_obj);

/*
 * Vector of VM operations for this EMM.
 * These routines are invoked by VM via the memory_object_*() interfaces.
 */
const struct memory_object_pager_ops dyld_pager_ops = {
	.memory_object_reference = dyld_pager_reference,
	.memory_object_deallocate = dyld_pager_deallocate,
	.memory_object_init = dyld_pager_init,
	.memory_object_terminate = dyld_pager_terminate,
	.memory_object_data_request = dyld_pager_data_request,
	.memory_object_data_return = dyld_pager_data_return,
	.memory_object_data_initialize = dyld_pager_data_initialize,
	.memory_object_map = dyld_pager_map,
	.memory_object_last_unmap = dyld_pager_last_unmap,
	.memory_object_backing_object = dyld_pager_backing_object,
	.memory_object_pager_name = "dyld"
};

/*
 * The "dyld_pager" structure. We create one of these for each use of
 * map_with_linking_np() that dyld uses.
 */
struct dyld_pager {
	struct memory_object    dyld_header;          /* mandatory generic header */

#if MEMORY_OBJECT_HAS_REFCOUNT
#define dyld_ref_count           dyld_header.mo_ref
#else
	os_ref_atomic_t         dyld_ref_count;      /* active uses */
#endif
	bool                    dyld_is_mapped;      /* has active mappings */
	bool                    dyld_is_ready;       /* is this pager ready? */
	vm_object_t             dyld_backing_object; /* VM object for shared cache */
	void                    *dyld_link_info;
	uint32_t                dyld_link_info_size;
	uint32_t                dyld_num_range;
	memory_object_offset_t  dyld_file_offset[MWL_MAX_REGION_COUNT];
	mach_vm_address_t       dyld_address[MWL_MAX_REGION_COUNT];
	mach_vm_size_t          dyld_size[MWL_MAX_REGION_COUNT];
#if defined(HAS_APPLE_PAC)
	uint64_t                dyld_a_key;
#endif /* defined(HAS_APPLE_PAC) */
};


/*
 * "dyld_pager_lock" for counters, ref counting, etc.
 */
LCK_GRP_DECLARE(dyld_pager_lck_grp, "dyld_pager");
LCK_MTX_DECLARE(dyld_pager_lock, &dyld_pager_lck_grp);

/*
 * Statistics & counters.
 */
uint32_t dyld_pager_count = 0;
uint32_t dyld_pager_count_max = 0;

/*
 * dyld_pager_init()
 *
 * Initialize the memory object and makes it ready to be used and mapped.
 */
static kern_return_t
dyld_pager_init(
	memory_object_t                 mem_obj,
	memory_object_control_t         control,
	__unused
	memory_object_cluster_size_t    pg_size)
{
	dyld_pager_t                    pager;
	kern_return_t                   kr;
	memory_object_attr_info_data_t  attributes;

	if (control == MEMORY_OBJECT_CONTROL_NULL) {
		printf("%s(): control NULL\n", __func__);
		return KERN_INVALID_ARGUMENT;
	}

	pager = dyld_pager_lookup(mem_obj);

	memory_object_control_reference(control);

	pager->dyld_header.mo_control = control;

	attributes.copy_strategy = MEMORY_OBJECT_COPY_DELAY;
	attributes.cluster_size = (1 << (PAGE_SHIFT));
	attributes.may_cache_object = FALSE;
	attributes.temporary = TRUE;

	kr = memory_object_change_attributes(
		control,
		MEMORY_OBJECT_ATTRIBUTE_INFO,
		(memory_object_info_t) &attributes,
		MEMORY_OBJECT_ATTR_INFO_COUNT);
	if (kr != KERN_SUCCESS) {
		panic("dyld_pager_init: " "memory_object_change_attributes() failed");
	}

	return KERN_SUCCESS;
}

/*
 * dyld_data_return()
 *
 * A page-out request from VM -- should never happen so panic.
 */
static kern_return_t
dyld_pager_data_return(
	__unused memory_object_t        mem_obj,
	__unused memory_object_offset_t offset,
	__unused memory_object_cluster_size_t data_cnt,
	__unused memory_object_offset_t *resid_offset,
	__unused int                    *io_error,
	__unused boolean_t              dirty,
	__unused boolean_t              kernel_copy,
	__unused int                    upl_flags)
{
	panic("dyld_pager_data_return: should never happen!");
	return KERN_FAILURE;
}

static kern_return_t
dyld_pager_data_initialize(
	__unused memory_object_t        mem_obj,
	__unused memory_object_offset_t offset,
	__unused memory_object_cluster_size_t data_cnt)
{
	panic("dyld_pager_data_initialize: should never happen");
	return KERN_FAILURE;
}


/*
 * Apply fixups to a page used by a 64 bit process.
 */
static kern_return_t
fixupPage64(
	vm_offset_t                           contents,
	vm_offset_t                           end_contents,
	void                                  *link_info,
	struct dyld_chained_starts_in_segment *segInfo,
	uint32_t                              pageIndex,
	bool                                  offsetBased)
{
	struct mwl_info_hdr                   *hdr = (struct mwl_info_hdr *)link_info;
	uint64_t                              *bindsArray  = (uint64_t *)((uintptr_t)hdr + hdr->mwli_binds_offset);
	uint16_t                              firstStartOffset = segInfo->page_start[pageIndex];

	/*
	 * Done if no fixups on the page
	 */
	if (firstStartOffset == DYLD_CHAINED_PTR_START_NONE) {
		return KERN_SUCCESS;
	}

	/*
	 * walk the chain
	 */
	uint64_t *chain  = (uint64_t *)(contents + firstStartOffset);
	uint64_t targetAdjust = (offsetBased ? hdr->mwli_image_address : hdr->mwli_slide);
	uint64_t delta = 0;
	do {
		if ((uintptr_t)chain < contents || (uintptr_t)chain + sizeof(*chain) > end_contents) {
			printf("%s(): chain 0x%llx out of range 0x%llx..0x%llx", __func__,
			    (long long)chain, (long long)contents, (long long)end_contents);
			return KERN_FAILURE;
		}
		uint64_t value  = *chain;
		bool     isBind = (value & 0x8000000000000000ULL);
		delta = (value >> 51) & 0xFFF;
		if (isBind) {
			uint32_t bindOrdinal = value & 0x00FFFFFF;
			if (bindOrdinal >= hdr->mwli_binds_count) {
				printf("%s out of range bind ordinal %u (max %u)\n", __func__,
				    bindOrdinal, hdr->mwli_binds_count);
				return KERN_FAILURE;
			}
			uint32_t addend = (value >> 24) & 0xFF;
			*chain = bindsArray[bindOrdinal] + addend;
		} else {
			/* is rebase */
			uint64_t target = value & 0xFFFFFFFFFULL;
			uint64_t high8  = (value >> 36) & 0xFF;
			*chain = target + targetAdjust + (high8 << 56);
		}
		if (delta * 4 >= PAGE_SIZE) {
			printf("%s(): delta offset > page size %lld\n", __func__, delta * 4);
			return KERN_FAILURE;
		}
		chain = (uint64_t *)((uintptr_t)chain + (delta * 4)); // 4-byte stride
	} while (delta != 0);
	return KERN_SUCCESS;
}


/*
 * Apply fixups within a page used by a 32 bit process.
 */
static kern_return_t
fixupChain32(
	uint32_t                              *chain,
	vm_offset_t                           contents,
	vm_offset_t                           end_contents,
	void                                  *link_info,
	struct dyld_chained_starts_in_segment *segInfo,
	uint32_t                              *bindsArray)
{
	struct mwl_info_hdr                   *hdr = (struct mwl_info_hdr *)link_info;
	uint32_t                              delta = 0;

	do {
		if ((uintptr_t)chain < contents || (uintptr_t)chain + sizeof(*chain) > end_contents) {
			printf("%s(): chain 0x%llx out of range 0x%llx..0x%llx", __func__,
			    (long long)chain, (long long)contents, (long long)end_contents);
			return KERN_FAILURE;
		}
		uint32_t value = *chain;
		delta = (value >> 26) & 0x1F;
		if (value & 0x80000000) {
			// is bind
			uint32_t bindOrdinal = value & 0x000FFFFF;
			if (bindOrdinal >= hdr->mwli_binds_count) {
				printf("%s(): out of range bind ordinal %u (max %u)",
				    __func__, bindOrdinal, hdr->mwli_binds_count);
				return KERN_FAILURE;
			}
			uint32_t addend = (value >> 20) & 0x3F;
			*chain = bindsArray[bindOrdinal] + addend;
		} else {
			// is rebase
			uint32_t target = value & 0x03FFFFFF;
			if (target > segInfo->max_valid_pointer) {
				// handle non-pointers in chain
				uint32_t bias = (0x04000000 + segInfo->max_valid_pointer) / 2;
				*chain = target - bias;
			} else {
				*chain = target + (uint32_t)hdr->mwli_slide;
			}
		}
		chain += delta;
	} while (delta != 0);
	return KERN_SUCCESS;
}


/*
 * Apply fixups to a page used by a 32 bit process.
 */
static kern_return_t
fixupPage32(
	vm_offset_t                           contents,
	vm_offset_t                           end_contents,
	void                                  *link_info,
	uint32_t                              link_info_size,
	struct dyld_chained_starts_in_segment *segInfo,
	uint32_t                              pageIndex)
{
	struct mwl_info_hdr                   *hdr = (struct mwl_info_hdr  *)link_info;
	uint32_t                              *bindsArray = (uint32_t *)((uintptr_t)hdr + hdr->mwli_binds_offset);
	uint16_t                              startOffset = segInfo->page_start[pageIndex];

	/*
	 * done if no fixups
	 */
	if (startOffset == DYLD_CHAINED_PTR_START_NONE) {
		return KERN_SUCCESS;
	}

	if (startOffset & DYLD_CHAINED_PTR_START_MULTI) {
		// some fixups in the page are too far apart, so page has multiple starts
		uint32_t overflowIndex = startOffset & ~DYLD_CHAINED_PTR_START_MULTI;
		bool chainEnd = false;
		while (!chainEnd) {
			/*
			 * range check against link_info, note +1 to include data we'll dereference
			 */
			if ((uintptr_t)&segInfo->page_start[overflowIndex + 1] > (uintptr_t)link_info + link_info_size) {
				printf("%s(): out of range segInfo->page_start[overflowIndex]", __func__);
				return KERN_FAILURE;
			}
			chainEnd    = (segInfo->page_start[overflowIndex] & DYLD_CHAINED_PTR_START_LAST);
			startOffset = (segInfo->page_start[overflowIndex] & ~DYLD_CHAINED_PTR_START_LAST);
			uint32_t *chain = (uint32_t *)(contents + startOffset);
			fixupChain32(chain, contents, end_contents, link_info, segInfo, bindsArray);
			++overflowIndex;
		}
	} else {
		uint32_t *chain = (uint32_t *)(contents + startOffset);
		fixupChain32(chain, contents, end_contents, link_info, segInfo, bindsArray);
	}
	return KERN_SUCCESS;
}

#if defined(HAS_APPLE_PAC)
/*
 * Sign a pointer needed for fixups.
 */
static kern_return_t
signPointer(
	uint64_t         unsignedAddr,
	void             *loc,
	bool             addrDiv,
	uint16_t         diversity,
	ptrauth_key      key,
	dyld_pager_t     pager,
	uint64_t         *signedAddr)
{
	// don't sign NULL
	if (unsignedAddr == 0) {
		*signedAddr = 0;
		return KERN_SUCCESS;
	}

	uint64_t extendedDiscriminator = diversity;
	if (addrDiv) {
		extendedDiscriminator = __builtin_ptrauth_blend_discriminator(loc, extendedDiscriminator);
	}

	switch (key) {
	case ptrauth_key_asia:
	case ptrauth_key_asda:
		if (pager->dyld_a_key == 0 || arm_user_jop_disabled()) {
			*signedAddr = unsignedAddr;
		} else {
			*signedAddr = (uintptr_t)pmap_sign_user_ptr((void *)unsignedAddr, key, extendedDiscriminator, pager->dyld_a_key);
		}
		break;

	default:
		printf("%s(): Invalid ptr auth key %d\n", __func__, key);
		return KERN_FAILURE;
	}
	return KERN_SUCCESS;
}

/*
 * Apply fixups to a page used by a 64 bit process using pointer authentication.
 */
static kern_return_t
fixupPageAuth64(
	uint64_t                              userVA,
	vm_offset_t                           contents,
	vm_offset_t                           end_contents,
	dyld_pager_t                          pager,
	struct dyld_chained_starts_in_segment *segInfo,
	uint32_t                              pageIndex,
	bool                                  offsetBased)
{
	void                 *link_info = pager->dyld_link_info;
	uint32_t             link_info_size = pager->dyld_link_info_size;
	struct mwl_info_hdr  *hdr = (struct mwl_info_hdr *)link_info;
	uint64_t             *bindsArray = (uint64_t*)((uintptr_t)link_info + hdr->mwli_binds_offset);

	/*
	 * range check against link_info, note +1 to include data we'll dereference
	 */
	if ((uintptr_t)&segInfo->page_start[pageIndex + 1] > (uintptr_t)link_info + link_info_size) {
		printf("%s(): out of range segInfo->page_start[pageIndex]", __func__);
		return KERN_FAILURE;
	}
	uint16_t firstStartOffset = segInfo->page_start[pageIndex];

	/*
	 * All done if no fixups on the page
	 */
	if (firstStartOffset == DYLD_CHAINED_PTR_START_NONE) {
		return KERN_SUCCESS;
	}

	/*
	 * Walk the chain of offsets to fix up
	 */
	uint64_t *chain = (uint64_t *)(contents + firstStartOffset);
	uint64_t targetAdjust = (offsetBased ? hdr->mwli_image_address : hdr->mwli_slide);
	uint64_t delta = 0;
	do {
		if ((uintptr_t)chain < contents || (uintptr_t)chain + sizeof(*chain) > end_contents) {
			printf("%s(): chain 0x%llx out of range 0x%llx..0x%llx", __func__,
			    (long long)chain, (long long)contents, (long long)end_contents);
			return KERN_FAILURE;
		}
		uint64_t value = *chain;
		delta = (value >> 51) & 0x7FF;
		bool isAuth = (value & 0x8000000000000000ULL);
		bool isBind = (value & 0x4000000000000000ULL);
		if (isAuth) {
			ptrauth_key key = (ptrauth_key)((value >> 49) & 0x3);
			bool        addrDiv = ((value & (1ULL << 48)) != 0);
			uint16_t    diversity = (uint16_t)((value >> 32) & 0xFFFF);
			uintptr_t   uVA = userVA + ((uintptr_t)chain - contents);
			if (isBind) {
				uint32_t bindOrdinal = value & 0x00FFFFFF;
				if (bindOrdinal >= hdr->mwli_binds_count) {
					printf("%s(): out of range bind ordinal %u (max %u)",
					    __func__, bindOrdinal, hdr->mwli_binds_count);
					return KERN_FAILURE;
				}
				if (signPointer(bindsArray[bindOrdinal], (void *)uVA, addrDiv, diversity, key, pager, chain) != KERN_SUCCESS) {
					return KERN_FAILURE;
				}
			} else {
				/* note: in auth rebases only have 32-bits, so target is always offset - never vmaddr */
				uint64_t target = (value & 0xFFFFFFFF) + hdr->mwli_image_address;
				if (signPointer(target, (void *)uVA, addrDiv, diversity, key, pager, chain) != KERN_SUCCESS) {
					return KERN_FAILURE;
				}
			}
		} else {
			if (isBind) {
				uint32_t bindOrdinal = value & 0x00FFFFFF;
				if (bindOrdinal >= hdr->mwli_binds_count) {
					printf("%s(): out of range bind ordinal %u (max %u)",
					    __func__, bindOrdinal, hdr->mwli_binds_count);
					return KERN_FAILURE;
				} else {
					uint64_t addend19 = (value >> 32) & 0x0007FFFF;
					if (addend19 & 0x40000) {
						addend19 |=  0xFFFFFFFFFFFC0000ULL;
					}
					*chain = bindsArray[bindOrdinal] + addend19;
				}
			} else {
				uint64_t target = (value & 0x7FFFFFFFFFFULL);
				uint64_t high8  = (value << 13) & 0xFF00000000000000ULL;
				*chain = target + targetAdjust + high8;
			}
		}
		chain += delta;
	} while (delta != 0);
	return KERN_SUCCESS;
}
#endif /* defined(HAS_APPLE_PAC) */


/*
 * Handle dyld fixups for a page.
 */
static kern_return_t
fixup_page(
	vm_offset_t         contents,
	vm_offset_t         end_contents,
	uint64_t            userVA,
	dyld_pager_t        pager)
{
	void                                  *link_info = pager->dyld_link_info;
	uint32_t                              link_info_size = pager->dyld_link_info_size;
	struct mwl_info_hdr                   *hdr = (struct mwl_info_hdr *)link_info;
	struct dyld_chained_starts_in_segment *segInfo = NULL;
	uint32_t                              pageIndex = 0;
	uint32_t                              segIndex;
	struct dyld_chained_starts_in_image   *startsInfo;
	struct dyld_chained_starts_in_segment *seg;
	uint64_t                              segStartAddress;
	uint64_t                              segEndAddress;

	/*
	 * Note this is a linear search done for every page we have to fix up.
	 * However, it should be quick as there should only be 2 or 4 segments:
	 * - data
	 * - data const
	 * - data auth (for arm64e)
	 * - data const auth (for arm64e)
	 */
	startsInfo = (struct dyld_chained_starts_in_image *)((uintptr_t)hdr + hdr->mwli_chains_offset);
	for (segIndex = 0; segIndex < startsInfo->seg_count; ++segIndex) {
		seg = (struct dyld_chained_starts_in_segment *)
		    ((uintptr_t)startsInfo + startsInfo->seg_info_offset[segIndex]);

		/*
		 * ensure we don't go out of bounds of the link_info
		 */
		if ((uintptr_t)seg + sizeof(*seg) > (uintptr_t)link_info + link_info_size) {
			printf("%s(): seg_info out of bounds\n", __func__);
			return KERN_FAILURE;
		}

		segStartAddress = hdr->mwli_image_address + seg->segment_offset;
		segEndAddress = segStartAddress + seg->page_count * seg->page_size;
		if (segStartAddress <= userVA && userVA < segEndAddress) {
			segInfo = seg;
			pageIndex = (uint32_t)(userVA - segStartAddress) / PAGE_SIZE;

			/* ensure seg->size fits in link_info_size */
			if ((uintptr_t)seg + seg->size > (uintptr_t)link_info + link_info_size) {
				printf("%s(): seg->size out of bounds\n", __func__);
				return KERN_FAILURE;
			}
			if (seg->size < sizeof(struct dyld_chained_starts_in_segment)) {
				printf("%s(): seg->size too small\n", __func__);
				return KERN_FAILURE;
			}
			/* ensure page_count and pageIndex are valid too */
			if ((uintptr_t)&seg->page_start[seg->page_count] > (uintptr_t)link_info + link_info_size) {
				printf("%s(): seg->page_count out of bounds\n", __func__);
				return KERN_FAILURE;
			}
			if (pageIndex >= seg->page_count) {
				printf("%s(): seg->page_count too small\n", __func__);
				return KERN_FAILURE;
			}

			break;
		}
	}

	/*
	 * Question for Nick.. or can we make this OK and just return KERN_SUCCESS, nothing to do?
	 */
	if (segInfo == NULL) {
		printf("%s(): No segment for user VA 0x%llx\n", __func__, (long long)userVA);
		return KERN_FAILURE;
	}

	/*
	 * Route to the appropriate fixup routine
	 */
	switch (hdr->mwli_pointer_format) {
#if defined(HAS_APPLE_PAC)
	case DYLD_CHAINED_PTR_ARM64E:
		fixupPageAuth64(userVA, contents, end_contents, pager, segInfo, pageIndex, false);
		break;
	case DYLD_CHAINED_PTR_ARM64E_USERLAND:
	case DYLD_CHAINED_PTR_ARM64E_USERLAND24:
		fixupPageAuth64(userVA, contents, end_contents, pager, segInfo, pageIndex, true);
		break;
#endif /* defined(HAS_APPLE_PAC) */
	case DYLD_CHAINED_PTR_64:
		fixupPage64(contents, end_contents, link_info, segInfo, pageIndex, false);
		break;
	case DYLD_CHAINED_PTR_64_OFFSET:
		fixupPage64(contents, end_contents, link_info, segInfo, pageIndex, true);
		break;
	case DYLD_CHAINED_PTR_32:
		fixupPage32(contents, end_contents, link_info, link_info_size, segInfo, pageIndex);
		break;
	default:
		printf("%s(): unknown pointer_format %d\n", __func__, hdr->mwli_pointer_format);
		return KERN_FAILURE;
	}
	return KERN_SUCCESS;
}

/*
 * dyld_pager_data_request()
 *
 * Handles page-in requests from VM.
 */
static kern_return_t
dyld_pager_data_request(
	memory_object_t              mem_obj,
	memory_object_offset_t       offset,
	memory_object_cluster_size_t length,
	__unused vm_prot_t           protection_required,
	memory_object_fault_info_t   mo_fault_info)
{
	dyld_pager_t            pager;
	memory_object_control_t mo_control;
	upl_t                   upl = NULL;
	int                     upl_flags;
	upl_size_t              upl_size;
	upl_page_info_t         *upl_pl = NULL;
	unsigned int            pl_count;
	vm_object_t             src_top_object = VM_OBJECT_NULL;
	vm_object_t             src_page_object = VM_OBJECT_NULL;
	vm_object_t             dst_object;
	kern_return_t           kr;
	kern_return_t           retval = KERN_SUCCESS;
	vm_offset_t             src_vaddr;
	vm_offset_t             dst_vaddr;
	vm_offset_t             cur_offset;
	kern_return_t           error_code;
	vm_prot_t               prot;
	vm_page_t               src_page, top_page;
	int                     interruptible;
	struct vm_object_fault_info fault_info = *((struct vm_object_fault_info *)(uintptr_t)mo_fault_info);
	struct mwl_info_hdr     *hdr;
	uint32_t                r;
	uint64_t                userVA;

	fault_info.stealth = TRUE;
	fault_info.io_sync = FALSE;
	fault_info.mark_zf_absent = FALSE;
	fault_info.batch_pmap_op = FALSE;
	interruptible = fault_info.interruptible;

	pager = dyld_pager_lookup(mem_obj);
	assert(pager->dyld_is_ready);
	assert(os_ref_get_count_raw(&pager->dyld_ref_count) > 1); /* pager is alive */
	assert(pager->dyld_is_mapped); /* pager is mapped */
	hdr = (struct mwl_info_hdr *)pager->dyld_link_info;

	/*
	 * Gather in a UPL all the VM pages requested by VM.
	 */
	mo_control = pager->dyld_header.mo_control;

	upl_size = length;
	upl_flags =
	    UPL_RET_ONLY_ABSENT |
	    UPL_SET_LITE |
	    UPL_NO_SYNC |
	    UPL_CLEAN_IN_PLACE |        /* triggers UPL_CLEAR_DIRTY */
	    UPL_SET_INTERNAL;
	pl_count = 0;
	kr = memory_object_upl_request(mo_control,
	    offset, upl_size,
	    &upl, NULL, NULL, upl_flags, VM_KERN_MEMORY_SECURITY);
	if (kr != KERN_SUCCESS) {
		ktriage_record(thread_tid(current_thread()), KDBG_TRIAGE_EVENTID(KDBG_TRIAGE_SUBSYS_DYLD_PAGER, KDBG_TRIAGE_RESERVED, KDBG_TRIAGE_DYLD_PAGER_NO_UPL), 0 /* arg */);
		retval = kr;
		goto done;
	}
	dst_object = memory_object_control_to_vm_object(mo_control);
	assert(dst_object != VM_OBJECT_NULL);

	/*
	 * We'll map the original data in the kernel address space from the
	 * backing VM object, itself backed by the executable/library file via
	 * the vnode pager.
	 */
	src_top_object = pager->dyld_backing_object;
	assert(src_top_object != VM_OBJECT_NULL);
	vm_object_reference(src_top_object); /* keep the source object alive */

	/*
	 * Fill in the contents of the pages requested by VM.
	 */
	upl_pl = UPL_GET_INTERNAL_PAGE_LIST(upl);
	pl_count = length / PAGE_SIZE;
	for (cur_offset = 0;
	    retval == KERN_SUCCESS && cur_offset < length;
	    cur_offset += PAGE_SIZE) {
		ppnum_t dst_pnum;

		if (!upl_page_present(upl_pl, (int)(cur_offset / PAGE_SIZE))) {
			/* this page is not in the UPL: skip it */
			continue;
		}

		/*
		 * Map the source page in the kernel's virtual address space.
		 * We already hold a reference on the src_top_object.
		 */
retry_src_fault:
		vm_object_lock(src_top_object);
		vm_object_paging_begin(src_top_object);
		error_code = 0;
		prot = VM_PROT_READ;
		src_page = VM_PAGE_NULL;
		kr = vm_fault_page(src_top_object,
		    offset + cur_offset,
		    VM_PROT_READ,
		    FALSE,
		    FALSE,                /* src_page not looked up */
		    &prot,
		    &src_page,
		    &top_page,
		    NULL,
		    &error_code,
		    FALSE,
		    &fault_info);
		switch (kr) {
		case VM_FAULT_SUCCESS:
			break;
		case VM_FAULT_RETRY:
			goto retry_src_fault;
		case VM_FAULT_MEMORY_SHORTAGE:
			if (vm_page_wait(interruptible)) {
				goto retry_src_fault;
			}
			ktriage_record(thread_tid(current_thread()), KDBG_TRIAGE_EVENTID(KDBG_TRIAGE_SUBSYS_DYLD_PAGER, KDBG_TRIAGE_RESERVED, KDBG_TRIAGE_DYLD_PAGER_MEMORY_SHORTAGE), 0 /* arg */);
			OS_FALLTHROUGH;
		case VM_FAULT_INTERRUPTED:
			retval = MACH_SEND_INTERRUPTED;
			goto done;
		case VM_FAULT_SUCCESS_NO_VM_PAGE:
			/* success but no VM page: fail */
			vm_object_paging_end(src_top_object);
			vm_object_unlock(src_top_object);
			OS_FALLTHROUGH;
		case VM_FAULT_MEMORY_ERROR:
			/* the page is not there ! */
			if (error_code) {
				retval = error_code;
			} else {
				retval = KERN_MEMORY_ERROR;
			}
			goto done;
		default:
			panic("dyld_pager_data_request: vm_fault_page() unexpected error 0x%x\n", kr);
		}
		assert(src_page != VM_PAGE_NULL);
		assert(src_page->vmp_busy);

		if (src_page->vmp_q_state != VM_PAGE_ON_SPECULATIVE_Q) {
			vm_page_lockspin_queues();
			if (src_page->vmp_q_state != VM_PAGE_ON_SPECULATIVE_Q) {
				vm_page_speculate(src_page, FALSE);
			}
			vm_page_unlock_queues();
		}

		/*
		 * Establish pointers to the source and destination physical pages.
		 */
		dst_pnum = (ppnum_t)upl_phys_page(upl_pl, (int)(cur_offset / PAGE_SIZE));
		assert(dst_pnum != 0);

		src_vaddr = (vm_map_offset_t)phystokv((pmap_paddr_t)VM_PAGE_GET_PHYS_PAGE(src_page) << PAGE_SHIFT);
		dst_vaddr = (vm_map_offset_t)phystokv((pmap_paddr_t)dst_pnum << PAGE_SHIFT);
		src_page_object = VM_PAGE_OBJECT(src_page);

		/*
		 * Validate the original page...
		 */
		if (src_page_object->code_signed) {
			vm_page_validate_cs_mapped(src_page, PAGE_SIZE, 0, (const void *)src_vaddr);
		}

		/*
		 * ... and transfer the results to the destination page.
		 */
		UPL_SET_CS_VALIDATED(upl_pl, cur_offset / PAGE_SIZE, src_page->vmp_cs_validated);
		UPL_SET_CS_TAINTED(upl_pl, cur_offset / PAGE_SIZE, src_page->vmp_cs_tainted);
		UPL_SET_CS_NX(upl_pl, cur_offset / PAGE_SIZE, src_page->vmp_cs_nx);

		/*
		 * The page provider might access a mapped file, so let's
		 * release the object lock for the source page to avoid a
		 * potential deadlock.
		 * The source page is kept busy and we have a
		 * "paging_in_progress" reference on its object, so it's safe
		 * to unlock the object here.
		 */
		assert(src_page->vmp_busy);
		assert(src_page_object->paging_in_progress > 0);
		vm_object_unlock(src_page_object);

		/*
		 * Process the original contents of the source page
		 * into the destination page.
		 */
		bcopy((const char *)src_vaddr, (char *)dst_vaddr, PAGE_SIZE);

		/*
		 * Figure out what the original user virtual address was, based on the offset.
		 */
		userVA = 0;
		for (r = 0; r < pager->dyld_num_range; ++r) {
			vm_offset_t o = offset + cur_offset;
			if (pager->dyld_file_offset[r] <= o &&
			    o < pager->dyld_file_offset[r] + pager->dyld_size[r]) {
				userVA = pager->dyld_address[r] + (o - pager->dyld_file_offset[r]);
				break;
			}
		}

		/*
		 * If we have a valid range fixup the page.
		 */
		if (r == pager->dyld_num_range) {
			printf("%s(): Range not found for offset 0x%llx\n", __func__, (long long)cur_offset);
			retval = KERN_FAILURE;
		} else if (fixup_page(dst_vaddr, dst_vaddr + PAGE_SIZE, userVA, pager) != KERN_SUCCESS) {
			/* printf was done under fixup_page() */
			retval = KERN_FAILURE;
		}
		if (retval != KERN_SUCCESS) {
			ktriage_record(thread_tid(current_thread()), KDBG_TRIAGE_EVENTID(KDBG_TRIAGE_SUBSYS_DYLD_PAGER, KDBG_TRIAGE_RESERVED, KDBG_TRIAGE_DYLD_PAGER_SLIDE_ERROR), 0 /* arg */);
		}

		assert(VM_PAGE_OBJECT(src_page) == src_page_object);
		assert(src_page->vmp_busy);
		assert(src_page_object->paging_in_progress > 0);
		vm_object_lock(src_page_object);

		/*
		 * Cleanup the result of vm_fault_page() of the source page.
		 */
		PAGE_WAKEUP_DONE(src_page);
		src_page = VM_PAGE_NULL;
		vm_object_paging_end(src_page_object);
		vm_object_unlock(src_page_object);

		if (top_page != VM_PAGE_NULL) {
			assert(VM_PAGE_OBJECT(top_page) == src_top_object);
			vm_object_lock(src_top_object);
			VM_PAGE_FREE(top_page);
			vm_object_paging_end(src_top_object);
			vm_object_unlock(src_top_object);
		}
	}

done:
	if (upl != NULL) {
		/* clean up the UPL */

		/*
		 * The pages are currently dirty because we've just been
		 * writing on them, but as far as we're concerned, they're
		 * clean since they contain their "original" contents as
		 * provided by us, the pager.
		 * Tell the UPL to mark them "clean".
		 */
		upl_clear_dirty(upl, TRUE);

		/* abort or commit the UPL */
		if (retval != KERN_SUCCESS) {
			upl_abort(upl, 0);
		} else {
			boolean_t empty;
			assertf(page_aligned(upl->u_offset) && page_aligned(upl->u_size),
			    "upl %p offset 0x%llx size 0x%x\n",
			    upl, upl->u_offset, upl->u_size);
			upl_commit_range(upl, 0, upl->u_size,
			    UPL_COMMIT_CS_VALIDATED | UPL_COMMIT_WRITTEN_BY_KERNEL,
			    upl_pl, pl_count, &empty);
		}

		/* and deallocate the UPL */
		upl_deallocate(upl);
		upl = NULL;
	}
	if (src_top_object != VM_OBJECT_NULL) {
		vm_object_deallocate(src_top_object);
	}
	return retval;
}

/*
 * dyld_pager_reference()
 *
 * Get a reference on this memory object.
 * For external usage only.  Assumes that the initial reference count is not 0,
 * i.e one should not "revive" a dead pager this way.
 */
static void
dyld_pager_reference(
	memory_object_t mem_obj)
{
	dyld_pager_t    pager;

	pager = dyld_pager_lookup(mem_obj);

	lck_mtx_lock(&dyld_pager_lock);
	os_ref_retain_locked_raw(&pager->dyld_ref_count, NULL);
	lck_mtx_unlock(&dyld_pager_lock);
}



/*
 * dyld_pager_terminate_internal:
 *
 * Trigger the asynchronous termination of the memory object associated
 * with this pager.
 * When the memory object is terminated, there will be one more call
 * to memory_object_deallocate() (i.e. dyld_pager_deallocate())
 * to finish the clean up.
 *
 * "dyld_pager_lock" should not be held by the caller.
 */
static void
dyld_pager_terminate_internal(
	dyld_pager_t pager)
{
	assert(pager->dyld_is_ready);
	assert(!pager->dyld_is_mapped);
	assert(os_ref_get_count_raw(&pager->dyld_ref_count) == 1);

	if (pager->dyld_backing_object != VM_OBJECT_NULL) {
		vm_object_deallocate(pager->dyld_backing_object);
		pager->dyld_backing_object = VM_OBJECT_NULL;
	}
	/* trigger the destruction of the memory object */
	memory_object_destroy(pager->dyld_header.mo_control, 0);
}

/*
 * dyld_pager_deallocate_internal()
 *
 * Release a reference on this pager and free it when the last reference goes away.
 * Can be called with dyld_pager_lock held or not, but always returns
 * with it unlocked.
 */
static void
dyld_pager_deallocate_internal(
	dyld_pager_t   pager,
	bool           locked)
{
	os_ref_count_t ref_count;

	if (!locked) {
		lck_mtx_lock(&dyld_pager_lock);
	}

	/* drop a reference on this pager */
	ref_count = os_ref_release_locked_raw(&pager->dyld_ref_count, NULL);

	if (ref_count == 1) {
		/*
		 * Only this reference is left, which means that
		 * no one is really holding on to this pager anymore.
		 * Terminate it.
		 */
		dyld_pager_count--;
		/* the pager is all ours: no need for the lock now */
		lck_mtx_unlock(&dyld_pager_lock);
		dyld_pager_terminate_internal(pager);
	} else if (ref_count == 0) {
		/*
		 * Dropped all references;  the memory object has
		 * been terminated.  Do some final cleanup and release the
		 * pager structure.
		 */
		lck_mtx_unlock(&dyld_pager_lock);

		kfree_data(pager->dyld_link_info, pager->dyld_link_info_size);
		pager->dyld_link_info = NULL;

		if (pager->dyld_header.mo_control != MEMORY_OBJECT_CONTROL_NULL) {
			memory_object_control_deallocate(pager->dyld_header.mo_control);
			pager->dyld_header.mo_control = MEMORY_OBJECT_CONTROL_NULL;
		}
		kfree_type(struct dyld_pager, pager);
		pager = NULL;
	} else {
		/* there are still plenty of references:  keep going... */
		lck_mtx_unlock(&dyld_pager_lock);
	}

	/* caution: lock is not held on return... */
}

/*
 * dyld_pager_deallocate()
 *
 * Release a reference on this pager and free it when the last
 * reference goes away.
 */
static void
dyld_pager_deallocate(
	memory_object_t mem_obj)
{
	dyld_pager_t    pager;

	pager = dyld_pager_lookup(mem_obj);
	dyld_pager_deallocate_internal(pager, FALSE);
}

/*
 *
 */
static kern_return_t
dyld_pager_terminate(
#if !DEBUG
	__unused
#endif
	memory_object_t mem_obj)
{
	return KERN_SUCCESS;
}

/*
 * dyld_pager_map()
 *
 * This allows VM to let us, the EMM, know that this memory object
 * is currently mapped one or more times.  This is called by VM each time
 * the memory object gets mapped, but we only take one extra reference the
 * first time it is called.
 */
static kern_return_t
dyld_pager_map(
	memory_object_t         mem_obj,
	__unused vm_prot_t      prot)
{
	dyld_pager_t   pager;

	pager = dyld_pager_lookup(mem_obj);

	lck_mtx_lock(&dyld_pager_lock);
	assert(pager->dyld_is_ready);
	assert(os_ref_get_count_raw(&pager->dyld_ref_count) > 0); /* pager is alive */
	if (!pager->dyld_is_mapped) {
		pager->dyld_is_mapped = TRUE;
		os_ref_retain_locked_raw(&pager->dyld_ref_count, NULL);
	}
	lck_mtx_unlock(&dyld_pager_lock);

	return KERN_SUCCESS;
}

/*
 * dyld_pager_last_unmap()
 *
 * This is called by VM when this memory object is no longer mapped anywhere.
 */
static kern_return_t
dyld_pager_last_unmap(
	memory_object_t mem_obj)
{
	dyld_pager_t    pager;

	pager = dyld_pager_lookup(mem_obj);

	lck_mtx_lock(&dyld_pager_lock);
	if (pager->dyld_is_mapped) {
		/*
		 * All the mappings are gone, so let go of the one extra
		 * reference that represents all the mappings of this pager.
		 */
		pager->dyld_is_mapped = FALSE;
		dyld_pager_deallocate_internal(pager, TRUE);
		/* caution: deallocate_internal() released the lock ! */
	} else {
		lck_mtx_unlock(&dyld_pager_lock);
	}

	return KERN_SUCCESS;
}

static boolean_t
dyld_pager_backing_object(
	memory_object_t         mem_obj,
	memory_object_offset_t  offset,
	vm_object_t             *backing_object,
	vm_object_offset_t      *backing_offset)
{
	dyld_pager_t   pager;

	pager = dyld_pager_lookup(mem_obj);

	*backing_object = pager->dyld_backing_object;
	*backing_offset = offset;

	return TRUE;
}


/*
 * Convert from memory_object to dyld_pager.
 */
static dyld_pager_t
dyld_pager_lookup(
	memory_object_t  mem_obj)
{
	dyld_pager_t   pager;

	assert(mem_obj->mo_pager_ops == &dyld_pager_ops);
	pager = (dyld_pager_t)(uintptr_t) mem_obj;
	assert(os_ref_get_count_raw(&pager->dyld_ref_count) > 0);
	return pager;
}

/*
 * Create and return a pager for the given object with the
 * given slide information.
 */
static dyld_pager_t
dyld_pager_create(
#if !defined(HAS_APPLE_PAC)
	__unused
#endif /* defined(HAS_APPLE_PAC) */
	task_t            task,
	vm_object_t       backing_object,
	struct mwl_region *regions,
	uint32_t          region_cnt,
	void              *link_info,
	uint32_t          link_info_size)
{
	dyld_pager_t            pager;
	memory_object_control_t control;
	kern_return_t           kr;

	pager = kalloc_type(struct dyld_pager, Z_WAITOK);
	if (pager == NULL) {
		return NULL;
	}

	/*
	 * The vm_map call takes both named entry ports and raw memory
	 * objects in the same parameter.  We need to make sure that
	 * vm_map does not see this object as a named entry port.  So,
	 * we reserve the first word in the object for a fake ip_kotype
	 * setting - that will tell vm_map to use it as a memory object.
	 */
	pager->dyld_header.mo_ikot = IKOT_MEMORY_OBJECT;
	pager->dyld_header.mo_pager_ops = &dyld_pager_ops;
	pager->dyld_header.mo_control = MEMORY_OBJECT_CONTROL_NULL;

	pager->dyld_is_ready = FALSE;/* not ready until it has a "name" */
	/* existence reference for the caller */
	os_ref_init_count_raw(&pager->dyld_ref_count, NULL, 1);
	pager->dyld_is_mapped = FALSE;
	pager->dyld_backing_object = backing_object;
	pager->dyld_link_info = link_info;
	pager->dyld_link_info_size = link_info_size;
#if defined(HAS_APPLE_PAC)
	pager->dyld_a_key = (task->map && task->map->pmap && !task->map->pmap->disable_jop) ? task->jop_pid : 0;
#endif /* defined(HAS_APPLE_PAC) */

	/*
	 * Record the regions so the pager can find the offset from an address.
	 */
	pager->dyld_num_range = region_cnt;
	for (uint32_t r = 0; r < region_cnt; ++r) {
		pager->dyld_file_offset[r] = regions[r].mwlr_file_offset;
		pager->dyld_address[r] = regions[r].mwlr_address;
		pager->dyld_size[r] = regions[r].mwlr_size;
	}

	vm_object_reference(backing_object);

	lck_mtx_lock(&dyld_pager_lock);
	dyld_pager_count++;
	if (dyld_pager_count > dyld_pager_count_max) {
		dyld_pager_count_max = dyld_pager_count;
	}
	lck_mtx_unlock(&dyld_pager_lock);

	kr = memory_object_create_named((memory_object_t) pager, 0, &control);
	assert(kr == KERN_SUCCESS);

	memory_object_mark_trusted(control);

	lck_mtx_lock(&dyld_pager_lock);
	/* the new pager is now ready to be used */
	pager->dyld_is_ready = TRUE;
	lck_mtx_unlock(&dyld_pager_lock);

	/* wakeup anyone waiting for this pager to be ready */
	thread_wakeup(&pager->dyld_is_ready);

	return pager;
}

/*
 * dyld_pager_setup()
 *
 * Provide the caller with a memory object backed by the provided
 * "backing_object" VM object.
 */
static memory_object_t
dyld_pager_setup(
	task_t            task,
	vm_object_t       backing_object,
	struct mwl_region *regions,
	uint32_t          region_cnt,
	void              *link_info,
	uint32_t          link_info_size)
{
	dyld_pager_t      pager;

	/* create new pager */
	pager = dyld_pager_create(task, backing_object, regions, region_cnt, link_info, link_info_size);
	if (pager == NULL) {
		/* could not create a new pager */
		return MEMORY_OBJECT_NULL;
	}

	lck_mtx_lock(&dyld_pager_lock);
	while (!pager->dyld_is_ready) {
		lck_mtx_sleep(&dyld_pager_lock,
		    LCK_SLEEP_DEFAULT,
		    &pager->dyld_is_ready,
		    THREAD_UNINT);
	}
	lck_mtx_unlock(&dyld_pager_lock);

	return (memory_object_t) pager;
}

/*
 * Set up regions which use a special pager to apply dyld fixups.
 *
 * The arguments to this function are mostly just used as input.
 * Except for the link_info! That is saved off in the pager that
 * gets created, so shouldn't be free'd by the caller, if KERN_SUCCES.
 */
kern_return_t
vm_map_with_linking(
	task_t                  task,
	struct mwl_region       *regions,
	uint32_t                region_cnt,
	void                    *link_info,
	uint32_t                link_info_size,
	memory_object_control_t file_control)
{
	vm_map_t                map = task->map;
	vm_object_t             object = VM_OBJECT_NULL;
	memory_object_t         pager = MEMORY_OBJECT_NULL;
	uint32_t                r;
	struct mwl_region       *rp;
	vm_map_address_t        map_addr;
	int                     vm_flags;
	vm_map_kernel_flags_t   vmk_flags;
	kern_return_t           kr = KERN_SUCCESS;

	object = memory_object_control_to_vm_object(file_control);
	if (object == VM_OBJECT_NULL || object->internal) {
		printf("%s no object for file_control\n", __func__);
		object = VM_OBJECT_NULL;
		kr = KERN_INVALID_ADDRESS;
		goto done;
	}

	/* create a pager */
	pager = dyld_pager_setup(task, object, regions, region_cnt, link_info, link_info_size);
	if (pager == MEMORY_OBJECT_NULL) {
		kr = KERN_RESOURCE_SHORTAGE;
		goto done;
	}

	for (r = 0; r < region_cnt; ++r) {
		rp = &regions[r];

		/* map that pager over the portion of the mapping that needs sliding */
		vm_flags = VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE;
		vmk_flags = VM_MAP_KERNEL_FLAGS_NONE;
		vmk_flags.vmkf_overwrite_immutable = TRUE;
		map_addr = (vm_map_address_t)rp->mwlr_address;
		kr = vm_map_enter_mem_object(map,
		    &map_addr,
		    rp->mwlr_size,
		    (mach_vm_offset_t) 0,
		    vm_flags,
		    vmk_flags,
		    VM_KERN_MEMORY_NONE,
		    (ipc_port_t)(uintptr_t)pager,
		    rp->mwlr_file_offset,
		    TRUE,       /* copy == TRUE, as this is MAP_PRIVATE so COW may happen */
		    rp->mwlr_protections,
		    rp->mwlr_protections,
		    VM_INHERIT_DEFAULT);
		if (kr != KERN_SUCCESS) {
			/* no need to clean up earlier regions, this will be process fatal */
			goto done;
		}
	}

	/* success! */
	kr = KERN_SUCCESS;

done:

	if (pager != MEMORY_OBJECT_NULL) {
		/*
		 * Release the pager reference obtained by dyld_pager_setup().
		 * The mapping, if it succeeded, is now holding a reference on the memory object.
		 */
		memory_object_deallocate(pager);
		pager = MEMORY_OBJECT_NULL;
	}
	return kr;
}
