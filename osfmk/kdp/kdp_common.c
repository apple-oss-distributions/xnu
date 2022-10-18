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


#include <kdp/kdp_common.h>
#include <kdp/kdp_dyld.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <vm/vm_pageout.h>
#include <vm/vm_fault.h>
#include <vm/vm_shared_region.h>
#include <vm/vm_compressor.h>
#include <sys/errno.h>

extern unsigned int not_in_kdp;
extern void bcopy_phys(addr64_t, addr64_t, vm_size_t);
extern addr64_t kdp_vtophys(pmap_t pmap, addr64_t va);

/*
 * Sets the appropriate page mask and size to use for dealing with pages --
 * it's important that this is a "min" of page size to account for both K16/U4
 * (Rosetta) and K4/U16 (armv7k) environments.
 */
size_t
kdp_vm_map_get_page_size(vm_map_t map, size_t *effective_page_mask)
{
	/* must be called from debugger context */
	assert(!not_in_kdp);

	if (VM_MAP_PAGE_SHIFT(map) < PAGE_SHIFT) {
		if (effective_page_mask) {
			*effective_page_mask = VM_MAP_PAGE_MASK(map);
		}
		return VM_MAP_PAGE_SIZE(map);
	} else {
		if (effective_page_mask) {
			*effective_page_mask = PAGE_MASK;
		}
		return PAGE_SIZE;
	}
}

void
kdp_memcpy(void *dst, const void *src, size_t len)
{
	/* must be called from debugger context */
	assert(!not_in_kdp);

#if defined(__arm64__)
	/* Identify if destination buffer is in panic storage area */
	if (((vm_offset_t)dst >= gPanicBase) && ((vm_offset_t)dst < (gPanicBase + gPanicSize))) {
		/* Copy over bytes individually to prevent unaligned access */
		uint8_t *dest_bytes = (uint8_t *)dst;
		const uint8_t *src_bytes = (const uint8_t *)src;
		for (size_t i = 0; i < len; i++) {
			dest_bytes[i] = src_bytes[i];
		}
	} else
#endif
	memcpy(dst, src, len);
}

size_t
kdp_strlcpy(char *dst, const char *src, size_t maxlen)
{
	/* must be called from debugger context */
	assert(!not_in_kdp);

	const size_t srclen = strlen(src);

	if (srclen < maxlen) {
		kdp_memcpy(dst, src, srclen + 1);
	} else if (maxlen != 0) {
		kdp_memcpy(dst, src, maxlen - 1);
		dst[maxlen - 1] = '\0';
	}

	return srclen;
}

kern_return_t
kdp_traverse_mappings(
	task_t task,
	kdp_fault_flags_t fault_flags,
	kdp_traverse_mappings_flags_t traverse_mappings_flags,
	kdp_traverse_mappings_callback callback,
	void * context)
{
	vm_map_t map = task->map;
	vm_map_entry_t entry;
	vm_offset_t vcur;
	kern_return_t ret = KERN_SUCCESS;

	/* must be called from debugger context */
	assert(!not_in_kdp);

	size_t effective_page_mask;
	size_t task_page_size = kdp_vm_map_get_page_size(map, &effective_page_mask);

	// Iterate vm map
	for (entry = vm_map_first_entry(map); ret == KERN_SUCCESS && entry != NULL && entry != vm_map_to_entry(map); entry = entry->vme_next) {
		// Found a region, iterate over pages in the region
		for (vcur = entry->vme_start; ret == KERN_SUCCESS && vcur < entry->vme_end; vcur += task_page_size) {
			vm_offset_t vphys = kdp_find_phys(map, vcur, fault_flags, NULL);
			if (vphys) {
				if (traverse_mappings_flags & KDP_TRAVERSE_MAPPINGS_FLAGS_PHYSICAL) {
					ret = callback(vphys, vphys + task_page_size, context);
				} else {
					ret = callback(vcur, vcur + task_page_size, context);
				}
			}
		}
	}

	return ret;
}

vm_offset_t
kdp_find_phys(vm_map_t map, vm_offset_t target_addr, kdp_fault_flags_t fault_flags, struct kdp_fault_result * fault_results)
{
	vm_offset_t cur_phys_addr;

	/* must be called from debugger context */
	assert(!not_in_kdp);

	if (map == VM_MAP_NULL) {
		return 0;
	}

	cur_phys_addr = (vm_offset_t)kdp_vtophys(map->pmap, target_addr);
	if (!pmap_valid_page((ppnum_t) atop(cur_phys_addr))) {
		if (!(fault_flags & KDP_FAULT_FLAGS_ENABLE_FAULTING)) {
			if (fault_results) {
				fault_results->flags |= KDP_FAULT_RESULT_PAGED_OUT;
			}

			return 0;
		}

		/*
		 * The pmap doesn't have a valid page so we start at the top level
		 * vm map and try a lightweight fault. Update fault path usage stats.
		 */
		uint64_t fault_start_time = mach_absolute_time();
		uint64_t fault_end_time;
		size_t effective_page_mask;
		(void)kdp_vm_map_get_page_size(map, &effective_page_mask);

		cur_phys_addr = kdp_lightweight_fault(map, (target_addr & ~effective_page_mask));
		fault_end_time = mach_absolute_time();

		if (fault_results) {
			fault_results->time_spent_faulting += fault_end_time - fault_start_time;
		}

		cur_phys_addr += (target_addr & effective_page_mask);

		if (!pmap_valid_page((ppnum_t) atop(cur_phys_addr))) {
			if (fault_results) {
				fault_results->flags |= (KDP_FAULT_RESULT_TRIED_FAULT | KDP_FAULT_RESULT_PAGED_OUT);
			}

			return 0;
		}

		if (fault_results) {
			fault_results->flags |= KDP_FAULT_RESULT_FAULTED_IN;
		}
	} else {
		/*
		 * This check is done in kdp_lightweight_fault for the fault path.
		 */
		unsigned int cur_wimg_bits = pmap_cache_attributes((ppnum_t) atop(cur_phys_addr));

		if ((cur_wimg_bits & VM_WIMG_MASK) != VM_WIMG_DEFAULT) {
			return 0;
		}
	}

	return cur_phys_addr;
}

int
kdp_generic_copyin(vm_map_t map, uint64_t uaddr, void *dest, size_t size, kdp_fault_flags_t fault_flags, find_phys_fn_t find_phys_fn, void *context)
{
	size_t rem = size;
	char *kvaddr = dest;
	size_t effective_page_mask;
	size_t effective_page_size = kdp_vm_map_get_page_size(map, &effective_page_mask);

	/* must be called from debugger context */
	assert(!not_in_kdp);

#if defined(__arm64__)
	/* Identify if destination buffer is in panic storage area */
	if (!not_in_kdp && ((vm_offset_t)dest >= gPanicBase) && ((vm_offset_t)dest < (gPanicBase + gPanicSize))) {
		if (((vm_offset_t)dest + size) > (gPanicBase + gPanicSize)) {
			return EINVAL;
		}
	}
#endif

	while (rem) {
		uint64_t phys_src = (*find_phys_fn)(map, (vm_offset_t)uaddr, fault_flags, context);
		uint64_t phys_dest = kvtophys((vm_offset_t)kvaddr);
		uint64_t src_rem = effective_page_size - (phys_src & effective_page_mask);
		uint64_t dst_rem = PAGE_SIZE - (phys_dest & PAGE_MASK);
		size_t cur_size = (uint32_t) MIN(src_rem, dst_rem);
		cur_size = MIN(cur_size, rem);

		if (phys_src && phys_dest) {
#if defined(__arm64__)
			/*
			 * On arm devices the panic buffer is mapped as device memory and doesn't allow
			 * unaligned accesses. To prevent these, we copy over bytes individually here.
			 */
			if (!not_in_kdp) {
				kdp_memcpy(kvaddr, (const void *)phystokv((pmap_paddr_t)phys_src), cur_size);
			} else
#endif /* defined(__arm64__) */
			bcopy_phys(phys_src, phys_dest, cur_size);
		} else {
			break;
		}

		uaddr += cur_size;
		kvaddr += cur_size;
		rem -= cur_size;
	}

	return 0;
}

int
kdp_generic_copyin_word(
	task_t task, uint64_t addr, uint64_t *result, kdp_fault_flags_t fault_flags, find_phys_fn_t find_phys_fn, void *context)
{
	/* must be called from debugger context */
	assert(!not_in_kdp);

	if (task_has_64Bit_addr(task)) {
		return kdp_generic_copyin(task->map, addr, result, sizeof(uint64_t), fault_flags, find_phys_fn, context);
	} else {
		uint32_t buf;
		int r = kdp_generic_copyin(task->map, addr, &buf, sizeof(uint32_t), fault_flags, find_phys_fn, context);
		if (r == KERN_SUCCESS) {
			*result = buf;
		}
		return r;
	}
}

static int
kdp_generic_copyin_string_slowpath(
	task_t task, uint64_t addr, char *buf, int buf_sz, kdp_fault_flags_t fault_flags, find_phys_fn_t find_phys_fn, void *context)
{
	int i;
	uint64_t validated = 0, valid_from;
	uint64_t phys_src, phys_dest;
	vm_map_t map = task->map;
	size_t effective_page_mask;
	size_t effective_page_size = kdp_vm_map_get_page_size(map, &effective_page_mask);

	/* must be called from debugger context */
	assert(!not_in_kdp);

	for (i = 0; i < buf_sz; i++) {
		if (validated == 0) {
			valid_from = i;
			phys_src = (*find_phys_fn)(map, (vm_offset_t)(addr + i), fault_flags, context);
			phys_dest = kvtophys((vm_offset_t)&buf[i]);
			uint64_t src_rem = effective_page_size - (phys_src & effective_page_mask);
			uint64_t dst_rem = PAGE_SIZE - (phys_dest & PAGE_MASK);
			if (phys_src && phys_dest) {
				validated = MIN(src_rem, dst_rem);
				if (validated) {
					bcopy_phys(phys_src, phys_dest, 1);
					validated--;
				} else {
					return 0;
				}
			} else {
				return 0;
			}
		} else {
			bcopy_phys(phys_src + (i - valid_from), phys_dest + (i - valid_from), 1);
			validated--;
		}

		if (buf[i] == '\0') {
			return i + 1;
		}
	}

	/* ran out of space */
	return -1;
}

int
kdp_generic_copyin_string(
	task_t task, uint64_t addr, char *buf, int buf_sz, kdp_fault_flags_t fault_flags, find_phys_fn_t find_phys_fn, void *context)
{
	/* try to opportunistically copyin 32 bytes, most strings should fit */
	char optbuffer[32] = {0};
	int res;

	/* must be called from debugger context */
	assert(!not_in_kdp);

	res = kdp_generic_copyin(task->map, addr, optbuffer, sizeof(optbuffer), fault_flags, find_phys_fn, context);
	if (res != KERN_SUCCESS || strnlen(optbuffer, sizeof(optbuffer)) == sizeof(optbuffer)) {
		/* try the slowpath */
		return kdp_generic_copyin_string_slowpath(task, addr, buf, buf_sz, fault_flags, find_phys_fn, context);
	}

	/* success */
	return (int) strlcpy(buf, optbuffer, buf_sz) + 1;
}

static int
kdp_copyin(vm_map_t map, uint64_t uaddr, void *dest, size_t size, kdp_fault_flags_t fault_flags)
{
	return kdp_generic_copyin(map, uaddr, dest, size, fault_flags, (find_phys_fn_t)kdp_find_phys, NULL);
}

kern_return_t
kdp_task_dyld_info(task_t task, kdp_fault_flags_t fault_flags, uint64_t * dyld_load_address, uuid_t dyld_uuid, size_t * task_page_size)
{
	uint32_t uuid_info_count = 0;
	mach_vm_address_t uuid_info_addr = 0;
	mach_vm_address_t dyld_load_addr = 0;
	boolean_t task_64bit_addr = task_has_64Bit_addr(task);

	/* must be called from debugger context */
	assert(!not_in_kdp);

	if (dyld_uuid == NULL || dyld_load_address == NULL || task_page_size == NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	*task_page_size = kdp_vm_map_get_page_size(task->map, NULL);

	if (task_64bit_addr) {
		struct user64_dyld_all_image_infos task_image_infos;
		if (kdp_copyin(task->map, task->all_image_info_addr, &task_image_infos,
		    sizeof(struct user64_dyld_all_image_infos), fault_flags) == KERN_SUCCESS) {
			uuid_info_count = (uint32_t)task_image_infos.uuidArrayCount;
			uuid_info_addr = task_image_infos.uuidArray;
			dyld_load_addr = task_image_infos.dyldImageLoadAddress;
		}
	} else {
		struct user32_dyld_all_image_infos task_image_infos;
		if (kdp_copyin(task->map, task->all_image_info_addr, &task_image_infos,
		    sizeof(struct user32_dyld_all_image_infos), fault_flags) == KERN_SUCCESS) {
			uuid_info_count = (uint32_t)task_image_infos.uuidArrayCount;
			uuid_info_addr = task_image_infos.uuidArray;
			dyld_load_addr = task_image_infos.dyldImageLoadAddress;
		}
	}

	if (uuid_info_count == 0 || uuid_info_addr == 0 || dyld_load_addr == 0) {
		return KERN_NOT_FOUND;
	}

	// Find the UUID of dyld
	for (size_t i = 0; i < uuid_info_count; i++) {
		if (task_64bit_addr) {
			struct user64_dyld_uuid_info uuid_info;
			if (kdp_copyin(task->map, uuid_info_addr + (i * sizeof(struct user64_dyld_uuid_info)), &uuid_info, sizeof(struct user64_dyld_uuid_info), fault_flags) == KERN_SUCCESS) {
				if (uuid_info.imageLoadAddress == dyld_load_addr) {
					uuid_copy(dyld_uuid, uuid_info.imageUUID);
					*dyld_load_address = dyld_load_addr;
					return KERN_SUCCESS;
				}
			}
		} else {
			struct user32_dyld_uuid_info uuid_info;
			if (kdp_copyin(task->map, uuid_info_addr + (i * sizeof(struct user32_dyld_uuid_info)), &uuid_info, sizeof(struct user32_dyld_uuid_info), fault_flags) == KERN_SUCCESS) {
				if (uuid_info.imageLoadAddress == dyld_load_addr) {
					uuid_copy(dyld_uuid, uuid_info.imageUUID);
					*dyld_load_address = dyld_load_addr;
					return KERN_SUCCESS;
				}
			}
		}
	}

	return KERN_NOT_FOUND;
}
