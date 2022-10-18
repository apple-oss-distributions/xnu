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

#if CONFIG_KDP_INTERACTIVE_DEBUGGING && defined(__arm64__)

#include <IOKit/IOTypes.h>
#include <kdp/output_stages/output_stages.h>
#include <kdp/kdp_core.h>
#include <kdp/processor_core.h>
#include <mach/mach_types.h>
#include <mach/vm_param.h>
#include <mach/vm_types.h>
#include <vm/memory_types.h>
#include <vm/pmap.h>

static bool
is_normal_memory(uint64_t phys)
{
	unsigned int attr = pmap_cache_attributes((ppnum_t)(phys >> PAGE_SHIFT));
	/*
	 * Note that VM_WIMG_DEFAULT doesn't cover all normal memory, however it is a good enough
	 * heuristic for our purposes. It also means we won't have to update this check when new
	 * memory types are inevitably added.
	 */
	return (attr & VM_WIMG_MASK) == VM_WIMG_DEFAULT;
}

static void
memory_backing_aware_buffer_stage_reset(__unused struct kdp_output_stage *stage)
{
}

static kern_return_t
memory_backing_aware_buffer_stage_outproc(struct kdp_output_stage *stage, unsigned int request,
    char *corename, uint64_t length, void * panic_data)
{
	kern_return_t err = KERN_SUCCESS;
	void *buffer = stage->kos_data;
	struct kdp_output_stage  *next_stage = STAILQ_NEXT(stage, kos_next);

	assert(next_stage != NULL);

	if ((request != KDP_DATA) || !panic_data) {
		/* nothing to be buffered, so call onto the next stage with the same request */
		err = next_stage->kos_funcs.kosf_outproc(next_stage, request, corename, length, panic_data);
		if (KERN_SUCCESS != err) {
			kern_coredump_log(NULL, "%s (passing along request) returned 0x%x\n", __func__, err);
			return err;
		}

		return err;
	}

	while (length) {
		pmap_paddr_t phys = kvtophys((vm_offset_t)panic_data);
		if (!phys) {
			kern_coredump_log(NULL, "%s kvtophys() for address %p returned NULL\n", __func__, panic_data);
			return KERN_MEMORY_ERROR;
		}

		size_t bytes_in_page = MIN(length, PAGE_SIZE - ((vm_offset_t)panic_data % PAGE_SIZE));
		if (is_normal_memory(phys)) {
			err = next_stage->kos_funcs.kosf_outproc(next_stage, KDP_DATA, corename, bytes_in_page, panic_data);
			if (KERN_SUCCESS != err) {
				kern_coredump_log(NULL, "%s next stage output failed\n", __func__);
				return err;
			}
		} else {
			/*
			 * If this is not normal memory, be pessimistic and assume we have to
			 * do aligned loads, we can't just do a memcpy (which can perform
			 * 128-bit loads and unaligned accesses). We don't know if the data
			 * pointer or length are aligned, so we do a bytewise copy.
			 */
			volatile const uint8_t *src = panic_data;
			volatile uint8_t *dst = buffer;
			for (size_t i = 0; i < bytes_in_page; i++) {
				dst[i] = src[i];
			}

			err = next_stage->kos_funcs.kosf_outproc(next_stage, KDP_DATA, corename, bytes_in_page, buffer);
			if (KERN_SUCCESS != err) {
				kern_coredump_log(NULL, "%s next stage output failed\n", __func__);
				return err;
			}
		}

		length -= bytes_in_page;
		panic_data = (void *)((uintptr_t)panic_data + bytes_in_page);
	}

	return err;
}

static void
memory_backing_aware_buffer_stage_free(struct kdp_output_stage *stage)
{
	kmem_free(kernel_map, (vm_offset_t) stage->kos_data, stage->kos_data_size);

	stage->kos_data = NULL;
	stage->kos_data_size = 0;
	stage->kos_initialized = false;
}

kern_return_t
memory_backing_aware_buffer_stage_initialize(struct kdp_output_stage *stage)
{
	kern_return_t ret = KERN_SUCCESS;

	assert(stage != NULL);
	assert(stage->kos_initialized == false);
	assert(stage->kos_data == NULL);

	stage->kos_data_size = PAGE_SIZE;
	ret = kmem_alloc(kernel_map, (vm_offset_t*) &stage->kos_data, stage->kos_data_size,
	    KMA_DATA, VM_KERN_MEMORY_DIAG);
	if (KERN_SUCCESS != ret) {
		printf("%s failed to allocate memory. Error 0x%x\n", __func__, ret);
		return ret;
	}

	stage->kos_funcs.kosf_reset = memory_backing_aware_buffer_stage_reset;
	stage->kos_funcs.kosf_outproc = memory_backing_aware_buffer_stage_outproc;
	stage->kos_funcs.kosf_free = memory_backing_aware_buffer_stage_free;

	stage->kos_initialized = true;

	return KERN_SUCCESS;
}

#endif /* CONFIG_KDP_INTERACTIVE_DEBUGGING && defined(__arm64__) */
