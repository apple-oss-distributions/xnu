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

#ifdef CONFIG_KDP_INTERACTIVE_DEBUGGING

#include <mach/mach_types.h>
#include <IOKit/IOTypes.h>
#include <kdp/output_stages/output_stages.h>
#include <kdp/kdp_core.h>
#include <kdp/processor_core.h>

struct buffer_stage_data {
	size_t total_buffer_size;
	size_t current_size;
	char   buffer[];
};

static void
buffer_stage_reset(struct kdp_output_stage *stage)
{
	struct buffer_stage_data *data = (struct buffer_stage_data *) stage->kos_data;

	data->current_size = 0;
	stage->kos_bypass = false;
	stage->kos_bytes_written = 0;
}

static kern_return_t
buffer_stage_flush(struct kdp_output_stage *stage)
{
	kern_return_t err = KERN_SUCCESS;
	struct buffer_stage_data *data = (struct buffer_stage_data *) stage->kos_data;
	struct kdp_output_stage *next_stage = STAILQ_NEXT(stage, kos_next);

	err = next_stage->kos_funcs.kosf_outproc(next_stage, KDP_DATA, NULL, data->current_size, data->buffer);

	if (KERN_SUCCESS != err) {
		return err;
	} else {
		stage->kos_bytes_written += data->current_size;
		data->current_size = 0;
	}

	return err;
}

static kern_return_t
buffer_stage_outproc(struct kdp_output_stage *stage, unsigned int request,
    char *corename, uint64_t length, void * panic_data)
{
	kern_return_t err = KERN_SUCCESS;
	struct buffer_stage_data *data = (struct buffer_stage_data *) stage->kos_data;
	struct kdp_output_stage  *next_stage = STAILQ_NEXT(stage, kos_next);

	boolean_t should_flush = FALSE;

	assert(next_stage != NULL);

	if ((data->current_size && (request == KDP_SEEK || request == KDP_FLUSH || request == KDP_EOF))
	    || (request == KDP_DATA && length == 0 && !panic_data)) {
		should_flush = TRUE;
	}

	if (should_flush) {
		err = buffer_stage_flush(stage);
		if (KERN_SUCCESS != err) {
			kern_coredump_log(NULL, "buffer_stage_outproc (during flush) returned 0x%x\n", err);
			return err;
		}
	}

	if (request == KDP_WRQ || request == KDP_SEEK || request == KDP_EOF) {
		err = next_stage->kos_funcs.kosf_outproc(next_stage, request, corename, length, panic_data);

		if (KERN_SUCCESS != err) {
			kern_coredump_log(NULL, "buffer_stage_outproc (during forwarding) returned 0x%x\n", err);
			return err;
		}
	} else if (request == KDP_DATA) {
		while (length != 0) {
			size_t bytes_to_copy = data->total_buffer_size - data->current_size;

			if (length < bytes_to_copy) {
				/* Safe to cast to size_t here since we just checked that 'length' is less
				 * than a size_t value. */
				bytes_to_copy = (size_t) length;
			}

			bcopy(panic_data, (void *)((uintptr_t)data->buffer + data->current_size), bytes_to_copy);

			data->current_size += bytes_to_copy;
			length -= bytes_to_copy;
			panic_data = (void *) ((uintptr_t) panic_data + bytes_to_copy);

			if (data->current_size == data->total_buffer_size) {
				err = buffer_stage_flush(stage);
				if (KERN_SUCCESS != err) {
					kern_coredump_log(NULL, "buffer_stage_outproc (during flush) returned 0x%x\n", err);
					return err;
				}
			}
		}
	}

	return err;
}

static void
buffer_stage_free(struct kdp_output_stage *stage)
{
	kmem_free(kernel_map, (vm_offset_t) stage->kos_data, stage->kos_data_size);

	stage->kos_data = NULL;
	stage->kos_data_size = 0;
	stage->kos_initialized = false;
}

kern_return_t
buffer_stage_initialize(struct kdp_output_stage *stage, size_t buffer_size)
{
	kern_return_t ret = KERN_SUCCESS;
	struct buffer_stage_data *data = NULL;

	assert(stage != NULL);
	assert(stage->kos_initialized == false);
	assert(stage->kos_data == NULL);
	assert(buffer_size != 0);

	stage->kos_data_size = sizeof(struct buffer_stage_data) + buffer_size;
	ret = kmem_alloc(kernel_map, (vm_offset_t*) &stage->kos_data, stage->kos_data_size,
	    KMA_DATA, VM_KERN_MEMORY_DIAG);
	if (KERN_SUCCESS != ret) {
		printf("buffer_stage_initialize failed to allocate memory. Error 0x%x\n", ret);
		return ret;
	}

	data = (struct buffer_stage_data *) stage->kos_data;
	data->total_buffer_size = buffer_size;
	data->current_size = 0;

	stage->kos_funcs.kosf_reset = buffer_stage_reset;
	stage->kos_funcs.kosf_outproc = buffer_stage_outproc;
	stage->kos_funcs.kosf_free = buffer_stage_free;

	stage->kos_initialized = true;

	return KERN_SUCCESS;
}

#endif /* CONFIG_KDP_INTERACTIVE_DEBUGGING */
