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
#include <machine/param.h>
#include <libkern/apple_encrypted_archive/apple_encrypted_archive.h>

struct aea_stage_data {
	bool     encryption_open;
	uint64_t starting_corefile_offset;;
	uint64_t current_corefile_offset;
	size_t   state_size;
	char     state[];
};

static ssize_t
aea_write_callback(void *context, const void *buffer, size_t length, off_t offset)
{
	kern_return_t            err = KERN_SUCCESS;
	struct kdp_output_stage *stage = (struct kdp_output_stage *) context;
	struct kdp_output_stage *next_stage = STAILQ_NEXT(stage, kos_next);
	struct aea_stage_data   *stage_data = (struct aea_stage_data *) stage->kos_data;
	uint64_t absolute_corefile_offset = stage_data->starting_corefile_offset + offset;

	err = disk_stage_write(next_stage, absolute_corefile_offset, length, buffer);

	if (KERN_SUCCESS != err) {
		kern_coredump_log(NULL, "(aea_write_callback) next stage outproc returned 0x%x\n", err);
		return -1;
	}

	stage_data->current_corefile_offset = absolute_corefile_offset + length;
	if (offset + length > stage->kos_bytes_written) {
		stage->kos_bytes_written = offset + length;
		next_stage->kos_bytes_written = stage->kos_bytes_written;
	}

	return length;
}

static ssize_t
aea_read_callback(void *context, void *buffer, size_t length, off_t offset)
{
	kern_return_t            err = KERN_SUCCESS;
	struct kdp_output_stage *stage = (struct kdp_output_stage *) context;
	struct kdp_output_stage *next_stage = STAILQ_NEXT(stage, kos_next);
	struct aea_stage_data   *stage_data = (struct aea_stage_data *) stage->kos_data;
	uint64_t absolute_corefile_offset = stage_data->starting_corefile_offset + offset;

	err = disk_stage_read(next_stage, absolute_corefile_offset, length, buffer);
	if (KERN_SUCCESS != err) {
		kern_coredump_log(NULL, "(aea_read_callback) next stage read proc returned 0x%x\n", err);
		return -1;
	}

	stage_data->current_corefile_offset = absolute_corefile_offset + length;

	return length;
}

static void
aea_stage_reset(struct kdp_output_stage *stage)
{
	int aea_ret = 0;
	struct aea_stage_data *stage_data = (struct aea_stage_data *) stage->kos_data;

	if (stage_data->encryption_open) {
		aea_ret = apple_encrypted_archive->aea_close(stage_data->state, stage_data->state_size);
		if (aea_ret != 0) {
			kern_coredump_log(NULL, "(aea_stage_reset) aea_close() returned %d\n", aea_ret);
			// TODO return the error?
		} else {
			stage_data->encryption_open = false;
		}
	}

	stage->kos_bypass = false;
	stage->kos_bytes_written = 0;
}

static kern_return_t
aea_stage_outproc(struct kdp_output_stage *stage, unsigned int request,
    __unused char *corename, uint64_t length, void *panic_data)
{
	kern_return_t            err = KERN_SUCCESS;
	int                      aea_ret = 0;
	struct aea_stage_data   *stage_data = (struct aea_stage_data *) stage->kos_data;
	struct kdp_output_stage *next_stage = STAILQ_NEXT(stage, kos_next);
	size_t                   chunk = 0;

	assert(next_stage != NULL);

	switch (request) {
	case KDP_SEEK:
		stage->kos_bypass = true;
		if (stage_data->encryption_open) {
			aea_ret = apple_encrypted_archive->aea_close(stage_data->state, stage_data->state_size);
			if (aea_ret != 0) {
				kern_coredump_log(NULL, "(aea_stage_outproc) aea_close() returned %d\n", aea_ret);
				err = KERN_FAILURE;
			} else {
				stage_data->encryption_open = false;
			}
		}
		if (KERN_SUCCESS == err) {
			err = next_stage->kos_funcs.kosf_outproc(next_stage, request, corename, length, panic_data);
		}
		if (KERN_SUCCESS == err) {
			stage_data->starting_corefile_offset = *((uint64_t *) panic_data);
			stage_data->current_corefile_offset = stage_data->starting_corefile_offset;
		}
		break;
	case KDP_DATA:
		if (!stage->kos_bypass) {
			if (!length && !panic_data) {
				// Flush
				if (stage_data->encryption_open) {
					aea_ret = apple_encrypted_archive->aea_close(stage_data->state, stage_data->state_size);
					if (aea_ret != 0) {
						kern_coredump_log(NULL, "(aea_stage_outproc) aea_close() returned %d\n", aea_ret);
						err = KERN_FAILURE;
					} else {
						stage_data->encryption_open = false;
					}
				}
			} else {
				if (stage_data->encryption_open == false) {
					aea_ret = apple_encrypted_archive->aea_open(stage_data->state, stage_data->state_size, (void *) stage, aea_write_callback, aea_read_callback);
					if (aea_ret != 0) {
						kern_coredump_log(NULL, "(aea_stage_outproc) aea_open() returned %d\n", aea_ret);
						err = KERN_FAILURE;
					} else {
						stage_data->encryption_open = true;
					}
				}
				if (KERN_SUCCESS == err) {
					do{
						ssize_t write_result;

						if (length <= UINT32_MAX) {
							chunk = (size_t) length;
						} else {
							chunk = UINT32_MAX;
						}
						write_result = apple_encrypted_archive->aea_write(stage_data->state, stage_data->state_size, panic_data, chunk);
						if (write_result != chunk) {
							kern_coredump_log(NULL, "(aea_stage_outproc) aea_write() returned %zd\n", write_result);
							err = KERN_FAILURE;
						}

						length -= chunk;

						if (panic_data) {
							panic_data = (void *) (((uintptr_t) panic_data) + chunk);
						}
					} while (length && (KERN_SUCCESS == err));
				}
			}
		} else {
			err = next_stage->kos_funcs.kosf_outproc(next_stage, request, corename, length, panic_data);
		}
		break;
	case KDP_WRQ:
	/* Fall-through */
	case KDP_FLUSH:
	/* Fall-through */
	case KDP_EOF:
		err = next_stage->kos_funcs.kosf_outproc(next_stage, request, corename, length, panic_data);
		break;
	default:
		break;
	}

	return err;
}

static void
aea_stage_free(struct kdp_output_stage *stage)
{
	kmem_free(kernel_map, (vm_offset_t) stage->kos_data, stage->kos_data_size);

	stage->kos_data = NULL;
	stage->kos_data_size = 0;
	stage->kos_initialized = false;
}

kern_return_t
aea_stage_initialize(struct kdp_output_stage *stage, const void *recipient_public_key, size_t recipient_public_key_size)
{
	kern_return_t ret = KERN_SUCCESS;
	int aea_ret = 0;
	struct aea_stage_data *data = NULL;
	size_t state_size = 0;

	assert(apple_encrypted_archive != NULL);
	assert(stage != NULL);
	assert(stage->kos_initialized == false);
	assert(stage->kos_data == NULL);
	assert(recipient_public_key != NULL);
	assert(recipient_public_key_size != 0);

	state_size = apple_encrypted_archive->aea_get_state_size();
	if (0 == state_size) {
		printf("AEA kext returned an error while calculating state size.");
		ret = KERN_FAILURE;
		return ret;
	}
	stage->kos_data_size = sizeof(struct aea_stage_data) + state_size;
	ret = kmem_alloc(kernel_map, (vm_offset_t*) &stage->kos_data, stage->kos_data_size,
	    KMA_DATA, VM_KERN_MEMORY_DIAG);
	if (KERN_SUCCESS != ret) {
		printf("Failed to allocate memory (%zu bytes) for the AEA stage. Error 0x%x\n", stage->kos_data_size, ret);
		return ret;
	}

	data = (struct aea_stage_data *) stage->kos_data;
	data->encryption_open = false;
	data->starting_corefile_offset = 0;
	data->current_corefile_offset = 0;
	data->state_size = state_size;

	aea_ret = apple_encrypted_archive->aea_initialize_state(data->state, data->state_size, (const uint8_t *)recipient_public_key, recipient_public_key_size);
	if (aea_ret != 0) {
		printf("WARNING: Coredump encryption failed to initialize. aea_initialize_state() returned %d\n", aea_ret);
		aea_stage_free(stage);
		return KERN_FAILURE;
	}

	stage->kos_funcs.kosf_reset = aea_stage_reset;
	stage->kos_funcs.kosf_outproc = aea_stage_outproc;
	stage->kos_funcs.kosf_free = aea_stage_free;

	stage->kos_initialized = true;

	return ret;
}

static void
aea_availability_callback(void)
{
	kern_return_t ret = kdp_core_handle_encryption_available();
	if (KERN_SUCCESS != ret) {
		printf("(aea_availability_callback) Failed to handle availability of encryption. Error 0x%x\n", ret);
	}
}

void
aea_stage_monitor_availability(void)
{
	apple_encrypted_archive_interface_set_registration_callback(aea_availability_callback);
}

bool
aea_stage_is_available(void)
{
	return apple_encrypted_archive != NULL;
}

#endif /* CONFIG_KDP_INTERACTIVE_DEBUGGING */
