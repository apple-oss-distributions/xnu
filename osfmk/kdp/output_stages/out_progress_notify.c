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
#include <IOKit/IOPlatformExpert.h>
#include <kdp/output_stages/output_stages.h>
#include <kdp/kdp_core.h>
#include <kdp/processor_core.h>

#define NOTIFY_INTERVAL_NSECS (5 * NSEC_PER_SEC)

struct progress_notify_stage_data {
	uint64_t notify_interval_matus;
	uint64_t last_notify_timestamp;
};

static void
progress_notify_stage_reset(struct kdp_output_stage *stage)
{
	struct progress_notify_stage_data *data = (struct progress_notify_stage_data*) stage->kos_data;

	data->last_notify_timestamp = 0;
}

static kern_return_t
progress_notify_stage_outproc(struct kdp_output_stage *stage, unsigned int request,
    char *corename, uint64_t length, void * panic_data)
{
	kern_return_t err = KERN_SUCCESS;
	struct progress_notify_stage_data *data = (struct progress_notify_stage_data*) stage->kos_data;
	struct kdp_output_stage  *next_stage = STAILQ_NEXT(stage, kos_next);
	uint64_t now = mach_absolute_time();

	assert(next_stage != NULL);

	if (now >= (data->last_notify_timestamp + data->notify_interval_matus)) {
		PEHaltRestart(kPEPanicDiagnosticsInProgress);
		data->last_notify_timestamp = now;
	}

	err = next_stage->kos_funcs.kosf_outproc(next_stage, request, corename, length, panic_data);
	if (KERN_SUCCESS != err) {
		kern_coredump_log(NULL, "%s (during forwarding) returned 0x%x\n", __func__, err);
		return err;
	}

	return KERN_SUCCESS;
}

static void
progress_notify_stage_free(struct kdp_output_stage *stage)
{
	kmem_free(kernel_map, (vm_offset_t) stage->kos_data, stage->kos_data_size);

	stage->kos_data = NULL;
	stage->kos_data_size = 0;
	stage->kos_initialized = false;
}

kern_return_t
progress_notify_stage_initialize(struct kdp_output_stage *stage)
{
	kern_return_t ret = KERN_SUCCESS;
	struct progress_notify_stage_data *data = NULL;

	assert(stage != NULL);
	assert(stage->kos_initialized == false);
	assert(stage->kos_data == NULL);

	stage->kos_data_size = sizeof(struct progress_notify_stage_data);
	ret = kmem_alloc(kernel_map, (vm_offset_t*) &stage->kos_data, stage->kos_data_size, VM_KERN_MEMORY_DIAG);
	if (KERN_SUCCESS != ret) {
		printf("progress_notify_stage_initialize failed to allocate memory. Error 0x%x\n", ret);
		return ret;
	}

	data = (struct progress_notify_stage_data *) stage->kos_data;
	data->last_notify_timestamp = 0;
	nanoseconds_to_absolutetime(NOTIFY_INTERVAL_NSECS, &data->notify_interval_matus);

	stage->kos_funcs.kosf_reset = progress_notify_stage_reset;
	stage->kos_funcs.kosf_outproc = progress_notify_stage_outproc;
	stage->kos_funcs.kosf_free = progress_notify_stage_free;

	stage->kos_initialized = true;

	return KERN_SUCCESS;
}

#endif // CONFIG_KDP_INTERACTIVE_DEBUGGING
