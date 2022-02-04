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

static void
net_stage_reset(struct kdp_output_stage *stage)
{
	stage->kos_bypass = false;
	stage->kos_bytes_written = 0;
}

static kern_return_t
net_stage_outproc(struct kdp_output_stage *stage, unsigned int request,
    char *corename, uint64_t length, void * data)
{
	kern_return_t err = KERN_SUCCESS;

	assert(STAILQ_NEXT(stage, kos_next) == NULL);

	err = kdp_send_crashdump_data(request, corename, length, data);
	if (KERN_SUCCESS != err) {
		kern_coredump_log(NULL, "kdp_send_crashdump_data returned 0x%x\n", err);
		return err;
	}

	if (KDP_DATA == request) {
		stage->kos_bytes_written += length;
	}

	return err;
}

static void
net_stage_free(struct kdp_output_stage *stage)
{
	stage->kos_initialized = false;
}

kern_return_t
net_stage_initialize(struct kdp_output_stage *stage)
{
	assert(stage != NULL);
	assert(stage->kos_initialized == false);

	stage->kos_funcs.kosf_reset = net_stage_reset;
	stage->kos_funcs.kosf_outproc = net_stage_outproc;
	stage->kos_funcs.kosf_free = net_stage_free;

	stage->kos_initialized = true;

	return KERN_SUCCESS;
}

#endif /* CONFIG_KDP_INTERACTIVE_DEBUGGING */
