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

#pragma once

#include <sys/queue.h>

struct kdp_output_stage;

struct kdp_core_out_state {
	STAILQ_HEAD(, kdp_output_stage) kcos_out_stage;
	struct kdp_output_stage *       kcos_encryption_stage;
	bool                            kcos_enforce_encryption;
	uint64_t                        kcos_totalbytes;
	uint64_t                        kcos_bytes_written;
	uint64_t                        kcos_lastpercent;
	kern_return_t                   kcos_error;
};

struct kdp_output_stage_funcs {
	void (*kosf_reset)(struct kdp_output_stage *stage);
	kern_return_t (*kosf_outproc)(struct kdp_output_stage *stage, unsigned int request,
	    char *corename, uint64_t length, void *panic_data);
	void (*kosf_free)(struct kdp_output_stage *stage);
};

struct kdp_output_stage {
	STAILQ_ENTRY(kdp_output_stage) kos_next;
	bool                           kos_initialized;
	struct kdp_core_out_state *    kos_outstate;
	struct kdp_output_stage_funcs  kos_funcs;
	uint64_t                       kos_bytes_written; // bytes written since the last call to reset()
	bool                           kos_bypass;
	void *                         kos_data;
	size_t                         kos_data_size;
};
