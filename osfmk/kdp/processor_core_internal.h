/*
 * Copyright (c) 2025 Apple Inc. All rights reserved.
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
#ifndef _PROCESSOR_CORE_PRIVATE_H_
#define _PROCESSOR_CORE_PRIVATE_H_

#include <kdp/processor_core.h>

/*
 * Only compile when interactive debugging is enabled. This reduces kernel size
 *  and attack surface when KDP debugging features are not needed in
 *  production builds.
 */
#ifdef CONFIG_KDP_INTERACTIVE_DEBUGGING
/*
 * The processor_core_context structure describes the current
 * corefile that's being generated. It also includes a pointer
 * to the core_outvars which is used by the KDP code for context
 * about the specific output mechanism being used.
 *
 * We include X_remaining variables to catch inconsistencies / bugs
 * in the co-processor coredump callbacks.
 */
typedef struct {
	struct kdp_core_out_vars * core_outvars;     /* Output procedure info (see kdp_out_stage.h) */
	kern_coredump_callback_config *core_config;  /* Information about core currently being dumped */
	void *core_refcon;                           /* Reference constant associated with the coredump helper */
	boolean_t core_should_be_skipped;            /* Indicates whether this specific core should not be dumped */
	boolean_t core_is64bit;                      /* Bitness of CPU */
	kern_coredump_type_t core_type;              /* Indicates type of this core*/
	uint32_t core_mh_magic;                      /* Magic for mach header */
	cpu_type_t core_cpu_type;                    /* CPU type for mach header */
	cpu_subtype_t core_cpu_subtype;              /* CPU subtype for mach header */
	uint64_t core_file_length;                   /* Overall corefile length including any zero padding */
	uint64_t core_file_length_compressed;        /* File length after compression */
	uint64_t core_segment_count;                 /* Number of LC_SEGMENTs in the core currently being dumped */
	uint64_t core_segments_remaining;            /* Number of LC_SEGMENTs that have not been added to the header */
	uint64_t core_segment_byte_total;            /* Sum of all the data from the LC_SEGMENTS in the core */
	uint64_t core_segment_bytes_remaining;       /* Quantity of data remaining from LC_SEGMENTs that have yet to be added */
	uint64_t core_thread_count;                  /* Number of LC_THREADs to be included */
	uint64_t core_threads_remaining;             /* Number of LC_THREADs that have yet to be included */
	uint64_t core_thread_state_size;             /* Size of each LC_THREAD */
	uint64_t core_note_count;                    /* Number of LC_NOTEs to be included */
	uint64_t core_notes_remaining;               /* Number of LC_NOTEs that have not been added to the header */
	uint64_t core_note_bytes_total;              /* Sum of all data from the LC_NOTE segments in the core */
	uint64_t core_note_bytes_remaining;          /* Quantity of data remaining from LC_NOTEs that have yet to be added */
	uint64_t core_cur_hoffset;                   /* Current offset in this core's header */
	uint64_t core_cur_foffset;                   /* Current offset in this core's overall file */
	uint64_t core_header_size;                   /* Size of this core's header */
	uint64_t core_total_bytes;                   /* Total amount of data to be included in this core (excluding zero fill) */
	const char *core_name;                       /* Name of corefile being produced */
} processor_core_context;

__static_testable struct kern_coredump_core *kern_register_coredump_helper_internal(int kern_coredump_config_vers, const kern_coredump_callback_config *kc_callbacks,
    void *refcon, const char *core_description, kern_coredump_type_t type, boolean_t is64bit,
    uint32_t mh_magic, cpu_type_t cpu_type, cpu_subtype_t cpu_subtype);

#endif /* CONFIG_KDP_INTERACTIVE_DEBUGGING */

#endif /* _PROCESSOR_CORE_PRIVATE_H_ */
