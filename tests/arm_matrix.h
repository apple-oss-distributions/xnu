/*
 * Copyright (c) 2022 Apple Computer, Inc. All rights reserved.
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

#ifndef __ARM_MATRIX_H
#define __ARM_MATRIX_H

#include <mach/mach_types.h>
#include <mach/thread_status.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>

struct arm_matrix_operations {
	const char *name;

	size_t (*data_size)(void);
	void *(*alloc_data)(void);

	bool (*is_available)(void);
	void (*start)(void);
	void (*stop)(void);

	void (*load_one_vector)(const void *);
	void (*load_data)(const void *);
	void (*store_data)(void *);

	kern_return_t (*thread_get_state)(thread_act_t, void *);
	kern_return_t (*thread_set_state)(thread_act_t, const void *);
};

extern const struct arm_matrix_operations sme_operations;

#endif /* __ARM_MATRIX_H */
