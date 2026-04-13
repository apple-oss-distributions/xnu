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

#pragma once

#include <mach/kern_return.h>
#include <stdint.h>
#include <sys/cdefs.h>

__BEGIN_DECLS

/**
 * LLC event versions.
 */
typedef enum : uint8_t {
	LLC_EVENT_V1,

	LLC_EVENT_NUM_VERSIONS
} llc_event_version_t;

/**
 * LLC event descriptor.
 */
typedef struct {
	/* Version of this struct. */
	llc_event_version_t version;

	/* LLC_ERR_STS. */
	uint64_t sts;
	/* LLC_ERR_INF. */
	uint64_t inf;
	/* LLC_ERR_ADR. */
	uint64_t adr;

	/* ECC syndrome. */
	uint32_t syn;
	/* LLC way. */
	uint32_t way;
} llc_event_t;
_Static_assert(sizeof(llc_event_t) == 10 * sizeof(uint32_t),
    "llc_event_t size must be updated in memory_error_notification.defs");

#if KERNEL_PRIVATE
/**
 * Log an LLC error.
 *
 * @param event Event to be logged.
 *
 * @returns KERN_SUCCESS on success, KERN_FAILURE otherwise.
 */
kern_return_t llc_log_memory_error(llc_event_t event);
#endif /* KERNEL_PRIVATE */

__END_DECLS
