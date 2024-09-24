/*
 * Copyright (c) 2022 Apple Inc. All rights reserved.
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

#ifndef _BTI_TELEMETRY_H_
#define _BTI_TELEMETRY_H_
#ifdef CONFIG_BTI_TELEMETRY
#include <mach/exception.h>
#include <mach/vm_types.h>
#include <mach/machine/thread_status.h>

/**
 * Wakes up the BTI exception telemetry subsystem. Call once per boot.
 */
void
bti_telemetry_init(void);

/**
 *  Handle a BTI exception. Returns TRUE if handled and OK to return from the
 *  exception, false otherwise.
 */
bool
bti_telemetry_handle_exception(arm_saved_state_t *state);

#endif /* CONFIG_BTI_TELEMETRY */
#endif /* _BTI_TELEMETRY_H_ */
