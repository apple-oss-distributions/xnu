/*
 * Copyright (c) 2020 Apple Inc. All rights reserved.
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
#include <arm64/sptm/pmap/pmap_internal.h>
#include <arm/preemption_disable_internal.h>

/**
 * Placeholder for random pmap functionality that doesn't fit into any of the
 * other files. This will contain things like the CPU copy windows, ASID
 * management and context switching code, and stage 2 pmaps (among others).
 *
 * My idea is that code that doesn't fit into any of the other files will live
 * in this file until we deem it large and important enough to break into its
 * own file.
 */


void
pmap_abandon_measurement(void)
{
#if SCHED_HYGIENE_DEBUG
	struct _preemption_disable_pcpu *pcpu = PERCPU_GET(_preemption_disable_pcpu_data);
	const boolean_t istate = ml_set_interrupts_enabled(FALSE);
	if (pcpu->pdp_start.pds_mach_time != 0) {
		pcpu->pdp_abandon = true;
	}
	ml_set_interrupts_enabled(istate);
#endif /* SCHED_HYGIENE_DEBUG */
}
