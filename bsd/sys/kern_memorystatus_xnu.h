/*
 * Copyright (c) 2024 Apple Computer, Inc. All rights reserved.
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
#include <stdbool.h>
#include <stdint.h>

#pragma once

__BEGIN_DECLS
#if XNU_KERNEL_PRIVATE

/* TODO: migrate other xnu-private interfaces from kern_memorystatus.h */

/*
 * Return the minimum number of available pages jetsam requires before it
 * begins killing non-idle processes. This is useful for some pageout
 * mechanisms to avoid deadlock.
 */
extern uint32_t memorystatus_get_critical_page_shortage_threshold(void);

/*
 * Return the minimum number of available pages jetsam requires before it
 * begins killing idle processes. This is consumed by the vm pressure
 * notification system in the absence of the compressor.
 */
extern uint32_t memorystatus_get_idle_exit_page_shortage_threshold(void);

/*
 * Return the minimum number of available pages jetsam requires before it
 * begins killing processes which have violated their soft memory limit. This
 * is consumed by the vm pressure notification system in the absence of the
 * compressor.
 */
extern uint32_t memorystatus_get_soft_memlimit_page_shortage_threshold(void);

/*
 * Return the current number of available pages in the system.
 */
extern uint32_t memorystatus_get_available_page_count(void);

/*
 * Set the available page count and consider engaging response measures (e.g.
 * waking jetsam thread/pressure-notification thread).
 */
extern void memorystatus_update_available_page_count(uint32_t available_pages);

/*
 * Override fast-jetsam support. If override is enabled, fast-jetsam will be
 * disabled.
 */
extern void memorystatus_fast_jetsam_override(bool enable_override);

#endif /* XNU_KERNEL_PRIVATE */
__END_DECLS
