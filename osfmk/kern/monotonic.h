/*
 * Copyright (c) 2017-2019 Apple Inc. All rights reserved.
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
#ifndef KERN_MONOTONIC_H
#define KERN_MONOTONIC_H

#if CONFIG_CPU_COUNTERS && MACH_KERNEL_PRIVATE

#include <kern/thread.h>
#include <kern/task.h>
#include <stdbool.h>

__BEGIN_DECLS

/*
 * Private API for the platform layers.
 */

/*
 * Called while single-threaded when the system is going to sleep.
 */
void mt_sleep(void);

/*
 * Called on each CPU as the system is waking from sleep.
 */
void mt_wake_per_core(void);

__END_DECLS

#endif /* CONFIG_CPU_COUNTERS && MACH_KERNEL_PRIVATE */

#endif /* !defined(KERN_MONOTONIC_H) */
