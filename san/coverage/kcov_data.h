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
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
#ifndef _KCOV_DATA_H_
#define _KCOV_DATA_H_

#include <san/kcov.h>
#include <san/kcov_ksancov_data.h>
#include <san/kcov_stksz_data.h>

#if KERNEL_PRIVATE

#if CONFIG_KCOV

/*
 * Coverage sanitizer per-cpu data
 */
struct kcov_cpu_data {
	uint32_t       kcd_enabled;     /* coverage recording enabled for CPU. */
};

/*
 * Coverage sanitizer per-thread data
 */
struct kcov_thread_data {
	uint32_t               ktd_disabled;    /* disable sanitizer for a thread */
#if CONFIG_KSANCOV
	ksancov_dev_t          ktd_device;     /* ksancov per-thread data */
#endif
#if CONFIG_STKSZ
	kcov_stksz_thread_t    ktd_stksz;       /* stack size per-thread data */
#endif
};

#endif /* CONFIG_KCOV */

#endif /* KERNEL_PRIVATE */

#endif /* _KCOV_DATA_H_ */
