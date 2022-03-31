/*
 * Copyright (c) 2000-2021 Apple Inc. All rights reserved.
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

#ifndef _SYS_RESOURCE_PRIVATE_H_
#define _SYS_RESOURCE_PRIVATE_H_

#include <os/base.h>
#include <stdint.h>
#include <sys/cdefs.h>

/*
 * The kind of counters to copy into the destination buffer with
 * `thread_selfcounts`.
 */
__enum_decl(thread_selfcounts_kind_t, uint32_t, {
	THSC_CPI = 0x01,
});

/*
 * The data structure expected by `thread_selfcounts(THSC_CPI, ...)`.
 */
struct thsc_cpi {
	uint64_t tcpi_instructions;
	uint64_t tcpi_cycles;
};

#ifndef KERNEL

#include <stddef.h>
#include <AvailabilityInternalPrivate.h>

__BEGIN_DECLS

/*
 * Get the current thread's counters according to a `kind` and store them into
 * `dst`.
 */
    __SPI_AVAILABLE(macos(12.4), ios(15.4), watchos(8.5), tvos(15.4))
int thread_selfcounts(thread_selfcounts_kind_t kind, void *dst, size_t size);

/*
 * Get the current thread's cycles and instructions.  May return ENOTSUP on
 * certain hardware.
 */
#define thread_selfcounts_cpi(DST) thread_selfcounts(THSC_CPI, (DST), sizeof(struct thsc_cpi))

__END_DECLS

#endif /* !defined(KERNEL) */

#endif  /* !defined(_SYS_RESOURCE_PRIVATE_H_) */
