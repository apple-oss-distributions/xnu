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
	/*
	 * Get the current thread's cycles and instructions -- may return ENOTSUP
	 * on certain hardware.
	 */
	THSC_CPI = 1,
	/*
	 * Same as `THSC_CPI`, except fills in an array indexed by CPU perf-level,
	 * with `sysctl hw.nperflevels` entries.
	 */
	THSC_CPI_PER_PERF_LEVEL = 2,
	/*
	 * Get the current thread's cycles, instructions, user time and system time.
	 * Instructions and cycles may be left 0 on certain hardware.  System time
	 * may be accounted for by user time and left 0 on certain hardware.
	 */
	THSC_TIME_CPI = 3,
	/*
	 * Same as `THSC_TIME_CPI`, except fills in an array indexed by CPU
	 * perf-level, with `sysctl hw.nperflevels` entries.
	 */
	THSC_TIME_CPI_PER_PERF_LEVEL = 4,
	/*
	 * Get the current thread's cycles, instructions, times, and energy usage.
	 */
	THSC_TIME_ENERGY_CPI = 5,
	/*
	 * Same as `THSC_TIME_ENERGY_CPI`, except fills in an array indexd by CPU
	 * perf-level, with `sysctl hw.nperflevels` entries.
	 */
	THSC_TIME_ENERGY_CPI_PER_PERF_LEVEL = 6,
});

/*
 * The data structure expected by `THSC_CPI*`.
 */
struct thsc_cpi {
	uint64_t tcpi_instructions;
	uint64_t tcpi_cycles;
};

/*
 * The data structure expected by `THSC_TIME_CPI*`.
 */
struct thsc_time_cpi {
	uint64_t ttci_instructions;
	uint64_t ttci_cycles;
	uint64_t ttci_user_time_mach;
	uint64_t ttci_system_time_mach;
};

/*
 * The data structure expected by `THSC_TIME_ENERGY_CPI*`.
 */
struct thsc_time_energy_cpi {
	uint64_t ttec_instructions;
	uint64_t ttec_cycles;
	uint64_t ttec_user_time_mach;
	uint64_t ttec_system_time_mach;
	uint64_t ttec_energy_nj;
};

#ifndef KERNEL

#include <stddef.h>
#include <Availability.h>
#include <AvailabilityInternalPrivate.h>

__BEGIN_DECLS

/*
 * Get the current thread's counters according to a `kind` and store them into
 * `dst`.
 */
__SPI_AVAILABLE(macos(12.4), ios(15.4), watchos(8.5), tvos(15.4))
int thread_selfcounts(thread_selfcounts_kind_t kind, void *dst, size_t size);

__END_DECLS

#endif /* !defined(KERNEL) */

/* Additional private parameters to getpriority()/setpriority( */

#define PRIO_DARWIN_GAME_MODE   7               /* Second argument is a PID */

#define PRIO_DARWIN_GAME_MODE_OFF   0x0
#define PRIO_DARWIN_GAME_MODE_ON    0x1

#endif  /* !defined(_SYS_RESOURCE_PRIVATE_H_) */
