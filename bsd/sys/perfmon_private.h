// Copyright (c) 2020 Apple Inc. All rights reserved.
//
// @APPLE_OSREFERENCE_LICENSE_HEADER_START@
//
// This file contains Original Code and/or Modifications of Original Code
// as defined in and that are subject to the Apple Public Source License
// Version 2.0 (the 'License'). You may not use this file except in
// compliance with the License. The rights granted to you under the License
// may not be used to create, or enable the creation or redistribution of,
// unlawful or unlicensed copies of an Apple operating system, or to
// circumvent, violate, or enable the circumvention or violation of, any
// terms of an Apple operating system software license agreement.
//
// Please obtain a copy of the License at
// http://www.opensource.apple.com/apsl/ and read it before using this file.
//
// The Original Code and all software distributed under the License are
// distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
// EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
// INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
// Please see the License for the specific language governing rights and
// limitations under the License.
//
// @APPLE_OSREFERENCE_LICENSE_HEADER_END@

#ifndef BSD_PERFMON_PRIVATE_H
#define BSD_PERFMON_PRIVATE_H

#if KERNEL
#include <machine/limits.h>
#else // KERNEL
#include <limits.h>
#endif // !KERNEL
#include <stdint.h>
#include <stdbool.h>
#include <sys/cdefs.h>

__BEGIN_DECLS

struct perfmon_layout {
	unsigned short pl_counter_count;
	unsigned short pl_fixed_offset;
	unsigned short pl_fixed_count;
	unsigned short pl_unit_count;
	unsigned short pl_reg_count;
	unsigned short pl_attr_count;
};

typedef char perfmon_name_t[16];

struct perfmon_event {
	char pe_name[32];
	uint64_t pe_number;
	unsigned short pe_counter;
};

struct perfmon_attr {
	perfmon_name_t pa_name;
	uint64_t pa_value;
};

struct perfmon_spec {
	struct perfmon_event *ps_events;
	struct perfmon_attr *ps_attrs;
	unsigned short ps_event_count;
	unsigned short ps_attr_count;
};

#if !MACH_KERNEL_PRIVATE

#include <sys/ioccom.h>

// A perfmon file is initially mutable, where events can be added and
// attributes set.  The fine-grained nature of this API gives clients insight
// into which specific configuration was erroneous and the associated overheads
// are taken only when the system is configured, at process startup.
enum perfmon_ioctl {
	// PMU metadata, always allowed.

	// Immutable information about the PMU.
	PERFMON_CTL_GET_LAYOUT = _IOR('P', 0, struct perfmon_layout),
	PERFMON_CTL_LIST_ATTRS = _IO('P', 1),
	PERFMON_CTL_LIST_REGS = _IO('P', 2),

	// Get diagnostic information by sampling the hardware registers.
	PERFMON_CTL_SAMPLE_REGS = _IO('P', 3),

	// Set up a configuration, only allowed when open for writing and before
	// configure.

	// Add an event to the configuration.
	PERFMON_CTL_ADD_EVENT = _IOWR('P', 5, struct perfmon_event),
	// Apply attributes to a given event, or globally.
	PERFMON_CTL_SET_ATTR = _IOW('P', 6, struct perfmon_attr),

	// Control the state of the PMU, only allowed when open for writing.

	// Configure the monitor, no more settings can be adjusted after this is
	// called, one time only.
	PERFMON_CTL_CONFIGURE = _IO('P', 7),
	// Start counting, only allowed after configuration and counting stopped.
	PERFMON_CTL_START = _IO('P', 8),
	// Stop counting, only allowed with counting started.
	PERFMON_CTL_STOP = _IO('P', 9),

	// Query the confguration, only allowed when open for writing.
	PERFMON_CTL_SPECIFY = _IOWR('P', 10, struct perfmon_spec),
};

#if XNU_KERNEL_PRIVATE

// Called from the pseudo-device initializer in config/MASTER.
int perfmon_dev_init(void);

#endif // XNU_KERNEL_PRIVATE

#endif // !MACH_KERNEL_PRIVATE

__END_DECLS

#endif // !defined(BSD_PERFMON_PRIVATE_H)
