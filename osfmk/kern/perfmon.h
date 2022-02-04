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

#ifndef KERN_PERFMON_H
#define KERN_PERFMON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/cdefs.h>
#include <sys/perfmon_private.h>

__BEGIN_DECLS

enum perfmon_kind {
	perfmon_cpmu,
	perfmon_upmu,
	perfmon_kind_max,
};

#if CONFIG_PERFMON

// Allow other performance monitoring SPIs to take ownership of the hardware and
// prevent interference.

// Returns whether the hardware could be acquired
__result_use_check bool perfmon_acquire(enum perfmon_kind kind,
    const char *name);
// Returns whether the hardware is being used.
__result_use_check bool perfmon_in_use(enum perfmon_kind kind);
// Releases use of the hardware, or panics if it wasn't acquired.
void perfmon_release(enum perfmon_kind kind, const char *name);

struct perfmon_source {
	const char *ps_name;
	const perfmon_name_t *ps_register_names;
	const perfmon_name_t *ps_attribute_names;
	struct perfmon_layout ps_layout;
	enum perfmon_kind ps_kind;
	bool ps_supported;
};

extern struct perfmon_source perfmon_sources[perfmon_kind_max];

struct perfmon_source *perfmon_source_reserve(enum perfmon_kind kind);

void perfmon_source_sample_regs(struct perfmon_source *, uint64_t *, size_t);

#define PERFMON_SPEC_MAX_EVENT_COUNT (16)
#define PERFMON_SPEC_MAX_ATTR_COUNT (32)

typedef struct perfmon_config *perfmon_config_t;

perfmon_config_t perfmon_config_create(struct perfmon_source *source);

int perfmon_config_add_event(perfmon_config_t,
    const struct perfmon_event *event);
int perfmon_config_set_attr(perfmon_config_t, const struct perfmon_attr *attr);
int perfmon_configure(perfmon_config_t);
struct perfmon_spec *perfmon_config_specify(perfmon_config_t);
void perfmon_config_destroy(perfmon_config_t);

#else // CONFIG_PERFMON

#define perfmon_acquire(...) true
#define perfmon_in_use(...) false
#define perfmon_release(...) do { } while (0)

#endif // !CONFIG_PERMON

#endif // !defined(KERN_PERFMON_H)
