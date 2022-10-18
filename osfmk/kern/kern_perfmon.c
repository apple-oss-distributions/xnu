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

#if KERNEL
#include <kern/kalloc.h>
#include <kern/misc_protos.h>
#include <kern/perfmon.h>
#include <machine/atomic.h>
#include <machine/machine_perfmon.h>
#include <pexpert/pexpert.h>
#endif // KERNEL

#include <stdint.h>
#include <sys/errno.h>
#include <sys/perfmon_private.h>
#include <sys/queue.h>

SECURITY_READ_ONLY_LATE(struct perfmon_source) perfmon_sources[perfmon_kind_max]
        = { 0 };

const char *perfmon_names[perfmon_kind_max] = {
	[perfmon_cpmu] = "core",
	[perfmon_upmu] = "uncore",
};

_Atomic perfmon_config_t active_configs[perfmon_kind_max] = { NULL };

#if KERNEL

const char * _Atomic perfmon_owners[perfmon_kind_max] = { NULL };

__result_use_check bool
perfmon_acquire(enum perfmon_kind kind, const char *name)
{
	assert(kind < perfmon_kind_max);
#if KPC
	extern int kpc_get_force_all_ctrs(void);
	if (kind == perfmon_cpmu && kpc_get_force_all_ctrs()) {
		return false;
	}
#endif // KPC
	return os_atomic_cmpxchg(&perfmon_owners[kind], NULL, name, acq_rel);
}

bool
perfmon_in_use(enum perfmon_kind kind)
{
	assert(kind < perfmon_kind_max);
	return os_atomic_load(&perfmon_owners[kind], acquire) != NULL;
}

void
perfmon_release(enum perfmon_kind kind, const char *name)
{
	assert(kind < perfmon_kind_max);
	if (!os_atomic_cmpxchg(&perfmon_owners[kind], name, NULL, acq_rel)) {
		panic("perfmon: unpaired release: %s on %u", name, kind);
	}
}

#endif // KERNEL

struct perfmon_source *
perfmon_source_reserve(enum perfmon_kind kind)
{
	assert(kind < perfmon_kind_max);
	struct perfmon_source *source = &perfmon_sources[kind];
	if (source->ps_supported) {
		panic("perfmon: reserving source twice: %d", kind);
	}
	source->ps_kind = kind;
	source->ps_name = perfmon_names[kind];
	source->ps_supported = true;
	return source;
}

void
perfmon_source_sample_regs(struct perfmon_source *source, uint64_t *regs,
    size_t regs_count)
{
#if KERNEL
	perfmon_machine_sample_regs(source->ps_kind, regs, regs_count);
#else // KERNEL
#pragma unused(source, regs, regs_count)
	panic("perfmon: sample registers unavailable");
#endif // !KERNEL
}

static void
perfmon_spec_init(struct perfmon_spec *spec)
{
	spec->ps_events = kalloc_data(
		PERFMON_SPEC_MAX_EVENT_COUNT * sizeof(spec->ps_events[0]),
		Z_WAITOK | Z_ZERO);
	spec->ps_attrs = kalloc_data(
		PERFMON_SPEC_MAX_ATTR_COUNT * sizeof(spec->ps_attrs[0]),
		Z_WAITOK | Z_ZERO);
}

static void
perfmon_spec_deinit(struct perfmon_spec *spec)
{
	kfree_data(spec->ps_events,
	    PERFMON_SPEC_MAX_EVENT_COUNT * sizeof(spec->ps_events[0]));
	kfree_data(spec->ps_attrs,
	    PERFMON_SPEC_MAX_ATTR_COUNT * sizeof(spec->ps_attrs[0]));
}

perfmon_config_t
perfmon_config_create(struct perfmon_source *source)
{
	if (!source->ps_supported) {
		return NULL;
	}
	struct perfmon_config *config = kalloc_type(struct perfmon_config,
	    Z_WAITOK | Z_ZERO);
	config->pc_counters = kalloc_data(
		sizeof(config->pc_counters[0]) *
		source->ps_layout.pl_counter_count, Z_WAITOK | Z_ZERO);
	perfmon_spec_init(&config->pc_spec);
	config->pc_source = source;
	return config;
}

int
perfmon_config_add_event(perfmon_config_t config,
    const struct perfmon_event *event)
{
	if (config->pc_configured) {
		return EBUSY;
	}
	struct perfmon_layout *layout = &config->pc_source->ps_layout;
	struct perfmon_spec *spec = &config->pc_spec;
	if (event->pe_counter >= layout->pl_counter_count) {
		return ERANGE;
	}
	unsigned short fixed_end = layout->pl_fixed_offset +
	    layout->pl_fixed_count;
	if (event->pe_counter >= layout->pl_fixed_offset &&
	    event->pe_counter < fixed_end) {
		return ENODEV;
	}

	if (spec->ps_event_count >= PERFMON_SPEC_MAX_EVENT_COUNT) {
		return ENOSPC;
	}
	struct perfmon_counter *counter = &config->pc_counters[event->pe_counter];
	uint64_t counter_bit = (1ULL << event->pe_counter);
	if ((config->pc_counters_used & counter_bit) != 0) {
		return EALREADY;
	}

	counter->pc_number = event->pe_number;
	config->pc_counters_used |= counter_bit;
	spec->ps_events[spec->ps_event_count] = *event;
	spec->ps_event_count += 1;
	return 0;
}

static int
perfmon_source_resolve_attr(struct perfmon_source *source,
    const struct perfmon_attr *attr)
{
	unsigned short attr_count = source->ps_layout.pl_attr_count;
	for (unsigned short i = 0; i < attr_count; i++) {
		const perfmon_name_t *cur_attr = &source->ps_attribute_names[i];
		if (strncmp(attr->pa_name, *cur_attr, sizeof(*cur_attr)) == 0) {
			return i;
		}
	}
	return -1;
}

int
perfmon_config_set_attr(perfmon_config_t config,
    const struct perfmon_attr *attr)
{
	if (config->pc_configured) {
		return EBUSY;
	}
	struct perfmon_spec *spec = &config->pc_spec;
	if (spec->ps_attr_count >= PERFMON_SPEC_MAX_ATTR_COUNT) {
		return ENOSPC;
	}
	if (!PE_i_can_has_debugger(NULL)) {
		return EPERM;
	}

	int attr_id = perfmon_source_resolve_attr(config->pc_source, attr);
	if (attr_id < 0) {
		return ENOATTR;
	}

	uint64_t attr_bit = 1ULL << attr_id;
	if (config->pc_attrs_used & attr_bit) {
		return EALREADY;
	}

	config->pc_attr_ids[spec->ps_attr_count] = (unsigned short)attr_id;
	config->pc_attrs_used |= attr_bit;
	spec->ps_attrs[spec->ps_attr_count] = *attr;
	spec->ps_attr_count += 1;
	return 0;
}

int
perfmon_configure(perfmon_config_t config)
{
	enum perfmon_kind kind = config->pc_source->ps_kind;
	if (!os_atomic_cmpxchg(&active_configs[kind], NULL, config, acq_rel)) {
		return EBUSY;
	}
	int error = perfmon_machine_configure(config->pc_source->ps_kind,
	    config);
	config->pc_configured = true;
	return error;
}

struct perfmon_spec *
perfmon_config_specify(perfmon_config_t config)
{
	return &config->pc_spec;
}

void
perfmon_config_destroy(perfmon_config_t config)
{
	if (config->pc_configured) {
		enum perfmon_kind kind = config->pc_source->ps_kind;
		if (!os_atomic_cmpxchg(&active_configs[kind], config, NULL, acq_rel)) {
			panic("perfmon: destroying config that wasn't active: %p", config);
		}

		perfmon_machine_reset(config->pc_source->ps_kind);
	}
	kfree_data(config->pc_counters, sizeof(config->pc_counters[0]) *
	    config->pc_source->ps_layout.pl_counter_count);
	perfmon_spec_deinit(&config->pc_spec);
	kfree_type(struct perfmon_config, config);
}
