/*
 * Copyright (c) 2012 Apple Inc. All rights reserved.
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

#include <mach/mach_types.h>
#include <machine/machine_routines.h>
#include <kern/processor.h>
#include <i386/cpuid.h>
#include <i386/proc_reg.h>
#include <i386/mp.h>
#include <sys/errno.h>
#include <sys/monotonic.h>
#include <kperf/buffer.h>
#include <kern/kpc.h>
#include <kperf/kperf.h>
#include <kperf/sample.h>
#include <kperf/context.h>
#include <kperf/action.h>

#include <kern/startup.h>

#define IA32_PERFEVT_USER_EN (0x10000)
#define IA32_PERFEVT_OS_EN (0x20000)

kpc_config_t
kpc_config_arch_process(kpc_config_t config)
{
	return config;
}

cpc_event_flags_t
kpc_config_arch_flags(kpc_config_t config)
{
	cpc_event_flags_t flags = CPC_EF_NONE;
	// Assume no masks means all masks on.
	if ((config & (IA32_PERFEVT_USER_EN | IA32_PERFEVT_OS_EN)) == 0) {
		config |= IA32_PERFEVT_USER_EN | IA32_PERFEVT_OS_EN;
	}
	if (!(config & IA32_PERFEVT_USER_EN)) {
		flags |= CPC_EF_NO_USER;
	}
	if (!(config & IA32_PERFEVT_OS_EN)) {
		flags |= CPC_EF_NO_KERNEL;
	}
	return flags;
}

/* internal functions */

uint32_t
kpc_fixed_count(void)
{
	return cpuid_info()->cpuid_arch_perf_leaf.fixed_number;
}

uint32_t
kpc_configurable_count(void)
{
	return cpuid_info()->cpuid_arch_perf_leaf.number / 2;
}

uint32_t
kpc_fixed_config_count(void)
{
	return 1;
}

uint32_t
kpc_configurable_config_count(uint64_t pmc_mask)
{
	assert(kpc_popcount(pmc_mask) <= kpc_configurable_count());
	return kpc_popcount(pmc_mask);
}

uint32_t
kpc_rawpmu_config_count(void)
{
	return 0;
}

int
kpc_get_rawpmu_config(__unused kpc_config_t *configv)
{
	return 0;
}

static uint8_t
kpc_fixed_width(void)
{
	return cpuid_info()->cpuid_arch_perf_leaf.fixed_width;
}

static uint8_t
kpc_configurable_width(void)
{
	return cpuid_info()->cpuid_arch_perf_leaf.width;
}

uint64_t
kpc_fixed_max(void)
{
	return (1ULL << kpc_fixed_width()) - 1;
}

uint64_t
kpc_configurable_max(void)
{
	return (1ULL << kpc_configurable_width()) - 1;
}

static uint64_t
IA32_FIXED_CTR_CTRL(void)
{
	return rdmsr64(MSR_IA32_PERF_FIXED_CTR_CTRL);
}

int
kpc_get_fixed_config(kpc_config_t *configv)
{
	configv[0] = IA32_FIXED_CTR_CTRL();
	return 0;
}

static uint64_t
IA32_PERFEVTSELx(uint32_t ctr)
{
	return rdmsr64(MSR_IA32_EVNTSEL0 + ctr);
}

int
kpc_get_configurable_config(kpc_config_t *configv, uint64_t pmc_mask)
{
	uint32_t cfg_count = kpc_configurable_count();

	assert(configv);

	for (uint32_t i = 0; i < cfg_count; ++i) {
		if ((1ULL << i) & pmc_mask) {
			*configv++  = IA32_PERFEVTSELx(i);
		}
	}
	return 0;
}

static void
kpc_get_curcpu_counters_mp_call(void *args)
{
	struct kpc_get_counters_remote *handler = args;
	int offset = 0, r = 0;

	assert(handler);
	assert(handler->buf);

	offset = cpu_number() * handler->buf_stride;
	r = kpc_get_curcpu_counters(handler->classes, NULL, &handler->buf[offset]);

	/* number of counters added by this CPU, needs to be atomic  */
	os_atomic_add(&(handler->nb_counters), r, relaxed);
}

int
kpc_get_all_cpus_counters(uint32_t classes, int *curcpu, uint64_t *buf)
{
	int enabled = 0;

	struct kpc_get_counters_remote hdl = {
		.classes = classes, .nb_counters = 0,
		.buf_stride = kpc_get_counter_count(classes), .buf = buf
	};

	assert(buf);

	enabled = ml_set_interrupts_enabled(FALSE);

	if (curcpu) {
		*curcpu = cpu_number();
	}
	mp_cpus_call(CPUMASK_ALL, ASYNC, kpc_get_curcpu_counters_mp_call, &hdl);

	ml_set_interrupts_enabled(enabled);

	return hdl.nb_counters;
}

uint32_t
kpc_get_classes(void)
{
	return KPC_CLASS_FIXED_MASK | KPC_CLASS_CONFIGURABLE_MASK;
}

int
kpc_get_pmu_version(void)
{
	uint8_t version_id = cpuid_info()->cpuid_arch_perf_leaf.version;

	if (version_id == 3) {
		return KPC_PMU_INTEL_V3;
	} else if (version_id == 2) {
		return KPC_PMU_INTEL_V2;
	}

	return KPC_PMU_ERROR;
}

static int
_no_core_init(__unused mt_device_t dev)
{
	return ENOTSUP;
}

struct mt_device mt_devices[1] = {
	[0] = {
		.mtd_name = "core",
		.mtd_init = _no_core_init,
	},
};
