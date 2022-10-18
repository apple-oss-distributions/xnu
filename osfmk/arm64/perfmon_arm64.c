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

#include <arm64/perfmon_arm64_regs.h>
#include <kern/perfmon.h>
#include <kern/sched_prim.h>
#include <kern/startup.h>
#include <machine/machine_perfmon.h>
#include <machine/machine_routines.h>
#include <os/atomic.h>
#include <pexpert/arm64/board_config.h>

#endif // KERNEL

#include <stdatomic.h>
#include <stddef.h>
#include <string.h>
#include <sys/perfmon_private.h>

#define _STR(N) #N
#define STR(N) _STR(N)
#define ARRAYLEN(A) (sizeof(A) / sizeof(A[0]))

#define REG(N) #N,
#define PMC(N) "PMC" #N,
const perfmon_name_t cpmu_reg_names[] = { CPMU_REGS };
const size_t cpmu_reg_count = ARRAYLEN(cpmu_reg_names);

const perfmon_name_t cpmu_attr_names[] = { CPMU_ATTR_REGS };
const size_t cpmu_attr_count = ARRAYLEN(cpmu_attr_names);

#if HAS_UPMU

#define PIOREG(N, O) #N,
#define UPMC(N, O) "UPMC" #N,
const perfmon_name_t upmu_reg_names[] = { UPMU_REGS };
const size_t upmu_reg_count = ARRAYLEN(upmu_reg_names);

const perfmon_name_t upmu_attr_names[] = { UPMU_ATTR_REGS };
const size_t upmu_attr_count = ARRAYLEN(upmu_attr_names);

#if KERNEL

SECURITY_READ_ONLY_LATE(static uintptr_t) cpm_impl[MAX_CPU_CLUSTERS] = {};
SECURITY_READ_ONLY_LATE(static uintptr_t) acc_impl[MAX_CPU_CLUSTERS] = {};

#endif // KERNEL

SECURITY_READ_ONLY_LATE(static unsigned int) cluster_count = 1;
SECURITY_READ_ONLY_LATE(static uint64_t) upmu_cpu_pmi_mask = 0;

#if UPMU_PER_CLUSTER
#define UPMU_UNIT_COUNT (cluster_count)
#else // UPMU_PER_CLUSTER
#define UPMU_UNIT_COUNT (1)
#endif // !UPMU_PER_CLUSTER

#endif // HAS_UPMU

const unsigned short cpmu_fixed_count = 2;

__startup_func
static void
perfmon_machine_startup(void)
{
	struct perfmon_source *cpmu_source = perfmon_source_reserve(perfmon_cpmu);
	cpmu_source->ps_layout = (struct perfmon_layout){
		.pl_counter_count = CPMU_PMC_COUNT,
		.pl_fixed_offset = 0,
		.pl_fixed_count = cpmu_fixed_count,
		.pl_unit_count = (unsigned short)ml_get_cpu_count(),
		.pl_reg_count = cpmu_reg_count,
		.pl_attr_count = cpmu_attr_count,
	};
	cpmu_source->ps_register_names = cpmu_reg_names;
	cpmu_source->ps_attribute_names = cpmu_attr_names;

#if HAS_UPMU
	bool upmu_mapped = true;

#if KERNEL
	const ml_topology_info_t *topo_info = ml_get_topology_info();
	cluster_count = topo_info->num_clusters;

	for (unsigned int c = 0; c < cluster_count; c++) {
		ml_topology_cluster_t *cluster = &topo_info->clusters[c];
		upmu_cpu_pmi_mask |= 1ULL << cluster->first_cpu_id;
		cpm_impl[c] = (uintptr_t)cluster->cpm_IMPL_regs;
		acc_impl[c] = (uintptr_t)cluster->acc_IMPL_regs;
		if (cpm_impl[c] == 0 || acc_impl[c] == 0) {
			upmu_mapped = false;
			break;
		}
	}
#endif // KERNEL

	if (!upmu_mapped) {
		return;
	}
	struct perfmon_source *upmu_source = perfmon_source_reserve(perfmon_upmu);
	upmu_source->ps_layout = (struct perfmon_layout){
		.pl_counter_count = UPMU_PMC_COUNT,
		.pl_fixed_offset = 0,
		.pl_fixed_count = 0,
		.pl_unit_count = (unsigned short)UPMU_UNIT_COUNT,
		.pl_reg_count = upmu_reg_count,
		.pl_attr_count = upmu_attr_count,
	};
	upmu_source->ps_register_names = upmu_reg_names;
	upmu_source->ps_attribute_names = upmu_attr_names;
#endif // HAS_UPMU
}

#if KERNEL

STARTUP(PERCPU, STARTUP_RANK_MIDDLE, perfmon_machine_startup);

static void
perfmon_cpmu_sample_regs_xcall(void *regs_arg)
{
	uint64_t *regs = regs_arg;

#undef REG
#define REG_EL1(N) N##_EL1
#define REG(N) __builtin_arm_rsr64(STR(REG_EL1(N))),
#undef PMC
#define PMC_EL1(N) PMC##N
#define PMC(N) __builtin_arm_rsr64(STR(PMC_EL1(N))),

	const uint64_t cpmu_regs[] = { CPMU_REGS };
	memcpy(&regs[cpu_number() * cpmu_reg_count], cpmu_regs, sizeof(cpmu_regs));
}

#if HAS_UPMU
#undef PIOREG
#undef UPMC

#if UPMU_PER_CLUSTER
#define PIOREG(N, O) O,
#define UPMC(N, O) O,
const uintptr_t upmu_reg_cpm_offs[] = { UPMU_REGS };
const uintptr_t upmu_attr_cpm_offs[] = { UPMU_ATTR_REGS };
#endif // !UPMU_PER_CLUSTER
#endif // HAS_UPMU

void
perfmon_machine_sample_regs(enum perfmon_kind kind, uint64_t *regs,
    size_t __unused regs_len)
{
	if (kind == perfmon_cpmu) {
		boolean_t include_self = TRUE;
		cpu_broadcast_xcall_simple(include_self,
		    perfmon_cpmu_sample_regs_xcall, regs);
#if HAS_UPMU
	} else if (kind == perfmon_upmu) {
#if UPMU_PER_CLUSTER
		// Read the registers remotely through PIO when each cluster has its own
		// UPMU.
		for (unsigned int c = 0; c < UPMU_UNIT_COUNT; c++) {
			for (size_t r = 0; r < upmu_reg_count; r++) {
				regs[c * upmu_reg_count + r] =
				    *(uint64_t *)(cpm_impl[c] + upmu_reg_cpm_offs[r]);
			}
		}
#else // UPMU_PER_CLUSTER
#define PIOREG(N, O) REG(N)
#define UPMC_EL1(N) UPMC##N
#define UPMC(N, O) __builtin_arm_rsr64(STR(UPMC_EL1(N))),
		// Use direct MSR reads when the UPMU is global -- PIO access is not
		// consistent across all registers.
		const uint64_t upmu_regs[] = { UPMU_REGS };
		assert(regs_len == ARRAYLEN(upmu_regs));
		memcpy(regs, upmu_regs, sizeof(upmu_regs));
#endif // !UPMU_PER_CLUSTER
#endif // HAS_UPMU
	} else {
		panic("perfmon: unexpected kind: %d", kind);
	}
}

#endif // KERNEL

#undef REG
#define REG(N) CPMU_##N,

enum perfmon_cpmu_attr_reg {
	CPMU_ATTR_REGS
	CPMU_ATTR_REG_MAX,
};

struct perfmon_cpmu_regs {
	uint64_t pcr_pmcr0;
	uint64_t pcr_pmesr[2];
	uint64_t pcr_attr_regs[CPMU_ATTR_REG_MAX];
};

struct perfmon_cpmu_regs cpmu_reg_state;

static void
perfmon_cpmu_regs_init(struct perfmon_cpmu_regs *cpmu_regs)
{
	bzero(cpmu_regs, sizeof(*cpmu_regs));
	const uint64_t fixed_enable = 0x3;
	const uint64_t __unused intgen_fiq = 0x400;
	const uint64_t __unused intgen_aic = 0x100;
	const uint64_t fixed_pmi_enable = 0x3000;
	cpmu_regs->pcr_pmcr0 = fixed_enable | fixed_pmi_enable |
#if CPMU_AIC_PMI
	    intgen_aic;
#else // CPMU_AIC_PMI
	    intgen_fiq;
#endif // !CPMU_AIC_PMI
}

#if HAS_UPMU

#undef PIOREG
#define PIOREG(N, O) UPMU_##N,

enum perfmon_upmu_attr_reg {
	UPMU_ATTR_REGS
	UPMU_ATTR_REG_MAX,
};

#if UPMU_PMC_COUNT > 8
#define UPMU_ESR_COUNT 2
#else // UPMU_PMC_COUNT > 8
#define UPMU_ESR_COUNT 1
#endif // UPMU_PMC_COUNT <= 8

struct perfmon_upmu_regs {
	uint64_t pur_upmcr0;
	uint64_t pur_upmesr[UPMU_ESR_COUNT];
	// UPMPCM is handled by Monotonic.
	uint64_t pur_attr_regs[UPMU_ATTR_REG_MAX];
};

struct perfmon_upmu_regs upmu_reg_state;

static void
perfmon_upmu_regs_init(struct perfmon_upmu_regs *upmu_regs)
{
	bzero(upmu_regs, sizeof(*upmu_regs));

	uint64_t pmi_enable = 0xff000
#if UPMU_PMC_COUNT > 8
	    | 0xff00000
#endif // UPMU_PMC_COUNT > 8
	;
	uint64_t intgen_fiq = 0x100;
	upmu_regs->pur_upmcr0 = pmi_enable | intgen_fiq;
}

#endif // HAS_UPMU

#if KERNEL

static void
perfmon_cpmu_configure_xcall(void *cpmu_regs_arg)
{
	struct perfmon_cpmu_regs *cpmu_regs = cpmu_regs_arg;
	__builtin_arm_wsr64("PMCR0_EL1", cpmu_regs->pcr_pmcr0);
	__builtin_arm_wsr64("PMESR0_EL1", cpmu_regs->pcr_pmesr[0]);
	__builtin_arm_wsr64("PMESR1_EL1", cpmu_regs->pcr_pmesr[1]);

	if (!PE_i_can_has_debugger(NULL)) {
		return;
	}

	enum { REG_COUNTER_BASE = __COUNTER__ };
#define REG_COUNTER (__COUNTER__ - REG_COUNTER_BASE - 1)

	for (size_t i = 0; i < cpmu_attr_count; i++) {
		uint64_t attr_value = cpmu_regs->pcr_attr_regs[i];
		switch (i) {
#undef REG
#define REG(N) \
	        case REG_COUNTER: \
	                __builtin_arm_wsr64(STR(REG_EL1(N)), attr_value); \
	                break;

			CPMU_ATTR_REGS

		default:
			panic("perfmon: unexpected CPMU attribute ID: %zu", i);
			break;
		}
	}
}

#endif // KERNEL

#if HAS_UPMU

#if KERNEL

static void
perfmon_upmu_apply_attrs(struct perfmon_upmu_regs *upmu_regs,
    unsigned int __unused cluster_id)
{
#if KERNEL
	if (!PE_i_can_has_debugger(NULL)) {
		return;
	}

	for (size_t i = 0; i < upmu_attr_count; i++) {
		uint64_t attr_value = upmu_regs->pur_attr_regs[i];

#if UPMU_PER_CLUSTER
		uint64_t *attr_addr =
		    (uint64_t *)(cpm_impl[cluster_id] + upmu_attr_cpm_offs[i]);
		*attr_addr = attr_value;
#else // UPMU_PER_CLUSTER
		enum { PIOREG_COUNTER_BASE = __COUNTER__ };
#define PIOREG_COUNTER (__COUNTER__ - PIOREG_COUNTER_BASE - 1)

		switch (i) {
#undef PIOREG
#define PIOREG(N, O) \
	        case PIOREG_COUNTER: \
	                __builtin_arm_wsr64(STR(REG_EL1(N)), attr_value); \
	                break;

			UPMU_ATTR_REGS

		default:
			panic("perfmon: unexpected UPMU attribute ID: %zu", i);
			break;
		}
#endif // !UPMU_PER_CLUSTER
	}
#else // KERNEL
#pragma unused(cluster_id, upmu_regs)
#endif // KERNEL
}

static void
perfmon_upmu_configure(struct perfmon_upmu_regs *upmu_regs)
{
#if !UPMU_PER_CLUSTER
	__builtin_arm_wsr64("UPMCR0_EL1", upmu_regs->pur_upmcr0);
	__builtin_arm_wsr64("UPMESR0_EL1", upmu_regs->pur_upmesr[0]);
#if UPMU_PMC_COUNT > 8
	__builtin_arm_wsr64("UPMESR1_EL1", upmu_regs->pur_upmesr[1]);
#endif // UPMU_PMC_COUNT > 8
#endif // !UPMU_PER_CLUSTER

	for (unsigned int cluster = 0; cluster < cluster_count; cluster++) {
#if UPMU_PER_CLUSTER
#undef PIOREG
#define PIOREG(N, O) ((uint64_t *)(cpm_impl[cluster] + O))
		*UPMCR0 = upmu_regs->pur_upmcr0;
		*UPMESR0 = upmu_regs->pur_upmesr[0];
#if UPMU_PMC_COUNT > 8
		*UPMESR1 = upmu_regs->pur_upmesr[1];
#endif // UPMU_PMC_COUNT > 8
#endif // UPMU_PER_CLUSTER
		perfmon_upmu_apply_attrs(&upmu_reg_state, cluster);
	}
}

#endif // KERNEL

#endif // HAS_UPMU

static void
perfmon_set_attrs(uint64_t *attr_regs, size_t __unused attr_regs_len,
    perfmon_config_t config)
{
	for (size_t attr = 0; attr < config->pc_spec.ps_attr_count; attr++) {
		unsigned short id = config->pc_attr_ids[attr];
		assert(id < attr_regs_len);
		attr_regs[id] = config->pc_spec.ps_attrs[attr].pa_value;
	}
}

int
perfmon_machine_configure(enum perfmon_kind kind, const perfmon_config_t config)
{
	if (kind == perfmon_cpmu) {
		perfmon_cpmu_regs_init(&cpmu_reg_state);

		for (unsigned int pmc = cpmu_fixed_count; pmc < CPMU_PMC_COUNT; pmc++) {
			if ((config->pc_counters_used & (1ULL << pmc)) == 0) {
				continue;
			}
			struct perfmon_counter *counter = &config->pc_counters[pmc];
			uint64_t event = counter->pc_number &
#if CPMU_16BIT_EVENTS
			    0xffff;
#else // CPMU_16BIT_EVENTS
			    0xff;
#endif // !CPMU_16BIT_EVENTS

			unsigned int enable_offset = pmc > 7 ? 32 : 0;
			cpmu_reg_state.pcr_pmcr0 |= 1ULL << (enable_offset + pmc);

			unsigned int pmi_offset = pmc > 7 ? 44 - 7 : 12;
			cpmu_reg_state.pcr_pmcr0 |= 1ULL << (pmi_offset + pmc);

			unsigned int pmesr_index = pmc > 5 ? 1 : 0;
			unsigned int pmesr_shift = pmc > 5 ? pmc - 6 :
			    pmc - cpmu_fixed_count;
			// 8-bits for each event.
#if CPMU_16BIT_EVENTS
			pmesr_shift *= 16;
#else // CPMU_16BIT_EVENTS
			pmesr_shift *= 8;
#endif // !CPMU_16BIT_EVENTS
			uint64_t pmesr_bits = event << pmesr_shift;
			cpmu_reg_state.pcr_pmesr[pmesr_index] |= pmesr_bits;
		}
		perfmon_set_attrs(cpmu_reg_state.pcr_attr_regs,
		    ARRAYLEN(cpmu_reg_state.pcr_attr_regs), config);

#if KERNEL
		boolean_t include_self = TRUE;
		cpu_broadcast_xcall_simple(include_self, perfmon_cpmu_configure_xcall,
		    &cpmu_reg_state);
#endif // KERNEL
#if HAS_UPMU
	} else if (kind == perfmon_upmu) {
		perfmon_upmu_regs_init(&upmu_reg_state);

		for (unsigned short pmc = 0; pmc < UPMU_PMC_COUNT; pmc++) {
			struct perfmon_counter *counter = &config->pc_counters[pmc];
			if ((config->pc_counters_used & (1ULL << pmc)) == 0) {
				continue;
			}

			upmu_reg_state.pur_upmcr0 |= 1 << pmc;

			uint64_t event = counter->pc_number & 0xff;
			unsigned int upmesr_index = pmc >= 8 ? 1 : 0;
			unsigned int upmesr_shift = pmc >= 8 ? pmc - 8 : pmc;
			uint64_t upmesr_bits = event << upmesr_shift;
			upmu_reg_state.pur_upmesr[upmesr_index] |= upmesr_bits;
		}
		perfmon_set_attrs(upmu_reg_state.pur_attr_regs,
		    ARRAYLEN(upmu_reg_state.pur_attr_regs), config);

#if KERNEL
		perfmon_upmu_configure(&upmu_reg_state);
#endif // KERNEL
#endif // HAS_UPMU
	} else {
		panic("perfmon: unexpected kind: %d", kind);
	}
	return 0;
}

void
perfmon_machine_reset(enum perfmon_kind kind)
{
	if (kind == perfmon_cpmu) {
		perfmon_cpmu_regs_init(&cpmu_reg_state);
#if KERNEL
		boolean_t include_self = TRUE;
		cpu_broadcast_xcall_simple(include_self, perfmon_cpmu_configure_xcall,
		    &cpmu_reg_state);
#endif // KERNEL
#if HAS_UPMU
	} else if (kind == perfmon_upmu) {
#if KERNEL
		perfmon_upmu_regs_init(&upmu_reg_state);
		perfmon_upmu_configure(&upmu_reg_state);
#endif // KERNEL
#endif // HAS_PMU
	} else {
		panic("perfmon: unexpected kind: %d", kind);
	}
}
