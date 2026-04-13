// Copyright (c) 2023 Apple Inc. All rights reserved.
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

#pragma once

#include <os/base.h>
#include <stdbool.h>
#include <stdint.h>
#include <kern/cpc.h>
#include <pexpert/arm64/board_config.h>

#if CONFIG_CPU_COUNTERS

__BEGIN_DECLS

#if CPMU_64BIT_PMCS
#define CPC_CPMU_MAX_COUNT ((1ULL << 63) - 1)
#else // CPMU_64BIT_PMCS
#define CPC_CPMU_MAX_COUNT ((1ULL << 47) - 1)
#endif // !CPMU_64BIT_PMCS

union cpc_machine_regs {
	struct _cpc_arm64_cpmu_regs {
		uint64_t cacr_pmcr[2];
		cpc_event_t cacr_events[CPMU_PMC_COUNT - 2];
		uint64_t cacr_pmesr[2];
		bool cacr_has_events;

		bool cacr_ext;
		uint64_t cacr_pmcr2, cacr_pmcr3, cacr_pmcr4;
		uint64_t cacr_opmat0, cacr_opmat1;
		uint64_t cacr_opmsk0, cacr_opmsk1;
		uint64_t cacr_pm_memflt_ctl23, cacr_pm_memflt_ctl45;
		uint64_t cacr_pmefr[8];
	} cmr_cpmu;
};

// Set by hardware if a PMI was delivered
#define PMCR0_PMAI (UINT64_C(1) << 11)
#define PMCR0_PMI(REG) ((REG) & PMCR0_PMAI)

#if HAS_UPMU

#define UPMSR_PMI(REG) ((REG) & 0x1)

#endif // HAS_UPMU

__enum_closed_decl(cpc_legacy_rawpmu_t, int, {
	CPC_LRP_CPMU_PMCR2 = -1,
	CPC_LRP_CPMU_PMCR3 = -2,
	CPC_LRP_CPMU_PMCR4 = -3,
	CPC_LRP_CPMU_OPMAT0 = -4,
	CPC_LRP_CPMU_OPMAT1 = -5,
	CPC_LRP_CPMU_OPMSK0 = -6,
	CPC_LRP_CPMU_OPMSK1 = -7,
#if CPMU_EVENT_FILTERING
	CPC_LRP_CPMU_PM_MEMFLT_CTL23 = -8,
	CPC_LRP_CPMU_PM_MEMFLT_CTL45 = -9,
	CPC_LRP_CPMU_PMEFR2 = -10,
	CPC_LRP_CPMU_PMEFR3 = -11,
	CPC_LRP_CPMU_PMEFR4 = -12,
	CPC_LRP_CPMU_PMEFR5 = -13,
	CPC_LRP_CPMU_PMEFR6 = -14,
	CPC_LRP_CPMU_PMEFR7 = -15,
	CPC_LRP_CPMU_PMEFR8 = -16,
	CPC_LRP_CPMU_PMEFR9 = -17,
#endif // CPMU_EVENT_FILTERING
});

static inline bool
cpc_pmi_pending(uint64_t * restrict pmcr0_out,
    uint64_t * restrict upmsr_out)
{
	uint64_t pmcr0 = __builtin_arm_rsr64("S3_1_C15_C0_0");
	bool pmi = PMCR0_PMI(pmcr0);
	*pmcr0_out = pmcr0;

#if HAS_UPMU
	extern bool mt_uncore_enabled;
	if (mt_uncore_enabled) {
		uint64_t upmsr = __builtin_arm_rsr64("S3_7_C15_C6_4");
		if (UPMSR_PMI(upmsr)) {
			pmi = true;
		}
		*upmsr_out = upmsr;
	}
#else // HAS_UPMU
#pragma unused(upmsr_out)
#endif // !HAS_UPMU

	return pmi;
}

// Called by the second level exception handler when a PMI FIQ occurs.
void cpc_fiq(void *cpu, uint64_t pmcr0, uint64_t upmsr);

struct cpc_cpu {
	uint64_t ccp_cpmu_pmi_count;
	struct cpc_counter ccp_cpmu_counters[CPMU_PMC_COUNT];
	struct cpc_deadlines ccp_cpmu_deadlines[CPMU_PMC_COUNT];
};

__enum_closed_decl(cpc_event_policy_t, unsigned int, {
	CPC_EVPOL_DENY_ALL = 0,
	CPC_EVPOL_ALLOW_ALL,
	CPC_EVPOL_RESTRICT_TO_KNOWN,
#if CPC_INSECURE
	CPC_EVPOL_DEFAULT = CPC_EVPOL_ALLOW_ALL,
#else // CPC_INSECURE
	CPC_EVPOL_DEFAULT = CPC_EVPOL_RESTRICT_TO_KNOWN,
#endif // !CPC_INSECURE
});

cpc_event_policy_t cpc_get_event_policy(void);

/// Change how event restrictions are applied.
///
/// - Parameters:
///   - new_policy: The event policy to start applying indefinitely.
void cpc_set_event_policy(cpc_event_policy_t new_policy);

struct cpc_event_info {
	const char *cev_name;
	uint16_t cev_selector;
};

struct cpc_event_list {
	unsigned int cel_event_count;
	struct cpc_event_info cel_events[];
};

extern const struct cpc_event_list cpc_known_cpmu_events;

__END_DECLS

#endif // CONFIG_CPU_COUNTERS
