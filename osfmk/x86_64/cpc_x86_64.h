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
#include <kern/cpc.h>

__BEGIN_DECLS

#define CPMU_PMC_COUNT     (8)
#define CPC_CPMU_MAX_COUNT ((UINT64_C(1) << 48) - 1)
#define CPC_COUNTERS_WRAP  1

union cpc_machine_regs {
	struct _cpc_x86_64_cpmu_regs {
		uint64_t cxcr_global_ctrl;
		uint64_t cxcr_fixed_ctrl;
		uint64_t cxcr_evtsel[4];
#if DEVELOPMENT || DEBUG
		// Read-only values for debugging purposes.
		uint64_t cxcr_global_ovf_ctrl;
		uint64_t cxcr_global_status;
#endif // DEVELOPMENT || DEBUG
	} cmr_cpmu;
};

struct cpc_cpu {
	bool ccp_core_active;
	uint64_t ccp_core_pmi_count;
	struct cpc_counter ccp_cpmu_counters[CPMU_PMC_COUNT];
	struct cpc_deadlines ccp_cpmu_deadlines[CPMU_PMC_COUNT];
};

struct cpc_cycles_instrs cpc_cycles_instrs_raw_approx_x86_64(
	uint64_t *unhalted_ref_cycles_out);

void cpc_early_init(void);

__END_DECLS
