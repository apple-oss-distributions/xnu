/*
 * Copyright (c) 2019 Apple Inc. All rights reserved.
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

#ifndef _PEXPERT_ARM64_H13_H
#define _PEXPERT_ARM64_H13_H

#define APPLEFIRESTORM
#define NO_MONITOR              1 /* No EL3 for this CPU -- ever */
#define HAS_CTRR                1 /* Has CTRR registers */
#define HAS_NEX_PG              1 /* Supports p-Core NEX powergating during Neon inactivity */
#define HAS_BP_RET              1 /* Supports branch predictor state retention across ACC sleep */
#define HAS_CONTINUOUS_HWCLOCK  1 /* Has a hardware clock that ticks during sleep */
#define HAS_IPI                 1 /* Has IPI registers */
#define HAS_CLUSTER             1 /* Has eCores and pCores in separate clusters */
#define HAS_RETENTION_STATE     1 /* Supports architectural state retention */
#define HAS_UCNORMAL_MEM        1 /* Supports completely un-cacheable normal memory type */
#define HAS_FAST_CNTVCT         1
#define HAS_ACNTVCT             1 /* Supports private ISA non speculative MRS reads of timebase registers (ACNTPCT/ACNTVCT) */

#define HAS_ARM_FEAT_SSBS2      1 /* Supports Speculative Store Bypass Safe with MSR controls */
#define HAS_USAT_BIT            1 /* ACTLR has USAT bit (H12+) */
#define HAS_E0PD                1 /* Supports E0PD0 and E0PD1 in TCR for Meltdown mitigation (ARMv8.5)*/
#define HAS_CPU_DPE_COUNTER     1 /* Has a hardware counter for digital power estimation */
#define HAS_GUARDED_IO_FILTER   1 /* Has a guarded runtime dedicated to the fine-grained IO access filter */

#define CPU_HAS_APPLE_PAC                    1
#define HAS_UNCORE_CTRS                      1
#define UNCORE_VERSION                       2
#define UNCORE_PER_CLUSTER                   1
#define UNCORE_NCTRS                         16
#define CORE_NCTRS                           10
#define HAS_CPMU_PC_CAPTURE                  1

/* Performance Monitor */
#define CPMU_PMC_COUNT                       10
#define CPMU_INSTRUCTION_MATCHING            1
#define CPMU_MEMORY_FILTERING                1
#define HAS_UPMU                             1
#define UPMU_VERSION                         2
#define UPMU_PMC_COUNT                       16
#define UPMU_PER_CLUSTER                     1
#define UPMU_AF_LATENCY                      1
#define UPMU_META_EVENTS                     1

#define __ARM_AMP__                             1
#define __ARM_16K_PG__                          1
#define __ARM_GLOBAL_SLEEP_BIT__                1
#define __ARM_PAN_AVAILABLE__                   1
#define __ARM_SB_AVAILABLE__                    1

#define __HWP_CFG_BIT_VER__                     1

/* Optional CPU features -- an SoC may #undef these */
#define ARM_PARAMETERIZED_PMAP               1
#define __ARM_MIXED_PAGE_SIZE__              1

#define __ARM_RANGE_TLBI__                   1

#include <pexpert/arm64/vhe_disable.h>

#include <pexpert/arm64/apple_arm64_common.h>

#endif /* !_PEXPERT_ARM64_H13_H */
