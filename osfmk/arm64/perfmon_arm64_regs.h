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

#ifndef PERFMON_ARM64_REGS_H
#define PERFMON_ARM64_REGS_H

#if KERNEL
#include <pexpert/arm64/board_config.h>
#endif // KERNEL

// Store the register list in a macro, as it needs to both describe each
// register (as a string name) and sample them, preserving the list order.  The
// MSR builtins require string literals, limiting the ability to avoid macros.
//
// The source file that includes this header is responsible for defining the
// following macros to generate the PMC and register lists:
//
// - PMC
// - REG
#if HAS_UPMU
// - UPMC
// - PIOREG
#endif // HAS_UPMU

// Core Perfrormance Monitoring Unit Registers.

#define CPMU_PMCS_BASE PMC(0) PMC(1) PMC(2) PMC(3) PMC(4) PMC(5) PMC(6) PMC(7)

#if CPMU_PMC_COUNT > 8
#define CPMU_PMCS CPMU_PMCS_BASE PMC(8) PMC(9)
#else // CPMU_PMC_COUNT > 8
#define CPMU_PMCS CPMU_PMCS_BASE
#endif // CPMU_PMC_COUNT <= 8

// Only read MSRs that are supported for this hardware.  clang will abort if it
// sees an MSR that's not present in its machine model.

#if CPMU_MEMORY_FILTERING
#define MEMFLT_REGS REG(PM_MEMFLT_CTL23) REG(PM_MEMFLT_CTL45)
#else // CPMU_MEMORY_FILTERING
#define MEMFLT_REGS
#endif // !CPMU_MEMORY_FILTERING
#if CPMU_INSTRUCTION_MATCHING
#define BP_REGS REG(PMCR_BVRNG4) REG(PMCR_BVRNG5)
#else // CPMU_INSTRUCTION_MATCHING
#define BP_REGS
#endif // !CPMU_INSTRUCTION_MATCHING

#define META_REGS REG(PMMMAP)
#define USER_CTL_REGS REG(PMCR2) REG(PMCR3) REG(PMCR4)
#define OPMATCH_REGS REG(OPMAT0) REG(OPMAT1)

#define CPMU_REGS \
	REG(PMCR0) REG(PMCR1) USER_CTL_REGS \
	REG(PMESR0) REG(PMESR1) REG(PMSR) \
	OPMATCH_REGS BP_REGS MEMFLT_REGS META_REGS CPMU_PMCS

#define CPMU_ATTR_REGS \
	USER_CTL_REGS OPMATCH_REGS BP_REGS MEMFLT_REGS META_REGS

#if HAS_UPMU

// Uncore Perfmormance Monitoring Unit Registers.

#define UPMU_PMCS_BASE \
	UPMC(0, 0x4100) UPMC(1, 0x4248) UPMC(2, 0x4110) UPMC(3, 0x4250) \
	UPMC(4, 0x4120) UPMC(5, 0x4258) UPMC(6, 0x4130) UPMC(7, 0x4260)

#if UPMU_PMC_COUNT > 8
#define UPMU_PMCS \
	UPMU_PMCS_BASE UPMC(8, 0x4140) UPMC(9, 0x4268) UPMC(10, 0x4150) \
	UPMC(11, 0x4270) UPMC(12, 0x4160) UPMC(13, 0x4278) UPMC(14, 0x4170) \
	UPMC(15, 0x4280)
#else // UPMU_PMC_COUNT > 8
#define UPMU_PMCS UPMU_PMCS_BASE
#endif // UPMU_PMC_COUNT <= 8

// TODO UPMPCM is ACC_IMPL-relative in version 2.

#if UPMU_AF_LATENCY
#define AFLAT_REGS \
	PIOREG(AFLATCTL1, 0x41d0) PIOREG(AFLATCTL2, 0x41d8) \
	PIOREG(AFLATCTL3, 0x41e0) PIOREG(AFLATCTL4, 0x41e8) \
	PIOREG(AFLATCTL5, 0x41f0) \
	PIOREG(AFLATVALBIN0, 0x4208) PIOREG(AFLATVALBIN1, 0x4210) \
	PIOREG(AFLATVALBIN2, 0x4218) PIOREG(AFLATVALBIN3, 0x4220) \
	PIOREG(AFLATVALBIN4, 0x4228) PIOREG(AFLATVALBIN5, 0x4230) \
	PIOREG(AFLATVALBIN6, 0x4238) PIOREG(AFLATVALBIN7, 0x4240) \
	PIOREG(AFLATINFLO, 0x4288) PIOREG(AFLATINFHI, 0x4290)
#else // UPMU_AF_LATENCY
#define AFLAT_REGS
#endif // !UPMU_AF_LATENCY

#if UPMU_PMC_COUNT > 8
#define UPMESR1 PIOREG(UPMESR1, 0x41b8)
#define UPMU_16_REGS UPMESR1 PIOREG(UPMCR1, 0x4188)
#else // UPMU_PMC_COUNT > 8
#define UPMU_16_REGS
#endif // UPMU_PMC_COUNT <= 8

#define ECM_REGS_BASE PIOREG(UPMECM0, 0x4190) PIOREG(UPMECM1, 0x4198)
#if UPMU_PMC_COUNT > 8
#define ECM_REGS ECM_REGS_BASE PIOREG(UPMECM2, 0x41a0) PIOREG(UPMECM3, 0x41a8)
#else // UPMU_PMC_COUNT > 8
#define ECM_REGS ECM_REGS_BASE
#endif // UPMU_PMC_COUNT <= 8

#if UPMU_META_EVENTS
#define UMETA_REGS \
	PIOREG(UPMCFILTER0, 0x0600) PIOREG(UPMCFILTER1, 0x0608) \
	PIOREG(UPMCFILTER2, 0x0610) PIOREG(UPMCFILTER3, 0x0618) \
	PIOREG(UPMCFILTER4, 0x0620) PIOREG(UPMCFILTER5, 0x0628) \
	PIOREG(UPMCFILTER6, 0x0630) PIOREG(UPMCFILTER7, 0x0638)
#else // UPMU_META_EVENTS
#define UMETA_REGS
#endif // !UPMU_META_EVENTS

#define UPMCR0 PIOREG(UPMCR0, 0x4180)
#define UPMESR0 PIOREG(UPMESR0, 0x41b0)

#define UPMU_REGS UPMCR0 UPMESR0 UPMU_16_REGS ECM_REGS AFLAT_REGS UPMU_PMCS

#define UPMU_ATTR_REGS ECM_REGS AFLAT_REGS

#endif // HAS_UPMU

#endif // !defined(PERFMON_ARM64_REGS_H)
