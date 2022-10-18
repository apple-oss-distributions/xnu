/*
 * Copyright (c) 2017-2021 Apple Inc. All rights reserved.
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
#include <arm/cpuid.h>
#include <arm/cpuid_internal.h>
#include <machine/atomic.h>
#include <machine/machine_cpuid.h>
#include <arm/cpu_data_internal.h>

static arm_mvfp_info_t cpuid_mvfp_info;
static arm_debug_info_t cpuid_debug_info;

uint32_t
machine_read_midr(void)
{
	uint64_t midr;
	__asm__ volatile ("mrs	%0, MIDR_EL1"  : "=r" (midr));

	return (uint32_t)midr;
}

uint32_t
machine_read_clidr(void)
{
	uint64_t clidr;
	__asm__ volatile ("mrs	%0, CLIDR_EL1"  : "=r" (clidr));

	return (uint32_t)clidr;
}

uint32_t
machine_read_ccsidr(void)
{
	uint64_t ccsidr;
	__asm__ volatile ("mrs	%0, CCSIDR_EL1"  : "=r" (ccsidr));

	return (uint32_t)ccsidr;
}

void
machine_write_csselr(csselr_cache_level level, csselr_cache_type type)
{
	uint64_t csselr = (uint64_t)level | (uint64_t)type;
	__asm__ volatile ("msr	CSSELR_EL1, %0"  : : "r" (csselr));

	__builtin_arm_isb(ISB_SY);
}

void
machine_do_debugid(void)
{
	arm_cpuid_id_aa64dfr0_el1 id_dfr0;

	/* read ID_AA64DFR0_EL1 */
	__asm__ volatile ("mrs %0, ID_AA64DFR0_EL1" : "=r"(id_dfr0.value));

	if (id_dfr0.debug_feature.debug_arch_version) {
		cpuid_debug_info.num_watchpoint_pairs = id_dfr0.debug_feature.wrps + 1;
		cpuid_debug_info.num_breakpoint_pairs = id_dfr0.debug_feature.brps + 1;
	}
}

arm_debug_info_t *
machine_arm_debug_info(void)
{
	return &cpuid_debug_info;
}

void
machine_do_mvfpid()
{
	cpuid_mvfp_info.neon = 1;
	cpuid_mvfp_info.neon_hpfp = 1;
#if defined(__ARM_ARCH_8_2__)
	cpuid_mvfp_info.neon_fp16 = 1;
#endif /* defined(__ARM_ARCH_8_2__) */
}

arm_mvfp_info_t *
machine_arm_mvfp_info(void)
{
	return &cpuid_mvfp_info;
}
