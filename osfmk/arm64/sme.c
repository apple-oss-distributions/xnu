/*
 * Copyright (c) 2022 Apple Computer, Inc. All rights reserved.
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

#include <arm/misc_protos.h>
#include <arm64/proc_reg.h>
#include <libkern/section_keywords.h>

SECURITY_READ_ONLY_LATE(arm_sme_version_t) sme_version = 0;
SECURITY_READ_ONLY_LATE(int) sme_max_svl_b = 0;

/**
 * Returns the version of SME supported on this platform.
 *
 * In contrast to the compile-time HAS_ARM_FEAT_SME/HAS_ARM_FEAT_SME2 checks
 * that indicate compiler support, arm_sme_version() is a runtime check that
 * indicates actual processor support.
 *
 * @return the highest SME ISA version supported on this platform
 * (where ARM_SME_UNSUPPORTED or 0 indicates no SME support)
 */
arm_sme_version_t
arm_sme_version(void)
{
	return sme_version;
}

#if HAS_ARM_FEAT_SME

#include <kern/cpu_data.h>
#include <kern/thread.h>

static arm_sme_version_t
arm_sme_probe_version(void)
{
	uint64_t aa64pfr1_el1 = __builtin_arm_rsr64("ID_AA64PFR1_EL1");
	uint64_t aa64pfr1_el1_sme = aa64pfr1_el1 & ID_AA64PFR1_EL1_SME_MASK;

	if (aa64pfr1_el1_sme < ID_AA64PFR1_EL1_SME_EN) {
		return ARM_SME_UNSUPPORTED;
	}

	uint64_t aa64smfr0_el1 = __builtin_arm_rsr64("ID_AA64SMFR0_EL1");
	uint64_t aa64smfr0_el1_smever = aa64smfr0_el1 & ID_AA64SMFR0_EL1_SMEver_MASK;

	switch (aa64smfr0_el1_smever) {
	case ID_AA64SMFR0_EL1_SMEver_SME:
		return ARM_FEAT_SME;

	case ID_AA64SMFR0_EL1_SMEver_SME2:
		return ARM_FEAT_SME2;

	default:
		return ARM_FEAT_SME2;
	}
}

#if !APPLEVIRTUALPLATFORM
__assert_only
#endif
static const unsigned int SME_MAX_SVL_B = 64;

void
arm_sme_init(bool is_boot_cpu)
{
	if (is_boot_cpu) {
		sme_version = arm_sme_probe_version();
	}

	if (!sme_version) {
		return;
	}

	/* enable SME at EL1 only */
	uint64_t cpacr_el1 = __builtin_arm_rsr64("CPACR_EL1");
	cpacr_el1 &= ~CPACR_SMEN_MASK;
	cpacr_el1 |= CPACR_SMEN_EL0_TRAP;
	__builtin_arm_wsr64("CPACR_EL1", cpacr_el1);
	__builtin_arm_isb(ISB_SY);

#if APPLEVIRTUALPLATFORM
	uint64_t smcr_el1 = SMCR_EL1_LEN((SME_MAX_SVL_B / 16) - 1);
#else
	uint64_t smcr_el1 = SMCR_EL1_LEN(~0);
#endif
#if HAS_ARM_FEAT_SME2
	/* enable ZT0 access */
	smcr_el1 |= SMCR_EL1_EZT0;
#endif
	/*
	 * Request the highest possible SVL and read back the actual SVL.
	 * ARM guarantees these accesses will occur in program order.
	 */
	__builtin_arm_wsr64("SMCR_EL1", smcr_el1);
	if (is_boot_cpu) {
		sme_max_svl_b = arm_sme_svl_b();
	}

	/* disable SME prioritization */
	const uint64_t smpri_el1 = SMPRI_EL1_PRIORITY(0);
	__builtin_arm_wsr64("SMPRI_EL1", smpri_el1);

	__builtin_arm_wsr64("TPIDR2_EL0", 0);
}

/**
 * Returns the streaming SVE vector length.  The total size of the ZA array is
 * SVL_B x SVL_B bytes.
 *
 * @return the number of 8-bit elements in a streaming SVE vector
 */
uint16_t
arm_sme_svl_b(void)
{
	uint64_t ret = 0;
	asm volatile (
                "rdsvl	%[ret], #1"
                : [ret] "=r"(ret)
        );

	assert(__builtin_popcountll(ret) == 1);
	assert(ret >= 16);
	assert(ret <= SME_MAX_SVL_B);

	return (uint16_t)ret;
}

/**
 * Save the current CPU's ZA array to the provided storage space.
 *
 * @param sme_ss destination ZA storage
 * @param svl_b SVL corresponding to sme_ss, in bytes
 */
void
arm_save_sme_za(arm_sme_context_t *sme_ss, uint16_t svl_b)
{
	uint8_t *za = arm_sme_za(sme_ss, svl_b);
	/*
	 * SME adds ldr and str variants convenient for context-switching ZA:
	 *
	 *   <ldr|str> za[<Wv>, #<imm>], [<Xn>, #<imm>, mul vl]
	 *
	 * If we view ZA as a 2D array with dimensions SVL_B x SVL_B, then these
	 * instructions copy data between ZA[<Wv> + <imm>][] and an SVL_B-sized
	 * block of memory starting at address <Xn> + <imm> * SVL_B.
	 *
	 * <imm> is between 0-15, so we can perform up to 16 copies before
	 * updating <Wv> and <Xn>.  <Wv> also must be one of W12-W15.  This is
	 * an unusual restriction for AArch64 that can't be represented with
	 * extended asm register constraints, so we need to manually constrain
	 * this operand with the register keyword.
	 */
	for (register uint16_t i asm("w12") = 0; i < svl_b; i += 16) {
		asm volatile (
                        "str    za[%w[i],  #0], [%[addr],  #0, mul vl]"   "\n"
                        "str    za[%w[i],  #1], [%[addr],  #1, mul vl]"   "\n"
                        "str    za[%w[i],  #2], [%[addr],  #2, mul vl]"   "\n"
                        "str    za[%w[i],  #3], [%[addr],  #3, mul vl]"   "\n"
                        "str    za[%w[i],  #4], [%[addr],  #4, mul vl]"   "\n"
                        "str    za[%w[i],  #5], [%[addr],  #5, mul vl]"   "\n"
                        "str    za[%w[i],  #6], [%[addr],  #6, mul vl]"   "\n"
                        "str    za[%w[i],  #7], [%[addr],  #7, mul vl]"   "\n"
                        "str    za[%w[i],  #8], [%[addr],  #8, mul vl]"   "\n"
                        "str    za[%w[i],  #9], [%[addr],  #9, mul vl]"   "\n"
                        "str    za[%w[i], #10], [%[addr], #10, mul vl]"   "\n"
                        "str    za[%w[i], #11], [%[addr], #11, mul vl]"   "\n"
                        "str    za[%w[i], #12], [%[addr], #12, mul vl]"   "\n"
                        "str    za[%w[i], #13], [%[addr], #13, mul vl]"   "\n"
                        "str    za[%w[i], #14], [%[addr], #14, mul vl]"   "\n"
                        "str    za[%w[i], #15], [%[addr], #15, mul vl]"   "\n"
                        :
                        : [i] "r"(i),
                          [addr] "r"(za + (i * svl_b))
                );
	}
}

/**
 * Load the current CPU's ZA array from the provided storage space.
 *
 * @param sme_ss source ZA storage
 * @param svl_b SVL corresponding to sme_ss, in bytes
 */
void
arm_load_sme_za(const arm_sme_context_t *sme_ss, uint16_t svl_b)
{
	const uint8_t *za = const_arm_sme_za(sme_ss, svl_b);
	for (register uint16_t i asm("w12") = 0; i < svl_b; i += 16) {
		asm volatile (
                        "ldr    za[%w[i],  #0], [%[addr],  #0, mul vl]"   "\n"
                        "ldr    za[%w[i],  #1], [%[addr],  #1, mul vl]"   "\n"
                        "ldr    za[%w[i],  #2], [%[addr],  #2, mul vl]"   "\n"
                        "ldr    za[%w[i],  #3], [%[addr],  #3, mul vl]"   "\n"
                        "ldr    za[%w[i],  #4], [%[addr],  #4, mul vl]"   "\n"
                        "ldr    za[%w[i],  #5], [%[addr],  #5, mul vl]"   "\n"
                        "ldr    za[%w[i],  #6], [%[addr],  #6, mul vl]"   "\n"
                        "ldr    za[%w[i],  #7], [%[addr],  #7, mul vl]"   "\n"
                        "ldr    za[%w[i],  #8], [%[addr],  #8, mul vl]"   "\n"
                        "ldr    za[%w[i],  #9], [%[addr],  #9, mul vl]"   "\n"
                        "ldr    za[%w[i], #10], [%[addr], #10, mul vl]"   "\n"
                        "ldr    za[%w[i], #11], [%[addr], #11, mul vl]"   "\n"
                        "ldr    za[%w[i], #12], [%[addr], #12, mul vl]"   "\n"
                        "ldr    za[%w[i], #13], [%[addr], #13, mul vl]"   "\n"
                        "ldr    za[%w[i], #14], [%[addr], #14, mul vl]"   "\n"
                        "ldr    za[%w[i], #15], [%[addr], #15, mul vl]"   "\n"
                        :
                        : [i] "r"(i),
                          [addr] "r"(za + (i * svl_b))
                );
	}
}

/**
 * Configures CPACR_EL1 to trap or enable SME instructions at EL0.
 *
 * The caller does not need to issue any instruction barriers;
 * arm_context_switch_requires_sync() is automatically invoked if needed.
 *
 * @param trap_enabled whether to trap SME instructions at EL0
 */
void
arm_sme_trap_at_el0(bool trap_enabled)
{
	uint64_t cpacr_el1 = __builtin_arm_rsr64("CPACR_EL1");
	unsigned int prev_mode = (unsigned int)(cpacr_el1 & CPACR_SMEN_MASK);
	unsigned int new_mode = trap_enabled ? CPACR_SMEN_EL0_TRAP : CPACR_SMEN_ENABLE;

	if (prev_mode != new_mode) {
		cpacr_el1 &= ~CPACR_SMEN_MASK;
		cpacr_el1 |= new_mode;
		__builtin_arm_wsr64("CPACR_EL1", cpacr_el1);
		arm_context_switch_requires_sync();
	}
}

/**
 * Returns whether the current thread has an active SME context.
 */
boolean_t
arm_sme_is_active(void)
{
	/* Kernel entry clobbers SVCR.SM, so check the saved state instead of live register state */
	arm_sme_saved_state_t *sme_ss = machine_thread_get_sme_state(current_thread());
	return sme_ss && (sme_ss->svcr & (SVCR_SM | SVCR_ZA));
}

#if HAS_ARM_FEAT_SME2
/**
 * Save the current CPU's ZT0 array to the provided storage space.
 *
 * @param sme_ss destination ZT0 storage
 */
void
arm_save_sme_zt0(arm_sme_context_t *sme_ss)
{
	asm volatile (
                "str zt0, [%[addr]]"
                :
                : [addr] "r"(sme_ss->zt0)
        );
}

/**
 * Load the current CPU's ZT0 array from the provided storage space.
 *
 * @param sme_ss source ZT0 storage
 */
void
arm_load_sme_zt0(const arm_sme_context_t *sme_ss)
{
	asm volatile (
                "ldr	zt0, [%[addr]]"
                :
                : [addr] "r"(sme_ss->zt0)
        );
}
#endif /* HAS_ARM_FEAT_SME2 */

/**
 * Save the current CPU's ZA and ZT0 arrays to the provided storage space.
 *
 * If this CPU does not support SME2, ZT0 storage is zeroed out instead.
 *
 * @param sme_ss destination storage
 * @param svl_b SVL corresponding to sme_ss, in bytes
 */
void
arm_save_sme_za_zt0(arm_sme_context_t *sme_ss, uint16_t svl_b)
{
	arm_save_sme_za(sme_ss, svl_b);
#if HAS_ARM_FEAT_SME2
	if (arm_sme_version() >= 2) {
		arm_save_sme_zt0(sme_ss);
	}
#else
	if (0) {
	}
#endif
	else {
		bzero(sme_ss->zt0, sizeof(sme_ss->zt0));
	}
}

/**
 * Load the current CPU's ZA and ZT0 arrays from the provided storage space.
 *
 * If this CPU does not support SME2, ZT0 storage is ignored.
 *
 * @param sme_ss source storage
 * @param svl_b SVL corresponding to sme_ss, in bytes
 */
void
arm_load_sme_za_zt0(const arm_sme_context_t *sme_ss, uint16_t svl_b)
{
	arm_load_sme_za(sme_ss, svl_b);
#if HAS_ARM_FEAT_SME2
	if (arm_sme_version() >= 2) {
		arm_load_sme_zt0(sme_ss);
	}
#endif
}

#endif /* HAS_ARM_FEAT_SME */
