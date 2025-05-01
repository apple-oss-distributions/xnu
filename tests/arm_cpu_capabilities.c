/*
 * Copyright (c) 2020 Apple Computer, Inc. All rights reserved.
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

#include <cpu_capabilities_public.h>
#include <darwintest.h>
#include <machine/cpu_capabilities.h>
#include <stdlib.h>
#include <sys/sysctl.h>

#include "exc_helpers.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.arm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("arm"),
	T_META_OWNER("ghackmann"),
	T_META_RUN_CONCURRENTLY(true),
	T_META_TAG("SoCSpecific")
	);

static volatile bool cap_usable;

static size_t
bad_instruction_handler(mach_port_t task __unused, mach_port_t thread __unused,
    exception_type_t type __unused, mach_exception_data_t codes __unused)
{
	cap_usable = false;
	return 4;
}

static void
try_fp16(void)
{
	asm volatile (
                "fmov	h0, #0" "\n"
                :
                :
                : "v0"
        );
}

static void
try_atomics(void)
{
	uint64_t dword;
	asm volatile (
                "swp	xzr, xzr, [%[dword]]"
                :
                : [dword]"r"(&dword)
        );
}

static void
try_crc32(void)
{
	asm volatile ( "crc32b	wzr, wzr, wzr");
}

static void
try_fhm(void)
{
	asm volatile (
                "fmov	d0, #0"                 "\n"
                "fmlal	v0.2s, v0.2h, v0.2h"    "\n"
                :
                :
                : "v0"
        );
}

static void
try_sha512(void)
{
	asm volatile (
                "fmov		d0, #0"                 "\n"
                "fmov		d1, #0"                 "\n"
                "sha512h	q0, q0, v0.2d"          "\n"
                :
                :
                : "v0"
        );
}

static void
try_sha3(void)
{
	asm volatile (
                "fmov	d0, #0"                         "\n"
                "fmov	d1, #0"                         "\n"
                "eor3	v0.16b, v0.16b, v0.16b, v0.16b" "\n"
                :
                :
                : "v0"
        );
}

static void
try_sha1(void)
{
	asm volatile (
                "fmov		s0, #0"         "\n"
                "sha1h		s0, s0"         "\n"
                :
                :
                : "v0"
        );
}

static void
try_pmull(void)
{
	asm volatile (
                "fmov	d0, #0"                 "\n"
                "pmull	v0.1q, v0.1d, v0.1d"    "\n"
                :
                :
                : "v0"
        );
}

static void
try_aes(void)
{
	asm volatile (
                "fmov		d0, #0"                 "\n"
                "fmov		d1, #0"                 "\n"
                "aesd		v0.16B, v0.16B"         "\n"
                :
                :
                : "v0"
        );
}


static void
try_sha256(void)
{
	asm volatile (
                "fmov           d0, #0"                 "\n"
                "fmov           d1, #0"                 "\n"
                "sha256h        q0, q0, v0.4s"          "\n"
                :
                :
                : "v0"
        );
}


static void
try_compnum(void)
{
	asm volatile (
                "fmov	d0, #0"                         "\n"
                "fcadd	v0.2s, v0.2s, v0.2s, #90"       "\n"
                :
                :
                : "v0"
        );
}


static void
try_flagm(void)
{
	asm volatile (
                "cfinv"        "\n"
                "cfinv"        "\n"
        );
}

static void
try_flagm2(void)
{
	asm volatile (
                "axflag"        "\n"
                "xaflag"        "\n"
        );
}

static void
try_dotprod(void)
{
	asm volatile (
                "udot v0.4S,v1.16B,v2.16B"
                :
                :
                : "v0"
        );
}

static void
try_rdm(void)
{
	asm volatile (
                "sqrdmlah s0, s1, s2"
                :
                :
                : "s0"
        );
}

static void
try_sb(void)
{
	asm volatile (
                "sb"
        );
}

static void
try_frintts(void)
{
	asm volatile (
                "frint32x s0, s0"
                :
                :
                : "s0"
        );
}

static void
try_jscvt(void)
{
	asm volatile (
                "fmov	d0, #0"      "\n"
                "fjcvtzs w1, d0"     "\n"
                :
                :
                : "w1", "d0"
        );
}

static void
try_pauth(void)
{
	asm volatile (
                "pacga x0, x0, x0"
                :
                :
                : "x0"
        );
}

static void
try_dpb(void)
{
	int x;
	asm volatile (
                "dc cvap, %0"
                :
                : "r" (&x)
        );
}

static void
try_dpb2(void)
{
	int x;
	asm volatile (
                "dc cvadp, %0"
                :
                : "r" (&x)
        );
}

static void
try_lrcpc(void)
{
	int x;
	asm volatile (
                "ldaprb w0, [%0]"
                :
                : "r" (&x)
                : "w0"
        );
}

static void
try_lrcpc2(void)
{
	int x;
	asm volatile (
                "ldapurb w0, [%0]"
                :
                : "r" (&x)
                : "w0"
        );
}


static void
try_specres(void)
{
	int x;
	asm volatile (
                "cfp rctx, %0"
                :
                : "r" (&x)
        );
}

static void
try_bf16(void)
{
	asm volatile (
                "bfdot v0.4S,v1.8H,v2.8H"
                :
                :
                : "v0"
        );
}

static void
try_i8mm(void)
{
	asm volatile (
                "sudot v0.4S,v1.16B,v2.4B[0]"
                :
                :
                : "v0"
        );
}

static void
try_ecv(void)
{
	/*
	 * These registers are present only when FEAT_ECV is implemented.
	 * Otherwise, direct accesses to CNTPCTSS_EL0 or CNTVCTSS_EL0 are UNDEFINED.
	 */
	(void)__builtin_arm_rsr64("CNTPCTSS_EL0");
	(void)__builtin_arm_rsr64("CNTVCTSS_EL0");
}

static void
try_afp(void)
{
	/*
	 * FEAT_AFP can be detected via three new FPCR bits which were
	 * previously marked read-as-zero.
	 */
	const uint64_t FPCR_AFP_FLAGS = (1 << 0) | (1 << 1) | (1 << 2);

	uint64_t old_fpcr = __builtin_arm_rsr64("FPCR");
	__builtin_arm_wsr64("FPCR", old_fpcr | FPCR_AFP_FLAGS);
	uint64_t new_fpcr = __builtin_arm_rsr64("FPCR");
	__builtin_arm_wsr64("FPCR", old_fpcr);

	if ((new_fpcr & FPCR_AFP_FLAGS) != FPCR_AFP_FLAGS) {
		cap_usable = false;
	}
}

static void
try_rpres(void)
{
	/*
	 * When FEAT_RPRES is enabled via FPCR.AH, floating-point reciprocal
	 * estimate instructions increase precision from 8 mantissa bits to 12
	 * mantissa bits.  This can be detected by estimating 1/10.0 (which has
	 * no exact floating-point representation) and checking bits 11-14.
	 */
	const uint64_t FPCR_AH = (1 << 1);
	const uint32_t EXTRA_MANTISSA_BITS = (0xf << 11);

	uint32_t recip;
	uint64_t old_fpcr = __builtin_arm_rsr64("FPCR");
	__builtin_arm_wsr64("FPCR", old_fpcr | FPCR_AH);
	asm volatile (
                "fmov	s0, #10.0"      "\n"
                "frecpe s0, s0"         "\n"
                "fmov   %w0, s0"        "\n"
                : "=r"(recip)
                :
                : "s0"
        );
	__builtin_arm_wsr64("FPCR", old_fpcr);

	if ((recip & EXTRA_MANTISSA_BITS) == 0) {
		cap_usable = false;
	}
}

__attribute__((target("wfxt")))
static void
try_wfxt(void)
{
	asm volatile ("wfet xzr");
}

static void
try_sme(void)
{
	asm volatile (
               "rdsvl	x0, #1"
               :
               :
               : "x0"
        );
}

static void
try_sme2(void)
{
	asm volatile (
               "smstart za"             "\n"
               "zero    { zt0 }"        "\n"
               "smstop  za"             "\n"
        );
}

static void
try_sme_f32f32(void)
{
	asm volatile (
               "smstart"                                "\n"
               "fmopa   za0.s, p0/m, p0/m, z0.s, z0.s"  "\n"
               "smstop"                                 "\n"
        );
}

static void
try_sme_bi32i32(void)
{
	asm volatile (
               "smstart"                                "\n"
               "bmopa   za0.s, p0/m, p0/m, z0.s, z0.s"  "\n"
               "smstop"                                 "\n"
        );
}

static void
try_sme_b16f32(void)
{
	asm volatile (
               "smstart"                                "\n"
               "bfmopa  za0.s, p0/m, p0/m, z0.h, z0.h"  "\n"
               "smstop"                                 "\n"
        );
}

static void
try_sme_f16f32(void)
{
	asm volatile (
               "smstart"                                "\n"
               "fmopa   za0.s, p0/m, p0/m, z0.h, z0.h"  "\n"
               "smstop"                                 "\n"
        );
}

static void
try_sme_i8i32(void)
{
	asm volatile (
               "smstart"                                "\n"
               "smopa   za0.s, p0/m, p0/m, z0.b, z0.b"  "\n"
               "smstop"                                 "\n"
        );
}

static void
try_sme_i16i32(void)
{
	asm volatile (
               "smstart"                                "\n"
               "smopa   za0.s, p0/m, p0/m, z0.h, z0.h"  "\n"
               "smstop"                                 "\n"
        );
}

__attribute__((target("sme-f64f64")))
static void
try_sme_f64f64(void)
{
	asm volatile (
               "smstart"                                "\n"
               "fmopa   za0.d, p0/m, p0/m, z0.d, z0.d"  "\n"
               "smstop"                                 "\n"
        );
}

__attribute__((target("sme-i16i64")))
static void
try_sme_i16i64(void)
{
	asm volatile (
               "smstart"                                "\n"
               "smopa   za0.d, p0/m, p0/m, z0.h, z0.h"  "\n"
               "smstop"                                 "\n"
        );
}


static void
try_fpexcp(void)
{
	/* FP Exceptions are supported if all exceptions bit can be set. */
	const uint64_t flags = (1 << 8) | (1 << 9) | (1 << 10) | (1 << 11) | (1 << 12) | (1 << 15);

	uint64_t old_fpcr = __builtin_arm_rsr64("FPCR");
	__builtin_arm_wsr64("FPCR", old_fpcr | flags);
	uint64_t new_fpcr = __builtin_arm_rsr64("FPCR");
	__builtin_arm_wsr64("FPCR", old_fpcr);

	if ((new_fpcr & flags) != flags) {
		cap_usable = false;
	}
}

static void
try_dit(void)
{
	asm volatile (
                "msr DIT, x0"
                :
                :
                : "x0"
        );
}

static mach_port_t exc_port;

static uint8_t hw_optional_arm_caps[(CAP_BIT_NB + 7) / 8];

static void
test_cpu_capability(const char *cap_name, uint64_t commpage_flag, const char *cap_sysctl, int cap_bit, void (*try_cpu_capability)(void))
{
	bool has_commpage_flag = commpage_flag != 0;
	uint64_t commpage_caps = _get_cpu_capabilities();
	bool commpage_flag_set = false;
	if (has_commpage_flag) {
		commpage_flag_set = (commpage_caps & commpage_flag);
	}

	bool has_sysctl = cap_sysctl != NULL;
	int sysctl_val;
	bool sysctl_flag_set = false;
	if (has_sysctl) {
		size_t sysctl_size = sizeof(sysctl_val);
		int err = sysctlbyname(cap_sysctl, &sysctl_val, &sysctl_size, NULL, 0);
		sysctl_flag_set = (err == 0 && sysctl_val > 0);
	}

	bool has_cap_bit = (cap_bit != -1);
	bool cap_bit_set = false;
	if (has_cap_bit) {
		size_t idx = (unsigned int)cap_bit / 8;
		unsigned int bit = 1U << (cap_bit % 8);
		cap_bit_set = (hw_optional_arm_caps[idx] & bit);
	}

	bool has_capability = has_commpage_flag ? commpage_flag_set : sysctl_flag_set;

	if (!has_commpage_flag && !has_sysctl) {
		T_FAIL("Tested capability must have either sysctl or commpage flag");
		return;
	}

	if (has_commpage_flag && has_sysctl) {
		T_EXPECT_EQ(commpage_flag_set, sysctl_flag_set, "%s commpage flag matches sysctl flag", cap_name);
	}
	if (has_commpage_flag && has_cap_bit) {
		T_EXPECT_EQ(commpage_flag_set, cap_bit_set, "%s commpage flag matches hw.optional.arm.caps bit", cap_name);
	}
	if (has_sysctl && has_cap_bit) {
		T_EXPECT_EQ(sysctl_flag_set, cap_bit_set, "%s sysctl flag matches hw.optional.arm.caps bit", cap_name);
	}

	if (try_cpu_capability != NULL) {
		cap_usable = true;
		try_cpu_capability();
		T_EXPECT_EQ(has_capability, cap_usable, "%s capability matches actual usability", cap_name);
	}
}

static inline void
test_deprecated_sysctl(const char *cap_name, uint64_t commpage_flag, const char *deprecated_sysctl)
{
	char *deprecated_cap_name;
	int err = asprintf(&deprecated_cap_name, "%s (deprecated sysctl)", cap_name);
	T_QUIET; T_ASSERT_NE(err, -1, "asprintf");
	test_cpu_capability(deprecated_cap_name, commpage_flag, deprecated_sysctl, -1, NULL);
	free(deprecated_cap_name);
}

T_DECL(cpu_capabilities, "Verify ARM CPU capabilities", T_META_TAG_VM_NOT_ELIGIBLE) {
	T_SETUPBEGIN;
	size_t hw_optional_arm_caps_size = sizeof(hw_optional_arm_caps);
	int err = sysctlbyname("hw.optional.arm.caps", hw_optional_arm_caps, &hw_optional_arm_caps_size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(err, "sysctlbyname(\"hw.optional.arm.caps\")");

	exc_port = create_exception_port(EXC_MASK_BAD_INSTRUCTION);
	T_SETUPEND;

	repeat_exception_handler(exc_port, bad_instruction_handler);

	test_deprecated_sysctl("FP16", kHasFeatFP16, "hw.optional.neon_fp16");
	test_cpu_capability("FP16", kHasFeatFP16, "hw.optional.arm.FEAT_FP16", CAP_BIT_FEAT_FP16, try_fp16);
	test_deprecated_sysctl("LSE", kHasFeatLSE, "hw.optional.armv8_1_atomics");
	test_cpu_capability("LSE", kHasFeatLSE, "hw.optional.arm.FEAT_LSE", CAP_BIT_FEAT_LSE, try_atomics);
	test_deprecated_sysctl("CRC32", kHasARMv8Crc32, "hw.optional.armv8_crc32");
	test_cpu_capability("CRC32", kHasARMv8Crc32, "hw.optional.arm.FEAT_CRC32", CAP_BIT_FEAT_CRC32, try_crc32);
	test_deprecated_sysctl("FHM", kHasFeatFHM, "hw.optional.armv8_2_fhm");
	test_cpu_capability("FHM", kHasFeatFHM, "hw.optional.arm.FEAT_FHM", CAP_BIT_FEAT_FHM, try_fhm);
	test_deprecated_sysctl("SHA512", kHasFeatSHA512, "hw.optional.armv8_2_sha512");
	test_cpu_capability("SHA512", kHasFeatSHA512, "hw.optional.arm.FEAT_SHA512", CAP_BIT_FEAT_SHA512, try_sha512);
	test_deprecated_sysctl("SHA3", kHasFeatSHA3, "hw.optional.armv8_2_sha3");
	test_cpu_capability("SHA3", kHasFeatSHA3, "hw.optional.arm.FEAT_SHA3", CAP_BIT_FEAT_SHA3, try_sha3);
	test_cpu_capability("AES", kHasFeatAES, "hw.optional.arm.FEAT_AES", CAP_BIT_FEAT_AES, try_aes);
	test_cpu_capability("SHA1", kHasFeatSHA1, "hw.optional.arm.FEAT_SHA1", CAP_BIT_FEAT_SHA1, try_sha1);
	test_cpu_capability("SHA256", kHasFeatSHA256, "hw.optional.arm.FEAT_SHA256", CAP_BIT_FEAT_SHA256, try_sha256);
	test_cpu_capability("PMULL", kHasFeatPMULL, "hw.optional.arm.FEAT_PMULL", CAP_BIT_FEAT_PMULL, try_pmull);
	test_deprecated_sysctl("FCMA", kHasFeatFCMA, "hw.optional.armv8_3_compnum");
	test_cpu_capability("FCMA", kHasFeatFCMA, "hw.optional.arm.FEAT_FCMA", CAP_BIT_FEAT_FCMA, try_compnum);
	test_cpu_capability("FlagM", kHasFEATFlagM, "hw.optional.arm.FEAT_FlagM", CAP_BIT_FEAT_FlagM, try_flagm);
	test_cpu_capability("FlagM2", kHasFEATFlagM2, "hw.optional.arm.FEAT_FlagM2", CAP_BIT_FEAT_FlagM2, try_flagm2);
	test_cpu_capability("DotProd", kHasFeatDotProd, "hw.optional.arm.FEAT_DotProd", CAP_BIT_FEAT_DotProd, try_dotprod);
	test_cpu_capability("RDM", kHasFeatRDM, "hw.optional.arm.FEAT_RDM", CAP_BIT_FEAT_RDM, try_rdm);
	test_cpu_capability("SB", kHasFeatSB, "hw.optional.arm.FEAT_SB", CAP_BIT_FEAT_SB, try_sb);
	test_cpu_capability("FRINTTS", kHasFeatFRINTTS, "hw.optional.arm.FEAT_FRINTTS", CAP_BIT_FEAT_FRINTTS, try_frintts);
	test_cpu_capability("JSCVT", kHasFeatJSCVT, "hw.optional.arm.FEAT_JSCVT", CAP_BIT_FEAT_JSCVT, try_jscvt);
	test_cpu_capability("PAuth", kHasFeatPAuth, "hw.optional.arm.FEAT_PAuth", CAP_BIT_FEAT_PAuth, try_pauth);
	test_cpu_capability("DBP", kHasFeatDPB, "hw.optional.arm.FEAT_DPB", CAP_BIT_FEAT_DPB, try_dpb);
	test_cpu_capability("DBP2", kHasFeatDPB2, "hw.optional.arm.FEAT_DPB2", CAP_BIT_FEAT_DPB2, try_dpb2);
	test_cpu_capability("SPECRES", kHasFeatSPECRES, "hw.optional.arm.FEAT_SPECRES", CAP_BIT_FEAT_SPECRES, try_specres);
	test_cpu_capability("LRCPC", kHasFeatLRCPC, "hw.optional.arm.FEAT_LRCPC", CAP_BIT_FEAT_LRCPC, try_lrcpc);
	test_cpu_capability("LRCPC2", kHasFeatLRCPC2, "hw.optional.arm.FEAT_LRCPC2", CAP_BIT_FEAT_LRCPC2, try_lrcpc2);
	test_cpu_capability("AFP", kHasFeatAFP, "hw.optional.arm.FEAT_AFP", CAP_BIT_FEAT_AFP, try_afp);
	test_cpu_capability("DIT", kHasFeatDIT, "hw.optional.arm.FEAT_DIT", CAP_BIT_FEAT_DIT, try_dit);
	test_cpu_capability("FP16", kHasFP_SyncExceptions, "hw.optional.arm.FP_SyncExceptions", -1, try_fpexcp);
	test_cpu_capability("SME", kHasFeatSME, "hw.optional.arm.FEAT_SME", CAP_BIT_FEAT_SME, try_sme);
	test_cpu_capability("SME2", kHasFeatSME2, "hw.optional.arm.FEAT_SME2", CAP_BIT_FEAT_SME2, try_sme2);

	// The following features do not have a commpage entry
	test_cpu_capability("BF16", 0, "hw.optional.arm.FEAT_BF16", CAP_BIT_FEAT_BF16, try_bf16);
	test_cpu_capability("I8MM", 0, "hw.optional.arm.FEAT_I8MM", CAP_BIT_FEAT_I8MM, try_i8mm);
	test_cpu_capability("ECV", 0, "hw.optional.arm.FEAT_ECV", CAP_BIT_FEAT_ECV, try_ecv);
	test_cpu_capability("RPRES", 0, "hw.optional.arm.FEAT_RPRES", CAP_BIT_FEAT_RPRES, try_rpres);
	test_cpu_capability("WFxT", 0, "hw.optional.arm.FEAT_WFxT", CAP_BIT_FEAT_WFxT, try_wfxt);
	test_cpu_capability("SME_F32F32", 0, "hw.optional.arm.SME_F32F32", CAP_BIT_SME_F32F32, try_sme_f32f32);
	test_cpu_capability("SME_BI32I32", 0, "hw.optional.arm.SME_BI32I32", CAP_BIT_SME_BI32I32, try_sme_bi32i32);
	test_cpu_capability("SME_B16F32", 0, "hw.optional.arm.SME_B16F32", CAP_BIT_SME_B16F32, try_sme_b16f32);
	test_cpu_capability("SME_F16F32", 0, "hw.optional.arm.SME_F16F32", CAP_BIT_SME_F16F32, try_sme_f16f32);
	test_cpu_capability("SME_I8I32", 0, "hw.optional.arm.SME_I8I32", CAP_BIT_SME_I8I32, try_sme_i8i32);
	test_cpu_capability("SME_I16I32", 0, "hw.optional.arm.SME_I16I32", CAP_BIT_SME_I16I32, try_sme_i16i32);
	test_cpu_capability("SME_F64F64", 0, "hw.optional.arm.FEAT_SME_F64F64", CAP_BIT_FEAT_SME_F64F64, try_sme_f64f64);
	test_cpu_capability("SME_I16I64", 0, "hw.optional.arm.FEAT_SME_I16I64", CAP_BIT_FEAT_SME_I16I64, try_sme_i16i64);

	// The following features do not add instructions or registers to test for the presence of
	test_deprecated_sysctl("PACIMP", kHasArmv8GPI, "hw.optional.armv8_gpi");
	test_cpu_capability("PACIMP", kHasArmv8GPI, "hw.optional.arm.FEAT_PACIMP", CAP_BIT_FEAT_PACIMP, NULL);
	test_cpu_capability("LSE2", kHasFeatLSE2, "hw.optional.arm.FEAT_LSE2", CAP_BIT_FEAT_LSE2, NULL);
	test_cpu_capability("CSV2", kHasFeatCSV2, "hw.optional.arm.FEAT_CSV2", CAP_BIT_FEAT_CSV2, NULL);
	test_cpu_capability("CSV3", kHasFeatCSV3, "hw.optional.arm.FEAT_CSV3", CAP_BIT_FEAT_CSV3, NULL);
}
