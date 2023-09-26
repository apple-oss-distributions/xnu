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

#include <darwintest.h>
#include <machine/cpu_capabilities.h>
#include <sys/sysctl.h>

#include "exc_helpers.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.arm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("arm"),
	T_META_OWNER("sdooher"),
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

static void
test_cpu_capability(const char *cap_name, uint64_t cap_flag, bool has_commpage_entry, const char *cap_sysctl, void (*try_cpu_capability)(void))
{
	uint64_t caps = _get_cpu_capabilities();
	bool has_cap_flag = (caps & cap_flag);

	int sysctl_val;
	bool has_sysctl_flag = 0;
	if (cap_sysctl != NULL) {
		size_t sysctl_size = sizeof(sysctl_val);
		int err = sysctlbyname(cap_sysctl, &sysctl_val, &sysctl_size, NULL, 0);
		has_sysctl_flag = (err == 0 && sysctl_val > 0);
	}

	bool has_capability = has_commpage_entry ? has_cap_flag : has_sysctl_flag;

	if (!has_commpage_entry && cap_sysctl == NULL) {
		T_FAIL("Tested capability must have either sysctl or commpage flag");
		return;
	}

	if (has_commpage_entry && cap_sysctl != NULL) {
		T_EXPECT_EQ(has_cap_flag, has_sysctl_flag, "%s commpage flag matches sysctl flag", cap_name);
	}

	if (try_cpu_capability != NULL) {
		cap_usable = true;
		try_cpu_capability();
		T_EXPECT_EQ(has_capability, cap_usable, "%s capability matches actual usability", cap_name);
	}
}

T_DECL(cpu_capabilities, "Verify ARM CPU capabilities") {
	exc_port = create_exception_port(EXC_MASK_BAD_INSTRUCTION);
	repeat_exception_handler(exc_port, bad_instruction_handler);

	test_cpu_capability("FP16 (deprecated sysctl)", kHasFeatFP16, true, "hw.optional.neon_fp16", NULL);
	test_cpu_capability("FP16", kHasFeatFP16, true, "hw.optional.arm.FEAT_FP16", try_fp16);
	test_cpu_capability("LSE (deprecated sysctl)", kHasFeatLSE, true, "hw.optional.armv8_1_atomics", NULL);
	test_cpu_capability("LSE", kHasFeatLSE, true, "hw.optional.arm.FEAT_LSE", try_atomics);
	test_cpu_capability("CRC32", kHasARMv8Crc32, true, "hw.optional.armv8_crc32", try_crc32);
	test_cpu_capability("FHM (deprecated sysctl)", kHasFeatFHM, true, "hw.optional.armv8_2_fhm", NULL);
	test_cpu_capability("FHM", kHasFeatFHM, true, "hw.optional.arm.FEAT_FHM", try_fhm);
	test_cpu_capability("SHA512", kHasFeatSHA512, true, "hw.optional.armv8_2_sha512", try_sha512);
	test_cpu_capability("SHA3", kHasFeatSHA3, true, "hw.optional.armv8_2_sha3", try_sha3);
	test_cpu_capability("AES", kHasFeatAES, true, "hw.optional.arm.FEAT_AES", try_aes);
	test_cpu_capability("SHA1", kHasFeatSHA1, true, "hw.optional.arm.FEAT_SHA1", try_sha1);
	test_cpu_capability("SHA256", kHasFeatSHA256, true, "hw.optional.arm.FEAT_SHA256", try_sha256);
	test_cpu_capability("PMULL", kHasFeatPMULL, true, "hw.optional.arm.FEAT_PMULL", try_pmull);
	test_cpu_capability("FCMA (deprecated sysctl)", kHasFeatFCMA, true, "hw.optional.armv8_3_compnum", NULL);
	test_cpu_capability("FCMA", kHasFeatFCMA, true, "hw.optional.arm.FEAT_FCMA", try_compnum);
	test_cpu_capability("FlagM", kHasFEATFlagM, true, "hw.optional.arm.FEAT_FlagM", try_flagm);
	test_cpu_capability("FlagM2", kHasFEATFlagM2, true, "hw.optional.arm.FEAT_FlagM2", try_flagm2);
	test_cpu_capability("DotProd", kHasFeatDotProd, true, "hw.optional.arm.FEAT_DotProd", try_dotprod);
	test_cpu_capability("RDM", kHasFeatRDM, true, "hw.optional.arm.FEAT_RDM", try_rdm);
	test_cpu_capability("SB", kHasFeatSB, true, "hw.optional.arm.FEAT_SB", try_sb);
	test_cpu_capability("FRINTTS", kHasFeatFRINTTS, true, "hw.optional.arm.FEAT_FRINTTS", try_frintts);
	test_cpu_capability("JSCVT", kHasFeatJSCVT, true, "hw.optional.arm.FEAT_JSCVT", try_jscvt);
	test_cpu_capability("PAuth", kHasFeatPAuth, true, "hw.optional.arm.FEAT_PAuth", try_pauth);
	test_cpu_capability("DBP", kHasFeatDPB, true, "hw.optional.arm.FEAT_DPB", try_dpb);
	test_cpu_capability("DBP2", kHasFeatDPB2, true, "hw.optional.arm.FEAT_DPB2", try_dpb2);
	test_cpu_capability("SPECRES", kHasFeatSPECRES, true, "hw.optional.arm.FEAT_SPECRES", try_specres);
	test_cpu_capability("LRCPC", kHasFeatLRCPC, true, "hw.optional.arm.FEAT_LRCPC", try_lrcpc);
	test_cpu_capability("LRCPC2", kHasFeatLRCPC2, true, "hw.optional.arm.FEAT_LRCPC2", try_lrcpc2);
	test_cpu_capability("DIT", kHasFeatDIT, true, "hw.optional.arm.FEAT_DIT", try_dit);
	test_cpu_capability("FP16", kHasFP_SyncExceptions, true, "hw.optional.arm.FP_SyncExceptions", try_fpexcp);

	// The following features do not have a commpage entry
	test_cpu_capability("BF16", 0, false, "hw.optional.arm.FEAT_BF16", try_bf16);
	test_cpu_capability("I8MM", 0, false, "hw.optional.arm.FEAT_I8MM", try_i8mm);
	test_cpu_capability("ECV", 0, false, "hw.optional.arm.FEAT_ECV", try_ecv);

	// The following features do not add instructions or registers to test for the presence of
	test_cpu_capability("LSE2", kHasFeatLSE2, true, "hw.optional.arm.FEAT_LSE2", NULL);
	test_cpu_capability("CSV2", kHasFeatCSV2, true, "hw.optional.arm.FEAT_CSV2", NULL);
	test_cpu_capability("CSV3", kHasFeatCSV3, true, "hw.optional.arm.FEAT_CSV3", NULL);
}
