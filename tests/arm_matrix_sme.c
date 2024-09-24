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

#include <stdint.h>
#include <stdlib.h>
#include <sys/sysctl.h>

#include "arm_matrix.h"

const static unsigned int SME_Z_VECTORS = 32;
const static unsigned int SME_P_VECTORS = 16;

static unsigned int
sme_version(void)
{
	static unsigned int ret = 0;
	static bool already_read = false;

	if (!already_read) {
		size_t size = sizeof(unsigned int);
		unsigned int feat_sme, feat_sme2;
		sysctlbyname("hw.optional.arm.FEAT_SME", &feat_sme, &size, NULL, 0);
		sysctlbyname("hw.optional.arm.FEAT_SME2", &feat_sme2, &size, NULL, 0);

		if (feat_sme2) {
			ret = 2;
		} else if (feat_sme) {
			ret = 1;
		} else {
			ret = 0;
		}

		already_read = true;
	}

	return ret;
}

static uint16_t
arm_sme_svl_b(void)
{
	uint64_t ret = 0;
	asm volatile (
                "rdsvl	%[ret], #1"
                : [ret] "=r"(ret)
        );
	return (uint16_t)ret;
}

static size_t
sme_za_size(void)
{
	return arm_sme_svl_b() * arm_sme_svl_b();
}

static size_t
sme_z_size(void)
{
	return arm_sme_svl_b() * SME_Z_VECTORS;
}

static size_t
sme_p_size(void)
{
	return arm_sme_svl_b() * SME_P_VECTORS / 8;
}

static size_t
sme_zt0_size(void)
{
	if (sme_version() >= 2) {
		return 64;
	} else {
		return 0;
	}
}

static size_t
sme_data_size(void)
{
	return sme_za_size() + sme_z_size() + sme_p_size() + sme_zt0_size();
}

static void *
sme_alloc_data(void)
{
	return malloc(sme_data_size());
}

static bool
sme_is_available(void)
{
	return sme_version() > 0;
}

static void
sme_start(void)
{
	asm volatile ("smstart");
}

static void
sme_stop(void)
{
	asm volatile ("smstop");
}

static void
sme_load_one_vector(const void *addr)
{
	asm volatile (
                "mov    w12, #0"                "\n"
                "ldr    za[w12, #0], [%[addr]]" "\n"
                :
                : [addr] "r"(addr)
                : "w12"
        );
}

static void
sme_load_data(const void *addr)
{
	const uint8_t *za = addr;
	const uint8_t *z = za + sme_za_size();
	const uint8_t *p = z + sme_z_size();
	uint16_t svl_b = arm_sme_svl_b();

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

	asm volatile (
                "ldr    z0, [%[z],   #0, mul vl]"        "\n"
                "ldr    z1, [%[z],   #1, mul vl]"        "\n"
                "ldr    z2, [%[z],   #2, mul vl]"        "\n"
                "ldr    z3, [%[z],   #3, mul vl]"        "\n"
                "ldr    z4, [%[z],   #4, mul vl]"        "\n"
                "ldr    z5, [%[z],   #5, mul vl]"        "\n"
                "ldr    z6, [%[z],   #6, mul vl]"        "\n"
                "ldr    z7, [%[z],   #7, mul vl]"        "\n"
                "ldr    z8, [%[z],   #8, mul vl]"        "\n"
                "ldr    z9, [%[z],   #9, mul vl]"        "\n"
                "ldr   z10, [%[z],  #10, mul vl]"        "\n"
                "ldr   z11, [%[z],  #11, mul vl]"        "\n"
                "ldr   z12, [%[z],  #12, mul vl]"        "\n"
                "ldr   z13, [%[z],  #13, mul vl]"        "\n"
                "ldr   z14, [%[z],  #14, mul vl]"        "\n"
                "ldr   z15, [%[z],  #15, mul vl]"        "\n"
                "ldr   z16, [%[z],  #16, mul vl]"        "\n"
                "ldr   z17, [%[z],  #17, mul vl]"        "\n"
                "ldr   z18, [%[z],  #18, mul vl]"        "\n"
                "ldr   z19, [%[z],  #19, mul vl]"        "\n"
                "ldr   z20, [%[z],  #20, mul vl]"        "\n"
                "ldr   z21, [%[z],  #21, mul vl]"        "\n"
                "ldr   z22, [%[z],  #22, mul vl]"        "\n"
                "ldr   z23, [%[z],  #23, mul vl]"        "\n"
                "ldr   z24, [%[z],  #24, mul vl]"        "\n"
                "ldr   z25, [%[z],  #25, mul vl]"        "\n"
                "ldr   z26, [%[z],  #26, mul vl]"        "\n"
                "ldr   z27, [%[z],  #27, mul vl]"        "\n"
                "ldr   z28, [%[z],  #28, mul vl]"        "\n"
                "ldr   z29, [%[z],  #29, mul vl]"        "\n"
                "ldr   z30, [%[z],  #30, mul vl]"        "\n"
                "ldr   z31, [%[z],  #31, mul vl]"        "\n"
                :
                : [z] "r"(z)
        );

	asm volatile (
                "ldr     p0, [%[p],  #0, mul vl]"        "\n"
                "ldr     p1, [%[p],  #1, mul vl]"        "\n"
                "ldr     p2, [%[p],  #2, mul vl]"        "\n"
                "ldr     p3, [%[p],  #3, mul vl]"        "\n"
                "ldr     p4, [%[p],  #4, mul vl]"        "\n"
                "ldr     p5, [%[p],  #5, mul vl]"        "\n"
                "ldr     p6, [%[p],  #6, mul vl]"        "\n"
                "ldr     p7, [%[p],  #7, mul vl]"        "\n"
                "ldr     p8, [%[p],  #8, mul vl]"        "\n"
                "ldr     p9, [%[p],  #9, mul vl]"        "\n"
                "ldr    p10, [%[p], #10, mul vl]"        "\n"
                "ldr    p11, [%[p], #11, mul vl]"        "\n"
                "ldr    p12, [%[p], #12, mul vl]"        "\n"
                "ldr    p13, [%[p], #13, mul vl]"        "\n"
                "ldr    p14, [%[p], #14, mul vl]"        "\n"
                "ldr    p15, [%[p], #15, mul vl]"        "\n"
                :
                : [p] "r"(p)
        );

	if (sme_zt0_size()) {
		const uint8_t *zt0 = p + sme_p_size();
		asm volatile (
                        "ldr	zt0, [%[zt0]]"
                        :
                        : [zt0] "r"(zt0)
                );
	}
}

static void
sme_store_data(void *addr)
{
	uint8_t *za = addr;
	uint8_t *z = za + sme_za_size();
	uint8_t *p = z + sme_z_size();
	uint16_t svl_b = arm_sme_svl_b();

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

	asm volatile (
                "str    z0, [%[z],   #0, mul vl]"        "\n"
                "str    z1, [%[z],   #1, mul vl]"        "\n"
                "str    z2, [%[z],   #2, mul vl]"        "\n"
                "str    z3, [%[z],   #3, mul vl]"        "\n"
                "str    z4, [%[z],   #4, mul vl]"        "\n"
                "str    z5, [%[z],   #5, mul vl]"        "\n"
                "str    z6, [%[z],   #6, mul vl]"        "\n"
                "str    z7, [%[z],   #7, mul vl]"        "\n"
                "str    z8, [%[z],   #8, mul vl]"        "\n"
                "str    z9, [%[z],   #9, mul vl]"        "\n"
                "str   z10, [%[z],  #10, mul vl]"        "\n"
                "str   z11, [%[z],  #11, mul vl]"        "\n"
                "str   z12, [%[z],  #12, mul vl]"        "\n"
                "str   z13, [%[z],  #13, mul vl]"        "\n"
                "str   z14, [%[z],  #14, mul vl]"        "\n"
                "str   z15, [%[z],  #15, mul vl]"        "\n"
                "str   z16, [%[z],  #16, mul vl]"        "\n"
                "str   z17, [%[z],  #17, mul vl]"        "\n"
                "str   z18, [%[z],  #18, mul vl]"        "\n"
                "str   z19, [%[z],  #19, mul vl]"        "\n"
                "str   z20, [%[z],  #20, mul vl]"        "\n"
                "str   z21, [%[z],  #21, mul vl]"        "\n"
                "str   z22, [%[z],  #22, mul vl]"        "\n"
                "str   z23, [%[z],  #23, mul vl]"        "\n"
                "str   z24, [%[z],  #24, mul vl]"        "\n"
                "str   z25, [%[z],  #25, mul vl]"        "\n"
                "str   z26, [%[z],  #26, mul vl]"        "\n"
                "str   z27, [%[z],  #27, mul vl]"        "\n"
                "str   z28, [%[z],  #28, mul vl]"        "\n"
                "str   z29, [%[z],  #29, mul vl]"        "\n"
                "str   z30, [%[z],  #30, mul vl]"        "\n"
                "str   z31, [%[z],  #31, mul vl]"        "\n"
                :
                : [z] "r"(z)
        );

	asm volatile (
                "str     p0, [%[p],  #0, mul vl]"        "\n"
                "str     p1, [%[p],  #1, mul vl]"        "\n"
                "str     p2, [%[p],  #2, mul vl]"        "\n"
                "str     p3, [%[p],  #3, mul vl]"        "\n"
                "str     p4, [%[p],  #4, mul vl]"        "\n"
                "str     p5, [%[p],  #5, mul vl]"        "\n"
                "str     p6, [%[p],  #6, mul vl]"        "\n"
                "str     p7, [%[p],  #7, mul vl]"        "\n"
                "str     p8, [%[p],  #8, mul vl]"        "\n"
                "str     p9, [%[p],  #9, mul vl]"        "\n"
                "str    p10, [%[p], #10, mul vl]"        "\n"
                "str    p11, [%[p], #11, mul vl]"        "\n"
                "str    p12, [%[p], #12, mul vl]"        "\n"
                "str    p13, [%[p], #13, mul vl]"        "\n"
                "str    p14, [%[p], #14, mul vl]"        "\n"
                "str    p15, [%[p], #15, mul vl]"        "\n"
                :
                : [p] "r"(p)
        );

	if (sme_zt0_size()) {
		uint8_t *zt0 = p + sme_p_size();
		asm volatile (
                        "str	zt0, [%[zt0]]"
                        :
                        : [zt0] "r"(zt0)
                );
	}
}

const struct arm_matrix_operations sme_operations = {
	.name = "SME",

	.data_size = sme_data_size,
	.alloc_data = sme_alloc_data,

	.is_available = sme_is_available,
	.start = sme_start,
	.stop = sme_stop,

	.load_one_vector = sme_load_one_vector,
	.load_data = sme_load_data,
	.store_data = sme_store_data,
};
