/* Copyright (c) (2011,2014,2015,2018,2019,2021,2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
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

#include <corecrypto/cc_config.h>
#include "ccmode_internal.h"
#include "ccn_internal.h"


#if (CCN_UNIT_SIZE == 8) && CC_DUNIT_SUPPORTED

// Binary multiplication, x * y = (r_hi << 64) | r_lo.
static void
bmul64(uint64_t x, uint64_t y, uint64_t *r_hi, uint64_t *r_lo)
{
	cc_dunit x1, x2, x3, x4, x5;
	cc_dunit y1, y2, y3, y4, y5;
	cc_dunit r, z;

	const cc_unit m1 = 0x1084210842108421;
	const cc_unit m2 = 0x2108421084210842;
	const cc_unit m3 = 0x4210842108421084;
	const cc_unit m4 = 0x8421084210842108;
	const cc_unit m5 = 0x0842108421084210;

	x1 = x & m1;
	y1 = y & m1;
	x2 = x & m2;
	y2 = y & m2;
	x3 = x & m3;
	y3 = y & m3;
	x4 = x & m4;
	y4 = y & m4;
	x5 = x & m5;
	y5 = y & m5;

	z = (x1 * y1) ^ (x2 * y5) ^ (x3 * y4) ^ (x4 * y3) ^ (x5 * y2);
	r = z & (((cc_dunit)m2 << 64) | m1);
	z = (x1 * y2) ^ (x2 * y1) ^ (x3 * y5) ^ (x4 * y4) ^ (x5 * y3);
	r |= z & (((cc_dunit)m3 << 64) | m2);
	z = (x1 * y3) ^ (x2 * y2) ^ (x3 * y1) ^ (x4 * y5) ^ (x5 * y4);
	r |= z & (((cc_dunit)m4 << 64) | m3);
	z = (x1 * y4) ^ (x2 * y3) ^ (x3 * y2) ^ (x4 * y1) ^ (x5 * y5);
	r |= z & (((cc_dunit)m5 << 64) | m4);
	z = (x1 * y5) ^ (x2 * y4) ^ (x3 * y3) ^ (x4 * y2) ^ (x5 * y1);
	r |= z & (((cc_dunit)m1 << 64) | m5);

	*r_hi = (uint64_t)(r >> 64);
	*r_lo = (uint64_t)r;
}

void
ccmode_gcm_gf_mult_64(const unsigned char *a, const unsigned char *b, unsigned char *c)
{
	cc_unit a_lo, a_hi, b_lo, b_hi;
	cc_unit z0_lo, z0_hi, z1_lo, z1_hi, z2_lo, z2_hi;
	cc_dunit z_hi, z_lo;

	a_lo = cc_load64_be(a + 8);;
	a_hi = cc_load64_be(a);

	b_lo = cc_load64_be(b + 8);
	b_hi = cc_load64_be(b);

	// Binary Karatsuba multiplication z = a * b.
	bmul64(a_lo, b_lo, &z0_hi, &z0_lo);
	bmul64(a_hi, b_hi, &z2_hi, &z2_lo);
	bmul64(a_hi ^ a_lo, b_hi ^ b_lo, &z1_hi, &z1_lo);
	z1_hi ^= z2_hi ^ z0_hi;
	z1_lo ^= z2_lo ^ z0_lo;
	z_hi = ((cc_dunit)z2_hi << 64) | (z2_lo ^ z1_hi);
	z_lo = (((cc_dunit)z0_hi << 64) | z0_lo) ^ (((cc_dunit)z1_lo) << 64);

	// Shift left by one to get reflected(a * b).
	z_hi = (z_hi << 1) | (z_lo >> 127);
	z_lo <<= 1;

	// Reduce.
	z_lo ^= (z_lo << 126) ^ (z_lo << 121);
	z_hi ^= z_lo ^ (z_lo >> 1) ^ (z_lo >> 2) ^ (z_lo >> 7);

	cc_store64_be((cc_unit)z_hi, c + 8);
	cc_store64_be((cc_unit)(z_hi >> 64), c);
}

#endif

// Binary multiplication, x * y = (r_hi << 32) | r_lo.
static void
bmul32(uint32_t x, uint32_t y, uint32_t *r_hi, uint32_t *r_lo)
{
	uint32_t x0, x1, x2, x3;
	uint32_t y0, y1, y2, y3;
	uint64_t z, z0, z1, z2, z3;

	const uint32_t m1 = 0x11111111;
	const uint32_t m2 = 0x22222222;
	const uint32_t m4 = 0x44444444;
	const uint32_t m8 = 0x88888888;

	x0 = x & m1;
	x1 = x & m2;
	x2 = x & m4;
	x3 = x & m8;
	y0 = y & m1;
	y1 = y & m2;
	y2 = y & m4;
	y3 = y & m8;

	z0 = ((uint64_t)x0 * y0) ^ ((uint64_t)x1 * y3) ^ ((uint64_t)x2 * y2) ^ ((uint64_t)x3 * y1);
	z1 = ((uint64_t)x0 * y1) ^ ((uint64_t)x1 * y0) ^ ((uint64_t)x2 * y3) ^ ((uint64_t)x3 * y2);
	z2 = ((uint64_t)x0 * y2) ^ ((uint64_t)x1 * y1) ^ ((uint64_t)x2 * y0) ^ ((uint64_t)x3 * y3);
	z3 = ((uint64_t)x0 * y3) ^ ((uint64_t)x1 * y2) ^ ((uint64_t)x2 * y1) ^ ((uint64_t)x3 * y0);

	z0 &= ((uint64_t)m1 << 32) | m1;
	z1 &= ((uint64_t)m2 << 32) | m2;
	z2 &= ((uint64_t)m4 << 32) | m4;
	z3 &= ((uint64_t)m8 << 32) | m8;
	z = z0 | z1 | z2 | z3;

	*r_hi = (uint32_t)(z >> 32);
	*r_lo = (uint32_t)z;
}

void
ccmode_gcm_gf_mult_32(const unsigned char *a, const unsigned char *b, unsigned char *c)
{
	uint32_t a_hi_h, a_hi_l, a_lo_h, a_lo_l;
	uint32_t b_hi_h, b_hi_l, b_lo_h, b_lo_l;

	uint64_t z_hi_h, z_hi_l, z_lo_h, z_lo_l;
	uint32_t z0_a_h, z0_a_l, z0_b_h, z0_b_l;
	uint32_t z1_a_h, z1_a_l, z1_b_h, z1_b_l;
	uint32_t z2_a_h, z2_a_l, z2_b_h, z2_b_l;

	uint32_t t_hi, t_lo;

	a_lo_l = cc_load32_be(a + 12);
	a_lo_h = cc_load32_be(a + 8);
	a_hi_l = cc_load32_be(a + 4);
	a_hi_h = cc_load32_be(a);

	uint32_t a_hiXlo_h = a_hi_h ^ a_lo_h;
	uint32_t a_hiXlo_l = a_hi_l ^ a_lo_l;

	b_lo_l = cc_load32_be(b + 12);
	b_lo_h = cc_load32_be(b + 8);
	b_hi_l = cc_load32_be(b + 4);
	b_hi_h = cc_load32_be(b);

	uint32_t b_hiXlo_h = b_hi_h ^ b_lo_h;
	uint32_t b_hiXlo_l = b_hi_l ^ b_lo_l;

	// Binary Karatsuba multiplication z = a * b.

	// a_lo * b_lo (64 bits)
	bmul32(a_lo_h, b_lo_h, &z0_a_h, &z0_a_l);
	bmul32(a_lo_l, b_lo_l, &z0_b_h, &z0_b_l);
	bmul32(a_lo_h ^ a_lo_l, b_lo_h ^ b_lo_l, &t_hi, &t_lo);
	t_hi ^= z0_a_h ^ z0_b_h;
	t_lo ^= z0_a_l ^ z0_b_l;
	z0_a_l ^= t_hi;
	z0_b_h ^= t_lo;

	// a_hi * b_hi (64 bits)
	bmul32(a_hi_h, b_hi_h, &z2_a_h, &z2_a_l);
	bmul32(a_hi_l, b_hi_l, &z2_b_h, &z2_b_l);
	bmul32(a_hi_h ^ a_hi_l, b_hi_h ^ b_hi_l, &t_hi, &t_lo);
	t_hi ^= z2_a_h ^ z2_b_h;
	t_lo ^= z2_a_l ^ z2_b_l;
	z2_a_l ^= t_hi;
	z2_b_h ^= t_lo;

	// (a_hi ^ a_lo) * (b_hi ^ b_lo) (64 bits)
	bmul32(a_hiXlo_h, b_hiXlo_h, &z1_a_h, &z1_a_l);
	bmul32(a_hiXlo_l, b_hiXlo_l, &z1_b_h, &z1_b_l);
	bmul32(a_hiXlo_h ^ a_hiXlo_l, b_hiXlo_h ^ b_hiXlo_l, &t_hi, &t_lo);
	t_hi ^= z1_a_h ^ z1_b_h;
	t_lo ^= z1_a_l ^ z1_b_l;
	z1_a_l ^= t_hi;
	z1_b_h ^= t_lo;

	// Another round of Karatsuba for a 128-bit result.
	z1_a_h ^= z0_a_h ^ z2_a_h;
	z1_a_l ^= z0_a_l ^ z2_a_l;
	z1_b_h ^= z0_b_h ^ z2_b_h;
	z1_b_l ^= z0_b_l ^ z2_b_l;
	z_hi_h = ((uint64_t)z2_a_h << 32) | z2_a_l;
	z_hi_l = (((uint64_t)z2_b_h << 32) | z2_b_l) ^ (((uint64_t)z1_a_h << 32) | z1_a_l);
	z_lo_h = (((uint64_t)z0_a_h << 32) | z0_a_l) ^ (((uint64_t)z1_b_h << 32) | z1_b_l);
	z_lo_l = ((uint64_t)z0_b_h << 32) | z0_b_l;

	// Shift left by one to get reflected(a * b).
	z_hi_h = (z_hi_h << 1) | (z_hi_l >> 63);
	z_hi_l = (z_hi_l << 1) | (z_lo_h >> 63);
	z_lo_h = (z_lo_h << 1) | (z_lo_l >> 63);
	z_lo_l <<= 1;

	// Reduce.
	z_lo_h ^= (z_lo_l << 62) ^ (z_lo_l << 57);
	z_hi_h ^= z_lo_h ^ (z_lo_h >> 1) ^ (z_lo_h >> 2) ^ (z_lo_h >> 7);
	z_hi_l ^= z_lo_l ^ (z_lo_l >> 1) ^ (z_lo_l >> 2) ^ (z_lo_l >> 7);
	z_hi_l ^= (z_lo_h << 63) ^ (z_lo_h << 62) ^ (z_lo_h << 57);

	cc_store64_be(z_hi_l, c + 8);
	cc_store64_be(z_hi_h, c);
}

void
ccmode_gcm_gf_mult(const unsigned char *a, const unsigned char *b, unsigned char *c)
{
#if (CCN_UNIT_SIZE == 8) && CC_DUNIT_SUPPORTED
	ccmode_gcm_gf_mult_64(a, b, c);
#else
	ccmode_gcm_gf_mult_32(a, b, c);
#endif
}
