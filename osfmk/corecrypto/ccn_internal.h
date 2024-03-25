/* Copyright (c) (2017-2023) Apple Inc. All rights reserved.
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

#ifndef _CORECRYPTO_CCN_INTERNAL_H
#define _CORECRYPTO_CCN_INTERNAL_H

#include <corecrypto/ccn.h>
#include "cc_workspaces.h"
#include "cc_memory.h"
#include "cc_internal.h"

CC_PTRCHECK_CAPABLE_HEADER()

#if CCN_UNIT_SIZE == 8

 #if CC_DUNIT_SUPPORTED
typedef unsigned cc_dunit __attribute__((mode(TI)));
 #endif

#define cc_clz_nonzero cc_clz64
#define cc_ctz_nonzero cc_ctz64
#define CC_STORE_UNIT_BE(x, out) cc_store64_be(x, out)
#define CC_LOAD_UNIT_BE(x, out) (x = cc_load64_be(out))

#elif CCN_UNIT_SIZE == 4

typedef uint64_t cc_dunit;

#define cc_clz_nonzero cc_clz32
#define cc_ctz_nonzero cc_ctz32
#define CC_STORE_UNIT_BE(x, out) cc_store32_be(x, out)
#define CC_LOAD_UNIT_BE(x, out) (x = cc_load32_be(out))

#else

#error Unsupported CCN_UNIT_SIZE

#endif

#if CC_DUNIT_SUPPORTED

// r := x + y
#define CC_DUNIT_ADD(r, x, y, tmp)      \
    do {                             \
	tmp = ((cc_dunit)(x)) + (y); \
	r = (cc_unit)tmp;            \
    } while (0);

// r := x + y + (tmp >> 64)
#define CC_DUNIT_ADC(r, x, y, tmp)              \
    do {                                     \
	cc_unit _c = (tmp) >> CCN_UNIT_BITS; \
	tmp = ((cc_dunit)(x)) + (y) + _c;    \
	r = (cc_unit)tmp;                    \
    } while (0);

// r := x - y
#define CC_DUNIT_SUB(r, x, y, tmp)      \
    do {                             \
	tmp = ((cc_dunit)(x)) - (y); \
	r = (cc_unit)tmp;            \
    } while (0);

// r := x - y - (tmp >> 127)
#define CC_DUNIT_SBC(r, x, y, tmp)                        \
    do {                                               \
	cc_unit _b = (tmp) >> (2 * CCN_UNIT_BITS - 1); \
	tmp = ((cc_dunit)(x)) - (y) - _b;              \
	r = (cc_unit)tmp;                              \
    } while (0);

// (hi,lo) += (x * y)
#define CC_DUNIT_MUL(x, y, hi, lo, tmp)  \
    do {                              \
	tmp = (cc_dunit)(x) * (y);    \
	lo += (tmp) & CCN_UNIT_MASK;  \
	hi += (tmp) >> CCN_UNIT_BITS; \
    } while (0);

// (hi,lo) += (x * y) * i
#define CC_DUNIT_MULI(x, y, hi, lo, tmp, i)      \
    do {                                      \
	tmp = (cc_dunit)(x) * (y);            \
	lo += ((tmp) & CCN_UNIT_MASK) * (i);  \
	hi += ((tmp) >> CCN_UNIT_BITS) * (i); \
    } while (0);

// r := lo and (hi,lo) >>= 64
#define CC_STORE_LO(r, hi, lo)        \
    do {                           \
	r = (cc_unit)lo;           \
	hi += lo >> CCN_UNIT_BITS; \
	lo = hi & CCN_UNIT_MASK;   \
	hi >>= CCN_UNIT_BITS;      \
    } while (0);

#endif

CC_NONNULL((2, 3))
void ccn_set(cc_size n, cc_unit *cc_counted_by(n) r, const cc_unit *cc_counted_by(n) s);

CC_INLINE
CC_NONNULL((2, 4))
void
ccn_setn(cc_size n, cc_unit *cc_counted_by (n)r, const cc_size s_size, const cc_unit *cc_counted_by (s_size)s)
{
	cc_assert(n > 0 && s_size <= n);

	if (s_size > 0) {
		ccn_set(s_size, r, s);
	}

	ccn_zero(n - s_size, r + s_size);
}

CC_INLINE
CC_NONNULL((2))
void
ccn_clear(cc_size n, cc_unit *cc_sized_by (n)r)
{
	cc_clear(ccn_sizeof_n(n), r);
}

/* Returns the value of bit _k_ of _ccn_, both are only evaluated once.  */
CC_INLINE cc_unit
ccn_bit(const cc_unit *cc_indexable x, size_t k)
{
	return 1 & (x[k >> CCN_LOG2_BITS_PER_UNIT] >> (k & (CCN_UNIT_BITS - 1)));
}

/* |s - t| -> r return 1 iff t > s, 0 otherwise */
CC_WARN_RESULT
cc_unit ccn_abs(cc_size n, cc_unit *cc_counted_by(n) r, const cc_unit *cc_counted_by(n) s, const cc_unit *cc_counted_by(n) t);

/* Returns the number of bits which are zero before the first one bit
 *  counting from least to most significant bit. */
CC_WARN_RESULT
CC_NONNULL((2))
size_t ccn_trailing_zeros(cc_size n, const cc_unit *s);

/*! @function ccn_shift_right
 *  @abstract Shifts s to the right by k bits, where 0 <= k < CCN_UNIT_BITS.
 *
 *  @param n Length of r and s
 *  @param r Resulting big int.
 *  @param s Big int to shift.
 *  @param k Number of bits to shift by.
 */
CC_NONNULL_ALL
void ccn_shift_right(cc_size n, cc_unit *cc_counted_by(n) r, const cc_unit *cc_counted_by(n) s, size_t k) __asm__("_ccn_shift_right");

/*! @function ccn_shift_right_multi
 *  @abstract Constant-time, SPA-safe, right shift.
 *
 *  @param n Length of r and s as number of cc_units.
 *  @param r Destination, can overlap with s.
 *  @param s Input that's shifted by k bits.
 *  @param k Number of bits by which to shift s to the right.
 */
CC_NONNULL_ALL
void ccn_shift_right_multi(cc_size n, cc_unit *cc_counted_by(n) r, const cc_unit *cc_counted_by(n) s, size_t k);

/* s << k -> r return bits shifted out of most significant word in bits [0, n>
 *  { N bit, scalar -> N bit } N = n * sizeof(cc_unit) * 8
 *  the _multi version doesn't return the shifted bits, but does support multiple
 *  word shifts */
CC_NONNULL_ALL
void ccn_shift_left(cc_size n, cc_unit *cc_counted_by(n) r, const cc_unit *cc_counted_by(n) s, size_t k) __asm__("_ccn_shift_left");

CC_NONNULL_ALL
void ccn_shift_left_multi(cc_size n, cc_unit *cc_counted_by(n) r, const cc_unit *cc_counted_by(n) s, size_t k);

// Conditionally swap the content of r0 and r1 buffers in constant time
// r0:r1 <- r1*k1 + s0*(k1-1)
CC_NONNULL_ALL
void ccn_cond_swap(cc_size n, cc_unit ki, cc_unit *cc_counted_by(n) r0, cc_unit *cc_counted_by(n) r1);

/*! @function ccn_cond_shift_right
 *  @abstract Constant-time, SPA-safe, conditional right shift.
 *
 *  @param n Length of each of r and a as number of cc_units.
 *  @param s Selector bit (0 or 1).
 *  @param r Destination, can overlap with a.
 *  @param a Input that's shifted by k bits, if s=1.
 *  @param k Number of bits by which to shift a to the right, if s=1.
 *         (k must not be larger than CCN_UNIT_BITS.)
 */
CC_NONNULL_ALL
void ccn_cond_shift_right(cc_size n, cc_unit s, cc_unit *cc_counted_by(n) r, const cc_unit *cc_counted_by(n) a, size_t k);

/*! @function ccn_cond_neg
 *  @abstract Constant-time, SPA-safe, conditional negation.
 *
 *  @param n Length of each of r and x as number of cc_units.
 *  @param s Selector bit (0 or 1).
 *  @param r Destination, can overlap with x.
 *  @param x Input that's negated, if s=1.
 */
void ccn_cond_neg(cc_size n, cc_unit s, cc_unit *cc_counted_by(n) r, const cc_unit *cc_counted_by(n) x);

/*! @function ccn_cond_shift_right_carry
 *  @abstract Constant-time, SPA-safe, conditional right shift.
 *
 *  @param n Length of each of r and a as number of cc_units.
 *  @param s Selector bit (0 or 1).
 *  @param r Destination, can overlap with a.
 *  @param a Input that's shifted by k bits, if s=1.
 *  @param k Number of bits by which to shift a to the right, if s=1.
 *         (k must not be larger than CCN_UNIT_BITS.)
 *  @param c Carry bit(s), the most significant bit(s) after shifting, if s=1.
 */
CC_NONNULL_ALL
void ccn_cond_shift_right_carry(cc_size n, cc_unit s, cc_unit *cc_counted_by(n) r, const cc_unit *cc_counted_by(n) a, size_t k, cc_unit c);

/*! @function ccn_cond_add
 *  @abstract Constant-time, SPA-safe, conditional addition.
 *          Computes r:= x + y, iff s = 1. Set r := x otherwise.
 *
 *  @param n Length of each of r, x, and y as number of cc_units.
 *  @param s Selector bit (0 or 1).
 *  @param r Destination, can overlap with x or y.
 *  @param x First addend.
 *  @param y Second addend.
 *
 *  @return The carry bit, if s=1. 0 otherwise.
 */
CC_WARN_RESULT CC_NONNULL_ALL
cc_unit ccn_cond_add(cc_size n, cc_unit s, cc_unit *cc_counted_by(n) r, const cc_unit *cc_counted_by(n) x, const cc_unit *cc_counted_by(n) y);

/*! @function ccn_cond_rsub
 *  @abstract Constant-time, SPA-safe, conditional reverse subtraction.
 *          Computes r := y - x, iff s = 1. Sets r := x otherwise.
 *
 *  @param n Length of each of r, x, and y as number of cc_units.
 *  @param s Selector bit (0 or 1).
 *  @param r Destination, can overlap with x or y.
 *  @param x Subtrahend.
 *  @param y Minuend.
 *
 *  @return The carry bit, if s=1. 0 otherwise.
 */
CC_WARN_RESULT CC_NONNULL_ALL
cc_unit ccn_cond_rsub(cc_size n, cc_unit s, cc_unit *cc_counted_by(n) r, const cc_unit *cc_counted_by(n) x, const cc_unit *cc_counted_by(n) y);

/*! @function ccn_cond_sub
 *  @abstract Constant-time, SPA-safe, conditional subtraction.
 *          Computes r := x - y, iff s = 1. Sets r := x otherwise.
 *
 *  @param n Length of each of r, x, and y as number of cc_units.
 *  @param s Selector bit (0 or 1).
 *  @param r Destination, can overlap with x or y.
 *  @param x Minuend.
 *  @param y Subtrahend.
 *
 *  @return The carry bit, if s=1. 0 otherwise.
 */
CC_WARN_RESULT CC_NONNULL_ALL
cc_unit ccn_cond_sub(cc_size n, cc_unit s, cc_unit *cc_counted_by(n) r, const cc_unit *cc_counted_by(n) x, const cc_unit *cc_counted_by(n) y);

/*! @function ccn_cond_clear
 *  @abstract Constant-time, SPA-safe, conditional zeroization.
 *          Sets r := 0, if s = 1. Does nothing otherwise.
 *
 *  @param n Length of r as number of cc_units.
 *  @param s Selector bit (0 or 1).
 *  @param r Destination, can overlap with x or y.
 */
CC_NONNULL_ALL
void ccn_cond_clear(cc_size n, cc_unit s, cc_unit *r);

/*! @function ccn_mux
 *  @abstract Constant-time, SPA-safe multiplexer. Sets r = (s ? a : b).
 *
 *  @discussion This works like a normal multiplexer (s & a) | (~s & b) but is
 *            slightly more complicated and expensive. Out of `s` we build
 *            half-word masks to hide extreme Hamming weights of operands.
 *
 *  @param n Length of each of r, a, and b as number of cc_units.
 *  @param s Selector bit (0 or 1).
 *  @param r Destination, can overlap with a or b.
 *  @param a Input selected when s=1.
 *  @param b Input selected when s=0.
 */
CC_NONNULL_ALL
void ccn_mux(cc_size n, cc_unit s, cc_unit *cc_counted_by(n) r, const cc_unit *cc_counted_by(n) a, const cc_unit *cc_counted_by(n) b);

/*! @function ccn_gcd_ws
 *  @abstract Computes the greatest common divisor of s and t,
 *          r = gcd(s,t) / 2^k, and returns k.
 *
 *  @param ws Workspace.
 *  @param rn Length of r as a number of cc_units.
 *  @param r  Resulting GCD.
 *  @param sn Length of s as a number of cc_units.
 *  @param s  First number s.
 *  @param tn Length of t as a number of cc_units.
 *  @param t  First number t.
 *
 *  @return The factor of two to shift r by to compute the actual GCD.
 */
CC_WARN_RESULT
CC_NONNULL_ALL
size_t ccn_gcd_ws(cc_ws_t ws, cc_size rn, cc_unit *cc_counted_by(rn) r, cc_size sn, const cc_unit *cc_counted_by(sn) s, cc_size tn, const cc_unit *cc_counted_by(tn) t);

/*! @function ccn_lcm_ws
 *  @abstract Computes lcm(s,t), the least common multiple of s and t.
 *
 *  @param ws  Workspace.
 *  @param n   Length of s,t as a number of cc_units.
 *  @param r2n Resulting LCM of length 2*n.
 *  @param s   First number s.
 *  @param t   First number t.
 */
void ccn_lcm_ws(cc_ws_t ws, cc_size n, cc_unit *cc_unsafe_indexable r2n, const cc_unit *cc_counted_by(n)s, const cc_unit *cc_counted_by(n)t);

/* s * t -> r_2n                   r_2n must not overlap with s nor t
 *  { n bit, n bit -> 2 * n bit } n = count * sizeof(cc_unit) * 8
 *  { N bit, N bit -> 2N bit } N = ccn_bitsof(n) */
CC_NONNULL((2, 3, 4))
void ccn_mul(cc_size n, cc_unit *cc_unsafe_indexable r_2n, const cc_unit *cc_counted_by(n)s, const cc_unit *cc_counted_by(n)t) __asm__("_ccn_mul");

/* s[0..n) * v -> r[0..n)+return value
 *  { N bit, sizeof(cc_unit) * 8 bit -> N + sizeof(cc_unit) * 8 bit } N = n * sizeof(cc_unit) * 8 */
CC_WARN_RESULT
CC_NONNULL((2, 3))
cc_unit ccn_mul1(cc_size n, cc_unit *cc_counted_by(n) r, const cc_unit *cc_counted_by(n) s, const cc_unit v);

/* s[0..n) * v[0..nv] -> r[0..n+nv)
*  { n bit, nv bit -> n + nv bit} n = count * sizeof(cc_unit) * 8
*  { N bit, NV bit -> N + NV bit} N = ccn_bitsof(n), NV = ccn_bitsof(nv)
*  r, s, and v should not overlap
*  Leaks n and nv through timing */
CC_NONNULL_ALL
void ccn_muln(cc_size n, cc_unit *cc_counted_by(n + nv) r, const cc_unit *cc_counted_by(n) s, cc_size nv, const cc_unit *cc_counted_by(n) v);

/* s[0..n) * v + r[0..n) -> r[0..n)+return value
 *  { N bit, sizeof(cc_unit) * 8 bit -> N + sizeof(cc_unit) * 8 bit } N = n * sizeof(cc_unit) * 8 */
CC_WARN_RESULT
CC_NONNULL((2, 3))
cc_unit ccn_addmul1(cc_size n, cc_unit *cc_counted_by(n) r, const cc_unit *cc_counted_by(n) s, const cc_unit v);

/* s * t -> r_2n                   r_2n must not overlap with s nor t
 *  { n bit, n bit -> 2 * n bit } n = count * sizeof(cc_unit) * 8
 *  { N bit, N bit -> 2N bit } N = ccn_bitsof(n)
 *  Provide a workspace for potential speedup */
CC_NONNULL_ALL
void ccn_mul_ws(cc_ws_t ws, cc_size count, cc_unit *cc_unsafe_indexable r, const cc_unit *cc_counted_by(count)s, const cc_unit *cc_counted_by(count)t);

/* s^2 -> r
 *  { n bit -> 2 * n bit } */
CC_NONNULL_ALL
void ccn_sqr_ws(cc_ws_t ws, cc_size n, cc_unit *cc_unsafe_indexable r, const cc_unit *cc_counted_by(n)s);

/*! @function ccn_mod_ws
 *  @abstract Computes r = a % d.
 *
 *  @discussion Use CCN_DIVMOD_WORKSPACE_N(n) for the workspace.
 *
 *  @param ws  Workspace
 *  @param na  Length of a as a number of cc_units.
 *  @param a   The dividend a.
 *  @param n   Length of r,d as a number of cc_units.
 *  @param r   The resulting remainder.
 *  @param d   The divisor d.
 */
#define ccn_mod_ws(ws, na, a, n, r, d) ccn_divmod_ws(ws, na, a, 0, NULL, n, r, d)
#define ccn_mod(na, a, n, r, d) ccn_divmod(na, a, 0, NULL, n, r, d)

/*! @function ccn_neg
 *  @abstract Computes the two's complement of x.
 *
 *  @param n  Length of r and x
 *  @param r  Result of the negation
 *  @param x  Number to negate
 */
CC_NONNULL_ALL
void ccn_neg(cc_size n, cc_unit *cc_counted_by(n) r, const cc_unit *cc_counted_by(n) x);

/*! @function ccn_invert
 *  @abstract Computes x^-1 (mod 2^w).
 *
 *  @param x  Number to invert
 *
 *  @return x^-1 (mod 2^w)
 */
CC_WARN_RESULT
CC_CONST CC_NONNULL_ALL
CC_INLINE cc_unit
ccn_invert(cc_unit x)
{
	cc_assert(x & 1);

	// Initial precision is 5 bits.
	cc_unit y = (3 * x) ^ 2;

	// Newton-Raphson iterations.
	// Precision doubles with every step.
	y *= 2 - y * x;
	y *= 2 - y * x;
	y *= 2 - y * x;
#if CCN_UNIT_SIZE == 8
	y *= 2 - y * x;
#endif

	cc_assert(y * x == 1);
	return y;
}

/*! @function ccn_div_exact_ws
 *  @abstract Computes q = a / d where a = 0 (mod d).
 *
 *  @param ws  Workspace
 *  @param n   Length of q,a,d as a number of cc_units.
 *  @param q   The resulting exact quotient.
 *  @param a   The dividend a.
 *  @param d   The divisor d.
 */
CC_NONNULL_ALL
void ccn_div_exact_ws(cc_ws_t ws, cc_size n, cc_unit *cc_counted_by(n) q, const cc_unit *cc_counted_by(n) a, const cc_unit *cc_counted_by(n) d);

/*! @function ccn_divides1
 *  @abstract Returns whether q divides x.
 *
 *  @param n  Length of x as a number of cc_units.
 *  @param x  The dividend x.
 *  @param q  The divisor q.
 *
 *  @return True if q divides x without remainder, false otherwise.
 */
CC_WARN_RESULT
CC_NONNULL_ALL
bool ccn_divides1(cc_size n, const cc_unit *cc_counted_by(n)x, cc_unit q);

/*! @function ccn_select
 *  @abstract Select r[i] in constant-time, not revealing i via cache-timing.
 *
 *  @param start Start index.
 *  @param end   End index (length of r).
 *  @param r     Big int r.
 *  @param i     Offset into r.
 *
 *  @return r[i], or zero if start > i or end < i.
 */
CC_WARN_RESULT
CC_INLINE cc_unit
ccn_select(cc_size start, cc_size end, const cc_unit *cc_counted_by(end)r, cc_size i)
{
	cc_unit ri = 0;

	for (cc_size j = start; j < end; j++) {
		cc_size i_neq_j; // i≠j?
		CC_HEAVISIDE_STEP(i_neq_j, i ^ j);
		ri |= r[j] & ((cc_unit)i_neq_j - 1);
	}

	return ri;
}

/*! @function ccn_invmod_ws
 *  @abstract Computes the inverse of x modulo m, r = x^-1 (mod m).
 *          Returns an error if there's no inverse, i.e. gcd(x,m) ≠ 1.
 *
 *  @discussion This is a very generic version of the binary XGCD algorithm. You
 *            don't want to use it when you have an odd modulus.
 *
 *            This function is meant to be used by RSA key generation, for
 *            computation of d = e^1 (mod lcm(p-1,q-1)), where m can be even.
 *
 *            x > m is allowed as long as xn == n, i.e. they occupy the same
 *            number of cc_units.
 *
 *  @param ws Workspace.
 *  @param n  Length of r and m as a number of cc_units.
 *  @param r  The resulting inverse r.
 *  @param xn Length of x as a number of cc_units.
 *  @param x  The number to invert.
 *  @param m  The modulus.
 *
 *  @return 0 on success, non-zero on failure. See cc_error.h for more details.
 */
CC_WARN_RESULT
int ccn_invmod_ws(cc_ws_t ws, cc_size n, cc_unit *cc_counted_by(n) r, cc_size xn, const cc_unit *cc_counted_by(xn) x, const cc_unit *cc_counted_by(n) m);

/*! @function ccn_mux_seed_mask
 *  @abstract Refreshes the internal state of the PRNG used to mask cmov/cswap
 *          operations with a given seed.
 *
 *  @discussion The seed should be of good entropy, i.e. generated by our default
 *            RNG. This function should be called before running algorithms that
 *            defend against side-channel attacks by using cmov/cswap. Examples
 *            are blinded modular exponentation (for RSA, DH, or MR) and EC
 *            scalar multiplication.
 *
 *  @param seed A seed value.
 */
void ccn_mux_seed_mask(cc_unit seed);

/*! @function ccn_divmod
 *  @abstract Computes a = q * d + r with r < d.
 *
 *  @param na  Length of a as a number of cc_units.
 *  @param a   The dividend a.
 *  @param nq  Length of q as a number of cc_units.
 *  @param q   The quotient q.
 *  @param n   Length of r and d as a number of cc_units.
 *  @param r   The remainder r.
 *  @param d   The divisor d.
 *
 *  @return 0 on success, non-zero on failure. See cc_error.h for more details.
 */
CC_NONNULL((2, 7)) CC_WARN_RESULT
int ccn_divmod(cc_size na, const cc_unit *cc_counted_by(na) a, cc_size nq, cc_unit *cc_counted_by(nq) q, cc_size n, cc_unit *cc_counted_by(n) r, const cc_unit *cc_counted_by(n) d);

CC_NONNULL((1, 3, 8))
void ccn_divmod_ws(cc_ws_t ws, cc_size na, const cc_unit *cc_counted_by(na) a, cc_size nq, cc_unit *cc_counted_by(nq) q, cc_size n, cc_unit *cc_counted_by(n) r, const cc_unit *cc_counted_by(n) d);

CC_NONNULL((2)) CC_SENTINEL
void ccn_zero_multi(cc_size n, cc_unit *r, ...);

CC_NONNULL((3, 4, 5))
cc_unit ccn_add_ws(cc_ws_t ws, cc_size count, cc_unit *r, const cc_unit *s, const cc_unit *t);

CC_NONNULL((3, 4, 5))
cc_unit ccn_sub_ws(cc_ws_t ws, cc_size count, cc_unit *r, const cc_unit *s, const cc_unit *t);

CC_NONNULL((3, 4))
cc_unit ccn_add1_ws(cc_ws_t ws, cc_size n, cc_unit *r, const cc_unit *s, cc_unit v);

/* s + t -> r return carry if result doesn't fit in n bits
 *  { N bit, NT bit -> N bit  NT <= N} N = n * sizeof(cc_unit) * 8 */
CC_NONNULL_ALL
cc_unit ccn_addn(cc_size n, cc_unit *cc_counted_by(n) r, const cc_unit *cc_counted_by(n) s, cc_size nt, const cc_unit *cc_counted_by(nt) t);

/* s - v -> r return 1 iff v > s return 0 otherwise.
 *  { N bit, sizeof(cc_unit) * 8 bit -> N bit } N = n * sizeof(cc_unit) * 8 */
CC_NONNULL_ALL
cc_unit ccn_sub1(cc_size n, cc_unit *cc_counted_by(n) r, const cc_unit *cc_counted_by(n) s, cc_unit v);

/* s - t -> r return 1 iff t > s
 *  { N bit, NT bit -> N bit  NT <= N} N = n * sizeof(cc_unit) * 8 */
CC_NONNULL_ALL
cc_unit ccn_subn(cc_size n, cc_unit *cc_counted_by(n) r, const cc_unit *cc_counted_by(n) s, cc_size nt, const cc_unit *cc_counted_by(nt) t);

/* Return the number of used units after stripping leading 0 units.  */
CC_NONNULL_ALL
cc_size ccn_n(cc_size n, const cc_unit *cc_counted_by(n)s);

/* Make a ccn of size ccn_nof(nbits) units with up to nbits sized random value. */
CC_NONNULL_ALL
int ccn_random_bits(cc_size nbits, cc_unit *cc_unsafe_indexable r, struct ccrng_state *rng);

/* Like ccn_random_bits, but uses ccrng_generate_fips under the hood. */
CC_NONNULL_ALL
int ccn_random_bits_fips(cc_size nbits, cc_unit *cc_unsafe_indexable r, struct ccrng_state *rng);

// Joint Sparse Form recoding context for EC double-scalar multiplication.
struct ccn_rjsf_state {
	uint8_t u[2];
	const cc_unit *s;
	const cc_unit *t;
};

/*! @function ccn_recode_jsf_init
 *  @abstract Initialize Joint Sparse Form recoding for EC scalars s and t.
 *
 *  @param r     JSF-recoding context.
 *  @param nbits Max. bit length of s and t.
 *  @param s     Scalar to be recoded.
 *  @param t     Scalar to be recoded.
 */
CC_NONNULL_ALL
void ccn_recode_jsf_init(struct ccn_rjsf_state *r, size_t nbits, const cc_unit *s, const cc_unit *t);

/*! @function ccn_recode_jsf_column
 *  @abstract Retrieve JSF-recoded digits for column k.
 *
 *  @param r JSF-recoding context.
 *  @param k Column index.
 *  @param c Digits (output).
 */
CC_NONNULL_ALL
void ccn_recode_jsf_column(struct ccn_rjsf_state *r, size_t k, int c[2]);

/*! @function ccn_recode_jsf_index
 *  @abstract Retrieve the lookup table index for given column digits.
 *
 *  @discussion For EC double-scalar multiplication, we assume a lookup table
 *            holding the four values [P, Q, P+Q, P-Q], in the same order.
 *
 *  @param c Column digits.
 *
 *  @return The lookup table index.
 */
CC_NONNULL_ALL CC_WARN_RESULT
size_t ccn_recode_jsf_index(int c[2]);

/*! @function ccn_recode_jsf_direction
 *  @abstract Retrieve the "direction" for given column digits.
 *
 *  @discussion For EC double-scalar multiplication, we assume a lookup table
 *            holding the four values [P, Q, P+Q, P-Q]. Negating each of
 *            these also yields [-P, -Q, -P-Q, -P+Q].
 *
 *            An EC double-and-add algorithm will either add or subtract a
 *            precomputed point to cover all possible digit combinations of two
 *            JSF-recoded EC scalars.
 *
 *  @param c Column digits.
 *
 *  @return The "direction". 1 for addition. -1 for subtraction.
 */
CC_NONNULL_ALL CC_WARN_RESULT
int ccn_recode_jsf_direction(int c[2]);

/*! @function ccn_read_le_bytes
 *  @abstract Copies a number given as little-endian bytes into `out`.
 *
 *  @param n   Number of limbs of `out`.
 *  @param in  Number to parse as little-endian bytes.
 *  @param out Output.
 */
CC_NONNULL_ALL
CC_INLINE void
ccn_read_le_bytes(cc_size n, const uint8_t *in, cc_unit *out)
{
	for (cc_size i = 0; i < n; i++) {
		out[i] = cc_load_le(&in[i * CCN_UNIT_SIZE]);
	}
}

/*! @function ccn_write_le_bytes
 *  @abstract Encodes a number as little-endian bytes into `out`.
 *
 *  @param n   Number of limbs of `in`.
 *  @param in  Number to encode as little-endian bytes.
 *  @param out Output.
 */
CC_NONNULL_ALL
CC_INLINE void
ccn_write_le_bytes(cc_size n, const cc_unit *in, uint8_t *out)
{
	for (cc_size i = 0; i < n; i++) {
		cc_store_le(in[i], &out[i * CCN_UNIT_SIZE]);
	}
}

/*! @function ccn_recode_ssw
 *  @abstract Recodes a given number into signed sliding windows.
 *
 *  @param n Number of limbs of `s`.
 *  @param s Number to recode.
 *  @param w Recode width, for windows in range (-2^w,2^w).
 *  @param r Output for the computed signed sliding windows.
 */
CC_NONNULL_ALL
void ccn_recode_ssw(cc_size n, const cc_unit *s, int w, int8_t *r);

#endif // _CORECRYPTO_CCN_INTERNAL_H
