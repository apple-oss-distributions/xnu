/* Copyright (c) (2010-2020,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCRNG_H_
#define _CORECRYPTO_CCRNG_H_

#include <corecrypto/cc.h>

#define CCRNG_STATE_COMMON \
    int (*CC_SPTR(ccrng_state, generate))(struct ccrng_state *rng, size_t outlen, void *out);

/*!
 @type      struct ccrng_state
 @abstract  Default state structure. Do not instantiate. ccrng() returns a reference to this structure
 */
struct ccrng_state {
    CCRNG_STATE_COMMON
};

/*!
 @function ccrng
 @abstract Get a handle to a secure RNG

 @param error A pointer to set in case of error; may be null

 @result A handle to a secure RNG, or null if one cannot be initialized successfully

 @discussion
 This function returns a pointer to the most appropriate RNG for the
 environment. This may be a TRNG if one is available. Otherwise, it is
 a PRNG offering several features:
 - Good performance
 - FIPS Compliant: NIST SP800-90A + FIPS 140-2
 - Seeded from the appropriate entropy source for the platform
 - Provides at least 128-bit security
 - Backtracing resistance
 - Prediction break (after reseed)
 */
struct ccrng_state *ccrng(int *error);

/*!
 @function   ccrng_generate
 @abstract   Generate `outlen` bytes of output, stored in `out`, using ccrng_state `rng`.

 @param rng  `struct ccrng_state` representing the state of the RNG.
 @param outlen  Amount of random bytes to generate.
 @param out  Pointer to memory where random bytes are stored, of size at least `outlen`.

 @result 0 on success and nonzero on failure.
 */
#define ccrng_generate(rng, outlen, out) \
    ((rng)->generate((struct ccrng_state *)(rng), (outlen), (out)))

#if !CC_EXCLAVEKIT
/*!
  @function ccrng_uniform
  @abstract Generate a random value in @p [0, bound).

  @param rng   The state of the RNG.
  @param bound The exclusive upper bound on the output.
  @param rand  A pointer to a single @p uint64_t to store the result.

  @result Returns zero iff the operation is successful.
 */
int ccrng_uniform(struct ccrng_state *rng, uint64_t bound, uint64_t *rand);
#endif

#endif /* _CORECRYPTO_CCRNG_H_ */
