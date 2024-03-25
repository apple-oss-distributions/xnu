/* Copyright (c) (2021,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCRNG_CRYPTO_H_
#define _CORECRYPTO_CCRNG_CRYPTO_H_

#include <corecrypto/ccrng.h>
#include <corecrypto/ccrng_schedule.h>
#include <corecrypto/ccentropy.h>
#include "cc_lock.h"

// This is a framework for a cryptographically-secure RNG. It is
// configurable in many aspects, including:
//
// - DRBG implementation
// - Entropy source
// - Reseed schedule
// - Locks (optional)
// - Request chunking
// - Output caching

#define CCRNG_CRYPTO_SEED_MAX_NBYTES ((size_t)64)

typedef struct ccrng_crypto_ctx {
    CCRNG_STATE_COMMON

    ccentropy_ctx_t *entropy_ctx;
    ccrng_schedule_ctx_t *schedule_ctx;
    cc_lock_ctx_t *lock_ctx;

    const struct ccdrbg_info *drbg_info;
    struct ccdrbg_state *drbg_ctx;

    size_t generate_chunk_nbytes;
    size_t seed_nbytes;

    size_t cache_nbytes;
    uint8_t *cache;
    size_t cache_pos;
} ccrng_crypto_ctx_t;

int
ccrng_crypto_init(ccrng_crypto_ctx_t *ctx,
                  ccentropy_ctx_t *entropy_ctx,
                  ccrng_schedule_ctx_t *schedule_ctx,
                  cc_lock_ctx_t *lock_ctx,
                  const struct ccdrbg_info *drbg_info,
                  struct ccdrbg_state *drbg_ctx,
                  size_t generate_chunk_nbytes,
                  size_t seed_nbytes,
                  size_t cache_nbytes,
                  void *cache);

int
ccrng_crypto_generate(ccrng_crypto_ctx_t *ctx,
                      size_t nbytes,
                      void *rand);

int
ccrng_crypto_reseed(ccrng_crypto_ctx_t *ctx,
                    size_t seed_nbytes,
                    const void *seed,
                    size_t nonce_nbytes,
                    const void *nonce);

#endif /* _CORECRYPTO_CCRNG_CRYPTO_H_ */
