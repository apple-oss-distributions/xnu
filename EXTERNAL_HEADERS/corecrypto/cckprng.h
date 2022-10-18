/* Copyright (c) (2018-2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCKPRNG_H_
#define _CORECRYPTO_CCKPRNG_H_

#include <stdbool.h>

#include <corecrypto/cc.h>
#include "ccrng_fortuna.h"
#include "ccrng_crypto.h"
#include <corecrypto/ccrng_schedule.h>
#include <corecrypto/ccentropy.h>
#include <corecrypto/ccdrbg.h>
#include "cc_lock.h"

// This is a Fortuna-inspired PRNG. While it differs from Fortuna in
// many minor details, the biggest difference is its support for
// multiple independent output generators. This is to make it suitable
// for use in concurrent environments.
//
// This PRNG targets a 256-bit security level.
//
// First, the user should call cckprng_init. The user must specify the
// maximum number of output generators that might be
// needed. (Typically, users should align this argument with the
// number of available CPUs.)
//
// The user must also provide a read-only handle to an entropy
// source. This is a fixed-size buffer that will receive entropy
// updates out of band from the PRNG (e.g. in an interrupt
// handler). The PRNG will consume entropy from this buffer according
// to an internal schedule driven by calls to cckprng_refresh (see
// below).
//
// The user should call cckprng_initgen for as many output generators
// as are needed. The numeric argument is an identifier to be reused
// during calls to cckprng_generate (see below) and must be less than
// the maximum number of generators specified to cckprng_init.
//
// After initialization, the user is free to call cckprng_generate to
// generate random bytes. The user must specify the generator in this
// call using a numeric identifier passed in the call to
// cckprng_initgen.
//
// Output generation is limited to 256 bytes per request. Users should
// make multiple requests if more output is needed.
//
// The user is expected to call cckprng_refresh regularly. This
// function consumes entropy and mixes it into the output generators
// according to an internal schedule.
//
// This implementation is thread-safe. Internally, a set of mutexes
// guard access to internal state. Most functions rely on a single
// mutex to protect shared state. The main exception is the
// cckprng_generate function, which uses a per-generator mutex to
// allow concurrent output generation on different threads.
//
// Another important exception is cckprng_refresh. While this function
// relies on the shared mutex, it returns immediately if it cannot
// acquire it.
//
// The PRNG also supports user-initiated reseeds. This is to support a
// user-writable random device.
//
// This PRNG supports reseeds concurrent with output generation,
// i.e. it is safe to call cckprng_reseed or cckprng_refresh while
// another thread is calling cckprng_generate.

#define CCKPRNG_SEED_NBYTES 32

// A function pointer to fill an entropy buffer. It should return some
// estimate of entropy (e.g. the number of timing samples resident in
// the buffer). The implementation may return zero if no entropy is
// available. The implementation should return negative in case of an
// error (e.g. a failure in continuous health tests).
//
// The caller should set entropy_nbytes to the maximum size of the
// input buffer, and the implementation should set it to the number of
// bytes it has initialized. The third argument is arbitrary state the
// implementation provides and receives back on each call.
typedef ccrng_fortuna_getentropy cckprng_getentropy;

#define CCKPRNG_ENTROPY_SIZE 64
#define CCKPRNG_DRBG_STATE_MAX_SIZE ((size_t)1280)
#define CCKPRNG_CACHED_BUF_SIZE ((size_t)256)
#define CCKPRNG_MAX_REQUEST_SIZE ((size_t)4096)

struct cckprng_ctx {
    // A flag set every time Fortuna reseeds itself
    ccrng_schedule_atomic_flag_ctx_t schedule_ctx;

    ccentropy_rng_ctx_t entropy_ctx;

    cc_lock_ctx_t lock_ctx;

    struct ccdrbg_info drbg_info;
    uint8_t drbg_state[CCKPRNG_DRBG_STATE_MAX_SIZE];

    uint8_t cache[CCKPRNG_CACHED_BUF_SIZE];

    ccrng_crypto_ctx_t rng_ctx;

    struct ccrng_fortuna_ctx fortuna_ctx;
};

// This collection of function pointers is just a convenience for
// registering the PRNG with xnu
struct cckprng_funcs {
    void (*CC_SPTR(cckprng_funcs, init))(struct cckprng_ctx *ctx,
                                         size_t seed_nbytes,
                                         const void *seed,
                                         size_t nonce_nbytes,
                                         const void *nonce,
                                         cckprng_getentropy getentropy,
                                         void *getentropy_arg);
    void (*CC_SPTR(cckprng_funcs, initgen))(struct cckprng_ctx *ctx, unsigned gen_idx);
    void (*CC_SPTR(cckprng_funcs, reseed))(struct cckprng_ctx *ctx, size_t nbytes, const void *seed);
    void (*CC_SPTR(cckprng_funcs, refresh))(struct cckprng_ctx *ctx);
    void (*CC_SPTR(cckprng_funcs, generate))(struct cckprng_ctx *ctx, unsigned gen_idx, size_t nbytes, void *out);
    void (*CC_SPTR(cckprng_funcs, init_with_getentropy))(struct cckprng_ctx *ctx,
                                                         unsigned max_ngens,
                                                         size_t seed_nbytes,
                                                         const void *seed,
                                                         size_t nonce_nbytes,
                                                         const void *nonce,
                                                         cckprng_getentropy getentropy,
                                                         void *getentropy_arg);
};

/*
  @function cckprng_init
  @abstract Initialize a kernel PRNG context.

  @param ctx Context for this instance
  @param seed_nbytes Length of the seed in bytes
  @param seed Pointer to a high-entropy seed
  @param nonce_nbytes Length of the nonce in bytes
  @param nonce Pointer to a single-use nonce
  @param getentropy A function pointer to fill an entropy buffer
  @param getentropy_arg State provided to the entropy function

  @discussion See the @p cckprng_getentropy type definition for discussion on its semantics.

*/
void cckprng_init(struct cckprng_ctx *ctx,
                  size_t seed_nbytes,
                  const void *seed,
                  size_t nonce_nbytes,
                  const void *nonce,
                  cckprng_getentropy getentropy,
                  void *getentropy_arg);

/*
  @function cckprng_init_with_getentropy
  @abstract Initialize a kernel PRNG context.

  @param ctx Context for this instance
  @param max_ngens Maximum count of generators that may be allocated
  @param seed_nbytes Length of the seed in bytes
  @param seed Pointer to a high-entropy seed
  @param nonce_nbytes Length of the nonce in bytes
  @param nonce Pointer to a single-use nonce
  @param getentropy A function pointer to fill an entropy buffer
  @param getentropy_arg State provided to the entropy function

  @discussion @p max_ngens should be set based on an upper bound of CPUs available on the device. See the @p cckprng_getentropy type definition for discussion on its semantics.
*/
void cckprng_init_with_getentropy(struct cckprng_ctx *ctx,
                                  unsigned max_ngens,
                                  size_t seed_nbytes,
                                  const void *seed,
                                  size_t nonce_nbytes,
                                  const void *nonce,
                                  cckprng_getentropy getentropy,
                                  void *getentropy_arg);

/*
  @function cckprng_initgen
  @abstract Initialize an output generator.

  @param ctx Context for this instance
  @param gen_idx Index of the generator

  @discussion @p gen_idx must be less than @p max_ngens provided to @cckprng_init and must be unique within the lifetime of a PRNG context. This function will abort if these contracts are violated.
*/
void cckprng_initgen(struct cckprng_ctx *ctx, unsigned gen_idx);

/*
  @function cckprng_reseed
  @abstract Reseed a kernel PRNG context with a user-supplied seed.

  @param ctx Context for this instance
  @param nbytes Length of the seed in bytes
  @param seed Pointer to a high-entropy seed

  @discussion It is safe to expose this function to attacker-controlled requests (e.g. writes to /dev/random).
*/
void cckprng_reseed(struct cckprng_ctx *ctx, size_t nbytes, const void *seed);

/*
  @function cckprng_refresh
  @abstract Consume entropy and reseed according to an internal schedule.

  @param ctx Context for this instance

  @discussion This function should be called on a regular basis. (For example, it is reasonable to call this inline before a call to @p cckprng_generate.) This function will not necessarily consume entropy or reseed the internal state on any given invocation. To force an immediate reseed, call @p cckprng_reseed.
*/
void cckprng_refresh(struct cckprng_ctx *ctx);

#define CCKPRNG_GENERATE_MAX_NBYTES 256

/*
  @function cckprng_generate
  @abstract Generate random values for use in applications.

  @param ctx Context for this instance
  @param gen_idx Index of the output generator
  @param nbytes Length of the desired output in bytes
  @param out Pointer to the output buffer

  @discussion @p gen_idx must be a previous argument to @p cckprng_initgen. @p nbytes must be less than or equal to @p CCKPRNG_GENERATE_MAX_NBYTES. (Callers may invoke this function in a loop to generate larger outputs.) This function will abort if these contracts are violated.
*/
void cckprng_generate(struct cckprng_ctx *ctx, unsigned gen_idx, size_t nbytes, void *out);

#endif /* _CORECRYPTO_CCKPRNG_H_ */
