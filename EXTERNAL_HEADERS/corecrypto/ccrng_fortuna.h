/* Copyright (c) (2018-2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCRNG_FORTUNA_H_
#define _CORECRYPTO_CCRNG_FORTUNA_H_

#include <corecrypto/cc.h>
#include <corecrypto/ccrng.h>
#include "cc_lock.h"

// This is a Fortuna-inspired PRNG. While it differs from Fortuna in
// many minor details, the biggest difference is its support for
// multiple independent output generators. This is to make it suitable
// for use in concurrent environments.
//
// This PRNG targets a 256-bit security level.
//
// First, the user should call ccrng_fortuna_init. The user must
// specify the maximum number of output generators that might be
// needed. (Typically, users should align this argument with the
// number of available CPUs.)
//
// The user must also provide a read-only handle to an entropy
// source. This is a fixed-size buffer that will receive entropy
// updates out of band from the PRNG (e.g. in an interrupt
// handler). The PRNG will consume entropy from this buffer according
// to an internal schedule driven by calls to ccrng_fortuna_refresh
// (see below).
//
// The user should call ccrng_fortuna_initgen for as many output
// generators as are needed. The numeric argument is an identifier to
// be reused during calls to ccrng_fortuna_generate (see below) and
// must be less than the maximum number of generators specified to
// ccrng_fortuna_init.
//
// After initialization, the user is free to call
// ccrng_fortuna_generate to generate random bytes. The user must
// specify the generator in this call using a numeric identifier
// passed in the call to ccrng_fortuna_initgen.
//
// Output generation is limited to 256 bytes per request. Users should
// make multiple requests if more output is needed.
//
// The user is expected to call ccrng_fortuna_refresh regularly. This
// function consumes entropy and mixes it into the output generators
// according to an internal schedule.
//
// This implementation is thread-safe. Internally, a set of mutexes
// guard access to internal state. Most functions rely on a single
// mutex to protect shared state. The main exception is the
// ccrng_fortuna_generate function, which uses a per-generator mutex
// to allow concurrent output generation on different threads.
//
// Another important exception is ccrng_fortuna_refresh. While this
// function relies on the shared mutex, it returns immediately if it
// cannot acquire it.
//
// The PRNG also supports user-initiated reseeds. This is to support a
// user-writable random device.
//
// This PRNG supports reseeds concurrent with output generation,
// i.e. it is safe to call ccrng_fortuna_reseed or
// ccrng_fortuna_refresh while another thread is calling
// ccrng_fortuna_generate.

#define CCRNG_FORTUNA_NPOOLS 32
#define CCRNG_FORTUNA_SEED_NBYTES 32
#define CCRNG_FORTUNA_POOL_NBYTES 32
#define CCRNG_FORTUNA_KEY_NBYTES 32

struct ccrng_fortuna_pool_ctx {
    uint8_t data[CCRNG_FORTUNA_POOL_NBYTES];

    // The number of samples currently resident in the pool
    uint64_t nsamples;

    // The number of times this pool has been drained in a reseed
    uint64_t ndrains;

    // The maximum number of samples this pool has held at any one time
    uint64_t nsamples_max;
};

struct ccrng_fortuna_sched_ctx {
    // A counter governing the set of entropy pools to drain
    uint64_t reseed_sched;

    // An index used to add entropy to pools in a round-robin style
    unsigned pool_idx;
};

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
typedef int32_t (*ccrng_fortuna_getentropy)(size_t *entropy_nbytes,
                                            void *entropy,
                                            void *arg);

struct ccrng_fortuna_ctx {
    CCRNG_STATE_COMMON

    // The root secret of the PRNG
    uint8_t key[CCRNG_FORTUNA_KEY_NBYTES];

    // A counter used in CTR mode (with the root secret)
    uint8_t ctr[16];

    // State used to schedule entropy consumption and reseeds
    struct ccrng_fortuna_sched_ctx sched;

    // A mutex governing access to shared state
    cc_lock_ctx_t lock;

    // A set of entropy pools
    struct ccrng_fortuna_pool_ctx pools[CCRNG_FORTUNA_NPOOLS];

    // A function pointer to get entropy
    CC_SPTR(ccrng_fortuna_ctx, ccrng_fortuna_getentropy) getentropy;

    // An arbitrary piece of state to be provided to the entropy function
    void *getentropy_arg;

    // A flag describing whether the instance has been seeded with
    // sufficient entropy. This flag is set when a set of pools
    // containing a minimum threshold of entropy inputs is
    // drained. The PRNG will not generate output until this flag is
    // set. This flag is reset if the entropy source signals a
    // failure.
    bool seeded;

    // The number of scheduled reseeds
    uint64_t nreseeds;

    // The maximum number of samples included in any one scheduler reseed
    uint64_t schedreseed_nsamples_max;

    // The maximum number of samples included in any one entropy input
    uint64_t addentropy_nsamples_max;
};

/*
  @function ccrng_fortuna_init
  @abstract Initialize a kernel PRNG context.

  @param ctx Context for this instance
  @param getentropy A function pointer to fill an entropy buffer
  @param getentropy_arg State provided to the entropy function

  @discussion @p max_ngens should be set based on an upper bound of CPUs available on the device. See the @p ccrng_fortuna_getentropy type definition for discussion on its semantics.
*/
void ccrng_fortuna_init(struct ccrng_fortuna_ctx *ctx,
                        ccrng_fortuna_getentropy getentropy,
                        void *getentropy_arg);

/*
  @function ccrng_fortuna_refresh
  @abstract Consume entropy and reseed according to an internal schedule.

  @param ctx Context for this instance

  @return True if a reseed occurred, false otherwise.

  @discussion This function should be called on a regular basis. (For example, it is reasonable to call this inline before a call to @p ccrng_fortuna_generate.) This function will not necessarily consume entropy or reseed the internal state on any given invocation. To force an immediate reseed, call @p ccrng_fortuna_reseed.
*/
bool ccrng_fortuna_refresh(struct ccrng_fortuna_ctx *ctx);

#define CCRNG_FORTUNA_GENERATE_MAX_NBYTES 256

/*
  @function ccrng_fortuna_generate
  @abstract Generate random values for use in applications.

  @param ctx Context for this instance
  @param nbytes Length of the desired output in bytes
  @param out Pointer to the output buffer

  @return 0 on success, negative otherwise.

  @discussion @p gen_idx must be a previous argument to @p ccrng_fortuna_initgen. @p nbytes must be less than or equal to @p CCRNG_FORTUNA_GENERATE_MAX_NBYTES. (Callers may invoke this function in a loop to generate larger outputs.) This function will abort if these contracts are violated.
*/
int ccrng_fortuna_generate(struct ccrng_fortuna_ctx *ctx, size_t nbytes, void *out);

#endif /* _CORECRYPTO_CCRNG_FORTUNA_H_ */
