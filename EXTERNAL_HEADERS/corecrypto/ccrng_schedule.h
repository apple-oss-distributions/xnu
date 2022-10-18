/* Copyright (c) (2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCRNG_SCHEDULE_H_
#define _CORECRYPTO_CCRNG_SCHEDULE_H_

#include <corecrypto/cc.h>
#include <stdatomic.h>

// Depending on the environment and platform APIs available, different
// RNGs will use different reseed strategies. For example, an RNG that
// can communicate with its entropy source might check a flag set by
// the latter when entropy is available. In another case, the RNG
// might poll its entropy source on a time interval. In some cases,
// the RNG might always (or never) want to try to reseed.
//
// This module provides a common interface for such reseed
// schedules. It is intended for use as a component by RNG
// implementations.

typedef enum {
    CCRNG_SCHEDULE_CONTINUE = 1,
    CCRNG_SCHEDULE_TRY_RESEED = 2,
    CCRNG_SCHEDULE_MUST_RESEED = 3,
} ccrng_schedule_action_t;

CC_INLINE bool
ccrng_schedule_action_is_reseed(ccrng_schedule_action_t action)
{
    return (action == CCRNG_SCHEDULE_TRY_RESEED ||
            action == CCRNG_SCHEDULE_MUST_RESEED);
}

typedef enum {
    CCRNG_SCHEDULE_RESEED_SUCCEEDED = 1,
    CCRNG_SCHEDULE_RESEED_FAILED = 2,
} ccrng_schedule_result_t;

typedef struct ccrng_schedule_ctx ccrng_schedule_ctx_t;

// The schedule interface provides two function pointers: one to check the
// schedule and one to propagate the result of the reseed.
typedef struct ccrng_schedule_info {
    ccrng_schedule_action_t (*read)(ccrng_schedule_ctx_t *ctx);
    void (*update)(ccrng_schedule_ctx_t *ctx, ccrng_schedule_result_t result);
} ccrng_schedule_info_t;

struct ccrng_schedule_ctx {
    const ccrng_schedule_info_t *info;
};

ccrng_schedule_action_t ccrng_schedule_read(ccrng_schedule_ctx_t *ctx);

void ccrng_schedule_update(ccrng_schedule_ctx_t *ctx, ccrng_schedule_result_t update);

// This is a concrete schedule implementation where the state of the
// entropy source is communicated via a flag. The entropy source can
// set the flag with ccrng_schedule_atomic_flag_set to indicate
// entropy is available. The flag is cleared automatically on read and
// reset if the reseed fails.
typedef struct ccrng_schedule_atomic_flag_ctx {
    ccrng_schedule_ctx_t schedule_ctx;
    _Atomic ccrng_schedule_action_t flag;
} ccrng_schedule_atomic_flag_ctx_t;

void ccrng_schedule_atomic_flag_init(ccrng_schedule_atomic_flag_ctx_t *ctx);

void ccrng_schedule_atomic_flag_set(ccrng_schedule_atomic_flag_ctx_t *ctx);

// This is a concrete schedule implementation that simply always
// returns a constant action.
typedef struct ccrng_schedule_constant_ctx {
    ccrng_schedule_ctx_t schedule_ctx;
    ccrng_schedule_action_t action;
} ccrng_schedule_constant_ctx_t;

void ccrng_schedule_constant_init(ccrng_schedule_constant_ctx_t *ctx,
                                  ccrng_schedule_action_t action);

typedef struct ccrng_schedule_timer_ctx {
    ccrng_schedule_ctx_t schedule_ctx;
    uint64_t (*get_time)(void);
    uint64_t reseed_interval;
    uint64_t last_read_time;
    uint64_t last_reseed_time;
} ccrng_schedule_timer_ctx_t;

void ccrng_schedule_timer_init(ccrng_schedule_timer_ctx_t *ctx,
                               uint64_t (*get_time)(void),
                               uint64_t reseed_interval);

#endif /* _CORECRYPTO_CCRNG_SCHEDULE_H_ */
