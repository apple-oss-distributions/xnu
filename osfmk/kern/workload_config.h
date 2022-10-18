/*
 * Copyright (c) 2021 Apple Inc. All rights reserved.
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
#include <sys/queue.h>
#include <sys/work_interval.h>
#include <kern/work_interval.h>

#pragma once

#ifdef XNU_KERNEL_PRIVATE

OS_ASSUME_NONNULL_BEGIN

    __BEGIN_DECLS

typedef struct workload_config_ctx workload_config_ctx_t;

extern workload_config_ctx_t workload_config_boot;
#if DEVELOPMENT || DEBUG
extern workload_config_ctx_t workload_config_devel;
#endif

#define WORKLOAD_CONFIG_ID_NAME_MAX WORK_INTERVAL_WORKLOAD_ID_NAME_MAX

typedef struct workload_config {
	uint32_t   wc_thread_group_flags;
	uint32_t   wc_flags;
	uint32_t   wc_create_flags;
	uint8_t    wc_class_offset;
	wi_class_t wc_class;
} workload_config_t;

typedef enum {
	WLC_F_NONE          = 0,
	WLC_F_THREAD_POLICY = 1, // By default set for new workload configs.
} workload_config_flags_t;

/*!
 * @function   workload_config_init
 * @abstract   Allocate global workload data structures.
 * @param      ctx     Configuration context
 * @result     KERN_SUCCESS on success or error.
 */
extern kern_return_t workload_config_init(workload_config_ctx_t *ctx);

/*!
 * @function   workload_config_initialized
 * @abstract   Tests whether or not a config context has been initialized
 * @param      ctx     Configuration context
 * @result     true if initialized, false if not
 */
extern bool workload_config_initialized(const workload_config_ctx_t *ctx);

/*!
 * @function   workload_config_free
 * @abstract   Free global workload data structures.
 */
extern void workload_config_free(workload_config_ctx_t *ctx);

/*!
 * @function   workload_config_insert
 * @abstract   Insert a new workload configuration
 * @param      ctx     Configuration context
 * @param      id     Workload identifier
 * @param      phase  Phase assoicated with this config
 * @param      config Configuration
 * @result     KERN_SUCCESS on success or error.
 */
extern kern_return_t workload_config_insert(workload_config_ctx_t *ctx,
    const char *id, const char *phase, const workload_config_t *config);

/*!
 * @function   workload_config_set_default
 * @abstract   Set the default phase for the specified workload ID
 * @param      ctx     Configuration context
 * @param      id     Workload identifier
 * @param      phase  The new default phase
 * @result     KERN_SUCCESS on success or error.
 * @discussion The configuration for the specified phase must already exist.
 */
extern kern_return_t workload_config_set_default(workload_config_ctx_t *ctx,
    const char *id, const char *phase);

/*!
 * @function   workload_config_lookup
 * @abstract   Find per phase workload configuration
 * @param      id     Workload identifier
 * @param      phase  Phase assoicated with this config
 * @param      config Returned configuration
 * @result     KERN_SUCCESS on success or error.
 */
extern kern_return_t workload_config_lookup(const char *id, const char *phase,
    workload_config_t *config);

/*!
 * @function   workload_config_lookup_default
 * @abstract   Find the default phase workload configuration
 * @param      id     Workload identifier
 * @param      config Returned configuration
 * @result     KERN_SUCCESS on success or error.
 */
extern kern_return_t workload_config_lookup_default(const char *id,
    workload_config_t *config);

/*!
 * @function   workload_config_iterate
 * @abstract   Iterate over the active workload configuration
 * @param      cb     Block called per ID
 * @discussion If cb returns true, the iteration stops.
 *             The phases argument can be passed into workload_config_iterate_phases.
 */
extern void workload_config_iterate(bool (^cb)(const char *id,
    const void *phases));

/*!
 * @function   workload_config_iterate_phase
 * @abstract   Iterate over the phases in a workload configuration
 * @param      phases Phase configuration to iterate over
 * @param      cb     Block called per phase
 * @discussion If cb returns true, the iteration stops.
 *             This must always be called from a workload_config_iterate block.
 */
extern void workload_config_phases_iterate(const void *phases,
    bool (^cb)(const char *phase, const bool is_default,
    const workload_config_t *config));

/*!
 * @function   workload_config_get_flags
 * @abstract   Read the workload config flags
 * @param      flags     Returns set flags
 * @result     KERN_SUCCESS on success or error.
 */
extern kern_return_t workload_config_get_flags(workload_config_flags_t *flags);

/*!
 * @function   workload_config_clear_flag
 * @abstract   Clear a workload config flag
 * @param      ctx     Configuration context
 * @param      flag    Flag to be cleared
 * @result     KERN_SUCCESS on success or error.
 */
extern kern_return_t workload_config_clear_flag(workload_config_ctx_t *ctx,
    workload_config_flags_t flag);

/*!
 * @function   workload_config_available
 * @abstract   See if a workload configuration is available
 * @result     KERN_SUCCESS on success or error.
 * @discussion Note: this can be racy on kernels that support dynamically
 *             setting and clearing workload configuration.
 */
extern bool workload_config_available(void);

__END_DECLS

    OS_ASSUME_NONNULL_END

#endif /* XNU_KERNEL_PRIVATE */
