/*
 * Copyright (c) 2019 Apple Inc. All rights reserved.
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

#include <sys/sysctl.h>
#include <sys/malloc.h>
#include <pexpert/pexpert.h>
#include <kern/kalloc.h>
#include <kern/percpu.h>
#include <prng/entropy.h>
#include <libkern/section_keywords.h>

SYSCTL_NODE(_kern, OID_AUTO, entropy, CTLFLAG_RD, 0, NULL);
SYSCTL_NODE(_kern_entropy, OID_AUTO, health, CTLFLAG_RD, 0, NULL);
SYSCTL_INT(_kern_entropy_health, OID_AUTO, startup_done, CTLFLAG_RD, &entropy_health_startup_done, 0, NULL);

SYSCTL_NODE(_kern_entropy_health, OID_AUTO, repetition_count_test, CTLFLAG_RD, 0, NULL);
SYSCTL_UINT(_kern_entropy_health_repetition_count_test, OID_AUTO, reset_count, CTLFLAG_RD, &entropy_health_rct_stats.reset_count, 0, NULL);
SYSCTL_UINT(_kern_entropy_health_repetition_count_test, OID_AUTO, failure_count, CTLFLAG_RD, &entropy_health_rct_stats.failure_count, 0, NULL);
SYSCTL_UINT(_kern_entropy_health_repetition_count_test, OID_AUTO, max_observation_count, CTLFLAG_RD, &entropy_health_rct_stats.max_observation_count, 0, NULL);

SYSCTL_NODE(_kern_entropy_health, OID_AUTO, adaptive_proportion_test, CTLFLAG_RD, 0, NULL);
SYSCTL_UINT(_kern_entropy_health_adaptive_proportion_test, OID_AUTO, reset_count, CTLFLAG_RD, &entropy_health_apt_stats.reset_count, 0, NULL);
SYSCTL_UINT(_kern_entropy_health_adaptive_proportion_test, OID_AUTO, failure_count, CTLFLAG_RD, &entropy_health_apt_stats.failure_count, 0, NULL);
SYSCTL_UINT(_kern_entropy_health_adaptive_proportion_test, OID_AUTO, max_observation_count, CTLFLAG_RD, &entropy_health_apt_stats.max_observation_count, 0, NULL);

SYSCTL_NODE(_kern_entropy, OID_AUTO, filter, CTLFLAG_RD, 0,
    "Entropy filter information");
SYSCTL_QUAD(_kern_entropy_filter, OID_AUTO, total_sample_count, CTLFLAG_RD, &entropy_filter_total_sample_count,
    "The total number of samples processed (i.e. the number of interrupts)");
SYSCTL_QUAD(_kern_entropy_filter, OID_AUTO, accepted_sample_count, CTLFLAG_RD, &entropy_filter_accepted_sample_count,
    "The number of samples that passed the filter");
SYSCTL_QUAD(_kern_entropy_filter, OID_AUTO, rejected_sample_count, CTLFLAG_RD, &entropy_filter_rejected_sample_count,
    "The number of samples that were rejected by the filters");

SYSCTL_NODE(_kern_entropy, OID_AUTO, analysis, CTLFLAG_RD, 0,
    "Subsystem to collect entropy samples for offline analysis");

static int entropy_analysis_supported = ENTROPY_ANALYSIS_SUPPORTED;
SYSCTL_INT(_kern_entropy_analysis, OID_AUTO, supported, CTLFLAG_RD, &entropy_analysis_supported, 0,
    "1 if the kernel was built with entropy analysis support; 0 otherwise");

#if ENTROPY_ANALYSIS_SUPPORTED

SYSCTL_INT(_kern_entropy_analysis, OID_AUTO, enabled, CTLFLAG_RD, &entropy_analysis_enabled, 0,
    "1 if entropy analysis is enabled (via boot arg); 0 otherwise");
SYSCTL_UINT(_kern_entropy_analysis, OID_AUTO, max_sample_count, CTLFLAG_RD | CTLFLAG_NOAUTO, &entropy_analysis_max_sample_count, 0,
    "Target count of samples to be collected");
SYSCTL_UINT(_kern_entropy_analysis, OID_AUTO, sample_count, CTLFLAG_RD | CTLFLAG_NOAUTO, &entropy_analysis_sample_count, 0,
    "Current count of samples collected");

static int entropy_analysis_sample_size = sizeof(entropy_sample_t);
SYSCTL_UINT(_kern_entropy_analysis, OID_AUTO, sample_size, CTLFLAG_RD | CTLFLAG_NOAUTO, &entropy_analysis_sample_size, 0,
    "Size (in bytes) of a single sample");

SYSCTL_UINT(_kern_entropy_analysis, OID_AUTO, buffer_size, CTLFLAG_RD | CTLFLAG_NOAUTO, &entropy_analysis_buffer_size, 0,
    "Size (in bytes) of the buffer of samples");

SYSCTL_UINT(_kern_entropy_analysis, OID_AUTO, filter_size, CTLFLAG_RD | CTLFLAG_NOAUTO, &entropy_analysis_filter_size, 0,
    "Size (in bytes) of the filter bitmap");

static int
sysctl_entropy_collect SYSCTL_HANDLER_ARGS
{
	if (req->oldptr == USER_ADDR_NULL) {
		return SYSCTL_OUT(req, NULL, entropy_analysis_buffer_size);
	}

	return SYSCTL_OUT(req, entropy_analysis_buffer, entropy_analysis_buffer_size);
}

SYSCTL_PROC(_kern_entropy_analysis, OID_AUTO, buffer,
    CTLTYPE_OPAQUE | CTLFLAG_RD | CTLFLAG_NOAUTO,
    NULL, 0, sysctl_entropy_collect, "-",
    "The buffer of samples");

static int
sysctl_entropy_filter SYSCTL_HANDLER_ARGS
{
	if (req->oldptr == USER_ADDR_NULL) {
		return SYSCTL_OUT(req, NULL, entropy_analysis_filter_size);
	}

	// There is one bit in the bitmap for each sample.
	unsigned filter_nbits = entropy_analysis_max_sample_count;

	bitmap_t *filter = bitmap_alloc(filter_nbits);
	if (!filter) {
		return ENOMEM;
	}

	entropy_filter(entropy_analysis_max_sample_count, entropy_analysis_buffer, BITMAP_LEN(filter_nbits), filter);

	int status = SYSCTL_OUT(req, filter, entropy_analysis_filter_size);

	bitmap_free(filter, filter_nbits);
	return status;
}

SYSCTL_PROC(_kern_entropy_analysis, OID_AUTO, filter,
    CTLTYPE_OPAQUE | CTLFLAG_RD | CTLFLAG_NOAUTO,
    NULL, 0, sysctl_entropy_filter, "-",
    "The bitmap of filtered samples");

__startup_func
static void
entropy_analysis_sysctl_startup(void)
{
	uint32_t sample_count = 0;
	if (__improbable(PE_parse_boot_argn(ENTROPY_ANALYSIS_BOOTARG, &sample_count, sizeof(sample_count)))) {
		sysctl_register_oid_early(&sysctl__kern_entropy_analysis_max_sample_count);
		sysctl_register_oid_early(&sysctl__kern_entropy_analysis_sample_count);
		sysctl_register_oid_early(&sysctl__kern_entropy_analysis_sample_size);
		sysctl_register_oid_early(&sysctl__kern_entropy_analysis_buffer_size);
		sysctl_register_oid_early(&sysctl__kern_entropy_analysis_buffer);
		sysctl_register_oid_early(&sysctl__kern_entropy_analysis_filter_size);
		sysctl_register_oid_early(&sysctl__kern_entropy_analysis_filter);
	}
}
STARTUP(SYSCTL, STARTUP_RANK_MIDDLE, entropy_analysis_sysctl_startup);

#endif  // ENTROPY_ANALYSIS_SUPPORTED
