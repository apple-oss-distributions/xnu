/*
 * Copyright (c) 2022 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 *
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */

#ifndef _SYS_TRUST_CACHES_H_
#define _SYS_TRUST_CACHES_H_

#ifdef KERNEL_PRIVATE

#include <mach/kern_return.h>
#include <sys/cdefs.h>
#include <TrustCache/API.h>

#if (DEVELOPMENT || DEBUG)
#define TRUST_CACHE_INCLUDE_INTERNAL_CODE 1
#endif

/* Availability macros to check for support */
#define XNU_HAS_TRUST_CACHE_LOADING 1
#define XNU_HAS_TRUST_CACHE_CHECK_RUNTIME_FOR_UUID 1

#ifdef XNU_PLATFORM_BridgeOS
#define XNU_HAS_LEGACY_TRUST_CACHE_LOADING 1
#elif defined(TARGET_OS_BRIDGE) && TARGET_OS_BRIDGE
#define XNU_HAS_LEGACY_TRUST_CACHE_LOADING 1
#else
#define XNU_HAS_LEGACY_TRUST_CACHE_LOADING 0
#endif

__BEGIN_DECLS

#if XNU_KERNEL_PRIVATE

/* Temporary definition until we get a proper shared one */
typedef struct DTTrustCacheRange {
	vm_offset_t paddr;
	size_t length;
} DTTrustCacheRange;

/* This is the structure iBoot uses to deliver the trust caches to the system */
typedef struct _trust_cache_offsets {
	/* The number of trust caches provided */
	uint32_t num_caches;

	/* Offset of each from beginning of the structure */
	uint32_t offsets[0];
} __attribute__((__packed__)) trust_cache_offsets_t;

/**
 * Initialize the trust cache runtime for the system environment.
 */
void
trust_cache_runtime_init(void);

/**
 * Load the static and engineering trust caches passed over to the system by the boot loader.
 */
void
load_static_trust_cache(void);

#endif /* XNU_KERNEL_PRIVATE */

/**
 * Check the capabilities of the static trust caches on the system. Since the static trust
 * caches are loaded at boot, kernel extensions don't get a chance to observe their format
 * and miss out on the information.
 *
 * This function can be queried to obtain this information.
 */
kern_return_t
static_trust_cache_capabilities(
	uint32_t *num_static_trust_caches_ret,
	TCCapabilities_t *capabilities0_ret,
	TCCapabilities_t *capabilities1_ret);

/**
 * Check if a particular trust cache has already been loaded into the system on the basis
 * of a provided UUID.
 *
 * Based on the system environment, this request may trap into the kernel's code signing
 * monitor environment as the trust cache data structures need to be locked down.
 */
kern_return_t
check_trust_cache_runtime_for_uuid(
	const uint8_t check_uuid[kUUIDSize]);

/**
 * Load an image4 trust cache. Since the type of trust cache isn't specified, this interface
 * attempts to validate the trust cache through all known types. Therefore, this evaluation
 * can be expensive.
 *
 * This is a deprecated interface and should no longer be used. It also doesn't support usage
 * of the auxiliary manifest. Please use the newer interface "load_trust_cache_with_type".
 */
kern_return_t
load_trust_cache(
	const uint8_t *img4_object, const size_t img4_object_len,
	const uint8_t *img4_ext_manifest, const size_t img4_ext_manifest_len);

/**
 * Load an image4 based trust cache of a particular type. This function performs an entitlement
 * check on the calling process to ensure it has the entitlement for loading the specified trust
 * cache.
 *
 * Based on the system environment, the trust cache may be loaded into kernel memory, or it may
 * be loaded into memory controlled by the kernel monitor environment. In either case, this
 * function creates its own allocations for the data, and the caller may free their allocations,
 * if any.
 */
kern_return_t
load_trust_cache_with_type(
	TCType_t type,
	const uint8_t *img4_object, const size_t img4_object_len,
	const uint8_t *img4_ext_manifest, const size_t img4_ext_manifest_len,
	const uint8_t *img4_aux_manifest, const size_t img4_aux_manifest_len);

/**
 * Load a legacy trust cache module for supported platforms. Availability for the KPI can
 * be checked by querying the macro "XNU_HAS_LEGACY_TRUST_CACHE_LOADING". Using this KPI
 * on an unsupported platform will panic the system.
 */
kern_return_t
load_legacy_trust_cache(
	const uint8_t *module_data, const size_t module_size);

/**
 * Query a trust cache based on the type passed in.
 *
 * Based on the system environment, the trust cache may be queried from kernel memory, or it may
 * be queried from memory controller by the kernel monitor environment.
 */
kern_return_t
query_trust_cache(
	TCQueryType_t query_type,
	const uint8_t cdhash[kTCEntryHashSize],
	TrustCacheQueryToken_t *query_token);

__END_DECLS

#endif /* KERNEL_PRIVATE */
#endif /* _SYS_TRUST_CACHES_H_ */
