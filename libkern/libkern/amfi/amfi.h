/*
 * Copyright (c) 2020 Apple Inc. All rights reserved.
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

#ifndef __AMFI_H
#define __AMFI_H

#include <os/base.h>
#include <sys/cdefs.h>
#include <kern/cs_blobs.h>

#define KERN_AMFI_INTERFACE_VERSION 6
#define KERN_AMFI_SUPPORTS_DATA_ALLOC 2

#pragma mark Forward Declarations
struct proc;
struct cs_blob;

#pragma mark Type Defines
typedef struct proc* proc_t;

#if XNU_KERNEL_PRIVATE
#ifndef CORE_ENTITLEMENTS_I_KNOW_WHAT_IM_DOING
#define CORE_ENTITLEMENTS_I_KNOW_WHAT_IM_DOING
#endif

#include <CoreEntitlements/CoreEntitlementsPriv.h>
#endif

typedef void (*amfi_OSEntitlements_invalidate)(void* osentitlements);
typedef void* (*amfi_OSEntitlements_asDict)(void* osentitlements);
typedef CEError_t (*amfi_OSEntitlements_query)(void* osentitlements, uint8_t cdhash[CS_CDHASH_LEN], CEQuery_t query, size_t queryLength);
typedef bool (*amfi_OSEntitlements_get_transmuted_blob)(void* osentitlements, const CS_GenericBlob **blob);
typedef bool (*amfi_OSEntitlements_get_xml_blob)(void* osentitlements, CS_GenericBlob **blob);
typedef bool (*amfi_get_legacy_profile_exemptions)(const uint8_t **profile, size_t *profileLength);
typedef bool (*amfi_get_udid)(const uint8_t **udid, size_t *udidLength);
typedef void* (*amfi_query_context_to_object)(CEQueryContext_t ctx);

#pragma mark OSEntitlements

#define KERN_AMFI_SUPPORTS_OSENTITLEMENTS_API 1
#define OSENTITLEMENTS_INTERFACE_VERSION 1u

typedef kern_return_t (*OSEntitlements_adjustContextWithMonitor)(
	void* os_entitlements,
	const CEQueryContext_t ce_ctx,
	const void *monitor_sig_obj,
	const char *identity,
	const uint32_t code_signing_flags
	);

typedef kern_return_t (*OSEntitlements_adjustContextWithoutMonitor)(
	void* os_entitlements,
	struct cs_blob *code_signing_blob
	);

typedef kern_return_t (*OSEntitlements_queryEntitlementBoolean)(
	const void *os_entitlements,
	const char *entitlement_name
	);

typedef kern_return_t (*OSEntitlements_queryEntitlementBooleanWithProc)(
	const proc_t proc,
	const char *entitlement_name
	);

typedef kern_return_t (*OSEntitlements_queryEntitlementString)(
	const void *os_entitlements,
	const char *entitlement_name,
	const char *entitlement_value
	);

typedef kern_return_t (*OSEntitlements_queryEntitlementStringWithProc)(
	const proc_t proc,
	const char *entitlement_name,
	const char *entitlement_value
	);

typedef kern_return_t (*OSEntitlements_copyEntitlementAsOSObject)(
	const void *os_entitlements,
	const char *entitlement_name,
	void **entitlement_object
	);

typedef kern_return_t (*OSEntitlements_copyEntitlementAsOSObjectWithProc)(
	const proc_t proc,
	const char *entitlement_name,
	void **entitlement_object
	);

typedef struct _OSEntitlementsInterface {
	uint32_t version;
	OSEntitlements_adjustContextWithMonitor adjustContextWithMonitor;
	OSEntitlements_adjustContextWithoutMonitor adjustContextWithoutMonitor;
	OSEntitlements_queryEntitlementBoolean queryEntitlementBoolean;
	OSEntitlements_queryEntitlementBooleanWithProc queryEntitlementBooleanWithProc;
	OSEntitlements_queryEntitlementString queryEntitlementString;
	OSEntitlements_queryEntitlementStringWithProc queryEntitlementStringWithProc;
	OSEntitlements_copyEntitlementAsOSObject copyEntitlementAsOSObject;
	OSEntitlements_copyEntitlementAsOSObjectWithProc copyEntitlementAsOSObjectWithProc;
} OSEntitlementsInterface_t;

#pragma mark libTrustCache

#include <TrustCache/API.h>
#define KERN_AMFI_SUPPORTS_TRUST_CACHE_API 1
#define TRUST_CACHE_INTERFACE_VERSION 3u

typedef TCReturn_t (*constructInvalid_t)(
	TrustCache_t *trustCache,
	const uint8_t *moduleAddr,
	size_t moduleSize
	);

typedef TCReturn_t (*checkRuntimeForUUID_t)(
	const TrustCacheRuntime_t *runtime,
	const uint8_t checkUUID[kUUIDSize],
	const TrustCache_t **trustCacheRet
	);

typedef TCReturn_t (*loadModule_t)(
	TrustCacheRuntime_t *runtime,
	const TCType_t type,
	TrustCache_t *trustCache,
	const uintptr_t dataAddr,
	const size_t dataSize
	);

typedef TCReturn_t (*load_t)(
	TrustCacheRuntime_t *runtime,
	TCType_t type,
	TrustCache_t *trustCache,
	const uintptr_t payloadAddr,
	const size_t payloadSize,
	const uintptr_t manifestAddr,
	const size_t manifestSize
	);

typedef TCReturn_t (*extractModule_t)(
	TrustCache_t *trustCache,
	const uint8_t *dataAddr,
	size_t dataSize
	);

typedef TCReturn_t (*query_t)(
	const TrustCacheRuntime_t *runtime,
	TCQueryType_t queryType,
	const uint8_t CDHash[kTCEntryHashSize],
	TrustCacheQueryToken_t *queryToken
	);

typedef TCReturn_t (*getModule_t)(
	const TrustCache_t *trustCache,
	const uint8_t **moduleAddrRet,
	size_t *moduleSizeRet
	);

typedef TCReturn_t (*getUUID_t)(
	const TrustCache_t *trustCache,
	uint8_t returnUUID[kUUIDSize]
	);

typedef TCReturn_t (*getCapabilities_t)(
	const TrustCache_t *trustCache,
	TCCapabilities_t *capabilities
	);

typedef TCReturn_t (*queryGetTCType_t)(
	const TrustCacheQueryToken_t *queryToken,
	TCType_t *typeRet
	);

typedef TCReturn_t (*queryGetCapabilities_t)(
	const TrustCacheQueryToken_t *queryToken,
	TCCapabilities_t *capabilities
	);

typedef TCReturn_t (*queryGetHashType_t)(
	const TrustCacheQueryToken_t *queryToken,
	uint8_t *hashTypeRet
	);

typedef TCReturn_t (*queryGetFlags_t)(
	const TrustCacheQueryToken_t *queryToken,
	uint64_t *flagsRet
	);

typedef TCReturn_t (*queryGetConstraintCategory_t)(
	const TrustCacheQueryToken_t *queryToken,
	uint8_t *constraintCategoryRet
	);

typedef struct _TrustCacheInterface {
	uint32_t version;
	loadModule_t loadModule;
	load_t load;
	query_t query;
	getCapabilities_t getCapabilities;
	queryGetTCType_t queryGetTCType;
	queryGetCapabilities_t queryGetCapabilities;
	queryGetHashType_t queryGetHashType;
	queryGetFlags_t queryGetFlags;
	queryGetConstraintCategory_t queryGetConstraintCategory;

	/* Available since interface version 3 */
	constructInvalid_t constructInvalid;
	checkRuntimeForUUID_t checkRuntimeForUUID;
	extractModule_t extractModule;
	getModule_t getModule;
	getUUID_t getUUID;
} TrustCacheInterface_t;

#pragma mark Main AMFI Structure

typedef struct _amfi {
	amfi_OSEntitlements_invalidate OSEntitlements_invalidate;
	amfi_OSEntitlements_asDict OSEntitlements_asdict;
	amfi_OSEntitlements_query OSEntitlements_query;
	amfi_OSEntitlements_get_transmuted_blob OSEntitlements_get_transmuted;
	amfi_OSEntitlements_get_xml_blob OSEntitlements_get_xml;
	coreentitlements_t CoreEntitlements;
	amfi_get_legacy_profile_exemptions get_legacy_profile_exemptions;
	amfi_get_udid get_udid;
	amfi_query_context_to_object query_context_to_object;

#if KERN_AMFI_SUPPORTS_TRUST_CACHE_API
	/* Interface to interact with libTrustCache */
	TrustCacheInterface_t TrustCache;
#endif

#if KERN_AMFI_SUPPORTS_OSENTITLEMENTS_API
	/* Interface to interact with OSEntitlements */
	OSEntitlementsInterface_t OSEntitlements;
#endif
} amfi_t;

__BEGIN_DECLS

/*!
 * @const amfi
 * The AMFI interface that was registered.
 */
extern const amfi_t * amfi;

/*!
 * @function amfi_interface_register
 * Registers the AMFI kext interface for use within the kernel proper.
 *
 * @param mfi
 * The interface to register.
 *
 * @discussion
 * This routine may only be called once and must be called before late-const has
 * been applied to kernel memory.
 */
OS_EXPORT OS_NONNULL1
void
amfi_interface_register(const amfi_t *mfi);

__END_DECLS

#endif // __AMFI_H
