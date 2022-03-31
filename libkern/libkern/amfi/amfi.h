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
#include <sys/types.h>
#include <kern/cs_blobs.h>

#define KERN_AMFI_INTERFACE_VERSION 5
#define KERN_AMFI_SUPPORTS_DATA_ALLOC 1

#if XNU_KERNEL_PRIVATE
#define CORE_ENTITLEMENTS_I_KNOW_WHAT_IM_DOING
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
} amfi_t;

__BEGIN_DECLS

/*!
 * @const amfi
 * The AMFI interface that was registered.
 */
extern const amfi_t *amfi;

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
