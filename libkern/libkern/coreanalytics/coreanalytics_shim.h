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
#ifdef KERNEL_PRIVATE
#ifndef _COREANALYTICS_SHIM_H
#define _COREANALYTICS_SHIM_H

/*
 * Shim between xnu and CoreAnalyticsFamily kext.
 * If you're trying to use CoreAnalytics from within xnu, you're in the wrong place.
 * See libkern/libkern/coreanalytics/coreanalytics.h instead.
 */

#ifdef __cplusplus
#include <libkern/c++/OSDictionary.h>
#include <libkern/c++/OSString.h>
#include <libkern/c++/OSObject.h>
#include <IOKit/IOService.h>
#endif /* __cplusplus */

#include <os/base.h>

/*
 * Increment whenever core_analytics_hub_functions_s changes.
 * CoreAnalyticsHub will report which version it was built against.
 * If the versions don't match, we will panic at boot.
 * This likely means CoreAnalyticsHub needs to be rebuilt.
 */
#define CORE_ANALYTICS_FUNCTIONS_TABLE_VERSION 1

#ifdef __cplusplus
typedef const struct core_analytics_hub_functions_s {
	int version;
	bool (*analytics_send_event_lazy)(IOService *core_analytics_hub, OSString *event_name, OSObject *event_payload);
} core_analytics_hub_functions_t;
#else
typedef const struct core_analytics_hub_functions_s {
	int version;
	bool (*analytics_send_event_lazy)(void *core_analytics_hub, void *event_name, void *event_payload);
} core_analytics_hub_functions_t;
#endif /* __cplusplus */

__BEGIN_DECLS

OS_EXPORT OS_NONNULL1
void core_analytics_hub_register(core_analytics_hub_functions_t *fns);

__END_DECLS

#ifdef XNU_KERNEL_PRIVATE
/* XNU private interface to shim into CoreAnalyticsHub */
extern core_analytics_hub_functions_t *core_analytics_hub_functions;

#ifdef __cplusplus
typedef IOService core_analytics_family_service_t;
extern "C" {
#else
/*
 * Anonymous struct representing the CoreAnalyticsFamily IOService.
 * This is just here to provide some basic type-checking to C clients.
 */
typedef struct core_analytics_family_service core_analytics_family_service_t;
#endif
/*
 * Match the CoreAnalyticsFamily IOService.
 * Retains a reference to the IOService which may be released via
 * core_analyics_family_release.
 * May block.
 */
core_analytics_family_service_t *core_analytics_family_match(void);

/*
 * Release the reference retained by core_analytics_family_match
 */
#ifdef __cplusplus
void core_analytics_family_release(LIBKERN_CONSUMED core_analytics_family_service_t *);
#else
void core_analytics_family_release(core_analytics_family_service_t *);
#endif

int core_analytics_send_event_lazy(core_analytics_family_service_t *core_analytics_hub, const char *event_spec, const ca_event_t event);

/*
 * Checks if field spec is string. If yes, it returns size of the string buffer,
 * (not strlen) else it returns 0.
 */
size_t core_analytics_field_is_string(const char *field_spec);
#ifdef __cplusplus
}
#endif

#endif /* XNU_KERNEL_PRIVATE */

#endif /* _COREANALYTICS_SHIM_H */
#endif /* KERNEL_PRIVATE */
