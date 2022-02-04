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

#define IOKIT_ENABLE_SHARED_PTR
#include <kern/debug.h>
#include <libkern/coreanalytics/coreanalytics.h>
#include <libkern/coreanalytics/coreanalytics_shim.h>
#include <libkern/c++/OSBoolean.h>
#include <libkern/c++/OSDictionary.h>
#include <libkern/c++/OSNumber.h>
#include <libkern/c++/OSMetaClass.h>
#include <libkern/c++/OSString.h>
#include <os/atomic.h>
#include <os/log.h>
#include <sys/errno.h>

/* Pulled from CoreAnalyticsHub.h in CoreAnalytics project */
static const char *kCoreAnalyticsMatchingClassName = "CoreAnalyticsHub";

core_analytics_hub_functions_t *core_analytics_hub_functions = NULL;

core_analytics_family_service_t *
core_analytics_family_match()
{
	OSSharedPtr<OSDictionary> dict = IOService::serviceMatching(kCoreAnalyticsMatchingClassName);
	OSSharedPtr<IOService> service = nullptr;
	if (dict) {
		service = IOService::waitForMatchingService(dict.get());
	} else {
		os_log_with_startup_serial(OS_LOG_DEFAULT, "No service matching %s", kCoreAnalyticsMatchingClassName);
	}
	if (service) {
		return service.detach();
	} else {
		os_log_with_startup_serial(OS_LOG_DEFAULT, "Unable to match CoreAnalyticsHub");
		return nullptr;
	}
}

void
core_analytics_family_release(core_analytics_family_service_t *service)
{
	service->release();
}

typedef struct core_analytics_serialized_event_s {
	OSSharedPtr<OSString> case_event_name;
	OSSharedPtr<OSDictionary> case_event;
} core_analytics_serialized_event_t;

/*
 * Stringifying CA_BOOL is different in C vs. C++ b/c the underlying
 * bool typename is different (_Bool vs bool).
 * We want to support both since the event may have been defined in C or C++ code.
 */
extern const char *core_analytics_ca_bool_c_stringified;
const char *core_analytics_ca_bool_cpp_stringified = _CA_STRINGIFY_EXPAND(CA_BOOL);

static OSSharedPtr<OSObject>
serialize_event_field(const char **field_spec, ptrdiff_t *event, OSSharedPtr<const OSSymbol> *key)
{
	OSSharedPtr<OSObject> field = nullptr;
	ptrdiff_t field_value = (ptrdiff_t) *event;
	uint64_t number_value;
	const char *str_value;
	size_t str_len = 0;
	bool bool_value;

	if (strcmp(*field_spec, _CA_STRINGIFY_EXPAND(CA_INT)) == 0) {
		number_value = *(const uint64_t *)field_value;
		field = OSNumber::withNumber(number_value, sizeof(uint64_t) * 8);
		*event += sizeof(const uint64_t);
	} else if (strcmp(*field_spec, core_analytics_ca_bool_cpp_stringified) == 0 ||
	    strcmp(*field_spec, core_analytics_ca_bool_c_stringified) == 0) {
		bool_value = *(const bool *)field_value;
		field = OSBoolean::withBoolean(bool_value);
		*event += sizeof(const bool);
	} else if ((str_len = core_analytics_field_is_string(*field_spec)) != 0) {
		str_value = (const char *) field_value;
		assert(strlen(str_value) < str_len);
		if (strlen(str_value) < str_len) {
			field = OSString::withCString(str_value);
		} else {
			field = nullptr;
		}
		*event += str_len;
	} else {
		panic("Unknown CoreAnalytics event type: %s.", *field_spec);
	}
	*field_spec += strlen(*field_spec) + 1;

	*key = OSSymbol::withCString(*field_spec);
	assert(*key != nullptr);
	if (!*key) {
		return nullptr;
	}
	*field_spec += strlen(*field_spec) + 1;
	return field;
}

static int
core_analytics_serialize_event(const char *event_spec,
    const ca_event_t event,
    core_analytics_serialized_event_t *serialized_event)
{
	serialized_event->case_event_name = nullptr;
	serialized_event->case_event = nullptr;
	OSSharedPtr<OSDictionary> dict = nullptr;
	bool success;
	OSSharedPtr<OSString> name = OSString::withCStringNoCopy(event_spec);
	if (!name) {
		return ENOMEM;
	}
	dict = OSDictionary::withCapacity(1);
	if (!dict) {
		return ENOMEM;
	}
	const char *spec_curr = event_spec + strlen(event_spec) + 1;
	ptrdiff_t event_curr = (ptrdiff_t) event->data;
	while (strlen(spec_curr) != 0) {
		OSSharedPtr<const OSSymbol> key = NULL;
		OSSharedPtr<OSObject> object = serialize_event_field(&spec_curr, &event_curr, &key);
		if (!object) {
			return ENOMEM;
		}
		success = dict->setObject(key, object);
		if (!success) {
			return ENOMEM;
		}
	}

	serialized_event->case_event_name = name;
	serialized_event->case_event = dict;
	return 0;
}

int
core_analytics_send_event_lazy(
	core_analytics_family_service_t *core_analytics_hub,
	const char *event_spec, const ca_event_t event)
{
	int ret = 0;
	bool success;
	static constexpr size_t kMaxRetries = 5;
	static constexpr uint64_t kDelayBetweenRetries = 1000; // microseconds
	core_analytics_serialized_event_t serialized;
	if (!core_analytics_hub_functions) {
		os_log_with_startup_serial(OS_LOG_DEFAULT, "Dropping attempt to send a CoreAnalytics event before CoreAnalyticsHub has registered.");
		return EAGAIN;
	}

	ret = core_analytics_serialize_event(event_spec, event, &serialized);
	if (ret != 0) {
		os_log_with_startup_serial(OS_LOG_DEFAULT, "Unable to serialize CoreAnalytics event: %d", ret);
		return ret;
	}
	for (size_t i = 0; i < kMaxRetries; i++) {
		success = core_analytics_hub_functions->analytics_send_event_lazy(core_analytics_hub, serialized.case_event_name.get(), serialized.case_event.get());
		if (success) {
			break;
		} else {
			if (i != kMaxRetries - 1) {
				os_log_with_startup_serial(OS_LOG_DEFAULT, "Unable to send CoreAnalytics event. Delaying for %llu u.s. to see if the queue drains.", kDelayBetweenRetries);
				delay(kDelayBetweenRetries);
			} else {
				os_log_with_startup_serial(OS_LOG_DEFAULT, "Unable to send CoreAnalytics event. Giving up.");
				ret = EAGAIN;
				break;
			}
		}
	}
	return ret;
}

void
core_analytics_hub_register(core_analytics_hub_functions_t *fns)
{
	if (fns->version != CORE_ANALYTICS_FUNCTIONS_TABLE_VERSION) {
		panic("CoreAnalyticsHub is out of sync with xnu. CoreAnalyticsHub table version: %d. xnu table version: %d", fns->version, CORE_ANALYTICS_FUNCTIONS_TABLE_VERSION);
	}
	core_analytics_hub_functions = fns;
	os_log_with_startup_serial(OS_LOG_DEFAULT, "Registered CoreAnalyticsHub functions with xnu.");
}
