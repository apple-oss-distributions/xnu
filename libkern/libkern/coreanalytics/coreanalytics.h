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
#ifdef XNU_KERNEL_PRIVATE
#ifndef _COREANALYTICS_H
#include <libkern/coreanalytics/coreanalytics_internal.h>

/*
 * CoreAnalytics data types
 */

/* 64bit signed integers */
#define CA_INT 1ULL
/* Boolean */
#define CA_BOOL ((bool) 1)
/*
 * A static const string.
 * Currently, it is NOT safe to use a dynamically allocated string with
 * the xnu CoreAnalytics interface.
 */
#define CA_UUID_LEN          37
#define CA_PROCNAME_LEN      17
#define CA_UBSANBUF_LEN      86
#define CA_TEAMID_MAX_LEN    32
#define CA_SIGNINGID_MAX_LEN 128
#define CA_STATIC_STRING(len) ca_sstr[len]

#define CA_EVENT_TYPE(name) struct _ca_event_ ## name

/*
 * Defines a new CoreAnalytics event.
 * The first argument is the event name. This will be prefixed with "com.apple.xnu.".
 * The following arguments define the event type. Fields are defined as a type followed by a name.
 * For example, say we've defined an event called "com.apple.xnu.my_event". It has the following fields
 * count Integer
 * bad_thing_happened Boolean
 * name String
 *
 * We would define this event in xnu like so:
 * CA_EVENT(my_event,
 *     CA_INT, count,
 *     CA_BOOL, bad_thing_happened,
 *     CA_STATIC_STRING(CA_UUID_LEN), name);
 *
 * This defines a struct that we can use to create the event. To get the struct's typename, use the CA_EVENT_TYPE macro.
 * To send the struct, it needs to be allocated via the CoreAnalytics subsystem. So to create and send "my_event" we can do:
 * ca_event_t event = CA_EVENT_ALLOCATE(my_event);
 * CA_EVENT_TYPE(my_event) *event_data = event->data;
 * event_data->count = count_value;
 * event_data->bad_thing_happened = did_bad_thing_happen;
 * strlcpy(event_data->name, bad_thing_name, CA_UUID_LEN);
 * CA_EVENT_SEND(event);
 *
 * Note that CA_EVENT_SEND just enqueues the event on a lock free queue. Serializing & sending the event to userspace happens on another thread.
 */

#define CA_EVENT(name, ...) \
	const char * _CA_EVENT_NAME_PREFIX(name) = _CA_EVENT_ORG #name "\0" _CA_FOREACH(_CA_STRINGIFY, _CA_NULL_TERMINATOR, _CA_STRINGIFY, ##__VA_ARGS__) "\0"; \
	_Static_assert(sizeof(_CA_EVENT_ORG #name) <= 64, "CoreAnalytics event name ('" _CA_EVENT_ORG #name "') is too long"); \
	CA_EVENT_TYPE(name) { \
	        _CA_FOREACH(_CA_TYPE_DECLARATION, _CA_NULL_EPSILON, _CA_VARIABLE_DECLARATION, ##__VA_ARGS__) \
	} __attribute__ ((packed))

/*
 * Allocates a new event struct.
 * Should be freed via CA_EVENT_DEALLOCATE.
 * Will be freed automatically by CA_EVENT_SEND.
 * May block (use CA_EVENT_ALLOCATE_FLAGS with Z_NOWAIT for an allocation which can't block but may fail).
 */
#define CA_EVENT_ALLOCATE(name) \
	core_analytics_allocate_event(sizeof(CA_EVENT_TYPE(name)), _CA_EVENT_NAME_PREFIX(name), Z_WAITOK | Z_ZERO | Z_NOFAIL)

/*
 * Allocate a new event struct with custom zalloc flags.
 */
#define CA_EVENT_ALLOCATE_FLAGS(name, flags) \
	core_analytics_allocate_event(sizeof(CA_EVENT_TYPE(name)), _CA_EVENT_NAME_PREFIX(name), flags)

/*
 * Deallocate an event allocated via CA_EVENT_ALLOCATE
 */
#define CA_EVENT_DEALLOCATE(event)                         \
({                                                         \
	kfree_data(event->data,                                \
	    core_analytics_event_size(event->format_str));     \
	kfree_type(struct _ca_event, event);            \
})

/*
 * Deallocate an event allocated via CA_EVENT_ALLOCATE using name
 */
#define CA_EVENT_DEALLOCATE_WITH_NAME(event, name)         \
({                                                         \
	kfree_data(event->data, sizeof(CA_EVENT_TYPE(name)));  \
	kfree_type(struct _ca_event, event);            \
})

/*
 * Send the given event. Ownership of the event is transferred.
 * Does not block. Does not allocate memory.
 * Is safe to use from an interrupt context.
 * The event may be dropped later in the pipeline.
 *
 * Disables preemption while sending the event.
 * Use CA_EVENT_SEND_PREEMPTION_DISABLED if calling from a context
 * where preemption is already disabled.
 */
#define CA_EVENT_SEND(event) core_analytics_send_event(event)

/*
 * Same as CA_EVENT_SEND but the caller takes responsibility for disabling preemption.
 */
#define CA_EVENT_SEND_PREEMPTION_DISABLED(event) core_analytics_send_event_preemption_disabled(event)

#endif /* _COREANALYTICS_H */
#endif /* XNU_KERNEL_PRIVATE */
