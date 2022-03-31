/* @APPLE_OSREFERENCE_LICENSE_HEADER_START@
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

#include <kern/mpsc_queue.h>
#include <kern/thread.h>
#include <libkern/coreanalytics/coreanalytics.h>
#include <libkern/coreanalytics/coreanalytics_shim.h>
#include <os/log.h>
#include <stdlib.h>

/*
 * xnu telemetry is meant to be extremely lightweight.
 * Clients put a buffer in a mpsc queue & the telemetry thread
 * drains the queue.
 * Serialization happens in the telemetry thread.
 * Currently we serialize to an OSDictionary & send it to
 * the CoreAnalyticsFamily kext (which sticks it on its own queue and
 * has another thread to serialize & send to osanalyticsd).
 * This is fine for a low volume of events.
 * But long term we should send directly to osanlyticsd from here
 * & kexts should send their events to xnu rather than rely on another kext.
 */

#define CORE_ANALYTICS_EVENT_QUEUE_PRIORITY MAXPRI_USER

/* Holds private state used by the telemetry thread */
static struct {
	core_analytics_family_service_t *ts_core_analytics_service;
} telemetry_state = {0};

static struct mpsc_daemon_queue core_analytics_event_queue;

const char *core_analytics_ca_bool_c_stringified = _CA_STRINGIFY_EXPAND(CA_BOOL);
extern const char *core_analytics_ca_bool_cpp_stringified;

size_t
core_analytics_field_is_string(const char *field_spec)
{
	size_t size = 0;
	static const char *ca_str_prefix = _CA_STRINGIFY_EXPAND(CA_STATIC_STRING());
	size_t ca_str_len = strlen(ca_str_prefix) - 1;
	if (strncmp(field_spec, ca_str_prefix, ca_str_len) == 0) {
		const char *sizep = field_spec + ca_str_len;
		size = strtoul(sizep, NULL, 10);
	}
	return size;
}

static size_t
event_field_size(const char **field_spec)
{
	size_t size = 0;
	size_t str_len = 0;
	if (strcmp(*field_spec, _CA_STRINGIFY_EXPAND(CA_INT)) == 0) {
		size = sizeof(const uint64_t);
	} else if ((strcmp(*field_spec, core_analytics_ca_bool_cpp_stringified) == 0) ||
	    (strcmp(*field_spec, core_analytics_ca_bool_c_stringified) == 0)) {
		size = sizeof(const bool);
	} else if ((str_len = core_analytics_field_is_string(*field_spec)) != 0) {
		size = str_len;
	} else {
		panic("Unknown CA event type: %s.", *field_spec);
	}
	/* Skip over the type */
	*field_spec += strlen(*field_spec) + 1;
	/* Skip over the key */
	*field_spec += strlen(*field_spec) + 1;
	return size;
}

size_t
core_analytics_event_size(const char *event_spec)
{
	size_t size = 0;
	/* Skip over the event name. */
	const char *curr = event_spec + strlen(event_spec) + 1;
	while (strlen(curr) != 0) {
		size += event_field_size(&curr);
	}
	return size;
}

static void
core_analytics_event_queue_invoke(mpsc_queue_chain_t e, mpsc_daemon_queue_t queue __unused)
{
	if (!telemetry_state.ts_core_analytics_service) {
		/* First event since boot. Ensure the CoreAnalytics IOService is running. */
		telemetry_state.ts_core_analytics_service = core_analytics_family_match();
	}
	ca_event_t event;
	event = mpsc_queue_element(e, struct _ca_event, link);
	core_analytics_send_event_lazy(telemetry_state.ts_core_analytics_service, event->format_str, event);
	CA_EVENT_DEALLOCATE(event);
}

__startup_func
static void
telemetry_init(void *arg __unused)
{
	kern_return_t result;
	result = mpsc_daemon_queue_init_with_thread(&core_analytics_event_queue,
	    core_analytics_event_queue_invoke, CORE_ANALYTICS_EVENT_QUEUE_PRIORITY,
	    "daemon.core-analytics-events", MPSC_DAEMON_INIT_NONE);
}
STARTUP_ARG(EARLY_BOOT, STARTUP_RANK_MIDDLE, telemetry_init, NULL);

void
core_analytics_send_event(ca_event_t event)
{
	mpsc_daemon_enqueue(&core_analytics_event_queue, &event->link, MPSC_QUEUE_DISABLE_PREEMPTION);
}

void
core_analytics_send_event_preemption_disabled(ca_event_t event)
{
	mpsc_daemon_enqueue(&core_analytics_event_queue, &event->link, MPSC_QUEUE_NONE);
}

ca_event_t
core_analytics_allocate_event(size_t data_size, const char *format_str, zalloc_flags_t flags)
{
	ca_event_t event = kalloc_type(struct _ca_event, flags);
	if (!event) {
		return NULL;
	}
	event->data = kalloc_data(data_size, flags);
	if (!event->data) {
		kfree_type(struct _ca_event, event);
		return NULL;
	}
	event->format_str = format_str;
	return event;
}
