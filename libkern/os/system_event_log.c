/* Copyright (c) 2021 Apple Inc. All rights reserved. */

#include <kern/clock.h>
#include <libkern/libkern.h>
#include <machine/machine_routines.h>
#include <os/system_event_log.h>

static const char *
convert_subsystem_to_string(uint8_t subsystem)
{
	switch (subsystem) {
	case SYSTEM_EVENT_SUBSYSTEM_LAUNCHD:
		return "launchd";
	case SYSTEM_EVENT_SUBSYSTEM_TEST:
		return "test";
	case SYSTEM_EVENT_SUBSYSTEM_NVRAM:
		return "nvram";
	case SYSTEM_EVENT_SUBSYSTEM_PROCESS:
		return "process";
	default:
		break;
	}
	return "UNKNOWN";
}

static const char *
convert_type_to_string(uint8_t type)
{
	switch (type) {
	case SYSTEM_EVENT_TYPE_INFO:
		return "INFO";
	case SYSTEM_EVENT_TYPE_ERROR:
		return "ERROR";
	default:
		break;
	}
	return "UNKNOWN";
}

/* We don't want to interfere with critical tasks.
 * Skip recording this event if:
 *   1. Interrupts are disabled.
 *   2. We are not in a panic.
 * A suggested improvement is adding events to an MPSC queue to log later on (rdar://84678724).
 */
static bool
is_recording_allowed(void)
{
	return ml_get_interrupts_enabled() || panic_active();
}

static void
_record_system_event_internal(uint8_t type, uint8_t subsystem, const char *event, const char *payload)
{
	const char *type_string = convert_type_to_string(type);
	const char *subsystem_string = convert_subsystem_to_string(subsystem);

	uint64_t nanosecs;
	const uint64_t timestamp = mach_continuous_time();
	absolutetime_to_nanoseconds(timestamp, &nanosecs);

	printf("[System Event] [%llu] [%s] [Subsystem: %s] [Event: %.*s] %s\n", timestamp, type_string, subsystem_string, SYSTEM_EVENT_EVENT_MAX, event, payload);
}

void
record_system_event(uint8_t type, uint8_t subsystem, const char *event, const char *format, ...)
{
	if (!is_recording_allowed()) {
		return;
	}

	va_list args;
	va_start(args, format);
	char payload[SYSTEM_EVENT_PAYLOAD_MAX];

	vsnprintf(payload, sizeof(payload), format, args);
	va_end(args);

	_record_system_event_internal(type, subsystem, event, payload);
}

void
record_system_event_no_varargs(uint8_t type, uint8_t subsystem, const char *event, const char *payload)
{
	if (!is_recording_allowed()) {
		return;
	}

	_record_system_event_internal(type, subsystem, event, payload);
}
