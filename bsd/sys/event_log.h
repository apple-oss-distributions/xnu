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

#ifndef _SYSTEM_EVENT_LOG_H_
#define _SYSTEM_EVENT_LOG_H_

#include <Availability.h>
#include <sys/cdefs.h>
#include <stdint.h>

__BEGIN_DECLS

#define SYSTEM_EVENT_ENTITLEMENT "com.apple.private.record_system_event"

// These arbitrary numbers are used to limit the size of the system event message.
// We don't want the messages to be too long, as they're going over serial.
#define SYSTEM_EVENT_EVENT_MAX 64
#define SYSTEM_EVENT_PAYLOAD_MAX 96

__enum_decl(system_event_type, uint8_t, {
	SYSTEM_EVENT_TYPE_FIRST = 0,
	SYSTEM_EVENT_TYPE_INFO,
	SYSTEM_EVENT_TYPE_ERROR,
	SYSTEM_EVENT_TYPE_LAST
});

__enum_decl(system_event_subsystem, uint8_t, {
	SYSTEM_EVENT_SUBSYSTEM_FIRST = 0,
	SYSTEM_EVENT_SUBSYSTEM_LAUNCHD,
	SYSTEM_EVENT_SUBSYSTEM_TEST,
	SYSTEM_EVENT_SUBSYSTEM_NVRAM,
	SYSTEM_EVENT_SUBSYSTEM_PROCESS,
	SYSTEM_EVENT_SUBSYSTEM_LAST
});

#ifndef KERNEL

/*
 * Known subsystems can use this to emit system event transition logging messages in
 * a structured and understandable way.
 */

__WATCHOS_AVAILABLE(9.0) __OSX_AVAILABLE(13.0) __IOS_AVAILABLE(16.0) __TVOS_AVAILABLE(16.0)
int
record_system_event_as_kernel(system_event_type type, system_event_subsystem subsystem, const char *event,
    const char *payload);

#endif /* !KERNEL */

__END_DECLS

#endif /* _SYSTEM_EVENT_LOG_H_ */
