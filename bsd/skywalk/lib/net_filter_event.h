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

#include <stdbool.h>

#include <sys/types.h>
#include <sys/eventhandler.h>

enum net_filter_event_subsystems : uint32_t {
	NET_FILTER_EVENT_PF = (1 << 0),
	NET_FILTER_EVENT_SOCKET = (1 << 1),
	NET_FILTER_EVENT_INTERFACE = (1 << 2),
	NET_FILTER_EVENT_IP = (1 << 3),
	NET_FILTER_EVENT_ALF = (1 << 4),
	NET_FILTER_EVENT_PARENTAL_CONTROLS = (1 << 5)
};

/* Marks subsystem filtering state. */
void
net_filter_event_mark(enum net_filter_event_subsystems subsystem, bool compatible);

typedef void (*net_filter_event_callback_t) (struct eventhandler_entry_arg,
    enum net_filter_event_subsystems);

/* Registers a function to be called when state changes. */
void
net_filter_event_register(net_filter_event_callback_t callback);

/* Gets the state of the filters. */
enum net_filter_event_subsystems
net_filter_event_get_state(void);
