/*
 * Copyright (c) 2019-2021 Apple Inc. All rights reserved.
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


#include <stddef.h>
#include <stdint.h>
#include <errno.h>
#include <skywalk/os_packet.h>
#include <skywalk/os_channel_event.h>

#ifndef LIBSYSCALL_INTERFACE
#error "LIBSYSCALL_INTERFACE not defined"
#endif /* !LIBSYSCALL_INTERFACE */

int
os_channel_event_get_next_event(const os_channel_event_handle_t event_handle,
    const os_channel_event_t prev_event, os_channel_event_t *event)
{
	struct __kern_channel_event *cev, *pev;
	buflet_t buflet;
	uint16_t bdlen;
	char *baddr, *estart;

	*event = NULL;
	if (!event_handle) {
		return EINVAL;
	}
	buflet = os_packet_get_next_buflet(event_handle, NULL);
	if (__improbable(buflet == NULL)) {
		return EINVAL;
	}
	baddr = os_buflet_get_object_address(buflet);
	if (__improbable(baddr == NULL)) {
		return ENXIO;
	}
	bdlen = os_buflet_get_data_length(buflet);
	baddr += os_buflet_get_data_offset(buflet);
	estart = baddr + __KERN_CHANNEL_EVENT_OFFSET;
	pev = (struct __kern_channel_event *)prev_event;
	if (pev == NULL) {
		cev = (struct __kern_channel_event *)estart;
	} else {
		if ((pev->ev_flags & CHANNEL_EVENT_FLAG_MORE_EVENT) == 0) {
			return ENODATA;
		}
		cev = (struct __kern_channel_event *)((char *)pev + sizeof(*pev) +
		    pev->ev_dlen);
	}
	if (__improbable((char *)cev < estart)) {
		return ENXIO;
	}
	if (__improbable((cev->ev_dlen + (char *)cev) > (baddr + bdlen))) {
		return ENXIO;
	}
	*event = (os_channel_event_t)cev;
	return 0;
}

int
os_channel_event_get_event_data(const os_channel_event_t event,
    struct os_channel_event_data *event_data)
{
	struct __kern_channel_event *kev;

	if (__improbable(event == 0 || event_data == NULL)) {
		return EINVAL;
	}
	kev = (struct __kern_channel_event *)event;
	if (__improbable(kev->ev_type < CHANNEL_EVENT_MIN ||
	    kev->ev_type > CHANNEL_EVENT_MAX)) {
		return ENXIO;
	}
	event_data->event_type = kev->ev_type;
	event_data->event_more =
	    (kev->ev_flags & CHANNEL_EVENT_FLAG_MORE_EVENT) != 0;
	event_data->event_data_length = kev->ev_dlen;
	event_data->event_data = kev->ev_data;
	return 0;
}
