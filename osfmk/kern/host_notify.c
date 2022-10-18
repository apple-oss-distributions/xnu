/*
 * Copyright (c) 2003-2020 Apple Inc. All rights reserved.
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

#include <mach/mach_types.h>
#include <mach/mach_host.h>

#include <kern/kern_types.h>
#include <kern/ipc_kobject.h>
#include <kern/host_notify.h>

#include <kern/queue.h>

#include "mach/host_notify_reply.h"

struct host_notify_entry {
	queue_chain_t                   entries;
	ipc_port_t                      port;
	ipc_port_request_index_t        index;
};

LCK_GRP_DECLARE(host_notify_lock_grp, "host_notify");
LCK_MTX_DECLARE(host_notify_lock, &host_notify_lock_grp);

static KALLOC_TYPE_DEFINE(host_notify_zone,
    struct host_notify_entry, KT_DEFAULT);

static queue_head_t     host_notify_queue[HOST_NOTIFY_TYPE_MAX + 1] = {
	QUEUE_HEAD_INITIALIZER(host_notify_queue[HOST_NOTIFY_CALENDAR_CHANGE]),
	QUEUE_HEAD_INITIALIZER(host_notify_queue[HOST_NOTIFY_CALENDAR_SET]),
};

static mach_msg_id_t    host_notify_replyid[HOST_NOTIFY_TYPE_MAX + 1] = {
	HOST_CALENDAR_CHANGED_REPLYID,
	HOST_CALENDAR_SET_REPLYID,
};

kern_return_t
host_request_notification(
	host_t          host,
	host_flavor_t   notify_type,
	ipc_port_t      port)
{
	host_notify_t entry;
	kern_return_t kr;

	if (host == HOST_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if (!IP_VALID(port)) {
		return KERN_INVALID_CAPABILITY;
	}

	if (notify_type > HOST_NOTIFY_TYPE_MAX || notify_type < 0) {
		return KERN_INVALID_ARGUMENT;
	}

	entry = zalloc_flags(host_notify_zone, Z_WAITOK | Z_ZERO | Z_NOFAIL);
	entry->port = port;

again:
	lck_mtx_lock(&host_notify_lock);

	ip_mq_lock(port);
	if (ip_active(port)) {
		kr = ipc_port_request_hnotify_alloc(port, entry, &entry->index);
	} else {
		kr = KERN_INVALID_CAPABILITY;
	}

	if (kr == KERN_SUCCESS) {
		/*
		 * Preserve original ABI of host-notify ports being immovable
		 * as a side effect of being a kobject.
		 *
		 * Unlike the original ABI, multiple registrations
		 * for the same port are now allowed.
		 */
		port->ip_immovable_receive = true;
		enqueue_tail(&host_notify_queue[notify_type], &entry->entries);
	}

	lck_mtx_unlock(&host_notify_lock);

	if (kr == KERN_NO_SPACE) {
		kr = ipc_port_request_grow(port);
		/* port unlocked */
		if (kr == KERN_SUCCESS) {
			goto again;
		}
	} else {
		ip_mq_unlock(port);
	}

	if (kr != KERN_SUCCESS) {
		zfree(host_notify_zone, entry);
	}

	return kr;
}

void
host_notify_cancel(host_notify_t entry)
{
	ipc_port_t port;

	lck_mtx_lock(&host_notify_lock);
	remqueue((queue_entry_t)entry);
	port = entry->port;
	lck_mtx_unlock(&host_notify_lock);

	zfree(host_notify_zone, entry);
	ipc_port_release_sonce(port);
}

static void
host_notify_all(
	host_flavor_t           notify_type,
	mach_msg_header_t       *msg,
	mach_msg_size_t         msg_size)
{
	queue_head_t  send_queue = QUEUE_HEAD_INITIALIZER(send_queue);
	queue_entry_t e;
	host_notify_t entry;
	ipc_port_t    port;

	lck_mtx_lock(&host_notify_lock);

	qe_foreach_safe(e, &host_notify_queue[notify_type]) {
		entry = (host_notify_t)e;
		port  = entry->port;

		ip_mq_lock(port);
		if (ip_active(port)) {
			ipc_port_request_cancel(port, IPR_HOST_NOTIFY,
			    entry->index);
			remqueue(e);
			enqueue_tail(&send_queue, e);
		} else {
			/*
			 * leave the entry in place,
			 * we're racing with ipc_port_dnnotify()
			 * which will call host_notify_cancel().
			 */
		}
		ip_mq_unlock(port);
	}

	lck_mtx_unlock(&host_notify_lock);

	if (queue_empty(&send_queue)) {
		return;
	}

	msg->msgh_bits =
	    MACH_MSGH_BITS_SET(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0, 0, 0);
	msg->msgh_local_port = MACH_PORT_NULL;
	msg->msgh_voucher_port = MACH_PORT_NULL;
	msg->msgh_id = host_notify_replyid[notify_type];

	qe_foreach_safe(e, &send_queue) {
		entry = (host_notify_t)e;
		port  = entry->port;

		zfree(host_notify_zone, entry);

		msg->msgh_remote_port = port;
		(void)mach_msg_send_from_kernel_proper(msg, msg_size);
	}
}

void
host_notify_calendar_change(void)
{
	__Request__host_calendar_changed_t      msg;

	host_notify_all(HOST_NOTIFY_CALENDAR_CHANGE, &msg.Head, sizeof(msg));
}

void
host_notify_calendar_set(void)
{
	__Request__host_calendar_set_t  msg;

	host_notify_all(HOST_NOTIFY_CALENDAR_SET, &msg.Head, sizeof(msg));
}
