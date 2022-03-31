/*
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
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
/*
 * @OSF_COPYRIGHT@
 */
/*
 * Mach Operating System
 * Copyright (c) 1991,1990,1989 Carnegie Mellon University
 * All Rights Reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */
/*
 */
/*
 *	File:	ipc/ipc_notify.c
 *	Author:	Rich Draves
 *	Date:	1989
 *
 *	Notification-sending functions.
 */

#include <mach/port.h>
#include <mach/message.h>
#include <mach/mach_notify.h>
#include <kern/misc_protos.h>
#include <kern/ipc_kobject.h>
#include <ipc/ipc_notify.h>
#include <ipc/ipc_port.h>

/*
 *	Routine:	ipc_notify_port_deleted
 *	Purpose:
 *		Send a port-deleted notification.
 *	Conditions:
 *		Nothing locked.
 *		Consumes a ref/soright for port.
 */

void
ipc_notify_port_deleted(
	ipc_port_t              port,
	mach_port_name_t        name)
{
	(void)mach_notify_port_deleted(port, name);
	/* send-once right consumed */
}

/*
 *	Routine:	ipc_notify_send_possible
 *	Purpose:
 *		Send a send-possible notification.
 *	Conditions:
 *		Nothing locked.
 *		Consumes a ref/soright for port.
 */

void
ipc_notify_send_possible(
	ipc_port_t              port,
	mach_port_name_t        name)
{
	(void)mach_notify_send_possible(port, name);
	/* send-once right consumed */
}

/*
 *	Routine:	ipc_notify_port_destroyed
 *	Purpose:
 *		Send a port-destroyed notification.
 *	Conditions:
 *		Nothing locked.
 *		Consumes a ref/soright for port.
 *		Consumes a ref for right, which should be a receive right
 *		prepped for placement into a message.  (In-transit,
 *		or in-limbo if a circularity was detected.)
 */

void
ipc_notify_port_destroyed(
	ipc_port_t      port,
	ipc_port_t      right)
{
	mach_notify_port_destroyed(port, right);
	/* send-once and receive rights consumed */
}

/*
 *	Routine:	ipc_notify_no_senders_prepare
 *	Purpose:
 *		Prepare for consuming a no senders notification
 *		when the port send right count just hit 0.
 *	Conditions:
 *		The port is locked.
 *
 *		For kobjects (ns_is_kobject), the `ns_notify` port has a reference.
 *		For regular ports, the `ns_notify` has an outstanding send once right.
 *	Returns:
 *		A token that must be passed to ipc_notify_no_senders_emit.
 */
ipc_notify_nsenders_t
ipc_notify_no_senders_prepare(
	ipc_port_t              port)
{
	ipc_notify_nsenders_t req = { };

	ip_mq_lock_held(port);

	if (port->ip_nsrequest == IP_KOBJECT_NSREQUEST_ARMED) {
		port->ip_nsrequest = IP_NULL;

		if (ip_active(port)) {
			req.ns_notify = port;
			req.ns_mscount = port->ip_mscount;
			req.ns_is_kobject = true;
		} else {
			/* silently consume the port-ref */
			ip_release_live(port);
		}
	} else if (port->ip_nsrequest) {
		req.ns_notify = port->ip_nsrequest;
		req.ns_mscount = port->ip_mscount;
		req.ns_is_kobject = false;

		port->ip_nsrequest = IP_NULL;
	}

	return req;
}

/*
 *	Routine:	ipc_notify_no_senders
 *	Purpose:
 *		Send a no-senders notification.
 *	Conditions:
 *		Nothing locked.
 *		Consumes a ref/soright for port.
 */

void
ipc_notify_no_senders(
	ipc_port_t              port,
	mach_port_mscount_t     mscount,
	boolean_t               kobject)
{
	if (kobject) {
		ipc_kobject_notify_no_senders(port, mscount);
	} else {
		(void)mach_notify_no_senders(port, mscount);
		/* send-once right consumed */
	}
}

/*
 *	Routine:	ipc_notify_no_senders_consume
 *	Purpose:
 *		Consume a no-senders notification.
 *	Conditions:
 *		Nothing locked.
 *		Consumes a ref/soright for port.
 */

void
ipc_notify_no_senders_consume(
	ipc_notify_nsenders_t   nsrequest)
{
	if (nsrequest.ns_notify) {
		if (nsrequest.ns_is_kobject) {
			ip_release(nsrequest.ns_notify);
		} else {
			ipc_port_release_sonce(nsrequest.ns_notify);
		}
	}
}

/*
 *	Routine:	ipc_notify_send_once_and_unlock
 *	Purpose:
 *		Send a send-once notification.
 *	Conditions:
 *		Port is locked.
 *		Consumes a ref/soright for port.
 */

void
ipc_notify_send_once_and_unlock(
	ipc_port_t      port)
{
	if (!ip_active(port)) {
		ipc_port_release_sonce_and_unlock(port);
	} else if (ip_in_space(port, ipc_space_kernel)) {
		ipc_kobject_notify_send_once_and_unlock(port);
	} else if (ip_full_kernel(port)) {
		ipc_port_release_sonce_and_unlock(port);
	} else {
		ip_mq_unlock(port);
		(void)mach_notify_send_once(port);
	}
	/* send-once right consumed */
}

/*
 *	Routine:	ipc_notify_dead_name
 *	Purpose:
 *		Send a dead-name notification.
 *	Conditions:
 *		Nothing locked.
 *		Consumes a ref/soright for port.
 */

void
ipc_notify_dead_name(
	ipc_port_t              port,
	mach_port_name_t        name)
{
	(void)mach_notify_dead_name(port, name);
	/* send-once right consumed */
}
