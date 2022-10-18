/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
 *	File:	ipc/ipc_pset.h
 *	Author:	Rich Draves
 *	Date:	1989
 *
 *	Definitions for port sets.
 */

#ifndef _IPC_IPC_PSET_H_
#define _IPC_IPC_PSET_H_

#include <mach/mach_types.h>
#include <mach/port.h>
#include <mach/kern_return.h>
#include <kern/kern_types.h>
#include <ipc/ipc_types.h>
#include <ipc/ipc_object.h>
#include <ipc/ipc_mqueue.h>

struct ipc_pset {
	/*
	 * Initial sub-structure in common with all ipc_objects.
	 */
	struct ipc_object       ips_object;
	struct waitq_set        ips_wqset;
	struct klist            ips_klist;
};

#define ips_object_to_pset(io)      __container_of(io, struct ipc_pset, ips_object)
#define ips_to_object(pset)         (&(pset)->ips_object)

static inline ipc_pset_t
ips_from_waitq(waitq_t wq)
{
	return __container_of(wq.wqs_set, struct ipc_pset, ips_wqset);
}

#define ips_active(pset)            io_active(ips_to_object(pset))
#define ips_mq_lock(pset)           io_lock(ips_to_object(pset))
#define ips_mq_lock_held_kdp(pset)  io_lock_held_kdp(ips_to_object(pset))
#define ips_mq_unlock(pset)         io_unlock(ips_to_object(pset))
#define ips_reference(pset)         io_reference(ips_to_object(pset))
#define ips_release(pset)           io_release(ips_to_object(pset))
#define ips_validate(pset) \
	zone_id_require(ZONE_ID_IPC_PORT_SET, sizeof(struct ipc_pset), pset)

/* Allocate a port set */
extern kern_return_t ipc_pset_alloc(
	ipc_space_t             space,
	mach_port_name_t        *namep,
	ipc_pset_t              *psetp);

/* Allocate a port set, with a specific name */
extern kern_return_t ipc_pset_alloc_name(
	ipc_space_t             space,
	mach_port_name_t        name,
	ipc_pset_t              *psetp);

/* Allocate a port set in a special space */
extern ipc_pset_t ipc_pset_alloc_special(
	ipc_space_t             space);

/* Destroy a port_set */
extern void ipc_pset_destroy(
	ipc_space_t     space,
	ipc_pset_t      pset);

/* Finalize the destruction of a pset before it gets freed */
extern void ipc_pset_finalize(
	ipc_pset_t      pset);

#if MACH_KERNEL_PRIVATE
extern struct turnstile *filt_ipc_kqueue_turnstile(
	struct knote   *kn);

extern bool filt_machport_kqueue_has_turnstile(
	struct knote   *kn);

extern void filt_machport_turnstile_prepare_lazily(
	struct knote   *kn,
	mach_msg_type_name_t    msgt_name,
	ipc_port_t      port);

extern struct turnstile *filt_machport_stash_port(
	struct knote   *kn,
	ipc_port_t      port,
	int            *link);
#endif

#endif  /* _IPC_IPC_PSET_H_ */
