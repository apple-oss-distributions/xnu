/*
 * Copyright (c) 2000-2020 Apple Inc. All rights reserved.
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
 * NOTICE: This file was modified by McAfee Research in 2004 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 * Copyright (c) 2005-2006 SPARTA, Inc.
 */
/*
 */
/*
 *	File:	ipc/ipc_object.c
 *	Author:	Rich Draves
 *	Date:	1989
 *
 *	Functions to manipulate IPC objects.
 */

#include <mach/mach_types.h>
#include <mach/boolean.h>
#include <mach/kern_return.h>
#include <mach/port.h>
#include <mach/message.h>

#include <kern/kern_types.h>
#include <kern/misc_protos.h>
#include <kern/ipc_kobject.h>
#include <kern/zalloc_internal.h> // zone_id_for_native_element

#include <ipc/ipc_types.h>
#include <ipc/ipc_importance.h>
#include <ipc/port.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_entry.h>
#include <ipc/ipc_object.h>
#include <ipc/ipc_hash.h>
#include <ipc/ipc_right.h>
#include <ipc/ipc_notify.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_pset.h>

#include <security/mac_mach_internal.h>

static struct mpsc_daemon_queue ipc_object_deallocate_queue;
SECURITY_READ_ONLY_LATE(zone_t) ipc_object_zones[IOT_NUMBER];

/*
 * In order to do lockfree lookups in the IPC space, we combine two schemes:
 *
 * - the ipc table pointer is protected with hazard pointers to allow
 *   dereferencing it with only holding a ref on a task or space;
 *
 * - we use ipc_object_lock_allow_invalid in order to lock locks and validate
 *   that they are the droid we're looking for.
 *
 * The second half requires that virtual addresses assigned that ever held
 * a port, either hold a port, or nothing, forever. To get this property,
 * we just piggy back on the zone sequestering security feature which gives
 * us exactly that.
 *
 * However, sequestering really only "works" on a sufficiently large address
 * space, especially for a resource that can be made by userspace at will,
 * so we can't do lockless lookups on ILP32.
 *
 * Note: this scheme is incompatible with gzalloc (because it doesn't sequester)
 *       and kasan quarantines (because it uses elements to store backtraces
 *       in them which lets the waitq lock appear "valid" by accident when
 *       elements are freed).
 */
#if MACH_LOCKFREE_SPACE
#define IPC_OBJECT_ZC_BASE (ZC_ZFREE_CLEARMEM | ZC_SEQUESTER | \
	ZC_NOGZALLOC | ZC_KASAN_NOQUARANTINE)
#else
#define IPC_OBJECT_ZC_BASE (ZC_ZFREE_CLEARMEM)
#endif

ZONE_INIT(&ipc_object_zones[IOT_PORT],
    "ipc ports", sizeof(struct ipc_port),
    IPC_OBJECT_ZC_BASE | ZC_CACHING, ZONE_ID_IPC_PORT, NULL);

ZONE_INIT(&ipc_object_zones[IOT_PORT_SET],
    "ipc port sets", sizeof(struct ipc_pset),
    IPC_OBJECT_ZC_BASE, ZONE_ID_IPC_PORT_SET, NULL);

__attribute__((noinline))
static void
ipc_object_free(unsigned int otype, ipc_object_t object, bool last_ref)
{
	if (last_ref && otype == IOT_PORT) {
		ipc_port_finalize(ip_object_to_port(object));
	}
	zfree(ipc_object_zones[otype], object);
}

__attribute__((noinline))
static void
ipc_object_free_safe(ipc_object_t object)
{
	struct waitq *wq = io_waitq(object);

	assert(!waitq_is_valid(wq));
	assert(wq->waitq_tspriv == NULL);
	assert(sizeof(wq->waitq_tspriv) == sizeof(struct mpsc_queue_chain));
	mpsc_daemon_enqueue(&ipc_object_deallocate_queue,
	    (mpsc_queue_chain_t)&wq->waitq_tspriv, MPSC_QUEUE_NONE);
}

static void
ipc_object_deallocate_queue_invoke(mpsc_queue_chain_t e,
    __assert_only mpsc_daemon_queue_t dq)
{
	struct waitq *wq;
	ipc_object_t io;

	assert(dq == &ipc_object_deallocate_queue);

	wq = __container_of((void **)e, struct waitq, waitq_tspriv);
	io = io_from_waitq(wq);
	ipc_object_free(io_otype(io), io, true);
}

void
ipc_object_deallocate_register_queue(void)
{
	thread_deallocate_daemon_register_queue(&ipc_object_deallocate_queue,
	    ipc_object_deallocate_queue_invoke);
}

/*
 *	Routine:	ipc_object_reference
 *	Purpose:
 *		Take a reference to an object.
 */

void
ipc_object_reference(
	ipc_object_t    io)
{
	static_assert(sizeof(os_ref_atomic_t) == sizeof(io->io_references));
	os_ref_retain_raw((os_ref_atomic_t *)&io->io_references, NULL);
}

/*
 *	Routine:	ipc_object_release
 *	Purpose:
 *		Release a reference to an object.
 */

void
ipc_object_release(
	ipc_object_t    io)
{
#if DEBUG
	assert(get_preemption_level() == 0);
#endif

	if (os_ref_release_raw((os_ref_atomic_t *)&io->io_references, NULL) == 0) {
		/* Free the object */
		ipc_object_free(io_otype(io), io, true);
	}
}

/*
 *	Routine:	ipc_object_release_safe
 *	Purpose:
 *		Release a reference to an object safely
 */

void
ipc_object_release_safe(
	ipc_object_t    io)
{
	if (os_ref_release_raw((os_ref_atomic_t *)&io->io_references, NULL) == 0) {
		if (get_preemption_level() == 0) {
			ipc_object_free(io_otype(io), io, true);
		} else {
			ipc_object_free_safe(io);
		}
	}
}

/*
 *	Routine:	ipc_object_release_live
 *	Purpose:
 *		Release a reference to an object that isn't the last one.
 */

void
ipc_object_release_live(
	ipc_object_t    io)
{
	os_ref_release_live_raw((os_ref_atomic_t *)&io->io_references, NULL);
}

/*
 *	Routine:	ipc_object_translate
 *	Purpose:
 *		Look up an object in a space.
 *	Conditions:
 *		Nothing locked before.  If successful, the object
 *		is returned active and locked.  The caller doesn't get a ref.
 *	Returns:
 *		KERN_SUCCESS		Object returned locked.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_INVALID_NAME	The name doesn't denote a right
 *		KERN_INVALID_RIGHT	Name doesn't denote the correct right
 */
kern_return_t
ipc_object_translate(
	ipc_space_t             space,
	mach_port_name_t        name,
	mach_port_right_t       right,
	ipc_object_t            *objectp)
{
	ipc_entry_bits_t bits;
	ipc_object_t object;
	kern_return_t kr;

	if (!MACH_PORT_RIGHT_VALID_TRANSLATE(right)) {
		return KERN_INVALID_RIGHT;
	}

	kr = ipc_right_lookup_read(space, name, &bits, &object);
	if (kr != KERN_SUCCESS) {
		return kr;
	}
	/* object is locked and active */

	if ((bits & MACH_PORT_TYPE(right)) == MACH_PORT_TYPE_NONE) {
		io_unlock(object);
		return KERN_INVALID_RIGHT;
	}

	*objectp = object;
	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_object_translate_two
 *	Purpose:
 *		Look up two objects in a space.
 *	Conditions:
 *		Nothing locked before.  If successful, the objects
 *		are returned locked.  The caller doesn't get a ref.
 *	Returns:
 *		KERN_SUCCESS		Objects returned locked.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_INVALID_NAME	A name doesn't denote a right.
 *		KERN_INVALID_RIGHT	A name doesn't denote the correct right.
 */

kern_return_t
ipc_object_translate_two(
	ipc_space_t             space,
	mach_port_name_t        name1,
	mach_port_right_t       right1,
	ipc_object_t            *objectp1,
	mach_port_name_t        name2,
	mach_port_right_t       right2,
	ipc_object_t            *objectp2)
{
	ipc_entry_t entry1;
	ipc_entry_t entry2;
	ipc_object_t object1, object2;
	kern_return_t kr;
	boolean_t doguard = TRUE;

	kr = ipc_right_lookup_two_read(space, name1, &entry1, name2, &entry2);
	if (kr != KERN_SUCCESS) {
		return kr;
	}
	/* space is read-locked and active */

	if ((entry1->ie_bits & MACH_PORT_TYPE(right1)) == MACH_PORT_TYPE_NONE) {
		/* If looking for receive, and the entry used to hold one, give a pass on EXC_GUARD */
		if ((right1 & MACH_PORT_RIGHT_RECEIVE) == MACH_PORT_RIGHT_RECEIVE &&
		    (entry1->ie_bits & MACH_PORT_TYPE_EX_RECEIVE) == MACH_PORT_TYPE_EX_RECEIVE) {
			doguard = FALSE;
		}
		is_read_unlock(space);
		if (doguard) {
			mach_port_guard_exception(name1, 0, 0, kGUARD_EXC_INVALID_RIGHT);
		}
		return KERN_INVALID_RIGHT;
	}

	if ((entry2->ie_bits & MACH_PORT_TYPE(right2)) == MACH_PORT_TYPE_NONE) {
		/* If looking for receive, and the entry used to hold one, give a pass on EXC_GUARD */
		if ((right2 & MACH_PORT_RIGHT_RECEIVE) == MACH_PORT_RIGHT_RECEIVE &&
		    (entry2->ie_bits & MACH_PORT_TYPE_EX_RECEIVE) == MACH_PORT_TYPE_EX_RECEIVE) {
			doguard = FALSE;
		}
		is_read_unlock(space);
		if (doguard) {
			mach_port_guard_exception(name2, 0, 0, kGUARD_EXC_INVALID_RIGHT);
		}
		return KERN_INVALID_RIGHT;
	}

	object1 = entry1->ie_object;
	assert(object1 != IO_NULL);
	io_lock(object1);
	if (!io_active(object1)) {
		io_unlock(object1);
		is_read_unlock(space);
		return KERN_INVALID_NAME;
	}

	object2 = entry2->ie_object;
	assert(object2 != IO_NULL);
	io_lock(object2);
	if (!io_active(object2)) {
		io_unlock(object1);
		io_unlock(object2);
		is_read_unlock(space);
		return KERN_INVALID_NAME;
	}

	*objectp1 = object1;
	*objectp2 = object2;

	is_read_unlock(space);
	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_object_alloc_dead
 *	Purpose:
 *		Allocate a dead-name entry.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		The dead name is allocated.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_NO_SPACE		No room for an entry in the space.
 */

kern_return_t
ipc_object_alloc_dead(
	ipc_space_t             space,
	mach_port_name_t        *namep)
{
	ipc_entry_t entry;
	kern_return_t kr;

	kr = ipc_entry_alloc(space, IO_NULL, namep, &entry);
	if (kr != KERN_SUCCESS) {
		return kr;
	}
	/* space is write-locked */

	/* null object, MACH_PORT_TYPE_DEAD_NAME, 1 uref */

	entry->ie_bits |= MACH_PORT_TYPE_DEAD_NAME | 1;
	ipc_entry_modified(space, *namep, entry);
	is_write_unlock(space);
	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_object_alloc_dead_name
 *	Purpose:
 *		Allocate a dead-name entry, with a specific name.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		The dead name is allocated.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_NAME_EXISTS	The name already denotes a right.
 */

kern_return_t
ipc_object_alloc_dead_name(
	ipc_space_t             space,
	mach_port_name_t        name)
{
	ipc_entry_t entry;
	kern_return_t kr;

	kr = ipc_entry_alloc_name(space, name, &entry);
	if (kr != KERN_SUCCESS) {
		return kr;
	}
	/* space is write-locked */

	if (ipc_right_inuse(entry)) {
		is_write_unlock(space);
		return KERN_NAME_EXISTS;
	}

	/* null object, MACH_PORT_TYPE_DEAD_NAME, 1 uref */

	assert(entry->ie_object == IO_NULL);
	entry->ie_bits |= MACH_PORT_TYPE_DEAD_NAME | 1;
	ipc_entry_modified(space, name, entry);
	is_write_unlock(space);
	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_object_alloc
 *	Purpose:
 *		Allocate an object.
 *	Conditions:
 *		Nothing locked.
 *		The space is write locked on successful return.
 *		The caller doesn't get a reference for the object.
 *	Returns:
 *		KERN_SUCCESS		The object is allocated.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_NO_SPACE		No room for an entry in the space.
 */

kern_return_t
ipc_object_alloc(
	ipc_space_t             space,
	ipc_object_type_t       otype,
	mach_port_type_t        type,
	mach_port_urefs_t       urefs,
	mach_port_name_t        *namep,
	ipc_object_t            *objectp)
{
	ipc_object_t object;
	ipc_entry_t entry;
	kern_return_t kr;

	assert(otype < IOT_NUMBER);
	assert((type & MACH_PORT_TYPE_ALL_RIGHTS) == type);
	assert(type != MACH_PORT_TYPE_NONE);
	assert(urefs <= MACH_PORT_UREFS_MAX);

	object = io_alloc(otype, Z_WAITOK | Z_ZERO | Z_NOFAIL);
	os_atomic_init(&object->io_bits, io_makebits(TRUE, otype, 0));
	os_atomic_init(&object->io_references, 1); /* for entry, not caller */

	*namep = CAST_MACH_PORT_TO_NAME(object);
	kr = ipc_entry_alloc(space, object, namep, &entry);
	if (kr != KERN_SUCCESS) {
		ipc_object_free(otype, object, false);
		return kr;
	}
	/* space is write-locked */

	entry->ie_bits |= type | urefs;
	ipc_entry_modified(space, *namep, entry);

	*objectp = object;
	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_object_alloc_name
 *	Purpose:
 *		Allocate an object, with a specific name.
 *	Conditions:
 *		Nothing locked.  If successful, the object is returned locked.
 *		The caller doesn't get a reference for the object.
 *
 *		finish_init() must call an ipc_*_init function
 *		that will return the object locked (using IPC_PORT_INIT_LOCKED,
 *		or SYNC_POLICY_INIT_LOCKED, or equivalent).
 *
 *	Returns:
 *		KERN_SUCCESS		The object is allocated.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_NAME_EXISTS	The name already denotes a right.
 */

kern_return_t
ipc_object_alloc_name(
	ipc_space_t             space,
	ipc_object_type_t       otype,
	mach_port_type_t        type,
	mach_port_urefs_t       urefs,
	mach_port_name_t        name,
	ipc_object_t            *objectp,
	void                    (^finish_init)(ipc_object_t))
{
	ipc_object_t object;
	ipc_entry_t entry;
	kern_return_t kr;

	assert(otype < IOT_NUMBER);
	assert((type & MACH_PORT_TYPE_ALL_RIGHTS) == type);
	assert(type != MACH_PORT_TYPE_NONE);
	assert(urefs <= MACH_PORT_UREFS_MAX);

	object = io_alloc(otype, Z_WAITOK | Z_ZERO | Z_NOFAIL);
	os_atomic_init(&object->io_bits, io_makebits(TRUE, otype, 0));
	os_atomic_init(&object->io_references, 1); /* for entry, not caller */

	kr = ipc_entry_alloc_name(space, name, &entry);
	if (kr != KERN_SUCCESS) {
		ipc_object_free(otype, object, false);
		return kr;
	}
	/* space is write-locked */

	if (ipc_right_inuse(entry)) {
		is_write_unlock(space);
		ipc_object_free(otype, object, false);
		return KERN_NAME_EXISTS;
	}

	entry->ie_bits |= type | urefs;
	entry->ie_object = object;

	finish_init(object);
	/* object is locked */
	io_lock_held(object);

	ipc_entry_modified(space, name, entry);
	is_write_unlock(space);

	*objectp = object;
	return KERN_SUCCESS;
}

/*	Routine:	ipc_object_validate
 *	Purpose:
 *		Validates an ipc port or port set as belonging to the correct
 *		zone.
 */

void
ipc_object_validate(
	ipc_object_t    object)
{
	if (io_otype(object) != IOT_PORT_SET) {
		zone_id_require(ZONE_ID_IPC_PORT,
		    sizeof(struct ipc_port), object);
	} else {
		zone_id_require(ZONE_ID_IPC_PORT_SET,
		    sizeof(struct ipc_pset), object);
	}
}

/*
 *	Routine:	ipc_object_copyin_type
 *	Purpose:
 *		Convert a send type name to a received type name.
 */

mach_msg_type_name_t
ipc_object_copyin_type(
	mach_msg_type_name_t    msgt_name)
{
	switch (msgt_name) {
	case MACH_MSG_TYPE_MOVE_RECEIVE:
		return MACH_MSG_TYPE_PORT_RECEIVE;

	case MACH_MSG_TYPE_MOVE_SEND_ONCE:
	case MACH_MSG_TYPE_MAKE_SEND_ONCE:
		return MACH_MSG_TYPE_PORT_SEND_ONCE;

	case MACH_MSG_TYPE_MOVE_SEND:
	case MACH_MSG_TYPE_MAKE_SEND:
	case MACH_MSG_TYPE_COPY_SEND:
		return MACH_MSG_TYPE_PORT_SEND;

	case MACH_MSG_TYPE_DISPOSE_RECEIVE:
	case MACH_MSG_TYPE_DISPOSE_SEND:
	case MACH_MSG_TYPE_DISPOSE_SEND_ONCE:
	/* fall thru */
	default:
		return MACH_MSG_TYPE_PORT_NONE;
	}
}

/*
 *	Routine:	ipc_object_copyin
 *	Purpose:
 *		Copyin a capability from a space.
 *		If successful, the caller gets a ref
 *		for the resulting object, unless it is IO_DEAD.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		Acquired an object, possibly IO_DEAD.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_INVALID_NAME	Name doesn't exist in space.
 *		KERN_INVALID_RIGHT	Name doesn't denote correct right.
 */

kern_return_t
ipc_object_copyin(
	ipc_space_t                space,
	mach_port_name_t           name,
	mach_msg_type_name_t       msgt_name,
	ipc_object_t               *objectp,
	mach_port_context_t        context,
	mach_msg_guard_flags_t     *guard_flags,
	ipc_object_copyin_flags_t  copyin_flags)
{
	ipc_entry_t entry;
	ipc_port_t soright;
	ipc_port_t release_port;
	kern_return_t kr;
	int assertcnt = 0;

	ipc_object_copyin_flags_t irc_flags = IPC_OBJECT_COPYIN_FLAGS_ALLOW_IMMOVABLE_SEND;
	irc_flags = (copyin_flags & irc_flags) | IPC_OBJECT_COPYIN_FLAGS_DEADOK;
	/*
	 *	Could first try a read lock when doing
	 *	MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND,
	 *	and MACH_MSG_TYPE_MAKE_SEND_ONCE.
	 */

	kr = ipc_right_lookup_write(space, name, &entry);
	if (kr != KERN_SUCCESS) {
		return kr;
	}
	/* space is write-locked and active */

	release_port = IP_NULL;
	kr = ipc_right_copyin(space, name, entry,
	    msgt_name, irc_flags,
	    objectp, &soright,
	    &release_port,
	    &assertcnt,
	    context,
	    guard_flags);
	is_write_unlock(space);

#if IMPORTANCE_INHERITANCE
	if (0 < assertcnt && ipc_importance_task_is_any_receiver_type(current_task()->task_imp_base)) {
		ipc_importance_task_drop_internal_assertion(current_task()->task_imp_base, assertcnt);
	}
#endif /* IMPORTANCE_INHERITANCE */

	if (release_port != IP_NULL) {
		ip_release(release_port);
	}

	if ((kr == KERN_SUCCESS) && (soright != IP_NULL)) {
		ipc_notify_port_deleted(soright, name);
	}

	return kr;
}

/*
 *	Routine:	ipc_object_copyin_from_kernel
 *	Purpose:
 *		Copyin a naked capability from the kernel.
 *
 *		MACH_MSG_TYPE_MOVE_RECEIVE
 *			The receiver must be ipc_space_kernel
 *			or the receive right must already be in limbo.
 *			Consumes the naked receive right.
 *		MACH_MSG_TYPE_COPY_SEND
 *			A naked send right must be supplied.
 *			The port gains a reference, and a send right
 *			if the port is still active.
 *		MACH_MSG_TYPE_MAKE_SEND
 *			The receiver must be ipc_space_kernel.
 *			The port gains a reference and a send right.
 *		MACH_MSG_TYPE_MOVE_SEND
 *			Consumes a naked send right.
 *		MACH_MSG_TYPE_MAKE_SEND_ONCE
 *			The port gains a reference and a send-once right.
 *			Receiver also be the caller of device subsystem,
 *			so no assertion.
 *		MACH_MSG_TYPE_MOVE_SEND_ONCE
 *			Consumes a naked send-once right.
 *	Conditions:
 *		Nothing locked.
 */

void
ipc_object_copyin_from_kernel(
	ipc_object_t            object,
	mach_msg_type_name_t    msgt_name)
{
	assert(IO_VALID(object));

	switch (msgt_name) {
	case MACH_MSG_TYPE_MOVE_RECEIVE: {
		ipc_port_t port = ip_object_to_port(object);

		ip_mq_lock(port);
		require_ip_active(port);
		if (ip_in_a_space(port)) {
			assert(ip_in_space(port, ipc_space_kernel));
			assert(port->ip_immovable_receive == 0);

			/* relevant part of ipc_port_clear_receiver */
			port->ip_mscount = 0;

			/* port transtions to IN-LIMBO state */
			port->ip_receiver_name = MACH_PORT_NULL;
			port->ip_destination = IP_NULL;
		}
		ip_mq_unlock(port);
		break;
	}

	case MACH_MSG_TYPE_COPY_SEND: {
		ipc_port_t port = ip_object_to_port(object);

		ip_mq_lock(port);
		if (ip_active(port)) {
			assert(port->ip_srights > 0);
		}
		port->ip_srights++;
		ip_reference(port);
		ip_mq_unlock(port);
		break;
	}

	case MACH_MSG_TYPE_MAKE_SEND: {
		ipc_port_t port = ip_object_to_port(object);

		ip_mq_lock(port);
		if (ip_active(port)) {
			assert(ip_in_a_space(port));
			assert((ip_in_space(port, ipc_space_kernel)) ||
			    (port->ip_receiver->is_node_id != HOST_LOCAL_NODE));
			port->ip_mscount++;
		}

		port->ip_srights++;
		ip_reference(port);
		ip_mq_unlock(port);
		break;
	}

	case MACH_MSG_TYPE_MOVE_SEND: {
		/* move naked send right into the message */
		assert(ip_object_to_port(object)->ip_srights);
		break;
	}

	case MACH_MSG_TYPE_MAKE_SEND_ONCE: {
		ipc_port_t port = ip_object_to_port(object);

		ip_mq_lock(port);
		if (ip_active(port)) {
			assert(ip_in_a_space(port));
		}
		ipc_port_make_sonce_locked(port);
		ip_mq_unlock(port);
		break;
	}

	case MACH_MSG_TYPE_MOVE_SEND_ONCE: {
		/* move naked send-once right into the message */
		assert(ip_object_to_port(object)->ip_sorights);
		break;
	}

	default:
		panic("ipc_object_copyin_from_kernel: strange rights");
	}
}

/*
 *	Routine:	ipc_object_destroy
 *	Purpose:
 *		Destroys a naked capability.
 *		Consumes a ref for the object.
 *
 *		A receive right should be in limbo or in transit.
 *	Conditions:
 *		Nothing locked.
 */

void
ipc_object_destroy(
	ipc_object_t            object,
	mach_msg_type_name_t    msgt_name)
{
	assert(IO_VALID(object));
	assert(io_otype(object) == IOT_PORT);

	switch (msgt_name) {
	case MACH_MSG_TYPE_PORT_SEND:
		ipc_port_release_send(ip_object_to_port(object));
		break;

	case MACH_MSG_TYPE_PORT_SEND_ONCE:
		io_lock(object);
		ipc_notify_send_once_and_unlock(ip_object_to_port(object));
		break;

	case MACH_MSG_TYPE_PORT_RECEIVE:
		ipc_port_release_receive(ip_object_to_port(object));
		break;

	default:
		panic("ipc_object_destroy: strange rights");
	}
}

/*
 *	Routine:	ipc_object_destroy_dest
 *	Purpose:
 *		Destroys a naked capability for the destination of
 *		of a message. Consumes a ref for the object.
 *
 *	Conditions:
 *		Nothing locked.
 */

void
ipc_object_destroy_dest(
	ipc_object_t            object,
	mach_msg_type_name_t    msgt_name)
{
	ipc_port_t port = ip_object_to_port(object);

	assert(IO_VALID(object));
	assert(io_otype(object) == IOT_PORT);

	switch (msgt_name) {
	case MACH_MSG_TYPE_PORT_SEND:
		ipc_port_release_send(port);
		break;

	case MACH_MSG_TYPE_PORT_SEND_ONCE:
		ip_mq_lock(port);
		ipc_notify_send_once_and_unlock(port);
		break;

	default:
		panic("ipc_object_destroy_dest: strange rights");
	}
}

/*
 *	Routine:	ipc_object_insert_send_right
 *	Purpose:
 *		Insert a send right into an object already in the space.
 *		The specified name must already point to a valid object.
 *
 *		Note: This really is a combined copyin()/copyout(),
 *		that avoids most of the overhead of being implemented that way.
 *
 *		This is the fastpath for mach_port_insert_right.
 *
 *	Conditions:
 *		Nothing locked.
 *
 *		msgt_name must be MACH_MSG_TYPE_MAKE_SEND_ONCE or
 *		MACH_MSG_TYPE_MOVE_SEND_ONCE.
 *
 *	Returns:
 *		KERN_SUCCESS		Copied out object, consumed ref.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_INVALID_NAME	Name doesn't exist in space.
 *		KERN_INVALID_CAPABILITY	The object is dead.
 *		KERN_RIGHT_EXISTS	Space has rights under another name.
 */
kern_return_t
ipc_object_insert_send_right(
	ipc_space_t             space,
	mach_port_name_t        name,
	mach_msg_type_name_t    msgt_name)
{
	ipc_entry_bits_t bits;
	ipc_object_t object;
	ipc_entry_t entry;
	kern_return_t kr;

	assert(msgt_name == MACH_MSG_TYPE_MAKE_SEND ||
	    msgt_name == MACH_MSG_TYPE_COPY_SEND);

	kr = ipc_right_lookup_write(space, name, &entry);
	if (kr != KERN_SUCCESS) {
		return kr;
	}
	/* space is write-locked and active */

	if (!IO_VALID(entry->ie_object)) {
		is_write_unlock(space);
		return KERN_INVALID_CAPABILITY;
	}

	bits = entry->ie_bits;
	object = entry->ie_object;

	io_lock(object);
	if (!io_active(object)) {
		kr = KERN_INVALID_CAPABILITY;
	} else if (msgt_name == MACH_MSG_TYPE_MAKE_SEND) {
		if (bits & MACH_PORT_TYPE_RECEIVE) {
			ipc_port_t port = ip_object_to_port(object);
			port->ip_mscount++;
			if ((bits & MACH_PORT_TYPE_SEND) == 0) {
				port->ip_srights++;
				bits |= MACH_PORT_TYPE_SEND;
			}
			/* leave urefs pegged to maximum if it overflowed */
			if (IE_BITS_UREFS(bits) < MACH_PORT_UREFS_MAX) {
				bits += 1; /* increment urefs */
			}
			entry->ie_bits = bits;
			ipc_entry_modified(space, name, entry);
			kr = KERN_SUCCESS;
		} else {
			kr = KERN_INVALID_RIGHT;
		}
	} else { // MACH_MSG_TYPE_COPY_SEND
		if (bits & MACH_PORT_TYPE_SEND) {
			/* leave urefs pegged to maximum if it overflowed */
			if (IE_BITS_UREFS(bits) < MACH_PORT_UREFS_MAX) {
				entry->ie_bits = bits + 1; /* increment urefs */
			}
			ipc_entry_modified(space, name, entry);
			kr = KERN_SUCCESS;
		} else {
			kr = KERN_INVALID_RIGHT;
		}
	}

	io_unlock(object);
	is_write_unlock(space);

	return kr;
}

/*
 *	Routine:	ipc_object_copyout
 *	Purpose:
 *		Copyout a capability, placing it into a space.
 *		Always consumes a ref for the object.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		Copied out object, consumed ref.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_INVALID_CAPABILITY	The object is dead.
 *		KERN_NO_SPACE		No room in space for another right.
 *		KERN_UREFS_OVERFLOW	Urefs limit exceeded
 *			and overflow wasn't specified.
 */

kern_return_t
ipc_object_copyout(
	ipc_space_t             space,
	ipc_object_t            object,
	mach_msg_type_name_t    msgt_name,
	ipc_object_copyout_flags_t flags,
	mach_port_context_t     *context,
	mach_msg_guard_flags_t  *guard_flags,
	mach_port_name_t        *namep)
{
	struct knote *kn = current_thread()->ith_knote;
	mach_port_name_t name;
	ipc_port_t port = ip_object_to_port(object);
	ipc_entry_t entry;
	kern_return_t kr;

	assert(IO_VALID(object));
	assert(io_otype(object) == IOT_PORT);

	if (ITH_KNOTE_VALID(kn, msgt_name)) {
		filt_machport_turnstile_prepare_lazily(kn, msgt_name, port);
	}

	is_write_lock(space);

	for (;;) {
		ipc_port_t port_subst = IP_NULL;

		if (!is_active(space)) {
			is_write_unlock(space);
			kr = KERN_INVALID_TASK;
			goto out;
		}

		kr = ipc_entries_hold(space, 1);
		if (kr != KERN_SUCCESS) {
			/* unlocks/locks space, so must start again */

			kr = ipc_entry_grow_table(space, ITS_SIZE_NONE);
			if (kr != KERN_SUCCESS) {
				/* space is unlocked */
				goto out;
			}
			continue;
		}

		io_lock(object);
		if (!io_active(object)) {
			io_unlock(object);
			is_write_unlock(space);
			kr = KERN_INVALID_CAPABILITY;
			goto out;
		}

		/* Don't actually copyout rights we aren't allowed to */
		if (!ip_label_check(space, port, msgt_name, &flags, &port_subst)) {
			io_unlock(object);
			is_write_unlock(space);
			assert(port_subst == IP_NULL);
			kr = KERN_INVALID_CAPABILITY;
			goto out;
		}

		/* is the kolabel requesting a substitution */
		if (port_subst != IP_NULL) {
			/*
			 * port is unlocked, its right consumed
			 * space is unlocked
			 */
			assert(msgt_name == MACH_MSG_TYPE_PORT_SEND);
			port = port_subst;
			if (!IP_VALID(port)) {
				object = IO_DEAD;
				kr = KERN_INVALID_CAPABILITY;
				goto out;
			}

			object = ip_to_object(port);
			is_write_lock(space);
			continue;
		}

		break;
	}

	/* space is write-locked and active, object is locked and active */

	if ((msgt_name != MACH_MSG_TYPE_PORT_SEND_ONCE) &&
	    ipc_right_reverse(space, object, &name, &entry)) {
		assert(entry->ie_bits & MACH_PORT_TYPE_SEND_RECEIVE);
	} else {
		ipc_entry_claim(space, object, &name, &entry);
	}

	kr = ipc_right_copyout(space, name, entry,
	    msgt_name, flags, context, guard_flags, object);

	/* object is unlocked */
	is_write_unlock(space);

out:
	if (kr == KERN_SUCCESS) {
		*namep = name;
	} else if (IO_VALID(object)) {
		ipc_object_destroy(object, msgt_name);
	}

	return kr;
}

/*
 *	Routine:	ipc_object_copyout_name
 *	Purpose:
 *		Copyout a capability, placing it into a space.
 *		The specified name is used for the capability.
 *		If successful, consumes a ref for the object.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		Copied out object, consumed ref.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_INVALID_CAPABILITY	The object is dead.
 *		KERN_UREFS_OVERFLOW	Urefs limit exceeded
 *			and overflow wasn't specified.
 *		KERN_RIGHT_EXISTS	Space has rights under another name.
 *		KERN_NAME_EXISTS	Name is already used.
 *      KERN_INVALID_VALUE  Supplied port name is invalid.
 */

kern_return_t
ipc_object_copyout_name(
	ipc_space_t             space,
	ipc_object_t            object,
	mach_msg_type_name_t    msgt_name,
	mach_port_name_t        name)
{
	ipc_port_t port = ip_object_to_port(object);
	mach_port_name_t oname;
	ipc_entry_t oentry;
	ipc_entry_t entry;
	kern_return_t kr;

#if IMPORTANCE_INHERITANCE
	int assertcnt = 0;
	ipc_importance_task_t task_imp = IIT_NULL;
#endif /* IMPORTANCE_INHERITANCE */

	assert(IO_VALID(object));
	assert(io_otype(object) == IOT_PORT);

	kr = ipc_entry_alloc_name(space, name, &entry);
	if (kr != KERN_SUCCESS) {
		return kr;
	}
	/* space is write-locked and active */

	io_lock(object);

	/*
	 * Don't actually copyout rights we aren't allowed to
	 *
	 * In particular, kolabel-ed objects do not allow callers
	 * to pick the name they end up with.
	 */
	if (!io_active(object) || ip_is_kolabeled(port)) {
		io_unlock(object);
		if (!ipc_right_inuse(entry)) {
			ipc_entry_dealloc(space, IO_NULL, name, entry);
		}
		is_write_unlock(space);
		return KERN_INVALID_CAPABILITY;
	}

	/* space is write-locked and active, object is locked and active */

	if ((msgt_name != MACH_MSG_TYPE_PORT_SEND_ONCE) &&
	    ipc_right_reverse(space, object, &oname, &oentry)) {
		if (name != oname) {
			io_unlock(object);
			if (!ipc_right_inuse(entry)) {
				ipc_entry_dealloc(space, IO_NULL, name, entry);
			}
			is_write_unlock(space);
			return KERN_RIGHT_EXISTS;
		}

		assert(entry == oentry);
		assert(entry->ie_bits & MACH_PORT_TYPE_SEND_RECEIVE);
	} else if (ipc_right_inuse(entry)) {
		io_unlock(object);
		is_write_unlock(space);
		return KERN_NAME_EXISTS;
	} else {
		assert(entry->ie_object == IO_NULL);

		entry->ie_object = object;
	}

#if IMPORTANCE_INHERITANCE
	/*
	 * We are slamming a receive right into the space, without
	 * first having been enqueued on a port destined there.  So,
	 * we have to arrange to boost the task appropriately if this
	 * port has assertions (and the task wants them).
	 */
	if (msgt_name == MACH_MSG_TYPE_PORT_RECEIVE) {
		if (space->is_task != TASK_NULL) {
			task_imp = space->is_task->task_imp_base;
			if (ipc_importance_task_is_any_receiver_type(task_imp)) {
				assertcnt = port->ip_impcount;
				ipc_importance_task_reference(task_imp);
			} else {
				task_imp = IIT_NULL;
			}
		}

		/* take port out of limbo */
		port->ip_tempowner = 0;
	}

#endif /* IMPORTANCE_INHERITANCE */

	kr = ipc_right_copyout(space, name, entry,
	    msgt_name, IPC_OBJECT_COPYOUT_FLAGS_NONE, NULL, NULL, object);

	/* object is unlocked */
	is_write_unlock(space);

#if IMPORTANCE_INHERITANCE
	/*
	 * Add the assertions to the task that we captured before
	 */
	if (task_imp != IIT_NULL) {
		ipc_importance_task_hold_internal_assertion(task_imp, assertcnt);
		ipc_importance_task_release(task_imp);
	}
#endif /* IMPORTANCE_INHERITANCE */

	return kr;
}

/*
 *	Routine:	ipc_object_copyout_dest
 *	Purpose:
 *		Translates/consumes the destination right of a message.
 *		This is unlike normal copyout because the right is consumed
 *		in a funny way instead of being given to the receiving space.
 *		The receiver gets his name for the port, if he has receive
 *		rights, otherwise MACH_PORT_NULL.
 *	Conditions:
 *		The object is locked and active.  Nothing else locked.
 *		The object is unlocked and loses a reference.
 */

void
ipc_object_copyout_dest(
	ipc_space_t             space,
	ipc_object_t            object,
	mach_msg_type_name_t    msgt_name,
	mach_port_name_t        *namep)
{
	mach_port_name_t name;

	assert(IO_VALID(object));
	assert(io_active(object));

	/*
	 *	If the space is the receiver/owner of the object,
	 *	then we quietly consume the right and return
	 *	the space's name for the object.  Otherwise
	 *	we destroy the right and return MACH_PORT_NULL.
	 */

	switch (msgt_name) {
	case MACH_MSG_TYPE_PORT_SEND: {
		ipc_port_t port = ip_object_to_port(object);
		ipc_notify_nsenders_t nsrequest = { };

		if (ip_in_space(port, space)) {
			name = ip_get_receiver_name(port);
		} else {
			name = MACH_PORT_NULL;
		}

		assert(port->ip_srights > 0);
		if (--port->ip_srights == 0) {
			nsrequest = ipc_notify_no_senders_prepare(port);
		}
		ipc_port_clear_sync_rcv_thread_boost_locked(port);
		/* port unlocked */

		ipc_notify_no_senders_emit(nsrequest);

		ip_release(port);
		break;
	}

	case MACH_MSG_TYPE_PORT_SEND_ONCE: {
		ipc_port_t port = ip_object_to_port(object);

		assert(port->ip_sorights > 0);

		if (ip_in_space(port, space)) {
			/* quietly consume the send-once right */
			port->ip_sorights--;
			name = ip_get_receiver_name(port);
			ipc_port_clear_sync_rcv_thread_boost_locked(port);
			/* port unlocked */
			ip_release(port);
		} else {
			/*
			 *	A very bizarre case.  The message
			 *	was received, but before this copyout
			 *	happened the space lost receive rights.
			 *	We can't quietly consume the soright
			 *	out from underneath some other task,
			 *	so generate a send-once notification.
			 */

			ipc_notify_send_once_and_unlock(port);
			name = MACH_PORT_NULL;
		}

		break;
	}

	default:
		panic("ipc_object_copyout_dest: strange rights");
		name = MACH_PORT_DEAD;
	}

	*namep = name;
}

static_assert(offsetof(struct ipc_object_waitq, iowq_waitq) ==
    offsetof(struct ipc_port, ip_waitq));
static_assert(offsetof(struct ipc_object_waitq, iowq_waitq) ==
    offsetof(struct ipc_pset, ips_wqset.wqset_q));

/*
 *	Routine:        ipc_object_lock
 *	Purpose:
 *		Validate, then acquire a lock on an ipc object
 */
void
ipc_object_lock(ipc_object_t io)
{
	ipc_object_validate(io);
	waitq_lock(io_waitq(io));
}

#if MACH_LOCKFREE_SPACE
__abortlike
static void
ipc_object_validate_preflight_panic(ipc_object_t io)
{
	panic("ipc object %p is neither a port or a port-set", io);
}

/*
 *	Routine:	ipc_object_lock_allow_invalid
 *	Purpose:
 *		Speculatively try to lock an object in an undefined state.
 *
 *		This relies on the fact that IPC object memory is allocated
 *		from sequestered zones, so at a given address, one can find:
 *		1. a valid object,
 *		2. a freed or invalid (uninitialized) object,
 *		3. unmapped memory.
 *
 *		(2) is possible because the zone is made with ZC_ZFREE_CLEARMEM which
 *		    ensures freed elements are always zeroed.
 *
 *		(3) is a direct courtesy of waitq_lock_allow_invalid().
 *
 *		In order to disambiguate (1) from (2), we use the "waitq valid"
 *		bit which is part of the lock. When that bit is absent,
 *		waitq_lock() will function as expected, but
 *		waitq_lock_allow_invalid() will not.
 *
 *		Objects are then initialized and destroyed carefully so that
 *		this "valid bit" is only set when the object invariants are
 *		respected.
 *
 *	Returns:
 *		true:  the lock was acquired
 *		false: the object was freed or not initialized.
 */
bool
ipc_object_lock_allow_invalid(ipc_object_t io)
{
	struct waitq *wq = io_waitq(io);

	switch (zone_id_for_native_element(wq, sizeof(*wq))) {
	case ZONE_ID_IPC_PORT:
	case ZONE_ID_IPC_PORT_SET:
		break;
	default:
		ipc_object_validate_preflight_panic(io);
	}

	if (__probable(waitq_lock_allow_invalid(wq))) {
		ipc_object_validate(io);
		return true;
	}
	return false;
}
#endif /* MACH_LOCKFREE_SPACE */

/*
 *	Routine:	ipc_object_lock_try
 *	Purpose:
 *		Validate, then try to acquire a lock on an object,
 *		fail if there is an existing busy lock
 */
bool
ipc_object_lock_try(ipc_object_t io)
{
	ipc_object_validate(io);
	return waitq_lock_try(io_waitq(io));
}

/*
 *	Routine:        ipc_object_unlock
 *	Purpose:
 *	    Unlocks the given object.
 */
void
ipc_object_unlock(ipc_object_t io)
{
	waitq_unlock(io_waitq(io));
}
