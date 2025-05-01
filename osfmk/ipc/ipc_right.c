/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
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
 * @OSF_FREE_COPYRIGHT@
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
 *	File:	ipc/ipc_right.c
 *	Author:	Rich Draves
 *	Date:	1989
 *
 *	Functions to manipulate IPC capabilities.
 */

#include <mach/boolean.h>
#include <mach/kern_return.h>
#include <mach/port.h>
#include <mach/message.h>
#include <kern/assert.h>
#include <kern/ipc_kobject.h>
#include <kern/misc_protos.h>
#include <kern/policy_internal.h>
#include <libkern/coreanalytics/coreanalytics.h>
#include <ipc/port.h>
#include <ipc/ipc_entry.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_object.h>
#include <ipc/ipc_hash.h>
#include <ipc/ipc_policy.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_pset.h>
#include <ipc/ipc_right.h>
#include <ipc/ipc_notify.h>
#include <ipc/ipc_importance.h>
#include <ipc/ipc_service_port.h>
#include <security/mac_mach_internal.h>

extern struct proc *current_proc(void);
extern int csproc_hardened_runtime(struct proc* p);

extern void * XNU_PTRAUTH_SIGNED_PTR("initproc") initproc;

TUNABLE(bool, service_port_defense_enabled, "-service_port_defense_enabled", false);
static TUNABLE(bool, reply_port_semantics, "reply_port_semantics", true);

/*
 *	Routine:	ipc_right_lookup_read
 *	Purpose:
 *		Finds an entry in a space, given the name.
 *	Conditions:
 *		Nothing locked.
 *		If an object is found, it is locked and active.
 *	Returns:
 *		KERN_SUCCESS		Found an entry.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_INVALID_NAME	Name doesn't exist in space.
 */
kern_return_t
ipc_right_lookup_read(
	ipc_space_t             space,
	mach_port_name_t        name,
	ipc_entry_bits_t       *bitsp,
	ipc_object_t           *objectp)
{
	mach_port_index_t index;
	ipc_entry_table_t table;
	ipc_entry_t entry;
	ipc_object_t object;
	kern_return_t kr;

	index = MACH_PORT_INDEX(name);
	if (__improbable(index == 0)) {
		*bitsp = 0;
		*objectp = IPC_OBJECT_NULL;
		return KERN_INVALID_NAME;
	}

	smr_ipc_enter();

	/*
	 * Acquire a (possibly stale) pointer to the table,
	 * and guard it so that it can't be deallocated while we use it.
	 *
	 * smr_ipc_enter() has the property that it strongly serializes
	 * after any store-release. This is important because it means that if
	 * one considers this (broken) userspace usage:
	 *
	 * Thread 1:
	 *   - makes a semaphore, gets name 0x1003
	 *   - stores that name to a global `sema` in userspace
	 *
	 * Thread 2:
	 *   - spins to observe `sema` becoming non 0
	 *   - calls semaphore_wait() on 0x1003
	 *
	 * Then, because in order to return 0x1003 this thread issued
	 * a store-release (when calling is_write_unlock()),
	 * then this smr_entered_load() can't possibly observe a table
	 * pointer that is older than the one that was current when the
	 * semaphore was made.
	 *
	 * This fundamental property allows us to never loop.
	 */
	table = smr_entered_load(&space->is_table);
	if (__improbable(table == NULL)) {
		kr = KERN_INVALID_TASK;
		goto out_put;
	}
	entry = ipc_entry_table_get(table, index);
	if (__improbable(entry == NULL)) {
		kr = KERN_INVALID_NAME;
		goto out_put;
	}

	/*
	 * Note: this should be an atomic load, but PAC and atomics
	 *       don't work interact well together.
	 */
	object = entry->ie_volatile_object;

	/*
	 * Attempt to lock an object that lives in this entry.
	 * It might fail or be a completely different object by now.
	 *
	 * Make sure that acquiring the lock is fully ordered after any
	 * lock-release (using os_atomic_barrier_before_lock_acquire()).
	 * This allows us to always reliably observe space termination below.
	 */
	os_atomic_barrier_before_lock_acquire();
	if (__improbable(object == IPC_OBJECT_NULL ||
	    !io_lock_allow_invalid(object))) {
		kr = KERN_INVALID_NAME;
		goto out_put;
	}

	/*
	 * Now that we hold the object lock, we are preventing any entry
	 * in this space for this object to be mutated.
	 *
	 * If the space didn't grow after we acquired our hazardous reference,
	 * and before a mutation of the entry, then holding the object lock
	 * guarantees we will observe the truth of ie_bits, ie_object and
	 * ie_request (those are always mutated with the object lock held).
	 *
	 * However this ordering is problematic:
	 * - [A]cquisition of the table pointer
	 * - [G]rowth of the space (making the table pointer in [A] stale)
	 * - [M]utation of the entry
	 * - [L]ocking of the object read through [A].
	 *
	 * The space lock is held for both [G] and [M], and the object lock
	 * is held for [M], which means that once we lock the object we can
	 * observe if [G] happenend by reloading the table pointer.
	 *
	 * We might still fail to observe any growth operation that happened
	 * after the last mutation of this object's entry, because holding
	 * an object lock doesn't guarantee anything about the liveness
	 * of the space table pointer. This is not a problem at all: by
	 * definition, those didn't affect the state of the entry.
	 *
	 * TODO: a data-structure where the entries are grown by "slabs",
	 *       would allow for the address of an ipc_entry_t to never
	 *       change once it exists in a space and would avoid a reload
	 *       (as well as making space growth faster).
	 *       We however still need to check for termination.
	 */
	table = smr_entered_load(&space->is_table);
	if (__improbable(table == NULL)) {
		kr = KERN_INVALID_TASK;
		goto out_put_unlock;
	}

	/*
	 * Tables never shrink so we don't need to validate the length twice.
	 */
	entry = ipc_entry_table_get_nocheck(table, index);

	/*
	 * Now that we hold the lock and have a "fresh enough" table pointer,
	 * validate if this entry is what we think it is.
	 *
	 * To the risk of being repetitive, we still need to protect
	 * those accesses under SMR, because subsequent
	 * table growths might retire the memory. However we know
	 * those growths will have left our entry unchanged.
	 */
	if (__improbable(entry->ie_object != object)) {
		kr = KERN_INVALID_NAME;
		goto out_put_unlock;
	}

	ipc_entry_bits_t bits = entry->ie_bits;
	if (__improbable(IE_BITS_GEN(bits) != MACH_PORT_GEN(name) ||
	    IE_BITS_TYPE(bits) == MACH_PORT_TYPE_NONE)) {
		kr = KERN_INVALID_NAME;
		goto out_put_unlock;
	}

	/* Done with hazardous accesses to the table */
	smr_ipc_leave();

	*bitsp = bits;
	*objectp = object;
	return KERN_SUCCESS;

out_put_unlock:
	io_unlock(object);
out_put:
	smr_ipc_leave();
	return kr;
}

/*
 *	Routine:	ipc_right_lookup_write
 *	Purpose:
 *		Finds an entry in a space, given the name.
 *	Conditions:
 *		Nothing locked.  If successful, the space is write-locked.
 *	Returns:
 *		KERN_SUCCESS		Found an entry.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_INVALID_NAME	Name doesn't exist in space.
 */

kern_return_t
ipc_right_lookup_write(
	ipc_space_t             space,
	mach_port_name_t        name,
	ipc_entry_t             *entryp)
{
	ipc_entry_t entry;

	assert(space != IS_NULL);

	is_write_lock(space);

	if (!is_active(space)) {
		is_write_unlock(space);
		return KERN_INVALID_TASK;
	}

	if ((entry = ipc_entry_lookup(space, name)) == IE_NULL) {
		is_write_unlock(space);
		return KERN_INVALID_NAME;
	}

	*entryp = entry;
	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_right_lookup_two_write
 *	Purpose:
 *		Like ipc_right_lookup except that it returns two
 *		entries for two different names that were looked
 *		up under the same space lock.
 *	Conditions:
 *		Nothing locked.  If successful, the space is write-locked.
 *	Returns:
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_INVALID_NAME	Name doesn't exist in space.
 */

kern_return_t
ipc_right_lookup_two_write(
	ipc_space_t             space,
	mach_port_name_t        name1,
	ipc_entry_t             *entryp1,
	mach_port_name_t        name2,
	ipc_entry_t             *entryp2)
{
	ipc_entry_t entry1;
	ipc_entry_t entry2;

	assert(space != IS_NULL);

	is_write_lock(space);

	if (!is_active(space)) {
		is_write_unlock(space);
		return KERN_INVALID_TASK;
	}

	if ((entry1 = ipc_entry_lookup(space, name1)) == IE_NULL) {
		is_write_unlock(space);
		mach_port_guard_exception(name1, 0, kGUARD_EXC_INVALID_NAME);
		return KERN_INVALID_NAME;
	}
	if ((entry2 = ipc_entry_lookup(space, name2)) == IE_NULL) {
		is_write_unlock(space);
		mach_port_guard_exception(name2, 0, kGUARD_EXC_INVALID_NAME);
		return KERN_INVALID_NAME;
	}
	*entryp1 = entry1;
	*entryp2 = entry2;
	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_right_reverse
 *	Purpose:
 *		Translate (space, port) -> (name, entry).
 *		Only finds send/receive rights.
 *		Returns TRUE if an entry is found; if so,
 *		the port active.
 *	Conditions:
 *		The space must be locked (read or write) and active.
 *		The port is locked and active
 */

bool
ipc_right_reverse(
	ipc_space_t             space,
	ipc_port_t              port,
	mach_port_name_t       *namep,
	ipc_entry_t            *entryp)
{
	mach_port_name_t name;
	ipc_entry_t entry;

	assert(is_active(space));

	require_ip_active(port);

	ip_mq_lock_held(port);

	if (ip_in_space(port, space)) {
		name = ip_get_receiver_name(port);
		assert(name != MACH_PORT_NULL);

		entry = ipc_entry_lookup(space, name);

		assert(entry != IE_NULL);
		assert(entry->ie_bits & MACH_PORT_TYPE_RECEIVE);
		assert(port == entry->ie_port);

		*namep = name;
		*entryp = entry;
		return true;
	}

	if (ipc_hash_lookup(space, ip_to_object(port), namep, entryp)) {
		entry = *entryp;
		assert(entry != IE_NULL);
		assert(IE_BITS_TYPE(entry->ie_bits) == MACH_PORT_TYPE_SEND);
		assert(port == entry->ie_port);

		return true;
	}

	return false;
}

/*
 *	Routine:	ipc_right_request_cancel
 *	Purpose:
 *		Cancel a notification request and return the send-once right.
 *		Afterwards, entry->ie_request == 0.
 *	Conditions:
 *		The space must be write-locked; the port must be locked.
 *		The port must be active.
 */

static inline ipc_port_t
ipc_right_request_cancel(
	ipc_port_t              port,
	mach_port_name_t        name,
	ipc_entry_t             entry)
{
	ipc_port_request_index_t request = entry->ie_request;

	if (request != IE_REQ_NONE) {
		entry->ie_request = IE_REQ_NONE;
		return ipc_port_request_cancel(port, name, request);
	}
	return IP_NULL;
}

/*
 *	Routine:	ipc_right_dnrequest
 *	Purpose:
 *		Make a dead-name request, returning the previously
 *		registered send-once right.  If notify is IP_NULL,
 *		just cancels the previously registered request.
 *
 *	Conditions:
 *		Nothing locked.  May allocate memory.
 *		Only consumes/returns refs if successful.
 *	Returns:
 *		KERN_SUCCESS		Made/canceled dead-name request.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_INVALID_NAME	Name doesn't exist in space.
 *		KERN_INVALID_RIGHT	Name doesn't denote port/dead rights.
 *		KERN_INVALID_ARGUMENT	Name denotes dead name, but
 *			immediate is FALSE or notify is IP_NULL.
 *		KERN_RESOURCE_SHORTAGE	Couldn't allocate memory.
 */

kern_return_t
ipc_right_request_alloc(
	ipc_space_t             space,
	mach_port_name_t        name,
	ipc_port_request_opts_t options,
	ipc_port_t              notify,
	ipc_port_t              *previousp)
{
	ipc_port_t previous = IP_NULL;
	ipc_entry_t entry;
	kern_return_t kr;
#if IMPORTANCE_INHERITANCE
	bool will_arm = false;
#endif /* IMPORTANCE_INHERITANCE */

	for (;;) {
		ipc_port_t port = IP_NULL;

		kr = ipc_right_lookup_write(space, name, &entry);
		if (kr != KERN_SUCCESS) {
			return kr;
		}

		/* space is write-locked and active */

		/* if nothing to do or undo, we're done */
		if (notify == IP_NULL && entry->ie_request == IE_REQ_NONE) {
			is_write_unlock(space);
			*previousp = IP_NULL;
			return KERN_SUCCESS;
		}

		/* see if the entry is of proper type for requests */
		if (entry->ie_bits & MACH_PORT_TYPE_PORT_RIGHTS) {
			ipc_port_request_index_t new_request;

			port = entry->ie_port;
			assert(port != IP_NULL);

			if (!ipc_right_check(space, port, name, entry, IPC_OBJECT_COPYIN_FLAGS_NONE)) {
				/* port is locked and active */

				/*
				 * No matter what, we need to cancel any
				 * previous request.
				 */
				previous = ipc_right_request_cancel(port, name, entry);

				/* if no new request, just cancel previous */
				if (notify == IP_NULL) {
					ip_mq_unlock(port);
					ipc_entry_modified(space, name, entry);
					is_write_unlock(space);
					break;
				}

				/*
				 * send-once rights, kernel objects, and non-full other queues
				 * fire immediately (if immediate specified).
				 */
				if (options == (IPR_SOR_SPARM_MASK | IPR_SOR_SPREQ_MASK) &&
				    ((entry->ie_bits & MACH_PORT_TYPE_SEND_ONCE) ||
				    ip_in_space(port, ipc_space_kernel) ||
				    !ip_full(port))) {
					ip_mq_unlock(port);
					ipc_entry_modified(space, name, entry);
					is_write_unlock(space);

					ipc_notify_send_possible(notify, name);
					break;
				}

				/*
				 * If there was a previous request, freeing it
				 * above guarantees that the subsequent
				 * allocation will find a slot and succeed,
				 * thus assuring an atomic swap.
				 */
#if IMPORTANCE_INHERITANCE
				will_arm = port->ip_sprequests == 0 &&
				    options == (IPR_SOR_SPARM_MASK | IPR_SOR_SPREQ_MASK);
#endif /* IMPORTANCE_INHERITANCE */
				kr = ipc_port_request_alloc(port, name, notify,
				    options, &new_request);

				if (kr != KERN_SUCCESS) {
					assert(previous == IP_NULL);
					is_write_unlock(space);

					kr = ipc_port_request_grow(port);
					/* port is unlocked */

					if (kr != KERN_SUCCESS) {
						return kr;
					}

					continue;
				}

				assert(new_request != IE_REQ_NONE);
				entry->ie_request = new_request;
				ipc_entry_modified(space, name, entry);
				is_write_unlock(space);

#if IMPORTANCE_INHERITANCE
				if (will_arm &&
				    port->ip_impdonation != 0 &&
				    port->ip_spimportant == 0 &&
				    task_is_importance_donor(current_task())) {
					if (ipc_port_importance_delta(port, IPID_OPTION_SENDPOSSIBLE, 1) == FALSE) {
						ip_mq_unlock(port);
					}
				} else
#endif /* IMPORTANCE_INHERITANCE */
				ip_mq_unlock(port);

				break;
			}
			/* entry may have changed to dead-name by ipc_right_check() */
		}

		/* treat send_possible requests as immediate w.r.t. dead-name */
		if (options && notify != IP_NULL &&
		    (entry->ie_bits & MACH_PORT_TYPE_DEAD_NAME)) {
			mach_port_urefs_t urefs = IE_BITS_UREFS(entry->ie_bits);

			assert(urefs > 0);

			/* leave urefs pegged to maximum if it overflowed */
			if (urefs < MACH_PORT_UREFS_MAX) {
				(entry->ie_bits)++; /* increment urefs */
			}
			ipc_entry_modified(space, name, entry);

			is_write_unlock(space);

			if (port != IP_NULL) {
				ip_release(port);
			}

			ipc_notify_dead_name(notify, name);
			previous = IP_NULL;
			break;
		}

		kr = (entry->ie_bits & MACH_PORT_TYPE_PORT_OR_DEAD) ?
		    KERN_INVALID_ARGUMENT : KERN_INVALID_RIGHT;

		is_write_unlock(space);

		if (port != IP_NULL) {
			ip_release(port);
		}

		return kr;
	}

	*previousp = previous;
	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_right_inuse
 *	Purpose:
 *		Check if an entry is being used.
 *		Returns TRUE if it is.
 *	Conditions:
 *		The space is write-locked and active.
 */

bool
ipc_right_inuse(
	ipc_entry_t entry)
{
	return IE_BITS_TYPE(entry->ie_bits) != MACH_PORT_TYPE_NONE;
}

/*
 *	Routine:	ipc_right_check
 *	Purpose:
 *		Check if the port has died.  If it has,
 *              and IPC_OBJECT_COPYIN_FLAGS_ALLOW_DEAD_SEND_ONCE is not
 *              passed and it is not a send once right then
 *		clean up the entry and return TRUE.
 *	Conditions:
 *		The space is write-locked; the port is not locked.
 *		If returns FALSE, the port is also locked.
 *		Otherwise, entry is converted to a dead name.
 *
 *		Caller is responsible for a reference to port if it
 *		had died (returns TRUE).
 */

boolean_t
ipc_right_check(
	ipc_space_t              space,
	ipc_port_t               port,
	mach_port_name_t         name,
	ipc_entry_t              entry,
	ipc_object_copyin_flags_t flags)
{
	ipc_entry_bits_t bits;

	assert(is_active(space));
	assert(port == entry->ie_port);

	ip_mq_lock(port);
	if (ip_active(port) ||
	    ((flags & IPC_OBJECT_COPYIN_FLAGS_ALLOW_DEAD_SEND_ONCE) &&
	    entry->ie_request == IE_REQ_NONE &&
	    (entry->ie_bits & MACH_PORT_TYPE_SEND_ONCE))) {
		return FALSE;
	}

	/* this was either a pure send right or a send-once right */

	bits = entry->ie_bits;
	assert((bits & MACH_PORT_TYPE_RECEIVE) == 0);
	assert(IE_BITS_UREFS(bits) > 0);

	if (bits & MACH_PORT_TYPE_SEND) {
		assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_SEND);
		assert(IE_BITS_UREFS(bits) > 0);
		ip_srights_dec(port);
	} else {
		assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_SEND_ONCE);
		assert(IE_BITS_UREFS(bits) == 1);
		ip_sorights_dec(port);
	}

	/*
	 * delete SEND rights from ipc hash.
	 */

	if ((bits & MACH_PORT_TYPE_SEND) != 0) {
		ipc_hash_delete(space, ip_to_object(port), name, entry);
	}

	/* convert entry to dead name */
	bits = (bits & ~IE_BITS_TYPE_MASK) | MACH_PORT_TYPE_DEAD_NAME;

	/*
	 * If there was a notification request outstanding on this
	 * name, and the port went dead, that notification
	 * must already be on its way up from the port layer.
	 *
	 * Add the reference that the notification carries. It
	 * is done here, and not in the notification delivery,
	 * because the latter doesn't have a space reference and
	 * trying to actually move a send-right reference would
	 * get short-circuited into a MACH_PORT_DEAD by IPC. Since
	 * all calls that deal with the right eventually come
	 * through here, it has the same result.
	 *
	 * Once done, clear the request index so we only account
	 * for it once.
	 */
	if (entry->ie_request != IE_REQ_NONE) {
		if (ipc_port_request_type(port, name, entry->ie_request) != 0) {
			/* if urefs are pegged due to overflow, leave them pegged */
			if (IE_BITS_UREFS(bits) < MACH_PORT_UREFS_MAX) {
				bits++; /* increment urefs */
			}
		}
		entry->ie_request = IE_REQ_NONE;
	}
	entry->ie_bits = bits;
	entry->ie_object = IPC_OBJECT_NULL;

	ip_mq_unlock(port);

	ipc_entry_modified(space, name, entry);

	return TRUE;
}

/*
 *	Routine:	ipc_right_terminate
 *	Purpose:
 *		Cleans up an entry in a terminated space.
 *		The entry isn't deallocated or removed
 *		from reverse hash tables.
 *	Conditions:
 *		The space is dead and unlocked.
 */

void
ipc_right_terminate(
	ipc_space_t             space,
	mach_port_name_t        name,
	ipc_entry_t             entry)
{
	mach_port_type_t type;
	ipc_port_t port = IP_NULL;
	ipc_pset_t pset = IPS_NULL;

	assert(!is_active(space));

	type   = IE_BITS_TYPE(entry->ie_bits);

	/*
	 * Hollow the entry under the port lock,
	 * in order to avoid dangling pointers.
	 *
	 * ipc_right_lookup_read() doesn't need it for correctness,
	 * but ipc_space_terminate() as it now goes through 2 rounds
	 * of termination (receive rights first, the rest second).
	 */

	if (type & MACH_PORT_TYPE_PORT_SET) {
		pset = entry->ie_pset;
		ips_mq_lock(pset);
	} else if (type != MACH_PORT_TYPE_DEAD_NAME) {
		port = entry->ie_port;
		ip_mq_lock(port);
	}
	entry->ie_object = IPC_OBJECT_NULL;
	entry->ie_bits  &= (IE_BITS_GEN_MASK | IE_BITS_ROLL_MASK);

	switch (type) {
	case MACH_PORT_TYPE_DEAD_NAME:
		assert(entry->ie_request == IE_REQ_NONE);
		break;

	case MACH_PORT_TYPE_PORT_SET:
		assert(entry->ie_request == IE_REQ_NONE);
		assert(ips_active(pset));

		ipc_pset_destroy(space, pset); /* consumes ref, unlocks */
		break;

	case MACH_PORT_TYPE_SEND:
	case MACH_PORT_TYPE_RECEIVE:
	case MACH_PORT_TYPE_SEND_RECEIVE:
	case MACH_PORT_TYPE_SEND_ONCE: {
		ipc_port_t request = IP_NULL;
		ipc_notify_nsenders_t nsrequest = { };

		if (!ip_active(port)) {
			ip_mq_unlock(port);
			ip_release(port);
			break;
		}

		request = ipc_right_request_cancel(port, name, entry);

		if (type & MACH_PORT_TYPE_SEND) {
			ip_srights_dec(port);
			if (port->ip_srights == 0) {
				nsrequest = ipc_notify_no_senders_prepare(port);
			}
		}

		if (type & MACH_PORT_TYPE_RECEIVE) {
			assert(ip_get_receiver_name(port) == name);
			assert(ip_in_space(port, space));

			ipc_port_destroy(port); /* clears receiver, consumes our ref, unlocks */
		} else if (type & MACH_PORT_TYPE_SEND_ONCE) {
			assert(port->ip_sorights > 0);
			port->ip_reply_context = 0;

			ipc_notify_send_once_and_unlock(port); /* consumes our ref */
		} else {
			/* port could be dead, in-transit, or in a foreign space */
			assert(!ip_in_space(port, space));

			ip_mq_unlock(port);
			ip_release(port);
		}

		/*
		 * For both no-senders and port-deleted notifications,
		 * look at whether the destination is still active.
		 * If it isn't, just swallow the send-once right.
		 *
		 * This is a racy check, but this ok because we can only
		 * fail to notice that the port is now inactive, which
		 * only causes us to fail at an optimizaiton.
		 *
		 * The purpose here is to avoid sending messages
		 * to receive rights that used to be in this space,
		 * which we can't fail to observe.
		 */
		if (nsrequest.ns_notify != IP_NULL) {
			if (ip_active(nsrequest.ns_notify)) {
				ipc_notify_no_senders_emit(nsrequest);
			} else {
				ipc_notify_no_senders_consume(nsrequest);
			}
		}

		if (request != IP_NULL) {
			if (ip_active(request)) {
				ipc_notify_port_deleted(request, name);
			} else {
				ipc_port_release_sonce(request);
			}
		}
		break;
	}

	default:
		panic("ipc_right_terminate: strange type - 0x%x", type);
	}
}

/*
 *	Routine:	ipc_right_destroy
 *	Purpose:
 *		Destroys an entry in a space.
 *	Conditions:
 *		The space is write-locked (returns unlocked).
 *		The space must be active.
 *	Returns:
 *		KERN_SUCCESS		      The entry was destroyed.
 *      KERN_INVALID_CAPABILITY   The port is pinned.
 *      KERN_INVALID_RIGHT        Port guard violation.
 */

kern_return_t
ipc_right_destroy(
	ipc_space_t             space,
	mach_port_name_t        name,
	ipc_entry_t             entry,
	boolean_t               check_guard,
	uint64_t                guard)
{
	ipc_entry_bits_t bits;
	mach_port_type_t type;

	bits = entry->ie_bits;
	type = IE_BITS_TYPE(bits);

	assert(is_active(space));

	switch (type) {
	case MACH_PORT_TYPE_DEAD_NAME:
		assert(entry->ie_request == IE_REQ_NONE);
		assert(entry->ie_object == IPC_OBJECT_NULL);

		ipc_entry_dealloc(space, IPC_OBJECT_NULL, name, entry);
		is_write_unlock(space);
		break;

	case MACH_PORT_TYPE_PORT_SET: {
		ipc_pset_t pset = entry->ie_pset;

		assert(entry->ie_request == IE_REQ_NONE);
		assert(pset != IPS_NULL);

		ips_mq_lock(pset);
		assert(ips_active(pset));

		ipc_entry_dealloc(space, ips_to_object(pset), name, entry);

		is_write_unlock(space);

		ipc_pset_destroy(space, pset); /* consumes ref, unlocks */
		break;
	}

	case MACH_PORT_TYPE_SEND:
	case MACH_PORT_TYPE_RECEIVE:
	case MACH_PORT_TYPE_SEND_RECEIVE:
	case MACH_PORT_TYPE_SEND_ONCE: {
		ipc_port_t port = entry->ie_port;
		ipc_notify_nsenders_t nsrequest = { };
		ipc_port_t request;

		assert(port != IP_NULL);

		if (type == MACH_PORT_TYPE_SEND) {
			if (ip_is_pinned(port)) {
				assert(ip_active(port));
				is_write_unlock(space);
				mach_port_guard_exception_pinned(space, name, port, MPG_FLAGS_MOD_REFS_PINNED_DESTROY);
				return KERN_INVALID_CAPABILITY;
			}
			ipc_hash_delete(space, ip_to_object(port), name, entry);
		}

		ip_mq_lock(port);

		if (!ip_active(port)) {
			assert((type & MACH_PORT_TYPE_RECEIVE) == 0);
			entry->ie_request = IE_REQ_NONE;
			assert(!ip_is_pinned(port));
			ipc_entry_dealloc(space, ip_to_object(port), name, entry);
			ip_mq_unlock(port);
			is_write_unlock(space);
			ip_release(port);
			break;
		}

		/* For receive rights, check for guarding */
		if ((type & MACH_PORT_TYPE_RECEIVE) &&
		    (check_guard) && (port->ip_guarded) &&
		    (guard != port->ip_context)) {
			/* Guard Violation */
			uint64_t portguard = port->ip_context;
			ip_mq_unlock(port);
			is_write_unlock(space);
			/* Raise mach port guard exception */
			mach_port_guard_exception(name, portguard, kGUARD_EXC_DESTROY);
			return KERN_INVALID_RIGHT;
		}


		request = ipc_right_request_cancel(port, name, entry);
		assert(!ip_is_pinned(port));
		ipc_entry_dealloc(space, ip_to_object(port), name, entry);

		is_write_unlock(space);

		if (type & MACH_PORT_TYPE_SEND) {
			ip_srights_dec(port);
			if (port->ip_srights == 0) {
				nsrequest = ipc_notify_no_senders_prepare(port);
			}
		}

		if (type & MACH_PORT_TYPE_RECEIVE) {
			require_ip_active(port);
			assert(ip_in_space(port, space));

			ipc_port_destroy(port); /* clears receiver, consumes our ref, unlocks */
		} else if (type & MACH_PORT_TYPE_SEND_ONCE) {
			assert(port->ip_sorights > 0);
			port->ip_reply_context = 0;
			ipc_notify_send_once_and_unlock(port); /* consumes our ref */
		} else {
			assert(!ip_in_space(port, space));

			ip_mq_unlock(port);
			ip_release(port);
		}

		ipc_notify_no_senders_emit(nsrequest);

		if (request != IP_NULL) {
			ipc_notify_port_deleted(request, name);
		}


		break;
	}

	default:
		ipc_unreachable("ipc_right_destroy: strange type");
	}

	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_right_dealloc
 *	Purpose:
 *		Releases a send/send-once/dead-name/port_set user ref.
 *		Like ipc_right_delta with a delta of -1,
 *		but looks at the entry to determine the right.
 *	Conditions:
 *		The space is write-locked, and is unlocked upon return.
 *		The space must be active.
 *	Returns:
 *		KERN_SUCCESS		A user ref was released.
 *		KERN_INVALID_RIGHT	Entry has wrong type.
 *      KERN_INVALID_CAPABILITY  Deallocating a pinned right.
 */

kern_return_t
ipc_right_dealloc(
	ipc_space_t             space,
	mach_port_name_t        name,
	ipc_entry_t             entry)
{
	ipc_port_t port = IP_NULL;
	ipc_entry_bits_t bits;
	mach_port_type_t type;

	bits = entry->ie_bits;
	type = IE_BITS_TYPE(bits);

	assert(is_active(space));

	switch (type) {
	case MACH_PORT_TYPE_PORT_SET: {
		ipc_pset_t pset;

		assert(IE_BITS_UREFS(bits) == 0);
		assert(entry->ie_request == IE_REQ_NONE);

		pset = entry->ie_pset;
		ips_mq_lock(pset);
		assert(ips_active(pset));

		ipc_entry_dealloc(space, ips_to_object(pset), name, entry);

		is_write_unlock(space);

		ipc_pset_destroy(space, pset); /* consumes ref, unlocks */
		break;
	}

	case MACH_PORT_TYPE_DEAD_NAME: {
dead_name:

		assert(IE_BITS_UREFS(bits) > 0);
		assert(entry->ie_request == IE_REQ_NONE);
		assert(entry->ie_object == IPC_OBJECT_NULL);

		if (IE_BITS_UREFS(bits) == 1) {
			ipc_entry_dealloc(space, IPC_OBJECT_NULL, name, entry);
		} else {
			/* if urefs are pegged due to overflow, leave them pegged */
			if (IE_BITS_UREFS(bits) < MACH_PORT_UREFS_MAX) {
				entry->ie_bits = bits - 1; /* decrement urefs */
			}
			ipc_entry_modified(space, name, entry);
		}
		is_write_unlock(space);

		/* release any port that got converted to dead name below */
		if (port != IP_NULL) {
			ip_release(port);
		}
		break;
	}

	case MACH_PORT_TYPE_SEND_ONCE: {
		ipc_port_t request;

		assert(IE_BITS_UREFS(bits) == 1);

		port = entry->ie_port;
		assert(port != IP_NULL);

		if (ipc_right_check(space, port, name, entry, IPC_OBJECT_COPYIN_FLAGS_NONE)) {
			bits = entry->ie_bits;
			assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_DEAD_NAME);
			goto dead_name;     /* it will release port */
		}
		/* port is locked and active */

		assert(port->ip_sorights > 0);

		/*
		 * clear any reply context:
		 * no one will be sending the response b/c we are destroying
		 * the single, outstanding send once right.
		 */
		port->ip_reply_context = 0;

		request = ipc_right_request_cancel(port, name, entry);
		assert(!ip_is_pinned(port));
		ipc_entry_dealloc(space, ip_to_object(port), name, entry);

		is_write_unlock(space);

		ipc_notify_send_once_and_unlock(port);

		if (request != IP_NULL) {
			ipc_notify_port_deleted(request, name);
		}
		break;
	}

	case MACH_PORT_TYPE_SEND: {
		ipc_port_t request = IP_NULL;
		ipc_notify_nsenders_t nsrequest = { };

		assert(IE_BITS_UREFS(bits) > 0);

		port = entry->ie_port;
		assert(port != IP_NULL);

		if (ipc_right_check(space, port, name, entry, IPC_OBJECT_COPYIN_FLAGS_NONE)) {
			bits = entry->ie_bits;
			assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_DEAD_NAME);
			goto dead_name;     /* it will release port */
		}
		/* port is locked and active */

		assert(port->ip_srights > 0);

		if (IE_BITS_UREFS(bits) == 1) {
			if (ip_is_pinned(port)) {
				ip_mq_unlock(port);
				is_write_unlock(space);
				mach_port_guard_exception_pinned(space, name, port, MPG_FLAGS_MOD_REFS_PINNED_DEALLOC);
				return KERN_INVALID_CAPABILITY;
			}
			ip_srights_dec(port);
			if (port->ip_srights == 0) {
				nsrequest = ipc_notify_no_senders_prepare(port);
			}

			request = ipc_right_request_cancel(port, name, entry);
			ipc_hash_delete(space, ip_to_object(port), name, entry);
			ipc_entry_dealloc(space, ip_to_object(port), name, entry);
			ip_mq_unlock(port);
			is_write_unlock(space);

			ip_release(port);
		} else {
			/* if urefs are pegged due to overflow, leave them pegged */
			if (IE_BITS_UREFS(bits) < MACH_PORT_UREFS_MAX) {
				entry->ie_bits = bits - 1; /* decrement urefs */
			}
			ip_mq_unlock(port);
			ipc_entry_modified(space, name, entry);
			is_write_unlock(space);
		}

		ipc_notify_no_senders_emit(nsrequest);

		if (request != IP_NULL) {
			ipc_notify_port_deleted(request, name);
		}
		break;
	}

	case MACH_PORT_TYPE_SEND_RECEIVE: {
		ipc_notify_nsenders_t nsrequest = { };

		assert(IE_BITS_UREFS(bits) > 0);

		port = entry->ie_port;
		assert(port != IP_NULL);

		ip_mq_lock(port);
		require_ip_active(port);
		assert(ip_get_receiver_name(port) == name);
		assert(ip_in_space(port, space));
		assert(port->ip_srights > 0);

		if (IE_BITS_UREFS(bits) == 1) {
			ip_srights_dec(port);
			if (port->ip_srights == 0) {
				nsrequest = ipc_notify_no_senders_prepare(port);
			}

			entry->ie_bits = bits & ~(IE_BITS_UREFS_MASK |
			    MACH_PORT_TYPE_SEND);
		} else {
			/* if urefs are pegged due to overflow, leave them pegged */
			if (IE_BITS_UREFS(bits) < MACH_PORT_UREFS_MAX) {
				entry->ie_bits = bits - 1; /* decrement urefs */
			}
		}
		ip_mq_unlock(port);

		ipc_entry_modified(space, name, entry);
		is_write_unlock(space);

		ipc_notify_no_senders_emit(nsrequest);
		break;
	}

	default:
		is_write_unlock(space);
		mach_port_guard_exception(name, 0, kGUARD_EXC_INVALID_RIGHT);
		return KERN_INVALID_RIGHT;
	}

	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_right_delta
 *	Purpose:
 *		Modifies the user-reference count for a right.
 *		May deallocate the right, if the count goes to zero.
 *	Conditions:
 *		The space is write-locked, and is unlocked upon return.
 *		The space must be active.
 *	Returns:
 *		KERN_SUCCESS		Count was modified.
 *		KERN_INVALID_RIGHT	Entry has wrong type.
 *		KERN_INVALID_VALUE	Bad delta for the right.
 *		KERN_INVALID_CAPABILITY Deallocating a pinned right.
 */

kern_return_t
ipc_right_delta(
	ipc_space_t             space,
	mach_port_name_t        name,
	ipc_entry_t             entry,
	mach_port_right_t       right,
	mach_port_delta_t       delta)
{
	ipc_port_t port = IP_NULL;
	ipc_port_t port_to_release = IP_NULL;
	ipc_entry_bits_t bits;

	bits = entry->ie_bits;

/*
 *	The following is used (for case MACH_PORT_RIGHT_DEAD_NAME) in the
 *	switch below. It is used to keep track of those cases (in DIPC)
 *	where we have postponed the dropping of a port reference. Since
 *	the dropping of the reference could cause the port to disappear
 *	we postpone doing so when we are holding the space lock.
 */

	assert(is_active(space));
	assert(right < MACH_PORT_RIGHT_NUMBER);

	/* Rights-specific restrictions and operations. */

	switch (right) {
	case MACH_PORT_RIGHT_PORT_SET: {
		ipc_pset_t pset;

		if ((bits & MACH_PORT_TYPE_PORT_SET) == 0) {
			mach_port_guard_exception(name, 0, kGUARD_EXC_INVALID_RIGHT);
			goto invalid_right;
		}

		assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_PORT_SET);
		assert(IE_BITS_UREFS(bits) == 0);
		assert(entry->ie_request == IE_REQ_NONE);

		if (delta == 0) {
			goto success;
		}

		if (delta != -1) {
			goto invalid_value;
		}

		pset = entry->ie_pset;
		ips_mq_lock(pset);
		assert(ips_active(pset));

		ipc_entry_dealloc(space, ips_to_object(pset), name, entry);

		is_write_unlock(space);

		ipc_pset_destroy(space, pset); /* consumes ref, unlocks */
		break;
	}

	case MACH_PORT_RIGHT_RECEIVE: {
		ipc_port_t request = IP_NULL;

		if ((bits & MACH_PORT_TYPE_RECEIVE) == 0) {
			if ((bits & MACH_PORT_TYPE_EX_RECEIVE) == 0) {
				mach_port_guard_exception(name, 0, kGUARD_EXC_INVALID_RIGHT);
			}
			goto invalid_right;
		}

		if (delta == 0) {
			goto success;
		}

		if (delta != -1) {
			goto invalid_value;
		}

		port = entry->ie_port;
		assert(port != IP_NULL);

		/*
		 *	The port lock is needed for ipc_right_dncancel;
		 *	otherwise, we wouldn't have to take the lock
		 *	until just before dropping the space lock.
		 */

		ip_mq_lock(port);
		require_ip_active(port);
		assert(ip_get_receiver_name(port) == name);
		assert(ip_in_space(port, space));

		/* Mach Port Guard Checking */
		if (port->ip_guarded) {
			uint64_t portguard = port->ip_context;
			ip_mq_unlock(port);
			is_write_unlock(space);
			/* Raise mach port guard exception */
			mach_port_guard_exception(name, portguard, kGUARD_EXC_DESTROY);
			goto guard_failure;
		}

		if (bits & MACH_PORT_TYPE_SEND) {
			assert(IE_BITS_TYPE(bits) ==
			    MACH_PORT_TYPE_SEND_RECEIVE);
			assert(IE_BITS_UREFS(bits) > 0);
			assert(port->ip_srights > 0);

			if (ipc_port_has_prdrequest(port)) {
				/*
				 * Since another task has requested a
				 * destroy notification for this port, it
				 * isn't actually being destroyed - the receive
				 * right is just being moved to another task.
				 * Since we still have one or more send rights,
				 * we need to record the loss of the receive
				 * right and enter the remaining send right
				 * into the hash table.
				 */
				bits &= ~MACH_PORT_TYPE_RECEIVE;
				bits |= MACH_PORT_TYPE_EX_RECEIVE;
				ipc_hash_insert(space, ip_to_object(port),
				    name, entry);
				ip_reference(port);
			} else {
				/*
				 *	The remaining send right turns into a
				 *	dead name.  Notice we don't decrement
				 *	ip_srights, generate a no-senders notif,
				 *	or use ipc_right_dncancel, because the
				 *	port is destroyed "first".
				 */
				bits &= ~IE_BITS_TYPE_MASK;
				bits |= (MACH_PORT_TYPE_DEAD_NAME | MACH_PORT_TYPE_EX_RECEIVE);
				if (entry->ie_request) {
					entry->ie_request = IE_REQ_NONE;
					/* if urefs are pegged due to overflow, leave them pegged */
					if (IE_BITS_UREFS(bits) < MACH_PORT_UREFS_MAX) {
						bits++; /* increment urefs */
					}
				}
				entry->ie_object = IPC_OBJECT_NULL;
			}
			entry->ie_bits = bits;
			ipc_entry_modified(space, name, entry);
		} else {
			assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_RECEIVE);
			assert(IE_BITS_UREFS(bits) == 0);

			request = ipc_right_request_cancel(port, name, entry);
			assert(!ip_is_pinned(port));
			ipc_entry_dealloc(space, ip_to_object(port), name, entry);
		}
		is_write_unlock(space);

		ipc_port_destroy(port); /* clears receiver, consumes ref, unlocks */

		if (request != IP_NULL) {
			ipc_notify_port_deleted(request, name);
		}
		break;
	}

	case MACH_PORT_RIGHT_SEND_ONCE: {
		ipc_port_t request;

		if ((bits & MACH_PORT_TYPE_SEND_ONCE) == 0) {
			goto invalid_right;
		}

		assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_SEND_ONCE);
		assert(IE_BITS_UREFS(bits) == 1);

		port = entry->ie_port;
		assert(port != IP_NULL);

		if (ipc_right_check(space, port, name, entry, IPC_OBJECT_COPYIN_FLAGS_NONE)) {
			assert(!(entry->ie_bits & MACH_PORT_TYPE_SEND_ONCE));
			mach_port_guard_exception(name, 0, kGUARD_EXC_INVALID_RIGHT);
			/* port has died and removed from entry, release port */
			goto invalid_right;
		}
		/* port is locked and active */

		assert(port->ip_sorights > 0);

		if ((delta > 0) || (delta < -1)) {
			ip_mq_unlock(port);
			goto invalid_value;
		}

		if (delta == 0) {
			ip_mq_unlock(port);
			goto success;
		}

		/*
		 * clear any reply context:
		 * no one will be sending the response b/c we are destroying
		 * the single, outstanding send once right.
		 */
		port->ip_reply_context = 0;

		request = ipc_right_request_cancel(port, name, entry);
		assert(!ip_is_pinned(port));
		ipc_entry_dealloc(space, ip_to_object(port), name, entry);

		is_write_unlock(space);

		ipc_notify_send_once_and_unlock(port);

		if (request != IP_NULL) {
			ipc_notify_port_deleted(request, name);
		}
		break;
	}

	case MACH_PORT_RIGHT_DEAD_NAME: {
		mach_port_urefs_t urefs;

		if (bits & MACH_PORT_TYPE_SEND_RIGHTS) {
			port = entry->ie_port;
			assert(port != IP_NULL);

			if (!ipc_right_check(space, port, name, entry, IPC_OBJECT_COPYIN_FLAGS_NONE)) {
				/* port is locked and active */
				ip_mq_unlock(port);
				port = IP_NULL;
				mach_port_guard_exception(name, 0, kGUARD_EXC_INVALID_RIGHT);
				goto invalid_right;
			}
			bits = entry->ie_bits;
			/* port has died and removed from entry, release port */
			port_to_release = port;
			port = IP_NULL;
		} else if ((bits & MACH_PORT_TYPE_DEAD_NAME) == 0) {
			mach_port_guard_exception(name, 0, kGUARD_EXC_INVALID_RIGHT);
			goto invalid_right;
		}

		assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_DEAD_NAME);
		assert(IE_BITS_UREFS(bits) > 0);
		assert(entry->ie_object == IPC_OBJECT_NULL);
		assert(entry->ie_request == IE_REQ_NONE);

		if (delta > ((mach_port_delta_t)MACH_PORT_UREFS_MAX) ||
		    delta < (-((mach_port_delta_t)MACH_PORT_UREFS_MAX))) {
			/* this will release port */
			goto invalid_value;
		}

		urefs = IE_BITS_UREFS(bits);

		if (urefs == MACH_PORT_UREFS_MAX) {
			/*
			 * urefs are pegged due to an overflow
			 * only a delta removing all refs at once can change it
			 */

			if (delta != (-((mach_port_delta_t)MACH_PORT_UREFS_MAX))) {
				delta = 0;
			}
		} else {
			if (MACH_PORT_UREFS_UNDERFLOW(urefs, delta)) {
				/* this will release port */
				goto invalid_value;
			}
			if (MACH_PORT_UREFS_OVERFLOW(urefs, delta)) {
				/* leave urefs pegged to maximum if it overflowed */
				delta = MACH_PORT_UREFS_MAX - urefs;
			}
		}

		if ((urefs + delta) == 0) {
			ipc_entry_dealloc(space, IPC_OBJECT_NULL, name, entry);
		} else if (delta != 0) {
			entry->ie_bits = bits + delta;
			ipc_entry_modified(space, name, entry);
		}

		is_write_unlock(space);

		if (port_to_release != IP_NULL) {
			ip_release(port_to_release);
			port_to_release = IP_NULL;
		}

		break;
	}

	case MACH_PORT_RIGHT_SEND: {
		mach_port_urefs_t urefs;
		ipc_port_t request = IP_NULL;
		ipc_notify_nsenders_t nsrequest = { };

		if ((bits & MACH_PORT_TYPE_SEND) == 0) {
			/* invalid right exception only when not live/dead confusion */
			if ((bits & MACH_PORT_TYPE_DEAD_NAME) == 0
#if !defined(AE_MAKESENDRIGHT_FIXED)
			    /*
			     * AE tries to add single send right without knowing if it already owns one.
			     * But if it doesn't, it should own the receive right and delta should be 1.
			     */
			    && (((bits & MACH_PORT_TYPE_RECEIVE) == 0) || (delta != 1))
#endif
			    ) {
				mach_port_guard_exception(name, 0, kGUARD_EXC_INVALID_RIGHT);
			}
			goto invalid_right;
		}

		/* maximum urefs for send is MACH_PORT_UREFS_MAX */

		port = entry->ie_port;
		assert(port != IP_NULL);

		if (ipc_right_check(space, port, name, entry, IPC_OBJECT_COPYIN_FLAGS_NONE)) {
			assert((entry->ie_bits & MACH_PORT_TYPE_SEND) == 0);
			/* port has died and removed from entry, release port */
			goto invalid_right;
		}
		/* port is locked and active */

		assert(port->ip_srights > 0);

		if (delta > ((mach_port_delta_t)MACH_PORT_UREFS_MAX) ||
		    delta < (-((mach_port_delta_t)MACH_PORT_UREFS_MAX))) {
			ip_mq_unlock(port);
			goto invalid_value;
		}

		urefs = IE_BITS_UREFS(bits);

		if (urefs == MACH_PORT_UREFS_MAX) {
			/*
			 * urefs are pegged due to an overflow
			 * only a delta removing all refs at once can change it
			 */

			if (delta != (-((mach_port_delta_t)MACH_PORT_UREFS_MAX))) {
				delta = 0;
			}
		} else {
			if (MACH_PORT_UREFS_UNDERFLOW(urefs, delta)) {
				ip_mq_unlock(port);
				goto invalid_value;
			}
			if (MACH_PORT_UREFS_OVERFLOW(urefs, delta)) {
				/* leave urefs pegged to maximum if it overflowed */
				delta = MACH_PORT_UREFS_MAX - urefs;
			}
		}

		if ((urefs + delta) == 0) {
			if (ip_is_pinned(port)) {
				ip_mq_unlock(port);
				is_write_unlock(space);
				mach_port_guard_exception_pinned(space, name, port, MPG_FLAGS_MOD_REFS_PINNED_DEALLOC);
				return KERN_INVALID_CAPABILITY;
			}

			ip_srights_dec(port);
			if (port->ip_srights == 0) {
				nsrequest = ipc_notify_no_senders_prepare(port);
			}

			if (bits & MACH_PORT_TYPE_RECEIVE) {
				assert(ip_get_receiver_name(port) == name);
				assert(ip_in_space(port, space));
				assert(IE_BITS_TYPE(bits) ==
				    MACH_PORT_TYPE_SEND_RECEIVE);

				entry->ie_bits = bits & ~(IE_BITS_UREFS_MASK |
				    MACH_PORT_TYPE_SEND);
				ipc_entry_modified(space, name, entry);
			} else {
				assert(IE_BITS_TYPE(bits) ==
				    MACH_PORT_TYPE_SEND);

				request = ipc_right_request_cancel(port, name, entry);
				ipc_hash_delete(space, ip_to_object(port),
				    name, entry);
				assert(!ip_is_pinned(port));
				ipc_entry_dealloc(space, ip_to_object(port),
				    name, entry);
				port_to_release = port;
			}
		} else if (delta != 0) {
			entry->ie_bits = bits + delta;
			ipc_entry_modified(space, name, entry);
		}

		ip_mq_unlock(port);

		is_write_unlock(space);

		if (port_to_release != IP_NULL) {
			ip_release(port_to_release);
			port_to_release = IP_NULL;
		}

		ipc_notify_no_senders_emit(nsrequest);

		if (request != IP_NULL) {
			ipc_notify_port_deleted(request, name);
		}
		break;
	}

	case MACH_PORT_RIGHT_LABELH:
		goto invalid_right;

	default:
		panic("ipc_right_delta: strange right %d for 0x%x (%p) in space:%p",
		    right, name, (void *)entry, (void *)space);
	}

	return KERN_SUCCESS;

success:
	is_write_unlock(space);
	return KERN_SUCCESS;

invalid_right:
	is_write_unlock(space);
	if (port != IP_NULL) {
		ip_release(port);
	}
	return KERN_INVALID_RIGHT;

invalid_value:
	is_write_unlock(space);
	if (port_to_release) {
		ip_release(port_to_release);
	}
	mach_port_guard_exception(name, 0, kGUARD_EXC_INVALID_VALUE);
	return KERN_INVALID_VALUE;

guard_failure:
	return KERN_INVALID_RIGHT;
}

/*
 *	Routine:	ipc_right_destruct
 *	Purpose:
 *		Deallocates the receive right and modifies the
 *		user-reference count for the send rights as requested.
 *	Conditions:
 *		The space is write-locked, and is unlocked upon return.
 *		The space must be active.
 *	Returns:
 *		KERN_SUCCESS		Count was modified.
 *		KERN_INVALID_RIGHT	Entry has wrong type.
 *		KERN_INVALID_VALUE	Bad delta for the right.
 */

kern_return_t
ipc_right_destruct(
	ipc_space_t             space,
	mach_port_name_t        name,
	ipc_entry_t             entry,
	mach_port_delta_t       srdelta,
	uint64_t                guard)
{
	ipc_port_t port = IP_NULL;
	ipc_entry_bits_t bits;

	mach_port_urefs_t urefs;
	ipc_port_t request = IP_NULL;
	ipc_notify_nsenders_t nsrequest = { };

	bits = entry->ie_bits;

	assert(is_active(space));

	if ((bits & MACH_PORT_TYPE_RECEIVE) == 0) {
		is_write_unlock(space);

		/* No exception if we used to have receive and held entry since */
		if ((bits & MACH_PORT_TYPE_EX_RECEIVE) == 0) {
			mach_port_guard_exception(name, 0, kGUARD_EXC_INVALID_RIGHT);
		}
		return KERN_INVALID_RIGHT;
	}

	if (srdelta && (bits & MACH_PORT_TYPE_SEND) == 0) {
		is_write_unlock(space);
		mach_port_guard_exception(name, 0, kGUARD_EXC_INVALID_RIGHT);
		return KERN_INVALID_RIGHT;
	}

	if (srdelta > 0) {
		goto invalid_value;
	}

	port = entry->ie_port;
	assert(port != IP_NULL);

	ip_mq_lock(port);
	require_ip_active(port);
	assert(ip_get_receiver_name(port) == name);
	assert(ip_in_space(port, space));

	/* Mach Port Guard Checking */
	if (port->ip_guarded && (guard != port->ip_context)) {
		uint64_t portguard = port->ip_context;
		ip_mq_unlock(port);
		is_write_unlock(space);
		mach_port_guard_exception(name, portguard, kGUARD_EXC_DESTROY);
		return KERN_INVALID_ARGUMENT;
	}

	/*
	 * First reduce the send rights as requested and
	 * adjust the entry->ie_bits accordingly. The
	 * ipc_entry_modified() call is made once the receive
	 * right is destroyed too.
	 */

	if (srdelta) {
		assert(port->ip_srights > 0);

		urefs = IE_BITS_UREFS(bits);

		/*
		 * Since we made sure that srdelta is negative,
		 * the check for urefs overflow is not required.
		 */
		if (MACH_PORT_UREFS_UNDERFLOW(urefs, srdelta)) {
			ip_mq_unlock(port);
			goto invalid_value;
		}

		if (urefs == MACH_PORT_UREFS_MAX) {
			/*
			 * urefs are pegged due to an overflow
			 * only a delta removing all refs at once can change it
			 */
			if (srdelta != (-((mach_port_delta_t)MACH_PORT_UREFS_MAX))) {
				srdelta = 0;
			}
		}

		if ((urefs + srdelta) == 0) {
			ip_srights_dec(port);
			if (port->ip_srights == 0) {
				nsrequest = ipc_notify_no_senders_prepare(port);
			}
			assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_SEND_RECEIVE);
			entry->ie_bits = bits & ~(IE_BITS_UREFS_MASK |
			    MACH_PORT_TYPE_SEND);
		} else {
			entry->ie_bits = bits + srdelta;
		}
	}

	/*
	 * Now destroy the receive right. Update space and
	 * entry accordingly.
	 */

	bits = entry->ie_bits;
	if (bits & MACH_PORT_TYPE_SEND) {
		assert(IE_BITS_UREFS(bits) > 0);
		assert(IE_BITS_UREFS(bits) <= MACH_PORT_UREFS_MAX);

		if (ipc_port_has_prdrequest(port)) {
			/*
			 * Since another task has requested a
			 * destroy notification for this port, it
			 * isn't actually being destroyed - the receive
			 * right is just being moved to another task.
			 * Since we still have one or more send rights,
			 * we need to record the loss of the receive
			 * right and enter the remaining send right
			 * into the hash table.
			 */
			bits &= ~MACH_PORT_TYPE_RECEIVE;
			bits |= MACH_PORT_TYPE_EX_RECEIVE;
			ipc_hash_insert(space, ip_to_object(port),
			    name, entry);
			ip_reference(port);
		} else {
			/*
			 *	The remaining send right turns into a
			 *	dead name.  Notice we don't decrement
			 *	ip_srights, generate a no-senders notif,
			 *	or use ipc_right_dncancel, because the
			 *	port is destroyed "first".
			 */
			bits &= ~IE_BITS_TYPE_MASK;
			bits |= (MACH_PORT_TYPE_DEAD_NAME | MACH_PORT_TYPE_EX_RECEIVE);
			if (entry->ie_request) {
				entry->ie_request = IE_REQ_NONE;
				if (IE_BITS_UREFS(bits) < MACH_PORT_UREFS_MAX) {
					bits++; /* increment urefs */
				}
			}
			entry->ie_object = IPC_OBJECT_NULL;
		}
		entry->ie_bits = bits;
		ipc_entry_modified(space, name, entry);
	} else {
		assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_RECEIVE);
		assert(IE_BITS_UREFS(bits) == 0);
		request = ipc_right_request_cancel(port, name, entry);
		assert(!ip_is_pinned(port));
		ipc_entry_dealloc(space, ip_to_object(port), name, entry);
	}

	/* Unlock space */
	is_write_unlock(space);

	ipc_notify_no_senders_emit(nsrequest);

	ipc_port_destroy(port); /* clears receiver, consumes ref, unlocks */

	if (request != IP_NULL) {
		ipc_notify_port_deleted(request, name);
	}

	return KERN_SUCCESS;

invalid_value:
	is_write_unlock(space);
	mach_port_guard_exception(name, 0, kGUARD_EXC_INVALID_VALUE);
	return KERN_INVALID_VALUE;
}


/*
 *	Routine:	ipc_right_info
 *	Purpose:
 *		Retrieves information about the right.
 *	Conditions:
 *		The space is active and write-locked.
 *	        The space is unlocked upon return.
 *	Returns:
 *		KERN_SUCCESS		Retrieved info
 */

kern_return_t
ipc_right_info(
	ipc_space_t             space,
	mach_port_name_t        name,
	ipc_entry_t             entry,
	mach_port_type_t        *typep,
	mach_port_urefs_t       *urefsp)
{
	ipc_port_t port;
	ipc_entry_bits_t bits;
	mach_port_type_t type = 0;
	ipc_port_request_index_t request;

	bits = entry->ie_bits;
	request = entry->ie_request;
	port = entry->ie_port;

	if (bits & MACH_PORT_TYPE_RECEIVE) {
		assert(IP_VALID(port));

		if (request != IE_REQ_NONE) {
			ip_mq_lock(port);
			require_ip_active(port);
			type |= ipc_port_request_type(port, name, request);
			ip_mq_unlock(port);
		}
		is_write_unlock(space);
	} else if (bits & MACH_PORT_TYPE_SEND_RIGHTS) {
		/*
		 * validate port is still alive - if so, get request
		 * types while we still have it locked.  Otherwise,
		 * recapture the (now dead) bits.
		 */
		if (!ipc_right_check(space, port, name, entry, IPC_OBJECT_COPYIN_FLAGS_NONE)) {
			if (request != IE_REQ_NONE) {
				type |= ipc_port_request_type(port, name, request);
			}
			ip_mq_unlock(port);
			is_write_unlock(space);
		} else {
			bits = entry->ie_bits;
			assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_DEAD_NAME);
			is_write_unlock(space);
			ip_release(port);
		}
	} else {
		is_write_unlock(space);
	}

	type |= IE_BITS_TYPE(bits);

	*typep = type;
	*urefsp = IE_BITS_UREFS(bits);
	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_right_copyin_check_reply
 *	Purpose:
 *		Check if a subsequent ipc_right_copyin would succeed. Used only
 *		by ipc_kmsg_copyin_header to check if reply_port can be copied in.
 *		If the reply port is an immovable send right, it errors out.
 *	Conditions:
 *		The space is locked (read or write) and active.
 */

boolean_t
ipc_right_copyin_check_reply(
	__assert_only ipc_space_t       space,
	mach_port_name_t                reply_name,
	ipc_entry_t                     reply_entry,
	mach_msg_type_name_t            reply_type,
	ipc_entry_t                     dest_entry,
	uint8_t                         *reply_port_semantics_violation)
{
	ipc_entry_bits_t bits;
	ipc_port_t reply_port;
	ipc_port_t dest_port;
	bool violate_reply_port_semantics = false;

	bits = reply_entry->ie_bits;
	assert(is_active(space));

	switch (reply_type) {
	case MACH_MSG_TYPE_MAKE_SEND:
		if ((bits & MACH_PORT_TYPE_RECEIVE) == 0) {
			return FALSE;
		}
		break;

	case MACH_MSG_TYPE_MAKE_SEND_ONCE:
		if ((bits & MACH_PORT_TYPE_RECEIVE) == 0) {
			return FALSE;
		}
		break;

	case MACH_MSG_TYPE_MOVE_RECEIVE:
		/* ipc_kmsg_copyin_header already filters it out */
		return FALSE;

	case MACH_MSG_TYPE_COPY_SEND:
	case MACH_MSG_TYPE_MOVE_SEND:
	case MACH_MSG_TYPE_MOVE_SEND_ONCE: {
		if (bits & MACH_PORT_TYPE_DEAD_NAME) {
			break;
		}

		if ((bits & MACH_PORT_TYPE_SEND_RIGHTS) == 0) {
			return FALSE;
		}

		reply_port = reply_entry->ie_port;
		assert(reply_port != IP_NULL);

		/*
		 * active status peek to avoid checks that will be skipped
		 * on copyin for dead ports.  Lock not held, so will not be
		 * atomic (but once dead, there's no going back).
		 */
		if (!ip_active(reply_port)) {
			break;
		}

		/*
		 * Can't copyin a send right that is marked immovable. This bit
		 * is set only during port creation and never unset. So it can
		 * be read without a lock.
		 */
		if (ip_is_immovable_send(reply_port)) {
			mach_port_guard_exception_immovable(space, reply_name, reply_port);
			return FALSE;
		}

		if (reply_type == MACH_MSG_TYPE_MOVE_SEND_ONCE) {
			if ((bits & MACH_PORT_TYPE_SEND_ONCE) == 0) {
				return FALSE;
			}
		} else {
			if ((bits & MACH_PORT_TYPE_SEND) == 0) {
				return FALSE;
			}
		}

		break;
	}

	default:
		panic("ipc_right_copyin_check: strange rights");
	}

	if ((IE_BITS_TYPE(dest_entry->ie_bits) == MACH_PORT_TYPE_PORT_SET) ||
	    (IE_BITS_TYPE(reply_entry->ie_bits) == MACH_PORT_TYPE_PORT_SET)) {
		return TRUE;
	}

	/* The only disp allowed when a reply port is a local port of mach msg is MAKE_SO. */
	reply_port = reply_entry->ie_port;
	assert(reply_port != IP_NULL);

	if (ip_active(reply_port)) {
		if (ip_is_reply_port(reply_port) && (reply_type != MACH_MSG_TYPE_MAKE_SEND_ONCE)) {
			return FALSE;
		}

		/* When sending a msg to remote port that requires reply port semantics enforced the local port of that msg needs to be a reply port. */
		dest_port = dest_entry->ie_port;
		if (IP_VALID(dest_port)) {
			ip_mq_lock(dest_port);
			if (ip_active(dest_port)) {
				/* populates reply_port_semantics_violation if we need to send telemetry */
				violate_reply_port_semantics = ip_violates_rigid_reply_port_semantics(dest_port, reply_port, reply_port_semantics_violation) ||
				    ip_violates_reply_port_semantics(dest_port, reply_port, reply_port_semantics_violation);
			}
			ip_mq_unlock(dest_port);
			if (violate_reply_port_semantics && reply_port_semantics) {
				mach_port_guard_exception(reply_name, 0, kGUARD_EXC_REQUIRE_REPLY_PORT_SEMANTICS);
				return FALSE;
			}
		}
	}

	return TRUE;
}

/*
 *	Routine:	ipc_right_copyin_check_guard_locked
 *	Purpose:
 *		Check if the port is guarded and the guard
 *		value matches the one passed in the arguments.
 *		If MACH_MSG_GUARD_FLAGS_UNGUARDED_ON_SEND is set,
 *		check if the port is unguarded.
 *	Conditions:
 *		The port is locked.
 *	Returns:
 *		KERN_SUCCESS		Port is either unguarded
 *					or guarded with expected value
 *		KERN_INVALID_ARGUMENT	Port is either unguarded already or guard mismatch.
 *					This also raises a EXC_GUARD exception.
 */
static kern_return_t
ipc_right_copyin_check_guard_locked(
	ipc_port_t              port,
	mach_port_name_t        name,
	mach_msg_guarded_port_descriptor_t *gdesc)
{
	mach_port_context_t    context = gdesc->u_context;
	mach_msg_guard_flags_t flags   = gdesc->flags;

	if ((flags & MACH_MSG_GUARD_FLAGS_UNGUARDED_ON_SEND) && !port->ip_guarded && !context) {
		return KERN_SUCCESS;
	} else if (port->ip_guarded && (port->ip_context == context)) {
		return KERN_SUCCESS;
	}

	/* Incorrect guard; Raise exception */
	mach_port_guard_exception(name, port->ip_context, kGUARD_EXC_INCORRECT_GUARD);
	return KERN_INVALID_ARGUMENT;
}

void
ipc_right_copyin_rcleanup_init(
	ipc_copyin_rcleanup_t  *icrc,
	mach_msg_guarded_port_descriptor_t *gdesc)
{
	*icrc = (ipc_copyin_rcleanup_t){
		.icrc_guarded_desc = gdesc,
	};
}

void
ipc_right_copyin_cleanup_destroy(
	ipc_copyin_cleanup_t   *icc,
	mach_port_name_t        name)
{
	if (icc->icc_release_port) {
		ip_release(icc->icc_release_port);
	}
	if (icc->icc_deleted_port) {
		ipc_notify_port_deleted(icc->icc_deleted_port, name);
	}
}

void
ipc_right_copyin_rcleanup_destroy(ipc_copyin_rcleanup_t *icrc)
{
#if IMPORTANCE_INHERITANCE
	if (icrc->icrc_assert_count) {
		ipc_importance_task_drop_internal_assertion(current_task()->task_imp_base,
		    icrc->icrc_assert_count);
	}
#endif /* IMPORTANCE_INHERITANCE */
	if (icrc->icrc_free_list.next) {
		waitq_link_free_list(WQT_PORT_SET, &icrc->icrc_free_list);
	}
}

/*
 *	Routine:	ipc_right_copyin
 *	Purpose:
 *		Copyin a capability from a space.
 *		If successful, the caller gets a ref
 *		for the resulting port, unless it is IP_DEAD,
 *		and possibly a send-once right which should
 *		be used in a port-deleted notification.
 *
 *		If deadok is not TRUE, the copyin operation
 *		will fail instead of producing IO_DEAD.
 *
 *		The entry is deallocated if the entry type becomes
 *		MACH_PORT_TYPE_NONE.
 *	Conditions:
 *		The space is write-locked and active.
 *	Returns:
 *		KERN_SUCCESS		Acquired a port, possibly IP_DEAD.
 *		KERN_INVALID_RIGHT	Name doesn't denote correct right.
 *		KERN_INVALID_CAPABILITY	Trying to move a kobject port,
 *					an immovable right or
 *					the last ref of a pinned right
 *		KERN_INVALID_ARGUMENT	Port is unguarded or guard mismatch
 */

kern_return_t
ipc_right_copyin(
	ipc_space_t             space,
	mach_port_name_t        name,
	mach_msg_type_name_t    msgt_name,
	ipc_object_copyin_flags_t  flags,
	ipc_entry_t             entry,
	ipc_port_t             *portp,
	ipc_copyin_cleanup_t   *icc,
	ipc_copyin_rcleanup_t  *icrc)
{
	ipc_entry_bits_t bits;
	ipc_port_t port;
	kern_return_t kr;
	uint32_t moves = (flags & IPC_OBJECT_COPYIN_FLAGS_DEST_EXTRA_MOVE) ? 2 : 1;
	boolean_t deadok = !!(flags & IPC_OBJECT_COPYIN_FLAGS_DEADOK);
	boolean_t allow_imm_send = !!(flags & IPC_OBJECT_COPYIN_FLAGS_ALLOW_IMMOVABLE_SEND);
	boolean_t allow_reply_make_so = !!(flags & IPC_OBJECT_COPYIN_FLAGS_ALLOW_REPLY_MAKE_SEND_ONCE);
	boolean_t allow_reply_move_so = !!(flags & IPC_OBJECT_COPYIN_FLAGS_ALLOW_REPLY_MOVE_SEND_ONCE);

	if (flags & IPC_OBJECT_COPYIN_FLAGS_DEST_EXTRA_MOVE) {
		assert((flags & IPC_OBJECT_COPYIN_FLAGS_DEST_EXTRA_COPY) == 0);
		assert(msgt_name == MACH_MSG_TYPE_MOVE_SEND);
	}
	if (flags & IPC_OBJECT_COPYIN_FLAGS_DEST_EXTRA_COPY) {
		assert(msgt_name == MACH_MSG_TYPE_MOVE_SEND ||
		    msgt_name == MACH_MSG_TYPE_COPY_SEND);
	}

	*portp = IP_NULL;
	icc->icc_release_port = IP_NULL;
	icc->icc_deleted_port = IP_NULL;

	bits = entry->ie_bits;

	assert(is_active(space));

	switch (msgt_name) {
	case MACH_MSG_TYPE_MAKE_SEND: {
		if ((bits & MACH_PORT_TYPE_RECEIVE) == 0) {
			goto invalid_right;
		}

		port = entry->ie_port;
		assert(port != IP_NULL);

		if (ip_is_reply_port(port)) {
			mach_port_guard_exception(name, 0, kGUARD_EXC_INVALID_RIGHT);
			return KERN_INVALID_CAPABILITY;
		}

		ip_mq_lock(port);
		assert(ip_get_receiver_name(port) == name);
		assert(ip_in_space(port, space));

		ipc_port_make_send_any_locked(port);
		ip_mq_unlock(port);

		*portp = port;
		break;
	}

	case MACH_MSG_TYPE_MAKE_SEND_ONCE: {
		if ((bits & MACH_PORT_TYPE_RECEIVE) == 0) {
			goto invalid_right;
		}

		port = entry->ie_port;
		assert(port != IP_NULL);

		if ((ip_is_reply_port(port)) && !allow_reply_make_so) {
			mach_port_guard_exception(name, 0, kGUARD_EXC_INVALID_RIGHT);
			return KERN_INVALID_CAPABILITY;
		}

		ip_mq_lock(port);
		require_ip_active(port);
		assert(ip_get_receiver_name(port) == name);
		assert(ip_in_space(port, space));

		ipc_port_make_sonce_locked(port);
		ip_mq_unlock(port);

		*portp = port;
		break;
	}

	case MACH_MSG_TYPE_MOVE_RECEIVE: {
		bool allow_imm_recv = false;
		ipc_port_t request = IP_NULL;

		if ((bits & MACH_PORT_TYPE_RECEIVE) == 0) {
			goto invalid_right;
		}

		port = entry->ie_port;
		assert(port != IP_NULL);

		ip_mq_lock(port);
		require_ip_active(port);
		assert(ip_get_receiver_name(port) == name);
		assert(ip_in_space(port, space));

		/*
		 * Disallow moving receive-right kobjects/kolabel, e.g. mk_timer ports
		 * The ipc_port structure uses the kdata union of kobject and
		 * imp_task exclusively. Thus, general use of a kobject port as
		 * a receive right can cause type confusion in the importance
		 * code.
		 */
		if (ip_is_kobject(port) || ip_is_kolabeled(port)) {
			/*
			 * Distinguish an invalid right, e.g., trying to move
			 * a send right as a receive right, from this
			 * situation which is, "This is a valid receive right,
			 * but it's also a kobject and you can't move it."
			 */
			ip_mq_unlock(port);
			mach_port_guard_exception(name, 0, kGUARD_EXC_IMMOVABLE);
			return KERN_INVALID_CAPABILITY;
		}

		if (port->ip_service_port && port->ip_splabel &&
		    !ipc_service_port_label_is_bootstrap_port((ipc_service_port_label_t)port->ip_splabel)) {
			allow_imm_recv = !!(flags & IPC_OBJECT_COPYIN_FLAGS_ALLOW_IMMOVABLE_RECEIVE);
		} else if (ip_is_libxpc_connection_port(port)) {
			allow_imm_recv = !!(flags & IPC_OBJECT_COPYIN_FLAGS_ALLOW_CONN_IMMOVABLE_RECEIVE);
		}

		if ((!allow_imm_recv && port->ip_immovable_receive) ||
		    ip_is_reply_port(port) ||     /* never move reply port rcv right */
		    port->ip_specialreply) {
			assert(!ip_in_space(port, ipc_space_kernel));
			ip_mq_unlock(port);
			assert(current_task() != kernel_task);
			mach_port_guard_exception(name, 0, kGUARD_EXC_IMMOVABLE);
			return KERN_INVALID_CAPABILITY;
		}

		if (icrc->icrc_guarded_desc) {
			kr = ipc_right_copyin_check_guard_locked(port, name,
			    icrc->icrc_guarded_desc);
			if (kr != KERN_SUCCESS) {
				ip_mq_unlock(port);
				return kr;
			}
			/* this flag will be cleared during copyout */
			icrc->icrc_guarded_desc->flags |=
			    MACH_MSG_GUARD_FLAGS_UNGUARDED_ON_SEND;
		}

		if (bits & MACH_PORT_TYPE_SEND) {
			assert(IE_BITS_TYPE(bits) ==
			    MACH_PORT_TYPE_SEND_RECEIVE);
			assert(IE_BITS_UREFS(bits) > 0);
			assert(port->ip_srights > 0);

			bits &= ~MACH_PORT_TYPE_RECEIVE;
			bits |= MACH_PORT_TYPE_EX_RECEIVE;
			entry->ie_bits = bits;
			ipc_hash_insert(space, ip_to_object(port), name, entry);
			ip_reference(port);
			ipc_entry_modified(space, name, entry);
		} else {
			assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_RECEIVE);
			assert(IE_BITS_UREFS(bits) == 0);

			request = ipc_right_request_cancel(port, name, entry);
			assert(!ip_is_pinned(port));
			ipc_entry_dealloc(space, ip_to_object(port), name, entry);
		}

		/* ipc_port_clear_receiver unguards the port and clears the ip_immovable_receive bit */
		(void)ipc_port_clear_receiver(port, FALSE, &icrc->icrc_free_list); /* don't destroy the port/mqueue */

#if IMPORTANCE_INHERITANCE
		/*
		 * Account for boosts the current task is going to lose when
		 * copying this right in.  Tempowner ports have either not
		 * been accounting to any task (and therefore are already in
		 * "limbo" state w.r.t. assertions) or to some other specific
		 * task. As we have no way to drop the latter task's assertions
		 * here, We'll deduct those when we enqueue it on its
		 * destination port (see ipc_port_check_circularity()).
		 */
		if (port->ip_tempowner == 0) {
			assert(IIT_NULL == ip_get_imp_task(port));

			/* ports in limbo have to be tempowner */
			port->ip_tempowner = 1;
			icrc->icrc_assert_count = port->ip_impcount;
		}
#endif /* IMPORTANCE_INHERITANCE */

		ip_mq_unlock(port);

		*portp = port;
		icc->icc_deleted_port = request;
		break;
	}

	case MACH_MSG_TYPE_COPY_SEND: {
		if (bits & MACH_PORT_TYPE_DEAD_NAME) {
			goto copy_dead;
		}

		/* allow for dead send-once rights */

		if ((bits & MACH_PORT_TYPE_SEND_RIGHTS) == 0) {
			goto invalid_right;
		}

		assert(IE_BITS_UREFS(bits) > 0);

		port = entry->ie_port;
		assert(port != IP_NULL);

		if (ipc_right_check(space, port, name, entry, IPC_OBJECT_COPYIN_FLAGS_NONE)) {
			bits = entry->ie_bits;
			icc->icc_release_port = port;
			goto copy_dead;
		}
		/* port is locked and active */

		if ((bits & MACH_PORT_TYPE_SEND) == 0) {
			assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_SEND_ONCE);
			assert(port->ip_sorights > 0);

			ip_mq_unlock(port);
			goto invalid_right;
		}

		if (ip_is_reply_port(port)) {
			ip_mq_unlock(port);
			mach_port_guard_exception(name, 0, kGUARD_EXC_INVALID_RIGHT);
			return KERN_INVALID_CAPABILITY;
		}

		if (!allow_imm_send && ip_is_immovable_send(port)) {
			ip_mq_unlock(port);
			mach_port_guard_exception_immovable(space, name, port);
			return KERN_INVALID_CAPABILITY;
		}

		ipc_port_copy_send_any_locked(port);
		if (flags & IPC_OBJECT_COPYIN_FLAGS_DEST_EXTRA_COPY) {
			ipc_port_copy_send_any_locked(port);
		}
		ip_mq_unlock(port);

		*portp = port;
		break;
	}

	case MACH_MSG_TYPE_MOVE_SEND: {
		ipc_port_t request = IP_NULL;

		if (bits & MACH_PORT_TYPE_DEAD_NAME) {
			goto move_dead;
		}

		/* allow for dead send-once rights */

		if ((bits & MACH_PORT_TYPE_SEND_RIGHTS) == 0) {
			goto invalid_right;
		}

		assert(IE_BITS_UREFS(bits) > 0);

		port = entry->ie_port;
		assert(port != IP_NULL);

		if (ipc_right_check(space, port, name, entry, IPC_OBJECT_COPYIN_FLAGS_NONE)) {
			bits = entry->ie_bits;
			icc->icc_release_port = port;
			goto move_dead;
		}
		/* port is locked and active */

		if ((bits & MACH_PORT_TYPE_SEND) == 0 ||
		    IE_BITS_UREFS(bits) < moves) {
			ip_mq_unlock(port);
			goto invalid_right;
		}

		if (ip_is_pinned(port) && IE_BITS_UREFS(bits) == moves) {
			ip_mq_unlock(port);
			mach_port_guard_exception_pinned(space, name,
			    port, MPG_FLAGS_MOD_REFS_PINNED_COPYIN);
			return KERN_INVALID_CAPABILITY;
		}

		if (ip_is_reply_port(port)) {
			ip_mq_unlock(port);
			mach_port_guard_exception(name, 0, kGUARD_EXC_INVALID_RIGHT);
			return KERN_INVALID_CAPABILITY;
		}

		if (!allow_imm_send && ip_is_immovable_send(port)) {
			ip_mq_unlock(port);
			mach_port_guard_exception_immovable(space, name, port);
			return KERN_INVALID_CAPABILITY;
		}

		if (IE_BITS_UREFS(bits) == moves) {
			assert(port->ip_srights > 0);

			/*
			 * We have exactly "moves" send rights for this port
			 * in this space, which means that we will liberate the
			 * naked send right held by this entry.
			 *
			 * However refcounting rules around entries are that
			 * naked send rights on behalf of spaces do not have an
			 * associated port reference, so we need to donate one
			 * ...
			 */
			if (bits & MACH_PORT_TYPE_RECEIVE) {
				assert(ip_get_receiver_name(port) == name);
				assert(ip_in_space(port, space));
				assert(IE_BITS_TYPE(bits) ==
				    MACH_PORT_TYPE_SEND_RECEIVE);

				/*
				 * ... that we inject manually when the entry
				 * stays alive
				 */
				entry->ie_bits = bits & ~
				    (IE_BITS_UREFS_MASK | MACH_PORT_TYPE_SEND);
				ipc_entry_modified(space, name, entry);
				ip_reference(port);
			} else {
				assert(IE_BITS_TYPE(bits) ==
				    MACH_PORT_TYPE_SEND);

				/* ... that we steal from the entry when it dies */
				request = ipc_right_request_cancel(port, name, entry);
				ipc_hash_delete(space, ip_to_object(port),
				    name, entry);
				ipc_entry_dealloc(space, ip_to_object(port),
				    name, entry);
				/* transfer entry's reference to caller */
			}
		} else {
			ipc_port_copy_send_any_locked(port);
			/* if urefs are pegged due to overflow, leave them pegged */
			if (IE_BITS_UREFS(bits) < MACH_PORT_UREFS_MAX) {
				entry->ie_bits = bits - moves; /* decrement urefs */
			}
			ipc_entry_modified(space, name, entry);
		}

		if (flags & (IPC_OBJECT_COPYIN_FLAGS_DEST_EXTRA_COPY |
		    IPC_OBJECT_COPYIN_FLAGS_DEST_EXTRA_MOVE)) {
			ipc_port_copy_send_any_locked(port);
		}

		ip_mq_unlock(port);
		*portp = port;
		icc->icc_deleted_port = request;
		break;
	}

	case MACH_MSG_TYPE_MOVE_SEND_ONCE: {
		ipc_port_t request;

		if (bits & MACH_PORT_TYPE_DEAD_NAME) {
			goto move_dead;
		}

		/* allow for dead send rights */

		if ((bits & MACH_PORT_TYPE_SEND_RIGHTS) == 0) {
			goto invalid_right;
		}

		assert(IE_BITS_UREFS(bits) > 0);

		port = entry->ie_port;
		assert(port != IP_NULL);

		if (ipc_right_check(space, port, name, entry, flags)) {
			bits = entry->ie_bits;
			icc->icc_release_port = port;
			goto move_dead;
		}
		/*
		 * port is locked, but may not be active:
		 * Allow copyin of inactive ports with no dead name request and treat it
		 * as if the copyin of the port was successful and port became inactive
		 * later.
		 */

		if ((bits & MACH_PORT_TYPE_SEND_ONCE) == 0) {
			assert(bits & MACH_PORT_TYPE_SEND);
			assert(port->ip_srights > 0);

			ip_mq_unlock(port);
			goto invalid_right;
		}

		if (ip_is_reply_port(port) && !allow_reply_move_so) {
			ip_mq_unlock(port);
			mach_port_guard_exception(name, 0, kGUARD_EXC_INVALID_RIGHT);
			return KERN_INVALID_CAPABILITY;
		}

		if (!allow_imm_send && ip_is_immovable_send(port)) {
			ip_mq_unlock(port);
			mach_port_guard_exception_immovable(space, name, port);
			return KERN_INVALID_CAPABILITY;
		}

		assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_SEND_ONCE);
		assert(IE_BITS_UREFS(bits) == 1);
		assert(port->ip_sorights > 0);

		request = ipc_right_request_cancel(port, name, entry);
		assert(!ip_is_pinned(port));
		ipc_entry_dealloc(space, ip_to_object(port), name, entry);
		ip_mq_unlock(port);

		*portp = port;
		icc->icc_deleted_port = request;
		break;
	}

	default:
invalid_right:
		return KERN_INVALID_RIGHT;
	}

	return KERN_SUCCESS;

copy_dead:
	assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_DEAD_NAME);
	assert(IE_BITS_UREFS(bits) > 0);
	assert(entry->ie_request == IE_REQ_NONE);
	assert(entry->ie_object == 0);

	if (!deadok) {
		goto invalid_right;
	}

	*portp = IP_DEAD;
	return KERN_SUCCESS;

move_dead:
	assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_DEAD_NAME);
	assert(IE_BITS_UREFS(bits) > 0);
	assert(entry->ie_request == IE_REQ_NONE);
	assert(entry->ie_object == IPC_OBJECT_NULL);

	if (!deadok || IE_BITS_UREFS(bits) < moves) {
		goto invalid_right;
	}

	if (IE_BITS_UREFS(bits) == moves) {
		ipc_entry_dealloc(space, IPC_OBJECT_NULL, name, entry);
	} else {
		/* if urefs are pegged due to overflow, leave them pegged */
		if (IE_BITS_UREFS(bits) < MACH_PORT_UREFS_MAX) {
			entry->ie_bits = bits - moves; /* decrement urefs */
		}
		ipc_entry_modified(space, name, entry);
	}
	*portp = IP_DEAD;
	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_right_copyout
 *	Purpose:
 *		Copyout a capability to a space.
 *		If successful, consumes a ref for the port.
 *
 *		Always succeeds when given a newly-allocated entry,
 *		because user-reference overflow isn't a possibility.
 *
 *		If copying out the port would cause the user-reference
 *		count in the entry to overflow, then the user-reference
 *		count is left pegged to its maximum value and the copyout
 *		succeeds anyway.
 *	Conditions:
 *		The space is write-locked and active.
 *		The port is locked and active.
 *		The port is unlocked; the space isn't.
 *	Returns:
 *		KERN_SUCCESS		Copied out capability.
 */

kern_return_t
ipc_right_copyout(
	ipc_space_t             space,
	ipc_port_t              port,
	mach_msg_type_name_t    msgt_name,
	ipc_object_copyout_flags_t flags,
	mach_port_name_t        name,
	ipc_entry_t             entry,
	mach_msg_guarded_port_descriptor_t *gdesc)
{
	ipc_entry_bits_t bits;
	mach_port_name_t sp_name = MACH_PORT_NULL;
	mach_port_context_t sp_context = 0;

	bits = entry->ie_bits;

	assert(IP_VALID(port));
	assert(ip_active(port));
	assert(entry->ie_port == port);

	if (flags & IPC_OBJECT_COPYOUT_FLAGS_PINNED) {
		assert(!ip_is_pinned(port));
		assert(ip_is_immovable_send(port));
		assert(task_is_immovable(space->is_task));
		assert(task_is_pinned(space->is_task));
		port->ip_pinned = 1;
	}

	switch (msgt_name) {
	case MACH_MSG_TYPE_PORT_SEND_ONCE:

		assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_NONE);
		assert(IE_BITS_UREFS(bits) == 0);
		assert(port->ip_sorights > 0);

		if (port->ip_specialreply) {
			ipc_port_adjust_special_reply_port_locked(port,
			    current_thread()->ith_knote, IPC_PORT_ADJUST_SR_LINK_WORKLOOP, FALSE);
			/* port unlocked on return */
		} else {
			ip_mq_unlock(port);
		}

		entry->ie_bits = bits | (MACH_PORT_TYPE_SEND_ONCE | 1); /* set urefs to 1 */
		ipc_entry_modified(space, name, entry);
		break;

	case MACH_MSG_TYPE_PORT_SEND:
		assert(port->ip_srights > 0);

		if (bits & MACH_PORT_TYPE_SEND) {
			mach_port_urefs_t urefs = IE_BITS_UREFS(bits);

			assert(port->ip_srights > 1);
			assert(urefs > 0);
			assert(urefs <= MACH_PORT_UREFS_MAX);

			if (urefs == MACH_PORT_UREFS_MAX) {
				/*
				 * leave urefs pegged to maximum,
				 * consume send right and ref
				 */

				ip_srights_dec(port);
				ip_mq_unlock(port);
				ip_release_live(port);
				return KERN_SUCCESS;
			}

			/* consume send right and ref */
			ip_srights_dec(port);
			ip_mq_unlock(port);
			ip_release_live(port);
		} else if (bits & MACH_PORT_TYPE_RECEIVE) {
			assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_RECEIVE);
			assert(IE_BITS_UREFS(bits) == 0);

			/* transfer send right to entry, consume ref */
			ip_mq_unlock(port);
			ip_release_live(port);
		} else {
			assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_NONE);
			assert(IE_BITS_UREFS(bits) == 0);

			/* transfer send right and ref to entry */
			ip_mq_unlock(port);

			/* entry is locked holding ref, so can use port */

			ipc_hash_insert(space, ip_to_object(port), name, entry);
		}

		entry->ie_bits = (bits | MACH_PORT_TYPE_SEND) + 1; /* increment urefs */
		ipc_entry_modified(space, name, entry);
		break;

	case MACH_MSG_TYPE_PORT_RECEIVE: {
		ipc_port_t dest;
#if IMPORTANCE_INHERITANCE
		natural_t assertcnt = port->ip_impcount;
#endif /* IMPORTANCE_INHERITANCE */

		assert(port->ip_mscount == 0);
		assert(!ip_in_a_space(port));

		/*
		 * Don't copyout kobjects or kolabels as receive right
		 */
		if (ip_is_kobject(port) || ip_is_kolabeled(port)) {
			panic("ipc_right_copyout: Copyout kobject/kolabel as receive right");
		}

		dest = ip_get_destination(port);

		/* port transitions to IN-SPACE state */
		port->ip_receiver_name = name;
		port->ip_receiver = space;

		struct knote *kn = current_thread()->ith_knote;

		if (gdesc && gdesc->flags & MACH_MSG_GUARD_FLAGS_IMMOVABLE_RECEIVE) {
			assert(port->ip_immovable_receive == 0);
			port->ip_guarded = 1;
			port->ip_strict_guard = 0;
			/* pseudo receive shouldn't set the receive right as immovable in the sender's space */
			if (kn != ITH_KNOTE_PSEUDO) {
				port->ip_immovable_receive = 1;
			}
			port->ip_context = current_thread()->ith_recv_bufs.recv_msg_addr;
			gdesc->u_context = port->ip_context;
			gdesc->flags &= ~MACH_MSG_GUARD_FLAGS_UNGUARDED_ON_SEND;
		}

		if (ip_is_libxpc_connection_port(port)) {
			/*
			 * There are 3 ways to reach here.
			 * 1. A libxpc client successfully sent this receive right to a named service
			 *    and we are copying out in that service's ipc space.
			 * 2. A libxpc client tried doing (1) but failed so we are doing pseudo-receive.
			 * 3. Kernel sent this receive right to a libxpc client as a part of port destroyed notification.
			 *
			 * This flag needs to be set again in all 3 cases as they reset it as part of their flow.
			 */
			port->ip_immovable_receive = 1;
		}

		/* Check if this is a service port */
		if (port->ip_service_port) {
			assert(port->ip_splabel != NULL);
			/*
			 * This flag gets reset during all 3 ways described above for libxpc connection port.
			 * The only difference is launchd acts as an initiator instead of a libxpc client.
			 */
			if (service_port_defense_enabled) {
				port->ip_immovable_receive = 1;
			}

			/* Check if this is a port-destroyed notification to ensure
			 * that initproc doesnt end up with a guarded service port
			 * sent in a regular message
			 */
			if (!ipc_service_port_label_is_pd_notification((ipc_service_port_label_t)port->ip_splabel)) {
				goto skip_sp_check;
			}

			ipc_service_port_label_clear_flag(port->ip_splabel, ISPL_FLAGS_SEND_PD_NOTIFICATION);
#if !(DEVELOPMENT || DEBUG)
			if (get_bsdtask_info(current_task()) != initproc) {
				goto skip_sp_check;
			}
#endif /* !(DEVELOPMENT || DEBUG) */
			ipc_service_port_label_get_attr(port->ip_splabel, &sp_name, &sp_context);
			assert(sp_name != MACH_PORT_NULL);
			/* Verify the port name and restore the guard value, if any */
			if (name != sp_name) {
				panic("Service port name = 0x%x doesnt match the stored launchd port name = 0x%x", name, sp_name);
			}
			if (sp_context) {
				port->ip_guarded = 1;
				port->ip_strict_guard = 1;
				port->ip_context = sp_context;
			}
		}
skip_sp_check:

		assert((bits & MACH_PORT_TYPE_RECEIVE) == 0);
		if (bits & MACH_PORT_TYPE_SEND) {
			assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_SEND);
			assert(IE_BITS_UREFS(bits) > 0);
			assert(port->ip_srights > 0);
		} else {
			assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_NONE);
			assert(IE_BITS_UREFS(bits) == 0);
		}
		entry->ie_bits = bits | MACH_PORT_TYPE_RECEIVE;
		ipc_entry_modified(space, name, entry);

		boolean_t sync_bootstrap_checkin = FALSE;
		if (kn != ITH_KNOTE_PSEUDO && port->ip_sync_bootstrap_checkin) {
			sync_bootstrap_checkin = TRUE;
		}
		if (!ITH_KNOTE_VALID(kn, MACH_MSG_TYPE_PORT_RECEIVE)) {
			kn = NULL;
		}
		ipc_port_adjust_port_locked(port, kn, sync_bootstrap_checkin);
		/* port unlocked */

		if (bits & MACH_PORT_TYPE_SEND) {
			ip_release_live(port);

			/* entry is locked holding ref, so can use port */
			ipc_hash_delete(space, ip_to_object(port), name, entry);
		}

		if (dest != IP_NULL) {
#if IMPORTANCE_INHERITANCE
			/*
			 * Deduct the assertion counts we contributed to
			 * the old destination port.  They've already
			 * been reflected into the task as a result of
			 * getting enqueued.
			 */
			ip_mq_lock(dest);
			ipc_port_impcount_delta(dest, 0 - assertcnt, IP_NULL);
			ip_mq_unlock(dest);
#endif /* IMPORTANCE_INHERITANCE */

			/* Drop turnstile ref on dest */
			ipc_port_send_turnstile_complete(dest);
			/* space lock is held */
			ip_release_safe(dest);
		}
		break;
	}

	default:
		ipc_unreachable("ipc_right_copyout: strange rights");
	}
	return KERN_SUCCESS;
}
