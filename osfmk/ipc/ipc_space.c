/*
 * Copyright (c) 2000-2020 Apple Computer, Inc. All rights reserved.
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
 */
/*
 */
/*
 *	File:	ipc/ipc_space.c
 *	Author:	Rich Draves
 *	Date:	1989
 *
 *	Functions to manipulate IPC capability spaces.
 */

#include <mach/boolean.h>
#include <mach/kern_return.h>
#include <mach/port.h>
#include <kern/assert.h>
#include <kern/sched_prim.h>
#include <kern/zalloc.h>
#include <ipc/port.h>
#include <ipc/ipc_entry.h>
#include <ipc/ipc_object.h>
#include <ipc/ipc_hash.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_right.h>
#include <prng/random.h>
#include <string.h>

/* Remove this in the future so port names are less predictable. */
#define CONFIG_SEMI_RANDOM_ENTRIES
#ifdef CONFIG_SEMI_RANDOM_ENTRIES
#define NUM_SEQ_ENTRIES 8
#endif

os_refgrp_decl(static, is_refgrp, "is", NULL);
static ZONE_DEFINE_TYPE(ipc_space_zone, "ipc spaces",
    struct ipc_space, ZC_ZFREE_CLEARMEM);

SECURITY_READ_ONLY_LATE(ipc_space_t) ipc_space_kernel;
SECURITY_READ_ONLY_LATE(ipc_space_t) ipc_space_reply;

static ipc_space_t
ipc_space_alloc(void)
{
	ipc_space_t space;

	space = zalloc_flags(ipc_space_zone, Z_WAITOK | Z_ZERO | Z_NOFAIL);
	lck_ticket_init(&space->is_lock, &ipc_lck_grp);

	return space;
}

__attribute__((noinline))
static void
ipc_space_free(ipc_space_t space)
{
	assert(!is_active(space));
	lck_ticket_destroy(&space->is_lock, &ipc_lck_grp);
	zfree(ipc_space_zone, space);
}

static void
ipc_space_free_table(smr_node_t node)
{
	ipc_entry_t entry = __container_of(node, struct ipc_entry, ie_smr_node);
	ipc_entry_table_t table = entry->ie_self;

	ipc_entry_table_free_noclear(table);
}

void
ipc_space_retire_table(ipc_entry_table_t table)
{
	ipc_entry_t base;
	vm_size_t size;

	base = ipc_entry_table_base(table);
	size = ipc_entry_table_size(table);
	base->ie_self = table;
	smr_ipc_call(&base->ie_smr_node, size, ipc_space_free_table);
}

void
ipc_space_reference(
	ipc_space_t     space)
{
	os_ref_retain_mask(&space->is_bits, IS_FLAGS_BITS, &is_refgrp);
}

void
ipc_space_release(
	ipc_space_t     space)
{
	if (os_ref_release_mask(&space->is_bits, IS_FLAGS_BITS, &is_refgrp) == 0) {
		ipc_space_free(space);
	}
}

void
ipc_space_lock(
	ipc_space_t     space)
{
	lck_ticket_lock(&space->is_lock, &ipc_lck_grp);
}

void
ipc_space_unlock(
	ipc_space_t     space)
{
	lck_ticket_unlock(&space->is_lock);
}

void
ipc_space_lock_sleep(
	ipc_space_t     space)
{
	lck_ticket_sleep_with_inheritor(&space->is_lock, &ipc_lck_grp,
	    LCK_SLEEP_DEFAULT, (event_t)space, space->is_grower,
	    THREAD_UNINT, TIMEOUT_WAIT_FOREVER);
}

/*      Routine:		ipc_space_get_rollpoint
 *      Purpose:
 *              Generate a new gencount rollover point from a space's entropy pool
 */
ipc_entry_bits_t
ipc_space_get_rollpoint(
	ipc_space_t     space)
{
	return random_bool_gen_bits(
		&space->bool_gen,
		&space->is_entropy[0],
		IS_ENTROPY_CNT,
		IE_BITS_ROLL_BITS);
}

/*
 *	Routine:	ipc_entry_rand_freelist
 *	Purpose:
 *		Pseudo-randomly permute the order of entries in an IPC space
 *	Arguments:
 *		space:	the ipc space to initialize.
 *		table:	the corresponding ipc table to initialize.
 *			the table is 0 initialized.
 *		bottom:	the start of the range to initialize (inclusive).
 *		top:	the end of the range to initialize (noninclusive).
 */
void
ipc_space_rand_freelist(
	ipc_space_t             space,
	ipc_entry_t             table,
	mach_port_index_t       bottom,
	mach_port_index_t       size)
{
	int at_start = (bottom == 0);
#ifdef CONFIG_SEMI_RANDOM_ENTRIES
	/*
	 * Only make sequential entries at the start of the table, and not when
	 * we're growing the space.
	 */
	ipc_entry_num_t total = 0;
#endif

	/* First entry in the free list is always free, and is the start of the free list. */
	mach_port_index_t curr = bottom;
	mach_port_index_t top = size;

	bottom++;
	top--;

	/*
	 *	Initialize the free list in the table.
	 *	Add the entries in pseudo-random order and randomly set the generation
	 *	number, in order to frustrate attacks involving port name reuse.
	 */
	while (bottom <= top) {
		ipc_entry_t entry = &table[curr];
		int which;
#ifdef CONFIG_SEMI_RANDOM_ENTRIES
		/*
		 * XXX: This is a horrible hack to make sure that randomizing the port
		 * doesn't break programs that might have (sad) hard-coded values for
		 * certain port names.
		 */
		if (at_start && total++ < NUM_SEQ_ENTRIES) {
			which = 0;
		} else
#endif
		which = random_bool_gen_bits(
			&space->bool_gen,
			&space->is_entropy[0],
			IS_ENTROPY_CNT,
			1);

		mach_port_index_t next;
		if (which) {
			next = top;
			top--;
		} else {
			next = bottom;
			bottom++;
		}

		/*
		 * The entry's gencount will roll over on its first allocation, at which
		 * point a random rollover will be set for the entry.
		 */
		entry->ie_bits   = IE_BITS_GEN_MASK;
		entry->ie_next   = next;
		curr = next;
	}
	table[curr].ie_bits   = IE_BITS_GEN_MASK;
}


/*
 *	Routine:	ipc_space_create
 *	Purpose:
 *		Creates a new IPC space.
 *
 *		The new space has two references, one for the caller
 *		and one because it is active.
 *	Conditions:
 *		Nothing locked.  Allocates memory.
 *	Returns:
 *		KERN_SUCCESS		Created a space.
 *		KERN_RESOURCE_SHORTAGE	Couldn't allocate memory.
 */

kern_return_t
ipc_space_create(
	ipc_label_t             label,
	ipc_space_t             *spacep)
{
	ipc_space_t space;
	ipc_entry_table_t table;
	ipc_entry_num_t count;

	table = ipc_entry_table_alloc_by_count(IPC_ENTRY_TABLE_MIN,
	    Z_WAITOK | Z_ZERO | Z_NOFAIL);
	space = ipc_space_alloc();
	count = ipc_entry_table_count(table);

	random_bool_init(&space->bool_gen);
	ipc_space_rand_freelist(space, ipc_entry_table_base(table), 0, count);

	os_ref_init_count_mask(&space->is_bits, IS_FLAGS_BITS, &is_refgrp, 2, 0);
	space->is_table_free = count - 1;
	space->is_label = label;
	space->is_low_mod = count;
	space->is_node_id = HOST_LOCAL_NODE; /* HOST_LOCAL_NODE, except proxy spaces */
	smr_init_store(&space->is_table, table);

	*spacep = space;
	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_space_label
 *	Purpose:
 *		Modify the label on a space. The desired
 *      label must be a super-set of the current
 *      label for the space (as rights may already
 *      have been previously copied out under the
 *      old label value.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		Updated the label
 *		KERN_INVALID_VALUE  label not a superset of old
 */
kern_return_t
ipc_space_label(
	ipc_space_t space,
	ipc_label_t label)
{
	is_write_lock(space);
	if (!is_active(space)) {
		is_write_unlock(space);
		return KERN_SUCCESS;
	}

	if ((space->is_label & label) != space->is_label) {
		is_write_unlock(space);
		return KERN_INVALID_VALUE;
	}
	space->is_label = label;
	is_write_unlock(space);
	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_space_add_label
 *	Purpose:
 *		Modify the label on a space. The desired
 *      label is added to the labels already set
 *      on the space.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		Updated the label
 *		KERN_INVALID_VALUE  label not a superset of old
 */
kern_return_t
ipc_space_add_label(
	ipc_space_t space,
	ipc_label_t label)
{
	is_write_lock(space);
	if (!is_active(space)) {
		is_write_unlock(space);
		return KERN_SUCCESS;
	}

	space->is_label |= label;
	is_write_unlock(space);
	return KERN_SUCCESS;
}
/*
 *	Routine:	ipc_space_create_special
 *	Purpose:
 *		Create a special space.  A special space
 *		doesn't hold rights in the normal way.
 *		Instead it is place-holder for holding
 *		disembodied (naked) receive rights.
 *		See ipc_port_alloc_special/ipc_port_dealloc_special.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		Created a space.
 *		KERN_RESOURCE_SHORTAGE	Couldn't allocate memory.
 */

kern_return_t
ipc_space_create_special(
	ipc_space_t     *spacep)
{
	ipc_space_t space;

	space = ipc_space_alloc();
	os_ref_init_count_mask(&space->is_bits, IS_FLAGS_BITS, &is_refgrp, 1, 0);
	space->is_label      = IPC_LABEL_SPECIAL;
	space->is_node_id = HOST_LOCAL_NODE; /* HOST_LOCAL_NODE, except proxy spaces */

	*spacep = space;
	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_space_terminate
 *	Purpose:
 *		Marks the space as dead and cleans up the entries.
 *		Does nothing if the space is already dead.
 *	Conditions:
 *		Nothing locked.
 */

void
ipc_space_terminate(
	ipc_space_t     space)
{
	ipc_entry_table_t table;

	assert(space != IS_NULL);

	is_write_lock(space);
	if (!is_active(space)) {
		is_write_unlock(space);
		return;
	}

	table = smr_serialized_load(&space->is_table);
	smr_clear_store(&space->is_table);

	/*
	 *	If somebody is trying to grow the table,
	 *	we must wait until they finish and figure
	 *	out the space died.
	 */
	while (is_growing(space)) {
		is_write_sleep(space);
	}

	is_write_unlock(space);


	/*
	 *	Now we can futz with it	unlocked.
	 *
	 *	First destroy receive rights, then the rest.
	 *	This will cut down the number of notifications
	 *	being sent when the notification destination
	 *	was a receive right in this space.
	 */

	for (mach_port_index_t index = 1;
	    ipc_entry_table_contains(table, index);
	    index++) {
		ipc_entry_t entry = ipc_entry_table_get_nocheck(table, index);
		mach_port_type_t type;

		type = IE_BITS_TYPE(entry->ie_bits);
		if (type != MACH_PORT_TYPE_NONE) {
			mach_port_name_t name;

			name = MACH_PORT_MAKE(index,
			    IE_BITS_GEN(entry->ie_bits));
			ipc_right_terminate(space, name, entry);
		}
	}

	ipc_space_retire_table(table);
	space->is_table_free = 0;

	/*
	 *	Because the space is now dead,
	 *	we must release the "active" reference for it.
	 *	Our caller still has his reference.
	 */
	is_release(space);
}

#if CONFIG_PROC_RESOURCE_LIMITS
/*
 *	ipc_space_set_table_size_limits:
 *
 *	Set the table size's soft and hard limit.
 */
kern_return_t
ipc_space_set_table_size_limits(
	ipc_space_t     space,
	ipc_entry_num_t soft_limit,
	ipc_entry_num_t hard_limit)
{
	if (space == IS_NULL) {
		return KERN_INVALID_TASK;
	}

	is_write_lock(space);

	if (!is_active(space)) {
		is_write_unlock(space);
		return KERN_INVALID_TASK;
	}

	if (hard_limit && soft_limit >= hard_limit) {
		soft_limit = 0;
	}

	space->is_table_size_soft_limit = soft_limit;
	space->is_table_size_hard_limit = hard_limit;

	is_write_unlock(space);

	return KERN_SUCCESS;
}

/*
 * Check if port space has exceeded its limits.
 * Should be called with the space write lock held.
 */
void
ipc_space_check_limit_exceeded(ipc_space_t space)
{
	size_t size = ipc_entry_table_count(is_active_table(space));

	if (!is_above_soft_limit_notify(space) && space->is_table_size_soft_limit &&
	    ((size - space->is_table_free) > space->is_table_size_soft_limit)) {
		is_above_soft_limit_send_notification(space);
		act_set_astproc_resource(current_thread());
	} else if (!is_above_hard_limit_notify(space) && space->is_table_size_hard_limit &&
	    ((size - space->is_table_free) > space->is_table_size_hard_limit)) {
		is_above_hard_limit_send_notification(space);
		act_set_astproc_resource(current_thread());
	}
}
#endif /* CONFIG_PROC_RESOURCE_LIMITS */

kern_return_t
ipc_space_get_table_size_and_limits(
	ipc_space_t     space,
	ipc_entry_num_t *current_size,
	ipc_entry_num_t *soft_limit,
	ipc_entry_num_t *hard_limit)
{
	kern_return_t kr = KERN_SUCCESS;
	ipc_entry_table_t table;

	if (space == IS_NULL) {
		return KERN_INVALID_TASK;
	}

	is_write_lock(space);

	if (!is_active(space)) {
		kr = KERN_INVALID_TASK;
		goto exit;
	}

	table = is_active_table(space);
	*current_size = ipc_entry_table_count(table) - space->is_table_free;
	if (is_at_max_limit_notify(space)) {
		if (is_at_max_limit_already_notified(space)) {
			kr = KERN_FAILURE;
		} else {
			*soft_limit = 0;
			*hard_limit = 0;
			is_at_max_limit_notified(space);
		}
		goto exit;
	}

#if CONFIG_PROC_RESOURCE_LIMITS
	*soft_limit = space->is_table_size_soft_limit;
	*hard_limit = space->is_table_size_hard_limit;

	if (!*soft_limit && !*hard_limit) {
		kr = KERN_INVALID_VALUE;
		goto exit;
	}

	/*
	 * Check if the thread sending the soft limit notification arrives after
	 * the one that sent the hard limit notification
	 */
	if (is_hard_limit_already_notified(space)) {
		kr = KERN_FAILURE;
		goto exit;
	}

	if (*hard_limit > 0 && *current_size >= *hard_limit) {
		*soft_limit = 0;
		is_hard_limit_notified(space);
	} else {
		if (is_soft_limit_already_notified(space)) {
			kr = KERN_FAILURE;
			goto exit;
		}
		if (*soft_limit > 0 && *current_size >= *soft_limit) {
			*hard_limit = 0;
			is_soft_limit_notified(space);
		}
	}
#endif /* CONFIG_PROC_RESOURCE_LIMITS */

exit:
	is_write_unlock(space);
	return kr;
}

/*
 * Set an ast if port space is at its max limit.
 * Should be called with the space write lock held.
 */
void
ipc_space_set_at_max_limit(ipc_space_t space)
{
	if (!is_at_max_limit_notify(space)) {
		is_at_max_limit_send_notification(space);
		act_set_astproc_resource(current_thread());
	}
}
