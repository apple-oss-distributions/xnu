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
 *	File:	ipc/ipc_entry.c
 *	Author:	Rich Draves
 *	Date:	1989
 *
 *	Primitive functions to manipulate translation entries.
 */

#include <mach/kern_return.h>
#include <mach/port.h>
#include <kern/assert.h>
#include <kern/sched_prim.h>
#include <kern/zalloc.h>
#include <kern/misc_protos.h>
#include <ipc/port.h>
#include <ipc/ipc_entry.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_object.h>
#include <ipc/ipc_hash.h>
#include <ipc/ipc_port.h>
#include <string.h>
#include <sys/kdebug.h>

KALLOC_ARRAY_TYPE_DEFINE(ipc_entry_table, struct ipc_entry, KT_PRIV_ACCT);

/*
 *	Routine: ipc_entry_table_count_max
 *	Purpose:
 *		returns the maximum number of entries an IPC space
 *		is allowed to contain (the maximum size to which it will grow)
 *	Conditions:
 *		none
 */
unsigned int
ipc_entry_table_count_max(void)
{
	return ipc_entry_table_size_to_count(CONFIG_IPC_TABLE_ENTRIES_SIZE_MAX);
}

/*
 *	Routine:	ipc_entry_lookup
 *	Purpose:
 *		Searches for an entry, given its name.
 *	Conditions:
 *		The space must be read or write locked throughout.
 *		The space must be active.
 */

ipc_entry_t
ipc_entry_lookup(
	ipc_space_t             space,
	mach_port_name_t        name)
{
	mach_port_index_t index;
	ipc_entry_table_t table;
	ipc_entry_t entry;

	table = is_active_table(space);
	index = MACH_PORT_INDEX(name);
	if (__improbable(index == 0)) {
		return IE_NULL;
	}

	entry = ipc_entry_table_get(table, index);
	if (__improbable(!entry ||
	    IE_BITS_GEN(entry->ie_bits) != MACH_PORT_GEN(name) ||
	    IE_BITS_TYPE(entry->ie_bits) == MACH_PORT_TYPE_NONE)) {
		return IE_NULL;
	}

	return entry;
}


/*
 *	Routine:	ipc_entries_hold
 *	Purpose:
 *		Verifies that there are at least 'entries_needed'
 *		free list members
 *	Conditions:
 *		The space is write-locked and active throughout.
 *		An object may be locked.  Will not allocate memory.
 *	Returns:
 *		KERN_SUCCESS		Free entries were found.
 *		KERN_NO_SPACE		No entry allocated.
 */

kern_return_t
ipc_entries_hold(
	ipc_space_t             space,
	uint32_t                entries_needed)
{
	mach_port_index_t next_free = 0;
	ipc_entry_table_t table;
	ipc_entry_t entry;
	uint32_t i;

	/*
	 * Assume that all new entries will need hashing.
	 * If the table is more than 87.5% full pretend we didn't have space.
	 */
	table = is_active_table(space);
	if (space->is_table_hashed + entries_needed >
	    ipc_entry_table_count(table) * 7 / 8) {
		return KERN_NO_SPACE;
	}

	entry = ipc_entry_table_base(table);

	for (i = 0; i < entries_needed; i++) {
		next_free = entry->ie_next;
		if (next_free == 0) {
			return KERN_NO_SPACE;
		}

		entry = ipc_entry_table_get(table, next_free);

		assert(entry && entry->ie_object == IO_NULL);
	}

#if CONFIG_PROC_RESOURCE_LIMITS
	ipc_space_check_limit_exceeded(space);
#endif /* CONFIG_PROC_RESOURCE_LIMITS */
	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_entry_claim
 *	Purpose:
 *		Take formal ownership of a held entry.
 *	Conditions:
 *		The space is write-locked and active throughout.
 *		Objects must be: NULL, locked, or not initialized yet.
 *		Will not allocate memory.
 *
 *      Note: The returned entry must be marked as modified before
 *            releasing the space lock
 */

kern_return_t
ipc_entry_claim(
	ipc_space_t             space,
	ipc_object_t            object,
	mach_port_name_t        *namep,
	ipc_entry_t             *entryp)
{
	ipc_entry_t base, entry;
	ipc_entry_table_t table;
	mach_port_index_t first_free;
	mach_port_gen_t gen;
	mach_port_name_t new_name;

	table = is_active_table(space);
	base  = ipc_entry_table_base(table);

	first_free = base->ie_next;
	assert(first_free != 0);

	entry = ipc_entry_table_get(table, first_free);
	assert(entry &&
	    ipc_entry_table_contains(table, entry->ie_next) &&
	    entry->ie_object == IO_NULL);
	base->ie_next = entry->ie_next;
	space->is_table_free--;

	if (object && waitq_valid(io_waitq(object))) {
		assert(waitq_held(io_waitq(object)));
	}

	/*
	 *	Initialize the new entry: increment gencount and reset
	 *	rollover point if it rolled over, and clear ie_request.
	 */
	gen = ipc_entry_new_gen(entry->ie_bits);
	if (__improbable(ipc_entry_gen_rolled(entry->ie_bits, gen))) {
		ipc_entry_bits_t roll = ipc_space_get_rollpoint(space);
		gen = ipc_entry_new_rollpoint(roll);
	}
	entry->ie_bits = gen;
	entry->ie_request = IE_REQ_NONE;
	entry->ie_object = object;

	/*
	 *	The new name can't be MACH_PORT_NULL because index
	 *	is non-zero.  It can't be MACH_PORT_DEAD because
	 *	the table isn't allowed to grow big enough.
	 *	(See comment in ipc/ipc_table.h.)
	 */
	new_name = MACH_PORT_MAKE(first_free, gen);
	assert(MACH_PORT_VALID(new_name));
	*namep = new_name;
	*entryp = entry;

	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_entry_alloc
 *	Purpose:
 *		Allocate an entry out of the space.
 *	Conditions:
 *		The space is not locked before, but it is write-locked after
 *		if the call is successful.  May allocate memory.
 *	Returns:
 *		KERN_SUCCESS		An entry was allocated.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_NO_SPACE		No room for an entry in the space.
 *		KERN_RESOURCE_SHORTAGE	Couldn't allocate memory for an entry.
 */

kern_return_t
ipc_entry_alloc(
	ipc_space_t             space,
	ipc_object_t            object,
	mach_port_name_t        *namep,
	ipc_entry_t             *entryp)
{
	kern_return_t kr;

	is_write_lock(space);

	for (;;) {
		if (!is_active(space)) {
			is_write_unlock(space);
			return KERN_INVALID_TASK;
		}

		kr = ipc_entries_hold(space, 1);
		if (kr == KERN_SUCCESS) {
			return ipc_entry_claim(space, object, namep, entryp);
		}

		kr = ipc_entry_grow_table(space, ITS_SIZE_NONE);
		if (kr != KERN_SUCCESS) {
			return kr; /* space is unlocked */
		}
	}
}

/*
 *	Routine:	ipc_entry_alloc_name
 *	Purpose:
 *		Allocates/finds an entry with a specific name.
 *		If an existing entry is returned, its type will be nonzero.
 *	Conditions:
 *		The space is not locked before, but it is write-locked after
 *		if the call is successful.  May allocate memory.
 *	Returns:
 *		KERN_SUCCESS		Found existing entry with same name.
 *		KERN_SUCCESS		Allocated a new entry.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_RESOURCE_SHORTAGE	Couldn't allocate memory.
 *		KERN_FAILURE		Couldn't allocate requested name.
 *      KERN_INVALID_VALUE  Supplied port name is invalid.
 */

kern_return_t
ipc_entry_alloc_name(
	ipc_space_t             space,
	mach_port_name_t        name,
	ipc_entry_t             *entryp)
{
	const mach_port_index_t index = MACH_PORT_INDEX(name);
	mach_port_gen_t gen = MACH_PORT_GEN(name);

	/*
	 * Callers today never pass MACH_PORT_NULL
	 */
	assert(MACH_PORT_VALID(name));

	if (index > ipc_entry_table_count_max()) {
		return KERN_NO_SPACE;
	}
	if (name != ipc_entry_name_mask(name)) {
		/* must have valid generation bits */
		return KERN_INVALID_VALUE;
	}
	if (index == 0) {
		return KERN_FAILURE;
	}

	is_write_lock(space);

	for (;;) {
		ipc_entry_table_t table;
		ipc_entry_t entry;

		if (!is_active(space)) {
			is_write_unlock(space);
			return KERN_INVALID_TASK;
		}

		table = is_active_table(space);

		/*
		 *	If we are under the table cutoff,
		 *	there are usually four cases:
		 *		1) The entry is reserved (index 0)
		 *		   dealt with on entry.
		 *		2) The entry is free
		 *		3) The entry is inuse, for the same name
		 *		4) The entry is inuse, for a different name
		 *
		 *	For a task with a "fast" IPC space, we disallow
		 *	cases 1) and 4), because ports cannot be renamed.
		 */

		entry = ipc_entry_table_get(table, index);
		if (!entry) {
			/*
			 *      We grow the table so that the name
			 *	index fits in the array space.
			 *      Because the space will be unlocked,
			 *      we must restart.
			 */
			kern_return_t kr;
			kr = ipc_entry_grow_table(space, index + 1);
			if (kr != KERN_SUCCESS) {
				/* space is unlocked */
				return kr;
			}
			continue;
		}

		if (!IE_BITS_TYPE(entry->ie_bits)) {
			mach_port_index_t prev_index;
			ipc_entry_t prev_entry;

			/*
			 *      case #2 -- the entry is free
			 *	Rip the entry out of the free list.
			 */

			prev_index = 0;
			prev_entry = ipc_entry_table_base(table);
			while (prev_entry->ie_next != index) {
				prev_index = prev_entry->ie_next;
				prev_entry = ipc_entry_table_get(table, prev_index);
			}

			prev_entry->ie_next = entry->ie_next;
			space->is_table_free--;

			/*
			 *	prev_index can be 0 here if the desired index
			 *	happens to be at the top of the freelist.
			 *
			 *	Mark the previous entry modified -
			 *	reconstructing the name.
			 *
			 *	Do not do so for the first entry, which is
			 *	reserved and ipc_entry_grow_table() will handle
			 *	its ie_next separately after the rescan loop.
			 */
			if (prev_index > 0) {
				/*
				 */
				ipc_entry_modified(space,
				    MACH_PORT_MAKE(prev_index,
				    IE_BITS_GEN(prev_entry->ie_bits)),
				    prev_entry);
			}

			entry->ie_bits = gen;
			entry->ie_request = IE_REQ_NONE;
			*entryp = entry;

			assert(entry->ie_object == IO_NULL);
			return KERN_SUCCESS;
		} else if (IE_BITS_GEN(entry->ie_bits) == gen) {
			/* case #3 -- the entry is inuse, for the same name */
			*entryp = entry;
			return KERN_SUCCESS;
		} else {
			/* case #4 -- the entry is inuse, for a different name. */
			/* Collisions are not allowed */
			is_write_unlock(space);
			return KERN_FAILURE;
		}
	}
}

/*
 *	Routine:	ipc_entry_dealloc
 *	Purpose:
 *		Deallocates an entry from a space.
 *	Conditions:
 *		The space must be write-locked throughout.
 *		The space must be active.
 */

void
ipc_entry_dealloc(
	ipc_space_t             space,
	ipc_object_t            object,
	mach_port_name_t        name,
	ipc_entry_t             entry)
{
	ipc_entry_table_t table;
	mach_port_index_t index;
	ipc_entry_t base;

	assert(entry->ie_object == object);
	assert(entry->ie_request == IE_REQ_NONE);
	if (object) {
		io_lock_held(object);
	}

#if 1
	if (entry->ie_request != IE_REQ_NONE) {
		panic("ipc_entry_dealloc()");
	}
#endif

	index = MACH_PORT_INDEX(name);
	table = is_active_table(space);
	base  = ipc_entry_table_base(table);

	assert(index > 0 && entry == ipc_entry_table_get(table, index));

	assert(IE_BITS_GEN(entry->ie_bits) == MACH_PORT_GEN(name));
	entry->ie_bits &= (IE_BITS_GEN_MASK | IE_BITS_ROLL_MASK);
	entry->ie_next = base->ie_next;
	entry->ie_object = IO_NULL;
	base->ie_next = index;
	space->is_table_free++;

	ipc_entry_modified(space, name, entry);
}

/*
 *	Routine:	ipc_entry_modified
 *	Purpose:
 *		Note that an entry was modified in a space.
 *	Conditions:
 *		Assumes exclusive write access to the space,
 *		either through a write lock or being the cleaner
 *		on an inactive space.
 */

void
ipc_entry_modified(
	ipc_space_t             space,
	mach_port_name_t        name,
	__assert_only ipc_entry_t entry)
{
	ipc_entry_table_t table;
	mach_port_index_t index;

	index = MACH_PORT_INDEX(name);
	table = is_active_table(space);

	assert(entry == ipc_entry_table_get(table, index));
	assert(space->is_low_mod <= ipc_entry_table_count(table));
	assert(space->is_high_mod < ipc_entry_table_count(table));

	if (index < space->is_low_mod) {
		space->is_low_mod = index;
	}
	if (index > space->is_high_mod) {
		space->is_high_mod = index;
	}

	KERNEL_DEBUG_CONSTANT(
		MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_PORT_ENTRY_MODIFY) | DBG_FUNC_NONE,
		space->is_task ? task_pid(space->is_task) : 0,
		name,
		entry->ie_bits,
		0,
		0);
}

#define IPC_ENTRY_GROW_STATS 1
#if IPC_ENTRY_GROW_STATS
static uint64_t ipc_entry_grow_count = 0;
static uint64_t ipc_entry_grow_rescan = 0;
static uint64_t ipc_entry_grow_rescan_max = 0;
static uint64_t ipc_entry_grow_rescan_entries = 0;
static uint64_t ipc_entry_grow_rescan_entries_max = 0;
static uint64_t ipc_entry_grow_freelist_entries = 0;
static uint64_t ipc_entry_grow_freelist_entries_max = 0;
#endif

static inline void
ipc_space_start_growing(ipc_space_t is)
{
	assert(!is_growing(is));
	is->is_grower = current_thread();
}

static void
ipc_space_done_growing_and_unlock(ipc_space_t space)
{
	assert(space->is_grower == current_thread());
	space->is_grower = THREAD_NULL;
	is_write_unlock(space);
	wakeup_all_with_inheritor((event_t)space, THREAD_AWAKENED);
}

/*
 *	Routine:	ipc_entry_grow_table
 *	Purpose:
 *		Grows the table in a space.
 *	Conditions:
 *		The space must be write-locked and active before.
 *		If successful, the space is also returned locked.
 *		On failure, the space is returned unlocked.
 *		Allocates memory.
 *	Returns:
 *		KERN_SUCCESS		Grew the table.
 *		KERN_SUCCESS		Somebody else grew the table.
 *		KERN_SUCCESS		The space died.
 *		KERN_NO_SPACE		Table has maximum size already.
 *		KERN_RESOURCE_SHORTAGE	Couldn't allocate a new table.
 */

kern_return_t
ipc_entry_grow_table(
	ipc_space_t             space,
	ipc_table_elems_t       target_count)
{
	ipc_entry_num_t osize, nsize;
	ipc_entry_num_t ocount, ncount;
	ipc_entry_table_t otable, ntable;
	ipc_entry_t obase, nbase;
	mach_port_index_t free_index;
	mach_port_index_t low_mod, hi_mod;
	ipc_table_index_t sanity;
#if IPC_ENTRY_GROW_STATS
	uint64_t rescan_count = 0;
#endif

	if (is_growing(space)) {
		/*
		 *	Somebody else is growing the table.
		 *	We just wait for them to finish.
		 */
		is_write_sleep(space);
		return KERN_SUCCESS;
	}

	otable = is_active_table(space);
	obase  = ipc_entry_table_base(otable);
	osize  = ipc_entry_table_size(otable);
	ocount = ipc_entry_table_size_to_count(osize);

	if (target_count == ITS_SIZE_NONE) {
		nsize = ipc_entry_table_next_size(IPC_ENTRY_TABLE_MIN, osize,
		    IPC_ENTRY_TABLE_PERIOD);
	} else if (target_count <= ocount) {
		return KERN_SUCCESS;
	} else if (target_count > ipc_entry_table_count_max()) {
		goto no_space;
	} else {
		uint32_t tsize = ipc_entry_table_count_to_size(target_count);

		nsize = ipc_entry_table_next_size(IPC_ENTRY_TABLE_MIN, tsize,
		    IPC_ENTRY_TABLE_PERIOD);
	}
	if (nsize > CONFIG_IPC_TABLE_ENTRIES_SIZE_MAX) {
		nsize = CONFIG_IPC_TABLE_ENTRIES_SIZE_MAX;
	}
	if (osize == nsize) {
		goto no_space;
	}


	/*
	 * We'll attempt to grow the table.
	 *
	 * Because we will be copying without the space lock, reset
	 * the lowest_mod index to just beyond the end of the current
	 * table.  Modification of entries (other than hashes) will
	 * bump this downward, and we only have to reprocess entries
	 * above that mark.  Eventually, we'll get done.
	 */
	ipc_space_start_growing(space);
	space->is_low_mod = ocount;
	space->is_high_mod = 0;
#if IPC_ENTRY_GROW_STATS
	ipc_entry_grow_count++;
#endif
	is_write_unlock(space);

	ntable = ipc_entry_table_alloc_by_size(nsize, Z_WAITOK | Z_ZERO);
	if (ntable == NULL) {
		is_write_lock(space);
		ipc_space_done_growing_and_unlock(space);
		return KERN_RESOURCE_SHORTAGE;
	}

	nbase  = ipc_entry_table_base(ntable);
	nsize  = ipc_entry_table_size(ntable);
	ncount = ipc_entry_table_count(ntable);
	ipc_space_rand_freelist(space, nbase, ocount, ncount);

	low_mod = 1;
	hi_mod = ocount - 1;
rescan:
	/*
	 * Within the range of the table that changed, determine what we
	 * have to take action on. For each entry, take a snapshot of the
	 * corresponding entry in the old table (so it won't change
	 * during this iteration). The snapshot may not be self-consistent
	 * (if we caught it in the middle of being changed), so be very
	 * cautious with the values.
	 */
	assert(low_mod > 0);
	for (mach_port_index_t i = MAX(1, low_mod); i <= hi_mod; i++) {
		ipc_entry_t entry = &nbase[i];
		ipc_object_t osnap_object = obase[i].ie_object;
		ipc_entry_bits_t osnap_bits = obase[i].ie_bits;
		ipc_entry_bits_t osnap_request = obase[i].ie_request;

		/*
		 * We need to make sure the osnap_* fields are never reloaded.
		 */
		os_compiler_barrier();

		if (entry->ie_object != osnap_object ||
		    IE_BITS_TYPE(entry->ie_bits) != IE_BITS_TYPE(osnap_bits)) {
			if (entry->ie_object != IO_NULL &&
			    IE_BITS_TYPE(entry->ie_bits) == MACH_PORT_TYPE_SEND) {
				ipc_hash_table_delete(ntable, entry->ie_object, i, entry);
			}

			entry->ie_object = osnap_object;
			entry->ie_bits = osnap_bits;
			entry->ie_request = osnap_request; /* or ie_next */

			if (osnap_object != IO_NULL &&
			    IE_BITS_TYPE(osnap_bits) == MACH_PORT_TYPE_SEND) {
				ipc_hash_table_insert(ntable, osnap_object, i, entry);
			}
		} else {
			entry->ie_bits = osnap_bits;
			entry->ie_request = osnap_request; /* or ie_next */
		}
	}
	nbase[0].ie_next = obase[0].ie_next;  /* always rebase the freelist */

	/*
	 * find the end of the freelist (should be short). But be careful,
	 * the list items can change so only follow through truly free entries
	 * (no problem stopping short in those cases, because we'll rescan).
	 */
	free_index = 0;
	for (sanity = 0; sanity < ocount; sanity++) {
		if (nbase[free_index].ie_object != IPC_OBJECT_NULL) {
			break;
		}
		mach_port_index_t i = nbase[free_index].ie_next;
		if (i == 0 || i >= ocount) {
			break;
		}
		free_index = i;
	}
#if IPC_ENTRY_GROW_STATS
	ipc_entry_grow_freelist_entries += sanity;
	if (sanity > ipc_entry_grow_freelist_entries_max) {
		ipc_entry_grow_freelist_entries_max = sanity;
	}
#endif

	is_write_lock(space);

	/*
	 *	We need to do a wakeup on the space,
	 *	to rouse waiting threads.  We defer
	 *	this until the space is unlocked,
	 *	because we don't want them to spin.
	 */

	if (!is_active(space)) {
		/*
		 *	The space died while it was unlocked.
		 */

		ipc_space_done_growing_and_unlock(space);
		ipc_entry_table_free(&ntable);
		is_write_lock(space);
		return KERN_SUCCESS;
	}

	/* If the space changed while unlocked, go back and process the changes */
	if (space->is_low_mod < ocount) {
		assert(space->is_high_mod > 0);
		low_mod = space->is_low_mod;
		space->is_low_mod = ocount;
		hi_mod = space->is_high_mod;
		space->is_high_mod = 0;
		is_write_unlock(space);

		if (hi_mod >= ocount) {
			panic("corrupt hi_mod: %d, obase: %p, ocount: %d\n",
			    hi_mod, obase, ocount);
		}

#if IPC_ENTRY_GROW_STATS
		rescan_count++;
		if (rescan_count > ipc_entry_grow_rescan_max) {
			ipc_entry_grow_rescan_max = rescan_count;
		}

		ipc_entry_grow_rescan++;
		ipc_entry_grow_rescan_entries += hi_mod - low_mod + 1;
		if (hi_mod - low_mod + 1 > ipc_entry_grow_rescan_entries_max) {
			ipc_entry_grow_rescan_entries_max = hi_mod - low_mod + 1;
		}
#endif
		goto rescan;
	}

	/* link new free entries onto the rest of the freelist */
	assert(nbase[free_index].ie_next == 0 &&
	    nbase[free_index].ie_object == IO_NULL);
	nbase[free_index].ie_next = ocount;

	assert(smr_serialized_load(&space->is_table) == otable);

	space->is_table_free += ncount - ocount;
	smr_serialized_store(&space->is_table, ntable);

	ipc_space_done_growing_and_unlock(space);

	/*
	 *	Now we need to free the old table.
	 */
	ipc_space_retire_table(otable);
	is_write_lock(space);

	return KERN_SUCCESS;

no_space:
	ipc_space_set_at_max_limit(space);
	is_write_unlock(space);
	return KERN_NO_SPACE;
}


/*
 *	Routine:	ipc_entry_name_mask
 *	Purpose:
 *		Ensure a mach port name has the default ipc entry
 *		generation bits set. This can be used to ensure that
 *		a name passed in by user space matches names generated
 *		by the kernel.
 *	Conditions:
 *		None.
 *	Returns:
 *		'name' input with default generation bits masked or added
 *		as appropriate.
 */
mach_port_name_t
ipc_entry_name_mask(mach_port_name_t name)
{
#ifndef NO_PORT_GEN
	static mach_port_name_t null_name = MACH_PORT_MAKE(0, IE_BITS_GEN_MASK + IE_BITS_GEN_ONE);
	return name | null_name;
#else
	static mach_port_name_t null_name = MACH_PORT_MAKE(0, ~(IE_BITS_GEN_MASK + IE_BITS_GEN_ONE));
	return name & ~null_name;
#endif
}
