/*
 * Copyright (c) 2000-2016 Apple Computer, Inc. All rights reserved.
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
 *	File:	ipc/ipc_space.h
 *	Author:	Rich Draves
 *	Date:	1989
 *
 *	Definitions for IPC spaces of capabilities.
 */

#ifndef _IPC_IPC_SPACE_H_
#define _IPC_IPC_SPACE_H_


#include <prng/random.h>
#include <mach/mach_types.h>
#include <mach/boolean.h>
#include <mach/kern_return.h>
#include <mach/vm_types.h>

#include <sys/appleapiopts.h>

#ifdef __APPLE_API_PRIVATE
#ifdef MACH_KERNEL_PRIVATE
#include <kern/macro_help.h>
#include <kern/kern_types.h>
#include <kern/hazard.h>
#include <kern/locks.h>
#include <kern/task.h>
#include <kern/zalloc.h>
#include <ipc/ipc_entry.h>
#include <ipc/ipc_types.h>

#include <os/refcnt.h>

/*
 *	Every task has a space of IPC capabilities.
 *	IPC operations like send and receive use this space.
 *	IPC kernel calls manipulate the space of the target task.
 *
 *	Every space has a non-NULL is_table with is_table[0].ie_size entries.
 *
 *	Only one thread can be growing the space at a time.  Others
 *	that need it grown wait for the first.  We do almost all the
 *	work with the space unlocked, so lookups proceed pretty much
 *	unaffected while the grow operation is underway.
 */

typedef natural_t ipc_space_refs_t;
#define IS_ENTROPY_CNT                 1        /* per-space entropy pool size */

#define IS_FLAGS_BITS                  6
#if CONFIG_PROC_RESOURCE_LIMITS
#define IS_ABOVE_SOFT_LIMIT_NOTIFY     0x01     /* space has hit the soft limit */
#define IS_ABOVE_HARD_LIMIT_NOTIFY     0x02     /* space has hit the hard limit */
#define IS_SOFT_LIMIT_NOTIFIED         0x04     /* Sent soft limit notification */
#define IS_HARD_LIMIT_NOTIFIED         0x08     /* Sent hard limit notification */
#endif /* CONFIG_PROC_RESOURCE_LIMITS */
#define IS_AT_MAX_LIMIT_NOTIFY         0x10     /* space has hit the max limit */
#define IS_AT_MAX_LIMIT_NOTIFIED       0x20     /* sent max limit notification */

struct ipc_space {
	lck_ticket_t    is_lock;
	os_ref_atomic_t is_bits;        /* holds refs, active, growing */
	ipc_entry_num_t is_table_hashed;/* count of hashed elements */
	ipc_entry_num_t is_table_free;  /* count of free elements */
	HAZARD_POINTER(ipc_entry_t XNU_PTRAUTH_SIGNED_PTR("ipc_space.is_table")) is_table; /* an array of entries */
	struct ipc_table_size * XNU_PTRAUTH_SIGNED_PTR("ipc_space.is_table_next") is_table_next; /* info for larger table */
	task_t XNU_PTRAUTH_SIGNED_PTR("ipc_space.is_task") is_task; /* associated task */
	thread_t        is_grower;      /* thread growing the space */
	ipc_label_t     is_label;       /* [private] mandatory access label */
	ipc_entry_num_t is_low_mod;     /* lowest modified entry during growth */
	ipc_entry_num_t is_high_mod;    /* highest modified entry during growth */
	struct bool_gen bool_gen;       /* state for boolean RNG */
	unsigned int    is_entropy[IS_ENTROPY_CNT]; /* pool of entropy taken from RNG */
	int             is_node_id;     /* HOST_LOCAL_NODE, or remote node if proxy space */
#if CONFIG_PROC_RESOURCE_LIMITS
	ipc_entry_num_t is_table_size_soft_limit; /* resource_notify is sent when the table size hits this limit */
	ipc_entry_num_t is_table_size_hard_limit; /* same as soft limit except the task is killed soon after data collection */
#endif /* CONFIG_PROC_RESOURCE_LIMITS */
};

#define IS_NULL                 ((ipc_space_t) 0)
#define IS_INSPECT_NULL         ((ipc_space_inspect_t) 0)

static inline bool
is_bits_set(ipc_space_t is, uint32_t bit)
{
	return (os_atomic_or_orig(&is->is_bits, bit, relaxed) & bit) == 0;
}

static inline bool
is_bits_clear(ipc_space_t is, uint32_t bit)
{
	return (os_atomic_andnot_orig(&is->is_bits, bit, relaxed) & bit) != 0;
}

static inline bool
is_bits_test(ipc_space_t is, uint32_t bit)
{
	return os_ref_get_raw_mask(&is->is_bits) & bit;
}

#define is_active(is)           (hazard_ptr_load(&(is)->is_table) != NULL)
#define is_growing(is)          ((is)->is_grower != THREAD_NULL)

static inline ipc_entry_t
is_active_table(ipc_space_t space)
{
	ipc_entry_t table = hazard_ptr_serialized_load(&space->is_table);
	assert(table != NULL);
	return table;
}

#if CONFIG_PROC_RESOURCE_LIMITS
#define is_above_soft_limit_notify(is)      is_bits_test(is, IS_ABOVE_SOFT_LIMIT_NOTIFY)
#define is_above_hard_limit_notify(is)      is_bits_test(is, IS_ABOVE_HARD_LIMIT_NOTIFY)

static inline void
is_above_soft_limit_send_notification(ipc_space_t is)
{
	is_bits_set(is, IS_ABOVE_SOFT_LIMIT_NOTIFY);
}

static inline void
is_above_hard_limit_send_notification(ipc_space_t is)
{
	is_bits_set(is, IS_ABOVE_HARD_LIMIT_NOTIFY);
}

#define is_soft_limit_already_notified(is)  is_bits_test(is, IS_SOFT_LIMIT_NOTIFIED)
#define is_hard_limit_already_notified(is)  is_bits_test(is, IS_HARD_LIMIT_NOTIFIED)

static inline void
is_soft_limit_notified(ipc_space_t is)
{
	is_bits_set(is, IS_SOFT_LIMIT_NOTIFIED);
}

static inline void
is_hard_limit_notified(ipc_space_t is)
{
	is_bits_set(is, IS_HARD_LIMIT_NOTIFIED);
}

#endif /* CONFIG_PROC_RESOURCE_LIMITS */

#define is_at_max_limit_notify(is)                is_bits_test(is, IS_AT_MAX_LIMIT_NOTIFY)
#define is_at_max_limit_already_notified(is)      is_bits_test(is, IS_AT_MAX_LIMIT_NOTIFIED)

static inline void
is_at_max_limit_send_notification(ipc_space_t is)
{
	is_bits_set(is, IS_AT_MAX_LIMIT_NOTIFY);
}

static inline void
is_at_max_limit_notified(ipc_space_t is)
{
	is_bits_set(is, IS_AT_MAX_LIMIT_NOTIFIED);
}

extern ipc_space_t ipc_space_kernel;
extern ipc_space_t ipc_space_reply;
extern lck_grp_t   ipc_lck_grp;
extern lck_attr_t  ipc_lck_attr;

#define is_read_lock(is)        ipc_space_lock(is)
#define is_read_unlock(is)      ipc_space_unlock(is)

#define is_write_lock(is)       ipc_space_lock(is)
#define is_write_unlock(is)     ipc_space_unlock(is)
#define is_write_sleep(is)      ipc_space_lock_sleep(is)

#define is_reference(is)        ipc_space_reference(is)
#define is_release(is)          ipc_space_release(is)

#define current_space_fast()    (current_task_fast()->itk_space)
#define current_space()         (current_space_fast())

extern void         ipc_space_lock(
	ipc_space_t     space);

extern void         ipc_space_unlock(
	ipc_space_t     space);

extern void         ipc_space_lock_sleep(
	ipc_space_t     space);

extern void         ipc_space_free_table(
	ipc_entry_t     table);

#if MACH_LOCKFREE_SPACE
extern void         ipc_space_retire_table(
	ipc_entry_t     table);
#else
#define ipc_space_retire_table  ipc_space_free_table
#endif

/* Create a special IPC space */
extern kern_return_t ipc_space_create_special(
	ipc_space_t     *spacep);

/* Create a new IPC space */
extern kern_return_t ipc_space_create(
	ipc_table_size_t        initial,
	ipc_label_t             label,
	ipc_space_t             *spacep);

/* Change the label on an existing space */
extern kern_return_t ipc_space_label(
	ipc_space_t space,
	ipc_label_t label);

/* Add a label to an existing space */
extern kern_return_t ipc_space_add_label(
	ipc_space_t space,
	ipc_label_t label);

/* Mark a space as dead and cleans up the entries*/
extern void ipc_space_terminate(
	ipc_space_t     space);

/* Permute the order of a range within an IPC space */
extern void ipc_space_rand_freelist(
	ipc_space_t             space,
	ipc_entry_t             table,
	mach_port_index_t       bottom,
	mach_port_index_t       top);

/* Generate a new gencount rollover point from a space's entropy pool */
extern ipc_entry_bits_t ipc_space_get_rollpoint(ipc_space_t space);

#if CONFIG_PROC_RESOURCE_LIMITS
/* Set limits on a space's size */
extern kern_return_t ipc_space_set_table_size_limits(
	ipc_space_t     space,
	ipc_entry_num_t soft_limit,
	ipc_entry_num_t hard_limit);

extern void ipc_space_check_limit_exceeded(
	ipc_space_t space);
#endif /* CONFIG_PROC_RESOURCE_LIMITS */

extern kern_return_t ipc_space_get_table_size_and_limits(
	ipc_space_t space,
	ipc_entry_num_t *current_limit,
	ipc_entry_num_t *soft_limit,
	ipc_entry_num_t *hard_limit);

extern void ipc_space_set_at_max_limit(
	ipc_space_t space);

#endif /* MACH_KERNEL_PRIVATE */
#endif /* __APPLE_API_PRIVATE */

#ifdef  __APPLE_API_UNSTABLE
#ifndef MACH_KERNEL_PRIVATE

extern ipc_space_t              current_space(void);

#endif /* !MACH_KERNEL_PRIVATE */
#endif /* __APPLE_API_UNSTABLE */

/* Take a reference on a space */
extern void ipc_space_reference(
	ipc_space_t     space);

/* Realase a reference on a space */
extern void ipc_space_release(
	ipc_space_t     space);

#endif  /* _IPC_IPC_SPACE_H_ */
