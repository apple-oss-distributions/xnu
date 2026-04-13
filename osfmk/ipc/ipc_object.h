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
 *	File:	ipc/ipc_object.h
 *	Author:	Rich Draves
 *	Date:	1989
 *
 *	Definitions for IPC objects, for which tasks have capabilities.
 */

#ifndef _IPC_IPC_OBJECT_H_
#define _IPC_IPC_OBJECT_H_

#include <stdbool.h>
#include <os/atomic_private.h>
#include <mach/kern_return.h>
#include <mach/message.h>
#include <kern/locks.h>
#include <kern/macro_help.h>
#include <kern/assert.h>
#include <kern/waitq.h>
#include <kern/zalloc.h>
#include <ipc/ipc_types.h>
#include <libkern/OSAtomic.h>

__BEGIN_DECLS __ASSUME_PTR_ABI_SINGLE_BEGIN
__exported_push_hidden

typedef natural_t ipc_object_bits_t;

__options_closed_decl(ipc_object_copyout_flags_t, uint32_t, {
	IPC_OBJECT_COPYOUT_FLAGS_NONE                 = 0x0,
	IPC_OBJECT_COPYOUT_FLAGS_PINNED               = 0x1,
	/*
	 * XNU code paths that may enter immovable send rights must
	 * self-declare via this copyout flag.
	 */
	IPC_OBJECT_COPYOUT_FLAGS_ALLOW_IMMOVABLE_SEND = 0x2,
});

__options_closed_decl(ipc_object_copyin_flags_t, uint16_t, {
	IPC_OBJECT_COPYIN_FLAGS_NONE                          = 0x0,
	IPC_OBJECT_COPYIN_FLAGS_ALLOW_IMMOVABLE_SEND          = 0x1, /* Dest port contains an immovable send right */
	IPC_OBJECT_COPYIN_FLAGS_DEADOK                        = 0x2,
	IPC_OBJECT_COPYIN_FLAGS_DEST_EXTRA_COPY               = 0x4,
	IPC_OBJECT_COPYIN_FLAGS_DEST_EXTRA_MOVE               = 0x8,
});

__enum_decl(ipc_copyin_op_t, uint16_t, {
	IPC_COPYIN_REASON_NONE,
	IPC_COPYIN_KMSG_DESTINATION,
	IPC_COPYIN_KMSG_REPLY,
	IPC_COPYIN_KMSG_VOUCHER,
	IPC_COPYIN_KMSG_PORT_DESCRIPTOR,
	IPC_COPYIN_KMSG_GUARDED_PORT_DESCRIPTOR,
	IPC_COPYIN_KMSG_OOL_PORT_ARRAY_DESCRIPTOR,
	IPC_COPYIN_KERNEL_DESTINATION,
});

/*!
 * @typedef ipc_object_state_t
 *
 * @abstract
 *   Denotes the state of an IPC object.
 *
 * @const IO_STATE_INACTIVE
 *   The object is dead.
 *
 *   Inactive ports have:
 *   - the receiver union is using the ip_timestamp field,
 *     holding a timestamp of when ipc_port_mark_inactive()
 *     was called;
 *   - ip_receiver_name set to MACH_PORT_NULL.
 *
 * @const IO_STATE_IN_SPACE
 *   The object is owned by some IPC space.
 *
 *   In-space ports have:
 *   - the receiver union is using the ip_receiver field, pointing
 *     to the (possibly special) space holding the receive right for this port;
 *   - ip_receiver_name set to a non MACH_PORT_NULL value corresponding to the
 *     name of the receive right for this port within the corresponding space
 *     (MACH_PORT_SPECIAL_DEFAULT is used for special spaces).
 *
 * @const IO_STATE_IN_SPACE_IMMOVABLE
 *   The object is owned by some IPC space, and can't move out of it.
 *
 *   @see IO_STATE_IN_SPACE for details of the receiver fields.
 *
 * @const IO_STATE_IN_LIMBO
 *   The object is a port and is currently being manipulated by the kernel
 *   and is in between states.
 *
 *   In limbo ports have:
 *   - the receiver union set to 0;
 *   - ip_receiver_name set to MACH_PORT_NULL.
 *
 * @const IO_STATE_IN_LIMBO_PD
 *   The object is a port and is currently being manipulated by the kernel
 *   before being enqueued into a port-destroyed notification message.
 *
 *   @see IO_STATE_IN_LIMBO_PD for details of the receiver fields.
 *
 * @const IO_STATE_IN_TRANSIT
 *   The object is a port and is enqueued on some port inside a message.
 *
 *   In-transit ports have:
 *   - the receiver union using the ip_destination field, with a reference
 *     owning pointer to a valid port;
 *   - ip_receiver_name set to MACH_PORT_NULL.
 *
 * @const IO_STATE_IN_TRANSIT_PD
 *   The object is a port and is enqueued on some port inside a port-destroyed
 *   notification message.
 *
 *   @see IO_STATE_IN_TRANSIT for details on the receiver fields.
 */
__enum_closed_decl(ipc_object_state_t, uint8_t, {
	IO_STATE_INACTIVE,
	IO_STATE_IN_SPACE,
	IO_STATE_IN_SPACE_IMMOVABLE,
	IO_STATE_IN_LIMBO,
	IO_STATE_IN_LIMBO_PD,
	IO_STATE_IN_TRANSIT,
	IO_STATE_IN_TRANSIT_PD,
});

/*!
 * @brief
 * The header of an IPC object (port or pset).
 *
 * @discussion
 * This header must be at the start of any IPC object that can be held
 * in a port-space (currently, IPC ports and IPC port sets).
 *
 * @field io_type
 * The type of the IPC object, this value is an immutable property
 * of the IPC object and can be read without holding any locks.
 *
 * @field io_state
 * This field denots the state of the object, it is mutable,
 * and must be read under the object lock held.
 *
 * Furthermore, it can be autnenticated by extracting the IPC object label
 * from the object (using @c io_label_get()), which is the preferred way
 * to look at this field.
 *
 * @field io_filtered
 * Whether this port uses IPC filtering, this is an immutable property
 * of the object and can be consulted without holding any lock.
 *
 * @field io_label_lock
 * This is used to track extent IPC object labels for this object,
 * and should not be consulted or manipulated directly.
 *
 * @field io_references
 * The refcount for this IPC object (meaningless on a IPC object label).
 *
 * @field iol_pointer
 * This union holds the actual label for an IPC object, it is signed
 * and must be read by using the @c io_label_get() accessor. The pointer
 * is not stable during the lifecycle of the object.
 */
struct ipc_object {
	union {
		struct {
			ipc_object_type_t       io_type;
			ipc_object_state_t      io_state     : 3;
			uint8_t                 io_filtered  : 1;
			uint8_t                 __io_unused1 : 4;
			/* dPAC modifier boundary */
			/*
			 * the io_label_lock supports io_label_get/put,
			 * it could be a single bit, but a full byte
			 * yields much better codegen, and the bits are unused.
			 */
			bool                    io_label_lock;
			uint8_t                 __io_unused2;
		};
		ipc_object_bits_t               io_bits;
	};
	os_ref_atomic_t                         io_references;
	union {
		/* these are dPACed when on a port header */
		const void                      *iol_pointer;
		unsigned long                    iol_value;
		struct ipc_service_port_label   *iol_service;
		struct ipc_bootstrap_port_label *iol_bootstrap;
		struct ipc_conn_port_label      *iol_connection;
		struct ipc_kobject_label        *iol_kobject;
		struct mk_timer                 *iol_mktimer;
	};
};

/*!
 * @brief
 * Type used to hold details about a resolved IPC object type and label.
 *
 * @discussion
 * This is a non-copyable, movable value type which is never stored
 * on any data structure.
 *
 * It is also required that at most one such structure is extant for a given
 * port at any point in time, and that the port lock is held for the whole
 * time this structure is live. This is enforced at runtime.
 *
 * The core API to acquire such a type is @c io_label_get(), and when it is
 * no longer used, @c ip_label_put() can be used to denote it's no longer
 * valid, and the value will be poisoned. @c ip_label_set() can also be used
 * if the value is going to be updated, which also consumes the label.
 *
 * Passing this structure by value to functions that will not call
 * @c ip_label_put() or release the port lock is a valid and even encouraged
 * practice, as this is a much better calling convention.
 */
typedef struct ipc_object       ipc_object_label_t;

#define IPC_OBJECT_LABEL(otype, ...) \
	((ipc_object_label_t){ \
	        .io_type = otype, \
	        .io_state = IO_STATE_IN_SPACE, \
	        ## __VA_ARGS__, \
	})

#define IPC_OBJECT_LABEL_INVALID \
	((ipc_object_label_t){ \
	        .io_bits = ~0u, \
	        .io_references = ~0u, \
	        .iol_value = ~0ul, \
	})

#define io_type(io)             ((io)->io_type)
#define io_is_pset_type(t)      ((t) == IOT_PORT_SET)
#define io_is_any_port_type(t)  (!io_is_pset_type(t))
#define io_is_kobject_type(t)   ((t) >= __IKOT_FIRST)
#define io_is_any_port(io)      io_is_any_port_type(io_type(io))
#define io_is_pset(io)          io_is_pset_type(io_type(io))
#define io_is_kobject(io)       io_is_kobject_type(io_type(io))

ZONE_DECLARE_ID(ZONE_ID_IPC_PORT, struct ipc_port);
ZONE_DECLARE_ID(ZONE_ID_IPC_PORT_SET, struct ipc_pset);

/*
 * Here we depend on all ipc_objects being an ipc_wait_queue
 *
 * this type doesn't exist and is only used to do math
 */
struct ipc_object_waitq {
	struct ipc_object       iowq_object;
	struct waitq            iowq_waitq;
};
#define io_waitq(io) \
	(&__container_of(io, struct ipc_object_waitq, iowq_object)->iowq_waitq)
#define io_from_waitq(waitq) \
	(&__container_of(waitq, struct ipc_object_waitq, iowq_waitq)->iowq_object)

#define io_unlock(io)                   ipc_object_unlock(io)
#define io_unlock_nocheck(io)           waitq_unlock(io_waitq(io))
#define io_lock_held(io)                assert(waitq_held(io_waitq(io)))
#define io_lock_held_kdp(io)            waitq_held(io_waitq(io))
#define io_lock_allow_invalid(io)       ipc_object_lock_allow_invalid(io)

#define io_reference(io)                ipc_object_reference(io)
#define io_release(io)                  ipc_object_release(io)
#define io_release_safe(io)             ipc_object_release_safe(io)
#define io_release_live(io)             ipc_object_release_live(io)

static inline bool
io_state_active(ipc_object_state_t state)
{
	return state != IO_STATE_INACTIVE;
}

static inline bool
io_state_in_space(ipc_object_state_t state)
{
	switch (state) {
	case IO_STATE_IN_SPACE:
	case IO_STATE_IN_SPACE_IMMOVABLE:
		return true;
	default:
		return false;
	}
}

static inline bool
io_state_in_limbo(ipc_object_state_t state)
{
	switch (state) {
	case IO_STATE_IN_LIMBO:
	case IO_STATE_IN_LIMBO_PD:
		return true;
	default:
		return false;
	}
}

static inline bool
io_state_in_transit(ipc_object_state_t state)
{
	switch (state) {
	case IO_STATE_IN_TRANSIT:
	case IO_STATE_IN_TRANSIT_PD:
		return true;
	default:
		return false;
	}
}

static inline bool
io_state_is_moving(ipc_object_state_t state)
{
	switch (state) {
	case IO_STATE_IN_LIMBO:
	case IO_STATE_IN_LIMBO_PD:
	case IO_STATE_IN_TRANSIT:
	case IO_STATE_IN_TRANSIT_PD:
		return true;
	default:
		return false;
	}
}

__result_use_check
__attribute__((always_inline))
static inline ipc_object_label_t
__io_label_validate(ipc_object_t io, ipc_object_label_t label, bool lock)
{
	if (lock) {
		io_lock_held(io);
		release_assert(!io->io_label_lock);
		io->io_label_lock = true;
	}

	label.iol_pointer = ptrauth_auth_data(label.iol_pointer,
	    ptrauth_key_process_independent_data,
	    ptrauth_blend_discriminator(io, (uint32_t)(label.io_bits +
	    ptrauth_string_discriminator("ipc_object.iol_pointer"))));

#if __has_feature(ptrauth_calls)
	/*
	 * io_label() must guarantee that we always do the PAC evaluation,
	 * as callers even if they do not use bits or the pointer value,
	 * expect this validation to take place.
	 */
	__compiler_materialize_and_prevent_reordering_on(label.iol_pointer);
#endif

	return label;
}

__result_use_check
__attribute__((always_inline, overloadable))
static inline ipc_object_label_t
io_label_get(ipc_object_t io, ipc_object_type_t otype)
{
	ipc_object_label_t label;

	label = *io;
	label.io_type = otype;

	return __io_label_validate(io, label, true);
}

__result_use_check
__attribute__((always_inline, overloadable))
static inline ipc_object_label_t
io_label_get(ipc_object_t io)
{
	return __io_label_validate(io, *io, true);
}

__attribute__((always_inline, overloadable))
static inline ipc_object_label_t
io_label_peek_kdp(ipc_object_t io)
{
	assert(!io_lock_held_kdp(io));
	return __io_label_validate(io, *io, false);
}

__attribute__((always_inline))
static inline void
io_label_init(ipc_object_t io, ipc_object_label_t label)
{
	atomic_store_explicit(os_cast_to_atomic_pointer(&io->io_bits),
	    label.io_bits, memory_order_relaxed);

	io->iol_pointer = ptrauth_sign_unauthenticated(label.iol_pointer,
	    ptrauth_key_process_independent_data,
	    ptrauth_blend_discriminator(io, (uint32_t)(label.io_bits +
	    ptrauth_string_discriminator("ipc_object.iol_pointer"))));
}

__attribute__((always_inline))
static inline void
io_label_set_and_put(ipc_object_t io, ipc_object_label_t *label)
{
	release_assert(io->io_label_lock);
	io_lock_held(io);

	io_label_init(io, *label);
	*label = IPC_OBJECT_LABEL_INVALID;
}

__attribute__((always_inline))
static inline void
io_label_put(ipc_object_t io, ipc_object_label_t *label)
{
	assert(io->io_type == label->io_type &&
	    io->io_state == label->io_state);
	release_assert(io->io_label_lock);

	io->io_label_lock = false;
	*label = IPC_OBJECT_LABEL_INVALID;
}

/*
 * Exported interfaces
 */

extern bool ipc_object_lock_allow_invalid(
	ipc_object_t            object) __result_use_check;

extern void ipc_object_unlock(
	ipc_object_t            object);

extern void ipc_object_deallocate_register_queue(void);

/* Take a reference to an object */
extern void ipc_object_reference(
	ipc_object_t            object);

/* Release a reference to an object */
extern void ipc_object_release(
	ipc_object_t            object);

extern void ipc_object_release_safe(
	ipc_object_t            object);

/* Release a reference to an object that isn't the last one */
extern void ipc_object_release_live(
	ipc_object_t            object);

/* Look up an object in a space */
extern kern_return_t ipc_object_translate(
	ipc_space_t             space,
	mach_port_name_t        name,
	mach_port_right_t       right,
	ipc_object_t           *objectp);

/* Look up two objects in a space, locking them in the order described */
extern kern_return_t ipc_object_translate_port_pset(
	ipc_space_t             space,
	mach_port_name_t        port_name,
	ipc_port_t             *port,
	mach_port_name_t        pset_name,
	ipc_pset_t             *pset);

/* Validate an object as belonging to the correct zone */
extern void ipc_object_validate(
	ipc_object_t            object,
	ipc_object_type_t       type);

/* Allocate a dead-name entry */
extern kern_return_t ipc_object_alloc_dead(
	ipc_space_t         space,
	mach_port_name_t    *namep);

/* Allocate an object */
extern kern_return_t ipc_object_alloc_entry(
	ipc_space_t         space,
	ipc_object_t        object,
	mach_port_name_t    *namep,
	ipc_entry_t         *entry);

/* Allocate an object, with a specific name */
extern kern_return_t ipc_object_alloc_entry_with_name(
	ipc_space_t         space,
	mach_port_name_t    name,
	ipc_entry_t         *entry);

/* Convert a send type name to a received type name */
extern mach_msg_type_name_t ipc_object_copyin_type(
	mach_msg_type_name_t    msgt_name);

/* Copyin a capability from a space */
extern kern_return_t ipc_object_copyin(
	ipc_space_t             space,
	mach_port_name_t        name,
	mach_msg_type_name_t    msgt_name,
	ipc_object_copyin_flags_t copyin_flags,
	ipc_copyin_op_t         copyin_reason,
	mach_msg_guarded_port_descriptor_t *gdesc,
	ipc_port_t             *portp);

/* Copyin a naked capability from the kernel */
extern void ipc_object_copyin_from_kernel(
	ipc_port_t              port,
	mach_msg_type_name_t    msgt_name);

/* Destroy a naked capability */
extern void ipc_object_destroy(
	ipc_port_t              port,
	mach_msg_type_name_t    msgt_name);

/* Destroy a naked destination capability */
extern void ipc_object_destroy_dest(
	ipc_port_t              port,
	mach_msg_type_name_t    msgt_name);

/* Insert a send right into an object already in the current space */
extern kern_return_t ipc_object_insert_send_right(
	ipc_space_t             space,
	mach_port_name_t        name,
	mach_msg_type_name_t    msgt_name);

/* Copyout a capability, placing it into a space */
extern kern_return_t ipc_object_copyout(
	ipc_space_t             space,
	ipc_port_t              port,
	mach_msg_type_name_t    msgt_name,
	ipc_object_copyout_flags_t flags,
	mach_msg_guarded_port_descriptor_t *gdesc,
	mach_port_name_t        *namep);

/* Copyout a capability with a name, placing it into a space */
extern kern_return_t ipc_object_copyout_name(
	ipc_space_t             space,
	ipc_port_t              port,
	mach_msg_type_name_t    msgt_name,
	mach_port_name_t        name);

/* Translate/consume the destination right of a message */
extern void ipc_object_copyout_dest(
	ipc_space_t             space,
	ipc_port_t              port,
	mach_msg_type_name_t    msgt_name,
	mach_port_name_t        *namep);

/* Unpin the entry for a send right pointing to "object" */
extern void ipc_object_unpin(
	ipc_space_t             space,
	ipc_port_t              port);

__exported_pop
__ASSUME_PTR_ABI_SINGLE_END __END_DECLS

#endif  /* _IPC_IPC_OBJECT_H_ */
