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

#include <os/atomic_private.h>
#include <mach/kern_return.h>
#include <mach/message.h>
#include <kern/locks.h>
#include <kern/macro_help.h>
#include <kern/assert.h>
#include <kern/zalloc.h>
#include <ipc/ipc_types.h>
#include <libkern/OSAtomic.h>

__BEGIN_DECLS __ASSUME_PTR_ABI_SINGLE_BEGIN
#pragma GCC visibility push(hidden)

typedef natural_t ipc_object_refs_t;    /* for ipc/ipc_object.h		*/
typedef natural_t ipc_object_bits_t;
typedef natural_t ipc_object_type_t;

__options_closed_decl(ipc_object_copyout_flags_t, uint32_t, {
	IPC_OBJECT_COPYOUT_FLAGS_NONE                 = 0x0,
	IPC_OBJECT_COPYOUT_FLAGS_PINNED               = 0x1,
	IPC_OBJECT_COPYOUT_FLAGS_NO_LABEL_CHECK       = 0x2,
});

__options_closed_decl(ipc_object_copyin_flags_t, uint16_t, {
	IPC_OBJECT_COPYIN_FLAGS_NONE                          = 0x0,
	IPC_OBJECT_COPYIN_FLAGS_ALLOW_IMMOVABLE_SEND          = 0x1, /* Dest port contains an immovable send right */
	IPC_OBJECT_COPYIN_FLAGS_ALLOW_DEAD_SEND_ONCE          = 0x2,
	IPC_OBJECT_COPYIN_FLAGS_DEADOK                        = 0x4,
	IPC_OBJECT_COPYIN_FLAGS_ALLOW_REPLY_MAKE_SEND_ONCE    = 0x8,  /* Port is a reply port. */
	IPC_OBJECT_COPYIN_FLAGS_ALLOW_REPLY_MOVE_SEND_ONCE    = 0x10, /* Port is a reply port. */
	IPC_OBJECT_COPYIN_FLAGS_ALLOW_IMMOVABLE_RECEIVE       = 0x20,
	IPC_OBJECT_COPYIN_FLAGS_ALLOW_CONN_IMMOVABLE_RECEIVE  = 0x40, /* Port is a libxpc connection port. */
});

/*
 * The ipc_object is used to both tag and reference count these two data
 * structures, and (Noto Bene!) pointers to either of these or the
 * ipc_object at the head of these are freely cast back and forth; hence
 * the ipc_object MUST BE FIRST in the ipc_common_data.
 *
 * If the RPC implementation enabled user-mode code to use kernel-level
 * data structures (as ours used to), this peculiar structuring would
 * avoid having anything in user code depend on the kernel configuration
 * (with which lock size varies).
 */
struct ipc_object {
	ipc_object_bits_t _Atomic io_bits;
	ipc_object_refs_t _Atomic io_references;
} __attribute__((aligned(8)));

/*
 * Legacy defines.  Should use IPC_OBJECT_NULL, etc...
 */
#define IO_NULL                 ((ipc_object_t) 0)
#define IO_DEAD                 ((ipc_object_t) ~0UL)
#define IO_VALID(io)            (((io) != IO_NULL) && ((io) != IO_DEAD))

/*
 *	IPC steals the high-order bits from the kotype to use
 *	for its own purposes.  This allows IPC to record facts
 *	about ports that aren't otherwise obvious from the
 *	existing port fields.  In particular, IPC can optionally
 *	mark a port for no more senders detection.  Any change
 *	to IO_BITS_PORT_INFO must be coordinated with bitfield
 *	definitions in ipc_port.h.
 *
 *	Note that the io_bits can be read atomically without
 *	holding the object lock (for example to read the kobject type).
 *	As such updates to this field need to use the io_bits_or()
 *	or io_bits_andnot() functions.
 */
#define IO_BITS_PORT_INFO       0x0000f000      /* stupid port tricks */
#define IO_BITS_KOTYPE          0x000003ff      /* used by the object */
#define IO_BITS_KOLABEL         0x00000400      /* The kobject has a label */
#define IO_BITS_OTYPE           0x7fff0000      /* determines a zone */
#define IO_BITS_ACTIVE          0x80000000      /* is object alive? */

#define io_bits(io)             atomic_load_explicit(&(io)->io_bits, memory_order_relaxed)

static inline void
io_bits_or(ipc_object_t io, ipc_object_bits_t bits)
{
	/*
	 * prevent any possibility for the compiler to tear the update,
	 * the update still requires the io lock to be held.
	 */
	os_atomic_store(&io->io_bits, io_bits(io) | bits, relaxed);
}

static inline void
io_bits_andnot(ipc_object_t io, ipc_object_bits_t bits)
{
	/*
	 * prevent any possibility for the compiler to tear the update,
	 * the update still requires the io lock to be held.
	 */
	os_atomic_store(&io->io_bits, io_bits(io) & ~bits, relaxed);
}

#define io_active(io)           ((io_bits(io) & IO_BITS_ACTIVE) != 0)

#define io_otype(io)            ((io_bits(io) & IO_BITS_OTYPE) >> 16)
#define io_kotype(io)           (io_bits(io) & IO_BITS_KOTYPE)
#define io_is_kobject(io)       (io_kotype(io) != 0)
#define io_is_kolabeled(io)     ((io_bits(io) & IO_BITS_KOLABEL) != 0)
#define io_makebits(otype)      (IO_BITS_ACTIVE | ((otype) << 16))

/*
 * Object types: ports, port sets, kernel-loaded ports
 */
#define IOT_PORT                0
#define IOT_PORT_SET            1
#define IOT_NUMBER              2               /* number of types used */

extern zone_t __single ipc_object_zones[IOT_NUMBER];

#define io_alloc(otype, flags) \
	zalloc_flags(ipc_object_zones[otype], flags)

/*
 * Here we depend on all ipc_objects being an ipc_wait_queue
 */
#define io_waitq(io) \
	(&__container_of(io, struct ipc_object_waitq, iowq_object)->iowq_waitq)
#define io_from_waitq(waitq) \
	(&__container_of(waitq, struct ipc_object_waitq, iowq_waitq)->iowq_object)

#define io_lock(io) ({ \
	ipc_object_t __io = (io); \
	ipc_object_lock(__io, io_otype(__io)); \
})
#define io_unlock(io)        ipc_object_unlock(io)
#define io_lock_held(io)     assert(waitq_held(io_waitq(io)))
#define io_lock_held_kdp(io) waitq_held(io_waitq(io))
#define io_lock_allow_invalid(io) ipc_object_lock_allow_invalid(io)

#define io_reference(io)     ipc_object_reference(io)
#define io_release(io)       ipc_object_release(io)
#define io_release_safe(io)  ipc_object_release_safe(io)
#define io_release_live(io)  ipc_object_release_live(io)

/*
 * Retrieve a label for use in a kernel call that takes a security
 * label as a parameter. If necessary, io_getlabel acquires internal
 * (not io_lock) locks, and io_unlocklabel releases them.
 */

struct label;
extern struct label *io_getlabel(ipc_object_t obj);
#define io_unlocklabel(obj)

/*
 * Exported interfaces
 */

extern void ipc_object_lock(
	ipc_object_t            object,
	ipc_object_type_t       type);

extern void ipc_object_lock_check_aligned(
	ipc_object_t            object,
	ipc_object_type_t       type);

extern bool ipc_object_lock_allow_invalid(
	ipc_object_t            object) __result_use_check;

extern bool ipc_object_lock_try(
	ipc_object_t            object,
	ipc_object_type_t       type);

extern void ipc_object_unlock(
	ipc_object_t            object);

extern void ipc_object_deallocate_register_queue(void);

/* Take a reference to an object */
extern void ipc_object_reference(
	ipc_object_t    object);

/* Release a reference to an object */
extern void ipc_object_release(
	ipc_object_t    object);

extern void ipc_object_release_safe(
	ipc_object_t    object);

/* Release a reference to an object that isn't the last one */
extern void ipc_object_release_live(
	ipc_object_t    object);

/* Look up an object in a space */
extern kern_return_t ipc_object_translate(
	ipc_space_t             space,
	mach_port_name_t        name,
	mach_port_right_t       right,
	ipc_object_t            *objectp);

/* Look up two objects in a space, locking them in the order described */
extern kern_return_t ipc_object_translate_two(
	ipc_space_t             space,
	mach_port_name_t        name1,
	mach_port_right_t       right1,
	ipc_object_t            *objectp1,
	mach_port_name_t        name2,
	mach_port_right_t       right2,
	ipc_object_t            *objectp2);

/* Validate an object as belonging to the correct zone */
extern void ipc_object_validate(
	ipc_object_t            object,
	ipc_object_type_t       type);

extern void ipc_object_validate_aligned(
	ipc_object_t            object,
	ipc_object_type_t       type);

/* Allocate a dead-name entry */
extern kern_return_t
ipc_object_alloc_dead(
	ipc_space_t             space,
	mach_port_name_t        *namep);

/* Allocate an object */
extern kern_return_t ipc_object_alloc(
	ipc_space_t             space,
	ipc_object_type_t       otype,
	mach_port_type_t        type,
	mach_port_urefs_t       urefs,
	mach_port_name_t        *namep,
	ipc_object_t            *objectp);

/* Allocate an object, with a specific name */
extern kern_return_t ipc_object_alloc_name(
	ipc_space_t             space,
	ipc_object_type_t       otype,
	mach_port_type_t        type,
	mach_port_urefs_t       urefs,
	mach_port_name_t        name,
	ipc_object_t            *objectp,
	void                    (^finish_init)(ipc_object_t object));

/* Convert a send type name to a received type name */
extern mach_msg_type_name_t ipc_object_copyin_type(
	mach_msg_type_name_t    msgt_name);

/* Copyin a capability from a space */
extern kern_return_t ipc_object_copyin(
	ipc_space_t             space,
	mach_port_name_t        name,
	mach_msg_type_name_t    msgt_name,
	ipc_object_t            *objectp,
	mach_port_context_t     context,
	mach_msg_guard_flags_t  *guard_flags,
	ipc_object_copyin_flags_t copyin_flags);

/* Copyin a naked capability from the kernel */
extern void ipc_object_copyin_from_kernel(
	ipc_object_t            object,
	mach_msg_type_name_t    msgt_name);

/* Destroy a naked capability */
extern void ipc_object_destroy(
	ipc_object_t            object,
	mach_msg_type_name_t    msgt_name);

/* Destroy a naked destination capability */
extern void ipc_object_destroy_dest(
	ipc_object_t            object,
	mach_msg_type_name_t    msgt_name);

/* Insert a send right into an object already in the current space */
extern kern_return_t ipc_object_insert_send_right(
	ipc_space_t             space,
	mach_port_name_t        name,
	mach_msg_type_name_t    msgt_name);

/* Copyout a capability, placing it into a space */
extern kern_return_t ipc_object_copyout(
	ipc_space_t             space,
	ipc_object_t            object,
	mach_msg_type_name_t    msgt_name,
	ipc_object_copyout_flags_t flags,
	mach_port_context_t     *context,
	mach_msg_guard_flags_t  *guard_flags,
	mach_port_name_t        *namep);

/* Copyout a capability with a name, placing it into a space */
extern kern_return_t ipc_object_copyout_name(
	ipc_space_t             space,
	ipc_object_t            object,
	mach_msg_type_name_t    msgt_name,
	mach_port_name_t        name);

/* Translate/consume the destination right of a message */
extern void ipc_object_copyout_dest(
	ipc_space_t             space,
	ipc_object_t            object,
	mach_msg_type_name_t    msgt_name,
	mach_port_name_t        *namep);

#pragma GCC visibility pop
__ASSUME_PTR_ABI_SINGLE_BEGIN __END_DECLS

#endif  /* _IPC_IPC_OBJECT_H_ */
