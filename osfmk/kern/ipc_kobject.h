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
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */
/*
 */
/*
 *	File:	kern/ipc_kobject.h
 *	Author:	Rich Draves
 *	Date:	1989
 *
 *	Declarations for letting a port represent a kernel object.
 */

#ifndef _KERN_IPC_KOBJECT_H_
#define _KERN_IPC_KOBJECT_H_

#ifdef MACH_KERNEL_PRIVATE
#include <ipc/ipc_kmsg.h>
#include <ipc/ipc_port.h>
#include <kern/startup.h>
#endif /* MACH_KERNEL_PRIVATE */
#include <mach/machine/vm_types.h>
#include <mach/mach_types.h>
#include <ipc/ipc_types.h>

__BEGIN_DECLS
__exported_push_hidden

typedef ipc_object_type_t ipc_kobject_type_t;

/* set the bitstring index for kobject */
extern kern_return_t ipc_kobject_set_kobjidx(
	int                         msgid,
	int                         index);

#ifdef MACH_KERNEL_PRIVATE

/*!
 * @typedef ipc_kobject_ops_t
 *
 * @brief
 * Describes the operations for a given kobject.
 *
 * @field iko_ko_type
 * An @c IOT_* value.
 *
 * @field iko_op_stable
 * The kobject/port association is stable:
 * - ipc_kobject_dealloc_port() cannot be called
 *   while there are outstanding send rights,
 * - ipc_kobject_enable() is never called.
 * - ipc_kobject_disable() is never called.
 *
 * @field iko_op_permanent
 * The port is never destroyed.
 * This doesn't necessarily imply iko_op_stable.
 *
 * @field iko_op_no_senders
 * A callback to run when a NO_SENDERS notification fires.
 *
 * This callback is called each time a kobject port reaches 0 send rights
 * (from a non 0 value). There is no need to actively arm no-senders.
 *
 * Kobjects that destroy their port on no senders only are guaranteed
 * to be called with an active port only.
 *
 * However kobject ports that can be destroyed concurrently need
 * to be prepared for no senders to fail to acquire the kobject port.
 *
 * When this callback is set, @c ipc_kobject_dealloc_port()
 * will not implicitly call @c ipc_kobject_disable().
 *
 * The callback runs after the port has been marked inactive,
 * hence @c ipc_kobject_get_raw() needs to be used to get to the port.
 *
 * @field iko_op_label_free
 * How to free the label on this kobject port (if it supports one).
 *
 * @field iko_op_movable_send
 * Whether send rights created to this kobject are movable
 */
typedef const struct ipc_kobject_ops {
	ipc_kobject_type_t iko_op_type;
	unsigned long
	    iko_op_stable               : 1,
	    iko_op_permanent            : 1,
	    iko_op_movable_send         : 1;
	const char        *iko_op_name;
	void (*iko_op_no_senders)(ipc_port_t port, mach_port_mscount_t mscount);
	void (*iko_op_label_free)(ipc_object_label_t label);
} *ipc_kobject_ops_t;

#define IPC_KOBJECT_DEFINE(type, ...) \
	__startup_data \
	static struct ipc_kobject_ops ipc_kobject_ops_##type = { \
	    .iko_op_type = type, \
	    .iko_op_name = #type, \
	    __VA_ARGS__ \
	}; \
	STARTUP_ARG(MACH_IPC, STARTUP_RANK_FIRST, ipc_kobject_register_startup, \
	    &ipc_kobject_ops_##type)

struct ipc_kobject_label {
	ipc_label_t   ikol_label;       /* [private] mandatory access label */
	ipc_port_t XNU_PTRAUTH_SIGNED_PTR("ipc_kobject_label.ikol_alt_port") ikol_alt_port;
};

extern ipc_object_label_t ipc_kobject_label_alloc(
	ipc_object_type_t       otype,
	ipc_label_t             label_tag,
	ipc_port_t              alt_port);

extern void ipc_kobject_label_free(
	ipc_object_label_t      label);

__options_decl(ipc_kobject_alloc_options_t, uint32_t, {
	/* Just make the naked port */
	IPC_KOBJECT_ALLOC_NONE      = 0x00000000,
	/* Make a send right */
	IPC_KOBJECT_ALLOC_MAKE_SEND = 0x00000001,
});

/* Allocates a kobject port, never fails */
extern ipc_port_t ipc_kobject_alloc_port(
	ipc_kobject_t               kobject,
	ipc_object_label_t          label,
	ipc_kobject_alloc_options_t options);

__attribute__((always_inline, overloadable))
static inline ipc_port_t
ipc_kobject_alloc_port(
	ipc_kobject_t               kobject,
	ipc_object_type_t           otype,
	ipc_kobject_alloc_options_t options)
{
	return ipc_kobject_alloc_port(kobject, IPC_OBJECT_LABEL(otype), options);
}

/*!
 * @function ipc_kobject_make_send_lazy_alloc_port()
 *
 * @brief
 * Make a send once for a kobject port, lazily allocating the port.
 *
 * @discussion
 * A location owning this port is passed in port_store.
 * If no port exists, a port is made lazily.
 *
 * A send right is made for the port, and if this is the first one
 * (possibly not for the first time), then the no-more-senders
 * notification is rearmed.
 *
 * When a notification is armed, the kobject must donate
 * one of its references to the port. It is expected
 * the no-more-senders notification will consume this reference.
 *
 * In order to use this function, the kobject type requested must:
 * - be use stable objects (iko_op_stable is true),
 * - have a no-senders callback (iko_op_no_senders is set).
 *
 * @returns
 * - true, if this was the first send right made for this port,
 *   and an object reference must be donated to the port;
 * - false otherwise.
 */
extern bool ipc_kobject_make_send_lazy_alloc_port(
	ipc_port_t                 *port_store,
	ipc_kobject_t               kobject,
	ipc_kobject_type_t          type);

/*!
 * @function ipc_kobject_is_mscount_current()
 *
 * @brief
 * Returns whether the current make-send count is the current one.
 *
 * @discussion
 * This is meant to be called from the context of a no-senders notification
 * callout to determine whether the object/port has since been rematerialized.
 *
 * Most kobjects are uniquely owned by their port, and the object is otherwise
 * not reachable from any place in the system (see semaphores, eventlink, etc),
 * and die when the port has no more senders.
 *
 * However some kobjects might still be reachable from other means,
 * and can make new send rights in a way that isn't synchronized with Mach IPC.
 * (See IKOT_TASK_RESUME for an example of that).
 *
 * This function allows for such kobject types to verify under the
 * synchronization it uses whether this no-senders callout is the last one,
 * or if there has been new send rights made concurrently.
 *
 * @param port          The target port.
 * @param mscount       The make-send count for which the no-senders
 *                      notification was issued.
 */
extern bool ipc_kobject_is_mscount_current(
	ipc_port_t                  port,
	mach_port_mscount_t         mscount);

extern bool ipc_kobject_is_mscount_current_locked(
	ipc_port_t                  port,
	mach_port_mscount_t         mscount);

/*!
 * @function ipc_kobject_copy_send()
 *
 * @brief
 * Copies a naked send right for the specified kobject port.
 *
 * @decription
 * This function will validate that the specified port is pointing
 * to the expected kobject pointer and type (by calling ipc_kobject_require()).
 *
 * @param port          The target port.
 * @param kobject       The kobject pointer this port should be associated to.
 * @param kotype        The kobject type this port should have.
 *
 * @returns
 * - IP_DEAD            if @c port was dead.
 * - @c port            if @c port was valid, in which case
 *                      a naked send right was made.
 */
extern ipc_port_t ipc_kobject_copy_send(
	ipc_port_t                  port,
	ipc_kobject_t               kobject,
	ipc_kobject_type_t          kotype) __result_use_check;

/*!
 * @function ipc_kobject_make_send()
 *
 * @brief
 * Makes a naked send right for the specified kobject port.
 *
 * @decription
 * @see ipc_port_make_send_any_locked() for a general warning about
 * making send rights.
 *
 * This function will validate that the specified port is pointing
 * to the expected kobject pointer and type (by calling ipc_kobject_require()).
 *
 * @param port          The target port.
 * @param kobject       The kobject pointer this port should be associated to.
 * @param kotype        The kobject type this port should have.
 *
 * @returns
 * - IP_DEAD            if @c port was dead.
 * - @c port            if @c port was valid, in which case
 *                      a naked send right was made.
 */
extern ipc_port_t ipc_kobject_make_send(
	ipc_port_t                  port,
	ipc_kobject_t               kobject,
	ipc_kobject_type_t          kotype) __result_use_check;

#define IPC_KOBJECT_NO_MSCOUNT      (~0ull)

extern ipc_kobject_t ipc_kobject_dealloc_port_and_unlock(
	ipc_port_t                  port,
	uint64_t                    mscount,
	ipc_kobject_type_t          type);

extern ipc_kobject_t ipc_kobject_dealloc_port(
	ipc_port_t                  port,
	uint64_t                    mscount,
	ipc_kobject_type_t          type);

extern void         ipc_kobject_enable(
	ipc_port_t                  port,
	ipc_kobject_t               kobject,
	ipc_kobject_type_t          type);

/*!
 * @function ipc_kobject_require()
 *
 * @brief
 * Asserts that a given port is of the specified type
 * with the expected kobject pointer.
 *
 * @decription
 * Port type confusion can lead to catastrophic system compromise,
 * this function can be used in choke points to ensure ports are
 * what they're expected to be before their use.
 *
 * @note It is allowed for the kobject pointer to be NULL,
 *       as in some cases ipc_kobject_disable() can be raced with this check.
 *
 * @param port          The target port.
 * @param kobject       The kobject pointer this port should be associated to.
 * @param kotype        The kobject type this port should have.
 */
extern void         ipc_kobject_require(
	ipc_port_t                  port,
	ipc_kobject_t               kobject,
	ipc_kobject_type_t          kotype);

extern ipc_kobject_t ipc_kobject_get_raw(
	ipc_port_t                  port,
	ipc_kobject_type_t          type);

extern ipc_kobject_t ipc_kobject_get_locked(
	ipc_port_t                  port,
	ipc_kobject_type_t          type);

extern ipc_kobject_t ipc_kobject_get_stable(
	ipc_port_t                  port,
	ipc_kobject_type_t          type);

extern ipc_kobject_t ipc_kobject_disable_locked(
	ipc_port_t                  port,
	ipc_kobject_type_t          type);

extern ipc_kobject_t ipc_kobject_disable(
	ipc_port_t                  port,
	ipc_kobject_type_t          type);

/* Check if a kobject can be copied out to a given space */
extern bool     ipc_kobject_label_check_or_substitute(
	ipc_space_t                 space,
	ipc_port_t                  port,
	ipc_object_label_t         *label,
	mach_msg_type_name_t        msgt_name,
	ipc_port_t                 *subst_portp) __result_use_check;

/*!
 * @brief
 * Evaluate a port for substitution and kobject label rules.
 *
 * @discussion
 * This function has a really cumbersome calling convention.
 *
 * If it returns false, then it means that some policy was violated,
 * in that case, @c port has been unlocked, and @c label put.
 *
 * If it returns true, and subst_portp is not IP_NULL, then @c port
 * has been unlocked, and @c label put, and the caller is expected
 * to redrive evaluation with that substitution port.
 *
 * If it returns true, and subst_port is IP_NULL, then @c port
 * is still locked, and @c label still valid, and the caller is expected
 * to proceed further.
 *
 * @param space         The current space
 * @param port          The port to evaluate (must be locked and active)
 * @param label         (In/out) the label for @c port.
 * @param msgt_name     The disposition for @c port in the message.
 * @param subst_portp   (out) an optional substitution port,
 *                      to replace @c port with.
 */
__result_use_check
static inline bool
ip_label_check_or_substitute(
	ipc_space_t                 space,
	ipc_port_t                  port,
	ipc_object_label_t         *label,
	mach_msg_type_name_t        msgt_name,
	ipc_port_t                 *subst_portp)
{
	if (!io_is_kobject_type(label->io_type) || !label->iol_kobject) {
		*subst_portp = IP_NULL;
		return true;
	}
	return ipc_kobject_label_check_or_substitute(space, port, label, msgt_name, subst_portp);
}

/* implementation details */

__startup_func
extern void ipc_kobject_register_startup(
	ipc_kobject_ops_t           ops);

/* Dispatch a kernel server function */
extern ipc_kmsg_t ipc_kobject_server(
	ipc_port_t                  receiver,
	ipc_kmsg_t                  request,
	mach_msg_option64_t         option);

#define null_conversion(port)   (port)

extern void ipc_kobject_notify_send_once_and_unlock(
	ipc_port_t                  port);

extern kern_return_t uext_server(
	ipc_port_t                  receiver,
	ipc_kmsg_t                  request,
	ipc_kmsg_t                  *reply);

#endif /* MACH_KERNEL_PRIVATE */
#if XNU_KERNEL_PRIVATE

/*!
 * @function ipc_typed_port_copyin_send()
 *
 * @brief
 * Copies in a naked send right for the specified typed port.
 *
 * @decription
 * This function will validate that the specified port is pointing
 * to the expected kobject type, unless @c kotype is IOT_ANY,
 * in which case any right is accepted.
 *
 * @param space         The space to copyin in from.
 * @param name          The name to copyin.
 * @param kotype        The kobject type this port should have.
 * @param port          The resulting port or IP_NULL.
 *
 * @returns
 * - KERN_SUCCESS       Acquired an object, possibly IP_DEAD.
 * - KERN_INVALID_TASK  The space is dead.
 * - KERN_INVALID_NAME  Name doesn't exist in space.
 * - KERN_INVALID_RIGHT Name doesn't denote correct right.
 * - KERN_INVALID_CAPABILITY
 *                      The right isn't of the right kobject type.
 */
extern kern_return_t ipc_typed_port_copyin_send(
	ipc_space_t                 space,
	mach_port_name_t            name,
	ipc_kobject_type_t          kotype,
	ipc_port_t                 *port);

/*!
 * @function ipc_typed_port_release_send()
 *
 * @brief
 * Release a send right for a typed port.
 *
 * @description
 * This is an alias for ipc_port_release_send() that the BSD side can use.
 * If @c kotype is IOT_ANY, any right is accepted.
 */
extern void       ipc_typed_port_release_send(
	ipc_port_t                  port,
	ipc_kobject_type_t          kotype);

#endif /* XNU_KERNEL_PRIVATE */
__exported_pop
__END_DECLS

#endif /* _KERN_IPC_KOBJECT_H_ */
