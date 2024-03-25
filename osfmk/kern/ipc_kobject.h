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

__BEGIN_DECLS
#pragma GCC visibility push(hidden)

__enum_decl(ipc_kotype_t, natural_t, {
	IKOT_NONE                     = 0,
	IKOT_THREAD_CONTROL           = 1,
	IKOT_TASK_CONTROL             = 2,
	IKOT_HOST                     = 3,
	IKOT_HOST_PRIV                = 4,
	IKOT_PROCESSOR                = 5,
	IKOT_PSET                     = 6,
	IKOT_PSET_NAME                = 7,
	IKOT_TIMER                    = 8,
	IKOT_PORT_SUBST_ONCE          = 9,
	// IKOT_MIG                   = 10,
	IKOT_MEMORY_OBJECT            = 11,
	// IKOT_XMM_PAGER             = 12,
	// IKOT_XMM_KERNEL            = 13,
	// IKOT_XMM_REPLY             = 14,
	IKOT_UND_REPLY                = 15,
	// IKOT_HOST_NOTIFY           = 16,
	// IKOT_HOST_SECURITY         = 17,
	// IKOT_LEDGER                = 18,
	IKOT_MAIN_DEVICE              = 19,
	IKOT_TASK_NAME                = 20,
	// IKOT_SUBSYSTEM             = 21,
	// IKOT_IO_DONE_QUEUE         = 22,
	IKOT_SEMAPHORE                = 23,
	// IKOT_LOCK_SET              = 24,
	IKOT_CLOCK                    = 25,
	// IKOT_CLOCK_CTRL            = 26,
	IKOT_IOKIT_IDENT              = 27,
	IKOT_NAMED_ENTRY              = 28,
	IKOT_IOKIT_CONNECT            = 29,
	IKOT_IOKIT_OBJECT             = 30,
	// IKOT_UPL                   = 31,
	// IKOT_MEM_OBJ_CONTROL       = 32,
#if CONFIG_AUDIT
	IKOT_AU_SESSIONPORT           = 33,
#endif
	IKOT_FILEPORT                 = 34,
	// IKOT_LABELH                = 35,
	IKOT_TASK_RESUME              = 36,
	IKOT_VOUCHER                  = 37,
	// IKOT_VOUCHER_ATTR_CONTROL  = 38,
	IKOT_WORK_INTERVAL            = 39,
	IKOT_UX_HANDLER               = 40,
	IKOT_UEXT_OBJECT              = 41,
	IKOT_ARCADE_REG               = 42,
	IKOT_EVENTLINK                = 43,
	IKOT_TASK_INSPECT             = 44,
	IKOT_TASK_READ                = 45,
	IKOT_THREAD_INSPECT           = 46,
	IKOT_THREAD_READ              = 47,
	// IKOT_SUID_CRED             = 48,
#if HYPERVISOR
	IKOT_HYPERVISOR               = 49,
#endif
	IKOT_TASK_ID_TOKEN            = 50,
#if CONFIG_PROC_RESOURCE_LIMITS
	IKOT_TASK_FATAL               = 51,
#endif
	IKOT_KCDATA                   = 52,
#if CONFIG_EXCLAVES
	IKOT_EXCLAVES_RESOURCE        = 53,
#endif
	/* magic catch-all; should be the last entry */
	IKOT_UNKNOWN,
});

#define IKOT_MAX_TYPE   (IKOT_UNKNOWN+1)        /* # of IKOT_ types	*/

#ifdef __cplusplus
/* preserve legacy ABI for c++ */
typedef natural_t ipc_kobject_type_t;
#else
typedef ipc_kotype_t ipc_kobject_type_t;
#endif

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
 * An @c IKOT_* value.
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
 * Kobjects that destroy their port on no senders only are guaranteed
 * to be called with an active port only.
 *
 * However kobject ports that can be destroyed concurrently need
 * to be prepared for no senders to fail to acquire the kobject port.
 *
 * @field iko_op_destroy
 * A callback to run as part of destroying the kobject port.
 *
 * When this callback is set, @c ipc_kobject_dealloc_port()
 * will not implicitly call @c ipc_kobject_disable().
 *
 * The callback runs after the port has been marked inactive,
 * hence @c ipc_kobject_get_raw() needs to be used to get to the port.
 */
typedef const struct ipc_kobject_ops {
	ipc_kobject_type_t iko_op_type;
	unsigned long
	    iko_op_stable        : 1,
	    iko_op_permanent     : 1;
	const char        *iko_op_name;
	void (*iko_op_no_senders)(ipc_port_t port, mach_port_mscount_t mscount);
	void (*iko_op_destroy)(ipc_port_t port);
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

__options_decl(ipc_kobject_alloc_options_t, uint32_t, {
	/* Just make the naked port */
	IPC_KOBJECT_ALLOC_NONE      = 0x00000000,
	/* Make a send right */
	IPC_KOBJECT_ALLOC_MAKE_SEND = 0x00000001,
	/* Register for no-more-senders */
	IPC_KOBJECT_ALLOC_NSREQUEST = 0x00000002,
	/* Make it no grant port */
	IPC_KOBJECT_ALLOC_NO_GRANT  = 0x00000004,
	/* Mark the port as immovable send right */
	IPC_KOBJECT_ALLOC_IMMOVABLE_SEND = 0x00000008,
	/* Add a label structure to the port */
	IPC_KOBJECT_ALLOC_LABEL     = 0x00000010,
	/* Mark the port as pinned (non dealloc-able) in an ipc space */
	IPC_KOBJECT_ALLOC_PINNED    = 0x00000020,
});

/* Allocates a kobject port, never fails */
extern ipc_port_t ipc_kobject_alloc_port(
	ipc_kobject_t               kobject,
	ipc_kobject_type_t          type,
	ipc_kobject_alloc_options_t options);

/* Allocates a kobject port, never fails */
extern ipc_port_t ipc_kobject_alloc_labeled_port(
	ipc_kobject_t               kobject,
	ipc_kobject_type_t          type,
	ipc_label_t                 label,
	ipc_kobject_alloc_options_t options);

extern ipc_port_t ipc_kobject_alloc_subst_once(
	ipc_port_t                  target);

/* Makes a send right, lazily allocating a kobject port, arming for no-senders, never fails */
extern bool ipc_kobject_make_send_lazy_alloc_port(
	ipc_port_t                 *port_store,
	ipc_kobject_t               kobject,
	ipc_kobject_type_t          type,
	ipc_kobject_alloc_options_t alloc_opts);

/* Makes a send right, lazily allocating a kobject port, arming for no-senders, never fails */
extern boolean_t ipc_kobject_make_send_lazy_alloc_labeled_port(
	ipc_port_t                 *port_store,
	ipc_kobject_t               kobject,
	ipc_kobject_type_t          type,
	ipc_label_t                 label) __result_use_check;

extern kern_return_t ipc_kobject_nsrequest(
	ipc_port_t                  port,
	mach_port_mscount_t         sync,
	mach_port_mscount_t        *mscount) __result_use_check;

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

/*!
 * @function ipc_kobject_make_send_nsrequest()
 *
 * @brief
 * Makes a naked send right for the specified kobject port,
 * and arms no-more-senders if it wasn't already.
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
 * - KERN_SUCCESS:           the notification was armed
 * - KERN_ALREADY_WAITING:   the notification was already armed
 * - KERN_INVALID_RIGHT:     the port is dead
 */
extern kern_return_t ipc_kobject_make_send_nsrequest(
	ipc_port_t                  port,
	ipc_kobject_t               kobject,
	ipc_kobject_type_t          kotype) __result_use_check;

extern kern_return_t ipc_kobject_make_send_nsrequest_locked(
	ipc_port_t                  port,
	ipc_kobject_t               kobject,
	ipc_kobject_type_t          kotype) __result_use_check;

extern ipc_kobject_t ipc_kobject_dealloc_port_and_unlock(
	ipc_port_t                  port,
	mach_port_mscount_t         mscount,
	ipc_kobject_type_t          type);

extern ipc_kobject_t ipc_kobject_dealloc_port(
	ipc_port_t                  port,
	mach_port_mscount_t         mscount,
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

extern void         ipc_kobject_upgrade_mktimer_locked(
	ipc_port_t                  port,
	ipc_kobject_t               kobject);

/* in mk_timer.c */
extern void         ipc_kobject_mktimer_require_locked(
	ipc_port_t                  port);

/* Check if a kobject can be copied out to a given space */
extern bool     ipc_kobject_label_check(
	ipc_space_t                 space,
	ipc_port_t                  port,
	mach_msg_type_name_t        msgt_name,
	ipc_object_copyout_flags_t *flags,
	ipc_port_t                 *subst_portp) __result_use_check;

__result_use_check
static inline bool
ip_label_check(
	ipc_space_t                 space,
	ipc_port_t                  port,
	mach_msg_type_name_t        msgt_name,
	ipc_object_copyout_flags_t *flags,
	ipc_port_t                 *subst_portp)
{
	if (!ip_is_kolabeled(port)) {
		*subst_portp = IP_NULL;
		return true;
	}
	return ipc_kobject_label_check(space, port, msgt_name, flags, subst_portp);
}

/* implementation details */

__startup_func
extern void ipc_kobject_register_startup(
	ipc_kobject_ops_t           ops);

/* initialization of kobject subsystem */
extern void ipc_kobject_init(void);

/* Dispatch a kernel server function */
extern ipc_kmsg_t ipc_kobject_server(
	ipc_port_t                  receiver,
	ipc_kmsg_t                  request,
	mach_msg_option_t           option);

/* Release any kernel object resources associated with a port */
extern void ipc_kobject_destroy(
	ipc_port_t                  port);

#define null_conversion(port)   (port)

extern void ipc_kobject_notify_no_senders(
	ipc_port_t                  port,
	mach_port_mscount_t         mscount);

extern void ipc_kobject_notify_send_once_and_unlock(
	ipc_port_t                  port);

extern kern_return_t uext_server(
	ipc_port_t                  receiver,
	ipc_kmsg_t                  request,
	ipc_kmsg_t                  *reply);

#endif /* MACH_KERNEL_PRIVATE */

#pragma GCC visibility pop
__END_DECLS

#endif /* _KERN_IPC_KOBJECT_H_ */
