/*
 * Copyright (c) 2000-2009 Apple Inc. All rights reserved.
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
 * Copyright (c) 1991,1990,1989,1988 Carnegie Mellon University
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
 *	kern/ipc_host.c
 *
 *	Routines to implement host ports.
 */
#include <mach/message.h>
#include <mach/mach_traps.h>
#include <mach/mach_host_server.h>
#include <mach/host_priv_server.h>
#include <kern/host.h>
#include <kern/processor.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/ipc_host.h>
#include <kern/ipc_kobject.h>
#include <kern/misc_protos.h>
#include <kern/spl.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_space.h>

#if CONFIG_MACF
#include <security/mac_mach_internal.h>
#endif

/*
 *	ipc_host_init: set up various things.
 */

extern lck_grp_t                host_notify_lock_grp;

IPC_KOBJECT_DEFINE(IKOT_HOST,
    .iko_op_stable    = true,
    .iko_op_permanent = true);
IPC_KOBJECT_DEFINE(IKOT_HOST_PRIV,
    .iko_op_stable    = true,
    .iko_op_permanent = true);

IPC_KOBJECT_DEFINE(IKOT_PROCESSOR,
    .iko_op_stable    = true,
    .iko_op_permanent = true);
IPC_KOBJECT_DEFINE(IKOT_PSET,
    .iko_op_stable    = true,
    .iko_op_permanent = true);
IPC_KOBJECT_DEFINE(IKOT_PSET_NAME,
    .iko_op_stable    = true,
    .iko_op_permanent = true);

void
ipc_host_init(void)
{
	ipc_port_t      port;
	int i;

	lck_mtx_init(&realhost.lock, &host_notify_lock_grp, LCK_ATTR_NULL);

	/*
	 *	Allocate and set up the two host ports.
	 */
	port = ipc_kobject_alloc_port((ipc_kobject_t) &realhost, IKOT_HOST,
	    IPC_KOBJECT_ALLOC_MAKE_SEND);
	kernel_set_special_port(&realhost, HOST_PORT, port);

	port = ipc_kobject_alloc_port((ipc_kobject_t) &realhost, IKOT_HOST_PRIV,
	    IPC_KOBJECT_ALLOC_MAKE_SEND);
	kernel_set_special_port(&realhost, HOST_PRIV_PORT, port);

	/* the rest of the special ports will be set up later */

	bzero(&realhost.exc_actions[0], sizeof(realhost.exc_actions[0]));
	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; i++) {
		realhost.exc_actions[i].port = IP_NULL;
		/* The mac framework is not yet initialized, so we defer
		 * initializing the labels to later, when they are set
		 * for the first time. */
		realhost.exc_actions[i].label = NULL;
		/* initialize the entire exception action struct */
		realhost.exc_actions[i].behavior = 0;
		realhost.exc_actions[i].flavor = 0;
		realhost.exc_actions[i].privileged = FALSE;
	} /* for */

	/*
	 *	Set up ipc for default processor set.
	 */
	ipc_pset_init(&pset0);

	/*
	 *	And for master processor
	 */
	ipc_processor_init(master_processor);
}

/*
 *	Routine:	host_self_trap [mach trap]
 *	Purpose:
 *		Give the caller send rights for his own host port.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		MACH_PORT_NULL if there are any resource failures
 *		or other errors.
 */

mach_port_name_t
host_self_trap(
	__unused struct host_self_trap_args *args)
{
	task_t self = current_task();
	ipc_port_t sright;
	mach_port_name_t name;

	itk_lock(self);
	sright = ipc_port_copy_send(self->itk_host);
	itk_unlock(self);
	name = ipc_port_copyout_send(sright, current_space());
	return name;
}

/*
 *	ipc_processor_init:
 *
 *	Initialize ipc access to processor by allocating port.
 */

void
ipc_processor_init(
	processor_t     processor)
{
	processor->processor_self = ipc_kobject_alloc_port(processor,
	    IKOT_PROCESSOR, IPC_KOBJECT_ALLOC_NONE);
}

/*
 *	ipc_pset_init:
 *
 *	Initialize ipc control of a processor set by allocating its ports.
 */

void
ipc_pset_init(
	processor_set_t         pset)
{
	pset->pset_self = ipc_kobject_alloc_port(pset,
	    IKOT_PSET, IPC_KOBJECT_ALLOC_NONE);
	pset->pset_name_self = ipc_kobject_alloc_port(pset,
	    IKOT_PSET_NAME, IPC_KOBJECT_ALLOC_NONE);
}

/*
 *	processor_set_default:
 *
 *	Return ports for manipulating default_processor set.
 */
kern_return_t
processor_set_default(
	host_t                  host,
	processor_set_t         *pset)
{
	if (host == HOST_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	*pset = &pset0;

	return KERN_SUCCESS;
}

/*
 *	Routine:	convert_port_to_host
 *	Purpose:
 *		Convert from a port to a host.
 *		Doesn't consume the port ref; the host produced may be null.
 *	Conditions:
 *		Nothing locked.
 */

host_t
convert_port_to_host(
	ipc_port_t      port)
{
	host_t host = HOST_NULL;
	ipc_kobject_type_t type;

	if (IP_VALID(port)) {
		type = ip_kotype(port);
		if (type == IKOT_HOST || type == IKOT_HOST_PRIV) {
			host = (host_t)ipc_kobject_get_stable(port, type);
			if (host && host != &realhost) {
				panic("unexpected host object: %p", host);
			}
		}
	}
	return host;
}

/*
 *	Routine:	convert_port_to_host_priv
 *	Purpose:
 *		Convert from a port to a host.
 *		Doesn't consume the port ref; the host produced may be null.
 *	Conditions:
 *		Nothing locked.
 */

host_t
convert_port_to_host_priv(
	ipc_port_t      port)
{
	host_t host = HOST_NULL;

	/* reject translation if itk_host is not host_priv */
	if (port != current_task()->itk_host) {
		return HOST_NULL;
	}

	if (IP_VALID(port)) {
		host = ipc_kobject_get_stable(port, IKOT_HOST_PRIV);
		if (host && host != &realhost) {
			panic("unexpected host object: %p", host);
		}
	}

	return host;
}

/*
 *	Routine:	convert_port_to_processor
 *	Purpose:
 *		Convert from a port to a processor.
 *		Doesn't consume the port ref;
 *		the processor produced may be null.
 *	Conditions:
 *		Nothing locked.
 */

processor_t
convert_port_to_processor(
	ipc_port_t      port)
{
	processor_t processor = PROCESSOR_NULL;

	if (IP_VALID(port)) {
		processor = ipc_kobject_get_stable(port, IKOT_PROCESSOR);
	}

	return processor;
}

/*
 *	Routine:	convert_port_to_pset
 *	Purpose:
 *		Convert from a port to a pset.
 *		Doesn't consume the port ref
 *		which may be null.
 *	Conditions:
 *		Nothing locked.
 */

processor_set_t
convert_port_to_pset(
	ipc_port_t      port)
{
	processor_set_t pset = PROCESSOR_SET_NULL;

	if (IP_VALID(port)) {
		pset = ipc_kobject_get_stable(port, IKOT_PSET);
	}

	return pset;
}

/*
 *	Routine:	convert_port_to_pset_name
 *	Purpose:
 *		Convert from a port to a pset.
 *		Doesn't consume the port ref
 *		which may be null.
 *	Conditions:
 *		Nothing locked.
 */

processor_set_name_t
convert_port_to_pset_name(
	ipc_port_t      port)
{
	processor_set_t pset = PROCESSOR_SET_NULL;
	ipc_kobject_type_t type;

	if (IP_VALID(port)) {
		type = ip_kotype(port);
		if (type == IKOT_PSET || type == IKOT_PSET_NAME) {
			pset = ipc_kobject_get_stable(port, type);
		}
	}
	return pset;
}

/*
 *	Routine:	convert_host_to_port
 *	Purpose:
 *		Convert from a host to a port.
 *		Produces a naked send right which may be invalid.
 *	Conditions:
 *		Nothing locked.
 */

ipc_port_t
convert_host_to_port(
	host_t          host)
{
	ipc_port_t port;

	host_get_host_port(host, &port);
	return port;
}

/*
 *	Routine:	convert_processor_to_port
 *	Purpose:
 *		Convert from a processor to a port.
 *		Produces a naked send right which may be invalid.
 *		Processors are not reference counted, so nothing to release.
 *	Conditions:
 *		Nothing locked.
 */

ipc_port_t
convert_processor_to_port(
	processor_t             processor)
{
	ipc_port_t port = processor->processor_self;

	if (port != IP_NULL) {
		port = ipc_port_make_send(port);
	}
	return port;
}

/*
 *	Routine:	convert_pset_to_port
 *	Purpose:
 *		Convert from a pset to a port.
 *		Produces a naked send right which may be invalid.
 *		Processor sets are not reference counted, so nothing to release.
 *	Conditions:
 *		Nothing locked.
 */

ipc_port_t
convert_pset_to_port(
	processor_set_t         pset)
{
	ipc_port_t port = pset->pset_self;

	if (port != IP_NULL) {
		port = ipc_port_make_send(port);
	}

	return port;
}

/*
 *	Routine:	convert_pset_name_to_port
 *	Purpose:
 *		Convert from a pset to a port.
 *		Produces a naked send right which may be invalid.
 *		Processor sets are not reference counted, so nothing to release.
 *	Conditions:
 *		Nothing locked.
 */

ipc_port_t
convert_pset_name_to_port(
	processor_set_name_t            pset)
{
	ipc_port_t port = pset->pset_name_self;

	if (port != IP_NULL) {
		port = ipc_port_make_send(port);
	}

	return port;
}

/*
 *	Routine:	host_set_exception_ports [kernel call]
 *	Purpose:
 *			Sets the host exception port, flavor and
 *			behavior for the exception types specified by the mask.
 *			There will be one send right per exception per valid
 *			port.
 *	Conditions:
 *		Nothing locked.  If successful, consumes
 *		the supplied send right.
 *	Returns:
 *		KERN_SUCCESS		Changed the special port.
 *		KERN_INVALID_ARGUMENT	The host_priv is not valid,
 *					Illegal mask bit set.
 *					Illegal exception behavior
 */
kern_return_t
host_set_exception_ports(
	host_priv_t                     host_priv,
	exception_mask_t                exception_mask,
	ipc_port_t                      new_port,
	exception_behavior_t            new_behavior,
	thread_state_flavor_t           new_flavor)
{
	int     i;
	ipc_port_t      old_port[EXC_TYPES_COUNT];

#if CONFIG_MACF
	struct label *deferred_labels[EXC_TYPES_COUNT];
	struct label *new_label;
#endif

	if (host_priv == HOST_PRIV_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if (exception_mask & ~EXC_MASK_VALID) {
		return KERN_INVALID_ARGUMENT;
	}

	if (IP_VALID(new_port)) {
		switch (new_behavior & ~MACH_EXCEPTION_MASK) {
		case EXCEPTION_DEFAULT:
		case EXCEPTION_STATE:
		case EXCEPTION_STATE_IDENTITY:
		case EXCEPTION_IDENTITY_PROTECTED:
			break;
		default:
			return KERN_INVALID_ARGUMENT;
		}
	}

	/*
	 * Check the validity of the thread_state_flavor by calling the
	 * VALID_THREAD_STATE_FLAVOR architecture dependent macro defined in
	 * osfmk/mach/ARCHITECTURE/thread_status.h
	 */
	if (new_flavor != 0 && !VALID_THREAD_STATE_FLAVOR(new_flavor)) {
		return KERN_INVALID_ARGUMENT;
	}

	if ((new_behavior & ~MACH_EXCEPTION_MASK) == EXCEPTION_IDENTITY_PROTECTED
	    && !(new_behavior & MACH_EXCEPTION_CODES)) {
		return KERN_INVALID_ARGUMENT;
	}

#if CONFIG_MACF
	if (mac_task_check_set_host_exception_ports(current_task(), exception_mask) != 0) {
		return KERN_NO_ACCESS;
	}

	new_label = mac_exc_create_label_for_current_proc();

	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; i++) {
		if (mac_exc_label(&host_priv->exc_actions[i]) == NULL) {
			deferred_labels[i] = mac_exc_create_label(&host_priv->exc_actions[i]);
		} else {
			deferred_labels[i] = NULL;
		}
	}
#endif

	host_lock(host_priv);

	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; i++) {
#if CONFIG_MACF
		if (mac_exc_label(&host_priv->exc_actions[i]) == NULL) {
			// Lazy initialization (see ipc_port_init).
			mac_exc_associate_action_label(&host_priv->exc_actions[i], deferred_labels[i]);
			deferred_labels[i] = NULL; // Label is used, do not free.
		}
#endif

		if ((exception_mask & (1 << i))
#if CONFIG_MACF
		    && mac_exc_update_action_label(&host_priv->exc_actions[i], new_label) == 0
#endif
		    ) {
			old_port[i] = host_priv->exc_actions[i].port;

			host_priv->exc_actions[i].port =
			    ipc_port_copy_send(new_port);
			host_priv->exc_actions[i].behavior = new_behavior;
			host_priv->exc_actions[i].flavor = new_flavor;
		} else {
			old_port[i] = IP_NULL;
		}
	}/* for */

	/*
	 * Consume send rights without any lock held.
	 */
	host_unlock(host_priv);

#if CONFIG_MACF
	mac_exc_free_label(new_label);
#endif

	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; i++) {
		if (IP_VALID(old_port[i])) {
			ipc_port_release_send(old_port[i]);
		}
#if CONFIG_MACF
		if (deferred_labels[i] != NULL) {
			/* Deferred label went unused: Another thread has completed the lazy initialization. */
			mac_exc_free_label(deferred_labels[i]);
		}
#endif
	}
	if (IP_VALID(new_port)) {        /* consume send right */
		ipc_port_release_send(new_port);
	}

	return KERN_SUCCESS;
}

/*
 *	Routine:	host_get_exception_ports [kernel call]
 *	Purpose:
 *		Clones a send right for each of the host's exception
 *		ports specified in the mask and returns the behaviour
 *		and flavor of said port.
 *
 *		Returns upto [in} CountCnt elements.
 *
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		Extracted a send right.
 *		KERN_INVALID_ARGUMENT	Invalid host_priv specified,
 *					Invalid special port,
 *					Illegal mask bit set.
 *		KERN_FAILURE		The thread is dead.
 */
kern_return_t
host_get_exception_ports(
	host_priv_t                     host_priv,
	exception_mask_t                exception_mask,
	exception_mask_array_t          masks,
	mach_msg_type_number_t          * CountCnt,
	exception_port_array_t          ports,
	exception_behavior_array_t      behaviors,
	thread_state_flavor_array_t     flavors         )
{
	unsigned int    i, j, count;

	if (host_priv == HOST_PRIV_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if (exception_mask & ~EXC_MASK_VALID) {
		return KERN_INVALID_ARGUMENT;
	}

	host_lock(host_priv);

	count = 0;

	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; i++) {
		if (exception_mask & (1 << i)) {
			for (j = 0; j < count; j++) {
/*
 *				search for an identical entry, if found
 *				set corresponding mask for this exception.
 */
				if (host_priv->exc_actions[i].port == ports[j] &&
				    host_priv->exc_actions[i].behavior == behaviors[j]
				    && host_priv->exc_actions[i].flavor == flavors[j]) {
					masks[j] |= (1 << i);
					break;
				}
			}/* for */
			if (j == count && count < *CountCnt) {
				masks[j] = (1 << i);
				ports[j] =
				    ipc_port_copy_send(host_priv->exc_actions[i].port);
				behaviors[j] = host_priv->exc_actions[i].behavior;
				flavors[j] = host_priv->exc_actions[i].flavor;
				count++;
			}
		}
	}/* for */
	host_unlock(host_priv);

	*CountCnt = count;
	return KERN_SUCCESS;
}

kern_return_t
host_swap_exception_ports(
	host_priv_t                     host_priv,
	exception_mask_t                exception_mask,
	ipc_port_t                      new_port,
	exception_behavior_t            new_behavior,
	thread_state_flavor_t           new_flavor,
	exception_mask_array_t          masks,
	mach_msg_type_number_t          * CountCnt,
	exception_port_array_t          ports,
	exception_behavior_array_t      behaviors,
	thread_state_flavor_array_t     flavors         )
{
	unsigned int    i,
	    j,
	    count;
	ipc_port_t      old_port[EXC_TYPES_COUNT];

#if CONFIG_MACF
	struct label *deferred_labels[EXC_TYPES_COUNT];
	struct label *new_label;
#endif

	if (host_priv == HOST_PRIV_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if (exception_mask & ~EXC_MASK_VALID) {
		return KERN_INVALID_ARGUMENT;
	}

	if (IP_VALID(new_port)) {
		switch (new_behavior & ~MACH_EXCEPTION_MASK) {
		case EXCEPTION_DEFAULT:
		case EXCEPTION_STATE:
		case EXCEPTION_STATE_IDENTITY:
		case EXCEPTION_IDENTITY_PROTECTED:
			break;
		default:
			return KERN_INVALID_ARGUMENT;
		}
	}

	if (new_flavor != 0 && !VALID_THREAD_STATE_FLAVOR(new_flavor)) {
		return KERN_INVALID_ARGUMENT;
	}

	if ((new_behavior & ~MACH_EXCEPTION_MASK) == EXCEPTION_IDENTITY_PROTECTED
	    && !(new_behavior & MACH_EXCEPTION_CODES)) {
		return KERN_INVALID_ARGUMENT;
	}

#if CONFIG_MACF
	if (mac_task_check_set_host_exception_ports(current_task(), exception_mask) != 0) {
		return KERN_NO_ACCESS;
	}

	new_label = mac_exc_create_label_for_current_proc();

	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; i++) {
		if (mac_exc_label(&host_priv->exc_actions[i]) == NULL) {
			deferred_labels[i] = mac_exc_create_label(&host_priv->exc_actions[i]);
		} else {
			deferred_labels[i] = NULL;
		}
	}
#endif /* CONFIG_MACF */

	host_lock(host_priv);

	assert(EXC_TYPES_COUNT > FIRST_EXCEPTION);
	for (count = 0, i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT && count < *CountCnt; i++) {
#if CONFIG_MACF
		if (mac_exc_label(&host_priv->exc_actions[i]) == NULL) {
			// Lazy initialization (see ipc_port_init).
			mac_exc_associate_action_label(&host_priv->exc_actions[i], deferred_labels[i]);
			deferred_labels[i] = NULL; // Label is used, do not free.
		}
#endif

		if ((exception_mask & (1 << i))
#if CONFIG_MACF
		    && mac_exc_update_action_label(&host_priv->exc_actions[i], new_label) == 0
#endif
		    ) {
			for (j = 0; j < count; j++) {
/*
 *				search for an identical entry, if found
 *				set corresponding mask for this exception.
 */
				if (host_priv->exc_actions[i].port == ports[j] &&
				    host_priv->exc_actions[i].behavior == behaviors[j]
				    && host_priv->exc_actions[i].flavor == flavors[j]) {
					masks[j] |= (1 << i);
					break;
				}
			}/* for */
			if (j == count) {
				masks[j] = (1 << i);
				ports[j] =
				    ipc_port_copy_send(host_priv->exc_actions[i].port);
				behaviors[j] = host_priv->exc_actions[i].behavior;
				flavors[j] = host_priv->exc_actions[i].flavor;
				count++;
			}
			old_port[i] = host_priv->exc_actions[i].port;
			host_priv->exc_actions[i].port =
			    ipc_port_copy_send(new_port);
			host_priv->exc_actions[i].behavior = new_behavior;
			host_priv->exc_actions[i].flavor = new_flavor;
		} else {
			old_port[i] = IP_NULL;
		}
	}/* for */
	host_unlock(host_priv);

#if CONFIG_MACF
	mac_exc_free_label(new_label);
#endif

	/*
	 * Consume send rights without any lock held.
	 */
	while (--i >= FIRST_EXCEPTION) {
		if (IP_VALID(old_port[i])) {
			ipc_port_release_send(old_port[i]);
		}
#if CONFIG_MACF
		if (deferred_labels[i] != NULL) {
			mac_exc_free_label(deferred_labels[i]); // Label unused.
		}
#endif
	}

	if (IP_VALID(new_port)) {        /* consume send right */
		ipc_port_release_send(new_port);
	}
	*CountCnt = count;

	return KERN_SUCCESS;
}
