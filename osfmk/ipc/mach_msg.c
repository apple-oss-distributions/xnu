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
 * Copyright (c) 2005 SPARTA, Inc.
 */
/*
 */
/*
 *	File:	ipc/mach_msg.c
 *	Author:	Rich Draves
 *	Date:	1989
 *
 *	Exported message traps.  See mach/message.h.
 */

#include <mach/mach_types.h>
#include <mach/kern_return.h>
#include <mach/port.h>
#include <mach/message.h>
#include <mach/mig_errors.h>
#include <mach/mach_traps.h>

#include <kern/kern_types.h>
#include <kern/assert.h>
#include <kern/cpu_number.h>
#include <kern/ipc_kobject.h>
#include <kern/ipc_mig.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/sched_prim.h>
#include <kern/exception.h>
#include <kern/misc_protos.h>
#include <kern/processor.h>
#include <kern/syscall_subr.h>
#include <kern/policy_internal.h>
#include <kern/mach_filter.h>

#include <vm/vm_map.h>

#include <ipc/port.h>
#include <ipc/ipc_types.h>
#include <ipc/ipc_kmsg.h>
#include <ipc/ipc_mqueue.h>
#include <ipc/ipc_object.h>
#include <ipc/ipc_notify.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_pset.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_entry.h>
#include <ipc/ipc_importance.h>
#include <ipc/ipc_voucher.h>

#include <machine/machine_routines.h>
#include <security/mac_mach_internal.h>

#include <sys/kdebug.h>

#ifndef offsetof
#define offsetof(type, member)  ((size_t)(&((type *)0)->member))
#endif /* offsetof */

/*
 * Forward declarations - kernel internal routines
 */

static mach_msg_return_t msg_receive_error(
	ipc_kmsg_t              kmsg,
	mach_msg_option_t       option,
	mach_vm_address_t       rcv_addr,
	mach_msg_size_t         rcv_size,
	mach_port_seqno_t       seqno,
	ipc_space_t             space,
	mach_msg_size_t         *out_size);

static mach_msg_return_t
mach_msg_rcv_link_special_reply_port(
	ipc_port_t special_reply_port,
	mach_port_name_t dest_name_port);

void
mach_msg_receive_results_complete(ipc_object_t object);

const security_token_t KERNEL_SECURITY_TOKEN = KERNEL_SECURITY_TOKEN_VALUE;
const audit_token_t KERNEL_AUDIT_TOKEN = KERNEL_AUDIT_TOKEN_VALUE;

/*
 *	Routine:	mach_msg_receive_results
 *	Purpose:
 *		Receive a message.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		MACH_MSG_SUCCESS	Received a message.
 *		MACH_RCV_INVALID_NAME	The name doesn't denote a right,
 *			or the denoted right is not receive or port set.
 *		MACH_RCV_IN_SET		Receive right is a member of a set.
 *		MACH_RCV_TOO_LARGE	Message wouldn't fit into buffer.
 *		MACH_RCV_TIMED_OUT	Timeout expired without a message.
 *		MACH_RCV_INTERRUPTED	Reception interrupted.
 *		MACH_RCV_PORT_DIED	Port/set died while receiving.
 *		MACH_RCV_PORT_CHANGED	Port moved into set while receiving.
 *		MACH_RCV_INVALID_DATA	Couldn't copy to user buffer.
 *		MACH_RCV_INVALID_NOTIFY	Bad notify port.
 *		MACH_RCV_HEADER_ERROR
 */

mach_msg_return_t
mach_msg_receive_results(
	mach_msg_size_t *sizep)
{
	thread_t          self = current_thread();
	ipc_space_t       space = current_space();
	vm_map_t          map = current_map();

	ipc_object_t      object = self->ith_object;
	mach_msg_return_t mr = self->ith_state;
	mach_vm_address_t rcv_addr = self->ith_msg_addr;
	mach_msg_size_t   rcv_size = self->ith_rsize;
	mach_msg_option_t option = self->ith_option;
	ipc_kmsg_t        kmsg = self->ith_kmsg;
	mach_port_seqno_t seqno = self->ith_seqno;

	mach_msg_trailer_size_t trailer_size;
	mach_vm_address_t context;
	mach_msg_size_t   size = 0;

	/*
	 * unlink the special_reply_port before releasing reference to object.
	 * get the thread's turnstile, if the thread donated it's turnstile to the port
	 */
	mach_msg_receive_results_complete(object);
	io_release(object);

	if (mr != MACH_MSG_SUCCESS) {
		if (mr == MACH_RCV_TOO_LARGE) {
			/*
			 * If the receive operation occurs with MACH_RCV_LARGE set
			 * then no message was extracted from the queue, and the size
			 * and (optionally) receiver names were the only thing captured.
			 * Just copyout the size (and optional port name) in a fake
			 * header.
			 */
			if (option & MACH_RCV_LARGE) {
				if ((option & MACH_RCV_STACK) == 0 &&
				    rcv_size >= offsetof(mach_msg_user_header_t, msgh_reserved)) {
					/*
					 * We need to inform the user-level code that it needs more
					 * space.  The value for how much space was returned in the
					 * msize save area instead of the message (which was left on
					 * the queue).
					 */
					if (option & MACH_RCV_LARGE_IDENTITY) {
						if (copyout((char *) &self->ith_receiver_name,
						    rcv_addr + offsetof(mach_msg_user_header_t, msgh_local_port),
						    sizeof(mach_port_name_t))) {
							mr = MACH_RCV_INVALID_DATA;
						}
					}
					if (copyout((char *) &self->ith_msize,
					    rcv_addr + offsetof(mach_msg_user_header_t, msgh_size),
					    sizeof(mach_msg_size_t))) {
						mr = MACH_RCV_INVALID_DATA;
					}
				}
			} else {
				/* discard importance in message */
				ipc_importance_clean(kmsg);

				if (msg_receive_error(kmsg, option, rcv_addr, rcv_size, seqno, space, &size)
				    == MACH_RCV_INVALID_DATA) {
					mr = MACH_RCV_INVALID_DATA;
				}
			}
		}

		if (sizep) {
			*sizep = size;
		}
		return mr;
	}

	/* MACH_MSG_SUCCESS */

#if IMPORTANCE_INHERITANCE

	/* adopt/transform any importance attributes carried in the message */
	ipc_importance_receive(kmsg, option);

#endif  /* IMPORTANCE_INHERITANCE */

	/* auto redeem the voucher in the message */
	ipc_voucher_receive_postprocessing(kmsg, option);

	/* Save destination port context for the trailer before copyout */
	context = kmsg->ikm_header->msgh_remote_port->ip_context;

	mr = ipc_kmsg_copyout(kmsg, space, map, MACH_MSG_BODY_NULL, option);

	trailer_size = ipc_kmsg_trailer_size(option, self);

	if (mr != MACH_MSG_SUCCESS) {
		/* already received importance, so have to undo that here */
		ipc_importance_unreceive(kmsg, option);

		/* if we had a body error copyout what we have, otherwise a simple header/trailer */
		if ((mr & ~MACH_MSG_MASK) == MACH_RCV_BODY_ERROR) {
			ipc_kmsg_add_trailer(kmsg, space, option, self, seqno, FALSE, context);
			if (ipc_kmsg_put_to_user(kmsg, option, rcv_addr, rcv_size,
			    trailer_size, &size) == MACH_RCV_INVALID_DATA) {
				mr = MACH_RCV_INVALID_DATA;
			}
		} else {
			if (msg_receive_error(kmsg, option, rcv_addr, rcv_size, seqno, space, &size)
			    == MACH_RCV_INVALID_DATA) {
				mr = MACH_RCV_INVALID_DATA;
			}
		}
	} else {
		/* capture ksmg QoS values to the thread continuation state */
		self->ith_ppriority = kmsg->ikm_ppriority;
		self->ith_qos_override = kmsg->ikm_qos_override;
		ipc_kmsg_add_trailer(kmsg, space, option, self, seqno, FALSE, context);
		mr = ipc_kmsg_put_to_user(kmsg, option, rcv_addr, rcv_size,
		    trailer_size, &size);
	}

	if (sizep) {
		*sizep = size;
	}
	return mr;
}

void
mach_msg_receive_continue(void)
{
	mach_msg_return_t mr;
	thread_t self = current_thread();

	ipc_port_thread_group_unblocked();
	if (self->ith_state == MACH_PEEK_READY) {
		mr = MACH_PEEK_READY;
	} else {
		mr = mach_msg_receive_results(NULL);
	}
	(*self->ith_continuation)(mr);
}


/*
 *	Routine:	mach_msg_overwrite_trap [mach trap]
 *	Purpose:
 *		Possibly send a message; possibly receive a message.
 *	Conditions:
 *		Nothing locked.
 *		The 'priority' is only a QoS if MACH_SEND_OVERRIDE is passed -
 *		otherwise, it is a port name.
 *	Returns:
 *		All of mach_msg_send and mach_msg_receive error codes.
 */

mach_msg_return_t
mach_msg_overwrite_trap(
	struct mach_msg_overwrite_trap_args *args)
{
	mach_vm_address_t       msg_addr = args->msg;
	mach_msg_option_t       option = args->option;
	mach_msg_size_t         send_size = args->send_size;
	mach_msg_size_t         rcv_size = args->rcv_size;
	mach_port_name_t        rcv_name = args->rcv_name;
	mach_msg_timeout_t      msg_timeout = args->timeout;
	mach_msg_priority_t     priority = args->priority;
	mach_vm_address_t       rcv_msg_addr = args->rcv_msg;
	__unused mach_port_seqno_t temp_seqno = 0;

	mach_msg_return_t  mr = MACH_MSG_SUCCESS;
	vm_map_t map = current_map();

	/*
	 * Only accept options allowed by the user.  Extract user-only options up
	 * front, as they are not included in MACH_MSG_OPTION_USER.
	 */
	bool filter_nonfatal = (option & MACH_SEND_FILTER_NONFATAL);

	option &= MACH_MSG_OPTION_USER;

	if (option & MACH_SEND_MSG) {
		ipc_space_t space = current_space();
		ipc_kmsg_t kmsg;

		KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_START);

		mr = ipc_kmsg_get_from_user(msg_addr, send_size, &kmsg);

		if (mr != MACH_MSG_SUCCESS) {
			KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_END, mr);
			return mr;
		}

		KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_LINK) | DBG_FUNC_NONE,
		    (uintptr_t)msg_addr,
		    VM_KERNEL_ADDRPERM((uintptr_t)kmsg),
		    0, 0,
		    0);

		mr = ipc_kmsg_copyin_from_user(kmsg, space, map, priority, &option,
		    filter_nonfatal);

		if (mr != MACH_MSG_SUCCESS) {
			ipc_kmsg_free(kmsg);
			KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_END, mr);
			goto end;
		}

		mr = ipc_kmsg_send(kmsg, option, msg_timeout);

		if (mr != MACH_MSG_SUCCESS) {
			mr |= ipc_kmsg_copyout_pseudo(kmsg, space, map, MACH_MSG_BODY_NULL);
			(void) ipc_kmsg_put_to_user(kmsg, option, msg_addr, send_size, 0, NULL);
			KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_END, mr);
			goto end;
		}
	}

	if (option & MACH_RCV_MSG) {
		thread_t self = current_thread();
		ipc_space_t space = current_space();
		ipc_object_t object;

		mr = ipc_mqueue_copyin(space, rcv_name, &object);
		if (mr != MACH_MSG_SUCCESS) {
			goto end;
		}
		/* hold ref for object */

		/*
		 * Although just the presence of MACH_RCV_SYNC_WAIT and absence of
		 * MACH_SEND_OVERRIDE should imply that 'priority' is a valid port name
		 * to link, in practice older userspace is dependent on
		 * MACH_SEND_SYNC_OVERRIDE also excluding this path.
		 */
		if ((option & MACH_RCV_SYNC_WAIT) &&
		    !(option & (MACH_SEND_OVERRIDE | MACH_SEND_MSG)) &&
		    !(option & MACH_SEND_SYNC_OVERRIDE)) {
			ipc_port_t special_reply_port;
			special_reply_port = ip_object_to_port(object);
			/* link the special reply port to the destination */
			mr = mach_msg_rcv_link_special_reply_port(special_reply_port,
			    (mach_port_name_t)priority);
			if (mr != MACH_MSG_SUCCESS) {
				io_release(object);
				goto end;
			}
		}

		if (rcv_msg_addr != (mach_vm_address_t)0) {
			self->ith_msg_addr = rcv_msg_addr;
		} else {
			self->ith_msg_addr = msg_addr;
		}
		self->ith_object = object;
		self->ith_rsize = rcv_size;
		self->ith_msize = 0;
		self->ith_option = option;
		self->ith_receiver_name = MACH_PORT_NULL;
		self->ith_continuation = thread_syscall_return;
		self->ith_knote = ITH_KNOTE_NULL;

		ipc_mqueue_receive(io_waitq(object), option, rcv_size, msg_timeout,
		    THREAD_ABORTSAFE);
		if ((option & MACH_RCV_TIMEOUT) && msg_timeout == 0) {
			thread_poll_yield(self);
		}
		mr = mach_msg_receive_results(NULL);
		goto end;
	}

end:
	ipc_port_thread_group_unblocked();
	return mr;
}

/*
 *	Routine:	mach_msg_rcv_link_special_reply_port
 *	Purpose:
 *		Link the special reply port(rcv right) to the
 *		other end of the sync ipc channel.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		None.
 */
static mach_msg_return_t
mach_msg_rcv_link_special_reply_port(
	ipc_port_t special_reply_port,
	mach_port_name_t dest_name_port)
{
	ipc_port_t dest_port = IP_NULL;
	kern_return_t kr;

	if (current_thread()->ith_special_reply_port != special_reply_port) {
		return MACH_RCV_INVALID_NOTIFY;
	}

	/* Copyin the destination port */
	if (!MACH_PORT_VALID(dest_name_port)) {
		return MACH_RCV_INVALID_NOTIFY;
	}

	kr = ipc_port_translate_send(current_space(), dest_name_port, &dest_port);
	if (kr == KERN_SUCCESS) {
		ip_reference(dest_port);
		ip_mq_unlock(dest_port);

		/*
		 * The receive right of dest port might have gone away,
		 * do not fail the receive in that case.
		 */
		ipc_port_link_special_reply_port(special_reply_port,
		    dest_port, FALSE);

		ip_release(dest_port);
	}
	return MACH_MSG_SUCCESS;
}

/*
 *	Routine:	mach_msg_receive_results_complete
 *	Purpose:
 *		Get thread's turnstile back from the object and
 *              if object is a special reply port then reset its
 *		linkage.
 *	Condition:
 *		Nothing locked.
 *	Returns:
 *		None.
 */
void
mach_msg_receive_results_complete(ipc_object_t object)
{
	thread_t self = current_thread();
	ipc_port_t port = IPC_PORT_NULL;
	boolean_t get_turnstile = (self->turnstile == TURNSTILE_NULL);

	if (io_otype(object) == IOT_PORT) {
		port = ip_object_to_port(object);
	} else {
		assert(self->turnstile != TURNSTILE_NULL);
		return;
	}

	uint8_t flags = IPC_PORT_ADJUST_SR_ALLOW_SYNC_LINKAGE;

	/*
	 * Don't clear the ip_srp_msg_sent bit if...
	 */
	if (!((self->ith_state == MACH_RCV_TOO_LARGE && self->ith_option & MACH_RCV_LARGE) || //msg was too large and the next receive will get it
	    self->ith_state == MACH_RCV_INTERRUPTED ||
	    self->ith_state == MACH_RCV_TIMED_OUT ||
	    self->ith_state == MACH_RCV_PORT_CHANGED ||
	    self->ith_state == MACH_PEEK_READY)) {
		flags |= IPC_PORT_ADJUST_SR_RECEIVED_MSG;
	}

	if (port->ip_specialreply || get_turnstile) {
		ip_mq_lock(port);
		ipc_port_adjust_special_reply_port_locked(port, NULL,
		    flags, get_turnstile);
		/* port unlocked */
	}
	assert(self->turnstile != TURNSTILE_NULL);
	/* thread now has a turnstile */
}

/*
 *	Routine:	mach_msg_trap [mach trap]
 *	Purpose:
 *		Possibly send a message; possibly receive a message.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		All of mach_msg_send and mach_msg_receive error codes.
 */

mach_msg_return_t
mach_msg_trap(
	struct mach_msg_overwrite_trap_args *args)
{
	kern_return_t kr;
	args->rcv_msg = (mach_vm_address_t)0;

	kr = mach_msg_overwrite_trap(args);
	return kr;
}


/*
 *	Routine:	msg_receive_error	[internal]
 *	Purpose:
 *		Builds a minimal header/trailer and copies it to
 *		the user message buffer.  Invoked when in the case of a
 *		MACH_RCV_TOO_LARGE or MACH_RCV_BODY_ERROR error.
 *	Conditions:
 *		Nothing locked.
 *		size - maximum buffer size on input,
 *		       actual copied-out size on output
 *	Returns:
 *		MACH_MSG_SUCCESS	minimal header/trailer copied
 *		MACH_RCV_INVALID_DATA	copyout to user buffer failed
 */

static mach_msg_return_t
msg_receive_error(
	ipc_kmsg_t              kmsg,
	mach_msg_option_t       option,
	mach_vm_address_t       rcv_addr,
	mach_msg_size_t         rcv_size,
	mach_port_seqno_t       seqno,
	ipc_space_t             space,
	mach_msg_size_t         *sizep)
{
	mach_vm_address_t       context;
	mach_msg_trailer_size_t trailer_size;
	thread_t                self = current_thread();

	context = kmsg->ikm_header->msgh_remote_port->ip_context;

	/*
	 * Copy out the destination port in the message.
	 * Destroy all other rights and memory in the message.
	 */
	ipc_kmsg_copyout_dest_to_user(kmsg, space);

	/*
	 * Build a minimal message with the requested trailer.
	 */
	kmsg->ikm_header->msgh_size = sizeof(mach_msg_header_t);
	ipc_kmsg_init_trailer(kmsg, sizeof(mach_msg_header_t), TASK_NULL);

	trailer_size = ipc_kmsg_trailer_size(option, self);
	ipc_kmsg_add_trailer(kmsg, space, option, self,
	    seqno, TRUE, context);

	/*
	 * Copy the message to user space and return the size
	 * (note that ipc_kmsg_put_to_user may also adjust the actual
	 * size copied out to user-space).
	 */
	if (ipc_kmsg_put_to_user(kmsg, option, rcv_addr, rcv_size,
	    trailer_size, sizep) == MACH_RCV_INVALID_DATA) {
		return MACH_RCV_INVALID_DATA;
	} else {
		return MACH_MSG_SUCCESS;
	}
}


SECURITY_READ_ONLY_LATE(struct mach_msg_filter_callbacks) mach_msg_filter_callbacks;

kern_return_t
mach_msg_filter_register_callback(
	const struct mach_msg_filter_callbacks *callbacks)
{
	size_t size = 0;

	if (callbacks == NULL) {
		return KERN_INVALID_ARGUMENT;
	}
	if (mach_msg_filter_callbacks.fetch_filter_policy != NULL) {
		/* double init */
		return KERN_FAILURE;
	}

	if (callbacks->version >= MACH_MSG_FILTER_CALLBACKS_VERSION_0) {
		/* check for missing v0 callbacks */
		if (callbacks->fetch_filter_policy == NULL) {
			return KERN_INVALID_ARGUMENT;
		}
		size = offsetof(struct mach_msg_filter_callbacks, alloc_service_port_sblabel);
	}

	if (callbacks->version >= MACH_MSG_FILTER_CALLBACKS_VERSION_1) {
		if (callbacks->alloc_service_port_sblabel == NULL ||
		    callbacks->dealloc_service_port_sblabel == NULL ||
		    callbacks->derive_sblabel_from_service_port == NULL ||
		    callbacks->get_connection_port_filter_policy == NULL ||
		    callbacks->retain_sblabel == NULL) {
			return KERN_INVALID_ARGUMENT;
		}
		size = sizeof(struct mach_msg_filter_callbacks);
	}

	if (callbacks->version > MACH_MSG_FILTER_CALLBACKS_VERSION_1) {
		/* invalid version */
		return KERN_INVALID_ARGUMENT;
	}

	memcpy(&mach_msg_filter_callbacks, callbacks, size);
	return KERN_SUCCESS;
}

/* This function should only be called if the task and port allow message filtering */
boolean_t
mach_msg_fetch_filter_policy(
	void *port_label,
	mach_msg_id_t msgh_id,
	mach_msg_filter_id *fid)
{
	boolean_t ret = TRUE;

	if (mach_msg_fetch_filter_policy_callback == NULL) {
		*fid = MACH_MSG_FILTER_POLICY_ALLOW;
		return true;
	}
	ret = mach_msg_fetch_filter_policy_callback(current_task(), port_label, msgh_id, fid);

	return ret;
}
