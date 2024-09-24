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
 *  File:   ipc/mach_msg.c
 *  Author: Rich Draves
 *  Date:   1989
 *
 *  Exported message traps.  See mach/message.h.
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

#include <vm/vm_map_xnu.h>

#include <ipc/port.h>
#include <ipc/ipc_types.h>
#include <ipc/ipc_kmsg.h>
#include <ipc/ipc_mqueue.h>
#include <ipc/ipc_object.h>
#include <ipc/ipc_notify.h>
#include <ipc/ipc_policy.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_pset.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_entry.h>
#include <ipc/ipc_importance.h>
#include <ipc/ipc_voucher.h>

#include <machine/machine_routines.h>
#include <security/mac_mach_internal.h>

#include <sys/kdebug.h>
#include <sys/proc_ro.h>

#ifndef offsetof
#define offsetof(type, member)  ((size_t)(&((type *)0)->member))
#endif /* offsetof */

/*
 * Forward declarations - kernel internal routines
 */

static mach_msg_return_t
mach_msg_rcv_link_special_reply_port(
	ipc_port_t special_reply_port,
	mach_port_name_t dest_name_port);

void
mach_msg_receive_results_complete(ipc_object_t object);

const security_token_t KERNEL_SECURITY_TOKEN = KERNEL_SECURITY_TOKEN_VALUE;
const audit_token_t KERNEL_AUDIT_TOKEN = KERNEL_AUDIT_TOKEN_VALUE;

#define mach_copyout_field(kaddr, uaddr, type_t, field) \
	mach_copyout((kaddr), (uaddr) + offsetof(type_t, field), \
	    sizeof(((type_t *)0)->field))

/*
 *	Routine:	mach_msg_receive_too_large()
 *	Purpose:
 *		Helper for mach_msg_receive_results() to handle
 *		the MACH_RCV_TOO_LARGE error when the MACH64_RCV_LARGE
 *		option is set.
 *	Returns:
 *		MACH_RCV_INVALID_DATA or the passed in mr.
 */
static mach_msg_return_t
mach_msg_receive_too_large(
	mach_msg_recv_bufs_t   *recv_bufs,
	mach_msg_recv_result_t *msgr,
	mach_msg_option64_t     options,
	mach_msg_return_t       mr)
{
	assert(mr == MACH_RCV_TOO_LARGE);
	assert(options & MACH_RCV_LARGE);

	if (options & MACH64_RCV_LINEAR_VECTOR) {
		/*
		 * If MACH64_RCV_LINEAR_VECTOR is set, kevent is calling
		 * from filt_machportprocess() and the reporting of name
		 * and sizes happen via the knote in filt_machportprocess()
		 * rather than a receive operation, there's nothing for us
		 * to do here.
		 */
		return mr;
	}

	/*
	 * For the regular case, just copyout the size
	 * (and optional port name) in a fake header.
	 */
	if ((options & MACH64_RCV_LARGE_IDENTITY) &&
	    recv_bufs->recv_msg_size >=
	    offsetof(mach_msg_user_header_t, msgh_voucher_port)) {
		/*
		 * If MACH64_RCV_LARGE_IDENTITY is set,
		 * we monkey patch the msgh_local_port field.
		 */
		if (mach_copyout_field(&msgr->msgr_recv_name,
		    recv_bufs->recv_msg_addr,
		    mach_msg_user_header_t, msgh_local_port)) {
			mr = MACH_RCV_INVALID_DATA;
		}
	}

	if (recv_bufs->recv_msg_size >=
	    offsetof(mach_msg_user_header_t, msgh_remote_port)) {
		/*
		 * For all cases, we monkey patch the msgh_size
		 * field with how much size is needed.
		 */
		if (mach_copyout_field(&msgr->msgr_msg_size,
		    recv_bufs->recv_msg_addr,
		    mach_msg_user_header_t, msgh_size)) {
			mr = MACH_RCV_INVALID_DATA;
		}
	}

	if (recv_bufs->recv_aux_addr) {
		/*
		 * Then we report the incoming aux size as well,
		 * if the caller has an aux buffer.
		 */
		assert(recv_bufs->recv_aux_size >= sizeof(mach_msg_aux_header_t));
		if (mach_copyout_field(&msgr->msgr_aux_size,
		    recv_bufs->recv_aux_addr,
		    mach_msg_aux_header_t, msgdh_size)) {
			mr = MACH_RCV_INVALID_DATA;
		}
	}

	return mr;
}

/*
 *  Routine:    mach_msg_receive_error   [internal]
 *  Purpose:
 *      Builds a minimal header/trailer and copies it to
 *      the user message buffer.  Invoked when in the case of a
 *      MACH_RCV_TOO_LARGE or MACH_RCV_BODY_ERROR error.
 *  Conditions:
 *      Nothing locked. kmsg is freed upon return.
 *  Returns:
 *      the incoming "mr"       minimal header/trailer copied
 *      MACH_RCV_INVALID_DATA   copyout to user buffer failed
 */
static mach_msg_return_t
mach_msg_receive_error(
	ipc_kmsg_t              kmsg,
	mach_msg_recv_bufs_t   *recv_bufs,
	mach_msg_recv_result_t *msgr,
	mach_msg_option64_t     options,
	ipc_space_t             space,
	vm_map_t                map,
	mach_msg_return_t       mr)
{
	/*
	 * Copy out the destination port in the message.
	 *
	 * Destroy all other rights and memory in the message,
	 * and turn it into a very simple bare message with just a header.
	 */
	ipc_kmsg_copyout_dest_to_user(kmsg, space);

	/*
	 * Copy the message to user space and return the size
	 * (note that ipc_kmsg_put_to_user may also adjust the actual
	 * msg and aux size copied out to user-space).
	 */
	return ipc_kmsg_put_to_user(kmsg, recv_bufs, msgr, options, map, mr);
}

/*
 *  Routine:    mach_msg_receive_results
 *  Purpose:
 *      Receive a message.
 *  Conditions:
 *      Nothing locked.
 *
 *  Returns:
 *          sizep (out): copied out size of message proper
 *          aux_sizep (out): copied out size of aux data
 *      MACH_MSG_SUCCESS    Received a message.
 *      MACH_RCV_INVALID_NAME   The name doesn't denote a right,
 *          or the denoted right is not receive or port set.
 *      MACH_RCV_IN_SET     Receive right is a member of a set.
 *      MACH_RCV_TOO_LARGE  Message wouldn't fit into buffer.
 *      MACH_RCV_TIMED_OUT  Timeout expired without a message.
 *      MACH_RCV_INTERRUPTED    Reception interrupted.
 *      MACH_RCV_PORT_DIED  Port/set died while receiving.
 *      MACH_RCV_PORT_CHANGED   Port moved into set while receiving.
 *      MACH_RCV_INVALID_DATA   Couldn't copy to user buffer.
 *      MACH_RCV_INVALID_NOTIFY Bad notify port.
 *      MACH_RCV_HEADER_ERROR
 */
mach_msg_return_t
mach_msg_receive_results(
	mach_msg_recv_result_t *msgr_out)
{
	thread_t                self    = current_thread();
	ipc_space_t             space   = current_space();
	vm_map_t                map     = current_map();

	/*
	 * /!\IMPORTANT/!\: Pull out values we stashed on thread struct now.
	 * Values may be stomped over if copyio operations in this function
	 * trigger kernel IPC calls.
	 */
	ipc_object_t            object  = self->ith_object;
	mach_msg_return_t       mr      = self->ith_state;
	mach_msg_option64_t     options = self->ith_option;
	ipc_kmsg_t              kmsg    = self->ith_kmsg;

	mach_msg_recv_bufs_t recv_bufs = self->ith_recv_bufs;
	mach_msg_recv_result_t msgr = {
		.msgr_seqno     = self->ith_seqno,
		.msgr_context   = 0,
	};

	/*
	 * unlink the special_reply_port before releasing reference to object.
	 * get the thread's turnstile, if the thread donated it's turnstile to the port
	 */
	mach_msg_receive_results_complete(object);
	io_release(object);

	if (options & MACH64_RCV_LINEAR_VECTOR) {
		assert(recv_bufs.recv_aux_addr == 0);
		assert(recv_bufs.recv_aux_size == 0);
	}

	if (mr == MACH_RCV_TOO_LARGE) {
		/* these ith_* fields are only set for MACH_RCV_TOO_LARGE */
		msgr.msgr_msg_size  = self->ith_msize;
		msgr.msgr_aux_size  = self->ith_asize;
		msgr.msgr_recv_name = self->ith_receiver_name;

		/*
		 * If the receive operation occurs with MACH_RCV_LARGE set
		 * then no message was extracted from the queue, and the size
		 * and (optionally) receiver names were the only thing captured.
		 */
		if (options & MACH64_RCV_LARGE) {
			mr = mach_msg_receive_too_large(&recv_bufs, &msgr,
			    options, mr);
		} else {
			/* discard importance in message */
			ipc_importance_clean(kmsg);
			mr = mach_msg_receive_error(kmsg, &recv_bufs, &msgr,
			    options, space, map, mr);
			/* kmsg freed */
		}
	}
	if (mr != MACH_MSG_SUCCESS) {
		goto out;
	}

#if IMPORTANCE_INHERITANCE

	/* adopt/transform any importance attributes carried in the message */
	ipc_importance_receive(kmsg, options);

#endif  /* IMPORTANCE_INHERITANCE */

	/* auto redeem the voucher in the message */
	ipc_voucher_receive_postprocessing(kmsg, options);

	/* Save destination port context for the trailer before copyout */
	msgr.msgr_context = ikm_header(kmsg)->msgh_remote_port->ip_context;

	/*
	 * restore the recv_bufs values that are used by
	 * ipc_kmsg_copyout_guarded_port_descriptor()
	 */
	self->ith_recv_bufs = recv_bufs;
	mr = ipc_kmsg_copyout(kmsg, space, map, options);

	if (mr != MACH_MSG_SUCCESS) {
		/* already received importance, so have to undo that here */
		ipc_importance_unreceive(kmsg, options);

		/* if we had a body error copyout what we have, otherwise a simple header/trailer */
		if ((mr & ~MACH_MSG_MASK) == MACH_RCV_BODY_ERROR) {
			mr = ipc_kmsg_put_to_user(kmsg, &recv_bufs, &msgr,
			    options, map, mr);
		} else {
			mr = mach_msg_receive_error(kmsg, &recv_bufs, &msgr,
			    options, space, map, mr);
		}
	} else {
		msgr.msgr_priority = kmsg->ikm_ppriority;
		msgr.msgr_qos_ovrd = kmsg->ikm_qos_override;
		mr = ipc_kmsg_put_to_user(kmsg, &recv_bufs, &msgr,
		    options, map, mr);
	}
	/* kmsg freed */

out:
	if (msgr_out) {
		*msgr_out = msgr;
	}
	return mr;
}

void
mach_msg_receive_continue(void)
{
	mach_msg_return_t mr;

	ipc_port_thread_group_unblocked();

#if MACH_FLIPC
	if (current_thread()->ith_state == MACH_PEEK_READY) {
		thread_syscall_return(MACH_PEEK_READY);
		__builtin_unreachable();
	}
#endif /* MACH_FLIPC */

	mr = mach_msg_receive_results(NULL);
	thread_syscall_return(mr);
}

/*
 *  Routine:    mach_msg_validate_data_vectors
 *  Purpose:
 *      Perform validations on message and auxiliary data vectors
 *      we have copied in.
 */
static mach_msg_return_t
mach_msg_validate_data_vectors(
	mach_msg_vector_t       *msg_vec,
	mach_msg_vector_t       *aux_vec,
	mach_msg_size_t         vec_count,
	__unused mach_msg_option64_t     option64,
	bool                    sending)
{
	mach_msg_size_t msg_size = 0, aux_size = 0; /* user size */

	assert(vec_count <= MACH_MSGV_MAX_COUNT);
	assert(option64 & MACH64_MSG_VECTOR);

	assert(msg_vec != NULL);
	assert(aux_vec != NULL);

	if (vec_count == 0) {
		/*
		 * can't use MACH_RCV_TOO_LARGE or MACH_RCV_INVALID_DATA here because
		 * they imply a message has been dropped. use a new error code that
		 * suggests an early error and that message is still queued.
		 */
		return sending ? MACH_SEND_MSG_TOO_SMALL : MACH_RCV_INVALID_ARGUMENTS;
	}

	/*
	 * Validate first (message proper) data vector.
	 *
	 * Since we are using mach_msg2_trap() to shim existing mach_msg() calls,
	 * we unfortunately cannot validate message rcv address or message rcv size
	 * at this point for compatibility reasons.
	 *
	 * (1) If rcv address is invalid, we will destroy the incoming message during
	 * ipc_kmsg_put_to_user(), instead of returning an error before receive
	 * is attempted.
	 * (2) If rcv size is smaller than the minimal message header and trailer
	 * that mach_msg_receive_error() builds, we will truncate the message
	 * and copy out a partial message.
	 *
	 * See: ipc_kmsg_put_vector_to_user().
	 */
	if (sending) {
		if (msg_vec->msgv_data == 0) {
			return MACH_SEND_INVALID_DATA;
		}
		msg_size = msg_vec->msgv_send_size;
		if ((msg_size < sizeof(mach_msg_user_header_t)) || (msg_size & 3)) {
			return MACH_SEND_MSG_TOO_SMALL;
		}
		if (msg_size > IPC_KMSG_MAX_BODY_SPACE) {
			return MACH_SEND_TOO_LARGE;
		}
	}

	/* Validate second (optional auxiliary) data vector */
	if (vec_count == MACH_MSGV_MAX_COUNT) {
		if (sending) {
			aux_size = aux_vec->msgv_send_size;
			if (aux_size != 0 && aux_vec->msgv_data == 0) {
				return MACH_SEND_INVALID_DATA;
			}
			if (aux_size != 0 && aux_size < sizeof(mach_msg_aux_header_t)) {
				return MACH_SEND_AUX_TOO_SMALL;
			}
			if (aux_size > IPC_KMSG_MAX_AUX_DATA_SPACE) {
				return MACH_SEND_AUX_TOO_LARGE;
			}
		} else {
			mach_vm_address_t rcv_addr = aux_vec->msgv_rcv_addr ?
			    aux_vec->msgv_rcv_addr : aux_vec->msgv_data;

			if (rcv_addr == 0) {
				return MACH_RCV_INVALID_ARGUMENTS;
			}
			/*
			 * We are using this aux vector to receive, kernel will at
			 * least copy out an empty aux data header.
			 *
			 * See: ipc_kmsg_put_vector_to_user()
			 */
			aux_size = aux_vec->msgv_rcv_size;
			if (aux_size < sizeof(mach_msg_aux_header_t)) {
				return MACH_RCV_INVALID_ARGUMENTS;
			}
		}
	} else {
		if (sending) {
			/*
			 * Not sending aux data vector, but we still might have copied it
			 * in if doing a combined send/receive. Nil out the send size.
			 */
			aux_vec->msgv_send_size = 0;
		} else {
			/* Do the same for receive */
			aux_vec->msgv_rcv_size = 0;
		}
	}

	return MACH_MSG_SUCCESS;
}

/*
 *  Routine:    mach_msg_copyin_data_vectors
 *  Purpose:
 *      Copy in and message user data vectors.
 */
static mach_msg_return_t
mach_msg_copyin_data_vectors(
	mach_vm_address_t   data_addr,/* user address */
	mach_msg_size_t     cpin_count,
	mach_msg_option64_t option64,
	mach_msg_vector_t   *msg_vecp,/* out */
	mach_msg_vector_t   *aux_vecp)/* out */
{
	mach_msg_vector_t data_vecs[MACH_MSGV_MAX_COUNT] = {};

	static_assert(MACH_MSGV_MAX_COUNT == 2);
	assert(option64 & MACH64_MSG_VECTOR);

	if (cpin_count > MACH_MSGV_MAX_COUNT) {
		return (option64 & MACH64_SEND_MSG) ?
		       MACH_SEND_INVALID_DATA : MACH_RCV_INVALID_ARGUMENTS;
	}

	if (cpin_count == 0) {
		return (option64 & MACH64_SEND_MSG) ?
		       MACH_SEND_MSG_TOO_SMALL : MACH_RCV_INVALID_ARGUMENTS;
	}

	if (mach_copyin(data_addr, data_vecs,
	    cpin_count * sizeof(mach_msg_vector_t))) {
		return (option64 & MACH64_SEND_MSG) ?
		       MACH_SEND_INVALID_DATA : MACH_RCV_INVALID_ARGUMENTS;
	}

	memcpy(msg_vecp, &data_vecs[MACH_MSGV_IDX_MSG], sizeof(mach_msg_vector_t));

	if (cpin_count == MACH_MSGV_MAX_COUNT) {
		memcpy(aux_vecp, &data_vecs[MACH_MSGV_IDX_AUX], sizeof(mach_msg_vector_t));
	}

	return MACH_MSG_SUCCESS;
}

#if IPC_HAS_LEGACY_MACH_MSG_TRAP
/*
 *  Routine:    mach_msg_copyin_user_header
 *  Purpose:
 *      Copy in the message header, or up until message body if message is
 *      large enough. Returns the header of the message and number of descriptors.
 *      Used for mach_msg_overwrite_trap() only. Not available on embedded.
 *  Returns:
 *      MACH_MSG_SUCCESS - Copyin succeeded, msg_addr and msg_size are validated.
 *      MACH_SEND_MSG_TOO_SMALL
 *      MACH_SEND_TOO_LARGE
 *      MACH_SEND_INVALID_DATA
 */
static mach_msg_return_t
mach_msg_copyin_user_header(
	mach_msg_send_uctx_t   *send_uctx,
	mach_msg_option64_t     options)
{
	mach_msg_return_t       mr = MACH_MSG_SUCCESS;

	if (send_uctx->send_msg_size < sizeof(mach_msg_user_header_t) ||
	    (send_uctx->send_msg_size & 3)) {
		return MACH_SEND_MSG_TOO_SMALL;
	}

	if (send_uctx->send_msg_size > IPC_KMSG_MAX_BODY_SPACE) {
		return MACH_SEND_TOO_LARGE;
	}

	if (send_uctx->send_msg_size < sizeof(mach_msg_user_base_t)) {
		static_assert(offsetof(mach_msg_send_uctx_t, send_dsc_count) ==
		    offsetof(mach_msg_user_base_t, body.msgh_descriptor_count));

		mr = copyinmsg(send_uctx->send_msg_addr,
		    &send_uctx->send_header, sizeof(mach_msg_user_header_t));
	} else {
		mr = copyinmsg(send_uctx->send_msg_addr,
		    &send_uctx->send_header, sizeof(mach_msg_user_base_t));
	}
	if (mr != KERN_SUCCESS) {
		return MACH_SEND_INVALID_DATA;
	}

	/*
	 * If the message claims to be complex, it must at least
	 * have the length of a "base" message (header + dsc_count).
	 */
	if (send_uctx->send_header.msgh_bits & MACH_MSGH_BITS_COMPLEX) {
		if (send_uctx->send_msg_size < sizeof(mach_msg_user_base_t)) {
			return MACH_SEND_MSG_TOO_SMALL;
		}
	} else {
		send_uctx->send_dsc_count = 0;
	}
	send_uctx->send_header.msgh_size = send_uctx->send_msg_size;

	return ipc_policy_allow_legacy_send_trap(send_uctx->send_header.msgh_id,
	           options);
}
#endif /* IPC_HAS_LEGACY_MACH_MSG_TRAP */


__attribute__((noinline, cold))
static mach_msg_return_t
mach_msg_receive_pseudo(
	ipc_kmsg_t              kmsg,
	mach_msg_send_uctx_t   *send_uctx,
	mach_msg_option64_t     options,
	ipc_space_t             space,
	vm_map_t                map)
{
	mach_msg_recv_bufs_t recv_bufs = {
		.recv_msg_addr  = send_uctx->send_msg_addr,
		.recv_aux_addr  = send_uctx->send_aux_addr,
		.recv_msg_size  = send_uctx->send_msg_size,
		.recv_aux_size  = send_uctx->send_aux_size,
	};
	mach_msg_recv_result_t msgr = {
		.msgr_recv_name = MSGR_PSEUDO_RECEIVE,
	};
	mach_msg_return_t mr;

	/*
	 * set the recv_bufs values that are used by
	 * ipc_kmsg_copyout_guarded_port_descriptor()
	 */
	current_thread()->ith_recv_bufs = recv_bufs;
	mr = ipc_kmsg_copyout_pseudo(kmsg, space, map);
	(void)ipc_kmsg_put_to_user(kmsg, &recv_bufs, &msgr, options, map, mr);
	return mr;
}

/*
 *  Routine:    mach_msg_trap_send [internal]
 *  Purpose:
 *      Send a message.
 *  Conditions:
 *      MACH_SEND_MSG is set. aux_send_size is bound checked.
 *      send_aux_{addr, size} are 0 if not vector send.
 *      send_msg_size needs additional bound checks.
 *  Returns:
 *      All of mach_msg_send error codes.
 */
static mach_msg_return_t
mach_msg_trap_send(
	/* shared args between send and receive */
	mach_msg_send_uctx_t   *send_uctx,
	mach_msg_option64_t     options,
	mach_msg_timeout_t      msg_timeout,
	mach_msg_priority_t     priority)
{
	ipc_space_t       space = current_space();
	vm_map_t          map = current_map();
	ipc_kmsg_t        kmsg;
	mach_msg_return_t mr;

	assert(options & MACH64_SEND_MSG);

	/*
	 * Validate the send sizes and header carefuly.
	 */
	if (send_uctx->send_msg_size < sizeof(mach_msg_user_header_t) ||
	    (send_uctx->send_msg_size & 3)) {
		return MACH_SEND_MSG_TOO_SMALL;
	}
	if (send_uctx->send_msg_size > IPC_KMSG_MAX_BODY_SPACE) {
		return MACH_SEND_TOO_LARGE;
	}
	/*
	 * Complex message must have a body, also do a bound check on descriptor count
	 * (more in ikm_check_descriptors()).
	 */
	if (send_uctx->send_header.msgh_bits & MACH_MSGH_BITS_COMPLEX) {
		if (send_uctx->send_msg_size < sizeof(mach_msg_user_base_t)) {
			return MACH_SEND_MSG_TOO_SMALL;
		}
		if (send_uctx->send_dsc_count >
		    (send_uctx->send_msg_size - sizeof(mach_msg_user_base_t)) /
		    sizeof(mach_msg_type_descriptor_t)) {
			return MACH_SEND_MSG_TOO_SMALL;
		}
	} else if (send_uctx->send_dsc_count != 0) {
		/*
		 * Simple message cannot contain descriptors.
		 *
		 * This invalid config can only happen from mach_msg2_trap()
		 * since desc_count is passed as its own trap argument.
		 */
		assert(options & MACH64_MACH_MSG2);
		return MACH_SEND_TOO_LARGE;
	}

	/*
	 * Now that we have validated send_msg_size, send_aux_size and
	 * send_dsc_count, copy in the message.
	 */
	kmsg = ipc_kmsg_alloc(send_uctx->send_msg_size, send_uctx->send_aux_size,
	    send_uctx->send_dsc_count, IPC_KMSG_ALLOC_USER);
	if (kmsg == IKM_NULL) {
		return MACH_SEND_NO_BUFFER;
	}

	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_LINK) | DBG_FUNC_NONE,
	    (uintptr_t)send_uctx->send_msg_addr, VM_KERNEL_ADDRPERM((uintptr_t)kmsg),
	    0, 0, 0);

	/*
	 * holding kmsg ref
	 * may add MACH64_SEND_ALWAYS to options
	 */
	mr = ipc_kmsg_copyin_from_user(kmsg, send_uctx, space, map, priority, &options);
	if (mr != MACH_MSG_SUCCESS) {
		ipc_kmsg_free(kmsg);
		return mr;
	}

	mr = ipc_kmsg_send(kmsg, options, msg_timeout);

	if (mr != MACH_MSG_SUCCESS) {
		mr |= mach_msg_receive_pseudo(kmsg, send_uctx, options, space, map);
		/* kmsg is freed */
	}

	return mr;
}

/*
 *  Routine:    mach_msg_trap_receive [internal]
 *  Purpose:
 *      Receive a message.
 *  Conditions:
 *      MACH_RCV_MSG is set.
 *      max_{msg, aux}_rcv_size are already validated.
 *  Returns:
 *      All of mach_msg_receive error codes.
 */
static mach_msg_return_t
mach_msg_trap_receive(
	/* shared args between send and receive */
	mach_vm_address_t   msg_addr,
	mach_vm_address_t   aux_addr,        /* 0 if not vector send/rcv */
	mach_msg_option64_t option64,
	mach_msg_timeout_t  msg_timeout,
	mach_port_name_t    sync_send,
	/* msg receive args */
	mach_msg_size_t     max_msg_rcv_size,
	mach_msg_size_t     max_aux_rcv_size,        /* 0 if not vector send/rcv */
	mach_port_name_t    rcv_name)
{
	ipc_object_t object;

	thread_t           self = current_thread();
	ipc_space_t        space = current_space();
	mach_msg_return_t  mr = MACH_MSG_SUCCESS;

	assert(option64 & MACH64_RCV_MSG);

	mr = ipc_mqueue_copyin(space, rcv_name, &object);
	if (mr != MACH_MSG_SUCCESS) {
		return mr;
	}
	/* hold ref for object */

	if (sync_send != MACH_PORT_NULL) {
		ipc_port_t special_reply_port = ip_object_to_port(object);
		/* link the special reply port to the destination */
		mr = mach_msg_rcv_link_special_reply_port(special_reply_port, sync_send);
		if (mr != MACH_MSG_SUCCESS) {
			io_release(object);
			return mr;
		}
	}

	/* Set up message proper receive params on thread */
	bzero(&self->ith_receive, sizeof(self->ith_receive));
	self->ith_recv_bufs = (mach_msg_recv_bufs_t){
		.recv_msg_addr = msg_addr,
		.recv_msg_size = max_msg_rcv_size,
		.recv_aux_addr = max_aux_rcv_size ? aux_addr : 0,
		.recv_aux_size = max_aux_rcv_size,
	};
	self->ith_object = object;
	self->ith_option = option64;
	self->ith_knote  = ITH_KNOTE_NULL; /* not part of ith_receive */

	ipc_mqueue_receive(io_waitq(object), msg_timeout, THREAD_ABORTSAFE,
	    self, /* continuation ? */ true);
	/* NOTREACHED if thread started waiting */

	if ((option64 & MACH_RCV_TIMEOUT) && msg_timeout == 0) {
		thread_poll_yield(self);
	}

	mr = mach_msg_receive_results(NULL);
	/* release ref on ith_object */

	return mr;
}

/*
 *  Routine:    mach_msg_overwrite_trap [mach trap]
 *  Purpose:
 *      Possibly send a message; possibly receive a message.
 *
 *		/!\ Deprecated /!\
 *      No longer supported on embedded and will be removed from macOS.
 *      Use mach_msg2_trap() instead.
 *  Conditions:
 *      Nothing locked.
 *      The 'priority' is only a QoS if MACH_SEND_OVERRIDE is passed -
 *      otherwise, it is a port name.
 *  Returns:
 *      All of mach_msg_send and mach_msg_receive error codes.
 */
mach_msg_return_t
mach_msg_overwrite_trap(
	struct mach_msg_overwrite_trap_args *args)
{
#if IPC_HAS_LEGACY_MACH_MSG_TRAP
	mach_msg_option64_t     options = args->option;
	mach_msg_return_t       mr = MACH_MSG_SUCCESS;

	options = ipc_current_user_policy(current_task(), options);

	KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_START);

	if (options & MACH_SEND_MSG) {
		mach_msg_send_uctx_t send_uctx = {
			.send_msg_addr = args->msg,
			.send_msg_size = args->send_size,
		};

		/*
		 * Perform a crude copyin of the mach_msg_user_header_t,
		 * including the next 4 bytes in case it is a complex message,
		 * in order to mimic mach_msg2_trap() behavior of synthesizing
		 * the mach_msg_user_base_t via the trap arguments.
		 *
		 * mach_msg_trap_send() will do more thorough validation of
		 * sizes and header.
		 */

		mr = mach_msg_copyin_user_header(&send_uctx, options);
		if (mr != MACH_MSG_SUCCESS) {
			return mr;
		}

		mr = mach_msg_trap_send(&send_uctx, options,
		    args->timeout, args->priority);
	}

	/* If send failed, skip receive */
	if (mr != MACH_MSG_SUCCESS) {
		KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_END, mr);
		goto end;
	}

	if (options & MACH_RCV_MSG) {
		mach_vm_address_t msg_addr = args->rcv_msg ?: args->msg;
		mach_port_name_t  sync_send = MACH_PORT_NULL;

		/*
		 * Although just the presence of MACH_RCV_SYNC_WAIT and absence of
		 * MACH_SEND_OVERRIDE should imply that 'priority' is a valid port name
		 * to link, in practice older userspace is dependent on
		 * MACH_SEND_SYNC_OVERRIDE also excluding this path.
		 */
		if ((options & MACH_RCV_SYNC_WAIT) &&
		    !(options & (MACH_SEND_OVERRIDE | MACH_SEND_MSG)) &&
		    !(options & MACH_SEND_SYNC_OVERRIDE)) {
			sync_send = (mach_port_name_t)args->priority;
		}

		mr = mach_msg_trap_receive(msg_addr, 0, options, args->timeout,
		    sync_send, args->rcv_size, 0, args->rcv_name);
	}

end:
	/* unblock call is idempotent */
	ipc_port_thread_group_unblocked();
	return mr;
#else
	(void)args;
	return KERN_NOT_SUPPORTED;
#endif /* IPC_HAS_LEGACY_MACH_MSG_TRAP */
}

/*
 *  Routine:    mach_msg_trap [mach trap]
 *  Purpose:
 *      Possibly send a message; possibly receive a message.
 *
 *		/!\ Deprecated /!\
 *      No longer supported on embedded and will be removed from macOS.
 *      Use mach_msg2_trap() instead.
 *  Conditions:
 *      Nothing locked.
 *  Returns:
 *      All of mach_msg_send and mach_msg_receive error codes.
 */
mach_msg_return_t
mach_msg_trap(
	struct mach_msg_overwrite_trap_args *args)
{
	args->rcv_msg = (mach_vm_address_t)0;

	return mach_msg_overwrite_trap(args);
}

/*
 *  Routine:    mach_msg2_trap [mach trap]
 *  Purpose:
 *      Modern mach_msg_trap() with vector message and CFI support.
 *  Conditions:
 *      Nothing locked.
 *  Returns:
 *      All of mach_msg_send and mach_msg_receive error codes.
 */
mach_msg_return_t
mach_msg2_trap(
	struct mach_msg2_trap_args *args)
{
	/* packed arguments, LO_BITS_and_HI_BITS */
	uint64_t mb_ss = args->msgh_bits_and_send_size;
	uint64_t mr_lp = args->msgh_remote_and_local_port;
	uint64_t mv_id = args->msgh_voucher_and_id;
	uint64_t dc_rn = args->desc_count_and_rcv_name;
	uint64_t rs_pr = args->rcv_size_and_priority;

	mach_msg_timeout_t  msg_timeout = (mach_msg_timeout_t)args->timeout;
	mach_msg_vector_t   msg_vec = {}, aux_vec = {};
	mach_msg_size_t     vec_snd_count = 0;
	mach_msg_size_t     vec_rcv_count = 0;
	mach_msg_option64_t option64;
	mach_msg_return_t   mr = MACH_MSG_SUCCESS;

	option64 = ipc_current_user_policy(current_task(),
	    args->options) | MACH64_MACH_MSG2;

	KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_START);

	mr = ipc_preflight_msg_option64(option64);
	if (mr != MACH_MSG_SUCCESS) {
		goto send_fail;
	}

	if (option64 & MACH64_MSG_VECTOR) {
		vec_snd_count = (mach_msg_size_t)(mb_ss >> 32);
		vec_rcv_count = (mach_msg_size_t)rs_pr;

		mr = mach_msg_copyin_data_vectors(args->data,
		    MAX(vec_snd_count, vec_rcv_count), option64, &msg_vec, &aux_vec);
		if (mr != MACH_MSG_SUCCESS) {
			goto send_fail;
		}
	}

	if (option64 & MACH64_SEND_MSG) {
		mach_msg_send_uctx_t send_uctx = {
			.send_header = {
				.msgh_bits         = (mach_msg_bits_t) (mb_ss),
				.msgh_size         = 0,
				.msgh_remote_port  = (mach_port_name_t)(mr_lp),
				.msgh_local_port   = (mach_port_name_t)(mr_lp >> 32),
				.msgh_voucher_port = (mach_port_name_t)(mv_id),
				.msgh_id           = (mach_msg_id_t)   (mv_id >> 32),
			},
			.send_dsc_count = (mach_msg_size_t)dc_rn,
		};
		mach_msg_priority_t priority = (mach_msg_priority_t)(rs_pr >> 32);

		if (option64 & MACH64_MSG_VECTOR) {
			/*
			 * only validate msg send related arguments.
			 *
			 * bad receive args do not stop us from sending
			 * during combined send/rcv.
			 */
			mr = mach_msg_validate_data_vectors(&msg_vec, &aux_vec,
			    vec_snd_count, option64, /* sending? */ TRUE);
			if (mr != MACH_MSG_SUCCESS) {
				goto send_fail;
			}

			send_uctx.send_msg_addr = msg_vec.msgv_data;
			send_uctx.send_msg_size = msg_vec.msgv_send_size;
			send_uctx.send_aux_size = aux_vec.msgv_send_size;
			if (send_uctx.send_aux_size) {
				send_uctx.send_aux_addr = aux_vec.msgv_data;
			}
		} else {
			send_uctx.send_msg_addr = args->data;
			send_uctx.send_msg_size = (mach_msg_size_t)(mb_ss >> 32);
		}

		mr = mach_msg_trap_send(&send_uctx, option64, msg_timeout, priority);
	}

send_fail:
	/* if send failed, skip receive */
	if (mr != MACH_MSG_SUCCESS) {
		KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_END, mr);
		goto end;
	}

	if (option64 & MACH64_RCV_MSG) {
		mach_port_name_t    rcv_name   = (mach_port_name_t)(dc_rn >> 32);
		mach_port_name_t    sync_send  = MACH_PORT_NULL;
		mach_vm_address_t   msg_addr   = 0;
		mach_msg_size_t     msg_size   = 0;
		mach_vm_address_t   aux_addr   = 0;
		mach_msg_size_t     aux_size   = 0;

		if (option64 & MACH64_MSG_VECTOR) {
			/* only validate msg receive related arguments */
			mr = mach_msg_validate_data_vectors(&msg_vec, &aux_vec,
			    vec_rcv_count, option64, /* sending? */ FALSE);
			if (mr != MACH_MSG_SUCCESS) {
				goto end;
			}

			msg_addr = msg_vec.msgv_rcv_addr ?: msg_vec.msgv_data;
			msg_size = msg_vec.msgv_rcv_size;
			aux_size = aux_vec.msgv_rcv_size;
			if (aux_size) {
				aux_addr = aux_vec.msgv_rcv_addr ?: aux_vec.msgv_data;
			}
		} else {
			msg_addr = args->data;
			msg_size = (mach_msg_size_t)rs_pr;
		}

		if (option64 & MACH64_RCV_SYNC_WAIT) {
			/* use msgh_remote_port as sync send boosting port */
			sync_send = (mach_port_name_t)mr_lp;
		}

		mr = mach_msg_trap_receive(msg_addr, aux_addr, option64,
		    msg_timeout, sync_send, msg_size, aux_size, rcv_name);
	}

end:
	/* unblock call is idempotent */
	ipc_port_thread_group_unblocked();
	return mr;
}

/*
 *  Routine:    mach_msg_rcv_link_special_reply_port
 *  Purpose:
 *      Link the special reply port(rcv right) to the
 *      other end of the sync ipc channel.
 *  Conditions:
 *      Nothing locked.
 *  Returns:
 *      None.
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
 *  Routine:    mach_msg_receive_results_complete
 *  Purpose:
 *      Get thread's turnstile back from the object and
 *              if object is a special reply port then reset its
 *      linkage.
 *  Condition:
 *      Nothing locked.
 *  Returns:
 *      None.
 */
void
mach_msg_receive_results_complete(ipc_object_t object)
{
	thread_t self = current_thread();
	ipc_port_t port = IP_NULL;
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
	if (!((self->ith_state == MACH_RCV_TOO_LARGE && self->ith_option & MACH_RCV_LARGE) ||         //msg was too large and the next receive will get it
	    self->ith_state == MACH_RCV_INTERRUPTED ||
	    self->ith_state == MACH_RCV_TIMED_OUT ||
#if MACH_FLIPC
	    self->ith_state == MACH_PEEK_READY ||
#endif /* MACH_FLIPC */
	    self->ith_state == MACH_RCV_PORT_CHANGED)) {
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
