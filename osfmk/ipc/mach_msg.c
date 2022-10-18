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
#include <sys/proc_ro.h>

#ifndef offsetof
#define offsetof(type, member)  ((size_t)(&((type *)0)->member))
#endif /* offsetof */

/*
 * Forward declarations - kernel internal routines
 */

static mach_msg_return_t msg_receive_error(
	ipc_kmsg_t              kmsg,
	mach_msg_option64_t     option64,
	mach_vm_address_t       rcv_addr,
	mach_msg_size_t         rcv_size,
	mach_vm_address_t       aux_addr,
	mach_msg_size_t         aux_size,
	mach_port_seqno_t       seqno,
	ipc_space_t             space,
	mach_msg_size_t         *sizep,
	mach_msg_size_t         *aux_sizep);

static mach_msg_return_t
mach_msg_rcv_link_special_reply_port(
	ipc_port_t special_reply_port,
	mach_port_name_t dest_name_port);

void
mach_msg_receive_results_complete(ipc_object_t object);

const security_token_t KERNEL_SECURITY_TOKEN = KERNEL_SECURITY_TOKEN_VALUE;
const audit_token_t KERNEL_AUDIT_TOKEN = KERNEL_AUDIT_TOKEN_VALUE;

/*
 * values to limit inline message body handling
 * avoid copyin/out limits - even after accounting for maximum descriptor expansion.
 */
#define IPC_KMSG_MAX_SPACE (64 * 1024 * 1024) /* keep in sync with COPYSIZELIMIT_PANIC */
static const vm_size_t ipc_kmsg_max_body_space = ((IPC_KMSG_MAX_SPACE * 3) / 4 - MAX_TRAILER_SIZE);

static const vm_size_t ipc_kmsg_max_aux_data_space = 1024;

#define MACH_MSG_DESC_MIN_SIZE       sizeof(mach_msg_type_descriptor_t)

/*
 *  Routine:    mach_msg_receive_results
 *  Purpose:
 *      Receive a message.
 *  Conditions:
 *      Nothing locked.
 *
 *      Arguments passed on thread struct:
 *       If MACH64_RCV_LINEAR_VECTOR is not set:
 *          - ith_msg_addr: buffer address for message proper
 *          - ith_aux_addr: buffer address for auxiliary data (if any),
 *            only used if MACH64_MSG_VECTOR
 *          - ith_max_msize: size of message proper buffer
 *          - ith_max_asize: size of aux data buffer (if any)
 *       Otherwise:
 *          - ith_msg_addr: buffer address for combined message and aux
 *          - ith_aux_addr: Unused
 *          - ith_max_msize: size of combined
 *          - ith_max_asize: Unused
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
mach_msg_receive_results_kevent(
	mach_msg_size_t   *sizep,     /* copied out msg size */
	mach_msg_size_t   *aux_sizep, /* copied out aux size */
	uint32_t          *ppri,  /* received message pthread_priority_t */
	mach_msg_qos_t    *oqos)  /* override qos for message */
{
	mach_msg_trailer_size_t trailer_size;
	mach_vm_address_t context;

	thread_t          self = current_thread();
	ipc_space_t       space = current_space();
	vm_map_t          map = current_map();

	/*
	 * /!\IMPORTANT/!\: Pull out values we stashed on thread struct now.
	 * Values may be stomped over if copyio operations in this function
	 * trigger kernel IPC calls.
	 */
	ipc_object_t      object = self->ith_object;
	mach_msg_return_t mr = self->ith_state;
	mach_vm_address_t msg_rcv_addr = self->ith_msg_addr;
	mach_msg_size_t   msg_rcv_size = self->ith_max_msize;
	mach_port_name_t  receiver_name = self->ith_receiver_name;

	mach_vm_address_t aux_rcv_addr = self->ith_aux_addr;
	mach_msg_size_t   aux_rcv_size = self->ith_max_asize;
	mach_msg_size_t   msg_size = self->ith_msize;
	mach_msg_size_t   aux_size = self->ith_asize;

	mach_msg_option64_t option64 = self->ith_option;
	ipc_kmsg_t        kmsg = self->ith_kmsg;
	mach_port_seqno_t seqno = self->ith_seqno;

	mach_msg_size_t   cpout_msg_size = 0, cpout_aux_size = 0;

	/*
	 * unlink the special_reply_port before releasing reference to object.
	 * get the thread's turnstile, if the thread donated it's turnstile to the port
	 */
	mach_msg_receive_results_complete(object);
	io_release(object);

	if (option64 & MACH64_RCV_LINEAR_VECTOR) {
		assert(aux_rcv_addr == 0);
		assert(aux_rcv_size == 0);
	}

	if (mr != MACH_MSG_SUCCESS) {
		if (mr == MACH_RCV_TOO_LARGE) {
			/*
			 * If the receive operation occurs with MACH_RCV_LARGE set
			 * then no message was extracted from the queue, and the size
			 * and (optionally) receiver names were the only thing captured.
			 * Just copyout the size (and optional port name) in a fake
			 * header.
			 */
			if (option64 & MACH64_RCV_LARGE) {
				if (!(option64 & MACH64_RCV_STACK) &&
				    msg_rcv_size >= offsetof(mach_msg_user_header_t, msgh_reserved)) {
					/*
					 * We need to inform the user-level code that it needs more
					 * space. The value for how much space was returned in the
					 * msize save area instead of the message (which was left on
					 * the queue).
					 */
					if (option64 & MACH64_RCV_LARGE_IDENTITY) {
						if (copyout((char *) &receiver_name,
						    msg_rcv_addr + offsetof(mach_msg_user_header_t, msgh_local_port),
						    sizeof(mach_port_name_t))) {
							mr = MACH_RCV_INVALID_DATA;
						}
					}
					if (copyout((char *) &msg_size,
					    msg_rcv_addr + offsetof(mach_msg_user_header_t, msgh_size),
					    sizeof(mach_msg_size_t))) {
						mr = MACH_RCV_INVALID_DATA;
					}
				}

				/* Report the incoming aux size if caller has aux buffer */
				if (!(option64 & MACH64_RCV_STACK) &&
				    !(option64 & MACH64_RCV_LINEAR_VECTOR) &&
				    aux_rcv_addr != 0) {
					if (copyout((char *) &aux_size,
					    aux_rcv_addr + offsetof(mach_msg_aux_header_t, msgdh_size),
					    sizeof(mach_msg_size_t))) {
						assert(aux_rcv_size >= sizeof(mach_msg_aux_header_t));
						mr = MACH_RCV_INVALID_DATA;
					}
				}
			} else {
				/* discard importance in message */
				ipc_importance_clean(kmsg);

				if (msg_receive_error(kmsg, option64, msg_rcv_addr, msg_rcv_size,
				    aux_rcv_addr, aux_rcv_size, seqno, space, &cpout_msg_size,
				    &cpout_aux_size) == MACH_RCV_INVALID_DATA) {
					/* MACH_RCV_INVALID_DATA takes precedence */
					mr = MACH_RCV_INVALID_DATA;
				}
			}
		}

		if (sizep) {
			*sizep = cpout_msg_size;
		}
		if (aux_sizep) {
			*aux_sizep = cpout_aux_size;
		}
		return mr;
	}

	/* MACH_MSG_SUCCESS */
	assert(mr == MACH_MSG_SUCCESS);

#if IMPORTANCE_INHERITANCE

	/* adopt/transform any importance attributes carried in the message */
	ipc_importance_receive(kmsg, (mach_msg_option_t)option64);

#endif  /* IMPORTANCE_INHERITANCE */

	/* auto redeem the voucher in the message */
	ipc_voucher_receive_postprocessing(kmsg, (mach_msg_option_t)option64);

	/* Save destination port context for the trailer before copyout */
	context = ikm_header(kmsg)->msgh_remote_port->ip_context;

	mr = ipc_kmsg_copyout(kmsg, space, map, (mach_msg_option_t)option64);

	trailer_size = ipc_kmsg_trailer_size((mach_msg_option_t)option64, self);

	if (mr != MACH_MSG_SUCCESS) {
		/* already received importance, so have to undo that here */
		ipc_importance_unreceive(kmsg, (mach_msg_option_t)option64);

		/* if we had a body error copyout what we have, otherwise a simple header/trailer */
		if ((mr & ~MACH_MSG_MASK) == MACH_RCV_BODY_ERROR) {
			ipc_kmsg_add_trailer(kmsg, space, (mach_msg_option_t)option64,
			    self, seqno, FALSE, context);
			if (ipc_kmsg_put_to_user(kmsg, option64, msg_rcv_addr,
			    msg_rcv_size, aux_rcv_addr, aux_rcv_size, trailer_size,
			    &cpout_msg_size, &cpout_aux_size) == MACH_RCV_INVALID_DATA) {
				mr = MACH_RCV_INVALID_DATA;
			}
		} else {
			if (msg_receive_error(kmsg, option64, msg_rcv_addr, msg_rcv_size,
			    aux_rcv_addr, aux_rcv_size, seqno, space,
			    &cpout_msg_size, &cpout_aux_size) == MACH_RCV_INVALID_DATA) {
				mr = MACH_RCV_INVALID_DATA;
			}
		}
	} else {
		if (ppri) {
			*ppri = kmsg->ikm_ppriority;
		}
		if (oqos) {
			*oqos = kmsg->ikm_qos_override;
		}
		ipc_kmsg_add_trailer(kmsg, space, option64, self, seqno, FALSE, context);

		mr = ipc_kmsg_put_to_user(kmsg, option64, msg_rcv_addr, msg_rcv_size,
		    aux_rcv_addr, aux_rcv_size, trailer_size, &cpout_msg_size, &cpout_aux_size);
		/* kmsg freed */
	}

	if (sizep) {
		*sizep = cpout_msg_size;
	}

	if (aux_sizep) {
		*aux_sizep = cpout_aux_size;
	}

	/*
	 * Restore the values that are used by filt_machportprocess() after this
	 * call, as they may be overwritten by upcalls duing copyout().
	 *
	 * We should make this code more legible in 95817694.
	 */
	self->ith_asize = aux_size;
	self->ith_msize = msg_size;
	self->ith_receiver_name = receiver_name;

	return mr;
}

mach_msg_return_t
mach_msg_receive_results(void)
{
	return mach_msg_receive_results_kevent(NULL, NULL, NULL, NULL);
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
		mr = mach_msg_receive_results();
	}
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
	 * that msg_receive_error() builds, we will truncate the message and copy
	 * out a partial message.
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
		if (msg_size > ipc_kmsg_max_body_space) {
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
			if (aux_size > ipc_kmsg_max_aux_data_space) {
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
	mach_msg_vector_t   *data_addr,/* user address */
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

	if (copyin((user_addr_t)data_addr, (caddr_t)data_vecs,
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

#if XNU_TARGET_OS_OSX || XNU_TARGET_OS_IOS
#if DEVELOPMENT || DEBUG
static TUNABLE(bool, allow_legacy_mach_msg, "allow_legacy_mach_msg", false);
#endif /* DEVELOPMENT || DEBUG */

static bool
mach_msg_legacy_allowed(mach_msg_user_header_t *header)
{
	struct proc_ro *pro = current_thread_ro()->tro_proc_ro;
	uint32_t platform = pro->p_platform_data.p_platform;
	uint32_t sdk = pro->p_platform_data.p_sdk;
	uint32_t sdk_major = sdk >> 16;
#if __x86_64__ || CONFIG_ROSETTA
	task_t task = current_task();
#endif

#if __x86_64__
	if (!task_has_64Bit_addr(task)) {
		/*
		 * Legacy mach_msg_trap() is the only
		 * available thing for 32-bit tasks
		 */
		return true;
	}
#endif /* __x86_64__ */
#if CONFIG_ROSETTA
	if (task_is_translated(task)) {
		/*
		 * Similarly, on Rosetta, allow mach_msg_trap()
		 * as those apps likely can't be fixed anymore
		 */
		return true;
	}
#endif
	if (pro->t_flags_ro & TFRO_PLATFORM) {
		/* Platform binaries must use mach_msg2_trap() */
		return false;
	}

#if DEVELOPMENT || DEBUG
	if (allow_legacy_mach_msg) {
		/* Honor boot-arg */
		return true;
	}
#endif /* DEVELOPMENT || DEBUG */

	/*
	 * Special rules, due to unfortunate bincompat reasons,
	 * allow for a hardcoded list of MIG calls to XNU to go through:
	 * - for iOS, Catalyst and iOS Simulator apps linked against
	 *   an SDK older than 15.x,
	 * - for macOS apps linked against an SDK older than 12.x.
	 */
	switch (platform) {
	case PLATFORM_IOS:
	case PLATFORM_IOSSIMULATOR:
	case PLATFORM_MACCATALYST:
		if (sdk == 0 || sdk_major > 15) {
			return false;
		}
		break;
	case PLATFORM_MACOS:
		if (sdk == 0 || sdk_major > 12) {
			return false;
		}
		break;
	default:
		return false;
	}

	switch (header->msgh_id) {
	case 0xd4a: /* task_threads */
	case 0xd4d: /* task_info */
	case 0xe13: /* thread_get_state */
	case 0x12c4: /* mach_vm_read */
	case 0x12c8: /* mach_vm_read_overwrite */
		return true;
	default:
		return false;
	}
}

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
	mach_vm_address_t       msg_addr,
	mach_msg_size_t         msg_size,
	mach_msg_user_header_t  *header,
	mach_msg_size_t         *desc_count)
{
	mach_msg_size_t         len_copied;
	mach_msg_size_t         descriptors;
	mach_msg_user_base_t    user_base;

	if ((msg_size < sizeof(mach_msg_user_header_t)) || (msg_size & 3)) {
		return MACH_SEND_MSG_TOO_SMALL;
	}

	if (msg_size > ipc_kmsg_max_body_space) {
		return MACH_SEND_TOO_LARGE;
	}

	if (msg_size == sizeof(mach_msg_user_header_t)) {
		len_copied = sizeof(mach_msg_user_header_t);
	} else {
		len_copied = sizeof(mach_msg_user_base_t);
	}

	user_base.body.msgh_descriptor_count = descriptors = 0;
	/*
	 * If message is larger than mach_msg_user_header_t, first copy in
	 * header + next 4 bytes, which is treated as descriptor count
	 * if message is complex.
	 */
	if (copyinmsg(msg_addr, (char *)&user_base, len_copied)) {
		return MACH_SEND_INVALID_DATA;
	}

	/*
	 * If the message claims to be complex, it must at least
	 * have the length of a "base" message (header + dsc_count).
	 */
	if (user_base.header.msgh_bits & MACH_MSGH_BITS_COMPLEX) {
		if (len_copied < sizeof(mach_msg_user_base_t)) {
			return MACH_SEND_MSG_TOO_SMALL;
		}
		descriptors = user_base.body.msgh_descriptor_count;
		/* desc count bound check in mach_msg_trap_send() */
	}

	if (!mach_msg_legacy_allowed(&user_base.header)) {
		mach_port_guard_exception(user_base.header.msgh_id, 0, 0, kGUARD_EXC_INVALID_OPTIONS);
		/*
		 * this should be MACH_SEND_INVALID_OPTIONS,
		 * but this is a new mach_msg2 error only.
		 */
		return KERN_NOT_SUPPORTED;
	}

	memcpy(header, &user_base, sizeof(mach_msg_user_header_t));

	/*
	 * return message "body" as desriptor count,
	 * zero if message is not complex.
	 */
	*desc_count = descriptors;

	return MACH_MSG_SUCCESS;
}
#endif /* XNU_TARGET_OS_OSX || XNU_TARGET_OS_IOS */

/*
 *  Routine:    mach_msg_trap_send [internal]
 *  Purpose:
 *      Send a message.
 *  Conditions:
 *      MACH_SEND_MSG is set. aux_send_size is bound checked.
 *      aux_{addr, send_size} are 0 if not vector send.
 *      msg_send_size needs additional bound checks.
 *  Returns:
 *      All of mach_msg_send error codes.
 */
static mach_msg_return_t
mach_msg_trap_send(
	/* shared args between send and receive */
	mach_vm_address_t   msg_addr,
	mach_vm_address_t   aux_addr,
	mach_msg_option64_t option64,
	mach_msg_timeout_t  msg_timeout,
	mach_msg_priority_t priority,
	/* msg send args */
	bool                filter_nonfatal,
	mach_msg_user_header_t user_header,
	mach_msg_size_t     msg_send_size,
	mach_msg_size_t     aux_send_size,        /* bound checked */
	mach_msg_size_t     desc_count)
{
	ipc_kmsg_t kmsg;

	mach_msg_return_t  mr = MACH_MSG_SUCCESS;
	vm_map_t map = current_map();
	ipc_space_t space = current_space();

	assert(option64 & MACH64_SEND_MSG);

	/*
	 * Bound checks on msg_send_size to cover mach_msg2() scalar send case.
	 *
	 * For mach_msg2() vector send:
	 *  - We have checked during mach_msg_validate_data_vectors().
	 * For mach_msg() send:
	 *  - We have checked during mach_msg_copyin_user_header().
	 *
	 * But checking again here can't hurt.
	 */
	if ((msg_send_size < sizeof(mach_msg_user_header_t)) || (msg_send_size & 3)) {
		return MACH_SEND_MSG_TOO_SMALL;
	}
	if (msg_send_size > ipc_kmsg_max_body_space) {
		return MACH_SEND_TOO_LARGE;
	}
	/*
	 * Complex message must have a body, also do a bound check on descriptor count
	 * (more in ikm_check_descriptors()).
	 */
	if (user_header.msgh_bits & MACH_MSGH_BITS_COMPLEX) {
		if (msg_send_size < sizeof(mach_msg_user_base_t)) {
			return MACH_SEND_MSG_TOO_SMALL;
		}
		if (desc_count > (msg_send_size - sizeof(mach_msg_user_base_t)) / MACH_MSG_DESC_MIN_SIZE) {
			return MACH_SEND_MSG_TOO_SMALL;
		}
	} else if (desc_count != 0) {
		/*
		 * Simple message cannot contain descriptors. This invalid config can only
		 * happen from mach_msg2_trap() since desc_count is passed as its own trap
		 * argument.
		 */
		assert(option64 & MACH64_MACH_MSG2);
		return MACH_SEND_TOO_LARGE;
	}

	/*
	 * Now that we have validated msg_send_size, aux_send_size and desc_count,
	 * copy in the message.
	 */
	mr = ipc_kmsg_get_from_user(msg_addr, msg_send_size, (aux_send_size == 0) ?
	    0 : aux_addr, aux_send_size, user_header, desc_count, option64, &kmsg);

	if (mr != MACH_MSG_SUCCESS) {
		return mr;
	}

	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_LINK) | DBG_FUNC_NONE,
	    (uintptr_t)msg_addr,
	    VM_KERNEL_ADDRPERM((uintptr_t)kmsg),
	    0, 0, 0);

	/* holding kmsg ref */
	mr = ipc_kmsg_copyin_from_user(kmsg, space, map, priority,
	    &option64,         /* may add MACH64_SEND_ALWAYS option */
	    filter_nonfatal);

	if (mr != MACH_MSG_SUCCESS) {
		ipc_kmsg_free(kmsg);
		return mr;
	}

	mr = ipc_kmsg_send(kmsg, option64, msg_timeout);

	if (mr != MACH_MSG_SUCCESS) {
		/* we still have the kmsg */
		mr |= ipc_kmsg_copyout_pseudo(kmsg, space, map);
		(void)ipc_kmsg_put_to_user(kmsg, option64, msg_addr, msg_send_size,
		    (aux_send_size == 0) ? 0 : aux_addr, aux_send_size, 0, NULL, NULL);
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
	self->ith_msg_addr = msg_addr;
	self->ith_max_msize = max_msg_rcv_size;
	self->ith_msize = 0;

	/* Set up aux data receive params on thread */
	self->ith_aux_addr = (max_aux_rcv_size == 0) ? 0 : aux_addr;
	self->ith_max_asize = max_aux_rcv_size;
	self->ith_asize = 0;

	self->ith_object = object;
	self->ith_option = option64;
	self->ith_receiver_name = MACH_PORT_NULL;
	self->ith_knote = ITH_KNOTE_NULL;

	ipc_mqueue_receive(io_waitq(object),
	    option64, max_msg_rcv_size,
	    max_aux_rcv_size, msg_timeout,
	    THREAD_ABORTSAFE, /* continuation ? */ true);
	/* NOTREACHED if thread started waiting */

	if ((option64 & MACH_RCV_TIMEOUT) && msg_timeout == 0) {
		thread_poll_yield(self);
	}

	mr = mach_msg_receive_results();
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
#if XNU_TARGET_OS_OSX || XNU_TARGET_OS_IOS
	mach_msg_return_t       mr;
	bool                    filter_nonfatal;

	mach_vm_address_t       msg_addr = args->msg;
	mach_msg_option_t       option32 = args->option;
	mach_msg_size_t         send_size = args->send_size;
	mach_msg_size_t         rcv_size = args->rcv_size;
	mach_port_name_t        rcv_name = args->rcv_name;
	mach_msg_timeout_t      msg_timeout = args->timeout;
	mach_msg_priority_t     priority = args->priority;
	mach_vm_address_t       rcv_msg_addr = args->rcv_msg;

	mach_msg_user_header_t  user_header = {};
	mach_msg_size_t         desc_count = 0;
	mach_port_name_t        sync_send = MACH_PORT_NULL;

	option32 &= MACH_MSG_OPTION_USER;
	/*
	 * MACH_SEND_FILTER_NONFATAL is aliased to MACH_SEND_ALWAYS kernel
	 * flag. Unset it as early as possible.
	 */
	filter_nonfatal = (option32 & MACH_SEND_FILTER_NONFATAL);
	option32 &= ~MACH_SEND_FILTER_NONFATAL;

	KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_START);

	if (option32 & MACH_SEND_MSG) {
		mr = mach_msg_copyin_user_header(msg_addr, send_size, &user_header, &desc_count);
		if (mr != MACH_MSG_SUCCESS) {
			return mr;
		}
	}

	if (option32 & MACH_SEND_MSG) {
		/* send_size is bound checked */
		mr = mach_msg_trap_send(msg_addr, 0, (mach_msg_option64_t)option32,
		    msg_timeout, priority, filter_nonfatal,
		    user_header, send_size, 0, desc_count);
	}

	/* If send failed, skip receive */
	if (mr != MACH_MSG_SUCCESS) {
		KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_END, mr);
		goto end;
	}

	if (option32 & MACH_RCV_MSG) {
		/*
		 * Although just the presence of MACH_RCV_SYNC_WAIT and absence of
		 * MACH_SEND_OVERRIDE should imply that 'priority' is a valid port name
		 * to link, in practice older userspace is dependent on
		 * MACH_SEND_SYNC_OVERRIDE also excluding this path.
		 */
		if ((option32 & MACH_RCV_SYNC_WAIT) &&
		    !(option32 & (MACH_SEND_OVERRIDE | MACH_SEND_MSG)) &&
		    !(option32 & MACH_SEND_SYNC_OVERRIDE)) {
			sync_send = (mach_port_name_t)priority;
		}

		if (rcv_msg_addr != 0) {
			msg_addr = rcv_msg_addr;
		}
		mr = mach_msg_trap_receive(msg_addr, 0, (mach_msg_option64_t)option32,
		    msg_timeout, sync_send, rcv_size, 0, rcv_name);
	}

end:
	/* unblock call is idempotent */
	ipc_port_thread_group_unblocked();
	return mr;
#else
	(void)args;
	return KERN_NOT_SUPPORTED;
#endif /* XNU_TARGET_OS_OSX || XNU_TARGET_OS_IOS */
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

static inline bool
mach_msg2_cfi_option_valid(
	mach_msg_option64_t    option64)
{
	option64 &= MACH64_MSG_OPTION_CFI_MASK;

	/* mach_msg2() calls must have _exactly_ one of three options set */
	return (option64 != 0) && ((option64 & (option64 - 1)) == 0);
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
	mach_port_name_t rcv_name, sync_send;
	mach_vm_address_t msg_addr, aux_addr;
	mach_msg_size_t   msg_send_size, max_msg_rcv_size,
	    aux_send_size, max_aux_rcv_size,
	    send_data_cnt, rcv_data_cnt;
	mach_msg_size_t   desc_count;
	mach_msg_priority_t priority;
	bool filter_nonfatal, vector_msg;

	mach_vm_address_t data_addr = args->data;
	mach_msg_option64_t option64 = args->options;
	/* packed arguments, LO_BITS_and_HI_BITS */
	uint64_t mb_ss = args->msgh_bits_and_send_size;
	uint64_t mr_lp = args->msgh_remote_and_local_port;
	uint64_t mv_id = args->msgh_voucher_and_id;
	uint64_t dc_rn = args->desc_count_and_rcv_name;
	uint64_t rs_pr = args->rcv_size_and_priority;

	mach_msg_timeout_t msg_timeout = (mach_msg_timeout_t)args->timeout;
	mach_msg_return_t  mr = MACH_MSG_SUCCESS;

	mach_msg_user_header_t user_header = {};
	mach_msg_vector_t msg_vec = {}, aux_vec = {};         /* zeroed */

	option64 &= MACH64_MSG_OPTION_USER;
	option64 |= MACH64_MACH_MSG2;

	/*
	 * MACH_SEND_FILTER_NONFATAL is aliased to MACH_SEND_ALWAYS kernel
	 * flag. Unset it as early as possible.
	 */
	filter_nonfatal = (option64 & MACH64_SEND_FILTER_NONFATAL);
	option64 &= ~MACH64_SEND_FILTER_NONFATAL;
	vector_msg = (option64 & MACH64_MSG_VECTOR);

	KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_START);

	/* kobject calls must be scalar calls (hence no aux data) */
	if (__improbable((option64 & MACH64_SEND_KOBJECT_CALL) && vector_msg)) {
		mach_port_guard_exception(0, 0, 0, kGUARD_EXC_INVALID_OPTIONS);
		return MACH_SEND_INVALID_OPTIONS;
	}

	if (vector_msg) {
		send_data_cnt = (mb_ss >> 32);
		rcv_data_cnt = (mach_msg_size_t)rs_pr;

		mr = mach_msg_copyin_data_vectors((mach_msg_vector_t *)data_addr,
		    MAX(send_data_cnt, rcv_data_cnt), option64, &msg_vec, &aux_vec);

		if (mr != MACH_MSG_SUCCESS) {
			return mr;
		}
	}

	if (option64 & MACH64_SEND_MSG) {
		if (vector_msg) {
			/*
			 * only validate msg send related arguments. bad receive args
			 * do not stop us from sending during combined send/rcv.
			 */
			mr = mach_msg_validate_data_vectors(&msg_vec, &aux_vec, send_data_cnt,
			    option64, /* sending? */ TRUE);
			if (mr != MACH_MSG_SUCCESS) {
				return mr;
			}
			/* msg_vec.msgv_send_size is bound checked */
		}

		/* desc_count is bound checked in mach_msg_trap_send() */
		desc_count = (mach_msg_size_t)dc_rn;
		priority = (mach_msg_priority_t)(rs_pr >> 32);

		msg_addr = vector_msg ? msg_vec.msgv_data : data_addr;
		/* mb_ss is bound checked in mach_msg_trap_send() */
		msg_send_size = vector_msg ? msg_vec.msgv_send_size : (mb_ss >> 32);

		/* Nullable for vector send without aux */
		aux_send_size = vector_msg ? aux_vec.msgv_send_size : 0;
		aux_addr = (vector_msg && aux_send_size) ? aux_vec.msgv_data : 0;

		user_header = (mach_msg_user_header_t){
			.msgh_bits         = (mach_msg_bits_t)  (mb_ss),
			.msgh_size         = (mach_msg_size_t)  (msg_send_size),
			.msgh_remote_port  = (mach_port_name_t) (mr_lp),
			.msgh_local_port   = (mach_port_name_t) (mr_lp >> 32),
			.msgh_voucher_port = (mach_port_name_t) (mv_id),
			.msgh_id           = (mach_msg_id_t)    (mv_id >> 32),
		};

		/*
		 * if it's not to a message queue and user attempts to send aux data,
		 * something fishy is going on.
		 */
		if (__improbable(!(option64 & MACH64_SEND_MQ_CALL) && (aux_send_size != 0))) {
			mach_port_guard_exception(0, 0, 0, kGUARD_EXC_INVALID_OPTIONS);
			return MACH_SEND_INVALID_OPTIONS;
		}
		/* must have _exactly_ one of three cfi options set */
		if (__improbable(!mach_msg2_cfi_option_valid(option64))) {
			mach_port_guard_exception(0, 0, 0, kGUARD_EXC_INVALID_OPTIONS);
			return MACH_SEND_INVALID_OPTIONS;
		}

		/* for scalar send: msg_send_size (from mb_ss) has not been bound checked */
		mr = mach_msg_trap_send(msg_addr, aux_addr, option64,
		    msg_timeout, priority, filter_nonfatal,
		    user_header, msg_send_size,
		    aux_send_size, desc_count);
	}

	/* if send failed, skip receive */
	if (mr != MACH_MSG_SUCCESS) {
		KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_END, mr);
		goto end;
	}

	if (option64 & MACH64_RCV_MSG) {
		if (vector_msg) {
			/* only validate msg receive related arguments */
			mr = mach_msg_validate_data_vectors(&msg_vec, &aux_vec, rcv_data_cnt,
			    option64, /* sending? */ FALSE);
			if (mr != MACH_MSG_SUCCESS) {
				goto end;
			}
		}
		rcv_name = (mach_port_name_t)(dc_rn >> 32);

		msg_addr = vector_msg ?
		    (msg_vec.msgv_rcv_addr ? msg_vec.msgv_rcv_addr : msg_vec.msgv_data) :
		    data_addr;
		max_msg_rcv_size = vector_msg ? msg_vec.msgv_rcv_size : (mach_msg_size_t)rs_pr;

		/* Nullable for vector receive without aux */
		max_aux_rcv_size = vector_msg ? aux_vec.msgv_rcv_size : 0;
		aux_addr = (vector_msg && max_aux_rcv_size) ?
		    (aux_vec.msgv_rcv_addr ? aux_vec.msgv_rcv_addr : aux_vec.msgv_data) :
		    0;

		if (option64 & MACH64_RCV_SYNC_WAIT) {
			/* use msgh_remote_port as sync send boosting port */
			sync_send = (mach_port_name_t)mr_lp;
		} else {
			sync_send = MACH_PORT_NULL;
		}

		mr = mach_msg_trap_receive(msg_addr, aux_addr, option64,
		    msg_timeout, sync_send, max_msg_rcv_size,
		    max_aux_rcv_size, rcv_name);
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
	if (!((self->ith_state == MACH_RCV_TOO_LARGE && self->ith_option & MACH_RCV_LARGE) ||         //msg was too large and the next receive will get it
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
 *  Routine:    msg_receive_error   [internal]
 *  Purpose:
 *      Builds a minimal header/trailer and copies it to
 *      the user message buffer.  Invoked when in the case of a
 *      MACH_RCV_TOO_LARGE or MACH_RCV_BODY_ERROR error.
 *  Conditions:
 *      ipc_kmsg_copyout_body() has not been called. ipc_kmsg_add_trailer()
 *      relies on this condition to calculate trailer address.
 *      Nothing locked. kmsg is freed upon return.
 *  Returns:
 *      MACH_MSG_SUCCESS    minimal header/trailer copied
 *      MACH_RCV_INVALID_DATA   copyout to user buffer failed
 */
static mach_msg_return_t
msg_receive_error(
	ipc_kmsg_t              kmsg,
	mach_msg_option64_t     option64,
	mach_vm_address_t       msg_rcv_addr,
	mach_msg_size_t         max_msg_size,
	mach_vm_address_t       aux_rcv_addr,        /* Nullable */
	mach_msg_size_t         max_aux_size,        /* Nullable */
	mach_port_seqno_t       seqno,
	ipc_space_t             space,
	mach_msg_size_t         *sizep,
	mach_msg_size_t         *aux_sizep)
{
	mach_vm_address_t       context;
	mach_msg_trailer_size_t trailer_size;
	thread_t                self = current_thread();
	mach_msg_header_t       *hdr = ikm_header(kmsg);

	context = hdr->msgh_remote_port->ip_context;

	/*
	 * Copy out the destination port in the message.
	 * Destroy all other rights and memory in the message.
	 */
	ipc_kmsg_copyout_dest_to_user(kmsg, space);

	/*
	 * Build a minimal message with the requested trailer.
	 */
	hdr->msgh_size = sizeof(mach_msg_header_t);
	ipc_kmsg_init_trailer(kmsg, TASK_NULL);

	trailer_size = ipc_kmsg_trailer_size((mach_msg_option_t)option64, self);
	ipc_kmsg_add_trailer(kmsg, space, (mach_msg_option_t)option64, self,
	    seqno, TRUE, context);

	/* Build a minimal aux data header for vector kmsg with aux */
	mach_msg_aux_header_t aux_header = {
		.msgdh_size = sizeof(mach_msg_aux_header_t)
	};
	ipc_kmsg_set_aux_data_header(kmsg, &aux_header);

	/*
	 * Copy the message to user space and return the size
	 * (note that ipc_kmsg_put_to_user may also adjust the actual
	 * msg and aux size copied out to user-space).
	 */
	if (ipc_kmsg_put_to_user(kmsg, option64, msg_rcv_addr,
	    max_msg_size, aux_rcv_addr, max_aux_size,
	    trailer_size, sizep, aux_sizep) == MACH_RCV_INVALID_DATA) {
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
