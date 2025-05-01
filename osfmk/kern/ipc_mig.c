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
 * Copyright (c) 1991,1990 Carnegie Mellon University
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

#include <mach/boolean.h>
#include <mach/port.h>
#include <mach/mig.h>
#include <mach/mig_errors.h>
#include <mach/mach_types.h>
#include <mach/mach_traps.h>

#include <kern/ipc_tt.h>
#include <kern/ipc_mig.h>
#include <kern/kalloc.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/ipc_kobject.h>
#include <kern/misc_protos.h>

#include <ipc/port.h>
#include <ipc/ipc_kmsg.h>
#include <ipc/ipc_entry.h>
#include <ipc/ipc_object.h>
#include <ipc/ipc_mqueue.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_pset.h>
#include <ipc/ipc_notify.h>
#include <vm/vm_map.h>
#include <mach/thread_act.h>

#include <libkern/OSAtomic.h>

#define KERNEL_DESC_SIZE             sizeof(mach_msg_kdescriptor_t)

void
mach_msg_receive_results_complete(ipc_object_t object);

/*
 *	Routine:	mach_msg_send_from_kernel
 *	Purpose:
 *		Send a message from the kernel.
 *
 *		This is used by the client side of KernelUser interfaces
 *		to implement SimpleRoutines.  Currently, this includes
 *		memory_object messages.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		MACH_MSG_SUCCESS	Sent the message.
 *		MACH_SEND_INVALID_DEST	Bad destination port.
 *		MACH_MSG_SEND_NO_BUFFER Destination port had inuse fixed bufer
 *		                        or destination is above kernel limit
 */

mach_msg_return_t
mach_msg_send_from_kernel(
	mach_msg_header_t      *msg,
	mach_msg_size_t         send_size)
{
	mach_msg_option64_t option = MACH_SEND_KERNEL_DEFAULT;
	mach_msg_timeout_t  timeout_val = MACH_MSG_TIMEOUT_NONE;
	return kernel_mach_msg_send(msg, send_size, option, timeout_val, NULL);
}

mach_msg_return_t
mach_msg_send_from_kernel_with_options(
	mach_msg_header_t      *msg,
	mach_msg_size_t         send_size,
	mach_msg_option64_t     option,
	mach_msg_timeout_t      timeout_val)
{
	return kernel_mach_msg_send(msg, send_size, option, timeout_val, NULL);
}

static mach_msg_return_t
kernel_mach_msg_send_common(
	ipc_kmsg_t              kmsg,
	mach_msg_option64_t     option,
	mach_msg_timeout_t      timeout_val,
	boolean_t              *message_moved)
{
	mach_msg_return_t mr;

	mr = ipc_kmsg_copyin_from_kernel(kmsg);
	if (mr != MACH_MSG_SUCCESS) {
		ipc_kmsg_free(kmsg);
		KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_END, mr);
		return mr;
	}

	if (message_moved) {
		*message_moved = TRUE;
	}

	/*
	 * Until we are sure of its effects, we are disabling
	 * importance donation from the kernel-side of user
	 * threads in importance-donating tasks - unless the
	 * option to force importance donation is passed in,
	 * or the thread's SEND_IMPORTANCE option has been set.
	 * (11938665 & 23925818)
	 */
	if (current_thread()->options & TH_OPT_SEND_IMPORTANCE) {
		option &= ~MACH_SEND_NOIMPORTANCE;
	} else if ((option & MACH_SEND_IMPORTANCE) == 0) {
		option |= MACH_SEND_NOIMPORTANCE;
	}

	mr = ipc_kmsg_send(kmsg, option, timeout_val);

	if (mr != MACH_MSG_SUCCESS) {
		ipc_kmsg_destroy(kmsg, IPC_KMSG_DESTROY_ALL);
		KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_END, mr);
	}

	return mr;
}

mach_msg_return_t
kernel_mach_msg_send(
	mach_msg_header_t      *msg,
	mach_msg_size_t         send_size,
	mach_msg_option64_t     option,
	mach_msg_timeout_t      timeout_val,
	boolean_t              *message_moved)
{
	ipc_kmsg_t kmsg;
	mach_msg_return_t mr;

	KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_START);

	if (message_moved) {
		*message_moved = FALSE;
	}

	option &= ~MACH64_POLICY_KERNEL_EXTENSION;
	mr = ipc_kmsg_get_from_kernel(msg, send_size, option, &kmsg);
	if (mr != MACH_MSG_SUCCESS) {
		KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_END, mr);
		return mr;
	}

	return kernel_mach_msg_send_common(kmsg, option, timeout_val, message_moved);
}

extern typeof(mach_msg_send_from_kernel) mach_msg_send_from_kernel_proper;
mach_msg_return_t
mach_msg_send_from_kernel_proper(
	mach_msg_header_t      *msg,
	mach_msg_size_t         send_size)
{
	mach_msg_option64_t option = MACH_SEND_KERNEL_DEFAULT;
	mach_msg_timeout_t  timeout_val = MACH_MSG_TIMEOUT_NONE;
	ipc_kmsg_t          kmsg;
	mach_msg_return_t   mr;

	KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_START);

	option |= MACH64_POLICY_KERNEL_EXTENSION;
	mr = ipc_kmsg_get_from_kernel(msg, send_size, option, &kmsg);
	if (mr != MACH_MSG_SUCCESS) {
		KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_END, mr);
		return mr;
	}

	return kernel_mach_msg_send_common(kmsg, option, timeout_val, NULL);
}

mach_msg_return_t
kernel_mach_msg_send_kmsg(
	ipc_kmsg_t              kmsg)
{
	mach_msg_option_t   option = MACH_SEND_KERNEL_DEFAULT;
	mach_msg_timeout_t  timeout_val = MACH_MSG_TIMEOUT_NONE;

	KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_START);

	return kernel_mach_msg_send_common(kmsg, option, timeout_val, NULL);
}

mach_msg_return_t
kernel_mach_msg_send_with_builder_internal(
	mach_msg_size_t         desc_count,
	mach_msg_size_t         payload_size, /* Not total send size */
	mach_msg_option64_t     option,
	mach_msg_timeout_t      timeout_val,
	boolean_t              *message_moved,
	void                  (^builder)(mach_msg_header_t *, mach_msg_descriptor_t *, void *))
{
	ipc_kmsg_t kmsg;
	mach_msg_return_t mr;
	mach_msg_header_t *hdr;
	void *udata;
	bool complex;
	mach_msg_size_t send_size;

	KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_START);

	/*
	 * If message has descriptors it must be complex and vice versa. We assume
	 * this for messages originated from kernel. The two are not equivalent for
	 * user messages for bin-compat reasons.
	 */
	complex = (desc_count > 0);
	send_size = sizeof(mach_msg_header_t) + payload_size;

	if (complex) {
		send_size += sizeof(mach_msg_body_t) + desc_count * KERNEL_DESC_SIZE;
	}
	if (message_moved) {
		*message_moved = FALSE;
	}

	kmsg = ipc_kmsg_alloc(send_size, 0, desc_count,
	    IPC_KMSG_ALLOC_KERNEL | IPC_KMSG_ALLOC_ZERO);
	/* kmsg can be non-linear */

	if (kmsg == IKM_NULL) {
		mr = MACH_SEND_NO_BUFFER;
		KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_END, mr);
		return mr;
	}

	hdr   = ikm_header(kmsg);
	udata = (payload_size > 0) ? ikm_udata(kmsg, desc_count, complex) : NULL;

	/* Allow the caller to build the message, and sanity check it */
	if (complex) {
		mach_msg_kbase_t *kbase = mach_msg_header_to_kbase(hdr);

		builder(hdr, (mach_msg_descriptor_t *)kbase->msgb_dsc_array, udata);

		assert(hdr->msgh_bits & MACH_MSGH_BITS_COMPLEX);
		hdr->msgh_bits |= MACH_MSGH_BITS_COMPLEX;

		/* Set the correct descriptor count */
		kbase->msgb_dsc_count = desc_count;
	} else {
		builder(hdr, NULL, udata);

		assert(!(hdr->msgh_bits & MACH_MSGH_BITS_COMPLEX));
		hdr->msgh_bits &= ~MACH_MSGH_BITS_COMPLEX;
	}
	assert(hdr->msgh_size == send_size);

	return kernel_mach_msg_send_common(kmsg, option, timeout_val, NULL);
}

mach_msg_return_t
kernel_mach_msg_send_with_builder(
	mach_msg_size_t         desc_count,
	mach_msg_size_t         udata_size,
	void                    (^builder)(mach_msg_header_t *,
	mach_msg_descriptor_t *, void *))
{
	mach_msg_option64_t options;

	options = MACH_SEND_KERNEL_DEFAULT | MACH64_POLICY_KERNEL_EXTENSION;
	return kernel_mach_msg_send_with_builder_internal(desc_count, udata_size,
	           options, MACH_MSG_TIMEOUT_NONE, NULL, builder);
}

/*
 *	Routine:	mach_msg_rpc_from_kernel
 *	Purpose:
 *		Send a message from the kernel and receive a reply.
 *		Uses ith_rpc_reply for the reply port.
 *
 *		This is used by the client side of KernelUser interfaces
 *		to implement Routines.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		MACH_MSG_SUCCESS	Sent the message.
 *		MACH_RCV_PORT_DIED	The reply port was deallocated.
 */

static mach_msg_return_t
kernel_mach_msg_rpc_common(
	mach_msg_header_t       *msg,
	mach_msg_size_t         send_size,
	mach_msg_size_t         rcv_size,
	boolean_t               interruptible,
	mach_msg_option64_t     options,
	boolean_t              *message_moved)
{
	thread_t self = current_thread();
	ipc_port_t dest = IPC_PORT_NULL;
	/* Sync IPC from kernel should pass adopted voucher and importance */
	mach_msg_option64_t option = MACH_SEND_KERNEL_DEFAULT & ~MACH_SEND_NOIMPORTANCE;
	ipc_port_t reply;
	ipc_kmsg_t kmsg;
	mach_msg_header_t *hdr;
	mach_port_seqno_t seqno;
	mach_msg_return_t mr;

	assert(msg->msgh_local_port == MACH_PORT_NULL);

	KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_START);

	if (message_moved) {
		*message_moved = FALSE;
	}

	if (!IP_VALID(msg->msgh_remote_port)) {
		return MACH_SEND_INVALID_DEST;
	}

	mr = ipc_kmsg_get_from_kernel(msg, send_size, options, &kmsg);
	/* kmsg can be non-linear */

	if (mr != MACH_MSG_SUCCESS) {
		KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_END, mr);
		return mr;
	}
	hdr = ikm_header(kmsg);

	reply = self->ith_kernel_reply_port;
	if (reply == IP_NULL) {
		thread_get_kernel_special_reply_port();
		reply = self->ith_kernel_reply_port;
		if (reply == IP_NULL) {
			panic("mach_msg_rpc_from_kernel");
		}
	}

	/* Get voucher port for the current thread's voucher */
	ipc_voucher_t voucher = IPC_VOUCHER_NULL;
	ipc_port_t voucher_port = IP_NULL;

	/* Kernel server routines do not need voucher */
	bool has_voucher = !ip_is_kobject(hdr->msgh_remote_port);

	if (has_voucher && thread_get_mach_voucher(self, 0, &voucher) == KERN_SUCCESS) {
		/* If thread does not have a voucher, get the default voucher of the process */
		if (voucher == IPC_VOUCHER_NULL) {
			voucher = ipc_voucher_get_default_voucher();
		}
		voucher_port = convert_voucher_to_port(voucher);
		ipc_kmsg_set_voucher_port(kmsg, voucher_port, MACH_MSG_TYPE_MOVE_SEND);
	}

	/* insert send-once right for the reply port and send right for the adopted voucher */
	hdr->msgh_local_port = reply;
	hdr->msgh_bits |=
	    MACH_MSGH_BITS_SET_PORTS(
		0,
		MACH_MSG_TYPE_MAKE_SEND_ONCE,
		has_voucher ? MACH_MSG_TYPE_MOVE_SEND : 0);

	mr = ipc_kmsg_copyin_from_kernel(kmsg);
	if (mr != MACH_MSG_SUCCESS) {
		/* Remove the voucher from the kmsg */
		if (has_voucher) {
			voucher_port = ipc_kmsg_get_voucher_port(kmsg);
			ipc_kmsg_clear_voucher_port(kmsg);
			ipc_port_release_send(voucher_port);
		}

		ipc_kmsg_free(kmsg);
		KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_END, mr);
		return mr;
	}

	if (message_moved) {
		*message_moved = TRUE;
	}

	/*
	 * Destination port would be needed during receive for creating
	 * Sync IPC linkage with kernel special reply port, grab a reference
	 * of the destination port before it gets donated to mqueue in ipc_kmsg_send.
	 */
	dest = hdr->msgh_remote_port;
	ip_reference(dest);

	mr = ipc_kmsg_send(kmsg, option, MACH_MSG_TIMEOUT_NONE);
	if (mr != MACH_MSG_SUCCESS) {
		ip_release(dest);
		ipc_kmsg_destroy(kmsg, IPC_KMSG_DESTROY_ALL);
		KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_END, mr);
		return mr;
	}

	for (;;) {
		assert(!ip_in_pset(reply));
		require_ip_active(reply);

		/* JMM - why this check? */
		if (interruptible && !self->active && !self->inspection) {
			ip_release(dest);
			thread_dealloc_kernel_special_reply_port(current_thread());
			return MACH_RCV_INTERRUPTED;
		}

		/* Setup the sync IPC linkage for the special reply port */
		ipc_port_link_special_reply_port(reply,
		    dest, FALSE);

		bzero(&self->ith_receive, sizeof(self->ith_receive));
		self->ith_recv_bufs = (mach_msg_recv_bufs_t){
			.recv_msg_size = MACH_MSG_SIZE_MAX,
		};
		self->ith_object = IPC_OBJECT_NULL;
		self->ith_option = MACH64_MSG_OPTION_NONE;
		self->ith_knote  = ITH_KNOTE_NULL; /* not part of ith_receive */

		ipc_mqueue_receive(&reply->ip_waitq, MACH_MSG_TIMEOUT_NONE,
		    interruptible ? THREAD_INTERRUPTIBLE : THREAD_UNINT,
		    self, /* continuation ? */ false);

		mr = self->ith_state;
		kmsg = self->ith_kmsg;
		seqno = self->ith_seqno;

		mach_msg_receive_results_complete(ip_to_object(reply));

		if (mr == MACH_MSG_SUCCESS) {
			break;
		}

		assert(mr == MACH_RCV_INTERRUPTED);
		assert(interruptible);
		assert(reply == self->ith_kernel_reply_port);

		if (thread_ast_peek(self, AST_APC)) {
			ip_release(dest);
			thread_dealloc_kernel_special_reply_port(current_thread());
			return mr;
		}
	}

	/* release the destination port ref acquired above */
	ip_release(dest);
	dest = IPC_PORT_NULL;

	/* reload hdr from reply kmsg got above */
	hdr = ikm_header(kmsg);

	mach_msg_size_t kmsg_size = hdr->msgh_size;
	mach_msg_size_t kmsg_and_max_trailer_size;

	/*
	 * The amount of trailer to receive is flexible (see below),
	 * but the kmsg header must have a size that allows for a maximum
	 * trailer to follow as that's how IPC works (otherwise it might be corrupt).
	 */
	if (os_add_overflow(kmsg_size, MAX_TRAILER_SIZE, &kmsg_and_max_trailer_size)) {
		panic("kernel_mach_msg_rpc");
	}

	/* The message header and body itself must be receivable */
	if (rcv_size < kmsg_size) {
		ipc_kmsg_destroy(kmsg, IPC_KMSG_DESTROY_ALL);
		return MACH_RCV_TOO_LARGE;
	}

	/*
	 *	We want to preserve rights and memory in reply!
	 *	We don't have to put them anywhere; just leave them
	 *	as they are.
	 */
	ipc_kmsg_copyout_dest_to_kernel(kmsg, ipc_space_reply);

	mach_msg_format_0_trailer_t *trailer =  (mach_msg_format_0_trailer_t *)
	    ipc_kmsg_get_trailer(kmsg);

	/* Determine what trailer bits we can receive (as no option specified) */
	if (rcv_size < kmsg_size + MACH_MSG_TRAILER_MINIMUM_SIZE) {
		rcv_size = kmsg_size;
	} else {
		if (rcv_size >= kmsg_and_max_trailer_size) {
			/*
			 * Enough room for a maximum trailer.
			 * JMM - we really should set the expected receiver-set fields:
			 *       (seqno, context, filterid, etc...) but nothing currently
			 *       expects them anyway.
			 */
			trailer->msgh_trailer_size = MAX_TRAILER_SIZE;
			rcv_size = kmsg_and_max_trailer_size;
		} else {
			assert(trailer->msgh_trailer_size == MACH_MSG_TRAILER_MINIMUM_SIZE);
			rcv_size = kmsg_size + MACH_MSG_TRAILER_MINIMUM_SIZE;
		}
	}
	assert(trailer->msgh_trailer_type == MACH_MSG_TRAILER_FORMAT_0);
	mr = MACH_MSG_SUCCESS;

	ipc_kmsg_put_to_kernel(msg, options, kmsg, rcv_size);
	return mr;
}

mach_msg_return_t
kernel_mach_msg_rpc(
	mach_msg_header_t       *msg,
	mach_msg_size_t         send_size,
	mach_msg_size_t         rcv_size,
	boolean_t               interruptible,
	boolean_t              *message_moved)
{
	mach_msg_option64_t options = MACH64_MSG_OPTION_NONE;

	return kernel_mach_msg_rpc_common(msg, send_size, rcv_size,
	           interruptible, options, message_moved);
}

mach_msg_return_t
mach_msg_rpc_from_kernel(
	mach_msg_header_t       *msg,
	mach_msg_size_t         send_size,
	mach_msg_size_t         rcv_size)
{
	mach_msg_option64_t options = MACH64_MSG_OPTION_NONE;

	return kernel_mach_msg_rpc_common(msg, send_size, rcv_size, TRUE,
	           options, NULL);
}

/* same as mach_msg_rpc_from_kernel but for kexts */
extern typeof(mach_msg_rpc_from_kernel) mach_msg_rpc_from_kernel_proper;
mach_msg_return_t
mach_msg_rpc_from_kernel_proper(
	mach_msg_header_t       *msg,
	mach_msg_size_t         send_size,
	mach_msg_size_t         rcv_size)
{
	mach_msg_option64_t options = MACH64_POLICY_KERNEL_EXTENSION;

	return kernel_mach_msg_rpc_common(msg, send_size, rcv_size, TRUE,
	           options, NULL);
}

/*
 *	Routine:	mach_msg_destroy_from_kernel
 *	Purpose:
 *		mach_msg_destroy_from_kernel is used to destroy
 *		an unwanted/unexpected reply message from a MIG
 *		kernel-specific user-side stub.	It is like ipc_kmsg_destroy(),
 *		except we no longer have the kmsg - just the contents.
 */
void
mach_msg_destroy_from_kernel(mach_msg_header_t *msg)
{
	mach_msg_bits_t mbits = msg->msgh_bits;
	ipc_port_t      port = msg->msgh_remote_port;

	if (IP_VALID(port)) {
		ipc_object_destroy(port, MACH_MSGH_BITS_REMOTE(mbits));
		msg->msgh_remote_port = IP_NULL;
	}

	/*
	 * The destination (now in msg->msgh_local_port via
	 * ipc_kmsg_copyout_dest_to_kernel) has been consumed with
	 * ipc_object_copyout_dest.
	 */

	/* MIG kernel users don't receive vouchers */
	assert(!MACH_MSGH_BITS_VOUCHER(mbits));

	/* For simple messages, we're done */
	if (mbits & MACH_MSGH_BITS_COMPLEX) {
		mach_msg_kbase_t *kbase = mach_msg_header_to_kbase(msg);

		ipc_kmsg_clean_descriptors(kbase->msgb_dsc_array,
		    kbase->msgb_dsc_count);
	}
}

/* same as mach_msg_destroy_from_kernel but for kexts */
extern typeof(mach_msg_destroy_from_kernel) mach_msg_destroy_from_kernel_proper;
void
mach_msg_destroy_from_kernel_proper(mach_msg_header_t *msg)
{
	if (msg->msgh_bits & MACH_MSGH_BITS_COMPLEX) {
		mach_msg_kbase_t *kbase = mach_msg_header_to_kbase(msg);

		ipc_kmsg_sign_descriptors(kbase->msgb_dsc_array,
		    kbase->msgb_dsc_count);
	}
	mach_msg_destroy_from_kernel(msg);
}


/************** These Calls are set up for kernel-loaded tasks/threads **************/

/*
 *	Routine:	mig_get_reply_port
 *	Purpose:
 *		Called by client side interfaces living in the kernel
 *		to get a reply port.
 */
mach_port_t
mig_get_reply_port(void)
{
	return MACH_PORT_NULL;
}

/*
 *	Routine:	mig_dealloc_reply_port
 *	Purpose:
 *		Called by client side interfaces to get rid of a reply port.
 */

void
mig_dealloc_reply_port(
	__unused mach_port_t reply_port)
{
}

/*
 *	Routine:	mig_put_reply_port
 *	Purpose:
 *		Called by client side interfaces after each RPC to
 *		let the client recycle the reply port if it wishes.
 */
void
mig_put_reply_port(
	__unused mach_port_t reply_port)
{
}

/*
 * mig_strncpy.c - by Joshua Block
 *
 * mig_strncp -- Bounded string copy.  Does what the library routine strncpy
 * OUGHT to do:  Copies the (null terminated) string in src into dest, a
 * buffer of length len.  Assures that the copy is still null terminated
 * and doesn't overflow the buffer, truncating the copy if necessary.
 *
 * Parameters:
 *
 *     dest - Pointer to destination buffer.
 *
 *     src - Pointer to source string.
 *
 *     len - Length of destination buffer.
 */
int
mig_strncpy(
	char            *dest,
	const char      *src,
	int             len)
{
	int i = 0;

	if (len > 0) {
		if (dest != NULL) {
			if (src != NULL) {
				for (i = 1; i < len; i++) {
					if (!(*dest++ = *src++)) {
						return i;
					}
				}
			}
			*dest = '\0';
		}
	}
	return i;
}

/*
 * mig_strncpy_zerofill -- Bounded string copy.  Does what the
 * library routine strncpy OUGHT to do:  Copies the (null terminated)
 * string in src into dest, a buffer of length len.  Assures that
 * the copy is still null terminated and doesn't overflow the buffer,
 * truncating the copy if necessary. If the string in src is smaller
 * than given length len, it will zero fill the remaining bytes in dest.
 *
 * Parameters:
 *
 *     dest - Pointer to destination buffer.
 *
 *     src - Pointer to source string.
 *
 *     len - Length of destination buffer.
 */
int
mig_strncpy_zerofill(
	char            *dest,
	const char      *src,
	int             len)
{
	int i = 0;
	boolean_t terminated = FALSE;
	int retval = 0;

	if (len <= 0 || dest == NULL) {
		return 0;
	}

	if (src == NULL) {
		terminated = TRUE;
	}

	for (i = 1; i < len; i++) {
		if (!terminated) {
			if (!(*dest++ = *src++)) {
				retval = i;
				terminated = TRUE;
			}
		} else {
			*dest++ = '\0';
		}
	}

	*dest = '\0';
	if (!terminated) {
		retval = i;
	}

	return retval;
}

void *
mig_user_allocate(
	vm_size_t       size)
{
	return kalloc_type_var_impl(KT_IPC_KMSG_KDATA_OOL,
	           size, Z_WAITOK, NULL);
}

void
mig_user_deallocate(
	char            *data,
	vm_size_t       size)
{
	kfree_type_var_impl(KT_IPC_KMSG_KDATA_OOL, data, size);
}
