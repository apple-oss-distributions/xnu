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
 */
/*
 *	File:	ipc/ipc_mqueue.h
 *	Author:	Rich Draves
 *	Date:	1989
 *
 *	Definitions for message queues.
 */

#ifndef _IPC_IPC_MQUEUE_H_
#define _IPC_IPC_MQUEUE_H_

#include <mach_assert.h>

#include <mach/message.h>

#include <kern/assert.h>
#include <kern/macro_help.h>
#include <kern/kern_types.h>
#include <kern/waitq.h>

#include <ipc/ipc_kmsg.h>
#include <ipc/ipc_object.h>
#include <ipc/ipc_types.h>

#include <sys/event.h>

/* this type doesn't exist and is only used to do math */
struct ipc_object_waitq {
	struct ipc_object       iowq_object;
	struct waitq            iowq_waitq;
};

typedef struct ipc_mqueue {
	struct ipc_kmsg_queue   imq_messages;
	mach_port_seqno_t       imq_seqno;
	mach_port_name_t        imq_receiver_name;
	uint16_t                imq_msgcount;
	uint16_t                imq_qlimit;
	/*
	 * The imq_context structure member fills in a 32-bit padding gap
	 * in ipc_mqueue.
	 */
	uint32_t                imq_context;
#if MACH_FLIPC
	struct flipc_port       *imq_fport; // Null for local port, or ptr to flipc port
#endif
	union {
		/*
		 * Special Reply Ports (ip_specialreply == true):
		 *   only use imq_srp_owner_thread
		 *
		 * Ports, based on ip_sync_link_state, use:
		 * - PORT_SYNC_LINK_ANY:            imq_klist
		 * - PORT_SYNC_LINK_WORKLOOP_KNOTE: imq_inheritor_knote
		 * - PORT_SYNC_LINK_WORKLOOP_STASH: imq_inheritor_turnstile (has a +1)
		 * - PORT_SYNC_LINK_RCV_THREAD: imq_inheritor_thread_ref
		 */
		struct klist            imq_klist;
		struct knote            *imq_inheritor_knote;
		struct turnstile        *imq_inheritor_turnstile;
		thread_t                imq_inheritor_thread_ref;
		thread_t                imq_srp_owner_thread;
	};
} *ipc_mqueue_t;

#define IMQ_NULL                ((ipc_mqueue_t) 0)

#define imq_full(mq)            ((mq)->imq_msgcount >= (mq)->imq_qlimit)
#define imq_full_kernel(mq)     ((mq)->imq_msgcount >= MACH_PORT_QLIMIT_KERNEL)

extern int ipc_mqueue_full;
// extern int ipc_mqueue_rcv;

#define IPC_MQUEUE_FULL         CAST_EVENT64_T(&ipc_mqueue_full)
#define IPC_MQUEUE_RECEIVE      NO_EVENT64

/*
 * Exported interfaces
 */

/* Initialize a newly-allocated message queue */
extern void ipc_mqueue_init(
	ipc_mqueue_t            mqueue);

/* destroy an mqueue */
extern boolean_t ipc_mqueue_destroy_locked(
	ipc_mqueue_t            mqueue,
	waitq_link_list_t      *free_l);

/* Wake up receivers waiting in a message queue */
extern void ipc_mqueue_changed(
	ipc_space_t             space,
	waitq_t                 waitq);

/* Add the specific mqueue as a member of the set */
extern kern_return_t ipc_mqueue_add_locked(
	ipc_mqueue_t            mqueue,
	ipc_pset_t              pset,
	waitq_link_t           *linkp);

/* Send a message to a port */
extern mach_msg_return_t ipc_mqueue_send_locked(
	ipc_mqueue_t            mqueue,
	ipc_kmsg_t              kmsg,
	mach_msg_option_t       option,
	mach_msg_timeout_t      timeout_val);

/* check for queue send queue full of a port */
extern mach_msg_return_t ipc_mqueue_preflight_send(
	ipc_mqueue_t            mqueue,
	ipc_kmsg_t              kmsg,
	mach_msg_option_t       option,
	mach_msg_timeout_t      timeout_val);

/* Set a [send-possible] override on the mqueue */
extern void ipc_mqueue_override_send_locked(
	ipc_mqueue_t            mqueue,
	mach_msg_qos_t          qos_ovr);

/* Receive a message from a message queue */
extern void ipc_mqueue_receive(
	waitq_t                 waitq,
	mach_msg_option_t       option,
	mach_msg_size_t         max_size,
	mach_msg_timeout_t      timeout_val,
	int                     interruptible);

/* Receive a message from a message queue using a specified thread */
extern wait_result_t ipc_mqueue_receive_on_thread_and_unlock(
	waitq_t                 waitq,
	mach_msg_option_t       option,
	mach_msg_size_t         max_size,
	mach_msg_timeout_t      rcv_timeout,
	int                     interruptible,
	thread_t                thread);

/* Continuation routine for message receive */
extern void ipc_mqueue_receive_continue(
	void                    *param,
	wait_result_t           wresult);

/* Select a message from a queue and try to post it to ourself */
extern void ipc_mqueue_select_on_thread_locked(
	ipc_mqueue_t            port_mq,
	mach_msg_option_t       option,
	mach_msg_size_t         max_size,
	thread_t                thread);

/* Peek into a messaqe queue to see if there are messages */
extern unsigned ipc_mqueue_peek(
	ipc_mqueue_t            mqueue,
	mach_port_seqno_t       *msg_seqnop,
	mach_msg_size_t         *msg_sizep,
	mach_msg_id_t           *msg_idp,
	mach_msg_max_trailer_t  *msg_trailerp,
	ipc_kmsg_t              *kmsgp);

/* Peek into a locked messaqe queue to see if there are messages */
extern unsigned ipc_mqueue_peek_locked(
	ipc_mqueue_t            mqueue,
	mach_port_seqno_t       *msg_seqnop,
	mach_msg_size_t         *msg_sizep,
	mach_msg_id_t           *msg_idp,
	mach_msg_max_trailer_t  *msg_trailerp,
	ipc_kmsg_t              *kmsgp);

#if MACH_FLIPC
/* Release an mqueue/port reference that was granted by MACH_PEEK_MSG */
extern void ipc_mqueue_release_peek_ref(
	ipc_mqueue_t            mqueue);
#endif /* MACH_FLIPC */

/* Clear a message count reservation */
extern void ipc_mqueue_release_msgcount(
	ipc_mqueue_t            port_mq);

/* Change a queue limit */
extern void ipc_mqueue_set_qlimit_locked(
	ipc_mqueue_t            mqueue,
	mach_port_msgcount_t    qlimit);

/* Change a queue's sequence number */
extern void ipc_mqueue_set_seqno_locked(
	ipc_mqueue_t            mqueue,
	mach_port_seqno_t       seqno);

/* Convert a name in a space to a message queue */
extern mach_msg_return_t ipc_mqueue_copyin(
	ipc_space_t             space,
	mach_port_name_t        name,
	ipc_object_t            *objectp);

/* Safe to use the klist ptr */
extern bool
ipc_port_has_klist(
	ipc_port_t              port);

#endif  /* _IPC_IPC_MQUEUE_H_ */
