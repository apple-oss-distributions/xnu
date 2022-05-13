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
 * @OSF_FREE_COPYRIGHT@
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
 *	File:	ipc/ipc_mqueue.c
 *	Author:	Rich Draves
 *	Date:	1989
 *
 *	Functions to manipulate IPC message queues.
 */
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2006 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */


#include <mach/port.h>
#include <mach/message.h>
#include <mach/sync_policy.h>

#include <kern/assert.h>
#include <kern/counter.h>
#include <kern/sched_prim.h>
#include <kern/ipc_kobject.h>
#include <kern/ipc_mig.h>       /* XXX - for mach_msg_receive_continue */
#include <kern/misc_protos.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/waitq.h>

#include <ipc/port.h>
#include <ipc/ipc_mqueue.h>
#include <ipc/ipc_kmsg.h>
#include <ipc/ipc_right.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_pset.h>
#include <ipc/ipc_space.h>

#if MACH_FLIPC
#include <ipc/flipc.h>
#endif

#ifdef __LP64__
#include <vm/vm_map.h>
#endif

#include <sys/event.h>

extern char     *proc_name_address(void *p);

int ipc_mqueue_full;            /* address is event for queue space */
int ipc_mqueue_rcv;             /* address is event for message arrival */

/* forward declarations */
static void ipc_mqueue_receive_results(wait_result_t result);
static void ipc_mqueue_peek_on_thread_locked(
	ipc_mqueue_t        port_mq,
	mach_msg_option_t   option,
	thread_t            thread);

/* Deliver message to message queue or waiting receiver */
static void ipc_mqueue_post(
	ipc_mqueue_t            mqueue,
	ipc_kmsg_t              kmsg,
	mach_msg_option_t       option);

/*
 *	Routine:	ipc_mqueue_init
 *	Purpose:
 *		Initialize a newly-allocated message queue.
 */
void
ipc_mqueue_init(
	ipc_mqueue_t            mqueue)
{
	ipc_kmsg_queue_init(&mqueue->imq_messages);
	mqueue->imq_qlimit = MACH_PORT_QLIMIT_DEFAULT;
	klist_init(&mqueue->imq_klist);
}

/*
 *	Routine:	ipc_mqueue_add_locked.
 *	Purpose:
 *		Associate the portset's mqueue with the port's mqueue.
 *		This has to be done so that posting the port will wakeup
 *		a portset waiter.  If there are waiters on the portset
 *		mqueue and messages on the port mqueue, try to match them
 *		up now.
 *	Conditions:
 *		Port and Pset both locked.
 */
kern_return_t
ipc_mqueue_add_locked(
	ipc_mqueue_t    port_mqueue,
	ipc_pset_t      pset,
	waitq_link_t   *linkp)
{
	ipc_port_t       port = ip_from_mq(port_mqueue);
	struct waitq_set *wqset = &pset->ips_wqset;
	ipc_kmsg_queue_t kmsgq = &port_mqueue->imq_messages;
	kern_return_t    kr = KERN_SUCCESS;
	ipc_kmsg_t       kmsg;

	kr = waitq_link_locked(&port->ip_waitq, wqset, linkp);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	/*
	 * Now that the set has been added to the port, there may be
	 * messages queued on the port and threads waiting on the set
	 * waitq.  Lets get them together.
	 *
	 * Only consider this set however, as the other ones have been
	 * posted to already.
	 */
	while ((kmsg = ipc_kmsg_queue_first(kmsgq)) != IKM_NULL) {
		thread_t th;
		mach_msg_size_t msize;
		spl_t th_spl;

		th = waitq_wakeup64_identify_locked(
			wqset, IPC_MQUEUE_RECEIVE,
			THREAD_AWAKENED, &th_spl,
			WAITQ_ALL_PRIORITIES, WAITQ_KEEP_LOCKED);
		/* port and pset still locked, thread locked */

		if (th == THREAD_NULL) {
			/*
			 * Didn't find a thread to wake up but messages
			 * are enqueued, prepost the set instead,
			 * as calling waitq_wakeup64_identify_locked()
			 * on the set directly will not take care of it.
			 */
			waitq_link_prepost_locked(&port->ip_waitq, wqset);
			break;
		}

		/*
		 * If the receiver waited with a facility not directly
		 * related to Mach messaging, then it isn't prepared to get
		 * handed the message directly.  Just set it running, and
		 * go look for another thread that can.
		 */
		if (th->ith_state != MACH_RCV_IN_PROGRESS) {
			if (th->ith_state == MACH_PEEK_IN_PROGRESS) {
				/*
				 * wakeup the peeking thread, but
				 * continue to loop over the threads
				 * waiting on the port's mqueue to see
				 * if there are any actual receivers
				 */
				ipc_mqueue_peek_on_thread_locked(port_mqueue,
				    th->ith_option,
				    th);
			}
			thread_unlock(th);
			splx(th_spl);
			continue;
		}

		/*
		 * Found a receiver. see if they can handle the message
		 * correctly (the message is not too large for them, or
		 * they didn't care to be informed that the message was
		 * too large).  If they can't handle it, take them off
		 * the list and let them go back and figure it out and
		 * just move onto the next.
		 */
		msize = ipc_kmsg_copyout_size(kmsg, th->map);
		if (th->ith_rsize <
		    (msize + REQUESTED_TRAILER_SIZE(thread_is_64bit_addr(th), th->ith_option))) {
			th->ith_state = MACH_RCV_TOO_LARGE;
			th->ith_msize = msize;
			if (th->ith_option & MACH_RCV_LARGE) {
				/*
				 * let him go without message
				 */
				th->ith_receiver_name = port_mqueue->imq_receiver_name;
				th->ith_kmsg = IKM_NULL;
				th->ith_seqno = 0;
				thread_unlock(th);
				splx(th_spl);
				continue; /* find another thread */
			}
		} else {
			th->ith_state = MACH_MSG_SUCCESS;
		}

		/*
		 * This thread is going to take this message,
		 * so give it to him.
		 */
		ipc_kmsg_rmqueue(kmsgq, kmsg);
#if MACH_FLIPC
		mach_node_t  node = kmsg->ikm_node;
#endif
		ipc_mqueue_release_msgcount(port_mqueue);

		th->ith_kmsg = kmsg;
		th->ith_seqno = port_mqueue->imq_seqno++;
		thread_unlock(th);
		splx(th_spl);
#if MACH_FLIPC
		if (MACH_NODE_VALID(node) && FPORT_VALID(port_mqueue->imq_fport)) {
			flipc_msg_ack(node, port_mqueue, TRUE);
		}
#endif
	}

	return KERN_SUCCESS;
}


/*
 *	Routine:	ipc_port_has_klist
 *	Purpose:
 *		Returns whether the given port imq_klist field can be used as a klist.
 */
bool
ipc_port_has_klist(ipc_port_t port)
{
	return !port->ip_specialreply &&
	       port->ip_sync_link_state == PORT_SYNC_LINK_ANY;
}

static inline struct klist *
ipc_object_klist(ipc_object_t object)
{
	if (io_otype(object) == IOT_PORT) {
		ipc_port_t port = ip_object_to_port(object);

		return ipc_port_has_klist(port) ? &port->ip_klist : NULL;
	}
	return &ips_object_to_pset(object)->ips_klist;
}

/*
 *	Routine:	ipc_mqueue_changed
 *	Purpose:
 *		Wake up receivers waiting in a message queue.
 *	Conditions:
 *		The object containing the message queue is locked.
 */
void
ipc_mqueue_changed(
	ipc_space_t         space,
	struct waitq       *waitq)
{
	ipc_object_t object = io_from_waitq(waitq);
	struct klist *klist = ipc_object_klist(object);

	if (klist && SLIST_FIRST(klist)) {
		/*
		 * Indicate that this message queue is vanishing
		 *
		 * When this is called, the associated receive right may be in flight
		 * between two tasks: the one it used to live in, and the one that armed
		 * a port destroyed notification for it.
		 *
		 * The new process may want to register the port it gets back with an
		 * EVFILT_MACHPORT filter again, and may have pending sync IPC on this
		 * port pending already, in which case we want the imq_klist field to be
		 * reusable for nefarious purposes.
		 *
		 * Fortunately, we really don't need this linkage anymore after this
		 * point as EV_VANISHED / EV_EOF will be the last thing delivered ever.
		 *
		 * Note: we don't have the space lock here, however, this covers the
		 *       case of when a task is terminating the space, triggering
		 *       several knote_vanish() calls.
		 *
		 *       We don't need the lock to observe that the space is inactive as
		 *       we just deactivated it on the same thread.
		 *
		 *       We still need to call knote_vanish() so that the knote is
		 *       marked with EV_VANISHED or EV_EOF so that the detach step
		 *       in filt_machportdetach is skipped correctly.
		 */
		assert(space);
		knote_vanish(klist, is_active(space));
	}

	if (io_otype(object) == IOT_PORT) {
		ipc_port_adjust_sync_link_state_locked(ip_object_to_port(object),
		    PORT_SYNC_LINK_ANY, NULL);
	} else {
		klist_init(klist);
	}

	waitq_wakeup64_all_locked(waitq, IPC_MQUEUE_RECEIVE,
	    THREAD_RESTART, WAITQ_ALL_PRIORITIES, WAITQ_KEEP_LOCKED);
}




/*
 *	Routine:	ipc_mqueue_send
 *	Purpose:
 *		Send a message to a message queue.  The message holds a reference
 *		for the destination port for this message queue in the
 *		msgh_remote_port field.
 *
 *		If unsuccessful, the caller still has possession of
 *		the message and must do something with it.  If successful,
 *		the message is queued, given to a receiver, or destroyed.
 *	Conditions:
 *		port is locked.
 *	Returns:
 *		MACH_MSG_SUCCESS	The message was accepted.
 *		MACH_SEND_TIMED_OUT	Caller still has message.
 *		MACH_SEND_INTERRUPTED	Caller still has message.
 */
mach_msg_return_t
ipc_mqueue_send_locked(
	ipc_mqueue_t            mqueue,
	ipc_kmsg_t              kmsg,
	mach_msg_option_t       option,
	mach_msg_timeout_t  send_timeout)
{
	ipc_port_t port = ip_from_mq(mqueue);
	int wresult;

	/*
	 *  Don't block if:
	 *	1) We're under the queue limit.
	 *	2) Caller used the MACH_SEND_ALWAYS internal option.
	 *	3) Message is sent to a send-once right.
	 */
	if (!imq_full(mqueue) ||
	    (!imq_full_kernel(mqueue) &&
	    ((option & MACH_SEND_ALWAYS) ||
	    (MACH_MSGH_BITS_REMOTE(kmsg->ikm_header->msgh_bits) ==
	    MACH_MSG_TYPE_PORT_SEND_ONCE)))) {
		mqueue->imq_msgcount++;
		assert(mqueue->imq_msgcount > 0);
		ip_mq_unlock(port);
	} else {
		thread_t cur_thread = current_thread();
		struct turnstile *send_turnstile = TURNSTILE_NULL;
		uint64_t deadline;

		/*
		 * We have to wait for space to be granted to us.
		 */
		if ((option & MACH_SEND_TIMEOUT) && (send_timeout == 0)) {
			ip_mq_unlock(port);
			return MACH_SEND_TIMED_OUT;
		}
		if (imq_full_kernel(mqueue)) {
			ip_mq_unlock(port);
			return MACH_SEND_NO_BUFFER;
		}
		port->ip_fullwaiters = true;

		if (option & MACH_SEND_TIMEOUT) {
			clock_interval_to_deadline(send_timeout, 1000 * NSEC_PER_USEC, &deadline);
		} else {
			deadline = 0;
		}

		thread_set_pending_block_hint(cur_thread, kThreadWaitPortSend);

		send_turnstile = turnstile_prepare((uintptr_t)port,
		    port_send_turnstile_address(port),
		    TURNSTILE_NULL, TURNSTILE_SYNC_IPC);

		ipc_port_send_update_inheritor(port, send_turnstile,
		    TURNSTILE_DELAYED_UPDATE);

		wresult = waitq_assert_wait64_leeway(
			&send_turnstile->ts_waitq,
			IPC_MQUEUE_FULL,
			THREAD_ABORTSAFE,
			TIMEOUT_URGENCY_USER_NORMAL,
			deadline,
			TIMEOUT_NO_LEEWAY);

		ip_mq_unlock(port);
		turnstile_update_inheritor_complete(send_turnstile,
		    TURNSTILE_INTERLOCK_NOT_HELD);

		if (wresult == THREAD_WAITING) {
			wresult = thread_block(THREAD_CONTINUE_NULL);
		}

		/* Call turnstile complete with interlock held */
		ip_mq_lock(port);
		turnstile_complete((uintptr_t)port, port_send_turnstile_address(port), NULL, TURNSTILE_SYNC_IPC);
		ip_mq_unlock(port);

		/* Call cleanup after dropping the interlock */
		turnstile_cleanup();

		switch (wresult) {
		case THREAD_AWAKENED:
			/*
			 * we can proceed - inherited msgcount from waker
			 * or the message queue has been destroyed and the msgcount
			 * has been reset to zero (will detect in ipc_mqueue_post()).
			 */
			break;

		case THREAD_TIMED_OUT:
			assert(option & MACH_SEND_TIMEOUT);
			return MACH_SEND_TIMED_OUT;

		case THREAD_INTERRUPTED:
			return MACH_SEND_INTERRUPTED;

		case THREAD_RESTART:
			/* mqueue is being destroyed */
			return MACH_SEND_INVALID_DEST;
		default:
			panic("ipc_mqueue_send");
		}
	}

	ipc_mqueue_post(mqueue, kmsg, option);
	return MACH_MSG_SUCCESS;
}

/*
 *	Routine:	ipc_mqueue_override_send_locked
 *	Purpose:
 *		Set an override qos on the first message in the queue
 *		(if the queue is full). This is a send-possible override
 *		that will go away as soon as we drain a message from the
 *		queue.
 *
 *	Conditions:
 *		The port corresponding to mqueue is locked.
 *		The caller holds a reference on the message queue.
 */
void
ipc_mqueue_override_send_locked(
	ipc_mqueue_t        mqueue,
	mach_msg_qos_t      qos_ovr)
{
	ipc_port_t port = ip_from_mq(mqueue);
	boolean_t __unused full_queue_empty = FALSE;

	assert(waitq_is_valid(&port->ip_waitq));

	if (imq_full(mqueue)) {
		ipc_kmsg_t first = ipc_kmsg_queue_first(&mqueue->imq_messages);

		if (first && ipc_kmsg_override_qos(&mqueue->imq_messages, first, qos_ovr)) {
			if (ip_in_a_space(port) &&
			    is_active(ip_get_receiver(port)) &&
			    ipc_port_has_klist(port)) {
				KNOTE(&port->ip_klist, 0);
			}
		}
		if (!first) {
			full_queue_empty = TRUE;
		}
	}

#if DEVELOPMENT || DEBUG
	if (full_queue_empty) {
		int dst_pid = 0;
		dst_pid = ipc_port_get_receiver_task(port, NULL);
	}
#endif
}

/*
 *	Routine:	ipc_mqueue_release_msgcount
 *	Purpose:
 *		Release a message queue reference in the case where we
 *		found a waiter.
 *
 *	Conditions:
 *		The port corresponding to message queue is locked.
 *		The message corresponding to this reference is off the queue.
 *		There is no need to pass reserved preposts because this will
 *		never prepost to anyone
 */
void
ipc_mqueue_release_msgcount(ipc_mqueue_t port_mq)
{
	ipc_port_t port = ip_from_mq(port_mq);
	struct turnstile *send_turnstile = port_send_turnstile(port);

	ip_mq_lock_held(port);
	assert(port_mq->imq_msgcount > 1 || ipc_kmsg_queue_empty(&port_mq->imq_messages));

	port_mq->imq_msgcount--;

	if (!imq_full(port_mq) && port->ip_fullwaiters &&
	    send_turnstile != TURNSTILE_NULL) {
		/*
		 * boost the priority of the awoken thread
		 * (WAITQ_PROMOTE_PRIORITY) to ensure it uses
		 * the message queue slot we've just reserved.
		 *
		 * NOTE: this will never prepost
		 *
		 * The wakeup happens on a turnstile waitq
		 * which will wakeup the highest priority waiter.
		 * A potential downside of this would be starving low
		 * priority senders if there is a constant churn of
		 * high priority threads trying to send to this port.
		 */
		if (waitq_wakeup64_one(&send_turnstile->ts_waitq,
		    IPC_MQUEUE_FULL,
		    THREAD_AWAKENED,
		    WAITQ_PROMOTE_PRIORITY) != KERN_SUCCESS) {
			port->ip_fullwaiters = false;
		} else {
			/* gave away our slot - add reference back */
			port_mq->imq_msgcount++;
		}
	}

	if (ipc_kmsg_queue_empty(&port_mq->imq_messages)) {
		waitq_clear_prepost_locked(&port->ip_waitq);
	}
}

/*
 *	Routine:	ipc_mqueue_post
 *	Purpose:
 *		Post a message to a waiting receiver or enqueue it.  If a
 *		receiver is waiting, we can release our reserved space in
 *		the message queue.
 *
 *	Conditions:
 *		port is unlocked
 *		If we need to queue, our space in the message queue is reserved.
 */
static void
ipc_mqueue_post(
	ipc_mqueue_t               mqueue,
	ipc_kmsg_t                 kmsg,
	mach_msg_option_t __unused option)
{
	ipc_port_t port = ip_from_mq(mqueue);
	struct waitq *waitq = &port->ip_waitq;
	boolean_t destroy_msg = FALSE;

	ipc_kmsg_trace_send(kmsg, option);

	/*
	 *	While the msg queue is locked, we have control of the
	 *	kmsg, so the ref in it for the port is still good.
	 *
	 *	Check for a receiver for the message.
	 */
	ip_mq_lock(port);

	/* we may have raced with port destruction! */
	if (!waitq_is_valid(&port->ip_waitq)) {
		destroy_msg = TRUE;
		goto out_unlock;
	}

	for (;;) {
		spl_t th_spl;
		thread_t receiver;
		mach_msg_size_t msize;

		receiver = waitq_wakeup64_identify_locked(waitq,
		    IPC_MQUEUE_RECEIVE, THREAD_AWAKENED,
		    &th_spl, WAITQ_ALL_PRIORITIES, WAITQ_KEEP_LOCKED);
		/* waitq still locked, thread locked */

		if (receiver == THREAD_NULL) {
			/*
			 * no receivers; queue kmsg if space still reserved
			 * Reservations are cancelled when the port goes inactive.
			 * note that this will enqueue the message for any
			 * "peeking" receivers.
			 *
			 * Also, post the knote to wake up any threads waiting
			 * on that style of interface if this insertion is of
			 * note (first insertion, or adjusted override qos all
			 * the way to the head of the queue).
			 *
			 * This is just for ports. port-sets knotes are being
			 * posted to by the waitq_wakeup64_identify_locked()
			 * above already.
			 */
			if (mqueue->imq_msgcount == 0) {
				/*
				 * The message queue must belong
				 * to an inactive port, so just destroy
				 * the message and pretend it was posted.
				 */
				destroy_msg = TRUE;
			} else if (!ipc_kmsg_enqueue_qos(&mqueue->imq_messages, kmsg)) {
				/*
				 * queue was not empty and qos
				 * didn't change, nothing to do.
				 */
			} else if (ip_in_a_space(port) &&
			    is_active(ip_get_receiver(port)) &&
			    ipc_port_has_klist(port)) {
				/*
				 * queue was empty or qos changed
				 * we need to tell kqueue, unless
				 * the space is getting torn down
				 */
				KNOTE(&port->ip_klist, 0);
			}
			break;
		}

		/*
		 * If a thread is attempting a "peek" into the message queue
		 * (MACH_PEEK_IN_PROGRESS), then we enqueue the message and set the
		 * thread running.  A successful peek is essentially the same as
		 * message delivery since the peeking thread takes responsibility
		 * for delivering the message and (eventually) removing it from
		 * the mqueue.  Only one thread can successfully use the peek
		 * facility on any given port, so we exit the waitq loop after
		 * encountering such a thread.
		 */
		if (receiver->ith_state == MACH_PEEK_IN_PROGRESS && mqueue->imq_msgcount > 0) {
			ipc_kmsg_enqueue_qos(&mqueue->imq_messages, kmsg);
			ipc_mqueue_peek_on_thread_locked(mqueue, receiver->ith_option, receiver);
			thread_unlock(receiver);
			splx(th_spl);
			break; /* Message was posted, so break out of loop */
		}

		/*
		 * If the receiver waited with a facility not directly related
		 * to Mach messaging, then it isn't prepared to get handed the
		 * message directly. Just set it running, and go look for
		 * another thread that can.
		 */
		if (receiver->ith_state != MACH_RCV_IN_PROGRESS) {
			thread_unlock(receiver);
			splx(th_spl);
			continue;
		}


		/*
		 * We found a waiting thread.
		 * If the message is too large or the scatter list is too small
		 * the thread we wake up will get that as its status.
		 */
		msize = ipc_kmsg_copyout_size(kmsg, receiver->map);
		if (receiver->ith_rsize <
		    (msize + REQUESTED_TRAILER_SIZE(thread_is_64bit_addr(receiver), receiver->ith_option))) {
			receiver->ith_msize = msize;
			receiver->ith_state = MACH_RCV_TOO_LARGE;
		} else {
			receiver->ith_state = MACH_MSG_SUCCESS;
		}

		/*
		 * If there is no problem with the upcoming receive, or the
		 * receiver thread didn't specifically ask for special too
		 * large error condition, go ahead and select it anyway.
		 */
		if ((receiver->ith_state == MACH_MSG_SUCCESS) ||
		    !(receiver->ith_option & MACH_RCV_LARGE)) {
			receiver->ith_kmsg = kmsg;
			receiver->ith_seqno = mqueue->imq_seqno++;
#if MACH_FLIPC
			mach_node_t node = kmsg->ikm_node;
#endif
			thread_unlock(receiver);
			splx(th_spl);

			/* we didn't need our reserved spot in the queue */
			ipc_mqueue_release_msgcount(mqueue);

#if MACH_FLIPC
			if (MACH_NODE_VALID(node) && FPORT_VALID(mqueue->imq_fport)) {
				flipc_msg_ack(node, mqueue, TRUE);
			}
#endif
			break;
		}

		/*
		 * Otherwise, this thread needs to be released to run
		 * and handle its error without getting the message.  We
		 * need to go back and pick another one.
		 */
		receiver->ith_receiver_name = mqueue->imq_receiver_name;
		receiver->ith_kmsg = IKM_NULL;
		receiver->ith_seqno = 0;
		thread_unlock(receiver);
		splx(th_spl);
	}

out_unlock:
	/* clear the waitq boost we may have been given */
	waitq_clear_promotion_locked(waitq, current_thread());
	waitq_unlock(waitq);

	if (destroy_msg) {
		ipc_kmsg_destroy(kmsg, IPC_KMSG_DESTROY_ALL);
	}

	counter_inc(&current_task()->messages_sent);
	return;
}


static void
ipc_mqueue_receive_results(wait_result_t saved_wait_result)
{
	thread_t                self = current_thread();
	mach_msg_option_t       option = self->ith_option;

	/*
	 * why did we wake up?
	 */
	switch (saved_wait_result) {
	case THREAD_TIMED_OUT:
		self->ith_state = MACH_RCV_TIMED_OUT;
		return;

	case THREAD_INTERRUPTED:
		self->ith_state = MACH_RCV_INTERRUPTED;
		return;

	case THREAD_RESTART:
		/* something bad happened to the port/set */
		self->ith_state = MACH_RCV_PORT_CHANGED;
		return;

	case THREAD_AWAKENED:
		/*
		 * We do not need to go select a message, somebody
		 * handed us one (or a too-large indication).
		 */
		switch (self->ith_state) {
		case MACH_RCV_SCATTER_SMALL:
		case MACH_RCV_TOO_LARGE:
			/*
			 * Somebody tried to give us a too large
			 * message. If we indicated that we cared,
			 * then they only gave us the indication,
			 * otherwise they gave us the indication
			 * AND the message anyway.
			 */
			if (option & MACH_RCV_LARGE) {
				return;
			}
			return;
		case MACH_MSG_SUCCESS:
			return;
		case MACH_PEEK_READY:
			return;

		default:
			panic("ipc_mqueue_receive_results: strange ith_state");
		}

	default:
		panic("ipc_mqueue_receive_results: strange wait_result");
	}
}

void
ipc_mqueue_receive_continue(
	__unused void *param,
	wait_result_t wresult)
{
	ipc_mqueue_receive_results(wresult);
	mach_msg_receive_continue();  /* hard-coded for now */
}

/*
 *	Routine:	ipc_mqueue_receive
 *	Purpose:
 *		Receive a message from a message queue.
 *
 *	Conditions:
 *		Our caller must hold a reference for the port or port set
 *		to which this queue belongs, to keep the queue
 *		from being deallocated.
 *
 *		The kmsg is returned with clean header fields
 *		and with the circular bit turned off through the ith_kmsg
 *		field of the thread's receive continuation state.
 *	Returns:
 *		MACH_MSG_SUCCESS	Message returned in ith_kmsg.
 *		MACH_RCV_TOO_LARGE	Message size returned in ith_msize.
 *		MACH_RCV_TIMED_OUT	No message obtained.
 *		MACH_RCV_INTERRUPTED	No message obtained.
 *		MACH_RCV_PORT_DIED	Port/set died; no message.
 *		MACH_RCV_PORT_CHANGED	Port moved into set; no msg.
 *
 */

void
ipc_mqueue_receive(
	struct waitq           *waitq,
	mach_msg_option_t       option,
	mach_msg_size_t         max_size,
	mach_msg_timeout_t      rcv_timeout,
	int                     interruptible)
{
	wait_result_t           wresult;
	thread_t                self = current_thread();

	waitq_lock(waitq);

	wresult = ipc_mqueue_receive_on_thread_and_unlock(waitq, option, max_size,
	    rcv_timeout, interruptible, self);
	/* object unlocked */
	if (wresult == THREAD_NOT_WAITING) {
		return;
	}

	if (wresult == THREAD_WAITING) {
		if (self->ith_continuation) {
			thread_block(ipc_mqueue_receive_continue);
		}
		/* NOTREACHED */

		wresult = thread_block(THREAD_CONTINUE_NULL);
	}
	ipc_mqueue_receive_results(wresult);
}

/*
 *	Routine:	ipc_mqueue_receive_on_thread_and_unlock
 *	Purpose:
 *		Receive a message from a message queue using a specified thread.
 *		If no message available, assert_wait on the appropriate waitq.
 *
 *	Conditions:
 *		Assumes thread is self.
 *		The port/port-set waitq is locked on entry, unlocked on return.
 *		May have assert-waited. Caller must block in those cases.
 */
wait_result_t
ipc_mqueue_receive_on_thread_and_unlock(
	struct waitq           *waitq,
	mach_msg_option_t       option,
	mach_msg_size_t         max_size,
	mach_msg_timeout_t      rcv_timeout,
	int                     interruptible,
	thread_t                thread)
{
	ipc_object_t            object = io_from_waitq(waitq);
	ipc_port_t              port = IP_NULL;
	wait_result_t           wresult;
	uint64_t                deadline;
	struct turnstile        *rcv_turnstile = TURNSTILE_NULL;

	if (waitq_type(waitq) == WQT_PORT_SET) {
		ipc_pset_t pset = ips_object_to_pset(object);
		struct waitq *port_wq;

		/*
		 * Put the message at the back of the prepost list
		 * if it's not a PEEK.
		 *
		 * Might drop the pset lock temporarily.
		 */
		port_wq = waitq_set_first_prepost(&pset->ips_wqset, WQS_PREPOST_LOCK |
		    ((option & MACH_PEEK_MSG) ? WQS_PREPOST_PEEK: 0));

		/* Returns with port locked */

		if (port_wq != NULL) {
			/*
			 * We get here if there is at least one message
			 * waiting on port_wq. We have instructed the prepost
			 * iteration logic to leave both the port_wq and the
			 * set waitq locked.
			 *
			 * Continue on to handling the message with just
			 * the port waitq locked.
			 */
			io_unlock(object);
			port = ip_from_waitq(port_wq);
		}
	} else if (waitq_type(waitq) == WQT_PORT) {
		port = ip_from_waitq(waitq);
		if (ipc_kmsg_queue_empty(&port->ip_messages.imq_messages)) {
			port = IP_NULL;
		}
	} else {
		panic("Unknown waitq type (%p/0x%x)", waitq, waitq_type(waitq));
	}

	if (port) {
		if (option & MACH_PEEK_MSG) {
			ipc_mqueue_peek_on_thread_locked(&port->ip_messages,
			    option, thread);
		} else {
			ipc_mqueue_select_on_thread_locked(&port->ip_messages,
			    option, max_size, thread);
		}
		ip_mq_unlock(port);
		return THREAD_NOT_WAITING;
	}

	if (!waitq_is_valid(waitq)) {
		/* someone raced us to destroy this mqueue/port! */
		io_unlock(object);
		/*
		 * ipc_mqueue_receive_results updates the thread's ith_state
		 * TODO: differentiate between rights being moved and
		 * rights/ports being destroyed (21885327)
		 */
		return THREAD_RESTART;
	}

	/*
	 * Looks like we'll have to block.  The waitq we will
	 * block on (whether the set's or the local port's) is
	 * still locked.
	 */
	if ((option & MACH_RCV_TIMEOUT) && rcv_timeout == 0) {
		io_unlock(object);
		thread->ith_state = MACH_RCV_TIMED_OUT;
		return THREAD_NOT_WAITING;
	}

	thread->ith_option = option;
	thread->ith_rsize = max_size;
	thread->ith_msize = 0;

	if (option & MACH_PEEK_MSG) {
		thread->ith_state = MACH_PEEK_IN_PROGRESS;
	} else {
		thread->ith_state = MACH_RCV_IN_PROGRESS;
	}

	if (option & MACH_RCV_TIMEOUT) {
		clock_interval_to_deadline(rcv_timeout, 1000 * NSEC_PER_USEC, &deadline);
	} else {
		deadline = 0;
	}

	/*
	 * Threads waiting on a reply port (not portset)
	 * will wait on its receive turnstile.
	 *
	 * Donate waiting thread's turnstile and
	 * setup inheritor for special reply port.
	 * Based on the state of the special reply
	 * port, the inheritor would be the send
	 * turnstile of the connection port on which
	 * the send of sync ipc would happen or
	 * workloop's turnstile who would reply to
	 * the sync ipc message.
	 *
	 * Pass in mqueue wait in waitq_assert_wait to
	 * support port set wakeup. The mqueue waitq of port
	 * will be converted to to turnstile waitq
	 * in waitq_assert_wait instead of global waitqs.
	 */
	if (waitq_type(waitq) == WQT_PORT) {
		port = ip_from_waitq(waitq);
		rcv_turnstile = turnstile_prepare((uintptr_t)port,
		    port_rcv_turnstile_address(port),
		    TURNSTILE_NULL, TURNSTILE_SYNC_IPC);

		ipc_port_recv_update_inheritor(port, rcv_turnstile,
		    TURNSTILE_DELAYED_UPDATE);
	}

	thread_set_pending_block_hint(thread, kThreadWaitPortReceive);
	wresult = waitq_assert_wait64_locked(waitq,
	    IPC_MQUEUE_RECEIVE,
	    interruptible,
	    TIMEOUT_URGENCY_USER_NORMAL,
	    deadline,
	    TIMEOUT_NO_LEEWAY,
	    thread);
	if (wresult == THREAD_AWAKENED) {
		/*
		 * The first thing we did was to look for preposts
		 * (using waitq_set_first_prepost() for sets, or looking
		 * at the port's queue for ports).
		 *
		 * Since we found none, we kept the waitq locked.
		 *
		 * It ensures that waitq_assert_wait64_locked() can't
		 * find pre-posts either, won't drop the waitq lock
		 * either (even for a set), and can't return THREAD_AWAKENED.
		 */
		panic("ipc_mqueue_receive_on_thread: sleep walking");
	}

	io_unlock(object);

	/* Check if its a port mqueue and if it needs to call turnstile_update_inheritor_complete */
	if (rcv_turnstile != TURNSTILE_NULL) {
		turnstile_update_inheritor_complete(rcv_turnstile, TURNSTILE_INTERLOCK_NOT_HELD);
	}
	/* Its callers responsibility to call turnstile_complete to get the turnstile back */

	return wresult;
}


/*
 *	Routine:	ipc_mqueue_peek_on_thread_locked
 *	Purpose:
 *		A receiver discovered that there was a message on the queue
 *		before he had to block. Tell a thread about the message queue,
 *		but don't pick off any messages.
 *	Conditions:
 *		port_mq locked
 *		at least one message on port_mq's message queue
 *
 *	Returns: (on thread->ith_state)
 *		MACH_PEEK_READY		ith_peekq contains a message queue
 */
void
ipc_mqueue_peek_on_thread_locked(
	ipc_mqueue_t        port_mq,
	mach_msg_option_t   option,
	thread_t            thread)
{
	(void)option;
	assert(option & MACH_PEEK_MSG);
	assert(ipc_kmsg_queue_first(&port_mq->imq_messages) != IKM_NULL);

	/*
	 * Take a reference on the mqueue's associated port:
	 * the peeking thread will be responsible to release this reference
	 */
	ip_reference(ip_from_mq(port_mq));
	thread->ith_peekq = port_mq;
	thread->ith_state = MACH_PEEK_READY;
}

/*
 *	Routine:	ipc_mqueue_select_on_thread_locked
 *	Purpose:
 *		A receiver discovered that there was a message on the queue
 *		before he had to block.  Pick the message off the queue and
 *		"post" it to thread.
 *	Conditions:
 *		port locked.
 *              thread not locked.
 *		There is a message.
 *		No need to reserve prepost objects - it will never prepost
 *
 *	Returns:
 *		MACH_MSG_SUCCESS	Actually selected a message for ourselves.
 *		MACH_RCV_TOO_LARGE  May or may not have pull it, but it is large
 */
void
ipc_mqueue_select_on_thread_locked(
	ipc_mqueue_t            port_mq,
	mach_msg_option_t       option,
	mach_msg_size_t         max_size,
	thread_t                thread)
{
	ipc_kmsg_t kmsg;
	mach_msg_return_t mr = MACH_MSG_SUCCESS;
	mach_msg_size_t msize;

	/*
	 * Do some sanity checking of our ability to receive
	 * before pulling the message off the queue.
	 */
	kmsg = ipc_kmsg_queue_first(&port_mq->imq_messages);
	assert(kmsg != IKM_NULL);

	/*
	 * If we really can't receive it, but we had the
	 * MACH_RCV_LARGE option set, then don't take it off
	 * the queue, instead return the appropriate error
	 * (and size needed).
	 */
	msize = ipc_kmsg_copyout_size(kmsg, thread->map);
	if (msize + REQUESTED_TRAILER_SIZE(thread_is_64bit_addr(thread), option) > max_size) {
		mr = MACH_RCV_TOO_LARGE;
		if (option & MACH_RCV_LARGE) {
			thread->ith_receiver_name = port_mq->imq_receiver_name;
			thread->ith_kmsg = IKM_NULL;
			thread->ith_msize = msize;
			thread->ith_seqno = 0;
			thread->ith_state = mr;
			return;
		}
	}

	ipc_kmsg_rmqueue(&port_mq->imq_messages, kmsg);
#if MACH_FLIPC
	if (MACH_NODE_VALID(kmsg->ikm_node) && FPORT_VALID(port_mq->imq_fport)) {
		flipc_msg_ack(kmsg->ikm_node, port_mq, TRUE);
	}
#endif
	ipc_mqueue_release_msgcount(port_mq);
	thread->ith_seqno = port_mq->imq_seqno++;
	thread->ith_kmsg = kmsg;
	thread->ith_state = mr;

	counter_inc(&current_task()->messages_received);
	return;
}

/*
 *	Routine:	ipc_mqueue_peek_locked
 *	Purpose:
 *		Peek at a (non-set) message queue to see if it has a message
 *		matching the sequence number provided (if zero, then the
 *		first message in the queue) and return vital info about the
 *		message.
 *
 *	Conditions:
 *		The io object corresponding to mq is locked by callers.
 *		Other locks may be held by callers, so this routine cannot block.
 *		Caller holds reference on the message queue.
 */
unsigned
ipc_mqueue_peek_locked(ipc_mqueue_t mq,
    mach_port_seqno_t * seqnop,
    mach_msg_size_t * msg_sizep,
    mach_msg_id_t * msg_idp,
    mach_msg_max_trailer_t * msg_trailerp,
    ipc_kmsg_t *kmsgp)
{
	ipc_kmsg_queue_t kmsgq;
	ipc_kmsg_t kmsg;
	mach_port_seqno_t seqno, msgoff;
	unsigned res = 0;

	seqno = 0;
	if (seqnop != NULL) {
		seqno = *seqnop;
	}

	if (seqno == 0) {
		seqno = mq->imq_seqno;
		msgoff = 0;
	} else if (seqno >= mq->imq_seqno &&
	    seqno < mq->imq_seqno + mq->imq_msgcount) {
		msgoff = seqno - mq->imq_seqno;
	} else {
		goto out;
	}

	/* look for the message that would match that seqno */
	kmsgq = &mq->imq_messages;
	kmsg = ipc_kmsg_queue_first(kmsgq);
	while (msgoff-- && kmsg != IKM_NULL) {
		kmsg = ipc_kmsg_queue_next(kmsgq, kmsg);
	}
	if (kmsg == IKM_NULL) {
		goto out;
	}

	/* found one - return the requested info */
	if (seqnop != NULL) {
		*seqnop = seqno;
	}
	if (msg_sizep != NULL) {
		*msg_sizep = kmsg->ikm_header->msgh_size;
	}
	if (msg_idp != NULL) {
		*msg_idp = kmsg->ikm_header->msgh_id;
	}
	if (msg_trailerp != NULL) {
		memcpy(msg_trailerp,
		    (mach_msg_max_trailer_t *)((vm_offset_t)kmsg->ikm_header +
		    mach_round_msg(kmsg->ikm_header->msgh_size)),
		    sizeof(mach_msg_max_trailer_t));
	}
	if (kmsgp != NULL) {
		*kmsgp = kmsg;
	}

	res = 1;

out:
	return res;
}


/*
 *	Routine:	ipc_mqueue_peek
 *	Purpose:
 *		Peek at a (non-set) message queue to see if it has a message
 *		matching the sequence number provided (if zero, then the
 *		first message in the queue) and return vital info about the
 *		message.
 *
 *	Conditions:
 *		The ipc_mqueue_t is unlocked.
 *		Locks may be held by callers, so this routine cannot block.
 *		Caller holds reference on the message queue.
 */
unsigned
ipc_mqueue_peek(ipc_mqueue_t mq,
    mach_port_seqno_t * seqnop,
    mach_msg_size_t * msg_sizep,
    mach_msg_id_t * msg_idp,
    mach_msg_max_trailer_t * msg_trailerp,
    ipc_kmsg_t *kmsgp)
{
	ipc_port_t port = ip_from_mq(mq);
	unsigned res;

	ip_mq_lock(port);

	res = ipc_mqueue_peek_locked(mq, seqnop, msg_sizep, msg_idp,
	    msg_trailerp, kmsgp);

	ip_mq_unlock(port);
	return res;
}

#if MACH_FLIPC
/*
 *	Routine:	ipc_mqueue_release_peek_ref
 *	Purpose:
 *		Release the reference on an mqueue's associated port which was
 *		granted to a thread in ipc_mqueue_peek_on_thread (on the
 *		MACH_PEEK_MSG thread wakeup path).
 *
 *	Conditions:
 *		The ipc_mqueue_t should be locked on entry.
 *		The ipc_mqueue_t will be _unlocked_ on return
 *			(and potentially invalid!)
 *
 */
void
ipc_mqueue_release_peek_ref(ipc_mqueue_t mqueue)
{
	ipc_port_t port = ip_from_mq(mqueue);

	ip_mq_lock_held(port);

	/*
	 * clear any preposts this mq may have generated
	 * (which would cause subsequent immediate wakeups)
	 */
	waitq_clear_prepost_locked(&port->ip_waitq);

	ip_mq_unlock(port);

	/*
	 * release the port reference: we need to do this outside the lock
	 * because we might be holding the last port reference!
	 **/
	ip_release(port);
}
#endif /* MACH_FLIPC */

/*
 *	Routine:	ipc_mqueue_destroy_locked
 *	Purpose:
 *		Destroy a message queue.
 *		Set any blocked senders running.
 *		Destroy the kmsgs in the queue.
 *	Conditions:
 *		port locked
 *		Receivers were removed when the receive right was "changed"
 */
boolean_t
ipc_mqueue_destroy_locked(ipc_mqueue_t mqueue, waitq_link_list_t *free_l)
{
	ipc_port_t port = ip_from_mq(mqueue);
	boolean_t reap = FALSE;
	struct turnstile *send_turnstile = port_send_turnstile(port);

	/*
	 *	rouse all blocked senders
	 *	(don't boost anyone - we're tearing this queue down)
	 *	(never preposts)
	 */
	port->ip_fullwaiters = false;

	if (send_turnstile != TURNSTILE_NULL) {
		waitq_wakeup64_all(&send_turnstile->ts_waitq,
		    IPC_MQUEUE_FULL,
		    THREAD_RESTART,
		    WAITQ_ALL_PRIORITIES);
	}

#if MACH_FLIPC
	ipc_kmsg_t first = ipc_kmsg_queue_first(&mqueue->imq_messages);
	if (first) {
		ipc_kmsg_t kmsg = first;
		do {
			if (MACH_NODE_VALID(kmsg->ikm_node) && FPORT_VALID(mqueue->imq_fport)) {
				flipc_msg_ack(kmsg->ikm_node, mqueue, TRUE);
			}
			kmsg = kmsg->ikm_next;
		} while (kmsg != first);
	}
#endif

	/*
	 * Move messages from the specified queue to the per-thread
	 * clean/drain queue while we have the mqueue lock.
	 */
	reap = ipc_kmsg_delayed_destroy_queue(&mqueue->imq_messages);

	/*
	 * Wipe out message count, both for messages about to be
	 * reaped and for reserved space for (previously) woken senders.
	 * This is the indication to them that their reserved space is gone
	 * (the mqueue was destroyed).
	 */
	mqueue->imq_msgcount = 0;

	/*
	 * invalidate the waitq for subsequent mqueue operations,
	 * the port lock could be dropped after invalidating the mqueue.
	 */

	waitq_invalidate(&port->ip_waitq);

	waitq_unlink_all_locked(&port->ip_waitq, NULL, free_l);

	return reap;
}

/*
 *	Routine:	ipc_mqueue_set_qlimit_locked
 *	Purpose:
 *		Changes a message queue limit; the maximum number
 *		of messages which may be queued.
 *	Conditions:
 *		Port locked.
 */

void
ipc_mqueue_set_qlimit_locked(
	ipc_mqueue_t           mqueue,
	mach_port_msgcount_t   qlimit)
{
	ipc_port_t port = ip_from_mq(mqueue);

	assert(qlimit <= MACH_PORT_QLIMIT_MAX);

	/* wake up senders allowed by the new qlimit */
	if (qlimit > mqueue->imq_qlimit) {
		mach_port_msgcount_t i, wakeup;
		struct turnstile *send_turnstile = port_send_turnstile(port);

		/* caution: wakeup, qlimit are unsigned */
		wakeup = qlimit - mqueue->imq_qlimit;

		for (i = 0; i < wakeup; i++) {
			/*
			 * boost the priority of the awoken thread
			 * (WAITQ_PROMOTE_PRIORITY) to ensure it uses
			 * the message queue slot we've just reserved.
			 *
			 * NOTE: this will never prepost
			 */
			if (send_turnstile == TURNSTILE_NULL ||
			    waitq_wakeup64_one(&send_turnstile->ts_waitq,
			    IPC_MQUEUE_FULL,
			    THREAD_AWAKENED,
			    WAITQ_PROMOTE_PRIORITY) == KERN_NOT_WAITING) {
				port->ip_fullwaiters = false;
				break;
			}
			mqueue->imq_msgcount++;  /* give it to the awakened thread */
		}
	}
	mqueue->imq_qlimit = (uint16_t)qlimit;
}

/*
 *	Routine:	ipc_mqueue_set_seqno_locked
 *	Purpose:
 *		Changes an mqueue's sequence number.
 *	Conditions:
 *		Caller holds a reference to the queue's containing object.
 */
void
ipc_mqueue_set_seqno_locked(
	ipc_mqueue_t            mqueue,
	mach_port_seqno_t       seqno)
{
	mqueue->imq_seqno = seqno;
}


/*
 *	Routine:	ipc_mqueue_copyin
 *	Purpose:
 *		Convert a name in a space to a message queue.
 *	Conditions:
 *		Nothing locked.  If successful, the caller gets a ref for
 *		for the object.	This ref ensures the continued existence of
 *		the queue.
 *	Returns:
 *		MACH_MSG_SUCCESS	Found a message queue.
 *		MACH_RCV_INVALID_NAME	The space is dead.
 *		MACH_RCV_INVALID_NAME	The name doesn't denote a right.
 *		MACH_RCV_INVALID_NAME
 *			The denoted right is not receive or port set.
 *		MACH_RCV_IN_SET		Receive right is a member of a set.
 */

mach_msg_return_t
ipc_mqueue_copyin(
	ipc_space_t             space,
	mach_port_name_t        name,
	ipc_object_t            *objectp)
{
	ipc_entry_bits_t bits;
	ipc_object_t object;
	kern_return_t kr;

	kr = ipc_right_lookup_read(space, name, &bits, &object);
	if (kr != KERN_SUCCESS) {
		return MACH_RCV_INVALID_NAME;
	}
	/* object is locked and active */

	if (bits & MACH_PORT_TYPE_RECEIVE) {
		__assert_only ipc_port_t port = ip_object_to_port(object);
		assert(ip_get_receiver_name(port) == name);
		assert(ip_in_space(port, space));
	}
	if (bits & (MACH_PORT_TYPE_RECEIVE | MACH_PORT_TYPE_PORT_SET)) {
		io_reference(object);
		io_unlock(object);
	} else {
		io_unlock(object);
		/* guard exception if we never held the receive right in this entry */
		if ((bits & MACH_PORT_TYPE_EX_RECEIVE) == 0) {
			mach_port_guard_exception(name, 0, 0, kGUARD_EXC_RCV_INVALID_NAME);
		}
		return MACH_RCV_INVALID_NAME;
	}

	*objectp = object;
	return MACH_MSG_SUCCESS;
}
