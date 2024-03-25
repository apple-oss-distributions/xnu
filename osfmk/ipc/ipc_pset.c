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
 *	File:	ipc/ipc_pset.c
 *	Author:	Rich Draves
 *	Date:	1989
 *
 *	Functions to manipulate IPC port sets.
 */

#include <mach/port.h>
#include <mach/kern_return.h>
#include <mach/message.h>
#include <ipc/ipc_mqueue.h>
#include <ipc/ipc_object.h>
#include <ipc/ipc_pset.h>
#include <ipc/ipc_right.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_kmsg.h>
#include <kern/policy_internal.h>

#include <kern/kern_types.h>

#include <vm/vm_map.h>
#include <libkern/section_keywords.h>
#include <pthread/priority_private.h>

/* processor_set stole ipc_pset_init */
static void
ipc_port_set_init(ipc_pset_t pset, mach_port_name_t name, int policy)
{
	waitq_init(&pset->ips_wqset, WQT_PORT_SET, policy | SYNC_POLICY_FIFO);
	klist_init(&pset->ips_klist);
	pset->ips_wqset.wqset_index = MACH_PORT_INDEX(name);
}

/*
 *	Routine:	ipc_pset_alloc
 *	Purpose:
 *		Allocate a port set.
 *	Conditions:
 *		Nothing locked.  If successful, the port set is returned
 *		locked.  (The caller doesn't have a reference.)
 *	Returns:
 *		KERN_SUCCESS		The port set is allocated.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_NO_SPACE		No room for an entry in the space.
 */

kern_return_t
ipc_pset_alloc(
	ipc_space_t             space,
	mach_port_name_t        *namep,
	ipc_pset_t              *psetp)
{
	ipc_pset_t pset;
	mach_port_name_t name;
	kern_return_t kr;

	kr = ipc_object_alloc(space, IOT_PORT_SET,
	    MACH_PORT_TYPE_PORT_SET, 0,
	    &name, (ipc_object_t *) &pset);
	if (kr != KERN_SUCCESS) {
		return kr;
	}
	/* space is locked */

	ipc_port_set_init(pset, name, SYNC_POLICY_INIT_LOCKED);
	/* port set is locked */

	is_write_unlock(space);

	*namep = name;
	*psetp = pset;
	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_pset_alloc_name
 *	Purpose:
 *		Allocate a port set, with a specific name.
 *	Conditions:
 *		Nothing locked.  If successful, the port set is returned
 *		locked.  (The caller doesn't have a reference.)
 *	Returns:
 *		KERN_SUCCESS		The port set is allocated.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_NAME_EXISTS	The name already denotes a right.
 */

kern_return_t
ipc_pset_alloc_name(
	ipc_space_t             space,
	mach_port_name_t        name,
	ipc_pset_t              *psetp)
{
	return ipc_object_alloc_name(space, IOT_PORT_SET,
	           MACH_PORT_TYPE_PORT_SET, 0,
	           name, (ipc_object_t *)psetp, ^(ipc_object_t object){
		ipc_port_set_init(ips_object_to_pset(object), name,
		SYNC_POLICY_INIT_LOCKED);
	});
}


/*
 *	Routine:	ipc_pset_alloc_special
 *	Purpose:
 *		Allocate a port set in a special space.
 *		The new port set is returned with one ref.
 *		If unsuccessful, IPS_NULL is returned.
 *	Conditions:
 *		Nothing locked.
 */
ipc_pset_t
ipc_pset_alloc_special(
	__assert_only ipc_space_t space)
{
	ipc_pset_t pset;

	assert(space != IS_NULL);
	assert(!is_active(space));

	pset = ips_object_to_pset(io_alloc(IOT_PORT_SET, Z_WAITOK | Z_ZERO));
	if (pset == IPS_NULL) {
		return IPS_NULL;
	}

	os_atomic_init(&pset->ips_object.io_bits, io_makebits(IOT_PORT_SET));
	os_atomic_init(&pset->ips_object.io_references, 1);

	ipc_port_set_init(pset, MACH_PORT_SPECIAL_DEFAULT, 0);

	return pset;
}


/*
 *	Routine:	ipc_pset_destroy
 *	Purpose:
 *		Destroys a port_set.
 *	Conditions:
 *		The port_set is locked and alive.
 *		The caller has a reference, which is consumed.
 *		Afterwards, the port_set is unlocked and dead.
 */

void
ipc_pset_destroy(
	ipc_space_t     space,
	ipc_pset_t      pset)
{
	waitq_link_list_t free_l = { };

	assert(ips_active(pset));

	io_bits_andnot(ips_to_object(pset), IO_BITS_ACTIVE);

	/*
	 * Set all waiters on the portset running to
	 * discover the change.
	 *
	 * Then under the same lock hold, deinit the waitq-set,
	 * which will remove all the member message queues,
	 * linkages and clean up preposts.
	 */
	ipc_mqueue_changed(space, &pset->ips_wqset);
	waitq_invalidate(&pset->ips_wqset);
	waitq_set_unlink_all_locked(&pset->ips_wqset, &free_l);

	ips_mq_unlock(pset);

	ips_release(pset);       /* consume the ref our caller gave us */

	waitq_link_free_list(WQT_PORT_SET, &free_l);
}

/*
 *	Routine:	ipc_pset_finalize
 *	Purpose:
 *		Called on last reference deallocate to
 *		free any remaining data associated with the pset.
 *	Conditions:
 *		Nothing locked.
 */
void
ipc_pset_finalize(
	ipc_pset_t              pset)
{
	waitq_deinit(&pset->ips_wqset);
}


#pragma mark - kevent support

/*
 * Kqueue EVFILT_MACHPORT support
 *
 * - kn_ipc_{port,pset} points to the monitored ipc port or pset. If the knote
 *   is using a kqwl, it is eligible to participate in sync IPC overrides.
 *
 *   For the first such sync IPC message in the port, we set up the port's
 *   turnstile to directly push on the kqwl's turnstile (which is in turn set up
 *   during filt_machportattach). If userspace responds to the message, the
 *   turnstile push is severed the point of reply. If userspace returns without
 *   responding to the message, we sever the turnstile push at the
 *   point of reenabling the knote to deliver the next message. This is why the
 *   knote needs to remember the port. For more details, see also
 *   filt_machport_turnstile_complete.
 *
 *   If there are multiple other sync IPC messages in the port, messages 2 to n
 *   redirect their turnstile push to the kqwl through an intermediatry "knote"
 *   turnstile which in turn, pushes on the kqwl turnstile. This knote turnstile
 *   is stored in the kn_hook. See also filt_machport_turnstile_prepare_lazily.
 *
 * - (in/out) ext[0] holds a mach_vm_address_t to a userspace buffer
 *   that can be used to direct-deliver messages when
 *   MACH_RCV_MSG is set in kn_sfflags
 *
 * - (in/out) ext[1] holds a mach_msg_size_t representing the size
 *   of the userspace buffer held in ext[0].
 *
 * - (out)    ext[2] is used to deliver qos information
 *   about the send queue to userspace.
 *
 * - (abused) ext[3] is used in kernel to hold a reference to the first port
 *   with a turnstile that participate to sync IPC override. For more details,
 *   see filt_machport_stash_port
 *
 * - kn_hook is optionally a "knote" turnstile. It is used as the inheritor
 *   of turnstiles for rights copied out as part of direct message delivery
 *   when they can participate to sync IPC override.
 *
 *   It is used to atomically neuter the sync IPC override when the knote is
 *   re-enabled.
 *
 */

#include <sys/event.h>
#include <sys/errno.h>

static int
filt_pset_filter_result(ipc_pset_t pset)
{
	ips_mq_lock_held(pset);

	if (!waitq_is_valid(&pset->ips_wqset)) {
		return 0;
	}

	return waitq_set_first_prepost(&pset->ips_wqset, WQS_PREPOST_PEEK) ?
	       FILTER_ACTIVE : 0;
}

static int
filt_port_filter_result(struct knote *kn, ipc_port_t port)
{
	struct kqueue *kqwl = knote_get_kq(kn);
	ipc_kmsg_t first;
	int result = 0;

	ip_mq_lock_held(port);

	if (kn->kn_sfflags & MACH_RCV_MSG) {
		result = FILTER_RESET_EVENT_QOS;
	}

	if (!waitq_is_valid(&port->ip_waitq)) {
		return result;
	}

	if (port->ip_kernel_iotier_override != kqueue_get_iotier_override(kqwl)) {
		kqueue_set_iotier_override(kqwl, port->ip_kernel_iotier_override);
		result |= FILTER_ADJUST_EVENT_IOTIER_BIT;
	}

	first = ipc_kmsg_queue_first(&port->ip_messages.imq_messages);
	if (!first) {
		return result;
	}

	result = FILTER_ACTIVE;
	if (kn->kn_sfflags & MACH_RCV_MSG) {
		result |= FILTER_ADJUST_EVENT_QOS(first->ikm_qos_override);
	}

#if CONFIG_PREADOPT_TG
	struct thread_group *tg = ipc_kmsg_get_thread_group(first);
	if (tg) {
		struct kqueue *kq = knote_get_kq(kn);
		kqueue_set_preadopted_thread_group(kq, tg,
		    first->ikm_qos_override);
	}
#endif

	return result;
}

struct turnstile *
filt_ipc_kqueue_turnstile(struct knote *kn)
{
	assert(kn->kn_filter == EVFILT_MACHPORT || kn->kn_filter == EVFILT_WORKLOOP);
	return kqueue_turnstile(knote_get_kq(kn));
}

bool
filt_machport_kqueue_has_turnstile(struct knote *kn)
{
	assert(kn->kn_filter == EVFILT_MACHPORT);
	return ((kn->kn_sfflags & MACH_RCV_MSG) || (kn->kn_sfflags & MACH_RCV_SYNC_PEEK))
	       && (kn->kn_flags & EV_DISPATCH);
}

/*
 * Stashes a port that participate to sync IPC override on the knote until the
 * knote is re-enabled.
 *
 * It returns:
 * - the turnstile to use as an inheritor for the stashed port
 * - the kind of stash that happened as PORT_SYNC_* value among:
 *   o not stashed (no sync IPC support)
 *   o stashed in the knote (in kn_ext[3])
 *   o to be hooked to the kn_hook knote
 */
struct turnstile *
filt_machport_stash_port(struct knote *kn, ipc_port_t port, int *link)
{
	struct turnstile *ts = TURNSTILE_NULL;

	if (kn->kn_filter == EVFILT_WORKLOOP) {
		assert(kn->kn_ipc_port == NULL);
		kn->kn_ipc_port = port;
		ip_reference(port);
		if (link) {
			*link = PORT_SYNC_LINK_WORKLOOP_KNOTE;
		}
		ts = filt_ipc_kqueue_turnstile(kn);
	} else if (!filt_machport_kqueue_has_turnstile(kn)) {
		if (link) {
			*link = PORT_SYNC_LINK_NO_LINKAGE;
		}
	} else if (kn->kn_ext[3] == 0) {
		ip_reference(port);
		kn->kn_ext[3] = (uintptr_t)port;
		ts = filt_ipc_kqueue_turnstile(kn);
		if (link) {
			*link = PORT_SYNC_LINK_WORKLOOP_KNOTE;
		}
	} else {
		ts = (struct turnstile *)knote_kn_hook_get_raw(kn);
		if (link) {
			*link = PORT_SYNC_LINK_WORKLOOP_STASH;
		}
	}

	return ts;
}

/*
 * Lazily prepare a turnstile so that filt_machport_stash_port()
 * can be called with the mqueue lock held.
 *
 * It will allocate a turnstile in kn_hook if:
 * - the knote supports sync IPC override,
 * - we already stashed a port in kn_ext[3],
 * - the object that will be copied out has a chance to ask to be stashed.
 *
 * It is setup so that its inheritor is the workloop turnstile that has been
 * allocated when this knote was attached.
 */
void
filt_machport_turnstile_prepare_lazily(
	struct knote *kn,
	mach_msg_type_name_t msgt_name,
	ipc_port_t port)
{
	/* This is called from within filt_machportprocess */
	assert((kn->kn_status & KN_SUPPRESSED) && (kn->kn_status & KN_LOCKED));

	if (!filt_machport_kqueue_has_turnstile(kn)) {
		return;
	}

	if (kn->kn_ext[3] == 0 || knote_kn_hook_get_raw(kn)) {
		return;
	}

	struct turnstile *ts = filt_ipc_kqueue_turnstile(kn);
	if ((msgt_name == MACH_MSG_TYPE_PORT_SEND_ONCE && port->ip_specialreply) ||
	    (msgt_name == MACH_MSG_TYPE_PORT_RECEIVE)) {
		struct turnstile *kn_ts = turnstile_alloc();
		struct turnstile *ts_store;
		kn_ts = turnstile_prepare((uintptr_t)kn, &ts_store, kn_ts, TURNSTILE_KNOTE);
		knote_kn_hook_set_raw(kn, ts_store);

		turnstile_update_inheritor(kn_ts, ts,
		    TURNSTILE_IMMEDIATE_UPDATE | TURNSTILE_INHERITOR_TURNSTILE);
		turnstile_cleanup();
	}
}

static void
filt_machport_turnstile_complete_port(struct knote *kn, ipc_port_t port)
{
	struct turnstile *ts = TURNSTILE_NULL;

	ip_mq_lock(port);
	if (port->ip_specialreply) {
		/*
		 * If the reply has been sent to the special reply port already,
		 * then the special reply port may already be reused to do something
		 * entirely different.
		 *
		 * However, the only reason for it to still point to this knote is
		 * that it's still waiting for a reply, so when this is the case,
		 * neuter the linkage.
		 */
		if (port->ip_sync_link_state == PORT_SYNC_LINK_WORKLOOP_KNOTE &&
		    port->ip_sync_inheritor_knote == kn) {
			ipc_port_adjust_special_reply_port_locked(port, NULL,
			    (IPC_PORT_ADJUST_SR_NONE | IPC_PORT_ADJUST_SR_ENABLE_EVENT), FALSE);
			/* port unlocked */
		} else {
			ip_mq_unlock(port);
		}
	} else {
		/*
		 * For receive rights, if their IMQ_KNOTE() is still this
		 * knote, then sever the link.
		 */
		if (port->ip_sync_link_state == PORT_SYNC_LINK_WORKLOOP_KNOTE &&
		    port->ip_messages.imq_inheritor_knote == kn) {
			ipc_port_adjust_sync_link_state_locked(port, PORT_SYNC_LINK_ANY, NULL);
			ts = port_send_turnstile(port);
		}
		if (ts) {
			turnstile_reference(ts);
			turnstile_update_inheritor(ts, TURNSTILE_INHERITOR_NULL,
			    TURNSTILE_IMMEDIATE_UPDATE);
		}
		ip_mq_unlock(port);

		if (ts) {
			turnstile_update_inheritor_complete(ts,
			    TURNSTILE_INTERLOCK_NOT_HELD);
			turnstile_deallocate(ts);
		}
	}

	ip_release(port);
}

void
filt_wldetach_sync_ipc(struct knote *kn)
{
	ipc_port_t port = kn->kn_ipc_port;
	filt_machport_turnstile_complete_port(kn, port);
	kn->kn_ipc_port = IP_NULL;
}

/*
 * Other half of filt_machport_turnstile_prepare_lazily()
 *
 * This is serialized by the knote state machine.
 */
static void
filt_machport_turnstile_complete(struct knote *kn)
{
	if (kn->kn_ext[3]) {
		ipc_port_t port = (ipc_port_t)kn->kn_ext[3];
		filt_machport_turnstile_complete_port(kn, port);
		kn->kn_ext[3] = 0;
	}

	struct turnstile *ts = knote_kn_hook_get_raw(kn);
	if (ts) {
		turnstile_update_inheritor(ts, TURNSTILE_INHERITOR_NULL,
		    TURNSTILE_IMMEDIATE_UPDATE);
		turnstile_update_inheritor_complete(ts, TURNSTILE_INTERLOCK_HELD);

		struct turnstile *ts_store = ts;
		turnstile_complete((uintptr_t)kn, (struct turnstile **)&ts_store, &ts, TURNSTILE_KNOTE);
		knote_kn_hook_set_raw(kn, ts_store);

		turnstile_cleanup();

		assert(ts);
		turnstile_deallocate(ts);
	}
}

static void
filt_machport_link(struct klist *klist, struct knote *kn)
{
	struct knote *hd = SLIST_FIRST(klist);

	if (hd && filt_machport_kqueue_has_turnstile(kn)) {
		SLIST_INSERT_AFTER(hd, kn, kn_selnext);
	} else {
		SLIST_INSERT_HEAD(klist, kn, kn_selnext);
	}
}

static void
filt_machport_unlink(struct klist *klist, struct knote *kn)
{
	struct knote **knprev;

	KNOTE_DETACH(klist, kn);

	/* make sure the first knote is a knote we can push on */
	SLIST_FOREACH_PREVPTR(kn, knprev, klist, kn_selnext) {
		if (filt_machport_kqueue_has_turnstile(kn)) {
			*knprev = SLIST_NEXT(kn, kn_selnext);
			SLIST_INSERT_HEAD(klist, kn, kn_selnext);
			break;
		}
	}
}

int
filt_wlattach_sync_ipc(struct knote *kn)
{
	mach_port_name_t name = (mach_port_name_t)kn->kn_id;
	ipc_space_t space = current_space();
	ipc_entry_bits_t bits;
	ipc_object_t object;
	ipc_port_t port = IP_NULL;
	int error = 0;

	if (ipc_right_lookup_read(space, name, &bits, &object) != KERN_SUCCESS) {
		return ENOENT;
	}
	/* object is locked and active */

	if (bits & MACH_PORT_TYPE_RECEIVE) {
		port = ip_object_to_port(object);
		if (port->ip_specialreply) {
			error = ENOENT;
		}
	} else if (bits & MACH_PORT_TYPE_SEND_ONCE) {
		port = ip_object_to_port(object);
		if (!port->ip_specialreply) {
			error = ENOENT;
		}
	} else {
		error = ENOENT;
	}
	if (error) {
		io_unlock(object);
		return error;
	}

	if (port->ip_sync_link_state == PORT_SYNC_LINK_ANY) {
		io_unlock(object);
		/*
		 * We cannot start a sync IPC inheritance chain, only further one
		 * Note: this can also happen if the inheritance chain broke
		 * because the original requestor died.
		 */
		return ENOENT;
	}

	if (port->ip_specialreply) {
		ipc_port_adjust_special_reply_port_locked(port, kn,
		    IPC_PORT_ADJUST_SR_LINK_WORKLOOP, FALSE);
	} else {
		ipc_port_adjust_port_locked(port, kn, FALSE);
	}

	/* make sure the port was stashed */
	assert(kn->kn_ipc_port == port);

	/* port has been unlocked by ipc_port_adjust_* */

	return 0;
}

static int
filt_psetattach(struct knote *kn, ipc_pset_t pset)
{
	int result = 0;

	ips_reference(pset);
	kn->kn_ipc_pset = pset;

	filt_machport_link(&pset->ips_klist, kn);
	result = filt_pset_filter_result(pset);
	ips_mq_unlock(pset);

	return result;
}

static int
filt_portattach(struct knote *kn, ipc_port_t port)
{
	struct turnstile *send_turnstile = TURNSTILE_NULL;
	int result = 0;

	if (port->ip_specialreply) {
		/*
		 * Registering for kevents on special reply ports
		 * isn't supported for two reasons:
		 *
		 * 1. it really makes very little sense for a port that
		 *    is supposed to be used synchronously
		 *
		 * 2. their ports's ip_klist field will be used to
		 *    store the receive turnstile, so we can't possibly
		 *    attach them anyway.
		 */
		ip_mq_unlock(port);
		knote_set_error(kn, ENOTSUP);
		return 0;
	}

	ip_reference(port);
	kn->kn_ipc_port = port;
	if (port->ip_sync_link_state != PORT_SYNC_LINK_ANY) {
		/*
		 * We're attaching a port that used to have an IMQ_KNOTE,
		 * clobber this state, we'll fixup its turnstile inheritor below.
		 */
		ipc_port_adjust_sync_link_state_locked(port, PORT_SYNC_LINK_ANY, NULL);
	}

	filt_machport_link(&port->ip_klist, kn);
	result = filt_port_filter_result(kn, port);

	/*
	 * Update the port's turnstile inheritor
	 *
	 * Unlike filt_machportdetach(), we don't have to care about races for
	 * turnstile_workloop_pusher_info(): filt_machport_link() doesn't affect
	 * already pushing knotes, and if the current one becomes the new
	 * pusher, it'll only be visible when turnstile_workloop_pusher_info()
	 * returns.
	 */
	send_turnstile = port_send_turnstile(port);
	if (send_turnstile) {
		turnstile_reference(send_turnstile);
		ipc_port_send_update_inheritor(port, send_turnstile,
		    TURNSTILE_IMMEDIATE_UPDATE);

		/*
		 * rdar://problem/48861190
		 *
		 * When a listener connection resumes a peer,
		 * updating the inheritor above has moved the push
		 * from the current thread to the workloop.
		 *
		 * However, we haven't told the workloop yet
		 * that it needs a thread request, and we risk
		 * to be preeempted as soon as we drop the space
		 * lock below.
		 *
		 * To avoid this disable preemption and let kevent
		 * reenable it after it takes the kqlock.
		 */
		disable_preemption();
		result |= FILTER_THREADREQ_NODEFEER;
	}

	ip_mq_unlock(port);

	if (send_turnstile) {
		turnstile_update_inheritor_complete(send_turnstile,
		    TURNSTILE_INTERLOCK_NOT_HELD);
		turnstile_deallocate_safe(send_turnstile);
	}

	return result;
}

static int
filt_machportattach(struct knote *kn, __unused struct kevent_qos_s *kev)
{
	mach_port_name_t name = (mach_port_name_t)kn->kn_id;
	ipc_space_t space = current_space();
	ipc_entry_bits_t bits;
	ipc_object_t object;
	kern_return_t kr;

	kn->kn_flags &= ~EV_EOF;
	kn->kn_ext[3] = 0;

	if (filt_machport_kqueue_has_turnstile(kn)) {
		/*
		 * If the filter is likely to support sync IPC override,
		 * and it happens to be attaching to a workloop,
		 * make sure the workloop has an allocated turnstile.
		 */
		kqueue_alloc_turnstile(knote_get_kq(kn));
	}

	kr = ipc_right_lookup_read(space, name, &bits, &object);

	if (kr != KERN_SUCCESS) {
		knote_set_error(kn, ENOENT);
		return 0;
	}
	/* object is locked and active */

	if (bits & MACH_PORT_TYPE_PORT_SET) {
		kn->kn_filtid = EVFILTID_MACH_PORT_SET;
		return filt_psetattach(kn, ips_object_to_pset(object));
	}

	if (bits & MACH_PORT_TYPE_RECEIVE) {
		kn->kn_filtid = EVFILTID_MACH_PORT;
		return filt_portattach(kn, ip_object_to_port(object));
	}

	io_unlock(object);
	knote_set_error(kn, ENOTSUP);
	return 0;
}

static void
filt_psetdetach(struct knote *kn)
{
	ipc_pset_t pset = kn->kn_ipc_pset;

	filt_machport_turnstile_complete(kn);

	ips_mq_lock(pset);

	if ((kn->kn_status & KN_VANISHED) || (kn->kn_flags & EV_EOF)) {
		/*
		 * ipc_mqueue_changed() already unhooked this knote from the waitq,
		 */
	} else {
		filt_machport_unlink(&pset->ips_klist, kn);
	}

	kn->kn_ipc_pset = IPS_NULL;
	ips_mq_unlock(pset);
	ips_release(pset);
}

static void
filt_portdetach(struct knote *kn)
{
	ipc_port_t port = kn->kn_ipc_port;
	struct turnstile *send_turnstile = TURNSTILE_NULL;

	filt_machport_turnstile_complete(kn);

	ip_mq_lock(port);
	if ((kn->kn_status & KN_VANISHED) || (kn->kn_flags & EV_EOF)) {
		/*
		 * ipc_mqueue_changed() already unhooked this knote from the waitq,
		 */
	} else {
		/*
		 * When the knote being detached is the first one in the list,
		 * then unlinking the knote *and* updating the turnstile inheritor
		 * need to happen atomically with respect to the callers of
		 * turnstile_workloop_pusher_info().
		 *
		 * The caller of turnstile_workloop_pusher_info() will use the kq req
		 * lock (and hence the kqlock), so we just need to hold the kqlock too.
		 */
		assert(port->ip_sync_link_state == PORT_SYNC_LINK_ANY);
		if (kn == SLIST_FIRST(&port->ip_klist)) {
			send_turnstile = port_send_turnstile(port);
		}
		filt_machport_unlink(&port->ip_klist, kn);
		struct kqueue *kq = knote_get_kq(kn);
		kqueue_set_iotier_override(kq, THROTTLE_LEVEL_END);
	}

	if (send_turnstile) {
		turnstile_reference(send_turnstile);
		ipc_port_send_update_inheritor(port, send_turnstile,
		    TURNSTILE_IMMEDIATE_UPDATE);
	}

	/* Clear the knote pointer once the knote has been removed from turnstile */
	kn->kn_ipc_port = IP_NULL;
	ip_mq_unlock(port);

	if (send_turnstile) {
		turnstile_update_inheritor_complete(send_turnstile,
		    TURNSTILE_INTERLOCK_NOT_HELD);
		turnstile_deallocate(send_turnstile);
	}

	ip_release(port);
}

/*
 * filt_{pset,port}event - deliver events into the mach port filter
 *
 * Mach port message arrival events are currently only posted via the
 * kqueue filter routine for ports.
 *
 * If there is a message at the head of the queue,
 * we indicate that the knote should go active.  If
 * the message is to be direct-received, we adjust the
 * QoS of the knote according the requested and override
 * QoS of that first message.
 *
 * When the knote is for a port-set, the hint is non 0
 * and is the waitq which is posting.
 */
static int
filt_psetevent(struct knote *kn __unused, long hint __assert_only)
{
	/*
	 * When called for a port-set,
	 * the posting port waitq is locked.
	 *
	 * waitq_set_first_prepost()
	 * in filt_machport_filter_result()
	 * would try to lock it and be very sad.
	 *
	 * Just trust what we know to be true.
	 */
	assert(hint != 0);
	return FILTER_ACTIVE;
}

static int
filt_portevent(struct knote *kn, long hint __assert_only)
{
	assert(hint == 0);
	return filt_port_filter_result(kn, kn->kn_ipc_port);
}

void
ipc_pset_prepost(struct waitq_set *wqs, struct waitq *waitq)
{
	KNOTE(&ips_from_waitq(wqs)->ips_klist, (long)waitq);
}

static void
filt_machporttouch(struct knote *kn, struct kevent_qos_s *kev)
{
	/*
	 * Specificying MACH_RCV_MSG or MACH_RCV_SYNC_PEEK during attach results in
	 * allocation of a turnstile. Modifying the filter flags to include these
	 * flags later, without a turnstile being allocated, leads to
	 * inconsistencies.
	 */
	if ((kn->kn_sfflags ^ kev->fflags) & (MACH_RCV_MSG | MACH_RCV_SYNC_PEEK)) {
		kev->flags |= EV_ERROR;
		kev->data = EINVAL;
		return;
	}

	/* copy in new settings and save off new input fflags */
	kn->kn_sfflags = kev->fflags;
	kn->kn_ext[0] = kev->ext[0];
	kn->kn_ext[1] = kev->ext[1];

	if (kev->flags & EV_ENABLE) {
		/*
		 * If the knote is being enabled, make sure there's no lingering
		 * IPC overrides from the previous message delivery.
		 */
		filt_machport_turnstile_complete(kn);
	}
}

static int
filt_psettouch(struct knote *kn, struct kevent_qos_s *kev)
{
	ipc_pset_t pset = kn->kn_ipc_pset;
	int result = 0;

	filt_machporttouch(kn, kev);
	if (kev->flags & EV_ERROR) {
		return 0;
	}

	ips_mq_lock(pset);
	result = filt_pset_filter_result(pset);
	ips_mq_unlock(pset);

	return result;
}

static int
filt_porttouch(struct knote *kn, struct kevent_qos_s *kev)
{
	ipc_port_t port = kn->kn_ipc_port;
	int result = 0;

	filt_machporttouch(kn, kev);
	if (kev->flags & EV_ERROR) {
		return 0;
	}

	ip_mq_lock(port);
	result = filt_port_filter_result(kn, port);
	ip_mq_unlock(port);

	return result;
}

static int
filt_machportprocess(
	struct knote           *kn,
	struct kevent_qos_s    *kev,
	ipc_object_t            object,
	ipc_object_type_t       otype)
{
	thread_t self = current_thread();
	kevent_ctx_t kectx = NULL;

	wait_result_t wresult;
	mach_msg_option64_t option64;
	mach_vm_address_t msg_addr;
	mach_msg_size_t max_msg_size, cpout_aux_size, cpout_msg_size;
	uint32_t ppri;
	mach_msg_qos_t oqos;

	int result = FILTER_ACTIVE;

	/* Capture current state */
	knote_fill_kevent(kn, kev, MACH_PORT_NULL);

	/* Clear port reference, use ext3 as size of msg aux data */
	kev->ext[3] = 0;

	/* If already deallocated/moved return one last EOF event */
	if (kev->flags & EV_EOF) {
		return FILTER_ACTIVE | FILTER_RESET_EVENT_QOS;
	}

	/*
	 * Only honor supported receive options. If no options are
	 * provided, just force a MACH_RCV_LARGE to detect the
	 * name of the port and sizeof the waiting message.
	 *
	 * Extend kn_sfflags to 64 bits.
	 */
	option64 = (mach_msg_option64_t)kn->kn_sfflags & (MACH_RCV_MSG |
	    MACH_RCV_LARGE | MACH_RCV_LARGE_IDENTITY |
	    MACH_RCV_TRAILER_MASK | MACH_RCV_VOUCHER | MACH_MSG_STRICT_REPLY);

	if (option64 & MACH_RCV_MSG) {
		msg_addr = (mach_vm_address_t) kn->kn_ext[0];
		max_msg_size = (mach_msg_size_t) kn->kn_ext[1];

		/*
		 * Copy out the incoming message as vector, and append aux data
		 * immediately after the message proper (if any) and report its
		 * size on ext3.
		 */
		option64 |= (MACH64_MSG_VECTOR | MACH64_RCV_LINEAR_VECTOR);

		/*
		 * If the kevent didn't specify a buffer and length, carve a buffer
		 * from the filter processing data according to the flags.
		 */
		if (max_msg_size == 0) {
			kectx = kevent_get_context(self);
			msg_addr  = (mach_vm_address_t)kectx->kec_data_out;
			max_msg_size  = (mach_msg_size_t)kectx->kec_data_resid;
			option64 |= (MACH_RCV_LARGE | MACH_RCV_LARGE_IDENTITY);
			/* Receive vector linearly onto stack */
			if (kectx->kec_process_flags & KEVENT_FLAG_STACK_DATA) {
				option64 |= MACH64_RCV_STACK;
			}
		}
	} else {
		/* just detect the port name (if a set) and size of the first message */
		option64 = MACH_RCV_LARGE;
		msg_addr = 0;
		max_msg_size = 0;
	}

	/*
	 * Set up to receive a message or the notification of a
	 * too large message.  But never allow this call to wait.
	 * If the user provided aditional options, like trailer
	 * options, pass those through here.  But we don't support
	 * scatter lists through this interface.
	 *
	 * Note: while in filt_machportprocess(),
	 *       the knote has a reference on `object` that we can borrow.
	 */
	self->ith_object = object;

	/* Using msg_addr as combined buffer for message proper and aux */
	self->ith_msg_addr = msg_addr;
	self->ith_max_msize = max_msg_size;
	self->ith_msize = 0;

	self->ith_aux_addr = 0;
	self->ith_max_asize = 0;
	self->ith_asize = 0;

	self->ith_option = option64;
	self->ith_receiver_name = MACH_PORT_NULL;
	option64 |= MACH_RCV_TIMEOUT; // never wait
	self->ith_state = MACH_RCV_IN_PROGRESS;
	self->ith_knote = kn;

	ipc_object_lock(object, otype);

	wresult = ipc_mqueue_receive_on_thread_and_unlock(
		io_waitq(object),
		option64,
		self->ith_max_msize,       /* max msg suze */
		0,                         /* max aux size 0, using combined buffer */
		0,                         /* immediate timeout */
		THREAD_INTERRUPTIBLE,
		self);
	/* port unlocked */

	/* If we timed out, or the process is exiting, just zero.  */
	if (wresult == THREAD_RESTART || self->ith_state == MACH_RCV_TIMED_OUT) {
		assert(self->turnstile != TURNSTILE_NULL);
		self->ith_knote = ITH_KNOTE_NULL;
		return 0;
	}

	assert(wresult == THREAD_NOT_WAITING);
	assert(self->ith_state != MACH_RCV_IN_PROGRESS);

	/*
	 * If we weren't attempting to receive a message
	 * directly, we need to return the port name in
	 * the kevent structure.
	 */
	if ((option64 & MACH_RCV_MSG) != MACH_RCV_MSG) {
		assert(self->ith_state == MACH_RCV_TOO_LARGE);
		assert(self->ith_kmsg == IKM_NULL);
		kev->data = self->ith_receiver_name;
		self->ith_knote = ITH_KNOTE_NULL;
		return result;
	}

#if CONFIG_PREADOPT_TG
	/* If we're the first EVFILT_MACHPORT knote that is being processed for this
	 * kqwl, then make sure to preadopt the thread group from the kmsg we're
	 * about to receive. This is to make sure that we fix up the preadoption
	 * thread group correctly on the receive side for the first message.
	 */
	struct kqueue *kq = knote_get_kq(kn);

	if (self->ith_kmsg) {
		struct thread_group *tg = ipc_kmsg_get_thread_group(self->ith_kmsg);

		kqueue_process_preadopt_thread_group(self, kq, tg);
	}
#endif
	if (otype == IOT_PORT) {
		ipc_port_t port = ip_object_to_port(object);
		struct kqueue *kqwl = knote_get_kq(kn);
		if (port->ip_kernel_iotier_override != kqueue_get_iotier_override(kqwl)) {
			/*
			 * Lock the port to make sure port->ip_kernel_iotier_override does
			 * not change while updating the kqueue override, else kqueue could
			 * have old iotier value.
			 */
			ip_mq_lock(port);
			kqueue_set_iotier_override(kqwl, port->ip_kernel_iotier_override);
			ip_mq_unlock(port);
			result |= FILTER_ADJUST_EVENT_IOTIER_BIT;
		}
	}

	/*
	 * Attempt to receive the message directly, returning
	 * the results in the fflags field.
	 */
	io_reference(object);
	kev->fflags = mach_msg_receive_results_kevent(&cpout_msg_size,
	    &cpout_aux_size, &ppri, &oqos);

	/* kmsg and object reference consumed */

	/*
	 * if the user asked for the identity of ports containing a
	 * a too-large message, return it in the data field (as we
	 * do for messages we didn't try to receive).
	 */
	if (kev->fflags == MACH_RCV_TOO_LARGE) {
		kev->ext[1] = self->ith_msize;
		kev->ext[3] = self->ith_asize;  /* Only lower 32 bits of ext3 are used */
		if (option64 & MACH_RCV_LARGE_IDENTITY) {
			kev->data = self->ith_receiver_name;
		} else {
			kev->data = MACH_PORT_NULL;
		}
	} else {
		kev->ext[1] = cpout_msg_size;
		kev->ext[3] = cpout_aux_size; /* Only lower 32 bits of ext3 are used */
		kev->data = MACH_PORT_NULL;
	}

	/*
	 * If we used a data buffer carved out from the filt_process data,
	 * store the address used in the knote and adjust the residual and
	 * other parameters for future use.
	 */
	if (kectx) {
		assert(kectx->kec_data_resid >= cpout_msg_size + cpout_aux_size);
		kectx->kec_data_resid -= cpout_msg_size + cpout_aux_size;
		if ((kectx->kec_process_flags & KEVENT_FLAG_STACK_DATA) == 0) {
			kev->ext[0] = kectx->kec_data_out;
			kectx->kec_data_out += cpout_msg_size + cpout_aux_size;
		} else {
			assert(option64 & MACH64_RCV_STACK);
			kev->ext[0] = kectx->kec_data_out + kectx->kec_data_resid;
		}
	}

	/*
	 * Apply message-based QoS values to output kevent as prescribed.
	 * The kev->ext[2] field gets (msg-qos << 32) | (override-qos).
	 */
	if (kev->fflags == MACH_MSG_SUCCESS) {
		kev->ext[2] = ((uint64_t)ppri << 32) |
		    _pthread_priority_make_from_thread_qos(oqos, 0, 0);
	}

	self->ith_knote = ITH_KNOTE_NULL;
	return result;
}

static int
filt_psetprocess(struct knote *kn, struct kevent_qos_s *kev)
{
	ipc_object_t io = ips_to_object(kn->kn_ipc_pset);

	return filt_machportprocess(kn, kev, io, IOT_PORT_SET);
}

static int
filt_portprocess(struct knote *kn, struct kevent_qos_s *kev)
{
	ipc_object_t io = ip_to_object(kn->kn_ipc_port);

	return filt_machportprocess(kn, kev, io, IOT_PORT);
}

static void
filt_machportsanitizedcopyout(struct knote *kn, struct kevent_qos_s *kev)
{
	*kev = *(struct kevent_qos_s *)&kn->kn_kevent;

	// We may have stashed the address to the port that is pushing on the sync
	// IPC so clear it out.
	kev->ext[3] = 0;
}

const struct filterops machport_attach_filtops = {
	.f_adjusts_qos = true,
	.f_extended_codes = true,
	.f_attach = filt_machportattach,
	.f_sanitized_copyout = filt_machportsanitizedcopyout,
};

const struct filterops mach_port_filtops = {
	.f_adjusts_qos = true,
	.f_extended_codes = true,
	.f_detach = filt_portdetach,
	.f_event = filt_portevent,
	.f_touch = filt_porttouch,
	.f_process = filt_portprocess,
	.f_sanitized_copyout = filt_machportsanitizedcopyout,
};

const struct filterops mach_port_set_filtops = {
	.f_adjusts_qos = true,
	.f_extended_codes = true,
	.f_detach = filt_psetdetach,
	.f_event = filt_psetevent,
	.f_touch = filt_psettouch,
	.f_process = filt_psetprocess,
	.f_sanitized_copyout = filt_machportsanitizedcopyout,
};
