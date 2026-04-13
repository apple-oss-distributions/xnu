/*
 * Copyright (c) 2000-2016 Apple Computer, Inc. All rights reserved.
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
 */
/*
 */
/*
 *	File:	ipc/ipc_port.h
 *	Author:	Rich Draves
 *	Date:	1989
 *
 *	Definitions for ports.
 */

#ifndef _IPC_IPC_PORT_H_
#define _IPC_IPC_PORT_H_

#include <mach/mach_types.h>
#include <mach/boolean.h>
#include <mach/kern_return.h>
#include <mach/port.h>

#ifdef MACH_KERNEL_PRIVATE
#include <mach_assert.h>

#include <kern/assert.h>
#include <kern/kern_types.h>
#include <kern/turnstile.h>

#include <ipc/ipc_types.h>
#include <ipc/ipc_object.h>
#include <ipc/ipc_mqueue.h>

#include <ptrauth.h>
#endif /* MACH_KERNEL_PRIVATE */

__BEGIN_DECLS __ASSUME_PTR_ABI_SINGLE_BEGIN
#if MACH_KERNEL_PRIVATE
__exported_push_hidden

struct task_watchport_elem;

typedef unsigned long ipc_port_timestamp_t;

struct ipc_port_request {
	union {
		struct ipc_port                *ipr_soright;
		struct host_notify_entry *XNU_PTRAUTH_SIGNED_PTR("ipc_port_request.ipr_hnotify") ipr_hnotify;
		struct ipc_port_request *XNU_PTRAUTH_SIGNED_PTR("ipc_port_request.ipr_hn_slot") ipr_hn_slot;
	};

	union {
#define IPR_HOST_NOTIFY                         0xfffffffeu
		mach_port_name_t                ipr_name;
		ipc_port_request_index_t        ipr_next;
	};
};
xnu_static_assert_struct_size(struct ipc_port_request, 16);

KALLOC_ARRAY_TYPE_DECL(ipc_port_request_table, struct ipc_port_request);

struct ipc_port {
	struct ipc_object               ip_object;
	union {
		/*
		 * The waitq_eventmask field is only used on the global queues.
		 * We hence repurpose all those bits for our own use.
		 *
		 * Note: if too many bits are added, compilation will fail
		 *       with errors about "negative bitfield sizes"
		 */
		WAITQ_FLAGS(ip_waitq
		    , ip_fullwaiters:1            /* Whether there are senders blocked on a full queue */
		    , ip_sprequests:1             /* send-possible requests outstanding */
		    , ip_spimportant:1            /* ... at least one is importance donating */
		    , ip_impdonation:1            /* port supports importance donation */
		    , ip_tempowner:1              /* dont give donations to current receiver */
		    , ip_guarded:1                /* port guarded (use context value as guard) */
		    , ip_strict_guard:1           /* Strict guarding; Prevents user manipulation of context values directly */
		    , ip_sync_link_state:3        /* link the port to destination port/ Workloop */
		    , ip_sync_bootstrap_checkin:1 /* port part of sync bootstrap checkin, push on thread doing the checkin */
		    , ip_tg_block_tracking:1      /* Track blocking relationship between thread groups during sync IPC */
		    , ip_has_watchport:1          /* port has an exec watchport */
		    , ip_kernel_iotier_override:2 /* kernel iotier override */
		    , ip_kernel_qos_override:3    /* kernel qos override */
		    /* development bits only */
		    , ip_srp_lost_link:1           /* special reply port turnstile link chain broken */
		    , ip_srp_msg_sent:1            /* special reply port msg sent */
		    , ip_enforce_reply_semantics:1 /* enforce reply port semantics */
		    , __ip_unused:6                /* reserve of bits */
		    );
		struct waitq            ip_waitq;
	};

	struct ipc_mqueue               ip_messages;

	/*
	 * IMPORTANT: Direct access of unionized fields are highly discouraged.
	 * Use accessor functions below and see header doc for possible states.
	 */
	union {
		struct ipc_space       *XNU_PTRAUTH_SIGNED_PTR("ipc_port.ip_receiver") ip_receiver;
		struct ipc_port        *XNU_PTRAUTH_SIGNED_PTR_AUTH_NULL("ipc_port.ip_destination") ip_destination;
		ipc_port_timestamp_t    ip_timestamp;
	};

	union {
		uintptr_t               ip_kobject; /* manually PAC-ed, see ipc_kobject_get_raw() */
		struct ipc_port        *XNU_PTRAUTH_SIGNED_PTR("ipc_port.ip_nsrequest") ip_nsrequest;
	};

	union {
		ipc_importance_task_t   XNU_PTRAUTH_SIGNED_PTR("ipc_port.ip_imp_task") ip_imp_task; /* use accessor ip_get_imp_task() */
		/* following three are ip_is_special_reply_port disambiguated by ip_sync_link_state */
		struct ipc_port        *XNU_PTRAUTH_SIGNED_PTR("ipc_port.ip_sync_inheritor_port")ip_sync_inheritor_port;
		struct knote           *XNU_PTRAUTH_SIGNED_PTR("ipc_port.ip_sync_inheritor_knote")ip_sync_inheritor_knote;
		struct turnstile       *XNU_PTRAUTH_SIGNED_PTR("ipc_port.ip_sync_inheritor_ts")ip_sync_inheritor_ts;
	};

	/*
	 * IOT_SPECIAL_REPLY:   ip_pid
	 * ip_has_watchport:    ip_twe
	 * else:                ip_pdrequest
	 */
	union {
		int                     ip_pid;
		struct task_watchport_elem *XNU_PTRAUTH_SIGNED_PTR_AUTH_NULL("ipc_port.ip_twe") ip_twe;
		struct ipc_port *XNU_PTRAUTH_SIGNED_PTR_AUTH_NULL("ipc_port.ip_pdrequest") ip_pdrequest;
	};

	ipc_port_request_table_t XNU_PTRAUTH_SIGNED_PTR("ipc_port.ip_request") ip_requests;
	struct turnstile               *ip_send_turnstile;
	mach_vm_address_t               ip_context;

	natural_t                       ip_impcount;    /* number of importance donations in nested queue */
	mach_port_mscount_t             ip_mscount;
	mach_port_rights_t              ip_srights;
	mach_port_rights_t              ip_sorights;

#if MACH_ASSERT
	unsigned long                   ip_timetrack;   /* give an idea of "when" created */
	uint32_t                        ip_made_bt;     /* stack trace (btref_t) */
	uint32_t                        ip_made_pid;    /* for debugging */
#endif  /* MACH_ASSERT */
};
#if DEVELOPMENT || DEBUG
xnu_static_assert_struct_size(struct ipc_port, 160);
#else /* DEVELOPMENT || DEBUG */
xnu_static_assert_struct_size(struct ipc_port, 144);
#endif /* DEVELOPMENT || DEBUG */


static inline bool
ip_in_pset(ipc_port_t port)
{
	return !circle_queue_empty(&port->ip_waitq.waitq_links);
}

#define ip_receiver_name        ip_messages.imq_receiver_name
#define ip_reply_context        ip_messages.imq_context
#define ip_klist                ip_messages.imq_klist

#define port_send_turnstile(port) \
	((port)->ip_send_turnstile)

#define set_port_send_turnstile(port, value) \
MACRO_BEGIN                                  \
	(port)->ip_send_turnstile = (value); \
MACRO_END

#define port_send_turnstile_address(port)    \
	(&((port)->ip_send_turnstile))

#define port_rcv_turnstile_address(port)   (&(port)->ip_waitq.waitq_ts)

extern void __ipc_right_delta_overflow_panic(
	ipc_port_t          port,
	natural_t          *field,
	int                 delta) __abortlike;

#define ip_right_delta(port, field, delta)  ({ \
    ipc_port_t __port = (port);                                  \
    if (os_add_overflow(__port->field, delta, &__port->field)) { \
	__ipc_right_delta_overflow_panic(__port, &__port->field, delta);  \
    }                                                            \
    __port->field;                                               \
})

#define ip_srights_inc(port)  ip_right_delta(port, ip_srights, 1)
#define ip_srights_dec(port)  ip_right_delta(port, ip_srights, -1)
#define ip_sorights_inc(port) ip_right_delta(port, ip_sorights, 1)
#define ip_sorights_dec(port) ip_right_delta(port, ip_sorights, -1)

/*
 * SYNC IPC state flags for special reply port/ rcv right.
 *
 * PORT_SYNC_LINK_ANY
 *    Special reply port is not linked to any other port
 *    or WL and linkage should be allowed.
 *
 * PORT_SYNC_LINK_PORT
 *    Special reply port is linked to the port and
 *    ip_sync_inheritor_port contains the inheritor
 *    port.
 *
 * PORT_SYNC_LINK_WORKLOOP_KNOTE
 *    Special reply port is linked to a WL (via a knote).
 *    ip_sync_inheritor_knote contains a pointer to the knote
 *    the port is stashed on.
 *
 * PORT_SYNC_LINK_WORKLOOP_STASH
 *    Special reply port is linked to a WL (via a knote stash).
 *    ip_sync_inheritor_ts contains a pointer to the turnstile with a +1
 *    the port is stashed on.
 *
 * PORT_SYNC_LINK_NO_LINKAGE
 *    Message sent to special reply port, do
 *    not allow any linkages till receive is
 *    complete.
 *
 * PORT_SYNC_LINK_RCV_THREAD
 *    Receive right copied out as a part of bootstrap check in,
 *    push on the thread which copied out the port.
 */
#define PORT_SYNC_LINK_ANY              (0)
#define PORT_SYNC_LINK_PORT             (0x1)
#define PORT_SYNC_LINK_WORKLOOP_KNOTE   (0x2)
#define PORT_SYNC_LINK_WORKLOOP_STASH   (0x3)
#define PORT_SYNC_LINK_NO_LINKAGE       (0x4)
#define PORT_SYNC_LINK_RCV_THREAD       (0x5)

#define IP_NULL                         IPC_PORT_NULL
#define IP_DEAD                         IPC_PORT_DEAD
#define IP_VALID(port)                  IPC_PORT_VALID(port)

#define ip_object_to_port(io)           __container_of(io, struct ipc_port, ip_object)
#define ip_to_object(port)              (&(port)->ip_object)
#define ip_mq_lock_held(port)           io_lock_held(ip_to_object(port))
#define ip_mq_lock(port)                ipc_port_lock(port)
#define ip_mq_lock_label_get(port)      ipc_port_lock_label_get(port)
#define ip_mq_lock_check_aligned(port)  ipc_port_lock_check_aligned(port)
#define ip_mq_lock_try(port)            ipc_port_lock_try(port)
#define ip_mq_lock_held_kdp(port)       io_lock_held_kdp(ip_to_object(port))
#define ip_mq_unlock(port)              io_unlock(ip_to_object(port))

#define ip_reference(port)              io_reference(ip_to_object(port))
#define ip_release(port)                io_release(ip_to_object(port))
#define ip_release_safe(port)           io_release_safe(ip_to_object(port))
#define ip_release_live(port)           io_release_live(ip_to_object(port))
#define ip_alloc()                      zalloc_id(ZONE_ID_IPC_PORT, Z_WAITOK_ZERO_NOFAIL)
#define ip_free(port)                   zfree_id(ZONE_ID_IPC_PORT, port)
#define ip_validate(port) \
	zone_id_require(ZONE_ID_IPC_PORT, sizeof(struct ipc_port), port)

#define ip_from_waitq(wq)               __container_of(wq, struct ipc_port, ip_waitq)
#define ip_from_mq(mq)                  __container_of(mq, struct ipc_port, ip_messages)

#define ip_type(port)                   io_type(ip_to_object(port))
#define ip_is_kobject(port)             io_is_kobject(ip_to_object(port))
#define ip_label_get(port, ...)         io_label_get(ip_to_object(port), ## __VA_ARGS__)
#define ip_label_put(port, label)       io_label_put(ip_to_object(port), label)
#define ip_label_peek_kdp(port, ...)    io_label_peek_kdp(ip_to_object(port), ## __VA_ARGS__)

#define ip_full_kernel(port)            imq_full_kernel(&(port)->ip_messages)
#define ip_full(port)                   imq_full(&(port)->ip_messages)

#define ip_active(port)                 io_state_active(ip_to_object(port)->io_state)
#define ip_in_a_space(port)             io_state_in_space(ip_to_object(port)->io_state)
#define ip_in_limbo(port)               io_state_in_limbo(ip_to_object(port)->io_state)
#define ip_in_transit(port)             io_state_in_transit(ip_to_object(port)->io_state)
#define ip_is_moving(port)              io_state_is_moving(ip_to_object(port)->io_state)
#define ip_is_immovable_receive(port)   (ip_to_object(port)->io_state == IO_STATE_IN_SPACE_IMMOVABLE)

#define ip_is_exception_port(port)              (ip_is_exception_port_type(ip_type(port)))
#define ip_is_exception_port_type(type)         ((type) == IOT_EXCEPTION_PORT)
#define ip_is_notification_port(port)           (ip_is_notification_port_type(ip_type(port)))
#define ip_is_notification_port_type(type)      ((type) == IOT_NOTIFICATION_PORT)
#define ip_is_weak_reply_port(port)             (ip_type(port) == IOT_WEAK_REPLY_PORT)
#define ip_is_special_reply_port_type(type)     ((type) == IOT_SPECIAL_REPLY_PORT)
#define ip_is_special_reply_port(port)          (ip_is_special_reply_port_type(ip_type(port)))
#define ip_is_any_service_port(port)            ip_is_any_service_port_type(ip_type(port))
#define ip_is_strong_service_port(port)         ip_is_strong_service_port_type(ip_type(port))
#define ip_is_weak_service_port_type(type)      ((type) == IOT_WEAK_SERVICE_PORT)
#define ip_is_bootstrap_port(port)              ip_is_bootstrap_port_type(ip_type(port))
#define ip_is_port_array_allowed(port)          (ip_type(port) == IOT_CONNECTION_PORT_WITH_PORT_ARRAY)
#define ip_is_connection_port(port)             (ip_type(port) == IOT_CONNECTION_PORT)
#define ip_is_timer(port)                       (ip_type(port) == IOT_TIMER_PORT)

static inline bool
ip_is_any_service_port_type(ipc_object_type_t type)
{
	return type == IOT_SERVICE_PORT || type == IOT_WEAK_SERVICE_PORT;
}
static inline bool
ip_is_strong_service_port_type(ipc_object_type_t type)
{
	return type == IOT_SERVICE_PORT;
}
static inline bool
ip_is_bootstrap_port_type(ipc_object_type_t type)
{
	return type == IOT_BOOTSTRAP_PORT;
}
static inline bool
ip_is_reply_port_type(ipc_object_type_t type)
{
	return type == IOT_REPLY_PORT || type == IOT_SPECIAL_REPLY_PORT;
}
static inline bool
ip_is_reply_port(ipc_port_t port)
{
	ipc_object_type_t type = ip_type(port);
	return ip_is_reply_port_type(type);
}

#define ip_is_tt_control_port(port)             (ip_is_tt_control_port_type(ip_type(port)))

static inline bool
ip_is_tt_control_port_type(ipc_object_type_t type)
{
	return type == IKOT_TASK_CONTROL || type == IKOT_THREAD_CONTROL;
}

/*
 * Use the low bits in the ipr_soright to specify the request type
 */
__enum_decl(ipc_port_request_opts_t, uintptr_t, {
	IPR_SOR_SPARM_MASK = 0x01,              /* send-possible armed */
	IPR_SOR_SPREQ_MASK = 0x02,              /* send-possible requested */
});
#define IPR_SOR_SPBIT_MASK      3               /* combo */
#define IPR_SOR_SPARMED(sor)    (((uintptr_t)(sor) & IPR_SOR_SPARM_MASK) != 0)
#define IPR_SOR_SPREQ(sor)      (((uintptr_t)(sor) & IPR_SOR_SPREQ_MASK) != 0)
#define IPR_SOR_PORT(sor)       ((ipc_port_t)((uintptr_t)(sor) & ~IPR_SOR_SPBIT_MASK))
#define IPR_SOR_MAKE(p, m)      ((ipc_port_t)((uintptr_t)(p) | (m)))

extern lck_grp_t        ipc_lck_grp;
extern lck_attr_t       ipc_lck_attr;

/*
 *	Taking the ipc_port_multiple lock grants the privilege
 *	to lock multiple ports at once.  No ports must locked
 *	when it is taken.
 */

extern lck_spin_t ipc_port_multiple_lock_data;

#define ipc_port_multiple_lock()                                        \
	lck_spin_lock_grp(&ipc_port_multiple_lock_data, &ipc_lck_grp)

#define ipc_port_multiple_unlock()                                      \
	lck_spin_unlock(&ipc_port_multiple_lock_data)

/*
 *	Search for the end of the chain (a port not in transit),
 *	acquiring locks along the way.
 */
extern boolean_t ipc_port_destination_chain_lock(
	ipc_port_t port,
	ipc_port_t *base);

/*
 *	The port timestamp facility provides timestamps
 *	for port destruction.  It is used to serialize
 *	mach_port_names with port death.
 */

/* Retrieve a port timestamp value */
extern ipc_port_timestamp_t ipc_port_timestamp(void);

/*
 *	Compares two timestamps, and returns TRUE if one
 *	happened before two.  Note that this formulation
 *	works when the timestamp wraps around at 2^32,
 *	as long as one and two aren't too far apart.
 */

#define IP_TIMESTAMP_ORDER(one, two)    ((int) ((one) - (two)) < 0)

extern void __abortlike __ipc_port_inactive_panic(ipc_port_t port);

static inline void
require_ip_active(ipc_port_t port)
{
	if (!ip_active(port)) {
		__ipc_port_inactive_panic(port);
	}
}

static inline void
ip_mq_unlock_label_put(ipc_port_t port, ipc_object_label_t *label)
{
	ip_label_put(port, label);
	io_unlock_nocheck(ip_to_object(port));
}

static inline bool
ip_in_space(ipc_port_t port, ipc_space_t space)
{
	ip_mq_lock_held(port); /* port must be locked, otherwise PAC could fail */
	return ip_in_a_space(port) && port->ip_receiver == space;
}

/* use sparsely when port lock is not possible, just compare raw pointer */
static inline bool
ip_in_space_noauth(ipc_port_t port, void* space)
{
	void *__single raw_ptr = ptrauth_strip(*(void **)&port->ip_receiver, ptrauth_key_process_independent_data);
	return raw_ptr == space;
}

static inline ipc_space_t
ip_get_receiver(ipc_port_t port)
{
	ip_mq_lock_held(port); /* port must be locked, otherwise PAC could fail */
	return ip_in_a_space(port) ? port->ip_receiver : NULL;
}

static inline mach_port_name_t
ip_get_receiver_name(ipc_port_t port)
{
	return ip_in_a_space(port) ? port->ip_receiver_name : MACH_PORT_NULL;
}

static inline ipc_port_t
ip_get_destination(ipc_port_t port)
{
	ip_mq_lock_held(port); /* port must be locked, otherwise PAC could fail */
	return ip_is_moving(port) ? port->ip_destination : IP_NULL;
}

static inline ipc_port_timestamp_t
ip_get_death_time(ipc_port_t port)
{
	assert(!ip_active(port));
	return port->ip_timestamp;
}

static inline ipc_importance_task_t
ip_get_imp_task(ipc_port_t port)
{
	return (!ip_is_special_reply_port(port) && port->ip_tempowner) ? port->ip_imp_task : IIT_NULL;
}

extern kern_return_t ipc_port_translate_send(
	ipc_space_t                     space,
	mach_port_name_t                name,
	ipc_port_t                     *portp);

extern kern_return_t ipc_port_translate_receive(
	ipc_space_t                     space,
	mach_port_name_t                name,
	ipc_port_t                     *portp);

/* Allocate a notification request slot */
extern kern_return_t ipc_port_request_alloc(
	ipc_port_t                      port,
	mach_port_name_t                name,
	ipc_port_t                      soright,
	ipc_port_request_opts_t         options,
	ipc_port_request_index_t       *indexp);

extern kern_return_t ipc_port_request_hnotify_alloc(
	ipc_port_t                      port,
	struct host_notify_entry       *hnotify,
	ipc_port_request_index_t       *indexp);

/* Grow one of a port's tables of notifcation requests */
extern kern_return_t ipc_port_request_grow(
	ipc_port_t                      port);

/* Return the type(s) of notification requests outstanding */
extern mach_port_type_t ipc_port_request_type(
	ipc_port_t                      port,
	mach_port_name_t                name,
	ipc_port_request_index_t        index);

/* Cancel a notification request and return the send-once right */
extern ipc_port_t ipc_port_request_cancel(
	ipc_port_t                      port,
	mach_port_name_t                name,
	ipc_port_request_index_t        index);

/* Arm any delayed send-possible notification */
extern bool ipc_port_request_sparm(
	ipc_port_t                port,
	mach_port_name_t          name,
	ipc_port_request_index_t  index,
	mach_msg_option64_t       option,
	mach_msg_priority_t       priority);


/*!
 * @abstract
 * Marks a port as in-space.
 *
 * @discussion
 * The port must be in transit.
 * @c port must be locked.
 *
 * @param port          the port to mark as in-space.
 * @param label         the current object label for @c port.
 * @param space         the space the port is being received into.
 * @param name          the name the port will have in @c space.
 * @param force_state   the state to force. Must be one of:
 *                      - IO_STATE_INACTIVE (means default policy),
 *                      - IO_STATE_IN_SPACE,
 *                      - IO_STATE_IN_SPACE_IMMOVABLE.
 * @returns             the current port destination or IP_NULL.
 */
extern ipc_port_t ipc_port_mark_in_space(
	ipc_port_t              port,
	ipc_object_label_t     *label,
	ipc_space_t             space,
	mach_port_name_t        name,
	ipc_object_state_t      force_state);

#define IPC_PORT_SET_IN_SPACE_DEFAULT         0
#define IPC_PORT_SET_IN_SPACE_PSEUDO_RECEIVE  1
#define IPC_PORT_SET_IN_SPACE_FORCE_IMMOVABLE 2


/*!
 * @abstract
 * Marks a port as in-limbo, and prepare it for a move.
 *
 * @discussion
 * The port must be in space.
 * @c port must be locked.
 *
 * @param port          the port to mark as in-space.
 * @param label         the current object label for @c port.
 * @param free_l        a list to accumulate waitq linkages to free
 *                      by calling waitq_link_free_list(WQT_PORT_SET, &free_l)
 *                      on it.
 */
extern void ipc_port_mark_in_limbo(
	ipc_port_t              port,
	ipc_object_label_t     *label,
	waitq_link_list_t      *free_l);


/*!
 * @abstract
 * Sets a port as in-transit
 *
 * @discussion
 * The port must be in limbo.
 * @c port must be locked.
 *
 * A reference on @c dest is taken.
 *
 * @param port          the port to mark as in-space.
 * @param dest          the port @c port is enqueued onto.
 */
extern void ipc_port_mark_in_transit(
	ipc_port_t              port,
	ipc_port_t              dest);

__options_decl(ipc_port_init_flags_t, uint32_t, {
	IP_INIT_NONE            = 0x00000000,
	IP_INIT_MAKE_SEND_RIGHT = 0x00000001,
});

extern void ipc_port_lock(
	ipc_port_t              port);

extern ipc_object_label_t ipc_port_lock_label_get(
	ipc_port_t              port) __result_use_check;

extern ipc_object_label_t ipc_port_lock_check_aligned(
	ipc_port_t              port) __result_use_check;

extern bool ipc_port_lock_try(
	ipc_port_t              port);

/* Allocate a port */
extern kern_return_t ipc_port_alloc(
	ipc_space_t             space,
	ipc_object_label_t      label,
	ipc_port_init_flags_t   flags,
	mach_port_name_t       *namep,
	ipc_port_t             *portp);

/* Allocate a port, with a specific name */
extern kern_return_t ipc_port_alloc_name(
	ipc_space_t             space,
	ipc_object_label_t      label,
	ipc_port_init_flags_t   flags,
	mach_port_name_t        name,
	ipc_port_t             *portp);

extern ipc_object_label_t ipc_kobject_label_alloc(
	ipc_object_type_t       otype,
	ipc_label_t             label_tag,
	ipc_port_t              alt_port);

extern void ipc_kobject_label_free(
	ipc_object_label_t      label);

/* Generate dead name notifications */
extern void ipc_port_dnnotify(
	ipc_port_t              port);

/* Generate send-possible notifications */
extern void ipc_port_spnotify(
	ipc_port_t              port);

/* Destroy a port */
extern void ipc_port_destroy(
	ipc_port_t              port);

/* Check if queueing "port" in a message for "dest" would create a circular
 *  group of ports and messages */
extern boolean_t
ipc_port_check_circularity(
	ipc_port_t              port,
	ipc_port_t              dest);

#if IMPORTANCE_INHERITANCE

enum {
	IPID_OPTION_NORMAL       = 0, /* normal boost */
	IPID_OPTION_SENDPOSSIBLE = 1, /* send-possible induced boost */
};

/* link the destination port with special reply port */
void
ipc_port_link_special_reply_port(
	ipc_port_t special_reply_port,
	ipc_port_t dest_port,
	boolean_t sync_bootstrap_checkin);

#define IPC_PORT_ADJUST_SR_NONE                      0
#define IPC_PORT_ADJUST_SR_ALLOW_SYNC_LINKAGE        0x1
#define IPC_PORT_ADJUST_SR_LINK_WORKLOOP             0x2
#define IPC_PORT_ADJUST_UNLINK_THREAD                0x4
#define IPC_PORT_ADJUST_SR_RECEIVED_MSG              0x8
#define IPC_PORT_ADJUST_SR_ENABLE_EVENT              0x10
#define IPC_PORT_ADJUST_RESET_BOOSTRAP_CHECKIN       0x20

void
ipc_special_reply_port_bits_reset(ipc_port_t special_reply_port);

void
ipc_special_reply_port_msg_sent(ipc_port_t special_reply_port);

void
ipc_special_reply_port_msg_sent(ipc_port_t special_reply_port);

/* Adjust special reply port linkage */
void
ipc_port_adjust_special_reply_port_locked(
	ipc_port_t special_reply_port,
	struct knote *kn,
	uint8_t flags,
	boolean_t get_turnstile);

void
ipc_port_adjust_sync_link_state_locked(
	ipc_port_t port,
	int sync_link_state,
	turnstile_inheritor_t inheritor);

/* Adjust special reply port linkage */
void
ipc_port_adjust_special_reply_port(
	ipc_port_t special_reply_port,
	uint8_t flags);

void
ipc_port_adjust_port_locked(
	ipc_port_t port,
	struct knote *kn,
	boolean_t sync_bootstrap_checkin);

void
ipc_port_clear_sync_rcv_thread_boost_locked(
	ipc_port_t port);

bool
ipc_port_has_prdrequest(
	ipc_port_t port);

kern_return_t
ipc_port_add_watchport_elem_locked(
	ipc_port_t                 port,
	struct task_watchport_elem *watchport_elem,
	struct task_watchport_elem **old_elem);

kern_return_t
ipc_port_clear_watchport_elem_internal_conditional_locked(
	ipc_port_t                 port,
	struct task_watchport_elem *watchport_elem);

kern_return_t
ipc_port_replace_watchport_elem_conditional_locked(
	ipc_port_t                 port,
	struct task_watchport_elem *old_watchport_elem,
	struct task_watchport_elem *new_watchport_elem);

struct task_watchport_elem *
ipc_port_clear_watchport_elem_internal(
	ipc_port_t                 port);

void
ipc_port_send_turnstile_prepare(ipc_port_t port);

void
ipc_port_send_turnstile_complete(ipc_port_t port);

struct waitq *
ipc_port_rcv_turnstile_waitq(struct waitq *waitq);

/* apply importance delta to port only */
extern mach_port_delta_t
ipc_port_impcount_delta(
	ipc_port_t              port,
	mach_port_delta_t       delta,
	ipc_port_t              base);

/* apply importance delta to port, and return task importance for update */
extern boolean_t
ipc_port_importance_delta_internal(
	ipc_port_t              port,
	natural_t               options,
	mach_port_delta_t       *deltap,
	ipc_importance_task_t   *imp_task);

/* Apply an importance delta to a port and reflect change in receiver task */
extern boolean_t
ipc_port_importance_delta(
	ipc_port_t              port,
	natural_t               options,
	mach_port_delta_t       delta);
#endif /* IMPORTANCE_INHERITANCE */

/*!
 * @function ipc_port_make_send_any_locked()
 *
 * @brief
 * Makes a naked send right for a locked and active port.
 *
 * @decription
 * @c ipc_port_make_send_*() should not be used in any generic IPC
 * plumbing, as this is an operation that subsystem owners need
 * to be able to synchronize against with the make-send-count
 * and no-senders notifications.
 *
 * It is especially important for kobject types, and in general MIG upcalls
 * or replies from the kernel should never use MAKE_SEND dispositions,
 * and prefer COPY_SEND or MOVE_SEND, so that subsystems can control
 * where that send right comes from.
 *
 * This function doesn't perform any validation on the type of port,
 * this duty is left to the caller.
 *
 * @param port          An active and locked port.
 */
extern ipc_port_t ipc_port_make_send_any_locked(
	ipc_port_t      port);

/*!
 * @function ipc_port_make_send_any()
 *
 * @brief
 * Makes a naked send right for the specified port.
 *
 * @decription
 * @see ipc_port_make_send_any_locked() for a general warning about
 * making send rights.
 *
 * This function doesn't perform any validation on the type of port,
 * this duty is left to the caller.
 *
 * Using @c ipc_port_make_send_mqueue() or @c ipc_kobject_make_send()
 * is preferred.
 *
 * @param port          The target port.
 *
 * @returns
 * - IP_DEAD            if @c port was dead.
 * - @c port            if @c port was valid, in which case
 *                      a naked send right was made.
 */
extern ipc_port_t ipc_port_make_send_any(
	ipc_port_t      port) __result_use_check;

/*!
 * @function ipc_port_make_send_mqueue()
 *
 * @brief
 * Makes a naked send right for the specified port.
 *
 * @decription
 * @see ipc_port_make_send_any_locked() for a general warning about
 * making send rights.
 *
 * This function will return IP_NULL if the port wasn't a message queue.
 *
 * This avoids confusions where kobject ports are being set in places
 * where the system expects message queues.
 *
 * @param port          The target port.
 *
 * @returns
 * - IP_NULL            if @c port was not a message queue port
 *                      (!ip_is_kobject()), or @c port was IP_NULL.
 * - IP_DEAD            if @c port was dead.
 * - @c port            if @c port was valid, in which case
 *                      a naked send right was made.
 */
extern ipc_port_t ipc_port_make_send_mqueue(
	ipc_port_t      port) __result_use_check;

/*!
 * @function ipc_port_copy_send_any_locked()
 *
 * @brief
 * Copies a naked send right for a locked and active port.
 *
 * @decription
 * This function doesn't perform any validation on the type of port,
 * this duty is left to the caller.
 *
 * @param port          An active and locked port.
 */
extern void ipc_port_copy_send_any_locked(
	ipc_port_t      port);

/*!
 * @function ipc_port_make_send_any()
 *
 * @brief
 * Copies a naked send right for the specified port.
 *
 * @decription
 * This function doesn't perform any validation on the type of port,
 * this duty is left to the caller.
 *
 * Using @c ipc_port_copy_send_mqueue() or @c ipc_kobject_copy_send()
 * is preferred.
 *
 * @param port          The target port.
 *
 * @returns
 * - IP_DEAD            if @c port was dead.
 * - @c port            if @c port was valid, in which case
 *                      a naked send right was made.
 */
extern ipc_port_t ipc_port_copy_send_any(
	ipc_port_t      port) __result_use_check;

/*!
 * @function ipc_port_copy_send_mqueue()
 *
 * @brief
 * Copies a naked send right for the specified port.
 *
 * @decription
 * This function will return IP_NULL if the port wasn't a message queue.
 *
 * This avoids confusions where kobject ports are being set in places
 * where the system expects message queues.
 *
 * @param port          The target port.
 *
 * @returns
 * - IP_NULL            if @c port was not a message queue port
 *                      (!ip_is_kobject()), or @c port was IP_NULL.
 * - IP_DEAD            if @c port was dead.
 * - @c port            if @c port was valid, in which case
 *                      a naked send right was made.
 */
extern ipc_port_t ipc_port_copy_send_mqueue(
	ipc_port_t      port) __result_use_check;

/* Copyout a naked send right */
extern mach_port_name_t ipc_port_copyout_send(
	ipc_port_t      sright,
	ipc_space_t     space);

extern mach_port_name_t ipc_port_copyout_send_pinned(
	ipc_port_t      sright,
	ipc_space_t     space);

extern mach_port_name_t ipc_port_copyout_send_allow_immovable(
	ipc_port_t      sright,
	ipc_space_t     space);

extern void ipc_port_thread_group_blocked(
	ipc_port_t      port);

extern void ipc_port_thread_group_unblocked(void);

extern void ipc_port_release_send_and_unlock(
	ipc_port_t      port);

extern kern_return_t mach_port_deallocate_kernel(
	ipc_space_t             space,
	mach_port_name_t        name,
	ipc_object_type_t       otype);

/* Make a naked send-once right from a locked and active receive right */
extern ipc_port_t ipc_port_make_sonce_locked(
	ipc_port_t              port);

/* Make a naked send-once right from a receive right */
extern ipc_port_t ipc_port_make_sonce(
	ipc_port_t              port);

/* Release a naked send-once right */
extern void ipc_port_release_sonce(
	ipc_port_t              port);

/* Release a naked send-once right */
extern void ipc_port_release_sonce_and_unlock(
	ipc_port_t              port);

/* Release a naked (in limbo or in transit) receive right */
extern void ipc_port_release_receive(
	ipc_port_t              port);

/* Finalize the destruction of a port and free it */
extern void ipc_port_free(
	ipc_port_t              port);

/* Get receiver task and its pid (if any) for port. Assumes port is locked. */
extern pid_t ipc_port_get_receiver_task_locked(
	ipc_port_t              port,
	task_t                 *task);

/* Get receiver task and its pid (if any) for port. */
extern pid_t ipc_port_get_receiver_task(
	ipc_port_t              port,
	task_t                 *task);

/* Allocate a port in a special space */
extern ipc_port_t ipc_port_alloc_special(
	ipc_space_t             space,
	ipc_object_label_t      label,
	ipc_port_init_flags_t   flags);

extern void ipc_port_recv_update_inheritor(
	ipc_port_t              port,
	struct turnstile       *turnstile,
	turnstile_update_flags_t flags);

extern void ipc_port_send_update_inheritor(
	ipc_port_t              port,
	struct turnstile       *turnstile,
	turnstile_update_flags_t flags);

extern int ipc_special_reply_get_pid_locked(
	ipc_port_t              port);

__exported_pop
#endif /* MACH_KERNEL_PRIVATE */
#if KERNEL_PRIVATE

/* Release a (valid) naked send right */
extern void ipc_port_release_send(
	ipc_port_t             port);

extern void ipc_port_reference(
	ipc_port_t             port);

extern void ipc_port_release(
	ipc_port_t             port);

struct thread_attr_for_ipc_propagation {
	union {
		struct {
			uint64_t tafip_iotier:2,
			    tafip_qos:3;
		};
		uint64_t tafip_value;
	};
	uint64_t tafip_reserved;
};
xnu_static_assert_struct_size(struct thread_attr_for_ipc_propagation, 16);

extern kern_return_t ipc_port_propagate_thread_attr(
	ipc_port_t             port,
	struct thread_attr_for_ipc_propagation attr);

extern kern_return_t ipc_port_reset_thread_attr(
	ipc_port_t             port);

#endif /* KERNEL_PRIVATE */

__ASSUME_PTR_ABI_SINGLE_END __END_DECLS

#endif  /* _IPC_IPC_PORT_H_ */
