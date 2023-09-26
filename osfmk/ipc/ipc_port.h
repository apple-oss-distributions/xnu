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

#ifdef MACH_KERNEL_PRIVATE

#include <mach_assert.h>

#include <mach/mach_types.h>
#include <mach/boolean.h>
#include <mach/kern_return.h>
#include <mach/port.h>

#include <kern/assert.h>
#include <kern/kern_types.h>
#include <kern/turnstile.h>

#include <ipc/ipc_types.h>
#include <ipc/ipc_object.h>
#include <ipc/ipc_mqueue.h>
#include <ipc/ipc_space.h>

#include <security/_label.h>

#include <ptrauth.h>

extern int proc_isinitproc(struct proc *p);

struct task_watchport_elem;

typedef unsigned int ipc_port_timestamp_t;

struct ipc_port_request {
	union {
		struct ipc_port                *ipr_soright;
		struct host_notify_entry       *ipr_hnotify;
	};

	union {
#define IPR_HOST_NOTIFY                         0xfffffffeu
		mach_port_name_t                ipr_name;
		ipc_port_request_index_t        ipr_next;
	};
};

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
		    , ip_specialreply:1           /* port is a special reply port */
		    , ip_sync_link_state:3        /* link the port to destination port/ Workloop */
		    , ip_sync_bootstrap_checkin:1 /* port part of sync bootstrap checkin, push on thread doing the checkin */
		    , ip_immovable_receive:1      /* the receive right cannot be moved out of a space, until it is destroyed */
		    , ip_immovable_send:1         /* No send(once) rights to this port can be moved out of a space, never unset */
		    , ip_no_grant:1               /* Port wont accept complex messages containing (ool) port descriptors */
		    , ip_tg_block_tracking:1      /* Track blocking relationship between thread groups during sync IPC */
		    , ip_pinned:1                 /* Can't deallocate the last send right from a space while the bit is set */
		    , ip_service_port:1           /* port is a service port */
		    , ip_has_watchport:1          /* port has an exec watchport */
		    , ip_kernel_iotier_override:2 /* kernel iotier override */
		    , ip_kernel_qos_override:3    /* kernel qos override */
		    , ip_reply_port_semantics:3   /* reply port defense in depth type */
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
		struct ipc_port        *XNU_PTRAUTH_SIGNED_PTR("ipc_port.ip_destination") ip_destination;
		ipc_port_timestamp_t    ip_timestamp;
	};

	/* update ipc_kobject_upgrade_locked() if this union is changed */
	union {
		uintptr_t               ip_kobject; /* manually PAC-ed, see ipc_kobject_get_raw() */
		ipc_importance_task_t   ip_imp_task; /* use accessor ip_get_imp_task() */
		struct ipc_port        *ip_sync_inheritor_port;
		struct knote           *ip_sync_inheritor_knote;
		struct turnstile       *ip_sync_inheritor_ts;
	};

	/*
	 * ip_specialreply:  ip_pid
	 * ip_has_watchport: ip_twe
	 * else:             ip_pdrequest
	 */
	union {
		int                     ip_pid;
		struct task_watchport_elem *XNU_PTRAUTH_SIGNED_PTR("ipc_port.ip_twe") ip_twe;
		struct ipc_port *XNU_PTRAUTH_SIGNED_PTR("ipc_port.ip_pdrequest") ip_pdrequest;
	};

#define IP_KOBJECT_NSREQUEST_ARMED      ((struct ipc_port *)1)
	struct ipc_port                *ip_nsrequest;
	ipc_port_request_table_t XNU_PTRAUTH_SIGNED_PTR("ipc_port.ip_request") ip_requests;
	union {
		struct ipc_kmsg *XNU_PTRAUTH_SIGNED_PTR("ipc_port.premsg") ip_premsg;
		struct turnstile       *ip_send_turnstile;
	};
	mach_vm_address_t               ip_context;

#if DEVELOPMENT || DEBUG
	natural_t                       ip_srp_lost_link : 1;   /* special reply port turnstile link chain broken */
	natural_t                       ip_srp_msg_sent : 1;    /* special reply port msg sent */
	natural_t                       ip_impcount : 30;       /* number of importance donations in nested queue */
#else
	natural_t                       ip_impcount;            /* number of importance donations in nested queue */
#endif
	mach_port_mscount_t             ip_mscount;
	mach_port_rights_t              ip_srights;
	mach_port_rights_t              ip_sorights;

	union {
		ipc_kobject_label_t XNU_PTRAUTH_SIGNED_PTR("ipc_port.kolabel") ip_kolabel;
		/* Union of service and connection ports' message filtering metadata */
		void * XNU_PTRAUTH_SIGNED_PTR("ipc_port.ip_splabel") ip_splabel;
	};

#if MACH_ASSERT
	unsigned long                   ip_timetrack;   /* give an idea of "when" created */
	uint32_t                        ip_made_bt;     /* stack trace (btref_t) */
	uint32_t                        ip_made_pid;    /* for debugging */
#endif  /* MACH_ASSERT */
};

static inline bool
ip_in_pset(ipc_port_t port)
{
	return !circle_queue_empty(&port->ip_waitq.waitq_links);
}

#define ip_receiver_name        ip_messages.imq_receiver_name
#define ip_reply_context        ip_messages.imq_context
#define ip_klist                ip_messages.imq_klist

#define port_send_turnstile(port)                            \
	(IP_PREALLOC(port) ? TURNSTILE_NULL : (port)->ip_send_turnstile)

#define set_port_send_turnstile(port, value)                 \
MACRO_BEGIN                                                  \
if (!IP_PREALLOC(port)) {                                     \
	(port)->ip_send_turnstile = (value);           \
}                                                         \
MACRO_END

#define port_send_turnstile_address(port)                    \
	(IP_PREALLOC(port) ? NULL : &((port)->ip_send_turnstile))

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
#define ip_active(port)                 io_active(ip_to_object(port))
#define ip_mq_lock_held(port)           io_lock_held(ip_to_object(port))
#define ip_mq_lock(port)                io_lock(ip_to_object(port))
#define ip_mq_lock_try(port)            io_lock_try(ip_to_object(port))
#define ip_mq_lock_held_kdp(port)       io_lock_held_kdp(ip_to_object(port))
#define ip_mq_unlock(port)              io_unlock(ip_to_object(port))

#define ip_reference(port)              io_reference(ip_to_object(port))
#define ip_release(port)                io_release(ip_to_object(port))
#define ip_release_safe(port)           io_release_safe(ip_to_object(port))
#define ip_release_live(port)           io_release_live(ip_to_object(port))
#define ip_validate(port) \
	zone_id_require(ZONE_ID_IPC_PORT, sizeof(struct ipc_port), port)

#define ip_from_waitq(wq)               __container_of(wq, struct ipc_port, ip_waitq)
#define ip_from_mq(mq)                  __container_of(mq, struct ipc_port, ip_messages)

#define ip_kotype(port)                 io_kotype(ip_to_object(port))
#define ip_is_kobject(port)             io_is_kobject(ip_to_object(port))
#define ip_is_control(port) \
	(ip_kotype(port) == IKOT_TASK_CONTROL || ip_kotype(port) == IKOT_THREAD_CONTROL)
#define ip_is_kolabeled(port)           io_is_kolabeled(ip_to_object(port))

#define ip_full_kernel(port)            imq_full_kernel(&(port)->ip_messages)
#define ip_full(port)                   imq_full(&(port)->ip_messages)

/*
 * IPC Port flags for reply port defense in depth
 *
 * PORT_MARK_REPLY_PORT
 *   Port is marked as a reply port.
 *
 * PORT_ENFORCE_REPLY_PORT_SEMANTICS
 *   When talking to this port, the local port of mach msg needs to be a reply port.
 *   Currrently service ports and libxpc connection ports adopt this.
 *
 * PORT_MARK_PROVISIONAL_REPLY_PORT
 *   Port is marked as a provisional reply port with an eventual goal of making it port as PORT_MARK_REPLY_PORT.
 *
 * PORT_ENFORCE_RIGID_REPLY_PORT_SEMANTICS
 *   Same as PORT_ENFORCE_REPLY_PORT_SEMANTICS above, but does not allow for provisional reply ports.
 *   Once provisional reply ports no longer exist, this will be removed as "rigidness/strictness" will be irrelavant.
 *
 * PORT_ID_PROTECTED_OPT_OUT
 *   Port is opted out from identity protected enforcement for mach exceptions.
 */
#define PORT_MARK_REPLY_PORT              0x01
#define PORT_ENFORCE_REPLY_PORT_SEMANTICS 0x02
#define PORT_MARK_PROVISIONAL_REPLY_PORT  0x03
#define PORT_ENFORCE_RIGID_REPLY_PORT_SEMANTICS  0x04
#define PORT_ID_PROTECTED_OPT_OUT                 0x05

/* ip_reply_port_semantics can be read without a lock as it is never unset after port creation. */
#define ip_is_reply_port(port)                          (((port)->ip_reply_port_semantics) == PORT_MARK_REPLY_PORT)
#define ip_require_reply_port_semantics(port)           (((port)->ip_reply_port_semantics) == PORT_ENFORCE_REPLY_PORT_SEMANTICS)
#define ip_is_provisional_reply_port(port)              (((port)->ip_reply_port_semantics) == PORT_MARK_PROVISIONAL_REPLY_PORT)
#define ip_require_rigid_reply_port_semantics(port)     (((port)->ip_reply_port_semantics) == PORT_ENFORCE_RIGID_REPLY_PORT_SEMANTICS)
#define ip_is_id_prot_opted_out(port)                   (((port)->ip_reply_port_semantics) == PORT_ID_PROTECTED_OPT_OUT)

#define ip_mark_reply_port(port)                        ((port)->ip_reply_port_semantics = PORT_MARK_REPLY_PORT)
#define ip_enforce_reply_port_semantics(port)           ((port)->ip_reply_port_semantics = PORT_ENFORCE_REPLY_PORT_SEMANTICS)
#define ip_mark_provisional_reply_port(port)            ((port)->ip_reply_port_semantics = PORT_MARK_PROVISIONAL_REPLY_PORT)
#define ip_enforce_rigid_reply_port_semantics(port)     ((port)->ip_reply_port_semantics = PORT_ENFORCE_RIGID_REPLY_PORT_SEMANTICS)
#define ip_mark_id_prot_opt_out(port)                   ((port)->ip_reply_port_semantics = PORT_ID_PROTECTED_OPT_OUT)

#define ip_is_immovable_send(port)      ((port)->ip_immovable_send)
#define ip_is_pinned(port)              ((port)->ip_pinned)

#define ip_is_libxpc_connection_port(port) \
	(!ip_is_kolabeled(port) && (!(port)->ip_service_port) && ((port)->ip_splabel != NULL))

extern bool ip_violates_rigid_reply_port_semantics(ipc_port_t dest_port, ipc_port_t reply_port,
    int *reply_port_semantics_violation);

extern bool ip_violates_reply_port_semantics(ipc_port_t dest_port, ipc_port_t reply_port,
    int *reply_port_semantics_violation);

/* Rigid Reply Port and Move Reply Port violators */
#define REPLY_PORT_SEMANTICS_VIOLATOR    1 /* normal reply port semantics violator */
#define RRP_HARDENED_RUNTIME_VIOLATOR    2
#define MRP_HARDENED_RUNTIME_VIOLATOR    3
#define MRP_3P_VIOLATOR                  4
#define RRP_3P_VIOLATOR                  5

/* Bits reserved in IO_BITS_PORT_INFO are defined here */

/*
 * JMM - Preallocation flag
 * This flag indicates that there is a message buffer preallocated for this
 * port and we should use that when sending (from the kernel) rather than
 * allocate a new one.  This avoids deadlocks during notification message
 * sends by critical system threads (which may be needed to free memory and
 * therefore cannot be blocked waiting for memory themselves).
 */
#define IP_BIT_PREALLOC         0x00008000      /* preallocated mesg */
#define IP_PREALLOC(port)       (io_bits(ip_to_object(port)) & IP_BIT_PREALLOC)

#define IP_SET_PREALLOC(port, kmsg)                                     \
MACRO_BEGIN                                                             \
	io_bits_or(ip_to_object(port), IP_BIT_PREALLOC);                \
	(port)->ip_premsg = (kmsg);                                     \
MACRO_END

/*
 * This flag indicates that the port has opted into message filtering based
 * on a policy defined in the Sandbox.
 */
#define IP_BIT_FILTER_MSG               0x00001000
#define ip_enforce_msg_filtering(port)  ((io_bits(ip_to_object(port)) & IP_BIT_FILTER_MSG) != 0)

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

extern ipc_port_timestamp_t ipc_port_timestamp_data;

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

/*
 *  A receive right (port) can be in ONE of the following four states:
 *
 *  1) INACTIVE: Dead
 *  2) IN-SPACE: In a space
 *  3) IN-TRANSIT: Enqueued in a message
 *  4) IN-LIMBO
 *
 *  If the port is active and ip_receiver_name != MACH_PORT_NULL, we can safely
 *  deference the union as ip_receiver, which points to the space that holds
 *  receive right (but doesn't hold a ref for it).
 *
 *  If the port is active and ip_receiver_name == MACH_PORT_NULL, we can safely
 *  deference the union as ip_destination. The port is either IN-LIMBO (ip_destination == IP_NULL)
 *  or ip_destination points to the destination port and holds a ref for it.
 *
 *  If the port is not active, we can safely deference the union as ip_timestamp,
 *  which contains a timestamp taken when the port was destroyed.
 *
 *  If the port is in a space, ip_receiver_name denotes the port name its receive
 *  right occupies in the receiving space. The only exception, as an optimization trick,
 *  is task's self port (itk_self), whose ip_receiver_name actually denotes the name
 *  of mach_task_self() in owning task's space (a send right, with receive right in ipc_space_kernel).
 */

static inline bool
ip_in_a_space(ipc_port_t port)
{
	/* IN-SPACE */
	return ip_active(port) && port->ip_receiver_name != MACH_PORT_NULL;
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

static inline bool
ip_in_transit(ipc_port_t port)
{
	/* IN-TRANSIT */
	ip_mq_lock_held(port); /* port must be locked, otherwise PAC could fail */
	return ip_active(port) && !ip_in_a_space(port) && port->ip_destination != IP_NULL;
}

static inline bool
ip_in_limbo(ipc_port_t port)
{
	/* IN-LIMBO */
	ip_mq_lock_held(port); /* port must be locked, otherwise PAC could fail */
	return ip_active(port) && !ip_in_a_space(port) && port->ip_destination == IP_NULL;
}

static inline ipc_space_t
ip_get_receiver(ipc_port_t port)
{
	ip_mq_lock_held(port); /* port must be locked, otherwise PAC could fail */
	return ip_in_a_space(port) ? port->ip_receiver : NULL;
}

static inline void*
ip_get_receiver_ptr_noauth(ipc_port_t port)
{
	void *__single raw_ptr = ptrauth_strip(*(void **)&port->ip_receiver, ptrauth_key_process_independent_data);
	return raw_ptr;
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
	return ip_active(port) && !ip_in_a_space(port) ? port->ip_destination : IP_NULL;
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
	return (!ip_is_kobject(port) && !port->ip_specialreply && port->ip_tempowner) ? port->ip_imp_task : IIT_NULL;
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
extern boolean_t ipc_port_request_sparm(
	ipc_port_t                port,
	mach_port_name_t          name,
	ipc_port_request_index_t  index,
	mach_msg_option_t         option,
	mach_msg_priority_t       priority);

/* Make a no-senders request */
extern void ipc_port_nsrequest(
	ipc_port_t              port,
	mach_port_mscount_t     sync,
	ipc_port_t              notify,
	ipc_port_t              *previousp);

/* Prepare a receive right for transmission/destruction */
extern boolean_t ipc_port_clear_receiver(
	ipc_port_t              port,
	boolean_t               should_destroy,
	waitq_link_list_t      *free_l);

__options_decl(ipc_port_init_flags_t, uint32_t, {
	IPC_PORT_INIT_NONE                              = 0x00000000,
	IPC_PORT_INIT_MAKE_SEND_RIGHT                   = 0x00000001,
	IPC_PORT_INIT_MESSAGE_QUEUE                     = 0x00000002,
	IPC_PORT_INIT_SPECIAL_REPLY                     = 0x00000004,
	IPC_PORT_INIT_FILTER_MESSAGE                    = 0x00000008,
	IPC_PORT_INIT_TG_BLOCK_TRACKING                 = 0x00000010,
	IPC_PORT_INIT_LOCKED                            = 0x00000020,
	IPC_PORT_INIT_REPLY                             = 0x00000040,
	IPC_PORT_ENFORCE_REPLY_PORT_SEMANTICS           = 0x00000080,
	IPC_PORT_INIT_PROVISIONAL_REPLY                 = 0x00000100,
	IPC_PORT_INIT_PROVISIONAL_ID_PROT_OPTOUT        = 0x00000200,
	IPC_PORT_ENFORCE_RIGID_REPLY_PORT_SEMANTICS     = 0x00000300,
});

/* Initialize a newly-allocated port */
extern void ipc_port_init(
	ipc_port_t              port,
	ipc_space_t             space,
	ipc_port_init_flags_t   flags,
	mach_port_name_t        name);

/* Allocate a port */
extern kern_return_t ipc_port_alloc(
	ipc_space_t             space,
	ipc_port_init_flags_t   flags,
	mach_port_name_t        *namep,
	ipc_port_t              *portp);

/* Allocate a port, with a specific name */
extern kern_return_t ipc_port_alloc_name(
	ipc_space_t             space,
	ipc_port_init_flags_t   flags,
	mach_port_name_t        name,
	ipc_port_t              *portp);

/* Attach a label to the port */
extern void ipc_port_set_label(
	ipc_port_t              port,
	ipc_label_t             label);

/* Generate dead name notifications */
extern void ipc_port_dnnotify(
	ipc_port_t              port);

/* Generate send-possible notifications */
extern void ipc_port_spnotify(
	ipc_port_t              port);

/* Destroy a port */
extern void ipc_port_destroy(
	ipc_port_t      port);

/* Check if queueing "port" in a message for "dest" would create a circular
 *  group of ports and messages */
extern boolean_t
ipc_port_check_circularity(
	ipc_port_t      port,
	ipc_port_t      dest);

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
 *                      (IKOT_NONE, or IKOT_TIMER), or @c port was IP_NULL.
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
 *                      (IKOT_NONE, or IKOT_TIMER), or @c port was IP_NULL.
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

extern void ipc_port_thread_group_blocked(
	ipc_port_t      port);

extern void ipc_port_thread_group_unblocked(void);

extern void ipc_port_release_send_and_unlock(
	ipc_port_t      port);
#endif /* MACH_KERNEL_PRIVATE */

#if KERNEL_PRIVATE

/* Release a (valid) naked send right */
extern void ipc_port_release_send(
	ipc_port_t      port);

extern void ipc_port_reference(
	ipc_port_t port);

extern void ipc_port_release(
	ipc_port_t port);

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

extern kern_return_t
ipc_port_propagate_thread_attr(
	ipc_port_t port,
	struct thread_attr_for_ipc_propagation attr);

extern kern_return_t
ipc_port_reset_thread_attr(ipc_port_t port);
#endif /* KERNEL_PRIVATE */

#ifdef MACH_KERNEL_PRIVATE

/* Make a naked send-once right from a locked and active receive right */
extern ipc_port_t ipc_port_make_sonce_locked(
	ipc_port_t      port);

/* Make a naked send-once right from a receive right */
extern ipc_port_t ipc_port_make_sonce(
	ipc_port_t      port);

/* Release a naked send-once right */
extern void ipc_port_release_sonce(
	ipc_port_t      port);

/* Release a naked send-once right */
extern void ipc_port_release_sonce_and_unlock(
	ipc_port_t      port);

/* Release a naked (in limbo or in transit) receive right */
extern void ipc_port_release_receive(
	ipc_port_t      port);

/* Finalize the destruction of a port before it gets freed */
extern void ipc_port_finalize(
	ipc_port_t      port);

/* Get receiver task and its pid (if any) for port. Assumes port is locked. */
extern pid_t ipc_port_get_receiver_task_locked(ipc_port_t port, uintptr_t *task);

/* Get receiver task and its pid (if any) for port. */
extern pid_t ipc_port_get_receiver_task(ipc_port_t port, uintptr_t *task);

/* Allocate a port in a special space */
extern ipc_port_t ipc_port_alloc_special(
	ipc_space_t             space,
	ipc_port_init_flags_t   flags);

/* Deallocate a port in a special space */
extern void ipc_port_dealloc_special_and_unlock(
	ipc_port_t      port,
	ipc_space_t     space);

/* Deallocate a port in a special space */
extern void ipc_port_dealloc_special(
	ipc_port_t      port,
	ipc_space_t     space);

extern void ipc_port_recv_update_inheritor(ipc_port_t port,
    struct turnstile *turnstile,
    turnstile_update_flags_t flags);

extern void ipc_port_send_update_inheritor(ipc_port_t port,
    struct turnstile *turnstile,
    turnstile_update_flags_t flags);

extern int
ipc_special_reply_get_pid_locked(ipc_port_t port);

#define ipc_port_alloc_reply()          \
	ipc_port_alloc_special(ipc_space_reply, IPC_PORT_INIT_MESSAGE_QUEUE | IPC_PORT_INIT_SPECIAL_REPLY)
#define ipc_port_dealloc_reply(port)    \
	ipc_port_dealloc_special((port), ipc_space_reply)

#endif /* MACH_KERNEL_PRIVATE */

#endif  /* _IPC_IPC_PORT_H_ */
