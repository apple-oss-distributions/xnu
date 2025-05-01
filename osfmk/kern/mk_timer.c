/*
 * Copyright (c) 2000-2020 Apple Computer, Inc. All rights reserved.
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
 * Copyright (c) 2000 Apple Computer, Inc.  All rights reserved.
 *
 * HISTORY
 *
 * 29 June 2000 (debo)
 *  Created.
 */

#include <mach/mach_types.h>
#include <mach/mach_traps.h>
#include <mach/mach_port_server.h>

#include <mach/mk_timer.h>

#include <ipc/port.h>
#include <ipc/ipc_space.h>

#include <kern/lock_group.h>
#include <kern/thread_call.h>
#include <ipc/ipc_kmsg.h>

struct mk_timer {
	decl_simple_lock_data(, lock);
	thread_call_data_t      mkt_thread_call;
	bool                    is_dead;
	bool                    is_armed;
	int                     active;
	ipc_port_t XNU_PTRAUTH_SIGNED_PTR("mk_timer.port") port;
	ipc_kmsg_t XNU_PTRAUTH_SIGNED_PTR("mk_timer.prealloc") prealloc;
};

static ZONE_DEFINE_TYPE(mk_timer_zone, "mk_timer",
    struct mk_timer, ZC_ZFREE_CLEARMEM);

static void mk_timer_port_destroy(ipc_port_t);
static void mk_timer_expire(void *p0, void *p1);

IPC_KOBJECT_DEFINE(IKOT_TIMER,
    .iko_op_destroy = mk_timer_port_destroy);

mach_port_name_t
mk_timer_create_trap(
	__unused struct mk_timer_create_trap_args *args)
{
	struct mk_timer*      timer;
	ipc_space_t           myspace = current_space();
	mach_port_name_t      name = MACH_PORT_NULL;
	ipc_port_init_flags_t init_flags;
	ipc_port_t            port;
	kern_return_t         result;
	ipc_kmsg_t            kmsg;

	/* Allocate and initialize local state of a timer object */
	timer = zalloc_flags(mk_timer_zone, Z_ZERO | Z_WAITOK | Z_NOFAIL);
	simple_lock_init(&timer->lock, 0);
	thread_call_setup(&timer->mkt_thread_call, mk_timer_expire, timer);

	/* Pre-allocate a kmsg for the timer messages */
	kmsg = ipc_kmsg_alloc(sizeof(mk_timer_expire_msg_t), 0, 0,
	    IPC_KMSG_ALLOC_KERNEL | IPC_KMSG_ALLOC_ZERO |
	    IPC_KMSG_ALLOC_ALL_INLINE | IPC_KMSG_ALLOC_NOFAIL |
	    IPC_KMSG_ALLOC_USE_KEEP_ALIVE);
	init_flags = IPC_PORT_INIT_MESSAGE_QUEUE;
	result = ipc_port_alloc(myspace, init_flags, &name, &port);
	if (result != KERN_SUCCESS) {
		zfree(mk_timer_zone, timer);
		ipc_kmsg_keep_alive_abandon(kmsg);
		return MACH_PORT_NULL;
	}

	/* port locked, receive right at user-space */
	port->ip_immovable_receive = true;
	ipc_kobject_upgrade_mktimer_locked(port, (ipc_kobject_t)timer);

	/* make a (naked) send right for the timer to keep */
	timer->port = ipc_port_make_send_any_locked(port);

	/* Associate the pre-allocated kmsg with the port */
	timer->prealloc = kmsg;

	ip_mq_unlock(port);

	return name;
}

static void
mk_timer_unlock_and_destroy(struct mk_timer *timer, ipc_port_t port)
{
	ipc_kmsg_t kmsg = timer->prealloc;

	simple_unlock(&timer->lock);

	zfree(mk_timer_zone, timer);
	ipc_kmsg_keep_alive_abandon(kmsg);
	ipc_port_release_send(port);
}

static void
mk_timer_port_destroy(
	ipc_port_t                      port)
{
	struct mk_timer *timer = NULL;

	timer = ipc_kobject_disable(port, IKOT_TIMER);

	simple_lock(&timer->lock, LCK_GRP_NULL);

	if (thread_call_cancel(&timer->mkt_thread_call)) {
		timer->active--;
	}
	timer->is_armed = false;

	timer->is_dead = true;
	if (timer->active == 0) {
		mk_timer_unlock_and_destroy(timer, port);
	} else {
		simple_unlock(&timer->lock);
	}
}

static void
mk_timer_expire(
	void                    *p0,
	__unused void           *p1)
{
	struct mk_timer *timer = p0;
	ipc_kmsg_t kmsg;
	ipc_port_t port;

	simple_lock(&timer->lock, LCK_GRP_NULL);

	port = timer->port;
	kmsg = timer->prealloc;
	assert(port != IP_NULL);
	assert(timer->active > 0);

	while (timer->is_armed && timer->active == 1) {
		timer->is_armed = false;
		simple_unlock(&timer->lock);

		if (ipc_kmsg_keep_alive_try_reusing(kmsg)) {
			mk_timer_expire_msg_t *msg;

			msg = __container_of(ikm_header(kmsg),
			    mk_timer_expire_msg_t, header);
			bzero(msg, sizeof(mk_timer_expire_msg_t));
			msg->header.msgh_bits =
			    MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND, 0, 0, 0);
			msg->header.msgh_size = sizeof(mk_timer_expire_msg_t);
			msg->header.msgh_remote_port = port;

			kernel_mach_msg_send_kmsg(kmsg);
		}

		simple_lock(&timer->lock, LCK_GRP_NULL);
	}

	timer->active -= 1;

	if (timer->active == 0 && timer->is_dead) {
		mk_timer_unlock_and_destroy(timer, port);
	} else {
		simple_unlock(&timer->lock);
	}
}

/*
 * mk_timer_destroy_trap: Destroy the Mach port associated with a timer
 *
 * Parameters:  args                     User argument descriptor (see below)
 *
 * Indirect:     args->name               Mach port name
 *
 *
 * Returns:        0                      Success
 *                !0                      Not success
 *
 */
kern_return_t
mk_timer_destroy_trap(
	struct mk_timer_destroy_trap_args *args)
{
	mach_port_name_t        name = args->name;
	ipc_space_t             myspace = current_space();
	kern_return_t           kr;
	ipc_entry_t             entry;

	kr = ipc_right_lookup_write(myspace, name, &entry);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	/* space is write-locked and active */

	if ((IE_BITS_TYPE(entry->ie_bits) & MACH_PORT_TYPE_RECEIVE) == 0) {
		is_write_unlock(myspace);
		return KERN_INVALID_RIGHT;
	}

	if (ip_kotype(entry->ie_port) != IKOT_TIMER) {
		is_write_unlock(myspace);
		return KERN_INVALID_ARGUMENT;
	}

	/*
	 * This should have been a mach_mod_refs(RR, -1) but unfortunately,
	 * the fact this is a mach_port_destroy() is ABI now.
	 */
	return ipc_right_destroy(myspace, name, entry, TRUE, 0); /* unlocks space */
}

/*
 * mk_timer_arm_trap: Start (arm) a timer
 *
 * Parameters:  args                     User argument descriptor (see below)
 *
 * Indirect:     args->name               Mach port name
 *               args->expire_time        Time when timer expires
 *
 *
 * Returns:        0                      Success
 *                !0                      Not success
 *
 */

static kern_return_t
mk_timer_arm_trap_internal(mach_port_name_t name, uint64_t expire_time, uint64_t mk_leeway, uint64_t mk_timer_flags)
{
	struct mk_timer*                timer;
	ipc_space_t                     myspace = current_space();
	ipc_port_t                      port;
	kern_return_t                   result;

	result = ipc_port_translate_receive(myspace, name, &port);
	if (result != KERN_SUCCESS) {
		return result;
	}

	timer = ipc_kobject_get_locked(port, IKOT_TIMER);

	if (timer) {

		simple_lock(&timer->lock, LCK_GRP_NULL);
		assert(timer->port == port);
		ip_mq_unlock(port);

		if (!timer->is_dead) {
			timer->is_armed = true;

			if (expire_time > mach_absolute_time()) {
				uint32_t tcflags = THREAD_CALL_DELAY_USER_NORMAL;

				if (mk_timer_flags & MK_TIMER_CRITICAL) {
					tcflags = THREAD_CALL_DELAY_USER_CRITICAL;
				}

				if (mk_leeway != 0) {
					tcflags |= THREAD_CALL_DELAY_LEEWAY;
				}

				if (!thread_call_enter_delayed_with_leeway(
					    &timer->mkt_thread_call, NULL,
					    expire_time, mk_leeway, tcflags)) {
					timer->active++;
				}
			} else {
				if (!thread_call_enter1(&timer->mkt_thread_call, NULL)) {
					timer->active++;
				}
			}
		}

		simple_unlock(&timer->lock);
	} else {
		ip_mq_unlock(port);
		result = KERN_INVALID_ARGUMENT;
	}
	return result;
}

kern_return_t
mk_timer_arm_trap(struct mk_timer_arm_trap_args *args)
{
	return mk_timer_arm_trap_internal(args->name, args->expire_time, 0, MK_TIMER_NORMAL);
}

kern_return_t
mk_timer_arm_leeway_trap(struct mk_timer_arm_leeway_trap_args *args)
{
	return mk_timer_arm_trap_internal(args->name, args->expire_time, args->mk_leeway, args->mk_timer_flags);
}

/*
 * mk_timer_cancel_trap: Cancel a timer
 *
 * Parameters:  args                     User argument descriptor (see below)
 *
 * Indirect:     args->name               Mach port name
 *               args->result_time        The armed time of the cancelled timer (return value)
 *
 *
 * Returns:        0                      Success
 *                !0                      Not success
 *
 */
kern_return_t
mk_timer_cancel_trap(
	struct mk_timer_cancel_trap_args *args)
{
	mach_port_name_t        name = args->name;
	mach_vm_address_t       result_time_addr = args->result_time;
	uint64_t                        armed_time = 0;
	struct mk_timer*                timer;
	ipc_space_t                     myspace = current_space();
	ipc_port_t                      port;
	kern_return_t           result;

	result = ipc_port_translate_receive(myspace, name, &port);
	if (result != KERN_SUCCESS) {
		return result;
	}

	timer = ipc_kobject_get_locked(port, IKOT_TIMER);
	if (timer != NULL) {
		simple_lock(&timer->lock, LCK_GRP_NULL);
		assert(timer->port == port);
		ip_mq_unlock(port);

		if (timer->is_armed) {
			armed_time = thread_call_get_armed_deadline(&timer->mkt_thread_call);
			if (thread_call_cancel(&timer->mkt_thread_call)) {
				timer->active--;
			}
			timer->is_armed = false;
		}

		simple_unlock(&timer->lock);
	} else {
		ip_mq_unlock(port);
		result = KERN_INVALID_ARGUMENT;
	}

	if (result == KERN_SUCCESS && result_time_addr != 0) {
		if (copyout((void *)&armed_time, result_time_addr, sizeof(armed_time)) != 0) {
			result = KERN_FAILURE;
		}
	}

	return result;
}
