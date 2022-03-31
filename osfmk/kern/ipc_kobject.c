/*
 * Copyright (c) 2000-2020 Apple Inc. All rights reserved.
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
 *	File:	kern/ipc_kobject.c
 *	Author:	Rich Draves
 *	Date:	1989
 *
 *	Functions for letting a port represent a kernel object.
 */

#include <mach_debug.h>
#include <mach_ipc_test.h>
#include <mach/mig.h>
#include <mach/port.h>
#include <mach/kern_return.h>
#include <mach/message.h>
#include <mach/mig_errors.h>
#include <mach/mach_notify.h>
#include <mach/ndr.h>
#include <mach/vm_param.h>

#include <mach/mach_vm_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_host_server.h>
#include <mach/host_priv_server.h>
#include <mach/clock_server.h>
#include <mach/clock_priv_server.h>
#include <mach/memory_entry_server.h>
#include <mach/memory_object_control_server.h>
#include <mach/memory_object_default_server.h>
#include <mach/processor_server.h>
#include <mach/processor_set_server.h>
#include <mach/task_server.h>
#include <mach/mach_voucher_server.h>
#include <mach/mach_voucher_attr_control_server.h>
#ifdef VM32_SUPPORT
#include <mach/vm32_map_server.h>
#endif
#include <mach/thread_act_server.h>
#include <mach/restartable_server.h>

#include <mach/exc_server.h>
#include <mach/mach_exc_server.h>
#include <mach/mach_eventlink_server.h>

#include <device/device_types.h>
#include <device/device_server.h>

#if     CONFIG_USER_NOTIFICATION
#include <UserNotification/UNDReplyServer.h>
#endif

#if     CONFIG_ARCADE
#include <mach/arcade_register_server.h>
#endif

#if     CONFIG_AUDIT
#include <kern/audit_sessionport.h>
#endif

#if     MACH_MACHINE_ROUTINES
#include <machine/machine_routines.h>
#endif  /* MACH_MACHINE_ROUTINES */
#if     XK_PROXY
#include <uk_xkern/xk_uproxy_server.h>
#endif  /* XK_PROXY */

#include <kern/counter.h>
#include <kern/ipc_tt.h>
#include <kern/ipc_mig.h>
#include <kern/ipc_misc.h>
#include <kern/ipc_kobject.h>
#include <kern/host_notify.h>
#include <kern/misc_protos.h>

#if CONFIG_ARCADE
#include <kern/arcade.h>
#endif /* CONFIG_ARCADE */

#include <ipc/ipc_kmsg.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_voucher.h>
#include <kern/sync_sema.h>
#include <kern/work_interval.h>
#include <kern/task_ident.h>

#if HYPERVISOR
#include <kern/hv_support.h>
#endif

#include <vm/vm_protos.h>

#include <security/mac_mach_internal.h>

extern char *proc_name_address(void *p);
struct proc;
extern int proc_pid(struct proc *p);

typedef struct {
	mach_msg_id_t num;
	mig_routine_t routine;
	int size;
	int kobjidx;
} mig_hash_t;

static void ipc_kobject_subst_once_no_senders(ipc_port_t, mach_msg_type_number_t);

IPC_KOBJECT_DEFINE(IKOT_MEMORY_OBJECT);   /* vestigial, no real instance */
IPC_KOBJECT_DEFINE(IKOT_MEM_OBJ_CONTROL); /* vestigial, no real instance */
IPC_KOBJECT_DEFINE(IKOT_PORT_SUBST_ONCE,
    .iko_op_no_senders = ipc_kobject_subst_once_no_senders);

#define MAX_MIG_ENTRIES 1031
#define MIG_HASH(x) (x)

#define KOBJ_IDX_NOT_SET (-1)

#ifndef max
#define max(a, b)        (((a) > (b)) ? (a) : (b))
#endif /* max */

static SECURITY_READ_ONLY_LATE(mig_hash_t) mig_buckets[MAX_MIG_ENTRIES];
static SECURITY_READ_ONLY_LATE(int) mig_table_max_displ;
SECURITY_READ_ONLY_LATE(int) mach_kobj_count; /* count of total number of kobjects */

ZONE_DEFINE_TYPE(ipc_kobject_label_zone, "ipc kobject labels",
    struct ipc_kobject_label, ZC_ZFREE_CLEARMEM);

__startup_data
static const struct mig_subsystem *mig_e[] = {
	(const struct mig_subsystem *)&mach_vm_subsystem,
	(const struct mig_subsystem *)&mach_port_subsystem,
	(const struct mig_subsystem *)&mach_host_subsystem,
	(const struct mig_subsystem *)&host_priv_subsystem,
	(const struct mig_subsystem *)&clock_subsystem,
	(const struct mig_subsystem *)&clock_priv_subsystem,
	(const struct mig_subsystem *)&processor_subsystem,
	(const struct mig_subsystem *)&processor_set_subsystem,
	(const struct mig_subsystem *)&is_iokit_subsystem,
	(const struct mig_subsystem *)&task_subsystem,
	(const struct mig_subsystem *)&thread_act_subsystem,
#ifdef VM32_SUPPORT
	(const struct mig_subsystem *)&vm32_map_subsystem,
#endif
#if CONFIG_USER_NOTIFICATION
	(const struct mig_subsystem *)&UNDReply_subsystem,
#endif
	(const struct mig_subsystem *)&mach_voucher_subsystem,
	(const struct mig_subsystem *)&mach_voucher_attr_control_subsystem,
	(const struct mig_subsystem *)&memory_entry_subsystem,
	(const struct mig_subsystem *)&task_restartable_subsystem,

#if     XK_PROXY
	(const struct mig_subsystem *)&do_uproxy_xk_uproxy_subsystem,
#endif /* XK_PROXY */
#if     MACH_MACHINE_ROUTINES
	(const struct mig_subsystem *)&MACHINE_SUBSYSTEM,
#endif  /* MACH_MACHINE_ROUTINES */
#if     MCMSG && iPSC860
	(const struct mig_subsystem *)&mcmsg_info_subsystem,
#endif  /* MCMSG && iPSC860 */
	(const struct mig_subsystem *)&catch_exc_subsystem,
	(const struct mig_subsystem *)&catch_mach_exc_subsystem,
#if CONFIG_ARCADE
	(const struct mig_subsystem *)&arcade_register_subsystem,
#endif
	(const struct mig_subsystem *)&mach_eventlink_subsystem,
};

static struct ipc_kobject_ops __security_const_late
    ipc_kobject_ops_array[IKOT_MAX_TYPE];

void
ipc_kobject_register_startup(ipc_kobject_ops_t ops)
{
	if (ipc_kobject_ops_array[ops->iko_op_type].iko_op_type) {
		panic("trying to register kobject(%d) twice", ops->iko_op_type);
	}
	if (ops->iko_op_allow_upgrade && ops->iko_op_no_senders) {
		panic("Cant receive notifications when upgradable");
	}
	ipc_kobject_ops_array[ops->iko_op_type] = *ops;
}

static ipc_kobject_ops_t
ipc_kobject_ops_get(ipc_kobject_type_t ikot)
{
	if (ikot < IKOT_NONE || ikot >= IKOT_MAX_TYPE) {
		panic("invalid kobject type %d", ikot);
	}
	return &ipc_kobject_ops_array[ikot];
}

static void
mig_init(void)
{
	unsigned int i, n = sizeof(mig_e) / sizeof(const struct mig_subsystem *);
	int howmany;
	mach_msg_id_t j, pos, nentry, range;

	for (i = 0; i < n; i++) {
		range = mig_e[i]->end - mig_e[i]->start;
		if (!mig_e[i]->start || range < 0) {
			panic("the msgh_ids in mig_e[] aren't valid!");
		}

		if (mig_e[i]->maxsize > KALLOC_SAFE_ALLOC_SIZE - MAX_TRAILER_SIZE) {
			panic("mig subsystem %d (%p) replies are too large (%d > %d)",
			    mig_e[i]->start, mig_e[i], mig_e[i]->maxsize,
			    KALLOC_SAFE_ALLOC_SIZE - MAX_TRAILER_SIZE);
		}

		for (j = 0; j < range; j++) {
			if (mig_e[i]->routine[j].stub_routine) {
				/* Only put real entries in the table */
				nentry = j + mig_e[i]->start;
				for (pos = MIG_HASH(nentry) % MAX_MIG_ENTRIES, howmany = 1;
				    mig_buckets[pos].num;
				    pos++, pos = pos % MAX_MIG_ENTRIES, howmany++) {
					if (mig_buckets[pos].num == nentry) {
						printf("message id = %d\n", nentry);
						panic("multiple entries with the same msgh_id");
					}
					if (howmany == MAX_MIG_ENTRIES) {
						panic("the mig dispatch table is too small");
					}
				}

				mig_buckets[pos].num = nentry;
				mig_buckets[pos].routine = mig_e[i]->routine[j].stub_routine;
				if (mig_e[i]->routine[j].max_reply_msg) {
					mig_buckets[pos].size = mig_e[i]->routine[j].max_reply_msg;
				} else {
					mig_buckets[pos].size = mig_e[i]->maxsize;
				}

				mig_buckets[pos].kobjidx = KOBJ_IDX_NOT_SET;

				mig_table_max_displ = max(howmany, mig_table_max_displ);
				mach_kobj_count++;
			}
		}
	}

	/* 77417305: pad to allow for MIG routines removals/cleanups */
	mach_kobj_count += 32;

	printf("mig_table_max_displ = %d mach_kobj_count = %d\n",
	    mig_table_max_displ, mach_kobj_count);
}
STARTUP(MACH_IPC, STARTUP_RANK_FIRST, mig_init);

/*
 * Do a hash table lookup for given msgh_id. Return 0
 * if not found.
 */
static mig_hash_t *
find_mig_hash_entry(int msgh_id)
{
	unsigned int i = (unsigned int)MIG_HASH(msgh_id);
	int max_iter = mig_table_max_displ;
	mig_hash_t *ptr;

	do {
		ptr = &mig_buckets[i++ % MAX_MIG_ENTRIES];
	} while (msgh_id != ptr->num && ptr->num && --max_iter);

	if (!ptr->routine || msgh_id != ptr->num) {
		ptr = (mig_hash_t *)0;
	}

	return ptr;
}

static kern_return_t
ipc_kobject_reply_status(ipc_kmsg_t kmsg)
{
	if (kmsg->ikm_header->msgh_bits & MACH_MSGH_BITS_COMPLEX) {
		return KERN_SUCCESS;
	}

	return ((mig_reply_error_t *)kmsg->ikm_header)->RetCode;
}

/*
 *      Routine:	ipc_kobject_set_kobjidx
 *      Purpose:
 *              Set the index for the kobject filter
 *              mask for a given message ID.
 */
kern_return_t
ipc_kobject_set_kobjidx(
	int       msgh_id,
	int       index)
{
	mig_hash_t *ptr = find_mig_hash_entry(msgh_id);

	if (ptr == (mig_hash_t *)0) {
		return KERN_INVALID_ARGUMENT;
	}

	assert(index < mach_kobj_count);
	ptr->kobjidx = index;

	return KERN_SUCCESS;
}

static void
ipc_kobject_init_reply(
	ipc_kmsg_t          reply,
	const ipc_kmsg_t    request,
	kern_return_t       kr)
{
#define InP     ((mach_msg_header_t *) request->ikm_header)
#define OutP    ((mig_reply_error_t *) reply->ikm_header)

	OutP->NDR = NDR_record;
	OutP->Head.msgh_size = sizeof(mig_reply_error_t);

	OutP->Head.msgh_bits =
	    MACH_MSGH_BITS_SET(MACH_MSGH_BITS_LOCAL(InP->msgh_bits), 0, 0, 0);
	OutP->Head.msgh_remote_port = InP->msgh_local_port;
	OutP->Head.msgh_local_port = MACH_PORT_NULL;
	OutP->Head.msgh_voucher_port = MACH_PORT_NULL;
	OutP->Head.msgh_id = InP->msgh_id + 100;

	OutP->RetCode = kr;
#undef  InP
#undef  OutP
}

/*
 *	Routine:	ipc_kobject_server_internal
 *	Purpose:
 *		Handle a message sent to the kernel.
 *		Generates a reply message.
 *		Version for Untyped IPC.
 *	Conditions:
 *		Nothing locked.
 */
static kern_return_t
ipc_kobject_server_internal(
	ipc_port_t      port,
	ipc_kmsg_t      request,
	ipc_kmsg_t      *replyp)
{
	const int request_msgh_id = request->ikm_header->msgh_id;
	ipc_kmsg_t reply = IKM_NULL;
	mach_msg_size_t reply_size;
	bool exec_token_changed = false;
	mig_hash_t *ptr;

	/* Find corresponding mig_hash entry, if any */
	ptr = find_mig_hash_entry(request_msgh_id);

	/* Get the reply_size. */
	if (ptr == (mig_hash_t *)0) {
		reply_size = sizeof(mig_reply_error_t);
	} else {
		reply_size = ptr->size;
	}

	/*
	 * MIG should really assure no data leakage -
	 * but until it does, pessimistically zero the
	 * whole reply buffer.
	 */
	reply = ipc_kmsg_alloc(reply_size, 0,
	    IPC_KMSG_ALLOC_KERNEL | IPC_KMSG_ALLOC_ZERO | IPC_KMSG_ALLOC_NOFAIL);

	ipc_kobject_init_reply(reply, request, KERN_SUCCESS);

	/*
	 * Find the routine to call, and call it
	 * to perform the kernel function
	 */
	if (ptr) {
		thread_ro_t tro = current_thread_ro();
		task_t curtask = tro->tro_task;
		struct proc *curproc = tro->tro_proc;
		task_t task = TASK_NULL;
		uint32_t exec_token;

		/*
		 * Check if the port is a task port, if its a task port then
		 * snapshot the task exec token before the mig routine call.
		 */
		if (ip_kotype(port) == IKOT_TASK_CONTROL && port != curtask->itk_self) {
			task = convert_port_to_task_with_exec_token(port, &exec_token);
		}

#if CONFIG_MACF
		int idx = ptr->kobjidx;
		uint8_t *filter_mask = task_get_mach_kobj_filter_mask(curtask);

		/* Check kobject mig filter mask, if exists. */
		if (filter_mask != NULL &&
		    idx != KOBJ_IDX_NOT_SET &&
		    !bitstr_test(filter_mask, idx) &&
		    mac_task_kobj_msg_evaluate != NULL) {
			/* Not in filter mask, evaluate policy. */
			kern_return_t kr = mac_task_kobj_msg_evaluate(curproc,
			    request_msgh_id, idx);
			if (kr != KERN_SUCCESS) {
				((mig_reply_error_t *) reply->ikm_header)->RetCode = kr;
				goto skip_kobjcall;
			}
		}
#endif /* CONFIG_MACF */

		(*ptr->routine)(request->ikm_header, reply->ikm_header);

#if CONFIG_MACF
skip_kobjcall:
#endif

		/* Check if the exec token changed during the mig routine */
		if (task != TASK_NULL) {
			if (exec_token != task->exec_token) {
				exec_token_changed = true;
			}
			task_deallocate(task);
		}

		counter_inc(&kernel_task->messages_received);
	} else {
#if DEVELOPMENT || DEBUG
		printf("ipc_kobject_server: bogus kernel message, id=%d\n",
		    request->ikm_header->msgh_id);
#endif  /* DEVELOPMENT || DEBUG */
		_MIG_MSGID_INVALID(request->ikm_header->msgh_id);

		((mig_reply_error_t *)reply->ikm_header)->RetCode = MIG_BAD_ID;
	}

	/* Fail the MIG call if the task exec token changed during the call */
	if (exec_token_changed && ipc_kobject_reply_status(reply) == KERN_SUCCESS) {
		/*
		 *	Create a new reply msg with error and destroy the old reply msg.
		 */
		ipc_kmsg_t new_reply = ipc_kmsg_alloc(reply_size, 0,
		    IPC_KMSG_ALLOC_KERNEL | IPC_KMSG_ALLOC_ZERO |
		    IPC_KMSG_ALLOC_NOFAIL);

		/*
		 *	Initialize the new reply message.
		 */
		{
#define OutP_new        ((mig_reply_error_t *) new_reply->ikm_header)
#define OutP_old        ((mig_reply_error_t *) reply->ikm_header)

			OutP_new->NDR = OutP_old->NDR;
			OutP_new->Head.msgh_size = sizeof(mig_reply_error_t);
			OutP_new->Head.msgh_bits = OutP_old->Head.msgh_bits & ~MACH_MSGH_BITS_COMPLEX;
			OutP_new->Head.msgh_remote_port = OutP_old->Head.msgh_remote_port;
			OutP_new->Head.msgh_local_port = MACH_PORT_NULL;
			OutP_new->Head.msgh_voucher_port = MACH_PORT_NULL;
			OutP_new->Head.msgh_id = OutP_old->Head.msgh_id;

			/* Set the error as KERN_INVALID_TASK */
			OutP_new->RetCode = KERN_INVALID_TASK;

#undef  OutP_new
#undef  OutP_old
		}

		/*
		 *	Destroy everything in reply except the reply port right,
		 *	which is needed in the new reply message.
		 */
		reply->ikm_header->msgh_remote_port = MACH_PORT_NULL;
		ipc_kmsg_destroy(reply);
		reply = new_reply;
	} else if (ipc_kobject_reply_status(reply) == MIG_NO_REPLY) {
		/*
		 *	The server function will send a reply message
		 *	using the reply port right, which it has saved.
		 */
		ipc_kmsg_free(reply);
		reply = IKM_NULL;
	}

	*replyp = reply;
	return KERN_SUCCESS;
}


/*
 *	Routine:	ipc_kobject_server
 *	Purpose:
 *		Handle a message sent to the kernel.
 *		Generates a reply message.
 *		Version for Untyped IPC.
 *
 *		Ownership of the incoming rights (from the request)
 *		are transferred on success (wether a reply is made or not).
 *
 *	Conditions:
 *		Nothing locked.
 */
ipc_kmsg_t
ipc_kobject_server(
	ipc_port_t          port,
	ipc_kmsg_t          request,
	mach_msg_option_t   option __unused)
{
#if DEVELOPMENT || DEBUG
	const int request_msgh_id = request->ikm_header->msgh_id;
#endif
	ipc_port_t request_voucher_port;
	ipc_kmsg_t reply = IKM_NULL;
	kern_return_t kr;

	ipc_kmsg_trace_send(request, option);

	if (ip_kotype(port) == IKOT_UEXT_OBJECT) {
		kr = uext_server(port, request, &reply);
	} else {
		kr = ipc_kobject_server_internal(port, request, &reply);
	}

	if (kr != KERN_SUCCESS) {
		assert(kr != MACH_SEND_TIMED_OUT &&
		    kr != MACH_SEND_INTERRUPTED &&
		    kr != MACH_SEND_INVALID_DEST);
		assert(reply == IKM_NULL);

		/* convert the server error into a MIG error */
		reply = ipc_kmsg_alloc(sizeof(mig_reply_error_t), 0,
		    IPC_KMSG_ALLOC_KERNEL | IPC_KMSG_ALLOC_ZERO);
		ipc_kobject_init_reply(reply, request, kr);
	}

	counter_inc(&kernel_task->messages_sent);
	/*
	 *	Destroy destination. The following code differs from
	 *	ipc_object_destroy in that we release the send-once
	 *	right instead of generating a send-once notification
	 *	(which would bring us here again, creating a loop).
	 *	It also differs in that we only expect send or
	 *	send-once rights, never receive rights.
	 *
	 *	We set msgh_remote_port to IP_NULL so that the kmsg
	 *	destroy routines don't try to destroy the port twice.
	 */
	switch (MACH_MSGH_BITS_REMOTE(request->ikm_header->msgh_bits)) {
	case MACH_MSG_TYPE_PORT_SEND:
		ipc_port_release_send(request->ikm_header->msgh_remote_port);
		request->ikm_header->msgh_remote_port = IP_NULL;
		break;

	case MACH_MSG_TYPE_PORT_SEND_ONCE:
		ipc_port_release_sonce(request->ikm_header->msgh_remote_port);
		request->ikm_header->msgh_remote_port = IP_NULL;
		break;

	default:
		panic("ipc_kobject_server: strange destination rights");
	}

	/*
	 *	Destroy voucher.  The kernel MIG servers never take ownership
	 *	of vouchers sent in messages.  Swallow any such rights here.
	 */
	request_voucher_port = ipc_kmsg_get_voucher_port(request);
	if (IP_VALID(request_voucher_port)) {
		assert(MACH_MSG_TYPE_PORT_SEND ==
		    MACH_MSGH_BITS_VOUCHER(request->ikm_header->msgh_bits));
		ipc_port_release_send(request_voucher_port);
		ipc_kmsg_clear_voucher_port(request);
	}

	if (reply == IKM_NULL ||
	    ipc_kobject_reply_status(reply) == KERN_SUCCESS) {
		/*
		 *	The server function is responsible for the contents
		 *	of the message.  The reply port right is moved
		 *	to the reply message, and we have deallocated
		 *	the destination port right, so we just need
		 *	to free the kmsg.
		 */
		ipc_kmsg_free(request);
	} else {
		/*
		 *	The message contents of the request are intact.
		 *	Destroy everthing except the reply port right,
		 *	which is needed in the reply message.
		 */
		request->ikm_header->msgh_local_port = MACH_PORT_NULL;
		ipc_kmsg_destroy(request);
	}

	if (reply != IKM_NULL) {
		ipc_port_t reply_port = reply->ikm_header->msgh_remote_port;

		if (!IP_VALID(reply_port)) {
			/*
			 *	Can't queue the reply message if the destination
			 *	(the reply port) isn't valid.
			 */

			ipc_kmsg_destroy(reply);
			reply = IKM_NULL;
		} else if (ip_in_space_noauth(reply_port, ipc_space_kernel)) {
			/* do not lock reply port, use raw pointer comparison */

			/*
			 *	Don't send replies to kobject kernel ports.
			 */
#if DEVELOPMENT || DEBUG
			printf("%s: refusing to send reply to kobject %d port (id:%d)\n",
			    __func__, ip_kotype(reply_port), request_msgh_id);
#endif  /* DEVELOPMENT || DEBUG */
			ipc_kmsg_destroy(reply);
			reply = IKM_NULL;
		}
	}

	return reply;
}

static __header_always_inline void
ipc_kobject_set_raw(
	ipc_port_t          port,
	ipc_kobject_t       kobject,
	ipc_kobject_type_t  type)
{
	uintptr_t *store = &port->ip_kobject;

#if __has_feature(ptrauth_calls)
	if (kobject) {
		type ^= OS_PTRAUTH_DISCRIMINATOR("ipc_port.ip_kobject");
		kobject = ptrauth_sign_unauthenticated(kobject,
		    ptrauth_key_process_independent_data,
		    ptrauth_blend_discriminator(store, type));
	}
#else
	(void)type;
#endif // __has_feature(ptrauth_calls)

	*store = (uintptr_t)kobject;
}

static inline void
ipc_kobject_set_internal(
	ipc_port_t          port,
	ipc_kobject_t       kobject,
	ipc_kobject_type_t  type)
{
	assert(type != IKOT_NONE);
	io_bits_or(ip_to_object(port), type | IO_BITS_KOBJECT);
	ipc_kobject_set_raw(port, kobject, type);
}

/*
 *	Routine:	ipc_kobject_get_raw
 *	Purpose:
 *		Returns the kobject pointer of a specified port.
 *
 *		This returns the current value of the kobject pointer,
 *		without any validation (the caller is expected to do
 *		the validation it needs).
 *
 *	Conditions:
 *		The port is a kobject of the proper type.
 */
__header_always_inline ipc_kobject_t
ipc_kobject_get_raw(
	ipc_port_t                  port,
	ipc_kobject_type_t          type)
{
	uintptr_t *store = &port->ip_kobject;
	ipc_kobject_t kobject = (ipc_kobject_t)*store;

#if __has_feature(ptrauth_calls)
	if (kobject) {
		type ^= OS_PTRAUTH_DISCRIMINATOR("ipc_port.ip_kobject");
		kobject = ptrauth_auth_data(kobject,
		    ptrauth_key_process_independent_data,
		    ptrauth_blend_discriminator(store, type));
	}
#else
	(void)type;
#endif // __has_feature(ptrauth_calls)

	return kobject;
}

/*
 *	Routine:	ipc_kobject_get_locked
 *	Purpose:
 *		Returns the kobject pointer of a specified port,
 *		for an expected type.
 *
 *		Returns IKO_NULL if the port isn't active.
 *
 *		This function may be used when:
 *		- the port lock is held
 *		- the kobject association stays while there
 *		  are any outstanding rights.
 *
 *	Conditions:
 *		The port is a kobject of the proper type.
 */
ipc_kobject_t
ipc_kobject_get_locked(
	ipc_port_t                  port,
	ipc_kobject_type_t          type)
{
	ipc_kobject_t kobject = IKO_NULL;

	if (ip_active(port) && type == ip_kotype(port)) {
		kobject = ipc_kobject_get_raw(port, type);
	}

	return kobject;
}

/*
 *	Routine:	ipc_kobject_get_stable
 *	Purpose:
 *		Returns the kobject pointer of a specified port,
 *		for an expected type, for types where the port/kobject
 *		association is permanent.
 *
 *		Returns IKO_NULL if the port isn't active.
 *
 *	Conditions:
 *		The port is a kobject of the proper type.
 */
ipc_kobject_t
ipc_kobject_get_stable(
	ipc_port_t                  port,
	ipc_kobject_type_t          type)
{
	assert(ipc_kobject_ops_get(type)->iko_op_stable);
	return ipc_kobject_get_locked(port, type);
}

/*
 *	Routine:	ipc_kobject_init_port
 *	Purpose:
 *		Initialize a kobject port with the given types and options.
 *
 *		This function never fails.
 */
static inline void
ipc_kobject_init_port(
	ipc_port_t port,
	ipc_kobject_t kobject,
	ipc_kobject_type_t type,
	ipc_kobject_alloc_options_t options)
{
	ipc_kobject_set_internal(port, kobject, type);

	if (options & IPC_KOBJECT_ALLOC_MAKE_SEND) {
		ipc_port_make_send_locked(port);
	}
	if (options & IPC_KOBJECT_ALLOC_NSREQUEST) {
		port->ip_nsrequest = IP_KOBJECT_NSREQUEST_ARMED;
		ip_reference(port);
	}
	if (options & IPC_KOBJECT_ALLOC_NO_GRANT) {
		port->ip_no_grant = 1;
	}
	if (options & IPC_KOBJECT_ALLOC_IMMOVABLE_SEND) {
		port->ip_immovable_send = 1;
	}
	if (options & IPC_KOBJECT_ALLOC_PINNED) {
		port->ip_pinned = 1;
	}
}

/*
 *	Routine:	ipc_kobject_alloc_port
 *	Purpose:
 *		Allocate a kobject port in the kernel space of the specified type.
 *
 *		This function never fails.
 *
 *	Conditions:
 *		No locks held (memory is allocated)
 */
ipc_port_t
ipc_kobject_alloc_port(
	ipc_kobject_t           kobject,
	ipc_kobject_type_t      type,
	ipc_kobject_alloc_options_t     options)
{
	ipc_port_t port;

	port = ipc_port_alloc_special(ipc_space_kernel, IPC_PORT_INIT_NONE);
	if (port == IP_NULL) {
		panic("ipc_kobject_alloc_port(): failed to allocate port");
	}

	ipc_kobject_init_port(port, kobject, type, options);
	return port;
}

/*
 *	Routine:	ipc_kobject_alloc_labeled_port
 *	Purpose:
 *		Allocate a kobject port and associated mandatory access label
 *		in the kernel space of the specified type.
 *
 *		This function never fails.
 *
 *	Conditions:
 *		No locks held (memory is allocated)
 */

ipc_port_t
ipc_kobject_alloc_labeled_port(
	ipc_kobject_t           kobject,
	ipc_kobject_type_t      type,
	ipc_label_t             label,
	ipc_kobject_alloc_options_t     options)
{
	ipc_port_t port;

	port = ipc_kobject_alloc_port(kobject, type, options);

	ipc_port_set_label(port, label);

	return port;
}

static void
ipc_kobject_subst_once_no_senders(
	ipc_port_t          port,
	mach_port_mscount_t mscount)
{
	ipc_port_t ko_port;

	ko_port = ipc_kobject_dealloc_port(port, mscount, IKOT_PORT_SUBST_ONCE);

	if (ko_port) {
		/*
		 * Clean up the right if the wrapper wasn't hollowed out
		 * by ipc_kobject_alloc_subst_once().
		 */
		ipc_port_release_send(ko_port);
	}
}

/*
 *	Routine:	ipc_kobject_alloc_subst_once
 *	Purpose:
 *		Make a port that will be substituted by the kolabel
 *		rules once, preventing the next substitution (of its target)
 *		to happen if any.
 *
 *	Returns:
 *		A port with a send right, that will substitute to its "kobject".
 *
 *	Conditions:
 *		No locks held (memory is allocated).
 *
 *		`target` holds a send-right donated to this function,
 *		consumed in ipc_kobject_subst_once_no_senders().
 */
ipc_port_t
ipc_kobject_alloc_subst_once(
	ipc_port_t          target)
{
	if (!IP_VALID(target)) {
		return target;
	}
	return ipc_kobject_alloc_labeled_port(target,
	           IKOT_PORT_SUBST_ONCE, IPC_LABEL_SUBST_ONCE,
	           IPC_KOBJECT_ALLOC_MAKE_SEND | IPC_KOBJECT_ALLOC_NSREQUEST);
}

/*
 *	Routine:	ipc_kobject_make_send_lazy_alloc_port
 *	Purpose:
 *		Make a send once for a kobject port.
 *
 *		A location owning this port is passed in port_store.
 *		If no port exists, a port is made lazily.
 *
 *		A send right is made for the port, and if this is the first one
 *		(possibly not for the first time), then the no-more-senders
 *		notification is rearmed.
 *
 *		When a notification is armed, the kobject must donate
 *		one of its references to the port. It is expected
 *		the no-more-senders notification will consume this reference.
 *
 *	Returns:
 *		TRUE if a notification was armed
 *		FALSE else
 *
 *	Conditions:
 *		Nothing is locked, memory can be allocated.
 *		The caller must be able to donate a kobject reference to the port.
 */
boolean_t
ipc_kobject_make_send_lazy_alloc_port(
	ipc_port_t              *port_store,
	ipc_kobject_t           kobject,
	ipc_kobject_type_t      type,
	ipc_kobject_alloc_options_t alloc_opts,
	uint64_t                __ptrauth_only ptrauth_discriminator)
{
	ipc_port_t port, previous, __ptrauth_only port_addr;
	kern_return_t kr;

	port = os_atomic_load(port_store, dependency);

#if __has_feature(ptrauth_calls)
	/* If we're on a ptrauth system and this port is signed, authenticate and strip the pointer */
	if ((alloc_opts & IPC_KOBJECT_PTRAUTH_STORE) && IP_VALID(port)) {
		port = ptrauth_auth_data(port,
		    ptrauth_key_process_independent_data,
		    ptrauth_blend_discriminator(port_store, ptrauth_discriminator));
	}
#endif // __has_feature(ptrauth_calls)

	if (!IP_VALID(port)) {
		port = ipc_kobject_alloc_port(kobject, type,
		    IPC_KOBJECT_ALLOC_MAKE_SEND | IPC_KOBJECT_ALLOC_NSREQUEST | alloc_opts);

#if __has_feature(ptrauth_calls)
		if (alloc_opts & IPC_KOBJECT_PTRAUTH_STORE) {
			port_addr = ptrauth_sign_unauthenticated(port,
			    ptrauth_key_process_independent_data,
			    ptrauth_blend_discriminator(port_store, ptrauth_discriminator));
		} else {
			port_addr = port;
		}
#else
		port_addr = port;
#endif // __has_feature(ptrauth_calls)

		if (os_atomic_cmpxchgv(port_store, IP_NULL, port_addr, &previous, release)) {
			return TRUE;
		}

		/*
		 * undo IPC_KOBJECT_ALLOC_MAKE_SEND,
		 * ipc_kobject_dealloc_port will handle
		 * IPC_KOBJECT_ALLOC_NSREQUEST.
		 */
		port->ip_mscount = 0;
		port->ip_srights = 0;
		ip_release_live(port);
		ipc_kobject_dealloc_port(port, 0, type);

		port = previous;
	}

	kr = ipc_kobject_make_send_nsrequest(port);
	assert(kr == KERN_SUCCESS || kr == KERN_ALREADY_WAITING);

	return kr == KERN_SUCCESS;
}

/*
 *	Routine:	ipc_kobject_make_send_lazy_alloc_labeled_port
 *	Purpose:
 *		Make a send once for a kobject port.
 *
 *		A location owning this port is passed in port_store.
 *		If no port exists, a port is made lazily.
 *
 *		A send right is made for the port, and if this is the first one
 *		(possibly not for the first time), then the no-more-senders
 *		notification is rearmed.
 *
 *		When a notification is armed, the kobject must donate
 *		one of its references to the port. It is expected
 *		the no-more-senders notification will consume this reference.
 *
 *	Returns:
 *		TRUE if a notification was armed
 *		FALSE else
 *
 *	Conditions:
 *		Nothing is locked, memory can be allocated.
 *		The caller must be able to donate a kobject reference to the port.
 */
boolean_t
ipc_kobject_make_send_lazy_alloc_labeled_port(
	ipc_port_t              *port_store,
	ipc_kobject_t           kobject,
	ipc_kobject_type_t      type,
	ipc_label_t             label)
{
	ipc_port_t port, previous;
	kern_return_t kr;

	port = os_atomic_load(port_store, dependency);

	if (!IP_VALID(port)) {
		port = ipc_kobject_alloc_labeled_port(kobject, type, label,
		    IPC_KOBJECT_ALLOC_MAKE_SEND | IPC_KOBJECT_ALLOC_NSREQUEST);
		if (os_atomic_cmpxchgv(port_store, IP_NULL, port, &previous, release)) {
			return TRUE;
		}

		/*
		 * undo IPC_KOBJECT_ALLOC_MAKE_SEND,
		 * ipc_kobject_dealloc_port will handle
		 * IPC_KOBJECT_ALLOC_NSREQUEST.
		 */
		port->ip_mscount = 0;
		port->ip_srights = 0;
		ip_release_live(port);
		ipc_kobject_dealloc_port(port, 0, type);

		port = previous;
		assert(ip_is_kolabeled(port));
	}

	kr = ipc_kobject_make_send_nsrequest(port);
	assert(kr == KERN_SUCCESS || kr == KERN_ALREADY_WAITING);

	return kr == KERN_SUCCESS;
}

/*
 *	Routine:	ipc_kobject_nsrequest_locked
 *	Purpose:
 *		Arm the no-senders notification for the given kobject
 *		if it doesn't have one armed yet.
 *
 *	Conditions:
 *		Port is locked and active.
 *
 *	Returns:
 *		KERN_SUCCESS:           the notification was armed
 *		KERN_ALREADY_WAITING:   the notification was already armed
 *		KERN_FAILURE:           the notification would fire immediately
 */
static inline kern_return_t
ipc_kobject_nsrequest_locked(
	ipc_port_t                  port,
	mach_port_mscount_t         sync)
{
	if (port->ip_nsrequest == IP_KOBJECT_NSREQUEST_ARMED) {
		return KERN_ALREADY_WAITING;
	}

	if (port->ip_srights == 0 && sync <= port->ip_mscount) {
		return KERN_FAILURE;
	}

	port->ip_nsrequest = IP_KOBJECT_NSREQUEST_ARMED;
	ip_reference(port);
	return KERN_SUCCESS;
}


/*
 *	Routine:	ipc_kobject_nsrequest
 *	Purpose:
 *		Arm the no-senders notification for the given kobject
 *		if it doesn't have one armed yet.
 *
 *	Returns:
 *		KERN_SUCCESS:           the notification was armed
 *		KERN_ALREADY_WAITING:   the notification was already armed
 *		KERN_FAILURE:           the notification would fire immediately
 *		KERN_INVALID_RIGHT:     the port is dead
 */
kern_return_t
ipc_kobject_nsrequest(
	ipc_port_t                  port,
	mach_port_mscount_t         sync,
	mach_port_mscount_t        *mscount)
{
	kern_return_t kr = KERN_INVALID_RIGHT;

	if (IP_VALID(port)) {
		ip_mq_lock(port);

		if (mscount) {
			*mscount = port->ip_mscount;
		}
		if (ip_active(port)) {
			kr = ipc_kobject_nsrequest_locked(port, sync);
		}

		ip_mq_unlock(port);
	} else if (mscount) {
		*mscount = 0;
	}

	return kr;
}


/*
 *	Routine:	ipc_kobject_make_send_nsrequest
 *	Purpose:
 *		Make a send right for a kobject port.
 *
 *		Then the no-more-senders notification is armed
 *		if it wasn't already.
 *
 *	Conditions:
 *		Nothing is locked.
 *
 *	Returns:
 *		KERN_SUCCESS:           the notification was armed
 *		KERN_ALREADY_WAITING:   the notification was already armed
 *		KERN_INVALID_RIGHT:     the port is dead
 */
kern_return_t
ipc_kobject_make_send_nsrequest(
	ipc_port_t                  port)
{
	kern_return_t kr = KERN_INVALID_RIGHT;

	if (IP_VALID(port)) {
		ip_mq_lock(port);
		if (ip_active(port)) {
			ipc_port_make_send_locked(port);
			kr = ipc_kobject_nsrequest_locked(port, 0);
			assert(kr != KERN_FAILURE);
		}
		ip_mq_unlock(port);
	}

	return kr;
}

static inline ipc_kobject_t
ipc_kobject_disable_internal(
	ipc_port_t              port,
	ipc_kobject_type_t      type)
{
	ipc_kobject_t kobject = ipc_kobject_get_raw(port, type);

	port->ip_kobject = 0;
	if (ip_is_kolabeled(port)) {
		port->ip_kolabel->ikol_alt_port = IP_NULL;
	}

	return kobject;
}

/*
 *	Routine:	ipc_kobject_dealloc_port_and_unlock
 *	Purpose:
 *		Destroys a port allocated with any of the ipc_kobject_alloc*
 *		functions.
 *
 *		This will atomically:
 *		- make the port inactive,
 *		- optionally check the make send count
 *		- disable (nil-out) the kobject pointer for kobjects without
 *		  a destroy callback.
 *
 *		The port will retain its kobject-ness and kobject type.
 *
 *
 *	Returns:
 *		The kobject pointer that was set prior to this call
 *		(possibly NULL if the kobject was already disabled).
 *
 *	Conditions:
 *		The port is active and locked.
 *		On return the port is inactive and unlocked.
 */
__abortlike
static void
__ipc_kobject_dealloc_bad_type_panic(ipc_port_t port, ipc_kobject_type_t type)
{
	panic("port %p of type %d, expecting %d", port, ip_kotype(port), type);
}

__abortlike
static void
__ipc_kobject_dealloc_bad_mscount_panic(
	ipc_port_t                  port,
	mach_port_mscount_t         mscount,
	ipc_kobject_type_t          type)
{
	panic("unexpected make-send count: %p[%d], %d, %d",
	    port, type, port->ip_mscount, mscount);
}

__abortlike
static void
__ipc_kobject_dealloc_bad_srights_panic(
	ipc_port_t                  port,
	ipc_kobject_type_t          type)
{
	panic("unexpected send right count: %p[%d], %d",
	    port, type, port->ip_srights);
}

ipc_kobject_t
ipc_kobject_dealloc_port_and_unlock(
	ipc_port_t                  port,
	mach_port_mscount_t         mscount,
	ipc_kobject_type_t          type)
{
	ipc_kobject_t kobject = IKO_NULL;
	ipc_kobject_ops_t ops = ipc_kobject_ops_get(type);

	require_ip_active(port);

	if (ip_kotype(port) != type) {
		__ipc_kobject_dealloc_bad_type_panic(port, type);
	}

	if (mscount && port->ip_mscount != mscount) {
		__ipc_kobject_dealloc_bad_mscount_panic(port, mscount, type);
	}
	if ((mscount || ops->iko_op_stable) && port->ip_srights != 0) {
		__ipc_kobject_dealloc_bad_srights_panic(port, type);
	}

	if (!ops->iko_op_destroy) {
		kobject = ipc_kobject_disable_internal(port, type);
	}

	ipc_port_dealloc_special_and_unlock(port, ipc_space_kernel);

	return kobject;
}

/*
 *	Routine:	ipc_kobject_dealloc_port
 *	Purpose:
 *		Destroys a port allocated with any of the ipc_kobject_alloc*
 *		functions.
 *
 *		This will atomically:
 *		- make the port inactive,
 *		- optionally check the make send count
 *		- disable (nil-out) the kobject pointer for kobjects without
 *		  a destroy callback.
 *
 *		The port will retain its kobject-ness and kobject type.
 *
 *
 *	Returns:
 *		The kobject pointer that was set prior to this call
 *		(possibly NULL if the kobject was already disabled).
 *
 *	Conditions:
 *		Nothing is locked.
 *		The port is active.
 *		On return the port is inactive.
 */
ipc_kobject_t
ipc_kobject_dealloc_port(
	ipc_port_t                  port,
	mach_port_mscount_t         mscount,
	ipc_kobject_type_t          type)
{
	ip_mq_lock(port);
	return ipc_kobject_dealloc_port_and_unlock(port, mscount, type);
}

/*
 *	Routine:	ipc_kobject_enable
 *	Purpose:
 *		Make a port represent a kernel object of the given type.
 *		The caller is responsible for handling refs for the
 *		kernel object, if necessary.
 *	Conditions:
 *		Nothing locked.
 *		The port must be active.
 */
void
ipc_kobject_enable(
	ipc_port_t              port,
	ipc_kobject_t           kobject,
	ipc_kobject_type_t      type)
{
	assert(!ipc_kobject_ops_get(type)->iko_op_stable);

	ip_mq_lock(port);
	require_ip_active(port);

	if (type != ip_kotype(port)) {
		panic("%s: unexpected kotype of port %p: want %d, got %d",
		    __func__, port, type, ip_kotype(port));
	}

	ipc_kobject_set_raw(port, kobject, type);

	ip_mq_unlock(port);
}

/*
 *	Routine:	ipc_kobject_disable_locked
 *	Purpose:
 *		Clear the kobject pointer for a port.
 *	Conditions:
 *		The port is locked.
 *		Returns the current kobject pointer.
 */
ipc_kobject_t
ipc_kobject_disable_locked(
	ipc_port_t              port,
	ipc_kobject_type_t      type)
{
	if (ip_active(port)) {
		assert(!ipc_kobject_ops_get(type)->iko_op_stable);
	}

	if (ip_kotype(port) != type) {
		panic("port %p of type %d, expecting %d",
		    port, ip_kotype(port), type);
	}

	return ipc_kobject_disable_internal(port, type);
}

/*
 *	Routine:	ipc_kobject_disable
 *	Purpose:
 *		Clear the kobject pointer for a port.
 *	Conditions:
 *		Nothing locked.
 *		Returns the current kobject pointer.
 */
ipc_kobject_t
ipc_kobject_disable(
	ipc_port_t              port,
	ipc_kobject_type_t      type)
{
	ipc_kobject_t kobject;

	ip_mq_lock(port);
	kobject = ipc_kobject_disable_locked(port, type);
	ip_mq_unlock(port);

	return kobject;
}

static inline bool
ipc_kobject_may_upgrade(ipc_port_t port)
{
	if (!ip_active(port) || ip_kotype(port) != IKOT_NONE) {
		/* needs to be active and have no tag */
		return false;
	}

	if (port->ip_tempowner || port->ip_specialreply) {
		/* union overlays with ip_kobject */
		return false;
	}

	if (port->ip_has_watchport || ipc_port_has_prdrequest(port)) {
		/* outstanding watchport or port-destroyed is also disallowed */
		return false;
	}

	return true;
}

/*
 *	Routine:	ipc_kobject_upgrade_locked
 *	Purpose:
 *		Upgrades a port to kobject status
 *		Only kobjects with iko_op_allow_upgrade can do this.
 *	Conditions:
 *		Port is locked
 */
void
ipc_kobject_upgrade_locked(
	ipc_port_t                  port,
	ipc_kobject_t               kobject,
	ipc_kobject_type_t          type)
{
	assert(ipc_kobject_may_upgrade(port));
	assert(ipc_kobject_ops_get(type)->iko_op_allow_upgrade);
	ipc_kobject_set_internal(port, kobject, type);
}

/*
 *	Routine:	ipc_kobject_upgrade
 *	Purpose:
 *		Upgrades a port to kobject status
 *		Only kobjects with iko_op_allow_upgrade can do this.
 *	Returns:
 *		KERN_SUCCESS: the upgrade was possible
 *		KERN_INVALID_CAPABILITY: the upgrade wasn't possible
 *	Conditions:
 *		Nothing is locked
 */
kern_return_t
ipc_kobject_upgrade(
	ipc_port_t              port,
	ipc_kobject_t           kobject,
	ipc_kobject_type_t      type)
{
	kern_return_t kr = KERN_INVALID_CAPABILITY;

	assert(ipc_kobject_ops_get(type)->iko_op_allow_upgrade);

	ip_mq_lock(port);

	if (ipc_kobject_may_upgrade(port)) {
		ipc_kobject_set_internal(port, kobject, type);
		kr = KERN_SUCCESS;
	}

	ip_mq_unlock(port);

	return kr;
}

/*
 *	Routine:	ipc_kobject_downgrade_host_notify
 *	Purpose:
 *		Downgrade a kobject port back to receive right status.
 *		Only IKOT_HOST_NOTIFY should use this facility.
 *
 *		/!\ WARNING /!\
 *
 *		This feature is breaking the kobject abstraction
 *		and is grandfathered in. Accessing io_kotype() without a lock
 *		only works because this is the only such kobject doing
 *		this disgusting dance.
 *
 *	Returns:
 *		The kobject pointer previously set on the object.
 *	Conditions:
 *		Nothing is locked
 *		The port doesn't need to be active
 */
ipc_kobject_t
ipc_kobject_downgrade_host_notify(
	ipc_port_t              port)
{
	ipc_kobject_t kobject = IKO_NULL;

	ip_mq_lock(port);

	if (ip_kotype(port) == IKOT_HOST_NOTIFY) {
		kobject = ipc_kobject_disable_locked(port, IKOT_HOST_NOTIFY);
		io_bits_andnot(ip_to_object(port), IO_BITS_KOTYPE);
	}

	ip_mq_unlock(port);

	return kobject;
}

/*
 *	Routine:	ipc_kobject_notify_no_senders
 *	Purpose:
 *		Handles a no-senders notification
 *		sent to a kobject.
 *
 *		A port reference is consumed.
 *
 *	Conditions:
 *		Nothing locked.
 */
void
ipc_kobject_notify_no_senders(
	ipc_port_t              port,
	mach_port_mscount_t     mscount)
{
	ipc_kobject_ops_t ops = ipc_kobject_ops_get(ip_kotype(port));

	assert(ops->iko_op_no_senders);
	ops->iko_op_no_senders(port, mscount);

	/* consume the ref ipc_notify_no_senders_prepare left */
	ip_release(port);
}

/*
 *	Routine:	ipc_kobject_notify_no_senders
 *	Purpose:
 *		Handles a send once notifications
 *		sent to a kobject.
 *
 *		A send-once port reference is consumed.
 *
 *	Conditions:
 *		Port is locked.
 */
void
ipc_kobject_notify_send_once_and_unlock(
	ipc_port_t              port)
{
	/*
	 * drop the send once right while we hold the port lock.
	 * we will keep a port reference while we run the possible
	 * callouts to kobjects.
	 *
	 * This a simplified version of ipc_port_release_sonce()
	 * since kobjects can't be special reply ports.
	 */
	assert(!port->ip_specialreply);

	if (port->ip_sorights == 0) {
		panic("Over-release of port %p send-once right!", port);
	}

	port->ip_sorights--;
	ip_mq_unlock(port);

	/*
	 * because there's very few consumers,
	 * the code here isn't generic as it's really not worth it.
	 */
	switch (ip_kotype(port)) {
	case IKOT_TASK_RESUME:
		task_suspension_send_once(port);
		break;
	default:
		break;
	}

	ip_release(port);
}


/*
 *	Routine:	ipc_kobject_destroy
 *	Purpose:
 *		Release any kernel object resources associated
 *		with the port, which is being destroyed.
 *
 *		This path to free object resources should only be
 *		needed when resources are associated with a user's port.
 *		In the normal case, when the kernel is the receiver,
 *		the code calling ipc_kobject_dealloc_port() should clean
 *		up the object resources.
 *
 *		Cleans up any kobject label that might be present.
 *	Conditions:
 *		The port is not locked, but it is dead.
 */
void
ipc_kobject_destroy(
	ipc_port_t              port)
{
	ipc_kobject_ops_t ops = ipc_kobject_ops_get(ip_kotype(port));

	if (ops->iko_op_permanent) {
		panic("trying to destroy an permanent port %p", port);
	}
	if (ops->iko_op_destroy) {
		ops->iko_op_destroy(port);
	}

	if (ip_is_kolabeled(port)) {
		ipc_kobject_label_t labelp = port->ip_kolabel;

		assert(labelp != NULL);
		assert(labelp->ikol_alt_port == IP_NULL);
		assert(ip_is_kobject(port));
		port->ip_kolabel = NULL;
		io_bits_andnot(ip_to_object(port), IO_BITS_KOLABEL);
		zfree(ipc_kobject_label_zone, labelp);
	}
}

/*
 *	Routine:	ipc_kobject_label_substitute_task
 *	Purpose:
 *		Substitute a task control port for its immovable
 *		equivalent when the receiver is that task.
 *	Conditions:
 *		Space is write locked and active.
 *		Port is locked and active.
 *	Returns:
 *		- IP_NULL port if no substitution is to be done
 *		- a valid port if a substitution needs to happen
 */
static ipc_port_t
ipc_kobject_label_substitute_task(
	ipc_space_t             space,
	ipc_kobject_label_t     kolabel,
	ipc_port_t              port)
{
	ipc_port_t subst = IP_NULL;
	task_t task = ipc_kobject_get_raw(port, IKOT_TASK_CONTROL);

	if (task != TASK_NULL && task == space->is_task) {
		if ((subst = kolabel->ikol_alt_port)) {
			return subst;
		}
	}

	return IP_NULL;
}

/*
 *	Routine:	ipc_kobject_label_substitute_thread
 *	Purpose:
 *		Substitute a thread control port for its immovable
 *		equivalent when it belongs to the receiver task.
 *	Conditions:
 *		Space is write locked and active.
 *		Port is locked and active.
 *	Returns:
 *		- IP_NULL port if no substitution is to be done
 *		- a valid port if a substitution needs to happen
 */
static ipc_port_t
ipc_kobject_label_substitute_thread(
	ipc_space_t             space,
	ipc_kobject_label_t     kolabel,
	ipc_port_t              port)
{
	ipc_port_t subst = IP_NULL;
	thread_t thread = ipc_kobject_get_raw(port, IKOT_THREAD_CONTROL);

	if (thread != THREAD_NULL && space->is_task == get_threadtask(thread)) {
		if ((subst = kolabel->ikol_alt_port) != IP_NULL) {
			return subst;
		}
	}

	return IP_NULL;
}

/*
 *	Routine:	ipc_kobject_label_check
 *	Purpose:
 *		Check to see if the space is allowed to possess
 *		a right for the given port. In order to qualify,
 *		the space label must contain all the privileges
 *		listed in the port/kobject label.
 *
 *	Conditions:
 *		Space is write locked and active.
 *		Port is locked and active.
 *
 *	Returns:
 *		Whether the copyout is authorized.
 *
 *		If a port substitution is requested, the space is unlocked,
 *		the port is unlocked and its "right" consumed.
 *
 *		As of now, substituted ports only happen for send rights.
 */
bool
ipc_kobject_label_check(
	ipc_space_t                     space,
	ipc_port_t                      port,
	mach_msg_type_name_t            msgt_name,
	ipc_object_copyout_flags_t     *flags,
	ipc_port_t                     *subst_portp)
{
	ipc_kobject_label_t kolabel;
	ipc_label_t label;

	assert(is_active(space));
	assert(ip_active(port));

	*subst_portp = IP_NULL;

	/* Unlabled ports/kobjects are always allowed */
	if (!ip_is_kolabeled(port)) {
		return true;
	}

	/* Never OK to copyout the receive right for a labeled kobject */
	if (msgt_name == MACH_MSG_TYPE_PORT_RECEIVE) {
		panic("ipc_kobject_label_check: attempted receive right "
		    "copyout for labeled kobject");
	}

	kolabel = port->ip_kolabel;
	label = kolabel->ikol_label;

	if ((*flags & IPC_OBJECT_COPYOUT_FLAGS_NO_LABEL_CHECK) == 0 &&
	    (label & IPC_LABEL_SUBST_MASK)) {
		ipc_port_t subst = IP_NULL;

		if (msgt_name != MACH_MSG_TYPE_PORT_SEND) {
			return false;
		}

		if ((label & IPC_LABEL_SUBST_MASK) == IPC_LABEL_SUBST_ONCE) {
			/*
			 * The next check will _not_ substitute.
			 * hollow out our one-time wrapper,
			 * and steal its send right.
			 */
			*flags |= IPC_OBJECT_COPYOUT_FLAGS_NO_LABEL_CHECK;
			subst = ipc_kobject_disable_locked(port,
			    IKOT_PORT_SUBST_ONCE);
			is_write_unlock(space);
			ipc_port_release_send_and_unlock(port);
			if (subst == IP_NULL) {
				panic("subst-once port %p was consumed twice", port);
			}
			*subst_portp = subst;
			return true;
		}

		switch (label & IPC_LABEL_SUBST_MASK) {
		case IPC_LABEL_SUBST_TASK:
			subst = ipc_kobject_label_substitute_task(space,
			    kolabel, port);
			break;
		case IPC_LABEL_SUBST_THREAD:
			subst = ipc_kobject_label_substitute_thread(space,
			    kolabel, port);
			break;
		default:
			panic("unexpected label: %llx", label);
		}

		if (subst != IP_NULL) {
			ip_reference(subst);
			is_write_unlock(space);

			/*
			 * We do not hold a proper send right on `subst`,
			 * only a reference.
			 *
			 * Because of how thread/task termination works,
			 * there is no guarantee copy_send() would work,
			 * so we need to make_send().
			 *
			 * We can do that because ports tagged with
			 * IPC_LABEL_SUBST_{THREAD,TASK} do not use
			 * the no-senders notification.
			 */

			ipc_port_release_send_and_unlock(port);
			port = ipc_port_make_send(subst);
			ip_release(subst);
			*subst_portp = port;
			return true;
		}
	}

	return (label & space->is_label & IPC_LABEL_SPACE_MASK) ==
	       (label & IPC_LABEL_SPACE_MASK);
}
