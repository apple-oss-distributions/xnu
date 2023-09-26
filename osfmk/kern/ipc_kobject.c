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
#include <mach/memory_entry_server.h>
#include <mach/processor_server.h>
#include <mach/processor_set_server.h>
#include <mach/task_server.h>
#include <mach/mach_voucher_server.h>
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

#if CONFIG_CSR
#include <sys/csr.h>
#endif

#include <vm/vm_protos.h>

#include <security/mac_mach_internal.h>

extern char *proc_name_address(void *p);
struct proc;
extern int proc_pid(struct proc *p);

typedef struct {
	mach_msg_id_t num;
	int kobjidx;
	mig_kern_routine_t kroutine;    /* Kernel server routine */
	unsigned int kreply_size;       /* Size of kernel reply msg */
	unsigned int kreply_desc_cnt;   /* Number of descs in kernel reply msg */
} mig_hash_t;

static void ipc_kobject_subst_once_no_senders(ipc_port_t, mach_msg_type_number_t);

IPC_KOBJECT_DEFINE(IKOT_MEMORY_OBJECT);   /* vestigial, no real instance */
IPC_KOBJECT_DEFINE(IKOT_PORT_SUBST_ONCE,
    .iko_op_no_senders = ipc_kobject_subst_once_no_senders);

#define MAX_MIG_ENTRIES 1031
#define MIG_HASH(x) (x)

#define KOBJ_IDX_NOT_SET (-1)

static SECURITY_READ_ONLY_LATE(mig_hash_t) mig_buckets[MAX_MIG_ENTRIES];
static SECURITY_READ_ONLY_LATE(int) mig_table_max_displ;
SECURITY_READ_ONLY_LATE(int) mach_kobj_count; /* count of total number of kobjects */

ZONE_DEFINE_TYPE(ipc_kobject_label_zone, "ipc kobject labels",
    struct ipc_kobject_label, ZC_ZFREE_CLEARMEM);

__startup_data
static const struct mig_kern_subsystem *mig_e[] = {
	(const struct mig_kern_subsystem *)&mach_vm_subsystem,
	(const struct mig_kern_subsystem *)&mach_port_subsystem,
	(const struct mig_kern_subsystem *)&mach_host_subsystem,
	(const struct mig_kern_subsystem *)&host_priv_subsystem,
	(const struct mig_kern_subsystem *)&clock_subsystem,
	(const struct mig_kern_subsystem *)&processor_subsystem,
	(const struct mig_kern_subsystem *)&processor_set_subsystem,
	(const struct mig_kern_subsystem *)&is_iokit_subsystem,
	(const struct mig_kern_subsystem *)&task_subsystem,
	(const struct mig_kern_subsystem *)&thread_act_subsystem,
#ifdef VM32_SUPPORT
	(const struct mig_kern_subsystem *)&vm32_map_subsystem,
#endif
#if CONFIG_USER_NOTIFICATION
	(const struct mig_kern_subsystem *)&UNDReply_subsystem,
#endif
	(const struct mig_kern_subsystem *)&mach_voucher_subsystem,
	(const struct mig_kern_subsystem *)&memory_entry_subsystem,
	(const struct mig_kern_subsystem *)&task_restartable_subsystem,
	(const struct mig_kern_subsystem *)&catch_exc_subsystem,
	(const struct mig_kern_subsystem *)&catch_mach_exc_subsystem,
#if CONFIG_ARCADE
	(const struct mig_kern_subsystem *)&arcade_register_subsystem,
#endif
	(const struct mig_kern_subsystem *)&mach_eventlink_subsystem,
};

static struct ipc_kobject_ops __security_const_late
    ipc_kobject_ops_array[IKOT_MAX_TYPE];

__startup_func
void
ipc_kobject_register_startup(ipc_kobject_ops_t ops)
{
	if (ipc_kobject_ops_array[ops->iko_op_type].iko_op_type) {
		panic("trying to register kobject(%d) twice", ops->iko_op_type);
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

__startup_func
static void
mig_init(void)
{
	unsigned int i, n = sizeof(mig_e) / sizeof(const struct mig_kern_subsystem *);
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
			if (mig_e[i]->kroutine[j].kstub_routine) {
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
				mig_buckets[pos].kroutine = mig_e[i]->kroutine[j].kstub_routine;
				if (mig_e[i]->kroutine[j].max_reply_msg) {
					mig_buckets[pos].kreply_size = mig_e[i]->kroutine[j].max_reply_msg;
					mig_buckets[pos].kreply_desc_cnt = mig_e[i]->kroutine[j].reply_descr_count;
				} else {
					/*
					 * Allocating a larger-than-needed kmsg creates hole for
					 * inlined kmsgs (IKM_TYPE_ALL_INLINED) during copyout.
					 * Disallow that.
					 */
					panic("kroutine must have precise size %d %d", mig_e[i]->start, j);
				}

				mig_buckets[pos].kobjidx = KOBJ_IDX_NOT_SET;

				if (mig_table_max_displ < howmany) {
					mig_table_max_displ = howmany;
				}
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

	if (!ptr->kroutine || msgh_id != ptr->num) {
		ptr = (mig_hash_t *)0;
	}

	return ptr;
}

/*
 * Routine: ipc_kobject_reply_status
 *
 * Returns the error/success status from a given kobject call reply message.
 *
 * Contract for KernelServer MIG routines is as follows:
 *
 * (1) If reply header has complex bit set, kernel server implementation routine
 *     must have implicitly returned KERN_SUCCESS.
 *
 * (2) Otherwise we can always read RetCode from after the header. This is not
 *     obvious to see, and is discussed below by case.
 *
 * MIG can return three types of replies from KernelServer routines.
 *
 * (A) Complex Reply (i.e. with Descriptors)
 *
 *     E.g.: thread_get_exception_ports()
 *
 *       If complex bit is set, we can deduce the call is successful since the bit
 *     is set at the very end.
 *       If complex bit is not set, we must have returned from MIG_RETURN_ERROR.
 *     MIG writes RetCode to immediately after the header, and we know this is
 *     safe to do for all kmsg layouts. (See discussion in ipc_kmsg_server_internal()).
 *
 *  (B) Simple Reply with Out Params
 *
 *      E.g.: thread_get_states()
 *
 *        If the call failed, we return from MIG_RETURN_ERROR, which writes RetCode
 *      to immediately after the header.
 *        If the call succeeded, MIG writes RetCode as KERN_SUCCESS to USER DATA
 *      buffer. *BUT* since the region after header is always initialized with
 *      KERN_SUCCESS, reading from there gives us the same result. We rely on
 *      this behavior to not make a special case.
 *
 *  (C) Simple Reply without Out Params
 *
 *      E.g.: thread_set_states()
 *
 *        For this type of MIG routines we always allocate a mig_reply_error_t
 *      as reply kmsg, which fits inline in kmsg. RetCode can be found after
 *      header, and can be KERN_SUCCESS or otherwise a failure code.
 */
static kern_return_t
ipc_kobject_reply_status(ipc_kmsg_t reply)
{
	mach_msg_header_t *hdr = ikm_header(reply);

	if (hdr->msgh_bits & MACH_MSGH_BITS_COMPLEX) {
		return KERN_SUCCESS;
	}

	return ((mig_reply_error_t *)hdr)->RetCode;
}

static void
ipc_kobject_set_reply_error_status(
	ipc_kmsg_t    reply,
	kern_return_t kr)
{
	mig_reply_error_t *error = (mig_reply_error_t *)ikm_header(reply);

	assert(!(error->Head.msgh_bits & MACH_MSGH_BITS_COMPLEX));
	error->RetCode = kr;
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
	mach_msg_header_t *req_hdr   = ikm_header(request);
	mach_msg_header_t *reply_hdr = ikm_header(reply);

#define InP     ((mach_msg_header_t *) req_hdr)
#define OutP    ((mig_reply_error_t *) reply_hdr)

	OutP->Head.msgh_size = sizeof(mig_reply_error_t);
	OutP->Head.msgh_bits =
	    MACH_MSGH_BITS_SET(MACH_MSGH_BITS_LOCAL(InP->msgh_bits), 0, 0, 0);
	OutP->Head.msgh_remote_port = InP->msgh_local_port;
	OutP->Head.msgh_local_port = MACH_PORT_NULL;
	OutP->Head.msgh_voucher_port = MACH_PORT_NULL;
	OutP->Head.msgh_id = InP->msgh_id + 100;

	OutP->NDR = NDR_record;
	OutP->RetCode = kr;

#undef  InP
#undef  OutP
}

static void
ipc_kobject_init_new_reply(
	ipc_kmsg_t          new_reply,
	const ipc_kmsg_t    old_reply,
	kern_return_t       kr)
{
	mach_msg_header_t *new_hdr = ikm_header(new_reply);
	mach_msg_header_t *old_hdr = ikm_header(old_reply);

#define InP     ((mig_reply_error_t *) old_hdr)
#define OutP    ((mig_reply_error_t *) new_hdr)

	OutP->Head.msgh_size = sizeof(mig_reply_error_t);
	OutP->Head.msgh_bits = InP->Head.msgh_bits & ~MACH_MSGH_BITS_COMPLEX;
	OutP->Head.msgh_remote_port = InP->Head.msgh_remote_port;
	OutP->Head.msgh_local_port = MACH_PORT_NULL;
	OutP->Head.msgh_voucher_port = MACH_PORT_NULL;
	OutP->Head.msgh_id = InP->Head.msgh_id;

	OutP->NDR = InP->NDR;
	OutP->RetCode = kr;

#undef  InP
#undef  OutP
}

static ipc_kmsg_t
ipc_kobject_alloc_mig_error(void)
{
	return ipc_kmsg_alloc(sizeof(mig_reply_error_t),
	           0, 0, IPC_KMSG_ALLOC_KERNEL | IPC_KMSG_ALLOC_SAVED | IPC_KMSG_ALLOC_ZERO |
	           IPC_KMSG_ALLOC_NOFAIL);
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
	__unused ipc_port_t port,
	ipc_kmsg_t          request,
	ipc_kmsg_t          *replyp)
{
	int request_msgh_id;
	ipc_kmsg_t reply = IKM_NULL;
	mach_msg_size_t reply_size, reply_desc_cnt;
	mig_hash_t *ptr;
	mach_msg_header_t *req_hdr, *reply_hdr;
	void *req_data, *reply_data;
	mach_msg_max_trailer_t *req_trailer;

	thread_ro_t tro = current_thread_ro();
	task_t curtask = tro->tro_task;
	struct proc *curproc = tro->tro_proc;

	req_hdr = ikm_header(request);
	req_data = ikm_udata_from_header(request);
	req_trailer = ipc_kmsg_get_trailer(request, FALSE);
	request_msgh_id = req_hdr->msgh_id;

	/* Find corresponding mig_hash entry, if any */
	ptr = find_mig_hash_entry(request_msgh_id);

	/* Get the reply_size. */
	if (ptr == (mig_hash_t *)0) {
		reply_size = sizeof(mig_reply_error_t);
		reply_desc_cnt = 0;
	} else {
		reply_size = ptr->kreply_size;
		reply_desc_cnt = ptr->kreply_desc_cnt;
	}

	assert(reply_size >= sizeof(mig_reply_error_t));

	/*
	 * MIG should really assure no data leakage -
	 * but until it does, pessimistically zero the
	 * whole reply buffer.
	 */
	reply = ipc_kmsg_alloc(reply_size, 0, reply_desc_cnt, IPC_KMSG_ALLOC_KERNEL |
	    IPC_KMSG_ALLOC_ZERO | IPC_KMSG_ALLOC_NOFAIL);
	/* reply can be non-linear */

	if (ptr == (mig_hash_t *)0) {
#if DEVELOPMENT || DEBUG
		printf("ipc_kobject_server: bogus kernel message, id=%d\n",
		    req_hdr->msgh_id);
#endif  /* DEVELOPMENT || DEBUG */
		_MIG_MSGID_INVALID(req_hdr->msgh_id);

		ipc_kobject_init_reply(reply, request, MIG_BAD_ID);

		*replyp = reply;
		return KERN_SUCCESS;
	}

	/*
	 * We found the routine to call. Call it to perform the kernel function.
	 */
	assert(ptr != (mig_hash_t *)0);

	reply_hdr = ikm_header(reply);
	/* reply is allocated by kernel. non-zero desc count means complex msg */
	reply_data = ikm_udata(reply, reply_desc_cnt, (reply_desc_cnt > 0));

	/*
	 * Reply can be of layout IKM_TYPE_ALL_INLINED, IKM_TYPE_UDATA_OOL,
	 * or IKM_TYPE_ALL_OOL, each of which guarantees kernel/user data segregation.
	 *
	 * Here is the trick: In each case, there _must_ be enough space in
	 * the kdata (header) buffer in `reply` to hold a mig_reply_error_t.
	 */
	assert(reply->ikm_type != IKM_TYPE_KDATA_OOL);
	assert((vm_offset_t)reply_hdr + sizeof(mig_reply_error_t) <= ikm_kdata_end(reply));

	/*
	 * Discussion by case:
	 *
	 * (1) IKM_TYPE_ALL_INLINED
	 *     - IKM_SAVED_MSG_SIZE is large enough for mig_reply_error_t
	 * (2) IKM_TYPE_UDATA_OOL
	 *     - Same as (1).
	 * (3) IKM_TYPE_ALL_OOL
	 *     - This layout is only possible if kdata (header + descs) doesn't fit
	 *       in IKM_SAVED_MSG_SIZE. So we must have at least one descriptor
	 *       following the header, which is enough to fit mig_reply_error_t.
	 */
	static_assert(sizeof(mig_reply_error_t) < IKM_SAVED_MSG_SIZE);
	static_assert(sizeof(mig_reply_error_t) < sizeof(mach_msg_base_t) +
	    1 * sizeof(mach_msg_descriptor_t));

	/*
	 * Therefore, we can temporarily treat `reply` as a *simple* message that
	 * contains NDR Record + RetCode immediately after the header (which overlaps
	 * with descriptors, if the reply msg is supposed to be complex).
	 *
	 * In doing so we save having a separate allocation specifically for errors.
	 */
	ipc_kobject_init_reply(reply, request, KERN_SUCCESS);

	/* Check if the kobject call should be filtered */
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
			ipc_kobject_set_reply_error_status(reply, kr);
			goto skip_kobjcall;
		}
	}
#endif /* CONFIG_MACF */

	__BeforeKobjectServerTrace(idx);
	/* See contract in header doc for ipc_kobject_reply_status() */
	(*ptr->kroutine)(req_hdr, req_data, req_trailer, reply_hdr, reply_data);
	__AfterKobjectServerTrace(idx);

#if CONFIG_MACF
skip_kobjcall:
#endif
	counter_inc(&kernel_task->messages_received);

	kern_return_t reply_status = ipc_kobject_reply_status(reply);

	if (reply_status == MIG_NO_REPLY) {
		/*
		 *	The server function will send a reply message
		 *	using the reply port right, which it has saved.
		 */
		ipc_kmsg_free(reply);
		reply = IKM_NULL;
	} else if (reply_status != KERN_SUCCESS && reply_size > sizeof(mig_reply_error_t)) {
		assert(ikm_header(reply)->msgh_size == sizeof(mig_reply_error_t));
		/*
		 * MIG returned an error, and the original kmsg we allocated for reply
		 * is oversized. Deallocate it and allocate a smaller, proper kmsg
		 * that fits mig_reply_error_t snuggly.
		 *
		 * We must do so because we used the trick mentioned above which (depending
		 * on the kmsg layout) may cause payload in mig_reply_error_t to overlap
		 * with kdata buffer meant for descriptors.
		 *
		 * This will mess with ikm_kdata_size() calculation down the line so
		 * reallocate a new buffer immediately here.
		 */
		ipc_kmsg_t new_reply = ipc_kobject_alloc_mig_error();
		ipc_kobject_init_new_reply(new_reply, reply, reply_status);

		/* MIG contract: If status is not KERN_SUCCESS, reply must be simple. */
		assert(!(ikm_header(reply)->msgh_bits & MACH_MSGH_BITS_COMPLEX));
		assert(ikm_header(reply)->msgh_local_port == MACH_PORT_NULL);
		assert(ikm_header(reply)->msgh_voucher_port == MACH_PORT_NULL);
		/* So we can simply free the original reply message. */
		ipc_kmsg_free(reply);
		reply = new_reply;
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
	mach_msg_header_t *req_hdr = ikm_header(request);
#if DEVELOPMENT || DEBUG
	const int request_msgh_id = req_hdr->msgh_id;
#endif
	ipc_port_t request_voucher_port;
	ipc_kmsg_t reply = IKM_NULL;
	mach_msg_header_t *reply_hdr;
	kern_return_t kr;

	ipc_kmsg_trace_send(request, option);

	if (ip_kotype(port) == IKOT_UEXT_OBJECT) {
		kr = uext_server(port, request, &reply);
	} else {
		kr = ipc_kobject_server_internal(port, request, &reply);
		assert(kr == KERN_SUCCESS);
	}

	if (kr != KERN_SUCCESS) {
		assert(kr != MACH_SEND_TIMED_OUT &&
		    kr != MACH_SEND_INTERRUPTED &&
		    kr != MACH_SEND_INVALID_DEST);
		assert(reply == IKM_NULL);

		/* convert the server error into a MIG error */
		reply = ipc_kobject_alloc_mig_error();
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
	 */
	switch (MACH_MSGH_BITS_REMOTE(req_hdr->msgh_bits)) {
	case MACH_MSG_TYPE_PORT_SEND:
		ipc_port_release_send(req_hdr->msgh_remote_port);
		break;

	case MACH_MSG_TYPE_PORT_SEND_ONCE:
		ipc_port_release_sonce(req_hdr->msgh_remote_port);
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
		    MACH_MSGH_BITS_VOUCHER(req_hdr->msgh_bits));
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
		 *  Remote port has been released above. Do not destroy
		 *  the reply port right either, which is needed in the reply message.
		 */
		ipc_kmsg_destroy(request, IPC_KMSG_DESTROY_SKIP_LOCAL | IPC_KMSG_DESTROY_SKIP_REMOTE);
	}

	if (reply != IKM_NULL) {
		reply_hdr = ikm_header(reply);
		ipc_port_t reply_port = reply_hdr->msgh_remote_port;

		if (!IP_VALID(reply_port)) {
			/*
			 *	Can't queue the reply message if the destination
			 *	(the reply port) isn't valid.
			 */
			ipc_kmsg_destroy(reply, IPC_KMSG_DESTROY_NOT_SIGNED);
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
			ipc_kmsg_destroy(reply, IPC_KMSG_DESTROY_NOT_SIGNED);
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
	type |= port->ip_immovable_receive << 14;
	type |= port->ip_immovable_send << 15;
	type ^= OS_PTRAUTH_DISCRIMINATOR("ipc_port.ip_kobject");
	kobject = ptrauth_sign_unauthenticated(kobject,
	    ptrauth_key_process_independent_data,
	    ptrauth_blend_discriminator(store, type));
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
	io_bits_or(ip_to_object(port), type);
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
	type |= port->ip_immovable_receive << 14;
	type |= port->ip_immovable_send << 15;
	type ^= OS_PTRAUTH_DISCRIMINATOR("ipc_port.ip_kobject");
	kobject = ptrauth_auth_data(kobject,
	    ptrauth_key_process_independent_data,
	    ptrauth_blend_discriminator(store, type));
#else
	(void)type;
#endif // __has_feature(ptrauth_calls)

	return kobject;
}

__abortlike
static void
ipc_kobject_require_panic(
	ipc_port_t                  port,
	ipc_kobject_t               kobject,
	ipc_kobject_type_t          kotype)
{
	if (ip_kotype(port) != kotype) {
		panic("port %p: invalid kobject type, got %d wanted %d",
		    port, ip_kotype(port), kotype);
	}
	panic("port %p: invalid kobject, got %p wanted %p",
	    port, ipc_kobject_get_raw(port, kotype), kobject);
}

__header_always_inline void
ipc_kobject_require(
	ipc_port_t                  port,
	ipc_kobject_t               kobject,
	ipc_kobject_type_t          kotype)
{
	ipc_kobject_t cur;

	if (__improbable(ip_kotype(port) != kotype)) {
		ipc_kobject_require_panic(port, kobject, kotype);
	}
	cur = ipc_kobject_get_raw(port, kotype);
	if (cur && cur != kobject) {
		ipc_kobject_require_panic(port, kobject, kotype);
	}
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
	if (options & IPC_KOBJECT_ALLOC_MAKE_SEND) {
		ipc_port_make_send_any_locked(port);
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

	ipc_kobject_set_internal(port, kobject, type);
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
	port = ipc_port_alloc_special(ipc_space_kernel, IPC_PORT_ENFORCE_RIGID_REPLY_PORT_SEMANTICS);

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
bool
ipc_kobject_make_send_lazy_alloc_port(
	ipc_port_t              *port_store,
	ipc_kobject_t           kobject,
	ipc_kobject_type_t      type,
	ipc_kobject_alloc_options_t alloc_opts)
{
	ipc_port_t port, previous;
	kern_return_t kr;

	alloc_opts |= IPC_KOBJECT_ALLOC_MAKE_SEND | IPC_KOBJECT_ALLOC_NSREQUEST;
	port = os_atomic_load(port_store, dependency);

	if (!IP_VALID(port)) {
		port = ipc_kobject_alloc_port(kobject, type, alloc_opts);

		if (os_atomic_cmpxchgv(port_store,
		    IP_NULL, port, &previous, release)) {
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

	kr = ipc_kobject_make_send_nsrequest(port, kobject, type);
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

	kr = ipc_kobject_make_send_nsrequest(port, kobject, type);
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
	ipc_port_t              port,
	mach_port_mscount_t     sync,
	mach_port_mscount_t    *mscount)
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

ipc_port_t
ipc_kobject_copy_send(
	ipc_port_t              port,
	ipc_kobject_t           kobject,
	ipc_kobject_type_t      kotype)
{
	ipc_port_t sright = port;

	if (IP_VALID(port)) {
		ip_mq_lock(port);
		if (ip_active(port)) {
			ipc_kobject_require(port, kobject, kotype);
			ipc_port_copy_send_any_locked(port);
		} else {
			sright = IP_DEAD;
		}
		ip_mq_unlock(port);
	}

	return sright;
}

ipc_port_t
ipc_kobject_make_send(
	ipc_port_t              port,
	ipc_kobject_t           kobject,
	ipc_kobject_type_t      kotype)
{
	ipc_port_t sright = port;

	if (IP_VALID(port)) {
		ip_mq_lock(port);
		if (ip_active(port)) {
			ipc_kobject_require(port, kobject, kotype);
			ipc_port_make_send_any_locked(port);
		} else {
			sright = IP_DEAD;
		}
		ip_mq_unlock(port);
	}

	return sright;
}

kern_return_t
ipc_kobject_make_send_nsrequest(
	ipc_port_t              port,
	ipc_kobject_t           kobject,
	ipc_kobject_type_t      kotype)
{
	kern_return_t kr = KERN_INVALID_RIGHT;

	if (IP_VALID(port)) {
		ip_mq_lock(port);
		if (ip_active(port)) {
			ipc_kobject_require(port, kobject, kotype);
			ipc_port_make_send_any_locked(port);
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

	ipc_kobject_set_raw(port, IKO_NULL, type);
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

/*
 *	Routine:	ipc_kobject_upgrade_mktimer_locked
 *	Purpose:
 *		Upgrades a port to mktimer kobject status
 *
 *		This pattern is rather bad as it leads to various
 *		confusions that need to be special cased with kobject-ness
 *		of ports. No new port with dual kobject/message-queue
 *		semantics should be made ever.
 *
 *	Conditions:
 *		Port is locked
 */
void
ipc_kobject_upgrade_mktimer_locked(
	ipc_port_t                  port,
	ipc_kobject_t               kobject)
{
	ipc_kobject_set_internal(port, kobject, IKOT_TIMER);
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

	ip_sorights_dec(port);
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
 *	Routine:	ipc_kobject_label_substitute_task_read
 *	Purpose:
 *		Substitute a task read port for its immovable
 *		control equivalent when the receiver is that task.
 *	Conditions:
 *		Space is write locked and active.
 *		Port is locked and active.
 *	Returns:
 *		- IP_NULL port if no substitution is to be done
 *		- a valid port if a substitution needs to happen
 */
static ipc_port_t
ipc_kobject_label_substitute_task_read(
	ipc_space_t             space,
	ipc_kobject_label_t     kolabel,
	ipc_port_t              port)
{
	ipc_port_t subst = IP_NULL;
	task_t task = ipc_kobject_get_raw(port, IKOT_TASK_READ);

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
 *	Routine:	ipc_kobject_label_substitute_thread_read
 *	Purpose:
 *		Substitute a thread read port for its immovable
 *		control equivalent when it belongs to the receiver task.
 *	Conditions:
 *		Space is write locked and active.
 *		Port is locked and active.
 *	Returns:
 *		- IP_NULL port if no substitution is to be done
 *		- a valid port if a substitution needs to happen
 */
static ipc_port_t
ipc_kobject_label_substitute_thread_read(
	ipc_space_t             space,
	ipc_kobject_label_t     kolabel,
	ipc_port_t              port)
{
	ipc_port_t subst = IP_NULL;
	thread_t thread = ipc_kobject_get_raw(port, IKOT_THREAD_READ);

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
		case IPC_LABEL_SUBST_TASK_READ:
			subst = ipc_kobject_label_substitute_task_read(space,
			    kolabel, port);
			break;
		case IPC_LABEL_SUBST_THREAD:
			subst = ipc_kobject_label_substitute_thread(space,
			    kolabel, port);
			break;
		case IPC_LABEL_SUBST_THREAD_READ:
			subst = ipc_kobject_label_substitute_thread_read(space,
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
			/* no check: dPAC integrity */
			port = ipc_port_make_send_any(subst);
			ip_release(subst);
			*subst_portp = port;
			return true;
		}
	}

	return (label & space->is_label & IPC_LABEL_SPACE_MASK) ==
	       (label & IPC_LABEL_SPACE_MASK);
}
