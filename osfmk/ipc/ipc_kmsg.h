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
 * NOTICE: This file was modified by McAfee Research in 2004 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 * Copyright (c) 2005 SPARTA, Inc.
 */
/*
 */
/*
 *	File:	ipc/ipc_kmsg.h
 *	Author:	Rich Draves
 *	Date:	1989
 *
 *	Definitions for kernel messages.
 */

#ifndef _IPC_IPC_KMSG_H_
#define _IPC_IPC_KMSG_H_

#include <mach/vm_types.h>
#include <mach/message.h>
#include <kern/kern_types.h>
#include <kern/assert.h>
#include <kern/macro_help.h>
#include <kern/kalloc.h>
#include <kern/circle_queue.h>
#include <ipc/ipc_types.h>
#include <ipc/ipc_object.h>
#include <sys/kdebug.h>

/*
 *	This structure is only the header for a kmsg buffer;
 *	the actual buffer is normally larger. The rest of the buffer
 *	holds the body of the message.
 *
 *	In a kmsg, the port fields hold pointers to ports instead
 *	of port names. These pointers hold references.
 *
 *	The ikm_header.msgh_remote_port field is the destination
 *	of the message.
 */

/*
 * A kmsg can be in one of the following four layouts
 *
 * @see <doc/mach_ipc/kmsg.md> for a visual representation.
 */
__enum_decl(ipc_kmsg_type_t, uint8_t, {
	/*
	 * IKM_TYPE_ALL_INLINED: The entire message (and aux) is allocated inline.
	 * mach_msg_header_t is immediately after the kmsg header. An optional aux
	 * may be following the inline message proper.
	 */
	IKM_TYPE_ALL_INLINED    = 0,
	/*
	 * IKM_TYPE_UDATA_OOL: Message header and descriptors are allocated inline,
	 * and message data, trailer, and aux are in buffer pointed to by ikm_udata.
	 * mach_msg_header_t is immediately after the kmsg header.
	 */
	IKM_TYPE_UDATA_OOL      = 1,
	/*
	 * IKM_TYPE_KDATA_OOL: The entire message is allocated out-of-line.
	 * {ikm_kdata, ikm_kdata_size} specifies the address and size
	 * of the allocation.
	 *
	 * There is no aux data.
	 */
	IKM_TYPE_KDATA_OOL      = 2,
	/*
	 * IKM_TYPE_ALL_OOL: Everything is allocated out-of-line. Message header
	 * and descriptors are allocated from typed kernel heap (kalloc_type)
	 * and pointed at by ikm_kdata.  The message data, trailer, and aux are
	 * in data buffer pointed to by ikm_udata.
	 */
	IKM_TYPE_ALL_OOL        = 3
});

#define IKM_ALLOC_SIZE          256
#define IKM_SMALL_MSG_SIZE      168 /* for !IKM_TYPE_ALL_INLINED */
#define IKM_BIG_MSG_SIZE        192 /* for IKM_TYPE_ALL_INLINED  */

/* used by mk_timer to prevent the message from being freed */
__options_closed_decl(ipc_kmsg_keep_alive_t, uint8_t, {
	IKM_KEEP_ALIVE_NONE   = 0x0, /* keep-alive not used on this message     */
	IKM_KEEP_ALIVE_OWNED  = 0x1, /* keep-alive used, owned by the subsystem */
	IKM_KEEP_ALIVE_IN_USE = 0x2, /* keep-alive used, message is in flight   */
});

struct ipc_kmsg {
	queue_chain_t              ikm_link;
	ipc_port_t                 XNU_PTRAUTH_SIGNED_PTR("kmsg.ikm_voucher_port") ikm_voucher_port;   /* voucher port carried */
	struct ipc_importance_elem *ikm_importance;  /* inherited from */
	queue_chain_t              ikm_inheritance;  /* inherited from link */
#if MACH_FLIPC
	struct mach_node           *ikm_node;        /* originating node - needed for ack */
#endif
	uint16_t                   ikm_aux_size;     /* size reserved for auxiliary data */
	ipc_kmsg_keep_alive_t      ikm_keep_alive;   /* only used for IKM_TYPE_ALL_INLINED */
	uint8_t                    __ikm_padding;
	uint32_t                   ikm_ppriority;    /* pthread priority of this kmsg */
	uint32_t                   ikm_signature;    /* sig for all kernel-processed data */
	ipc_object_copyin_flags_t  ikm_flags;
	mach_msg_qos_t             ikm_qos_override; /* qos override on this kmsg */

	mach_msg_type_name_t       ikm_voucher_type: 6; /* disposition type the voucher came in with */
	ipc_kmsg_type_t            ikm_type: 2;

	union {
		/*
		 * - ikm_big_data (IKM_TYPE_ALL_INLINED)
		 *   inline buffer used for everything
		 *
		 * - ikm_small_data (IKM_TYPE_UDATA_OOL)
		 *   inline buffer used for the kernel data/header
		 *
		 * - ikm_kdata{,_size} (IKM_TYPE_KDATA_OOL, IKM_TYPE_ALL_OOL)
		 *   kernel data buffer and size (with kernel pointers).
		 *
		 * - ikm_udata{,_size} (IKM_TYPE_UDATA_OOL, IKM_TYPE_ALL_OOL)
		 *   user data buffer and size (no kernel pointers).
		 *
		 * Note: ikm_big_data and ikm_small_data are at the same address
		 *       so that `ikm_header()` only has two cases.
		 *
		 *       dPAC-ed pointers follow so that linear overflows are
		 *       unlikely to be exploitable.
		 */
		uint32_t           ikm_big_data[IKM_BIG_MSG_SIZE / 4];
		struct {
			uint32_t   ikm_small_data[IKM_SMALL_MSG_SIZE / 4];
			void *XNU_PTRAUTH_SIGNED_PTR("kmsg.ikm_kdata") ikm_kdata;
			void *XNU_PTRAUTH_SIGNED_PTR("kmsg.ikm_udata") ikm_udata;
			mach_msg_size_t ikm_kdata_size;
			mach_msg_size_t ikm_udata_size;
		} __attribute__((packed, aligned(4)));
	};
};

static_assert(sizeof(struct ipc_kmsg) == IKM_ALLOC_SIZE);
static_assert(offsetof(struct ipc_kmsg, ikm_big_data) +
    IKM_BIG_MSG_SIZE == IKM_ALLOC_SIZE);
static_assert(offsetof(struct ipc_kmsg, ikm_small_data) + IKM_SMALL_MSG_SIZE +
    2 * sizeof(void *) + 2 * sizeof(mach_msg_size_t) == IKM_ALLOC_SIZE);

KALLOC_TYPE_VAR_DECLARE(KT_IPC_KMSG_KDATA_OOL);

/*
 * Exported interfaces
 */

typedef circle_queue_t                  ipc_kmsg_queue_t;

#define ipc_kmsg_queue_init(queue)      circle_queue_init(queue)

#define ipc_kmsg_queue_empty(queue)     circle_queue_empty(queue)

#define ipc_kmsg_queue_element(elem) \
	cqe_element(elem, struct ipc_kmsg, ikm_link)

#define ipc_kmsg_queue_first(queue) \
	cqe_queue_first(queue, struct ipc_kmsg, ikm_link)

#define ipc_kmsg_queue_next(queue, elt) \
	cqe_queue_next(&(elt)->ikm_link, queue, struct ipc_kmsg, ikm_link)

#define ipc_kmsg_enqueue(queue, kmsg) \
	circle_enqueue_tail(queue, &(kmsg)->ikm_link)

#define ipc_kmsg_rmqueue(queue, kmsg) \
	circle_dequeue(queue, &(kmsg)->ikm_link)

extern bool ipc_kmsg_enqueue_qos(
	ipc_kmsg_queue_t        queue,
	ipc_kmsg_t              kmsg);

extern bool ipc_kmsg_override_qos(
	ipc_kmsg_queue_t        queue,
	ipc_kmsg_t              kmsg,
	mach_msg_qos_t          qos_ovr);

/* Pull the (given) first kmsg out of a queue */
extern void ipc_kmsg_rmqueue_first(
	ipc_kmsg_queue_t        queue,
	ipc_kmsg_t              kmsg);

__options_decl(ipc_kmsg_alloc_flags_t, uint32_t, {
	/* specify either user or kernel flag */
	IPC_KMSG_ALLOC_USER             = 0x0000,
	IPC_KMSG_ALLOC_KERNEL           = 0x0001,

	IPC_KMSG_ALLOC_ZERO             = 0x0002,
	IPC_KMSG_ALLOC_ALL_INLINE       = 0x0004,
	IPC_KMSG_ALLOC_NOFAIL           = 0x0008,
	IPC_KMSG_ALLOC_LINEAR           = 0x0010,
	IPC_KMSG_ALLOC_USE_KEEP_ALIVE   = 0x0020, /* must call ipc_kmsg_keep_alive_abandon () */
});

/* Allocate a kernel message */
extern ipc_kmsg_t ipc_kmsg_alloc(
	mach_msg_size_t         msg_size,
	mach_msg_size_t         aux_size,
	mach_msg_size_t         desc_count,
	ipc_kmsg_alloc_flags_t  flags);

/* Free a kernel message buffer */
extern void ipc_kmsg_free(
	ipc_kmsg_t              kmsg);

extern void ipc_kmsg_clean_descriptors(
	mach_msg_kdescriptor_t * kdesc __counted_by(number),
	mach_msg_type_number_t  number);

extern void ipc_kmsg_sign_descriptors(
	mach_msg_kdescriptor_t *kdesc,
	mach_msg_size_t         dsc_count);

__options_decl(ipc_kmsg_destroy_flags_t, uint32_t, {
	IPC_KMSG_DESTROY_ALL           = 0x0000,
	IPC_KMSG_DESTROY_SKIP_REMOTE   = 0x0001,
	IPC_KMSG_DESTROY_SKIP_LOCAL    = 0x0002,
	IPC_KMSG_DESTROY_NOT_SIGNED    = 0x0004,
});
/* Destroy kernel message */
extern void ipc_kmsg_destroy(
	ipc_kmsg_t                kmsg,
	ipc_kmsg_destroy_flags_t  flags);

/* Enqueue kernel message for deferred destruction */
extern bool ipc_kmsg_delayed_destroy(
	ipc_kmsg_t              kmsg);

/* Enqueue queue of kernel messages for deferred destruction */
extern bool ipc_kmsg_delayed_destroy_queue(
	ipc_kmsg_queue_t        queue);

/* Process all the delayed message destroys */
extern void ipc_kmsg_reap_delayed(void);

/* Try to mark a message as in use (setting IKM_KEEP_ALIVE_IN_USE). */
extern bool ipc_kmsg_keep_alive_try_reusing(
	ipc_kmsg_t              kmsg);

/* Abandons a message that was allocated with IPC_KMSG_ALLOC_USE_KEEP_ALIVE. */
extern void ipc_kmsg_keep_alive_abandon(
	ipc_kmsg_t              kmsg);

/* get the unshifted message header of a kmsg */
extern mach_msg_header_t *ikm_header(
	ipc_kmsg_t              kmsg);

/* get the start address of user data (after the last descriptor) for a kmsg */
extern void *ikm_udata(
	ipc_kmsg_t              kmsg,
	mach_msg_size_t         desc_count,
	bool                    complex);

extern void * ikm_udata_from_header(
	ipc_kmsg_t              kmsg);

/* Allocate a kernel message buffer and copy a kernel message to the buffer */
extern mach_msg_return_t ipc_kmsg_get_from_kernel(
	mach_msg_header_t      *msg,
	mach_msg_size_t         size,
	mach_msg_option64_t     options,
	ipc_kmsg_t             *kmsgp);

/* Send a message to a port */
extern mach_msg_return_t ipc_kmsg_send(
	ipc_kmsg_t              kmsg,
	mach_msg_option64_t     options,
	mach_msg_timeout_t      timeout_val);

/* Copy a kernel message buffer to a user message */
extern mach_msg_return_t ipc_kmsg_put_to_user(
	ipc_kmsg_t              kmsg,     /* scalar or vector */
	mach_msg_recv_bufs_t   *recv_bufs,
	mach_msg_recv_result_t *msgr,
	mach_msg_option64_t     option,
	vm_map_t                map,
	mach_msg_return_t       mr);

/* Copy a kernel message buffer to a kernel message */
extern void ipc_kmsg_put_to_kernel(
	mach_msg_header_t      *msg,
	mach_msg_option64_t     options,
	ipc_kmsg_t              kmsg,
	mach_msg_size_t         size);

/* Copyin data, port rights and out-of-line memory from a user message */
extern mach_msg_return_t ipc_kmsg_copyin_from_user(
	ipc_kmsg_t              kmsg,
	mach_msg_send_uctx_t   *send_uctx,
	ipc_space_t             space,
	vm_map_t                map,
	mach_msg_priority_t     priority,
	mach_msg_option64_t    *optionp);

/* Copyin port rights and out-of-line memory from a kernel message */
extern mach_msg_return_t ipc_kmsg_copyin_from_kernel(
	ipc_kmsg_t              kmsg);

/* Copyout the header and body to a user message */
extern mach_msg_return_t ipc_kmsg_copyout(
	ipc_kmsg_t              kmsg,
	ipc_space_t             space,
	vm_map_t                map,
	mach_msg_option64_t     option);

/* Copyout port rights and out-of-line memory to a user message,
 *  not reversing the ports in the header */
extern mach_msg_return_t ipc_kmsg_copyout_pseudo(
	ipc_kmsg_t              kmsg,
	ipc_space_t             space,
	vm_map_t                map);

/* Compute size of message as copied out to the specified space/map */
extern mach_msg_size_t ipc_kmsg_copyout_size(
	ipc_kmsg_t              kmsg,
	vm_map_t                map);

/* Copyout the destination port in the message */
extern void ipc_kmsg_copyout_dest_to_user(
	ipc_kmsg_t              kmsg,
	ipc_space_t             space);

/* kernel's version of ipc_kmsg_copyout_dest_to_user */
extern void ipc_kmsg_copyout_dest_to_kernel(
	ipc_kmsg_t              kmsg,
	ipc_space_t             space);

/* Returns a pointer to a thread group in the kmsg if any. Caller has a
 * reference to the kmsg */
extern struct thread_group *ipc_kmsg_get_thread_group(
	ipc_kmsg_t              kmsg);

extern mach_msg_trailer_size_t ipc_kmsg_trailer_size(
	mach_msg_option64_t     option,
	vm_map_t                map);

extern mach_msg_max_trailer_t *ipc_kmsg_get_trailer(
	ipc_kmsg_t              kmsg);

extern void ipc_kmsg_set_voucher_port(
	ipc_kmsg_t              kmsg,
	ipc_port_t              voucher,
	mach_msg_type_name_t    type);

extern ipc_port_t ipc_kmsg_get_voucher_port(
	ipc_kmsg_t              kmsg);

extern void ipc_kmsg_clear_voucher_port(
	ipc_kmsg_t              kmsg);

/* checks signature and returns descriptor count */
extern mach_msg_size_t ipc_kmsg_validate_signature(
	ipc_kmsg_t              kmsg) __result_use_check;

#define moved_provisional_reply_port(port_type, port) \
	(port_type == MACH_MSG_TYPE_MOVE_RECEIVE && IP_VALID(port) && ip_is_provisional_reply_port(port)) \

extern void send_prp_telemetry(int msgh_id);

#if (KDEBUG_LEVEL >= KDEBUG_LEVEL_STANDARD)
extern void ipc_kmsg_trace_send(
	ipc_kmsg_t              kmsg,
	mach_msg_option64_t     option);
#else
#define ipc_kmsg_trace_send(a, b) do { } while (0)
#endif

#if (DEVELOPMENT || DEBUG)
vm_offset_t ikm_kdata_end(ipc_kmsg_t kmsg);
#endif

#endif  /* _IPC_IPC_KMSG_H_ */
