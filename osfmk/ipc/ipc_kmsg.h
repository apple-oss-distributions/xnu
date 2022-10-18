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
 *
 *	sync_qos and special_port_qos stores the qos for prealloced
 *	port, this fields could be deleted once we remove ip_prealloc.
 */

/* A kmsg can be in one of the following four layouts */
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
	 * An ipc_kmsg_vector_t follows the kmsg header specifying the address and
	 * size of the allocation. There is no aux data.
	 */
	IKM_TYPE_KDATA_OOL      = 2,
	/*
	 * IKM_TYPE_ALL_OOL: Everything is allocated out-of-line. Message header
	 * and descriptors are allocated from typed kernel heap (kalloc_type), and
	 * message data, trailer, and aux are in data buffer pointed to by ikm_udata.
	 * An ipc_kmsg_vector_t follows the kmsg header specifying the address and
	 * size of the kdata allocation.
	 */
	IKM_TYPE_ALL_OOL        = 3
});

struct ipc_kmsg {
	queue_chain_t              ikm_link;
	union {
		/* port we were preallocated from, for IKM_TYPE_ALL_INLINED */
		ipc_port_t XNU_PTRAUTH_SIGNED_PTR("kmsg.ikm_prealloc") ikm_prealloc;
		/* user data buffer, unused for IKM_TYPE_ALL_INLINED */
		void      *XNU_PTRAUTH_SIGNED_PTR("kmsg.ikm_udata")    ikm_udata;
	};
	ipc_port_t                 XNU_PTRAUTH_SIGNED_PTR("kmsg.ikm_voucher_port") ikm_voucher_port;   /* voucher port carried */
	struct ipc_importance_elem *ikm_importance;  /* inherited from */
	queue_chain_t              ikm_inheritance;  /* inherited from link */
#if MACH_FLIPC
	struct mach_node           *ikm_node;        /* originating node - needed for ack */
#endif
	mach_msg_size_t            ikm_aux_size;     /* size reserved for auxiliary data */
	uint32_t                   ikm_ppriority;    /* pthread priority of this kmsg */
	union {
		struct {
			/* For PAC-supported devices */
			uint32_t           ikm_sig_partial;  /* partial sig for header + trailer */
			uint32_t           ikm_sig_full;     /* upper 32 bits is full signature */
		};
		uint64_t               ikm_signature;    /* sig for all kernel-processed data */
	};
	ipc_object_copyin_flags_t  ikm_flags;
	mach_msg_qos_t             ikm_qos_override; /* qos override on this kmsg */

	mach_msg_type_name_t       ikm_voucher_type: 6; /* disposition type the voucher came in with */
	ipc_kmsg_type_t            ikm_type: 2;

	/* size of buffer pointed to by ikm_udata, unused for IKM_TYPE_ALL_INLINED. */
	mach_msg_size_t            ikm_udata_size;
	/* inline data of size IKM_SAVED_MSG_SIZE follows */
};

typedef struct {
	void                            *XNU_PTRAUTH_SIGNED_PTR("kmsgv.kmsgv_data") kmsgv_data;
	mach_msg_size_t                 kmsgv_size; /* size of buffer, or descriptor count */
} ipc_kmsg_vector_t;

/*
 * XXX	For debugging.
 */
#define IKM_BOGUS               ((ipc_kmsg_t) 0xffffff10)

/*
 *	The size of the kernel message buffers that will be cached.
 *	IKM_SAVED_KMSG_SIZE includes overhead; IKM_SAVED_MSG_SIZE doesn't.
 */
extern zone_t ipc_kmsg_zone;
#define IKM_SAVED_KMSG_SIZE     256
#define IKM_SAVED_MSG_SIZE      (IKM_SAVED_KMSG_SIZE - sizeof(struct ipc_kmsg))

#define ikm_prealloc_inuse_port(kmsg)                                   \
	((kmsg)->ikm_prealloc)

#define ikm_prealloc_inuse(kmsg)                                        \
	((kmsg)->ikm_prealloc != IP_NULL)

#define ikm_prealloc_set_inuse(kmsg, port)                              \
MACRO_BEGIN                                                             \
	assert((port) != IP_NULL);                                      \
	(kmsg)->ikm_prealloc = (port);                                  \
	ip_validate(port);                                              \
	ip_reference(port);                                             \
MACRO_END

#define ikm_prealloc_clear_inuse(kmsg)                            \
MACRO_BEGIN                                                             \
	(kmsg)->ikm_prealloc = IP_NULL;                                 \
MACRO_END

/*
 * Exported interfaces
 */
struct ipc_kmsg_queue {
	struct ipc_kmsg *ikmq_base;
};

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

extern bool ipc_kmsg_too_large(
	mach_msg_size_t         msg_size,
	mach_msg_size_t         aux_size,
	mach_msg_option64_t     options,
	mach_msg_size_t         max_msg_size,
	mach_msg_size_t         max_aux_size,
	thread_t                receiver);

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
	IPC_KMSG_ALLOC_USER     = 0x0000,
	IPC_KMSG_ALLOC_KERNEL   = 0x0001,

	IPC_KMSG_ALLOC_ZERO     = 0x0002,
	IPC_KMSG_ALLOC_SAVED    = 0x0004,
	IPC_KMSG_ALLOC_NOFAIL   = 0x0008,
	IPC_KMSG_ALLOC_LINEAR   = 0x0010,
});

/* Allocate a kernel message */
extern ipc_kmsg_t ipc_kmsg_alloc(
	mach_msg_size_t         msg_size,
	mach_msg_size_t         aux_size,
	mach_msg_size_t         user_descriptors,
	ipc_kmsg_alloc_flags_t  flags);

/* Free a kernel message buffer */
extern void ipc_kmsg_free(
	ipc_kmsg_t              kmsg);

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

/* bind a preallocated message buffer to a port */
extern void ipc_kmsg_set_prealloc(
	ipc_kmsg_t              kmsg,
	ipc_port_t              port);

/* get the unshifted message header of a kmsg */
extern mach_msg_header_t *ikm_header(
	ipc_kmsg_t         kmsg);

/* get the size of auxiliary data for a kmsg */
extern mach_msg_size_t ipc_kmsg_aux_data_size(
	ipc_kmsg_t              kmsg);

extern void ipc_kmsg_set_aux_data_header(
	ipc_kmsg_t              kmsg,
	mach_msg_aux_header_t   *header);

/* Allocate a kernel message buffer and copy a user message to the buffer */
extern mach_msg_return_t ipc_kmsg_get_from_user(
	mach_vm_address_t       msg_addr,
	mach_msg_size_t         user_msg_size,
	mach_vm_address_t       aux_addr,
	mach_msg_size_t         aux_size,
	mach_msg_user_header_t  user_header,
	mach_msg_size_t         desc_count,
	mach_msg_option64_t     option64,
	ipc_kmsg_t              *kmsgp);

/* Allocate a kernel message buffer and copy a kernel message to the buffer */
extern mach_msg_return_t ipc_kmsg_get_from_kernel(
	mach_msg_header_t       *msg,
	mach_msg_size_t         size,
	ipc_kmsg_t              *kmsgp);

/* Send a message to a port */
extern mach_msg_return_t ipc_kmsg_send(
	ipc_kmsg_t              kmsg,
	mach_msg_option64_t     option64,
	mach_msg_timeout_t      timeout_val);

/* Copy a kernel message buffer to a user message */
extern mach_msg_return_t ipc_kmsg_put_to_user(
	ipc_kmsg_t              kmsg,     /* scalar or vector */
	mach_msg_option64_t     option,
	mach_vm_address_t       rcv_msg_addr,
	mach_msg_size_t         max_msg_size,
	mach_vm_address_t       rcv_aux_addr,
	mach_msg_size_t         max_aux_size,
	mach_msg_size_t         trailer_size,
	mach_msg_size_t         *msg_sizep,
	mach_msg_size_t         *aux_sizep);

/* Copy a kernel message buffer to a kernel message */
extern void ipc_kmsg_put_to_kernel(
	mach_msg_header_t       *msg,
	ipc_kmsg_t              kmsg,
	mach_msg_size_t         size);

/* Copyin port rights and out-of-line memory from a user message */
extern mach_msg_return_t ipc_kmsg_copyin_from_user(
	ipc_kmsg_t              kmsg,
	ipc_space_t             space,
	vm_map_t                map,
	mach_msg_priority_t     priority,
	mach_msg_option64_t     *optionp,
	bool                    filter_nonfatal);

/* Copyin port rights and out-of-line memory from a kernel message */
extern mach_msg_return_t ipc_kmsg_copyin_from_kernel(
	ipc_kmsg_t              kmsg);

/* Copyout the header and body to a user message */
extern mach_msg_return_t ipc_kmsg_copyout(
	ipc_kmsg_t              kmsg,
	ipc_space_t             space,
	vm_map_t                map,
	mach_msg_option_t       option);

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
	mach_msg_option_t       option,
	thread_t                thread);

extern void ipc_kmsg_init_trailer(
	ipc_kmsg_t              kmsg,
	task_t                  sender);

extern void ipc_kmsg_add_trailer(
	ipc_kmsg_t              kmsg,
	ipc_space_t             space,
	mach_msg_option_t       option,
	thread_t                thread,
	mach_port_seqno_t       seqno,
	boolean_t               minimal_trailer,
	mach_vm_offset_t        context);

extern mach_msg_max_trailer_t *ipc_kmsg_get_trailer(
	ipc_kmsg_t              kmsg,
	bool                    body_copied_out);

extern void ipc_kmsg_set_voucher_port(
	ipc_kmsg_t              kmsg,
	ipc_port_t              voucher,
	mach_msg_type_name_t    type);

extern ipc_port_t ipc_kmsg_get_voucher_port(
	ipc_kmsg_t              kmsg);

extern void ipc_kmsg_clear_voucher_port(
	ipc_kmsg_t              kmsg);

extern void ipc_kmsg_validate_sig(
	ipc_kmsg_t              kmsg,
	bool                    partial);

#if (KDEBUG_LEVEL >= KDEBUG_LEVEL_STANDARD)
extern void ipc_kmsg_trace_send(
	ipc_kmsg_t              kmsg,
	mach_msg_option_t       option);
#else
#define ipc_kmsg_trace_send(a, b) do { } while (0)
#endif

#endif  /* _IPC_IPC_KMSG_H_ */
