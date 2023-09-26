/*
 * Copyright (c) 2022 Apple Inc. All rights reserved.
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

#ifndef _MACH_EXCLAVES_H
#define _MACH_EXCLAVES_H

#if defined(PRIVATE)

#include <os/base.h>
#include <mach/mach_types.h>

__BEGIN_DECLS

typedef uint64_t exclaves_id_t;
typedef uint64_t exclaves_tag_t;
typedef uint64_t exclaves_error_t;

#if !defined(KERNEL)

/*!
 * @function exclaves_endpoint_call
 *
 * @abstract
 * Perform RPC to an exclaves endpoint.
 *
 * @param port
 * Reserved, must be MACH_PORT_NULL for now.
 *
 * @param endpoint_id
 * Identifier of exclaves endpoint to send RPC to.
 *
 * @param msg_buffer
 * Pointer to exclaves IPC buffer.
 *
 * @param size
 * Size of specified exclaves IPC buffer.
 *
 * @param tag
 * In-out parameter for exclaves IPC tag.
 *
 * @param error
 * Out parameter for exclaves IPC error.
 *
 * @result
 * KERN_SUCCESS or mach system call error code.
 */
kern_return_t
exclaves_endpoint_call(mach_port_t port, exclaves_id_t endpoint_id,
    mach_vm_address_t msg_buffer, mach_vm_size_t size, exclaves_tag_t *tag,
    exclaves_error_t *error);

/*!
 * @function exclaves_named_buffer_create
 *
 * @abstract
 * Setup access by xnu to a pre-defined named exclaves shared memory buffer
 * and return a mach port for it.
 *
 * @param port
 * Reserved, must be MACH_PORT_NULL for now.
 *
 * @param buffer_id
 * Identifier of named buffer to operate on.
 *
 * @param size
 * Size of requested named buffer.
 *
 * @param named_buffer_port
 * Out parameter filled in with mach port name for the newly created named
 * buffer object, must be mach_port_deallocate()d to tear down the access to
 * the named buffer.
 *
 * @result
 * KERN_SUCCESS or mach system call error code.
 */
kern_return_t
exclaves_named_buffer_create(mach_port_t port, exclaves_id_t buffer_id,
    mach_vm_size_t size, mach_port_t* named_buffer_port);

/*!
 * @function exclaves_named_buffer_copyin
 *
 * @abstract
 * Copy from specified userspace buffer into previously setup named exclaves
 * shared memory buffer.
 *
 * @param named_buffer_port
 * A named buffer port name returned from exclaves_named_buffer_create()
 *
 * @param src_buffer
 * Pointer to userspace buffer to copy into named buffer.
 *
 * @param size
 * Number of bytes to copy (<= size of specified userspace buffer).
 *
 * @param offset
 * Offset in shared memory buffer to start copy at.
 *
 * @result
 * KERN_SUCCESS or mach system call error code.
 */
kern_return_t
exclaves_named_buffer_copyin(mach_port_t named_buffer_port,
    mach_vm_address_t src_buffer, mach_vm_size_t size, mach_vm_size_t offset);

/*!
 * @function exclaves_named_buffer_copyout
 *
 * @abstract
 * Copy out to specified userspace buffer from previously setup named exclaves
 * shared memory buffer.
 *
 * @param named_buffer_port
 * A named buffer port name returned from exclaves_named_buffer_create()
 *
 * @param dst_buffer
 * Pointer to userspace buffer to copy out from named buffer.
 *
 * @param size
 * Number of bytes to copy (<= size of specified userspace buffer).
 *
 * @param offset
 * Offset in shared memory buffer to start copy at.
 *
 * @result
 * KERN_SUCCESS or mach system call error code.
 */
kern_return_t
exclaves_named_buffer_copyout(mach_port_t named_buffer_port,
    mach_vm_address_t dst_buffer, mach_vm_size_t size, mach_vm_size_t offset);

/*!
 * @function exclaves_boot
 *
 * @abstract
 * Perform exclaves boot.
 *
 * @param port
 * Reserved, must be MACH_PORT_NULL for now.
 *
 * @param flags
 * Reserved, must be 0 for now.
 *
 * @result
 * KERN_SUCCESS or mach system call error code.
 */
kern_return_t
exclaves_boot(mach_port_t port, uint64_t flags);

#else /* defined(KERNEL) */

/*!
 * @function exclaves_endpoint_call
 *
 * @abstract
 * Perform RPC to an exclaves endpoint via per-thread exclaves IPC buffer.
 *
 * @param port
 * Reserved, must be IPC_PORT_NULL for now.
 *
 * @param endpoint_id
 * Identifier of exclaves endpoint to send RPC to.
 *
 * @param tag
 * In-out parameter for exclaves IPC tag.
 *
 * @param error
 * Out parameter for exclaves IPC error.
 *
 * @result
 * KERN_SUCCESS or mach error code.
 */
kern_return_t
exclaves_endpoint_call(ipc_port_t port, exclaves_id_t endpoint_id,
    exclaves_tag_t *tag, exclaves_error_t *error);

/*!
 * @function exclaves_allocate_ipc_buffer
 *
 * @abstract
 * If necessary, allocate per-thread exclaves IPC buffer.
 *
 * @param ipc_buffer
 * Out parameter filled in with address of IPC buffer. Can be NULL.
 *
 * @result
 * KERN_SUCCESS or mach error code.
 */
kern_return_t
exclaves_allocate_ipc_buffer(void **ipc_buffer);

/*!
 * @function exclaves_free_ipc_buffer
 *
 * @abstract
 * If necessary, free per-thread exclaves IPC buffer.
 *
 * @result
 * KERN_SUCCESS or mach error code.
 */
kern_return_t
exclaves_free_ipc_buffer(void);

/*!
 * @function exclaves_get_ipc_buffer
 *
 * @abstract
 * Return per-thread exclaves IPC buffer.
 *
 * @result
 * If allocated, pointer to per-thread exclaves IPC buffer, NULL otherwise.
 */
OS_CONST
void*
exclaves_get_ipc_buffer(void);

/* For use by Tightbeam kernel runtime only */

typedef uint64_t exclaves_badge_t;

/*!
 * @typedef exclaves_upcall_handler_t
 *
 * @abstract
 * RPC message handler for upcalls from exclaves via per-thread exclaves IPC
 * buffer.
 *
 * @param context
 * Opaque context pointer specified at handler registration.
 *
 * @param tag
 * In-out parameter for exclaves IPC tag.
 *
 * @param badge
 * Badge value identifying upcall RPC message.
 *
 * @result
 * KERN_SUCCESS or mach error code.
 */
typedef kern_return_t
(*exclaves_upcall_handler_t)(void *context, exclaves_tag_t *tag,
    exclaves_badge_t badge);

/*!
 * @function exclaves_register_upcall_handler
 *
 * @abstract
 * One-time registration of exclaves upcall RPC handler for specified upcall ID.
 * Must be called during Exclaves boot sequence, will assert otherwise.
 *
 * @param upcall_id
 * Identifier of upcall to configure.
 *
 * @param upcall_context
 * Opaque context pointer to pass to upcall RPC handler.
 *
 * @param upcall_handler
 * Pointer to upcall RPC handler.
 *
 * @result
 * KERN_SUCCESS or mach error code.
 */
kern_return_t
exclaves_register_upcall_handler(exclaves_id_t upcall_id, void *upcall_context,
    exclaves_upcall_handler_t upcall_handler);

struct XrtHosted_Callbacks;

/*!
 * @function xrt_hosted_register_callbacks
 *
 * @abstract
 * Exclaves XRT hosted kext interface.
 *
 * @param callbacks
 * Pointer to callback function table.
 */
void
exclaves_register_xrt_hosted_callbacks(struct XrtHosted_Callbacks *callbacks);

#endif /* defined(KERNEL) */

#if defined(MACH_KERNEL_PRIVATE)

/* -------------------------------------------------------------------------- */

/* Internal kernel interface */

kern_return_t
exclaves_thread_terminate(thread_t thread);

kern_return_t
exclaves_boot(ipc_port_t port, uint64_t flags);

#endif /* defined(MACH_KERNEL_PRIVATE) */

/* -------------------------------------------------------------------------- */

/* Private interface between Libsyscall and xnu */

OS_ENUM(exclaves_ctl_op, uint8_t,
    EXCLAVES_CTL_OP_ENDPOINT_CALL = 1,
    EXCLAVES_CTL_OP_NAMED_BUFFER_CREATE = 2,
    EXCLAVES_CTL_OP_NAMED_BUFFER_COPYIN = 3,
    EXCLAVES_CTL_OP_NAMED_BUFFER_COPYOUT = 4,
    EXCLAVES_CTL_OP_BOOT = 5,
    EXCLAVES_CTL_OP_LAST,
    );
#define EXCLAVES_CTL_FLAGS_MASK (0xfffffful)
#define EXCLAVES_CTL_OP_AND_FLAGS(op, flags) \
	((uint32_t)EXCLAVES_CTL_OP_##op << 24 | \
	((uint32_t)(flags) & EXCLAVES_CTL_FLAGS_MASK))
#define EXCLAVES_CTL_OP(op_and_flags) \
	((uint8_t)((op_and_flags) >> 24))
#define EXCLAVES_CTL_FLAGS(op_and_flags) \
	((uint32_t)(op_and_flags) & EXCLAVES_CTL_FLAGS_MASK)

#if !defined(KERNEL)

OS_NOT_TAIL_CALLED
kern_return_t
_exclaves_ctl_trap(mach_port_name_t name, uint32_t operation_and_flags,
    exclaves_id_t identifier, mach_vm_address_t buffer, mach_vm_size_t size);

#endif /* !defined(KERNEL) */

/* -------------------------------------------------------------------------- */

/* Sysctl interface */

OS_ENUM(exclaves_status, uint8_t,
    EXCLAVES_STATUS_NOT_STARTED = 0x00,
    EXCLAVES_STATUS_AVAILABLE = 0x01,
    EXCLAVES_STATUS_FAILED = 0xFE,
    EXCLAVES_STATUS_NOT_SUPPORTED = 0xFF,
    );

#if defined(KERNEL)

/*!
 * @function exclaves_get_status
 *
 * @abstract
 * Return the current running status of exclaves.
 *
 * @result
 * The status of exclaves.
 */
exclaves_status_t
exclaves_get_status(void);

#endif /* defined(KERNEL) */

__END_DECLS

#endif /* defined(PRIVATE) */

#endif /* _MACH_EXCLAVES_H */
