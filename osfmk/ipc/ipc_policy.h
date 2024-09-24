/*
 * Copyright (c) 2023 Apple Computer, Inc. All rights reserved.
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

#ifndef _IPC_IPC_POLICY_H_
#define _IPC_IPC_POLICY_H_

#include <ipc/ipc_types.h>
#include <ipc/ipc_port.h>

__BEGIN_DECLS __ASSUME_PTR_ABI_SINGLE_BEGIN
#pragma GCC visibility push(hidden)

/*!
 * @file <ipc/ipc_policy.h>
 *
 * @description
 * This file exports interfaces that implement various security policies
 * for Mach IPC.
 */


#pragma mark compile time globals and configurations

/*!
 * @const IPC_HAS_LEGACY_MACH_MSG_TRAP
 * Whether the legacy mach_msg_trap() is (somewhat) supported
 */
#if XNU_TARGET_OS_OSX || XNU_TARGET_OS_IOS
#define IPC_HAS_LEGACY_MACH_MSG_TRAP    1
#else
#define IPC_HAS_LEGACY_MACH_MSG_TRAP    0
#endif

/*!
 * @const IPC_KOBJECT_DESC_MAX
 * The maximum number of inline descriptors
 * allowed in an incoming MACH64_SEND_KOBJECT_CALL message.
 */
#define IPC_KOBJECT_DESC_MAX          3
/*!
 * @const IPC_KOBJECT_RDESC_MAX
 * The maximum number of inline descriptors
 * allowed in a reply to a MACH64_SEND_KOBJECT_CALL message.
 */
#define IPC_KOBJECT_RDESC_MAX        32

/*!
 * @const IPC_KMSG_MAX_BODY_SPACE
 * Maximum size of ipc kmsg body sizes (not including trailer or aux).
 */
#define IPC_KMSG_MAX_BODY_SPACE ((64 * 1024 * 1024 * 3) / 4 - MAX_TRAILER_SIZE)

/*!
 * @const IPC_KMSG_MAX_AUX_DATA_SPACE
 * Maximum size for the auxiliary data of an IPC kmsg.
 */
#define IPC_KMSG_MAX_AUX_DATA_SPACE  1024

/*!
 * @const IPC_KMSG_MAX_OOL_PORT_COUNT
 * The maximum number of ports that can be sent at once in a message.
 */
#define IPC_KMSG_MAX_OOL_PORT_COUNT  16383


#pragma mark policy utils

/*!
 * @brief
 * Implementation backend for ipc_unreachable() and friends.
 */
__abortlike
extern void __ipc_unreachable(
	const char *reason,
	const char *file,
	int         line);

/*!
 * @brief
 * Denote that a path is unreachable.
 *
 * @discussion
 * If this codepath is ever reached, it will reliably panic,
 * even on release kernels.
 */
#define ipc_unreachable(reason) \
	__ipc_unreachable(reason, __FILE_NAME__, __LINE__)

/*!
 * @brief
 * Performs an invariant check that stays on release kernels.
 */
#define ipc_release_assert(expr) \
	((expr) ? (void)0 : ipc_unreachable(#expr))


#pragma mark policy options

/*!
 * @brief
 * Derive the current policy flags for the current process.
 *
 * @discussion
 * This function will derive the proper in-kernel mach_msg options
 * from user specified flags and the current context.
 *
 * @param task          the current task
 * @param user_flags    flags passed in from userspace
 */
extern mach_msg_option64_t ipc_current_user_policy(
	task_t                  task,
	mach_msg_option64_t     user_flags);

/*!
 * @brief
 * Preflight send options for invalid combinations
 *
 * @discussion
 * If the send options have "obviously" incorrect parameters,
 * then a mach port guard exception (@c kGUARD_EXC_INVALID_OPTIONS) is raised.
 *
 * @param opts          the mach_msg() options, after sanitization
 *                      via @c ipc_current_user_policy().
 * @returns
 * - MACH_MSG_SUCCESS   success,
 * - MACH_SEND_INVALID_OPTIONS
 *                      for failure cases if MACH64_MACH_MSG2 is set
 * - KERN_NOT_SUPPORTED for failure cases if MACH64_MACH_MSG2 is not set
 */
extern mach_msg_return_t ipc_preflight_msg_option64(
	mach_msg_option64_t     opts);


#pragma mark legacy trap policies
#if IPC_HAS_LEGACY_MACH_MSG_TRAP

/*!
 * @brief
 * Whether the current task is allowed to use the legacy @c mach_msg_trap().
 *
 * @description
 * If using the legacy mach_msg_trap() is disallowed, this will raise
 * a mach port guard exception (@c kGUARD_EXC_INVALID_OPTIONS).
 *
 * Nothing should be locked.
 *
 * @param msgid         the message ID of the message being sent
 *                      with the legacy interface.
 * @param opts          the mach_msg() options passed to the legacy interface,
 *                      after sanitization via @c ipc_current_user_policy().
 * @returns
 * - MACH_MSG_SUCCESS   success,
 * - KERN_NOT_SUPPORTED for failure cases.
 */
extern mach_msg_return_t ipc_policy_allow_legacy_send_trap(
	mach_msg_id_t           msgid,
	mach_msg_option64_t     opts);


#endif /* IPC_HAS_LEGACY_MACH_MSG_TRAP */
#pragma mark reply port semantics telemetry [temporary]

extern void stash_reply_port_semantics_violations_telemetry(
	mach_service_port_info_t sp_info,
	int                     reply_port_semantics_violation,
	int                     msgh_id);


#pragma mark MACH_SEND_MSG policies

/*!
 * @brief
 * Validation function that runs after the message header bytes have been copied
 * from user, but before any other content or right is copied in.
 *
 * @discussion
 * Nothing should be locked.
 *
 * @param hdr           the user message header bytes, before anything
 *                      else has been copied in.
 * @param dsc_count     the number of inline descriptors for the user message.
 * @param opts          the mach_msg() options, after sanitization
 *                      via @c ipc_current_user_policy().
 *
 * @returns
 * - MACH_MSG_SUCCESS   the message passed validation
 * - MACH_SEND_TOO_LARGE
 *                      a MACH64_SEND_KOBJECT_CALL had too many descriptors.
 * - MACH_MSG_VM_KERNEL the message would use more than ipc_kmsg_max_vm_space
 *                      of kernel wired memory.
 */
extern mach_msg_return_t ipc_validate_kmsg_header_schema_from_user(
	mach_msg_user_header_t *hdr,
	mach_msg_size_t         dsc_count,
	mach_msg_option64_t     opts);

/*!
 * @brief
 * Validation function that runs after the message bytes has been copied from
 * user, but before any right is copied in.
 *
 * @discussion
 * Nothing should be locked.
 *
 * @param kdata         the "kernel data" part of the incoming message.
 *                      the descriptors data is copied in "kernel" format.
 * @param send_uctx     the IPC kmsg send context for the current send operation.
 * @param opts          the mach_msg() options, after sanitization
 *                      via @c ipc_current_user_policy().
 *
 * @returns
 * - MACH_MSG_SUCCESS   the message passed validation
 * - MACH_SEND_TOO_LARGE
 *                      a MACH64_SEND_KOBJECT_CALL had too many descriptors.
 * - MACH_MSG_VM_KERNEL the message would use more than ipc_kmsg_max_vm_space
 *                      of kernel wired memory.
 */
extern mach_msg_return_t ipc_validate_kmsg_schema_from_user(
	mach_msg_header_t      *kdata,
	mach_msg_send_uctx_t   *send_uctx,
	mach_msg_option64_t     opts);


/*!
 * @brief
 * Validation function that runs after the rights in the message header have
 * been copied in.
 *
 * @discussion
 * Nothing should be locked.
 *
 * @param hdr           the copied in message header.
 * @param send_uctx     the IPC kmsg send context for the current send operation.
 * @param opts          the mach_msg() options, after sanitization
 *                      via @c ipc_current_user_policy().
 * @returns
 * - MACH_MSG_SUCCESS   the message passed validation
 * - MACH_SEND_INVALID_OPTIONS
 *                      some options are incompatible with the destination
 *                      of the message. a kGUARD_EXC_INVALID_OPTIONS guard
 *                      will be raised.
 * - MACH_SEND_MSG_FILTERED
 *                      the message failed a filtering check.
 *                      a kGUARD_EXC_MSG_FILTERED guard might be raised.
 * - MACH_SEND_NO_GRANT_DEST
 *                      attempting to send descriptors to a no_grant port.
 */
extern mach_msg_return_t ipc_validate_kmsg_header_from_user(
	mach_msg_header_t      *hdr,
	mach_msg_send_uctx_t   *send_uctx,
	mach_msg_option64_t     opts);


#pragma GCC visibility pop
__ASSUME_PTR_ABI_SINGLE_END __END_DECLS

#endif  /* _IPC_IPC_POLICY_H_ */
