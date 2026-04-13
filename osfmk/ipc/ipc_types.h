/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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
 * Define Basic IPC types available to callers.
 * These are not intended to be used directly, but
 * are used to define other types available through
 * port.h and mach_types.h for in-kernel entities.
 */

#ifndef _IPC_IPC_TYPES_H_
#define _IPC_IPC_TYPES_H_

#include <mach/port.h>
#include <mach/message.h>
#include <mach/mach_types.h>

#ifdef  MACH_KERNEL_PRIVATE

typedef natural_t ipc_table_index_t;    /* index into tables */
typedef natural_t ipc_table_elems_t;    /* size of tables */
typedef natural_t ipc_entry_bits_t;
typedef ipc_table_elems_t ipc_entry_num_t;      /* number of entries */
typedef ipc_table_index_t ipc_port_request_index_t;

typedef mach_port_name_t mach_port_index_t;             /* index values */
typedef mach_port_name_t mach_port_gen_t;               /* generation numbers */

typedef struct ipc_entry *ipc_entry_t;

typedef struct ipc_table_size *ipc_table_size_t;
typedef struct ipc_port_request *ipc_port_request_t;
typedef struct ipc_pset *ipc_pset_t;
typedef struct ipc_kmsg *ipc_kmsg_t;
typedef uint8_t sync_qos_count_t;

typedef uint64_t ipc_label_t;
#define IPC_LABEL_NONE          ((ipc_label_t)0x0000)
#define IPC_LABEL_DEXT          ((ipc_label_t)0x0001)
#define IPC_LABEL_PLATFORM      ((ipc_label_t)0x0002)
#define IPC_LABEL_SPECIAL       ((ipc_label_t)0x0003)
#define IPC_LABEL_SPACE_MASK    ((ipc_label_t)0x00ff)

#define IPC_LABEL_SUBST_TASK_READ   ((ipc_label_t)0x0400)
#define IPC_LABEL_SUBST_THREAD_READ ((ipc_label_t)0x0500)
#define IPC_LABEL_SUBST_MASK        ((ipc_label_t)0xff00)

typedef struct ipc_kobject_label *ipc_kobject_label_t;

#define IE_NULL ((ipc_entry_t)NULL)

#define ITS_NULL        ((ipc_table_size_t)NULL)
#define ITS_SIZE_NONE   ((ipc_table_elems_t) -1)
#define IPR_NULL        ((ipc_port_request_t)NULL)
#define IPS_NULL        ((ipc_pset_t)NULL)
#define IKM_NULL        ((ipc_kmsg_t)NULL)

typedef void (*mach_msg_continue_t)(mach_msg_return_t); /* after wakeup */
#define MACH_MSG_CONTINUE_NULL  ((mach_msg_continue_t)NULL)

typedef struct ipc_importance_elem *__single ipc_importance_elem_t;
#define IIE_NULL        ((ipc_importance_elem_t)NULL)

typedef struct ipc_importance_task *__single ipc_importance_task_t;
#define IIT_NULL        ((ipc_importance_task_t)NULL)

typedef struct ipc_importance_inherit *__single ipc_importance_inherit_t;
#define III_NULL        ((ipc_importance_inherit_t)NULL)

/*!
 * @typedef ipc_space_policy_t
 *
 * @brief
 * Flags used to determine the IPC policy for a given task/space.
 *
 * @const IPC_SPACE_POLICY_INVALID
 * This policy is never used, the zero value is never a valid policy.
 *
 * @const IPC_SPACE_POLICY_DEFAULT
 * Denotes that this task has the default policy.
 * This bit is always set in a properly inited policy.
 *
 * @const IPC_SPACE_POLICY_ENHANCED
 * Denotes an IPC space for a task that has opted in some way to receive more
 * security. The "enhanced" security space has several versions for bincompat
 * reasons, where each increasing version opts you into more security features.
 * `ENHANCED_V0` includes those opted into macOS hardened runtime
 * `ENHANCED_V1` includes those opted into browser entitlements (FY24)
 * `ENHANCED_V2` includes those opted into the FY25 platform restrictions entitlement
 * No new features should be placed into the previous versions for bincompat
 * reasons, and binaries opted into the newer versions always get the features
 * from all previous versions.
 *
 * @const IPC_SPACE_POLICY_PLATFORM
 * Denotes an IPC space for a platform binary. This flag always implies
 * @c IPC_SPACE_POLICY_ENHANCED is set, meaning platform binaries always get the
 * highest version of platform restrictions.
 *
 * @const IPC_SPACE_POLICY_KERNEL
 * Denotes that this is the IPC space for the kernel.
 *
 * @const IPC_SPACE_POLICY_SIMULATED
 * Denotes IPC spaces for simulator environments (macOS only).
 * In general this bit will cause policies to be relaxed because software
 * running in these environment was written before policies were made,
 * and probably do not comply with them naturally.
 *
 * @const IPC_SPACE_POLICY_TRANSLATED
 * Denotes IPC spaces for translated environments (macOS only).
 * Similarly to @c IPC_SPACE_POLICY_SIMULATED, processes running in a Rosetta
 * environment are likely older software that predate policy changes,
 * and these processes tend to be opted out of certain policies as a result.
 */

__options_closed_decl(ipc_space_policy_t, uint32_t, {
	IPC_SPACE_POLICY_INVALID       = 0x0000,

	/* Security level */
	IPC_SPACE_POLICY_DEFAULT       = 0x0001, /* MACH64_POLICY_DEFAULT */
	IPC_SPACE_POLICY_ENHANCED      = 0x0002,
	IPC_SPACE_POLICY_PLATFORM      = 0x0004,
	IPC_SPACE_POLICY_CONTAINED     = 0x0008,
	IPC_SPACE_POLICY_KERNEL        = 0x0010,

	/* flags to turn off security */
#if XNU_TARGET_OS_OSX
	IPC_SPACE_POLICY_SIMULATED     = 0x0020,
#else
	IPC_SPACE_POLICY_SIMULATED     = 0x0000,
#endif
#if CONFIG_ROSETTA
	IPC_SPACE_POLICY_TRANSLATED    = 0x0040,
#else
	IPC_SPACE_POLICY_TRANSLATED    = 0x0000,
#endif
#if XNU_TARGET_OS_OSX
	IPC_SPACE_POLICY_OPTED_OUT     = 0x0080,
#else
	IPC_SPACE_POLICY_OPTED_OUT     = 0x0000,
#endif


	IPC_SPACE_POLICY_MASK          = (
		IPC_SPACE_POLICY_DEFAULT |
		IPC_SPACE_POLICY_ENHANCED |
		IPC_SPACE_POLICY_PLATFORM |
		IPC_SPACE_POLICY_CONTAINED |
		IPC_SPACE_POLICY_KERNEL |
		IPC_SPACE_POLICY_SIMULATED |
		IPC_SPACE_POLICY_TRANSLATED |
		IPC_SPACE_POLICY_OPTED_OUT),


/* platform restrictions Versioning Levels */
	IPC_SPACE_POLICY_ENHANCED_V0 = 0x100,   /* DEPRECATED - includes macos hardened runtime */
	IPC_SPACE_POLICY_ENHANCED_V1 = 0x200,   /* ES features exposed to 3P in FY2024 release */
	IPC_SPACE_POLICY_ENHANCED_V2 = 0x300,   /* ES features exposed to 3P in FY2025 release */
	IPC_SPACE_POLICY_ENHANCED_V3 = 0x400,   /* ES features exposed to 3P in FY2026 release */
	IPC_SPACE_POLICY_ENHANCED_VERSION_MASK = (
		IPC_SPACE_POLICY_ENHANCED_V0 |
		IPC_SPACE_POLICY_ENHANCED_V1 |
		IPC_SPACE_POLICY_ENHANCED_V2 |
		IPC_SPACE_POLICY_ENHANCED_V3
		),
});

#define IPC_SPACE_POLICY_BASE(prefix) \
	prefix ## _DEFAULT      = IPC_SPACE_POLICY_DEFAULT,                     \
	prefix ## _ENHANCED     = IPC_SPACE_POLICY_ENHANCED,                    \
	prefix ## _PLATFORM     = IPC_SPACE_POLICY_PLATFORM,                    \
	prefix ## _CONTAINED    = IPC_SPACE_POLICY_CONTAINED,                   \
	prefix ## _KERNEL       = IPC_SPACE_POLICY_KERNEL,                      \
	prefix ## _SIMULATED    = IPC_SPACE_POLICY_SIMULATED,                   \
	prefix ## _TRANSLATED   = IPC_SPACE_POLICY_TRANSLATED,                  \
	prefix ## _MASK         = IPC_SPACE_POLICY_MASK

#else   /* MACH_KERNEL_PRIVATE */

struct ipc_object;

#endif  /* MACH_KERNEL_PRIVATE */
#if XNU_KERNEL_PRIVATE

/*!
 * @brief
 * Type for IPC objects
 *
 * @discussion
 * This type is non ABI stable, and limited to XNU internally.
 * Please keep this type ordered semantically for readability purposes.
 *
 * When adding types here, update @c mach_port_kobject_type() which maps
 * these values to the previously stable legacy IKOT_* values for the sake
 * of userspace (and tools like lsmp(1)).
 */
__enum_decl(ipc_object_type_t, uint8_t, {
	/*
	 * Object is a port set (see <ipc/ipc_pset.h>).
	 */
	IOT_PORT_SET,

	/*
	 * Catchall type for generic ports.
	 */
	IOT_PORT,

	/*
	 * Service/Connection ports
	 */
	IOT_SERVICE_PORT,
	IOT_BOOTSTRAP_PORT,
	IOT_WEAK_SERVICE_PORT,
	IOT_CONNECTION_PORT,
	IOT_CONNECTION_PORT_WITH_PORT_ARRAY,

	/*
	 * Notification ports
	 */
	IOT_NOTIFICATION_PORT,
	IOT_EXCEPTION_PORT,
	IOT_TIMER_PORT,

	/*
	 * Reply Ports
	 */
	IOT_REPLY_PORT,
	IOT_SPECIAL_REPLY_PORT,
	IOT_WEAK_REPLY_PORT,

	/*
	 * IPC Kernel Object types
	 *
	 * Matching entries must be added to <mach_debug/ipc_info.h>,
	 * and case labels to mach_port_kobject_type().
	 */
	__IKOT_FIRST,

	/* thread ports */
	IKOT_THREAD_CONTROL = __IKOT_FIRST,
	IKOT_THREAD_READ,
	IKOT_THREAD_INSPECT,
	IKOT_THREAD_RESUME,

	/* task ports */
	IKOT_TASK_CONTROL,
	IKOT_TASK_READ,
	IKOT_TASK_INSPECT,
	IKOT_TASK_NAME,

	IKOT_TASK_RESUME,
	IKOT_TASK_ID_TOKEN,
	IKOT_TASK_FATAL,                /* CONFIG_PROC_RESOURCE_LIMITS only */

	/* host services */
	IKOT_HOST,
	IKOT_HOST_PRIV,
	IKOT_CLOCK,
	IKOT_PROCESSOR,
	IKOT_PROCESSOR_SET,
	IKOT_PROCESSOR_SET_NAME,

	/* common userspace used ports */
	IKOT_EVENTLINK,
	IKOT_FILEPORT,
	IKOT_SEMAPHORE,
	IKOT_VOUCHER,
	IKOT_WORK_INTERVAL,

	/* VM ports */
	IKOT_MEMORY_OBJECT,
	IKOT_NAMED_ENTRY,

	/* IOKit & exclaves ports */
	IKOT_MAIN_DEVICE,
	IKOT_IOKIT_IDENT,
	IKOT_IOKIT_CONNECT,
	IKOT_IOKIT_OBJECT,
	IKOT_UEXT_OBJECT,
	IKOT_EXCLAVES_RESOURCE,         /* CONFIG_EXCLAVES only */

	/* misc. */
	IKOT_ARCADE_REG,                /* CONFIG_ARCADE only */
	IKOT_AU_SESSIONPORT,            /* CONFIG_AUDIT only */
	IKOT_HYPERVISOR,                /* HYPERVISOR only */
	IKOT_KCDATA,
	IKOT_UND_REPLY,                 /* CONFIG_USER_NOTIFICATION only */
	IKOT_UX_HANDLER,

	/* catchall, keep last */
	IOT_UNKNOWN,
	IOT_ANY = 0xff,
});

#endif  /* XNU_KERNEL_PRIVATE */

typedef struct ipc_object       *ipc_object_t;

#define IPC_OBJECT_NULL         ((ipc_object_t) 0)
#define IPC_OBJECT_DEAD         ((ipc_object_t)~0)
#define IPC_OBJECT_VALID(io)    (((io) != IPC_OBJECT_NULL) && \
	                         ((io) != IPC_OBJECT_DEAD))

#endif  /* _IPC_IPC_TYPES_H_ */
