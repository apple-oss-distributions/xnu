/*
 * Copyright (c) 2000-2019 Apple Computer, Inc. All rights reserved.
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

#ifndef _IPC_IPC_SERVICE_PORT_H_
#define _IPC_IPC_SERVICE_PORT_H_

#include <ipc/ipc_types.h>
#include <ipc/ipc_port.h>

#ifdef MACH_KERNEL_PRIVATE

#define XPC_DOMAIN_PORT 7 /* This value should match what is in <xpc/launch_private.h> */

struct ipc_service_port_label {
	/* points to the Sandbox's message filtering data structure */
	struct ipc_conn_port_label *XNU_PTRAUTH_SIGNED_PTR_AUTH_NULL("ipc_service_port_label.ispl_sblabel") ispl_sblabel;
	mach_port_context_t     ispl_launchd_context;     /* context used to guard the port, specific to launchd */
	mach_port_name_t        ispl_launchd_name;        /* port name in launchd's ipc space */
	uint8_t                 ispl_throttled : 1;       /* service throttled by launchd */
	uint8_t                 __ispl_unused : 7;
#if CONFIG_SERVICE_PORT_INFO
	uint8_t                 ispl_domain;             /* launchd domain */
	char                   *ispl_service_name;       /* string name used to identify the service port */
#endif /* CONFIG_SERVICE_PORT_INFO */
};

typedef struct ipc_service_port_label *ipc_service_port_label_t;

struct ipc_bootstrap_port_label {
	/* points to the Sandbox's message filtering data structure */
	struct ipc_conn_port_label *XNU_PTRAUTH_SIGNED_PTR_AUTH_NULL("ipc_service_port_label.ispl_sblabel") ispl_sblabel;
#if CONFIG_SERVICE_PORT_INFO
	char                   *ispl_service_name;       /* string name used to identify the service port */
#endif /* CONFIG_SERVICE_PORT_INFO */
};

typedef struct ipc_bootstrap_port_label *ipc_bootstrap_port_label_t;

/* Function declarations */
extern kern_return_t ipc_service_port_label_alloc(
	mach_service_port_info_t sp_info,
	ipc_object_label_t     *label);

extern kern_return_t ipc_bootstrap_port_label_alloc(
	mach_service_port_info_t sp_info,
	ipc_object_label_t     *label);

extern void ipc_connection_port_label_dealloc(
	ipc_object_label_t      label);

extern void ipc_service_port_label_dealloc(
	ipc_object_label_t      label);

extern void ipc_bootstrap_port_label_dealloc(
	ipc_object_label_t      label);

extern kern_return_t ipc_service_port_derive_sblabel(
	mach_port_name_t        service_port_name,
	ipc_object_label_t     *label,
	mpo_flags_t             flags);

extern void ipc_service_port_label_set_attr(
	ipc_service_port_label_t port_splabel,
	mach_port_name_t        name,
	mach_port_context_t     context);

#if CONFIG_SERVICE_PORT_INFO

extern void ipc_service_port_label_get_info(
	ipc_service_port_label_t port_splabel,
	mach_service_port_info_t info);

extern void ipc_bootstrap_port_label_get_info(
	ipc_bootstrap_port_label_t port_bplabel,
	mach_service_port_info_t info);

extern bool ip_is_report_crash_service_port_locked(
	ipc_object_label_t port_label);

#endif /* CONFIG_SERVICE_PORT_INFO */
#endif /* MACH_KERNEL_PRIVATE */
#endif /* _IPC_IPC_SERVICE_PORT_H_ */
