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

#include <mach/std_types.h>
#include <mach/port.h>
#include <mach/mach_eventlink_types.h>
#include <mach_assert.h>

#include <mach/mach_types.h>
#include <mach/boolean.h>
#include <mach/kern_return.h>

#include <kern/assert.h>
#include <kern/kern_types.h>

#include <ipc/ipc_types.h>
#include <ipc/ipc_object.h>
#include <ipc/ipc_port.h>
#include <kern/waitq.h>
#include <os/refcnt.h>

#ifdef MACH_KERNEL_PRIVATE

__options_decl(ipc_service_port_label_flags_t, uint16_t, {
	ISPL_FLAGS_SPECIAL_PDREQUEST      = 1,/* Special port destroyed notification for service ports */
	ISPL_FLAGS_SEND_PD_NOTIFICATION   = (1 << 1),/* Port destroyed notification is being sent */
	ISPL_FLAGS_BOOTSTRAP_PORT         = (1 << 2),
	ISPL_FLAGS_THROTTLED              = (1 << 3),/* Service throttled by launchd */
});

struct ipc_service_port_label {
	void * XNU_PTRAUTH_SIGNED_PTR("ipc_service_port_label.ispl_sblabel") ispl_sblabel; /* points to the Sandbox's message filtering data structure */
	mach_port_context_t               ispl_launchd_context;     /* context used to guard the port, specific to launchd */
	mach_port_name_t                  ispl_launchd_name;        /* port name in launchd's ipc space */
	ipc_service_port_label_flags_t    ispl_flags;
#if CONFIG_SERVICE_PORT_INFO
	uint8_t             ispl_domain;             /* launchd domain */
	char                *ispl_service_name;       /* string name used to identify the service port */
#endif /* CONFIG_SERVICE_PORT_INFO */
};

typedef struct ipc_service_port_label* ipc_service_port_label_t;

#define IPC_SERVICE_PORT_LABEL_NULL ((ipc_service_port_label_t)NULL)

/*
 * These ispl_flags based macros/functions should be called with the port lock held
 */
#define ipc_service_port_label_is_special_pdrequest(port_splabel) \
    (((port_splabel)->ispl_flags & ISPL_FLAGS_SPECIAL_PDREQUEST) == ISPL_FLAGS_SPECIAL_PDREQUEST)

#define ipc_service_port_label_is_pd_notification(port_splabel) \
    (((port_splabel)->ispl_flags & ISPL_FLAGS_SEND_PD_NOTIFICATION) == ISPL_FLAGS_SEND_PD_NOTIFICATION)

#define ipc_service_port_label_is_bootstrap_port(port_splabel) \
    (((port_splabel)->ispl_flags & ISPL_FLAGS_BOOTSTRAP_PORT) == ISPL_FLAGS_BOOTSTRAP_PORT)

#define ipc_service_port_label_is_throttled(port_splabel) \
	(((port_splabel)->ispl_flags & ISPL_FLAGS_THROTTLED) == ISPL_FLAGS_THROTTLED)

static inline void
ipc_service_port_label_set_flag(ipc_service_port_label_t port_splabel, ipc_service_port_label_flags_t flag)
{
	assert(port_splabel != IPC_SERVICE_PORT_LABEL_NULL);
	port_splabel->ispl_flags |= flag;
}

static inline void
ipc_service_port_label_clear_flag(ipc_service_port_label_t port_splabel, ipc_service_port_label_flags_t flag)
{
	assert(port_splabel != IPC_SERVICE_PORT_LABEL_NULL);
	port_splabel->ispl_flags &= ~flag;
}

/* Function declarations */
kern_return_t
ipc_service_port_label_alloc(mach_service_port_info_t sp_info, void **port_label_ptr);

void
ipc_service_port_label_dealloc(void * ip_splabel, bool service_port);

kern_return_t
ipc_service_port_derive_sblabel(mach_port_name_t service_port_name, void **sblabel_ptr, bool *filter_msgs);

void *
ipc_service_port_get_sblabel(ipc_port_t port);

void
ipc_service_port_label_set_attr(ipc_service_port_label_t port_splabel, mach_port_name_t name, mach_port_context_t context);

void
ipc_service_port_label_get_attr(ipc_service_port_label_t port_splabel, mach_port_name_t *name, mach_port_context_t *context);

#if CONFIG_SERVICE_PORT_INFO
void
ipc_service_port_label_get_info(ipc_service_port_label_t port_splabel, mach_service_port_info_t info);
#endif /* CONFIG_SERVICE_PORT_INFO */

#endif /* MACH_KERNEL_PRIVATE */
#endif /* _IPC_IPC_SERVICE_PORT_H_ */
