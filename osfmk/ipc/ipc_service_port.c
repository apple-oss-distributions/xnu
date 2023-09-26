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

#include <mach/port.h>
#include <mach/kern_return.h>
#include <kern/ipc_tt.h>
#include <ipc/ipc_port.h>
#include <kern/zalloc.h>
#include <kern/kalloc.h>
#include <kern/mach_param.h>
#include <mach/message.h>
#include <kern/mach_filter.h>
#include <ipc/ipc_service_port.h>
#include <security/mac_mach_internal.h>

#define XPC_DOMAIN_PORT 7 /* This value should match what is in <xpc/launch_private.h> */

ZONE_DEFINE_TYPE(ipc_service_port_label_zone, "ipc_service_port_label",
    struct ipc_service_port_label, ZC_ZFREE_CLEARMEM | ZC_NOCACHING);

#if CONFIG_SERVICE_PORT_INFO
const bool kdp_ipc_have_splabel = true;
#else
const bool kdp_ipc_have_splabel = false;
#endif

void
kdp_ipc_splabel_size(size_t *ispl_size, size_t *maxnamelen)
{
	*ispl_size = sizeof(struct ipc_service_port_label);
	*maxnamelen = MACH_SERVICE_PORT_INFO_STRING_NAME_MAX_BUF_LEN + 1;
}

void
kdp_ipc_fill_splabel(struct ipc_service_port_label *ispl,
    struct portlabel_info *spl, const char **namep)
{
#pragma unused(ispl, spl, namep)

	/* validate that ispl is in our zone */
#if CONFIG_SERVICE_PORT_INFO
	*namep = ispl->ispl_service_name;
	spl->portlabel_domain = ispl->ispl_domain;
	if (ipc_service_port_label_is_throttled(ispl)) {
		spl->portlabel_flags |= STACKSHOT_PORTLABEL_THROTTLED;
	}
#endif
}

/*
 * Name: ipc_service_port_label_alloc
 *
 * Description: Allocates the service port label
 *
 * Args:
 *   sp_info: service port string name, length, domain information
 *   send_side_filtering: indicates if the messages should be filtered during mach_msg_send
 *   port_label_ptr: used to return the allocated service_port_label
 *
 * Returns:
 *   KERN_SUCCESS
 */
kern_return_t
ipc_service_port_label_alloc(mach_service_port_info_t sp_info, void **port_label_ptr)
{
	ipc_service_port_label_t sp_label = IPC_SERVICE_PORT_LABEL_NULL;
	kern_return_t ret;
	void *sblabel = NULL;

	sp_label = zalloc(ipc_service_port_label_zone);

	if (mach_msg_filter_alloc_service_port_sblabel_callback) {
		ret = mach_msg_filter_alloc_service_port_sblabel_callback(sp_info, &sblabel);
		if (ret) {
			zfree(ipc_service_port_label_zone, sp_label);
			return ret;
		}
	}

	sp_label->ispl_sblabel = sblabel;
#if CONFIG_SERVICE_PORT_INFO
	size_t sp_string_name_len = strlen(sp_info->mspi_string_name);
	/* We could investigate compressing the names, but it doesn't seem worth it */
	sp_label->ispl_service_name = kalloc_data(sp_string_name_len + 1, Z_WAITOK);
	strlcpy(sp_label->ispl_service_name, sp_info->mspi_string_name, sp_string_name_len + 1);
	sp_label->ispl_domain = sp_info->mspi_domain_type;
#endif /* CONFIG_SERVICE_PORT_INFO */

	if (sp_info->mspi_domain_type == XPC_DOMAIN_PORT) {
		sp_label->ispl_flags |= ISPL_FLAGS_BOOTSTRAP_PORT;
	}
	*port_label_ptr = (void *)sp_label;
	return KERN_SUCCESS;
}

/*
 * Name: ipc_service_port_dealloc
 *
 * Description: Deallocates the service port label
 *
 * Args:
 *   ip_splabel: port's ip_splabel
 *
 * Returns: None
 *
 * Should not be called with the port lock held.
 */
void
ipc_service_port_label_dealloc(void *ip_splabel, bool service_port)
{
	void *sblabel = ip_splabel;

	if (service_port) {
		ipc_service_port_label_t sp_label = (ipc_service_port_label_t)ip_splabel;
		sblabel = sp_label->ispl_sblabel;
#if CONFIG_SERVICE_PORT_INFO
		kfree_data(sp_label->ispl_service_name, strlen(sp_label->ispl_service_name) + 1);
#endif /* CONFIG_SERVICE_PORT_INFO */
		zfree(ipc_service_port_label_zone, sp_label);
	}

	if (sblabel) {
		assert(mach_msg_filter_dealloc_service_port_sblabel_callback);
		mach_msg_filter_dealloc_service_port_sblabel_callback(sblabel);
	}
}

/*
 * Name: ipc_service_port_derive_sblabel
 *
 * Description: Derive the port's sandbox label using info from the service port's label
 *
 * Args:
 *   service_port_name: send right to a service port
 *   sblabel_ptr: used to return the allocated sblabel
 *
 * Returns:
 *   KERN_SUCCESS
 *   KERN_INVALID_NAME: service_port_name is mach_port_null or mach_port_dead
 *   KERN_INVALID_RIGHT: service_port_name is not a send right
 *   KERN_INVALID_CAPABILITY: service_port_name is not a right to a service port
 */
kern_return_t
ipc_service_port_derive_sblabel(mach_port_name_t service_port_name, void **sblabel_ptr, bool *filter_msgs)
{
	ipc_service_port_label_t port_label;
	void *derived_sblabel = NULL;
	void *sblabel = NULL;
	ipc_port_t port;
	kern_return_t kr;
	boolean_t send_side_filtering = FALSE;
#if CONFIG_MACF && XNU_TARGET_OS_OSX
	struct mach_service_port_info sp_info = {};
#endif

	if (!MACH_PORT_VALID(service_port_name)) {
		return KERN_INVALID_NAME;
	}

	if (mach_msg_filter_at_least(MACH_MSG_FILTER_CALLBACKS_VERSION_1)) {
		kr = ipc_port_translate_send(current_space(), service_port_name, &port);
		if (kr != KERN_SUCCESS) {
			return kr;
		}
		/* port is locked and active */

		if (ip_is_kolabeled(port) || !port->ip_service_port) {
			ip_mq_unlock(port);
			return KERN_INVALID_CAPABILITY;
		}

		port_label = (ipc_service_port_label_t)port->ip_splabel;
		if (!port_label) {
			ip_mq_unlock(port);
			return KERN_SUCCESS;
		}

#if CONFIG_MACF && XNU_TARGET_OS_OSX
		ipc_service_port_label_get_info(port_label, &sp_info);
#endif

		sblabel = port_label->ispl_sblabel;
		if (sblabel) {
			mach_msg_filter_retain_sblabel_callback(sblabel);
		}
		ip_mq_unlock(port);

		if (sblabel) {
			/* This callback will release the reference on sblabel */
			derived_sblabel = mach_msg_filter_derive_sblabel_from_service_port_callback(sblabel, &send_side_filtering);
		}

#if CONFIG_MACF && XNU_TARGET_OS_OSX
		if (sp_info.mspi_string_name[0] != '\0') {
			mac_proc_notify_service_port_derive(&sp_info);
		}
#endif
	}

	*sblabel_ptr = derived_sblabel;
	*filter_msgs = (bool)send_side_filtering;
	return KERN_SUCCESS;
}

/*
 * Name: ipc_service_port_get_sblabel
 *
 * Description: Get the port's sandbox label.
 *
 * Args:
 *   port
 *
 * Conditions:
 *   Should be called on an active port with the lock held.
 *
 * Returns:
 *   Sandbox label
 */
void *
ipc_service_port_get_sblabel(ipc_port_t port)
{
	void *sblabel = NULL;
	void *ip_splabel = NULL;

	if (port == IP_NULL) {
		return NULL;
	}

	ip_mq_lock_held(port);
	assert(ip_active(port));

	if (ip_is_kolabeled(port) || !port->ip_splabel) {
		return NULL;
	}

	ip_splabel = port->ip_splabel;

	if (!port->ip_service_port) {
		sblabel = ip_splabel;
		assert(sblabel != NULL);
	} else {
		ipc_service_port_label_t sp_label = (ipc_service_port_label_t)ip_splabel;
		sblabel = sp_label->ispl_sblabel;
	}

	return sblabel;
}

/*
 * Name: ipc_service_port_label_set_attr
 *
 * Description: Set the remaining port label attributes after port allocation
 *
 * Args:
 *   port_splabel
 *   name : port name in launchd's ipc space
 *   context : launchd's port guard; will be restored after a port destroyed notification if non-zero
 *
 * Conditions:
 *   Should be called only once in mach_port_construct on a newly created port with the lock held
 *   The context should be set only if the port is guarded.
 */
void
ipc_service_port_label_set_attr(ipc_service_port_label_t port_splabel, mach_port_name_t name, mach_port_context_t context)
{
	assert(port_splabel->ispl_launchd_name == MACH_PORT_NULL);
	port_splabel->ispl_launchd_name = name;
	port_splabel->ispl_launchd_context = context;
	if (context) {
		ipc_service_port_label_set_flag(port_splabel, ISPL_FLAGS_SPECIAL_PDREQUEST);
	}
}

/*
 * Name: ipc_service_port_label_get_attr
 *
 * Description: Get the port label attributes
 *
 * Args:
 *   port_splabel
 *   name : port name in launchd's ipc space
 *   context : launchd's port guard
 *
 * Conditions:
 *   Should be called with port lock held.
 */
void
ipc_service_port_label_get_attr(ipc_service_port_label_t port_splabel, mach_port_name_t *name, mach_port_context_t *context)
{
	*name = port_splabel->ispl_launchd_name;
	*context = port_splabel->ispl_launchd_context;
}

#if CONFIG_SERVICE_PORT_INFO
void
ipc_service_port_label_get_info(ipc_service_port_label_t port_splabel, mach_service_port_info_t info)
{
	info->mspi_domain_type = (uint8_t)port_splabel->ispl_domain;
	size_t sp_string_name_len = strlen(port_splabel->ispl_service_name);
	strlcpy(info->mspi_string_name, port_splabel->ispl_service_name, sp_string_name_len + 1);
}
#endif /* CONFIG_SERVICE_PORT_INFO */
