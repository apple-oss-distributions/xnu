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

#include <kern/block_hint.h>
#include <kern/kalloc.h>
#include <kern/mach_filter.h>
#include <kern/task.h>
#include <ipc/ipc_service_port.h>
#include <security/mac_mach_internal.h>

ZONE_DEFINE_TYPE(ipc_service_port_label_zone, "ipc_service_port_label",
    struct ipc_service_port_label, ZC_ZFREE_CLEARMEM | ZC_NOCACHING);

ZONE_DEFINE_TYPE(ipc_bootstrap_port_label_zone, "ipc_bootstrap_port_label",
    struct ipc_bootstrap_port_label, ZC_ZFREE_CLEARMEM | ZC_NOCACHING);

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
	if (ispl->ispl_throttled) {
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
 *   port_label_ptr: used to return the allocated service_port_label
 *
 * Returns:
 *   KERN_SUCCESS
 *   KERN_FAILURE: sandbox failed to alloc sblabel
 */
kern_return_t
ipc_service_port_label_alloc(
	mach_service_port_info_t sp_info,
	ipc_object_label_t     *label)
{
	ipc_service_port_label_t sp_label = NULL;
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

	label->iol_service = sp_label;
	if (sblabel) {
		/* always filter service ports with a label */
		label->io_filtered = true;
	}

	return KERN_SUCCESS;
}

/*
 * Name: ipc_bootstrap_port_label_alloc
 *
 * Description: Allocates the bootstrap port label
 *
 * Args:
 *   sp_info: service port string name, length, domain information
 *   port_label_ptr: used to return the allocated bootstrap_port_label
 *
 * Returns:
 *   KERN_SUCCESS
 *   KERN_FAILURE: sandbox failed to alloc sblabel
 */
kern_return_t
ipc_bootstrap_port_label_alloc(
	mach_service_port_info_t sp_info,
	ipc_object_label_t     *label)
{
	ipc_bootstrap_port_label_t bp_label = NULL;
	kern_return_t ret;
	void *sblabel = NULL;

	bp_label = zalloc(ipc_bootstrap_port_label_zone);

	if (mach_msg_filter_alloc_service_port_sblabel_callback) {
		ret = mach_msg_filter_alloc_service_port_sblabel_callback(sp_info, &sblabel);
		if (ret) {
			zfree(ipc_bootstrap_port_label_zone, bp_label);
			return ret;
		}
	}

	bp_label->ispl_sblabel = sblabel;
#if CONFIG_SERVICE_PORT_INFO
	size_t sp_string_name_len = strlen(sp_info->mspi_string_name);
	/* We could investigate compressing the names, but it doesn't seem worth it */
	bp_label->ispl_service_name = kalloc_data(sp_string_name_len + 1, Z_WAITOK);
	strlcpy(bp_label->ispl_service_name, sp_info->mspi_string_name, sp_string_name_len + 1);
#endif /* CONFIG_SERVICE_PORT_INFO */

	label->iol_bootstrap = bp_label;
	if (sblabel) {
		/* always filter service ports with a label */
		label->io_filtered = true;
	}

	return KERN_SUCCESS;
}

void
ipc_connection_port_label_dealloc(ipc_object_label_t label)
{
	mach_msg_filter_dealloc_service_port_sblabel_callback(label.iol_connection);
}

/*
 * Name: ipc_service_port_dealloc
 *
 * Description: Deallocates the service port label
 *
 * Args:
 *   label: port's label
 *
 * Returns: None
 *
 * Should not be called with the port lock held.
 */
void
ipc_service_port_label_dealloc(ipc_object_label_t label)
{
	ipc_service_port_label_t sp_label = label.iol_service;
	void *sblabel = sp_label->ispl_sblabel;

#if CONFIG_SERVICE_PORT_INFO
	kfree_data(sp_label->ispl_service_name, strlen(sp_label->ispl_service_name) + 1);
#endif /* CONFIG_SERVICE_PORT_INFO */
	zfree(ipc_service_port_label_zone, sp_label);

	if (sblabel) {
		mach_msg_filter_dealloc_service_port_sblabel_callback(sblabel);
	}
}

/*
 * Name: ipc_bootstrap_port_label_dealloc
 *
 * Description: Deallocates the bootstrap port label
 *
 * Args:
 *   label: port's label
 *
 * Returns: None
 *
 * Should not be called with the port lock held.
 */
void
ipc_bootstrap_port_label_dealloc(ipc_object_label_t label)
{
	ipc_bootstrap_port_label_t bp_label = label.iol_bootstrap;
	void *sblabel = bp_label->ispl_sblabel;

#if CONFIG_SERVICE_PORT_INFO
	kfree_data(bp_label->ispl_service_name, strlen(bp_label->ispl_service_name) + 1);
#endif /* CONFIG_SERVICE_PORT_INFO */
	zfree(ipc_bootstrap_port_label_zone, bp_label);

	if (sblabel) {
		mach_msg_filter_dealloc_service_port_sblabel_callback(sblabel);
	}
}

#if CONFIG_MACF && XNU_TARGET_OS_OSX
__static_testable __mockable bool
ipc_service_port_string_name_is_empty(struct mach_service_port_info *sp_info)
{
	return sp_info->mspi_string_name[0] == '\0';
}
#endif /* CONFIG_MACF && XNU_TARGET_OS_OSX */

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
ipc_service_port_derive_sblabel(
	mach_port_name_t        service_port_name,
	ipc_object_label_t     *label,
	mpo_flags_t             flags)
{
	ipc_port_t port;
	kern_return_t kr;
	bool force_filtering = !!(flags & MPO_FILTER_MSG);
	/*
	 * In a libxpc connection, there is a foward channel for client to send
	 * to server, and a backward channel for server to send to client.
	 *
	 * Prior to rdar://143008067, only the port in the forward channel is
	 * created as a connection port, calling ipc_service_port_derive_sblabel
	 * only once per connection.
	 *
	 * With rdar://143008067, the port in the backward channel is now created
	 * as a connection port. This introduced a regression where we are now
	 * duplicating callouts to ES and sandbox for every connection and break
	 * their semantics. To fix that, we identify the forward channel by
	 * checking the absence of MPO_IMMOVABLE_RECEIVE and do the callouts
	 * in the forward channel only.
	 *
	 * Note: it is more secure to identify the forward channel by the absence
	 * of MPO_IMMOVABLE_RECEIVE, such that attackers can't bypass ES and
	 * sandbox by not passing certain MPO flags.
	 */
	bool is_forward_connection_channel = !(flags & MPO_IMMOVABLE_RECEIVE);
#if CONFIG_MACF && XNU_TARGET_OS_OSX
	struct mach_service_port_info sp_info = {};
#endif

	if (!MACH_PORT_VALID(service_port_name)) {
		return KERN_INVALID_NAME;
	}

	if (mach_msg_filter_at_least(MACH_MSG_FILTER_CALLBACKS_VERSION_1)) {
		ipc_object_label_t sp_label;
		boolean_t send_side_filtering;
		void *sblabel = NULL;

		kr = ipc_port_translate_send(current_space(), service_port_name, &port);
		if (kr != KERN_SUCCESS) {
			return kr;
		}
		/* port is locked and active */

		sp_label = ip_label_get(port);
		if (!ip_is_any_service_port_type(sp_label.io_type)) {
			ip_mq_unlock_label_put(port, &sp_label);
			return KERN_INVALID_CAPABILITY;
		}

#if CONFIG_MACF && XNU_TARGET_OS_OSX
		ipc_service_port_label_get_info(sp_label.iol_service, &sp_info);
#endif

		if (is_forward_connection_channel) {
			sblabel = sp_label.iol_service->ispl_sblabel;
		}

		if (sblabel) {
			mach_msg_filter_retain_sblabel_callback(sblabel);
		}
		ip_mq_unlock_label_put(port, &sp_label);

		if (sblabel) {
			/* This callback will release the reference on sblabel */
			label->iol_connection = mach_msg_filter_derive_sblabel_from_service_port_callback(sblabel,
			    &send_side_filtering);
			if (label->iol_connection && (send_side_filtering || force_filtering)) {
				label->io_filtered = true;
			}
		}

#if CONFIG_MACF && XNU_TARGET_OS_OSX
		if (!ipc_service_port_string_name_is_empty(&sp_info) && is_forward_connection_channel) {
			mac_proc_notify_service_port_derive(&sp_info);
		}
#endif
	}

	return KERN_SUCCESS;
}

#if CONFIG_SERVICE_PORT_INFO
void
ipc_service_port_label_get_info(ipc_service_port_label_t port_splabel, mach_service_port_info_t info)
{
	info->mspi_domain_type = (uint8_t)port_splabel->ispl_domain;
	size_t sp_string_name_len = strlen(port_splabel->ispl_service_name);
	strlcpy(info->mspi_string_name, port_splabel->ispl_service_name, sp_string_name_len + 1);
}

void
ipc_bootstrap_port_label_get_info(ipc_bootstrap_port_label_t port_bplabel, mach_service_port_info_t info)
{
	info->mspi_domain_type = XPC_DOMAIN_PORT;
	size_t sp_string_name_len = strlen(port_bplabel->ispl_service_name);
	strlcpy(info->mspi_string_name, port_bplabel->ispl_service_name, sp_string_name_len + 1);
}

/*
 * Name: ip_is_report_crash_service_port_locked
 *
 * Description: Determines if a port is a valid service port for ReportCrash service
 *
 * Returns:
 *   true if the port is a ReportCrash service port
 *   false otherwise
 *
 * Conditions:
 *   Port must be locked and active
 */
bool
ip_is_report_crash_service_port_locked(ipc_object_label_t port_label)
{
	const struct ipc_service_port_label *iol_service_ptr = port_label.iol_service;
	return iol_service_ptr &&
	       port_label.io_type == IOT_SERVICE_PORT &&
	       (!strcmp(iol_service_ptr->ispl_service_name, "com.apple.ReportCrash"));
}
#endif /* CONFIG_SERVICE_PORT_INFO */
