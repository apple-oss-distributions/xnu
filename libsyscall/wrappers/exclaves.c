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

#include <mach/exclaves.h>
#include <string/strings.h>
#include <sys/cdefs.h>
#include <mach/exclaves_l4.h>

#if defined(__LP64__)
#define EXCLAVES_CTL_TRAP _exclaves_ctl_trap
#else
#define EXCLAVES_CTL_TRAP(port, opf, id, buffer, size, offset, size2, status) ({ \
	(void)port; (void)opf; (void)id; (void)buffer;                   \
	(void)size; (void)offset; (void)size2; (void)status;             \
	KERN_NOT_SUPPORTED;                                              \
})
#endif /* __LP64__ */

kern_return_t
exclaves_endpoint_call(mach_port_t port, exclaves_id_t endpoint_id,
    mach_vm_address_t msg_buffer, mach_vm_size_t size, exclaves_tag_t *tag,
    exclaves_error_t *error)
{
#if defined(__LP64__)
	kern_return_t kr = KERN_SUCCESS;
	if (size != Exclaves_L4_IpcBuffer_Size) {
		return KERN_INVALID_ARGUMENT;
	}
	Exclaves_L4_IpcBuffer_t *ipcb;
	ipcb = Exclaves_L4_IpcBuffer_Ptr((void*)msg_buffer);
	ipcb->mr[Exclaves_L4_Ipc_Mr_Tag] = *tag;
	const uint32_t opf = EXCLAVES_CTL_OP_AND_FLAGS(ENDPOINT_CALL, 0);
	kr = EXCLAVES_CTL_TRAP(port, opf, endpoint_id, msg_buffer, size, 0, 0, 0);
	*tag = ipcb->mr[Exclaves_L4_Ipc_Mr_Tag];
	*error = EXCLAVES_XNU_PROXY_CR_RETVAL(ipcb);
	return kr;
#else
#pragma unused(port, endpoint_id, msg_buffer, size, tag, error)
	return KERN_NOT_SUPPORTED;
#endif /* defined(__LP64__) */
}

kern_return_t
exclaves_outbound_buffer_create(mach_port_t port, const char *buffer_name,
    mach_vm_size_t size, mach_port_t *out_outbound_buffer_port)
{
	const uint32_t opf = EXCLAVES_CTL_OP_AND_FLAGS(NAMED_BUFFER_CREATE, 0);
	return EXCLAVES_CTL_TRAP(port, opf, buffer_name,
	           (uintptr_t)out_outbound_buffer_port, size,
	           EXCLAVES_BUFFER_PERM_READ, 0, 0);
}

kern_return_t
exclaves_outbound_buffer_copyout(mach_port_t outbound_buffer_port,
    mach_vm_address_t dst_buffer, mach_vm_size_t size1, mach_vm_size_t offset1,
    mach_vm_size_t size2, mach_vm_size_t offset2)
{
	const uint32_t opf = EXCLAVES_CTL_OP_AND_FLAGS(NAMED_BUFFER_COPYOUT, 0);
	return EXCLAVES_CTL_TRAP(outbound_buffer_port, opf,
	           (exclaves_id_t) offset1, dst_buffer, size1, size2, offset2, 0);
}

kern_return_t
exclaves_inbound_buffer_create(mach_port_t port, const char *buffer_name,
    mach_vm_size_t size, mach_port_t *out_inbound_buffer_port)
{
	const uint32_t opf = EXCLAVES_CTL_OP_AND_FLAGS(NAMED_BUFFER_CREATE, 0);
	return EXCLAVES_CTL_TRAP(port, opf, buffer_name,
	           (uintptr_t)out_inbound_buffer_port, size,
	           EXCLAVES_BUFFER_PERM_WRITE, 0, 0);
}

kern_return_t
exclaves_inbound_buffer_copyin(mach_port_t inbound_buffer_port,
    mach_vm_address_t src_buffer, mach_vm_size_t size1, mach_vm_size_t offset1,
    mach_vm_size_t size2, mach_vm_size_t offset2)
{
	const uint32_t opf = EXCLAVES_CTL_OP_AND_FLAGS(NAMED_BUFFER_COPYIN, 0);
	return EXCLAVES_CTL_TRAP(inbound_buffer_port, opf,
	           (exclaves_id_t) offset1, src_buffer, size1, size2, offset2, 0);
}

kern_return_t
exclaves_named_buffer_create(mach_port_t port, exclaves_id_t buffer_id,
    mach_vm_size_t size, mach_port_t *out_named_buffer_port)
{
	(void)port; (void)buffer_id; (void)size; (void)out_named_buffer_port;
	return KERN_NOT_SUPPORTED;
}

kern_return_t
exclaves_named_buffer_copyin(mach_port_t named_buffer_port,
    mach_vm_address_t src_buffer, mach_vm_size_t size, mach_vm_size_t offset)
{
	(void)named_buffer_port; (void)src_buffer; (void)size; (void)offset;
	return KERN_NOT_SUPPORTED;
}

kern_return_t
exclaves_named_buffer_copyout(mach_port_t named_buffer_port,
    mach_vm_address_t dst_buffer, mach_vm_size_t size, mach_vm_size_t offset)
{
	(void)named_buffer_port; (void)dst_buffer; (void)size; (void)offset;
	return KERN_NOT_SUPPORTED;
}

kern_return_t
exclaves_launch_conclave(mach_port_t port, void *arg1,
    uint64_t arg2)
{
	if (arg1 != NULL || arg2 != 0) {
		return KERN_INVALID_ARGUMENT;
	}

	const uint32_t opf = EXCLAVES_CTL_OP_AND_FLAGS(LAUNCH_CONCLAVE, 0);
	return EXCLAVES_CTL_TRAP(port, opf, 0, 0, 0, 0, 0, 0);
}

kern_return_t
exclaves_lookup_service(mach_port_t port, const char *name,
    exclaves_id_t *resource_id)
{
	struct exclaves_resource_user conclave_resource_user;
	kern_return_t kr;
	mach_vm_size_t size = sizeof(struct exclaves_resource_user);

	strlcpy(conclave_resource_user.r_name, name, MAXCONCLAVENAME);
	conclave_resource_user.r_type = 0;
	const uint32_t opf = EXCLAVES_CTL_OP_AND_FLAGS(LOOKUP_SERVICES, 0);

	kr = EXCLAVES_CTL_TRAP(port, opf, 0,
	    (mach_vm_address_t)&conclave_resource_user, size, 0, 0, 0);
	if (kr == KERN_SUCCESS && resource_id) {
		*resource_id = conclave_resource_user.r_id;
	}
	return kr;
}

kern_return_t
exclaves_boot(mach_port_t port, exclaves_boot_stage_t stage)
{
	const uint32_t opf = EXCLAVES_CTL_OP_AND_FLAGS(BOOT, 0);
	return EXCLAVES_CTL_TRAP(port, opf, stage, 0, 0, 0, 0, 0);
}

kern_return_t
exclaves_audio_buffer_create(mach_port_t port, const char *buffer_name,
    mach_vm_size_t size, mach_port_t* out_audio_buffer_port)
{
	const uint32_t opf = EXCLAVES_CTL_OP_AND_FLAGS(AUDIO_BUFFER_CREATE, 0);
	return EXCLAVES_CTL_TRAP(port, opf, (exclaves_id_t) buffer_name,
	           (uintptr_t) out_audio_buffer_port, size, 0, 0, 0);
}

kern_return_t
exclaves_audio_buffer_copyout(mach_port_t audio_buffer_port,
    mach_vm_address_t dst_buffer,
    mach_vm_size_t size1, mach_vm_size_t offset1,
    mach_vm_size_t size2, mach_vm_size_t offset2)
{
	const uint32_t opf = EXCLAVES_CTL_OP_AND_FLAGS(AUDIO_BUFFER_COPYOUT, 0);
	return EXCLAVES_CTL_TRAP(audio_buffer_port, opf,
	           (exclaves_id_t) offset1, dst_buffer, size1, size2, offset2, 0);
}

kern_return_t
exclaves_audio_buffer_copyout_with_status(mach_port_t audio_buffer_port,
    mach_vm_address_t dst_buffer,
    mach_vm_size_t size1, mach_vm_size_t offset1,
    mach_vm_size_t size2, mach_vm_size_t offset2,
    exclaves_sensor_status_t *status)
{
	const uint32_t opf = EXCLAVES_CTL_OP_AND_FLAGS(AUDIO_BUFFER_COPYOUT, 0);
	return EXCLAVES_CTL_TRAP(audio_buffer_port, opf,
	           (exclaves_id_t) offset1, dst_buffer, size1, size2, offset2,
	           status);
}

kern_return_t
exclaves_arbitrated_buffer_create(mach_port_t port, const char *buffer_name,
    mach_vm_size_t size, mach_port_t* out_arbitrated_buffer_port)
{
	const uint32_t opf = EXCLAVES_CTL_OP_AND_FLAGS(ARBITRATED_BUFFER_CREATE, 0);
	return EXCLAVES_CTL_TRAP(port, opf, (exclaves_id_t) buffer_name,
	           (uintptr_t) out_arbitrated_buffer_port, size, 0, 0, 0);
}

kern_return_t
exclaves_arbitrated_buffer_copyout(mach_port_t arbitrated_buffer_port,
    mach_vm_address_t dst_buffer, mach_vm_size_t size, mach_vm_size_t offset,
    uint64_t param1, uint64_t param2, exclaves_sensor_status_t *status)
{
	const uint32_t opf = EXCLAVES_CTL_OP_AND_FLAGS(ARBITRATED_BUFFER_COPYOUT, 0);
	return EXCLAVES_CTL_TRAP(arbitrated_buffer_port, opf,
	           (exclaves_id_t) offset, dst_buffer, size, param1, param2,
	           status);
}

kern_return_t
exclaves_sensor_create(mach_port_t port, const char *sensor_name,
    mach_port_t *sensor_port)
{
	const uint32_t opf = EXCLAVES_CTL_OP_AND_FLAGS(SENSOR_CREATE, 0);
	return EXCLAVES_CTL_TRAP(port, opf, (exclaves_id_t) sensor_name,
	           (uintptr_t) sensor_port, 0, 0, 0, 0);
}

kern_return_t
exclaves_sensor_start(mach_port_t sensor_port, uint64_t flags,
    exclaves_sensor_status_t *sensor_status)
{
	const uint32_t opf = EXCLAVES_CTL_OP_AND_FLAGS(SENSOR_START, 0);
	return EXCLAVES_CTL_TRAP(sensor_port, opf, flags,
	           (uintptr_t) sensor_status, 0, 0, 0, 0);
}

kern_return_t
exclaves_sensor_stop(mach_port_t sensor_port, uint64_t flags,
    exclaves_sensor_status_t *sensor_status)
{
	const uint32_t opf = EXCLAVES_CTL_OP_AND_FLAGS(SENSOR_STOP, 0);
	return EXCLAVES_CTL_TRAP(sensor_port, opf, flags,
	           (uintptr_t) sensor_status, 0, 0, 0, 0);
}

kern_return_t
exclaves_sensor_status(mach_port_t sensor_port, uint64_t flags,
    exclaves_sensor_status_t *sensor_status)
{
	const uint32_t opf = EXCLAVES_CTL_OP_AND_FLAGS(SENSOR_STATUS, 0);
	return EXCLAVES_CTL_TRAP(sensor_port, opf, flags,
	           (uintptr_t) sensor_status, 0, 0, 0, 0);
}

kern_return_t
exclaves_indicator_min_on_time(mach_port_t port, uint64_t flags,
    uint64_t *camera_indicator, uint64_t *mic_indicator, uint64_t *faceid_indicator)
{
	if ((camera_indicator == NULL) || (mic_indicator == NULL) || (faceid_indicator == NULL)) {
		return KERN_INVALID_ARGUMENT;
	}

	struct exclaves_indicator_deadlines indicator = {
		.version = 1
	};

	const uint32_t opf = EXCLAVES_CTL_OP_AND_FLAGS(SENSOR_MIN_ON_TIME, 0);
	kern_return_t kr = EXCLAVES_CTL_TRAP(port, opf, flags, (mach_vm_address_t)&indicator, sizeof(indicator), 0, 0, 0);
	if (kr == KERN_SUCCESS) {
		*camera_indicator = indicator.camera_indicator;
		*mic_indicator = indicator.mic_indicator;
		*faceid_indicator = indicator.faceid_indicator;
	}
	return kr;
}

kern_return_t
exclaves_notification_create(__unused mach_port_t port, const char *name,
    uint64_t *notification_id)
{
	const uint32_t opf = EXCLAVES_CTL_OP_AND_FLAGS(NOTIFICATION_RESOURCE_LOOKUP, 0);
	kern_return_t kr;
	struct exclaves_resource_user notification_resource_user;
	if (name == NULL) {
		return KERN_INVALID_ARGUMENT;
	}
	if (notification_id == NULL) {
		return KERN_INVALID_ARGUMENT;
	}
	strlcpy(notification_resource_user.r_name, name, MAXCONCLAVENAME);
	kr = EXCLAVES_CTL_TRAP(port, opf, (exclaves_id_t)0,
	    (mach_vm_address_t)&notification_resource_user,
	    sizeof(notification_resource_user), 0, 0, 0);
	if (kr == KERN_SUCCESS) {
		*notification_id = notification_resource_user.r_port;
	}
	return kr;
}

kern_return_t
exclaves_daemon_notification_register(__unused mach_port_t port,
    const char *conclave_name, const char *notification_name,
    mach_port_name_t send_right)
{
	const uint32_t opf = EXCLAVES_CTL_OP_AND_FLAGS(DAEMON_NOTIFICATION_REGISTER, 0);
	struct exclaves_daemon_notification register_args = {0};

	if (conclave_name == NULL || notification_name == NULL ||
	    !MACH_PORT_VALID(send_right) ||
	    strnlen(conclave_name, MAXCONCLAVENAME) >= MAXCONCLAVENAME ||
	    strnlen(notification_name, MAXCONCLAVENAME) >= MAXCONCLAVENAME) {
		return KERN_INVALID_ARGUMENT;
	}

	strlcpy(register_args.conclave_name, conclave_name, sizeof(register_args.conclave_name));
	strlcpy(register_args.notification_name, notification_name, sizeof(register_args.notification_name));
	register_args.send_right = send_right;

	return EXCLAVES_CTL_TRAP(port, opf, 0,
	           (mach_vm_address_t)&register_args, sizeof(register_args), 0, 0, 0);
}

kern_return_t
exclaves_daemon_notification_deregister(__unused mach_port_t port,
    const char *conclave_name, const char *notification_name,
    mach_port_name_t send_right)
{
	const uint32_t opf = EXCLAVES_CTL_OP_AND_FLAGS(DAEMON_NOTIFICATION_DEREGISTER, 0);
	struct exclaves_daemon_notification deregister_args = {0};

	if (conclave_name == NULL || notification_name == NULL ||
	    !MACH_PORT_VALID(send_right) ||
	    strnlen(conclave_name, MAXCONCLAVENAME) >= MAXCONCLAVENAME ||
	    strnlen(notification_name, MAXCONCLAVENAME) >= MAXCONCLAVENAME) {
		return KERN_INVALID_ARGUMENT;
	}

	strlcpy(deregister_args.conclave_name, conclave_name, sizeof(deregister_args.conclave_name));
	strlcpy(deregister_args.notification_name, notification_name, sizeof(deregister_args.notification_name));
	deregister_args.send_right = send_right;

	return EXCLAVES_CTL_TRAP(port, opf, 0,
	           (mach_vm_address_t)&deregister_args, sizeof(deregister_args), 0, 0, 0);
}

kern_return_t
exclaves_aoe_setup(__unused mach_port_t port, uint8_t *num_message,
    uint8_t *num_worker)
{
	/* Hack for now. */
	const uint32_t opf = EXCLAVES_CTL_OP_AND_FLAGS(AOE_SETUP, 0);
	return EXCLAVES_CTL_TRAP(port, opf, 0, (uintptr_t)num_message, 0, 0, 0,
	           (uintptr_t)num_worker);
}

kern_return_t
exclaves_aoe_enumerate_and_setup_services(__unused mach_port_t port, uint8_t *num_services)
{
	const uint32_t opf = EXCLAVES_CTL_OP_AND_FLAGS(AOE_ENUMERATE_AND_SETUP_SERVICES, 0);
	return EXCLAVES_CTL_TRAP(port, opf, 0, (uintptr_t)num_services, 0, 0, 0, 0);
}

kern_return_t
exclaves_aoe_get_all_service_infos(__unused mach_port_t port, exclaves_aoe_service_info_t *sinfos, mach_vm_size_t sinfos_size)
{
	const uint32_t opf = EXCLAVES_CTL_OP_AND_FLAGS(AOE_GET_ALL_SERVICE_INFOS, 0);
	return EXCLAVES_CTL_TRAP(port, opf, 0, (uintptr_t)sinfos, sinfos_size, 0, 0, 0);
}

kern_return_t
exclaves_aoe_work_loop(__unused mach_port_t port)
{
	const uint32_t opf = EXCLAVES_CTL_OP_AND_FLAGS(AOE_WORK_LOOP, 0);
	return EXCLAVES_CTL_TRAP(port, opf, 0, 0, 0, 0, 0, 0);
}

kern_return_t
exclaves_aoe_message_loop(__unused mach_port_t port)
{
	const uint32_t opf = EXCLAVES_CTL_OP_AND_FLAGS(AOE_MESSAGE_LOOP, 0);
	return EXCLAVES_CTL_TRAP(port, opf, 0, 0, 0, 0, 0, 0);
}

kern_return_t
exclaves_aoe_work_loop_with_service_id(__unused mach_port_t port, uint64_t service_id)
{
	const uint32_t opf = EXCLAVES_CTL_OP_AND_FLAGS(AOE_WORK_LOOP_WITH_SERVICE_ID, 0);
	return EXCLAVES_CTL_TRAP(port, opf, 0, 0, 0, service_id, 0, 0);
}

kern_return_t
exclaves_aoe_message_loop_with_service_id(__unused mach_port_t port, uint64_t service_id)
{
	const uint32_t opf = EXCLAVES_CTL_OP_AND_FLAGS(AOE_MESSAGE_LOOP_WITH_SERVICE_ID, 0);
	return EXCLAVES_CTL_TRAP(port, opf, 0, 0, 0, service_id, 0, 0);
}
