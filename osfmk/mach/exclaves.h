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
#include <mach/mach_param.h>
#if !defined(KERNEL)
#include <AvailabilityInternalPrivate.h>
#endif /* defined(KERNEL) */


__BEGIN_DECLS

typedef uint64_t exclaves_id_t;
typedef uint64_t exclaves_tag_t;
typedef uint64_t exclaves_error_t;

/*!
 * @enum exclaves_sensor_status_t
 *
 * @brief
 * The status of an exclaves sensor.
 *
 * Indicates if data from this sensor can currently be accessed.
 * If the data cannot be accessed, exclaves_sensor_start() must be
 * called (with an accompanying exclaves_sensor_stop()).
 *
 * If the data cannot be accessed, then reading sensor data will
 * only result in 0s.
 */
OS_ENUM(exclaves_sensor_status, uint32_t,
    EXCLAVES_SENSOR_STATUS_ALLOWED = 1,
    EXCLAVES_SENSOR_STATUS_DENIED = 2,
    EXCLAVES_SENSOR_STATUS_CONTROL = 3,
    );

OS_CLOSED_OPTIONS(exclaves_buffer_perm, uint32_t,
    EXCLAVES_BUFFER_PERM_READ = 1,
    EXCLAVES_BUFFER_PERM_WRITE = 2,
    );

OS_ENUM(exclaves_boot_stage, uint32_t,
    EXCLAVES_BOOT_STAGE_NONE = ~0u,
    EXCLAVES_BOOT_STAGE_2 = 0,
    EXCLAVES_BOOT_STAGE_EXCLAVEKIT = 100,

    /* The EXCLAVEKIT boot stage failed in some way. */
    EXCLAVES_BOOT_STAGE_FAILED = 200,
    );

OS_ENUM(exclaves_status, uint8_t,
    EXCLAVES_STATUS_NOT_STARTED = 0x00, /* Obsolete. Never used. */
    EXCLAVES_STATUS_AVAILABLE = 0x01,
    EXCLAVES_STATUS_FAILED = 0xFE,      /* Obsolete. Never used. */
    EXCLAVES_STATUS_NOT_SUPPORTED = 0xFF,
    );

#define MAX_CONCLAVE_RESOURCE_NUM 50

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
SPI_AVAILABLE(macos(14.4), ios(17.4), tvos(17.4), watchos(10.4))
kern_return_t
exclaves_endpoint_call(mach_port_t port, exclaves_id_t endpoint_id,
    mach_vm_address_t msg_buffer, mach_vm_size_t size, exclaves_tag_t *tag,
    exclaves_error_t *error);

/*!
 * @function exclaves_outbound_buffer_create
 *
 * @abstract
 * Setup access by xnu to a pre-defined exclaves outbound memory buffer and
 * return a mach port for it. The buffer can only be read from.
 *
 * @param port
 * Reserved, must be MACH_PORT_NULL for now.
 *
 * @param buffer_name
 * String name of buffer to operate on.
 *
 * @param size
 * Size of requested outbound buffer.
 *
 * @param outbound_buffer_port
 * Out parameter filled in with mach port name for the newly created outbound
 * buffer object, must be mach_port_deallocate()d to tear down the access to
 * the outbound buffer.
 *
 * @result
 * KERN_SUCCESS or mach system call error code.
 */
SPI_AVAILABLE(macos(14.4), ios(17.4), tvos(17.4), watchos(10.4))
kern_return_t
exclaves_outbound_buffer_create(mach_port_t port, const char *buffer_name,
    mach_vm_size_t size, mach_port_t *outbound_buffer_port);

/*!
 * @function exclaves_outbound_buffer_copyout
 *
 * @abstract
 * Copy out to specified userspace buffer from previously setup exclaves
 * outbound memory buffer.
 *
 * Two size/offsets are provided to faciliate fast copy that wraps around a ring
 * buffer that could be placed arbitrarily in the outbound memory region.
 *
 * @param outbound_buffer_port
 * A outbound buffer port name returned from exclaves_outbound_buffer_create()
 *
 * @param dst_buffer
 * Pointer to userspace buffer to copy out from outbound buffer.
 *
 * @param size1
 * Number of bytes to copy (<= size of specified userspace buffer).
 *
 * @param offset1
 * Offset in outbound memory buffer to start copy at.
 *
 * @param size2
 * Number of bytes to copy (<= size of specified userspace buffer). Can be 0,
 * in which case the 2nd range is not copied.
 *
 * @param offset2
 * Offset in outbound memory buffer to start copy at.
 *
 * @result
 * KERN_SUCCESS or mach system call error code.
 */
SPI_AVAILABLE(macos(14.4), ios(17.4), tvos(17.4), watchos(10.4))
kern_return_t
exclaves_outbound_buffer_copyout(mach_port_t outbound_buffer_port,
    mach_vm_address_t dst_buffer, mach_vm_size_t size1, mach_vm_size_t offset1,
    mach_vm_size_t size2, mach_vm_size_t offset2);

/*!
 * @function exclaves_inbound_buffer_create
 *
 * @abstract
 * Setup access by xnu to a pre-defined exclaves inbound memory buffer and
 * return a mach port for it. The buffer can be both read from and written to.
 *
 * @param port
 * Reserved, must be MACH_PORT_NULL for now.
 *
 * @param buffer_name
 * String name of buffer to operate on.
 *
 * @param size
 * Size of requested inbound buffer.
 *
 * @param inbound_buffer_port
 * Out parameter filled in with mach port name for the newly created inbound
 * buffer object, must be mach_port_deallocate()d to tear down the access to
 * the inbound buffer.
 *
 * @result
 * KERN_SUCCESS or mach system call error code.
 */
SPI_AVAILABLE(macos(14.4), ios(17.4), tvos(17.4), watchos(10.4))
kern_return_t
exclaves_inbound_buffer_create(mach_port_t port, const char *buffer_name,
    mach_vm_size_t size, mach_port_t *inbound_buffer_port);

/*!
 * @function exclaves_inbound_buffer_copyin
 *
 * @abstract
 * Copy from specified userspace buffer into previously setup inbound exclaves
 * inbound memory buffer.
 *
 * Two size/offsets are provided to faciliate fast copy that wraps around a ring
 * buffer that could be placed arbitrarily in the inbound memory region.
 *
 * @param inbound_buffer_port
 * An inbound buffer port name returned from exclaves_inbound_buffer_create()
 *
 * @param src_buffer
 * Pointer to userspace buffer to copy into inbound buffer.
 *
 * @param size1
 * Number of bytes to copy (<= size of specified userspace buffer).
 *
 * @param offset1
 * Offset in inbound memory buffer to start copy at.
 *
 * @param size2
 * Number of bytes to copy (<= size of specified userspace buffer). Can be 0,
 * in which case the 2nd range is not copied.
 *
 * @param offset2
 * Offset in inbound memory buffer to start copy at.
 *
 * @result
 * KERN_SUCCESS or mach system call error code. Some buffers are read-only and
 * calls to exclaves_inbound_buffer_copyin() will result in
 * KERN_PROTECTION_FAILURE.
 */
SPI_AVAILABLE(macos(14.4), ios(17.4), tvos(17.4), watchos(10.4))
kern_return_t
exclaves_inbound_buffer_copyin(mach_port_t inbound_buffer_port,
    mach_vm_address_t src_buffer, mach_vm_size_t size1, mach_vm_size_t offset1,
    mach_vm_size_t size2, mach_vm_size_t offset2);

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
SPI_AVAILABLE(macos(14.4), ios(17.4), tvos(17.4), watchos(10.4))
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
SPI_AVAILABLE(macos(14.4), ios(17.4), tvos(17.4), watchos(10.4))
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
SPI_AVAILABLE(macos(14.4), ios(17.4), tvos(17.4), watchos(10.4))
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
 * @param boot_stage
 * Stage of boot requested
 *
 * @result
 * KERN_SUCCESS or mach system call error code.
 */
SPI_AVAILABLE(macos(14.4), ios(17.4), tvos(17.4), watchos(10.4))
kern_return_t
exclaves_boot(mach_port_t port, exclaves_boot_stage_t boot_stage);

/*!
 * @function exclaves_audio_buffer_create
 *
 * @abstract
 * Setup access by xnu to a pre-defined named exclaves audio shared memory
 * buffer and return a mach port for it.
 *
 * @param port
 * Reserved, must be MACH_PORT_NULL for now.
 *
 * @param buffer_name
 * String name of buffer to operate on.
 *
 * @param size
 * Size of requested named buffer.
 *
 * @param audio_buffer_port
 * Out parameter filled in with mach port name for the newly created named
 * buffer object, must be mach_port_deallocate()d to tear down the access to
 * the named buffer.
 *
 * Audio buffers are distiguished from general named buffers as shared memory
 * is arbitrated by the EIC.
 *
 * @result
 * KERN_SUCCESS or mach system call error code.
 */
SPI_AVAILABLE(macos(14.4), ios(17.4), tvos(17.4), watchos(10.4))
kern_return_t
exclaves_audio_buffer_create(mach_port_t port, const char * buffer_name,
    mach_vm_size_t size, mach_port_t *audio_buffer_port);

/*!
 * @function exclaves_audio_buffer_copyout
 *
 * @abstract
 * Copy out to specified userspace buffer from previously setup named exclaves
 * audio shared memory buffer.
 *
 * Audio buffers are arbitrated via the EIC and copies will return 0's when
 * access to the sensor is not granted.
 *
 * Two size/offsets are provided to faciliate fast copy that wraps around a
 * ring buffer that could be placed arbitrarily in the shared memory region.
 *
 * @param audio_buffer_port
 * A named buffer port name returned from exclaves_audio_buffer_create()
 *
 * @param dst_buffer
 * Pointer to userspace buffer to copy out from named buffer.
 *
 * @param size1
 * Number of bytes to copy (<= size of specified userspace buffer).
 *
 * @param offset1
 * Offset in shared memory buffer to start copy at.
 *
 * @param size2
 * Number of bytes to copy (<= size of specified userspace buffer). Can be 0,
 * in which case the 2nd range is not copied.
 *
 * @param offset2
 * Offset in shared memory buffer to start copy at.
 *
 * @result
 * KERN_SUCCESS or mach system call error code.
 */
SPI_AVAILABLE(macos(14.4), ios(17.4), tvos(17.4), watchos(10.4))
kern_return_t
exclaves_audio_buffer_copyout(mach_port_t audio_buffer_port,
    mach_vm_address_t dst_buffer, mach_vm_size_t size1, mach_vm_size_t offset1,
    mach_vm_size_t size2, mach_vm_size_t offset2);

/*!
 * @function exclaves_sensor_create
 *
 * @abstract
 * Setup access by xnu to a pre-defined named sensor
 *
 * @param port
 * Reserved, must be MACH_PORT_NULL for now.
 *
 * @param sensor_name
 * String name of sensor to operate on.
 *
 * @param sensor_port
 * Out parameter filled in with mach port name for the newly created
 * sensor object, must be mach_port_deallocate()d to tear down the access to
 * the sensor.
 *
 * @result
 * KERN_SUCCESS or mach system call error code.
 */
SPI_AVAILABLE(macos(14.4), ios(17.4), tvos(17.4), watchos(10.4))
kern_return_t
exclaves_sensor_create(mach_port_t port, const char *sensor_name, mach_port_t *sensor_port);

/*!
 * @function exclaves_sensor_start
 *
 * @abstract
 * Start accessing a sensor and cause any indicators to display.
 *
 * If multiple clients start the same sensor, the sensor will only
 * actually start on the first client.
 *
 * @param sensor_port
 * A sensor buffer port name returned from exclaves_sensor_create()
 * for the sensor.
 *
 * @param flags to pass to the implementation. Must be 0 for now.
 *
 * @param sensor_status
 * Out parameter filled with the sensor status.
 *
 * @result
 * KERN_SUCCESS or mach system call error code.
 */
SPI_AVAILABLE(macos(14.4), ios(17.4), tvos(17.4), watchos(10.4))
kern_return_t
exclaves_sensor_start(mach_port_t sensor_port, uint64_t flags,
    exclaves_sensor_status_t *sensor_status);

/*!
 * @function exclaves_sensor_stop
 *
 * @abstract
 * Stop accessing a sensor and cause any indicators to stop displaying access.
 *
 * If multiple clients are accessing the sensor, sensor access will
 * continue to display until all clients have called this function.
 *
 * @param sensor_port
 * A sensor buffer port name returned from exclaves_sensor_create()
 * for the sensor.
 *
 * @param flags to pass to the implementation. Must be 0 for now.
 *
 * @param sensor_status
 * Out parameter filled with the sensor status.
 *
 * @result
 * KERN_SUCCESS or mach system call error code.
 */
SPI_AVAILABLE(macos(14.4), ios(17.4), tvos(17.4), watchos(10.4))
kern_return_t
exclaves_sensor_stop(mach_port_t sensor_port, uint64_t flags,
    exclaves_sensor_status_t *sensor_status);

/*!
 * @function exclaves_sensor_status
 *
 * @abstract
 * Get the status of access to a sensor
 *
 * @param sensor_port
 * A sensor buffer port name returned from exclaves_sensor_create()
 * for the sensor.
 *
 * @param flags to pass to the implementation. Must be 0 for now.
 *
 * @param sensor_status
 * Out parameter filled with the sensor status.
 *
 * @result
 * KERN_SUCCESS or mach system call error code.
 */
SPI_AVAILABLE(macos(14.4), ios(17.4), tvos(17.4), watchos(10.4))
kern_return_t
exclaves_sensor_status(mach_port_t sensor_port, uint64_t flags,
    exclaves_sensor_status_t *sensor_status);

/*!
 * @function exclaves_launch_conclave
 *
 * @abstract
 * Launch conclave.
 *
 * @param port
 * Reserved, must be MACH_PORT_NULL for now.
 *
 * @param arg1
 * Reserved, must be NULL for now.
 *
 * @param arg2
 * Reserved, must be 0 for now.
 *
 * @result
 * KERN_SUCCESS or mach system call error code.
 */
SPI_AVAILABLE(macos(14.4), ios(17.4), tvos(17.4), watchos(10.4))
kern_return_t
exclaves_launch_conclave(mach_port_t port, void *arg1,
    uint64_t arg2);

/*!
 * @function exclaves_lookup_service
 *
 * @abstract
 * Lookup Conclave Resource.
 *
 * @param port
 * Reserved, must be MACH_PORT_NULL for now.
 *
 * @param name
 * Name of exclave resource to lookup
 *
 * @param resource_id
 * Out param for resource id
 *
 * @result
 * KERN_SUCCESS or mach system call error code.
 */
SPI_AVAILABLE(macos(14.4), ios(17.4), tvos(17.4), watchos(10.4))
kern_return_t
exclaves_lookup_service(mach_port_t port, const char *name, exclaves_id_t *resource_id);

/*!
 * @function exclaves_notification_create
 *
 * @abstract
 * Finds the exclave notification resource with the specified name and
 * makes it available for use by the calling task.
 *
 * @param port
 * Reserved, must be MACH_PORT_NULL for now.
 *
 * @param name
 * Notification identifier.
 *
 * @param notification_id
 * Out parameter filled in with the notification ID
 *
 * @result
 * KERN_SUCCESS or mach system call error code.
 */
SPI_AVAILABLE(macos(14.4), ios(17.4), tvos(17.4), watchos(10.4))
kern_return_t
exclaves_notification_create(mach_port_t port, const char *name, uint64_t *notification_id);

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

/*!
 * @enum exclaves_sensor_type_t
 *
 * @brief
 * Identifier for an exclaves sensor
 */
OS_ENUM(exclaves_sensor_type, uint32_t,
    EXCLAVES_SENSOR_CAM = 1,
    EXCLAVES_SENSOR_MIC = 2,
    EXCLAVES_SENSOR_CAM_ALT_FACEID = 3,
    /* update max if more sensors added */
    EXCLAVES_SENSOR_MAX = 3,
    );

/*!
 * @function exclaves_sensor_start
 *
 * @abstract
 * Start accessing a sensor and cause any indicators to display.
 *
 * If multiple clients start the same sensor, the sensor will only
 * actually start on the first client.
 *
 * @param sensor_type
 * type of sensor to operate on.
 *
 * @param flags to pass to the implementation. Must be 0 for now.
 *
 * @param sensor_status
 * Out parameter filled with the sensor status.
 *
 * @result
 * KERN_SUCCESS or mach system call error code.
 */
kern_return_t
exclaves_sensor_start(exclaves_sensor_type_t sensor_type, uint64_t flags,
    exclaves_sensor_status_t *sensor_status);

/*!
 * @function exclaves_sensor_stop
 *
 * @abstract
 * Stop accessing a sensor and cause any indicators to stop displaying access.
 *
 * If multiple clients are accessing the sensor, sensor access will
 * continue to display until all clients have called this function.
 *
 * @param sensor_type
 * type of sensor to operate on.
 *
 * @param flags to pass to the implementation. Must be 0 for now.
 *
 * @param sensor_status
 * Out parameter filled with the sensor status.
 *
 * @result
 * KERN_SUCCESS or mach system call error code.
 */
kern_return_t
exclaves_sensor_stop(exclaves_sensor_type_t sensor_type, uint64_t flags,
    exclaves_sensor_status_t *sensor_status);
/*!
 * @function exclaves_sensor_status
 *
 * @abstract
 * Get the status of access to a sensor
 *
 * @param sensor_type
 * type of sensor to operate on.
 *
 * @param sensor_status
 * Out parameter filled with the sensor status.
 *
 * @param flags to pass to the implementation. Must be 0 for now.
 *
 * @result
 * KERN_SUCCESS or mach system call error code.
 */
kern_return_t
exclaves_sensor_status(exclaves_sensor_type_t sensor_type, uint64_t flags,
    exclaves_sensor_status_t *sensor_status);

/*!
 * @function exclaves_display_healthcheck_rate
 *
 * @abstract
 * Update the rate of the display healthcheck based on the specified
 * display update rate
 *
 * @param ns
 * The rate in nanoseconds.
 * Note: This value may be be rounded to the nearest rate supported and not used
 * as-is.
 *
 * @result
 * KERN_SUCCESS or mach system call error code.
 */
kern_return_t
exclaves_display_healthcheck_rate(uint64_t ns);

#endif /* defined(KERNEL) */

#if defined(MACH_KERNEL_PRIVATE)

/* -------------------------------------------------------------------------- */

/* Internal kernel interface */

extern kern_return_t
exclaves_thread_terminate(thread_t thread);

extern bool
exclaves_booted(void);

extern exclaves_id_t
exclaves_endpoint_lookup(const char *name);

extern size_t
exclaves_ipc_buffer_count(void);

#endif /* defined(MACH_KERNEL_PRIVATE) */

/* -------------------------------------------------------------------------- */

/* Private interface between Libsyscall and xnu */

OS_ENUM(exclaves_ctl_op, uint8_t,
    EXCLAVES_CTL_OP_ENDPOINT_CALL = 1,
    EXCLAVES_CTL_OP_NAMED_BUFFER_CREATE = 2,
    EXCLAVES_CTL_OP_NAMED_BUFFER_COPYIN = 3,
    EXCLAVES_CTL_OP_NAMED_BUFFER_COPYOUT = 4,
    EXCLAVES_CTL_OP_BOOT = 5,
    EXCLAVES_CTL_OP_LAUNCH_CONCLAVE = 6,
    EXCLAVES_CTL_OP_LOOKUP_RESOURCES = 7,
    EXCLAVES_CTL_OP_AUDIO_BUFFER_CREATE = 8,
    EXCLAVES_CTL_OP_AUDIO_BUFFER_COPYOUT = 9,
    EXCLAVES_CTL_OP_SENSOR_CREATE = 10,
    EXCLAVES_CTL_OP_SENSOR_START = 11,
    EXCLAVES_CTL_OP_SENSOR_STOP = 12,
    EXCLAVES_CTL_OP_SENSOR_STATUS = 13,
    EXCLAVES_CTL_OP_NOTIFICATION_RESOURCE_LOOKUP = 14,
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

/*!
 * @struct exclaves_resource_user
 *
 * @brief
 * User representation of exclave resource
 */
struct exclaves_resource_user {
	char                  r_name[MAXCONCLAVENAME];
	uint64_t              r_type;
	exclaves_id_t         r_id;
	mach_port_name_t      r_port;
};

#if !defined(KERNEL)

SPI_AVAILABLE(macos(14.4), ios(17.4), tvos(17.4), watchos(10.4))
OS_NOT_TAIL_CALLED
kern_return_t
_exclaves_ctl_trap(mach_port_name_t name, uint32_t operation_and_flags,
    exclaves_id_t identifier, mach_vm_address_t buffer, mach_vm_size_t size,
    mach_vm_size_t size2, mach_vm_size_t offset);

#endif /* !defined(KERNEL) */

/* -------------------------------------------------------------------------- */

/* Sysctl interface */

#if defined(KERNEL)

/*!
 * @function exclaves_get_status
 *
 * @abstract
 * Return the current running status of exclaves. This function will block until
 * exclaves has booted, failed to boot, or are known to be not available.
 *
 * @result
 * The status of exclaves.
 */
exclaves_status_t
exclaves_get_status(void);

#endif /* defined(KERNEL) */

#if defined(XNU_KERNEL_PRIVATE)

/*!
 * @function exclaves_get_boot_stage
 *
 * @abstract
 * Return the current boot stage of exclaves. This function will not block.
 * In general this shouldn't be used (other than for the sysctl).
 * exclaves_boot_wait() is mostly what is wanted.
 *
 * @result
 * The boot stage of exclaves.
 */
exclaves_boot_stage_t
exclaves_get_boot_stage(void);

#endif /* defined(XNU_KERNEL_PRIVATE) */

__END_DECLS

#endif /* defined(PRIVATE) */

#endif /* _MACH_EXCLAVES_H */
