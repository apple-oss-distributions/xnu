/*
 * Copyright (c) 2023 Apple Inc. All rights reserved.
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

#if CONFIG_EXCLAVES

#pragma once

#include <mach/exclaves.h>
#include <mach/kern_return.h>

#include <stdint.h>

__BEGIN_DECLS

/*!
 * @enum exclaves_device_type
 *
 * @brief
 * Identifier for an exclaves device with sensors
 */
OS_ENUM(exclaves_device_type, uint16_t,
    EXCLAVES_DEVICE_BUILTIN = 0,
    /* update max if more devices added */
    EXCLAVES_DEVICE_MAX = 1,
    );


/* -------------------------------------------------------------------------- */
/* Resource ID macros (keep in sync with ECB xnu_proxy_resources.h)           */

/*
 * Resource identifier
 *
 * | Flag (32 bits) | ID (32 bits) |
 */

#define RESOURCE_ID_MAKE(flag, id, offset) \
    ((uint64_t)(flag) << (offset) | ((uint64_t)(id) << (offset) >> (offset)))
#define RESOURCE_ID_GET_ID(id, offset) \
    ((uint64_t)(id) << (offset) >> (offset))
#define RESOURCE_ID_GET_FLAG(id, offset) \
    ((uint64_t)(id) >> (offset))

/*
 * Sensor identifier
 *
 * | Device Identifier (32 bits) | Sensor Type (32 bits) |
 */
#define SENSOR_ID_MAKE(device_id, sensor_id) \
    (RESOURCE_ID_MAKE(device_id, sensor_id, 32))
#define SENSOR_ID_GET_SENSOR(id) \
    (RESOURCE_ID_GET_ID(id, 32))
#define SENSOR_ID_GET_DEVICE(id) \
    (RESOURCE_ID_GET_FLAG(id, 32))

/*
 * Arbitrated Buffer identifier
 *
 *  | device id (16 bits) | sensor id (8 bits) | buffer id (8 bits) | endpoint (32 bits) |
 */
#define ARBITRATED_BUFFER_MEMORY_ID_MAKE(endpoint, device_id, sensor_id, buffer_id) \
    ((((uint64_t)(device_id) & 0xFFFFU) << 48) | \
    (((uint64_t) (sensor_id) & 0x00FFU) << 40) | \
    (((uint64_t) (buffer_id) & 0x00FFU) << 32) | \
    (((uint64_t) (endpoint)  & 0xFFFFFFFFUL)))
#define ARBITRATED_BUFFER_MEMORY_ID_GET_ENDPOINT(rid) \
    ((uint64_t)(uint32_t)((rid)      ))
#define ARBITRATED_BUFFER_MEMORY_ID_GET_BUFFER(rid) \
    ((uint64_t)(uint8_t) ((rid) >> 32))
#define ARBITRATED_BUFFER_MEMORY_ID_GET_SENSOR(rid) \
    ((uint64_t)(uint8_t) ((rid) >> 40))
#define ARBITRATED_BUFFER_MEMORY_ID_GET_DEVICE(rid) \
    ((uint64_t)(uint16_t)((rid) >> 48))

/* -------------------------------------------------------------------------- */

/* Sensor operations on sensor resource ids */

kern_return_t
exclaves_sensor_id_init(uint64_t sensor_id);

kern_return_t
exclaves_sensor_id_start(uint64_t sensor_id, uint64_t flags,
    exclaves_sensor_status_t *status);

kern_return_t
exclaves_sensor_id_stop(uint64_t sensor_id, uint64_t flags,
    exclaves_sensor_status_t *status);

kern_return_t
exclaves_sensor_id_status(uint64_t sensor_id, uint64_t flags,
    exclaves_sensor_status_t *status);

/*!
 * @function exclaves_sensor_buffer_id_copy
 *
 * @abstract
 * Request arbitrated copy from the EIC for the specified arbitrated memory
 * buffer resource id
 *
 * @param resource_id
 * The resource identifier of the arbitrated memory buffer to copy
 *
 * @param size
 * The length in bytes to copy
 *
 * @param offset
 * Start copy offset in the arbitrated buffer.
 *
 * @param param1
 * Additional EIC parameter for copy
 *
 * @param param2
 * Additional EIC parameter for copy
 *
 * @param status
 * Out parameter filled with the sensor status.
 *
 * @param second_range
 * Out parameter filled with a boolean indicating whether a second memory range
 * [offset2, offset2 + size2] := [param2, param2 + param1] should be copied
 * out in addition to the first range [offset, offset + size].
 *
 * @result
 * KERN_SUCCESS or mach system call error code.
 */
kern_return_t
exclaves_sensor_buffer_id_copy(uint64_t resource_id, uint64_t size,
    uint64_t offset, uint64_t param1, uint64_t param2,
    exclaves_sensor_status_t *status, bool *second_range);

/*!
 * @function exclaves_sensor_buffer_id_endpoint
 *
 * @abstract
 * Return endpoint id for the specified arbitrated memory buffer resource id
 *
 * @param resource_id
 * The resource identifier of the arbitrated memory buffer
 *
 * @result
 * Endpoint id.
 */
uint64_t
exclaves_sensor_buffer_id_endpoint(uint64_t resource_id);

__END_DECLS

#endif /* CONFIG_EXCLAVES */
