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
 * @function exclaves_sensor_copy
 *
 * @abstract
 * Allow a copy from an aribtrated audio memory segment
 *
 * @param buffer
 * Identifies which arbitrated memory buffer to operate on
 *
 * @param size1
 * The length in bytes of the data to be copied
 *
 * @param offset1
 * Offset in bytes of the data to be copied
 *
 * @param size2
 * The length in bytes of the data to be copied
 *
 * @param offset2
 * Offset in bytes of the data to be copied
 *
 * @param sensor_status
 * Out parameter filled with the sensor status.
 *
 * @result
 * KERN_SUCCESS or mach system call error code.
 */
kern_return_t
exclaves_sensor_copy(uint32_t buffer, uint64_t size1,
    uint64_t offset1, uint64_t size2, uint64_t offset2,
    exclaves_sensor_status_t *sensor_status);

__END_DECLS

#endif /* CONFIG_EXCLAVES */
