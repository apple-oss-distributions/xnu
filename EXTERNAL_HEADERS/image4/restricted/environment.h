/*
 * Copyright © 2017-2024 Apple Inc. All rights reserved.
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
/*!
 * @header
 * Restricted environment interfaces.
 */
#ifndef __IMAGE4_API_RESTRICTED_ENVIRONMENT_H
#define __IMAGE4_API_RESTRICTED_ENVIRONMENT_H

#include <image4/image4.h>
#include <image4/environment.h>

__BEGIN_DECLS
OS_ASSUME_NONNULL_BEGIN
OS_ASSUME_PTR_ABI_SINGLE_BEGIN

#pragma mark Restricted API
/*!
 * @function image4_environment_get_firmware_chip
 * Returns the legacy chip pointer corresponding to an environment.
 *
 * @param nv
 * The environment to query.
 *
 * @result
 * Upon success, a pointer to an object which can be safely cast to an
 * `const img4_chip_t *` is returned. If the environment does not support
 * returning a legacy chip, NULL is returned.
 *
 * @availability
 * This API is restricted and should only be called via the
 * {@link image4_restricted_call} macro.
 *
 * This function first became available in restricted API version 1000; it will
 * be functionally neutered in version 2000.
 */
OS_EXPORT OS_WARN_RESULT OS_NONNULL2
const void *_Nullable
image4_environment_get_firmware_chip(
	uint32_t v,
	const image4_environment_t *nv);
#define image4_environment_get_firmware_chip(...) \
	image4_call_restricted(environment_get_firmware_chip, ## __VA_ARGS__)

OS_ASSUME_PTR_ABI_SINGLE_END
OS_ASSUME_NONNULL_END
__END_DECLS

#endif // __IMAGE4_API_RESTRICTED_ENVIRONMENT_H
