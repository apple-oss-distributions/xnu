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
 * Locally-Signed Application Processor and associated handles.
 */
#ifndef __IMAGE4_API_COPROCESSOR_AP_LOCAL_H
#define __IMAGE4_API_COPROCESSOR_AP_LOCAL_H

#include <image4/image4.h>
#include <image4/types.h>

__BEGIN_DECLS
OS_ASSUME_NONNULL_BEGIN
OS_ASSUME_PTR_ABI_SINGLE_BEGIN

/*!
 * @const IMAGE4_COPROCESSOR_AP_LOCAL
 * The Application Processor executing payloads signed by the Basic Attestation
 * Authority.
 *
 * Handles for this environment are enumerated in the
 * {@link image4_coprocessor_handle_ap_local_t} type.
 */
IMAGE4_API_AVAILABLE_SPRING_2024
OS_EXPORT
const image4_coprocessor_t _image4_coprocessor_ap_local;
#define IMAGE4_COPROCESSOR_AP_LOCAL (&_image4_coprocessor_ap_local)
IMAGE4_XNU_AVAILABLE_INDIRECT(_image4_coprocessor_ap_local);

/*!
 * @typedef image4_coprocessor_handle_ap_local_t
 * Handles describing supported local policy execution environments.
 *
 * @const IMAGE4_COPROCESSOR_HANDLE_AP_LOCAL
 * The host's local policy environment.
 */
OS_CLOSED_ENUM(image4_coprocessor_handle_ap_local, image4_coprocessor_handle_t,
	IMAGE4_COPROCESSOR_HANDLE_AP_LOCAL = 0,
	IMAGE4_COPROCESSOR_HANDLE_AP_LOCAL_RESERVED_0,
	IMAGE4_COPROCESSOR_HANDLE_AP_LOCAL_RESERVED_1,
	IMAGE4_COPROCESSOR_HANDLE_AP_LOCAL_RESERVED_2,
	_IMAGE4_COPROCESSOR_HANDLE_AP_LOCAL_CNT,
);

/*!
 * @const IMAGE4_COPROCESSOR_HANDLE_AP_LOCAL_DEFAULT
 * The default handle for {@link IMAGE4_COPROCESSOR_AP_LOCAL}. This constant
 * enables `DEFAULT` to be used as the second and third arguments to
 * {@link image4_environment_init_coproc} and
 * {@link image4_environment_new_coproc} respectively.
 */
#define IMAGE4_COPROCESSOR_HANDLE_AP_LOCAL_DEFAULT \
	IMAGE4_COPROCESSOR_HANDLE_AP_LOCAL

OS_ASSUME_PTR_ABI_SINGLE_END
OS_ASSUME_NONNULL_END
__END_DECLS

#endif // __IMAGE4_API_COPROCESSOR_AP_LOCAL_H
