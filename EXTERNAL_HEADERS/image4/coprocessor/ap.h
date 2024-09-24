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
 * Application Processor and associated handles.
 */
#ifndef __IMAGE4_API_COPROCESSOR_AP_H
#define __IMAGE4_API_COPROCESSOR_AP_H

#include <image4/image4.h>
#include <image4/types.h>

__BEGIN_DECLS
OS_ASSUME_NONNULL_BEGIN
OS_ASSUME_PTR_ABI_SINGLE_BEGIN

/*!
 * @const IMAGE4_COPROCESSOR_AP
 * The Application Processor executing payloads signed by the Secure Boot CA.
 *
 * Handles for this environment are enumerated in the
 * {@link image4_coprocessor_ap_handle_t} type.
 */
IMAGE4_API_AVAILABLE_SPRING_2024
OS_EXPORT
const image4_coprocessor_t _image4_coprocessor_ap;
#define IMAGE4_COPROCESSOR_AP (&_image4_coprocessor_ap)
IMAGE4_XNU_AVAILABLE_INDIRECT(_image4_coprocessor_ap);

/*!
 * @typedef image4_coprocessor_handle_ap_t
 * Handles describing supported AP execution environments.
 *
 * @const IMAGE4_COPROCESSOR_HANDLE_AP
 * The host's Application Processor environment.
 *
 * @const IMAGE4_COPROCESSOR_HANDLE_AP_FF00
 * The software AP environment used for loading globally-signed OTA update brain
 * trust caches.
 *
 * @const IMAGE4_COPROCESSOR_HANDLE_AP_FF01
 * The software AP environment used for loading globally-signed Install
 * Assistant brain trust caches.
 *
 * @const IMAGE4_COPROCESSOR_HANDLE_AP_FF06
 * The software AP environment used for loading globally-signed Bootability
 * brain trust caches.
 *
 * @const IMAGE4_COPROCESSOR_HANDLE_AP_PDI
 * The sideloading AP environment used to load a personalized disk image.
 *
 * @const IMAGE4_COPROCESSOR_HANDLE_AP_SRDP
 * The sideloading AP environment used to load firmware which has been
 * authorized as part of the Security Research Device Program.
 *
 * @const IMAGE4_COPROCESSOR_HANDLE_AP_DDI
 * The sideloading AP environment used to load a personalized disk image which
 * is automatically mounted at boot.
 *
 * This handle is available starting in API version 20231027.
 *
 * @const IMAGE4_COPROCESSOR_HANDLE_AP_BOOTPC
 * The AP environment for use in calculating boot policy closures. While relying
 * parties can simply do an unauthenticated calculation to verify that a
 * manifest is consistent with an authorized closure measurement, the initial
 * generation of that authorized measurement must still verify that the boot
 * ticket was issued by the Secure Boot CA. This environment facilitates that
 * procedure.
 *
 * This handle is available starting in API version 20240318.
 */
OS_CLOSED_ENUM(image4_coprocessor_handle_ap, image4_coprocessor_handle_t,
	IMAGE4_COPROCESSOR_HANDLE_AP = 0,
	IMAGE4_COPROCESSOR_HANDLE_AP_FF00,
	IMAGE4_COPROCESSOR_HANDLE_AP_FF01,
	IMAGE4_COPROCESSOR_HANDLE_AP_FF06,
	IMAGE4_COPROCESSOR_HANDLE_AP_PDI,
	IMAGE4_COPROCESSOR_HANDLE_AP_SRDP,
	IMAGE4_COPROCESSOR_HANDLE_AP_RESERVED_0,
	IMAGE4_COPROCESSOR_HANDLE_AP_RESERVED_1,
	IMAGE4_COPROCESSOR_HANDLE_AP_RESERVED_2,
	IMAGE4_COPROCESSOR_HANDLE_AP_DDI,
	IMAGE4_COPROCESSOR_HANDLE_AP_BOOTPC,
	_IMAGE4_COPROCESSOR_HANDLE_AP_CNT,
);

/*!
 * @const IMAGE4_COPROCESSOR_HANDLE_AP_DEFAULT
 * The default handle for {@link IMAGE4_COPROCESSOR_AP}. This constant enables
 * `DEFAULT` to be used as the second and third arguments to
 * {@link image4_environment_init_coproc} and
 * {@link image4_environment_new_coproc} respectively.
 */
#define IMAGE4_COPROCESSOR_HANDLE_AP_DEFAULT IMAGE4_COPROCESSOR_HANDLE_AP

OS_ASSUME_PTR_ABI_SINGLE_END
OS_ASSUME_NONNULL_END
__END_DECLS

#endif // __IMAGE4_API_COPROCESSOR_AP_H
