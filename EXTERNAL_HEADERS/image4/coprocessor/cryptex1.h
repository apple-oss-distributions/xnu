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
 * Cryptex1 coprocessor and associated handles.
 */
#ifndef __IMAGE4_API_COPROCESSOR_CRYPTEX1_H
#define __IMAGE4_API_COPROCESSOR_CRYPTEX1_H

#include <image4/image4.h>
#include <image4/types.h>

__BEGIN_DECLS
OS_ASSUME_NONNULL_BEGIN
OS_ASSUME_PTR_ABI_SINGLE_BEGIN

/*!
 * @const IMAGE4_COPROCESSOR_CRYPTEX1
 * The Cryptex1 coprocessor executing payloads signed by the Secure Boot Extra
 * Content CA.
 *
 * Handles for this environment are enumerated in the
 * {@link image4_coprocessor_handle_cryptex1_t} type.
 */
IMAGE4_API_AVAILABLE_SPRING_2024
OS_EXPORT
const image4_coprocessor_t _image4_coprocessor_cryptex1;
#define IMAGE4_COPROCESSOR_CRYPTEX1 (&_image4_coprocessor_cryptex1)
IMAGE4_XNU_AVAILABLE_INDIRECT(_image4_coprocessor_cryptex1);

/*!
 * @typedef image4_coprocessor_handle_cryptex1_t
 * Handles describing supported Cryptex1 execution environments.
 *
 * @const IMAGE4_COPROCESSOR_HANDLE_CRYPTEX1_BOOT
 * The host's Cryptex1 boot coprocessor.
 *
 * @const IMAGE4_COPROCESSOR_HANDLE_CRYPTEX1_BOOT_LIVE
 * The host's Cryptex1 boot coprocessor used for executing newly-authorized
 * firmware prior to that firmware being evaluated by Secure Boot.
 *
 * @const IMAGE4_COPROCESSOR_HANDLE_CRYPTEX1_ASSET_BRAIN
 * The host's Cryptex1 coprocessor used for loading MobileAsset brain firmware.
 *
 * @const IMAGE4_COPROCESSOR_HANDLE_CRYPTEX1_GENERIC
 * The host's Cryptex1 coprocessor used for loading generic supplemental
 * content.
 */
OS_CLOSED_ENUM(image4_coprocessor_handle_cryptex1, image4_coprocessor_handle_t,
	IMAGE4_COPROCESSOR_HANDLE_CRYPTEX1_BOOT = 0,
	IMAGE4_COPROCESSOR_HANDLE_CRYPTEX1_BOOT_LIVE,
	IMAGE4_COPROCESSOR_HANDLE_CRYPTEX1_ASSET_BRAIN,
	IMAGE4_COPROCESSOR_HANDLE_CRYPTEX1_GENERIC,
	IMAGE4_COPROCESSOR_HANDLE_CRYPTEX1_RESERVED_0,
	IMAGE4_COPROCESSOR_HANDLE_CRYPTEX1_RESERVED_1,
	IMAGE4_COPROCESSOR_HANDLE_CRYPTEX1_RESERVED_2,
	_IMAGE4_COPROCESSOR_HANDLE_CRYPTEX1_CNT,
);

/*!
 * @const IMAGE4_COPROCESSOR_HANDLE_CRYPTEX1_DEFAULT
 * The default handle for {@link IMAGE4_COPROCESSOR_CRYPTEX1}. This constant
 * enables `DEFAULT` to be used as the second and third arguments to
 * {@link image4_environment_init_coproc} and
 * {@link image4_environment_new_coproc} respectively.
 */
#define IMAGE4_COPROCESSOR_HANDLE_CRYPTEX1_DEFAULT \
	IMAGE4_COPROCESSOR_HANDLE_CRYPTEX1_BOOT

OS_ASSUME_PTR_ABI_SINGLE_END
OS_ASSUME_NONNULL_END
__END_DECLS

#endif // __IMAGE4_API_COPROCESSOR_CRYPTEX1_H
