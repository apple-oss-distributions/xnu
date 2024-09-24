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
 * x86 processor and associated handles.
 */
#ifndef __IMAGE4_API_COPROCESSOR_X86_H
#define __IMAGE4_API_COPROCESSOR_X86_H

#include <image4/image4.h>
#include <image4/types.h>

__BEGIN_DECLS
OS_ASSUME_NONNULL_BEGIN
OS_ASSUME_PTR_ABI_SINGLE_BEGIN

/*!
 * @const IMAGE4_COPROCESSOR_X86
 * An x86 processor executing payloads signed by the x86 Secure Boot CA.
 *
 * Handles for this environment are enumerated in the
 * {@link image4_coprocessor_handle_x86_t} type.
 */
IMAGE4_API_AVAILABLE_SPRING_2024
OS_EXPORT
const image4_coprocessor_t _image4_coprocessor_x86;
#define IMAGE4_COPROCESSOR_X86 (&_image4_coprocessor_x86)
IMAGE4_XNU_AVAILABLE_INDIRECT(_image4_coprocessor_x86);

/*!
 * @typedef image4_coprocessor_handle_x86_t
 * Handles describing supported x86 execution environments.
 *
 * @const IMAGE4_COPROCESSOR_HANDLE_X86
 * The host's x86 environment.
 */
OS_CLOSED_ENUM(image4_coprocessor_handle_x86, image4_coprocessor_handle_t,
	IMAGE4_COPROCESSOR_HANDLE_X86 = 0,
	_IMAGE4_COPROCESSOR_HANDLE_X86_CNT,
);

/*!
 * @const IMAGE4_COPROCESSOR_HANDLE_X86_DEFAULT
 * The default handle for {@link IMAGE4_COPROCESSOR_X86}. This constant enables
 * `DEFAULT` to be used as the second and third arguments to
 * {@link image4_environment_init_coproc} and
 * {@link image4_environment_new_coproc} respectively.
 */
#define IMAGE4_COPROCESSOR_HANDLE_X86_DEFAULT \
	IMAGE4_COPROCESSOR_HANDLE_X86

OS_ASSUME_PTR_ABI_SINGLE_END
OS_ASSUME_NONNULL_END
__END_DECLS

#endif // __IMAGE4_API_COPROCESSOR_X86_H
