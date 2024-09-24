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
 * Boot Policy Closure environment and associated handles.
 */
#ifndef __IMAGE4_API_COPROCESSOR_BOOTPC_H
#define __IMAGE4_API_COPROCESSOR_BOOTPC_H

#include <image4/image4.h>
#include <image4/types.h>

__BEGIN_DECLS
OS_ASSUME_NONNULL_BEGIN
OS_ASSUME_PTR_ABI_SINGLE_BEGIN

/*!
 * @const IMAGE4_COPROCESSOR_BOOTPC
 * An environment that facilitates computing boot policy closures without
 * performing trust evaluation on the manifest signature.
 *
 * Handles for this environment are enumerated in the
 * {@link image4_coprocessor_handle_bootpc_t} type.
 *
 * @section Supported Algorithms
 * The choice of algorithm should be made based on the algorithm that produced
 * the policy closure digest which is being compared.
 *
 * @discussion
 * This coprocessor environment should only be used to compute a policy closure
 * hash that is to be compared to a known-trustworthy measurement. It should not
 * be used to produce a measurement that is to be nominated for signing. The
 * algorithm choice should be made based on the algorithm that produced the
 * trustworthy measurement.
 *
 * @availability
 * This constant first became available in API version 20240223.
 */
IMAGE4_API_AVAILABLE_FALL_2024
OS_EXPORT
const image4_coprocessor_t _image4_coprocessor_bootpc;
#define IMAGE4_COPROCESSOR_BOOTPC (&_image4_coprocessor_bootpc)
IMAGE4_XNU_AVAILABLE_INDIRECT(_image4_coprocessor_bootpc);

/*!
 * @typedef image4_coprocessor_handle_bootpc_t
 * Handles describing supported boot policy closure environments.
 *
 * @const IMAGE4_COPROCESSOR_HANDLE_BOOTPC_SHA2_224
 * A policy closure whose digest is computed with sha2-224.
 *
 * @const IMAGE4_COPROCESSOR_HANDLE_BOOTPC_SHA2_256
 * A policy closure whose digest is computed with sha2-256.
 *
 * @const IMAGE4_COPROCESSOR_HANDLE_BOOTPC_SHA2_384
 * A policy closure whose digest is computed with sha2-384.
 *
 * @const IMAGE4_COPROCESSOR_HANDLE_BOOTPC_SHA2_512
 * A policy closure whose digest is computed with sha2-512.
 */
OS_CLOSED_ENUM(image4_coprocessor_handle_bootpc, image4_coprocessor_handle_t,
	IMAGE4_COPROCESSOR_HANDLE_BOOTPC_SHA2_224 = 0,
	IMAGE4_COPROCESSOR_HANDLE_BOOTPC_SHA2_256,
	IMAGE4_COPROCESSOR_HANDLE_BOOTPC_SHA2_384,
	IMAGE4_COPROCESSOR_HANDLE_BOOTPC_SHA2_512,
	_IMAGE4_COPROCESSOR_HANDLE_BOOTPC_CNT,
);

/*!
 * @const IMAGE4_COPROCESSOR_HANDLE_BOOTPC_DEFAULT
 * The default handle for {@link IMAGE4_COPROCESSOR_BOOTPC}. This constant
 * enables `DEFAULT` to be used as the second and third arguments to
 * {@link image4_environment_init_coproc} and
 * {@link image4_environment_new_coproc} respectively.
 */
#define IMAGE4_COPROCESSOR_HANDLE_BOOTPC_DEFAULT \
	IMAGE4_COPROCESSOR_HANDLE_BOOTPC_SHA2_384

OS_ASSUME_PTR_ABI_SINGLE_END
OS_ASSUME_NONNULL_END
__END_DECLS

#endif // __IMAGE4_API_COPROCESSOR_BOOTPC_H
