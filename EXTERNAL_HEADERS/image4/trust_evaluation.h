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
 * Encapsulation which describes an Image4 trust evaluation procedure. The type
 * of procedure impacts the result delivered to the
 * {@link image4_trust_evaluation_result_t}.
 *
 * All trust evaluations require a manifest to be present in the trust object.
 */
#ifndef __IMAGE4_API_TRUST_EVALUATION_H
#define __IMAGE4_API_TRUST_EVALUATION_H

#include <image4/image4.h>
#include <image4/types.h>

__BEGIN_DECLS
OS_ASSUME_NONNULL_BEGIN
OS_ASSUME_PTR_ABI_SINGLE_BEGIN

/*!
 * @const IMAGE4_TRUST_EVALUATION_EXEC
 * The trust evaluation is intended to execute firmware in the designated
 * environment. This is to be used for either first- or second-stage boots.
 *
 * This type of trust evaluation requires a payload.
 *
 * @section Trust Evaluation Result
 * Upon successful evaluation, the result is a pointer to the unwrapped Image4
 * payload bytes.
 *
 * @discussion
 * This trust evaluation is supported on all targets.
 */
IMAGE4_API_AVAILABLE_SPRING_2024
OS_EXPORT
const image4_trust_evaluation_t _image4_trust_evaluation_exec;
#define IMAGE4_TRUST_EVALUATION_EXEC (&_image4_trust_evaluation_exec)
IMAGE4_XNU_AVAILABLE_INDIRECT(_image4_trust_evaluation_exec);

/*!
 * @const IMAGE4_TRUST_EVALUATION_PREFLIGHT
 * The trust evaluation is intended to preflight a manifest to verify that it is
 * likely to be accepted during a boot trust evaluation in the future. This is
 * a best effort evaluation, and depending on the environment, certain
 * enforcement policies may be relaxed due to the relevant information not being
 * available.
 *
 * This type of trust evaluation does not require a payload.
 *
 * @section Trust Evaluation Result
 * The result is an error code indicating whether the manifest is likely to be
 * accepted by the environment.
 *
 * @discussion
 * This type of trust evaluation is not supported on all targets.
 */
IMAGE4_API_AVAILABLE_SPRING_2024
OS_EXPORT
const image4_trust_evaluation_t _image4_trust_evaluation_preflight;
#define IMAGE4_TRUST_EVALUATION_PREFLIGHT (&_image4_trust_evaluation_preflight)
IMAGE4_XNU_AVAILABLE_INDIRECT(_image4_trust_evaluation_preflight);

/*!
 * @const IMAGE4_TRUST_EVALUATION_SIGN
 * The trust evaluation is intended to facilitate counter-signing the manifest.
 *
 * @section Trust Evaluation Result
 * Upon successful evaluation, the result is a pointer to the digest of the
 * manifest. The digest is computed using the algorithm specified by the
 * environment.
 *
 * @discussion
 * This type of trust evaluation is not supported on all targets.
 */
IMAGE4_API_AVAILABLE_SPRING_2024
OS_EXPORT
const image4_trust_evaluation_t _image4_trust_evaluation_sign;
#define IMAGE4_TRUST_EVALUATION_SIGN (&_image4_trust_evaluation_sign)
IMAGE4_XNU_AVAILABLE_INDIRECT(_image4_trust_evaluation_sign);

/*!
 * @const IMAGE4_TRUST_EVALUATION_BOOT
 * The trust evaluation is intended to bootstrap a subsequent trust evaluation
 * in a chain of trust. The ultimate purpose of the chain of trust must be to
 * either preflight a manifest or sign it.
 *
 * This type of trust evaluation does not require a payload.
 *
 * @section Trust Evaluation Result
 * This type of trust evaluation is not intended to be performed directly by way
 * of {@link image4_trust_evaluate}. It is instead intended to create a trust
 * object which can be used as a previous stage of boot for another trust object
 * by way of {@link image4_trust_set_booter}.
 *
 * However, if the caller wishes to perform a boot trust evaluation directly,
 * then the trust evaluation result equivalent to that of
 * {@link IMAGE4_TRUST_EVALUATION_SIGN}.
 *
 * @discussion
 * This trust evaluation is supported on all targets.
 */
IMAGE4_API_AVAILABLE_SPRING_2024
OS_EXPORT
const image4_trust_evaluation_t _image4_trust_evaluation_boot;
#define IMAGE4_TRUST_EVALUATION_BOOT (&_image4_trust_evaluation_boot)
IMAGE4_XNU_AVAILABLE_INDIRECT(_image4_trust_evaluation_boot);

/*!
 * @const IMAGE4_TRUST_EVALUATION_NORMALIZE
 * The trust evaluation is intended to produce a normalized form of an Image4
 * manifest known as a "policy closure". This form of a manifest describes all
 * possible personalized instantiations of a manifest. The normalized contents
 * include all items in the signed section, i.e. all object dictionaries are
 * captured.
 *
 * Because this type of trust evaluation operates on all objects in the
 * manifest (as opposed to the object corresponding to a specific payload), only
 * manifest properties are recorded through the
 * {@link image4_trust_record_property_*} family of APIs. The property values
 * recorded are the ones from the source manifest, not the ones which were
 * inserted into the policy closure.
 *
 * Any payload provided to this type of trust evaluation is ignored.
 *
 * @section Trust Evaluation Result
 * Upon successful evaluation, the result is a pointer to the resulting Image4
 * manifest object representing the closure.
 *
 * @discussion
 * This trust evaluation is only supported on targets which have an allocator.
 * The pointer to the resulting bytes is not valid beyond the scope of the
 * trust evaluation callback.
 *
 * @availability
 * This constant first became available in API version 20231215.
 */
IMAGE4_API_AVAILABLE_FALL_2024
OS_EXPORT
const image4_trust_evaluation_t _image4_trust_evaluation_normalize;
#define IMAGE4_TRUST_EVALUATION_NORMALIZE (&_image4_trust_evaluation_normalize)
IMAGE4_XNU_AVAILABLE_INDIRECT(_image4_trust_evaluation_normalize);

OS_ASSUME_PTR_ABI_SINGLE_END
OS_ASSUME_NONNULL_END
__END_DECLS

#endif // __IMAGE4_API_TRUST_EVALUATION_H
