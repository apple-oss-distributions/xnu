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
 * Common types shared across the Image4 trust evaluation API.
 */
#ifndef __IMAGE4_API_TYPES_H
#define __IMAGE4_API_TYPES_H

#include <image4/image4.h>
#include <stdint.h>
#include <stddef.h>

__BEGIN_DECLS
OS_ASSUME_NONNULL_BEGIN
OS_ASSUME_PTR_ABI_SINGLE_BEGIN

#pragma mark Definitions
/*!
 * @const IMAGE4_DIGEST_MAX_LEN
 * The maximum size of a digest.
 */
#define IMAGE4_DIGEST_MAX_LEN (64u)

/*!
 * @const IMAGE4_NONCE_MAX_LEN
 * The maximum size of a nonce.
 */
#define IMAGE4_NONCE_MAX_LEN (16u)

#pragma mark Supporting Types
/*!
 * @typedef image4_struct_version_t
 * The version of a structure in the API.
 */
typedef uint16_t image4_struct_version_t;

/*!
 * @typedef image4_coprocessor_handle_t
 * A handle which specifies a particular execution environment within a
 * coprocessor.
 */
typedef uint64_t image4_coprocessor_handle_t;

/*!
 * @const IMAGE4_COPROCESSOR_HANDLE_NULL
 * An coprocessor handle which is invalid for all coprocessors. This constant is
 * suitable for initialization purposes only.
 */
#define IMAGE4_COPROCESSOR_HANDLE_NULL ((image4_coprocessor_handle_t)0xffff)

/*!
 * @typedef image4_secure_boot_t
 * An enumeration of secure boot levels.
 *
 * @const IMAGE4_SECURE_BOOT_FULL
 * Secure Boot will only accept a live, personalized manifest.
 *
 * @const IMAGE4_SECURE_BOOT_REDUCED
 * Secure Boot will only accept a globally-signed manifest whose lifetime is not
 * entangled with the individual silicon instance. The manifest's lifetime may
 * be statically constrained in other ways, but the device cannot unilaterally
 * host the manifest without a software change.
 *
 * @const IMAGE4_SECURE_BOOT_LEAST
 * Secure Boot will accept any Apple-signed manifest, and the manifest will not
 * be meaningfully enforced.
 *
 * @const IMAGE4_SECURE_BOOT_NONE
 * Secure Boot does not meaningfully exist.
 */
OS_CLOSED_ENUM(image4_secure_boot, uint64_t,
	IMAGE4_SECURE_BOOT_FULL,
	IMAGE4_SECURE_BOOT_REDUCED,
	IMAGE4_SECURE_BOOT_LEAST,
	IMAGE4_SECURE_BOOT_NONE,
	_IMAGE4_SECURE_BOOT_CNT,
);

/*!
 * @function image4_secure_boot_check
 * Checks the secure boot level to ensure that it represents a valid, known
 * secure boot configuration.
 *
 * @param sb
 * The secure boot level.
 *
 * @result
 * If the {@link sb} is a valid secure boot level, zero is returned. Otherwise,
 * a non-zero value is returned.
 */
OS_ALWAYS_INLINE OS_WARN_RESULT
static inline int
image4_secure_boot_check(image4_secure_boot_t sb)
{
	if (sb > _IMAGE4_SECURE_BOOT_CNT) {
		__builtin_trap();
	}
	if (sb == _IMAGE4_SECURE_BOOT_CNT) {
		return 1;
	}
	return 0;
}

#pragma mark API Objects
/*!
 * @typedef image4_coprocessor_t
 * An opaque structure representing a coprocessor.
 */
typedef struct _image4_coprocessor image4_coprocessor_t;

/*!
 * @typedef image4_environment_t
 * An opaque structure representing an Image4 trust evaluation environment.
 */
typedef struct _image4_environment image4_environment_t;

/*!
 * @typedef image4_identifier_t
 * An opaque structure representing an Image4 identifier.
 */
typedef struct _image4_identifier image4_identifier_t;

/*!
 * @typedef image4_trust_evaluation_t
 * An opaque structure representing an Image4 trust evaluation.
 */
typedef struct _image4_trust_evaluation image4_trust_evaluation_t;

/*!
 * @typedef image4_trust_t
 * An opaque structure representing an Image4 trust object which performs
 * evaluations.
 */
typedef struct _image4_trust image4_trust_t;

OS_ASSUME_PTR_ABI_SINGLE_END
OS_ASSUME_NONNULL_END
__END_DECLS

#endif // __IMAGE4_API_TYPES_H
