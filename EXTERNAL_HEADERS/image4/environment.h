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
 * Encapsulation which describes an Image4 environment. The environment
 * encompasses chip properties and trust evaluation policies, including digest
 * algorithm selection and secure boot level enforcement.
 */
#ifndef __IMAGE4_API_ENVIRONMENT_H
#define __IMAGE4_API_ENVIRONMENT_H

#include <image4/image4.h>
#include <image4/types.h>
#include <image4/coprocessor.h>
#include <stdbool.h>

__BEGIN_DECLS
OS_ASSUME_NONNULL_BEGIN
OS_ASSUME_PTR_ABI_SINGLE_BEGIN

#pragma mark Forward Types
/*!
 * @typedef image4_environment_storage_t
 * The canonical type for environment storage.
 */
typedef struct _image4_environment_storage image4_environment_storage_t;

/*!
 * @typedef image4_environment_query_boot_nonce_t
 * A callback to provide the boot nonce for the environment.
 *
 * @param nv
 * The environment for which to retrieve the boot nonce.
 *
 * @param n
 * Storage in which the callee should write the nonce upon successful return.
 *
 * @param n_len
 * Storage in which the callee should write the nonce length upon successful
 * return.
 *
 * On function entry, the content of this parameter is undefined.
 *
 * @param _ctx
 * The context pointer which was provided during the environment's construction.
 *
 * @result
 * The callee is expected to return zero on success. Otherwise, the callee may
 * return one of the following POSIX error codes:
 *
 *     [ENOTSUP]  Obtaining the boot nonce is not supported; this will cause the
 *                implementation to act as if no callback was specified
 *     [ENOENT]   The boot nonce does not exist
 *     [ENXIO]    The boot nonce is not yet available for the environment, and
 *                the environment's bootstrap nonce (if any) should be used for
 *                anti-replay instead
 *
 * @discussion
 * This callback is utilized by exec, sign, and boot trust evaluations.
 */
typedef errno_t (*image4_environment_query_boot_nonce_t)(
	const image4_environment_t *nv,
	uint8_t n[__static_size _Nonnull IMAGE4_NONCE_MAX_LEN],
	size_t *n_len,
	void *_ctx
);

/*!
 * @typedef image4_environment_query_nonce_digest_t
 * A callback to provide a nonce digest for use during preflight trust
 * evaluations.
 *
 * @param nv
 * The environment for which to retrieve the boot nonce.
 *
 * @param nd
 * Storage in which the callee should write the nonce digest upon successful
 * return.
 *
 * @param nd_len
 * Storage in which the callee should write the nonce digest length upon
 * successful return.
 *
 * On function entry, the content of this parameter is undefined.
 *
 * @param _ctx
 * The context pointer which was provided during the environment's construction.
 *
 * @result
 * The callee is expected to return zero on success. Otherwise, the callee may
 * return one of the following POSIX error codes:
 *
 *     [ENOTSUP]  Obtaining the nonce digest is not supported; this will cause
 *                the implementation to act as if no callback was specified
 *     [ENOENT]   The nonce digest does not exist
 *
 * @discussion
 * This callback is utilized by preflight, sign, and boot trust evaluations. In
 * sign and trust trust evaluations, it is only called if the nonce itself
 * cannot be obtained from either the environment internally or the boot nonce
 * callback.
 */
typedef errno_t (*image4_environment_query_nonce_digest_t)(
	const image4_environment_t *nv,
	uint8_t nd[__static_size _Nonnull IMAGE4_DIGEST_MAX_LEN],
	size_t *nd_len,
	void *_ctx
);

/*!
 * @typedef image4_environment_identifier_bool_t
 * A callback which conveys the value of a Boolean identifier associated with
 * the environment during an identification.
 *
 * @param nv
 * The environment which is being identified.
 *
 * @param id4
 * The Boolean identifier.
 *
 * @param val
 * The value of the identifier.
 *
 * @param _ctx
 * The context pointer which was provided during the environment's construction.
 */
typedef void (*image4_environment_identifier_bool_t)(
	const image4_environment_t *nv,
	const image4_identifier_t *id4,
	bool val,
	void *_ctx
);

/*!
 * @typedef image4_environment_identifier_integer_t
 * A callback which conveys the value of an unsigned 64-bit integer identifier
 * associated with the environment during an identification.
 *
 * @param nv
 * The environment which is being identified.
 *
 * @param id4
 * The integer identifier.
 *
 * @param val
 * The value of the identifier.
 *
 * @param _ctx
 * The context pointer which was provided during the environment's construction.
 */
typedef void (*image4_environment_identifier_integer_t)(
	const image4_environment_t *nv,
	const image4_identifier_t *id4,
	uint64_t val,
	void *_ctx
);

/*!
 * @typedef image4_environment_identifier_data_t
 * A callback which conveys the value of an octet string identifier associated
 * with the environment during an identification.
 *
 * @param nv
 * The environment which is being identified.
 *
 * @param id4
 * The octet string identifier.
 *
 * @param vp
 * A pointer to the octet string bytes.
 *
 * @param vp_len
 * The length of the octet string indicated by {@link vp}.
 *
 * @param _ctx
 * The context pointer which was provided during the environment's construction.
 */
typedef void (*image4_environment_identifier_data_t)(
	const image4_environment_t *nv,
	const image4_identifier_t *id4,
	const void *vp,
	size_t vp_len,
	void *_ctx
);

/*!
 * @const IMAGE4_ENVIRONMENT_CALLBACKS_STRUCT_VERSION
 * The version of the {@link image4_environment_callbacks_t} structure supported
 * by the implementation.
 */
#define IMAGE4_ENVIRONMENT_CALLBACKS_STRUCT_VERSION (0u)

/*!
 * @struct image4_environment_callbacks_t
 * A callback structure which may be given to influence the behavior of an
 * {@link image4_environment_t}.
 *
 * @field nvcb_version
 * The version of the structure. Initialize to
 * {@link IMAGE4_ENVIRONMENT_CALLBACKS_STRUCT_VERSION}.
 *
 * @field nvcb_query_boot_nonce
 * The callback to query the boot nonce.
 *
 * @field nvcb_query_nonce_digest
 * The callback to query a nonce digest.
 *
 * @field nvcb_construct_boot
 * The callback to construct the boot sequence for the environment.
 *
 * @field nvcb_identifier_bool
 * The callback to convey a Boolean identifier in the environment.
 *
 * @field nvcb_identifier_integer
 * The callback to convey an integer identifier in the environment.
 *
 * @field nvcb_identifier_data
 * The callback to convey an octet string identifier in the environment.
 */
typedef struct _image4_environment_callbacks {
	image4_struct_version_t nvcb_version;
	image4_environment_query_boot_nonce_t _Nullable nvcb_query_boot_nonce;
	image4_environment_query_nonce_digest_t _Nullable nvcb_query_nonce_digest;
	image4_environment_identifier_bool_t _Nullable nvcb_identifier_bool;
	image4_environment_identifier_integer_t _Nullable nvcb_identifier_integer;
	image4_environment_identifier_data_t _Nullable nvcb_identifier_data;
} image4_environment_callbacks_t;

/*!
 * @const IMAGE4_ENVIRONMENT_STRUCT_VERSION
 * The version of the {@link image4_environment_t} structure supported by the
 * implementation.
 */
#define IMAGE4_ENVIRONMENT_STRUCT_VERSION (0u)

/*!
 * @struct image4_environment_storage_t
 * An opaque structure which is guaranteed to be large enough to accommodate an
 * {@link image4_environment_t}.
 *
 * @field __opaque
 * The opaque storage.
 */
struct _image4_environment_storage {
	uint8_t __opaque[256];
};

/*!
 * @const IMAGE4_TRUST_STORAGE_INIT
 * Initializer for a {@link image4_environment_storage_t} object.
 */
#define IMAGE4_ENVIRONMENT_STORAGE_INIT (image4_environment_storage_t){ \
	.__opaque = { 0x00 }, \
}

#pragma mark API
/*!
 * @function image4_environment_init
 * Initializes an environment in which to perform a trust evaluation.
 *
 * @param storage
 * The storage structure.
 *
 * @param coproc
 * The coprocessor which will perform the evaluation. If NULL,
 * {@link IMAGE4_COPROCESSOR_HOST} will be assumed.
 *
 * @param handle
 * The specific environment and policy within the coprocessor to use for
 * performing the evaluation. If {@link IMAGE4_COPROCESSOR_HOST} is used, this
 * parameter is ignored.
 *
 * @result
 * An initialized {@link image4_environment_t} object.
 */
IMAGE4_API_AVAILABLE_SPRING_2024
OS_EXPORT OS_WARN_RESULT OS_NONNULL1
image4_environment_t *
_image4_environment_init(
	image4_environment_storage_t *storage,
	const image4_coprocessor_t *_Nullable coproc,
	image4_coprocessor_handle_t handle,
	image4_struct_version_t v);
#define image4_environment_init(_storage, _coproc, _handle) \
	_image4_environment_init( \
		(_storage), \
		(_coproc), \
		(_handle), \
		IMAGE4_ENVIRONMENT_STRUCT_VERSION)
IMAGE4_XNU_AVAILABLE_INDIRECT(_image4_environment_init);

/*!
 * @function image4_environment_init_coproc
 * A less-verbose form of {@link image4_environment_init}.
 *
 * @param _storage
 * The storage structure.
 *
 * @param _coproc_short
 * The shortened form of the coprocessor name, e.g. `AP` for
 * `IMAGE4_COPROCESSOR_AP`.
 *
 * @param _handle_short
 * The shortened form of the coprocessor handle name, e.g. `FF00` for
 * `IMAGE4_COPROCESSOR_AP_FF00`.
 *
 * @result
 * An initialized {@link image4_environment_t} object.
 *
 * @example
 * The following two code snippets are equivalent.
 *
 *     nv = image4_environment_init(
 *             &s,
 *             IMAGE4_COPROCESSOR_CRYPTEX1,
 *             IMAGE4_COPROCESSOR_CRYPTEX1_BOOT);
 * and
 *
 *     nv = image4_environment_init_coproc(&s, CRYPTEX1, BOOT);
 */
#define image4_environment_init_coproc(_storage, _coproc_short, _handle_short) \
	image4_environment_init( \
		(_storage), \
		IMAGE4_COPROCESSOR_ ## _coproc_short, \
		IMAGE4_COPROCESSOR_HANDLE_ ## _coproc_short ## _ ## _handle_short)

/*!
 * @function image4_environment_new
 * Allocates an environment in which to perform a trust evaluation.
 *
 * @param coproc
 * The coprocessor which will perform the evaluation. If NULL,
 * {@link IMAGE4_COPROCESSOR_HOST} will be assumed.
 *
 * @param handle
 * The specific environment and policy within the coprocessor to use for
 * performing the evaluation. If {@link IMAGE4_COPROCESSOR_HOST} is used, this
 * parameter is ignored.
 *
 * @result
 * A newly-allocated and initialized {@link image4_environment_t} object. The
 * caller is responsible for disposing of this object with
 * {@link image4_environment_destroy} when it is no longer needed.
 *
 * If insufficient resources were available to allocate the object, or if the
 * host runtime does not have an allocator, NULL is returned.
 */
IMAGE4_API_AVAILABLE_SPRING_2024
OS_EXPORT OS_WARN_RESULT
image4_environment_t *_Nullable
image4_environment_new(
	const image4_coprocessor_t *_Nullable coproc,
	image4_coprocessor_handle_t handle);
IMAGE4_XNU_AVAILABLE_DIRECT(image4_environment_new);

/*!
 * @function image4_environment_new_coproc
 * A less-verbose form of {@link image4_environment_new}.
 *
 * @param _coproc_short
 * The shortened form of the coprocessor name, e.g. `AP` for
 * `IMAGE4_COPROCESSOR_AP`.
 *
 * @param _handle_short
 * The shortened form of the coprocessor handle name, e.g. `FF00` for
 * `IMAGE4_COPROCESSOR_AP_FF00`.
 *
 * @result
 * A newly-allocated and initialized {@link image4_environment_t} object. The
 * caller is responsible for disposing of this object with
 * {@link image4_environment_destroy} when it is no longer needed.
 *
 * If insufficient resources were available to allocate the object, or if the
 * host runtime does not have an allocator, NULL is returned.
 *
 * @example
 * The following two code snippets are equivalent.
 *
 *     nv = image4_environment_new(
 *             IMAGE4_COPROCESSOR_CRYPTEX1,
 *             IMAGE4_COPROCESSOR_CRYPTEX1_BOOT);
 * and
 *
 *     nv = image4_environment_new_coproc(CRYPTEX1, BOOT);
 */
#define image4_environment_new_coproc(_coproc_short, _handle_short) \
	image4_environment_new( \
		IMAGE4_COPROCESSOR_ ## _coproc_short, \
		IMAGE4_COPROCESSOR_HANDLE_ ## _coproc_short ## _ ## _handle_short)

/*!
 * @function image4_environment_set_secure_boot
 * Sets the desired secure boot level of the environment.
 *
 * @param nv
 * The environment to manipulate.
 *
 * @param secure_boot
 * The desired secure boot level.
 *
 * @discussion
 * If the environment designated by the coprocessor and handle does not support
 * secure boot, this is a no-op.
 */
IMAGE4_API_AVAILABLE_SPRING_2024
OS_EXPORT OS_NONNULL1
void
image4_environment_set_secure_boot(
	image4_environment_t *nv,
	image4_secure_boot_t secure_boot);
IMAGE4_XNU_AVAILABLE_DIRECT(image4_environment_set_secure_boot);

/*!
 * @function image4_environment_set_nonce_domain
 * Sets the nonce domain number for the environment. This value will be returned
 * as the value for the coprocessor's nonce domain property during environment
 * iteration (e.g. if the environment is a Cryptex1 coprocessor handle, the ndom
 * property).
 *
 * @param nv
 * The environment to modify.
 *
 * @param nonce_domain
 * The nonce domain number to set.
 *
 * @discussion
 * This operation does not impact trust evaluation, which always defers to the
 * nonce domain signed into the manifest if one is present. It is intended to
 * support two workflows:
 *
 *     1. Constructing a personalization request using the callbacks associated
 *        with {@link image4_environment_identify} by allowing all the code that
 *        sets the values of the TSS request to reside in the identifier
 *        callbacks
 *     2. Related to the above, performing nonce management operations on the
 *        nonce slot associated by the given domain (e.g. generating a proposal
 *        nonce with {@link image4_environment_generate_nonce_proposal})
 *
 * Certain coprocessor environments recognize a nonce domain entitlement, but
 * only one valid value for that entitlement (e.g.
 * {@link IMAGE4_COPROCESSOR_HANDLE_CRYPTEX1_BOOT}). These environments do not
 * require the nonce domain to be set; it is automatically recognized based on
 * the static properties of the coprocessor.
 */
IMAGE4_API_AVAILABLE_SPRING_2024
OS_EXPORT OS_NONNULL1
void
image4_environment_set_nonce_domain(
	image4_environment_t *nv,
	uint32_t nonce_domain);
IMAGE4_XNU_AVAILABLE_DIRECT(image4_environment_set_nonce_domain);

/*!
 * @function image4_environment_set_callbacks
 * Sets the callbacks for an environment.
 *
 * @param nv
 * The environment to manipulate.
 *
 * @param callbacks
 * The callback structure.
 *
 * @param _ctx
 * The caller-defined context to be passed to each callback.
 */
IMAGE4_API_AVAILABLE_SPRING_2024
OS_EXPORT OS_NONNULL1 OS_NONNULL2
void
image4_environment_set_callbacks(
	image4_environment_t *nv,
	const image4_environment_callbacks_t *callbacks,
	void *_Nullable _ctx);
IMAGE4_XNU_AVAILABLE_DIRECT(image4_environment_set_callbacks);

/*!
 * @function image4_environment_identify
 * Identifies the environment and provides the identity via the callbacks
 * specified in the {@link image4_environment_callbacks_t} structure set for
 * the environment.
 *
 * @param nv
 * The environment to identify.
 *
 * @discussion
 * If no callbacks were provided, or if no identifier callbacks were set in the
 * callback structure, the implementation's behavior is undefined.
 */
IMAGE4_API_AVAILABLE_SPRING_2024
OS_EXPORT OS_NONNULL1
void
image4_environment_identify(
	const image4_environment_t *nv);
IMAGE4_XNU_AVAILABLE_DIRECT(image4_environment_identify);

/*!
 * @function image4_environment_get_digest_info
 * Retrieves the CoreCrypto digest info structure which the environment uses to
 * compute digests.
 *
 * @param nv
 * The environment to query.
 *
 * @result
 * A pointer to the CoreCrypto digest info structure corresponding to the
 * environment.
 *
 * @availability
 * This function first became available in API version 20231215.
 */
IMAGE4_API_AVAILABLE_FALL_2024
OS_EXPORT OS_WARN_RESULT OS_NONNULL1
const struct ccdigest_info *
image4_environment_get_digest_info(
		const image4_environment_t *nv);
IMAGE4_XNU_AVAILABLE_DIRECT(image4_environment_get_digest_info);

/*!
 * @function image4_environment_copy_nonce_digest
 * Copies the digest of the specified nonce.
 *
 * @param nv
 * The environment to query.
 *
 * @param d
 * Upon successful return, the digest of the live nonce for the environment. On
 * failure, the contents of this structure are undefined.
 *
 * @param d_len
 * Upon successful return, the length of the nonce digest.
 *
 * @result
 * Upon success, zero is returned. Otherwise, the implementation may directly
 * return one of the following POSIX error codes:
 *
 *     [EPERM]    The caller lacks the entitlement required to access the
 *                desired nonce
 *     [ENOTSUP]  The environment does not manage a nonce for anti-replay
 *     [ESTALE]   The nonce has been invalidated and will not be available until
 *                the next boot
 */
IMAGE4_API_AVAILABLE_SPRING_2024
OS_EXPORT OS_WARN_RESULT OS_NONNULL1 OS_NONNULL2 OS_NONNULL3
errno_t
image4_environment_copy_nonce_digest(
	const image4_environment_t *nv,
	uint8_t d[__static_size _Nonnull IMAGE4_DIGEST_MAX_LEN],
	size_t *d_len);
IMAGE4_XNU_AVAILABLE_DIRECT(image4_environment_copy_nonce_digest);

/*!
 * @function image4_environment_roll_nonce
 * Invalidates the live nonce for the environment such that a new nonce will be
 * generated at the next boot.
 *
 * @param nv
 * The environment to manipulate.
 *
 * @result
 * Upon success, zero is returned. Otherwise, the implementation may directly
 * return one of the following POSIX error codes:
 *
 *     [EPERM]    The caller lacks the entitlement required to access the
 *                desired nonce
 *     [ENOTSUP]  The environment does not manage a nonce for anti-replay
 */
IMAGE4_API_AVAILABLE_SPRING_2024
OS_EXPORT OS_WARN_RESULT OS_NONNULL1
errno_t
image4_environment_roll_nonce(
	const image4_environment_t *nv);
IMAGE4_XNU_AVAILABLE_DIRECT(image4_environment_roll_nonce);

/*!
 * @function image4_environment_generate_nonce_proposal
 * Generates a nonce proposal for the environment and returns the hash of the
 * proposal.
 *
 * @param nv
 * The environment to manipulate.
 *
 * @param d
 * Upon successful return, the digest of the proposal nonce which was
 * generated. On failure, the contents of this structure are undefined.
 *
 * @param d_len
 * Upon successful return, the length of the nonce digest.
 *
 * @param n
 * Upon successful return, the proposal nonce which was generated.
 *
 * This parameter may be NULL. If the caller's minimum deployment target is less
 * than macOS 15 or iOS 17, and the caller is building with -fbounds-checking,
 * then the caller must pass a non-NULL parameter.
 *
 * @param n_len
 * Upon input, the length of the buffer referred to by {@link n}. Since
 * {@link n} can be NULL, C does not permit the static qualifier to enforce a
 * minimum array size, and therefore this parameter communicates the length of
 * the buffer to the callee. Upon successful return, the this parameter will
 * be the length of the nonce returned in {@link n}.
 *
 * @result
 * Upon success, zero is returned. Otherwise, the implementation may directly
 * return one of the following POSIX error codes:
 *
 *     [EPERM]    The caller lacks the entitlement required to manipulate the
 *                desired nonce
 *     [EACCES]   The caller requested the proposal nonce in addition to its
 *                digest, and the environment does not support returning the
 *                nonce to the caller's execution context
 *     [ENOTSUP]  The environment does not manage a nonce for anti-replay
 *
 * @discussion
 * The {@link n} and {@link n_len} parameters must either both be NULL or non-
 * NULL. Passing NULL for one but not the other will result in undefined
 * behavior in the implementation.
 *
 * If the caller's minimum deployment target is less than macOS 15 or iOS 17,
 * and the caller is building with -fbounds-checking, then the caller must pass
 * non-NULL values for both {@link n} and {@link n_len}. In this case, the value
 * referred to be {@link n_len} should be 0 to indicate to the implementation
 * that the proposal nonce itself is not desired.
 */
IMAGE4_API_AVAILABLE_SPRING_2024
OS_EXPORT OS_WARN_RESULT OS_NONNULL1 OS_NONNULL2
errno_t
image4_environment_generate_nonce_proposal(
	const image4_environment_t *nv,
	uint8_t d[__static_size _Nonnull IMAGE4_DIGEST_MAX_LEN],
	size_t *d_len,
	uint8_t n[__static_array_or_null(IMAGE4_NONCE_MAX_LEN)],
	size_t *_Nullable n_len);
IMAGE4_XNU_AVAILABLE_DIRECT(image4_environment_generate_nonce_proposal);

/*!
 * @function image4_environment_commit_nonce_proposal
 * Commits the nonce proposal corresponding to the digest provided by the caller
 * such that it will be accepted and live at the next boot.
 *
 * @param nv
 * The environment to manipulate.
 *
 * @param d
 * The digest of the proposal to commit.
 *
 * @param d_len
 * The length of the nonce proposal digest.
 *
 * @result
 * Upon success, zero is returned. Otherwise, the implementation may directly
 * return one of the following POSIX error codes:
 *
 *     [EPERM]    The caller lacks the entitlement required to manipulate the
 *                desired nonce
 *     [ENOTSUP]  The environment does not manage a nonce for anti-replay
 *     [ENODEV]   There is no proposal for the given nonce
 *     [EILSEQ]   The digest provided by the caller does not correspond to the
 *                active proposal; this may occur if another subsystem
 *                generates a proposal for the environment
 */
IMAGE4_API_AVAILABLE_SPRING_2024
OS_EXPORT OS_WARN_RESULT OS_NONNULL1 OS_NONNULL2
errno_t
image4_environment_commit_nonce_proposal(
	const image4_environment_t *nv,
	const uint8_t d[__static_size _Nonnull IMAGE4_DIGEST_MAX_LEN],
	size_t *d_len);
IMAGE4_XNU_AVAILABLE_DIRECT(image4_environment_commit_nonce_proposal);

/*!
 * @function image4_environment_flash
 * Activates an Image4 object with the provided environment.
 *
 * @param nv
 * The environment to manipulate.
 *
 * @param object
 * A pointer to the Image4 object bytes that will be activated. These bytes must
 * represent a complete Image4 object. If the environment requires personalized
 * signatures, then the object must also have a RestoreInfo section with the DFU
 * nonce set in the appropriate property.
 *
 * @param object_len
 * The length of the buffer referenced by {@link object}.
 *
 * @param n
 * Upon successful return, the value of the nonce which was consumed during the
 * DFU operation. The caller is expected to store this value in a RestoreInfo
 * section in order to subsequently verify the manifest.
 *
 * This parameter may be NULL.
 *
 * @param n_len
 * Upon input, the length of the buffer referred to by {@link n}. Since
 * {@link n} can be NULL, C does not permit the static qualifier to enforce a
 * minimum array size, and therefore this parameter communicates the length of
 * the buffer to the callee. Upon successful return, the this parameter will
 * be the length of the nonce returned in {@link n}.
 *
 * @result
 * Upon success, zero is returned. Otherwise, the implementation may directly
 * return one of the following POSIX error codes:
 *
 *     [EPERM]    The caller lacks the entitlement required to DFU the
 *                environment
 *     [ENOTSUP]  The environment does not support DFU in this target
 *
 * The implementation may also return any error that the
 * {@link image4_trust_evaluation_result_t} callback may deliver to its callee.
 *
 * @availability
 * This function first became available in API version 20240112.
 *
 * @discussion
 * The {@link n} and {@link n_len} parameters must either both be NULL or non-
 * NULL. Passing NULL for one but not the other will result in undefined
 * behavior in the implementation.
 *
 * If the caller's minimum deployment target is less than macOS 15 or iOS 17,
 * and the caller is building with -fbounds-checking, then the caller must pass
 * non-NULL values for both {@link n} and {@link n_len}. In this case, the value
 * referred to be {@link n_len} should be 0 to indicate to the implementation
 * that the proposal nonce itself is not desired.
 */
IMAGE4_API_AVAILABLE_FALL_2024
OS_EXPORT OS_WARN_RESULT OS_NONNULL1 OS_NONNULL2
errno_t
image4_environment_flash(
	const image4_environment_t *nv,
	const void *__sized_by(object_len) object,
	size_t object_len,
	uint8_t n[__static_array_or_null(IMAGE4_NONCE_MAX_LEN)],
	size_t *_Nullable n_len);
IMAGE4_XNU_AVAILABLE_DIRECT(image4_environment_flash);

/*!
 * @function image4_environment_destroy
 * Disposes an environment object which was created via
 * {@link image4_environment_new}.
 *
 * @param nv
 * A pointer to the environment object. Upon return, this storage will be set to
 * NULL. If the object pointed to by this parameter is NULL, this is a no-op.
 *
 * @discussion
 * If this routine is called on an environment object which was not allocated,
 * it is a no-op.
 */
IMAGE4_API_AVAILABLE_SPRING_2024
OS_EXPORT OS_NONNULL1
void
image4_environment_destroy(
	image4_environment_t *_Nonnull *_Nullable nv);
IMAGE4_XNU_AVAILABLE_DIRECT(image4_environment_destroy);

#pragma mark Retired
IMAGE4_XNU_RETIRED_DIRECT(image4_environment_get_nonce_handle);

OS_ASSUME_PTR_ABI_SINGLE_END
OS_ASSUME_NONNULL_END
__END_DECLS

#endif // __IMAGE4_API_ENVIRONMENT_H
