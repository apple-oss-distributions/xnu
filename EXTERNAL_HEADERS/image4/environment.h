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
 * @param env
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
	const image4_environment_t *env,
	uint8_t n[__static_size _Nonnull IMAGE4_NONCE_MAX_LEN],
	size_t *n_len,
	void *_ctx
);

/*!
 * @typedef image4_environment_query_nonce_digest_t
 * A callback to provide a nonce digest for use during preflight trust
 * evaluations.
 *
 * @param env
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
	const image4_environment_t *env,
	uint8_t nd[__static_size _Nonnull IMAGE4_NONCE_DIGEST_MAX_LEN],
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
 * @function image4_environment_copy_nonce_digest
 * Copies the digest of the specified nonce.
 *
 * @param nv
 * The environment to query.
 *
 * @param digest
 * Upon successful return, the digest of the live nonce for the environment. On
 * failure, the contents of this structure are undefined.
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
OS_EXPORT OS_WARN_RESULT OS_NONNULL1 OS_NONNULL2
errno_t
image4_environment_copy_nonce_digest(
	const image4_environment_t *nv,
	image4_nonce_digest_t *digest);
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
 * @param digest
 * Upon successful return, the digest of the nonce proposal which was generated.
 * On failure, the contents of this structure are undefined.
 *
 * @result
 * Upon success, zero is returned. Otherwise, the implementation may directly
 * return one of the following POSIX error codes:
 *
 *     [EPERM]    The caller lacks the entitlement required to manipulate the
 *                desired nonce
 *     [ENOTSUP]  The environment does not manage a nonce for anti-replay
 */
IMAGE4_API_AVAILABLE_SPRING_2024
OS_EXPORT OS_WARN_RESULT OS_NONNULL1 OS_NONNULL2
errno_t
image4_environment_generate_nonce_proposal(
	const image4_environment_t *nv,
	image4_nonce_digest_t *digest);
IMAGE4_XNU_AVAILABLE_DIRECT(image4_environment_generate_nonce_proposal);

/*!
 * @function image4_environment_commit_nonce_proposal
 * Commits the nonce proposal corresponding to the digest provided by the caller
 * such that it will be accepted and live at the next boot.
 *
 * @param nv
 * The environment to manipulate.
 *
 * @param digest
 * The digest of the proposal to commit.
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
	const image4_nonce_digest_t *digest);
IMAGE4_XNU_AVAILABLE_DIRECT(image4_environment_commit_nonce_proposal);

/*!
 * @function image4_environment_get_nonce_handle
 * Obtains the appropriate nonce handle to include in a signing request for the
 * environment.
 *
 * @param nv
 * The environment to query.
 *
 * @param handle
 * Upon successful return, the handle appropriate for the signing request's
 * nonce domain field. On failure, this parameter's value is undefined.
 *
 * @result
 * Upon success, zero is returned. Otherwise, the implementation may directly
 * return one of the following POSIX error codes:
 *
 *     [ENOTSUP]  The environment does not manage a nonce for anti-replay
 *     [ENOENT]   The environment does not support identifing a nonce by its
 *                handle in the personalization request
 *
 * @discussion
 * This function is not implemented and will be removed. See discussion in
 * {@link image4_environment_set_nonce_handle} for guidance as to how to
 * implement the relevant workflows.
 */
IMAGE4_API_AVAILABLE_SPRING_2024
OS_EXPORT OS_WARN_RESULT OS_NONNULL1 OS_NONNULL2
errno_t
image4_environment_get_nonce_handle(
	const image4_environment_t *nv,
	uint64_t *handle);
IMAGE4_XNU_AVAILABLE_DIRECT(image4_environment_get_nonce_handle);

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

OS_ASSUME_PTR_ABI_SINGLE_END
OS_ASSUME_NONNULL_END
__END_DECLS

#endif // __IMAGE4_API_ENVIRONMENT_H
