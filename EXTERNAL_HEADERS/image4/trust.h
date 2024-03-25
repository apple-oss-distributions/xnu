/*!
 * @header
 * Encapsulation which describes an Image4 trust object. This object can perform
 * an evaluation in the context of a given environment, record properties that
 * were encountered during evaluation, and deliver the evaluation result to the
 * caller according to the type of evaluation being performed.
 */
#ifndef __IMAGE4_API_TRUST_H
#define __IMAGE4_API_TRUST_H

#include <image4/image4.h>
#include <image4/types.h>
#include <stdint.h>
#include <stdbool.h>

#if __has_include(<sys/types.h>)
#include <sys/types.h>
#else
typedef int errno_t;
#endif

__BEGIN_DECLS
OS_ASSUME_NONNULL_BEGIN
OS_ASSUME_PTR_ABI_SINGLE_BEGIN

#pragma mark Supporting Types
/*!
 * @typedef image4_trust_flags_t
 * Flags that may be provided to influence the behavior of an
 * {@link image4_trust_t} object.
 *
 * @const IMAGE4_TRUST_FLAG_INIT
 * No flags set. This value is suitable for initialization purposes.
 *
 * @const IMAGE4_TRUST_FLAG_VIOLATION_PANIC
 * Upon encountering a violation during trust evaluation, the implementation
 * should abort the current context.
 */
OS_CLOSED_OPTIONS(image4_trust_flags, uint64_t,
	IMAGE4_TRUST_FLAG_INIT = 0,
	IMAGE4_TRUST_FLAG_VIOLATION_PANIC = (1 << 0),
);

/*!
 * @typedef image4_trust_section_t
 * An enumeration of property sections in an Image4 manifest or object. Note
 * that this is not strictly aligned with the concept of a "section" as defined
 * in the Image4 specification.
 *
 * @const IMAGE4_TRUST_SECTION_CERTIFICATE
 * The certificate properties within the manifest section.
 *
 * @const IMAGE4_TRUST_SECTION_MANIFEST
 * The top-level properties in the manifest section.
 *
 * @const IMAGE4_TRUST_SECTION_OBJECT
 * The properties associated with a particular object in the manifest section.
 *
 * @const IMAGE4_TRUST_SECTION_RESTORE_INFO
 * The top-level properties in the RestoreInfo section. The RestoreInfo section
 * is only recognized by the implementation when the trust object has been
 * initialized with an IMG4 object that contains an IM4R section.
 *
 * This constant first became available in API version 20231103.
 *
 * @const IMAGE4_TRUST_SECTION_PAYLOAD_PROPERTIES
 * The properties associated with the payload that is associated with the trust
 * object, either by initializing the object with an IMG4 object, or by setting
 * a payload with {@link image4_trust_set_payload}.
 *
 * This constant first became available in API version 20231103.
 */
OS_CLOSED_ENUM(image4_trust_section, uint64_t,
	IMAGE4_TRUST_SECTION_CERTIFICATE,
	IMAGE4_TRUST_SECTION_MANIFEST,
	IMAGE4_TRUST_SECTION_OBJECT,
	IMAGE4_TRUST_SECTION_RESTORE_INFO,
	IMAGE4_TRUST_SECTION_PAYLOAD_PROPERTIES,
	_IMAGE4_TRUST_SECTION_CNT,
);

/*!
 * @typedef image4_trust_evaluation_result_t
 * A callback for the result of a trust evaluation.
 *
 * @param trst
 * The trust object.
 *
 * @param result
 * Upon success, the prescribed payload resulting from the type of trust
 * evaluation. If the trust evaluation type does not deliver a payload, or the
 * trust evaluation failed, NULL will be passed.
 *
 * @param result_len
 * The length of the buffer referenced by {@link payload}. If {@link payload} is
 * NULL, zero will be passed.
 *
 * @param error
 * A POSIX error code describing the result of the trust evaluation. Upon
 * success, zero will be passed.
 *
 * @param context
 * The caller-provided context pointer. If no context pointer was set, NULL will
 * be passed.
 */
typedef void (*image4_trust_evaluation_result_t)(
	const image4_trust_t *trst,
	const void *_Nullable result,
	size_t result_len,
	errno_t error,
	void *_Nullable context
);

/*!
 * @const IMAGE4_TRUST_STRUCT_VERSION
 * The version of the {@link image4_trust_t} structure supported by the
 * implementation.
 */
#define IMAGE4_TRUST_STRUCT_VERSION (0u)

/*!
 * @header image4_trust_storage_t
 * An opaque structure which is guaranteed to be large enough to accommodate an
 * {@link image4_trust_t}.
 *
 * @field __opaque
 * The opaque storage.
 *
 * @discussion
 * The size of this object was set in API version 20231103.
 */
typedef struct _image4_trust_storage {
	uint8_t __opaque[1920];
} image4_trust_storage_t;

/*!
 * @const IMAGE4_TRUST_STORAGE_INIT
 * Initializer for a {@link image4_trust_storage_t} object.
 */
#define IMAGE4_TRUST_STORAGE_INIT (image4_trust_storage_t){ \
	.__opaque = { 0x00 }, \
}

#pragma mark API
/*!
 * @function image4_trust_init
 * Convert a {@link image4_trust_storage_t} to an initialized
 * {@link image4_trust_t} object.
 *
 * @param storage
 * The storage structure.
 *
 * @param environment
 * The environment in which the trust evaluation should be performed.
 *
 * @param evaluation
 * The trust evaluation type that should be performed.
 *
 * @param manifest
 * A pointer to the Image4 manifest bytes. This buffer may refer to a stitched
 * manifest and payload object, in which case the implementation will extract
 * the manifest portion.
 *
 * These bytes are not copied into any implementation storage, and the caller is
 * responsible for ensuring that this memory remains valid for the duration of
 * the trust object's use.
 *
 * @param manifest_len
 * The length of the buffer referenced by {@link manifest}.
 *
 * @param flags
 * Flags to influence the behavior of the resulting trust object.
 *
 * @result
 * An initialized {@link image4_trust_t} object.
 */
IMAGE4_API_AVAILABLE_SPRING_2024
OS_EXPORT OS_WARN_RESULT OS_NONNULL1 OS_NONNULL2 OS_NONNULL3 OS_NONNULL4
image4_trust_t *
_image4_trust_init(
	image4_trust_storage_t *storage,
	const image4_environment_t *environment,
	const image4_trust_evaluation_t *evaluation,
	const void *__sized_by(manifest_len) manifest,
	size_t manifest_len,
	image4_trust_flags_t flags,
	image4_struct_version_t v);
#define image4_trust_init(_storage, _environment, _evaluation, \
		_manifest, _manifest_len, _flags) \
	_image4_trust_init( \
		(_storage), \
		(_environment), \
		(_evaluation), \
		(_manifest), \
		(_manifest_len), \
		(_flags), \
		IMAGE4_TRUST_STRUCT_VERSION)
IMAGE4_XNU_AVAILABLE_INDIRECT(_image4_trust_init);

/*!
 * @function image4_trust_new
 * Allocates a trust object.
 *
 * @param nv
 * The environment in which the trust evaluation should be performed.
 *
 * @param eval
 * The trust evaluation type that should be performed.
 *
 * @param manifest
 * A pointer to the Image4 manifest bytes. This buffer may refer to a stitched
 * manifest and payload object, in which case the implementation will extract
 * the manifest portion.
 *
 * These bytes are not copied into any implementation storage, and the caller is
 * responsible for ensuring that this memory remains valid for the duration of
 * the trust object's use.
 *
 * @param manifest_len
 * The length of the buffer referenced by {@link manifest}.
 *
 * @param flags
 * Flags to influence the behavior of the resulting trust object.
 *
 * @result
 * A newly-allocated and initialized {@link image4_trust_t} object. The caller
 * is responsible for disposing of this object with {@link image4_trust_destroy}
 * when it is no longer needed.
 *
 * If insufficient resources were available to allocate the object, or if the
 * host runtime does not have an allocator, NULL is returned.
 */
IMAGE4_API_AVAILABLE_SPRING_2024
OS_EXPORT OS_WARN_RESULT OS_NONNULL1 OS_NONNULL2 OS_NONNULL3
image4_trust_t *_Nullable
image4_trust_new(
	const image4_environment_t *nv,
	const image4_trust_evaluation_t *eval,
	const void *__sized_by(manifest_len) manifest,
	size_t manifest_len,
	image4_trust_flags_t flags);
IMAGE4_XNU_AVAILABLE_DIRECT(image4_trust_new);

/*!
 * @function image4_trust_set_payload
 * Sets the payload to be used during the trust evaluation.
 *
 * @param trst
 * The trust object.
 *
 * @param type
 * The four-character code of the payload.
 *
 * @param bytes
 * A pointer to the payload bytes to authenticate during trust evaluation. This
 * buffer may refer to a stitched manifest and payload object, in which case the
 * implementation will extract the payload portion.
 *
 * If the buffer does not refer to either a valid Image4 manifest or payload,
 * the implementation will conclude that it is a bare Image4 payload -- that is,
 * a payload which is not Image4-wrapped.
 *
 * These bytes are not copied into any implementation storage, and the caller is
 * responsible for ensuring that this memory remains valid for the duration of
 * the trust object's use.
 *
 * @param len
 * The length of the buffer referenced by {@link bytes}.
 */
IMAGE4_API_AVAILABLE_SPRING_2024
OS_EXPORT OS_NONNULL1 OS_NONNULL3
void
image4_trust_set_payload(
	image4_trust_t *trst,
	uint32_t type,
	const void *__sized_by(len) bytes,
	size_t len);
IMAGE4_XNU_AVAILABLE_DIRECT(image4_trust_set_payload);

/*!
 * @function image4_trust_set_booter
 * Establish a link between the trust object and another trust object
 * representing a previous stage of boot, securing it to that stage of boot.
 * This may be called multiple times. Successive calls secure the previously-
 * specified booter stage to the newly-specified booter stage, establishing a
 * chain of trust from the last stage to the first stage.
 *
 * @param trst
 * The trust object. This object must have been created with one of the
 * following trust evaluation types:
 *
 *     - {@link IMAGE4_TRUST_EVALUATION_PREFLIGHT}
 *     - {@link IMAGE4_TRUST_EVALUATION_SIGN}
 *
 * @param booter
 * The trust object representing the previous stage of boot for {@link trst}.
 * This object must have been created with the
 * {@link IMAGE4_TRUST_EVALUATION_BOOT} trust evaluation type.
 *
 * This object is not copied into any implementation storage, and the caller is
 * responsible for ensuring that it remains valid for the duration of the trust
 * object's use.
 *
 * @discussion
 * Trust objects with booter stages cannot be used to execute firmware because
 * they are only intended to simulate a boot by replicating side effects of
 * previous evaluations into the ultimate environment used by the trust object.
 *
 * In order to execute firmware, the environment must be consistent with the
 * requirements of the manifest without modifications being required.
 */
IMAGE4_API_AVAILABLE_SPRING_2024
OS_EXPORT OS_NONNULL1 OS_NONNULL2
void
image4_trust_set_booter(
	image4_trust_t *trst,
	const image4_trust_t *booter);
IMAGE4_XNU_AVAILABLE_DIRECT(image4_trust_set_booter);

/*!
 * @function image4_trust_record_property_bool
 * Records the specified Boolean value into caller-provided storage.
 *
 * @param trst
 * The trust object.
 *
 * @param type
 * The type of property to be recorded (currently either manifest or object).
 *
 * @param tag
 * The four character code of the property to capture.
 *
 * @param vp
 * A pointer to the storage where the value should be written.
 *
 * @param vpp
 * A pointer to storage where a pointer to the value should be written. This
 * allows the caller to know whether the property was encountered during the
 * trust evaluation at all. If the property was encountered, the storage
 * referred to by this pointer will hold the same pointer given in the
 * {@link vp} parameter.
 *
 * If the property was not encountered during trust evaluation, the contents of
 * this storage are undefined. The caller should initialize the storage to a
 * reasonable default.
 *
 * This may be NULL.
 *
 * @discussion
 * If the property represented a constraint which was not satisfied, the
 * implementation will not record its value.
 *
 * If the property associated with the given tag is present, but is not a
 * Boolean, the implementation will not record its value.
 */
IMAGE4_API_AVAILABLE_SPRING_2024
OS_EXPORT OS_NONNULL1 OS_NONNULL4
void
image4_trust_record_property_bool(
	image4_trust_t *trst,
	image4_trust_section_t type,
	uint32_t tag,
	bool *vp,
	const bool *_Nullable *_Nullable vpp);
IMAGE4_XNU_AVAILABLE_DIRECT(image4_trust_record_property_bool);

/*!
 * @function image4_trust_record_property_integer
 * Records the specified unsigned integer value into caller-provided storage.
 *
 * @param trst
 * The trust object.
 *
 * @param type
 * The type of property to be recorded (currently either manifest or object).
 *
 * @param tag
 * The four character code of the property to capture.
 *
 * @param vp
 * A pointer to the storage where the value should be written.
 *
 * @param vpp
 * A pointer to storage where a pointer to the value should be written. This
 * allows the caller to know whether the property was encountered during the
 * trust evaluation at all. If the property was encountered, the storage
 * referred to by this pointer will hold the same pointer given in the
 * {@link vp} parameter.
 *
 * If the property was not encountered during trust evaluation, the contents of
 * this storage are undefined. The caller should initialize the storage to a
 * reasonable default.
 *
 * This may be NULL.
 *
 * @discussion
 * For boring implementation reasons, all integer properties are expressed as
 * 64-bit unsigned integers. The caller is responsible for enforcing boundaries
 * on the value recorded.
 *
 * If the property represented a constraint which was not satisfied, the
 * implementation will not record its value.
 *
 * If the property associated with the given tag is present, but is not an
 * integer, the implementation will not record its value.
 */
IMAGE4_API_AVAILABLE_SPRING_2024
OS_EXPORT OS_NONNULL1 OS_NONNULL4
void
image4_trust_record_property_integer(
	image4_trust_t *trst,
	image4_trust_section_t type,
	uint32_t tag,
	uint64_t *vp,
	const uint64_t *_Nullable *_Nullable vpp);
IMAGE4_XNU_AVAILABLE_DIRECT(image4_trust_record_property_integer);

/*!
 * @function image4_trust_record_property_data
 * Records a pointer to the specified octet string value into caller-provided
 * storage.
 *
 * @param trst
 * The trust object.
 *
 * @param type
 * The type of property to be recorded (currently either manifest or object).
 *
 * @param tag
 * The four character code of the property to capture.
 *
 * @param vp
 * A pointer to the storage where the value should be written. The storage
 * referenced by this pointer ultimately refers to the caller-provided memory
 * which contains the Image4 manifest, and therefore its lifetime is tied to the
 * caller's management of that storage.
 *
 * If the property was not encountered during trust evaluation, the contents of
 * this storage are undefined. The caller should initialize the storage to a
 * reasonable default.
 *
 * @param vp_len
 * A pointer to the storage where the length of the octet string should be
 * written.
 *
 * @discussion
 * If the property represented a constraint which was not satisfied, the
 * implementation will not record its value.
 *
 * If the property associated with the given tag is present, but is not an octet
 * string, the implementation will not record its value.
 *
 * Properties which are intended to be used as C strings are represented in the
 * manifest as simple octet strings which may or may not be null-terminated. The
 * caller should take care to ensure null termination when the data is used,
 * e.g. by copying the data into a local buffer using strlcpy(3).
 */
IMAGE4_API_AVAILABLE_SPRING_2024
OS_EXPORT OS_NONNULL1 OS_NONNULL4 OS_NONNULL5
void
image4_trust_record_property_data(
	image4_trust_t *trst,
	image4_trust_section_t type,
	uint32_t tag,
	const void *_Nullable *_Nonnull vp,
	size_t *vp_len);
IMAGE4_XNU_AVAILABLE_DIRECT(image4_trust_record_property_data);

/*!
 * @function image4_trust_evaluate
 * Perform the trust evaluation.
 *
 * @param trst
 * The trust object.
 *
 * @param _ctx
 * A context parameter to be delivered to the result callback.
 *
 * @param result
 * The callback to invoke with the result of the trust evaluation. This callback
 * is called directly inline from the implementation and must not re-enter the
 * calling scope.
 */
IMAGE4_API_AVAILABLE_SPRING_2024
OS_EXPORT OS_NONNULL1 OS_NONNULL3
void
image4_trust_evaluate(
	const image4_trust_t *trst,
	void *_Nullable _ctx,
	image4_trust_evaluation_result_t result);
IMAGE4_XNU_AVAILABLE_DIRECT(image4_trust_evaluate);

/*!
 * @function image4_trust_destroy
 * Disposes a trust object which was created via {@link image4_trust_new}.
 *
 * @param nv
 * A pointer to the trust object. Upon return, this storage will be set to NULL.
 * If the object pointed to by this parameter is NULL, this is a no-op.
 *
 * @discussion
 * If this routine is called on an environment object which was not allocated,
 * it is a no-op.
 */
IMAGE4_API_AVAILABLE_SPRING_2024
OS_EXPORT OS_NONNULL1
void
image4_trust_destroy(
	image4_trust_t *_Nonnull *_Nullable trst);
IMAGE4_XNU_AVAILABLE_DIRECT(image4_trust_destroy);

OS_ASSUME_PTR_ABI_SINGLE_END
OS_ASSUME_NONNULL_END
__END_DECLS

#endif // __IMAGE4_API_TRUST_H
