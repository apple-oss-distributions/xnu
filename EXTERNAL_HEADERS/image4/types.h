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

#pragma mark Supporting Types
/*!
 * @typedef image4_struct_version_t
 * The version of a structure in the API.
 */
typedef uint16_t image4_struct_version_t;

#pragma mark Supporting Types
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

/*!
 * @const IMAGE4_NONCE_MAX_LEN
 * The maximum size of a boot nonce.
 */
#define IMAGE4_NONCE_MAX_LEN (16u)

/*!
 * @const IMAGE4_NONCE_DIGEST_STRUCT_VERSION
 * The version of the {@link image4_nonce_digest_t} structure supported by the
 * implementation.
 */
#define IMAGE4_NONCE_DIGEST_STRUCT_VERSION (0u)

/*!
 * @const IMAGE4_NONCE_DIGEST_MAX_LEN
 * The maximum size of a nonce digest.
 */
#define IMAGE4_NONCE_DIGEST_MAX_LEN (64u)

/*!
 * @typedef image4_nonce_digest_t
 * A structure representing a nonce digest.
 *
 * @field nd_version
 * The version of the structure. Initialize to
 * {@link IMAGE4_NONCE_DIGEST_STRUCT_VERSION}.
 *
 * @field nd_length
 * The length of the digest.
 *
 * @field nd_bytes
 * The digest bytes.
 */
typedef struct _image4_nonce_digest {
	image4_struct_version_t nd_version;
	size_t nd_length;
	uint8_t nd_bytes[IMAGE4_NONCE_DIGEST_MAX_LEN];
} image4_nonce_digest_t;

/*!
 * @const IMAGE4_NONCE_DIGEST_INIT
 * Initializer for an {@link image4_nonce_digest_t} structure.
 */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
#define IMAGE4_NONCE_DIGEST_INIT (image4_nonce_digest_t){ \
	.nd_version = IMAGE4_NONCE_DIGEST_STRUCT_VERSION, \
	.nd_length = 0, \
	.nd_bytes = { \
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, \
	}, \
}
#elif defined(__cplusplus) && __cplusplus >= 201103L
#define IMAGE4_NONCE_DIGEST_INIT (image4_nonce_digest_t {\
	IMAGE4_NONCE_DIGEST_STRUCT_VERSION, \
	0, \
	{ \
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, \
	}, \
})
#elif defined(__cplusplus)
#define IMAGE4_NONCE_DIGEST_INIT (image4_nonce_digest_t(\
	(image4_nonce_digest_t){ \
		IMAGE4_NONCE_DIGEST_STRUCT_VERSION, \
		0, \
		{ \
			0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, \
		}, \
	} \
))
#else
#define IMAGE4_NONCE_DIGEST_INIT { \
	IMAGE4_NONCE_DIGEST_STRUCT_VERSION, \
	0, \
	{ \
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, \
	}, \
}
#endif

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
