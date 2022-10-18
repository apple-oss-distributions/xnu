/*!
 * @header
 * Interfaces for manipulating Image4 firmware objects.
 */
#ifndef __IMG4_FIRMWARE_H
#define __IMG4_FIRMWARE_H

#define __IMG4_INDIRECT 1
#include <img4/api.h>

/*!
 * @discussion
 * When used from the pmap layer, this header pulls in the types from libsa,
 * which conflict with the BSD sys/types.h header that we need to pull in. But
 * we only need it for the errno_t typedef and the vnode_t typedef. So when
 * building MACH_KERNEL_PRIVATE, we do two things:
 *
 *     1. Explicitly pull in <sys/_types/_errno_t.h>, so we get errno_t and
 *        nothing else (no transitive #include's)
 *     2. #define _SYS_TYPES_H_ before #includ'ing <sys/kernel_types.h> so that
 *        we don't get the transitive #include of <sys/types.h> but we still get
 *        the definitions we need
 */
#if IMG4_TARGET_XNU
#if MACH_KERNEL_PRIVATE
#define _SYS_TYPES_H_ 1
#include <sys/kernel_types.h>
#include <sys/_types/_errno_t.h>
#else
#include <sys/kernel_types.h>
#include <sys/types.h>
#endif

#if XNU_KERNEL_PRIVATE
#include <img4/4xnu.h>
#endif
#endif // IMG4_TARGET_XNU

#if IMG4_TARGET_DARWIN
#include <os/stdio.h>
#include <sys/types.h>
#include <img4/4ignition.h>
#include <img4/4MSU.h>
#endif

__BEGIN_DECLS
OS_ASSUME_NONNULL_BEGIN

/*!
 * @typedef img4_4cc_t
 * A type which represents a four-character code (4cc) that identifies the
 * firmware. These 4cc's are statically assigned and correspond to long-form tag
 * names -- e.g. the 4cc 'krnl' corresponds to the "KernelCache" tag.
 */
IMG4_API_AVAILABLE_20200508
typedef uint32_t img4_4cc_t;

/*!
 * @typedef img4_buff_t
 * A structure describing a buffer. See {@link _img4_buff}.
 */
IMG4_API_AVAILABLE_20200508
typedef struct _img4_buff img4_buff_t;

/*!
 * @const IMG4_DGST_STRUCT_VERSION
 * The version of the {@link img4_dgst_t} structure supported by the
 * implementation.
 */
#define IMG4_DGST_STRUCT_VERSION (0u)

/*!
 * @const IMG4_DGST_MAX_LEN
 * The maximum length of a digest representable by an {@link img4_dgst_t}.
 */
#define IMG4_DGST_MAX_LEN (48u)

/*!
 * @typedef img4_dgst_t
 * A type representing an Image4 identifier which is a digest.
 *
 * @field i4d_len
 * The version of the structure. Initialize to {@link IMG4_DGST_STRUCT_VERSION}.
 *
 * @field i4d_len
 * The length of the digest.
 *
 * @field i4d_bytes
 * The digest bytes.
 */
IMG4_API_AVAILABLE_20200508
typedef struct _img4_dgst {
	img4_struct_version_t i4d_version;
	size_t i4d_len;
	uint8_t i4d_bytes[IMG4_DGST_MAX_LEN];
} img4_dgst_t;

/*!
 * @const IMG4_DGST_INIT
 * A convenience initializer for an {@link img4_dgst_t} structure.
 */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
#define IMG4_DGST_INIT (img4_dgst_t){ \
	.i4d_version = IMG4_DGST_STRUCT_VERSION, \
	.i4d_len = 0, \
	.i4d_bytes = {0}, \
}
#elif defined(__cplusplus) && __cplusplus >= 201103L
#define IMG4_DGST_INIT (img4_dgst_t{ \
	IMG4_DGST_STRUCT_VERSION, \
	0, \
	{0}, \
})
#elif defined(__cplusplus)
#define IMG4_DGST_INIT (img4_nonce_t((img4_nonce_t){ \
	IMG4_DGST_STRUCT_VERSION, \
	0, \
	{0}, \
}))
#else
#define IMG4_DGST_INIT {IMG4_DGST_STRUCT_VERSION}
#endif

/*!
 * @struct _img4_cstr
 * A type representing an Image4 identifier which is a C-string. These
 * identifiers can be no more than 64 bytes in length, including the null
 * terminating byte.
 *
 * @field i4b_len
 * The length of the C-string, not including the null terminating byte.
 *
 * @field i4b_cstr
 * The null-terminated C-string.
 *
 * @discussion
 * This structure is intentionally unversioned. It should never evolve into
 * anything more complex than it is.
 */
IMG4_API_AVAILABLE_20210113
typedef struct _img4_cstr {
	size_t i4cs_len;
	char i4cs_cstr[64];
} img4_cstr_t;

/*!
 * @const IMG4_CSTR_INIT
 * A convenience initializer for an {@link img4_cstr_t}.
 */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
#define IMG4_CSTR_INIT (img4_cstr_t){ \
	.i4cs_len = 0, \
	.i4cs_cstr = {0}, \
}
#elif defined(__cplusplus) && __cplusplus >= 201103L
#define IMG4_CSTR_INIT (img4_cstr_t{ \
	0, \
	{0}, \
})
#elif defined(__cplusplus)
#define IMG4_CSTR_INIT \
		(img4_cstr_t((img4_cstr_t){ \
	0, \
	{0}, \
}))
#else
#define IMG4_CSTR_INIT {0}
#endif

/*!
 * @typedef img4_chip_t
 * An opaque type describing a destination chip environment for the firmware
 * image.
 */
IMG4_API_AVAILABLE_20200508
typedef struct _img4_chip img4_chip_t;

/*!
 * @typedef img4_firmware_t
 * An opaque type describing an Image4 firmware object.
 */
IMG4_API_AVAILABLE_20200508
typedef struct _img4_firmware *img4_firmware_t;

/*!
 * @typedef img4_image_t
 * An opaque type describing an authenticated Image4 firmware image.
 */
IMG4_API_AVAILABLE_20200508
typedef struct _img4_image *img4_image_t;

/*!
 * @typedef img4_runtime_t
 * A structure describing required primitives in the operating environment's
 * runtime. See {@link _img4_runtime}.
 */
IMG4_API_AVAILABLE_20200508
typedef struct _img4_runtime img4_runtime_t;

OS_ASSUME_NONNULL_END

#include <img4/nonce.h>
#include <img4/object.h>
#include <img4/chip.h>
#include <img4/chip_ap.h>
#include <img4/chip_ap_category.h>
#include <img4/chip_ap_software.h>
#include <img4/chip_cryptex1.h>
#include <img4/chip_sep.h>
#include <img4/chip_x86.h>
#include <img4/image.h>
#include <img4/runtime.h>

OS_ASSUME_NONNULL_BEGIN

/*!
 * @typedef img4_firmware_authenticated_execute_t
 * A firmware execution function. This function is called when the firmware has
 * been successfully authenticated and is ready for execution.
 *
 * @param fw
 * The firmware which has been authenticated.
 *
 * @param image
 * The resulting firmware image that may be executed. The implementation will
 * pass NULL if there was a failure.
 *
 * This object is automatically freed by the implementation upon return.
 *
 * @param error
 * An error code describing the result of the authentication. If authentication
 * was successful, the implementation will pass zero. Otherwise, one of the
 * following error codes will be provided:
 *
 *     [EILSEQ]     The firmware data is not valid Image4 data -- this will not
 *                  be passed for firmwares created with
 *                  {@link IMG4_FIRMWARE_FLAG_BARE}
 *     [EFTYPE]     The attached manifest is not a valid Image4 manifest
 *     [ENOENT]     The attached manifest does not authenticate this type of
 *                  firmware
 *     [EAUTH]      The attached manifest is not authentic (i.e. was not signed
 *                  by an Apple CA)
 *     [EACCES]     The given chip does not satisfy the constraints of the
 *                  attached manifest
 *     [ESTALE]     The manifest has been invalidated and is no longer valid for
 *                  the provided chip
 *     [ENOEXEC]    The firmware has been corrupted, or the given chip does not
 *                  satisfy the constraints of the corresponding object in the
 *                  attached manifest
 *
 * @param _ctx
 * The user-provided context pointer.
 */
IMG4_API_AVAILABLE_20200508
typedef void (*img4_firmware_authenticated_execute_t)(
	const img4_firmware_t fw,
	img4_image_t _Nullable image,
	errno_t error,
	void *_ctx
);

#if IMG4_TARGET_EFI
typedef void (*img4_firmware_authenticated_execute_efi_t)(
	const img4_firmware_t fw,
	img4_image_t _Nullable image,
	EFI_STATUS status,
	void *_ctx
);
#endif

/*!
 * @define IMG4_FIRMWARE_EXECUTION_CONTEXT_STRUCT_VERSION
 * The version of the {@link img4_firmware_execution_context_t} structure
 * supported by the implementation.
 */
#define IMG4_FIRMWARE_EXECUTION_CONTEXT_STRUCT_VERSION (1u)

/*!
 * @typedef img4_firmware_execution_context_t
 * A structure describing the context in which a firmware is to be executed.
 *
 * @field i4fex_version
 * The version of the structure supported by the implementation. Initialize to
 * {@link IMG4_FIRMWARE_EXECUTION_CONTEXT_STRUCT_VERSION}.
 *
 * @field i4fex_execute
 * A pointer to the firmware execution function.
 *
 * @field i4fex_execute_efi
 * A pointer to the EFI-specific firmware execution function. This is only
 * available in the EFI environment. If both this field and
 * {@link i4fex_execute} are specified in the execution context, the
 * one which is called by the implementation will be undefined.
 *
 * This field was added in version 1 of the structure. It was not appended to
 * the end of the structure since the non-EFI structure did not change, and the
 * structure did not previously exist in the EFI environment. The version
 * increment was not strictly necessary, but was done for hygienic reasons.
 *
 * @field i4fex_context
 * A caller-provided context pointer that will be passed to functions invoked
 * from the execution context.
 */
IMG4_API_AVAILABLE_20200508
typedef struct _img4_firmware_execution_context {
	img4_struct_version_t i4fex_version;
	img4_firmware_authenticated_execute_t i4fex_execute;
#if IMG4_TARGET_EFI
	img4_firmware_authenticated_execute_efi_t i4fex_execute_efi;
#endif
	void *i4fex_context;
} img4_firmware_execution_context_t;

/*!
 * @typedef img4_firmware_flags_t
 * A bitfield modifying the behavior of an {@link img4_firmware_t} object.
 *
 * @const IMG4_FIRMWARE_FLAG_INIT
 * No bits set. This value is suitable for initialization purposes.
 *
 * @const IMG4_FIRMWARE_FLAG_ATTACHED_MANIFEST
 * The manifest authenticating the firmware is attached (i.e. the buffer given
 * represents a .img4 file).
 *
 * @const IMG4_FIRMWARE_FLAG_BARE
 * The firmware image is not wrapped with an Image4 payload structure. This flag
 * is mutually exclusive with {@link IMG4_FIRMWARE_FLAG_ATTACHED_MANIFEST}, and
 * if both are present, the implementation's behavior is undefined.
 *
 * @const IMG4_FIRMWARE_FLAG_SUBSEQUENT_STAGE
 * The firmware image extends an existing chain of trust. If set, the
 * runtime must provide a {@link i4rt_get_digest} function which returns a
 * digest for {@link IMG4_IDENTIFIER_CHMH}.
 *
 * If set, the firmware may optionally provide a {@link i4rt_get_bool} function
 * which returns a value for {@link IMG4_IDENTIFIER_AMNM}.
 *
 * @const IMG4_FIRMWARE_FLAG_RESPECT_AMNM
 * Forces the implementation to respect the manifest's AMNM entitlement if it is
 * present, even if the validation is creating a new chain of trust. This is
 * technically maybe sort of against the Image4 spec, but it is useful for
 * certain internal workflows (cf. v2.3, §2.2.10).
 *
 * This flag has no effect if {@link IMG4_FIRMWARE_FLAG_SUBSEQUENT_STAGE} is
 * also passed.
 *
 * @const IMG4_FIRMWARE_FLAG_PASSTHROUGH
 * Causes the wrapped payload bytes to be delivered to the image execution
 * callback. These bytes do not have the Image4 wrapping stripped.
 *
 * @const IMG4_FIRMWARE_FLAG_FORCE_ANTI_REPLAY
 * Force anti-replay enforcement even when performing just manifest evaluation
 * without executing a firmware. When executing a firmware, this flag need not
 * be passed in since anti-replay enforcement is always enabled.
 */
IMG4_API_AVAILABLE_20200508
OS_CLOSED_OPTIONS(img4_firmware_flags, uint64_t,
	IMG4_FIRMWARE_FLAG_INIT,
	IMG4_FIRMWARE_FLAG_ATTACHED_MANIFEST = (1 << 0),
	IMG4_FIRMWARE_FLAG_BARE = (1 << 1),
	IMG4_FIRMWARE_FLAG_SUBSEQUENT_STAGE = (1 << 2),
	IMG4_FIRMWARE_FLAG_RESPECT_AMNM = (1 << 3),
	IMG4_FIRMWARE_FLAG_PASSTHROUGH = (1 << 4),
	IMG4_FIRMWARE_FLAG_FORCE_ANTI_REPLAY = (1 << 5),
);

/*!
 * @function img4_firmware_new
 * Allocate and initialize a new firmware object.
 *
 * @param rt
 * The runtime in which to initialize the object.
 *
 * @param _4cc
 * The 4cc which distinguishes the firmware.
 *
 * @param buff
 * A buffer containing a valid Image4 payload (usually the contents of either a
 * .im4p or .img4 file).
 *
 * Upon return, the destructor in the buffer is replaced with NULL, and the
 * implementation assumes responsibility for deallocating the underlying memory.
 *
 * @param flags
 * Flags modifying the behavior of the object.
 *
 * @result
 * A new firmware object or NULL if there was an allocation failure. If
 * {@link rt} has a NULL allocation function, NULL is returned.
 *
 * @discussion
 * The resulting object assumes ownership of the given buffer.
 *
 * In the Darwin userspace runtime, NULL will not be returned.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT OS_WARN_RESULT OS_MALLOC OS_NONNULL1 OS_NONNULL2 OS_NONNULL4
img4_firmware_t _Nullable
img4_firmware_new(const img4_runtime_t *rt,
		const img4_firmware_execution_context_t *exec,
		img4_4cc_t _4cc,
		img4_buff_t *buff,
		img4_firmware_flags_t flags);
#else
#define img4_firmware_new(...) (img4if->i4if_v7.firmware_new(__VA_ARGS__))
#endif

/*!
 * @function img4_firmware_new_from_vnode_4xnu
 * Allocate and initialize a new firmware object from a vnode.
 *
 * @param rt
 * The runtime in which to initialize the object. This interface is only
 * supported with the Darwin kernel runtime. If any other runtime is provided,
 * the implementation's behavior is undefined.
 *
 * @param _4cc
 * The 4cc which distinguishes the firmware.
 *
 * @param vn
 * A vnode representing a valid Image4 payload (usually the contents of either a
 * .im4p or .img4 file).
 *
 * @param flags
 * Flags modifying the behavior of the object.
 *
 * @result
 * A new firmware object or NULL if there was an allocation failure.
 *
 * @discussion
 * Verification of a vnode is performed by reading in chunks of data, updating
 * an ongoing hash operation with that data, and then discarding it. Therefore,
 * firmware objects created in this manner can only guarantee their validity at
 * the time the check was performed since the vnode's contents are not kept in
 * memory and may be tampered with after validation has been performed.
 *
 * As such, on successful execution, the image passed to the
 * {@link img4_firmware_authenticated_execute_t} function of the execution
 * context is NULL.
 *
 * Firmwares created with this interface cannot be created with the
 * {@link IMG4_FIRMWARE_FLAG_ATTACHED_MANIFEST} flag.
 */
#if IMG4_TARGET_XNU
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT OS_WARN_RESULT OS_MALLOC OS_NONNULL1 OS_NONNULL2 OS_NONNULL4
img4_firmware_t _Nullable
img4_firmware_new_from_vnode_4xnu(const img4_runtime_t *rt,
		const img4_firmware_execution_context_t *exec,
		img4_4cc_t _4cc,
		vnode_t vn,
		img4_firmware_flags_t flags);
#else
#define img4_firmware_new_from_vnode_4xnu(...) \
		(img4if->i4if_v7.firmware_new_from_vnode_4xnu(__VA_ARGS__))
#endif // !XNU_KERNEL_PRIVATE
#endif // IMG4_TARGET_XNU

/*!
 * @function img4_firmware_new_from_fd_4MSM
 * Allocate and initialize a new firmware object from a file descriptor.
 *
 * @param rt
 * The runtime in which to initialize the object. This interface is only
 * supported with the Darwin userspace runtime. If any other runtime is
 * provided, the implementation's behavior is undefined.
 *
 * @param _4cc
 * The 4cc which distinguishes the firmware.
 *
 * @param fd
 * A pointer to a file descriptor representing a valid Image4 payload (usually
 * the contents of either a .im4p or .img4 file). The object assumes ownership
 * of the descriptor, and upon return, the value referenced by the pointer will
 * be set to -1.
 *
 * @param flags
 * Flags modifying the behavior of the object.
 *
 * @result
 * A new firmware object. The implementation will not return NULL.
 *
 * @discussion
 * This interface is the userspace equivalent of
 * {@link img4_firmware_new_from_vnode_4xnu}, and all the same caveats apply.
 */
#if IMG4_TARGET_DARWIN
IMG4_API_AVAILABLE_20200508
OS_EXPORT OS_WARN_RESULT OS_MALLOC OS_NONNULL1 OS_NONNULL2
img4_firmware_t
img4_firmware_new_from_fd_4MSM(const img4_runtime_t *rt,
		const img4_firmware_execution_context_t *exec,
		img4_4cc_t _4cc,
		os_fd_t *fd,
		img4_firmware_flags_t flags);
#endif

/*!
 * @function img4_firmware_init_from_buff
 * Initializes a buffer as a firmware object. This interface is useful for
 * runtimes which do not provide for dynamic memory allocation.
 *
 * @param storage
 * A pointer to the storage to use for the firmware object.
 *
 * @param len
 * The size of the buffer.
 *
 * @discussion
 * The caller is expected to pass a buffer that is "big enough". If the provided
 * buffer is too small, the implementation will abort the caller.
 *
 * @example
 *
 *     uint8_t _buff[IMG4_FIRMWARE_SIZE_RECOMMENDED];
 *     img4_firmware_t fw = NULL;
 *
 *     fw = img4_firmware_init_from_buff(_buff, sizeof(_buff));
 *     img4_firmware_init(fw, IMG4_RUNTIME_DEFAULT, &exec_context,
 *             kImg4Tag_krnl, fw_buff, 0);
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT OS_WARN_RESULT OS_NONNULL1
img4_firmware_t
img4_firmware_init_from_buff(void *buff, size_t len);
#else
#define img4_firmware_init_from_buff(...) \
		(img4if->i4if_v7.firmware_init_from_buff(__VA_ARGS__))
#endif

/*!
 * @function img4_firmware_init
 * Initialize a firmware object.
 *
 * @param fw
 * A pointer to the storage for the firmware object. This pointer should refer
 * to a region of memory that is sufficient to hold a {@link img4_firmware_t}
 * object. This size should be queried with the {@link i4rt_object_size}
 * function of the runtime.
 *
 * @param rt
 * The runtime in which to initialize the object.
 *
 * @param _4cc
 * The 4cc which distinguishes the firmware.
 *
 * @param buff
 * A buffer containing a valid Image4 payload (usually the contents of either a
 * .im4p or .img4 file).
 *
 * Upon return, the destructor in the buffer is replaced with NULL, and the
 * implementation assumes responsibility for deallocating the underlying memory.
 *
 * @param flags
 * Flags modifying the behavior of the object.
 *
 * @discussion
 * The resulting object assumes ownership of the given buffer. This routine
 * should only be used when dynamic memory allocation is not available in the
 * runtime. Otherwise, use {@link img4_firmware_new}.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT OS_NONNULL1 OS_NONNULL2 OS_NONNULL3 OS_NONNULL5
void
img4_firmware_init(img4_firmware_t fw,
		const img4_runtime_t *rt,
		const img4_firmware_execution_context_t *exec,
		img4_4cc_t _4cc,
		img4_buff_t *buff,
		img4_firmware_flags_t flags);
#else
#define img4_firmware_init(...) (img4if->i4if_v7.firmware_init(__VA_ARGS__))
#endif

/*!
 * @function img4_firmware_init_sentinel
 * Initialize a firmware object as a sentinel without any manifest attached.
 * This firmware has no object tag and is not executable. It is only suitable
 * for use with {@link img4_firmware_attach_manifest} and
 * {@link img4_firmware_evaluate} to determine whether a manifest is acceptable
 * to a particular chip environment.
 *
 * @param fw
 * A pointer to the storage for the firmware object. This pointer should refer
 * to a region of memory that is sufficient to hold a {@link img4_firmware_t}
 * object. This size should be queried with the {@link i4rt_object_size}
 * function of the runtime.
 *
 * @param rt
 * The runtime in which to initialize the object.
 *
 * @param flags
 * Flags modifying the behavior of the object.
 *
 * @discussion
 * Sentinel firmwares do not enforce anti-replay, so
 * {@link img4_firmware_evaluate} will not return ESTALE when evaluating such
 * firmwares. Anti-replay enforcement can be enabled by using
 * {@link IMG4_FIRMWARE_FLAG_FORCE_ANTI_REPLAY}.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20211126
OS_EXPORT OS_NONNULL1 OS_NONNULL2
void
img4_firmware_init_sentinel(img4_firmware_t fw,
		const img4_runtime_t *rt,
		img4_firmware_flags_t flags);
#else
#define img4_firmware_init_sentinel(...) \
		(img4if->i4if_v17.firmware_init_sentinel(__VA_ARGS__))
#endif

/*!
 * @function img4_firmware_attach_manifest
 * Attaches a signed manifest to the firmware.
 *
 * @param fw
 * The firmware to manipulate.
 *
 * @param buff
 * A buffer containing a valid Image4 manifest (usually the contents of either a
 * .im4m or .img4 file).
 *
 * Upon return, the destructor in the buffer is replaced with NULL, and the
 * implementation assumes responsibility for deallocating the underlying memory.
 *
 * @discussion
 * If this interface is called on a firmware created with the
 * {@link IMG4_FIRMWARE_FLAG_ATTACHED_MANIFEST} flag, the implementation's
 * behavior is undefined.
 *
 * This interface must be called on any firmware created with the
 * {@link IMG4_FIRMWARE_FLAG_BARE} flag.
 *
 * The object assumes ownership of the given buffer.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT OS_NONNULL1 OS_NONNULL2
void
img4_firmware_attach_manifest(img4_firmware_t fw,
		img4_buff_t *buff);
#else
#define img4_firmware_attach_manifest(...) \
		(img4if->i4if_v7.firmware_attach_manifest(__VA_ARGS__))
#endif

/*!
 * @function img4_firmware_select_chip
 * Returns the chip from the provided array which may be used to authenticate
 * the firmware.
 *
 * @param fw
 * The firmware to query.
 *
 * @param acceptable_chips
 * An array of chips the caller finds acceptable to verify the firmware.
 *
 * @param acceptable_chips_cnt
 * The number of elements in {@link acceptable_chips}.
 *
 * @result
 * If the manifest may be authenticated by the certificate chain associated with
 * one of the manifests provided in {@link acceptable_chips}, that chip is
 * returned. If the manifest cannot be authenticated with any of the provided
 * chips, NULL is returned.
 *
 * @discussion
 * The result of calling this function on a firmware which does not have a
 * manifest attached is undefined.
 *
 * If multiple chips may be used to authenticate the firmware, the
 * implementation does not define which of those chips will be returned.
 *
 * If the firmware was created without the
 * {@link IMG4_FIRMWARE_FLAG_SUBSEQUENT_STAGE} flag, this function will return
 * NULL. This function cannot be used to establish new trust chains, only to
 * verify an existing one.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200724
OS_EXPORT OS_WARN_RESULT
const img4_chip_t *_Nullable
img4_firmware_select_chip(const img4_firmware_t fw,
		const img4_chip_select_array_t _Nonnull acceptable_chips,
		size_t acceptable_chips_cnt);
#else
#define img4_firmware_select_chip(...) \
		(img4if->i4if_v10.firmware_select_chip(__VA_ARGS__))
#endif

/*!
 * @function img4_firmware_execute
 * Authenticate the firmware and execute it within its context.
 *
 * @param fw
 * The firmware to execute.
 *
 * @param chip
 * The chip on which to execute the firmware.
 *
 * @param nonce
 * The nonce to use for authentication. May be NULL if the chip environment does
 * not maintain an anti-replay token or if a chained evaluation is being
 * performed.
 *
 * @discussion
 * The implementation will always invoke the
 * {@link img4_firmware_authenticated_execute_t} provided in the execution
 * context with either a successful result or a failure. All error handling must
 * take place in that context.
 *
 * The {@link img4_firmware_authenticated_execute_t} is called before the
 * implementation returns.
 *
 * The result of executing a firmware without a manifest attached (either via
 * {@link img4_firmware_attach_manifest} or by creating the firmware with the
 * {@link IMG4_FIRMWARE_FLAG_ATTACHED_MANIFEST} flag set) is undefined.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT OS_NONNULL1 OS_NONNULL2
void
img4_firmware_execute(img4_firmware_t fw,
		const img4_chip_t *chip,
		const img4_nonce_t *_Nullable nonce);
#else
#define img4_firmware_execute(...) \
		(img4if->i4if_v7.firmware_execute(__VA_ARGS__))
#endif

/*!
 * @function img4_firmware_evaluate
 * Evaluate the firmware for authenticity.
 *
 * @param fw
 * The firmware to evaluate.
 *
 * @param chip
 * The chip on which to evaluate the firmware.
 *
 * @param nonce
 * The nonce to use for authentication. May be NULL if the chip environment does
 * not maintain an anti-replay token or if a chained evaluation is being
 * performed.
 *
 * @result
 * An error code describing the result of the authentication. If authentication
 * was successful, zero is returned. Otherwise, one of the following error codes
 * will be returned:
 *
 *     [EILSEQ]     The firmware data is not valid Image4 data -- this will not
 *                  be returned for firmwares created with
 *                  {@link IMG4_FIRMWARE_FLAG_BARE}
 *     [EFTYPE]     The attached manifest is not a valid Image4 manifest
 *     [ENOENT]     The attached manifest does not authenticate this type of
 *                  firmware
 *     [EAUTH]      The attached manifest is not authentic (i.e. was not signed
 *                  by an Apple CA)
 *     [EACCES]     The given chip does not satisfy the constraints of the
 *                  attached manifest
 *     [ESTALE]     The manifest has been invalidated and is no longer valid for
 *                  the provided chip
 *     [ENOEXEC]    The firmware has been corrupted, or the given chip does not
 *                  satisfy the constraints of the corresponding object in the
 *                  attached manifest
 *     [EPWROFF]    The chip environment has not yet booted; most chip
 *                  environments are booted and available by the time the caller
 *                  has begun executing, but some require additional
 *                  initialization before they can execute objects
 *
 * @discussion
 * This interface should be used when the caller is only concerned with the
 * authenticity and integrity of the firmware image and does not intend to
 * execute it.
 *
 * The result of evaluating a firmware without a manifest attached (either via
 * {@link img4_firmware_attach_manifest} or by creating the firmware with the
 * {@link IMG4_FIRMWARE_FLAG_ATTACHED_MANIFEST} flag set) is undefined.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200608
OS_EXPORT OS_WARN_RESULT OS_NONNULL1 OS_NONNULL2
errno_t
img4_firmware_evaluate(img4_firmware_t fw,
		const img4_chip_t *chip,
		const img4_nonce_t *_Nullable nonce);
#else
#define img4_firmware_evaluate(...) \
		(img4if->i4if_v9.firmware_evaluate(__VA_ARGS__))
#endif

/*!
 * @function img4_firmware_destroy
 * Destroys a firmware object and releases the associated resources according to
 * the runtime's specification.
 *
 * @param fw
 * A pointer to the firmware object.
 *
 * Upon return, this will be replaced with a known-invalid pointer value. This
 * parameter may be NULL in which case the implementation will return
 * immediately.
 *
 * @discussion
 * The implementation will invoke the provided deallocation function of the
 * buffer object underlying the firmware.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT
void
img4_firmware_destroy(img4_firmware_t _Nonnull *_Nullable fw);
#else
#define img4_firmware_destroy(...) \
		(img4if->i4if_v7.firmware_destroy(__VA_ARGS__))
#endif

OS_ASSUME_NONNULL_END
__END_DECLS

#endif // __IMG4_FIRMWARE_H
