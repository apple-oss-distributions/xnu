/*!
 * @header
 * Image4 runtime interfaces.
 */
#ifndef __IMG4_RUNTIME_H
#define __IMG4_RUNTIME_H

#ifndef __IMG4_INDIRECT
#error "Please #include <img4/firmware.h> instead of this file directly"
#endif // __IMG4_INDIRECT

OS_ASSUME_NONNULL_BEGIN

/*!
 * @typedef img4_identifier_t
 * An enumeration describing identifiers in the Image4 specification.
 *
 * @const IMG4_IDENTIFIER_CEPO
 * The chip epoch as documented in 2.1.1. Authoritative manifests will specify a
 * certificate epoch which is greater than or equal to that of the chip.
 *
 * Unsigned 32-bit integer.
 *
 * @const IMG4_IDENTIFIER_BORD
 * The board identifier as documented in 2.1.3. Authoritative manifests will
 * specify a board identifier which is equal to that of the chip.
 *
 * Unsigned 32-bit integer.
 *
 * @const IMG4_IDENTIFIER_CHIP
 * The chip identifier as documented in 2.1.2. Authoritative manifests will
 * specify a chip identifier which is equal to that of the chip.
 *
 * Unsigned 32-bit integer.
 *
 * @const IMG4_IDENTIFIER_SDOM
 * The security domain as documented in 2.1.5. Authoritative manifests will
 * specify a security domain which is equal to that that of the chip.
 *
 * Unsigned 32-bit integer. Valid values are
 *
 *     0    Manufacturing
 *     1    Darwin
 *     2    Data Center (unsure)
 *     3    Unused
 *
 * @const IMG4_IDENTIFIER_ECID
 * The unique chip identifier as documented in 2.1.4. Authoritative manifests
 * will specify a unique chip identifier which is equal to that of the chip.
 *
 * Unsigned 64-bit integer.
 *
 * @const IMG4_IDENTIFIER_CPRO
 * The certificate production status as documented in 2.1.6. Authoritative
 * manifests will specify a certificate production status which is equal to that
 * of the chip.
 *
 * Boolean.
 *
 * @const IMG4_IDENTIFIER_CSEC
 * The certificate security mode as documented in 2.1.7. Authoritative manifests
 * will specify a certificate security mode which is equal to that of the chip.
 *
 * Boolean.
 *
 * @const IMG4_IDENTIFIER_EPRO
 * The effective production status as documented in 2.1.23. Unless the chip
 * environment supports demotion, this will always be the same as
 * {@link IMG4_IDENTIFIER_CPRO}. An executable firmware in an authoritative
 * manifest will specify an EPRO object property which is equal to that of the
 * chip post-demotion.
 *
 * Boolean.
 *
 * @const IMG4_IDENTIFIER_ESEC
 * The effective security mode as documented in 2.1.25. Unless the chip
 * environment supports demotion, this will always be the same as
 * {@link IMG4_IDENTIFIER_CSEC}. An executable firmware in an authoritative
 * manifest will specify an ESEC object property which is equal to that of the
 * chip post-demotion.
 *
 * Boolean.
 *
 * @const IMG4_IDENTIFIER_IUOU
 * The "internal use only unit" property. Indicates whether the chip is present
 * on a server-side authlist which permits installing builds which are otherwise
 * restricted to parts whose CPRO is 0. This property is only published by macOS
 * devices whose root of trust is in an arm coprocessor (e.g. T2).
 *
 * Authoritative manifests will specify an internal-use-only-build property
 * which, if true, is equal to the internal-use-only-unit property of the chip.
 * If the internal-use-only-build property is false, then there is no constraint
 * on the chip's internal-use-only-unit property.
 *
 * Boolean.
 *
 * @const IMG4_IDENTIFIER_RSCH
 * The research fusing status. Indicates whether the chip is intended for
 * security research to be performed by external parties. Authoritative
 * manifests will specify a research fusing state which is equal to that of the
 * chip.
 *
 * Boolean.
 *
 * This identifier was never recognized by SecureROM and has been obsoleted by
 * {@link IMG4_IDENTIFIER_ESDM}.
 *
 * @const IMG4_IDENTIFIER_CHMH
 * The chained manifest hash from the previous stage of secure boot as described
 * in 2.2.11. An authoritative manifest will either
 *
 *     - specify a manifest hash which is equal to that of the previous secure
 *       boot stage's manifest
 *     - itself have a manifest hash which is equal to that of the previous
 *       secure boot stage's manifest
 *
 * If the previous stage of secure boot enabled mix-n-match, there is no
 * constraint on the previous stage's manifest hash.
 *
 * Manifests which specify this property cannot be used to create new trust
 * chains -- they may only extend existing ones.
 *
 * Digest.
 *
 * @const IMG4_IDENTIFIER_AMNM
 * The allow-mix-n-match status of the chip. If mix-n-match is enabled, secure
 * boot will permit different manifests to be used at each stage of boot. If the
 * chip environment allows mix-n-match, evaluation will not require an anti-
 * replay token to be specified, and any chained manifest hash constraints are
 * ignored.
 *
 * Boolean.
 *
 * @const IMG4_IDENTIFIER_EUOU
 * The engineering-use-only-unit status of the chip. This is in effect an alias
 * for the {@link IMG4_IDENTIFIER_IUOU} property. Either property being present
 * in the environment will satisfy a manifest's iuob constraint.
 *
 * Boolean.
 *
 * @const IMG4_IDENTIFIER_LOVE
 * The long version of the OS currently booted on the chip (Long Os VErsion).
 *
 * Authoritative manifests will specify a version number which is greater than
 * that of the chip.
 *
 * C string.
 *
 * @const IMG4_IDENTIFIER_ESDM
 * The extended security domain of the chip. Authoritative manifests will
 * specify an extended security domain which is equal to that of the chip.
 *
 * Unsigned 32-bit integer. This integer represents 8 fusing bits, and therefore
 * the maximum valid value is 0xff.
 *
 * @const IMG4_IDENTIFIER_FPGT
 * The factory pre-release global trust status of the chip. This is in effect an
 * alias for the {@link IMG4_IDENTIFIER_IUOU} property. Either property being
 * present in the environment will satisfy a manifest's iuob constraint.
 *
 * Boolean.
 *
 * @const IMG4_IDENTIFIER_UDID
 * The universal device identifier of the chip. This uniquely identifies the SoC
 * globally across all SoCs. Authoritative manifests will specify a UDID which
 * is equal to that of the chip.
 *
 * 128-bit octet string.
 *
 * @const IMG4_IDENTIFIER_FCHP
 * The chip identifier of the Cryptex coprocessor associated with the chip. This
 * distinguishes the software Crytpex coprocessor instances which operate on the
 * AP. Authoritative manifests will specify a Cryptex chip identifier that is
 * equal to that of the chip.
 *
 * Runtimes are not capable of reporting this value, and queries for it should
 * return ENOENT. This invariant is defined for convenience to the
 * implementation.
 *
 * Unsigned 32-bit integer.
 *
 * @const IMG4_IDENTIFIER_TYPE
 * The type identifier of the Cryptex coprocessor associated with the chip. This
 * distinguishes software Cryptex coprocessor instances of the same chip
 * identifier which operate on the AP. Authoritative manifests will specify a
 * Cryptex type that is equal to that of the chip.
 *
 * Runtimes are not capable of reporting this value, and queries for it should
 * return ENOENT. This invariant is defined for convenience to the
 * implementation.
 *
 * Unsigned 32-bit integer.
 *
 * @const IMG4_IDENTIFIER_STYP
 * The subtype identifier of the Cryptex coprocessor associated with the chip.
 * This permits an additional level of granularity to distinguish Cryptex
 * coprocessor instances from one another. Authoritative manifests will specify
 * a Cryptex subtype that is equal to that of the chip.
 *
 * Runtimes are not capable of reporting this value, and queries for it should
 * return ENOENT. This invariant is defined for convenience to the
 * implementation.
 *
 * Unsigned 32-bit integer.
 *
 * @const IMG4_IDENTIFIER_CLAS
 * The product class of the Cryptex coprocessor associated with the chip.
 * Authoritative manifests will specify a product class that is equal to that of
 * the chip.
 *
 * Valid values for this property are:
 *
 *     0xf0 - Intel Mac (with or without T2 security chip)
 *     0xf1 - Apple Silicon Mac
 *     0xf2 - iPhone/iPad/iPod touch
 *     0xf3 - watch
 *     0xf4 - tv/HomePod
 *
 * Unsigned 32-bit integer.
 *
 * @const IMG4_IDENTIFIER_SPIH
 * The booted supplemental manifest hash.
 *
 * Digest.
 *
 * @const IMG4_IDENTIFIER_NSPH
 * The preboot supplemental manifest hash intended to become active at the next
 * boot.
 *
 * Digest.
 *
 * @const IMG4_IDENTIFIER_STNG
 * The generation number of the last-executed blessed local policy on the AP.
 *
 * Unsigned 64-bit integer.
 *
 * @const IMG4_IDENTIFIER_VUID
 * The volume group UUID that the chip is booting from.
 *
 * 128-bit octet string.
 *
 * @const _IMG4_IDENTIFIER_CNT
 * A convenience value representing the number of known identifiers.
 */
IMG4_API_AVAILABLE_20200508
OS_CLOSED_ENUM(img4_identifier, uint64_t,
	IMG4_IDENTIFIER_CEPO,
	IMG4_IDENTIFIER_BORD,
	IMG4_IDENTIFIER_CHIP,
	IMG4_IDENTIFIER_SDOM,
	IMG4_IDENTIFIER_ECID,
	IMG4_IDENTIFIER_CPRO,
	IMG4_IDENTIFIER_CSEC,
	IMG4_IDENTIFIER_EPRO,
	IMG4_IDENTIFIER_ESEC,
	IMG4_IDENTIFIER_IUOU,
	IMG4_IDENTIFIER_RSCH,
	IMG4_IDENTIFIER_CHMH,
	IMG4_IDENTIFIER_AMNM,
	IMG4_IDENTIFIER_EUOU,
	IMG4_IDENTIFIER_LOVE,
	IMG4_IDENTIFIER_ESDM,
	IMG4_IDENTIFIER_FPGT,
	IMG4_IDENTIFIER_UDID,
	IMG4_IDENTIFIER_FCHP,
	IMG4_IDENTIFIER_TYPE,
	IMG4_IDENTIFIER_STYP,
	IMG4_IDENTIFIER_CLAS,
	IMG4_IDENTIFIER_SPIH,
	IMG4_IDENTIFIER_NSPH,
	IMG4_IDENTIFIER_STNG,
	IMG4_IDENTIFIER_VUID,
	_IMG4_IDENTIFIER_CNT,
);

/*!
 * @typedef img4_pmap_data_t
 * An opaque type representing state protected by the host's page mapping layer
 * as it deems appropriate. Do not use directly.
 */
IMG4_API_AVAILABLE_20210521
typedef struct _img4_pmap_data img4_pmap_data_t;

/*!
 * @typedef img4_runtime_object_spec_index_t
 * An enumeration describing the executable objects recognized by runtimes.
 *
 * @const IMG4_RUNTIME_OBJECT_SPEC_INDEX_MANIFEST
 * The enumerated constant which refers to the internal manifest object.
 *
 * @const IMG4_RUNTIME_OBJECT_SPEC_INDEX_SUPPLEMENTAL_ROOT
 * The enumerated constant which refers to the
 * {@link IMG4_RUNTIME_OBJECT_SPEC_SUPPLEMENTAL_ROOT} object.
 *
 * @const IMG4_RUNTIME_OBJECT_SPEC_INDEX_SUPPLEMENTAL_OBJECT
 * The enumerated constant which refers to the
 * {@link IMG4_RUNTIME_OBJECT_SPEC_SUPPLEMENTAL_OBJECT} object.
 *
 * @const IMG4_RUNTIME_OBJECT_SPEC_INDEX_LOCAL_POLICY
 * The enumerated constant which refers to the
 * {@link IMG4_RUNTIME_OBJECT_SPEC_LOCAL_POLICY} object.
 *
 * @const _IMG4_RUNTIME_OBJECT_SPEC_INDEX_CNT
 * A sentinel value representing the total number of executable object
 * specifications.
 */
IMG4_API_AVAILABLE_20210521
OS_CLOSED_ENUM(img4_runtime_object_spec_index, uint64_t,
	IMG4_RUNTIME_OBJECT_SPEC_INDEX_MANIFEST,
	IMG4_RUNTIME_OBJECT_SPEC_INDEX_SUPPLEMENTAL_ROOT,
	IMG4_RUNTIME_OBJECT_SPEC_INDEX_SUPPLEMENTAL_OBJECT,
	IMG4_RUNTIME_OBJECT_SPEC_INDEX_LOCAL_POLICY,
	_IMG4_RUNTIME_OBJECT_SPEC_INDEX_CNT,
);

/*!
 * @typedef img4_runtime_object_spec_t
 * A specification for an object known to and executable by a runtime.
 */
IMG4_API_AVAILABLE_20210205
typedef struct _img4_runtime_object_spec img4_runtime_object_spec_t;

/*!
 * @typedef img4_runtime_init_t
 * A function which initializes the runtime.
 *
 * @param rt
 * The runtime for which the function is being invoked.
 *
 * @discussion
 * This function is called by the implementation prior to any other runtime
 * function being called. The implementation will ensure that it is called only
 * once. Any runtime with an initialization function must be registered with the
 * {@link IMG4_RUNTIME_REGISTER} macro.
 */
IMG4_API_AVAILABLE_20200508
typedef void (*img4_runtime_init_t)(
	const img4_runtime_t *rt
);

/*!
 * @typedef img4_runtime_alloc_t
 * An allocation function.
 *
 * @param rt
 * The runtime for which the function is being invoked.
 *
 * @param n
 * The number of bytes to allocate.
 *
 * @result
 * A pointer to the new allocation, or NULL if there was an allocation failure.
 *
 * The memory returned by this function is expected to be zero-filled.
 */
IMG4_API_AVAILABLE_20200508
typedef void *_Nullable (*img4_runtime_alloc_t)(
	const img4_runtime_t *rt,
	size_t n
);

/*!
 * @typedef img4_runtime_dealloc_t
 * A deallocation function.
 *
 * @param rt
 * The runtime for which the function is being invoked.
 *
 * @param p
 * A pointer to the allocation to free. The callee is expected to return
 * immediately if NULL is passed.
 *
 * @param n
 * The size of the allocation. Not all implementation may require this
 * information to be specified.
 */
IMG4_API_AVAILABLE_20200508
typedef void (*img4_runtime_dealloc_t)(
	const img4_runtime_t *rt,
	void *_Nullable p,
	size_t n
);

/*!
 * @typedef img4_log_level_t
 * An enumeration describing the importance/severity of a log message.
 *
 * @const IMG4_LOG_LEVEL_ERROR
 * A fatal condition which will cause the implementation to abort its current
 * operation.
 *
 * @const IMG4_LOG_LEVEL_INFO
 * Information that may be of interest to the system operator.
 *
 * @const IMG4_LOG_LEVEL_DEBUG
 * Information that may be of interest to the maintainer.
 *
 * @const _IMG4_LOG_LEVEL_CNT
 * A convenience constant indicating the number of log levels.
 */
IMG4_API_AVAILABLE_20200508
OS_CLOSED_ENUM(img4_log_level, uint64_t,
	IMG4_LOG_LEVEL_ERROR,
	IMG4_LOG_LEVEL_INFO,
	IMG4_LOG_LEVEL_DEBUG,
	_IMG4_LOG_LEVEL_CNT,
);

/*!
 * @typedef img4_runtime_log_t
 * A function which writes log messages.
 *
 * @param rt
 * The runtime for which the function is being invoked.
 *
 * @param handle
 * An implementation-specific handle for the log message.
 *
 * @param level
 * The message of the log level. The implementation is free to determine whether
 * a given message is worthy of record.
 *
 * @param fmt
 * A printf(3)-style format string.
 *
 * @param ...
 * Arguments to be interpreted by the format string according to the
 * specifications in printf(3).
 */
OS_FORMAT_PRINTF(4, 5)
IMG4_API_AVAILABLE_20200508
typedef void (*img4_runtime_log_t)(
	const img4_runtime_t *rt,
	void *_Nullable handle,
	img4_log_level_t level,
	const char *fmt,
	...
);

/*!
 * @typedef img4_runtime_log_handle_t
 * A function which returns a log handle.
 *
 * @param rt
 * The runtime for which the function is being invoked.
 *
 * @result
 * A runtime-specific log handle that will be passed to the logging function.
 */
IMG4_API_AVAILABLE_20200508
typedef void *_Nullable (*img4_runtime_log_handle_t)(
	const img4_runtime_t *rt
);

/*!
 * @typedef img4_runtime_get_identifier_bool_t
 * A function which retrieves a Boolean Image4 identifier.
 *
 * @param rt
 * The runtime for which the function is being invoked.
 *
 * @param chip
 * The chip for which to retrieve the identifier.
 *
 * @param identifier
 * The identifier to retrieve.
 *
 * @param value
 * Upon successful return, storage which is populated with the retrieved value.
 *
 * @result
 * Upon success, the callee is expected to return zero. Otherwise, the callee
 * may return one of the following error codes:
 *
 *     [ENOTSUP]     The identifier cannot be queried in the runtime
 *     [ENOENT]      The identifier was not found in the runtime's identity
 *                   oracle
 *     [ENODEV]      There was an error querying the runtime's identity oracle
 */
IMG4_API_AVAILABLE_20200508
typedef errno_t (*img4_runtime_get_identifier_bool_t)(
	const img4_runtime_t *rt,
	const img4_chip_t *chip,
	img4_identifier_t identifier,
	bool *value
);

/*!
 * @typedef img4_runtime_get_identifier_uint32_t
 * A function which retrieves an unsigned 32-bit integer Image4 identifier.
 *
 * @param rt
 * The runtime for which the function is being invoked.
 *
 * @param chip
 * The chip for which to retrieve the identifier.
 *
 * @param identifier
 * The identifier to retrieve.
 *
 * @param value
 * Upon successful return, storage which is populated with the retrieved value.
 *
 * @result
 * Upon success, the callee is expected to return zero. Otherwise, the callee
 * may return one of the following error codes:
 *
 *     [ENOTSUP]     The identifier cannot be queried in the runtime
 *     [ENOENT]      The identifier was not found in the runtime's identity
 *                   oracle
 *     [ENODEV]      There was an error querying the runtime's identity oracle
 */
IMG4_API_AVAILABLE_20200508
typedef errno_t (*img4_runtime_get_identifier_uint32_t)(
	const img4_runtime_t *rt,
	const img4_chip_t *chip,
	img4_identifier_t identifier,
	uint32_t *value
);

/*!
 * @typedef img4_runtime_get_identifier_uint64_t
 * A function which retrieves an unsigned 64-bit integer Image4 identifier.
 *
 * @param rt
 * The runtime for which the function is being invoked.
 *
 * @param chip
 * The chip for which to retrieve the identifier.
 *
 * @param identifier
 * The identifier to retrieve.
 *
 * @param value
 * Upon successful return, storage which is populated with the retrieved value.
 *
 * @result
 * Upon success, the callee is expected to return zero. Otherwise, the callee
 * may return one of the following error codes:
 *
 *     [ENOTSUP]     The identifier cannot be queried in the runtime
 *     [ENOENT]      The identifier was not found in the runtime's identity
 *                   oracle
 *     [ENODEV]      There was an error querying the runtime's identity oracle
 */
IMG4_API_AVAILABLE_20200508
typedef errno_t (*img4_runtime_get_identifier_uint64_t)(
	const img4_runtime_t *rt,
	const img4_chip_t *chip,
	img4_identifier_t identifier,
	uint64_t *value
);

/*!
 * @typedef img4_runtime_get_identifier_digest_t
 * A function which retrieves a digest Image4 identifier.
 *
 * @param rt
 * The runtime for which the function is being invoked.
 *
 * @param chip
 * The chip for which to retrieve the identifier.
 *
 * @param identifier
 * The identifier to retrieve.
 *
 * @param value
 * Upon successful return, storage which is populated with the retrieved value.
 *
 * @result
 * Upon success, the callee is expected to return zero. Otherwise, the callee
 * may return one of the following error codes:
 *
 *     [ENOTSUP]     The identifier cannot be queried in the runtime
 *     [ENOENT]      The identifier was not found in the runtime's identity
 *                   oracle
 *     [ENODEV]      There was an error querying the runtime's identity oracle
 */
IMG4_API_AVAILABLE_20200508
typedef errno_t (*img4_runtime_get_identifier_digest_t)(
	const img4_runtime_t *rt,
	const img4_chip_t *chip,
	img4_identifier_t identifier,
	img4_dgst_t *value
);

/*!
 * @typedef img4_runtime_get_identifier_cstr_t
 * A function which retrieves a C-string Image4 identifier.
 *
 * @param rt
 * The runtime for which the function is being invoked.
 *
 * @param chip
 * The chip for which to retrieve the identifier.
 *
 * @param identifier
 * The identifier to retrieve.
 *
 * @param value
 * Upon successful return, storage which is populated with the retrieved value.
 *
 * @result
 * Upon success, the callee is expected to return zero. Otherwise, the callee
 * may return one of the following error codes:
 *
 *     [ENOTSUP]     The identifier cannot be queried in the runtime
 *     [ENOENT]      The identifier was not found in the runtime's identity
 *                   oracle
 *     [ENODEV]      There was an error querying the runtime's identity oracle
 */
IMG4_API_AVAILABLE_20210113
typedef errno_t (*img4_runtime_get_identifier_cstr_t)(
	const img4_runtime_t *rt,
	const img4_chip_t *chip,
	img4_identifier_t identifier,
	img4_cstr_t *value
);

/*!
 * @typedef img4_runtime_execute_object_t
 * A function which executes an object type known to the runtime.
 *
 * @param rt
 * The runtime for which the function is being invoked.
 *
 * @param obj_spec
 * The object specification for the payload being executed.
 *
 * @param payload
 * The payload bytes to execute. These bytes are delivered in their raw form,
 * i.e. without any Image4 payload wrapping.
 *
 * @param manifest
 * The manifest which authenticats the payload. If the payload is intended to be
 * used without authentication (or with alternate means of authentication), this
 * may be NULL.
 *
 * @result
 * Upon success, the callee is expected to return zero. Otherwise, the callee
 * may return any appropriate POSIX error code.
 *
 * @discussion
 * This function is only called if the payload has been successfully
 * authenticated; the callee can consider the bytes as trusted.
 */
IMG4_API_AVAILABLE_20210205
typedef errno_t (*img4_runtime_execute_object_t)(
	const img4_runtime_t *rt,
	const img4_runtime_object_spec_t *obj_spec,
	const img4_buff_t *payload,
	const img4_buff_t *_Nullable manifest
);

/*!
 * @typedef img4_runtime_copy_object_t
 * A function which obtains the payload of a previously-executed object.
 *
 * @param rt
 * The runtime for which the function is being invoked.
 *
 * @param obj_spec
 * The object specification for the payload being obtained.
 *
 * @param payload
 * A pointer to a buffer object in which to copy the object.
 *
 * @param payload_len
 * Upon successful return, a pointer to the total number of bytes coped into the
 * buffer referred to by {@link payload}. This parameter may be NULL.
 *
 * In the event that buffer referred to be {@link payload} is insufficient to,
 * accommodate the object, the callee is expected to set this parameter to the
 * total number of bytes required.
 *
 * @result
 * Upon success, the callee is expected to return zero. Otherwise, the callee
 * may return one of the following error codes:
 *
 *     [EOVERFLOW]     The provided buffer is not large enough for the payload;
 *                     in this case the callee is expected to set the
 *                     {@link i4b_len} of the given buffer to the required
 *                     length
 *     [ENOENT]        The object has not yet been executed
 */
IMG4_API_AVAILABLE_20210205
typedef errno_t (*img4_runtime_copy_object_t)(
	const img4_runtime_t *rt,
	const img4_runtime_object_spec_t *obj_spec,
	img4_buff_t *payload,
	size_t *_Nullable payload_len
);

/*!
 * @typedef img4_runtime_alloc_type_t
 * A function which allocates a single object of a given type.
 *
 * @param rt
 * The runtime for which the function is being invoked.
 *
 * @param handle
 * The domain-specific handle describing the object and the allocation site.
 *
 * @result
 * A pointer to the new allocation, or NULL if there was an allocation failure.
 * The memory returned by this function is expected to be zero-filled.
 */
IMG4_API_AVAILABLE_20210226
typedef void *_Nullable (*img4_runtime_alloc_type_t)(
	const img4_runtime_t *rt,
	void *_Nullable handle
);

/*!
 * @typedef img4_runtime_dealloc_type_t
 * A function which deallocates a single object of a given type.
 *
 * @param rt
 * The runtime for which the function is being invoked.
 *
 * @param handle
 * The domain-specific handle describing the object and the deallocation site.
 *
 * @param p
 * The address of the object to deallocate.
 */
IMG4_API_AVAILABLE_20210226
typedef void (*img4_runtime_dealloc_type_t)(
	const img4_runtime_t *rt,
	void *_Nullable handle,
	void *p
);

/*!
 * @typedef img4_runtime_set_nonce_t
 * A function which sets the value of a nonce managed by the runtime.
 *
 * @param rt
 * The runtime for which the function is being invoked.
 *
 * @param ndi
 * The index of the nonce domain whose nonce should be set.
 *
 * @param n
 * The value of the nonce indicated by {@link nd}.
 */
IMG4_API_AVAILABLE_20210521
typedef void (*img4_runtime_set_nonce_t)(
	const img4_runtime_t *rt,
	img4_nonce_domain_index_t ndi,
	const img4_nonce_t *n
);

/*!
 * @typedef img4_runtime_roll_nonce_t
 * A function which rolls a nonce managed by the runtime.
 *
 * @param rt
 * The runtime for which the function is being invoked.
 *
 * @param ndi
 * The index of the nonce domain whose nonce should be rolled.
 */
IMG4_API_AVAILABLE_20210521
typedef void (*img4_runtime_roll_nonce_t)(
	const img4_runtime_t *rt,
	img4_nonce_domain_index_t ndi
);

/*!
 * @typedef img4_runtime_copy_nonce_t
 * A function which retrieve the value of a nonce managed by the runtime.
 *
 * @param rt
 * The runtime for which the function is being invoked.
 *
 * @param ndi
 * The index of the nonce domain whose nonce should be queried.
 *
 * @param n
 * Upon successful return, the value of the nonce indicated by {@link nd}. If
 * the caller simply wishes to check if the nonce has been invalidated, this
 * parameter may be NULL, and the caller can check for ESTALE.
 *
 * @result
 * Upon success, zero is returned. The implementation may also return one of the
 * following error codes directly:
 *
 *     [ESTALE]     The nonce for the given domain has been invalidated, and the
 *                  host must reboot in order to generate a new one
 */
IMG4_API_AVAILABLE_20210521
typedef errno_t (*img4_runtime_copy_nonce_t)(
	const img4_runtime_t *rt,
	img4_nonce_domain_index_t ndi,
	img4_nonce_t *_Nullable n
);

/*!
 * @define IMG4_BUFF_STRUCT_VERSION
 * The version of the {@link img4_buff_t} structure supported by the
 * implementation.
 */
#define IMG4_BUFF_STRUCT_VERSION (0u)

/*!
 * @struct _img4_buff
 * A structure describing a buffer.
 *
 * @field i4b_version
 * The version of the structure. Initialize to {@link IMG4_BUFF_STRUCT_VERSION}.
 *
 * @field i4b_bytes
 * A pointer to the buffer.
 *
 * @field i4b_len
 * The length of the buffer.
 *
 * @field i4b_dealloc
 * The deallocation function for the buffer. May be NULL if the underlying
 * memory does not require cleanup. When the implementation invokes this
 * function, it will always pass {@link IMG4_RUNTIME_DEFAULT}, and the callee
 * should not consult this parameter for any reason.
 */
struct _img4_buff {
	img4_struct_version_t i4b_version;
	uint8_t *i4b_bytes;
	size_t i4b_len;
	img4_runtime_dealloc_t _Nullable i4b_dealloc;
} IMG4_API_AVAILABLE_20200508;

/*!
 * @const IMG4_BUFF_INIT
 * A convenience initializer for the {@link img4_buff_t} structure.
 */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
#define IMG4_BUFF_INIT (img4_buff_t){ \
	.i4b_version = IMG4_BUFF_STRUCT_VERSION, \
	.i4b_len = 0, \
	.i4b_bytes = NULL, \
	.i4b_dealloc = NULL, \
}
#elif defined(__cplusplus) && __cplusplus >= 201103L
#define IMG4_BUFF_INIT (img4_buff_t{ \
	IMG4_BUFF_STRUCT_VERSION, \
	NULL, \
	0, \
	NULL, \
})
#elif defined(__cplusplus)
#define IMG4_BUFF_INIT (img4_buff_t((img4_buff_t){ \
	IMG4_BUFF_STRUCT_VERSION, \
	NULL, \
	0, \
	NULL, \
}))
#else
#define IMG4_BUFF_INIT {IMG4_BUFF_STRUCT_VERSION}
#endif

/*!
 * @define IMG4_RUNTIME_STRUCT_VERSION
 * The version of the {@link img4_runtime_t} structure supported by the
 * implementation.
 */
#define IMG4_RUNTIME_STRUCT_VERSION (5u)

/*!
 * @struct _img4_runtime
 * A structure describing required primitives in the operating environment's
 * runtime.
 *
 * @field i4rt_version
 * The version of the structure supported by the implementation. In a custom
 * execution context, initialize to {@link IMG4_RUNTIME_STRUCT_VERSION}.
 *
 * @field i4rt_name
 * A string describing the environment.
 *
 * @field i4rt_init
 * The runtime initialization function. See discussion in
 * {@link img4_runtime_init_t}.
 *
 * @field i4rt_alloc
 * The allocation function for the environment (e.g. in Darwin userspace, this
 * would be a pointer to malloc(3)). The memory returned is expected to be zero-
 * filled.
 *
 * @field i4rt_dealloc
 * The deallocation function for the environment (e.g. in Darwin userspace, this
 * would be a pointer to free(3)).
 *
 * @field i4rt_log
 * The function which logs messages from the implementation.
 *
 * @field i4rt_log_handle
 * The function which returns the handle to be passed to the logging function.
 *
 * @field i4rt_get_identifier_bool
 * The function which returns Boolean identifiers.
 *
 * @field i4rt_get_identifier_uint32
 * The function which returns unsigned 32-bit integer identifiers.
 *
 * @field i4rt_get_identifier_uint64
 * The function which returns unsigned 64-bit integer identifiers.
 *
 * @field i4rt_get_identifier_digest
 * The function which returns digest identifiers.
 *
 * @field i4rt_context
 * A user-defined context pointer. Introduced in version 1 of the structure.
 *
 * @field i4rt_get_identifier_cstr
 * The function which returns C-string identifiers. Introduced in version 2 of
 * the structure.
 *
 * @field i4rt_execute_object
 * The function which executes objects. Introduced in version 3 of the
 * structure.
 *
 * @field i4rt_copy_object
 * The function which copies objects. Introduced in version 3 of the structure.
 *
 * @field i4rt_alloc_type
 * The typed allocation function for the environment. This allocator should be
 * used for any fixed-size, structured allocation that may contain pointers.
 *
 * The memory returned is expected to be zero-filled. Introduced in version 4 of
 * the structure.
 *
 * @field i4rt_dealloc_type
 * The typed deallocation function for the environment. Introduced in version 4
 * of the structure.
 *
 * @field i4rt_set_nonce
 * The nonce-set function for the environment. Introduced in version 5 of the
 * structure.
 *
 * @field i4rt_roll_nonce
 * The nonce-roll function for the environment. Introduced in version 5 of the
 * structure.
 *
 * @field i4rt_roll_nonce
 * The nonce-copy function for the environment. Introduced in version 5 of the
 * structure.
 */
struct _img4_runtime {
	img4_struct_version_t i4rt_version;
	const char *i4rt_name;
	img4_runtime_init_t _Nullable i4rt_init;
	img4_runtime_alloc_t i4rt_alloc;
	img4_runtime_dealloc_t i4rt_dealloc;
	img4_runtime_log_t i4rt_log;
	img4_runtime_log_handle_t i4rt_log_handle;
	img4_runtime_get_identifier_bool_t i4rt_get_identifier_bool;
	img4_runtime_get_identifier_uint32_t i4rt_get_identifier_uint32;
	img4_runtime_get_identifier_uint64_t i4rt_get_identifier_uint64;
	img4_runtime_get_identifier_digest_t i4rt_get_identifier_digest;
	void *_Nullable i4rt_context;
	img4_runtime_get_identifier_cstr_t i4rt_get_identifier_cstr;
	img4_runtime_execute_object_t i4rt_execute_object;
	img4_runtime_copy_object_t i4rt_copy_object;
	img4_runtime_alloc_type_t i4rt_alloc_type;
	img4_runtime_dealloc_type_t i4rt_dealloc_type;
	img4_runtime_set_nonce_t i4rt_set_nonce;
	img4_runtime_roll_nonce_t i4rt_roll_nonce;
	img4_runtime_copy_nonce_t i4rt_copy_nonce;
} IMG4_API_AVAILABLE_20200508;

/*!
 * @function IMG4_RUNTIME_REGISTER
 * Registers a runtime with the module implementation such that its
 * initialization function can be called. In environments which support dynamic
 * library linkage, only runtimes registered from the main executable image can
 * be discovered by the implementation.
 *
 * @param _rt
 * The img4_runtime_t structure to register.
 */
#define IMG4_RUNTIME_REGISTER(_rt) LINKER_SET_ENTRY(__img4_rt, _rt);

/*!
 * @const IMG4_RUNTIME_DEFAULT
 * The default runtime for the current operating environment.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT
const img4_runtime_t _img4_runtime_default;
#define IMG4_RUNTIME_DEFAULT (&_img4_runtime_default)
#else
#define IMG4_RUNTIME_DEFAULT (img4if->i4if_v7.runtime_default)
#endif

/*!
 * @const IMG4_RUNTIME_PMAP_CS
 * The runtime for the xnu pmap layer which is safe to be executed in a
 * supervisor execution level if supported by hardware. This runtime is not
 * available outside the kernel-proper.
 */
#if XNU_KERNEL_PRIVATE
#define IMG4_RUNTIME_PMAP_CS (img4if->i4if_v7.runtime_pmap_cs)
#elif _DARWIN_BUILDING_TARGET_APPLEIMAGE4
#define IMG4_RUNTIME_PMAP_CS (&_img4_runtime_pmap_cs)
#endif

/*!
 * @const IMG4_RUNTIME_RESTORE
 * The runtime for the restore ramdisk. This runtime is not available outside
 * of the Darwin userspace library.
 */
#if !KERNEL
IMG4_API_AVAILABLE_20200508
OS_EXPORT
const img4_runtime_t _img4_runtime_restore;
#define IMG4_RUNTIME_RESTORE (&_img4_runtime_restore)
#endif

/*!
 * @function img4_buff_dealloc
 * Deallocates a buffer according to its deallocation function.
 *
 * @param buff
 * A pointer to the a pointer to the buffer. This parameter may be NULL, in
 * which case the implementation will return immediately.
 *
 * @discussion
 * This interface will always invoke the deallocation callback with
 * {@link IMG4_RUNTIME_DEFAULT}. The callee should not consult this parameter
 * for any reason.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT
void
img4_buff_dealloc(img4_buff_t *_Nullable buff);
#else
#define img4_buff_dealloc(...) (img4if->i4if_v7.buff_dealloc(__VA_ARGS__))
#endif

#pragma mark Object Specifications
/*!
 * @const IMG4_RUNTIME_OBJECT_SPEC_SUPPLEMENTAL_ROOT
 * The DER representation of the certificate to use as the root of trust for
 * evaluating the supplemental software package. This object can only be
 * executed once for any given boot session.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20210205
OS_EXPORT
const img4_runtime_object_spec_t _img4_runtime_object_spec_supplemental_root;
#define IMG4_RUNTIME_OBJECT_SPEC_SUPPLEMENTAL_ROOT \
		(&_img4_runtime_object_spec_supplemental_root)
#else
#define IMG4_RUNTIME_OBJECT_SPEC_SUPPLEMENTAL_ROOT \
		(img4if->i4if_v11.runtime_object_spec_supplemental_root)
#endif

/*!
 * @const IMG4_RUNTIME_OBJECT_SPEC_LOCAL_POLICY
 * The local policy object which has been authorized by the user for a
 * subsequent boot of the system. This object may be executed multiple times in
 * a given boot session. A subsequent local policy must have been authorized by
 * the user after the currently-active one in order to successfully execute.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20210205
OS_EXPORT
const img4_runtime_object_spec_t _img4_runtime_object_spec_local_policy;
#define IMG4_RUNTIME_OBJECT_SPEC_LOCAL_POLICY \
		(&_img4_runtime_object_spec_local_policy)
#else
#define IMG4_RUNTIME_OBJECT_SPEC_LOCAL_POLICY \
		(img4if->i4if_v18.runtime_object_spec_local_policy)
#endif

#pragma mark API
/*!
 * @function img4_runtime_find_object_spec
 * Returns the object specification for the given four-character code.
 *
 * @param _4cc
 * The four-character code for which to find the object specification.
 *
 * @result
 * The object specification, or NULL if the four-character code is not an
 * executable object known to the implementation.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20210205
OS_EXPORT OS_WARN_RESULT
const img4_runtime_object_spec_t *_Nullable
img4_runtime_find_object_spec(img4_4cc_t _4cc);
#else
#define img4_runtime_find_object_spec(...) \
		(img4if->i4if_v11.runtime_find_object_spec(__VA_ARGS__))
#endif

/*!
 * @function img4_runtime_execute_object
 * Executes an object within the runtime.
 *
 * @param rt
 * The runtime in which to execute the object.
 *
 * @param obj_spec
 * The specification for the object.
 *
 * @param obj
 * The buffer representing the object. The structure and form of the bytes
 * is dictated by the object specification. Usually, these bytes are a wrapped
 * Image4 payload.
 *
 * @param manifest
 * The Image4 manifest authenticating the object. If the object has a manifest
 * stitched to it, this parameter may be NULL.
 *
 * @result
 * Upon success, zero is returned. Otherwise, one of the following error codes:
 *
 *     [EPERM]     The caller does not have permission to set the object
 *     [EALREADY]  The object may only be set once, and it has already been set
 *
 * Any error code returned by {@link img4_firmware_evaluate} may also be
 * returned.
 *
 * Any error code returned by the runtime's {@link i4rt_execute_object} callback
 * will also be returned.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20210205
OS_EXPORT OS_WARN_RESULT OS_NONNULL1 OS_NONNULL2 OS_NONNULL3
errno_t
img4_runtime_execute_object(const img4_runtime_t *rt,
		const img4_runtime_object_spec_t *obj_spec,
		const img4_buff_t *obj,
		const img4_buff_t *_Nullable manifest);
#else
#define img4_runtime_execute_object(...) \
		(img4if->i4if_v11.runtime_execute_object(__VA_ARGS__))
#endif

/*!
 * @function img4_runtime_copy_object
 * Copies the payload of an object executed within the runtime.
 *
 * @param rt
 * The runtime in which to query the object.
 *
 * @param obj_spec
 * The specification for the object.
 *
 * @param payload
 * Upon successful return, a pointer to a buffer object which refers to storage
 * that will hold the payload.
 *
 * @param payload_len
 * Upon successful return, a pointer to the total number of bytes coped into the
 * buffer referred to by {@link payload}. This parameter may be NULL.
 *
 * In the event that buffer referred to be {@link payload} is not large enough,
 * this parameter will be set to the total number of bytes required.
 *
 * @result
 * Upon success, zero is returned. Otherwise, one of the following error codes:
 *
 *     [EPERM]    The caller does not have permission to copy the object
 *     [ENOENT]   The requested object is not present
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20210205
OS_EXPORT OS_WARN_RESULT OS_NONNULL1 OS_NONNULL2 OS_NONNULL3
errno_t
img4_runtime_copy_object(const img4_runtime_t *rt,
		const img4_runtime_object_spec_t *obj_spec,
		img4_buff_t *payload,
		size_t *_Nullable payload_len);
#else
#define img4_runtime_copy_object(...) \
		(img4if->i4if_v11.runtime_copy_object(__VA_ARGS__))
#endif

OS_ASSUME_NONNULL_END

#endif // __IMG4_RUNTIME_H
