/*!
 * @header
 * Supported chip environments.
 */
#ifndef __IMG4_CHIP_H
#define __IMG4_CHIP_H

#ifndef __IMG4_INDIRECT
#error "Please #include <img4/firmware.h> instead of this file directly"
#endif // __IMG4_INDIRECT

OS_ASSUME_NONNULL_BEGIN

/*!
 * @typedef img4_chip_select_array_t
 * A type representing a list of chips from which the implementation may select.
 */
IMG4_API_AVAILABLE_20200724
typedef const img4_chip_t *_Nullable const *img4_chip_select_array_t;

/*!
 * @const IMG4_CHIP_INSTANCE_STRUCT_VERSION
 * The version of the {@link img4_chip_instance_t} supported by the
 * implementation.
 */
#define IMG4_CHIP_INSTANCE_STRUCT_VERSION (6u)

/*!
 * @typedef img4_chip_instance_omit_t
 * A bitfield describing omitted identifiers from a chip instance.
 *
 * @const IMG4_CHIP_INSTANCE_OMIT_CEPO
 * The chip instance has no epoch.
 *
 * @const IMG4_CHIP_INSTANCE_OMIT_BORD
 * The chip instance has no board identifier.
 *
 * @const IMG4_CHIP_INSTANCE_OMIT_CHIP
 * The chip instance has no chip identifier.
 *
 * @const IMG4_CHIP_INSTANCE_OMIT_SDOM
 * The chip instance has no security domain.
 *
 * @const IMG4_CHIP_INSTANCE_OMIT_ECID
 * The chip instance has no unique chip identifier.
 *
 * @const IMG4_CHIP_INSTANCE_OMIT_CPRO
 * The chip instance has no certificate production status.
 *
 * @const IMG4_CHIP_INSTANCE_OMIT_CSEC
 * The chip instance has no certificate security mode.
 *
 * @const IMG4_CHIP_INSTANCE_OMIT_EPRO
 * The chip instance has no effective production status.
 *
 * @const IMG4_CHIP_INSTANCE_OMIT_ESEC
 * The chip instance has no effective security mode.
 *
 * @const IMG4_CHIP_INSTANCE_OMIT_IUOU
 * The chip instance has no internal-use-only-unit property.
 *
 * @const IMG4_CHIP_INSTANCE_OMIT_RSCH
 * The chip instance has no research fusing state.
 *
 * @const IMG4_CHIP_INSTANCE_OMIT_EUOU
 * The chip instance has no engineering-use-only-unit property.
 *
 * @const IMG4_CHIP_INSTANCE_OMIT_ESDM
 * The chip instance has no extended security domain property.
 *
 * @const IMG4_CHIP_INSTANCE_OMIT_FPGT
 * The chip instance has no factory pre-release global trust property.
 *
 * @const IMG4_CHIP_INSTANCE_OMIT_UDID
 * The chip instance has no universal device identifier property.
 *
 * @const IMG4_CHIP_INSTANCE_OMIT_FCHP
 * The chip instance has no cryptex chip identifier property.
 *
 * @const IMG4_CHIP_INSTANCE_OMIT_TYPE
 * The chip instance has no cryptex type identifier property.
 *
 * @const IMG4_CHIP_INSTANCE_OMIT_STYP
 * The chip instance has no cryptex subtype identifier property.
 *
 * @const IMG4_CHIP_INSTANCE_OMIT_CLAS
 * The chip instance has no product class property.
 */
OS_CLOSED_OPTIONS(img4_chip_instance_omit, uint64_t,
	IMG4_CHIP_INSTANCE_OMIT_CEPO = (1 << 0),
	IMG4_CHIP_INSTANCE_OMIT_BORD = (1 << 1),
	IMG4_CHIP_INSTANCE_OMIT_CHIP = (1 << 2),
	IMG4_CHIP_INSTANCE_OMIT_SDOM = (1 << 3),
	IMG4_CHIP_INSTANCE_OMIT_ECID = (1 << 4),
	IMG4_CHIP_INSTANCE_OMIT_CPRO = (1 << 5),
	IMG4_CHIP_INSTANCE_OMIT_CSEC = (1 << 6),
	IMG4_CHIP_INSTANCE_OMIT_EPRO = (1 << 7),
	IMG4_CHIP_INSTANCE_OMIT_ESEC = (1 << 8),
	IMG4_CHIP_INSTANCE_OMIT_IUOU = (1 << 9),
	IMG4_CHIP_INSTANCE_OMIT_RSCH = (1 << 10),
	IMG4_CHIP_INSTANCE_OMIT_EUOU = (1 << 11),
	IMG4_CHIP_INSTANCE_OMIT_ESDM = (1 << 12),
	IMG4_CHIP_INSTANCE_OMIT_FPGT = (1 << 13),
	IMG4_CHIP_INSTANCE_OMIT_UDID = (1 << 14),
	IMG4_CHIP_INSTANCE_OMIT_FCHP = (1 << 15),
	IMG4_CHIP_INSTANCE_OMIT_TYPE = (1 << 16),
	IMG4_CHIP_INSTANCE_OMIT_STYP = (1 << 17),
	IMG4_CHIP_INSTANCE_OMIT_CLAS = (1 << 18),
);

/*!
 * @typedef img4_chip_instance_t
 * An structure describing an instance of a chip.
 *
 * @field chid_version
 * The version of the structure. Initialize to
 * {@link IMG4_CHIP_INSTANCE_STRUCT_VERSION}.
 *
 * @field chid_chip_family
 * The chip family of which this is an instance.
 *
 * @field chid_omit
 * The identifiers which are absent from the chip instance.
 *
 * @field chid_cepo
 * The certificate epoch of the chip instance.
 *
 * @field chid_bord
 * The board identifier of the chip instance.
 *
 * @field chid_chip
 * The chip identifier of the chip instance.
 *
 * @field chid_sdom
 * The security domain of the chip instance.
 *
 * @field chid_ecid
 * The unique chip identifier of the chip instance.
 *
 * @field chid_cpro
 * The certificate production status of the chip instance.
 *
 * @field chid_csec
 * The certificate security mode of the chip instance.
 *
 * @field chid_epro
 * The effective production status of the chip instance.
 *
 * @field chid_esec
 * The effective security mode of the chip instance.
 *
 * @field chid_iuou
 * The internal use-only unit status of the chip instance.
 *
 * @field chid_rsch
 * The research mode of the chip instance.
 *
 * @field chid_euou
 * The engineering use-only unit status of the chip instance.
 *
 * Added in version 1 of the structure.
 *
 * @field chid_esdm
 * The extended security domain of the chip instance.
 *
 * Added in version 3 of the structure.
 *
 * @field chid_fpgt
 * The factory pre-release global trust status of the chip instance.
 *
 * Added in version 4 of the structure.
 *
 * @field chid_udid
 * The universal device identifier of the chip instance.
 *
 * Added in version 5 of the structure.
 *
 * @const chid_fchp
 * The cryptex chip identifier of the chip instance.
 *
 * Added in version 6 of the structure.
 *
 * @const chid_type
 * The cryptex type identifier of the chip instance.
 *
 * Added in version 6 of the structure.
 *
 * @const chid_styp
 * The cryptex subtype identifier of the chip instance.
 *
 * Added in version 6 of the structure.
 *
 * @field chid_clas
 * The product class of the chip instance.
 *
 * Added in version 6 of the structure.
 */
IMG4_API_AVAILABLE_20200508
typedef struct _img4_chip_instance {
	img4_struct_version_t chid_version;
	const img4_chip_t *chid_chip_family;
	img4_chip_instance_omit_t chid_omit;
	uint32_t chid_cepo;
	uint32_t chid_bord;
	uint32_t chid_chip;
	uint32_t chid_sdom;
	uint64_t chid_ecid;
	bool chid_cpro;
	bool chid_csec;
	bool chid_epro;
	bool chid_esec;
	bool chid_iuou;
	bool chid_rsch;
	bool chid_euou;
	uint32_t chid_esdm;
	bool chid_fpgt;
	img4_dgst_t chid_udid;
	uint32_t chid_fchp;
	uint32_t chid_type;
	uint32_t chid_styp;
	uint32_t chid_clas;
} img4_chip_instance_t;

/*!
 * @function IMG4_CHIP_INSTANCE_INIT
 * A convenience initializer which can be used to initialize a chip instance to
 * a given family.
 *
 * @param _family
 * The family of chip.
 *
 * @result
 * A fully-initialized structure of the appropriate version supported by the
 * implementation. The resulting chip instance omits no identifiers.
 */
#define IMG4_CHIP_INSTANCE_INIT(_family) (img4_chip_instance_t){ \
	.chid_version = IMG4_CHIP_INSTANCE_STRUCT_VERSION, \
	.chid_chip_family = (_family), \
	.chid_omit = 0, \
	.chid_cepo = 0, \
	.chid_bord = 0, \
	.chid_chip = 0, \
	.chid_sdom = 0, \
	.chid_ecid = 0, \
	.chid_cpro = false, \
	.chid_csec = false, \
	.chid_epro = false, \
	.chid_esec = false, \
	.chid_iuou = false, \
	.chid_rsch = false, \
	.chid_euou = false, \
	.chid_esdm = 0, \
	.chid_fpgt = false, \
	.chid_udid = {0}, \
	.chid_fchp = 0, \
	.chid_type = 0, \
	.chid_styp = 0, \
	.chid_clas = 0, \
}

/*!
 * @function img4_chip_init_from_buff
 * Initializes a buffer as a chip object.
 *
 * @param buff
 * A pointer to the storage to use for the chip object.
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
 *     uint8_t _buff[IMG4_CHIP_SIZE_RECOMMENDED];
 *     img4_chip_t *chip = NULL;
 *
 *     chip = img4_chip_init_from_buff(_buff, sizeof(_buff));
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT OS_WARN_RESULT OS_NONNULL1
img4_chip_t *
img4_chip_init_from_buff(void *buff, size_t len);
#else
#define img4_chip_init_from_buff (img4if->i4if_v7.chip_init_from_buff)
#endif

/*!
 * @function img4_chip_select_personalized_ap
 * Returns the chip appropriate for personalized verification against the host
 * AP.
 *
 * @result
 * The personalized chip environment for the host which corresponds to its
 * silicon identity.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT OS_WARN_RESULT
const img4_chip_t *
img4_chip_select_personalized_ap(void);
#else
#define img4_chip_select_personalized_ap(...) \
		(img4if->i4if_v7.chip_select_personalized_ap(__VA_ARGS__))
#endif

/*!
 * @function img4_chip_select_personalized_sep
 * Returns the chip appropriate for personalized verification against the host
 * SEP.
 *
 * @result
 * The personalized chip environment for the host's SEP which corresponds to its
 * silicon identity. This will return NULL when called outside of the SEP
 * runtime.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20211119
OS_EXPORT OS_WARN_RESULT
const img4_chip_t *_Nullable
img4_chip_select_personalized_sep(void);
#else
#define img4_chip_select_personalized_sep(...) \
		(img4if->i4if_v16.chip_select_personalized_sep(__VA_ARGS__))
#endif

/*!
 * @function img4_chip_select_categorized_ap
 * Returns the chip appropriate for categorized verification against the host
 * AP.
 *
 * @result
 * The categorized chip environment for the host which corresponds to its
 * silicon identity. If the host has no AP category defined for it, NULL will be
 * returned.
 *
 * @discussion
 * Categorized chip environments have been scuttled and were never used. Please
 * remove all uses of this function.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20210305
OS_EXPORT OS_WARN_RESULT
const img4_chip_t *_Nullable
img4_chip_select_categorized_ap(void);
#else
#define img4_chip_select_categorized_ap(...) \
		(img4if->i4if_v12.chip_select_categorized_ap(__VA_ARGS__))
#endif

/*!
 * @function img4_chip_select_effective_ap
 * Returns the chip appropriate for verification against the host AP.
 *
 * @result
 * The currently enforced chip environment for the host. This interface is
 * generally only useful on the AP.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT OS_WARN_RESULT
const img4_chip_t *
img4_chip_select_effective_ap(void);
#else
#define img4_chip_select_effective_ap(...) \
		(img4if->i4if_v7.chip_select_effective_ap(__VA_ARGS__))
#endif

/*!
 * @function img4_chip_select_cryptex1_boot
 * Returns the appropriate Cryptex1 boot chip environment for the currently-
 * booted effective AP environment.
 *
 * @result
 * The chip environment to use for verification.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20211126
OS_EXPORT OS_WARN_RESULT
const img4_chip_t *
img4_chip_select_cryptex1_boot(void);
#else
#define img4_chip_select_cryptex1_boot(...) \
		(img4if->i4if_v17.chip_select_cryptex1_boot(__VA_ARGS__))
#endif

/*!
 * @function img4_chip_select_cryptex1_preboot
 * Returns the appropriate Cryptex1 pre-reboot chip environment for the
 * currently-booted effective AP environment.
 *
 * @result
 * The chip environment to use for verification.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20211126
OS_EXPORT OS_WARN_RESULT
const img4_chip_t *
img4_chip_select_cryptex1_preboot(void);
#else
#define img4_chip_select_cryptex1_preboot(...) \
		(img4if->i4if_v17.chip_select_cryptex1_preboot(__VA_ARGS__))
#endif

/*!
 * @function img4_chip_get_cryptex1_boot
 * Returns the appropriate Cryptex1 boot chip environment associated with a
 * given AP environment.
 *
 * @param chip
 * The AP environment for which to obtain the associated Cryptex1 environment.
 *
 * @result
 * The Cryptex1 chip environment associated with {@link chip}. If there is no
 * Cryptex1 association, NULL is returned.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20220401
OS_EXPORT OS_WARN_RESULT OS_NONNULL1
const img4_chip_t *_Nullable
img4_chip_get_cryptex1_boot(const img4_chip_t *chip);
#else
#define img4_chip_get_cryptex1_boot(...) \
		(img4if->i4if_v18.chip_get_cryptex1_boot(__VA_ARGS__))
#endif

/*!
 * @function img4_chip_get_cryptex1_boot_proposal
 * Returns the appropriate Cryptex1 boot proposal chip environment associated
 * with a given AP environment.
 *
 * @param chip
 * The AP environment for which to obtain the associated Cryptex1 proposal
 * environment.
 *
 * @result
 * The Cryptex1 proposal chip environment associated with {@link chip}. If
 * there is no Cryptex1 association, NULL is returned.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20220401
OS_EXPORT OS_WARN_RESULT OS_NONNULL1
const img4_chip_t *_Nullable
img4_chip_get_cryptex1_boot_proposal(const img4_chip_t *chip);
#else
#define img4_chip_get_cryptex1_boot_proposal(...) \
		(img4if->i4if_v18.chip_get_cryptex1_boot_proposal(__VA_ARGS__))
#endif

/*!
 * @function img4_chip_instantiate
 * Returns an instantiation of the given chip using the default runtime where
 * necessary.
 *
 * @param chip
 * The chip to instantiate.
 *
 * @param chip_instance
 * Upon successful return, storage to be populated with the instantiated chip.
 * Upon failure, the contents of this storage are undefined.
 *
 * @result
 * Upon success, zero is returned. Otherwise, one of the following error codes
 * will be returned:
 *
 *     [EXDEV]       There was an error querying the runtime's identity oracle
 *     [ENODATA]     The expected property in the runtime's identity oracle was
 *                   of an unexpected type
 *     [EOVERFLOW]   The expected property in the runtime's identity oracle had
 *                   a value that was too large to be represented in the
 *                   expected type
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT OS_WARN_RESULT OS_NONNULL1 OS_NONNULL2
errno_t
img4_chip_instantiate(const img4_chip_t *chip,
		img4_chip_instance_t *chip_instance);
#else
#define img4_chip_instantiate(...) \
		(img4if->i4if_v7.chip_instantiate(__VA_ARGS__))
#endif

/*!
 * @function img4_chip_custom
 * Returns a custom chip derived from the given chip instance. The
 * {@link chid_chip_family} field of the given instance will be used as a
 * template from which to derive the new chip.
 *
 * @param chip_instance
 * The instance of the custom chip.
 *
 * The memory referenced by this pointer must be static or otherwise guaranteed
 * to be valid for the duration of the caller's use of the custom chip.
 *
 * @param chip
 * A pointer to storage for the new custom chip.
 *
 * The memory referenced by this pointer must be static or otherwise guaranteed
 * to be valid for the duration of the caller's use of the custom chip.
 *
 * This pointer should be obtained as the result of a call to
 * {@link img4_chip_init_from_buff}.
 *
 * @result
 * A new custom chip.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT OS_WARN_RESULT OS_NONNULL1
const img4_chip_t *
img4_chip_custom(const img4_chip_instance_t *chip_instance, img4_chip_t *chip);
#else
#define img4_chip_custom(...) (img4if->i4if_v7.chip_custom(__VA_ARGS__))
#endif

OS_ASSUME_NONNULL_END

#endif // __IMG4_CHIP_H
