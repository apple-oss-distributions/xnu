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
 * @typedef img4_chip_t
 * An opaque type describing a destination chip environment for the firmware
 * image.
 */
IMG4_API_AVAILABLE_20200508
typedef struct _img4_chip img4_chip_t;

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
#define IMG4_CHIP_INSTANCE_STRUCT_VERSION (2u)

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
}

/*!
 * @const IMG4_CHIP_AP_SHA1
 * The Application Processor on an Apple ARM SoC with an embedded sha1
 * certifcate chain.
 *
 * This chip environment represents one unique instance of such a chip.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT
const img4_chip_t _img4_chip_ap_sha1;
#define IMG4_CHIP_AP_SHA1 (&_img4_chip_ap_sha1)
#else
#define IMG4_CHIP_AP_SHA1 (img4if->i4if_v7.chip_ap_sha1)
#endif

/*!
 * @const IMG4_CHIP_AP_SHA2_384
 * The Application Processor on an Apple ARM SoC with an embedded sha2-384
 * certifcate chain.
 *
 * This chip environment represents one unique instance of such a chip.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT
const img4_chip_t _img4_chip_ap_sha2_384;
#define IMG4_CHIP_AP_SHA2_384 (&_img4_chip_ap_sha2_384)
#else
#define IMG4_CHIP_AP_SHA2_384 (img4if->i4if_v7.chip_ap_sha2_384)
#endif

/*!
 * @const IMG4_CHIP_AP_HYBRID
 * An Intel x86 processor whose chain of trust is rooted in an instance of a
 * {@link IMG4_CHIP_AP_SHA2_384} chip. Firmwares executed on this chip are
 * authenticated against the characteristics of the corresponding AP chip
 * environment and not the characteristics of the x86 processor.
 *
 * This chip environment represents one unique instance of such a chip pair.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT
const img4_chip_t _img4_chip_ap_hybrid;
#define IMG4_CHIP_AP_HYBRID (&_img4_chip_ap_hybrid)
#else
#define IMG4_CHIP_AP_HYBRID (img4if->i4if_v7.chip_ap_hybrid)
#endif

/*!
 * @const IMG4_CHIP_AP_REDUCED
 * An Application Processor on an Apple ARM SoC operating in a reduced security
 * configuration.
 *
 * This chip cannot be uniquely identified.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT
const img4_chip_t _img4_chip_ap_reduced;
#define IMG4_CHIP_AP_REDUCED (&_img4_chip_ap_reduced)
#else
#define IMG4_CHIP_AP_REDUCED (img4if->i4if_v7.chip_ap_reduced)
#endif

/*!
 * @const IMG4_CHIP_AP_PERMISSIVE
 * An Application Processor on an Apple ARM SoC operating with no secure boot
 * enforcement.
 *
 * This chip's identity is rooted in a device-specific authority rather than one
 * maintained by Apple.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT
const img4_chip_t _img4_chip_ap_permissive;
#define IMG4_CHIP_AP_PERMISSIVE (&_img4_chip_ap_permissive)
#else
#define IMG4_CHIP_AP_PERMISSIVE (img4if->i4if_v8.chip_ap_permissive)
#endif

/*!
 * @const IMG4_CHIP_AP_HYBRID_MEDIUM
 * An Intel x86 processor whose chain of trust is rooted in an instance of a
 * {@link IMG4_CHIP_AP_SHA2_384} chip and is operating in a "medium security"
 * mode due to a user-approved security degradation.
 *
 * This chip cannot be uniquely identified.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT
const img4_chip_t _img4_chip_ap_hybrid_medium;
#define IMG4_CHIP_AP_HYBRID_MEDIUM (&_img4_chip_ap_hybrid_medium)
#else
#define IMG4_CHIP_AP_HYBRID_MEDIUM (img4if->i4if_v8.chip_ap_hybrid_medium)
#endif

/*!
 * @const IMG4_CHIP_AP_HYBRID_RELAXED
 * An Intel x86 processor whose chain of trust is rooted in an instance of a
 * {@link IMG4_CHIP_AP_SHA2_384} chip and is operating with no secure boot
 * due to a user-approved security degradation.
 *
 * This chip cannot be uniquely identified.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT
const img4_chip_t _img4_chip_ap_hybrid_relaxed;
#define IMG4_CHIP_AP_HYBRID_RELAXED (&_img4_chip_ap_hybrid_relaxed)
#else
#define IMG4_CHIP_AP_HYBRID_RELAXED (img4if->i4if_v8.chip_ap_hybrid_relaxed)
#endif

/*!
 * @const IMG4_CHIP_AP_SOFTWARE_FF00
 * A software-defined chip environment whose firmwares are executed on any
 * Application Processor on an Apple ARM SoC. The firmwares are loadable trust
 * caches shipped with OTA update brains.
 *
 * This chip cannot be uniquely identified.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT
const img4_chip_t _img4_chip_ap_software_ff00;
#define IMG4_CHIP_AP_SOFTWARE_FF00 (&_img4_chip_ap_software_ff00)
#else
#define IMG4_CHIP_AP_SOFTWARE_FF00 (img4if->i4if_v7.chip_ap_software_ff00)
#endif

/*!
 * @const IMG4_CHIP_AP_SOFTWARE_FF01
 * A software-defined chip environment whose firmwares are executed on any
 * Application Processor on an Apple ARM SoC. The firmwares are loadable trust
 * caches which are shipped in the Install Assistant and loaded by an
 * unprivileged trampoline.
 *
 * This chip cannot be uniquely identified.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT
const img4_chip_t _img4_chip_ap_software_ff01;
#define IMG4_CHIP_AP_SOFTWARE_FF01 (&_img4_chip_ap_software_ff01)
#else
#define IMG4_CHIP_AP_SOFTWARE_FF01 (img4if->i4if_v7.chip_ap_software_ff01)
#endif

/*!
 * @const IMG4_CHIP_AP_CATEGORY_FF02
 * The Application Processor on an Intel Mac product.
 *
 * This chip environment represents one unique instance of such a chip, though
 * the uniqueness is not enforced by a secure boot chain with anti-replay
 * properties, and therefore this chip environment should be considered as
 * equivalent to a global signing environment.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20210305
OS_EXPORT
const img4_chip_t _img4_chip_ap_category_ff02;
#define IMG4_CHIP_AP_CATEGORY_FF02 (&_img4_chip_ap_category_ff02)
#else
#define IMG4_CHIP_AP_CATEGORY_FF02 (img4if->i4if_v12.chip_ap_category_ff02)
#endif

/*!
 * @const IMG4_CHIP_AP_CATEGORY_FF03
 * An Intel x86 processor whose chain of trust is rooted in an instance of a
 * {@link IMG4_CHIP_AP_SHA2_384} chip.
 *
 * This chip environment represents one unique instance of such a chip pair.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20210305
OS_EXPORT
const img4_chip_t _img4_chip_ap_category_ff03;
#define IMG4_CHIP_AP_CATEGORY_FF03 (&_img4_chip_ap_category_ff03)
#else
#define IMG4_CHIP_AP_CATEGORY_FF03 (img4if->i4if_v12.chip_ap_category_ff03)
#endif

/*!
 * @const IMG4_CHIP_AP_CATEGORY_FF04_F0
 * The Application Processor of an Apple ARM SoC in an Apple Silicon Mac
 * product.
 *
 * This chip environment represents one unique instance of such a chip.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20210305
OS_EXPORT
const img4_chip_t _img4_chip_ap_category_ff04_f0;
#define IMG4_CHIP_AP_CATEGORY_FF04_F0 (&_img4_chip_ap_category_ff04_f0)
#else
#define IMG4_CHIP_AP_CATEGORY_FF04_F0 \
		(img4if->i4if_v12.chip_ap_category_ff04_f0)
#endif

/*!
 * @const IMG4_CHIP_AP_CATEGORY_FF04_F1
 * The Application Processor of an Apple ARM SoC in an iPhone, iPad, or iPod
 * touch product.
 *
 * This chip environment represents one unique instance of such a chip.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20210305
OS_EXPORT
const img4_chip_t _img4_chip_ap_category_ff04_f1;
#define IMG4_CHIP_AP_CATEGORY_FF04_F1 (&_img4_chip_ap_category_ff04_f1)
#else
#define IMG4_CHIP_AP_CATEGORY_FF04_F1 \
		(img4if->i4if_v12.chip_ap_category_ff04_f1)
#endif

/*!
 * @const IMG4_CHIP_AP_CATEGORY_FF04_F2
 * The Application Processor of an Apple ARM SoC in an watch product.
 *
 * This chip environment represents one unique instance of such a chip.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20210305
OS_EXPORT
const img4_chip_t _img4_chip_ap_category_ff04_f2;
#define IMG4_CHIP_AP_CATEGORY_FF04_F2 (&_img4_chip_ap_category_ff04_f2)
#else
#define IMG4_CHIP_AP_CATEGORY_FF04_F2 \
		(img4if->i4if_v12.chip_ap_category_ff04_f2)
#endif

/*!
 * @const IMG4_CHIP_AP_CATEGORY_FF04_F3
 * The Application Processor of an Apple ARM SoC in an tv or HomePod product.
 *
 * This chip environment represents one unique instance of such a chip.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20210305
OS_EXPORT
const img4_chip_t _img4_chip_ap_category_ff04_f3;
#define IMG4_CHIP_AP_CATEGORY_FF04_F3 (&_img4_chip_ap_category_ff04_f3)
#else
#define IMG4_CHIP_AP_CATEGORY_FF04_F3 \
		(img4if->i4if_v12.chip_ap_category_ff04_f3)
#endif

/*!
 * @const IMG4_CHIP_AP_SOFTWARE_FF06
 * A software-defined chip environment whose firmwares are executed on any
 * Application Processor on an Apple ARM SoC. The firmwares are loadable trust
 * caches which are shipped in the preboot volume.
 *
 * This chip cannot be uniquely identified.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20210113
OS_EXPORT
const img4_chip_t _img4_chip_ap_software_ff06;
#define IMG4_CHIP_AP_SOFTWARE_FF06 (&_img4_chip_ap_software_ff06)
#else
#define IMG4_CHIP_AP_SOFTWARE_FF06 (img4if->i4if_v11.chip_ap_software_ff06)
#endif

/*!
 * @const IMG4_CHIP_X86
 * An Intel x86 processor which cannot be uniquely identified.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT
const img4_chip_t _img4_chip_x86;
#define IMG4_CHIP_X86 (&_img4_chip_x86)
#else
#define IMG4_CHIP_X86 (img4if->i4if_v7.chip_x86)
#endif

/*!
 * @const IMG4_CHIP_X86_SOFTWARE_8012
 * A software-defined chip environment describing a virtualized x86 processor.
 * Since the virtual machine is at the mercy of the VM, support for any sort of
 * chip identity may not be available. Therefore this environment is returned
 * from {@link img4_chip_select_personalized_ap} and
 * {@link img4_chip_select_effective_ap} when it is called on a virtual machine
 * so that the appropriate chip environment is present entirely in software.
 *
 * This environment provides an equivalent software identity to that of
 * the {@link IMG4_CHIP_X86} chip environment on non-Gibraltar Macs.
 *
 * @discussion
 * Do not use this environment directly.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT
const img4_chip_t _img4_chip_x86_software_8012;
#define IMG4_CHIP_X86_SOFTWARE_8012 (&_img4_chip_x86_software_8012)
#else
#define IMG4_CHIP_X86_SOFTWARE_8012 (img4if->i4if_v7.chip_x86_software_8012)
#endif

/*!
 * @const IMG4_CHIP_AP_INTRANSIGENT
 * An Application Processor which is incapable of executing code. This chip
 * environment's root of trust is a certificate authority which has never and
 * will never issue any certificates.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20210113
OS_EXPORT
const img4_chip_t _img4_chip_ap_intransigent;
#define IMG4_CHIP_AP_INTRANSIGENT (&_img4_chip_ap_intransigent)
#else
#define IMG4_CHIP_AP_INTRANSIGENT (img4if->i4if_v11.chip_ap_intransigent)
#endif

/*!
 * @const IMG4_CHIP_AP_SUPPLEMENTAL
 * An Application Processor whose root of trust resides in the
 * {@link IMG4_RUNTIME_OBJECT_SPEC_SUPPLEMENTAL_ROOT} object. Once the
 * supplemental root object is executed on the host's AP, this chip environment
 * is available to execute payloads.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20210113
OS_EXPORT
const img4_chip_t _img4_chip_ap_supplemental;
#define IMG4_CHIP_AP_SUPPLEMENTAL (&_img4_chip_ap_supplemental)
#else
#define IMG4_CHIP_AP_SUPPLEMENTAL (img4if->i4if_v11.chip_ap_supplemental)
#endif

/*!
 * @const IMG4_CHIP_AP_VMA2
 * The Application Processor of a virtualized Apple ARM device.
 *
 * This chip environment represents one unique instance of such a chip on the
 * host device.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20210113
OS_EXPORT
const img4_chip_t _img4_chip_ap_vma2;
#define IMG4_CHIP_AP_VMA2 (&_img4_chip_ap_vma2)
#else
#define IMG4_CHIP_AP_VMA2 (img4if->i4if_v13.chip_ap_vma2)
#endif

/*!
 * @const IMG4_CHIP_AP_VMA2_CLONE
 * The Application Processor of a virtualized Apple ARM device which has been
 * cloned from another on the same host.
 *
 * This chip environment cannot be uniquely identified.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20210113
OS_EXPORT
const img4_chip_t _img4_chip_ap_vma2_clone;
#define IMG4_CHIP_AP_VMA2_CLONE (&_img4_chip_ap_vma2_clone)
#else
#define IMG4_CHIP_AP_VMA2_CLONE (img4if->i4if_v13.chip_ap_vma2_clone)
#endif

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
 * @function img4_chip_select_categorized_ap
 * Returns the chip appropriate for categorized verification against the host
 * AP.
 *
 * @result
 * The categorized chip environment for the host which corresponds to its
 * silicon identity. If the host has no AP category defined for it, NULL will be
 * returned.
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
