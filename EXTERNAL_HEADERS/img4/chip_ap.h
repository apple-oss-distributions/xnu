/*!
 * @header
 * AP chip environments.
 */
#ifndef __IMG4_CHIP_AP_H
#define __IMG4_CHIP_AP_H

#ifndef __IMG4_INDIRECT
#error "Please #include <img4/firmware.h> instead of this file directly"
#endif // __IMG4_INDIRECT

__BEGIN_DECLS
OS_ASSUME_NONNULL_BEGIN
OS_ASSUME_PTR_ABI_SINGLE_BEGIN

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
 * An Application Processor on an Apple ARM SoC operating entirely within the
 * user's authority.
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
 * @const IMG4_CHIP_AP_LOCAL_BLESSED
 * An Application Processor on an Apple ARM SoC which is executing payloads from
 * a future local policy that has not yet booted.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20220513
OS_EXPORT
const img4_chip_t _img4_chip_ap_local_blessed;
#define IMG4_CHIP_AP_LOCAL_BLESSED (&_img4_chip_ap_local_blessed)
#else
#define IMG4_CHIP_AP_LOCAL_BLESSED (img4if->i4if_v18.chip_ap_local_blessed)
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

OS_ASSUME_PTR_ABI_SINGLE_END
OS_ASSUME_NONNULL_END
__END_DECLS

#endif // __IMG4_CHIP_AP_H
