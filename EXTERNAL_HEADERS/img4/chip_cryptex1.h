/*!
 * @header
 * Cryptex1 chip environments.
 */
#ifndef __IMG4_CHIP_CRYPTEX1_H
#define __IMG4_CHIP_CRYPTEX1_H

#ifndef __IMG4_INDIRECT
#error "Please #include <img4/firmware.h> instead of this file directly"
#endif // __IMG4_INDIRECT

__BEGIN_DECLS
OS_ASSUME_NONNULL_BEGIN
OS_ASSUME_PTR_ABI_SINGLE_BEGIN

/*!
 * @const IMG4_CHIP_CRYPTEX1_BOOT
 * A virtual coprocessor environment hosted on the AP which derives its unique
 * identity from the hosting AP. This chip assists in booting the AP's
 * userspace.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20211126
OS_EXPORT
const img4_chip_t _img4_chip_cryptex1_boot;
#define IMG4_CHIP_CRYPTEX1_BOOT (&_img4_chip_cryptex1_boot)
#else
#define IMG4_CHIP_CRYPTEX1_BOOT (img4if->i4if_v17.chip_cryptex1_boot)
#endif

/*!
 * @const IMG4_CHIP_CRYPTEX1_BOOT_REDUCED
 * A virtual coprocessor environment hosted on the reduced-security AP which
 * derives its unique identity from the hosting AP. This chip assists in booting
 * the AP's userspace.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20211126
OS_EXPORT
const img4_chip_t _img4_chip_cryptex1_boot_reduced;
#define IMG4_CHIP_CRYPTEX1_BOOT_REDUCED \
		(&_img4_chip_cryptex1_boot_reduced)
#else
#define IMG4_CHIP_CRYPTEX1_BOOT_REDUCED \
		(img4if->i4if_v17.chip_cryptex1_boot_reduced)
#endif

/*!
 * @const IMG4_CHIP_CRYPTEX1_BOOT_PROPOSAL
 * Equivalent to {@link IMG4_CHIP_CRYPTEX1_BOOT} with internal use constraints
 * relaxed to permit verification in scenarios where the currently-booted AP may
 * not represent the ultimate execution environment.
 *
 * @discussion
 * This environment should not be used for payload execution on the AP and is
 * intended to facilitate local policy signing in the SEP.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20220401
OS_EXPORT
const img4_chip_t _img4_chip_cryptex1_boot_proposal;
#define IMG4_CHIP_CRYPTEX1_BOOT_PROPOSAL (&_img4_chip_cryptex1_boot_proposal)
#else
#define IMG4_CHIP_CRYPTEX1_BOOT_PROPOSAL \
		(img4if->i4if_v18.chip_cryptex1_boot_proposal)
#endif

/*!
 * @const IMG4_CHIP_CRYPTEX1_BOOT_REDUCED_PROPOSAL
 * Equivalent to {@link IMG4_CHIP_CRYPTEX1_BOOT_REDUCED} with internal use
 * constraints relaxed to permit verification in scenarios where the currently-
 * booted AP may not represent the ultimate execution environment.
 *
 * @discussion
 * This environment should not be used for payload execution on the AP and is
 * intended to facilitate local policy signing in the SEP.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20220401
OS_EXPORT
const img4_chip_t _img4_chip_cryptex1_boot_reduced_proposal;
#define IMG4_CHIP_CRYPTEX1_BOOT_REDUCED_PROPOSAL \
		(&_img4_chip_cryptex1_boot_reduced_proposal)
#else
#define IMG4_CHIP_CRYPTEX1_BOOT_REDUCED_PROPOSAL \
		(img4if->i4if_v18.chip_cryptex1_boot_reduced_proposal)
#endif

/*!
 * @const IMG4_CHIP_CRYPTEX1_BOOT_X86
 * A virtual coprocessor environment hosted on an x86 chip which has no unique
 * identity. This chip assists in booting the x86 processor's userspace.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20211126
OS_EXPORT
const img4_chip_t _img4_chip_cryptex1_boot_x86;
#define IMG4_CHIP_CRYPTEX1_BOOT_X86 (&_img4_chip_cryptex1_boot_x86)
#else
#define IMG4_CHIP_CRYPTEX1_BOOT_X86 (img4if->i4if_v17.chip_cryptex1_boot_x86)
#endif

/*!
 * @const IMG4_CHIP_CRYPTEX1_BOOT_STATIC_X86
 * A virtual coprocessor environment hosted on an x86 chip which has no unique
 * identity. This chip assists in booting the x86 processor's userspace. This
 * chip has no ability to enforce expiration on its manifests.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20220912
OS_EXPORT
const img4_chip_t _img4_chip_cryptex1_boot_static_x86;
#define IMG4_CHIP_CRYPTEX1_BOOT_STATIC_X86 \
		(&_img4_chip_cryptex1_boot_static_x86)
#else
#define IMG4_CHIP_CRYPTEX1_BOOT_STATIC_X86 \
		(img4if->i4if_v19.chip_cryptex1_boot_static_x86)
#endif

/*!
 * @const IMG4_CHIP_CRYPTEX1_BOOT_RELAXED_X86
 * A virtual coprocessor environment hosted on an x86 chip which has no unique
 * identity and has secure boot disabled. This chip assists in booting the x86
 * processor's userspace.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20220711
OS_EXPORT
const img4_chip_t _img4_chip_cryptex1_boot_relaxed_x86;
#define IMG4_CHIP_CRYPTEX1_BOOT_RELAXED_X86 \
		(&_img4_chip_cryptex1_boot_relaxed_x86)
#else
#define IMG4_CHIP_CRYPTEX1_BOOT_RELAXED_X86 \
		(img4if->i4if_v19.chip_cryptex1_boot_relaxed_x86)
#endif

/*!
 * @const IMG4_CHIP_CRYPTEX1_BOOT_VMA2
 * A virtual coprocessor environment hosted on a virtualized ARM AP which
 * derives its unique identity from the hosting AP. This chip assists in booting
 * the AP's userspace.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20220128
OS_EXPORT
const img4_chip_t _img4_chip_cryptex1_boot_vma2;
#define IMG4_CHIP_CRYPTEX1_BOOT_VMA2 (&_img4_chip_cryptex1_boot_vma2)
#else
#define IMG4_CHIP_CRYPTEX1_BOOT_VMA2 (img4if->i4if_v17.chip_cryptex1_boot_vma2)
#endif

/*!
 * @const IMG4_CHIP_CRYPTEX1_BOOT_VMA2_CLONE
 * A virtual coprocessor environment hosted on a virtualized ARM AP which
 * derives its unique identity from the hosting AP. This chip assists in booting
 * the AP's userspace. This is the clone version which doesn't enforce ECID
 * and UDID.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20220322
OS_EXPORT
const img4_chip_t _img4_chip_cryptex1_boot_vma2_clone;
#define IMG4_CHIP_CRYPTEX1_BOOT_VMA2_CLONE \
		(&_img4_chip_cryptex1_boot_vma2_clone)
#else
#define IMG4_CHIP_CRYPTEX1_BOOT_VMA2_CLONE \
		(img4if->i4if_v18.chip_cryptex1_boot_vma2_clone)
#endif

/*!
 * @const IMG4_CHIP_CRYPTEX1_BOOT_VMA2_PROPOSAL
 * Equivalent to {@link IMG4_CHIP_CRYPTEX1_BOOT_VMA2} with internal use
 * constraints relaxed to permit verification in scenarios where the currently-
 * booted AP may not represent the ultimate execution environment.
 *
 * @discussion
 * This environment should not be used for payload execution on the AP and is
 * intended to facilitate local policy signing in the BootPolicy kext.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20220401
OS_EXPORT
const img4_chip_t _img4_chip_cryptex1_boot_vma2_proposal;
#define IMG4_CHIP_CRYPTEX1_BOOT_VMA2_PROPOSAL \
		(&_img4_chip_cryptex1_boot_vma2_proposal)
#else
#define IMG4_CHIP_CRYPTEX1_BOOT_VMA2_PROPOSAL \
		(img4if->i4if_v18.chip_cryptex1_boot_vma2_proposal)
#endif

/*!
 * @const IMG4_CHIP_CRYPTEX1_BOOT_VMA2_CLONE_PROPOSAL
 * Equivalent to {@link IMG4_CHIP_CRYPTEX1_BOOT_VMA2_CLONE} with internal use
 * constraints relaxed to permit verification in scenarios where the currently-
 * booted AP may not represent the ultimate execution environment.
 *
 * @discussion
 * This environment should not be used for payload execution on the AP and is
 * intended to facilitate local policy signing in the BootPolicy kext.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20220401
OS_EXPORT
const img4_chip_t _img4_chip_cryptex1_boot_vma2_clone_proposal;
#define IMG4_CHIP_CRYPTEX1_BOOT_VMA2_CLONE_PROPOSAL \
		(&_img4_chip_cryptex1_boot_vma2_clone_proposal)
#else
#define IMG4_CHIP_CRYPTEX1_BOOT_VMA2_CLONE_PROPOSAL \
		(img4if->i4if_v18.chip_cryptex1_boot_vma2_clone_proposal)
#endif

/*!
 * @const IMG4_CHIP_CRYPTEX1_PREBOOT
 * A virtual coprocessor environment hosted on the AP which derives its unique
 * identity from the hosting AP. This chip permits executing payloads intended
 * for the next boot prior to that boot. It does not assist in booting the AP.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20211126
OS_EXPORT
const img4_chip_t _img4_chip_cryptex1_preboot;
#define IMG4_CHIP_CRYPTEX1_PREBOOT (&_img4_chip_cryptex1_preboot)
#else
#define IMG4_CHIP_CRYPTEX1_PREBOOT (img4if->i4if_v17.chip_cryptex1_preboot)
#endif

/*!
 * @const IMG4_CHIP_CRYPTEX1_PREBOOT_REDUCED
 * A virtual coprocessor environment hosted on the reduced-security AP which
 * derives its unique identity from the hosting AP. This chip permits executing
 * payloads intended for the next boot prior to that boot. It does not assist in
 * booting the AP.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20211126
OS_EXPORT
const img4_chip_t _img4_chip_cryptex1_preboot_reduced;
#define IMG4_CHIP_CRYPTEX1_PREBOOT_REDUCED \
		(&_img4_chip_cryptex1_preboot_reduced)
#else
#define IMG4_CHIP_CRYPTEX1_PREBOOT_REDUCED \
		(img4if->i4if_v17.chip_cryptex1_preboot_reduced)
#endif

/*!
 * @const IMG4_CHIP_CRYPTEX1_PREBOOT_X86
 * A virtual coprocessor environment hosted on an x86 chip which has no unique
 * identity. This chip permits executing payloads intended for the next boot
 * prior to that boot. It does not assist in booting the x86 chip.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20211126
OS_EXPORT
const img4_chip_t _img4_chip_cryptex1_preboot_x86;
#define IMG4_CHIP_CRYPTEX1_PREBOOT_X86 \
		(&_img4_chip_cryptex1_preboot_x86)
#else
#define IMG4_CHIP_CRYPTEX1_PREBOOT_X86 \
		(img4if->i4if_v17.chip_cryptex1_preboot_x86)
#endif

/*!
 * @const IMG4_CHIP_CRYPTEX1_PREBOOT_STATIC_X86
 * A virtual coprocessor environment hosted on an x86 chip which has no unique
 * identity. This chip permits executing payloads intended for the next boot
 * prior to that boot. It does not assist in booting the x86 chip. This chip has
 * no ability to enforce expiration on its manifests.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20211126
OS_EXPORT
const img4_chip_t _img4_chip_cryptex1_preboot_static_x86;
#define IMG4_CHIP_CRYPTEX1_PREBOOT_STATIC_X86 \
		(&_img4_chip_cryptex1_preboot_static_x86)
#else
#define IMG4_CHIP_CRYPTEX1_PREBOOT_STATIC_X86 \
		(img4if->i4if_v19.chip_cryptex1_preboot_static_x86)
#endif

/*!
 * @const IMG4_CHIP_CRYPTEX1_PREBOOT_RELAXED_X86
 * A virtual coprocessor environment hosted on an x86 chip which has no unique
 * identity and has secure boot disabled. This chip permits executing payloads
 * intended for the next boot prior to that boot. It does not assist in booting
 * the x86 chip.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20220711
OS_EXPORT
const img4_chip_t _img4_chip_cryptex1_preboot_relaxed_x86;
#define IMG4_CHIP_CRYPTEX1_PREBOOT_RELAXED_X86 \
		(&_img4_chip_cryptex1_preboot_relaxed_x86)
#else
#define IMG4_CHIP_CRYPTEX1_PREBOOT_RELAXED_X86 \
		(img4if->i4if_v17.chip_cryptex1_preboot_relaxed_x86)
#endif

/*!
 * @const IMG4_CHIP_CRYPTEX1_PREBOOT_VMA2
 * A virtual coprocessor environment hosted on a virtualized ARM AP which
 * derives its unique identity from the hosting AP. This chip permits executing
 * payloads intended for the next boot prior to that boot. It does not assist in
 * booting the AP.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20220128
OS_EXPORT
const img4_chip_t _img4_chip_cryptex1_preboot_vma2;
#define IMG4_CHIP_CRYPTEX1_PREBOOT_VMA2 \
		(&_img4_chip_cryptex1_preboot_vma2)
#else
#define IMG4_CHIP_CRYPTEX1_PREBOOT_VMA2 \
		(img4if->i4if_v17.chip_cryptex1_preboot_vma2)
#endif

/*!
 * @const IMG4_CHIP_CRYPTEX1_PREBOOT_VMA2_CLONE
 * A virtual coprocessor environment hosted on a virtualized ARM AP which
 * derives its unique identity from the hosting AP. This chip permits executing
 * payloads intended for the next boot prior to that boot. It does not assist in
 * booting the AP. This is the clone version which doesn't enforce ECID
 * and UDID.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20220322
OS_EXPORT
const img4_chip_t _img4_chip_cryptex1_preboot_vma2_clone;
#define IMG4_CHIP_CRYPTEX1_PREBOOT_VMA2_CLONE \
		(&_img4_chip_cryptex1_preboot_vma2_clone)
#else
#define IMG4_CHIP_CRYPTEX1_PREBOOT_VMA2_CLONE \
		(img4if->i4if_v18.chip_cryptex1_preboot_vma2_clone)
#endif

/*!
 * @const IMG4_CHIP_CRYPTEX1_ASSET
 * A virtual coprocessor environment hosted on the AP which derives its unique
 * identity from the hosting AP. This chip assists in executing MobileAsset
 * brain payloads during runtime, after the host AP has booted its userspace.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20211126
OS_EXPORT
const img4_chip_t _img4_chip_cryptex1_asset;
#define IMG4_CHIP_CRYPTEX1_ASSET (&_img4_chip_cryptex1_asset)
#else
#define IMG4_CHIP_CRYPTEX1_ASSET (img4if->i4if_v17.chip_cryptex1_asset)
#endif

/*!
 * @const IMG4_CHIP_CRYPTEX1_ASSET_X86
 * A virtual coprocessor environment hosted on the AP which derives its unique
 * identity from the hosting AP. This chip assists in executing MobileAsset
 * brain payloads during runtime, after the host AP has booted its userspace.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20220401
OS_EXPORT
const img4_chip_t _img4_chip_cryptex1_asset_x86;
#define IMG4_CHIP_CRYPTEX1_ASSET_X86 (&_img4_chip_cryptex1_asset_x86)
#else
#define IMG4_CHIP_CRYPTEX1_ASSET_X86 (img4if->i4if_v18.chip_cryptex1_asset_x86)
#endif

/*!
 * @const IMG4_CHIP_CRYPTEX1_GENERIC
 * A virtual coprocessor environment hosted on the AP which derives its unique
 * identity from the hosting AP. This chip assists in executing generic cryptex
 * payloads during runtime, after the host AP has booted its userspace.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20221202
OS_EXPORT
const img4_chip_t _img4_chip_cryptex1_generic;
#define IMG4_CHIP_CRYPTEX1_GENERIC \
		(&_img4_chip_cryptex1_generic)
#else
#define IMG4_CHIP_CRYPTEX1_GENERIC \
		(img4if->i4if_v20.chip_cryptex1_generic)
#endif

/*!
 * @const IMG4_CHIP_CRYPTEX1_GENERIC_SUPPLEMENTAL
 * A virtual coprocessor environment hosted on the AP which derives its unique
 * identity from the hosting AP. This chip assists in executing generic cryptex
 * payloads during runtime, after the host AP has booted its userspace. Its
 * trust is rooted in a supplemental root of trust authorized by the Secure Boot
 * CA.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20221202
OS_EXPORT
const img4_chip_t _img4_chip_cryptex1_generic_supplemental;
#define IMG4_CHIP_CRYPTEX1_GENERIC_SUPPLEMENTAL \
		(&_img4_chip_cryptex1_generic_supplemental)
#else
#define IMG4_CHIP_CRYPTEX1_GENERIC_SUPPLEMENTAL \
		(img4if->i4if_v20.chip_cryptex1_generic_supplemental)
#endif

/*!
 * @const IMG4_CHIP_CRYPTEX1_GENERIC_X86
 * A virtual coprocessor environment hosted on an x86 chip. This chip assists in
 * executing generic cryptex payloads during runtime after the x86 chip has
 * booted.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20221202
OS_EXPORT
const img4_chip_t _img4_chip_cryptex1_generic_x86;
#define IMG4_CHIP_CRYPTEX1_GENERIC_X86 \
		(&_img4_chip_cryptex1_generic_x86)
#else
#define IMG4_CHIP_CRYPTEX1_GENERIC_X86 \
		(img4if->i4if_v20.chip_cryptex1_generic_x86)
#endif

OS_ASSUME_PTR_ABI_SINGLE_END
OS_ASSUME_NONNULL_END
__END_DECLS

#endif // __IMG4_CHIP_CRYPTEX1_H
