/*!
 * @header
 * Cryptex1 chip environments.
 */
#ifndef __IMG4_CHIP_SEP_H
#define __IMG4_CHIP_SEP_H

#ifndef __IMG4_INDIRECT
#error "Please #include <img4/firmware.h> instead of this file directly"
#endif // __IMG4_INDIRECT

OS_ASSUME_NONNULL_BEGIN

/*!
 * @const IMG4_CHIP_SEP_SHA1
 * The Secure Enclave Processor on an Apple ARM SoC with an embedded sha1
 * certifcate chain.
 *
 * This chip environment represents one unique instance of such a chip.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20211119
OS_EXPORT
const img4_chip_t _img4_chip_sep_sha1;
#define IMG4_CHIP_SEP_SHA1 (&_img4_chip_sep_sha1)
#else
#define IMG4_CHIP_SEP_SHA1 (img4if->i4if_v16.chip_sep_sha1)
#endif

/*!
 * @const IMG4_CHIP_SEP_SHA2_384
 * The Secure Enclave Processor on an Apple ARM SoC with an embedded sha2-384
 * certifcate chain.
 *
 * This chip environment represents one unique instance of such a chip.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20211119
OS_EXPORT
const img4_chip_t _img4_chip_sep_sha2_384;
#define IMG4_CHIP_SEP_SHA2_384 (&_img4_chip_sep_sha2_384)
#else
#define IMG4_CHIP_SEP_SHA2_384 (img4if->i4if_v16.chip_sep_sha2_384)
#endif

OS_ASSUME_NONNULL_END

#endif // __IMG4_CHIP_SEP_H
