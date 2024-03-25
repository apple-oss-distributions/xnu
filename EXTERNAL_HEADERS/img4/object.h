/*!
 * @header
 * Image4 object specifications.
 */
#ifndef __IMG4_OBJECT_H
#define __IMG4_OBJECT_H

#ifndef __IMG4_INDIRECT
#error "Please #include <img4/firmware.h> instead of this file directly"
#endif // __IMG4_INDIRECT

__BEGIN_DECLS
OS_ASSUME_NONNULL_BEGIN
OS_ASSUME_PTR_ABI_SINGLE_BEGIN

/*!
 * @typedef img4_object_spec_t
 * An opaque type which describes information about Image4 objects for use by
 * the runtime.
 */
IMG4_API_AVAILABLE_20200508
typedef struct _img4_object_spec img4_object_spec_t;

/*!
 * @const IMG4_FIRMWARE_SPEC
 * The object specification for an {@link img4_firmware_t} object.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT
const img4_object_spec_t _img4_firmware_spec;
#define IMG4_FIRMWARE_SPEC (&_img4_firmware_spec)
#else
#define IMG4_FIRMWARE_SPEC (img4if->i4if_v7.firmware_spec)
#endif

/*!
 * @const IMG4_FIRMWARE_SIZE_RECOMMENDED
 * A constant describing the recommended stack allocation required for a
 * {@link img4_firmware_t} object.
 */
#define IMG4_FIRMWARE_SIZE_RECOMMENDED (1536u)

/*!
 * @const IMG4_CHIP_SPEC
 * The object specification for an {@link img4_chip_t} object.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT
const img4_object_spec_t _img4_chip_spec;
#define IMG4_CHIP_SPEC (&_img4_chip_spec)
#else
#define IMG4_CHIP_SPEC (img4if->i4if_v7.chip_spec)
#endif

/*!
 * @const IMG4_CHIP_SIZE_RECOMMENDED
 * A constant describing the recommended stack allocation required for a
 * {@link img4_chip_t} object.
 */
#define IMG4_CHIP_SIZE_RECOMMENDED (960u)

/*!
 * @const IMG4_PMAP_DATA_SPEC
 * The object specification for an {@link img4_pmap_data_t} object.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20210521
OS_EXPORT
const img4_object_spec_t _img4_pmap_data_spec;
#define IMG4_PMAP_DATA_SPEC (&_img4_pmap_data_spec)
#else
#define IMG4_PMAP_DATA_SPEC (img4if->i4if_v13.pmap_data_spec)
#endif

/*!
 * @const IMG4_PMAP_DATA_SIZE_RECOMMENDED
 * A constant describing the recommended stack allocation required for a
 * {@link img4_pmap_data_t} object.
 */
#define IMG4_PMAP_DATA_SIZE_RECOMMENDED (5120u)

OS_ASSUME_PTR_ABI_SINGLE_END
OS_ASSUME_NONNULL_END
__END_DECLS

#endif // __IMG4_OBJECT_H
