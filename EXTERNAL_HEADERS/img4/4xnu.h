/*!
 * @header
 * xnu-specific interfaces. These are hacks that only exist because xnu doesn't
 * like linking static libraries, and we have a pre-existing contract for how to
 * export our interfaces to xnu.
 */
#ifndef __IMG4_4XNU_H
#define __IMG4_4XNU_H

#ifndef __IMG4_INDIRECT
#error "Please #include <img4/firmware.h> instead of this file directly"
#endif // __IMG4_INDIRECT

__BEGIN_DECLS
OS_ASSUME_NONNULL_BEGIN

/*!
 * @function img4_get_manifest
 * Returns a buffer representing the Image4 manifest bytes within the given DER
 * blob.
 *
 * @param buff
 * The buffer to examine for the Image4 manifest.
 *
 * @param len
 * The length of {@link buff}.
 *
 * @param buff_storage
 * Upon successful return, a buffer object which will contain a pointer to and
 * the length of the Image4 manifest.
 *
 * @result
 * Upon success, {@link buff_storage} is returned. If the DER blob contains no
 * Image4 manifest, then NULL is returned.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20211105
OS_EXPORT OS_WARN_RESULT OS_NONNULL1 OS_NONNULL3
const img4_buff_t *
img4_get_manifest(const void *buff, size_t len, img4_buff_t *buff_storage);
#else
#define img4_get_manifest(...) \
		(img4if->i4if_v15.get_manifest(__VA_ARGS__))
#endif

/*!
 * @function img4_get_payload
 * Returns a buffer representing the Image4 payload bytes within the given DER
 * blob.
 *
 * @param buff
 * The buffer to examine for the Image4 payload.
 *
 * @param len
 * The length of {@link buff}.
 *
 * @param buff_storage
 * Upon successful return, a buffer object which will contain a pointer to and
 * the length of the Image4 manifest.
 *
 * @result
 * Upon success, {@link buff_storage} is returned. If the DER blob contains no
 * Image4 payload, then NULL is returned.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20211105
OS_EXPORT OS_WARN_RESULT OS_NONNULL1 OS_NONNULL3
const img4_buff_t *
img4_get_payload(const void *buff, size_t len, img4_buff_t *buff_storage);
#else
#define img4_get_payload(...) \
		(img4if->i4if_v15.get_payload(__VA_ARGS__))
#endif

OS_ASSUME_NONNULL_END
__END_DECLS

#endif // __IMG4_4XNU_H
