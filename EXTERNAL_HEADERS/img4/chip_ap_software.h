/*!
 * @header
 * Software AP chip environments.
 */
#ifndef __IMG4_CHIP_AP_SOFTWARE_H
#define __IMG4_CHIP_AP_SOFTWARE_H

#ifndef __IMG4_INDIRECT
#error "Please #include <img4/firmware.h> instead of this file directly"
#endif // __IMG4_INDIRECT

OS_ASSUME_NONNULL_BEGIN

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

OS_ASSUME_NONNULL_END

#endif // __IMG4_CHIP_AP_SOFTWARE_H
