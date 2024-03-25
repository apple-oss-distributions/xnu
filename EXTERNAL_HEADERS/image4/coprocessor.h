/*!
 * @header
 * Supported coprocessors.
 */
#ifndef __IMAGE4_API_COPROCESSOR_H
#define __IMAGE4_API_COPROCESSOR_H

#include <image4/image4.h>
#include <image4/types.h>

__BEGIN_DECLS
OS_ASSUME_NONNULL_BEGIN
OS_ASSUME_PTR_ABI_SINGLE_BEGIN

/*!
 * @const IMAGE4_COPROCESSOR_HOST
 * The host execution environment. This environment does not support handles.
 */
IMAGE4_API_AVAILABLE_SPRING_2024
OS_EXPORT
const image4_coprocessor_t _image4_coprocessor_host;
#define IMAGE4_COPROCESSOR_HOST (&_image4_coprocessor_host)
IMAGE4_XNU_AVAILABLE_INDIRECT(_image4_coprocessor_host);

/*!
 * @const IMAGE4_COPROCESSOR_AP
 * The Application Processor executing payloads signed by the Secure Boot CA.
 *
 * Handles for this environment are enumerated in the
 * {@link image4_coprocessor_ap_handle_t} type.
 */
IMAGE4_API_AVAILABLE_SPRING_2024
OS_EXPORT
const image4_coprocessor_t _image4_coprocessor_ap;
#define IMAGE4_COPROCESSOR_AP (&_image4_coprocessor_ap)
IMAGE4_XNU_AVAILABLE_INDIRECT(_image4_coprocessor_ap);

/*!
 * @typedef image4_coprocessor_handle_ap_t
 * Handles describing supported AP execution environments.
 *
 * @const IMAGE4_COPROCESSOR_HANDLE_AP
 * The host's Application Processor environment.
 *
 * @const IMAGE4_COPROCESSOR_HANDLE_AP_FF00
 * The software AP environment used for loading globally-signed OTA update brain
 * trust caches.
 *
 * @const IMAGE4_COPROCESSOR_HANDLE_AP_FF01
 * The software AP environment used for loading globally-signed Install
 * Assistant brain trust caches.
 *
 * @const IMAGE4_COPROCESSOR_HANDLE_AP_FF06
 * The software AP environment used for loading globally-signed Bootability
 * brain trust caches.
 *
 * @const IMAGE4_COPROCESSOR_HANDLE_AP_PDI
 * The sideloading AP environment used to load a personalized disk image.
 *
 * @const IMAGE4_COPROCESSOR_HANDLE_AP_SRDP
 * The sideloading AP environment used to load firmware which has been
 * authorized as part of the Security Research Device Program.
 *
 * @const IMAGE4_COPROCESSOR_HANDLE_AP_DDI
 * The sideloading AP environment used to load a personalized disk image which
 * is automatically mounted at boot.
 *
 * This handle is available starting in API version 20231027.
 */
OS_CLOSED_ENUM(image4_coprocessor_handle_ap, image4_coprocessor_handle_t,
	IMAGE4_COPROCESSOR_HANDLE_AP = 0,
	IMAGE4_COPROCESSOR_HANDLE_AP_FF00,
	IMAGE4_COPROCESSOR_HANDLE_AP_FF01,
	IMAGE4_COPROCESSOR_HANDLE_AP_FF06,
	IMAGE4_COPROCESSOR_HANDLE_AP_PDI,
	IMAGE4_COPROCESSOR_HANDLE_AP_SRDP,
	IMAGE4_COPROCESSOR_HANDLE_AP_RESERVED_0,
	IMAGE4_COPROCESSOR_HANDLE_AP_RESERVED_1,
	IMAGE4_COPROCESSOR_HANDLE_AP_RESERVED_2,
	IMAGE4_COPROCESSOR_HANDLE_AP_DDI,
	_IMAGE4_COPROCESSOR_HANDLE_AP_CNT,
);

/*!
 * @const IMAGE4_COPROCESSOR_AP_LOCAL
 * The Application Processor executing payloads signed by the Basic Attestation
 * Authority.
 *
 * Handles for this environment are enumerated in the
 * {@link image4_coprocessor_handle_ap_local_t} type.
 */
IMAGE4_API_AVAILABLE_SPRING_2024
OS_EXPORT
const image4_coprocessor_t _image4_coprocessor_ap_local;
#define IMAGE4_COPROCESSOR_AP_LOCAL (&_image4_coprocessor_ap_local)
IMAGE4_XNU_AVAILABLE_INDIRECT(_image4_coprocessor_ap_local);

/*!
 * @typedef image4_coprocessor_handle_ap_local_t
 * Handles describing supported local policy execution environments.
 *
 * @const IMAGE4_COPROCESSOR_HANDLE_AP_LOCAL
 * The host's local policy environment.
 */

OS_CLOSED_ENUM(image4_coprocessor_handle_ap_local, image4_coprocessor_handle_t,
	IMAGE4_COPROCESSOR_HANDLE_AP_LOCAL = 0,
	IMAGE4_COPROCESSOR_HANDLE_AP_LOCAL_RESERVED_0,
	IMAGE4_COPROCESSOR_HANDLE_AP_LOCAL_RESERVED_1,
	IMAGE4_COPROCESSOR_HANDLE_AP_LOCAL_RESERVED_2,
	_IMAGE4_COPROCESSOR_HANDLE_AP_LOCAL_CNT,
);

/*!
 * @const IMAGE4_COPROCESSOR_CRYPTEX1
 * The Cryptex1 coprocessor executing payloads signed by the Secure Boot CA.
 *
 * Handles for this environment are enumerated in the
 * {@link image4_coprocessor_handle_cryptex1_t} type.
 */
IMAGE4_API_AVAILABLE_SPRING_2024
OS_EXPORT
const image4_coprocessor_t _image4_coprocessor_cryptex1;
#define IMAGE4_COPROCESSOR_CRYPTEX1 (&_image4_coprocessor_cryptex1)
IMAGE4_XNU_AVAILABLE_INDIRECT(_image4_coprocessor_cryptex1);

/*!
 * @typedef image4_coprocessor_handle_cryptex1_t
 * Handles describing supported Cryptex1 execution environments.
 *
 * @const IMAGE4_COPROCESSOR_HANDLE_CRYPTEX1_BOOT
 * The host's Cryptex1 boot coprocessor.
 *
 * @const IMAGE4_COPROCESSOR_HANDLE_CRYPTEX1_BOOT_LIVE
 * The host's Cryptex1 boot coprocessor used for executing newly-authorized
 * firmware prior to that firmware being evaluated by Secure Boot.
 *
 * @const IMAGE4_COPROCESSOR_HANDLE_CRYPTEX1_ASSET_BRAIN
 * The host's Cryptex1 coprocessor used for loading MobileAsset brain firmware.
 *
 * @const IMAGE4_COPROCESSOR_HANDLE_CRYPTEX1_GENERIC
 * The host's Cryptex1 coprocessor used for loading generic supplemental
 * content.
 */
OS_CLOSED_ENUM(image4_coprocessor_handle_cryptex1, image4_coprocessor_handle_t,
	IMAGE4_COPROCESSOR_HANDLE_CRYPTEX1_BOOT = 0,
	IMAGE4_COPROCESSOR_HANDLE_CRYPTEX1_BOOT_LIVE,
	IMAGE4_COPROCESSOR_HANDLE_CRYPTEX1_ASSET_BRAIN,
	IMAGE4_COPROCESSOR_HANDLE_CRYPTEX1_GENERIC,
	IMAGE4_COPROCESSOR_HANDLE_CRYPTEX1_RESERVED_0,
	IMAGE4_COPROCESSOR_HANDLE_CRYPTEX1_RESERVED_1,
	IMAGE4_COPROCESSOR_HANDLE_CRYPTEX1_RESERVED_2,
	_IMAGE4_COPROCESSOR_HANDLE_CRYPTEX1_CNT,
);

/*!
 * @const IMAGE4_COPROCESSOR_SEP
 * The Secure Enclave Processor executing payloads signed by the Secure Boot CA.
 *
 * Handles for this environment are enumerated in the
 * {@link image4_coprocessor_handle_sep_t} type.
 */
IMAGE4_API_AVAILABLE_SPRING_2024
OS_EXPORT
const image4_coprocessor_t _image4_coprocessor_sep;
#define IMAGE4_COPROCESSOR_SEP (&_image4_coprocessor_sep)
IMAGE4_XNU_AVAILABLE_INDIRECT(_image4_coprocessor_sep);

/*!
 * @typedef image4_coprocessor_handle_sep_t
 * Handles describing supported SEP execution environments.
 *
 * @const IMAGE4_COPROCESSOR_HANDLE_SEP
 * The host's SEP environment.
 */
OS_CLOSED_ENUM(image4_coprocessor_handle_sep, image4_coprocessor_handle_t,
	IMAGE4_COPROCESSOR_HANDLE_SEP = 0,
	_IMAGE4_COPROCESSOR_HANDLE_SEP_CNT,
);

/*!
 * @const IMAGE4_COPROCESSOR_X86
 * An x86 processor executing payloads signed by the x86 Secure Boot CA.
 *
 * Handles for this environment are enumerated in the
 * {@link image4_coprocessor_handle_x86_t} type.
 */
IMAGE4_API_AVAILABLE_SPRING_2024
OS_EXPORT
const image4_coprocessor_t _image4_coprocessor_x86;
#define IMAGE4_COPROCESSOR_X86 (&_image4_coprocessor_x86)
IMAGE4_XNU_AVAILABLE_INDIRECT(_image4_coprocessor_x86);

/*!
 * @typedef image4_coprocessor_handle_x86_t
 * Handles describing supported x86 execution environments.
 *
 * @const IMAGE4_COPROCESSOR_HANDLE_X86
 * The host's x86 environment.
 */
OS_CLOSED_ENUM(image4_coprocessor_handle_x86, image4_coprocessor_handle_t,
	IMAGE4_COPROCESSOR_HANDLE_X86 = 0,
	_IMAGE4_COPROCESSOR_HANDLE_X86_CNT,
);

OS_ASSUME_PTR_ABI_SINGLE_END
OS_ASSUME_NONNULL_END
__END_DECLS

#endif // __IMAGE4_API_COPROCESSOR_H
