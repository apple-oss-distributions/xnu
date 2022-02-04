/*!
 * @header
 * Shims for the SPI.
 */
#ifndef __IMG4_SHIM_H
#define __IMG4_SHIM_H

#ifndef __IMG4_INDIRECT
#error "Please #include <img4/firmware.h> instead of this file directly"
#endif // __IMG4_INDIRECT

#if KERNEL
#define IMG4_TARGET_XNU 1
#if __has_include(<img4/shim_xnu.h>)
#include <img4/shim_xnu.h>
#endif

#if XNU_KERNEL_PRIVATE
#define IMG4_TARGET_XNU_PROPER 1
#else
#define IMG4_TARGET_XNU_PROPER 0
#endif
#elif EFI
#define IMG4_TARGET_EFI 1
#if __has_include(<img4/shim_efi.h>)
#include <img4/shim_efi.h>
#endif
#else
#define IMG4_TARGET_DARWIN 1
#if __has_include(<img4/shim_darwin.h>)
#include <img4/shim_darwin.h>
#endif
#endif // KERNEL

#if IMG4_TARGET_XNU || IMG4_TARGET_DARWIN
#define IMG4_TARGET_DARWIN_GENERIC 1
#endif

#endif // __IMG4_SHIM_H
