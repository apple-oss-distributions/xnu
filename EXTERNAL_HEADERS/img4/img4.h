/*!
 * @header
 * Old umbrella header.
 */
#ifndef __IMG4_H
#define __IMG4_H

#include <os/base.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/cdefs.h>
#include <sys/kernel_types.h>
#include <sys/types.h>

#define __IMG4_INDIRECT 1
#include <img4/api.h>
#include <img4/firmware.h>

#if !_DARWIN_BUILDING_PROJECT_APPLEIMAGE4
#if IMG4_TARGET_EFI || IMG4_TARGET_SEP
#error "please #include <img4/firmware.h> instead"
#else
#warning "please #include <img4/firmware.h> instead"
#endif
#endif

IMG4_API_DEPRECATED_FALL_2018
typedef uint32_t img4_tag_t;

#endif // __IMG4_H
