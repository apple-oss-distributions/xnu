/*!
 * @header
 * Umbrella header for Image4 trust evaluation API.
 */
#ifndef __IMAGE4_API_H
#define __IMAGE4_API_H

/*!
 * @const IMAGE4_API_VERSION
 * The API version of the library. This version will be changed in accordance
 * with new API introductions so that callers may submit code to the build that
 * adopts those new APIs before the APIs land by using the following pattern:
 *
 *     #if IMAGE4_API_VERSION >= 20221230
 *     image4_new_api();
 *     #endif
 *
 * In this example, the library maintainer and API adopter agree on an API
 * version of 20221230 ahead of time for the introduction of
 * image4_new_api(). When a libdarwin with that API version is submitted, the
 * project is rebuilt, and the new API becomes active.
 *
 * Breaking API changes will be both covered under this mechanism as well as
 * individual preprocessor macros in this header that declare new behavior as
 * required.
 */
#define IMAGE4_API_VERSION (20231216u)

#if __has_include(<os/base.h>)
#include <os/base.h>
#else
#include <image4/shim/base.h>
#endif

#if __has_include(<sys/types.h>)
#include <sys/types.h>

#if !defined(_ERRNO_T)
typedef int errno_t;
#endif // !defined(_ERRNO_T)
#else
#include <image4/shim/types.h>
#endif

#if __has_include(<TargetConditionals.h>)
#include <TargetConditionals.h>
#endif

#if __has_include(<os/availability.h>)
#include <os/availability.h>
#endif

#if __has_include(<sys/cdefs.h>)
#include <sys/cdefs.h>
#endif

#if !defined(__BEGIN_DECLS)
#if defined(__cplusplus)
#define __BEGIN_DECLS   extern "C" {
#define __END_DECLS     }
#else
#define __BEGIN_DECLS
#define __END_DECLS
#endif
#endif

#if !defined(__static_size)
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L && __GNUC__
#define __static_size static
#define __static_size_const static const
#else
#define __static_size
#define __static_size_const
#endif
#endif // !defined(__static_size)

/*!
 * @brief
 * Pass -DIMAGE4_STRIP_AVAILABILITY=1 if the build environment is picking up a
 * definition of API_AVAILABLE from somewhere, e.g. an old shim header or from
 * inappropriately-injected header search paths.
 */
#if !defined(API_AVAILABLE) || IMAGE4_STRIP_AVAILABILITY
#undef API_AVAILABLE
#define API_AVAILABLE(...)
#endif

#if XNU_KERNEL_PRIVATE
#if !defined(__IMAGE4_XNU_INDIRECT)
#error "Please include <libkern/image4/dlxk.h> instead of this header"
#endif
#endif

/*!
 * @const IMAGE4_API_AVAILABLE_SPRING_2024
 * APIs which first became available in the Spring 2024 set of releases.
 */
#define IMAGE4_API_AVAILABLE_SPRING_2024 \
	API_AVAILABLE( \
		macos(14.3), \
		ios(17.4), \
		tvos(17.4), \
		watchos(10.4), \
		bridgeos(8.3))

/*!
 * @const IMAGE4_XNU_AVAILABLE_DIRECT
 * API symbol which is available to xnu via the dlxk mechanism.
 */
#if XNU_KERNEL_PRIVATE || IMAGE4_DLXK_AVAILABILITY
#define IMAGE4_XNU_AVAILABLE_DIRECT(_s) typedef typeof(&_s) _ ## _s ## _dlxk_t
#else
#define IMAGE4_XNU_AVAILABLE_DIRECT(_s)
#endif

/*!
 * @const IMAGE4_XNU_AVAILABLE_INDIRECT
 * API symbol which is accessed through a macro and is available to xnu via the
 * dlxk mechanism.
 */
#if XNU_KERNEL_PRIVATE || IMAGE4_DLXK_AVAILABILITY
#define IMAGE4_XNU_AVAILABLE_INDIRECT(_s) typedef typeof(&_s) _s ## _dlxk_t
#else
#define IMAGE4_XNU_AVAILABLE_INDIRECT(_s)
#endif

#endif // __IMAGE4_API_H
