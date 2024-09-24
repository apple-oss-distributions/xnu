/*
 * Copyright © 2017-2024 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
/*!
 * @header
 * Common header for Image4 trust evaluation API.
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
#define IMAGE4_API_VERSION (20240503u)

/*!
 * @const IMAGE4_RESTRICTED_API_VERSION
 * The restricted API version of the library. Restricted interfaces are
 *
 *     1. likely to be hacks,
 *     2. not guaranteed to function correctly in all contexts, and
 *     3. subject to a pre-arranged contract for deprecation and removal.
 *
 * The availability documentation for each restricted API will indicate the
 * expiration version.
 */
#define IMAGE4_RESTRICTED_API_VERSION (1002u)

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

#if !defined(__ASSUME_PTR_ABI_SINGLE_BEGIN)
#if __has_include(<ptrcheck.h>)
#include <ptrcheck.h>
#define __ASSUME_PTR_ABI_SINGLE_BEGIN __ptrcheck_abi_assume_single()
#define __ASSUME_PTR_ABI_SINGLE_END __ptrcheck_abi_assume_unsafe_indexable()
#else
#define __ASSUME_PTR_ABI_SINGLE_BEGIN
#define __ASSUME_PTR_ABI_SINGLE_END
#endif
#endif

#if defined(__counted_by_or_null)
#define __static_array_or_null(_S) _Nullable __counted_by_or_null(_S)
#else
#define __counted_by_or_null(_S)
#define __static_array_or_null(_S) _Nullable _S
#endif

#if !defined(__sized_by_or_null)
#define __sized_by_or_null(_S)
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
 * @const IMAGE4_API_AVAILABLE_FALL_2024
 * APIs which first became available in the Fall 2024 set of releases.
 */
#define IMAGE4_API_AVAILABLE_FALL_2024 \
	API_AVAILABLE( \
		macos(15.0), \
		ios(18.0), \
		tvos(18.0), \
		watchos(11.0), \
		bridgeos(9.0))

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

/*!
 * @const IMAGE4_XNU_RETIRED_DIRECT
 * API symbol which has been retired.
 */
#if XNU_KERNEL_PRIVATE || IMAGE4_DLXK_AVAILABILITY
#define IMAGE4_XNU_RETIRED_DIRECT(_s) typedef void * _ ## _s ## _dlxk_t
#else
#define IMAGE4_XNU_RETIRED_DIRECT(_s)
#endif

/*!
 * @const IMAGE4_XNU_RETIRED_INDIRECT
 * API symbol which has been retired.
 */
#if XNU_KERNEL_PRIVATE || IMAGE4_DLXK_AVAILABILITY
#define IMAGE4_XNU_RETIRED_INDIRECT(_s) typedef void * _s ## _dlxk_t
#else
#define IMAGE4_XNU_RETIRED_INDIRECT(_s)
#endif

/*!
 * @const image4_call_restricted
 * Calls a restricted API.
 */
#if IMAGE4_RESTRICTED_API
#define image4_call_restricted(_s, ...) image4_ ## _s(__VA_ARGS__)
#else
#define image4_call_restricted(_s, ...) \
	image4_ ## _s(IMAGE4_RESTRICTED_API_VERSION, ## __VA_ARGS__)
#endif

#endif // __IMAGE4_API_H
