/*
 * Copyright (c) 2025 Apple Inc. All rights reserved.
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

#include <TargetConditionals.h>
#include <machine/cpu_capabilities.h>

#if defined(__arm64e__)
#if __has_feature(ptrauth_calls)
#include <ptrauth.h>

#define COMMPAGE_PFZ_BASE_AUTH_KEY ptrauth_key_process_independent_code
#define COMMPAGE_PFZ_FN_AUTH_KEY ptrauth_key_function_pointer
#define COMMPAGE_PFZ_BASE_DISCRIMINATOR ptrauth_string_discriminator("pfz")

#define COMMPAGE_PFZ_BASE_PTR __ptrauth(COMMPAGE_PFZ_BASE_AUTH_KEY, 1, COMMPAGE_PFZ_BASE_DISCRIMINATOR)

#define SIGN_PFZ_FUNCTION_PTR(ptr) ptrauth_sign_unauthenticated(ptr, COMMPAGE_PFZ_FN_AUTH_KEY, 0)

#else /* __has_feature(ptrauth_calls) */

#define COMMPAGE_PFZ_BASE_AUTH_KEY 0
#define COMMPAGE_PFZ_FN_AUTH_KEY 0
#define COMMPAGE_PFZ_BASE_DISCRIMINATOR 0

#define COMMPAGE_PFZ_BASE_PTR

#define SIGN_PFZ_FUNCTION_PTR(ptr) ptr
#endif /* __has_feature(ptrauth_calls) */

__attribute__ ((visibility("hidden")))
extern void *COMMPAGE_PFZ_BASE_PTR commpage_pfz_base;

#elif defined(__arm64__)

#define COMMPAGE_PFZ_BASE_PTR
#define SIGN_PFZ_FUNCTION_PTR(ptr) ptr

__attribute__ ((visibility("hidden")))
extern void *COMMPAGE_PFZ_BASE_PTR commpage_pfz_base;

#endif /* defined(__arm64e__) */
