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

#ifdef XNU_KERNEL_PRIVATE
#endif /* XNU_KERNEL_PRIVATE */

#ifdef KERNEL_PRIVATE
#ifndef __ASSEMBLER__
/**
 * Block type for checking if a binary has a specific entitlement.
 *
 * This callback is used by ml_satisfies_x86_64_requirements() to verify
 * that a binary being loaded has the necessary entitlements for x86-64
 * emulation features. The caller provides this block to abstract the
 * entitlement lookup mechanism.
 *
 * The block shall take an entitlement identifier (e.g.,
 * "com.apple.developer.cross-architecture-support"), and return true iff the
 * binary has the entitlement given to it.
 */
typedef bool (^ml_entitlement_check)(char const *);

bool
ml_satisfies_x86_64_requirements(ml_entitlement_check check_ent);
#endif /* __ASSEMBLER__ */
#endif /* KERNEL_PRIVATE */
