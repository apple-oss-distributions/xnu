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
 * Kernel-private interfaces to link the upward-exported AppleImage4 API. This
 * header serves as an umbrella header to enforce inclusion ordering among its
 * associated headers.
 *
 * This file is intended for use in the xnu project.
 */
#ifndef __IMAGE4_DLXK_H
#define __IMAGE4_DLXK_H

#define __IMAGE4_XNU_INDIRECT 1
#include <image4/image4.h>
#include <image4/types.h>
#include <image4/coprocessor.h>
#include <image4/environment.h>
#include <image4/trust.h>
#include <image4/trust_evaluation.h>
#include <image4/cs/traps.h>

#if XNU_KERNEL_PRIVATE
#include <libkern/image4/interface.h>
#include <libkern/image4/api.h>
#else
#include <image4/dlxk/interface.h>
#endif

__BEGIN_DECLS
OS_ASSUME_NONNULL_BEGIN
OS_ASSUME_PTR_ABI_SINGLE_BEGIN

#pragma mark Definitions
/*!
 * @const IMAGE4_DLXK_VERSION
 * The API version of the upward-ish-linked kernel interface structure. The
 * kernel cannot directly call into kext exports, so the kext instead provides a
 * structure of function pointers and registers that structure with the kernel
 * at boot.
 */
#define IMAGE4_DLXK_VERSION (0u)

#pragma mark KPI
/*!
 * @function image4_dlxk_link
 * Links the interface exported by the AppleImage4 kext via the given structure
 * so that the kernel-proper can use it via the trampolines provided in
 * image4/dlxk/api.h.
 *
 * @param dlxk
 * The interface to link.
 *
 * @discussion
 * This routine may only be called once and must be called prior to machine
 * lockdown.
 */
OS_EXPORT OS_NONNULL1
void
image4_dlxk_link(const image4_dlxk_interface_t *dlxk);

/*!
 * @function image4_dlxk_get
 * Returns the interface structure which was linked at boot.
 *
 * @param v
 * The minimum required version. If the structure's version does not satisfy
 * this constraint, NULL is returned.
 *
 * @result
 * The interface structure which was linked at boot. If no structure was
 * registered at boot, or if the registered structure's version is less than
 * the version specified, NULL is returned.
 */
OS_EXPORT OS_WARN_RESULT
const image4_dlxk_interface_t *_Nullable
image4_dlxk_get(image4_struct_version_t v);

OS_ASSUME_PTR_ABI_SINGLE_END
OS_ASSUME_NONNULL_END
__END_DECLS

#endif // __IMAGE4_DLXK_H
