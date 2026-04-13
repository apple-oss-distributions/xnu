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
#pragma once

#include <Availability.h>
#include <mach/vm_statistics.h>
#include <os/base.h>
#include <sys/cdefs.h>

__BEGIN_DECLS

#if PRIVATE
#if !KERNEL
///
/// Return a human-readable description for a given VM user tag.
///
/// - Parameters:
///   - tag: A VM tag (`VM_MEMORY_*`)
///
/// - Returns: A string literal description of the tag
///
__SPI_AVAILABLE(macos(26.0), ios(26.0), watchos(26.0), tvos(26.0), visionos(26.0), bridgeos(26.0))
OS_EXPORT
const char *mach_vm_tag_describe(unsigned int tag);
#endif /* !KERNEL */
#endif /* PRIVATE */

__END_DECLS
