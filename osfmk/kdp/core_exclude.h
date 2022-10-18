/*
 * Copyright (c) 2021 Apple Computer, Inc. All rights reserved.
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

#ifndef _CORE_EXCLUDE_H_
#define _CORE_EXCLUDE_H_

#include <mach/kern_return.h>
#include <mach/vm_types.h>
#include <sys/cdefs.h>

__BEGIN_DECLS

#if KERNEL_PRIVATE

/*
 * Excludes a given memory region from the kernel coredump. This is recommended
 * for any sensitive data or data which is not expected to be necessary for
 * debugging.
 *
 * The address and size of the region must be page-aligned, the size must be
 * non-zero, and the addition of the address and size must not overflow.
 *
 * Note that you may need to call this function multiple times if the
 * underlying memory is shared.
 */
kern_return_t
kdp_core_exclude_region(vm_offset_t addr, vm_size_t size);

/*
 * Unexcludes a given memory region from the kernel coredump.
 *
 * The address and size of the region must match a currently excluded region.
 */
kern_return_t
kdp_core_unexclude_region(vm_offset_t addr, vm_size_t size);

#endif /* KERNEL_PRIVATE */

__END_DECLS

#endif /* _CORE_EXCLUDE_H_ */
