/*
 * Copyright (c) 2024 Apple Inc. All rights reserved.
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

#ifdef  XNU_KERNEL_PRIVATE

#ifndef _MACH_MEMORY_ENTRY_
#define _MACH_MEMORY_ENTRY_

__BEGIN_DECLS

#if XNU_PLATFORM_MacOSX
extern kern_return_t mach_memory_entry_page_op(
	ipc_port_t              entry_port,
	vm_object_offset_ut     offset,
	int                     ops,
	ppnum_t                 *phys_entry,
	int                     *flags);

extern kern_return_t mach_memory_entry_range_op(
	ipc_port_t              entry_port,
	vm_object_offset_ut     offset_beg,
	vm_object_offset_ut     offset_end,
	int                     ops,
	int                     *range);
#endif /* XNU_PLATFORM_MacOSX */

/*
 *	Routine:	vm_convert_port_to_copy_object
 *	Purpose:
 *		Convert from a port specifying a named entry
 *              backed by a copy map to the VM object itself.
 *              Returns NULL if the port does not refer to an copy map-backed named entry.
 *	Conditions:
 *		Nothing locked.
 */
extern vm_object_t vm_convert_port_to_copy_object(
	ipc_port_t      port);

__END_DECLS

#endif /* _MACH_MEMORY_ENTRY_ */
#endif /* XNU_KERNEL_PRIVATE */
