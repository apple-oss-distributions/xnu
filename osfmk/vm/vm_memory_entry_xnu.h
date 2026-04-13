/*
 * Copyright (c) 2023 Apple Inc. All rights reserved.
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

#ifndef _VM_VM_MEMORY_ENTRY_XNU_H_
#define _VM_VM_MEMORY_ENTRY_XNU_H_

#ifdef XNU_KERNEL_PRIVATE
#include <mach/port.h>
#include <mach_debug/mach_debug_types.h>
#include <vm/vm_memory_entry.h>

__BEGIN_DECLS

extern void mach_memory_entry_port_release(ipc_port_t port);
extern vm_named_entry_t mach_memory_entry_from_port(ipc_port_t port);
extern struct vm_named_entry *mach_memory_entry_allocate(ipc_port_t *user_handle_p);

extern memory_object_size_t mach_memory_entry_size(ipc_port_t user_handle);

extern void mach_memory_entry_describe(vm_named_entry_t named_entry, kobject_description_t desc);

extern kern_return_t
mach_memory_object_control_memory_entry_64(
	memory_object_control_t control,
	memory_object_offset_t  offset,
	memory_object_size_t    size,
	vm_prot_t               permission,
	ipc_port_t              *entry_handle);

__END_DECLS
#endif /* XNU_KERNEL_PRIVATE */
#endif  /* _VM_VM_MEMORY_ENTRY_XNU_H_ */
