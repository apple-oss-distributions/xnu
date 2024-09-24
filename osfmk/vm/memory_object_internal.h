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

#ifndef _VM_MEMORY_OBJECT_INTERNAL_H_
#define _VM_MEMORY_OBJECT_INTERNAL_H_

#ifdef XNU_KERNEL_PRIVATE

#include <vm/memory_object_xnu.h>

extern memory_object_default_t memory_manager_default;

__private_extern__
memory_object_default_t memory_manager_default_reference(void);

__private_extern__
kern_return_t           memory_manager_default_check(void);

__private_extern__
memory_object_control_t memory_object_control_allocate(
	vm_object_t             object);

__private_extern__
void                    memory_object_control_collapse(
	memory_object_control_t *control,
	vm_object_t             object);

__private_extern__
vm_object_t             memory_object_control_to_vm_object(
	memory_object_control_t control);
__private_extern__
vm_object_t             memory_object_to_vm_object(
	memory_object_t mem_obj);

extern void memory_object_control_disable(
	memory_object_control_t *control);

extern boolean_t        memory_object_is_shared_cache(
	memory_object_control_t         control);

#endif /* XNU_KERNEL_PRIVATE */

#endif  /* _VM_MEMORY_OBJECT_INTERNAL_H_ */
