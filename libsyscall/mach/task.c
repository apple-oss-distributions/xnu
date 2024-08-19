/*
 * Copyright (c) 2020 Apple Inc. All rights reserved.
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

#undef _task_user_
#include <TargetConditionals.h>
#include <stdbool.h>

#include <mach/kern_return.h>
#include <mach/mach_param.h>
#include <mach/mach_port.h>
#include <mach/message.h>
#include <mach/mig_errors.h>
#include <mach/task_internal.h>
#include <mach/vm_map.h>

extern mach_port_t      mach_task_self_;

boolean_t
mach_task_is_self(task_name_t task)
{
	boolean_t is_self;
	kern_return_t kr;

	if (task == mach_task_self_) {
		return TRUE;
	}

	kr = _kernelrpc_mach_task_is_self(task, &is_self);

	return kr == KERN_SUCCESS && is_self;
}


kern_return_t
mach_ports_register(
	task_t                  target_task,
	mach_port_array_t       init_port_set,
	mach_msg_type_number_t  init_port_setCnt)
{
	mach_port_t array[TASK_PORT_REGISTER_MAX] = { };
	kern_return_t kr;

	if (init_port_setCnt > TASK_PORT_REGISTER_MAX) {
		return KERN_INVALID_ARGUMENT;
	}

	for (mach_msg_type_number_t i = 0; i < init_port_setCnt; i++) {
		array[i] = init_port_set[i];
	}

	kr = _kernelrpc_mach_ports_register3(target_task, array[0], array[1], array[2]);
	return kr;
}

kern_return_t
mach_ports_lookup(
	task_t                  target_task,
	mach_port_array_t      *init_port_set,
	mach_msg_type_number_t *init_port_setCnt)
{
	vm_size_t size = TASK_PORT_REGISTER_MAX * sizeof(mach_port_t);
	mach_port_array_t array;
	vm_address_t addr = 0;
	kern_return_t kr;

	kr = vm_allocate(target_task, &addr, size, VM_FLAGS_ANYWHERE);
	array = (mach_port_array_t)addr;
	if (kr != KERN_SUCCESS) {
		return kr;
	}


	kr = _kernelrpc_mach_ports_lookup3(target_task,
	    &array[0], &array[1], &array[2]);
	if (kr != KERN_SUCCESS) {
		vm_deallocate(target_task, addr, size);
		return kr;
	}

	*init_port_set = array;
	*init_port_setCnt = TASK_PORT_REGISTER_MAX;
	return KERN_SUCCESS;
}
