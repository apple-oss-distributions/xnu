/*
 * Copyright (c) 2000-2020 Apple Inc. All rights reserved.
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

#ifndef _KERN_TASK_REF_H_
#define _KERN_TASK_REF_H_

#include <mach/mach_types.h>

#include <stdint.h>

#if MACH_KERNEL_PRIVATE


extern void task_ref_init(void);

extern void task_ref_count_fini(task_t);
extern kern_return_t task_ref_count_init(task_t);

extern void task_reference_external(task_t task);
extern void task_deallocate_external(task_t task);

#endif /* MACH_KERNEL_PRIVATE */

#if XNU_KERNEL_PRIVATE

#include <os/refcnt.h>

__BEGIN_DECLS

extern struct os_refgrp task_external_refgrp;

__options_closed_decl(task_grp_t, uint32_t, {
	TASK_GRP_KERNEL,
	TASK_GRP_INTERNAL,
	TASK_GRP_MIG,
	TASK_GRP_EXTERNAL,

	TASK_GRP_COUNT,
});

extern void task_reference_grp(task_t, task_grp_t);
extern void task_deallocate_grp(task_t, task_grp_t);

#define task_reference_mig(task) task_reference_grp(task, TASK_GRP_MIG)
#define task_deallocate_mig(task) task_deallocate_grp(task, TASK_GRP_MIG)

/*
 * Exported symbols get mapped to their _external versions. Internal consumers of
 * these functions need to pick up the _kernel version.
 */

#define task_reference(task) task_reference_grp(task, TASK_GRP_KERNEL)
#define task_deallocate(task) task_deallocate_grp(task, TASK_GRP_KERNEL)

#define convert_task_to_port(task) convert_task_to_port_kernel(task)
#define convert_task_read_to_port(task) convert_task_read_to_port_kernel(task)

#define port_name_to_task(name) port_name_to_task_kernel(name)

#define convert_port_to_task_suspension_token(port) convert_port_to_task_suspension_token_kernel(port)
#define convert_task_suspension_token_to_port(token) convert_task_suspension_token_to_port_kernel(token)

#define task_resume2(token) task_resume2_kernel(token)
#define task_suspend2(task, token) task_suspend2_kernel(task, token)

__END_DECLS

#else /* XNU_KERNEL_PRIVATE */

__BEGIN_DECLS

extern void             task_reference(task_t);
extern void             task_deallocate(task_t);

__END_DECLS
#endif /* XNU_KERNEL_PRIVATE */

#endif /*_KERN_TASK_REF_H_ */
