/*
 * Copyright (c) 2021 Apple Inc. All rights reserved.
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

/*
 *
 *	File: vm/vm_dyld_pager.h
 *
 *      protos and definitions for dyld pager
 */

#ifndef _VM_DYLD_PAGER_H_
#define _VM_DYLD_PAGER_H_

#include <mach/dyld_pager.h>

#ifdef KERNEL_PRIVATE
#include <kern/kern_types.h>
#include <vm/vm_map.h>

#define MWL_MIN_LINK_INFO_SIZE sizeof(struct mwl_info_hdr)
#define MWL_MAX_LINK_INFO_SIZE (64 * 1024 * 1024)   /* just a guess for now, may have to increase */

extern uint32_t dyld_pager_count;
extern uint32_t dyld_pager_count_max;

/*
 * VM call to implement map_with_linking_np() system call.
 */
extern kern_return_t
vm_map_with_linking(
	task_t                  task,
	struct mwl_region       *regions,
	uint32_t                region_cnt,
	void                    *link_info,
	uint32_t                link_info_size,
	memory_object_control_t file_control);

#endif /* KERNEL_PRIVATE */

#endif  /* _VM_DYLD_PAGER_H_ */
