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

#ifndef _VM_VM_FAULT_XNU_H_
#define _VM_VM_FAULT_XNU_H_

#ifdef XNU_KERNEL_PRIVATE

#include <sys/cdefs.h>
#include <vm/vm_fault.h>

__BEGIN_DECLS

#ifdef  MACH_KERNEL_PRIVATE

#include <vm/vm_page.h>
#include <vm/vm_object_xnu.h>
#include <vm/vm_map_xnu.h>

extern void vm_fault_init(void);

/* exported kext version */
extern kern_return_t vm_fault_external(
	vm_map_t        map,
	vm_map_offset_t vaddr,
	vm_prot_t       fault_type,
	boolean_t       change_wiring,
	int             interruptible,
	pmap_t          caller_pmap,
	vm_map_offset_t caller_pmap_addr);


extern vm_offset_t kdp_lightweight_fault(
	vm_map_t map,
	vm_offset_t cur_target_addr,
	bool multi_cpu);

#endif  /* MACH_KERNEL_PRIVATE */

/*
 * Disable vm faults on the current thread.
 */
extern void vm_fault_disable(void);

/*
 * Enable vm faults on the current thread.
 */
extern void vm_fault_enable(void);

/*
 * Return whether vm faults are disabled on the current thread.
 */
extern bool vm_fault_get_disabled(void);

extern boolean_t NEED_TO_HARD_THROTTLE_THIS_TASK(void);

__END_DECLS

#endif /* XNU_KERNEL_PRIVATE */
#endif  /* _VM_VM_FAULT_XNU_H_ */
