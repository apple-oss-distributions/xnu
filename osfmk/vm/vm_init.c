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
/*
 * @OSF_COPYRIGHT@
 */
/*
 * Mach Operating System
 * Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University
 * All Rights Reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */
/*
 */
/*
 *	File:	vm/vm_init.c
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young
 *	Date:	1985
 *
 *	Initialize the Virtual Memory subsystem.
 */

#include <mach/machine/vm_types.h>
#include <mach/vm_map.h>
#include <kern/startup.h>
#include <kern/zalloc_internal.h>
#include <kern/kext_alloc.h>
#include <sys/kdebug.h>
#include <vm/vm_object.h>
#include <vm/vm_map_internal.h>
#include <vm/vm_page.h>
#include <vm/vm_kern.h>
#include <vm/memory_object.h>
#include <vm/vm_fault.h>
#include <vm/vm_init.h>

#include <pexpert/pexpert.h>

#include <vm/vm_protos.h>

const vm_offset_t vm_min_kernel_address = VM_MIN_KERNEL_AND_KEXT_ADDRESS;
const vm_offset_t vm_max_kernel_address = VM_MAX_KERNEL_ADDRESS;

TUNABLE(bool, iokit_iomd_setownership_enabled,
    "iokit_iomd_setownership_enabled", true);

static inline void
vm_mem_bootstrap_log(const char *message)
{
//	kprintf("vm_mem_bootstrap: %s\n", message);
	kernel_debug_string_early(message);
}

/*
 *	vm_mem_bootstrap initializes the virtual memory system.
 *	This is done only by the first cpu up.
 */
__startup_func
void
vm_mem_bootstrap(void)
{
	vm_offset_t start, end;

	/*
	 *	Initializes resident memory structures.
	 *	From here on, all physical memory is accounted for,
	 *	and we use only virtual addresses.
	 */
	vm_mem_bootstrap_log("vm_page_bootstrap");
	vm_page_bootstrap(&start, &end);

	/*
	 *	Initialize other VM packages
	 */

	vm_mem_bootstrap_log("zone_bootstrap");
	zone_bootstrap();

	vm_mem_bootstrap_log("vm_object_bootstrap");
	vm_object_bootstrap();

	vm_retire_boot_pages();

	vm_mem_bootstrap_log("vm_map_init");
	vm_map_init();

	vm_mem_bootstrap_log("kmem_init");
	kmem_init(start, end);

	kernel_startup_initialize_upto(STARTUP_SUB_KMEM);

	vm_mem_bootstrap_log("pmap_init");
	pmap_init();

	vm_mem_bootstrap_log("vm_fault_init");
	vm_fault_init();

	kernel_startup_initialize_upto(STARTUP_SUB_ZALLOC);

	vm_page_delayed_work_init_ctx();

	if (iokit_iomd_setownership_enabled) {
		kprintf("IOKit IOMD setownership ENABLED\n");
	} else {
		kprintf("IOKit IOMD setownership DISABLED\n");
	}
}
