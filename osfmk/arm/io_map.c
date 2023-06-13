/*
 * Copyright (c) 2007 Apple Inc. All rights reserved.
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
 * Mach Operating System Copyright (c) 1991,1990 Carnegie Mellon University
 * All Rights Reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright notice
 * and this permission notice appear in all copies of the software,
 * derivative works or modified versions, and any portions thereof, and that
 * both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS" CONDITION.
 * CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR ANY DAMAGES
 * WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 * Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 * School of Computer Science Carnegie Mellon University Pittsburgh PA
 * 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie Mellon the
 * rights to redistribute these changes.
 */
/*
 */

#include <mach/vm_param.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <arm/pmap.h>
#include <san/kasan.h>

extern vm_offset_t virtual_space_start;     /* Next available kernel VA */

#define IO_MAP_SIZE            (8ul << 20)

__startup_data static struct mach_vm_range io_range;
static SECURITY_READ_ONLY_LATE(vm_map_t) io_submap;
KMEM_RANGE_REGISTER_STATIC(io_submap, &io_range, IO_MAP_SIZE);

__startup_func
static void
io_map_init(void)
{
	vm_map_will_allocate_early_map(&io_submap);
	io_submap = kmem_suballoc(kernel_map, &io_range.min_address, IO_MAP_SIZE,
	    VM_MAP_CREATE_NEVER_FAULTS | VM_MAP_CREATE_DISABLE_HOLELIST,
	    VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, KMS_PERMANENT | KMS_NOFAIL,
	    VM_KERN_MEMORY_IOKIT).kmr_submap;
}
STARTUP(KMEM, STARTUP_RANK_LAST, io_map_init);

/*
 * Allocate and map memory for devices that may need to be mapped before
 * Mach VM is running. Allows caller to specify mapping protection
 */
vm_offset_t
io_map(
	vm_map_offset_t         phys_addr,
	vm_size_t               size,
	unsigned int            flags,
	vm_prot_t               prot,
	bool                    unmappable)
{
	vm_offset_t start_offset = phys_addr - trunc_page(phys_addr);
	vm_offset_t alloc_size   = round_page(size + start_offset);
	vm_offset_t start;

	phys_addr = trunc_page(phys_addr);

	if (startup_phase < STARTUP_SUB_KMEM) {
		/*
		 * VM is not initialized.  Grab memory.
		 */
		start = virtual_space_start;
		virtual_space_start += round_page(size);

		assert(flags == VM_WIMG_WCOMB || flags == VM_WIMG_IO);

		if (flags == VM_WIMG_WCOMB) {
			pmap_map_bd_with_options(start, phys_addr,
			    phys_addr + alloc_size, prot, PMAP_MAP_BD_WCOMB);
		} else {
			pmap_map_bd(start, phys_addr, phys_addr + alloc_size, prot);
		}
#if KASAN
		kasan_notify_address(start + start_offset, size);
#endif
	} else {
		kma_flags_t kmaflags = KMA_NOFAIL | KMA_PAGEABLE;

		if (unmappable) {
			kmaflags |= KMA_DATA;
		} else {
			kmaflags |= KMA_PERMANENT;
		}

		kmem_alloc(unmappable ? kernel_map : io_submap,
		    &start, alloc_size, kmaflags, VM_KERN_MEMORY_IOKIT);
		pmap_map(start, phys_addr, phys_addr + alloc_size, prot, flags);
	}
	return start + start_offset;
}
