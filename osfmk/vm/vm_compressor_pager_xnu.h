/*
 * Copyright (c) 2013 Apple Inc. All rights reserved.
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

#ifndef _VM_VM_COMPRESSOR_PAGER_XNU_H_
#define _VM_VM_COMPRESSOR_PAGER_XNU_H_

#include <mach/mach_types.h>
#include <kern/kern_types.h>
#include <vm/vm_external.h>

__options_decl(vm_compressor_options_t, uint32_t, {
	C_DONT_BLOCK            = 0x00000001, /* vm_fault tells the compressor not to read from swap file */
	C_KEEP                  = 0x00000002, /* vm_fault tells the compressor to not remove the data from the segment after decompress*/
	C_KDP                   = 0x00000004, /* kdp fault tells the compressor to not do locking */
	C_PAGE_UNMODIFIED       = 0x00000008,
	C_KDP_MULTICPU          = 0x00000010,
});

extern kern_return_t vm_compressor_pager_get(
	memory_object_t         mem_obj,
	memory_object_offset_t  offset,
	ppnum_t                 ppnum,
	int                     *my_fault_type,
	vm_compressor_options_t flags,
	int                     *compressed_count_delta_p);


#if CONFIG_TRACK_UNMODIFIED_ANON_PAGES
extern uint64_t compressor_ro_uncompressed;
extern uint64_t compressor_ro_uncompressed_total_returned;
extern uint64_t compressor_ro_uncompressed_skip_returned;
extern uint64_t compressor_ro_uncompressed_get;
extern uint64_t compressor_ro_uncompressed_put;
extern uint64_t compressor_ro_uncompressed_swap_usage;
#endif /* CONFIG_TRACK_UNMODIFIED_ANON_PAGES */

extern unsigned int vm_compressor_pager_get_count(memory_object_t mem_obj);

#endif  /* _VM_VM_COMPRESSOR_PAGER_XNU_H_ */

#endif  /* XNU_KERNEL_PRIVATE */
