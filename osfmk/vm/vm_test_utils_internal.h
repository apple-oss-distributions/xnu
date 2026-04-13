/*
 * Copyright (c) 2025 Apple Inc. All rights reserved.
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
#ifndef _VM_VM_TEST_UTILS_INTERNAL_H
#define _VM_VM_TEST_UTILS_INTERNAL_H

#include <vm/vm_map_xnu.h>
#include <mach/vm_types.h>

__BEGIN_DECLS

/*
 * Allocate a 16k-page-size map for testing.
 */
vm_map_t vm_test_alloc_map(void);

/*
 * Allocate a 4k-page-size map for testing.
 */
vm_map_t vm_test_alloc_4k_map(void);

/*
 * Insert an entry of size `(end-start)` into `map` at offset `start`.
 */
vm_map_entry_t vm_test_add_map_entry(vm_map_t map, vm_map_offset_t start, vm_map_offset_t end);

/*
 * Create a constant submap, put within the newly allocated map parent_map.
 * Within the constant submap, the first entry will start at constant_submap_entry_start.
 * That submap will contain nentries entries that are each PAGE_SIZE.
 *
 * The entry in parent_map will be from start to end.
 */
void
setup_constant_submap(vm_map_address_t constant_submap_entry_start, vm_map_address_t start, vm_map_address_t end, int nentries, vm_map_t * parent_map, vm_map_t * submap);

__END_DECLS

#endif /* _VM_VM_TEST_UTILS_INTERNAL_H */
