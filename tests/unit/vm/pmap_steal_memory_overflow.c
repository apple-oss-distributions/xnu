/*
 * Copyright (c) 2000-2024 Apple Inc. All rights reserved.
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

#include "mach/arm/boolean.h"
#include "mocks/osfmk/unit_test_utils.h"
#include <darwintest.h>
#include <vm/pmap.h>

#define UT_MODULE osfmk
T_GLOBAL_META(
	T_META_NAMESPACE("xnu.unit.vm.pmap_steal_memory"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"),
	T_META_RUN_CONCURRENTLY(true)
	);

extern void *pmap_steal_memory_internal(
	vm_size_t size,
	vm_size_t alignment,
	boolean_t might_free,
	unsigned int flags,
	pmap_mapping_type_t mapping_type);

T_DECL(size_overflow, "make sure we panic when size is greater than UINT64_MAX - 8")
{
	vm_size_t size = UINT64_MAX - 7;
	vm_size_t alignment = 0;
	boolean_t might_free = false;
	unsigned int flags = 0;
	pmap_mapping_type_t mapping_type = PMAP_MAPPING_TYPE_INFER;
	T_ASSERT_PANIC({
		pmap_steal_memory_internal(
			size,
			alignment,
			might_free,
			flags,
			mapping_type);
	}, "should panic because of size overflow");
}

T_DECL(addr_plus_size_overflow, "make sure we panic when size is so big that addr + size will overflow")
{
	vm_size_t size = UINT64_MAX - 8;
	vm_size_t alignment = 0;
	boolean_t might_free = false;
	unsigned int flags = 0;
	pmap_mapping_type_t mapping_type = PMAP_MAPPING_TYPE_INFER;
	T_ASSERT_PANIC({
		pmap_steal_memory_internal(
			size,
			alignment,
			might_free,
			flags,
			mapping_type);
	}, "should panic because of size overflow");
}
