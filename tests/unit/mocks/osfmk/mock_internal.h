/*
 * Copyright (c) 2000-2025 Apple Inc. All rights reserved.
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

#pragma once
#include "mocks/std_safe.h"
#include "mocks/mock_dynamic.h"

#include <mach/kern_return.h>
#include <mach/vm_types.h>

T_MOCK_DECLARE(vm_offset_t, ml_io_map_wcomb, (vm_offset_t phys_addr, vm_size_t size));
T_MOCK_DECLARE(unsigned int, ml_get_cpu_number_local, (void));
T_MOCK_DECLARE(char *, PE_boot_args, (void));

T_MOCK_DECLARE(int, get_system_inshutdown, (void));

#ifdef copyout
#undef copyout
#endif
T_MOCK_DECLARE(int, copyout, (const void *kaddr, user_addr_t udaddr, size_t len));

T_MOCK_DECLARE(size_t, kernel_func1, (int a, char b));
T_MOCK_DECLARE(size_t, kernel_func2, (int a, char b));
T_MOCK_DECLARE(size_t, kernel_func3, (int a, char b));
T_MOCK_DECLARE(size_t, kernel_func4, (int a, char b));
T_MOCK_DECLARE(size_t, kernel_func5, (int a, char b));
T_MOCK_DECLARE(void, kernel_func6, (int a, char b));
T_MOCK_DECLARE(size_t, kernel_func7, (int a, char b));
T_MOCK_DECLARE(void, kernel_func8, (int a, char b));
T_MOCK_DECLARE(size_t, kernel_func10, (int a, char b));

T_MOCK_DECLARE(bool,
developer_mode_state,
(void));

T_MOCK_DECLARE(bool,
csm_enabled,
(void));

T_MOCK_DECLARE(void,
bzero_phys,
(addr64_t src,
vm_size_t bytes));

T_MOCK_DECLARE(void, os_log_with_args, (
	void* oslog,
	uint8_t type,
	const char *fmt,
	va_list args,
	void *addr));
