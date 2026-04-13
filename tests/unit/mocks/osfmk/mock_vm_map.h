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

#pragma once

#include "mocks/mock_dynamic.h"
#include <vm/vm_map_xnu.h>
#include <vm/vm_map.h>
#include <vm/vm_map_lock_internal.h>

T_MOCK_DECLARE(
	kern_return_t,
	vm_map_find_entry_sh_locked,
	(
		vm_map_find_lock_ctx_t  vml_ctx,
		vm_map_t               * map,
		vm_map_address_t        addr,
		vmrl_find_sh_flags_t    flags));

T_MOCK_DECLARE(
	void,
	vm_map_found_entry_sh_unlock,
	(
		vm_map_find_lock_ctx_t    vml_ctx,
		vm_map_t                 * map));
