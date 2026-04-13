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

#include <ipc/ipc_policy.h>


#include "mocks/osfmk/mock_ipc.h"
#include "mocks/mock_dynamic.h"

/*
 * This helper sets callback values for ipc_should_apply_policy since the
 * current task does not have IPC space bits configured properly
 * NOTE: it must be a macro because these functions only apply in a scope
 */
#define SET_IPC_POLICY(set_policy)                                         \
  T_MOCK_SET_CALLBACK(ipc_should_apply_policy, bool,                       \
	              (const ipc_space_policy_t current_policy,                \
	               const ipc_space_policy_t requested_level),              \
	              {                                                        \
	                return T_MOCK_ORIGINAL(ipc_should_apply_policy)(       \
	                    IPC_SPACE_POLICY_DEFAULT | (set_policy), requested_level);                      \
	              });
/*
 * TODO: rdar://164185202
 * mock ipc_space_policy so that places which don't use
 * ipc_should_apply_policy get right behavior
 * also consider ipc_convert_msg_options_to_space?
 */

/*
 * Enhanced security versions array for easy iteration
 */
#define ENHANCED_VERSION_COUNT 4
static const ipc_space_policy_t enhanced_versions[ENHANCED_VERSION_COUNT] = {
	IPC_POLICY_ENHANCED_V0,
	IPC_POLICY_ENHANCED_V1,
	IPC_POLICY_ENHANCED_V2,
	IPC_POLICY_ENHANCED_V3
};
