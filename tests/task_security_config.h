/*
 * Copyright (c) 2025 Apple Computer, Inc. All rights reserved.
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
#ifndef TASK_SECURITY_CONFIG_H
#define TASK_SECURITY_CONFIG_H

#include <stdint.h>

/*
 * PT: Adapted from the xnu definition in osfmk/kern/task.h.
 */
struct task_security_config {
	uint16_t hardened_heap: 1,
	    tpro: 1,
	    reserved: 1,
	    platform_restrictions_version: 3,
	    script_restrictions: 1,
	    ipc_containment_vessel: 1,
	    guard_objects: 1;
	uint8_t hardened_process_version;
};

__options_closed_decl(ipc_space_policy_t, uint32_t, {
	IPC_SPACE_POLICY_INVALID       = 0x0000,

	/* Security level */
	IPC_SPACE_POLICY_DEFAULT       = 0x0001, /* MACH64_POLICY_DEFAULT */
	IPC_SPACE_POLICY_ENHANCED      = 0x0002,
	IPC_SPACE_POLICY_PLATFORM      = 0x0004,
	IPC_SPACE_POLICY_CONTAINED     = 0x0008,
	IPC_SPACE_POLICY_KERNEL        = 0x0010,

	/* flags to turn off security */
#if XNU_TARGET_OS_OSX
	IPC_SPACE_POLICY_SIMULATED     = 0x0020,
#else
	IPC_SPACE_POLICY_SIMULATED     = 0x0000,
#endif
#if CONFIG_ROSETTA
	IPC_SPACE_POLICY_TRANSLATED    = 0x0040,
#else
	IPC_SPACE_POLICY_TRANSLATED    = 0x0000,
#endif
#if XNU_TARGET_OS_OSX
	IPC_SPACE_POLICY_OPTED_OUT     = 0x0080,
#else
	IPC_SPACE_POLICY_OPTED_OUT     = 0x0000,
#endif


	IPC_SPACE_POLICY_MASK          = (
		IPC_SPACE_POLICY_DEFAULT |
		IPC_SPACE_POLICY_ENHANCED |
		IPC_SPACE_POLICY_PLATFORM |
		IPC_SPACE_POLICY_CONTAINED |
		IPC_SPACE_POLICY_KERNEL |
		IPC_SPACE_POLICY_SIMULATED |
		IPC_SPACE_POLICY_TRANSLATED |
		IPC_SPACE_POLICY_OPTED_OUT),


/* platform restrictions Versioning Levels */
	IPC_SPACE_POLICY_ENHANCED_V0 = 0x100,   /* DEPRECATED - includes macos hardened runtime */
	IPC_SPACE_POLICY_ENHANCED_V1 = 0x200,   /* ES features exposed to 3P in FY2024 release */
	IPC_SPACE_POLICY_ENHANCED_V2 = 0x300,   /* ES features exposed to 3P in FY2025 release */
	IPC_SPACE_POLICY_ENHANCED_V3 = 0x400,   /* ES features exposed to 3P in FY2026 release */
	IPC_SPACE_POLICY_ENHANCED_VERSION_MASK = (
		IPC_SPACE_POLICY_ENHANCED_V0 |
		IPC_SPACE_POLICY_ENHANCED_V1 |
		IPC_SPACE_POLICY_ENHANCED_V2 |
		IPC_SPACE_POLICY_ENHANCED_V3
		),
});

#define HARDENED_PROCESS_VERSION_LATEST 2

#endif /* TASK_SECURITY_CONFIG_H */
