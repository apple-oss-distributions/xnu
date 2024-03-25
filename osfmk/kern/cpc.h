// Copyright (c) 2023 Apple Inc. All rights reserved.
//
// @APPLE_OSREFERENCE_LICENSE_HEADER_START@
//
// This file contains Original Code and/or Modifications of Original Code
// as defined in and that are subject to the Apple Public Source License
// Version 2.0 (the 'License'). You may not use this file except in
// compliance with the License. The rights granted to you under the License
// may not be used to create, or enable the creation or redistribution of,
// unlawful or unlicensed copies of an Apple operating system, or to
// circumvent, violate, or enable the circumvention or violation of, any
// terms of an Apple operating system software license agreement.
//
// Please obtain a copy of the License at
// http://www.opensource.apple.com/apsl/ and read it before using this file.
//
// The Original Code and all software distributed under the License are
// distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
// EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
// INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
// Please see the License for the specific language governing rights and
// limitations under the License.
//
// @APPLE_OSREFERENCE_LICENSE_HEADER_END@

#pragma once

#include <os/base.h>
#include <stdbool.h>
#include <stdint.h>

// Define whether CPC is operating in a secure environment,
// negated to fail closed (on missing `#include`).
#if DEVELOPMENT || DEBUG
#define CPC_INSECURE 1
#else // DEVELOPMENT || DEBUG
#define CPC_INSECURE 0
#endif // DEVELOPMENT || DEBUG

__enum_decl(cpc_hw_t, unsigned int, {
	CPC_HW_CPMU,
	CPC_HW_UPMU,
	CPC_HW_COUNT,
});

__result_use_check bool cpc_hw_acquire(cpc_hw_t hw, const char *owner_name);
bool cpc_hw_in_use(cpc_hw_t hw);
void cpc_hw_release(cpc_hw_t hw, const char *owner_name);

/// Return whether the event encoding `event_selector` is allowed on a given `hw`.
///
/// Parameters:
///   - hw: The allow list to check differs by the hardware.
///   - event_selector: The event encoding to be sent to the hardware.
bool cpc_event_allowed(cpc_hw_t hw, uint16_t event_selector);

/// Return whether CPC is operating securely.
bool cpc_is_secure(void);

#if CPC_INSECURE

/// Change the security enforcement of CPC.
///
/// Parameters:
///   - enforce_security: Whether to enforce secure usage of CPC.
void cpc_change_security(bool enforce_security);

#endif // CPC_INSECURE
