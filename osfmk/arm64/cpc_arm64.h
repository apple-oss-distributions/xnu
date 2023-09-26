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
#include <kern/cpc.h>

__enum_closed_decl(cpc_event_policy_t, unsigned int, {
	CPC_EVPOL_DENY_ALL = 0,
	CPC_EVPOL_ALLOW_ALL,
	CPC_EVPOL_RESTRICT_TO_KNOWN,
#if CPC_INSECURE
	CPC_EVPOL_DEFAULT = CPC_EVPOL_ALLOW_ALL,
#else // CPC_INSECURE
	CPC_EVPOL_DEFAULT = CPC_EVPOL_RESTRICT_TO_KNOWN,
#endif // !CPC_INSECURE
});

cpc_event_policy_t cpc_get_event_policy(void);

/// Change how event restrictions are applied.
///
/// - Parameters:
///   - new_policy: The event policy to start applying indefinitely.
void cpc_set_event_policy(cpc_event_policy_t new_policy);
