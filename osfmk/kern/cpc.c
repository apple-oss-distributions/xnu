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

#include <kern/cpc.h>
#include <stdbool.h>
#include <kern/assert.h>
#include <kern/debug.h>
#include <os/atomic.h>
#include <os/atomic_private.h>

#if __arm64__
#include <arm64/cpc_arm64.h>
#endif // __arm64__

#pragma mark - Ownership

#if CONFIG_CPU_COUNTERS
static const char * _Atomic _cpc_hw_owners[CPC_HW_COUNT] = { NULL };
#endif // CONFIG_CPU_COUNTERS

__result_use_check bool
cpc_hw_acquire(cpc_hw_t hw, const char *owner_name)
{
#if CONFIG_CPU_COUNTERS
	assert3u(hw, <, CPC_HW_COUNT);
	extern int kpc_get_force_all_ctrs(void);
	if (hw == CPC_HW_CPMU && kpc_get_force_all_ctrs()) {
		return false;
	}
	return os_atomic_cmpxchg(&_cpc_hw_owners[hw], NULL, owner_name, acq_rel);
#else // CONFIG_CPU_COUNTERS
#pragma unused(hw, owner_name)
	return false;
#endif // !CONFIG_CPU_COUNTERS
}

bool
cpc_hw_in_use(cpc_hw_t hw)
{
#if CONFIG_CPU_COUNTERS
	assert3u(hw, <, CPC_HW_COUNT);
	return os_atomic_load(&_cpc_hw_owners[hw], acquire) != NULL;
#else // CONFIG_CPU_COUNTERS
#pragma unused(hw)
	return false;
#endif // !CONFIG_CPU_COUNTERS
}

void
cpc_hw_release(cpc_hw_t hw, const char *owner_name)
{
#if CONFIG_CPU_COUNTERS
	assert3u(hw, <, CPC_HW_COUNT);
	if (!os_atomic_cmpxchg(&_cpc_hw_owners[hw], owner_name, NULL, acq_rel)) {
		panic("CPC: unpaired HW release: %s on %u", owner_name, hw);
	}
#else // CONFIG_CPU_COUNTERS
#pragma unused(hw, owner_name)
#endif // !CONFIG_CPU_COUNTERS
}

bool
cpc_is_secure(void)
{
#if CONFIG_CPU_COUNTERS
#if __arm64__
	cpc_event_policy_t policy = cpc_get_event_policy();
	return policy == CPC_EVPOL_RESTRICT_TO_KNOWN || policy == CPC_EVPOL_DENY_ALL;
#else // __arm64__
	return false;
#endif // !__arm64__
#else // CONFIG_CPU_COUNTERS
	return true;
#endif // !CONFIG_CPU_COUNTERS
}

#if CPC_INSECURE

void
cpc_change_security(bool enforce_security)
{
#if CONFIG_CPU_COUNTERS
#if __arm64__
	cpc_set_event_policy(enforce_security ? CPC_EVPOL_RESTRICT_TO_KNOWN : CPC_EVPOL_DEFAULT);
#else // __arm64__
#pragma unused(enforce_security)
	// Intel has no event policy or other security features.
#endif // !__arm64__
#else // CONFIG_CPU_COUNTERS
#pragma unused(enforce_security)
#endif // !CONFIG_CPU_COUNTERS
}

#endif // CPC_INSECURE
