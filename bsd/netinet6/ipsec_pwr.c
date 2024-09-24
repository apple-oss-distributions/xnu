/*
 * Copyright (c) 2023 Apple Inc. All rights reserved.
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

#include <netinet6/ipsec.h>
#include <netkey/key.h>
#include <IOKit/pwr_mgt/IOPM.h>

void *sleep_wake_handle = NULL;

typedef IOReturn (*IOServiceInterestHandler)( void * target, void * refCon,
    UInt32 messageType, void * provider,
    void * messageArgument, vm_size_t argSize );
extern void *registerSleepWakeInterest(IOServiceInterestHandler, void *, void *);

static IOReturn
ipsec_sleep_wake_handler(void *target, void *refCon, UInt32 messageType,
    void *provider, void *messageArgument, vm_size_t argSize)
{
#pragma unused(target, refCon, provider, messageArgument, argSize)
	switch (messageType) {
	case kIOMessageSystemWillSleep:
	{
		ipsec_get_local_ports();
		break;
	}
	default:
		break;
	}

	return IOPMAckImplied;
}

void
ipsec_monitor_sleep_wake(void)
{
	LCK_MTX_ASSERT(sadb_mutex, LCK_MTX_ASSERT_OWNED);

	if (sleep_wake_handle == NULL) {
		sleep_wake_handle = registerSleepWakeInterest(ipsec_sleep_wake_handler,
		    NULL, NULL);
		if (sleep_wake_handle != NULL) {
			ipseclog((LOG_INFO,
			    "ipsec: monitoring sleep wake"));
		}
	}
}
