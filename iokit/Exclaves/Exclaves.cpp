/*
 * Copyright (c) 1998-2023 Apple Inc. All rights reserved.
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

#include <IOKit/IOService.h>
#include <IOKit/IOInterruptEventSource.h>
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/IOMapper.h>
#include "../Kernel/IOServicePrivate.h"

#include <Exclaves/Exclaves.h>


struct IOService::IOExclaveProxyState {
	IOService    *service;
	uint64_t      mach_endpoint;
};


bool
IOService::exclaveStart(IOService * provider, IOExclaveProxyState ** pRef)
{
	IOExclaveProxyState * ref;

	ref = NULL;

	if (!ref) {
		return false;
	}

	*pRef = ref;
	return true;
}

uint64_t
IOService::exclaveEndpoint(IOExclaveProxyState * pRef)
{
	return pRef->mach_endpoint;
}

bool
IOExclaveProxy::start(IOService * provider)
{
	bool ok;

	ok = exclaveStart(provider, &exclaveState);

	return ok;
}

/* Exclave upcall handlers */


bool
IOService::exclaveRegisterInterrupt(IOExclaveProxyState * pRef, int index, bool noProvider = false)
{
	return false;
}

bool
IOService::exclaveRemoveInterrupt(IOExclaveProxyState * pRef, int index)
{
	return false;
}

bool
IOService::exclaveEnableInterrupt(IOExclaveProxyState * pRef, int index, bool enable)
{
	return false;
}


void
IOService::exclaveInterruptOccurred(IOInterruptEventSource *eventSource, int count)
{
}


bool
IOService::exclaveRegisterTimer(IOExclaveProxyState * pRef, uint32_t *timer_id)
{
	return false;
}

bool
IOService::exclaveRemoveTimer(IOExclaveProxyState * pRef, uint32_t timer_id)
{
	return false;
}

bool
IOService::exclaveEnableTimer(IOExclaveProxyState * pRef, uint32_t timer_id, bool enable)
{
	return false;
}

bool
IOService::exclaveTimerSetTimeout(IOExclaveProxyState * pRef, uint32_t timer_id, uint32_t options, AbsoluteTime interval, AbsoluteTime leeway, kern_return_t *kr)
{
	return false;
}

bool
IOService::exclaveTimerCancelTimeout(IOExclaveProxyState * pRef, uint32_t timer_id)
{
	return false;
}

void
IOService::exclaveTimerFired(IOTimerEventSource *eventSource)
{
}


kern_return_t
IOService::exclaveAsyncNotificationRegister(IOExclaveProxyState * pRef, IOInterruptEventSource *notification, uint32_t *notificationID)
{
#pragma unused(pRef, notification, notificationID)
	return kIOReturnUnsupported;
}

kern_return_t
IOService::exclaveAsyncNotificationSignal(IOExclaveProxyState * pRef, uint32_t notificationID)
{
#pragma unused(pRef, notificationID)
	return kIOReturnUnsupported;
}
