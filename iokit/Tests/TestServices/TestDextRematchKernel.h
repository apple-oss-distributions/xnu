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

#pragma once

#if DEVELOPMENT || DEBUG

#include <IOKit/IOService.h>
#include <IOKit/IOUserClient.h>
#include "Tests/TestServices/TestDextRematch.h"

enum {
	kTestDextRematchClientTypeDefault,
	kTestDextRematchClientTypeCompetitor
};

class IOUserServer;
class TestDextRematchProvider : public IOService
{
	OSDeclareDefaultStructors(TestDextRematchProvider);

public:
	bool matchPropertyTable(OSDictionary * table) APPLE_KEXT_OVERRIDE;
	bool start(IOService * provider) APPLE_KEXT_OVERRIDE;
	void registerService(IOOptionBits options = 0) APPLE_KEXT_OVERRIDE;
	void free() APPLE_KEXT_OVERRIDE;

	// Child queries this function to determine if Start or start should fail
	bool shouldStartFail(bool kernel);

	// Child queries this function to determine if user server should be killed,
	// which will trigger a rematch
	bool shouldRematch();

	// Force the upcoming dext child to fail Start or start
	void anticipateChildStartFailure(bool kernel);

	// Force the upcoming dext child to kill its user server
	void anticipateRematch();

	// Terminate all test relevant children (excluding user client)
	void terminateChildren();

	// Clear all anticipated actions
	void clearAllPendingActions();

	// Get the instance count of a specific client type
	uint32_t getClientInstanceCount(uint32_t clientType);

	// Get the count of the attached clients of a specific type
	uint32_t getClientCount(uint32_t clientType);

	// Get the matching user server of the dext service
	static IOUserServer * copyMatchingUserServer(IOService * whose);

private:
	IOLock * _lock;
	bool _childStartFailUser;
	bool _childStartFailKernel;
	bool _childRematchPending;
	bool _bootComplete;
	static bool _personalitiesInjected;
};

class TestDextRematchProviderUserClient : public IOUserClient
{
	OSDeclareDefaultStructors(TestDextRematchProviderUserClient);

public:
	bool start(IOService * provider) APPLE_KEXT_OVERRIDE;
	IOReturn clientClose() APPLE_KEXT_OVERRIDE;

	IOReturn externalMethod(uint32_t selector, IOExternalMethodArguments * arguments,
	    IOExternalMethodDispatch * dispatch, OSObject * target,
	    void * reference) APPLE_KEXT_OVERRIDE;

protected:
	static IOReturn _reRegisterService(TestDextRematchProviderUserClient * target,
	    void * reference, IOExternalMethodArguments * arguments);
	static IOReturn _terminateChildren(TestDextRematchProviderUserClient * target,
	    void * reference, IOExternalMethodArguments * arguments);
	static IOReturn _clearAllPendingActions(TestDextRematchProviderUserClient * target,
	    void * reference, IOExternalMethodArguments * arguments);
	static IOReturn _anticipateChildStartFailure(TestDextRematchProviderUserClient *target,
	    void *reference, IOExternalMethodArguments * arguments);
	static IOReturn _anticipateRematch(TestDextRematchProviderUserClient * target,
	    void * reference, IOExternalMethodArguments * arguments);
	static IOReturn _getClientInstanceCount(TestDextRematchProviderUserClient * target,
	    void * reference, IOExternalMethodArguments * arguments);
	static IOReturn _getClientCount(TestDextRematchProviderUserClient * target,
	    void * reference, IOExternalMethodArguments * arguments);

private:
	void reRegisterService();
	void terminateChildren();
	void clearAllPendingActions();
	void anticipateChildStartFailure(bool kernel);
	void anticipateRematch();
	uint32_t getClientInstanceCount(uint32_t clientType);
	uint32_t getClientCount(uint32_t clientType);

private:
	TestDextRematchProvider * _provider;
	static IOExternalMethodDispatch _methods[];
};

class TestDextRematch : public IOService
{
	OSDeclareDefaultStructorsWithDispatch(TestDextRematch);

public:
	IOService * probe(IOService * provider, SInt32 * score) APPLE_KEXT_OVERRIDE;
	bool start(IOService * provider) APPLE_KEXT_OVERRIDE;
	void stop(IOService * provider) APPLE_KEXT_OVERRIDE;
	void free() APPLE_KEXT_OVERRIDE;

private:
	TestDextRematchProvider * _provider;
};

class TestDextRematchCompetitor : public IOService
{
	OSDeclareDefaultStructors(TestDextRematchCompetitor);

public:
	IOService * probe(IOService * provider, SInt32 * score) APPLE_KEXT_OVERRIDE;
	bool start(IOService * provider) APPLE_KEXT_OVERRIDE;
};

#endif /* DEVELOPMENT || DEBUG */
