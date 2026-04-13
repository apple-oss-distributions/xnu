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

#include <IOKit/IOLib.h>
#include <IOKit/IOUserServer.h>
#include <IOKit/IOCatalogue.h>
#include <IOKit/IOKitKeysPrivate.h>
#include <sys/proc.h>

#if DEVELOPMENT || DEBUG

#include "TestDextRematchKernel.h"

#define super IOService
OSDefineMetaClassAndStructors(TestDextRematchProvider, IOService)

bool TestDextRematchProvider::_personalitiesInjected = false;

bool
TestDextRematchProvider::matchPropertyTable(OSDictionary *table)
{
	OSString * className = OSDynamicCast(OSString, table->getObject(gIOClassKey));
	bool bootComplete = __atomic_load_n(&_bootComplete, __ATOMIC_RELAXED);
	if ((className->isEqualTo("TestDextRematch") || className->isEqualTo("TestDextRematchCompetitor")) && !bootComplete) {
		// Start fresh and prevent either candidate from matching at the first service registration
		return false;
	}
	return true;
}

bool
TestDextRematchProvider::start(IOService *provider)
{
	if (!super::start(provider)) {
		IOLog("%s: super::start failed\n", getName());
		return false;
	}
	_lock = IOLockAlloc();
	super::registerService();

	OSString * userClientClassName = OSString::withCString("TestDextRematchProviderUserClient");
	setProperty(gIOUserClientClassKey, userClientClassName);
	OSSafeReleaseNULL(userClientClassName);

	// Inject kernel side personalities
	if (!_personalitiesInjected) {
		OSArray * personalities = OSArray::withCapacity(1);
		OSDictionary * dict = OSDictionary::withCapacity(3);
		OSString * ioClassName = OSString::withCString("TestDextRematchCompetitor");
		OSString * ioProviderClassName = OSString::withCString("TestDextRematchProvider");
		OSString * ioMatchCategory = OSString::withCString("com.apple.driver.TestDextRematch");
		dict->setObject(gIOClassKey, ioClassName);
		dict->setObject(gIOProviderClassKey, ioProviderClassName);
		dict->setObject(gIOMatchCategoryKey, ioMatchCategory);
		personalities->setObject(dict);

		if (!gIOCatalogue->addDrivers(personalities)) {
			IOLog("%s::%s: failed to inject personalities\n", getName(), __func__);
		}
		_personalitiesInjected = true;

		OSSafeReleaseNULL(ioMatchCategory);
		OSSafeReleaseNULL(ioProviderClassName);
		OSSafeReleaseNULL(ioClassName);
		OSSafeReleaseNULL(dict);
		OSSafeReleaseNULL(personalities);
	}

	IOLog("%s::%s\n", getName(), __func__);

	return true;
}

void
TestDextRematchProvider::registerService(IOOptionBits options)
{
	IOLog("%s::%s\n", getName(), __func__);
	__atomic_store_n(&_bootComplete, true, __ATOMIC_RELAXED);
	super::registerService(options);
}

void
TestDextRematchProvider::free()
{
	if (_lock) {
		IOLockFree(_lock);
		_lock = NULL;
	}
	super::free();
}

bool
TestDextRematchProvider::shouldStartFail(bool kernel)
{
	IOLog("%s::%s: %u\n", getName(), __func__, kernel);
	bool ret;
	IOLockLock(_lock);
	if (kernel) {
		ret = _childStartFailKernel;
		_childStartFailKernel = false;
	} else {
		ret = _childStartFailUser;
		_childStartFailUser = false;
	}
	IOLockUnlock(_lock);
	return ret;
}

bool
TestDextRematchProvider::shouldRematch()
{
	IOLog("%s::%s\n", getName(), __func__);
	bool ret;
	IOLockLock(_lock);
	ret = _childRematchPending;
	_childRematchPending = false;
	IOLockUnlock(_lock);
	return ret;
}

void
TestDextRematchProvider::anticipateChildStartFailure(bool kernel)
{
	IOLog("%s::%s: %u\n", getName(), __func__, kernel);
	IOLockLock(_lock);
	if (kernel) {
		_childStartFailKernel = true;
	} else {
		_childStartFailUser = true;
	}
	IOLockUnlock(_lock);
}

void
TestDextRematchProvider::anticipateRematch()
{
	IOLog("%s::%s\n", getName(), __func__);
	IOLockLock(_lock);
	_childRematchPending = true;
	IOLockUnlock(_lock);
}

void
TestDextRematchProvider::terminateChildren()
{
	IOLog("%s::%s\n", getName(), __func__);
	OSIterator * iter = getClientIterator();
	if (iter) {
		IOService * child;
		while ((child = (IOService *)iter->getNextObject()) != NULL) {
			if (OSDynamicCast(TestDextRematch, child) || OSDynamicCast(TestDextRematchCompetitor, child)) {
				child->terminate(kIOServiceTerminateNeedWillTerminate);
			}
		}
		iter->release();
	}
}

void
TestDextRematchProvider::clearAllPendingActions()
{
	IOLog("%s::%s\n", getName(), __func__);
	IOLockLock(_lock);
	_childStartFailKernel = false;
	_childStartFailUser = false;
	_childRematchPending = false;
	IOLockUnlock(_lock);
}

uint32_t
TestDextRematchProvider::getClientInstanceCount(uint32_t clientType)
{
	IOLog("%s::%s: type %u\n", getName(), __func__, clientType);
	if (clientType == kTestDextRematchClientTypeDefault) {
		return TestDextRematch::metaClass->getInstanceCount();
	} else if (clientType == kTestDextRematchClientTypeCompetitor) {
		return TestDextRematchCompetitor::metaClass->getInstanceCount();
	} else {
		return -1;
	}
}

uint32_t
TestDextRematchProvider::getClientCount(uint32_t clientType)
{
	IOLog("%s::%s: type %u\n", getName(), __func__, clientType);
	OSMetaClass * theMetaClass = NULL;
	if (clientType == kTestDextRematchClientTypeDefault) {
		theMetaClass = const_cast<OSMetaClass *>(TestDextRematch::metaClass);
	} else if (clientType == kTestDextRematchClientTypeCompetitor) {
		theMetaClass = const_cast<OSMetaClass *>(TestDextRematchCompetitor::metaClass);
	} else {
		return -1;
	}

	OSIterator * it = getClientIterator();
	uint32_t count = 0;
	if (it) {
		IOService * client;
		while ((client = (IOService *)it->getNextObject())) {
			if (client->metaCast(theMetaClass)) {
				count++;
			}
		}
		it->release();
	}
	return count;
}

IOUserServer *
TestDextRematchProvider::copyMatchingUserServer(IOService * whose)
{
	__block IOUserServer * userServer = NULL;
	OSDictionary * dict = serviceMatching("IOUserServer");
	OSIterator * iter = getMatchingServices(dict);
	uint64_t id = whose->getRegistryEntryID();
	if (iter) {
		IOService * candidate;
		while (!userServer && (candidate = (IOService *)iter->getNextObject()) != NULL) {
			OSObject * obj = candidate->copyProperty("IOAssociatedServices");
			OSArray * services = OSDynamicCast(OSArray, obj);
			if (services) {
				services->iterateObjects(^bool (OSObject *object) {
					if (((OSNumber *)object)->unsigned64BitValue() == id) {
					        userServer = OSDynamicCast(IOUserServer, candidate);
					        assert(userServer);
					        userServer->retain();
					        return true;
					}
					return false;
				});
			}
			OSSafeReleaseNULL(obj);
		}
		iter->release();
	}
	dict->release();

	return userServer;
}

#undef super
#define super IOUserClient
OSDefineMetaClassAndStructors(TestDextRematchProviderUserClient, IOUserClient)

IOExternalMethodDispatch
TestDextRematchProviderUserClient::_methods[] = {
	{ // Register
		(IOExternalMethodAction) & TestDextRematchProviderUserClient::_reRegisterService,
		0, 0,
		0, 0
	},
	{ // Terminate children
		(IOExternalMethodAction) & TestDextRematchProviderUserClient::_terminateChildren,
		0, 0,
		0, 0
	},
	{ // Clear all pending actions
		(IOExternalMethodAction) & TestDextRematchProviderUserClient::_clearAllPendingActions,
		0, 0,
		0, 0
	},
	{ // Anticipate start failure
		(IOExternalMethodAction) & TestDextRematchProviderUserClient::_anticipateChildStartFailure,
		1, 0,
		0, 0
	},
	{ // Anticipate rematch
		(IOExternalMethodAction) & TestDextRematchProviderUserClient::_anticipateRematch,
		0, 0,
		0, 0
	},
	{ // Get client instance count
		(IOExternalMethodAction) & TestDextRematchProviderUserClient::_getClientInstanceCount,
		1, 0,
		1, 0
	},
	{ // Get attached client instance count
		(IOExternalMethodAction) & TestDextRematchProviderUserClient::_getClientCount,
		1, 0,
		1, 0
	},
};

IOReturn
TestDextRematchProviderUserClient::externalMethod(uint32_t selector, IOExternalMethodArguments * arguments,
    IOExternalMethodDispatch * dispatch, OSObject * target, void * reference)
{
	if (selector < sizeof(_methods) / sizeof(_methods[0])) {
		dispatch = (IOExternalMethodDispatch *)&_methods[selector];
		if (!target) {
			target = this;
		}
	}

	return super::externalMethod(selector, arguments, dispatch, target, reference);
}

bool
TestDextRematchProviderUserClient::start(IOService *provider)
{
	if (!super::start(provider)) {
		IOLog("%s: super::start failed\n", getName());
		return false;
	}
	_provider = OSDynamicCast(TestDextRematchProvider, provider);
	assert(_provider);
	return true;
}

IOReturn
TestDextRematchProviderUserClient::_reRegisterService(TestDextRematchProviderUserClient *target, void *reference, IOExternalMethodArguments *arguments)
{
	target->reRegisterService();
	return kIOReturnSuccess;
}

void
TestDextRematchProviderUserClient::reRegisterService()
{
	_provider->registerService();
}

IOReturn
TestDextRematchProviderUserClient::_terminateChildren(TestDextRematchProviderUserClient *target, void *reference, IOExternalMethodArguments *arguments)
{
	target->terminateChildren();
	return kIOReturnSuccess;
}

void
TestDextRematchProviderUserClient::terminateChildren()
{
	_provider->terminateChildren();
}

IOReturn
TestDextRematchProviderUserClient::_clearAllPendingActions(TestDextRematchProviderUserClient *target, void *reference, IOExternalMethodArguments *arguments)
{
	target->clearAllPendingActions();
	return kIOReturnSuccess;
}

void
TestDextRematchProviderUserClient::clearAllPendingActions()
{
	_provider->clearAllPendingActions();
}

IOReturn
TestDextRematchProviderUserClient::_anticipateChildStartFailure(TestDextRematchProviderUserClient *target, void *reference, IOExternalMethodArguments *arguments)
{
	assert(arguments->scalarInputCount >= 1);
	target->anticipateChildStartFailure(arguments->scalarInput[0]);
	return kIOReturnSuccess;
}

void
TestDextRematchProviderUserClient::anticipateChildStartFailure(bool kernel)
{
	_provider->anticipateChildStartFailure(kernel);
}

IOReturn
TestDextRematchProviderUserClient::_anticipateRematch(TestDextRematchProviderUserClient *target, void *reference, IOExternalMethodArguments *arguments)
{
	target->anticipateRematch();
	return kIOReturnSuccess;
}

void
TestDextRematchProviderUserClient::anticipateRematch()
{
	_provider->anticipateRematch();
}

IOReturn
TestDextRematchProviderUserClient::_getClientInstanceCount(TestDextRematchProviderUserClient *target, void *reference, IOExternalMethodArguments *arguments)
{
	arguments->scalarOutput[0] = target->getClientInstanceCount((uint32_t)arguments->scalarInput[0]);
	arguments->scalarOutputCount = 1;
	return kIOReturnSuccess;
}

uint32_t
TestDextRematchProviderUserClient::getClientInstanceCount(uint32_t clientType)
{
	return _provider->getClientInstanceCount(clientType);
}

IOReturn
TestDextRematchProviderUserClient::_getClientCount(TestDextRematchProviderUserClient *target, void *reference, IOExternalMethodArguments *arguments)
{
	arguments->scalarOutput[0] = target->getClientCount((uint32_t)arguments->scalarInput[0]);
	arguments->scalarOutputCount = 1;
	return kIOReturnSuccess;
}

uint32_t
TestDextRematchProviderUserClient::getClientCount(uint32_t clientType)
{
	return _provider->getClientCount(clientType);
}

IOReturn
TestDextRematchProviderUserClient::clientClose()
{
	terminate();
	return kIOReturnSuccess;
}

#undef super
#define super IOService
OSDefineMetaClassAndStructors(TestDextRematch, IOService)

IOService *
TestDextRematch::probe(IOService * provider, SInt32 * score)
{
	IOLog("%s::%s\n", getName(), __func__);
	*score = 2000;
	return this;
}

bool
TestDextRematch::start(IOService *provider)
{
	IOReturn ret;

	IOLog("%s::%s\n", getName(), __func__);

	if (!super::start(provider)) {
		IOLog("%s: super start failed\n", getName());
		return false;
	}

	_provider = OSDynamicCast(TestDextRematchProvider, provider);
	assert(_provider);

	if (_provider->shouldRematch()) {
		IOLog("%s: triggering rematch logic\n", getName());

		// Now, kill the user server before leaving
		IOUserServer * userServer;
		uint32_t retries = 10; // 5s
		while ((userServer = _provider->copyMatchingUserServer(this)) == NULL && retries--) {
			IOSleep(500);
		}
		if (!userServer) {
			IOLog("%s: did not find matching user server\n", getName());
		} else {
			userServer->kill("test required");
			uint32_t retries = 10;
			while (!userServer->isInactive() && retries--) {
				IOSleep(500);
			}
			if (!userServer->isInactive()) {
				IOLog("%s: user server failed to be terminated\n", getName());
			}
			OSSafeReleaseNULL(userServer);
		}
		return false;
	}

	if (_provider->shouldStartFail(true)) {
		IOLog("%s: start is forced to fail by test parent\n", getName());
		return false;
	}

	ret = Start(provider);
	IOLog("%s: Start returned 0x%x\n", getName(), ret);

	return ret == kIOReturnSuccess;
}

void
TestDextRematch::stop(IOService *provider)
{
	IOLog("%s::%s\n", getName(), __func__);
	super::stop(provider);
}

void
TestDextRematch::free()
{
	IOLog("%s::%s\n", getName(), __func__);
	super::free();
}

bool
IMPL(TestDextRematch, ShouldStartFail)
{
	return _provider->shouldStartFail(false);
}

kern_return_t
IMPL(TestDextRematch, Start)
{
	return Start(provider, SUPERDISPATCH);
}

kern_return_t
IMPL(TestDextRematch, Stop)
{
	return Stop(provider, SUPERDISPATCH);
}

OSDefineMetaClassAndStructors(TestDextRematchCompetitor, IOService)

IOService *
TestDextRematchCompetitor::probe(IOService * provider, SInt32 * score)
{
	IOLog("%s: probe\n", getName());
	*score = 1000;
	return this;
}

bool
TestDextRematchCompetitor::start(IOService *provider)
{
	if (!super::start(provider)) {
		IOLog("%s: super start failed\n", getName());
		return false;
	}
	IOLog("%s: started\n", getName());
	return true;
}

#endif /* DEVELOPMENT || DEBUG */
