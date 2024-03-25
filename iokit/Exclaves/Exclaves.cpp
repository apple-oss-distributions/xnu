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

#if CONFIG_EXCLAVES
#include <mach/exclaves.h>
#include <Exclaves/IOService.tightbeam.h>

#define EXLOG(x...)  do { \
    if (kIOLogExclaves & gIOKitDebug) \
	IOLog(x); \
} while (false)

/* Global IOExclaveProxyState lookup table */

OSDictionary    *gExclaveProxyStates;
IORecursiveLock *gExclaveProxyStateLock;
const OSSymbol  *gDARTMapperFunctionSetActive;

/* IOExclaveProxyState */

class IOExclaveWorkLoopAperture {
public:
	IOWorkLoop *workLoop;
	void
	closeGate()
	{
		workLoop->closeGate();
	}
	void
	openGate()
	{
		workLoop->openGate();
	}
};

#endif /* CONFIG_EXCLAVES */

struct IOService::IOExclaveProxyState {
	IOService    *service;
	uint64_t      mach_endpoint;
#if CONFIG_EXCLAVES
	tb_endpoint_t tb_endpoint;
	ioservice_ioserviceconcrete client;
	// ExclaveDriverKit related state
	bool          edk_endpoint_exists;
	uint64_t      edk_mach_endpoint;
	tb_endpoint_t edk_tb_endpoint;
	ioservice_ioserviceprivate edk_client;
	OSDictionary *exclave_interrupts;
	OSDictionary *exclave_timers;
	uint32_t nextExclaveTimerId;

	// TODO: implement properly once ExclaveAperture removed
	IOExclaveWorkLoopAperture *ewla;

	IOLock * exclaveAsyncNotificationEventSourcesLock;
	OSArray *exclaveAsyncNotificationEventSources;

	// ANE specific upcalls
	ANEUpcallSetPowerStateHandler aneSetPowerStateUpcallHandler;
	ANEUpcallWorkHandler aneWorkSubmitUpcallHandler;
	ANEUpcallWorkHandler aneWorkBeginUpcallHandler;
	ANEUpcallWorkHandler aneWorkEndUpcallHandler;
#endif /* CONFIG_EXCLAVES */
};

#if CONFIG_EXCLAVES
class IOExclaveProxyStateWrapper : public OSObject {
	OSDeclareFinalStructors(IOExclaveProxyStateWrapper);
public:
	IOService::IOExclaveProxyState *proxyState;
};
OSDefineMetaClassAndFinalStructors(IOExclaveProxyStateWrapper, OSObject);
#endif /* CONFIG_EXCLAVES */

bool
IOService::exclaveStart(IOService * provider, IOExclaveProxyState ** pRef)
{
	IOExclaveProxyState * ref;

	ref = NULL;
#if CONFIG_EXCLAVES
	uint64_t serviceID;
	char key[16];
	do {
		OSObject * prop;
		OSData   * data;
		bool       result;
		uint64_t   mach_endpoint = 0;
		tb_error_t tberr;
		tb_endpoint_t tb_endpoint;
		ioservice_ioserviceconcrete client;
		bool edk_endpoint_exists = false;
		uint64_t   edk_mach_endpoint = 0;
		tb_endpoint_t edk_tb_endpoint;
		ioservice_ioserviceprivate edk_client;
		IOWorkLoop *wl;

		// exit early if Exclaves are not available
		if (exclaves_get_status() == EXCLAVES_STATUS_NOT_SUPPORTED) {
			break;
		}

		prop = provider->copyProperty("exclave-endpoint");
		if ((data = OSDynamicCast(OSData, prop))) {
			mach_endpoint = ((uint32_t *)data->getBytesNoCopy())[0];
		}
		OSSafeReleaseNULL(prop);

		prop = provider->copyProperty("exclave-edk-endpoint");
		if ((data = OSDynamicCast(OSData, prop))) {
			edk_mach_endpoint = ((uint32_t *)data->getBytesNoCopy())[0];
			edk_endpoint_exists = true;
		}
		OSSafeReleaseNULL(prop);

		// Initialize IOServiceConcrete endpoint
		tb_endpoint = tb_endpoint_create_with_value(TB_TRANSPORT_TYPE_XNU, mach_endpoint, TB_ENDPOINT_OPTIONS_NONE);
		assert(NULL != tb_endpoint);
		if (NULL == tb_endpoint) {
			break;
		}
		tberr = ioservice_ioserviceconcrete_init(&client, tb_endpoint);
		assert(TB_ERROR_SUCCESS == tberr);
		if (TB_ERROR_SUCCESS != tberr) {
			break;
		}

		if (edk_endpoint_exists) {
			// Initialize IOServicePrivate endpoint
			edk_tb_endpoint = tb_endpoint_create_with_value(TB_TRANSPORT_TYPE_XNU, edk_mach_endpoint, TB_ENDPOINT_OPTIONS_NONE);
			assert(NULL != edk_tb_endpoint);
			if (NULL == edk_tb_endpoint) {
				printf("%s: ERROR: Failed to create endpoint\n", __func__);
				break;
			}
			tberr = ioservice_ioserviceprivate_init(&edk_client, edk_tb_endpoint);
			assert(TB_ERROR_SUCCESS == tberr);
			if (TB_ERROR_SUCCESS != tberr) {
				printf("%s: ERROR: Failed to init IOServicePrivate\n", __func__);
				break;
			}
		}

		ref = IONewZero(IOExclaveProxyState, 1);
		if (!ref) {
			break;
		}
		ref->service = this;
		ref->mach_endpoint = mach_endpoint;
		ref->tb_endpoint   = tb_endpoint;
		ref->client = client;
		ref->edk_endpoint_exists = edk_endpoint_exists;
		if (edk_endpoint_exists) {
			ref->edk_mach_endpoint = edk_mach_endpoint;
			ref->edk_tb_endpoint   = edk_tb_endpoint;
			ref->edk_client = edk_client;
		}
		ref->exclave_interrupts = OSDictionary::withCapacity(1);
		ref->exclave_timers = OSDictionary::withCapacity(1);
		ref->exclaveAsyncNotificationEventSourcesLock = IOLockAlloc();

		// TODO: remove once workloop aperture workaround removed
		wl = getWorkLoop();
		if (!wl) {
			printf("%s ERROR: getWorkLoop failed\n", __func__);
			break;
		}
		ref->ewla = IONew(IOExclaveWorkLoopAperture, 1);
		if (!ref->ewla) {
			printf("%s ERROR: exclaveWorkLoopAperture init failed\n", __func__);
			break;
		}
		ref->ewla->workLoop = wl;

		// Add proxy state to global lookup table
		serviceID = getRegistryEntryID();
		snprintf(key, sizeof(key), "%llu", serviceID);
		IOExclaveProxyStateWrapper *wrapper = OSTypeAlloc(IOExclaveProxyStateWrapper);
		wrapper->proxyState = ref;
		IORecursiveLockLock(gExclaveProxyStateLock);
		gExclaveProxyStates->setObject(key, wrapper);
		IORecursiveLockUnlock(gExclaveProxyStateLock);

		if (ref->edk_endpoint_exists) {
			// Start() called after lookup table registration in case upcalls are made during exclave start().
			// Use registry ID as exclave's upcall identifer
			tberr = ioservice_ioserviceprivate_startprivate(&edk_client, serviceID, &result);
			if (TB_ERROR_SUCCESS != tberr || !result) {
				printf("%s ERROR: Failed StartPrivate\n", __func__);
				// Deregister from lookup table if start() fails
				IORecursiveLockLock(gExclaveProxyStateLock);
				gExclaveProxyStates->removeObject(key);
				IORecursiveLockUnlock(gExclaveProxyStateLock);
				wrapper->release();
				IODelete(ref, IOExclaveProxyState, 1);
				ref = NULL;
				break;
			}
		}
	} while (false);
#endif /* CONFIG_EXCLAVES */

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

#if CONFIG_EXCLAVES

static IOService::IOExclaveProxyState *
getProxyStateFromRegistryID(uint64_t id)
{
	OSObject *obj = NULL;
	IOExclaveProxyStateWrapper *wrapper = NULL;
	char key[15];

	snprintf(key, sizeof(key), "%llu", id);
	IORecursiveLockLock(gExclaveProxyStateLock);
	obj = gExclaveProxyStates->getObject(key);
	IORecursiveLockUnlock(gExclaveProxyStateLock);
	if (!obj) {
		printf("%s ERROR: failed to find proxy state\n", __func__);
		return NULL;
	}

	wrapper = OSDynamicCast(IOExclaveProxyStateWrapper, obj);
	if (!wrapper) {
		printf("%s ERROR: failed to cast IOExclaveProxyStateWrapper\n", __func__);
		return NULL;
	}

	if (!wrapper->proxyState) {
		printf("%s ERROR: IOExclaveProxyStateWrapper contains NULL proxy state\n", __func__);
		return NULL;
	}

	return wrapper->proxyState;
}

bool
IOExclaveInterruptUpcallHandler(uint64_t id, IOExclaveInterruptUpcallArgs *args)
{
	assert(args);
	IOService::IOExclaveProxyState *ref = getProxyStateFromRegistryID(id);
	if (!ref || !args) {
		return false;
	}
	ref->service->retain();

	bool res;
	switch (args->type) {
	case kIOExclaveInterruptUpcallTypeRegister:
		// Register interrupt
		res = ref->service->exclaveRegisterInterrupt(ref, args->index, args->data.register_args.test_irq);
		break;
	case kIOExclaveInterruptUpcallTypeRemove:
		// Remove interrupt
		res = ref->service->exclaveRemoveInterrupt(ref, args->index);
		break;
	case kIOExclaveInterruptUpcallTypeEnable:
		// Enable/disable interrupt
		res = ref->service->exclaveEnableInterrupt(ref, args->index, args->data.enable_args.enable);
		break;
	default:
		res = false;
		printf("%s ERROR: invalid upcall type\n", __func__);
	}

	if (!res) {
		printf("%s ERROR: upcall handler type %d failed\n", __func__, args->type);
		ref->service->release();
		return false;
	}

	ref->service->release();
	return true;
}

bool
IOExclaveTimerUpcallHandler(uint64_t id, IOExclaveTimerUpcallArgs *args)
{
	assert(args);
	IOService::IOExclaveProxyState *ref = getProxyStateFromRegistryID(id);
	if (!ref || !args) {
		return false;
	}
	ref->service->retain();

	bool res;
	uint32_t timer_id = args->timer_id;
	switch (args->type) {
	case kIOExclaveTimerUpcallTypeRegister:
		// Register timer
		res = ref->service->exclaveRegisterTimer(ref, &args->timer_id);
		break;
	case kIOExclaveTimerUpcallTypeRemove:
		// Remove timer
		res = ref->service->exclaveRemoveTimer(ref, timer_id);
		break;
	case kIOExclaveTimerUpcallTypeEnable:
	{
		// Enable/disable timer
		bool enable = args->data.enable_args.enable;
		res = ref->service->exclaveEnableTimer(ref, timer_id, enable);
		break;
	}
	case kIOExclaveTimerUpcallTypeSetTimeout:
	{
		// Set timeout
		uint32_t options = args->data.set_timeout_args.clock_continuous ? kIOTimeOptionsContinuous : 0;
		AbsoluteTime duration = args->data.set_timeout_args.duration;
		kern_return_t *kr = &args->data.set_timeout_args.kr;
		res = ref->service->exclaveTimerSetTimeout(ref, timer_id, options, duration, 0, kr);
		break;
	}
	case kIOExclaveTimerUpcallTypeCancelTimeout:
		// Cancel timeout
		res = ref->service->exclaveTimerCancelTimeout(ref, timer_id);
		break;
	default:
		res = false;
		printf("%s ERROR: invalid upcall type\n", __func__);
	}

	if (!res) {
		printf("%s ERROR: upcall handler type %d failed\n", __func__, args->type);
		ref->service->release();
		return false;
	}

	ref->service->release();
	return true;
}

bool
IOExclaveLockWorkloop(uint64_t id, bool lock)
{
	IOService::IOExclaveProxyState *ref = getProxyStateFromRegistryID(id);
	if (!ref) {
		return false;
	}

	// Lock or unlock workloop
	if (lock) {
		ref->ewla->closeGate();
		EXLOG("%s locked workloop\n", __func__);
	} else {
		ref->ewla->openGate();
		EXLOG("%s unlocked workloop\n", __func__);
	}
	return true;
}

static void
getExclaveInterruptKey(int index, char *key, size_t size)
{
	snprintf(key, size, "%d", index);
}

static IOInterruptEventSource *
getExclaveInterruptEventSource(IOService::IOExclaveProxyState * pRef, int index)
{
	OSObject *obj;
	IOInterruptEventSource *ies;
	char irqKey[5];

	if (!pRef) {
		return NULL;
	}

	getExclaveInterruptKey(index, irqKey, sizeof(irqKey));
	obj = pRef->exclave_interrupts->getObject(irqKey);
	if (!obj) {
		return NULL;
	}

	ies = OSDynamicCast(IOInterruptEventSource, obj);
	return ies;
}

// TODO: Remove after testing
void
IOExclaveTestSignalInterrupt(thread_call_param_t arg0, __unused thread_call_param_t arg1)
{
	EXLOG("%s called\n", __func__);

	// Unpackage params
	struct IOExclaveTestSignalInterruptParam *params = (struct IOExclaveTestSignalInterruptParam *) arg0;
	if (params->id == -1 || params->index == -1) {
		printf("%s: ERROR: id and irq index not initialized\n", __func__);
		return;
	}

	uint64_t id = params->id;
	int index = (int) params->index;

	IOService::IOExclaveProxyState *ref = getProxyStateFromRegistryID(id);
	if (!ref) {
		return;
	}
	ref->service->retain();

	// Get interrupt
	char irqKey[5];
	getExclaveInterruptKey(index, irqKey, sizeof(irqKey));
	OSObject *obj2 = ref->exclave_interrupts->getObject(irqKey);
	if (!obj2) {
		printf("%s: ERROR: failed to get ies\n", __func__);
		ref->service->release();
		return;
	}

	IOInterruptEventSource *ies = OSDynamicCast(IOInterruptEventSource, obj2);
	if (!ies) {
		printf("%s: ERROR: failed to cast ies\n", __func__);
		ref->service->release();
		return;
	}

	// Signal interrupt
	ies->interruptOccurred(NULL, NULL, 1);

	ref->service->release();
}

bool
IOExclaveAsyncNotificationUpcallHandler(uint64_t id, struct IOExclaveAsyncNotificationUpcallArgs *args)
{
	IOService::IOExclaveProxyState *ref = getProxyStateFromRegistryID(id);
	bool ret = false;
	if (!ref) {
		return false;
	}

	switch (args->type) {
	case AsyncNotificationUpcallTypeSignal:
		ret = ref->service->exclaveAsyncNotificationSignal(ref, args->notificationID) == kIOReturnSuccess;
		break;
	default:
		ret = false;
		break;
	}
	return ret;
}

bool
IOExclaveMapperOperationUpcallHandler(uint64_t id, IOExclaveMapperOperationUpcallArgs *args)
{
	assert(args);
	IOService *provider = NULL;
	bool res = false;
	IOService::IOExclaveProxyState *ref = getProxyStateFromRegistryID(id);
	if (!ref) {
		return false;
	}
	provider = ref->service->getProvider();

	IOMapper *mapper = IOMapper::copyMapperForDeviceWithIndex(provider, (unsigned int)(args->mapperIndex));
	if (!mapper) {
		goto finish;
	}

	switch (args->type) {
	case MapperActivate:
		res = kIOReturnSuccess == mapper->callPlatformFunction(gDARTMapperFunctionSetActive, false, (void *)(true), (void *)(false), NULL, NULL);
		break;
	case MapperDeactivate:
		res = kIOReturnSuccess == mapper->callPlatformFunction(gDARTMapperFunctionSetActive, false, (void *)(false), (void *)(false), NULL, NULL);
		break;
	default:
		break;
	}

finish:
	return res;
}

bool
IOExclaveANEUpcallHandler(uint64_t id, struct IOExclaveANEUpcallArgs *args, bool *result)
{
	IOService::IOExclaveProxyState *ref = getProxyStateFromRegistryID(id);
	bool ret = false;
	bool _result = false;
	if (!ref || !args) {
		return false;
	}

	switch (args->type) {
	case kIOExclaveANEUpcallTypeSetPowerState:
		if (ref->aneSetPowerStateUpcallHandler) {
			_result = (ref->aneSetPowerStateUpcallHandler)(
				args->setpowerstate_args.desired_state
				);
			ret = true;
		} else {
			printf("%s: no handler for upcall %d registered\n", __func__, (int)args->type);
		}
		break;
	case kIOExclaveANEUpcallTypeWorkSubmit:
		if (ref->aneWorkSubmitUpcallHandler) {
			_result = (ref->aneWorkSubmitUpcallHandler)(
				args->work_args.arg0,
				args->work_args.arg1,
				args->work_args.arg2
				);
			ret = true;
		} else {
			printf("%s: no handler for upcall %d registered\n", __func__, (int)args->type);
		}
		break;
	case kIOExclaveANEUpcallTypeWorkBegin:
		if (ref->aneWorkBeginUpcallHandler) {
			_result = (ref->aneWorkBeginUpcallHandler)(
				args->work_args.arg0,
				args->work_args.arg1,
				args->work_args.arg2
				);
			ret = true;
		} else {
			printf("%s: no handler for upcall %d registered\n", __func__, (int)args->type);
		}
		break;
	case kIOExclaveANEUpcallTypeWorkEnd:
		if (ref->aneWorkEndUpcallHandler) {
			_result = (ref->aneWorkEndUpcallHandler)(
				args->work_args.arg0,
				args->work_args.arg1,
				args->work_args.arg2
				);
			ret = true;
		} else {
			printf("%s: no handler for upcall %d registered\n", __func__, (int)args->type);
		}
		break;
	default:
		ret = false;
		break;
	}

	if (result) {
		*result = _result;
	}

	return ret;
}

/* IOService exclave methods */

#endif /* CONFIG_EXCLAVES */

bool
IOService::exclaveRegisterInterrupt(IOExclaveProxyState * pRef, int index, bool noProvider = false)
{
#if CONFIG_EXCLAVES
	IOInterruptEventSource *ies = NULL;
	IOInterruptEventSource::Action action;
	IOWorkLoop *wl;
	char irqKey[5];

	assert(getWorkLoop() && getWorkLoop()->inGate());

	if (!pRef) {
		return false;
	}

	action = OSMemberFunctionCast(IOInterruptEventSource::Action,
	    this, &IOService::exclaveInterruptOccurred);
	ies = IOInterruptEventSource::interruptEventSource(this, action, noProvider ? nullptr : getProvider(), index);
	if (!ies) {
		return false;
	}

	wl = getWorkLoop();
	if (!wl) {
		ies->release();
		return false;
	}
	if (wl->addEventSource(ies) != kIOReturnSuccess) {
		ies->release();
		return false;
	}

	// Register IOIES in exclave proxy state
	getExclaveInterruptKey(index, irqKey, sizeof(irqKey));
	pRef->exclave_interrupts->setObject(irqKey, ies);

	EXLOG("%s: IRQ %d register success!\n", __func__, index);
	return true;
#else /* CONFIG_EXCLAVES */
	return false;
#endif /* CONFIG_EXCLAVES */
}

bool
IOService::exclaveRemoveInterrupt(IOExclaveProxyState * pRef, int index)
{
#if CONFIG_EXCLAVES
	IOInterruptEventSource *ies;
	IOWorkLoop *wl;
	char irqKey[5];

	assert(getWorkLoop() && getWorkLoop()->inGate());

	if (!pRef) {
		return false;
	}

	ies = getExclaveInterruptEventSource(pRef, index);
	if (!ies) {
		return false;
	}

	wl = getWorkLoop();
	if (!wl) {
		return false;
	}

	getExclaveInterruptKey(index, irqKey, sizeof(irqKey));
	wl->removeEventSource(ies);
	pRef->exclave_interrupts->removeObject(irqKey);
	OSSafeReleaseNULL(ies);

	EXLOG("%s: IRQ %d removed successfully\n", __func__, index);
	return true;
#else /* CONFIG_EXCLAVES */
	return false;
#endif /* CONFIG_EXCLAVES */
}

bool
IOService::exclaveEnableInterrupt(IOExclaveProxyState * pRef, int index, bool enable)
{
#if CONFIG_EXCLAVES
	IOInterruptEventSource *ies;

	assert(getWorkLoop() && getWorkLoop()->inGate());

	if (!pRef) {
		return false;
	}

	ies = getExclaveInterruptEventSource(pRef, index);
	if (!ies) {
		return false;
	}

	if (enable) {
		ies->enable();
	} else {
		ies->disable();
	}

	EXLOG("%s: IRQ %s success!\n", __func__, enable ? "enable" : "disable");
	return true;
#else /* CONFIG_EXCLAVES */
	return false;
#endif /* CONFIG_EXCLAVES */
}


void
IOService::exclaveInterruptOccurred(IOInterruptEventSource *eventSource, int count)
{
#if CONFIG_EXCLAVES
	tb_error_t tberr;
	IOService::IOExclaveProxyState *ref;

	if (!eventSource) {
		printf("%s ERROR: IOInterruptEventSource is null\n", __func__);
		return;
	}

	EXLOG("%s id 0x%llx (irq index %d)\n", __func__, getRegistryEntryID(), eventSource->getIntIndex());

	ref = getProxyStateFromRegistryID(getRegistryEntryID());
	if (!ref) {
		printf("%s ERROR: failed to get IOExclaveProxyState\n", __func__);
		return;
	}

	assert(ref->edk_endpoint_exists);
	tberr = ioservice_ioserviceprivate_interruptoccurredprivate(&ref->edk_client, eventSource->getIntIndex(), count);
	assert(TB_ERROR_SUCCESS == tberr);
	if (TB_ERROR_SUCCESS != tberr) {
		printf("%s ERROR: tightbeam call failed\n", __func__);
		return;
	}
#endif /* CONFIG_EXCLAVES */
}

#if CONFIG_EXCLAVES
static void
getExclaveTimerKey(uint32_t timer_id, char *key, size_t size)
{
	snprintf(key, size, "%d", timer_id);
}

static IOTimerEventSource *
getExclaveTimerEventSource(IOService::IOExclaveProxyState * pRef, uint32_t timer_id)
{
	OSObject *obj;
	IOTimerEventSource *tes;
	char timerKey[5];

	if (!pRef) {
		return NULL;
	}

	getExclaveTimerKey(timer_id, timerKey, sizeof(timerKey));
	obj = pRef->exclave_timers->getObject(timerKey);
	if (!obj) {
		return NULL;
	}

	tes = OSDynamicCast(IOTimerEventSource, obj);
	return tes;
}
#endif /* CONFIG_EXCLAVES */

bool
IOService::exclaveRegisterTimer(IOExclaveProxyState * pRef, uint32_t *timer_id)
{
#if CONFIG_EXCLAVES
	IOTimerEventSource *tes = NULL;
	IOTimerEventSource::Action action;
	IOWorkLoop *wl;
	char timerKey[5];

	assert(getWorkLoop() && getWorkLoop()->inGate());

	if (!pRef || !timer_id) {
		return false;
	}

	action = OSMemberFunctionCast(IOTimerEventSource::Action,
	    this, &IOService::exclaveTimerFired);
	tes = IOTimerEventSource::timerEventSource(this, action);
	if (!tes) {
		return false;
	}

	wl = getWorkLoop();
	if (!wl) {
		tes->release();
		return false;
	}
	if (wl->addEventSource(tes) != kIOReturnSuccess) {
		tes->release();
		return false;
	}

	// Register IOTES in exclave proxy state
	*timer_id = pRef->nextExclaveTimerId++;
	getExclaveTimerKey(*timer_id, timerKey, sizeof(timerKey));
	pRef->exclave_timers->setObject(timerKey, tes);

	EXLOG("%s: timer %u register success!\n", __func__, *timer_id);
	return true;
#else /* CONFIG_EXCLAVES */
	return false;
#endif /* CONFIG_EXCLAVES */
}

bool
IOService::exclaveRemoveTimer(IOExclaveProxyState * pRef, uint32_t timer_id)
{
#if CONFIG_EXCLAVES
	IOTimerEventSource *tes;
	IOWorkLoop *wl;
	char timerKey[5];

	assert(getWorkLoop() && getWorkLoop()->inGate());

	if (!pRef) {
		return false;
	}

	tes = getExclaveTimerEventSource(pRef, timer_id);
	if (!tes) {
		return false;
	}

	wl = getWorkLoop();
	if (!wl) {
		return false;
	}

	wl->removeEventSource(tes);
	getExclaveTimerKey(timer_id, timerKey, sizeof(timerKey));
	pRef->exclave_timers->removeObject(timerKey);
	OSSafeReleaseNULL(tes);

	EXLOG("%s: timer %u removed successfully\n", __func__, timer_id);
	return true;
#else /* CONFIG_EXCLAVES */
	return false;
#endif /* CONFIG_EXCLAVES */
}

bool
IOService::exclaveEnableTimer(IOExclaveProxyState * pRef, uint32_t timer_id, bool enable)
{
#if CONFIG_EXCLAVES
	IOTimerEventSource *tes;

	assert(getWorkLoop() && getWorkLoop()->inGate());

	if (!pRef) {
		return false;
	}

	tes = getExclaveTimerEventSource(pRef, timer_id);
	if (!tes) {
		return false;
	}

	if (enable) {
		tes->enable();
	} else {
		tes->disable();
	}

	EXLOG("%s: timer %u %s success\n", __func__, timer_id, enable ? "enable" : "disable");
	return true;
#else /* CONFIG_EXCLAVES */
	return false;
#endif /* CONFIG_EXCLAVES */
}

bool
IOService::exclaveTimerSetTimeout(IOExclaveProxyState * pRef, uint32_t timer_id, uint32_t options, AbsoluteTime interval, AbsoluteTime leeway, kern_return_t *kr)
{
#if CONFIG_EXCLAVES
	IOTimerEventSource *tes;

	assert(getWorkLoop() && getWorkLoop()->inGate());

	if (!pRef || !kr) {
		return false;
	}

	tes = getExclaveTimerEventSource(pRef, timer_id);
	if (!tes) {
		return false;
	}

	*kr = tes->setTimeout(options, interval, leeway);

	EXLOG("%s: timer %u setTimeout completed (kr %d)\n", __func__, timer_id, *kr);
	return true;
#else /* CONFIG_EXCLAVES */
	return false;
#endif /* CONFIG_EXCLAVES */
}

bool
IOService::exclaveTimerCancelTimeout(IOExclaveProxyState * pRef, uint32_t timer_id)
{
#if CONFIG_EXCLAVES
	IOTimerEventSource *tes;

	assert(getWorkLoop() && getWorkLoop()->inGate());

	if (!pRef) {
		return false;
	}

	tes = getExclaveTimerEventSource(pRef, timer_id);
	if (!tes) {
		return false;
	}

	tes->cancelTimeout();
	EXLOG("%s: timer %u setTimeout success\n", __func__, timer_id);
	return true;
#else /* CONFIG_EXCLAVES */
	return false;
#endif /* CONFIG_EXCLAVES */
}

void
IOService::exclaveTimerFired(IOTimerEventSource *eventSource)
{
#if CONFIG_EXCLAVES
	tb_error_t tberr;
	IOService::IOExclaveProxyState *ref;
	__block bool found = false;
	__block uint32_t timer_id;

	if (!eventSource) {
		printf("%s ERROR: IOTimerEventSource is null\n", __func__);
		return;
	}

	ref = getProxyStateFromRegistryID(getRegistryEntryID());
	if (!ref) {
		printf("%s ERROR: failed to get IOExclaveProxyState\n", __func__);
		return;
	}

	// Find timer ID
	ref->exclave_timers->iterateObjects(^bool (const OSSymbol * id, OSObject * obj)
	{
		if (obj == eventSource) {
		        found = true;
		        const char *key = id->getCStringNoCopy();
		        timer_id = (uint32_t) strtol(key, NULL, 0);
		        return true;
		}
		return false;
	});

	if (!found) {
		printf("%s ERROR: Could not find timer ID\n", __func__);
		return;
	}

	EXLOG("%s id 0x%llx (timer_id %u)\n", __func__, getRegistryEntryID(), timer_id);
	assert(ref->edk_endpoint_exists);
	tberr = ioservice_ioserviceprivate_timerfiredprivate(&ref->edk_client, timer_id);
	assert(TB_ERROR_SUCCESS == tberr);
	if (TB_ERROR_SUCCESS != tberr) {
		printf("%s ERROR: tightbeam call failed\n", __func__);
		return;
	}
#endif /* CONFIG_EXCLAVES */
}


kern_return_t
IOService::exclaveAsyncNotificationRegister(IOExclaveProxyState * pRef, IOInterruptEventSource *notification, uint32_t *notificationID)
{
#if CONFIG_EXCLAVES
	kern_return_t ret;
	if (notification == NULL) {
		return kIOReturnBadArgument;
	}

	IOLockLock(pRef->exclaveAsyncNotificationEventSourcesLock);
	if (!pRef->exclaveAsyncNotificationEventSources) {
		pRef->exclaveAsyncNotificationEventSources = OSArray::withCapacity(1);
	}
	if (pRef->exclaveAsyncNotificationEventSources) {
		*notificationID = (uint32_t) pRef->exclaveAsyncNotificationEventSources->getCount();
		pRef->exclaveAsyncNotificationEventSources->setObject(notification);
		ret = kIOReturnSuccess;
	} else {
		ret = kIOReturnNoMemory;
	}
	IOLockUnlock(pRef->exclaveAsyncNotificationEventSourcesLock);
	return ret;
#else
#pragma unused(pRef, notification, notificationID)
	return kIOReturnUnsupported;
#endif /* CONFIG_EXCLAVES*/
}

kern_return_t
IOService::exclaveAsyncNotificationSignal(IOExclaveProxyState * pRef, uint32_t notificationID)
{
#if CONFIG_EXCLAVES
	kern_return_t ret;
	IOInterruptEventSource *event;

	IOLockLock(pRef->exclaveAsyncNotificationEventSourcesLock);
	if (pRef->exclaveAsyncNotificationEventSources && (event = OSDynamicCast(IOInterruptEventSource, pRef->exclaveAsyncNotificationEventSources->getObject((unsigned int)notificationID)))) {
		event->interruptOccurred(NULL, NULL, 0);
		ret = kIOReturnSuccess;
	} else {
		ret = kIOReturnError;
	}
	IOLockUnlock(pRef->exclaveAsyncNotificationEventSourcesLock);
	return ret;
#else
#pragma unused(pRef, notificationID)
	return kIOReturnUnsupported;
#endif /* CONFIG_EXCLAVES */
}

#if CONFIG_EXCLAVES

void
exclaves_wait_for_cpu_init()
{
	OSDictionary *match_dict = IOService::resourceMatching(gIOAllCPUInitializedKey);
	IOService *match = IOService::waitForMatchingService(match_dict);
	match_dict->release();
	match->release();
}

/* ANE Upcalls */

static kern_return_t
exclaveRegisterANEUpcallHelper(IOService::IOExclaveProxyState * pRef, IOExclaveANEUpcallType type, IOWorkLoop *wl, void *block)
{
	void __block * _block = block;

	if (!_block) {
		return kIOReturnBadArgument;
	}

	if (!pRef) {
		Block_release(_block);
		return kIOReturnBadArgument;
	}

	if (wl != NULL) {
		return wl->runActionBlock(^{
			switch (type) {
			case kIOExclaveANEUpcallTypeSetPowerState:
				if (pRef->aneSetPowerStateUpcallHandler) {
				        Block_release(pRef->aneSetPowerStateUpcallHandler);
				}
				pRef->aneSetPowerStateUpcallHandler = (ANEUpcallSetPowerStateHandler) _block;
				break;
			case kIOExclaveANEUpcallTypeWorkSubmit:
				if (pRef->aneWorkSubmitUpcallHandler) {
				        Block_release(pRef->aneWorkSubmitUpcallHandler);
				}
				pRef->aneWorkSubmitUpcallHandler = (ANEUpcallWorkHandler) _block;
				break;
			case kIOExclaveANEUpcallTypeWorkBegin:
				if (pRef->aneWorkBeginUpcallHandler) {
				        Block_release(pRef->aneWorkBeginUpcallHandler);
				}
				pRef->aneWorkBeginUpcallHandler = (ANEUpcallWorkHandler) _block;
				break;
			case kIOExclaveANEUpcallTypeWorkEnd:
				if (pRef->aneWorkEndUpcallHandler) {
				        Block_release(pRef->aneWorkEndUpcallHandler);
				}
				pRef->aneWorkEndUpcallHandler = (ANEUpcallWorkHandler) _block;
				break;
			default:
				Block_release(_block);
				return kIOReturnBadArgument;
			}
			return kIOReturnSuccess;
		});
	} else {
		Block_release(_block);
		return kIOReturnError;
	}
}

#endif /* CONFIG_EXCLAVES */

kern_return_t
IOService::exclaveRegisterANEUpcallSetPowerState(IOExclaveProxyState * pRef, ANEUpcallSetPowerStateHandler handler)
{
#if CONFIG_EXCLAVES
	return exclaveRegisterANEUpcallHelper(pRef, kIOExclaveANEUpcallTypeSetPowerState, getWorkLoop(), Block_copy(handler));
#else
#pragma unused(pRef, handler)
	return kIOReturnUnsupported;
#endif /* CONFIG_EXCLAVES*/
}

kern_return_t
IOService::exclaveRegisterANEUpcallWorkSubmit(IOExclaveProxyState * pRef, ANEUpcallWorkHandler handler)
{
#if CONFIG_EXCLAVES
	return exclaveRegisterANEUpcallHelper(pRef, kIOExclaveANEUpcallTypeWorkSubmit, getWorkLoop(), Block_copy(handler));
#else
#pragma unused(pRef, handler)
	return kIOReturnUnsupported;
#endif /* CONFIG_EXCLAVES*/
}

kern_return_t
IOService::exclaveRegisterANEUpcallWorkBegin(IOExclaveProxyState * pRef, ANEUpcallWorkHandler handler)
{
#if CONFIG_EXCLAVES
	return exclaveRegisterANEUpcallHelper(pRef, kIOExclaveANEUpcallTypeWorkBegin, getWorkLoop(), Block_copy(handler));
#else
#pragma unused(pRef, handler)
	return kIOReturnUnsupported;
#endif /* CONFIG_EXCLAVES*/
}

kern_return_t
IOService::exclaveRegisterANEUpcallWorkEnd(IOExclaveProxyState * pRef, ANEUpcallWorkHandler handler)
{
#if CONFIG_EXCLAVES
	return exclaveRegisterANEUpcallHelper(pRef, kIOExclaveANEUpcallTypeWorkEnd, getWorkLoop(), Block_copy(handler));
#else
#pragma unused(pRef, handler)
	return kIOReturnUnsupported;
#endif /* CONFIG_EXCLAVES*/
}
