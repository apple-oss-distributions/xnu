/*
 * Copyright (c) 1998-2021 Apple Inc. All rights reserved.
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

#include <IOKit/IORPC.h>
#include <IOKit/IOKitServer.h>
#include <IOKit/IOKitKeysPrivate.h>
#include <IOKit/IOKernelReportStructs.h>
#include <IOKit/IOUserClient.h>
#include <IOKit/IOService.h>
#include <IOKit/IORegistryEntry.h>
#include <IOKit/IOCatalogue.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/IOSubMemoryDescriptor.h>
#include <IOKit/IOMultiMemoryDescriptor.h>
#include <IOKit/IOMapper.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOHibernatePrivate.h>
#include <IOKit/IOBSD.h>
#include <IOKit/system.h>
#include <IOKit/IOUserServer.h>
#include <IOKit/IOInterruptEventSource.h>
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/pwr_mgt/RootDomain.h>
#include <IOKit/pwr_mgt/IOPowerConnection.h>
#include <libkern/c++/OSAllocation.h>
#include <libkern/c++/OSKext.h>
#include <libkern/c++/OSSharedPtr.h>
#include <libkern/OSDebug.h>
#include <libkern/Block.h>
#include <kern/cs_blobs.h>
#include <kern/thread_call.h>
#include <os/atomic_private.h>
#include <sys/proc.h>
#include <sys/reboot.h>
#include <sys/codesign.h>
#include "IOKitKernelInternal.h"

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#include <DriverKit/IODispatchQueue.h>
#include <DriverKit/OSObject.h>
#include <DriverKit/OSAction.h>
#include <DriverKit/IODispatchSource.h>
#include <DriverKit/IOInterruptDispatchSource.h>
#include <DriverKit/IOService.h>
#include <DriverKit/IOMemoryDescriptor.h>
#include <DriverKit/IOBufferMemoryDescriptor.h>
#include <DriverKit/IOMemoryMap.h>
#include <DriverKit/IODataQueueDispatchSource.h>
#include <DriverKit/IOServiceNotificationDispatchSource.h>
#include <DriverKit/IOServiceStateNotificationDispatchSource.h>
#include <DriverKit/IOEventLink.h>
#include <DriverKit/IOWorkGroup.h>
#include <DriverKit/IOUserServer.h>

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#include <System/IODataQueueDispatchSourceShared.h>

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

TUNABLE(SInt64, gIODKDebug, "dk", kIODKEnable);

#if DEBUG || DEVELOPMENT
TUNABLE(bool, disable_dext_crash_reboot, "disable_dext_crash_reboot", 0);
#endif /* DEBUG || DEVELOPMENT */

static OSString       * gIOSystemStateSleepDescriptionKey;
static const OSSymbol * gIOSystemStateSleepDescriptionReasonKey;
static const OSSymbol * gIOSystemStateSleepDescriptionHibernateStateKey;

static OSString       * gIOSystemStateWakeDescriptionKey;
static const OSSymbol * gIOSystemStateWakeDescriptionWakeReasonKey;

static OSString       * gIOSystemStateHaltDescriptionKey;
static const OSSymbol * gIOSystemStateHaltDescriptionHaltStateKey;

static OSString       * gIOSystemStatePowerSourceDescriptionKey;
static const OSSymbol * gIOSystemStatePowerSourceDescriptionACAttachedKey;

extern bool gInUserspaceReboot;

extern void iokit_clear_registered_ports(task_t task);

static IORPCMessage *
IORPCMessageFromMachReply(IORPCMessageMach * msg);

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

struct IOPStrings;

class OSUserMetaClass : public OSObject
{
	OSDeclareDefaultStructors(OSUserMetaClass);
public:
	const OSSymbol    * name;
	const OSMetaClass * meta;
	OSUserMetaClass   * superMeta;

	queue_chain_t       link;

	OSClassDescription * description;
	IOPStrings * queueNames;
	uint32_t     methodCount;
	uint64_t   * methods;

	virtual void free() override;
	virtual kern_return_t Dispatch(const IORPC rpc) APPLE_KEXT_OVERRIDE;
};
OSDefineMetaClassAndStructors(OSUserMetaClass, OSObject);

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

class IOUserService : public IOService
{
	friend class IOService;

	OSDeclareDefaultStructors(IOUserService)

	virtual bool
	start(IOService * provider) APPLE_KEXT_OVERRIDE;
};

OSDefineMetaClassAndStructors(IOUserService, IOService)

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

class IOUserUserClient : public IOUserClient
{
	OSDeclareDefaultStructors(IOUserUserClient);
public:
	task_t          fTask;
	OSDictionary  * fWorkGroups;
	OSDictionary  * fEventLinks;
	IOLock        * fLock;

	IOReturn                   setTask(task_t task);
	IOReturn                   eventlinkConfigurationTrap(void * p1, void * p2, void * p3, void * p4, void * p5, void * p6);
	IOReturn                   workgroupConfigurationTrap(void * p1, void * p2, void * p3, void * p4, void * p5, void * p6);

	virtual bool           init( OSDictionary * dictionary ) APPLE_KEXT_OVERRIDE;
	virtual void           free() APPLE_KEXT_OVERRIDE;
	virtual void           stop(IOService * provider) APPLE_KEXT_OVERRIDE;
	virtual IOReturn       clientClose(void) APPLE_KEXT_OVERRIDE;
	virtual IOReturn       setProperties(OSObject * properties) APPLE_KEXT_OVERRIDE;
	virtual IOReturn       externalMethod(uint32_t selector, IOExternalMethodArguments * args,
	    IOExternalMethodDispatch * dispatch, OSObject * target, void * reference) APPLE_KEXT_OVERRIDE;
	virtual IOReturn           clientMemoryForType(UInt32 type,
	    IOOptionBits * options,
	    IOMemoryDescriptor ** memory) APPLE_KEXT_OVERRIDE;
	virtual IOExternalTrap * getTargetAndTrapForIndex( IOService **targetP, UInt32 index ) APPLE_KEXT_OVERRIDE;
};

OSDefineMetaClassAndStructors(IOUserServerCheckInToken, OSObject);
OSDefineMetaClassAndStructors(_IOUserServerCheckInCancellationHandler, OSObject);

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */


bool
IOUserService::start(IOService * provider)
{
	bool     ok = true;
	IOReturn ret;

	ret = Start(provider);
	if (kIOReturnSuccess != ret) {
		return false;
	}

	return ok;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#undef super

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

struct IODispatchQueue_IVars {
	IOUserServer * userServer;
	IODispatchQueue   * queue;
	queue_chain_t  link;
	uint64_t       tid;

	mach_port_t    serverPort;
};

struct OSAction_IVars {
	OSObject             * target;
	uint64_t               targetmsgid;
	uint64_t               msgid;
	IOUserServer         * userServer;
	OSActionAbortedHandler abortedHandler;
	OSString             * typeName;
	void                 * reference;
	size_t                 referenceSize;
	bool                   aborted;
};

struct IOWorkGroup_IVars {
	IOUserServer * userServer;
	OSString * name;
	IOUserUserClient * userClient;
};

struct IOEventLink_IVars {
	IOUserServer * userServer;
	OSString * name;
	IOUserUserClient * userClient;
};

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

kern_return_t
IOService::GetRegistryEntryID_Impl(
	uint64_t * registryEntryID)
{
	IOReturn ret = kIOReturnSuccess;

	*registryEntryID = getRegistryEntryID();

	return ret;
}

kern_return_t
IOService::SetName_Impl(
	const char * name)
{
	IOReturn ret = kIOReturnSuccess;

	setName(name);

	return ret;
}

kern_return_t
IOService::CopyName_Impl(
	OSString ** name)
{
	const OSString * str = copyName();
	*name = __DECONST(OSString *, str);
	return str ? kIOReturnSuccess : kIOReturnError;
}


kern_return_t
IOService::Start_Impl(
	IOService * provider)
{
	IOReturn ret = kIOReturnSuccess;
	return ret;
}


IOReturn
IOService::UpdateReport_Impl(OSData *channels, uint32_t action,
    uint32_t *outElementCount,
    uint64_t offset, uint64_t capacity,
    IOMemoryDescriptor *buffer)
{
	return kIOReturnUnsupported;
}

IOReturn
IOService::ConfigureReport_Impl(OSData *channels, uint32_t action, uint32_t *outCount)
{
	return kIOReturnUnsupported;
}

// adapt old signature of configureReport to the iig-friendly signature of ConfigureReport
IOReturn
IOService::_ConfigureReport(IOReportChannelList    *channelList,
    IOReportConfigureAction action,
    void                   *result,
    void                   *destination)
{
	if (action != kIOReportEnable && action != kIOReportGetDimensions && action != kIOReportDisable) {
		return kIOReturnUnsupported;
	}
	static_assert(sizeof(IOReportChannelList) == 8);
	static_assert(sizeof(IOReportChannel) == 16);
	unsigned int size_of_channels;
	bool overflow = os_mul_and_add_overflow(channelList->nchannels, sizeof(IOReportChannel), sizeof(IOReportChannelList), &size_of_channels);
	if (overflow) {
		return kIOReturnOverrun;
	}
	OSSharedPtr<OSData> sp_channels(OSData::withBytesNoCopy(channelList, size_of_channels), libkern::no_retain);
	if (!sp_channels) {
		return kIOReturnNoMemory;
	}
	int *resultp = (int*) result;
	uint32_t count = 0;
	IOReturn r = ConfigureReport(sp_channels.get(), action, &count);
	int new_result;
	overflow = os_add_overflow(*resultp, count, &new_result);
	if (overflow) {
		return kIOReturnOverrun;
	}
	*resultp = new_result;
	return r;
}

// adapt old signature of updateReport to the iig-friendly signature of UpdateReport
IOReturn
IOService::_UpdateReport(IOReportChannelList      *channelList,
    IOReportUpdateAction      action,
    void                     *result,
    void                     *destination)
{
	if (action != kIOReportCopyChannelData) {
		return kIOReturnUnsupported;
	}
	unsigned int size_of_channels;
	bool overflow = os_mul_and_add_overflow(channelList->nchannels, sizeof(IOReportChannel), sizeof(IOReportChannelList), &size_of_channels);
	if (overflow) {
		return kIOReturnOverrun;
	}
	OSSharedPtr<OSData> sp_channels(OSData::withBytesNoCopy(channelList, size_of_channels), libkern::no_retain);
	if (!sp_channels) {
		return kIOReturnNoMemory;
	}
	int *resultp = (int*) result;
	uint32_t count = 0;
	auto buffer = (IOBufferMemoryDescriptor*) destination;
	uint64_t length = buffer->getLength();
	buffer->setLength(buffer->getCapacity());
	IOReturn r = UpdateReport(sp_channels.get(), action, &count, length, buffer->getCapacity() - length, buffer);
	int new_result;
	overflow = os_add_overflow(*resultp, count, &new_result);
	size_t new_length;
	overflow = overflow || os_mul_and_add_overflow(count, sizeof(IOReportElement), length, &new_length);
	if (overflow || new_length > buffer->getCapacity()) {
		buffer->setLength(length);
		return kIOReturnOverrun;
	}
	*resultp = new_result;
	buffer->setLength(new_length);
	return r;
}


IOReturn
IOService::SetLegend_Impl(OSArray *legend, bool is_public)
{
	bool ok = setProperty(kIOReportLegendKey, legend);
	ok = ok && setProperty(kIOReportLegendPublicKey, is_public);
	return ok ? kIOReturnSuccess : kIOReturnError;
}


kern_return_t
IOService::RegisterService_Impl()
{
	IOReturn ret = kIOReturnSuccess;
	bool started;

	IOUserServer *us = (typeof(us))thread_iokit_tls_get(0);
	if (reserved != NULL && reserved->uvars != NULL && reserved->uvars->userServer == us) {
		started = reserved->uvars->started;
	} else {
		// assume started
		started = true;
	}

	if (OSDynamicCast(IOUserServer, this) != NULL || started) {
		registerService(kIOServiceAsynchronous);
	} else {
		assert(reserved != NULL && reserved->uvars != NULL);
		reserved->uvars->deferredRegisterService = true;
	}

	return ret;
}

kern_return_t
IOService::CopyDispatchQueue_Impl(
	const char * name,
	IODispatchQueue ** queue)
{
	IODispatchQueue * result;
	IOService  * service;
	IOReturn     ret;
	uint32_t index;

	if (!reserved->uvars) {
		return kIOReturnError;
	}

	if (!reserved->uvars->queueArray) {
		// CopyDispatchQueue should not be called after the service has stopped
		return kIOReturnError;
	}

	ret = kIOReturnNotFound;
	index = -1U;
	if (!strcmp("Default", name)) {
		index = 0;
	} else if (reserved->uvars->userMeta
	    && reserved->uvars->userMeta->queueNames) {
		index = reserved->uvars->userServer->stringArrayIndex(reserved->uvars->userMeta->queueNames, name);
		if (index != -1U) {
			index++;
		}
	}
	if (index == -1U) {
		if ((service = getProvider())) {
			ret = service->CopyDispatchQueue(name, queue);
		}
	} else {
		result = reserved->uvars->queueArray[index];
		if (result) {
			result->retain();
			*queue = result;
			ret = kIOReturnSuccess;
		}
	}

	return ret;
}

kern_return_t
IOService::CreateDefaultDispatchQueue_Impl(
	IODispatchQueue ** queue)
{
	return kIOReturnError;
}

kern_return_t
IOService::CoreAnalyticsSendEvent_Impl(
	uint64_t       options,
	OSString     * eventName,
	OSDictionary * eventPayload)
{
	kern_return_t ret;

	if (NULL == gIOCoreAnalyticsSendEventProc) {
		// perhaps save for later?
		return kIOReturnNotReady;
	}

	ret = (*gIOCoreAnalyticsSendEventProc)(options, eventName, eventPayload);

	return ret;
}

kern_return_t
IOService::SetDispatchQueue_Impl(
	const char * name,
	IODispatchQueue * queue)
{
	IOReturn ret = kIOReturnSuccess;
	uint32_t index;

	if (!reserved->uvars) {
		return kIOReturnError;
	}

	if (kIODKLogSetup & gIODKDebug) {
		DKLOG(DKS "::SetDispatchQueue(%s)\n", DKN(this), name);
	}
	queue->ivars->userServer = reserved->uvars->userServer;
	index = -1U;
	if (!strcmp("Default", name)) {
		index = 0;
	} else if (reserved->uvars->userMeta
	    && reserved->uvars->userMeta->queueNames) {
		index = reserved->uvars->userServer->stringArrayIndex(reserved->uvars->userMeta->queueNames, name);
		if (index != -1U) {
			index++;
		}
	}
	if (index == -1U) {
		ret = kIOReturnBadArgument;
	} else {
		reserved->uvars->queueArray[index] = queue;
		queue->retain();
	}

	return ret;
}

IOService *
IOService::GetProvider() const
{
	return getProvider();
}

kern_return_t
IOService::SetProperties_Impl(
	OSDictionary * properties)
{
	IOUserServer   * us;
	OSDictionary   * dict;
	IOReturn         ret;

	us = (typeof(us))thread_iokit_tls_get(0);
	dict = OSDynamicCast(OSDictionary, properties);
	if (NULL == us) {
		if (!dict) {
			return kIOReturnBadArgument;
		}
		bool ok __block = true;
		dict->iterateObjects(^bool (const OSSymbol * key, OSObject * value) {
			ok = setProperty(key, value);
			return !ok;
		});
		ret = ok ? kIOReturnSuccess : kIOReturnNotWritable;
		return ret;
	}

	ret = setProperties(properties);

	if (kIOReturnUnsupported == ret) {
		if (dict && reserved->uvars && (reserved->uvars->userServer == us)) {
			ret = runPropertyActionBlock(^IOReturn (void) {
				OSDictionary   * userProps;
				IOReturn         ret;

				userProps = OSDynamicCast(OSDictionary, getProperty(gIOUserServicePropertiesKey));
				if (userProps) {
				        userProps = (typeof(userProps))userProps->copyCollection();
				} else {
				        userProps = OSDictionary::withCapacity(4);
				}
				if (!userProps) {
				        ret = kIOReturnNoMemory;
				} else {
				        bool ok = userProps->merge(dict);
				        if (ok) {
				                ok = setProperty(gIOUserServicePropertiesKey, userProps);
					}
				        OSSafeReleaseNULL(userProps);
				        ret = ok ? kIOReturnSuccess : kIOReturnNotWritable;
				}
				return ret;
			});
		}
	}

	return ret;
}

kern_return_t
IOService::RemoveProperty_Impl(OSString * propertyName)
{
	IOUserServer * us  = (IOUserServer *)thread_iokit_tls_get(0);
	IOReturn       ret = kIOReturnUnsupported;

	if (NULL == propertyName) {
		return kIOReturnUnsupported;
	}
	if (NULL == us) {
		removeProperty(propertyName);
		return kIOReturnSuccess;
	}
	if (reserved && reserved->uvars && reserved->uvars->userServer == us) {
		ret = runPropertyActionBlock(^IOReturn (void) {
			OSDictionary * userProps;
			userProps = OSDynamicCast(OSDictionary, getProperty(gIOUserServicePropertiesKey));
			if (userProps) {
			        userProps = (OSDictionary *)userProps->copyCollection();
			        if (!userProps) {
			                return kIOReturnNoMemory;
				}
			        userProps->removeObject(propertyName);
			        bool ok = setProperty(gIOUserServicePropertiesKey, userProps);
			        OSSafeReleaseNULL(userProps);
			        return ok ? kIOReturnSuccess : kIOReturnNotWritable;
			} else {
			        return kIOReturnNotFound;
			}
		});
	}
	return ret;
}

kern_return_t
IOService::CopyProperties_Local(
	OSDictionary ** properties)
{
	OSDictionary * props;
	OSDictionary * userProps;

	props = dictionaryWithProperties();
	userProps = OSDynamicCast(OSDictionary, props->getObject(gIOUserServicePropertiesKey));
	if (userProps) {
		props->merge(userProps);
		props->removeObject(gIOUserServicePropertiesKey);
	}

	*properties = props;

	return props ? kIOReturnSuccess : kIOReturnNoMemory;
}

kern_return_t
IOService::CopyProperties_Impl(
	OSDictionary ** properties)
{
	return CopyProperties_Local(properties);
}

kern_return_t
IOService::RequireMaxBusStall_Impl(
	uint64_t u64ns)
{
	IOReturn ret;
	UInt32   ns;

	if (os_convert_overflow(u64ns, &ns)) {
		return kIOReturnBadArgument;
	}
	ret = requireMaxBusStall(ns);

	return ret;
}

#if PRIVATE_WIFI_ONLY
kern_return_t
IOService::UserSetProperties_Impl(
	OSContainer * properties)
{
	return kIOReturnUnsupported;
}

kern_return_t
IOService::SendIOMessageServicePropertyChange_Impl(void)
{
	return messageClients(kIOMessageServicePropertyChange);
}
#endif /* PRIVATE_WIFI_ONLY */

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

kern_return_t
IOMemoryDescriptor::_CopyState_Impl(
	_IOMDPrivateState * state)
{
	IOReturn ret;

	state->length = _length;
	state->options = _flags;

	ret = kIOReturnSuccess;

	return ret;
}

kern_return_t
IOMemoryDescriptor::GetLength(uint64_t * returnLength)
{
	*returnLength = getLength();

	return kIOReturnSuccess;
}

kern_return_t
IOMemoryDescriptor::CreateMapping_Impl(
	uint64_t options,
	uint64_t address,
	uint64_t offset,
	uint64_t length,
	uint64_t alignment,
	IOMemoryMap ** map)
{
	IOReturn          ret;
	IOMemoryMap     * resultMap;
	IOOptionBits      koptions;
	mach_vm_address_t atAddress;

	ret       = kIOReturnSuccess;
	koptions  = 0;
	resultMap = NULL;

	if (kIOMemoryMapFixedAddress & options) {
		atAddress   = address;
		koptions    = 0;
	} else {
		switch (kIOMemoryMapGuardedMask & options) {
		default:
		case kIOMemoryMapGuardedDefault:
			koptions |= kIOMapGuardedSmall;
			break;
		case kIOMemoryMapGuardedNone:
			break;
		case kIOMemoryMapGuardedSmall:
			koptions |= kIOMapGuardedSmall;
			break;
		case kIOMemoryMapGuardedLarge:
			koptions |= kIOMapGuardedLarge;
			break;
		}
		atAddress   = 0;
		koptions   |= kIOMapAnywhere;
	}

	if ((kIOMemoryMapReadOnly & options) || (kIODirectionOut == getDirection())) {
		if (!reserved || (current_task() != reserved->creator)) {
			koptions   |= kIOMapReadOnly;
		}
	}

	switch (0xFF00 & options) {
	case kIOMemoryMapCacheModeDefault:
		koptions |= kIOMapDefaultCache;
		break;
	case kIOMemoryMapCacheModeInhibit:
		koptions |= kIOMapInhibitCache;
		break;
	case kIOMemoryMapCacheModeCopyback:
		koptions |= kIOMapCopybackCache;
		break;
	case kIOMemoryMapCacheModeWriteThrough:
		koptions |= kIOMapWriteThruCache;
		break;
	default:
		ret = kIOReturnBadArgument;
	}

	if (kIOReturnSuccess == ret) {
		resultMap = createMappingInTask(current_task(), atAddress, koptions, offset, length);
		if (!resultMap) {
			ret = kIOReturnError;
		}
	}

	*map = resultMap;

	return ret;
}

kern_return_t
IOMemoryDescriptor::CreateSubMemoryDescriptor_Impl(
	uint64_t memoryDescriptorCreateOptions,
	uint64_t offset,
	uint64_t length,
	IOMemoryDescriptor * ofDescriptor,
	IOMemoryDescriptor ** memory)
{
	IOReturn             ret;
	IOMemoryDescriptor * iomd;
	IOByteCount          mdOffset;
	IOByteCount          mdLength;
	IOByteCount          mdEnd;

	if (!ofDescriptor) {
		return kIOReturnBadArgument;
	}
	if (memoryDescriptorCreateOptions & ~kIOMemoryDirectionOutIn) {
		return kIOReturnBadArgument;
	}
	if (os_convert_overflow(offset, &mdOffset)) {
		return kIOReturnBadArgument;
	}
	if (os_convert_overflow(length, &mdLength)) {
		return kIOReturnBadArgument;
	}
	if (os_add_overflow(mdOffset, mdLength, &mdEnd)) {
		return kIOReturnBadArgument;
	}
	if (mdEnd > ofDescriptor->getLength()) {
		return kIOReturnBadArgument;
	}

	iomd = IOSubMemoryDescriptor::withSubRange(
		ofDescriptor, mdOffset, mdLength, (IOOptionBits) memoryDescriptorCreateOptions);

	if (iomd) {
		ret = kIOReturnSuccess;
		*memory = iomd;
	} else {
		ret = kIOReturnNoMemory;
		*memory = NULL;
	}

	return ret;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

kern_return_t
IOMemoryDescriptor::CreateWithMemoryDescriptors_Impl(
	uint64_t memoryDescriptorCreateOptions,
	uint32_t withDescriptorsCount,
	IOMemoryDescriptor ** const withDescriptors,
	IOMemoryDescriptor ** memory)
{
	IOReturn             ret;
	IOMemoryDescriptor * iomd;

	if (!withDescriptors) {
		return kIOReturnBadArgument;
	}
	if (!withDescriptorsCount) {
		return kIOReturnBadArgument;
	}
	if (memoryDescriptorCreateOptions & ~kIOMemoryDirectionOutIn) {
		return kIOReturnBadArgument;
	}

	for (unsigned int idx = 0; idx < withDescriptorsCount; idx++) {
		if (NULL == withDescriptors[idx]) {
			return kIOReturnBadArgument;
		}
	}

	iomd = IOMultiMemoryDescriptor::withDescriptors(withDescriptors, withDescriptorsCount,
	    (IODirection) memoryDescriptorCreateOptions, false);

	if (iomd) {
		ret = kIOReturnSuccess;
		*memory = iomd;
	} else {
		ret = kIOReturnNoMemory;
		*memory = NULL;
	}

	return ret;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *  * * * * * * * * * * * * * * * * * * * */

kern_return_t
IOUserClient::CreateMemoryDescriptorFromClient_Impl(
	uint64_t memoryDescriptorCreateOptions,
	uint32_t segmentsCount,
	const IOAddressSegment segments[32],
	IOMemoryDescriptor ** memory)
{
	IOReturn             ret;
	IOMemoryDescriptor * iomd;
	IOOptionBits         mdOptions;
	IOUserUserClient   * me;
	IOAddressRange     * ranges;

	me = OSDynamicCast(IOUserUserClient, this);
	if (!me) {
		return kIOReturnBadArgument;
	}
	if (!me->fTask) {
		return kIOReturnNotReady;
	}

	mdOptions = kIOMemoryThreadSafe;
	if (kIOMemoryDirectionOut & memoryDescriptorCreateOptions) {
		mdOptions |= kIODirectionOut;
	}
	if (kIOMemoryDirectionIn & memoryDescriptorCreateOptions) {
		mdOptions |= kIODirectionIn;
	}
	if (!(kIOMemoryDisableCopyOnWrite & memoryDescriptorCreateOptions)) {
		mdOptions |= kIOMemoryMapCopyOnWrite;
	}

	static_assert(sizeof(IOAddressRange) == sizeof(IOAddressSegment));
	ranges = __DECONST(IOAddressRange *, &segments[0]);

	iomd = IOMemoryDescriptor::withAddressRanges(
		ranges, segmentsCount,
		mdOptions, me->fTask);

	if (iomd) {
		ret = kIOReturnSuccess;
		*memory = iomd;
	} else {
		ret = kIOReturnNoMemory;
		*memory = NULL;
	}

	return ret;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

kern_return_t
IOMemoryMap::_CopyState_Impl(
	_IOMemoryMapPrivateState * state)
{
	IOReturn ret;

	state->offset  = fOffset;
	state->length  = getLength();
	state->address = getAddress();
	state->options = getMapOptions();

	ret = kIOReturnSuccess;

	return ret;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

kern_return_t
IOBufferMemoryDescriptor::Create_Impl(
	uint64_t options,
	uint64_t capacity,
	uint64_t alignment,
	IOBufferMemoryDescriptor ** memory)
{
	IOReturn ret;
	IOOptionBits                 bmdOptions;
	IOBufferMemoryDescriptor   * bmd;
	IOMemoryDescriptorReserved * reserved;

	if (options & ~((uint64_t) kIOMemoryDirectionOutIn)) {
		// no other options currently defined
		return kIOReturnBadArgument;
	}
	bmdOptions = (options & kIOMemoryDirectionOutIn) | kIOMemoryKernelUserShared | kIOMemoryThreadSafe;
	bmd = IOBufferMemoryDescriptor::inTaskWithOptions(
		kernel_task, bmdOptions, capacity, alignment);

	*memory = bmd;

	if (!bmd) {
		return kIOReturnNoMemory;
	}

	reserved = bmd->getKernelReserved();
	reserved->creator = current_task();
	task_reference(reserved->creator);

	ret = kIOReturnSuccess;

	return ret;
}

kern_return_t
IOBufferMemoryDescriptor::SetLength_Impl(
	uint64_t length)
{
	setLength(length);
	return kIOReturnSuccess;
}


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

kern_return_t
IODMACommand::Create_Impl(
	IOService * device,
	uint64_t options,
	const IODMACommandSpecification * specification,
	IODMACommand ** command)
{
	IOReturn ret;
	IODMACommand   * dma;
	IODMACommand::SegmentOptions segmentOptions;
	IOMapper             * mapper;

	if (options & ~((uint64_t) kIODMACommandCreateNoOptions)) {
		// no other options currently defined
		return kIOReturnBadArgument;
	}

	if (os_convert_overflow(specification->maxAddressBits, &segmentOptions.fNumAddressBits)) {
		return kIOReturnBadArgument;
	}
	segmentOptions.fMaxSegmentSize            = 0;
	segmentOptions.fMaxTransferSize           = 0;
	segmentOptions.fAlignment                 = 1;
	segmentOptions.fAlignmentLength           = 1;
	segmentOptions.fAlignmentInternalSegments = 1;
	segmentOptions.fStructSize                = sizeof(segmentOptions);

	mapper = IOMapper::copyMapperForDevice(device);

	dma = IODMACommand::withSpecification(
		kIODMACommandOutputHost64,
		&segmentOptions,
		kIODMAMapOptionDextOwner |
		kIODMAMapOptionMapped,
		mapper,
		NULL);

	OSSafeReleaseNULL(mapper);
	*command = dma;

	if (!dma) {
		return kIOReturnNoMemory;
	}
	ret = kIOReturnSuccess;

	return ret;
}

#define fInternalState reserved

kern_return_t
IODMACommand::PrepareForDMA_Impl(
	uint64_t options,
	IOMemoryDescriptor * memory,
	uint64_t offset,
	uint64_t length,
	uint64_t * flags,
	uint32_t * segmentsCount,
	IOAddressSegment * segments)
{
	IOReturn ret;
	uint64_t lflags, mdFlags;
	UInt32   numSegments;
	UInt64   genOffset;

	if (options & ~((uint64_t) kIODMACommandPrepareForDMANoOptions)) {
		// no other options currently defined
		return kIOReturnBadArgument;
	}

	if (memory == NULL) {
		return kIOReturnBadArgument;
	}

	assert(fInternalState->fDextLock);
	IOLockLock(fInternalState->fDextLock);

	// uses IOMD direction
	ret = memory->prepare();
	if (kIOReturnSuccess != ret) {
		goto exit;
	}

	ret = setMemoryDescriptor(memory, false);
	if (kIOReturnSuccess != ret) {
		memory->complete();
		goto exit;
	}

	ret = prepare(offset, length);
	if (kIOReturnSuccess != ret) {
		clearMemoryDescriptor(false);
		memory->complete();
		goto exit;
	}

	static_assert(sizeof(IODMACommand::Segment64) == sizeof(IOAddressSegment));

	numSegments = *segmentsCount;
	genOffset   = 0;
	ret = genIOVMSegments(&genOffset, segments, &numSegments);

	if (kIOReturnSuccess != ret) {
		clearMemoryDescriptor(true);
		memory->complete();
		goto exit;
	}

	mdFlags = fMemory->getFlags();
	lflags  = 0;
	if (kIODirectionOut & mdFlags) {
		lflags |= kIOMemoryDirectionOut;
	}
	if (kIODirectionIn & mdFlags) {
		lflags |= kIOMemoryDirectionIn;
	}
	*flags = lflags;
	*segmentsCount = numSegments;

exit:
	IOLockUnlock(fInternalState->fDextLock);

	return ret;
}

kern_return_t
IODMACommand::CompleteDMA_Impl(
	uint64_t options)
{
	IOReturn ret, completeRet;
	IOMemoryDescriptor * md;

	if (options & ~((uint64_t) kIODMACommandCompleteDMANoOptions)) {
		// no other options currently defined
		return kIOReturnBadArgument;
	}

	assert(fInternalState->fDextLock);
	IOLockLock(fInternalState->fDextLock);

	if (!fInternalState->fPrepared) {
		ret = kIOReturnNotReady;
		goto exit;
	}

	md = __DECONST(IOMemoryDescriptor *, fMemory);
	if (md) {
		md->retain();
	}

	ret = clearMemoryDescriptor(true);

	if (md) {
		completeRet = md->complete();
		OSSafeReleaseNULL(md);
		if (kIOReturnSuccess == ret) {
			ret = completeRet;
		}
	}
exit:
	IOLockUnlock(fInternalState->fDextLock);

	return ret;
}

kern_return_t
IODMACommand::GetPreparation_Impl(
	uint64_t * offset,
	uint64_t * length,
	IOMemoryDescriptor ** memory)
{
	IOReturn ret;
	IOMemoryDescriptor * md;

	if (!fActive) {
		return kIOReturnNotReady;
	}

	ret = getPreparedOffsetAndLength(offset, length);
	if (kIOReturnSuccess != ret) {
		return ret;
	}

	if (memory) {
		md = __DECONST(IOMemoryDescriptor *, fMemory);
		*memory = md;
		if (!md) {
			ret = kIOReturnNotReady;
		} else {
			md->retain();
		}
	}
	return ret;
}

kern_return_t
IODMACommand::PerformOperation_Impl(
	uint64_t options,
	uint64_t dmaOffset,
	uint64_t length,
	uint64_t dataOffset,
	IOMemoryDescriptor * data)
{
	IOReturn ret;
	OSDataAllocation<uint8_t> buffer;
	UInt64 copiedDMA;
	IOByteCount mdOffset, mdLength, copied;

	if (options & ~((uint64_t)
	    (kIODMACommandPerformOperationOptionRead
	    | kIODMACommandPerformOperationOptionWrite
	    | kIODMACommandPerformOperationOptionZero))) {
		// no other options currently defined
		return kIOReturnBadArgument;
	}

	if (!fActive) {
		return kIOReturnNotReady;
	}
	if (os_convert_overflow(dataOffset, &mdOffset)) {
		return kIOReturnBadArgument;
	}
	if (os_convert_overflow(length, &mdLength)) {
		return kIOReturnBadArgument;
	}
	if (length > fMemory->getLength()) {
		return kIOReturnBadArgument;
	}
	buffer = OSDataAllocation<uint8_t>(length, OSAllocateMemory);
	if (!buffer) {
		return kIOReturnNoMemory;
	}

	switch (options) {
	case kIODMACommandPerformOperationOptionZero:
		bzero(buffer.data(), length);
		copiedDMA = writeBytes(dmaOffset, buffer.data(), length);
		if (copiedDMA != length) {
			ret = kIOReturnUnderrun;
			break;
		}
		ret = kIOReturnSuccess;
		break;

	case kIODMACommandPerformOperationOptionRead:
	case kIODMACommandPerformOperationOptionWrite:

		if (!data) {
			ret = kIOReturnBadArgument;
			break;
		}
		if (length > data->getLength()) {
			ret = kIOReturnBadArgument;
			break;
		}
		if (kIODMACommandPerformOperationOptionWrite == options) {
			copied = data->readBytes(mdOffset, buffer.data(), mdLength);
			if (copied != mdLength) {
				ret = kIOReturnUnderrun;
				break;
			}
			copiedDMA = writeBytes(dmaOffset, buffer.data(), length);
			if (copiedDMA != length) {
				ret = kIOReturnUnderrun;
				break;
			}
		} else {       /* kIODMACommandPerformOperationOptionRead */
			copiedDMA = readBytes(dmaOffset, buffer.data(), length);
			if (copiedDMA != length) {
				ret = kIOReturnUnderrun;
				break;
			}
			copied = data->writeBytes(mdOffset, buffer.data(), mdLength);
			if (copied != mdLength) {
				ret = kIOReturnUnderrun;
				break;
			}
		}
		ret = kIOReturnSuccess;
		break;
	default:
		ret = kIOReturnBadArgument;
		break;
	}

	return ret;
}


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static kern_return_t
OSActionCreateWithTypeNameInternal(OSObject * target, uint64_t targetmsgid, uint64_t msgid, size_t referenceSize, OSString * typeName, bool fromKernel, OSAction ** action)
{
	OSAction * inst = NULL;
	void * reference = NULL; // must release
	const OSSymbol *sym = NULL; // must release
	OSObject *obj = NULL; // must release
	const OSMetaClass *actionMetaClass = NULL; // do not release
	kern_return_t ret;

	if (fromKernel && typeName) {
		/* The action is being constructed in the kernel with a type name */
		sym = OSSymbol::withString(typeName);
		actionMetaClass = OSMetaClass::getMetaClassWithName(sym);
		if (actionMetaClass && actionMetaClass->getSuperClass() == OSTypeID(OSAction)) {
			obj = actionMetaClass->alloc();
			if (!obj) {
				ret = kIOReturnNoMemory;
				goto finish;
			}
			inst = OSDynamicCast(OSAction, obj);
			obj = NULL; // prevent release
			assert(inst); // obj is a subclass of OSAction so the dynamic cast should always work
		} else {
			DKLOG("Attempted to create action object with type \"%s\" which does not inherit from OSAction\n", typeName->getCStringNoCopy());
			ret = kIOReturnBadArgument;
			goto finish;
		}
	} else {
		inst = OSTypeAlloc(OSAction);
		if (!inst) {
			ret = kIOReturnNoMemory;
			goto finish;
		}
	}

	if (referenceSize != 0) {
		reference = IONewZeroData(uint8_t, referenceSize);
		if (reference == NULL) {
			ret = kIOReturnNoMemory;
			goto finish;
		}
	}

	inst->ivars = IONewZero(OSAction_IVars, 1);
	if (!inst->ivars) {
		ret = kIOReturnNoMemory;
		goto finish;
	}
	if (target) {
		target->retain();
		if (!fromKernel && !OSDynamicCast(IOService, target)) {
			IOUserServer * us;
			us = (typeof(us))thread_iokit_tls_get(0);
			inst->ivars->userServer = OSDynamicCast(IOUserServer, us);
			assert(inst->ivars->userServer);
			inst->ivars->userServer->retain();
		}
	}
	inst->ivars->target        = target;
	inst->ivars->targetmsgid   = targetmsgid;
	inst->ivars->msgid         = msgid;

	inst->ivars->reference     = reference;
	inst->ivars->referenceSize = referenceSize;
	reference = NULL; // prevent release

	if (typeName) {
		typeName->retain();
	}
	inst->ivars->typeName      = typeName;

	*action = inst;
	inst = NULL; // prevent release
	ret = kIOReturnSuccess;

finish:
	OSSafeReleaseNULL(obj);
	OSSafeReleaseNULL(sym);
	OSSafeReleaseNULL(inst);
	if (reference) {
		IODeleteData(reference, uint8_t, referenceSize);
	}

	return ret;
}

kern_return_t
OSAction::Create(OSAction_Create_Args)
{
	return OSAction::CreateWithTypeName(target, targetmsgid, msgid, referenceSize, NULL, action);
}

kern_return_t
OSAction::CreateWithTypeName(OSAction_CreateWithTypeName_Args)
{
	return OSActionCreateWithTypeNameInternal(target, targetmsgid, msgid, referenceSize, typeName, true, action);
}

kern_return_t
OSAction::Create_Impl(
	OSObject * target,
	uint64_t targetmsgid,
	uint64_t msgid,
	size_t referenceSize,
	OSAction ** action)
{
	return OSAction::CreateWithTypeName_Impl(target, targetmsgid, msgid, referenceSize, NULL, action);
}

kern_return_t
OSAction::CreateWithTypeName_Impl(
	OSObject * target,
	uint64_t targetmsgid,
	uint64_t msgid,
	size_t referenceSize,
	OSString * typeName,
	OSAction ** action)
{
	return OSActionCreateWithTypeNameInternal(target, targetmsgid, msgid, referenceSize, typeName, false, action);
}

void
OSAction::free()
{
	if (ivars) {
		if (ivars->abortedHandler) {
			Block_release(ivars->abortedHandler);
			ivars->abortedHandler = NULL;
		}
		OSSafeReleaseNULL(ivars->target);
		OSSafeReleaseNULL(ivars->typeName);
		OSSafeReleaseNULL(ivars->userServer);
		if (ivars->reference) {
			assert(ivars->referenceSize > 0);
			IODeleteData(ivars->reference, uint8_t, ivars->referenceSize);
		}
		IOSafeDeleteNULL(ivars, OSAction_IVars, 1);
	}
	return super::free();
}

void *
OSAction::GetReference()
{
	assert(ivars && ivars->referenceSize && ivars->reference);
	return ivars->reference;
}

kern_return_t
OSAction::SetAbortedHandler(OSActionAbortedHandler handler)
{
	ivars->abortedHandler = Block_copy(handler);
	return kIOReturnSuccess;
}

void
OSAction::Aborted_Impl(void)
{
	if (!os_atomic_cmpxchg(&ivars->aborted, false, true, relaxed)) {
		// already aborted
		return;
	}
	if (ivars->abortedHandler) {
		ivars->abortedHandler();
	}
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

struct IODispatchSource_IVars {
	queue_chain_t           link;
	IODispatchSource      * source;
	IOUserServer          * server;
	IODispatchQueue_IVars * queue;
	bool                    enabled;
};

bool
IODispatchSource::init()
{
	if (!super::init()) {
		return false;
	}

	ivars = IOMallocType(IODispatchSource_IVars);

	ivars->source = this;

	return true;
}

void
IODispatchSource::free()
{
	IOFreeType(ivars, IODispatchSource_IVars);
	super::free();
}

kern_return_t
IODispatchSource::SetEnable_Impl(
	bool enable)
{
	return SetEnableWithCompletion(enable, NULL);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

struct IOInterruptDispatchSource_IVars {
	IOService    * provider;
	uint32_t       intIndex;
	uint32_t       flags;
	int            interruptType;
	IOSimpleLock * lock;
	thread_t       waiter;
	uint64_t       count;
	uint64_t       time;
	OSAction     * action;
	bool           enable;
	bool           canceled;
};

static void
IOInterruptDispatchSourceInterrupt(OSObject * target, void * refCon,
    IOService * nub, int source )
{
	IOInterruptDispatchSource_IVars * ivars = (typeof(ivars))refCon;
	IOInterruptState is;

	is = IOSimpleLockLockDisableInterrupt(ivars->lock);
	ivars->count++;
	ivars->time = (kIOInterruptSourceContinuousTime & ivars->flags)
	    ? mach_continuous_time() : mach_absolute_time();
	if (ivars->waiter) {
		thread_wakeup_thread((event_t) ivars, ivars->waiter);
		ivars->waiter = NULL;
	}
	if (kIOInterruptTypeLevel & ivars->interruptType) {
		ivars->provider->disableInterrupt(ivars->intIndex);
	}
	IOSimpleLockUnlockEnableInterrupt(ivars->lock, is);
}

kern_return_t
IOInterruptDispatchSource::Create_Impl(
	IOService * provider,
	uint32_t indexAndFlags,
	IODispatchQueue * queue,
	IOInterruptDispatchSource ** source)
{
	IOReturn ret;
	IOInterruptDispatchSource * inst;
	uint32_t index;
	uint32_t flags;

	index = indexAndFlags & kIOInterruptSourceIndexMask;
	flags = indexAndFlags & ~kIOInterruptSourceIndexMask;

	inst = OSTypeAlloc(IOInterruptDispatchSource);
	if (!inst->init()) {
		inst->free();
		return kIOReturnNoMemory;
	}

	inst->ivars->lock = IOSimpleLockAlloc();

	ret = provider->getInterruptType(index, &inst->ivars->interruptType);
	if (kIOReturnSuccess != ret) {
		OSSafeReleaseNULL(inst);
		return ret;
	}
	ret = provider->registerInterrupt(index, inst, IOInterruptDispatchSourceInterrupt, inst->ivars);
	if (kIOReturnSuccess == ret) {
		inst->ivars->intIndex = index;
		inst->ivars->flags    = flags;
		inst->ivars->provider = provider;
		inst->ivars->provider->retain();
		*source = inst;
	}
	return ret;
}

kern_return_t
IOInterruptDispatchSource::GetInterruptType_Impl(
	IOService * provider,
	uint32_t index,
	uint64_t * interruptType)
{
	IOReturn ret;
	int      type;

	*interruptType = 0;
	ret = provider->getInterruptType(index, &type);
	if (kIOReturnSuccess == ret) {
		*interruptType = type;
	}

	return ret;
}

bool
IOInterruptDispatchSource::init()
{
	if (!super::init()) {
		return false;
	}
	ivars = IOMallocType(IOInterruptDispatchSource_IVars);

	return true;
}

void
IOInterruptDispatchSource::free()
{
	IOReturn ret;

	if (ivars && ivars->provider) {
		ret = ivars->provider->unregisterInterrupt(ivars->intIndex);
		assert(kIOReturnSuccess == ret);
		ivars->provider->release();
	}

	if (ivars && ivars->lock) {
		IOSimpleLockFree(ivars->lock);
	}

	IOFreeType(ivars, IOInterruptDispatchSource_IVars);

	super::free();
}

kern_return_t
IOInterruptDispatchSource::SetHandler_Impl(
	OSAction * action)
{
	IOReturn ret;
	OSAction * oldAction;

	oldAction = (typeof(oldAction))ivars->action;
	if (oldAction && OSCompareAndSwapPtr(oldAction, NULL, &ivars->action)) {
		oldAction->release();
	}
	action->retain();
	ivars->action = action;

	ret = kIOReturnSuccess;

	return ret;
}

kern_return_t
IOInterruptDispatchSource::SetEnableWithCompletion_Impl(
	bool enable,
	IODispatchSourceCancelHandler handler)
{
	IOReturn ret;
	IOInterruptState is;

	if (enable == ivars->enable) {
		return kIOReturnSuccess;
	}

	if (enable) {
		is = IOSimpleLockLockDisableInterrupt(ivars->lock);
		ivars->enable = enable;
		IOSimpleLockUnlockEnableInterrupt(ivars->lock, is);
		ret = ivars->provider->enableInterrupt(ivars->intIndex);
	} else {
		ret = ivars->provider->disableInterrupt(ivars->intIndex);
		is = IOSimpleLockLockDisableInterrupt(ivars->lock);
		ivars->enable = enable;
		IOSimpleLockUnlockEnableInterrupt(ivars->lock, is);
	}

	return ret;
}

kern_return_t
IOInterruptDispatchSource::Cancel_Impl(
	IODispatchSourceCancelHandler handler)
{
	IOInterruptState is;

	is = IOSimpleLockLockDisableInterrupt(ivars->lock);
	ivars->canceled = true;
	if (ivars->waiter) {
		thread_wakeup_thread((event_t) ivars, ivars->waiter);
		ivars->waiter = NULL;
	}
	IOSimpleLockUnlockEnableInterrupt(ivars->lock, is);

	return kIOReturnSuccess;
}

kern_return_t
IOInterruptDispatchSource::CheckForWork_Impl(
	const IORPC rpc,
	bool synchronous)
{
	IOReturn         ret = kIOReturnNotReady;
	IOInterruptState is;
	bool             willWait;
	bool             canceled;
	wait_result_t    waitResult;
	uint64_t         icount;
	uint64_t         itime;
	thread_t         self;

	self = current_thread();
	icount = 0;
	do {
		willWait = false;
		is = IOSimpleLockLockDisableInterrupt(ivars->lock);
		canceled = ivars->canceled;
		if (!canceled) {
			if ((icount = ivars->count)) {
				itime = ivars->time;
				ivars->count = 0;
				waitResult = THREAD_AWAKENED;
			} else if (synchronous) {
				assert(NULL == ivars->waiter);
				ivars->waiter = self;
				waitResult = assert_wait((event_t) ivars, THREAD_INTERRUPTIBLE);
			}
			willWait = (synchronous && (waitResult == THREAD_WAITING));
			if (willWait && (kIOInterruptTypeLevel & ivars->interruptType) && ivars->enable) {
				IOSimpleLockUnlockEnableInterrupt(ivars->lock, is);
				ivars->provider->enableInterrupt(ivars->intIndex);
			} else {
				IOSimpleLockUnlockEnableInterrupt(ivars->lock, is);
			}
		} else {
			IOSimpleLockUnlockEnableInterrupt(ivars->lock, is);
		}
		if (willWait) {
			waitResult = thread_block(THREAD_CONTINUE_NULL);
			if (THREAD_INTERRUPTED == waitResult) {
				is = IOSimpleLockLockDisableInterrupt(ivars->lock);
				ivars->waiter = NULL;
				IOSimpleLockUnlockEnableInterrupt(ivars->lock, is);
				canceled = true;
				break;
			}
		}
	} while (synchronous && !icount && !canceled);

	if (icount && ivars->action) {
		ret = InterruptOccurred(rpc, ivars->action, icount, itime);
	}

	return ret;
}

void
IOInterruptDispatchSource::InterruptOccurred_Impl(
	OSAction * action,
	uint64_t count,
	uint64_t time)
{
}

kern_return_t
IOInterruptDispatchSource::GetLastInterrupt_Impl(
	uint64_t  * pCount,
	uint64_t  * pTime)
{
	IOInterruptState is;
	uint64_t count, time;

	is = IOSimpleLockLockDisableInterrupt(ivars->lock);
	count = ivars->count;
	time  = ivars->time;
	IOSimpleLockUnlockEnableInterrupt(ivars->lock, is);

	if (pCount) {
		*pCount = count;
	}
	if (pTime) {
		*pTime = time;
	}
	return kIOReturnSuccess;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

enum {
	kIOServiceNotificationTypeCount = kIOServiceNotificationTypeLast + 1,
};

struct IOServiceNotificationDispatchSource_IVars {
	OSObject     * serverName;
	OSAction     * action;
	IOLock       * lock;
	IONotifier   * notifier;
	OSDictionary * interestNotifiers;
	OSBoundedArray<OSArray *, kIOServiceNotificationTypeCount> pending;
	bool           enable;
};

kern_return_t
IOServiceNotificationDispatchSource::Create_Impl(
	OSDictionary * matching,
	uint64_t options,
	IODispatchQueue * queue,
	IOServiceNotificationDispatchSource ** notification)
{
	IOUserServer * us;
	IOReturn       ret;
	IOServiceNotificationDispatchSource * inst;

	inst = OSTypeAlloc(IOServiceNotificationDispatchSource);
	if (!inst->init()) {
		OSSafeReleaseNULL(inst);
		return kIOReturnNoMemory;
	}

	us = (typeof(us))thread_iokit_tls_get(0);
	assert(OSDynamicCast(IOUserServer, us));
	if (!us) {
		OSSafeReleaseNULL(inst);
		return kIOReturnError;
	}
	inst->ivars->serverName = us->copyProperty(gIOUserServerNameKey);
	if (!inst->ivars->serverName) {
		OSSafeReleaseNULL(inst);
		return kIOReturnNoMemory;
	}

	inst->ivars->lock    = IOLockAlloc();
	if (!inst->ivars->lock) {
		OSSafeReleaseNULL(inst);
		return kIOReturnNoMemory;
	}
	for (uint32_t idx = 0; idx < kIOServiceNotificationTypeCount; idx++) {
		inst->ivars->pending[idx] = OSArray::withCapacity(4);
		if (!inst->ivars->pending[idx]) {
			OSSafeReleaseNULL(inst);
			return kIOReturnNoMemory;
		}
	}
	inst->ivars->interestNotifiers = OSDictionary::withCapacity(4);
	if (!inst->ivars->interestNotifiers) {
		OSSafeReleaseNULL(inst);
		return kIOReturnNoMemory;
	}

	inst->ivars->notifier = IOService::addMatchingNotification(gIOMatchedNotification, matching, 0 /*priority*/,
	    ^bool (IOService * newService, IONotifier * notifier) {
		bool         notifyReady = false;
		IONotifier * interest;
		OSObject   * serverName;
		bool         okToUse;

		serverName = newService->copyProperty(gIOUserServerNameKey);
		okToUse = (serverName && inst->ivars->serverName->isEqualTo(serverName));
		OSSafeReleaseNULL(serverName);
		if (!okToUse) {
		        OSObject * prop;
		        OSObject * str;

		        if (!newService->reserved->uvars || !newService->reserved->uvars->userServer) {
		                return false;
			}
		        str = OSString::withCStringNoCopy(kIODriverKitAllowsPublishEntitlementsKey);
		        if (!str) {
		                return false;
			}
		        okToUse = newService->reserved->uvars->userServer->checkEntitlements(str, NULL, NULL);
		        if (!okToUse) {
		                DKLOG(DKS ": publisher entitlements check failed\n", DKN(newService));
		                return false;
			}
		        prop = newService->copyProperty(kIODriverKitPublishEntitlementsKey);
		        if (!prop) {
		                return false;
			}
		        okToUse = us->checkEntitlements(prop, NULL, NULL);
		        if (!okToUse) {
		                DKLOG(DKS ": subscriber entitlements check failed\n", DKN(newService));
		                return false;
			}
		}

		IOLockLock(inst->ivars->lock);
		notifyReady = (0 == inst->ivars->pending[kIOServiceNotificationTypeMatched]->getCount());
		inst->ivars->pending[kIOServiceNotificationTypeMatched]->setObject(newService);
		IOLockUnlock(inst->ivars->lock);

		interest = newService->registerInterest(gIOGeneralInterest,
		^IOReturn (uint32_t messageType, IOService * provider,
		void * messageArgument, size_t argSize) {
			IONotifier * interest;
			bool         notifyReady = false;

			switch (messageType) {
			case kIOMessageServiceIsTerminated:
				IOLockLock(inst->ivars->lock);
				notifyReady = (0 == inst->ivars->pending[kIOServiceNotificationTypeTerminated]->getCount());
				inst->ivars->pending[kIOServiceNotificationTypeTerminated]->setObject(provider);
				if (inst->ivars->interestNotifiers != NULL) {
				        interest = (typeof(interest))inst->ivars->interestNotifiers->getObject((const OSSymbol *) newService);
				        assert(interest);
				        interest->remove();
				        inst->ivars->interestNotifiers->removeObject((const OSSymbol *) newService);
				}
				IOLockUnlock(inst->ivars->lock);
				break;
			default:
				break;
			}
			if (notifyReady && inst->ivars->action) {
			        inst->ServiceNotificationReady(inst->ivars->action);
			}
			return kIOReturnSuccess;
		});
		if (interest) {
		        IOLockLock(inst->ivars->lock);
		        inst->ivars->interestNotifiers->setObject((const OSSymbol *) newService, interest);
		        IOLockUnlock(inst->ivars->lock);
		}
		if (notifyReady) {
		        if (inst->ivars->action) {
		                inst->ServiceNotificationReady(inst->ivars->action);
			}
		}
		return false;
	});

	if (!inst->ivars->notifier) {
		OSSafeReleaseNULL(inst);
		ret = kIOReturnError;
	}

	*notification = inst;
	ret = kIOReturnSuccess;

	return ret;
}

kern_return_t
IOServiceNotificationDispatchSource::CopyNextNotification_Impl(
	uint64_t * type,
	IOService ** service,
	uint64_t * options)
{
	IOService * next;
	uint32_t    idx;

	IOLockLock(ivars->lock);
	for (idx = 0; idx < kIOServiceNotificationTypeCount; idx++) {
		next = (IOService *) ivars->pending[idx]->getObject(0);
		if (next) {
			next->retain();
			ivars->pending[idx]->removeObject(0);
			break;
		}
	}
	IOLockUnlock(ivars->lock);

	if (idx == kIOServiceNotificationTypeCount) {
		idx = kIOServiceNotificationTypeNone;
	}
	*type    = idx;
	*service = next;
	*options = 0;

	return kIOReturnSuccess;
}

bool
IOServiceNotificationDispatchSource::init()
{
	if (!super::init()) {
		return false;
	}
	ivars = IOMallocType(IOServiceNotificationDispatchSource_IVars);

	return true;
}

void
IOServiceNotificationDispatchSource::free()
{
	if (ivars) {
		if (ivars->notifier) {
			ivars->notifier->remove();
			ivars->notifier = NULL;
		}
		if (ivars->interestNotifiers) {
			OSDictionary * savedInterestNotifiers = NULL;

			// the lock is always initialized first, so it should exist
			assert(ivars->lock);

			// Prevent additional changes to interestNotifiers
			IOLockLock(ivars->lock);
			savedInterestNotifiers = ivars->interestNotifiers;
			ivars->interestNotifiers = NULL;
			IOLockUnlock(ivars->lock);

			// Remove all interest notifiers
			savedInterestNotifiers->iterateObjects(^bool (const OSSymbol * key, OSObject * object) {
				IONotifier * interest = (typeof(interest))object;
				interest->remove();
				return false;
			});
			OSSafeReleaseNULL(savedInterestNotifiers);
		}
		for (uint32_t idx = 0; idx < kIOServiceNotificationTypeCount; idx++) {
			OSSafeReleaseNULL(ivars->pending[idx]);
		}
		if (ivars->lock) {
			IOLockFree(ivars->lock);
			ivars->lock = NULL;
		}
		OSSafeReleaseNULL(ivars->serverName);
		IOFreeType(ivars, IOServiceNotificationDispatchSource_IVars);
	}

	super::free();
}

kern_return_t
IOServiceNotificationDispatchSource::SetHandler_Impl(
	OSAction * action)
{
	IOReturn ret;
	bool     notifyReady;

	notifyReady = false;

	IOLockLock(ivars->lock);
	OSSafeReleaseNULL(ivars->action);
	action->retain();
	ivars->action = action;
	if (action) {
		for (uint32_t idx = 0; idx < kIOServiceNotificationTypeCount; idx++) {
			notifyReady = (ivars->pending[idx]->getCount());
			if (notifyReady) {
				break;
			}
		}
	}
	IOLockUnlock(ivars->lock);

	if (notifyReady) {
		ServiceNotificationReady(action);
	}
	ret = kIOReturnSuccess;

	return ret;
}

kern_return_t
IOServiceNotificationDispatchSource::SetEnableWithCompletion_Impl(
	bool enable,
	IODispatchSourceCancelHandler handler)
{
	if (enable == ivars->enable) {
		return kIOReturnSuccess;
	}

	IOLockLock(ivars->lock);
	ivars->enable = enable;
	IOLockUnlock(ivars->lock);

	return kIOReturnSuccess;
}

kern_return_t
IOServiceNotificationDispatchSource::Cancel_Impl(
	IODispatchSourceCancelHandler handler)
{
	return kIOReturnUnsupported;
}

kern_return_t
IOServiceNotificationDispatchSource::CheckForWork_Impl(
	const IORPC rpc,
	bool synchronous)
{
	return kIOReturnNotReady;
}

kern_return_t
IOServiceNotificationDispatchSource::DeliverNotifications(IOServiceNotificationBlock block)
{
	return kIOReturnUnsupported;
}


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

OSDictionary *
IOService::CreatePropertyMatchingDictionary(const char * key, OSObjectPtr value, OSDictionary * matching)
{
	OSDictionary   * result;
	const OSSymbol * keySym;

	keySym = OSSymbol::withCString(key);
	result = propertyMatching(keySym, (const OSObject *) value, matching);
	OSSafeReleaseNULL(keySym);

	return result;
}

OSDictionary *
IOService::CreatePropertyMatchingDictionary(const char * key, const char * stringValue, OSDictionary * matching)
{
	OSDictionary * result;
	OSString     * value;

	value = OSString::withCString(stringValue);
	result = CreatePropertyMatchingDictionary(key, value, matching);
	OSSafeReleaseNULL(value);

	return result;
}

OSDictionary *
IOService::CreateKernelClassMatchingDictionary(OSString * className, OSDictionary * matching)
{
	if (!className) {
		return NULL;
	}
	if (!matching) {
		matching = OSDictionary::withCapacity(2);
		if (!matching) {
			return NULL;
		}
	}
	matching->setObject(kIOProviderClassKey, className);

	return matching;
}

OSDictionary *
IOService::CreateKernelClassMatchingDictionary(const char * className, OSDictionary * matching)
{
	OSDictionary * result;
	OSString     * string;

	string = OSString::withCString(className);
	result = CreateKernelClassMatchingDictionary(string, matching);
	OSSafeReleaseNULL(string);

	return result;
}

OSDictionary *
IOService::CreateUserClassMatchingDictionary(OSString * className, OSDictionary * matching)
{
	return CreatePropertyMatchingDictionary(kIOUserClassKey, className, matching);
}

OSDictionary *
IOService::CreateUserClassMatchingDictionary(const char * className, OSDictionary * matching)
{
	return CreatePropertyMatchingDictionary(kIOUserClassKey, className, matching);
}

OSDictionary *
IOService::CreateNameMatchingDictionary(OSString * serviceName, OSDictionary * matching)
{
	if (!serviceName) {
		return NULL;
	}
	if (!matching) {
		matching = OSDictionary::withCapacity(2);
		if (!matching) {
			return NULL;
		}
	}
	matching->setObject(kIONameMatchKey, serviceName);

	return matching;
}

OSDictionary *
IOService::CreateNameMatchingDictionary(const char * serviceName, OSDictionary * matching)
{
	OSDictionary * result;
	OSString     * string;

	string = OSString::withCString(serviceName);
	result = CreateNameMatchingDictionary(string, matching);
	OSSafeReleaseNULL(string);

	return result;
}



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

kern_return_t
IOUserServer::waitInterruptTrap(void * p1, void * p2, void * p3, void * p4, void * p5, void * p6)
{
	IOReturn         ret = kIOReturnBadArgument;
	IOInterruptState is;
	IOInterruptDispatchSource * interrupt;
	IOInterruptDispatchSource_IVars * ivars;
	IOInterruptDispatchSourcePayload payload;

	bool             willWait;
	bool             canceled;
	wait_result_t    waitResult;
	thread_t         self;

	OSObject * object;

	object = iokit_lookup_object_with_port_name((mach_port_name_t)(uintptr_t)p1, IKOT_UEXT_OBJECT, current_task());

	if (!object) {
		return kIOReturnBadArgument;
	}
	if (!(interrupt = OSDynamicCast(IOInterruptDispatchSource, object))) {
		ret = kIOReturnBadArgument;
	} else {
		self = current_thread();
		ivars = interrupt->ivars;
		payload.count = 0;
		do {
			willWait = false;
			is = IOSimpleLockLockDisableInterrupt(ivars->lock);
			canceled = ivars->canceled;
			if (!canceled) {
				if ((payload.count = ivars->count)) {
					payload.time = ivars->time;
					ivars->count = 0;
					waitResult = THREAD_AWAKENED;
				} else {
					assert(NULL == ivars->waiter);
					ivars->waiter = self;
					waitResult = assert_wait((event_t) ivars, THREAD_INTERRUPTIBLE);
				}
				willWait = (waitResult == THREAD_WAITING);
				if (willWait && (kIOInterruptTypeLevel & ivars->interruptType) && ivars->enable) {
					IOSimpleLockUnlockEnableInterrupt(ivars->lock, is);
					ivars->provider->enableInterrupt(ivars->intIndex);
				} else {
					IOSimpleLockUnlockEnableInterrupt(ivars->lock, is);
				}
			} else {
				IOSimpleLockUnlockEnableInterrupt(ivars->lock, is);
			}
			if (willWait) {
				waitResult = thread_block(THREAD_CONTINUE_NULL);
				if (THREAD_INTERRUPTED == waitResult) {
					is = IOSimpleLockLockDisableInterrupt(ivars->lock);
					ivars->waiter = NULL;
					IOSimpleLockUnlockEnableInterrupt(ivars->lock, is);
					canceled = true;
					break;
				}
			}
		} while (!payload.count && !canceled);
		ret = (payload.count ? kIOReturnSuccess : kIOReturnAborted);
	}

	if (kIOReturnSuccess == ret) {
		int copyerr = copyout(&payload, (user_addr_t) p2, sizeof(payload));
		if (copyerr) {
			ret = kIOReturnVMError;
		}
	}

	object->release();

	return ret;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

kern_return_t
IOUserServer::Create_Impl(
	const char * name,
	uint64_t tag,
	uint64_t options,
	OSString * bundleID,
	IOUserServer ** server)
{
	IOReturn          ret;
	IOUserServer    * us;
	const OSSymbol  * sym;
	OSNumber        * serverTag;
	io_name_t         rname;
	OSKext          * kext;

	us = (typeof(us))thread_iokit_tls_get(0);
	assert(OSDynamicCast(IOUserServer, us));
	if (kIODKLogSetup & gIODKDebug) {
		DKLOG(DKS "::Create(" DKS ") %p\n", DKN(us), name, tag, us);
	}
	if (!us) {
		return kIOReturnError;
	}

	if (bundleID) {
		kext = OSKext::lookupKextWithIdentifier(bundleID->getCStringNoCopy());
		if (kext) {
			us->setTaskLoadTag(kext);
			us->setDriverKitUUID(kext);
			us->setDriverKitStatistics(kext);
			OSKext::OSKextLogDriverKitInfoLoad(kext);
			OSSafeReleaseNULL(kext);
		} else {
			DKLOG(DKS "::Create(" DKS "): could not find OSKext for %s\n", DKN(us), name, tag, bundleID->getCStringNoCopy());
		}

		us->fAllocationName = kern_allocation_name_allocate(bundleID->getCStringNoCopy(), 0);
		assert(us->fAllocationName);
	}

	sym       = OSSymbol::withCString(name);
	serverTag = OSNumber::withNumber(tag, 64);

	us->setProperty(gIOUserServerNameKey, (OSObject *) sym);
	us->setProperty(gIOUserServerTagKey, serverTag);

	serverTag->release();
	OSSafeReleaseNULL(sym);

	snprintf(rname, sizeof(rname), "IOUserServer(%s-0x%qx)", name, tag);
	us->setName(rname);

	us->retain();
	*server = us;
	ret = kIOReturnSuccess;

	return ret;
}

kern_return_t
IOUserServer::RegisterService_Impl()
{
	kern_return_t ret = IOService::RegisterService_Impl();

	return ret;
}

kern_return_t
IOUserServer::Exit_Impl(
	const char * reason)
{
	return kIOReturnUnsupported;
}

kern_return_t
IOUserServer::LoadModule_Impl(
	const char * path)
{
	return kIOReturnUnsupported;
}


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

kern_return_t
IODispatchQueue::Create_Impl(
	const char * name,
	uint64_t options,
	uint64_t priority,
	IODispatchQueue ** queue)
{
	IODispatchQueue * result;
	IOUserServer    * us;

	result = OSTypeAlloc(IODispatchQueue);
	if (!result) {
		return kIOReturnNoMemory;
	}
	if (!result->init()) {
		OSSafeReleaseNULL(result);
		return kIOReturnNoMemory;
	}

	*queue = result;

	if (!strcmp("Root", name)) {
		us = (typeof(us))thread_iokit_tls_get(0);
		assert(OSDynamicCast(IOUserServer, us));
		us->setRootQueue(result);
	}

	if (kIODKLogSetup & gIODKDebug) {
		DKLOG("IODispatchQueue::Create %s %p\n", name, result);
	}

	return kIOReturnSuccess;
}

kern_return_t
IODispatchQueue::SetPort_Impl(
	mach_port_t port)
{
	if (MACH_PORT_NULL != ivars->serverPort) {
		return kIOReturnNotReady;
	}

	ivars->serverPort = port;
	return kIOReturnSuccess;
}

bool
IODispatchQueue::init()
{
	ivars = IOMallocType(IODispatchQueue_IVars);
	ivars->queue = this;

	return true;
}

void
IODispatchQueue::free()
{
	if (ivars && ivars->serverPort) {
		ipc_port_release_send(ivars->serverPort);
		ivars->serverPort = MACH_PORT_NULL;
	}
	IOFreeType(ivars, IODispatchQueue_IVars);
	super::free();
}

bool
IODispatchQueue::OnQueue()
{
	return false;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */


kern_return_t
OSMetaClassBase::Dispatch(IORPC rpc)
{
	return kIOReturnUnsupported;
}

kern_return_t
OSMetaClassBase::Invoke(IORPC rpc)
{
	IOReturn          ret = kIOReturnUnsupported;
	OSMetaClassBase * object;
	OSAction        * action;
	IOService       * service;
	IOUserServer    * us;
	IORPCMessage    * message;

	assert(rpc.sendSize >= (sizeof(IORPCMessageMach) + sizeof(IORPCMessage)));
	message = rpc.kernelContent;
	if (!message) {
		return kIOReturnIPCError;
	}
	message->flags |= kIORPCMessageKernel;

	us = NULL;
	if (!(kIORPCMessageLocalHost & message->flags)) {
		us = OSDynamicCast(IOUserServer, this);
		if (!us) {
			IOEventLink * eventLink = NULL;
			IOWorkGroup * workgroup = NULL;

			if ((action = OSDynamicCast(OSAction, this))) {
				object = IOUserServer::target(action, message);
			} else {
				object = this;
			}
			if ((service = OSDynamicCast(IOService, object))
			    && service->reserved->uvars) {
				// xxx other classes
				us = service->reserved->uvars->userServer;
			} else if (action) {
				us = action->ivars->userServer;
			} else if ((eventLink = OSDynamicCast(IOEventLink, object))) {
				us = eventLink->ivars->userServer;
			} else if ((workgroup = OSDynamicCast(IOWorkGroup, object))) {
				us = workgroup->ivars->userServer;
			}
		}
	}
	if (us) {
		message->flags |= kIORPCMessageRemote;
		ret = us->rpc(rpc);
		if (kIOReturnSuccess != ret) {
			if (kIODKLogIPC & gIODKDebug) {
				DKLOG("OSMetaClassBase::Invoke user 0x%x\n", ret);
			}
		}
	} else {
		if (kIODKLogIPC & gIODKDebug) {
			DKLOG("OSMetaClassBase::Invoke kernel %s 0x%qx\n", getMetaClass()->getClassName(), message->msgid);
		}
		void * prior = thread_iokit_tls_get(0);
		thread_iokit_tls_set(0, NULL);
		ret = Dispatch(rpc);
		thread_iokit_tls_set(0, prior);
	}

	return ret;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

struct IOPStrings {
	uint32_t     dataSize;
	uint32_t     count;
	const char   strings[0];
};

kern_return_t
OSUserMetaClass::Dispatch(IORPC rpc)
{
	if (meta) {
		return const_cast<OSMetaClass *>(meta)->Dispatch(rpc);
	} else {
		return kIOReturnUnsupported;
	}
}

void
OSUserMetaClass::free()
{
	if (queueNames) {
		IOFreeData(queueNames, sizeof(IOPStrings) + queueNames->dataSize * sizeof(char));
		queueNames = NULL;
	}
	if (description) {
		IOFreeData(description, description->descriptionSize);
		description = NULL;
	}
	IODeleteData(methods, uint64_t, 2 * methodCount);
	if (meta) {
		meta->releaseMetaClass();
	}
	if (name) {
		name->release();
	}
	OSObject::free();
}

/*
 * Sets the loadTag of the associated OSKext
 * in the dext task.
 * NOTE: different instances of the same OSKext
 * (so same BounleID but different tasks)
 * will have the same loadTag.
 */
void
IOUserServer::setTaskLoadTag(OSKext *kext)
{
	task_t owningTask;
	uint32_t loadTag, prev_taskloadTag;

	owningTask = this->fOwningTask;
	if (!owningTask) {
		printf("%s: fOwningTask not found\n", __FUNCTION__);
		return;
	}

	loadTag = kext->getLoadTag();
	prev_taskloadTag = set_task_loadTag(owningTask, loadTag);
	if (prev_taskloadTag) {
		printf("%s: found the task loadTag already set to %u (set to %u)\n",
		    __FUNCTION__, prev_taskloadTag, loadTag);
	}
}

/*
 * Sets the OSKext uuid as the uuid of the userspace
 * dext executable.
 */
void
IOUserServer::setDriverKitUUID(OSKext *kext)
{
	task_t task;
	proc_t p;
	uuid_t p_uuid, k_uuid;
	OSData *k_data_uuid;
	OSData *new_uuid;
	uuid_string_t       uuid_string = "";

	task = this->fOwningTask;
	if (!task) {
		printf("%s: fOwningTask not found\n", __FUNCTION__);
		return;
	}

	p = (proc_t)(get_bsdtask_info(task));
	if (!p) {
		printf("%s: proc not found\n", __FUNCTION__);
		return;
	}
	proc_getexecutableuuid(p, p_uuid, sizeof(p_uuid));

	k_data_uuid = kext->copyUUID();
	if (k_data_uuid) {
		memcpy(&k_uuid, k_data_uuid->getBytesNoCopy(), sizeof(k_uuid));
		OSSafeReleaseNULL(k_data_uuid);
		if (uuid_compare(k_uuid, p_uuid) != 0) {
			printf("%s: uuid not matching\n", __FUNCTION__);
		}
		return;
	}

	uuid_unparse(p_uuid, uuid_string);
	new_uuid = OSData::withValue(p_uuid);
	kext->setDriverKitUUID(new_uuid);
}

void
IOUserServer::setDriverKitStatistics(OSKext *kext)
{
	OSDextStatistics * statistics = kext->copyDextStatistics();
	if (statistics == NULL) {
		panic("Kext %s was not a DriverKit OSKext", kext->getIdentifierCString());
	}
	fStatistics = statistics;
}

void
IOUserServer::setCheckInToken(IOUserServerCheckInToken *token)
{
	if (token != NULL && fCheckInToken == NULL) {
		token->retain();
		fCheckInToken = token;
		iokit_clear_registered_ports(fOwningTask);
	} else {
		printf("%s: failed to set check in token. token=%p, fCheckInToken=%p\n", __FUNCTION__, token, fCheckInToken);
	}
}

bool
IOUserServer::serviceMatchesCheckInToken(IOUserServerCheckInToken *token)
{
	if (token != NULL) {
		bool result = token == fCheckInToken;
		if (result) {
			fCheckInToken->complete();
		}
		return result;
	} else {
		printf("%s: null check in token\n", __FUNCTION__);
		return false;
	}
}

// entitlements - dict of entitlements to check
// prop - string - if present return true
//      - array of strings - if any present return true
//      - array of arrays of strings - in each leaf array all must be present
//                                   - if any top level array succeeds return true
// consumes one reference of prop
bool
IOUserServer::checkEntitlements(
	OSDictionary * entitlements, OSObject * prop,
	IOService * provider, IOService * dext)
{
	OSDictionary * matching;

	if (!prop) {
		return true;
	}
	if (!entitlements) {
		OSSafeReleaseNULL(prop);
		return false;
	}

	matching = NULL;
	if (dext) {
		matching = dext->dictionaryWithProperties();
		if (!matching) {
			OSSafeReleaseNULL(prop);
			return false;
		}
	}

	bool allPresent __block = false;
	prop->iterateObjects(^bool (OSObject * object) {
		allPresent = false;
		object->iterateObjects(^bool (OSObject * object) {
			OSString * string;
			OSObject * value;
			string = OSDynamicCast(OSString, object);
			value = entitlements->getObject(string);
			if (matching && value) {
			        matching->setObject(string, value);
			}
			allPresent = (NULL != value);
			// early terminate if not found
			return !allPresent;
		});
		// early terminate if found
		return allPresent;
	});

	if (allPresent && matching && provider) {
		allPresent = provider->matchPropertyTable(matching);
	}

	OSSafeReleaseNULL(matching);
	OSSafeReleaseNULL(prop);

	return allPresent;
}

bool
IOUserServer::checkEntitlements(OSObject * prop, IOService * provider, IOService * dext)
{
	return checkEntitlements(fEntitlements, prop, provider, dext);
}

bool
IOUserServer::checkEntitlements(IOService * provider, IOService * dext)
{
	OSObject     * prop;
	bool           ok;

	if (!fOwningTask) {
		return false;
	}

	prop = provider->copyProperty(gIOServiceDEXTEntitlementsKey);
	ok = checkEntitlements(fEntitlements, prop, provider, dext);
	if (!ok) {
		DKLOG(DKS ": provider entitlements check failed\n", DKN(dext));
	}
	if (ok) {
		prop = dext->copyProperty(gIOServiceDEXTEntitlementsKey);
		ok = checkEntitlements(fEntitlements, prop, NULL, NULL);
		if (!ok) {
			DKLOG(DKS ": family entitlements check failed\n", DKN(dext));
		}
	}

	return ok;
}

IOReturn
IOUserServer::exit(const char * reason)
{
	DKLOG("%s::exit(%s)\n", getName(), reason);
	Exit(reason);
	return kIOReturnSuccess;
}

IOReturn
IOUserServer::kill(const char * reason)
{
	IOReturn ret = kIOReturnError;
	if (fOwningTask != NULL) {
		DKLOG("%s::kill(%s)\n", getName(), reason);
		task_bsdtask_kill(fOwningTask);
		ret = kIOReturnSuccess;
	}
	return ret;
}

OSObjectUserVars *
IOUserServer::varsForObject(OSObject * obj)
{
	IOService * service;

	if ((service = OSDynamicCast(IOService, obj))) {
		return service->reserved->uvars;
	}

	return NULL;
}

IOPStrings *
IOUserServer::copyInStringArray(const char * string, uint32_t userSize)
{
	IOPStrings * array;
	vm_size_t    alloc;
	size_t       len;
	const char * end;
	OSBoundedPtr<const char> cstr;

	if (userSize <= 1) {
		return NULL;
	}

	if (os_add_overflow(sizeof(IOPStrings), userSize, &alloc)) {
		assert(false);
		return NULL;
	}
	if (alloc > 16384) {
		assert(false);
		return NULL;
	}
	array = (typeof(array))IOMallocData(alloc);
	if (!array) {
		return NULL;
	}
	array->dataSize = userSize;
	bcopy(string, (void *) &array->strings[0], userSize);

	array->count = 0;
	end =  &array->strings[array->dataSize];
	cstr = OSBoundedPtr<const char>(&array->strings[0], &array->strings[0], end);
	while ((len = (unsigned char)cstr[0])) {
		cstr++;
		if ((cstr + len) >= end) {
			break;
		}
		cstr += len;
		array->count++;
	}
	if (len) {
		IOFreeData(array, alloc);
		array = NULL;
	}

	return array;
}

uint32_t
IOUserServer::stringArrayIndex(IOPStrings * array, const char * look)
{
	uint32_t     idx;
	size_t       len, llen;
	OSBoundedPtr<const char> cstr;
	const char * end;

	idx  = 0;
	end  =  &array->strings[array->dataSize];
	cstr = OSBoundedPtr<const char>(&array->strings[0], &array->strings[0], end);

	llen = strlen(look);
	while ((len = (unsigned char)cstr[0])) {
		cstr++;
		if ((cstr + len) >= end) {
			break;
		}
		if ((len == llen) && !strncmp(cstr.discard_bounds(), look, len)) {
			return idx;
		}
		cstr += len;
		idx++;
	}

	return -1U;
}
#define kIODispatchQueueStopped ((IODispatchQueue *) -1L)

IODispatchQueue *
IOUserServer::queueForObject(OSObject * obj, uint64_t msgid)
{
	IODispatchQueue  * queue;
	OSObjectUserVars * uvars;
	uint64_t           option;

	uvars = varsForObject(obj);
	if (!uvars) {
		return NULL;
	}
	if (!uvars->queueArray) {
		if (uvars->stopped) {
			return kIODispatchQueueStopped;
		}
		return NULL;
	}
	queue = uvars->queueArray[0];

	if (uvars->userMeta
	    && uvars->userMeta->methods) {
		uint32_t idx, baseIdx;
		uint32_t lim;
		// bsearch
		for (baseIdx = 0, lim = uvars->userMeta->methodCount; lim; lim >>= 1) {
			idx = baseIdx + (lim >> 1);
			if (msgid == uvars->userMeta->methods[idx]) {
				option = uvars->userMeta->methods[uvars->userMeta->methodCount + idx];
				option &= 0xFF;
				if (option < uvars->userMeta->queueNames->count) {
					queue = uvars->queueArray[option + 1];
				}
				break;
			} else if (msgid > uvars->userMeta->methods[idx]) {
				// move right
				baseIdx += (lim >> 1) + 1;
				lim--;
			}
			// else move left
		}
	}
	return queue;
}

IOReturn
IOUserServer::objectInstantiate(OSObject * obj, IORPC rpc, IORPCMessage * message)
{
	IOReturn         ret;
	OSString       * str;
	OSObject       * prop;
	IOService      * service;

	OSAction       * action;
	OSObject       * target;
	uint32_t         queueCount, queueAlloc;
	const char     * resultClassName;
	uint64_t         resultFlags;

	mach_msg_size_t    replySize;
	uint32_t           methodCount;
	const uint64_t   * methods;
	IODispatchQueue  * queue;
	OSUserMetaClass  * userMeta;
	OSObjectUserVars * uvars;
	uint32_t           idx;
	ipc_port_t         sendPort;

	OSObject_Instantiate_Rpl_Content * reply;
	IODispatchQueue ** unboundedQueueArray = NULL;
	queueCount      = 0;
	methodCount     = 0;
	methods         = NULL;
	str             = NULL;
	prop            = NULL;
	userMeta        = NULL;
	resultClassName = NULL;
	resultFlags     = 0;
	ret = kIOReturnUnsupportedMode;

	service = OSDynamicCast(IOService, obj);
	action = OSDynamicCast(OSAction, obj);
	if (!service) {
		// xxx other classes hosted
		resultFlags |= kOSObjectRPCKernel;
		resultFlags |= kOSObjectRPCRemote;
	} else {
		if (service->isInactive()) {
			DKLOG(DKS "::instantiate inactive\n", DKN(service));
			return kIOReturnOffline;
		}
		prop = service->copyProperty(gIOUserClassKey);
		str = OSDynamicCast(OSString, prop);
		if (!service->reserved->uvars) {
			resultFlags |= kOSObjectRPCRemote;
			resultFlags |= kOSObjectRPCKernel;
		} else if (this != service->reserved->uvars->userServer) {
			// remote, use base class
			resultFlags |= kOSObjectRPCRemote;
		}
		if (service->reserved->uvars && service->reserved->uvars->userServer) {
			if (!str) {
				DKLOG("no IOUserClass defined for " DKS "\n", DKN(service));
				OSSafeReleaseNULL(prop);
				return kIOReturnError;
			}
			IOLockLock(service->reserved->uvars->userServer->fLock);
			userMeta = (typeof(userMeta))service->reserved->uvars->userServer->fClasses->getObject(str);
			IOLockUnlock(service->reserved->uvars->userServer->fLock);
		}
	}
	if (!str && !userMeta) {
		const OSMetaClass * meta;
		meta = obj->getMetaClass();
		IOLockLock(fLock);
		if (action) {
			str = action->ivars->typeName;
			if (str) {
				userMeta = (typeof(userMeta))fClasses->getObject(str);
			}
		}
		while (meta && !userMeta) {
			str = (OSString *) meta->getClassNameSymbol();
			userMeta = (typeof(userMeta))fClasses->getObject(str);
			if (!userMeta) {
				meta = meta->getSuperClass();
			}
		}
		IOLockUnlock(fLock);
	}
	if (str) {
		if (!userMeta) {
			IOLockLock(fLock);
			userMeta = (typeof(userMeta))fClasses->getObject(str);
			IOLockUnlock(fLock);
		}
		if (kIODKLogSetup & gIODKDebug) {
			DKLOG("userMeta %s %p\n", str->getCStringNoCopy(), userMeta);
		}
		if (userMeta) {
			if (kOSObjectRPCRemote & resultFlags) {
				if (!action) {
					/* Special case: For OSAction subclasses, do not use the superclass */
					while (userMeta && !(kOSClassCanRemote & userMeta->description->flags)) {
						userMeta = userMeta->superMeta;
					}
				}
				if (userMeta) {
					resultClassName = userMeta->description->name;
					ret = kIOReturnSuccess;
				}
			} else {
				service->reserved->uvars->userMeta = userMeta;
				queueAlloc = 1;
				if (userMeta->queueNames) {
					queueAlloc += userMeta->queueNames->count;
				}
				unboundedQueueArray = IONewZero(IODispatchQueue *, queueAlloc);
				service->reserved->uvars->queueArray =
				    OSBoundedArrayRef<IODispatchQueue *>(unboundedQueueArray, queueAlloc);
				resultClassName = str->getCStringNoCopy();
				ret = kIOReturnSuccess;
			}
		} else if (kIODKLogSetup & gIODKDebug) {
			DKLOG("userMeta %s was not found in fClasses\n", str->getCStringNoCopy());
			IOLockLock(fLock);
			fClasses->iterateObjects(^bool (const OSSymbol * key, OSObject * val) {
				DKLOG(" fClasses[\"%s\"] => %p\n", key->getCStringNoCopy(), val);
				return false;
			});
			IOLockUnlock(fLock);
		}
	}
	OSSafeReleaseNULL(prop);

	IORPCMessageMach * machReply = rpc.reply;
	replySize = sizeof(OSObject_Instantiate_Rpl);

	if ((kIOReturnSuccess == ret) && (kOSObjectRPCRemote & resultFlags)) {
		target = obj;
		if (action) {
			if (action->ivars->referenceSize) {
				resultFlags |= kOSObjectRPCKernel;
			} else {
				resultFlags &= ~kOSObjectRPCKernel;
				if (action->ivars->target) {
					target = action->ivars->target;
					queueCount = 1;
					queue = queueForObject(target, action->ivars->targetmsgid);
					if (!queue && action->ivars->userServer) {
						queue = action->ivars->userServer->fRootQueue;
					}
					idx = 0;
					sendPort = NULL;
					if (queue && (kIODispatchQueueStopped != queue)) {
						sendPort = ipc_port_copy_send_mqueue(queue->ivars->serverPort);
					}
					replySize = sizeof(OSObject_Instantiate_Rpl)
					    + queueCount * sizeof(machReply->objects[0])
					    + 2 * methodCount * sizeof(reply->methods[0]);
					if (replySize > rpc.replySize) {
						assert(false);
						return kIOReturnIPCError;
					}
					machReply->objects[idx].type        = MACH_MSG_PORT_DESCRIPTOR;
					machReply->objects[idx].disposition = MACH_MSG_TYPE_MOVE_SEND;
					machReply->objects[idx].name        = sendPort;
					machReply->objects[idx].pad2        = 0;
					machReply->objects[idx].pad_end     = 0;
				}
			}
		} else {
			uvars = varsForObject(target);
			if (uvars && uvars->userMeta) {
				queueCount = 1;
				if (uvars->userMeta->queueNames) {
					queueCount += uvars->userMeta->queueNames->count;
				}
				methods = &uvars->userMeta->methods[0];
				methodCount = uvars->userMeta->methodCount;
				replySize = sizeof(OSObject_Instantiate_Rpl)
				    + queueCount * sizeof(machReply->objects[0])
				    + 2 * methodCount * sizeof(reply->methods[0]);
				if (replySize > rpc.replySize) {
					assert(false);
					return kIOReturnIPCError;
				}
				for (idx = 0; idx < queueCount; idx++) {
					queue = uvars->queueArray[idx];
					sendPort = NULL;
					if (queue) {
						sendPort = ipc_port_copy_send_mqueue(queue->ivars->serverPort);
					}
					machReply->objects[idx].type        = MACH_MSG_PORT_DESCRIPTOR;
					machReply->objects[idx].disposition = MACH_MSG_TYPE_MOVE_SEND;
					machReply->objects[idx].name        = sendPort;
					machReply->objects[idx].pad2        = 0;
					machReply->objects[idx].pad_end     = 0;
				}
			}
		}
	}

	if (kIODKLogIPC & gIODKDebug) {
		DKLOG("instantiate object %s with user class %s\n", obj->getMetaClass()->getClassName(), str ? str->getCStringNoCopy() : "(null)");
	}

	if (kIOReturnSuccess != ret) {
		DKLOG("%s: no user class found\n", str ? str->getCStringNoCopy() : obj->getMetaClass()->getClassName());
		resultClassName = "unknown";
	}

	machReply->msgh.msgh_id                    = kIORPCVersionCurrentReply;
	machReply->msgh.msgh_size                  = replySize;
	machReply->msgh_body.msgh_descriptor_count = queueCount;

	reply = (typeof(reply))IORPCMessageFromMachReply(machReply);
	if (!reply) {
		return kIOReturnIPCError;
	}
	if (methodCount) {
		bcopy(methods, &reply->methods[0], methodCount * 2 * sizeof(reply->methods[0]));
	}
	reply->__hdr.msgid       = OSObject_Instantiate_ID;
	reply->__hdr.flags       = kIORPCMessageOneway;
	reply->__hdr.objectRefs  = 0;
	reply->__pad             = 0;
	reply->flags             = resultFlags;
	strlcpy(reply->classname, resultClassName, sizeof(reply->classname));
	reply->__result          = ret;

	ret = kIOReturnSuccess;

	return ret;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOReturn
IOUserServer::kernelDispatch(OSObject * obj, IORPC rpc)
{
	IOReturn       ret;
	IORPCMessage * message;

	message = rpc.kernelContent;
	if (!message) {
		return kIOReturnIPCError;
	}

	if (OSObject_Instantiate_ID == message->msgid) {
		ret = objectInstantiate(obj, rpc, message);
		if (kIOReturnSuccess != ret) {
			DKLOG("%s: instantiate failed 0x%x\n", obj->getMetaClass()->getClassName(), ret);
		}
	} else {
		if (kIODKLogIPC & gIODKDebug) {
			DKLOG("%s::Dispatch kernel 0x%qx\n", obj->getMetaClass()->getClassName(), message->msgid);
		}
		ret = obj->Dispatch(rpc);
		if (kIODKLogIPC & gIODKDebug) {
			DKLOG("%s::Dispatch kernel 0x%qx result 0x%x\n", obj->getMetaClass()->getClassName(), message->msgid, ret);
		}
	}

	return ret;
}


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

OSObject *
IOUserServer::target(OSAction * action, IORPCMessage * message)
{
	OSObject * object;

	if (message->msgid != action->ivars->msgid) {
		return action;
	}
	object = action->ivars->target;
	if (!object) {
		return action;
	}
	message->msgid      = action->ivars->targetmsgid;
	message->objects[0] = (OSObjectRef) object;
	if (kIORPCMessageRemote & message->flags) {
		object->retain();
#ifndef __clang_analyzer__
		// Hide the release of 'action' from the clang static analyzer to suppress
		// an overrelease diagnostic. The analyzer doesn't have a way to express the
		// non-standard contract of this method, which is that it releases 'action' when
		// the message flags have kIORPCMessageRemote set.
		action->release();
#endif
	}
	if (kIODKLogIPC & gIODKDebug) {
		DKLOG("TARGET %s msg 0x%qx from 0x%qx\n", object->getMetaClass()->getClassName(), message->msgid, action->ivars->msgid);
	}

	return object;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

kern_return_t
uext_server(ipc_port_t receiver, ipc_kmsg_t requestkmsg, ipc_kmsg_t * pReply)
{
	kern_return_t      ret;
	OSObject         * object;
	IOUserServer     * server;

	object = IOUserServer::copyObjectForSendRight(receiver, IKOT_UEXT_OBJECT);
	server = OSDynamicCast(IOUserServer, object);
	if (!server) {
		OSSafeReleaseNULL(object);
		return KERN_INVALID_NAME;
	}

	IORPCMessage * message = (typeof(message))ikm_udata_from_header(requestkmsg);

	ret = server->server(requestkmsg, message, pReply);
	object->release();

	return ret;
}

/*
 * Chosen to hit kalloc zones (as opposed to the VM).
 * doesn't include the trailer size which ipc_kmsg_alloc() will add
 */
#define MAX_UEXT_REPLY_SIZE     0x17c0
static_assert(MAX_UEXT_REPLY_SIZE + MAX_TRAILER_SIZE <= KALLOC_SAFE_ALLOC_SIZE);

kern_return_t
IOUserServer::server(ipc_kmsg_t requestkmsg, IORPCMessage * message, ipc_kmsg_t * pReply)
{
	kern_return_t      ret;
	mach_msg_size_t    replyAlloc;
	ipc_kmsg_t         replykmsg;
	IORPCMessageMach * msgin;
	IORPCMessageMach * msgout;
	IORPCMessage     * reply;
	uint32_t           replySize;
	OSObject         * object;
	OSAction         * action;
	bool               oneway;
	uint64_t           msgid;

	msgin   = (typeof(msgin))ikm_header(requestkmsg);
	replyAlloc = 0;
	msgout = NULL;
	replykmsg = NULL;

	if (msgin->msgh.msgh_size < (sizeof(IORPCMessageMach) + sizeof(IORPCMessage))) {
		if (kIODKLogIPC & gIODKDebug) {
			DKLOG("UEXT notify %o\n", msgin->msgh.msgh_id);
		}
		return KERN_NOT_SUPPORTED;
	}

	if (!(MACH_MSGH_BITS_COMPLEX & msgin->msgh.msgh_bits)) {
		msgin->msgh_body.msgh_descriptor_count = 0;
	}
	if (!message) {
		return kIOReturnIPCError;
	}
	if (message->objectRefs == 0) {
		return kIOReturnIPCError;
	}
	ret = copyInObjects(msgin, message, msgin->msgh.msgh_size, true, false);
	if (kIOReturnSuccess != ret) {
		if (kIODKLogIPC & gIODKDebug) {
			DKLOG("UEXT copyin(0x%x) %x\n", ret, msgin->msgh.msgh_id);
		}
		return KERN_NOT_SUPPORTED;
	}

	if (msgin->msgh_body.msgh_descriptor_count < 1) {
		return KERN_NOT_SUPPORTED;
	}
	object = (OSObject *) message->objects[0];
	msgid = message->msgid;
	message->flags &= ~kIORPCMessageKernel;
	message->flags |= kIORPCMessageRemote;

	if ((action = OSDynamicCast(OSAction, object))) {
		object = target(action, message);
		msgid  = message->msgid;
	}

	oneway = (0 != (kIORPCMessageOneway & message->flags));
	assert(oneway || (MACH_PORT_NULL != msgin->msgh.msgh_local_port));

	replyAlloc = oneway ? 0 : MAX_UEXT_REPLY_SIZE;




	if (replyAlloc) {
		/*
		 * Same as:
		 *    ipc_kmsg_alloc(MAX_UEXT_REPLY_SIZE_MACH, MAX_UEXT_REPLY_SIZE_MESSAGE,
		 *        IPC_KMSG_ALLOC_KERNEL | IPC_KMSG_ALLOC_ZERO | IPC_KMSG_ALLOC_LINEAR |
		 *        IPC_KMSG_ALLOC_NOFAIL);
		 */
		replykmsg = ipc_kmsg_alloc_uext_reply(MAX_UEXT_REPLY_SIZE);
		msgout = (typeof(msgout))ikm_header(replykmsg);
	}

	IORPC rpc = { .message = msgin, .reply = msgout, .sendSize = msgin->msgh.msgh_size, .replySize = replyAlloc, .kernelContent = message };

	if (object) {
		kern_allocation_name_t prior;
		bool                   setAllocationName;

		setAllocationName = (NULL != fAllocationName);
		if (setAllocationName) {
			prior = thread_set_allocation_name(fAllocationName);
		}
		thread_iokit_tls_set(0, this);
		ret = kernelDispatch(object, rpc);
		thread_iokit_tls_set(0, NULL);
		if (setAllocationName) {
			thread_set_allocation_name(prior);
		}
	} else {
		ret = kIOReturnBadArgument;
	}

	// release objects
	consumeObjects(message, msgin->msgh.msgh_size);

	// release ports
	copyInObjects(msgin, message, msgin->msgh.msgh_size, false, true);

	if (!oneway) {
		if (kIOReturnSuccess == ret) {
			replySize = msgout->msgh.msgh_size;
			reply = IORPCMessageFromMachReply(msgout);
			if (!reply) {
				ret = kIOReturnIPCError;
			} else {
				ret = copyOutObjects(msgout, reply, replySize, (kIORPCVersionCurrentReply == msgout->msgh.msgh_id) /* =>!InvokeReply */);
			}
		}
		if (kIOReturnSuccess != ret) {
			IORPCMessageErrorReturnContent * errorMsg;

			msgout->msgh_body.msgh_descriptor_count = 0;
			msgout->msgh.msgh_id                    = kIORPCVersionCurrentReply;
			errorMsg = (typeof(errorMsg))IORPCMessageFromMachReply(msgout);
			errorMsg->hdr.msgid      = message->msgid;
			errorMsg->hdr.flags      = kIORPCMessageOneway | kIORPCMessageError;
			errorMsg->hdr.objectRefs = 0;
			errorMsg->result         = ret;
			errorMsg->pad            = 0;
			replySize                = sizeof(IORPCMessageErrorReturn);
		}

		msgout->msgh.msgh_bits = MACH_MSGH_BITS_COMPLEX |
		    MACH_MSGH_BITS_SET(MACH_MSGH_BITS_LOCAL(msgin->msgh.msgh_bits) /*remote*/, 0 /*local*/, 0, 0);

		msgout->msgh.msgh_remote_port  = msgin->msgh.msgh_local_port;
		msgout->msgh.msgh_local_port   = MACH_PORT_NULL;
		msgout->msgh.msgh_voucher_port = (mach_port_name_t) 0;
		msgout->msgh.msgh_reserved     = 0;
		msgout->msgh.msgh_size         = replySize;
	}

	*pReply = replykmsg;
	return KERN_SUCCESS;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define MAX_OBJECT_COUNT(mach, size, message) \
	((uint32_t)(((((size) + ((uintptr_t) (mach))) - ((uintptr_t) (&message->objects[0]))) / sizeof(OSObjectRef))))

#pragma pack(push, 4)
struct UEXTTrapReply {
	uint64_t replySize;
	IORPCMessage replyMessage;
};
#pragma pack(pop)

kern_return_t
IOUserServerUEXTTrap(OSObject * object, void * p1, void * p2, void * p3, void * p4, void * p5, void * p6)
{
	const user_addr_t msg              = (uintptr_t) p1;
	size_t            inSize           = (uintptr_t) p2;
	user_addr_t       out              = (uintptr_t) p3;
	size_t            outSize          = (uintptr_t) p4;
	mach_port_name_t  objectName1      = (mach_port_name_t)(uintptr_t) p5;
	size_t            totalSize;
	OSObject        * objectArg1;

	IORPCMessageMach *  mach;
	mach_msg_port_descriptor_t * descs;

#pragma pack(4)
	struct {
		uint32_t                   pad;
		IORPCMessageMach           mach;
		mach_msg_port_descriptor_t objects[2];
		IOTrapMessageBuffer        buffer;
	} buffer;
#pragma pack()

	IOReturn           ret;
	OSAction         * action;
	int                copyerr;
	IORPCMessage     * message;
	IORPCMessage     * reply;
	IORPC              rpc;
	uint64_t           refs;
	uint32_t           maxObjectCount;
	size_t             copySize;
	UEXTTrapReply    * replyHdr;
	uintptr_t          p;

	bzero(&buffer, sizeof(buffer));

	p = (typeof(p)) & buffer.buffer[0];
	if (os_add_overflow(inSize, outSize, &totalSize)) {
		return kIOReturnMessageTooLarge;
	}
	if (totalSize > sizeof(buffer.buffer)) {
		return kIOReturnMessageTooLarge;
	}
	if (inSize < sizeof(IORPCMessage)) {
		return kIOReturnIPCError;
	}
	copyerr = copyin(msg, &buffer.buffer[0], inSize);
	if (copyerr) {
		return kIOReturnVMError;
	}

	message = (typeof(message))p;
	refs    = message->objectRefs;
	if ((refs > 2) || !refs) {
		return kIOReturnUnsupported;
	}
	if (!(kIORPCMessageSimpleReply & message->flags)) {
		return kIOReturnUnsupported;
	}
	message->flags &= ~(kIORPCMessageKernel | kIORPCMessageRemote);

	descs = (typeof(descs))(p - refs * sizeof(*descs));
	mach  = (typeof(mach))(p - refs * sizeof(*descs) - sizeof(*mach));

	mach->msgh.msgh_id   = kIORPCVersionCurrent;
	mach->msgh.msgh_size = (mach_msg_size_t) (sizeof(IORPCMessageMach) + refs * sizeof(*descs) + inSize); // totalSize was checked
	mach->msgh_body.msgh_descriptor_count = ((mach_msg_size_t) refs);

	rpc.message   = mach;
	rpc.sendSize  = mach->msgh.msgh_size;
	rpc.reply     = (IORPCMessageMach *) (p + inSize);
	rpc.replySize = ((uint32_t) (sizeof(buffer.buffer) - inSize));    // inSize was checked
	rpc.kernelContent = message;

	message->objects[0] = 0;
	if ((action = OSDynamicCast(OSAction, object))) {
		maxObjectCount = MAX_OBJECT_COUNT(rpc.message, rpc.sendSize, message);
		if (refs > maxObjectCount) {
			return kIOReturnBadArgument;
		}
		if (refs < 2) {
			DKLOG("invalid refs count %qd in message id 0x%qx\n", refs, message->msgid);
			return kIOReturnBadArgument;
		}
		object = IOUserServer::target(action, message);
		message->objects[1] = (OSObjectRef) action;
		if (kIODKLogIPC & gIODKDebug) {
			DKLOG("%s::Dispatch(trap) kernel 0x%qx\n", object->getMetaClass()->getClassName(), message->msgid);
		}
		ret = object->Dispatch(rpc);
	} else {
		objectArg1 = NULL;
		if (refs > 1) {
			if (objectName1) {
				objectArg1 = iokit_lookup_uext_ref_current_task(objectName1);
				if (!objectArg1) {
					return kIOReturnIPCError;
				}
			}
			message->objects[1] = (OSObjectRef) objectArg1;
		}
		if (kIODKLogIPC & gIODKDebug) {
			DKLOG("%s::Dispatch(trap) kernel 0x%qx\n", object->getMetaClass()->getClassName(), message->msgid);
		}
		ret = object->Dispatch(rpc);
		if (kIODKLogIPC & gIODKDebug) {
			DKLOG("%s::Dispatch(trap) kernel 0x%qx 0x%x\n", object->getMetaClass()->getClassName(), message->msgid, ret);
		}
		OSSafeReleaseNULL(objectArg1);

		if (kIOReturnSuccess == ret) {
			if (rpc.reply->msgh_body.msgh_descriptor_count) {
				return kIOReturnIPCError;
			}
			reply = IORPCMessageFromMachReply(rpc.reply);
			if (!reply) {
				return kIOReturnIPCError;
			}
			copySize = rpc.reply->msgh.msgh_size - (((uintptr_t) reply) - ((uintptr_t) rpc.reply)) + sizeof(uint64_t);
			if (copySize > outSize) {
				return kIOReturnIPCError;
			}
			replyHdr = (UEXTTrapReply *) ((uintptr_t)reply - sizeof(uint64_t));
			replyHdr->replySize = copySize;
			copyerr = copyout(replyHdr, out, copySize);
			if (copyerr) {
				return kIOReturnVMError;
			}
		}
	}

	return ret;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOReturn
IOUserServer::rpc(IORPC rpc)
{
	if (isInactive() && !fRootQueue) {
		return kIOReturnOffline;
	}

	IOReturn           ret;
	IORPCMessage     * message;
	IORPCMessageMach * mach;
	mach_msg_id_t      machid;
	uint32_t           sendSize, replySize;
	bool               oneway;
	uint64_t           msgid;
	IODispatchQueue  * queue;
	IOService        * service;
	ipc_port_t         port;
	ipc_port_t         sendPort;

	queue    = NULL;
	port     = NULL;
	sendPort = NULL;

	mach      = rpc.message;
	sendSize  = rpc.sendSize;
	replySize = rpc.replySize;

	assert(sendSize >= (sizeof(IORPCMessageMach) + sizeof(IORPCMessage)));

	message = rpc.kernelContent;
	if (!message) {
		return kIOReturnIPCError;
	}
	msgid   = message->msgid;
	machid  = (msgid >> 32);

	if (mach->msgh_body.msgh_descriptor_count < 1) {
		return kIOReturnNoMedia;
	}

	IOLockLock(gIOUserServerLock);
	if ((service = OSDynamicCast(IOService, (OSObject *) message->objects[0]))) {
		queue = queueForObject(service, msgid);
	}
	if (!queue) {
		queue = fRootQueue;
	}
	if (queue && (kIODispatchQueueStopped != queue)) {
		port = queue->ivars->serverPort;
	}
	if (port) {
		sendPort = ipc_port_copy_send_mqueue(port);
	}
	IOLockUnlock(gIOUserServerLock);
	if (!sendPort) {
		return kIOReturnNotReady;
	}

	oneway = (0 != (kIORPCMessageOneway & message->flags));

	ret = copyOutObjects(mach, message, sendSize, false);

	mach->msgh.msgh_bits = MACH_MSGH_BITS_COMPLEX |
	    MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, (oneway ? 0 : MACH_MSG_TYPE_MAKE_SEND_ONCE));
	mach->msgh.msgh_remote_port  = sendPort;
	mach->msgh.msgh_local_port   = (oneway ? MACH_PORT_NULL : mig_get_reply_port());
	mach->msgh.msgh_id           = kIORPCVersionCurrent;
	mach->msgh.msgh_reserved     = 0;

	boolean_t message_moved;

	if (oneway) {
		ret = kernel_mach_msg_send(&mach->msgh, sendSize,
		    MACH_SEND_MSG | MACH_SEND_ALWAYS | MACH_SEND_NOIMPORTANCE,
		    0, &message_moved);
	} else {
		assert(replySize >= (sizeof(IORPCMessageMach) + sizeof(IORPCMessage)));
		ret = kernel_mach_msg_rpc(&mach->msgh, sendSize, replySize, FALSE, &message_moved);
	}

	ipc_port_release_send(sendPort);

	if (MACH_MSG_SUCCESS != ret) {
		if (kIODKLogIPC & gIODKDebug) {
			DKLOG("mach_msg() failed 0x%x\n", ret);
		}
		if (!message_moved) {
			// release ports
			copyInObjects(mach, message, sendSize, false, true);
		}
	}

	if ((KERN_SUCCESS == ret) && !oneway) {
		if (kIORPCVersionCurrentReply != mach->msgh.msgh_id) {
			ret = (MACH_NOTIFY_SEND_ONCE == mach->msgh.msgh_id) ? MIG_SERVER_DIED : MIG_REPLY_MISMATCH;
		} else if ((replySize = mach->msgh.msgh_size) < (sizeof(IORPCMessageMach) + sizeof(IORPCMessage))) {
//				printf("BAD REPLY SIZE\n");
			ret = MIG_BAD_ARGUMENTS;
		} else {
			if (!(MACH_MSGH_BITS_COMPLEX & mach->msgh.msgh_bits)) {
				mach->msgh_body.msgh_descriptor_count = 0;
			}
			message = IORPCMessageFromMachReply(mach);
			if (!message) {
				ret = kIOReturnIPCError;
			} else if (message->msgid != msgid) {
//					printf("BAD REPLY ID\n");
				ret = MIG_BAD_ARGUMENTS;
			} else {
				bool isError = (0 != (kIORPCMessageError & message->flags));
				ret = copyInObjects(mach, message, replySize, !isError, true);
				if (kIOReturnSuccess != ret) {
					if (kIODKLogIPC & gIODKDebug) {
						DKLOG("rpc copyin(0x%x) %x\n", ret, mach->msgh.msgh_id);
					}
					return KERN_NOT_SUPPORTED;
				}
				if (isError) {
					IORPCMessageErrorReturnContent * errorMsg = (typeof(errorMsg))message;
					ret = errorMsg->result;
				}
			}
		}
	}

	return ret;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static IORPCMessage *
IORPCMessageFromMachReply(IORPCMessageMach * msg)
{
	mach_msg_size_t              idx, count;
	mach_msg_port_descriptor_t * desc;
	mach_msg_port_descriptor_t * maxDesc;
	size_t                       size, msgsize;
	bool                         upgrade;
	bool                         reply = true;

	msgsize = msg->msgh.msgh_size;
	count   = msg->msgh_body.msgh_descriptor_count;
	desc    = &msg->objects[0];
	maxDesc = (typeof(maxDesc))(((uintptr_t) msg) + msgsize);
	upgrade = (msg->msgh.msgh_id != (reply ? kIORPCVersionCurrentReply : kIORPCVersionCurrent));

	if (upgrade) {
		OSReportWithBacktrace("obsolete message");
		return NULL;
	}

	for (idx = 0; idx < count; idx++) {
		if (desc >= maxDesc) {
			return NULL;
		}
		switch (desc->type) {
		case MACH_MSG_PORT_DESCRIPTOR:
			size = sizeof(mach_msg_port_descriptor_t);
			break;
		case MACH_MSG_OOL_DESCRIPTOR:
			size = sizeof(mach_msg_ool_descriptor_t);
			break;
		default:
			return NULL;
		}
		desc = (typeof(desc))(((uintptr_t) desc) + size);
	}
	return (IORPCMessage *)(uintptr_t) desc;
}

ipc_port_t
IOUserServer::copySendRightForObject(OSObject * object, ipc_kobject_type_t type)
{
	ipc_port_t port;
	ipc_port_t sendPort = NULL;
	ipc_kobject_t kobj;

	port = iokit_port_for_object(object, type, &kobj);
	if (port) {
		sendPort = ipc_kobject_make_send(port, kobj, type);
		iokit_release_port(port);
	}

	return sendPort;
}

OSObject *
IOUserServer::copyObjectForSendRight(ipc_port_t port, ipc_kobject_type_t type)
{
	OSObject * object;
	object = iokit_lookup_io_object(port, type);
	return object;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// Create a vm_map_copy_t or kalloc'ed data for memory
// to be copied out. ipc will free after the copyout.

static kern_return_t
copyoutkdata(const void * data, vm_size_t len, void ** buf)
{
	kern_return_t       err;
	vm_map_copy_t       copy;

	err = vm_map_copyin( kernel_map, CAST_USER_ADDR_T(data), len,
	    false /* src_destroy */, &copy);

	assert( err == KERN_SUCCESS );
	if (err == KERN_SUCCESS) {
		*buf = (char *) copy;
	}

	return err;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOReturn
IOUserServer::copyOutObjects(IORPCMessageMach * mach, IORPCMessage * message,
    size_t size, bool consume)
{
	uint64_t           refs;
	uint32_t           idx, maxObjectCount;
	ipc_port_t         port;
	OSObject         * object;
	size_t             descsize;
	mach_msg_port_descriptor_t * desc;
	mach_msg_ool_descriptor_t  * ool;
	vm_map_copy_t                copy;
	void                       * address;
	mach_msg_size_t              length;
	kern_return_t                kr;
	OSSerialize                * s;

	refs           = message->objectRefs;
	maxObjectCount = MAX_OBJECT_COUNT(mach, size, message);
//	assert(refs <= mach->msgh_body.msgh_descriptor_count);
//	assert(refs <= maxObjectCount);
	if (refs > mach->msgh_body.msgh_descriptor_count) {
		return kIOReturnBadArgument;
	}
	if (refs > maxObjectCount) {
		return kIOReturnBadArgument;
	}

	desc = &mach->objects[0];
	for (idx = 0; idx < refs; idx++) {
		object = (OSObject *) message->objects[idx];

		switch (desc->type) {
		case MACH_MSG_PORT_DESCRIPTOR:
			descsize = sizeof(mach_msg_port_descriptor_t);
			port = NULL;
			if (object) {
#if DEVELOPMENT || DEBUG
				if (kIODKLogIPC & gIODKDebug) {
					IOMemoryDescriptor * iomd = OSDynamicCast(IOMemoryDescriptor, object);
					if (iomd != NULL && (iomd->getFlags() & kIOMemoryThreadSafe) == 0) {
						OSReportWithBacktrace("IOMemoryDescriptor %p was created without kIOMemoryThreadSafe flag", iomd);
					}
				}
#endif /* DEVELOPMENT || DEBUG */

				port = copySendRightForObject(object, IKOT_UEXT_OBJECT);
				if (!port) {
					break;
				}
				if (consume) {
					object->release();
				}
				message->objects[idx] = 0;
			}
//		    desc->type        = MACH_MSG_PORT_DESCRIPTOR;
			desc->disposition = MACH_MSG_TYPE_MOVE_SEND;
			desc->name        = port;
			desc->pad2        = 0;
			desc->pad_end     = 0;
			break;

		case MACH_MSG_OOL_DESCRIPTOR:
			descsize = sizeof(mach_msg_ool_descriptor_t);

			length = 0;
			address = NULL;
			if (object) {
				s = OSSerialize::binaryWithCapacity(4096);
				assert(s);
				if (!s) {
					break;
				}
				s->setIndexed(true);
				if (!object->serialize(s)) {
					assert(false);
					descsize = -1UL;
					s->release();
					break;
				}
				length = s->getLength();
				kr = copyoutkdata(s->text(), length, &address);
				s->release();
				if (KERN_SUCCESS != kr) {
					descsize = -1UL;
					address = NULL;
					length = 0;
				}
				if (consume) {
					object->release();
				}
				message->objects[idx] = 0;
			}
			ool = (typeof(ool))desc;
//		    ool->type        = MACH_MSG_OOL_DESCRIPTOR;
			ool->deallocate  = false;
			ool->copy        = MACH_MSG_PHYSICAL_COPY;
			ool->size        = length;
			ool->address     = address;
			break;

		default:
			descsize = -1UL;
			break;
		}
		if (-1UL == descsize) {
			break;
		}
		desc = (typeof(desc))(((uintptr_t) desc) + descsize);
	}

	if (idx >= refs) {
		return kIOReturnSuccess;
	}

	desc = &mach->objects[0];
	while (idx--) {
		switch (desc->type) {
		case MACH_MSG_PORT_DESCRIPTOR:
			descsize = sizeof(mach_msg_port_descriptor_t);
			port = desc->name;
			if (port) {
				ipc_port_release_send(port);
			}
			break;

		case MACH_MSG_OOL_DESCRIPTOR:
			descsize = sizeof(mach_msg_ool_descriptor_t);
			ool = (typeof(ool))desc;
			copy = (vm_map_copy_t) ool->address;
			if (copy) {
				vm_map_copy_discard(copy);
			}
			break;

		default:
			descsize = -1UL;
			break;
		}
		if (-1UL == descsize) {
			break;
		}
		desc = (typeof(desc))(((uintptr_t) desc) + descsize);
	}

	return kIOReturnBadArgument;
}

IOReturn
IOUserServer::copyInObjects(IORPCMessageMach * mach, IORPCMessage * message,
    size_t size, bool copyObjects, bool consumePorts)
{
	uint64_t           refs;
	uint32_t           idx, maxObjectCount;
	ipc_port_t         port;
	OSObject         * object;
	size_t                       descsize;
	mach_msg_port_descriptor_t * desc;
	mach_msg_ool_descriptor_t  * ool;
	vm_map_address_t             copyoutdata;
	kern_return_t                kr;

	refs           = message->objectRefs;
	maxObjectCount = MAX_OBJECT_COUNT(mach, size, message);
//	assert(refs <= mach->msgh_body.msgh_descriptor_count);
//	assert(refs <= maxObjectCount);
	if (refs > mach->msgh_body.msgh_descriptor_count) {
		return kIOReturnBadArgument;
	}
	if (refs > maxObjectCount) {
		return kIOReturnBadArgument;
	}

	desc = &mach->objects[0];
	for (idx = 0; idx < refs; idx++) {
		switch (desc->type) {
		case MACH_MSG_PORT_DESCRIPTOR:
			descsize = sizeof(mach_msg_port_descriptor_t);

			object = NULL;
			port = desc->name;
			if (port) {
				if (copyObjects) {
					object = copyObjectForSendRight(port, IKOT_UEXT_OBJECT);
					if (!object) {
						descsize = -1UL;
						break;
					}
				}
				if (consumePorts) {
					ipc_port_release_send(port);
				}
			}
			break;

		case MACH_MSG_OOL_DESCRIPTOR:
			descsize = sizeof(mach_msg_ool_descriptor_t);
			ool = (typeof(ool))desc;

			object = NULL;
			if (copyObjects && ool->size && ool->address) {
				kr = vm_map_copyout(kernel_map, &copyoutdata, (vm_map_copy_t) ool->address);
				if (KERN_SUCCESS == kr) {
					object = OSUnserializeXML((const char *) copyoutdata, ool->size);
					kr = vm_deallocate(kernel_map, copyoutdata, ool->size);
					assert(KERN_SUCCESS == kr);
					// vm_map_copyout() has consumed the vm_map_copy_t in the message
					ool->size = 0;
					ool->address = NULL;
				}
				if (!object) {
					descsize = -1UL;
					break;
				}
			}
			break;

		default:
			descsize = -1UL;
			break;
		}
		if (-1UL == descsize) {
			break;
		}
		if (copyObjects) {
			message->objects[idx] = (OSObjectRef) object;
		}
		desc = (typeof(desc))(((uintptr_t) desc) + descsize);
	}

	if (idx >= refs) {
		return kIOReturnSuccess;
	}

	while (idx--) {
		object = (OSObject *) message->objects[idx];
		OSSafeReleaseNULL(object);
		message->objects[idx] = 0;
	}

	return kIOReturnBadArgument;
}

IOReturn
IOUserServer::consumeObjects(IORPCMessage * message, size_t messageSize)
{
	uint64_t    refs, idx;
	OSObject  * object;

	refs   = message->objectRefs;
	for (idx = 0; idx < refs; idx++) {
		object = (OSObject *) message->objects[idx];
		if (object) {
			object->release();
			message->objects[idx] = 0;
		}
	}

	return kIOReturnSuccess;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

bool
IOUserServer::finalize(IOOptionBits options)
{
	OSArray   * services;

	if (kIODKLogSetup & gIODKDebug) {
		DKLOG("%s::finalize(%p)\n", getName(), this);
	}

	IOLockLock(gIOUserServerLock);
	OSSafeReleaseNULL(fRootQueue);
	IOLockUnlock(gIOUserServerLock);

	services = NULL;
	IOLockLock(fLock);
	if (fServices) {
		services = OSArray::withArray(fServices);
	}
	IOLockUnlock(fLock);

	IOOptionBits terminateFlags = kIOServiceTerminateNeedWillTerminate | kIOServiceTerminateWithRematch;
	if (fCheckInToken) {
		bool can_rematch = fCheckInToken->dextTerminate();
		if (can_rematch) {
			terminateFlags |= kIOServiceTerminateWithRematchCurrentDext;
		} else {
			DKLOG("%s::finalize(%p) dext was replaced, do not rematch current dext\n", getName(), this);
		}
	} else {
		terminateFlags |= kIOServiceTerminateWithRematchCurrentDext;
		DKLOG("%s::finalize(%p) could not find fCheckInToken\n", getName(), this);
	}

	if (services) {
		services->iterateObjects(^bool (OSObject * obj) {
			int         service __unused;       // hide outer defn
			IOService * nextService;
			IOService * provider;
			bool        started = false;

			nextService = (IOService *) obj;
			if (kIODKLogSetup & gIODKDebug) {
			        DKLOG("%s::terminate(" DKS ")\n", getName(), DKN(nextService));
			}
			if (nextService->reserved->uvars) {
			        IOUserClient * nextUserClient = OSDynamicCast(IOUserClient, nextService);
			        provider = nextService->getProvider();
			        if (nextUserClient) {
			                nextUserClient->setTerminateDefer(provider, false);
				}
			        started = nextService->reserved->uvars->started;
			        nextService->reserved->uvars->serverDied = true;

			        serviceDidStop(nextService, provider);
			        if (provider != NULL && (terminateFlags & kIOServiceTerminateWithRematchCurrentDext) == 0) {
			                provider->resetRematchProperties();
				}
			        if (started) {
			                nextService->terminate(terminateFlags);
				}
			}
			if (!started) {
			        DKLOG("%s::terminate(" DKS ") server exit before start()\n", getName(), DKN(nextService));
			        serviceStop(nextService, NULL);
			}
			return false;
		});
		services->release();
	}

	return IOUserClient::finalize(options);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#undef super
#define super IOUserClient2022

OSDefineMetaClassAndStructors(IOUserServer, IOUserClient2022)

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOUserClient * IOUserServer::withTask(task_t owningTask)
{
	IOUserServer * inst;

	assert(owningTask == current_task());
	if (!task_is_driver(owningTask)) {
		DKLOG("IOUserServer may only be created with driver tasks\n");
		return NULL;
	}

	inst = new IOUserServer;
	if (inst && !inst->init()) {
		inst->release();
		inst = NULL;
		return inst;
	}
	OS_ANALYZER_SUPPRESS("82033761") inst->PMinit();

	inst->fOwningTask = current_task();
	task_reference(inst->fOwningTask);

	inst->fEntitlements = IOUserClient::copyClientEntitlements(inst->fOwningTask);

	if (!(kIODKDisableEntitlementChecking & gIODKDebug)) {
		proc_t p;
		pid_t  pid;
		const char * name;
		p = (proc_t)get_bsdtask_info(inst->fOwningTask);
		if (p) {
			name = proc_best_name(p);
			pid = proc_pid(p);
		} else {
			name = "unknown";
			pid = 0;
		}

		if (inst->fEntitlements == NULL) {
#if DEVELOPMENT || DEBUG
			panic("entitlements are missing for %s[%d]\n", name, pid);
#else
			DKLOG("entitlements are missing for %s[%d]\n", name, pid);
#endif /* DEVELOPMENT || DEBUG */
		}


		const char * dextTeamID = csproc_get_teamid(p);
		if (dextTeamID != NULL) {
			inst->fTeamIdentifier = OSString::withCString(dextTeamID);
			DKLOG("%s[%d] has team identifier %s\n", name, pid, dextTeamID);
		}

		if (!IOCurrentTaskHasEntitlement(gIODriverKitEntitlementKey->getCStringNoCopy())) {
			IOLog(kIODriverKitEntitlementKey " entitlement check failed for %s[%d]\n", name, pid);
			inst->release();
			inst = NULL;
			return inst;
		}
	}

	/* Mark the current task's space as eligible for uext object ports */
	iokit_label_dext_task(inst->fOwningTask);

	inst->fLock     = IOLockAlloc();
	inst->fServices = OSArray::withCapacity(4);
	inst->fClasses  = OSDictionary::withCapacity(16);
	inst->fClasses->setOptions(OSCollection::kSort, OSCollection::kSort);
	inst->fPlatformDriver = task_get_platform_binary(inst->fOwningTask);
	if (csproc_get_validation_category(current_proc(), &inst->fCSValidationCategory) != KERN_SUCCESS) {
		inst->fCSValidationCategory = CS_VALIDATION_CATEGORY_INVALID;
	}

	inst->setProperty(kIOUserClientDefaultLockingKey, kOSBooleanTrue);
	inst->setProperty(kIOUserClientDefaultLockingSetPropertiesKey, kOSBooleanTrue);
	inst->setProperty(kIOUserClientDefaultLockingSingleThreadExternalMethodKey, kOSBooleanTrue);
	//requirement for gIODriverKitEntitlementKey is enforced elsewhere conditionally
	inst->setProperty(kIOUserClientEntitlementsKey, kOSBooleanFalse);

	return inst;
}

static bool gIOUserServerLeakObjects = false;

bool
IOUserServer::shouldLeakObjects()
{
	return gIOUserServerLeakObjects;
}

void
IOUserServer::beginLeakingObjects()
{
	gIOUserServerLeakObjects = true;
}

bool
IOUserServer::isPlatformDriver()
{
	return fPlatformDriver;
}

int
IOUserServer::getCSValidationCategory()
{
	return fCSValidationCategory;
}


struct IOUserServerRecordExitReasonContext {
	task_t task;
	os_reason_t reason;
};

static bool
IOUserServerRecordExitReasonMatch(const OSObject *obj, void * context)
{
	IOUserServerRecordExitReasonContext * ctx = (IOUserServerRecordExitReasonContext *)context;
	IOUserServer * us = OSDynamicCast(IOUserServer, obj);
	if (us == NULL) {
		return false;
	}

	if (us->fOwningTask == ctx->task) {
		assert(us->fTaskCrashReason == OS_REASON_NULL);
		assert(ctx->reason != OS_REASON_NULL);
		os_reason_ref(ctx->reason);
		us->fTaskCrashReason = ctx->reason;
		return true;
	}

	return false;
}

extern "C" void
IOUserServerRecordExitReason(task_t task, os_reason_t reason)
{
	IOUserServerRecordExitReasonContext ctx { task, reason };
	IOUserServer::gMetaClass.applyToInstances(IOUserServerRecordExitReasonMatch, &ctx);
}

IOReturn
IOUserServer::clientClose(void)
{
	OSArray   * services;
	bool __block unexpectedExit = false;

	if (kIODKLogSetup & gIODKDebug) {
		DKLOG("%s::clientClose(%p)\n", getName(), this);
	}
	services = NULL;
	IOLockLock(fLock);
	if (fServices) {
		services = OSArray::withArray(fServices);
	}
	IOLockUnlock(fLock);

	// if this was a an expected exit, termination and stop should have detached at this
	// point, so send any provider still attached and not owned by this user server
	// the ClientCrashed() notification
	if (services) {
		services->iterateObjects(^bool (OSObject * obj) {
			int         service __unused;       // hide outer defn
			IOService * nextService;
			IOService * provider;

			nextService = (IOService *) obj;
			if (nextService->isInactive()) {
			        return false;
			}
			if (nextService->reserved && nextService->reserved->uvars && nextService->reserved->uvars->started) {
			        unexpectedExit = true;
			}
			provider = nextService->getProvider();
			if (provider
			&& (!provider->reserved->uvars || (provider->reserved->uvars->userServer != this))) {
			        if (kIODKLogSetup & gIODKDebug) {
			                DKLOG(DKS "::ClientCrashed(" DKS ")\n", DKN(provider), DKN(nextService));
				}
			        provider->ClientCrashed(nextService, 0);
			}
			return false;
		});
		services->release();
	}

	if (unexpectedExit &&
	    !gInUserspaceReboot &&
	    (fTaskCrashReason != OS_REASON_NULL && fTaskCrashReason->osr_namespace != OS_REASON_JETSAM && fTaskCrashReason->osr_namespace != OS_REASON_RUNNINGBOARD) &&
	    fStatistics != NULL) {
		OSDextCrashPolicy policy = fStatistics->recordCrash();
		bool allowPanic;
#if DEVELOPMENT || DEBUG
		allowPanic = fPlatformDriver && fEntitlements->getObject(gIODriverKitTestDriverEntitlementKey) != kOSBooleanTrue && !disable_dext_crash_reboot;
#else
		allowPanic = fPlatformDriver;
#endif /* DEVELOPMENT || DEBUG */

		if (policy == kOSDextCrashPolicyReboot && allowPanic) {
			panic("Driver %s has crashed too many times\n", getName());
		}
	}

	terminate();
	return kIOReturnSuccess;
}

IOReturn
IOUserServer::setProperties(OSObject * properties)
{
	IOReturn kr = kIOReturnUnsupported;
	return kr;
}

void
IOUserServer::stop(IOService * provider)
{
	if (fOwningTask) {
		task_deallocate(fOwningTask);
		fOwningTask = TASK_NULL;
	}

	PMstop();

	IOServicePH::serverRemove(this);

	OSSafeReleaseNULL(fRootQueue);

	if (fInterruptLock) {
		IOSimpleLockFree(fInterruptLock);
	}
}

void
IOUserServer::free()
{
	OSSafeReleaseNULL(fEntitlements);
	OSSafeReleaseNULL(fClasses);
	if (fOwningTask) {
		task_deallocate(fOwningTask);
		fOwningTask = TASK_NULL;
	}
	if (fLock) {
		IOLockFree(fLock);
	}
	OSSafeReleaseNULL(fServices);
	OSSafeReleaseNULL(fCheckInToken);
	OSSafeReleaseNULL(fStatistics);
	OSSafeReleaseNULL(fTeamIdentifier);
	if (fAllocationName) {
		kern_allocation_name_release(fAllocationName);
		fAllocationName = NULL;
	}
	if (fTaskCrashReason != OS_REASON_NULL) {
		os_reason_free(fTaskCrashReason);
	}
	IOUserClient::free();
}

IOReturn
IOUserServer::registerClass(OSClassDescription * desc, uint32_t size, OSUserMetaClass ** pCls)
{
	OSUserMetaClass * cls;
	const OSSymbol  * sym;
	uint64_t        * methodOptions;
	const char      * queueNames;
	uint32_t          methodOptionsEnd, queueNamesEnd;
	IOReturn          ret = kIOReturnSuccess;

	if (size < sizeof(OSClassDescription)) {
		assert(false);
		return kIOReturnBadArgument;
	}

	if (kIODKLogSetup & gIODKDebug) {
		DKLOG("%s::registerClass %s, %d, %d\n", getName(), desc->name, desc->queueNamesSize, desc->methodNamesSize);
	}

	if (desc->descriptionSize != size) {
		assert(false);
		return kIOReturnBadArgument;
	}
	if (os_add_overflow(desc->queueNamesOffset, desc->queueNamesSize, &queueNamesEnd)) {
		assert(false);
		return kIOReturnBadArgument;
	}
	if (queueNamesEnd > size) {
		assert(false);
		return kIOReturnBadArgument;
	}
	if (os_add_overflow(desc->methodOptionsOffset, desc->methodOptionsSize, &methodOptionsEnd)) {
		assert(false);
		return kIOReturnBadArgument;
	}
	if (methodOptionsEnd > size) {
		assert(false);
		return kIOReturnBadArgument;
	}
	// overlaps?
	if ((desc->queueNamesOffset >= desc->methodOptionsOffset) && (desc->queueNamesOffset < methodOptionsEnd)) {
		assert(false);
		return kIOReturnBadArgument;
	}
	if ((queueNamesEnd >= desc->methodOptionsOffset) && (queueNamesEnd < methodOptionsEnd)) {
		assert(false);
		return kIOReturnBadArgument;
	}

	if (desc->methodOptionsSize & ((2 * sizeof(uint64_t)) - 1)) {
		assert(false);
		return kIOReturnBadArgument;
	}
	if (sizeof(desc->name) == strnlen(desc->name, sizeof(desc->name))) {
		assert(false);
		return kIOReturnBadArgument;
	}
	if (sizeof(desc->superName) == strnlen(desc->superName, sizeof(desc->superName))) {
		assert(false);
		return kIOReturnBadArgument;
	}

	cls = OSTypeAlloc(OSUserMetaClass);
	assert(cls);
	if (!cls) {
		return kIOReturnNoMemory;
	}

	cls->description = (typeof(cls->description))IOMallocData(size);
	assert(cls->description);
	if (!cls->description) {
		assert(false);
		cls->release();
		return kIOReturnNoMemory;
	}
	bcopy(desc, cls->description, size);

	cls->methodCount = desc->methodOptionsSize / (2 * sizeof(uint64_t));
	cls->methods = IONewData(uint64_t, 2 * cls->methodCount);
	if (!cls->methods) {
		assert(false);
		cls->release();
		return kIOReturnNoMemory;
	}

	methodOptions = (typeof(methodOptions))(((uintptr_t) desc) + desc->methodOptionsOffset);
	bcopy(methodOptions, cls->methods, 2 * cls->methodCount * sizeof(uint64_t));

	queueNames = (typeof(queueNames))(((uintptr_t) desc) + desc->queueNamesOffset);
	cls->queueNames = copyInStringArray(queueNames, desc->queueNamesSize);

	sym = OSSymbol::withCString(desc->name);
	assert(sym);
	if (!sym) {
		assert(false);
		cls->release();
		return kIOReturnNoMemory;
	}

	cls->name = sym;
	cls->meta = OSMetaClass::copyMetaClassWithName(sym);
	IOLockLock(fLock);
	cls->superMeta = OSDynamicCast(OSUserMetaClass, fClasses->getObject(desc->superName));
	if (fClasses->getObject(sym) != NULL) {
		/* class with this name exists */
		ret = kIOReturnBadArgument;
	} else {
		if (fClasses->setObject(sym, cls)) {
			*pCls = cls;
		} else {
			/* could not add class to fClasses */
			ret = kIOReturnNoMemory;
		}
	}
	IOLockUnlock(fLock);
	cls->release();
	return ret;
}

IOReturn
IOUserServer::registerClass(OSClassDescription * desc, uint32_t size, OSSharedPtr<OSUserMetaClass>& pCls)
{
	OSUserMetaClass* pClsRaw = NULL;
	IOReturn result = registerClass(desc, size, &pClsRaw);
	if (result == kIOReturnSuccess) {
		pCls.reset(pClsRaw, OSRetain);
	}
	return result;
}

IOReturn
IOUserServer::setRootQueue(IODispatchQueue * queue)
{
	assert(!fRootQueue);
	if (fRootQueue) {
		return kIOReturnStillOpen;
	}
	queue->retain();
	fRootQueue = queue;

	return kIOReturnSuccess;
}


IOReturn
IOUserServer::externalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque * args)
{
	static const IOExternalMethodDispatch2022 dispatchArray[] = {
		[kIOUserServerMethodRegisterClass] = {
			.function                 = &IOUserServer::externalMethodRegisterClass,
			.checkScalarInputCount    = 0,
			.checkStructureInputSize  = kIOUCVariableStructureSize,
			.checkScalarOutputCount   = 2,
			.checkStructureOutputSize = 0,
			.allowAsync               = false,
			.checkEntitlement         = NULL,
		},
		[kIOUserServerMethodStart] = {
			.function                 = &IOUserServer::externalMethodStart,
			.checkScalarInputCount    = 1,
			.checkStructureInputSize  = 0,
			.checkScalarOutputCount   = 1,
			.checkStructureOutputSize = 0,
			.allowAsync               = false,
			.checkEntitlement         = NULL,
		},
	};

	return dispatchExternalMethod(selector, args, dispatchArray, sizeof(dispatchArray) / sizeof(dispatchArray[0]), this, NULL);
}

IOReturn
IOUserServer::externalMethodRegisterClass(OSObject * target, void * reference, IOExternalMethodArguments * args)
{
	IOReturn ret = kIOReturnBadArgument;
	mach_port_name_t portname;

	IOUserServer * me = (typeof(me))target;

	OSUserMetaClass * cls;
	if (!args->structureInputSize) {
		return kIOReturnBadArgument;
	}

	ret = me->registerClass((OSClassDescription *) args->structureInput, args->structureInputSize, &cls);
	if (kIOReturnSuccess == ret) {
		portname = iokit_make_send_right(me->fOwningTask, cls, IKOT_UEXT_OBJECT);
		assert(portname);
		args->scalarOutput[0] = portname;
		args->scalarOutput[1] = kOSObjectRPCRemote;
	}

	return ret;
}

IOReturn
IOUserServer::externalMethodStart(OSObject * target, void * reference, IOExternalMethodArguments * args)
{
	mach_port_name_t portname;

	IOUserServer * me = (typeof(me))target;

	if (!(kIODKDisableCheckInTokenVerification & gIODKDebug)) {
		mach_port_name_t checkInPortName = ((typeof(checkInPortName))args->scalarInput[0]);
		OSObject * obj = iokit_lookup_object_with_port_name(checkInPortName, IKOT_IOKIT_IDENT, me->fOwningTask);
		IOUserServerCheckInToken * retrievedToken = OSDynamicCast(IOUserServerCheckInToken, obj);
		if (retrievedToken != NULL) {
			me->setCheckInToken(retrievedToken);
		} else {
			OSSafeReleaseNULL(obj);
			return kIOReturnBadArgument;
		}
		OSSafeReleaseNULL(obj);
	}
	portname = iokit_make_send_right(me->fOwningTask, me, IKOT_UEXT_OBJECT);
	assert(portname);
	args->scalarOutput[0] = portname;
	return kIOReturnSuccess;
}
IOExternalTrap *
IOUserServer::getTargetAndTrapForIndex( IOService **targetP, UInt32 index )
{
	static const OSBoundedArray<IOExternalTrap, 1> trapTemplate = {{
									       { NULL, (IOTrap) & IOUserServer::waitInterruptTrap},
								       }};
	if (index >= trapTemplate.size()) {
		return NULL;
	}
	*targetP = this;
	return (IOExternalTrap *)&trapTemplate[index];
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOReturn
IOUserServer::serviceAttach(IOService * service, IOService * provider)
{
	IOReturn           ret;
	OSObjectUserVars * vars;
	OSObject         * prop;
	OSString         * str;
	OSSymbol const*   bundleID;
	char               execPath[1024];

	vars = IOMallocType(OSObjectUserVars);
	service->reserved->uvars = vars;

	vars->userServer = this;
	vars->userServer->retain();
	vars->uvarsLock = IOLockAlloc();
	IOLockLock(fLock);
	if (-1U == fServices->getNextIndexOfObject(service, 0)) {
		fServices->setObject(service);

		// Add to IOAssociatedServices
		OSObject * serviceArrayObj = copyProperty(gIOAssociatedServicesKey);
		OSArray * serviceArray = OSDynamicCast(OSArray, serviceArrayObj);
		if (!serviceArray) {
			serviceArray = OSArray::withCapacity(0);
		} else {
			serviceArray = OSDynamicCast(OSArray, serviceArray->copyCollection());
			assert(serviceArray != NULL);
		}

		OSNumber * registryEntryNumber = OSNumber::withNumber(service->getRegistryEntryID(), 64);
		serviceArray->setObject(registryEntryNumber);
		setProperty(gIOAssociatedServicesKey, serviceArray);
		OSSafeReleaseNULL(registryEntryNumber);
		OSSafeReleaseNULL(serviceArray);
		OSSafeReleaseNULL(serviceArrayObj);

		// populate kIOUserClassesKey

		OSUserMetaClass * userMeta;
		OSArray         * classesArray;
		const OSString  * str2;

		classesArray = OSArray::withCapacity(4);
		prop = service->copyProperty(gIOUserClassKey);
		str2 = OSDynamicCast(OSString, prop);
		userMeta = (typeof(userMeta))service->reserved->uvars->userServer->fClasses->getObject(str2);
		while (str2 && userMeta) {
			classesArray->setObject(str2);
			userMeta = userMeta->superMeta;
			if (userMeta) {
				str2 = userMeta->name;
			}
		}
		service->setProperty(gIOUserClassesKey, classesArray);
		OSSafeReleaseNULL(classesArray);
		OSSafeReleaseNULL(prop);
	}
	IOLockUnlock(fLock);

	prop = service->copyProperty(gIOUserClassKey);
	str = OSDynamicCast(OSString, prop);
	if (str) {
		service->setName(str);
	}
	OSSafeReleaseNULL(prop);

	prop = service->copyProperty(gIOModuleIdentifierKey);
	bundleID = OSDynamicCast(OSSymbol, prop);
	if (bundleID) {
		execPath[0] = 0;
		bool ok = OSKext::copyUserExecutablePath(bundleID, execPath, sizeof(execPath));
		if (ok) {
			ret = LoadModule(execPath);
			if (kIODKLogSetup & gIODKDebug) {
				DKLOG("%s::LoadModule 0x%x %s\n", getName(), ret, execPath);
			}
		}
	}
	OSSafeReleaseNULL(prop);

	ret = kIOReturnSuccess;

	return ret;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOReturn
IOUserServer::serviceNewUserClient(IOService * service, task_t owningTask, void * securityID,
    uint32_t type, OSDictionary * properties, IOUserClient ** handler)
{
	IOReturn           ret;
	IOUserClient     * uc;
	IOUserUserClient * userUC;
	OSDictionary     * entitlements;
	OSObject         * prop;
	OSObject         * bundleID;
	bool               ok = false;

	entitlements = IOUserClient::copyClientEntitlements(owningTask);
	if (!entitlements) {
		entitlements = OSDictionary::withCapacity(8);
	}
	if (entitlements) {
		if (kIOReturnSuccess == clientHasPrivilege((void *) owningTask, kIOClientPrivilegeAdministrator)) {
			entitlements->setObject(kIODriverKitUserClientEntitlementAdministratorKey, kOSBooleanTrue);
		}
		OSString * creatorName = IOCopyLogNameForPID(proc_selfpid());
		if (creatorName) {
			entitlements->setObject(kIOUserClientCreatorKey, creatorName);
			OSSafeReleaseNULL(creatorName);
		}
	}

	*handler = NULL;
	ret = service->_NewUserClient(type, entitlements, &uc);
	if (kIOReturnSuccess != ret) {
		OSSafeReleaseNULL(entitlements);
		return ret;
	}
	userUC = OSDynamicCast(IOUserUserClient, uc);
	if (!userUC) {
		uc->terminate(kIOServiceTerminateNeedWillTerminate);
		uc->setTerminateDefer(service, false);
		OSSafeReleaseNULL(uc);
		OSSafeReleaseNULL(entitlements);
		return kIOReturnUnsupported;
	}
	userUC->setTask(owningTask);

	if (!(kIODKDisableEntitlementChecking & gIODKDebug)) {
		do {
			bool checkiOS3pEntitlements;

			// check if client has com.apple.private.driverkit.driver-access and the required entitlements match the driver's entitlements
			if (entitlements && (prop = entitlements->getObject(gIODriverKitRequiredEntitlementsKey))) {
				prop->retain();
				ok = checkEntitlements(fEntitlements, prop, NULL, NULL);
				if (ok) {
					break;
				} else {
					DKLOG(DKS ":UC failed required entitlement check\n", DKN(userUC));
				}
			}

#if XNU_TARGET_OS_IOS
			checkiOS3pEntitlements = !fPlatformDriver;
			if (checkiOS3pEntitlements && fTeamIdentifier == NULL) {
				DKLOG("warning: " DKS " does not have a team identifier\n", DKN(this));
			}
#else
			checkiOS3pEntitlements = false;
#endif
			if (checkiOS3pEntitlements) {
				// App must have com.apple.developer.driverkit.communicates-with-drivers
				ok = entitlements && entitlements->getObject(gIODriverKitUserClientEntitlementCommunicatesWithDriversKey) == kOSBooleanTrue;
				if (ok) {
					// check team ID
					const char * clientTeamID = csproc_get_teamid(current_proc());
					bool sameTeam = fTeamIdentifier != NULL && clientTeamID != NULL && strncmp(fTeamIdentifier->getCStringNoCopy(), clientTeamID, CS_MAX_TEAMID_LEN) == 0;

					if (sameTeam) {
						ok = true;
					} else {
						// different team IDs, dext must have com.apple.developer.driverkit.allow-third-party-userclients
						ok = fEntitlements && fEntitlements->getObject(gIODriverKitUserClientEntitlementAllowThirdPartyUserClientsKey) == kOSBooleanTrue;
					}
					if (!ok) {
						DKLOG(DKS ":UC failed team ID check. client team=%s, driver team=%s\n", DKN(userUC), clientTeamID ? clientTeamID : "(null)", fTeamIdentifier ? fTeamIdentifier->getCStringNoCopy() : "(null)");
					}
				} else {
					DKLOG(DKS ":UC entitlement check failed, app does not have %s entitlement\n", DKN(userUC), gIODriverKitUserClientEntitlementCommunicatesWithDriversKey->getCStringNoCopy());
				}

				// When checking iOS 3rd party entitlements, do not fall through to other entitlement checks
				break;
			}

			// first party dexts and third party macOS dexts

			// check if driver has com.apple.developer.driverkit.allow-any-userclient-access
			if (fEntitlements && fEntitlements->getObject(gIODriverKitUserClientEntitlementAllowAnyKey)) {
				ok = true;
				break;
			}

			// check if client has com.apple.developer.driverkit.userclient-access and its value matches the bundle ID of the service
			bundleID = service->copyProperty(gIOModuleIdentifierKey);
			ok = (entitlements
			    && bundleID
			    && (prop = entitlements->getObject(gIODriverKitUserClientEntitlementsKey)));
			if (ok) {
				bool found __block = false;
				ok = prop->iterateObjects(^bool (OSObject * object) {
					found = object->isEqualTo(bundleID);
					return found;
				});
				ok = found;
			} else {
				OSString * bundleIDStr = OSDynamicCast(OSString, bundleID);
				DKLOG(DKS ":UC failed userclient-access check, needed bundle ID %s\n", DKN(userUC), bundleIDStr ? bundleIDStr->getCStringNoCopy() : "(null)");
			}
			OSSafeReleaseNULL(bundleID);
		} while (false);

		if (ok) {
			prop = userUC->copyProperty(gIOServiceDEXTEntitlementsKey);
			ok = checkEntitlements(entitlements, prop, NULL, NULL);
		}

		if (!ok) {
			DKLOG(DKS ":UC entitlements check failed\n", DKN(userUC));
			uc->terminate(kIOServiceTerminateNeedWillTerminate);
			uc->setTerminateDefer(service, false);
			OSSafeReleaseNULL(uc);
			OSSafeReleaseNULL(entitlements);
			return kIOReturnNotPermitted;
		}
	}

	OSSafeReleaseNULL(entitlements);
	*handler = userUC;

	return ret;
}

IOReturn
IOUserServer::serviceNewUserClient(IOService * service, task_t owningTask, void * securityID,
    uint32_t type, OSDictionary * properties, OSSharedPtr<IOUserClient>& handler)
{
	IOUserClient* handlerRaw = NULL;
	IOReturn result = serviceNewUserClient(service, owningTask, securityID, type, properties, &handlerRaw);
	handler.reset(handlerRaw, OSNoRetain);
	return result;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static IOPMPowerState
    sPowerStates[] = {
	{   .version                = kIOPMPowerStateVersion1,
	    .capabilityFlags        = 0,
	    .outputPowerCharacter   = 0,
	    .inputPowerRequirement  = 0},
	{   .version                = kIOPMPowerStateVersion1,
	    .capabilityFlags        = kIOPMLowPower,
	    .outputPowerCharacter   = kIOPMLowPower,
	    .inputPowerRequirement  = kIOPMLowPower},
	{   .version                = kIOPMPowerStateVersion1,
	    .capabilityFlags        = kIOPMPowerOn,
	    .outputPowerCharacter   = kIOPMPowerOn,
	    .inputPowerRequirement  = kIOPMPowerOn},
};

enum {
	kUserServerMaxPowerState    = 2
};

IOReturn
IOUserServer::serviceJoinPMTree(IOService * service)
{
	IOReturn    ret;
	IOService * pmProvider;
	bool        joinTree;

	if (service->reserved->uvars->userServerPM) {
		return kIOReturnSuccess;
	}

	if (!fRootNotifier) {
		ret = registerPowerDriver(this, sPowerStates, sizeof(sPowerStates) / sizeof(sPowerStates[0]));
		assert(kIOReturnSuccess == ret);
		IOServicePH::serverAdd(this);
		fRootNotifier = true;
	}

	joinTree = false;
	if (!(kIODKDisablePM & gIODKDebug) && !service->pm_vars) {
		kern_return_t  kr;
		OSDictionary * props;
		kr = service->CopyProperties_Local(&props);
		if (kIOReturnSuccess == kr) {
			if (props->getObject(kIOPMResetPowerStateOnWakeKey) == kOSBooleanTrue) {
				service->setProperty(kIOPMResetPowerStateOnWakeKey, kOSBooleanTrue);
			}
			OSSafeReleaseNULL(props);
		}
		service->PMinit();
		ret = service->registerPowerDriver(this, sPowerStates, sizeof(sPowerStates) / sizeof(sPowerStates[0]));
		assert(kIOReturnSuccess == ret);
		joinTree = true;
	}

	pmProvider = service;
	while (pmProvider && !pmProvider->inPlane(gIOPowerPlane)) {
		pmProvider = pmProvider->getProvider();
	}
	if (!pmProvider) {
		pmProvider = getPMRootDomain();
	}
	if (pmProvider) {
		IOService * entry;
		OSObject  * prop;
		OSObject  * nextProp;
		OSString  * str;

		entry = pmProvider;
		prop  = NULL;
		do {
			nextProp = entry->copyProperty("non-removable");
			if (nextProp) {
				OSSafeReleaseNULL(prop);
				prop = nextProp;
			}
			entry = entry->getProvider();
		} while (entry);
		if (prop) {
			str = OSDynamicCast(OSString, prop);
			if (str && str->isEqualTo("yes")) {
				pmProvider = NULL;
			}
			prop->release();
		}
	}

	if (!(kIODKDisablePM & gIODKDebug) && pmProvider) {
		IOLockLock(fLock);
		service->reserved->uvars->powerState = true;
		IOLockUnlock(fLock);

		if (joinTree) {
			pmProvider->joinPMtree(service);
			service->reserved->uvars->userServerPM = true;
			service->reserved->uvars->resetPowerOnWake = service->propertyExists(kIOPMResetPowerStateOnWakeKey);
		}
	}

	service->registerInterestedDriver(this);
	return kIOReturnSuccess;
}

IOReturn
IOUserServer::setPowerState(unsigned long state, IOService * service)
{
	if (kIODKLogPM & gIODKDebug) {
		DKLOG(DKS "::setPowerState(%ld) %d\n", DKN(service), state, fSystemPowerAck);
	}
	return kIOPMAckImplied;
}


IOReturn
IOUserServer::serviceSetPowerState(IOService * controllingDriver, IOService * service, IOPMPowerFlags flags, unsigned long state)
{
	IOReturn ret;
	bool sendIt = false;

	IOLockLock(fLock);
	if (service->reserved->uvars) {
		if (!fSystemOff && !(kIODKDisablePM & gIODKDebug)) {
			OSDictionary * wakeDescription;
			OSObject     * prop;
			char           wakeReasonString[128];

			wakeDescription = OSDictionary::withCapacity(4);
			if (wakeDescription) {
				wakeReasonString[0] = 0;
				getPMRootDomain()->copyWakeReasonString(wakeReasonString, sizeof(wakeReasonString));

				if (wakeReasonString[0]) {
					prop = OSString::withCString(&wakeReasonString[0]);
					wakeDescription->setObject(gIOSystemStateWakeDescriptionWakeReasonKey, prop);
					OSSafeReleaseNULL(prop);
				}
				getSystemStateNotificationService()->StateNotificationItemSet(gIOSystemStateWakeDescriptionKey, wakeDescription);
				OSSafeReleaseNULL(wakeDescription);
			}

			service->reserved->uvars->willPower = true;
			service->reserved->uvars->willPowerState = state;
			service->reserved->uvars->controllingDriver = controllingDriver;
			sendIt = true;
		} else {
			service->reserved->uvars->willPower = false;
		}
	}
	IOLockUnlock(fLock);

	if (sendIt) {
		if (kIODKLogPM & gIODKDebug) {
			DKLOG(DKS "::serviceSetPowerState(%ld) %d\n", DKN(service), state, fSystemPowerAck);
		}
		ret = service->SetPowerState((uint32_t) flags);
		if (kIOReturnSuccess == ret) {
			return 20 * 1000 * 1000;
		} else {
			IOLockLock(fLock);
			service->reserved->uvars->willPower = false;
			IOLockUnlock(fLock);
		}
	}

	return kIOPMAckImplied;
}

IOReturn
IOUserServer::powerStateWillChangeTo(IOPMPowerFlags flags, unsigned long state, IOService * service)
{
	return kIOPMAckImplied;
}

IOReturn
IOUserServer::powerStateDidChangeTo(IOPMPowerFlags flags, unsigned long state, IOService * service)
{
	unsigned int idx;
	bool         pmAck;

	pmAck = false;
	IOLockLock(fLock);
	idx = fServices->getNextIndexOfObject(service, 0);
	if (-1U == idx) {
		IOLockUnlock(fLock);
		return kIOPMAckImplied;
	}

	service->reserved->uvars->powerState = (0 != state);
	bool allPowerStates __block = service->reserved->uvars->powerState;
	if (!allPowerStates) {
		// any service on?
		fServices->iterateObjects(^bool (OSObject * obj) {
			int         service __unused;       // hide outer defn
			IOService * nextService;
			nextService = (IOService *) obj;
			allPowerStates = nextService->reserved->uvars->powerState;
			// early terminate if true
			return allPowerStates;
		});
	}
	if (kIODKLogPM & gIODKDebug) {
		DKLOG(DKS "::powerStateDidChangeTo(%ld) %d, %d\n", DKN(service), state, allPowerStates, fSystemPowerAck);
	}
	if (!allPowerStates && (pmAck = fSystemPowerAck)) {
		fSystemPowerAck = false;
		fSystemOff      = true;
	}
	IOLockUnlock(fLock);

	if (pmAck) {
		IOServicePH::serverAck(this);
	}

	return kIOPMAckImplied;
}

bool
IOUserServer::checkPMReady()
{
	bool __block ready = true;

	IOLockLock(fLock);
	// Check if any services have not completely joined the PM tree (i.e.
	// addPowerChild has not compeleted).
	fServices->iterateObjects(^bool (OSObject * obj) {
		IOPowerConnection *conn;
		IOService *service = (IOService *) obj;
		IORegistryEntry *parent = service->getParentEntry(gIOPowerPlane);
		if ((conn = OSDynamicCast(IOPowerConnection, parent))) {
		        if (!conn->getReadyFlag()) {
		                ready = false;
		                return true;
			}
		}
		return false;
	});
	IOLockUnlock(fLock);

	return ready;
}

kern_return_t
IOService::JoinPMTree_Impl(void)
{
	if (!reserved->uvars || !reserved->uvars->userServer) {
		return kIOReturnNotReady;
	}
	return reserved->uvars->userServer->serviceJoinPMTree(this);
}

kern_return_t
IOService::SetPowerState_Impl(
	uint32_t powerFlags)
{
	if (kIODKLogPM & gIODKDebug) {
		DKLOG(DKS "::SetPowerState(%d), %d\n", DKN(this), powerFlags, reserved->uvars->willPower);
	}
	if (reserved->uvars
	    && reserved->uvars->userServer
	    && reserved->uvars->willPower) {
		IOReturn ret;
		reserved->uvars->willPower = false;
		ret = reserved->uvars->controllingDriver->setPowerState(reserved->uvars->willPowerState, this);
		if (kIOPMAckImplied == ret) {
			acknowledgeSetPowerState();
		}
		return kIOReturnSuccess;
	}
	return kIOReturnNotReady;
}

kern_return_t
IOService::ChangePowerState_Impl(
	uint32_t powerFlags)
{
	switch (powerFlags) {
	case kIOServicePowerCapabilityOff:
		changePowerStateToPriv(0);
		break;
	case kIOServicePowerCapabilityLow:
		changePowerStateToPriv(1);
		break;
	case kIOServicePowerCapabilityOn:
		changePowerStateToPriv(2);
		break;
	default:
		return kIOReturnBadArgument;
	}

	return kIOReturnSuccess;
}

kern_return_t
IOService::_ClaimSystemWakeEvent_Impl(
	IOService          * device,
	uint64_t             flags,
	const char         * reason,
	OSContainer        * details)
{
	IOPMrootDomain * rootDomain;
	IOOptionBits     pmFlags;

	rootDomain = getPMRootDomain();
	if (!rootDomain) {
		return kIOReturnNotReady;
	}
	if (os_convert_overflow(flags, &pmFlags)) {
		return kIOReturnBadArgument;
	}
	rootDomain->claimSystemWakeEvent(device, pmFlags, reason, details);

	return kIOReturnSuccess;
}

kern_return_t
IOService::Create_Impl(
	IOService * provider,
	const char * propertiesKey,
	IOService ** result)
{
	OSObject       * inst;
	IOService      * service;
	OSString       * str;
	const OSSymbol * sym;
	OSObject       * prop = NULL;
	OSObject       * moduleIdentifier = NULL;
	OSObject       * userServerName = NULL;
	OSDictionary   * properties = NULL;
	OSDictionary   * copyProperties = NULL;
	kern_return_t    ret;

	if (provider != this) {
		return kIOReturnUnsupported;
	}

	ret = kIOReturnUnsupported;
	inst = NULL;
	service = NULL;

	prop = copyProperty(propertiesKey);
	properties = OSDynamicCast(OSDictionary, prop);
	if (!properties) {
		ret = kIOReturnBadArgument;
		goto finish;
	}
	copyProperties = OSDynamicCast(OSDictionary, properties->copyCollection());
	if (!copyProperties) {
		ret = kIOReturnNoMemory;
		goto finish;
	}
	moduleIdentifier = copyProperty(gIOModuleIdentifierKey);
	if (moduleIdentifier) {
		copyProperties->setObject(gIOModuleIdentifierKey, moduleIdentifier);
	}
	userServerName = reserved->uvars->userServer->copyProperty(gIOUserServerNameKey);
	if (userServerName) {
		copyProperties->setObject(gIOUserServerNameKey, userServerName);
	}

	str = OSDynamicCast(OSString, copyProperties->getObject(gIOClassKey));
	if (!str) {
		ret = kIOReturnBadArgument;
		goto finish;
	}
	sym = OSSymbol::withString(str);
	if (sym) {
		inst = OSMetaClass::allocClassWithName(sym);
		service = OSDynamicCast(IOService, inst);
		if (service && service->init(copyProperties) && service->attach(this)) {
			reserved->uvars->userServer->serviceAttach(service, this);
			service->reserved->uvars->started = true;
			ret = kIOReturnSuccess;
			*result = service;
		}
		OSSafeReleaseNULL(sym);
	}

finish:
	OSSafeReleaseNULL(prop);
	OSSafeReleaseNULL(copyProperties);
	OSSafeReleaseNULL(moduleIdentifier);
	OSSafeReleaseNULL(userServerName);
	if (kIOReturnSuccess != ret) {
		OSSafeReleaseNULL(inst);
	}

	return ret;
}

kern_return_t
IOService::Terminate_Impl(
	uint64_t options)
{
	IOUserServer * us;

	if (options) {
		return kIOReturnUnsupported;
	}

	us = (typeof(us))thread_iokit_tls_get(0);
	if (us && (!reserved->uvars
	    || (reserved->uvars->userServer != us))) {
		return kIOReturnNotPermitted;
	}
	terminate(kIOServiceTerminateNeedWillTerminate);

	return kIOReturnSuccess;
}

kern_return_t
IOService::NewUserClient_Impl(
	uint32_t type,
	IOUserClient ** userClient)
{
	return kIOReturnError;
}

kern_return_t
IOService::_NewUserClient_Impl(
	uint32_t type,
	OSDictionary * entitlements,
	IOUserClient ** userClient)
{
	return kIOReturnError;
}

kern_return_t
IOService::SearchProperty_Impl(
	const char * name,
	const char * plane,
	uint64_t options,
	OSContainer ** property)
{
	OSObject   * object __block;
	IOService  * provider;
	IOOptionBits regOptions;

	if (kIOServiceSearchPropertyParents & options) {
		regOptions = kIORegistryIterateParents | kIORegistryIterateRecursively;
	} else {
		regOptions = 0;
	}

	object = copyProperty(name, IORegistryEntry::getPlane(plane), regOptions);

	if (NULL == object) {
		for (provider = this; provider; provider = provider->getProvider()) {
			provider->runPropertyActionBlock(^IOReturn (void) {
				OSDictionary * userProps;
				object = provider->getProperty(name);
				if (!object
				&& (userProps = OSDynamicCast(OSDictionary, provider->getProperty(gIOUserServicePropertiesKey)))) {
				        object = userProps->getObject(name);
				}
				if (object) {
				        object->retain();
				}
				return kIOReturnSuccess;
			});
			if (object || !(kIORegistryIterateParents & options)) {
				break;
			}
		}
	}

	*property = object;

	return object ? kIOReturnSuccess : kIOReturnNotFound;
}

kern_return_t
IOService::StringFromReturn_Impl(
	IOReturn retval,
	OSString ** str)
{
	OSString *obj = OSString::withCString(stringFromReturn(retval));
	*str = obj;
	return obj ? kIOReturnSuccess : kIOReturnError;
}

#if PRIVATE_WIFI_ONLY
const char *
IOService::StringFromReturn(
	IOReturn retval)
{
	return stringFromReturn(retval);
}
#endif /* PRIVATE_WIFI_ONLY */

kern_return_t
IOService::CopyProviderProperties_Impl(
	OSArray * propertyKeys,
	OSArray ** properties)
{
	IOReturn    ret;
	OSArray   * result;
	IOService * provider;

	result = OSArray::withCapacity(8);
	if (!result) {
		return kIOReturnNoMemory;
	}

	ret = kIOReturnSuccess;
	for (provider = this; provider; provider = provider->getProvider()) {
		OSObject     * obj;
		OSDictionary * props;

		obj = provider->copyProperty(gIOSupportedPropertiesKey);
		props = OSDynamicCast(OSDictionary, obj);
		if (!props) {
			OSSafeReleaseNULL(obj);
			props = provider->dictionaryWithProperties();
		}
		if (!props) {
			ret = kIOReturnNoMemory;
			break;
		}

		bool __block addClass = true;
		if (propertyKeys) {
			OSDictionary * retProps;
			retProps = OSDictionary::withCapacity(4);
			addClass = false;
			if (!retProps) {
				ret = kIOReturnNoMemory;
				OSSafeReleaseNULL(props);
				break;
			}
			propertyKeys->iterateObjects(^bool (OSObject * _key) {
				OSString * key = OSDynamicCast(OSString, _key);
				if (gIOClassKey->isEqualTo(key)) {
				        addClass = true;
				        return false;
				}
				retProps->setObject(key, props->getObject(key));
				return false;
			});
			OSSafeReleaseNULL(props);
			props = retProps;
		}
		if (addClass) {
			OSArray * classes = OSArray::withCapacity(8);
			if (!classes) {
				OSSafeReleaseNULL(props);
				ret = kIOReturnNoMemory;
				break;
			}
			for (const OSMetaClass * meta = provider->getMetaClass(); meta; meta = meta->getSuperClass()) {
				classes->setObject(meta->getClassNameSymbol());
			}
			props->setObject(gIOClassKey, classes);
			OSSafeReleaseNULL(classes);
		}
		bool ok = result->setObject(props);
		props->release();
		if (!ok) {
			ret = kIOReturnNoMemory;
			break;
		}
	}
	if (kIOReturnSuccess != ret) {
		OSSafeReleaseNULL(result);
	}
	*properties = result;
	return ret;
}

IOReturn
IOService::AdjustBusy_Impl(int32_t delta)
{
	adjustBusy(delta);
	return kIOReturnSuccess;
}

IOReturn
IOService::GetBusyState_Impl(uint32_t *busyState)
{
	*busyState = getBusyState();
	return kIOReturnSuccess;
}

void
IOUserServer::systemPower(bool powerOff)
{
	OSArray * services;
	{
		OSDictionary * sleepDescription;
		OSObject     * prop;

		sleepDescription = OSDictionary::withCapacity(4);
		if (sleepDescription) {
			prop = getPMRootDomain()->copyProperty(kRootDomainSleepReasonKey);
			if (prop) {
				sleepDescription->setObject(gIOSystemStateSleepDescriptionReasonKey, prop);
				OSSafeReleaseNULL(prop);
			}
			prop = getPMRootDomain()->copyProperty(kIOHibernateStateKey);
			if (prop) {
				sleepDescription->setObject(gIOSystemStateSleepDescriptionHibernateStateKey, prop);
				OSSafeReleaseNULL(prop);
			}
			getSystemStateNotificationService()->StateNotificationItemSet(gIOSystemStateSleepDescriptionKey, sleepDescription);
			OSSafeReleaseNULL(sleepDescription);
		}
	}

	IOLockLock(fLock);

	services = OSArray::withArray(fServices);

	bool allPowerStates __block = 0;
	// any service on?
	fServices->iterateObjects(^bool (OSObject * obj) {
		int         service __unused;       // hide outer defn
		IOService * nextService;
		nextService = (IOService *) obj;
		allPowerStates = nextService->reserved->uvars->powerState;
		// early terminate if true
		return allPowerStates;
	});

	if (kIODKLogPM & gIODKDebug) {
		DKLOG("%s::powerOff(%d) %d\n", getName(), powerOff, allPowerStates);
	}

	if (powerOff) {
		fSystemPowerAck = allPowerStates;
		if (!fSystemPowerAck) {
			fSystemOff = true;
		}
		IOLockUnlock(fLock);

		if (!fSystemPowerAck) {
			IOServicePH::serverAck(this);
		} else {
			if (services) {
				services->iterateObjects(^bool (OSObject * obj) {
					int         service __unused;       // hide outer defn
					IOService * nextService;
					nextService = (IOService *) obj;
					if (kIODKLogPM & gIODKDebug) {
					        DKLOG("changePowerStateWithOverrideTo(" DKS ", %d)\n", DKN(nextService), 0);
					}
					nextService->reserved->uvars->powerOverride = nextService->reserved->uvars->userServerPM ? kUserServerMaxPowerState : nextService->getPowerState();
					nextService->changePowerStateWithOverrideTo(0, 0);
					return false;
				});
			}
		}
	} else {
		fSystemOff = false;
		IOLockUnlock(fLock);
		if (services) {
			services->iterateObjects(^bool (OSObject * obj) {
				int         service __unused;       // hide outer defn
				IOService * nextService;
				nextService = (IOService *) obj;
				if (-1U != nextService->reserved->uvars->powerOverride) {
				        if (kIODKLogPM & gIODKDebug) {
				                DKLOG("%schangePowerStateWithOverrideTo(" DKS ", %d)\n", nextService->reserved->uvars->resetPowerOnWake ? "!" : "", DKN(nextService), nextService->reserved->uvars->powerOverride);
					}
				        if (!nextService->reserved->uvars->resetPowerOnWake) {
				                nextService->changePowerStateWithOverrideTo(nextService->reserved->uvars->powerOverride, 0);
					}
				        nextService->reserved->uvars->powerOverride = -1U;
				}
				return false;
			});
		}
	}
	OSSafeReleaseNULL(services);
}


void
IOUserServer::systemHalt(int howto)
{
	OSArray * services;

	if (true || (kIODKLogPM & gIODKDebug)) {
		DKLOG("%s::systemHalt()\n", getName());
	}

	{
		OSDictionary * haltDescription;
		OSNumber     * state;
		uint64_t       haltStateFlags;

		haltDescription = OSDictionary::withCapacity(4);
		if (haltDescription) {
			haltStateFlags = 0;
			if (RB_HALT & howto) {
				haltStateFlags |= kIOServiceHaltStatePowerOff;
			} else {
				haltStateFlags |= kIOServiceHaltStateRestart;
			}
			state = OSNumber::withNumber(haltStateFlags, 64);
			haltDescription->setObject(gIOSystemStateHaltDescriptionHaltStateKey, state);
			getSystemStateNotificationService()->StateNotificationItemSet(gIOSystemStateHaltDescriptionKey, haltDescription);

			OSSafeReleaseNULL(state);
			OSSafeReleaseNULL(haltDescription);
		}
	}

	IOLockLock(fLock);
	services = OSArray::withArray(fServices);
	IOLockUnlock(fLock);

	if (services) {
		services->iterateObjects(^bool (OSObject * obj) {
			int         service __unused;       // hide outer defn
			IOService  * nextService;
			IOService  * provider;
			IOOptionBits terminateOptions;
			bool         root;

			nextService = (IOService *) obj;
			provider = nextService->getProvider();
			if (!provider) {
			        DKLOG("stale service " DKS " found, skipping termination\n", DKN(nextService));
			        return false;
			}
			root = (NULL == provider->getProperty(gIOUserServerNameKey, gIOServicePlane));
			if (true || (kIODKLogPM & gIODKDebug)) {
			        DKLOG("%d: terminate(" DKS ")\n", root, DKN(nextService));
			}
			if (!root) {
			        return false;
			}
			terminateOptions = kIOServiceRequired | kIOServiceTerminateNeedWillTerminate;
			if (!nextService->terminate(terminateOptions)) {
			        IOLog("failed to terminate service %s-0x%llx\n", nextService->getName(), nextService->getRegistryEntryID());
			}
			return false;
		});
	}
	OSSafeReleaseNULL(services);
}

void
IOUserServer::powerSourceChanged(bool acAttached)
{
	OSDictionary * powerSourceDescription;

	powerSourceDescription = OSDictionary::withCapacity(4);
	if (!powerSourceDescription) {
		return;
	}
	powerSourceDescription->setObject(gIOSystemStatePowerSourceDescriptionACAttachedKey, acAttached ? kOSBooleanTrue : kOSBooleanFalse);
	getSystemStateNotificationService()->StateNotificationItemSet(gIOSystemStatePowerSourceDescriptionKey, powerSourceDescription);

	OSSafeReleaseNULL(powerSourceDescription);
}

IOReturn
IOUserServer::serviceStarted(IOService * service, IOService * provider, bool result)
{
	IOReturn    ret;

	DKLOG(DKS "::start(" DKS ") %s\n", DKN(service), DKN(provider), result ? "ok" : "fail");

	if (!result) {
		ret = kIOReturnSuccess;
		return ret;
	}

	ret = serviceJoinPMTree(service);

	service->reserved->uvars->started = true;

	if (service->reserved->uvars->deferredRegisterService) {
		service->registerService(kIOServiceAsynchronous | kIOServiceDextRequirePowerForMatching);
		service->reserved->uvars->deferredRegisterService = false;
	}

	return kIOReturnSuccess;
}


IOReturn
IOUserServer::serviceOpen(IOService * provider, IOService * client)
{
	OSObjectUserVars * uvars;
	IOReturn ret;

	IOLockLock(client->reserved->uvars->uvarsLock);
	uvars = client->reserved->uvars;
	if (uvars->willTerminate || uvars->stopped) {
		DKLOG(DKS "- " DKS " blocked attempt to open " DKS "\n", DKN(this), DKN(client), DKN(provider));
		ret = kIOReturnBadArgument;
	} else {
		if (!uvars->openProviders) {
			uvars->openProviders = OSArray::withObjects((const OSObject **) &provider, 1);
		} else if (-1U == uvars->openProviders->getNextIndexOfObject(provider, 0)) {
			uvars->openProviders->setObject(provider);
		}
		ret = kIOReturnSuccess;
	}

	IOLockUnlock(client->reserved->uvars->uvarsLock);

	return ret;
}

IOReturn
IOUserServer::serviceClose(IOService * provider, IOService * client)
{
	OSObjectUserVars * uvars;
	unsigned int       idx;
	IOReturn           ret;

	IOLockLock(client->reserved->uvars->uvarsLock);
	uvars = client->reserved->uvars;
	if (!uvars->openProviders) {
		ret = kIOReturnNotOpen;
		goto finish;
	}
	idx = uvars->openProviders->getNextIndexOfObject(provider, 0);
	if (-1U == idx) {
		ret = kIOReturnNotOpen;
		goto finish;
	}
	uvars->openProviders->removeObject(idx);
	if (!uvars->openProviders->getCount()) {
		OSSafeReleaseNULL(uvars->openProviders);
	}

	ret = kIOReturnSuccess;

finish:
	IOLockUnlock(client->reserved->uvars->uvarsLock);

	return ret;
}


IOReturn
IOUserServer::serviceStop(IOService * service, IOService *)
{
	IOReturn           ret;
	uint32_t           idx, queueAlloc;
	bool               pmAck;
	OSObjectUserVars * uvars;
	IODispatchQueue ** unboundedQueueArray = NULL;
	pmAck = false;
	IOLockLock(fLock);
	idx = fServices->getNextIndexOfObject(service, 0);
	if (-1U != idx) {
		fServices->removeObject(idx);

		// Remove the service from IOAssociatedServices
		OSObject * serviceArrayObj = copyProperty(gIOAssociatedServicesKey);
		OSArray * serviceArray = OSDynamicCast(OSArray, serviceArrayObj);
		assert(serviceArray != NULL);

		serviceArray = OSDynamicCast(OSArray, serviceArray->copyCollection());
		assert(serviceArray != NULL);

		// Index should be the same as it was in fServices
		OSNumber * __assert_only registryEntryID = OSDynamicCast(OSNumber, serviceArray->getObject(idx));
		assert(registryEntryID);

		// ensure it is the right service
		assert(registryEntryID->unsigned64BitValue() == service->getRegistryEntryID());
		serviceArray->removeObject(idx);

		setProperty(gIOAssociatedServicesKey, serviceArray);
		OSSafeReleaseNULL(serviceArray);
		OSSafeReleaseNULL(serviceArrayObj);

		uvars = service->reserved->uvars;
		uvars->stopped = true;
		uvars->powerState = 0;

		bool allPowerStates __block = 0;
		// any service on?
		fServices->iterateObjects(^bool (OSObject * obj) {
			int         service __unused;       // hide outer defn
			IOService * nextService;
			nextService = (IOService *) obj;
			allPowerStates = nextService->reserved->uvars->powerState;
			// early terminate if true
			return allPowerStates;
		});

		if (!allPowerStates && (pmAck = fSystemPowerAck)) {
			fSystemPowerAck = false;
			fSystemOff      = true;
		}
	}
	IOLockUnlock(fLock);
	if (pmAck) {
		IOServicePH::serverAck(this);
	}

	if (-1U == idx) {
		return kIOReturnSuccess;
	}

	if (uvars->queueArray && uvars->userMeta) {
		queueAlloc = 1;
		if (uvars->userMeta->queueNames) {
			queueAlloc += uvars->userMeta->queueNames->count;
		}
		for (idx = 0; idx < queueAlloc; idx++) {
			OSSafeReleaseNULL(uvars->queueArray[idx]);
		}
		unboundedQueueArray = uvars->queueArray.data();
		IOSafeDeleteNULL(unboundedQueueArray, IODispatchQueue *, queueAlloc);
		uvars->queueArray = OSBoundedArrayRef<IODispatchQueue *>();
	}

	(void) service->deRegisterInterestedDriver(this);
	if (uvars->userServerPM) {
		service->PMstop();
	}

	ret = kIOReturnSuccess;
	return ret;
}

void
IOUserServer::serviceFree(IOService * service)
{
	OSObjectUserVars * uvars;

	uvars = service->reserved->uvars;
	if (!uvars) {
		return;
	}
	OSSafeReleaseNULL(uvars->userServer);
	IOLockFree(uvars->uvarsLock);
	IOFreeType(service->reserved->uvars, OSObjectUserVars);
}

void
IOUserServer::serviceWillTerminate(IOService * client, IOService * provider, IOOptionBits options)
{
	IOReturn ret;
	bool     willTerminate;

	willTerminate = false;
	IOLockLock(client->reserved->uvars->uvarsLock);
	if (!client->reserved->uvars->serverDied
	    && !client->reserved->uvars->willTerminate) {
		client->reserved->uvars->willTerminate = true;
		willTerminate = true;
	}
	IOLockUnlock(client->reserved->uvars->uvarsLock);

	if (willTerminate) {
		if (provider->isInactive() || IOServicePH::serverSlept()) {
			client->Stop_async(provider);
			ret = kIOReturnOffline;
		} else {
			ret = client->Stop(provider);
		}
		if (kIOReturnSuccess != ret) {
			IOUserServer::serviceDidStop(client, provider);
			ret = kIOReturnSuccess;
		}
	}
}

void
IOUserServer::serviceDidTerminate(IOService * client, IOService * provider, IOOptionBits options, bool * defer)
{
	IOLockLock(client->reserved->uvars->uvarsLock);
	client->reserved->uvars->didTerminate = true;
	if (!client->reserved->uvars->serverDied
	    && !client->reserved->uvars->stopped) {
		*defer = true;
	}
	IOLockUnlock(client->reserved->uvars->uvarsLock);
}

void
IOUserServer::serviceDidStop(IOService * client, IOService * provider)
{
	bool complete;
	OSArray * closeArray;

	complete = false;
	closeArray = NULL;

	IOLockLock(client->reserved->uvars->uvarsLock);
	if (client->reserved->uvars
	    && client->reserved->uvars->willTerminate
	    && !client->reserved->uvars->stopped) {
		client->reserved->uvars->stopped = true;
		complete = client->reserved->uvars->didTerminate;
	}

	if (client->reserved->uvars) {
		closeArray = client->reserved->uvars->openProviders;
		client->reserved->uvars->openProviders = NULL;
	}
	IOLockUnlock(client->reserved->uvars->uvarsLock);

	if (closeArray) {
		closeArray->iterateObjects(^bool (OSObject * obj) {
			IOService * toClose;
			toClose = OSDynamicCast(IOService, obj);
			if (toClose) {
			        DKLOG(DKS ":force close (" DKS ")\n", DKN(client), DKN(toClose));
			        toClose->close(client);
			}
			return false;
		});
		closeArray->release();
	}

	if (complete) {
		bool defer = false;
		client->didTerminate(provider, 0, &defer);
	}
}

kern_return_t
IOService::ClientCrashed_Impl(
	IOService * client,
	uint64_t    options)
{
	return kIOReturnUnsupported;
}

kern_return_t
IOService::Stop_Impl(
	IOService * provider)
{
	IOUserServer::serviceDidStop(this, provider);

	return kIOReturnSuccess;
}

void
IOService::Stop_async_Impl(
	IOService * provider)
{
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#undef super
#define super IOUserClient

OSDefineMetaClassAndStructors(IOUserUserClient, IOUserClient)

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

bool
IOUserUserClient::init(OSDictionary * properties)
{
	if (!super::init(properties)) {
		return false;
	}

	fWorkGroups = OSDictionary::withCapacity(0);
	if (fWorkGroups == NULL) {
		return false;
	}

	fEventLinks = OSDictionary::withCapacity(0);
	if (fEventLinks == NULL) {
		return false;
	}

	fLock = IOLockAlloc();

	return true;
}

void
IOUserUserClient::free()
{
	OSSafeReleaseNULL(fWorkGroups);
	OSSafeReleaseNULL(fEventLinks);
	if (fLock) {
		IOLockFree(fLock);
	}

	super::free();
}

IOReturn
IOUserUserClient::setTask(task_t task)
{
	task_reference(task);
	fTask = task;

	return kIOReturnSuccess;
}

void
IOUserUserClient::stop(IOService * provider)
{
	if (fTask) {
		task_deallocate(fTask);
		fTask = NULL;
	}
	super::stop(provider);
}

IOReturn
IOUserUserClient::clientClose(void)
{
	terminate(kIOServiceTerminateNeedWillTerminate);
	return kIOReturnSuccess;
}

IOReturn
IOUserUserClient::setProperties(OSObject * properties)
{
	IOReturn ret = kIOReturnUnsupported;
	return ret;
}

// p1 - name of object
// p2 - length of object name
// p3 - mach port name

kern_return_t
IOUserUserClient::eventlinkConfigurationTrap(void * p1, void * p2, void * p3, void * p4, void * p5, void * p6)
{
	user_addr_t userObjectName = (user_addr_t)p1;
	mach_port_name_t portName = (mach_port_name_t)(uintptr_t)p3;
	mach_port_t port = MACH_PORT_NULL;
	ipc_kobject_type_t portType;
	char eventlinkName[kIOEventLinkMaxNameLength + 1] = {0};
	size_t eventLinkNameLen;
	OSString * eventlinkNameStr = NULL; // must release
	IOEventLink * eventLink = NULL; // do not release
	kern_return_t ret;

	ret = copyinstr(userObjectName, &eventlinkName[0], sizeof(eventlinkName), &eventLinkNameLen);
	if (ret != kIOReturnSuccess) {
		goto finish;
	}

	// ensure string length matches trap argument
	if (eventLinkNameLen != (size_t)p2 + 1) {
		ret = kIOReturnBadArgument;
		goto finish;
	}

	eventlinkNameStr = OSString::withCStringNoCopy(eventlinkName);
	if (eventlinkNameStr == NULL) {
		ret = kIOReturnNoMemory;
		goto finish;
	}

	IOLockLock(fLock);
	eventLink = OSDynamicCast(IOEventLink, fEventLinks->getObject(eventlinkNameStr));
	if (eventLink) {
		eventLink->retain();
	}
	IOLockUnlock(fLock);

	if (eventLink == NULL) {
		ret = kIOReturnNotFound;
		goto finish;
	}

	port = iokit_lookup_raw_current_task(portName, &portType);

	if (port == NULL) {
		ret = kIOReturnNotFound;
		goto finish;
	}

	if (portType != IKOT_EVENTLINK) {
		ret = kIOReturnBadArgument;
		goto finish;
	}

	ret = eventLink->SetEventlinkPort(port);
	if (ret != kIOReturnSuccess) {
		if (kIODKLogSetup & gIODKDebug) {
			DKLOG(DKS " %s SetEventlinkPort() returned %x\n", DKN(this), eventlinkNameStr->getCStringNoCopy(), ret);
		}
		goto finish;
	}

finish:
	if (port != NULL) {
		iokit_release_port_send(port);
	}

	OSSafeReleaseNULL(eventlinkNameStr);
	OSSafeReleaseNULL(eventLink);

	return ret;
}

kern_return_t
IOUserUserClient::workgroupConfigurationTrap(void * p1, void * p2, void * p3, void * p4, void * p5, void * p6)
{
	user_addr_t userObjectName = (user_addr_t)p1;
	mach_port_name_t portName = (mach_port_name_t)(uintptr_t)p3;
	mach_port_t port = MACH_PORT_NULL;
	ipc_kobject_type_t portType;
	char workgroupName[kIOWorkGroupMaxNameLength + 1] = {0};
	size_t workgroupNameLen;
	OSString * workgroupNameStr = NULL; // must release
	IOWorkGroup * workgroup = NULL; // do not release
	kern_return_t ret;

	ret = copyinstr(userObjectName, &workgroupName[0], sizeof(workgroupName), &workgroupNameLen);
	if (ret != kIOReturnSuccess) {
		goto finish;
	}

	// ensure string length matches trap argument
	if (workgroupNameLen != (size_t)p2 + 1) {
		ret = kIOReturnBadArgument;
		goto finish;
	}

	workgroupNameStr = OSString::withCStringNoCopy(workgroupName);
	if (workgroupNameStr == NULL) {
		ret = kIOReturnNoMemory;
		goto finish;
	}

	IOLockLock(fLock);
	workgroup = OSDynamicCast(IOWorkGroup, fWorkGroups->getObject(workgroupNameStr));
	if (workgroup) {
		workgroup->retain();
	}
	IOLockUnlock(fLock);

	if (workgroup == NULL) {
		ret = kIOReturnNotFound;
		goto finish;
	}

	port = iokit_lookup_raw_current_task(portName, &portType);

	if (port == NULL) {
		ret = kIOReturnNotFound;
		goto finish;
	}

	if (portType != IKOT_WORK_INTERVAL) {
		ret = kIOReturnBadArgument;
		goto finish;
	}

	ret = workgroup->SetWorkGroupPort(port);
	if (ret != kIOReturnSuccess) {
		if (kIODKLogSetup & gIODKDebug) {
			DKLOG(DKS " %s SetWorkGroupPort() returned %x\n", DKN(this), workgroupNameStr->getCStringNoCopy(), ret);
		}
		goto finish;
	}

finish:

	if (port != NULL) {
		iokit_release_port_send(port);
	}

	OSSafeReleaseNULL(workgroupNameStr);
	OSSafeReleaseNULL(workgroup);

	return ret;
}

IOExternalTrap *
IOUserUserClient::getTargetAndTrapForIndex( IOService **targetP, UInt32 index )
{
	static const OSBoundedArray<IOExternalTrap, 2> trapTemplate = {{
									       { NULL, (IOTrap) & IOUserUserClient::eventlinkConfigurationTrap},
									       { NULL, (IOTrap) & IOUserUserClient::workgroupConfigurationTrap},
								       }};
	if (index >= trapTemplate.size()) {
		return NULL;
	}
	*targetP = this;
	return (IOExternalTrap *)&trapTemplate[index];
}

kern_return_t
IOUserClient::CopyClientEntitlements_Impl(OSDictionary ** entitlements)
{
	return kIOReturnUnsupported;
};

struct IOUserUserClientActionRef {
	OSAsyncReference64 asyncRef;
};

void
IOUserClient::KernelCompletion_Impl(
	OSAction * action,
	IOReturn status,
	const unsigned long long * asyncData,
	uint32_t asyncDataCount)
{
	IOUserUserClientActionRef * ref;

	ref = (typeof(ref))action->GetReference();

	IOUserClient::sendAsyncResult64(ref->asyncRef, status, (io_user_reference_t *) asyncData, asyncDataCount);
}

kern_return_t
IOUserClient::_ExternalMethod_Impl(
	uint64_t selector,
	const unsigned long long * scalarInput,
	uint32_t scalarInputCount,
	OSData * structureInput,
	IOMemoryDescriptor * structureInputDescriptor,
	unsigned long long * scalarOutput,
	uint32_t * scalarOutputCount,
	uint64_t structureOutputMaximumSize,
	OSData ** structureOutput,
	IOMemoryDescriptor * structureOutputDescriptor,
	OSAction * completion)
{
	return kIOReturnUnsupported;
}

IOReturn
IOUserUserClient::clientMemoryForType(UInt32 type,
    IOOptionBits * koptions,
    IOMemoryDescriptor ** kmemory)
{
	IOReturn             kr;
	uint64_t             options;
	IOMemoryDescriptor * memory;

	kr = CopyClientMemoryForType(type, &options, &memory);

	*koptions = 0;
	*kmemory  = NULL;
	if (kIOReturnSuccess != kr) {
		return kr;
	}

	if (kIOUserClientMemoryReadOnly & options) {
		*koptions |= kIOMapReadOnly;
	}
	*kmemory = memory;

	return kr;
}

IOReturn
IOUserUserClient::externalMethod(uint32_t selector, IOExternalMethodArguments * args,
    IOExternalMethodDispatch * dispatch, OSObject * target, void * reference)
{
	IOReturn   kr;
	OSData   * structureInput;
	OSData   * structureOutput;
	size_t     copylen;
	uint64_t   structureOutputSize;
	OSAction                  * action;
	IOUserUserClientActionRef * ref;
	mach_port_t wake_port = MACH_PORT_NULL;

	kr             = kIOReturnUnsupported;
	structureInput = NULL;
	action         = NULL;
	ref            = NULL;

	if (args->structureInputSize) {
		structureInput = OSData::withBytesNoCopy((void *) args->structureInput, args->structureInputSize);
	}

	if (MACH_PORT_NULL != args->asyncWakePort) {
		// this retain is for the OSAction to release
		wake_port = ipc_port_make_send_mqueue(args->asyncWakePort);
		kr = CreateActionKernelCompletion(sizeof(IOUserUserClientActionRef), &action);
		assert(KERN_SUCCESS == kr);
		ref = (typeof(ref))action->GetReference();
		bcopy(args->asyncReference, &ref->asyncRef[0], args->asyncReferenceCount * sizeof(ref->asyncRef[0]));
		kr = action->SetAbortedHandler(^(void) {
			IOUserUserClientActionRef * ref;
			IOReturn ret;

			ref = (typeof(ref))action->GetReference();
			ret = releaseAsyncReference64(ref->asyncRef);
			assert(kIOReturnSuccess == ret);
			bzero(&ref->asyncRef[0], sizeof(ref->asyncRef));
		});
		assert(KERN_SUCCESS == kr);
	}

	if (args->structureVariableOutputData) {
		structureOutputSize = kIOUserClientVariableStructureSize;
	} else if (args->structureOutputDescriptor) {
		structureOutputSize = args->structureOutputDescriptor->getLength();
	} else {
		structureOutputSize = args->structureOutputSize;
	}

	kr = _ExternalMethod(selector, &args->scalarInput[0], args->scalarInputCount,
	    structureInput, args->structureInputDescriptor,
	    args->scalarOutput, &args->scalarOutputCount,
	    structureOutputSize, &structureOutput, args->structureOutputDescriptor,
	    action);

	OSSafeReleaseNULL(structureInput);
	OSSafeReleaseNULL(action);

	if (kr == kIOReturnSuccess && structureOutput) {
		if (args->structureVariableOutputData) {
			*args->structureVariableOutputData = structureOutput;
		} else {
			copylen = structureOutput->getLength();
			if (copylen > args->structureOutputSize) {
				kr = kIOReturnBadArgument;
			} else {
				bcopy((const void *) structureOutput->getBytesNoCopy(), args->structureOutput, copylen);
				args->structureOutputSize = (uint32_t) copylen;
			}
			OSSafeReleaseNULL(structureOutput);
		}
	}

	if (kIOReturnSuccess != kr) {
		// mig will destroy any async port
		return kr;
	}

	// We must never return error after this point in order to preserve MIG ownership semantics
	assert(kr == kIOReturnSuccess);
	if (MACH_PORT_NULL != wake_port) {
		// this release is for the mig created send right
		iokit_release_port_send(wake_port);
	}

	return kr;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

extern IORecursiveLock               * gDriverKitLaunchLock;
extern OSSet                         * gDriverKitLaunches;

_IOUserServerCheckInCancellationHandler *
IOUserServerCheckInToken::setCancellationHandler(IOUserServerCheckInCancellationHandler handler,
    void* handlerArgs)
{
	_IOUserServerCheckInCancellationHandler * handlerObj = _IOUserServerCheckInCancellationHandler::withHandler(handler, handlerArgs);
	if (!handlerObj) {
		goto finish;
	}

	IORecursiveLockLock(gDriverKitLaunchLock);

	assert(fState != kIOUserServerCheckInComplete);

	if (fState == kIOUserServerCheckInCanceled) {
		// Send cancel notification if we set the handler after this was canceled
		handlerObj->call(this);
	} else if (fState == kIOUserServerCheckInPending) {
		fHandlers->setObject(handlerObj);
	}

	IORecursiveLockUnlock(gDriverKitLaunchLock);

finish:
	return handlerObj;
}

void
IOUserServerCheckInToken::removeCancellationHandler(_IOUserServerCheckInCancellationHandler * handler)
{
	IORecursiveLockLock(gDriverKitLaunchLock);

	fHandlers->removeObject(handler);

	IORecursiveLockUnlock(gDriverKitLaunchLock);
}

void
IOUserServerCheckInToken::cancel()
{
	IORecursiveLockLock(gDriverKitLaunchLock);

	if (fState == kIOUserServerCheckInPending) {
		fState = kIOUserServerCheckInCanceled;
		if (gDriverKitLaunches != NULL) {
			// Remove pending launch from list, if we have not shut down yet.
			gDriverKitLaunches->removeObject(this);
		}

		fHandlers->iterateObjects(^bool (OSObject * obj){
			_IOUserServerCheckInCancellationHandler * handlerObj = OSDynamicCast(_IOUserServerCheckInCancellationHandler, obj);
			if (handlerObj) {
			        handlerObj->call(this);
			}
			return false;
		});
		fHandlers->flushCollection();
	}

	IORecursiveLockUnlock(gDriverKitLaunchLock);
}

void
IOUserServerCheckInToken::complete()
{
	IORecursiveLockLock(gDriverKitLaunchLock);

	if (fState == kIOUserServerCheckInPending && --fPendingCount == 0) {
		fState = kIOUserServerCheckInComplete;
		if (gDriverKitLaunches != NULL) {
			// Remove pending launch from list, if we have not shut down yet.
			gDriverKitLaunches->removeObject(this);
		}

		// No need to hold on to the cancellation handlers
		fHandlers->flushCollection();
	}

	IORecursiveLockUnlock(gDriverKitLaunchLock);
}

bool
IOUserServerCheckInToken::init(const OSSymbol * serverName, OSNumber * serverTag, OSKext *driverKext, OSData *serverDUI)
{
	if (!OSObject::init()) {
		return false;
	}

	if (!serverName) {
		return false;
	}
	fServerName = serverName;
	fServerName->retain();

	if (!serverTag) {
		return false;
	}
	fServerTag = serverTag;
	fServerTag->retain();

	fHandlers = OSSet::withCapacity(0);
	if (!fHandlers) {
		return false;
	}

	fState = kIOUserServerCheckInPending;
	fPendingCount = 1;

	fKextBundleID = NULL;
	fNeedDextDec = false;

	fExecutableName = NULL;

	if (driverKext) {
		fExecutableName = OSDynamicCast(OSSymbol, driverKext->getBundleExecutable());

		if (fExecutableName) {
			fExecutableName->retain();
		}

		/*
		 * We need to keep track of how many dexts we have started.
		 * For every new dext we are going to create a new token, and
		 * we consider the token creation as the initial step to
		 * create a dext as it is the data structure that will back up
		 * the userspace dance to start a dext.
		 * We later have to decrement only once per token.
		 * If no error occurs we consider the finalize() call on IOUserServer
		 * as the moment in which we do not consider the dext "alive" anymore;
		 * however in case of errors we will still need to decrement the count
		 * otherwise upgrades of the dext will never make progress.
		 */
		if (OSKext::incrementDextLaunchCount(driverKext, serverDUI)) {
			/*
			 * If fKext holds a pointer,
			 * it is the indication that a decrements needs
			 * to be called.
			 */
			fNeedDextDec = true;
			fKextBundleID = OSDynamicCast(OSString, driverKext->getIdentifier());
			fKextBundleID->retain();
		} else {
			return false;
		}
	}

	return true;
}

/*
 * Returns if the dext can be re-used
 * for matching.
 */
bool
IOUserServerCheckInToken::dextTerminate(void)
{
	bool ret = true;

	if (fNeedDextDec == true) {
		/*
		 * We can decrement DextLaunchCount only
		 * once per token.
		 */
		ret = !(OSKext::decrementDextLaunchCount(fKextBundleID));
		fNeedDextDec = false;
	}

	return ret;
}

void
IOUserServerCheckInToken::free()
{
	OSSafeReleaseNULL(fServerName);
	OSSafeReleaseNULL(fServerTag);
	OSSafeReleaseNULL(fExecutableName);
	OSSafeReleaseNULL(fHandlers);
	if (fKextBundleID != NULL) {
		dextTerminate();
		OSSafeReleaseNULL(fKextBundleID);
	}

	OSObject::free();
}

const OSSymbol *
IOUserServerCheckInToken::copyServerName() const
{
	fServerName->retain();
	return fServerName;
}

OSNumber *
IOUserServerCheckInToken::copyServerTag() const
{
	fServerTag->retain();
	return fServerTag;
}

IOUserServer *
IOUserServer::launchUserServer(OSString * bundleID, const OSSymbol * serverName, OSNumber * serverTag, bool reuseIfExists, IOUserServerCheckInToken ** resultToken, OSData *serverDUI)
{
	IOUserServer *me = NULL;
	IOUserServerCheckInToken * token = NULL;
	OSDictionary * matching = NULL;  // must release
	OSKext * driverKext = NULL; // must release
	OSDextStatistics * driverStatistics = NULL; // must release
	bool reslide = false;

	/* TODO: Check we are looking for same dextID
	 * and if it is not the same
	 * restart the matching process.
	 */
	driverKext = OSKext::lookupDextWithIdentifier(bundleID, serverDUI);
	if (driverKext != NULL) {
		driverStatistics = driverKext->copyDextStatistics();
		if (driverStatistics == NULL) {
			panic("Kext %s was not a DriverKit OSKext", bundleID->getCStringNoCopy());
		}
		IOLog("Driver %s has crashed %zu time(s)\n", bundleID->getCStringNoCopy(), driverStatistics->getCrashCount());
		reslide = driverStatistics->getCrashCount() > 0;
	} else {
		DKLOG("Could not find OSKext for %s\n", bundleID->getCStringNoCopy());
		*resultToken = NULL;
		return NULL;
	}

	IORecursiveLockLock(gDriverKitLaunchLock);

	if (gDriverKitLaunches == NULL) {
		// About to shut down, don't launch anything
		goto finish;
	}

	if (reuseIfExists) {
		const char * serverNameCStr;
		const char * bundleIDCStr;
		const char * endOrgCStr;

		serverNameCStr = serverName->getCStringNoCopy();
		bundleIDCStr = bundleID->getCStringNoCopy();
		(endOrgCStr = strchr(bundleIDCStr, '.')) && (endOrgCStr = strchr(endOrgCStr + 1, '.'));
		reuseIfExists = endOrgCStr && (0 == strncmp(bundleIDCStr, serverNameCStr, endOrgCStr + 1 - bundleIDCStr));
		if (!reuseIfExists) {
			IOLog(kIOUserServerNameKey " \"%s\" not correct organization for bundleID \"%s\"\n", serverNameCStr, bundleIDCStr);
		}
	}

	// Find existing server
	if (reuseIfExists) {
		token = IOUserServerCheckInToken::findExistingToken(serverName);
		if (token) {
			// Launch in progress, return token
			goto finish;
		} else {
			// Check if launch completed
			matching = IOService::serviceMatching(gIOUserServerClassKey);
			if (!matching) {
				goto finish;
			}
			IOService::propertyMatching(gIOUserServerNameKey, serverName, matching);
			IOService * service = IOService::copyMatchingService(matching);
			IOUserServer * userServer = OSDynamicCast(IOUserServer, service);
			if (userServer) {
				// found existing user server
				me = userServer;
				goto finish;
			} else {
				OSSafeReleaseNULL(service);
			}
		}
	}

	// No existing server, request launch
	token = new IOUserServerCheckInToken;
	if (!token) {
		goto finish;
	}

	/*
	 * TODO: If the init fails because the personalities are not up to date
	 * restart the whole matching process.
	 */
	if (token && !token->init(serverName, serverTag, driverKext, serverDUI)) {
		IOLog("Could not initialize token\n");
		OSSafeReleaseNULL(token);
		goto finish;
	}

	/*
	 * If the launch fails at any point terminate() will
	 * be called on this IOUserServer.
	 */
	gDriverKitLaunches->setObject(token);
	OSKext::requestDaemonLaunch(bundleID, (OSString *)serverName, serverTag, reslide ? kOSBooleanTrue : kOSBooleanFalse, token, serverDUI);

finish:
	IORecursiveLockUnlock(gDriverKitLaunchLock);
	OSSafeReleaseNULL(matching);
	OSSafeReleaseNULL(driverStatistics);
	OSSafeReleaseNULL(driverKext);

	if (resultToken) {
		*resultToken = token;
	} else {
		OSSafeReleaseNULL(token);
	}

	return me;
}

/*
 * IOUserServerCheckInTokens are used to track dext launches. They have three possible states:
 *
 * - Pending: A dext launch is pending
 * - Canceled: Dext launch failed
 * - Complete: Dext launch is complete
 *
 * A token can be shared among multiple IOServices that are waiting for dexts if the IOUserServerName
 * is the same. This allows dexts to be reused and host multiple services. All pending tokens are stored
 * in gDriverKitLaunches and we check here before creating a new token when launching a dext.
 *
 * A token starts in the pending state with a pending count of 1. When we reuse a token, we increase the
 * pending count of the token.
 *
 * The token is sent to userspace as a mach port through kernelmanagerd/driverkitd to the dext. The dext then
 * uses that token to check in to the kernel. If any part of the dext launch failed (dext crashed, kmd crashed, etc.)
 * we get a no-senders notification for the token in the kernel and the token goes into the Canceled state.
 *
 * Once the dext checks in to the kernel, we decrement the pending count for the token. When the pending count reaches
 * 0, the token goes into the Complete state. So if the token is in the Complete state, there are no kernel matching threads
 * waiting on the dext to check in.
 */

IOUserServerCheckInToken *
IOUserServerCheckInToken::findExistingToken(const OSSymbol * serverName)
{
	IOUserServerCheckInToken * __block result = NULL;

	IORecursiveLockLock(gDriverKitLaunchLock);
	if (gDriverKitLaunches == NULL) {
		goto finish;
	}

	gDriverKitLaunches->iterateObjects(^(OSObject * obj) {
		IOUserServerCheckInToken * token = OSDynamicCast(IOUserServerCheckInToken, obj);
		if (token) {
		        // Check if server name matches
		        const OSSymbol * tokenServerName = token->fServerName;
		        if (tokenServerName->isEqualTo(serverName)) {
		                assert(token->fState == kIOUserServerCheckInPending);
		                token->fPendingCount++;
		                result = token;
		                result->retain();
			}
		}
		return result != NULL;
	});

finish:
	IORecursiveLockUnlock(gDriverKitLaunchLock);
	return result;
}

void
IOUserServerCheckInToken::cancelAll()
{
	OSSet * tokensToCancel;

	IORecursiveLockLock(gDriverKitLaunchLock);
	tokensToCancel = gDriverKitLaunches;
	gDriverKitLaunches = NULL;


	tokensToCancel->iterateObjects(^(OSObject *obj) {
		IOUserServerCheckInToken * token = OSDynamicCast(IOUserServerCheckInToken, obj);
		if (token) {
		        token->cancel();
		}
		return false;
	});

	IORecursiveLockUnlock(gDriverKitLaunchLock);

	OSSafeReleaseNULL(tokensToCancel);
}

void
_IOUserServerCheckInCancellationHandler::call(IOUserServerCheckInToken * token)
{
	fHandler(token, fHandlerArgs);
}

_IOUserServerCheckInCancellationHandler *
_IOUserServerCheckInCancellationHandler::withHandler(IOUserServerCheckInCancellationHandler handler, void * args)
{
	_IOUserServerCheckInCancellationHandler * handlerObj = NULL;
	if (!handler) {
		goto finish;
	}

	handlerObj = new _IOUserServerCheckInCancellationHandler;
	if (!handlerObj) {
		goto finish;
	}

	handlerObj->fHandler = handler;
	handlerObj->fHandlerArgs = args;

finish:
	return handlerObj;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

struct IOServiceStateNotificationDispatchSource_IVars {
	IOLock                       * fLock;
	IOService                    * fStateNotification;
	IOStateNotificationListenerRef fListener;
	OSAction                     * fAction;
	bool                           fEnable;
	bool                           fArmed;
};

kern_return_t
IOServiceStateNotificationDispatchSource::Create_Impl(IOService * service, OSArray * items,
    IODispatchQueue * queue, IOServiceStateNotificationDispatchSource ** outSource)
{
	kern_return_t kr;
	IOServiceStateNotificationDispatchSource * source;

	source = OSTypeAlloc(IOServiceStateNotificationDispatchSource);
	source->init();

	source->ivars->fStateNotification = service;
	kr = service->stateNotificationListenerAdd(items, &source->ivars->fListener, ^kern_return_t () {
		OSAction * action;

		action = NULL;
		IOLockLock(source->ivars->fLock);
		if (source->ivars->fArmed && source->ivars->fAction) {
		        source->ivars->fArmed = false;
		        action = source->ivars->fAction;
		        action->retain();
		}
		IOLockUnlock(source->ivars->fLock);
		if (action) {
		        source->StateNotificationReady(action);
		        OSSafeReleaseNULL(action);
		}
		return kIOReturnSuccess;
	});

	if (kIOReturnSuccess != kr) {
		OSSafeReleaseNULL(source);
	}
	*outSource = source;

	return kr;
}


bool
IOServiceStateNotificationDispatchSource::init()
{
	if (!IODispatchSource::init()) {
		return false;
	}
	ivars = IOMallocType(IOServiceStateNotificationDispatchSource_IVars);
	if (!ivars) {
		return false;
	}
	ivars->fLock = IOLockAlloc();
	if (!ivars->fLock) {
		return false;
	}
	ivars->fArmed = true;

	return true;
}

void
IOServiceStateNotificationDispatchSource::free()
{
	if (ivars) {
		if (ivars->fListener) {
			ivars->fStateNotification->stateNotificationListenerRemove(ivars->fListener);
		}
		if (ivars->fLock) {
			IOLockFree(ivars->fLock);
		}
		IOFreeType(ivars, IOServiceStateNotificationDispatchSource_IVars);
	}
	IODispatchSource::free();
}

kern_return_t
IOServiceStateNotificationDispatchSource::SetHandler_Impl(OSAction * action)
{
	IOReturn ret;
	bool     notifyReady;

	notifyReady = false;

	IOLockLock(ivars->fLock);
	action->retain();
	OSSafeReleaseNULL(ivars->fAction);
	ivars->fAction = action;
	if (action) {
		notifyReady = true;
	}
	IOLockUnlock(ivars->fLock);

	if (notifyReady) {
		StateNotificationReady(action);
	}
	ret = kIOReturnSuccess;

	return ret;
}

kern_return_t
IOServiceStateNotificationDispatchSource::SetEnableWithCompletion_Impl(
	bool enable,
	IODispatchSourceCancelHandler handler)
{
	if (enable == ivars->fEnable) {
		return kIOReturnSuccess;
	}

	IOLockLock(ivars->fLock);
	ivars->fEnable = enable;
	IOLockUnlock(ivars->fLock);

	return kIOReturnSuccess;
}

kern_return_t
IOServiceStateNotificationDispatchSource::Cancel_Impl(
	IODispatchSourceCancelHandler handler)
{
	return kIOReturnUnsupported;
}

kern_return_t
IOServiceStateNotificationDispatchSource::StateNotificationBegin_Impl(void)
{
	IOLockLock(ivars->fLock);
	ivars->fArmed = true;
	IOLockUnlock(ivars->fLock);

	return kIOReturnSuccess;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#include <IOKit/IOServiceStateNotificationEventSource.h>

OSDefineMetaClassAndStructors(IOServiceStateNotificationEventSource, IOEventSource)
OSMetaClassDefineReservedUnused(IOServiceStateNotificationEventSource, 0);
OSMetaClassDefineReservedUnused(IOServiceStateNotificationEventSource, 1);
OSMetaClassDefineReservedUnused(IOServiceStateNotificationEventSource, 2);
OSMetaClassDefineReservedUnused(IOServiceStateNotificationEventSource, 3);
OSMetaClassDefineReservedUnused(IOServiceStateNotificationEventSource, 4);
OSMetaClassDefineReservedUnused(IOServiceStateNotificationEventSource, 5);
OSMetaClassDefineReservedUnused(IOServiceStateNotificationEventSource, 6);
OSMetaClassDefineReservedUnused(IOServiceStateNotificationEventSource, 7);

OSPtr<IOServiceStateNotificationEventSource>
IOServiceStateNotificationEventSource::serviceStateNotificationEventSource(IOService *service,
    OSArray * items,
    ActionBlock inAction)
{
	kern_return_t kr;
	IOServiceStateNotificationEventSource * source;

	source = OSTypeAlloc(IOServiceStateNotificationEventSource);
	if (source && !source->init(service, NULL)) {
		OSSafeReleaseNULL(source);
	}

	if (!source) {
		return nullptr;
	}

	source->fStateNotification = service;
	kr = service->stateNotificationListenerAdd(items, &source->fListener, ^kern_return_t () {
		if (!source->workLoop) {
		        return kIOReturnSuccess;
		}
		source->workLoop->runActionBlock(^IOReturn (void) {
			source->fArmed = true;
			return kIOReturnSuccess;
		});
		source->signalWorkAvailable();
		return kIOReturnSuccess;
	});

	if (kIOReturnSuccess != kr) {
		OSSafeReleaseNULL(source);
	}

	if (source) {
		source->setActionBlock((IOEventSource::ActionBlock) inAction);
	}

	return source;
}

void
IOServiceStateNotificationEventSource::free()
{
	if (fListener) {
		fStateNotification->stateNotificationListenerRemove(fListener);
	}
	IOEventSource::free();
}

void
IOServiceStateNotificationEventSource::enable()
{
	fEnable = true;
}

void
IOServiceStateNotificationEventSource::disable()
{
	fEnable = false;
}

void
IOServiceStateNotificationEventSource::setWorkLoop(IOWorkLoop *inWorkLoop)
{
	IOEventSource::setWorkLoop(inWorkLoop);
}

bool
IOServiceStateNotificationEventSource::checkForWork()
{
	ActionBlock intActionBlock = (ActionBlock) actionBlock;

	if (fArmed) {
		fArmed = false;
		(intActionBlock)();
	}

	return false;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

OSDefineMetaClassAndStructors(IOSystemStateNotification, IOService);

class IOStateNotificationItem : public OSObject
{
	OSDeclareDefaultStructors(IOStateNotificationItem);

public:
	virtual bool init() override;

	OSDictionary * fSchema;
	OSDictionary * fValue;
	OSSet        * fListeners;
};
OSDefineMetaClassAndStructors(IOStateNotificationItem, OSObject);


class IOStateNotificationListener : public OSObject
{
	OSDeclareDefaultStructors(IOStateNotificationListener);

public:
	virtual bool init() override;
	virtual void free() override;

	IOStateNotificationHandler fHandler;
};
OSDefineMetaClassAndStructors(IOStateNotificationListener, OSObject);


bool
IOStateNotificationItem::init()
{
	return OSObject::init();
}

bool
IOStateNotificationListener::init()
{
	return OSObject::init();
}

void
IOStateNotificationListener::free()
{
	if (fHandler) {
		Block_release(fHandler);
	}
	OSObject::free();
}


struct IOServiceStateChangeVars {
	IOLock       * fLock;
	OSDictionary * fItems;
};

IOService *
IOSystemStateNotification::initialize(void)
{
	IOSystemStateNotification * me;
	IOServiceStateChangeVars  * vars;

	me = OSTypeAlloc(IOSystemStateNotification);
	me->init();
	vars = IOMallocType(IOServiceStateChangeVars);
	me->reserved->svars = vars;
	vars->fLock  = IOLockAlloc();
	vars->fItems = OSDictionary::withCapacity(16);
	{
		kern_return_t ret;

		gIOSystemStateSleepDescriptionKey = (OSString *)OSSymbol::withCStringNoCopy(kIOSystemStateSleepDescriptionKey);
		gIOSystemStateSleepDescriptionHibernateStateKey = OSSymbol::withCStringNoCopy(kIOSystemStateSleepDescriptionHibernateStateKey);
		gIOSystemStateSleepDescriptionReasonKey = OSSymbol::withCStringNoCopy(kIOSystemStateSleepDescriptionReasonKey);

		ret = me->StateNotificationItemCreate(gIOSystemStateSleepDescriptionKey, NULL);
		assert(kIOReturnSuccess == ret);

		gIOSystemStateWakeDescriptionKey = (OSString *)OSSymbol::withCStringNoCopy(kIOSystemStateWakeDescriptionKey);
		gIOSystemStateWakeDescriptionWakeReasonKey = OSSymbol::withCStringNoCopy(kIOSystemStateWakeDescriptionWakeReasonKey);

		ret = me->StateNotificationItemCreate(gIOSystemStateWakeDescriptionKey, NULL);
		assert(kIOReturnSuccess == ret);

		gIOSystemStateHaltDescriptionKey = (OSString *)OSSymbol::withCStringNoCopy(kIOSystemStateHaltDescriptionKey);
		gIOSystemStateHaltDescriptionHaltStateKey = OSSymbol::withCStringNoCopy(kIOSystemStateHaltDescriptionHaltStateKey);

		ret = me->StateNotificationItemCreate(gIOSystemStateHaltDescriptionKey, NULL);
		assert(kIOReturnSuccess == ret);

		gIOSystemStatePowerSourceDescriptionKey = (OSString *)OSSymbol::withCStringNoCopy(kIOSystemStatePowerSourceDescriptionKey);
		gIOSystemStatePowerSourceDescriptionACAttachedKey = OSSymbol::withCStringNoCopy(kIOSystemStatePowerSourceDescriptionACAttachedKey);

		ret = me->StateNotificationItemCreate(gIOSystemStatePowerSourceDescriptionKey, NULL);
		assert(kIOReturnSuccess == ret);
	}

	return me;
}

bool
IOSystemStateNotification::serializeProperties(OSSerialize * s) const
{
	IOServiceStateChangeVars * ivars = reserved->svars;

	bool ok;
	OSDictionary * result;

	result = OSDictionary::withCapacity(16);

	IOLockLock(ivars->fLock);
	ivars->fItems->iterateObjects(^bool (const OSSymbol * key, OSObject * object) {
		IOStateNotificationItem * item;

		item = (typeof(item))object;
		if (!item->fValue) {
		        return false;
		}
		result->setObject(key, item->fValue);
		return false;
	});
	IOLockUnlock(ivars->fLock);

	ok = result->serialize(s);
	OSSafeReleaseNULL(result);

	return ok;
}

kern_return_t
IOSystemStateNotification::setProperties(OSObject * properties)
{
	kern_return_t  kr;
	OSDictionary * dict;
	OSDictionary * schema;
	OSDictionary * value;
	OSString     * itemName;

	dict = OSDynamicCast(OSDictionary, properties);
	if (!dict) {
		return kIOReturnBadArgument;
	}

	if (!IOCurrentTaskHasEntitlement(kIOSystemStateEntitlement)) {
		return kIOReturnNotPermitted;
	}

	if ((schema = OSDynamicCast(OSDictionary, dict->getObject(kIOStateNotificationItemCreateKey)))) {
		itemName = OSDynamicCast(OSString, schema->getObject(kIOStateNotificationNameKey));
		kr = StateNotificationItemCreate(itemName, schema);
	} else if ((value = OSDynamicCast(OSDictionary, dict->getObject(kIOStateNotificationItemSetKey)))) {
		itemName = OSDynamicCast(OSString, value->getObject(kIOStateNotificationNameKey));
		itemName->retain();
		value->removeObject(kIOStateNotificationNameKey);
		kr = StateNotificationItemSet(itemName, value);
		itemName->release();
	} else {
		kr = kIOReturnError;
	}

	return kr;
}

kern_return_t
IOService::CopySystemStateNotificationService_Impl(IOService ** outService)
{
	IOService * service;

	service = getSystemStateNotificationService();
	service->retain();
	*outService = service;

	return kIOReturnSuccess;
}

IOStateNotificationItem *
IOService::stateNotificationItemCopy(OSString * itemName, OSDictionary * schema)
{
	IOServiceStateChangeVars * ivars = reserved->svars;

	const OSSymbol          * name;
	IOStateNotificationItem * item;

	name = OSSymbol::withString(itemName);

	IOLockLock(ivars->fLock);
	if ((item = (typeof(item))ivars->fItems->getObject(name))) {
		item->retain();
	} else {
		item = OSTypeAlloc(IOStateNotificationItem);
		item->init();
		item->fListeners = OSSet::withCapacity(16);

		if (schema) {
			schema->retain();
		} else {
			schema = OSDictionary::withCapacity(8);
		}
		schema->setObject(kIOStateNotificationNameKey, name);
		item->fSchema = schema;
		ivars->fItems->setObject(name, item);
	}
	IOLockUnlock(ivars->fLock);

	OSSafeReleaseNULL(name);

	return item;
}

kern_return_t
IOService::StateNotificationItemCreate_Impl(OSString * itemName, OSDictionary * schema)
{
	IOStateNotificationItem * item;

	item = stateNotificationItemCopy(itemName, schema);
	if (!item) {
		return kIOReturnNoMemory;
	}
	item->release();

	return kIOReturnSuccess;
}

kern_return_t
IOService::StateNotificationItemSet_Impl(OSString * itemName, OSDictionary * value)
{
	IOServiceStateChangeVars * ivars = reserved->svars;

	OSSet                   * listeners;
	IOStateNotificationItem * item;

	value->retain();
	IOLockLock(ivars->fLock);
	item = (typeof(item))ivars->fItems->getObject(itemName);
	OSSafeReleaseNULL(item->fValue);
	item->fValue = value;
	listeners = NULL;
	if (item->fListeners->getCount()) {
		listeners = OSSet::withSet(item->fListeners);
	}
	IOLockUnlock(ivars->fLock);

	if (listeners) {
		listeners->iterateObjects(^bool (OSObject * object) {
			IOStateNotificationListener * listener;

			listener = (typeof(listener))object;
			listener->fHandler();
			return false;
		});
		OSSafeReleaseNULL(listeners);
	}

	return kIOReturnSuccess;
}

kern_return_t
IOService::StateNotificationItemCopy_Impl(OSString * itemName, OSDictionary ** outValue)
{
	IOServiceStateChangeVars * ivars = reserved->svars;

	kern_return_t              ret;
	IOStateNotificationItem  * item;
	OSDictionary             * value;

	IOLockLock(ivars->fLock);
	item = (typeof(item))ivars->fItems->getObject(itemName);
	if (item) {
		value = item->fValue;
	} else {
		value = NULL;
	}
	if (!value) {
		ret = kIOReturnNotFound;
	} else {
		value->retain();
		ret = kIOReturnSuccess;
	}
	IOLockUnlock(ivars->fLock);

	*outValue = value;

	return ret;
}

kern_return_t
IOService::stateNotificationListenerAdd(OSArray * items,
    IOStateNotificationListenerRef * outRef,
    IOStateNotificationHandler handler)
{
	IOServiceStateChangeVars * ivars = reserved->svars;

	kern_return_t                 kr __block;
	IOStateNotificationListener * listener;

	listener = OSTypeAlloc(IOStateNotificationListener);
	listener->init();
	listener->fHandler = Block_copy(handler);

	kr = kIOReturnSuccess;
	items->iterateObjects(^bool (OSObject * object) {
		OSString                * itemName;
		IOStateNotificationItem * item;

		itemName = OSDynamicCast(OSString, object);
		if (!itemName) {
		        kr = kIOReturnBadArgument;
		        return true;
		}
		item = stateNotificationItemCopy(itemName, NULL);
		if (!item) {
		        kr = kIOReturnNoMemory;
		        return true;
		}
		IOLockLock(ivars->fLock);
		item->fListeners->setObject(listener);
		IOLockUnlock(ivars->fLock);
		item->release();
		return false;
	});

	if (kIOReturnSuccess != kr) {
		stateNotificationListenerRemove(listener);
		OSSafeReleaseNULL(listener);
	}
	*outRef = listener;

	return kr;
}


kern_return_t
IOService::stateNotificationListenerRemove(IOStateNotificationListenerRef ref)
{
	IOServiceStateChangeVars * ivars = reserved->svars;

	IOStateNotificationListener * listener;
	kern_return_t                 kr;

	kr = kIOReturnSuccess;
	listener = (typeof(listener))ref;

	IOLockLock(ivars->fLock);
	ivars->fItems->iterateObjects(^bool (const OSSymbol * key, OSObject * object) {
		IOStateNotificationItem * item;

		item = (typeof(item))object;
		item->fListeners->removeObject(listener);
		return false;
	});
	IOLockUnlock(ivars->fLock);

	return kr;
}



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

kern_return_t
IOWorkGroup::Create_Impl(OSString * name, IOUserClient * userClient, IOWorkGroup ** workgroup)
{
	IOWorkGroup * inst = NULL;
	IOUserUserClient * uc = NULL;
	kern_return_t ret = kIOReturnError;
	IOUserServer * us;

	if (name == NULL) {
		ret = kIOReturnBadArgument;
		goto finish;
	}

	if (name->getLength() > kIOWorkGroupMaxNameLength) {
		ret = kIOReturnBadArgument;
		goto finish;
	}

	uc = OSDynamicCast(IOUserUserClient, userClient);
	if (uc == NULL) {
		ret = kIOReturnBadArgument;
		goto finish;
	}

	inst = OSTypeAlloc(IOWorkGroup);
	if (!inst->init()) {
		inst->free();
		inst = NULL;
		ret = kIOReturnNoMemory;
		goto finish;
	}

	us = (typeof(us))thread_iokit_tls_get(0);
	inst->ivars->userServer = OSDynamicCast(IOUserServer, us);

	if (inst->ivars->userServer == NULL) {
		ret = kIOReturnBadArgument;
		goto finish;
	}
	inst->ivars->userServer->retain();

	inst->ivars->name = name;
	inst->ivars->name->retain();

	inst->ivars->userClient = uc; // no retain

	IOLockLock(uc->fLock);
	uc->fWorkGroups->setObject(name, inst);
	IOLockUnlock(uc->fLock);
	ret = kIOReturnSuccess;

finish:
	if (ret != kIOReturnSuccess) {
		OSSafeReleaseNULL(inst);
	} else {
		*workgroup = inst;
	}

	return ret;
}

kern_return_t
IOWorkGroup::InvalidateKernel_Impl(IOUserClient * client)
{
	IOUserUserClient * uc = OSDynamicCast(IOUserUserClient, client);

	if (uc == NULL) {
		return kIOReturnBadArgument;
	}

	if (uc != ivars->userClient) {
		return kIOReturnBadArgument;
	}

	IOLockLock(uc->fLock);
	uc->fWorkGroups->removeObject(ivars->name);
	IOLockUnlock(uc->fLock);

	return kIOReturnSuccess;
}

kern_return_t
IOWorkGroup::SetWorkGroupPort_Impl(mach_port_t port)
{
	return kIOReturnUnsupported;
}

bool
IOWorkGroup::init()
{
	if (!OSObject::init()) {
		return false;
	}
	ivars = IOMallocType(IOWorkGroup_IVars);

	return true;
}

void
IOWorkGroup::free()
{
	if (ivars) {
		OSSafeReleaseNULL(ivars->userServer);
		OSSafeReleaseNULL(ivars->name);
		IOFreeType(ivars, IOWorkGroup_IVars);
	}

	OSObject::free();
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

kern_return_t
IOEventLink::Create_Impl(OSString * name, IOUserClient * userClient, IOEventLink ** eventlink)
{
	IOEventLink * inst = NULL;
	IOUserUserClient * uc = NULL;
	IOUserServer * us;
	kern_return_t ret = kIOReturnError;

	if (name == NULL) {
		ret = kIOReturnBadArgument;
		goto finish;
	}

	if (name->getLength() > kIOEventLinkMaxNameLength) {
		ret = kIOReturnBadArgument;
		goto finish;
	}

	uc = OSDynamicCast(IOUserUserClient, userClient);
	if (uc == NULL) {
		ret = kIOReturnBadArgument;
		goto finish;
	}

	inst = OSTypeAlloc(IOEventLink);
	if (!inst->init()) {
		inst->free();
		inst = NULL;
		ret = kIOReturnNoMemory;
		goto finish;
	}

	us = (typeof(us))thread_iokit_tls_get(0);
	inst->ivars->userServer = OSDynamicCast(IOUserServer, us);

	if (inst->ivars->userServer == NULL) {
		ret = kIOReturnBadArgument;
		goto finish;
	}
	inst->ivars->userServer->retain();

	inst->ivars->name = name;
	inst->ivars->name->retain();

	inst->ivars->userClient = uc; // no retain

	IOLockLock(uc->fLock);
	uc->fEventLinks->setObject(name, inst);
	IOLockUnlock(uc->fLock);

	ret = kIOReturnSuccess;

finish:
	if (ret != kIOReturnSuccess) {
		OSSafeReleaseNULL(inst);
	} else {
		*eventlink = inst;
	}

	return ret;
}

kern_return_t
IOEventLink::InvalidateKernel_Impl(IOUserClient * client)
{
	IOUserUserClient * uc = OSDynamicCast(IOUserUserClient, client);

	if (uc == NULL) {
		return kIOReturnBadArgument;
	}

	if (uc != ivars->userClient) {
		return kIOReturnBadArgument;
	}

	IOLockLock(uc->fLock);
	uc->fEventLinks->removeObject(ivars->name);
	IOLockUnlock(uc->fLock);

	return kIOReturnSuccess;
}

bool
IOEventLink::init()
{
	if (!OSObject::init()) {
		return false;
	}
	ivars = IOMallocType(IOEventLink_IVars);

	return true;
}

void
IOEventLink::free()
{
	if (ivars) {
		OSSafeReleaseNULL(ivars->userServer);
		OSSafeReleaseNULL(ivars->name);
		IOFreeType(ivars, IOEventLink_IVars);
	}

	OSObject::free();
}

kern_return_t
IOEventLink::SetEventlinkPort_Impl(mach_port_t port __unused)
{
	return kIOReturnUnsupported;
}
