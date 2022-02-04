#include "TestIOConnectMapMemoryPortLeak45265408.h"
#include <IOKit/IOKitKeys.h>

#if DEVELOPMENT || DEBUG

#define super IOService
OSDefineMetaClassAndStructors(TestIOConnectMapMemoryPortLeak45265408, IOService);

bool
TestIOConnectMapMemoryPortLeak45265408::start(IOService *provider)
{
	bool ret = super::start(provider);
	if (ret) {
		OSString * className = OSString::withCStringNoCopy("TestIOConnectMapMemoryPortLeak45265408UserClient");
		setProperty(gIOUserClientClassKey, className);
		OSSafeReleaseNULL(className);
		registerService();
	}
	return ret;
}

#undef super
#define super IOUserClient
OSDefineMetaClassAndStructors(TestIOConnectMapMemoryPortLeak45265408UserClient, IOUserClient);

bool
TestIOConnectMapMemoryPortLeak45265408UserClient::start(IOService *provider)
{
	bool ret = super::start(provider);
	if (ret) {
		setProperty(kIOUserClientSharedInstanceKey, kOSBooleanTrue);
		this->sharedMemory = IOBufferMemoryDescriptor::withOptions(kIOMemoryKernelUserShared, PAGE_SIZE);
		if (this->sharedMemory == NULL) {
			ret = false;
		}
	}

	return ret;
}

void
TestIOConnectMapMemoryPortLeak45265408UserClient::stop(IOService *provider)
{
	if (this->sharedMemory) {
		this->sharedMemory->release();
		this->sharedMemory = NULL;
	}
	super::stop(provider);
}

IOReturn
TestIOConnectMapMemoryPortLeak45265408UserClient::clientClose()
{
	if (!isInactive()) {
		terminate();
	}
	return kIOReturnSuccess;
}

IOReturn
TestIOConnectMapMemoryPortLeak45265408UserClient::clientMemoryForType(UInt32 type, IOOptionBits *flags, IOMemoryDescriptor **memory)
{
	*memory = this->sharedMemory;
	this->sharedMemory->retain();
	return kIOReturnSuccess;
}

#endif /* DEVELOPMENT || DEBUG */
