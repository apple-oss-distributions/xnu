#include "TestIOServiceUserNotification.h"
#include <IOKit/IOService.h>
#include <IOKit/IOUserClient.h>
#include <IOKit/IOKitServer.h>
#include <kern/ipc_kobject.h>

#if DEVELOPMENT || DEBUG

OSDefineMetaClassAndStructors(TestIOServiceUserNotification, IOService);

OSDefineMetaClassAndStructors(TestIOServiceUserNotificationUserClient, IOUserClient);

bool
TestIOServiceUserNotification::start(IOService * provider)
{
	OSString * str = OSString::withCStringNoCopy("TestIOServiceUserNotificationUserClient");
	bool ret = IOService::start(provider);
	if (ret && str != NULL) {
		setProperty(gIOUserClientClassKey, str);
		registerService();
	}
	OSSafeReleaseNULL(str);
	return ret;
}


IOReturn
TestIOServiceUserNotificationUserClient::clientClose()
{
	if (!isInactive()) {
		terminate();
	}
	return kIOReturnSuccess;
}

IOReturn
TestIOServiceUserNotificationUserClient::externalMethod(uint32_t selector, IOExternalMethodArguments * args,
    IOExternalMethodDispatch * dispatch, OSObject * target, void * reference)
{
	registerService();
	return kIOReturnSuccess;
}

#endif /* DEVELOPMENT || DEBUG */
