#include "TestIOUserClient2022Entitlements.h"
#include <IOKit/IOService.h>
#include <IOKit/IOUserClient.h>
#include <IOKit/IOKitServer.h>
#include <kern/ipc_kobject.h>

#if (DEVELOPMENT || DEBUG)

OSDefineMetaClassAndStructors(TestIOUserClient2022Entitlements, IOService);

OSDefineMetaClassAndStructors(TestIOUserClient2022EntitlementsUserClient, IOUserClient2022);

bool
TestIOUserClient2022Entitlements::start(IOService * provider)
{
	OSString * str = OSString::withCStringNoCopy("TestIOUserClient2022EntitlementsUserClient");
	bool ret = IOService::start(provider);
	if (ret && str != NULL) {
		setProperty(gIOUserClientClassKey, str);
		registerService();
	}
	OSSafeReleaseNULL(str);
	return ret;
}

bool
TestIOUserClient2022EntitlementsUserClient::start(IOService * provider)
{
	if (!IOUserClient2022::start(provider)) {
		return false;
	}
	setProperty(kIOUserClientDefaultLockingKey, kOSBooleanTrue);
	setProperty(kIOUserClientDefaultLockingSetPropertiesKey, kOSBooleanTrue);
	setProperty(kIOUserClientDefaultLockingSingleThreadExternalMethodKey, kOSBooleanTrue);

	setProperty(kIOUserClientEntitlementsKey, "com.apple.iokit.test-check-entitlement-open");

	return true;
}

IOReturn
TestIOUserClient2022EntitlementsUserClient::clientClose()
{
	terminate();
	return kIOReturnSuccess;
}

IOReturn
TestIOUserClient2022EntitlementsUserClient::extBasicMethod(OSObject * target, void * reference, IOExternalMethodArguments * arguments)
{
	return kIOReturnSuccess;
}

IOReturn
TestIOUserClient2022EntitlementsUserClient::extPerSelectorCheck(OSObject * target, void * reference, IOExternalMethodArguments * arguments)
{
	return kIOReturnSuccess;
}

IOReturn
TestIOUserClient2022EntitlementsUserClient::externalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque * args)
{
	static const IOExternalMethodDispatch2022 dispatchArray[] = {
		[0] {
			.function                 = &TestIOUserClient2022EntitlementsUserClient::extBasicMethod,
			.checkScalarInputCount    = 0,
			.checkStructureInputSize  = 0,
			.checkScalarOutputCount   = 0,
			.checkStructureOutputSize = 0,
			.allowAsync               = false,
			.checkEntitlement         = NULL,
		},
		[1] {
			.function                 = &TestIOUserClient2022EntitlementsUserClient::extPerSelectorCheck,
			.checkScalarInputCount    = 0,
			.checkStructureInputSize  = 0,
			.checkScalarOutputCount   = 0,
			.checkStructureOutputSize = 0,
			.allowAsync               = false,
			.checkEntitlement         = "com.apple.iokit.test-check-entitlement-per-selector",
		},
	};

	return dispatchExternalMethod(selector, args, dispatchArray, sizeof(dispatchArray) / sizeof(dispatchArray[0]), this, NULL);
}

#endif /* (DEVELOPMENT || DEBUG) */
