#include "TestIODeviceMemoryRosetta.h"
#include <IOKit/IOService.h>
#include <IOKit/IOUserClient.h>
#include <IOKit/IOKitServer.h>
#include <kern/ipc_kobject.h>

#if (DEVELOPMENT || DEBUG) && XNU_TARGET_OS_OSX

OSDefineMetaClassAndStructors(TestIODeviceMemoryRosetta, IOService);

OSDefineMetaClassAndStructors(TestIODeviceMemoryRosettaUserClient, IOUserClient2022);

bool
TestIODeviceMemoryRosetta::start(IOService * provider)
{
	OSString * str = OSString::withCStringNoCopy("TestIODeviceMemoryRosettaUserClient");
	bool ret = IOService::start(provider);
	if (ret && str != NULL) {
		setProperty(gIOUserClientClassKey, str);
		registerService();
	}
	OSSafeReleaseNULL(str);
	return ret;
}

bool
TestIODeviceMemoryRosettaUserClient::start(IOService * provider)
{
	if (!IOUserClient2022::start(provider)) {
		return false;
	}
	setProperty(kIOUserClientDefaultLockingKey, kOSBooleanTrue);
	setProperty(kIOUserClientDefaultLockingSetPropertiesKey, kOSBooleanTrue);
	setProperty(kIOUserClientDefaultLockingSingleThreadExternalMethodKey, kOSBooleanTrue);

	setProperty(kIOUserClientEntitlementsKey, kOSBooleanFalse);

	return true;
}

IOReturn
TestIODeviceMemoryRosettaUserClient::clientClose()
{
	if (!isInactive()) {
		terminate();
	}
	return kIOReturnSuccess;
}

struct TestIODeviceMemoryRosettaUserClientArgs {
	uint64_t size;
	uint64_t offset;
	uint64_t deviceMemoryOffset;
	uint64_t length;
	uint64_t xorkey;
};

struct TestIODeviceMemoryRosettaUserClientOutput {
	mach_vm_address_t address;
	mach_vm_size_t size;
};

IOReturn
TestIODeviceMemoryRosettaUserClient::externalMethodDispatched(IOExternalMethodArguments * args)
{
	IOReturn ret = kIOReturnError;
	IOMemoryMap * map = NULL;
	IODeviceMemory * deviceMemory = NULL;
	uint64_t * buf;

	TestIODeviceMemoryRosettaUserClientArgs * userClientArgs = (TestIODeviceMemoryRosettaUserClientArgs *)args->structureInput;
	TestIODeviceMemoryRosettaUserClientOutput * userClientOutput = (TestIODeviceMemoryRosettaUserClientOutput *)args->structureOutput;

	if (userClientArgs->size % sizeof(uint64_t) != 0) {
		return kIOReturnBadArgument;
	}

	if (userClientArgs->size + userClientArgs->deviceMemoryOffset > phys_carveout_size) {
		return kIOReturnBadArgument;
	}

	// Create memory descriptor using the physical carveout
	deviceMemory = IODeviceMemory::withRange(phys_carveout_pa + userClientArgs->deviceMemoryOffset, userClientArgs->size);
	if (!deviceMemory) {
		printf("Failed to allocate device memory\n");
		goto finish;
	}

	// Fill carveout memory with known values, xored with the key
	buf = (uint64_t *)phys_carveout;
	for (uint64_t idx = 0; idx < (userClientArgs->deviceMemoryOffset + userClientArgs->size) / sizeof(uint64_t); idx++) {
		buf[idx] = idx ^ userClientArgs->xorkey;
	}

	// Map the memory descriptor
	map = deviceMemory->createMappingInTask(current_task(), 0, kIOMapAnywhere, userClientArgs->offset, userClientArgs->length);

	if (map) {
		// Release map when task exits
		userClientOutput->address = map->getAddress();
		userClientOutput->size = map->getSize();
		mach_port_name_t name __unused = iokit_make_send_right(current_task(), map, IKOT_IOKIT_OBJECT);
		ret = kIOReturnSuccess;
	}

finish:
	OSSafeReleaseNULL(map);
	OSSafeReleaseNULL(deviceMemory);
	return ret;
}

static IOReturn
TestIODeviceMemoryRosettaMethodDispatched(OSObject * target, void * reference, IOExternalMethodArguments * arguments)
{
	TestIODeviceMemoryRosettaUserClient *
	    me = OSRequiredCast(TestIODeviceMemoryRosettaUserClient, target);
	return me->externalMethodDispatched(arguments);
}

IOReturn
TestIODeviceMemoryRosettaUserClient::externalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque * args)
{
	static const IOExternalMethodDispatch2022 dispatchArray[] = {
		[0] {
			.function                 = &TestIODeviceMemoryRosettaMethodDispatched,
			.checkScalarInputCount    = 0,
			.checkStructureInputSize  = sizeof(TestIODeviceMemoryRosettaUserClientArgs),
			.checkScalarOutputCount   = 0,
			.checkStructureOutputSize = sizeof(TestIODeviceMemoryRosettaUserClientOutput),
			.allowAsync               = false,
			.checkEntitlement         = "com.apple.iokit.test-check-entitlement",
		},
	};

	return dispatchExternalMethod(selector, args, dispatchArray, sizeof(dispatchArray) / sizeof(dispatchArray[0]), this, NULL);
}

#endif /* (DEVELOPMENT || DEBUG) && XNU_TARGET_OS_OSX */
