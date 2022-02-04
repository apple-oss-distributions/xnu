#include "TestIODeviceMemoryRosetta.h"
#include <IOKit/IOService.h>
#include <IOKit/IOUserClient.h>
#include <IOKit/IOKitServer.h>
#include <kern/ipc_kobject.h>

#if (DEVELOPMENT || DEBUG) && XNU_TARGET_OS_OSX

OSDefineMetaClassAndStructors(TestIODeviceMemoryRosetta, IOService);

OSDefineMetaClassAndStructors(TestIODeviceMemoryRosettaUserClient, IOUserClient);

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


IOReturn
TestIODeviceMemoryRosettaUserClient::clientClose()
{
	if (!isInactive()) {
		terminate();
	}
	return kIOReturnSuccess;
}

IOReturn
TestIODeviceMemoryRosettaUserClient::externalMethod(uint32_t selector, IOExternalMethodArguments * args,
    IOExternalMethodDispatch * dispatch, OSObject * target, void * reference)
{
	IOReturn ret = kIOReturnError;
	IOMemoryMap * map = NULL;
	IODeviceMemory * deviceMemory = NULL;
	uint64_t * buf;

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

	if (args->structureInputSize != sizeof(TestIODeviceMemoryRosettaUserClientArgs)) {
		return kIOReturnBadArgument;
	}

	if (args->structureOutputSize != sizeof(TestIODeviceMemoryRosettaUserClientOutput)) {
		return kIOReturnBadArgument;
	}

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

#endif /* (DEVELOPMENT || DEBUG) && XNU_TARGET_OS_OSX */
