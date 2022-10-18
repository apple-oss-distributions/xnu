#include <darwintest.h>
#include <mach/mach.h>
#include <mach/message.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <signal.h>
#include <mach/mach_vm.h>

#include <IOKit/IOKitLib.h>
#include "service_helpers.h"

// 10 MB physical carveout

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.iokit"),
	T_META_RUN_CONCURRENTLY(true),
	T_META_ALL_VALID_ARCHS(true),
	T_META_ASROOT(true),
	T_META_BOOTARGS_SET("phys_carveout_mb=10"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("IOKit"),
	T_META_OWNER("souvik_b"));

#define PHYSICAL_CARVEOUT_SIZE 10UL * 1024 * 1024

struct TestIODeviceMemoryRosettaUserClientArgs {
	// Size of the memory descriptor in the kernel. Must be less than the physical carveout size - deviceMemoryOffset
	uint64_t size;
	// Offset into the memory descriptor, used for mapping
	uint64_t offset;
	// Offset past physical carveout to create memory descriptor
	uint64_t deviceMemoryOffset;
	// Length of the memory descriptor to map starting from the offset
	uint64_t length;
	// Key used for xoring values in the physical memory carveout
	uint64_t xorkey;
};

struct TestIODeviceMemoryRosettaUserClientOutput {
	mach_vm_address_t address;
	mach_vm_size_t size;
};

T_DECL(rosetta_map_mmio, "Test mapping MMIO memory at 4K-page aligned offsets in Rosetta processes")
{
#if defined(__arm64__)
	T_SKIP("Test should run under Rosetta.");
#else
	io_service_t service;
	io_connect_t conn;
	const char *serviceName = "TestIODeviceMemoryRosetta";

	T_QUIET; T_ASSERT_POSIX_SUCCESS(IOTestServiceFindService(serviceName, &service), "Find service");
	T_QUIET; T_ASSERT_NE(service, MACH_PORT_NULL, "got service");
	T_QUIET; T_ASSERT_MACH_SUCCESS(IOServiceOpen(service, mach_task_self(), 0, &conn), "open service");
	T_LOG("PAGE_SIZE is 0x%lx", PAGE_SIZE);

	// start of memory descriptor, offset from start of physical carveout
	for (size_t deviceMemoryOffsetPages = 0; deviceMemoryOffsetPages < 16; deviceMemoryOffsetPages++) {
		T_QUIET; T_ASSERT_LE(deviceMemoryOffsetPages * PAGE_SIZE, PHYSICAL_CARVEOUT_SIZE, "device memory offset is within physical carveout range");

		// size of memory descriptor
		for (size_t sizeInPages = 0; sizeInPages < 16; sizeInPages++) {
			T_QUIET; T_ASSERT_LE((deviceMemoryOffsetPages + sizeInPages) * PAGE_SIZE, PHYSICAL_CARVEOUT_SIZE, "memory descriptor is within physical carveout range");

			// offset into memory descriptor
			for (size_t offsetInPages = 0; offsetInPages < sizeInPages; offsetInPages++) {
				struct TestIODeviceMemoryRosettaUserClientArgs args;
				args.deviceMemoryOffset = deviceMemoryOffsetPages * PAGE_SIZE;
				args.offset = offsetInPages * PAGE_SIZE;
				args.size = sizeInPages * PAGE_SIZE;
				args.length = args.size - args.offset;
				// Key for xoring values in the memory descriptor. Must be unique for each call to the external method
				args.xorkey = sizeInPages + (offsetInPages << 8) + (deviceMemoryOffsetPages << 16);

				struct TestIODeviceMemoryRosettaUserClientOutput output;
				size_t outputSize = sizeof(output);

				T_LOG("Mapping physical memory starting at device offset 0x%llx, size 0x%llx, memory descriptor offset 0x%llx, length 0x%llx", args.deviceMemoryOffset, args.size, args.offset, args.length);
				T_QUIET; T_ASSERT_MACH_SUCCESS(IOConnectCallMethod(conn, 0,
				    NULL, 0, &args, sizeof(args), NULL, 0, &output, &outputSize), "call external method");

				T_QUIET; T_ASSERT_EQ(outputSize, sizeof(output), "outputSize is correct");



				mach_vm_address_t regionAddress = output.address;
				mach_vm_size_t regionSize = output.size;
				vm_region_extended_info_data_t regionInfo;
				mach_msg_type_number_t count = VM_REGION_EXTENDED_INFO_COUNT;
				mach_port_t unused = MACH_PORT_NULL;
				T_QUIET; T_ASSERT_MACH_SUCCESS(mach_vm_region(current_task(), &regionAddress, &regionSize, VM_REGION_EXTENDED_INFO, (vm_region_info_t)&regionInfo, &count, &unused), "get vm region");


				T_LOG("Mapped memory descriptor to 0x%llx, size 0x%llx. Region 0x%llx, size 0x%llx", output.address, output.size, regionAddress, regionSize);
				T_QUIET; T_ASSERT_EQ(output.size, args.length, "mapped size should equal length");
				T_QUIET; T_ASSERT_EQ(output.size, regionSize, "mapped size should equal region size");
				T_QUIET; T_ASSERT_EQ(output.address, regionAddress, "mapped address should equal region address");

				// Check contents are what we expect. The kernel fills the memory descriptor with uint64_t values
				// starting from 0, 1, 2, ... up to size of the memory descriptor / sizeof(uint64_t). To prevent
				// subsequent test runs from affecting each other, these values are xored with the key set earlier.
				for (uint64_t i = 0; i < output.size / sizeof(uint64_t); i++) {
					uint64_t value = ((uint64_t *)output.address)[i];
					uint64_t index = (uint64_t)(i + (args.offset + args.deviceMemoryOffset) / sizeof(uint64_t));
					T_QUIET; T_ASSERT_EQ(value, index ^ args.xorkey, "actual value matches expected value");
				}
			}
		}
	}

	IOConnectRelease(conn);
	IOObjectRelease(service);
#endif
}
