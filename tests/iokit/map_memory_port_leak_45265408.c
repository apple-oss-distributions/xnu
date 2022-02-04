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

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.iokit"),
	T_META_RUN_CONCURRENTLY(true),
	T_META_ASROOT(true),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("IOKit"),
	T_META_OWNER("souvik_b"));

static mach_msg_type_number_t
getPortNameCount(void)
{
	mach_port_name_array_t portNameArray;
	mach_msg_type_number_t portNameCount;
	mach_port_type_array_t portTypeArray;
	mach_msg_type_number_t portTypeCount;
	T_QUIET; T_ASSERT_MACH_SUCCESS(mach_port_names(mach_task_self(), &portNameArray, &portNameCount, &portTypeArray, &portTypeCount), "mach_port_names");
	vm_deallocate(mach_task_self(), (vm_address_t) portNameArray, portNameCount * sizeof(*portNameArray));
	vm_deallocate(mach_task_self(), (vm_address_t) portTypeArray, portTypeCount * sizeof(*portTypeArray));

	return portNameCount;
}

T_DECL(testIOConnectMapMemoryPortLeak45265408, "Test mapping memory (rdar://45265408)")
{
	io_service_t service = IO_OBJECT_NULL;
	io_connect_t connect = IO_OBJECT_NULL;
	mach_msg_type_number_t lastPortNameCount = 0;
	mach_msg_type_number_t portNameCount = 0;
	mach_vm_address_t address;
	mach_vm_size_t size;
	size_t consecutive = 0;

	T_QUIET; T_ASSERT_POSIX_SUCCESS(IOTestServiceFindService("TestIOConnectMapMemoryPortLeak45265408", &service),
	    "Find service");
	T_QUIET; T_ASSERT_NE(service, MACH_PORT_NULL, "got service");

	for (size_t i = 0; i < 200000; i++) {
		T_QUIET; T_ASSERT_MACH_SUCCESS(IOServiceOpen(service, mach_task_self(), 1, &connect), "open service");
		T_QUIET; T_ASSERT_MACH_SUCCESS(IOConnectMapMemory(connect,
		    0,
		    mach_task_self(),
		    &address,
		    &size,
		    kIOMapAnywhere | kIOMapDefaultCache | kIOMapReadOnly),
		    "map memory");
		T_QUIET; T_ASSERT_MACH_SUCCESS(IOConnectUnmapMemory(connect,
		    0,
		    mach_task_self(),
		    address),
		    "map memory");
		T_QUIET; T_ASSERT_MACH_SUCCESS(IOServiceClose(connect), "close service");

		if ((i % 10000) == 0) {
			portNameCount = getPortNameCount();

			T_LOG("Iteration %zu, ports %u", i, portNameCount);

			if (lastPortNameCount != 0) {
				if (portNameCount - lastPortNameCount > 1000) {
					consecutive += 1;
					if (consecutive > 10) {
						T_FAIL("Detected port leak %u -> %u", lastPortNameCount, portNameCount);
					}
				}
			}

			lastPortNameCount = portNameCount;
		}
	}

	IOObjectRelease(service);
}
