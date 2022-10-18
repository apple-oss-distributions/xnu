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
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("IOKit"),
	T_META_OWNER("ayao"));

//A client like IOUserClient2022_entitlements_unentitled without the com.apple.iokit.test-check-entitlement-open entitlement should fail on IOServiceOpen
//A client like IOUserClient2022_entitlements without com.apple.iokit.test-check-entitlement-per-selector should fail to call selector 1
T_DECL(TESTNAME, "Test IOUserClient2022 entitlement enforcement")
{
	io_service_t service;
	io_connect_t conn;
	const char *serviceName = "TestIOUserClient2022Entitlements";

	T_QUIET; T_ASSERT_POSIX_SUCCESS(IOTestServiceFindService(serviceName, &service), "Find service");
	T_QUIET; T_ASSERT_NE(service, MACH_PORT_NULL, "got service");
#if OPEN_ENTITLED
	T_QUIET; T_ASSERT_MACH_SUCCESS(IOServiceOpen(service, mach_task_self(), 0, &conn), "open service");
	//We expect failure since we don't have the entitlement to use selector 1
	T_QUIET; T_ASSERT_NE(IOConnectCallMethod(conn, 1,
	    NULL, 0, NULL, 0, NULL, 0, NULL, NULL), kIOReturnSuccess, "call external method 2");
#else
	//not entitled to open the service, so we expect failure.
	T_QUIET; T_ASSERT_NE(IOServiceOpen(service, mach_task_self(), 0, &conn), kIOReturnSuccess, "open service");
#endif
	IOConnectRelease(conn);
	IOObjectRelease(service);
}
