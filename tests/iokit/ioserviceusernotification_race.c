#include <darwintest.h>
#include <darwintest_utils.h>
#include <mach/mach.h>
#include <mach/message.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <signal.h>
#include <mach/mach_vm.h>
#include <libproc.h>
#include <IOKit/IOKitLib.h>
#include <CoreFoundation/CoreFoundation.h>
#include <dispatch/dispatch.h>

#include "service_helpers.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.iokit"),
	T_META_RUN_CONCURRENTLY(true),
	T_META_ASROOT(true),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("IOKit"),
	T_META_OWNER("souvik_b"));


static bool
ioclasscount(const char * className, size_t * result)
{
	bool ret = false;
	kern_return_t status;
	io_registry_entry_t root = IO_OBJECT_NULL; //must release
	CFMutableDictionaryRef rootProps   = NULL; //must release
	CFStringRef classStr = CFStringCreateWithCString(kCFAllocatorDefault, className, kCFStringEncodingUTF8); //must release

	CFDictionaryRef diagnostics = NULL; //do not release
	CFDictionaryRef classes = NULL; //do not release
	CFNumberRef num = NULL; //do not release
	int32_t num32;

	root = IORegistryGetRootEntry(kIOMainPortDefault);
	status = IORegistryEntryCreateCFProperties(root,
	    &rootProps, kCFAllocatorDefault, kNilOptions);
	if (KERN_SUCCESS != status) {
		T_LOG("Error: Can't read registry root properties.");
		goto finish;
	}
	if (CFDictionaryGetTypeID() != CFGetTypeID(rootProps)) {
		T_LOG("Error: Registry root properties not a dictionary.");
		goto finish;
	}

	diagnostics = (CFDictionaryRef)CFDictionaryGetValue(rootProps,
	    CFSTR(kIOKitDiagnosticsKey));
	if (!diagnostics) {
		T_LOG("Error: Allocation information missing.");
		goto finish;
	}
	if (CFDictionaryGetTypeID() != CFGetTypeID(diagnostics)) {
		T_LOG("Error: Allocation information not a dictionary.");
		goto finish;
	}

	classes = (CFDictionaryRef)CFDictionaryGetValue(diagnostics, CFSTR("Classes"));
	if (!classes) {
		T_LOG("Error: Class information missing.");
		goto finish;
	}
	if (CFDictionaryGetTypeID() != CFGetTypeID(classes)) {
		T_LOG("Error: Class information not a dictionary.");
		goto finish;
	}

	num = (CFNumberRef)CFDictionaryGetValue(classes, classStr);
	if (!num) {
		T_LOG("Error: Could not find class %s in dictionary.", className);
		goto finish;
	}

	if (CFNumberGetTypeID() != CFGetTypeID(num)) {
		T_LOG("Error: Instance information not a number.");
		goto finish;
	}

	if (!CFNumberGetValue(num, kCFNumberSInt32Type, &num32)) {
		T_LOG("Error: Failed to get number.");
		goto finish;
	}

	if (num32 < 0) {
		T_LOG("Instance count is negative.");
		goto finish;
	}

	*result = (size_t)num32;

	ret = true;

finish:
	if (root != IO_OBJECT_NULL) {
		IOObjectRelease(root);
	}
	if (rootProps != NULL) {
		CFRelease(rootProps);
	}
	if (classStr != NULL) {
		CFRelease(classStr);
	}

	return ret;
}

static size_t
absoluteDifference(size_t first, size_t second)
{
	if (first > second) {
		return first - second;
	} else {
		return second - first;
	}
}

static void
notificationReceived(void * refcon __unused, io_iterator_t iter __unused, uint32_t msgType __unused, void * msgArg __unused)
{
	// T_LOG("notification received");
}

struct Context {
	IONotificationPortRef notifyPort;
	io_iterator_t iter;
};

static void
notificationReceived2(void * refcon, io_iterator_t iter __unused, uint32_t msgType __unused, void * msgArg __unused)
{
	struct Context * ctx = (struct Context *)refcon;
	IONotificationPortDestroy(ctx->notifyPort);
	IOObjectRelease(ctx->iter);
	free(ctx);
	T_LOG("notification received, destroyed");
}

T_HELPER_DECL(ioserviceusernotification_race_helper, "ioserviceusernotification_race_helper")
{
	dispatch_async(dispatch_get_main_queue(), ^{
		io_iterator_t iter;
		io_iterator_t iter2;
		IONotificationPortRef notifyPort;
		IONotificationPortRef notifyPort2;
		io_service_t service;

		notifyPort = IONotificationPortCreate(kIOMainPortDefault);
		IONotificationPortSetDispatchQueue(notifyPort, dispatch_get_main_queue());
		notifyPort2 = IONotificationPortCreate(kIOMainPortDefault);
		IONotificationPortSetDispatchQueue(notifyPort2, dispatch_get_main_queue());

		service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("TestIOServiceUserNotificationUserClient"));
		T_ASSERT_NE(service, IO_OBJECT_NULL, "service is nonnull");

		// The first notification object is kept for the lifetime of the helper
		T_ASSERT_MACH_SUCCESS(
			IOServiceAddInterestNotification(notifyPort, service, kIOBusyInterest, notificationReceived, NULL, &iter),
			"add notification");

		struct Context * c = calloc(1, sizeof(struct Context));

		// The second notification object is released after a notification is received
		T_ASSERT_MACH_SUCCESS(
			IOServiceAddInterestNotification(notifyPort2, service, kIOBusyInterest, notificationReceived2, c, &iter2),
			"add notification 2");

		c->notifyPort = notifyPort2;
		c->iter = iter2;

		IOObjectRelease(service);
	});

	dispatch_main();
}

// how many notification objects to create
#define NUM_NOTIFICATION_ITERS 500

// how many times we should run the helper
#define NUM_HELPER_INVOCATIONS 50

// when calling the external method, call in groups of N
#define EXTERNAL_METHOD_GROUP_SIZE 5

// How much ioclasscount variation to tolerate before we think we have a leak
#define IOCLASSCOUNT_LEAK_TOLERANCE 20

T_DECL(ioserviceusernotification_race, "Test IOServiceUserNotification race")
{
	io_service_t service = IO_OBJECT_NULL;
	io_connect_t connect = IO_OBJECT_NULL;
	IONotificationPortRef notifyPort = IONotificationPortCreate(kIOMainPortDefault);
	char test_path[MAXPATHLEN] = {0};
	char * helper_args[] = { test_path, "-n", "ioserviceusernotification_race_helper", NULL };
	io_iterator_t notificationIters[NUM_NOTIFICATION_ITERS];
	size_t initialIOServiceUserNotificationCount;
	size_t initialIOServiceMessageUserNotificationCount;
	size_t initialIOUserNotificationCount;
	size_t finalIOServiceUserNotificationCount;
	size_t finalIOServiceMessageUserNotificationCount;
	size_t finalIOUserNotificationCount;

	// Initial class counts
	T_ASSERT_TRUE(ioclasscount("IOServiceUserNotification", &initialIOServiceUserNotificationCount), "ioclasscount IOServiceUserNotification");
	T_ASSERT_TRUE(ioclasscount("IOServiceMessageUserNotification", &initialIOServiceMessageUserNotificationCount), "ioclasscount IOServiceMessageUserNotification");
	T_ASSERT_TRUE(ioclasscount("IOUserNotification", &initialIOUserNotificationCount), "ioclasscount IOUserNotification");

	T_QUIET; T_ASSERT_POSIX_SUCCESS(proc_pidpath(getpid(), test_path, MAXPATHLEN), "get pid path");
	T_QUIET; T_ASSERT_POSIX_SUCCESS(IOTestServiceFindService("TestIOServiceUserNotification", &service),
	    "Find service");
	T_QUIET; T_ASSERT_NE(service, MACH_PORT_NULL, "got service");

	for (size_t i = 0; i < NUM_HELPER_INVOCATIONS; i++) {
		pid_t child;
		if (connect == IO_OBJECT_NULL) {
			T_ASSERT_MACH_SUCCESS(IOServiceOpen(service, mach_task_self(), 1, &connect), "open service");
		}
		// Call the external method. This re-registers the service
		T_QUIET; T_ASSERT_MACH_SUCCESS(IOConnectCallMethod(connect, 0,
		    NULL, 0, NULL, 0, NULL, 0, NULL, NULL), "call external method");

		sleep(1);
		dt_launch_tool(&child, helper_args, false, NULL, NULL);
		T_LOG("launch helper -> pid %d", child);
		sleep(1);

		while (true) {
			for (size_t k = 0; k < EXTERNAL_METHOD_GROUP_SIZE; k++) {
				T_QUIET; T_ASSERT_MACH_SUCCESS(IOConnectCallMethod(connect, 0,
				    NULL, 0, NULL, 0, NULL, 0, NULL, NULL), "call external method");
				usleep(100);
			}
			if ((random() % 1000) == 0) {
				break;
			}
		}

		T_LOG("kill helper %d", child);
		kill(child, SIGKILL);

		if ((random() % 3) == 0) {
			IOServiceClose(connect);
			connect = IO_OBJECT_NULL;
		}
	}

	// Register for notifications
	for (size_t i = 0; i < sizeof(notificationIters) / sizeof(notificationIters[0]); i++) {
		T_QUIET; T_ASSERT_MACH_SUCCESS(
			IOServiceAddInterestNotification(notifyPort, service, kIOBusyInterest, notificationReceived, NULL, &notificationIters[i]),
			"add notification");
	}

	sleep(1);

	// Release the notifications
	for (size_t i = 0; i < sizeof(notificationIters) / sizeof(notificationIters[0]); i++) {
		T_QUIET; T_ASSERT_MACH_SUCCESS(
			IOObjectRelease(notificationIters[i]),
			"remove notification");
		notificationIters[i] = MACH_PORT_NULL;
	}

	// Check for leaks
	T_ASSERT_TRUE(ioclasscount("IOServiceUserNotification", &finalIOServiceUserNotificationCount), "ioclasscount IOServiceUserNotification");
	T_ASSERT_TRUE(ioclasscount("IOServiceMessageUserNotification", &finalIOServiceMessageUserNotificationCount), "ioclasscount IOServiceMessageUserNotification");
	T_ASSERT_TRUE(ioclasscount("IOUserNotification", &finalIOUserNotificationCount), "ioclasscount IOUserNotification");
	T_ASSERT_LT(absoluteDifference(initialIOServiceUserNotificationCount, finalIOServiceUserNotificationCount), (size_t)IOCLASSCOUNT_LEAK_TOLERANCE, "did not leak IOServiceUserNotification");
	T_ASSERT_LT(absoluteDifference(initialIOServiceMessageUserNotificationCount, finalIOServiceMessageUserNotificationCount), (size_t)IOCLASSCOUNT_LEAK_TOLERANCE, "did not leak IOServiceMessageUserNotification");
	T_ASSERT_LT(absoluteDifference(initialIOUserNotificationCount, finalIOUserNotificationCount), (size_t)IOCLASSCOUNT_LEAK_TOLERANCE, "did not leak IOUserNotification");

	IOObjectRelease(service);
	IONotificationPortDestroy(notifyPort);
}
