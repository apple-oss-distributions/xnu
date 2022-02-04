// Copyright (c) 2019-2020 Apple Inc.

#include <darwintest.h>
#include <sys/sysctl.h>

#include <Foundation/Foundation.h>
#include <IOKit/IOCFSerialize.h>
#include <IOKit/IOKitLib.h>

T_GLOBAL_META(T_META_NAMESPACE("xnu.iokit"),
	T_META_RUN_CONCURRENTLY(true));

static kern_return_t
build_ioregistry_by_catalog_send_data(const char *match_name,
    const char *userclient_name, const char *service_name)
{
	NSArray *rootCatalogueArray = @[@{
	    @kIOProviderClassKey: @kIOResourcesClass,
	    @kIOClassKey: (NSString * __nonnull)@(service_name),
	    @kIOUserClientClassKey: (NSString * __nonnull)@(userclient_name),
	    @kIOMatchCategoryKey: (NSString * __nonnull)@(match_name)
	}];

	CFDataRef cfData = IOCFSerialize((__bridge CFTypeRef)rootCatalogueArray,
	    kIOCFSerializeToBinary);
	T_QUIET; T_ASSERT_NOTNULL(cfData, "IOCFSerialize root catalogue array");
	kern_return_t kret = IOCatalogueSendData(MACH_PORT_NULL, 1,
	    (const char *)CFDataGetBytePtr(cfData),
	    (uint32_t)CFDataGetLength(cfData));
	CFRelease(cfData);
	return kret;
}

static bool
test_open_ioregistry(const char *match_name, const char *service_name,
    bool exploit)
{
	kern_return_t kret;
	bool ioreg_found = false;
	CFStringRef cfstrMatchName = NULL;
	io_connect_t conn = IO_OBJECT_NULL;
	io_iterator_t iter = IO_OBJECT_NULL, obj = IO_OBJECT_NULL;
	CFMutableDictionaryRef service_info = NULL, properties = NULL;

	service_info = IOServiceMatching(service_name);
	kret = IOServiceGetMatchingServices(kIOMasterPortDefault, service_info, &iter);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kret, "IOServiceGetMatchingServices");
	cfstrMatchName = CFStringCreateWithCString(kCFAllocatorDefault,
	    match_name, kCFStringEncodingUTF8);
	T_QUIET; T_ASSERT_NOTNULL(cfstrMatchName,
	    "created CFString from match name");

	while ((obj = IOIteratorNext(iter)) != 0) {
		kret = IORegistryEntryCreateCFProperties(obj, &properties,
		    kCFAllocatorDefault, kNilOptions);
		if (kret != KERN_SUCCESS) {
			T_LOG("IORegistryEntryCreateCFProperties fails, 0x%08X",
			    (uint32_t)kret);
			IOObjectRelease(obj);
			continue;
		}

		CFStringRef value = CFDictionaryGetValue(properties, CFSTR("IOMatchCategory"));
		if (value && CFGetTypeID(value) == CFStringGetTypeID() &&
		    CFEqual(value, cfstrMatchName)) {
			ioreg_found = true;
		} else {
			IOObjectRelease(obj);
			continue;
		}

		if (!exploit) {
			IOObjectRelease(obj);
			break;
		}

		T_LOG("try to exploit by opening service, possibly panic...");
		IOServiceOpen(obj, mach_task_self(), 0, &conn);
		IOObjectRelease(obj);

		break;
	}

	CFRelease(cfstrMatchName);

	if (properties) {
		CFRelease(properties);
	}

	if (iter != IO_OBJECT_NULL) {
		IOObjectRelease(iter);
	}

	if (conn != IO_OBJECT_NULL) {
		IOServiceClose(conn);
	}

	return ioreg_found;
}

T_DECL(io_catalog_send_data_test,
	"build an IORegistry entry with mismatching IOService and "
	"IOUserClientClass by IOCatalogueSendData to check for DoS in "
	"IOCatalogueSendData")
{
	kern_return_t kret = build_ioregistry_by_catalog_send_data("fooBar",
	    "IOSurfaceRootUserClient", "IOReportHub");
#if (TARGET_OS_IPHONE && !TARGET_OS_SIMULATOR)
	int development = 0;
	size_t development_size = sizeof(development);

	T_ASSERT_POSIX_SUCCESS(sysctlbyname("kern.development", &development,
	    &development_size, NULL, 0), "sysctl kern.development");

	if (development) {
		T_EXPECT_MACH_SUCCESS(kret, "IOCatalogueSendData should "
		    "return success with development kernel");
	} else {
		/* this trick to build an entry by io_catalog_send_data should fail */
		T_EXPECT_EQ(kret, kIOReturnNotPrivileged, "build an entry with"
		    " mismatch IOService and IOUserClientClass by IOCatalogueSendData "
		    "should fail as kIOReturnNotPrivileged in none-dev kernel without kernelmanagerd");
	}
#else
	T_EXPECT_MACH_SUCCESS(kret,
	    "IOCatalogueSendData should return success with kernelmanagerd");
#endif /* (TARGET_OS_IPHONE && !TARGET_OS_SIMULATOR) */
	T_EXPECT_FALSE(test_open_ioregistry("fooBar", "IOReportHub", false),
	    "mismatched entry built by IOCatalogueSendData should not be opened");
}
