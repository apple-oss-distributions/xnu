/*
 * Tests to validate that:
 *  - we can schedule threads on all hw.ncpus cores according to _os_cpu_number
 *  - we can schedule threads on all hw.cpuclusters clusters according to _os_cpu_cluster_number
 *  - the cluster id returned by _os_cpu_cluster_number aligns with mappings from IORegistry
 *
 * <rdar://problem/29545645>
 * <rdar://problem/30445216>
 *
 *  xcrun -sdk macosx.internal clang -o cpucount cpucount.c -ldarwintest -framework IOKit -framework CoreFoundation -g -Weverything
 *  xcrun -sdk iphoneos.internal clang -arch arm64 -o cpucount-ios cpucount.c -ldarwintest -framework IOKit -framework CoreFoundation -g -Weverything
 *  xcrun -sdk macosx.internal clang -o cpucount cpucount.c -ldarwintest -framework IOKit -framework CoreFoundation -arch arm64e -Weverything
 */

#include <darwintest.h>
#include "test_utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/commpage.h>
#include <sys/sysctl.h>
#include <sys/proc_info.h>
#include <libproc.h>

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>

#include <mach/mach.h>
#include <mach/mach_time.h>
#include <machine/cpu_capabilities.h>

#include <os/tsd.h> /* private header for _os_cpu_number, _os_cpu_cluster_number */

T_GLOBAL_META(
	T_META_RUN_CONCURRENTLY(false),
	T_META_BOOTARGS_SET("enable_skstb=1"),
	T_META_CHECK_LEAKS(false),
	T_META_ASROOT(true),
	T_META_ALL_VALID_ARCHS(true),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("scheduler"),
	T_META_OWNER("jarrad")
	);

#define KERNEL_BOOTARGS_MAX_SIZE 1024
static char kernel_bootargs[KERNEL_BOOTARGS_MAX_SIZE];

#define KERNEL_VERSION_MAX_SIZE 1024
static char kernel_version[KERNEL_VERSION_MAX_SIZE];

static mach_timebase_info_data_t timebase_info;

// Source: libktrace:corefoundation_helpers.c

static void
dict_number_internal(CFDictionaryRef dict, CFStringRef key, void *dst_out, CFNumberType nbr_type)
{
	bool success;
	T_QUIET; T_ASSERT_NOTNULL(dict, "dict must not be null");
	T_QUIET; T_ASSERT_NOTNULL(key, " key must not be null");
	T_QUIET; T_ASSERT_NOTNULL(dst_out, "dst out must not be null");

	CFTypeRef val = CFDictionaryGetValue(dict, key);
	T_QUIET; T_ASSERT_NOTNULL(val, "unable to get value for key %s", CFStringGetCStringPtr(key, kCFStringEncodingASCII));

	CFTypeID type = CFGetTypeID(val);
	if (type == CFNumberGetTypeID()) {
		CFNumberRef val_nbr = (CFNumberRef)val;
		success = CFNumberGetValue(val_nbr, nbr_type, dst_out);
		T_QUIET; T_ASSERT_TRUE(success, "dictionary number at key '%s' is not the right type", CFStringGetCStringPtr(key, kCFStringEncodingASCII));
	} else if (type == CFDataGetTypeID()) {
		CFDataRef val_data = (CFDataRef)val;
		size_t raw_size = (size_t)CFDataGetLength(val_data);
		T_QUIET; T_ASSERT_EQ(raw_size, (size_t)4, "cannot convert CFData of size %zu to number", raw_size);
		CFDataGetBytes(val_data, CFRangeMake(0, (CFIndex)raw_size), dst_out);
	} else {
		T_ASSERT_FAIL("dictionary value at key '%s' should be a number or data", CFStringGetCStringPtr(key, kCFStringEncodingASCII));
	}
}

static void
dict_uint32(CFDictionaryRef dict, CFStringRef key, uint32_t *dst_out)
{
	dict_number_internal(dict, key, dst_out, kCFNumberSInt32Type);
}

static uint64_t
abs_to_nanos(uint64_t abs)
{
	return abs * timebase_info.numer / timebase_info.denom;
}

static int32_t
get_csw_count(void)
{
	struct proc_taskinfo taskinfo;
	int rv;

	rv = proc_pidinfo(getpid(), PROC_PIDTASKINFO, 0, &taskinfo, sizeof(taskinfo));
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "PROC_PIDTASKINFO");

	return taskinfo.pti_csw;
}

// noinline hopefully keeps the optimizer from hoisting it out of the loop
// until rdar://68253516 is fixed.
__attribute__((noinline))
static uint32_t
fixed_os_cpu_number(void)
{
	uint32_t cpu_number = _os_cpu_number();
	return cpu_number;
}

static unsigned int
commpage_cpu_cluster_number(void)
{
	uint8_t cpu_number = (uint8_t)fixed_os_cpu_number();
	volatile uint8_t *cpu_to_cluster = COMM_PAGE_SLOT(uint8_t, CPU_TO_CLUSTER);
	return (unsigned int)*(cpu_to_cluster + cpu_number);
}

static void
cpucount_setup(void)
{
	int rv;
	kern_return_t kr;

	T_SETUPBEGIN;

	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	/* Validate what kind of kernel we're on */
	size_t kernel_version_size = sizeof(kernel_version);
	rv = sysctlbyname("kern.version", kernel_version, &kernel_version_size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "kern.version");

	T_LOG("kern.version: %s\n", kernel_version);

	/* Double check that darwintest set the boot arg we requested */
	size_t kernel_bootargs_size = sizeof(kernel_bootargs);
	rv = sysctlbyname("kern.bootargs", kernel_bootargs, &kernel_bootargs_size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "kern.bootargs");

	T_LOG("kern.bootargs: %s\n", kernel_bootargs);

	if (NULL == strstr(kernel_bootargs, "enable_skstb=1")) {
		T_ASSERT_FAIL("enable_skstb=1 boot-arg is missing");
	}

	kr = mach_timebase_info(&timebase_info);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_timebase_info");

	struct sched_param param = {.sched_priority = 63};

	rv = pthread_setschedparam(pthread_self(), SCHED_FIFO, &param);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "pthread_setschedparam");

	T_SETUPEND;
}


T_DECL(count_cpus,
    "Tests we can schedule bound threads on all hw.ncpus cores and that _os_cpu_number matches",
    XNU_T_META_SOC_SPECIFIC)
{
	int rv;

	cpucount_setup();

	int bound_cpu_out = 0;
	size_t bound_cpu_out_size = sizeof(bound_cpu_out);
	rv = sysctlbyname("kern.sched_thread_bind_cpu", &bound_cpu_out, &bound_cpu_out_size, NULL, 0);

	if (rv == -1) {
		if (errno == ENOENT) {
			T_ASSERT_FAIL("kern.sched_thread_bind_cpu doesn't exist, must set enable_skstb=1 boot-arg on development kernel");
		}
		if (errno == EPERM) {
			T_ASSERT_FAIL("must run as root");
		}
	}

	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "read kern.sched_thread_bind_cpu");
	T_QUIET; T_ASSERT_EQ(bound_cpu_out, -1, "kern.sched_thread_bind_cpu should exist, start unbound");

	uint32_t sysctl_ncpu = 0;
	size_t ncpu_size = sizeof(sysctl_ncpu);
	rv = sysctlbyname("hw.ncpu", &sysctl_ncpu, &ncpu_size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "sysctlbyname(hw.ncpu)");

	T_LOG("hw.ncpu: %2d\n", sysctl_ncpu);

	T_ASSERT_GT(sysctl_ncpu, 0, "at least one CPU exists");

	for (uint32_t cpu_to_bind = 0; cpu_to_bind < sysctl_ncpu; cpu_to_bind++) {
		int32_t before_csw_count = get_csw_count();
		T_LOG("(csw %4d) attempting to bind to cpu %2d\n", before_csw_count, cpu_to_bind);

		uint64_t start =  mach_absolute_time();

		rv = sysctlbyname("kern.sched_thread_bind_cpu", NULL, 0, &cpu_to_bind, sizeof(cpu_to_bind));

		uint64_t end =  mach_absolute_time();

		if (rv == -1 && errno == ENOTSUP) {
			T_SKIP("Binding is available, but this process doesn't support binding (e.g. Rosetta on Aruba)");
		}

		T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "kern.sched_thread_bind_cpu(%u)", cpu_to_bind);

		uint32_t os_cpu_number_reported = fixed_os_cpu_number();

		bound_cpu_out = 0;
		rv = sysctlbyname("kern.sched_thread_bind_cpu", &bound_cpu_out, &bound_cpu_out_size, NULL, 0);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "read kern.sched_thread_bind_cpu");

		T_QUIET; T_EXPECT_EQ((int)cpu_to_bind, bound_cpu_out,
		    "should report bound cpu id matching requested bind target");

		uint64_t delta_abs = end - start;
		uint64_t delta_ns = abs_to_nanos(delta_abs);

		int32_t after_csw_count = get_csw_count();

		T_LOG("(csw %4d) bound to cpu %2d in %f milliseconds\n",
		    after_csw_count, cpu_to_bind,
		    ((double)delta_ns / 1000000.0));

		if (cpu_to_bind > 0) {
			T_QUIET; T_EXPECT_LT(before_csw_count, after_csw_count,
			    "should have had to context switch to execute the bind");
		}

		T_LOG("cpu %2d reported id %2d\n",
		    cpu_to_bind, os_cpu_number_reported);

		T_QUIET;
		T_EXPECT_EQ(cpu_to_bind, os_cpu_number_reported,
		    "should report same CPU number as was bound to");
	}

	int unbind = -1; /* pass -1 in order to unbind the thread */

	rv = sysctlbyname("kern.sched_thread_bind_cpu", NULL, 0, &unbind, sizeof(unbind));

	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "kern.sched_thread_bind_cpu(%u)", unbind);

	rv = sysctlbyname("kern.sched_thread_bind_cpu", &bound_cpu_out, &bound_cpu_out_size, NULL, 0);

	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "read kern.sched_thread_bind_cpu");
	T_QUIET; T_ASSERT_EQ(bound_cpu_out, -1, "thread should be unbound at the end");

	T_PASS("test has run threads on all CPUS");
}

T_DECL(count_clusters,
    "Tests we can schedule bound threads on all cpu clusters and that _os_cpu_cluster_number matches",
    XNU_T_META_SOC_SPECIFIC)
{
	int rv;

	cpucount_setup();

	uint8_t cpuclusters = COMM_PAGE_READ(uint8_t, CPU_CLUSTERS);
	T_LOG("cpuclusters: %2d\n", cpuclusters);
	T_QUIET; T_ASSERT_GT(cpuclusters, 0, "at least one CPU cluster exists");
	if (cpuclusters == 1) {
		T_SKIP("Test is unsupported on non-AMP platforms");
	}

	uint32_t sysctl_ncpu = 0;
	size_t ncpu_size = sizeof(sysctl_ncpu);
	rv = sysctlbyname("hw.ncpu", &sysctl_ncpu, &ncpu_size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "sysctlbyname(hw.ncpu)");
	T_LOG("hw.ncpu: %2d\n", sysctl_ncpu);

	uint64_t recommended_cores = 0;
	size_t recommended_cores_size = sizeof(recommended_cores);
	rv = sysctlbyname("kern.sched_recommended_cores", &recommended_cores, &recommended_cores_size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "sysctlbyname(kern.sched_recommended_cores)");
	T_LOG("kern.sched_recommended_cores: %llu", recommended_cores);
	if ((uint32_t)__builtin_popcountll(recommended_cores) != sysctl_ncpu) {
		T_SKIP("Missing recommended cores");
	}

	int bound_cluster_out = 0;
	size_t bound_cluster_out_size = sizeof(bound_cluster_out);
	rv = sysctlbyname("kern.sched_thread_bind_cluster_id", &bound_cluster_out, &bound_cluster_out_size, NULL, 0);

	if (rv == -1) {
		if (errno == ENOENT) {
			T_ASSERT_FAIL("kern.sched_thread_bind_cluster_id doesn't exist, must set enable_skstb=1 boot-arg on development kernel");
		}
		if (errno == EPERM) {
			T_ASSERT_FAIL("must run as root");
		}
	}

	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "read kern.sched_thread_bind_cluster_id");
	T_QUIET; T_ASSERT_EQ(bound_cluster_out, -1, "kern.sched_thread_bind_cluster_id should exist, start unbound");

	for (uint32_t cluster_to_bind = 0; cluster_to_bind < cpuclusters; cluster_to_bind++) {
		int32_t before_csw_count = get_csw_count();
		T_LOG("(csw %4d) attempting to bind to cluster %2d\n", before_csw_count, cluster_to_bind);

		uint64_t start =  mach_absolute_time();

		rv = sysctlbyname("kern.sched_thread_bind_cluster_id", NULL, 0, &cluster_to_bind, sizeof(cluster_to_bind));

		uint64_t end =  mach_absolute_time();

		if (rv == -1 && errno == ENOTSUP) {
			T_SKIP("Binding is available, but this process doesn't support binding (e.g. Rosetta on Aruba)");
		}

		T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "kern.sched_thread_bind_cluster_id(%u)", cluster_to_bind);

		T_LOG("CPU ID: %d", fixed_os_cpu_number());

#if TARGET_CPU_X86_64
		T_LOG("_os_cpu_cluster_number unsupported under x86.");
#else
		unsigned int os_cluster_number_reported = _os_cpu_cluster_number();
		T_LOG("OS reported cluster number: %2d\n",
		    os_cluster_number_reported);
		T_QUIET; T_EXPECT_EQ(cluster_to_bind, os_cluster_number_reported,
		    "_os_cpu_cluster_number should report same cluster number as was bound to");
#endif

		unsigned int commpage_cluster_number_reported = commpage_cpu_cluster_number();
		T_LOG("Comm Page reported cluster number: %u", commpage_cluster_number_reported);
		T_EXPECT_EQ(commpage_cluster_number_reported, cluster_to_bind, "comm page cluster number matches commpage for this CPU");

		bound_cluster_out = 0;
		rv = sysctlbyname("kern.sched_thread_bind_cluster_id", &bound_cluster_out, &bound_cluster_out_size, NULL, 0);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "read kern.sched_thread_bind_cluster_id");

		T_QUIET; T_EXPECT_EQ((int)cluster_to_bind, bound_cluster_out,
		    "bound cluster id matches requested bind target");

		uint64_t delta_abs = end - start;
		uint64_t delta_ns = abs_to_nanos(delta_abs);

		int32_t after_csw_count = get_csw_count();

		T_LOG("(csw %4d) bound to cluster %2d in %f milliseconds\n",
		    after_csw_count, cluster_to_bind,
		    ((double)delta_ns / 1000000.0));

		if (cluster_to_bind > 0) {
			T_QUIET; T_EXPECT_LT(before_csw_count, after_csw_count,
			    "should have had to context switch to execute the bind");
		}
	}

	int unbind = -1; /* pass -1 in order to unbind the thread */

	rv = sysctlbyname("kern.sched_thread_bind_cluster_id", NULL, 0, &unbind, sizeof(unbind));

	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "kern.sched_thread_bind_cluster_id(%u)", unbind);

	rv = sysctlbyname("kern.sched_thread_bind_cluster_id", &bound_cluster_out, &bound_cluster_out_size, NULL, 0);

	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "read kern.sched_thread_bind_cluster_id");
	T_QUIET; T_ASSERT_EQ(bound_cluster_out, -1, "thread should be unbound at the end");

	T_PASS("test has run threads on all clusters");
}

T_DECL(check_cpu_topology,
    "Verify _os_cpu_cluster_number(), _os_cpu_number() against IORegistry",
    XNU_T_META_SOC_SPECIFIC,
    T_META_ENABLED(TARGET_CPU_ARM || TARGET_CPU_ARM64))
{
	int rv;
	uint32_t cpu_id, cluster_id;
	kern_return_t kr;
	io_iterator_t cpus_iter = 0;
	io_service_t cpus_service = 0;
	io_service_t cpu_service = 0;
	CFDictionaryRef match = NULL;

	cpucount_setup();

	int bound_cpu_out = 0;
	size_t bound_cpu_out_size = sizeof(bound_cpu_out);
	rv = sysctlbyname("kern.sched_thread_bind_cpu", &bound_cpu_out, &bound_cpu_out_size, NULL, 0);

	if (rv == -1) {
		if (errno == ENOENT) {
			T_FAIL("kern.sched_thread_bind_cpu doesn't exist, must set enable_skstb=1 boot-arg on development kernel");
		}
		if (errno == EPERM) {
			T_FAIL("must run as root");
		}
	}

	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "read kern.sched_thread_bind_cpu");
	T_QUIET; T_ASSERT_EQ(bound_cpu_out, -1, "kern.sched_thread_bind_cpu should exist, start unbound");

	match = IOServiceNameMatching("cpus");
	cpus_service = IOServiceGetMatchingService(kIOMainPortDefault, match);
	match = NULL; // consumes reference to match
	T_QUIET; T_ASSERT_NE(cpus_service, (io_service_t)0, "Failed get cpus IOService");

	kr = IORegistryEntryGetChildIterator(cpus_service, "IODeviceTree", &cpus_iter);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "IORegistryEntryGetChildIterator");

	while ((cpu_service = IOIteratorNext(cpus_iter)) != 0) {
		CFMutableDictionaryRef props = NULL;
		kr = IORegistryEntryCreateCFProperties(cpu_service, &props, kCFAllocatorDefault, 0);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "IORegistryEntryCreateCFProperties");

		dict_uint32(props, CFSTR("logical-cpu-id"), &cpu_id);
		T_LOG("IORegistry logical cpu id: %u", cpu_id);
		dict_uint32(props, CFSTR("logical-cluster-id"), &cluster_id);
		T_LOG("IORegistry logical cpu cluster id: %u", cluster_id);

		T_LOG("Binding thread to cpu %u", cpu_id);
		rv = sysctlbyname("kern.sched_thread_bind_cpu", NULL, 0, &cpu_id, sizeof(cpu_id));
		if (rv == -1 && errno == ENOTSUP) {
			T_SKIP("Binding is available, but this process doesn't support binding (e.g. Rosetta on Aruba)");
		}
		T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "kern.sched_thread_bind_cpu(%u)", cpu_id);

		unsigned int os_cpu_number_reported = fixed_os_cpu_number();
		T_EXPECT_EQ(os_cpu_number_reported, cpu_id, "_os_cpu_number matches IORegistry entry for this CPU");
		unsigned int os_cluster_number_reported = _os_cpu_cluster_number();
		T_EXPECT_EQ(os_cluster_number_reported, cluster_id, "_os_cpu_cluster_number matches IORegistry entry for this CPU");
		unsigned int commpage_cluster_number_reported = commpage_cpu_cluster_number();
		T_EXPECT_EQ(commpage_cluster_number_reported, cluster_id, "comm page cluster number matches IORegistry entry for this CPU");

		CFRelease(props);
		IOObjectRelease(cpu_service);
	}
	T_PASS("All cluster IDs match with IORegistry");
}
