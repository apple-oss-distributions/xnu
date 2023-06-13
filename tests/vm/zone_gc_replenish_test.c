#include <sys/sysctl.h>
#include <time.h>

#include <darwintest.h>
#include <darwintest_utils.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"));

static int64_t
run_sysctl_test(const char *t, int64_t value)
{
	char name[1024];
	int64_t result = 0;
	size_t s = sizeof(value);
	int rc;

	snprintf(name, sizeof(name), "debug.test.%s", t);
	rc = sysctlbyname(name, &result, &s, &value, s);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rc, "sysctlbyname(%s)", t);
	return result;
}


static void *
gc_thread_func(__unused void *arg)
{
	time_t start = time(NULL);
	size_t n = 0;

	/*
	 * Keep kicking the test for 15 seconds to see if we can panic() the kernel
	 */
	while (time(NULL) < start + 15) {
		run_sysctl_test("zone_gc_replenish_test", 0);
		if (++n % 100000 == 0) {
			T_LOG("%zd zone_gc_replenish_test done", n);
		}
	}
	return NULL;
}

static void *
alloc_thread_func(__unused void *arg)
{
	time_t start = time(NULL);
	size_t n = 0;

	/*
	 * Keep kicking the test for 15 seconds to see if we can panic() the kernel
	 */
	while (time(NULL) < start + 15) {
		run_sysctl_test("zone_alloc_replenish_test", 0);
		if (++n % 10000 == 0) {
			T_LOG("%zd zone_alloc_replenish_test done", n);
		}
	}
	return NULL;
}

T_DECL(zone_gc_replenish_test,
    "Test zone garbage collection, exhaustion and replenishment",
    T_META_CHECK_LEAKS(false))
{
	pthread_attr_t attr;
	pthread_t gc_thread;
	pthread_t alloc_thread;
	int ret;

	ret = pthread_attr_init(&attr);
	T_QUIET; T_ASSERT_MACH_SUCCESS(ret, "pthread_attr_init");

	ret = pthread_create(&gc_thread, &attr, gc_thread_func, NULL);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "gc pthread_create");

	ret = pthread_create(&alloc_thread, &attr, alloc_thread_func, NULL);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "alloc pthread_create");

	T_ASSERT_POSIX_ZERO(pthread_join(gc_thread, NULL), NULL);
	T_ASSERT_POSIX_ZERO(pthread_join(alloc_thread, NULL), NULL);
	T_PASS("Ran 15 seconds with no panic");
}
