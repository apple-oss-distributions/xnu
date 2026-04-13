#include <sys/sysctl.h>
#include <signal.h>
#include <darwintest.h>
#include <darwintest_utils.h>
#include <ptrauth.h>
#include "test_utils.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"),
	T_META_ASROOT(YES),
	T_META_RUN_CONCURRENTLY(false),
	T_META_TAG_VM_PREFERRED);

static int64_t
run_sysctl_test(const char *t, int64_t value)
{
	char name[1024];
	int64_t result = 0;
	size_t s = sizeof(value);
	int rc;

	snprintf(name, sizeof(name), "debug.test.%s", t);
	rc = sysctlbyname(name, &result, &s, &value, s);
	T_ASSERT_POSIX_SUCCESS(rc, "sysctlbyname(%s)", t);
	return result;
}


uint64_t threads_and_iters;

static void *
race_thread_impl(void * args __unused)
{
	int64_t result = run_sysctl_test("vm_range_lock_race_test", threads_and_iters);
	T_QUIET; T_EXPECT_EQ(1ULL, result, "vm_range_lock_race_test");
	return NULL;
}


static void *
fault_thread_impl(void * args __unused)
{
	int64_t result = run_sysctl_test("vm_range_lock_fault_bench", threads_and_iters);
	T_QUIET; T_EXPECT_EQ(1ULL, result, "vm_range_lock_fault_bench");
	return NULL;
}

static void *
entry_lock_stress_test_impl(void * args __unused)
{
	int64_t result = run_sysctl_test("vm_entry_lock_stress_test", threads_and_iters);
	T_QUIET; T_EXPECT_EQ(1ULL, result, "vm_entry_lock_stress_test");
	return NULL;
}
/*
 * We communicate with our kernel side stress tests via a 64 bit value
 * Put the thread count in the top 32 bits, the iterations in the bottom 32.
 */
uint64_t
pack_threads_and_iterations(uint32_t threads, uint32_t iterations)
{
	return (((uint64_t)threads) << 32) | ((uint64_t) iterations);
}

static void
test_n_threads_for_n_iterations(uint32_t thread_count, uint32_t iterations, void *  (*func)(void *))
{
	size_t max_threads;
	size_t max_threads_size = sizeof(max_threads);
	int rc = sysctlbyname("kern.num_taskthreads", &max_threads, &max_threads_size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rc, "sysctlbyname(kern.num_taskthreads)");
	T_QUIET; T_ASSERT_LT_ULONG((size_t) thread_count, max_threads, "Only %lu threads can exist", max_threads);

	threads_and_iters = pack_threads_and_iterations(thread_count, iterations);

	pthread_t * race_threads = malloc(sizeof(pthread_t) * thread_count);
	for (size_t i = 0; i < thread_count; i++) {
		int err = pthread_create(&race_threads[i], NULL, func, NULL);
		T_QUIET; T_ASSERT_EQ(err, 0, "pthread_create");
	}

	for (size_t i = 0; i < thread_count; i++) {
		void * unused;
		pthread_join(race_threads[i], &unused);
	}
	T_PASS("test_threads(%u)", thread_count);
}

T_DECL(vm_map_lock_single_entry_stress_test, "Range Lock Single Entry Stress")
{
	test_n_threads_for_n_iterations(1, 0x10000, fault_thread_impl);
	test_n_threads_for_n_iterations(16, 0x10000, fault_thread_impl);
	test_n_threads_for_n_iterations(512, 0x10000, fault_thread_impl);
}

T_DECL(vm_map_lock_stress_test, "Range Lock Stress test")
{
	test_n_threads_for_n_iterations(1, 400000, race_thread_impl);
	test_n_threads_for_n_iterations(2, 400000, race_thread_impl);
	test_n_threads_for_n_iterations(3, 400000, race_thread_impl);
	test_n_threads_for_n_iterations(5, 400000, race_thread_impl);
	test_n_threads_for_n_iterations(10, 10000, race_thread_impl);
	test_n_threads_for_n_iterations(1023, 100, race_thread_impl); // 1023 because 1024 threads is the limit
}

T_DECL(vm_entry_lock_stress_test, "vm_entry_lock_stress_test")
{
	test_n_threads_for_n_iterations(1, 1000000, entry_lock_stress_test_impl);
	test_n_threads_for_n_iterations(2, 1000000, entry_lock_stress_test_impl);
	test_n_threads_for_n_iterations(3, 1000000, entry_lock_stress_test_impl);
	test_n_threads_for_n_iterations(10, 400000, entry_lock_stress_test_impl);
	test_n_threads_for_n_iterations(50, 150000, entry_lock_stress_test_impl);
}
