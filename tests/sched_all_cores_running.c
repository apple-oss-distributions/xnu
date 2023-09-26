// Copyright (c) 2023 Apple Inc.  All rights reserved.

#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <stdatomic.h>
#include <time.h>

#include <machine/cpu_capabilities.h>
#include <os/tsd.h>

#include <darwintest.h>
#include <darwintest_utils.h>
#include "test_utils.h"

T_GLOBAL_META(T_META_NAMESPACE("xnu.scheduler"),
    T_META_RADAR_COMPONENT_NAME("xnu"),
    T_META_RADAR_COMPONENT_VERSION("scheduler"));

/*
 * As a successor of clpc_disabling_cores_test_21636137, this test ensures that threads
 * are naturally being scheduled on all of the logical cores (without binding). The test
 * fails if CLPC has derecommended any cores.
 */

static mach_timebase_info_data_t timebase_info;

static uint64_t
nanos_to_abs(uint64_t nanos)
{
	mach_timebase_info(&timebase_info);
	return nanos * timebase_info.denom / timebase_info.numer;
}

static _Atomic uint64_t visited_cores_bitmask = 0;
static uint64_t spin_deadline_timestamp = 0;

static void *
spin_thread_fn(__unused void *arg)
{
	while (mach_absolute_time() < spin_deadline_timestamp) {
		unsigned int curr_cpu = _os_cpu_number();
		atomic_fetch_or_explicit(&visited_cores_bitmask, (1ULL << curr_cpu), memory_order_relaxed);
	}
	return NULL;
}

static void
start_threads(pthread_t *threads, void *(*start_routine)(void *), int priority, unsigned int num_threads)
{
	int rv;
	pthread_attr_t attr;

	rv = pthread_attr_init(&attr);
	T_QUIET; T_ASSERT_POSIX_ZERO(rv, "pthread_attr_init");

	for (unsigned int i = 0; i < num_threads; i++) {
		struct sched_param param = { .sched_priority = (int)priority };

		rv = pthread_attr_setschedparam(&attr, &param);
		T_QUIET; T_ASSERT_POSIX_ZERO(rv, "pthread_attr_setschedparam");

		rv = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
		T_QUIET; T_ASSERT_POSIX_ZERO(rv, "pthread_attr_setdetachstate");

		rv = pthread_create(&threads[i], &attr, start_routine, NULL);
		T_QUIET; T_ASSERT_POSIX_ZERO(rv, "pthread_create");
	}

	rv = pthread_attr_destroy(&attr);
	T_QUIET; T_ASSERT_POSIX_ZERO(rv, "pthread_attr_destroy");
}

static host_t host;
static processor_port_array_t cpu_ports;
static mach_msg_type_number_t cpu_count;

static void
init_host_and_cpu_count(void)
{
	kern_return_t kr;
	host_t priv_host;

	host = mach_host_self();

	kr = host_get_host_priv_port(host, &priv_host);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "host_get_host_priv_port");

	kr = host_processors(priv_host, &cpu_ports, &cpu_count);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "host_processors");

	T_QUIET; T_ASSERT_EQ(cpu_count, (unsigned int)dt_ncpu(), "cpu counts between host_processors() and hw.ncpu don't match");
}

static void
record_cpu_loads(struct processor_cpu_load_info *cpu_loads)
{
	kern_return_t kr;
	mach_msg_type_number_t info_count = PROCESSOR_CPU_LOAD_INFO_COUNT;
	for (unsigned int i = 0; i < cpu_count; i++) {
		kr = processor_info(cpu_ports[i], PROCESSOR_CPU_LOAD_INFO, &host, (processor_info_t)&cpu_loads[i], &info_count);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "processor_info");
	}
}

static void
cpu_loads_delta(struct processor_cpu_load_info *start_loads,
    struct processor_cpu_load_info *finish_loads,
    unsigned int *non_idle_ticks)
{
	struct processor_cpu_load_info delta_loads[cpu_count];
	T_LOG("Non-idle time per CPU:");
	for (unsigned int i = 0; i < cpu_count; i++) {
		uint64_t delta_sum = 0;
		for (int state = CPU_STATE_USER; state < CPU_STATE_MAX; state++) {
			T_QUIET; T_ASSERT_GE(finish_loads[i].cpu_ticks[state], start_loads[i].cpu_ticks[state], "non-monotonic ticks for state %d", state);
			delta_loads[i].cpu_ticks[state] = finish_loads[i].cpu_ticks[state] - start_loads[i].cpu_ticks[state];
			delta_sum += delta_loads[i].cpu_ticks[state];
		}
		T_QUIET; T_ASSERT_GT(delta_sum, 0ULL, "Failed to read meaningful load data for the core. Was the amfi_get_out_of_my_way=1 boot-arg missing?");
		non_idle_ticks[i] = delta_loads[i].cpu_ticks[CPU_STATE_USER] + delta_loads[i].cpu_ticks[CPU_STATE_SYSTEM];
		T_LOG("\tCore %d non-idle ticks: %d", i, non_idle_ticks[i]);
	}
}

#define KERNEL_BOOTARGS_MAX_SIZE 1024
static char kernel_bootargs[KERNEL_BOOTARGS_MAX_SIZE];

static const int DEFAULT_THREAD_PRI = 31;

T_DECL(all_cores_running,
    "Verify that we are using all available cores on the system",
    /* Required to get around the rate limit for processor_info() */
    T_META_BOOTARGS_SET("amfi_get_out_of_my_way=1"),
    T_META_ASROOT(true),
    XNU_T_META_SOC_SPECIFIC)
{
	T_SETUPBEGIN;
	int rv;

	/* Warn if amfi_get_out_of_my_way is not set and fail later on if we actually run into the rate limit */
	size_t kernel_bootargs_size = sizeof(kernel_bootargs);
	rv = sysctlbyname("kern.bootargs", kernel_bootargs, &kernel_bootargs_size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "kern.bootargs");
	if (strstr(kernel_bootargs, "amfi_get_out_of_my_way=1") == NULL) {
		T_LOG("WARNING: amfi_get_out_of_my_way=1 boot-arg is missing, required to reliably capture CPU load data");
	}

	init_host_and_cpu_count();
	T_LOG("System has %d logical cores", cpu_count);

	uint64_t recommended_cores_mask = 0;
	size_t recommended_cores_mask_size = sizeof(recommended_cores_mask);
	rv = sysctlbyname("kern.sched_recommended_cores", &recommended_cores_mask, &recommended_cores_mask_size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "kern.sched_recommended_cores");
	T_LOG("Mask kern.sched_recommended_cores: 0x%016llx", recommended_cores_mask);

	T_SETUPEND;

	struct processor_cpu_load_info start_cpu_loads[cpu_count];
	record_cpu_loads(start_cpu_loads);

	/* Wait 100ms for the system to settle down */
	usleep(100000);

	const uint64_t spin_seconds = 3;
	spin_deadline_timestamp = mach_absolute_time() + nanos_to_abs(spin_seconds * NSEC_PER_SEC);
	unsigned int num_threads = (unsigned int)dt_ncpu() * 2;
	T_LOG("Launching %u threads to spin for %lld seconds...", num_threads, spin_seconds);

	pthread_t threads[num_threads];
	start_threads(threads, &spin_thread_fn, DEFAULT_THREAD_PRI, num_threads);

	/* Wait for threads to perform spinning work */
	sleep(spin_seconds);
	T_LOG("...%lld seconds have elapsed", spin_seconds);

	struct processor_cpu_load_info finish_cpu_loads[cpu_count];
	record_cpu_loads(finish_cpu_loads);

	uint64_t final_visited_cores_bitmask = atomic_load(&visited_cores_bitmask);
	T_LOG("Visited cores bitmask: %llx", final_visited_cores_bitmask);

	unsigned int non_idle_ticks[cpu_count];
	cpu_loads_delta(start_cpu_loads, finish_cpu_loads, non_idle_ticks);

	/*
	 * Now after we have logged all of the relevant information, enforce that each
	 * of the cores was recommended and had test threads scheduled on it.
	 */
	T_ASSERT_EQ((unsigned int)__builtin_popcountll(final_visited_cores_bitmask), cpu_count, "Each core ran at least one of the test threads");
	for (unsigned int i = 0; i < cpu_count; i++) {
		T_QUIET; T_ASSERT_GT(non_idle_ticks[i], 0, "One or more cores were idle during the work period");
	}
	T_PASS("Each core performed work during the work period");

	T_END;
}

T_DECL(recommended_cores_mask,
    "Tests that the mask of recommended cores includes all logical cores according to hw.ncpu",
    T_META_NAMESPACE("xnu.scheduler"),
    XNU_T_META_SOC_SPECIFIC)
{
	int ret;

	uint32_t ncpu = 0;
	size_t ncpu_size = sizeof(ncpu);
	ret = sysctlbyname("hw.ncpu", &ncpu, &ncpu_size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "hw.ncpu");
	T_LOG("hw.ncpu: %d\n", ncpu);

	T_ASSERT_LE(ncpu, 64, "Core count isn't too high to reflect in the system's 64-bit wide core masks");

	int passed_test = 0;
	int tries = 0;
	int MAX_RETRIES = 3;
	while (!passed_test && tries < MAX_RETRIES) {
		uint64_t recommended_cores_mask = 0;
		size_t recommended_cores_mask_size = sizeof(recommended_cores_mask);
		ret = sysctlbyname("kern.sched_recommended_cores", &recommended_cores_mask, &recommended_cores_mask_size, NULL, 0);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "kern.sched_recommended_cores");
		T_LOG("kern.sched_recommended_cores:     0x%016llx", recommended_cores_mask);

		uint64_t expected_set_mask = ~0ULL >> (64 - ncpu);
		T_LOG("Expected bits set for all cores:  0x%016llx", expected_set_mask);

		if ((recommended_cores_mask & expected_set_mask) == expected_set_mask) {
			passed_test = 1;
		} else {
			/*
			 * Maybe some of the cores are derecommended due to thermals.
			 * Sleep to give the system a chance to quiesce and try again.
			 */
			unsigned int sleep_seconds = 10;
			T_LOG("Missing expected bits. Sleeping for %u seconds before retrying", sleep_seconds);
			sleep(sleep_seconds);
			tries++;
		}
	}

	T_ASSERT_EQ(passed_test, 1, "kern.sched_recommended_cores reflects that all expected cores are recommended");
}
