/* test that the header doesn't implicitly depend on others */
#include <sys/work_interval.h>

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>
#include <string.h>
#include <pthread.h>
#include <sys/sysctl.h>

#include <mach/mach.h>
#include <mach/semaphore.h>

#include <libkern/OSAtomic.h>

#include <darwintest.h>
#include "test_utils.h"

T_GLOBAL_META(T_META_NAMESPACE("xnu.scheduler"),
    T_META_RADAR_COMPONENT_NAME("xnu"),
    T_META_RADAR_COMPONENT_VERSION("scheduler"));


static mach_timebase_info_data_t timebase_info;

static uint64_t
nanos_to_abs(uint64_t nanos)
{
	mach_timebase_info(&timebase_info);
	return nanos * timebase_info.denom / timebase_info.numer;
}

static uint64_t
abs_to_nanos(uint64_t abs)
{
	return abs * timebase_info.numer / timebase_info.denom;
}

static void
set_realtime(pthread_t thread, uint64_t interval_nanos)
{
	kern_return_t kr;
	thread_time_constraint_policy_data_t pol;

	mach_port_t target_thread = pthread_mach_thread_np(thread);
	T_QUIET; T_ASSERT_GT(target_thread, 0, "pthread_mach_thread_np");

	/* 1s 100ms 10ms */
	pol.period      = (uint32_t)nanos_to_abs(interval_nanos);
	pol.constraint  = (uint32_t)nanos_to_abs(interval_nanos);
	pol.computation = (uint32_t)nanos_to_abs(interval_nanos - 1000000); // 1 ms of leeway

	pol.preemptible = 0; /* Ignored by OS */
	kr = thread_policy_set(target_thread, THREAD_TIME_CONSTRAINT_POLICY, (thread_policy_t) &pol,
	    THREAD_TIME_CONSTRAINT_POLICY_COUNT);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "thread_policy_set(THREAD_TIME_CONSTRAINT_POLICY)");
}

static void
create_coreaudio_work_interval(work_interval_t *wi_handle, work_interval_instance_t *wi_instance,
    mach_port_t *wi_port, bool enable_telemetry, uint32_t create_flags)
{
	int ret = 0;
	create_flags |= WORK_INTERVAL_FLAG_GROUP | WORK_INTERVAL_FLAG_JOINABLE | WORK_INTERVAL_TYPE_COREAUDIO;
	if (enable_telemetry) {
		create_flags |= WORK_INTERVAL_FLAG_ENABLE_TELEMETRY_DATA;
	}

	ret = work_interval_create(wi_handle, create_flags);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "work_interval_create");

	ret = work_interval_copy_port(*wi_handle, wi_port);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "work_interval_copy_port");

	*wi_instance = work_interval_instance_alloc(*wi_handle);
	T_QUIET; T_ASSERT_NE(*wi_instance, NULL, "work_interval_instance_alloc");
}

static void
join_coreaudio_work_interval(mach_port_t *wi_port, uint64_t interval_nanos)
{
	int ret = 0;

	set_realtime(pthread_self(), interval_nanos);

	ret = work_interval_join_port(*wi_port);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "work_interval_join_port");
}

static pthread_mutex_t barrier_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t barrier_cond = PTHREAD_COND_INITIALIZER;
static uint32_t barrier_count[2];
static unsigned int active_barrier_ind;
static uint32_t total_thread_count;
static uint32_t expected_cond_wakeups;

/*
 * This implementation of a barrier using pthread_cond_t is
 * intended to control the number of thread sleeps/wakeups
 * that can occur, so that the reported wakeup counts from
 * the work interval data can be validated.
 * Each call to pthread_mutex_lock can produce 0 or 1 thread
 * wakeups, and each call to pthread_cond_wait produces 0 or
 * 1 wakeups.
 */
static void
thread_barrier(void)
{
	int ret = 0;
	ret = pthread_mutex_lock(&barrier_lock);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "pthread_mutex_lock");

	barrier_count[active_barrier_ind]--;

	if (barrier_count[active_barrier_ind]) {
		unsigned int local_active_barrier_ind = active_barrier_ind;
		while (barrier_count[local_active_barrier_ind]) {
			expected_cond_wakeups++;
			ret = pthread_cond_wait(&barrier_cond, &barrier_lock);
			T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "pthread_cond_wait");
		}
	} else {
		ret = pthread_cond_broadcast(&barrier_cond);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "pthread_cond_broadcast");
		active_barrier_ind = (active_barrier_ind + 1) % 2;
		barrier_count[active_barrier_ind] = total_thread_count;
	}

	ret = pthread_mutex_unlock(&barrier_lock);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "pthread_mutex_unlock");
}

struct thread_data {
	work_interval_t wi_handle;
	mach_port_t *wi_port;
	unsigned int num_iterations;
	uint64_t interval_nanos;
};

static volatile int64_t work_sum;

/*
 * This work performed in the work interval is designed to
 * require CPU compute so that CLPC perf-controls the work
 * interval as it typically would. It is also designed such that
 * the threads agree when the work interval work is done
 * (work_sum higher than a specified threshold), so that the
 * amount of work performed will be consistent between the
 * different work interval instances.
 */
static void
contribute_to_work_sum(void)
{
	volatile unsigned int x = 0;
	do {
		for (int i = 0; i < 1000; i++) {
			x = x * x - x - 1;
		}
		x %= 10;
	} while (OSAtomicAdd64(x, &work_sum) < 10000);
}

static void *
coreaudio_workload_fn(void *arg)
{
	struct thread_data *info = (struct thread_data *)arg;

	join_coreaudio_work_interval(info->wi_port, info->interval_nanos);

	for (unsigned int i = 0; i < info->num_iterations; i++) {
		thread_barrier();
		contribute_to_work_sum();
	}

	int ret = work_interval_leave();
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "work_interval_leave");

	thread_barrier();

	return NULL;
}

static void
start_helper_threads(unsigned int num_threads, pthread_t *threads, struct thread_data *thread_datas,
    work_interval_t wi_handle, mach_port_t *wi_port, unsigned int num_iterations, uint64_t interval_nanos)
{
	int ret = 0;
	for (unsigned int i = 0; i < num_threads; i++) {
		thread_datas[i].wi_handle = wi_handle;
		thread_datas[i].wi_port = wi_port;
		thread_datas[i].num_iterations = num_iterations;
		thread_datas[i].interval_nanos = interval_nanos;
		ret = pthread_create(&threads[i], NULL, coreaudio_workload_fn, &thread_datas[i]);
		T_QUIET; T_ASSERT_POSIX_ZERO(ret, "pthread_create");
	}
}

static void
start_work_interval_instance(uint64_t interval_length_abs, work_interval_instance_t wi_instance,
    work_interval_data_t wi_data)
{
	int ret = 0;
	uint64_t start = mach_absolute_time();

	work_interval_instance_clear(wi_instance);
	work_interval_instance_set_start(wi_instance, start);
	work_interval_instance_set_deadline(wi_instance, start + interval_length_abs);

	// Sanity assertions that the work interval creation flags and interval id are as expected
	T_QUIET; T_ASSERT_EQ(wi_instance->wi_create_flags & WORK_INTERVAL_FLAG_IGNORED, 0, "ignored flag start");
	T_QUIET; T_ASSERT_EQ(wi_instance->wi_create_flags & WORK_INTERVAL_TYPE_MASK, WORK_INTERVAL_TYPE_COREAUDIO, "coreaudio start");
	T_QUIET; T_ASSERT_NE(wi_instance->wi_interval_id, 0ULL, "nonzero wi_interval_id");

	ret = work_interval_instance_start(wi_instance);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "work_interval_instance_start");

	if (wi_instance->wi_instance_id == 0ULL) {
		T_LOG("wi_instance_id is 0, which is an acceptable condition for devices running legacy CLPC");
	}

	work_interval_instance_get_telemetry_data(wi_instance, wi_data, sizeof(struct work_interval_data));
}

static uint64_t
finish_work_interval_instance(work_interval_instance_t wi_instance, work_interval_data_t wi_data)
{
	int ret = 0;
	uint64_t finish = mach_absolute_time();
	work_interval_instance_set_finish(wi_instance, finish);

	// Sanity assertions that the work interval creation flags and interval id are as expected
	T_QUIET; T_ASSERT_EQ(wi_instance->wi_create_flags & WORK_INTERVAL_FLAG_IGNORED, 0, "ignored flag");
	T_QUIET; T_ASSERT_EQ(wi_instance->wi_create_flags & WORK_INTERVAL_TYPE_MASK, WORK_INTERVAL_TYPE_COREAUDIO, "coreaudio start");
	T_QUIET; T_ASSERT_NE(wi_instance->wi_interval_id, 0ULL, "nonzero wi_interval_id");

	uint64_t remembered_start = wi_instance->wi_start;

	ret = work_interval_instance_finish(wi_instance);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "work_interval_instance_finish");

	work_interval_instance_get_telemetry_data(wi_instance, wi_data, sizeof(struct work_interval_data));

	return abs_to_nanos(finish - remembered_start);
}

static void
verify_monotonic_work_interval_data(struct work_interval_data *curr_data, struct work_interval_data *prev_data, bool supports_cpi)
{
	if (prev_data != NULL) {
		T_QUIET; T_ASSERT_GE(curr_data->wid_external_wakeups, prev_data->wid_external_wakeups, "wid_external_wakeups");
		T_QUIET; T_ASSERT_GE(curr_data->wid_total_wakeups, prev_data->wid_total_wakeups, "wid_external_wakeups");
	}
	T_QUIET; T_ASSERT_GE(curr_data->wid_user_time_mach, prev_data == NULL ? 1 : prev_data->wid_user_time_mach, "monotonic wid_user_time_mach");
	T_QUIET; T_ASSERT_GE(curr_data->wid_system_time_mach, prev_data == NULL ? 1 : prev_data->wid_system_time_mach, "monotonic wid_system_time_mach");
	if (supports_cpi) {
		T_QUIET; T_ASSERT_GE(curr_data->wid_cycles, prev_data == NULL ? 1 : prev_data->wid_cycles, "monotonic wid_cycles");
		T_QUIET; T_ASSERT_GE(curr_data->wid_instructions, prev_data == NULL ? 1 : prev_data->wid_instructions, "monotonic wid_instructions");
	}
}

static void
verify_zero_work_interval_data(struct work_interval_data *wi_data, bool supports_cpi)
{
	T_QUIET; T_ASSERT_EQ(wi_data->wid_external_wakeups, 0, "zero wid_external_wakeups");
	T_QUIET; T_ASSERT_EQ(wi_data->wid_total_wakeups, 0, "zero wid_total_wakeups");
	T_QUIET; T_ASSERT_EQ(wi_data->wid_user_time_mach, 0ULL, "zero wid_user_time_mach");
	T_QUIET; T_ASSERT_EQ(wi_data->wid_system_time_mach, 0ULL, "zero wid_system_time_mach");
	if (supports_cpi) {
		T_QUIET; T_ASSERT_EQ(wi_data->wid_cycles, 0ULL, "zero wid_cycles");
		T_QUIET; T_ASSERT_EQ(wi_data->wid_instructions, 0ULL, "zero wid_instructions");
	}
}

static void
run_work_interval_data_test(unsigned int num_iterations, uint64_t interval_nanos, unsigned int thread_count,
    bool enable_telemetry, uint32_t flags)
{
	T_SETUPBEGIN;

	int ret = 0;

	int supports_cpi = 0;
	size_t supports_cpi_size = sizeof(supports_cpi);
	ret = sysctlbyname("kern.monotonic.supported", &supports_cpi, &supports_cpi_size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "sysctl kern.monotonic.supported");

	work_interval_t wi_handle = NULL;
	work_interval_instance_t wi_instance = NULL;
	mach_port_t wi_port = MACH_PORT_NULL;

	create_coreaudio_work_interval(&wi_handle, &wi_instance, &wi_port, enable_telemetry, flags);
	join_coreaudio_work_interval(&wi_port, interval_nanos);

	total_thread_count = thread_count;
	expected_cond_wakeups = 0;
	unsigned int num_helper_threads = thread_count - 1;
	active_barrier_ind = 0;
	barrier_count[active_barrier_ind] = thread_count;
	pthread_t wi_threads[num_helper_threads];
	struct thread_data wi_thread_datas[num_helper_threads];

	start_helper_threads(num_helper_threads, wi_threads, wi_thread_datas, wi_handle, &wi_port, num_iterations, interval_nanos);

	T_SETUPEND;

	uint64_t interval_length_abs = nanos_to_abs(interval_nanos);
	uint64_t duration_sum = 0;
	struct work_interval_data start_data = {0};
	struct work_interval_data finish_data = {0};

	for (unsigned int i = 0; i < num_iterations; i++) {
		work_sum = 0;

		usleep(1000);

		start_work_interval_instance(interval_length_abs, wi_instance, &start_data);
		if (i == 0 && enable_telemetry) {
			verify_monotonic_work_interval_data(&start_data, NULL, supports_cpi);
		} else if (!enable_telemetry) {
			verify_zero_work_interval_data(&start_data, supports_cpi);
		}

		thread_barrier();
		contribute_to_work_sum();

		duration_sum += finish_work_interval_instance(wi_instance, &finish_data);
		if (enable_telemetry) {
			verify_monotonic_work_interval_data(&finish_data, &start_data, supports_cpi);
		} else {
			verify_zero_work_interval_data(&finish_data, supports_cpi);
		}
	}

	ret = work_interval_leave();
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "work_interval_leave");
	thread_barrier();

	if (enable_telemetry) {
		T_ASSERT_TRUE(true, "Overall wid_external_wakeups: %u\n", finish_data.wid_external_wakeups);
		// Only the wakeups from usleep() are guaranteed to occur
		T_ASSERT_GE(finish_data.wid_total_wakeups, num_iterations, "wid_total_wakeups at least accounts for the usleep() wakeups");
	}
	T_ASSERT_TRUE(true, "Workload survived %u iterations without failures!!! Avg. work interval duration was %llu ns out of a requested %llu ns", num_iterations, duration_sum / num_iterations, interval_nanos);
}

static const unsigned int DEFAULT_ITERS = 1000;
static const uint64_t DEFAULT_INTERVAL_NS = 15000000; // 15 ms
static const uint64_t DEFAULT_THREAD_COUNT = 3;

T_DECL(work_interval_rt_coreaudio_quality_telemetry_data, "receiving accurate telemetry data as a coreaudio work interval",
    T_META_ASROOT(YES), XNU_T_META_SOC_SPECIFIC, T_META_ENABLED(TARGET_CPU_ARM64))
{
	run_work_interval_data_test(
		DEFAULT_ITERS,
		DEFAULT_INTERVAL_NS,
		DEFAULT_THREAD_COUNT,
		true, // enable_telemetry
		0); // no added flags
}

T_DECL(work_interval_rt_coreaudio_telemetry_disabled, "reading telemetry data should see all zeroes if it isn't enabled",
    T_META_ASROOT(YES), XNU_T_META_SOC_SPECIFIC, T_META_ENABLED(TARGET_CPU_ARM64))
{
	run_work_interval_data_test(
		DEFAULT_ITERS,
		DEFAULT_INTERVAL_NS,
		DEFAULT_THREAD_COUNT,
		false, // enable_telemetry
		0); // no added flags
}

T_DECL(work_interval_rt_coreaudio_telemetry_data_many_threads, "work interval telemetry data works with many joined threads",
    T_META_ASROOT(YES), XNU_T_META_SOC_SPECIFIC, T_META_ENABLED(TARGET_CPU_ARM64))
{
	run_work_interval_data_test(
		DEFAULT_ITERS,
		DEFAULT_INTERVAL_NS,
		20, // threads
		true, // enable_telemetry
		0); // no added flags
}

T_DECL(work_interval_rt_coreaudio_telemetry_supported_with_other_flags, "telemetry supported when the other creation flags used by coreaudio are set",
    T_META_ASROOT(YES), XNU_T_META_SOC_SPECIFIC, T_META_ENABLED(TARGET_CPU_ARM64))
{
	T_LOG("Coreaudio work interval with auto-join and deferred finish enabled");
	run_work_interval_data_test(
		DEFAULT_ITERS,
		DEFAULT_INTERVAL_NS,
		DEFAULT_THREAD_COUNT, // threads
		true, // enable_telemetry
		WORK_INTERVAL_FLAG_ENABLE_AUTO_JOIN | WORK_INTERVAL_FLAG_ENABLE_DEFERRED_FINISH);

	T_LOG("Coreaudio work interval with auto-join, deferred finish, and unrestricted flags enabled");
	run_work_interval_data_test(
		DEFAULT_ITERS,
		DEFAULT_INTERVAL_NS,
		DEFAULT_THREAD_COUNT, // threads
		true, // enable_telemetry
		WORK_INTERVAL_FLAG_ENABLE_AUTO_JOIN | WORK_INTERVAL_FLAG_ENABLE_DEFERRED_FINISH | WORK_INTERVAL_FLAG_UNRESTRICTED);
}
