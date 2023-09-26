#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <spawn.h>
#include <string.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <TargetConditionals.h>
#include <sys/work_interval.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <stdatomic.h>
#include <time.h>

#include <darwintest.h>
#include <darwintest_utils.h>
#include <perfdata/perfdata.h>

T_GLOBAL_META(T_META_NAMESPACE("xnu.scheduler"),
    T_META_RADAR_COMPONENT_NAME("xnu"),
    T_META_RADAR_COMPONENT_VERSION("scheduler"),
    T_META_TAG_PERF);

/* Code and logic taken from Daniel Chimene's yield-aggressor.c test (rdar://47327537) */

static const size_t MAX_PDJ_PATH_LEN = 256;

static void
sched_yield_loop(uint64_t iterations)
{
	for (uint64_t i = 0; i < iterations; i++) {
		sched_yield();
	}
}

static void
swtch_loop(uint64_t iterations)
{
	for (uint64_t i = 0; i < iterations; i++) {
		swtch();
	}
}

static void
swtch_pri_loop(uint64_t iterations)
{
	for (uint64_t i = 0; i < iterations; i++) {
		swtch_pri(0);
	}
}

static void
thread_switch_loop(uint64_t iterations)
{
	for (uint64_t i = 0; i < iterations; i++) {
		thread_switch(MACH_PORT_NULL, SWITCH_OPTION_NONE, MACH_MSG_TIMEOUT_NONE);
	}
}

static void
thread_switch_wait_loop(uint64_t iterations)
{
	for (uint64_t i = 0; i < iterations; i++) {
		thread_switch(MACH_PORT_NULL, SWITCH_OPTION_WAIT, MACH_MSG_TIMEOUT_NONE);
	}
}

static void
thread_switch_depress_loop(uint64_t iterations)
{
	for (uint64_t i = 0; i < iterations; i++) {
		thread_switch(MACH_PORT_NULL, SWITCH_OPTION_DEPRESS, MACH_MSG_TIMEOUT_NONE);
	}
}

typedef enum yield_type {
	SCHED_YIELD = 0,
	SWTCH = 1,
	SWTCH_PRI = 2,
	THREAD_SWITCH = 3,
	THREAD_SWITCH_WAIT = 4,
	THREAD_SWITCH_DEPRESS = 5
} yield_type_t;

static const int NUM_YIELD_TYPES = 6;

static char* name_table[NUM_YIELD_TYPES] = {
	[SCHED_YIELD]           = "sched_yield",
	[SWTCH]                 = "swtch",
	[SWTCH_PRI]             = "swtch_pri",
	[THREAD_SWITCH]         = "thread_switch(none)",
	[THREAD_SWITCH_WAIT]    = "thread_switch(wait)",
	[THREAD_SWITCH_DEPRESS] = "thread_switch(depress)",
};

static void (*fn_table[NUM_YIELD_TYPES])(uint64_t) = {
	[SCHED_YIELD]           = sched_yield_loop,
	[SWTCH]                 = swtch_loop,
	[SWTCH_PRI]             = swtch_pri_loop,
	[THREAD_SWITCH]         = thread_switch_loop,
	[THREAD_SWITCH_WAIT]    = thread_switch_wait_loop,
	[THREAD_SWITCH_DEPRESS] = thread_switch_depress_loop,
};

static semaphore_t ready_sem, go_sem;
static unsigned int num_iterations, num_threads;
static _Atomic unsigned int done_threads;
static yield_type_t curr_yield_type;

static void *
thread_fn(__unused void *arg)
{
	kern_return_t kr;

	kr = semaphore_wait_signal(go_sem, ready_sem);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "semaphore_wait_signal");

	fn_table[curr_yield_type](num_iterations);

	if (atomic_fetch_add(&done_threads, 1) == num_threads - 1) {
		kr = semaphore_wait_signal(go_sem, ready_sem);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "semaphore_wait_signal");
	} else {
		kr = semaphore_wait(go_sem);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "semaphore_wait");
	}
	return NULL;
}

static void
start_threads(pthread_t *threads, void *(*start_routine)(void *), int priority)
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

struct cpu_time {
	natural_t sys;
	natural_t user;
	natural_t idle;
};

static void
record_cpu_time(struct cpu_time *cpu_time)
{
	host_cpu_load_info_data_t load;
	kern_return_t kr;
	mach_msg_type_number_t count = HOST_CPU_LOAD_INFO_COUNT;

	kr = host_statistics(mach_host_self(), HOST_CPU_LOAD_INFO, (int *)&load, &count);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "host_statistics");

	cpu_time->sys = load.cpu_ticks[CPU_STATE_SYSTEM];
	cpu_time->user = load.cpu_ticks[CPU_STATE_USER] + load.cpu_ticks[CPU_STATE_NICE];
	cpu_time->idle = load.cpu_ticks[CPU_STATE_IDLE];
}

static void
write_independent_variables(pdwriter_t writer)
{
	pdwriter_record_variable_str(writer, "yield_variant", name_table[curr_yield_type]);
	pdwriter_record_variable_dbl(writer, "num_iterations", num_iterations);
	pdwriter_record_variable_dbl(writer, "num_threads", num_threads);
}

static const double MS_PER_CPU_TICK = 10.0;

static void
write_time_values(pdwriter_t writer, struct cpu_time *delta_times, uint64_t elapsed_usecs, double idle_ratio)
{
	pdwriter_new_value(writer, "system_time", pdunit_milliseconds_cpu, delta_times->sys * MS_PER_CPU_TICK);
	write_independent_variables(writer);

	pdwriter_new_value(writer, "user_time", pdunit_milliseconds_cpu, delta_times->user * MS_PER_CPU_TICK);
	write_independent_variables(writer);

	pdwriter_new_value(writer, "idle_time", pdunit_milliseconds_cpu, delta_times->idle * MS_PER_CPU_TICK);
	write_independent_variables(writer);

	pdwriter_new_value(writer, "wall_clock_time", pdunit_microseconds, elapsed_usecs);
	write_independent_variables(writer);

	/* Main metric of note, with a threshold in perfmeta to guard against regression */
	pdwriter_new_value(writer, "idle_time_ratio", pdunit_percent_cpus, idle_ratio);
	write_independent_variables(writer);
}

static void
run_yielding_test(yield_type_t yield_type, unsigned int num_iters, unsigned int thread_count,
    int thread_pri, pdwriter_t writer)
{
	T_SETUPBEGIN;

	T_LOG("===== Yield Variety: %s", name_table[yield_type]);

	kern_return_t kr;

	num_iterations = num_iters;
	num_threads = thread_count;
	curr_yield_type = yield_type;
	done_threads = 0;

	kr = semaphore_create(mach_task_self(), &ready_sem, SYNC_POLICY_FIFO, 0);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "semaphore_create");
	kr = semaphore_create(mach_task_self(), &go_sem, SYNC_POLICY_FIFO, 0);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "semaphore_create");

	pthread_t threads[num_threads];
	start_threads(threads, &thread_fn, thread_pri);

	for (uint32_t i = 0; i < num_threads; i++) {
		kr = semaphore_wait(ready_sem);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "semaphore_wait");
	}

	/* Wait 100ms for the system to settle down */
	usleep(100000);

	T_SETUPEND;

	struct cpu_time start_times, finish_times, delta_times;
	uint64_t before_nsec, after_nsec;

	record_cpu_time(&start_times);
	before_nsec = clock_gettime_nsec_np(CLOCK_REALTIME);

	/* Signal threads to begin yielding "work" */
	kr = semaphore_signal_all(go_sem);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "semaphore_signal_all");

	kr = semaphore_wait(ready_sem);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "semaphore_wait");

	/* Capture cpu stats after yielding "work" has finished */
	after_nsec = clock_gettime_nsec_np(CLOCK_REALTIME);
	record_cpu_time(&finish_times);

	uint64_t elapsed_usecs = (after_nsec - before_nsec) / 1000;
	T_LOG("All %u threads finished yielding %u times each", num_threads, num_iterations);
	T_LOG("Elapsed Runtime: %f seconds", ((double) elapsed_usecs) / USEC_PER_SEC);

	delta_times.sys = finish_times.sys - start_times.sys;
	delta_times.user = finish_times.user - start_times.user;
	delta_times.idle = finish_times.idle - start_times.idle;
	T_LOG("System CPU ticks: %d", delta_times.sys);
	T_LOG("User CPU ticks: %d", delta_times.user);
	T_LOG("Idle CPU ticks: %d", delta_times.idle);

	natural_t total_ticks = delta_times.sys + delta_times.user + delta_times.idle;
	T_QUIET; T_ASSERT_GT(total_ticks, 0, "CPU load stats failed to update, likely due to host_statistics() rate limit");

	double cpu_idle_ratio = delta_times.idle * 1.0 / total_ticks;
	T_LOG("*** Ratio of Idle CPU time: %f\n\n", cpu_idle_ratio);

	write_time_values(writer, &delta_times, elapsed_usecs, cpu_idle_ratio);
}

static const int DEFAULT_THREAD_PRI = 31;
static const int DEFAULT_NUM_ITERS = 100000;

#define KERNEL_BOOTARGS_MAX_SIZE 1024
static char kernel_bootargs[KERNEL_BOOTARGS_MAX_SIZE];

T_DECL(yield_aggressor,
    "Ensure that CPUs do not go idle when there are many threads all yielding "
    "in a loop (for different varieties of yield)",
    /* Required to get around the rate limit for host_statistics() */
    T_META_BOOTARGS_SET("amfi_get_out_of_my_way=1"),
    T_META_ASROOT(true))
{
	/* Warn if amfi_get_out_of_my_way is not set and fail later on if we actually run into the rate limit */
	size_t kernel_bootargs_size = sizeof(kernel_bootargs);
	int rv = sysctlbyname("kern.bootargs", kernel_bootargs, &kernel_bootargs_size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "kern.bootargs");
	if (strstr(kernel_bootargs, "amfi_get_out_of_my_way=1") == NULL) {
		T_LOG("WARNING: amfi_get_out_of_my_way=1 boot-arg is missing, required to reliably capture CPU load data");
	}

	char pdj_path[MAX_PDJ_PATH_LEN];
	pdwriter_t writer = pdwriter_open_tmp("xnu", "scheduler.yield_aggressor", 0, 0, pdj_path, MAX_PDJ_PATH_LEN);
	T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(writer, "pdwriter_open_tmp");

	/*
	 * Thread count is NCPU * 3 in order to ensure that there are enough yielding threads
	 * to keep all of the cores busy context-switching between them. NCPU * 1 threads would
	 * not be sufficient to guarantee this, because a core temporarily keeps two threads
	 * off of the run-queues at a time while performing a context-switch (rather than only
	 * the one thread it is running during normal execution). Lastly, we choose NCPU * 3
	 * rather than NCPU * 2 because doing so empirically reduces the variance of values
	 * betweens runs.
	 */
	unsigned int thread_count = (unsigned int) dt_ncpu() * 3;

	for (yield_type_t yield_type = SCHED_YIELD; yield_type <= THREAD_SWITCH_DEPRESS; yield_type++) {
		run_yielding_test(yield_type, DEFAULT_NUM_ITERS, thread_count, DEFAULT_THREAD_PRI, writer);
	}

	T_LOG("Perfdata file written to: %s", pdj_path);
	pdwriter_close(writer);

	T_END;
}
