#include <darwintest.h>

#include <assert.h>
#include <mach/clock_types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <err.h>
#include <sys/time.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <pthread.h>
#include <sys/sysctl.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <stdbool.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/resource_private.h>
#include <os/atomic_private.h>
#include <libproc.h>
#include <TargetConditionals.h>

#if __has_include(<mach/mach_time_private.h>)
#include <mach/mach_time_private.h>
#else
kern_return_t           mach_get_times(uint64_t* absolute_time,
    uint64_t* continuous_time,
    struct timespec *tp);
#endif

/*
 * This test program creates up to 8 worker threads performing
 * mixed workloads of system calls (which contribute to both
 * user and system time), as well as spins in userspace (which
 * only contribute to user time).
 *
 * setitimer(2) is used to program timers that fire signals
 * after various thresholds. The signal handler detects
 * which thread the signal was delivered on by matching the
 * stack pointer to ranges for each thread.
 *
 * After the test scenario is complete, the distribution of
 * threads which received interrupts is evaluated to match
 * expected heuristics.
 */

T_GLOBAL_META(
	T_META_RUN_CONCURRENTLY(false),
	T_META_CHECK_LEAKS(false),
	T_META_ALL_VALID_ARCHS(true),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("scheduler"),
	T_META_OWNER("chimene"),
	T_META_ENABLED(TARGET_OS_OSX)
	);

static void *stat_thread(void *arg);
static void *statfs_thread(void *arg);

static void alrm_handler(int, struct __siginfo *, void *);

static semaphore_t gMainWaitForWorkers;
static semaphore_t gWorkersStart;

static pthread_mutex_t gShouldExitMutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  gShouldExitCondition = PTHREAD_COND_INITIALIZER;

static _Atomic bool gShouldExit = false;

static const uint32_t max_threads = 9;

static struct threadentry {
	pthread_t thread;
	uint64_t tid;
	void* stack_addr;
	size_t stack_size;
	bool expect_cpu_usage;
	uint32_t alrm_count;
	uint32_t vtalrm_count;
	uint32_t prof_count;
	uint32_t xcpu_count;
	struct thsc_time_cpi self_stats;
} __attribute__((aligned(128))) gThreadList[max_threads];

static uint32_t nworkers;
static uint32_t nthreads;

static double offcore_time_percent_threshold = 75.0;

static bool is_rosetta = false;

static mach_timebase_info_data_t timebase_info;

static uint64_t
abs_to_nanos(uint64_t abs)
{
	return abs * timebase_info.numer / timebase_info.denom;
}

/* Some statistics APIs return host abstime instead of Rosetta-translated abstime */
static uint64_t
abs_to_nanos_host(uint64_t abstime)
{
	if (is_rosetta) {
		return abstime * 125 / 3;
	} else {
		return abs_to_nanos(abstime);
	}
}

static int
processIsTranslated(void)
{
	int ret = 0;
	size_t size = sizeof(ret);
	if (sysctlbyname("sysctl.proc_translated", &ret, &size, NULL, 0) == -1) {
		if (errno == ENOENT) {
			return 0;
		} else {
			return -1;
		}
	}
	return ret;
}

static void
fill_thread_stats(uint32_t i)
{
	struct threadentry *entry = &gThreadList[i];

	int rv = thread_selfcounts(THSC_TIME_CPI, &entry->self_stats, sizeof(entry->self_stats));
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "thread_selfcounts(THSC_TIME_CPI)");
}

T_DECL(setitimer,
    "Test various setitimer delivered signals to CPU-burning threads")
{
	int rv;
	kern_return_t kr;
	uint32_t ncpu;
	size_t ncpu_size = sizeof(ncpu);

	struct sched_param self_param = {.sched_priority = 47};

	rv = pthread_setschedparam(pthread_self(), SCHED_FIFO, &self_param);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "pthread_setschedparam");

	kr = mach_timebase_info(&timebase_info);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_timebase_info");

	is_rosetta = processIsTranslated();

	rv = sysctlbyname("hw.ncpu", &ncpu, &ncpu_size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "sysctlbyname(hw.ncpu)");

	if (ncpu < 2) {
		T_SKIP("%d CPUs not supported for test, returning success", ncpu);
	}

	nworkers = MIN(max_threads - 1, ncpu);
	nthreads = nworkers + 1;

	T_LOG("rosetta = %d\n", is_rosetta);
	T_LOG("hw.ncpu = %d\n", ncpu);
	T_LOG("nworkers = %d\n", nworkers);
	T_LOG("nthreads = %d\n", nthreads);

	kr = semaphore_create(mach_task_self(), &gMainWaitForWorkers, SYNC_POLICY_FIFO, 0);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "semaphore_create()");

	kr = semaphore_create(mach_task_self(), &gWorkersStart, SYNC_POLICY_FIFO, 0);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "semaphore_create()");

	pthread_attr_t attr;

	rv = pthread_attr_init(&attr);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "pthread_attr_init");

	struct sched_param child_param = {.sched_priority = 37};

	rv = pthread_attr_setschedparam(&attr, &child_param);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "pthread_attr_set_qos_class_np");

	for (uint32_t i = 0; i < nthreads; i++) {
		if (i == 0) {
			gThreadList[i].thread = pthread_self();
		} else {
			rv = pthread_create(&gThreadList[i].thread, &attr,
			    i % 2 ? stat_thread : statfs_thread,
			    (void *)(uintptr_t)i);
			T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "pthread_create");
			gThreadList[i].expect_cpu_usage = i % 2 == 0 ? true : false;
		}

		rv = pthread_threadid_np(gThreadList[i].thread, &gThreadList[i].tid);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "pthread_threadid_np");

		gThreadList[i].stack_addr = pthread_get_stackaddr_np(gThreadList[i].thread);
		gThreadList[i].stack_size = pthread_get_stacksize_np(gThreadList[i].thread);
	}

	rv = pthread_attr_destroy(&attr);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "pthread_attr_destroy");

	for (uint32_t i = 1; i < nthreads; i++) {
		kr = semaphore_wait(gMainWaitForWorkers);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "semaphore_wait()");
	}

	for (uint32_t i = 0; i < nthreads; i++) {
		T_LOG("Thread %p (0x%llx) checked in, stack %p/%p\n",
		    (void*)gThreadList[i].thread,
		    gThreadList[i].tid,
		    gThreadList[i].stack_addr,
		    (void *)gThreadList[i].stack_size);
	}

	sigset_t sigmk;
	sigemptyset(&sigmk);

	struct sigaction sigact = {
		.sa_sigaction = alrm_handler,
		.sa_mask = sigmk,
		.sa_flags = SA_SIGINFO,
	};

	rv = sigaction(SIGALRM, &sigact, NULL);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "sigaction(SIGALRM)");

	rv = sigaction(SIGVTALRM, &sigact, NULL);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "sigaction(SIGVTALRM)");

	rv = sigaction(SIGPROF, &sigact, NULL);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "sigaction(SIGPROF)");

	rv = sigaction(SIGXCPU, &sigact, NULL);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "sigaction(SIGXCPU)");

	struct itimerval itime = {
		.it_interval.tv_sec = 0,
		.it_interval.tv_usec = 10000,
		.it_value.tv_sec = 0,
		.it_value.tv_usec = 10,  /* immediately */
	};

	rv = setitimer(ITIMER_REAL, &itime, NULL);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "setitimer(ITIMER_REAL)");

	rv = setitimer(ITIMER_VIRTUAL, &itime, NULL);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "setitimer(ITIMER_REAL)");

	rv = setitimer(ITIMER_PROF, &itime, NULL);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "setitimer(ITIMER_REAL)");

	struct rlimit rlim = {};

	rv = getrlimit(RLIMIT_CPU, &rlim);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "getrlimit(RLIMIT_CPU)");

	rlim.rlim_cur = 1;
	rv = setrlimit(RLIMIT_CPU, &rlim);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "setrlimit(RLIMIT_CPU)");

	rv = pthread_mutex_lock(&gShouldExitMutex);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "pthread_mutex_lock(&gShouldExitMutex)");

	kr = semaphore_signal_all(gWorkersStart);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "semaphore_signal_all()");

	struct timespec timenow = {};
	uint64_t time_start;

	kr = mach_get_times(&time_start, NULL, &timenow);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_get_times()");

	struct timespec timeout = {
		.tv_sec = timenow.tv_sec + 10,
		.tv_nsec = timenow.tv_nsec,
	};

	uint64_t time_end = 0;

	do {
		assert(os_atomic_load(&gShouldExit, relaxed) == false);

		rv = pthread_cond_timedwait(&gShouldExitCondition, &gShouldExitMutex, &timeout);
		if (rv == ETIMEDOUT) {
			os_atomic_store(&gShouldExit, true, relaxed);

			time_end = mach_absolute_time();

			struct itimerval itime_stop = {
				.it_interval.tv_sec = 0,
				.it_interval.tv_usec = 0,
				.it_value.tv_sec = 0,
				.it_value.tv_usec = 0,  /* stop immediately */
			};

			rv = setitimer(ITIMER_REAL, &itime_stop, NULL);
			T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "setitimer(ITIMER_REAL)");

			rv = setitimer(ITIMER_VIRTUAL, &itime_stop, NULL);
			T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "setitimer(ITIMER_VIRTUAL)");

			rv = setitimer(ITIMER_PROF, &itime_stop, NULL);
			T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "setitimer(ITIMER_PROF)");

			break;
		} else {
			T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "pthread_cond_timedwait(&gShouldExitCondition, ...)");
		}
	} while (true);

	rv = pthread_mutex_unlock(&gShouldExitMutex);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "pthread_mutex_unlock(&gShouldExitMutex)");

	for (uint32_t i = 1; i < nthreads; i++) {
		rv = pthread_join(gThreadList[i].thread, NULL);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "pthread_join");
	}

	uint64_t test_duration = time_end - time_start;
	uint64_t test_duration_ns = abs_to_nanos(test_duration);

	double elapsed_secs = (double) test_duration_ns / (uint64_t)NSEC_PER_SEC;

	T_LOG("test duration %3.3f seconds\n", elapsed_secs);

	fill_thread_stats(0);

	struct rusage_info_v6 ru = {};
	rv = proc_pid_rusage(getpid(), RUSAGE_INFO_V6, (rusage_info_t *)&ru);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "proc_pid_rusage");

	uint64_t total_user_time_ns = abs_to_nanos_host(ru.ri_user_time);
	double total_user_time_s = (double)total_user_time_ns / (uint64_t)NSEC_PER_SEC;

	uint64_t total_system_time_ns = abs_to_nanos_host(ru.ri_system_time);
	double total_system_time_s = (double)total_system_time_ns / (uint64_t)NSEC_PER_SEC;

	uint64_t total_time_ns = (total_user_time_ns + total_system_time_ns);
	double total_time_s = (double)total_time_ns / (uint64_t)NSEC_PER_SEC;

	uint64_t total_runnable_time_ns = abs_to_nanos_host(ru.ri_runnable_time);
	double total_runnable_time_s = (double)total_runnable_time_ns / (uint64_t)NSEC_PER_SEC;

	uint64_t total_pending_time_ns = total_runnable_time_ns - (total_time_ns);
	double total_pending_time_s = (double)total_pending_time_ns / (uint64_t)NSEC_PER_SEC;

	uint64_t total_p_time_ns = abs_to_nanos_host(ru.ri_user_ptime + ru.ri_system_ptime);
	double total_p_time_s = (double)total_p_time_ns / (uint64_t)NSEC_PER_SEC;

	T_LOG("total usage: time: %3.3f user: %3.3f kernel: %3.3f runnable: %3.3f pending: %3.3f pcore: %3.3f\n",
	    total_time_s, total_user_time_s, total_system_time_s,
	    total_runnable_time_s, total_pending_time_s,
	    total_p_time_s);

	/*
	 * "Good" data looks like:
	 *
	 * total usage: time: 77.696 user: 16.570 kernel: 61.126 runnable: 79.951 pending: 2.255 pcore: 72.719
	 * Thread        ALRM VTALRM   PROF   XCPU      inst        cycle               user                  kernel          offcore  type
	 * 0x16f78f000      0    251    811      0  27680301973  28913501188   3706622958 (  38.14%)   6012631083 (  61.86%)    2.81%  statfs
	 * 0x16f81b000      0      2    889      0  27962710058  28780576123    439297291 (   4.53%)   9259942583 (  95.47%)    3.01%  stat
	 * 0x16f8a7000      0    251    836      0  27558331077  28889228535   3699010000 (  38.08%)   6016015083 (  61.92%)    2.85%  statfs
	 * 0x16f933000      0      0    939      0  28078084696  28880195679    443067500 (   4.56%)   9269807666 (  95.44%)    2.87%  stat
	 * 0x16f9bf000      0    283    874      0  27691851016  28969873070   3710916750 (  38.16%)   6012783541 (  61.84%)    2.76%  statfs
	 * 0x16fa4b000      0      2    908      1  27945063330  28769971396    438583000 (   4.53%)   9252694291 (  95.47%)    3.09%  stat
	 * 0x16fad7000      0    262    889      0  27328496429  28772748055   3689245375 (  38.03%)   6011061458 (  61.97%)    3.00%  statfs
	 * 0x16fb63000      0      0    914      0  27942195343  28757254100    439690166 (   4.53%)   9256659500 (  95.47%)    3.04%  stat
	 * 0x1fe2bb400   1001      0      3      0     72144372    102339334      3532125 (   9.35%)     34249208 (  90.65%)   99.62%  main
	 */
	uint32_t total_alrm = 0;
	uint32_t total_vtalrm = 0;
	uint32_t total_prof = 0;
	uint32_t total_xcpu = 0;
	uint32_t total_vtalrm_in_cpubound = 0;

	uint32_t total_threads_not_finding_cpus = 0;

	T_LOG("Thread         ALRM VTALRM   PROF   XCPU      "
	    "inst        cycle               user                  kernel          "
	    "offcore type\n");

	for (uint32_t i = 0; i < nthreads; i++) {
		uint64_t user_time = abs_to_nanos_host(gThreadList[i].self_stats.ttci_user_time_mach);
		uint64_t system_time = abs_to_nanos_host(gThreadList[i].self_stats.ttci_system_time_mach);


		uint64_t total_time = user_time + system_time;

		double percentage_user = (double)user_time / (double) total_time * 100;
		double percentage_system = (double)system_time / (double) total_time * 100;
		double percentage_not_running = (double)(test_duration_ns - total_time) / (double) test_duration_ns * 100;

		char* thread_type_str = "";
		char* warning_str = "";

		if (i == 0) {
			thread_type_str = "main ";
		} else {
			thread_type_str = i % 2 ? "stat   " : "statfs ";

			if (percentage_not_running > offcore_time_percent_threshold) {
				total_threads_not_finding_cpus++;
				warning_str = "** too much offcore time **";
			}
		}

		T_LOG("0x%010llx %6d %6d %6d %6d %12lld %12lld %12lld (%7.2f%%) %12lld (%7.2f%%) %7.2f%% %s%s\n",
		    gThreadList[i].tid,
		    gThreadList[i].alrm_count,
		    gThreadList[i].vtalrm_count,
		    gThreadList[i].prof_count,
		    gThreadList[i].xcpu_count,
		    gThreadList[i].self_stats.ttci_instructions,
		    gThreadList[i].self_stats.ttci_cycles,
		    user_time, percentage_user,
		    system_time, percentage_system,
		    percentage_not_running,
		    thread_type_str, warning_str);

		total_alrm += gThreadList[i].alrm_count;
		total_vtalrm += gThreadList[i].vtalrm_count;
		total_prof += gThreadList[i].prof_count;
		total_xcpu += gThreadList[i].xcpu_count;

		if (gThreadList[i].expect_cpu_usage) {
			total_vtalrm_in_cpubound += gThreadList[i].vtalrm_count;
		}
	}

	/*
	 * We expect all SIGALRM to go to the main thread, because it is the
	 * first thread in the process with the signal unmasked, and we
	 * never expect the signal handler itself to take >10ms
	 *
	 * This can happen if the main thread is preempted for the entire 10ms duration, though.
	 * Being high priority, it shouldn't be delayed for more than 10ms too often.
	 * Allow up to 10% to deliver to other threads.
	 */
	if ((double)gThreadList[0].alrm_count * 100 / total_alrm < 90.0) {
		T_FAIL("SIGALRM delivered to non-main thread more than 10%% of the time (%d of %d)",
		    gThreadList[0].alrm_count,
		    total_alrm);
	}

	/* We expect all worker threads to find CPUs of their own for most of the test */
	if (total_threads_not_finding_cpus != 0) {
		T_FAIL("%d worker threads spent more than %2.0f%% of time off-core",
		    total_threads_not_finding_cpus, offcore_time_percent_threshold);
	}

	/*
	 * SIGVTALRM is delivered based on user time, and we expect the busy
	 * threads to have an advantage and account for 80% (non-scientific) of events,
	 * since the other threads will spend more time in kernel mode.
	 */
	if (total_vtalrm_in_cpubound * 100 / total_vtalrm < 80) {
		T_FAIL("SIGVTALRM delivered to threads without extra userspace spin (only %d of %d)",
		    total_vtalrm_in_cpubound, total_vtalrm);
	}

	/*
	 * SIGPROF is delivered based on user+system time, and we expect it to be distributed
	 * among non-blocked threads (so not the main thread, which only handles SIGALRM).
	 */
	if (gThreadList[0].prof_count * 100 / total_prof > 1) {
		T_FAIL("SIGPROF delivered to main thread more than 1%% (%d of %d)",
		    gThreadList[0].prof_count,
		    total_prof);
	}

	/*
	 * SIGXCPU should be delivered exactly once.
	 */
	if (total_xcpu == 0) {
		T_FAIL("SIGXCPU delivered %d times (expected at least once)", total_xcpu);
	}
}

static void *
stat_thread(void *arg)
{
	kern_return_t kr;
	int rv;

	/* This wait can be aborted by one of the signals, so we make sure to wait for the first iteration of main */
	kr = semaphore_wait_signal(gWorkersStart, gMainWaitForWorkers);
	if (kr != KERN_ABORTED) {
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "semaphore_wait_signal()");
	}

	rv = pthread_mutex_lock(&gShouldExitMutex);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "pthread_mutex_lock(&gShouldExitMutex)");
	rv = pthread_mutex_unlock(&gShouldExitMutex);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "pthread_mutex_unlock(&gShouldExitMutex)");

	do {
		struct stat sb;

		rv = stat("/", &sb);
		if (rv != 0) {
			T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "stat");
		}
	} while (os_atomic_load(&gShouldExit, relaxed) == false);

	fill_thread_stats((uint32_t)(uintptr_t)arg);

	return NULL;
}

static void *
statfs_thread(void *arg)
{
	kern_return_t kr;
	uint64_t previous_spin_timestamp;
	int iteration = 0;
	int rv;

	/* This wait can be aborted by one of the signals, so we make sure to wait for the first iteration of main */
	kr = semaphore_wait_signal(gWorkersStart, gMainWaitForWorkers);
	if (kr != KERN_ABORTED) {
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "semaphore_wait_signal()");
	}

	rv = pthread_mutex_lock(&gShouldExitMutex);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "pthread_mutex_lock(&gShouldExitMutex)");
	rv = pthread_mutex_unlock(&gShouldExitMutex);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "pthread_mutex_unlock(&gShouldExitMutex)");

	previous_spin_timestamp = mach_absolute_time();

	do {
		struct statfs sf;

		/*
		 * Every so many system calls, inject a spin in userspace
		 * proportional to how much time was spent performing the
		 * system calls.
		 */
#define SYSCALL_ITERATIONS_BETWEEN_SPINS (10000)
		if (++iteration % SYSCALL_ITERATIONS_BETWEEN_SPINS == 0) {
			uint64_t now = mach_absolute_time();
			uint64_t spin_deadline = now + (now - previous_spin_timestamp) / 2;

			while (mach_absolute_time() < spin_deadline) {
				;
			}

			previous_spin_timestamp = mach_absolute_time();
		}

		rv = statfs("/", &sf);
		if (rv != 0) {
			T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "statfs");
		}
	} while (os_atomic_load(&gShouldExit, relaxed) == false);

	fill_thread_stats((uint32_t)(uintptr_t)arg);

	return NULL;
}

static void
alrm_handler(int signum, struct __siginfo *info __unused, void *uap)
{
	ucontext_t *context = (ucontext_t *)uap;
	struct threadentry *entry = NULL;
	void *sp;

#if defined(__arm64__)
	sp = (void *)__darwin_arm_thread_state64_get_sp((context->uc_mcontext)->__ss);
#elif defined(__i386__)
	sp = (void *)(context->uc_mcontext)->__ss.__esp;
#elif defined(__x86_64__)
	sp = (void *)(context->uc_mcontext)->__ss.__rsp;
#else
#error Unrecognized architecture
#endif

	for (uint32_t i = 0; i < nworkers + 1; i++) {
		struct threadentry *t = &gThreadList[i];
		if (((uintptr_t)sp >= ((uintptr_t)t->stack_addr - t->stack_size) &&
		    ((uintptr_t)sp < (uintptr_t)t->stack_addr))) {
			entry = t;
			break;
		}
	}

	if (entry == NULL) {
		T_ASSERT_FAIL("Signal %d delivered to unknown thread, SP=%p", signum, sp);
	}

	switch (signum) {
	case SIGALRM:
		os_atomic_inc(&entry->alrm_count, relaxed);
		break;
	case SIGVTALRM:
		os_atomic_inc(&entry->vtalrm_count, relaxed);
		break;
	case SIGPROF:
		os_atomic_inc(&entry->prof_count, relaxed);
		break;
	case SIGXCPU:
		os_atomic_inc(&entry->xcpu_count, relaxed);
		break;
	}
}
