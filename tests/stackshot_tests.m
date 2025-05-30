#include <darwintest.h>
#include <darwintest_utils.h>
#include <darwintest_multiprocess.h>
#include <kern/debug.h>
#include <kern/kern_cdata.h>
#include <kern/block_hint.h>
#include <kdd.h>
#include <libproc.h>
#include <os/atomic_private.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <mach-o/dyld_priv.h>
#include <sys/syscall.h>
#include <sys/stackshot.h>
#include <uuid/uuid.h>
#include <servers/bootstrap.h>
#include <pthread/workqueue_private.h>
#include <dispatch/private.h>
#include <stdalign.h>
#include <TargetConditionals.h>

#import <zlib.h>
#import <IOKit/IOKitLib.h>
#import <IOKit/IOKitLibPrivate.h>
#import <IOKit/IOKitKeysPrivate.h>
#import "test_utils.h"



T_GLOBAL_META(
		T_META_NAMESPACE("xnu.stackshot"),
		T_META_RADAR_COMPONENT_NAME("xnu"),
		T_META_RADAR_COMPONENT_VERSION("stackshot"),
		T_META_OWNER("jonathan_w_adams"),
		T_META_CHECK_LEAKS(false),
		T_META_ASROOT(true),
		XNU_T_META_SOC_SPECIFIC
		);

static const char *current_process_name(void);
static void verify_stackshot_sharedcache_layout(struct dyld_uuid_info_64 *uuids, uint32_t uuid_count);
static void parse_stackshot(uint64_t stackshot_parsing_flags, void *ssbuf, size_t sslen, NSDictionary *extra);
static void parse_thread_group_stackshot(void **sbuf, size_t sslen);
static uint64_t stackshot_timestamp(void *ssbuf, size_t sslen);
static void initialize_thread(void);

static uint64_t global_flags = 0;

#define DEFAULT_STACKSHOT_BUFFER_SIZE (1024 * 1024)
#define MAX_STACKSHOT_BUFFER_SIZE     (6 * 1024 * 1024)

#define SRP_SERVICE_NAME "com.apple.xnu.test.stackshot.special_reply_port"

/* bit flags for parse_stackshot */
#define PARSE_STACKSHOT_DELTA                0x01
#define PARSE_STACKSHOT_ZOMBIE               0x02
#define PARSE_STACKSHOT_SHAREDCACHE_LAYOUT   0x04
#define PARSE_STACKSHOT_DISPATCH_QUEUE_LABEL 0x08
#define PARSE_STACKSHOT_TURNSTILEINFO        0x10
#define PARSE_STACKSHOT_POSTEXEC             0x20
#define PARSE_STACKSHOT_WAITINFO_CSEG        0x40
#define PARSE_STACKSHOT_WAITINFO_SRP         0x80
#define PARSE_STACKSHOT_TRANSLATED           0x100
#define PARSE_STACKSHOT_SHAREDCACHE_FLAGS    0x200
#define PARSE_STACKSHOT_EXEC_INPROGRESS      0x400
#define PARSE_STACKSHOT_TRANSITIONING        0x800
#define PARSE_STACKSHOT_ASYNCSTACK           0x1000
#define PARSE_STACKSHOT_COMPACTINFO          0x2000 /* TODO: rdar://88789261 */
#define PARSE_STACKSHOT_DRIVERKIT            0x4000
#define PARSE_STACKSHOT_THROTTLED_SP         0x8000
#define PARSE_STACKSHOT_SUSPENDINFO          0x10000
#define PARSE_STACKSHOT_TARGETPID            0x20000

/* keys for 'extra' dictionary for parse_stackshot */
static const NSString* zombie_child_pid_key = @"zombie_child_pid"; // -> @(pid), required for PARSE_STACKSHOT_ZOMBIE
static const NSString* postexec_child_unique_pid_key = @"postexec_child_unique_pid";  // -> @(unique_pid), required for PARSE_STACKSHOT_POSTEXEC
static const NSString* cseg_expected_threadid_key = @"cseg_expected_threadid"; // -> @(tid), required for PARSE_STACKSHOT_WAITINFO_CSEG
static const NSString* srp_expected_threadid_key = @"srp_expected_threadid"; // -> @(tid), this or ..._pid required for PARSE_STACKSHOT_WAITINFO_SRP
static const NSString* srp_expected_pid_key = @"srp_expected_pid"; // -> @(pid), this or ..._threadid required for PARSE_STACKSHOT_WAITINFO_SRP
static const NSString* translated_child_pid_key = @"translated_child_pid"; // -> @(pid), required for PARSE_STACKSHOT_TRANSLATED
static const NSString* sharedcache_child_pid_key = @"sharedcache_child_pid"; // @(pid), required for PARSE_STACKSHOT_SHAREDCACHE_FLAGS
static const NSString* sharedcache_child_sameaddr_key = @"sharedcache_child_sameaddr"; // @(0 or 1), required for PARSE_STACKSHOT_SHAREDCACHE_FLAGS
static const NSString* exec_inprogress_pid_key = @"exec_inprogress_pid";
static const NSString* exec_inprogress_found_key = @"exec_inprogress_found";  // callback when inprogress is found
static const NSString* transitioning_pid_key = @"transitioning_task_pid"; // -> @(pid), required for PARSE_STACKSHOT_TRANSITIONING
static const NSString* asyncstack_expected_threadid_key = @"asyncstack_expected_threadid"; // -> @(tid), required for PARSE_STACKSHOT_ASYNCSTACK
static const NSString* asyncstack_expected_stack_key = @"asyncstack_expected_stack"; // -> @[pc...]), expected PCs for asyncstack
static const NSString* driverkit_found_key = @"driverkit_found_key"; // callback when driverkit process is found. argument is the process pid.
static const NSString* sp_throttled_expected_ctxt_key = @"sp_throttled_expected_ctxt_key"; // -> @(ctxt), required for PARSE_STACKSHOT_THROTTLED_SP
static const NSString* sp_throttled_expect_flag = @"sp_throttled_expect_flag"; // -> @(is_throttled), required for PARSE_STACKSHOT_THROTTLED_SP
static const NSString* no_exclaves_key = @"no_exclaves";

#define TEST_STACKSHOT_QUEUE_LABEL        "houston.we.had.a.problem"
#define TEST_STACKSHOT_QUEUE_LABEL_LENGTH sizeof(TEST_STACKSHOT_QUEUE_LABEL)

#define THROTTLED_SERVICE_NAME "com.apple.xnu.test.stackshot.throttled_service"

static int64_t
run_sysctl_test(const char *t, int64_t value)
{
	char name[1024];
	int64_t result = 0;
	size_t s = sizeof(value);
	int rc;

	snprintf(name, sizeof(name), "debug.test.%s", t);
	rc = sysctlbyname(name, &result, &s, &value, s);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rc, "sysctlbyname(%s)", name);
	return result;
}

T_DECL(microstackshots, "test the microstackshot syscall", T_META_TAG_VM_PREFERRED)
{
	void *buf = NULL;
	unsigned int size = DEFAULT_STACKSHOT_BUFFER_SIZE;

	while (1) {
		buf = malloc(size);
		T_QUIET; T_ASSERT_NOTNULL(buf, "allocated stackshot buffer");

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
		int len = syscall(SYS_microstackshot, buf, size,
				(uint32_t) STACKSHOT_GET_MICROSTACKSHOT);
#pragma clang diagnostic pop
		if (len == ENOSYS) {
			T_SKIP("microstackshot syscall failed, likely not compiled with CONFIG_TELEMETRY");
		}
		if (len == -1 && errno == ENOSPC) {
			/* syscall failed because buffer wasn't large enough, try again */
			free(buf);
			buf = NULL;
			size *= 2;
			T_ASSERT_LE(size, (unsigned int)MAX_STACKSHOT_BUFFER_SIZE,
					"growing stackshot buffer to sane size");
			continue;
		}
		T_ASSERT_POSIX_SUCCESS(len, "called microstackshot syscall");
		break;
    }

	T_EXPECT_EQ(*(uint32_t *)buf,
			(uint32_t)STACKSHOT_MICRO_SNAPSHOT_MAGIC,
			"magic value for microstackshot matches");

	free(buf);
}

struct scenario {
	const char *name;
	uint64_t flags;
	bool quiet;
	bool should_fail;
	bool maybe_unsupported;
	bool maybe_enomem;
	bool no_recordfile;
	pid_t target_pid;
	bool target_kernel;
	uint64_t since_timestamp;
	uint32_t size_hint;
	dt_stat_time_t timer;
};

static void
quiet(struct scenario *scenario)
{
	if (scenario->timer || scenario->quiet) {
		T_QUIET;
	}
}

static void
take_stackshot(struct scenario *scenario, bool compress_ok, void (^cb)(void *buf, size_t size))
{
start:
	initialize_thread();

	void *config = stackshot_config_create();
	quiet(scenario);
	T_ASSERT_NOTNULL(config, "created stackshot config");

	int ret = stackshot_config_set_flags(config, scenario->flags | global_flags);
	quiet(scenario);
	T_ASSERT_POSIX_ZERO(ret, "set flags %#llx on stackshot config", scenario->flags);

	if (scenario->size_hint > 0) {
		ret = stackshot_config_set_size_hint(config, scenario->size_hint);
		quiet(scenario);
		T_ASSERT_POSIX_ZERO(ret, "set size hint %" PRIu32 " on stackshot config",
				scenario->size_hint);
	}

	if (scenario->target_pid > 0) {
		ret = stackshot_config_set_pid(config, scenario->target_pid);
		quiet(scenario);
		T_ASSERT_POSIX_ZERO(ret, "set target pid %d on stackshot config",
				scenario->target_pid);
	} else if (scenario->target_kernel) {
		ret = stackshot_config_set_pid(config, 0);
		quiet(scenario);
		T_ASSERT_POSIX_ZERO(ret, "set kernel target on stackshot config");
	}

	if (scenario->since_timestamp > 0) {
		ret = stackshot_config_set_delta_timestamp(config, scenario->since_timestamp);
		quiet(scenario);
		T_ASSERT_POSIX_ZERO(ret, "set since timestamp %" PRIu64 " on stackshot config",
				scenario->since_timestamp);
	}

	int retries_remaining = 5;

retry: ;
	uint64_t start_time = mach_absolute_time();
	ret = stackshot_capture_with_config(config);
	uint64_t end_time = mach_absolute_time();

	if (scenario->should_fail) {
		T_EXPECTFAIL;
		T_ASSERT_POSIX_ZERO(ret, "called stackshot_capture_with_config");
		return;
	}

	if (ret == EBUSY || ret == ETIMEDOUT) {
		if (retries_remaining > 0) {
			if (!scenario->timer) {
				T_LOG("stackshot_capture_with_config failed with %s (%d), retrying",
						strerror(ret), ret);
			}

			retries_remaining--;
			goto retry;
		} else {
			T_ASSERT_POSIX_ZERO(ret,
					"called stackshot_capture_with_config (no retries remaining)");
		}
	} else if ((ret == ENOTSUP) && scenario->maybe_unsupported) {
		T_SKIP("kernel indicated this stackshot configuration is not supported");
	} else if ((ret == ENOMEM) && scenario->maybe_enomem) {
		T_SKIP("insufficient available memory to run test");
	} else {
		quiet(scenario);
		T_ASSERT_POSIX_ZERO(ret, "called stackshot_capture_with_config");
	}

	if (scenario->timer) {
		dt_stat_mach_time_add(scenario->timer, end_time - start_time);
	}
	void *buf = stackshot_config_get_stackshot_buffer(config);
	size_t size = stackshot_config_get_stackshot_size(config);
	if (scenario->name && !scenario->no_recordfile) {
		char sspath[MAXPATHLEN];
		strlcpy(sspath, scenario->name, sizeof(sspath));
		strlcat(sspath, ".kcdata", sizeof(sspath));
		T_QUIET; T_ASSERT_POSIX_ZERO(dt_resultfile(sspath, sizeof(sspath)),
				"create result file path");

		if (!scenario->quiet) {
			T_LOG("writing stackshot to %s", sspath);
		}

		FILE *f = fopen(sspath, "w");
		T_WITH_ERRNO; T_QUIET; T_ASSERT_NOTNULL(f,
				"open stackshot output file");

		size_t written = fwrite(buf, size, 1, f);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(written, "wrote stackshot to file");

		fclose(f);
	}
	cb(buf, size);
	if (compress_ok) {
		if (global_flags == 0) {
			T_LOG("Restarting test with compression");
			global_flags |= STACKSHOT_DO_COMPRESS;
			goto start;
		} else {
			global_flags = 0;
		}
	}

	ret = stackshot_config_dealloc(config);
	T_QUIET; T_EXPECT_POSIX_ZERO(ret, "deallocated stackshot config");
}

T_DECL(simple_compressed, "take a simple compressed stackshot", T_META_TAG_VM_PREFERRED)
{
	struct scenario scenario = {
		.name = "kcdata_compressed",
		.flags = (STACKSHOT_DO_COMPRESS | STACKSHOT_SAVE_LOADINFO | STACKSHOT_THREAD_WAITINFO | STACKSHOT_GET_GLOBAL_MEM_STATS |
				STACKSHOT_SAVE_IMP_DONATION_PIDS | STACKSHOT_KCDATA_FORMAT),
	};

	T_LOG("taking compressed kcdata stackshot");
	take_stackshot(&scenario, true, ^(void *ssbuf, size_t sslen) {
		parse_stackshot(0, ssbuf, sslen, nil);
	});
}

T_DECL(panic_compressed, "take a compressed stackshot with the same flags as a panic stackshot", T_META_TAG_VM_PREFERRED)
{
	uint64_t stackshot_flags = (STACKSHOT_SAVE_KEXT_LOADINFO |
			STACKSHOT_SAVE_LOADINFO |
			STACKSHOT_KCDATA_FORMAT |
			STACKSHOT_ENABLE_BT_FAULTING |
			STACKSHOT_ENABLE_UUID_FAULTING |
			STACKSHOT_DO_COMPRESS |
			STACKSHOT_NO_IO_STATS |
			STACKSHOT_THREAD_WAITINFO |
#if TARGET_OS_MAC
			STACKSHOT_COLLECT_SHAREDCACHE_LAYOUT |
#endif
			STACKSHOT_DISABLE_LATENCY_INFO);

	struct scenario scenario = {
		.name = "kcdata_panic_compressed",
		.flags = stackshot_flags,
	};

	T_LOG("taking compressed kcdata stackshot with panic flags");
	take_stackshot(&scenario, true, ^(void *ssbuf, size_t sslen) {
		parse_stackshot(0, ssbuf, sslen, nil);
	});
}

T_DECL(kcdata, "test that kcdata stackshots can be taken and parsed", T_META_TAG_VM_PREFERRED)
{
	struct scenario scenario = {
		.name = "kcdata",
		.flags = (STACKSHOT_SAVE_LOADINFO | STACKSHOT_GET_GLOBAL_MEM_STATS |
				STACKSHOT_SAVE_IMP_DONATION_PIDS | STACKSHOT_KCDATA_FORMAT),
	};

	T_LOG("taking kcdata stackshot");
	take_stackshot(&scenario, true, ^(void *ssbuf, size_t sslen) {
		parse_stackshot(0, ssbuf, sslen, nil);
	});
}

static void
get_stats(stackshot_stats_t *_Nonnull out)
{
	size_t oldlen = sizeof (*out);
	bzero(out, oldlen);
	int result = sysctlbyname("kern.stackshot_stats", out, &oldlen, NULL, 0);
	T_WITH_ERRNO; T_ASSERT_POSIX_SUCCESS(result, "reading \"kern.stackshot_stats\" sysctl should succeed");
	T_EXPECT_EQ(oldlen, sizeof (*out), "kernel should update full stats structure");
}

static void
log_stats(mach_timebase_info_data_t timebase, uint64_t now, const char *name, stackshot_stats_t stat)
{
	uint64_t last_ago = (now - stat.ss_last_start) * timebase.numer / timebase.denom;
	uint64_t last_duration = (stat.ss_last_end - stat.ss_last_start) * timebase.numer / timebase.denom;
	uint64_t total_duration = (stat.ss_duration) * timebase.numer / timebase.denom;

	uint64_t nanosec = 1000000000llu;
	T_LOG("%s: %8lld stackshots, %10lld.%09lld total nsecs, last %lld.%09lld secs ago, %lld.%09lld secs long",
		name, stat.ss_count,
		total_duration / nanosec, total_duration % nanosec,
		last_ago / nanosec, last_ago % nanosec,
		last_duration / nanosec, last_duration % nanosec);
}

T_DECL(stats, "test that stackshot stats can be read out and change when a stackshot occurs", T_META_TAG_VM_PREFERRED)
{
	mach_timebase_info_data_t timebase = {0, 0};
	mach_timebase_info(&timebase);

	struct scenario scenario = {
		.name = "kcdata",
		.flags = (STACKSHOT_SAVE_LOADINFO | STACKSHOT_KCDATA_FORMAT),
	};

	stackshot_stats_t pre, post;

	get_stats(&pre);

	T_LOG("taking kcdata stackshot");
	take_stackshot(&scenario, true, ^(__unused void *ssbuf, __unused size_t sslen) {
		(void)0;
	});

	get_stats(&post);

	uint64_t now = mach_absolute_time();

	log_stats(timebase, now, "  pre", pre);
	log_stats(timebase, now, " post", post);

	int64_t delta_stackshots = (int64_t)(post.ss_count - pre.ss_count);
	int64_t delta_duration = (int64_t)(post.ss_duration - pre.ss_duration) * (int64_t)timebase.numer / (int64_t)timebase.denom;
	int64_t delta_nsec = delta_duration % 1000000000ll;
	if (delta_nsec < 0) {
	    delta_nsec += 1000000000ll;
	}
	T_LOG("delta: %+8lld stackshots, %+10lld.%09lld total nsecs", delta_stackshots, delta_duration / 1000000000ll, delta_nsec);

	T_EXPECT_LT(pre.ss_last_start, pre.ss_last_end, "pre: stackshot should take time");
	T_EXPECT_LT(pre.ss_count, post.ss_count, "stackshot count should increase when a stackshot is taken");
	T_EXPECT_LT(pre.ss_duration, post.ss_duration, "stackshot duration should increase when a stackshot is taken");
	T_EXPECT_LT(pre.ss_last_end, post.ss_last_start, "previous end should be less than new start after a stackshot");
	T_EXPECT_LT(post.ss_last_start, post.ss_last_end, "post: stackshot should take time");
}

T_DECL(kcdata_faulting, "test that kcdata stackshots while faulting can be taken and parsed", T_META_TAG_VM_PREFERRED)
{
	struct scenario scenario = {
		.name = "faulting",
		.flags = (STACKSHOT_SAVE_LOADINFO | STACKSHOT_GET_GLOBAL_MEM_STATS
				| STACKSHOT_SAVE_IMP_DONATION_PIDS | STACKSHOT_KCDATA_FORMAT
				| STACKSHOT_ENABLE_BT_FAULTING | STACKSHOT_ENABLE_UUID_FAULTING),
	};

	T_LOG("taking faulting stackshot");
	take_stackshot(&scenario, true, ^(void *ssbuf, size_t sslen) {
		parse_stackshot(0, ssbuf, sslen, nil);
	});
}

T_DECL(bad_flags, "test a poorly-formed stackshot syscall", T_META_TAG_VM_PREFERRED)
{
	struct scenario scenario = {
		.flags = STACKSHOT_SAVE_IN_KERNEL_BUFFER /* not allowed from user space */,
		.should_fail = true,
	};

	T_LOG("attempting to take stackshot with kernel-only flag");
	take_stackshot(&scenario, true, ^(__unused void *ssbuf, __unused size_t sslen) {
		T_ASSERT_FAIL("stackshot data callback called");
	});
}

T_DECL(delta, "test delta stackshots", T_META_TAG_VM_PREFERRED)
{
	struct scenario scenario = {
		.name = "delta",
		.flags = (STACKSHOT_SAVE_LOADINFO | STACKSHOT_GET_GLOBAL_MEM_STATS
				| STACKSHOT_SAVE_IMP_DONATION_PIDS | STACKSHOT_KCDATA_FORMAT),
	};

	T_LOG("taking full stackshot");
	take_stackshot(&scenario, false, ^(void *ssbuf, size_t sslen) {
		uint64_t stackshot_time = stackshot_timestamp(ssbuf, sslen);

		T_LOG("taking delta stackshot since time %" PRIu64, stackshot_time);

		parse_stackshot(0, ssbuf, sslen, nil);

		struct scenario delta_scenario = {
			.flags = (STACKSHOT_SAVE_LOADINFO | STACKSHOT_GET_GLOBAL_MEM_STATS
					| STACKSHOT_SAVE_IMP_DONATION_PIDS | STACKSHOT_KCDATA_FORMAT
					| STACKSHOT_COLLECT_DELTA_SNAPSHOT),
			.since_timestamp = stackshot_time
		};

		take_stackshot(&delta_scenario, false, ^(void *dssbuf, size_t dsslen) {
			parse_stackshot(PARSE_STACKSHOT_DELTA, dssbuf, dsslen, nil);
		});
	});
}

T_DECL(shared_cache_layout, "test stackshot inclusion of shared cache layout", T_META_TAG_VM_PREFERRED)
{
	struct scenario scenario = {
		.name = "shared_cache_layout",
		.flags = (STACKSHOT_SAVE_LOADINFO | STACKSHOT_GET_GLOBAL_MEM_STATS
				| STACKSHOT_SAVE_IMP_DONATION_PIDS | STACKSHOT_KCDATA_FORMAT |
				STACKSHOT_COLLECT_SHAREDCACHE_LAYOUT),
	};

	size_t shared_cache_length;
	const void *cache_header = _dyld_get_shared_cache_range(&shared_cache_length);
	if (cache_header == NULL) {
		T_SKIP("Device not running with shared cache, skipping test...");
	}

	if (shared_cache_length == 0) {
		T_SKIP("dyld reports that currently running shared cache has zero length");
	}

	T_LOG("taking stackshot with STACKSHOT_COLLECT_SHAREDCACHE_LAYOUT set");
	take_stackshot(&scenario, true, ^(void *ssbuf, size_t sslen) {
		parse_stackshot(PARSE_STACKSHOT_SHAREDCACHE_LAYOUT, ssbuf, sslen, nil);
	});
}

T_DECL(stress, "test that taking stackshots for 60 seconds doesn't crash the system", T_META_TAG_VM_PREFERRED)
{
	uint64_t max_diff_time = 60ULL /* seconds */ * 1000000000ULL;
	uint64_t start_time;

	struct scenario scenario = {
		.name = "stress",
		.quiet = true,
		.flags = (STACKSHOT_KCDATA_FORMAT |
				STACKSHOT_THREAD_WAITINFO |
				STACKSHOT_SAVE_LOADINFO |
				STACKSHOT_SAVE_KEXT_LOADINFO |
				STACKSHOT_GET_GLOBAL_MEM_STATS |
				STACKSHOT_SAVE_IMP_DONATION_PIDS |
				STACKSHOT_COLLECT_SHAREDCACHE_LAYOUT |
				STACKSHOT_THREAD_GROUP |
				STACKSHOT_SAVE_JETSAM_COALITIONS |
				STACKSHOT_ASID |
				STACKSHOT_EXCLAVES |
				0),
	};

	start_time = clock_gettime_nsec_np(CLOCK_MONOTONIC);
	while (clock_gettime_nsec_np(CLOCK_MONOTONIC) - start_time < max_diff_time) {
		take_stackshot(&scenario, false, ^(void * __unused ssbuf,
				size_t __unused sslen) {
			printf(".");
			fflush(stdout);
		});

		/*
		 * After the first stackshot, there's no point in continuing to
		 * write them to disk, and it wears down the SSDs.
		 */
		scenario.no_recordfile = true;

		/* Leave some time for the testing infrastructure to catch up */
		usleep(10000);

	}
	printf("\n");
}

T_DECL(dispatch_queue_label, "test that kcdata stackshots contain libdispatch queue labels", T_META_TAG_VM_PREFERRED)
{
	struct scenario scenario = {
		.name = "kcdata",
		.flags = (STACKSHOT_GET_DQ | STACKSHOT_KCDATA_FORMAT),
	};
	dispatch_semaphore_t child_ready_sem, parent_done_sem;
	dispatch_queue_t dq;

#if TARGET_OS_WATCH
	T_SKIP("This test is flaky on watches: 51663346");
#endif

	child_ready_sem = dispatch_semaphore_create(0);
	T_QUIET; T_ASSERT_NOTNULL(child_ready_sem, "dqlabel child semaphore");

	parent_done_sem = dispatch_semaphore_create(0);
	T_QUIET; T_ASSERT_NOTNULL(parent_done_sem, "dqlabel parent semaphore");

	dq = dispatch_queue_create(TEST_STACKSHOT_QUEUE_LABEL, NULL);
	T_QUIET; T_ASSERT_NOTNULL(dq, "dispatch queue");

	/* start the helper thread */
	dispatch_async(dq, ^{
			dispatch_semaphore_signal(child_ready_sem);

			dispatch_semaphore_wait(parent_done_sem, DISPATCH_TIME_FOREVER);
	});

	/* block behind the child starting up */
	dispatch_semaphore_wait(child_ready_sem, DISPATCH_TIME_FOREVER);

	T_LOG("taking kcdata stackshot with libdispatch queue labels");
	take_stackshot(&scenario, true, ^(void *ssbuf, size_t sslen) {
		parse_stackshot(PARSE_STACKSHOT_DISPATCH_QUEUE_LABEL, ssbuf, sslen, nil);
	});

	dispatch_semaphore_signal(parent_done_sem);
}

#define CACHEADDR_ENV "STACKSHOT_TEST_DYLDADDR"
T_HELPER_DECL(spawn_reslide_child, "child process to spawn with alternate slide")
{
	size_t shared_cache_len;
	const void *addr, *prevaddr;
	uintmax_t v;
	char *endptr;

	const char *cacheaddr_env = getenv(CACHEADDR_ENV);
	T_QUIET; T_ASSERT_NOTNULL(cacheaddr_env, "getenv("CACHEADDR_ENV")");
	errno = 0;
	endptr = NULL;
	v = strtoumax(cacheaddr_env, &endptr, 16);	/* read hex value */
	T_WITH_ERRNO; T_QUIET; T_ASSERT_NE(v, 0l, "getenv(%s) = \"%s\" should be a non-zero hex number", CACHEADDR_ENV, cacheaddr_env);
	T_QUIET; T_ASSERT_EQ(*endptr, 0, "getenv(%s) = \"%s\" endptr \"%s\" should be empty", CACHEADDR_ENV, cacheaddr_env, endptr);

	prevaddr = (const void *)v;
	addr = _dyld_get_shared_cache_range(&shared_cache_len);
	T_QUIET; T_ASSERT_NOTNULL(addr, "shared cache address");

	T_QUIET; T_ASSERT_POSIX_SUCCESS(kill(getppid(), (addr == prevaddr) ? SIGUSR2 : SIGUSR1), "signaled parent to take stackshot");
	for (;;) {
		(void) pause();		/* parent will kill -9 us */
	}
}

T_DECL(shared_cache_flags, "tests stackshot's task_ss_flags for the shared cache", T_META_TAG_VM_PREFERRED)
{
	posix_spawnattr_t		attr;
	char *env_addr;
	char path[PATH_MAX];
	__block bool child_same_addr = false;

	uint32_t path_size = sizeof(path);
	T_QUIET; T_ASSERT_POSIX_ZERO(_NSGetExecutablePath(path, &path_size), "_NSGetExecutablePath");
	char *args[] = { path, "-n", "spawn_reslide_child", NULL };
	pid_t pid;
	size_t shared_cache_len;
	const void *addr;

	dispatch_source_t child_diffsig_src, child_samesig_src;
	dispatch_semaphore_t child_ready_sem = dispatch_semaphore_create(0);
	T_QUIET; T_ASSERT_NOTNULL(child_ready_sem, "shared_cache child semaphore");

	dispatch_queue_t signal_processing_q = dispatch_queue_create("signal processing queue", NULL);
	T_QUIET; T_ASSERT_NOTNULL(signal_processing_q, "signal processing queue");

	signal(SIGUSR1, SIG_IGN);
	signal(SIGUSR2, SIG_IGN);
	child_samesig_src = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGUSR1, 0, signal_processing_q);
	T_QUIET; T_ASSERT_NOTNULL(child_samesig_src, "dispatch_source_create (child_samesig_src)");
	child_diffsig_src = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGUSR2, 0, signal_processing_q);
	T_QUIET; T_ASSERT_NOTNULL(child_diffsig_src, "dispatch_source_create (child_diffsig_src)");

	/* child will signal us depending on if their addr is the same or different */
	dispatch_source_set_event_handler(child_samesig_src, ^{ child_same_addr = false; dispatch_semaphore_signal(child_ready_sem); });
	dispatch_source_set_event_handler(child_diffsig_src, ^{ child_same_addr = true; dispatch_semaphore_signal(child_ready_sem); });
	dispatch_activate(child_samesig_src);
	dispatch_activate(child_diffsig_src);

	addr = _dyld_get_shared_cache_range(&shared_cache_len);
	T_QUIET; T_ASSERT_NOTNULL(addr, "shared cache address");

	T_QUIET; T_ASSERT_POSIX_SUCCESS(asprintf(&env_addr, "%p", addr), "asprintf of env_addr succeeded");
	T_QUIET; T_ASSERT_POSIX_SUCCESS(setenv(CACHEADDR_ENV, env_addr, true), "setting "CACHEADDR_ENV" to %s", env_addr);

	T_QUIET; T_ASSERT_POSIX_ZERO(posix_spawnattr_init(&attr), "posix_spawnattr_init");
	T_QUIET; T_ASSERT_POSIX_ZERO(posix_spawnattr_setflags(&attr, _POSIX_SPAWN_RESLIDE), "posix_spawnattr_setflags");
	int sp_ret = posix_spawn(&pid, path, NULL, &attr, args, environ);
	T_ASSERT_POSIX_ZERO(sp_ret, "spawned process '%s' with PID %d", args[0], pid);

	dispatch_semaphore_wait(child_ready_sem, DISPATCH_TIME_FOREVER);
	T_LOG("received signal from child (%s), capturing stackshot", child_same_addr ? "same shared cache addr" : "different shared cache addr");

	struct scenario scenario = {
		.name = "shared_cache_flags",
		.flags = (STACKSHOT_SAVE_LOADINFO | STACKSHOT_GET_GLOBAL_MEM_STATS
				| STACKSHOT_COLLECT_SHAREDCACHE_LAYOUT
				| STACKSHOT_SAVE_IMP_DONATION_PIDS | STACKSHOT_KCDATA_FORMAT),
	};

	take_stackshot(&scenario, false, ^( void *ssbuf, size_t sslen) {
		int status;
		/* First kill the child so we can reap it */
		T_QUIET; T_ASSERT_POSIX_SUCCESS(kill(pid, SIGKILL), "killing spawned process");
		T_QUIET; T_ASSERT_POSIX_SUCCESS(waitpid(pid, &status, 0), "waitpid on spawned child");
		T_QUIET; T_ASSERT_EQ(!!WIFSIGNALED(status), 1, "waitpid status should be signalled");
		T_QUIET; T_ASSERT_EQ(WTERMSIG(status), SIGKILL, "waitpid status should be SIGKILLed");

		parse_stackshot(PARSE_STACKSHOT_SHAREDCACHE_FLAGS, ssbuf, sslen,
			@{sharedcache_child_pid_key: @(pid), sharedcache_child_sameaddr_key: @(child_same_addr ? 1 : 0)});
	});
}

T_DECL(transitioning_tasks, "test that stackshot contains transitioning task info", T_META_BOOTARGS_SET("enable_proc_exit_lpexit_spin=1"), T_META_TAG_VM_PREFERRED)
{
    int32_t sysctlValue = -1, numAttempts =0;
    char path[PATH_MAX];
    uint32_t path_size = sizeof(path);
    T_QUIET; T_ASSERT_POSIX_ZERO(_NSGetExecutablePath(path, &path_size), "_NSGetExecutablePath");
    char *args[] = { path, "-n", "exec_child_preexec", NULL };

    dispatch_source_t child_sig_src;
    dispatch_semaphore_t child_ready_sem = dispatch_semaphore_create(0);
    T_QUIET; T_ASSERT_NOTNULL(child_ready_sem, "exec child semaphore");

    dispatch_queue_t signal_processing_q = dispatch_queue_create("signal processing queue", NULL);
    T_QUIET; T_ASSERT_NOTNULL(signal_processing_q, "signal processing queue");

    pid_t pid;

    signal(SIGUSR1, SIG_IGN);
    child_sig_src = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGUSR1, 0, signal_processing_q);
    T_QUIET; T_ASSERT_NOTNULL(child_sig_src, "dispatch_source_create (child_sig_src)");

    dispatch_source_set_event_handler(child_sig_src, ^{ dispatch_semaphore_signal(child_ready_sem); });
    dispatch_activate(child_sig_src);

    T_ASSERT_POSIX_SUCCESS(sysctlbyname("debug.proc_exit_lpexit_spin_pid", NULL, NULL, &sysctlValue, sizeof(sysctlValue)), "set debug.proc_exit_lpexit_spin_pid=-1");

    int proc_exit_spin_pos = 0 ;

    while (0 == sysctlbyname("debug.proc_exit_lpexit_spin_pos", NULL, NULL, &proc_exit_spin_pos, sizeof(proc_exit_spin_pos))) {

        T_LOG(" ##### Testing while spinning in proc_exit at position %d ##### ", proc_exit_spin_pos);

        int sp_ret = posix_spawn(&pid, args[0], NULL, NULL, args, NULL);
        T_ASSERT_POSIX_ZERO(sp_ret, "spawned process '%s' with PID %d", args[0], pid);

        dispatch_semaphore_wait(child_ready_sem, DISPATCH_TIME_FOREVER);

        struct proc_uniqidentifierinfo proc_info_data = { };
        int retval = proc_pidinfo(getpid(), PROC_PIDUNIQIDENTIFIERINFO, 0, &proc_info_data, sizeof(proc_info_data));
        T_QUIET; T_EXPECT_POSIX_SUCCESS(retval, "proc_pidinfo PROC_PIDUNIQIDENTIFIERINFO");
        T_QUIET; T_ASSERT_EQ_INT(retval, (int) sizeof(proc_info_data), "proc_pidinfo PROC_PIDUNIQIDENTIFIERINFO returned data");

        T_ASSERT_POSIX_SUCCESS(kill(pid, SIGUSR1), "signaled pre-exec child to exec");

	/* wait for a signal from post-exec child */
        dispatch_semaphore_wait(child_ready_sem, DISPATCH_TIME_FOREVER);

        T_ASSERT_POSIX_SUCCESS(sysctlbyname("debug.proc_exit_lpexit_spin_pid", NULL, NULL, &pid, sizeof(pid)), "set debug.proc_exit_lpexit_spin_pid =  %d, ", pid);

        T_ASSERT_POSIX_SUCCESS(kill(pid, SIGKILL), "kill post-exec child %d", pid);

        sysctlValue = 0;
        size_t len = sizeof(sysctlValue);
        while (numAttempts < 5) {
            T_ASSERT_POSIX_SUCCESS(sysctlbyname("debug.proc_exit_lpexit_spinning", &sysctlValue, &len, NULL, 0), "retrieve debug.proc_exit_lpexit_spinning");
            if (sysctlValue != 1) numAttempts++;
            else break;
            sleep(1);
        }

        T_ASSERT_EQ_UINT(sysctlValue, 1, "find spinning task in proc_exit()");

        struct scenario scenario = {
            .name = "transitioning_tasks",
            .flags = (STACKSHOT_KCDATA_FORMAT)
        };

        take_stackshot(&scenario, false, ^( void *ssbuf, size_t sslen) {
            parse_stackshot(PARSE_STACKSHOT_TRANSITIONING, ssbuf, sslen, @{transitioning_pid_key: @(pid)});

            // Kill the child
            int sysctlValueB = -1;
            T_ASSERT_POSIX_SUCCESS(sysctlbyname("debug.proc_exit_lpexit_spin_pid", NULL, NULL, &sysctlValueB, sizeof(sysctlValueB)), "set debug.proc_exit_lpexit_spin_pid=-1");
            sleep(1);
            size_t blen = sizeof(sysctlValueB);
            T_ASSERT_POSIX_SUCCESS(sysctlbyname("debug.proc_exit_lpexit_spinning", &sysctlValueB, &blen, NULL, 0), "retrieve debug.proc_exit_lpexit_spinning");
            T_ASSERT_EQ_UINT(sysctlValueB, 0, "make sure nothing is spining in proc_exit()");
            int status;
            T_ASSERT_POSIX_SUCCESS(waitpid(pid, &status, 0), "waitpid on post-exec child");
        });

        proc_exit_spin_pos++;
    }

}

static void *stuck_sysctl_thread(void *arg) {
	int val = 1;
	dispatch_semaphore_t child_thread_started = *(dispatch_semaphore_t *)arg;

	dispatch_semaphore_signal(child_thread_started);
	T_ASSERT_POSIX_SUCCESS(sysctlbyname("kern.wedge_thread", NULL, NULL, &val, sizeof(val)), "wedge child thread");

	return NULL;
}

T_HELPER_DECL(zombie_child, "child process to sample as a zombie")
{
	pthread_t pthread;
	dispatch_semaphore_t child_thread_started = dispatch_semaphore_create(0);
	T_QUIET; T_ASSERT_NOTNULL(child_thread_started, "zombie child thread semaphore");

	/* spawn another thread to get stuck in the kernel, then call exit() to become a zombie */
	T_QUIET; T_ASSERT_POSIX_SUCCESS(pthread_create(&pthread, NULL, stuck_sysctl_thread, &child_thread_started), "pthread_create");

	dispatch_semaphore_wait(child_thread_started, DISPATCH_TIME_FOREVER);

	/* sleep for a bit in the hope of ensuring that the other thread has called the sysctl before we signal the parent */
	usleep(100);
	T_ASSERT_POSIX_SUCCESS(kill(getppid(), SIGUSR1), "signaled parent to take stackshot");

	exit(0);
}

T_DECL(zombie, "tests a stackshot of a zombie task with a thread stuck in the kernel",
	T_META_ENABLED(false), /* test is too flaky to run by default, but transitioning_tasks covers this case as well */
	T_META_TAG_VM_PREFERRED)
{
	char path[PATH_MAX];
	uint32_t path_size = sizeof(path);
	T_ASSERT_POSIX_ZERO(_NSGetExecutablePath(path, &path_size), "_NSGetExecutablePath");
	char *args[] = { path, "-n", "zombie_child", NULL };

	dispatch_source_t child_sig_src;
	dispatch_semaphore_t child_ready_sem = dispatch_semaphore_create(0);
	T_QUIET; T_ASSERT_NOTNULL(child_ready_sem, "zombie child semaphore");

	dispatch_queue_t signal_processing_q = dispatch_queue_create("signal processing queue", NULL);
	T_QUIET; T_ASSERT_NOTNULL(signal_processing_q, "signal processing queue");

	pid_t pid;

	T_LOG("spawning a child");

	signal(SIGUSR1, SIG_IGN);
	child_sig_src = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGUSR1, 0, signal_processing_q);
	T_QUIET; T_ASSERT_NOTNULL(child_sig_src, "dispatch_source_create (child_sig_src)");

	dispatch_source_set_event_handler(child_sig_src, ^{ dispatch_semaphore_signal(child_ready_sem); });
	dispatch_activate(child_sig_src);

	int sp_ret = posix_spawn(&pid, args[0], NULL, NULL, args, NULL);
	T_QUIET; T_ASSERT_POSIX_ZERO(sp_ret, "spawned process '%s' with PID %d", args[0], pid);

	dispatch_semaphore_wait(child_ready_sem, DISPATCH_TIME_FOREVER);

	T_LOG("received signal from child, capturing stackshot");

	struct proc_bsdshortinfo bsdshortinfo;
	int retval, iterations_to_wait = 10;

	while (iterations_to_wait > 0) {
		retval = proc_pidinfo(pid, PROC_PIDT_SHORTBSDINFO, 0, &bsdshortinfo, sizeof(bsdshortinfo));
		if ((retval == 0) && errno == ESRCH) {
			T_LOG("unable to find child using proc_pidinfo, assuming zombie");
			break;
		}

		T_QUIET; T_WITH_ERRNO; T_ASSERT_GT(retval, 0, "proc_pidinfo(PROC_PIDT_SHORTBSDINFO) returned a value > 0");
		T_QUIET; T_ASSERT_EQ(retval, (int)sizeof(bsdshortinfo), "proc_pidinfo call for PROC_PIDT_SHORTBSDINFO returned expected size");

		if (bsdshortinfo.pbsi_flags & PROC_FLAG_INEXIT) {
			T_LOG("child proc info marked as in exit");
			break;
		}

		iterations_to_wait--;
		if (iterations_to_wait == 0) {
			/*
			 * This will mark the test as failed but let it continue so we
			 * don't leave a process stuck in the kernel.
			 */
			T_FAIL("unable to discover that child is marked as exiting");
		}

		/* Give the child a few more seconds to make it to exit */
		sleep(5);
	}

	/* Give the child some more time to make it through exit */
	sleep(10);

	struct scenario scenario = {
		.name = "zombie",
		.flags = (STACKSHOT_SAVE_LOADINFO | STACKSHOT_GET_GLOBAL_MEM_STATS
				| STACKSHOT_SAVE_IMP_DONATION_PIDS | STACKSHOT_KCDATA_FORMAT),
	};

	take_stackshot(&scenario, false, ^( void *ssbuf, size_t sslen) {
		/* First unwedge the child so we can reap it */
		int val = 1, status;
		T_ASSERT_POSIX_SUCCESS(sysctlbyname("kern.unwedge_thread", NULL, NULL, &val, sizeof(val)), "unwedge child");

		T_QUIET; T_ASSERT_POSIX_SUCCESS(waitpid(pid, &status, 0), "waitpid on zombie child");

		parse_stackshot(PARSE_STACKSHOT_ZOMBIE, ssbuf, sslen, @{zombie_child_pid_key: @(pid)});
	});
}

T_HELPER_DECL(exec_child_preexec, "child process pre-exec")
{
	dispatch_queue_t signal_processing_q = dispatch_queue_create("signal processing queue", NULL);
	T_QUIET; T_ASSERT_NOTNULL(signal_processing_q, "signal processing queue");

	signal(SIGUSR1, SIG_IGN);
	dispatch_source_t parent_sig_src = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGUSR1, 0, signal_processing_q);
	T_QUIET; T_ASSERT_NOTNULL(parent_sig_src, "dispatch_source_create (child_sig_src)");
	dispatch_source_set_event_handler(parent_sig_src, ^{

		// Parent took a timestamp then signaled us: exec into the next process

		char path[PATH_MAX];
		uint32_t path_size = sizeof(path);
		T_QUIET; T_ASSERT_POSIX_ZERO(_NSGetExecutablePath(path, &path_size), "_NSGetExecutablePath");
		char *args[] = { path, "-n", "exec_child_postexec", NULL };

		T_QUIET; T_ASSERT_POSIX_ZERO(execve(args[0], args, NULL), "execing into exec_child_postexec");
	});
	dispatch_activate(parent_sig_src);

	T_ASSERT_POSIX_SUCCESS(kill(getppid(), SIGUSR1), "signaled parent to take timestamp");

	sleep(100);
	// Should never get here
	T_FAIL("Received signal to exec from parent");
}

T_HELPER_DECL(exec_child_postexec, "child process post-exec to sample")
{
	T_ASSERT_POSIX_SUCCESS(kill(getppid(), SIGUSR1), "signaled parent to take stackshot");
	sleep(100);
	// Should never get here
	T_FAIL("Killed by parent");
}

T_DECL(exec, "test getting full task snapshots for a task that execs", T_META_TAG_VM_PREFERRED)
{
	char path[PATH_MAX];
	uint32_t path_size = sizeof(path);
	T_QUIET; T_ASSERT_POSIX_ZERO(_NSGetExecutablePath(path, &path_size), "_NSGetExecutablePath");
	char *args[] = { path, "-n", "exec_child_preexec", NULL };

	dispatch_source_t child_sig_src;
	dispatch_semaphore_t child_ready_sem = dispatch_semaphore_create(0);
	T_QUIET; T_ASSERT_NOTNULL(child_ready_sem, "exec child semaphore");

	dispatch_queue_t signal_processing_q = dispatch_queue_create("signal processing queue", NULL);
	T_QUIET; T_ASSERT_NOTNULL(signal_processing_q, "signal processing queue");

	pid_t pid;

	T_LOG("spawning a child");

	signal(SIGUSR1, SIG_IGN);
	child_sig_src = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGUSR1, 0, signal_processing_q);
	T_QUIET; T_ASSERT_NOTNULL(child_sig_src, "dispatch_source_create (child_sig_src)");

	dispatch_source_set_event_handler(child_sig_src, ^{ dispatch_semaphore_signal(child_ready_sem); });
	dispatch_activate(child_sig_src);

	int sp_ret = posix_spawn(&pid, args[0], NULL, NULL, args, NULL);
	T_QUIET; T_ASSERT_POSIX_ZERO(sp_ret, "spawned process '%s' with PID %d", args[0], pid);

	dispatch_semaphore_wait(child_ready_sem, DISPATCH_TIME_FOREVER);
	uint64_t start_time = mach_absolute_time();

	struct proc_uniqidentifierinfo proc_info_data = { };
	int retval = proc_pidinfo(getpid(), PROC_PIDUNIQIDENTIFIERINFO, 0, &proc_info_data, sizeof(proc_info_data));
	T_QUIET; T_EXPECT_POSIX_SUCCESS(retval, "proc_pidinfo PROC_PIDUNIQIDENTIFIERINFO");
	T_QUIET; T_ASSERT_EQ_INT(retval, (int) sizeof(proc_info_data), "proc_pidinfo PROC_PIDUNIQIDENTIFIERINFO returned data");
	uint64_t unique_pid = proc_info_data.p_uniqueid;

	T_LOG("received signal from pre-exec child, unique_pid is %llu, timestamp is %llu", unique_pid, start_time);

	T_ASSERT_POSIX_SUCCESS(kill(pid, SIGUSR1), "signaled pre-exec child to exec");

	dispatch_semaphore_wait(child_ready_sem, DISPATCH_TIME_FOREVER);

	T_LOG("received signal from post-exec child, capturing stackshot");

	struct scenario scenario = {
		.name = "exec",
		.flags = (STACKSHOT_SAVE_LOADINFO | STACKSHOT_GET_GLOBAL_MEM_STATS
				  | STACKSHOT_SAVE_IMP_DONATION_PIDS | STACKSHOT_KCDATA_FORMAT
				  | STACKSHOT_COLLECT_DELTA_SNAPSHOT),
		.since_timestamp = start_time
	};

	take_stackshot(&scenario, false, ^( void *ssbuf, size_t sslen) {
		// Kill the child
		int status;
		T_ASSERT_POSIX_SUCCESS(kill(pid, SIGKILL), "kill post-exec child %d", pid);
		T_ASSERT_POSIX_SUCCESS(waitpid(pid, &status, 0), "waitpid on post-exec child");

		parse_stackshot(PARSE_STACKSHOT_POSTEXEC | PARSE_STACKSHOT_DELTA, ssbuf, sslen, @{postexec_child_unique_pid_key: @(unique_pid)});
	});
}

T_DECL(
	exec_inprogress,
	"test stackshots of processes in the middle of exec",
	T_META_ENABLED(false), /* rdar://111691318 */
	T_META_TAG_VM_PREFERRED)
{
	pid_t pid;
	/* a BASH quine which execs itself as long as the parent doesn't exit */
        char *bash_prog = "[[ $PPID -ne 1 ]] && exec /bin/bash -c \"$0\" \"$0\"";
	char *args[] = { "/bin/bash", "-c", bash_prog, bash_prog, NULL };

	posix_spawnattr_t sattr;
	T_ASSERT_POSIX_ZERO(posix_spawnattr_init(&sattr), "posix_spawnattr_init");
	T_ASSERT_POSIX_ZERO(posix_spawn(&pid, args[0], NULL, &sattr, args, NULL), "spawn exec_inprogress_child");

	struct scenario scenario = {
		.name = "exec_inprogress",
		.flags = (STACKSHOT_KCDATA_FORMAT),
		.target_pid = pid,
	};

	int tries = 0;
	int tries_limit = 30;
	__block bool found = false;
	__block uint64_t cid1 = 0, cid2 = 0;

	for (tries = 0; !found && tries < tries_limit; tries++) {
		take_stackshot(&scenario, false,
		    ^( void *ssbuf, size_t sslen) {
			parse_stackshot(PARSE_STACKSHOT_EXEC_INPROGRESS | PARSE_STACKSHOT_TARGETPID,
			    ssbuf, sslen, @{
				exec_inprogress_pid_key: @(pid),
				exec_inprogress_found_key: ^(uint64_t id1, uint64_t id2) { found = true; cid1 = id1; cid2 = id2; }});
		});
	}
	T_QUIET; T_ASSERT_POSIX_SUCCESS(kill(pid, SIGKILL), "killing exec loop");
	T_ASSERT_TRUE(found, "able to find our execing process mid-exec in %d tries", tries);
	T_ASSERT_NE(cid1, cid2, "container IDs for in-progress exec are unique");
	T_PASS("found mid-exec process in %d tries", tries);
}

#ifdef _LP64
#if __has_feature(ptrauth_calls)
#define __ptrauth_swift_async_context_parent \
  __ptrauth(ptrauth_key_process_independent_data, 1, 0xbda2)
#define __ptrauth_swift_async_context_resume \
  __ptrauth(ptrauth_key_function_pointer, 1, 0xd707)
#else
#define __ptrauth_swift_async_context_parent
#define __ptrauth_swift_async_context_resume
#endif
// Add 1 to match the symbolication aid added by the stackshot backtracer.
#define asyncstack_frame(x) ((uintptr_t)(void *)ptrauth_strip((void *)(x), ptrauth_key_function_pointer) + 1)

// This struct fakes the Swift AsyncContext struct which is used by
// the Swift concurrency runtime. We only care about the first 2 fields.
struct fake_async_context {
	struct fake_async_context* __ptrauth_swift_async_context_parent next;
	void(*__ptrauth_swift_async_context_resume resume_pc)(void);
};

static void
level1_func()
{
}
static void
level2_func()
{
}

// Create a chain of fake async contexts; sync with asyncstack_expected_stack below
static alignas(16) struct fake_async_context level1 = { 0, level1_func };
static alignas(16) struct fake_async_context level2 = { &level1, level2_func };

struct async_test_semaphores {
	dispatch_semaphore_t child_ready_sem;	/* signal parent we're ready */
	dispatch_semaphore_t child_exit_sem;	/* parent tells us to go away */
};

#define	ASYNCSTACK_THREAD_NAME "asyncstack_thread"

static void __attribute__((noinline, not_tail_called))
expect_asyncstack(void *arg)
{
	struct async_test_semaphores *async_ts = arg;

	T_QUIET; T_ASSERT_POSIX_ZERO(pthread_setname_np(ASYNCSTACK_THREAD_NAME),
	     "set thread name to %s", ASYNCSTACK_THREAD_NAME);

	/* Tell the main thread we're all set up, then wait for permission to exit */
	dispatch_semaphore_signal(async_ts->child_ready_sem);
	dispatch_semaphore_wait(async_ts->child_exit_sem, DISPATCH_TIME_FOREVER);
	usleep(1);	/* make sure we don't tailcall semaphore_wait */
}

static void *
asyncstack_thread(void *arg)
{
	uint64_t *fp = __builtin_frame_address(0);
	// We cannot use a variable of pointer type, because this ABI is valid
	// on arm64_32 where pointers are 32bits, but the context pointer will
	// still be stored in a 64bits slot on the stack.
#if __has_feature(ptrauth_calls)
#define __stack_context_auth __ptrauth(ptrauth_key_process_dependent_data, 1, \
	        0xc31a)
	struct fake_async_context * __stack_context_auth ctx = &level2;
#else // __has_feature(ptrauth_calls)
	/* struct fake_async_context * */uint64_t ctx  = (uintptr_t)&level2;
#endif // !__has_feature(ptrauth_calls)

	// The signature of an async frame on the OS stack is:
	// [ <AsyncContext address>, <Saved FP | (1<<60)>, <return address> ]
	// The Async context must be right before the saved FP on the stack. This
	// should happen naturally in an optimized build as it is the only
	// variable on the stack.
	// This function cannot use T_ASSERT_* becuse it changes the stack
	// layout.
	assert((uintptr_t)fp - (uintptr_t)&ctx == 8);

	// Modify the saved FP on the stack to include the async frame marker
	*fp |= (0x1ULL << 60);
	expect_asyncstack(arg);
	return NULL;
}

T_DECL(asyncstack, "test swift async stack entries", T_META_TAG_VM_PREFERRED)
{
	struct scenario scenario = {
		.name = "asyncstack",
		.flags = STACKSHOT_KCDATA_FORMAT | STACKSHOT_SAVE_LOADINFO,
	};
	struct async_test_semaphores async_ts = {
	    .child_ready_sem = dispatch_semaphore_create(0),
	    .child_exit_sem = dispatch_semaphore_create(0),
	};
	T_QUIET; T_ASSERT_NOTNULL(async_ts.child_ready_sem, "child_ready_sem alloc");
	T_QUIET; T_ASSERT_NOTNULL(async_ts.child_exit_sem, "child_exit_sem alloc");

	pthread_t pthread;
	__block uint64_t threadid = 0;
	T_QUIET; T_ASSERT_POSIX_ZERO(pthread_create(&pthread, NULL, asyncstack_thread, &async_ts), "pthread_create");
	T_QUIET; T_ASSERT_POSIX_ZERO(pthread_threadid_np(pthread, &threadid), "pthread_threadid_np");

	dispatch_semaphore_wait(async_ts.child_ready_sem, DISPATCH_TIME_FOREVER);

	take_stackshot(&scenario, true, ^( void *ssbuf, size_t sslen) {
		parse_stackshot(PARSE_STACKSHOT_ASYNCSTACK, ssbuf, sslen, @{
		    asyncstack_expected_threadid_key: @(threadid),
		       asyncstack_expected_stack_key: @[ @(asyncstack_frame(level2_func)), @(asyncstack_frame(level1_func)) ],
		});
	});

	dispatch_semaphore_signal(async_ts.child_exit_sem);
	T_QUIET; T_ASSERT_POSIX_ZERO(pthread_join(pthread, NULL), "wait for thread");

}
#endif /* #ifdef _LP64 */

static uint32_t
get_user_promotion_basepri(void)
{
	mach_msg_type_number_t count = THREAD_POLICY_STATE_COUNT;
	struct thread_policy_state thread_policy;
	boolean_t get_default = FALSE;
	mach_port_t thread_port = pthread_mach_thread_np(pthread_self());

	kern_return_t kr = thread_policy_get(thread_port, THREAD_POLICY_STATE,
	    (thread_policy_t)&thread_policy, &count, &get_default);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "thread_policy_get");
	return thread_policy.thps_user_promotion_basepri;
}

static int
get_pri(thread_t thread_port)
{
	kern_return_t kr;

	thread_extended_info_data_t extended_info;
	mach_msg_type_number_t count = THREAD_EXTENDED_INFO_COUNT;
	kr = thread_info(thread_port, THREAD_EXTENDED_INFO,
	    (thread_info_t)&extended_info, &count);

	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "thread_info");

	return extended_info.pth_curpri;
}


T_DECL(turnstile_singlehop, "turnstile single hop test", T_META_TAG_VM_PREFERRED)
{
	dispatch_queue_t dq1, dq2;
	dispatch_semaphore_t sema_x;
	dispatch_queue_attr_t dq1_attr, dq2_attr;
	__block qos_class_t main_qos = 0;
	__block int main_relpri = 0, main_relpri2 = 0, main_afterpri = 0;
	struct scenario scenario = {
		.name = "turnstile_singlehop",
		.flags = (STACKSHOT_THREAD_WAITINFO | STACKSHOT_KCDATA_FORMAT),
	};
	dq1_attr = dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL, QOS_CLASS_UTILITY, 0);
	dq2_attr = dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL, QOS_CLASS_USER_INITIATED, 0);
	pthread_mutex_t lock_a = PTHREAD_MUTEX_INITIALIZER;
	pthread_mutex_t lock_b = PTHREAD_MUTEX_INITIALIZER;

	pthread_mutex_t *lockap = &lock_a, *lockbp = &lock_b;

	dq1 = dispatch_queue_create("q1", dq1_attr);
	dq2 = dispatch_queue_create("q2", dq2_attr);
	sema_x = dispatch_semaphore_create(0);

	pthread_mutex_lock(lockap);
	dispatch_async(dq1, ^{
		pthread_mutex_lock(lockbp);
		T_ASSERT_POSIX_SUCCESS(pthread_get_qos_class_np(pthread_self(), &main_qos, &main_relpri), "get qos class");
		T_LOG("The priority of q1 is %d\n", get_pri(mach_thread_self()));
		dispatch_semaphore_signal(sema_x);
		pthread_mutex_lock(lockap);
	});
	dispatch_semaphore_wait(sema_x, DISPATCH_TIME_FOREVER);

	T_LOG("Async1 completed");

	pthread_set_qos_class_self_np(QOS_CLASS_UTILITY, 0);
	T_ASSERT_POSIX_SUCCESS(pthread_get_qos_class_np(pthread_self(), &main_qos, &main_relpri), "get qos class");
	T_LOG("The priority of main is %d\n", get_pri(mach_thread_self()));
	main_relpri = get_pri(mach_thread_self());

	dispatch_async(dq2, ^{
		T_ASSERT_POSIX_SUCCESS(pthread_get_qos_class_np(pthread_self(), &main_qos, &main_relpri2), "get qos class");
		T_LOG("The priority of q2 is %d\n", get_pri(mach_thread_self()));
		dispatch_semaphore_signal(sema_x);
		pthread_mutex_lock(lockbp);
	});
	dispatch_semaphore_wait(sema_x, DISPATCH_TIME_FOREVER);

	T_LOG("Async2 completed");

	while (1) {
		main_afterpri = (int) get_user_promotion_basepri();
		if (main_relpri != main_afterpri) {
			T_LOG("Success with promotion pri is %d", main_afterpri);
			break;
		}

		usleep(100);
	}

	take_stackshot(&scenario, true, ^( void *ssbuf, size_t sslen) {
		parse_stackshot(PARSE_STACKSHOT_TURNSTILEINFO, ssbuf, sslen, nil);
	});
}


static void
expect_instrs_cycles_in_stackshot(void *ssbuf, size_t sslen)
{
	kcdata_iter_t iter = kcdata_iter(ssbuf, sslen);

	bool in_task = false;
	bool in_thread = false;
	bool saw_instrs_cycles = false;
	iter = kcdata_iter_next(iter);

	KCDATA_ITER_FOREACH(iter) {
		switch (kcdata_iter_type(iter)) {
		case KCDATA_TYPE_CONTAINER_BEGIN:
			switch (kcdata_iter_container_type(iter)) {
			case STACKSHOT_KCCONTAINER_TASK:
				in_task = true;
				saw_instrs_cycles = false;
				break;

			case STACKSHOT_KCCONTAINER_THREAD:
				in_thread = true;
				saw_instrs_cycles = false;
				break;

			default:
				break;
			}
			break;

		case STACKSHOT_KCTYPE_INSTRS_CYCLES:
			saw_instrs_cycles = true;
			break;

		case KCDATA_TYPE_CONTAINER_END:
			if (in_thread) {
				T_QUIET; T_EXPECT_TRUE(saw_instrs_cycles,
						"saw instructions and cycles in thread");
				in_thread = false;
			} else if (in_task) {
				T_QUIET; T_EXPECT_TRUE(saw_instrs_cycles,
						"saw instructions and cycles in task");
				in_task = false;
			}

		default:
			break;
		}
	}
}

static void
skip_if_monotonic_unsupported(void)
{
	int supported = 0;
	size_t supported_size = sizeof(supported);
	int ret = sysctlbyname("kern.monotonic.supported", &supported,
			&supported_size, 0, 0);
	if (ret < 0 || !supported) {
		T_SKIP("monotonic is unsupported");
	}
}

T_DECL(instrs_cycles, "test a getting instructions and cycles in stackshot", T_META_TAG_VM_PREFERRED)
{
	skip_if_monotonic_unsupported();

	struct scenario scenario = {
		.name = "instrs-cycles",
		.flags = (STACKSHOT_SAVE_LOADINFO | STACKSHOT_INSTRS_CYCLES
				| STACKSHOT_KCDATA_FORMAT),
	};

	T_LOG("attempting to take stackshot with instructions and cycles");
	take_stackshot(&scenario, false, ^(void *ssbuf, size_t sslen) {
		parse_stackshot(0, ssbuf, sslen, nil);
		expect_instrs_cycles_in_stackshot(ssbuf, sslen);
	});
}

T_DECL(delta_instrs_cycles,
		"test delta stackshots with instructions and cycles", T_META_TAG_VM_PREFERRED)
{
	skip_if_monotonic_unsupported();

	struct scenario scenario = {
		.name = "delta-instrs-cycles",
		.flags = (STACKSHOT_SAVE_LOADINFO | STACKSHOT_INSTRS_CYCLES
				| STACKSHOT_KCDATA_FORMAT),
	};

	T_LOG("taking full stackshot");
	take_stackshot(&scenario, false, ^(void *ssbuf, size_t sslen) {
		uint64_t stackshot_time = stackshot_timestamp(ssbuf, sslen);

		T_LOG("taking delta stackshot since time %" PRIu64, stackshot_time);

		parse_stackshot(0, ssbuf, sslen, nil);
		expect_instrs_cycles_in_stackshot(ssbuf, sslen);

		struct scenario delta_scenario = {
			.name = "delta-instrs-cycles-next",
			.flags = (STACKSHOT_SAVE_LOADINFO | STACKSHOT_INSTRS_CYCLES
					| STACKSHOT_KCDATA_FORMAT
					| STACKSHOT_COLLECT_DELTA_SNAPSHOT),
			.since_timestamp = stackshot_time,
		};

		take_stackshot(&delta_scenario, false, ^(void *dssbuf, size_t dsslen) {
			parse_stackshot(PARSE_STACKSHOT_DELTA, dssbuf, dsslen, nil);
			expect_instrs_cycles_in_stackshot(dssbuf, dsslen);
		});
	});
}

static void
check_thread_groups_supported()
{
	int err;
	int supported = 0;
	size_t supported_size = sizeof(supported);
	err = sysctlbyname("kern.thread_groups_supported", &supported, &supported_size, NULL, 0);

	if (err || !supported)
		T_SKIP("thread groups not supported on this system");
}

T_DECL(thread_groups, "test getting thread groups in stackshot", T_META_TAG_VM_PREFERRED)
{
	check_thread_groups_supported();

	struct scenario scenario = {
		.name = "thread-groups",
		.flags = (STACKSHOT_SAVE_LOADINFO | STACKSHOT_THREAD_GROUP
				| STACKSHOT_KCDATA_FORMAT),
	};

	T_LOG("attempting to take stackshot with thread group flag");
	take_stackshot(&scenario, false, ^(void *ssbuf, size_t sslen) {
		parse_thread_group_stackshot(ssbuf, sslen);
	});
}

T_DECL(compactinfo, "test compactinfo inclusion", T_META_TAG_VM_PREFERRED)
{
	struct scenario scenario = {
		.name = "compactinfo",
		.target_pid = getpid(),
		.flags = (STACKSHOT_SAVE_LOADINFO | STACKSHOT_SAVE_DYLD_COMPACTINFO
				| STACKSHOT_KCDATA_FORMAT),
	};

	T_LOG("attempting to take stackshot with compactinfo flag");
	take_stackshot(&scenario, false, ^(void *ssbuf, size_t sslen) {
		parse_stackshot(PARSE_STACKSHOT_COMPACTINFO | PARSE_STACKSHOT_TARGETPID, ssbuf, sslen, nil);
	});
}

T_DECL(suspendinfo, "test task suspend info inclusion", T_META_TAG_VM_PREFERRED)
{
	struct scenario scenario = {
		.name = "suspendinfo",
		.target_pid = getpid(),
		.flags = (STACKSHOT_SAVE_LOADINFO | STACKSHOT_KCDATA_FORMAT),
	};

	T_LOG("attempting to take stackshot with suspendinfo flag");
	take_stackshot(&scenario, false, ^(void *ssbuf, size_t sslen) {
		parse_stackshot(PARSE_STACKSHOT_SUSPENDINFO | PARSE_STACKSHOT_TARGETPID, ssbuf, sslen, nil);
	});
}

static NSMutableSet * find_driverkit_pids(io_registry_entry_t root) {
	NSMutableSet * driverkit_pids = [NSMutableSet setWithCapacity:3];
	io_registry_entry_t current = IO_OBJECT_NULL;
	io_iterator_t iter = IO_OBJECT_NULL;

	T_EXPECT_MACH_SUCCESS(IORegistryEntryGetChildIterator(root, kIOServicePlane, &iter), "get registry iterator");

	while ((current = IOIteratorNext(iter)) != IO_OBJECT_NULL) {
		if (_IOObjectConformsTo(current, "IOUserServer", kIOClassNameOverrideNone)) {
			CFMutableDictionaryRef cfProperties = NULL;
			NSMutableDictionary * properties;
			NSString * client_creator_info;
			NSArray<NSString *> *creator_info_array;
			pid_t pid;

			T_QUIET; T_EXPECT_MACH_SUCCESS(IORegistryEntryCreateCFProperties(current, &cfProperties, kCFAllocatorDefault, kNilOptions), "get properties");
			properties = CFBridgingRelease(cfProperties);
			T_QUIET; T_ASSERT_NOTNULL(properties, "properties is not null");
			client_creator_info = properties[@kIOUserClientCreatorKey];
			creator_info_array = [client_creator_info componentsSeparatedByString:@","];
			if ([creator_info_array[0] hasPrefix:@"pid"]) {
				NSArray<NSString *> *pid_info = [creator_info_array[0] componentsSeparatedByString:@" "];
				T_QUIET; T_ASSERT_EQ(pid_info.count, 2UL, "Get pid info components from %s", creator_info_array[0].UTF8String);
				pid = pid_info[1].intValue;
			} else {
				T_ASSERT_FAIL("No pid info in client creator info: %s", client_creator_info.UTF8String);
			}
			T_LOG("Found driver pid %d", pid);
			[driverkit_pids addObject:[NSNumber numberWithInt:pid]];
		} else {
			[driverkit_pids unionSet:find_driverkit_pids(current)];
		}
		IOObjectRelease(current);
	}

	IOObjectRelease(iter);
	return driverkit_pids;
}

T_DECL(driverkit, "test driverkit inclusion", T_META_TAG_VM_PREFERRED)
{
	struct scenario scenario = {
		.name = "driverkit",
		.target_kernel = true,
		.flags = (STACKSHOT_SAVE_LOADINFO | STACKSHOT_KCDATA_FORMAT
			    | STACKSHOT_INCLUDE_DRIVER_THREADS_IN_KERNEL),
	};

	io_registry_entry_t root = IORegistryGetRootEntry(kIOMainPortDefault);
	NSMutableSet * driverkit_pids = find_driverkit_pids(root);
	IOObjectRelease(root);

	T_LOG("expecting to find %lu driverkit processes", [driverkit_pids count]);
	T_LOG("attempting to take stackshot with STACKSHOT_INCLUDE_DRIVER_THREADS_IN_KERNEL flag");
	take_stackshot(&scenario, false, ^(void *ssbuf, size_t sslen) {
		parse_stackshot(PARSE_STACKSHOT_DRIVERKIT | PARSE_STACKSHOT_TARGETPID, ssbuf, sslen, @{
			driverkit_found_key: ^(pid_t pid) {
				[driverkit_pids removeObject:[NSNumber numberWithInt:pid]];
		}});
	});

	T_EXPECT_EQ([driverkit_pids count], (NSUInteger)0, "found expected number of driverkit processes");
}

static void
parse_page_table_asid_stackshot(void **ssbuf, size_t sslen)
{
	bool seen_asid = false;
	bool seen_page_table_snapshot = false;
	bool seen_task = false;
	int container = 0;
	int task_container = -1;
	kcdata_iter_t iter = kcdata_iter(ssbuf, sslen);
	T_ASSERT_EQ(kcdata_iter_type(iter), KCDATA_BUFFER_BEGIN_STACKSHOT,
			"buffer provided is a stackshot");

	iter = kcdata_iter_next(iter);
	KCDATA_ITER_FOREACH(iter) {
		switch (kcdata_iter_type(iter)) {
		/* There's a slight chance that we see a transit version of this task
		 * in the stackshot, so we want to make sure to check both */
		case KCDATA_TYPE_CONTAINER_BEGIN: {
			container++;
			if (kcdata_iter_container_type(iter) == STACKSHOT_KCCONTAINER_TASK) {
				seen_asid = seen_page_table_snapshot = false;
				task_container = container;
			}
			break;
		}
		case KCDATA_TYPE_CONTAINER_END: {
			if (container == task_container) {
				task_container = -1;
				seen_task = true;
				T_ASSERT_TRUE(seen_page_table_snapshot, "check that we have seen a page table snapshot");
				T_ASSERT_TRUE(seen_asid, "check that we have seen an ASID");
			}
			container--;
			break;
		}
		case KCDATA_TYPE_ARRAY: {
			T_QUIET;
			T_ASSERT_TRUE(kcdata_iter_array_valid(iter),
					"checked that array is valid");

			if (kcdata_iter_array_elem_type(iter) != STACKSHOT_KCTYPE_PAGE_TABLES) {
				continue;
			}

			T_ASSERT_FALSE(seen_page_table_snapshot, "check that we haven't yet seen a page table snapshot");
			seen_page_table_snapshot = true;

			T_ASSERT_EQ((size_t) kcdata_iter_array_elem_size(iter), sizeof(uint64_t),
				"check that each element of the pagetable dump is the expected size");

			uint64_t *pt_array = kcdata_iter_payload(iter);
			uint32_t elem_count = kcdata_iter_array_elem_count(iter);
			uint32_t j;
			bool nonzero_tte = false;
			for (j = 0; j < elem_count;) {
				T_QUIET; T_ASSERT_LE(j + 4, elem_count, "check for valid page table segment header");
				uint64_t pa = pt_array[j];
				uint64_t num_entries = pt_array[j + 1];
				uint64_t start_va = pt_array[j + 2];
				uint64_t end_va = pt_array[j + 3];

				T_QUIET; T_ASSERT_NE(pa, (uint64_t) 0, "check that the pagetable physical address is non-zero");
				T_QUIET; T_ASSERT_EQ(pa % (num_entries * sizeof(uint64_t)), (uint64_t) 0, "check that the pagetable physical address is correctly aligned");
				T_QUIET; T_ASSERT_NE(num_entries, (uint64_t) 0, "check that a pagetable region has more than 0 entries");
				T_QUIET; T_ASSERT_LE(j + 4 + num_entries, (uint64_t) elem_count, "check for sufficient space in page table array");
				T_QUIET; T_ASSERT_GT(end_va, start_va, "check for valid VA bounds in page table segment header");

				for (uint32_t k = j + 4; k < (j + 4 + num_entries); ++k) {
					if (pt_array[k] != 0) {
						nonzero_tte = true;
						T_QUIET; T_ASSERT_EQ((pt_array[k] >> 48) & 0xf, (uint64_t) 0, "check that bits[48:51] of arm64 TTE are clear");
						// L0-L2 table and non-compressed L3 block entries should always have bit 1 set; assumes L0-L2 blocks will not be used outside the kernel
						bool table = ((pt_array[k] & 0x2) != 0);
						if (table) {
							T_QUIET; T_ASSERT_NE(pt_array[k] & ((1ULL << 48) - 1) & ~((1ULL << 12) - 1), (uint64_t) 0, "check that arm64 TTE physical address is non-zero");
						} else { // should be a compressed PTE
							T_QUIET; T_ASSERT_NE(pt_array[k] & 0xC000000000000000ULL, (uint64_t) 0, "check that compressed PTE has at least one of bits [63:62] set");
							T_QUIET; T_ASSERT_EQ(pt_array[k] & ~0xC000000000000000ULL, (uint64_t) 0, "check that compressed PTE has no other bits besides [63:62] set");
						}
					}
				}

				j += (4 + num_entries);
			}
			T_ASSERT_TRUE(nonzero_tte, "check that we saw at least one non-empty TTE");
			T_ASSERT_EQ(j, elem_count, "check that page table dump size matches extent of last header");
			break;
		}
		case STACKSHOT_KCTYPE_ASID: {
			T_ASSERT_FALSE(seen_asid, "check that we haven't yet seen an ASID");
			seen_asid = true;
		}
		}
	}

	T_QUIET; T_ASSERT_TRUE(seen_task, "check that we have seen a complete task container");
}

T_DECL(dump_page_tables, "test stackshot page table dumping support", T_META_TAG_VM_PREFERRED)
{
	struct scenario scenario = {
		.name = "asid-page-tables",
		.flags = (STACKSHOT_KCDATA_FORMAT | STACKSHOT_ASID | STACKSHOT_PAGE_TABLES),
		.size_hint = (9ull << 20), // 9 MB
		.target_pid = getpid(),
		.maybe_unsupported = true,
		.maybe_enomem = true,
	};

	T_LOG("attempting to take stackshot with ASID and page table flags");
	take_stackshot(&scenario, false, ^(void *ssbuf, size_t sslen) {
		parse_page_table_asid_stackshot(ssbuf, sslen);
	});
}

static void stackshot_verify_current_proc_uuid_info(void **ssbuf, size_t sslen, uint64_t expected_offset, const struct proc_uniqidentifierinfo *proc_info_data)
{
	const uuid_t *current_uuid = (const uuid_t *)(&proc_info_data->p_uuid);

	kcdata_iter_t iter = kcdata_iter(ssbuf, sslen);
	T_ASSERT_EQ(kcdata_iter_type(iter), KCDATA_BUFFER_BEGIN_STACKSHOT, "buffer provided is a stackshot");

	iter = kcdata_iter_next(iter);

	KCDATA_ITER_FOREACH(iter) {
		switch (kcdata_iter_type(iter)) {
			case KCDATA_TYPE_ARRAY: {
				T_QUIET; T_ASSERT_TRUE(kcdata_iter_array_valid(iter), "checked that array is valid");
				if (kcdata_iter_array_elem_type(iter) == KCDATA_TYPE_LIBRARY_LOADINFO64) {
					struct user64_dyld_uuid_info *info = (struct user64_dyld_uuid_info *) kcdata_iter_payload(iter);
					if (uuid_compare(*current_uuid, info->imageUUID) == 0) {
						T_ASSERT_EQ(expected_offset, info->imageLoadAddress, "found matching UUID with matching binary offset");
						return;
					}
				} else if (kcdata_iter_array_elem_type(iter) == KCDATA_TYPE_LIBRARY_LOADINFO) {
					struct user32_dyld_uuid_info *info = (struct user32_dyld_uuid_info *) kcdata_iter_payload(iter);
					if (uuid_compare(*current_uuid, info->imageUUID) == 0) {
						T_ASSERT_EQ(expected_offset, ((uint64_t) info->imageLoadAddress),  "found matching UUID with matching binary offset");
						return;
					}
				}
				break;
			}
			default:
				break;
		}
	}

	T_FAIL("failed to find matching UUID in stackshot data");
}

T_DECL(translated,
    "tests translated bit is set correctly",
    T_META_TAG_VM_PREFERRED,
    T_META_ENABLED(false /* rdar://133956022 */))
{
#if !(TARGET_OS_OSX && TARGET_CPU_ARM64)
	T_SKIP("Only valid on Apple silicon Macs")
#endif
	// Get path of stackshot_translated_child helper binary
	char path[PATH_MAX];
	uint32_t path_size = sizeof(path);
	T_QUIET; T_ASSERT_POSIX_ZERO(_NSGetExecutablePath(path, &path_size), "_NSGetExecutablePath");
	char* binary_name = strrchr(path, '/');
	if (binary_name) binary_name++;
	T_QUIET; T_ASSERT_NOTNULL(binary_name, "Find basename in path '%s'", path);
	strlcpy(binary_name, "stackshot_translated_child", path_size - (binary_name - path));
	char *args[] = { path, NULL };

	dispatch_source_t child_sig_src;
	dispatch_semaphore_t child_ready_sem = dispatch_semaphore_create(0);
	T_QUIET; T_ASSERT_NOTNULL(child_ready_sem, "exec child semaphore");

	dispatch_queue_t signal_processing_q = dispatch_queue_create("signal processing queue", NULL);
	T_QUIET; T_ASSERT_NOTNULL(signal_processing_q, "signal processing queue");

	signal(SIGUSR1, SIG_IGN);
	child_sig_src = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGUSR1, 0, signal_processing_q);
	T_QUIET; T_ASSERT_NOTNULL(child_sig_src, "dispatch_source_create (child_sig_src)");

	dispatch_source_set_event_handler(child_sig_src, ^{ dispatch_semaphore_signal(child_ready_sem); });
	dispatch_activate(child_sig_src);

	// Spawn child
	pid_t pid;
	T_LOG("spawning translated child");
	T_QUIET; T_ASSERT_POSIX_ZERO(posix_spawn(&pid, args[0], NULL, NULL, args, NULL), "spawned process '%s' with PID %d", args[0], pid);

	// Wait for the the child to spawn up
	dispatch_semaphore_wait(child_ready_sem, DISPATCH_TIME_FOREVER);

	// Make sure the child is running and is translated
	int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, pid };
	struct kinfo_proc process_info;
	size_t bufsize = sizeof(process_info);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(sysctl(mib, (unsigned)(sizeof(mib)/sizeof(int)), &process_info, &bufsize, NULL, 0), "get translated child process info");
	T_QUIET; T_ASSERT_GT(bufsize, (size_t)0, "process info is not empty");
	T_QUIET; T_ASSERT_TRUE((process_info.kp_proc.p_flag & P_TRANSLATED), "KERN_PROC_PID reports child is translated");

	T_LOG("capturing stackshot");

	struct scenario scenario = {
		.name = "translated",
		.flags = (STACKSHOT_SAVE_LOADINFO | STACKSHOT_GET_GLOBAL_MEM_STATS
				  | STACKSHOT_SAVE_IMP_DONATION_PIDS | STACKSHOT_KCDATA_FORMAT),
	};

	take_stackshot(&scenario, true, ^( void *ssbuf, size_t sslen) {
		parse_stackshot(PARSE_STACKSHOT_TRANSLATED, ssbuf, sslen, @{translated_child_pid_key: @(pid)});
	});

    // Kill the child
    int status;
    T_QUIET; T_ASSERT_POSIX_SUCCESS(kill(pid, SIGTERM), "kill translated child");
    T_QUIET; T_ASSERT_POSIX_SUCCESS(waitpid(pid, &status, 0), "waitpid on translated child");

}

T_DECL(proc_uuid_info, "tests that the main binary UUID for a proc is always populated", T_META_TAG_VM_PREFERRED)
{
	struct proc_uniqidentifierinfo proc_info_data = { };
	mach_msg_type_number_t      count;
	kern_return_t               kernel_status;
	task_dyld_info_data_t       task_dyld_info;
	struct dyld_all_image_infos *target_infos;
	int retval;
	bool found_image_in_image_infos = false;
	uint64_t expected_mach_header_offset = 0;

	/* Find the UUID of our main binary */
	retval = proc_pidinfo(getpid(), PROC_PIDUNIQIDENTIFIERINFO, 0, &proc_info_data, sizeof(proc_info_data));
	T_QUIET; T_EXPECT_POSIX_SUCCESS(retval, "proc_pidinfo PROC_PIDUNIQIDENTIFIERINFO");
	T_QUIET; T_ASSERT_EQ_INT(retval, (int) sizeof(proc_info_data), "proc_pidinfo PROC_PIDUNIQIDENTIFIERINFO returned data");

	uuid_string_t str = {};
	uuid_unparse(*(uuid_t*)&proc_info_data.p_uuid, str);
	T_LOG("Found current UUID is %s", str);

	/* Find the location of the dyld image info metadata */
	count = TASK_DYLD_INFO_COUNT;
	kernel_status = task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&task_dyld_info, &count);
	T_QUIET; T_ASSERT_EQ(kernel_status, KERN_SUCCESS, "retrieve task_info for TASK_DYLD_INFO");

	target_infos = (struct dyld_all_image_infos *)task_dyld_info.all_image_info_addr;

	/* Find our binary in the dyld image info array */
	for (int i = 0; i < (int) target_infos->uuidArrayCount; i++) {
		if (uuid_compare(target_infos->uuidArray[i].imageUUID, *(uuid_t*)&proc_info_data.p_uuid) == 0) {
			expected_mach_header_offset = (uint64_t) target_infos->uuidArray[i].imageLoadAddress;
			found_image_in_image_infos = true;
		}
	}

	T_ASSERT_TRUE(found_image_in_image_infos, "found binary image in dyld image info list");

	/* Overwrite the dyld image info data so the kernel has to fallback to the UUID stored in the proc structure */
	target_infos->uuidArrayCount = 0;

	struct scenario scenario = {
		.name = "proc_uuid_info",
		.flags = (STACKSHOT_SAVE_LOADINFO | STACKSHOT_KCDATA_FORMAT),
		.target_pid = getpid(),
	};

	T_LOG("attempting to take stackshot for current PID");
	take_stackshot(&scenario, false, ^(void *ssbuf, size_t sslen) {
		stackshot_verify_current_proc_uuid_info(ssbuf, sslen, expected_mach_header_offset, &proc_info_data);
	});
}

T_DECL(cseg_waitinfo, "test that threads stuck in the compressor report correct waitinfo", T_META_TAG_VM_PREFERRED)
{
	struct scenario scenario = {
		.name = "cseg_waitinfo",
		.quiet = false,
		.flags = (STACKSHOT_THREAD_WAITINFO | STACKSHOT_KCDATA_FORMAT),
	};
	__block uint64_t thread_id = 0;

	dispatch_queue_t dq = dispatch_queue_create("com.apple.stackshot.cseg_waitinfo", NULL);
	dispatch_semaphore_t child_ok = dispatch_semaphore_create(0);

	dispatch_async(dq, ^{
		pthread_threadid_np(NULL, &thread_id);
		dispatch_semaphore_signal(child_ok);
		int val = 1;
		T_ASSERT_POSIX_SUCCESS(sysctlbyname("kern.cseg_wedge_thread", NULL, NULL, &val, sizeof(val)), "wedge child thread");
	});

	dispatch_semaphore_wait(child_ok, DISPATCH_TIME_FOREVER);
	sleep(1);

	T_LOG("taking stackshot");
	take_stackshot(&scenario, false, ^(void *ssbuf, size_t sslen) {
		int val = 1;
		T_ASSERT_POSIX_SUCCESS(sysctlbyname("kern.cseg_unwedge_thread", NULL, NULL, &val, sizeof(val)), "unwedge child thread");
		parse_stackshot(PARSE_STACKSHOT_WAITINFO_CSEG, ssbuf, sslen, @{cseg_expected_threadid_key: @(thread_id)});
	});
}

static void
srp_send(
	mach_port_t send_port,
	mach_port_t reply_port,
	mach_port_t msg_port)
{
	kern_return_t ret = 0;

	struct test_msg {
		mach_msg_header_t header;
		mach_msg_body_t body;
		mach_msg_port_descriptor_t port_descriptor;
	};
	struct test_msg send_msg = {
		.header = {
			.msgh_remote_port = send_port,
			.msgh_local_port  = reply_port,
			.msgh_bits        = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND,
	    reply_port ? MACH_MSG_TYPE_MAKE_SEND_ONCE : 0,
	    MACH_MSG_TYPE_MOVE_SEND,
	    MACH_MSGH_BITS_COMPLEX),
			.msgh_id          = 0x100,
			.msgh_size        = sizeof(send_msg),
		},
		.body = {
			.msgh_descriptor_count = 1,
		},
		.port_descriptor = {
			.name        = msg_port,
			.disposition = MACH_MSG_TYPE_MOVE_RECEIVE,
			.type        = MACH_MSG_PORT_DESCRIPTOR,
		},
	};

	if (msg_port == MACH_PORT_NULL) {
		send_msg.body.msgh_descriptor_count = 0;
	}

	ret = mach_msg(&(send_msg.header),
	    MACH_SEND_MSG |
	    MACH_SEND_TIMEOUT |
	    MACH_SEND_OVERRIDE,
	    send_msg.header.msgh_size,
	    0,
	    MACH_PORT_NULL,
	    10000,
	    0);

	T_ASSERT_MACH_SUCCESS(ret, "client mach_msg");
}

T_HELPER_DECL(srp_client,
    "Client used for the special_reply_port test")
{
	pid_t ppid = getppid();
	dispatch_semaphore_t can_continue  = dispatch_semaphore_create(0);
	dispatch_queue_t dq = dispatch_queue_create("client_signalqueue", NULL);
	dispatch_source_t sig_src;

	mach_msg_return_t mr;
	mach_port_t service_port;
	mach_port_t conn_port;
	mach_port_t special_reply_port;
	mach_port_options_t opts = {
		.flags = MPO_INSERT_SEND_RIGHT,
	};

	signal(SIGUSR1, SIG_IGN);
	sig_src = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGUSR1, 0, dq);

	dispatch_source_set_event_handler(sig_src, ^{
			dispatch_semaphore_signal(can_continue);
	});
	dispatch_activate(sig_src);

	/* lookup the mach service port for the parent */
	kern_return_t kr = bootstrap_look_up(bootstrap_port,
	    SRP_SERVICE_NAME, &service_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "client bootstrap_look_up");

	/* create the send-once right (special reply port) and message to send to the server */
	kr = mach_port_construct(mach_task_self(), &opts, 0ull, &conn_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_construct");

	special_reply_port = thread_get_special_reply_port();
	T_QUIET; T_ASSERT_TRUE(MACH_PORT_VALID(special_reply_port), "get_thread_special_reply_port");

	/* send the message with the special reply port */
	srp_send(service_port, special_reply_port, conn_port);

	/* signal the parent to continue */
	kill(ppid, SIGUSR1);

	struct {
		mach_msg_header_t header;
		mach_msg_body_t body;
		mach_msg_port_descriptor_t port_descriptor;
	} rcv_msg = {
		.header =
		{
			.msgh_remote_port = MACH_PORT_NULL,
			.msgh_local_port  = special_reply_port,
			.msgh_size        = sizeof(rcv_msg),
		},
	};

	/* wait on the reply from the parent (that we will never receive) */
	mr = mach_msg(&(rcv_msg.header),
			(MACH_RCV_MSG | MACH_RCV_SYNC_WAIT),
			0,
			rcv_msg.header.msgh_size,
			special_reply_port,
			MACH_MSG_TIMEOUT_NONE,
			service_port);

	/* not expected to execute as parent will SIGKILL client... */
	T_LOG("client process exiting after sending message to parent (server)");
}

enum srp_test_type {
	SRP_TEST_THREAD,	/* expect waiter on current thread */
	SRP_TEST_PID,		/* expect waiter on current PID */
	SRP_TEST_EITHER,	/* waiter could be on either */
};

static void
check_srp_test(const char *name, enum srp_test_type ty)
{
	struct scenario scenario = {
		.name = name,
		.quiet = false,
		.flags = (STACKSHOT_THREAD_WAITINFO | STACKSHOT_KCDATA_FORMAT),
	};
	uint64_t thread_id = 0;
	pthread_threadid_np(NULL, &thread_id);
	if (ty == SRP_TEST_THREAD) {
		take_stackshot(&scenario, false, ^(void *ssbuf, size_t sslen) {
			parse_stackshot(PARSE_STACKSHOT_WAITINFO_SRP, ssbuf, sslen,
					@{srp_expected_threadid_key: @(thread_id)});
		});
	} else if (ty == SRP_TEST_PID) {
		take_stackshot(&scenario, false, ^(void *ssbuf, size_t sslen) {
			parse_stackshot(PARSE_STACKSHOT_WAITINFO_SRP, ssbuf, sslen,
					@{srp_expected_pid_key: @(getpid())});
		});
	} else {
		take_stackshot(&scenario, false, ^(void *ssbuf, size_t sslen) {
			parse_stackshot(PARSE_STACKSHOT_WAITINFO_SRP, ssbuf, sslen,
					@{srp_expected_pid_key: @(getpid()), srp_expected_threadid_key: @(thread_id)});
		});
	}

}


/*
 * Tests the stackshot wait info plumbing for synchronous IPC that doesn't use kevent on the server.
 *
 * (part 1): tests the scenario where a client sends a request that includes a special reply port
 *           to a server that doesn't receive the message and doesn't copy the send-once right
 *           into its address space as a result. for this case the special reply port is enqueued
 *           in a port and we check which task has that receive right and use that info. (rdar://60440338)
 * (part 2): tests the scenario where a client sends a request that includes a special reply port
 *           to a server that receives the message and copies in the send-once right, but doesn't
 *           reply to the client. for this case the special reply port is copied out and the kernel
 *           stashes the info about which task copied out the send once right. (rdar://60440592)
 * (part 3): tests the same as part 2, but uses kevents, which allow for
 *           priority inheritance
 */
T_DECL(special_reply_port, "test that tasks using special reply ports have correct waitinfo", T_META_TAG_VM_PREFERRED)
{
	dispatch_semaphore_t can_continue  = dispatch_semaphore_create(0);
	dispatch_queue_t dq = dispatch_queue_create("signalqueue", NULL);
	dispatch_queue_t machdq = dispatch_queue_create("machqueue", NULL);
	dispatch_source_t sig_src;
	char path[PATH_MAX];
	uint32_t path_size = sizeof(path);
	T_ASSERT_POSIX_ZERO(_NSGetExecutablePath(path, &path_size), "_NSGetExecutablePath");
	char *client_args[] = { path, "-n", "srp_client", NULL };
	pid_t client_pid;
	int sp_ret;
	kern_return_t kr;
	mach_port_t port;

	/* setup the signal handler in the parent (server) */
	T_LOG("setup sig handlers");
	signal(SIGUSR1, SIG_IGN);
	sig_src = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGUSR1, 0, dq);

	dispatch_source_set_event_handler(sig_src, ^{
			dispatch_semaphore_signal(can_continue);
	});
	dispatch_activate(sig_src);

	/* register with the mach service name so the client can lookup and send a message to the parent (server) */
	T_LOG("Server about to check in");
	kr = bootstrap_check_in(bootstrap_port, SRP_SERVICE_NAME, &port);
	T_ASSERT_MACH_SUCCESS(kr, "server bootstrap_check_in");

	T_LOG("Launching client");
	sp_ret = posix_spawn(&client_pid, client_args[0], NULL, NULL, client_args, NULL);
	T_QUIET; T_ASSERT_POSIX_ZERO(sp_ret, "spawned process '%s' with PID %d", client_args[0], client_pid);
	T_LOG("Spawned client as PID %d", client_pid);

	dispatch_semaphore_wait(can_continue, DISPATCH_TIME_FOREVER);
	T_LOG("Ready to take stackshot, but waiting 1s for the coast to clear");

	/*
	 * can_continue indicates the client has signaled us, but we want to make
	 * sure they've actually blocked sending their mach message.  It's cheesy, but
	 * sleep() works for this.
	 */
	sleep(1);

	/*
	 * take the stackshot without calling receive to verify that the stackshot wait
	 * info shows our (the server) thread for the scenario where the server has yet to
	 * receive the message.
	 */
	T_LOG("Taking stackshot for part 1 coverage");
	check_srp_test("srp", SRP_TEST_THREAD);

	/*
	 * receive the message from the client (which should copy the send once right into
	 * our address space).
	 */
	struct {
		mach_msg_header_t header;
		mach_msg_body_t body;
		mach_msg_port_descriptor_t port_descriptor;
	} rcv_msg = {
		.header =
		{
			.msgh_remote_port = MACH_PORT_NULL,
			.msgh_local_port  = port,
			.msgh_size        = sizeof(rcv_msg),
		},
	};

	T_LOG("server: starting sync receive\n");

	mach_msg_return_t mr;
	mr = mach_msg(&(rcv_msg.header),
			(MACH_RCV_MSG | MACH_RCV_TIMEOUT),
			0,
			4096,
			port,
			10000,
			MACH_PORT_NULL);
	T_QUIET; T_ASSERT_MACH_SUCCESS(mr, "mach_msg() recieve of message from client");

	/*
	 * take the stackshot to verify that the stackshot wait info shows our (the server) PID
	 * for the scenario where the server has received the message and copied in the send-once right.
	 */
	T_LOG("Taking stackshot for part 2 coverage");
	check_srp_test("srp", SRP_TEST_PID);

	/* cleanup - kill the client */
	T_ASSERT_POSIX_SUCCESS(kill(client_pid, SIGKILL), "killing client");
	T_ASSERT_POSIX_SUCCESS(waitpid(client_pid, NULL, 0), "waiting for the client to exit");

	// do it again, but using kevents
	T_LOG("Launching client");
	sp_ret = posix_spawn(&client_pid, client_args[0], NULL, NULL, client_args, NULL);
	T_QUIET; T_ASSERT_POSIX_ZERO(sp_ret, "spawned process '%s' with PID %d", client_args[0], client_pid);
	T_LOG("Spawned client as PID %d", client_pid);

	dispatch_semaphore_wait(can_continue, DISPATCH_TIME_FOREVER);
	T_LOG("Ready to take stackshot, but waiting 1s for the coast to clear");

	/*
	 * can_continue indicates the client has signaled us, but we want to make
	 * sure they've actually blocked sending their mach message.  It's cheesy, but
	 * sleep() works for this.
	 */
	sleep(1);

	dispatch_mach_t dispatch_mach = dispatch_mach_create(SRP_SERVICE_NAME, machdq,
	    ^(dispatch_mach_reason_t reason,
	      dispatch_mach_msg_t message,
	      mach_error_t error __unused) {
		switch (reason) {
		case DISPATCH_MACH_MESSAGE_RECEIVED: {
			size_t size = 0;
			mach_msg_header_t *msg __unused = dispatch_mach_msg_get_msg(message, &size);
			T_LOG("server: recieved %ld byte message", size);
			check_srp_test("turnstile_port_thread", SRP_TEST_THREAD);
			T_LOG("server: letting client go");
			// drop the message on the ground, we'll kill the client later
			dispatch_semaphore_signal(can_continue);
			break;
		}
		default:
			break;
		}
	});

	dispatch_mach_connect(dispatch_mach, port, MACH_PORT_NULL, NULL);

	dispatch_semaphore_wait(can_continue, DISPATCH_TIME_FOREVER);

	/* cleanup - kill the client */
	T_ASSERT_POSIX_SUCCESS(kill(client_pid, SIGKILL), "killing client");
	T_ASSERT_POSIX_SUCCESS(waitpid(client_pid, NULL, 0), "waiting for the client to exit");
}

T_HELPER_DECL(throtlled_sp_client,
	"client that uses a connection port to send a message to a server")
{
	mach_port_t conn_port, service_port, reply_port, *stash;
	mach_msg_type_number_t stash_cnt = 0;

	kern_return_t kr = mach_ports_lookup(mach_task_self(), &stash, &stash_cnt);
	T_ASSERT_MACH_SUCCESS(kr, "mach_ports_lookup");

	service_port = stash[0];
	T_ASSERT_TRUE(MACH_PORT_VALID(service_port), "valid service port");
	mig_deallocate((vm_address_t)stash, stash_cnt * sizeof(stash[0]));

	mach_port_options_t opts = {
		.flags = MPO_INSERT_SEND_RIGHT
			| MPO_CONNECTION_PORT,
		.service_port_name = service_port,
	};

	kr = mach_port_construct(mach_task_self(), &opts, 0ull, &conn_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_construct");

	mach_port_options_t opts2 = {
		.flags = MPO_REPLY_PORT
	};
	kr = mach_port_construct(mach_task_self(), &opts2, 0ull, &reply_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_construct");

	/* XPC-like check-in message */
	struct {
		mach_msg_header_t header;
		mach_msg_port_descriptor_t recvp;
		mach_msg_port_descriptor_t sendp;
	} checkin_message = {
		.header =
		{
			.msgh_remote_port = service_port,
			.msgh_local_port = MACH_PORT_NULL,
			.msgh_size = sizeof(checkin_message),
			.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0),
		},
		.recvp =
		{
			.type = MACH_MSG_PORT_DESCRIPTOR,
			.name = conn_port,
			.disposition = MACH_MSG_TYPE_MOVE_RECEIVE,
		},
		.sendp =
		{
			.type = MACH_MSG_PORT_DESCRIPTOR,
			.name = reply_port,
			.disposition = MACH_MSG_TYPE_MAKE_SEND,
		}
	};
	dispatch_mach_msg_t dmsg = dispatch_mach_msg_create((mach_msg_header_t *)&checkin_message, sizeof(checkin_message),
		DISPATCH_MACH_MSG_DESTRUCTOR_DEFAULT, NULL);

	dispatch_queue_t machdq = dispatch_queue_create("machqueue", NULL);
	dispatch_mach_t dchannel = dispatch_mach_create(THROTTLED_SERVICE_NAME, machdq,
		^(dispatch_mach_reason_t reason,
	      dispatch_mach_msg_t message __unused,
	      mach_error_t error __unused) {
		switch (reason) {
			case DISPATCH_MACH_CONNECTED:
				T_LOG("mach channel connected");
				break;
			case DISPATCH_MACH_MESSAGE_SENT:
				T_LOG("sent mach message");
				break;
			default:
				T_ASSERT_FAIL("Unexpected reply to channel reason %lu", reason);
		}
	});
	dispatch_mach_connect(dchannel, reply_port, service_port, dmsg);
	dispatch_release(dmsg);

	struct {
		mach_msg_header_t header;
		uint64_t request_id;
	} request = {
		.header =
		{
			.msgh_size = sizeof(request),
			.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE),
		},
		.request_id = 1,
	};
	dispatch_mach_msg_t dmsg2 = dispatch_mach_msg_create((mach_msg_header_t *)&request, sizeof(request),
		DISPATCH_MACH_MSG_DESTRUCTOR_DEFAULT, NULL);

	dispatch_mach_reason_t reason;
	mach_error_t error;

	/* send the check-in message and the request message */
	dispatch_mach_msg_t dreply = dispatch_mach_send_with_result_and_wait_for_reply(dchannel,
			dmsg2, 0, DISPATCH_MACH_SEND_DEFAULT, &reason, &error);
	dispatch_release(dmsg2);

	/* not expected to execute as parent will SIGKILL client */
	T_ASSERT_FAIL("client process exiting after receiving %s reply", dreply ? "non-null" : "null");
}

static void
check_throttled_sp(const char *test_name, uint64_t context, bool is_throttled)
{
	struct scenario scenario = {
		.name = test_name,
		.quiet = false,
		.flags = (STACKSHOT_THREAD_WAITINFO | STACKSHOT_KCDATA_FORMAT),
	};

	T_LOG("taking stackshot %s", test_name);
	take_stackshot(&scenario, false, ^(void *ssbuf, size_t sslen) {
		parse_stackshot(PARSE_STACKSHOT_THROTTLED_SP, ssbuf, sslen,
					@{sp_throttled_expected_ctxt_key: @(context),
					sp_throttled_expect_flag: @(is_throttled)});
	});
}

/* Take stackshot when a client is blocked on the service port of a process, in the scenario when
 * the process with the receive right for the service port is:
 *     (a) Monitoring the service port using kevents
 *     (b) Not monitoring the service port
 */
T_DECL(throttled_sp,
	"test that service port throttled flag is propagated to the stackshot correctly", T_META_TAG_VM_PREFERRED)
{
	mach_port_t service_port;
	__block dispatch_semaphore_t can_continue  = dispatch_semaphore_create(0);

	char path[PATH_MAX];
	uint32_t path_size = sizeof(path);
	T_ASSERT_POSIX_ZERO(_NSGetExecutablePath(path, &path_size), "_NSGetExecutablePath");
	char *client_args[] = { path, "-n", "throtlled_sp_client", NULL };

	__block	uint64_t thread_id = 0;
	pid_t client_pid;
	int mark_throttled;

	struct mach_service_port_info sp_info = {};
	strcpy(sp_info.mspi_string_name, THROTTLED_SERVICE_NAME);
	sp_info.mspi_domain_type = (uint8_t)1;
	kern_return_t kr;

	mach_port_options_t opts = {
		.flags = MPO_SERVICE_PORT | MPO_INSERT_SEND_RIGHT | MPO_CONTEXT_AS_GUARD | MPO_STRICT | MPO_TEMPOWNER,
		.service_port_info = &sp_info,
	};

	kr = mach_port_construct(mach_task_self(), &opts, 0ull, &service_port);
	T_ASSERT_MACH_SUCCESS(kr, "mach_port_construct %u", service_port);

	/* Setup a dispatch source to monitor the service port similar to how launchd does. */
	dispatch_queue_t machdq = dispatch_queue_create("machqueue", NULL);
	dispatch_source_t mach_src = dispatch_source_create(DISPATCH_SOURCE_TYPE_MACH_RECV, service_port,
		DISPATCH_MACH_RECV_SYNC_PEEK, machdq);
	dispatch_source_set_event_handler(mach_src, ^{
		pthread_threadid_np(NULL, &thread_id);
		dispatch_semaphore_signal(can_continue);
	});
	dispatch_activate(mach_src);

	/* Stash the port in task to make sure child also gets it */
	kr = mach_ports_register(mach_task_self(), &service_port, 1);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_ports_register service port");

	mark_throttled = 1;
	kr = mach_port_set_attributes(mach_task_self(), service_port, MACH_PORT_SERVICE_THROTTLED, (mach_port_info_t)(&mark_throttled),
	           MACH_PORT_SERVICE_THROTTLED_COUNT);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mark service port as throttled");

	int rc = posix_spawn(&client_pid, client_args[0], NULL, NULL, client_args, NULL);
	T_QUIET; T_ASSERT_POSIX_ZERO(rc, "spawned process '%s' with PID %d", client_args[0], client_pid);
	T_LOG("Spawned client as PID %d", client_pid);

	dispatch_semaphore_wait(can_continue, DISPATCH_TIME_FOREVER);

	/* The service port has received the check-in message. Take stackshot for scenario (a). */
	check_throttled_sp("throttled_service_port_monitored", thread_id, true);

	/* This simulates a throttled spawn when the service port is no longer monitored. */
	dispatch_source_cancel(mach_src);

	/* Take stackshot for scenario (b) */
	check_throttled_sp("throttled_service_port_unmonitored", (uint64_t)getpid(), true);

	mark_throttled = 0;
	kr = mach_port_set_attributes(mach_task_self(), service_port, MACH_PORT_SERVICE_THROTTLED, (mach_port_info_t)(&mark_throttled),
	           MACH_PORT_SERVICE_THROTTLED_COUNT);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "unmark service port as throttled");

	/* Throttled flag should not be set when the port is not throttled. */
	check_throttled_sp("unthrottled_service_port_unmonitored", (uint64_t)getpid(), false);

	/* cleanup - kill the client */
	T_ASSERT_POSIX_SUCCESS(kill(client_pid, SIGKILL), "killing client");
	T_ASSERT_POSIX_SUCCESS(waitpid(client_pid, NULL, 0), "waiting for the client to exit");
}


char *const clpcctrl_path = "/usr/local/bin/clpcctrl";

static void
run_clpcctrl(char *const argv[]) {
	posix_spawnattr_t sattr;
	pid_t pid;
	int wstatus;

	T_QUIET; T_ASSERT_POSIX_ZERO(posix_spawn(&pid, argv[0], NULL, NULL, argv, NULL), "spawn clpcctrl");
	T_QUIET; T_ASSERT_POSIX_SUCCESS(waitpid(pid, &wstatus, 0), "wait for clpcctrl");
	T_QUIET; T_ASSERT_TRUE(WIFEXITED(wstatus), "clpcctrl exited normally");
	T_QUIET; T_ASSERT_POSIX_ZERO(WEXITSTATUS(wstatus), "clpcctrl exited successfully");

	uint64_t sched_recommended_cores = 1;
	size_t sched_recommended_cores_sz = sizeof(uint64_t);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(
	    sysctlbyname("kern.sched_recommended_cores", &sched_recommended_cores, &sched_recommended_cores_sz, NULL, 0),
	    "get kern.sched_recommended_cores");
	T_LOG("Recommended cores: 0x%llx", sched_recommended_cores);
}

static void
restore_clpcctrl() {
	run_clpcctrl((char *const []) { clpcctrl_path, "-d", NULL });
}

#define CLUSTER_TYPE_SMP 0
#define CLUSTER_TYPE_E 1
#define CLUSTER_TYPE_P 2

void test_stackshot_cpu_info(void *ssbuf, size_t sslen, int exp_cpus, NSArray *exp_cluster_types) {
	kcdata_iter_t iter = kcdata_iter(ssbuf, sslen);
	bool seen = false;
	int singlethread_override = 0;
	size_t singlethread_override_sz = sizeof(singlethread_override);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(
		sysctlbyname("kern.stackshot_single_thread", &singlethread_override, &singlethread_override_sz, NULL, 0),
		"get kern.stackshot_single_thread");
	if (singlethread_override) {
		T_LOG("skipping cpu count/type check due to single-thread override (kern.stackshot_single_thread=1)");
		return;
	}

	KCDATA_ITER_FOREACH(iter) {
		if ((kcdata_iter_type(iter) != KCDATA_TYPE_ARRAY) || (kcdata_iter_array_elem_type(iter) != STACKSHOT_KCTYPE_LATENCY_INFO_CPU)) {
			continue;
		}

		seen = true;

		/* Check ncpus */
		int ncpus = kcdata_iter_array_elem_count(iter);
		if (exp_cpus != -1) {
			T_QUIET; T_ASSERT_EQ(exp_cpus, ncpus, "Expected number of CPUs matches number of CPUs used for stackshot");
		}

		if (exp_cluster_types == nil) {
			continue;
		}

		/* Check cluster types */
		struct stackshot_latency_cpu *latencies = (struct stackshot_latency_cpu *) kcdata_iter_payload(iter);
		for (int i = 0; i < ncpus; i++) {
			NSNumber *cluster_type = [NSNumber numberWithInt:latencies[i].cluster_type];
			T_QUIET; T_ASSERT_TRUE([exp_cluster_types containsObject:cluster_type], "Type of CPU cluster in expected CPU cluster types");
		}
	}

	T_QUIET; T_ASSERT_TRUE(seen || !is_development_kernel(), "Seen CPU latency info or is release kernel");
}

void test_stackshot_with_clpcctrl(char *const name, char *const argv[], int exp_cpus, NSArray *exp_cluster_types) {
	T_LOG("Stackshot CLPC scenario %s", name);
	run_clpcctrl(argv);
	struct scenario scenario = {
		.name = name,
		.flags = (STACKSHOT_KCDATA_FORMAT | STACKSHOT_SAVE_LOADINFO |
			STACKSHOT_THREAD_WAITINFO | STACKSHOT_GET_GLOBAL_MEM_STATS)
	};
	take_stackshot(&scenario, false, ^(void *ssbuf, size_t sslen) {
		parse_stackshot(0, ssbuf, sslen, nil);
		test_stackshot_cpu_info(ssbuf, sslen, exp_cpus, exp_cluster_types);
	});
}

T_DECL(core_masks,
	"test that stackshot works under various core masks on ARM systems",
	T_META_REQUIRES_SYSCTL_EQ("hw.optional.arm64", 1),
	T_META_REQUIRES_SYSCTL_NE("kern.kasan.available", 1), /* rdar://115577993 */
	XNU_T_META_REQUIRES_DEVELOPMENT_KERNEL,
	T_META_REQUIRE_NOT_VIRTUALIZED,
	T_META_RUN_CONCURRENTLY(false),
	T_META_TAG_VM_NOT_ELIGIBLE,
	T_META_ENABLED(!TARGET_OS_VISION)) // disable for visionOS: device may not be stable with many cores masked off (127904530)
{
	/*
	 * Make sure we're not in a release kernel
	 * (cannot check with T_META; only one sysctl T_META at a time will work)
	 */
	if (!is_development_kernel()) {
		T_SKIP("test was not run because kernel is release; cannot set core masks");
		return;
	}

	/*
	 * rdar://115577993 - CLPC compiles as release in KASAN-variant builds,
	 * preventing clpcctrl from working. For now, skip this. (Cannot check
	 * with T_META; only one sysctl T_META at a time will work)
	 */
	int kasan_avail = 0;
	size_t kasan_avail_sz = sizeof(kasan_avail);
	sysctlbyname("kern.kasan.available", &kasan_avail, &kasan_avail_sz, NULL, 0);
	if (kasan_avail) {
		T_SKIP("test was not run because kernel is KASAN; cannot set core masks (see rdar://115577993)");
		return;
	}


	T_ATEND(restore_clpcctrl);

	/* Test with 1 and 2 CPUs for basic functionality */
	test_stackshot_with_clpcctrl(
		"core_masks_1cpu", (char *const[]) {clpcctrl_path, "-c", "1", NULL},
		1, nil);

	test_stackshot_with_clpcctrl(
		"core_masks_2cpus", (char *const[]) {clpcctrl_path, "-c", "2", NULL},
		2, nil);

	/* Check nperflevels to see if we're on an AMP system */
	int nperflevels = 1;
	size_t nperflevels_sz = sizeof(int);
	T_ASSERT_POSIX_SUCCESS(
	    sysctlbyname("hw.nperflevels", &nperflevels, &nperflevels_sz, NULL, 0),
	    "get hw.nperflevels");
	if (nperflevels == 1) {
		T_LOG("On SMP system, skipping stackshot core_masks AMP tests");
		return;
	}

	T_QUIET; T_ASSERT_EQ(nperflevels, 2, "nperflevels is 1 or 2");
	T_LOG("On AMP system, performing stackshot core_masks AMP tests");

	/* Perform AMP tests with different cluster types active */
	test_stackshot_with_clpcctrl(
		"core_masks_amp_allcpus",
		(char *const[]) {clpcctrl_path, "-C", "all", NULL},
		-1, @[@CLUSTER_TYPE_E, @CLUSTER_TYPE_P]);

	test_stackshot_with_clpcctrl(
		"core_masks_amp_ecpus",
		(char *const[]) {clpcctrl_path, "-C", "e", NULL},
		-1, @[@CLUSTER_TYPE_E]);

	test_stackshot_with_clpcctrl(
		"core_masks_amp_pcpus",
		(char *const[]) {clpcctrl_path, "-C", "p", NULL},
		-1, @[@CLUSTER_TYPE_P]);
}

#pragma mark performance tests

#define SHOULD_REUSE_SIZE_HINT 0x01
#define SHOULD_USE_DELTA       0x02
#define SHOULD_TARGET_SELF     0x04

static void
stackshot_perf(unsigned int options)
{
	struct scenario scenario = {
		.flags = (STACKSHOT_SAVE_LOADINFO | STACKSHOT_GET_GLOBAL_MEM_STATS
			| STACKSHOT_SAVE_IMP_DONATION_PIDS | STACKSHOT_KCDATA_FORMAT),
	};

	dt_stat_t size = dt_stat_create("bytes", "size");
	dt_stat_time_t duration = dt_stat_time_create("duration");
	scenario.timer = duration;

	if (options & SHOULD_TARGET_SELF) {
		scenario.target_pid = getpid();
	}

	while (!dt_stat_stable(duration) || !dt_stat_stable(size)) {
		__block uint64_t last_time = 0;
		__block uint32_t size_hint = 0;
		take_stackshot(&scenario, false, ^(void *ssbuf, size_t sslen) {
			dt_stat_add(size, (double)sslen);
			last_time = stackshot_timestamp(ssbuf, sslen);
			size_hint = (uint32_t)sslen;
		});
		if (options & SHOULD_USE_DELTA) {
			scenario.since_timestamp = last_time;
			scenario.flags |= STACKSHOT_COLLECT_DELTA_SNAPSHOT;
		}
		if (options & SHOULD_REUSE_SIZE_HINT) {
			scenario.size_hint = size_hint;
		}
	}

	dt_stat_finalize(duration);
	dt_stat_finalize(size);
}

static void
stackshot_flag_perf_noclobber(uint64_t flag, char *flagname)
{
	struct scenario scenario = {
		.quiet = true,
		.flags = (flag | STACKSHOT_KCDATA_FORMAT),
	};

	dt_stat_t duration = dt_stat_create("nanoseconds per thread", "%s_duration", flagname);
	dt_stat_t size = dt_stat_create("bytes per thread", "%s_size", flagname);
	T_LOG("Testing \"%s\" = 0x%" PRIx64, flagname, flag);

	while (!dt_stat_stable(duration) || !dt_stat_stable(size)) {
		take_stackshot(&scenario, false, ^(void *ssbuf, size_t sslen) {
			kcdata_iter_t iter = kcdata_iter(ssbuf, sslen);
			unsigned long no_threads = 0;
			mach_timebase_info_data_t timebase = {0, 0};
			uint64_t stackshot_duration = 0;
			int found = 0;
			T_QUIET; T_ASSERT_EQ(kcdata_iter_type(iter), KCDATA_BUFFER_BEGIN_STACKSHOT, "stackshot buffer");

			KCDATA_ITER_FOREACH(iter) {
				switch(kcdata_iter_type(iter)) {
					case STACKSHOT_KCTYPE_THREAD_SNAPSHOT: {
						found |= 1;
						no_threads ++;
						break;
					}
					case STACKSHOT_KCTYPE_STACKSHOT_DURATION: {
						struct stackshot_duration *ssd = kcdata_iter_payload(iter);
						stackshot_duration = ssd->stackshot_duration;
						found |= 2;
						break;
					}
					case KCDATA_TYPE_TIMEBASE: {
						found |= 4;
						mach_timebase_info_data_t *tb = kcdata_iter_payload(iter);
						memcpy(&timebase, tb, sizeof(timebase));
						break;
					}
				}
			}

			T_QUIET; T_ASSERT_EQ(found, 0x7, "found everything needed");

			uint64_t ns = (stackshot_duration * timebase.numer) / timebase.denom;
			uint64_t per_thread_ns = ns / no_threads;
			uint64_t per_thread_size = sslen / no_threads;

			dt_stat_add(duration, per_thread_ns);
			dt_stat_add(size, per_thread_size);
		});
	}

	dt_stat_finalize(duration);
	dt_stat_finalize(size);
}

static void
stackshot_flag_perf(uint64_t flag, char *flagname)
{
	/*
	 * STACKSHOT_NO_IO_STATS disables data collection, so set it for
	 * more accurate perfdata collection.
	 */
	flag |= STACKSHOT_NO_IO_STATS;

	stackshot_flag_perf_noclobber(flag, flagname);
}


T_DECL(flag_perf, "test stackshot performance with different flags set", T_META_TAG_PERF, T_META_TAG_VM_NOT_ELIGIBLE)
{
	stackshot_flag_perf_noclobber(STACKSHOT_NO_IO_STATS, "baseline");
	stackshot_flag_perf_noclobber(0, "io_stats");

	stackshot_flag_perf(STACKSHOT_THREAD_WAITINFO, "thread_waitinfo");
	stackshot_flag_perf(STACKSHOT_GET_DQ, "get_dq");
	stackshot_flag_perf(STACKSHOT_SAVE_LOADINFO, "save_loadinfo");
	stackshot_flag_perf(STACKSHOT_GET_GLOBAL_MEM_STATS, "get_global_mem_stats");
	stackshot_flag_perf(STACKSHOT_SAVE_KEXT_LOADINFO, "save_kext_loadinfo");
	stackshot_flag_perf(STACKSHOT_SAVE_IMP_DONATION_PIDS, "save_imp_donation_pids");
	stackshot_flag_perf(STACKSHOT_ENABLE_BT_FAULTING, "enable_bt_faulting");
	stackshot_flag_perf(STACKSHOT_COLLECT_SHAREDCACHE_LAYOUT, "collect_sharedcache_layout");
	stackshot_flag_perf(STACKSHOT_ENABLE_UUID_FAULTING, "enable_uuid_faulting");
	stackshot_flag_perf(STACKSHOT_THREAD_GROUP, "thread_group");
	stackshot_flag_perf(STACKSHOT_SAVE_JETSAM_COALITIONS, "save_jetsam_coalitions");
	stackshot_flag_perf(STACKSHOT_INSTRS_CYCLES, "instrs_cycles");
	stackshot_flag_perf(STACKSHOT_ASID, "asid");
	stackshot_flag_perf(STACKSHOT_EXCLAVES, "all_exclaves");
	stackshot_flag_perf(STACKSHOT_EXCLAVES | STACKSHOT_ASID, "all_exclaves_and_asid");
	stackshot_flag_perf(STACKSHOT_SKIP_EXCLAVES, "skip_exclaves");
}

T_DECL(perf_no_size_hint, "test stackshot performance with no size hint",
		T_META_TAG_PERF, T_META_TAG_VM_NOT_ELIGIBLE)
{
	stackshot_perf(0);
}

T_DECL(perf_size_hint, "test stackshot performance with size hint",
		T_META_TAG_PERF, T_META_TAG_VM_NOT_ELIGIBLE)
{
	stackshot_perf(SHOULD_REUSE_SIZE_HINT);
}

T_DECL(perf_process, "test stackshot performance targeted at process",
		T_META_TAG_PERF, T_META_TAG_VM_NOT_ELIGIBLE)
{
	stackshot_perf(SHOULD_REUSE_SIZE_HINT | SHOULD_TARGET_SELF);
}

T_DECL(perf_delta, "test delta stackshot performance",
		T_META_TAG_PERF, T_META_TAG_VM_NOT_ELIGIBLE)
{
	stackshot_perf(SHOULD_REUSE_SIZE_HINT | SHOULD_USE_DELTA);
}

T_DECL(perf_delta_no_exclaves, "test delta stackshot performance without Exclaves",
	    T_META_REQUIRES_SYSCTL_EQ("kern.exclaves_status", 1),
		T_META_REQUIRES_SYSCTL_EQ("kern.exclaves_inspection_status", 1),
		T_META_TAG_PERF, T_META_TAG_VM_NOT_ELIGIBLE)
{
	stackshot_perf(SHOULD_REUSE_SIZE_HINT | SHOULD_USE_DELTA | STACKSHOT_SKIP_EXCLAVES);
}

T_DECL(perf_delta_process, "test delta stackshot performance targeted at a process",
		T_META_TAG_PERF, T_META_TAG_VM_NOT_ELIGIBLE)
{
	stackshot_perf(SHOULD_REUSE_SIZE_HINT | SHOULD_USE_DELTA | SHOULD_TARGET_SELF);
}

T_DECL(stackshot_entitlement_report_test, "test stackshot entitlement report", T_META_TAG_VM_PREFERRED)
{
	int sysctlValue = 1;
	T_ASSERT_POSIX_SUCCESS(
	    sysctlbyname("debug.stackshot_entitlement_send_batch", NULL, NULL, &sysctlValue, sizeof(sysctlValue)),
	    "set debug.stackshot_entitlement_send_batch=1");
	// having a way to verify that the coreanalytics event was received would be even better
	// See rdar://74197197
	T_PASS("entitlement test ran");
}

static void
expect_os_build_version_in_stackshot(void *ssbuf, size_t sslen)
{
	kcdata_iter_t iter = kcdata_iter(ssbuf, sslen);

	bool saw_os_build_version = false;
	iter = kcdata_iter_next(iter);

	KCDATA_ITER_FOREACH(iter) {
		switch (kcdata_iter_type(iter)) {
		case STACKSHOT_KCTYPE_OS_BUILD_VERSION:
			saw_os_build_version = true;
			T_LOG("Found os build version in stackshot: %s", kcdata_iter_payload(iter));
			return;

		default:
			break;
		}
	}

	T_ASSERT_FAIL("didn't see os build version in stackshot");
}

T_DECL(os_build_version, "test stackshot contains os build version", T_META_TAG_VM_PREFERRED)
{

	struct scenario scenario = {
		.name = "os-build-version",
		.flags = (STACKSHOT_SAVE_LOADINFO | STACKSHOT_KCDATA_FORMAT),
	};

	T_LOG("attempting to take stackshot with an os build version");
	take_stackshot(&scenario, false, ^(void *ssbuf, size_t sslen) {
		expect_os_build_version_in_stackshot(ssbuf, sslen);
	});
}

static uint64_t
stackshot_timestamp(void *ssbuf, size_t sslen)
{
	kcdata_iter_t iter = kcdata_iter(ssbuf, sslen);

	uint32_t type = kcdata_iter_type(iter);
	if (type != KCDATA_BUFFER_BEGIN_STACKSHOT && type != KCDATA_BUFFER_BEGIN_DELTA_STACKSHOT) {
		T_ASSERT_FAIL("invalid kcdata type %u", kcdata_iter_type(iter));
	}

	iter = kcdata_iter_find_type(iter, KCDATA_TYPE_MACH_ABSOLUTE_TIME);
	T_QUIET;
	T_ASSERT_TRUE(kcdata_iter_valid(iter), "timestamp found in stackshot");

	return *(uint64_t *)kcdata_iter_payload(iter);
}

#define TEST_THREAD_NAME "stackshot_test_thread"

static void
parse_thread_group_stackshot(void **ssbuf, size_t sslen)
{
	bool seen_thread_group_snapshot = false;
	kcdata_iter_t iter = kcdata_iter(ssbuf, sslen);
	T_ASSERT_EQ(kcdata_iter_type(iter), KCDATA_BUFFER_BEGIN_STACKSHOT,
			"buffer provided is a stackshot");

	NSMutableSet *thread_groups = [[NSMutableSet alloc] init];

	iter = kcdata_iter_next(iter);
	KCDATA_ITER_FOREACH(iter) {
		switch (kcdata_iter_type(iter)) {
		case KCDATA_TYPE_ARRAY: {
			T_QUIET;
			T_ASSERT_TRUE(kcdata_iter_array_valid(iter),
					"checked that array is valid");

			if (kcdata_iter_array_elem_type(iter) != STACKSHOT_KCTYPE_THREAD_GROUP_SNAPSHOT) {
				continue;
			}

			seen_thread_group_snapshot = true;

			if (kcdata_iter_array_elem_size(iter) >= sizeof(struct thread_group_snapshot_v3)) {
				struct thread_group_snapshot_v3 *tgs_array = kcdata_iter_payload(iter);
				for (uint32_t j = 0; j < kcdata_iter_array_elem_count(iter); j++) {
					struct thread_group_snapshot_v3 *tgs = tgs_array + j;
					[thread_groups addObject:@(tgs->tgs_id)];
				}
			}
			else {
				struct thread_group_snapshot *tgs_array = kcdata_iter_payload(iter);
				for (uint32_t j = 0; j < kcdata_iter_array_elem_count(iter); j++) {
					struct thread_group_snapshot *tgs = tgs_array + j;
					[thread_groups addObject:@(tgs->tgs_id)];
				}
			}
			break;
		}
		}
	}
	KCDATA_ITER_FOREACH(iter) {
		NSError *error = nil;

		switch (kcdata_iter_type(iter)) {

		case KCDATA_TYPE_CONTAINER_BEGIN: {
			T_QUIET;
			T_ASSERT_TRUE(kcdata_iter_container_valid(iter),
					"checked that container is valid");

			if (kcdata_iter_container_type(iter) != STACKSHOT_KCCONTAINER_THREAD) {
				break;
			}

			NSDictionary *container = parseKCDataContainer(&iter, &error);
			T_QUIET; T_ASSERT_NOTNULL(container, "parsed thread container from stackshot");
			T_QUIET; T_ASSERT_NULL(error, "error unset after parsing container");

			int tg = [container[@"thread_snapshots"][@"thread_group"] intValue];

			T_ASSERT_TRUE([thread_groups containsObject:@(tg)], "check that the thread group the thread is in exists");

			break;
		};

		}
	}
	T_ASSERT_TRUE(seen_thread_group_snapshot, "check that we have seen a thread group snapshot");
}

static void
verify_stackshot_sharedcache_layout(struct dyld_uuid_info_64 *uuids, uint32_t uuid_count)
{
	uuid_t cur_shared_cache_uuid;
	__block uint32_t lib_index = 0, libs_found = 0;

	_dyld_get_shared_cache_uuid(cur_shared_cache_uuid);
	int result = dyld_shared_cache_iterate_text(cur_shared_cache_uuid, ^(const dyld_shared_cache_dylib_text_info* info) {
			T_QUIET; T_ASSERT_LT(lib_index, uuid_count, "dyld_shared_cache_iterate_text exceeded number of libraries returned by kernel");

			libs_found++;
			struct dyld_uuid_info_64 *cur_stackshot_uuid_entry = &uuids[lib_index];
			T_QUIET; T_ASSERT_EQ(memcmp(info->dylibUuid, cur_stackshot_uuid_entry->imageUUID, sizeof(info->dylibUuid)), 0,
					"dyld returned UUID doesn't match kernel returned UUID");
			T_QUIET; T_ASSERT_EQ(info->loadAddressUnslid, cur_stackshot_uuid_entry->imageLoadAddress,
					"dyld returned load address doesn't match kernel returned load address");
			lib_index++;
		});

	T_ASSERT_EQ(result, 0, "iterate shared cache layout");
	T_ASSERT_EQ(libs_found, uuid_count, "dyld iterator returned same number of libraries as kernel");

	T_LOG("verified %d libraries from dyld shared cache", libs_found);
}

static void
check_shared_cache_uuid(uuid_t imageUUID)
{
	static uuid_t shared_cache_uuid;
	static dispatch_once_t read_shared_cache_uuid;

	dispatch_once(&read_shared_cache_uuid, ^{
		T_QUIET;
		T_ASSERT_TRUE(_dyld_get_shared_cache_uuid(shared_cache_uuid), "retrieve current shared cache UUID");
	});
	T_QUIET; T_ASSERT_EQ(uuid_compare(shared_cache_uuid, imageUUID), 0,
			"dyld returned UUID doesn't match kernel returned UUID for system shared cache");
}

/*
 * extra dictionary contains data relevant for the given flags:
 * PARSE_STACKSHOT_ZOMBIE:   zombie_child_pid_key -> @(pid)
 * PARSE_STACKSHOT_POSTEXEC: postexec_child_unique_pid_key -> @(unique_pid)
 */
static void
parse_stackshot(uint64_t stackshot_parsing_flags, void *ssbuf, size_t sslen, NSDictionary *extra)
{
	bool delta = (stackshot_parsing_flags & PARSE_STACKSHOT_DELTA);
	bool expect_sharedcache_child = (stackshot_parsing_flags & PARSE_STACKSHOT_SHAREDCACHE_FLAGS);
	bool expect_zombie_child = (stackshot_parsing_flags & PARSE_STACKSHOT_ZOMBIE);
	bool expect_postexec_child = (stackshot_parsing_flags & PARSE_STACKSHOT_POSTEXEC);
	bool expect_cseg_waitinfo = (stackshot_parsing_flags & PARSE_STACKSHOT_WAITINFO_CSEG);
	bool expect_translated_child = (stackshot_parsing_flags & PARSE_STACKSHOT_TRANSLATED);
	bool expect_shared_cache_layout = false;
	bool expect_shared_cache_uuid = !delta;
	bool expect_dispatch_queue_label = (stackshot_parsing_flags & PARSE_STACKSHOT_DISPATCH_QUEUE_LABEL);
	bool expect_turnstile_lock = (stackshot_parsing_flags & PARSE_STACKSHOT_TURNSTILEINFO);
	bool expect_srp_waitinfo = (stackshot_parsing_flags & PARSE_STACKSHOT_WAITINFO_SRP);
	bool expect_sp_throttled = (stackshot_parsing_flags & PARSE_STACKSHOT_THROTTLED_SP);
	bool expect_exec_inprogress = (stackshot_parsing_flags & PARSE_STACKSHOT_EXEC_INPROGRESS);
	bool expect_transitioning_task = (stackshot_parsing_flags & PARSE_STACKSHOT_TRANSITIONING);
	bool expect_asyncstack = (stackshot_parsing_flags & PARSE_STACKSHOT_ASYNCSTACK);
	bool expect_driverkit = (stackshot_parsing_flags & PARSE_STACKSHOT_DRIVERKIT);
	bool expect_suspendinfo = (stackshot_parsing_flags & PARSE_STACKSHOT_SUSPENDINFO);
	bool found_zombie_child = false, found_postexec_child = false, found_shared_cache_layout = false, found_shared_cache_uuid = false;
	bool found_translated_child = false, found_transitioning_task = false;
	bool found_dispatch_queue_label = false, found_turnstile_lock = false;
	bool found_cseg_waitinfo = false, found_srp_waitinfo = false;
	bool found_sharedcache_child = false, found_sharedcache_badflags = false, found_sharedcache_self = false;
	bool found_asyncstack = false;
	bool found_throttled_service = false;
	bool found_exclaves = false;
	bool expect_single_task = (stackshot_parsing_flags & PARSE_STACKSHOT_TARGETPID);
	uint64_t srp_expected_threadid = 0;
	pid_t zombie_child_pid = -1, srp_expected_pid = -1, sharedcache_child_pid = -1, throttled_service_ctx = -1;
	pid_t translated_child_pid = -1, transistioning_task_pid = -1;
	bool sharedcache_child_sameaddr = false, is_throttled = false;
	uint64_t postexec_child_unique_pid = 0, cseg_expected_threadid = 0;
	uint64_t sharedcache_child_flags = 0, sharedcache_self_flags = 0;
	uint64_t asyncstack_threadid = 0;
	NSArray *asyncstack_stack = nil;
	char *inflatedBufferBase = NULL;
	pid_t exec_inprogress_pid = -1;
	void (^exec_inprogress_cb)(uint64_t, uint64_t) = NULL;
	int exec_inprogress_found = 0;
	uint64_t exec_inprogress_containerid = 0;
	void (^driverkit_cb)(pid_t) = NULL;
	NSMutableDictionary *sharedCaches = [NSMutableDictionary new];
	uint64_t expected_num_threads = 0, expected_num_tasks = 0, found_percpu_threads = 0, found_tasks = 0, found_percpu_tasks = 0;
	NSMutableSet *seen_tasks = [NSMutableSet new];

	if (expect_shared_cache_uuid) {
		uuid_t shared_cache_uuid;
		if (!_dyld_get_shared_cache_uuid(shared_cache_uuid)) {
			T_LOG("Skipping verifying shared cache UUID in stackshot data because not running with a shared cache");
			expect_shared_cache_uuid = false;
		}
	}

	if (stackshot_parsing_flags & PARSE_STACKSHOT_SHAREDCACHE_LAYOUT) {
		size_t shared_cache_length = 0;
		const void *cache_header = _dyld_get_shared_cache_range(&shared_cache_length);
		T_QUIET; T_ASSERT_NOTNULL(cache_header, "current process running with shared cache");
		T_QUIET; T_ASSERT_GT(shared_cache_length, sizeof(struct _dyld_cache_header), "valid shared cache length populated by _dyld_get_shared_cache_range");

		if (_dyld_shared_cache_is_locally_built()) {
			T_LOG("device running with locally built shared cache, expect shared cache layout");
			expect_shared_cache_layout = true;
		} else {
			T_LOG("device running with B&I built shared-cache, no shared cache layout expected");
		}
	}

	if (expect_sharedcache_child) {
		NSNumber* pid_num = extra[sharedcache_child_pid_key];
		NSNumber* sameaddr_num = extra[sharedcache_child_sameaddr_key];
		T_QUIET; T_ASSERT_NOTNULL(pid_num, "sharedcache child pid provided");
		T_QUIET; T_ASSERT_NOTNULL(sameaddr_num, "sharedcache child addrsame provided");
		sharedcache_child_pid = [pid_num intValue];
		T_QUIET; T_ASSERT_GT(sharedcache_child_pid, 0, "sharedcache child pid greater than zero");
		sharedcache_child_sameaddr = [sameaddr_num intValue];
		T_QUIET; T_ASSERT_GE([sameaddr_num intValue], 0, "sharedcache child sameaddr is boolean (0 or 1)");
		T_QUIET; T_ASSERT_LE([sameaddr_num intValue], 1, "sharedcache child sameaddr is boolean (0 or 1)");
	}

    if (expect_transitioning_task) {
        NSNumber* pid_num = extra[transitioning_pid_key];
        T_ASSERT_NOTNULL(pid_num, "transitioning task pid provided");
        transistioning_task_pid = [pid_num intValue];
    }

	if (expect_zombie_child) {
		NSNumber* pid_num = extra[zombie_child_pid_key];
		T_QUIET; T_ASSERT_NOTNULL(pid_num, "zombie child pid provided");
		zombie_child_pid = [pid_num intValue];
		T_QUIET; T_ASSERT_GT(zombie_child_pid, 0, "zombie child pid greater than zero");
	}

	if (expect_postexec_child) {
		NSNumber* unique_pid_num = extra[postexec_child_unique_pid_key];
		T_QUIET; T_ASSERT_NOTNULL(unique_pid_num, "postexec child unique pid provided");
		postexec_child_unique_pid = [unique_pid_num unsignedLongLongValue];
		T_QUIET; T_ASSERT_GT(postexec_child_unique_pid, 0ull, "postexec child unique pid greater than zero");
	}

	if (expect_cseg_waitinfo) {
		NSNumber* tid_num = extra[cseg_expected_threadid_key];
		T_QUIET; T_ASSERT_NOTNULL(tid_num, "cseg's expected thread id provided");
		cseg_expected_threadid = tid_num.unsignedLongValue;
		T_QUIET; T_ASSERT_GT(cseg_expected_threadid, UINT64_C(0), "compressor segment thread is present");
	}

	if (expect_srp_waitinfo) {
		NSNumber* threadid_num = extra[srp_expected_threadid_key];
		NSNumber* pid_num = extra[srp_expected_pid_key];
		T_QUIET; T_ASSERT_TRUE(threadid_num != nil || pid_num != nil, "expected SRP threadid or pid");
		if (threadid_num != nil) {
			srp_expected_threadid = [threadid_num unsignedLongLongValue];
			T_QUIET; T_ASSERT_GT(srp_expected_threadid, 0ull, "srp_expected_threadid greater than zero");
		}
		if (pid_num != nil) {
			srp_expected_pid = [pid_num intValue];
			T_QUIET; T_ASSERT_GT(srp_expected_pid, 0, "srp_expected_pid greater than zero");
		}
		T_LOG("looking for SRP pid: %d threadid: %llu", srp_expected_pid, srp_expected_threadid);
	}

	if (expect_sp_throttled) {
		NSNumber* ctx = extra[sp_throttled_expected_ctxt_key];
		T_QUIET; T_ASSERT_TRUE(ctx != nil, "expected pid");
		throttled_service_ctx = [ctx intValue];
		T_QUIET; T_ASSERT_GT(throttled_service_ctx, 0, "expected pid greater than zero");

		NSNumber *throttled = extra[sp_throttled_expect_flag];
		T_QUIET; T_ASSERT_TRUE(throttled != nil, "expected flag value");
		is_throttled = ([throttled intValue] != 0);

		T_LOG("Looking for service with ctxt: %d, thottled:%d", throttled_service_ctx, is_throttled);
	}

	if (expect_translated_child) {
		NSNumber* pid_num = extra[translated_child_pid_key];
		T_QUIET; T_ASSERT_NOTNULL(pid_num, "translated child pid provided");
		translated_child_pid = [pid_num intValue];
		T_QUIET; T_ASSERT_GT(translated_child_pid, 0, "translated child pid greater than zero");
	}
	if (expect_exec_inprogress) {
		NSNumber* pid_num = extra[exec_inprogress_pid_key];
		T_QUIET; T_ASSERT_NOTNULL(pid_num, "exec inprogress pid provided");
		exec_inprogress_pid = [pid_num intValue];
		T_QUIET; T_ASSERT_GT(exec_inprogress_pid, 0, "exec inprogress pid greater than zero");

		exec_inprogress_cb = extra[exec_inprogress_found_key];
		T_QUIET; T_ASSERT_NOTNULL(exec_inprogress_cb, "exec inprogress found callback provided");
	}
	if (expect_driverkit) {
		driverkit_cb = extra[driverkit_found_key];
		T_QUIET; T_ASSERT_NOTNULL(driverkit_cb, "driverkit found callback provided");
	}

	if (expect_asyncstack) {
		NSNumber* threadid_id = extra[asyncstack_expected_threadid_key];
		T_QUIET; T_ASSERT_NOTNULL(threadid_id, "asyncstack threadid provided");
		asyncstack_threadid = [threadid_id unsignedLongLongValue];
		asyncstack_stack = extra[asyncstack_expected_stack_key];
		T_QUIET; T_ASSERT_NOTNULL(asyncstack_stack, "asyncstack expected stack provided");
	}

	kcdata_iter_t iter = kcdata_iter(ssbuf, sslen);
	if (delta) {
		T_ASSERT_EQ(kcdata_iter_type(iter), KCDATA_BUFFER_BEGIN_DELTA_STACKSHOT,
				"buffer provided is a delta stackshot");

			iter = kcdata_iter_next(iter);
	} else {
		if (kcdata_iter_type(iter) != KCDATA_BUFFER_BEGIN_COMPRESSED) {
			T_ASSERT_EQ(kcdata_iter_type(iter), KCDATA_BUFFER_BEGIN_STACKSHOT,
					"buffer provided is a stackshot");

			iter = kcdata_iter_next(iter);
		} else {
			/* we are dealing with a compressed buffer */
			iter = kcdata_iter_next(iter);
			uint64_t compression_type = 0, totalout = 0, totalin = 0;

			uint64_t *data;
			char *desc;
			for (int i = 0; i < 3; i ++) {
				kcdata_iter_get_data_with_desc(iter, &desc, (void **)&data, NULL);
				if (strcmp(desc, "kcd_c_type") == 0) {
					compression_type = *data;
				} else if (strcmp(desc, "kcd_c_totalout") == 0){
					totalout = *data;
				} else if (strcmp(desc, "kcd_c_totalin") == 0){
					totalin = *data;
				}

				iter = kcdata_iter_next(iter);
			}

			T_ASSERT_EQ(compression_type, UINT64_C(1), "zlib compression is used");
			T_ASSERT_GT(totalout, UINT64_C(0), "successfully gathered how long the compressed buffer is");
			T_ASSERT_GT(totalin, UINT64_C(0), "successfully gathered how long the uncompressed buffer will be at least");

			/* progress to the next kcdata item */
			T_ASSERT_EQ(kcdata_iter_type(iter), KCDATA_BUFFER_BEGIN_STACKSHOT, "compressed stackshot found");

			char *bufferBase = kcdata_iter_payload(iter);

			/*
			 * zlib is used, allocate a buffer based on the metadata, plus
			 * extra scratch space (+12.5%) in case totalin was inconsistent
			 */
			size_t inflatedBufferSize = totalin + (totalin >> 3);
			inflatedBufferBase = malloc(inflatedBufferSize);
			T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(inflatedBufferBase, "allocated temporary output buffer");

			z_stream zs;
			memset(&zs, 0, sizeof(zs));
			T_QUIET; T_ASSERT_EQ(inflateInit(&zs), Z_OK, "inflateInit OK");
			zs.next_in = (unsigned char *)bufferBase;
			T_QUIET; T_ASSERT_LE(totalout, (uint64_t)UINT_MAX, "stackshot is not too large");
			zs.avail_in = (uInt)totalout;
			zs.next_out = (unsigned char *)inflatedBufferBase;
			T_QUIET; T_ASSERT_LE(inflatedBufferSize, (size_t)UINT_MAX, "output region is not too large");
			zs.avail_out = (uInt)inflatedBufferSize;
			T_ASSERT_EQ(inflate(&zs, Z_FINISH), Z_STREAM_END, "inflated buffer");
			inflateEnd(&zs);

			T_ASSERT_EQ((uint64_t)zs.total_out, totalin, "expected number of bytes inflated");

			/* copy the data after the compressed area */
			T_QUIET; T_ASSERT_GE((void *)bufferBase, ssbuf,
					"base of compressed stackshot is after the returned stackshot buffer");
			size_t header_size = (size_t)(bufferBase - (char *)ssbuf);
			size_t data_after_compressed_size = sslen - totalout - header_size;
			T_QUIET; T_ASSERT_LE(data_after_compressed_size,
					inflatedBufferSize - zs.total_out,
					"footer fits in the buffer");
			memcpy(inflatedBufferBase + zs.total_out,
					bufferBase + totalout,
					data_after_compressed_size);

			iter = kcdata_iter(inflatedBufferBase, inflatedBufferSize);
		}
	}

	KCDATA_ITER_FOREACH(iter) {
		NSError *error = nil;

		switch (kcdata_iter_type(iter)) {
		case KCDATA_TYPE_ARRAY: {
			T_QUIET;
			T_ASSERT_TRUE(kcdata_iter_array_valid(iter),
					"checked that array is valid");

			NSMutableDictionary *array = parseKCDataArray(iter, &error);
			T_QUIET; T_ASSERT_NOTNULL(array, "parsed array from stackshot");
			T_QUIET; T_ASSERT_NULL(error, "error unset after parsing array");

			if (kcdata_iter_array_elem_type(iter) == STACKSHOT_KCTYPE_SYS_SHAREDCACHE_LAYOUT) {
				struct dyld_uuid_info_64 *shared_cache_uuids = kcdata_iter_payload(iter);
				uint32_t uuid_count = kcdata_iter_array_elem_count(iter);
				T_ASSERT_NOTNULL(shared_cache_uuids, "parsed shared cache layout array");
				T_ASSERT_GT(uuid_count, 0, "returned valid number of UUIDs from shared cache");
				verify_stackshot_sharedcache_layout(shared_cache_uuids, uuid_count);
				found_shared_cache_layout = true;
			}

			break;
		}
		case KCDATA_TYPE_CONTAINER_BEGIN: {
			T_QUIET;
			T_ASSERT_TRUE(kcdata_iter_container_valid(iter),
					"checked that container is valid");

			uint64_t containerid = kcdata_iter_container_id(iter);
			uint32_t container_type = kcdata_iter_container_type(iter);

			if (container_type == STACKSHOT_KCCONTAINER_SHAREDCACHE) {
				NSDictionary *container = parseKCDataContainer(&iter, &error);
				T_QUIET; T_ASSERT_NOTNULL(container, "parsed sharedcache container from stackshot");
				T_QUIET; T_ASSERT_NULL(error, "error unset after parsing sharedcache container");
				T_QUIET; T_EXPECT_EQ(sharedCaches[@(containerid)], nil, "sharedcache containerid %lld should be unique", containerid);
				sharedCaches[@(containerid)] = container;
				break;
			}

			if (container_type == STACKSHOT_KCCONTAINER_EXCLAVES) {
				found_exclaves = true;
				break;
			}

			/*
			 * treat containers other than tasks/transitioning_tasks
			 * as expanded in-line.
			 */
			if (container_type != STACKSHOT_KCCONTAINER_TASK &&
			    container_type != STACKSHOT_KCCONTAINER_TRANSITIONING_TASK) {
				T_LOG("container skipped: %d", container_type);
				break;
			}
			NSDictionary *container = parseKCDataContainer(&iter, &error);
			T_QUIET; T_ASSERT_NOTNULL(container, "parsed task/transitioning_task container from stackshot");
			T_QUIET; T_ASSERT_NULL(error, "error unset after parsing container");

			found_tasks++;

			NSDictionary* task_snapshot = container[@"task_snapshots"][@"task_snapshot"];
			NSDictionary* task_delta_snapshot = container[@"task_snapshots"][@"task_delta_snapshot"];
			NSDictionary* transitioning_task_snapshot = container[@"transitioning_task_snapshots"][@"transitioning_task_snapshot"];

			NSNumber *task_pid = NULL;
			if (task_snapshot) {
				task_pid = task_snapshot[@"ts_unique_pid"];
			} else if(task_delta_snapshot) {
				task_pid = task_snapshot[@"tds_unique_pid"];
			} else if(transitioning_task_snapshot) {
				task_pid = transitioning_task_snapshot[@"tts_pid"];
			}

			if (task_pid && [seen_tasks containsObject:task_pid]) {
				T_QUIET; T_ASSERT_FALSE([seen_tasks containsObject:task_pid], "No duplicate PIDs in stackshot");
				[seen_tasks addObject:task_pid];
			}

			/*
			 * Having processed the container, we now only check it
			 * if it's the correct type.
			 */
			if ((!expect_transitioning_task && (container_type != STACKSHOT_KCCONTAINER_TASK)) ||
			    (expect_transitioning_task && (container_type != STACKSHOT_KCCONTAINER_TRANSITIONING_TASK))) {
				break;
			}
			if (!expect_transitioning_task) {
			    	T_QUIET; T_ASSERT_TRUE(!!task_snapshot != !!task_delta_snapshot, "Either task_snapshot xor task_delta_snapshot provided");
			}

			if (expect_dispatch_queue_label && !found_dispatch_queue_label) {
				for (id thread_key in container[@"task_snapshots"][@"thread_snapshots"]) {
					NSMutableDictionary *thread = container[@"task_snapshots"][@"thread_snapshots"][thread_key];
					NSString *dql = thread[@"dispatch_queue_label"];

					if ([dql isEqualToString:@TEST_STACKSHOT_QUEUE_LABEL]) {
						found_dispatch_queue_label = true;
						break;
					}
				}
			}

			if (expect_transitioning_task && !found_transitioning_task) {
				if (transitioning_task_snapshot) {
					uint64_t the_pid = [transitioning_task_snapshot[@"tts_pid"] unsignedLongLongValue];
					if (the_pid == (uint64_t)transistioning_task_pid) {
					    found_transitioning_task = true;

					    T_PASS("FOUND Transitioning task %llu has a transitioning task snapshot", (uint64_t) transistioning_task_pid);
					    break;
					}
				}
			}

			if (expect_postexec_child && !found_postexec_child) {
				if (task_snapshot) {
					uint64_t unique_pid = [task_snapshot[@"ts_unique_pid"] unsignedLongLongValue];
					if (unique_pid == postexec_child_unique_pid) {
						found_postexec_child = true;

						T_PASS("post-exec child %llu has a task snapshot", postexec_child_unique_pid);

						break;
					}
				}

				if (task_delta_snapshot) {
					uint64_t unique_pid = [task_delta_snapshot[@"tds_unique_pid"] unsignedLongLongValue];
					if (unique_pid == postexec_child_unique_pid) {
						found_postexec_child = true;

						T_FAIL("post-exec child %llu shouldn't have a delta task snapshot", postexec_child_unique_pid);

						break;
					}
				}
			}

			int pid = [task_snapshot[@"ts_pid"] intValue];

			if (pid && expect_shared_cache_uuid && !found_shared_cache_uuid) {
				id ptr = container[@"task_snapshots"][@"shared_cache_dyld_load_info"];
				if (ptr) {
					id uuid = ptr[@"imageUUID"];

					uint8_t uuid_p[16];
					for (unsigned int i = 0; i < 16; i ++) {
						NSNumber *uuidByte = uuid[i];
						uuid_p[i] = (uint8_t)uuidByte.charValue;
					}

					check_shared_cache_uuid(uuid_p);

					uint64_t baseAddress = (uint64_t)((NSNumber *)ptr[@"imageSlidBaseAddress"]).longLongValue;
					uint64_t firstMapping = (uint64_t)((NSNumber *)ptr[@"sharedCacheSlidFirstMapping"]).longLongValue;

					T_EXPECT_LE(baseAddress, firstMapping,
						"in per-task shared_cache_dyld_load_info, "
						"baseAddress <= firstMapping");
					T_EXPECT_GE(baseAddress + (7ull << 32) + (1ull << 29),
						firstMapping,
						"in per-task shared_cache_dyld_load_info, "
						"baseAddress + 28.5gig >= firstMapping");

					size_t shared_cache_len;
					const void *addr = _dyld_get_shared_cache_range(&shared_cache_len);
					T_EXPECT_EQ((uint64_t)addr, firstMapping,
							"SlidFirstMapping should match shared_cache_range");

					/*
					 * check_shared_cache_uuid() will assert on failure, so if
					 * we get here, then we have found the shared cache UUID
					 * and it's correct
					 */
					found_shared_cache_uuid = true;
				}
			}

			if (expect_sharedcache_child) {
				uint64_t task_flags = [task_snapshot[@"ts_ss_flags"] unsignedLongLongValue];
				uint64_t sharedregion_flags = (task_flags & (kTaskSharedRegionNone | kTaskSharedRegionSystem | kTaskSharedRegionOther));
				id sharedregion_info = container[@"task_snapshots"][@"shared_cache_dyld_load_info"];
				id sharedcache_id = container[@"task_snapshots"][@"sharedCacheID"];
				if (!found_sharedcache_badflags) {
					T_QUIET; T_EXPECT_NE(sharedregion_flags, 0ll, "one of the kTaskSharedRegion flags should be set on all tasks");
					bool multiple = (sharedregion_flags & (sharedregion_flags - 1)) != 0;
					T_QUIET; T_EXPECT_FALSE(multiple, "only one kTaskSharedRegion flag should be set on each task");
					found_sharedcache_badflags = (sharedregion_flags == 0 || multiple);
				}
				if (pid == 0) {
					T_ASSERT_EQ(sharedregion_flags, (uint64_t)kTaskSharedRegionNone, "Kernel proc (pid 0) should have no shared region");
				} else if (pid == sharedcache_child_pid) {
					found_sharedcache_child = true;
					sharedcache_child_flags = sharedregion_flags;
				} else if (pid == getpid()) {
					found_sharedcache_self = true;
					sharedcache_self_flags = sharedregion_flags;
				}
				if (sharedregion_flags == kTaskSharedRegionOther && !(task_flags & kTaskSharedRegionInfoUnavailable)) {
					T_QUIET; T_EXPECT_NOTNULL(sharedregion_info, "kTaskSharedRegionOther should have a shared_cache_dyld_load_info struct");
					T_QUIET; T_EXPECT_NOTNULL(sharedcache_id, "kTaskSharedRegionOther should have a sharedCacheID");
					if (sharedcache_id != nil) {
						T_QUIET; T_EXPECT_NOTNULL(sharedCaches[sharedcache_id], "sharedCacheID %d should exist", [sharedcache_id intValue]);
					}
				} else {
					T_QUIET; T_EXPECT_NULL(sharedregion_info, "non-kTaskSharedRegionOther should have no shared_cache_dyld_load_info struct");
					T_QUIET; T_EXPECT_NULL(sharedcache_id, "non-kTaskSharedRegionOther should have no sharedCacheID");
				}
			}

			if (expect_zombie_child && (pid == zombie_child_pid)) {
				found_zombie_child = true;

				expected_num_tasks += 1;

				uint64_t task_flags = [task_snapshot[@"ts_ss_flags"] unsignedLongLongValue];
				T_ASSERT_TRUE((task_flags & kTerminatedSnapshot) == kTerminatedSnapshot, "child zombie marked as terminated");

				continue;
			}

			if (expect_translated_child && (pid == translated_child_pid)) {
				found_translated_child = true;

				uint64_t task_flags = [task_snapshot[@"ts_ss_flags"] unsignedLongLongValue];
				T_EXPECT_BITS_SET(task_flags, kTaskIsTranslated, "child marked as translated");

				continue;
			}
			if (expect_exec_inprogress && (pid == exec_inprogress_pid || pid == -exec_inprogress_pid)) {
				exec_inprogress_found++;
				T_LOG("found exec task with pid %d, instance %d", pid, exec_inprogress_found);
				T_QUIET; T_ASSERT_LE(exec_inprogress_found, 2, "no more than two with the expected pid");
				if (exec_inprogress_found == 2) {
					T_LOG("found 2 tasks with pid %d", exec_inprogress_pid);
					exec_inprogress_cb(containerid, exec_inprogress_containerid);
				} else {
					exec_inprogress_containerid = containerid;
				}
			}
			if (expect_driverkit && driverkit_cb != NULL) {
				driverkit_cb(pid);
			}
			if (expect_cseg_waitinfo) {
				NSArray *winfos = container[@"task_snapshots"][@"thread_waitinfo"];

				for (id i in winfos) {
					NSNumber *waitType = i[@"wait_type"];
					NSNumber *owner = i[@"owner"];
					if (waitType.intValue == kThreadWaitCompressor &&
							owner.unsignedLongValue == cseg_expected_threadid) {
						found_cseg_waitinfo = true;
						break;
					}
				}
			}

			if (expect_srp_waitinfo) {
				NSArray *tinfos = container[@"task_snapshots"][@"thread_turnstileinfo"];
				NSArray *winfos = container[@"task_snapshots"][@"thread_waitinfo"];
				for (id i in tinfos) {
					if (!found_srp_waitinfo) {
						bool found_thread = false;
						bool found_pid = false;
						if (([i[@"turnstile_flags"] intValue] & STACKSHOT_TURNSTILE_STATUS_THREAD) &&
						    [i[@"turnstile_context"] unsignedLongLongValue] == srp_expected_threadid &&
						    srp_expected_threadid != 0) {
							found_thread = true;
						}
						if (([i[@"turnstile_flags"] intValue] & STACKSHOT_TURNSTILE_STATUS_BLOCKED_ON_TASK) &&
						    [i[@"turnstile_context"] intValue] == srp_expected_pid &&
						    srp_expected_pid != -1) {
							found_pid = true;
						}
						if (found_pid || found_thread) {
							T_LOG("found SRP %s %lld waiter: %d", (found_thread ? "thread" : "pid"),
							    [i[@"turnstile_context"] unsignedLongLongValue], [i[@"waiter"] intValue]);
							/* we found something that is blocking the correct threadid */
							for (id j in winfos) {
								if ([j[@"waiter"] intValue] == [i[@"waiter"] intValue] &&
								    [j[@"wait_type"] intValue] == kThreadWaitPortReceive) {
									found_srp_waitinfo = true;
									T_EXPECT_EQ([j[@"wait_flags"] intValue], STACKSHOT_WAITINFO_FLAGS_SPECIALREPLY,
									    "SRP waitinfo should be marked as a special reply");
									break;
								}
							}

							if (found_srp_waitinfo) {
								break;
							}
						}
					}
				}
			}

			if (expect_sp_throttled) {
				NSArray *tinfos = container[@"task_snapshots"][@"thread_turnstileinfo"];
				for (id i in tinfos) {
					if (([i[@"turnstile_flags"] intValue] & STACKSHOT_TURNSTILE_STATUS_PORTFLAGS)
						&& [i[@"turnstile_context"] intValue] == throttled_service_ctx) {
						int portlabel_id = [i[@"portlabel_id"] intValue];
						T_LOG("[pid:%d] Turnstile (flags = 0x%x, ctx = %d, portlabel_id = %d)", pid,
							[i[@"turnstile_flags"] intValue], [i[@"turnstile_context"] intValue], portlabel_id);
						for (id portid in container[@"task_snapshots"][@"portlabels"]) {
							if (portlabel_id != [portid intValue]) {
								continue;
							}

							NSMutableDictionary *portlabel = container[@"task_snapshots"][@"portlabels"][portid];
							T_ASSERT_TRUE(portlabel != nil, "Found portlabel id: %d", [portid intValue]);
							NSString *portlabel_name = portlabel[@"portlabel_name"];
							T_EXPECT_TRUE(portlabel_name != nil, "Found portlabel %s", portlabel_name.UTF8String);
							T_EXPECT_EQ_STR(portlabel_name.UTF8String, THROTTLED_SERVICE_NAME, "throttled service port name matches");
							T_EXPECT_EQ(([portlabel[@"portlabel_flags"] intValue] & STACKSHOT_PORTLABEL_THROTTLED) != 0,
								is_throttled, "Port %s throttled", is_throttled ? "is" : "isn't");
							found_throttled_service = true;
							break;
						}
					}

					if (found_throttled_service) {
						break;
					}
				}
			}

			if (expect_suspendinfo) {
				// TODO: rdar://112563110
			}


			if (pid != getpid()) {
				break;
			}

			T_EXPECT_EQ_STR(current_process_name(),
					[task_snapshot[@"ts_p_comm"] UTF8String],
					"current process name matches in stackshot");

			uint64_t task_flags = [task_snapshot[@"ts_ss_flags"] unsignedLongLongValue];
			T_ASSERT_BITS_NOTSET(task_flags, kTerminatedSnapshot, "current process not marked as terminated");
			T_ASSERT_BITS_NOTSET(task_flags, kTaskIsTranslated, "current process not marked as translated");

			T_QUIET;
			T_EXPECT_LE(pid, [task_snapshot[@"ts_unique_pid"] intValue],
					"unique pid is greater than pid");

			NSDictionary* task_cpu_architecture = container[@"task_snapshots"][@"task_cpu_architecture"];
			T_QUIET; T_ASSERT_NOTNULL(task_cpu_architecture[@"cputype"], "have cputype");
			T_QUIET; T_ASSERT_NOTNULL(task_cpu_architecture[@"cpusubtype"], "have cputype");
			int cputype = [task_cpu_architecture[@"cputype"] intValue];
			int cpusubtype = [task_cpu_architecture[@"cpusubtype"] intValue];

			struct proc_archinfo archinfo;
			int retval = proc_pidinfo(pid, PROC_PIDARCHINFO, 0, &archinfo, sizeof(archinfo));
			T_QUIET; T_WITH_ERRNO; T_ASSERT_GT(retval, 0, "proc_pidinfo(PROC_PIDARCHINFO) returned a value > 0");
			T_QUIET; T_ASSERT_EQ(retval, (int)sizeof(struct proc_archinfo), "proc_pidinfo call for PROC_PIDARCHINFO returned expected size");
			T_QUIET; T_EXPECT_EQ(cputype, archinfo.p_cputype, "cpu type is correct");
			T_QUIET; T_EXPECT_EQ(cpusubtype, archinfo.p_cpusubtype, "cpu subtype is correct");

			NSDictionary * codesigning_info = container[@"task_snapshots"][@"stackshot_task_codesigning_info"];
			T_QUIET; T_ASSERT_NOTNULL(codesigning_info[@"csflags"], "have csflags");
			uint64_t flags = [codesigning_info[@"csflags"] unsignedLongLongValue];
			T_QUIET; T_EXPECT_GT(flags, 0, "nonzero csflags");

			T_QUIET; T_ASSERT_NOTNULL(container[@"task_snapshots"][@"jetsam_coalition"], "have jetsam coalition");
			uint64_t jetsam_coalition = [container[@"task_snapshots"][@"jetsam_coalition"] unsignedLongLongValue];
			T_QUIET; T_EXPECT_GT(jetsam_coalition, 0, "nonzero jetsam coalition");

			bool found_main_thread = false;
			uint64_t main_thread_id = -1ULL;
			bool found_null_kernel_frame = false;
			for (id thread_key in container[@"task_snapshots"][@"thread_snapshots"]) {
				NSMutableDictionary *thread = container[@"task_snapshots"][@"thread_snapshots"][thread_key];
				NSDictionary *thread_snap = thread[@"thread_snapshot"];

				T_QUIET; T_EXPECT_GT([thread_snap[@"ths_thread_id"] intValue], 0,
						"thread ID of thread in current task is valid");
				T_QUIET; T_EXPECT_GT([thread_snap[@"ths_base_priority"] intValue], 0,
						"base priority of thread in current task is valid");
				T_QUIET; T_EXPECT_GT([thread_snap[@"ths_sched_priority"] intValue], 0,
						"scheduling priority of thread in current task is valid");

				NSString *pth_name = thread[@"pth_name"];
				if (pth_name != nil && [pth_name isEqualToString:@TEST_THREAD_NAME]) {
					found_main_thread = true;
					main_thread_id = [thread_snap[@"ths_thread_id"] unsignedLongLongValue];

					T_QUIET; T_EXPECT_GT([thread_snap[@"ths_total_syscalls"] intValue], 0,
							"total syscalls of current thread is valid");

					NSDictionary *cpu_times = thread[@"cpu_times"];
					T_EXPECT_GE([cpu_times[@"runnable_time"] intValue],
							[cpu_times[@"system_time"] intValue] +
							[cpu_times[@"user_time"] intValue],
							"runnable time of current thread is valid");
				}
				if (!found_null_kernel_frame) {
					for (NSNumber *frame in thread[@"kernel_frames"]) {
						if (frame.unsignedLongValue == 0) {
							found_null_kernel_frame = true;
							break;
						}
					}
				}
				if (expect_asyncstack && !found_asyncstack &&
				    asyncstack_threadid == [thread_snap[@"ths_thread_id"] unsignedLongLongValue]) {
					found_asyncstack = true;
					NSArray* async_stack = thread[@"user_async_stack_frames"];
					NSNumber* start_idx = thread[@"user_async_start_index"];
					NSArray* user_stack = thread[@"user_stack_frames"];
					T_QUIET; T_ASSERT_NOTNULL(async_stack, "async thread %#llx has user_async_stack_frames", asyncstack_threadid);
					T_QUIET; T_ASSERT_NOTNULL(start_idx, "async thread %#llx has user_async_start_index", asyncstack_threadid);
					T_QUIET; T_ASSERT_NOTNULL(user_stack, "async thread %#llx has user_stack_frames", asyncstack_threadid);
					T_QUIET; T_ASSERT_EQ(async_stack.count, asyncstack_stack.count,
						"actual async_stack count == expected async_stack count");
					for (size_t i = 0; i < async_stack.count; i++) {
						T_EXPECT_EQ([async_stack[i][@"lr"] unsignedLongLongValue],
							[asyncstack_stack[i] unsignedLongLongValue], "frame %zu matches", i);
					}
				}
			}
			T_EXPECT_TRUE(found_main_thread, "found main thread for current task in stackshot");
			T_EXPECT_FALSE(found_null_kernel_frame, "should not see any NULL kernel frames");

			if (expect_turnstile_lock && !found_turnstile_lock) {
				NSArray *tsinfos = container[@"task_snapshots"][@"thread_turnstileinfo"];

				for (id i in tsinfos) {
					if ([i[@"turnstile_context"] unsignedLongLongValue] == main_thread_id) {
						found_turnstile_lock = true;
						break;
					}
				}
			}
			break;
		}
		case STACKSHOT_KCTYPE_SHAREDCACHE_LOADINFO: {
			// Legacy shared cache info
			struct dyld_shared_cache_loadinfo *payload = kcdata_iter_payload(iter);
			T_ASSERT_EQ((size_t)kcdata_iter_size(iter), sizeof(*payload), "valid dyld_shared_cache_loadinfo struct");

			check_shared_cache_uuid(payload->sharedCacheUUID);

			T_EXPECT_LE(payload->sharedCacheUnreliableSlidBaseAddress,
				payload->sharedCacheSlidFirstMapping,
				"SlidBaseAddress <= SlidFirstMapping");
			T_EXPECT_GE(payload->sharedCacheUnreliableSlidBaseAddress + (7ull << 32) + (1ull << 29),
				payload->sharedCacheSlidFirstMapping,
				"SlidFirstMapping should be within 28.5gigs of SlidBaseAddress");

			size_t shared_cache_len;
			const void *addr = _dyld_get_shared_cache_range(&shared_cache_len);
			T_EXPECT_EQ((uint64_t)addr, payload->sharedCacheSlidFirstMapping,
			    "SlidFirstMapping should match shared_cache_range");

			/*
			 * check_shared_cache_uuid() asserts on failure, so we must have
			 * found the shared cache UUID to be correct.
			 */
			found_shared_cache_uuid = true;
			break;
		}
		case KCDATA_TYPE_UINT64_DESC: {
			char     *desc;
			uint64_t *data;
			uint32_t  size;
			kcdata_iter_get_data_with_desc(iter, &desc, &data, &size);

			if (strcmp(desc, "stackshot_tasks_count") == 0) {
				expected_num_tasks = *data;
			} else if (strcmp(desc, "stackshot_threads_count") == 0) {
				expected_num_threads = *data;
			}

			break;
		}
		case STACKSHOT_KCTYPE_LATENCY_INFO_CPU: {
			struct stackshot_latency_cpu *cpu_latency = kcdata_iter_payload(iter);
			found_percpu_tasks += cpu_latency->tasks_processed;
			found_percpu_threads += cpu_latency->threads_processed;
			break;
		}
		}
	}

	if (expect_sharedcache_child) {
		T_QUIET; T_ASSERT_TRUE(found_sharedcache_child, "found sharedcache child in kcdata");
		T_QUIET; T_ASSERT_TRUE(found_sharedcache_self, "found self in kcdata");
		if (found_sharedcache_child && found_sharedcache_self) {
			T_QUIET; T_ASSERT_NE(sharedcache_child_flags, (uint64_t)kTaskSharedRegionNone, "sharedcache child should have shared region");
			T_QUIET; T_ASSERT_NE(sharedcache_self_flags, (uint64_t)kTaskSharedRegionNone, "sharedcache: self should have shared region");
			if (sharedcache_self_flags == kTaskSharedRegionSystem && !sharedcache_child_sameaddr) {
				/* If we're in the system shared region, and the child has a different address, child must have an Other shared region */
				T_ASSERT_EQ(sharedcache_child_flags, (uint64_t)kTaskSharedRegionOther,
				    "sharedcache child should have Other shared region");
			}
		}
	}

	if (expect_transitioning_task) {
		T_QUIET; T_ASSERT_TRUE(found_transitioning_task, "found transitioning_task child in kcdata");
	}

	if (expect_exec_inprogress) {
		T_QUIET; T_ASSERT_GT(exec_inprogress_found, 0, "found at least 1 task for execing process");
	}

	if (expect_zombie_child) {
		T_QUIET; T_ASSERT_TRUE(found_zombie_child, "found zombie child in kcdata");
	}

	if (expect_postexec_child) {
		T_QUIET; T_ASSERT_TRUE(found_postexec_child, "found post-exec child in kcdata");
	}

	if (expect_translated_child) {
		T_QUIET; T_ASSERT_TRUE(found_translated_child, "found translated child in kcdata");
	}

	if (expect_shared_cache_layout) {
		T_QUIET; T_ASSERT_TRUE(found_shared_cache_layout, "shared cache layout found in kcdata");
	}

	if (expect_shared_cache_uuid) {
		T_QUIET; T_ASSERT_TRUE(found_shared_cache_uuid, "shared cache UUID found in kcdata");
	}

	if (expect_dispatch_queue_label) {
		T_QUIET; T_ASSERT_TRUE(found_dispatch_queue_label, "dispatch queue label found in kcdata");
	}

	if (expect_turnstile_lock) {
		T_QUIET; T_ASSERT_TRUE(found_turnstile_lock, "found expected deadlock");
	}

	if (expect_cseg_waitinfo) {
		T_QUIET; T_ASSERT_TRUE(found_cseg_waitinfo, "found c_seg waitinfo");
	}

	if (expect_srp_waitinfo) {
		T_QUIET; T_ASSERT_TRUE(found_srp_waitinfo, "found special reply port waitinfo");
	}

	if (expect_sp_throttled) {
		T_QUIET; T_ASSERT_TRUE(found_throttled_service, "found the throttled service");
	}

	if (expect_asyncstack) {
		T_QUIET; T_ASSERT_TRUE(found_asyncstack, "found async stack threadid");
	}

	if ([extra objectForKey:no_exclaves_key] != nil) {
		T_QUIET; T_ASSERT_FALSE(found_exclaves, "did not find any Exclaves data");
	}


	bool check_counts = !delta && !found_transitioning_task && !expect_single_task && !expect_driverkit;

	if (check_counts && (expected_num_threads != 0) && (found_percpu_threads != 0)) {
		/* If the task counts below check out, we can be sure that the per-cpu reported thread counts are accurate. */
		T_QUIET; T_ASSERT_EQ_ULLONG(found_percpu_threads, expected_num_threads, "number of threads reported by CPUs matches expected count");
	}

	if (check_counts && (expected_num_tasks != 0)) {
		T_QUIET; T_ASSERT_EQ_ULLONG(found_tasks, expected_num_tasks, "number of tasks in kcdata matches expected count");
		if (found_percpu_tasks != 0) {
			T_QUIET; T_ASSERT_EQ_ULLONG(found_percpu_tasks, expected_num_tasks, "number of tasks reported by CPUs matches expected count");
		}
	}

	T_ASSERT_FALSE(KCDATA_ITER_FOREACH_FAILED(iter), "successfully iterated kcdata");

	free(inflatedBufferBase);
}

static const char *
current_process_name(void)
{
	static char name[64];

	if (!name[0]) {
		int ret = proc_name(getpid(), name, sizeof(name));
		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(ret, "proc_name failed for current process");
	}

	return name;
}

static void
initialize_thread(void)
{
	int ret = pthread_setname_np(TEST_THREAD_NAME);
	T_QUIET;
	T_ASSERT_POSIX_ZERO(ret, "set thread name to %s", TEST_THREAD_NAME);
}

T_DECL(dirty_buffer, "test that stackshot works with a dirty input buffer from kernel", T_META_TAG_VM_PREFERRED)
{
	const char *test_sysctl = "stackshot_dirty_buffer";
	int64_t result;

	T_LOG("running sysctl to trigger kernel-driven stackshot");
	result = run_sysctl_test(test_sysctl, 0);
	T_ASSERT_EQ_LLONG(result, 1, "sysctl result indicated success");
}

T_DECL(kernel_initiated, "smoke test that stackshot works with kernel-initiated stackshots", T_META_TAG_VM_PREFERRED)
{
	const char *test_sysctl = "stackshot_kernel_initiator";
	int64_t result;
	__block bool did_get_stackshot = false;

	initialize_thread(); // must run before the stackshots to keep parse_stackshot happy

	T_LOG("running sysctl to trigger kernel-driven stackshot type 1");
	result = run_sysctl_test(test_sysctl, 1);
	T_ASSERT_EQ_LLONG(result, 1, "sysctl result indicated success");

	T_LOG("running sysctl to trigger kernel-driven stackshot type 2");
	result = run_sysctl_test(test_sysctl, 2);
	T_ASSERT_EQ_LLONG(result, 1, "sysctl result indicated success");

	struct scenario scenario = {
		.name = "from_kernel_initiated",
		.flags = STACKSHOT_RETRIEVE_EXISTING_BUFFER,
	};

	T_LOG("attempting to fetch stored in-kernel stackshot");
	take_stackshot(&scenario, false, ^(void *ssbuf, size_t sslen) {
		T_ASSERT_NOTNULL(ssbuf, "non-null kernel stackshot");
		T_ASSERT_GT(sslen, 0, "non-zero stackshot size");
		parse_stackshot(0, ssbuf, sslen, nil);
		did_get_stackshot = true;
	});

	T_ASSERT_TRUE(did_get_stackshot, "got stackshot from kernel type 2");
}
