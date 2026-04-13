/*
 * Copyright (c) 2025 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

/* test that the header doesn't implicitly depend on others */
#include <sys/resource_private.h>
#include <sys/resource.h>

#include <libproc.h>

#include <sys/types.h>
#include <unistd.h>

#include <mach/task.h>
#include <mach/task_policy.h>
#include <mach/mach.h>

#include <darwintest.h>
#include <darwintest_utils.h>
#include <sched/sched_test_utils.h>

#include <sys/sfi.h>
#include <Kernel/kern/ledger.h>  /* TODO: this should be installed for userspace */
extern int ledger(int cmd, caddr_t arg1, caddr_t arg2, caddr_t arg3);

#include <kern/debug.h>
extern int __microstackshot(char *tracebuf, uint32_t tracebuf_size, uint32_t flags);


T_GLOBAL_META(T_META_NAMESPACE("xnu.scheduler"),
    T_META_RADAR_COMPONENT_NAME("xnu"),
    T_META_RADAR_COMPONENT_VERSION("scheduler"),
    T_META_OWNER("chimene"),
    T_META_RUN_CONCURRENTLY(false), /* because of messing with global SFI */
    T_META_ASROOT(true), /* for TASK_POLICY_STATE, and setting SFI */
    T_META_TAG_VM_PREFERRED);

static void
check_is_bg(bool wants_bg)
{
	kern_return_t kr;
	struct task_policy_state policy_state;

	mach_msg_type_number_t count = TASK_POLICY_STATE_COUNT;
	boolean_t get_default = FALSE;

	kr = task_policy_get(mach_task_self(), TASK_POLICY_STATE,
	    (task_policy_t)&policy_state, &count, &get_default);

	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "task_policy_get(TASK_POLICY_STATE)");

	/*
	 * A test reporting type=APPLICATION should have the live donor bit set.
	 * If this fails, the test may have been launched as a daemon instead.
	 */
	T_QUIET; T_ASSERT_BITS_SET(policy_state.flags, TASK_IMP_LIVE_DONOR, "test should be live donor enabled");

	/*
	 * The BG bit is updated via task_policy_update_internal_locked,
	 * checking this proves that the first phase update ran on this task.
	 */
	if (wants_bg) {
		T_ASSERT_BITS_SET(policy_state.effective, POLICY_EFF_DARWIN_BG, "%d: is BG", getpid());
	} else {
		T_ASSERT_BITS_NOTSET(policy_state.effective, POLICY_EFF_DARWIN_BG, "%d: is not BG", getpid());
	}

	/*
	 * The live donor bit is updated via task_policy_update_complete_unlocked,
	 * checking this proves that the second phase update ran on this task.
	 */
	if (wants_bg) {
		T_ASSERT_BITS_NOTSET(policy_state.flags, TASK_IMP_DONOR, "%d: is not live donor", getpid());
	} else {
		T_ASSERT_BITS_SET(policy_state.flags, TASK_IMP_DONOR, "%d: is live donor", getpid());
	}
}

static void
check_runaway_mode(bool expected_mode)
{
	int runaway_mode = getpriority(PRIO_DARWIN_RUNAWAY_MITIGATION, 0);

	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(runaway_mode, "getpriority(PRIO_DARWIN_RUNAWAY_MITIGATION)");

	T_LOG("pid %d: runaway mitigation mode is: %d", getpid(), runaway_mode);

	if (expected_mode) {
		T_QUIET;
		T_ASSERT_EQ(runaway_mode, PRIO_DARWIN_RUNAWAY_MITIGATION_ON, "should be on");
		check_is_bg(true);
	} else {
		T_QUIET;
		T_ASSERT_EQ(runaway_mode, PRIO_DARWIN_RUNAWAY_MITIGATION_OFF, "should be off");
		check_is_bg(false);
	}
}

T_DECL(entitled_runaway_mode, "runaway mitigation mode should be settable while entitled")
{
	T_LOG("uid: %d", getuid());

	check_runaway_mode(false);

	T_ASSERT_POSIX_SUCCESS(setpriority(PRIO_DARWIN_RUNAWAY_MITIGATION, 0, PRIO_DARWIN_RUNAWAY_MITIGATION_ON),
	    "setpriority(PRIO_DARWIN_RUNAWAY_MITIGATION, 0, PRIO_DARWIN_RUNAWAY_MITIGATION_ON)");

	check_runaway_mode(true);

	T_ASSERT_POSIX_SUCCESS(setpriority(PRIO_DARWIN_RUNAWAY_MITIGATION, 0, PRIO_DARWIN_RUNAWAY_MITIGATION_OFF),
	    "setpriority(PRIO_DARWIN_RUNAWAY_MITIGATION, 0, PRIO_DARWIN_RUNAWAY_MITIGATION_OFF)");

	check_runaway_mode(false);
}

T_DECL(entitled_runaway_mode_read_root, "runaway mitigation mode should be readable as root",
    T_META_ASROOT(true))
{
	T_LOG("uid: %d", getuid());

	check_runaway_mode(false);
}

T_DECL(entitled_runaway_mode_read_notroot, "runaway mitigation mode should be readable as not root but entitled",
    T_META_ASROOT(false))
{
	T_LOG("uid: %d", getuid());

	int runaway_mode = getpriority(PRIO_DARWIN_RUNAWAY_MITIGATION, getpid());

	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(runaway_mode, "getpriority(PRIO_DARWIN_RUNAWAY_MITIGATION)");

	T_ASSERT_EQ(runaway_mode, PRIO_DARWIN_RUNAWAY_MITIGATION_OFF, "should be off");
}

T_DECL(runaway_mode_child_exit, "runaway mitigation mode should disappear when child exits")
{
	T_LOG("uid: %d", getuid());

	check_runaway_mode(false);

	T_LOG("Spawning child");

	pid_t child_pid = fork();

	if (child_pid == 0) {
		/* child process */

		check_runaway_mode(false);

		T_ASSERT_POSIX_SUCCESS(setpriority(PRIO_DARWIN_RUNAWAY_MITIGATION, 0, PRIO_DARWIN_RUNAWAY_MITIGATION_ON),
		    "setpriority(PRIO_DARWIN_RUNAWAY_MITIGATION, 0, PRIO_DARWIN_RUNAWAY_MITIGATION_ON)");

		check_runaway_mode(true);

		T_LOG("Exit pid %d with runaway mitigation mode on", getpid());

		exit(0);
	} else {
		T_ASSERT_POSIX_SUCCESS(child_pid, "fork, pid %d", child_pid);

		/* wait for child process to exit */
		int exit_status = 0, signum = 0;

		T_ASSERT_TRUE(dt_waitpid(child_pid, &exit_status, &signum, 5),
		    "wait for child (%d) complete", child_pid);

		T_QUIET; T_ASSERT_EQ(exit_status, 0, "dt_waitpid: exit_status");
		T_QUIET; T_ASSERT_EQ(signum, 0, "dt_waitpid: signum");
	}

	check_runaway_mode(false);
}

T_DECL(runaway_mode_child_set, "runaway mitigation mode should be settable on child pid")
{
	T_LOG("uid: %d", getuid());

	check_runaway_mode(false);

	int fd[2];

	T_QUIET; T_ASSERT_POSIX_SUCCESS(pipe(fd), "pipe()");

	T_LOG("Spawning child");

	pid_t child_pid = fork();

	if (child_pid == 0) {
		char buf[10];

		/* child process */
		T_ASSERT_POSIX_SUCCESS(child_pid, "fork, in child with pid %d", getpid());

		T_ASSERT_POSIX_SUCCESS(close(fd[1]), "close(fd[1])");

		T_ASSERT_POSIX_SUCCESS(read(fd[0], buf, sizeof(buf)), "read(fd[0], buf, sizeof(buf)");

		T_ASSERT_POSIX_SUCCESS(close(fd[0]), "close(fd[0])");

		check_runaway_mode(true);

		T_LOG("Exit pid %d with runaway mitigation mode on", getpid());

		exit(0);
	} else {
		T_ASSERT_POSIX_SUCCESS(child_pid, "fork parent: child pid %d", child_pid);

		T_ASSERT_POSIX_SUCCESS(setpriority(PRIO_DARWIN_RUNAWAY_MITIGATION, child_pid, PRIO_DARWIN_RUNAWAY_MITIGATION_ON),
		    "setpriority(PRIO_DARWIN_RUNAWAY_MITIGATION, child_pid, PRIO_DARWIN_RUNAWAY_MITIGATION_ON)");

		int runaway_mode = getpriority(PRIO_DARWIN_RUNAWAY_MITIGATION, child_pid);

		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(runaway_mode, "getpriority(PRIO_DARWIN_RUNAWAY_MITIGATION)");

		T_ASSERT_EQ(runaway_mode, PRIO_DARWIN_RUNAWAY_MITIGATION_ON, "should be on");

		T_QUIET; T_LOG("Signalling child to continue");
		T_ASSERT_POSIX_SUCCESS(close(fd[1]), "close(fd[1])");

		/* wait for child process to exit */
		int exit_status = 0, signum = 0;

		T_ASSERT_TRUE(dt_waitpid(child_pid, &exit_status, &signum, 5),
		    "wait for child (%d) complete", child_pid);

		T_QUIET; T_ASSERT_EQ(exit_status, 0, "dt_waitpid: exit_status");
		T_QUIET; T_ASSERT_EQ(signum, 0, "dt_waitpid: signum");
	}

	check_runaway_mode(false);
}


/*
 * TODO: This should be in a test utils library,
 * but it requires including Kernel.framework header kern/ledger.h, which is Bad
 */
static size_t
ledger_index_for_string(size_t *num_entries, char* string)
{
	struct ledger_info li;
	struct ledger_template_info *templateInfo = NULL;
	int ret;
	size_t i, footprint_index;
	bool found = false;

	ret = ledger(LEDGER_INFO, (caddr_t)(uintptr_t)getpid(), (caddr_t)&li, NULL);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "ledger(LEDGER_INFO)");

	T_QUIET; T_ASSERT_GT(li.li_entries, (int64_t) 0, "num ledger entries is valid");
	*num_entries = (size_t) li.li_entries;
	templateInfo = malloc((size_t)li.li_entries * sizeof(struct ledger_template_info));
	T_QUIET; T_ASSERT_NOTNULL(templateInfo, "malloc entries");

	footprint_index = 0;
	ret = ledger(LEDGER_TEMPLATE_INFO, (caddr_t) templateInfo, (caddr_t) num_entries, NULL);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "ledger(LEDGER_TEMPLATE_INFO)");
	for (i = 0; i < *num_entries; i++) {
		if (strcmp(templateInfo[i].lti_name, string) == 0) {
			footprint_index = i;
			found = true;
		}
	}
	free(templateInfo);
	T_QUIET; T_ASSERT_TRUE(found, "found %s in ledger", string);
	return footprint_index;
}

/*
 * sadly there's no 'get just this one ledger index' syscall,
 * we have to read all ledgers and filter for the one we want
 */
static int64_t
get_ledger_entry_for_pid(pid_t pid, size_t index, size_t num_entries)
{
	int ret;
	int64_t value;
	struct ledger_entry_info *lei = NULL;

	lei = malloc(num_entries * sizeof(*lei));
	ret = ledger(LEDGER_ENTRY_INFO, (caddr_t) (uintptr_t) pid, (caddr_t) lei, (caddr_t) &num_entries);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "ledger(LEDGER_ENTRY_INFO)");
	value = lei[index].lei_balance;
	free(lei);
	return value;
}


uint64_t initial_sfi_window = 0, initial_class_offtime = 0;

static void
restore_sfi_state(void)
{
	T_LOG("Restoring initial system SFI window %lld, SFI_CLASS_RUNAWAY_MITIGATION class offtime %lld",
	    initial_sfi_window, initial_class_offtime);

	/*
	 * Setting window will fail if there is a larger offtime set, and
	 * setting class will fail if the window is smaller.
	 * To avoid this, disable the window, configure new values, then finally
	 * re-enable the window.
	 */

	T_QUIET; T_ASSERT_POSIX_SUCCESS(system_set_sfi_window(0),
	    "system_set_sfi_window(0)");

	T_QUIET; T_ASSERT_POSIX_SUCCESS(sfi_set_class_offtime(SFI_CLASS_RUNAWAY_MITIGATION, initial_class_offtime),
	    "system_set_sfi_window(%lld)", initial_class_offtime);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(system_set_sfi_window(initial_sfi_window),
	    "system_set_sfi_window(%lld)", initial_sfi_window);
}

const int spin_seconds = 1;


static void *
spin_thread(void *arg)
{
	static mach_timebase_info_data_t timebase_info;
	mach_timebase_info(&timebase_info);

	uint64_t duration = spin_seconds * NSEC_PER_SEC * timebase_info.denom / timebase_info.numer;
	uint64_t deadline = mach_absolute_time() + duration;

	while (mach_absolute_time() < deadline) {
		;
	}

	return NULL;
}

T_DECL(runaway_mode_child_sfi, "runaway mitigation mode should cause SFI")
{
	if (!wait_for_quiescence_default(argc, argv)) {
		T_LOG("WARN: System did not quiesce. This test is sensitive to thermal effects, so other workloads may cause interference.");
	}

	T_LOG("uid: %d", getuid());

	trace_handle_t trace = begin_collect_trace(argc, argv, T_NAME);

	check_runaway_mode(false);

	T_QUIET; T_ASSERT_POSIX_SUCCESS(system_get_sfi_window(&initial_sfi_window),
	    "system_get_sfi_window(&initial_sfi_window)");

	T_QUIET; T_ASSERT_POSIX_SUCCESS(sfi_get_class_offtime(SFI_CLASS_RUNAWAY_MITIGATION, &initial_class_offtime),
	    "sfi_get_class_offtime(SFI_CLASS_RUNAWAY_MITIGATION, &initial_class_offtime)");

	T_LOG("Initial System SFI window %lld, SFI_CLASS_RUNAWAY_MITIGATION class offtime %lld\n", initial_sfi_window, initial_class_offtime);

	size_t num_ledger_entries = 0;
	size_t ledger_index = ledger_index_for_string(&num_ledger_entries, "SFI_CLASS_RUNAWAY_MITIGATION");
	uint64_t sfi_time_before = get_ledger_entry_for_pid(getpid(), ledger_index, num_ledger_entries);

	T_LOG("SFI_CLASS_RUNAWAY_MITIGATION ledger index: %zu out of %zu\n", ledger_index, num_ledger_entries);

	T_LOG("Initial accumulated SFI time: %lld\n", sfi_time_before);

	T_ATEND(restore_sfi_state);

	uint64_t custom_sfi_window = 100000; /* microseconds */
	uint64_t custom_class_offtime = 50000;

	T_LOG("Setting custom system SFI window %lld, SFI_CLASS_RUNAWAY_MITIGATION class offtime %lld",
	    custom_sfi_window, custom_class_offtime);

	T_QUIET; T_ASSERT_POSIX_SUCCESS(system_set_sfi_window(0),
	    "system_set_sfi_window(0)");
	T_ASSERT_POSIX_SUCCESS(sfi_set_class_offtime(SFI_CLASS_RUNAWAY_MITIGATION, custom_class_offtime),
	    "sfi_set_class_offtime(SFI_CLASS_RUNAWAY_MITIGATION, %lld)", custom_class_offtime);
	T_ASSERT_POSIX_SUCCESS(system_set_sfi_window(custom_sfi_window),
	    "system_set_sfi_window(%lld)", custom_sfi_window);

	pthread_t thread;

	T_LOG("Spawning thread to spin for %d seconds\n", spin_seconds);

	int rv = pthread_create(&thread, NULL, spin_thread, NULL);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "pthread_create");

	T_LOG("Enable mitigation mode\n");

	T_ASSERT_POSIX_SUCCESS(setpriority(PRIO_DARWIN_RUNAWAY_MITIGATION, 0, PRIO_DARWIN_RUNAWAY_MITIGATION_ON),
	    "setpriority(PRIO_DARWIN_RUNAWAY_MITIGATION, 0, PRIO_DARWIN_RUNAWAY_MITIGATION_ON)");

	check_runaway_mode(true);

	T_LOG("Wait %d seconds for spin to finish\n", spin_seconds);

	rv = pthread_join(thread, NULL);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "pthread_join");

	T_LOG("Thread joined, disable mitigation mode\n");

	T_ASSERT_POSIX_SUCCESS(setpriority(PRIO_DARWIN_RUNAWAY_MITIGATION, 0, PRIO_DARWIN_RUNAWAY_MITIGATION_OFF),
	    "setpriority(PRIO_DARWIN_RUNAWAY_MITIGATION, 0, PRIO_DARWIN_RUNAWAY_MITIGATION_OFF)");

	uint64_t sfi_time_after = get_ledger_entry_for_pid(getpid(), ledger_index, num_ledger_entries);

	T_LOG("Ending accumulated SFI time: %lld\n", sfi_time_after);

	T_ASSERT_LT(sfi_time_before, sfi_time_after, "SFI_CLASS_RUNAWAY_MITIGATION SFI time must have increased");

	check_runaway_mode(false);

	uint64_t final_sfi_window = 0, final_class_offtime = 0;

	T_QUIET; T_ASSERT_POSIX_SUCCESS(system_get_sfi_window(&final_sfi_window),
	    "system_get_sfi_window(&final_sfi_window)");

	T_QUIET; T_ASSERT_POSIX_SUCCESS(sfi_get_class_offtime(SFI_CLASS_RUNAWAY_MITIGATION, &final_class_offtime),
	    "sfi_get_class_offtime(SFI_CLASS_RUNAWAY_MITIGATION, &final_class_offtime)");

	/*
	 * If the System SFI configuration was changed out from under us during the test, either us or them will be confused.
	 */
	T_QUIET; T_ASSERT_EQ(custom_sfi_window, final_sfi_window, "[%s] System SFI window should not unexpectedly change during the test", platform_train_descriptor());
	T_QUIET; T_ASSERT_EQ(custom_class_offtime, final_class_offtime, "[%s] System SFI offtime should not unexpectedly change during the test", platform_train_descriptor());

	end_collect_trace(trace);
}

#if defined(__arm64__)

static bool found_flag = false;
static bool found_self = false;

static const size_t microstackshot_buf_size = 16 * 1024;

static bool
search_for_self_microstackshot(bool log_details)
{
	void *buf = calloc(microstackshot_buf_size, 1);
	T_QUIET; T_ASSERT_NOTNULL(buf, "allocate buffer");

	int ret = __microstackshot(buf, microstackshot_buf_size, STACKSHOT_GET_MICROSTACKSHOT);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "microstackshot");

	if (!log_details) {
		T_QUIET;
	}
	T_EXPECT_EQ(*(uint32_t *)buf,
	    (uint32_t)STACKSHOT_MICRO_SNAPSHOT_MAGIC,
	    "magic value for microstackshot matches");

	uint32_t magic = STACKSHOT_TASK_SNAPSHOT_MAGIC;

	void* next_tsnap = memmem(buf, microstackshot_buf_size, &magic, sizeof(magic));

	void* buf_end = buf + microstackshot_buf_size;

	while (next_tsnap != NULL && next_tsnap + sizeof(struct task_snapshot) < buf_end) {
		struct task_snapshot *tsnap = (struct task_snapshot *)next_tsnap;
		unsigned int offset = next_tsnap - buf;

		if (log_details) {
			T_LOG("%6d: found snap pid %d name %s\n", offset, tsnap->pid, (char*)&tsnap->p_comm);
		}

		if (tsnap->pid == getpid()) {
			if (log_details) {
				T_LOG("%6d: found self snap: flags 0x%x 0x%llx\n", offset, tsnap->ss_flags, tsnap->disk_reads_count);
			}
			found_self = true;

			if (tsnap->disk_reads_count & kTaskRunawayMitigation) {
				T_LOG("%6d: found runaway flag: pid %d, name %s, flags: 0x%x 0x%llx, \n",
				    offset, tsnap->pid, (char*)&tsnap->p_comm, tsnap->ss_flags, tsnap->disk_reads_count);
				found_flag = true;
			}
		}

		void* search_start = next_tsnap + sizeof(struct task_snapshot);
		size_t remaining_size = buf_end - search_start;
		next_tsnap = memmem(search_start, remaining_size, &magic, sizeof(magic));
	}

	free(buf);

	return found_flag;
}

T_DECL(runaway_mode_microstackshot_flag,
    "check that mitigated processes show up in microstackshot",
    T_META_REQUIRES_SYSCTL_EQ("kern.monotonic.supported", 1),
    T_META_TAG_VM_NOT_ELIGIBLE, T_META_TIMEOUT(120))
{
	unsigned int pmi_counter;
	size_t sysctl_size = sizeof(pmi_counter);
	int ret = sysctlbyname(
		"kern.microstackshot.pmi_sample_counter",
		&pmi_counter, &sysctl_size, NULL, 0);
	if (ret == -1 && errno == ENOENT) {
		T_SKIP("no PMI support");
	} else {
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "query PMI counter");
	}
	uint64_t pmi_period;
	sysctl_size = sizeof(pmi_period);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(sysctlbyname(
		    "kern.microstackshot.pmi_sample_period",
		    &pmi_period, &sysctl_size, NULL, 0),
	    "query PMI period");

	T_LOG("PMI counter: %u", pmi_counter);
	T_LOG("PMI period: %llu", pmi_period);

	if (pmi_period == 0) {
		T_SKIP("PMI microstackshots not enabled");
	}

	T_LOG("Enable mitigation mode on self\n");

	T_EXPECT_POSIX_SUCCESS(setpriority(PRIO_DARWIN_RUNAWAY_MITIGATION,
	    0, PRIO_DARWIN_RUNAWAY_MITIGATION_ON),
	    "setpriority(PRIO_DARWIN_RUNAWAY_MITIGATION, 0, PRIO_DARWIN_RUNAWAY_MITIGATION_ON)");

	uint32_t iterations = 100;

	/* Over-spin to make it likely we get sampled at least once before failing */
	uint32_t multiplier = 10;
	uint64_t target_cycles = multiplier * pmi_period;

	T_LOG("Spinning for %d iterations or %lld*%d cycles or until self-sample is found\n",
	    iterations, pmi_period, multiplier);

	struct rusage_info_v6 ru = {};

	for (int i = 0; i < iterations; i++) {
		spin_thread(NULL);

		int rv = proc_pid_rusage(getpid(), RUSAGE_INFO_V6, (rusage_info_t *)&ru);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "proc_pid_rusage");

		T_LOG("iteration %3d: %14lld / %14lld cycles executed (%.2f%%)\n", i,
		    ru.ri_cycles, target_cycles,
		    ((double)ru.ri_cycles) * 100.0 / (double)target_cycles);

		T_QUIET; T_ASSERT_NE(ru.ri_cycles, (uint64_t)0,
		    "should be able to measure cycles with proc_pid_rusage");

		bool found = search_for_self_microstackshot(false);
		if (ru.ri_cycles > target_cycles || found) {
			break;
		}
	}

	T_LOG("Complete, executed %lld cycles.  Disable mitigation mode.\n", ru.ri_cycles);

	T_EXPECT_POSIX_SUCCESS(setpriority(PRIO_DARWIN_RUNAWAY_MITIGATION,
	    0, PRIO_DARWIN_RUNAWAY_MITIGATION_OFF),
	    "setpriority(PRIO_DARWIN_RUNAWAY_MITIGATION, 0, PRIO_DARWIN_RUNAWAY_MITIGATION_OFF)");

	search_for_self_microstackshot(true);

	T_EXPECT_EQ(found_self, true,
	    "Should have found self in microstackshot buffer");
	T_EXPECT_EQ(found_flag, true,
	    "Should have found kTaskRunawayMitigation flag in microstackshot buffer");
}
#endif // defined(__arm64__)
