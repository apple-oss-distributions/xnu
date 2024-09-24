/*
 * Jetsam zprint snapshot test
 *
 * This test validates the ability of the kernel to generate a Jetsam zprint snapshot
 *
 * Main flow:
 * 1. main process sets the kernel variable jzs_trigger_band to 0 to activate a Jetsam zprint snapshot asap
 * 2. main process creates a child process to be Jetsem'd
 * 3. main process Jetsam the child process via memorystatus_control() for the kernel to grab a Jetsam zprint snapshot
 * 4. main process periodically polls on the Jetsam zprint snapshot structures via memorystatus_control()
 *
 * Result:
 *    Test is marked as PASS if the main process is able to obtain Jetsam zprint snapshot structures successfully;
 *            marked as FAIL if the test times out before it could obtain Jetsam zprint snapshot structures.
 */


#include <stdio.h>
#include <stdlib.h>
#include <mach/mach.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/sysctl.h>
#include <sys/kern_memorystatus.h>

#include <darwintest.h>
#include <darwintest_utils.h>

T_GLOBAL_META(
	T_META_RUN_CONCURRENTLY(true),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"));

/* MEMORYSTATUS_CMD_GET_JETSAM_ZPRINT_{NAMES/INFO/MEMINFO} */
#define JZS_COMMAND_COUNT 3

/* Run the test for 1 hour at most */
static const uint64_t test_timeout_in_nanoseconds = 3600 * NSEC_PER_SEC;

/* Jetsam zprint snapshot data */
static mach_zone_name_t *jzs_name_buffer = NULL;
static mach_zone_info_t *jzs_info_buffer = NULL;
static mach_memory_info_t *jzs_meminfo_buffer = NULL;

static boolean_t
jzs_data_available(void)
{
	return (jzs_name_buffer && jzs_info_buffer && jzs_meminfo_buffer) ? TRUE : FALSE;
}

static const char *
memorystatus_jzs_command_string(uint32_t command)
{
	switch (command) {
	case MEMORYSTATUS_CMD_GET_JETSAM_ZPRINT_NAMES:
		return "MEMORYSTATUS_CMD_GET_JETSAM_ZPRINT_NAMES";
	case MEMORYSTATUS_CMD_GET_JETSAM_ZPRINT_INFO:
		return "MEMORYSTATUS_CMD_GET_JETSAM_ZPRINT_INFO";
	case MEMORYSTATUS_CMD_GET_JETSAM_ZPRINT_MEMINFO:
		return "MEMORYSTATUS_CMD_GET_JETSAM_ZPRINT_MEMINFO";
	default:
		return "?";
	}
}

static int
collect_jzs_data(mach_zone_name_t **namep, mach_zone_info_t **infop, mach_memory_info_t **memInfop)
{
	const uint32_t memorystatus_jzs_commands[JZS_COMMAND_COUNT] = {
		MEMORYSTATUS_CMD_GET_JETSAM_ZPRINT_NAMES,
		MEMORYSTATUS_CMD_GET_JETSAM_ZPRINT_INFO,
		MEMORYSTATUS_CMD_GET_JETSAM_ZPRINT_MEMINFO
	};

	size_t jzs_name_size = 0, jzs_info_size = 0, jzs_meminfo_size = 0;

	for (unsigned int i = 0; i < JZS_COMMAND_COUNT; i++) {
		const uint32_t jzs_command = memorystatus_jzs_commands[i];
		int err;
		void *jzs_buffer;
		size_t jzs_buffer_size;

		/* Fetch jetsam zprint snapshot data from the kernel */
		err = memorystatus_control(jzs_command, 0, 0, NULL, 0);
		if (err == -1) {
			if (errno == EAGAIN) {
				T_LOG("No Jetsam zprint snapshot found, retry later...");
			} else {
				T_LOG("memorystatus_control(%s ...) size_only failed", memorystatus_jzs_command_string(jzs_command));
			}
			return -1;
		}
		jzs_buffer_size = (size_t) err; // buffer size returned by memorystatus_control on a success call
		jzs_buffer = malloc(jzs_buffer_size);
		if (jzs_buffer == NULL) {
			T_LOG("malloc(%zu) failed for %s", jzs_buffer_size, memorystatus_jzs_command_string(jzs_command));
			return -1;
		}
		err = memorystatus_control(jzs_command, 0, 0, jzs_buffer, jzs_buffer_size);
		if (err == -1) {
			if (errno == EAGAIN) {
				T_LOG("No Jetsam zprint snapshot found, retry later...");
			} else {
				T_LOG("memorystatus_control(%s ...) failed to fetch jetsam zprint snapshot data", memorystatus_jzs_command_string(jzs_command));
			}
			return -1;
		}

		/* Point the caller's buffer to jzs data */
		switch (jzs_command) {
		case MEMORYSTATUS_CMD_GET_JETSAM_ZPRINT_NAMES:
			*namep = jzs_buffer;
			jzs_name_size = jzs_buffer_size;
			break;
		case MEMORYSTATUS_CMD_GET_JETSAM_ZPRINT_INFO:
			*infop = jzs_buffer;
			jzs_info_size = jzs_buffer_size;
			break;
		case MEMORYSTATUS_CMD_GET_JETSAM_ZPRINT_MEMINFO:
			*memInfop = jzs_buffer;
			jzs_meminfo_size = jzs_buffer_size;
			break;
		default:
			break;
		}
	}
	T_LOG("Collected jetsam zprint snapshot successfully");

	// Log some contents of zprint snapshot.
	T_LOG("name_size %u, # of names %u", (unsigned)jzs_name_size, (unsigned)(jzs_name_size / sizeof(mach_zone_name_t)));
	T_LOG("info_size %u, # of zone infos %u", (unsigned)jzs_info_size, (unsigned)(jzs_info_size / sizeof(mach_zone_info_t)));
	T_LOG("meminfo_size %u, # of memory infos %u", (unsigned)jzs_meminfo_size, (unsigned)(jzs_meminfo_size / sizeof(mach_memory_info_t)));

	T_LOG("First zone name is '%s'", (*namep)[0].mzn_name);
	T_LOG("First zone count is %u", (unsigned)((*infop)[0].mzi_count));
	T_LOG("First tag size is %u name is '%s'", (unsigned)((*memInfop)[0].size), (*memInfop)[0].name);

	return 0;
}

static mach_zone_name_t *live_name = NULL;
static mach_zone_info_t *live_info = NULL;
static mach_memory_info_t *live_wiredInfo = NULL;

static void
compare_live_memory_info(void)
{
	unsigned int nameCnt = 0;
	unsigned int infoCnt = 0;
	unsigned int wiredInfoCnt = 0;
	kern_return_t kr;

	kr = mach_memory_info(mach_host_self(),
	    &live_name, &nameCnt, &live_info, &infoCnt,
	    &live_wiredInfo, &wiredInfoCnt);
	T_ASSERT_POSIX_SUCCESS(kr, "live mach_memory_info");

	// Log the live results of mach_memory_info to compare them.
	// Note, the contents won't match because live info is not necessarily redacted, while zprint snapshot is.
	T_LOG("# of names %u", nameCnt);
	T_LOG("# of zone infos %u", infoCnt);
	T_LOG("# of memory infos %u", wiredInfoCnt);

	T_LOG("First zone name is '%s'", live_name[0].mzn_name);
	T_LOG("First zone count is %u", (unsigned)(live_info[0].mzi_count));
	T_LOG("First tag size is %u name is '%s'", (unsigned)(live_wiredInfo[0].size), live_wiredInfo[0].name);
}

static void
run_jzs_test(void)
{
	pid_t child_pid;
	unsigned int retries = 0;
	int status;
	const unsigned int jzs_check_interval_sec = 2;
	const uint64_t start_time = mach_absolute_time();
	int err;

	do {
		T_LOG("Jetsam zprint snapshot test run %d starts", retries);

		child_pid = fork();

		if (child_pid == 0) {
			/* Child process waiting to be Jetsam'd */
			T_LOG("Child process pid %d waiting to be Jetsam'd (sleep for %llu seconds)", getpid(), test_timeout_in_nanoseconds / NSEC_PER_SEC);
			sleep(test_timeout_in_nanoseconds / NSEC_PER_SEC);
			exit(0);
		} else if (child_pid == -1) {
			perror("fork");
			T_FAIL("fork failed");
		} else {
			T_LOG("Created child process pid %d to be Jetsam'd\n", child_pid);
		}

		/* Jetsam the child process */
		err = memorystatus_control(MEMORYSTATUS_CMD_TEST_JETSAM, child_pid, 0, NULL, 0);
		T_EXPECT_NE_INT(err, -1, " memorystatus_control(MEMORYSTATUS_CMD_TEST_JETSAM, %d, ...) returned %d", child_pid, err);

		while (0 == waitpid(child_pid, &status, WNOHANG)) {
			if (jzs_data_available() || collect_jzs_data(&jzs_name_buffer, &jzs_info_buffer, &jzs_meminfo_buffer) == 0) {
				T_LOG("Stopping child pid %d", child_pid);

				/* Collected jetsam zprint snapshot, kill child process */
				kill(child_pid, SIGKILL);
				break;
			}
			T_LOG("No jzs data yet...");
			sleep(jzs_check_interval_sec);
		}

		/* Child finished execution, report reason. */
		if (WIFEXITED(status)) {
			T_LOG("child %d exited, status %d", child_pid, WEXITSTATUS(status));
		} else if (WIFSIGNALED(status)) {
			T_LOG("child %d killed, status %d", child_pid, WTERMSIG(status));
		} else if (WIFSTOPPED(status)) {
			T_LOG("child %d stopped, status %d", child_pid, WSTOPSIG(status));
		} else {
			T_LOG("child %d, unexpected status 0x%x", child_pid, status);
		}

		/* Collect jzs data if we haven't */
		if (!jzs_data_available()) {
			collect_jzs_data(&jzs_name_buffer, &jzs_info_buffer, &jzs_meminfo_buffer);
		}

		/* Test should time out? */
		if ((mach_absolute_time() - start_time) > test_timeout_in_nanoseconds) {
			T_FAIL("run_jzs_loop timed out");
			break;
		}

		sleep(jzs_check_interval_sec);

		retries++;
	} while (!jzs_data_available());

	if (jzs_data_available()) {
		T_PASS("Copied jetsam zprint snapshot after %u run%s", retries, (retries == 1) ? "" : "s");
	} else {
		T_FAIL("Failed to copy jetsam zprint snapshot after %u run%s", retries, (retries == 1) ? "" : "s");
	}
}

T_DECL(memorystatus_jetsam_zprint_snapshot,
    "Test for zprint snapshot")
{
	int err;
	unsigned int jzs_trigger_band_target;

	T_SETUPBEGIN;

	/* Skip test if not running as root (required by memorystatus_control syscall) */
	if (geteuid() != 0) {
		T_SKIP("Jetsam zprint snapshot test requires root privilege to run.");
	}

	/* To trigger a zprint snapshot as early as possible */
	jzs_trigger_band_target = 0;
	err = sysctlbyname("kern.jzs_trigger_band", NULL, NULL, &jzs_trigger_band_target, sizeof(jzs_trigger_band_target));
	if (err != 0 && errno == ENOENT) {
		/* No such file or directory, the running kernel doesn't know about jetsam zprint snapshot, skip the test*/
		T_SKIP("The running kernel doesn't know about jetsam zprint snapshot");
	}
	T_ASSERT_POSIX_SUCCESS(err, "sysctlbyname(kern.jzs_trigger_band) set jzs_trigger_band to %d", jzs_trigger_band_target);

	T_LOG("Test is set to time out after %llu seconds\n", test_timeout_in_nanoseconds / NSEC_PER_SEC);
	T_SETUPEND;

	/* Munch memory and fetch jetsam zprint snapshot */
	run_jzs_test();

	T_EXPECT_EQ_INT(1, jzs_data_available(), "Test finished: jzs_data_available()");

	compare_live_memory_info();
}
