/* xcrun -sdk iphoneos.internal clang -ldarwintest -o freeable_vnodes freeable_vnodes.c -g -Weverything */

#include <darwintest.h>
#include <darwintest_utils.h>

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <fcntl.h>
#include <string.h>
#include <sys/sysctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <TargetConditionals.h>

static pid_t vnoder_pid = -1;
static uint32_t maxvnodes = 0;
T_GLOBAL_META(T_META_NAMESPACE("xnu.vfs"));

#if TARGET_OS_IOS

static char *dlpaths[] = {
	"/System/Library/Assistant/FlowDelegatePlugins/HomeAutomationFlowDelegatePlugin.bundle/HomeAutomationFlowDelegatePlugin",
	"/System/Library/NanoPreferenceBundles/Applications/NanoPassbookBridgeSettings.bundle/NanoPassbookBridgeSettings",
	"/System/Library/Assistant/FlowDelegatePlugins/MessagesFlowDelegatePlugin.bundle/MessagesFlowDelegatePlugin",
	"/System/Library/NanoPreferenceBundles/Discover/HealthAndFitnessPlugin.bundle/HealthAndFitnessPlugin",
	"/System/Library/NanoPreferenceBundles/SetupBundles/DepthCompanionSetup.bundle/DepthCompanionSetup",
	"/System/Library/PreferenceBundles/DigitalSeparationSettings.bundle/DigitalSeparationSettings",
	"/System/Library/Assistant/FlowDelegatePlugins/NotebookFlowPlugin.bundle/NotebookFlowPlugin",
	"/System/Library/NanoPreferenceBundles/Discover/UserGuidePlugin.bundle/UserGuidePlugin",
	"/System/Library/PreferenceBundles/NotificationsSettings.bundle/NotificationsSettings",
	"/System/Library/PreferenceBundles/AssistantSettings.bundle/AssistantSettings",
	"/System/Library/PreferenceBundles/SettingsCellular.bundle/SettingsCellular",
	"/System/Library/PreferenceBundles/FocusSettings.bundle/FocusSettings",
	"/private/preboot/Cryptexes/App/System/Library/PreferenceBundles/MobileSafariSettings.bundle/MobileSafariSettings",
	NULL
};

#elif TARGET_OS_WATCH

static char *dlpaths[] = {
	"/System/Library/Assistant/FlowDelegatePlugins/HomeAutomationFlowDelegatePlugin.bundle/HomeAutomationFlowDelegatePlugin",
	"/System/Library/Assistant/FlowDelegatePlugins/MessagesFlowDelegatePlugin.bundle/MessagesFlowDelegatePlugin",
	"/System/Library/PreferenceBundles/NanoAccessibilitySettings.bundle/NanoAccessibilitySettings",
	"/System/Library/Assistant/FlowDelegatePlugins/NotebookFlowPlugin.bundle/NotebookFlowPlugin",
	NULL
};

#elif TARGET_OS_OSX

static char *dlpaths[] = {
	"/System/Library/Assistant/FlowDelegatePlugins/HomeAutomationFlowDelegatePlugin.bundle/Contents/MacOS/HomeAutomationFlowDelegatePlugin",
	"/System/Library/Assistant/FlowDelegatePlugins/MessagesFlowDelegatePlugin.bundle/Contents/MacOS/MessagesFlowDelegatePlugin",
	"/System/Library/Assistant/FlowDelegatePlugins/NotebookFlowPlugin.bundle/Contents/MacOS/NotebookFlowPlugin",
	NULL
};

#else

static char *dlpaths[] = {
	NULL
};

#endif

static uint32_t
get_sysctl_int(char *sysctl_name)
{
	uint32_t max_vnodes = 0;
	size_t length = sizeof(max_vnodes);
	int return_code = 0;

	return_code = sysctlbyname(sysctl_name, &max_vnodes, &length, NULL, 0);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(return_code, "sysctl call should return 0");
	return max_vnodes;
}

#define MINVNODES_FOR_TEST 200
#define MAXVNODES_FOR_TEST 18000

static void
run_vnoder(void)
{
	void *buffer;
	uint32_t i = 0;
	uint32_t current_num = 0;
	uint32_t num_files =  maxvnodes - MINVNODES_FOR_TEST;
	int fd = -1;
	int dir_fd = -1;
	char dirpath[PATH_MAX];
	char filepath[NAME_MAX];

	T_WITH_ERRNO;

	/* Create a temporary working directory */
	sprintf(dirpath, "%s/tmp-mmap-bomb-dir.%d", dt_tmpdir(), getpid());
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(mkdir(dirpath, S_IRWXU | S_IRWXG ), NULL);

	T_LOG("Created test dir %s\n", dirpath);

	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(dir_fd = open(dirpath, O_RDONLY), NULL);

	/* use mmap to exhaust vnode pool */
	uint32_t log_interval = (num_files / 4);
	uint32_t next_test_log_number = log_interval;
	T_LOG("trying to map %u files, progress every %u files\n", num_files, log_interval);
	/*
	 * This loop can take an ideterminate amount of time on different devices since the
	 * it is based on file creation (which is rate limited by the SEP) and the number we
	 * will attempt to create. At some point it should be replaced by walking a large hierarchy
	 * (like /System) and mapping those files instead of creating files.
	 */
	for (i = 0; i < num_files; ++i) {
		if (i == next_test_log_number) {
			T_LOG("created and mapped %u files so far\n", next_test_log_number);
			next_test_log_number += log_interval;
			current_num = get_sysctl_int("vfs.vnstats.num_vnodes");
			if (current_num >= (maxvnodes + 5000)) {
				T_LOG("numvnodes is >= maxvnodes + 5000 (%u), done with creation and mmap loop\n",
				    current_num);
				break;
			}
		}

		sprintf(filepath, "file-%d", i);

		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(fd = openat(dir_fd, filepath, O_CREAT | O_RDWR, 0666), NULL);

		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(ftruncate(fd, (off_t)PAGE_SIZE), NULL);

		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(unlinkat(dir_fd, filepath, 0), NULL);

		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(buffer = mmap(NULL, PAGE_SIZE, PROT_READ, MAP_FILE | MAP_NOCACHE | MAP_PRIVATE, fd, 0), NULL);

		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(close(fd), NULL);
	}
	T_LOG("created and mapped %u files\n", i);

	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(close(dir_fd), NULL);

	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(rmdir(dirpath), NULL);
}

static void
cleanup(void)
{
	if (vnoder_pid > 0) {
		T_LOG("Killing vnoder pid in cleanup: %d", vnoder_pid);
		kill(vnoder_pid, SIGKILL);
	}
}


T_DECL(vnode_max_increase,
    "Consume vnodes to cause the max vnodes available to increase",
    T_META_REQUIRES_SYSCTL_EQ("vfs.vnstats.vn_dealloc_level", 1),
    T_META_RADAR_COMPONENT_NAME("xnu"),
    T_META_RADAR_COMPONENT_VERSION("VFS"))
{
	int sock_fd[2];
	char buf[10];
	uint32_t initial_num = 0, current_num = 0;
	uint32_t deallocateable_vnodes = 0;
	uint32_t deallocateable_busy_vnodes = 0;
	uint32_t vnode_delta = 100;
	uint32_t timeout = 10;
	uint32_t i = 0;

	T_ATEND(cleanup);
	T_WITH_ERRNO;

	T_SETUPBEGIN;
	/*
	 * We use this to handshake certain actions between this process and its
	 * child.
	 */
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(socketpair(AF_UNIX, SOCK_STREAM, 0, sock_fd),
	    NULL);

	maxvnodes = get_sysctl_int("kern.maxvnodes");
	T_LOG("max vnodes: %d", maxvnodes);
	if (maxvnodes > MAXVNODES_FOR_TEST) {
		T_SKIP("maxvnodes can't be more than %d for test", MAXVNODES_FOR_TEST);
	} else if (maxvnodes <= MINVNODES_FOR_TEST) {
		T_SKIP("maxvnodes can't be less than %d for test", MINVNODES_FOR_TEST);
	}

	initial_num = get_sysctl_int("vfs.vnstats.num_vnodes");
	T_LOG("Initial num vnodes: %d", initial_num);

	T_SETUPEND;

	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(vnoder_pid = fork(), NULL);

	if (vnoder_pid == 0) { /* child */
		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(close(sock_fd[0]), NULL);

		run_vnoder();

		/* now let parent know we're done with creating all the vnodes */
		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(write(sock_fd[1], "done", sizeof("done")), NULL);

		/* wait for parent to set us to send us a signal */
		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(read(sock_fd[1], buf, sizeof(buf)), NULL);

		pause();

		exit(0);
	}

	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(close(sock_fd[1]), NULL);

	/* wait for child to run and run up the vnodes */
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(read(sock_fd[0], buf, sizeof(buf)), NULL);

	int num_getpaths = 0;
	for (i = 0; i < 5 && dlpaths[0] != NULL; i++) {
		for (int j = 0; dlpaths[j] != NULL; j++) {
			int dlpath_fd;
			char path[256] = {0};
			struct stat sb;

			if (stat(dlpaths[j], &sb) != -1) {
				T_QUIET;
				T_ASSERT_POSIX_SUCCESS(dlpath_fd = open(dlpaths[j], O_RDONLY), NULL);
				T_QUIET;
				T_ASSERT_POSIX_SUCCESS(fcntl(dlpath_fd, F_GETPATH, &path), "path is %s, iteration number is %d and path number is %d", dlpaths[j], i + 1, j + 1);
				T_QUIET;
				T_ASSERT_POSIX_SUCCESS(close(dlpath_fd), NULL);
				num_getpaths++;
			}
		}
	}
	T_LOG("Num getpaths done = %d", num_getpaths);

	current_num = get_sysctl_int("vfs.vnstats.num_vnodes");
	T_LOG("num vnodes after vnoder: %d", current_num);

	T_QUIET;
	T_ASSERT_GT(current_num, maxvnodes,
	    "vnode maximum should increase under vnode presssure");

	T_LOG("Killing vnoder (pid %d) to free up held vnodes", vnoder_pid);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(write(sock_fd[0], "done", sizeof("done")), NULL);
	kill(vnoder_pid, SIGKILL);
	vnoder_pid = -1;

	T_LOG("Waiting up to %ds for vnodes to be deallocated", timeout);
	for (i = 0; i < timeout; i++) {
		sleep(1);
		deallocateable_vnodes = get_sysctl_int(
			"vfs.vnstats.num_deallocable_vnodes");
		deallocateable_busy_vnodes = get_sysctl_int(
			"vfs.vnstats.num_deallocable_busy_vnodes");

		T_LOG("deallocateable_vnodes after %d second%s : %d",
		    i + 1, (i == 0) ? "" : "s", deallocateable_vnodes);
		T_LOG("deallocateable_busy_vnodes after %d second%s : %d",
		    i + 1, (i == 0) ? "" : "s", deallocateable_busy_vnodes);

		if (deallocateable_vnodes < vnode_delta) {
			break;
		}
		/* This can happen because we don't fetch atomically */
		if (deallocateable_busy_vnodes > deallocateable_vnodes) {
			deallocateable_busy_vnodes = deallocateable_vnodes;
		}

		if ((i == (timeout - 1)) &&
		    ((deallocateable_vnodes - deallocateable_busy_vnodes) < vnode_delta)) {
			break;
		}
	}

	T_QUIET;
	T_ASSERT_NE(i, timeout, "Deallocateable vnodes should drop in under %ds",
	    timeout);

	current_num = get_sysctl_int("vfs.vnstats.num_vnodes");
	T_LOG("num vnodes after killing vnoder: %d", current_num);

	T_QUIET;
	T_ASSERT_LE(current_num, maxvnodes + deallocateable_busy_vnodes + vnode_delta,
	    "vnode maximum should be within %d of the initial maximum",
	    vnode_delta);
}
