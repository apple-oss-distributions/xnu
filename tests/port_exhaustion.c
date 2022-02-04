#include <darwintest.h>
#include <mach/mach.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <darwintest_multiprocess.h>
#include <spawn.h>
#include <spawn_private.h>
#include <libproc_internal.h>
#include <signal.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.ipc"),
	T_META_RUN_CONCURRENTLY(TRUE),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("IPC"));

#define MAX_ARGV 2

extern char **environ;

T_DECL(port_exhaustion_test_max_ports, "Allocate maximum ipc ports possible", T_META_IGNORECRASHES(".*port_exhaustion_client.*"), T_META_CHECK_LEAKS(false))
{
	char *test_prog_name = "./port_exhaustion_client";
	char *child_args[MAX_ARGV];
	int child_pid;
	posix_spawnattr_t       attrs;
	int err;

	/* Initialize posix_spawn attributes */
	posix_spawnattr_init(&attrs);

	child_args[0] = test_prog_name;
	child_args[1] = NULL;

	err = posix_spawn(&child_pid, child_args[0], NULL, &attrs, &child_args[0], environ);
	T_EXPECT_POSIX_SUCCESS(err, "posix_spawn port_exhaustion_client");

	int child_status;
	/* Wait for child and check for exception */
	if (-1 == waitpid(child_pid, &child_status, 0)) {
		T_FAIL("waitpid: child mia");
	}

	T_ASSERT_EQ(WIFEXITED(child_status), 0, "Child did not exit normally");

	if (WIFSIGNALED(child_status)) {
		T_ASSERT_EQ(child_status, 9, "Child exited with status = %x", child_status);
	}
}
