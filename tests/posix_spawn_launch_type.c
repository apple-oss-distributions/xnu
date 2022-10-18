#include <darwintest.h>

#include <errno.h>
#include <libproc.h>
#include <signal.h>
#include <spawn.h>
#include <spawn_private.h>
#include <sys/spawn_internal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/kauth.h>
#include <sys/proc_info.h>
#include <sys/sysctl.h>
#include <sysexits.h>
#include <unistd.h>
#include <kern/cs_blobs.h>
#include <sys/codesign.h>

T_GLOBAL_META(T_META_RUN_CONCURRENTLY(true),
    T_META_RADAR_COMPONENT_NAME("xnu"),
    T_META_RADAR_COMPONENT_VERSION("codesigning"));

T_DECL(cs_launch_type_t, "Check posix_spawnattr for launch type",
    T_META_ASROOT(true))
{
	posix_spawnattr_t attr;
	int ret;

	ret = posix_spawnattr_init(&attr);
	T_QUIET;
	T_ASSERT_POSIX_ZERO(ret, "posix_spawnattr_init");

	ret = posix_spawnattr_set_launch_type_np(&attr, CS_LAUNCH_TYPE_SYSTEM_SERVICE);
	T_QUIET;
	T_ASSERT_POSIX_ZERO(ret, "posix_spawnattr_set_launch_type_np");


	char * const    prog = "/bin/ls";
	char * const    argv_child[] = { prog,
		                         NULL, };
	pid_t           child_pid;
	extern char   **environ;

	ret = posix_spawn(&child_pid, prog, NULL, &attr, argv_child, environ);
	T_ASSERT_POSIX_ZERO(ret, "posix_spawn");

	T_LOG("parent: spawned child with pid %d\n", child_pid);

	ret = posix_spawnattr_destroy(&attr);
	T_QUIET;
	T_ASSERT_POSIX_ZERO(ret, "posix_spawnattr_destroy");

	T_LOG("parent: waiting for child process");

	int status = 0;
	int waitpid_result = waitpid(child_pid, &status, 0);
	T_ASSERT_EQ(waitpid_result, child_pid, "waitpid should return child we spawned");
	T_ASSERT_EQ(WIFEXITED(status), 1, "child should have exited normally");
	T_ASSERT_EQ(WEXITSTATUS(status), EX_OK, "child should have exited with success");
}
