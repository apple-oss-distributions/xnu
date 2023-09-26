#include <darwintest.h>
#include <darwintest_utils.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <spawn_filtering_private.h>
#include <spawn_private.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/spawn_internal.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/syslimits.h>
#include <sysexits.h>
#include <unistd.h>

static char tmp_path_filter_rules[PATH_MAX] = "";
static char tmp_path_env_output[PATH_MAX] = "";

static void
cleanup_tmpfiles(void)
{
	if (tmp_path_filter_rules[0] != '\0') {
		unlink(tmp_path_filter_rules);
	}
	if (tmp_path_env_output[0] != '\0') {
		unlink(tmp_path_env_output);
	}
}

/*
 * Creates a filtering rules file that says "when launching sh, add this env
 * var". The we launch "sh -c env", redirect the output to a file, read the file
 * and check that the added env var is present.
 */
T_DECL(posix_spawn_filtering,
    "Check posix_spawn_filtering",
    T_META_ENVVAR("FEATUREFLAGS_ENABLED=Libsystem/posix_spawn_filtering"))
{
#if POSIX_SPAWN_FILTERING_ENABLED
	const char *tmpdir = dt_tmpdir();
	T_LOG("tmpdir: %s\n", tmpdir);

	strlcat(tmp_path_filter_rules, tmpdir ? tmpdir : "/tmp", sizeof(tmp_path_filter_rules));
	strlcat(tmp_path_filter_rules, "/filter.rules.XXXXX", sizeof(tmp_path_filter_rules));
	int filter_rules_fd = mkstemp(tmp_path_filter_rules);
	T_ASSERT_POSIX_SUCCESS(filter_rules_fd, "create temporary file 1");

	const char *filter_rules_contents =
	    "binary_name:sh\n"
	    "add_env:ADDED_VAR=VIA_RULES\n";
	ssize_t bytes_written = write(filter_rules_fd, filter_rules_contents, strlen(filter_rules_contents));
	T_ASSERT_EQ(bytes_written, (long)strlen(filter_rules_contents), "write should write all contents");
	close(filter_rules_fd);

	strlcat(tmp_path_env_output, tmpdir ? tmpdir : "/tmp", sizeof(tmp_path_env_output));
	strlcat(tmp_path_env_output, "/env.output.XXXXX", sizeof(tmp_path_env_output));
	int env_output_fd = mkstemp(tmp_path_env_output);
	T_ASSERT_POSIX_SUCCESS(env_output_fd, "create temporary file 2");

	T_ATEND(cleanup_tmpfiles);

	char * const    prog = "/bin/sh";
	char * const    argv_child[] = { prog,
		                         "-c",
		                         "/usr/bin/env",
		                         NULL, };

	char rules_path_env[PATH_MAX + 100] = {0};
	sprintf(rules_path_env, "POSIX_SPAWN_FILTERING_RULES_PATH=%s", tmp_path_filter_rules);
	char * const    envp_child[] = {
		"HELLO=WORLD",
		rules_path_env,
		NULL,
	};

	pid_t           child_pid;

	posix_spawn_file_actions_t      file_actions;
	T_ASSERT_POSIX_SUCCESS(posix_spawn_file_actions_init(&file_actions), "posix_spawn_file_actions_init");
	T_ASSERT_POSIX_SUCCESS(posix_spawn_file_actions_adddup2(&file_actions, env_output_fd, STDOUT_FILENO), "posix_spawn_file_actions_addup2");

	int ret;
	ret = posix_spawn(&child_pid, prog, &file_actions, NULL, argv_child, envp_child);
	T_ASSERT_POSIX_SUCCESS(ret, "posix_spawn");
	T_LOG("parent: spawned child with pid %d, waiting for child to exit\n", child_pid);

	ret = posix_spawn_file_actions_destroy(&file_actions);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(ret, "posix_spawn_file_actions_destroy");

	int status = 0;
	int waitpid_result = waitpid(child_pid, &status, 0);
	T_ASSERT_POSIX_SUCCESS(waitpid_result, "waitpid");
	T_ASSERT_EQ(waitpid_result, child_pid, "waitpid should return child we spawned");
	T_ASSERT_EQ(WIFEXITED(status), 1, "child should have exited normally");
	T_ASSERT_EQ(WEXITSTATUS(status), EX_OK, "child should have exited with success");

	T_ASSERT_EQ(lseek(env_output_fd, 0, SEEK_SET), 0ull, "lseek should succeed");
	struct stat s;
	T_ASSERT_POSIX_SUCCESS(fstat(env_output_fd, &s), "fstat should succeed");
	T_ASSERT_GT(s.st_size, 0ll, "s.st_size > 0");
	char env_file_content[s.st_size + 1];
	memset(env_file_content, 0, s.st_size + 1);
	T_ASSERT_EQ((long)read(env_output_fd, env_file_content, (size_t)s.st_size), (long)s.st_size, "read should load the whole file");

	T_ASSERT_NOTNULL(strstr(env_file_content, "HELLO=WORLD\n"), "original env var present");
	T_ASSERT_NOTNULL(strstr(env_file_content, "ADDED_VAR=VIA_RULES\n"), "added env var present");

	T_PASS("posix_spawn_filtering did succeed to set an env var");

#else // POSIX_SPAWN_FILTERING_ENABLED
	T_SKIP("posix_spawn_filtering only supported with POSIX_SPAWN_FILTERING_ENABLED");
#endif // POSIX_SPAWN_FILTERING_ENABLED
}
