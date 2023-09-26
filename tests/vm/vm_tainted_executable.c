/*
 * Copyright (c) 2023 Apple Computer, Inc. All rights reserved.
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

#include <darwintest.h>

#include <fcntl.h>
#include <stdlib.h>
#include <spawn.h>
#include <string.h>
#include <unistd.h>
#include <sys/codesign.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"));

T_DECL(vm_tainted_executable, "Test that a tainted executable gets killed")
{
	char tmp_path[] = "/tmp/hell0-XXXXXX";
	int fd1, fd2;
	struct stat fs;
	char *mapaddr1;
	size_t fsize;
	char *big_sp, *big_cp, *big_ep, *little_cp;
	size_t little_len;
	char *child_argv[2];
	pid_t child_pid;
	int child_status;
	int cs_status;

	T_SETUPBEGIN;
	/* copy "./hello" to "/tmp/hell0" */
	fd1 = open("./hello", O_RDONLY);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(fd1, "open(./hello)");
	fd2 = mkstemp(tmp_path);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(fd2, "mkstemp(%s)", tmp_path);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(fstat(fd1, &fs), NULL);
	fsize = (size_t)fs.st_size;
	mapaddr1 = mmap(NULL, fsize, PROT_READ, MAP_FILE | MAP_PRIVATE, fd1, 0);
	T_QUIET; T_ASSERT_NOTNULL(mapaddr1, NULL);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(write(fd2, mapaddr1, fsize), NULL);
	/* change "hello, world!" to "hell0, world!" */
	big_sp = &mapaddr1[0]; /* start pointer in "big" byte string */
	big_ep = &mapaddr1[fsize]; /* end pointer in "big" byte string */
	little_cp = "hello, world!"; /* little byte string */
	little_len = strlen(little_cp); /* length of little byte string */
	big_cp = big_sp; /* start pointer in "big" byte string */
	for (;;) {
		char zero = '0';
		big_cp = memmem(big_cp, (size_t)(big_ep - big_cp),
		    little_cp, little_len);
		if (big_cp == NULL) {
			break;
		}
		T_LOG("found string at offset 0x%llx", (off_t) (big_cp - big_sp));
		T_QUIET; T_ASSERT_POSIX_SUCCESS(pwrite(fd2, &zero, 1,
		    (big_cp - big_sp + 4)), NULL);
		big_cp += little_len;
	}
	/* make the new binary "r-x" */
	T_QUIET; T_ASSERT_POSIX_SUCCESS(fchmod(fd2, S_IRUSR | S_IXUSR), NULL);
	/* cleanup */
	T_QUIET; T_ASSERT_POSIX_SUCCESS(close(fd1), NULL);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(close(fd2), NULL);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(munmap(mapaddr1, fsize), NULL);
	T_SETUPEND;
	/* spawn the newly-tainted binary */
	T_LOG("launching '%s'", tmp_path);
	child_argv[0] = tmp_path;
	child_argv[1] = NULL;
	T_QUIET; T_ASSERT_POSIX_SUCCESS(posix_spawn(&child_pid, tmp_path, NULL, NULL, child_argv, NULL), NULL);
	/* check our code-signing policy, assuming the child has same policy */
	T_QUIET; T_ASSERT_POSIX_SUCCESS(csops(getpid(), CS_OPS_STATUS, &cs_status, sizeof(cs_status)), NULL);
	T_LOG("parent %d cs status 0x%x CS_KILL:%s", getpid(), cs_status,
	    (cs_status & CS_KILL) ? "yes" : "no");
	/* get child's exit status */
	T_QUIET; T_ASSERT_POSIX_SUCCESS(waitpid(child_pid, &child_status, 0), NULL);
	T_LOG("child %d exit status 0x%x", child_pid, child_status);
	/* we no longer need our modified binary */
	T_QUIET; T_ASSERT_POSIX_SUCCESS(unlink(tmp_path), NULL);
	if (cs_status & CS_KILL) {
		/* check that child got SIGKILL */
		T_QUIET; T_ASSERT_TRUE(WIFSIGNALED(child_status), NULL);
		T_QUIET; T_ASSERT_TRUE(WTERMSIG(child_status) == SIGKILL, NULL);
		T_PASS("enforced process launched from modified binary got SIGKILL");
	} else {
		/* check that child exited with 0 */
		T_QUIET; T_ASSERT_TRUE(WIFEXITED(child_status), NULL);
		T_QUIET; T_ASSERT_TRUE(WEXITSTATUS(child_status) == 0, NULL);
		T_PASS("non-enforced process launched from modified binary exited with 0");
	}
}
