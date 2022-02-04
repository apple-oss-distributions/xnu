/*
 * Copyright (c) 2020 Apple Inc. All rights reserved.
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
#include <unistd.h>
#include <stdlib.h>
#include <sys/event.h>
#include <sys/mman.h>
#include <sys/socket.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.syscall.pwrite"),
	T_META_RUN_CONCURRENTLY(true)
	);

static void
test_file_equals(int fd, const char* expected_buffer, size_t size)
{
	T_ASSERT_POSIX_SUCCESS(lseek(fd, 0, SEEK_SET), "Reset file offset");
	char* read_buffer = malloc(size);
	T_ASSERT_TRUE(read_buffer != 0, "Allocated read_buffer");
	T_ASSERT_EQ(read(fd, read_buffer, size), (ssize_t)size, "Read expected buffer");
	T_ASSERT_EQ(strncmp(read_buffer, expected_buffer, size), 0, "Buffer as expected");
	free(read_buffer);
}

T_DECL(pwrite_regular_file,
    "test pwrite() on a regular file.") {
	char scratchfile_path[] = "/tmp/scratch.XXXXXX";
	int fd = mkstemp(scratchfile_path);
	T_ASSERT_POSIX_SUCCESS(fd, "created temporary file");
	T_ASSERT_POSIX_SUCCESS(unlink(scratchfile_path), "unlinked temporary file");

	T_ASSERT_POSIX_SUCCESS(pwrite(fd, "a", 1, 1), "pwrite 'a' at offset 1");
	test_file_equals(fd, "\0a", 2);

	T_ASSERT_POSIX_SUCCESS(pwrite(fd, "bcd", 3, 0), "pwrite 'bcd' at offset 0");
	test_file_equals(fd, "bcd", 3);
}

static void
test_pwrite_should_fail(int fd, int expected_errno)
{
	char input_buffer = 'A';
	ssize_t pwrite_result = pwrite(fd, &input_buffer, 1, 0);
	int err = errno;
	T_ASSERT_EQ(pwrite_result, (ssize_t)-1, "pwrite offset 0 size 1 returns -1");
	T_ASSERT_EQ(err, expected_errno, "errno is as expected");
	T_ASSERT_EQ(input_buffer, 'A', "input buffer is unchanged");

	pwrite_result = pwrite(fd, &input_buffer, 1, 1);
	err = errno;
	T_ASSERT_EQ(pwrite_result, (ssize_t)-1, "pwrite offset 1 size 1 returns -1");
	T_ASSERT_EQ(err, expected_errno, "errno is as expected");
	T_ASSERT_EQ(input_buffer, 'A', "input buffer is unchanged");

	pwrite_result = pwrite(fd, &input_buffer, 0, 0);
	err = errno;
	T_ASSERT_EQ(pwrite_result, (ssize_t)-1, "pwrite offset 0 size 0 returns -1");
	T_ASSERT_EQ(err, expected_errno, "errno is as expected");
	T_ASSERT_EQ(input_buffer, 'A', "input buffer is unchanged");

	pwrite_result = pwrite(fd, &input_buffer, 0, 1);
	err = errno;
	T_ASSERT_EQ(pwrite_result, (ssize_t)-1, "pwrite offset 1 size 0 returns -1");
	T_ASSERT_EQ(err, expected_errno, "errno is as expected");
	T_ASSERT_EQ(input_buffer, 'A', "input buffer is unchanged");
}

T_DECL(pwrite_socket,
    "test pwrite() on a socket.") {
	int sockets[2];
	int result = socketpair(AF_UNIX, SOCK_STREAM, 0, sockets);
	T_ASSERT_POSIX_SUCCESS(result, "Created socket pair");

	test_pwrite_should_fail(sockets[0], ESPIPE);
	test_pwrite_should_fail(sockets[1], ESPIPE);

	T_ASSERT_POSIX_SUCCESS(close(sockets[0]), "Closed socket 0");
	T_ASSERT_POSIX_SUCCESS(close(sockets[1]), "Closed socket 1");
}

T_DECL(pwrite_unix_shared_memory,
    "test pwrite() on unix shared memory.") {
	const char* memory_path = "test_pwrite_unix_shared_memory";
	int shm_fd = shm_open(memory_path, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
	T_ASSERT_POSIX_SUCCESS(shm_fd, "Created shared memory");

	test_pwrite_should_fail(shm_fd, ESPIPE);

	T_ASSERT_POSIX_SUCCESS(close(shm_fd), "Closed shm fd");
	T_ASSERT_POSIX_SUCCESS(shm_unlink(memory_path), "Unlinked");
}

T_DECL(pwrite_kqueue,
    "test pwrite() on kqueue.") {
	int queue = kqueue();
	T_ASSERT_POSIX_SUCCESS(queue, "Got kqueue");

	test_pwrite_should_fail(queue, ESPIPE);

	T_ASSERT_POSIX_SUCCESS(close(queue), "Close queue");
}

T_DECL(pwrite_pipe,
    "test pwrite() on pipe.") {
	int pipe_fds[2];
	T_ASSERT_POSIX_SUCCESS(pipe(pipe_fds), "Created pipe");

	test_pwrite_should_fail(pipe_fds[0], ESPIPE);
	test_pwrite_should_fail(pipe_fds[1], ESPIPE);

	T_ASSERT_POSIX_SUCCESS(close(pipe_fds[1]), "Close write pipe");
	T_ASSERT_POSIX_SUCCESS(close(pipe_fds[0]), "Close read pipe");
}

T_DECL(pwrite_write_to_dev_null,
    "test pwrite() from null.") {
	int fd = open("/dev/null", O_RDONLY);
	T_ASSERT_POSIX_SUCCESS(fd, "Opened /dev/null");

	char buffer = 'A';
	errno = 0;
	ssize_t pwrite_result = pwrite(fd, &buffer, 1, 0);
	int err = errno;
	T_ASSERT_EQ(pwrite_result, (ssize_t)-1, "pwrite offset 0 size 1 returns -1");
	T_ASSERT_EQ(err, EBADF, "pwrite on /dev/null results in EBADF");

	errno = 0;
	pwrite_result = pwrite(fd, &buffer, 1, 1);
	err = errno;
	T_ASSERT_EQ(pwrite_result, (ssize_t)-1, "pwrite offset 1 size 1 returns -1");
	T_ASSERT_EQ(buffer, 'A', "input buffer is unchanged");
	T_ASSERT_EQ(err, EBADF, "pwrite on /dev/null results in EBADF");

	errno = 0;
	pwrite_result = pwrite(fd, &buffer, 0, 0);
	err = errno;
	T_ASSERT_EQ(pwrite_result, (ssize_t)-1, "pwrite offset 0 size 0 returns -1");
	T_ASSERT_EQ(err, EBADF, "pwrite on /dev/null results in EBADF");
	T_ASSERT_EQ(buffer, 'A', "input buffer is unchanged");

	errno = 0;
	pwrite_result = pwrite(fd, &buffer, 0, 1);
	err = errno;
	T_ASSERT_EQ(pwrite_result, (ssize_t)-1, "pwrite offset 1 size 0 returns -1");
	T_ASSERT_EQ(err, EBADF, "pwrite on /dev/null results in EBADF");
	T_ASSERT_EQ(buffer, 'A', "input buffer is unchanged");

	T_ASSERT_POSIX_SUCCESS(close(fd), "Closed /dev/null");
}
