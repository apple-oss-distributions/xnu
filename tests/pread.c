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
#include <sys/event.h>
#include <sys/mman.h>
#include <sys/socket.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.syscall.pread"),
	T_META_RUN_CONCURRENTLY(true)
	);

T_DECL(pread_regular_file,
    "test pread() on a regular file.") {
	char scratchfile_path[] = "/tmp/scratch.XXXXXX";
	int fd = mkstemp(scratchfile_path);
	T_ASSERT_POSIX_SUCCESS(fd, "created temporary file");
	T_ASSERT_POSIX_SUCCESS(unlink(scratchfile_path), "unlinked temporary file");

	char test_buffer[] = "a\0b";
	T_ASSERT_POSIX_SUCCESS(write(fd, test_buffer, 3), "wrote expected data");

	char pread_output_buffer[4];
	bzero(pread_output_buffer, 4);

	// Read one byte from zero.
	ssize_t result = pread(fd, pread_output_buffer, 1, 0);
	T_ASSERT_EQ(result, 1l, "pread 1 byte from 0");
	T_ASSERT_EQ(pread_output_buffer[0], 'a', "first byte output");
	T_ASSERT_EQ(pread_output_buffer[1], 0, "second byte output");
	T_ASSERT_EQ(pread_output_buffer[2], 0, "third byte output");
	T_ASSERT_EQ(pread_output_buffer[3], 0, "fourth byte output");

	// Read all bytes from zero.
	bzero(pread_output_buffer, 4);
	result = pread(fd, pread_output_buffer, 3, 0);
	T_ASSERT_EQ(result, 3l, "pread 3 bytes from 0");
	T_ASSERT_EQ(pread_output_buffer[0], 'a', "first byte output");
	T_ASSERT_EQ(pread_output_buffer[1], 0, "second byte output");
	T_ASSERT_EQ(pread_output_buffer[2], 'b', "third byte output");
	T_ASSERT_EQ(pread_output_buffer[3], 0, "fourth byte output");

	// Read more bytes than length from zero.
	bzero(pread_output_buffer, 4);
	result = pread(fd, pread_output_buffer, 4, 0);
	T_ASSERT_EQ(result, 3l, "pread 4 bytes from 0");
	T_ASSERT_EQ(pread_output_buffer[0], 'a', "first byte output");
	T_ASSERT_EQ(pread_output_buffer[1], 0, "second byte output");
	T_ASSERT_EQ(pread_output_buffer[2], 'b', "third byte output");
	T_ASSERT_EQ(pread_output_buffer[3], 0, "fourth byte output");

	// Read one byte from 2.
	bzero(pread_output_buffer, 4);
	result = pread(fd, pread_output_buffer, 1, 2);
	T_ASSERT_EQ(result, 1l, "pread 1 byte from 2");
	T_ASSERT_EQ(pread_output_buffer[0], 'b', "first byte output");
	T_ASSERT_EQ(pread_output_buffer[1], 0, "second byte output");
	T_ASSERT_EQ(pread_output_buffer[2], 0, "third byte output");
	T_ASSERT_EQ(pread_output_buffer[3], 0, "fourth byte output");

	// Read more bytes than length from 2.
	bzero(pread_output_buffer, 4);
	result = pread(fd, pread_output_buffer, 4, 2);
	T_ASSERT_EQ(result, 1l, "pread 4 bytes from 2");
	T_ASSERT_EQ(pread_output_buffer[0], 'b', "first byte output");
	T_ASSERT_EQ(pread_output_buffer[1], 0, "second byte output");
	T_ASSERT_EQ(pread_output_buffer[2], 0, "third byte output");
	T_ASSERT_EQ(pread_output_buffer[3], 0, "fourth byte output");
}

static void
test_pread_should_fail(int fd, int expected_errno)
{
	char output_buffer = 'A';
	ssize_t pread_result = pread(fd, &output_buffer, 1, 0);
	int err = errno;
	T_ASSERT_EQ(pread_result, (ssize_t)-1, "pread offset 0 size 1 returns -1");
	T_ASSERT_EQ(err, expected_errno, "errno is as expected");
	T_ASSERT_EQ(output_buffer, 'A', "input buffer is unchanged");

	pread_result = pread(fd, &output_buffer, 1, 1);
	err = errno;
	T_ASSERT_EQ(pread_result, (ssize_t)-1, "pread offset 1 size 1 returns -1");
	T_ASSERT_EQ(err, expected_errno, "errno is as expected");
	T_ASSERT_EQ(output_buffer, 'A', "input buffer is unchanged");

	pread_result = pread(fd, &output_buffer, 0, 0);
	err = errno;
	T_ASSERT_EQ(pread_result, (ssize_t)-1, "pread offset 0 size 0 returns -1");
	T_ASSERT_EQ(err, expected_errno, "errno is as expected");
	T_ASSERT_EQ(output_buffer, 'A', "input buffer is unchanged");

	pread_result = pread(fd, &output_buffer, 0, 1);
	err = errno;
	T_ASSERT_EQ(pread_result, (ssize_t)-1, "pread offset 1 size 0 returns -1");
	T_ASSERT_EQ(err, expected_errno, "errno is as expected");
	T_ASSERT_EQ(output_buffer, 'A', "input buffer is unchanged");
}

T_DECL(pread_socket,
    "test pread() on a socket.") {
	int sockets[2];
	int result = socketpair(AF_UNIX, SOCK_STREAM, 0, sockets);
	T_ASSERT_POSIX_SUCCESS(result, "Created socket pair");

	test_pread_should_fail(sockets[0], ESPIPE);
	test_pread_should_fail(sockets[1], ESPIPE);

	T_ASSERT_POSIX_SUCCESS(close(sockets[0]), "Closed socket 0");
	T_ASSERT_POSIX_SUCCESS(close(sockets[1]), "Closed socket 1");
}

T_DECL(pread_unix_shared_memory,
    "test pread() on unix shared memory.") {
	const char* memory_path = "test_pread_unix_shared_memory";
	int shm_fd = shm_open(memory_path, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
	T_ASSERT_POSIX_SUCCESS(shm_fd, "Created shared memory");

	test_pread_should_fail(shm_fd, ESPIPE);

	T_ASSERT_POSIX_SUCCESS(close(shm_fd), "Closed shm fd");
	T_ASSERT_POSIX_SUCCESS(shm_unlink(memory_path), "Unlinked");
}

T_DECL(pread_kqueue,
    "test pread() on kqueue.") {
	int queue = kqueue();
	T_ASSERT_POSIX_SUCCESS(queue, "Got kqueue");

	test_pread_should_fail(queue, ESPIPE);

	T_ASSERT_POSIX_SUCCESS(close(queue), "Closed queue");
}

T_DECL(pread_pipe,
    "test pread() on pipe.") {
	int pipe_fds[2];
	T_ASSERT_POSIX_SUCCESS(pipe(pipe_fds), "Created pipe");

	test_pread_should_fail(pipe_fds[0], ESPIPE);
	test_pread_should_fail(pipe_fds[1], EBADF);

	T_ASSERT_POSIX_SUCCESS(close(pipe_fds[1]), "Close write pipe");
	T_ASSERT_POSIX_SUCCESS(close(pipe_fds[0]), "Close read pipe");
}

T_DECL(pread_read_from_null,
    "test pread() from null.") {
	int fd = open("/dev/null", O_RDONLY);
	T_ASSERT_POSIX_SUCCESS(fd, "Opened /dev/null");

	char output_buffer = 'A';
	ssize_t pread_result = pread(fd, &output_buffer, 1, 0);
	T_ASSERT_EQ(pread_result, (ssize_t)0, "pread offset 0 size 1 returns 0");
	T_ASSERT_EQ(output_buffer, 'A', "input buffer is unchanged");

	pread_result = pread(fd, &output_buffer, 1, 1);
	T_ASSERT_EQ(pread_result, (ssize_t)0, "pread offset 1 size 1 returns 0");
	T_ASSERT_EQ(output_buffer, 'A', "input buffer is unchanged");

	pread_result = pread(fd, &output_buffer, 0, 0);
	T_ASSERT_EQ(pread_result, (ssize_t)0, "pread offset 0 size 0 returns 0");
	T_ASSERT_EQ(output_buffer, 'A', "input buffer is unchanged");

	pread_result = pread(fd, &output_buffer, 0, 1);
	T_ASSERT_EQ(pread_result, (ssize_t)0, "pread offset 1 size 0 returns 0");
	T_ASSERT_EQ(output_buffer, 'A', "input buffer is unchanged");

	T_ASSERT_POSIX_SUCCESS(close(fd), "Closed /dev/null");
}
