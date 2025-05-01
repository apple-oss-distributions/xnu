/*
 * Copyright (c) 2024 Apple Inc. All rights reserved.
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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <util.h>

T_GLOBAL_META(T_META_TAG_VM_PREFERRED);

T_DECL(
	lseek_not_allowed_on_pipe,
	"Ensure that lseek() is disallowed on pipes"
	) {
	// rdar://3837316: Per the POSIX spec, lseek is disallowed on pipes.
	//
	T_SETUPBEGIN;

	// Given a pipe
	int fildes[2] = {-1, -1};
	T_ASSERT_POSIX_SUCCESS(pipe(&fildes[0]), "setup: created a pipe");

	T_SETUPEND;

	// When I try to seek on it
	// Then it fails
	// And errno is set appropriately
	T_ASSERT_POSIX_FAILURE(lseek(fildes[0], 0, SEEK_CUR), ESPIPE, "lseek fails with appropriate errno");
}

T_DECL(
	lseek_not_allowed_on_fifo,
	"Ensure that lseek() is disallowed on FIFOs"
	) {
	// rdar://3837316: Per the POSIX spec, lseek is disallowed on FIFOs.
	T_SETUPBEGIN;

	// Given a FIFO
	char path_template[] = "/tmp/fifoXXXXXX";
	T_ASSERT_POSIX_SUCCESS(mkstemp(path_template), "setup: created temp file");
	// (Remove the file so we can create a FIFO in its place)
	// (There's a race here between create->delete->create again)
	T_ASSERT_POSIX_ZERO(remove(path_template), "setup: removed temp file");
	T_ASSERT_POSIX_SUCCESS(mkfifo(path_template, (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)), "setup: created FIFO in temp file's place");
	int fifo_fd = open(path_template, O_RDWR, 0);
	T_ASSERT_POSIX_SUCCESS(fifo_fd, "setup: opened FIFO");

	T_SETUPEND;

	// When I try to seek on it
	// Then it fails
	// And errno is set appropriately
	T_ASSERT_POSIX_FAILURE(lseek(fifo_fd, 0, SEEK_CUR), ESPIPE, "lseek fails with appropriate errno");
}

T_DECL(
	lseek_not_allowed_on_tty,
	"Ensure that lseek() is disallowed on TTY device files"
	) {
	// rdar://120750171: Seeking a TTY is undefined and should be denied.
	T_SETUPBEGIN;

	// Given a TTY device
	int primary_fd, replica_fd;
	T_ASSERT_POSIX_SUCCESS(openpty(&primary_fd, &replica_fd, NULL, NULL, NULL), "setup: open PTY");

	T_SETUPEND;

	// When I try to seek on it
	// Then it fails
	// And errno is set appropriately
	T_ASSERT_POSIX_FAILURE(lseek(primary_fd, 0, SEEK_CUR), ESPIPE, "lseek fails with appropriate errno");
}
