/*
 * Copyright (c) 2024 Apple Computer, Inc. All rights reserved.
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

/* compile: xcrun -sdk macosx.internal clang -arch arm64e -arch x86_64 -ldarwintest -o tty_revoke tty_revoke.c */

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <sys/mman.h>
#include <errno.h>
#include <assert.h>
#include <stdlib.h>

#include <darwintest.h>
#include <darwintest/utils.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vfs"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("vfs"),
	T_META_ASROOT(true),  /* Need root privileges for revoke() */
	T_META_CHECK_LEAKS(false));

T_DECL(tty_revoke,
    "Test that reading revoked terminal devices returns 0 (EOF), not EIO")
{
	int controller_fd, terminal_fd;
	struct stat sb;
	char c = 0x41;  /* Initial value to verify it gets changed */
	ssize_t r;
	char *terminal_name;

	T_LOG("Testing revoke behavior on terminal devices");

	/* Step 1: Create a pseudoterminal pair using posix_openpt */
	T_ASSERT_POSIX_SUCCESS((controller_fd = posix_openpt(O_RDWR)), "Creating pseudoterminal controller");

	/* Step 2: Grant access and unlock the terminal */
	T_ASSERT_POSIX_SUCCESS(grantpt(controller_fd), "Granting access to pseudoterminal");
	T_ASSERT_POSIX_SUCCESS(unlockpt(controller_fd), "Unlocking pseudoterminal");

	/* Step 3: Get the terminal device name */
	T_ASSERT_NOTNULL((terminal_name = ptsname(controller_fd)), "Getting pseudoterminal device name");
	T_LOG("Created pseudoterminal: %s", terminal_name);

	/* Step 4: Open the terminal side */
	T_ASSERT_POSIX_SUCCESS((terminal_fd = open(terminal_name, O_RDONLY)), "Opening pseudoterminal device");

	/* Step 5: Verify it's a character device */
	T_ASSERT_POSIX_SUCCESS(fstat(terminal_fd, &sb), "Getting stat info for pseudoterminal device");
	T_ASSERT_EQ((sb.st_mode & S_IFMT), S_IFCHR, "Verifying pseudoterminal device is a character device");

	/* Step 6: Revoke the terminal device */
	T_ASSERT_POSIX_SUCCESS(revoke(terminal_name), "Revoking pseudoterminal device");

	/* Step 7: Attempt to read from the revoked device */
	/* According to the fix, terminal devices should return 0 (EOF) after revoke */
	r = read(terminal_fd, &c, 1);
	T_ASSERT_POSIX_SUCCESS((int)r, "Reading from revoked terminal device should succeed");
	T_ASSERT_EQ((long)r, 0L, "Reading from revoked terminal device should return 0 (EOF)");

	/* Step 8: Verify the character wasn't modified (since we got EOF) */
	T_ASSERT_EQ(c, 0x41, "Buffer should be unchanged when read returns 0");

	/* Step 9: Clean up */
	T_ASSERT_POSIX_SUCCESS(close(terminal_fd), "Closing revoked pseudoterminal device");
	T_ASSERT_POSIX_SUCCESS(close(controller_fd), "Closing pseudoterminal controller");

	T_LOG("Test completed successfully - revoked terminal device returned EOF as expected");
}

T_DECL(tty_revoke_non_terminal,
    "Test that reading revoked non-terminal character devices returns EIO")
{
	int fd;
	struct stat sb;
	char c = 0x41;
	ssize_t r;

	T_LOG("Testing revoke behavior on non-terminal character devices");

	/* Try to open a non-terminal character device like /dev/null */
	T_ASSERT_POSIX_SUCCESS((fd = open("/dev/null", O_RDONLY)), "Opening /dev/null");

	/* Verify it's a character device */
	T_ASSERT_POSIX_SUCCESS(fstat(fd, &sb), "Getting stat info for /dev/null");
	T_ASSERT_EQ((sb.st_mode & S_IFMT), S_IFCHR, "Verifying /dev/null is a character device");

	/* Revoke the device */
	T_ASSERT_POSIX_SUCCESS(revoke("/dev/null"), "Revoking /dev/null");

	/* Attempt to read from the revoked device */
	/* Non-terminal character devices should return EIO after revoke */
	r = read(fd, &c, 1);
	T_ASSERT_EQ((long)r, -1L, "Reading from revoked non-terminal device should fail");
	T_ASSERT_EQ(errno, EIO, "Reading from revoked non-terminal device should return EIO");

	/* Close the file descriptor */
	T_ASSERT_POSIX_SUCCESS(close(fd), "Closing revoked /dev/null");

	T_LOG("Test completed successfully - revoked non-terminal device returned EIO as expected");
}

T_DECL(tty_revoke_regular_file,
    "Test that revoking regular files returns ENOTSUP")
{
	int fd;
	struct stat sb;
	char template[PATH_MAX];
	char *testfile;
	ssize_t r;

	T_LOG("Testing revoke behavior on regular files (should fail)");

	/* Create a temporary file */
	snprintf(template, sizeof(template), "%s/tty_revoke_regular_file-XXXXXX", dt_tmpdir());
	T_ASSERT_POSIX_SUCCESS((fd = mkstemp(template)), "Creating temporary file");
	testfile = template;

	/* Write some data to it */
	T_ASSERT_POSIX_SUCCESS((int)write(fd, "test", 4), "Writing to temporary file");
	T_ASSERT_POSIX_SUCCESS(close(fd), "Closing temporary file after write");

	/* Reopen for reading */
	T_ASSERT_POSIX_SUCCESS((fd = open(testfile, O_RDONLY)), "Reopening temporary file for reading");

	/* Verify it's a regular file */
	T_ASSERT_POSIX_SUCCESS(fstat(fd, &sb), "Getting stat info for temporary file");
	T_ASSERT_EQ((sb.st_mode & S_IFMT), S_IFREG, "Verifying temporary file is a regular file");

	/* Attempt to revoke the regular file - this should fail */
	r = revoke(testfile);
	T_ASSERT_EQ((long)r, -1L, "Revoking regular file should fail");
	T_ASSERT_EQ(errno, ENOTSUP, "Revoking regular file should return ENOTSUP");

	/* Clean up */
	T_ASSERT_POSIX_SUCCESS(close(fd), "Closing temporary file");
	T_ASSERT_POSIX_SUCCESS(unlink(testfile), "Removing temporary file");

	T_LOG("Test completed successfully - revoke correctly failed on regular file");
}
