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
#include <darwintest_utils.h>

#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"));

T_DECL(direct_write_cow,
    "test direct write() to file mapped with MAP_PRIVATE", T_META_TAG_VM_PREFERRED)
{
	int fd;
	int ret;
	char tmpf[PATH_MAX] = "";
	char *map_shared_addr, *map_private_addr;
	size_t file_size;
	ssize_t num_bytes;
	char *buf;

	T_SETUPBEGIN;

	strlcpy(tmpf, dt_tmpdir(), PATH_MAX);
	strlcat(tmpf, "/cow_direct_write.txt", PATH_MAX);
	T_LOG("file name: <%s>\n", tmpf);
	fd = open(tmpf, O_RDWR | O_CREAT | O_TRUNC, 0644);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(fd, "open()");

	file_size = PAGE_SIZE;
	ret = ftruncate(fd, (off_t) file_size);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(fd, "ftruncate()");

	ret = fcntl(fd, F_NOCACHE, true);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "fcntl(F_NOCACHE)");

	buf = valloc(file_size);
	T_QUIET; T_ASSERT_NOTNULL(buf, "valloc()");

	memset(buf, 'a', file_size);
	num_bytes = pwrite(fd, buf, file_size, 0);
	T_QUIET; T_EXPECT_POSIX_SUCCESS(num_bytes, "write()");
	T_QUIET; T_EXPECT_EQ(num_bytes, (ssize_t) file_size, "wrote <file_size> bytes");

	map_shared_addr = mmap(NULL, file_size, PROT_READ, MAP_FILE | MAP_SHARED, fd, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(map_shared_addr, "mmap(MAP_SHARE)");
//	T_ASSERT_EQ(map_addr[0], 'a', 1); /* that would pollute the buffer cache... */

	map_private_addr = mmap(NULL, file_size, PROT_READ, MAP_FILE | MAP_PRIVATE, fd, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(map_private_addr, "mmap(MAP_PRIVATE)");
//	T_ASSERT_EQ(map_addr[0], 'a', 1); /* that would pollute the buffer cache... */

	T_SETUPEND;

	memset(buf, 'b', file_size);
	num_bytes = pwrite(fd, buf, file_size, 0);
	T_QUIET; T_EXPECT_POSIX_SUCCESS(num_bytes, "write()");
	T_QUIET; T_EXPECT_EQ(num_bytes, (ssize_t) file_size, "wrote <file_size> bytes");

	T_ASSERT_EQ(map_shared_addr[0], 'b', "shared mapping was modified");
	T_ASSERT_EQ(map_private_addr[0], 'a', "private mapping was not modified");
}
