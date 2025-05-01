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
#include <sys/uio.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"),
	T_META_OWNER("francois"),
	T_META_CHECK_LEAKS(true),
	T_META_RUN_CONCURRENTLY(true));

T_DECL(direct_write_wired,
    "test direct write() to wired file", T_META_TAG_VM_PREFERRED)
{
	int fd;
	int ret;
	char tmpf[PATH_MAX] = "";
	char *map_addr;
	size_t file_size;
	ssize_t num_bytes;
	char *buf;

	T_SETUPBEGIN;

	strlcpy(tmpf, dt_tmpdir(), PATH_MAX);
	strlcat(tmpf, "/wire_direct_write.txt", PATH_MAX);
	T_LOG("file name: <%s>\n", tmpf);
	fd = open(tmpf, O_RDWR | O_CREAT | O_TRUNC, 0644);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(fd, "open()");

	file_size = PAGE_SIZE;
	ret = ftruncate(fd, (off_t) file_size);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(fd, "ftruncate()");

	map_addr = mmap(NULL, file_size, PROT_READ | PROT_WRITE, MAP_FILE | MAP_SHARED, fd, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(map_addr, "mmap()");
	memset(map_addr, 'a', file_size);

	ret = mlock(map_addr, file_size);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "mlock()");

	ret = fcntl(fd, F_NOCACHE, true);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "fcntl(F_NOCACHE)");

	buf = valloc(file_size);
	T_QUIET; T_ASSERT_NOTNULL(buf, "valloc()");
	memset(buf, 'b', file_size);

	T_SETUPEND;

	num_bytes = pwrite(fd, buf, file_size, 0);
	T_QUIET; T_EXPECT_POSIX_SUCCESS(num_bytes, "write()");
	T_QUIET; T_EXPECT_EQ(num_bytes, (ssize_t) file_size, "wrote <file_size> bytes");

	ret = munlock(map_addr, file_size);
	T_ASSERT_POSIX_SUCCESS(ret, "munlock()");

	T_ASSERT_EQ(map_addr[0], 'b', "write() worked");

	T_QUIET; T_ASSERT_POSIX_SUCCESS(close(fd), "close()");
	T_QUIET; T_ASSERT_POSIX_SUCCESS(unlink(tmpf), "unlink(%s)", tmpf);
}


#define NUM_IOVS 7

T_DECL(direct_write_wired_vector_upl,
    "test direct write() to wired file with vector UIO",
    T_META_TAG_VM_PREFERRED)
{
	char tmpf[PATH_MAX] = "";
	struct iovec w_iovs[NUM_IOVS];
	struct iovec r_iovs[NUM_IOVS];
	int fd;
	ssize_t bytes, expected_bytes;
	int w, r;
	char *w_base, *r_base;
	int w_cnt, r_cnt;
	int w_idx, r_idx;
	char *map_addr;
	int ret;
	char *buf;

	T_SETUPBEGIN;

	expected_bytes = 0;
	for (w = 0, r = NUM_IOVS - 1; w < NUM_IOVS; w++, r--) {
		w_iovs[w].iov_len = (size_t) ((w + 1) * (int)PAGE_SIZE);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(posix_memalign(&w_iovs[w].iov_base, PAGE_SIZE, w_iovs[w].iov_len), "alloc(w_iov_base[%d])", w);
		memset(w_iovs[w].iov_base, 'a' + w, w_iovs[w].iov_len);
		expected_bytes += w_iovs[w].iov_len;

		r_iovs[r].iov_len = w_iovs[w].iov_len;
		T_QUIET; T_ASSERT_POSIX_SUCCESS(posix_memalign(&r_iovs[r].iov_base, PAGE_SIZE, r_iovs[r].iov_len), "alloc(r_iov_base[%d])", r);
	}
	strlcpy(tmpf, dt_tmpdir(), PATH_MAX);
	strlcat(tmpf, "/wire_direct_write.txt", PATH_MAX);
	T_QUIET; T_ASSERT_LT(strlen(tmpf), (unsigned long)PATH_MAX,
	    "path exceeds PATH_MAX");
	fd = open(tmpf, O_RDWR | O_CREAT | O_TRUNC);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(fd, "open()");
	/* use F_NOCACHE to get direct I/O */
	T_QUIET; T_ASSERT_POSIX_SUCCESS(fcntl(fd, F_NOCACHE, 1), "fcntl(F_NOCACHE)");

	buf = valloc(expected_bytes);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(buf, "valloc()");
	memset(buf, '?', expected_bytes);
	bytes = pwrite(fd, buf, expected_bytes, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(bytes, "pwrite()");
	T_ASSERT_EQ(bytes, expected_bytes,
	    "pwrite() wrote %ld bytes", bytes);

	T_SETUPEND;

	map_addr = mmap(NULL, expected_bytes, PROT_READ | PROT_WRITE,
	    MAP_FILE | MAP_SHARED, fd, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(map_addr, "mmap()");
	ret = mlock(&map_addr[(NUM_IOVS / 2) * PAGE_SIZE], PAGE_SIZE);
	T_ASSERT_POSIX_SUCCESS(ret, "mlock(0x%llx)", (uint64_t)((NUM_IOVS / 2) * PAGE_SIZE));

	bytes = pwritev(fd, w_iovs, NUM_IOVS, 0);
	T_ASSERT_EQ(bytes, expected_bytes,
	    "pwritev() wrote %ld bytes", bytes);

	bytes = preadv(fd, r_iovs, NUM_IOVS, 0);
	T_ASSERT_EQ(bytes, expected_bytes,
	    "preadv() read %ld bytes", bytes);

	w = 0;
	w_base = w_iovs[w].iov_base;
	w_cnt = (int) w_iovs[w].iov_len;
	w_idx = 0;
	for (r = 0; r < NUM_IOVS; r++) {
		r_base = r_iovs[r].iov_base;
		r_cnt = (int) r_iovs[r].iov_len;
		for (r_idx = 0; r_idx < r_cnt; r_idx++) {
			T_QUIET; T_ASSERT_EQ(r_base[r_idx], w_base[w_idx],
			    "r_iovs[%d].iov_base[%d]='%c' == w_iovs[%d].iov_base[%d]='%c'",
			    r, r_idx, (unsigned char)r_base[r_idx],
			    w, w_idx, (unsigned char) w_base[w_idx]);
			if (++w_idx == w_cnt) {
				w++;
				w_base = w_iovs[w].iov_base;
				w_cnt = (int) w_iovs[w].iov_len;
				w_idx = 0;
			}
		}
	}

	T_QUIET; T_ASSERT_POSIX_SUCCESS(close(fd), "close()");
	T_QUIET; T_ASSERT_POSIX_SUCCESS(unlink(tmpf), "unlink(%s)", tmpf);

	T_PASS("%s", __FUNCTION__);
}
