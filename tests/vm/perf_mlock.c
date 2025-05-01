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
 *
 */
#include <darwintest.h>
#include <darwintest_perf.h>
#include <darwintest_utils.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <sys/syslimits.h>

/*
 * Wiring performance micro-benchmark.
 */

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm.perf"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"),
	T_META_OWNER("jarrad"),
	T_META_CHECK_LEAKS(false),
	T_META_TAG_PERF,
	T_META_REQUIRE_NOT_VIRTUALIZED);

#define MiB(b) ((uint64_t)b << 20)

extern int vfs_purge(void);

T_DECL(mlock_external,
    "File-backed wire microbenchmark",
    T_META_ENABLED(false /* rdar://133954365 */))
{
	void *buf = NULL;
	int fd, ret;
	char tmpf[PATH_MAX] = "";
	uint8_t pattern[4] = {0xFEu, 0xDCu, 0xBAu, 0x98u};
	// This should be kept larger than MAX_UPL_TRANFER_BYTES to ensure clustering
	// greater than the default fault clustering is tested
	const size_t vmsize = MiB(512);

	T_SETUPBEGIN;

	buf = malloc(vmsize);
	T_QUIET; T_ASSERT_NOTNULL(buf, "malloc()");

	// Create a tmp file and populate it with data
	strlcpy(tmpf, dt_tmpdir(), PATH_MAX);
	strlcat(tmpf, "/mlock_external.txt", PATH_MAX);
	T_QUIET; T_ASSERT_LT(strlen(tmpf), (unsigned long)PATH_MAX,
	    "path exceeds PATH_MAX");

	fd = open(tmpf, (O_RDWR | O_CREAT));
	T_QUIET; T_ASSERT_POSIX_SUCCESS(fd, "open()");

	memset_pattern4((char *)buf, pattern, vmsize);
	write(fd, buf, vmsize);
	fsync(fd);
	close(fd);
	free(buf);
	buf = NULL;

	// Purge to flush the test file from the filecache
	vfs_purge();

	fd = open(tmpf, O_RDWR);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(fd, "open()");
	buf = mmap(NULL, vmsize, PROT_READ,
	    (MAP_FILE | MAP_SHARED), fd, 0);
	T_QUIET; T_ASSERT_NOTNULL(buf, "mmap()");

	T_SETUPEND;

	dt_stat_time_t mlock_time = dt_stat_time_create("mlock_duration");
	dt_stat_set_variable(mlock_time, "buffer_size_mb",
	    (unsigned int)(vmsize >> 20));

	T_LOG("Collecting measurements...");
	while (!dt_stat_stable(mlock_time)) {
		T_STAT_MEASURE(mlock_time) {
			ret = mlock(buf, vmsize);
		}
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "mlock()");

		ret = munlock(buf, vmsize);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "munlock()");

		vfs_purge();
	}
	dt_stat_finalize(mlock_time);

	ret = munmap(buf, vmsize);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "munmap()");
	ret = close(fd);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "close()");
}
