/*
 * Copyright (c) 2026 Apple Inc. All rights reserved.
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

/*
 * Test case for bpf_setup() NULL buffer panic.
 *
 * bpf_setup() copies buffers from d_from to d_to but doesn't verify
 * that d_from has buffers allocated. If d_from has BPF_COMP_REQ set
 * but was never attached to an interface (BIOCSETIF never called),
 * its bd_prev_sbuf is NULL. The code copies BPF_COMP_REQ to d_to,
 * allocates bd_prev_sbuf for d_to, then tries to memcpy from
 * d_from's NULL bd_prev_sbuf — triggering a bounds-safety trap.
 *
 * Steps:
 *   1. Open BPF device d_from, enable header compression (sets BPF_COMP_REQ)
 *      but do NOT call BIOCSETIF — buffers stay NULL
 *   2. Get d_from's UUID via BIOCGETUUID
 *   3. Open BPF device d_to
 *   4. Call BIOCSETUP on d_to with d_from's UUID and a valid interface name
 *   -> on an unpatched kernel, panics in bpf_setup() at the memcpy
 *   -> on a patched kernel, BIOCSETUP returns an error
 */

#include <darwintest.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/bpf.h>
#include <net/if.h>
#include <uuid/uuid.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_ASROOT(true)
	);


static int
open_bpf(void)
{
	char path[32];

	for (int i = 0; i < 256; i++) {
		snprintf(path, sizeof(path), "/dev/bpf%d", i);
		int fd = open(path, O_RDWR);
		if (fd >= 0) {
			return fd;
		}
	}
	return -1;
}

T_DECL(bpf_setup_null_buf,
    "test bpf_setup with unattached d_from having BPF_COMP_REQ set",
    T_META_CHECK_LEAKS(false))
{
	/*
	 * Step 1: Open d_from and enable header compression.
	 * Do NOT call BIOCSETIF — buffers remain unallocated.
	 */
	int fd_from = open_bpf();
	T_ASSERT_POSIX_SUCCESS(fd_from, "open BPF device for d_from");

	int comp = 1;
	T_ASSERT_POSIX_SUCCESS(ioctl(fd_from, BIOCSHDRCOMP, &comp),
	    "BIOCSHDRCOMP on d_from (set BPF_COMP_REQ)");

	/*
	 * Step 2: Get d_from's UUID.
	 */
	uuid_t uuid;
	T_ASSERT_POSIX_SUCCESS(ioctl(fd_from, BIOCGETUUID, &uuid),
	    "BIOCGETUUID on d_from");

	uuid_string_t uuid_str;
	uuid_unparse(uuid, uuid_str);
	T_LOG("d_from UUID: %s", uuid_str);

	/*
	 * Step 3: Open d_to.
	 */
	int fd_to = open_bpf();
	T_ASSERT_POSIX_SUCCESS(fd_to, "open BPF device for d_to");

	/*
	 * Step 4: Call BIOCSETUP on d_to with d_from's UUID.
	 * On an unpatched kernel this panics in bpf_setup() because d_from
	 * has no buffers allocated but has BPF_COMP_REQ set.
	 * On a patched kernel this should return an error.
	 */
	struct bpf_setup_args bsa;
	memset(&bsa, 0, sizeof(bsa));
	uuid_copy(bsa.bsa_uuid, uuid);
	strlcpy(bsa.bsa_ifname, "lo0", sizeof(bsa.bsa_ifname));

	T_LOG("Calling BIOCSETUP (would panic an unpatched kernel)...");
	int ret = ioctl(fd_to, BIOCSETUP, &bsa);
	T_EXPECT_POSIX_FAILURE(ret, ENOENT,
	    "BIOCSETUP should fail when d_from has no buffers");

	close(fd_from);
	close(fd_to);

	T_PASS("bpf_setup_null_buf completed without panic");
}
