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

#include <sys/socket.h>

#include <nfs/nfs.h>

#include <darwintest.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_ASROOT(true)
	);

T_DECL(test_unp_sock_release, "UDS with sock_release()")
{
	int fds[2] = { -1, -1 };
	struct nfsd_args nfsd_args = { 0 };

	T_ASSERT_POSIX_SUCCESS(socketpair(AF_UNIX, SOCK_DGRAM, 0, fds),
	    "socketpair(AF_UNIX, SOCK_DGRAM, 0)");
	T_LOG("socketpair() fds: %d, %d\n", fds[0], fds[1]);

	nfsd_args.sock = fds[0];
	T_ASSERT_POSIX_SUCCESS(nfssvc(NFSSVC_EXPORT | NFSSVC_ADDSOCK | NFSSVC_NFSD, &nfsd_args),
	    "nfssvc() sock %d", fds[0]);

	T_ASSERT_POSIX_SUCCESS(close(fds[0]), "close(%d)\n", fds[0]);

	T_ASSERT_POSIX_SUCCESS(nfssvc(NFSSVC_EXPORT | NFSSVC_NFSD, NULL), "nfssvc() NULL");

	T_ASSERT_POSIX_SUCCESS(close(fds[1]), "close(%d)\n", fds[1]);
}
