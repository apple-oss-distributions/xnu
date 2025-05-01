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
#include <sys/wait.h>
#include <spawn.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.sysctl"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("sysctl"),
	T_META_OWNER("p_tennen"),
	T_META_TAG_VM_PREFERRED,
	T_META_RUN_CONCURRENTLY(true)
	);

T_DECL(tree_walk, "Ensure we can walk a contrived sysctl tree")
{
	// rdar://138698424
	// Given a particular sysctl node tree (defined in-kernel)
	// When we invoke the sysctl machinery to walk this tree
	// (By specifying a partial path to the tree to the `sysctl` CLI tool -
	// trying to use sysctlbyname won't trigger the walk we're interested in.)
	char *args[] = { "/usr/sbin/sysctl", "debug.test.sysctl_node_test", NULL };
	int child_pid;
	T_ASSERT_POSIX_ZERO(posix_spawn(&child_pid, args[0], NULL, NULL, args, NULL), "posix_spawn() sysctl");
	// And we give the child a chance to execute
	int status = 0;
	T_ASSERT_POSIX_SUCCESS(waitpid(child_pid, &status, 0), "waitpid");
	// Then the machine does not panic :}
	T_PASS("The machine didn't panic, therefore our sysctl machinery can handle walking our node tree");
}
