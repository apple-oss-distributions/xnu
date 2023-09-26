/*
 * Copyright (c) 2023 Apple Inc. All rights reserved.
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

/* test that the header doesn't implicitly depend on others */
#include <sys/resource_private.h>
#include <sys/resource.h>

#include <sys/types.h>
#include <unistd.h>

#include <darwintest.h>

T_GLOBAL_META(T_META_NAMESPACE("xnu.scheduler"),
    T_META_RADAR_COMPONENT_NAME("xnu"),
    T_META_RADAR_COMPONENT_VERSION("scheduler"),
    T_META_OWNER("chimene"),
    T_META_RUN_CONCURRENTLY(true));

T_DECL(unentitled_game_mode, "game mode bit shouldn't work unentitled")
{
	T_LOG("uid: %d", getuid());

	T_EXPECT_POSIX_FAILURE(setpriority(PRIO_DARWIN_GAME_MODE, 0, PRIO_DARWIN_GAME_MODE_ON),
	    EPERM, "setpriority(PRIO_DARWIN_GAME_MODE, 0, PRIO_DARWIN_GAME_MODE_ON)");
}

T_DECL(unentitled_game_mode_read_root, "game mode bit should be readable as root",
    T_META_ASROOT(true))
{
	T_LOG("uid: %d", getuid());

	T_ASSERT_POSIX_SUCCESS(getpriority(PRIO_DARWIN_GAME_MODE, 0),
	    "getpriority(PRIO_DARWIN_GAME_MODE)");
}

T_DECL(unentitled_game_mode_read_notroot, "game mode bit should not be readable as not root",
    T_META_ASROOT(false))
{
	T_LOG("uid: %d", getuid());

	T_EXPECT_POSIX_FAILURE(getpriority(PRIO_DARWIN_GAME_MODE, 0), EPERM,
	    "getpriority(PRIO_DARWIN_GAME_MODE)");
}
