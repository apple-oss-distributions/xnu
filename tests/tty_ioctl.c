/*
 * Copyright (c) 2024 Apple Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <darwintest.h>


T_GLOBAL_META(
	T_META_NAMESPACE("xnu.tty"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("file descriptors"),
	T_META_OWNER("souvik_b"),
	T_META_RUN_CONCURRENTLY(true));

static void
tty_ioctl_tioccons(bool privileged)
{
	int primary;
	const char *name;
	int replica;
	int on = 1;
	int off = 0;

	// open primary tty
	T_ASSERT_POSIX_SUCCESS(primary = posix_openpt(O_RDWR | O_NOCTTY), "open primary");

	// allow opening a replica from the primary
	T_ASSERT_POSIX_SUCCESS(grantpt(primary), "grantpt");
	T_ASSERT_POSIX_SUCCESS(unlockpt(primary), "unlockpt");

	// get the name of the primary tty
	T_ASSERT_NOTNULL((name = ptsname(primary)), "ptsname");

	// open the replica
	T_ASSERT_POSIX_SUCCESS(replica = open(name, O_RDWR | O_NOCTTY), "open replica");

	// try calling the TIOCCONS ioctl
	if (privileged) {
		T_ASSERT_POSIX_SUCCESS(ioctl(primary, TIOCCONS, (char *)&on), "ioctl TIOCCONS on");
	} else {
		T_ASSERT_POSIX_ERROR(ioctl(primary, TIOCCONS, (char *)&on), -EPERM, "ioctl TIOCCONS on");
	}
	T_ASSERT_POSIX_SUCCESS(ioctl(primary, TIOCCONS, (char *)&off), "ioctl TIOCCONS off");

	// close primary and replica
	T_ASSERT_POSIX_SUCCESS(close(primary), "close primary");
	T_ASSERT_POSIX_SUCCESS(close(replica), "close replica");
}

T_DECL(tty_ioctl_tioccons_privileged,
    "call the TIOCCONS ioctl as root",
    T_META_ASROOT(true),
    T_META_TAG_VM_PREFERRED)
{
	tty_ioctl_tioccons(true);
}


T_DECL(tty_ioctl_tioccons_unprivileged,
    "call the TIOCCONS ioctl without root",
    T_META_ASROOT(false),
    T_META_TAG_VM_PREFERRED)
{
	tty_ioctl_tioccons(false);
}
