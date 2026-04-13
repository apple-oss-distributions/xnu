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

/* compile: xcrun -sdk macosx.internal clang -ldarwintest -lsandbox -arch arm64e -arch x86_64 -o sandbox_getattrlist_vol sandbox_getattrlist_vol.c */

#include <sys/paths.h>
#include <sys/attr.h>
#include <sys/mount.h>
#include <sandbox/libsandbox.h>
#include <TargetConditionals.h>

#include <darwintest.h>
#include <darwintest/utils.h>

#define RUN_TEST     TARGET_OS_OSX

static sandbox_params_t params = NULL;
static sandbox_profile_t profile = NULL;

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vfs"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("vfs"),
	T_META_ASROOT(false),
	T_META_ENABLED(RUN_TEST),
	T_META_CHECK_LEAKS(false));

static void
cleanup(void)
{
	if (profile) {
		sandbox_free_profile(profile);
	}
	if (params) {
		sandbox_free_params(params);
	}
}

struct AttributeBuffer {
	u_int32_t length;
	u_int32_t mode;
} __attribute__((aligned(4), packed));

static int
get_mode_getattrlist(const char *path, bool use_volume_attrs, u_int32_t *mode_out)
{
	struct AttributeBuffer attr_buf = {};
	struct attrlist attrs = {};

	attrs.bitmapcount = ATTR_BIT_MAP_COUNT;
	attrs.commonattr = ATTR_CMN_ACCESSMASK;
	if (use_volume_attrs) {
		attrs.volattr = ATTR_VOL_INFO;
	}

	int result = getattrlist(path, &attrs, &attr_buf, sizeof(attr_buf), FSOPT_RETURN_REALDEV);
	if (result == 0 && mode_out) {
		*mode_out = attr_buf.mode;
	}

	return result;
}

static void
create_profile_string_sudo(char *buff, size_t size)
{
	snprintf(buff, size, "(version 1) \n\
                          (allow default) \n\
                          (import \"system.sb\") \n\
                          (deny file-read-metadata (path \"/usr/bin/sudo\")) \n");
}

static void
create_profile_string_root(char *buff, size_t size)
{
	snprintf(buff, size, "(version 1) \n\
                          (allow default) \n\
                          (import \"system.sb\") \n\
                          (deny file-read-metadata (path \"/\")) \n");
}

static void
do_test_sudo(int expected_error)
{
	u_int32_t mode_nonvol = 0, mode_vol = 0;
	int result_nonvol, result_vol;

	/* Test getattrlist() with non-volume attributes */
	result_nonvol = get_mode_getattrlist("/usr/bin/sudo", false, &mode_nonvol);
	if (expected_error) {
		T_EXPECT_POSIX_FAILURE(result_nonvol, expected_error,
		    "getattrlist() non-volume on /usr/bin/sudo should FAIL with '%s'", strerror(expected_error));
	} else {
		T_EXPECT_POSIX_SUCCESS(result_nonvol,
		    "getattrlist() non-volume on /usr/bin/sudo should PASS");
	}

	/* Test getattrlist() with volume attributes - this should also fail after the fix */
	result_vol = get_mode_getattrlist("/usr/bin/sudo", true, &mode_vol);
	if (expected_error) {
		T_EXPECT_POSIX_FAILURE(result_vol, expected_error,
		    "getattrlist() volume on /usr/bin/sudo should FAIL with '%s'", strerror(expected_error));
	} else {
		T_EXPECT_POSIX_SUCCESS(result_vol,
		    "getattrlist() volume on /usr/bin/sudo should PASS");
	}

	/* Note: Volume attributes return mountpoint mode, not file mode, so they will differ */
	if (result_nonvol == 0 && result_vol == 0) {
		T_LOG("Non-volume mode: %08x, Volume mode: %08x", mode_nonvol, mode_vol);
		T_LOG("Volume attributes correctly return mountpoint mode, not file mode");
	}
}

static void
do_test_root(int expected_error)
{
	u_int32_t mode_nonvol = 0, mode_vol = 0;
	int result_nonvol, result_vol;

	/* Test getattrlist() with non-volume attributes on /usr/bin/sudo (should work) */
	result_nonvol = get_mode_getattrlist("/usr/bin/sudo", false, &mode_nonvol);
	T_EXPECT_POSIX_SUCCESS(result_nonvol,
	    "getattrlist() non-volume on /usr/bin/sudo should PASS (not denied)");

	/* Test getattrlist() with volume attributes on /usr/bin/sudo - this accesses root mountpoint */
	/* This should fail after the fix because it tries to access root mountpoint metadata */
	result_vol = get_mode_getattrlist("/usr/bin/sudo", true, &mode_vol);
	if (expected_error) {
		T_EXPECT_POSIX_FAILURE(result_vol, expected_error,
		    "getattrlist() volume on /usr/bin/sudo should FAIL with '%s' (accessing denied root mountpoint)", strerror(expected_error));
	} else {
		T_EXPECT_POSIX_SUCCESS(result_vol,
		    "getattrlist() volume on /usr/bin/sudo should PASS");
	}

	/* Log the modes for clarity */
	if (result_nonvol == 0 && result_vol == 0) {
		T_LOG("Non-volume mode (sudo file): %08x", mode_nonvol);
		T_LOG("Volume mode (root mountpoint): %08x", mode_vol);
	}
}

T_DECL(sandbox_getattrlist_vol_sudo,
    "Test getattrlist volume attributes with sudo file denied")
{
#if (!RUN_TEST)
	T_SKIP("Not macOS");
#endif

	char *sberror = NULL;
	char profile_string[1000];

	T_ATEND(cleanup);
	T_SETUPBEGIN;

	/* Create sandbox variables */
	T_ASSERT_POSIX_NOTNULL(params = sandbox_create_params(), "Creating Sandbox params object");
	create_profile_string_sudo(profile_string, sizeof(profile_string));
	T_ASSERT_POSIX_NOTNULL(profile = sandbox_compile_string(profile_string, params, &sberror),
	    "Creating Sandbox profile object");

	T_SETUPEND;

	/* Test getattrlist() before sandbox - should work */
	T_LOG("Testing getattrlist() before applying sandbox...");
	do_test_sudo(0);

	/* Apply sandbox profile */
	T_ASSERT_POSIX_SUCCESS(sandbox_apply(profile), "Applying Sandbox profile to deny file-read-metadata on /usr/bin/sudo");

	/* Test getattrlist() after sandbox - both should fail */
	T_LOG("Testing getattrlist() after applying sandbox...");
	do_test_sudo(EPERM);
}

T_DECL(sandbox_getattrlist_vol_root,
    "Test getattrlist volume attributes with root mountpoint denied")
{
#if (!RUN_TEST)
	T_SKIP("Not macOS");
#endif

	char *sberror = NULL;
	char profile_string[1000];

	T_ATEND(cleanup);
	T_SETUPBEGIN;

	/* Create sandbox variables */
	T_ASSERT_POSIX_NOTNULL(params = sandbox_create_params(), "Creating Sandbox params object");
	create_profile_string_root(profile_string, sizeof(profile_string));
	T_ASSERT_POSIX_NOTNULL(profile = sandbox_compile_string(profile_string, params, &sberror),
	    "Creating Sandbox profile object");

	T_SETUPEND;

	/* Test getattrlist() before sandbox - should work */
	T_LOG("Testing getattrlist() before applying sandbox...");
	do_test_root(0);

	/* Apply sandbox profile */
	T_ASSERT_POSIX_SUCCESS(sandbox_apply(profile), "Applying Sandbox profile to deny file-read-metadata on root mountpoint");

	/* Test getattrlist() after sandbox - both should fail */
	T_LOG("Testing getattrlist() after applying sandbox...");
	do_test_root(EPERM);
}
