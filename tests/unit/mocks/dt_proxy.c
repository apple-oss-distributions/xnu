/*
 * Copyright (c) 2000-2024 Apple Inc. All rights reserved.
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

#include "std_safe.h"
#include "dt_proxy.h"
#include <darwintest.h>

static void
pt_assert_true(bool cond, const char *msg)
{
	T_ASSERT_TRUE(cond, "%s", msg);
}
static void
pt_assert_notnull(void *ptr, const char *msg)
{
	T_ASSERT_NOTNULL(ptr, "%s", msg);
}
static void
pt_assert_posix_zero(int v, const char *msg)
{
	T_ASSERT_POSIX_ZERO(v, "%s", msg);
}
static void
pt_assert_mach_success(kern_return_t kr, const char *msg)
{
	T_ASSERT_MACH_SUCCESS(kr, "%s", msg);
}
static void
pt_log(const char *msg)
{
	T_LOG("%s", msg);
}
static void
pt_log_fmtstr(const char* fmt, const char *msg)
{
	T_LOG(fmt, msg);
}
static void
pt_fail(const char *msg)
{
	T_ASSERT_FAIL("%s", msg);
}
static void
pt_quiet(void)
{
	T_QUIET;
}

static bool
pt_state_pass(void)
{
	return T_STATE == T_STATE_PASS;
}

static struct dt_proxy_callbacks dt_callbacks = {
	.t_assert_true = &pt_assert_true,
	.t_assert_notnull = &pt_assert_notnull,
	.t_assert_posix_zero = &pt_assert_posix_zero,
	.t_assert_mach_success = &pt_assert_mach_success,
	.t_log = &pt_log,
	.t_log_fmtstr = &pt_log_fmtstr,
	.t_fail = &pt_fail,
	.t_quiet = &pt_quiet,
	.t_state_pass = &pt_state_pass
};

// This code is linked into every test executable to allow the XNU and mocks .dylibs access to some
// darwintest functionality.  libdarwintest.a is only linked to the executable so code in the XNU and
// mocks .dylibs can't call into it directly
// due to how dyld works, this constructor is going to be called after the fake_kinit() constructor
// so during fake_kinit() dt_proxy is going to stay NULL and any output to darwintest asserts is lost.
__attribute__((constructor)) void
dt_init(void)
{
	set_dt_proxy_attached(&dt_callbacks);
	set_dt_proxy_mock(&dt_callbacks);
}
