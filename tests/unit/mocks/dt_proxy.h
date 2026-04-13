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

#pragma once
#include <stdbool.h>
#include "osfmk/unit_test_utils.h"
#include <mach/kern_return.h>

// -- darwin-test proxy macros and support --
// libdarwintest.a is linked only to the main executable of the test and not to the XNU .dylib or
// the mocks .dylib, otherwise there would create 3 instances of darwintest in the same process, each with different
// state.
// On some occasions some code in these .dylibs need to call darwin-test macros so that the output
// is visible to the user. An example for this is when XNU code calls panic or assert.
// To achieve this, the file dt_proxy.c is built into every test executable and it contains a constructor function
// which registers a set of proxy functions that call the darwin-test macros.

struct dt_proxy_callbacks {
	void (*t_assert_true)(bool cond, const char *msg);
	void (*t_assert_notnull)(void *ptr, const char *msg);
	void (*t_assert_posix_zero)(int v, const char *msg);
	void (*t_assert_mach_success)(kern_return_t kr, const char *msg);
	void (*t_log)(const char *msg);
	void (*t_log_fmtstr)(const char *fmt, const char *msg);
	void (*t_fail)(const char *msg);
	void (*t_quiet)(void);
	bool (*t_state_pass)(void);
};

// register the proxies to the XNU .dylib
extern void set_dt_proxy_attached(struct dt_proxy_callbacks *p);
// register the proxies to the mocks .dylib
extern void set_dt_proxy_mock(struct dt_proxy_callbacks *p);

extern struct dt_proxy_callbacks *get_dt_proxy_attached(void);
extern struct dt_proxy_callbacks *get_dt_proxy_mock(void);

// A pointer of this name appears in the XNU .dylib and the mocks .dylib
extern struct dt_proxy_callbacks *dt_proxy;

/*
 * PT_ASSERT and PT_FAIL fall back to raw_printf() and abort()
 * during initialization before dt_proxy is set.
 */
#define PT_ASSERT_TRUE(cond, msg) \
	do { \
	        if (dt_proxy) { \
	                dt_proxy->t_assert_true((cond), #cond " " msg); \
	        } else if (!(cond)) { \
	                raw_printf("FAIL assertion %s %s\n", #cond, msg); \
	                abort(); \
	        } \
	} while(false)

#define PT_ASSERT_TRUE_S(cond, msg) \
	do { \
	        if (dt_proxy) { \
	                dt_proxy->t_assert_true((cond), msg); \
	        } else if (!(cond)) { \
	                raw_printf("FAIL assertion %s\n", msg); \
	                abort(); \
	        } \
	} while(false)

#define PT_ASSERT_NOTNULL(ptr, msg) \
	do { \
	        if (dt_proxy) { \
	                dt_proxy->t_assert_notnull((ptr), msg); \
	        } else if (!(ptr)) { \
	                raw_printf("FAIL non-null %s %s\n", #ptr, msg); \
	                abort(); \
	        } \
	} while(false)

#define PT_ASSERT_POSIX_ZERO(v, msg) \
	do { \
	        if (dt_proxy) { \
	                dt_proxy->t_assert_posix_zero((v), msg); \
	        } else if (v) { \
	                raw_printf("FAIL non-zero posix return %s %s\n", #v, msg); \
	                abort(); \
	        } \
	} while(false)

#define PT_ASSERT_MACH_SUCCESS(kr, msg) \
	do { \
	        if (dt_proxy) { \
	                dt_proxy->t_assert_mach_success((kr), msg); \
	        } else if (kr) { \
	                raw_printf("FAIL non-zero mach return %s %s\n", #kr, msg); \
	                abort(); \
	        } \
	} while(false)

#define PT_FAIL(msg) \
	do { \
	        if (dt_proxy) { \
	                dt_proxy->t_fail(msg); \
	        } else { \
	                raw_printf("FAIL %s\n", msg); \
	                abort(); \
	        } \
	} while(false)

#define PT_LOG(msg) do { if (dt_proxy) { dt_proxy->t_log(msg); } } while(false)
#define PT_LOG_FMTSTR(fmt, str) do { if (dt_proxy) { dt_proxy->t_log_fmtstr(fmt, str); } } while(false)
#define PT_LOG_OR_RAW_FMTSTR(fmt, str) do { \
	if (dt_proxy) {                         \
	    dt_proxy->t_log_fmtstr(fmt, str);   \
	} else {                                \
	    raw_printf(fmt "\n", str);          \
	}                                       \
	} while(false)
#define PT_QUIET do { if (dt_proxy) { dt_proxy->t_quiet(); } } while(false)
#define PT_STATE_PASS  ((dt_proxy) ? dt_proxy->t_state_pass() : false)
