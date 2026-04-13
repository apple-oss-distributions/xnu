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
#include "mocks/std_safe.h"
#include "mocks/mock_dynamic.h"

#define countof(arr) (sizeof(arr) / sizeof((arr)[0]))
#define UT_LLDB_ENV "UT_IN_LLDB_SESSION"

struct ut_expected_panic_s {
	bool expect_panic;
	jmp_buf jb;
	const char* str_contains;
};
extern struct ut_expected_panic_s ut_expected_panic;

// Wrap a call that's expected to panic
// This assumes tester is single threaded
#define T_ASSERT_PANIC_CONTAINS(code_block, s_contains, msg, ...) do {   \
	  char __TAPC_msg[PRINT_BUF_SIZE] = "";                          \
	  if (msg) {                                                     \
	          int __TAPC_ret = snprintf(__TAPC_msg, PRINT_BUF_SIZE, \
	                msg __VA_OPT__(,) __VA_ARGS__);                  \
	          assert(__TAPC_ret >= 0);                               \
	  }                                                              \
	  if (setjmp(ut_expected_panic.jb) == 0) {                       \
	        ut_expected_panic.expect_panic = true;                   \
	        ut_expected_panic.str_contains = s_contains;             \
	        {                                                        \
	                code_block;                                      \
	        }                                                        \
	        T_FAIL("did not panic() %s", __TAPC_msg);                \
	  } else {                                                       \
	        T_PASS("OK panic()ed %s", __TAPC_msg);                   \
	  }                                                              \
	} while(false)

#define T_ASSERT_PANIC(code_block, msg, ...) \
	T_ASSERT_PANIC_CONTAINS(code_block, NULL, msg, __VA_ARGS__)

extern void ut_check_expected_panic(const char* panic_str);

static inline void raw_printf(const char *fmt, ...) __attribute__((format(printf, 1, 0)));

#define PRINT_BUF_SIZE 1024
static inline void
raw_printf(const char *fmt, ...)
{
	va_list listp;
	va_start(listp, fmt);
	char buf[PRINT_BUF_SIZE];
	int printed = vsnprintf(buf, PRINT_BUF_SIZE, fmt, listp);
	if (printed > PRINT_BUF_SIZE - 1) {
		printed = PRINT_BUF_SIZE - 1;
	}
	write(STDOUT_FILENO, buf, printed);
	va_end(listp);
}

extern void *checked_alloc_align(size_t size, size_t mask);

#define BACKTRACE_ARRAY_SIZE 100
struct backtrace_array {
	void* buffer[BACKTRACE_ARRAY_SIZE];
	int nptrs;
};
extern struct backtrace_array *collect_current_backtrace(void);
extern void print_collected_backtrace(struct backtrace_array *bt);
extern void print_current_backtrace(void);

extern void ut_set_perm_quiet(bool v);

extern int64_t run_sysctl_test(const char *t, int64_t value, int argc, char* const* argv);

/**
 * Global variable to store the current checkpoint name for LLDB debugging.
 * This is set by ut_lldb_check_point() and can be read by the debugger.
 */
extern const char *lldb_current_checkpoint_name;

/**
 * @function ut_is_running_in_lldb_test_session
 * @discussion This function checks whether the executable is running in an LLDB session
 *             as part of the testing infrastructure for LLDB macros. It determines this
 *             by looking for the UT_LLDB_ENV environment variable in the process
 *             environment.
 *
 * @return true if running in an LLDB test session (UT_LLDB_ENV environment
 *         variable is set), false otherwise.
 */
static inline bool
ut_is_running_in_lldb_test_session(void)
{
	// Check for LLDB debugger environment variable
	char *lldb_env_var = getenv(UT_LLDB_ENV);
	return lldb_env_var && strcmp(lldb_env_var, "1") == 0;
}
/**
 * @function ut_lldb_check_point
 * @discussion This function accepts a string and triggers a debugger breakpoint using
 *             __builtin_debugtrap(). The checkpoint name is stored in a global variable
 *             that can be read by the LLDB session.
 *
 * @param checkpoint_name A name for the checkpoint, stored in global variable
 */
static inline void
ut_lldb_check_point(const char *checkpoint_name)
{
	lldb_current_checkpoint_name = checkpoint_name;
	if (ut_is_running_in_lldb_test_session()) {
		__builtin_debugtrap();
	}
	lldb_current_checkpoint_name = NULL;
}
