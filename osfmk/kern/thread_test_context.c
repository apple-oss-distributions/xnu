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

/*
 * Implementation and tests of thread test contexts.
 */

#if !(DEBUG || DEVELOPMENT)
#error this file is not for release
#endif

#include <kern/thread_test_context.h>

/* For testing thread_test_context_t itself. */
DECLARE_TEST_IDENTITY(test_identity_thread_test_context);
DEFINE_TEST_IDENTITY(test_identity_thread_test_context);

void
thread_test_context_deinit(thread_test_context_t *ctx)
{
	/*
	 * Deinitialize thread_text_context_t->ttc_* fields.
	 * Don't touch ttc->ttc_data.
	 */

	/*
	 * for testing ttc itself: modify *ttc->ttc_data so the
	 * test can verify that this deinit was executed.
	 */
	if (ctx->ttc_identity == test_identity_thread_test_context) {
		int *data_p = (int *)ctx->ttc_data;
		if (data_p) {
			*data_p += 1;
		}
	}
}

/* Tests of thread test contexts */

#define FAIL                                    \
	({                                      \
	        *out_value = __LINE__;          \
	        return 0;                       \
	})

static int
thread_test_context_tests(int64_t in_value __unused, int64_t *out_value)
{
	*out_value = 0;

	/*
	 * Tests of:
	 * thread_set_test_context
	 * thread_cleanup_test_context when thread's context is NULL
	 * thread_cleanup_test_context when thread's context is not NULL
	 * thread_test_context_deinit
	 */
	{
		/* no attribute(cleanup), we call cleanup manually */
		int data;
		thread_test_context_t ctx = {
			.ttc_identity = test_identity_thread_test_context,
			.ttc_data = &data,
		};

		data = 0;
		/* cleanup called when thread's context is NULL */
		if (current_thread()->th_test_ctx != NULL) {
			FAIL;
		}
		if (thread_get_test_context() != NULL) {
			FAIL;
		}
		thread_cleanup_test_context(&ctx);
		/* thread_test_context_deinit increments *ttc_data */
		if (data != 1) {
			FAIL;
		}
		/* thread_cleanup_test_context clears thread's context */
		if (current_thread()->th_test_ctx != NULL) {
			FAIL;
		}

		data = 1;
		/* cleanup called when thread's context is not NULL */
		thread_set_test_context(&ctx);
		if (current_thread()->th_test_ctx != &ctx) {
			FAIL;
		}
		if (thread_get_test_context() != &ctx) {
			FAIL;
		}
		thread_cleanup_test_context(&ctx);
		/* thread_test_context_deinit increments *ttc_data */
		if (data != 2) {
			FAIL;
		}
		/* thread_cleanup_test_context clears thread's context */
		if (current_thread()->th_test_ctx != NULL) {
			FAIL;
		}
	}

	/*
	 * Tests of:
	 * access test options with no test context set
	 * access test options when a context is installed but no options are set
	 * attribute(cleanup(thread_cleanup_test_context))
	 */
	int data = 0;
	{
		thread_test_context_t ctx CLEANUP_THREAD_TEST_CONTEXT = {
			.ttc_identity = test_identity_thread_test_context,
			.ttc_data = &data,
			.ttc_testing_ttc_int = 1,
			.ttc_testing_ttc_struct = { 33, 44 }
		};

		/* access test options with no test context set */
		if (thread_get_test_context() != NULL) {
			FAIL;
		}

		if (thread_get_test_option(ttc_testing_ttc_int) != 0) {
			FAIL;
		}
		/* setting an option with no context has no effect */
		thread_set_test_option(ttc_testing_ttc_int, 1 + thread_get_test_option(ttc_testing_ttc_int));
		if (thread_get_test_option(ttc_testing_ttc_int) != 0) {
			FAIL;
		}

		if (thread_get_test_option(ttc_testing_ttc_struct).min_address != 0) {
			FAIL;
		}
		/* setting an option with no context has no effect */
		thread_set_test_option(ttc_testing_ttc_struct, (struct mach_vm_range){55, 66});
		if (thread_get_test_option(ttc_testing_ttc_struct).min_address != 0) {
			FAIL;
		}

		/* access test options with a test context set */
		thread_set_test_context(&ctx);
		if (thread_get_test_option(ttc_testing_ttc_int) != 1) {
			FAIL;
		}
		thread_set_test_option(ttc_testing_ttc_int, 1 + thread_get_test_option(ttc_testing_ttc_int));
		if (thread_get_test_option(ttc_testing_ttc_int) != 2) {
			FAIL;
		}
		thread_set_test_option(ttc_testing_ttc_int, 0);
		if (thread_get_test_option(ttc_testing_ttc_int) != 0) {
			FAIL;
		}

		if (thread_get_test_option(ttc_testing_ttc_struct).min_address != 33) {
			FAIL;
		}
		thread_set_test_option(ttc_testing_ttc_struct, (struct mach_vm_range){55, 66});
		if (thread_get_test_option(ttc_testing_ttc_struct).min_address != 55) {
			FAIL;
		}

		/* thread_cleanup_test_context runs at end of scope */
		if (data != 0) {
			FAIL;
		}
	}
	/* thread_cleanup_test_context incremented data through ttc->ttc_data */
	if (data != 1) {
		FAIL;
	}

	if (current_thread()->th_test_ctx != NULL) {
		FAIL;
	}

	/* success */
	*out_value = 0;
	return 0;
}

#undef FAIL

SYSCTL_TEST_REGISTER(thread_test_context, thread_test_context_tests);
