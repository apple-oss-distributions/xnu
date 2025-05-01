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

#ifndef _KERN_THREAD_TEST_CONTEXT_H_
#define _KERN_THREAD_TEST_CONTEXT_H_

#include <kern/thread.h>

/*
 * Thread-specific data for threads running kernel tests.
 *
 * A kernel test may store a "test context" in current_thread().
 * The test context is used to communicate between the kernel test
 * and the kernel implementation code being tested.
 *
 * A "test option" is a field in the thread test context that
 * is intended to be accessed by convenience accessors (such as
 * thread_get_test_option) that do nothing in release builds.
 *
 * Example uses:
 * - a kernel test sets a flag that some kernel implementation
 *   code sees to return an error instead of panicking
 * - some kernel implementation code increments counters as it
 *   progresses for kernel test code to validate its execution
 */

__BEGIN_DECLS

#ifdef MACH_KERNEL_PRIVATE

#define DECLARE_TEST_IDENTITY(ident) \
	extern test_identity_t const ident
#define DEFINE_TEST_IDENTITY(ident) \
	test_identity_t const ident = (test_identity_t)&ident

typedef const struct test_identity_t *test_identity_t;

typedef struct thread_test_context {
	/*
	 * ttc_identity optionally names the kernel test that owns this
	 * context structure. If you want to wrap thread_test_context_t
	 * in some larger structure for your test, use this field.
	 *
	 * ttc_data is reserved for the use of the test named by ttc_identity.
	 */
	test_identity_t ttc_identity;
	void *ttc_data;

	/*
	 * Additional fields below may be used by any kernel test or
	 * kernel implementation code regardless of test identity.
	 * Kernel tests that don't use a field initialize it to zero.
	 * Any non-trivial deinitialization is in thread_test_context_deinit().
	 */

	/* for tests of thread_test_context_t itself */
	int ttc_testing_ttc_int;
	struct mach_vm_range ttc_testing_ttc_struct;

	/* prevent some panics for untagged wired memory */
	bool test_option_vm_prevent_wire_tag_panic;
	/* allow NULL vm_map->pmap in some places? */
	bool test_option_vm_map_allow_null_pmap;
	/* clamp virtual addresses before passing to pmap_remove? */
	bool test_option_vm_map_clamp_pmap_remove;
} thread_test_context_t;


/*
 * Gets the test context of current_thread.
 * Returns NULL if current_thread has no test context set.
 * Returns NULL on release builds.
 */
static inline thread_test_context_t * __result_use_check
thread_get_test_context(void)
{
#if DEBUG || DEVELOPMENT
	return current_thread()->th_test_ctx;
#else
	return NULL;
#endif
}

/*
 * Gets a field from the test context on current_thread.
 * Returns a zero-initialized value if current_thread has no test context set.
 * Returns a zero-initialized value on release builds.
 */
#define thread_get_test_option(field)                                   \
	({                                                              \
	        thread_test_context_t *_get_ctx = thread_get_test_context(); \
	        __improbable(_get_ctx != NULL)                          \
	            ? (_get_ctx->field)                                 \
	            : (__typeof__(_get_ctx->field)){};                  \
	})

/*
 * Sets thread_test_context_t->field = new_value on current_thread.
 * Does nothing if current_thread has no test context set.
 * Does nothing on release builds; new_value is not evaluated.
 */
#if DEBUG || DEVELOPMENT
#define thread_set_test_option(field, /* new_value */ ...)          \
	({                                                              \
	        thread_test_context_t *_set_ctx = thread_get_test_context(); \
	        if (__improbable(_set_ctx != NULL)) {                   \
	                _set_ctx->field = (__VA_ARGS__);                \
	        }                                                       \
	})
#else /* not (DEBUG || DEVELOPMENT) */
#define thread_set_test_option(field, /* new_value */ ...)      \
	({ })
#endif /* not (DEBUG || DEVELOPMENT) */


#if DEBUG || DEVELOPMENT

/*
 * Sets the test context of current_thread.
 * Panics if new_ctx is NULL.
 * Panics if current_thread's test context is already set.
 * Not available in release builds.
 */
static inline void
thread_set_test_context(thread_test_context_t *new_ctx)
{
	thread_t thread = current_thread();
	assert(new_ctx);
	assert(thread->th_test_ctx == NULL);
	thread->th_test_ctx = new_ctx;
}

/*
 * Performs any deinitialization of ctx required.
 * The contents of *ctx are left in an indeterminate state.
 * ctx is not freed.
 * Panics if ctx is NULL.
 * Not available in release builds.
 */
extern void
thread_test_context_deinit(thread_test_context_t *ctx);

/*
 * Convenience macro for using attribute(cleanup) to disconnect and
 * destroy a stack-allocated thread test context at end of scope.
 * Not available in release builds.
 *
 * Usage:
 * {
 *     thread_test_context_t ctx CLEANUP_THREAD_TEST_CONTEXT = {
 *             .ttc_field = value, .ttc_field_2 = value2, ...
 *     };
 *     thread_set_test_context(&ctx);
 *     ... run tests ...
 *     ... ctx is disconnected and deinited here at end of scope ...
 * }
 */

#define CLEANUP_THREAD_TEST_CONTEXT                             \
	__attribute__((cleanup(thread_cleanup_test_context)))

static inline void
thread_cleanup_test_context(thread_test_context_t *ctx)
{
	/*
	 * No assertion that th_test_ctx is non-NULL here,
	 * in case the caller needed to exit before setting it.
	 * ... but if it is set, it must be set to ctx.
	 */
	thread_test_context_t *thread_ctx = current_thread()->th_test_ctx;
	if (thread_ctx) {
		assert(thread_ctx == ctx);
	}
	current_thread()->th_test_ctx = NULL;

	thread_test_context_deinit(ctx);
	/* No heap deallocation necessary here: *ctx is stored on the stack */
}

#endif /* DEBUG || DEVELOPMENT */

#endif /* MACH_KERNEL_PRIVATE */

__END_DECLS

#endif /* _KERN_THREAD_TEST_CONTEXT_H_ */
