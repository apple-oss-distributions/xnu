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

#include <darwintest.h>

#include <stdint.h>
#include "mocks/std_safe.h"
#include "mocks/mock_dynamic.h"
#include "mocks/osfmk/unit_test_utils.h"
#include "mocks/mock_mem.h"
#include "mocks/osfmk/mock_internal.h"
#include "mocks/dt_proxy.h"
#include "mocks/fake_kinit.h"
#include <kern/lock_mtx.h>
#include <os/atomic_private.h>
#include <kern/sched_prim.h>
#include <kern/startup.h>

#define UT_MODULE osfmk
T_GLOBAL_META(
	T_META_NAMESPACE("xnu.unit.mocks"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("misc"),
	T_META_OWNER("s_shalom"),
	T_META_RUN_CONCURRENTLY(true)
	);

T_MOCK_ZALLOC_LEAK_CHECK_GLOBAL();

#define NUM_INCREMENTS 100000
#define NUM_THREADS 10

struct inc_state {
	volatile int64_t counter;
	//_Atomic int64_t counter;
	lck_mtx_t mtx;
	lck_grp_t grp;
};

void*
increment_counter(void* arg)
{
	struct inc_state *s = (struct inc_state *)arg;
	for (int i = 0; i < NUM_INCREMENTS; i++) {
		lck_mtx_lock(&s->mtx);
		//lck_mtx_lock_spin(&s->mtx);
		s->counter++;
		//os_atomic_inc(&s->counter, relaxed);
		lck_mtx_unlock(&s->mtx);
	}
	return NULL;
}


T_DECL(mutex_mock_increment_int, "mutex mock test")
{
	pthread_t mythreads[NUM_THREADS] = {};
	struct inc_state s = {.counter = 0};
	lck_grp_init(&s.grp, "test_mutex", LCK_GRP_ATTR_NULL);
	lck_mtx_init(&s.mtx, &s.grp, LCK_ATTR_NULL);

	// Create threads
	for (int i = 0; i < NUM_THREADS; i++) {
		pthread_create(&mythreads[i], NULL, increment_counter, (void*)&s);
	}

	// Wait for all threads to finish
	for (int i = 0; i < NUM_THREADS; i++) {
		pthread_join(mythreads[i], NULL);
	}
	lck_mtx_destroy(&s.mtx, &s.grp);

	T_LOG("Done counter=%lld", os_atomic_load(&s.counter, relaxed));
	T_ASSERT_EQ(s.counter, (int64_t)(NUM_INCREMENTS * NUM_THREADS), "eq");
}

struct wait_state {
	event_t event;
	volatile bool thread_did_sleep;
};

// from unistd.h.
// This can't be in stdsafe.h since it conflicts with a definition in bsd/sys/proc_internal.h
unsigned int sleep(unsigned int seconds);

void*
do_sleep_and_wake(void *arg)
{
	struct wait_state *s = (struct wait_state *)arg;
	sleep(1);
	s->thread_did_sleep = true;
	kern_return_t ret = thread_wakeup(s->event);
	T_ASSERT_EQ(ret, KERN_SUCCESS, "thread_wakeup");
	return NULL;
}

T_DECL(mocks_can_call_dt, "check that mocks can call T_x macros via PT_x")
{
	T_ASSERT_NOTNULL(get_dt_proxy_mock(), "mock dt_proxy null");
	T_ASSERT_NOTNULL(get_dt_proxy_attached(), "attached dt_proxy null");
}

// this test is meant to fail in order to verify that we're linking with the mock unimplemented sptm functions
// it's useful when debugging the Makefile
void libsptm_init(void);
T_DECL(sptm_link_unimpl, "sptm_link_unimpl")
{
	T_EXPECTFAIL_WITH_REASON("fail due to unimplemented sptm mock");
	libsptm_init();
}

#define MAKE_POOL(elem_size, align, count)                             \
	struct mock_mem_pool pool;                                         \
	size_t sz = mock_mem_init(&pool, elem_size, align, count, "test"); \
    struct mock_mem_pool_buffer pb;                                    \
    mock_pool_buffer_init(&pb, sz);                                    \
    mock_mem_setup(&pool, &pb);

T_DECL(mock_mem_free_smoke, "make sure freeing from mocked mem pool works as expected (allocate one and free it)")
{
	MAKE_POOL(sizeof(int), __alignof(int), 1);

	T_ASSERT_EQ(pool.free_count, 1, "free count is 1");

	void *ptr = mock_mem_alloc(&pool);
	T_ASSERT_NOTNULL(ptr, "allocation");
	T_ASSERT_EQ(pool.free_count, 0, "free count is 0 after allocation");

	mock_mem_free(&pool, ptr);
	T_ASSERT_EQ(pool.free_count, 1, "free count is restored to 1 after free");
}

T_DECL(mock_mem_free_reusable, "make sure freed space is reusable")
{
	MAKE_POOL(sizeof(int), __alignof(int), 2);

	void *ptr1 = mock_mem_alloc(&pool);
	void *ptr2 = mock_mem_alloc(&pool);
	T_ASSERT_NOTNULL(ptr1, "first allocation");
	T_ASSERT_NOTNULL(ptr2, "second allocation");

	mock_mem_free(&pool, ptr1);
	T_ASSERT_EQ(pool.free_count, 1, "free count is 1 after first free");

	ptr2 = mock_mem_alloc(&pool);
	T_ASSERT_NOTNULL(ptr2, "third allocation");

	mock_mem_free(&pool, ptr2);
	T_ASSERT_EQ(pool.free_count, 1, "free count is 1 after second free");

	ptr1 = mock_mem_alloc(&pool);
	T_ASSERT_NOTNULL(ptr1, "fourth allocation failed");
}

T_DECL(mock_mem_free_invalid, "make sure freeing an invalid pointer fails")
{
	MAKE_POOL(sizeof(int), __alignof(int), 2);

	int some_var = 0xdeadbeef; /* not in the memory pool */
	T_ASSERT_PANIC({
		mock_mem_free(&pool, &some_var);
	}, "free something that's not in the pool");
}

T_DECL(mock_mem_alignment, "test alignemnt requirement")
{
	struct mock_mem_pool p1, p2, p3, p4;
	size_t sz = mock_mem_init(&p1, sizeof(int), 8, 5, "test1");
	sz += mock_mem_init(&p2, sizeof(int), 64, 2, "test2");
	sz += mock_mem_init(&p3, sizeof(int), 4, 3, "test3");
	sz += mock_mem_init(&p4, sizeof(int), 64, 3, "test4");
	struct mock_mem_pool_buffer pb;
	mock_pool_buffer_init(&pb, sz);

	mock_mem_setup(&p1, &pb);
	mock_mem_setup(&p2, &pb);
	mock_mem_setup(&p3, &pb);
	mock_mem_setup(&p4, &pb);

#define T_ASSERT_ALIGN(ptr, align, msg) T_ASSERT_EQ( (((uintptr_t)(ptr)) & ((uintptr_t)((align) - 1))), (uintptr_t)0, msg)

	void *ptr1 = mock_mem_alloc(&p1);
	T_ASSERT_ALIGN(ptr1, 8, "p1");
	void *ptr2 = mock_mem_alloc(&p2);
	T_ASSERT_ALIGN(ptr2, 64, "p2");
	void *ptr3 = mock_mem_alloc(&p3);
	T_ASSERT_ALIGN(ptr3, 4, "p1");
	void *ptr4 = mock_mem_alloc(&p4);
	T_ASSERT_ALIGN(ptr4, 64, "p4");
}

T_DECL(mock_mem_scoped_leak_test, "test scoped leak check")
{
	{
		T_MOCK_ZALLOC_LEAK_CHECK();
		void* addr = mock_mem_alloc_id(MEM_POOL_VM_MAP_ENTRIES);
		T_PASS("ok");
		// cleanup of the leak-check is going to fail
		T_EXPECTFAIL_WITH_REASON("leak check is expected to fail");
	}
}

// see T_MOCK_ZALLOC_LEAK_CHECK_GLOBAL() above
T_DECL(mock_mem_global_leak_test, "test global leak check", T_META_EXPECTFAIL("Failed due to global leak check"))
{
	void* addr = mock_mem_alloc_id(MEM_POOL_VM_MAP_ENTRIES);
	T_PASS("ok");
}

// --------------- dynamic mocks ---------------------------------

#if (DEBUG || DEVELOPMENT)
// disabled in release since the kernel_funcX() functions are not defined by xnu in release

T_DECL(mock_with_callback, "mock_with_callback")
{
	size_t ret1 = kernel_func1(1, 2);
	T_ASSERT_EQ(ret1, (size_t)0, "expected return before - default value from mock");
	{
		T_MOCK_SET_CALLBACK(kernel_func1,
		    size_t,
		    (int a, char b),
		{
			T_ASSERT_EQ(a, 3, "expected a");
			T_ASSERT_EQ(b, 4, "expected b");
			return a + b;
		});

		size_t ret2 = kernel_func1(3, 4);
		T_ASSERT_EQ(ret2, (size_t)7, "expected return sum");

		T_MOCK_SET_CALLBACK(kernel_func1,
		    size_t,
		    (int a, char b),
		{
			return a - b;
		});

		size_t ret3 = kernel_func1(40, 30);
		T_ASSERT_EQ(ret3, (size_t)10, "expected return second in the same scope");

		size_t ret4 = T_MOCK_CALL_ORIGINAL(kernel_func1, 100, 90);
		T_ASSERT_EQ(ret4, (size_t)0, "the original is expected to return 0");

		size_t ret5 = kernel_func1(100, 90);
		T_ASSERT_EQ(ret5, (size_t)10, "the callback is restored after calling the original");
	}

	size_t ret4 = kernel_func1(5, 6);
	T_ASSERT_EQ(ret4, (size_t)0, "expected return before - mock default value");
}


T_DECL(mock_with_retval, "mock_with_retval")
{
	size_t r1 = kernel_func1(0, 1);
	T_ASSERT_EQ(r1, (size_t)0, "expected value before - mock default value");

	{
		T_MOCK_SET_RETVAL(kernel_func1, size_t, 42);

		size_t r2 = kernel_func1(0, 1);
		T_ASSERT_EQ(r2, (size_t)42, "expected value with mock");


		T_MOCK_SET_RETVAL(kernel_func1, size_t, 43);

		size_t r3 = kernel_func1(0, 1);
		T_ASSERT_EQ(r3, (size_t)43, "expected value with mock second in the same scope");
	}

	size_t r4 = kernel_func1(0, 1);
	T_ASSERT_EQ(r4, (size_t)0, "expected value after - mock default value");
}


T_MOCK_SET_PERM_FUNC(size_t,
    kernel_func2,
    (int a, char b))
{
	T_ASSERT_EQ((int)a % 2, 0, "a is even");
	return a * 2;
}

T_DECL(mock_with_static_func, "mock_with_static_func")
{
	size_t r = kernel_func2(10, 1);
	T_ASSERT_EQ(r, (size_t)20, "expected return value");
}


T_MOCK_SET_PERM_RETVAL(kernel_func3, size_t, 42);

T_DECL(mock_with_perm_retval, "mock_with_perm_retval")
{
	size_t r = kernel_func3(1, 2);
	T_ASSERT_EQ(r, (size_t)42, "expected return value");
}


T_MOCK_CALL_QUEUE(fb_call, {
	int expected_a;
	char expected_b;
	size_t ret_val;
})

T_DECL(mock_call_queue, "mock_call_queue")
{
	enqueue_fb_call((fb_call){ .expected_a = 1, .expected_b = 2, .ret_val = 3 });
	enqueue_fb_call((fb_call){ .expected_a = 10, .expected_b = 20, .ret_val = 30 });

	{
		fb_call c1 = dequeue_fb_call();
		T_ASSERT_EQ(c1.expected_a, 1, "a arg");
		T_ASSERT_EQ(c1.expected_b, 2, "b arg");
		T_ASSERT_EQ(c1.ret_val, (size_t)3, "a arg");
	}
	{
		fb_call c2 = dequeue_fb_call();
		T_ASSERT_EQ(c2.expected_a, 10, "a arg");
		T_ASSERT_EQ(c2.expected_b, 20, "b arg");
		T_ASSERT_EQ(c2.ret_val, (size_t)30, "a arg");
	}
}


T_MOCK_SET_PERM_FUNC(size_t,
    kernel_func4,
    (int a, char b))
{
	fb_call c = dequeue_fb_call();
	T_ASSERT_EQ(a, c.expected_a, "a arg");
	T_ASSERT_EQ(b, c.expected_b, "b arg");
	return c.ret_val;
}

T_DECL(mock_call_queue_in_a_mock, "mock_call_queue_in_a_mock")
{
	enqueue_fb_call((fb_call){ .expected_a = 1, .expected_b = 2, .ret_val = 3 });
	enqueue_fb_call((fb_call){ .expected_a = 10, .expected_b = 20, .ret_val = 30 });

	size_t r1 = kernel_func4(1, 2);
	T_ASSERT_EQ(r1, (size_t)3, "r1 ret");
	size_t r2 = kernel_func4(10, 20);
	T_ASSERT_EQ(r2, (size_t)30, "r2 ret");
}

// a mock that calls the original function explicitly
T_DECL(mock_default_calling_original, "mock_default_calling_original")
{
	size_t r = kernel_func5(1, 2);
	T_ASSERT_EQ(r, (size_t)5000, "r ret");
}

// a mock that calls the original function implicitly through _T_MOCK_DEFAULT_IMPL
T_DECL(mock_default_calling_original_implicit, "mock_default_calling_original_auto_define")
{
	size_t r = kernel_func7(1, 2);
	T_ASSERT_EQ(r, (size_t)7000, "r ret");
}

T_DECL(mock_void_ret, "mock_void_ret")
{
	extern int kernel_func6_was_called;
	kernel_func6_was_called = 0;
	kernel_func6(3, 4);
	T_ASSERT_EQ(kernel_func6_was_called, 3, "original called");

	kernel_func6_was_called = 0;
	T_MOCK_SET_CALLBACK(kernel_func6,
	    void,
	    (int a, char b),
	{
		T_ASSERT_EQ(a, 3, "expected a");
		T_ASSERT_EQ(b, 4, "expected b");
	});
	kernel_func6(3, 4);
	T_ASSERT_EQ(kernel_func6_was_called, 0, "original called");
}

extern int kernel_func8_was_called;

// void function with the default action that calls the original function
T_DECL(mock_void_ret_original_implicit, "mock_void_ret_original_implicit")
{
	kernel_func8_was_called = 0;
	kernel_func8(3, 4);
	T_ASSERT_EQ(kernel_func8_was_called, 3, "original called");
}

T_DECL(mock_explicit_call_original_and_default, "mock_explicit_call_original_and_default")
{
	// call interposed function
	size_t v = kernel_func10(0, 0);
	T_ASSERT_EQ(v, (size_t)11000, "call through intepose");

	// call mock directly (without any callback, default action)
	v = T_MOCK_MOCK(kernel_func10)(0, 0);
	T_ASSERT_EQ(v, (size_t)11000, "call mock directly");

	// calling default action from test
	v = T_MOCK_DEFAULT_ACTION(kernel_func10)(0, 0);
	T_ASSERT_EQ(v, (size_t)11000, "call default action directly");

	// calling original from test
	v = T_MOCK_ORIGINAL(kernel_func10)(0, 0);
	T_ASSERT_EQ(v, (size_t)10000, "call original directly");

	// calling original from mock
	{
		T_MOCK_SET_CALLBACK(kernel_func10, size_t, (int a, char b), {
			return T_MOCK_ORIGINAL(kernel_func10)(0, 0) + 100;
		});
		v = kernel_func10(0, 0);
		T_ASSERT_EQ(v, (size_t)10100, "call through intepose");

		v = T_MOCK_MOCK(kernel_func10)(0, 0);
		T_ASSERT_EQ(v, (size_t)10100, "call mock directly");

		v = T_MOCK_DEFAULT_ACTION(kernel_func10)(0, 0);
		T_ASSERT_EQ(v, (size_t)11000, "call default action directly");

		v = T_MOCK_ORIGINAL(kernel_func10)(0, 0);
		T_ASSERT_EQ(v, (size_t)10000, "call original directly");
	}

	{
		T_MOCK_SET_CALLBACK(kernel_func10, size_t, (int a, char b), {
			return T_MOCK_DEFAULT_ACTION(kernel_func10)(0, 0) + 100;
		});
		v = kernel_func10(0, 0);
		T_ASSERT_EQ(v, (size_t)11100, "call through intepose");

		v = T_MOCK_MOCK(kernel_func10)(0, 0);
		T_ASSERT_EQ(v, (size_t)11100, "call mock directly");

		v = T_MOCK_DEFAULT_ACTION(kernel_func10)(0, 0);
		T_ASSERT_EQ(v, (size_t)11000, "call default action directly");

		v = T_MOCK_ORIGINAL(kernel_func10)(0, 0);
		T_ASSERT_EQ(v, (size_t)10000, "call original directly");
	}
}

__attribute__((overloadable)) int kernel_func9(__unused const char* s);
__attribute__((overloadable)) int kernel_func9(__unused int v);
int kernel_func9(__unused int a, __unused int b);

T_DECL(mock_overloadable_function, "mock_overloadable_function")
{
	int r = kernel_func9("hello");
	T_ASSERT_EQ(r, 101, "string overload return 1, mock adds 100");
	r = kernel_func9(42);
	T_ASSERT_EQ(r, 202, "int overload return 2, mock adds 200");
	r = kernel_func9(42, 43);
	T_ASSERT_EQ(r, 303, "int overload return 3, mock adds 300");
}

extern void test_mock_noinline(size_t expect_from_func5, int expect_from_func8);

// Test that __mockable prevets constant propagation into the arguments and out of return value,
// which would hinder interposing
T_DECL(mockable_disallows_constant_propagation, "mockable_disallows_constant_propagation") {
	T_MOCK_SET_CALLBACK(kernel_func5, size_t, (int a, char b), {
		return 3000;
	});
	T_MOCK_SET_CALLBACK(kernel_func8, void, (int a, char b), {
		T_MOCK_ORIGINAL(kernel_func8)(3001, 0);
	});

	test_mock_noinline(3000, 3001);

	T_PASS("ok");
}

// check multiple pmocks section in the same file
PMOCKS_START
#define RET_FOR_KERNEL_FUNC11 (2)
PMOCKS_END

PMOCKS_START

// this function is mocked both here and in libmocks. This one should win
// because it appears later in OTHER_LDFLAGS in the makefile
T_MOCK_PRIVATE(int, kernel_func11, (int a, char b), (a, b), {
	return RET_FOR_KERNEL_FUNC11;
});

PMOCKS_END
T_DECL(test_private_mocks_work, "test that the PMOCKS mechanism works")
{
	int r = kernel_func11(1, 2);
	T_ASSERT_EQ(r, RET_FOR_KERNEL_FUNC11, "value should come from private mock");
}

T_DECL(test_private_mocks_local_override, "test we can override a private mocks")
{
	T_MOCK_SET_CALLBACK(kernel_func11, int, (int a, char b), {
		return 20;
	});

	int r = kernel_func11(1, 2);
	T_ASSERT_EQ(r, 20, "value should come from override");
}


#endif // (DEBUG || DEVELOPMENT)


// from dlfcn.h
typedef struct dl_info {
	const char      *dli_fname;     /* Pathname of shared object */
	void            *dli_fbase;     /* Base address of shared object */
	const char      *dli_sname;     /* Name of nearest symbol */
	void            *dli_saddr;     /* Address of nearest symbol */
} Dl_info;
extern int dladdr(const void *, Dl_info *);

#define T_MAX_PATH (1024)

static __attribute__((optnone, noinline)) void
get_folder(const char* fname, char* buf)
{
	const char* last_slash = strrchr(fname, '/');
	T_QUIET; T_ASSERT_NOTNULL(last_slash, "did not find folder in %s", fname);
	size_t dir_len = last_slash - fname;
	T_QUIET; T_ASSERT_GT(dir_len, (size_t)0, "no folder name in %s", fname);
	T_QUIET; T_ASSERT_LT(dir_len, (size_t)(T_MAX_PATH - 1), "Directory path too long for buffer: %zu >= %d", dir_len, T_MAX_PATH - 1);
	strncpy(buf, fname, dir_len);
	buf[dir_len] = '\0';
}

T_DECL(check_mocks_original, "Check that the original function of all mocks is actally in the xnu lib")
{
	// Take a function that is known to be in libkernel as a reference to compare to
	Dl_info ref_info;
	T_QUIET; T_ASSERT_NE(dladdr(ORIGINAL_kernel_func8, &ref_info), 0, "dladdr(kernel_func8)");
	char ref_folder[T_MAX_PATH];
	get_folder(ref_info.dli_fname, ref_folder);

	int count = 0;
	for (struct mock_entry* me = _mock_entry_first(); me != NULL; me = me->me_next) {
		T_LOG("name: %s  original:%p  mock:%p  from: %s", me->me_name, me->me_original_func, me->me_mock_func, me->me_location);
		++count;

		// Check that the function that was found for interposing is indeed a function in one of out dylibs and not a
		// function of the same name in a system dylib.
		// If this fails it means that the a function of the same name as the one that you're trying to mock appears
		// in a different dylib and that this function obscures the one in libkernel which has __attribute__((weak))
		// Adding __mockable_strong to the original function instead of __mockable should solve this issue because
		// it makes the function in libkernel take priority, since we're linking to it first.

		// if the mock comes from a pmocks.dylib, dladdr() is going to find it in libmocks, so we only test the
		// folder of the path that it found to verify that it's just not a system dylib.
		Dl_info info;
		T_QUIET; T_EXPECT_NE(dladdr(me->me_original_func, &info), 0, "dladdr(%s)", me->me_name);
		char info_folder[T_MAX_PATH];
		get_folder(info.dli_fname, info_folder);
		T_QUIET; T_EXPECT_EQ_STR(ref_folder, info_folder, "Function `%s` mocked from the wrong dylib (%s) expected (%s). This probably means you need to use __mockable_strong", me->me_name, info.dli_fname, ref_info.dli_fname);
	}
	T_LOG("Found %d mocks", count);
}



// --------------- fake_kinit tests ---------------------------------

static uint32_t custom_kinit_at_step = FKI_USER_STEP + 1;

static void
test_custom_kinit_step_1(uint32_t step_id)
{
	assert3u(custom_kinit_at_step, ==, FKI_USER_STEP + 1);
	assert3u(custom_kinit_at_step, ==, step_id);
	custom_kinit_at_step++;
}
static void
test_custom_kinit_step_2(uint32_t step_id)
{
	assert3u(custom_kinit_at_step, ==, FKI_USER_STEP + 2);
	assert3u(custom_kinit_at_step, ==, step_id);
	custom_kinit_at_step++;
}
static void
test_custom_kinit_step_3(uint32_t step_id)
{
	assert3u(custom_kinit_at_step, ==, FKI_USER_STEP + 3);
	assert3u(custom_kinit_at_step, ==, step_id);
	custom_kinit_at_step++;
}

// Test customization function using FAKE_KINIT_CUSTOMIZE_PLAN
FAKE_KINIT_CUSTOMIZE_PLAN() {
	// Find the bootstrap step and add our custom step after it
	fki_step_t bs_step = fki_plan_find_step(^bool (fki_step_t s) {
		return s->fki_step_id == FKI_FUNC_BOOTSTRAP;
	});

	fki_plan_insert_before(bs_step, fki_plan_make_func_step(FKI_USER_STEP + 1, test_custom_kinit_step_1));
	fki_plan_insert_after(bs_step, fki_plan_make_func_step(FKI_USER_STEP + 2, test_custom_kinit_step_2));
	fki_plan_append(fki_plan_make_func_step(FKI_USER_STEP + 3, test_custom_kinit_step_3));
}

T_DECL(fake_kinit_customization_executed, "test that fake_kinit customization was executed during startup")
{
	T_ASSERT_EQ(custom_kinit_at_step, FKI_USER_STEP + 4, "custom kinit step should have been executed during startup");
}
