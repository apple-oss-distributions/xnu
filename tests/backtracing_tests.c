// Copyright (c) 2016-2020 Apple Computer, Inc.  All rights reserved.

#include <CoreSymbolication/CoreSymbolication.h>
#include <darwintest.h>
#include <dispatch/dispatch.h>
#include <execinfo.h>
#include <pthread.h>
#include <ptrauth.h>
#include <mach/mach.h>
#include <stdalign.h>
#include <sys/mman.h>
#include <sys/sysctl.h>

T_GLOBAL_META(T_META_RUN_CONCURRENTLY(true));

enum test_scenario {
	USER_SCENARIO = 0,
	RESUME_SCENARIO = 1,
};

#define USER_FRAMES (12)
#define MAX_SYSCALL_SETUP_FRAMES (3)
#define NON_RECURSE_FRAMES (2)
#define ASYNC_FRAMES (2 + NON_RECURSE_FRAMES)

static const char *user_bt[USER_FRAMES] = {
	"backtrace_thread",
	"recurse_a", "recurse_b", "recurse_a", "recurse_b",
	"recurse_a", "recurse_b", "recurse_a", "recurse_b",
	"recurse_a", "recurse_b", "expect_callstack",
};

struct callstack_exp {
	bool in_syscall_setup;
	unsigned int syscall_frames;
	const char **callstack;
	size_t callstack_len;
	unsigned int nchecked;
};

#if __has_feature(ptrauth_calls)
#define __ptrauth_swift_async_context_parent \
  __ptrauth(ptrauth_key_process_independent_data, 1, 0xbda2)
#define __ptrauth_swift_async_context_resume \
  __ptrauth(ptrauth_key_function_pointer, 1, 0xd707)
#else
#define __ptrauth_swift_async_context_parent
#define __ptrauth_swift_async_context_resume
#endif

// This struct fakes the Swift AsyncContext struct which is used by
// the Swift concurrency runtime. We only care about the first 2 fields.
struct fake_async_context {
	struct fake_async_context* __ptrauth_swift_async_context_parent next;
	void(*__ptrauth_swift_async_context_resume resume_pc)(void);
};

static void
level1_func()
{
}
static void
level2_func()
{
}

// Create a chain of fake async contexts
static alignas(16) struct fake_async_context level1 = { 0, level1_func };
static alignas(16) struct fake_async_context level2 = { &level1, level2_func };

static const char *async_bt[ASYNC_FRAMES] = {
	"level1_func", "level2_func", "backtrace_thread_async",
	"expect_async_callstack",
};

static void
expect_frame(struct callstack_exp *cs, CSSymbolRef symbol,
    unsigned long addr, unsigned int bt_idx)
{
	if (CSIsNull(symbol)) {
		if (!cs->in_syscall_setup) {
			T_FAIL("invalid symbol for address %#lx at frame %d", addr,
			    bt_idx);
		}
		return;
	}

	const char *name = CSSymbolGetName(symbol);
	if (name) {
		if (cs->in_syscall_setup) {
			if (strcmp(name, cs->callstack[cs->callstack_len - 1]) == 0) {
				cs->in_syscall_setup = false;
				cs->syscall_frames = bt_idx;
				T_LOG("found start of controlled stack at frame %u, expected "
				    "index %zu", cs->syscall_frames, cs->callstack_len - 1);
			} else {
				T_LOG("found syscall setup symbol %s at frame %u", name,
				    bt_idx);
			}
		}
		if (!cs->in_syscall_setup) {
			if (cs->nchecked >= cs->callstack_len) {
				T_LOG("frame %2u: skipping system frame %s", bt_idx, name);
			} else {
				size_t frame_idx = cs->callstack_len - cs->nchecked - 1;
				T_EXPECT_EQ_STR(name, cs->callstack[frame_idx],
				    "frame %2zu: saw '%s', expected '%s'",
				    frame_idx, name, cs->callstack[frame_idx]);
			}
			cs->nchecked++;
		}
	} else {
		if (!cs->in_syscall_setup) {
			T_ASSERT_NOTNULL(name, NULL, "symbol should not be NULL");
		}
	}
}

static bool
is_kernel_64_bit(void)
{
	static dispatch_once_t k64_once;
	static bool k64 = false;
	dispatch_once(&k64_once, ^{
		int errb;
		int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, 0 /* kernproc */ };

		struct kinfo_proc kp;
		size_t len = sizeof(kp);

		errb = sysctl(mib, sizeof(mib) / sizeof(mib[0]), &kp, &len, NULL, 0);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(errb,
		"sysctl({ CTL_KERN, KERN_PROC, KERN_PROC_PID, 0})");

		k64 = kp.kp_proc.p_flag & P_LP64;
		T_LOG("executing with a %s-bit kernel", k64 ? "64" : "32");
	});
	return k64;
}

// Use an extra, non-inlineable function so that any frames after expect_stack
// can be safely ignored.  This insulates the test from changes in how syscalls
// are called by Libc and the kernel.
static void __attribute__((noinline, not_tail_called))
backtrace_current_thread_wrapper(enum test_scenario scenario, uint64_t *bt,
    size_t *bt_filled)
{
	int ret = sysctlbyname("kern.backtrace.user", bt, bt_filled, NULL,
	    scenario);
	getpid(); // Really prevent tail calls.
	if (ret == -1 && errno == ENOENT) {
		T_SKIP("release kernel: kern.backtrace.user sysctl returned ENOENT");
	}
	T_ASSERT_POSIX_SUCCESS(ret, "sysctlbyname(\"kern.backtrace.user\")");
	T_LOG("kernel returned %zu frame backtrace", *bt_filled);
}

static CSSymbolicatorRef
get_symbolicator(void)
{
	static CSSymbolicatorRef user_symb;
	static dispatch_once_t expect_stack_once;
	dispatch_once(&expect_stack_once, ^{
		user_symb = CSSymbolicatorCreateWithTask(mach_task_self());
		T_QUIET; T_ASSERT_FALSE(CSIsNull(user_symb), NULL);
		T_QUIET; T_ASSERT_TRUE(CSSymbolicatorIsTaskValid(user_symb), NULL);
	});
	return user_symb;
}

static void __attribute__((noinline, not_tail_called))
expect_callstack(enum test_scenario scenario)
{
	uint64_t bt[USER_FRAMES + MAX_SYSCALL_SETUP_FRAMES] = { 0 };

	CSSymbolicatorRef user_symb = get_symbolicator();
	size_t bt_filled = USER_FRAMES + MAX_SYSCALL_SETUP_FRAMES;
	backtrace_current_thread_wrapper(scenario, bt, &bt_filled);

	unsigned int bt_len = (unsigned int)bt_filled;
	T_EXPECT_GE(bt_len, (unsigned int)USER_FRAMES,
	    "at least %u frames should be present in backtrace", USER_FRAMES);
	T_EXPECT_LE(bt_len, (unsigned int)USER_FRAMES + MAX_SYSCALL_SETUP_FRAMES,
	    "at most %u frames should be present in backtrace",
	    USER_FRAMES + MAX_SYSCALL_SETUP_FRAMES);

	struct callstack_exp callstack = {
		.in_syscall_setup = true,
		.syscall_frames = 0,
		.callstack = user_bt,
		.callstack_len = USER_FRAMES,
		.nchecked = 0,
	};
	for (unsigned int i = 0; i < bt_len; i++) {
		uintptr_t addr;
#if !defined(__LP64__)
		// Backtrace frames come out as kernel words; convert them back to user
		// uintptr_t for 32-bit processes.
		if (is_kernel_64_bit()) {
			addr = (uintptr_t)(bt[i]);
		} else {
			addr = (uintptr_t)(((uint32_t *)bt)[i]);
		}
#else // defined(__LP32__)
		addr = (uintptr_t)bt[i];
#endif // defined(__LP32__)

		CSSymbolRef symbol = CSSymbolicatorGetSymbolWithAddressAtTime(
			user_symb, addr, kCSNow);
		expect_frame(&callstack, symbol, addr, i);
	}

	T_EXPECT_GE(callstack.nchecked, USER_FRAMES,
	    "checked enough frames for correct symbols");
}

static int __attribute__((noinline, not_tail_called))
recurse_a(enum test_scenario, unsigned int frames);
static int __attribute__((noinline, not_tail_called))
recurse_b(enum test_scenario, unsigned int frames);

static int __attribute__((noinline, not_tail_called))
recurse_a(enum test_scenario scenario, unsigned int frames)
{
	if (frames == 1) {
		expect_callstack(scenario);
		getpid(); // Really prevent tail calls.
		return 0;
	}

	return recurse_b(scenario, frames - 1) + 1;
}

static int __attribute__((noinline, not_tail_called))
recurse_b(enum test_scenario scenario, unsigned int frames)
{
	if (frames == 1) {
		expect_callstack(scenario);
		getpid(); // Really prevent tail calls.
		return 0;
	}

	return recurse_a(scenario, frames - 1) + 1;
}

static void __attribute__((noinline, not_tail_called))
expect_async_callstack(void)
{
	uint64_t bt[ASYNC_FRAMES + MAX_SYSCALL_SETUP_FRAMES] = { 0 };

	CSSymbolicatorRef user_symb = get_symbolicator();
	size_t bt_filled = ASYNC_FRAMES + MAX_SYSCALL_SETUP_FRAMES;
	backtrace_current_thread_wrapper(USER_SCENARIO, bt, &bt_filled);

	unsigned int bt_len = (unsigned int)bt_filled;
	T_EXPECT_GE(bt_len, (unsigned int)ASYNC_FRAMES,
	    "at least %u frames should be present in backtrace", ASYNC_FRAMES);
	T_EXPECT_LE(bt_len, (unsigned int)ASYNC_FRAMES + MAX_SYSCALL_SETUP_FRAMES,
	    "at most %u frames should be present in backtrace",
	    ASYNC_FRAMES + MAX_SYSCALL_SETUP_FRAMES);

	struct callstack_exp callstack = {
		.in_syscall_setup = true,
		.syscall_frames = 0,
		.callstack = async_bt,
		.callstack_len = ASYNC_FRAMES,
		.nchecked = 0,
	};
	for (unsigned int i = 0; i < bt_len; i++) {
		uintptr_t addr;
#if !defined(__LP64__)
		// Backtrace frames come out as kernel words; convert them back to user
		// uintptr_t for 32-bit processes.
		if (is_kernel_64_bit()) {
			addr = (uintptr_t)(bt[i]);
		} else {
			addr = (uintptr_t)(((uint32_t *)bt)[i]);
		}
#else // defined(__LP32__)
		addr = (uintptr_t)bt[i];
#endif // defined(__LP32__)

		CSSymbolRef symbol = CSSymbolicatorGetSymbolWithAddressAtTime(
			user_symb, addr, kCSNow);
		expect_frame(&callstack, symbol, addr, i);
	}

	T_EXPECT_GE(callstack.nchecked, ASYNC_FRAMES,
	    "checked enough frames for correct symbols");
}

static void *
backtrace_thread_async(void * __unused arg)
{
	uint64_t *fp = __builtin_frame_address(0);
	// We cannot use a variable of pointer type, because this ABI is valid
	// on arm64_32 where pointers are 32bits, but the context pointer will
	// still be stored in a 64bits slot on the stack.
#if __has_feature(ptrauth_calls)
#define __stack_context_auth __ptrauth(ptrauth_key_process_dependent_data, 1, \
	        0xc31a)
	struct fake_async_context * __stack_context_auth ctx = &level2;
#else // __has_feature(ptrauth_calls)
	/* struct fake_async_context * */uint64_t ctx  = (uintptr_t)&level2;
#endif // !__has_feature(ptrauth_calls)

	// The signature of an async frame on the OS stack is:
	// [ <AsyncContext address>, <Saved FP | (1<<60)>, <return address> ]
	// The Async context must be right before the saved FP on the stack. This
	// should happen naturally in an optimized build as it is the only
	// variable on the stack.
	// This function cannot use T_ASSERT_* becuse it changes the stack
	// layout.
	assert((uintptr_t)fp - (uintptr_t)&ctx == 8);

	// Modify the saved FP on the stack to include the async frame marker
	*fp |= (0x1ULL << 60);
	expect_async_callstack();
	return NULL;
}

static void *
backtrace_thread(void *arg)
{
	unsigned int calls;
	enum test_scenario scenario = (enum test_scenario)arg;

	// backtrace_thread, recurse_a, recurse_b, ..., __sysctlbyname
	//
	// Always make one less call for this frame (backtrace_thread).
	calls = USER_FRAMES - NON_RECURSE_FRAMES;

	T_LOG("backtrace thread calling into %d frames (already at %d frames)",
	    calls, NON_RECURSE_FRAMES);
	(void)recurse_a(scenario, calls);
	return NULL;
}

T_DECL(backtrace_user, "test that the kernel can backtrace user stacks",
    T_META_CHECK_LEAKS(false), T_META_ALL_VALID_ARCHS(true))
{
	pthread_t thread;

	// Run the test from a different thread to insulate it from libdarwintest
	// setup.
	T_QUIET; T_ASSERT_POSIX_ZERO(pthread_create(&thread, NULL, backtrace_thread,
	    (void *)USER_SCENARIO), "create additional thread to backtrace");

	T_QUIET; T_ASSERT_POSIX_ZERO(pthread_join(thread, NULL), NULL);
}

T_DECL(backtrace_user_bounds,
    "test that the kernel doesn't write frames out of expected bounds")
{
	uint64_t bt_init[USER_FRAMES] = {};
	size_t bt_filled = USER_FRAMES, bt_filled_after = 0;
	int error = 0;
	kern_return_t kr = KERN_FAILURE;
	void *bt_page = NULL;
	void *guard_page = NULL;
	void *bt_start = NULL;

	// The backtrace addresses come back as kernel words.
	size_t kword_size = is_kernel_64_bit() ? 8 : 4;

	// Get an idea of how many frames to expect.
	int ret = sysctlbyname("kern.backtrace.user", bt_init, &bt_filled, NULL, 0);
	if (ret == -1 && errno == ENOENT) {
		T_SKIP("release kernel: kern.backtrace.user missing");
	}
	T_ASSERT_POSIX_SUCCESS(error, "sysctlbyname(\"kern.backtrace.user\")");

	// Allocate two pages -- a first one that's valid and a second that
	// will be non-writeable to catch a copyout that's too large.
	bt_page = mmap(NULL, vm_page_size * 2, PROT_READ | PROT_WRITE,
	    MAP_ANON | MAP_PRIVATE, -1, 0);
	T_WITH_ERRNO;
	T_ASSERT_NE(bt_page, MAP_FAILED, "allocated backtrace pages");
	guard_page = (char *)bt_page + vm_page_size;

	error = mprotect(guard_page, vm_page_size, PROT_READ);
	T_ASSERT_POSIX_SUCCESS(error, "mprotect(..., PROT_READ) guard page");

	// Ensure the pages are set up as expected.
	kr = vm_write(mach_task_self(), (vm_address_t)bt_page,
	    (vm_offset_t)&(int){ 12345 }, sizeof(int));
	T_ASSERT_MACH_SUCCESS(kr,
	    "should succeed in writing to backtrace page");
	kr = vm_write(mach_task_self(), (vm_address_t)guard_page,
	    (vm_offset_t)&(int){ 12345 }, sizeof(int));
	T_ASSERT_NE(kr, KERN_SUCCESS, "should fail to write to guard page");

	// Ask the kernel to write the backtrace just before the guard page.
	bt_start = (char *)guard_page - (kword_size * bt_filled);
	bt_filled_after = bt_filled;

	error = sysctlbyname("kern.backtrace.user", bt_start, &bt_filled_after,
	    NULL, 0);
	T_EXPECT_POSIX_SUCCESS(error,
	    "sysctlbyname(\"kern.backtrace.user\") just before guard page");
	T_EXPECT_EQ(bt_filled, bt_filled_after,
	    "both calls to backtrace should have filled in the same number of "
	    "frames");

	// Expect the kernel to fault when writing too far.
	bt_start = (char *)bt_start + 1;
	bt_filled_after = bt_filled;
	error = sysctlbyname("kern.backtrace.user", bt_start, &bt_filled_after,
	    (void *)USER_SCENARIO, 0);
	T_EXPECT_POSIX_FAILURE(error, EFAULT,
	    "sysctlbyname(\"kern.backtrace.user\") should fault one byte into "
	    "guard page");
}

T_DECL(backtrace_user_async,
    "test that the kernel can backtrace user async stacks",
    T_META_CHECK_LEAKS(false), T_META_ALL_VALID_ARCHS(false))
{
#if !defined(__LP64__)
	T_SKIP("unsupported on LP32");
#else // __LP32__
	pthread_t thread;
	// Run the test from a different thread to insulate it from libdarwintest
	// setup.
	T_QUIET; T_ASSERT_POSIX_ZERO(pthread_create(&thread, NULL,
	    backtrace_thread_async, NULL),
	    "create additional thread to backtrace");

	T_QUIET; T_ASSERT_POSIX_ZERO(pthread_join(thread, NULL), NULL);
#endif // !__LP32__
}

T_DECL(backtrace_user_resume,
    "test that the kernel can resume a backtrace into a smaller buffer",
    T_META_CHECK_LEAKS(false), T_META_ALL_VALID_ARCHS(false))
{
	pthread_t thread;
	T_QUIET; T_ASSERT_POSIX_ZERO(pthread_create(&thread, NULL, backtrace_thread,
	    (void *)RESUME_SCENARIO), "create additional thread to backtrace");
	T_QUIET; T_ASSERT_POSIX_ZERO(pthread_join(thread, NULL), NULL);
}

#pragma mark - utilities

static void __attribute__((noinline, not_tail_called))
spin_forever(void)
{
	while (true) {
		;
	}
}

static void
check_stack(uintptr_t fp, uintptr_t ctx)
{
	if ((fp - ctx) != 0x8) {
		fprintf(stderr, "stack frame is not set up properly: "
		    "%#lx, %#lx is %lx bytes away\n", fp, ctx, fp - ctx);
		exit(1);
	}
}

static void __attribute__((noinline, not_tail_called))
spin_backtrace_async(void)
{
	uint64_t *fp = __builtin_frame_address(0);
#if __has_feature(ptrauth_calls)
	struct fake_async_context * __stack_context_auth ctx = &level2;
#else // __has_feature(ptrauth_calls)
	/* struct fake_async_context * */uint64_t ctx  = (uintptr_t)&level2;
#endif // !__has_feature(ptrauth_calls)
	check_stack((uintptr_t)fp, (uintptr_t)&ctx);
	*fp |= (0x1ULL << 60);

	spin_forever();
}

T_DECL(backtrace_user_async_spin_forever,
    "try spinning forever with an async call stack set up",
    T_META_ENABLED(false), T_META_CHECK_LEAKS(false),
    T_META_ALL_VALID_ARCHS(false))
{
#if !defined(__LP64__)
	T_SKIP("unsupported on LP32");
#else // __LP32__
	spin_backtrace_async();
#endif // !__LP32__
}
