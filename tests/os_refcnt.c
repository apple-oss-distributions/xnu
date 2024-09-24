#include <darwintest.h>
#include <darwintest_utils.h>
#include <stdio.h>
#include <assert.h>
#include <setjmp.h>
#include <os/tsd.h>

#define DEVELOPMENT 1
#define DEBUG 0
#define XNU_KERNEL_PRIVATE 1

#define OS_REFCNT_DEBUG 1
#define STRESS_TESTS 0
#define __zpercpu

#pragma clang diagnostic ignored "-Watomic-implicit-seq-cst"
#pragma clang diagnostic ignored "-Wc++98-compat"

__abortlike
void handle_panic(const char *func, char *str, ...);
#define panic(...) handle_panic(__func__, __VA_ARGS__)

#define ZPERCPU_STRIDE 128

static inline int
zpercpu_count(void)
{
	static int n;
	if (__improbable(n == 0)) {
		n = dt_ncpu();
	}
	return n;
}

static inline void
thread_wakeup(void *event)
{
	abort();
}

#define zalloc_percpu(zone, flags) \
	(uint64_t _Atomic *)calloc((size_t)zpercpu_count(), ZPERCPU_STRIDE)

#define zfree_percpu(zone, ptr) \
	free(ptr)

static inline uint64_t _Atomic *
zpercpu_get_cpu(uint64_t _Atomic *ptr, int cpu)
{
	return (uint64_t _Atomic *)((uintptr_t)ptr + (uintptr_t)cpu * ZPERCPU_STRIDE);
}

#define zpercpu_get(ptr)  zpercpu_get_cpu(ptr, 0)

#define zpercpu_foreach_cpu(cpu) \
	for (int cpu = 0, __n = zpercpu_count(); cpu < __n; cpu++)

#define zpercpu_foreach(cpu) \
	for (int cpu = 0, __n = zpercpu_count(); cpu < __n; cpu++)

#define cpu_number() (int)_os_cpu_number()

#include "../libkern/os/refcnt.h"
#include "../libkern/os/refcnt.c"

T_GLOBAL_META(T_META_RUN_CONCURRENTLY(true));

/* import some of the refcnt internal state for testing */
extern bool ref_debug_enable;
os_refgrp_decl_extern(global_ref_group);

T_GLOBAL_META(
	T_META_NAMESPACE("os_refcnt"),
	T_META_CHECK_LEAKS(false)
	);

T_DECL(os_refcnt, "Basic atomic refcount")
{
	struct os_refcnt rc;
	os_ref_init(&rc, NULL);
	T_ASSERT_EQ_UINT(os_ref_get_count(&rc), 1, "refcount correctly initialized");

	os_ref_retain(&rc);
	os_ref_retain(&rc);
	T_ASSERT_EQ_UINT(os_ref_get_count(&rc), 3, "retain increased count");

	os_ref_count_t x = os_ref_release(&rc);
	T_ASSERT_EQ_UINT(os_ref_get_count(&rc), 2, "release decreased count");
	T_ASSERT_EQ_UINT(x, 2, "release returned correct count");

	os_ref_release_live(&rc);
	T_ASSERT_EQ_UINT(os_ref_get_count(&rc), 1, "release_live decreased count");

	x = os_ref_release(&rc);
	T_ASSERT_EQ_UINT(os_ref_get_count(&rc), 0, "released");
	T_ASSERT_EQ_UINT(x, 0, "returned released");

	os_ref_init(&rc, NULL);
	T_ASSERT_TRUE(os_ref_retain_try(&rc), "try retained");

	(void)os_ref_release(&rc);
	(void)os_ref_release(&rc);
	T_QUIET; T_ASSERT_EQ_UINT(os_ref_get_count(&rc), 0, "release");

	T_ASSERT_FALSE(os_ref_retain_try(&rc), "try failed");
}

T_DECL(os_pcpu_refcnt, "Basic atomic refcount")
{
	dispatch_queue_t rq = dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0);
	dispatch_group_t g = dispatch_group_create();
	os_pcpu_ref_t rc;

	os_pcpu_ref_init(&rc, NULL);
	T_ASSERT_EQ_UINT(os_pcpu_ref_count(rc), OS_REFCNT_MAX_COUNT,
	    "refcount correctly initialized");

	dispatch_group_async(g, rq, ^{
		os_pcpu_ref_retain(rc, NULL);
	});
	dispatch_group_async(g, rq, ^{
		T_ASSERT_TRUE(os_pcpu_ref_retain_try(rc, NULL), "try succeeded");
	});
	dispatch_group_wait(g, DISPATCH_TIME_FOREVER);

	T_ASSERT_EQ_UINT(os_pcpu_ref_count(rc), OS_REFCNT_MAX_COUNT,
	    "retain increased count");

	T_ASSERT_EQ_UINT(os_pcpu_ref_kill(rc, NULL), 2,
	    "kill decreased count");
	T_ASSERT_EQ_UINT(os_pcpu_ref_count(rc), 2,
	    "kill decreased count");

	T_ASSERT_FALSE(os_pcpu_ref_retain_try(rc, NULL), "try failed");

	os_pcpu_ref_release_live(rc, NULL);
	T_ASSERT_EQ_UINT(os_pcpu_ref_count(rc), 1, "release_live decreased count");

	T_ASSERT_EQ_UINT(os_pcpu_ref_release(rc, NULL), 0, "returned released");
	T_ASSERT_EQ_UINT(os_pcpu_ref_count(rc), 0, "released");

	os_pcpu_ref_destroy(&rc, NULL);
}

T_DECL(refcnt_raw, "Raw refcount")
{
	os_ref_atomic_t rc;
	os_ref_init_raw(&rc, NULL);
	T_ASSERT_EQ_UINT(os_ref_get_count_raw(&rc), 1, "refcount correctly initialized");

	os_ref_retain_raw(&rc, NULL);
	os_ref_retain_raw(&rc, NULL);
	T_ASSERT_EQ_UINT(os_ref_get_count_raw(&rc), 3, "retain increased count");

	os_ref_count_t x = os_ref_release_raw(&rc, NULL);
	T_ASSERT_EQ_UINT(os_ref_get_count_raw(&rc), 2, "release decreased count");
	T_ASSERT_EQ_UINT(x, 2, "release returned correct count");

	os_ref_release_live_raw(&rc, NULL);
	T_ASSERT_EQ_UINT(os_ref_get_count_raw(&rc), 1, "release_live decreased count");

	x = os_ref_release_raw(&rc, NULL);
	T_ASSERT_EQ_UINT(os_ref_get_count_raw(&rc), 0, "released");
	T_ASSERT_EQ_UINT(x, 0, "returned released");

	os_ref_init_raw(&rc, NULL);
	T_ASSERT_TRUE(os_ref_retain_try_raw(&rc, NULL), "try retained");

	(void)os_ref_release_raw(&rc, NULL);
	(void)os_ref_release_raw(&rc, NULL);
	T_QUIET; T_ASSERT_EQ_UINT(os_ref_get_count_raw(&rc), 0, "release");

	T_ASSERT_FALSE(os_ref_retain_try_raw(&rc, NULL), "try failed");
}

T_DECL(refcnt_locked, "Locked refcount")
{
	struct os_refcnt rc;
	os_ref_init(&rc, NULL);

	os_ref_retain_locked(&rc);
	os_ref_retain_locked(&rc);
	T_ASSERT_EQ_UINT(os_ref_get_count(&rc), 3, "retain increased count");

	os_ref_count_t x = os_ref_release_locked(&rc);
	T_ASSERT_EQ_UINT(os_ref_get_count(&rc), 2, "release decreased count");
	T_ASSERT_EQ_UINT(x, 2, "release returned correct count");

	(void)os_ref_release_locked(&rc);
	x = os_ref_release_locked(&rc);
	T_ASSERT_EQ_UINT(os_ref_get_count(&rc), 0, "released");
	T_ASSERT_EQ_UINT(x, 0, "returned released");
}

T_DECL(refcnt_raw_locked, "Locked raw refcount")
{
	os_ref_atomic_t rc;
	os_ref_init_raw(&rc, NULL);

	os_ref_retain_locked_raw(&rc, NULL);
	os_ref_retain_locked_raw(&rc, NULL);
	T_ASSERT_EQ_UINT(os_ref_get_count_raw(&rc), 3, "retain increased count");

	os_ref_count_t x = os_ref_release_locked_raw(&rc, NULL);
	T_ASSERT_EQ_UINT(os_ref_get_count_raw(&rc), 2, "release decreased count");
	T_ASSERT_EQ_UINT(x, 2, "release returned correct count");

	(void)os_ref_release_locked_raw(&rc, NULL);
	x = os_ref_release_locked_raw(&rc, NULL);
	T_ASSERT_EQ_UINT(os_ref_get_count_raw(&rc), 0, "released");
	T_ASSERT_EQ_UINT(x, 0, "returned released");
}

static void
do_bitwise_test(const os_ref_count_t bits)
{
	os_ref_atomic_t rc;
	os_ref_count_t reserved = 0xaaaaaaaaU & ((1U << bits) - 1);

	T_LOG("do_bitwise_test(nbits:%d, reserved:%#x)", bits, reserved);

	os_ref_init_count_mask(&rc, bits, NULL, 1, reserved);

	T_ASSERT_EQ_UINT(os_ref_get_count_mask(&rc, bits), 1, "[%u bits] refcount initialized", bits);

	os_ref_retain_mask(&rc, bits, NULL);
	os_ref_retain_mask(&rc, bits, NULL);
	T_ASSERT_EQ_UINT(os_ref_get_count_mask(&rc, bits), 3, "retain increased count");

	os_ref_count_t x = os_ref_release_mask(&rc, bits, NULL);
	T_ASSERT_EQ_UINT(x, 2, "release returned correct count");

	os_ref_release_live_mask(&rc, bits, NULL);
	T_ASSERT_EQ_UINT(os_ref_get_count_mask(&rc, bits), 1, "release_live decreased count");

	x = os_ref_release_mask(&rc, bits, NULL);
	T_ASSERT_EQ_UINT(os_ref_get_count_mask(&rc, bits), 0, "released");
	T_ASSERT_EQ_UINT(x, 0, "returned released");

	T_ASSERT_EQ_UINT(rc & ((1U << bits) - 1), reserved, "Reserved bits not modified");

	os_ref_init_count_mask(&rc, bits, NULL, 1, reserved);
	T_ASSERT_TRUE(os_ref_retain_try_mask(&rc, bits, 0, NULL), "try retained");
	if (reserved) {
		T_ASSERT_FALSE(os_ref_retain_try_mask(&rc, bits, reserved, NULL), "try reject");
	}

	(void)os_ref_release_mask(&rc, bits, NULL);
	(void)os_ref_release_mask(&rc, bits, NULL);
	T_QUIET; T_ASSERT_EQ_UINT(os_ref_get_count_mask(&rc, bits), 0, "release");

	T_ASSERT_FALSE(os_ref_retain_try_mask(&rc, bits, 0, NULL), "try fail");

	T_ASSERT_EQ_UINT(os_ref_get_bits_mask(&rc, bits), reserved, "Reserved bits not modified");
}

T_DECL(refcnt_bitwise, "Bitwise refcount")
{
	do_bitwise_test(0);
	do_bitwise_test(1);
	do_bitwise_test(8);
	do_bitwise_test(26);

	os_ref_atomic_t rc = 0xaaaaaaaa;

	const os_ref_count_t nbits = 3;
	const os_ref_count_t count = 5;
	const os_ref_count_t bits = 7;
	os_ref_init_count_mask(&rc, nbits, NULL, count, bits);

	os_ref_count_t mask = (1U << nbits) - 1;
	T_ASSERT_EQ_UINT(rc & mask, bits, "bits correctly initialized");
	T_ASSERT_EQ_UINT(rc >> nbits, count, "count correctly initialized");
}

os_refgrp_decl(static, g1, "test group", NULL);
os_refgrp_decl_extern(g1);

T_DECL(refcnt_groups, "Group accounting")
{
#if OS_REFCNT_DEBUG
	ref_debug_enable = true;

	struct os_refcnt rc;
	os_ref_init(&rc, &g1);

	T_ASSERT_EQ_UINT(g1.grp_children, 1, "group attached");
	T_ASSERT_EQ_UINT(global_ref_group.grp_children, 1, "global group attached");
	T_ASSERT_EQ_UINT(g1.grp_count, 1, "group count");
	T_ASSERT_EQ_ULLONG(g1.grp_retain_total, 1ULL, "group retains");
	T_ASSERT_EQ_ULLONG(g1.grp_release_total, 0ULL, "group releases");

	os_ref_retain(&rc);
	os_ref_retain(&rc);
	os_ref_release_live(&rc);
	os_ref_release_live(&rc);

	T_EXPECT_EQ_ULLONG(g1.grp_retain_total, 3ULL, "group retains");
	T_EXPECT_EQ_ULLONG(g1.grp_release_total, 2ULL, "group releases");

	os_ref_count_t x = os_ref_release(&rc);
	T_QUIET; T_ASSERT_EQ_UINT(x, 0, "released");

	T_ASSERT_EQ_UINT(g1.grp_children, 0, "group detatched");
	T_ASSERT_EQ_UINT(g1.grp_count, 0, "group count");
#else
	T_SKIP("Refcount debugging disabled");
#endif
}

enum {
	OSREF_UNDERFLOW    = 1,
	OSREF_OVERFLOW     = 2,
	OSREF_RETAIN       = 3,
	OSREF_DEALLOC_LIVE = 4,
};

static jmp_buf jb;
static bool expect_panic = false;

void
handle_panic(const char *func, char *__unused str, ...)
{
	int ret = -1;
	if (!expect_panic) {
		T_FAIL("unexpected panic from %s", func);
		T_LOG("corrupt program state, aborting");
		abort();
	}
	expect_panic = false;

	if (strcmp(func, "os_ref_panic_underflow") == 0) {
		ret = OSREF_UNDERFLOW;
	} else if (strcmp(func, "os_ref_panic_overflow") == 0) {
		ret = OSREF_OVERFLOW;
	} else if (strcmp(func, "os_ref_panic_retain") == 0) {
		ret = OSREF_RETAIN;
	} else if (strcmp(func, "os_ref_panic_live") == 0) {
		ret = OSREF_DEALLOC_LIVE;
	} else {
		T_LOG("unexpected panic from %s", func);
	}

	longjmp(jb, ret);
}

T_DECL(refcnt_underflow, "Underflow")
{
	os_ref_atomic_t rc;
	os_ref_init_raw(&rc, NULL);
	(void)os_ref_release_raw(&rc, NULL);

	int x = setjmp(jb);
	if (x == 0) {
		expect_panic = true;
		(void)os_ref_release_raw(&rc, NULL);
		T_FAIL("underflow not caught");
	} else {
		T_ASSERT_EQ_INT(x, OSREF_UNDERFLOW, "underflow caught");
	}
}

T_DECL(refcnt_overflow, "Overflow")
{
	os_ref_atomic_t rc;
	os_ref_init_count_raw(&rc, NULL, 0x0fffffffU);

	int x = setjmp(jb);
	if (x == 0) {
		expect_panic = true;
		(void)os_ref_retain_raw(&rc, NULL);
		T_FAIL("overflow not caught");
	} else {
		T_ASSERT_EQ_INT(x, OSREF_RETAIN, "overflow caught");
	}
}

T_DECL(refcnt_resurrection, "Resurrection")
{
	os_ref_atomic_t rc;
	os_ref_init_raw(&rc, NULL);
	os_ref_count_t n = os_ref_release_raw(&rc, NULL);

	T_QUIET; T_EXPECT_EQ_UINT(n, 0, "reference not released");

	int x = setjmp(jb);
	if (x == 0) {
		expect_panic = true;
		(void)os_ref_retain_raw(&rc, NULL);
		T_FAIL("resurrection not caught");
	} else {
		T_ASSERT_EQ_INT(x, OSREF_RETAIN, "resurrection caught");
	}
}

T_DECL(refcnt_dealloc_live, "Dealloc expected live object")
{
	os_ref_atomic_t rc;
	os_ref_init_raw(&rc, NULL);

	expect_panic = true;
	int x = setjmp(jb);
	if (x == 0) {
		expect_panic = true;
		os_ref_release_live_raw(&rc, NULL);
		T_FAIL("dealloc live not caught");
	} else {
		T_ASSERT_EQ_INT(x, OSREF_DEALLOC_LIVE, "dealloc live caught");
	}
}

T_DECL(refcnt_initializer, "Static intializers")
{
	struct os_refcnt rc = OS_REF_INITIALIZER;
	os_ref_atomic_t rca = OS_REF_ATOMIC_INITIALIZER;

	T_ASSERT_EQ_INT(0, os_ref_retain_try(&rc), NULL);
	T_ASSERT_EQ_INT(0, os_ref_get_count_raw(&rca), NULL);
}

#if STRESS_TESTS

static unsigned pcpu_perf_step = 0;

static void
worker_ref(os_ref_atomic_t *rc, unsigned long *count)
{
	unsigned long n = 0;

	while (os_atomic_load(&pcpu_perf_step, relaxed) == 0) {
	}

	while (os_atomic_load(&pcpu_perf_step, relaxed) == 1) {
		os_ref_retain_raw(rc, NULL);
		os_ref_release_live_raw(rc, NULL);
		n++;
	}

	os_atomic_add(count, n, relaxed);
}

static void
worker_pcpu_ref(os_pcpu_ref_t rc, unsigned long *count)
{
	unsigned long n = 0;

	while (os_atomic_load(&pcpu_perf_step, relaxed) == 0) {
	}

	while (os_atomic_load(&pcpu_perf_step, relaxed) == 1) {
		os_pcpu_ref_retain(rc, NULL);
		os_pcpu_ref_release_live(rc, NULL);
		n++;
	}

	os_atomic_add(count, n, relaxed);
}

#define PCPU_BENCH_LEN   2

static void
warmup_thread_pool(dispatch_group_t g, dispatch_queue_t rq)
{
	os_atomic_store(&pcpu_perf_step, 1, relaxed);

	zpercpu_foreach_cpu(cpu) {
		dispatch_group_async(g, rq, ^{
			while (os_atomic_load(&pcpu_perf_step, relaxed) == 1) {
			}
		});
	}

	os_atomic_store(&pcpu_perf_step, 0, relaxed);
	dispatch_group_wait(g, DISPATCH_TIME_FOREVER);
}

T_DECL(pcpu_perf, "Performance per-cpu")
{
	os_ref_atomic_t rc;
	os_pcpu_ref_t prc;
	__block unsigned long count = 0;
	double scale = PCPU_BENCH_LEN * 1e6;
	dispatch_queue_t rq = dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0);
	dispatch_group_t g = dispatch_group_create();

	os_ref_init_raw(&rc, NULL);
	os_pcpu_ref_init(&prc, NULL);

	T_LOG("uncontended benchmark");

	dispatch_group_async(g, rq, ^{
		worker_ref(&rc, &count);
	});

	count = 0;
	os_atomic_store(&pcpu_perf_step, 1, relaxed);
	sleep(PCPU_BENCH_LEN);
	os_atomic_store(&pcpu_perf_step, 0, relaxed);
	dispatch_group_wait(g, DISPATCH_TIME_FOREVER);

	T_PASS("%.2fM rounds per thread per second (atomic)", count / scale);

	dispatch_group_async(g, rq, ^{
		worker_pcpu_ref(prc, &count);
	});

	count = 0;
	os_atomic_store(&pcpu_perf_step, 1, relaxed);
	sleep(PCPU_BENCH_LEN);
	os_atomic_store(&pcpu_perf_step, 0, relaxed);
	dispatch_group_wait(g, DISPATCH_TIME_FOREVER);

	T_PASS("%.2fM rounds per thread per second (pcpu)", count / scale);

	T_LOG("contended benchmark");

	warmup_thread_pool(g, rq);
	zpercpu_foreach_cpu(cpu) {
		dispatch_group_async(g, rq, ^{
			worker_ref(&rc, &count);
		});
	}

	count = 0;
	os_atomic_store(&pcpu_perf_step, 1, relaxed);
	sleep(PCPU_BENCH_LEN);
	os_atomic_store(&pcpu_perf_step, 0, relaxed);
	dispatch_group_wait(g, DISPATCH_TIME_FOREVER);

	T_PASS("%.2fM rounds per thread per second (atomic)", count / (zpercpu_count() * scale));

	warmup_thread_pool(g, rq);
	zpercpu_foreach_cpu(cpu) {
		dispatch_group_async(g, rq, ^{
			worker_pcpu_ref(prc, &count);
		});
	}

	count = 0;
	os_atomic_store(&pcpu_perf_step, 1, relaxed);
	sleep(PCPU_BENCH_LEN);
	os_atomic_store(&pcpu_perf_step, 0, relaxed);
	dispatch_group_wait(g, DISPATCH_TIME_FOREVER);

	T_PASS("%.2fM rounds per thread per second (pcpu)", count / (zpercpu_count() * scale));

	(void)os_pcpu_ref_kill(prc, NULL);
	os_pcpu_ref_destroy(&prc, NULL);
}

static const unsigned long iters = 1024 * 1024 * 32;

static void *
func(void *_rc)
{
	struct os_refcnt *rc = _rc;
	for (unsigned long i = 0; i < iters; i++) {
		os_ref_retain(rc);
		os_ref_release_live(rc);
	}
	return NULL;
}

T_DECL(refcnt_stress, "Stress test")
{
	pthread_t th1, th2;

	struct os_refcnt rc;
	os_ref_init(&rc, NULL);

	T_ASSERT_POSIX_ZERO(pthread_create(&th1, NULL, func, &rc), "pthread_create");
	T_ASSERT_POSIX_ZERO(pthread_create(&th2, NULL, func, &rc), "pthread_create");

	void *r1, *r2;
	T_ASSERT_POSIX_ZERO(pthread_join(th1, &r1), "pthread_join");
	T_ASSERT_POSIX_ZERO(pthread_join(th2, &r2), "pthread_join");

	os_ref_count_t x = os_ref_release(&rc);
	T_ASSERT_EQ_INT(x, 0, "Consistent refcount");
}

#endif
