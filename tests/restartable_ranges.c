#include <darwintest.h>
#include <kern/restartable.h>
#include <mach/mach.h>
#include <mach/task.h>
#include <os/atomic_private.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <unistd.h>
#include <dispatch/dispatch.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("all"),
	T_META_RUN_CONCURRENTLY(true));

extern task_restartable_range_t ranges[2];
static int step = 0;

extern void restartable_function(int *);

#if defined(__x86_64__)
__asm__("    .align 4\n"
        "    .text\n"
        "    .private_extern _restartable_function\n"
        "_restartable_function:\n"
        "    incl   (%rdi)\n"
        "1:\n"
        "    pause\n"
        "    jmp 1b\n"
        "LExit_restartable_function:\n"
        "    ret\n");
#elif defined(__arm64__)
__asm__("    .align 4\n"
        "    .text\n"
        "    .private_extern _restartable_function\n"
        "_restartable_function:\n"
        "    ldr    x11, [x0]\n"
        "    add    x11, x11, #1\n"
        "    str    x11, [x0]\n"
        "1:\n"
        "    b 1b\n"
        "LExit_restartable_function:\n"
        "    ret\n");
#else
#define SKIP_TEST 1
#endif

extern uint64_t __thread_selfid(void);
extern void fake_msgSend(void * _Nullable);

#if defined(__x86_64__)
__asm__("    .align 4\n"
        "    .text\n"
        "    .private_extern _fake_msgSend\n"
        "_fake_msgSend:\n"
        "    movq   (%rdi), %rax\n"             /* load isa */
        "1:\n"
        "    movq   16(%rax), %rcx\n"           /* load buckets */
        "    movq   (%rcx), %rcx\n"             /* load selector */
        "LRecover_fake_msgSend:\n"
        "    jmp    1b\n"
        "LExit_fake_msgSend:\n"
        "    ret\n");
#elif defined(__arm64__)
__asm__("    .align 4\n"
        "    .text\n"
        "    .private_extern _fake_msgSend\n"
        "_fake_msgSend:\n"
        "    ldr    x16, [x0]\n"                /* load isa */
        "1:\n"
#if __LP64__
        "    ldr    x11, [x16, #16]\n"          /* load buckets */
#else
        "    ldr    x11, [x16, #8]\n"           /* load buckets */
#endif
        "    ldr    x17, [x11]\n"               /* load selector */
        "LRecover_fake_msgSend:\n"
        "    b      1b\n"
        "LExit_fake_msgSend:\n"
        "    ret\n");
#else
#define SKIP_TEST 1
#endif

#ifndef SKIP_TEST

__asm__("    .align 4\n"
        "    .data\n"
        "    .private_extern _ranges\n"
        "_ranges:\n"
#if __LP64__
        "    .quad _restartable_function\n"
#else
        "    .long _restartable_function\n"
        "    .long 0\n"
#endif
        "    .short LExit_restartable_function - _restartable_function\n"
        "    .short LExit_restartable_function - _restartable_function\n"
        "    .long 0\n"
        "\n"
#if __LP64__
        "    .quad _fake_msgSend\n"
#else
        "    .long _fake_msgSend\n"
        "    .long 0\n"
#endif
        "    .short LExit_fake_msgSend - _fake_msgSend\n"
        "    .short LRecover_fake_msgSend - _fake_msgSend\n"
        "    .long 0\n");

static void
noop_signal(int signo __unused)
{
}

static void *
task_restartable_ranges_thread(void *_ctx)
{
	int *stepp = _ctx;
	restartable_function(stepp); // increments step
	T_PASS("was successfully restarted\n");
	(*stepp)++;
	return NULL;
}

static void
wait_for_step(int which)
{
	for (int i = 0; step != which && i < 10; i++) {
		usleep(100000);
	}
}

#endif

T_DECL(task_restartable_ranges, "test task_restartable_ranges")
{
#ifdef SKIP_TEST
	T_SKIP("Not supported");
#else
	kern_return_t kr;
	pthread_t th;
	int rc;

	signal(SIGUSR1, noop_signal);

	kr = task_restartable_ranges_register(mach_task_self(), ranges, 2);
	T_ASSERT_MACH_SUCCESS(kr, "task_restartable_ranges_register");

	{
		rc = pthread_create(&th, NULL, &task_restartable_ranges_thread, &step);
		T_ASSERT_POSIX_SUCCESS(rc, "pthread_create");

		wait_for_step(1);
		T_ASSERT_EQ(step, 1, "The thread started (sync)");

		kr = task_restartable_ranges_synchronize(mach_task_self());
		T_ASSERT_MACH_SUCCESS(kr, "task_restartable_ranges_synchronize");

		T_LOG("wait for the function to be restarted (sync)");
		wait_for_step(2);
		T_ASSERT_EQ(step, 2, "The thread exited (sync)");
		pthread_join(th, NULL);
	}

	{
		rc = pthread_create(&th, NULL, &task_restartable_ranges_thread, &step);
		T_ASSERT_POSIX_SUCCESS(rc, "pthread_create");

		wait_for_step(3);
		T_ASSERT_EQ(step, 3, "The thread started (signal)");

		rc = pthread_kill(th, SIGUSR1);
		T_ASSERT_POSIX_SUCCESS(rc, "pthread_kill");

		T_LOG("wait for the function to be restarted (signal)");
		wait_for_step(4);
		T_ASSERT_EQ(step, 4, "The thread exited (signal)");
		pthread_join(th, NULL);
	}
#endif
}

#ifndef SKIP_TEST

#define N_BUCKETS 4
struct bucket {
	char buf[PAGE_MAX_SIZE] __attribute__((aligned(PAGE_MAX_SIZE)));
};

static struct bucket arena[N_BUCKETS];
static size_t arena_cur = 1;

static void *cls[5] = { 0, 0, &arena[0], 0, 0 }; /* our fake objc Class */
static void *obj[4] = { cls, 0, 0, 0, };         /* our fake objc object */

static volatile long syncs = 1;

static void *
arena_alloc(void)
{
	struct bucket *p = &arena[arena_cur++ % N_BUCKETS];

	T_QUIET; T_ASSERT_POSIX_SUCCESS(mprotect(p, PAGE_MAX_SIZE,
	    PROT_READ | PROT_WRITE), "arena_alloc");

	return p;
}

static void
arena_free(void *p)
{
	T_QUIET; T_ASSERT_POSIX_SUCCESS(mprotect(p, PAGE_MAX_SIZE,
	    PROT_NONE), "arena_free");
}

static void
task_restartable_ranges_race_fail(int signo)
{
	T_FAIL("test crashed with signal %s after %d syncs",
	    strsignal(signo), syncs);
	T_END;
}

#endif

T_DECL(task_restartable_ranges_race, "test for 88873668")
{
#ifdef SKIP_TEST
	T_SKIP("Not supported");
#else
	kern_return_t kr;
	pthread_t th;
	void *old;
	int rc;

	signal(SIGBUS, task_restartable_ranges_race_fail);

	kr = task_restartable_ranges_register(mach_task_self(), ranges, 2);
	T_ASSERT_MACH_SUCCESS(kr, "task_restartable_ranges_register");

	dispatch_async_f(dispatch_get_global_queue(QOS_CLASS_BACKGROUND, 0),
	    obj, fake_msgSend);

	T_QUIET; T_ASSERT_POSIX_SUCCESS(mprotect(&arena[1],
	    (N_BUCKETS - 1) * PAGE_MAX_SIZE, PROT_NONE), "arena_init");

	long step  = 16 << 10;
	long count = 16;

	for (syncs = 1; syncs <= count * step; syncs++) {
		/*
		 * Simulate obj-c's algorithm:
		 *
		 * 1. allocate a new bucket
		 * 2. publish it
		 * 3. synchronize
		 * 4. dealloc the old bucket
		 */
		old = os_atomic_xchg(&cls[2], arena_alloc(), release);

		kr = task_restartable_ranges_synchronize(mach_task_self());
		if (kr != KERN_SUCCESS) {
			T_FAIL("task_restartable_ranges_register failed");
			T_END;
		}

		if (syncs % step == 0) {
			T_LOG("%d/%d", syncs / step, count);
		}

		arena_free(old);
	}

	T_PASS("survived without crashing");
#endif
}
