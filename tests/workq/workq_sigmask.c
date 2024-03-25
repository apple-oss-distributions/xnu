#include <pthread.h>
#include <signal.h>
#include <darwintest.h>
#include <dispatch/dispatch.h>

// For BSDTHREAD_CTL_WORKQ_PRESERVE_SIGMASK
#define __PTHREAD_EXPOSE_INTERNALS__
#include <pthread/bsdthread_private.h>
#undef __PTHREAD_EXPOSE_INTERNALS__

extern int __bsdthread_ctl(uintptr_t cmd, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3);

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.workq"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("workq"),
	T_META_RUN_CONCURRENTLY(true));

T_DECL(invalid_allow_sigmask, "test that BSDTHREAD_CTL_WORKQ_ALLOW_SIGMASK returns EINVAL for things like SIGKILL")
{
	int ret = __bsdthread_ctl(BSDTHREAD_CTL_WORKQ_ALLOW_SIGMASK, sigmask(SIGKILL), 0, 0);
	T_ASSERT_EQ(ret, -1, "BSDTHREAD_CTL_WORKQ_ALLOW_SIGMASK should not work on prohibited signals");
}

static void
print_sigmask(void)
{
	sigset_t omask;
	sigprocmask(0, NULL, &omask);
	T_LOG("sigmask is %x\n", omask);
}


T_DECL(preserve_sigmask_unblock, "test that BSDTHREAD_CTL_WORKQ_ALLOW_SIGMASK preserves unblocking SIGUSR1 on a workq thread")
{
	__block int ret;
	const int sig = SIGUSR1;
	const sigset_t mask = sigmask(sig);
	const sigset_t expected = 0;

	dispatch_queue_t q = dispatch_get_global_queue(0, 0);
	dispatch_async(q, ^{
		T_WITH_ERRNO;
		ret = __bsdthread_ctl(BSDTHREAD_CTL_WORKQ_ALLOW_SIGMASK, mask, 0, 0);
		T_ASSERT_POSIX_SUCCESS(ret, "BSDTHREAD_CTL_WORKQ_ALLOW_SIGMASK");

		print_sigmask();

		T_WITH_ERRNO;
		ret = sigprocmask(SIG_UNBLOCK, &mask, NULL);
		T_ASSERT_POSIX_SUCCESS(ret, "sigprocmask");

		print_sigmask();

		sigset_t omask;
		T_WITH_ERRNO;
		ret = sigprocmask(0, NULL, &omask);
		T_ASSERT_POSIX_SUCCESS(ret, "sigprocmask");
		T_ASSERT_EQ(omask & mask, expected, "Is the mask right?");
	});

	// This should park the workq, and hopefully use it again
	dispatch_time_t sec = dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC);
	dispatch_after(sec, q, ^{
		print_sigmask();

		sigset_t omask;
		T_WITH_ERRNO;
		ret = sigprocmask(0, NULL, &omask);
		T_ASSERT_POSIX_SUCCESS(ret, "sigprocmask");
		T_ASSERT_EQ(omask & mask, expected, "Was mask preserved across park?");
		T_END;
	});
	dispatch_main();
}

static volatile bool handled;

static void
handler(int signum)
{
	T_ASSERT_EQ(signum, SIGUSR2, "did we get the signal we expected?");
	handled = true;
}

T_DECL(sigmask_signallable, "test that a workq thread can be signalled after BSDTHREAD_CTL_WORKQ_ALLOW_SIGMASK")
{
	__block int ret;
	const int sig = SIGUSR2;
	const sigset_t mask = sigmask(sig);

	T_ASSERT_FALSE(handled, "make sure our static bool is sane");

	// Set up handler
	struct sigaction action = {
		.sa_handler = handler,
	};
	ret = sigaction(sig, &action, NULL);
	T_ASSERT_POSIX_SUCCESS(ret, "sigaction");

	// Enable signal for workq threads
	T_WITH_ERRNO;
	ret = __bsdthread_ctl(BSDTHREAD_CTL_WORKQ_ALLOW_SIGMASK, mask, 0, 0);
	T_ASSERT_POSIX_SUCCESS(ret, "BSDTHREAD_CTL_WORKQ_ALLOW_SIGMASK");

	// Set sigmask
	dispatch_queue_t q = dispatch_get_global_queue(0, 0);
	dispatch_async(q, ^{
		print_sigmask();

		T_WITH_ERRNO;
		ret = sigprocmask(SIG_UNBLOCK, &mask, NULL);
		T_ASSERT_POSIX_SUCCESS(ret, "sigprocmask");

		print_sigmask();
	});

	sleep(1);

	// Get workq and signal it
	dispatch_async(q, ^{
		T_WITH_ERRNO;
		ret = pthread_kill(pthread_self(), sig);
		T_ASSERT_POSIX_SUCCESS(ret, "pthread_kill");
	});

	sleep(2);

	// Check delivery
	T_ASSERT_TRUE(handled, "signal should have been handled");
}
