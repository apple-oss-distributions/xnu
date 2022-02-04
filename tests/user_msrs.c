#include <machine/cpu_capabilities.h>
#include <os/thread_self_restrict.h>
#include <libkern/OSCacheControl.h>
#include <sys/time.h>
#include <darwintest.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <ptrauth.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>


#define NUM_THREADS             256

T_GLOBAL_META(T_META_RUN_CONCURRENTLY(true));


#if defined(__arm64__) && defined(__LP64__)

enum msr_op_reason {
	msr_get_name, // -> const char *name
	msr_read,     // -> uint64_t val
	msr_write,    // <- uint64_t val
};

typedef void (*msr_op)(enum msr_op_reason why, void *param);

static pthread_mutex_t threads_please_die_lock = PTHREAD_MUTEX_INITIALIZER;
static volatile bool did_fault;
static bool threads_please_die;


static void*
thread_func(void *param)
{
	bool die;

	(void)param;

	do {
		pthread_mutex_lock(&threads_please_die_lock);
		die = threads_please_die;
		pthread_mutex_unlock(&threads_please_die_lock);
	} while (!die);

	return NULL;
}

static void
msr_test(msr_op op)
{
	struct timeval time_start, time_end, time_passed;
	uint64_t val, new_val, wrote_val;
	pthread_t threads[NUM_THREADS];
	bool readable, writeable;
	const char *reg_name;
	int i;

	op(msr_get_name, &reg_name);
	T_LOG("sub-test '%s'\n", reg_name);

	//let's see if we can read and write it
	did_fault = false;
	op(msr_read, &val);
	readable = !did_fault;

	did_fault = false;
	op(msr_write, &val);
	writeable = !did_fault;

	T_LOG("\tcan read: %s\n", readable ? "YES" : "NO");
	T_LOG("\tcan write: %s\n", writeable ? "YES" : "NO");
	if (readable) {
		T_LOG("\tvalue found: 0x%016llx\n", (unsigned long long)val);
	}

	if (!readable || !writeable) {
		T_LOG("\t RW needed for more testing. no further testing will be performed\n");
		return;
	}

	//write inverse of what we read and see if the read differs
	wrote_val = ~val;
	op(msr_write, &wrote_val);
	op(msr_read, &new_val);

	if (new_val == val) {
		T_LOG("\t reg seems to not take writes (0x%016llx). no further testing will be performed\n", val);
		return;
	}
	T_LOG("\twrote 0x%016llx, saw 0x%016llx\n", (unsigned long long)wrote_val, (unsigned long long)new_val);
	wrote_val = new_val;

	//verify it flips to original value at context switch or otherwise
	//for context switch to happen, spin up a lot of threads
	pthread_mutex_lock(&threads_please_die_lock);
	threads_please_die = false;
	pthread_mutex_unlock(&threads_please_die_lock);
	for (i = 0; i < NUM_THREADS; i++) {
		if (pthread_create(threads + i, NULL, thread_func, NULL)) {
			T_ASSERT_FAIL("cannot create thread %d\n", i);
		}
	}

	gettimeofday(&time_start, NULL);
	while (1) {
		op(msr_read, &new_val);
		if (new_val != wrote_val) {
			T_LOG("\tvalue reverted to 0x%016llx from 0x%016llx\n", (unsigned long long)new_val, (unsigned long long)wrote_val);
			break;
		}

		gettimeofday(&time_end, NULL);
		timersub(&time_end, &time_start, &time_passed);
		if (time_passed.tv_sec) { //wait one second at most
			T_FAIL("\ttoo long for register to be cleared, last read value was 0x%016llx, expected revert to 0x%016llx!", (unsigned long long)new_val, (unsigned long long)val);
			break;
		}
	}
	pthread_mutex_lock(&threads_please_die_lock);
	threads_please_die = true;
	pthread_mutex_unlock(&threads_please_die_lock);
	for (i = 0; i < NUM_THREADS; i++) {
		if (pthread_join(threads[i], NULL)) {
			T_ASSERT_FAIL("cannot join thread %d\n", i);
		}
	}
}

static void
msr_test_1(enum msr_op_reason why, void *param)
{
	switch (why) {
	case msr_get_name:
		*(const char **)param = "S3_5_C15_C1_4";
		break;

	case msr_read:
		*(uint64_t*)param = __builtin_arm_rsr64("S3_5_C15_C1_4");
		break;

	case msr_write:
		__builtin_arm_wsr64("S3_5_C15_C1_4", *(const uint64_t*)param);
		break;
	}
}

static void
msr_test_2(enum msr_op_reason why, void *param)
{
	switch (why) {
	case msr_get_name:
		*(const char **)param = "S3_5_C15_C10_1";
		break;

	case msr_read:
		*(uint64_t*)param = __builtin_arm_rsr64("S3_5_C15_C10_1");
		break;

	case msr_write:
		__builtin_arm_wsr64("S3_5_C15_C10_1", *(const uint64_t*)param);
		break;
	}
}

static void
msr_test_3(enum msr_op_reason why, void *param)
{
	switch (why) {
	case msr_get_name:
		*(const char **)param = "TPIDRRO_EL0";
		break;

	case msr_read:
		*(uint64_t*)param = __builtin_arm_rsr64("TPIDRRO_EL0");
		break;

	case msr_write:
		__builtin_arm_wsr64("TPIDRRO_EL0", *(const uint64_t*)param);
		break;
	}
}

static void
msr_test_4(enum msr_op_reason why, void *param)
{
	switch (why) {
	case msr_get_name:
		*(const char **)param = "TPIDR_EL1";
		break;

	case msr_read:
		*(uint64_t*)param = __builtin_arm_rsr64("TPIDR_EL1");
		break;

	case msr_write:
		__builtin_arm_wsr64("TPIDR_EL1", *(const uint64_t*)param);
		break;
	}
}

static void
sig_caught(int signo, siginfo_t *sinfop, void *ucontext)
{
	_STRUCT_MCONTEXT64 *ctx = ((ucontext_t *)ucontext)->uc_mcontext;
	void (*pc)(void);
	uint32_t instr;

	(void)sinfop;

	if (signo != SIGILL) {
		T_ASSERT_FAIL("We did not expect signal %d", signo);
	}

	pc = (void (*)(void))__darwin_arm_thread_state64_get_pc(ctx->__ss);
	instr = *(uint32_t*)pc;

	if ((instr & 0xffd00000) != 0xd5100000) {
		T_ASSERT_FAIL("We did not expect SIGILL on an instr that is not an MSR/MRS");
	}

	pc = (void (*)(void))(((uintptr_t)pc) + 4);
	pc = ptrauth_sign_unauthenticated(pc, ptrauth_key_function_pointer, 0);

	did_fault = true;

	// skip the instruction
	__darwin_arm_thread_state64_set_pc_fptr(ctx->__ss, pc);
}

static bool
is_release_kernel(void)
{
/*
 *       I apologize to anyone reading this code!! I promise you that I felt
 *       as dirty writing this as you do reading this. I asked in the proper
 *       channels, but nobody had a good idea how to detect a release kernel
 *       from userspace. Sadly, we need that here as the mitigations at hand
 *       are only applied in RELEASE builds. Again: I am sorry.
 */
	char ver_str[1024] = {};
	size_t len = sizeof(ver_str) - 1;

	(void)sysctlbyname("kern.version", ver_str, &len, NULL, 0);

	return !!strstr(ver_str, "/RELEASE_ARM64");
}

#endif // defined(__arm64__) && defined(__LP64__)

T_DECL(user_msrs, "Userspace MSR access test")
{
#if defined(__arm64__) && defined(__LP64__)
	if (is_release_kernel()) {
		struct sigaction sa_old, sa_new = {.__sigaction_u = { .__sa_sigaction = sig_caught, }, .sa_flags = SA_SIGINFO, };

		sigaction(SIGILL, &sa_new, &sa_old);
		msr_test(msr_test_1);
		msr_test(msr_test_2);
		msr_test(msr_test_3);
		msr_test(msr_test_4);
		//todo: macro autogen all of them
		sigaction(SIGILL, &sa_old, NULL);

		T_PASS("Userspace MSR access test passed");
	} else {
		T_PASS("Userspace MSR access test only runs on release kernels");
	}
#else // defined(__arm64__) && defined(__LP64__)
	T_SKIP("userspace MSR access test skipped - not ARM64.64");
#endif // defined(__arm64__) && defined(__LP64__)
}
