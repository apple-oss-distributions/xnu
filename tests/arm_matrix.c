/*
 * Copyright (c) 2019 Apple Computer, Inc. All rights reserved.
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
/**
 * On devices that support it, this test ensures that a mach exception is
 * generated when a matrix-math exception is triggered, and that the
 * matrix register file is correctly preserved or zeroed on context switch.
 */

/*
 * IMPLEMENTATION NOTE:
 *
 * This test code goes to some unusual lengths to avoid calling out to libc or
 * libdarwintest while the CPU is in streaming SVE mode (i.e., between
 * ops->start() and ops->stop()).  Both of these libraries are built with SIMD
 * instructions that will cause the test executable to crash while in streaming
 * SVE mode.
 *
 * Ordinarily this is the wrong way to solve this problem.  Functions that use
 * streaming SVE mode should have annotations telling the compiler so, and the
 * compiler will automatically generate appropriate interworking code.  However
 * this interworking code will stash SME state to memory and temporarily exit
 * streaming SVE mode.  We're specifically testing how xnu manages live SME
 * register state, so we can't let the compiler stash and disable this state
 * behind our backs.
 */

#ifdef __arm64__
#include <mach/error.h>
#endif /* __arm64__ */

#include <darwintest.h>
#include <pthread.h>
#include <stdlib.h>
#include <mach/mach.h>
#include <mach/thread_status.h>
#include <mach/exception.h>
#include <machine/cpu_capabilities.h>
#include <sys/types.h>
#include <sys/sysctl.h>

#include "arm_matrix.h"
#include "exc_helpers.h"
#include "test_utils.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.arm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("arm"),
	T_META_OWNER("ghackmann"),
	T_META_RUN_CONCURRENTLY(true)
	);

#ifdef __arm64__

#ifndef EXC_ARM_SME_DISALLOWED
#define EXC_ARM_SME_DISALLOWED 2
#endif

/* Whether we caught the EXC_BAD_INSTRUCTION mach exception or not. */
static volatile bool mach_exc_caught = false;

static size_t
bad_instruction_exception_handler(
	__unused mach_port_t task,
	__unused mach_port_t thread,
	exception_type_t type,
	mach_exception_data_t codes)
{
	T_QUIET; T_ASSERT_EQ(type, EXC_BAD_INSTRUCTION, "Caught an EXC_BAD_INSTRUCTION exception");
	T_QUIET; T_ASSERT_EQ(codes[0], (uint64_t)EXC_ARM_UNDEFINED, "The subcode is EXC_ARM_UNDEFINED");

	mach_exc_caught = true;
	return 4;
}
#endif


#ifdef __arm64__
static void
test_matrix_not_started(const struct arm_matrix_operations *ops)
{
	if (!ops->is_available()) {
		T_SKIP("Running on non-%s target, skipping...", ops->name);
	}

	mach_port_t exc_port = create_exception_port(EXC_MASK_BAD_INSTRUCTION);

	size_t size = ops->data_size();
	uint8_t *d = ops->alloc_data();
	bzero(d, size);

	ops->start();
	ops->load_one_vector(d);
	ops->stop();
	T_PASS("%s instruction after start instruction should not cause an exception", ops->name);

	mach_exc_caught = false;
	run_exception_handler(exc_port, bad_instruction_exception_handler);
	ops->load_one_vector(d);
	T_EXPECT_TRUE(mach_exc_caught, "%s instruction before start instruction should cause an exception", ops->name);

	free(d);
}
#endif


T_DECL(sme_not_started,
    "Test that SME instructions before smstart generate mach exceptions.", T_META_TAG_VM_NOT_ELIGIBLE)
{
#ifndef __arm64__
	T_SKIP("Running on non-arm64 target, skipping...");
#else
	test_matrix_not_started(&sme_operations);
#endif
}

#ifdef __arm64__
typedef bool (*thread_fn_t)(const struct arm_matrix_operations *, uint32_t);

struct test_thread {
	pthread_t thread;
	thread_fn_t thread_fn;
	uint32_t cpuid;
	uint32_t thread_id;
	const struct arm_matrix_operations *ops;
};

static uint32_t barrier;
static pthread_cond_t barrier_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t barrier_lock = PTHREAD_MUTEX_INITIALIZER;

static void
test_thread_barrier(void)
{
	/* Wait for all threads to reach this barrier */
	pthread_mutex_lock(&barrier_lock);
	barrier--;
	if (barrier) {
		while (barrier) {
			pthread_cond_wait(&barrier_cond, &barrier_lock);
		}
	} else {
		pthread_cond_broadcast(&barrier_cond);
	}
	pthread_mutex_unlock(&barrier_lock);
}

static uint32_t
ncpus(void)
{
	uint32_t ncpu;
	size_t ncpu_size = sizeof(ncpu);
	int err = sysctlbyname("hw.ncpu", &ncpu, &ncpu_size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_ZERO(err, "Retrieved CPU count");

	return ncpu;
}

static int
thread_bind_cpu_unchecked(uint32_t cpuid)
{
	/*
	 * libc's sysctl() implementation calls strlen(name), which is
	 * SIMD-accelerated.  Avoid this by directly invoking the libsyscall
	 * wrapper with namelen computed at compile time.
	 */
#define THREAD_BIND_CPU "kern.sched_thread_bind_cpu"
	extern int __sysctlbyname(const char *name, size_t namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
	const char *name = THREAD_BIND_CPU;
	size_t namelen = sizeof(THREAD_BIND_CPU) - 1;
	return __sysctlbyname(name, namelen, NULL, 0, &cpuid, sizeof(cpuid));
}

static void
thread_bind_cpu(uint32_t cpuid)
{
	int err = thread_bind_cpu_unchecked(cpuid);
	T_QUIET; T_ASSERT_POSIX_ZERO(err, "Bound thread to CPU %u", cpuid);
}

static void *
test_thread_shim(void *arg)
{
	struct test_thread *thread = arg;

	thread_bind_cpu(thread->cpuid);
	bool ret = thread->thread_fn(thread->ops, thread->thread_id);
	return (void *)(uintptr_t)ret;
}

static void
test_on_each_cpu(thread_fn_t thread_fn, const struct arm_matrix_operations *ops, const char *desc)
{
	uint32_t ncpu = ncpus();
	uint32_t nthreads = ncpu * 2;
	barrier = nthreads;
	struct test_thread *threads = calloc(nthreads, sizeof(threads[0]));
	for (uint32_t i = 0; i < nthreads; i++) {
		threads[i].thread_fn = thread_fn;
		threads[i].cpuid = i % ncpu;
		threads[i].thread_id = i;
		threads[i].ops = ops;

		int err = pthread_create(&threads[i].thread, NULL, test_thread_shim, &threads[i]);
		T_QUIET; T_ASSERT_EQ(err, 0, "%s: created thread #%u", desc, i);
	}

	for (uint32_t i = 0; i < nthreads; i++) {
		void *thread_ret_ptr;
		int err = pthread_join(threads[i].thread, &thread_ret_ptr);
		T_QUIET; T_ASSERT_EQ(err, 0, "%s: joined thread #%u", desc, i);

		bool thread_ret = (uintptr_t)thread_ret_ptr;
		if (thread_ret) {
			T_PASS("%s: thread #%u passed", desc, i);
		} else {
			T_FAIL("%s: thread #%u failed", desc, i);
		}
	}

	free(threads);
}

static bool
active_context_switch_thread(const struct arm_matrix_operations *ops, uint32_t thread_id)
{
	size_t size = ops->data_size();
	uint8_t *d1 = ops->alloc_data();
	memset(d1, (char)thread_id, size);

	uint8_t *d2 = ops->alloc_data();

	test_thread_barrier();

	bool ok = true;
	for (unsigned int i = 0; i < 100000 && ok; i++) {
		ops->start();
		ops->load_data(d1);

		/*
		 * Rescheduling with the matrix registers active must preserve
		 * state, even after a context switch.
		 */
		sched_yield();

		ops->store_data(d2);
		ops->stop();

		if (memcmp(d1, d2, size)) {
			ok = false;
		}
	}

	free(d2);
	free(d1);
	return ok;
}

static bool
inactive_context_switch_thread(const struct arm_matrix_operations *ops, uint32_t thread_id)
{
	size_t size = ops->data_size();
	uint8_t *d1 = ops->alloc_data();
	memset(d1, (char)thread_id, size);

	uint8_t *d2 = ops->alloc_data();

	test_thread_barrier();

	bool ok = true;
	for (unsigned int i = 0; i < 100000 && ok; i++) {
		ops->start();
		ops->load_data(d1);
		ops->stop();

		/*
		 * Rescheduling with the matrix registers inactive may preserve
		 * state or may zero it out.
		 */
		sched_yield();

		ops->start();
		ops->store_data(d2);
		ops->stop();

		for (size_t j = 0; j < size; j++) {
			if (d1[j] != d2[j] && d2[j] != 0) {
				ok = false;
			}
		}
	}

	free(d2);
	free(d1);
	return ok;
}

static void
test_thread_migration(const struct arm_matrix_operations *ops)
{
	size_t size = ops->data_size();
	uint8_t *d = ops->alloc_data();
	arc4random_buf(d, size);

	uint32_t ncpu = ncpus();
	uint8_t *cpu_d[ncpu];
	for (uint32_t cpuid = 0; cpuid < ncpu; cpuid++) {
		cpu_d[cpuid] = ops->alloc_data();
		memset(cpu_d[cpuid], 0, size);
	}

	ops->start();
	ops->load_data(d);
	for (uint32_t cpuid = 0; cpuid < ncpu; cpuid++) {
		int err = thread_bind_cpu_unchecked(cpuid);
		if (err) {
			ops->stop();
			T_ASSERT_POSIX_ZERO(err, "Bound thread to CPU %u", cpuid);
		}
		ops->store_data(cpu_d[cpuid]);
	}
	ops->stop();

	for (uint32_t cpuid = 0; cpuid < ncpu; cpuid++) {
		int cmp = memcmp(d, cpu_d[cpuid], size);
		T_EXPECT_EQ(cmp, 0, "Matrix state migrated to CPU %u", cpuid);
		free(cpu_d[cpuid]);
	}
	free(d);
}
#endif


T_DECL(sme_context_switch,
    "Test that SME contexts are migrated during context switch and do not leak between process contexts.",
    T_META_BOOTARGS_SET("enable_skstb=1"),
    T_META_REQUIRES_SYSCTL_EQ("hw.optional.arm.FEAT_SME2", 1),
    XNU_T_META_SOC_SPECIFIC, T_META_TAG_VM_NOT_ELIGIBLE)
{
#ifndef __arm64__
	T_SKIP("Running on non-arm64 target, skipping...");
#else
	if (!sme_operations.is_available()) {
		T_SKIP("Running on non-SME target, skipping...");
	}

	test_thread_migration(&sme_operations);
	test_on_each_cpu(active_context_switch_thread, &sme_operations, "SME context migrates when active");
	test_on_each_cpu(inactive_context_switch_thread, &sme_operations, "SME context does not leak across processes");
#endif
}

