/*
 * Copyright (c) 2011-2018 Apple Inc. All rights reserved.
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
 * @OSF_COPYRIGHT@
 */
/*
 * Mach Operating System Copyright (c) 1991,1990,1989,1988,1987 Carnegie
 * Mellon University All Rights Reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright notice
 * and this permission notice appear in all copies of the software,
 * derivative works or modified versions, and any portions thereof, and that
 * both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS" CONDITION.
 * CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR ANY DAMAGES
 * WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 * Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 * School of Computer Science Carnegie Mellon University Pittsburgh PA
 * 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie Mellon the
 * rights to redistribute these changes.
 */

#include <mach_ldebug.h>

#define LOCK_PRIVATE 1

#include <vm/pmap.h>
#include <vm/vm_map_xnu.h>
#include <vm/vm_page_internal.h>
#include <vm/vm_kern_xnu.h>
#include <mach/vm_map.h>
#include <kern/backtrace.h>
#include <kern/kalloc.h>
#include <kern/cpu_number.h>
#include <kern/locks.h>
#include <kern/misc_protos.h>
#include <kern/thread.h>
#include <kern/processor.h>
#include <kern/sched_prim.h>
#include <kern/debug.h>
#include <stdatomic.h>
#include <string.h>
#include <tests/xnupost.h>

#if     MACH_KDB
#include <ddb/db_command.h>
#include <ddb/db_output.h>
#include <ddb/db_sym.h>
#include <ddb/db_print.h>
#endif                          /* MACH_KDB */

#include <san/kasan.h>
#include <sys/errno.h>
#include <sys/kdebug.h>
#include <sys/munge.h>
#include <machine/cpu_capabilities.h>
#include <machine/machine_routines.h>
#include <arm/cpu_data_internal.h>
#include <arm/cpu_internal.h>
#include <arm/pmap.h>
#include <arm/pmap/pmap_pt_geometry.h>
#include <pexpert/pexpert.h>

#if defined(KERNEL_INTEGRITY_KTRR) || defined(KERNEL_INTEGRITY_CTRR) || defined(KERNEL_INTEGRITY_PV_CTRR)
#include <arm64/amcc_rorgn.h>
#endif // defined(KERNEL_INTEGRITY_KTRR) || defined(KERNEL_INTEGRITY_CTRR) || defined(KERNEL_INTEGRITY_PV_CTRR)

#include <arm64/machine_machdep.h>

#if CONFIG_SPTM
#include <sptm/sptm_xnu.h>
#endif /* CONFIG_SPTM */

kern_return_t arm64_backtrace_test(void);
kern_return_t arm64_lock_test(void);
kern_return_t arm64_munger_test(void);
kern_return_t arm64_pan_test(void);
kern_return_t arm64_late_pan_test(void);
#if DEVELOPMENT || DEBUG
#if CONFIG_SPTM
void __attribute__((noreturn)) sptm_vs_xnu_panic_test(void);
void __attribute__((noreturn)) xnu_vs_sptm_panic_test(void);
void __attribute__((noreturn)) sptm_vs_sptm_panic_test(void);
#endif /* CONFIG_SPTM */
void __attribute__((noreturn)) xnu_vs_xnu_panic_test(void);
void __attribute__((noreturn)) stack_overflow_panic_test(void);
#endif /* DEVELOPMENT || DEBUG */
#if defined(HAS_APPLE_PAC)
#include <ptrauth.h>
kern_return_t arm64_ropjop_test(void);
#endif
#if defined(KERNEL_INTEGRITY_CTRR) || defined(KERNEL_INTEGRITY_PV_CTRR)
kern_return_t ctrr_test(void);
kern_return_t ctrr_test_cpu(void);
#endif
#if BTI_ENFORCED
kern_return_t arm64_bti_test(void);
#endif /* BTI_ENFORCED */
#if HAS_MTE
#include <arm_acle.h>
kern_return_t mte_test(void);
kern_return_t mte_copyio_recovery_handler_test(void);
#endif
#if HAS_SPECRES
extern kern_return_t specres_test(void);
#endif

// exception handler ignores this fault address during PAN test
#if __ARM_PAN_AVAILABLE__
const uint64_t pan_ro_value = 0xFEEDB0B0DEADBEEF;
vm_offset_t pan_test_addr = 0;
vm_offset_t pan_ro_addr = 0;
volatile int pan_exception_level = 0;
volatile char pan_fault_value = 0;
#endif

#if CONFIG_SPTM
kern_return_t arm64_panic_lockdown_test(void);
#endif /* CONFIG_SPTM */


#include <arm64/speculation.h>
kern_return_t arm64_speculation_guard_test(void);


#include <machine/static_if.h>
kern_return_t arm64_static_if_asm_test(void);

#include <libkern/OSAtomic.h>
#define LOCK_TEST_ITERATIONS 50
#define LOCK_TEST_SETUP_TIMEOUT_SEC 15
static hw_lock_data_t   lt_hw_lock;
static lck_spin_t       lt_lck_spin_t;
static lck_mtx_t        lt_mtx;
static lck_rw_t         lt_rwlock;
static volatile uint32_t lt_counter = 0;
static volatile int     lt_spinvolatile;
static volatile uint32_t lt_max_holders = 0;
static volatile uint32_t lt_upgrade_holders = 0;
static volatile uint32_t lt_max_upgrade_holders = 0;
static volatile uint32_t lt_num_holders = 0;
static volatile uint32_t lt_done_threads;
static volatile uint32_t lt_target_done_threads;
static volatile uint32_t lt_cpu_bind_id = 0;
static uint64_t          lt_setup_timeout = 0;

static void
lt_note_another_blocking_lock_holder()
{
	hw_lock_lock(&lt_hw_lock, LCK_GRP_NULL);
	lt_num_holders++;
	lt_max_holders = (lt_max_holders < lt_num_holders) ? lt_num_holders : lt_max_holders;
	hw_lock_unlock(&lt_hw_lock);
}

static void
lt_note_blocking_lock_release()
{
	hw_lock_lock(&lt_hw_lock, LCK_GRP_NULL);
	lt_num_holders--;
	hw_lock_unlock(&lt_hw_lock);
}

static void
lt_spin_a_little_bit()
{
	uint32_t i;

	for (i = 0; i < 10000; i++) {
		lt_spinvolatile++;
	}
}

static void
lt_sleep_a_little_bit()
{
	delay(100);
}

static void
lt_grab_mutex()
{
	lck_mtx_lock(&lt_mtx);
	lt_note_another_blocking_lock_holder();
	lt_sleep_a_little_bit();
	lt_counter++;
	lt_note_blocking_lock_release();
	lck_mtx_unlock(&lt_mtx);
}

static void
lt_grab_mutex_with_try()
{
	while (0 == lck_mtx_try_lock(&lt_mtx)) {
		;
	}
	lt_note_another_blocking_lock_holder();
	lt_sleep_a_little_bit();
	lt_counter++;
	lt_note_blocking_lock_release();
	lck_mtx_unlock(&lt_mtx);
}

static void
lt_grab_rw_exclusive()
{
	lck_rw_lock_exclusive(&lt_rwlock);
	lt_note_another_blocking_lock_holder();
	lt_sleep_a_little_bit();
	lt_counter++;
	lt_note_blocking_lock_release();
	lck_rw_done(&lt_rwlock);
}

static void
lt_grab_rw_exclusive_with_try()
{
	while (0 == lck_rw_try_lock_exclusive(&lt_rwlock)) {
		lt_sleep_a_little_bit();
	}

	lt_note_another_blocking_lock_holder();
	lt_sleep_a_little_bit();
	lt_counter++;
	lt_note_blocking_lock_release();
	lck_rw_done(&lt_rwlock);
}

/* Disabled until lt_grab_rw_shared() is fixed (rdar://30685840)
 *  static void
 *  lt_grab_rw_shared()
 *  {
 *       lck_rw_lock_shared(&lt_rwlock);
 *       lt_counter++;
 *
 *       lt_note_another_blocking_lock_holder();
 *       lt_sleep_a_little_bit();
 *       lt_note_blocking_lock_release();
 *
 *       lck_rw_done(&lt_rwlock);
 *  }
 */

/* Disabled until lt_grab_rw_shared_with_try() is fixed (rdar://30685840)
 *  static void
 *  lt_grab_rw_shared_with_try()
 *  {
 *       while(0 == lck_rw_try_lock_shared(&lt_rwlock));
 *       lt_counter++;
 *
 *       lt_note_another_blocking_lock_holder();
 *       lt_sleep_a_little_bit();
 *       lt_note_blocking_lock_release();
 *
 *       lck_rw_done(&lt_rwlock);
 *  }
 */

static void
lt_upgrade_downgrade_rw()
{
	boolean_t upgraded, success;

	success = lck_rw_try_lock_shared(&lt_rwlock);
	if (!success) {
		lck_rw_lock_shared(&lt_rwlock);
	}

	lt_note_another_blocking_lock_holder();
	lt_sleep_a_little_bit();
	lt_note_blocking_lock_release();

	upgraded = lck_rw_lock_shared_to_exclusive(&lt_rwlock);
	if (!upgraded) {
		success = lck_rw_try_lock_exclusive(&lt_rwlock);

		if (!success) {
			lck_rw_lock_exclusive(&lt_rwlock);
		}
	}

	lt_upgrade_holders++;
	if (lt_upgrade_holders > lt_max_upgrade_holders) {
		lt_max_upgrade_holders = lt_upgrade_holders;
	}

	lt_counter++;
	lt_sleep_a_little_bit();

	lt_upgrade_holders--;

	lck_rw_lock_exclusive_to_shared(&lt_rwlock);

	lt_spin_a_little_bit();
	lck_rw_done(&lt_rwlock);
}

#if __AMP__
const int limit = 1000000;
static int lt_stress_local_counters[MAX_CPUS];

lck_ticket_t lt_ticket_lock;
lck_grp_t lt_ticket_grp;

static void
lt_stress_ticket_lock()
{
	uint local_counter = 0;

	uint cpuid = cpu_number();

	kprintf("%s>cpu %u starting\n", __FUNCTION__, cpuid);

	lck_ticket_lock(&lt_ticket_lock, &lt_ticket_grp);
	lt_counter++;
	local_counter++;
	lck_ticket_unlock(&lt_ticket_lock);

	/* Wait until all test threads have finished any binding */
	while (lt_counter < lt_target_done_threads) {
		if (mach_absolute_time() > lt_setup_timeout) {
			kprintf("%s>cpu %u noticed that we exceeded setup timeout of %d seconds during initial setup phase (only %u out of %u threads checked in)",
			    __FUNCTION__, cpuid, LOCK_TEST_SETUP_TIMEOUT_SEC, lt_counter, lt_target_done_threads);
			return;
		}
		/* Yield to keep the CPUs available for the threads to bind */
		thread_yield_internal(1);
	}

	lck_ticket_lock(&lt_ticket_lock, &lt_ticket_grp);
	lt_counter++;
	local_counter++;
	lck_ticket_unlock(&lt_ticket_lock);

	/*
	 * Now that the test threads have finished any binding, wait
	 * until they are all actively spinning on-core (done yielding)
	 * so we get a fairly timed start.
	 */
	while (lt_counter < 2 * lt_target_done_threads) {
		if (mach_absolute_time() > lt_setup_timeout) {
			kprintf("%s>cpu %u noticed that we exceeded setup timeout of %d seconds during secondary setup phase (only %u out of %u threads checked in)",
			    __FUNCTION__, cpuid, LOCK_TEST_SETUP_TIMEOUT_SEC, lt_counter - lt_target_done_threads, lt_target_done_threads);
			return;
		}
	}

	kprintf("%s>cpu %u started\n", __FUNCTION__, cpuid);

	while (lt_counter < limit) {
		lck_ticket_lock(&lt_ticket_lock, &lt_ticket_grp);
		if (lt_counter < limit) {
			lt_counter++;
			local_counter++;
		}
		lck_ticket_unlock(&lt_ticket_lock);
	}

	lt_stress_local_counters[cpuid] = local_counter;

	kprintf("%s>final counter %u cpu %u incremented the counter %u times\n", __FUNCTION__, lt_counter, cpuid, local_counter);
}
#endif

static void
lt_grab_hw_lock()
{
	hw_lock_lock(&lt_hw_lock, LCK_GRP_NULL);
	lt_counter++;
	lt_spin_a_little_bit();
	hw_lock_unlock(&lt_hw_lock);
}

static void
lt_grab_hw_lock_with_try()
{
	while (0 == hw_lock_try(&lt_hw_lock, LCK_GRP_NULL)) {
		;
	}
	lt_counter++;
	lt_spin_a_little_bit();
	hw_lock_unlock(&lt_hw_lock);
}

static void
lt_grab_hw_lock_with_to()
{
	(void)hw_lock_to(&lt_hw_lock, &hw_lock_spin_policy, LCK_GRP_NULL);
	lt_counter++;
	lt_spin_a_little_bit();
	hw_lock_unlock(&lt_hw_lock);
}

static void
lt_grab_spin_lock()
{
	lck_spin_lock(&lt_lck_spin_t);
	lt_counter++;
	lt_spin_a_little_bit();
	lck_spin_unlock(&lt_lck_spin_t);
}

static void
lt_grab_spin_lock_with_try()
{
	while (0 == lck_spin_try_lock(&lt_lck_spin_t)) {
		;
	}
	lt_counter++;
	lt_spin_a_little_bit();
	lck_spin_unlock(&lt_lck_spin_t);
}

static volatile boolean_t lt_thread_lock_grabbed;
static volatile boolean_t lt_thread_lock_success;

static void
lt_reset()
{
	lt_counter = 0;
	lt_max_holders = 0;
	lt_num_holders = 0;
	lt_max_upgrade_holders = 0;
	lt_upgrade_holders = 0;
	lt_done_threads = 0;
	lt_target_done_threads = 0;
	lt_cpu_bind_id = 0;
	/* Reset timeout deadline out from current time */
	nanoseconds_to_absolutetime(LOCK_TEST_SETUP_TIMEOUT_SEC * NSEC_PER_SEC, &lt_setup_timeout);
	lt_setup_timeout += mach_absolute_time();

	OSMemoryBarrier();
}

static void
lt_trylock_hw_lock_with_to()
{
	OSMemoryBarrier();
	while (!lt_thread_lock_grabbed) {
		lt_sleep_a_little_bit();
		OSMemoryBarrier();
	}
	lt_thread_lock_success = hw_lock_to(&lt_hw_lock,
	    &hw_lock_test_give_up_policy, LCK_GRP_NULL);
	OSMemoryBarrier();
	mp_enable_preemption();
}

static void
lt_trylock_spin_try_lock()
{
	OSMemoryBarrier();
	while (!lt_thread_lock_grabbed) {
		lt_sleep_a_little_bit();
		OSMemoryBarrier();
	}
	lt_thread_lock_success = lck_spin_try_lock(&lt_lck_spin_t);
	OSMemoryBarrier();
}

static void
lt_trylock_thread(void *arg, wait_result_t wres __unused)
{
	void (*func)(void) = (void (*)(void))arg;

	func();

	OSIncrementAtomic((volatile SInt32*) &lt_done_threads);
}

static void
lt_start_trylock_thread(thread_continue_t func)
{
	thread_t thread;
	kern_return_t kr;

	kr = kernel_thread_start(lt_trylock_thread, func, &thread);
	assert(kr == KERN_SUCCESS);

	thread_deallocate(thread);
}

static void
lt_wait_for_lock_test_threads()
{
	OSMemoryBarrier();
	/* Spin to reduce dependencies */
	while (lt_done_threads < lt_target_done_threads) {
		lt_sleep_a_little_bit();
		OSMemoryBarrier();
	}
	OSMemoryBarrier();
}

static kern_return_t
lt_test_trylocks()
{
	boolean_t success;
	extern unsigned int real_ncpus;

	/*
	 * First mtx try lock succeeds, second fails.
	 */
	success = lck_mtx_try_lock(&lt_mtx);
	T_ASSERT_NOTNULL(success, "First mtx try lock");
	success = lck_mtx_try_lock(&lt_mtx);
	T_ASSERT_NULL(success, "Second mtx try lock for a locked mtx");
	lck_mtx_unlock(&lt_mtx);

	/*
	 * After regular grab, can't try lock.
	 */
	lck_mtx_lock(&lt_mtx);
	success = lck_mtx_try_lock(&lt_mtx);
	T_ASSERT_NULL(success, "try lock should fail after regular lck_mtx_lock");
	lck_mtx_unlock(&lt_mtx);

	/*
	 * Two shared try locks on a previously unheld rwlock suceed, and a
	 * subsequent exclusive attempt fails.
	 */
	success = lck_rw_try_lock_shared(&lt_rwlock);
	T_ASSERT_NOTNULL(success, "Two shared try locks on a previously unheld rwlock should succeed");
	success = lck_rw_try_lock_shared(&lt_rwlock);
	T_ASSERT_NOTNULL(success, "Two shared try locks on a previously unheld rwlock should succeed");
	success = lck_rw_try_lock_exclusive(&lt_rwlock);
	T_ASSERT_NULL(success, "exclusive lock attempt on previously held lock should fail");
	lck_rw_done(&lt_rwlock);
	lck_rw_done(&lt_rwlock);

	/*
	 * After regular shared grab, can trylock
	 * for shared but not for exclusive.
	 */
	lck_rw_lock_shared(&lt_rwlock);
	success = lck_rw_try_lock_shared(&lt_rwlock);
	T_ASSERT_NOTNULL(success, "After regular shared grab another shared try lock should succeed.");
	success = lck_rw_try_lock_exclusive(&lt_rwlock);
	T_ASSERT_NULL(success, "After regular shared grab an exclusive lock attempt should fail.");
	lck_rw_done(&lt_rwlock);
	lck_rw_done(&lt_rwlock);

	/*
	 * An exclusive try lock succeeds, subsequent shared and exclusive
	 * attempts fail.
	 */
	success = lck_rw_try_lock_exclusive(&lt_rwlock);
	T_ASSERT_NOTNULL(success, "An exclusive try lock should succeed");
	success = lck_rw_try_lock_shared(&lt_rwlock);
	T_ASSERT_NULL(success, "try lock in shared mode attempt after an exclusive grab should fail");
	success = lck_rw_try_lock_exclusive(&lt_rwlock);
	T_ASSERT_NULL(success, "try lock in exclusive mode attempt after an exclusive grab should fail");
	lck_rw_done(&lt_rwlock);

	/*
	 * After regular exclusive grab, neither kind of trylock succeeds.
	 */
	lck_rw_lock_exclusive(&lt_rwlock);
	success = lck_rw_try_lock_shared(&lt_rwlock);
	T_ASSERT_NULL(success, "After regular exclusive grab, shared trylock should not succeed");
	success = lck_rw_try_lock_exclusive(&lt_rwlock);
	T_ASSERT_NULL(success, "After regular exclusive grab, exclusive trylock should not succeed");
	lck_rw_done(&lt_rwlock);

	/*
	 * First spin lock attempts succeed, second attempts fail.
	 */
	success = hw_lock_try(&lt_hw_lock, LCK_GRP_NULL);
	T_ASSERT_NOTNULL(success, "First spin lock attempts should succeed");
	success = hw_lock_try(&lt_hw_lock, LCK_GRP_NULL);
	T_ASSERT_NULL(success, "Second attempt to spin lock should fail");
	hw_lock_unlock(&lt_hw_lock);

	hw_lock_lock(&lt_hw_lock, LCK_GRP_NULL);
	success = hw_lock_try(&lt_hw_lock, LCK_GRP_NULL);
	T_ASSERT_NULL(success, "After taking spin lock, trylock attempt should fail");
	hw_lock_unlock(&lt_hw_lock);

	lt_reset();
	lt_thread_lock_grabbed = false;
	lt_thread_lock_success = true;
	lt_target_done_threads = 1;
	OSMemoryBarrier();
	lt_start_trylock_thread(lt_trylock_hw_lock_with_to);
	success = hw_lock_to(&lt_hw_lock, &hw_lock_test_give_up_policy, LCK_GRP_NULL);
	T_ASSERT_NOTNULL(success, "First spin lock with timeout should succeed");
	if (real_ncpus == 1) {
		mp_enable_preemption(); /* if we re-enable preemption, the other thread can timeout and exit */
	}
	OSIncrementAtomic((volatile SInt32*)&lt_thread_lock_grabbed);
	lt_wait_for_lock_test_threads();
	T_ASSERT_NULL(lt_thread_lock_success, "Second spin lock with timeout should fail and timeout");
	if (real_ncpus == 1) {
		mp_disable_preemption(); /* don't double-enable when we unlock */
	}
	hw_lock_unlock(&lt_hw_lock);

	lt_reset();
	lt_thread_lock_grabbed = false;
	lt_thread_lock_success = true;
	lt_target_done_threads = 1;
	OSMemoryBarrier();
	lt_start_trylock_thread(lt_trylock_hw_lock_with_to);
	hw_lock_lock(&lt_hw_lock, LCK_GRP_NULL);
	if (real_ncpus == 1) {
		mp_enable_preemption(); /* if we re-enable preemption, the other thread can timeout and exit */
	}
	OSIncrementAtomic((volatile SInt32*)&lt_thread_lock_grabbed);
	lt_wait_for_lock_test_threads();
	T_ASSERT_NULL(lt_thread_lock_success, "after taking a spin lock, lock attempt with timeout should fail");
	if (real_ncpus == 1) {
		mp_disable_preemption(); /* don't double-enable when we unlock */
	}
	hw_lock_unlock(&lt_hw_lock);

	success = lck_spin_try_lock(&lt_lck_spin_t);
	T_ASSERT_NOTNULL(success, "spin trylock of previously unheld lock should succeed");
	success = lck_spin_try_lock(&lt_lck_spin_t);
	T_ASSERT_NULL(success, "spin trylock attempt of previously held lock (with trylock) should fail");
	lck_spin_unlock(&lt_lck_spin_t);

	lt_reset();
	lt_thread_lock_grabbed = false;
	lt_thread_lock_success = true;
	lt_target_done_threads = 1;
	lt_start_trylock_thread(lt_trylock_spin_try_lock);
	lck_spin_lock(&lt_lck_spin_t);
	if (real_ncpus == 1) {
		mp_enable_preemption(); /* if we re-enable preemption, the other thread can timeout and exit */
	}
	OSIncrementAtomic((volatile SInt32*)&lt_thread_lock_grabbed);
	lt_wait_for_lock_test_threads();
	T_ASSERT_NULL(lt_thread_lock_success, "spin trylock attempt of previously held lock should fail");
	if (real_ncpus == 1) {
		mp_disable_preemption(); /* don't double-enable when we unlock */
	}
	lck_spin_unlock(&lt_lck_spin_t);

	return KERN_SUCCESS;
}

static void
lt_thread(void *arg, wait_result_t wres __unused)
{
	void (*func)(void) = (void (*)(void))arg;
	uint32_t i;

	for (i = 0; i < LOCK_TEST_ITERATIONS; i++) {
		func();
	}

	OSIncrementAtomic((volatile SInt32*) &lt_done_threads);
}

static void
lt_start_lock_thread(thread_continue_t func)
{
	thread_t thread;
	kern_return_t kr;

	kr = kernel_thread_start(lt_thread, func, &thread);
	assert(kr == KERN_SUCCESS);

	thread_deallocate(thread);
}

#if __AMP__
static void
lt_bound_thread(void *arg, wait_result_t wres __unused)
{
	void (*func)(void) = (void (*)(void))arg;

	int cpuid = OSIncrementAtomic((volatile SInt32 *)&lt_cpu_bind_id);

	processor_t processor = processor_list;
	while ((processor != NULL) && (processor->cpu_id != cpuid)) {
		processor = processor->processor_list;
	}

	if (processor != NULL) {
		thread_bind(processor);
	}

	thread_block(THREAD_CONTINUE_NULL);

	func();

	OSIncrementAtomic((volatile SInt32*) &lt_done_threads);
}

static void
lt_pset_bound_thread(void *arg, char pset_type)
{
	void (*func)(void) = (void (*)(void))arg;

	thread_t thread = current_thread();

	kern_return_t kr = thread_soft_bind_pset_type(thread, pset_type);
	if (kr != KERN_SUCCESS) {
		printf("%s>failed to bind to pset type %c\n", __FUNCTION__, pset_type);
	}

	func();

	OSIncrementAtomic((volatile SInt32*) &lt_done_threads);
}

static void
lt_e_thread(void *arg, wait_result_t wres __unused)
{
	lt_pset_bound_thread(arg, 'e');
}

static void
lt_m_thread(void *arg, wait_result_t wres __unused)
{
	lt_pset_bound_thread(arg, 'm');
}

static void
lt_p_thread(void *arg, wait_result_t wres __unused)
{
	lt_pset_bound_thread(arg, 'p');
}

static void
lt_start_lock_thread_with_bind(thread_continue_t bind_type, thread_continue_t func)
{
	thread_t thread;
	kern_return_t kr;

	kr = kernel_thread_start(bind_type, func, &thread);
	assert(kr == KERN_SUCCESS);

	thread_deallocate(thread);
}
#endif /* __AMP__ */

static kern_return_t
lt_test_locks()
{
#if SCHED_HYGIENE_DEBUG
	/*
	 * When testing, the preemption disable threshold may be hit (for
	 * example when testing a lock timeout). To avoid this, the preemption
	 * disable measurement is temporarily disabled during lock testing.
	 */
	int old_mode = sched_preemption_disable_debug_mode;
	if (old_mode == SCHED_HYGIENE_MODE_PANIC) {
		sched_preemption_disable_debug_mode = SCHED_HYGIENE_MODE_OFF;
	}
#endif /* SCHED_HYGIENE_DEBUG */

	kern_return_t kr = KERN_SUCCESS;
	lck_grp_attr_t *lga = lck_grp_attr_alloc_init();
	lck_grp_t *lg = lck_grp_alloc_init("lock test", lga);

	lck_mtx_init(&lt_mtx, lg, LCK_ATTR_NULL);
	lck_rw_init(&lt_rwlock, lg, LCK_ATTR_NULL);
	lck_spin_init(&lt_lck_spin_t, lg, LCK_ATTR_NULL);
	hw_lock_init(&lt_hw_lock);

	T_LOG("Testing locks.");

	/* Try locks (custom) */
	lt_reset();

	T_LOG("Running try lock test.");
	kr = lt_test_trylocks();
	T_EXPECT_NULL(kr, "try lock test failed.");

	/* Uncontended mutex */
	T_LOG("Running uncontended mutex test.");
	lt_reset();
	lt_target_done_threads = 1;
	lt_start_lock_thread(lt_grab_mutex);
	lt_wait_for_lock_test_threads();
	T_EXPECT_EQ_UINT(lt_counter, LOCK_TEST_ITERATIONS * lt_target_done_threads, NULL);
	T_EXPECT_EQ_UINT(lt_max_holders, 1, NULL);

	/* Contended mutex:try locks*/
	T_LOG("Running contended mutex test.");
	lt_reset();
	lt_target_done_threads = 3;
	lt_start_lock_thread(lt_grab_mutex);
	lt_start_lock_thread(lt_grab_mutex);
	lt_start_lock_thread(lt_grab_mutex);
	lt_wait_for_lock_test_threads();
	T_EXPECT_EQ_UINT(lt_counter, LOCK_TEST_ITERATIONS * lt_target_done_threads, NULL);
	T_EXPECT_EQ_UINT(lt_max_holders, 1, NULL);

	/* Contended mutex: try locks*/
	T_LOG("Running contended mutex trylock test.");
	lt_reset();
	lt_target_done_threads = 3;
	lt_start_lock_thread(lt_grab_mutex_with_try);
	lt_start_lock_thread(lt_grab_mutex_with_try);
	lt_start_lock_thread(lt_grab_mutex_with_try);
	lt_wait_for_lock_test_threads();
	T_EXPECT_EQ_UINT(lt_counter, LOCK_TEST_ITERATIONS * lt_target_done_threads, NULL);
	T_EXPECT_EQ_UINT(lt_max_holders, 1, NULL);

	/* Uncontended exclusive rwlock */
	T_LOG("Running uncontended exclusive rwlock test.");
	lt_reset();
	lt_target_done_threads = 1;
	lt_start_lock_thread(lt_grab_rw_exclusive);
	lt_wait_for_lock_test_threads();
	T_EXPECT_EQ_UINT(lt_counter, LOCK_TEST_ITERATIONS * lt_target_done_threads, NULL);
	T_EXPECT_EQ_UINT(lt_max_holders, 1, NULL);

	/* Uncontended shared rwlock */

	/* Disabled until lt_grab_rw_shared() is fixed (rdar://30685840)
	 *  T_LOG("Running uncontended shared rwlock test.");
	 *  lt_reset();
	 *  lt_target_done_threads = 1;
	 *  lt_start_lock_thread(lt_grab_rw_shared);
	 *  lt_wait_for_lock_test_threads();
	 *  T_EXPECT_EQ_UINT(lt_counter, LOCK_TEST_ITERATIONS * lt_target_done_threads, NULL);
	 *  T_EXPECT_EQ_UINT(lt_max_holders, 1, NULL);
	 */

	/* Contended exclusive rwlock */
	T_LOG("Running contended exclusive rwlock test.");
	lt_reset();
	lt_target_done_threads = 3;
	lt_start_lock_thread(lt_grab_rw_exclusive);
	lt_start_lock_thread(lt_grab_rw_exclusive);
	lt_start_lock_thread(lt_grab_rw_exclusive);
	lt_wait_for_lock_test_threads();
	T_EXPECT_EQ_UINT(lt_counter, LOCK_TEST_ITERATIONS * lt_target_done_threads, NULL);
	T_EXPECT_EQ_UINT(lt_max_holders, 1, NULL);

	/* One shared, two exclusive */
	/* Disabled until lt_grab_rw_shared() is fixed (rdar://30685840)
	 *  T_LOG("Running test with one shared and two exclusive rw lock threads.");
	 *  lt_reset();
	 *  lt_target_done_threads = 3;
	 *  lt_start_lock_thread(lt_grab_rw_shared);
	 *  lt_start_lock_thread(lt_grab_rw_exclusive);
	 *  lt_start_lock_thread(lt_grab_rw_exclusive);
	 *  lt_wait_for_lock_test_threads();
	 *  T_EXPECT_EQ_UINT(lt_counter, LOCK_TEST_ITERATIONS * lt_target_done_threads, NULL);
	 *  T_EXPECT_EQ_UINT(lt_max_holders, 1, NULL);
	 */

	/* Four shared */
	/* Disabled until lt_grab_rw_shared() is fixed (rdar://30685840)
	 *  T_LOG("Running test with four shared holders.");
	 *  lt_reset();
	 *  lt_target_done_threads = 4;
	 *  lt_start_lock_thread(lt_grab_rw_shared);
	 *  lt_start_lock_thread(lt_grab_rw_shared);
	 *  lt_start_lock_thread(lt_grab_rw_shared);
	 *  lt_start_lock_thread(lt_grab_rw_shared);
	 *  lt_wait_for_lock_test_threads();
	 *  T_EXPECT_LE_UINT(lt_max_holders, 4, NULL);
	 */

	/* Three doing upgrades and downgrades */
	T_LOG("Running test with threads upgrading and downgrading.");
	lt_reset();
	lt_target_done_threads = 3;
	lt_start_lock_thread(lt_upgrade_downgrade_rw);
	lt_start_lock_thread(lt_upgrade_downgrade_rw);
	lt_start_lock_thread(lt_upgrade_downgrade_rw);
	lt_wait_for_lock_test_threads();
	T_EXPECT_EQ_UINT(lt_counter, LOCK_TEST_ITERATIONS * lt_target_done_threads, NULL);
	T_EXPECT_LE_UINT(lt_max_holders, 3, NULL);
	T_EXPECT_EQ_UINT(lt_max_upgrade_holders, 1, NULL);

	/* Uncontended - exclusive trylocks */
	T_LOG("Running test with single thread doing exclusive rwlock trylocks.");
	lt_reset();
	lt_target_done_threads = 1;
	lt_start_lock_thread(lt_grab_rw_exclusive_with_try);
	lt_wait_for_lock_test_threads();
	T_EXPECT_EQ_UINT(lt_counter, LOCK_TEST_ITERATIONS * lt_target_done_threads, NULL);
	T_EXPECT_EQ_UINT(lt_max_holders, 1, NULL);

	/* Uncontended - shared trylocks */
	/* Disabled until lt_grab_rw_shared_with_try() is fixed (rdar://30685840)
	 *  T_LOG("Running test with single thread doing shared rwlock trylocks.");
	 *  lt_reset();
	 *  lt_target_done_threads = 1;
	 *  lt_start_lock_thread(lt_grab_rw_shared_with_try);
	 *  lt_wait_for_lock_test_threads();
	 *  T_EXPECT_EQ_UINT(lt_counter, LOCK_TEST_ITERATIONS * lt_target_done_threads, NULL);
	 *  T_EXPECT_EQ_UINT(lt_max_holders, 1, NULL);
	 */

	/* Three doing exclusive trylocks */
	T_LOG("Running test with threads doing exclusive rwlock trylocks.");
	lt_reset();
	lt_target_done_threads = 3;
	lt_start_lock_thread(lt_grab_rw_exclusive_with_try);
	lt_start_lock_thread(lt_grab_rw_exclusive_with_try);
	lt_start_lock_thread(lt_grab_rw_exclusive_with_try);
	lt_wait_for_lock_test_threads();
	T_EXPECT_EQ_UINT(lt_counter, LOCK_TEST_ITERATIONS * lt_target_done_threads, NULL);
	T_EXPECT_EQ_UINT(lt_max_holders, 1, NULL);

	/* Three doing shared trylocks */
	/* Disabled until lt_grab_rw_shared_with_try() is fixed (rdar://30685840)
	 *  T_LOG("Running test with threads doing shared rwlock trylocks.");
	 *  lt_reset();
	 *  lt_target_done_threads = 3;
	 *  lt_start_lock_thread(lt_grab_rw_shared_with_try);
	 *  lt_start_lock_thread(lt_grab_rw_shared_with_try);
	 *  lt_start_lock_thread(lt_grab_rw_shared_with_try);
	 *  lt_wait_for_lock_test_threads();
	 *  T_EXPECT_LE_UINT(lt_counter, LOCK_TEST_ITERATIONS * lt_target_done_threads, NULL);
	 *  T_EXPECT_LE_UINT(lt_max_holders, 3, NULL);
	 */

	/* Three doing various trylocks */
	/* Disabled until lt_grab_rw_shared_with_try() is fixed (rdar://30685840)
	 *  T_LOG("Running test with threads doing mixed rwlock trylocks.");
	 *  lt_reset();
	 *  lt_target_done_threads = 4;
	 *  lt_start_lock_thread(lt_grab_rw_shared_with_try);
	 *  lt_start_lock_thread(lt_grab_rw_shared_with_try);
	 *  lt_start_lock_thread(lt_grab_rw_exclusive_with_try);
	 *  lt_start_lock_thread(lt_grab_rw_exclusive_with_try);
	 *  lt_wait_for_lock_test_threads();
	 *  T_EXPECT_LE_UINT(lt_counter, LOCK_TEST_ITERATIONS * lt_target_done_threads, NULL);
	 *  T_EXPECT_LE_UINT(lt_max_holders, 2, NULL);
	 */

	/* HW locks */
	T_LOG("Running test with hw_lock_lock()");
	lt_reset();
	lt_target_done_threads = 3;
	lt_start_lock_thread(lt_grab_hw_lock);
	lt_start_lock_thread(lt_grab_hw_lock);
	lt_start_lock_thread(lt_grab_hw_lock);
	lt_wait_for_lock_test_threads();
	T_EXPECT_EQ_UINT(lt_counter, LOCK_TEST_ITERATIONS * lt_target_done_threads, NULL);

#if __AMP__
	/* Ticket locks stress test */
	T_LOG("Running Ticket locks stress test with lck_ticket_lock()");
	extern unsigned int real_ncpus;
	lck_grp_init(&lt_ticket_grp, "ticket lock stress", LCK_GRP_ATTR_NULL);
	lck_ticket_init(&lt_ticket_lock, &lt_ticket_grp);
	lt_reset();
	lt_target_done_threads = real_ncpus;
	uint thread_count = 0;
	for (processor_t processor = processor_list; processor != NULL; processor = processor->processor_list) {
		lt_start_lock_thread_with_bind(lt_bound_thread, lt_stress_ticket_lock);
		thread_count++;
	}
	T_EXPECT_GE_UINT(thread_count, lt_target_done_threads, "Spawned enough threads for valid test");
	lt_wait_for_lock_test_threads();
	bool starvation = false;
	uint total_local_count = 0;
	for (processor_t processor = processor_list; processor != NULL; processor = processor->processor_list) {
		starvation = starvation || (lt_stress_local_counters[processor->cpu_id] < 10);
		total_local_count += lt_stress_local_counters[processor->cpu_id];
	}
	if (mach_absolute_time() > lt_setup_timeout) {
		T_FAIL("Stress test setup timed out after %d seconds", LOCK_TEST_SETUP_TIMEOUT_SEC);
	} else if (total_local_count != lt_counter) {
		T_FAIL("Lock failure\n");
	} else if (starvation) {
		T_FAIL("Lock starvation found\n");
	} else {
		T_PASS("Ticket locks stress test with lck_ticket_lock() (%u total acquires)", total_local_count);
	}

	/* AMP ticket locks stress test */
	T_LOG("Running AMP Ticket locks stress test bound to clusters with lck_ticket_lock()");
	lt_reset();
	lt_target_done_threads = real_ncpus;
	thread_count = 0;
	for (processor_t processor = processor_list; processor != NULL; processor = processor->processor_list) {
		processor_set_t pset = processor->processor_set;
		switch (pset->pset_type) {
		case PSET_AMP_P:
			lt_start_lock_thread_with_bind(lt_p_thread, lt_stress_ticket_lock);
			break;
		case PSET_AMP_M:
			lt_start_lock_thread_with_bind(lt_m_thread, lt_stress_ticket_lock);
			break;
		case PSET_AMP_E:
			lt_start_lock_thread_with_bind(lt_e_thread, lt_stress_ticket_lock);
			break;
		default:
			lt_start_lock_thread(lt_stress_ticket_lock);
			break;
		}
		thread_count++;
	}
	T_EXPECT_GE_UINT(thread_count, lt_target_done_threads, "Spawned enough threads for valid test");
	lt_wait_for_lock_test_threads();
#endif /* __AMP__ */

	/* HW locks: trylocks */
	T_LOG("Running test with hw_lock_try()");
	lt_reset();
	lt_target_done_threads = 3;
	lt_start_lock_thread(lt_grab_hw_lock_with_try);
	lt_start_lock_thread(lt_grab_hw_lock_with_try);
	lt_start_lock_thread(lt_grab_hw_lock_with_try);
	lt_wait_for_lock_test_threads();
	T_EXPECT_EQ_UINT(lt_counter, LOCK_TEST_ITERATIONS * lt_target_done_threads, NULL);

	/* HW locks: with timeout */
	T_LOG("Running test with hw_lock_to()");
	lt_reset();
	lt_target_done_threads = 3;
	lt_start_lock_thread(lt_grab_hw_lock_with_to);
	lt_start_lock_thread(lt_grab_hw_lock_with_to);
	lt_start_lock_thread(lt_grab_hw_lock_with_to);
	lt_wait_for_lock_test_threads();
	T_EXPECT_EQ_UINT(lt_counter, LOCK_TEST_ITERATIONS * lt_target_done_threads, NULL);

	/* Spin locks */
	T_LOG("Running test with lck_spin_lock()");
	lt_reset();
	lt_target_done_threads = 3;
	lt_start_lock_thread(lt_grab_spin_lock);
	lt_start_lock_thread(lt_grab_spin_lock);
	lt_start_lock_thread(lt_grab_spin_lock);
	lt_wait_for_lock_test_threads();
	T_EXPECT_EQ_UINT(lt_counter, LOCK_TEST_ITERATIONS * lt_target_done_threads, NULL);

	/* Spin locks: trylocks */
	T_LOG("Running test with lck_spin_try_lock()");
	lt_reset();
	lt_target_done_threads = 3;
	lt_start_lock_thread(lt_grab_spin_lock_with_try);
	lt_start_lock_thread(lt_grab_spin_lock_with_try);
	lt_start_lock_thread(lt_grab_spin_lock_with_try);
	lt_wait_for_lock_test_threads();
	T_EXPECT_EQ_UINT(lt_counter, LOCK_TEST_ITERATIONS * lt_target_done_threads, NULL);

#if SCHED_HYGIENE_DEBUG
	sched_preemption_disable_debug_mode = old_mode;
#endif /* SCHED_HYGIENE_DEBUG */

	return KERN_SUCCESS;
}

#define MT_MAX_ARGS             8
#define MT_INITIAL_VALUE        0xfeedbeef
#define MT_W_VAL                (0x00000000feedbeefULL) /* Drop in zeros */
#define MT_S_VAL                (0xfffffffffeedbeefULL) /* High bit is 1, so sign-extends as negative */
#define MT_L_VAL                (((uint64_t)MT_INITIAL_VALUE) | (((uint64_t)MT_INITIAL_VALUE) << 32)) /* Two back-to-back */

typedef void (*sy_munge_t)(void*);

#define MT_FUNC(x) #x, x
struct munger_test {
	const char      *mt_name;
	sy_munge_t      mt_func;
	uint32_t        mt_in_words;
	uint32_t        mt_nout;
	uint64_t        mt_expected[MT_MAX_ARGS];
} munger_tests[] = {
	{MT_FUNC(munge_w), 1, 1, {MT_W_VAL}},
	{MT_FUNC(munge_ww), 2, 2, {MT_W_VAL, MT_W_VAL}},
	{MT_FUNC(munge_www), 3, 3, {MT_W_VAL, MT_W_VAL, MT_W_VAL}},
	{MT_FUNC(munge_wwww), 4, 4, {MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL}},
	{MT_FUNC(munge_wwwww), 5, 5, {MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL}},
	{MT_FUNC(munge_wwwwww), 6, 6, {MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL}},
	{MT_FUNC(munge_wwwwwww), 7, 7, {MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL}},
	{MT_FUNC(munge_wwwwwwww), 8, 8, {MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL}},
	{MT_FUNC(munge_wl), 3, 2, {MT_W_VAL, MT_L_VAL}},
	{MT_FUNC(munge_wwl), 4, 3, {MT_W_VAL, MT_W_VAL, MT_L_VAL}},
	{MT_FUNC(munge_wwlll), 8, 5, {MT_W_VAL, MT_W_VAL, MT_L_VAL, MT_L_VAL, MT_L_VAL}},
	{MT_FUNC(munge_wwlllll), 12, 7, {MT_W_VAL, MT_W_VAL, MT_L_VAL, MT_L_VAL, MT_L_VAL, MT_L_VAL, MT_L_VAL}},
	{MT_FUNC(munge_wwllllll), 14, 8, {MT_W_VAL, MT_W_VAL, MT_L_VAL, MT_L_VAL, MT_L_VAL, MT_L_VAL, MT_L_VAL, MT_L_VAL}},
	{MT_FUNC(munge_wlw), 4, 3, {MT_W_VAL, MT_L_VAL, MT_W_VAL}},
	{MT_FUNC(munge_wlwwwll), 10, 7, {MT_W_VAL, MT_L_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_L_VAL, MT_L_VAL}},
	{MT_FUNC(munge_wlwwwllw), 11, 8, {MT_W_VAL, MT_L_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_L_VAL, MT_L_VAL, MT_W_VAL}},
	{MT_FUNC(munge_wlwwlwlw), 11, 8, {MT_W_VAL, MT_L_VAL, MT_W_VAL, MT_W_VAL, MT_L_VAL, MT_W_VAL, MT_L_VAL, MT_W_VAL}},
	{MT_FUNC(munge_wll), 5, 3, {MT_W_VAL, MT_L_VAL, MT_L_VAL}},
	{MT_FUNC(munge_wlll), 7, 4, {MT_W_VAL, MT_L_VAL, MT_L_VAL, MT_L_VAL}},
	{MT_FUNC(munge_wllwwll), 11, 7, {MT_W_VAL, MT_L_VAL, MT_L_VAL, MT_W_VAL, MT_W_VAL, MT_L_VAL, MT_L_VAL}},
	{MT_FUNC(munge_wwwlw), 6, 5, {MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_L_VAL, MT_W_VAL}},
	{MT_FUNC(munge_wwwlww), 7, 6, {MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_L_VAL, MT_W_VAL, MT_W_VAL}},
	{MT_FUNC(munge_wwwlwww), 8, 7, {MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_L_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL}},
	{MT_FUNC(munge_wwwl), 5, 4, {MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_L_VAL}},
	{MT_FUNC(munge_wwwwlw), 7, 6, {MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_L_VAL, MT_W_VAL}},
	{MT_FUNC(munge_wwwwllww), 10, 8, {MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_L_VAL, MT_L_VAL, MT_W_VAL, MT_W_VAL}},
	{MT_FUNC(munge_wwwwl), 6, 5, {MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_L_VAL}},
	{MT_FUNC(munge_wwwwwl), 7, 6, {MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_L_VAL}},
	{MT_FUNC(munge_wwwwwlww), 9, 8, {MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_L_VAL, MT_W_VAL, MT_W_VAL}},
	{MT_FUNC(munge_wwwwwllw), 10, 8, {MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_L_VAL, MT_L_VAL, MT_W_VAL}},
	{MT_FUNC(munge_wwwwwlll), 11, 8, {MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_L_VAL, MT_L_VAL, MT_L_VAL}},
	{MT_FUNC(munge_wwwwwwl), 8, 7, {MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_L_VAL}},
	{MT_FUNC(munge_wwwwwwlw), 9, 8, {MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_L_VAL, MT_W_VAL}},
	{MT_FUNC(munge_wwwwwwll), 10, 8, {MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_L_VAL, MT_L_VAL}},
	{MT_FUNC(munge_wsw), 3, 3, {MT_W_VAL, MT_S_VAL, MT_W_VAL}},
	{MT_FUNC(munge_wws), 3, 3, {MT_W_VAL, MT_W_VAL, MT_S_VAL}},
	{MT_FUNC(munge_wwwsw), 5, 5, {MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_S_VAL, MT_W_VAL}},
	{MT_FUNC(munge_llllll), 12, 6, {MT_L_VAL, MT_L_VAL, MT_L_VAL, MT_L_VAL, MT_L_VAL, MT_L_VAL}},
	{MT_FUNC(munge_llll), 8, 4, {MT_L_VAL, MT_L_VAL, MT_L_VAL, MT_L_VAL}},
	{MT_FUNC(munge_l), 2, 1, {MT_L_VAL}},
	{MT_FUNC(munge_lw), 3, 2, {MT_L_VAL, MT_W_VAL}},
	{MT_FUNC(munge_lww), 4, 3, {MT_L_VAL, MT_W_VAL, MT_W_VAL}},
	{MT_FUNC(munge_lwww), 5, 4, {MT_L_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL}},
	{MT_FUNC(munge_lwwwwwww), 9, 8, {MT_L_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL}},
	{MT_FUNC(munge_wlwwwl), 8, 6, {MT_W_VAL, MT_L_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_L_VAL}},
	{MT_FUNC(munge_wwlwwwl), 9, 7, {MT_W_VAL, MT_W_VAL, MT_L_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_L_VAL}}
};

#define MT_TEST_COUNT (sizeof(munger_tests) / sizeof(struct munger_test))

static void
mt_reset(uint32_t in_words, size_t total_size, uint32_t *data)
{
	uint32_t i;

	for (i = 0; i < in_words; i++) {
		data[i] = MT_INITIAL_VALUE;
	}

	if (in_words * sizeof(uint32_t) < total_size) {
		bzero(&data[in_words], total_size - in_words * sizeof(uint32_t));
	}
}

static void
mt_test_mungers()
{
	uint64_t data[MT_MAX_ARGS];
	uint32_t i, j;

	for (i = 0; i < MT_TEST_COUNT; i++) {
		struct munger_test *test = &munger_tests[i];
		int pass = 1;

		T_LOG("Testing %s", test->mt_name);

		mt_reset(test->mt_in_words, sizeof(data), (uint32_t*)data);
		test->mt_func(data);

		for (j = 0; j < test->mt_nout; j++) {
			if (data[j] != test->mt_expected[j]) {
				T_FAIL("Index %d: expected %llx, got %llx.", j, test->mt_expected[j], data[j]);
				pass = 0;
			}
		}
		if (pass) {
			T_PASS(test->mt_name);
		}
	}
}

#if defined(HAS_APPLE_PAC)


kern_return_t
arm64_ropjop_test()
{
	T_LOG("Testing ROP/JOP");

	/* how is ROP/JOP configured */
	boolean_t config_rop_enabled = TRUE;
	boolean_t config_jop_enabled = TRUE;


	if (config_jop_enabled) {
		/* jop key */
		uint64_t apiakey_hi = __builtin_arm_rsr64("APIAKEYHI_EL1");
		uint64_t apiakey_lo = __builtin_arm_rsr64("APIAKEYLO_EL1");

		T_EXPECT(apiakey_hi != 0 && apiakey_lo != 0, NULL);
	}

	if (config_rop_enabled) {
		/* rop key */
		uint64_t apibkey_hi = __builtin_arm_rsr64("APIBKEYHI_EL1");
		uint64_t apibkey_lo = __builtin_arm_rsr64("APIBKEYLO_EL1");

		T_EXPECT(apibkey_hi != 0 && apibkey_lo != 0, NULL);

		/* sign a KVA (the address of this function) */
		uint64_t kva_signed = (uint64_t) ptrauth_sign_unauthenticated((void *)&config_rop_enabled, ptrauth_key_asib, 0);

		/* assert it was signed (changed) */
		T_EXPECT(kva_signed != (uint64_t)&config_rop_enabled, NULL);

		/* authenticate the newly signed KVA */
		uint64_t kva_authed = (uint64_t) ml_auth_ptr_unchecked((void *)kva_signed, ptrauth_key_asib, 0);

		/* assert the authed KVA is the original KVA */
		T_EXPECT(kva_authed == (uint64_t)&config_rop_enabled, NULL);

		/* corrupt a signed ptr, auth it, ensure auth failed */
		uint64_t kva_corrupted = kva_signed ^ 1;

		/* authenticate the corrupted pointer */
		kva_authed = (uint64_t) ml_auth_ptr_unchecked((void *)kva_corrupted, ptrauth_key_asib, 0);

		/* when AuthIB fails, bits 63:62 will be set to 2'b10 */
		uint64_t auth_fail_mask = 3ULL << 61;
		uint64_t authib_fail = 2ULL << 61;

		/* assert the failed authIB of corrupted pointer is tagged */
		T_EXPECT((kva_authed & auth_fail_mask) == authib_fail, NULL);
	}

	return KERN_SUCCESS;
}
#endif /* defined(HAS_APPLE_PAC) */

#if __ARM_PAN_AVAILABLE__

struct pan_test_thread_args {
	volatile bool join;
};

static void
arm64_pan_test_thread(void *arg, wait_result_t __unused wres)
{
	T_ASSERT(__builtin_arm_rsr("pan") != 0, NULL);

	struct pan_test_thread_args *args = arg;

	for (processor_t p = processor_list; p != NULL; p = p->processor_list) {
		thread_bind(p);
		thread_block(THREAD_CONTINUE_NULL);
		kprintf("Running PAN test on cpu %d\n", p->cpu_id);
		arm64_pan_test();
	}

	/* unbind thread from specific cpu */
	thread_bind(PROCESSOR_NULL);
	thread_block(THREAD_CONTINUE_NULL);

	while (!args->join) {
		;
	}

	thread_wakeup(args);
}

kern_return_t
arm64_late_pan_test()
{
	thread_t thread;
	kern_return_t kr;

	struct pan_test_thread_args args;
	args.join = false;

	kr = kernel_thread_start(arm64_pan_test_thread, &args, &thread);
	assert(kr == KERN_SUCCESS);

	thread_deallocate(thread);

	assert_wait(&args, THREAD_UNINT);
	args.join = true;
	thread_block(THREAD_CONTINUE_NULL);
	return KERN_SUCCESS;
}

// Disable KASAN checking for PAN tests as the fixed commpage address doesn't have a shadow mapping

static NOKASAN bool
arm64_pan_test_pan_enabled_fault_handler(arm_saved_state_t * state)
{
	bool retval                 = false;
	uint64_t esr                = get_saved_state_esr(state);
	esr_exception_class_t class = ESR_EC(esr);
	fault_status_t fsc          = ISS_IA_FSC(ESR_ISS(esr));
	uint32_t cpsr               = get_saved_state_cpsr(state);
	uint64_t far                = get_saved_state_far(state);

	if ((class == ESR_EC_DABORT_EL1) && (fsc == FSC_PERMISSION_FAULT_L3) &&
	    (cpsr & PSR64_PAN) &&
	    ((esr & ISS_DA_WNR) ? mmu_kvtop_wpreflight(far) : mmu_kvtop(far))) {
		++pan_exception_level;
		// read the user-accessible value to make sure
		// pan is enabled and produces a 2nd fault from
		// the exception handler
		if (pan_exception_level == 1) {
			ml_expect_fault_begin(arm64_pan_test_pan_enabled_fault_handler, far);
			pan_fault_value = *(volatile char *)far;
			ml_expect_fault_end();
			__builtin_arm_wsr("pan", 1); // turn PAN back on after the nested exception cleared it for this context
		}
		// this fault address is used for PAN test
		// disable PAN and rerun
		mask_saved_state_cpsr(state, 0, PSR64_PAN);

		retval = true;
	}

	return retval;
}

static NOKASAN bool
arm64_pan_test_pan_disabled_fault_handler(arm_saved_state_t * state)
{
	bool retval             = false;
	uint64_t esr            = get_saved_state_esr(state);
	esr_exception_class_t class = ESR_EC(esr);
	fault_status_t fsc      = ISS_IA_FSC(ESR_ISS(esr));
	uint32_t cpsr           = get_saved_state_cpsr(state);

	if ((class == ESR_EC_DABORT_EL1) && (fsc == FSC_PERMISSION_FAULT_L3) &&
	    !(cpsr & PSR64_PAN)) {
		++pan_exception_level;
		// On an exception taken from a PAN-disabled context, verify
		// that PAN is re-enabled for the exception handler and that
		// accessing the test address produces a PAN fault.
		ml_expect_fault_begin(arm64_pan_test_pan_enabled_fault_handler, pan_test_addr);
		pan_fault_value = *(volatile char *)pan_test_addr;
		ml_expect_fault_end();
		__builtin_arm_wsr("pan", 1); // turn PAN back on after the nested exception cleared it for this context
		add_saved_state_pc(state, 4);

		retval = true;
	}

	return retval;
}

NOKASAN kern_return_t
arm64_pan_test()
{
	bool values_match = false;
	vm_offset_t priv_addr = 0;

	T_LOG("Testing PAN.");


	T_ASSERT((__builtin_arm_rsr("SCTLR_EL1") & SCTLR_PAN_UNCHANGED) == 0, "SCTLR_EL1.SPAN must be cleared");

	T_ASSERT(__builtin_arm_rsr("pan") != 0, NULL);

	pan_exception_level = 0;
	pan_fault_value = 0xDE;

	// Create an empty pmap, so we can map a user-accessible page
	pmap_t pmap = pmap_create_options(NULL, 0, PMAP_CREATE_64BIT);
	T_ASSERT(pmap != NULL, NULL);

	// Get a physical page to back the mapping
	vm_page_t vm_page = vm_page_grab();
	T_ASSERT(vm_page != VM_PAGE_NULL, NULL);
	ppnum_t pn = VM_PAGE_GET_PHYS_PAGE(vm_page);
	pmap_paddr_t pa = ptoa(pn);

	// Write to the underlying physical page through the physical aperture
	// so we can test against a known value
	priv_addr = phystokv((pmap_paddr_t)pa);
	*(volatile char *)priv_addr = 0xAB;

	// Map the page in the user address space at some, non-zero address
	pan_test_addr = PAGE_SIZE;
	pmap_enter(pmap, pan_test_addr, pn, VM_PROT_READ, VM_PROT_READ, 0, true, PMAP_MAPPING_TYPE_INFER);

	// Context-switch with PAN disabled is prohibited; prevent test logging from
	// triggering a voluntary context switch.
	mp_disable_preemption();

	// Insert the user's pmap root table pointer in TTBR0
	thread_t thread = current_thread();
	pmap_t old_pmap = vm_map_pmap(thread->map);
	pmap_switch(pmap, thread);

	// Below should trigger a PAN exception as pan_test_addr is accessible
	// in user mode
	// The exception handler, upon recognizing the fault address is pan_test_addr,
	// will disable PAN and rerun this instruction successfully
	ml_expect_fault_begin(arm64_pan_test_pan_enabled_fault_handler, pan_test_addr);
	values_match = (*(volatile char *)pan_test_addr == *(volatile char *)priv_addr);
	ml_expect_fault_end();
	T_ASSERT(values_match, NULL);

	T_ASSERT(pan_exception_level == 2, NULL);

	T_ASSERT(__builtin_arm_rsr("pan") == 0, NULL);

	T_ASSERT(pan_fault_value == *(char *)priv_addr, NULL);

	pan_exception_level = 0;
	pan_fault_value = 0xAD;
	pan_ro_addr = (vm_offset_t) &pan_ro_value;

	// Force a permission fault while PAN is disabled to make sure PAN is
	// re-enabled during the exception handler.
	ml_expect_fault_begin(arm64_pan_test_pan_disabled_fault_handler, pan_ro_addr);
	*((volatile uint64_t*)pan_ro_addr) = 0xFEEDFACECAFECAFE;
	ml_expect_fault_end();

	T_ASSERT(pan_exception_level == 2, NULL);

	T_ASSERT(__builtin_arm_rsr("pan") == 0, NULL);

	T_ASSERT(pan_fault_value == *(char *)priv_addr, NULL);

	pmap_switch(old_pmap, thread);

	pan_ro_addr = 0;

	__builtin_arm_wsr("pan", 1);

	mp_enable_preemption();

	pmap_remove(pmap, pan_test_addr, pan_test_addr + PAGE_SIZE);
	pan_test_addr = 0;

	vm_page_lock_queues();
	vm_page_free(vm_page);
	vm_page_unlock_queues();
	pmap_destroy(pmap);

	return KERN_SUCCESS;
}
#endif /* __ARM_PAN_AVAILABLE__ */


kern_return_t
arm64_lock_test()
{
	return lt_test_locks();
}

kern_return_t
arm64_munger_test()
{
	mt_test_mungers();
	return 0;
}

#if (defined(KERNEL_INTEGRITY_CTRR) || defined(KERNEL_INTEGRITY_PV_CTRR)) && defined(CONFIG_XNUPOST)
SECURITY_READ_ONLY_LATE(uint64_t) ctrr_ro_test;
uint64_t ctrr_nx_test = 0xd65f03c0; /* RET */
volatile uint64_t ctrr_exception_esr;
vm_offset_t ctrr_test_va;
vm_offset_t ctrr_test_page;
atomic_bool ctrr_test_in_progress;

kern_return_t
ctrr_test(void)
{
	processor_t p;

	/*
	 * The test uses some globals and also a specific reserved VA region, so it
	 * can't run concurrently.  This might otherwise happen via the sysctl
	 * interface.
	 */
	bool expected = false;
	if (!atomic_compare_exchange_strong_explicit(&ctrr_test_in_progress,
	    &expected, true,
	    memory_order_acq_rel, memory_order_relaxed)) {
		T_FAIL("Can't run multiple CTRR tests at once");
		return KERN_SUCCESS;
	}


	T_LOG("Running CTRR test.");

	for (p = processor_list; p != NULL; p = p->processor_list) {
		thread_bind(p);
		thread_block(THREAD_CONTINUE_NULL);
		T_LOG("Running CTRR test on CPU %d\n", p->cpu_id);
		ctrr_test_cpu();
	}

	/* unbind thread from specific cpu */
	thread_bind(PROCESSOR_NULL);
	thread_block(THREAD_CONTINUE_NULL);

	T_PASS("Done running CTRR test on all CPUs");
	atomic_store_explicit(&ctrr_test_in_progress, false, memory_order_release);

	return KERN_SUCCESS;
}

static bool
ctrr_test_ro_fault_handler(arm_saved_state_t * state)
{
	bool retval                 = false;
	uint64_t esr                = get_saved_state_esr(state);
	esr_exception_class_t class = ESR_EC(esr);
	fault_status_t fsc          = ISS_DA_FSC(ESR_ISS(esr));

	if ((class == ESR_EC_DABORT_EL1) && (fsc == FSC_PERMISSION_FAULT_L3)) {
		ctrr_exception_esr = esr;
		add_saved_state_pc(state, 4);
		retval = true;
	}

	return retval;
}

static bool
ctrr_test_nx_fault_handler(arm_saved_state_t * state)
{
	bool retval                 = false;
	uint64_t esr                = get_saved_state_esr(state);
	esr_exception_class_t class = ESR_EC(esr);
	fault_status_t fsc          = ISS_IA_FSC(ESR_ISS(esr));

	if ((class == ESR_EC_IABORT_EL1) && (fsc == FSC_PERMISSION_FAULT_L3)) {
		ctrr_exception_esr = esr;
		/* return to the instruction immediately after the call to NX page */
		set_saved_state_pc(state, get_saved_state_lr(state));
#if BTI_ENFORCED
		/* Clear BTYPE to prevent taking another exception on ERET */
		uint32_t spsr = get_saved_state_cpsr(state);
		spsr &= ~PSR_BTYPE_MASK;
		set_saved_state_cpsr(state, spsr);
#endif /* BTI_ENFORCED */
		retval = true;
	}

	return retval;
}

// Disable KASAN checking for CTRR tests as the test VA  doesn't have a shadow mapping

/* test CTRR on a cpu, caller to bind thread to desired cpu */
/* ctrr_test_page was reserved during bootstrap process if no SPTM */
NOKASAN kern_return_t
ctrr_test_cpu(void)
{
	ppnum_t ro_pn, nx_pn;
	uint64_t *ctrr_ro_test_ptr;
	void (*ctrr_nx_test_ptr)(void);
	kern_return_t kr;
	uint64_t prot = 0;
	extern vm_offset_t virtual_space_start;
	extern vm_offset_t rorgn_begin;
	extern vm_offset_t rorgn_end;

	vm_offset_t ro_test_va = (vm_offset_t)&ctrr_ro_test;
	vm_offset_t nx_test_va = (vm_offset_t)&ctrr_nx_test;
	bool ctrr_enabled = !ml_unsafe_kernel_text();

#if CONFIG_SPTM
	if (/* DISABLES CODE */ (1)) {
		T_SKIP("Skipping CTRR test because testing under SPTM is not supported yet");
		return KERN_SUCCESS;
	}
#endif

#if defined(KERNEL_INTEGRITY_PV_CTRR)
	if (rorgn_begin == 0 && rorgn_end == 0) {
		// Under paravirtualized CTRR, it's possible that we want CTRR to be
		// enabled but we're running under an older host that doesn't support
		// it.
		ctrr_enabled = false;
		T_LOG("Treating paravirtualized CTRR as disabled due to lack of support");
	}
#endif

	// The CTRR read-only region is the physical address range [rorgn_begin, rorgn_end].
	// rorgn_end will be one byte short of a page boundary.
	if (ctrr_enabled) {
		T_EXPECT(rorgn_begin != 0, "Expect rorgn_begin to be set when CTRR enabled");
		T_EXPECT_GE_ULONG(rorgn_end, rorgn_begin, "Expect rorgn_end to be >= rorgn_begin when CTRR enabled");

		pmap_paddr_t ro_test_pa = kvtophys_nofail(ro_test_va);
		pmap_paddr_t nx_test_pa = kvtophys_nofail(nx_test_va);

		T_EXPECT(rorgn_begin <= ro_test_pa && ro_test_pa <= rorgn_end, "Expect ro_test_pa to be inside the CTRR region");
		T_EXPECT((nx_test_pa < rorgn_begin) ^ (nx_test_pa > rorgn_end), "Expect nx_test_pa to be outside the CTRR region");
	} else {
		T_EXPECT_EQ_ULONG(rorgn_begin, 0, "Expect rorgn_begin to be unset when CTRR disabled");
		T_EXPECT_EQ_ULONG(rorgn_end, 0, "Expect rorgn_end to be unset when CTRR disabled");
		T_LOG("Skipping region check because CTRR is disabled");
	}

	if (ctrr_enabled) {
		T_LOG("Expect no faults when reading CTRR region to verify correct programming of CTRR limits");
		for (pmap_paddr_t page_pa = rorgn_begin; page_pa <= rorgn_end; page_pa += PAGE_SIZE) {
			vm_offset_t page_va = phystokv(page_pa);
			for (vm_offset_t va = page_va; va < page_va + PAGE_SIZE; va += 8) {
				volatile uint64_t x = *(uint64_t *)va;
				(void) x; /* read for side effect only */
			}
		}
	} else {
		T_LOG("Skipping read test because CTRR is disabled");
	}

	ro_pn = pmap_find_phys(kernel_pmap, ro_test_va);
	nx_pn = pmap_find_phys(kernel_pmap, nx_test_va);
	T_EXPECT(ro_pn && nx_pn, "Expect ro page number and nx page number to be non zero");

	T_LOG("test virtual page: %p, ctrr_ro_test: %p, ctrr_nx_test: %p, ro_pn: %x, nx_pn: %x ",
	    (void *)ctrr_test_page, &ctrr_ro_test, &ctrr_nx_test, ro_pn, nx_pn);
	T_ASSERT(ctrr_test_page != 0, "Expect ctrr_test_page to be initialized");

	prot = pmap_get_arm64_prot(kernel_pmap, ctrr_test_page);
	T_EXPECT(~prot & ARM_TTE_VALID, "Expect ctrr_test_page to be unmapped");

	T_LOG("Read only region test mapping virtual page %p to CTRR RO page number %d", ctrr_test_page, ro_pn);
	kr = pmap_enter(kernel_pmap, ctrr_test_page, ro_pn,
	    VM_PROT_READ | VM_PROT_WRITE, VM_PROT_NONE, VM_WIMG_USE_DEFAULT, FALSE, PMAP_MAPPING_TYPE_INFER);
	T_EXPECT(kr == KERN_SUCCESS, "Expect pmap_enter of RW mapping to succeed");

	// assert entire mmu prot path (Hierarchical protection model) is NOT RO
	// fetch effective block level protections from table/block entries
	prot = pmap_get_arm64_prot(kernel_pmap, ctrr_test_page);
	T_EXPECT(ARM_PTE_EXTRACT_AP(prot) == AP_RWNA && (prot & ARM_PTE_PNX), "Mapping is EL1 RWNX");

	ctrr_test_va = ctrr_test_page + (ro_test_va & PAGE_MASK);
	ctrr_ro_test_ptr = (void *)ctrr_test_va;

	T_LOG("Read only region test writing to %p to provoke data abort", ctrr_ro_test_ptr);

	// should cause data abort
	ml_expect_fault_begin(ctrr_test_ro_fault_handler, ctrr_test_va);
	*ctrr_ro_test_ptr = 1;
	ml_expect_fault_end();

	// ensure write permission fault at expected level
	// data abort handler will set ctrr_exception_esr when ctrr_test_va takes a permission fault

	if (ctrr_enabled) {
		T_EXPECT(ESR_EC(ctrr_exception_esr) == ESR_EC_DABORT_EL1, "Data Abort from EL1 expected");
		T_EXPECT(ISS_DA_FSC(ESR_ISS(ctrr_exception_esr)) == FSC_PERMISSION_FAULT_L3, "Permission Fault Expected");
		T_EXPECT(ESR_ISS(ctrr_exception_esr) & ISS_DA_WNR, "Write Fault Expected");
	} else {
		T_EXPECT(ctrr_exception_esr == 0, "No fault expected with CTRR disabled");
	}

	ctrr_test_va = 0;
	ctrr_exception_esr = 0;
	pmap_remove(kernel_pmap, ctrr_test_page, ctrr_test_page + PAGE_SIZE);

	T_LOG("No execute test mapping virtual page %p to CTRR PXN page number %d", ctrr_test_page, nx_pn);

	kr = pmap_enter(kernel_pmap, ctrr_test_page, nx_pn,
	    VM_PROT_READ | VM_PROT_EXECUTE, VM_PROT_NONE, VM_WIMG_USE_DEFAULT, FALSE, PMAP_MAPPING_TYPE_INFER);

	T_EXPECT(kr == KERN_SUCCESS, "Expect pmap_enter of RX mapping to succeed");

	// assert entire mmu prot path (Hierarchical protection model) is NOT XN
	prot = pmap_get_arm64_prot(kernel_pmap, ctrr_test_page);
	T_EXPECT(ARM_PTE_EXTRACT_AP(prot) == AP_RONA && (~prot & ARM_PTE_PNX), "Mapping is EL1 ROX (prot=0x%lx)", prot);

	ctrr_test_va = ctrr_test_page + (nx_test_va & PAGE_MASK);
#if __has_feature(ptrauth_calls)
	ctrr_nx_test_ptr = ptrauth_sign_unauthenticated((void *)ctrr_test_va, ptrauth_key_function_pointer, 0);
#else
	ctrr_nx_test_ptr = (void *)ctrr_test_va;
#endif

	T_LOG("No execute test calling ctrr_nx_test_ptr(): %p to provoke instruction abort", ctrr_nx_test_ptr);

	// should cause prefetch abort
	ml_expect_fault_begin(ctrr_test_nx_fault_handler, ctrr_test_va);
	ctrr_nx_test_ptr();
	ml_expect_fault_end();

	if (ctrr_enabled) {
		// FIXME: rdar://143430725 (xnu support for paravirtualized CTXR)
		// Without FEAT_XNX support on the host side, we cannot test kernel execution outside CTXR regions.
#if !defined(KERNEL_INTEGRITY_PV_CTRR)
		// TODO: ensure execute permission fault at expected level
		T_EXPECT(ESR_EC(ctrr_exception_esr) == ESR_EC_IABORT_EL1, "Instruction abort from EL1 Expected");
		T_EXPECT(ISS_DA_FSC(ESR_ISS(ctrr_exception_esr)) == FSC_PERMISSION_FAULT_L3, "Permission Fault Expected");
#endif /* !defined(KERNEL_INTEGRITY_PV_CTRR) */
	} else {
		T_EXPECT(ctrr_exception_esr == 0, "No fault expected with CTRR disabled");
	}

	ctrr_test_va = 0;
	ctrr_exception_esr = 0;

	pmap_remove(kernel_pmap, ctrr_test_page, ctrr_test_page + PAGE_SIZE);

	return KERN_SUCCESS;
}
#endif /* (defined(KERNEL_INTEGRITY_CTRR) || defined(KERNEL_INTEGRITY_PV_CTRR)) && defined(CONFIG_XNUPOST) */


/**
 * Explicitly assert that xnu is still uniprocessor before running a POST test.
 *
 * In practice, tests in this module can safely manipulate CPU state without
 * fear of getting preempted.  There's no way for cpu_boot_thread() to bring up
 * the secondary CPUs until StartIOKitMatching() completes, and arm64 orders
 * kern_post_test() before StartIOKitMatching().
 *
 * But this is also an implementation detail.  Tests that rely on this ordering
 * should call assert_uniprocessor(), so that we can figure out a workaround
 * on the off-chance this ordering ever changes.
 */
__unused static void
assert_uniprocessor(void)
{
	extern unsigned int real_ncpus;
	unsigned int ncpus = os_atomic_load(&real_ncpus, relaxed);
	T_QUIET; T_ASSERT_EQ_UINT(1, ncpus, "arm64 kernel POST tests should run before any secondary CPUs are brought up");
}


#if CONFIG_SPTM
volatile uint8_t xnu_post_panic_lockdown_did_fire = false;
typedef uint64_t (panic_lockdown_helper_fcn_t)(uint64_t raw);
typedef bool (panic_lockdown_precondition_fcn_t)(void);
typedef bool (panic_lockdown_recovery_fcn_t)(arm_saved_state_t *);

/* SP0 vector tests */
extern panic_lockdown_helper_fcn_t arm64_panic_lockdown_test_load;
extern panic_lockdown_helper_fcn_t arm64_panic_lockdown_test_gdbtrap;
extern panic_lockdown_helper_fcn_t arm64_panic_lockdown_test_pac_brk_c470;
extern panic_lockdown_helper_fcn_t arm64_panic_lockdown_test_pac_brk_c471;
extern panic_lockdown_helper_fcn_t arm64_panic_lockdown_test_pac_brk_c472;
extern panic_lockdown_helper_fcn_t arm64_panic_lockdown_test_pac_brk_c473;
extern panic_lockdown_helper_fcn_t arm64_panic_lockdown_test_telemetry_brk_ff00;
extern panic_lockdown_helper_fcn_t arm64_panic_lockdown_test_br_auth_fail;
extern panic_lockdown_helper_fcn_t arm64_panic_lockdown_test_ldr_auth_fail;
extern panic_lockdown_helper_fcn_t arm64_panic_lockdown_test_fpac;
extern panic_lockdown_helper_fcn_t arm64_panic_lockdown_test_copyio;
extern uint8_t arm64_panic_lockdown_test_copyio_fault_pc;
#if HAS_MTE
extern panic_lockdown_helper_fcn_t arm64_panic_lockdown_test_copyio_tag_check_fault_recoverable;
extern uint8_t arm64_panic_lockdown_test_copyio_tag_check_fault_recoverable_fault_pc;
#endif /* HAS_MTE */

extern int gARM_FEAT_FPACCOMBINE;

/* SP1 vector tests */
extern panic_lockdown_helper_fcn_t arm64_panic_lockdown_test_sp1_invalid_stack;
extern bool arm64_panic_lockdown_test_sp1_invalid_stack_handler(arm_saved_state_t *);
extern panic_lockdown_helper_fcn_t arm64_panic_lockdown_test_sp1_exception_in_vector;
extern panic_lockdown_helper_fcn_t el1_sp1_synchronous_raise_exception_in_vector;
extern bool arm64_panic_lockdown_test_sp1_exception_in_vector_handler(arm_saved_state_t *);

#if DEVELOPMENT || DEBUG
extern struct panic_lockdown_initiator_state debug_panic_lockdown_initiator_state;
#endif /* DEVELOPMENT || DEBUG */

typedef struct arm64_panic_lockdown_test_case {
	const char *name;
	panic_lockdown_helper_fcn_t *func;
	uint64_t arg;
	panic_lockdown_precondition_fcn_t *precondition;
	esr_exception_class_t expected_ec;
	bool check_fs;
	fault_status_t expected_fs;
	bool expect_lockdown_exceptions_masked;
	bool expect_lockdown_exceptions_unmasked;
	bool override_expected_fault_pc_valid;
	uint64_t override_expected_fault_pc;
} arm64_panic_lockdown_test_case_s;

static arm64_panic_lockdown_test_case_s *arm64_panic_lockdown_active_test;
static volatile bool arm64_panic_lockdown_caught_exception;

static bool
arm64_panic_lockdown_test_exception_handler(arm_saved_state_t * state)
{
	uint64_t esr = get_saved_state_esr(state);
	esr_exception_class_t class = ESR_EC(esr);
	fault_status_t fs = ISS_DA_FSC(ESR_ISS(esr));

	if (!arm64_panic_lockdown_active_test ||
	    class != arm64_panic_lockdown_active_test->expected_ec ||
	    (arm64_panic_lockdown_active_test->check_fs &&
	    fs != arm64_panic_lockdown_active_test->expected_fs)) {
		return false;
	}


#if BTI_ENFORCED
	/* Clear BTYPE to prevent taking another exception on ERET */
	uint32_t spsr = get_saved_state_cpsr(state);
	spsr &= ~PSR_BTYPE_MASK;
	set_saved_state_cpsr(state, spsr);
#endif /* BTI_ENFORCED */

	/* We got the expected exception, recover by forging an early return */
	set_saved_state_pc(state, get_saved_state_lr(state));
	arm64_panic_lockdown_caught_exception = true;

	return true;
}

static void
panic_lockdown_expect_test(const char *treatment,
    arm64_panic_lockdown_test_case_s *test,
    bool expect_lockdown,
    bool mask_interrupts)
{
	int ints = 0;

	arm64_panic_lockdown_active_test = test;
	xnu_post_panic_lockdown_did_fire = false;
	arm64_panic_lockdown_caught_exception = false;

	uintptr_t fault_pc;
	if (test->override_expected_fault_pc_valid) {
		fault_pc = (uintptr_t)test->override_expected_fault_pc;
	} else {
		fault_pc = (uintptr_t)test->func;
#ifdef BTI_ENFORCED
		/* When BTI is enabled, we expect the fault to occur after the landing pad */
		fault_pc += 4;
#endif /* BTI_ENFORCED */
	}


	ml_expect_fault_pc_begin(
		arm64_panic_lockdown_test_exception_handler,
		fault_pc);

	if (mask_interrupts) {
		ints = ml_set_interrupts_enabled(FALSE);
	}

	(void)test->func(test->arg);

	if (mask_interrupts) {
		(void)ml_set_interrupts_enabled(ints);
	}

	ml_expect_fault_end();

	if (expect_lockdown == xnu_post_panic_lockdown_did_fire &&
	    arm64_panic_lockdown_caught_exception) {
		T_PASS("%s + %s OK\n", test->name, treatment);
	} else {
		T_FAIL(
			"%s + %s FAIL (expected lockdown: %d, did lockdown: %d, caught exception: %d)\n",
			test->name, treatment,
			expect_lockdown, xnu_post_panic_lockdown_did_fire,
			arm64_panic_lockdown_caught_exception);
	}

#if DEVELOPMENT || DEBUG
	/* Check that the debug info is minimally functional */
	if (expect_lockdown) {
		T_EXPECT_NE_ULLONG(debug_panic_lockdown_initiator_state.initiator_pc,
		    0ULL, "Initiator PC set");
	} else {
		T_EXPECT_EQ_ULLONG(debug_panic_lockdown_initiator_state.initiator_pc,
		    0ULL, "Initiator PC not set");
	}

	/* Reset the debug data so it can be filled later if needed */
	debug_panic_lockdown_initiator_state.initiator_pc = 0;
#endif /* DEVELOPMENT || DEBUG */
}

static void
panic_lockdown_expect_fault_raw(const char *label,
    panic_lockdown_helper_fcn_t entrypoint,
    panic_lockdown_helper_fcn_t faulting_function,
    expected_fault_handler_t fault_handler)
{
	uint64_t test_success = 0;
	xnu_post_panic_lockdown_did_fire = false;

	uintptr_t fault_pc = (uintptr_t)faulting_function;
#ifdef BTI_ENFORCED
	/* When BTI is enabled, we expect the fault to occur after the landing pad */
	fault_pc += 4;
#endif /* BTI_ENFORCED */

	ml_expect_fault_pc_begin(fault_handler, fault_pc);

	test_success = entrypoint(0);

	ml_expect_fault_end();

	if (test_success && xnu_post_panic_lockdown_did_fire) {
		T_PASS("%s OK\n", label);
	} else {
		T_FAIL("%s FAIL (test returned: %d, did lockdown: %d)\n",
		    label, test_success, xnu_post_panic_lockdown_did_fire);
	}
}

/**
 * Returns a pointer which is guranteed to be invalid under IA with the zero
 * discriminator.
 *
 * This is somewhat over complicating it since it's exceedingly likely that a
 * any given pointer will have a zero PAC (and thus break the test), but it's
 * easy enough to avoid the problem.
 */
static uint64_t
panic_lockdown_pacia_get_invalid_ptr()
{
	char *unsigned_ptr = (char *)0xFFFFFFFFAABBCC00;
	char *signed_ptr = NULL;
	do {
		unsigned_ptr += 4 /* avoid alignment exceptions */;
		signed_ptr = ptrauth_sign_unauthenticated(
			unsigned_ptr,
			ptrauth_key_asia,
			0);
	} while ((uint64_t)unsigned_ptr == (uint64_t)signed_ptr);

	return (uint64_t)unsigned_ptr;
}

/**
 * Returns a pointer which is guranteed to be invalid under DA with the zero
 * discriminator.
 */
static uint64_t
panic_lockdown_pacda_get_invalid_ptr(void)
{
	char *unsigned_ptr = (char *)0xFFFFFFFFAABBCC00;
	char *signed_ptr = NULL;
	do {
		unsigned_ptr += 8 /* avoid alignment exceptions */;
		signed_ptr = ptrauth_sign_unauthenticated(
			unsigned_ptr,
			ptrauth_key_asda,
			0);
	} while ((uint64_t)unsigned_ptr == (uint64_t)signed_ptr);

	return (uint64_t)unsigned_ptr;
}

#if HAS_MTE
static bool
arm64_panic_lockdown_is_mte_enabled(void)
{
	if (!mte_kern_enabled()) {
		T_LOG("MTE disabled");
		return false;
	}
	return true;
}
#endif /* HAS_MTE */

kern_return_t
arm64_panic_lockdown_test(void)
{
#if __has_feature(ptrauth_calls)
	uint64_t ia_invalid = panic_lockdown_pacia_get_invalid_ptr();
#endif /* ptrauth_calls */

#if HAS_MTE
	/*
	 * Generate a kernel pointer with an invalid/wrong tag by grabbing an
	 * arbitrary pointer (in this case, a canonically tagged global) and
	 * advancing the tag by one.
	 */
	uintptr_t kernel_ptr_invalid_tag = (uintptr_t)__arm_mte_increment_tag(
		&xnu_post_panic_lockdown_did_fire, 1);
#endif /* HAS_MTE */
	arm64_panic_lockdown_test_case_s tests[] = {
		{
			.name = "arm64_panic_lockdown_test_load",
			.func = &arm64_panic_lockdown_test_load,
			/* Trigger a null deref */
			.arg = (uint64_t)NULL,
			.expected_ec = ESR_EC_DABORT_EL1,
			.expect_lockdown_exceptions_masked = true,
			.expect_lockdown_exceptions_unmasked = false,
		},
		{
			.name = "arm64_panic_lockdown_test_gdbtrap",
			.func = &arm64_panic_lockdown_test_gdbtrap,
			.arg = 0,
			.expected_ec = ESR_EC_UNCATEGORIZED,
			/* GDBTRAP instructions should be allowed everywhere */
			.expect_lockdown_exceptions_masked = false,
			.expect_lockdown_exceptions_unmasked = false,
		},
#if __has_feature(ptrauth_calls)
		{
			.name = "arm64_panic_lockdown_test_pac_brk_c470",
			.func = &arm64_panic_lockdown_test_pac_brk_c470,
			.arg = 0,
			.expected_ec = ESR_EC_BRK_AARCH64,
			.expect_lockdown_exceptions_masked = true,
			.expect_lockdown_exceptions_unmasked = true,
		},
		{
			.name = "arm64_panic_lockdown_test_pac_brk_c471",
			.func = &arm64_panic_lockdown_test_pac_brk_c471,
			.arg = 0,
			.expected_ec = ESR_EC_BRK_AARCH64,
			.expect_lockdown_exceptions_masked = true,
			.expect_lockdown_exceptions_unmasked = true,
		},
		{
			.name = "arm64_panic_lockdown_test_pac_brk_c472",
			.func = &arm64_panic_lockdown_test_pac_brk_c472,
			.arg = 0,
			.expected_ec = ESR_EC_BRK_AARCH64,
			.expect_lockdown_exceptions_masked = true,
			.expect_lockdown_exceptions_unmasked = true,
		},
		{
			.name = "arm64_panic_lockdown_test_pac_brk_c473",
			.func = &arm64_panic_lockdown_test_pac_brk_c473,
			.arg = 0,
			.expected_ec = ESR_EC_BRK_AARCH64,
			.expect_lockdown_exceptions_masked = true,
			.expect_lockdown_exceptions_unmasked = true,
		},
		{
			.name = "arm64_panic_lockdown_test_telemetry_brk_ff00",
			.func = &arm64_panic_lockdown_test_telemetry_brk_ff00,
			.arg = 0,
			.expected_ec = ESR_EC_BRK_AARCH64,
			/*
			 * PAC breakpoints are not the only breakpoints, ensure that other
			 * BRKs (like those used for telemetry) do not trigger lockdowns.
			 * This is necessary to avoid conflicts with features like UBSan
			 * telemetry (which could fire at any time in C code).
			 */
			.expect_lockdown_exceptions_masked = false,
			.expect_lockdown_exceptions_unmasked = false,
		},
		{
			.name = "arm64_panic_lockdown_test_br_auth_fail",
			.func = &arm64_panic_lockdown_test_br_auth_fail,
			.arg = ia_invalid,
			.expected_ec = gARM_FEAT_FPACCOMBINE ? ESR_EC_PAC_FAIL : ESR_EC_IABORT_EL1,
			.expect_lockdown_exceptions_masked = true,
			.expect_lockdown_exceptions_unmasked = true,
			/*
			 * Pre-FEAT_FPACCOMBINED, BRAx branches to a poisoned PC so we
			 * expect to fault on the branch target rather than the branch
			 * itself. The exact ELR will likely be different from ia_invalid,
			 * but since the expect logic in sleh only matches on low bits (i.e.
			 * not bits which will be poisoned), this is fine.
			 * On FEAT_FPACCOMBINED devices, we will fault on the branch itself.
			 */
			.override_expected_fault_pc_valid = !gARM_FEAT_FPACCOMBINE,
			.override_expected_fault_pc = ia_invalid
		},
		{
			.name = "arm64_panic_lockdown_test_ldr_auth_fail",
			.func = &arm64_panic_lockdown_test_ldr_auth_fail,
			.arg = panic_lockdown_pacda_get_invalid_ptr(),
			.expected_ec = gARM_FEAT_FPACCOMBINE ? ESR_EC_PAC_FAIL : ESR_EC_DABORT_EL1,
			.expect_lockdown_exceptions_masked = true,
			.expect_lockdown_exceptions_unmasked = true,
		},
		{
			.name = "arm64_panic_lockdown_test_copyio_poison",
			.func = &arm64_panic_lockdown_test_copyio,
			/* fake a poisoned kernel pointer by flipping the bottom PAC bit */
			.arg = ((uint64_t)-1) ^ (1LLU << (64 - T1SZ_BOOT)),
			.expected_ec = ESR_EC_DABORT_EL1,
			.expect_lockdown_exceptions_masked = false,
			.expect_lockdown_exceptions_unmasked = false,
			.override_expected_fault_pc_valid = true,
			.override_expected_fault_pc = (uint64_t)&arm64_panic_lockdown_test_copyio_fault_pc,
		},
#if __ARM_ARCH_8_6__
		{
			.name = "arm64_panic_lockdown_test_fpac",
			.func = &arm64_panic_lockdown_test_fpac,
			.arg = ia_invalid,
			.expected_ec = ESR_EC_PAC_FAIL,
			.expect_lockdown_exceptions_masked = true,
			.expect_lockdown_exceptions_unmasked = true,
		},
#endif /* __ARM_ARCH_8_6__ */
#endif /* ptrauth_calls */
		{
			.name = "arm64_panic_lockdown_test_copyio",
			.func = &arm64_panic_lockdown_test_copyio,
			.arg = 0x0 /* load from NULL */,
			.expected_ec = ESR_EC_DABORT_EL1,
			.expect_lockdown_exceptions_masked = false,
			.expect_lockdown_exceptions_unmasked = false,
			.override_expected_fault_pc_valid = true,
			.override_expected_fault_pc = (uint64_t)&arm64_panic_lockdown_test_copyio_fault_pc,
		},
#if HAS_MTE
		{
			/* Validate that non-copyio tag check fails trigger a lockdown */
			.name = "arm64_panic_lockdown_test_load_mte_fail",
			.func = &arm64_panic_lockdown_test_load,
			.arg = kernel_ptr_invalid_tag,
			.precondition = arm64_panic_lockdown_is_mte_enabled,
			.expected_ec = ESR_EC_DABORT_EL1,
			.check_fs = true,
			.expected_fs = FSC_SYNC_TAG_CHECK_FAULT,
			.expect_lockdown_exceptions_masked = true,
			.expect_lockdown_exceptions_unmasked = true,
		},
		{
			/*
			 * Validate that non-tag check recoverable copyio tag check fails
			 * trigger a lockdown
			 */
			.name = "arm64_panic_lockdown_test_copyio_mte_fail",
			.func = &arm64_panic_lockdown_test_copyio,
			.arg = kernel_ptr_invalid_tag,
			.precondition = arm64_panic_lockdown_is_mte_enabled,
			.expected_ec = ESR_EC_DABORT_EL1,
			.check_fs = true,
			.expected_fs = FSC_SYNC_TAG_CHECK_FAULT,
			.expect_lockdown_exceptions_masked = true,
			.expect_lockdown_exceptions_unmasked = true,
			.override_expected_fault_pc_valid = true,
			.override_expected_fault_pc = (uint64_t)&arm64_panic_lockdown_test_copyio_fault_pc,
		},
#if 0 /* rdar://153476527 */
		{
			/*
			 * Validate that kernel tag check recoverable copyio functions do
			 * not trigger a lockdown on tag check fail.
			 */
			.name = "arm64_panic_lockdown_test_copyio_tag_check_fault_recoverable",
			.func = &arm64_panic_lockdown_test_copyio_tag_check_fault_recoverable,
			.arg = kernel_ptr_invalid_tag,
			.precondition = arm64_panic_lockdown_is_mte_enabled,
			.expected_ec = ESR_EC_DABORT_EL1,
			.check_fs = true,
			.expected_fs = FSC_SYNC_TAG_CHECK_FAULT,
			.expect_lockdown_exceptions_masked = false,
			.expect_lockdown_exceptions_unmasked = false,
			.override_expected_fault_pc_valid = true,
			.override_expected_fault_pc = (uint64_t)&arm64_panic_lockdown_test_copyio_tag_check_fault_recoverable_fault_pc,
		},
#endif /* 0 */
#endif /* HAS_MTE */
	};

	size_t test_count = sizeof(tests) / sizeof(*tests);
	for (size_t i = 0; i < test_count; i++) {
		if (tests[i].precondition &&
		    !tests[i].precondition()) {
			T_LOG("%s skipped due to precondition check", tests[i].name);
			continue;
		}

		panic_lockdown_expect_test(
			"Exceptions unmasked",
			&tests[i],
			tests[i].expect_lockdown_exceptions_unmasked,
			/* mask_interrupts */ false);

		panic_lockdown_expect_test(
			"Exceptions masked",
			&tests[i],
			tests[i].expect_lockdown_exceptions_masked,
			/* mask_interrupts */ true);
	}

	panic_lockdown_expect_fault_raw("arm64_panic_lockdown_test_sp1_invalid_stack",
	    arm64_panic_lockdown_test_sp1_invalid_stack,
	    arm64_panic_lockdown_test_pac_brk_c470,
	    arm64_panic_lockdown_test_sp1_invalid_stack_handler);

	panic_lockdown_expect_fault_raw("arm64_panic_lockdown_test_sp1_exception_in_vector",
	    arm64_panic_lockdown_test_sp1_exception_in_vector,
	    el1_sp1_synchronous_raise_exception_in_vector,
	    arm64_panic_lockdown_test_sp1_exception_in_vector_handler);
	return KERN_SUCCESS;
}
#endif /* CONFIG_SPTM */

#if HAS_MTE
volatile uint64_t mte_test_esr;

static bool
mte_test_fault_handler(arm_saved_state_t *ss)
{
	uint64_t esr = get_saved_state_esr(ss);
	esr_exception_class_t ec = ESR_EC(esr);
	bool ret = false;

	if (ec == ESR_EC_DABORT_EL1) {
		fault_status_t fsc = ISS_IA_FSC(ESR_ISS(esr));
		if (fsc == FSC_SYNC_TAG_CHECK_FAULT) {
			mte_test_esr = esr;
			add_saved_state_pc(ss, 4);
			ret = true;
		}
	}

	return ret;
}

static inline unsigned int
extract_mte_tag(void *ptr)
{
	return (((uintptr_t)ptr) >> 56) & 0xF;
}

kern_return_t
mte_test(void)
{
	if (!mte_kern_enabled()) {
		T_SKIP("MTE disabled");
		return KERN_SUCCESS;
	}

	/* This test needs to manipulate GCR_EL1 without getting preempted */
	assert_uniprocessor();

	vm_address_t address;
	kern_return_t kr;
	const size_t MTE_GRANULE_SIZE = 16;
	const unsigned int NUM_MTE_TAGS = 16;

	/* Allocate a MTE backed page */
	kr = kmem_alloc(kernel_map, &address, PAGE_SIZE, KMA_ZERO | KMA_TAG | KMA_KOBJECT, VM_KERN_MEMORY_DIAG);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "kmem_alloc(KMA_TAG) - allocate an MTE enabled page");
	char *untagged_ptr = (char *)vm_memtag_canonicalize_kernel(address);
	ppnum_t pn = pmap_find_phys(kernel_pmap, address);
	T_ASSERT(pmap_is_tagged_page(pn), "kmem_alloc(KMA_TAG) returned MTE-enabled translation");

	/* Read the originally assigned tag to the page */
	char *orig_tagged_ptr = __arm_mte_get_tag(untagged_ptr);
	T_LOG("__arm_mte_get_tag(%p) == %p\n", untagged_ptr, orig_tagged_ptr);
	unsigned int orig_tag = extract_mte_tag(orig_tagged_ptr);

	/* Exclude the original tag from random tag generation */
	uint64_t mask = __arm_mte_exclude_tag(orig_tagged_ptr, 0);
	T_EXPECT_EQ_ULLONG(mask, 1 << orig_tag, "original tag is excluded");

	char *random_tagged_ptr;
	/*
	 * Generate the random tag.  We've excluded the original tag, so it should never
	 * reappear no matter how many times we regenerate a new tag.
	 */
	for (unsigned int i = 0; i < NUM_MTE_TAGS * 4; i++) {
		random_tagged_ptr = __arm_mte_create_random_tag(untagged_ptr, mask);
		T_QUIET; T_EXPECT_NE_PTR(orig_tagged_ptr, random_tagged_ptr,
		    "random tag was not taken from excluded tag set");

		ptrdiff_t diff = __arm_mte_ptrdiff(untagged_ptr, random_tagged_ptr);
		T_QUIET; T_EXPECT_EQ_ULLONG(diff, 0, "untagged %p and tagged %p have identical address bits",
		    untagged_ptr, random_tagged_ptr);
	}
	T_LOG("__arm_mte_create_random_tag(%p, %llx) == %p\n", untagged_ptr, mask, random_tagged_ptr);

	/*
	 * Globally exclude another tag.  Let's arbitrarily pick orig_tag - 1,
	 * so that it takes effect the 15th time we increment orig_tagged_ptr.
	 */
	uint64_t excluded_tag = (orig_tag + (NUM_MTE_TAGS - 1)) % NUM_MTE_TAGS;
	uint64_t old_gcr_el1 = __builtin_arm_rsr64("GCR_EL1");
	uint64_t new_gcr_el1 = old_gcr_el1 & ~GCR_EL1_EXCLUDE_MASK;
	new_gcr_el1 |= (1 << excluded_tag) << GCR_EL1_EXCLUDE_OFFSET;
	__builtin_arm_wsr64("GCR_EL1", new_gcr_el1);

	char *last_tagged_ptr = orig_tagged_ptr;
	unsigned int last_tag = orig_tag;
	/* Increment the tag until we're just about to reach the excluded one */
	for (unsigned int i = 0; i < NUM_MTE_TAGS - 2; i++) {
		char *next_tagged_ptr = __arm_mte_increment_tag(last_tagged_ptr, 1);
		unsigned int next_tag = extract_mte_tag(next_tagged_ptr);
		T_QUIET; T_EXPECT_EQ_UINT(next_tag, (last_tag + 1) % NUM_MTE_TAGS,
		    "__arm_mte_increment_tag(%p, 1) = %p", last_tagged_ptr, next_tagged_ptr);

		ptrdiff_t diff = __arm_mte_ptrdiff(last_tagged_ptr, next_tagged_ptr);
		T_QUIET; T_EXPECT_EQ_ULLONG(diff, 0, "previous %p and incremented %p have identical address bits",
		    last_tagged_ptr, next_tagged_ptr);

		last_tagged_ptr = next_tagged_ptr;
		last_tag = next_tag;
	}
	/* Increment again, and confirm that we've skipped over the excluded tag */
	char *skip_tagged_ptr = __arm_mte_increment_tag(last_tagged_ptr, 1);
	unsigned int skip_tag = extract_mte_tag(skip_tagged_ptr);
	T_EXPECT_EQ_UINT(skip_tag, orig_tag, "__arm_mte_increment_tag() skipped over excluded tag");

	/* Restore the original tag configuration */
	__builtin_arm_wsr64("GCR_EL1", old_gcr_el1);

	/* Time to make things real, commit the tag to memory */
	__arm_mte_set_tag(random_tagged_ptr);

	/* Ensure that we can read back the tag */
	char *read_back = __arm_mte_get_tag(untagged_ptr);
	T_EXPECT_EQ_PTR(read_back, random_tagged_ptr, "tag was committed to memory correctly");

	/* Verify that accessing memory actually works */
	random_tagged_ptr[0] = 't';
	random_tagged_ptr[1] = 'e';
	random_tagged_ptr[2] = 's';
	random_tagged_ptr[3] = 't';
	T_EXPECT_EQ_STR(random_tagged_ptr, "test", "read/write from tagged memory");

	/*
	 * Confirm that the next MTE granule still has the default tag, and then
	 * simulate an out-of-bounds access into that granule.
	 */
	void *next_granule_ptr = orig_tagged_ptr + MTE_GRANULE_SIZE;
	unsigned int next_granule_tag = extract_mte_tag(next_granule_ptr);
	T_QUIET; T_ASSERT_EQ_UINT(next_granule_tag, orig_tag,
	    "next MTE granule still has its originally assigned tag");

	mte_test_esr = 0;
	ml_expect_fault_begin(mte_test_fault_handler, (uintptr_t)&random_tagged_ptr[MTE_GRANULE_SIZE]);
	random_tagged_ptr[MTE_GRANULE_SIZE] = '!';
	ml_expect_fault_end();
	T_EXPECT_EQ_UINT(ESR_EC(mte_test_esr), ESR_EC_DABORT_EL1,
	    "out-of-bounds access to tagged memory raised a data abort");
	T_EXPECT_EQ_UINT(ISS_IA_FSC(ESR_ISS(mte_test_esr)), FSC_SYNC_TAG_CHECK_FAULT,
	    "out-of-bounds access to tagged memory raised a synchronous tag check fault");

	/*
	 * Simulate a use-after-free by accessing orig_tagged_ptr, which has an
	 * out-of-date tag.
	 */
	mte_test_esr = 0;
	ml_expect_fault_begin(mte_test_fault_handler, (uintptr_t)&orig_tagged_ptr[0]);
	orig_tagged_ptr[0] = 'T';
	ml_expect_fault_end();
	T_EXPECT_EQ_UINT(ESR_EC(mte_test_esr), ESR_EC_DABORT_EL1,
	    "use-after-free access to tagged memory raised a data abort");
	T_EXPECT_EQ_UINT(ISS_IA_FSC(ESR_ISS(mte_test_esr)), FSC_SYNC_TAG_CHECK_FAULT,
	    "use-after-free access to tagged memory raised a synchronous tag check fault");

	kmem_free(kernel_map, (vm_address_t)__arm_mte_get_tag(untagged_ptr), PAGE_SIZE, KMF_TAG);
	return KERN_SUCCESS;
}

kern_return_t
mte_copyio_recovery_handler_test(void)
{
	if (!mte_kern_enabled()) {
		T_SKIP("MTE disabled");
		return KERN_SUCCESS;
	}

	extern int _copyin_atomic64(const char *src, uint64_t *dst);
	extern int _copyin_atomic64_allow_invalid_kernel_tag(const char *src, uint64_t *dst);

	vm_address_t kern_addr;
	kern_return_t kr = kmem_alloc(kernel_map, &kern_addr, PAGE_SIZE, KMA_ZERO | KMA_TAG | KMA_KOBJECT, VM_KERN_MEMORY_DIAG);
	T_QUIET; T_ASSERT_EQ_INT(kr, 0, "allocated a tagged page");

	uint64_t *tagged_addr = __arm_mte_create_random_tag((void *)kern_addr, 0);
	__arm_mte_set_tag(tagged_addr);
	*tagged_addr = 0xFEEDFACECAFEF00D;

	uint64_t dst;
	int err = _copyin_atomic64((char *)tagged_addr, &dst);
	T_EXPECT_EQ_INT(err, 0, "_copyin_atomic64 from tagged kernel address succeeded");
	T_EXPECT_EQ_ULLONG(*tagged_addr, dst, "_copyin_atomic64 from tagged kernel address copied data correctly");

	uint64_t *incorrectly_tagged_addr = __arm_mte_increment_tag(tagged_addr, 1);
	dst = 0;
	err = _copyin_atomic64_allow_invalid_kernel_tag((char *)incorrectly_tagged_addr, &dst);
	T_EXPECT_EQ_INT(err, EFAULT, "_copyin_atomic64_allow_invalid_kernel_tag with incorrectly tagged kernel address recovered with EFAULT");
	T_EXPECT_NE_ULLONG(*tagged_addr, dst, "_copyin_atomic64_allow_invalid_kernel_tag from incorrectly tagged kernel address did not copy data");

	mte_test_esr = 0;
	ml_expect_fault_begin(mte_test_fault_handler, (uintptr_t)incorrectly_tagged_addr);
	_copyin_atomic64((char *)incorrectly_tagged_addr, &dst);
	ml_expect_fault_end();
	T_EXPECT_EQ_UINT(ESR_EC(mte_test_esr), ESR_EC_DABORT_EL1,
	    "_copyin_atomic64 with incorrectly tagged kernel address raised an unrecoverable data abort");
	T_EXPECT_EQ_UINT(ISS_IA_FSC(ESR_ISS(mte_test_esr)), FSC_SYNC_TAG_CHECK_FAULT,
	    "_copyin_atomic64 with incorrectly tagged kernel address raised an unrecoverable synchronous tag check fault");

	kmem_free(kernel_map, (vm_address_t)__arm_mte_get_tag(tagged_addr), PAGE_SIZE, KMF_TAG);
	return KERN_SUCCESS;
}
#endif /* HAS_MTE */




#if HAS_SPECRES

/*** CPS RCTX ***/


/*** SPECRES ***/

#if HAS_SPECRES2
/*
 * Execute a COSP RCTX instruction.
 */
static void
_cosprctx_exec(uint64_t raw)
{
	asm volatile ( "ISB SY");
	__asm__ volatile ("COSP RCTX, %0" :: "r" (raw));
	asm volatile ( "DSB SY");
	asm volatile ( "ISB SY");
}
#endif

/*
 * Execute a CFP RCTX instruction.
 */
static void
_cfprctx_exec(uint64_t raw)
{
	asm volatile ( "ISB SY");
	__asm__ volatile ("CFP RCTX, %0" :: "r" (raw));
	asm volatile ( "DSB SY");
	asm volatile ( "ISB SY");
}

/*
 * Execute a CPP RCTX instruction.
 */
static void
_cpprctx_exec(uint64_t raw)
{
	asm volatile ( "ISB SY");
	__asm__ volatile ("CPP RCTX, %0" :: "r" (raw));
	asm volatile ( "DSB SY");
	asm volatile ( "ISB SY");
}

/*
 * Execute a DVP RCTX instruction.
 */
static void
_dvprctx_exec(uint64_t raw)
{
	asm volatile ( "ISB SY");
	__asm__ volatile ("DVP RCTX, %0" :: "r" (raw));
	asm volatile ( "DSB SY");
	asm volatile ( "ISB SY");
}

static void
_specres_do_test_std(void (*impl)(uint64_t raw))
{
	typedef struct {
		union {
			struct {
				uint64_t ASID:16;
				uint64_t GASID:1;
				uint64_t :7;
				uint64_t EL:2;
				uint64_t NS:1;
				uint64_t NSE:1;
				uint64_t :4;
				uint64_t VMID:16;
				uint64_t GVMID:1;
			};
			uint64_t raw;
		};
	} specres_ctx;

	assert(sizeof(specres_ctx) == 8);

	/*
	 * Test various possible meaningful COSP_RCTX context ID.
	 */

	/* el : EL0 / EL1 / EL2. */
	for (uint8_t el = 0; el < 3; el++) {
		/* Always non-secure. */
		const uint8_t ns = 1;
		const uint8_t nse = 0;

		/* Iterate over some couples of ASIDs / VMIDs. */
		for (uint16_t xxid = 0; xxid < 256; xxid++) {
			const uint16_t asid = (uint16_t) (xxid << 4);
			const uint16_t vmid = (uint16_t) (256 - (xxid << 4));

			/* Test 4 G[AS|VM]ID combinations. */
			for (uint8_t bid = 0; bid < 4; bid++) {
				const uint8_t gasid = bid & 1;
				const uint8_t gvmid = bid & 2;

				/* Generate the context descriptor. */
				specres_ctx ctx = {0};
				ctx.ASID = asid;
				ctx.GASID = gasid;
				ctx.EL = el;
				ctx.NS = ns;
				ctx.NSE = nse;
				ctx.VMID = vmid;
				ctx.GVMID = gvmid;

				/* Execute the COSP instruction. */
				(*impl)(ctx.raw);

				/* Insert some operation. */
				volatile uint8_t sum = 0;
				for (volatile uint8_t i = 0; i < 64; i++) {
					sum += i * sum + 3;
				}

				/* If el0 is not targetted, just need to do it once. */
				if (el != 0) {
					goto not_el0_skip;
				}
			}
		}

		/* El0 skip. */
not_el0_skip:   ;
	}
}

/*** RCTX ***/

static void
_rctx_do_test(void)
{
	_specres_do_test_std(&_cfprctx_exec);
	_specres_do_test_std(&_cpprctx_exec);
	_specres_do_test_std(&_dvprctx_exec);
#if HAS_SPECRES2
	_specres_do_test_std(&_cosprctx_exec);
#endif
}

kern_return_t
specres_test(void)
{
	/* Basic instructions test. */
	_cfprctx_exec(0);
	_cpprctx_exec(0);
	_dvprctx_exec(0);
#if HAS_SPECRES2
	_cosprctx_exec(0);
#endif

	/* More advanced instructions test. */
	_rctx_do_test();

	return KERN_SUCCESS;
}

#endif /* HAS_SPECRES */
#if BTI_ENFORCED
typedef uint64_t (bti_landing_pad_func_t)(void);
typedef uint64_t (bti_shim_func_t)(bti_landing_pad_func_t *);

extern bti_shim_func_t arm64_bti_test_jump_shim;
extern bti_shim_func_t arm64_bti_test_call_shim;

extern bti_landing_pad_func_t arm64_bti_test_func_with_no_landing_pad;
extern bti_landing_pad_func_t arm64_bti_test_func_with_call_landing_pad;
extern bti_landing_pad_func_t arm64_bti_test_func_with_jump_landing_pad;
extern bti_landing_pad_func_t arm64_bti_test_func_with_jump_call_landing_pad;
#if __has_feature(ptrauth_returns)
extern bti_landing_pad_func_t arm64_bti_test_func_with_pac_landing_pad;
#endif /* __has_feature(ptrauth_returns) */

typedef struct arm64_bti_test_func_case {
	const char *func_str;
	bti_landing_pad_func_t *func;
	uint64_t expect_return_value;
	uint8_t  expect_call_ok;
	uint8_t  expect_jump_ok;
} arm64_bti_test_func_case_s;

static volatile uintptr_t bti_exception_handler_pc = 0;

static bool
arm64_bti_test_exception_handler(arm_saved_state_t * state)
{
	uint64_t esr = get_saved_state_esr(state);
	esr_exception_class_t class = ESR_EC(esr);

	if (class != ESR_EC_BTI_FAIL) {
		return false;
	}

	/* Capture any desired exception metrics */
	bti_exception_handler_pc = get_saved_state_pc(state);

	/* "Cancel" the function call by forging an early return */
	set_saved_state_pc(state, get_saved_state_lr(state));

	/* Clear BTYPE to prevent taking another exception after ERET */
	uint32_t spsr = get_saved_state_cpsr(state);
	spsr &= ~PSR_BTYPE_MASK;
	set_saved_state_cpsr(state, spsr);

	return true;
}

static void
arm64_bti_test_func_with_shim(
	uint8_t expect_ok,
	const char *shim_str,
	bti_shim_func_t *shim,
	arm64_bti_test_func_case_s *test_case)
{
	uint64_t result = -1;

	/* Capture BTI exceptions triggered by our target function */
	uintptr_t raw_func = (uintptr_t)ptrauth_strip(
		(void *)test_case->func,
		ptrauth_key_function_pointer);
	ml_expect_fault_pc_begin(arm64_bti_test_exception_handler, raw_func);
	bti_exception_handler_pc = 0;

	/*
	 * The assembly routines do not support C function type discriminators, so
	 * strip and resign with zero if needed
	 */
	bti_landing_pad_func_t *resigned = ptrauth_auth_and_resign(
		test_case->func,
		ptrauth_key_function_pointer,
		ptrauth_type_discriminator(bti_landing_pad_func_t),
		ptrauth_key_function_pointer, 0);

	result = shim(resigned);

	ml_expect_fault_end();

	if (!expect_ok && raw_func != bti_exception_handler_pc) {
		T_FAIL("Expected BTI exception at 0x%llx but got one at %llx instead\n",
		    raw_func, bti_exception_handler_pc);
	} else if (expect_ok && bti_exception_handler_pc) {
		T_FAIL("Did not expect BTI exception but got on at 0x%llx\n",
		    bti_exception_handler_pc);
	} else if (!expect_ok && !bti_exception_handler_pc) {
		T_FAIL("Failed to hit expected exception!\n");
	} else if (expect_ok && result != test_case->expect_return_value) {
		T_FAIL("Incorrect test function result (expected=%llu, result=%llu\n)",
		    test_case->expect_return_value, result);
	} else {
		T_PASS("%s (shim=%s)\n", test_case->func_str, shim_str);
	}
}

/**
 * This test works to ensure that BTI exceptions are raised where expected
 * and only where they are expected by exhaustively testing all indirect branch
 * combinations with all landing pad options.
 */
kern_return_t
arm64_bti_test(void)
{
	static arm64_bti_test_func_case_s tests[] = {
		{
			.func_str = "arm64_bti_test_func_with_no_landing_pad",
			.func = &arm64_bti_test_func_with_no_landing_pad,
			.expect_return_value     = 1,
			.expect_call_ok          = 0,
			.expect_jump_ok          = 0,
		},
		{
			.func_str = "arm64_bti_test_func_with_call_landing_pad",
			.func = &arm64_bti_test_func_with_call_landing_pad,
			.expect_return_value     = 2,
			.expect_call_ok          = 1,
			.expect_jump_ok          = 0,
		},
		{
			.func_str = "arm64_bti_test_func_with_jump_landing_pad",
			.func = &arm64_bti_test_func_with_jump_landing_pad,
			.expect_return_value     = 3,
			.expect_call_ok          = 0,
			.expect_jump_ok          = 1,
		},
		{
			.func_str = "arm64_bti_test_func_with_jump_call_landing_pad",
			.func = &arm64_bti_test_func_with_jump_call_landing_pad,
			.expect_return_value     = 4,
			.expect_call_ok          = 1,
			.expect_jump_ok          = 1,
		},
#if __has_feature(ptrauth_returns)
		{
			.func_str = "arm64_bti_test_func_with_pac_landing_pad",
			.func = &arm64_bti_test_func_with_pac_landing_pad,
			.expect_return_value     = 5,
			.expect_call_ok          = 1,
			.expect_jump_ok          = 0,
		},
#endif /* __has_feature(ptrauth_returns) */
	};

	size_t test_count = sizeof(tests) / sizeof(*tests);
	for (size_t i = 0; i < test_count; i++) {
		arm64_bti_test_func_case_s *test_case = tests + i;

		arm64_bti_test_func_with_shim(test_case->expect_call_ok,
		    "arm64_bti_test_call_shim",
		    arm64_bti_test_call_shim,
		    test_case);


		arm64_bti_test_func_with_shim(test_case->expect_jump_ok,
		    "arm64_bti_test_jump_shim",
		    arm64_bti_test_jump_shim,
		    test_case);
	}

	return KERN_SUCCESS;
}
#endif /* BTI_ENFORCED */

#if CONFIG_SPTM && HAS_MTE && (DEVELOPMENT || DEBUG)
/**
 * Tests MTE in guarded mode by calling into the SPTM with an
 * XNU-provided pointer.
 *
 * Currently supported test cases:
 * 0. Pass SPTM a pointer with a valid tag --> success
 * 1. Pass SPTM an untagged pointer from the physical aperture --> panic
 * 2. Pass SPTM a pointer with an invalid tag --> panic
 */
static int
mte_test_gl2(__unused int64_t test_case, __unused int64_t *out)
{

	return 0;
}

SYSCTL_TEST_REGISTER(mte_gl2, mte_test_gl2);
#endif /* CONFIG_SPTM && HAS_MTE && (DEVELOPMENT || DEBUG) */


/**
 * Test the speculation guards
 * We can't easily ensure that the guards actually behave correctly under
 * speculation, but we can at least ensure that the guards are non-speculatively
 * correct.
 */
kern_return_t
arm64_speculation_guard_test(void)
{
	uint64_t cookie1_64 = 0x5350454354524521ULL; /* SPECTRE! */
	uint64_t cookie2_64 = 0x5941592043505553ULL; /* YAY CPUS */
	uint32_t cookie1_32 = (uint32_t)cookie1_64;
	uint32_t cookie2_32 = (uint32_t)cookie2_64;
	uint64_t result64 = 0;
	uint32_t result32 = 0;
	bool result_valid;

	/*
	 * Test the zeroing guard
	 * Since failing the guard triggers a panic, we don't actually test that
	 * part as part of the automated tests.
	 */

	result64 = 0;
	SPECULATION_GUARD_ZEROING_XXX(
		/* out */ result64, /* out_valid */ result_valid,
		/* value */ cookie1_64,
		/* cmp_1 */ 0ULL, /* cmp_2 */ 1ULL, /* cc */ "NE");
	T_EXPECT(result_valid, "result valid");
	T_EXPECT_EQ_ULLONG(result64, cookie1_64, "64, 64 zeroing guard works");

	result64 = 0;
	SPECULATION_GUARD_ZEROING_XWW(
		/* out */ result64, /* out_valid */ result_valid,
		/* value */ cookie1_64,
		/* cmp_1 */ 1U, /* cmp_2 */ 0U, /* cc */ "HI");
	T_EXPECT(result_valid, "result valid");
	T_EXPECT_EQ_ULLONG(result64, cookie1_64, "64, 32 zeroing guard works");

	result32 = 0;
	SPECULATION_GUARD_ZEROING_WXX(
		/* out */ result32, /* out_valid */ result_valid,
		/* value */ cookie1_32,
		/* cmp_1 */ -1LL, /* cmp_2 */ 4LL, /* cc */ "LT");
	T_EXPECT(result_valid, "result valid");
	T_EXPECT_EQ_UINT(result32, cookie1_32, "32, 64 zeroing guard works");

	result32 = 0;
	SPECULATION_GUARD_ZEROING_WWW(
		/* out */ result32, /* out_valid */ result_valid,
		/* value */ cookie1_32,
		/* cmp_1 */ 1, /* cmp_2 */ -4, /* cc */ "GT");
	T_EXPECT(result_valid, "result valid");
	T_EXPECT_EQ_UINT(result32, cookie1_32, "32, 32 zeroing guard works");

	result32 = 0x41;
	SPECULATION_GUARD_ZEROING_WWW(
		/* out */ result32, /* out_valid */ result_valid,
		/* value */ cookie1_32,
		/* cmp_1 */ 1, /* cmp_2 */ -4, /* cc */ "LT");
	T_EXPECT(!result_valid, "result invalid");
	T_EXPECT_EQ_UINT(result32, 0, "zeroing guard works with failing condition");

	/*
	 * Test the selection guard
	 */

	result64 = 0;
	SPECULATION_GUARD_SELECT_XXX(
		/* out */ result64,
		/* cmp_1 */ 16ULL, /* cmp_2 */ 32ULL,
		/* cc   */ "EQ", /* sel_1 */ cookie1_64,
		/* n_cc */ "NE", /* sel_2 */ cookie2_64);
	T_EXPECT_EQ_ULLONG(result64, cookie2_64, "64, 64 select guard works (1)");

	result64 = 0;
	SPECULATION_GUARD_SELECT_XXX(
		/* out */ result64,
		/* cmp_1 */ 32ULL, /* cmp_2 */ 32ULL,
		/* cc   */ "EQ", /* sel_1 */ cookie1_64,
		/* n_cc */ "NE", /* sel_2 */ cookie2_64);
	T_EXPECT_EQ_ULLONG(result64, cookie1_64, "64, 64 select guard works (2)");


	result32 = 0;
	SPECULATION_GUARD_SELECT_WXX(
		/* out */ result32,
		/* cmp_1 */ 16ULL, /* cmp_2 */ 32ULL,
		/* cc   */ "HI", /* sel_1 */ cookie1_64,
		/* n_cc */ "LS", /* sel_2 */ cookie2_64);
	T_EXPECT_EQ_ULLONG(result32, cookie2_32, "32, 64 select guard works (1)");

	result32 = 0;
	SPECULATION_GUARD_SELECT_WXX(
		/* out */ result32,
		/* cmp_1 */ 16ULL, /* cmp_2 */ 2ULL,
		/* cc   */ "HI", /* sel_1 */ cookie1_64,
		/* n_cc */ "LS", /* sel_2 */ cookie2_64);
	T_EXPECT_EQ_ULLONG(result32, cookie1_32, "32, 64 select guard works (2)");

	return KERN_SUCCESS;
}


extern void arm64_brk_lr_gpr(void);
extern void arm64_brk_lr_fault(void);

static NOKASAN bool
arm64_backtrace_test_fault_handler(arm_saved_state_t * state)
{
	/* Similar setup to backtrace_kernel_sysctl() */
	const unsigned int bt_len = 24;
	const size_t bt_size = sizeof(uint8_t) * bt_len;
	uint8_t *bt = kalloc_data(bt_size, Z_WAITOK | Z_ZERO);
	backtrace_info_t packed_info = BTI_NONE;

	/* Call the backtrace function */
	backtrace_packed(BTP_KERN_OFFSET_32, bt, bt_size, NULL, &packed_info);

	add_saved_state_pc(state, 4);
	return true;
}

/**
 * Make sure EL1 fleh doesn't push a bogus stack frame when LR is being used as
 * a GPR in the caller.
 *
 * This test writes a GPR-like value into LR that is >4GB away from any kernel
 * address and tries to run backtrace_packed() from a sync handler.
 * backtrace_packed() has an invariant that all addresses in the stack frame are
 * within 4GB of the kernel text.
 */
kern_return_t
arm64_backtrace_test(void)
{
	ml_expect_fault_pc_begin(arm64_backtrace_test_fault_handler, (uintptr_t)&arm64_brk_lr_fault);
	arm64_brk_lr_gpr();
	ml_expect_fault_end();

#if CONFIG_SPTM && (DEVELOPMENT || DEBUG)
	/* Reset the debug data so it can be filled later if needed */
	debug_panic_lockdown_initiator_state.initiator_pc = 0;
#endif /* CONFIG_SPTM && (DEVELOPMENT || DEBUG) */
	return KERN_SUCCESS;
}

#if DEVELOPMENT || DEBUG
/*
 * Helper function to choose a remote CPU to send a test IPI to.
 */
static cpu_data_t *
find_different_cpu(void)
{
	cpu_data_t *current_cpu = getCpuDatap();
	cpu_data_t *target_cpu;

	for (int cpu_id = 0; cpu_id < MAX_CPUS; cpu_id++) {
		target_cpu = cpu_datap(cpu_id);
		if (target_cpu != NULL && target_cpu != current_cpu) {
			return target_cpu;
		}
	}
	return NULL;
}

#if CONFIG_SPTM
static void __attribute__((noreturn))
sptm_vs_xnu_panic_vector(void)
{
	panic("sptm_vs_xnu panic test");
}

static void __attribute__((noreturn))
xnu_vs_sptm_panic_vector(void)
{
	sptm_iofilter_protected_write(0, 0, 8);
	panic("xnu_vs_sptm panic test - should not reach here");
}

static void __attribute__((noreturn))
sptm_vs_sptm_panic_vector(void)
{
	sptm_iofilter_protected_write(0, 0, 8);
	panic("sptm_vs_sptm panic test - should not reach here");
}

/*
 * Test SPTM winning a race to panic vs XNU panicking on a different
 * processor.
 */
void __attribute__((noreturn))
sptm_vs_xnu_panic_test(void)
{
	cpu_data_t *target_cpu = find_different_cpu();

	cpu_signal_set_test_vector(sptm_vs_xnu_panic_vector);
	if (target_cpu != NULL) {
		cpu_signal_deferred(target_cpu, SIGPtest);
	}
	sptm_iofilter_protected_write(0, 0, 8);
	panic("sptm_vs_xnu panic test - should not reach here");
}

/*
 * Test XNU winning a race to panic vs SPTM panicking on a different
 * processor.
 */
void __attribute__((noreturn))
xnu_vs_sptm_panic_test(void)
{
	cpu_data_t *target_cpu = find_different_cpu();

	cpu_signal_set_test_vector(xnu_vs_sptm_panic_vector);
	if (target_cpu != NULL) {
		cpu_signal_deferred(target_cpu, SIGPtest);
	}
	panic("xnu_vs_sptm panic test");
}

/*
 * Test SPTM racing to panic on two CPUs.
 */
void __attribute__((noreturn))
sptm_vs_sptm_panic_test(void)
{
	cpu_data_t *target_cpu = find_different_cpu();

	cpu_signal_set_test_vector(sptm_vs_sptm_panic_vector);
	if (target_cpu != NULL) {
		cpu_signal_deferred(target_cpu, SIGPtest);
	}
	sptm_iofilter_protected_write(0, 0, 8);
	panic("sptm_vs_sptm panic test - should not reach here");
}
#endif /* CONFIG_SPTM */

static void __attribute__((noreturn))
xnu_vs_xnu_panic_vector(void)
{
	panic("xnu_vs_xnu panic test");
}

/*
 * Test XNU panicking on two CPUs very close together.
 */
void __attribute__((noreturn))
xnu_vs_xnu_panic_test(void)
{
	cpu_data_t *target_cpu = find_different_cpu();

	cpu_signal_set_test_vector(xnu_vs_xnu_panic_vector);
	if (target_cpu != NULL) {
		cpu_signal_deferred(target_cpu, SIGPtest);
	}
	xnu_vs_xnu_panic_vector();
}

/*
 * Test creating a stack overflow to ensure we panic
 * properly in that case.
 */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Winfinite-recursion"
void __attribute__((noreturn))
__attribute((disable_tail_calls))
stack_overflow_panic_test(void)
{
	stack_overflow_panic_test();
	panic("stack_overflow_panic_test");
}
#pragma clang diagnostic pop
#endif /* DEVELOPMENT || DEBUG */

kern_return_t
arm64_static_if_asm_test(void)
{
	extern unsigned int arm64_static_if_asm_test_key_true(void);
	extern unsigned int arm64_static_if_asm_test_key_true_to_false(void);
	extern unsigned int arm64_static_if_asm_test_key_false(void);
	extern unsigned int arm64_static_if_asm_test_key_false_to_true(void);

	/*
	 * Each testcase exercises STATIC_BRANCH_IF_ENABLED and
	 * STATIC_BRANCH_IF_DISABLED.  They return the number of times the key
	 * evaluated to true.
	 */
	const unsigned int KEY_DISABLED = 0;
	const unsigned int KEY_ENABLED = 2;

	unsigned int n = arm64_static_if_asm_test_key_true();
	T_EXPECT_EQ_UINT(n, KEY_ENABLED, "static_if_test_key_true should be enabled");

	n = arm64_static_if_asm_test_key_true_to_false();
	T_EXPECT_EQ_UINT(n, KEY_DISABLED, "static_if_test_key_true_to_false should be disabled");

	n = arm64_static_if_asm_test_key_false();
	T_EXPECT_EQ_UINT(n, KEY_DISABLED, "static_if_test_key_false should be disabled");

	n = arm64_static_if_asm_test_key_false_to_true();
	T_EXPECT_EQ_UINT(n, KEY_ENABLED, "static_if_test_key_false_to_true should be enabled");

	return KERN_SUCCESS;
}
