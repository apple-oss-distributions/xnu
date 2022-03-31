#include <mach_ldebug.h>
#include <debug.h>

#include <mach/kern_return.h>
#include <mach/mach_host_server.h>
#include <mach_debug/lockgroup_info.h>

#include <kern/locks.h>
#include <kern/misc_protos.h>
#include <kern/kalloc.h>
#include <kern/thread.h>
#include <kern/processor.h>
#include <kern/sched_prim.h>
#include <kern/debug.h>
#include <libkern/section_keywords.h>
#include <machine/atomic.h>
#include <machine/machine_cpu.h>
#include <machine/atomic.h>
#include <string.h>
#include <kern/kalloc.h>

#include <sys/kdebug.h>
#include <sys/errno.h>

static hw_lock_timeout_status_t
hw_lock_timeout_bail_handler(void *_lock, uint64_t timeout, uint64_t start, uint64_t now, uint64_t interrupt_time)
{
#pragma unused(_lock, timeout, start, now, interrupt_time)
	return HW_LOCK_TIMEOUT_RETURN;
}

static uint64_t
sane_us2abs(uint64_t ns)
{
	uint64_t t;
	nanoseconds_to_absolutetime(ns * NSEC_PER_USEC, &t);
	return t;
}

static int
hw_lock_allow_invalid_test(__unused int64_t in, int64_t *out)
{
	vm_offset_t addr = 0;
	hw_lock_bit_t *lck;
	kern_return_t kr;
	hw_lock_status_t rc;

	printf("%s: STARTING\n", __func__);

	kr = kernel_memory_allocate(kernel_map, &addr, PAGE_SIZE, PAGE_MASK,
	    KMA_ZERO | KMA_KOBJECT, VM_KERN_MEMORY_DIAG);
	if (kr != KERN_SUCCESS) {
		printf("%s: kma failed (%d)\n", __func__, kr);
		return ENOMEM;
	}

	lck = (hw_lock_bit_t *)addr;
	rc = hw_lock_bit_to_allow_invalid(lck, 0, sane_us2abs(1),
	    hw_lock_timeout_bail_handler, NULL);
	assert(rc == HW_LOCK_INVALID); // because the lock is 0
	assert(os_atomic_load(lck, relaxed) == 0);
	assert(preemption_enabled());

	os_atomic_init(lck, 0x100);
	rc = hw_lock_bit_to_allow_invalid(lck, 0, sane_us2abs(1),
	    hw_lock_timeout_bail_handler, NULL);
	assert(rc == HW_LOCK_ACQUIRED); // because the lock is 0x100
	assert(os_atomic_load(lck, relaxed) == 0x101);
	assert(!preemption_enabled());

	rc = hw_lock_bit_to_allow_invalid(lck, 0, sane_us2abs(1),
	    hw_lock_timeout_bail_handler, NULL);
	assert(rc == HW_LOCK_CONTENDED);
	enable_preemption(); /* HW_LOCK_CONTENDED doesn't re-enable preemption */

	hw_unlock_bit(lck, 0);
	assert(os_atomic_load(lck, relaxed) == 0x100);
	assert(preemption_enabled());

	kernel_memory_depopulate(kernel_map, addr, PAGE_SIZE, KMA_KOBJECT,
	    VM_KERN_MEMORY_DIAG);

	rc = hw_lock_bit_to_allow_invalid(lck, 0, sane_us2abs(1),
	    hw_lock_timeout_bail_handler, NULL);
	assert(rc == HW_LOCK_INVALID); // because the memory is unmapped

	kmem_free(kernel_map, addr, PAGE_SIZE);

	printf("%s: SUCCESS\n", __func__);

	*out = 1;
	return 0;
}
SYSCTL_TEST_REGISTER(hw_lock_allow_invalid, hw_lock_allow_invalid_test);

#if !KASAN
static void
hw_lck_ticket_test_wait_for_delta(hw_lck_ticket_t *lck, uint8_t delta, int msec)
{
	hw_lck_ticket_t tmp;

	for (int i = 0; i < msec * 1000; i++) {
		tmp.lck_value = os_atomic_load(&lck->lck_value, relaxed);
		if ((uint8_t)(tmp.nticket - tmp.cticket) == delta) {
			return;
		}
		delay(1);
	}
	assert(false);
}

__dead2
static void
hw_lck_ticket_allow_invalid_worker(void *arg, wait_result_t __unused wr)
{
	hw_lck_ticket_t *lck = arg;
	hw_lock_status_t rc;

	/* wait until we can observe the test take the lock */
	hw_lck_ticket_test_wait_for_delta(lck, 1, 10);

	rc = hw_lck_ticket_lock_allow_invalid(lck, sane_us2abs(100),
	    hw_lock_timeout_bail_handler, NULL);
	assert(rc == HW_LOCK_INVALID); // because the other thread invalidated it
	assert(preemption_enabled());

	thread_terminate_self();
	__builtin_unreachable();
}
#endif /* !KASAN */

static int
hw_lck_ticket_allow_invalid_test(__unused int64_t in, int64_t *out)
{
	vm_offset_t addr = 0;
	hw_lck_ticket_t *lck;
	kern_return_t kr;
	hw_lock_status_t rc;

	printf("%s: STARTING\n", __func__);

	kr = kernel_memory_allocate(kernel_map, &addr, PAGE_SIZE, PAGE_MASK,
	    KMA_ZERO | KMA_KOBJECT, VM_KERN_MEMORY_DIAG);
	if (kr != KERN_SUCCESS) {
		printf("%s: kma failed (%d)\n", __func__, kr);
		return ENOMEM;
	}

	lck = (hw_lck_ticket_t *)addr;
	rc = hw_lck_ticket_lock_allow_invalid(lck, sane_us2abs(100),
	    hw_lock_timeout_bail_handler, NULL);
	assert(rc == HW_LOCK_INVALID); // because the lock is 0
	assert(preemption_enabled());

	hw_lck_ticket_init(lck, NULL);

	assert(hw_lck_ticket_lock_try(lck, NULL));
	assert(!hw_lck_ticket_lock_try(lck, NULL));
	hw_lck_ticket_unlock(lck);

	rc = hw_lck_ticket_lock_allow_invalid(lck, sane_us2abs(100),
	    hw_lock_timeout_bail_handler, NULL);
	assert(rc == HW_LOCK_ACQUIRED); // because the lock is initialized
	assert(!preemption_enabled());

	hw_lck_ticket_unlock(lck);
	assert(preemption_enabled());

#if !KASAN
	thread_t th;

	kr = kernel_thread_start_priority(hw_lck_ticket_allow_invalid_worker, lck,
	    BASEPRI_KERNEL, &th);
	assert(kr == KERN_SUCCESS);
	thread_deallocate(th);

	/* invalidate the lock */
	hw_lck_ticket_lock(lck, NULL);

	/* wait for the worker thread to take the reservation */
	hw_lck_ticket_test_wait_for_delta(lck, 2, 20);
	hw_lck_ticket_invalidate(lck);
	hw_lck_ticket_unlock(lck);
	hw_lck_ticket_destroy(lck, NULL);

	hw_lck_ticket_init(lck, NULL);
#endif /* !KASAN */

	kernel_memory_depopulate(kernel_map, addr, PAGE_SIZE, KMA_KOBJECT,
	    VM_KERN_MEMORY_DIAG);

	rc = hw_lck_ticket_lock_allow_invalid(lck, sane_us2abs(100),
	    hw_lock_timeout_bail_handler, NULL);
	assert(rc == HW_LOCK_INVALID); // because the memory is unmapped

	kmem_free(kernel_map, addr, PAGE_SIZE);

	printf("%s: SUCCESS\n", __func__);

	*out = 1;
	return 0;
}
SYSCTL_TEST_REGISTER(hw_lck_ticket_allow_invalid, hw_lck_ticket_allow_invalid_test);
