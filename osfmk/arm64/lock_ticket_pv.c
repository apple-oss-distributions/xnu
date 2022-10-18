/*
 * Copyright (c) 2021 Apple Inc. All rights reserved.
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
#define ATOMIC_PRIVATE 1
#define LOCK_PRIVATE 1

#include <stdint.h>
#include <kern/thread.h>
#include <machine/atomic.h>
#include <kern/locks.h>
#include <kern/lock_stat.h>
#include <machine/machine_cpu.h>
#include <os/atomic_private.h>
#include <kern/hvg_hypercall.h>

static _Atomic cpumap_t ticket_waitmask_pv;

/*
 * The ticket has been unlocked i.e. we just incremented cticket, so it's
 * ready for acquisition by an acquirer that has nticket == cticket.
 * Find the waiting vcpu and kick it out of its passive state.
 */
__attribute__((noinline))
void
hw_lck_ticket_unlock_kick_pv(hw_lck_ticket_t *lck, uint8_t ticket)
{
	const cpumap_t wmask = os_atomic_load(&ticket_waitmask_pv, acquire);

	percpu_foreach_base(base) {
		const processor_t ps = PERCPU_GET_WITH_BASE(base, processor);
		const uint32_t tcpunum = ps->cpu_id;

		if (!bit_test(wmask, tcpunum)) {
			continue; // vcpu not currently waiting for a kick
		}
		const lck_tktlock_pv_info_t ltpi = PERCPU_GET_WITH_BASE(base,
		    lck_tktlock_pv_info);

		const hw_lck_ticket_t *wlck = os_atomic_load(&ltpi->ltpi_lck,
		    acquire);
		if (wlck != lck) {
			continue; // vcpu waiting on a different lock
		}

		const uint8_t wt = os_atomic_load(&ltpi->ltpi_wt, acquire);
		if (wt != ticket) {
			continue; // vcpu doesn't have the right ticket
		}

		hvg_hc_kick_cpu(tcpunum);
		PVTICKET_STATS_INC(kick_count);
		break;
	}
}


/*
 * The current vcpu wants 'lck' but the vcpu holding it may not be running.
 * Wait for it to kick us (above), just /after/ it increments cticket to
 * drop the lock.
 *
 * Other states are possible e.g. the lock may have been unlocked just before
 * this routine and so no kick was sent because we haven't initialized
 * the per-cpu wait data. Or we may be sent a kick immediately after storing
 * the wait data, but before halting.
 *
 * All we really know is that when we get here, spinning has been unsuccessful.
 */
__attribute__((noinline))
void
hw_lck_ticket_lock_wait_pv(hw_lck_ticket_t *lck, uint8_t mt)
{
	/*
	 * Disable interrupts so we don't lose the kick.
	 * (Also prevents collisions with ticket lock
	 * acquisition in an interrupt handler)
	 */

	const boolean_t istate = ml_set_interrupts_enabled(FALSE);

	/* Record the ticket + the lock this cpu is waiting for */

	assert(!preemption_enabled());
	lck_tktlock_pv_info_t ltpi = PERCPU_GET(lck_tktlock_pv_info);

	os_atomic_store(&ltpi->ltpi_lck, NULL, release);
	os_atomic_store(&ltpi->ltpi_wt, mt, release);
	os_atomic_store(&ltpi->ltpi_lck, lck, release);

	/* Mark this cpu as eligible for kicking */

	const cpumap_t kickmask = BIT(cpu_number());
	os_atomic_or(&ticket_waitmask_pv, kickmask, acq_rel);

	assert((mt & HW_LCK_TICKET_LOCK_PVWAITFLAG) == 0);

	/* Check the "now serving" field one last time */

	const uint8_t cticket = os_atomic_load(&lck->cticket, acquire);
	const uint8_t ccount = cticket & ~HW_LCK_TICKET_LOCK_PVWAITFLAG;

	if (__probable(ccount != mt)) {
		PVTICKET_STATS_INC(wait_count);
		assert(cticket & HW_LCK_TICKET_LOCK_PVWAITFLAG);

		/* wait for a kick (or other interrupt) */
		hvg_hc_wait_for_kick(istate);
		/*
		 * Note: if interrupts were enabled at entry to the routine,
		 * even though we disabled them above, they'll be enabled here.
		 */
	} else {
		/* just return to the caller to claim the ticket */
		PVTICKET_STATS_INC(already_count);
	}

	os_atomic_andnot(&ticket_waitmask_pv, kickmask, acq_rel);
	os_atomic_store(&ltpi->ltpi_lck, NULL, release);

	(void) ml_set_interrupts_enabled(istate);

	assert(!preemption_enabled());
}
