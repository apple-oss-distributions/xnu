/*
 * Copyright (c) 2013 Apple Inc. All rights reserved.
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

#include <mach/host_priv.h>
#include <mach/host_special_ports.h>
#include <mach/memory_error_notification.h>

#include <mach/mach_types.h>
#include <mach/host_info.h>
#include <kern/host.h>
#include <kern/locks.h>
#include <kern/ecc.h>
#include <kern/spl.h>
#include <kern/mpsc_queue.h>
#include <kern/thread.h>
#include <kern/thread_call.h>
#include <kern/startup.h>
#include <os/log.h>
#include <pexpert/pexpert.h>
#include <pexpert/device_tree.h>
#include <libkern/OSAtomic.h>
#include <arm/pmap_public.h>
#include <vm/vm_protos.h>

/* New CoreAnalytics ECC logging mechanism */

/**
 * Stubs for targets which do not support ECC.
 */

kern_return_t
ecc_log_memory_error(
	__unused pmap_paddr_t physical_address,
	__unused uint32_t ecc_flags)
{
	return KERN_NOT_SUPPORTED;
}

kern_return_t
ecc_log_memory_error_internal(
	__unused pmap_paddr_t physical_address,
	__unused uint32_t ecc_flags)
{
	return KERN_NOT_SUPPORTED;
}

kern_return_t
ecc_log_memory_error_ce(
	__unused pmap_paddr_t physical_address,
	__unused uint32_t ecc_flags,
	__unused uint32_t ce_count)
{
	return KERN_NOT_SUPPORTED;
}


kern_return_t
kern_ecc_poll_register(
	__unused platform_error_handler_ecc_poll_t poll_func,
	__unused uint32_t max_errors)
{
	return KERN_NOT_SUPPORTED;
}

/*
 * Used to report earlier errors that were found after ECC gets enabled.
 * We don't want the VM to panic for these.
 */
kern_return_t
ecc_log_memory_error_delayed(
	__unused pmap_paddr_t physical_address,
	__unused uint32_t ecc_flags)
{
	return KERN_FAILURE;
}

/**
 * MCC Logging
 */

/**
 * TODO: rdar://97394997 (Clean up ECC / MCC logging)
 * We can probably clean some of this up and share some of the code with ECC.
 */
#if XNU_HANDLE_MCC

static struct mpsc_daemon_queue mcc_memory_error_event_queue;
struct _mcc_mem_err_event {
	struct mpsc_queue_chain link;
	mcc_ecc_event_t event;
};
typedef struct _mcc_mem_err_event* mcc_mem_err_event_t;

#define MCC_ECC_NUM_ERRORS (1024)
#define MCC_ERROR_EVENT_QUEUE_PRIORITY MAXPRI_USER
static struct _mcc_mem_err_event mcc_events[MCC_ECC_NUM_ERRORS];
static atomic_int mcc_events_producer_idx = 0;
static atomic_int mcc_events_consumer_idx = 0;
SCALABLE_COUNTER_DEFINE(mcc_dropped_events);
LCK_GRP_DECLARE(mcc_lock_grp, "mcc");
LCK_SPIN_DECLARE(mcc_lock, &mcc_lock_grp);

static inline int
mcc_events_next(int idx)
{
	assert(idx < MCC_ECC_NUM_ERRORS);
	return (idx + 1) % MCC_ECC_NUM_ERRORS;
}

/* MCC ECC CoreAnalytics Error Logging */
static void
mcc_error_notify_user(mcc_ecc_event_t event)
{
	mach_port_t user_port = MACH_PORT_NULL;

	kern_return_t kr = host_get_memory_error_port(host_priv_self(), &user_port);

	if ((kr != KERN_SUCCESS) || !IPC_PORT_VALID(user_port)) {
		os_log(OS_LOG_DEFAULT, "Failed to get memory error port");
		return;
	}

	mcc_memory_error_notification(user_port, event);

	ipc_port_release_send(user_port);
}

static void
mcc_memory_error_event_queue_invoke(mpsc_queue_chain_t e, mpsc_daemon_queue_t queue __unused)
{
	mcc_mem_err_event_t event;

	/* The consumer should never be invoked if there is nothing to consume. */
	int mcc_events_consumer_curr_idx = atomic_load(&mcc_events_consumer_idx);
	assert(mcc_events_consumer_curr_idx != atomic_load(&mcc_events_producer_idx));

	event = mpsc_queue_element(e, struct _mcc_mem_err_event, link);
	mcc_error_notify_user(event->event);
	int mcc_events_consumer_next_idx = mcc_events_next(mcc_events_consumer_curr_idx);
	atomic_store(&mcc_events_consumer_idx, mcc_events_consumer_next_idx);
}

static mcc_mem_err_event_t
mcc_memory_error_create_event(mcc_ecc_event_t mcc_event)
{
	mcc_mem_err_event_t ret = NULL;

	/**
	 * @note We are unable to dynamically allocate events, because this function can be called from
	 * the primary interrupt context.  Instead, we allocate from a statically sized ring buffer.
	 */
	const boolean_t interrupts_enabled = ml_set_interrupts_enabled(FALSE);
	lck_spin_lock(&mcc_lock);
	int mcc_events_producer_curr_idx = atomic_load(&mcc_events_producer_idx);
	int mcc_events_producer_next_idx = mcc_events_next(mcc_events_producer_curr_idx);
	if (mcc_events_producer_next_idx == atomic_load(&mcc_events_consumer_idx)) {
		/**
		 * The consumer is running behind the producer, and we're in the primary interrupt context.
		 * Drop this event and return NULL to the caller.
		 */
		counter_inc(&mcc_dropped_events);
		ret = NULL;
		goto done;
	}

	mcc_mem_err_event_t event = &mcc_events[mcc_events_producer_curr_idx];
	event->event = mcc_event;
	atomic_store(&mcc_events_producer_idx, mcc_events_producer_next_idx);
	ret = event;

done:
	lck_spin_unlock(&mcc_lock);
	ml_set_interrupts_enabled(interrupts_enabled);
	return ret;
}

__startup_func
static void
mcc_logging_init(void)
{
	mpsc_daemon_queue_init_with_thread(&mcc_memory_error_event_queue,
	    mcc_memory_error_event_queue_invoke, MCC_ERROR_EVENT_QUEUE_PRIORITY,
	    "daemon.mcc_error-events", MPSC_DAEMON_INIT_INACTIVE);

	mpsc_daemon_queue_activate(&mcc_memory_error_event_queue);
}
STARTUP(THREAD_CALL, STARTUP_RANK_MIDDLE, mcc_logging_init);

#endif /* XNU_HANDLE_MCC */

kern_return_t
mcc_log_memory_error(mcc_ecc_event_t mcc_event __unused)
{
#if XNU_HANDLE_MCC
	mcc_mem_err_event_t event = mcc_memory_error_create_event(mcc_event);
	if (event == NULL) {
		return KERN_RESOURCE_SHORTAGE;
	}
	assert(mcc_memory_error_event_queue.mpd_thread != NULL);
	mpsc_daemon_enqueue(&mcc_memory_error_event_queue,
	    &event->link, MPSC_QUEUE_DISABLE_PREEMPTION);
	return KERN_SUCCESS;
#else
	return KERN_FAILURE;
#endif
}

#if (DEBUG || DEVELOPMENT)
static int
mcc_memory_error_notify_test_run(int64_t in, int64_t *out)
{
	printf("Running mcc_memory_error_notify_test for %llu iterations\n", in);
	for (uint64_t i = 0; i < in; i++) {
		mcc_ecc_event_t event = {.version = MCC_ECC_V1, .status = (uint32_t)i};
		/**
		 * To accurately test mcc_log_memory_error, we must disable preemption, because it is called
		 * from the primary interrupt context.
		 */
		disable_preemption();
		mcc_log_memory_error(event);
		enable_preemption();
	}

	*out = 1;
	return 0;
}

SYSCTL_TEST_REGISTER(mcc_memory_error_notify_test, mcc_memory_error_notify_test_run);
#endif /* (DEBUG || DEVELOPMENT) */


/* Legacy ECC logging mechanism */

/*
 * ECC data.  Not really KPCs, but this still seems like the
 * best home for this code.
 *
 * Circular buffer of events.  When we fill up, drop data.
 */
#define ECC_EVENT_BUFFER_COUNT  (256)

struct ecc_event                ecc_data[ECC_EVENT_BUFFER_COUNT];
static uint32_t                 ecc_data_next_read;
static uint32_t                 ecc_data_next_write;
static boolean_t                ecc_data_empty = TRUE; // next read == next write : empty or full?
static LCK_GRP_DECLARE(ecc_data_lock_group, "ecc-data");
static LCK_SPIN_DECLARE(ecc_data_lock, &ecc_data_lock_group);
static uint32_t                 ecc_correction_count;


uint32_t
ecc_log_get_correction_count()
{
	return ecc_correction_count;
}

kern_return_t
ecc_log_record_event(const struct ecc_event *ev)
{
	spl_t x;

	if (ev->count > ECC_EVENT_INFO_DATA_ENTRIES) {
		panic("Count of %u on ecc event is too large.", (unsigned)ev->count);
	}

	x = splhigh();
	lck_spin_lock(&ecc_data_lock);

	ecc_correction_count++;

	if (ecc_data_next_read == ecc_data_next_write && !ecc_data_empty) {
		lck_spin_unlock(&ecc_data_lock);
		splx(x);
		return KERN_FAILURE;
	}

	bcopy(ev, &ecc_data[ecc_data_next_write], sizeof(*ev));
	ecc_data_next_write++;
	ecc_data_next_write %= ECC_EVENT_BUFFER_COUNT;
	ecc_data_empty = FALSE;

	lck_spin_unlock(&ecc_data_lock);
	splx(x);

	return KERN_SUCCESS;
}


kern_return_t
ecc_log_get_next_event(struct ecc_event *ev)
{
	spl_t x;

	x = splhigh();
	lck_spin_lock(&ecc_data_lock);

	if (ecc_data_empty) {
		assert(ecc_data_next_write == ecc_data_next_read);

		lck_spin_unlock(&ecc_data_lock);
		splx(x);
		return KERN_FAILURE;
	}

	bcopy(&ecc_data[ecc_data_next_read], ev, sizeof(*ev));
	ecc_data_next_read++;
	ecc_data_next_read %= ECC_EVENT_BUFFER_COUNT;

	if (ecc_data_next_read == ecc_data_next_write) {
		ecc_data_empty = TRUE;
	}

	lck_spin_unlock(&ecc_data_lock);
	splx(x);

	return KERN_SUCCESS;
}
