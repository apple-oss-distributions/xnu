/*
 * Copyright (c) 2025 Apple Inc. All rights reserved.
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

#include <ipc/ipc_port.h>
#include <kern/cpu_data.h>
#include <kern/host.h>
#include <kern/mpsc_queue.h>
#include <kern/startup.h>
#include <kern/locks.h>
#include <kern/thread.h>
#include <machine/machine_routines.h>
#include <kern/counter.h>
#include <mach/host_priv.h>
#include <mach/host_special_ports.h>
#include <mach/memory_error_notification.h>
#include <os/log.h>
#include <pexpert/pexpert.h>

#include "ecc.h"
#include "llc_error.h"

static struct mpsc_daemon_queue memory_error_event_queue;

typedef enum {
#if XNU_LOG_MCC
	MEMORY_ERROR_TYPE_MCC,
#endif /* XNU_LOG_MCC */
	MEMORY_ERROR_TYPE_LLC
} memory_error_type_t;

typedef struct {
	struct mpsc_queue_chain link;
	memory_error_type_t type;
	union {
#if XNU_LOG_MCC
		mcc_ecc_event_t mcc;
#endif /* XNU_LOG_MCC */
		llc_event_t llc;
	} event;
} memory_error_event_t;

#define MEMORY_ERROR_NUM_EVENTS (768)
#define MEMORY_ERROR_EVENT_QUEUE_PRIORITY MAXPRI_USER
static memory_error_event_t memory_error_events[MEMORY_ERROR_NUM_EVENTS];
static atomic_int memory_error_producer_idx = 0;
static atomic_int memory_error_consumer_idx = 0;

#if XNU_LOG_MCC
SCALABLE_COUNTER_DEFINE(mcc_dropped_events);
#endif /* XNU_LOG_MCC */
SCALABLE_COUNTER_DEFINE(llc_dropped_events);

LCK_GRP_DECLARE(memory_error_lock_grp, "memory_error");
LCK_SPIN_DECLARE(memory_error_lock, &memory_error_lock_grp);

static inline int
memory_error_events_next(int idx)
{
	assert(idx < MEMORY_ERROR_NUM_EVENTS);
	return (idx + 1) % MEMORY_ERROR_NUM_EVENTS;
}

static void
memory_error_notify_user(memory_error_event_t *event)
{
	mach_port_t user_port = MACH_PORT_NULL;
	kern_return_t kr;

	kr = host_get_memory_error_port(host_priv_self(), &user_port);
	assert(kr == KERN_SUCCESS);
	if (!IPC_PORT_VALID(user_port)) {
		os_log_error(OS_LOG_DEFAULT,
		    "Failed to get memory error port (type %d)", event->type);
		return;
	}

	switch (event->type) {
#if XNU_LOG_MCC
	case MEMORY_ERROR_TYPE_MCC:
		mcc_memory_error_notification(user_port, event->event.mcc);
		break;
#endif /* XNU_LOG_MCC */
	case MEMORY_ERROR_TYPE_LLC:
		llc_memory_error_notification(user_port, event->event.llc);
		break;
	default:
		os_log_error(OS_LOG_DEFAULT,
		    "Unknown memory error event type: %d", event->type);
		break;
	}

	ipc_port_release_send(user_port);
}

static void
memory_error_event_queue_invoke(mpsc_queue_chain_t e,
    mpsc_daemon_queue_t queue)
{
#pragma unused(queue)
	/*
	 * The consumer should never be invoked if there is nothing to consume.
	 */
	int consumer_curr_idx = atomic_load(&memory_error_consumer_idx);
	assert(consumer_curr_idx != atomic_load(&memory_error_producer_idx));

	memory_error_event_t *event =
	    mpsc_queue_element(e, memory_error_event_t, link);
	memory_error_notify_user(event);
	int consumer_next_idx = memory_error_events_next(consumer_curr_idx);
	atomic_store(&memory_error_consumer_idx, consumer_next_idx);
}

static memory_error_event_t *
memory_error_create_event(memory_error_type_t type, const void *event_data)
{
	memory_error_event_t *ret = NULL;

	/*
	 * We are unable to dynamically allocate events, because this function
	 * can be called from the primary interrupt context.
	 * Instead, we allocate from a statically sized ring buffer.
	 */
	const boolean_t interrupts_enabled = ml_set_interrupts_enabled(FALSE);
	lck_spin_lock(&memory_error_lock);
	int producer_curr_idx = atomic_load(&memory_error_producer_idx);
	int producer_next_idx = memory_error_events_next(producer_curr_idx);
	if (producer_next_idx == atomic_load(&memory_error_consumer_idx)) {
		/*
		 * The consumer is running behind the producer, and we're in
		 * the primary interrupt context.
		 * Drop this event and return NULL to the caller.
		 */
		switch (type) {
#if XNU_LOG_MCC
		case MEMORY_ERROR_TYPE_MCC:
			counter_inc(&mcc_dropped_events);
			break;
#endif /* XNU_LOG_MCC */
		case MEMORY_ERROR_TYPE_LLC:
			counter_inc(&llc_dropped_events);
			break;
		}
		ret = NULL;
		goto done;
	}

	memory_error_event_t *event =
	    &memory_error_events[producer_curr_idx];

	event->type = type;
	switch (type) {
#if XNU_LOG_MCC
	case MEMORY_ERROR_TYPE_MCC:
		event->event.mcc = *(const mcc_ecc_event_t *)event_data;
		break;
#endif /* XNU_LOG_MCC */
	case MEMORY_ERROR_TYPE_LLC:
		event->event.llc = *(const llc_event_t *)event_data;
		break;
	}

	atomic_store(&memory_error_producer_idx, producer_next_idx);
	ret = event;

done:
	lck_spin_unlock(&memory_error_lock);
	ml_set_interrupts_enabled(interrupts_enabled);
	return ret;
}

__startup_func
static void
memory_error_logging_init(void)
{
	mpsc_daemon_queue_init_with_thread(&memory_error_event_queue,
	    memory_error_event_queue_invoke,
	    MEMORY_ERROR_EVENT_QUEUE_PRIORITY,
	    "daemon.memory_error-events", MPSC_DAEMON_INIT_INACTIVE);

	mpsc_daemon_queue_activate(&memory_error_event_queue);
}
STARTUP(THREAD_CALL, STARTUP_RANK_MIDDLE, memory_error_logging_init);

kern_return_t
mcc_log_memory_error(mcc_ecc_event_t mcc_event)
{
#if XNU_LOG_MCC
	memory_error_event_t *event = memory_error_create_event(
		MEMORY_ERROR_TYPE_MCC, &mcc_event);
	if (event == NULL) {
		return KERN_RESOURCE_SHORTAGE;
	}
	assert(memory_error_event_queue.mpd_thread != NULL);

	mpsc_daemon_enqueue(&memory_error_event_queue, &event->link,
	    MPSC_QUEUE_DISABLE_PREEMPTION);

	return KERN_SUCCESS;
#else
#pragma unused(mcc_event)
	return KERN_FAILURE;
#endif
}

kern_return_t
llc_log_memory_error(llc_event_t llc_event)
{
	memory_error_event_t *event = memory_error_create_event(
		MEMORY_ERROR_TYPE_LLC, &llc_event);
	if (event == NULL) {
		return KERN_RESOURCE_SHORTAGE;
	}
	assert(memory_error_event_queue.mpd_thread != NULL);

	mpsc_daemon_enqueue(&memory_error_event_queue, &event->link,
	    MPSC_QUEUE_DISABLE_PREEMPTION);

	return KERN_SUCCESS;
}

#if (DEBUG || DEVELOPMENT)
static int
mcc_memory_error_notify_test_run(int64_t in, int64_t *out)
{
	printf("Running %s for %llu iterations\n", __func__, in);

	for (uint64_t i = 0; i < in; i++) {
		mcc_ecc_event_t event = {
			.version = MCC_ECC_V1,
			.status = (uint32_t)i,
		};

		/*
		 * To accurately test mcc_log_memory_error, we must disable
		 * preemption, because it is called from the primary interrupt
		 * context.
		 */
		disable_preemption();
		kern_return_t kr = mcc_log_memory_error(event);
		enable_preemption();

		if (kr != KERN_SUCCESS) {
			printf("Failed to log on i=%llu\n", i);
		}
	}

	*out = 1;
	return 0;
}

SYSCTL_TEST_REGISTER(mcc_memory_error_notify_test,
    mcc_memory_error_notify_test_run);

static int
llc_memory_error_notify_test_run(int64_t in, int64_t *out)
{
	printf("Running %s for %llu iterations\n", __func__, in);

	for (uint64_t i = 0; i < in; i++) {
		llc_event_t event = {
			.version = LLC_EVENT_V1,
			.sts = (uint32_t)i,
		};

		/*
		 * LLC errors are reported from the primary interrupt context.
		 */
		disable_preemption();
		kern_return_t kr = llc_log_memory_error(event);
		enable_preemption();

		if (kr != KERN_SUCCESS) {
			printf("Failed to log on i=%llu\n", i);
		}
	}

	*out = 1;
	return 0;
}

SYSCTL_TEST_REGISTER(llc_memory_error_notify_test,
    llc_memory_error_notify_test_run);
#endif /* (DEBUG || DEVELOPMENT) */
