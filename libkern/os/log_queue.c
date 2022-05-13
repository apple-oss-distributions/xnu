/*
 * Copyright (c) 2020-2021 Apple Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *           log_queue_failed_intr);
 *
 * @APPLE_LICENSE_HEADER_END@
 */

#include <kern/assert.h>
#include <kern/counter.h>
#include <kern/cpu_data.h>
#include <kern/percpu.h>
#include <kern/kalloc.h>
#include <kern/thread_call.h>
#include <libkern/libkern.h>
#include <sys/queue.h>
#include <vm/vm_kern.h>

#include "log_queue.h"
#include "log_mem.h"

#define LQ_DEFAULT_SZ_ORDER 15 // 32K per slot
#define LQ_DEFAULT_FREE_AFTER_CNT 15000 // Deallocate log queue after N logs
#define LQ_MAX_SZ_ORDER 20 // 1MB per CPU should really be enough and a hard cap
#define LQ_MIN_LOG_SZ_ORDER 5
#define LQ_MAX_LOG_SZ_ORDER 11
#define LQ_BATCH_SIZE 24
#define LQ_MAX_LM_SLOTS 8
#define LQ_LOW_MEM_SCALE 3

#define LQ_MEM_ENABLE(q, i) ((q)->lq_mem_set |= (1 << (i)))
#define LQ_MEM_ENABLED(q, i) ((q)->lq_mem_set & (1 << (i)))
#define LQ_MEM_DISABLE(q, i) ((q)->lq_mem_set &= ~(1 << (i)))

OS_ENUM(log_queue_entry_state, uint8_t,
    LOG_QUEUE_ENTRY_STATE_INVALID = 0,
    LOG_QUEUE_ENTRY_STATE_STORED,
    LOG_QUEUE_ENTRY_STATE_DISPATCHED,
    LOG_QUEUE_ENTRY_STATE_SENT,
    LOG_QUEUE_ENTRY_STATE_FAILED
    );

OS_ENUM(lq_mem_state, uint8_t,
    LQ_MEM_STATE_READY = 0,
    LQ_MEM_STATE_ALLOCATING,
    LQ_MEM_STATE_RELEASING
    );

OS_ENUM(lq_req_state, uint8_t,
    LQ_REQ_STATE_INVALID = 0,
    LQ_REQ_STATE_ALLOCATING,
    LQ_REQ_STATE_RELEASING,
    LQ_REQ_STATE_READY
    );

typedef struct log_queue_entry {
	STAILQ_ENTRY(log_queue_entry)   lqe_link;
	uint16_t                        lqe_size;
	uint16_t                        lqe_lm_id;
	_Atomic log_queue_entry_state_t lqe_state;
	log_payload_s                   lqe_payload;
} log_queue_entry_s, *log_queue_entry_t;

typedef STAILQ_HEAD(, log_queue_entry) log_queue_list_s, *log_queue_list_t;

typedef struct {
	log_queue_list_s        lq_log_list;
	log_queue_list_s        lq_dispatch_list;
	logmem_t                lq_mem[LQ_MAX_LM_SLOTS];
	size_t                  lq_mem_set;
	size_t                  lq_mem_size;
	size_t                  lq_mem_size_order;
	lq_mem_state_t          lq_mem_state;
	thread_call_t           lq_mem_handler;
	size_t                  lq_cnt_mem_active;
	size_t                  lq_cnt_mem_avail;
	_Atomic lq_req_state_t  lq_req_state;
	void                    *lq_req_mem;
	uint32_t                lq_ready : 1;
	uint32_t                lq_suspend : 1;
} log_queue_s, *log_queue_t;

extern bool os_log_disabled(void);

/*
 * Log Queue
 *
 * Log queues are allocated and set up per cpu. When a firehose memory is full
 * logs are stored in a log queue and sent into the firehose once it has a free
 * space again. Each log queue (memory) can grow and shrink based on demand by
 * adding/removing additional memory to/from its memory slots. There are
 * LQ_MAX_LM_SLOTS memory slots available for every log queue to use. Memory
 * slots are released when not needed, with one slot always allocated per queue
 * as a minimum.
 *
 * Boot args:
 *
 * lq_size_order: Per slot memory size defined as a power of 2 exponent
 *                (i.e. 2^lq_bootarg_size_order). Zero disables queues.
 *
 * lq_nslots: Number of allocated slots to boot with per each log queue.
 *            Once initial log traffic decreases, log queues release
 *            slots as needed.
 *
 * If extensive number of logs is expected, setting aforementioned boot-args as
 * needed allows to capture the vast majority of logs and avoid drops.
 */
TUNABLE(size_t, lq_bootarg_size_order, "lq_size_order", LQ_DEFAULT_SZ_ORDER);
TUNABLE(size_t, lq_bootarg_nslots, "lq_nslots", LQ_MAX_LM_SLOTS);

SCALABLE_COUNTER_DEFINE(log_queue_cnt_received);
SCALABLE_COUNTER_DEFINE(log_queue_cnt_rejected_fh);
SCALABLE_COUNTER_DEFINE(log_queue_cnt_queued);
SCALABLE_COUNTER_DEFINE(log_queue_cnt_sent);
SCALABLE_COUNTER_DEFINE(log_queue_cnt_dropped_nomem);
SCALABLE_COUNTER_DEFINE(log_queue_cnt_dropped_off);
SCALABLE_COUNTER_DEFINE(log_queue_cnt_mem_allocated);
SCALABLE_COUNTER_DEFINE(log_queue_cnt_mem_released);
SCALABLE_COUNTER_DEFINE(log_queue_cnt_mem_failed);

static log_queue_s PERCPU_DATA(oslog_queue);
static size_t lq_low_mem_limit;

static void *
log_queue_buffer_alloc(size_t amount)
{
	return kalloc_data_tag(amount, Z_WAITOK_ZERO, VM_KERN_MEMORY_LOG);
}

static void
log_queue_buffer_free(void *addr, size_t amount)
{
	kfree_data(addr, amount);
}

#define log_queue_entry_size(p) (sizeof(log_queue_entry_s) + (p)->lp_data_size)

#define publish(a, v) os_atomic_store((a), (v), release)
#define read_dependency(v) os_atomic_load((v), dependency)
#define read_dependent(v, t) os_atomic_load_with_dependency_on((v), (uintptr_t)(t))
#define read_dependent_w(v, t) ({ \
	__auto_type _v = os_atomic_inject_dependency((v), (uintptr_t)(t)); \
	os_atomic_load_wide(_v, dependency); \
})

static log_queue_entry_state_t
log_queue_entry_state(const log_queue_entry_t lqe)
{
	log_queue_entry_state_t state = read_dependency(&lqe->lqe_state);
	assert(state != LOG_QUEUE_ENTRY_STATE_INVALID);
	return state;
}

static log_queue_entry_t
log_queue_entry_alloc(log_queue_t lq, size_t lqe_size)
{
	for (short i = 0; i < LQ_MAX_LM_SLOTS; i++) {
		if (!LQ_MEM_ENABLED(lq, i)) {
			continue;
		}
		log_queue_entry_t lqe = logmem_alloc(&lq->lq_mem[i], &lqe_size);
		if (lqe) {
			assert(lqe_size <= lq->lq_cnt_mem_avail);
			lq->lq_cnt_mem_avail -= lqe_size;
			assert(lqe_size <= UINT16_MAX);
			lqe->lqe_size = (uint16_t)lqe_size;
			lqe->lqe_lm_id = i;
			return lqe;
		}
	}

	return NULL;
}

static void
log_queue_entry_free(log_queue_t lq, log_queue_entry_t lqe)
{
	const size_t lqe_size = lqe->lqe_size;
	const uint16_t lqe_lm_id = lqe->lqe_lm_id;

	bzero(lqe, lqe_size);
	logmem_free(&lq->lq_mem[lqe_lm_id], lqe, lqe_size);
	lq->lq_cnt_mem_avail += lqe_size;
}

static bool
log_queue_add_entry(log_queue_t lq, log_payload_t lp, const uint8_t *lp_data)
{
	log_queue_entry_t lqe = log_queue_entry_alloc(lq, log_queue_entry_size(lp));
	if (!lqe) {
		counter_inc_preemption_disabled(&log_queue_cnt_dropped_nomem);
		return false;
	}
	assert(lqe->lqe_size >= lp->lp_data_size);

	lqe->lqe_payload = *lp;
	(void) memcpy((uint8_t *)lqe + sizeof(*lqe), lp_data, lqe->lqe_payload.lp_data_size);
	STAILQ_INSERT_TAIL(&lq->lq_log_list, lqe, lqe_link);
	publish(&lqe->lqe_state, LOG_QUEUE_ENTRY_STATE_STORED);

	counter_inc_preemption_disabled(&log_queue_cnt_queued);

	return true;
}

/*
 * Remove successfully sent logs from a dispatch list and free them.
 */
static size_t
dispatch_list_cleanup(log_queue_t lq)
{
	log_queue_entry_t lqe, lqe_tmp;
	size_t freed = 0;

	STAILQ_FOREACH_SAFE(lqe, &lq->lq_dispatch_list, lqe_link, lqe_tmp) {
		log_queue_entry_state_t lqe_state = log_queue_entry_state(lqe);
		assert(lqe_state != LOG_QUEUE_ENTRY_STATE_STORED);

		if (lqe_state == LOG_QUEUE_ENTRY_STATE_SENT) {
			STAILQ_REMOVE(&lq->lq_dispatch_list, lqe, log_queue_entry, lqe_link);
			publish(&lqe->lqe_state, LOG_QUEUE_ENTRY_STATE_INVALID);
			log_queue_entry_free(lq, lqe);
			counter_dec_preemption_disabled(&log_queue_cnt_queued);
			freed++;
		}
	}

	return freed;
}

/*
 * Walk and collect logs stored in the log queue suitable for dispatching.
 * First, collect previously failed logs, then (if still enough space) grab new
 * logs.
 */
static size_t
log_dispatch_prepare(log_queue_t lq, size_t requested, log_queue_entry_t *buf)
{
	log_queue_entry_t lqe, lqe_tmp;
	size_t collected = 0;

	STAILQ_FOREACH(lqe, &lq->lq_dispatch_list, lqe_link) {
		log_queue_entry_state_t lqe_state = log_queue_entry_state(lqe);
		assert(lqe_state != LOG_QUEUE_ENTRY_STATE_STORED);

		if (lqe_state == LOG_QUEUE_ENTRY_STATE_FAILED) {
			publish(&lqe->lqe_state, LOG_QUEUE_ENTRY_STATE_DISPATCHED);
			buf[collected++] = lqe;
		}

		if (collected == requested) {
			return collected;
		}
	}
	assert(collected < requested);

	STAILQ_FOREACH_SAFE(lqe, &lq->lq_log_list, lqe_link, lqe_tmp) {
		assert(log_queue_entry_state(lqe) == LOG_QUEUE_ENTRY_STATE_STORED);

		STAILQ_REMOVE(&lq->lq_log_list, lqe, log_queue_entry, lqe_link);
		STAILQ_INSERT_TAIL(&lq->lq_dispatch_list, lqe, lqe_link);
		publish(&lqe->lqe_state, LOG_QUEUE_ENTRY_STATE_DISPATCHED);

		buf[collected++] = lqe;
		if (collected == requested) {
			break;
		}
	}

	return collected;
}

/*
 * Send dispatched logs to the firehose. Skip streaming when replaying.
 * Streaming does not process timestamps and would therefore show logs out of
 * order.
 */
static void
log_queue_dispatch_logs(size_t logs_count, log_queue_entry_t *logs)
{
	for (size_t i = 0; i < logs_count; i++) {
		const log_queue_entry_t lqe = logs[i];
		log_queue_entry_state_t lqe_state = log_queue_entry_state(lqe);

		if (lqe_state == LOG_QUEUE_ENTRY_STATE_DISPATCHED) {
			const log_payload_t lqe_lp = &lqe->lqe_payload;

			log_payload_s lp = {
				.lp_ftid = read_dependent_w(&lqe_lp->lp_ftid, lqe_state),
				.lp_timestamp = read_dependent_w(&lqe_lp->lp_timestamp, lqe_state),
				.lp_stream = read_dependent(&lqe_lp->lp_stream, lqe_state),
				.lp_data_size = read_dependent(&lqe_lp->lp_data_size, lqe_state)
			};
			const void *lp_data = (uint8_t *)lqe + sizeof(*lqe);

			/*
			 * The log queue mechanism expects only the state to be
			 * modified here since we are likely running on a
			 * different cpu. Queue cleanup will be done safely
			 * later in dispatch_list_cleanup().
			 */
			if (log_payload_send(&lp, lp_data, false)) {
				publish(&lqe->lqe_state, LOG_QUEUE_ENTRY_STATE_SENT);
				counter_inc(&log_queue_cnt_sent);
			} else {
				publish(&lqe->lqe_state, LOG_QUEUE_ENTRY_STATE_FAILED);
			}
		}
	}
}

static bool
log_queue_empty(const log_queue_t lq)
{
	return STAILQ_EMPTY(&lq->lq_log_list) && STAILQ_EMPTY(&lq->lq_dispatch_list);
}

static boolean_t
log_queue_low_mem(const log_queue_t lq)
{
	return lq->lq_cnt_mem_avail < (lq->lq_cnt_mem_active * lq_low_mem_limit);
}

static lq_req_state_t
log_queue_request_state(log_queue_t lq)
{
	lq_req_state_t req_state = read_dependency(&lq->lq_req_state);
	return req_state;
}

static void
log_queue_mem_init(log_queue_t lq, size_t idx, void *buf, size_t buflen)
{
	assert(buf);
	assert(buflen > 0);
	assert(idx < LQ_MAX_LM_SLOTS);
	assert(!LQ_MEM_ENABLED(lq, idx));

	logmem_init(&lq->lq_mem[idx], buf, buflen, lq->lq_mem_size_order,
	    LQ_MIN_LOG_SZ_ORDER, LQ_MAX_LOG_SZ_ORDER);
}

static void
log_queue_mem_deinit(log_queue_t lq, size_t idx)
{
	assert(idx < LQ_MAX_LM_SLOTS);
	assert(!LQ_MEM_ENABLED(lq, idx));

	logmem_t *lm = &lq->lq_mem[idx];
	bzero((void *)lm, sizeof(*lm));
}

static int
log_queue_mem_free_slot(log_queue_t lq)
{
	assert(LQ_MEM_ENABLED(lq, 0));

	for (int i = 1; i < LQ_MAX_LM_SLOTS; i++) {
		if (!LQ_MEM_ENABLED(lq, i)) {
			return i;
		}
	}
	return -1;
}

static void
log_queue_memory_handler(thread_call_param_t a0, __unused thread_call_param_t a1)
{
	log_queue_t lq = (log_queue_t)a0;
	lq_req_state_t req_state = log_queue_request_state(lq);

	assert(req_state != LQ_REQ_STATE_INVALID);

	if (req_state == LQ_REQ_STATE_ALLOCATING) {
		lq->lq_req_mem = log_queue_buffer_alloc(lq->lq_mem_size);
		publish(&lq->lq_req_state, LQ_REQ_STATE_READY);

		if (lq->lq_req_mem) {
			counter_inc(&log_queue_cnt_mem_allocated);
		} else {
			counter_inc(&log_queue_cnt_mem_failed);
		}
	} else if (req_state == LQ_REQ_STATE_RELEASING) {
		void *buf = read_dependent(&lq->lq_req_mem, req_state);

		log_queue_buffer_free(buf, lq->lq_mem_size);
		lq->lq_req_mem = NULL;
		publish(&lq->lq_req_state, LQ_REQ_STATE_READY);

		counter_inc(&log_queue_cnt_mem_released);
	}
}

static void
log_queue_order_memory(log_queue_t lq)
{
	boolean_t __assert_only running;

	lq->lq_req_mem = NULL;
	publish(&lq->lq_req_state, LQ_REQ_STATE_ALLOCATING);

	running = thread_call_enter(lq->lq_mem_handler);
	assert(!running);
}

static void
log_queue_release_memory(log_queue_t lq, void *buf)
{
	boolean_t __assert_only running;

	assert(buf);
	lq->lq_req_mem = buf;
	publish(&lq->lq_req_state, LQ_REQ_STATE_RELEASING);

	running = thread_call_enter(lq->lq_mem_handler);
	assert(!running);
}

static void
log_queue_mem_enable(log_queue_t lq, size_t i)
{
	logmem_t *lm = &lq->lq_mem[i];
	assert(!LQ_MEM_ENABLED(lq, i));

	LQ_MEM_ENABLE(lq, i);
	lq->lq_cnt_mem_active++;
	lq->lq_cnt_mem_avail += lm->lm_cnt_free;
}

static void
log_queue_mem_disable(log_queue_t lq, size_t i)
{
	logmem_t *lm = &lq->lq_mem[i];
	assert(LQ_MEM_ENABLED(lq, i));

	LQ_MEM_DISABLE(lq, i);
	lq->lq_cnt_mem_active--;
	lq->lq_cnt_mem_avail -= lm->lm_cnt_free;
}

static void *
log_queue_mem_reclaim(log_queue_t lq)
{
	for (int i = 1; i < LQ_MAX_LM_SLOTS; i++) {
		logmem_t *lm = &lq->lq_mem[i];
		if (LQ_MEM_ENABLED(lq, i) && logmem_empty(lm)) {
			assert(lm->lm_mem_size == lq->lq_mem_size);
			void *reclaimed = lm->lm_mem;
			log_queue_mem_disable(lq, i);
			log_queue_mem_deinit(lq, i);
			return reclaimed;
		}
	}
	return NULL;
}

static void
log_queue_mem_reconfigure(log_queue_t lq)
{
	assert(lq->lq_mem_state == LQ_MEM_STATE_ALLOCATING ||
	    lq->lq_mem_state == LQ_MEM_STATE_RELEASING);

	lq_req_state_t req_state = log_queue_request_state(lq);

	if (req_state == LQ_REQ_STATE_READY) {
		if (lq->lq_mem_state == LQ_MEM_STATE_ALLOCATING) {
			void *buf = read_dependent(&lq->lq_req_mem, req_state);
			if (buf) {
				const int i = log_queue_mem_free_slot(lq);
				assert(i > 0);
				log_queue_mem_init(lq, i, buf, lq->lq_mem_size);
				log_queue_mem_enable(lq, i);
			}
		}
		lq->lq_mem_state = LQ_MEM_STATE_READY;
		publish(&lq->lq_req_state, LQ_REQ_STATE_INVALID);
	}
}

static boolean_t
log_queue_needs_memory(log_queue_t lq, boolean_t new_suspend)
{
	if (new_suspend || log_queue_low_mem(lq)) {
		return lq->lq_cnt_mem_active < LQ_MAX_LM_SLOTS;
	}
	return false;
}

static boolean_t
log_queue_can_release_memory(log_queue_t lq)
{
	assert(lq->lq_mem_state == LQ_MEM_STATE_READY);

	if (lq->lq_cnt_mem_active > 1 && log_queue_empty(lq) && !lq->lq_suspend) {
		const uint64_t total_log_cnt = counter_load(&log_queue_cnt_received);
		return total_log_cnt > LQ_DEFAULT_FREE_AFTER_CNT;
	}
	return false;
}

extern boolean_t tasks_suspend_state;

static boolean_t
detect_new_suspend(log_queue_t lq)
{
	if (!tasks_suspend_state) {
		lq->lq_suspend = false;
		return false;
	}

	if (!lq->lq_suspend) {
		lq->lq_suspend = true;
		return true;
	}

	return false;
}

static void
log_queue_dispatch(void)
{
	lq_mem_state_t new_mem_state = LQ_MEM_STATE_READY;
	void *reclaimed_memory = NULL;

	disable_preemption();

	log_queue_t lq = PERCPU_GET(oslog_queue);
	if (__improbable(!lq->lq_ready)) {
		enable_preemption();
		return;
	}

	dispatch_list_cleanup(lq);

	log_queue_entry_t logs[LQ_BATCH_SIZE];
	size_t logs_count = log_dispatch_prepare(lq, LQ_BATCH_SIZE, (log_queue_entry_t *)&logs);

	boolean_t new_suspend = detect_new_suspend(lq);

	if (__improbable(lq->lq_mem_state != LQ_MEM_STATE_READY)) {
		log_queue_mem_reconfigure(lq);
	} else if (logs_count == 0 && log_queue_can_release_memory(lq)) {
		reclaimed_memory = log_queue_mem_reclaim(lq);
		if (reclaimed_memory) {
			lq->lq_mem_state = LQ_MEM_STATE_RELEASING;
			new_mem_state = lq->lq_mem_state;
		}
	} else if (log_queue_needs_memory(lq, new_suspend)) {
		lq->lq_mem_state = LQ_MEM_STATE_ALLOCATING;
		new_mem_state = lq->lq_mem_state;
	}

	enable_preemption();

	switch (new_mem_state) {
	case LQ_MEM_STATE_RELEASING:
		assert(logs_count == 0);
		log_queue_release_memory(lq, reclaimed_memory);
		break;
	case LQ_MEM_STATE_ALLOCATING:
		log_queue_order_memory(lq);
	/* FALLTHROUGH */
	case LQ_MEM_STATE_READY:
		log_queue_dispatch_logs(logs_count, logs);
		break;
	default:
		panic("Invalid log memory state %u", new_mem_state);
		break;
	}
}

static bool
log_queue_add(log_payload_t lp, const uint8_t *lp_data)
{
	boolean_t order_memory = false;

	disable_preemption();

	log_queue_t lq = PERCPU_GET(oslog_queue);
	if (__improbable(!lq->lq_ready)) {
		enable_preemption();
		counter_inc(&log_queue_cnt_dropped_off);
		return false;
	}

	boolean_t new_suspend = detect_new_suspend(lq);

	if (__improbable(lq->lq_mem_state != LQ_MEM_STATE_READY)) {
		log_queue_mem_reconfigure(lq);
	} else if (log_queue_needs_memory(lq, new_suspend)) {
		lq->lq_mem_state = LQ_MEM_STATE_ALLOCATING;
		order_memory = true;
	}

	bool added = log_queue_add_entry(lq, lp, lp_data);
	enable_preemption();

	if (order_memory) {
		log_queue_order_memory(lq);
	}

	return added;
}

__startup_func
static size_t
log_queue_init_memory(log_queue_t lq, size_t lm_count)
{
	assert(lm_count <= LQ_MAX_LM_SLOTS);

	for (size_t i = 0; i < lm_count; i++) {
		void *buf = log_queue_buffer_alloc(lq->lq_mem_size);
		if (!buf) {
			return i;
		}
		counter_inc(&log_queue_cnt_mem_allocated);
		log_queue_mem_init(lq, i, buf, lq->lq_mem_size);
		log_queue_mem_enable(lq, i);
	}

	return lm_count;
}

__startup_func
static void
oslog_init_log_queues(void)
{
	if (os_log_disabled()) {
		printf("Log queues disabled: Logging disabled by ATM\n");
		return;
	}

	if (lq_bootarg_size_order == 0) {
		printf("Log queues disabled: Zero lq_size_order boot argument\n");
		return;
	}

	lq_bootarg_size_order = MAX(lq_bootarg_size_order, PAGE_SHIFT);
	lq_bootarg_size_order = MIN(lq_bootarg_size_order, LQ_MAX_SZ_ORDER);

	lq_bootarg_nslots = MAX(lq_bootarg_nslots, 1);
	lq_bootarg_nslots = MIN(lq_bootarg_nslots, LQ_MAX_LM_SLOTS);

	lq_low_mem_limit = MAX(1 << (lq_bootarg_size_order - LQ_LOW_MEM_SCALE), 1024);

	unsigned int slot_count = 0;

	percpu_foreach(lq, oslog_queue) {
		lq->lq_mem_size_order = lq_bootarg_size_order;
		lq->lq_mem_size = round_page(logmem_required_size(lq->lq_mem_size_order, LQ_MIN_LOG_SZ_ORDER));
		lq->lq_mem_handler = thread_call_allocate(log_queue_memory_handler, (thread_call_param_t)lq);
		slot_count += log_queue_init_memory(lq, lq_bootarg_nslots);
		STAILQ_INIT(&lq->lq_log_list);
		STAILQ_INIT(&lq->lq_dispatch_list);
		lq->lq_ready = true;
	}

	printf("Log queues configured: slot count: %u, per-slot size: %u, total size: %u\n",
	    slot_count, (1 << lq_bootarg_size_order),
	    slot_count * (1 << lq_bootarg_size_order));
}
STARTUP(OSLOG, STARTUP_RANK_SECOND, oslog_init_log_queues);

bool
log_queue_log(log_payload_t lp, const void *lp_data, bool stream)
{
	assert(lp);
	assert(oslog_is_safe() || startup_phase < STARTUP_SUB_EARLY_BOOT);

	counter_inc(&log_queue_cnt_received);

	if (log_payload_send(lp, lp_data, stream)) {
		counter_inc(&log_queue_cnt_sent);
		log_queue_dispatch();
		return true;
	}
	counter_inc(&log_queue_cnt_rejected_fh);

	if (!log_queue_add(lp, lp_data)) {
		return false;
	}

	return true;
}
