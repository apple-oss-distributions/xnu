/*
 * Copyright (c) 2023 Apple Inc. All rights reserved.
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

#if CONFIG_EXCLAVES

#include <kern/exclaves_debug.h>
#include <kern/exclaves_inspection.h>
#include <kern/exclaves_stackshot.h>
#include <kern/exclaves_test_stackshot.h>
#include <kern/exclaves_boot.h>
#include <kern/exclaves.tightbeam.h>
#include <mach/exclaves_l4.h>
#include <vm/pmap.h>

#define EXCLAVES_STACKSHOT_BATCH_SIZE 32
#define EXCLAVES_STACKSHOT_BUFFER_SIZE (16 * PAGE_SIZE)

#include "exclaves_resource.h"

#define EXCLAVES_ID_STACKSHOT_SERVER_EP              \
    (exclaves_service_lookup(EXCLAVES_DOMAIN_KERNEL, \
    "com.apple.service.Stackshot"))

static _Atomic bool exclaves_inspection_initialized;

/* Exclaves may provide full stackshot server with service Taker or redacted
 * stackshot server with service RedactedTaker. */
static struct {
	stackshot_stackshotservervariant_s variant;
	union {
		stackshot_redactedtaker_s redacted;
		stackshot_taker_s internal;
	} conn;
} exclaves_stackshot_client;

static uint8_t exclaves_stackshot_buffer[EXCLAVES_STACKSHOT_BUFFER_SIZE];
static integer_t exclaves_collect_priority = MAXPRI_KERNEL;
static thread_t exclaves_collection_thread;
static uint64_t scid_list[EXCLAVES_STACKSHOT_BATCH_SIZE];
static ctid_t ctid_list[EXCLAVES_STACKSHOT_BATCH_SIZE];
static size_t scid_list_count;
bool exclaves_stackshot_raw_addresses;
bool exclaves_stackshot_all_address_spaces;
exclaves_resource_t * stackshot_sharedmem_resource;
exclaves_panic_ss_status_t exclaves_panic_ss_status = EXCLAVES_PANIC_STACKSHOT_UNKNOWN;

static void *exclaves_collect_event = NULL;

static uint8_t exclaves_collect_thread_ready = 0;

queue_head_t exclaves_inspection_queue_stackshot;
queue_head_t exclaves_inspection_queue_kperf;

static LCK_GRP_DECLARE(exclaves_inspection_lck_grp, "exclaves_inspection_lock");
LCK_MTX_DECLARE(exclaves_collect_mtx, &exclaves_inspection_lck_grp);
// Guards initialization to ensure nothing tries to collect before all threads/allocations/etc. are done
LCK_MTX_DECLARE(exclaves_collect_init_mtx, &exclaves_inspection_lck_grp);

static void             exclaves_collect_threads_thread(void *arg, wait_result_t __unused wr);

extern kern_return_t
stackshot_exclaves_process_result(kern_return_t collect_kr, const stackshot_stackshotresult_s *result, bool want_raw_addresses);

extern __attribute__((noinline))
void kperf_thread_exclaves_ast_handler(thread_t thread, const stackshot_stackshotentry_s * _Nonnull entry);

typedef kern_return_t (*exclaves_inspection_process_fn)(kern_return_t collect_kr, const stackshot_stackshotresult_s *data, bool want_raw_addresses);


/* Populate provided buffer with a list of scid values of threads from end of the list. */
static size_t
prepare_scid_list_stackshot(queue_t wl, uint64_t *pscid_list, ctid_t *pctid_list, uint64_t max_threads)
{
	thread_t thread = NULL;
	size_t count = 0;

	lck_mtx_assert(&exclaves_collect_mtx, LCK_MTX_ASSERT_OWNED);

	for (count = 0; count < max_threads; ++count) {
		thread = qe_dequeue_tail(wl, struct thread, th_exclaves_inspection_queue_stackshot);
		if (thread == NULL) {
			break;
		}
		pscid_list[count] = thread->th_exclaves_ipc_ctx.scid;
		pctid_list[count] = thread_get_ctid(thread);
	}

	return count;
}

static size_t
prepare_scid_list_kperf(queue_t wl, uint64_t *pscid_list, ctid_t *pctid_list, uint64_t max_threads)
{
	thread_t thread = NULL;
	size_t count = 0;

	lck_mtx_assert(&exclaves_collect_mtx, LCK_MTX_ASSERT_OWNED);

	for (count = 0; count < max_threads; ++count) {
		thread = qe_dequeue_tail(wl, struct thread, th_exclaves_inspection_queue_kperf);
		if (thread == NULL) {
			break;
		}
		pscid_list[count] = thread->th_exclaves_ipc_ctx.scid;
		pctid_list[count] = thread_get_ctid(thread);
	}

	return count;
}

/* Clear flag from the list of pending threads, allowing them to run. */
static void
clear_pending_threads_stackshot(ctid_t *ctids, size_t count, thread_exclaves_inspection_flags_t flag)
{
	size_t i;
	thread_t thread;

	for (i = 0; i < count; ++i) {
		thread = ctid_get_thread(ctids[i]);
		ctids[i] = 0;
		assert(thread);

		os_atomic_and(&thread->th_exclaves_inspection_state, ~flag, relaxed);
		wakeup_all_with_inheritor((event_t)&thread->th_exclaves_inspection_queue_stackshot, THREAD_AWAKENED);
		thread_deallocate_safe(thread);
	}
}

static void
clear_pending_threads_kperf(ctid_t *ctids, size_t count, thread_exclaves_inspection_flags_t flag)
{
	size_t i;
	thread_t thread;

	for (i = 0; i < count; ++i) {
		thread = ctid_get_thread(ctids[i]);
		ctids[i] = 0;
		assert(thread);

		os_atomic_and(&thread->th_exclaves_inspection_state, ~flag, relaxed);
		wakeup_all_with_inheritor((event_t)&thread->th_exclaves_inspection_queue_kperf, THREAD_AWAKENED);
		thread_deallocate_safe(thread);
	}
}

static void
clear_stackshot_queue(thread_exclaves_inspection_flags_t flag)
{
	thread_t thread;

	lck_mtx_assert(&exclaves_collect_mtx, LCK_MTX_ASSERT_OWNED);

	while (!queue_empty(&exclaves_inspection_queue_stackshot)) {
		thread = qe_dequeue_tail(&exclaves_inspection_queue_stackshot, struct thread, th_exclaves_inspection_queue_stackshot);
		assert(thread);
		os_atomic_and(&thread->th_exclaves_inspection_state, ~flag, relaxed);
		wakeup_all_with_inheritor((event_t)&thread->th_exclaves_inspection_queue_stackshot, THREAD_AWAKENED);
		thread_deallocate_safe(thread);
	}
}

static void
clear_kperf_queue(thread_exclaves_inspection_flags_t flag)
{
	thread_t thread;

	lck_mtx_assert(&exclaves_collect_mtx, LCK_MTX_ASSERT_OWNED);

	while (!queue_empty(&exclaves_inspection_queue_kperf)) {
		thread = qe_dequeue_tail(&exclaves_inspection_queue_kperf, struct thread, th_exclaves_inspection_queue_kperf);
		assert(thread);
		os_atomic_and(&thread->th_exclaves_inspection_state, ~flag, relaxed);
		wakeup_all_with_inheritor((event_t)&thread->th_exclaves_inspection_queue_kperf, THREAD_AWAKENED);
		thread_deallocate_safe(thread);
	}
}

static kern_return_t
process_exclaves_buffer(uint8_t * buffer, size_t output_length, exclaves_inspection_process_fn process_fn, bool want_raw_addresses)
{
	__block kern_return_t error = KERN_SUCCESS;
	tb_error_t tberr = TB_ERROR_SUCCESS;

	if (output_length) {
		tberr = stackshot_stackshotresult__unmarshal(buffer, output_length, ^(stackshot_stackshotresult_s result){
			error = process_fn(KERN_SUCCESS, &result, want_raw_addresses);
			if (error != KERN_SUCCESS) {
			        exclaves_debug_printf(show_errors, "exclaves stackshot: error processing stackshot result\n");
			}
		});
		if (tberr != TB_ERROR_SUCCESS) {
			exclaves_debug_printf(show_errors, "exclaves stackshot: process_exclaves_buffer could not unmarshal stackshot data 0x%x\n", tberr);
			error = KERN_FAILURE;
			goto error_exit;
		}
	} else {
		error = KERN_FAILURE;
		exclaves_debug_printf(show_errors, "exclaves stackshot: exclave stackshot data did not fit into shared memory buffer\n");
	}

error_exit:
	return error;
}

static kern_return_t
collect_scid_list(exclaves_inspection_process_fn process_fn, bool want_raw_addresses, bool all_address_spaces)
{
	__block kern_return_t kr = KERN_SUCCESS;
	tb_error_t tberr = 0;
	scid_v_s scids = { 0 };

	scid__v_assign_unowned(&scids, scid_list, scid_list_count);

	// copy data from stackshot_sharedmem_resource to exclaves_stackshot_buffer
	void (^success_handler)(stackshot_outputlength_s);
	success_handler = ^(stackshot_outputlength_s output_length) {
		__assert_only size_t len = 0;
		char *ss_buffer = exclaves_resource_shared_memory_get_buffer(stackshot_sharedmem_resource, &len);
		assert3u(len, ==, EXCLAVES_STACKSHOT_BUFFER_SIZE);

		assert3u(output_length, <=, EXCLAVES_STACKSHOT_BUFFER_SIZE);
		memcpy(exclaves_stackshot_buffer, ss_buffer, output_length);

		kr = process_exclaves_buffer(exclaves_stackshot_buffer, (size_t)output_length, process_fn, want_raw_addresses);
	};

	if (exclaves_stackshot_client.variant == STACKSHOT_STACKSHOTSERVERVARIANT_INTERNAL) {
		tberr = stackshot_taker_runstackshot(&exclaves_stackshot_client.conn.internal, &scids, want_raw_addresses, all_address_spaces, ^(stackshot_taker_runstackshot__result_s res) {
			stackshot_outputlength_s * p_len = stackshot_taker_runstackshot__result_get_success(&res);
			if (p_len) {
			        success_handler(*p_len);
			} else {
			        stackshot_stackshotserverfailure_s * p_failure = stackshot_taker_runstackshot__result_get_failure(&res);
			        if (p_failure) {
			                exclaves_debug_printf(show_errors, "exclaves stackshot: stackshot_taker_runstackshot failure %ul\n", *p_failure);
				} else {
			                exclaves_debug_printf(show_errors, "exclaves stackshot: stackshot_taker_runstackshot unknown failure\n");
				}
			}
		});
	} else {
		tberr = stackshot_redactedtaker_runstackshotredacted(&exclaves_stackshot_client.conn.redacted, &scids, all_address_spaces, ^(stackshot_redactedtaker_runstackshotredacted__result_s res){
			stackshot_outputlength_s * p_len = stackshot_redactedtaker_runstackshotredacted__result_get_success(&res);
			if (p_len) {
			        success_handler(*p_len);
			} else {
			        stackshot_stackshotserverfailure_s * p_failure = stackshot_redactedtaker_runstackshotredacted__result_get_failure(&res);
			        if (p_failure) {
			                exclaves_debug_printf(show_errors, "exclaves stackshot: stackshot_redactedtaker_runstackshotredacted failure %ul\n", *p_failure);
				} else {
			                exclaves_debug_printf(show_errors, "exclaves stackshot: stackshot_redactedtaker_runstackshotredacted unknown failure\n");
				}
			}
		});
	}

	if (tberr != TB_ERROR_SUCCESS) {
		exclaves_debug_printf(show_errors, "exclaves stackshot: stackshot_(redacted)taker_runstackshot error 0x%x\n", tberr);
		kr = KERN_FAILURE;
		goto error_exit;
	}

error_exit:
	exclaves_debug_printf(show_progress, "exclaves stackshot: collection done with result %d\n", kr);
	return kr;
}

static kern_return_t
complete_kperf_ast(kern_return_t collect_kr, const stackshot_stackshotresult_s *result, __unused bool want_raw_addresses)
{
	if (collect_kr != KERN_SUCCESS) {
		return collect_kr;
	}

	stackshot_stackshotentry__v_visit(&result->stackshotentries, ^(size_t i, const stackshot_stackshotentry_s * _Nonnull entry) {
		assert(i < scid_list_count);
		thread_t thread = ctid_get_thread(ctid_list[i]);
		assert(thread);
		kperf_thread_exclaves_ast_handler(thread, entry);
	});

	return KERN_SUCCESS;
}

/*
 * Kernel thread that will collect, upon event (exclaves_collect_event), data
 * on the current activity in the Exclave world of a set of threads registered
 * with its waitlist.
 */
__attribute__((noreturn))
static void
exclaves_collect_threads_thread(void __unused *arg, wait_result_t __unused wr)
{
	kern_return_t kr = KERN_SUCCESS;

	kr = exclaves_allocate_ipc_buffer(NULL);
	if (kr != KERN_SUCCESS) {
		panic("exclaves stackshot: failed to allocate collect ipcb: %d", kr);
	}

	os_atomic_store(&current_thread()->th_exclaves_inspection_state, TH_EXCLAVES_INSPECTION_NOINSPECT, relaxed);
	lck_mtx_lock(&exclaves_collect_init_mtx);
	exclaves_collect_thread_ready = true;
	wakeup_all_with_inheritor(&exclaves_collect_thread_ready, THREAD_AWAKENED);
	lck_mtx_unlock(&exclaves_collect_init_mtx);

	lck_mtx_lock(&exclaves_collect_mtx);

	for (;;) {
		while (queue_empty(&exclaves_inspection_queue_stackshot) && queue_empty(&exclaves_inspection_queue_kperf)) {
			lck_mtx_sleep(&exclaves_collect_mtx, LCK_SLEEP_DEFAULT, (event_t)&exclaves_collect_event, THREAD_UNINT);
		}

		if (!queue_empty(&exclaves_inspection_queue_stackshot)) {
			// only this thread should manipulate the scid_list
			scid_list_count = prepare_scid_list_stackshot(&exclaves_inspection_queue_stackshot, scid_list, ctid_list, EXCLAVES_STACKSHOT_BATCH_SIZE);
			while (scid_list_count) {
				lck_mtx_unlock(&exclaves_collect_mtx);

				kr = collect_scid_list(stackshot_exclaves_process_result, exclaves_stackshot_raw_addresses, exclaves_stackshot_all_address_spaces);
				lck_mtx_lock(&exclaves_collect_mtx);
				clear_pending_threads_stackshot(ctid_list, scid_list_count, TH_EXCLAVES_INSPECTION_STACKSHOT);
				if (kr != KERN_SUCCESS) {
					goto stackshot_error;
				}

				scid_list_count = prepare_scid_list_stackshot(&exclaves_inspection_queue_stackshot, scid_list, ctid_list, EXCLAVES_STACKSHOT_BATCH_SIZE);
			}

stackshot_error:
			if (!queue_empty(&exclaves_inspection_queue_stackshot)) {
				clear_stackshot_queue(TH_EXCLAVES_INSPECTION_STACKSHOT);
			}
			stackshot_exclaves_process_result(kr, NULL, true);
			wakeup_all_with_inheritor(&exclaves_inspection_queue_stackshot, THREAD_AWAKENED);
		}

		if (!queue_empty(&exclaves_inspection_queue_kperf)) {
			scid_list_count = prepare_scid_list_kperf(&exclaves_inspection_queue_kperf, scid_list, ctid_list, EXCLAVES_STACKSHOT_BATCH_SIZE);
			while (scid_list_count) {
				lck_mtx_unlock(&exclaves_collect_mtx);

				kr = collect_scid_list(complete_kperf_ast, false, false);
				lck_mtx_lock(&exclaves_collect_mtx);
				clear_pending_threads_kperf(ctid_list, scid_list_count, TH_EXCLAVES_INSPECTION_KPERF);
				if (kr != KERN_SUCCESS) {
					goto kperf_error;
				}

				scid_list_count = prepare_scid_list_kperf(&exclaves_inspection_queue_kperf, scid_list, ctid_list, EXCLAVES_STACKSHOT_BATCH_SIZE);
			}
kperf_error:
			if (!queue_empty(&exclaves_inspection_queue_kperf)) {
				clear_kperf_queue(TH_EXCLAVES_INSPECTION_KPERF);
			}
		}
	}
}

void
exclaves_inspection_begin_collecting(void)
{
	lck_mtx_assert(&exclaves_collect_mtx, LCK_MTX_ASSERT_OWNED);

	thread_wakeup_thread((event_t)&exclaves_collect_event, exclaves_collection_thread);
}

void
exclaves_inspection_wait_complete(queue_t queue)
{
	lck_mtx_assert(&exclaves_collect_mtx, LCK_MTX_ASSERT_OWNED);

	while (!queue_empty(queue)) {
		lck_mtx_sleep_with_inheritor(&exclaves_collect_mtx, LCK_SLEEP_DEFAULT, (event_t)queue, exclaves_collection_thread, THREAD_UNINT, TIMEOUT_WAIT_FOREVER);
	}
}

static kern_return_t
exclaves_inspection_init(void)
{
	__block kern_return_t kr = KERN_SUCCESS;
	tb_error_t tberr = 0;
	tb_endpoint_t tb_endpoint = { 0 };

	assert(!os_atomic_load(&exclaves_inspection_initialized, relaxed));

	/*
	 * If there's no stackshot service available, just return.
	 */
	if (EXCLAVES_ID_STACKSHOT_SERVER_EP == EXCLAVES_INVALID_ID) {
		exclaves_requirement_assert(EXCLAVES_R_STACKSHOT,
		    "stackshot server not found");
		return KERN_SUCCESS;
	}

	queue_init(&exclaves_inspection_queue_stackshot);
	queue_init(&exclaves_inspection_queue_kperf);

	tb_endpoint = tb_endpoint_create_with_value(TB_TRANSPORT_TYPE_XNU, EXCLAVES_ID_STACKSHOT_SERVER_EP, TB_ENDPOINT_OPTIONS_NONE);

	tberr = stackshot_redactedtaker__init(&exclaves_stackshot_client.conn.redacted, tb_endpoint);
	if (tberr != TB_ERROR_SUCCESS) {
		exclaves_debug_printf(show_errors, "exclaves stackshot: stackshot_redactedtaker__init error 0x%x\n", tberr);
		return KERN_FAILURE;
	}

	/* This will initialize whatever version of stackshot server is available */
	tberr = stackshot_redactedtaker_initialize(&exclaves_stackshot_client.conn.redacted, ^(stackshot_stackshotservervariant_s variant) {
		exclaves_stackshot_client.variant = variant;
	});

	if (tberr != TB_ERROR_SUCCESS) {
		exclaves_debug_printf(show_errors, "exclaves stackshot: stackshot_redactedtaker_initialize error 0x%x\n", tberr);
		return KERN_FAILURE;
	}

	if (exclaves_stackshot_client.variant == STACKSHOT_STACKSHOTSERVERVARIANT_INTERNAL) {
		tb_endpoint = tb_endpoint_create_with_value(TB_TRANSPORT_TYPE_XNU, EXCLAVES_ID_STACKSHOT_SERVER_EP, TB_ENDPOINT_OPTIONS_NONE);
		tberr = stackshot_taker__init(&exclaves_stackshot_client.conn.internal, tb_endpoint);
		if (tberr != TB_ERROR_SUCCESS) {
			panic("exclaves stackshot: stackshot_redactedtaker__init error 0x%x\n", tberr);
		}
	}

	// initialize sharedmemv2 resource
	const char *v2_seg_name = "com.apple.sharedmem.stackshotserver";
	kr = exclaves_resource_shared_memory_map(
		EXCLAVES_DOMAIN_KERNEL, v2_seg_name,
		EXCLAVES_STACKSHOT_BUFFER_SIZE,
		EXCLAVES_BUFFER_PERM_READ,
		&stackshot_sharedmem_resource);

	if (kr != KERN_SUCCESS) {
		exclaves_debug_printf(show_errors,
		    "exclaves_inspection_init: Cannot map shared memory segment '%s': failed with %d\n",
		    v2_seg_name, kr);
		return kr;
	}

	exclaves_debug_printf(show_progress, "exclaves stackshot: exclaves inspection initialized\n");

	kr = (kernel_thread_start_priority(
		    exclaves_collect_threads_thread, NULL, exclaves_collect_priority, &exclaves_collection_thread));
	if (kr != KERN_SUCCESS) {
		goto error_exit;
	}
	thread_set_thread_name(exclaves_collection_thread, "exclaves-stackshot");
	thread_deallocate(exclaves_collection_thread);

	lck_mtx_lock(&exclaves_collect_init_mtx);

	while (!exclaves_collect_thread_ready) {
		lck_mtx_sleep_with_inheritor(&exclaves_collect_init_mtx, LCK_SLEEP_DEFAULT, (event_t)&exclaves_collect_thread_ready, exclaves_collection_thread, THREAD_UNINT, TIMEOUT_WAIT_FOREVER);
	}

	os_atomic_store(&exclaves_inspection_initialized, true, release);
	lck_mtx_unlock(&exclaves_collect_init_mtx);
error_exit:
	return kr;
}

EXCLAVES_BOOT_TASK(exclaves_inspection_init, EXCLAVES_BOOT_RANK_SECOND);

bool
exclaves_inspection_is_initialized()
{
	return os_atomic_load(&exclaves_inspection_initialized, acquire);
}

/*
 * TH_EXCLAVES_INSPECTION_STACKSHOT is set when stackshot is running in debug mode
 * and adds a thread to waiting list.
 *
 * TH_EXCLAVES_INSPECTION_STACKSHOT is cleaned up by a collection thread which is
 * holding exclaves_collect_mtx.
 */
void
exclaves_inspection_check_ast(void)
{
	thread_t thread = current_thread();

	assert((os_atomic_load(&thread->th_exclaves_inspection_state, relaxed) & TH_EXCLAVES_INSPECTION_NOINSPECT) == 0);

	/* This will unblock exclaves stackshot collection */
	STACKSHOT_TESTPOINT(TP_AST);

	/* Grab the mutex to prevent cleanup just after next check */
	lck_mtx_lock(&exclaves_collect_mtx);
	while ((os_atomic_load(&thread->th_exclaves_inspection_state, relaxed) & TH_EXCLAVES_INSPECTION_STACKSHOT) != 0) {
		lck_mtx_sleep_with_inheritor(&exclaves_collect_mtx, LCK_SLEEP_DEFAULT,
		    (event_t)&thread->th_exclaves_inspection_queue_stackshot, exclaves_collection_thread,
		    THREAD_UNINT, TIMEOUT_WAIT_FOREVER
		    );
	}

	if ((os_atomic_load(&thread->th_exclaves_inspection_state, relaxed) & TH_EXCLAVES_INSPECTION_KPERF) != 0) {
		exclaves_inspection_queue_add(&exclaves_inspection_queue_kperf, &thread->th_exclaves_inspection_queue_kperf);
		thread_reference(thread);
		exclaves_inspection_begin_collecting();
		lck_mtx_sleep_with_inheritor(&exclaves_collect_mtx, LCK_SLEEP_DEFAULT,
		    (event_t)&thread->th_exclaves_inspection_queue_kperf, exclaves_collection_thread,
		    THREAD_UNINT, TIMEOUT_WAIT_FOREVER
		    );
	}
	lck_mtx_unlock(&exclaves_collect_mtx);
}


/* this should come from somewhere in EP */
#define STACKSHOT_PANIC_MAGIC 0xdeadcafebeefbabe
typedef struct stackshot_panic_magic {
	uint64_t magic;
	uint64_t size;
} stackshot_panic_magic_t;
_Static_assert(sizeof(stackshot_panic_magic_t) == 16, "panic magic should be 16 bytes");

void
kdp_read_panic_exclaves_stackshot(struct exclaves_panic_stackshot *eps)
{
	assert(debug_mode_active());

	*eps = (struct exclaves_panic_stackshot){ 0 };

	if (!exclaves_inspection_is_initialized()) {
		return;
	}

	/* copy the entire potential range of the buffer */
	__assert_only size_t len = 0;
	char *ss_buffer = exclaves_resource_shared_memory_get_buffer(stackshot_sharedmem_resource, &len);
	assert3u(len, ==, EXCLAVES_STACKSHOT_BUFFER_SIZE);
	memcpy(exclaves_stackshot_buffer, ss_buffer, EXCLAVES_STACKSHOT_BUFFER_SIZE);

	/* check for panic magic value in xnu's copy of the region */
	stackshot_panic_magic_t *panic_magic = __IGNORE_WCASTALIGN((stackshot_panic_magic_t *)(exclaves_stackshot_buffer + (EXCLAVES_STACKSHOT_BUFFER_SIZE - sizeof(stackshot_panic_magic_t))));
	if (panic_magic->magic != STACKSHOT_PANIC_MAGIC) {
		return;
	}

	eps->stackshot_buffer = exclaves_stackshot_buffer;
	eps->stackshot_buffer_size = panic_magic->size;
}

#endif /* CONFIG_EXCLAVES */
