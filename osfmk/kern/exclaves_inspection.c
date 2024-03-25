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

#define EXCLAVES_ID_STACKSHOT_SERVER_EP \
	(exclaves_endpoint_lookup("com.apple.service.Stackshot"))

static _Atomic bool exclaves_inspection_initialized;
static stackshot_taker_s tb_client;
static size_t exclaves_stackshot_buffer_size;
static uint8_t ** exclaves_stackshot_buffer_pages;
static uint8_t * exclaves_stackshot_buffer;
static integer_t exclaves_collect_priority = MAXPRI_KERNEL;
static thread_t exclaves_collection_thread;
static uint64_t scid_list[EXCLAVES_STACKSHOT_BATCH_SIZE];
static ctid_t ctid_list[EXCLAVES_STACKSHOT_BATCH_SIZE];
static size_t scid_list_count;

static void *exclaves_collect_event = NULL;

queue_head_t exclaves_inspection_queue_stackshot;
queue_head_t exclaves_inspection_queue_kperf;

static LCK_GRP_DECLARE(exclaves_inspection_lck_grp, "exclaves_inspection_lock");
LCK_MTX_DECLARE(exclaves_collect_mtx, &exclaves_inspection_lck_grp);

void *fake_crash_buffer = NULL;
uint32_t fake_crash_buffer_length = 0;
TUNABLE(bool, fake_exclave_crash_report, "fake_exclave_crash_report", true); /* Generate fake exclave crash report */

static void             exclaves_collect_threads_thread(void *arg, wait_result_t __unused wr);
void                    exclaves_inspection_check_ast(void);

extern kern_return_t
stackshot_exclaves_process_result(kern_return_t collect_kr, const stackshot_stackshotresult_s *result);

extern __attribute__((noinline))
void kperf_thread_exclaves_ast_handler(thread_t thread, const stackshot_stackshotentry_s * _Nonnull entry);

typedef kern_return_t (*exclaves_inspection_process_fn)(kern_return_t collect_kr, const stackshot_stackshotresult_s *data);

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
		pscid_list[count] = thread->th_exclaves_scheduling_context_id;
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
		pscid_list[count] = thread->th_exclaves_scheduling_context_id;
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
process_exclaves_buffer(uint8_t * buffer, size_t output_length, exclaves_inspection_process_fn process_fn)
{
	__block kern_return_t error = KERN_SUCCESS;
	tb_error_t tberr = TB_ERROR_SUCCESS;

	if (output_length) {
		tberr = stackshot_stackshotresult__unmarshal(buffer, output_length, ^(stackshot_stackshotresult_s result){
			error = process_fn(KERN_SUCCESS, &result);
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
collect_scid_list(exclaves_inspection_process_fn process_fn)
{
	__block kern_return_t kr = KERN_SUCCESS;
	tb_error_t tberr = 0;
	scid_v_s scids = { 0 };

	exclaves_debug_printf(show_progress, "exclaves stackshot: starting collection, scid_list_count=%zu\n", scid_list_count);

	scid__v_assign_copy(&scids, scid_list, scid_list_count);

	tberr = stackshot_taker_takestackshot(&tb_client, &scids, true, false, ^(stackshot_outputlength_s output_length) {
		assert3u(output_length, <=, exclaves_stackshot_buffer_size);

		size_t remaining = output_length;
		uint8_t * dst = exclaves_stackshot_buffer;
		size_t page_index = 0;
		bool copy_to_fake_buffer = fake_exclave_crash_report && !fake_crash_buffer_length &&
		(output_length <= PAGE_SIZE * CONCLAVE_CRASH_BUFFER_PAGECOUNT);
		uint8_t *fake_dst = fake_crash_buffer;

		/* TODO: rdar://115413837 (Map stackshot buffer pages to a continuous range, do not copy) */
		while (remaining >= PAGE_SIZE) {
		        memcpy(dst, exclaves_stackshot_buffer_pages[page_index], PAGE_SIZE);
		        if (copy_to_fake_buffer) {
		                memcpy(fake_dst, exclaves_stackshot_buffer_pages[page_index], PAGE_SIZE);
		                fake_dst += PAGE_SIZE;
			}
		        dst += PAGE_SIZE;
		        page_index++;
		        remaining -= PAGE_SIZE;
		}
		if (remaining) {
		        memcpy(dst, exclaves_stackshot_buffer_pages[page_index], remaining);
		        if (copy_to_fake_buffer) {
		                memcpy(fake_dst, exclaves_stackshot_buffer_pages[page_index], remaining);
			}
		}
		if (copy_to_fake_buffer) {
		        fake_crash_buffer_length = (uint32_t)output_length;
		}

		kr = process_exclaves_buffer(exclaves_stackshot_buffer, (size_t)output_length, process_fn);
	});

	if (tberr != TB_ERROR_SUCCESS) {
		exclaves_debug_printf(show_errors, "exclaves stackshot: stackshot_taker_takestackshot error 0x%x\n", tberr);
		kr = KERN_FAILURE;
		goto error_exit;
	}

error_exit:
	exclaves_debug_printf(show_progress, "exclaves stackshot: collection done with result %d\n", kr);
	return kr;
}

static kern_return_t
complete_kperf_ast(kern_return_t collect_kr, const stackshot_stackshotresult_s *result)
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
	os_atomic_store(&current_thread()->th_exclaves_inspection_state, TH_EXCLAVES_INSPECTION_NOINSPECT, relaxed);
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

				kr = collect_scid_list(stackshot_exclaves_process_result);
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
			stackshot_exclaves_process_result(kr, NULL);
			wakeup_all_with_inheritor(&exclaves_inspection_queue_stackshot, THREAD_AWAKENED);
		}

		if (!queue_empty(&exclaves_inspection_queue_kperf)) {
			scid_list_count = prepare_scid_list_kperf(&exclaves_inspection_queue_kperf, scid_list, ctid_list, EXCLAVES_STACKSHOT_BATCH_SIZE);
			while (scid_list_count) {
				lck_mtx_unlock(&exclaves_collect_mtx);

				kr = collect_scid_list(complete_kperf_ast);
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

	queue_init(&exclaves_inspection_queue_stackshot);
	queue_init(&exclaves_inspection_queue_kperf);

	kr = (kernel_thread_start_priority(
		    exclaves_collect_threads_thread, NULL, exclaves_collect_priority, &exclaves_collection_thread));
	if (kr != KERN_SUCCESS) {
		goto error_exit;
	}
	thread_set_thread_name(exclaves_collection_thread, "exclaves-stackshot");
	thread_deallocate(exclaves_collection_thread);

	tb_endpoint = tb_endpoint_create_with_value(TB_TRANSPORT_TYPE_XNU, EXCLAVES_ID_STACKSHOT_SERVER_EP, TB_ENDPOINT_OPTIONS_NONE);

	tberr = stackshot_taker__init(&tb_client, tb_endpoint);
	if (tberr != TB_ERROR_SUCCESS) {
		exclaves_debug_printf(show_errors, "exclaves stackshot: stackshot_taker_init error 0x%x\n", tberr);
		return KERN_FAILURE;
	}

	if (fake_exclave_crash_report) {
		fake_crash_buffer = kalloc_data(CONCLAVE_CRASH_BUFFER_PAGECOUNT * PAGE_SIZE, Z_WAITOK);
	}

	tberr = stackshot_taker_allocsharedbuffer(&tb_client, ^(stackshot_sharedbuffer_s tbresult) {
		__block size_t page_count = 0;
		exclaves_stackshot_buffer_size = 0;
		u64__v_visit(&tbresult.physaddr, ^(size_t __unused i, const uint64_t __unused item) {
			page_count++;
		});
		if (!page_count) {
		        exclaves_debug_printf(show_errors, "exclaves stackshot: stackshot_taker_allocsharedbuffer did not return any page addresses\n");
		        kr = KERN_RESOURCE_SHORTAGE;
		        return;
		}

		if (os_mul_overflow(page_count, PAGE_SIZE, &exclaves_stackshot_buffer_size)) {
		        panic("exclaves stackshot: buffer size overflow");
		        return;
		}
		exclaves_stackshot_buffer = kalloc_type(uint8_t, exclaves_stackshot_buffer_size, Z_WAITOK);
		if (!exclaves_stackshot_buffer) {
		        panic("exclaves stackshot: cannot allocate buffer for exclaves shared memory");
		        return;
		}

		exclaves_stackshot_buffer_pages = kalloc_type(uint8_t*, page_count, Z_WAITOK);
		if (!exclaves_stackshot_buffer_pages) {
		        panic("exclaves stackshot: cannot allocate buffer for exclaves shared memory addresses");
		        return;
		}

		u64__v_visit(&tbresult.physaddr, ^(size_t i, const uint64_t item) {
			exclaves_stackshot_buffer_pages[i] = (uint8_t*)phystokv((pmap_paddr_t)item);
		});
	});

	if (tberr != TB_ERROR_SUCCESS) {
		exclaves_debug_printf(show_errors, "exclaves stackshot: stackshot_taker_allocsharedbuffer error 0x%x\n", tberr);
		/*
		 * Until rdar://115836013 is resolved, this failure must be
		 * supressed.
		 */
		return KERN_SUCCESS;
	}

	// this may be due to invalid call or set from result handler
	if (kr != KERN_SUCCESS) {
		goto error_exit;
	}

	exclaves_debug_printf(show_progress, "exclaves stackshot: exclaves stackshot buffer size: %zu bytes\n", exclaves_stackshot_buffer_size);

	os_atomic_store(&exclaves_inspection_initialized, true, release);
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
 * This function expects preemption and interrupts disabled as
 * exclaves_scheduler_request does.
 *
 * TH_EXCLAVES_STACKSHOT_AST is set when stackshot is running in debug mode
 * and adds a thread to waiting list.
 *
 * TH_EXCLAVES_STACKSHOT_AST is cleaned up by a collection thread which is
 * holding exclaves_collect_mtx.
 *
 * It's guaranteed that th_exclaves_inspection_state & TH_EXCLAVES_STACKSHOT_AST is false
 * when it exits.
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

#endif /* CONFIG_EXCLAVES */
