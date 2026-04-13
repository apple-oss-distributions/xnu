/*
 * Copyright (c) 2024 Apple Inc. All rights reserved.
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

#include "mach/arm/kern_return.h"
#if CONFIG_EXCLAVES

#include <kern/debug.h>
#include <kern/sched_prim.h>
#include <kern/queue.h>

#include <mach/task.h>

#include <Exclaves/Exclaves.h>

#include "exclaves_aoe.h"
#include "exclaves_boot.h"
#include "exclaves_resource.h"
#include "exclaves_debug.h"

#include "kern/exclaves.tightbeam.h"

#define EXCLAVES_AOE_PROXY "com.apple.service.AlwaysOnExclavesProxy"

static exclavesmessagequeueproxy_exclavesmessagequeueproxy_s aoeproxy_client;

static kern_return_t
exclaves_aoe_boot(void)
{
	exclaves_id_t aoeproxy_id = exclaves_service_lookup(
		EXCLAVES_DOMAIN_KERNEL, EXCLAVES_AOE_PROXY);

	if (aoeproxy_id == EXCLAVES_INVALID_ID) {
		/*
		 * For now just silently return if the AOE proxy can't be found.
		 * In future this should call:
		 *    exclaves_requirement_assert(EXCLAVES_R_AOE,
		 *        "exclaves always on exclave proxy not found");
		 */
		return KERN_SUCCESS;
	}

	tb_endpoint_t ep = tb_endpoint_create_with_value(
		TB_TRANSPORT_TYPE_XNU, aoeproxy_id, TB_ENDPOINT_OPTIONS_NONE);

	tb_error_t ret =
	    exclavesmessagequeueproxy_exclavesmessagequeueproxy__init(&aoeproxy_client, ep);
	if (ret != TB_ERROR_SUCCESS) {
		return KERN_FAILURE;
	}

	return KERN_SUCCESS;
}
EXCLAVES_BOOT_TASK(exclaves_aoe_boot, EXCLAVES_BOOT_RANK_ANY);

kern_return_t
exclaves_aoe_setup(uint8_t *num_message, uint8_t *num_worker)
{
	exclaves_resource_t *conclave = task_get_conclave(current_task());
	assert3p(conclave, !=, NULL);

	/* Return with an error if uninitialised. */
	if (aoeproxy_client.connection == NULL) {
		return KERN_NOT_SUPPORTED;
	}

	lck_mtx_lock(&conclave->r_mutex);

	if (!queue_empty(&conclave->r_conclave.c_aoe_q)) {
		lck_mtx_unlock(&conclave->r_mutex);
		return KERN_FAILURE; /* Already initialised. */
	}

	// since this is the legacy initializer, we will enable legacy "free agent" workers
	conclave->r_conclave.c_aoe_using_free_agents = true;

	/*
	 * Iterate over each AOE Service in the conclave and call setup for each
	 * one.
	 */

	__block uint8_t nmessage = 0;
	__block uint8_t nworker = 0;
	__block bool saw_error = false;
	__block tb_error_t ret = TB_ERROR_SUCCESS;

	/* BEGIN IGNORE CODESTYLE */
	exclaves_resource_aoeservice_iterate(conclave->r_name,
	    ^(exclaves_resource_t *aoe_service) {

		ret = exclavesmessagequeueproxy_exclavesmessagequeueproxy_setup(
		    &aoeproxy_client, aoe_service->r_id,
		    ^(exclavesmessagequeueproxy_exclavesmessagequeueproxy_setup__result_s result) {

			exclavesmessagequeuetypes_workercount_s *wc =
			    exclavesmessagequeueproxy_exclavesmessagequeueproxy_setup__result_get_success(&result);

			if (wc == NULL) {
				exclavesmessagequeueproxy_proxyerror_s *error =
					exclavesmessagequeueproxy_exclavesmessagequeueproxy_setup__result_get_failure(&result);
				assert3p(error, !=, NULL);

				// if AOEproxy doesn't have a service defined in the xnu_proxy_resources table, continue on
				// TODO reconsider this, see rdar://162746126
				if (exclavesmessagequeueproxy_proxyerror_missingservice__get(error)) {
					exclaves_debug_printf(show_progress,
							      "warning: AOE service %llu is missing\n",
							      aoe_service->r_id);
				} else {
					exclaves_debug_printf(show_errors,
							      "AOE setup failed for service: %llu (error: %llu)\n",
							      aoe_service->r_id, error->tag);
					saw_error = true;
				}
			} else {
				/*
				 * Allocate an aoe item for each service to be
				 * used as a per-service rendezvous for message
				 * threads and to hold worker counts for worker
				 * requests.
				 */
				aoe_item_t *aitem = kalloc_type(aoe_item_t,
				    Z_WAITOK | Z_ZERO | Z_NOFAIL);
				aitem->aoei_serviceid = aoe_service->r_id;
				aitem->aoei_message_count = 0;
				aitem->aoei_messenger_count = 0;
				aitem->aoei_work_count = 0;
				aitem->aoei_worker_count = 0;

				queue_enter(&conclave->r_conclave.c_aoe_q, aitem,
				    aoe_item_t *, aoei_chain);

				nmessage++;
				nworker += *wc;
			}
		});

		/* Break out early for errors. */
		if (saw_error || ret != TB_ERROR_SUCCESS) {
			return (bool)true;
		}

		return (bool)(false);
	});
	/* END IGNORE CODESTYLE */

	if (saw_error || ret != TB_ERROR_SUCCESS) {
		exclaves_aoe_teardown();
		lck_mtx_unlock(&conclave->r_mutex);
		return KERN_FAILURE;
	}

	lck_mtx_unlock(&conclave->r_mutex);

	if (nmessage == 0) {
		return KERN_FAILURE;
	}

	*num_message = nmessage;
	*num_worker = nworker;

	return KERN_SUCCESS;
}

kern_return_t
exclaves_aoe_enumerate_and_setup_services(uint8_t *num_services)
{
	exclaves_resource_t *conclave = task_get_conclave(current_task());
	assert3p(conclave, !=, NULL);

	/* Return with an error if uninitialised. */
	if (aoeproxy_client.connection == NULL) {
		return KERN_NOT_SUPPORTED;
	}

	lck_mtx_lock(&conclave->r_mutex);

	if (!queue_empty(&conclave->r_conclave.c_aoe_q)) {
		lck_mtx_unlock(&conclave->r_mutex);
		return KERN_FAILURE; /* Already initialised. */
	}
	conclave->r_conclave.c_aoe_using_free_agents = false;

	/*
	 * Iterate over each AOE Service in the conclave and call setup for each
	 * one.
	 */

	__block uint8_t nserv = 0;
	__block bool saw_error = false;
	__block tb_error_t ret = TB_ERROR_SUCCESS;

	/* BEGIN IGNORE CODESTYLE */
	exclaves_resource_aoeservice_iterate(conclave->r_name,
	    ^(exclaves_resource_t *aoe_service) {

		ret = exclavesmessagequeueproxy_exclavesmessagequeueproxy_setup(
		    &aoeproxy_client, aoe_service->r_id,
		    ^(exclavesmessagequeueproxy_exclavesmessagequeueproxy_setup__result_s result) {

			exclavesmessagequeuetypes_workercount_s *wc =
			    exclavesmessagequeueproxy_exclavesmessagequeueproxy_setup__result_get_success(&result);
			if (wc == NULL) {
				exclavesmessagequeueproxy_proxyerror_s *error =
					exclavesmessagequeueproxy_exclavesmessagequeueproxy_setup__result_get_failure(&result);
				assert3p(error, !=, NULL);

				// if AOEproxy doesn't have a service defined in the xnu_proxy_resources table, continue on
				// TODO reconsider this, see rdar://162746126
				if (exclavesmessagequeueproxy_proxyerror_missingservice__get(error)) {
					exclaves_debug_printf(show_errors,
							      "warning: AOE service %llu is missing\n",
							      aoe_service->r_id);
				} else {
					exclaves_debug_printf(show_errors,
							      "AOE setup failed for service: %llu (error: %llu)\n",
							      aoe_service->r_id, error->tag);
					saw_error = true;
				}
			} else {
				/*
				 * Allocate an aoe item for each service to be
				 * used as a per-service rendezvous for message
				 * threads and to hold worker counts for worker
				 * requests.
				 */
				aoe_item_t *aitem = kalloc_type(aoe_item_t,
				    Z_WAITOK | Z_ZERO | Z_NOFAIL);
				aitem->aoei_serviceid = aoe_service->r_id;
				aitem->aoei_message_count = 0;
				aitem->aoei_messenger_count = 0;
				aitem->aoei_work_count = 0;
				aitem->aoei_worker_count = 0;

				queue_enter(&conclave->r_conclave.c_aoe_q, aitem,
				    aoe_item_t *, aoei_chain);

				nserv++;
				if (nserv == 0) {
					// overflow
					saw_error = true;
				}
				return;
			}
		});

		/* Break out early for errors. */
		if (saw_error || ret != TB_ERROR_SUCCESS) {
			return (bool)true;
		}

		return (bool)(false);
	});
	/* END IGNORE CODESTYLE */

	if (saw_error || ret != TB_ERROR_SUCCESS) {
		exclaves_aoe_teardown();
		lck_mtx_unlock(&conclave->r_mutex);
		return KERN_FAILURE;
	}

	lck_mtx_unlock(&conclave->r_mutex);

	*num_services = nserv;

	return KERN_SUCCESS;
}

kern_return_t
exclaves_aoe_get_all_service_infos(exclaves_aoe_service_info_t *sinfos, uint8_t n_services)
{
	exclaves_resource_t *conclave = task_get_conclave(current_task());
	assert3p(conclave, !=, NULL);

	/* Return with an error if uninitialised. */
	if (aoeproxy_client.connection == NULL) {
		return KERN_NOT_SUPPORTED;
	}

	lck_mtx_lock(&conclave->r_mutex);

	if (queue_empty(&conclave->r_conclave.c_aoe_q)) {
		lck_mtx_unlock(&conclave->r_mutex);
		return KERN_FAILURE; /* AOE items have not been populated--setup not called? */
	}

	__block size_t service_index = 0;
	__block bool saw_error = false;
	__block bool overflow = false;
	__block tb_error_t tb_ret = TB_ERROR_SUCCESS;

	aoe_item_t *iter = NULL;
	queue_iterate(&conclave->r_conclave.c_aoe_q, iter, aoe_item_t *, aoei_chain) {
		// if we have already filled n_services sinfos into buffer
		// but we still have more services, userland has undersized
		// the buffer and we need to bail out immediately
		if (service_index == n_services) {
			overflow = true;
			break;
		}

		tb_ret = exclavesmessagequeueproxy_exclavesmessagequeueproxy_serviceinfo(
			&aoeproxy_client, iter->aoei_serviceid,
			^(exclavesmessagequeueproxy_exclavesmessagequeueproxy_serviceinfo__result_s result) {
			exclavesmessagequeuetypes_serviceinfo_s *tb_sinfo =
			exclavesmessagequeueproxy_exclavesmessagequeueproxy_serviceinfo__result_get_success(&result);
			if (tb_sinfo != NULL) {
			        exclaves_aoe_service_info_t *sinfo = &sinfos[service_index];
			        sinfo->id = tb_sinfo->id;
			        sinfo->sc = tb_sinfo->schedulingcategory;
			        const exclavesmessagequeuetypes_workerinfo_count_s *wc =
			        exclavesmessagequeuetypes_workerinfo_count__get(&(tb_sinfo->workerinfo));
			        assert(wc != NULL);
			        sinfo->nworkers = wc->field0;
			        service_index++;
			} else {
			        exclavesmessagequeueproxy_proxyerror_s *error =
			        exclavesmessagequeueproxy_exclavesmessagequeueproxy_serviceinfo__result_get_failure(&result);
			        assert3p(error, !=, NULL);

			        exclaves_debug_printf(show_errors,
			        "AOE getinfo failed for service: %llu (error: %llu)\n",
			        iter->aoei_serviceid, error->tag);
			        saw_error = true;
			}
		});

		/* Break out early for errors. */
		if (saw_error || tb_ret != TB_ERROR_SUCCESS) {
			break;
		}
	};

	kern_return_t return_code = KERN_SUCCESS;
	if (saw_error || tb_ret != TB_ERROR_SUCCESS) {
		return_code = KERN_FAILURE;
	}
	if (service_index == 0 || service_index < n_services || overflow) {
		return_code = KERN_INVALID_ARGUMENT;
	}

	if (return_code != KERN_SUCCESS) {
		// clear out buffer
		memset(sinfos, 0, sizeof(exclaves_aoe_service_info_t) * n_services);
		exclaves_aoe_teardown();
	}
	lck_mtx_unlock(&conclave->r_mutex);

	return return_code;
}

static bool
exclaves_aoe_service_is_idle(const aoe_item_t * const item)
{
	return item->aoei_message_count == 0 && item->aoei_messenger_count == 0 && item->aoei_work_count == 0 && item->aoei_worker_count == 0;
}

static void
exclaves_aoe_service_try_take_assertion(exclaves_resource_t * const conclave, aoe_item_t * const item)
{
	assert3p(conclave, !=, NULL);
	LCK_MTX_ASSERT(&conclave->r_mutex, LCK_MTX_ASSERT_OWNED);

	if (item->aoei_assertion_id == 0 && exclaves_aoe_service_is_idle(item)) {
		const char *desc = exclaves_conclave_get_domain(conclave);
		__assert_only IOReturn ret = IOExclaveLPWCreateAssertion(&item->aoei_assertion_id, desc);
		assert3u(ret, ==, kIOReturnSuccess);
	}
}

static void
exclaves_aoe_service_drop_assertion(exclaves_resource_t * const __assert_only conclave, aoe_item_t * const item)
{
	assert3p(conclave, !=, NULL);
	LCK_MTX_ASSERT(&conclave->r_mutex, LCK_MTX_ASSERT_OWNED);

	__assert_only IOReturn ret = IOExclaveLPWReleaseAssertion(item->aoei_assertion_id);
	assert3u(ret, ==, kIOReturnSuccess);
	item->aoei_assertion_id = 0;
}

static void
exclaves_aoe_service_try_drop_assertion(exclaves_resource_t * const __assert_only conclave, aoe_item_t * const item)
{
	assert3p(conclave, !=, NULL);
	LCK_MTX_ASSERT(&conclave->r_mutex, LCK_MTX_ASSERT_OWNED);

	if (item->aoei_assertion_id && exclaves_aoe_service_is_idle(item)) {
		exclaves_aoe_service_drop_assertion(conclave, item);
	}
}

void
exclaves_aoe_teardown(void)
{
	exclaves_resource_t *conclave = task_get_conclave(current_task());
	assert3p(conclave, !=, NULL);

	LCK_MTX_ASSERT(&conclave->r_mutex, LCK_MTX_ASSERT_OWNED);

	aoe_item_t *aitem = NULL;

	if (!queue_empty(&conclave->r_conclave.c_aoe_q)) {
		/* Request a full wake for relaunch if AOE conclave crashes */
		IOExclavesFullWake("AlwaysOnExclaves.termination");

		while (!queue_empty(&conclave->r_conclave.c_aoe_q)) {
			queue_remove_first(&conclave->r_conclave.c_aoe_q, aitem,
			    aoe_item_t *, aoei_chain);

			exclaves_aoe_service_drop_assertion(conclave, aitem);

			tb_error_t teardown_ret = exclavesmessagequeueproxy_exclavesmessagequeueproxy_teardown(
				&aoeproxy_client, aitem->aoei_serviceid);
			if (teardown_ret != TB_ERROR_SUCCESS) {
				exclaves_debug_printf(show_errors,
				    "exclaves: AOE teardown call for service id %lld failed with TB return code %d\n",
				    aitem->aoei_serviceid, teardown_ret);
				assert(teardown_ret == TB_ERROR_SUCCESS);
			}

			kfree_type(aoe_item_t, aitem);
		}
	}
}

static wait_result_t
exclaves_aoe_claim_work(exclaves_resource_t *conclave, uint64_t *id)
{
	uint64_t requested_id = *id;
	bool ignore_requested_id = requested_id == EXCLAVESMESSAGEQUEUETYPES_SERVICEIDENTIFIER_INVALID;
	if (ignore_requested_id) {
		assert(conclave->r_conclave.c_aoe_using_free_agents);
	}

	while (true) {
		// The thread could have been aborted after the performing work, do not proceed to
		// claiming more work
		if (current_thread()->sched_flags & (TH_SFLAG_ABORT | TH_SFLAG_ABORTSAFELY)) {
			return THREAD_INTERRUPTED;
		}

		lck_mtx_lock(&conclave->r_mutex);

		aoe_item_t *aitem = NULL;
		queue_iterate(&conclave->r_conclave.c_aoe_q, aitem, aoe_item_t *, aoei_chain) {
			if (aitem->aoei_work_count != 0 && (ignore_requested_id ||
			    aitem->aoei_serviceid == requested_id)) {
				aitem->aoei_work_count--;
				aitem->aoei_worker_count++;
				*id = aitem->aoei_serviceid;

				lck_mtx_unlock(&conclave->r_mutex);
				return THREAD_AWAKENED;
			}

			// non-free agent worker threads should wait on their service's work count
			if (aitem->aoei_serviceid == requested_id && !ignore_requested_id) {
				break;
			}
		}

		/* Nothing on the work queue, sleep */
		assert_wait(conclave->r_conclave.c_aoe_using_free_agents
		    ? (void *) &conclave->r_conclave.c_aoe_q
		    : (void *) &aitem->aoei_work_count,
		    THREAD_INTERRUPTIBLE);

		lck_mtx_unlock(&conclave->r_mutex);

		wait_result_t wr = thread_block(THREAD_CONTINUE_NULL);
		assert(wr == THREAD_AWAKENED || wr == THREAD_INTERRUPTED);

		if (wr == THREAD_INTERRUPTED) {
			return wr;
		}
	}
}

static void
exclaves_aoe_finish_work(exclaves_resource_t *conclave, uint64_t service_id)
{
	bool work_finished = false;

	lck_mtx_lock(&conclave->r_mutex);

	aoe_item_t *aitem = NULL;
	queue_iterate(&conclave->r_conclave.c_aoe_q, aitem,
	    aoe_item_t *, aoei_chain) {
		if (service_id == aitem->aoei_serviceid) {
			aitem->aoei_worker_count--;

			exclaves_aoe_service_try_drop_assertion(conclave, aitem);

			work_finished = true;
		}
	}

	lck_mtx_unlock(&conclave->r_mutex);

	assert(work_finished);
}

static void
exclaves_aoe_post_work(exclaves_resource_t *conclave, uint64_t service_id, uint8_t worker_count)
{
	lck_mtx_lock(&conclave->r_mutex);

	/* Find the associated aoe item. */
	aoe_item_t *aitem = NULL;
	queue_iterate(&conclave->r_conclave.c_aoe_q, aitem, aoe_item_t *,
	    aoei_chain) {
		if (aitem->aoei_serviceid == service_id) {
			aitem->aoei_messenger_count--;
			aitem->aoei_work_count += worker_count;
			if (worker_count != 0) {
				// free agent worker threads wait on the queue as a whole,
				// instead of on the specific aitem for the service they are bound to
				thread_wakeup(conclave->r_conclave.c_aoe_using_free_agents
				    ? (void *) &conclave->r_conclave.c_aoe_q
				    : (void *) &aitem->aoei_work_count);
			} else {
				// If there are no workers, check if the active assertion can be dropped.
				exclaves_aoe_service_try_drop_assertion(conclave, aitem);
			}
			break;
		}
	}

	lck_mtx_unlock(&conclave->r_mutex);
}

kern_return_t
exclaves_aoe_work_loop_with_service_id(uint64_t id)
{
	thread_t cur_thread = current_thread();

	exclaves_resource_t *conclave = task_get_conclave(current_task());
	assert3p(conclave, !=, NULL);
	if (id == EXCLAVESMESSAGEQUEUETYPES_SERVICEIDENTIFIER_INVALID) {
		assert(conclave->r_conclave.c_aoe_using_free_agents);
	} else {
		assert(!conclave->r_conclave.c_aoe_using_free_agents);
	}

	/* Return with an error if uninitialised. */
	if (aoeproxy_client.connection == NULL) {
		return KERN_NOT_SUPPORTED;
	}

	/*
	 * Mark this thread as being an Exclaves AOE thread. After this point
	 * cannot return to userspace.
	 */
	cur_thread->th_exclaves_state |= TH_EXCLAVES_AOE;

	// Wait to be interrupted or aborted..
	while (exclaves_aoe_claim_work(conclave, &id) != THREAD_INTERRUPTED) {
		// Call into AOE proxy to process.
		// make sure claim_work gave us a real service
		assert3u(id, !=, EXCLAVESMESSAGEQUEUETYPES_SERVICEIDENTIFIER_INVALID);

		/* BEGIN IGNORE CODESTYLE */
		__assert_only tb_error_t ret =
			exclavesmessagequeueproxy_exclavesmessagequeueproxy_workerinvoke(
				&aoeproxy_client, id);
		/* END IGNORE CODESTYLE */

		assert3u(ret, ==, TB_ERROR_SUCCESS);

		// Complete conclave stop upcall if worker invoke caused conclave stop
		task_stop_conclave_upcall_complete();
		exclaves_aoe_finish_work(conclave, id);

		// if free agent, clean up id field
		if (conclave->r_conclave.c_aoe_using_free_agents) {
			id = EXCLAVESMESSAGEQUEUETYPES_SERVICEIDENTIFIER_INVALID;
		}
	}

	/* unset AOE flag after exiting work loop */
	cur_thread->th_exclaves_state &= (~TH_EXCLAVES_AOE);

	/*
	 * This thread was aborted, assert that the thread has actually aborted
	 * and won't try to return to userspace.
	 */
	assert3u(cur_thread->sched_flags & TH_SFLAG_ABORT, !=, 0);

	return KERN_SUCCESS;
}

/*
 * Worker thread run-loop.
 */
kern_return_t
exclaves_aoe_work_loop(void)
{
	return exclaves_aoe_work_loop_with_service_id(
		EXCLAVESMESSAGEQUEUETYPES_SERVICEIDENTIFIER_INVALID);
}

static wait_result_t
exclaves_aoe_claim_message(exclaves_resource_t *conclave, aoe_item_t *item)
{
	while (true) {
		// The thread could have been aborted after the delivering message, do not proceed to
		// claiming more messages
		if (current_thread()->sched_flags & (TH_SFLAG_ABORT | TH_SFLAG_ABORTSAFELY)) {
			return THREAD_INTERRUPTED;
		}

		lck_mtx_lock(&conclave->r_mutex);

		/* Claim message and return immediately if available. */
		if (item->aoei_message_count > 0) {
			item->aoei_message_count--;
			item->aoei_messenger_count++;
			lck_mtx_unlock(&conclave->r_mutex);
			return THREAD_AWAKENED;
		}

		/* Nothing on the message queue, sleep. */
		assert_wait(&item->aoei_message_count,
		    THREAD_INTERRUPTIBLE);

		lck_mtx_unlock(&conclave->r_mutex);

		wait_result_t wr = thread_block(THREAD_CONTINUE_NULL);
		assert(wr == THREAD_AWAKENED || wr == THREAD_INTERRUPTED);

		if (wr == THREAD_INTERRUPTED) {
			return wr;
		}
	}
}

static void
exclaves_aoe_post_message(exclaves_resource_t *conclave,
    __unused exclavesmessagequeuetypes_serviceidentifier_s id)
{
	lck_mtx_lock(&conclave->r_mutex);

	aoe_item_t *aitem = NULL;
	queue_iterate(&conclave->r_conclave.c_aoe_q, aitem, aoe_item_t *,
	    aoei_chain) {
		if (aitem->aoei_serviceid == id) {
			exclaves_aoe_service_try_take_assertion(conclave, aitem);

			aitem->aoei_message_count++;
			thread_wakeup(&aitem->aoei_message_count);
			break;
		}
	}

	lck_mtx_unlock(&conclave->r_mutex);
}

static aoe_item_t *
exclaves_aoe_associate_serviceid(void)
{
	exclaves_resource_t *conclave = task_get_conclave(current_task());
	assert3p(conclave, !=, NULL);

	lck_mtx_lock(&conclave->r_mutex);

	aoe_item_t *aitem = NULL;
	queue_iterate(&conclave->r_conclave.c_aoe_q, aitem, aoe_item_t *,
	    aoei_chain) {
		if (!aitem->aoei_associated) {
			aitem->aoei_associated = true;
			lck_mtx_unlock(&conclave->r_mutex);

			return aitem;
		}
	}

	lck_mtx_unlock(&conclave->r_mutex);

	return NULL;
}


static kern_return_t
exclaves_aoe_message_loop_internal(aoe_item_t *item)
{
	thread_t cur_thread = current_thread();
	exclaves_resource_t *conclave = task_get_conclave(current_task());

	/*
	 * Mark this thread as being an Exclaves AOE thread. After this point
	 * cannot return to userspace.
	 */
	cur_thread->th_exclaves_state |= TH_EXCLAVES_AOE;

	// Wait to be interrupted or aborted..
	while (exclaves_aoe_claim_message(conclave, item) !=
	    THREAD_INTERRUPTED) {
		// Call into AOE proxy to handle message.

		/* BEGIN IGNORE CODESTYLE */
		__assert_only tb_error_t ret = exclavesmessagequeueproxy_exclavesmessagequeueproxy_messagedeliver(
		    &aoeproxy_client, item->aoei_serviceid,
		    ^(workercount__opt_s wc_opt) {

			exclavesmessagequeuetypes_workercount_s *wc = NULL;
			wc = workercount__opt_get(&wc_opt);

			// Complete conclave stop upcall if message deliver caused conclave stop
			task_stop_conclave_upcall_complete();

			// Post work for the worker threads.
			exclaves_aoe_post_work(conclave, item->aoei_serviceid, wc ? *wc : 0);
		});
		/* END IGNORE CODESTYLE */

		assert3u(ret, ==, TB_ERROR_SUCCESS);
	}

	/* unset AOE flag after exiting message loop */
	cur_thread->th_exclaves_state &= (~TH_EXCLAVES_AOE);

	/*
	 * This thread was aborted, assert that the thread has actually aborted
	 * and won't try to return to userspace.
	 */
	assert3u(cur_thread->sched_flags & TH_SFLAG_ABORT, !=, 0);

	return KERN_SUCCESS;
}

/* Message thread run-loop. */
kern_return_t
exclaves_aoe_message_loop(void)
{
	/* Return with an error if uninitialised. */
	if (aoeproxy_client.connection == NULL) {
		return KERN_NOT_SUPPORTED;
	}

	/* Claim a message endpoint. */
	aoe_item_t *item = exclaves_aoe_associate_serviceid();
	if (item == NULL) {
		return KERN_NOT_FOUND;
	}

	return exclaves_aoe_message_loop_internal(item);
}

kern_return_t
exclaves_aoe_message_loop_with_service_id(uint64_t service_id)
{
	exclaves_resource_t *conclave = task_get_conclave(current_task());
	assert3p(conclave, !=, NULL);

	/* Return with an error if uninitialised. */
	if (aoeproxy_client.connection == NULL) {
		return KERN_NOT_SUPPORTED;
	}

	// iterate through queue to find matching aoe item for service
	lck_mtx_lock(&conclave->r_mutex);
	aoe_item_t *iter = NULL;
	aoe_item_t *matching_item = NULL;
	queue_iterate(&conclave->r_conclave.c_aoe_q, iter, aoe_item_t *, aoei_chain) {
		if (iter->aoei_serviceid == service_id) {
			matching_item = iter;
			break;
		}
	}
	lck_mtx_unlock(&conclave->r_mutex);
	if (matching_item == NULL) {
		return KERN_NOT_FOUND;
	}

	return exclaves_aoe_message_loop_internal(matching_item);
}

tb_error_t
exclaves_aoe_upcall_work_available(const xnuupcallsv2_aoeworkinfo_s *work_info,
    tb_error_t (^completion)(void))
{
	assert3p(work_info, !=, NULL);

	const xnuupcallsv2_aoeworkinfo_conclavework_s *cw =
	    xnuupcallsv2_aoeworkinfo_conclavework__get(work_info);

	// Only conclave work is supported right now.
	if (cw == NULL) {
		exclaves_debug_printf(show_errors, "conclave work is null");
		completion();
		return TB_ERROR_USER_FAILURE;
	}

	exclavesmessagequeuetypes_serviceidentifier_s id = cw->field0;
	if (id == EXCLAVESMESSAGEQUEUETYPES_SERVICEIDENTIFIER_INVALID) {
		exclaves_debug_printf(show_errors, "invalid service identifier");
		completion();
		return TB_ERROR_USER_FAILURE;
	}

	exclaves_resource_t *conclave =
	    exclaves_conclave_lookup_by_aoeserviceid(id);
	if (conclave == NULL ||
	    queue_empty(&conclave->r_conclave.c_aoe_q)) {
		exclaves_debug_printf(show_errors,
		    "exclaves: work available but conclave not found or "
		    "uninitialised: %llu\n", id);
		completion();
		return TB_ERROR_USER_FAILURE;
	}

	exclaves_aoe_post_message(conclave, id);

	return completion();
}

#endif /* CONFIG_EXCLAVES */
