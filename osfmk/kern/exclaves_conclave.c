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

#include <mach/kern_return.h>
#include <kern/assert.h>
#include <stdint.h>
#include <kern/startup.h>
#include <kern/locks.h>
#include <kern/kalloc.h>
#include <kern/task.h>

#include <Tightbeam/tightbeam.h>

#include "kern/exclaves.tightbeam.h"

#include "exclaves_debug.h"
#include "exclaves_conclave.h"
#include "exclaves_resource.h"
#include "exclaves_internal.h"

/* -------------------------------------------------------------------------- */
#pragma mark Conclave Launcher

kern_return_t
exclaves_conclave_launcher_init(uint64_t id, tb_client_connection_t *connection)
{
	assert3p(connection, !=, NULL);

	tb_error_t tb_result = TB_ERROR_SUCCESS;

	conclave_launcher_conclavecontrol_s control = {};

	tb_endpoint_t conclave_control_endpoint =
	    tb_endpoint_create_with_value(TB_TRANSPORT_TYPE_XNU, id,
	    TB_ENDPOINT_OPTIONS_NONE);

	tb_result = conclave_launcher_conclavecontrol__init(&control,
	    conclave_control_endpoint);
	if (tb_result != TB_ERROR_SUCCESS) {
		exclaves_debug_printf(show_errors,
		    "conclave init failure: %llu\n", id);
		return KERN_FAILURE;
	}

	*connection = control.connection;

	return KERN_SUCCESS;
}

kern_return_t
exclaves_conclave_launcher_launch(const tb_client_connection_t connection)
{
	assert3p(connection, !=, NULL);

	tb_error_t tb_result = TB_ERROR_SUCCESS;

	const conclave_launcher_conclavecontrol_s control = {
		.connection = connection,
	};

	__block bool success = false;

	/* BEGIN IGNORE CODESTYLE */
	tb_result = conclave_launcher_conclavecontrol_launch(&control,
	    ^(conclave_launcher_conclavecontrol_launch__result_s result) {
		conclave_launcher_conclavestatus_s *status = NULL;
		status = conclave_launcher_conclavecontrol_launch__result_get_success(&result);
		if (status != NULL) {
		        success = true;
		        return;
		}

		conclave_launcher_conclavelauncherfailure_s *failure = NULL;
		failure = conclave_launcher_conclavecontrol_launch__result_get_failure(&result);
		assert3p(failure, !=, NULL);
		exclaves_debug_printf(show_errors,
		    "conclave launch failure: failure %u\n", *failure);
	});
	/* END IGNORE CODESTYLE */

	if (tb_result != TB_ERROR_SUCCESS || !success) {
		return KERN_FAILURE;
	}

	return KERN_SUCCESS;
}

kern_return_t
exclaves_conclave_launcher_stop(const tb_client_connection_t connection,
    uint32_t stop_reason)
{
	assert3p(connection, !=, NULL);

	tb_error_t tb_result = TB_ERROR_SUCCESS;

	const conclave_launcher_conclavecontrol_s control = {
		.connection = connection,
	};

	__block bool success = false;

	/* BEGIN IGNORE CODESTYLE */
	tb_result = conclave_launcher_conclavecontrol_stop(
	    &control, stop_reason, true,
	    ^(conclave_launcher_conclavecontrol_stop__result_s result) {
		conclave_launcher_conclavestatus_s *status = NULL;
		status = conclave_launcher_conclavecontrol_stop__result_get_success(&result);
		if (status != NULL) {
		        success = true;
		        return;
		}

		conclave_launcher_conclavelauncherfailure_s *failure = NULL;
		failure = conclave_launcher_conclavecontrol_stop__result_get_failure(&result);
		assert3p(failure, !=, NULL);

		exclaves_debug_printf(show_errors,
		    "conclave stop failure: failure %u\n", *failure);
	});
	/* END IGNORE CODESTYLE */

	if (tb_result != TB_ERROR_SUCCESS || !success) {
		return KERN_FAILURE;
	}

	return KERN_SUCCESS;
}

kern_return_t
exclaves_conclave_launcher_suspend(const tb_client_connection_t connection,
    bool suspend)
{
	assert3p(connection, !=, NULL);

	tb_error_t tb_result = TB_ERROR_SUCCESS;

	const conclave_launcher_conclavecontrol_s control = {
		.connection = connection,
	};

	__block bool success = false;

	/* BEGIN IGNORE CODESTYLE */
	tb_result = conclave_launcher_conclavecontrol_suspend(
	    &control, suspend,
	    ^(conclave_launcher_conclavecontrol_suspend__result_s result) {
		conclave_launcher_conclavestatus_s *status = NULL;
		status = conclave_launcher_conclavecontrol_suspend__result_get_success(&result);
		if (status != NULL) {
		        success = true;
		        return;
		}

		conclave_launcher_conclavelauncherfailure_s *failure = NULL;
		failure = conclave_launcher_conclavecontrol_suspend__result_get_failure(&result);
		assert3p(failure, !=, NULL);

		exclaves_debug_printf(show_errors,
		    "conclave suspend failure: failure %u\n", *failure);
	});
	/* END IGNORE CODESTYLE */

	if (tb_result != TB_ERROR_SUCCESS || !success) {
		return KERN_FAILURE;
	}

	return KERN_SUCCESS;
}

/* -------------------------------------------------------------------------- */
#pragma mark Conclave Upcalls

/* Legacy upcall handlers */

tb_error_t
exclaves_conclave_upcall_legacy_suspend(const uint32_t flags,
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_conclave_suspend__result_s))
{
	xnuupcalls_conclavescidlist_s scid_list = {};

	exclaves_debug_printf(show_lifecycle_upcalls,
	    "[lifecycle_upcalls] conclave_suspend flags %x\n", flags);

	kern_return_t kret = task_suspend_conclave_upcall(scid_list.scid,
	    ARRAY_COUNT(scid_list.scid));

	exclaves_debug_printf(show_lifecycle_upcalls,
	    "[lifecycle_upcalls] task_suspend_conclave_upcall returned %x\n", kret);

	xnuupcalls_xnuupcalls_conclave_suspend__result_s result = {};

	switch (kret) {
	case KERN_SUCCESS:
		xnuupcalls_xnuupcalls_conclave_suspend__result_init_success(&result, scid_list);
		break;

	case KERN_INVALID_TASK:
	case KERN_INVALID_ARGUMENT:
		xnuupcalls_xnuupcalls_conclave_suspend__result_init_failure(&result,
		    XNUUPCALLS_LIFECYCLEERROR_INVALIDTASK);
		break;

	default:
		xnuupcalls_xnuupcalls_conclave_suspend__result_init_failure(&result,
		    XNUUPCALLS_LIFECYCLEERROR_FAILURE);
		break;
	}

	return completion(result);
}

tb_error_t
exclaves_conclave_upcall_legacy_stop(const uint32_t flags,
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_conclave_stop__result_s))
{
	exclaves_debug_printf(show_lifecycle_upcalls,
	    "[lifecycle_upcalls] conclave_stop flags %x\n", flags);

	kern_return_t kret = task_stop_conclave_upcall();

	exclaves_debug_printf(show_lifecycle_upcalls,
	    "[lifecycle_upcalls] task_stop_conclave_upcall returned %x\n", kret);

	xnuupcalls_xnuupcalls_conclave_stop__result_s result = {};

	switch (kret) {
	case KERN_SUCCESS:
		xnuupcalls_xnuupcalls_conclave_stop__result_init_success(&result);
		break;

	case KERN_INVALID_TASK:
	case KERN_INVALID_ARGUMENT:
		xnuupcalls_xnuupcalls_conclave_stop__result_init_failure(&result,
		    XNUUPCALLS_LIFECYCLEERROR_INVALIDTASK);
		break;

	default:
		xnuupcalls_xnuupcalls_conclave_stop__result_init_failure(&result,
		    XNUUPCALLS_LIFECYCLEERROR_FAILURE);
		break;
	}

	return completion(result);
}

tb_error_t
exclaves_conclave_upcall_legacy_crash_info(const xnuupcalls_conclavesharedbuffer_s *shared_buf,
    const uint32_t length,
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_conclave_crash_info__result_s ))
{
	task_t task;

	/* Check if the thread was calling conclave stop on another task */
	task = current_thread()->conclave_stop_task;
	if (task == TASK_NULL) {
		task = current_task();
	}

	exclaves_debug_printf(show_lifecycle_upcalls,
	    "[lifecycle_upcalls] conclave_crash_info\n");

	const conclave_sharedbuffer_t *buf = (const conclave_sharedbuffer_t *) shared_buf;
	kern_return_t kret = task_crash_info_conclave_upcall(task, buf, length);

	exclaves_debug_printf(show_lifecycle_upcalls,
	    "[lifecycle_upcalls] task_crash_info_conclave_upcall returned 0x%x\n", kret);

	xnuupcalls_xnuupcalls_conclave_crash_info__result_s result = {};

	switch (kret) {
	case KERN_SUCCESS:
		xnuupcalls_xnuupcalls_conclave_crash_info__result_init_success(&result);
		break;

	case KERN_INVALID_TASK:
	case KERN_INVALID_ARGUMENT:
		xnuupcalls_xnuupcalls_conclave_crash_info__result_init_failure(&result,
		    XNUUPCALLS_LIFECYCLEERROR_INVALIDTASK);
		break;

	default:
		xnuupcalls_xnuupcalls_conclave_crash_info__result_init_failure(&result,
		    XNUUPCALLS_LIFECYCLEERROR_FAILURE);
		break;
	}

	return completion(result);
}

/* V2 upcall handlers */

tb_error_t
exclaves_conclave_upcall_suspend(const uint32_t flags,
    tb_error_t (^completion)(xnuupcallsv2_conclaveupcallsprivate_suspend__result_s))
{
	xnuupcallsv2_conclavescidlist_s scid_list = {};

	exclaves_debug_printf(show_lifecycle_upcalls,
	    "[lifecycle_upcalls] conclave_suspend flags %x\n", flags);

	kern_return_t kret = task_suspend_conclave_upcall(scid_list.scid,
	    ARRAY_COUNT(scid_list.scid));

	exclaves_debug_printf(show_lifecycle_upcalls,
	    "[lifecycle_upcalls] task_suspend_conclave_upcall returned %x\n", kret);

	xnuupcallsv2_conclaveupcallsprivate_suspend__result_s result = {};

	switch (kret) {
	case KERN_SUCCESS:
		xnuupcallsv2_conclaveupcallsprivate_suspend__result_init_success(
			&result, scid_list);
		break;

	case KERN_INVALID_TASK:
	case KERN_INVALID_ARGUMENT:
		xnuupcallsv2_conclaveupcallsprivate_suspend__result_init_failure(
			&result, XNUUPCALLSV2_LIFECYCLEERROR_INVALIDTASK);
		break;

	default:
		xnuupcallsv2_conclaveupcallsprivate_suspend__result_init_failure(
			&result, XNUUPCALLSV2_LIFECYCLEERROR_FAILURE);
		break;
	}

	return completion(result);
}

tb_error_t
exclaves_conclave_upcall_stop(const uint32_t flags,
    tb_error_t (^completion)(xnuupcallsv2_conclaveupcallsprivate_stop__result_s))
{
	exclaves_debug_printf(show_lifecycle_upcalls,
	    "[lifecycle_upcalls] conclave_stop flags %x\n", flags);

	kern_return_t kret = task_stop_conclave_upcall();

	exclaves_debug_printf(show_lifecycle_upcalls,
	    "[lifecycle_upcalls] task_stop_conclave_upcall returned %x\n", kret);

	xnuupcallsv2_conclaveupcallsprivate_stop__result_s result = {};

	switch (kret) {
	case KERN_SUCCESS:
		xnuupcallsv2_conclaveupcallsprivate_stop__result_init_success(
			&result);
		break;

	case KERN_INVALID_TASK:
	case KERN_INVALID_ARGUMENT:
		xnuupcallsv2_conclaveupcallsprivate_stop__result_init_failure(
			&result, XNUUPCALLSV2_LIFECYCLEERROR_INVALIDTASK);
		break;

	default:
		xnuupcallsv2_conclaveupcallsprivate_stop__result_init_failure(
			&result, XNUUPCALLSV2_LIFECYCLEERROR_FAILURE);
		break;
	}

	return completion(result);
}

tb_error_t
exclaves_conclave_upcall_crash_info(const xnuupcallsv2_conclavesharedbuffer_s *shared_buf,
    const uint32_t length,
    tb_error_t (^completion)(xnuupcallsv2_conclaveupcallsprivate_crashinfo__result_s ))
{
	task_t task;

	/* Check if the thread was calling conclave stop on another task */
	task = current_thread()->conclave_stop_task;
	if (task == TASK_NULL) {
		task = current_task();
	}

	exclaves_debug_printf(show_lifecycle_upcalls,
	    "[lifecycle_upcalls] conclave_crash_info\n");

	const conclave_sharedbuffer_t *buf = (const conclave_sharedbuffer_t *) shared_buf;
	kern_return_t kret = task_crash_info_conclave_upcall(task, buf, length);

	exclaves_debug_printf(show_lifecycle_upcalls,
	    "[lifecycle_upcalls] task_crash_info_conclave_upcall returned 0x%x\n", kret);

	xnuupcallsv2_conclaveupcallsprivate_crashinfo__result_s result = {};

	switch (kret) {
	case KERN_SUCCESS:
		xnuupcallsv2_conclaveupcallsprivate_crashinfo__result_init_success(
			&result);
		break;

	case KERN_INVALID_TASK:
	case KERN_INVALID_ARGUMENT:
		xnuupcallsv2_conclaveupcallsprivate_crashinfo__result_init_failure(
			&result, XNUUPCALLSV2_LIFECYCLEERROR_INVALIDTASK);
		break;

	default:
		xnuupcallsv2_conclaveupcallsprivate_crashinfo__result_init_failure(
			&result, XNUUPCALLSV2_LIFECYCLEERROR_FAILURE);
		break;
	}

	return completion(result);
}

#endif /* CONFIG_EXCLAVES */
