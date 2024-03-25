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


/* -------------------------------------------------------------------------- */
#pragma mark Conclave Upcalls

tb_error_t
exclaves_conclave_upcall_suspend(const uint32_t flags,
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
exclaves_conclave_upcall_stop(const uint32_t flags,
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
exclaves_conclave_upcall_crash_info(const xnuupcalls_conclavesharedbuffer_s *shared_buf,
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

	kern_return_t kret = task_crash_info_conclave_upcall(task, shared_buf, length);

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

#if DEVELOPMENT || DEBUG

/* -------------------------------------------------------------------------- */
#pragma mark Testing

typedef struct conclave_test_context {
	tb_endpoint_t conclave_control_endpoint;
	conclave_launcher_conclavecontrol_s conclave_control;
	tb_endpoint_t conclave_debug_endpoint;
	conclave_launcher_conclavedebug_s conclave_debug;
} conclave_test_context_t;

extern lck_grp_t exclaves_lck_grp;

LCK_MTX_DECLARE(exclaves_conclave_lock, &exclaves_lck_grp);

static conclave_test_context_t *conclave_context = NULL;

#define EXCLAVES_ID_CONCLAVECONTROL_EP \
    (exclaves_endpoint_lookup("com.apple.service.ConclaveLauncherControl"))

#define EXCLAVES_ID_CONCLAVEDEBUG_EP \
    (exclaves_endpoint_lookup("com.apple.service.ConclaveLauncherDebug"))

static TUNABLE(bool, enable_hello_conclaves, "enable_hello_conclaves", false);

static int
exclaves_hello_conclaves_test(int64_t in, int64_t *out)
{
	tb_error_t tb_result = TB_ERROR_SUCCESS;
	if (!enable_hello_conclaves) {
		exclaves_debug_printf(show_errors,
		    "%s: SKIPPED: enable_hello_conclaves not set\n", __func__);
		*out = -1;
		return 0;
	}

	if (exclaves_get_status() != EXCLAVES_STATUS_AVAILABLE) {
		exclaves_debug_printf(show_errors,
		    "%s: SKIPPED: Exclaves not available\n", __func__);
		*out = -1;
		return 0;
	}
	lck_mtx_lock(&exclaves_conclave_lock);
	switch (in) {
	case 0: {         /* init */
		if (conclave_context != NULL) {
			break;
		}

		conclave_context = kalloc_type(conclave_test_context_t, Z_WAITOK);
		assert(conclave_context != NULL);

		/* BEGIN IGNORE CODESTYLE */
		conclave_context->conclave_control_endpoint =
		    tb_endpoint_create_with_value(TB_TRANSPORT_TYPE_XNU,
		    EXCLAVES_ID_CONCLAVECONTROL_EP, TB_ENDPOINT_OPTIONS_NONE);
		tb_result = conclave_launcher_conclavecontrol__init(
		    &conclave_context->conclave_control,
		    conclave_context->conclave_control_endpoint);
		assert(tb_result == TB_ERROR_SUCCESS);

		conclave_context->conclave_debug_endpoint =
		    tb_endpoint_create_with_value(TB_TRANSPORT_TYPE_XNU,
		    EXCLAVES_ID_CONCLAVEDEBUG_EP, TB_ENDPOINT_OPTIONS_NONE);
		tb_result = conclave_launcher_conclavedebug__init(
		    &conclave_context->conclave_debug,
		    conclave_context->conclave_debug_endpoint);
		assert(tb_result == TB_ERROR_SUCCESS);
		/* END IGNORE CODESTYLE */

		break;
	}
	case 1: {         /* launch conclave */
		assert(conclave_context != NULL);

		/* BEGIN IGNORE CODESTYLE */
		tb_result = conclave_launcher_conclavecontrol_launch(
		    &conclave_context->conclave_control,
		    ^(conclave_launcher_conclavecontrol_launch__result_s result) {
			conclave_launcher_conclavestatus_s *status = NULL;
			status = conclave_launcher_conclavecontrol_launch__result_get_success(&result);
			if (status != NULL) {
			        exclaves_debug_printf(show_test_output,
			            "%s:%d conclave launch success: status %u\n",
			            __func__, __LINE__, *status);
			        return;
			}

			conclave_launcher_conclavelauncherfailure_s *failure = NULL;
			failure = conclave_launcher_conclavecontrol_launch__result_get_failure(&result);
			assert3p(failure, !=, NULL);
			exclaves_debug_printf(show_errors,
			    "%s:%d conclave launch failure: failure %u\n",
			    __func__, __LINE__, *failure);
		});
		/* END IGNORE CODESTYLE */

		if (tb_result != TB_ERROR_SUCCESS) {
			exclaves_debug_printf(show_errors,
			    "%s:%d conclave launch failure: tightbeam error %u\n",
			    __func__, __LINE__, tb_result);
		}
		break;
	}
	case 2: {         /* status */
		assert(conclave_context != NULL);

		/* BEGIN IGNORE CODESTYLE */
		tb_result = conclave_launcher_conclavecontrol_status(
		    &conclave_context->conclave_control,
		    ^(conclave_launcher_conclavecontrol_status__result_s result) {
			conclave_launcher_conclavestatus_s *status = NULL;
			status = conclave_launcher_conclavecontrol_status__result_get_success(&result);
			if (status != NULL) {
			        exclaves_debug_printf(show_test_output,
			            "%s:%d conclave status success: status %u\n",
			            __func__, __LINE__, *status);
			        return;
			}

			conclave_launcher_conclavelauncherfailure_s *failure = NULL;
			failure = conclave_launcher_conclavecontrol_status__result_get_failure(&result);
			assert3p(failure, !=, NULL);
			exclaves_debug_printf(show_errors,
			    "%s:%d conclave status failure: failure %u\n",
			    __func__, __LINE__, *failure);
		});
		/* END IGNORE CODESTYLE */

		if (tb_result != TB_ERROR_SUCCESS) {
			exclaves_debug_printf(show_errors,
			    "%s:%d conclave status failure: tightbeam error %u\n",
			    __func__, __LINE__, tb_result);
		}
		break;
	}
	case 3: {         /* stop conclave */
		conclave_launcher_conclavestopreason_s stop_reason =
		    CONCLAVE_LAUNCHER_CONCLAVESTOPREASON_EXIT;
		assert(conclave_context != NULL);

		/* BEGIN IGNORE CODESTYLE */
		tb_result = conclave_launcher_conclavecontrol_stop(
		    &conclave_context->conclave_control, stop_reason, true,
		    ^(conclave_launcher_conclavecontrol_stop__result_s result) {
			conclave_launcher_conclavestatus_s *status = NULL;
			status = conclave_launcher_conclavecontrol_stop__result_get_success(&result);
			if (status != NULL) {
				exclaves_debug_printf(show_test_output,
				    "%s:%d conclave stop success: status %u\n",
				    __func__, __LINE__, *status);
			        return;
			}

			conclave_launcher_conclavelauncherfailure_s *failure = NULL;
			failure = conclave_launcher_conclavecontrol_stop__result_get_failure(&result);
			assert3p(failure, !=, NULL);
			exclaves_debug_printf(show_errors,
			    "%s:%d conclave stop failure: failure %u\n",
			    __func__, __LINE__, *failure);
		});
		/* END IGNORE CODESTYLE */

		if (tb_result != TB_ERROR_SUCCESS) {
			exclaves_debug_printf(show_errors,
			    "%s:%d conclave stop failure: tightbeam error %u\n",
			    __func__, __LINE__, tb_result);
		}
		break;
	}
	case 4: {         /* debug info */
		assert(conclave_context != NULL);

		/* BEGIN IGNORE CODESTYLE */
		tb_result = conclave_launcher_conclavedebug_debuginfo(
		    &conclave_context->conclave_debug,
		    ^(conclave_launcher_conclavedebug_debuginfo__result_s result) {
			conclave_launcher_conclavedebuginfo_s *debuginfo = NULL;
			debuginfo = conclave_launcher_conclavedebug_debuginfo__result_get_success(&result);
			if (debuginfo != NULL) {
				uuid_string_t uuid_string;
				uuid_unparse(debuginfo->conclaveuuid, uuid_string);
				exclaves_debug_printf(show_test_output,
				    "%s:%d conclave debuginfo success: result %s\n",
				    __func__, __LINE__, uuid_string);
			        return;
			}

			conclave_launcher_conclavelauncherfailure_s *failure = NULL;
			failure = conclave_launcher_conclavedebug_debuginfo__result_get_failure(&result);
			assert3p(failure, !=, NULL);
			exclaves_debug_printf(show_errors,
			    "%s:%d conclave debuginfo failure: failure %u\n",
			    __func__, __LINE__, *failure);
		});
		/* END IGNORE CODESTYLE */

		if (tb_result != TB_ERROR_SUCCESS) {
			exclaves_debug_printf(show_errors,
			    "%s:%d conclave debug info failure: tightbeam error %u\n",
			    __func__, __LINE__, tb_result);
		}
		break;
	}
	}
	lck_mtx_unlock(&exclaves_conclave_lock);
	*out = tb_result == TB_ERROR_SUCCESS ? 1 : 0;
	return tb_result == TB_ERROR_SUCCESS ? KERN_SUCCESS : KERN_FAILURE;
}

SYSCTL_TEST_REGISTER(exclaves_hello_conclaves_test,
    exclaves_hello_conclaves_test);

#endif /* DEVELOPMENT || DEBUG */

#endif /* CONFIG_EXCLAVES */
