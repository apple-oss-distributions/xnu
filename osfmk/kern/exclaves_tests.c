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

#if DEVELOPMENT || DEBUG

#include <kern/kalloc.h>
#include <kern/locks.h>

#include "exclaves_debug.h"
#include "exclaves_resource.h"

/* External & generated headers */
#include <xrt_hosted_types/types.h>
#include <xnuproxy/messages.h>

#include "exclaves_resource.h"
#include "exclaves_xnuproxy.h"

#if __has_include(<Tightbeam/tightbeam.h>)

#include <Tightbeam/tightbeam.h>
#include <Tightbeam/tightbeam_private.h>
#include "kern/exclaves.tightbeam.h"

#define EXCLAVES_ID_HELLO_EXCLAVE_EP                 \
    (exclaves_service_lookup(EXCLAVES_DOMAIN_KERNEL, \
    "com.apple.service.ExclavesCHelloServer"))

static int
exclaves_hello_exclave_test(__unused int64_t in, int64_t *out)
{
	tb_error_t tb_result;
	exclaveschelloserver_tests_s client;

	if (exclaves_get_status() != EXCLAVES_STATUS_AVAILABLE) {
		exclaves_debug_printf(show_test_output,
		    "%s: SKIPPED: Exclaves not available\n", __func__);
		*out = -1;
		return 0;
	}

	exclaves_debug_printf(show_test_output, "%s: STARTING\n", __func__);

	tb_endpoint_t ep = tb_endpoint_create_with_value(TB_TRANSPORT_TYPE_XNU,
	    EXCLAVES_ID_HELLO_EXCLAVE_EP, TB_ENDPOINT_OPTIONS_NONE);

	tb_result = exclaveschelloserver_tests__init(&client, ep);
	assert3u(tb_result, ==, TB_ERROR_SUCCESS);

	tb_result = exclaveschelloserver_tests_default_hello(&client, ^(uint64_t result) {
		assert3u(tb_result, ==, TB_ERROR_SUCCESS);
		assert3u((uint16_t)(result), ==, 0x1338);
	});

	exclaves_debug_printf(show_test_output, "%s: SUCCESS\n", __func__);
	*out = 1;

	return KERN_SUCCESS;
}
SYSCTL_TEST_REGISTER(exclaves_hello_exclave_test, exclaves_hello_exclave_test);

static int
exclaves_panic_exclave_test(__unused int64_t in, int64_t *out)
{
	tb_error_t tb_result;
	exclaveschelloserver_tests_s client;

	if (exclaves_get_status() != EXCLAVES_STATUS_AVAILABLE) {
		exclaves_debug_printf(show_test_output,
		    "%s: SKIPPED: Exclaves not available\n", __func__);
		*out = -1;
		return 0;
	}

	exclaves_debug_printf(show_test_output, "%s: STARTING\n", __func__);

	tb_endpoint_t ep = tb_endpoint_create_with_value(TB_TRANSPORT_TYPE_XNU,
	    EXCLAVES_ID_HELLO_EXCLAVE_EP, TB_ENDPOINT_OPTIONS_NONE);

	tb_result = exclaveschelloserver_tests__init(&client, ep);
	assert3u(tb_result, ==, TB_ERROR_SUCCESS);

	tb_result = exclaveschelloserver_tests_panic_exclave_example(&client);

	/* This should not be reachable. Hence, failed. */
	exclaves_debug_printf(show_test_output, "%s: FAILED\n", __func__);
	*out = -1;

	return KERN_SUCCESS;
}
SYSCTL_TEST_REGISTER(exclaves_panic_exclave_test, exclaves_panic_exclave_test);

#endif /* __has_include(<Tightbeam/tightbeam.h>) */

static int
exclaves_sensor_kpi_test(int64_t in, int64_t *out)
{
#pragma unused(in)
#define SENSOR_TEST(x) \
    if (!(x)) { \
	        exclaves_debug_printf(show_errors, \
	            "%s: FAILURE -- %s:%d\n", __func__, __FILE__, __LINE__); \
	success = false; \
	goto out; \
    }

	bool success = true;
	exclaves_debug_printf(show_test_output, "%s: STARTING\n", __func__);

	// TODO: EIC-based camera tests are disabled until rdar://132025387
	exclaves_sensor_type_t sensors[] = {
		EXCLAVES_SENSOR_MIC,
	};
	unsigned num_sensors = sizeof(sensors) / sizeof(sensors[0]);
	exclaves_sensor_status_t sensor_status = EXCLAVES_SENSOR_STATUS_DENIED;
	exclaves_sensor_type_t bad =
	    (exclaves_sensor_type_t) (unsigned) (EXCLAVES_SENSOR_MAX + 1);
	kern_return_t kr;

	/* invalid sensor */
	kr = exclaves_sensor_stop(bad, 0, &sensor_status);
	SENSOR_TEST(kr == KERN_INVALID_ARGUMENT);

	kr = exclaves_sensor_start(bad, 0, &sensor_status);
	SENSOR_TEST(kr == KERN_INVALID_ARGUMENT);

	kr = exclaves_sensor_status(bad, 0, &sensor_status);
	SENSOR_TEST(kr == KERN_INVALID_ARGUMENT);

	/* stop before start */
	for (unsigned i = 0; i < num_sensors; i++) {
		kr = exclaves_sensor_stop(sensors[i], 0, &sensor_status);
		SENSOR_TEST(kr == KERN_INVALID_ARGUMENT);
	}

	/* start status is denied */
	for (unsigned i = 0; i < num_sensors; i++) {
		kr = exclaves_sensor_status(sensors[i], 0, &sensor_status);
		SENSOR_TEST(kr == KERN_SUCCESS);
		SENSOR_TEST(sensor_status == EXCLAVES_SENSOR_STATUS_ALLOWED); /* Not enforced */
	}

	/* ALLOWED after at least 1 start */
	unsigned const n = 5;
	for (unsigned i = 0; i < num_sensors; i++) {
		for (unsigned j = 0; j < n; j++) {
			kr = exclaves_sensor_start(sensors[i], 0, &sensor_status);
			SENSOR_TEST(kr == KERN_SUCCESS);
			SENSOR_TEST(sensor_status == EXCLAVES_SENSOR_STATUS_ALLOWED);
			kr = exclaves_sensor_status(sensors[i], 0, &sensor_status);
			SENSOR_TEST(kr == KERN_SUCCESS);
			SENSOR_TEST(sensor_status == EXCLAVES_SENSOR_STATUS_ALLOWED);
		}
	}

	/* ALLOWED after n-1 stops */
	for (unsigned i = 0; i < num_sensors; i++) {
		for (unsigned j = 0; j < n - 1; j++) {
			kr = exclaves_sensor_stop(sensors[i], 0, &sensor_status);
			SENSOR_TEST(kr == KERN_SUCCESS);
			SENSOR_TEST(sensor_status == EXCLAVES_SENSOR_STATUS_ALLOWED);
			kr = exclaves_sensor_status(sensors[i], 0, &sensor_status);
			SENSOR_TEST(kr == KERN_SUCCESS);
			SENSOR_TEST(sensor_status == EXCLAVES_SENSOR_STATUS_ALLOWED);
		}
	}

	/* DENIED after final stop */
	for (unsigned i = 0; i < num_sensors; i++) {
		kr = exclaves_sensor_stop(sensors[i], 0, &sensor_status);
		SENSOR_TEST(kr == KERN_SUCCESS);
		SENSOR_TEST(sensor_status == EXCLAVES_SENSOR_STATUS_ALLOWED); /* Not enforced */
	}

	/* exclaves_display_healthcheck_rate does something */
	kr = exclaves_display_healthcheck_rate(NSEC_PER_SEC / 60);
	SENSOR_TEST(kr == KERN_SUCCESS);

#undef SENSOR_TEST
out:
	if (success) {
		exclaves_debug_printf(show_test_output,
		    "%s: SUCCESS\n", __func__);
		*out = 1;
	} else {
		exclaves_debug_printf(show_errors, "%s: FAILED\n", __func__);
		*out = 0;
	}
	return 0;
}
SYSCTL_TEST_REGISTER(exclaves_sensor_kpi_test,
    exclaves_sensor_kpi_test);

static int
exclaves_check_mem_usage_test(__unused int64_t in, int64_t *out)
{
	if (exclaves_get_status() != EXCLAVES_STATUS_AVAILABLE) {
		exclaves_debug_printf(show_test_output,
		    "%s: SKIPPED: Exclaves not available\n", __func__);
		*out = -1;
		return 0;
	}

	exclaves_debug_printf(show_test_output, "%s: STARTING\n", __func__);

	kern_return_t r = exclaves_xnuproxy_pmm_usage();
	if (r == KERN_FAILURE) {
		exclaves_debug_printf(show_errors,
		    "Exclave Check Memory Usage failed: Kernel Failure\n");
		return 0;
	}

	exclaves_debug_printf(show_test_output, "%s: SUCCESS\n", __func__);
	*out = 1;

	return 0;
}
SYSCTL_TEST_REGISTER(exclaves_check_mem_usage_test, exclaves_check_mem_usage_test);


#endif /* DEVELOPMENT || DEBUG */

#endif /* CONFIG_EXCLAVES */
