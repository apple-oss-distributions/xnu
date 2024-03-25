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

#include <mach/exclaves_l4.h>

#include <Tightbeam/tightbeam.h>
#include <Tightbeam/tightbeam_private.h>
#include "kern/exclaves.tightbeam.h"
#include "exclaves_debug.h"

/* External & generated headers */
#include <xrt_hosted_types/types.h>
#include <xnuproxy/messages.h>
#include "exclaves_resource.h"

#if __has_include(<Tightbeam/tightbeam.h>)

#define EXCLAVES_ID_HELLO_EXCLAVE_EP \
    (exclaves_endpoint_lookup("com.apple.service.HelloExclave"))

static int
exclaves_hello_exclave_test(__unused int64_t in, int64_t *out)
{
	kern_return_t kr = KERN_SUCCESS;

	if (exclaves_get_status() != EXCLAVES_STATUS_AVAILABLE) {
		exclaves_debug_printf(show_test_output,
		    "%s: SKIPPED: Exclaves not available\n", __func__);
		*out = -1;
		return 0;
	}

	exclaves_debug_printf(show_test_output, "%s: STARTING\n", __func__);

	Exclaves_L4_IpcBuffer_t *ipcb;
	kr = exclaves_allocate_ipc_buffer((void**)&ipcb);
	assert(kr == KERN_SUCCESS);
	assert(ipcb != NULL);

	exclaves_tag_t tag = Exclaves_L4_MessageTag(0, 0, 0x1338ul,
	    Exclaves_L4_False);

	exclaves_debug_printf(show_test_output,
	    "exclaves: exclaves_endpoint_call() sending tag 0x%llx, "
	    "label 0x%lx\n", tag, Exclaves_L4_MessageTag_Label(tag));

	exclaves_error_t error;
	kr = exclaves_endpoint_call(IPC_PORT_NULL, EXCLAVES_ID_HELLO_EXCLAVE_EP,
	    &tag, &error);
	assert(kr == KERN_SUCCESS);

	exclaves_debug_printf(show_test_output,
	    "exclaves: exclaves_endpoint_call() returned tag 0x%llx, "
	    "label 0x%lx, error 0x%llx\n", tag, Exclaves_L4_MessageTag_Label(tag),
	    error);

	assert(error == Exclaves_L4_Success);
	assert(Exclaves_L4_MessageTag_Mrs(tag) == 0);
	assert((uint16_t)Exclaves_L4_MessageTag_Label(tag) == (uint16_t)0x1339ul);

	kr = exclaves_free_ipc_buffer();
	assert(kr == KERN_SUCCESS);

	exclaves_debug_printf(show_test_output, "%s: SUCCESS\n", __func__);
	*out = 1;

	return 0;
}
SYSCTL_TEST_REGISTER(exclaves_hello_exclave_test, exclaves_hello_exclave_test);

static int
exclaves_panic_exclave_test(__unused int64_t in, int64_t *out)
{
	kern_return_t kr = KERN_SUCCESS;

	if (exclaves_get_status() != EXCLAVES_STATUS_AVAILABLE) {
		exclaves_debug_printf(show_test_output,
		    "%s: SKIPPED: Exclaves not available\n", __func__);
		*out = -1;
		return 0;
	}

	printf("%s: STARTING\n", __func__);

	Exclaves_L4_IpcBuffer_t *ipcb;
	kr = exclaves_allocate_ipc_buffer((void**)&ipcb);
	assert(kr == KERN_SUCCESS);
	assert(ipcb != NULL);

	// 0x9 tag will panic the HELLO C Exclave example
	exclaves_tag_t tag = Exclaves_L4_MessageTag(0, 0, 0x9ul,
	    Exclaves_L4_False);

	printf("exclaves: exclaves_endpoint_call() sending tag 0x%llx, "
	    "label 0x%lx\n", tag, Exclaves_L4_MessageTag_Label(tag));

	exclaves_error_t error;
	kr = exclaves_endpoint_call(IPC_PORT_NULL, EXCLAVES_ID_HELLO_EXCLAVE_EP,
	    &tag, &error);

	/* Should never reach here */
	assert(kr == KERN_SUCCESS);

	printf("exclaves: exclaves_endpoint_call() returned tag 0x%llx, "
	    "label 0x%lx, error 0x%llx\n", tag, Exclaves_L4_MessageTag_Label(tag),
	    error);

	assert(error == Exclaves_L4_Success);

	kr = exclaves_free_ipc_buffer();
	assert(kr == KERN_SUCCESS);

	/* This should not be reachable. Hence, failed. */
	printf("%s: FAILED\n", __func__);
	*out = 1;

	return 0;
}
SYSCTL_TEST_REGISTER(exclaves_panic_exclave_test, exclaves_panic_exclave_test);

#define EXCLAVES_ID_SWIFT_HELLO_EXCLAVE_EP \
    (exclaves_endpoint_lookup("com.apple.service.HelloTightbeam"))

static int
exclaves_hello_tightbeam_test(__unused int64_t in, int64_t *out)
{
	if (exclaves_get_status() != EXCLAVES_STATUS_AVAILABLE) {
		exclaves_debug_printf(show_test_output,
		    "%s: SKIPPED: Exclaves not available\n", __func__);
		*out = -1;
		return 0;
	}

	exclaves_debug_printf(show_test_output, "%s: STARTING\n", __func__);
	tb_endpoint_t ep = tb_endpoint_create_with_value(
		TB_TRANSPORT_TYPE_XNU, EXCLAVES_ID_SWIFT_HELLO_EXCLAVE_EP, 0);

	tb_client_connection_t client =
	    tb_client_connection_create_with_endpoint(ep);

	tb_client_connection_activate(client);

	tb_message_t message = NULL;
	tb_transport_message_buffer_t tpt_buf = NULL;

	message = kalloc_type(struct tb_message_s, Z_WAITOK | Z_ZERO | Z_NOFAIL);
	tpt_buf = kalloc_type(struct tb_transport_message_buffer_s,
	    Z_WAITOK | Z_ZERO | Z_NOFAIL);

	const char *hello_tb = "Hello!";
	const char *hello = hello_tb;
	const char *goodbye = "Goodbye!";

	tb_error_t err = TB_ERROR_SUCCESS;
	err = tb_client_connection_message_construct(client, message,
	    tpt_buf, strlen(hello), 0);
	if (err != TB_ERROR_SUCCESS) {
		exclaves_debug_printf(show_errors,
		    "%s: FAILURE -- Failed to construct message\n", __func__);
		*out = 0;
		goto out;
	}
	exclaves_debug_printf(show_test_output,
	    "%s: Tightbeam constructing message: ", __func__);
	for (const char *c = hello; *c; c++) {
		exclaves_debug_printf(show_test_output, "%c", (uint8_t)*c);
		tb_message_encode_u8(message, (uint8_t)*c);
	}
	printf("\n");
	tb_message_complete(message);
	exclaves_debug_printf(show_test_output,
	    "%s: Tightbeam message completed\n", __func__);

	tb_message_t response = NULL;

	err = tb_connection_send_query(client, message, &response,
	    TB_CONNECTION_WAIT_FOR_REPLY);
	if (err != TB_ERROR_SUCCESS) {
		exclaves_debug_printf(show_errors,
		    "%s: FAILURE -- Failed to send message\n", __func__);
		goto out;
	}
	exclaves_debug_printf(show_test_output,
	    "%s: Tightbeam message send success, reply: ", __func__);

	bool mismatch = false;
	uint8_t val = 0;
	for (const char *c = goodbye; *c; c++) {
		tb_message_decode_u8(response, &val);
		printf("%c", val);
		if (val != (uint8_t)*c) {
			mismatch = true;
		}
	}
	exclaves_debug_printf(show_test_output, "\n");
	if (mismatch) {
		exclaves_debug_printf(show_errors,
		    "%s: FAILURE -- Mismatched reply message\n", __func__);
		*out = 0;
		goto out;
	}
	tb_client_connection_message_destruct(client, message);

	exclaves_debug_printf(show_test_output, "%s: SUCCESS\n", __func__);
	*out = 1;

out:
	kfree_type(struct tb_message_s, message);
	kfree_type(struct tb_transport_message_buffer_s, tpt_buf);
	return 0;
}

SYSCTL_TEST_REGISTER(exclaves_hello_tightbeam_test,
    exclaves_hello_tightbeam_test);

#endif /* __has_include(<Tightbeam/tightbeam.h>) */

static int
exclaves_sensor_kpi_test(int64_t in, int64_t *out)
{
#pragma unused(in)
#define SENSOR_TEST(x) \
    if (!(x)) { \
	        printf("%s: FAILURE -- %s:%d\n", __func__, __FILE__, __LINE__); \
	success = false; \
	goto out; \
    }

	bool success = true;
	printf("%s: STARTING\n", __func__);

	exclaves_sensor_type_t sensors[] = {
		EXCLAVES_SENSOR_CAM,
		EXCLAVES_SENSOR_MIC,
		EXCLAVES_SENSOR_CAM_ALT_FACEID,
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
		printf("%s: SUCCESS\n", __func__);
		*out = 1;
	} else {
		printf("%s: FAILED\n", __func__);
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

	kern_return_t r = exclaves_xnu_proxy_check_mem_usage();
	if (r == KERN_FAILURE) {
		printf("Exclave Check Memory Usage failed: Kernel Failure\n");
		return 0;
	}

	exclaves_debug_printf(show_test_output, "%s: SUCCESS\n", __func__);
	*out = 1;

	return 0;
}
SYSCTL_TEST_REGISTER(exclaves_check_mem_usage_test, exclaves_check_mem_usage_test);


#endif /* DEVELOPMENT || DEBUG */

#endif /* CONFIG_EXCLAVES */
