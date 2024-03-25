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

#include <firehose/tracepoint_private.h>
#include <kern/thread.h>
#include <mach/exclaves.h>
#include <os/log_private.h>
#include <os/log.h>
#include <stdbool.h>
#include <stdint.h>

#include "kern/exclaves.tightbeam.h"
#include "exclaves_boot.h"

#define EXCLAVES_ID_LOGSERVER_EP \
    (exclaves_endpoint_lookup("com.apple.service.LogServer_xnuproxy"))

#if DEVELOPMENT || DEBUG

#define OS_LOG_MAX_SIZE (2048)

TUNABLE(bool, oslog_exclaves, "oslog_exclaves", true);

SCALABLE_COUNTER_DEFINE(oslog_e_log_count);
SCALABLE_COUNTER_DEFINE(oslog_e_log_dropped_count);
SCALABLE_COUNTER_DEFINE(oslog_e_metadata_count);
SCALABLE_COUNTER_DEFINE(oslog_e_metadata_dropped_count);
SCALABLE_COUNTER_DEFINE(oslog_e_signpost_count);
SCALABLE_COUNTER_DEFINE(oslog_e_signpost_dropped_count);
SCALABLE_COUNTER_DEFINE(oslog_e_query_count);
SCALABLE_COUNTER_DEFINE(oslog_e_error_query_count);

/*
 * Interpose kernel UUID until Exclaves cstring harvesting is in place. This
 * workaround allows to send out proper logs and signposts instead of plain
 * strings. As a result, logs and signposts will be attributed to the kernel.
 */
static inline void
interpose_kernel_uuid(uint8_t *ld_data, __assert_only size_t ld_data_size)
{
	assert3u(sizeof(uint32_t) + sizeof(uuid_t), <, ld_data_size);
	memcpy(&ld_data[sizeof(uint32_t)], kernel_uuid, sizeof(uuid_t));
}

static size_t
oslogdarwin_logdata_data(const oslogdarwin_logdata_s *ld, uint8_t *ld_data, size_t ld_data_size)
{
	__block size_t count = 0;

	logbyte__v_visit(&ld->data, ^(size_t i, const uint8_t item) {
		/*
		 * logbyte__v_visit() does not provide means to stop the iteration
		 * and so the index is being checked not to overflow ld_data
		 * array.
		 */
		if (i < ld_data_size) {
		        ld_data[i] = item;
		}
		count++;
	});
	return count;
}

static void
os_log_replay_log(const oslogdarwin_logdata_s *ld, uint8_t *ld_data, size_t ld_data_size)
{
	const size_t ld_size = oslogdarwin_logdata_data(ld, ld_data, ld_data_size);
	assert3u(ld_size, <=, ld_data_size);
	assert3u(ld->pubsize, <=, ld_size);

	firehose_tracepoint_id_u ftid = {
		.ftid_value = ld->ftid
	};

	switch (ftid.ftid._namespace) {
	case firehose_tracepoint_namespace_metadata:
		counter_inc(&oslog_e_metadata_count);
		if (!os_log_encoded_metadata(ftid, ld->stamp, ld_data, ld_size)) {
			counter_inc(&oslog_e_metadata_dropped_count);
		}
		break;
	case firehose_tracepoint_namespace_log:
		counter_inc(&oslog_e_log_count);
		interpose_kernel_uuid(ld_data, ld_size);
		if (!os_log_encoded_log(ftid, ld->stamp, ld_data, ld_size, ld->pubsize)) {
			counter_inc(&oslog_e_log_dropped_count);
		}
		break;
	case firehose_tracepoint_namespace_signpost:
		counter_inc(&oslog_e_signpost_count);
		interpose_kernel_uuid(ld_data, ld_size);
		if (!os_log_encoded_signpost(ftid, ld->stamp, ld_data, ld_size, ld->pubsize)) {
			counter_inc(&oslog_e_signpost_dropped_count);
		}
		break;
	default:
		panic("Unsupported Exclaves log type %d", ftid.ftid._namespace);
	}
}

static void
os_log_replay_logs(const oslogdarwin_logdata_v_s *logs, uint8_t *log_buffer, size_t log_buffer_size)
{
	oslogdarwin_logdata__v_visit(logs, ^(size_t __unused i, const oslogdarwin_logdata_s *_Nonnull log) {
		os_log_replay_log(log, log_buffer, log_buffer_size);
	});
}

/*
 * The log retrieval thread (served by this handler) does not busy loop the
 * whole time. It sleeps on a conditional variable in the Exclaves log server
 * and runs only when there are new logs in Exclaves to pick up and to replay.
 */
static void
log_server_retrieve_logs(void *arg, __unused wait_result_t w)
{
	os_log_t log = arg;

	tb_endpoint_t ep = tb_endpoint_create_with_value(TB_TRANSPORT_TYPE_XNU,
	    EXCLAVES_ID_LOGSERVER_EP, TB_ENDPOINT_OPTIONS_NONE);
	if (ep == NULL) {
		os_log_error(log, "Exclaves logging: Failed to create the endpoint\n");
		return;
	}

	oslogdarwin_consumer_s log_server = {0};

	tb_error_t err = oslogdarwin_consumer__init(&log_server, ep);
	if (err != TB_ERROR_SUCCESS) {
		os_log_error(log, "Exclaves logging: Failed to initialize client with %d\n", err);
		return;
	}

	uint8_t *log_buffer = kalloc_data_tag(OS_LOG_MAX_SIZE, Z_WAITOK_ZERO, VM_KERN_MEMORY_LOG);
	if (!log_buffer) {
		os_log_error(log, "Exclaves logging: Failed to allocate a log buffer\n");
		return;
	}

	do {
		err = oslogdarwin_consumer_getlogs(&log_server, ^(oslogdarwin_logdata_v_s logs) {
			os_log_replay_logs(&logs, log_buffer, OS_LOG_MAX_SIZE);
			counter_inc(&oslog_e_query_count);
		});
	} while (__probable(err == TB_ERROR_SUCCESS));

	kfree_data(log_buffer, OS_LOG_MAX_SIZE);

	counter_inc(&oslog_e_error_query_count);
	os_log_error(log, "Exclaves logging: Failed to retrieve logs, error: %d. Exiting.\n", err);
}

#else // DEVELOPMENT || DEBUG

/*
 * Exclaves logging is temporarily disabled until all parts of the logging
 * pipeline land.
 */
TUNABLE(bool, oslog_exclaves, "oslog_exclaves", false);

static void
replay_redacted_log(const oslogdarwin_redactedlogdata_log_s *log)
{
	uuid_string_t uuidstr;
	uuid_unparse(log->uuid, uuidstr);

	os_log_at_time(OS_LOG_DEFAULT, (os_log_type_t)log->type, log->stamp, "log,%s,%0x",
	    uuidstr, log->offset);
}

static void
replay_redacted_signpost(const oslogdarwin_redactedlogdata_signpost_s *signpost)
{
	uuid_string_t uuidstr;
	uuid_unparse(signpost->uuid, uuidstr);

	os_log_at_time(OS_LOG_DEFAULT, OS_LOG_TYPE_DEBUG, signpost->stamp, "signpost,%s,%0x,%0x,%u,%u",
	    uuidstr, signpost->fmtOffset, signpost->nameOffset, signpost->type, signpost->scope);
}

static void
os_log_replay_redacted_log(const oslogdarwin_redactedlogdata_s *ld)
{
	const oslogdarwin_redactedlogdata_log_s *log;
	const oslogdarwin_redactedlogdata_signpost_s *signpost;

	switch (ld->tag) {
	case OSLOGDARWIN_REDACTEDLOGDATA__LOG:
		log = oslogdarwin_redactedlogdata_log__get(ld);
		replay_redacted_log(log);
		break;
	case OSLOGDARWIN_REDACTEDLOGDATA__SIGNPOST:
		signpost = oslogdarwin_redactedlogdata_signpost__get(ld);
		replay_redacted_signpost(signpost);
		break;
	case OSLOGDARWIN_REDACTEDLOGDATA__SUBSYSTEM:
		// Subsystem registration not supported for now.
		break;
	default:
		panic("Unsupported redacted Exclaves log type %llu", ld->tag);
	}
}

static void
os_log_replay_redacted_logs(const oslogdarwin_redactedlogdata_v_s *logs)
{
	oslogdarwin_redactedlogdata__v_visit(logs, ^(size_t __unused i, const oslogdarwin_redactedlogdata_s *_Nonnull log) {
		os_log_replay_redacted_log(log);
	});
}

/*
 * The log retrieval thread (served by this handler) does not busy loop the
 * whole time. It sleeps on a conditional variable in the Exclaves log server
 * and runs only when there are new logs in Exclaves to pick up and to replay.
 */
static void
redacted_log_server_retrieve_logs(void *arg, __unused wait_result_t w)
{
	os_log_t log = arg;

	tb_endpoint_t ep = tb_endpoint_create_with_value(TB_TRANSPORT_TYPE_XNU,
	    EXCLAVES_ID_LOGSERVER_EP, TB_ENDPOINT_OPTIONS_NONE);
	if (ep == NULL) {
		os_log_error(log, "Exclaves logging: Failed to create the endpoint\n");
		return;
	}

	oslogdarwin_redactedconsumer_s log_server = {0};

	tb_error_t err = oslogdarwin_redactedconsumer__init(&log_server, ep);
	if (err != TB_ERROR_SUCCESS) {
		os_log_error(log, "Exclaves logging: Failed to initialize client with %d\n", err);
		return;
	}

	do {
		err = oslogdarwin_redactedconsumer_getlogs(&log_server, ^(oslogdarwin_redactedlogdata_v_s logs) {
			os_log_replay_redacted_logs(&logs);
		});
	} while (__probable(err == TB_ERROR_SUCCESS));

	os_log_error(log, "Exclaves logging: Failed to retrieve logs, error: %d. Exiting.\n", err);
}

#endif // DEVELOPMENT || DEBUG

static kern_return_t
exclaves_oslog_init(void)
{
	extern bool os_log_disabled(void);

	if (os_log_disabled()) {
		printf("Exclaves logging: Disabled by ATM\n");
		return KERN_SUCCESS;
	}

	os_log_t log = os_log_create(OS_LOG_XNU_SUBSYSTEM, "oslog-exclaves-handler");

	if (!oslog_exclaves) {
		os_log(log, "Exclaves logging: Disabled by boot argument\n");
		return KERN_SUCCESS;
	}

	thread_t oslog_exclaves_thread = THREAD_NULL;
#if DEVELOPMENT || DEBUG
	thread_continue_t log_handler = log_server_retrieve_logs;
#else
	thread_continue_t log_handler = redacted_log_server_retrieve_logs;
#endif

	kern_return_t err = kernel_thread_start(log_handler, log, &oslog_exclaves_thread);
	if (err != KERN_SUCCESS) {
		os_log_error(log, "Exclaves logging: Disabled. Starting the thread failed with %d\n", err);
		return KERN_FAILURE;
	}
	thread_deallocate(oslog_exclaves_thread);

	os_log(log, "Exclaves logging: Enabled\n");

	return KERN_SUCCESS;
}
/* Make sure oslog init runs as early as possible so that there's a chance to
 * see logs for failures.
 */
EXCLAVES_BOOT_TASK(exclaves_oslog_init, EXCLAVES_BOOT_RANK_SECOND);

#endif // CONFIG_EXCLAVES
