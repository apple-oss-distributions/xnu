/*
 * Copyright (c) 2022 Apple Inc. All rights reserved.
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

#ifndef _KERN_EXT_PANICLOG_H_
#define _KERN_EXT_PANICLOG_H_

#include <sys/queue.h>
#include <uuid/uuid.h>
#include <os/base.h>

#define EXT_PANICLOG_ENABLE     1

#define EXT_PANICLOG_VERSION    1

#define MAX_DATA_ID_SIZE    32

#define MAX_EXT_PANICLOG_SIZE   32 * 1024

#define MAX_EXT_PANICLOG_LOGS   100

/*
 * From the panic log metrics, we estimate that the paniclog takes up
 * ~15K bytes and other log takes ~1K bytes. This 64K bytes ensures that
 * we have enough space for other log and nested panics
 */
#define OTHER_LOG_REQUIRED_SIZE (64 * 1024)

#define PANIC_WITH_DATA_UUID "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
#define PANIC_WITH_DATA_MAX_LEN 2048
#define PANIC_WITH_DATA_DATA_ID "Panic with Data Buffer"

#define EXTPANICLOG_ENTITLEMENT         "com.apple.private.allow-ext_paniclog"

#if KERNEL_PRIVATE

OS_CLOSED_OPTIONS(ext_paniclog_create_options, uint32_t,
    EXT_PANICLOG_OPTIONS_NONE = 0x0,
    EXT_PANICLOG_OPTIONS_WITH_BUFFER = 0x1);

enum ext_paniclog_test_options {
	EXT_PANICLOG_TEST_HANDLE_CREATE = 1,
	EXT_PANICLOG_TEST_SET_ACTIVE_INACTIVE,
	EXT_PANICLOG_TEST_INSERT_DATA,
	EXT_PANICLOG_TEST_WRITE_PANIC_DATA,
	EXT_PANICLOG_TEST_MULTIPLE_HANDLES,
	EXT_PANICLOG_TEST_MULTIPLE_HANDLES_PANIC,
	EXT_PANICLOG_TEST_INSERT_DUMMY_HANDLES,
	EXT_PANICLOG_TEST_INSERT_STRUCT_HANDLES,
	EXT_PANICLOG_TEST_END,
};

typedef struct ext_paniclog_handle {
	LIST_ENTRY(ext_paniclog_handle) handles;
	uuid_t uuid;
	char data_id[MAX_DATA_ID_SIZE];
	void * XNU_PTRAUTH_SIGNED_PTR("ext_paniclog_handle.buf_addr") buf_addr;
	uint32_t max_len;
	uint32_t used_len;
	ext_paniclog_create_options_t options;
	uint8_t active;
} ext_paniclog_handle_t;

typedef struct ext_paniclog_header {
	uint32_t len;
	uuid_t uuid;
} ext_paniclog_header_t;

void ext_paniclog_init(void);
int ext_paniclog_handle_set_active(ext_paniclog_handle_t *handle);
int ext_paniclog_handle_set_inactive(ext_paniclog_handle_t *handle);
ext_paniclog_handle_t *ext_paniclog_handle_alloc_with_uuid(uuid_t uuid, const char *data_id, uint32_t max_len, ext_paniclog_create_options_t options);
ext_paniclog_handle_t *ext_paniclog_handle_alloc_with_buffer(uuid_t uuid, const char *data_id, uint32_t max_len, void * buff, ext_paniclog_create_options_t options);
void ext_paniclog_handle_free(ext_paniclog_handle_t *handle);
int ext_paniclog_insert_data(ext_paniclog_handle_t *handle, void *addr, uint32_t len);
int ext_paniclog_append_data(ext_paniclog_handle_t *handle, void *addr, uint32_t len);
void *ext_paniclog_get_buffer(ext_paniclog_handle_t *handle);
uint32_t ext_paniclog_write_panicdata(void);
void *ext_paniclog_claim_buffer(ext_paniclog_handle_t *handle);
int ext_paniclog_yield_buffer(ext_paniclog_handle_t *handle, uint32_t used_len);
int ext_paniclog_set_used_len(ext_paniclog_handle_t *handle, uint32_t used_len);
bool is_debug_ptr_in_ext_paniclog(void);

/*
 * This function is used to panic and add a buffer data to the extensible paniclog.
 * uuid here is used to decode the data.
 */
__abortlike __printflike(4, 5)
void panic_with_data(uuid_t uuid, void *addr, uint32_t len, const char *format, ...);
int ext_paniclog_test_hook(uint32_t option);
void ext_paniclog_panic_with_data(uuid_t uuid, void *addr, uint32_t len);
#endif // KERNEL_PRIVATE

#endif // _KERN_EXT_PANICLOG_H_
