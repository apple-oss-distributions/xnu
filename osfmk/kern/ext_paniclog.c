/*
 * Copyright (c) 2022 Apple Computer, Inc. All rights reserved.
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

#include <kern/locks.h>
#include <kern/kalloc.h>
#include <kern/zalloc.h>
#include <libkern/OSAtomic.h>
#include <os/log.h>

#include <kern/ext_paniclog.h>
#include <kern/debug.h>

#if defined(__arm64__)
#include <pexpert/pexpert.h> /* For gPanicBase */
#endif

#if CONFIG_EXT_PANICLOG

static LCK_GRP_DECLARE(ext_paniclog_lck_grp, "Extensible panic log locks");
static LCK_MTX_DECLARE(ext_paniclog_list_lock, &ext_paniclog_lck_grp);

// Global slot for panic_with_data
ext_paniclog_handle_t *panic_with_data_handle;

// Global to keep track of number of handles
uint32_t ext_paniclog_handle_count = 0;

uint8_t ext_paniclog_panic_in_progress = 0;

uint8_t ext_paniclog_panic_write_done = 0;

uuid_string_t panic_with_data_uuid = PANIC_WITH_DATA_UUID;

LIST_HEAD(_ext_paniclog_handle_list, ext_paniclog_handle) ext_paniclog_handle_list;

void
ext_paniclog_init(void)
{
	os_log(OS_LOG_DEFAULT, "EXT_PANICLOG: Initializing list\n");
	LIST_INIT(&ext_paniclog_handle_list);

	uuid_t uuid;
	panic_with_data_handle = ext_paniclog_handle_alloc_with_uuid(uuid,
	    PANIC_WITH_DATA_DATA_ID,
	    PANIC_WITH_DATA_MAX_LEN, EXT_PANICLOG_OPTIONS_NONE);
}

ext_paniclog_handle_t *
ext_paniclog_handle_alloc_with_uuid(uuid_t uuid, const char *data_id,
    uint32_t max_len, ext_paniclog_create_options_t options)
{
	size_t data_id_size = strnlen(data_id, MAX_DATA_ID_SIZE - 1);

	if (max_len > (MAX_EXT_PANICLOG_SIZE - data_id_size - sizeof(ext_paniclog_header_t))) {
		os_log_error(OS_LOG_DEFAULT, "EXT_PANICLOG_: Input len %d greater than max allowed %d\n",
		    max_len, MAX_EXT_PANICLOG_SIZE);
		return NULL;
	}

	ext_paniclog_handle_t *handle = kalloc_type(ext_paniclog_handle_t, Z_WAITOK | Z_ZERO);
	if (!handle) {
		return NULL;
	}

	/* We don't alloc a buffer if the create call is from a dext.
	 * In the Create call for dext, we use a IOBMD to backup this handle
	 */

	if (!(options & EXT_PANICLOG_OPTIONS_WITH_BUFFER)) {
		handle->buf_addr = kalloc_data(max_len, Z_WAITOK | Z_ZERO);
		if (!handle->buf_addr) {
			kfree_type(ext_paniclog_handle_t, handle);
			return NULL;
		}
	}

	memcpy(handle->uuid, uuid, sizeof(uuid_t));
	memcpy(handle->data_id, data_id, data_id_size);

	handle->options = options;
	handle->max_len = max_len;
	handle->used_len = 0;
	handle->active = 0;

	return handle;
}

ext_paniclog_handle_t *
ext_paniclog_handle_alloc_with_buffer(uuid_t uuid, const char *data_id,
    uint32_t max_len, void * buff, ext_paniclog_create_options_t options)
{
	ext_paniclog_handle_t *handle = NULL;

	handle = ext_paniclog_handle_alloc_with_uuid(uuid, data_id, max_len, options);
	if (handle == NULL) {
		return NULL;
	}

	handle->buf_addr = buff;

	return handle;
}

void
ext_paniclog_handle_free(ext_paniclog_handle_t *handle)
{
	if (handle == NULL) {
		return;
	}

	ext_paniclog_handle_set_inactive(handle);

	if (!(handle->options & EXT_PANICLOG_OPTIONS_WITH_BUFFER)) {
		kfree_data(handle->buf_addr, handle->max_len);
	}

	kfree_type(ext_paniclog_handle_t, handle);
}

int
ext_paniclog_handle_set_active(ext_paniclog_handle_t *handle)
{
	if (handle == NULL) {
		return -1;
	}

	if (!OSCompareAndSwap8(0, 1, &handle->active)) {
		return -1;
	}

	lck_mtx_lock(&ext_paniclog_list_lock);

	LIST_INSERT_HEAD(&ext_paniclog_handle_list, handle, handles);
	ext_paniclog_handle_count++;

	lck_mtx_unlock(&ext_paniclog_list_lock);

	return 0;
}

int
ext_paniclog_handle_set_inactive(ext_paniclog_handle_t *handle)
{
	if (handle == NULL) {
		return -1;
	}

	if (!OSCompareAndSwap8(1, 0, &handle->active)) {
		return -1;
	}

	lck_mtx_lock(&ext_paniclog_list_lock);

	LIST_REMOVE(handle, handles);
	ext_paniclog_handle_count--;

	lck_mtx_unlock(&ext_paniclog_list_lock);

	return 0;
}

static int
ext_paniclog_insert_data_internal(ext_paniclog_handle_t *handle, void *addr,
    uint32_t len, uint32_t offset)
{
	if ((handle == NULL) || (addr == NULL)) {
		return -1;
	}

	if (len > handle->max_len) {
		return -1;
	}

	char *dst = (char *)handle->buf_addr + offset;

	memcpy(dst, addr, len);

	(void)ext_paniclog_handle_set_active(handle);

	return 0;
}

int
ext_paniclog_insert_data(ext_paniclog_handle_t *handle, void *addr, uint32_t len)
{
	int ret = 0;

	ret = ext_paniclog_insert_data_internal(handle, addr, len, 0);
	if (ret == 0) {
		handle->used_len = len;
	}

	return ret;
}

int
ext_paniclog_append_data(ext_paniclog_handle_t *handle, void *addr, uint32_t len)
{
	int ret = 0;
	uint32_t updt_len = 0;

	if (os_add_overflow(len, handle->used_len, &updt_len)
	    || (updt_len > handle->max_len)) {
		return -1;
	}

	ret = ext_paniclog_insert_data_internal(handle, addr, len,
	    handle->used_len);
	if (ret == 0) {
		handle->used_len += len;
	}

	return ret;
}

void *
ext_paniclog_claim_buffer(ext_paniclog_handle_t *handle)
{
	if (handle == NULL) {
		return NULL;
	}

	handle->used_len = handle->max_len;

	return handle->buf_addr;
}

void *
ext_paniclog_get_buffer(ext_paniclog_handle_t *handle)
{
	if (handle == NULL) {
		return NULL;
	}

	return handle->buf_addr;
}

int
ext_paniclog_set_used_len(ext_paniclog_handle_t *handle, uint32_t used_len)
{
	if (handle == NULL) {
		return -1;
	}

	handle->used_len = used_len;

	return 0;
}

int
ext_paniclog_yield_buffer(ext_paniclog_handle_t *handle, uint32_t used_len)
{
	return ext_paniclog_set_used_len(handle, used_len);
}

void
ext_paniclog_panic_with_data(uuid_t uuid, void *addr, uint32_t len)
{
	if (!OSCompareAndSwap8(0, 1, &ext_paniclog_panic_in_progress)) {
		return;
	}

	if (uuid_is_null(uuid)) {
		uuid_parse(panic_with_data_uuid, uuid);
	}

	memcpy(&panic_with_data_handle->uuid[0], &uuid[0], sizeof(uuid_t));

	ext_paniclog_insert_data(panic_with_data_handle, addr, len);

	return;
}

static uint32_t
ext_paniclog_get_size_required(void)
{
	uint32_t size_req = 0;
	ext_paniclog_handle_t *tmp;

	LIST_FOREACH(tmp, &ext_paniclog_handle_list, handles) {
		size_req += (strnlen(tmp->data_id, MAX_DATA_ID_SIZE - 1) + 1) +
		    sizeof(ext_paniclog_header_t) + tmp->used_len;
	}

	// Adding the size of handle count and ext paniclog version variable
	size_req += sizeof(ext_paniclog_handle_count) + sizeof(uint32_t);

	return size_req;
}

bool
is_debug_ptr_in_ext_paniclog(void)
{
	bool ext_paniclog_exceeds = ((panic_info->eph_ext_paniclog_offset != 0) ?
	    ((uint32_t)(debug_buf_ptr - gPanicBase) >= panic_info->eph_ext_paniclog_offset) :
	    false);

	return ext_paniclog_exceeds;
}

/*
 * Format of the Extensible panic log:
 *
 * +---------+------------+---------+------------+------------+---------+--------+-----------+------------+----------+
 * |         |            |         |            |            |         |        |           |            |          |
 * |Version  | No of logs | UUID 1  | Data ID 1  | Data len 1 | Data 1  | UUID 2 | Data ID 2 | Data len 2 | Data 2   |
 * |         |            |         |            |            |         |        |           |            |          |
 * +---------+------------+---------+------------+------------+---------+--------+-----------+------------+----------+
 *
 *
 */
uint32_t
ext_paniclog_write_panicdata(void)
{
	ext_paniclog_handle_t *tmp;
	char *end = (char *)(debug_buf_base + debug_buf_size);
	uint32_t paniclog_buf_size = (uint32_t)(end - debug_buf_ptr);
	uint32_t space_left = paniclog_buf_size - OTHER_LOG_REQUIRED_SIZE;
	size_t data_id_size = 0;
	uint32_t ext_paniclog_version = EXT_PANICLOG_VERSION;
	char *dst = NULL;

	if (!OSCompareAndSwap8(0, 1, &ext_paniclog_panic_write_done) || (ext_paniclog_handle_count == 0)
	    || (paniclog_buf_size < MAX_EXT_PANICLOG_SIZE)) {
		return 0;
	}

	uint32_t size_req = ext_paniclog_get_size_required();

	size_req = MIN(MIN(size_req, MAX_EXT_PANICLOG_SIZE), space_left);

	dst = (char *)(end - size_req);

	memcpy(dst, &ext_paniclog_version, sizeof(ext_paniclog_version));
	dst += sizeof(ext_paniclog_version);

	memcpy(dst, &ext_paniclog_handle_count, sizeof(ext_paniclog_handle_count));
	dst += sizeof(ext_paniclog_handle_count);

	LIST_FOREACH(tmp, &ext_paniclog_handle_list, handles) {
		data_id_size = strnlen(tmp->data_id, MAX_DATA_ID_SIZE - 1) + 1;

		if ((dst + tmp->used_len + data_id_size + sizeof(ext_paniclog_header_t)) > end) {
			break;
		}

		memcpy(dst, tmp->uuid, sizeof(uuid_t));
		dst += sizeof(uuid_t);
		memcpy(dst, &tmp->data_id, data_id_size);
		dst += data_id_size;
		memcpy(dst, &tmp->used_len, sizeof(tmp->used_len));
		dst += sizeof(tmp->used_len);
		memcpy(dst, tmp->buf_addr, tmp->used_len);
		dst += tmp->used_len;
	}

	return size_req;
}


#if DEVELOPMENT || DEBUG

#pragma mark Extensible paniclog tests

static int
ext_paniclog_create_multiple_handles(ext_paniclog_handle_t *handles[], const char *data_id[], char *data)
{
	uuid_t uuid;
	uuid_string_t uuid_string;
	ext_paniclog_handle_t *handle;

	for (int i = 0; i < 2; i++) {
		uuid_generate(uuid);
		uuid_unparse(uuid, uuid_string);
		os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: Creating handle %d with UUID: %s\n", (i + 1), uuid_string);

		handle = ext_paniclog_handle_alloc_with_uuid(uuid, data_id[i], 1024, EXT_PANICLOG_OPTIONS_NONE);
		if (handle == NULL) {
			os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: Handle %d is NULL\n", (i + 1));
			return -1;
		}

		handles[i] = handle;

		ext_paniclog_insert_data(handle, data, 16);

		os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: Used len of buffer: %d\n", handle->used_len);
		os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: Data in buffer: %s\n", (char *)ext_paniclog_get_buffer(handle));

		ext_paniclog_handle_set_active(handle);
	}

	return 0;
}

/*
 * Test 6: EXT_PANICLOG_TEST_MULTIPLE_HANDLES_PANIC
 */
static int
ext_paniclog_multiple_handles_panic_test(void)
{
	char data[17] = "abcdefghabcdefgh";
	ext_paniclog_handle_t *handles[2] = {0};
	const char *data_id[] = {"Test Handle 1", "Test Handle 2"};
	uuid_t uuid;
	uuid_string_t uuid_string;
	uuid_generate(uuid);
	uuid_unparse(uuid, uuid_string);
	os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: panic with data UUID: %s", uuid_string);

	ext_paniclog_create_multiple_handles(handles, data_id, data);

	panic_with_data(uuid, data, 16, "Extensible panic log test");
}

/*
 * Test 5: EXT_PANICLOG_TEST_MULTIPLE_HANDLES
 */
static int
ext_paniclog_multiple_handles_test(void)
{
	char data[17] = "abcdefghabcdefgh";
	uint32_t bytes_copied = 0;
	uint32_t no_of_logs;
	uint32_t data_len = 0;
	ext_paniclog_handle_t *handles[2] = {0};
	const char *data_id[] = {"Test Handle 1", "Test Handle 2"};
	char *buf_ptr;
	int ret = 0;
	uint32_t version = 0;

	ret = ext_paniclog_create_multiple_handles(handles, data_id, data);
	if (ret < 0) {
		os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: Create handles failed\n");
		return -1;
	}

	bytes_copied = ext_paniclog_write_panicdata();
	os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: Bytes copied: %d\n", bytes_copied);

	buf_ptr = (debug_buf_base + debug_buf_size) - bytes_copied;
#if 0
	os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: *****************************************");
	for (int i = 0; i < 128; i++) {
		os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: %u ", buf_ptr[i]);
	}
	os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: *****************************************");
#endif


	memcpy(&version, buf_ptr, 4);
	if (version != EXT_PANICLOG_VERSION) {
		os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: Version mismatch: %d\n", version);
		ret = -1;
		goto finish;
	}

	buf_ptr += 4;

	memcpy(&no_of_logs, buf_ptr, 4);

	if (no_of_logs != 2) {
		os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: Num logs is not equal: %d\n", no_of_logs);
		ret = -1;
		goto finish;
	}

	buf_ptr = buf_ptr + 20;
	for (int i = 1; i >= 0; i--) {
		size_t data_id_len = strnlen(data_id[i], MAX_DATA_ID_SIZE);

		if (strncmp(data_id[i], buf_ptr, data_id_len)) {
			os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: data id is not equal\n");
			ret = -1;
			goto finish;
		}
		buf_ptr += data_id_len + 1;
		memcpy(&data_len, buf_ptr, 4);

		if (data_len != 16) {
			os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: data len is not equal: %d\n", data_len);
			ret = -1;
			goto finish;
		}

		buf_ptr += 4;

		if (memcmp(buf_ptr, data, data_len)) {
			os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: Buffers don't match\n");
			ret = -1;
			goto finish;
		}

		buf_ptr += data_len;
		buf_ptr += 16;
	}

finish:
	for (int i = 0; i < 2; i++) {
		ext_paniclog_handle_free(handles[i]);
	}

	return ret;
}

/*
 * Test 4: EXT_PANICLOG_TEST_WRITE_PANIC_DATA
 */
static int
ext_paniclog_write_panicdata_test(void)
{
	uuid_t uuid;
	uuid_generate(uuid);
	uuid_string_t uuid_string;
	uuid_unparse(uuid, uuid_string);
	uint32_t bytes_copied;
	const char data_id[] = "Test Handle";
	char *buf_ptr;
	uint32_t num_of_logs = 0;
	uint32_t data_len = 0;
	char data1[17] = "abcdefghabcdefgh";
	char panic_data[1024] = {0};
	uint32_t version = 0;
	os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: Creating handle with UUID: %s\n", uuid_string);

	ext_paniclog_handle_t *handle = ext_paniclog_handle_alloc_with_uuid(uuid, data_id, 1024, EXT_PANICLOG_OPTIONS_NONE);
	if (handle == NULL) {
		os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: Handle is NULL\n");
		return -1;
	}

	ext_paniclog_insert_data(handle, data1, 16);

	os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: Used len of buffer: %d\n", handle->used_len);
	os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: Data in buffer: %s\n", (char *)ext_paniclog_get_buffer(handle));

	ext_paniclog_handle_set_active(handle);

	bytes_copied = ext_paniclog_write_panicdata();

	os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: Bytes copied: %d\n", bytes_copied);

	buf_ptr = (debug_buf_base + debug_buf_size) - bytes_copied;
#if 0
	os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: *****************************************");
	for (int i = 0; i < 100; i++) {
		os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: %u ", panic_data[i]);
	}
	os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: *****************************************");
#endif

	memcpy(&version, buf_ptr, 4);
	if (version != EXT_PANICLOG_VERSION) {
		os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: Version mismatch: %d\n", version);
		ext_paniclog_handle_free(handle);
		return -1;
	}

	buf_ptr += 4;

	memcpy(&num_of_logs, buf_ptr, 4);

	if (num_of_logs != 1) {
		os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: Num logs is not equal: %d\n", num_of_logs);
		ext_paniclog_handle_free(handle);
		return -1;
	}

	buf_ptr += 4;

	char *uuid_cmp = (char *)(buf_ptr);

	if (memcmp(uuid_cmp, uuid, 16)) {
		os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: UUID is not equal\n");
		ext_paniclog_handle_free(handle);
		return -1;
	}

	buf_ptr += 16;

	size_t data_id_len = strnlen(data_id, MAX_DATA_ID_SIZE);

	if (strncmp(data_id, buf_ptr, data_id_len)) {
		os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: data id is not equal: %s\n", panic_data + 20);
		ext_paniclog_handle_free(handle);
		return -1;
	}

	buf_ptr += data_id_len + 1;
	memcpy(&data_len, buf_ptr, 4);

	if (data_len != 16) {
		os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: data len is not equal: %d\n", data_len);
		ext_paniclog_handle_free(handle);
		return -1;
	}

	buf_ptr += 4;
	char *data_cmp = (char *)(buf_ptr);

	if (memcmp(data_cmp, data1, data_len)) {
		os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: Buffers don't match\n");
		ext_paniclog_handle_free(handle);
		return -1;
	}

	ext_paniclog_handle_free(handle);

	return 0;
}

/*
 * Test 1: EXT_PANICLOG_TEST_HANDLE_CREATE
 */
static int
ext_paniclog_handle_create_test(void)
{
	uint32_t max_len = 1024;
	uuid_t uuid;
	uuid_generate(uuid);
	uuid_string_t uuid_string;
	uuid_unparse(uuid, uuid_string);
	os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: Creating handle with UUID: %s\n", uuid_string);

	ext_paniclog_handle_t *handle = ext_paniclog_handle_alloc_with_uuid(uuid, "Test Handle", max_len, EXT_PANICLOG_OPTIONS_NONE);
	if (handle == NULL) {
		os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: Handle create failed. Returned NULL\n");
		return -1;
	}

	if ((strncmp(handle->data_id, "Test Handle", strlen(handle->data_id))) ||
	    (handle->max_len != 1024)) {
		os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: attribute mismatch\n");
		ext_paniclog_handle_free(handle);
		return -1;
	}

	ext_paniclog_handle_free(handle);

	return 0;
}

static int
ext_paniclog_get_list_count(void)
{
	int cnt = 0;
	ext_paniclog_handle_t *tmp;

	lck_mtx_lock(&ext_paniclog_list_lock);

	LIST_FOREACH(tmp, &ext_paniclog_handle_list, handles) {
		if (tmp != NULL) {
			cnt++;
		}
	}

	lck_mtx_unlock(&ext_paniclog_list_lock);

	return cnt;
}

/*
 * Test 2: EXT_PANICLOG_TEST_SET_ACTIVE_INACTIVE
 */
static int
ext_paniclog_set_active_inactive_test(void)
{
	uuid_t uuid;
	uuid_generate(uuid);
	uuid_string_t uuid_string;
	uuid_unparse(uuid, uuid_string);
	os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: Creating handle with UUID: %s\n", uuid_string);

	ext_paniclog_handle_t *handle = ext_paniclog_handle_alloc_with_uuid(uuid, "Test handle", 1024, EXT_PANICLOG_OPTIONS_NONE);

	int cnt = 0;
	int initial_cnt = ext_paniclog_get_list_count();

	os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: Initial list count: %d\n", initial_cnt);

	ext_paniclog_handle_set_active(handle);

	cnt = ext_paniclog_get_list_count();

	os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: List count after active: %d\n", cnt);

	if (cnt != (initial_cnt + 1)) {
		os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: List count error after active\n");
		ext_paniclog_handle_free(handle);
		return -1;
	}

	ext_paniclog_handle_set_inactive(handle);

	cnt = ext_paniclog_get_list_count();

	os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: List count after inactive: %d\n", cnt);

	if (cnt != initial_cnt) {
		os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: List count error after inactive\n");
		ext_paniclog_handle_free(handle);
		return -1;
	}

	ext_paniclog_handle_free(handle);

	return 0;
}

/*
 * Test 3: EXT_PANICLOG_TEST_INSERT_DATA
 */
static int
ext_paniclog_insert_data_test(void)
{
	uuid_t uuid;
	uuid_generate(uuid);
	uuid_string_t uuid_string;
	uuid_unparse(uuid, uuid_string);
	os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: Creating handle with UUID: %s\n", uuid_string);

	ext_paniclog_handle_t *handle = ext_paniclog_handle_alloc_with_uuid(uuid, "Test handle", 1024, EXT_PANICLOG_OPTIONS_NONE);

	char data1[9] = "abcdefgh";

	ext_paniclog_insert_data(handle, data1, 8);

	if (memcmp(handle->buf_addr, data1, 8)) {
		os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: Buffers don't match\n");
		ext_paniclog_handle_free(handle);
		return -1;
	}

	char data2[9] = "abcdefgh";
	char cmp_data[17] = "abcdefghabcdefgh";

	ext_paniclog_append_data(handle, data2, 8);

	if (memcmp(handle->buf_addr, cmp_data, 16)) {
		os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: Buffers don't match\n");
		ext_paniclog_handle_free(handle);
		return -1;
	}

	os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: Used len of buffer: %d\n", handle->used_len);
	os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: Data in buffer: %s\n", (char *)ext_paniclog_get_buffer(handle));

	ext_paniclog_handle_free(handle);

	return 0;
}

/* Test 7 */
static int
ext_paniclog_insert_dummy_handles_test(void)
{
	ext_paniclog_handle_t *handle_1, *handle_2, *handle_3;
	char data1[18] = "Data for handle 1";
	char data2[18] = "Data for handle 2";
	char data3[18] = "Data for handle 3";

	char uuid_string_1[] = "28245A8F-04CA-4932-8A38-E6C159FD9C92";
	uuid_t uuid_1;
	uuid_parse(uuid_string_1, uuid_1);
	handle_1 = ext_paniclog_handle_alloc_with_uuid(uuid_1, "Dummy handle 1", 1024, EXT_PANICLOG_OPTIONS_NONE);
	if (handle_1 == NULL) {
		os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: Failed to create handle 1\n");
		return -1;
	}

	handle_2 = ext_paniclog_handle_alloc_with_uuid(uuid_1, "Dummy handle 2", 1024, EXT_PANICLOG_OPTIONS_NONE);
	if (handle_2 == NULL) {
		os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: Failed to create handle 2\n");
		return -1;
	}

	char uuid_string_3[] = "A10F32F8-D5AF-431F-8098-FEDD0FFB794A";
	uuid_t uuid_3;
	uuid_parse(uuid_string_3, uuid_3);

	handle_3 = ext_paniclog_handle_alloc_with_uuid(uuid_3, "Dummy handle 3", 1024, EXT_PANICLOG_OPTIONS_NONE);
	if (handle_3 == NULL) {
		os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: Failed to create handle 3\n");
		return -1;
	}

	os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: Created three handles\n");

	ext_paniclog_insert_data(handle_1, data1, 17);
	ext_paniclog_insert_data(handle_2, data2, 17);
	ext_paniclog_insert_data(handle_3, data3, 17);

	ext_paniclog_handle_set_active(handle_1);
	ext_paniclog_handle_set_active(handle_2);
	ext_paniclog_handle_set_active(handle_3);

	os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: Inserted three handles\n");

	return 0;
}

/* Test 8 */
static int
ext_paniclog_insert_struct_handles_test(void)
{
	ext_paniclog_handle_t *handle_1, *handle_2;
	struct _handle_1_data {
		uint32_t dummy_1;
		uint32_t dummy_2;
		uint32_t dummy_3;
	};

	struct _handle_2_data {
		uint32_t dummy_1;
		uint32_t dummy_2;
	};

	struct _handle_1_data *handle_1_data;
	struct _handle_2_data *handle_2_data;

	char uuid_string_1[] = "938371FB-3B47-415E-B766-743DE6D44E6E";
	uuid_t uuid_1;
	uuid_parse(uuid_string_1, uuid_1);
	handle_1 = ext_paniclog_handle_alloc_with_uuid(uuid_1, "Dummy handle 1", 1024, EXT_PANICLOG_OPTIONS_NONE);
	if (handle_1 == NULL) {
		os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: Failed to create handle 1\n");
		return -1;
	}

	char uuid_string_2[] = "78FD5A06-1FA3-4B1C-A2F5-AF82F5D9CEFD";
	uuid_t uuid_2;
	uuid_parse(uuid_string_2, uuid_2);

	handle_2 = ext_paniclog_handle_alloc_with_uuid(uuid_2, "Dummy handle 2", 1024, EXT_PANICLOG_OPTIONS_NONE);
	if (handle_2 == NULL) {
		os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: Failed to create handle 3\n");
		return -1;
	}

	os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: Created two handles\n");

	handle_1_data = (struct _handle_1_data *)ext_paniclog_claim_buffer(handle_1);

	handle_2_data = (struct _handle_2_data *)ext_paniclog_claim_buffer(handle_2);

	handle_1_data->dummy_1 = 0x1000;
	handle_1_data->dummy_2 = 0xFFFFFFFF;
	handle_1_data->dummy_3 = 0x65;

	handle_2_data->dummy_1 = 0x10000000;
	handle_2_data->dummy_2 = 0xFFFF;

	ext_paniclog_yield_buffer(handle_1, sizeof(struct _handle_1_data));
	ext_paniclog_yield_buffer(handle_2, sizeof(struct _handle_2_data));

	ext_paniclog_handle_set_active(handle_1);
	ext_paniclog_handle_set_active(handle_2);

	os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: Wrote two handles\n");

	return 0;
}

int
ext_paniclog_test_hook(uint32_t option)
{
	int rval = 0;

	switch (option) {
	case EXT_PANICLOG_TEST_HANDLE_CREATE:
		os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: Create handle test\n");
		rval = ext_paniclog_handle_create_test();
		break;
	case EXT_PANICLOG_TEST_SET_ACTIVE_INACTIVE:
		os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: Testing set active and inactive\n");
		rval = ext_paniclog_set_active_inactive_test();
		break;
	case EXT_PANICLOG_TEST_INSERT_DATA:
		os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: Testing insert data\n");
		rval = ext_paniclog_insert_data_test();
		break;
	case EXT_PANICLOG_TEST_WRITE_PANIC_DATA:
		os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: Testing panic data write\n");
		rval = ext_paniclog_write_panicdata_test();
		break;
	case EXT_PANICLOG_TEST_MULTIPLE_HANDLES:
		os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: Testing multiple handles\n");
		rval = ext_paniclog_multiple_handles_test();
		break;
	case EXT_PANICLOG_TEST_MULTIPLE_HANDLES_PANIC:
		os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: Testing multiple handles with panic\n");
		rval = ext_paniclog_multiple_handles_panic_test();
		break;
	case EXT_PANICLOG_TEST_INSERT_DUMMY_HANDLES:
		os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: Insert dummy handles\n");
		rval = ext_paniclog_insert_dummy_handles_test();
		break;
	case EXT_PANICLOG_TEST_INSERT_STRUCT_HANDLES:
		os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: Insert struct handles\n");
		rval = ext_paniclog_insert_struct_handles_test();
		break;
	default:
		os_log(OS_LOG_DEFAULT, "Not a valid option\n");
		break;
	}

	os_log(OS_LOG_DEFAULT, "EXT_PANICLOG_TEST: Test exit: %d\n", rval);
	return rval;
}
#endif // DEVELOPEMNT || DEBUG

#else // CONFIG_EXT_PANICLOG

/*
 * All ext paniclog functions which fail when CONFIG_EXT_PANICLOG is not
 * enabled.
 */

void
ext_paniclog_init(void)
{
	os_log_error(OS_LOG_DEFAULT, "Extensible paniclog not supported");
	return;
}

ext_paniclog_handle_t *
ext_paniclog_handle_alloc_with_uuid(uuid_t uuid __unused, const char *data_id __unused,
    uint32_t max_len __unused, ext_paniclog_create_options_t options __unused)
{
	os_log_error(OS_LOG_DEFAULT, "Extensible paniclog not supported");
	return NULL;
}

ext_paniclog_handle_t *
ext_paniclog_handle_alloc_with_buffer(uuid_t uuid __unused, const char *data_id __unused,
    uint32_t max_len __unused, void * buff __unused, ext_paniclog_create_options_t options __unused)
{
	os_log_error(OS_LOG_DEFAULT, "Extensible paniclog not supported");
	return NULL;
}

void
ext_paniclog_handle_free(ext_paniclog_handle_t *handle __unused)
{
	os_log_error(OS_LOG_DEFAULT, "Extensible paniclog not supported");
	return;
}

int
ext_paniclog_handle_set_active(ext_paniclog_handle_t *handle __unused)
{
	os_log_error(OS_LOG_DEFAULT, "Extensible paniclog not supported");
	return -1;
}

int
ext_paniclog_handle_set_inactive(ext_paniclog_handle_t *handle __unused)
{
	os_log_error(OS_LOG_DEFAULT, "Extensible paniclog not supported");
	return -1;
}

int
ext_paniclog_insert_data(ext_paniclog_handle_t *handle __unused, void *addr __unused, uint32_t len __unused)
{
	os_log_error(OS_LOG_DEFAULT, "Extensible paniclog not supported");
	return -1;
}

int
ext_paniclog_append_data(ext_paniclog_handle_t *handle __unused, void *addr __unused, uint32_t len __unused)
{
	os_log_error(OS_LOG_DEFAULT, "Extensible paniclog not supported");
	return -1;
}

void *
ext_paniclog_claim_buffer(ext_paniclog_handle_t *handle __unused)
{
	os_log_error(OS_LOG_DEFAULT, "Extensible paniclog not supported");
	return NULL;
}

void *
ext_paniclog_get_buffer(ext_paniclog_handle_t *handle __unused)
{
	os_log_error(OS_LOG_DEFAULT, "Extensible paniclog not supported");
	return NULL;
}

int
ext_paniclog_set_used_len(ext_paniclog_handle_t *handle __unused, uint32_t used_len __unused)
{
	os_log_error(OS_LOG_DEFAULT, "Extensible paniclog not supported");
	return -1;
}

int
ext_paniclog_yield_buffer(ext_paniclog_handle_t *handle __unused, uint32_t used_len __unused)
{
	os_log_error(OS_LOG_DEFAULT, "Extensible paniclog not supported");
	return -1;
}

void
ext_paniclog_panic_with_data(uuid_t uuid __unused, void *addr __unused, uint32_t len __unused)
{
	os_log_error(OS_LOG_DEFAULT, "Extensible paniclog not supported");
	return;
}

bool
is_debug_ptr_in_ext_paniclog(void)
{
	return false;
}

uint32_t
ext_paniclog_write_panicdata(void)
{
	os_log_error(OS_LOG_DEFAULT, "Extensible paniclog not supported");
	return 0;
}
#endif // CONFIG_EXT_PANICLOG
