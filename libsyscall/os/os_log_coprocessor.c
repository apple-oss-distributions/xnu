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

#include <sys/os_log_coprocessor.h>
#include <strings.h>

extern int
__oslog_coproc(void *buff, uint64_t buff_len, uint32_t type, const char *uuid, uint64_t timestamp, uint32_t offset, uint32_t stream_log);

extern int
__oslog_coproc_reg(const char *uuid, const char *file_path, size_t file_path_len);

int
os_log_coprocessor_as_kernel(void *buff, uint64_t buff_len, os_log_type_t type, const char *uuid, uint64_t timestamp, uint32_t offset, bool stream_log)
{
	return __oslog_coproc(buff, buff_len, type, uuid, timestamp, offset, stream_log);
}

int
os_log_coprocessor_register_as_kernel(const char *uuid, const char *file_path, size_t file_path_len)
{
	return __oslog_coproc_reg(uuid, file_path, file_path_len);
}
