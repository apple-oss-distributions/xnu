/*
 * Copyright (c) 2021-2022 Apple Inc. All rights reserved.
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

#ifndef _SYS_PREOSLOG_H_
#define _SYS_PREOSLOG_H_

#include <sys/cdefs.h>

__BEGIN_DECLS

#define PREOSLOG_MAGIC 'LSOP'
#define PREOSLOG_SYSCTL "kern.preoslog"

typedef uint8_t preoslog_source_t;
enum {
	PREOSLOG_SOURCE_IBOOT = 0,
	PREOSLOG_SOURCE_MACEFI,
	PREOSLOG_SOURCE_MAX
};

/*
 * Any change to this structure must be reflected in boot loader (iboot / xnu SDK header) and vice versa.
 * Beware: if you remove __attribute__((packed)) here, then sizeof() on this structure will return 16.
 * However, with or without __attribute__((packed)), offset_of(preoslog_header_t, data) will always return 14.
 */

typedef struct  __attribute__((packed)) {
	uint32_t magic; /* PREOGLOS_MAGIC if valid */
	uint32_t size; /* Size of the preoslog buffer including the header */
	uint32_t offset; /* Write pointer. Indicates where in the buffer new log entry would go */
	preoslog_source_t source; /* Indicates who filled in the buffer (e.g. iboot vs MacEFI) */
	uint8_t wrapped; /* If equal to 1, the preoslog ring buffer wrapped at least once */
	char data[]; /* log buffer */
} preoslog_header_t;

__END_DECLS

#endif  /* !_SYS_PREOSLOG_H_ */
