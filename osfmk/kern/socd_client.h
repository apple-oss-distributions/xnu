/*
 * Copyright (c) 2021 Apple Inc. All rights reserved.
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

/* socd_client.h: machine-independent API for interfacing with soc diagnostics data pipeline.
 * NOTE: this file is included by socd parser and should not declare any symbols nor
 * include kernel specific headers. Use socd_client_kern.h for kernel specifics.
 */

#ifndef _KERN_SOCD_CLIENT_H_
#define _KERN_SOCD_CLIENT_H_

#include <stdint.h>
#include <sys/cdefs.h>
#include <uuid/uuid.h>
#include <sys/kdebug.h>

__BEGIN_DECLS

/* socd trace event id format within kdebug code */
#define SOCD_TRACE_CLASS_MASK   (0x3c00)
#define SOCD_TRACE_CLASS_SMASK  (0xf)
#define SOCD_TRACE_CLASS_OFFSET (10)
#define SOCD_TRACE_CODE_MASK    (0x3ff)
#define SOCD_TRACE_CODE_SMASK   (SOCD_TRACE_CODE_MASK)
#define SOCD_TRACE_CODE_OFFSET  (0)

#define SOCD_TRACE_EXTRACT_EVENTID(debugid) (KDBG_EXTRACT_CODE(debugid))
#define SOCD_TRACE_EXTRACT_CLASS(debugid) ((SOCD_TRACE_EXTRACT_EVENTID(debugid) & SOCD_TRACE_CLASS_MASK) >> SOCD_TRACE_CLASS_OFFSET)
#define SOCD_TRACE_EXTRACT_CODE(debugid) ((SOCD_TRACE_EXTRACT_EVENTID(debugid) & SOCD_TRACE_CODE_MASK) >> SOCD_TRACE_CODE_OFFSET)

/* Generate an eventid corresponding to Class, Code. */
#define SOCD_TRACE_EVENTID(class, code) \
	(((unsigned)((class)  &  SOCD_TRACE_CLASS_SMASK) << SOCD_TRACE_CLASS_OFFSET) | \
	 ((unsigned)((code)   &  SOCD_TRACE_CODE_SMASK) << SOCD_TRACE_CODE_OFFSET))

/* SOCD_TRACE_GEN_STR is used by socd parser to symbolicate trace classes & codes */
#define SOCD_TRACE_GEN_STR(entry) #entry,
#define SOCD_TRACE_GEN_CLASS_ENUM(entry) SOCD_TRACE_CLASS_##entry,
#define SOCD_TRACE_GEN_CODE_ENUM(entry) SOCD_TRACE_CODE_##entry,

/* List of socd trace classes */
#define SOCD_TRACE_FOR_EACH_CLASS(iter) \
	iter(XNU) \
	iter(WDT)

/* List of xnu trace codes */
#define SOCD_TRACE_FOR_EACH_XNU_CODE(iter) \
	iter(XNU_PANIC) \
	iter(XNU_START_IOKIT) \
	iter(XNU_PLATFORM_ACTION) \
	iter(XNU_PM_SET_POWER_STATE) \
	iter(XNU_PM_INFORM_POWER_CHANGE) \
	iter(XNU_STACKSHOT) \
	iter(XNU_PM_SET_POWER_STATE_ACK) \
	iter(XNU_PM_INFORM_POWER_CHANGE_ACK) \
	iter(XNU_KERNEL_STATE_PANIC)

typedef enum {
	SOCD_TRACE_FOR_EACH_CLASS(SOCD_TRACE_GEN_CLASS_ENUM)
	SOCD_TRACE_CLASS_MAX
} socd_client_trace_class_t;

typedef enum {
	SOCD_TRACE_FOR_EACH_XNU_CODE(SOCD_TRACE_GEN_CODE_ENUM)
	SOCD_TRACE_CODE_XNU_MAX
} socd_client_trace_code_xnu_t;

/* *
 * Records socd client header information. Also used to determine
 * proper offset when appending trace data to SoCD report.
 *
 * SoCD Trace Layout in memory:
 *  socd_push_header_t:
 *     (5 bytes) socd_generic_header_t
 *     (3 bytes) --padding for alignment--
 *     (4 bytes) socd_desc_t (size of overall region, number of records that are supported === 1)
 *  socd_push_record_t:
 *     (1 byte) agent ID
 *     (1 byte) version
 *     (2 bytes) offset into buff for start of record in 32-bit words
 *     (2 bytes) size (same accounting)
 *     (2 bytes) --padding for alignement--
 *  socd_client_hdr_t: <--- header reports offset 0x14 here
 *     (4 bytes) version
 *     (8 bytes) boot time
 *     (16 bytes) kernel uuid
 *     (16 bytes) primary KC uuid
 *  socd_client_trace_entry_t:
 *     (8 bytes) timestamp
 *     (4 bytes) debugid
 *     (8 bytes) arg1
 *     (8 bytes) arg2
 *     (8 bytes) arg3
 *     (8 bytes) arg4
 *  <repeating trace records here, each is 44 bytes)
 *
 * Trace report will store as many entries as possible within the
 * allotted space.
 */
typedef struct {
	uint32_t version;
	uint64_t boot_time;
	uuid_t kernel_uuid;
	uuid_t primary_kernelcache_uuid;
} __attribute__((packed)) socd_client_hdr_t;

typedef uint64_t socd_client_trace_arg_t;

typedef struct {
	uint64_t timestamp;
	uint32_t debugid;
	socd_client_trace_arg_t arg1;
	socd_client_trace_arg_t arg2;
	socd_client_trace_arg_t arg3;
	socd_client_trace_arg_t arg4;
} __attribute ((packed)) socd_client_trace_entry_t;

__END_DECLS

#ifdef KERNEL
#include <kern/socd_client_kern.h>
#endif /* defined(KERNEL) */

#endif /* !defined(_KERN_SOCD_CLIENT_H_) */
