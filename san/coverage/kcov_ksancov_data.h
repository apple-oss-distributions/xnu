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
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
#ifndef _KCOV_KSANCOV_DATA_H_
#define _KCOV_KSANCOV_DATA_H_

#if KERNEL_PRIVATE

#if CONFIG_KSANCOV

/*
 * On arm64 the VM_MIN_KERNEL_ADDRESS is too far from %pc to fit into 32-bit value. As a result
 * ksancov reports invalid %pcs. To make at least kernel %pc values corect a different base has
 * to be used for arm.
 */
#if defined(__x86_64__) || defined(__i386__)
#define KSANCOV_PC_OFFSET VM_MIN_KERNEL_ADDRESS
#elif defined(__arm64__)
#define KSANCOV_PC_OFFSET VM_KERNEL_LINK_ADDRESS
#else
#error "Unsupported platform"
#endif


/*
 * Supported coverage modes.
 */
typedef enum {
	KS_MODE_NONE,
	KS_MODE_TRACE,
	KS_MODE_COUNTERS,
	KS_MODE_STKSIZE,
	KS_MODE_MAX
} ksancov_mode_t;

/*
 * A header that is always present in every ksancov mode shared memory structure.
 */
typedef struct ksancov_header {
	uint32_t         kh_magic;
	_Atomic uint32_t kh_enabled;
} ksancov_header_t;

/*
 * TRACE mode data structure.
 */

/*
 * All trace based tools share this structure.
 */
typedef struct ksancov_trace {
	ksancov_header_t kt_hdr;         /* header (must be always first) */
	uintptr_t        kt_offset;      /* All recorded PCs are relateive to this offset. */
	uint32_t         kt_maxent;      /* Maximum entries in this shared buffer. */
	_Atomic uint32_t kt_head;        /* Pointer to the first unused element. */
	uint64_t         kt_entries[];   /* Trace entries in this buffer. */
} ksancov_trace_t;


/* PC tracing only records PC deltas from the offset. */
typedef uint32_t ksancov_trace_pc_ent_t;

/* STKSIZE tracing records PC deltas and stack size. */
typedef struct ksancov_trace_stksize_entry {
	uint32_t pc;                      /* PC-delta (offset relative) */
	uint32_t stksize;                 /* associated stack size */
} ksancov_trace_stksize_ent_t;

/*
 * COUNTERS mode data structure.
 */
typedef struct ksancov_counters {
	ksancov_header_t kc_hdr;
	uint32_t         kc_nedges;       /* total number of edges */
	uint8_t          kc_hits[];       /* hits on each edge (8bit saturating) */
} ksancov_counters_t;

/*
 * Edge to PC mapping.
 */
typedef struct ksancov_edgemap {
	uint32_t  ke_magic;
	uint32_t  ke_nedges;
	uintptr_t ke_offset;              /* edge addrs relative to this */
	uint32_t  ke_addrs[];             /* address of each edge relative to 'offset' */
} ksancov_edgemap_t;

/*
 * Represents state of a ksancov device when userspace asks for coverage data recording.
 */

struct ksancov_dev {
	ksancov_mode_t mode;

	union {
		ksancov_header_t       *hdr;
		ksancov_trace_t        *trace;
		ksancov_counters_t     *counters;
	};
	size_t sz;     /* size of allocated trace/counters buffer */

	size_t maxpcs;

	thread_t thread;
	dev_t dev;
	lck_mtx_t lock;
};
typedef struct ksancov_dev * ksancov_dev_t;


#endif /* CONFIG_KSANCOV */

#endif /* KERNEL_PRIVATE */

#endif /* _KCOV_KSANCOV_DATA_H_ */
