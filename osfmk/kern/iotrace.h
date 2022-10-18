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

#if CONFIG_IOTRACE

#pragma once

#include <kern/percpu.h>
#include <libkern/OSDebug.h>
#include <stdint.h>

#define MAX_IOTRACE_BTFRAMES (16)

typedef enum {
	IOTRACE_PHYS_READ = 1,
	IOTRACE_PHYS_WRITE,
	IOTRACE_IO_READ,
	IOTRACE_IO_WRITE,
	IOTRACE_PORTIO_READ,
	IOTRACE_PORTIO_WRITE
} iotrace_type_e;

typedef struct {
	iotrace_type_e  iotype;
	int             size;
	uint64_t        vaddr;
	uint64_t        paddr;
	uint64_t        val;
	uint64_t        start_time_abs;
	uint64_t        duration;
	void           *backtrace[MAX_IOTRACE_BTFRAMES];
} iotrace_entry_t;

extern volatile int mmiotrace_enabled;
extern uint32_t iotrace_entries_per_cpu;

PERCPU_DECL(uint32_t, iotrace_next);
PERCPU_DECL(iotrace_entry_t * __unsafe_indexable, iotrace_ring);

static inline void
iotrace(iotrace_type_e type, uint64_t vaddr, uint64_t paddr, int size, uint64_t val,
    uint64_t sabs, uint64_t duration)
{
	uint32_t nextidx;
	iotrace_entry_t *cur_iotrace_ring;
	uint32_t *nextidxp;

	if (__improbable(mmiotrace_enabled == 0 ||
	    iotrace_entries_per_cpu == 0)) {
		return;
	}

	nextidxp = PERCPU_GET(iotrace_next);
	nextidx = *nextidxp;
	cur_iotrace_ring = *PERCPU_GET(iotrace_ring);

	cur_iotrace_ring[nextidx].iotype = type;
	cur_iotrace_ring[nextidx].vaddr = vaddr;
	cur_iotrace_ring[nextidx].paddr = paddr;
	cur_iotrace_ring[nextidx].size = size;
	cur_iotrace_ring[nextidx].val = val;
	cur_iotrace_ring[nextidx].start_time_abs = sabs;
	cur_iotrace_ring[nextidx].duration = duration;

	*nextidxp = ((nextidx + 1) >= iotrace_entries_per_cpu) ? 0 : (nextidx + 1);

	(void) OSBacktrace(cur_iotrace_ring[nextidx].backtrace,
	    MAX_IOTRACE_BTFRAMES);
}

static inline void
iotrace_disable(void)
{
	mmiotrace_enabled = 0;
}

#else /* CONFIG_IOTRACE */

#define iotrace_disable()
#define iotrace(type, vaddr, paddr, size, val, sabs, duration)

#endif /* CONFIG_IOTRACE */
