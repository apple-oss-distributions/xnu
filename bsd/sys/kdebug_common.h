// Copyright (c) 2000-2021 Apple Inc. All rights reserved.
//
// @Apple_LICENSE_HEADER_START@
//
// The contents of this file constitute Original Code as defined in and
// are subject to the Apple Public Source License Version 1.1 (the
// "License").  You may not use this file except in compliance with the
// License.  Please obtain a copy of the License at
// http://www.apple.com/publicsource and read it before using this file.
//
// This Original Code and all software distributed under the License are
// distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
// EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
// INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
// License for the specific language governing rights and limitations
// under the License.
//
// @APPLE_OSREFERENCE_LICENSE_HEADER_END@

#ifndef BSD_SYS_KDEBUG_COMMON_H
#define BSD_SYS_KDEBUG_COMMON_H

#include <kern/assert.h>
#include <kern/clock.h>
#include <kern/cpu_data.h>
#include <kern/cpu_number.h>
#include <kern/thread.h>
#include <kperf/kperf.h>
#include <mach/clock_types.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_types.h>
#include <machine/machine_routines.h>
#include <sys/kdebug_private.h>
#include <sys/mcache.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <vm/vm_kern.h>

#if defined(__x86_64__)
#include <i386/machine_routines.h>
#include <i386/mp.h>
#include <i386/rtclock_protos.h>
#include <i386/tsc.h>
#endif // defined(__x86_64__)

#define TRIAGE_EVENTS_PER_STORAGE_UNIT   128
#define TRIAGE_MIN_STORAGE_UNITS_PER_CPU 1

#define TRACE_EVENTS_PER_STORAGE_UNIT   2048
#define TRACE_MIN_STORAGE_UNITS_PER_CPU 4

// How to filter events.
__enum_decl(kdebug_emit_filter_t, uint32_t, {
	KDEMIT_DISABLE,
	KDEMIT_ALL,
	KDEMIT_TYPEFILTER,
	KDEMIT_RANGE,
	KDEMIT_EXACT,
});

extern lck_grp_t kdebug_lck_grp;

union kds_ptr {
	struct {
		uint32_t buffer_index:21;
		uint16_t offset:11;
	};
	uint32_t raw;
};

struct kd_storage {
	union kds_ptr kds_next;
	uint32_t kds_bufindx;
	uint32_t kds_bufcnt;
	uint32_t kds_readlast;
	uint32_t kds_lostevents:1;
	uint32_t unused:31;
	uint64_t kds_timestamp;

	kd_buf kds_records[TRACE_EVENTS_PER_STORAGE_UNIT];
};

#define MAX_BUFFER_SIZE            (1024 * 1024 * 128)
#define N_STORAGE_UNITS_PER_BUFFER (MAX_BUFFER_SIZE / sizeof(struct kd_storage))
static_assert(N_STORAGE_UNITS_PER_BUFFER <= 0x7ff,
    "shoudn't overflow kds_ptr.offset");

struct kd_region {
	struct kd_storage *kdr_addr;
	uint32_t           kdr_size;
};

#define KDS_PTR_NULL 0xffffffff

struct kd_bufinfo {
	union  kds_ptr kd_list_head;
	union  kds_ptr kd_list_tail;
	bool kd_lostevents;
	uint32_t _pad;
	uint64_t kd_prev_timebase;
	uint32_t num_bufs;
	uint64_t latest_past_event_timestamp;
	bool continuous_timestamps;
} __attribute__((aligned(MAX_CPU_CACHE_LINE_SIZE))) __attribute__((packed));

struct kd_coproc;

struct kd_control {
	union kds_ptr kds_free_list;
	uint32_t enabled:1,
	    mode:3,
	    _pad0:28;
	uint32_t kdebug_events_per_storage_unit;
	uint32_t kdebug_min_storage_units_per_cpu;
	uint32_t kdebug_kdcopybuf_count;
	uint32_t kdebug_kdcopybuf_size;
	uint32_t kdebug_cpus;
	uint32_t alloc_cpus;
	uint32_t kdc_flags;
	kdebug_emit_filter_t kdc_emit;
	kdebug_live_flags_t kdc_live_flags;
	uint64_t kdc_oldest_time;
	int kdc_storage_used;

	lck_spin_t kdc_storage_lock;

	struct kd_coproc *kdc_coprocs;

	kd_event_matcher disable_event_match;
	kd_event_matcher disable_event_mask;
};

struct kd_buffer {
	int kdb_event_count;
	int kdb_storage_count;
	int kdb_storage_threshold;
	uint32_t kdb_region_count;
	struct kd_bufinfo *kdb_info;
	struct kd_region *kd_bufs;
	kd_buf *kdcopybuf;
};

struct kd_record {
	int32_t  cpu;
	uint32_t debugid;
	int64_t timestamp;
	kd_buf_argtype arg1;
	kd_buf_argtype arg2;
	kd_buf_argtype arg3;
	kd_buf_argtype arg4;
	kd_buf_argtype arg5;
} __attribute__((packed));

#define POINTER_FROM_KDS_PTR(kd_bufs, x) (&kd_bufs[x.buffer_index].kdr_addr[x.offset])

extern bool kdbg_continuous_time;
extern int kdbg_debug;

uint32_t kdbg_cpu_count(void);

void kdebug_lck_init(void);
int kdebug_storage_lock(struct kd_control *ctl);
void kdebug_storage_unlock(struct kd_control *ctl, int intrs_en);

/*
 * Disable wrapping and return true if trace wrapped, false otherwise.
 */
bool kdebug_disable_wrap(struct kd_control *ctl, kdebug_emit_filter_t *old_emit,
    kdebug_live_flags_t *old_live_flags);

int create_buffers_triage(void);

int create_buffers(struct kd_control *ctl, struct kd_buffer *buf, vm_tag_t tag);

void delete_buffers(struct kd_control *ctl, struct kd_buffer *buf);

void kernel_debug_write(struct kd_control *ctl, struct kd_buffer *buf,
    struct kd_record kd_rec);

int kernel_debug_read(struct kd_control *ctl, struct kd_buffer *buf,
    user_addr_t buffer, size_t *number, vnode_t vp, vfs_context_t ctx,
    uint32_t file_version);

extern int     RAW_file_written;
#define RAW_FLUSH_SIZE (2 * 1024 * 1024)

void commpage_update_kdebug_state(void);

#endif /* BSD_SYS_KDEBUG_COMMON_H */
