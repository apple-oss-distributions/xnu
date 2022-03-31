/*
 * Copyright (c) 2000-2020 Apple Inc. All rights reserved.
 *
 * @Apple_LICENSE_HEADER_START@
 *
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 *
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#include <sys/kdebug_private.h>
#include <sys/param.h>
#include <kern/assert.h>
#include <mach/clock_types.h>
#include <mach/mach_types.h>
#include <sys/mcache.h>
#include <vm/vm_kern.h>
#include <kern/cpu_number.h>
#include <kern/cpu_data.h>
#include <mach/mach_time.h>
#include <kern/clock.h>
#include <kern/thread.h>
#include <sys/systm.h>
#include <machine/machine_routines.h>
#include <kperf/kperf.h>
#include <mach/mach_host.h>             /* for host_info() */

#if defined(__i386__) || defined(__x86_64__)
#include <i386/rtclock_protos.h>
#include <i386/mp.h>
#include <i386/machine_routines.h>
#include <i386/tsc.h>
#endif


#ifndef BSD_SYS_KDEBUG_COMMON_H
#define BSD_SYS_KDEBUG_COMMON_H

#define TRIAGE_EVENTS_PER_STORAGE_UNIT        128
#define TRIAGE_MIN_STORAGE_UNITS_PER_CPU      1

#define TRACE_EVENTS_PER_STORAGE_UNIT         2048
#define TRACE_MIN_STORAGE_UNITS_PER_CPU       4

#define SLOW_NOLOG  0x01
#define SLOW_CHECKS 0x02

extern lck_grp_t kdebug_lck_grp;

struct kd_buf;
union kds_ptr {
	struct {
		uint32_t buffer_index:21;
		uint16_t offset:11;
	};
	uint32_t raw;
};

/*
 * Ensure that both LP32 and LP64 variants of arm64 use the same kd_buf
 * structure.
 */
#if defined(__arm64__)
typedef uint64_t kd_buf_argtype;
#else
typedef uintptr_t kd_buf_argtype;
#endif

struct kd_storage {
	union   kds_ptr kds_next;
	uint32_t kds_bufindx;
	uint32_t kds_bufcnt;
	uint32_t kds_readlast;
	uint32_t kds_lostevents:1,
	    kds_mode:1,
	    unused:30;
	uint64_t  kds_timestamp;

	kd_buf  kds_records[TRACE_EVENTS_PER_STORAGE_UNIT];
};

#define MAX_BUFFER_SIZE            (1024 * 1024 * 128)
#define N_STORAGE_UNITS_PER_BUFFER (MAX_BUFFER_SIZE / sizeof(struct kd_storage))
static_assert(N_STORAGE_UNITS_PER_BUFFER <= 0x7ff,
    "shoudn't overflow kds_ptr.offset");

struct kd_storage_buffers {
	struct  kd_storage      *kdsb_addr;
	uint32_t                kdsb_size;
};

#define KDS_PTR_NULL 0xffffffff

struct kd_bufinfo {
	union  kds_ptr kd_list_head;
	union  kds_ptr kd_list_tail;
	bool kd_lostevents;
	uint32_t _pad;
	uint64_t kd_prev_timebase;
	uint32_t num_bufs;
	bool continuous_timestamps;
} __attribute__((aligned(MAX_CPU_CACHE_LINE_SIZE))) __attribute__((packed));


struct kd_iop;
struct kd_ctrl_page_t {
	union kds_ptr kds_free_list;
	uint32_t enabled:1,
	    mode:3,
	    _pad0:28;
	int      kds_inuse_count;
	uint32_t kdebug_events_per_storage_unit;
	uint32_t kdebug_min_storage_units_per_cpu;
	uint32_t kdebug_kdcopybuf_count;
	uint32_t kdebug_kdcopybuf_size;
	uint32_t kdebug_cpus;
	uint32_t kdebug_flags;
	uint32_t kdebug_slowcheck;
	uint64_t oldest_time;

	lck_spin_t  kds_spin_lock;

	/*
	 * The number of kd_bufinfo structs allocated may not match the current
	 * number of active cpus. We capture the iops list head at initialization
	 * which we could use to calculate the number of cpus we allocated data for,
	 * unless it happens to be null. To avoid that case, we explicitly also
	 * capture a cpu count.
	 */
	struct kd_iop* kdebug_iops;

	kd_event_matcher disable_event_match;
	kd_event_matcher disable_event_mask;
};

struct kd_data_page_t {
	int nkdbufs;
	int n_storage_units;
	int n_storage_threshold;
	uint32_t n_storage_buffer;
	struct kd_bufinfo *kdbip;
	struct kd_storage_buffers *kd_bufs;
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

#define POINTER_FROM_KDS_PTR(kd_bufs, x) (&kd_bufs[x.buffer_index].kdsb_addr[x.offset])

extern bool kdbg_continuous_time;
extern int kdbg_debug;

uint32_t kdbg_cpu_count(bool);

void kdebug_lck_init(void);
int kdebug_storage_lock(struct kd_ctrl_page_t *kd_ctrl_page);
void kdebug_storage_unlock(struct kd_ctrl_page_t *kd_ctrl_page, int intrs_en);

void
enable_wrap(struct kd_ctrl_page_t *kd_ctrl_page, uint32_t old_slowcheck);

bool
disable_wrap(struct kd_ctrl_page_t *kd_ctrl_page, uint32_t *old_slowcheck, uint32_t *old_flags);

int
create_buffers(struct kd_ctrl_page_t *kd_ctrl_page, struct kd_data_page_t *kd_data_page, vm_tag_t tag);

void
delete_buffers(struct kd_ctrl_page_t *kd_ctrl_page, struct kd_data_page_t *kd_data_page);

bool
allocate_storage_unit(struct kd_ctrl_page_t *kd_ctrl_page, struct kd_data_page_t *kd_data_page, int cpu);

void
release_storage_unit(struct kd_ctrl_page_t *kd_ctrl_page, struct kd_data_page_t *kd_data_page, int cpu, uint32_t kdsp_raw);

void
kernel_debug_write(struct kd_ctrl_page_t *kd_ctrl_page,
    struct kd_data_page_t *kd_data_page,
    struct kd_record kd_rec);

int
kernel_debug_read(struct kd_ctrl_page_t *kd_ctrl_page, struct kd_data_page_t *kd_data_page, user_addr_t buffer,
    size_t *number, vnode_t vp, vfs_context_t ctx, uint32_t file_version);


extern int     RAW_file_written;
#define RAW_FLUSH_SIZE  (2 * 1024 * 1024)

void commpage_update_kdebug_state(void); /* XXX sign */

#endif /* BSD_SYS_KDEBUG_COMMON_H */
