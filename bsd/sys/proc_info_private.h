/*
 * Copyright (c) 2005-2021 Apple Inc. All rights reserved.
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

#ifndef _SYS_PROC_INFO_PRIVATE_H
#define _SYS_PROC_INFO_PRIVATE_H

#include <mach/coalition.h>
#include <mach/machine.h>
#include <stdint.h>
#include <sys/cdefs.h>
#include <sys/event_private.h>
#include <sys/proc_info.h>
#include <sys/types.h>
#include <uuid/uuid.h>

__BEGIN_DECLS


struct proc_uniqidentifierinfo {
	uint8_t                 p_uuid[16];             /* UUID of the main executable */
	uint64_t                p_uniqueid;             /* 64 bit unique identifier for process */
	uint64_t                p_puniqueid;            /* unique identifier for process's parent */
	int32_t                 p_idversion;            /* pid version */
	uint32_t                p_reserve2;             /* reserved for future use */
	uint64_t                p_reserve3;             /* reserved for future use */
	uint64_t                p_reserve4;             /* reserved for future use */
};


struct proc_bsdinfowithuniqid {
	struct proc_bsdinfo             pbsd;
	struct proc_uniqidentifierinfo  p_uniqidentifier;
};

struct proc_archinfo {
	cpu_type_t              p_cputype;
	cpu_subtype_t           p_cpusubtype;
};

struct proc_pidcoalitioninfo {
	uint64_t coalition_id[COALITION_NUM_TYPES];
	uint64_t reserved1;
	uint64_t reserved2;
	uint64_t reserved3;
};

struct proc_originatorinfo {
	uuid_t                  originator_uuid;        /* UUID of the originator process */
	pid_t                   originator_pid;         /* pid of the originator process */
	uint64_t                p_reserve2;
	uint64_t                p_reserve3;
	uint64_t                p_reserve4;
};

struct proc_ipctableinfo {
	uint32_t               table_size;
	uint32_t               table_free;
};

struct proc_threadschedinfo {
	uint64_t               int_time_ns;         /* time spent in interrupt context */
};

// See PROC_PIDTHREADCOUNTS for a description of how to use these structures.

struct proc_threadcounts_data {
	uint64_t ptcd_instructions;
	uint64_t ptcd_cycles;
	uint64_t ptcd_user_time_mach;
	uint64_t ptcd_system_time_mach;
	uint64_t ptcd_energy_nj;
};

struct proc_threadcounts {
	uint16_t ptc_len;
	uint16_t ptc_reserved0;
	uint32_t ptc_reserved1;
	struct proc_threadcounts_data ptc_counts[];
};


#define PROC_FLAG_DARWINBG      0x8000  /* process in darwin background */
#define PROC_FLAG_EXT_DARWINBG  0x10000 /* process in darwin background - external enforcement */
#define PROC_FLAG_IOS_APPLEDAEMON 0x20000       /* Process is apple daemon  */
#define PROC_FLAG_DELAYIDLESLEEP 0x40000        /* Process is marked to delay idle sleep on disk IO */
#define PROC_FLAG_IOS_IMPPROMOTION 0x80000      /* Process is daemon which receives importane donation  */
#define PROC_FLAG_ADAPTIVE              0x100000         /* Process is adaptive */
#define PROC_FLAG_ADAPTIVE_IMPORTANT    0x200000         /* Process is adaptive, and is currently important */
#define PROC_FLAG_IMPORTANCE_DONOR   0x400000 /* Process is marked as an importance donor */
#define PROC_FLAG_SUPPRESSED         0x800000 /* Process is suppressed */
#define PROC_FLAG_APPLICATION 0x1000000 /* Process is an application */
#define PROC_FLAG_IOS_APPLICATION PROC_FLAG_APPLICATION /* Process is an application */
#define PROC_FLAG_ROSETTA 0x2000000 /* Process is running translated under Rosetta */


/* keep in sync with KQ_* in sys/eventvar.h */
#define PROC_KQUEUE_WORKQ       0x0040
#define PROC_KQUEUE_WORKLOOP    0x0080

struct kevent_extinfo {
	struct kevent_qos_s kqext_kev;
	uint64_t kqext_sdata;
	int kqext_status;
	int kqext_sfflags;
	uint64_t kqext_reserved[2];
};

/* Flavors for proc_pidinfo() */
#define PROC_PIDUNIQIDENTIFIERINFO      17
#define PROC_PIDUNIQIDENTIFIERINFO_SIZE \
	                                (sizeof(struct proc_uniqidentifierinfo))

#define PROC_PIDT_BSDINFOWITHUNIQID     18
#define PROC_PIDT_BSDINFOWITHUNIQID_SIZE \
	                                (sizeof(struct proc_bsdinfowithuniqid))

#define PROC_PIDARCHINFO                19
#define PROC_PIDARCHINFO_SIZE           \
	                                (sizeof(struct proc_archinfo))

#define PROC_PIDCOALITIONINFO           20
#define PROC_PIDCOALITIONINFO_SIZE      (sizeof(struct proc_pidcoalitioninfo))

#define PROC_PIDNOTEEXIT                21
#define PROC_PIDNOTEEXIT_SIZE           (sizeof(uint32_t))

#define PROC_PIDREGIONPATHINFO2         22
#define PROC_PIDREGIONPATHINFO2_SIZE    (sizeof(struct proc_regionwithpathinfo))

#define PROC_PIDREGIONPATHINFO3         23
#define PROC_PIDREGIONPATHINFO3_SIZE    (sizeof(struct proc_regionwithpathinfo))

#define PROC_PIDEXITREASONINFO          24
#define PROC_PIDEXITREASONINFO_SIZE     (sizeof(struct proc_exitreasoninfo))

#define PROC_PIDEXITREASONBASICINFO     25
#define PROC_PIDEXITREASONBASICINFOSIZE (sizeof(struct proc_exitreasonbasicinfo))

#define PROC_PIDLISTUPTRS      26
#define PROC_PIDLISTUPTRS_SIZE (sizeof(uint64_t))

#define PROC_PIDLISTDYNKQUEUES      27
#define PROC_PIDLISTDYNKQUEUES_SIZE (sizeof(kqueue_id_t))

#define PROC_PIDLISTTHREADIDS           28
#define PROC_PIDLISTTHREADIDS_SIZE      (2* sizeof(uint32_t))

#define PROC_PIDVMRTFAULTINFO           29
#define PROC_PIDVMRTFAULTINFO_SIZE (7 * sizeof(uint64_t))

#define PROC_PIDPLATFORMINFO 30
#define PROC_PIDPLATFORMINFO_SIZE (sizeof(uint32_t))

#define PROC_PIDREGIONPATH              31
#define PROC_PIDREGIONPATH_SIZE         (sizeof(struct proc_regionpath))

#define PROC_PIDIPCTABLEINFO 32
#define PROC_PIDIPCTABLEINFO_SIZE (sizeof(struct proc_ipctableinfo))

#define PROC_PIDTHREADSCHEDINFO 33
#define PROC_PIDTHREADSCHEDINFO_SIZE (sizeof(struct proc_threadschedinfo))

// PROC_PIDTHREADCOUNTS returns a list of counters for the given thread,
// separated out by the "perf-level" it was running on (typically either
// "performance" or "efficiency").
//
// This interface works a bit differently from the other proc_info(3) flavors.
// It copies out a structure with a variable-length array at the end of it.
// The start of the `proc_threadcounts` structure contains a header indicating
// the length of the subsequent array of `proc_threadcounts_data` elements.
//
// To use this interface, first read the `hw.nperflevels` sysctl to find out how
// large to make the allocation that receives the counter data:
//
//     sizeof(proc_threadcounts) + nperflevels * sizeof(proc_threadcounts_data)
//
// Use the `hw.perflevel[0-9].name` sysctl to find out which perf-level maps to
// each entry in the array.
//
// The complete usage would be (omitting error reporting):
//
//     uint32_t len = 0;
//     int ret = sysctlbyname("hw.nperflevels", &len, &len_sz, NULL, 0);
//     size_t size = sizeof(struct proc_threadcounts) +
//             len * sizeof(struct proc_threadcounts_data);
//     struct proc_threadcounts *counts = malloc(size);
//     // Fill this in with a thread ID, like from `PROC_PIDLISTTHREADS`.
//     uint64_t tid = 0;
//     int size_copied = proc_info(getpid(), PROC_PIDTHREADCOUNTS, tid, counts,
//             size);

#define PROC_PIDTHREADCOUNTS 34
#define PROC_PIDTHREADCOUNTS_SIZE (sizeof(struct proc_threadcounts))

/* Flavors for proc_pidfdinfo */

#define PROC_PIDFDKQUEUE_EXTINFO        9
#define PROC_PIDFDKQUEUE_EXTINFO_SIZE   (sizeof(struct kevent_extinfo))
#define PROC_PIDFDKQUEUE_KNOTES_MAX     (1024 * 128)
#define PROC_PIDDYNKQUEUES_MAX  (1024 * 128)


/* Flavors for proc_pidoriginatorinfo */
#define PROC_PIDORIGINATOR_UUID         0x1
#define PROC_PIDORIGINATOR_UUID_SIZE    (sizeof(uuid_t))

#define PROC_PIDORIGINATOR_BGSTATE      0x2
#define PROC_PIDORIGINATOR_BGSTATE_SIZE (sizeof(uint32_t))

#define PROC_PIDORIGINATOR_PID_UUID     0x3
#define PROC_PIDORIGINATOR_PID_UUID_SIZE (sizeof(struct proc_originatorinfo))

/* Flavors for proc_listcoalitions */
#define LISTCOALITIONS_ALL_COALS        1
#define LISTCOALITIONS_ALL_COALS_SIZE   (sizeof(struct procinfo_coalinfo))

#define LISTCOALITIONS_SINGLE_TYPE      2
#define LISTCOALITIONS_SINGLE_TYPE_SIZE (sizeof(struct procinfo_coalinfo))

/* reasons for proc_can_use_foreground_hw */
#define PROC_FGHW_OK                     0 /* pid may use foreground HW */
#define PROC_FGHW_DAEMON_OK              1
#define PROC_FGHW_DAEMON_LEADER         10 /* pid is in a daemon coalition */
#define PROC_FGHW_LEADER_NONUI          11 /* coalition leader is in a non-focal state */
#define PROC_FGHW_LEADER_BACKGROUND     12 /* coalition leader is in a background state */
#define PROC_FGHW_DAEMON_NO_VOUCHER     13 /* pid is a daemon with no adopted voucher */
#define PROC_FGHW_NO_VOUCHER_ATTR       14 /* pid has adopted a voucher with no bank/originator attribute */
#define PROC_FGHW_NO_ORIGINATOR         15 /* pid has adopted a voucher for a process that's gone away */
#define PROC_FGHW_ORIGINATOR_BACKGROUND 16 /* pid has adopted a voucher for an app that's in the background */
#define PROC_FGHW_VOUCHER_ERROR         98 /* error in voucher / originator callout */
#define PROC_FGHW_ERROR                 99 /* syscall parameter/permissions error */

/* flavors for proc_piddynkqueueinfo */
#define PROC_PIDDYNKQUEUE_INFO         0
#define PROC_PIDDYNKQUEUE_INFO_SIZE    (sizeof(struct kqueue_dyninfo))
#define PROC_PIDDYNKQUEUE_EXTINFO      1
#define PROC_PIDDYNKQUEUE_EXTINFO_SIZE (sizeof(struct kevent_extinfo))

/* __proc_info() call numbers */
#define PROC_INFO_CALL_LISTPIDS          0x1
#define PROC_INFO_CALL_PIDINFO           0x2
#define PROC_INFO_CALL_PIDFDINFO         0x3
#define PROC_INFO_CALL_KERNMSGBUF        0x4
#define PROC_INFO_CALL_SETCONTROL        0x5
#define PROC_INFO_CALL_PIDFILEPORTINFO   0x6
#define PROC_INFO_CALL_TERMINATE         0x7
#define PROC_INFO_CALL_DIRTYCONTROL      0x8
#define PROC_INFO_CALL_PIDRUSAGE         0x9
#define PROC_INFO_CALL_PIDORIGINATORINFO 0xa
#define PROC_INFO_CALL_LISTCOALITIONS    0xb
#define PROC_INFO_CALL_CANUSEFGHW        0xc
#define PROC_INFO_CALL_PIDDYNKQUEUEINFO  0xd
#define PROC_INFO_CALL_UDATA_INFO        0xe
#define PROC_INFO_CALL_SET_DYLD_IMAGES   0xf
#define PROC_INFO_CALL_TERMINATE_RSR     0x10

/* __proc_info_extended_id() flags */
#define PIF_COMPARE_IDVERSION           0x01
#define PIF_COMPARE_UNIQUEID            0x02

#ifdef KERNEL_PRIVATE
extern int proc_fdlist(proc_t p, struct proc_fdinfo *buf, size_t *count);
extern int proc_pidoriginatorpid_uuid(uuid_t uuid, uint32_t buffersize, pid_t *pid);
#endif

#ifdef XNU_KERNEL_PRIVATE
#ifndef pshmnode
struct pshmnode;
#endif

#ifndef psemnode
struct psemnode;
#endif

#ifndef pipe
struct pipe;
#endif

extern int fill_socketinfo(socket_t so, struct socket_info *si);
extern int fill_pshminfo(struct pshmnode * pshm, struct pshm_info * pinfo);
extern int fill_pseminfo(struct psemnode * psem, struct psem_info * pinfo);
extern int fill_pipeinfo(struct pipe * cpipe, struct pipe_info * pinfo);
extern int fill_kqueueinfo(struct kqueue * kq, struct kqueue_info * kinfo);
extern int pid_kqueue_extinfo(proc_t, struct kqueue * kq, user_addr_t buffer,
    uint32_t buffersize, int32_t * retval);
extern int pid_kqueue_udatainfo(proc_t p, struct kqueue *kq, uint64_t *buf,
    uint32_t bufsize);
extern int pid_kqueue_listdynamickqueues(proc_t p, user_addr_t ubuf,
    uint32_t bufsize, int32_t *retval);
extern int pid_dynamickqueue_extinfo(proc_t p, kqueue_id_t kq_id,
    user_addr_t ubuf, uint32_t bufsize, int32_t *retval);
struct kern_channel;
extern int fill_channelinfo(struct kern_channel * chan,
    struct proc_channel_info *chan_info);
extern int fill_procworkqueue(proc_t, struct proc_workqueueinfo *);
extern boolean_t workqueue_get_pwq_exceeded(void *v, boolean_t *exceeded_total,
    boolean_t *exceeded_constrained);
extern uint32_t workqueue_get_pwq_state_kdp(void *proc);

#endif /* XNU_KERNEL_PRIVATE */

__END_DECLS

#endif /*_SYS_PROC_INFO_PRIVATE_H */
