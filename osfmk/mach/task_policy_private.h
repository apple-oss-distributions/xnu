/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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

#ifndef _MACH_TASK_POLICY_PRIVATE_H_
#define _MACH_TASK_POLICY_PRIVATE_H_

#include <mach/mach_types.h>
#include <mach/task_policy.h>

/*
 * Internal bitfields are privately exported for *revlocked*
 * tools like msa to decode tracepoints and taskinfo to dump state
 *
 * These struct definitions *will* change in the future.
 * When they do, we will update TASK_POLICY_INTERNAL_STRUCT_VERSION.
 */

#define TASK_POLICY_INTERNAL_STRUCT_VERSION 4

#define trp_tal_enabled trp_reserved  /*  trp_tal_enabled is unused, reuse its slot to grow trp_role */

struct task_requested_policy {
	uint64_t        trp_int_darwinbg        :1, /* marked as darwinbg via setpriority */
	    trp_ext_darwinbg        :1,
	    trp_int_iotier          :2,             /* IO throttle tier */
	    trp_ext_iotier          :2,
	    trp_int_iopassive       :1,             /* should IOs cause lower tiers to be throttled */
	    trp_ext_iopassive       :1,
	    trp_bg_iotier           :2,             /* what IO throttle tier should apply to me when I'm darwinbg? (pushed to threads) */
	    trp_terminated          :1,             /* all throttles should be removed for quick exit or SIGTERM handling */
	    trp_base_latency_qos    :3,             /* Timer latency QoS */
	    trp_base_through_qos    :3,             /* Computation throughput QoS */

	    trp_apptype             :3,             /* What apptype did launchd tell us this was (inherited) */
	    trp_boosted             :1,             /* Has a non-zero importance assertion count */
	    trp_role                :5,             /* task's system role */
	    trp_over_latency_qos    :3,             /* Timer latency QoS override */
	    trp_over_through_qos    :3,             /* Computation throughput QoS override */
	    trp_sfi_managed         :1,             /* SFI Managed task */
	    trp_qos_clamp           :3,             /* task qos clamp */

	/* suppression policies (non-embedded only) */
	    trp_sup_active          :1,             /* Suppression is on */
	    trp_sup_lowpri_cpu      :1,             /* Wants low priority CPU (MAXPRI_THROTTLE) */
	    trp_sup_timer           :3,             /* Wanted timer throttling QoS tier */
	    trp_sup_disk            :1,             /* Wants disk throttling */
	    trp_sup_throughput      :3,             /* Wants throughput QoS tier */
	    trp_sup_cpu             :1,             /* Wants suppressed CPU priority (MAXPRI_SUPPRESSED) */
	    trp_sup_bg_sockets      :1,             /* Wants background sockets */

	    trp_reserved            :17;
};

struct task_effective_policy {
	uint64_t        tep_darwinbg            :1, /* marked as 'background', and sockets are marked bg when created */
	    tep_lowpri_cpu          :1,             /* cpu priority == MAXPRI_THROTTLE */
	    tep_io_tier             :2,             /* effective throttle tier */
	    tep_io_passive          :1,             /* should IOs cause lower tiers to be throttled */
	    tep_all_sockets_bg      :1,             /* All existing sockets in process are marked as bg (thread: all created by thread) */
	    tep_new_sockets_bg      :1,             /* Newly created sockets should be marked as bg */
	    tep_bg_iotier           :2,             /* What throttle tier should I be in when darwinbg is set? */
	    tep_terminated          :1,             /* all throttles have been removed for quick exit or SIGTERM handling */
	    tep_qos_ui_is_urgent    :1,             /* bump UI-Interactive QoS up to the urgent preemption band */
	    tep_latency_qos         :3,             /* Timer latency QoS level */
	    tep_through_qos         :3,             /* Computation throughput QoS level */

	    tep_tal_engaged         :1,             /* TAL mode is in effect */
	    tep_watchers_bg         :1,             /* watchers are BG-ed */
	    tep_sup_active          :1,             /* suppression behaviors are in effect */
	    tep_role                :4,             /* task's system role */
	    tep_suppressed_cpu      :1,             /* cpu priority == MAXPRI_SUPPRESSED (trumped by lowpri_cpu) */
	    tep_sfi_managed         :1,             /* SFI Managed task */
	    tep_live_donor          :1,             /* task is a live importance boost donor */
	    tep_qos_clamp           :3,             /* task qos clamp (applies to qos-disabled threads too) */
	    tep_qos_ceiling         :3,             /* task qos ceiling (applies to only qos-participating threads) */
	    tep_adaptive_bg         :1,             /* task is bg solely due to the adaptive daemon clamp */

	    tep_reserved            :30;
};

/*
 * Control structure for applying suppression behaviors to tasks
 */
struct task_suppression_policy {
	integer_t active;
	integer_t lowpri_cpu; /* priority MAXPRI_THROTTLE cpu */
	integer_t timer_throttle;
	integer_t disk_throttle;
	integer_t cpu_limit;
	integer_t suspend;
	integer_t throughput_qos;
	integer_t suppressed_cpu; /* priority MAXPRI_SUPPRESSED cpu */
	integer_t background_sockets;
	integer_t reserved[7];
};

typedef struct task_suppression_policy *task_suppression_policy_t;

#define TASK_SUPPRESSION_POLICY_COUNT   ((mach_msg_type_number_t) \
    (sizeof (struct task_suppression_policy) / sizeof (integer_t)))

struct task_policy_state {
	uint64_t requested;
	uint64_t effective;
	uint64_t pending;
	uint32_t imp_assertcnt;
	uint32_t imp_externcnt;
	uint64_t flags;
	uint64_t imp_transitions;
	uint64_t tps_requested_policy;
	uint64_t tps_effective_policy;
};

typedef struct task_policy_state *task_policy_state_t;

#define TASK_POLICY_STATE_COUNT ((mach_msg_type_number_t) \
    (sizeof (struct task_policy_state) / sizeof (integer_t)))


/*
 * Definitions for munging and unmunging a policy struct
 * Used in task_policy_state and in tracepoints
 *
 * Note: this is tightly bound to the implementation of task policy
 * and the values exported through this API may change or change meaning at any time
 *
 * Do not rely on these values, especially apptype, to decide behaviors at runtime.
 *
 * All per-thread state must be in the first 32 bits of the bitfield.
 */

#define TASK_APPTYPE_NONE                0
#define TASK_APPTYPE_DAEMON_INTERACTIVE  1
#define TASK_APPTYPE_DAEMON_STANDARD     2
#define TASK_APPTYPE_DAEMON_ADAPTIVE     3
#define TASK_APPTYPE_DAEMON_BACKGROUND   4
#define TASK_APPTYPE_APP_DEFAULT         5
#define TASK_APPTYPE_APP_TAL             6 /* unused */
#define TASK_APPTYPE_DRIVER              7

/* task policy state flags */
#define TASK_IMP_RECEIVER                    0x00000001
#define TASK_IMP_DONOR                       0x00000002
#define TASK_IMP_LIVE_DONOR                  0x00000004
#define TASK_DENAP_RECEIVER                  0x00000008
#define TASK_IS_PIDSUSPENDED                 0x00000010

/* requested_policy */
#define POLICY_REQ_INT_DARWIN_BG             0x00000001
#define POLICY_REQ_EXT_DARWIN_BG             0x00000002
#define POLICY_REQ_INT_IO_TIER_MASK          0x0000000c /* 2 bits */
#define POLICY_REQ_INT_IO_TIER_SHIFT         2
#define POLICY_REQ_EXT_IO_TIER_MASK          0x00000030 /* 2 bits */
#define POLICY_REQ_EXT_IO_TIER_SHIFT         4
#define POLICY_REQ_INT_PASSIVE_IO            0x00000040
#define POLICY_REQ_EXT_PASSIVE_IO            0x00000080
#define POLICY_REQ_BG_IOTIER_MASK            0x00000300 /* 2 bits */
#define POLICY_REQ_BG_IOTIER_SHIFT           8

/* thread requested policy */
#define POLICY_REQ_PIDBIND_BG                0x00000400
#define POLICY_REQ_WORKQ_BG                  0x00000800 /* deprecated */
#define POLICY_REQ_TH_QOS_MASK               0x07000000 /* 3 bits (overlaps with ROLE) */
#define POLICY_REQ_TH_QOS_SHIFT              24
#define POLICY_REQ_TH_QOS_OVER_MASK          0x70000000 /* 3 bits (overlaps with TAL and SFI) */
#define POLICY_REQ_TH_QOS_OVER_SHIFT         28

/* task_requested_policy */
#define POLICY_REQ_TERMINATED                0x00001000
#define POLICY_REQ_BOOSTED                   0x00002000
#define POLICY_REQ_INT_GPU_DENY              0x00004000
#define POLICY_REQ_EXT_GPU_DENY              0x00008000
#define POLICY_REQ_APPTYPE_MASK              0x00070000 /* 3 bits */
#define POLICY_REQ_APPTYPE_SHIFT             16
#define POLICY_REQ_BASE_LATENCY_QOS_MASK     0x00700000 /* 3 bits */
#define POLICY_REQ_BASE_LATENCY_QOS_SHIFT    20
#define POLICY_REQ_ROLE_MASK                 0x07000000 /* 3 bits */
#define POLICY_REQ_ROLE_SHIFT                24
#define POLICY_REQ_TAL_ENABLED               0x40000000
#define POLICY_REQ_SFI_MANAGED               0x80000000

/* requested suppression behaviors (note: clipped off in 32-bit tracepoints) */
#define POLICY_REQ_SUP_ACTIVE                0x0000000100000000
#define POLICY_REQ_SUP_LOWPRI_CPU            0x0000000200000000
#define POLICY_REQ_SUP_CPU                   0x0000000400000000
#define POLICY_REQ_SUP_DISK_THROTTLE         0x0000003000000000 /* 2 bits */
#define POLICY_REQ_SUP_CPU_LIMIT             0x0000004000000000
#define POLICY_REQ_SUP_SUSPEND               0x0000008000000000
#define POLICY_REQ_OVER_LATENCY_QOS_MASK     0x0000070000000000 /* 3 bits */
#define POLICY_REQ_OVER_LATENCY_QOS_SHIFT    40
#define POLICY_REQ_BASE_THROUGH_QOS_MASK     0x0000700000000000 /* 3 bits */
#define POLICY_REQ_BASE_THROUGH_QOS_SHIFT    44
#define POLICY_REQ_OVER_THROUGH_QOS_MASK     0x0007000000000000 /* 3 bits */
#define POLICY_REQ_OVER_THROUGH_QOS_SHIFT    48
#define POLICY_REQ_SUP_TIMER_THROTTLE_MASK   0x0070000000000000 /* 3 bits */
#define POLICY_REQ_SUP_TIMER_THROTTLE_SHIFT  52
#define POLICY_REQ_SUP_THROUGHPUT_MASK       0x0700000000000000 /* 3 bits */
#define POLICY_REQ_SUP_THROUGHPUT_SHIFT      56
#define POLICY_REQ_SUP_BG_SOCKETS            0x0800008000000000
#define POLICY_REQ_QOS_CLAMP_MASK            0x7000000000000000 /* 3 bits */
#define POLICY_REQ_QOS_CLAMP_SHIFT           60

/* effective policy */
#define POLICY_EFF_IO_TIER_MASK              0x00000003 /* 2 bits */
#define POLICY_EFF_IO_TIER_SHIFT             0
#define POLICY_EFF_IO_PASSIVE                0x00000008
#define POLICY_EFF_DARWIN_BG                 0x00000010
#define POLICY_EFF_LOWPRI_CPU                0x00000020
#define POLICY_EFF_ALL_SOCKETS_BG            0x00000040
#define POLICY_EFF_NEW_SOCKETS_BG            0x00000080
#define POLICY_EFF_BG_IOTIER_MASK            0x00000300 /* 2 bits */
#define POLICY_EFF_BG_IOTIER_SHIFT           8
#define POLICY_EFF_TERMINATED                0x00000400
#define POLICY_EFF_QOS_UI_IS_URGENT          0x80000000

/* thread effective policy */
#define POLICY_EFF_TH_QOS_MASK               0x00700000 /* 3 bits (overlaps with ROLE) */
#define POLICY_EFF_TH_QOS_SHIFT              20
#define POLICY_EFF_LATENCY_QOS_MASK          0x00070000 /* 3 bits */
#define POLICY_EFF_LATENCY_QOS_SHIFT         16
#define POLICY_EFF_THROUGH_QOS_MASK          0x07000000 /* 3 bits */
#define POLICY_EFF_THROUGH_QOS_SHIFT         24

/* task effective policy */
#define POLICY_EFF_GPU_DENY                  0x00001000
#define POLICY_EFF_TAL_ENGAGED               0x00002000
#define POLICY_EFF_SUSPENDED                 0x00004000
#define POLICY_EFF_WATCHERS_BG               0x00008000
#define POLICY_EFF_SUP_ACTIVE                0x00080000
#define POLICY_EFF_ROLE_MASK                 0x00700000 /* 3 bits */
#define POLICY_EFF_ROLE_SHIFT                20
#define POLICY_EFF_SUP_CPU                   0x00800000
#define POLICY_EFF_SFI_MANAGED               0x08000000
#define POLICY_EFF_QOS_CEILING_MASK          0x70000000
#define POLICY_EFF_QOS_CEILING_SHIFT         28

/* pending policy */
#define POLICY_PEND_UPDATING                 0x00000001
#define POLICY_PEND_SOCKETS                  0x00000002
#define POLICY_PEND_TIMERS                   0x00000004
#define POLICY_PEND_WATCHERS                 0x00000008

#ifdef MACH_KERNEL_PRIVATE

extern const struct task_requested_policy default_task_requested_policy;
extern const struct task_effective_policy default_task_effective_policy;

extern kern_return_t
    qos_latency_policy_validate(task_latency_qos_t);

extern kern_return_t
    qos_throughput_policy_validate(task_throughput_qos_t);

extern uint32_t
    qos_extract(uint32_t);

extern uint32_t
    qos_latency_policy_package(uint32_t);
extern uint32_t
    qos_throughput_policy_package(uint32_t);

#endif /* MACH_KERNEL_PRIVATE */

#endif  /* _MACH_TASK_POLICY_PRIVATE_H_ */
