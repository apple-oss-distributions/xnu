/*
 * Copyright (c) 2014 Apple Inc. All rights reserved.
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

#ifndef _MACH_COALITION_H_
#define _MACH_COALITION_H_

#include <stdint.h>
#include <stdbool.h>

/* code shared by userspace and xnu */

#define COALITION_SPAWN_ENTITLEMENT "com.apple.private.coalition-spawn"

#define COALITION_CREATE_FLAGS_MASK       ((uint32_t)0xFF3)
#define COALITION_CREATE_FLAGS_PRIVILEGED ((uint32_t)0x01)
#define COALITION_CREATE_FLAGS_EFFICIENT  ((uint32_t)0x02)

#define COALITION_CREATE_FLAGS_TYPE_MASK  ((uint32_t)0xF0)
#define COALITION_CREATE_FLAGS_TYPE_SHIFT (4)

#define COALITION_CREATE_FLAGS_GET_TYPE(flags) \
	(((flags) & COALITION_CREATE_FLAGS_TYPE_MASK) >> COALITION_CREATE_FLAGS_TYPE_SHIFT)

#define COALITION_CREATE_FLAGS_SET_TYPE(flags, type) \
	do { \
	        flags &= ~COALITION_CREATE_FLAGS_TYPE_MASK; \
	        flags |= (((type) << COALITION_CREATE_FLAGS_TYPE_SHIFT) \
	                   & COALITION_CREATE_FLAGS_TYPE_MASK); \
	} while (0)

#define COALITION_CREATE_FLAGS_ROLE_MASK  ((uint32_t)0xF00)
#define COALITION_CREATE_FLAGS_ROLE_SHIFT (8)

#define COALITION_CREATE_FLAGS_GET_ROLE(flags) \
    (((flags) & COALITION_CREATE_FLAGS_ROLE_MASK) >> COALITION_CREATE_FLAGS_ROLE_SHIFT)

#define COALITION_CREATE_FLAGS_SET_ROLE(flags, role) \
    do { \
	flags &= ~COALITION_CREATE_FLAGS_ROLE_MASK; \
	flags |= (((role) << COALITION_CREATE_FLAGS_ROLE_SHIFT) \
	       & COALITION_CREATE_FLAGS_ROLE_MASK); \
    } while (0)

/*
 * Default scheduling policy of the lead/parent task in a coalition
 */
#define COALITION_ROLE_UNDEF       (0)
#define COALITION_ROLE_SYSTEM      (1)
#define COALITION_ROLE_BACKGROUND  (2)
#define COALITION_ROLE_ADAPTIVE    (3)
#define COALITION_ROLE_INTERACTIVE (4)
#define COALITION_NUM_ROLES        (5)

#define COALITION_TYPE_RESOURCE  (0)
#define COALITION_TYPE_JETSAM    (1)
#define COALITION_TYPE_MAX       (1)

#define COALITION_NUM_TYPES      (COALITION_TYPE_MAX + 1)

#define COALITION_TASKROLE_NONE   (-1) /* task plays no role in the given coalition */
#define COALITION_TASKROLE_UNDEF  (0)
#define COALITION_TASKROLE_LEADER (1)
#define COALITION_TASKROLE_XPC    (2)
#define COALITION_TASKROLE_EXT    (3)

#define COALITION_NUM_TASKROLES   (4)

#define COALITION_ROLEMASK_ALLROLES ((1 << COALITION_NUM_TASKROLES) - 1)
#define COALITION_ROLEMASK_UNDEF    (1 << COALITION_TASKROLE_UNDEF)
#define COALITION_ROLEMASK_LEADER   (1 << COALITION_TASKROLE_LEADER)
#define COALITION_ROLEMASK_XPC      (1 << COALITION_TASKROLE_XPC)
#define COALITION_ROLEMASK_EXT      (1 << COALITION_TASKROLE_EXT)

#define COALITION_SORT_NOSORT     (0)
#define COALITION_SORT_DEFAULT    (1)
#define COALITION_SORT_MEM_ASC    (2)
#define COALITION_SORT_MEM_DEC    (3)
#define COALITION_SORT_USER_ASC   (4)
#define COALITION_SORT_USER_DEC   (5)

#define COALITION_NUM_SORT        (6)

#define COALITION_NUM_THREAD_QOS_TYPES   7

/* Flags for coalition efficiency (Deprecated) */
#define COALITION_FLAGS_EFFICIENT       (0x1)

struct coalition_resource_usage {
	uint64_t tasks_started;
	uint64_t tasks_exited;
	uint64_t time_nonempty;
	uint64_t cpu_time; /* mach_absolute_time units */
	uint64_t interrupt_wakeups;
	uint64_t platform_idle_wakeups;
	uint64_t bytesread;
	uint64_t byteswritten;
	uint64_t gpu_time; /* nanoseconds */
	uint64_t cpu_time_billed_to_me; /* mach_absolute_time units */
	uint64_t cpu_time_billed_to_others; /* mach_absolute_time units */
	uint64_t energy; /* nanojoules */
	uint64_t logical_immediate_writes;
	uint64_t logical_deferred_writes;
	uint64_t logical_invalidated_writes;
	uint64_t logical_metadata_writes;
	uint64_t logical_immediate_writes_to_external;
	uint64_t logical_deferred_writes_to_external;
	uint64_t logical_invalidated_writes_to_external;
	uint64_t logical_metadata_writes_to_external;
	uint64_t energy_billed_to_me; /* nanojoules */
	uint64_t energy_billed_to_others; /* nanojoules */
	uint64_t cpu_ptime; /* mach_absolute_time units */
	uint64_t cpu_time_eqos_len;     /* Stores the number of thread QoS types */
	uint64_t cpu_time_eqos[COALITION_NUM_THREAD_QOS_TYPES];
	uint64_t cpu_instructions;
	uint64_t cpu_cycles;
	uint64_t fs_metadata_writes;
	uint64_t pm_writes;
	uint64_t cpu_pinstructions;
	uint64_t cpu_pcycles;
	uint64_t conclave_mem;
	uint64_t ane_mach_time; /* mach_absolute_time units */
	uint64_t ane_energy_nj; /* nanojoules */
	uint64_t phys_footprint;        /* Sum of instantaneous process phys_footprint */
	uint64_t gpu_energy_nj; /* nanojoules that I did */
	uint64_t gpu_energy_nj_billed_to_me; /* nanojoules that others did on my behalf */
	uint64_t gpu_energy_nj_billed_to_others; /* nanojoules that I did on others' behalf */
};

#ifdef PRIVATE
/* definitions shared by only xnu + Libsyscall */

/* coalition id for kernel task */
#define COALITION_ID_KERNEL 1

/* Syscall flavors */
#define COALITION_OP_CREATE 1
#define COALITION_OP_TERMINATE 2
#define COALITION_OP_REAP 3

/* coalition_info flavors */
#define COALITION_INFO_RESOURCE_USAGE 1
#define COALITION_INFO_SET_NAME 2
#define COALITION_INFO_SET_EFFICIENCY 3
#define COALITION_INFO_GET_DEBUG_INFO 4

struct coalinfo_debuginfo {
	uint64_t thread_group_id;
	uint32_t thread_group_recommendation;
	uint32_t thread_group_flags;
	uint32_t focal_task_count;
	uint32_t nonfocal_task_count;
	uint32_t game_task_count;
	uint32_t carplay_task_count;
};

/* coalition_ledger_set operations */
#define COALITION_LEDGER_SET_LOGICAL_WRITES_LIMIT 1

#define COALITION_EFFICIENCY_VALID_FLAGS    (COALITION_FLAGS_EFFICIENT)

/* structure returned from libproc coalition listing interface */
struct procinfo_coalinfo {
	uint64_t coalition_id;
	uint32_t coalition_type;
	uint32_t coalition_tasks;
};

#endif /* PRIVATE */

#ifdef XNU_KERNEL_PRIVATE

#if COALITION_DEBUG
#define coal_dbg(fmt, ...) \
	printf("%s: " fmt "\n", __func__, ## __VA_ARGS__)
#else
#define coal_dbg(fmt, ...)
#endif

__options_decl(coalition_gpu_energy_t, uint32_t, {
	CGE_SELF    = 0x1,
	CGE_BILLED  = 0x2,
	CGE_OTHERS  = 0x4,
});

extern bool coalition_add_to_gpu_energy(uint64_t coalition_id, coalition_gpu_energy_t which, uint64_t energy);

#endif /* XNU_KERNEL_PRIVATE */

#ifdef MACH_KERNEL_PRIVATE

typedef struct coalition_pend_token {
	uint32_t        cpt_update_timers      :1,
	    cpt_update_j_coal_tasks :1;
} *coalition_pend_token_t;

#endif /* MACH_KERNEL_PRIVATE */

#endif /* _MACH_COALITION_H_ */
