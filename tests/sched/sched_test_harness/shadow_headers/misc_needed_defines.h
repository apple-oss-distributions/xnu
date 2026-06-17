// Copyright (c) 2024 Apple Inc.  All rights reserved.

#ifndef _MISC_NEEDED_DEFINES_H_
#define _MISC_NEEDED_DEFINES_H_

#include <kern/bits.h>

/*
 * Include non-kernel header dependencies to make up for the equivalent kernel header
 * dependencies which are not safe to compile in a userspace binary
 */
#include <os/overflow.h>
#include <sys/types.h>
#include <os/atomic_private.h>

/* Mock osfmk/kern/spl.h */
typedef int spl_t;
#define splsched() 0
#define splx(x) (void)x

extern void panic(char *msg, ...);

/* Mock osfmk/arm64/proc_reg.h */
#define MAX_PSETS 16
#define MAX_CPUS 64

/* Mock pexpert/arm64/board_config.h */
#define MAX_CPU_CLUSTERS 6

/* Dependencies from osfmk/mach/mach_types.h */
#include <mach/clock_types.h>
#include <mach/boolean.h>
#include <mach/kern_return.h>
#include <mach/thread_policy_private.h>
typedef struct task                     *task_t;
typedef struct thread                   *thread_t;
typedef struct processor                *processor_t;
typedef struct processor_set            *processor_set_t;
#define TASK_NULL               ((task_t) 0)
#define THREAD_NULL             ((thread_t) 0)
#define PROCESSOR_NULL          ((processor_t) 0)
#define PROCESSOR_SET_NULL      ((processor_set_t) 0)

typedef vm_offset_t uintptr_t;

/* Defines from osfmk/kern/timer_call.h */
typedef void            *timer_call_param_t;

/* Defines from osfmk/kern/kern_types.h */
typedef struct run_queue               *run_queue_t;
typedef struct pset_node                *pset_node_t;
#define PSET_NODE_NULL                  ((pset_node_t) 0)
typedef uint8_t pset_id_t;
#define PSET_ID_INVALID ((pset_id_t)UINT8_MAX)

/* Defines from osfmk/arm/machine_routines.h */
typedef uint64_t sched_perfcontrol_preferred_cluster_options_t;
typedef enum {
	CLUSTER_TYPE_INVALID = -1,
	CLUSTER_TYPE_SMP     = 0,
	CLUSTER_TYPE_E       = 1,
	CLUSTER_TYPE_P       = 2,
	CLUSTER_TYPE_M       = 3,
	MAX_CPU_TYPES,
} cluster_type_t;
#include <arm/cpu_topology.h>
extern unsigned int ml_get_die_id(unsigned int cluster_id);
extern uint64_t ml_cpu_signal_deferred_get_timer(void);
extern unsigned int ml_get_cpu_number_type(cluster_type_t cluster_type, bool logical, bool available);

extern struct ml_topology_info topology_info;

/* Defines from osfmk/kern/thread.h */
#define assert_thread_magic(thread) do { (void)(thread); } while (0)

/* Defines from osfmk/kern/startup.h */
#define TUNABLE(type_t, var, boot_arg, default_value) \
    type_t var = default_value
#define __startup_data

/* Defines from bsd/sys/kdebug_kernel.h */
#define __kdebug_only __unused

extern processor_t master_processor;

#define SECURITY_READ_ONLY_LATE(typ) typ

/* Defines from osfmk/kern/startup.h */
#define __startup_func
#define STARTUP(...)

#endif  /* _MISC_NEEDED_DEFINES_H_ */
