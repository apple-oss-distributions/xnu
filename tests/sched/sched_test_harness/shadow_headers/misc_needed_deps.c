// Copyright (c) 2023 Apple Inc.  All rights reserved.

#include <mach/mach_time.h>

#ifndef MIN
#define MIN(a, b) (((a)<(b))?(a):(b))
#endif /* MIN */
#ifndef MAX
#define MAX(a, b) (((a)>(b))?(a):(b))
#endif  /* MAX */

/* Overrides necessary for userspace code */
#define panic(...) ({ printf("Panicking:\n"); printf(__VA_ARGS__); abort(); })
#define KDBG(...) (void)0
#define kalloc_type(x, y, z) calloc((size_t)y, sizeof(x))
#define kfree_type(x, y, z) free(z)
#define PE_parse_boot_argn(x, y, z) FALSE

#define pset_lock(x) (void)x
#define pset_unlock(x) (void)x
#define thread_lock(x) (void)x
#define thread_unlock(x) (void)x

/* Expected global(s) */
static task_t kernel_task = NULL;

/* Time conversion to mock the implementation in osfmk/arm/rtclock.c */
static mach_timebase_info_data_t timebase_info;
void
clock_interval_to_absolutetime_interval(uint32_t   interval,
    uint32_t   scale_factor,
    uint64_t * result)
{
	mach_timebase_info(&timebase_info);
	uint64_t nanosecs = (uint64_t) interval * scale_factor;
	*result = nanosecs * timebase_info.denom / timebase_info.numer;
}

/*
 * thread struct from osfmk/kern/thread.h containing only fields needed by
 * the Clutch runqueue logic, followed by needed functions from osfmk/kern/thread.c
 * for operating on the __runq field
 */
struct thread {
	int id;
	sched_mode_t sched_mode;
	int16_t                 sched_pri;              /* scheduled (current) priority */
	int16_t                 base_pri;               /* effective base priority (equal to req_base_pri unless TH_SFLAG_BASE_PRI_FROZEN) */
	queue_chain_t                   runq_links;             /* run queue links */
	struct { processor_t    runq; } __runq; /* internally managed run queue assignment, see above comment */
	sched_bucket_t          th_sched_bucket;
	processor_t             bound_processor;        /* bound to a processor? */
	int                     state;
#define TH_WAIT                 0x01            /* queued for waiting */
#define TH_RUN                  0x04            /* running or on runq */
#define TH_IDLE                 0x80            /* idling processor */
	uint64_t                thread_id;             /* system wide unique thread-id */
	struct {
		uint64_t user_time;
		uint64_t system_time;
	} mock_recount_time;
	uint64_t sched_time_save;
	natural_t               sched_usage;            /* timesharing cpu usage [sched] */
	natural_t               pri_shift;              /* usage -> priority from pset */
	natural_t               cpu_usage;              /* instrumented cpu usage [%cpu] */
	natural_t               cpu_delta;              /* accumulated cpu_usage delta */
	struct thread_group     *thread_group;
	struct priority_queue_entry_stable      th_clutch_runq_link;
	struct priority_queue_entry_sched       th_clutch_pri_link;
	queue_chain_t                           th_clutch_timeshare_link;
	uint32_t                sched_flags;            /* current flag bits */
};

void
thread_assert_runq_null(__assert_only thread_t thread)
{
	assert(thread->__runq.runq == PROCESSOR_NULL);
}

void
thread_assert_runq_nonnull(thread_t thread)
{
	assert(thread->__runq.runq != PROCESSOR_NULL);
}

void
thread_clear_runq(thread_t thread)
{
	thread_assert_runq_nonnull(thread);
	thread->__runq.runq = PROCESSOR_NULL;
}

void
thread_set_runq_locked(thread_t thread, processor_t new_runq)
{
	thread_assert_runq_null(thread);
	thread->__runq.runq = new_runq;
}

processor_t
thread_get_runq_locked(thread_t thread)
{
	return thread->__runq.runq;
}

uint64_t
thread_tid(
	thread_t        thread)
{
	return thread != THREAD_NULL? thread->thread_id: 0;
}

/* Satisfy recount dependency needed by osfmk/kern/sched.h */
#define recount_thread_time_mach(thread) (thread->mock_recount_time.user_time + thread->mock_recount_time.system_time)

/*
 * thread_group struct from osfmk/kern/thread_group.c containing only fields
 * needed by the Clutch runqueue logic, followed by needed functions from
 * osfmk/kern/thread_group.c
 */
struct thread_group {
	uint64_t                tg_id;
	struct sched_clutch     tg_sched_clutch;
};

sched_clutch_t
sched_clutch_for_thread(thread_t thread)
{
	assert(thread->thread_group != NULL);
	return &(thread->thread_group->tg_sched_clutch);
}

sched_clutch_t
sched_clutch_for_thread_group(struct thread_group *thread_group)
{
	return &(thread_group->tg_sched_clutch);
}

inline uint64_t
thread_group_get_id(struct thread_group *tg)
{
	return tg->tg_id;
}

/*
 * processor and processor_set structs from osfmk/kern/processor.h containing
 * only fields needed by the Clutch runqueue logic
 */
struct processor_set {
	uint32_t pset_cluster_id;
	struct sched_clutch_root pset_clutch_root; /* clutch hierarchy root */
};
struct processor {
	processor_set_t         processor_set;  /* assigned set */
	struct run_queue        runq;                   /* runq for this processor */
	struct thread          *active_thread;          /* thread running on processor */
	bool                    first_timeslice;        /* has the quantum expired since context switch */
	int                     current_pri;            /* priority of current thread */
	int                     cpu_id;                 /* platform numeric id */
	processor_t             processor_primary;
	bool                    current_is_bound;       /* current thread is bound to this processor */
	struct thread_group    *current_thread_group;   /* thread_group of current thread */
};
