// Copyright (c) 2024 Apple Inc.  All rights reserved.

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

/* Mock locks */
typedef void *lck_ticket_t;
#define decl_lck_mtx_data(class, name)     class int name
#define decl_simple_lock_data(class, name) class int name
#define pset_lock(x) (void)x
#define pset_unlock(x) (void)x
#define pset_assert_locked(x) (void)x
#define thread_lock(x) (void)x
#define thread_unlock(x) (void)x

/* Processor-related */
#define PERCPU_DECL(type_t, name) type_t name
#include <kern/processor.h>
processor_t processor_array[MAX_SCHED_CPUS];
processor_set_t pset_array[MAX_PSETS];

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
	processor_t             last_processor;         /* processor last dispatched on */
	ast_t                   reason;         /* why we blocked */
	int                     state;
#define TH_WAIT                 0x01            /* queued for waiting */
#define TH_RUN                  0x04            /* running or on runq */
#define TH_IDLE                 0x80            /* idling processor */
#define TH_SFLAG_DEPRESS                0x0040          /* normal depress yield */
#define TH_SFLAG_POLLDEPRESS            0x0080          /* polled depress yield */
#define TH_SFLAG_DEPRESSED_MASK         (TH_SFLAG_DEPRESS | TH_SFLAG_POLLDEPRESS)
#define TH_SFLAG_BOUND_SOFT             0x20000         /* thread is soft bound to a cluster; can run anywhere if bound cluster unavailable */
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
#define THREAD_BOUND_CLUSTER_NONE       (UINT32_MAX)
	uint32_t                 th_bound_cluster_id;
#if CONFIG_SCHED_EDGE
	bool            th_bound_cluster_enqueued;
	bool            th_shared_rsrc_enqueued[CLUSTER_SHARED_RSRC_TYPE_COUNT];
	bool            th_shared_rsrc_heavy_user[CLUSTER_SHARED_RSRC_TYPE_COUNT];
	bool            th_shared_rsrc_heavy_perf_control[CLUSTER_SHARED_RSRC_TYPE_COUNT];
#endif /* CONFIG_SCHED_EDGE */
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

uint64_t
thread_group_get_id(struct thread_group *tg)
{
	return tg->tg_id;
}

#if CONFIG_SCHED_EDGE

bool
thread_shared_rsrc_policy_get(thread_t thread, cluster_shared_rsrc_type_t type)
{
	return thread->th_shared_rsrc_heavy_user[type] || thread->th_shared_rsrc_heavy_perf_control[type];
}

#endif /* CONFIG_SCHED_EDGE */
