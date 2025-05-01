// Copyright (c) 2024 Apple Inc.  All rights reserved.

/*
 * Listing of scheduler-related headers that are exported outside of the kernel.
 */

#include <kern/bits.h>
#include <kern/coalition.h>
#include <kern/policy_internal.h>
#include <kern/processor.h>
#include <kern/sched_amp_common.h>
#include <kern/sched_prim.h>
#include <kern/sched_urgency.h>
#include <kern/thread_call.h>
#include <kern/timer_call.h>
#include <kern/waitq.h>
#define CONFIG_THREAD_GROUPS 1
typedef void *cluster_type_t;
#include <kern/thread_group.h>
#include <kern/work_interval.h>
