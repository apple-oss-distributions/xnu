// Copyright (c) 2023 Apple Inc.  All rights reserved.

#pragma once

/* Base harness interface */
#include "sched_runqueue_harness.h"

#include <sys/types.h>
#include <kern/sched.h>

extern int root_bucket_to_highest_pri[TH_BUCKET_SCHED_MAX];

/* Publish Clutch implementation-specific paramemeters for use in unit tests */
extern uint64_t clutch_root_bucket_wcel_us[TH_BUCKET_SCHED_MAX];
extern uint64_t clutch_root_bucket_warp_us[TH_BUCKET_SCHED_MAX];
extern int clutch_interactivity_score_max;

/* Clutch/Edge trace codes */
extern unsigned int CLUTCH_THREAD_SELECT;
