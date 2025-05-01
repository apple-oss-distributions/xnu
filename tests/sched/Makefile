# Copyright (c) 2024 Apple Inc.  All rights reserved.

SCHED_UTILS = sched/sched_test_utils.c
SCHED_UTILS_FLAGS = -ldarwintest_utils -Wno-format-nonliteral -Wno-cast-qual -Wno-c++98-compat -Wno-format-security
EXCLUDED_SOURCES += $(SCHED_UTILS)
# Note, SCHED_UTILS depends on -ldarwintest_utils to build

include sched/sched_test_harness/Makefile

sched/all_cores_running: OTHER_LDFLAGS += $(SCHED_UTILS_FLAGS)
sched/all_cores_running: $(SCHED_UTILS)
SCHED_TARGETS += sched/all_cores_running


sched/cluster_bound_threads: OTHER_LDFLAGS += $(SCHED_UTILS_FLAGS)
sched/cluster_bound_threads: $(SCHED_UTILS)
SCHED_TARGETS += sched/cluster_bound_threads

sched/contextswitch: OTHER_LDFLAGS += $(SCHED_UTILS_FLAGS)
sched/contextswitch: $(SCHED_UTILS)
SCHED_TARGETS += sched/contextswitch

sched/enabled_policy: OTHER_LDFLAGS += $(SCHED_UTILS_FLAGS)
sched/enabled_policy: $(SCHED_UTILS)
SCHED_TARGETS += sched/enabled_policy

sched/headers_compat_cpp: OTHER_CXXFLAGS += -I$(SRCROOT)/../osfmk
SCHED_TARGETS += sched/headers_compat_cpp

sched/headers_compat_c: OTHER_CFLAGS += -I$(SRCROOT)/../osfmk
SCHED_TARGETS += sched/headers_compat_c

sched/overloaded_runqueue: CODE_SIGN_ENTITLEMENTS = sched/overloaded_runqueue.entitlements
sched/overloaded_runqueue: OTHER_CFLAGS += -DENTITLED=1
sched/overloaded_runqueue: OTHER_LDFLAGS += -framework ktrace $(SCHED_UTILS_FLAGS)
sched/overloaded_runqueue: $(SCHED_UTILS)
SCHED_TARGETS += sched/overloaded_runqueue

sched/thread_group_fairness: CODE_SIGN_ENTITLEMENTS = sched/thread_group_fairness.entitlements
sched/thread_group_fairness: OTHER_CFLAGS += -DENTITLED=1
sched/thread_group_fairness: OTHER_LDFLAGS += -framework perfdata $(SCHED_UTILS_FLAGS)
sched/thread_group_fairness: $(SCHED_UTILS)
sched/thread_group_fairness: sched/thread_group_fairness_workload_config.h
sched/thread_group_fairness_workload_config.h: sched/thread_group_fairness_workload_config.plist
	xxd -i $< > $@
SCHED_TARGETS += sched/thread_group_fairness

sched/thread_group_flags: CODE_SIGN_ENTITLEMENTS = sched/thread_group_flags.entitlements
sched/thread_group_flags: OTHER_CFLAGS += -DENTITLED=1
sched/thread_group_flags: OTHER_LDFLAGS += -framework ktrace
sched/thread_group_flags: sched/thread_group_flags_workload_config.h
sched/thread_group_flags_workload_config.h: sched/thread_group_flags_workload_config.plist
	xxd -i $< > $@
SCHED_TARGETS += sched/thread_group_flags

sched/yield_aggressor: OTHER_CFLAGS += -Wno-atomic-implicit-seq-cst
sched/yield_aggressor: OTHER_LDFLAGS += -framework perfdata $(SCHED_UTILS_FLAGS)
sched/yield_aggressor: $(SCHED_UTILS)
SCHED_TARGETS += sched/yield_aggressor

sched/zero_to_n_tests: OTHER_LDFLAGS += -framework perfdata $(SCHED_UTILS_FLAGS)
SCHED_TARGETS += sched/zero_to_n_tests

# Convenience command for building all of the test targets under sched/
.PHONY: sched/all
sched/all: $(SCHED_TARGETS)
