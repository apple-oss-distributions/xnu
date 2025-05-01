ifneq ($(PLATFORM),MacOSX)
# Exclude building for any platform except MacOSX, due to arch/target incompatibility
EXCLUDED_SOURCES += sched/clutch_runqueue.c sched/edge_runqueue.c sched/edge_migration.c
else

SCHED_HARNESS := sched/sched_test_harness
SCHED_HARNESS_SHADOW := $(SCHED_HARNESS)/shadow_headers
SCHED_CLUTCH_DISABLED_WARNINGS := -Wno-declaration-after-statement -Wno-nullability-completeness -Wno-missing-prototypes -Wno-gnu-statement-expression-from-macro-expansion -Wno-implicit-int-conversion -Wno-sign-conversion -Wno-c++98-compat -Wno-language-extension-token -Wno-c2x-extensions -Wno-format-nonliteral -Wno-unused-function
SCHED_TEST_DISABLED_WARNINGS := -Wno-gnu-binary-literal -Wno-format-nonliteral -Wno-language-extension-token -Wno-sign-conversion
SCHED_HARNESS_DEFINES := -DSCHED_TEST_HARNESS=1 -DCONFIG_SCHED_CLUTCH=1 -DCONFIG_SCHED_TIMESHARE_CORE=1 -DCONFIG_THREAD_GROUPS=1
# Configure osmfk/kern/queue.h to define symbol __queue_element_linkage_invalid()
SCHED_HARNESS_DEFINES += -DDRIVERKIT_FRAMEWORK_INCLUDE=1
SCHED_EDGE_DEFINES := -DCONFIG_SCHED_EDGE=1 -D__AMP__=1

# Enable some ASan/UBSan in the test binary for MacOS target
SCHED_HARNESS_DEBUG_FLAGS := -fsanitize=bounds -fsanitize=null -fsanitize=address -gfull

XNU_SRC := ..
# List the shadow_headers directory first before ../osfmk/ so that headers present in the
# harness directory override the versions in xnu source proper
SCHED_HARNESS_COMPILER_SEARCH_ORDER := -I $(SCHED_HARNESS_SHADOW)/ -I $(XNU_SRC)/osfmk/

# Track file modifications correctly in the recipe
SCHED_HARNESS_DEPS := $(shell find $(SCHED_HARNESS) -name "*.c" -o -name "*.h")
SCHED_CLUTCH_DEPS := $(XNU_SRC)/osfmk/kern/sched_clutch.c $(XNU_SRC)/osfmk/kern/sched_clutch.h $(XNU_SRC)/osfmk/kern/queue.h $(XNU_SRC)/osfmk/kern/circle_queue.h $(XNU_SRC)/osfmk/kern/bits.h $(XNU_SRC)/osfmk/kern/sched.h

# Guard-out some unwanted includes without needing to modify the original header files
SCHED_CLUTCH_UNWANTED_HDRS := mach/policy.h kern/smp.h kern/timer_call.h kern/macro_help.h kern/spl.h kern/misc_protos.h kern/thread.h
clutch_setup_placehold_hdrs:
	mkdir -p $(SCHED_HARNESS_SHADOW)/kern
	mkdir -p $(SCHED_HARNESS_SHADOW)/mach
	for hdr in $(SCHED_CLUTCH_UNWANTED_HDRS); do \
		echo "/* Empty file used as a placeholder for " $$hdr " that we don't want to import */" > $(SCHED_HARNESS_SHADOW)/$$hdr; \
	done
	# Replace osfmk/mach/mach_types.h with smaller set of dependencies combined in misc_needed_defines.h,
	# ultimately satisfying dependencies needed by osfmk/kern/sched.h
	echo '#include "misc_needed_defines.h"' > $(SCHED_HARNESS_SHADOW)/mach/mach_types.h

# Make it convenient to build all of the tests in one go
SCHED_USERSPACE_UNIT_TESTS = sched/clutch_runqueue sched/edge_runqueue sched/edge_migration
.PHONY: sched/userspace_unit_tests
sched/userspace_unit_tests: $(SCHED_USERSPACE_UNIT_TESTS)
SCHED_TARGETS += $(SCHED_USERSPACE_UNIT_TESTS)

# Link together all the object files (built below) with the unit tests into a final binary
sched/clutch_runqueue: INVALID_ARCHS = $(filter-out arm64e%,$(ARCH_CONFIGS))
sched/clutch_runqueue: OTHER_CFLAGS += $(SCHED_HARNESS_DEFINES) $(SCHED_HARNESS_DEBUG_FLAGS) $(SCHED_HARNESS_COMPILER_SEARCH_ORDER) $(SCHED_TEST_DISABLED_WARNINGS) -DTEST_RUNQ_POLICY="clutch"
sched/clutch_runqueue: OTHER_LDFLAGS += -ldarwintest_utils $(SCHED_HARNESS_DEBUG_FLAGS) $(OBJROOT)/sched_clutch_harness.o $(OBJROOT)/priority_queue.o $(OBJROOT)/sched_runqueue_harness.o
sched/clutch_runqueue: $(OBJROOT)/sched_clutch_harness.o $(OBJROOT)/priority_queue.o $(OBJROOT)/sched_runqueue_harness.o
sched/clutch_runqueue: CONFIG_FLAGS := $(filter-out -O%,$(CONFIG_FLAGS)) -O0 -gfull

sched/edge_runqueue: INVALID_ARCHS = $(filter-out arm64e%,$(ARCH_CONFIGS))
sched/edge_runqueue: OTHER_CFLAGS += $(SCHED_HARNESS_DEFINES) $(SCHED_EDGE_DEFINES) $(SCHED_HARNESS_DEBUG_FLAGS) $(SCHED_HARNESS_COMPILER_SEARCH_ORDER) $(SCHED_TEST_DISABLED_WARNINGS) -DTEST_RUNQ_POLICY="edge"
sched/edge_runqueue: OTHER_LDFLAGS += -ldarwintest_utils $(SCHED_HARNESS_DEBUG_FLAGS) $(OBJROOT)/sched_edge_harness.o $(OBJROOT)/priority_queue.o $(OBJROOT)/sched_runqueue_harness.o $(OBJROOT)/sched_migration_harness.o
sched/edge_runqueue: $(OBJROOT)/sched_edge_harness.o $(OBJROOT)/priority_queue.o $(OBJROOT)/sched_runqueue_harness.o $(OBJROOT)/sched_migration_harness.o
sched/edge_runqueue: CONFIG_FLAGS := $(filter-out -O%,$(CONFIG_FLAGS)) -O0 -gfull

sched/edge_migration: INVALID_ARCHS = $(filter-out arm64e%,$(ARCH_CONFIGS))
sched/edge_migration: OTHER_CFLAGS += $(SCHED_HARNESS_DEFINES) $(SCHED_EDGE_DEFINES) $(SCHED_HARNESS_DEBUG_FLAGS) $(SCHED_HARNESS_COMPILER_SEARCH_ORDER) $(SCHED_TEST_DISABLED_WARNINGS) -DTEST_RUNQ_POLICY="edge"
sched/edge_migration: OTHER_LDFLAGS += -ldarwintest_utils $(SCHED_HARNESS_DEBUG_FLAGS) $(OBJROOT)/sched_edge_harness.o $(OBJROOT)/priority_queue.o $(OBJROOT)/sched_runqueue_harness.o $(OBJROOT)/sched_migration_harness.o
sched/edge_migration: $(OBJROOT)/sched_edge_harness.o $(OBJROOT)/priority_queue.o $(OBJROOT)/sched_runqueue_harness.o $(OBJROOT)/sched_migration_harness.o
sched/edge_migration: CONFIG_FLAGS := $(filter-out -O%,$(CONFIG_FLAGS)) -O0 -gfull

# Runqueue harness
$(OBJROOT)/sched_runqueue_harness.o: OTHER_CFLAGS += $(SCHED_HARNESS_DEBUG_FLAGS)
$(OBJROOT)/sched_runqueue_harness.o: $(SCHED_HARNESS)/sched_runqueue_harness.c
	$(MAKE) clutch_setup_placehold_hdrs
	$(CC) $(OTHER_CFLAGS) $(CFLAGS) -c $< -o $@

# Migration harness
$(OBJROOT)/sched_migration_harness.o: OTHER_CFLAGS += $(SCHED_HARNESS_DEBUG_FLAGS)
$(OBJROOT)/sched_migration_harness.o: $(SCHED_HARNESS)/sched_migration_harness.c
	$(MAKE) clutch_setup_placehold_hdrs
	$(CC) $(OTHER_CFLAGS) $(CFLAGS) -c $< -o $@

# Clutch harness
$(OBJROOT)/sched_clutch_harness.o: OTHER_CFLAGS += -DRUNQUEUE_HARNESS_IMPLEMENTATION=1 $(SCHED_HARNESS_DEFINES) $(SCHED_HARNESS_DEBUG_FLAGS) $(SCHED_CLUTCH_DISABLED_WARNINGS) $(SCHED_HARNESS_COMPILER_SEARCH_ORDER)
$(OBJROOT)/sched_clutch_harness.o: $(SCHED_HARNESS)/sched_clutch_harness.c $(SCHED_HARNESS_DEPS) $(SCHED_CLUTCH_DEPS)
	$(MAKE) clutch_setup_placehold_hdrs
	$(CC) $(OTHER_CFLAGS) $(CFLAGS) -c $< -o $@

# Edge harness
$(OBJROOT)/sched_edge_harness.o: OTHER_CFLAGS += $(SCHED_HARNESS_DEFINES) $(SCHED_EDGE_DEFINES) $(SCHED_HARNESS_DEBUG_FLAGS) $(SCHED_CLUTCH_DISABLED_WARNINGS) $(SCHED_HARNESS_COMPILER_SEARCH_ORDER)
$(OBJROOT)/sched_edge_harness.o: $(SCHED_HARNESS)/sched_edge_harness.c $(SCHED_HARNESS)/sched_clutch_harness_impl.c $(SCHED_HARNESS_DEPS) $(SCHED_CLUTCH_DEPS)
	$(MAKE) clutch_setup_placehold_hdrs
	$(CC) $(OTHER_CFLAGS) $(CFLAGS) -c $< -o $@

# Priority queue C++ dependency
$(OBJROOT)/priority_queue.o: OTHER_CXXFLAGS += -std=c++11 $(SCHED_HARNESS_DEFINES) $(SCHED_HARNESS_DEBUG_FLAGS) $(SCHED_HARNESS_COMPILER_SEARCH_ORDER)
$(OBJROOT)/priority_queue.o: $(SCHED_HARNESS_SHADOW)/priority_queue.cpp
	$(CXX) $(OTHER_CXXFLAGS) $(CXXFLAGS) -c $< -o $@

endif
