RECOUNT_UTILS = recount/recount_test_utils.c
EXCLUDED_SOURCES += $(RECOUNT_UTILS)

recount/thread_selfcounts_tests: $(RECOUNT_UTILS)
recount/thread_selfcounts_tests: OTHER_CFLAGS += -l darwintest_utils
recount/rusage_tests: $(RECOUNT_UTILS)
recount/rusage_tests: OTHER_CFLAGS += -l darwintest_utils
recount/recount_tests: $(RECOUNT_UTILS)
recount/recount_tests: OTHER_CFLAGS += -l darwintest_utils
recount/recount_perf_tests: $(RECOUNT_UTILS)
recount/recount_perf_tests: OTHER_CFLAGS += -l darwintest_utils
recount/recount_perf_tests: OTHER_CFLAGS += -Wno-bad-function-cast
