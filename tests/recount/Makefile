RECOUNT_UTILS = recount/recount_test_utils.c
WARNING_CFLAGS = -Wno-declaration-after-statement -Wno-bad-function-cast
EXCLUDED_SOURCES += $(RECOUNT_UTILS)

recount/thread_selfcounts_tests: $(RECOUNT_UTILS)
recount/thread_selfcounts_tests: OTHER_CFLAGS += -l darwintest_utils $(WARNING_CFLAGS)
recount/rusage_tests: $(RECOUNT_UTILS)
recount/rusage_tests: OTHER_CFLAGS += -l darwintest_utils $(WARNING_CFLAGS)
recount/recount_tests: $(RECOUNT_UTILS)
recount/recount_tests: OTHER_CFLAGS += -l darwintest_utils $(WARNING_CFLAGS)
recount/recount_perf_tests: $(RECOUNT_UTILS)
recount/recount_perf_tests: OTHER_CFLAGS += -l darwintest_utils $(WARNING_CFLAGS)
