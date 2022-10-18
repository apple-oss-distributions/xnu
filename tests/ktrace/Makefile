INCLUDED_TEST_SOURCE_DIRS += ktrace
EXCLUDED_SOURCES += ktrace/kperf_helpers.c
KTRACE_LDFLAGS = -framework ktrace -framework kperf -framework kperfdata -ldarwintest_utils

ktrace/kdebug_tests: INVALID_ARCHS = i386
ktrace/kdebug_tests: OTHER_LDFLAGS = $(KTRACE_LDFLAGS)
ktrace/kdebug_tests: OTHER_CFLAGS += test_utils.c
ktrace/kdebug_tests: CODE_SIGN_ENTITLEMENTS = stackshot-entitlements.plist

ktrace/kdebug_coproc_tests: INVALID_ARCHS = i386
ktrace/kdebug_coproc_tests: OTHER_LDFLAGS = $(KTRACE_LDFLAGS)
ktrace/kdebug_coproc_tests: OTHER_CFLAGS += test_utils.c
ktrace/kdebug_coproc_tests: CODE_SIGN_ENTITLEMENTS = stackshot-entitlements.plist

ktrace/kpc_tests: OTHER_LDFLAGS += $(KTRACE_LDFLAGS)
ktrace/kpc_tests: INVALID_ARCHS = i386
ktrace/kpc_tests: CODE_SIGN_ENTITLEMENTS = stackshot-entitlements.plist

ktrace/kperf_tests: OTHER_CFLAGS += ktrace/kperf_helpers.c drop_priv.c
ktrace/kperf_tests: OTHER_LDFLAGS += $(KTRACE_LDFLAGS)
ktrace/kperf_tests: CODE_SIGN_ENTITLEMENTS = stackshot-entitlements.plist

ktrace/kperf_backtracing_tests: OTHER_CFLAGS += ktrace/kperf_helpers.c
ktrace/kperf_backtracing_tests: OTHER_LDFLAGS += $(KTRACE_LDFLAGS)
ktrace/kperf_backtracing_tests: OTHER_LDFLAGS += -framework CoreSymbolication
ktrace/kperf_backtracing_tests: CODE_SIGN_ENTITLEMENTS = kernel_symbolication_entitlements.plist
