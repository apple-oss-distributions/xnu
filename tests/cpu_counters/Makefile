cpu_counters/cpc_security_tests: OTHER_LDFLAGS += -framework kperf -framework kperfdata
cpu_counters/cpc_security_tests: OTHER_CFLAGS += -Wno-format-nonliteral

cpu_counters/kpc_tests: OTHER_CFLAGS += -Wno-declaration-after-statement -I ktrace
cpu_counters/kpc_tests: OTHER_LDFLAGS += -framework ktrace -framework kperf -framework kperfdata -ldarwintest_utils
cpu_counters/kpc_tests: INVALID_ARCHS = i386
cpu_counters/kpc_tests: CODE_SIGN_ENTITLEMENTS = stackshot-entitlements.plist
