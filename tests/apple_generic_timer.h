#pragma once

#include <darwintest.h>

#define TEST_ITERATIONS         10000000
#define ITERATIONS_BETWEEN_LOGS 100000

#define CNTFREQ_24_MHZ          24000000ULL
#define CNTFREQ_1_GHZ           1000000000ULL

#if __arm64__
static void
agt_test_helper(bool expect_1ghz)
{
	for (unsigned i = 0; i < TEST_ITERATIONS; i++) {
		const uint64_t freq = __builtin_arm_rsr64("CNTFRQ_EL0");

		if (expect_1ghz) {
			T_QUIET; T_ASSERT_EQ(freq, CNTFREQ_1_GHZ, "Expecting CNTFRQ_EL0 reads 1 GHz");
		} else {
			T_QUIET; T_ASSERT_EQ(freq, CNTFREQ_24_MHZ, "Expecting CNTFRQ_EL0 reads 24 MHz");
		}

		if (i % ITERATIONS_BETWEEN_LOGS == 0) {
			T_LOG("%s: %u iterations ...", __func__, i);
		}
	}
}
#endif /* __arm64__ */
