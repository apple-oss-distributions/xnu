/*
 * Copyright (c) 2019 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#include <libkern/crypto/sha2.h>
#include <libkern/crypto/crypto.h>
#include <os/atomic_private.h>
#include <kern/assert.h>
#include <kern/percpu.h>
#include <kern/zalloc.h>
#include <kern/lock_group.h>
#include <kern/locks.h>
#include <kern/misc_protos.h>
#include <pexpert/pexpert.h>
#include <prng/entropy.h>
#include <machine/machine_routines.h>
#include <libkern/section_keywords.h>
#include <sys/cdefs.h>

// The number of samples we can hold in an entropy buffer.
#define ENTROPY_MAX_SAMPLE_COUNT (2048)

// The length of a bitmap_t array with one bit per sample of an
// entropy buffer.
#define ENTROPY_MAX_FILTER_COUNT (BITMAP_LEN(ENTROPY_MAX_SAMPLE_COUNT))

// The threshold of approximate linearity used in the entropy
// filter. See the entropy_filter function for more discussion.
#define ENTROPY_FILTER_THRESHOLD (8)

// The state for a per-CPU entropy buffer.
typedef struct entropy_cpu_data {
	// A buffer to hold entropy samples.
	entropy_sample_t samples[ENTROPY_MAX_SAMPLE_COUNT];

	// A count of samples resident in the buffer. It also functions as
	// an index to the buffer. All entries at indices less than the
	// sample count are considered valid for consumption by the
	// reader. The reader resets this to zero after consuming the
	// available entropy.
	uint32_t _Atomic sample_count;
} entropy_cpu_data_t;

// This structure holds the state for an instance of a FIPS continuous
// health test. In practice, we do not expect these tests to fail.
typedef struct entropy_health_test {
	// The initial sample observed in this test instance. Tests look
	// for some repetition of the sample, either consecutively or
	// within a window.
	entropy_sample_t init_observation;

	// The count of times the initial observation has recurred within
	// the span of the current test.
	uint64_t observation_count;

	// The statistics are only relevant for telemetry and parameter
	// tuning. They do not drive any actual logic in the module.
	entropy_health_stats_t *stats;
} entropy_health_test_t;

typedef enum health_test_result {
	health_test_failure,
	health_test_success
} health_test_result_t;

// Along with various counters and the buffer itself, this includes
// the state for two FIPS continuous health tests.
typedef struct entropy_data {
	// State for a SHA512 computation. This is used to accumulate
	// entropy samples from across all CPUs. It is finalized when
	// entropy is provided to the consumer of this module.
	SHA512_CTX sha512_ctx;

	// A buffer to hold a bitmap with one bit per sample of an entropy
	// buffer. We are able to reuse this instance across all the
	// per-CPU entropy buffers to save space.
	bitmap_t filter[ENTROPY_MAX_FILTER_COUNT];

	// A total count of entropy samples that have passed through this
	// structure. It is incremented as new samples are accumulated
	// from the various per-CPU structures. The "current" count of
	// samples is the difference between this field and the "read"
	// sample count below (which see).
	uint64_t total_sample_count;

	// Initially zero, this flag is reset to the current sample count
	// if and when we fail a health test. We consider the startup
	// health tests to be complete when the difference between the
	// total sample count and this field is at least 1024. In other
	// words, we must accumulate 1024 good samples to demonstrate
	// viability. We refuse to provide any entropy before that
	// threshold is reached.
	uint64_t startup_sample_count;

	// The count of samples from the last time we provided entropy to
	// the kernel RNG. We use this to compute how many new samples we
	// have to contribute. This value is also reset to the current
	// sample count in case of health test failure.
	uint64_t read_sample_count;

	// The lock group for this structure; see below.
	lck_grp_t lock_group;

	// This structure accumulates entropy samples from across all CPUs
	// for a single point of consumption protected by a mutex.
	lck_mtx_t mutex;

	// State for the Repetition Count Test.
	entropy_health_test_t repetition_count_test;

	// State for the Adaptive Proportion Test.
	entropy_health_test_t adaptive_proportion_test;
} entropy_data_t;

static entropy_cpu_data_t PERCPU_DATA(entropy_cpu_data);

int entropy_health_startup_done;
entropy_health_stats_t entropy_health_rct_stats;
entropy_health_stats_t entropy_health_apt_stats;
uint64_t entropy_filter_accepted_sample_count;
uint64_t entropy_filter_rejected_sample_count;
uint64_t entropy_filter_total_sample_count;

static entropy_data_t entropy_data = {
	.repetition_count_test = {
		.init_observation = -1,
		.stats = &entropy_health_rct_stats,
	},
	.adaptive_proportion_test = {
		.init_observation = -1,
		.stats = &entropy_health_apt_stats,
	},
};

#if ENTROPY_ANALYSIS_SUPPORTED

__security_const_late int entropy_analysis_enabled;
__security_const_late entropy_sample_t *entropy_analysis_buffer;
__security_const_late uint32_t entropy_analysis_buffer_size;
__security_const_late uint32_t entropy_analysis_filter_size;
__security_const_late uint32_t entropy_analysis_max_sample_count;
uint32_t entropy_analysis_sample_count;

__startup_func
static void
entropy_analysis_init(uint32_t sample_count)
{
	entropy_analysis_enabled = 1;
	entropy_analysis_max_sample_count = sample_count;
	entropy_analysis_buffer_size = sample_count * sizeof(entropy_sample_t);
	entropy_analysis_buffer = zalloc_permanent(entropy_analysis_buffer_size, ZALIGN(entropy_sample_t));
	entropy_analysis_filter_size = (uint32_t) BITMAP_SIZE(entropy_analysis_max_sample_count);
}

static void
entropy_analysis_store(entropy_sample_t sample)
{
	uint32_t sample_count;
	uint32_t next_sample_count;

	os_atomic_rmw_loop(&entropy_analysis_sample_count, sample_count, next_sample_count, relaxed, {
		if (sample_count >= entropy_analysis_max_sample_count) {
		        os_atomic_rmw_loop_give_up(return );
		}

		next_sample_count = sample_count + 1;
	});

	entropy_analysis_buffer[sample_count] = sample;
}

#endif  // ENTROPY_ANALYSIS_SUPPORTED

__startup_func
void
entropy_init(void)
{
	SHA512_Init(&entropy_data.sha512_ctx);

	lck_grp_init(&entropy_data.lock_group, "entropy-data", LCK_GRP_ATTR_NULL);
	lck_mtx_init(&entropy_data.mutex, &entropy_data.lock_group, LCK_ATTR_NULL);

#if ENTROPY_ANALYSIS_SUPPORTED
	// The below path is used only for testing. This boot arg is used
	// to collect raw entropy samples for offline analysis.
	uint32_t sample_count = 0;
	if (__improbable(PE_parse_boot_argn(ENTROPY_ANALYSIS_BOOTARG, &sample_count, sizeof(sample_count)))) {
		entropy_analysis_init(sample_count);
	}
#endif  // ENTROPY_ANALYSIS_SUPPORTED
}

void
entropy_collect(void)
{
	// This function is called from within the interrupt handler, so
	// we do not need to disable interrupts.

	entropy_cpu_data_t *e = PERCPU_GET(entropy_cpu_data);

	uint32_t sample_count = os_atomic_load(&e->sample_count, relaxed);

	assert(sample_count <= ENTROPY_MAX_SAMPLE_COUNT);

	// If the buffer is full, we return early without collecting
	// entropy.
	if (sample_count == ENTROPY_MAX_SAMPLE_COUNT) {
		return;
	}

	entropy_sample_t sample = (entropy_sample_t)ml_get_timebase_entropy();
	e->samples[sample_count] = sample;

	// If the consumer has reset the sample count on us, the only
	// consequence is a dropped sample. We effectively abort the
	// entropy collection in this case.
	(void)os_atomic_cmpxchg(&e->sample_count, sample_count, sample_count + 1, release);

#if ENTROPY_ANALYSIS_SUPPORTED
	// This code path is only used for testing. Its use is governed by
	// a boot arg; see its initialization above.
	if (__improbable(entropy_analysis_buffer)) {
		entropy_analysis_store(sample);
	}
#endif  // ENTROPY_ANALYSIS_SUPPORTED
}

// This filter looks at the 1st differential (differences of subsequent
// timestamp values) and the 2nd differential (differences of subsequent
// 1st differentials). This filter will detect sequences of timestamps
// that are linear (that is, the 2nd differential is close to zero).
// Timestamps with a 2nd differential above the threshold ENTROPY_FILTER_THRESHOLD
// will be marked in the filter bitmap. 2nd differentials below the threshold
// will not be counted nor included in the filter bitmap.
//
// For example imagine the following sequence of 8-bit timestamps:
//
//  [25, 100, 175, 250, 69, 144, 219, 38, 113, 188]
//
// The 1st differential between timestamps is as follows:
//
//  [75, 75, 75, 75, 75, 75, 75, 75, 75]
//
// The 2nd differential is as follows:
//
//  [0, 0, 0, 0, 0, 0, 0, 0]
//
// The first two samples of any set of samples are always included as
// there is no 2nd differential to compare against. Thus all but
// the first two samples in this example will be removed.
uint32_t
entropy_filter(uint32_t sample_count, entropy_sample_t *samples, __assert_only uint32_t filter_count, bitmap_t *filter)
{
	assert(filter_count >= BITMAP_LEN(sample_count));

	bitmap_zero(filter, sample_count);

	// We always keep the first one (or two) sample(s) if we have at least one (or more) samples
	if (sample_count == 0) {
		return 0;
	} else if (sample_count == 1) {
		bitmap_set(filter, 0);
		return 1;
	} else if (sample_count == 2) {
		bitmap_set(filter, 0);
		bitmap_set(filter, 1);
		return 2;
	} else {
		bitmap_set(filter, 0);
		bitmap_set(filter, 1);
	}

	uint32_t filtered_sample_count = 2;

	// We don't care about underflows when computing any differential
	entropy_sample_t prev_1st_differential = samples[1] - samples[0];

	for (uint i = 2; i < sample_count; i++) {
		entropy_sample_t curr_1st_differential = samples[i] - samples[i - 1];

		entropy_sample_t curr_2nd_differential = curr_1st_differential - prev_1st_differential;

		if (curr_2nd_differential > ENTROPY_FILTER_THRESHOLD && curr_2nd_differential < ((entropy_sample_t) -ENTROPY_FILTER_THRESHOLD)) {
			bitmap_set(filter, i);
			filtered_sample_count += 1;
		}

		prev_1st_differential = curr_1st_differential;
	}

	return filtered_sample_count;
}

// For information on the following tests, see NIST SP 800-90B 4
// Health Tests. These tests are intended to detect catastrophic
// degradations in entropy. As noted in that document:
//
// > Health tests are expected to raise an alarm in three cases:
// > 1. When there is a significant decrease in the entropy of the
// > outputs,
// > 2. When noise source failures occur, or
// > 3. When hardware fails, and implementations do not work
// > correctly.
//
// Each entropy accumulator declines to release entropy until the
// startup tests required by NIST are complete. In the event that a
// health test does fail, all entropy accumulators are reset and
// decline to release further entropy until their startup tests can be
// repeated.

static health_test_result_t
add_observation(entropy_health_test_t *t, uint64_t bound)
{
	t->observation_count += 1;
	t->stats->max_observation_count = MAX(t->stats->max_observation_count, (uint32_t)t->observation_count);
	if (__improbable(t->observation_count >= bound)) {
		t->stats->failure_count += 1;
		return health_test_failure;
	}

	return health_test_success;
}

static void
reset_test(entropy_health_test_t *t, entropy_sample_t observation)
{
	t->stats->reset_count += 1;
	t->init_observation = observation;
	t->observation_count = 1;
	t->stats->max_observation_count = MAX(t->stats->max_observation_count, (uint32_t)t->observation_count);
}

// 4.4.1 Repetition Count Test
//
// Like the name implies, this test counts consecutive occurrences of
// the same value.
//
// We compute the bound C as:
//
// A = 2^-40
// H = 1
// C = 1 + ceil(-log(A, 2) / H) = 41
//
// With A the acceptable chance of false positive and H a conservative
// estimate for the min-entropy (in bits) of each sample.
//
// For more information, see tools/entropy_health_test_bounds.py.

#define REPETITION_COUNT_BOUND (41)

static health_test_result_t
repetition_count_test(entropy_sample_t observation)
{
	entropy_health_test_t *t = &entropy_data.repetition_count_test;

	if (t->init_observation == observation) {
		return add_observation(t, REPETITION_COUNT_BOUND);
	} else {
		reset_test(t, observation);
	}

	return health_test_success;
}

// 4.4.2 Adaptive Proportion Test
//
// This test counts occurrences of a value within a window of samples.
//
// We use a non-binary alphabet, giving us a window size of 512. (In
// particular, we consider the least-significant byte of each time
// sample.)
//
// Assuming one bit of entropy, we can compute the binomial cumulative
// distribution function over 512 trials and choose a bound such that
// the false positive rate is less than our target.
//
// For false positive rate and min-entropy estimate as above:
//
// A = 2^-40
// H = 1
//
// We have our bound:
//
// C = 336
//
// For more information, see tools/entropy_health_test_bounds.py.

#define ADAPTIVE_PROPORTION_BOUND (336)
#define ADAPTIVE_PROPORTION_WINDOW (512)

// This mask definition requires the window be a power of two.
static_assert(__builtin_popcount(ADAPTIVE_PROPORTION_WINDOW) == 1);
#define ADAPTIVE_PROPORTION_INDEX_MASK (ADAPTIVE_PROPORTION_WINDOW - 1)

static health_test_result_t
adaptive_proportion_test(entropy_sample_t observation, uint32_t offset)
{
	entropy_health_test_t *t = &entropy_data.adaptive_proportion_test;

	// We work in windows of size ADAPTIVE_PROPORTION_WINDOW, so we
	// can compute our index by taking the entropy buffer's overall
	// sample count plus the offset of this observation modulo the
	// window size.
	uint32_t index = (entropy_data.total_sample_count + offset) & ADAPTIVE_PROPORTION_INDEX_MASK;

	if (index == 0) {
		reset_test(t, observation);
	} else if (t->init_observation == observation) {
		return add_observation(t, ADAPTIVE_PROPORTION_BOUND);
	}

	return health_test_success;
}

static health_test_result_t
entropy_health_test(uint32_t sample_count, entropy_sample_t *samples, __assert_only uint32_t filter_count, bitmap_t *filter)
{
	health_test_result_t result = health_test_success;

	assert(filter_count >= BITMAP_LEN(sample_count));

	for (uint32_t i = 0; i < sample_count; i += 1) {
		// We use the filter to determine if a given sample "counts"
		// or not. We skip the health tests on those samples that
		// failed the filter, since they are not expected to provide
		// any entropy.
		if (!bitmap_test(filter, i)) {
			continue;
		}

		// We only consider the low bits of each sample, since that is
		// where we expect the entropy to be concentrated.
		entropy_sample_t observation = samples[i] & 0xff;

		if (__improbable(repetition_count_test(observation) == health_test_failure)) {
			result = health_test_failure;
		}

		if (__improbable(adaptive_proportion_test(observation, i) == health_test_failure)) {
			result = health_test_failure;
		}
	}

	return result;
}

int32_t
entropy_provide(size_t *entropy_size, void *entropy, __unused void *arg)
{
#if (DEVELOPMENT || DEBUG)
	if (*entropy_size < SHA512_DIGEST_LENGTH) {
		panic("[entropy_provide] recipient entropy buffer is too small");
	}
#endif

	int32_t sample_count = 0;
	*entropy_size = 0;

	// There is only one consumer (the kernel PRNG), but they could
	// try to consume entropy from different threads. We simply fail
	// if a consumption is already in progress.
	if (!lck_mtx_try_lock(&entropy_data.mutex)) {
		return sample_count;
	}

	health_test_result_t health_test_result = health_test_success;

	// We accumulate entropy from all CPUs.
	percpu_foreach(e, entropy_cpu_data) {
		// On each CPU, the sample count functions as an index into
		// the entropy buffer. All samples before that index are valid
		// for consumption.
		uint32_t cpu_sample_count = os_atomic_load(&e->sample_count, acquire);

		assert(cpu_sample_count <= ENTROPY_MAX_SAMPLE_COUNT);

		// We'll calculate how many samples that we would filter out
		// and only add that many to the total_sample_count. The bitmap
		// is not used during this operation.
		uint32_t filtered_sample_count = entropy_filter(cpu_sample_count, e->samples, ENTROPY_MAX_FILTER_COUNT, entropy_data.filter);
		assert(filtered_sample_count <= cpu_sample_count);

		entropy_filter_total_sample_count += cpu_sample_count;
		entropy_filter_accepted_sample_count += filtered_sample_count;
		entropy_filter_rejected_sample_count += (cpu_sample_count - filtered_sample_count);

		// The health test depends in part on the current state of
		// the entropy data, so we test the new sample before
		// accumulating it.
		health_test_result_t cpu_health_test_result = entropy_health_test(cpu_sample_count, e->samples, ENTROPY_MAX_FILTER_COUNT, entropy_data.filter);
		if (__improbable(cpu_health_test_result == health_test_failure)) {
			health_test_result = health_test_failure;
		}

		// We accumulate the samples regardless of whether the test
		// failed or a particular sample was filtered. It cannot hurt.
		entropy_data.total_sample_count += filtered_sample_count;
		SHA512_Update(&entropy_data.sha512_ctx, e->samples, cpu_sample_count * sizeof(e->samples[0]));

		// "Drain" the per-CPU buffer by resetting its sample count.
		os_atomic_store(&e->sample_count, 0, relaxed);
	}

	// We expect this never to happen.
	//
	// But if it does happen, we need to return negative to signal the
	// consumer (i.e. the kernel PRNG) that there has been a failure.
	if (__improbable(health_test_result == health_test_failure)) {
		entropy_health_startup_done = 0;
		entropy_data.startup_sample_count = entropy_data.total_sample_count;
		entropy_data.read_sample_count = entropy_data.total_sample_count;
		sample_count = -1;
		goto out;
	}

	// FIPS requires we pass our startup health tests before providing
	// any entropy. This condition is only true during startup and in
	// case of reset due to test failure.
	if (__improbable((entropy_data.total_sample_count - entropy_data.startup_sample_count) < 1024)) {
		goto out;
	}

	entropy_health_startup_done = 1;

	// The count of new samples from the consumer's perspective.
	int32_t n = (int32_t)(entropy_data.total_sample_count - entropy_data.read_sample_count);

	// Assuming one bit of entropy per sample, we buffer at least 512
	// samples before delivering a high-entropy payload. In theory,
	// each payload will be a 512-bit seed with full entropy.
	//
	// We buffer an additional 64 bits of entropy to satisfy
	// over-sampling requirements in FIPS 140-3 IG.
	if (n < (512 + 64)) {
		goto out;
	}

	// Extract the entropy seed from the digest context and adjust
	// counters accordingly.
	SHA512_Final(entropy, &entropy_data.sha512_ctx);
	entropy_data.read_sample_count = entropy_data.total_sample_count;
	sample_count = n;
	*entropy_size = SHA512_DIGEST_LENGTH;

	// Reinitialize the digest context for future entropy
	// conditioning.
	SHA512_Init(&entropy_data.sha512_ctx);

	// To harden the entropy conditioner against an attacker with
	// partial or temporary control of interrupts, we roll the
	// extracted seed back into the new digest context. Assuming
	// we are able to reach a threshold of entropy, we can prevent
	// the attacker from predicting future output seeds.
	//
	// Along with the seed, we mix in a fixed label to personalize
	// this context.
	const char label[SHA512_BLOCK_LENGTH - SHA512_DIGEST_LENGTH] = "xnu entropy extract seed";

	// We need the combined size of our inputs to equal the
	// internal SHA512 block size. This will force an additional
	// compression to provide backtracking resistance.
	assert(sizeof(label) + *entropy_size == SHA512_BLOCK_LENGTH);
	SHA512_Update(&entropy_data.sha512_ctx, label, sizeof(label));
	SHA512_Update(&entropy_data.sha512_ctx, entropy, *entropy_size);

out:
	lck_mtx_unlock(&entropy_data.mutex);

	return sample_count;
}
