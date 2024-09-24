/*
 * Copyright (c) 2013 Apple Inc. All rights reserved.
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

#include <kern/locks.h>
#include <kern/cpu_number.h>
#include <libkern/section_keywords.h>
#include <libkern/crypto/sha2.h>
#include <machine/machine_cpu.h>
#include <machine/machine_routines.h>
#include <pexpert/pexpert.h>
#include <sys/random.h>
#include <prng/random.h>
#include <prng/entropy.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccdigest_priv.h>
#include <corecrypto/ccdrbg.h>
#include <corecrypto/cckprng.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/cchkdf.h>

static struct cckprng_ctx *prng_ctx;

static SECURITY_READ_ONLY_LATE(struct cckprng_funcs) prng_funcs;
static SECURITY_READ_ONLY_LATE(int) prng_ready;

#define SEED_SIZE (SHA256_BLOCK_LENGTH)

// Seed sizes meant to trigger a compression in the underlying hash function
static uint8_t earlyseed[SEED_SIZE];
static uint8_t prngseed[SEED_SIZE];
static uint8_t entropyseed[SHA512_BLOCK_LENGTH];

// Instructions for deriving the above seeds
typedef struct dsp {
	size_t info_size;
	size_t dst_size;
	void *info;
	void *dst;
} derived_seed_param;

// These are HKDF-Expand parameters for derived seeds. To add a new one, add a new struct here.
static derived_seed_param seed_params[] = {
	{
		.info = "bootseed_init",
		.info_size = 14,
		.dst = earlyseed,
		.dst_size = sizeof(earlyseed)
	},
	{
		.info = "prngseed_init",
		.info_size = 14,
		.dst = prngseed,
		.dst_size = sizeof(prngseed)
	},
	{
		.info = "entropy_init",
		.info_size = 13,
		.dst = entropyseed,
		.dst_size = sizeof(entropyseed)
	}
};

// Hash the seed to ensure uniformity. But we have a limited-size digest available, so we make two invocations:
// out[0:SHA256_DIGEST_LENGTH]          = H(seed || 0)
// out[SHA256_DIGEST_LENGTH:SEED_SIZE]  = H(seed || 1)
static void
wide_hash(const struct ccdigest_info *di, uint8_t *dst, uint8_t *src)
{
	uint8_t counter;
	ccdigest_di_decl(di, ectx_left);
	ccdigest_init(di, ectx_left);
	ccdigest_update(di, ectx_left, SEED_SIZE, src);
	ccdigest_di_decl(di, ectx_right);
	ccdigest_copy_state(di, ectx_right, ectx_left);

	counter = 0;
	ccdigest_update(di, ectx_left, sizeof(counter), &counter);
	ccdigest_final(di, ectx_left, dst);

	counter = 1;
	ccdigest_update(di, ectx_right, sizeof(counter), &counter);
	ccdigest_final(di, ectx_right, &dst[SEED_SIZE / 2]);

	ccdigest_di_clear(di, ectx_left);
	ccdigest_di_clear(di, ectx_right);
}

static void
bootseed_init_bootloader(const struct ccdigest_info *di, uint8_t *dst)
{
	uint8_t seed[SEED_SIZE];
	uint32_t n;

	n = PE_get_random_seed(seed, SEED_SIZE);
	if (n < SEED_SIZE) {
		/*
		 * Insufficient entropy is fatal.  We must fill the
		 * entire entropy buffer during initializaton.
		 */
		panic("Expected %u seed bytes from bootloader, but got %u.", SEED_SIZE, n);
	}

	wide_hash(di, dst, seed);
	cc_clear(SEED_SIZE, seed);
}

#if defined(__x86_64__)
#include <i386/cpuid.h>

static void
bootseed_init_native(const struct ccdigest_info *di, uint8_t *dst)
{
	uint8_t seed[SEED_SIZE];
	uint64_t x;
	uint8_t ok;
	size_t i = 0;
	size_t n;

	if (cpuid_leaf7_features() & CPUID_LEAF7_FEATURE_RDSEED) {
		n = SEED_SIZE / sizeof(x);

		while (i < n) {
			asm volatile ("rdseed %0; setc %1" : "=r"(x), "=qm"(ok) : : "cc");
			if (ok) {
				cc_memcpy(&seed[i * sizeof(x)], &x, sizeof(x));
				i += 1;
			} else {
				// Intel recommends to pause between unsuccessful rdseed attempts.
				cpu_pause();
			}
		}
	} else if (cpuid_features() & CPUID_FEATURE_RDRAND) {
		// The Intel documentation guarantees a reseed every 512 rdrand calls.
		n = (SEED_SIZE / sizeof(x)) * 512;

		while (i < n) {
			asm volatile ("rdrand %0; setc %1" : "=r"(x), "=qm"(ok) : : "cc");
			if (ok) {
				if (i % 512 == 0) {
					cc_memcpy(&dst[(i / 512) * sizeof(x)], &x, sizeof(x));
				}
				i += 1;
			} else {
				// Intel does not recommend pausing between unsuccessful rdrand attempts.
			}
		}
	}

	wide_hash(di, dst, seed);
	cc_clear(SEED_SIZE, seed);
	cc_clear(sizeof(x), &x);
}

#else

static void
bootseed_init_native(__unused const struct ccdigest_info *di, uint8_t *dst)
{
	// Even if we don't have any input, the second input needs to be a fixed input of the same size
	// to maintain dual-PRF security for HKDF/HMAC. All zero is fine as long as it is fixed.
	cc_clear(SEED_SIZE, dst);
}

#endif

static void
bootseed_init(void)
{
	/*
	 *  This is a key combiner. HKDF provides dual-PRF security as long as we sample inputs
	 *  from a set of fixed-length, uniformly random inputs. Ideally those inputs will also
	 *  be the block size of the underlying digest, which we specify here with SEED_SIZE.
	 *
	 *  See https://eprint.iacr.org/2023/861 for proof details. The overall construction goes:
	 *
	 *       H* : {0, 1}* -> {0, 1}^c where c is the block size of the digest underlying HKDF, here 64.
	 *       n are long enough to require a compression in the underlying hash function.
	 *       prk = HKDF-Extract(H*(bootloader), H*(native))
	 *       earlyseed = HKDF-Expand(prk, "bootseed_init", n1)
	 *       prngseed = HKDF-Expand(prk, "prngseed_init", n2)
	 *		 entropyseed = HKDF-Expand(prk, "entropy_init", n3)
	 *
	 */

	const struct ccdigest_info * di = &ccsha256_ltc_di;
	assert3u(SEED_SIZE, ==, di->block_size);

	uint8_t bootloader_rand[SEED_SIZE];
	uint8_t native_rand[SEED_SIZE];
	uint8_t prk[SHA256_DIGEST_LENGTH];

	// Sample the two input seeds from the devicetree and any available RDRAND instructions
	bootseed_init_bootloader(di, bootloader_rand);
	bootseed_init_native(di, native_rand);

	// Combine the input seeds into one root seed of size di->output_size. Eventually we want to use a larger digest here:
	// rdar://119642787 (Move boot seed derivations to a digest that preserves the full width of the devicetree seed)
	int result = cchkdf_extract(di, SEED_SIZE, native_rand, SEED_SIZE, bootloader_rand, prk);
	if (result != CCERR_OK) {
		panic("Early boot random cchkdf_extract failed with err %d", result);
	}

	// Derive independent keys for each subsystem
	int seeds_expected = sizeof(seed_params) / sizeof(seed_params[0]);
	for (int i = 0; i < seeds_expected; i++) {
		derived_seed_param sp = seed_params[i];
		result = cchkdf_expand(di, di->output_size, prk, sp.info_size, sp.info, sp.dst_size, sp.dst);
		if (result != CCERR_OK) {
			panic("Early boot random cchkdf_expand %s failed with err %d", sp.info, result);
		}
	}

	cc_clear(di->output_size, prk);
	cc_clear(SEED_SIZE, bootloader_rand);
	cc_clear(SEED_SIZE, native_rand);
}

#define EARLY_RANDOM_STATE_STATIC_SIZE (264)

static struct {
	uint8_t drbg_state[EARLY_RANDOM_STATE_STATIC_SIZE];
	struct ccdrbg_info drbg_info;
	const struct ccdrbg_nisthmac_custom drbg_custom;
} erandom = {.drbg_custom = {
		     .di         = &ccsha256_ltc_di,
		     .strictFIPS = 0,
	     }};

__attribute__((noinline))
static void
early_random_init(void)
{
	uint64_t nonce;
	int rc;
	const char ps[] = "xnu early random";

	bootseed_init();

	/* Init DRBG for NIST HMAC */
	ccdrbg_factory_nisthmac(&erandom.drbg_info, &erandom.drbg_custom);
	assert3u(erandom.drbg_info.size, <=, sizeof(erandom.drbg_state));

	/*
	 * Init our DBRG from the boot entropy and a timestamp as nonce
	 * and the cpu number as personalization.
	 */
	assert3u(sizeof(earlyseed), >, sizeof(nonce));
	nonce = ml_get_timebase();
	rc = ccdrbg_init(&erandom.drbg_info, (struct ccdrbg_state *)erandom.drbg_state, sizeof(earlyseed), earlyseed, sizeof(nonce), &nonce, sizeof(ps) - 1, ps);
	if (rc != CCDRBG_STATUS_OK) {
		panic("ccdrbg_init() returned %d", rc);
	}

	cc_clear(sizeof(nonce), &nonce);
	cc_clear(sizeof(earlyseed), earlyseed);
}

static void read_erandom(void * buf, size_t nbytes);

/*
 * Return a uniformly distributed 64-bit random number.
 *
 * This interface should have minimal dependencies on kernel services,
 * and thus be available very early in the life of the kernel.
 *
 * This provides cryptographically secure randomness contingent on the
 * quality of the seed. It is seeded (lazily) with entropy provided by
 * the Booter.
 *
 * The implementation is a NIST HMAC-SHA256 DRBG instance used as
 * follows:
 *
 *  - When first called (on macOS this is very early while page tables
 *    are being built) early_random() calls ccdrbg_factory_hmac() to
 *    set-up a ccdbrg info structure.
 *
 *  - The boot seed (64 bytes) is hashed with a SHA256-based wide hash
 *    construction. Where available, hardware RNG outputs are mixed
 *    into the seed. (See bootseed_init.) The resulting seed is 64
 *    bytes.
 *
 *  - The ccdrbg state structure is a statically allocated area which
 *    is then initialized by calling the ccdbrg_init method. The
 *    initial entropy is the 32-byte seed described above. The nonce
 *    is an 8-byte timestamp from ml_get_timebase(). The
 *    personalization data provided is a fixed string.
 *
 *  - 64-bit outputs are generated via read_erandom, a wrapper around
 *    the ccdbrg_generate method. (Since "strict FIPS" is disabled,
 *    the DRBG will never request a reseed.)
 *
 *  - After the kernel PRNG is initialized, read_erandom defers
 *    generation to it via read_random_generate. (Note that this
 *    function acquires a per-processor mutex.)
 */
uint64_t
early_random(void)
{
	uint64_t result;
	static int init = 0;

	if (__improbable(init == 0)) {
		early_random_init();
		init = 1;
	}

	read_erandom(&result, sizeof(result));

	return result;
}

static void
read_random_generate(uint8_t *buffer, size_t numbytes);

// This code is used only during early boot (until corecrypto kext is
// loaded), so it's better not to inline it.
__attribute__((noinline))
static void
read_erandom_generate(void * buf, size_t nbytes)
{
	uint8_t * buffer_bytes = buf;
	size_t n;
	int rc;

	// The DBRG request size is limited, so we break the request into
	// chunks.
	while (nbytes > 0) {
		n = MIN(nbytes, PAGE_SIZE);

		// Since "strict FIPS" is disabled, the DRBG will never
		// request a reseed; therefore, we panic on any error
		rc = ccdrbg_generate(&erandom.drbg_info, (struct ccdrbg_state *)erandom.drbg_state, n, buffer_bytes, 0, NULL);
		if (rc != CCDRBG_STATUS_OK) {
			panic("read_erandom ccdrbg error %d", rc);
		}

		buffer_bytes += n;
		nbytes -= n;
	}
}

static void
read_erandom(void * buf, size_t nbytes)
{
	// We defer to the kernel PRNG after it has been installed and
	// initialized. This happens during corecrypto kext
	// initialization.
	if (__probable(prng_ready)) {
		read_random_generate(buf, nbytes);
	} else {
		read_erandom_generate(buf, nbytes);
	}
}

void
read_frandom(void * buffer, u_int numBytes)
{
	read_erandom(buffer, numBytes);
}

void
register_and_init_prng(struct cckprng_ctx *ctx, const struct cckprng_funcs *funcs)
{
	assert3s(cpu_number(), ==, master_cpu);
	assert(!prng_ready);

	entropy_init(sizeof(entropyseed), entropyseed);

	prng_ctx = ctx;
	prng_funcs = *funcs;

	uint64_t nonce = ml_get_timebase();
	prng_funcs.init_with_getentropy(prng_ctx, MAX_CPUS, sizeof(prngseed), prngseed, sizeof(nonce), &nonce, entropy_provide, NULL);
	prng_funcs.initgen(prng_ctx, master_cpu);
	prng_ready = 1;

	cc_clear(sizeof(entropyseed), entropyseed);
	cc_clear(sizeof(prngseed), prngseed);
	cc_clear(sizeof(erandom), &erandom);
}

void
random_cpu_init(int cpu)
{
	assert3s(cpu, !=, master_cpu);

	if (!prng_ready) {
		panic("random_cpu_init: kernel prng has not been installed");
	}

	prng_funcs.initgen(prng_ctx, cpu);
}

/* export good random numbers to the rest of the kernel */
void
read_random(void * buffer, u_int numbytes)
{
	prng_funcs.refresh(prng_ctx);
	read_random_generate(buffer, numbytes);
}

static void
ensure_gsbase(void)
{
#if defined(__x86_64__) && (DEVELOPMENT || DEBUG)
	/*
	 * Calling cpu_number() before gsbase is initialized is potentially
	 * catastrophic, so assert that it's not set to the magic value set
	 * in i386_init.c before proceeding with the call.  We cannot use
	 * assert here because it ultimately calls panic, which executes
	 * operations that involve accessing %gs-relative data (and additionally
	 * causes a debug trap which will not work properly this early in boot.)
	 */
	if (rdmsr64(MSR_IA32_GS_BASE) == EARLY_GSBASE_MAGIC) {
		kprintf("[early_random] Cannot proceed: GSBASE is not initialized\n");
		hlt();
		/*NOTREACHED*/
	}
#endif
}

static void
read_random_generate(uint8_t *buffer, size_t numbytes)
{
	ensure_gsbase();

	while (numbytes > 0) {
		size_t n = MIN(numbytes, CCKPRNG_GENERATE_MAX_NBYTES);

		prng_funcs.generate(prng_ctx, cpu_number(), n, buffer);

		buffer += n;
		numbytes -= n;
	}
}

int
write_random(void * buffer, u_int numbytes)
{
	uint8_t seed[SHA256_DIGEST_LENGTH];
	SHA256_CTX ctx;

	/* hash the input to minimize the time we need to hold the lock */
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, buffer, numbytes);
	SHA256_Final(seed, &ctx);

	prng_funcs.reseed(prng_ctx, sizeof(seed), seed);
	cc_clear(sizeof(seed), seed);

	return 0;
}

/*
 * Boolean PRNG for generating booleans to randomize order of elements
 * in certain kernel data structures. The algorithm is a
 * modified version of the KISS RNG proposed in the paper:
 * http://stat.fsu.edu/techreports/M802.pdf
 * The modifications have been documented in the technical paper
 * paper from UCL:
 * http://www0.cs.ucl.ac.uk/staff/d.jones/GoodPracticeRNG.pdf
 */

/* Initialize the PRNG structures. */
void
random_bool_init(struct bool_gen * bg)
{
	/* Seed the random boolean generator */
	read_frandom(bg->seed, sizeof(bg->seed));
	bg->state = 0;
	simple_lock_init(&bg->lock, 0);
}

/* Generate random bits and add them to an entropy pool. */
void
random_bool_gen_entropy(struct bool_gen * bg, unsigned int * buffer, int count)
{
	simple_lock(&bg->lock, LCK_GRP_NULL);
	int i, t;
	for (i = 0; i < count; i++) {
		bg->seed[1] ^= (bg->seed[1] << 5);
		bg->seed[1] ^= (bg->seed[1] >> 7);
		bg->seed[1] ^= (bg->seed[1] << 22);
		t           = bg->seed[2] + bg->seed[3] + bg->state;
		bg->seed[2] = bg->seed[3];
		bg->state   = t < 0;
		bg->seed[3] = t & 2147483647;
		bg->seed[0] += 1411392427;
		buffer[i] = (bg->seed[0] + bg->seed[1] + bg->seed[3]);
	}
	simple_unlock(&bg->lock);
}

/* Get some number of bits from the entropy pool, refilling if necessary. */
unsigned int
random_bool_gen_bits(struct bool_gen * bg, unsigned int * buffer, unsigned int count, unsigned int numbits)
{
	unsigned int index = 0;
	unsigned int rbits = 0;
	for (unsigned int bitct = 0; bitct < numbits; bitct++) {
		/*
		 * Find a portion of the buffer that hasn't been emptied.
		 * We might have emptied our last index in the previous iteration.
		 */
		while (index < count && buffer[index] == 0) {
			index++;
		}

		/* If we've exhausted the pool, refill it. */
		if (index == count) {
			random_bool_gen_entropy(bg, buffer, count);
			index = 0;
		}

		/* Collect-a-bit */
		unsigned int bit = buffer[index] & 1;
		buffer[index]    = buffer[index] >> 1;
		rbits            = bit | (rbits << 1);
	}
	return rbits;
}
