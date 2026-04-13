/*
 * Copyright (c) 2025 Apple Inc. All rights reserved.
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

#include "random.h"

#include <machine/machine_routines.h>

// written in 2015 by Sebastiano Vigna https://prng.di.unimi.it/splitmix64.c
static inline uint64_t
splitmix64_next(uint64_t *state)
{
	uint64_t z = (*state += 0x9e3779b97f4a7c15);
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9;
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb;
	return z ^ (z >> 31);
}

static inline uint64_t
rotl64(uint64_t x, int8_t r)
{
	return (x << r) | (x >> (64 - r));
}

// fast alternative to x % n
static inline uint64_t
fast_bound(uint64_t x, uint64_t n)
{
	uint128_t mul = (uint128_t)x * (uint128_t)n;
	return (uint64_t)(mul >> 64);
}

// initial state as if random_set_seed(1337) was called
struct random_r global_random = {
	.romuduojr_x_state = 13161956497586561035ull,
	.romuduojr_y_state = 14663483216071361993ull
};

void
random_r_set_seed(random_r_t *random, uint64_t seed)
{
	random->romuduojr_x_state = splitmix64_next(&seed);
	random->romuduojr_y_state = splitmix64_next(&seed);
}

uint64_t
random_r_next(random_r_t *random)
{
	const uint64_t xp = random->romuduojr_x_state;
	random->romuduojr_x_state = 15241094284759029579ull * random->romuduojr_y_state;
	random->romuduojr_y_state = random->romuduojr_y_state - xp;
	random->romuduojr_y_state = rotl64(random->romuduojr_y_state, 27);
	return xp;
}

uint64_t
random_r_below(random_r_t *random, uint64_t upper_bound)
{
	return fast_bound(random_r_next(random), upper_bound);
}

void
random_set_seed(uint64_t seed)
{
	random_r_set_seed(&global_random, seed);
}

uint64_t
random_next(void)
{
	return random_r_next(&global_random);
}

uint64_t
random_below(uint64_t upper_bound)
{
	return random_r_below(&global_random, upper_bound);
}
