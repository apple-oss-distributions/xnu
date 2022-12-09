/*
 * Copyright (c) 2016 Apple Computer, Inc. All rights reserved.
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

#ifndef _RAND_H
#define _RAND_H

#include <libkern/crypto/crypto.h>

__BEGIN_DECLS

// A handle to a random generator suitable for use with
// crypto_random_generate.
typedef void *crypto_random_ctx_t;

// The maximum size (in bytes) of a random generator.
#define CRYPTO_RANDOM_MAX_CTX_SIZE ((size_t)256)

typedef void (*crypto_random_generate_fn_t)(
	crypto_random_ctx_t ctx,
	void *random,
	size_t random_size);

typedef void (*crypto_random_uniform_fn_t)(
	crypto_random_ctx_t ctx,
	uint64_t bound,
	uint64_t *random);

typedef size_t (*crypto_random_kmem_ctx_size_fn_t)(void);

typedef void (*crypto_random_kmem_init_fn_t)(
	crypto_random_ctx_t ctx);

#if XNU_KERNEL_PRIVATE

int cc_rand_generate(void *out, size_t outlen);

// Generate random data with the supplied handle to a random
// generator. The behavior of this function (e.g. the quality of the
// randomness, whether it might acquire a lock, the cryptographic
// primitives used) depends on the semantics of the generator.
void crypto_random_generate(
	crypto_random_ctx_t ctx,
	void *random,
	size_t random_size);

// Generate a random value in the range [0, bound), i.e. including
// zero and excluding the bound. The generated value is stored in the
// random pointer which should point to a single value. As above, the
// behavior of this function depends in part on the semantics of the
// generator.
void crypto_random_uniform(
	crypto_random_ctx_t ctx,
	uint64_t bound,
	uint64_t *random);

// The following two functions are for use in the kmem subsystem
// only. They are NOT guaranteed to provide cryptographic randomness
// and should not be used elsewhere.

// Return the size needed for a random generator to be used by
// kmem. (See the discussion below for the semantics of this
// generator.)
//
// The returned value may vary by platform, but it is guaranteed to be
// no larger than CRYPTO_RANDOM_MAX_CTX_SIZE.
size_t crypto_random_kmem_ctx_size(void);

// Initialize the handle with a random generator for use by kmem. This
// function should only be called by kmem.
//
// The handle should point to memory at least as large as
// crypto_random_kmem_ctx_size() indicates.
//
// This generator is NOT guaranteed to provide cryptographic
// randomness.
//
// The initialized generator is guaranteed not to acquire a
// lock. (Note, however, that this initialization function MAY acquire
// a lock.)
//
// The initialized generator is guaranteed not to touch FP registers
// on Intel.
void crypto_random_kmem_init(
	crypto_random_ctx_t ctx);

#endif  /* XNU_KERNEL_PRIVATE */

int random_buf(void *buf, size_t buflen);

__END_DECLS

#endif
