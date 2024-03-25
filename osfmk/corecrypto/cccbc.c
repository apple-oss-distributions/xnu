/* Copyright (c) (2017-2019,2021,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
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

#include "cc_config.h"
#include "cc_internal.h"
#include "cc_macros.h"
#include "fipspost_trace.h"
#include <corecrypto/ccmode.h>

size_t
cccbc_context_size(const struct ccmode_cbc *mode)
{
	CC_ENSURE_DIT_ENABLED

	return mode->size;
}

size_t
cccbc_block_size(const struct ccmode_cbc *mode)
{
	CC_ENSURE_DIT_ENABLED

	return mode->block_size;
}

int
cccbc_init(const struct ccmode_cbc *mode,
    cccbc_ctx *ctx,
    size_t key_len,
    const void *cc_sized_by(key_len)key)
{
	CC_ENSURE_DIT_ENABLED

	return mode->init(mode, ctx, key_len, key);
}

int
cccbc_copy_iv(cccbc_iv *cc_sized_by(len)iv_ctx,
    const void *cc_sized_by(len)iv,
    size_t len)
{
	CC_ENSURE_DIT_ENABLED

#if CC_IBOOT
	// Currently ptrcheck in iboot doesn't understand the above annotations
	// and fails when we use cc_memcpy. A future version of ptrcheck will
	// fix this issue. See rdar://79987676
	memcpy(iv_ctx, iv, len);
#else
	cc_memcpy(iv_ctx, iv, len);
#endif
	return 0;
}

int
cccbc_clear_iv(cccbc_iv *cc_sized_by(len)iv_ctx, size_t len)
{
	CC_ENSURE_DIT_ENABLED

	cc_clear(len, iv_ctx);
	return 0;
}

int
cccbc_set_iv(const struct ccmode_cbc *mode, cccbc_iv *iv_ctx, const void *iv)
{
	CC_ENSURE_DIT_ENABLED

	if (iv) {
		return cccbc_copy_iv(iv_ctx, iv, mode->block_size);
	}

	return cccbc_clear_iv(iv_ctx, mode->block_size);
}

int
cccbc_update(const struct ccmode_cbc *mode,
    const cccbc_ctx *ctx,
    cccbc_iv *iv,
    size_t nblocks,
    const void *cc_indexable in,
    void *cc_indexable out)
{
	CC_ENSURE_DIT_ENABLED

	return mode->cbc(ctx, iv, nblocks, in, out);
}

int
cccbc_one_shot(const struct ccmode_cbc *mode,
    size_t key_len,
    const void *cc_sized_by(key_len)key,
    const void *iv,
    size_t nblocks,
    const void *in,
    void *out)
{
	CC_ENSURE_DIT_ENABLED

	    FIPSPOST_TRACE_EVENT;

	size_t iv_len = 0;
	if (iv) {
		iv_len = mode->block_size;
	}

	return cccbc_one_shot_explicit(mode,
	           key_len,
	           iv_len,
	           mode->block_size,
	           nblocks,
	           key,
	           cc_unsafe_forge_bidi_indexable(iv, iv_len),
	           cc_unsafe_forge_bidi_indexable(in, mode->block_size * nblocks),
	           cc_unsafe_forge_bidi_indexable(out, mode->block_size * nblocks));
}

int
cccbc_one_shot_explicit(const struct ccmode_cbc *mode,
    size_t key_len,
    size_t iv_len,
    size_t block_size,
    size_t nblocks,
    const void *cc_sized_by(key_len)key,
    const void *cc_sized_by(iv_len)iv,
    const void *cc_sized_by(block_size * nblocks)in,
    void *cc_sized_by(block_size * nblocks)out)
{
	CC_ENSURE_DIT_ENABLED

	    FIPSPOST_TRACE_EVENT;

	// iv_len must be either equal to block_size, or 0 if the iv is NULL.
	// Once __sized_by_or_null is available, we can get rid of iv_len and use
	//    cc_sized_by_or_null(block_size) to annotate the length of iv instead.
	if (block_size != mode->block_size || (iv_len != block_size && iv_len != 0)) {
		return CCERR_PARAMETER; /* Invalid input size */
	}

	int rc;
	cccbc_ctx_decl(mode->size, ctx);
	cccbc_iv_decl(mode->block_size, iv_ctx);
	rc = mode->init(mode, ctx, key_len, key);
	cc_require_or_return(rc == CCERR_OK, rc);
	if (iv) {
		cc_memcpy(iv_ctx, iv, mode->block_size);
	} else {
		cc_clear(mode->block_size, iv_ctx);
	}
	rc = mode->cbc(ctx, iv_ctx, nblocks, in, out);
	cccbc_ctx_clear(mode->size, ctx);
	return rc;
}
