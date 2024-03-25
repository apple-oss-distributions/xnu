/* Copyright (c) (2015-2019,2021,2022) Apple Inc. All rights reserved.
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

#include "cc_internal.h"
#include "cc_macros.h"
#include "fipspost_trace.h"
#include "ccmode_gcm_internal.h"
#include <corecrypto/ccmode.h>

size_t
ccgcm_context_size(const struct ccmode_gcm *mode)
{
	CC_ENSURE_DIT_ENABLED

	return mode->size;
}

size_t
ccgcm_block_size(const struct ccmode_gcm *mode)
{
	CC_ENSURE_DIT_ENABLED

	return mode->block_size;
}

int
ccgcm_init(const struct ccmode_gcm *mode,
    ccgcm_ctx *ctx,
    size_t key_nbytes,
    const void *cc_sized_by(key_nbytes)key)
{
	CC_ENSURE_DIT_ENABLED

	return mode->init(mode, ctx, key_nbytes, key);
}

int
ccgcm_init_with_iv(const struct ccmode_gcm *mode, ccgcm_ctx *ctx,
    size_t key_nbytes, const void *key,
    const void *iv)
{
	CC_ENSURE_DIT_ENABLED

	int rc;

	rc = ccgcm_init(mode, ctx, key_nbytes, key);
	if (rc == 0) {
		rc = ccgcm_set_iv(mode, ctx, CCGCM_IV_NBYTES, iv);
	}
	if (rc == 0) {
		_CCMODE_GCM_KEY(ctx)->flags |= CCGCM_FLAGS_INIT_WITH_IV;
	}
	return rc;
}

int
ccgcm_set_iv(const struct ccmode_gcm *mode,
    ccgcm_ctx *ctx,
    size_t iv_nbytes,
    const void *cc_sized_by(iv_nbytes)iv)
{
	CC_ENSURE_DIT_ENABLED

	return mode->set_iv(ctx, iv_nbytes, iv);
}

int
ccgcm_inc_iv(CC_UNUSED const struct ccmode_gcm *mode, ccgcm_ctx *ctx, void *iv)
{
	CC_ENSURE_DIT_ENABLED

	uint8_t *Y0 = CCMODE_GCM_KEY_Y_0(ctx);

	cc_require(_CCMODE_GCM_KEY(ctx)->state == CCMODE_GCM_STATE_IV, errOut);
	cc_require(_CCMODE_GCM_KEY(ctx)->flags & CCGCM_FLAGS_INIT_WITH_IV, errOut);

	inc_uint(Y0 + 4, 8);
	cc_memcpy(iv, Y0, CCGCM_IV_NBYTES);
	cc_memcpy(CCMODE_GCM_KEY_Y(ctx), Y0, CCGCM_BLOCK_NBYTES);
	ccmode_gcm_update_pad(ctx);

	_CCMODE_GCM_KEY(ctx)->state = CCMODE_GCM_STATE_AAD;

	return 0;

errOut:
	return CCMODE_INVALID_CALL_SEQUENCE;
}

int
ccgcm_aad(const struct ccmode_gcm *mode,
    ccgcm_ctx *ctx,
    size_t nbytes,
    const void *cc_sized_by(nbytes)additional_data)
{
	CC_ENSURE_DIT_ENABLED

	return mode->gmac(ctx, nbytes, additional_data);
}

int
ccgcm_gmac(const struct ccmode_gcm *mode,
    ccgcm_ctx *ctx,
    size_t nbytes,
    const void *cc_sized_by(nbytes)in)
{
	CC_ENSURE_DIT_ENABLED

	return mode->gmac(ctx, nbytes, in);
}

int
ccgcm_update(const struct ccmode_gcm *mode,
    ccgcm_ctx *ctx,
    size_t nbytes,
    const void *cc_sized_by(nbytes)in,
    void *cc_sized_by(nbytes)out)
{
	CC_ENSURE_DIT_ENABLED

	return mode->gcm(ctx, nbytes, in, out);
}

int
ccgcm_finalize(const struct ccmode_gcm *mode,
    ccgcm_ctx *ctx,
    size_t tag_nbytes,
    void *cc_sized_by(tag_nbytes)tag)
{
	CC_ENSURE_DIT_ENABLED

	return mode->finalize(ctx, tag_nbytes, tag);
}

int
ccgcm_reset(const struct ccmode_gcm *mode, ccgcm_ctx *ctx)
{
	CC_ENSURE_DIT_ENABLED

	return mode->reset(ctx);
}

int
ccgcm_one_shot(const struct ccmode_gcm *mode,
    size_t key_nbytes, const void *key,
    size_t iv_nbytes, const void *iv,
    size_t adata_nbytes, const void *adata,
    size_t nbytes, const void *in, void *out,
    size_t tag_nbytes, void *tag)
{
	CC_ENSURE_DIT_ENABLED

	    FIPSPOST_TRACE_EVENT;

	int rc = 0;

	ccgcm_ctx_decl(mode->size, ctx);
	rc = ccgcm_init(mode, ctx, key_nbytes, key); cc_require(rc == 0, errOut);
	rc = ccgcm_set_iv(mode, ctx, iv_nbytes, iv); cc_require(rc == 0, errOut);
	rc = ccgcm_aad(mode, ctx, adata_nbytes, adata); cc_require(rc == 0, errOut);
	rc = ccgcm_update(mode, ctx, nbytes, in, out); cc_require(rc == 0, errOut);
	rc = ccgcm_finalize(mode, ctx, tag_nbytes, tag); cc_require(rc == 0, errOut);

errOut:
	ccgcm_ctx_clear(mode->size, ctx);
	return rc;
}


//ccgcm_one_shot_legacy() is created because in the previous implementation of aes-gcm
//set_iv() could be skipped.
//In the new version of aes-gcm set_iv() cannot be skipped and IV length cannot
//be zero, as specified in FIPS.
//do not call ccgcm_one_shot_legacy() in any new application
int
ccgcm_set_iv_legacy(const struct ccmode_gcm *mode, ccgcm_ctx *key, size_t iv_nbytes, const void *iv)
{
	CC_ENSURE_DIT_ENABLED

	int rc = -1;

	if (iv_nbytes == 0 || iv == NULL) {
		/* must be in IV state */
		cc_require(_CCMODE_GCM_KEY(key)->state == CCMODE_GCM_STATE_IV, errOut); /* CRYPT_INVALID_ARG */

		// this is the net effect of setting IV to the empty string
		cc_clear(CCGCM_BLOCK_NBYTES, CCMODE_GCM_KEY_Y(key));
		ccmode_gcm_update_pad(key);
		cc_clear(CCGCM_BLOCK_NBYTES, CCMODE_GCM_KEY_Y_0(key));

		_CCMODE_GCM_KEY(key)->state = CCMODE_GCM_STATE_AAD;
		rc = 0;
	} else {
		rc = ccgcm_set_iv(mode, key, iv_nbytes, iv);
	}

errOut:
	return rc;
}

int
ccgcm_one_shot_legacy(const struct ccmode_gcm *mode,
    size_t key_nbytes, const void *key,
    size_t iv_nbytes, const void *iv,
    size_t adata_nbytes, const void *adata,
    size_t nbytes, const void *in, void *out,
    size_t tag_nbytes, void *tag)
{
	CC_ENSURE_DIT_ENABLED

	int rc = 0;

	ccgcm_ctx_decl(mode->size, ctx);
	rc = ccgcm_init(mode, ctx, key_nbytes, key); cc_require(rc == 0, errOut);
	rc = ccgcm_set_iv_legacy(mode, ctx, iv_nbytes, iv); cc_require(rc == 0, errOut);
	rc = ccgcm_aad(mode, ctx, adata_nbytes, adata); cc_require(rc == 0, errOut);
	rc = ccgcm_update(mode, ctx, nbytes, in, out); cc_require(rc == 0, errOut);
	rc = ccgcm_finalize(mode, ctx, tag_nbytes, tag); cc_require(rc == 0, errOut);

errOut:
	ccgcm_ctx_clear(mode->size, ctx);
	return rc;
}

void
inc_uint(uint8_t *buf, size_t nbytes)
{
	for (size_t i = 1; i <= nbytes; i += 1) {
		size_t j = nbytes - i;
		buf[j] = (uint8_t)(buf[j] + 1);
		if (buf[j] > 0) {
			return;
		}
	}
}

void
ccmode_gcm_update_pad(ccgcm_ctx *key)
{
	inc_uint(CCMODE_GCM_KEY_Y(key) + 12, 4);
	CCMODE_GCM_KEY_ECB(key)->ecb(CCMODE_GCM_KEY_ECB_KEY(key), 1,
	    CCMODE_GCM_KEY_Y(key),
	    CCMODE_GCM_KEY_PAD(key));
}

void
ccmode_gcm_aad_finalize(ccgcm_ctx *key)
{
	if (_CCMODE_GCM_KEY(key)->state == CCMODE_GCM_STATE_AAD) {
		if (_CCMODE_GCM_KEY(key)->aad_nbytes % CCGCM_BLOCK_NBYTES > 0) {
			ccmode_gcm_mult_h(key, CCMODE_GCM_KEY_X(key));
		}
		_CCMODE_GCM_KEY(key)->state = CCMODE_GCM_STATE_TEXT;
	}
}
