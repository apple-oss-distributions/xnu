/* Copyright (c) (2011,2014-2016,2018,2019,2021) Apple Inc. All rights reserved.
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

#include "cc_runtime_config.h"
#include "ccaes_vng_gcm.h"
#include "ccmode_internal.h"

/*!
 *  GCM multiply by H
 *  @param key   The GCM state which holds the H value
 *  @param I     The value to multiply H by
 */
void
ccmode_gcm_mult_h(ccgcm_ctx *key, unsigned char *I)
{
#if CCMODE_GCM_VNG_SPEEDUP
#ifdef  __x86_64__
	if (!(CC_HAS_AESNI() && CC_HAS_SupplementalSSE3())) {
		//It can handle in and out buffers to be the same
		ccmode_gcm_gf_mult(CCMODE_GCM_KEY_H(key), I, I);
		return;
	} else
#endif
	{
		// CCMODE_GCM_VNG_KEY_Htable must be the second argument. gcm_gmult() is not a general multiplier function.
		gcm_gmult(I, CCMODE_GCM_VNG_KEY_Htable(key), I );
		return;
	}
#else
	//It can handle in and out buffers to be the same
	ccmode_gcm_gf_mult(CCMODE_GCM_KEY_H(key), I, I);
#endif
}
