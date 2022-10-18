/* Copyright (c) (2017,2019) Apple Inc. All rights reserved.
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

#ifndef _CORECRYPTO_FIPSPOST_TRACE_H_
#define _CORECRYPTO_FIPSPOST_TRACE_H_

#if CC_FIPSPOST_TRACE

/*
 * Use this string to separate out tests.
 */
#define FIPSPOST_TRACE_TEST_STR    "?"

int fipspost_trace_is_active(void);
void fipspost_trace_call(const char *fname);

/* Only trace when VERBOSE is set to avoid impacting normal boots. */
#define FIPSPOST_TRACE_EVENT do {                                       \
    if (fipspost_trace_is_active()) {                                   \
	fipspost_trace_call(__FUNCTION__);                              \
    }                                                                   \
} while (0);

#define FIPSPOST_TRACE_MESSAGE(MSG) do {                                \
    if (fipspost_trace_is_active()) {                                   \
	fipspost_trace_call(MSG);                                       \
    }                                                                   \
} while (0);

#else

/* Not building a CC_FIPSPOST_TRACE-enabled, no TRACE operations. */
#define FIPSPOST_TRACE_EVENT
#define FIPSPOST_TRACE_MESSAGE(X)

#endif

#endif
