/*
 * Copyright (c) 2005-2017 Apple Inc. All Rights Reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */

/*
 * DER_CodecUtils.h - static inline functions common to DER_Encode and
 * DER_Decode
 */

#ifndef DER_CodecUtils_h
#define DER_CodecUtils_h

#include <libDER/libDER_config.h>

#if defined(__has_attribute) && __has_attribute(no_sanitize)
#define DER_ALLOW_UNSIGNED_INTEGER_OVERFLOW \
    __attribute__((no_sanitize("unsigned-integer-overflow")))
#else
#define DER_ALLOW_UNSIGNED_INTEGER_OVERFLOW
#endif

/*
 * Returns 1 if fieldBase + fieldSize does not overflow and is greater than
 * objSize, 0 otherwise.
 */
DER_ALLOW_UNSIGNED_INTEGER_OVERFLOW
static inline int DEREndOffsetSmallerOrEqualTo(
    DERSize fieldOffset,
    DERSize fieldSize,
    DERSize objSize)
{
    // can't use __builtin_add_overflow on Windows; rely on the definedness
    // of unsigned integer math
    DERSize endOffset = fieldOffset + fieldSize;
    return endOffset >= fieldOffset && endOffset <= objSize;
}

/*
 * Return the maximum possible length that `dst` could have without
 * address calculations overflowing.
 */
static inline
DERSize DERObjectMaxSize(const void *DER_unsafe_indexable ptr)
{
    DERSize maskOutTopBit = ~(DERSize)0 >> 1;
    return ~(DERSize)ptr & maskOutTopBit;
}

#endif /* DER_CodecUtils_h */
