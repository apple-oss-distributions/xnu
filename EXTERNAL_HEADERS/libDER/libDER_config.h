/*
 * Copyright (c) 2005-2007,2011-2012,2014 Apple Inc. All Rights Reserved.
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
 * libDER_config.h - platform dependent #defines and typedefs for libDER
 *
 */
 
#ifndef	_LIB_DER_CONFIG_H_
#define _LIB_DER_CONFIG_H_

#if !defined(EFI) || !EFI
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#else // EFI
// This requires $(SDKROOT)/usr/local/efi/include/Platform to be in your header
// search path.
#include <Apple/Common/Library/Include/EfiCompatibility.h>
#endif

#if (defined(EFI) && EFI) || defined(WIN32) || defined(_MSC_VER)
#if defined(__cplusplus)
#define __BEGIN_DECLS extern "C" {
#define __END_DECLS }
#else
#define __BEGIN_DECLS
#define __END_DECLS
#endif
#else
#include <sys/cdefs.h>
#endif

__BEGIN_DECLS

/*
 * Basic data types: unsigned 8-bit integer, unsigned 32-bit integer
 */
#if !defined(EFI) || !EFI
typedef uint8_t DERByte;
typedef uint16_t DERShort;
typedef uint32_t DERInt;
typedef int32_t DERSignedInt;
typedef uint64_t DERLong;
typedef int64_t DERSignedLong;
typedef size_t DERSize;
typedef bool DERBool;
#else
typedef UINT8 DERByte;
typedef UINT16 DERShort;
typedef UINT32 DERInt;
typedef INT32 DERSignedInt;
typedef UINT64 DERLong;
typedef INT64 DERSignedLong;
typedef size_t DERSize;
typedef BOOLEAN DERBool;
#endif

/* 
 * Use these #defines of you have memset, memmove, and memcmp; else
 * write your own equivalents.
 */

#if !defined(EFI) || !EFI
#define DERMemset(ptr, c, len)		memset(ptr, c, len)
#define DERMemmove(dst, src, len)	memmove(dst, src, len)
#define DERMemcmp(b1, b2, len)		memcmp(b1, b2, len)
#else
void *DERMemset(void *b, int c, size_t len);
void *DERMemmove(void *dst, const void *src, size_t len);
int DERMemcmp(const void *s1, const void *s2, size_t n);
#endif

/***
 *** Compile time options to trim size of the library. 
 ***/
 
/* enable general DER encode */
#define DER_ENCODE_ENABLE		1

/* enable general DER decode */
#define DER_DECODE_ENABLE		1

#ifndef DER_MULTIBYTE_TAGS
/* enable multibyte tag support. */
#define DER_MULTIBYTE_TAGS		1
#endif

#ifndef DER_TAG_SIZE
/* Iff DER_MULTIBYTE_TAGS is 1 this is the sizeof(DERTag) in bytes. Note that
   tags are still encoded and decoded from a minimally encoded DER
   represantation.  This value maintains compatibility with libImg4Decode/Encode.  */
#define DER_TAG_SIZE            8
#endif

/* bounds-safety defines */
#if !defined(_MSC_VER) && __has_feature(bounds_attributes)

#define DER_counted_by(x)		__attribute__((counted_by(x)))
#define DER_sized_by(x)			__attribute__((sized_by(x)))
#define DER_ended_by(x)         __attribute__((ended_by(x)))
#define DER_bidi_indexable		__attribute__((bidi_indexable))
#define DER_indexable			__attribute__((indexable))
#define DER_single				__attribute__((single))
#define DER_unsafe_indexable	__attribute__((unsafe_indexable))
#define DER_unsafe_forge_bidi_indexable(P, S)	__builtin_unsafe_forge_bidi_indexable(P, S)

/* For some prototype patterns that bounds-safety doesn't handle without
 * compromise, we ask adopters to use a different entry point. The old
 * entry point is marked unavailable _only_ in bounds-safety builds, since
 * there's nothing wrong with it otherwise.
 */
#define DER_bounds_safety_replaced_platform(P, REP)    \
    __attribute__((availability(P, unavailable, replacement=#REP)))

#define DER_bounds_safety_replaced(REP) \
    DER_bounds_safety_replaced_platform(macosx, REP) \
    DER_bounds_safety_replaced_platform(ios, REP)

#else // !__has_feature(bounds_attributes)

#define DER_counted_by(x)
#define DER_sized_by(x)
#define DER_ended_by(x)
#define DER_bidi_indexable
#define DER_indexable
#define DER_single
#define DER_unsafe_indexable
#define DER_unsafe_forge_bidi_indexable(P, S) (P)

#define DER_bounds_safety_replaced(...)

#endif // !__has_feature(bounds_attributes)

/* ---------------------- Do not edit below this line ---------------------- */

/*
 * Logical representation of a tag (the encoded representation is always in
 * the minimal number of bytes). The top 3 bits encode class and method
 * The remaining bits encode the tag value.  To obtain smaller DERItemSpecs
 * sizes, choose the smallest type that fits your needs.  Most standard ASN.1
 * usage only needs single byte tags, but ocasionally custom applications
 * require a larger tag namespace.
 */
#if DER_MULTIBYTE_TAGS

#if DER_TAG_SIZE == 1
typedef DERByte DERTag;
#elif DER_TAG_SIZE == 2
typedef DERShort DERTag;
#elif DER_TAG_SIZE == 4
typedef DERInt DERTag;
#elif DER_TAG_SIZE == 8
typedef DERLong DERTag;
#else
#error DER_TAG_SIZE invalid
#endif

#else /* DER_MULTIBYTE_TAGS */
typedef DERByte DERTag;
#endif /* !DER_MULTIBYTE_TAGS */

__END_DECLS

#endif	/* _LIB_DER_CONFIG_H_ */
