/*
 * Copyright (c) 2005-2016 Apple Inc. All Rights Reserved.
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
 * asn1Types.h - ASN.1/DER #defines - strictly hard coded per the real world
 *
 */

#ifndef	_ASN1_TYPES_H_
#define _ASN1_TYPES_H_

#include <libDER/libDER_config.h>

__BEGIN_DECLS

/* copied from libsecurity_asn1 project */

/* Type tag numbers */
#define ASN1_EOC                0x00
#define ASN1_BOOLEAN            0x01
#define ASN1_INTEGER            0x02
#define ASN1_BIT_STRING         0x03
#define ASN1_OCTET_STRING       0x04
#define ASN1_NULL               0x05
#define ASN1_OBJECT_ID          0x06
#define ASN1_OBJECT_DESCRIPTOR  0x07
/* External type and instance-of type   0x08 */
#define ASN1_REAL               0x09
#define ASN1_ENUMERATED         0x0a
#define ASN1_EMBEDDED_PDV       0x0b
#define ASN1_UTF8_STRING        0x0c
/*                                  0x0d */
/*                                  0x0e */
/*                                  0x0f */
#define ASN1_SEQUENCE           0x10
#define ASN1_SET                0x11
#define ASN1_NUMERIC_STRING     0x12
#define ASN1_PRINTABLE_STRING   0x13
#define ASN1_T61_STRING         0x14
#define ASN1_VIDEOTEX_STRING    0x15
#define ASN1_IA5_STRING         0x16
#define ASN1_UTC_TIME           0x17
#define ASN1_GENERALIZED_TIME   0x18
#define ASN1_GRAPHIC_STRING     0x19
#define ASN1_VISIBLE_STRING     0x1a
#define ASN1_GENERAL_STRING     0x1b
#define ASN1_UNIVERSAL_STRING   0x1c
/*                                  0x1d */
#define ASN1_BMP_STRING         0x1e
#define ASN1_HIGH_TAG_NUMBER    0x1f
#define ASN1_TELETEX_STRING ASN1_T61_STRING

/* Tag modifiers */
#define ASN1_TAG_MASK           ((DERTag)~0)
#define ASN1_TAGNUM_MASK        ((DERTag)~((DERTag)7 << (sizeof(DERTag) * 8 - 3)))

#define ASN1_METHOD_MASK        ((DERTag)1 << (sizeof(DERTag) * 8 - 3))
#define ASN1_PRIMITIVE          ((DERTag)0 << (sizeof(DERTag) * 8 - 3))
#define ASN1_CONSTRUCTED        ((DERTag)1 << (sizeof(DERTag) * 8 - 3))

#define ASN1_CLASS_MASK         ((DERTag)3 << (sizeof(DERTag) * 8 - 2))
#define ASN1_UNIVERSAL          ((DERTag)0 << (sizeof(DERTag) * 8 - 2))
#define ASN1_APPLICATION        ((DERTag)1 << (sizeof(DERTag) * 8 - 2))
#define ASN1_CONTEXT_SPECIFIC   ((DERTag)2 << (sizeof(DERTag) * 8 - 2))
#define ASN1_PRIVATE            ((DERTag)3 << (sizeof(DERTag) * 8 - 2))

/* One-byte tag modifiers */
#define ONE_BYTE_ASN1_TAG_MASK          0xff
#define ONE_BYTE_ASN1_TAGNUM_MASK       0x1f
#define ONE_BYTE_ASN1_METHOD_MASK       0x20
#define ONE_BYTE_ASN1_PRIMITIVE         0x00
#define ONE_BYTE_ASN1_CONSTRUCTED       0x20

#define ONE_BYTE_ASN1_CLASS_MASK        0xc0
#define ONE_BYTE_ASN1_UNIVERSAL         0x00
#define ONE_BYTE_ASN1_APPLICATION       0x40
#define ONE_BYTE_ASN1_CONTEXT_SPECIFIC  0x80
#define ONE_BYTE_ASN1_PRIVATE           0xc0

/* sequence and set appear as the following */
#define ASN1_CONSTR_SEQUENCE    ((DERTag)(ASN1_CONSTRUCTED | ASN1_SEQUENCE))
#define ASN1_CONSTR_SET         ((DERTag)(ASN1_CONSTRUCTED | ASN1_SET))

#define ONE_BYTE_ASN1_CONSTR_SEQUENCE   ((uint8_t)(ONE_BYTE_ASN1_CONSTRUCTED | ASN1_SEQUENCE))
#define ONE_BYTE_ASN1_CONSTR_SET        ((uint8_t)(ONE_BYTE_ASN1_CONSTRUCTED | ASN1_SET))

__END_DECLS

#endif	/* _ASN1_TYPES_H_ */
