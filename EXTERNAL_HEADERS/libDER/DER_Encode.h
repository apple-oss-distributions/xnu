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
 * DER_Encode.h - DER encoding routines
 *
 */

#ifndef	_DER_ENCODE_H_
#define _DER_ENCODE_H_

#include <libDER/libDER_config.h>
#include <libDER/libDER.h>

__BEGIN_DECLS

/*
 * Max size of an encoded item given its length.
 * This includes a possible leading zero prepended to a signed integer
 * (see DER_ENC_SIGNED_INT below).
 */
#define DER_MAX_ENCODED_SIZE(len)					\
	( 1 +			/* tag */						\
	  5 +			/* max length */				\
	  1 +			/* possible prepended zero */	\
	  len)

/* calculate size of encoded length */
DERSize DERLengthOfLength(
	DERSize length);

/* encode length */
DERReturn DEREncodeLength(
	DERSize length,
	DERByte *DER_counted_by(*inOutLen) buf,		/* encoded length goes here */
	DERSize *inOutLen);	/* IN/OUT */

DERReturn DEREncodeLengthSized(
	DERSize length,
	DERByte *DER_counted_by(*outLen) buf,		/* encoded length goes here */
	DERSize	inLen,
	DERSize *outLen);

/* calculate size of encoded length */
DERSize DERLengthOfItem(
	DERTag tag,
	DERSize length);

/* encode item */
DERReturn DEREncodeItem(
	DERTag tag,
	DERSize length,
    const DERByte *DER_counted_by(length) src,
	DERByte *DER_counted_by(*inOutLen) derOut,	/* encoded item goes here */
	DERSize *inOutLen);	/* IN/OUT */
	
DERReturn DEREncodeItemSized(
	DERTag tag,
	DERSize length,
    const DERByte *DER_counted_by(length) src,
	DERByte *DER_counted_by(*outLen) derOut,	/* encoded item goes here */
	DERSize inLen,
	DERSize *outLen);

/*
 * Per-item encode options.
 */

/* explicit default, no options */
#define DER_ENC_NO_OPTS			0x0000

/* signed integer check: if incoming m.s. bit is 1, prepend a zero */
#define DER_ENC_SIGNED_INT		0x0100

/* DERItem contains fully encoded item - copy, don't encode */
#define DER_ENC_WRITE_DER		0x0200


/*
 * High-level sequence or set encode support.
 *
 * The outgoing sequence is expressed as an array of DERItemSpecs, each
 * of which corresponds to one item in the encoded sequence.
 *
 * Normally the tag of the encoded item comes from the associated
 * DERItemSpec, and the content comes from the DERItem whose address is
 * the src arg plus the offset value in the associated DERItemSpec.
 *
 * If the DER_ENC_WRITE_DER option is true for a given DERItemSpec then
 * no per-item encoding is done; the DER - with tag, length, and content -
 * is taken en masse from the associated DERItem.
 */
DERReturn DEREncodeSequenceFromObject(
	DERTag				topTag,						/* ASN1_CONSTR_SEQUENCE, ASN1_CONSTR_SET */
	const void			*DER_sized_by(srcSize) src,	/* generally a ptr to a struct full of
													 *    DERItems */
	DERSize				srcSize,
	DERShort			numItems,					/* size of itemSpecs[] */
	const DERItemSpec	*DER_counted_by(numItems) itemSpecs,
	DERByte				*DER_counted_by(*outLen) derOut,	/* encoded data written here */
	DERSize				inLen,
	DERSize				*outLen);					/* OUT */

/* same as DEREncodeSequenceFromObject, but without a source size */
DER_bounds_safety_replaced(DEREncodeSequenceFromObject)
DERReturn DEREncodeSequence(
	DERTag				topTag,						/* ASN1_CONSTR_SEQUENCE, ASN1_CONSTR_SET */
	const void			*DER_unsafe_indexable src,	/* generally a ptr to a struct full of
									 				 *    DERItems */
	DERShort			numItems,					/* size of itemSpecs[] */
	const DERItemSpec	*DER_counted_by(numItems) itemSpecs,
	DERByte				*DER_counted_by(*inOutLen) derOut,	/* encoded data written here */
	DERSize				*inOutLen);					/* IN/OUT */


/* precalculate the length of an encoded sequence: can return an error for overflow, and
 * returns its result by argument */
DERReturn DERLengthOfEncodedSequenceFromObject(
	DERTag				topTag,							/* ASN1_CONSTR_SEQUENCE, ASN1_CONSTR_SET */
	const void			*DER_sized_by(srcSize) src,		/* generally a ptr to a struct full of
														 *    DERItems */
	DERSize				srcSize,
	DERShort			numItems,						/* size of itemSpecs[] */
	const DERItemSpec	*DER_counted_by(numItems) itemSpecs,
	DERSize				*result);
	
/* same, but without a source size, and without a chance to report errors: returns 0 if
 * the size can't possibly be valid for this pointer */
DER_bounds_safety_replaced(DERLengthOfEncodedSequenceFromObject)
DERSize DERLengthOfEncodedSequence(
	DERTag				topTag,							/* ASN1_CONSTR_SEQUENCE, ASN1_CONSTR_SET */
	const void			*DER_unsafe_indexable src,		/* generally a ptr to a struct full of
														 *    DERItems */
	DERShort			numItems,						/* size of itemSpecs[] */
	const DERItemSpec	*DER_counted_by(numItems) itemSpecs);


__END_DECLS

#endif	/* _DER_ENCODE_H_ */
