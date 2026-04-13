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
 * DER_Digest.h - DER encode a DigestInfo
 *
 */

#ifndef	_DER_DIGEST_H_
#define _DER_DIGEST_H_

#include <libDER/libDER_config.h>
#include <libDER/libDER.h>

__BEGIN_DECLS

/* 
 * Create an encoded DigestInfo based on the specified SHA1 digest. 
 * The incoming digest must be 20 bytes long. 
 *
 * Result is placed in caller's buffer, which must be at least of
 * length DER_SHA1_DIGEST_INFO_LEN bytes. 
 *
 * The *resultLen parameter is the available size in the result
 * buffer on input, and the actual length of the encoded DigestInfo 
 * on output. 
 */
#define DER_SHA1_DIGEST_LEN			20
#define DER_SHA1_DIGEST_INFO_LEN	35 
	
DERReturn DEREncodeSHA1DigestInfoSized(
	const DERByte	*DER_counted_by(sha1DigestLen) sha1Digest,
	DERSize			sha1DigestLen,
	DERByte			*DER_counted_by(*resultLen) result,	/* encoded result RETURNED here */
	DERSize			inputLen,
	DERSize			*resultLen);	/* OUT */

DERReturn DEREncodeSHA1DigestInfo(
	const DERByte	*DER_counted_by(sha1DigestLen) sha1Digest,
	DERSize			sha1DigestLen,
	DERByte			*DER_counted_by(*resultLen) result,	/* encoded result RETURNED here */
	DERSize			*resultLen);	/* IN/OUT */


#define DER_SHA256_DIGEST_LEN		32
#define DER_SHA256_DIGEST_INFO_LEN	51 

DERReturn DEREncodeSHA256DigestInfoSized(
	const DERByte	*DER_counted_by(sha256DigestLen) sha256Digest,
	DERSize			sha256DigestLen,
	DERByte			*DER_counted_by(*resultLen) result,		/* encoded result RETURNED here */
	DERSize			inputLen,
	DERSize			*resultLen);	/* OUT */

DERReturn DEREncodeSHA256DigestInfo(
	const DERByte	*DER_counted_by(sha256DigestLen) sha256Digest,
	DERSize			sha256DigestLen,
	DERByte			*DER_counted_by(*resultLen) result,		/* encoded result RETURNED here */
	DERSize			*resultLen);	/* IN/OUT */

/*
 * Likewise, create an encoded DIgestInfo for specified MD5 or MD2 digest. 
 */
#define DER_MD_DIGEST_LEN			16
#define DER_MD_DIGEST_INFO_LEN		34 

typedef enum {
	WD_MD2 = 1,
	WD_MD5 = 2
} WhichDigest;

DERReturn DEREncodeMDDigestInfoSized(
	WhichDigest		whichDigest,
	const DERByte	*DER_counted_by(mdDigestLen) mdDigest,
	DERSize			mdDigestLen,
	DERByte			*DER_counted_by(*resultLen) result,		/* encoded result RETURNED here */
	DERSize			inputLen,
	DERSize			*resultLen);	/* OUT */

DERReturn DEREncodeMDDigestInfo(
	WhichDigest		whichDigest,
	const DERByte	*DER_counted_by(mdDigestLen) mdDigest,
	DERSize			mdDigestLen,
	DERByte			*DER_counted_by(*resultLen) result,		/* encoded result RETURNED here */
	DERSize			*resultLen);	/* IN/OUT */

/* max sizes you'll need in the general cases */
#define DER_MAX_DIGEST_LEN			DER_SHA256_DIGEST_LEN
#define DER_MAX_ENCODED_INFO_LEN	DER_SHA256_DIGEST_INFO_LEN

__END_DECLS

#endif	/* _DER_DIGEST_H_ */

