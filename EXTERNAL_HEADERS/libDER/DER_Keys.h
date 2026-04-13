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
 * DER_Keys.h - support for decoding RSA keys
 *
 */
 
#ifndef	_DER_KEYS_H_
#define _DER_KEYS_H_

#include <libDER/libDER_config.h>
#include <libDER/libDER.h>
#include <libDER/DER_Decode.h>

__BEGIN_DECLS

/* Algorithm Identifier components */
typedef struct {
	DERItem		oid;			/* OID */
	DERItem		params;			/* ASN_ANY, optional, DER_DEC_SAVE_DER */
} DERAlgorithmId;

/* DERItemSpecs to decode into a DERAlgorithmId */
extern const DERSize DERNumAlgorithmIdItemSpecs;
extern const DERItemSpec DERAlgorithmIdItemSpecs[DER_counted_by(DERNumAlgorithmIdItemSpecs)];

/* X509 SubjectPublicKeyInfo */
typedef struct {
	DERItem		algId;			/* sequence, DERAlgorithmId */
	DERItem		pubKey;			/* BIT STRING */
} DERSubjPubKeyInfo;

/* DERItemSpecs to decode into a DERSubjPubKeyInfo */
extern const DERSize DERNumSubjPubKeyInfoItemSpecs;
extern const DERItemSpec DERSubjPubKeyInfoItemSpecs[DER_counted_by(DERNumSubjPubKeyInfoItemSpecs)];

/* 
 * RSA public key in PKCS1 format; this is inside the BIT_STRING in 
 * DERSubjPubKeyInfo.pubKey.
 */
typedef struct {
	DERItem		modulus;		/* n - INTEGER */
	DERItem		pubExponent;	/* e - INTEGER */
} DERRSAPubKeyPKCS1;

/* DERItemSpecs to decode/encode into/from a DERRSAPubKeyPKCS1 */
extern const DERSize DERNumRSAPubKeyPKCS1ItemSpecs;
extern const DERItemSpec DERRSAPubKeyPKCS1ItemSpecs[DER_counted_by(DERNumRSAPubKeyPKCS1ItemSpecs)];

/* 
 * RSA public key in custom (to this library) format, including
 * the reciprocal. All fields are integers. 
 */
typedef struct {
	DERItem		modulus;		/* n */
	DERItem		reciprocal;		/* reciprocal of modulus */
	DERItem		pubExponent;	/* e */
} DERRSAPubKeyApple;

/* DERItemSpecs to decode/encode into/from a DERRSAPubKeyApple */
extern const DERSize DERNumRSAPubKeyAppleItemSpecs;
extern const DERItemSpec DERRSAPubKeyAppleItemSpecs[DER_counted_by(DERNumRSAPubKeyAppleItemSpecs)];

/* 
 * RSA Private key, PKCS1 format, CRT option.
 * All fields are integers. 
 */
typedef struct {
	DERItem		p;				/* p * q = n */
	DERItem		q;
	DERItem		dp;				/* d mod (p-1) */
	DERItem		dq;				/* d mod (q-1) */
	DERItem		qInv;		
} DERRSAPrivKeyCRT;

/* DERItemSpecs to decode into a DERRSAPrivKeyCRT */
extern const DERSize DERNumRSAPrivKeyCRTItemSpecs;
extern const DERItemSpec DERRSAPrivKeyCRTItemSpecs[DER_counted_by(DERNumRSAPrivKeyCRTItemSpecs)];

/* Fully formed RSA key pair, for generating a PKCS1 private key */
typedef struct {
	DERItem		version;	
	DERItem		n;		/* modulus */
	DERItem		e;		/* public exponent */
	DERItem		d;		/* private exponent */
	DERItem		p;		/* n = p*q */
	DERItem		q;
	DERItem		dp;		/* d mod (p-1) */
	DERItem		dq;		/* d mod (q-1) */
	DERItem		qInv;	/* q^(-1) mod p */
} DERRSAKeyPair;

/* DERItemSpecs to encode a DERRSAKeyPair */
extern const DERSize DERNumRSAKeyPairItemSpecs;
extern const DERItemSpec DERRSAKeyPairItemSpecs[DER_counted_by(DERNumRSAKeyPairItemSpecs)];

__END_DECLS

#endif	/* _DER_KEYS_H_ */

