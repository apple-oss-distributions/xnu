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
 * DER_CertCrl.h - support for decoding X509 certificates and CRLs
 *
 */
 
#ifndef	_DER_CERT_CRL_H_
#define _DER_CERT_CRL_H_

#include <libDER/libDER_config.h>
#include <libDER/libDER.h>
#include <libDER/DER_Decode.h>

__BEGIN_DECLS

/* 
 * Top level cert or CRL - the two are identical at this level - three 
 * components. The tbs field is saved in full DER form for sig verify. 
 */
typedef struct {
	DERItem		tbs;			/* sequence, DERTBSCert, DER_DEC_SAVE_DER */
	DERItem		sigAlg;			/* sequence, DERAlgorithmId */
	DERItem		sig;			/* bit string */
} DERSignedCertCrl;

/* DERItemSpecs to decode into a DERSignedCertCrl */
extern const DERSize DERNumSignedCertCrlItemSpecs;
extern const DERItemSpec DERSignedCertCrlItemSpecs[DER_counted_by(DERNumSignedCertCrlItemSpecs)];

/* TBS cert components */
typedef struct {
	DERItem		version;		/* integer, optional, EXPLICIT */
	DERItem		serialNum;		/* integer */
	DERItem		tbsSigAlg;		/* sequence, DERAlgorithmId */
	DERItem		issuer;			/* sequence, TBD */
	DERItem		validity;		/* sequence,  DERValidity */
	DERItem		subject;		/* sequence, TBD */
	DERItem		subjectPubKey;	/* sequence, DERSubjPubKeyInfo */
	DERItem		issuerID;		/* bit string, optional */
	DERItem		subjectID;		/* bit string, optional */
	DERItem		extensions;		/* sequence, optional, EXPLICIT */
} DERTBSCert;

/* DERItemSpecs to decode into a DERTBSCert */
extern const DERSize DERNumTBSCertItemSpecs;
extern const DERItemSpec DERTBSCertItemSpecs[DER_counted_by(DERNumTBSCertItemSpecs)];

/* 
 * validity - components can be either UTC or generalized time.
 * Both are ASN_ANY with DER_DEC_SAVE_DER.
 */
typedef struct {
	DERItem		notBefore;
	DERItem		notAfter;
} DERValidity;

/* DERItemSpecs to decode into a DERValidity */
extern const DERSize DERNumValidityItemSpecs;
extern const DERItemSpec DERValidityItemSpecs[DER_counted_by(DERNumValidityItemSpecs)];

/* AttributeTypeAndValue components. */
typedef struct {
	DERItem		type;
	DERItem		value;
} DERAttributeTypeAndValue;

/* DERItemSpecs to decode into DERAttributeTypeAndValue */
extern const DERSize DERNumAttributeTypeAndValueItemSpecs;
extern const DERItemSpec DERAttributeTypeAndValueItemSpecs[DER_counted_by(DERNumAttributeTypeAndValueItemSpecs)];

/* Extension components */
typedef struct {
	DERItem		extnID;
	DERItem		critical;
	DERItem		extnValue;
} DERExtension;

/* DERItemSpecs to decode into DERExtension */
extern const DERSize DERNumExtensionItemSpecs;
extern const DERItemSpec DERExtensionItemSpecs[DER_counted_by(DERNumExtensionItemSpecs)];

/* BasicConstraints components. */
typedef struct {
	DERItem		cA;
	DERItem		pathLenConstraint;
} DERBasicConstraints;

/* DERItemSpecs to decode into DERBasicConstraints */
extern const DERSize DERNumBasicConstraintsItemSpecs;
extern const DERItemSpec DERBasicConstraintsItemSpecs[DER_counted_by(DERNumBasicConstraintsItemSpecs)];

/* NameConstraints components. */
typedef struct {
    DERItem		permittedSubtrees;
    DERItem		excludedSubtrees;
} DERNameConstraints;

/* DERItemSpecs to decode into a DERNameConstraints */
extern const DERSize DERNumNameConstraintsItemSpecs;
extern const DERItemSpec DERNameConstraintsItemSpecs[DER_counted_by(DERNumNameConstraintsItemSpecs)];

/* GeneralSubtree components. */
typedef struct {
    DERItem		generalName;
    DERItem		minimum;
    DERItem		maximum;
} DERGeneralSubtree;

/* DERItemSpecs to decode into a DERGeneralSubtree */
extern const DERSize DERNumGeneralSubtreeItemSpecs;
extern const DERItemSpec DERGeneralSubtreeItemSpecs[DER_counted_by(DERNumGeneralSubtreeItemSpecs)];

/* PrivateKeyUsagePeriod components. */
typedef struct {
	DERItem		notBefore;
	DERItem		notAfter;
} DERPrivateKeyUsagePeriod;

/* DERItemSpecs to decode into a DERPrivateKeyUsagePeriod */
extern const DERSize DERNumPrivateKeyUsagePeriodItemSpecs;
extern const DERItemSpec DERPrivateKeyUsagePeriodItemSpecs[DER_counted_by(DERNumPrivateKeyUsagePeriodItemSpecs)];

/* DistributionPoint components. */
typedef struct {
	DERItem		distributionPoint;
	DERItem		reasons;
    DERItem     cRLIssuer;
} DERDistributionPoint;

/* DERItemSpecs to decode into a DERDistributionPoint */
extern const DERSize DERNumDistributionPointItemSpecs;
extern const DERItemSpec DERDistributionPointItemSpecs[DER_counted_by(DERNumDistributionPointItemSpecs)];

/* PolicyInformation components. */
typedef struct {
    DERItem policyIdentifier;
    DERItem policyQualifiers;
} DERPolicyInformation;

/* DERItemSpecs to decode into a DERPolicyInformation */
extern const DERSize DERNumPolicyInformationItemSpecs;
extern const DERItemSpec DERPolicyInformationItemSpecs[DER_counted_by(DERNumPolicyInformationItemSpecs)];

/* PolicyQualifierInfo components. */
typedef struct {
    DERItem policyQualifierID;
    DERItem qualifier;
} DERPolicyQualifierInfo;

/* DERItemSpecs to decode into a DERPolicyQualifierInfo */
extern const DERSize DERNumPolicyQualifierInfoItemSpecs;
extern const DERItemSpec DERPolicyQualifierInfoItemSpecs[DER_counted_by(DERNumPolicyQualifierInfoItemSpecs)];

/* UserNotice components. */
typedef struct {
    DERItem noticeRef;
    DERItem explicitText;
} DERUserNotice;

/* DERItemSpecs to decode into a DERUserNotice */
extern const DERSize DERNumUserNoticeItemSpecs;
extern const DERItemSpec DERUserNoticeItemSpecs[DER_counted_by(DERNumUserNoticeItemSpecs)];

/* NoticeReference components. */
typedef struct {
    DERItem organization;
    DERItem noticeNumbers;
} DERNoticeReference;

/* DERItemSpecs to decode into a DERNoticeReference */
extern const DERSize DERNumNoticeReferenceItemSpecs;
extern const DERItemSpec DERNoticeReferenceItemSpecs[DER_counted_by(DERNumNoticeReferenceItemSpecs)];

/* PolicyMapping components. */
typedef struct {
    DERItem issuerDomainPolicy;
    DERItem subjectDomainPolicy;
} DERPolicyMapping;

/* DERItemSpecs to decode into a DERPolicyMapping */
extern const DERSize DERNumPolicyMappingItemSpecs;
extern const DERItemSpec DERPolicyMappingItemSpecs[DER_counted_by(DERNumPolicyMappingItemSpecs)];

/* AccessDescription components. */
typedef struct {
    DERItem accessMethod;
    DERItem accessLocation;
} DERAccessDescription;

/* DERItemSpecs to decode into a DERAccessDescription */
extern const DERSize DERNumAccessDescriptionItemSpecs;
extern const DERItemSpec DERAccessDescriptionItemSpecs[DER_counted_by(DERNumAccessDescriptionItemSpecs)];

/* AuthorityKeyIdentifier components. */
typedef struct {
    DERItem keyIdentifier;
    DERItem authorityCertIssuer;
    DERItem authorityCertSerialNumber;
} DERAuthorityKeyIdentifier;

/* DERItemSpecs to decode into a DERAuthorityKeyIdentifier */
extern const DERSize DERNumAuthorityKeyIdentifierItemSpecs;
extern const DERItemSpec DERAuthorityKeyIdentifierItemSpecs[DER_counted_by(DERNumAuthorityKeyIdentifierItemSpecs)];

/* OtherName components. */
typedef struct {
    DERItem typeIdentifier;
    DERItem value;
} DEROtherName;

/* DERItemSpecs to decode into a DEROtherName */
extern const DERSize DERNumOtherNameItemSpecs;
extern const DERItemSpec DEROtherNameItemSpecs[DER_counted_by(DERNumOtherNameItemSpecs)];

/* PolicyConstraints components. */
typedef struct {
    DERItem requireExplicitPolicy;
    DERItem inhibitPolicyMapping;
} DERPolicyConstraints;

/* DERItemSpecs to decode into a DERPolicyConstraints */
extern const DERSize DERNumPolicyConstraintsItemSpecs;
extern const DERItemSpec DERPolicyConstraintsItemSpecs[DER_counted_by(DERNumPolicyConstraintsItemSpecs)];

/* TBS CRL */
typedef struct {
	DERItem		version;		/* integer, optional */
	DERItem		tbsSigAlg;		/* sequence, DERAlgorithmId */
	DERItem		issuer;			/* sequence, TBD */
	DERItem		thisUpdate;		/* ASN_ANY, SAVE_DER */
	DERItem		nextUpdate;		/* ASN_ANY, SAVE_DER */
	DERItem		revokedCerts;	/* sequence of DERRevokedCert, optional */
	DERItem		extensions;		/* sequence, optional, EXPLICIT */
} DERTBSCrl;

/* DERItemSpecs to decode into a DERTBSCrl */
extern const DERSize DERNumTBSCrlItemSpecs;
extern const DERItemSpec DERTBSCrlItemSpecs[DER_counted_by(DERNumTBSCrlItemSpecs)];

typedef struct {
	DERItem		serialNum;		/* integer */
	DERItem		revocationDate;	/* time - ASN_ANY, SAVE_DER */
	DERItem		extensions;		/* sequence, optional, EXPLICIT */
} DERRevokedCert;

/* DERItemSpecs to decode into a DERRevokedCert */
extern const DERSize DERNumRevokedCertItemSpecs;
extern const DERItemSpec DERRevokedCertItemSpecs[DER_counted_by(DERNumRevokedCertItemSpecs)];

__END_DECLS

#endif	/* _DER_CERT_CRL_H_ */

