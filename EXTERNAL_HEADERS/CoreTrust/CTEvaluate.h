//
//  CoreTrust.h
//  CoreTrust
//
//  Copyright © 2017-2020 Apple Inc. All rights reserved.
//

#ifndef _CORETRUST_EVALUATE_H_
#define _CORETRUST_EVALUATE_H_

#include "CTConfig.h"

__BEGIN_DECLS

__ptrcheck_abi_assume_single()

typedef struct x509_octet_string {
    const CT_uint8_t * __counted_by(length) data;
    CT_size_t length;
} CTAsn1Item;

extern const CTAsn1Item CTOidItemAppleImg4Manifest; //1.2.840.113635.100.6.1.15

extern const CTAsn1Item CTOidItemAppleDeviceAttestationNonce;               // 1.2.840.113635.100.8.2
extern const CTAsn1Item CTOidItemAppleDeviceAttestationHardwareProperties;  // 1.2.840.113635.100.8.4
extern const CTAsn1Item CTOidItemAppleDeviceAttestationKeyUsageProperties;  // 1.2.840.113635.100.8.5
extern const CTAsn1Item CTOidItemAppleDeviceAttestationDeviceOSInformation; // 1.2.840.113635.100.8.7


/*! @function CTParseCertificateSet
 @abstract Parses binary (DER-encoded) certificates concatenated in memory into parsed CTAsn1Items
 @param der pointer to beginning of the encoded certificates
 @param der_end pointer to end of the encoded certificates
 @param certStorage an allocated array of CTAsn1Items which will be populated by the parser
 @param certStorageLen the number of CTAsn1Item in certStorage
 @param numParsedCerts return value, the number of certs successfully parse from the input
 @return 0 upon success or a parsing error (see CTErrors.h) */
CT_int CTParseCertificateSet(
    const CT_uint8_t * __ended_by(der_end) der,
    const CT_uint8_t *der_end,
    CTAsn1Item * __counted_by(certStorageLen) certStorage,
    CT_size_t certStorageLen,
    CT_size_t *numParsedCerts);

/*! @function CTParseExtensionValue
 @abstract Parse a certificate and return the value of an extension with a specifed extnId
 @param certData pointer to beginning of the encoded certificate
 @param certLen the length of the certificate
 @param extensionOidData pointer to the extnId OID to find in the certificate
 @param extensionOidLen length of the OID
 @param extensionValueData return value, pointer to the extension value found in the certificate with the specified OID
 @param extensionValueLen return value, length of the extension value found
 @return 0 upon success, a parsing error (see CTErrors.h) */
CT_int CTParseExtensionValue(
    const CT_uint8_t * __counted_by(certLen) certData,
    CT_size_t certLen,
    const CT_uint8_t *__counted_by(extensionOidLen) extensionOidData,
    CT_size_t extensionOidLen,
    const CT_uint8_t * __counted_by(*extensionValueLen) *extensionValueData,
    CT_size_t *extensionValueLen);

/*! @function CTParseKey
 @abstract Parse a certificate and return the public key
 @param certData pointer to beginning of the encoded certificate
 @param certLen the length of the certificate
 @param keyData return value, pointer to the key in the parsed certificate
 @param keyLen return value, length of the key in the parsed certificate
 @return 0 upon success, a parsing error (see CTErrors.h) */
CT_int CTParseKey(
    const CT_uint8_t * __counted_by(certLen) certData,
    CT_size_t certLen,
    const CT_uint8_t *__counted_by(*keyLen) *keyData,
    CT_size_t *keyLen);

/*! @function CTEvaluateSavageCerts
 @abstract Verify certificates against Savage policy, with specified anchor key
 @param certsData  pointer to beginning of the binary (DER-encoded) certificates (leaf first)
 @param certsLen the length of the certificates byte array
 @param rootKeyData pointer to the anchor public key
 @param rootKeyLen length of the anchor public key
 @param leafKeyData return value, pointer to the key in the verified leaf certificate
 @param leafKeyLen return value, length of the key in the verified leaf certificate
 @param isProdCert return value, boolean indicating whether the leaf certificate is prod-issued
 @return 0 upon success, a parsing or validation error (see CTErrors.h) */
CT_int CTEvaluateSavageCerts(
    const CT_uint8_t *__counted_by(certsLen) certsData, CT_size_t certsLen,
    const CT_uint8_t *__counted_by(rootKeyLen) rootKeyData, CT_size_t rootKeyLen,
    const CT_uint8_t *__counted_by(*leafKeyLen) *leafKeyData, CT_size_t *leafKeyLen,
    CT_bool *isProdCert);

/*! @function CTEvaluateSavageCertsWithUID
 @abstract Verify certificates against Savage policy, with specified anchor key
 @param certsData  pointer to beginning of the binary (DER-encoded) certificates (leaf first)
 @param certsLen the length of the certificates byte array
 @param rootKeyData pointer to the anchor public key
 @param rootKeyLen length of the anchor public key
 @param leafKeyData return value, pointer to the key in the verified leaf certificate
 @param leafKeyLen return value, length of the key in the verified leaf certificate
 @param UIDData pointer to a preallocated buffer of UIDLen, which will be populated with the UID
 @param UIDLen length of the UIDData buffer
 @param isProdCert return value, boolean indicating whether the leaf certificate is prod-issued
 @return 0 upon success, a parsing or validation error (see CTErrors.h) */
CT_int CTEvaluateSavageCertsWithUID(
    const CT_uint8_t *__counted_by(certsLen) certsData, CT_size_t certsLen,
    const CT_uint8_t *__counted_by(rootKeyLen) rootKeyData, CT_size_t rootKeyLen,
    const CT_uint8_t *__counted_by(*leafKeyLen) *leafKeyData, CT_size_t *leafKeyLen,
    CT_uint8_t *__counted_by(UIDLen) UIDData, CT_size_t UIDLen,
    CT_bool *isProdCert);

/*! @function CTEvaluateYonkersCerts
 @abstract Verify certificates against Yonkers policy, with specified anchor key
 @param certsData  pointer to beginning of the binary (DER-encoded) certificates (leaf first)
 @param certsLen the length of the certificates byte array
 @param rootKeyData pointer to the anchor public key
 @param rootKeyLen length of the anchor public key
 @param leafKeyData return value, pointer to the key in the verified leaf certificate
 @param leafKeyLen return value, length of the key in the verified leaf certificate
 @param UIDData pointer to a preallocated buffer of UIDLen, which will be populated with the UID
 @param UIDLen length of the UIDData buffer
 @param isProdCert return value, boolean indicating whether the leaf certificate is prod-issued
 @return 0 upon success, a parsing or validation error (see CTErrors.h) */
CT_int CTEvaluateYonkersCerts(
    const CT_uint8_t *__counted_by(certsLen) certsData, CT_size_t certsLen,
    const CT_uint8_t *__counted_by(rootKeyLen) rootKeyData, CT_size_t rootKeyLen,
    const CT_uint8_t *__counted_by(*leafKeyLen) *leafKeyData, CT_size_t *leafKeyLen,
    CT_uint8_t *__counted_by(UIDLen) UIDData, CT_size_t UIDLen,
    CT_bool *isProdCert);

/*! @function CTEvaluateSensorCerts
 @abstract Verify certificates against Sensor(s) policy, with specified anchor key and intermediate marker value
 @param certsData  pointer to beginning of the binary (DER-encoded) certificates (leaf first)
 @param certsLen the length of the certificates byte array
 @param rootKeyData pointer to the anchor public key
 @param rootKeyLen length of the anchor public key
 @param intermediateMarker pointer to the value expected in the intermediate marker extension
 @param intermediateMarkerLen length of the intermediate marker value
 @param leafKeyData return value, pointer to the key in the verified leaf certificate
 @param leafKeyLen return value, length of the key in the verified leaf certificate
 @param UIDData pointer to a preallocated buffer of UIDLen, which will be populated with the UID
 @param UIDLen length of the UIDData buffer
 @param isProdCert return value, boolean indicating whether the leaf certificate is prod-issued
 @return 0 upon success, a parsing or validation error (see CTErrors.h) */
CT_int CTEvaluateSensorCerts(
    const CT_uint8_t *__counted_by(certsLen) certsData, CT_size_t certsLen,
    const CT_uint8_t *__counted_by(rootKeyLen) rootKeyData, CT_size_t rootKeyLen,
    const CT_uint8_t *__counted_by(intermediateMarkerLen) intermediateMarker, CT_size_t intermediateMarkerLen,
    const CT_uint8_t *__counted_by(*leafKeyLen) *leafKeyData, CT_size_t *leafKeyLen,
    CT_uint8_t *__counted_by(UIDLen) UIDData, CT_size_t UIDLen,
    CT_bool *isProdCert);

/*! @function CTEvaluateAcrt
 @abstract Verify certificates against acrt policy
 @param certsData  pointer to beginning of the binary (DER-encoded) certificates (leaf first)
 @param certsLen the length of the certificates byte array
 @param leafKeyData return value, pointer to the key in the verified leaf certificate
 @param leafKeyLen return value, length of the key in the verified leaf certificate
 @return 0 upon success, a parsing or validation error (see CTErrors.h) */
CT_int CTEvaluateAcrt(
    const CT_uint8_t *__counted_by(certsLen) certsData, CT_size_t certsLen,
    const CT_uint8_t *__counted_by(*leafKeyLen) *leafKeyData, CT_size_t *leafKeyLen);

/*! @function CTEvaluateUcrt
 @abstract Verify certificates against ucrt policy
 @param certsData  pointer to beginning of the binary (DER-encoded) certificates (leaf first)
 @param certsLen the length of the certificates byte array
 @param leafKeyData return value, pointer to the key in the verified leaf certificate
 @param leafKeyLen return value, length of the key in the verified leaf certificate
 @return 0 upon success, a parsing or validation error (see CTErrors.h) */
CT_int CTEvaluateUcrt(
    const CT_uint8_t *__counted_by(certsLen) certsData, CT_size_t certsLen,
    const CT_uint8_t *__counted_by(*leafKeyLen) *leafKeyData, CT_size_t *leafKeyLen);  // Output: points to the leaf key data in the input certsData)

/*! @function CTEvaluateUcrtTestRoot
 @abstract Verify certificates against ucrt policy, with optional anchor key for test roots
 @param certsData  pointer to beginning of the binary (DER-encoded) certificates (leaf first)
 @param certsLen the length of the certificates byte array
 @param rootKeyData optional pointer to the test anchor public key. If unspecified the production anchor will be used
 @param rootKeyLen length of the optional anchor public key
 @param leafKeyData return value, pointer to the key in the verified leaf certificate
 @param leafKeyLen return value, length of the key in the verified leaf certificate
 @return 0 upon success, a parsing or validation error (see CTErrors.h) */
CT_int CTEvaluateUcrtTestRoot(
    const CT_uint8_t *__counted_by(certsLen) certsData, CT_size_t certsLen,
    const CT_uint8_t *__counted_by(rootKeyLen) rootKeyData, CT_size_t rootKeyLen,
    const CT_uint8_t *__counted_by(*leafKeyLen) *leafKeyData, CT_size_t *leafKeyLen);

/*! @function CTEvaluateBAASystem
 @abstract Verify certificates against BAA scrt-attested policy
 @param certsData  pointer to beginning of the binary (DER-encoded) certificates (leaf first)
 @param certsLen the length of the certificates byte array
 @param leafKeyData return value, pointer to the key in the verified leaf certificate
 @param leafKeyLen return value, length of the key in the verified leaf certificate
 @return 0 upon success, a parsing or validation error (see CTErrors.h) */
CT_int CTEvaluateBAASystem(
    const CT_uint8_t *__counted_by(certsLen) certsData, CT_size_t certsLen,
    const CT_uint8_t *__counted_by(*leafKeyLen) *leafKeyData, CT_size_t *leafKeyLen);

typedef struct baa_identity {
    CT_uint32_t chipId;
    CT_uint64_t ecid;
    CT_bool productionStatus;
    CT_bool securityMode;
    CT_uint8_t securityDomain;
    CTAsn1Item img4;
} CTBAAIdentity;

/*! @function CTEvaluateBAASystemWithId
 @abstract Verify certificates against BAA scrt-attested policy, returning BAA identity
 @param certsData  pointer to beginning of the binary (DER-encoded) certificates (leaf first)
 @param certsLen the length of the certificates byte array
 @param leafKeyData return value, pointer to the key in the verified leaf certificate
 @param leafKeyLen return value, length of the key in the verified leaf certificate
 @param identity return value, BAA identity from leaf certificate
 @return 0 upon success, a parsing or validation error (see CTErrors.h) */
CT_int CTEvaluateBAASystemWithId(
    const CT_uint8_t *__counted_by(certsLen) certsData, CT_size_t certsLen,
    const CT_uint8_t *__counted_by(*leafKeyLen) *leafKeyData, CT_size_t *leafKeyLen,
    CTBAAIdentity *identity);

/*! @function CTEvaluateBAASystemTestRoot
 @abstract Verify certificates against BAA scrt-attested policy, returning BAA identity with optional anchor key for test roots
 @param certsData  pointer to beginning of the binary (DER-encoded) certificates (leaf first)
 @param certsLen the length of the certificates byte array
 @param rootKeyData optional pointer to the test anchor public key. If unspecified the production anchor will be used
 @param rootKeyLen length of the optional anchor public key
 @param leafKeyData return value, pointer to the key in the verified leaf certificate
 @param leafKeyLen return value, length of the key in the verified leaf certificate
 @param identity return value, BAA identity from leaf certificate
 @return 0 upon success, a parsing or validation error (see CTErrors.h) */
CT_int CTEvaluateBAASystemTestRoot(
    const CT_uint8_t *__counted_by(certsLen) certsData, CT_size_t certsLen,
    const CT_uint8_t *__counted_by(rootKeyLen) rootKeyData, CT_size_t rootKeyLen,
    const CT_uint8_t *__counted_by(*leafKeyLen) *leafKeyData, CT_size_t *leafKeyLen,
    CTBAAIdentity *identity);

/*! @function CTEvaluateBAAUser
 @abstract Verify certificates against BAA ucrt-attested policy, returning BAA identity
 @param certsData  pointer to beginning of the binary (DER-encoded) certificates (leaf first)
 @param certsLen the length of the certificates byte array
 @param leafKeyData return value, pointer to the key in the verified leaf certificate
 @param leafKeyLen return value, length of the key in the verified leaf certificate
 @param identity return value, BAA identity from leaf certificate
 @return 0 upon success, a parsing or validation error (see CTErrors.h) */
CT_int CTEvaluateBAAUser(
    const CT_uint8_t *__counted_by(certsLen) certsData, CT_size_t certsLen,
    const CT_uint8_t *__counted_by(*leafKeyLen) *leafKeyData, CT_size_t *leafKeyLen,
    CTBAAIdentity *identity);

/*! @function CTEvaluateBAAUserTestRoot
 @abstract Verify certificates against BAA ucrt-attested policy, returning BAA identity with optional anchor key for test roots
 @param certsData  pointer to beginning of the binary (DER-encoded) certificates (leaf first)
 @param certsLen the length of the certificates byte array
 @param rootKeyData optional pointer to the test anchor public key. If unspecified the production anchor will be used
 @param rootKeyLen length of the optional anchor public key
 @param leafKeyData return value, pointer to the key in the verified leaf certificate
 @param leafKeyLen return value, length of the key in the verified leaf certificate
 @param identity return value, BAA identity from leaf certificate
 @return 0 upon success, a parsing or validation error (see CTErrors.h) */
CT_int CTEvaluateBAAUserTestRoot(
    const CT_uint8_t *__counted_by(certsLen) certsData, CT_size_t certsLen,
    const CT_uint8_t *__counted_by(rootKeyLen) rootKeyData, CT_size_t rootKeyLen,
    const CT_uint8_t *__counted_by(*leafKeyLen) *leafKeyData, CT_size_t *leafKeyLen,
    CTBAAIdentity *identity);

/*! @function CTEvaluateBAAAccessory
 @abstract Verify certificates against BAA accessory (MFi4) policy
 @param certsData  pointer to beginning of the binary (DER-encoded) certificates (leaf first)
 @param certsLen the length of the certificates byte array
 @param rootKeyData optional pointer to the test anchor public key. If unspecified the production anchor will be used
 @param rootKeyLen length of the optional anchor public key
 @param leafKeyData return value, pointer to the key in the verified leaf certificate
 @param leafKeyLen return value, length of the key in the verified leaf certificate
 @param propertiesData return value, pointer to the Apple Accessories properties extension value in the verified leaf certificate
 @param propertiesLen return value, length of the properties in the verified leaf certificate
 @return 0 upon success, a parsing or validation error (see CTErrors.h) */
CT_int CTEvaluateBAAAccessory(
    const CT_uint8_t *__counted_by(certsLen) certsData, CT_size_t certsLen,
    const CT_uint8_t *__counted_by(rootKeyLen) rootKeyData, CT_size_t rootKeyLen,
    const CT_uint8_t *__counted_by(*leafKeyLen) *leafKeyData, CT_size_t *leafKeyLen,
    const CT_uint8_t *__counted_by(*propertiesLen) *propertiesData, CT_size_t *propertiesLen);

/*! @function CTEvaluateSatori
 @abstract Verify certificates against Satori policy
 @param certsData  pointer to beginning of the binary (DER-encoded) certificates (leaf first)
 @param certsLen the length of the certificates byte array
 @param allowTestRoot allow the Test Apple roots to be used as anchors  in addition to the production roots
 @param leafKeyData return value, pointer to the key in the verified leaf certificate
 @param leafKeyLen return value, length of the key in the verified leaf certificate
 @return 0 upon success, a parsing or validation error (see CTErrors.h) */
CT_int CTEvaluateSatori(
    const CT_uint8_t *__counted_by(certsLen) certsData, CT_size_t certsLen,
    CT_bool allowTestRoot,
    const CT_uint8_t *__counted_by(*leafKeyLen) *leafKeyData, CT_size_t *leafKeyLen);

/*! @function CTEvaluatePragueSignatureCMS
 @abstract Verify CMS signature and certificates against Prague policy
 @param cmsData  pointer to beginning of the binary (BER-encoded) CMS object
 @param cmsLen the length of the CMS object
 @param detachedData pointer to data that is signed by the CMS object
 @param detachedDataLen the length of the signed data
 @param allowTestRoot allow the Test Apple roots to be used as anchors  in addition to the production roots
 @param leafKeyData return value, pointer to the key in the verified leaf certificate
 @param leafKeyLen return value, length of the key in the verified leaf certificate
 @return 0 upon success, a parsing or validation error (see CTErrors.h) */
CT_int CTEvaluatePragueSignatureCMS(
    const CT_uint8_t *__counted_by(cmsLen) cmsData, CT_size_t cmsLen,
    const CT_uint8_t *__counted_by(detachedDataLen) detachedData, CT_size_t detachedDataLen,
    CT_bool allowTestRoot,
    const CT_uint8_t *__counted_by(*leafKeyLen) *leafKeyData, CT_size_t *leafKeyLen);

/*! @function CTEvaluateKDLSignatureCMS
 @abstract Verify CMS signature and certificates against KDL policy
 @param cmsData  pointer to beginning of the binary (BER-encoded) CMS object
 @param cmsLen the length of the CMS object
 @param detachedData pointer to data that is signed by the CMS object
 @param detachedDataLen the length of the signed data
 @param allowTestRoot allow the Test Apple roots to be used as anchors  in addition to the production roots
 @param leafKeyData return value, pointer to the key in the verified leaf certificate
 @param leafKeyLen return value, length of the key in the verified leaf certificate
 @return 0 upon success, a parsing or validation error (see CTErrors.h) */
CT_int CTEvaluateKDLSignatureCMS(
    const CT_uint8_t *__counted_by(cmsLen) cmsData, CT_size_t cmsLen,                    // Input: CMS signature blob
    const CT_uint8_t *__counted_by(detachedDataLen) detachedData, CT_size_t detachedDataLen,      // Input: data signed by CMS blob
    CT_bool allowTestRoot,                                          // Input: permit use of test hierarchy
    const CT_uint8_t *__counted_by(*leafKeyLen) *leafKeyData, CT_size_t *leafKeyLen);         // Output: points to leaf key data in input cmsData

typedef CT_uint64_t CoreTrustPolicyFlags;
enum {
    CORETRUST_POLICY_BASIC =                0,
    CORETRUST_POLICY_SAVAGE_DEV =           1 << 0,
    CORETRUST_POLICY_SAVAGE_PROD =          1 << 1,
    CORETRUST_POLICY_MFI_AUTHV3 =           1 << 2,
    CORETRUST_POLICY_MAC_PLATFORM =         1 << 3,
    CORETRUST_POLICY_MAC_DEVELOPER =        1 << 4,
    CORETRUST_POLICY_DEVELOPER_ID =         1 << 5,
    CORETRUST_POLICY_MAC_APP_STORE =        1 << 6,
    CORETRUST_POLICY_IPHONE_DEVELOPER =     1 << 7,
    CORETRUST_POLICY_IPHONE_APP_PROD =      1 << 8,
    CORETRUST_POLICY_IPHONE_APP_DEV =       1 << 9,
    CORETRUST_POLICY_IPHONE_VPN_PROD =      1 << 10,
    CORETRUST_POLICY_IPHONE_VPN_DEV =       1 << 11,
    CORETRUST_POLICY_TVOS_APP_PROD =        1 << 12,
    CORETRUST_POLICY_TVOS_APP_DEV =         1 << 13,
    CORETRUST_POLICY_TEST_FLIGHT_PROD =     1 << 14,
    CORETRUST_POLICY_TEST_FLIGHT_DEV =      1 << 15,
    CORETRUST_POLICY_IPHONE_DISTRIBUTION =  1 << 16,
    CORETRUST_POLICY_MAC_SUBMISSION =       1 << 17,
    CORETRUST_POLICY_YONKERS_DEV =          1 << 18,
    CORETRUST_POLICY_YONKERS_PROD =         1 << 19,
    CORETRUST_POLICY_MAC_PLATFORM_G2 =      1 << 20,
    CORETRUST_POLICY_ACRT =                 1 << 21,
    CORETRUST_POLICY_SATORI =               1 << 22,
    CORETRUST_POLICY_BAA =                  1 << 23,
    CORETRUST_POLICY_BAA_SYSTEM =           1 << 23, // BAA and BAA_SYSTEM are the same
    CORETRUST_POLICY_UCRT =                 1 << 24,
    CORETRUST_POLICY_PRAGUE =               1 << 25,
    CORETRUST_POLICY_KDL =                  1 << 26,
    CORETRUST_POLICY_MFI_AUTHV2 =           1 << 27,
    CORETRUST_POLICY_MFI_SW_AUTH_PROD =     1 << 28,
    CORETRUST_POLICY_MFI_SW_AUTH_DEV =      1 << 29,
    CORETRUST_POLICY_COMPONENT =            1 << 30,
    CORETRUST_POLICY_IMG4 =                 1ULL << 31,
    CORETRUST_POLICY_SERVER_AUTH =          1ULL << 32,
    CORETRUST_POLICY_SERVER_AUTH_STRING =   1ULL << 33,
    CORETRUST_POLICY_MFI_AUTHV4_ACCESSORY = 1ULL << 34,
    CORETRUST_POLICY_MFI_AUTHV4_ATTESTATION = 1ULL << 35,
    CORETRUST_POLICY_MFI_AUTHV4_PROVISIONING = 1ULL << 36,
    CORETRUST_POLICY_WWDR_CLOUD_MANAGED =   1ULL << 37,
    CORETRUST_POLICY_HAVEN =                1ULL << 38,
    CORETRUST_POLICY_PROVISIONING_PROFILE = 1ULL << 39,
    CORETRUST_POLICY_SENSOR_PROD =          1ULL << 40,
    CORETRUST_POLICY_SENSOR_DEV =           1ULL << 41,
    CORETRUST_POLICY_BAA_USER =             1ULL << 42,
};

typedef CT_uint32_t CoreTrustDigestType;
enum {
    CORETRUST_DIGEST_TYPE_SHA1 = 1,
    CORETRUST_DIGEST_TYPE_SHA224 = 2,
    CORETRUST_DIGEST_TYPE_SHA256 = 4,
    CORETRUST_DIGEST_TYPE_SHA384 = 8,
    CORETRUST_DIGEST_TYPE_SHA512 = 16
};

/*! @function CTParseAmfiCMS
 @abstract Parse CMS signed data
 @param cmsData  pointer to beginning of the binary (BER-encoded) CMS object
 @param cmsLen the length of the CMS object
 @param maxDigestType maximum digest type supported by the client
 @param leafCert return value, pointer to the verified leaf certificate
 @param leafCertLen return value, length of the verified leaf certificate
 @param contentData return value, pointer to the CMS content, if present
 @param contentLen return value, length of the CMS content, if present
 @param cmsDigestType return value, the digest type used to sign the CMS object
 @param policyFlags return value, the CoreTrust policies that the chain may meet (based on leaf certificate only)
 @return 0 upon success, a parsing error (see CTErrors.h)
 */
CT_int CTParseAmfiCMS(
    const CT_uint8_t *__counted_by(cmsLen) cmsData, CT_size_t cmsLen,
    CoreTrustDigestType maxDigestType,
    const CT_uint8_t *__counted_by(*leafCertLen) *leafCert, CT_size_t *leafCertLen,
    const CT_uint8_t *__counted_by(*contentLen) *contentData, CT_size_t *contentLen,
    CoreTrustDigestType *cmsDigestType,
    CoreTrustPolicyFlags *policyFlags);

/*! @function CTVerifyAmfiCMS
 @abstract Verify CMS signed data signature
 @param cmsData  pointer to beginning of the binary (BER-encoded) CMS object
 @param cmsLen the length of the CMS object
 @param digestData  pointer to beginning of the content data hash
 @param digestLen the length of the content data hash
 @param maxDigestType maximum digest type supported by the client
 @param hashAgilityDigestType return value, the highest strength digest type available in the hash agility attribute
 @param hashAgilityDigestData return value, pointer to the hash agility value
 @param hashAgilityDigestLen return value, length of the hash agility value
 @return 0 upon success, a parsing or validation error (see CTErrors.h)
 @discussion
 Returns non-zero if there's a standards-based problem with the CMS or certificates.
 Some notes about hash agility outputs:
 - hashAgilityDigestType is only non-zero for HashAgilityV2
 - If hashAgilityDigestType is non-zero, digestData/Len provides the digest value
 - If hashAgilityDigestType is zero, digestData/Len provides the content of the HashAgilityV1 attribute (if present)
 - If neither HashAgilityV1 nor HashAgilityV2 attributes are found, these outputs will all be NULL.
 */
CT_int CTVerifyAmfiCMS(
    const CT_uint8_t *__counted_by(cmsLen) cmsData, CT_size_t cmsLen,
    const CT_uint8_t *__counted_by(digestLen) digestData, CT_size_t digestLen,
    CoreTrustDigestType maxDigestType,
    CoreTrustDigestType *hashAgilityDigestType,
    const CT_uint8_t *__counted_by(*hashAgilityDigestLen) *hashAgilityDigestData, CT_size_t *hashAgilityDigestLen);

/*!  @function CTVerifyAmfiCertificateChain
 @abstract Verify CMS signed data certificate chain
 @param cmsData  pointer to beginning of the binary (BER-encoded) CMS object
 @param cmsLen the length of the CMS object
 @param allow_test_hierarchy allow the Test Apple roots to be used as anchors  in addition to the production roots
 @param maxDigestType maximum digest type supported by the client
 @param policyFlags return value, the CoreTrust policies that the certificate chain met
 @return 0 upon success, a parsing or validation error (see CTErrors.h)
 @discussion
 Returns non-zero if there's a standards-based problem with the CMS or certificates.
 Policy matching of the certificates is only reflected in the policyFlags output. Namely, if the only problem is that
 the certificates don't match a policy, the returned integer will be 0 (success) and the policyFlags will be 0 (no matching policies).
 */
CT_int CTVerifyAmfiCertificateChain(
    const CT_uint8_t *__counted_by(cmsLen) cmsData, CT_size_t cmsLen,
    CT_bool allow_test_hierarchy,
    CoreTrustDigestType maxDigestType,
    CoreTrustPolicyFlags *policyFlags);

/*! @function CTEvaluateAMFICodeSignatureCMS
 @abstract Verify CMS signature and certificates against the AMFI policies
 @param cmsData  pointer to beginning of the binary (BER-encoded) CMS object
 @param cmsLen the length of the CMS object
 @param detachedData pointer to data that is signed by the CMS object
 @param detachedDataLen the length of the signed data
 @param allow_test_hierarchy allow the Test Apple roots to be used as anchors  in addition to the production roots
 @param leafCert return value, pointer to the verified leaf certificate
 @param leafCertLen return value, length of the verified leaf certificate
 @param policyFlags return value, the CoreTrust policies that the certificate chain met
 @param cmsDigestType return value, the digest type used to sign the CMS object
 @param hashAgilityDigestType return value, the highest strength digest type available in the hash agility attribute
 @param digestData return value, pointer to the hash agility value
 @param digestLen return value, length of the hash agility value
 @return 0 upon success, a parsing or validation error (see CTErrors.h)
 @discussion
 Returns non-zero if there's a standards-based problem with the CMS or certificates.
 Policy matching of the certificates is only reflected in the policyFlags output. Namely, if the only problem is that
 the certificates don't match a policy, the returned integer will be 0 (success) and the policyFlags will be 0 (no matching policies).
 Some notes about hash agility outputs:
 - hashAgilityDigestType is only non-zero for HashAgilityV2
 - If hashAgilityDigestType is non-zero, digestData/Len provides the digest value
 - If hashAgilityDigestType is zero, digestData/Len provides the content of the HashAgilityV1 attribute (if present)
 - If neither HashAgilityV1 nor HashAgilityV2 attributes are found, these outputs will all be NULL.
 */
CT_int CTEvaluateAMFICodeSignatureCMS(
    const CT_uint8_t *__counted_by(cmsLen) cmsData, CT_size_t cmsLen,
    const CT_uint8_t *__counted_by(detachedDataLen) detachedData, CT_size_t detachedDataLen,
    CT_bool allow_test_hierarchy,
    const CT_uint8_t *__counted_by(*leafCertLen) *leafCert, CT_size_t *leafCertLen,
    CoreTrustPolicyFlags *policyFlags,
    CoreTrustDigestType *cmsDigestType,
    CoreTrustDigestType *hashAgilityDigestType,
    const CT_uint8_t *__counted_by(*digestLen) *digestData, CT_size_t *digestLen);

/*! @function CTEvaluateAMFICodeSignatureCMS_MaxDigestType
 @abstract Verify CMS signature and certificates against the AMFI policies
 @param cmsData  pointer to beginning of the binary (BER-encoded) CMS object
 @param cmsLen the length of the CMS object
 @param detachedData pointer to data that is signed by the CMS object
 @param detachedDataLen the length of the signed data
 @param allow_test_hierarchy allow the Test Apple roots to be used as anchors  in addition to the production roots
 @param maxDigestType maximum digest type supported by the client
 @param leafCert return value, pointer to the verified leaf certificate
 @param leafCertLen return value, length of the verified leaf certificate
 @param policyFlags return value, the CoreTrust policies that the certificate chain met
 @param cmsDigestType return value, the digest type used to sign the CMS object
 @param hashAgilityDigestType return value, the highest strength digest type available and supported by client in the hash agility attribute
 @param digestData return value, pointer to the hash agility value
 @param digestLen return value, length of the hash agility value
 @return 0 upon success, a parsing or validation error (see CTErrors.h)
 @discussion
 Returns non-zero if there's a standards-based problem with the CMS or certificates.
 Policy matching of the certificates is only reflected in the policyFlags output. Namely, if the only problem is that
 the certificates don't match a policy, the returned integer will be 0 (success) and the policyFlags will be 0 (no matching policies).
 Some notes about hash agility outputs:
 - hashAgilityDigestType is only non-zero for HashAgilityV2
 - If hashAgilityDigestType is non-zero, digestData/Len provides the digest value
 - If hashAgilityDigestType is zero, digestData/Len provides the content of the HashAgilityV1 attribute (if present)
 - If neither HashAgilityV1 nor HashAgilityV2 attributes are found, these outputs will all be NULL.
 */
CT_int CTEvaluateAMFICodeSignatureCMS_MaxDigestType(
    const CT_uint8_t *__counted_by(cmsLen) cmsData, CT_size_t cmsLen,
    const CT_uint8_t *__counted_by(detachedDataLen) detachedData, CT_size_t detachedDataLen,
    CT_bool allow_test_hierarchy,
    CoreTrustDigestType maxDigestType,
    const CT_uint8_t *__counted_by(*leafCertLen) *leafCert, CT_size_t *leafCertLen,
    CoreTrustPolicyFlags *policyFlags,
    CoreTrustDigestType *cmsDigestType,
    CoreTrustDigestType *hashAgilityDigestType,
    const CT_uint8_t *__counted_by(*digestLen) *digestData, CT_size_t *digestLen);

/*! @function CTEvaluateAMFICodeSignatureCMSPubKey
 @abstract Verify CMS signature and certificates against the AMFI policies
 @param cmsData  pointer to beginning of the binary (BER-encoded) CMS object
 @param cmsLen the length of the CMS object
 @param detachedData pointer to data that is signed by the CMS object
 @param detachedDataLen the length of the signed data
 @param anchorPublicKey anchor public key for self-signed certificate
 @param anchorPublicKeyLen length of the anchor public key
 @param cmsDigestType return value, the digest type used to sign the CMS object
 @param hashAgilityDigestType return value, the highest strength digest type available and supported by client in the hash agility attribute
 @param digestData return value, pointer to the hash agility value
 @param digestLen return value, length of the hash agility value
 @return 0 upon success, a parsing or validation error (see CTErrors.h)
 @discussion
 Returns non-zero if there's a standards-based problem with the CMS or certificates.
 Policy matching of the certificates is only reflected in the policyFlags output. Namely, if the only problem is that
 the certificates don't match a policy, the returned integer will be 0 (success) and the policyFlags will be 0 (no matching policies).
 Some notes about hash agility outputs:
 - hashAgilityDigestType is only non-zero for HashAgilityV2
 - If hashAgilityDigestType is non-zero, digestData/Len provides the digest value
 - If hashAgilityDigestType is zero, digestData/Len provides the content of the HashAgilityV1 attribute (if present)
 - If neither HashAgilityV1 nor HashAgilityV2 attributes are found, these outputs will all be NULL.
 */
int CTEvaluateAMFICodeSignatureCMSPubKey(
    const CT_uint8_t *__counted_by(cmsLen) cmsData, CT_size_t cmsLen,
    const CT_uint8_t *__counted_by(detachedDataLen) detachedData, CT_size_t detachedDataLen,
    const CT_uint8_t *__counted_by(anchorPublicKeyLen) anchorPublicKey, CT_size_t anchorPublicKeyLen,
    CoreTrustDigestType *cmsDigestType,
    CoreTrustDigestType *hashAgilityDigestType,
    const CT_uint8_t *__counted_by(*digestLen) *digestData, CT_size_t *digestLen);

/*! @function CTParseAccessoryCerts
 @abstract Parse a CMS or binary encoded set of certificates and return the leaf and subCA(s)
 @param certsData  pointer to beginning of the binary (DER-encoded) certificates or binary (BER-encoded) CMS object
 @param certsLen the length of the input certificates
 @param leafCertData return value, pointer to the leaf certificate
 @param leafCertLen return value, length of the leaf certificate
 @param subCACertData return value, pointer to the subCA certificate(s), if present, null otherwise
 @param subCACertLen return value, length of the subCA certificates
 @param flags return value, the policy flags set by the leaf certificate (to indicate which type of accessory cert)
 @return 0 upon success, a parsing error (see CTErrors.h) */
CT_int CTParseAccessoryCerts(
    const CT_uint8_t *__counted_by(certsLen) certsData, CT_size_t certsLen,
    const CT_uint8_t *__counted_by(*leafCertLen) *leafCertData, CT_size_t *leafCertLen,
    const CT_uint8_t *__counted_by(*subCACertLen) *subCACertData, CT_size_t *subCACertLen,
    CoreTrustPolicyFlags *flags);

/*! @function CTEvaluateAccessoryCert
 @abstract Verify certificates against a specified accessory policy and anchor
 @param leafCertData  pointer to beginning of the binary (DER-encoded) leaf certificate
 @param leafCertLen the length of the leaf certificate
 @param subCACertData optional pointer to beginning of the binary (DER-encoded) subCA certificate(s)
 @param subCACertLen the length of thesubCA certificate(s)
 @param anchorCertData  pointer to beginning of the binary (DER-encoded) anchor certificate
 @param anchorCertLen the length of the anchor certificate
 @param policy the policy to verify the certificates against, see discussion
 @param leafKeyData return value, pointer to the key in the verified leaf certificate
 @param leafKeyLen return value, length of the key in the verified leaf certificate
 @param extensionValueData return value, pointer to the extension value in the verified leaf certificate, see discussion
 @param extensionValueLen return value, length of the extension value in the verified leaf certificate
 @return 0 upon success, a parsing or validation error (see CTErrors.h)
 @discussion It is expected that callers will first use CTParseAccessoryCerts and then pass that data into CTEvaluateAccessoryCert.
 Which extension value is returned is based on which policy the cert was verified against:
 - For MFI AuthV3, this is the value of the extension with OID 1.2.840.113635.100.6.36
 - For SW Auth, this is the value of the extension with OID 1.2.840.113635.100.6.59.1 (GeneralCapabilities extension)
 - For Component certs, this si the value of the extension with OID 1.2.840.113635.100.11.1 (Component Type)
 - For MFi AuthV4, this is the value of the extension with OID 1.2.840.113635.100.6.71.1 (Apple Accessory Properties extension)
 The following CoreTrustPolicyFlags are accepted:
 - CORETRUST_POLICY_BASIC
 - CORETRUST_POLICY_MFI_AUTHV2
 - CORETRUST_POLICY_MFI_AUTHV3
 - CORETRUST_POLICY_MFI_SW_AUTH_DEV
 - CORETRUST_POLICY_MFI_SW_AUTH_PROD
 - CORETRUST_POLICY_COMPONENT
 - CORETRUST_POLICY_MFI_AUTHV4_ACCESSORY
 - CORETRUST_POLICY_MFI_AUTHV4_ATTESTATION
 - CORETRUST_POLICY_MFI_AUTHV4_PROVISIONING
 */
CT_int CTEvaluateAccessoryCert(
    const CT_uint8_t *__counted_by(leafCertLen) leafCertData, CT_size_t leafCertLen,
    const CT_uint8_t *__counted_by(subCACertLen) subCACertData, CT_size_t subCACertLen,
    const CT_uint8_t *__counted_by(anchorCertLen) anchorCertData, CT_size_t anchorCertLen,
    CoreTrustPolicyFlags policy,
    const CT_uint8_t *__counted_by(*leafKeyLen) *leafKeyData, CT_size_t *leafKeyLen,
    const CT_uint8_t *__counted_by(*extensionValueLen) *extensionValueData, CT_size_t *extensionValueLen);

/*! @function CTEvaluateAppleSSL
 @abstract Verify certificates against an Apple SSL pinning policy
 @param certsData  pointer to beginning of the binary (DER-encoded) certificates (leaf first)
 @param certsLen the length of the certificates byte array
 @param hostnameData the hostname of the server being connected to
 @param hostnameLen length of the hostname
 @param leafMarker the last decimat of the leaf marker OID for this project (e.g. 32 for 1.2.840.113635.100.6.27.32)
 @param allowTestRoots allow the Test Apple roots to be used as anchors  in addition to the production roots
 @return 0 upon success, a parsing or validation error (see CTErrors.h) */
CT_int CTEvaluateAppleSSL(
    const CT_uint8_t *__counted_by(certsLen) certsData, CT_size_t certsLen,
    const CT_uint8_t *__counted_by(hostnameLen) hostnameData, CT_size_t hostnameLen,
    CT_uint64_t leafMarker,
    CT_bool allowTestRoots);

/*! @function CTEvaluateAppleSSLWithOptionalTemporalCheck
 @abstract Verify certificates against an Apple SSL pinning policy
 @param certsData  pointer to beginning of the binary (DER-encoded) certificates (leaf first)
 @param certsLen the length of the certificates byte array
 @param hostnameData the hostname of the server being connected to
 @param hostnameLen length of the hostname
 @param leafMarker the last decimat of the leaf marker OID for this project (e.g. 32 for 1.2.840.113635.100.6.27.32)
 @param allowTestRoots allow the Test Apple roots to be used as anchors  in addition to the production roots
 @param checkTemporalValidity indicate whether to check the temporal validity of certificates
 @return 0 upon success, a parsing or validation error (see CTErrors.h) */
CT_int CTEvaluateAppleSSLWithOptionalTemporalCheck(
    const CT_uint8_t *__counted_by(certsLen) certsData, CT_size_t certsLen,
    const CT_uint8_t *__counted_by(hostnameLen) hostnameData, CT_size_t hostnameLen,
    CT_uint64_t leafMarker,
    CT_bool allowTestRoots,
    CT_bool checkTemporalValidity);

/*! @function CTEvaluateProvisioningProfile
 @abstract Parse and verify the certificates of a signed provisioning profile
 @param provisioningProfileData  pointer to beginning of the binary (BER-encoded) provisioning profile CMS object
 @param provisioningProfileLen the length of the provisioning profile
 @param allowTestRoots allow the Test Apple roots to be used as anchors  in addition to the production roots
 @param contentData return value, pointer to the profile content
 @param contentLen return value, length of the profile content
 @return 0 upon success, a parsing or validation error (see CTErrors.h) */
int CTEvaluateProvisioningProfile(
    const CT_uint8_t *__counted_by(provisioningProfileLen) provisioningProfileData, CT_size_t provisioningProfileLen,
    CT_bool allowTestRoots,
    const CT_uint8_t *__counted_by(*contentLen) *contentData, CT_size_t *contentLen);

__END_DECLS

#endif /* _CORETRUST_EVALUATE_H_ */
