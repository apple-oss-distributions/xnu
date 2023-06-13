//
//  CoreTrust.h
//  CoreTrust
//
//  Copyright © 2017-2020 Apple Inc. All rights reserved.
//

#ifndef _CORETRUST_EVALUATE_H_
#define _CORETRUST_EVALUATE_H_

#if !defined(EFI) || !EFI
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#else // EFI
// This requires $(SDKROOT)/usr/local/efi/include/Platform to be in your header
// search path.
#include <Apple/Common/Library/Include/EfiCompatibility.h>
#endif // EFI

#if EFI
    #if defined(__cplusplus)
        #define __BEGIN_DECLS extern "C" {
        #define __END_DECLS }
    #else
        #define __BEGIN_DECLS
        #define __END_DECLS
    #endif
#else // !EFI
#include <sys/cdefs.h>
#endif // !EFI

__BEGIN_DECLS

#if !EFI
typedef uint8_t CT_uint8_t;
typedef uint32_t CT_uint32_t;
typedef uint64_t CT_uint64_t;
typedef size_t CT_size_t;
typedef int CT_int;
typedef bool CT_bool;
#else
typedef UINT8 CT_uint8_t;
typedef UINT32 CT_uint32_t;
typedef INT32 CT_int;
typedef UINT64 CT_uint64_t;
typedef size_t CT_size_t;
typedef BOOLEAN CT_bool;
#endif

typedef struct x509_octet_string {
    const CT_uint8_t *data;
    CT_size_t length;
} CTAsn1Item;

extern const CTAsn1Item CTOidItemAppleDeviceAttestationNonce;               // 1.2.840.113635.100.8.2
extern const CTAsn1Item CTOidItemAppleDeviceAttestationHardwareProperties;  // 1.2.840.113635.100.8.4
extern const CTAsn1Item CTOidItemAppleDeviceAttestationKeyUsageProperties;  // 1.2.840.113635.100.8.5
extern const CTAsn1Item CTOidItemAppleDeviceAttestationDeviceOSInformation; // 1.2.840.113635.100.8.7

CT_int CTParseCertificateSet(
    const CT_uint8_t *der, const CT_uint8_t *der_end,     // Input: binary representation of concatenated DER-encoded certs
    CTAsn1Item *certStorage, CT_size_t certStorageLen,    // Output: An array of certStorageLen CTAsn1Items that will be populated with the
                                                          //    CTAsn1Item for each parsed cert (in the same order as input)
    CT_size_t *numParsedCerts);                           // Output: number of successfully parsed certs

CT_int CTParseExtensionValue(
    const CT_uint8_t *certData, CT_size_t certLen,                          // Input: binary representation of DER-encoded cert
    const CT_uint8_t *extensionOidData, CT_size_t extensionOidLen,          // Input: extension OID to return value
    const CT_uint8_t **extensionValueData, CT_size_t *extensionValueLen);   // Output: points to the extension value

CT_int CTEvaluateSavageCerts(
    const CT_uint8_t *certsData, CT_size_t certsLen,
    const CT_uint8_t *rootKeyData, CT_size_t rootKeyLen,
    const CT_uint8_t **leafKeyData, CT_size_t *leafKeyLen,
    CT_bool *isProdCert);

CT_int CTEvaluateSavageCertsWithUID(
    const CT_uint8_t *certsData, CT_size_t certsLen,
    const CT_uint8_t *rootKeyData, CT_size_t rootKeyLen,
    const CT_uint8_t **leafKeyData, CT_size_t *leafKeyLen, // Output: points to the leaf key data in the input certsData
    CT_uint8_t *UIDData, CT_size_t UIDLen,                 // Output: a pre-allocated buffer of UIDLen
    CT_bool *isProdCert);

CT_int CTEvaluateYonkersCerts(
    const CT_uint8_t *certsData, CT_size_t certsLen,
    const CT_uint8_t *rootKeyData, CT_size_t rootKeyLen,
    const CT_uint8_t **leafKeyData, CT_size_t *leafKeyLen, // Output: points to the leaf key data in the input certsData
    CT_uint8_t *UIDData, CT_size_t UIDLen,                 // Output: a pre-allocated buffer of UIDLen
    CT_bool *isProdCert);

CT_int CTEvaluateAcrt(
    const CT_uint8_t *certsData, CT_size_t certsLen,         // Input: binary representation of at most 3 concatenated certs
                                                             //         with leaf first (root may be omitted)
    const CT_uint8_t **leafKeyData, CT_size_t *leafKeyLen);  // Output: points to the leaf key data in the input certsData

CT_int CTEvaluateUcrt(
    const CT_uint8_t *certsData, CT_size_t certsLen,         // Input: binary representation of exactly 3 concatenated
                                                             //        DER-encoded certs, with leaf first
    const CT_uint8_t **leafKeyData, CT_size_t *leafKeyLen);  // Output: points to the leaf key data in the input certsData)

CT_int CTEvaluateUcrtTestRoot(
    const CT_uint8_t *certsData, CT_size_t certsLen,         // Input: binary representation of exactly 3 concatenated
                                                             //        DER-encoded certs, with leaf first
    const CT_uint8_t *rootKeyData, CT_size_t rootKeyLen,     // Input: Root public key, if not specified production root will be used
    const CT_uint8_t **leafKeyData, CT_size_t *leafKeyLen);  // Output: points to the leaf key data in the input certsData)

CT_int CTEvaluateBAASystem(
    const CT_uint8_t *certsData, CT_size_t certsLen,        // Input: binary representation of exactly 3 concatenated
                                                            //        DER-encoded certs, with leaf first
    const CT_uint8_t **leafKeyData, CT_size_t *leafKeyLen); // Output: points to the leaf key data in the input certsData

typedef struct baa_identity {
    CT_uint32_t chipId;
    CT_uint64_t ecid;
    CT_bool productionStatus;
    CT_bool securityMode;
    CT_uint8_t securityDomain;
    CTAsn1Item img4;
} CTBAAIdentity;

CT_int CTEvaluateBAASystemWithId(
    const CT_uint8_t *certsData, CT_size_t certsLen,          // Input: binary representation of exactly 3 concatenated
                                                              //        DER-encoded certs, with leaf first
    const CT_uint8_t **leafKeyData, CT_size_t *leafKeyLen,    // Output: points to the leaf key data in the input certsData
    CTBAAIdentity *identity);                                 // Output from identity field in leaf certificate

CT_int CTEvaluateBAASystemTestRoot(
    const CT_uint8_t *certsData, CT_size_t certsLen,        // Input: binary representation of exactly 3 concatenated
                                                            //        DER-encoded certs, with leaf first
    const CT_uint8_t *rootKeyData, CT_size_t rootKeyLen,    // Input: Root public key, if not specified production root will be used
    const CT_uint8_t **leafKeyData, CT_size_t *leafKeyLen,  // Output: points to the leaf key data in the input certsData
    CTBAAIdentity *identity);                               // Output from identity field in leaf certificate

CT_int CTEvaluateBAAUser(
    const CT_uint8_t *certsData, CT_size_t certsLen,          // Input: binary representation of exactly 3 concatenated
                                                              //        DER-encoded certs, with leaf first
    const CT_uint8_t **leafKeyData, CT_size_t *leafKeyLen,    // Output: points to the leaf key data in the input certsData
    CTBAAIdentity *identity);                                 // Output from identity field in leaf certificate

CT_int CTEvaluateBAAUserTestRoot(
    const CT_uint8_t *certsData, CT_size_t certsLen,        // Input: binary representation of exactly 3 concatenated
                                                            //        DER-encoded certs, with leaf first
    const CT_uint8_t *rootKeyData, CT_size_t rootKeyLen,    // Input: Root public key, if not specified production root will be used
    const CT_uint8_t **leafKeyData, CT_size_t *leafKeyLen,  // Output: points to the leaf key data in the input certsData
    CTBAAIdentity *identity);                               // Output from identity field in leaf certificate

CT_int CTEvaluateBAAAccessory(
    const CT_uint8_t *certsData, CT_size_t certsLen,        // Input: binary representation of 2-4 concatenated
                                                            //        DER-encoded certs, with leaf first
    const CT_uint8_t *rootKeyData, CT_size_t rootKeyLen,    // Input: Root public key, if not specified
                                                            //        production root will be used
    const CT_uint8_t **leafKeyData, CT_size_t *leafKeyLen,  // Output: points to the leaf key data in the input certsData
    const CT_uint8_t **propertiesData, CT_size_t *propertiesLen); // Output: points to the Apple Accessory Properties extension value

CT_int CTEvaluateSatori(
    const CT_uint8_t *certsData, CT_size_t certsLen,           // Input: binary (DER) representation of 3 concatenated certs
                                                               //        with leaf first
    CT_bool allowTestRoot,                                     // Input: whether to allow the Test Apple Roots
    const CT_uint8_t **leafKeyData, CT_size_t *leafKeyLen);    // Output: points to the leaf key data in the input certsData

CT_int CTEvaluatePragueSignatureCMS(
    const CT_uint8_t *cmsData, CT_size_t cmsLen,                 // Input: CMS signature blob
    const CT_uint8_t *detachedData, CT_size_t detachedDataLen,   // Input: data signed by CMS blob
    CT_bool allowTestRoot,                                       // Input: permit use of test hierarchy
    const CT_uint8_t **leafKeyData, CT_size_t *leafKeyLen);      // Output: points to leaf key data in input cmsData

CT_int CTEvaluateKDLSignatureCMS(
    const CT_uint8_t *cmsData, CT_size_t cmsLen,                    // Input: CMS signature blob
    const CT_uint8_t *detachedData, CT_size_t detachedDataLen,      // Input: data signed by CMS blob
    CT_bool allowTestRoot,                                          // Input: permit use of test hierarchy
    const CT_uint8_t **leafKeyData, CT_size_t *leafKeyLen);         // Output: points to leaf key data in input cmsData

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
};

typedef CT_uint32_t CoreTrustDigestType;
enum {
    CORETRUST_DIGEST_TYPE_SHA1 = 1,
    CORETRUST_DIGEST_TYPE_SHA224 = 2,
    CORETRUST_DIGEST_TYPE_SHA256 = 4,
    CORETRUST_DIGEST_TYPE_SHA384 = 8,
    CORETRUST_DIGEST_TYPE_SHA512 = 16
};

CT_int CTEvaluateAMFICodeSignatureCMS(
    const CT_uint8_t *cmsData, CT_size_t cmsLen,               // Input: CMS blob
    const CT_uint8_t *detachedData, CT_size_t detachedDataLen, // Input: data signed by CMS blob
    CT_bool allow_test_hierarchy,                              // Input: permit use of test hierarchy
    const CT_uint8_t **leafCert, CT_size_t *leafCertLen,       // Output: signing certificate
    CoreTrustPolicyFlags *policyFlags,                         // Output: policy met by signing certificate
    CoreTrustDigestType *cmsDigestType,                        // Output: digest used to sign the CMS blob
    CoreTrustDigestType *hashAgilityDigestType,                // Output: highest strength digest type
                                                               //          from hash agility attribute
    const CT_uint8_t **digestData, CT_size_t *digestLen);      // Output: pointer to hash agility value
                                                               //          in CMS blob (with digest type above)

/* Returns non-zero if there's a standards-based problem with the CMS or certificates.
 * Policy matching of the certificates is only reflected in the policyFlags output. Namely, if the only problem is that
 * the certificates don't match a policy, the returned integer will be 0 (success) and the policyFlags will be 0 (no matching policies).
 * Some notes about hash agility outputs:
 *  - hashAgilityDigestType is only non-zero for HashAgilityV2
 *  - If hashAgilityDigestType is non-zero, digestData/Len provides the digest value
 *  - If hashAgilityDigestType is zero, digestData/Len provides the content of the HashAgilityV1 attribute (if present)
 *  - If neither HashAgilityV1 nor HashAgilityV2 attributes are found, these outputs will all be NULL.
 */

int CTEvaluateAMFICodeSignatureCMSPubKey(
    const CT_uint8_t *cmsData, CT_size_t cmsLen,                        // Input: CMS blob
    const CT_uint8_t *detachedData, CT_size_t detachedDataLen,          // Input: data signed by CMS blob
    const CT_uint8_t *anchorPublicKey, CT_size_t anchorPublicKeyLen,    // Input: anchor public key for self-signed cert
    CoreTrustDigestType *cmsDigestType,                                 // Output: digest used to sign the CMS blob
    CoreTrustDigestType *hashAgilityDigestType,                         // Output: highest strength digest type
                                                                        //          from hash agility attribute
    const CT_uint8_t **digestData, CT_size_t *digestLen);               // Output: pointer to hash agility value
                                                                        //          in CMS blob (with digest type above)

CT_int CTParseAccessoryCerts(
    const CT_uint8_t *certsData, CT_size_t certsLen,            // Input: CMS or binary representation of DER-encoded certs
    const CT_uint8_t **leafCertData, CT_size_t *leafCertLen,    // Output: points to leaf cert data in input certsData
    const CT_uint8_t **subCACertData, CT_size_t *subCACertLen,  // Output: points to subCA cert(s) data in input
                                                                //  certsData, if present. Is set to NULL if only
                                                                //  one cert present in input.
    CoreTrustPolicyFlags *flags);                               // Output: policy flags set by this leaf


CT_int CTEvaluateAccessoryCert(
    const CT_uint8_t *leafCertData, CT_size_t leafCertLen,        // Input: binary representation of DER-encoded leaf cert
    const CT_uint8_t *subCACertData, CT_size_t subCACertLen,      // Input: (optional) binary representation of DER-encoded subCA cert(s)
    const CT_uint8_t *anchorCertData, CT_size_t anchorCertLen,    // Input: binary representation of DER-encoded anchor cert
    CoreTrustPolicyFlags policy,                                  // Input: policy to use when evaluating chain
    const CT_uint8_t **leafKeyData, CT_size_t *leafKeyLen,        // Output: points to the leaf key data in the input leafCertData
    const CT_uint8_t **extensionValueData, CT_size_t *extensionValueLen); // Output: points to the extension value in the input leafCertData

/* Which extension value is returned is based on which policy the cert was verified against:
 *  - For MFI AuthV3, this is the value of the extension with OID 1.2.840.113635.100.6.36
 *  - For SW Auth, this is the value of the extension with OID 1.2.840.113635.100.6.59.1 (GeneralCapabilities extension)
 *  - For Component certs, this si the value of the extension with OID 1.2.840.113635.100.11.1 (Component Type)
 *  - For MFi AuthV4, this is the value of the extension with OID 1.2.840.113635.100.6.71.1 (Apple Accessory Properties extension)
 *
 * The following CoreTrustPolicyFlags are accepted:
 *  - CORETRUST_POLICY_BASIC
 *  - CORETRUST_POLICY_MFI_AUTHV2
 *  - CORETRUST_POLICY_MFI_AUTHV3
 *  - CORETRUST_POLICY_MFI_SW_AUTH_DEV
 *  - CORETRUST_POLICY_MFI_SW_AUTH_PROD
 *  - CORETRUST_POLICY_COMPONENT
 *  - CORETRUST_POLICY_MFI_AUTHV4_ACCESSORY
 *  - CORETRUST_POLICY_MFI_AUTHV4_ATTESTATION
 *  - CORETRUST_POLICY_MFI_AUTHV4_PROVISIONING
 */

CT_int CTEvaluateAppleSSL(
    const CT_uint8_t *certsData, CT_size_t certsLen,        // Input: binary representation of up to 3 concatenated
                                                            //        DER-encoded certificates, with leaf first
    const CT_uint8_t *hostnameData, CT_size_t hostnameLen,  // Input: The hostname of the TLS server being connected to
    CT_uint64_t leafMarker,                                 // Input: The last decimal of the marker OID for this project
                                                            //        (e.g. 32 for 1.2.840.113635.100.6.27.32
    CT_bool allowTestRoots);                                // Input: permit use of test hierarchy

CT_int CTEvaluateAppleSSLWithOptionalTemporalCheck(
    const CT_uint8_t *certsData, CT_size_t certsLen,
    const CT_uint8_t *hostnameData, CT_size_t hostnameLen,
    CT_uint64_t leafMarker,
    CT_bool allowTestRoots,
    CT_bool checkTemporalValidity);

int CTEvaluateProvisioningProfile(
    const CT_uint8_t *provisioningProfileData, CT_size_t provisioningProfileLen,
    CT_bool allowTestRoots,
    const CT_uint8_t **contentData, CT_size_t *contentLen);

__END_DECLS

#endif /* _CORETRUST_EVALUATE_H_ */
