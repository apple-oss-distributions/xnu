/* Copyright (c) (2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CC_IMPL_H_
#define _CORECRYPTO_CC_IMPL_H_

#define CC_IMPL_LIST                                        \
    CC_IMPL_ITEM(UNKNOWN, 0)                                \
                                                            \
    CC_IMPL_ITEM(SHA256_LTC, 1)                             \
    CC_IMPL_ITEM(SHA256_VNG_ARM, 2)                         \
    CC_IMPL_ITEM(SHA256_VNG_ARM64_NEON, 3)                  \
    CC_IMPL_ITEM(SHA256_VNG_INTEL_SUPPLEMENTAL_SSE3, 4)     \
    CC_IMPL_ITEM(SHA256_VNG_INTEL_AVX1, 5)                  \
    CC_IMPL_ITEM(SHA256_VNG_INTEL_AVX2, 6)                  \
                                                            \
    CC_IMPL_ITEM(AES_ECB_LTC, 11)                           \
    CC_IMPL_ITEM(AES_ECB_ARM, 12)                           \
    CC_IMPL_ITEM(AES_ECB_INTEL_OPT, 13)                     \
    CC_IMPL_ITEM(AES_ECB_INTEL_AESNI, 14)                   \
    CC_IMPL_ITEM(AES_ECB_SKG, 15)                           \
    CC_IMPL_ITEM(AES_ECB_TRNG, 16)                          \
                                                            \
    CC_IMPL_ITEM(AES_XTS_GENERIC, 21)                       \
    CC_IMPL_ITEM(AES_XTS_ARM, 22)                           \
    CC_IMPL_ITEM(AES_XTS_INTEL_OPT, 23)                     \
    CC_IMPL_ITEM(AES_XTS_INTEL_AESNI, 24)                   \
                                                            \
    CC_IMPL_ITEM(SHA1_LTC, 31)                              \
    CC_IMPL_ITEM(SHA1_VNG_ARM, 32)                          \
    CC_IMPL_ITEM(SHA1_VNG_INTEL_SUPPLEMENTAL_SSE3, 33)      \
    CC_IMPL_ITEM(SHA1_VNG_INTEL_AVX1, 34)                   \
    CC_IMPL_ITEM(SHA1_VNG_INTEL_AVX2, 35)                   \
                                                            \
    CC_IMPL_ITEM(SHA384_LTC, 41)                            \
    CC_IMPL_ITEM(SHA384_VNG_ARM, 42)                        \
    CC_IMPL_ITEM(SHA384_VNG_INTEL_SUPPLEMENTAL_SSE3, 43)    \
    CC_IMPL_ITEM(SHA384_VNG_INTEL_AVX1, 44)                 \
    CC_IMPL_ITEM(SHA384_VNG_INTEL_AVX2, 45)                 \
                                                            \
    CC_IMPL_ITEM(SHA512_LTC, 51)                            \
    CC_IMPL_ITEM(SHA512_VNG_ARM, 52)                        \
    CC_IMPL_ITEM(SHA512_VNG_INTEL_SUPPLEMENTAL_SSE3, 53)    \
    CC_IMPL_ITEM(SHA512_VNG_INTEL_AVX1, 54)                 \
    CC_IMPL_ITEM(SHA512_VNG_INTEL_AVX2, 55)


#define CC_IMPL_ITEM(k, v)                      \
    CC_IMPL_##k = v,

typedef enum cc_impl {
    CC_IMPL_LIST
} cc_impl_t;

#undef CC_IMPL_ITEM

const char *cc_impl_name(cc_impl_t impl);

#endif /* _CORECRYPTO_CC_IMPL_H_ */
