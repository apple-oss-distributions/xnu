/* Copyright (c) (2012,2014,2015,2016,2017,2018,2019,2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef CORECRYPTO_CC_RUNTIME_CONFIG_H_
#define CORECRYPTO_CC_RUNTIME_CONFIG_H_

#include <corecrypto/cc_config.h>

#if defined(__x86_64__) || defined(__i386__)

#if CC_KERNEL
    #include <i386/cpuid.h>
    #define CC_HAS_RDRAND() ((cpuid_features() & CPUID_FEATURE_RDRAND) != 0)
    #define CC_HAS_AESNI() ((cpuid_features() & CPUID_FEATURE_AES) != 0)
    #define CC_HAS_SupplementalSSE3() ((cpuid_features() & CPUID_FEATURE_SSSE3) != 0)
    #define CC_HAS_AVX1() ((cpuid_features() & CPUID_FEATURE_AVX1_0) != 0)
    #define CC_HAS_AVX2() ((cpuid_info()->cpuid_leaf7_features & CPUID_LEAF7_FEATURE_AVX2) != 0)
    #define CC_HAS_AVX512_AND_IN_KERNEL()    ((cpuid_info()->cpuid_leaf7_features & CPUID_LEAF7_FEATURE_AVX512F) !=0)
    #define CC_HAS_BMI2() ((cpuid_info()->cpuid_leaf7_features & CPUID_LEAF7_FEATURE_BMI2) != 0)
    #define CC_HAS_ADX() ((cpuid_info()->cpuid_leaf7_features & CPUID_LEAF7_FEATURE_ADX) != 0)

#elif CC_DARWIN && CC_INTERNAL_SDK
    #include <System/i386/cpu_capabilities.h>
    #define CC_HAS_RDRAND() (_get_cpu_capabilities() & kHasRDRAND)
    #define CC_HAS_AESNI() (_get_cpu_capabilities() & kHasAES)
    #define CC_HAS_SupplementalSSE3() (_get_cpu_capabilities() & kHasSupplementalSSE3)
    #define CC_HAS_AVX1() (_get_cpu_capabilities() & kHasAVX1_0)
    #define CC_HAS_AVX2() (_get_cpu_capabilities() & kHasAVX2_0)
    #define CC_HAS_AVX512_AND_IN_KERNEL() 0
    #define CC_HAS_BMI2() (_get_cpu_capabilities() & kHasBMI2)
    #define CC_HAS_ADX() (_get_cpu_capabilities() & kHasADX)

#elif CC_SGX
    #include <cpuid.h>
    #include <stdbool.h>
    #include <stdint.h>

    #define CPUID_REG_RAX 0
    #define CPUID_REG_RBX 1
    #define CPUID_REG_RCX 2
    #define CPUID_REG_RDX 3

    #define CPUID_FEATURE_AES 25
    #define CPUID_FEATURE_SSE3 0
    #define CPUID_FEATURE_AVX1 28
    #define CPUID_FEATURE_LEAF7_AVX2 5
    #define CPUID_FEATURE_LEAF7_BMI2 8
    #define CPUID_FEATURE_RDRAND 30
    #define CPUID_FEATURE_LEAF7_ADX 19

    CC_INLINE bool _cpu_supports(uint64_t leaf, uint64_t subleaf, uint8_t cpuid_register, uint8_t bit) {
        uint64_t registers[4] = {0};
        registers[CPUID_REG_RAX] = leaf;
        registers[CPUID_REG_RCX] = subleaf;
        if (oe_emulate_cpuid(&registers[CPUID_REG_RAX], &registers[CPUID_REG_RBX], &registers[CPUID_REG_RCX], &registers[CPUID_REG_RDX])) {
            return false;
        }
        return (registers[cpuid_register] >> bit) & 1;
    }


    #define CC_HAS_AESNI() _cpu_supports(1, 0, CPUID_REG_RCX, CPUID_FEATURE_AES)
    #define CC_HAS_SupplementalSSE3() _cpu_supports(1, 0, CPUID_REG_RCX, CPUID_FEATURE_SSE3)
    #define CC_HAS_AVX1() _cpu_supports(1, 0, CPUID_REG_RCX, CPUID_FEATURE_AVX1)
    #define CC_HAS_AVX2() _cpu_supports(7, 0, CPUID_REG_RBX, CPUID_FEATURE_LEAF7_AVX2)
    #define CC_HAS_AVX512_AND_IN_KERNEL() 0
    #define CC_HAS_BMI2() _cpu_supports(7, 0, CPUID_REG_RBX, CPUID_FEATURE_LEAF7_BMI2)
    #define CC_HAS_RDRAND() _cpu_supports(1, 0, CPUID_REG_RCX, CPUID_FEATURE_RDRAND)
    #define CC_HAS_ADX() _cpu_supports(7, 0, CPUID_REG_RBX, CPUID_FEATURE_LEAF7_ADX)
#else
    #define CC_HAS_AESNI() __builtin_cpu_supports("aes")
    #define CC_HAS_SupplementalSSE3() __builtin_cpu_supports("ssse3")
    #define CC_HAS_AVX1() __builtin_cpu_supports("avx")
    #define CC_HAS_AVX2() __builtin_cpu_supports("avx2")
    #define CC_HAS_AVX512_AND_IN_KERNEL() 0
    #define CC_HAS_BMI2() __builtin_cpu_supports("bmi2")
#if CC_LINUX || !CC_INTERNAL_SDK
    #include <cpuid.h>
    #include <stdbool.h>

    CC_INLINE bool _cpu_supports_rdrand()
    {
        unsigned int eax, ebx, ecx, edx;
        __cpuid(1, eax, ebx, ecx, edx);
        return ecx & bit_RDRND;
    }

    CC_INLINE bool _cpu_supports_adx()
    {
        unsigned int eax, ebx, ecx, edx;
        __cpuid_count(7, 0, eax, ebx, ecx, edx);
        return ebx & bit_ADX;
    }

    #define CC_HAS_RDRAND() _cpu_supports_rdrand()
    #define CC_HAS_ADX() _cpu_supports_adx()
#else
    #define CC_HAS_RDRAND() 0
    #define CC_HAS_ADX() 0
#endif

#endif

#endif  // defined(__x86_64__) || defined(__i386__)

#if defined(__arm64__)

#if CC_DARWIN && CC_INTERNAL_SDK
    #include <System/arm/cpu_capabilities.h>
    #define CC_HAS_SHA512() (_get_cpu_capabilities() & kHasARMv82SHA512)
    #define CC_HAS_SHA3() (_get_cpu_capabilities() & kHasARMv82SHA3)
#else
    #define CC_HAS_SHA512() (0)
    #define CC_HAS_SHA3() (0)
#endif

#endif // defined(__arm64__)

#endif /* CORECRYPTO_CC_RUNTIME_CONFIG_H_ */
