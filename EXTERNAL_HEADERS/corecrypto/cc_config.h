/* Copyright (c) (2010-2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CC_CONFIG_H_
#define _CORECRYPTO_CC_CONFIG_H_

/* A word about configuration macros:

    Conditional configuration macros specific to corecrypto should be named CORECRYPTO_xxx
    or CCxx_yyy and be defined to be either 0 or 1 in this file. You can add an
    #ifndef #error construct at the end of this file to make sure it's always defined.

    They should always be tested using the #if directive, never the #ifdef directive.

    No other conditional macros shall ever be used (except in this file)

    Configuration Macros that are defined outside of corecrypto (eg: KERNEL, DEBUG, ...)
    shall only be used in this file to define CCxxx macros.

    External macros should be assumed to be either undefined, defined with no value,
    or defined as true or false. We shall strive to build with -Wundef whenever possible,
    so the following construct should be used to test external macros in this file:

         #if defined(DEBUG) && (DEBUG)
         #define CORECRYPTO_DEBUG 1
         #else
         #define CORECRYPTO_DEBUG 0
         #endif


    It is acceptable to define a conditional CC_xxxx macro in an implementation file,
    to be used only in this file.

    The current code is not guaranteed to follow those rules, but should be fixed to.

    Corecrypto requires GNU and C99 compatibility.
    Typically enabled by passing --gnu --c99 to the compiler (eg. armcc)

*/

#if !defined(__has_feature)
    #define __has_feature(FEATURE) 0
#endif

#if !defined(__has_attribute)
    #define __has_attribute(ATTR) 0
#endif

//Do not set this macros to 1, unless you are developing/testing for Linux under macOS
#define CORECRYPTO_SIMULATE_POSIX_ENVIRONMENT    0

//Do not set these macros to 1, unless you are developing/testing for Windows under macOS
#define CORECRYPTO_SIMULATE_WINDOWS_ENVIRONMENT 0
#define CORECRYPTO_HACK_FOR_WINDOWS_DEVELOPMENT 0

#if (defined(DEBUG) && (DEBUG)) || defined(_DEBUG) //MSVC defines _DEBUG
/* CC_DEBUG is already used in CommonCrypto */
 #define CORECRYPTO_DEBUG 1
#else
 #define CORECRYPTO_DEBUG 0
#endif

// Enable specific configurations only relevant in test builds
#if defined(CORECRYPTO_BUILT_FOR_TESTING) && CORECRYPTO_BUILT_FOR_TESTING
  #define CC_BUILT_FOR_TESTING 1
#else
  #define CC_BUILT_FOR_TESTING 0
#endif

// This macro can be used to enable prints when a condition in the macro "cc_require"
// is false. This is especially useful to confirm that negative testing fails
// at the intended location
#define CORECRYPTO_DEBUG_ENABLE_CC_REQUIRE_PRINTS 0


#if defined(KERNEL) && (KERNEL)
 #define CC_KERNEL 1 // KEXT, XNU repo or kernel components such as AppleKeyStore
#else
 #define CC_KERNEL 0
#endif

#if defined(LINUX_SGX) && (LINUX_SGX)
 #define CC_SGX 1
#else
 #define CC_SGX 0
#endif

#if (defined(__linux__) && !(CC_SGX)) || CORECRYPTO_SIMULATE_POSIX_ENVIRONMENT
 #define CC_LINUX 1
#else
 #define CC_LINUX 0
#endif

#if defined(USE_L4) && (USE_L4)
 #define CC_USE_L4 1
#else
 #define CC_USE_L4 0
#endif

#if defined(RTKIT) && (RTKIT)
 #define CC_RTKIT 1
#else
 #define CC_RTKIT 0
#endif

#if defined(RTKITROM) && (RTKITROM)
#define CC_RTKITROM 1
#else
#define CC_RTKITROM 0
#endif

#if defined(USE_SEPROM) && (USE_SEPROM)
 #define CC_USE_SEPROM 1
#else
 #define CC_USE_SEPROM 0
#endif

#if (defined(ICE_FEATURES_ENABLED)) || (defined(MAVERICK) && (MAVERICK))
 #define CC_BASEBAND 1
#else
 #define CC_BASEBAND 0
#endif

#if defined(EFI) && (EFI)
 #define CC_EFI 1
#else
 #define CC_EFI 0
#endif

#if defined(IBOOT) && (IBOOT)
 #define CC_IBOOT 1
#else
 #define CC_IBOOT 0
#endif

// Include target conditionals if available.
#if defined(__has_include)     /* portability */
#if __has_include(<TargetConditionals.h>)
#include <TargetConditionals.h>
#endif /* __has_include(<TargetConditionals.h>) */
#endif /* defined(__has_include) */

#if defined(TARGET_OS_DRIVERKIT)
 #define CC_DRIVERKIT TARGET_OS_DRIVERKIT
#else
 #define CC_DRIVERKIT 0
#endif

#if defined(TARGET_OS_BRIDGE)
 #define CC_BRIDGE TARGET_OS_BRIDGE
#else
 #define CC_BRIDGE 0
#endif

// Check for open source builds

// Defined by the XNU build scripts
// Applies to code embedded in XNU but NOT to the kext
#if defined(XNU_KERNEL_PRIVATE)
 #define CC_XNU_KERNEL_PRIVATE 1
#else
 #define CC_XNU_KERNEL_PRIVATE 0
#endif

// handle unaligned data, if the cpu cannot. Currently for gladman AES and the C version of the SHA256
#define CC_HANDLE_UNALIGNED_DATA CC_BASEBAND

// BaseBand configuration
#if CC_BASEBAND

// -- ENDIANESS
#if !defined(__LITTLE_ENDIAN__) && !defined(__BIG_ENDIAN__)
 #if defined(ENDIAN_LITTLE) || (defined(__arm__) && !defined(__BIG_ENDIAN))
  #define __LITTLE_ENDIAN__
 #elif !defined(ENDIAN_BIG) && !defined(__BIG_ENDIAN)
  #error Baseband endianess not defined.
 #endif
 #define AESOPT_ENDIAN_NO_FILE
#endif

#if !defined(__x86_64__) && !defined(__arm64__)
// -- Architecture
 #define CCN_UNIT_SIZE  4 // 32 bits
#endif

// -- External function
 #define assert ASSERT   // sanity

// -- Warnings
// Ignore irrelevant warnings after verification
// #186-D: pointless comparison of unsigned integer with zero
// #546-D: transfer of control bypasses initialization of
 #ifdef __arm__
  #pragma diag_suppress 186, 546
 #endif // __arm__
#define CC_SMALL_CODE 1

#endif // CC_BASEBAND

#if CC_RTKIT || CC_RTKITROM
#define CC_SMALL_CODE 1
#endif


#ifndef CC_SMALL_CODE
#define CC_SMALL_CODE 0
#endif

#ifndef CC_DARWIN
 //CC_DARWIN indicates the availability of XNU kernel functions,
 //like what we have on OSX, iOS, tvOS, Watch OS
 #if (CC_USE_L4 || CC_RTKIT || CC_RTKITROM || CC_USE_SEPROM || CC_EFI || CC_LINUX || defined(_WIN32) || CC_BASEBAND || CC_SGX)
  #define CC_DARWIN 0
 #else
  #define CC_DARWIN 1
 #endif
#endif

//arm arch64 definition for gcc
#if defined(__GNUC__) && defined(__aarch64__) && !defined(__arm64__)
    #define __arm64__
#endif

#if !defined(CCN_UNIT_SIZE)
 #if defined(__arm64__) || defined(__x86_64__)  || defined(_WIN64)
  #define CCN_UNIT_SIZE  8
 #elif defined(__arm__) || defined(__i386__) || defined(_WIN32)
  #define CCN_UNIT_SIZE  4
 #else
  #error undefined architecture
 #endif
#endif /* !defined(CCN_UNIT_SIZE) */


//this allows corecrypto Windows development using xcode
#if defined(CORECRYPTO_SIMULATE_WINDOWS_ENVIRONMENT)
 #if CORECRYPTO_SIMULATE_WINDOWS_ENVIRONMENT && CC_DARWIN && CORECRYPTO_DEBUG
  #define CC_USE_ASM 0
  #define CC_USE_HEAP_FOR_WORKSPACE 1
   #if (CCN_UNIT_SIZE == 8)
    #define CC_DUNIT_SUPPORTED 0
   #else
    #define CC_DUNIT_SUPPORTED 1
   #endif
 #endif
#endif

#if !defined(CC_DUNIT_SUPPORTED)
 #if defined(_WIN64) && defined(_WIN32) && (CCN_UNIT_SIZE == 8)
  #define CC_DUNIT_SUPPORTED 0
 #else
  #define CC_DUNIT_SUPPORTED 1
 #endif
#endif

#if defined(_MSC_VER)
    #if defined(__clang__)
        #define CC_ALIGNED(x) __attribute__ ((aligned(x))) //clang compiler
    #else
        #define CC_ALIGNED(x) __declspec(align(x)) //MS complier
    #endif
#else
    #if defined(__clang__) || CCN_UNIT_SIZE==8
        #define CC_ALIGNED(x) __attribute__ ((aligned(x)))
    #else
        #define CC_ALIGNED(x) __attribute__ ((aligned((x)>8?8:(x))))
    #endif
#endif

#if defined(__arm__) && (defined (__ARM_ARCH_7A__) || defined (__ARM_ARCH_7S__) || defined (__ARM_ARCH_7F__) || defined (__ARM_ARCH_7K__) || defined(__ARM_ARCH_7EM__))
    #define CC_ARM_ARCH_7 1
#else
    #define CC_ARM_ARCH_7 0
#endif

// DSP is only available on aarch32
#if CC_ARM_ARCH_7 && defined(__ARM_FEATURE_DSP) && __ARM_FEATURE_DSP
    #define CC_ARM_ARCH_7_DSP 1
#else
    #define CC_ARM_ARCH_7_DSP 0
#endif

#if defined(__arm__)
 //This is copied from <arm/arch.h>, because <arm/arch.h> is not available on SEPROM environment
 #if defined(__ARM_ARCH_6M__) || defined(__TARGET_ARCH_6S_M) || defined (__armv6m__)
  #define _ARM_ARCH_6M
 #endif
#endif

#if !defined(CC_USE_HEAP_FOR_WORKSPACE)
 #if CC_USE_SEPROM || CC_RTKITROM
  #define CC_USE_HEAP_FOR_WORKSPACE 0
 #else
  #define CC_USE_HEAP_FOR_WORKSPACE 1
 #endif
#endif

// Secure memory zeroization functions
#if !defined(__APPLE__) || CC_RTKIT || CC_RTKITROM || CC_USE_SEPROM || defined(__CC_ARM) || defined(__hexagon__) || CC_EFI
 #define CC_HAS_MEMSET_S 0
#else
 #define CC_HAS_MEMSET_S 1
#endif

#if defined(_WIN32) && !defined(__clang__)
 // Clang with Microsoft CodeGen doesn't support SecureZeroMemory.
 #define CC_HAS_SECUREZEROMEMORY 1
#else
 #define CC_HAS_SECUREZEROMEMORY 0
#endif

#if defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 25))
 #define CC_HAS_EXPLICIT_BZERO 1
#else
 #define CC_HAS_EXPLICIT_BZERO 0
#endif

// Disable RSA Keygen on iBridge
#if CC_BRIDGE && CC_KERNEL
#define CC_DISABLE_RSAKEYGEN 1 /* for iBridge */
#else
#define CC_DISABLE_RSAKEYGEN 0 /* default */
#endif

#if (CCN_UNIT_SIZE == 8) && !( defined(_MSC_VER) && defined(__clang__))
#define CCEC25519_CURVE25519_64BIT 1
#else
#define CCEC25519_CURVE25519_64BIT 0
#endif

//- functions implemented in assembly ------------------------------------------
//this the list of corecrypto clients that use assembly and the clang compiler
#if !(CC_DARWIN || CC_KERNEL || CC_USE_L4 || CC_IBOOT || CC_RTKIT || CC_RTKITROM || CC_USE_SEPROM) && !defined(_WIN32) && CORECRYPTO_DEBUG
 #warning "You are using the default corecrypto configuration, assembly optimizations may not be available for your platform"
#endif

// Enable assembler in Linux if CC_LINUX_ASM is defined
#if (CC_LINUX || CC_SGX) && defined(CC_LINUX_ASM) && CC_LINUX_ASM
#define CC_USE_ASM 1
#endif

// Use this macro to strictly disable assembly regardless of cpu/os/compiler/etc.
// Our assembly code is not gcc compatible. Clang defines the __GNUC__ macro as well.
#if !defined(CC_USE_ASM)
 #if defined(_WIN32) || CC_EFI || CC_BASEBAND || CC_XNU_KERNEL_PRIVATE || (defined(__GNUC__) && !defined(__clang__)) || CC_LINUX
  #define CC_USE_ASM 0
 #else
  #define CC_USE_ASM 1
 #endif
#endif

#ifndef CC_LOG
#define CC_LOG (CC_DARWIN && !CC_KERNEL && !CC_IBOOT && !CC_DRIVERKIT)
#endif

#ifndef CC_EXTERN_MALLOC
  #define CC_EXTERN_MALLOC 0
#endif

#define CC_CACHE_DESCRIPTORS CC_KERNEL

//-(1) ARM V7
#if CC_ARM_ARCH_7 && defined(__clang__) && CC_USE_ASM
 #define CCN_MUL_KARATSUBA      0 // no performance improvement
 #define CCN_ADD_ASM            1
 #define CCN_SUB_ASM            1
 #define CCN_MUL_ASM            0
 #define CCN_ADDMUL1_ASM        1
 #define CCN_MUL1_ASM           1
 #define CCN_CMP_ASM            1
 #define CCN_ADD1_ASM           1
 #define CCN_SUB1_ASM           1
 #define CCN_N_ASM              1
 #define CCN_SET_ASM            1
 #define CCN_SHIFT_RIGHT_ASM    1
 #if defined(__ARM_NEON__) 
 #define CCN_SHIFT_LEFT_ASM     1
 #else
 #define CCN_SHIFT_LEFT_ASM     0
 #endif
 #define CCN_MULMOD_224_ASM     CC_ARM_ARCH_7_DSP
 #define CCN_MULMOD_256_ASM     CC_ARM_ARCH_7_DSP
 #define CCAES_ARM_ASM          1
 #define CCAES_INTEL_ASM        0
 #if CC_KERNEL || CC_USE_L4 || CC_IBOOT || CC_RTKIT || CC_RTKITROM || CC_USE_SEPROM || CC_DRIVERKIT
  #define CCAES_MUX             0
 #else
  #define CCAES_MUX             1
 #endif
 #define CCSHA1_VNG_INTEL       0
 #define CCSHA2_VNG_INTEL       0

 #if defined(__ARM_NEON__) || CC_KERNEL
  #define CCSHA1_VNG_ARM        1
  #define CCSHA2_VNG_ARM        1
 #else /* !defined(__ARM_NEON__) */
  #define CCSHA1_VNG_ARM        0
  #define CCSHA2_VNG_ARM        0
 #endif /* !defined(__ARM_NEON__) */

//-(2) ARM 64
#elif defined(__arm64__) && defined(__clang__) && CC_USE_ASM
 #define CCN_MUL_KARATSUBA      0 // 4*n CCN_UNIT extra memory required.
 #define CCN_ADD_ASM            1
 #define CCN_SUB_ASM            1
 #define CCN_MUL_ASM            1
 #define CCN_ADDMUL1_ASM        1
 #define CCN_MUL1_ASM           1
 #define CCN_CMP_ASM            1
 #define CCN_ADD1_ASM           0
 #define CCN_SUB1_ASM           0
 #define CCN_N_ASM              1
 #define CCN_SET_ASM            0
 #define CCN_SHIFT_RIGHT_ASM    1
 #define CCN_SHIFT_LEFT_ASM     1
 #define CCN_MULMOD_224_ASM     1
 #define CCN_MULMOD_256_ASM     1
 #define CCAES_ARM_ASM          1
 #define CCAES_INTEL_ASM        0
 #define CCAES_MUX              0        // On 64bit SoC, asm is much faster than HW
 #define CCSHA1_VNG_INTEL       0
 #define CCSHA2_VNG_INTEL       0
 #define CCSHA1_VNG_ARM         1
 #define CCSHA2_VNG_ARM         1

//-(3) Intel 32/64
#elif (defined(__x86_64__) || defined(__i386__)) && defined(__clang__) && CC_USE_ASM
 #define CCN_MUL_KARATSUBA      0 // 4*n CCN_UNIT extra memory required.
 /* These assembly routines only work for a single CCN_UNIT_SIZE. */
 #if (defined(__x86_64__) && CCN_UNIT_SIZE == 8) || (defined(__i386__) && CCN_UNIT_SIZE == 4)
  #define CCN_ADD_ASM            1
  #define CCN_SUB_ASM            1
  #define CCN_MUL_ASM            1
 #else
  #define CCN_ADD_ASM            0
  #define CCN_SUB_ASM            0
  #define CCN_MUL_ASM            0
 #endif

 #if (defined(__x86_64__) && CCN_UNIT_SIZE == 8)
  #define CCN_CMP_ASM            1
  #define CCN_N_ASM              1
  #define CCN_SHIFT_RIGHT_ASM    1
  #define CCN_SHIFT_LEFT_ASM     1
 #else
  #define CCN_CMP_ASM            0
  #define CCN_N_ASM              0
  #define CCN_SHIFT_RIGHT_ASM    0
  #define CCN_SHIFT_LEFT_ASM     0
 #endif

 #define CCN_MULMOD_224_ASM     0
 #if defined(__x86_64__) && CCN_UNIT_SIZE == 8 && !CC_SGX
  #define CCN_MULMOD_256_ASM    1
  #define CCN_ADDMUL1_ASM       1
  #define CCN_MUL1_ASM          1
 #else
  #define CCN_MULMOD_256_ASM    0
  #define CCN_ADDMUL1_ASM       0
  #define CCN_MUL1_ASM          0
 #endif
 #define CCN_ADD1_ASM           0
 #define CCN_SUB1_ASM           0
 #define CCN_SET_ASM            0
 #define CCAES_ARM_ASM          0
 #define CCAES_INTEL_ASM        1
 #define CCAES_MUX              0
 #define CCSHA1_VNG_INTEL       1
 #define CCSHA2_VNG_INTEL       1
 #define CCSHA1_VNG_ARM         0
 #define CCSHA2_VNG_ARM         0

//-(4) disable assembly
#else
 #define CCN_MUL_KARATSUBA      0 // 4*n CCN_UNIT extra memory required.
 #define CCN_ADD_ASM            0
 #define CCN_SUB_ASM            0
 #define CCN_MUL_ASM            0
 #define CCN_ADDMUL1_ASM        0
 #define CCN_MUL1_ASM           0
 #define CCN_CMP_ASM            0
 #define CCN_ADD1_ASM           0
 #define CCN_SUB1_ASM           0
 #define CCN_N_ASM              0
 #define CCN_SET_ASM            0
 #define CCN_SHIFT_RIGHT_ASM    0
 #define CCN_SHIFT_LEFT_ASM     0
 #define CCN_MULMOD_224_ASM     0
 #define CCN_MULMOD_256_ASM     0
 #define CCAES_ARM_ASM          0
 #define CCAES_INTEL_ASM        0
 #define CCAES_MUX              0
 #define CCSHA1_VNG_INTEL       0
 #define CCSHA2_VNG_INTEL       0
 #define CCSHA1_VNG_ARM         0
 #define CCSHA2_VNG_ARM         0

#endif

#define CC_INLINE static inline
#define CC_NONNULL4 CC_NONNULL((4))

#ifdef __GNUC__
 #define CC_NORETURN __attribute__((__noreturn__))
 #define CC_NOTHROW __attribute__((__nothrow__))
 #define CC_NONNULL(N) __attribute__((__nonnull__ N))
 #define CC_NONNULL_ALL __attribute__((__nonnull__))
 #define CC_SENTINEL __attribute__((__sentinel__))
 // Only apply the `CC_CONST` attribute to functions with no side-effects where the output is a strict function of pass by value input vars with no exterior side-effects.
 // Specifically, do not apply CC_CONST if the function has any arguments that are pointers (directly, or indirectly)
 #define CC_CONST __attribute__((__const__))
 #define CC_PURE __attribute__((__pure__))
 #define CC_NODISCARD __attribute__((warn_unused_result))
 #define CC_WARN_RESULT __attribute__((__warn_unused_result__))
 #define CC_MALLOC_CLEAR __attribute__((__malloc__))
 #define CC_UNUSED __attribute__((unused))
 #define CC_WEAK __attribute__((weak))
#elif defined(__KEIL__)
 #define CC_NORETURN __attribute__((noreturn))
 #define CC_NOTHROW __attribute__((nothrow))
 #define CC_NONNULL(N) __attribute__((nonnull N))
 #define CC_NONNULL_ALL __attribute__((nonnull))
 #define CC_SENTINEL __attribute__((sentinel))
 #define CC_CONST __attribute__((const))
 #define CC_PURE __attribute__((pure))
 #define CC_NODISCARD __attribute__((warn_unused_result))
 #define CC_WARN_RESULT __attribute__((warn_unused_result))
 #define CC_MALLOC_CLEAR __attribute__((malloc))
 #define CC_UNUSED __attribute__((unused))
 #define CC_WEAK __attribute__((weak))
#else /* !__GNUC__ */
/*! @parseOnly */
 #define CC_UNUSED
/*! @parseOnly */
 #define CC_NONNULL(N)
/*! @parseOnly */
 #define CC_NORETURN
/*! @parseOnly */
 #define CC_NOTHROW
/*! @parseOnly */
 #define CC_NONNULL_ALL
/*! @parseOnly */
 #define CC_SENTINEL
/*! @parseOnly */
 #define CC_CONST
/*! @parseOnly */
 #define CC_PURE
/*! @parseOnly */
 #define CC_NODISCARD
/*! @parseOnly */
 #define CC_WARN_RESULT
/*! @parseOnly */
 #define CC_MALLOC_CLEAR
/*! @parseOnly */
 #define CC_WEAK
#endif /* !__GNUC__ */

// Use CC_WEAK_IF_SMALL_CODE to mark symbols as weak when compiling with
// CC_SMALL_CODE=1. This allows replacing faster but bigger code with smaller
// versions at link time.
#if CC_SMALL_CODE
 #define CC_WEAK_IF_SMALL_CODE CC_WEAK
#else
 #define CC_WEAK_IF_SMALL_CODE
#endif

// Bridge differences between MachO and ELF compiler/assemblers. */
#if CC_LINUX || CC_SGX
#define CC_ASM_SECTION_CONST .rodata
#define CC_ASM_PRIVATE_EXTERN .hidden
#if CC_LINUX
// We need to be sure that assembler can access relocated C
// symbols. Sad but this is the quickest way to do that, at least with
// our current linux compiler (clang-3.4).
#define CC_C_LABEL(_sym) _sym@PLT
#else /* CC_SGX */
#define CC_C_LABEL(_sym) _sym
#endif
#define _IMM(x) $(x)
#else /* !CC_LINUX && !CC_SGX */
#define CC_ASM_SECTION_CONST .const
#define CC_ASM_PRIVATE_EXTERN .private_extern
#define CC_C_LABEL(_sym) _##_sym
#define _IMM(x) $$(x)
#endif /* !CC_LINUX && !CC_SGX */

// Enable FIPSPOST function tracing only when supported. */
#ifdef CORECRYPTO_POST_TRACE
#define CC_FIPSPOST_TRACE 1
#else
#define CC_FIPSPOST_TRACE 0
#endif

#ifndef CC_INTERNAL_SDK
#if __has_include(<System/i386/cpu_capabilities.h>)
#define CC_INTERNAL_SDK 1
#elif __has_include(<System/arm/cpu_capabilities.h>)
#define CC_INTERNAL_SDK 1
#else
#define CC_INTERNAL_SDK 0
#endif
#endif

// Currently thread sanitizer is only supported in local builds.
// Please edit your "corecrypto_test" scheme to build with thread
// sanitizer and then remove *all* variants of corecrypto_static
// besides "normal"

#if __has_feature(thread_sanitizer)
    #define CC_TSAN 1
#else
    #define CC_TSAN 0
#endif // __has_feature(thread_sanitizer)

#if __has_feature(bounds_attributes)
    #define CC_PTRCHECK                  1
    #define CC_PTRCHECK_CAPABLE_HEADER()   _Pragma("clang abi_ptr_attr set(single)")
    #define cc_counted_by(x)              __attribute__((counted_by(x)))
    #define cc_sized_by(x)                __attribute__((sized_by(x)))
    #define cc_bidi_indexable             __attribute__((bidi_indexable))
    #define cc_indexable                  __attribute__((indexable))
    #define cc_single                     __attribute__((single))
    #define cc_unsafe_indexable           __attribute__((unsafe_indexable))
    #define cc_unsafe_forge_bidi_indexable(P, S)     __builtin_unsafe_forge_bidi_indexable(P, S)
    #define cc_unsafe_forge_single(P)     __builtin_unsafe_forge_single(P)
    #define cc_cstring                    cc_unsafe_indexable
    #define CC_WIDE_NULL                  ((void *cc_bidi_indexable)NULL)
    #define cc_ended_by(x)                __attribute__((ended_by(x)))
#else
    #define CC_PTRCHECK                  0
    #define CC_PTRCHECK_CAPABLE_HEADER()
    #define cc_counted_by(x)
    #define cc_sized_by(x)
    #define cc_bidi_indexable
    #define cc_indexable
    #define cc_single
    #define cc_unsafe_indexable
    #define cc_unsafe_forge_bidi_indexable(P, S) (P)
    #define cc_unsafe_forge_single(P) (P)
    #define cc_cstring
    #define CC_WIDE_NULL NULL
    #define cc_ended_by(x)
#endif // __has_feature(bounds_attributes)

// Define endianess for GCC, if needed and applicable.
#if defined(__GNUC__) && !defined(__LITTLE_ENDIAN__)
    #if (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
        #define __LITTLE_ENDIAN__ 1
    #endif
#endif

#if defined(ENABLE_CRYPTOKIT_PRIVATE_DEFINITIONS) && ENABLE_CRYPTOKIT_PRIVATE_DEFINITIONS
#define CC_PRIVATE_CRYPTOKIT 1
#else
#define CC_PRIVATE_CRYPTOKIT 0
#endif

#if defined(__clang__)
 #define CC_WORKSPACE_OVERRIDE_PRAGMA(x) _Pragma(#x)
 #define CC_WORKSPACE_OVERRIDE(f, o) CC_WORKSPACE_OVERRIDE_PRAGMA(workspace-override f o)
#else
 #define CC_WORKSPACE_OVERRIDE(f, o)
#endif

#if defined(__ARM_ARCH_8_4__) && !CC_KERNEL && !CC_USE_L4 && !CC_USE_SEPROM
 #define CC_DIT_SUPPORTED 1
#else
 #define CC_DIT_SUPPORTED 0
#endif

#endif /* _CORECRYPTO_CC_CONFIG_H_ */
