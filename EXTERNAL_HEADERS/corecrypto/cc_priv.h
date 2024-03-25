/* Copyright (c) (2010-2012,2014-2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CC_PRIV_H_
#define _CORECRYPTO_CC_PRIV_H_

#include <corecrypto/cc.h>

CC_PTRCHECK_CAPABLE_HEADER()

#if !CC_EXCLAVEKIT
// Fork handlers for the stateful components of corecrypto.
void cc_atfork_prepare(void);
void cc_atfork_parent(void);
void cc_atfork_child(void);
#endif

#ifndef __has_builtin
#define __has_builtin(x) 0
#endif

#ifndef __DECONST
#define __DECONST(type, var) ((type)(uintptr_t)(const void *)(var))
#endif

/* defines the following macros :

 CC_ARRAY_LEN: returns the number of elements in an array

 CC_ROR  : Rotate Right 32 bits. Rotate count can be a variable.
 CC_ROL  : Rotate Left 32 bits. Rotate count can be a variable.
 CC_RORc : Rotate Right 32 bits. Rotate count must be a constant.
 CC_ROLc : Rotate Left 32 bits. Rotate count must be a constant.

 CC_ROR64  : Rotate Right 64 bits. Rotate count can be a variable.
 CC_ROL64  : Rotate Left 64 bits. Rotate count can be a variable.
 CC_ROR64c : Rotate Right 64 bits. Rotate count must be a constant.
 CC_ROL64c : Rotate Left 64 bits. Rotate count must be a constant.

 CC_BSWAP  : byte swap a 32 bits variable.

 CC_H2BE32 : convert a 32 bits value between host and big endian order.
 CC_H2LE32 : convert a 32 bits value between host and little endian order.

 CC_BSWAP64  : byte swap a 64 bits variable

 CC_H2BE64 : convert a 64 bits value between host and big endian order
 CC_H2LE64 : convert a 64 bits value between host and little endian order

*/

// RTKitOSPlatform should replace CC_MEMCPY with memcpy
#define CC_MEMCPY(D,S,L) cc_memcpy((D),(S),(L))
#define CC_MEMMOVE(D,S,L) cc_memmove((D),(S),(L))
#define CC_MEMSET(D,V,L) cc_memset((D),(V),(L))

#if CC_EFI
    void *cc_memcpy(void *dst, const void *src, size_t len);
    #define cc_memcpy_nochk(dst, src, len) cc_memcpy((dst), (src), (len))
#elif __has_builtin(__builtin___memcpy_chk) && !defined(_MSC_VER) && !CC_SGX && !CC_ARM_ARCH_6M
    #define cc_memcpy(dst, src, len) __builtin___memcpy_chk((dst), (src), (len), __builtin_object_size((dst), 1))
    #define cc_memcpy_nochk(dst, src, len) __builtin___memcpy_chk((dst), (src), (len), __builtin_object_size((dst), 0))
#else
    #define cc_memcpy(dst, src, len) memcpy((dst), (src), (len))
    #define cc_memcpy_nochk(dst, src, len) memcpy((dst), (src), (len))
#endif

#if CC_EFI
    void *cc_memmove(void *dst, const void *src, size_t len);
#elif __has_builtin(__builtin___memmove_chk) && !defined(_MSC_VER) && !CC_SGX && !CC_ARM_ARCH_6M
    #define cc_memmove(dst, src, len) __builtin___memmove_chk((dst), (src), (len), __builtin_object_size((dst), 1))
#else
    #define cc_memmove(dst, src, len) memmove((dst), (src), (len))
#endif

#if CC_EFI
    void *cc_memset(void *dst, int val, size_t num);
#elif __has_builtin(__builtin___memset_chk) && !defined(_MSC_VER) && !CC_SGX && !CC_ARM_ARCH_6M
    #define cc_memset(dst, val, len) __builtin___memset_chk((dst), (val), (len), __builtin_object_size((dst), 1))
#else
    #define cc_memset(dst, val, len) memset((dst), (val), (len))
#endif

#define CC_ARRAY_LEN(x) (sizeof((x))/sizeof((x)[0]))

// MARK: - Loads and Store

// 64 bit load & store big endian
#if defined(__x86_64__) && !defined(_MSC_VER)
CC_INLINE void cc_store64_be(uint64_t x, uint8_t cc_sized_by(8) * y)
{
    __asm__("bswapq %1     \n\t"
            "movq   %1, %0 \n\t"
            "bswapq %1     \n\t"
            : "=m"(*(y))
            : "r"(x));
}
CC_INLINE uint64_t cc_load64_be(const uint8_t cc_sized_by(8) * y)
{
    uint64_t x;
    __asm__("movq %1, %0 \n\t"
            "bswapq %0   \n\t"
            : "=r"(x)
            : "m"(*(y)));
    return x;
}
#else
CC_INLINE void cc_store64_be(uint64_t x, uint8_t cc_sized_by(8) * y)
{
    y[0] = (uint8_t)(x >> 56);
    y[1] = (uint8_t)(x >> 48);
    y[2] = (uint8_t)(x >> 40);
    y[3] = (uint8_t)(x >> 32);
    y[4] = (uint8_t)(x >> 24);
    y[5] = (uint8_t)(x >> 16);
    y[6] = (uint8_t)(x >> 8);
    y[7] = (uint8_t)(x);
}
CC_INLINE uint64_t cc_load64_be(const uint8_t cc_sized_by(8) * y)
{
    return (((uint64_t)(y[0])) << 56) | (((uint64_t)(y[1])) << 48) | (((uint64_t)(y[2])) << 40) | (((uint64_t)(y[3])) << 32) |
           (((uint64_t)(y[4])) << 24) | (((uint64_t)(y[5])) << 16) | (((uint64_t)(y[6])) << 8) | ((uint64_t)(y[7]));
}
#endif

// 32 bit load & store big endian
#if (defined(__i386__) || defined(__x86_64__)) && !defined(_MSC_VER)
CC_INLINE void cc_store32_be(uint32_t x, uint8_t cc_sized_by(4) * y)
{
    __asm__("bswapl %1     \n\t"
            "movl   %1, %0 \n\t"
            "bswapl %1     \n\t"
            : "=m"(*(y))
            : "r"(x));
}
CC_INLINE uint32_t cc_load32_be(const uint8_t cc_sized_by(4) * y)
{
    uint32_t x;
    __asm__("movl %1, %0 \n\t"
            "bswapl %0   \n\t"
            : "=r"(x)
            : "m"(*(y)));
    return x;
}
#else
CC_INLINE void cc_store32_be(uint32_t x, uint8_t cc_sized_by(4) * y)
{
    y[0] = (uint8_t)(x >> 24);
    y[1] = (uint8_t)(x >> 16);
    y[2] = (uint8_t)(x >> 8);
    y[3] = (uint8_t)(x);
}
CC_INLINE uint32_t cc_load32_be(const uint8_t cc_sized_by(4) * y)
{
    return (((uint32_t)(y[0])) << 24) | (((uint32_t)(y[1])) << 16) | (((uint32_t)(y[2])) << 8) | ((uint32_t)(y[3]));
}
#endif

CC_INLINE void cc_store16_be(uint16_t x, uint8_t cc_sized_by(2) * y)
{
    y[0] = (uint8_t)(x >> 8);
    y[1] = (uint8_t)(x);
}
CC_INLINE uint16_t cc_load16_be(const uint8_t cc_sized_by(2) * y)
{
    return (uint16_t) (((uint16_t)(y[0])) << 8) | ((uint16_t)(y[1]));
}

// 64 bit load & store little endian
CC_INLINE void cc_store64_le(uint64_t x, uint8_t cc_sized_by(8) * y)
{
    y[7] = (uint8_t)(x >> 56);
    y[6] = (uint8_t)(x >> 48);
    y[5] = (uint8_t)(x >> 40);
    y[4] = (uint8_t)(x >> 32);
    y[3] = (uint8_t)(x >> 24);
    y[2] = (uint8_t)(x >> 16);
    y[1] = (uint8_t)(x >> 8);
    y[0] = (uint8_t)(x);
}
CC_INLINE uint64_t cc_load64_le(const uint8_t cc_sized_by(8) * y)
{
    return (((uint64_t)(y[7])) << 56) | (((uint64_t)(y[6])) << 48) | (((uint64_t)(y[5])) << 40) | (((uint64_t)(y[4])) << 32) |
           (((uint64_t)(y[3])) << 24) | (((uint64_t)(y[2])) << 16) | (((uint64_t)(y[1])) << 8) | ((uint64_t)(y[0]));
}

// 32 bit load & store little endian
CC_INLINE void cc_store32_le(uint32_t x, uint8_t cc_sized_by(4) * y)
{
    y[3] = (uint8_t)(x >> 24);
    y[2] = (uint8_t)(x >> 16);
    y[1] = (uint8_t)(x >> 8);
    y[0] = (uint8_t)(x);
}
CC_INLINE uint32_t cc_load32_le(const uint8_t cc_sized_by(4) * y)
{
    return (((uint32_t)(y[3])) << 24) | (((uint32_t)(y[2])) << 16) | (((uint32_t)(y[1])) << 8) | ((uint32_t)(y[0]));
}

#if (CCN_UNIT_SIZE == 8)
 #define cc_load_le cc_load64_le
 #define cc_store_le cc_store64_le
#else
 #define cc_load_le cc_load32_le
 #define cc_store_le cc_store32_le
#endif

// MARK: - Byte Swaps

#if __has_builtin(__builtin_bswap32)
#define CC_BSWAP32(x) __builtin_bswap32(x)
#else
CC_INLINE uint32_t CC_BSWAP32(uint32_t x)
{
    return
        ((x & 0xff000000) >> 24) |
        ((x & 0x00ff0000) >>  8) |
        ((x & 0x0000ff00) <<  8) |
        ((x & 0x000000ff) << 24);
}
#endif

#if __has_builtin(__builtin_bswap64)
#define CC_BSWAP64(x) __builtin_bswap64(x)
#else
CC_INLINE uint64_t CC_BSWAP64(uint64_t x)
{
    return
        ((x & 0xff00000000000000ULL) >> 56) |
        ((x & 0x00ff000000000000ULL) >> 40) |
        ((x & 0x0000ff0000000000ULL) >> 24) |
        ((x & 0x000000ff00000000ULL) >>  8) |
        ((x & 0x00000000ff000000ULL) <<  8) |
        ((x & 0x0000000000ff0000ULL) << 24) |
        ((x & 0x000000000000ff00ULL) << 40) |
        ((x & 0x00000000000000ffULL) << 56);
}
#endif

#ifdef __LITTLE_ENDIAN__
#define CC_H2BE32(x) CC_BSWAP32(x)
#define CC_H2LE32(x) (x)
#define CC_H2BE64(x) CC_BSWAP64(x)
#define CC_H2LE64(x) (x)
#else
#define CC_H2BE32(x) (x)
#define CC_H2LE32(x) CC_BSWAP32(x)
#define CC_H2BE64(x) (x)
#define CC_H2LE64(x) CC_BSWAP64(x)
#endif

#define cc_ceiling(a,b)  (((a)+((b)-1))/(b))
#define CC_BITLEN_TO_BYTELEN(x) cc_ceiling((x), 8)

#define CC_PROVIDES_ABORT (!(CC_BASEBAND || CC_EFI || CC_RTKITROM || CC_USE_SEPROM))

/*!
 @function cc_abort
 @abstract Abort execution unconditionally
 */
CC_NORETURN
void cc_abort(const char *msg);

/*!
  @function cc_try_abort
  @abstract Abort execution iff the platform provides a function like @p abort() or @p panic()

  @discussion If the platform does not provide a means to abort execution, this function does nothing; therefore, callers should return an error code after calling this function.
*/
void cc_try_abort(const char *msg);

#if __has_builtin(__builtin_expect)
 #define CC_LIKELY(cond) __builtin_expect(!!(cond), 1)
 #define CC_UNLIKELY(cond) __builtin_expect(!!(cond), 0)
#else
 #define CC_LIKELY(cond) cond
 #define CC_UNLIKELY(cond) cond
#endif

#define cc_abort_if(cond, msg)                  \
    do {                                        \
        if (CC_UNLIKELY(cond)) {                \
            cc_abort(msg);                      \
        }                                       \
    } while (0)

void cc_try_abort_if(bool condition, const char *msg);

/*
  Unfortunately, since we export this symbol, this declaration needs
  to be in a public header to satisfy TAPI.

  See fipspost_trace_priv.h for more details.
*/
extern const void *fipspost_trace_vtable;


// MARK: -- Deprecated macros
/*
 Use `cc_store32_be`, `cc_store32_le`, `cc_store64_be`, `cc_store64_le`, and
 `cc_load32_be`, `cc_load32_le`, `cc_load64_be`, `cc_load64_le` instead.
 
 CC_STORE32_BE : store 32 bit value in big endian in unaligned buffer.
 CC_STORE32_LE : store 32 bit value in little endian in unaligned buffer.
 CC_STORE64_BE : store 64 bit value in big endian in unaligned buffer.
 CC_STORE64_LE : store 64 bit value in little endian in unaligned buffer.
 CC_LOAD32_BE : load 32 bit value in big endian from unaligned buffer.
 CC_LOAD32_LE : load 32 bit value in little endian from unaligned buffer.
 CC_LOAD64_BE : load 64 bit value in big endian from unaligned buffer.
 CC_LOAD64_LE : load 64 bit value in little endian from unaligned buffer.
 CC_READ_LE32 : read a 32 bits little endian value
 CC_WRITE_LE32 : write a 32 bits little endian value
 CC_WRITE_LE64 : write a 64 bits little endian value
*/

#define CC_STORE32_BE(x, y) cc_store32_be((uint32_t)(x), (uint8_t *)(y))
#define CC_STORE32_LE(x, y) cc_store32_le((uint32_t)(x), (uint8_t *)(y))
#define CC_STORE64_BE(x, y) cc_store64_be((uint64_t)(x), (uint8_t *)(y))
#define CC_STORE64_LE(x, y) cc_store64_le((uint64_t)(x), (uint8_t *)(y))

#define CC_LOAD32_BE(x, y) ((x) = cc_load32_be((uint8_t *)(y)))
#define CC_LOAD32_LE(x, y) ((x) = cc_load32_le((uint8_t *)(y)))
#define CC_LOAD64_BE(x, y) ((x) = cc_load64_be((uint8_t *)(y)))
#define CC_LOAD64_LE(x, y) ((x) = cc_load64_le((uint8_t *)(y)))

#define CC_READ_LE32(ptr) cc_load32_le((uint8_t *)(ptr))

#define CC_WRITE_LE32(ptr, x) cc_store32_le((uint32_t)(x), (uint8_t *)(ptr))
#define CC_WRITE_LE64(ptr, x) cc_store64_le((uint64_t)(x), (uint8_t *)(ptr))

#endif /* _CORECRYPTO_CC_PRIV_H_ */
