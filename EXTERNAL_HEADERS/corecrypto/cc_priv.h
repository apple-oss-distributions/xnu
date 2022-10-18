/* Copyright (c) (2010-2012,2014-2021) Apple Inc. All rights reserved.
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
#include <stdbool.h>
#include <stdint.h>

CC_PTRCHECK_CAPABLE_HEADER()

// Fork handlers for the stateful components of corecrypto.
void cc_atfork_prepare(void);
void cc_atfork_parent(void);
void cc_atfork_child(void);

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

#if __has_builtin(__builtin___memcpy_chk) && !defined(_MSC_VER) && !CC_SGX && !CC_EFI
#define cc_memcpy(dst, src, len) __builtin___memcpy_chk((dst), (src), (len), __builtin_object_size((dst), 1))
#define cc_memcpy_nochk(dst, src, len) __builtin___memcpy_chk((dst), (src), (len), __builtin_object_size((dst), 0))
#else
#define cc_memcpy(dst, src, len) memcpy((dst), (src), (len))
#define cc_memcpy_nochk(dst, src, len) memcpy((dst), (src), (len))
#endif

#if __has_builtin(__builtin___memmove_chk) && !defined(_MSC_VER) && !CC_SGX && !CC_EFI
#define cc_memmove(dst, src, len) __builtin___memmove_chk((dst), (src), (len), __builtin_object_size((dst), 1))
#else
#define cc_memmove(dst, src, len) memmove((dst), (src), (len))
#endif

#if __has_builtin(__builtin___memset_chk) && !defined(_MSC_VER) && !CC_SGX && !CC_EFI
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

// MARK: - 32-bit Rotates

#if defined(_MSC_VER)
// MARK: -- MSVC version

#include <stdlib.h>
#if !defined(__clang__)
 #pragma intrinsic(_lrotr,_lrotl)
#endif
#define	CC_ROR(x,n) _lrotr(x,n)
#define	CC_ROL(x,n) _lrotl(x,n)
#define	CC_RORc(x,n) _lrotr(x,n)
#define	CC_ROLc(x,n) _lrotl(x,n)

#elif (defined(__i386__) || defined(__x86_64__))
// MARK: -- intel asm version

CC_INLINE uint32_t CC_ROL(uint32_t word, int i)
{
    __asm__ ("roll %%cl,%0"
         :"=r" (word)
         :"0" (word),"c" (i));
    return word;
}

CC_INLINE uint32_t CC_ROR(uint32_t word, int i)
{
    __asm__ ("rorl %%cl,%0"
         :"=r" (word)
         :"0" (word),"c" (i));
    return word;
}

/* Need to be a macro here, because 'i' is an immediate (constant) */
#define CC_ROLc(word, i)                \
({  uint32_t _word=(word);              \
    __asm__ __volatile__ ("roll %2,%0"  \
        :"=r" (_word)                   \
        :"0" (_word),"I" (i));          \
    _word;                              \
})


#define CC_RORc(word, i)                \
({  uint32_t _word=(word);              \
    __asm__ __volatile__ ("rorl %2,%0"  \
        :"=r" (_word)                   \
        :"0" (_word),"I" (i));          \
    _word;                              \
})

#else

// MARK: -- default version

CC_INLINE uint32_t CC_ROL(uint32_t word, int i)
{
    return ( (word<<(i&31)) | (word >> ( (32-(i&31)) & 31 )) );
}

CC_INLINE uint32_t CC_ROR(uint32_t word, int i)
{
    return ( (word>>(i&31)) | (word << ( (32-(i&31)) & 31 )) );
}

#define	CC_ROLc(x, y) CC_ROL(x, y)
#define	CC_RORc(x, y) CC_ROR(x, y)

#endif

// MARK: - 64 bits rotates

#if defined(__x86_64__) && !defined(_MSC_VER) //clang _MSVC doesn't support GNU-style inline assembly
// MARK: -- intel 64 asm version

CC_INLINE uint64_t CC_ROL64(uint64_t word, int i)
{
    __asm__("rolq %%cl,%0"
        :"=r" (word)
        :"0" (word),"c" (i));
    return word;
}

CC_INLINE uint64_t CC_ROR64(uint64_t word, int i)
{
    __asm__("rorq %%cl,%0"
        :"=r" (word)
        :"0" (word),"c" (i));
    return word;
}

/* Need to be a macro here, because 'i' is an immediate (constant) */
#define CC_ROL64c(word, i)      \
({                              \
    uint64_t _word=(word);      \
    __asm__("rolq %2,%0"        \
        :"=r" (_word)           \
        :"0" (_word),"J" (i));  \
    _word;                      \
})

#define CC_ROR64c(word, i)      \
({                              \
    uint64_t _word=(word);      \
    __asm__("rorq %2,%0"        \
        :"=r" (_word)           \
        :"0" (_word),"J" (i));  \
    _word;                      \
})


#else /* Not x86_64  */

// MARK: -- default C version

CC_INLINE uint64_t CC_ROL64(uint64_t word, int i)
{
    return ( (word<<(i&63)) | (word >> ((64-(i&63)) & 63) ) );
}

CC_INLINE uint64_t CC_ROR64(uint64_t word, int i)
{
    return ( (word>>(i&63)) | (word << ((64-(i&63)) & 63) ) );
}

#define	CC_ROL64c(x, y) CC_ROL64(x, y)
#define	CC_ROR64c(x, y) CC_ROR64(x, y)

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

/* extract a byte portably */
#ifdef _MSC_VER
#define cc_byte(x, n) ((unsigned char)((x) >> (8 * (n))))
#else
#define cc_byte(x, n) (((x) >> (8 * (n))) & 255)
#endif

/* Count leading zeros (for nonzero inputs) */

/*
 *  On i386 and x86_64, we know clang and GCC will generate BSR for
 *  __builtin_clzl.  This instruction IS NOT constant time on all micro-
 *  architectures, but it *is* constant time on all micro-architectures that
 *  have been used by Apple, and we expect that to continue to be the case.
 *
 *  When building for x86_64h with clang, this produces LZCNT, which is exactly
 *  what we want.
 *
 *  On arm and arm64, we know that clang and GCC generate the constant-time CLZ
 *  instruction from __builtin_clzl( ).
 */

#if defined(_WIN32)
/* We use the Windows implementations below. */
#elif defined(__x86_64__) || defined(__i386__) || defined(__arm64__) || defined(__arm__)
/* We use a thought-to-be-good version of __builtin_clz. */
#elif defined __GNUC__
#warning Using __builtin_clz() on an unknown architecture; it may not be constant-time.
/* If you find yourself seeing this warning, file a radar for someone to
 * check whether or not __builtin_clz() generates a constant-time
 * implementation on the architecture you are targeting.  If it does, append
 * the name of that architecture to the list of "safe" architectures above.  */
#endif

CC_INLINE CC_CONST unsigned cc_clz32_fallback(uint32_t data)
{
    unsigned int b = 0;
    unsigned int bit = 0;
    // Work from LSB to MSB
    for (int i = 0; i < 32; i++) {
        bit = (data >> i) & 1;
        // If the bit is 0, update the "leading bits are zero" counter "b".
        b += (1 - bit);
        /* If the bit is 0, (bit - 1) is 0xffff... therefore b is retained.
         * If the bit is 1, (bit - 1) is 0 therefore b is set to 0.
         */
        b &= (bit - 1);
    }
    return b;
}

CC_INLINE CC_CONST unsigned cc_clz64_fallback(uint64_t data)
{
    unsigned int b = 0;
    unsigned int bit = 0;
    // Work from LSB to MSB
    for (int i = 0; i < 64; i++) {
        bit = (data >> i) & 1;
        // If the bit is 0, update the "leading bits are zero" counter.
        b += (1 - bit);
        /* If the bit is 0, (bit - 1) is 0xffff... therefore b is retained.
         * If the bit is 1, (bit - 1) is 0 therefore b is set to 0.
         */
        b &= (bit - 1);
    }
    return b;
}

CC_INLINE CC_CONST unsigned cc_ctz32_fallback(uint32_t data)
{
    unsigned int b = 0;
    unsigned int bit = 0;
    // Work from MSB to LSB
    for (int i = 31; i >= 0; i--) {
        bit = (data >> i) & 1;
        // If the bit is 0, update the "trailing zero bits" counter.
        b += (1 - bit);
        /* If the bit is 0, (bit - 1) is 0xffff... therefore b is retained.
         * If the bit is 1, (bit - 1) is 0 therefore b is set to 0.
         */
        b &= (bit - 1);
    }
    return b;
}

CC_INLINE CC_CONST unsigned cc_ctz64_fallback(uint64_t data)
{
    unsigned int b = 0;
    unsigned int bit = 0;
    // Work from MSB to LSB
    for (int i = 63; i >= 0; i--) {
        bit = (data >> i) & 1;
        // If the bit is 0, update the "trailing zero bits" counter.
        b += (1 - bit);
        /* If the bit is 0, (bit - 1) is 0xffff... therefore b is retained.
         * If the bit is 1, (bit - 1) is 0 therefore b is set to 0.
         */
        b &= (bit - 1);
    }
    return b;
}

/*!
  @function cc_clz32
  @abstract Count leading zeros of a nonzero 32-bit value

  @param data A nonzero 32-bit value

  @result Count of leading zeros of @p data

  @discussion @p data is assumed to be nonzero.
*/
CC_INLINE CC_CONST unsigned cc_clz32(uint32_t data) {
    cc_assert(data != 0);
#if __has_builtin(__builtin_clz)
    cc_static_assert(sizeof(unsigned) == 4, "clz relies on an unsigned int being 4 bytes");
    return (unsigned)__builtin_clz(data);
#else
    return cc_clz32_fallback(data);
#endif
}

/*!
  @function cc_clz64
  @abstract Count leading zeros of a nonzero 64-bit value

  @param data A nonzero 64-bit value

  @result Count of leading zeros of @p data

  @discussion @p data is assumed to be nonzero.
*/
CC_INLINE CC_CONST unsigned cc_clz64(uint64_t data) {
    cc_assert(data != 0);
#if __has_builtin(__builtin_clzll)
    return (unsigned)__builtin_clzll(data);
#else
    return cc_clz64_fallback(data);
#endif
}

/*!
  @function cc_ctz32
  @abstract Count trailing zeros of a nonzero 32-bit value

  @param data A nonzero 32-bit value

  @result Count of trailing zeros of @p data

  @discussion @p data is assumed to be nonzero.
*/
CC_INLINE CC_CONST unsigned cc_ctz32(uint32_t data) {
    cc_assert(data != 0);
#if __has_builtin(__builtin_ctz)
    cc_static_assert(sizeof(unsigned) == 4, "ctz relies on an unsigned int being 4 bytes");
    return (unsigned)__builtin_ctz(data);
#else
    return cc_ctz32_fallback(data);
#endif
}

/*!
  @function cc_ctz64
  @abstract Count trailing zeros of a nonzero 64-bit value

  @param data A nonzero 64-bit value

  @result Count of trailing zeros of @p data

  @discussion @p data is assumed to be nonzero.
*/
CC_INLINE CC_CONST unsigned cc_ctz64(uint64_t data) {
    cc_assert(data != 0);
#if __has_builtin(__builtin_ctzll)
    return (unsigned)__builtin_ctzll(data);
#else
    return cc_ctz64_fallback(data);
#endif
}

/*!
  @function cc_ffs32_fallback
  @abstract Find first bit set in a 32-bit value

  @param data A 32-bit value

  @result One plus the index of the least-significant bit set in @p data or, if @p data is zero, zero
 */
CC_INLINE CC_CONST unsigned cc_ffs32_fallback(int32_t data)
{
    unsigned b = 0;
    unsigned bit = 0;
    unsigned seen = 0;

    // Work from LSB to MSB
    for (int i = 0; i < 32; i++) {
        bit = ((uint32_t)data >> i) & 1;

        // Track whether we've seen a 1 bit.
        seen |= bit;

        // If the bit is 0 and we haven't seen a 1 yet, increment b.
        b += (1 - bit) & (seen - 1);
    }

    // If we saw a 1, return b + 1, else 0.
    return (~(seen - 1)) & (b + 1);
}

/*!
  @function cc_ffs64_fallback
  @abstract Find first bit set in a 64-bit value

  @param data A 64-bit value

  @result One plus the index of the least-significant bit set in @p data or, if @p data is zero, zero
 */
CC_INLINE CC_CONST unsigned cc_ffs64_fallback(int64_t data)
{
    unsigned b = 0;
    unsigned bit = 0;
    unsigned seen = 0;

    // Work from LSB to MSB
    for (int i = 0; i < 64; i++) {
        bit = ((uint64_t)data >> i) & 1;

        // Track whether we've seen a 1 bit.
        seen |= bit;

        // If the bit is 0 and we haven't seen a 1 yet, increment b.
        b += (1 - bit) & (seen - 1);
    }

    // If we saw a 1, return b + 1, else 0.
    return (~(seen - 1)) & (b + 1);
}

/*!
  @function cc_ffs32
  @abstract Find first bit set in a 32-bit value

  @param data A 32-bit value

  @result One plus the index of the least-significant bit set in @p data or, if @p data is zero, zero
 */
CC_INLINE CC_CONST unsigned cc_ffs32(int32_t data)
{
    cc_static_assert(sizeof(int) == 4, "ffs relies on an int being 4 bytes");
#if __has_builtin(__builtin_ffs)
    return (unsigned)__builtin_ffs(data);
#else
    return cc_ffs32_fallback(data);
#endif
}

/*!
  @function cc_ffs64
  @abstract Find first bit set in a 64-bit value

  @param data A 64-bit value

  @result One plus the index of the least-significant bit set in @p data or, if @p data is zero, zero
 */
CC_INLINE CC_CONST unsigned cc_ffs64(int64_t data)
{
#if __has_builtin(__builtin_ffsll)
    return (unsigned)__builtin_ffsll(data);
#else
    return cc_ffs64_fallback(data);
#endif
}

#define cc_add_overflow __builtin_add_overflow
#define cc_mul_overflow __builtin_mul_overflow

/* HEAVISIDE_STEP (shifted by one)
   function f(x): x->0, when x=0
                  x->1, when x>0
   Can also be seen as a bitwise operation:
      f(x): x -> y
        y[0]=(OR x[i]) for all i (all bits)
        y[i]=0 for all i>0
   Run in constant time (log2(<bitsize of x>))
   Useful to run constant time checks
*/
#define CC_HEAVISIDE_STEP(r, s) do {                                         \
    cc_static_assert(sizeof(uint64_t) >= sizeof(s), "max type is uint64_t"); \
    const uint64_t _s = (uint64_t)s;                                         \
    const uint64_t _t = (_s & 0xffffffff) | (_s >> 32);                      \
    r = (uint8_t)((_t + 0xffffffff) >> 32);                                  \
} while (0)

/* Return 1 if x mod 4 =1,2,3, 0 otherwise */
#define CC_CARRY_2BITS(x) (((x>>1) | x) & 0x1)
#define CC_CARRY_3BITS(x) (((x>>2) | (x>>1) | x) & 0x1)

#define cc_ceiling(a,b)  (((a)+((b)-1))/(b))
#define CC_BITLEN_TO_BYTELEN(x) cc_ceiling((x), 8)

/*!
 @brief     CC_MUXU(r, s, a, b) is equivalent to r = s ? a : b, but executes in constant time
 @param a   Input a
 @param b   Input b
 @param s   Selection parameter s. Must be 0 or 1.
 @param r   Output, set to a if s=1, or b if s=0.
 */
#define CC_MUXU(r, s, a, b) do {            \
    cc_assert((s) == 0 || (s) == 1);        \
    r = (~((s)-1) & (a)) | (((s)-1) & (b)); \
} while (0)

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
