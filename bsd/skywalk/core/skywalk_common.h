/*
 * Copyright (c) 2017-2021 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#ifndef _SKYWALK_COMMON_H_
#define _SKYWALK_COMMON_H_

#if defined(PRIVATE) || defined(BSD_KERNEL_PRIVATE)
/*
 * Routines common to kernel and userland.  This file is intended to
 * be included by the Skywalk kernel and libsyscall code.
 */

#include <skywalk/os_skywalk_private.h>

#ifndef KERNEL
#if defined(LIBSYSCALL_INTERFACE)
__BEGIN_DECLS
extern int fprintf_stderr(const char *format, ...);
__END_DECLS

/* CSTYLED */

#define SK_ABORT(msg) do {                                              \
	(void) fprintf_stderr("%s\n", msg);                             \
	__asm__(""); __builtin_trap();                                  \
} while (0)

#define SK_ABORT_WITH_CAUSE(msg, cause) do {                            \
	(void) fprintf_stderr("%s: cause 0x%x\n", msg, cause);          \
	__asm__(""); __builtin_trap();                                  \
} while (0)

#define SK_ABORT_DYNAMIC(msg)   SK_ABORT(msg)


#define VERIFY(EX) do {                                                 \
	if (__improbable(!(EX))) {                                      \
	        SK_ABORT("assertion failed: " #EX);                     \
	/* NOTREACHED */                                        \
	        __builtin_unreachable();                                \
	}                                                               \
} while (0)

#if (DEBUG || DEVELOPMENT)
#define ASSERT(EX)      VERIFY(EX)
#else /* !DEBUG && !DEVELOPMENT */
#define ASSERT(EX)      ((void)0)
#endif /* !DEBUG && !DEVELOPMENT */
#endif /* !LIBSYSCALL_INTERFACE */
#endif /* !KERNEL */

#ifndef container_of
#define container_of(ptr, type, member) \
	((type*)(((uintptr_t)ptr) - offsetof(type, member)))
#endif

/*
 * Prefetch.
 */
#define SK_PREFETCH(a, n) \
	__builtin_prefetch((const void *)((uintptr_t)(a) + (n)), 0, 3)
#define SK_PREFETCHW(a, n) \
	__builtin_prefetch((const void *)((uintptr_t)(a) + (n)), 1, 3)

/*
 * Slower roundup function; if "align" is not power of 2 (else use P2ROUNDUP)
 */
#define SK_ROUNDUP(x, align)    \
	((((x) % (align)) == 0) ? (x) : ((x) + ((align) - ((x) % (align)))))

/* compile time assert */
#ifndef _CASSERT
#define _CASSERT(x)     _Static_assert(x, "compile-time assertion failed")
#endif /* !_CASSERT */

/* power of 2 address alignment */
#ifndef IS_P2ALIGNED
#define IS_P2ALIGNED(v, a)      \
	((((uintptr_t)(v)) & ((uintptr_t)(a) - 1)) == 0)
#endif /* IS_P2ALIGNED */

#define __sk_aligned(a) __attribute__((__aligned__(a)))
#define __sk_packed     __attribute__((__packed__))
#define __sk_unused     __attribute__((__unused__))

#ifdef KERNEL
#include <sys/sdt.h>

/*
 * Copy 8-bytes total, 64-bit aligned, scalar.
 */
__attribute__((always_inline))
static inline void
__sk_copy64_8(uint64_t *src, uint64_t *dst)
{
	*dst = *src;            /* [#0*8] */
}

/*
 * Copy 8-bytes total, 32-bit aligned, scalar.
 */
__attribute__((always_inline))
static inline void
__sk_copy32_8(uint32_t *src, uint32_t *dst)
{
#if defined(__x86_64__)
	/* use unaligned scalar move on x86_64 */
	__sk_copy64_8((uint64_t *)(void *)src, (uint64_t *)(void *)dst);
#else
	*dst++ = *src++;                /* dw[0] */
	*dst = *src;                    /* dw[1] */
#endif
}

/*
 * Copy 16-bytes total, 64-bit aligned, scalar.
 */
static inline void
__sk_copy64_16(uint64_t *src, uint64_t *dst)
{
	*dst++ = *src++;        /* [#0*8] */
	*dst = *src;            /* [#1*8] */
}

/*
 * Copy 16-bytes total, 64-bit aligned, SIMD (if available).
 */
__attribute__((always_inline))
static inline void
__sk_vcopy64_16(uint64_t *src, uint64_t *dst)
{
#if defined(__arm64__)
	/* no need to save/restore registers on arm64 (SPILL_REGISTERS) */
	/* BEGIN CSTYLED */
	__asm__ __volatile__ (
                "ldr	q0, [%[src]]		\n\t"
                "str	q0, [%[dst]]		\n\t"
                :
                : [src] "r" (src), [dst] "r" (dst)
                : "v0", "memory"
        );
	/* END CSTYLED */
#else
	__sk_copy64_16(src, dst);
#endif
}

/*
 * Copy 16-bytes total, 32-bit aligned, scalar.
 */
__attribute__((always_inline))
static inline void
__sk_copy32_16(uint32_t *src, uint32_t *dst)
{
	*dst++ = *src++;        /* [#0*4] */
	*dst++ = *src++;        /* [#1*4] */
	*dst++ = *src++;        /* [#2*4] */
	*dst = *src;            /* [#3*4] */
}

/*
 * Copy 16-bytes total, 32-bit aligned, SIMD (if available).
 */
__attribute__((always_inline))
static inline void
__sk_vcopy32_16(uint32_t *src, uint32_t *dst)
{
#if defined(__arm64__)
	/* use SIMD unaligned move on arm64 */
	__sk_vcopy64_16((uint64_t *)(void *)src, (uint64_t *)(void *)dst);
#else
	__sk_copy32_16(src, dst);
#endif
}

/*
 * Copy 20-bytes total, 64-bit aligned, scalar.
 */
__attribute__((always_inline))
static inline void
__sk_copy64_20(uint64_t *src, uint64_t *dst)
{
	*dst++ = *src++;                        /* [#0*8] */
	*dst++ = *src++;                        /* [#1*8] */
	*(uint32_t *)dst = *(uint32_t *)src;    /* [#2*4] */
}

/*
 * Copy 20-bytes total, 64-bit aligned, SIMD (if available).
 */
__attribute__((always_inline))
static inline void
__sk_vcopy64_20(uint64_t *src, uint64_t *dst)
{
#if defined(__arm64__)
	/*
	 * Load pair 2x16-bytes, store single 16-bytes and 4-bytes;
	 * no need to save/restore registers on arm64 (SPILL_REGISTERS).
	 */
	/* BEGIN CSTYLED */
	__asm__ __volatile__ (
                "ldp	q0, q1, [%[src]]	\n\t"
                "str	q0, [%[dst]]		\n\t"
                "str	s1, [%[dst], #16]	\n\t"
                :
                : [src] "r" (src), [dst] "r" (dst)
                : "v0", "v1", "memory"
        );
	/* END CSTYLED */
#else
	__sk_copy64_20(src, dst);
#endif
}

/*
 * Copy 24-bytes total, 64-bit aligned, scalar.
 */
__attribute__((always_inline))
static inline void
__sk_copy64_24(uint64_t *src, uint64_t *dst)
{
	*dst++ = *src++;        /* [#0*8] */
	*dst++ = *src++;        /* [#1*8] */
	*dst = *src;            /* [#2*8] */
}

/*
 * Copy 24-bytes total, 64-bit aligned, SIMD (if available).
 */
__attribute__((always_inline))
static inline void
__sk_vcopy64_24(uint64_t *src, uint64_t *dst)
{
#if defined(__arm64__)
	/*
	 * Use 16-bytes load/store and 8-bytes load/store on arm64;
	 * no need to save/restore registers on arm64 (SPILL_REGISTERS).
	 */
	/* BEGIN CSTYLED */
	__asm__ __volatile__ (
                "ldr	q0, [%[src]]		\n\t"
                "str	q0, [%[dst]]		\n\t"
                "ldr	d0, [%[src], #16]	\n\t"
                "str	d0, [%[dst], #16]	\n\t"
                :
                : [src] "r" (src), [dst] "r" (dst)
                : "v0", "memory"
        );
	/* END CSTYLED */
#else
	__sk_copy64_24(src, dst);
#endif
}

/*
 * Copy 32-bytes total, 64-bit aligned, scalar.
 */
__attribute__((always_inline))
static inline void
__sk_copy64_32(uint64_t *src, uint64_t *dst)
{
	*dst++ = *src++;        /* [#0*8] */
	*dst++ = *src++;        /* [#1*8] */
	*dst++ = *src++;        /* [#2*8] */
	*dst = *src;            /* [#3*8] */
}

/*
 * Copy 32-bytes total, 64-bit aligned, SIMD (if available).
 */
__attribute__((always_inline))
static inline void
__sk_vcopy64_32(uint64_t *src, uint64_t *dst)
{
#if defined(__arm64__)
	/* no need to save/restore registers on arm64 (SPILL_REGISTERS) */
	/* BEGIN CSTYLED */
	__asm__ __volatile__ (
                "ldp	q0, q1, [%[src]]	\n\t"
                "stp	q0, q1, [%[dst]]	\n\t"
                :
                : [src] "r" (src), [dst] "r" (dst)
                : "v0", "v1", "memory"
        );
	/* END CSTYLED */
#else
	__sk_copy64_32(src, dst);
#endif
}

/*
 * Copy 32-bytes total, 32-bit aligned, scalar.
 */
__attribute__((always_inline))
static inline void
__sk_copy32_32(uint32_t *src, uint32_t *dst)
{
	*dst++ = *src++;        /* [#0*4] */
	*dst++ = *src++;        /* [#1*4] */
	*dst++ = *src++;        /* [#2*4] */
	*dst++ = *src++;        /* [#3*4] */
	*dst++ = *src++;        /* [#4*4] */
	*dst++ = *src++;        /* [#5*4] */
	*dst++ = *src++;        /* [#6*4] */
	*dst = *src;            /* [#7*4] */
}

/*
 * Copy 32-bytes total, 32-bit aligned, SIMD (if available).
 */
__attribute__((always_inline))
static inline void
__sk_vcopy32_32(uint32_t *src, uint32_t *dst)
{
#if defined(__arm64__)
	/* use SIMD unaligned move on arm64 */
	__sk_vcopy64_32((uint64_t *)(void *)src, (uint64_t *)(void *)dst);
#else
	__sk_copy32_32(src, dst);
#endif
}

/*
 * Copy 40-bytes total, 64-bit aligned, scalar.
 */
__attribute__((always_inline))
static inline void
__sk_copy64_40(uint64_t *src, uint64_t *dst)
{
	*dst++ = *src++;        /* [#0*8] */
	*dst++ = *src++;        /* [#1*8] */
	*dst++ = *src++;        /* [#2*8] */
	*dst++ = *src++;        /* [#3*8] */
	*dst = *src;            /* [#4*8] */
}

/*
 * Copy 40-bytes total, 64-bit aligned, SIMD (if available).
 */
__attribute__((always_inline))
static inline void
__sk_vcopy64_40(uint64_t *src, uint64_t *dst)
{
#if defined(__arm64__)
	/*
	 * Use 32-bytes load/store pair and 8-bytes load/store on arm64;
	 * no need to save/restore registers on arm64 (SPILL_REGISTERS).
	 */
	/* BEGIN CSTYLED */
	__asm__ __volatile__ (
                "ldp	q0, q1, [%[src]]	\n\t"
                "stp	q0, q1, [%[dst]]	\n\t"
                "ldr	d0, [%[src], #32]	\n\t"
                "str	d0, [%[dst], #32]	\n\t"
                :
                : [src] "r" (src), [dst] "r" (dst)
                : "v0", "v1", "memory"
        );
	/* END CSTYLED */
#else
	__sk_copy64_40(src, dst);
#endif
}

#if defined(__arm64__)
/*
 * On arm64, the following inline assembly fixed-length routines have
 * fewer clock cycles than bzero().  We can directly use vector registers
 * without saving/restoring them unlike on x86_64/arm32.
 */

/*
 * Zero 16-bytes total, SIMD.
 */
__attribute__((always_inline))
static inline void
__sk_zero_16(void *p)
{
	/*
	 * Use 16-bytes store pair using 64-bit zero register on arm64;
	 * no need to save/restore registers on arm64 (SPILL_REGISTERS).
	 */
	/* BEGIN CSTYLED */
	__asm__ __volatile__ (
                "stp	xzr, xzr, [%[p]]	\n\t"
                :
                : [p] "r" (p)
                : "memory"
        );
	/* END CSTYLED */
}

/*
 * Zero 32-bytes total, SIMD.
 */
__attribute__((always_inline))
static inline void
__sk_zero_32(void *p)
{
	/*
	 * Use 32-bytes store pair using zeroed v0 register on arm64;
	 * no need to save/restore registers on arm64 (SPILL_REGISTERS).
	 */
	/* BEGIN CSTYLED */
	__asm__ __volatile__ (
                "eor.16b v0, v0, v0		\n\t"
                "stp	 q0, q0, [%[p]]		\n\t"
                :
                : [p] "r" (p)
                : "v0", "memory", "cc"
        );
	/* END CSTYLED */
}

/*
 * Zero 48-bytes total, SIMD.
 */
__attribute__((always_inline))
static inline void
__sk_zero_48(void *p)
{
	/*
	 * Use 32-bytes store pair and 16-byte store using zeroed v0
	 * register on arm64; no need to save/restore registers on
	 * arm64 (SPILL_REGISTERS).
	 */
	/* BEGIN CSTYLED */
	__asm__ __volatile__ (
                "eor.16b v0, v0, v0		\n\t"
                "stp	 q0, q0, [%[p]]		\n\t"
                "str	 q0, [%[p], #32]	\n\t"
                :
                : [p] "r" (p)
                : "v0", "memory", "cc"
        );
	/* END CSTYLED */
}

/*
 * Zero 128-bytes total, SIMD.
 */
__attribute__((always_inline))
static inline void
__sk_zero_128(void *p)
{
	/*
	 * Use 4x 32-bytes store pairs using zeroed v0 register on arm64;
	 * no need to save/restore registers on arm64 (SPILL_REGISTERS).
	 *
	 * Note that we could optimize this routine by utilizing "dc zva"
	 * which zeroes the entire cache line.  However, that requires
	 * us to guarantee that the address is cache line aligned which
	 * we cannot (at the moment).
	 */
	/* BEGIN CSTYLED */
	__asm__ __volatile__ (
                "eor.16b v0, v0, v0		\n\t"
                "stp	 q0, q0, [%[p]]		\n\t"
                "stp	 q0, q0, [%[p], #32]	\n\t"
                "stp	 q0, q0, [%[p], #64]	\n\t"
                "stp	 q0, q0, [%[p], #96]	\n\t"
                :
                : [p] "r" (p)
                : "v0", "memory", "cc"
        );
	/* END CSTYLED */
}
#else /* !__arm64__ */
/*
 * Just use bzero() for simplicity.  On x86_64, "rep stosb" microcoded
 * implementation already uses wider stores and can go much faster than
 * one byte per clock cycle.  For arm32, bzero() is also good enough.
 */
#define __sk_zero_16(_p)        bzero(_p, 16)
#define __sk_zero_32(_p)        bzero(_p, 32)
#define __sk_zero_48(_p)        bzero(_p, 48)
#define __sk_zero_128(_p)       bzero(_p, 128)
#endif /* !__arm64__ */

/*
 * The following are optimized routines which rely on the caller
 * rounding up the source and destination buffers to multiples of
 * 4, 8 or 64 bytes, and are 64-bit aligned; faster than memcpy().
 *
 * Note: they do not support overlapping ranges.
 */

/*
 * Threshold as to when we use memcpy() rather than unrolled copy.
 */
#if defined(__x86_64__)
#define SK_COPY_THRES 2048
#elif defined(__arm64__)
#define SK_COPY_THRES 1024
#else /* !__x86_64__ && !__arm64__ */
#define SK_COPY_THRES 1024
#endif /* !__x86_64__ && !__arm64__ */

#if (DEVELOPMENT || DEBUG)
extern size_t sk_copy_thres;
#endif /* (DEVELOPMENT || DEBUG) */

/*
 * Scalar version, 4-bytes multiple.
 */
__attribute__((always_inline))
static inline void
sk_copy64_4x(uint32_t *src, uint32_t *dst, size_t l)
{
#if (DEVELOPMENT || DEBUG)
	if (__probable(l <= sk_copy_thres)) {
#else
	if (__probable(l <= SK_COPY_THRES)) {
#endif /* (!DEVELOPMENT && !DEBUG! */
		while ((ssize_t)(l -= 4) >= 0) {
			*dst++ = *src++;        /* [#n*4] */
		}
	} else {
		(void) memcpy((void *)dst, (void *)src, l);
	}
}

/*
 * Scalar version, 8-bytes multiple.
 */
__attribute__((always_inline))
static inline void
sk_copy64_8x(uint64_t *src, uint64_t *dst, size_t l)
{
#if (DEVELOPMENT || DEBUG)
	if (__probable(l <= sk_copy_thres)) {
#else
	if (__probable(l <= SK_COPY_THRES)) {
#endif /* (!DEVELOPMENT && !DEBUG! */
		while ((ssize_t)(l -= 8) >= 0) {
			*dst++ = *src++;        /* [#n*8] */
		}
	} else {
		(void) memcpy((void *)dst, (void *)src, l);
	}
}

/*
 * Scalar version (usually faster than SIMD), 32-bytes multiple.
 */
__attribute__((always_inline))
static inline void
sk_copy64_32x(uint64_t *src, uint64_t *dst, size_t l)
{
#if (DEVELOPMENT || DEBUG)
	if (__probable(l <= sk_copy_thres)) {
#else
	if (__probable(l <= SK_COPY_THRES)) {
#endif /* (!DEVELOPMENT && !DEBUG! */
		while ((ssize_t)(l -= 32) >= 0) {
			*dst++ = *src++;        /* [#0*8] */
			*dst++ = *src++;        /* [#1*8] */
			*dst++ = *src++;        /* [#2*8] */
			*dst++ = *src++;        /* [#3*8] */
		}
	} else {
		(void) memcpy((void *)dst, (void *)src, l);
	}
}

/*
 * Scalar version (usually faster than SIMD), 64-bytes multiple.
 */
__attribute__((always_inline))
static inline void
sk_copy64_64x(uint64_t *src, uint64_t *dst, size_t l)
{
#if (DEVELOPMENT || DEBUG)
	if (__probable(l <= sk_copy_thres)) {
#else
	if (__probable(l <= SK_COPY_THRES)) {
#endif /* (!DEVELOPMENT && !DEBUG! */
		while ((ssize_t)(l -= 64) >= 0) {
			*dst++ = *src++;        /* [#0*8] */
			*dst++ = *src++;        /* [#1*8] */
			*dst++ = *src++;        /* [#2*8] */
			*dst++ = *src++;        /* [#3*8] */
			*dst++ = *src++;        /* [#4*8] */
			*dst++ = *src++;        /* [#5*8] */
			*dst++ = *src++;        /* [#6*8] */
			*dst++ = *src++;        /* [#7*8] */
		}
	} else {
		(void) memcpy((void *)dst, (void *)src, l);
	}
}

/*
 * Use scalar or SIMD based on platform/size.
 */
#if defined(__x86_64__)
#define sk_copy64_8     __sk_copy64_8           /* scalar only */
#define sk_copy32_8     __sk_copy32_8           /* scalar only */
#define sk_copy64_16    __sk_copy64_16          /* scalar */
#define sk_copy32_16    __sk_copy32_16          /* scalar */
#define sk_copy64_20    __sk_copy64_20          /* scalar */
#define sk_copy64_24    __sk_copy64_24          /* scalar */
#define sk_copy64_32    __sk_copy64_32          /* scalar */
#define sk_copy32_32    __sk_copy32_32          /* scalar */
#define sk_copy64_40    __sk_copy64_40          /* scalar */
#define sk_zero_16      __sk_zero_16            /* scalar */
#define sk_zero_32      __sk_zero_32            /* scalar */
#define sk_zero_48      __sk_zero_48            /* scalar */
#define sk_zero_128     __sk_zero_128           /* scalar */
#elif defined(__arm64__)
#define sk_copy64_8     __sk_copy64_8           /* scalar only */
#define sk_copy32_8     __sk_copy32_8           /* scalar only */
#define sk_copy64_16    __sk_vcopy64_16         /* SIMD */
#define sk_copy32_16    __sk_vcopy32_16         /* SIMD */
#define sk_copy64_20    __sk_vcopy64_20         /* SIMD */
#define sk_copy64_24    __sk_vcopy64_24         /* SIMD */
#define sk_copy64_32    __sk_vcopy64_32         /* SIMD */
#define sk_copy32_32    __sk_vcopy32_32         /* SIMD */
#define sk_copy64_40    __sk_vcopy64_40         /* SIMD */
#define sk_zero_16      __sk_zero_16            /* SIMD */
#define sk_zero_32      __sk_zero_32            /* SIMD */
#define sk_zero_48      __sk_zero_48            /* SIMD */
#define sk_zero_128     __sk_zero_128           /* SIMD */
#else
#define sk_copy64_8     __sk_copy64_8           /* scalar only */
#define sk_copy32_8     __sk_copy32_8           /* scalar only */
#define sk_copy64_16    __sk_copy64_16          /* scalar */
#define sk_copy32_16    __sk_copy32_16          /* scalar */
#define sk_copy64_20    __sk_copy64_20          /* scalar */
#define sk_copy64_24    __sk_copy64_24          /* scalar */
#define sk_copy64_32    __sk_copy64_32          /* scalar */
#define sk_copy32_32    __sk_copy32_32          /* scalar */
#define sk_copy64_40    __sk_copy64_40          /* scalar */
#define sk_zero_16      __sk_zero_16            /* scalar */
#define sk_zero_32      __sk_zero_32            /* scalar */
#define sk_zero_48      __sk_zero_48            /* scalar */
#define sk_zero_128     __sk_zero_128           /* scalar */
#endif

/*
 * Do not use these directly.
 * Use the skn_ variants if you need custom probe names.
 */
#define _sk_alloc(probename, size, flags, tag)                          \
({                                                                      \
	void *ret;                                                      \
                                                                        \
	ret = kheap_alloc_site(KHEAP_DEFAULT, (size), Z_ZERO | (flags), \
	    (tag));                                                     \
	DTRACE_SKYWALK3(probename, size_t, (size), int, (flags),        \
	    void *, ret);                                               \
	ret;                                                            \
})

#define _sk_realloc(probename, elem, oldsize, newsize, flags, tag)      \
({                                                                      \
	void *ret;                                                      \
                                                                        \
	ret = krealloc_ext(KHEAP_DEFAULT, (elem), (oldsize), (newsize), \
	    Z_ZERO | (flags), (tag)).addr;                              \
	DTRACE_SKYWALK5(probename, void *, (elem), size_t, (oldsize),   \
	    size_t, (newsize), int, (flags), void *, ret);              \
	ret;                                                            \
})

#define _sk_free(probename, elem, size)                                 \
{                                                                       \
	DTRACE_SKYWALK2(probename, void *, (elem), size_t, (size));     \
	kheap_free(KHEAP_DEFAULT, (elem), (size));                      \
}

#define _sk_alloc_type(probename, type, flags, tag)                     \
({                                                                      \
	void *ret;                                                      \
                                                                        \
	/* XXX Modify this to use KT_PRIV_ACCT later  */                \
	ret = kalloc_type_site(type, Z_ZERO | (flags), (tag));          \
	DTRACE_SKYWALK3(probename, char *, #type, int, (flags),         \
	    void *, ret);                                               \
	ret;                                                            \
})

#define _sk_alloc_type_array(probename, type, count, flags, tag)        \
({                                                                      \
	void *ret;                                                      \
                                                                        \
	ret = kalloc_type_site(type, (count), Z_ZERO | (flags), (tag)); \
	DTRACE_SKYWALK4(probename, char *, #type, size_t, (count),      \
	    int, (flags), void *, ret);                                 \
	ret;                                                            \
})

#define _sk_alloc_type_header_array(probename, htype, type, count, flags, tag) \
({                                                                      \
	void *ret;                                                      \
                                                                        \
	ret = kalloc_type_site(htype, type, (count), Z_ZERO | (flags),  \
	    (tag));                                                     \
	DTRACE_SKYWALK5(probename, char *, #htype, char *, #type,       \
	    size_t, (count), int, (flags), void *, ret);                \
	ret;                                                            \
})

#define _sk_free_type(probename, type, elem)                            \
{                                                                       \
	DTRACE_SKYWALK2(probename, char *, #type, void *, (elem));      \
	kfree_type(type, (elem));                                       \
}

#define _sk_free_type_array(probename, type, count, elem)               \
{                                                                       \
	DTRACE_SKYWALK3(probename, char *, #type, size_t, (count),      \
	    void *, (elem));                                            \
	kfree_type(type, (count), (elem));                              \
}

#define _sk_free_type_header_array(probename, htype, type, count, elem) \
{                                                                       \
	DTRACE_SKYWALK4(probename, char *, #htype, char *, #type,       \
	    size_t, (count), void *, (elem));                           \
	kfree_type(htype, type, (count), (elem));                       \
}

#define _sk_alloc_data(probename, size, flags, tag)                     \
({                                                                      \
	void *ret;                                                      \
                                                                        \
	ret = kalloc_data_site((size), Z_ZERO | (flags), (tag));        \
	DTRACE_SKYWALK3(probename, size_t, (size), int, (flags),        \
	    void *, ret);                                               \
	ret;                                                            \
})

#define _sk_realloc_data(probename, elem, oldsize, newsize, flags, tag) \
({                                                                      \
	void *ret;                                                      \
                                                                        \
	ret = krealloc_data_site((elem), (oldsize), (newsize),          \
	    Z_ZERO | (flags), (tag));                                   \
	DTRACE_SKYWALK5(probename, void *, (elem), size_t, (oldsize),   \
	    size_t, (newsize), int, (flags), void *, ret);              \
	ret;                                                            \
})

#define _sk_free_data(probename, elem, size)                            \
{                                                                       \
	DTRACE_SKYWALK2(probename, void *, (elem), size_t, (size));     \
	kfree_data((elem), (size));                                     \
}

#define sk_alloc(size, flags, tag)                                      \
	_sk_alloc(sk_alloc, size, flags, tag)

#define sk_realloc(elem, oldsize, newsize, flags, tag)                  \
	_sk_realloc(sk_realloc, elem, oldsize, newsize, flags, tag)

#define sk_free(elem, size)                                             \
	_sk_free(sk_free, elem, size)

#define sk_alloc_type(type, flags, tag)                                 \
	_sk_alloc_type(sk_alloc_type, type, flags, tag)

#define sk_alloc_type_array(type, count, flags, tag)                    \
	_sk_alloc_type_array(sk_alloc_type_array, type, count, flags, tag)

#define sk_alloc_type_header_array(htype, type, count, flags, tag)      \
	_sk_alloc_type_header_array(sk_alloc_type_header_array, htype,  \
	type, count, flags, tag)

#define sk_free_type(type, elem)                                        \
	_sk_free_type(sk_free_type, type, elem)

#define sk_free_type_array(type, count, elem)                           \
	_sk_free_type_array(sk_free_type_array, type, count, elem)

#define sk_free_type_header_array(htype, type, count, elem)             \
	_sk_free_type_header_array(sk_free_type_header_array, htype,    \
	type, count, elem)

#define sk_alloc_data(size, flags, tag)                                 \
	_sk_alloc_data(sk_alloc_data, size, flags, tag)

#define sk_realloc_data(elem, oldsize, newsize, flags, tag)             \
	_sk_realloc_data(sk_realloc_data, elem, oldsize, newsize,       \
	flags, tag)

#define sk_free_data(elem, size)                                        \
	_sk_free_data(sk_free_data, elem, size)

/*
 * The skn_ variants are meant to be used if you need to use two or more
 * of the same call within the same function and you want the dtrace
 * probename to be different at each callsite.
 */
#define skn_alloc(name, size, flags, tag)                               \
	_sk_alloc(sk_alloc_ ## name, size, flags, tag)

#define skn_realloc(name, elem, oldsize, newsize, flags, tag)           \
	_sk_realloc(sk_realloc_ ## name, elem, oldsize, newsize, flags, \
	tag)

#define skn_free(name, elem, size)                                      \
	_sk_free(sk_free_ ## name, elem, size)

#define skn_alloc_type(name, type, flags, tag)                          \
	_sk_alloc_type(sk_alloc_type_ ## name, type, flags, tag)

#define skn_alloc_type_array(name, type, count, flags, tag)             \
	_sk_alloc_type_array(sk_alloc_type_array_ ## name, type, count, \
	flags, tag)

#define skn_alloc_type_header_array(name, htype, type, count, flags, tag) \
	_sk_alloc_type_header_array(sk_alloc_type_header_array_ ## name, \
	htype, type, count, flags, tag)

#define skn_free_type(name, type, elem)                                 \
	_sk_free_type(sk_free_type_ ## name, type, elem)

#define skn_free_type_array(name, type, count, elem)                    \
	_sk_free_type_array(sk_free_type_array_ ## name, type, count,   \
	elem)

#define skn_free_type_header_array(name, htype, type, count, elem)      \
	_sk_free_type_header_array(sk_free_type_header_array_ ## name,  \
	htype, type, count, elem)

#define skn_alloc_data(name, size, flags, tag)                          \
	_sk_alloc_data(sk_alloc_data_ ## name, size, flags, tag)

#define skn_realloc_data(name, elem, oldsize, newsize, flags, tag)      \
	_sk_realloc_data(sk_realloc_data_ ## name, elem, oldsize, newsize,\
	flags, tag)

#define skn_free_data(name, elem, size)                                 \
	_sk_free_data(sk_free_data_ ## name, elem, size)

/*!
 *  @abstract Compare byte buffers of n bytes long src1 against src2, applying
 *  the byte masks to input data before comparison.  (Scalar version)
 *
 *  @discussion
 *  Returns zero if the two buffers are identical after applying the byte
 *  masks, otherwise non-zero.
 *  Zero-length buffers are always identical.
 *
 *  @param src1 first input buffer of n bytes long
 *  @param src2 second input buffer of n bytes long
 *  @param byte_mask byte mask of n bytes long applied before comparision
 *  @param n number of bytes
 */
static inline int
__sk_memcmp_mask_scalar(const uint8_t *src1, const uint8_t *src2,
    const uint8_t *byte_mask, size_t n)
{
	uint32_t result = 0;
	for (size_t i = 0; i < n; i++) {
		result |= (src1[i] ^ src2[i]) & byte_mask[i];
	}
	return result;
}

static inline int
__sk_memcmp_mask_16B_scalar(const uint8_t *src1, const uint8_t *src2,
    const uint8_t *byte_mask)
{
	return __sk_memcmp_mask_scalar(src1, src2, byte_mask, 16);
}

static inline int
__sk_memcmp_mask_32B_scalar(const uint8_t *src1, const uint8_t *src2,
    const uint8_t *byte_mask)
{
	return __sk_memcmp_mask_scalar(src1, src2, byte_mask, 32);
}

static inline int
__sk_memcmp_mask_48B_scalar(const uint8_t *src1, const uint8_t *src2,
    const uint8_t *byte_mask)
{
	return __sk_memcmp_mask_scalar(src1, src2, byte_mask, 48);
}

static inline int
__sk_memcmp_mask_64B_scalar(const uint8_t *src1, const uint8_t *src2,
    const uint8_t *byte_mask)
{
	return __sk_memcmp_mask_scalar(src1, src2, byte_mask, 64);
}

static inline int
__sk_memcmp_mask_80B_scalar(const uint8_t *src1, const uint8_t *src2,
    const uint8_t *byte_mask)
{
	return __sk_memcmp_mask_scalar(src1, src2, byte_mask, 80);
}

#if defined(__arm64__) || defined(__arm__) || defined(__x86_64__)
extern int os_memcmp_mask_16B(const uint8_t *src1, const uint8_t *src2,
    const uint8_t *byte_mask);
extern int os_memcmp_mask_32B(const uint8_t *src1, const uint8_t *src2,
    const uint8_t *byte_mask);
extern int os_memcmp_mask_48B(const uint8_t *src1, const uint8_t *src2,
    const uint8_t *byte_mask);
extern int os_memcmp_mask_64B(const uint8_t *src1, const uint8_t *src2,
    const uint8_t *byte_mask);
extern int os_memcmp_mask_80B(const uint8_t *src1, const uint8_t *src2,
    const uint8_t *byte_mask);

/*
 * Use SIMD variants based on ARM64 and x86_64.
 */
#define sk_memcmp_mask                  __sk_memcmp_mask
#define sk_memcmp_mask_16B              os_memcmp_mask_16B
#define sk_memcmp_mask_32B              os_memcmp_mask_32B
#define sk_memcmp_mask_48B              os_memcmp_mask_48B
#define sk_memcmp_mask_64B              os_memcmp_mask_64B
#define sk_memcmp_mask_80B              os_memcmp_mask_80B

/*!
 *  @abstract Compare byte buffers of n bytes long src1 against src2, applying
 *  the byte masks to input data before comparison.  (SIMD version)
 *
 *  @discussion
 *  Returns zero if the two buffers are identical after applying the byte
 *  masks, otherwise non-zero.
 *  Zero-length buffers are always identical.
 *
 *  @param src1 first input buffer of n bytes long
 *  @param src2 second input buffer of n bytes long
 *  @param byte_mask byte mask of n bytes long applied before comparision
 *  @param n number of bytes
 */
static inline int
__sk_memcmp_mask(const uint8_t *src1, const uint8_t *src2,
    const uint8_t *byte_mask, size_t n)
{
	uint32_t result = 0;
	size_t i = 0;
	for (; i + 64 <= n; i += 64) {
		result |= sk_memcmp_mask_64B(src1 + i, src2 + i,
		    byte_mask + i);
	}
	for (; i + 32 <= n; i += 32) {
		result |= sk_memcmp_mask_32B(src1 + i, src2 + i,
		    byte_mask + i);
	}
	for (; i + 16 <= n; i += 16) {
		result |= sk_memcmp_mask_16B(src1 + i, src2 + i,
		    byte_mask + i);
	}
	if (i < n) {
		if (n >= 16) {
			/* Compare the last 16 bytes with vector code. */
			result |= sk_memcmp_mask_16B(src1 + n - 16,
			    src2 + n - 16, byte_mask + n - 16);
		} else {
			/* Use scalar code if n < 16. */
			for (; i < n; i++) {
				result |= (src1[i] ^ src2[i]) & byte_mask[i];
			}
		}
	}
	return result;
}
#else /* !(__arm64__ || __arm__ || __x86_64__) */
/*
 * Use scalar variants elsewhere.
 */
#define sk_memcmp_mask                  __sk_memcmp_mask_scalar
#define sk_memcmp_mask_16B              __sk_memcmp_mask_16B_scalar
#define sk_memcmp_mask_32B              __sk_memcmp_mask_32B_scalar
#define sk_memcmp_mask_48B              __sk_memcmp_mask_48B_scalar
#define sk_memcmp_mask_64B              __sk_memcmp_mask_64B_scalar
#define sk_memcmp_mask_80B              __sk_memcmp_mask_80B_scalar
#endif /* !(__arm64__ || __arm__ || __x86_64__) */

/*
 * Scalar variants are available on all platforms if needed.
 */
#define sk_memcmp_mask_scalar           __sk_memcmp_mask_scalar
#define sk_memcmp_mask_16B_scalar       __sk_memcmp_mask_16B_scalar
#define sk_memcmp_mask_32B_scalar       __sk_memcmp_mask_32B_scalar
#define sk_memcmp_mask_48B_scalar       __sk_memcmp_mask_48B_scalar
#define sk_memcmp_mask_64B_scalar       __sk_memcmp_mask_64B_scalar
#define sk_memcmp_mask_80B_scalar       __sk_memcmp_mask_80B_scalar

#endif /* KERNEL */
#endif /* PRIVATE || BSD_KERNEL_PRIVATE */
#endif /* !_SKYWALK_COMMON_H_ */
