/*
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
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
/*
 * NOTICE: This file was modified by McAfee Research in 2004 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */
/*
 * HISTORY
 * @OSF_COPYRIGHT@
 */

#if (defined(__has_include) && __has_include(<__xnu_libcxx_sentinel.h>) && !defined(XNU_LIBCXX_SDKROOT))

#if !__has_include_next(<string.h>)
#error Do not build with -nostdinc (use GCC_USE_STANDARD_INCLUDE_SEARCHING=NO)
#endif /* !__has_include_next(<string.h>) */

#include_next <string.h>

#else /* (defined(__has_include) && __has_include(<__xnu_libcxx_sentinel.h>) && !defined(XNU_LIBCXX_SDKROOT)) */

#ifndef _STRING_H_
#define _STRING_H_      1

#include <sys/cdefs.h>
#ifdef MACH_KERNEL_PRIVATE
#include <types.h>
#else /* MACH_KERNEL_PRIVATE */
#include <sys/types.h>
#endif /* MACH_KERNEL_PRIVATE */

#ifdef KERNEL
#include <machine/trap.h>
#endif /* KERNEL */

__BEGIN_DECLS

#ifndef NULL
#if defined (__cplusplus)
#if __cplusplus >= 201103L
#define NULL nullptr
#else
#define NULL 0
#endif
#else
#define NULL ((void *)0)
#endif
#endif

/*
 * Memory functions
 *
 *   int bcmp(const void *s1, const void *s2, size_t n);
 *   int memcmp(const void *s1, const void *s2, size_t n);
 *   int timingsafe_bcmp(const void *b1, const void *b2, size_t n);
 *
 *   void bzero(void *dst, size_t n);
 *   void *memset(void *s, int c, size_t n);
 *   int memset_s(void *s, size_t smax, int c, size_t n);
 *
 *   void bcopy(const void *src, void *dst, size_t n);
 *   void *memcpy(void *dst, const void *src, size_t n);
 *   void *memove(void *dst, const void *src, size_t n);
 *
 *
 * String functions
 *
 *   size_t strlen(const char *s);
 *   size_t strnlen(const char *s, size_t n);
 *
 *   int strcmp(const char *s1, const char *s2);
 *   int strncmp(const char *s1, const char *s2, size_t n);
 *   int strlcmp(const char *s1, const char *s2, size_t n);
 *   int strbufcmp(const char *s1, size_t n1, const char *s2, size_t n2);
 *   int strprefix(const char *s1, const char *s2);
 *   int strcasecmp(const char *s1, const char *s2);
 *   int strncasecmp(const char *s1, const char *s2, size_t n);
 *   int strlcasecmp(const char *s1, const char *s2, size_t n);
 *   int strbufcasecmp(const char *s1, size_t n1, const char *s2, size_t n2);
 *
 *   char *strchr(const char *s, int c);
 *   char *strrchr(const char *s, int c);
 *   char *strnstr(const char *s, const char *find, size_t slen);
 *
 *   size_t strlcpy(char *dst, const char *src, size_t n);
 *   const char *strbufcpy(char *dst, size_t dstlen, const char *src, size_t srclen);
 *   size_t strlcat(char *dst, const char *src, size_t n);
 *   const char *strbufcat(char *dst, size_t dstlen, const char *src, size_t srclen);
 */


#pragma mark _FORTIFY_SOURCE helpers

/*
 * _FORTIFY_SOURCE > 0 will enable checked memory/string functions.
 *
 * _FORTIFY_SOURCE_STRICT will enable stricter checking (optional)
 * for memcpy/memmove/bcopy and will check that copies do not go
 * past the end of a struct member.
 */
#if KASAN
#  define __XNU_FORTIFY_SOURCE          0 /* kasan is a superset */
#elif defined (_FORTIFY_SOURCE) && _FORTIFY_SOURCE == 0
#  define __XNU_FORTIFY_SOURCE          0 /* forcefully disabled */
#elif XNU_KERNEL_PRIVATE || defined(_FORTIFY_SOURCE_STRICT)
#  define __XNU_FORTIFY_SOURCE          2
#else
#  define __XNU_FORTIFY_SOURCE          1
#endif

/*
 * The overloadable attribute is load bearing in two major ways:
 * - __builtin_${function} from ${function} would be infinite recursion and UB,
 * - we need to still expose the regular prototype for people wanting to take
 *   its address.
 */
#define __xnu_string_inline \
	static inline __attribute__((__always_inline__, __overloadable__))

/*
 * We want to allow certain functions like strlen() to constant fold
 * at compile time (such as strlen("foo")).
 *
 * In order to do so, we need an overload that has a similar looking
 * signature but is different from the regular function so that it can
 * call its matching builtin without causing UB due to inifinite recursion.
 * We abuse that the pass_object_size class of attributes gives us
 * precisely that semantics.
 */
#define __xnu_force_overload            __xnu_pass_object_size

/*
 * The object_size extension defines two kinds of size: the "struct size" and
 * the "member size". The "struct size" is the size of the buffer from the
 * starting address to the end of the largest enclosing object. The "member
 * size" is the size of the buffer from the starting address to the end of the
 * immediately enclosing array. For instance, given this:
 *
 *  struct foo {
 *      char a[20];
 *      char b[20];
 *  } my_foo;
 *
 * The "struct size" for &my_foo.a[10] is 30 (`sizeof(struct foo) -
 * offsetof(struct foo, a[10])`), and the "member size" for it is 10
 * (`sizeof(my_foo.a) - 10`).
 *
 * In general, you should use the member size for string operations (as it is
 * always a mistake to go out of bounds of a char buffer with a string
 * operation) and the struct size for bytewise operations (like bcopy, bzero,
 * memset, etc). The object_size extension is intended to provide _some_ bounds
 * safety at a low engineering cost, and various patterns intentionally
 * overflowing from individual fields with bytewise operations have
 * historically been tolerated both by engineers and the compiler (despite
 * probably being undefined).
 *
 * As an important side note, -fbounds-safety does not allow naïvely
 * overflowing from individual fields. -fbounds-safety bounds checks are always
 * equivalent to checks against the member size.
 */

#if __has_builtin(__builtin_dynamic_object_size)
#  define __xnu_pass_struct_size        __attribute__((__pass_dynamic_object_size__(0)))
#  define __xnu_pass_member_size        __attribute__((__pass_dynamic_object_size__(1)))
#  define __xnu_struct_size(ptr)        __builtin_dynamic_object_size(ptr, 0)
#  define __xnu_member_size(ptr)        __builtin_dynamic_object_size(ptr, 1)
#else
#  define __xnu_pass_struct_size        __attribute__((__pass_object_size__(0)))
#  define __xnu_pass_member_size        __attribute__((__pass_object_size__(1)))
#  define __xnu_struct_size(ptr)        __builtin_object_size(ptr, 0)
#  define __xnu_member_size(ptr)        __builtin_object_size(ptr, 1)
#endif

#if __XNU_FORTIFY_SOURCE == 0 || !__has_attribute(diagnose_if)
#  define __xnu_struct_size_precondition(ptr, size, message)
#  define __xnu_member_size_precondition(ptr, size, message)
#else
#  define __xnu_struct_size_precondition(ptr, size, message) \
	__attribute__((__diagnose_if__(__xnu_struct_size(ptr) < (size), message, "error")))
#  define __xnu_member_size_precondition(ptr, size, message) \
	__attribute__((__diagnose_if__(__xnu_member_size(ptr) < (size), message, "error")))
#endif


#if __XNU_FORTIFY_SOURCE > 1
#  define __xnu_object_size_precondition(...) \
	__xnu_member_size_precondition(__VA_ARGS__)
#  define __xnu_object_size_check(...) \
	__xnu_member_size_check(__VA_ARGS__)
#  define __xnu_pass_object_size        __xnu_pass_member_size
#else
#  define __xnu_object_size_precondition(...) \
	__xnu_struct_size_precondition(__VA_ARGS__)
#  define __xnu_object_size_check(...) \
	__xnu_struct_size_check(__VA_ARGS__)
#  define __xnu_pass_object_size        __xnu_pass_struct_size
#endif

#if __XNU_FORTIFY_SOURCE == 0 || __has_ptrcheck
#define __xnu_struct_size_check(ptr, size)   ((void)0)
#define __xnu_member_size_check(ptr, size)   ((void)0)
#else
__xnu_string_inline __cold __dead2 void
__xnu_fortify_trap_write(void)
{
	ml_fatal_trap(0xbffe); /* XNU_HARD_TRAP_STRING_CHK */
}

__xnu_string_inline __cold void
__xnu_fortify_trap_read(void)
{
	/* for now do not emit read traps yet */
#if 0
	ml_recoverable_trap(0xfffe); /* XNU_SOFT_TRAP_STRING_CHK */
#endif
}

#define __xnu_fortify_trap(ptr)  _Generic(ptr, \
	const char *: __xnu_fortify_trap_read(),                                \
	const void *: __xnu_fortify_trap_read(),                                \
	default:      __xnu_fortify_trap_write())

#define __xnu_struct_size_check(ptr, size)  ({ \
	if (__xnu_struct_size(ptr) < (size)) {                                  \
	        __xnu_fortify_trap(ptr);                                        \
	}                                                                       \
})
#define __xnu_member_size_check(ptr, size)  ({ \
	if (__xnu_member_size(ptr) < (size)) {                                  \
	        __xnu_fortify_trap(ptr);                                        \
	}                                                                       \
})
#endif

/*
 * Verifies at compile-time that an expression is an array (of any type).
 */
#if __has_builtin(__builtin_types_compatible_p)
#define __xnu_is_array(A) __builtin_types_compatible_p(typeof((A)[0])[], typeof(A))
#else
#define __xnu_is_array(A) 1
#endif
#define __xnu_assert_is_array(A, MSG) _Static_assert(__xnu_is_array(A), MSG)

#define __xnu_count_args1(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, N, ...) N
#define __xnu_count_args(...) \
	__xnu_count_args1(, ##__VA_ARGS__, _9, _8, _7, _6, _5, _4, _3, _2, _1, _0)

#define __xnu_argc_overload1(base, N, ...) __CONCAT(base, N)(__VA_ARGS__)
#define __xnu_argc_overload(base, ...) \
	__xnu_argc_overload1(base, __xnu_count_args(__VA_ARGS__), ##__VA_ARGS__)

#pragma mark memory functions


extern int bcmp(const void *s1 __sized_by(n), const void *s2 __sized_by(n), size_t n) __stateful_pure;

__xnu_string_inline __stateful_pure
int
bcmp(
	const void *const       s1 __xnu_pass_struct_size __sized_by(n),
	const void *const       s2 __xnu_pass_struct_size __sized_by(n),
	size_t                  n)
__xnu_struct_size_precondition(s1, n, "read overflow (first argument)")
__xnu_struct_size_precondition(s2, n, "read overflow (second argument)")
{
	extern int __xnu_bcmp(
		const void * __sized_by(n),
		const void * __sized_by(n),
		size_t n) __asm("_bcmp");

	__xnu_struct_size_check(s1, n);
	__xnu_struct_size_check(s2, n);
#if __has_builtin(__builtin_bcmp)
	return __builtin_bcmp(s1, s2, n);
#else
	return __xnu_bcmp(s1, s2, n);
#endif
}


extern int memcmp(const void *s1 __sized_by(n), const void *s2 __sized_by(n), size_t n) __stateful_pure;

__xnu_string_inline __stateful_pure
int
memcmp(
	const void *const       s1 __xnu_pass_struct_size __sized_by(n),
	const void *const       s2 __xnu_pass_struct_size __sized_by(n),
	size_t                  n)
__xnu_struct_size_precondition(s1, n, "read overflow (first argument)")
__xnu_struct_size_precondition(s2, n, "read overflow (second argument)")
{
	extern int __xnu_memcmp(
		const void *__sized_by(n),
		const void *__sized_by(n),
		size_t n) __asm("_memcmp");

	__xnu_struct_size_check(s1, n);
	__xnu_struct_size_check(s2, n);
#if __has_builtin(__builtin_memcmp)
	return __builtin_memcmp(s1, s2, n);
#else
	return __xnu_memcmp(s1, s2, n);
#endif
}


#ifdef XNU_KERNEL_PRIVATE
/*
 * memcmp_zero_ptr_aligned() checks string s of n bytes contains all zeros.
 * Address and size of the string s must be pointer-aligned.
 * Return 0 if true, 1 otherwise. Also return 0 if n is 0.
 */
extern unsigned long memcmp_zero_ptr_aligned(const void *s __sized_by(n), size_t n) __stateful_pure;
#endif


extern int timingsafe_bcmp(const void *b1 __sized_by(n), const void *b2 __sized_by(n), size_t n);


extern void bzero(void *s __sized_by(n), size_t n);

__xnu_string_inline
void
bzero(
	void *const             s __xnu_pass_struct_size __sized_by(n),
	size_t                  n)
__xnu_struct_size_precondition(s, n, "write overflow")
{
	extern void __xnu_bzero(
		const void *__sized_by(n),
		size_t n) __asm("_bzero");

	__xnu_struct_size_check(s, n);
#if __has_builtin(__builtin_bzero)
	__builtin_bzero(s, n);
#else
	__xnu_bzero(s, n);
#endif
}


extern void *memset(void *s __sized_by(n), int c, size_t n);

__xnu_string_inline
void *
__sized_by(n)
memset(
	void *const             s __xnu_pass_object_size __sized_by(n),
	int                     c,
	size_t                  n)
__xnu_object_size_precondition(s, n, "write overflow")
{
	extern void __xnu_memset(
		void *__sized_by(n),
		int,
		size_t n) __asm("_memset");

	__xnu_object_size_check(s, n);
#if __has_builtin(__builtin_memset)
	return __builtin_memset(s, c, n);
#else
	return __xnu_memset(s, c, n);
#endif
}


extern int memset_s(void *s __sized_by(smax), size_t smax, int c, size_t n);


extern void *memmove(void *dst __sized_by(n), const void *src __sized_by(n), size_t n);

__xnu_string_inline
void *
__sized_by(n)
memmove(
	void *const             dst __xnu_pass_object_size __sized_by(n),
	const void *const       src __xnu_pass_object_size __sized_by(n),
	size_t                  n)
__xnu_object_size_precondition(dst, n, "write overflow")
__xnu_object_size_precondition(src, n, "read overflow")
{
	extern void *__xnu_memmove(
		void *dst __sized_by(n),
		const void *src __sized_by(n),
		size_t n) __asm("_memmove");

	__xnu_object_size_check(dst, n);
	__xnu_object_size_check(src, n);
#if __has_builtin(__builtin_memmove)
	return __builtin_memmove(dst, src, n);
#else
	return __xnu_memmove(dst, src, n);
#endif
}

__xnu_string_inline
void *
__sized_by(n)
__nochk_memmove(
	void *const             dst __xnu_pass_struct_size __sized_by(n),
	const void *const       src __xnu_pass_struct_size __sized_by(n),
	size_t                  n)
__xnu_struct_size_precondition(dst, n, "write overflow")
__xnu_struct_size_precondition(src, n, "read overflow")
{
	extern void *__xnu_memmove(
		void *dst __sized_by(n),
		const void *src __sized_by(n),
		size_t n) __asm("_memmove");

	__xnu_struct_size_check(dst, n);
	__xnu_struct_size_check(src, n);
#if __has_builtin(__builtin_memmove)
	return __builtin_memmove(dst, src, n);
#else
	return __xnu_memmove(dst, src, n);
#endif
}


extern void bcopy(const void *src __sized_by(n), void *dst __sized_by(n), size_t n);

__xnu_string_inline
void
bcopy(
	const void *const       src __xnu_pass_object_size __sized_by(n),
	void *const             dst __xnu_pass_object_size __sized_by(n),
	size_t                  n)
__xnu_struct_size_precondition(dst, n, "write overflow")
__xnu_struct_size_precondition(src, n, "read overflow")
{
	(void)memmove(dst, src, n);
}

__xnu_string_inline
void
__nochk_bcopy(
	const void *const       src __xnu_pass_struct_size __sized_by(n),
	void *const             dst __xnu_pass_struct_size __sized_by(n),
	size_t                  n)
__xnu_struct_size_precondition(dst, n, "write overflow")
__xnu_struct_size_precondition(src, n, "read overflow")
{
	(void)__nochk_memmove(dst, src, n);
}


extern void *memcpy(void *dst __sized_by(n), const void *src __sized_by(n), size_t n);

__xnu_string_inline
void *
__sized_by(n)
memcpy(
	void *const             dst __xnu_pass_object_size __sized_by(n),
	const void *const       src __xnu_pass_object_size __sized_by(n),
	size_t                  n)
__xnu_struct_size_precondition(dst, n, "write overflow")
__xnu_struct_size_precondition(src, n, "read overflow")
{
	return memmove(dst, src, n);
}

__xnu_string_inline
void *
__sized_by(n)
__nochk_memcpy(
	void *const             dst __xnu_pass_struct_size __sized_by(n),
	const void *const       src __xnu_pass_struct_size __sized_by(n),
	size_t                  n)
__xnu_struct_size_precondition(dst, n, "write overflow")
__xnu_struct_size_precondition(src, n, "read overflow")
{
	return __nochk_memmove(dst, src, n);
}


#pragma mark string functions

extern size_t strlen(const char *__null_terminated s) __stateful_pure;

#if __has_builtin(__builtin_strlen)
__xnu_string_inline __stateful_pure
size_t
strlen(const char * /* __null_terminated */ const s __xnu_force_overload)
{
	return __builtin_strlen(s);
}
#endif


extern size_t strnlen(const char *__counted_by(n)s, size_t n) __stateful_pure;

#if __has_builtin(__builtin_strnlen)
__xnu_string_inline __stateful_pure
size_t
strnlen(const char *const __counted_by(n) s __xnu_force_overload, size_t n)
{
	return __builtin_strnlen(s, n);
}
#endif


/* strbuflen is the same as strnlen. */
#define strbuflen_1(BUF) ({ \
	__xnu_assert_is_array(BUF, "argument is not an array"); \
	strnlen((BUF), sizeof(BUF)); \
})
#define strbuflen_2(BUF, LEN) strnlen(BUF, LEN)
#define strbuflen(...) __xnu_argc_overload(strbuflen, __VA_ARGS__)


extern int strcmp(const char *__null_terminated s1, const char *__null_terminated s2) __stateful_pure;

#if __has_builtin(__builtin_strcmp)
__xnu_string_inline __stateful_pure
int
strcmp(
	const char *const /* __null_terminated */ s1 __xnu_force_overload,
	const char *const __null_terminated s2)
{
	return __builtin_strcmp(s1, s2);
}
#else
#endif


__ptrcheck_unavailable_r("strlcmp or strbufcmp")
extern int strncmp(const char *__unsafe_indexable s1, const char *__unsafe_indexable s2, size_t n) __stateful_pure;

#if __has_builtin(__builtin_strncmp)
__ptrcheck_unavailable_r("strlcmp or strbufcmp")
__xnu_string_inline __stateful_pure
int
strncmp(
	const char *const __unsafe_indexable s1 __xnu_force_overload,
	const char *const __unsafe_indexable s2, size_t n)
{
	return __builtin_strncmp(s1, s2, n);
}
#endif

/*
 * Use strlcmp if you want to compare one string with a known length (with or
 * without a NUL terminator) and one string with an unknown length (that always
 * has a NUL terminator).
 * See docs/primitives/string-handling.md for more information.
 */
extern int strlcmp(const char *__counted_by(n)s1, const char *s2, size_t n) __stateful_pure;

#if __has_builtin(__builtin_strncmp)
__xnu_string_inline __stateful_pure
int
strlcmp(
	const char *const __counted_by(s1len) s1 __xnu_force_overload,
	const char *const s2, size_t s1len)
__xnu_member_size_precondition(s1, s1len, "read overflow")
{
	extern int __xnu_strlcmp(
		const char * __counted_by(s1len) s1,
		const char *__null_terminated s2,
		size_t s1len) __asm("_strlcmp");

	__xnu_member_size_check(s1, s1len);
	return __xnu_strlcmp(s1, s2, s1len);
}
#endif


/*
 * Use strbufcmp if you want to compare two strings and you know both of their
 * lengths. See docs/primitives/string-handling.md for more information.
 */
extern int strbufcmp(const char *__counted_by(s1len)s1, size_t s1len, const char *__counted_by(s2len)s2, size_t s2len) __stateful_pure;

__xnu_string_inline __stateful_pure
int
strbufcmp(
	const char *const __counted_by(s1len) s1 __xnu_pass_member_size, size_t s1len,
	const char *const __counted_by(s2len) s2 __xnu_pass_member_size, size_t s2len)
__xnu_member_size_precondition(s1, s1len, "read overflow")
__xnu_member_size_precondition(s2, s2len, "read overflow")
{
	extern int __xnu_strbufcmp(
		const char * __counted_by(s1len) s1,
		size_t s1len,
		const char *__counted_by(s2len) s2,
		size_t s2len) __asm("_strbufcmp");

	__xnu_member_size_check(s1, s1len);
	__xnu_member_size_check(s2, s2len);
	return __xnu_strbufcmp(s1, s1len, s2, s2len);
}

#define strbufcmp_2(A, B) ({ \
	__xnu_assert_is_array(A, "first argument is not an array"); \
	__xnu_assert_is_array(B, "second argument is not an array"); \
	(strbufcmp)((A), sizeof(A), (B), sizeof(B)); \
})
#define strbufcmp_4 (strbufcmp)
#define strbufcmp(...) __xnu_argc_overload(strbufcmp, __VA_ARGS__)


extern int strprefix(const char *__null_terminated s1, const char *__null_terminated s2) __stateful_pure;


extern int strcasecmp(const char *__null_terminated s1, const char *__null_terminated s2) __stateful_pure;

#if __has_builtin(__builtin_strcasecmp)
__xnu_string_inline __stateful_pure
int
strcasecmp(
	const char *const /* __null_terminated */ s1 __xnu_force_overload,
	const char *const __null_terminated s2)
{
	return __builtin_strcasecmp(s1, s2);
}
#endif


__ptrcheck_unavailable_r("strlcasecmp or strbufcasecmp")
extern int strncasecmp(const char *__unsafe_indexable s1, const char *__unsafe_indexable s2, size_t n) __stateful_pure;

#if __has_builtin(__builtin_strncasecmp)
__ptrcheck_unavailable_r("strlcasecmp or strbufcasecmp")
__xnu_string_inline __stateful_pure
int
strncasecmp(
	const char *const __unsafe_indexable s1 __xnu_force_overload,
	const char *const __unsafe_indexable s2, size_t n)
{
	return __builtin_strncasecmp(s1, s2, n);
}
#endif

/*
 * Use strlcasecmp if you want to compare one string with a known length (with
 * or without a NUL terminator) and one string with an unknown length (that
 * always has a NUL terminator).
 * See docs/primitives/string-handling.md for more information.
 */
extern int strlcasecmp(const char *__counted_by(n)s1, const char *s2, size_t n) __stateful_pure;

__xnu_string_inline __stateful_pure
int
strlcasecmp(
	const char *const __counted_by(s1len) s1 __xnu_force_overload,
	const char *__null_terminated const s2, size_t s1len)
__xnu_member_size_precondition(s1, s1len, "read overflow")
{
	extern int __xnu_strlcasecmp(
		const char * __counted_by(s1len) s1,
		const char *__null_terminated s2,
		size_t s1len) __asm("_strlcasecmp");

	__xnu_member_size_check(s1, s1len);
	return __xnu_strlcasecmp(s1, s2, s1len);
}


/*
 * Use strbufcmp if you want to compare two strings and you know both of their
 * lengths. See docs/primitives/string-handling.md for more information.
 */
extern int strbufcasecmp(const char *__counted_by(s1len)s1, size_t s1len, const char *__counted_by(s2len)s2, size_t s2len) __stateful_pure;

__xnu_string_inline __stateful_pure
int
strbufcasecmp(
	const char *const __counted_by(s1len) s1 __xnu_pass_member_size, size_t s1len,
	const char *const __counted_by(s2len) s2 __xnu_pass_member_size, size_t s2len)
__xnu_member_size_precondition(s1, s1len, "read overflow")
__xnu_member_size_precondition(s2, s2len, "read overflow")
{
	extern int __xnu_strbufcasecmp(
		const char * __counted_by(s1len) s1,
		size_t s1len,
		const char *__counted_by(s2len) s2,
		size_t s2len) __asm("_strbufcasecmp");

	__xnu_member_size_check(s1, s1len);
	__xnu_member_size_check(s2, s2len);
	return __xnu_strbufcasecmp(s1, s1len, s2, s2len);
}

#define strbufcasecmp_2(A, B) ({ \
	__xnu_assert_is_array(A, "first argument is not an array"); \
	__xnu_assert_is_array(B, "second argument is not an array"); \
	(strbufcasecmp)((A), sizeof(A), (B), sizeof(B)); \
})
#define strbufcasecmp_4 (strbufcasecmp)
#define strbufcasecmp(...) __xnu_argc_overload(strbufcasecmp, __VA_ARGS__)


#if __has_builtin(__builtin_strchr)
__xnu_string_inline
char *__null_terminated
strchr(const char *const /* __null_terminated */ s __xnu_force_overload, int c)
{
	return __unsafe_forge_null_terminated(char *, __builtin_strchr(s, c));
}
#endif


#if XNU_KERNEL_PRIVATE /* rdar://103276672 */
extern char *__null_terminated strrchr(const char *__null_terminated s, int c) __stateful_pure;

#if __has_builtin(__builtin_strrchr) && !__has_ptrcheck /* rdar://103265304 */
__xnu_string_inline
char *__null_terminated
strrchr(const char *const __null_terminated s __xnu_force_overload, int c)
{
	return __builtin_strrchr(s, c);
}
#endif
#endif


extern char *__null_terminated strnstr(const char *__null_terminated s, const char *__null_terminated find, size_t slen) __stateful_pure;


extern size_t strlcpy(char *__counted_by(n) dst, const char *__null_terminated src, size_t n);

__xnu_string_inline
size_t
strlcpy(
	char *const             dst __xnu_pass_member_size __counted_by(n),
	const char *const       src __null_terminated,
	size_t                  n)
__xnu_member_size_precondition(dst, n, "write overflow")
{
	extern size_t __xnu_strlcpy(
		char * __counted_by(n),
		const char *__null_terminated,
		size_t n) __asm("_strlcpy");

	__xnu_member_size_check(dst, n);
#if __has_builtin(__builtin_strlcpy)
	return __builtin_strlcpy(dst, src, n);
#else
	return __xnu_strlcpy(dst, src, n);
#endif
}


/*
 * strbufcpy returns its destination as a NUL-terminated string, which makes a
 * difference when -fbounds-safety is enabled.
 * See docs/primitives/string-handling.md for more information.
 */
extern const char *__null_terminated
    strbufcpy(
	char *__counted_by(dstsz) dst,
	size_t dstsz,
	const char *__counted_by(srcsz) src,
	size_t srcsz);

__xnu_string_inline
const char *
strbufcpy(
	char *const             dst __xnu_pass_member_size __counted_by(dstsz),
	size_t                  dstsz,
	const char *const       src __xnu_pass_member_size __counted_by(srcsz),
	size_t                  srcsz)
__xnu_member_size_precondition(dst, dstsz, "write overflow")
__xnu_member_size_precondition(src, srcsz, "read overflow")
{
	extern const char *__xnu_strbufcpy(
		char *__counted_by(dstsz) dst,
		size_t dstsz,
		const char *__counted_by(srcsz) src,
		size_t srcsz) __asm("_strbufcpy");

	__xnu_member_size_check(dst, dstsz);
	__xnu_member_size_check(src, srcsz);
	return __xnu_strbufcpy(dst, dstsz, src, srcsz);
}

#define strbufcpy_2(DST, SRC) ({ \
	__xnu_assert_is_array(DST, "dst is not an array"); \
	__xnu_assert_is_array(SRC, "src is not an array"); \
	(strbufcpy)((DST), sizeof(DST), (SRC), sizeof(SRC)); \
})
#define strbufcpy_4     (strbufcpy)
#define strbufcpy(...)  __xnu_argc_overload(strbufcpy, __VA_ARGS__)

extern size_t strlcat(char *__counted_by(n) dst, const char *__null_terminated src, size_t n);

__xnu_string_inline
size_t
strlcat(
	char *const             dst __xnu_pass_member_size __counted_by(n),
	const char *const       src __null_terminated,
	size_t                  n)
__xnu_member_size_precondition(dst, n, "write overflow")
{
	extern size_t __xnu_strlcat(
		char * __sized_by(n),
		const char *__null_terminated,
		size_t n) __asm("_strlcat");

	__xnu_member_size_check(dst, n);
#if __has_builtin(__builtin_strlcat)
	return __builtin_strlcat(dst, src, n);
#else
	return __xnu_strlcat(dst, src, n);
#endif
}


/*
 * strbufcat returns its destination as a NUL-terminated string, which makes a
 * difference when -fbounds-safety is enabled.
 * See docs/primitives/string-handling.md for more information.
 */
extern const char *__null_terminated
    strbufcat(
	char *__counted_by(dstsz) dst,
	size_t dstsz,
	const char *__counted_by(srcsz) src,
	size_t srcsz);

__xnu_string_inline
const char *
strbufcat(
	char *const             dst __xnu_pass_member_size __counted_by(dstsz),
	size_t                  dstsz,
	const char *const       src __xnu_pass_member_size __counted_by(srcsz),
	size_t                  srcsz)
__xnu_member_size_precondition(dst, dstsz, "write overflow")
__xnu_member_size_precondition(src, srcsz, "read overflow")
{
	extern const char *__xnu_strbufcat(
		char *__counted_by(dstsz) dst,
		size_t dstsz,
		const char *__counted_by(srcsz) src,
		size_t srcsz) __asm("_strbufcat");

	__xnu_member_size_check(dst, dstsz);
	__xnu_member_size_check(src, srcsz);
	return __xnu_strbufcat(dst, dstsz, src, srcsz);
}

#define strbufcat_2(DST, SRC) ({ \
	__xnu_assert_is_array(DST, "dst is not an array"); \
	__xnu_assert_is_array(SRC, "src is not an array"); \
	(strbufcat)((DST), sizeof(DST), (SRC), sizeof(SRC)); \
})
#define strbufcat_4     (strbufcat)
#define strbufcat(...) __xnu_argc_overload(strbufcat, __VA_ARGS__)

#pragma mark deprecated functions
#if !__has_ptrcheck && !__has_include(<__xnu_libcxx_sentinel.h>)

/*
 * char *strncat(char *dst, const char *src, size_t n);
 * char *strncpy(char *dst, const char *src, size_t n);
 *
 * char *strcat(char *dst, const char *src);
 * char *strcpy(char *, const char *);
 *
 * char *STRDUP(const char *, int);
 */

__deprecated_msg("use strlcat")
__kpi_deprecated_arm64_macos_unavailable
extern char *strncat(char *dst, const char *src, size_t n);
#if __XNU_FORTIFY_SOURCE && __has_builtin(__builtin___strncat_chk)
#define strncat(dst, src, n)            __builtin___strncat_chk(dst, src, n, __xnu_member_size(dst))
#endif


__deprecated_msg("use strlcpy")
__kpi_deprecated_arm64_macos_unavailable
extern char *strncpy(char *dst, const char *src, size_t n);
#if __XNU_FORTIFY_SOURCE && __has_builtin(__builtin___strncpy_chk)
#define strncpy(dst, src, n)            __builtin___strncpy_chk(dst, src, n, __xnu_member_size(dst))
#endif

__deprecated_msg("use strlcpy")
__kpi_deprecated_arm64_macos_unavailable
extern char *strcpy(char *, const char *);
#if __XNU_FORTIFY_SOURCE && __has_builtin(__builtin___strcpy_chk)
/* rdar://103287225 */
#define strcpy(dst, src, len)           __builtin___strcpy_chk(dst, src, __xnu_member_size(dst))
#endif

__deprecated_msg("use strlcat")
__kpi_deprecated_arm64_macos_unavailable
extern char *strcat(char *dst, const char *src);
#if __XNU_FORTIFY_SOURCE && __has_builtin(__builtin___strcat_chk)
#define strcat(dst, src)                __builtin___strcat_chk(dst, src, __xnu_member_size(dst))
#endif

#if XNU_PLATFORM_MacOSX
#ifndef KERNEL_PRIVATE
extern char *STRDUP(const char *, int);
#endif
#endif /* XNU_PLATFORM_MacOSX */

#endif /* !__has_ptrcheck && !__has_include(<__xnu_libcxx_sentinel.h>) */

#if __has_include(<san/memintrinsics.h>)
#include <san/memintrinsics.h>
#endif

__END_DECLS

#endif  /* _STRING_H_ */

#endif
