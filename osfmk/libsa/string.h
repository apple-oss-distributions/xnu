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
#ifndef _STRING_H_
#define _STRING_H_      1

#ifdef MACH_KERNEL_PRIVATE
#include <types.h>
#else
#include <sys/types.h>
#endif
#include <sys/cdefs.h>

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
 *   int memset_s(void *s __sized_by(smax), size_t smax, int c, size_t n);
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
 *   int strprefix(const char *s1, const char *s2) __stateful_pure;
 *   int strcasecmp(const char *s1, const char *s2);
 *   int strncasecmp(const char *s1, const char *s2, size_t n);
 *
 *   char *strchr(const char *s, int c);
 *   char *strrchr(const char *s, int c);
 *   char *strnstr(const char *s, const char *find, size_t slen);
 *
 *   size_t strlcpy(char *dst, const char *src, size_t n);
 *   size_t strlcat(char *dst, const char *src, size_t n);
 */


/*
 * _FORTIFY_SOURCE > 0 will enable checked memory/string functions.
 *
 * _FORTIFY_SOURCE_STRICT will enable stricter checking (optional)
 * for memcpy/memmove/bcopy and will check that copies do not go
 * past the end of a struct member.
 */
#if KASAN
#  define XNU_USE_CHK_BUILTIN(n)        0
#  define XNU_USE_STRING_BUILTIN(n)     0
#elif defined (_FORTIFY_SOURCE) && _FORTIFY_SOURCE == 0
#  define XNU_USE_CHK_BUILTIN(n)        0
#  define XNU_USE_STRING_BUILTIN(n)     __has_builtin(__builtin_##n)
#elif __has_ptrcheck
#  define XNU_USE_CHK_BUILTIN(n)        0
#  define XNU_USE_STRING_BUILTIN(n)     __has_builtin(__builtin_##n)
#elif defined(__cplusplus) && __has_include(<__xnu_libcxx_sentinel.h>)
#  define XNU_USE_CHK_BUILTIN(n)        0
#  define XNU_USE_STRING_BUILTIN(n)     0
#elif XNU_KERNEL_PRIVATE || defined(_FORTIFY_SOURCE_STRICT)
#  define XNU_USE_CHK_BUILTIN(n)        __has_builtin(__builtin___##n##_chk)
#  define XNU_USE_STRING_BUILTIN(n)     __has_builtin(__builtin_##n)
#  define __xnu_bos_default(ptr)        __xnu_bos_strict(ptr)
#else
#  define XNU_USE_CHK_BUILTIN(n)        __has_builtin(__builtin___##n##_chk)
#  define XNU_USE_STRING_BUILTIN(n)     __has_builtin(__builtin_##n)
#  define __xnu_bos_default(ptr)        __xnu_bos_loose(ptr)
#endif

#if __has_builtin(__builtin_dynamic_object_size)
#  define __xnu_bos_loose(ptr)          __builtin_dynamic_object_size(ptr, 0)
#  define __xnu_bos_strict(ptr)         __builtin_dynamic_object_size(ptr, 1)
#else
#  define __xnu_bos_loose(ptr)          __builtin_object_size(ptr, 0)
#  define __xnu_bos_strict(ptr)         __builtin_object_size(ptr, 1)
#endif


#pragma mark memory functions

extern int bcmp(const void *s1 __sized_by(n), const void *s2 __sized_by(n), size_t n) __stateful_pure;
#if XNU_USE_STRING_BUILTIN(bcmp)
#define bcmp(s1, s2, n)                 __builtin_bcmp(s1, s2, n)
#endif


extern int memcmp(const void *s1 __sized_by(n), const void *s2 __sized_by(n), size_t n) __stateful_pure;
#if XNU_USE_STRING_BUILTIN(memcmp)
#define memcmp(s1, s2, n)               __builtin_memcmp(s1, s2, n)
#endif


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
#if XNU_USE_STRING_BUILTIN(bzero)
#define bzero(s, n)                     __builtin_bzero(s, n)
#endif


extern void *memset(void *s __sized_by(n), int c, size_t n);
#if XNU_USE_CHK_BUILTIN(memset) && XNU_KERNEL_PRIVATE /* rdar://103270898&103281379 */
#define memset(s, c, n)                 __builtin___memset_chk(s, c, n, __xnu_bos_default(s))
#elif XNU_USE_STRING_BUILTIN(memset) && XNU_KERNEL_PRIVATE
#define memset(s, c, n)                 __builtin_memset(s, c, n)
#endif


extern int memset_s(void *s __sized_by(smax), size_t smax, int c, size_t n);


extern void *memcpy(void *dst __sized_by(n), const void *src __sized_by(n), size_t n);
#if XNU_USE_CHK_BUILTIN(memcpy)
#define memcpy(dst, src, n)             __builtin___memcpy_chk(dst, src, n, __xnu_bos_default(dst))
#define __nochk_memcpy(dst, src, n)     __builtin___memcpy_chk(dst, src, n, __xnu_bos_loose(dst))
#elif XNU_USE_STRING_BUILTIN(memcpy)
#define memcpy(dst, src, n)             __builtin_memcpy(dst, src, n)
#define __nochk_memcpy(dst, src, n)     memcpy(dst, src, n)
#else
#define __nochk_memcpy(dst, src, n)     memcpy(dst, src, n)
#endif


extern void *memmove(void *dst __sized_by(n), const void *src __sized_by(n), size_t n);
extern void bcopy(const void *src __sized_by(n), void *dst __sized_by(n), size_t n);
#if XNU_USE_CHK_BUILTIN(memmove)
#define memmove(dst, src, n)            __builtin___memmove_chk(dst, src, n, __xnu_bos_default(dst))
#define bcopy(src, dst, n)              __builtin___memmove_chk(dst, src, n, __xnu_bos_default(dst))
#define __nochk_memmove(dst, src, n)    __builtin___memmove_chk(dst, src, n, __xnu_bos_loose(dst))
#define __nochk_bcopy(src, dst, n)      __builtin___memmove_chk(dst, src, n, __xnu_bos_loose(dst))
#elif XNU_USE_STRING_BUILTIN(memmove)
#define memmove(dst, src, n)            __builtin_memmove(dst, src, n)
#define bcopy(src, dst, n)              __builtin_memmove(dst, src, n)
#define __nochk_memmove(dst, src, n)    memmove(dst, src, n)
#define __nochk_bcopy(src, dst, n)      bcopy(src, dst, n)
#else
#define __nochk_memmove(dst, src, n)    memmove(dst, src, n)
#define __nochk_bcopy(src, dst, n)      bcopy(src, dst, n)
#endif /* !XNU_USE_CHK_BUILTIN(memmove) */


#pragma mark string functions

extern size_t strlen(const char *__null_terminated s) __stateful_pure;
#if XNU_USE_STRING_BUILTIN(strlen)
#define strlen(s)                       __builtin_strlen(s)
#endif


extern size_t strnlen(const char *__null_terminated s, size_t n) __stateful_pure;
#if XNU_USE_STRING_BUILTIN(strnlen)
#define strnlen(s, n)                   __builtin_strnlen(s, n)
#endif


extern int strcmp(const char *__null_terminated s1, const char *__null_terminated s2) __stateful_pure;
#if XNU_USE_STRING_BUILTIN(strcmp)
#define strcmp(s1, s2)                  __builtin_strcmp(s1, s2)
#endif


extern int strncmp(const char *__null_terminated s1, const char *__null_terminated s2, size_t n) __stateful_pure;
#if XNU_USE_STRING_BUILTIN(strncmp)
#define strncmp(s1, s2, n)              __builtin_strncmp(s1, s2, n)
#endif


extern int strprefix(const char *__null_terminated s1, const char *__null_terminated s2) __stateful_pure;


extern int strcasecmp(const char *__null_terminated s1, const char *__null_terminated s2) __stateful_pure;
#if XNU_USE_STRING_BUILTIN(strcasecmp)
#define strcasecmp(s1, s2)              __builtin_strcasecmp(s1, s2)
#endif


extern int strncasecmp(const char *__null_terminated s1, const char *__null_terminated s2, size_t n) __stateful_pure;
#if XNU_USE_STRING_BUILTIN(strncasecmp)
#define strncasecmp(s1, s2, n)          __builtin_strncasecmp(s1, s2, n)
#endif


extern char *__null_terminated strchr(const char *__null_terminated s, int c) __stateful_pure;
#if XNU_USE_STRING_BUILTIN(strchr) && !__has_ptrcheck /* rdar://103265304 */
#define strchr(s, c)                    __builtin_strchr(s, c)
#endif


#if XNU_KERNEL_PRIVATE /* rdar://103276672 */
extern char *__null_terminated strrchr(const char *__null_terminated s, int c) __stateful_pure;
#if XNU_USE_STRING_BUILTIN(strrchr) && !__has_ptrcheck /* rdar://103265304 */
#define strrchr(s, c)                   __builtin_strrchr(s, c)
#endif
#endif


extern char *__null_terminated strnstr(const char *__null_terminated s, const char *__null_terminated find, size_t slen) __stateful_pure;
#if XNU_USE_STRING_BUILTIN(strnstr) && !__has_ptrcheck /* rdar://103265304 */
#define strnstr(s, find, slen)          __builtin_strnstr(s, find, slen)
#endif


extern size_t strlcpy(char *__sized_by(n) dst, const char *__null_terminated src, size_t n);
#if XNU_USE_CHK_BUILTIN(strlcpy)
#define strlcpy(dst, src, n)            __builtin___strlcpy_chk(dst, src, n, __xnu_bos_strict(dst))
#elif XNU_USE_STRING_BUILTIN(strlcpy)
#define strlcpy(dst, src, n)            __builtin_strlcpy(dst, src, n)
#endif


extern size_t strlcat(char *__sized_by(n) dst, const char *__null_terminated src, size_t n);
#if XNU_USE_CHK_BUILTIN(strlcat)
#define strlcat(dst, src, n)            __builtin___strlcat_chk(dst, src, n, __xnu_bos_strict(dst))
#elif XNU_USE_STRING_BUILTIN(strlcat)
#define strlcat(dst, src, n)            __builtin_strlcat(dst, src, n)
#endif


#pragma mark deprecated functions
#if !__has_ptrcheck

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
#if XNU_USE_CHK_BUILTIN(strncat)
#define strncat(dst, src, n)            __builtin___strncat_chk(dst, src, n, __xnu_bos_strict(dst))
#endif


__deprecated_msg("use strlcpy")
__kpi_deprecated_arm64_macos_unavailable
extern char *strncpy(char *dst, const char *src, size_t n);
#if XNU_USE_CHK_BUILTIN(strncpy)
#define strncpy(dst, src, n)            __builtin___strncpy_chk(dst, src, n, __xnu_bos_strict(dst))
#endif

__deprecated_msg("use strlcpy")
__kpi_deprecated_arm64_macos_unavailable
extern char *strcpy(char *, const char *);
#if XNU_USE_CHK_BUILTIN(strcpy)
/* rdar://103287225 */
#define strcpy(dst, src, len)           __builtin___strcpy_chk(dst, src, __xnu_bos_strict(dst))
#endif

__deprecated_msg("use strlcat")
__kpi_deprecated_arm64_macos_unavailable
extern char *strcat(char *dst, const char *src);
#if XNU_USE_CHK_BUILTIN(strcat)
#define strcat(dst, src)                __builtin___strcat_chk(dst, src, __xnu_bos_strict(dst))
#endif

#if XNU_PLATFORM_MacOSX
#ifndef KERNEL_PRIVATE
extern char *STRDUP(const char *, int);
#endif
#endif /* XNU_PLATFORM_MacOSX */

#endif /* !__has_ptrcheck */

#if __has_include(<san/memintrinsics.h>)
#include <san/memintrinsics.h>
#endif

__END_DECLS

#endif  /* _STRING_H_ */
