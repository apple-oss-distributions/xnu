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

#ifdef __cplusplus
extern "C" {
#endif

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

extern void     *memcpy(void *dst __sized_by(n), const void *src __sized_by(n), size_t n);
extern int      memcmp(const void *s1 __sized_by(n), const void *s2 __sized_by(n), size_t n) __stateful_pure;
extern void     *memmove(void *dst __sized_by(n), const void *src __sized_by(n), size_t n);
extern void     *memset(void *s __sized_by(n), int, size_t n);
extern int      memset_s(void *s __sized_by(smax), size_t smax, int c, size_t n);

#ifdef XNU_KERNEL_PRIVATE
/* memcmp_zero_ptr_aligned() checks string s of n bytes contains all zeros.
 * Address and size of the string s must be pointer-aligned.
 * Return 0 if true, 1 otherwise. Also return 0 if n is 0.
 */
extern unsigned long memcmp_zero_ptr_aligned(const void *s __sized_by(n), size_t n) __stateful_pure;
#endif

extern size_t   strlen(const char *) __stateful_pure;
extern size_t   strnlen(const char *, size_t) __stateful_pure;

/* strcpy() and strncpy() are deprecated. Please use strlcpy() instead. */
__kpi_deprecated_arm64_macos_unavailable
extern char     *strcpy(char *, const char *) __deprecated;

__kpi_deprecated_arm64_macos_unavailable
extern char     *strncpy(char *, const char *, size_t);

/* strcat() and strncat() are deprecated. Please use strlcat() instead. */
__kpi_deprecated_arm64_macos_unavailable
extern char     *strcat(char *, const char *) __deprecated;

__kpi_deprecated_arm64_macos_unavailable
extern char     *strncat(char *, const char *, size_t);

extern int      strcmp(const char *, const char *) __stateful_pure;
extern int      strncmp(const char *, const char *, size_t) __stateful_pure;

extern size_t   strlcpy(char *, const char *, size_t);
extern size_t   strlcat(char *, const char *, size_t);

extern int      strcasecmp(const char *s1, const char *s2) __stateful_pure;
extern int      strncasecmp(const char *s1, const char *s2, size_t n) __stateful_pure;
#ifdef XNU_KERNEL_PRIVATE
extern const char     *strnstr(const char *s, const char *find, size_t slen) __stateful_pure;
#else
extern char     *strnstr(const char *s, const char *find, size_t slen) __stateful_pure;
#endif
extern char     *strchr(const char *s, int c) __stateful_pure;
#ifdef XNU_KERNEL_PRIVATE
extern char     *strrchr(const char *s, int c) __stateful_pure;
#endif
extern char     *STRDUP(const char *, int);
extern int      strprefix(const char *s1, const char *s2) __stateful_pure;

extern int      bcmp(const void *s1 __sized_by(n), const void *s2 __sized_by(n), size_t n) __stateful_pure;
extern void     bcopy(const void *src __sized_by(n), void *dst __sized_by(n), size_t n);
extern void     bzero(void *s __sized_by(n), size_t n);
extern int      timingsafe_bcmp(const void *b1 __sized_by(n), const void *b2 __sized_by(n), size_t n);

#ifdef PRIVATE
#include <san/memintrinsics.h>
#endif

#if __has_builtin(__builtin_dynamic_object_size)
#define XNU_BOS __builtin_dynamic_object_size
#else
#define XNU_BOS __builtin_object_size
#endif

/* __nochk_ functions for opting out of type 1 bounds checking */
__attribute__((always_inline)) static inline void *
__nochk_memcpy(void *dest __sized_by(len), const void *src __sized_by(len), size_t len)
{
	return __builtin___memcpy_chk(dest, src, len, XNU_BOS(dest, 0));
}
__attribute__((always_inline)) static inline void *
__nochk_memmove(void *dest __sized_by(len), const void *src __sized_by(len), size_t len)
{
	return __builtin___memmove_chk(dest, src, len, XNU_BOS(dest, 0));
}
__attribute__((always_inline)) static inline void
__nochk_bcopy(const void *src __sized_by(len), void *dest __sized_by(len), size_t len)
{
	__builtin___memmove_chk(dest, src, len, XNU_BOS(dest, 0));
}

#if defined(__MAC_OS_X_VERSION_MIN_REQUIRED) && __MAC_OS_X_VERSION_MIN_REQUIRED < __MAC_10_13
/* older deployment target */
#elif defined(KASAN) || (defined (_FORTIFY_SOURCE) && _FORTIFY_SOURCE == 0)
/* _FORTIFY_SOURCE disabled */
#else /* _chk macros */

#if defined XNU_KERNEL_PRIVATE || defined(_FORTIFY_SOURCE_STRICT)
/* Stricter checking is optional for kexts. When type is set to 1, __builtin_object_size
 * returns the size of the closest surrounding sub-object, which would detect copying past
 * the end of a struct member. */
#define BOS_COPY_TYPE 1
#else
#define BOS_COPY_TYPE 0
#endif

#if __has_builtin(__builtin___memcpy_chk)
#define memcpy(dest, src, len) __builtin___memcpy_chk(dest, src, len, XNU_BOS(dest, BOS_COPY_TYPE))
#endif

#if __has_builtin(__builtin___memmove_chk)
#define memmove(dest, src, len) __builtin___memmove_chk(dest, src, len, XNU_BOS(dest, BOS_COPY_TYPE))
#endif

#if __has_builtin(__builtin___strncpy_chk)
#define strncpy(dest, src, len) __builtin___strncpy_chk(dest, src, len, XNU_BOS(dest, 1))
#endif

#if __has_builtin(__builtin___strncat_chk)
#define strncat(dest, src, len) __builtin___strncat_chk(dest, src, len, XNU_BOS(dest, 1))
#endif

#if __has_builtin(__builtin___strlcat_chk)
#define strlcat(dest, src, len) __builtin___strlcat_chk(dest, src, len, XNU_BOS(dest, 1))
#endif

#if __has_builtin(__builtin___strlcpy_chk)
#define strlcpy(dest, src, len) __builtin___strlcpy_chk(dest, src, len, XNU_BOS(dest, 1))
#endif

#if __has_builtin(__builtin___strcpy_chk)
#define strcpy(dest, src, len) __builtin___strcpy_chk(dest, src, XNU_BOS(dest, 1))
#endif

#if __has_builtin(__builtin___strcat_chk)
#define strcat(dest, src) __builtin___strcat_chk(dest, src, XNU_BOS(dest, 1))
#endif

#if __has_builtin(__builtin___memmove_chk)
#define bcopy(src, dest, len) __builtin___memmove_chk(dest, src, len, XNU_BOS(dest, BOS_COPY_TYPE))
#endif

#if KERNEL_PRIVATE
/*
 * those allow small memsets/bzeros to be reasoned about by the compiler
 * despite using -fno-builtin
 */
#ifndef memset
#define memset(p, c, len) __builtin_memset(p, c, len)
#endif

#ifndef bzero
#define bzero(p, len)     __builtin_bzero(p, len)
#endif
#endif /* KERNEL_PRIVATE */

#endif /* _chk macros */
#ifdef __cplusplus
}
#endif

#endif  /* _STRING_H_ */
