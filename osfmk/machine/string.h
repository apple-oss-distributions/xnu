/*
 * Copyright (c) 2022 Apple Inc. All rights reserved.
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

#ifndef _MACHINE_STRING_H_
#define _MACHINE_STRING_H_

#include <sys/cdefs.h>
#include <types.h>

#if defined (__i386__) || defined (__x86_64__)
#include "i386/string.h"
#elif defined (__arm__) || defined (__arm64__)
#include "arm/string.h"
#else
#error architecture not supported
#endif

/*
 * Below are prototypes that call into a precise symbol,
 * and prevent the compiler from using a builtin.
 */

/*
 * Memory functions
 */
extern int bcmp_impl(const void *, const void *, size_t) asm("_bcmp");
extern int memcmp_impl(const void *, const void *, size_t) asm("_memcmp");

extern void *bzero_impl(void *, const void *, size_t) asm("_bzero");
extern void *memset_impl(void *, int c, size_t) asm("_memset");

extern void *memcpy_impl(void *, const void *, size_t) asm("_memcpy");
extern void *memmove_impl(void *, const void *, size_t) asm("_memmove");
extern void bcopy_impl(const void *, void *, size_t) asm("_bcopy");

/*
 * String functions
 */
extern size_t strlen_impl(const char *) asm("_strlen");
extern size_t strnlen_impl(const char *s, size_t) asm("_strnlen");

extern int strcmp_impl(const char *, const char *) asm("_strcmp");
extern int strncmp_impl(const char *, const char *, size_t) asm("_strncmp");
extern int strcasecmp_impl(const char *, const char *) asm("_strcasecmp");
extern int strncasecmp_impl(const char *, const char *, size_t) asm("_strncasecmp");

extern char *strchr_impl(const char *, int) asm("_strchr");
extern char *strrchr_impl(const char *, int) asm("_strrchr");
extern char *strnstr_impl(const char *s, const char *, size_t) asm("_strnstr");

extern size_t strlcat_impl(char *, const char *, size_t) asm("_strlcat");
extern size_t strlcpy_impl(char *, const char *, size_t) asm("_strlcpy");

/*
 * Deprecated functions
 */
extern char *strncpy_impl(char *, const char *, size_t) asm("_strncpy");
extern char *strncat_impl(char *, const char *, size_t) asm("_strncat");

#if CONFIG_VSPRINTF
extern char *strcpy_impl(char *, const char *) asm("_strcpy");
extern char *strcat_impl(char *, const char *) asm("_strcat");
#endif

#endif /* _MACHINE_STRING_H_ */
