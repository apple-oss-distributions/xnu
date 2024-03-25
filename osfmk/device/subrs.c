/*
 * Copyright (c) 2000-2020 Apple Inc. All rights reserved.
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
 * @OSF_COPYRIGHT@
 */
/*
 *(C)UNIX System Laboratories, Inc. all or some portions of this file are
 * derived from material licensed to the University of California by
 * American Telephone and Telegraph Co. or UNIX System Laboratories,
 * Inc. and are reproduced herein with the permission of UNIX System
 * Laboratories, Inc.
 */

/*
 * Mach Operating System
 * Copyright (c) 1993,1991,1990,1989,1988 Carnegie Mellon University
 * All Rights Reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */
/*
 */
/*
 * Copyright (c) 1988 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Copyright (c) 1998 Todd C. Miller <Todd.Miller@courtesan.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * NOTICE: This file was modified by McAfee Research in 2004 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */
/*
 * Random device subroutines and stubs.
 */

#if KERNEL

#if defined (__i386__) || defined (__x86_64__)
#include "i386/string.h"
#elif defined (__arm__) || defined (__arm64__)
#include "arm/string.h"
#else
#error architecture not supported
#endif

#include <vm/vm_kern.h>
#include <kern/misc_protos.h>
#include <kern/telemetry.h>
#include <libsa/stdlib.h>
#include <sys/malloc.h>
#include <libkern/section_keywords.h>
#include <machine/string.h> /* __arch_* defines */

/*
 * Note to implementers, when adding new string/memory functions
 *
 * - add a prototype/wrapper to osfmk/libsa/string.h,
 *   and an impl prototype to osfmk/machine/string.h.
 *
 * - if the function has a "chk" variant, add support to osfmk/libsa/string.h
 *   and the implementation for the checked variant at the end of this file.
 *
 * - define the function with the "impl" name and wrap it inside
 *   an #ifndef __arch_${function} block to allow each architecture
 *   to provide an optimized version if they so desire.
 */

static_assert(__arch_bcopy, "architecture must provide bcopy");
static_assert(__arch_bzero, "architecture must provide bzero");
static_assert(__arch_memcpy, "architecture must provide memcpy");
static_assert(__arch_memmove, "architecture must provide memmove");
static_assert(__arch_memset, "architecture must provide memset");

#endif /* KERNEL */

#ifndef __arch_bcmp
int
bcmp_impl(const void *pa, const void *pb, size_t len)
{
	const char *a = (const char *)pa;
	const char *b = (const char *)pb;

	if (len == 0) {
		return 0;
	}

	do{
		if (*a++ != *b++) {
			break;
		}
	} while (--len);

	/*
	 * Check for the overflow case but continue to handle the non-overflow
	 * case the same way just in case someone is using the return value
	 * as more than zero/non-zero
	 */
	if ((len & 0xFFFFFFFF00000000ULL) && !(len & 0x00000000FFFFFFFFULL)) {
		return ~0;
	} else {
		return (int)len;
	}
}
#endif /* __arch_bcmp */

#ifndef __arch_memcmp
MARK_AS_HIBERNATE_TEXT
int
memcmp_impl(const void *s1, const void *s2, size_t n)
{
	if (n != 0) {
		const unsigned char *p1 = s1, *p2 = s2;

		do {
			if (*p1++ != *p2++) {
				return *--p1 - *--p2;
			}
		} while (--n != 0);
	}
	return 0;
}
#endif /* __arch_memcmp */

#ifndef __arch_memcmp_zero_ptr_aligned
unsigned long
memcmp_zero_ptr_aligned_impl(const void *addr, size_t size)
{
	const uint64_t *p = (const uint64_t *)addr;
	uint64_t a = p[0];

	static_assert(sizeof(unsigned long) == sizeof(uint64_t),
	    "uint64_t is not the same size as unsigned long");

	if (size < 4 * sizeof(uint64_t)) {
		if (size > 1 * sizeof(uint64_t)) {
			a |= p[1];
			if (size > 2 * sizeof(uint64_t)) {
				a |= p[2];
			}
		}
	} else {
		size_t count = size / sizeof(uint64_t);
		uint64_t b = p[1];
		uint64_t c = p[2];
		uint64_t d = p[3];

		/*
		 * note: for sizes not a multiple of 32 bytes, this will load
		 * the bytes [size % 32 .. 32) twice which is ok
		 */
		while (count > 4) {
			count -= 4;
			a |= p[count + 0];
			b |= p[count + 1];
			c |= p[count + 2];
			d |= p[count + 3];
		}

		a |= b | c | d;
	}

	return a;
}
#endif /* __arch_memcmp_zero_ptr_aligned */

/*
 * Abstract:
 * strlen returns the number of characters in "string" preceeding
 * the terminating null character.
 */
#ifndef __arch_strlen
size_t
strlen_impl(const char *string)
{
	const char *ret = string;

	while (*string++ != '\0') {
		continue;
	}
	return (size_t)(string - 1 - ret);
}
#endif /* __arch_strlen */

/*
 * Does the same thing as strlen, except only looks up
 * to max chars inside the buffer.
 * Taken from archive/kern-stuff/sbf_machine.c in
 * seatbelt.
 * inputs:
 *      s	string whose length is to be measured
 *	max	maximum length of string to search for null
 * outputs:
 *	length of s or max; whichever is smaller
 */
#ifndef __arch_strnlen
size_t
strnlen_impl(const char *s, size_t max)
{
	const char *es = s + max, *p = s;
	while (p != es && *p) {
		p++;
	}

	return (size_t)(p - s);
}
#endif /* __arch_strlen */

/*
 * Abstract:
 *      strcmp (s1, s2) compares the strings "s1" and "s2".
 *      It returns 0 if the strings are identical. It returns
 *      > 0 if the first character that differs in the two strings
 *      is larger in s1 than in s2 or if s1 is longer than s2 and
 *      the contents are identical up to the length of s2.
 *      It returns < 0 if the first differing character is smaller
 *      in s1 than in s2 or if s1 is shorter than s2 and the
 *      contents are identical upto the length of s1.
 * Deprecation Warning:
 *	strcmp() is being deprecated. Please use strncmp() instead.
 */
#ifndef __arch_strcmp
int
strcmp_impl(const char *s1, const char *s2)
{
	int a, b;

	do {
		a = *s1++;
		b = *s2++;
		if (a != b) {
			return a - b;     /* includes case when
			                   *  'a' is zero and 'b' is not zero
			                   *  or vice versa */
		}
	} while (a != '\0');

	return 0;       /* both are zero */
}
#endif /* __arch_strcmp */

/*
 * Abstract:
 *      strncmp (s1, s2, n) compares the strings "s1" and "s2"
 *      in exactly the same way as strcmp does.  Except the
 *      comparison runs for at most "n" characters.
 */

#ifndef __arch_strncmp
int
strncmp_impl(const char *s1, const char *s2, size_t n)
{
	return strbufcmp_impl(s1, n, s2, n);
}
#endif /* __arch_strncmp */

#ifndef __arch_strlcmp
int
strlcmp_impl(const char *s1, const char *s2, size_t n)
{
	return strbufcmp_impl(s1, n, s2, strlen(s2));
}
#endif

#ifndef __arch_strbufcmp
int
strbufcmp_impl(
	const char *__counted_by(alen)a,
	size_t alen,
	const char *__counted_by(blen)b,
	size_t blen)
{
	int ca, cb;
	size_t i, len;

	len = alen < blen ? alen : blen;
	for (i = 0; i < len; ++i) {
		ca = a[i];
		cb = b[i];
		if (ca != cb) {
			return ca - cb;   /* includes case when
			                   *  'a' is zero and 'b' is not zero
			                   *  or vice versa */
		}
		if (ca == '\0') {
			return 0;       /* both are zero */
		}
	}

	/* if either string is not NUL-terminated, pretend the next character is a
	 * NUL */
	if (alen < blen) {
		return 0 - b[len];
	}
	if (blen < alen) {
		return a[len] - 0;
	}
	return 0;
}
#endif /* __arch_strbufcmp */

#ifndef __arch_strprefix
/*
 * Return TRUE(1) if string 2 is a prefix of string 1.
 */
int
strprefix_impl(const char *s1, const char *s2)
{
	int c;

	while ((c = *s2++) != '\0') {
		if (c != *s1++) {
			return 0;
		}
	}
	return 1;
}
#endif /* __arch_strprefix */


//
// Lame implementation just for use by strcasecmp/strncasecmp
//
__header_always_inline int
tolower(int ch)
{
	if (ch >= 'A' && ch <= 'Z') {
		ch = 'a' + (ch - 'A');
	}

	return ch;
}

#ifndef __arch_strcasecmp
int
strcasecmp_impl(const char *s1, const char *s2)
{
	const unsigned char *us1 = (const u_char *)s1,
	    *us2 = (const u_char *)s2;

	while (tolower(*us1) == tolower(*us2++)) {
		if (*us1++ == '\0') {
			return 0;
		}
	}
	return tolower(*us1) - tolower(*--us2);
}
#endif /* __arch_strcasecmp */

#ifndef __arch_strncasecmp
int
strncasecmp_impl(const char *s1, const char *s2, size_t n)
{
	return strbufcasecmp_impl(s1, n, s2, n);
}
#endif /* __arch_strncasecmp */

#ifndef __arch_strlcasecmp
int
strlcasecmp_impl(const char *s1, const char *s2, size_t n)
{
	return strbufcasecmp_impl(s1, n, s2, strlen(s2));
}
#endif

#ifndef __arch_strbufcasecmp
int
strbufcasecmp_impl(
	const char *__counted_by(alen)a,
	size_t alen,
	const char *__counted_by(blen)b,
	size_t blen)
{
	int ca, cb;
	size_t i, len;

	len = alen < blen ? alen : blen;
	for (i = 0; i < len; ++i) {
		ca = tolower(a[i]);
		cb = tolower(b[i]);
		if (ca != cb) {
			return ca - cb; /* includes case when
			                 *  'a' is zero and 'b' is not zero
			                 *  or vice versa */
		}
		if (ca == '\0') {
			return 0;       /* both are zero */
		}
	}

	/* if either string is not NUL-terminated, pretend the next character is a
	 * NUL */
	if (alen < blen) {
		return 0 - tolower(b[len]);
	}
	if (blen < alen) {
		return tolower(a[len]) - 0;
	}
	return 0;
}
#endif /* __arch_strbufcasecmp */

#ifndef __arch_strchr
char *
strchr_impl(const char *s, int c)
{
	if (!s) {
		return NULL;
	}

	do {
		if (*s == c) {
			return __CAST_AWAY_QUALIFIER(s, const, char *);
		}
	} while (*s++);

	return NULL;
}
#endif /* __arch_strchr */

#ifndef __arch_strrchr
char *
strrchr_impl(const char *s, int c)
{
	const char *found = NULL;

	if (!s) {
		return NULL;
	}

	do {
		if (*s == c) {
			found = s;
		}
	} while (*s++);

	return __CAST_AWAY_QUALIFIER(found, const, char *);
}
#endif /* __arch_strchr */

#if CONFIG_VSPRINTF
/*
 * Abstract:
 *      strcpy copies the contents of the string "from" including
 *      the null terminator to the string "to". A pointer to "to"
 *      is returned.
 * Deprecation Warning:
 *	strcpy() is being deprecated. Please use strlcpy() instead.
 */
char *
strcpy_impl(char *to, const char *from)
{
	char *ret = to;

	while ((*to++ = *from++) != '\0') {
		continue;
	}

	return ret;
}
#endif

/*
 * Abstract:
 *      strncpy copies "count" characters from the "from" string to
 *      the "to" string. If "from" contains less than "count" characters
 *      "to" will be padded with null characters until exactly "count"
 *      characters have been written. The return value is a pointer
 *      to the "to" string.
 */
#ifndef __arch_strncpy
char *
strncpy_impl(char * dst, const char * src, size_t maxlen)
{
	const size_t srclen = strnlen_impl(src, maxlen);
	if (srclen < maxlen) {
		memcpy_impl(dst, src, srclen);
		memset_impl(dst + srclen, 0, maxlen - srclen);
	} else {
		memcpy_impl(dst, src, maxlen);
	}
	return dst;
}
#endif /* __arch_strncpy */

/*
 * atoi:
 *
 *      This function converts an ascii string into an integer.
 *
 * input        : string
 * output       : a number
 */

int
atoi(const char *cp)
{
	int     number;

	for (number = 0; ('0' <= *cp) && (*cp <= '9'); cp++) {
		number = (number * 10) + (*cp - '0');
	}

	return number;
}

/*
 * convert an integer to an ASCII string.
 * inputs:
 *	num	integer to be converted
 *	str	string pointer.
 *
 * outputs:
 *	pointer to string start.
 */

char *
itoa(int num, char *str)
{
	char    digits[11];
	char *dp;
	char *cp = str;

	if (num == 0) {
		*cp++ = '0';
	} else {
		dp = digits;
		while (num) {
			*dp++ = '0' + num % 10;
			num /= 10;
		}
		while (dp != digits) {
			*cp++ = *--dp;
		}
	}
	*cp++ = '\0';

	return str;
}

#if CONFIG_VSPRINTF
/*
 * Deprecation Warning:
 *	strcat() is being deprecated. Please use strlcat() instead.
 */
char *
strcat_impl(char *dest, const char *src)
{
	char *old = dest;

	while (*dest) {
		++dest;
	}
	while ((*dest++ = *src++)) {
		;
	}
	return old;
}
#endif

/*
 * Appends src to string dst of size siz (unlike strncat, siz is the
 * full size of dst, not space left).  At most siz-1 characters
 * will be copied.  Always NUL terminates (unless siz <= strlen(dst)).
 * Returns strlen(src) + MIN(siz, strlen(initial dst)).
 * If retval >= siz, truncation occurred.
 */
#ifndef __arch_strlcat
size_t
strlcat_impl(char *dst, const char *src, size_t siz)
{
	char *d = dst;
	const char *s = src;
	size_t n = siz;
	size_t dlen;

	/* Find the end of dst and adjust bytes left but don't go past end */
	while (n-- != 0 && *d != '\0') {
		d++;
	}
	dlen = (size_t)(d - dst);
	n = siz - dlen;

	if (n == 0) {
		return dlen + strlen_impl(s);
	}
	while (*s != '\0') {
		if (n != 1) {
			*d++ = *s;
			n--;
		}
		s++;
	}
	*d = '\0';

	return dlen + (size_t)(s - src);       /* count does not include NUL */
}
#endif /* __arch_strlcat */

/*
 * Append src string to dst. The operation stops once *any* of the following
 * conditions is met:
 *  * when `dst` is filled with `dstsz` characters;
 *  * when `srcsz` characters have been copied;
 *  * when a NUL character has been copied from `src` to `dst`.
 * `dst` is always NUL-terminated, truncating `src` as needed.
 * If `dstsz` is 0, the function returns NULL. Otherwise, it returns `dst`,
 * regardless of whether there was free space in dst to append any characters.
 * This function is most useful to concatenate a fixed-size string to another.
 */
#ifndef __arch_strbufcat
const char *__null_terminated
strbufcat_impl(
	char *__counted_by(dstsz)dst,
	size_t dstsz,
	const char *__counted_by(srcsz)src,
	size_t srcsz)
{
	size_t len;
	if (dstsz == 0) {
		return NULL;
	}

	len = strnlen_impl(dst, dstsz);
	strbufcpy_impl(dst + len, dstsz - len, src, srcsz);
	return dst;
}
#endif /* __arch_strbufcat */

/*
 * Copy src to string dst of size siz.  At most siz-1 characters
 * will be copied.  Always NUL terminates (unless siz == 0).
 * Returns strlen(src); if retval >= siz, truncation occurred.
 */
#ifndef __arch_strlcpy
size_t
strlcpy_impl(char * dst, const char * src, size_t maxlen)
{
	const size_t srclen = strlen_impl(src);
	if (srclen + 1 < maxlen) {
		memcpy_impl(dst, src, srclen + 1);
	} else if (maxlen != 0) {
		memcpy_impl(dst, src, maxlen - 1);
		dst[maxlen - 1] = '\0';
	}
	return srclen;
}
#endif /* __arch_strlcpy */

/*
 * Copy src string to dst. The copy stops once *any* of the following conditions
 * is met:
 *  * when `dstsz` characters have been copied;
 *  * when `srcsz` characters have been copied;
 *  * when a NUL character has been copied from `src` to `dst`.
 * `dst` is always NUL-terminated, truncating `src` as needed.
 * If `dstsz` is 0, the function returns NULL. Otherwise, it returns `dst`.
 * This function is most useful to copy a fixed-size string from one buffer to
 * another.
 */
#ifndef __arch_strbufcpy
const char *__null_terminated
strbufcpy_impl(
	char *__counted_by(dstsz)dst,
	size_t dstsz,
	const char *__counted_by(srcsz)src,
	size_t srcsz)
{
	size_t copymax;

	if (dstsz == 0) {
		return NULL;
	}

	copymax = strnlen_impl(src, srcsz);
	if (copymax < dstsz) {
		memmove_impl(dst, src, copymax);
		dst[copymax] = 0;
	} else {
		memmove_impl(dst, src, dstsz);
		dst[dstsz - 1] = 0;
	}
	return __unsafe_forge_null_terminated(const char *__null_terminated, dst);
}
#endif /* __arch_strbufcpy */

#ifndef __arch_strncat
char *
strncat_impl(char *s1, const char *s2, size_t n)
{
	if (n != 0) {
		char *d = s1;
		const char *s = s2;

		while (*d != 0) {
			d++;
		}
		do {
			if ((*d = *s++) == '\0') {
				break;
			}
			d++;
		} while (--n != 0);
		*d = '\0';
	}

	return __CAST_AWAY_QUALIFIER(s1, const, char *);
}
#endif /* __arch_strncat */

#ifndef __arch_strnstr
char *
strnstr_impl(const char *s, const char *find, size_t slen)
{
	char c, sc;
	size_t len;

	if ((c = *find++) != '\0') {
		len = strlen_impl(find);
		do {
			do {
				if ((sc = *s++) == '\0' || slen-- < 1) {
					return NULL;
				}
			} while (sc != c);
			if (len > slen) {
				return NULL;
			}
		} while (strncmp_impl(s, find, len) != 0);
		s--;
	}

	return __CAST_AWAY_QUALIFIER(s, const, char *);
}
#endif /* __arch_strnstr */

void * __memcpy_chk(void *dst, void const *src, size_t s, size_t chk_size);
void * __memmove_chk(void *dst, void const *src, size_t s, size_t chk_size);
void * __memset_chk(void *dst, int c, size_t s, size_t chk_size);
size_t __strlcpy_chk(char *dst, char const *src, size_t s, size_t chk_size);
size_t __strlcat_chk(char *dst, char const *src, size_t s, size_t chk_size);
char * __strncpy_chk(char *restrict dst, char *restrict src, size_t len, size_t chk_size);
char * __strncat_chk(char *restrict dst, const char *restrict src, size_t len, size_t chk_size);
char * __strcpy_chk(char *restrict dst, const char *restrict src, size_t chk_size);
char * __strcat_chk(char *restrict dst, const char *restrict src, size_t chk_size);

void *
__memcpy_chk(void *dst, void const *src, size_t s, size_t chk_size)
{
	if (__improbable(chk_size < s)) {
		panic("__memcpy_chk object size check failed: dst %p, src %p, (%zu < %zu)", dst, src, chk_size, s);
	}
	return memcpy_impl(dst, src, s);
}

void *
__memmove_chk(void *dst, void const *src, size_t s, size_t chk_size)
{
	if (__improbable(chk_size < s)) {
		panic("__memmove_chk object size check failed: dst %p, src %p, (%zu < %zu)", dst, src, chk_size, s);
	}
	return memmove_impl(dst, src, s);
}

void *
__memset_chk(void *dst, int c, size_t s, size_t chk_size)
{
	if (__improbable(chk_size < s)) {
		panic("__memset_chk object size check failed: dst %p, c %c, (%zu < %zu)", dst, c, chk_size, s);
	}
	return memset_impl(dst, c, s);
}

size_t
__strlcat_chk(char *dst, char const *src, size_t s, size_t chk_size)
{
	if (__improbable(chk_size < s)) {
		panic("__strlcat_chk object size check failed: dst %p, src %p, (%zu < %zu)", dst, src, chk_size, s);
	}
	return strlcat_impl(dst, src, s);
}

size_t
__strlcpy_chk(char *dst, char const *src, size_t s, size_t chk_size)
{
	if (__improbable(chk_size < s)) {
		panic("__strlcpy_chk object size check failed: dst %p, src %p, (%zu < %zu)", dst, src, chk_size, s);
	}
	return strlcpy_impl(dst, src, s);
}

char *
__strncpy_chk(char *restrict dst, char *restrict src,
    size_t len, size_t chk_size)
{
	if (__improbable(chk_size < len)) {
		panic("__strncpy_chk object size check failed: dst %p, src %p, (%zu < %zu)", dst, src, chk_size, len);
	}
	return strncpy_impl(dst, src, len);
}

char *
__strncat_chk(char *restrict dst, const char *restrict src,
    size_t len, size_t chk_size)
{
	size_t len1 = strlen_impl(dst);
	size_t len2 = strnlen_impl(src, len);
	if (__improbable(chk_size < len1 + len2 + 1)) {
		panic("__strncat_chk object size check failed: dst %p, src %p, (%zu < %zu + %zu + 1)", dst, src, chk_size, len1, len2);
	}
	return strncat_impl(dst, src, len);
}

char *
__strcpy_chk(char *restrict dst, const char *restrict src, size_t chk_size)
{
	size_t len = strlen_impl(src);
	if (__improbable(chk_size < len + 1)) {
		panic("__strcpy_chk object size check failed: dst %p, src %p, (%zu < %zu + 1)", dst, src, chk_size, len);
	}
	memcpy_impl(dst, src, len + 1);
	return dst;
}

char *
__strcat_chk(char *restrict dst, const char *restrict src, size_t chk_size)
{
	size_t len1 = strlen_impl(dst);
	size_t len2 = strlen_impl(src);
	size_t required_len = len1 + len2 + 1;
	if (__improbable(chk_size < required_len)) {
		panic("__strcat_chk object size check failed: dst %p, src %p, (%zu < %zu + %zu + 1)", dst, src, chk_size, len1, len2);
	}
	memcpy_impl(dst + len1, src, len2 + 1);
	return dst;
}
