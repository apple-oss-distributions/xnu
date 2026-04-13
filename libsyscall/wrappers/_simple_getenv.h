/*
 * Copyright (c) 2025 Apple Inc. All rights reserved.
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

#ifndef _SIMPLE_GETENV_H
#define _SIMPLE_GETENV_H

#include <stdbool.h>
#include <stdint.h>

static __unused __attribute__((no_builtin)) size_t
_simple_strlen(char const *s)
{
	size_t len = 0;
	while (*s++) {
		len++;
	}

	return len;
}

static __unused __attribute__((no_builtin)) bool
_simple_strncmp_equal(char const *s1, char const *s2, size_t n)
{
	size_t i;
	for (i = 0; i < n && *s1 && *s2; i++, s1++, s2++) {
		if (*s1 != *s2) {
			return false;
		}
	}

	return i == n;
}

static __unused __attribute__((no_builtin)) const char *
_simple_getenv(char const * const *envp, const char *var)
{
	size_t var_len = _simple_strlen(var);

	for (char const * const *p = envp; p && *p; p++) {
		size_t p_len = _simple_strlen(*p);

		if (p_len > var_len && _simple_strncmp_equal(*p, var, var_len) &&
		    (*p)[var_len] == '=') {
			return &(*p)[var_len + 1];
		}
	}

	return NULL;
}

static __unused __attribute__((no_builtin)) bool
_simple_getenv_check(char const * const *envp, char const *var, char const *expected)
{
	char const *value = _simple_getenv(envp, var);

	if (value == NULL) {
		return false;
	}

	size_t const n1 = _simple_strlen(value);
	size_t const n2 = _simple_strlen(expected);
	size_t const n = n1 > n2 ? n1 : n2;
	return value != NULL && _simple_strncmp_equal(value, expected, n);
}

#endif // _SIMPLE_GETENV_H
