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

#include <kern/turnstile.h>
#include <kern/kalloc.h>

ZONE_DECLARE_ID(ZONE_ID_TURNSTILE, struct turnstile);

#if DEBUG || DEVELOPMENT
/*
 * Make sure the various allocators work with bound checking.
 */
extern void zalloc_bound_checks(void);
extern void kalloc_type_bound_checks(void);
extern void kalloc_data_bound_checks(void);

void
zalloc_bound_checks(void)
{
	struct turnstile *__single ts = zalloc_id(ZONE_ID_TURNSTILE, Z_WAITOK);

	zfree_id(ZONE_ID_TURNSTILE, ts);
}

void
kalloc_data_bound_checks(void)
{
	int *__single i;
	int *__bidi_indexable a;
	void *__bidi_indexable d;

	d = kalloc_data(10, Z_WAITOK);
	kfree_data(d, 10);

	i = kalloc_type(int, Z_WAITOK);
	kfree_type(int, i);

	a = kalloc_type(int, 10, Z_WAITOK);
	a = krealloc_type(int, 10, 20, a, Z_WAITOK | Z_REALLOCF);
	kfree_type(int, 20, a);

	a = kalloc_type(int, int, 10, Z_WAITOK);
	a = krealloc_type(int, int, 10, 20, a, Z_WAITOK | Z_REALLOCF);
	kfree_type(int, int, 20, a);
}

void
kalloc_type_bound_checks(void)
{
	struct turnstile *__single ts;
	struct turnstile *__bidi_indexable ts_a;

	ts = kalloc_type(struct turnstile, Z_WAITOK);

	kfree_type(struct turnstile, ts);

	ts_a = kalloc_type(struct turnstile, 10, Z_WAITOK);

	ts_a = krealloc_type(struct turnstile, 10, 20,
	    ts_a, Z_WAITOK | Z_REALLOCF);

	kfree_type(struct turnstile, 20, ts_a);

	ts_a = kalloc_type(struct turnstile, struct turnstile, 10, Z_WAITOK);

	ts_a = krealloc_type(struct turnstile, struct turnstile, 10, 20,
	    ts_a, Z_WAITOK | Z_REALLOCF);

	kfree_type(struct turnstile, struct turnstile, 20, ts_a);
}
#endif /* DEBUG || DEVELOPMENT */
