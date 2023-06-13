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


#define REF 1
#define CREF 2
#define PTR 3
#define BPTR 4

#if defined(__CCT_TEST_ENABLED)
#define __CCT_ENABLE_USER_SPACE
#endif

#include <sys/constrained_ctypes.h>
#include <darwintest.h>
#include <string.h>
#include <unistd.h>

T_GLOBAL_META(
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_RUN_CONCURRENTLY(TRUE));

/*
 * Verify that `int_ref_t' and `int_ref_ref_t'
 * behave as expected, under different combinations
 * of the CCT being enabled / enacted
 */
#if defined(__CCT_TEST_ENABLED) && defined(__CCT_TEST_ENACTED)
/*
 * When the CCT are enabled in the user space,
 * __CCT_DECLARE_CONSTRAINED_PTR_TYPES(int, int) should
 * define the types `int_ref_t' and `int_ref_ref_t'.
 *
 * If the CCT are enacted in addition to being enabled,
 * the test code itself has to adhere to the type
 * constraints.
 */
__CCT_DECLARE_CONSTRAINED_PTR_TYPES(int, int);

T_DECL(enacted_constrained_types_are_size_compatible_with_plain_types, "rdar://101223528")
{
	T_ASSERT_EQ(sizeof(int_ref_t), sizeof(int*), NULL);
	T_ASSERT_EQ(sizeof(int_ref_ref_t), sizeof(int **), NULL);
}

T_DECL(enacted_constrained_types_are_assignable_from_plain_types, "rdar://101223528")
{
	int s = 1;
	T_ASSERT_EQ(s, 1, NULL);

	int * ps __single = &s;
	int_ref_t rs = ps;
	T_ASSERT_EQ(*rs, 1, NULL);

	int * * pps = &ps;
	int_ref_ref_t rrs = pps;
	T_ASSERT_EQ(**rrs, 1, NULL);
}
#elif defined(__CCT_TEST_ENABLED) && !defined(__CCT_TEST_ENACTED)
/*
 * When the CCT are enabled in the user space,
 * __CCT_DECLARE_CONSTRAINED_PTR_TYPES(int, int) should
 * define the types `int_ref_t' and `int_ref_ref_t'.
 *
 *  When CCT are not enacted, the test code itself does not have to adhere
 * to the type constraints.
 */
__CCT_DECLARE_CONSTRAINED_PTR_TYPES(int, int);

T_DECL(enabled_constrained_types_are_size_compatible_with_plain_types, "rdar://101223528")
{
	T_ASSERT_EQ(sizeof(int_ref_t), sizeof(int*), NULL);
	T_ASSERT_EQ(sizeof(int_ref_ref_t), sizeof(int **), NULL);
}

/*
 *  When CCT are not enacted, the test code itself does not have to adhere
 * to the type constraints.
 */
T_DECL(enabled_constrained_types_are_assignable_from_plain_types, "rdar://101223528")
{
	int s = 1;
	T_ASSERT_EQ(s, 1, NULL);

	int * ps __single = &s;
	int_ref_t rs = ps;
	T_ASSERT_EQ(*rs, 1, NULL);

	int * * pps = &ps;
	int_ref_ref_t rrs = pps;
	T_ASSERT_EQ(**rrs, 1, NULL);
}
#else /* !defined(__CCT_TEST_ENABLED) && !defined(__CCT_TEST_ENACTED) */
/*
 * When the CCT are disabled in the user space,
 * attempt to define `int_ref_t' and `int_ref_ref_t'
 * should be a no-op, and the subsequent redefintion
 * of `int_ref_t' and `int_ref_ref_t' should succeed.
 */
__CCT_DECLARE_CONSTRAINED_PTR_TYPES(int, int);

typedef int * int_ref_t;
typedef int * * int_ref_ref_t;

T_DECL(disabled_constrained_types_decay_into_plain_types, "rdar://101223528")
{
	int s = 1;
	T_ASSERT_EQ(s, 1, NULL);

	int_ref_t rs = &s;
	T_ASSERT_EQ(*rs, 1, NULL);

	int_ref_ref_t rrs = &rs;
	T_ASSERT_EQ(**rrs, 1, NULL);
}
#endif /* !defined(__CCT_TEST_ENABLED) && !defined(__CCT_TEST_ENACTED) */
