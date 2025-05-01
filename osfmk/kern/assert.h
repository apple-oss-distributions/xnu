/*
 * Copyright (c) 2000-2016 Apple Inc. All rights reserved.
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
 * Mach Operating System
 * Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University
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

#ifndef _KERN_ASSERT_H_
#define _KERN_ASSERT_H_

/*	assert.h	4.2	85/01/21	*/

#include <kern/macro_help.h>
#include <sys/cdefs.h>
#include <machine/trap.h>

#ifdef  XNU_KERNEL_PRIVATE
#include <machine/static_if.h>
#endif
#ifdef  MACH_KERNEL_PRIVATE
#include <mach_assert.h>
#endif

__BEGIN_DECLS

__abortlike
extern void     Assert(
	const char      *file,
	int             line,
	const char      *expression) __attribute__((noinline));

extern int kext_assertions_enable;

#ifndef __FILE_NAME__
#define __FILE_NAME__ __FILE__
#endif
#define __Panic(fmt, args...) (panic)(fmt, ##args)

__END_DECLS

#ifndef APPLE_KEXT_ASSERTIONS
#define APPLE_KEXT_ASSERTIONS   0
#endif

__enum_decl(mach_assert_type_t, unsigned char, {
	MACH_ASSERT_DEFAULT,
	MACH_ASSERT_3P,
	MACH_ASSERT_3S,
	MACH_ASSERT_3U,
});

struct mach_assert_hdr {
	mach_assert_type_t      type;
	unsigned                lineno : 24;
	const char             *filename;
} __attribute__((packed, aligned(4)));

struct mach_assert_default {
	struct mach_assert_hdr  hdr;
	const char             *expr;
} __attribute__((packed, aligned(4)));

struct mach_assert_3x {
	struct mach_assert_hdr  hdr;
	const char             *a;
	const char             *op;
	const char             *b;
} __attribute__((packed, aligned(4)));

#if MACH_ASSERT
# if XNU_KERNEL_PRIVATE
STATIC_IF_KEY_DECLARE_TRUE(mach_assert);
#   define mach_assert_enabled()    improbable_static_if(mach_assert)
# else
#   define mach_assert_enabled()    1
# endif /* !XNU_KERNEL_PRIVATE */
#elif APPLE_KEXT_ASSERTIONS
#  define mach_assert_enabled()     __builtin_expect(kext_assertions_enable, 0L)
#else /* !MACH_ASSERT && !APPLE_KEXT_ASSERTIONS */
#  define mach_assert_enabled()     0
#endif /* !MACH_ASSERT && !APPLE_KEXT_ASSERTIONS */

#define MACH_ASSERT_TRAP_CODE       0xbffc /*  XNU_HARD_TRAP_ASSERT_FAILURE  */
#define MACH_ASSERT_SEGSECT         "__DATA_CONST,__assert"

/*!
 * @abstract
 * Wrap any arbitrary expression/code behind a conditional
 * on whether assertions are enabled.
 */
#define MACH_ASSERT_DO(...)  ({ \
	if (mach_assert_enabled()) { \
	        __VA_ARGS__; \
	} \
})

#define mach_assert_abort(reason)  ({ \
	__attribute__((used, section(MACH_ASSERT_SEGSECT)))                     \
	static const struct mach_assert_default __desc = {                      \
	        { MACH_ASSERT_DEFAULT, __LINE__, __FILE_NAME__, },              \
	        reason,                                                         \
	};                                                                      \
                                                                                \
	ml_fatal_trap_with_value(MACH_ASSERT_TRAP_CODE, &__desc);               \
})

/*!
 * @abstract
 * assert() that is never elided or removed even in release builds.
 */
#define release_assert(ex) ({ \
	if (__builtin_expect(!(ex), 0L)) {                                      \
	        mach_assert_abort(#ex);                                         \
	}                                                                       \
})

#if MACH_ASSERT || APPLE_KEXT_ASSERTIONS

#define __assert_only

#define mach_assert_enabled_expr(ex) \
	(mach_assert_enabled() || __builtin_constant_p(!(ex)))

#define assert(ex) \
	(mach_assert_enabled_expr(ex) && !(ex) \
	? (void)mach_assert_abort(#ex) : (void)0)

#define assertf(ex, fmt, args...)  ({ \
	if (mach_assert_enabled_expr(ex) && __builtin_expect(!(ex), 0L)) {      \
	        __Panic("%s:%d Assertion failed: %s : " fmt,                    \
	            __FILE_NAME__, __LINE__, # ex, ##args);                     \
	}                                                                       \
})

/*
 * Each of the following three macros takes three arguments instead of one for
 * the assertion. The suffixes, 's', u' and 'p' indicate the type of arguments
 * expected: 'signed', 'unsigned' or 'pointer' respectively.
 *
 * assert(a > b)     -> file.c:123 Assertion failed: a > b
 * assert3u(a, >, b) -> file.c:124 Assertion failed: a > b (1 >= 10)
 *
 */
#define assert3u(a, op, b)  ({                                                  \
	if (mach_assert_enabled_expr((unsigned long long)(a) op                 \
	    (unsigned long long)(b))) {                                         \
	        const unsigned long long a_ = (a);                              \
	        const unsigned long long b_ = (b);                              \
                                                                                \
	        if (__builtin_expect(!(a_ op b_), 0L)) {                        \
	                __attribute__((used, section(MACH_ASSERT_SEGSECT)))     \
	                static const struct mach_assert_3x __desc3u = {         \
	                        { MACH_ASSERT_3U, __LINE__, __FILE_NAME__, },   \
	                        #a, #op, #b,                                    \
	                };                                                      \
                                                                                \
	                ml_fatal_trap_with_value3(MACH_ASSERT_TRAP_CODE,        \
	                    &__desc3u, a_, b_);                                 \
	        }                                                               \
	}                                                                       \
})

#define assert3s(a, op, b)  ({                                                  \
	if (mach_assert_enabled_expr((long long)(a) op ((long long)b))) {       \
	        const signed long long a_ = (a);                                \
	        const signed long long b_ = (b);                                \
                                                                                \
	        if (__builtin_expect(!(a_ op b_), 0L)) {                        \
	                __attribute__((used, section(MACH_ASSERT_SEGSECT)))     \
	                static const struct mach_assert_3x __desc3s = {         \
	                        { MACH_ASSERT_3S, __LINE__, __FILE_NAME__, },   \
	                        #a, #op, #b,                                    \
	                };                                                      \
                                                                                \
	                ml_fatal_trap_with_value3(MACH_ASSERT_TRAP_CODE,        \
	                    &__desc3s, a_, b_);                                 \
	        }                                                               \
	}                                                                       \
})

#define assert3p(a, op, b)  ({                                                  \
	if (mach_assert_enabled_expr((const void *)(a) op (const void *)(b))) { \
	        const void *a_ = (a);                                           \
	        const void *b_ = (b);                                           \
                                                                                \
	        if (__builtin_expect(!(a_ op b_), 0L)) {                        \
	                __attribute__((used, section(MACH_ASSERT_SEGSECT)))     \
	                static const struct mach_assert_3x __desc3p = {         \
	                        { MACH_ASSERT_3P, __LINE__, __FILE_NAME__, },   \
	                        #a, #op, #b,                                    \
	                };                                                      \
                                                                                \
	                ml_fatal_trap_with_value3(MACH_ASSERT_TRAP_CODE,        \
	                    &__desc3p, a_, b_);                                 \
	        }                                                               \
	}                                                                       \
})

#else /* !MACH_ASSERT && !XNU_KERNEL_PRIVATE */

#define __assert_only                   __unused
#define mach_assert_enabled_expr(ex)    0

#define assert(ex)                      ((void)0)
#define assertf(ex, fmt, args...)       ((void)0)

#define assert3s(a, op, b)              ((void)0)
#define assert3u(a, op, b)              ((void)0)
#define assert3p(a, op, b)              ((void)0)

#endif /* !MACH_ASSERT && !XNU_KERNEL_PRIVATE */

/*
 * static_assert is a C11 / C++0x / C++1z feature.
 *
 * Beginning with C++0x, it is a keyword and should not be #defined
 *
 * static_assert is not disabled by MACH_ASSERT or NDEBUG
 */

#ifndef __cplusplus
	#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
		#define _STATIC_ASSERT_OVERLOADED_MACRO(_1, _2, NAME, ...) NAME
		#define static_assert(...) _STATIC_ASSERT_OVERLOADED_MACRO(__VA_ARGS__, _static_assert_2_args, _static_assert_1_arg)(__VA_ARGS__)

		#define _static_assert_2_args(ex, str) _Static_assert((ex), str)
		#define _static_assert_1_arg(ex) _Static_assert((ex), #ex)
	#endif
#else
	#if !defined(__cpp_static_assert)
/* pre C++11 support */
		#define _STATIC_ASSERT_OVERLOADED_MACRO(_1, _2, NAME, ...) NAME
		#define static_assert(...) _STATIC_ASSERT_OVERLOADED_MACRO(__VA_ARGS__, _static_assert_2_args, _static_assert_1_arg)(__VA_ARGS__)

		#define _static_assert_2_args(ex, str) _Static_assert((ex), str)
		#define _static_assert_1_arg(ex) _Static_assert((ex), #ex)
	#else
/*
 * C++11 only supports the 2 argument version of static_assert.
 * C++1z has added support for the 1 argument version.
 */
		#define _static_assert_1_arg(ex) static_assert((ex), #ex)
	#endif
#endif

#endif  /* _KERN_ASSERT_H_ */
