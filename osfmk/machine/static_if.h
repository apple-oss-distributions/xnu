/*
 * Copyright (c) 2021 Apple Inc. All rights reserved.
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

#ifndef _MACHINE_STATIC_IF_H
#define _MACHINE_STATIC_IF_H

#include <sys/cdefs.h>
#include <stdbool.h>
#include <stdint.h>
#include <mach/kern_return.h>
#include <libkern/section_keywords.h>

typedef const struct static_if_entry *static_if_entry_t;

typedef struct static_if_key {
	short                   sik_enable_count;
	short                   sik_init_value;
	unsigned                sik_entries_count;
	static_if_entry_t       sik_entries_head;
} *static_if_key_t;

#if defined (__x86_64__)
#include "x86_64/static_if.h"
#elif defined (__arm__)
#include "arm/static_if.h"
#elif defined (__arm64__)
#include "arm64/static_if.h"
#else
#error architecture not supported
#endif

__BEGIN_DECLS
#pragma GCC visibility push(hidden)

/*
 * Declare/define a static jump key
 *
 * STATIC_IF_KEY_{DECLARE,DEFINE}_TRUE
 *     the static jump key initial enablement count is positive,
 *     and the key enabled.
 *
 * STATIC_IF_KEY_{DECLARE,DEFINE}_FALSE
 *     the static jump key initial enablement count is negative,
 *     and the key disabled.
 *
 * Enablement counts can be manipulated with @c static_if_key_{enable,disable}.
 */
#define STATIC_IF_KEY_DECLARE_TRUE(name) \
	extern struct static_if_key_true name##_jump_key

#define STATIC_IF_KEY_DEFINE_TRUE(name) \
	__used struct static_if_key_true name##_jump_key = { \
	        .key.sik_init_value = 0, \
	        .key.sik_enable_count = 0, \
	}

#define STATIC_IF_KEY_DECLARE_FALSE(name) \
	extern struct static_if_key_false name##_jump_key

#define STATIC_IF_KEY_DEFINE_FALSE(name) \
	__used struct static_if_key_false name##_jump_key = { \
	        .key.sik_init_value = -1, \
	        .key.sik_enable_count = -1, \
	}

/*!
 * @macro probable_static_if() / improbable_static_if()
 *
 * @brief
 * Returns whether the static if class is true or not,
 * encoding it in code rather than loading globals.
 *
 * @discussion
 * Static "ifs" are meant to provide extremely low overhead
 * enablement or disablement of features based on TEXT patching.
 *
 * It is meant for debugging features, or checkers that happen
 * on really hot paths where loading a global will affect
 * performance in meaningful ways (lock checks, preemption
 * disablement tracking, etc...).
 *
 * @c probable_static_if() versus @c improbable_static_if()
 * affects which direction will take a branch:
 *
 *   key value             |   TRUE   |  FALSE   |    outlining
 *   ----------------------+----------+----------+----------------
 *   probable_static_if    |  nop     |  branch  |  "FALSE" case
 *   improbable_static_if  |  branch  |  nop     |  "TRUE"  case
 *
 * @c static_if() will not outline any code, and will codegen a "nop"
 * for the initial value of the key.
 *
 * There usually is a STARTUP hook that pairs with those
 * static if domains that will toggle enablement based
 * on boot-args or various configurations.
 */
#define static_if(n)  ({                                        \
	__label__ __l;                                          \
	int __result = !__static_if_key_init_value(n);          \
	STATIC_IF_NOP(n, __l);                                  \
	__result = __static_if_key_init_value(n);               \
__l:                                                            \
	__result;                                               \
})

#define probable_static_if(n)  __probable(({                    \
	__label__ __l;                                          \
	int __result = 0;                                       \
	if (__static_if_key_init_value(n)) {                    \
	        STATIC_IF_NOP(n, __l);                          \
	} else {                                                \
	        STATIC_IF_BRANCH(n, __l);                       \
	}                                                       \
	__result = 1;                                           \
__l:                                                            \
	__result;                                               \
}))

#define improbable_static_if(n)  __improbable(({                \
	__label__ __l;                                          \
	int __result = 1;                                       \
	if (__static_if_key_init_value(n)) {                    \
	        STATIC_IF_BRANCH(n, __l);                       \
	} else {                                                \
	        STATIC_IF_NOP(n, __l);                          \
	}                                                       \
	__result = 0;                                           \
__l:                                                            \
	__result;                                               \
}))


/*!
 * @function static_if_key_enable()
 *
 * @brief
 * Increases the key enablement count.
 *
 * @discussion
 * The key becomes disabled when its enablement count becomes positive.
 * This function can only be called from the context of a STATIC_IF_INIT()
 * callout.
 */
#define static_if_key_enable(n) \
	__static_if_key_delta(&n##_jump_key.key, 1)

/*!
 * @function static_if_key_disable()
 *
 * @brief
 * Decreases the key enablement count.
 *
 * @discussion
 * The key becomes disabled when its enablement count becomes negative.
 * This function can only be called from the context of a STATIC_IF_INIT()
 * callout.
 */
#define static_if_key_disable(n) \
	__static_if_key_delta(&n##_jump_key.key, -1)

/*!
 * @brief
 * Marker for functions used to setup static_if() blocks during boot.
 */
#define __static_if_init_func MARK_AS_FIXUP_TEXT

/*!
 * @macro STATIC_IF_INIT
 *
 * @brief
 * Register a function to setup a static if direction.
 *
 * @discussion
 * This code runs extremly early during boot and it can only rely
 * on extremly basic notions such as boot-args or system registers.
 *
 * Code running during this call must be marked with __static_if_init_func.
 */
#define STATIC_IF_INIT(func) \
	__PLACE_IN_SECTION(STATIC_IF_SEGMENT "," STATIC_IFINIT_SECTION) \
	static static_if_initializer __static_if__ ## func = func

/*!
 * @function static_if_boot_arg_uint64()
 *
 * @brief
 * Parses a boot-arg within a STATIC_IF_INIT() function.
 *
 * @discussion
 * PE_parse_boot_argn() can't be used that early on SPTM devices,
 * and TUNABLES() aren't parsed yet.
 */
extern uint64_t static_if_boot_arg_uint64(
	const char             *args,
	const char             *name,
	uint64_t                defval);


#pragma mark implementation details

#if KASAN
/*
 * The use of weird sections that get unmapped confuse the hell out of kasan,
 * so for KASAN leave things in regular __TEXT/__DATA segments
 */
#define STATIC_IF_SEGMENT       "__DATA_CONST"
#elif defined(__x86_64__)
/* Intel doesn't have a __BOOTDATA but doesn't protect __KLD */
#define STATIC_IF_SEGMENT       "__KLDDATA"
#else
/* arm protects __KLD early, so use __BOOTDATA for data */
#define STATIC_IF_SEGMENT       "__BOOTDATA"
#endif
#define STATIC_IF_SECTION       "__static_if"
#define STATIC_IFINIT_SECTION   "__static_ifinit"
#define STATIC_IF_SEGSECT       STATIC_IF_SEGMENT "," STATIC_IF_SECTION

typedef void (*static_if_initializer)(const char *boot_args);

struct static_if_key_true {
	struct static_if_key    key;
#if __cplusplus
	static const bool       init_value = true;
#endif
};

struct static_if_key_false {
	struct static_if_key    key;
#if __cplusplus
	static const bool       init_value = false;
#endif
};

#if __cplusplus
#define __static_if_key_init_value(n)  decltype(n##_jump_key)::init_value
#else
#define __static_if_key_init_value(n)  _Generic(n##_jump_key, \
	struct static_if_key_true: 1, \
	struct static_if_key_false: 0)
#endif

extern void __static_if_key_delta(
	static_if_key_t         key,
	int                     delta);

#if MACH_KERNEL_PRIVATE

__attribute__((always_inline))
static inline unsigned long
__static_if_entry_patch_point(static_if_entry_t sie)
{
#if STATIC_IF_RELATIVE
	return (unsigned long)&sie->sie_base + (unsigned long)(long)sie->sie_base;
#else
	return (unsigned long)sie->sie_base;
#endif
}

extern void ml_static_if_entry_patch(
	static_if_entry_t     ent,
	int                     branch);

extern void ml_static_if_flush_icache(void);

extern void static_if_init(const char *args);

#endif /* MACH_KERNEL_PRIVATE */

#pragma GCC visibility pop
__END_DECLS

#endif /* _MACHINE_STATIC_IF_H */
