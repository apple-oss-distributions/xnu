/*
 * Copyright (c) 2020 Apple Inc. All rights reserved.
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
#ifdef XNU_KERNEL_PRIVATE
#ifndef _COREANALYTICS_H

/*
 * Internal macros used by coreanalytics code.
 * Kept in a separate header file to keep the interface file cleaner.
 * DO NOT USE DIRECTLY.
 */
#include <kern/mpsc_queue.h>
#include <kern/zalloc.h>

/*
 * Macros to perform a foreach loop over variadic macro arguments.
 * Calls a different macro for even (fe) and odd (fo) arguments.
 */

/* Return the 70th argument */
#define _CA_NTH(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14, \
	    _15, _16, _17, _18, _19, _20, _21, _22, _23, _24, _25, _26, _27, _28, _29, \
	    _30, _31, _32, _33, _34, _35, _36, _37, _38, _39, _40, _41, _42, _43, _44, \
	    _45, _46, _47, _48, _49, _50, _51, _52, _53, _54, _55, _56, _57, _58, _59, \
	    _60, _61, _62, _63, _64, _65, _66, _67, _68, _69, _70, N, ...) N

#define _CA_NULL_TERMINATOR "\0"
#define _CA_NULL_EPSILON

#define _f0(f, ...)
#define _f1(fe, e, fo, x, ...) fo(x)
#define _f2(fe, e, fo, x, ...) fe(x) e _f1(fe, e, fo, __VA_ARGS__)
#define _f3(fe, e, fo, x, ...) fo(x) e _f2(fe, e, fo, __VA_ARGS__)
#define _f4(fe, e, fo, x, ...) fe(x) e _f3(fe, e, fo, __VA_ARGS__)
#define _f5(fe, e, fo, x, ...) fo(x) e _f4(fe, e, fo, __VA_ARGS__)
#define _f6(fe, e, fo, x, ...) fe(x) e _f5(fe, e, fo, __VA_ARGS__)
#define _f7(fe, e, fo, x, ...) fo(x) e _f6(fe, e, fo, __VA_ARGS__)
#define _f8(fe, e, fo, x, ...) fe(x) e _f7(fe, e, fo, __VA_ARGS__)
#define _f9(fe, e, fo, x, ...) fo(x) e _f8(fe, e, fo, __VA_ARGS__)
#define _f10(fe, e, fo, x, ...) fe(x) e _f9(fe, e, fo, __VA_ARGS__)
#define _f11(fe, e, fo, x, ...) fo(x) e _f10(fe, e, fo, __VA_ARGS__)
#define _f12(fe, e, fo, x, ...) fe(x) e _f11(fe, e, fo, __VA_ARGS__)
#define _f13(fe, e, fo, x, ...) fo(x) e _f12(fe, e, fo, __VA_ARGS__)
#define _f14(fe, e, fo, x, ...) fe(x) e _f13(fe, e, fo, __VA_ARGS__)
#define _f15(fe, e, fo, x, ...) fo(x) e _f14(fe, e, fo, __VA_ARGS__)
#define _f16(fe, e, fo, x, ...) fe(x) e _f15(fe, e, fo, __VA_ARGS__)
#define _f17(fe, e, fo, x, ...) fo(x) e _f16(fe, e, fo, __VA_ARGS__)
#define _f18(fe, e, fo, x, ...) fe(x) e _f17(fe, e, fo, __VA_ARGS__)
#define _f19(fe, e, fo, x, ...) fo(x) e _f18(fe, e, fo, __VA_ARGS__)
#define _f20(fe, e, fo, x, ...) fe(x) e _f19(fe, e, fo, __VA_ARGS__)
#define _f21(fe, e, fo, x, ...) fo(x) e _f20(fe, e, fo, __VA_ARGS__)
#define _f22(fe, e, fo, x, ...) fe(x) e _f21(fe, e, fo, __VA_ARGS__)
#define _f23(fe, e, fo, x, ...) fo(x) e _f22(fe, e, fo, __VA_ARGS__)
#define _f24(fe, e, fo, x, ...) fe(x) e _f23(fe, e, fo, __VA_ARGS__)
#define _f25(fe, e, fo, x, ...) fo(x) e _f24(fe, e, fo, __VA_ARGS__)
#define _f26(fe, e, fo, x, ...) fe(x) e _f25(fe, e, fo, __VA_ARGS__)
#define _f27(fe, e, fo, x, ...) fo(x) e _f26(fe, e, fo, __VA_ARGS__)
#define _f28(fe, e, fo, x, ...) fe(x) e _f27(fe, e, fo, __VA_ARGS__)
#define _f29(fe, e, fo, x, ...) fo(x) e _f28(fe, e, fo, __VA_ARGS__)
#define _f30(fe, e, fo, x, ...) fe(x) e _f29(fe, e, fo, __VA_ARGS__)
#define _f31(fe, e, fo, x, ...) fo(x) e _f30(fe, e, fo, __VA_ARGS__)
#define _f32(fe, e, fo, x, ...) fe(x) e _f31(fe, e, fo, __VA_ARGS__)
#define _f33(fe, e, fo, x, ...) fo(x) e _f32(fe, e, fo, __VA_ARGS__)
#define _f34(fe, e, fo, x, ...) fe(x) e _f33(fe, e, fo, __VA_ARGS__)
#define _f35(fe, e, fo, x, ...) fo(x) e _f34(fe, e, fo, __VA_ARGS__)
#define _f36(fe, e, fo, x, ...) fe(x) e _f35(fe, e, fo, __VA_ARGS__)
#define _f37(fe, e, fo, x, ...) fo(x) e _f36(fe, e, fo, __VA_ARGS__)
#define _f38(fe, e, fo, x, ...) fe(x) e _f37(fe, e, fo, __VA_ARGS__)
#define _f39(fe, e, fo, x, ...) fo(x) e _f38(fe, e, fo, __VA_ARGS__)
#define _f40(fe, e, fo, x, ...) fe(x) e _f39(fe, e, fo, __VA_ARGS__)
#define _f41(fe, e, fo, x, ...) fo(x) e _f40(fe, e, fo, __VA_ARGS__)
#define _f42(fe, e, fo, x, ...) fe(x) e _f41(fe, e, fo, __VA_ARGS__)
#define _f43(fe, e, fo, x, ...) fo(x) e _f42(fe, e, fo, __VA_ARGS__)
#define _f44(fe, e, fo, x, ...) fe(x) e _f43(fe, e, fo, __VA_ARGS__)
#define _f45(fe, e, fo, x, ...) fo(x) e _f44(fe, e, fo, __VA_ARGS__)
#define _f46(fe, e, fo, x, ...) fe(x) e _f45(fe, e, fo, __VA_ARGS__)
#define _f47(fe, e, fo, x, ...) fo(x) e _f46(fe, e, fo, __VA_ARGS__)
#define _f48(fe, e, fo, x, ...) fe(x) e _f47(fe, e, fo, __VA_ARGS__)
#define _f49(fe, e, fo, x, ...) fo(x) e _f48(fe, e, fo, __VA_ARGS__)
#define _f50(fe, e, fo, x, ...) fe(x) e _f49(fe, e, fo, __VA_ARGS__)
#define _f51(fe, e, fo, x, ...) fo(x) e _f50(fe, e, fo, __VA_ARGS__)
#define _f52(fe, e, fo, x, ...) fe(x) e _f51(fe, e, fo, __VA_ARGS__)
#define _f53(fe, e, fo, x, ...) fo(x) e _f52(fe, e, fo, __VA_ARGS__)
#define _f54(fe, e, fo, x, ...) fe(x) e _f53(fe, e, fo, __VA_ARGS__)
#define _f55(fe, e, fo, x, ...) fo(x) e _f54(fe, e, fo, __VA_ARGS__)
#define _f56(fe, e, fo, x, ...) fe(x) e _f55(fe, e, fo, __VA_ARGS__)
#define _f57(fe, e, fo, x, ...) fo(x) e _f56(fe, e, fo, __VA_ARGS__)
#define _f58(fe, e, fo, x, ...) fe(x) e _f57(fe, e, fo, __VA_ARGS__)
#define _f59(fe, e, fo, x, ...) fo(x) e _f58(fe, e, fo, __VA_ARGS__)
#define _f60(fe, e, fo, x, ...) fe(x) e _f59(fe, e, fo, __VA_ARGS__)
#define _f61(fe, e, fo, x, ...) fo(x) e _f60(fe, e, fo, __VA_ARGS__)
#define _f62(fe, e, fo, x, ...) fe(x) e _f61(fe, e, fo, __VA_ARGS__)
#define _f63(fe, e, fo, x, ...) fo(x) e _f62(fe, e, fo, __VA_ARGS__)
#define _f64(fe, e, fo, x, ...) fe(x) e _f63(fe, e, fo, __VA_ARGS__)
#define _f65(fe, e, fo, x, ...) fo(x) e _f64(fe, e, fo, __VA_ARGS__)
#define _f66(fe, e, fo, x, ...) fe(x) e _f65(fe, e, fo, __VA_ARGS__)
#define _f67(fe, e, fo, x, ...) fo(x) e _f66(fe, e, fo, __VA_ARGS__)
#define _f68(fe, e, fo, x, ...) fe(x) e _f67(fe, e, fo, __VA_ARGS__)
#define _f69(fe, e, fo, x, ...) fo(x) e _f68(fe, e, fo, __VA_ARGS__)
#define _f70(fe, e, fo, x, ...) fe(x) e _f69(fe, e, fo, __VA_ARGS__)

#define _CA_FOREACH(fe, e, fo, ...) _CA_NTH(__VA_ARGS__, \
    _f70, _f69, _f68, _f67, _f66, _f65, _f64, _f63, _f62, _f61, \
    _f60, _f59, _f58, _f57, _f56, _f55, _f54, _f53, _f52, _f51, _f50, _f49, _f48, _f47, _f46, _f45, _f44, _f43, \
    _f42, _f41, _f40, _f39, _f38, _f37, _f36, _f35, _f34, _f33, _f32, _f31, _f30, _f29, _f28, _f27, _f26, _f25, \
    _f24, _f23, _f22, _f21, _f20, _f19, _f18, _f17, _f16, _f15, _f14, _f13, _f12, _f11, _f10, _f9, _f8, _f7, \
    _f6, _f5, _f4, _f3, _f2, _f1, _f0)(fe, e, fo, ##__VA_ARGS__)

#define _CA_TYPE_DECLARATION(T) __typeof__(T)

/* Stringify T before macro expansion. */
#define _CA_STRINGIFY(T) #T
/* Stringify T after macro expansion. */
#define _CA_STRINGIFY_EXPAND(T) _CA_STRINGIFY(T)
#define _CA_VARIABLE_DECLARATION(T) T;

#define _CA_EVENT_NAME_PREFIX(name) _ca_event_format_##name

#define _CA_EVENT_ORG "com.apple.xnu."

struct _ca_event {
	struct mpsc_queue_chain link;
	const char *format_str;
	void *data;
};

typedef struct _ca_event * ca_event_t;

/*
 * DO NOT USE DIRECTLY.
 * Use CA_EVENT_SEND instead.
 */
extern void core_analytics_send_event(ca_event_t event);
/*
 * DO NOT USE DIRECTLY.
 * Use CA_EVENT_SEND_PREEMPTION_DISABLED instead.
 */
extern void core_analytics_send_event_preemption_disabled(ca_event_t event);
/*
 * DO NOT USE DIRECTLY.
 * Use CA_EVENT_ALLOCATE instead.
 */
extern ca_event_t core_analytics_allocate_event(size_t data_size, const char *format_str, zalloc_flags_t flags);
/*
 * Placeholder token.
 * Used in an event format string to indicate that this is a static string.
 * Only the name and type of this string are important. The contents are not used.
 */
typedef char ca_sstr;

extern size_t core_analytics_event_size(const char *event_spec);

#endif /* _COREANALYTICS_H */
#endif /* XNU_KERNEL_PRIVATE */
