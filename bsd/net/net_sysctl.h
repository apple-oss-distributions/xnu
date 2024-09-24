/*
 * Copyright (c) 2000-2024 Apple Inc. All rights reserved.
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

 #ifndef _NET_SYSCTL_H_
 #define _NET_SYSCTL_H_

#include <sys/cdefs.h>
#include <sys/sysctl.h>
/*
 * Helper utilities for the sysctl procedures used
 * by bsd networking.
 */

/*
 * DECLARE_SYSCTL_HANDLER_ARG_ARRAY
 *
 * Helper macro to be invoked from a sysctl handler function.
 *
 * The macro compares the `arg2' sysctl handler argument
 * with the `expected_array_size' macro parameter.
 *
 * If `arg2' is equal to `expected_array_size', the macro will
 * define two local variables, the names of which are controlled
 * by macro parameters:
 *
 *    element_type  *`array_var';
 *    unsigned int   `len_var';
 *
 * The `array_var' local variable will be sized in accordance
 * to the parameters. It does not use `__sized_by` annotation,
 * to allow the body of the handler function to change the values,
 * if needed.
 *
 * If `arg2' is not equal to `expected_array_size', the macro
 * will return from the sysctl handler function with the
 * EINVAL code.
 */
#define DECLARE_SYSCTL_HANDLER_ARG_ARRAY(element_type,                     \
	    expected_array_size,                                               \
	    array_var,                                                         \
	    len_var)                                                           \
    unsigned int len_var = (unsigned int)arg2;                             \
    if (len_var != (expected_array_size)) {                                \
	    return EINVAL;                                                     \
    }                                                                      \
    element_type * array_var = __unsafe_forge_bidi_indexable(              \
	element_type *, arg1, len_var * sizeof(element_type))


 #endif /* _NET_SYSCTL_H_ */
