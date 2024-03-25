/*
 * Copyright (c) 2021 Apple Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */

#ifndef _OS_ALLOC_UTIL_H
#define _OS_ALLOC_UTIL_H

#include <sys/cdefs.h>
#if defined(__cplusplus) && __cplusplus >= 201103L
extern "C++" {
#include <os/cpp_util.h>
}
#endif

/*!
 * @macro os_is_ptr_like
 *
 * @abstract
 * Tell whether the given expression resembles a pointer.
 *
 * @discussion
 * When pointer bounds are enabled, only types that are actually classified
 * as pointers will be considered pointer-like. Otherwise, any pointer-sized
 * type will be considered pointer-like.
 *
 * @param P             the expression to be checked
 */
#if __has_ptrcheck
#define os_is_ptr_like(P) (__builtin_classify_type(P) == 5)
#else  /* __has_ptrcheck */
#define os_is_ptr_like(P) (sizeof(P) == sizeof(void *))
#endif /* __has_ptrcheck */

/*!
 * @macro os_ptr_load_and_erase
 *
 * @abstract
 * Load the value of @c elem into a temporary, set @c elem to NULL, and
 * return the value.
 *
 * @param elem          the pointer whose value will be taken, and which will
 *                      be set to NULL.
 */
#define os_ptr_load_and_erase(elem) ({                        \
	_Static_assert(os_is_ptr_like(elem),                      \
	    "elem isn't pointer sized");                          \
	__auto_type *__single __eptr = &(elem);                   \
	__auto_type __elem = *__eptr;                             \
	_Pragma("clang diagnostic push")                          \
	_Pragma("clang diagnostic ignored \"-Wold-style-cast\"")  \
	*__eptr = (__typeof__(__elem))NULL;                       \
	_Pragma("clang diagnostic pop")                           \
	__elem;                                                   \
})

/*!
 * @macro os_get_pointee_type
 *
 * @abstract
 * Get the type pointed to by @c ptr.
 *
 * @discussion
 * C++ forbids dereferencing a void pointer.
 * This macro provides an abstraction that is safe to use with any pointer,
 * both from C, and from C++.
 *
 * @param ptr           the pointer we want to get the pointee's type for
 */

#if defined(__cplusplus) && __has_builtin(__remove_pointer) && \
        __has_builtin(__remove_reference_t)
/*
 * The reason we're using the compiler builtins is that those are able to
 * properly deal with __ptrauth-qualified pointers, unlike template
 * specializations. Moreover, template specializations would require forwarding
 * type definitions, and currently __attribute__((xnu_usage_semantics(...)))
 * annotations are not carried over across typedefs.
 *
 * It is safe to assume that if the compiler does not support such builtins,
 * it also does not implement D150875, and we can therefore safely dereference
 * void pointers.
 */
#define os_get_pointee_type(ptr)                               \
	__remove_pointer(__remove_reference_t(__typeof__(ptr)))
#else
#define os_get_pointee_type(ptr)                                      \
	_Pragma("clang diagnostic push")                               \
	_Pragma("clang diagnostic ignored \"-Wvoid-ptr-dereference\"") \
	__typeof__(*(ptr))                                             \
	_Pragma("clang diagnostic pop")
#endif

#endif /* _OS_ALLOC_UTIL_H */
