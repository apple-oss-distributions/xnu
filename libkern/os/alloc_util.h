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

#ifdef __cplusplus

#if __cplusplus >= 201103L

extern "C++" {
#include <os/cpp_util.h>

namespace os {
namespace au_detail {
/*
 * This is implemented using constexpr member functions to work around
 * a compiler bug related to template deduction for __ptrauth-qualified
 * types (rdar://83481514).
 *
 * We use the constexpr variable __p as a parameter to the constexpr
 * member function; because function parameters strip the __ptrauth
 * attributes, this allows us to infer the non-__ptrauth qualified
 * type in the member function template.
 */
template<class PtrTy, class CheckTy>
struct is_compatible_ptr {
	template<class T>
	static constexpr bool
	__compute_result(T *p __unused)
	{
		using _T = os::remove_extent_t<os::remove_const_t<os::remove_volatile_t<T> > >;
		using _U = os::remove_extent_t<CheckTy>;
		return os::is_same<void, _T>::value || os::is_same<_T, _U>::value;
	}

	static constexpr os::remove_reference_t<PtrTy> __p = nullptr;
	static const bool value = __compute_result(__p);
};
} // namespace au_detail
} // namespace os

/*
 * Type checking macro implementation (C++)
 */
#define os_is_compatible_ptr_impl(ptr, type) \
	os::au_detail::is_compatible_ptr<decltype(ptr), type>::value
} // "extern C++"

#else  /* __cplusplus >= 201103L */

#define os_is_compatible_ptr_impl(ptr, type) 1

#endif /* __cplusplus >= 201103L */

#else  /* __cplusplus */

/*
 * Type checking macro implementation (C):
 * wildcard any void pointer type, and check all other types using
 * __builtin_types_compatible_p.
 */
#define os_is_compatible_ptr_impl(ptr, type) _Generic((ptr),              \
	void *: 1,                                                         \
	const void *: 1,                                                   \
	const volatile void *: 1,                                          \
	volatile void * const: 1,                                          \
	default: (__builtin_types_compatible_p(__typeof__(*(ptr)), type)))

#endif /* __cplusplus */

/*!
 * @macro os_is_compatible_ptr
 *
 * @abstract
 * Check at compile time that a pointer is compatible with a given type.
 *
 * @discussion
 * The goal of this macro is to check that the type pointed to by @c ptr
 * is compatible with the given type @c type.
 *
 * The underlying implementation differs between C and C++. In C, we
 * rely on the concept of compatible types, and we implement the check
 * using __builtin_types_compatible_p. In C++, we check type equivalence
 * using type traits.
 *
 * NOTE: This macro is a no-op for C++98 (no type check is performed).
 *
 * @param ptr           the pointer whose type needs to be checked.
 * @param type          the type which the pointer will be checked against.
 */
#define os_is_compatible_ptr(ptr, type)  os_is_compatible_ptr_impl(ptr, type)

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
#define os_ptr_load_and_erase(elem) ({                           \
	_Static_assert(os_is_ptr_like(elem),                      \
	    "elem isn't pointer sized");                          \
	__auto_type __eptr = &(elem);                             \
	__auto_type __elem = *__eptr;                             \
	_Pragma("clang diagnostic push")                          \
	_Pragma("clang diagnostic ignored \"-Wold-style-cast\"")  \
	*__eptr = (__typeof__(__elem))NULL;                       \
	_Pragma("clang diagnostic pop")                           \
	__elem;                                                   \
})

#endif /* _OS_ALLOC_UTIL_H */
