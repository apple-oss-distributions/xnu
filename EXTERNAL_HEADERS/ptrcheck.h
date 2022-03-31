/*===---- ptrcheck.h - Pointer bounds hints & specifications ----------------===
 *
 * Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
 * See https://llvm.org/LICENSE.txt for license information.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 *===-----------------------------------------------------------------------===
 */

#ifndef __PTRCHECK_H
#define __PTRCHECK_H

/* __has_ptrcheck can be used in preprocessor macros (and other parts of the
   language expecting constant expressions) to test if bounds attributes
   exist. */
#if defined(__has_feature) && __has_feature(bounds_attributes)
  #define __has_ptrcheck 1
#else
  #define __has_ptrcheck 0
#endif

#if __has_ptrcheck

/* An attribute that modifies a pointer type such that its ABI is three pointer
   components: the pointer value itself (the pointer value); one-past-the-end of
   the object it is derived from (the upper bound); and the base address of the
   object it is derived from (the lower bound). The pointer value is allowed to
   lie outside the [lower bound, upper bound) interval, and it supports the
   entire range of arithmetic operations that are usually applicable to
   pointers. Bounds are implicitly checked only when the pointer is dereferenced
   or converted to a different representation. */
#define __bidi_indexable __attribute__((__bidi_indexable__))

/* An attribute that modifies a pointer type such that its ABI is two pointer
   components: the pointer value itself (the lower bound); and one-past-the-end
   of the object it is derived from (the upper bound). Indexable pointers do not
   support negative arithmetic operations: it is a compile-time error to use a
   subtraction or add a negative quantity to them, and it is a runtime error if
   the same happens at runtime while it can't be detected at compile-time. Same
   as __bidi_indexable pointers, __indexable pointers are bounds-checked when
   dereferenced or converted to another representation. */
#define __indexable __attribute__((__indexable__))

/* An attribute that modifies a pointer type such than it has the ABI of a
   regular C pointer, without allowing pointer arithmetic. Pointer arithmetic is
   a compile-time error. A __single pointer is expected to be either NULL or
   point to exactly one valid value. */
#define __single __attribute__((__single__))

/* An attribute that modifies a pointer type such than it can be used exactly
   like a regular C pointer, with unchecked arithmetic and dereferencing. An
   __unsafe_indexable pointer cannot convert implicitly to another type of
   pointer since that would require information that is not available to the
   program. You must use __unsafe_forge_bidi_indexable or __unsafe_forge_single
   to convert __unsafe_indexable pointers to so-called safe pointers. */
#define __unsafe_indexable __attribute__((__unsafe_indexable__))

/* An attribute that modifies a pointer type such that it has the ABI of a
   regular C pointer, but it implicitly converts to a __bidi_indexable pointer
   with bounds that assume there are N valid elements starting at its address.
   The conversion happens at the same point the object converts to an rvalue, or
   immediately for values which cannot be lvalues (such as function calls). */

/* Assignments to the pointer object must be accompanied with an assignment to
   N if it is assignable. */

/* N must either be an expression that evaluates to a constant, or an integer
   declaration from the same scope, or (for structure fields) a declaration
   contained in basic arithmetic. */
#define __counted_by(N) __attribute__((__counted_by__(N)))

/* Identical to __counted_by(N), aside that N is a byte count instead of an
   object count. */
#define __sized_by(N) __attribute__((__sized_by__(N)))

/* An attribute that modifies a pointer type such that it has the ABI of a
   regular C pointer, but it implicitly converts to a __bidi_indexable pointer
   with bounds that assume that E is one-past-the-end of the original object.
   Implicitly, referencing E in the same scope will create a pointer that
   converts to a __bidi_indexable pointer one-past-the-end of the original
   object, but with a lower bound set to the value of the pointer that is
   attributed. */

/* Assignments to the pointer object must be accompanied with an assignment to
   E if it is assignable. */
#define __ended_by(E) __attribute__((__ended_by__(E)))

/* Directives that tells the compiler to assume that subsequent pointer types
   have the ABI specified by the ABI parameter, which may be one of single,
   indexable, bidi_indexable or unsafe_indexable. */

/* In project files, the ABI is assumed to be single by default. In headers
   included from libraries or the SDK, the ABI is assumed to be unsafe_indexable
   by default. */
#define __ptrcheck_abi_assume_single() \
  _Pragma("clang abi_ptr_attr set(single)")

#define __ptrcheck_abi_assume_indexable() \
  _Pragma("clang abi_ptr_attr set(indexable)")

#define __ptrcheck_abi_assume_bidi_indexable() \
  _Pragma("clang abi_ptr_attr set(bidi_indexable)")

#define __ptrcheck_abi_assume_unsafe_indexable() \
  _Pragma("clang abi_ptr_attr set(unsafe_indexable)")

/* Create a __bidi_indexable pointer of a given pointer type (T), starting at
   address P, pointing to S bytes of valid memory. T must be a pointer type. */
#define __unsafe_forge_bidi_indexable(T, P, S) \
  ((T __bidi_indexable)__builtin_unsafe_forge_bidi_indexable((P), (S)))

/* Create a __single pointer of a given type (T), starting at address P. T must
   be a pointer type. */
#define __unsafe_forge_single(T, P) \
  ((T __single)__builtin_unsafe_forge_single((P)))

/* Create a wide pointer with the same lower bound and upper bounds as X, but
   with a pointer component also equal to the lower bound. */
#define __ptr_lower_bound(X) __builtin_get_pointer_lower_bound(X)

/* Create a wide pointer with the same lower bound and upper bounds as X, but
   with a pointer component also equal to the upper bound. */
#define __ptr_upper_bound(X) __builtin_get_pointer_upper_bound(X)

/* Instruct the compiler to disregard the bounds of an array used in a function
   prototype and allow the decayed pointer to use __counted_by. This is a niche
   capability that is only useful in limited patterns (the way that `mig` uses
   arrays being one of them). */
#define __array_decay_dicards_count_in_parameters \
  __attribute__((__decay_discards_count_in_parameters__))

#else

/* We intentionally define to nothing pointer attributes which do not have an
   impact on the ABI. __indexable and __bidi_indexable are not defined because
   of the ABI incompatibility that makes the diagnostic preferable. */
#define __single
#define __unsafe_indexable
#define __counted_by(N)
#define __sized_by(N)
#define __ended_by(E)

/* Similarly, we intentionally define to nothing the
   __ptrcheck_abi_assume_single and __ptrcheck_abi_assume_unsafe_indexable
   macros because they do not lead to an ABI incompatibility. However, we do not
   define the indexable and unsafe_indexable ones because the diagnostic is
   better than the silent ABI break. */
#define __ptrcheck_abi_assume_single()
#define __ptrcheck_abi_assume_unsafe_indexable()

/* __unsafe_forge intrinsics are defined as regular C casts. */
#define __unsafe_forge_bidi_indexable(T, P, S) ((T)(P))
#define __unsafe_forge_single(T, P) ((T)(P))

/* decay operates normally; attribute is meaningless without pointer checks. */
#define __array_decay_dicards_count_in_parameters

#endif /* __has_ptrcheck */

#endif /* __PTRCHECK_H */
