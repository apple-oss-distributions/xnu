/*
 * Copyright (c) 2023 Apple Inc. All rights reserved.
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
#ifndef _NET_STRICT_TYPE_CNV_PRIVATE_H_
#define _NET_STRICT_TYPE_CNV_PRIVATE_H_

#ifdef XNU_KERNEL_PRIVATE

#include <sys/mcache.h>
#include <sys/socket.h>
#include <os/log.h>

/*
 * Only include this header file from <net/sockaddr_utils.h>
 */
#ifndef __NET_SOCKADDR_UTILS_H_INCLUDED
#error "do not include <net/strict_type_cnv_private.h> directly, use <net/sockaddr_utils.h> instead."
#endif



/*
 * Debug mode. If defined, disables certain optimizations,
 * and introduces a "conversion failed" upcall,
 * which can be set for testing.
 */
//#define __STC_DEBUG

/*
 * Attributes for the conversion functions.
 */
#if defined(__STC_DEBUG)
#define __STC_CONV_ATTRS__    __attribute__((__noinline__))
#else /* !defined(__STC_DEBUG) */
#define __STC_CONV_ATTRS__    __attribute__((always_inline))  __pure2
#endif /* defined(__STC_DEBUG)*/

#define __WCAST_ALIGN          "clang diagnostic ignored \"-Wcast-align\""
#define __WITH_SUPPRESSION(SUPPRESSION, ...) ({                                                   \
	_Pragma("clang diagnostic push");                                                             \
	_Pragma(SUPPRESSION);                                                                         \
	__VA_ARGS__                                                                                   \
	_Pragma("clang diagnostic pop");                                                              \
})
/*
 * Converts `const struct STYPE * VAL' to `struct DTYPE *'.
 */
#define __STC_DECONST_AND_CONVERT(STAG, STYPE, DTAG, DTYPE, VAL) ({                                \
    STAG STYPE *__single __sau_deconst_val;                                                        \
	__sau_deconst_val = __DECONST(STAG STYPE * __single, (VAL));                                   \
    __WITH_SUPPRESSION(__WCAST_ALIGN, (DTAG DTYPE * __single)(__sau_deconst_val));                 \
})

/*
 * Converts `struct STYPE * VAL' to `struct DTYPE *'.
 */
#define __STC_CONV_TO(STAG, STYPE, DTAG, DTYPE, VAL) ({                                           \
    __WITH_SUPPRESSION(__WCAST_ALIGN, (DTAG DTYPE * __single)((VAL)));                            \
})

/*
 * Converts `const struct STYPE * VAL' to `const struct DTYPE *'.
 */
#define __STC_CONV_CONST_TO_CONST(STYPE, DTYPE, VAL) ({                                           \
    __WITH_SUPPRESSION(__WCAST_ALIGN, (const struct DTYPE * __single)((VAL)));                    \
})

/*
 * Converts `[const] struct STYPE * VAL' to
 * `uint8_t* __bidi_indexable', bounded by MAX_LEN
 */
#define __STC_CONV_TO_BYTES_LEN(VAL, MAX_LEN) ({                                                  \
    __WITH_SUPPRESSION(__WCAST_ALIGN, __unsafe_forge_bidi_indexable(uint8_t*, (VAL), (MAX_LEN))); \
})


/*
 * Converts `uint8_t* __bidi_indexable' to `[const] struct DTYPE'.
 * Returns NULL if the conversion is not possible.
 */
#define __STC_CONV_FROM_BYTES_LEN(DTAG, DTYPE, VAL, LEN) ({                                       \
    __WITH_SUPPRESSION(__WCAST_ALIGN, __unsafe_forge_single(DTAG DTYPE *, (VAL)));                \
})


/*
 * Converter function names, used both to generate the inline stubs,
 * and in the generic dispatch expressions.
 */
#define __STC_OBJ_TO_BY_CNV(T)       __stc_convert_##T##_to_bytes
#define __STC_COBJ_TO_CBY_CNV(T)     __stc_convert_const_##T##_to_const_bytes
#define __STC_BY_TO_OBJ_CNV(T)       __stc_convert_bytes_to_##T
#define __STC_CBY_TO_COBJ_CNV(T)     __stc_convert_const_bytes_to_const_##T
#define __STC_CBY_TO_CBY_CNV()       __stc_convert_const_bytes_to_const_bytes
#define __STC_BY_TO_BY_CNV()         __stc_convert_bytes_to_bytes
#define __STC_TY_TY_CNV_F(F, T)      __stc_convert_##F##_to_##T
#define __STC_CTY_TY_CNV_F(F, T)     __stc_convert_const_##F##_to_##T
#define __STC_CTY_CTY_CNV_F(F, T)    __stc_convert_const_##F##_to_const_##T
#define __STC_TY_ID_CNV_F(F)         __stc_convert_##F##_identity
#define __STC_CTY_ID_CNV_F(F)        __stc_convert_const_##F##_identity
#define __STC_CTY_CID_CNV_F(F)       __stc_convert_##F##_const_identity


/*************************************************************************************************
 * Conversion building blocks, used below for converter definitions.
 */

#if __has_ptrcheck
#define __STC_ENFORCE_MIN_LEN(BTYPE, MIN_LEN, PTR) do {                                           \
    if ((PTR)) {                                                                                  \
	        BTYPE * __ensure_minimal_len __sized_by(MIN_LEN) = (PTR);                             \
	        (void)__ensure_minimal_len;                                                           \
	}                                                                                             \
} while(0)

#define __STC_CONVERT_INDEXABLE_PTR_TO(T, P)                                                      \
	__unsafe_forge_bidi_indexable(T,  (P), __ptr_upper_bound((P)) - (P));

#else /* !__has_ptrcheck */
#define __STC_ENFORCE_MIN_LEN(BTYPE, MIN_LEN, PTR) do {} while (0)

#define __STC_CONVERT_INDEXABLE_PTR_TO(T, P) ((T)(P))

#endif /* !__has_ptrcheck */


#define __STC_OBJ_TO_BYTES_CNV_IMPL(CV, TAG, TYPE, MAX_LEN, CNV_F)                                \
__STC_CONV_ATTRS__                                                                                \
static inline CV uint8_t* __indexable                                                             \
CNV_F(const TAG TYPE *ptr __single)                                                               \
{                                                                                                 \
    return __STC_CONV_TO_BYTES_LEN(__DECONST(TAG TYPE *__single, ptr), (MAX_LEN));                \
}

#define __STC_BYTES_TO_OBJ_CNV_IMPL(CV, TAG, TYPE, BTYPE, MIN_LEN, CNV_F)                         \
static inline CV TAG TYPE * __single                                                              \
__attribute__((overloadable))                                                                     \
CNV_F(CV BTYPE * data __header_indexable)                                                         \
{                                                                                                 \
	__STC_ENFORCE_MIN_LEN(CV BTYPE, MIN_LEN, data);                                               \
    return __STC_CONV_FROM_BYTES_LEN(CV TAG, TYPE, data, (MIN_LEN));                              \
}


/*
 * Converts `[CV] STAG STYPE *__single' to `[CV] DTAG DTYPE *__single', using CNV_F.
 */
#define __STC_OBJ_TO_OBJ_CNV_IMPL(CV, STAG, STYPE, DTAG, DTYPE, CNV_F)                            \
__STC_CONV_ATTRS__                                                                                \
static inline CV DTAG DTYPE * __single                                                            \
__attribute__((overloadable))                                                                     \
CNV_F(CV STAG STYPE *ptr __single)                                                                \
{                                                                                                 \
    return __STC_CONV_TO(CV STAG, STYPE, CV DTAG, DTYPE, ptr);                                    \
}


/*
 * Converts `const STAG STYPE *__single' to `DTAG DTYPE *__single', using CNV_F.
 */
#define __STC_COBJ_TO_OBJ_CNV_IMPL(STAG, STYPE, DTAG, DTYPE, CNV_F)                               \
__STC_CONV_ATTRS__                                                                                \
static inline DTAG DTYPE * __single                                                               \
__attribute__((overloadable))                                                                     \
CNV_F(const STAG STYPE *ptr __single)                                                             \
{                                                                                                 \
    return __STC_DECONST_AND_CONVERT(STAG, STYPE, DTAG, DTYPE, ptr);                              \
}


/*************************************************************************************************
 * Statically typed converters.
 */

/*
 * Conversions between different variants of pointers to sockaddr objects
 * that have the different types.
 *
 * Given tuple (STAG, STYPE, DTAG, DTYPE), defines the converters:
 * 0. "Forward":          STAG STYPE *__single -> DTAG DTYPE *__single
 * 1. "Reverse":          DTAG DTYPE *__single -> STAG STYPE *__single
 * 2. "Forward const":    const STAG STYPE *__single -> const DTAG DTYPE *__single
 * 3. "Reverse const":    const DTAG DTYPE *__single -> const STAG STYPE *__single
 * 4. "Forward deconst":  const STAG STYPE *__single -> DTAG DTYPE *__single
 * 5. "Reverse deconst":  const DTAG DTYPE *__single -> STAG STYPE *__single
 */
#define __STC_DEFINE_OBJECT_CONVERTERS(STAG, STYPE, DTAG, DTYPE)                                  \
/* [0] ("Forward")  */                                                                            \
__STC_OBJ_TO_OBJ_CNV_IMPL(, STAG, STYPE, DTAG, DTYPE,  __STC_TY_TY_CNV_F(STYPE, DTYPE))           \
                                                                                                  \
/* [1] ("Reverse") */                                                                             \
__STC_OBJ_TO_OBJ_CNV_IMPL(, DTAG, DTYPE, STAG, STYPE,  __STC_TY_TY_CNV_F(DTYPE, STYPE))           \
                                                                                                  \
/* [2] ("Forward const")  */                                                                      \
__STC_OBJ_TO_OBJ_CNV_IMPL(const, STAG, STYPE, DTAG, DTYPE, __STC_CTY_CTY_CNV_F(STYPE, DTYPE))     \
                                                                                                  \
/* [3] ("Reverse const")  */                                                                      \
__STC_OBJ_TO_OBJ_CNV_IMPL(const, DTAG, DTYPE, STAG, STYPE, __STC_CTY_CTY_CNV_F(DTYPE, STYPE))     \
                                                                                                  \
/* [4] ("Forward deconst")  */                                                                    \
__STC_COBJ_TO_OBJ_CNV_IMPL(STAG, STYPE, DTAG, DTYPE, __STC_CTY_TY_CNV_F(STYPE, DTYPE))            \
                                                                                                  \
/* [5] ("Reverse deconst")  */                                                                    \
__STC_COBJ_TO_OBJ_CNV_IMPL(DTAG, DTYPE, STAG, STYPE, __STC_CTY_TY_CNV_F(DTYPE, STYPE))


/*
 * Conversions between different variants of pointers to sockaddr objects
 * that have the same type.
 *
 * Given tuple (TAG, TYPE), defines the edge case converters:
 * 0. "Identity":          TAG TYPE *__single -> TAG TYPE *__single
 * 1. "Const identity":    const TAG TYPE *__single -> const TAG TYPE *__single
 * 2. "Deconst identity":  const TAG TYPE *__single -> TAG DTYPE *__single
 */
#define __STC_DEFINE_SELF_CONVERTERS(DTAG, DTYPE)                                                 \
/* [0] ("Identity")  */                                                                           \
__STC_CONV_ATTRS__                                                                                \
static inline DTAG DTYPE *__single                                                                \
__STC_TY_ID_CNV_F(DTYPE)(DTAG DTYPE *sin __single)                                                \
{                                                                                                 \
    return sin;                                                                                   \
}                                                                                                 \
                                                                                                  \
/* [1] ("Const identity")  */                                                                     \
__STC_CONV_ATTRS__                                                                                \
static inline const DTAG DTYPE *__single                                                          \
__STC_CTY_CID_CNV_F(DTYPE)(const DTAG DTYPE *sin __single)                                        \
{                                                                                                 \
    return sin;                                                                                   \
}                                                                                                 \
                                                                                                  \
/* [2] ("Deconst identity")  */                                                                   \
__STC_CONV_ATTRS__                                                                                \
static inline DTAG DTYPE *__single                                                                \
__STC_CTY_ID_CNV_F(DTYPE)(const DTAG DTYPE *sin __single)                                         \
{                                                                                                 \
    return __DECONST(DTAG DTYPE *__single, sin);                                                  \
}


/*
 * Conversions between byte arrays and pointers to sockaddr objects
 *
 * Given tuple (TAG, TYPE, MIN_LEN, MAX_LEN), defines
 * the edge case converters:
 * 0. "Type to bytes": TAG TYPE * __single -> uint8_t *__sized_by(MAX_LEN)
 * 1. "Const type to const bytes": const TAG TYPE * __single -> const uint8_t *__sized_by(MAX_LEN)
 * 2. "Bytes to type": uint8_t *__sized_by(MIN_LEN) -> TAG TYPE * __single
 * 3. "Const bytes to const type": const uint8_t *__sized_by(MIN_LEN) -> const TAG TYPE * __single
 *
 * NOTE: Type-to-bytes converters use MAX_LEN;
 *       bytes-to-type converters use MIN_LEN
 */
#define __STC_DEFINE_BYTE_TO_OBJ_CNVS(TAG, TYPE, MIN_LEN, MAX_LEN)                                \
/* [0] ("Type to bytes") */                                                                       \
__STC_OBJ_TO_BYTES_CNV_IMPL(, TAG, TYPE, MAX_LEN, __STC_OBJ_TO_BY_CNV(TYPE))                      \
                                                                                                  \
/* [1] ("Const type to const bytes") */                                                           \
__STC_OBJ_TO_BYTES_CNV_IMPL(, TAG, TYPE, MAX_LEN, __STC_COBJ_TO_CBY_CNV(TYPE))                    \
                                                                                                  \
/* [2] ("Bytes to type") */                                                                       \
__STC_BYTES_TO_OBJ_CNV_IMPL(, TAG, TYPE, void, MIN_LEN, __STC_BY_TO_OBJ_CNV(TYPE))                \
                                                                                                  \
/* [3] ("Const bytes to const type") */                                                           \
__STC_BYTES_TO_OBJ_CNV_IMPL(const, TAG, TYPE, void, MIN_LEN, __STC_CBY_TO_COBJ_CNV(TYPE))


/*
 * Edge condition between different variants of byte pointers to uint8_t.
 * These are used by the SOCKADDR_{COPY,ZERO,CMP} operations.
 */
__STC_CONV_ATTRS__
static inline const uint8_t * __header_indexable
__attribute__((overloadable))
__STC_CBY_TO_CBY_CNV()(const void * data __header_indexable)
{
	const uint8_t * __header_indexable cdata = data;
	return __STC_CONVERT_INDEXABLE_PTR_TO(const uint8_t*, cdata);
}

__STC_CONV_ATTRS__
static inline const uint8_t * __header_indexable
__attribute__((overloadable))
__STC_CBY_TO_CBY_CNV()(const char * data __header_indexable)
{
	return __STC_CONVERT_INDEXABLE_PTR_TO(const uint8_t*, data);
}

__STC_CONV_ATTRS__
static inline const uint8_t * __header_indexable
__attribute__((overloadable))
__STC_CBY_TO_CBY_CNV()(const uint8_t * data __header_indexable)
{
	return data;
}

__STC_CONV_ATTRS__
static inline uint8_t * __header_indexable
__attribute__((overloadable))
__STC_BY_TO_BY_CNV()(void * data __header_indexable)
{
	uint8_t * __header_indexable cdata = data;
	return __STC_CONVERT_INDEXABLE_PTR_TO(uint8_t*, cdata);
}

__STC_CONV_ATTRS__
static inline uint8_t * __header_indexable
__attribute__((overloadable))
__STC_BY_TO_BY_CNV()(uint8_t * data __header_indexable)
{
	return data;
}

__STC_CONV_ATTRS__
static inline uint8_t * __header_indexable
__attribute__((overloadable))
__STC_BY_TO_BY_CNV()(char * data __header_indexable)
{
	return __STC_CONVERT_INDEXABLE_PTR_TO(uint8_t*, data);
}



/*************************************************************************************************
 * Dispatch block definitions.
 *
 * The dispatch blocks below are meant to be composed into a single generic selection expression.
 * See the definition of `__SA_UTILS_CONV_TO_SOCKADDR` for an example.
 *
 * Each dispatch block defines several type expressions and the corresponding conversion macros.
 *
 * Wnen compiled with `-fbounds-safety', the dispatch block accepst sized and single pointers.
 * When compiled without `-fbounds-safety', each dispatch block accepts only a pointer to the type.
 */


/*
 * Basic building block for associating a CNV_F function with a pointer to CV TAG TYPE.
 * Depending on whehter `-fbounds-safety' is enabled, the match block is extended to sized pointers.
 */
#if __has_ptrcheck
#define __STC_GENERIC_CV_CNV_CLAUSE(CV, TAG, TYPE, CNV_F)                                        \
	CV TAG TYPE * __single:                         CNV_F,                                                    \
	CV TAG TYPE * __bidi_indexable:         CNV_F,                                                    \
	CV TAG TYPE * __indexable:                      CNV_F
#else /* !__has_ptrcheck */
#define __STC_GENERIC_CV_CNV_CLAUSE(CV, TAG, TYPE, CNV_F)                                        \
	CV TAG TYPE * :                                         CNV_F
#endif /* !__has_ptrcheck */


/**
 * __STC_TYPE_TO_OBJ_CNV_CLAUSE(STAG, STYPE, DTYPE)
 *
 * Matches its argument against `STYPE' (`STAG' indicates struct or union), and upon a type match,
 * converts the argument to `DTYPE'.
 *
 * If the argument type is `const STAG STYPE *', the argument will be converted
 * to `const struct DTYPE * __single'.
 *
 * Otherwise, the argument will be converted to `struct DTYPE * __single'
 */
#define __STC_TYPE_TO_OBJ_CNV_CLAUSE(STAG, STYPE, DTYPE)                                           \
	__STC_GENERIC_CV_CNV_CLAUSE(, STAG, STYPE, __STC_TY_TY_CNV_F(STYPE, DTYPE)),                 \
	__STC_GENERIC_CV_CNV_CLAUSE(const, STAG, STYPE, __STC_CTY_CTY_CNV_F(STYPE, DTYPE))


/**
 * __STC_BYTES_TO_OBJ_CNV_CLAUSE(TYPE)
 *
 * Matches a BYte array, and attempts to convert to `TYPE'
 *
 * Notes on `__indexable' vs. `__bidi_indexable':
 *
 * When bounds-checks are enabled, the match block treats the `__indexable' and the `__bidi_indexable'
 * pointers the same way (but still has to distinguish between the pointer sizes).
 *
 * The conversion preserves the `const' qualifier.
 */
#define __STC_BYTES_TO_OBJ_CNV_CLAUSE(TYPE)                                                        \
	__STC_GENERIC_CV_CNV_CLAUSE(     , , char,     __STC_BY_TO_OBJ_CNV(TYPE)),                   \
	__STC_GENERIC_CV_CNV_CLAUSE(     , , uint8_t,  __STC_BY_TO_OBJ_CNV(TYPE)),                   \
	__STC_GENERIC_CV_CNV_CLAUSE(     , , void,     __STC_BY_TO_OBJ_CNV(TYPE)),                   \
	__STC_GENERIC_CV_CNV_CLAUSE(const, , char,     __STC_CBY_TO_COBJ_CNV(TYPE)),                 \
	__STC_GENERIC_CV_CNV_CLAUSE(const, , uint8_t,  __STC_CBY_TO_COBJ_CNV(TYPE)),                 \
	__STC_GENERIC_CV_CNV_CLAUSE(const, , void,     __STC_CBY_TO_COBJ_CNV(TYPE))

/**
 *  __STC_OBJ_TO_BYTES_CNV_CLAUSE(TAG, TYPE)
 *
 * Matches a `TAG TYPE *' variable, and converts it to a BYte array.
 *
 * The conversion preserves the `const' qualifier.
 */
#define __STC_OBJ_TO_BYTES_CNV_CLAUSE(TAG, TYPE)                                                              \
	__STC_GENERIC_CV_CNV_CLAUSE(     , TAG, TYPE,  __STC_OBJ_TO_BY_CNV(TYPE)),                    \
	__STC_GENERIC_CV_CNV_CLAUSE(const, TAG, TYPE,  __STC_COBJ_TO_CBY_CNV(TYPE))

/**
 * __STC_BYTES_TO_BYTES_CNV_CLAUSE()
 *
 * Matches a BYte array and returns a BYte array.
 *
 * The conversion preserves the `const' qualifier.
 */
#define __STC_BYTES_TO_BYTES_CNV_CLAUSE()                                                           \
	__STC_GENERIC_CV_CNV_CLAUSE(     , , char,     __STC_BY_TO_BY_CNV()),                          \
	__STC_GENERIC_CV_CNV_CLAUSE(     , , uint8_t,  __STC_BY_TO_BY_CNV()),                          \
	__STC_GENERIC_CV_CNV_CLAUSE(     , , void,     __STC_BY_TO_BY_CNV()),                          \
	__STC_GENERIC_CV_CNV_CLAUSE(const, , char,     __STC_CBY_TO_CBY_CNV()),                        \
	__STC_GENERIC_CV_CNV_CLAUSE(const, , uint8_t,  __STC_CBY_TO_CBY_CNV()),                        \
	__STC_GENERIC_CV_CNV_CLAUSE(const, , void,     __STC_CBY_TO_CBY_CNV())


/**
 * __STC_CONST_TYPE_TO_OBJ_CNV_CLAUSE(STAG, STYPE, DTYPE)
 *
 * Matches a `const STAG STYPE *' and converts it to `STAG STYPE * __single'
 *
 * The conversion REMOVES the `const' qualifier, if present.
 * To preserve the `const' qualifier, use the `__STC_TYPE_TO_OBJ_CNV_CLAUSE' instead.
 */
#define __STC_CONST_TYPE_TO_OBJ_CNV_CLAUSE(STAG, STYPE, DTYPE)                                     \
	__STC_GENERIC_CV_CNV_CLAUSE(const, STAG, STYPE,   __STC_CTY_TY_CNV_F(STYPE, DTYPE))

/**
 * __STC_MATCH_MATCH_CID(TAG, TYPE)
 *
 * Matches a `const TAG TYPE *' and converts it to `TAG TYPE * __single'
 *
 * The conversion REMOVES the `const' qualifier, if present.
 * To preserve the `const' qualifier, use the `__STC_IDENTITY_CNV_CLAUSE' instead.
 */
#define __STC_CONST_IDENTITY_CNV_CLAUSE(TAG, TYPE)                                                 \
	__STC_GENERIC_CV_CNV_CLAUSE(const, TAG, TYPE, __STC_CTY_ID_CNV_F(TYPE))


/**
 * __STC_IDENTITY_CNV_CLAUSE(TAG, TYPE)
 *
 * Matches a `[const] TAG TYPE *' and converts it to `[const] TAG TYPE * __single'
 *
 * The conversion preserves the `const' qualifier.
 */
#define __STC_IDENTITY_CNV_CLAUSE(TAG, TYPE)                                                     \
	__STC_GENERIC_CV_CNV_CLAUSE(const, TAG, TYPE, __STC_CTY_ID_CNV_F(TYPE)),                     \
	__STC_GENERIC_CV_CNV_CLAUSE(,      TAG, TYPE, __STC_TY_ID_CNV_F(TYPE))



/*************************************************************************************************
 * Generators for cast operations.
 */


#define __STC_ENABLE_STATIC_CAST(SRC_TAG, SRC_TYPENAME, DST_TYPENAME)                             \
	__STC_TYPE_TO_OBJ_CNV_CLAUSE(SRC_TAG, SRC_TYPENAME, DST_TYPENAME)


#define __STC_ENABLE_DECONST_CAST(SRC_TAG, SRC_TYPENAME, DST_TYPENAME)                            \
	__STC_CONST_TYPE_TO_OBJ_CNV_CLAUSE(SRC_TAG, SRC_TYPENAME, DST_TYPENAME)


/*************************************************************************************************
 * Porcelain macros to define sockaddr subtypes.
 */

/*
 * Building blocks for variadic macro overrides.
 */
#define __STC_COUNT_ARGS1(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, N, ...) N
#define __STC_COUNT_ARGS(...)                                                                     \
	__STC_COUNT_ARGS1(, ##__VA_ARGS__, _9, _8, _7, _6, _5, _4, _3, _2, _1, _0)
#define __STC_DISPATCH1(base, N, ...) __CONCAT(base, N)(__VA_ARGS__)
#define __STC_DISPATCH(base, ...)                                                                 \
	__STC_DISPATCH1(base, __STC_COUNT_ARGS(__VA_ARGS__), ##__VA_ARGS__)

#define __STC_DEFINE_STATIC_CAST(SRC_TAG, SRC_TYPENAME, DST_TAG, DST_TYPENAME)                    \
__STC_DEFINE_OBJECT_CONVERTERS(SRC_TAG, SRC_TYPENAME, DST_TAG, DST_TYPENAME)

/*
 * Building blocks for sockaddr subtype definitions.
 */
#define __STC_DEFINE_SUBTYPE_IMPL_4(TAG, TYPENAME, MIN_LEN, MAX_LEN)                              \
	__STC_DEFINE_SELF_CONVERTERS(TAG, TYPENAME);      /* [0] */                                   \
	__STC_DEFINE_STATIC_CAST(TAG, TYPENAME, struct, sockaddr)                                     \
	__STC_DEFINE_STATIC_CAST(TAG, TYPENAME, struct, sockaddr_storage)                             \
	__STC_DEFINE_BYTE_TO_OBJ_CNVS(TAG, TYPENAME, MIN_LEN, MAX_LEN)

#define __STC_DEFINE_SUBTYPE_IMPL_6(TAG, TYPENAME, MIN_LEN, MAX_LEN, TAG1, TYPENAME1)             \
	__STC_DEFINE_SUBTYPE_IMPL_4(TAG, TYPENAME, MIN_LEN, MAX_LEN)                                  \
	__STC_DEFINE_STATIC_CAST(TAG, TYPENAME, TAG1, TYPENAME1)

#define __STC_DEFINE_SUBTYPE_IMPL_8(TAG, TYPENAME, MIN_LEN, MAX_LEN,                              \
	    TAG1, TYPENAME1, TAG2, TYPENAME2)                             \
	__STC_DEFINE_SUBTYPE_IMPL_6(TAG, TYPENAME, MIN_LEN, MAX_LEN, TAG1, TYPENAME1)                 \
	__STC_DEFINE_STATIC_CAST(TAG, TYPENAME, TAG2, TYPENAME2)


/*************************************************************************************************
 * Porcelain macros to define a socakddr subtype with variable size,
 * e.g. `struct sockaddr_dl' or `struct sockaddr_un'.
 */
#define __STC_DEFINE_VARIABLE_SIZE_SUBTYPE_2(TAG, TYPENAME)                                       \
    __STC_DEFINE_SUBTYPE_IMPL_4(TAG, TYPENAME, sizeof(TAG TYPENAME), 255)

#define __STC_DEFINE_VARIABLE_SIZE_SUBTYPE_4(TAG, TYPENAME, TAG1, TYPENAME1)                      \
	__STC_DEFINE_SUBTYPE_IMPL_6(TAG, TYPENAME, sizeof(TAG TYPENAME), 255, TAG1, TYPENAME1)

#define __STC_DEFINE_VARIABLE_SIZE_SUBTYPE_6(TAG, TYPENAME, TAG1, TYPENAME1, TAG2, TYPENAME2)     \
	__STC_DEFINE_SUBTYPE_IMPL_6(TAG, TYPENAME, sizeof(TAG TYPENAME), 255,                         \
	                                                        TAG1, TYPENAME1, TAG2, TYPENAME2)

#define __SA_UTILS_DEFINE_VARIABLE_SIZE_SUBTYPE(...)                                              \
	__STC_DISPATCH(__STC_DEFINE_VARIABLE_SIZE_SUBTYPE, ##__VA_ARGS__)


/*************************************************************************************************
 * Porcelain macros to define a socakddr subtype with fixed size,
 * e.g. `struct sockaddr_in' or `struct sockaddr_in6'.
 */
#define __STC_DEFINE_FIXED_SIZE_SUBTYPE_2(TAG, TYPENAME)                                          \
    __STC_DEFINE_SUBTYPE_IMPL_4(TAG, TYPENAME, sizeof(TAG TYPENAME), sizeof(TAG TYPENAME))

#define __STC_DEFINE_FIXED_SIZE_SUBTYPE_4(TAG, TYPENAME, TAG1, TYPENAME1)                         \
    __STC_DEFINE_SUBTYPE_IMPL_6(TAG, TYPENAME, sizeof(TAG TYPENAME), sizeof(TAG TYPENAME),        \
	                                                        TAG1, TYPENAME1)

#define __STC_DEFINE_FIXED_SIZE_SUBTYPE_6(TAG, TYPENAME, TAG1, TYPENAME1, TAG2, TYPENAME2)        \
    __STC_DEFINE_SUBTYPE_IMPL_8(TAG, TYPENAME, sizeof(TAG TYPENAME), sizeof(TAG TYPENAME),        \
	                                                        TAG1, TYPENAME1, TAG2, TYPENAME2)

#define __SA_UTILS_DEFINE_FIXED_SIZE_SUBTYPE(...)                                                 \
	__STC_DISPATCH(__STC_DEFINE_FIXED_SIZE_SUBTYPE, ##__VA_ARGS__)


#endif /* XNU_KERNEL_PRIVATE */

#endif /* _NET_STRICT_TYPE_CNV_PRIVATE_H_ */
