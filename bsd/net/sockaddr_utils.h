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
#ifndef _NET_SOCKADDR_UTILS_H_
#define _NET_SOCKADDR_UTILS_H_

#ifdef XNU_KERNEL_PRIVATE

#include <sys/socket.h>

/*
 * Type conversion rules for socket address types
 *
 * 1. Context:
 *
 * XNU networking uses the "socket address" abstraction to represent
 * the addresses for the different protocol families, e.g. IPv4, IPv6,
 * UNIX domain sockets, ARP etc.
 *
 * Historically, the socket addresses were represented as a byte array,
 * starting with a uint16_t "family" discriminator.
 *
 * This was changed with the advent of XOpen UNIX standard: the uint16_t
 * "family" discriminator was split into 2 uint8_t fields: the length
 * and the protocol family.
 *
 * Since the different protocols have different addressing semantics,
 * the different addresses are represented by multiple structures.
 * For example, the IPv6 addresses are represented by `struct sockaddr_in6',
 * while the IPv4 addresses can be represented by `struct sockaddr_in' or by
 * `struct sockaddr_inifscope', depending on whether the address is bound
 * to a particular interface.
 *
 * The type `struct sockaddr' can be used interchangeably to represent any
 * of the above addresses. Essentially, the C types that represent
 * the different socket address families form a type hierarchy,
 * with the `struct sockaddr' being the root type.
 *
 * There are some exceptions to the hierarchy. Sometimes the socket addresses
 * are represented by a "container" type, e.g. `struct sockaddr_storage'
 * or `union sockaddr_in_4_6'. Finally, some protocol families, such as
 * the routing sockets, are represented by the plain `struct sockaddr'.
 *
 *
 *
 *                         +-------+                           +-----------+
 *      +------------------+ Base  |      +. - - . - - . - - . |Containers |
 *      | struct sockaddr  +----+--+      .                    +-----------+
 *      +-----------------------+         | +----------------------------+ |
 *                     ^                  . | union sockaddr_in_4_6      | .
 *                     +------------------+ +----------------------------+ |
 *                     |                  . +----------------------------+ .
 *                     |                  | | struct sockaddr_storage    | |
 *                     |                  . +----------------------------+ .
 *                     |    +----------+  | +----------------------------+ |
 *   + . - - . - - . - + - .| Concrete |  . | uint8_t * __bidi_indexable | .
 *   .                      +----------+  | +----------------------------+ |
 *   |  +---------------------------+ |   .                                .
 *   .  | struct sockaddr_ctl       | .   +. - - . - - . - - . - - . - - . +
 *   |  +---------------------------+ |
 *   .  +---------------------------+ .
 *   |  | struct sockaddr_dl        | |
 *   .  +---------------------------+ .
 *   |  +---------------------------+ |
 *   .  | struct sockaddr_in        | .
 *   |  +---------------------------+ |
 *   .  +---------------------------+ .
 *   |  | struct sockaddr_inarp     | |
 *   .  +---------------------------+ .
 *   |  +---------------------------+ |
 *   .  | struct sockaddr_inifscope | .
 *   |  +---------------------------+ |
 *   .  +---------------------------+ .
 *   |  | struct sockaddr_in6       | |
 *   .  +---------------------------+ .
 *   |  +---------------------------+ |
 *   .  | struct sockaddr_ndrv      | .
 *   |  +---------------------------+ |
 *   .  +---------------------------+ .
 *   |  | struct sockaddr_sys       | |
 *   .  +---------------------------+ .
 *   |  +---------------------------+ |
 *   .   | struct sockaddr_un       | .
 *   |  +---------------------------+ |
 *   .                                .
 *   + . - - . - - . - - . - - . - - .+
 *
 *
 * 2. Challenges
 *
 * 2.1. Type safety challenges
 *
 * Since the pointer type `struct sockaddr *' can represent a pointer
 * to any concrete derived type, or to a container type,
 * the enforcement of bound checks can be tricky.
 *
 * In particular, one needs to safely support the following conversions:
 *
 * - From `struct sockaddr *' to any of the derived types, and vice versa.
 * - From `uint8_t *' to any of the derived types, and vice versa.
 * - From `union sockaddr_in_4_6 *' to either `struct sockaddr_in *'
 *   or to `struct sockaddr_in6 *', and vice versa.
 * - From `struct sockaddr_in *' to `struct sockaddr_inifscope *',
 *   and vice versa.
 *
 * At the same time, the system needs to make accidental conversions between
 * unrelated types difficult. Examples of such conversions include:
 *
 * - From `struct sockaddr_in *' to `struct sockaddr_un *' or vice versa.
 * - From `struct sockaddr_sys *' to `struct sockaddr_ndrv *' or vice versa.
 *
 * 2.2. ABI constraints.
 *
 * The concrete types that are listed above are used both in the kernel space,
 * the user space and by the drivers.
 *
 * 2.3. Pointer boundary challenges
 *
 * The transition between `__single' pointers, e.g. between
 * `struct sockaddr * __single' to `struct sockaddr_in6 * __single'
 * is currently assumed to be safe, as long as the concrete types
 * have determined sizes.
 *
 * The challenge occurs whenever one needs to serialize or to deserialize
 * the concrete socket address types into a byte arrays.
 *
 * 2.4. Runtime cost challenges
 *
 * The transition between the different socket address types
 * should not incure a significant CPU or memory cost in runtime.
 *
 *
 * 3. Implementation.
 *
 * This file implements a mechanism that:
 * - Enforces the type safety by ensuring that only the valid
 *   type conversions can be made.
 * - Ensures the ABI compatibility for the socket address types.
 * - Implements the conversion between the socket address types
 *   and the container types (including byte arrays) in a way
 *   that allows enforcing the boundary checks.
 * - Does not have a significant runtime impact.
 *
 * To achive that, the mechanism relies on the C generic dispatch
 * mechanism, which allows converting variables to and from
 * the desired types.
 *
 *
 * 4. Usage.
 *
 * In order to use the sockaddr_utils, the implementation
 * code needs to include this file *after* including the files
 * which define the relevant sockaddr structures.
 *
 * For example:
 *
 *    #include <netinet/in.h>
 *    #include <netinet/in_private.h>
 *    #include <net/sockaddr_utils.h>
 *
 *
 * Doing so will redefine the canonical macros such as `SA(s)`
 * and will allow for mostly seamless adoption.
 *
 * Once the adoption is mostly complete,
 * this file can be included in the "private" versions
 * of the header files, such as <netinet/in_private.h>
 */

#define __NET_SOCKADDR_UTILS_H_INCLUDED
#include <net/strict_type_cnv_private.h>
#undef __NET_SOCKADDR_UTILS_H_INCLUDED

#include <net/if_dl.h>
#include <sys/un.h>
#include <net/ndrv.h>
#include <netinet/in_private.h>
#include <netinet/if_ether.h>
#include <net/necp.h>

/*
 * Building blocks for the cast operations
 */


/*
 * Generic static cast for sockaddr subtypes.
 *
 * Defines a static cast expression that, given the expression EXPR
 * and the destination type DST_TYPENAME will:
 * 0. If EXPR represents a byte array, attempt to convert EXPR
 *    to DST_TYPENAME.
 * 1. If EXPR is compatible with `struct DST_TYPENAME *': return EXPR.
 * 2. If EXPR is compatible with `struct sockaddr *', perform type conversion
 *    from `struct sockaddr *' to `struct DST_TYPENAME  *'
 * 3. If EXPR is compatible with  `struct sockaddr_storage *',
 *    perform type conversion from `struct sockaddr_storage *'
 *    to `struct DST_TYPENAME *'.
 * 4. If additional conversions are enabled, attempt to apply those
 *    to the EXPR, and if successful, return the result of conversion.
 *
 * NOTE: The static cast preserves the CV qualifiers.
 */
#define __SA_UTILS_STATIC_CAST(EXPR, DST_TYPENAME, ...)  _Generic((EXPR),                         \
	__STC_BYTES_TO_OBJ_CNV_CLAUSE(DST_TYPENAME),                                     /* [0] */    \
	__STC_IDENTITY_CNV_CLAUSE(struct, DST_TYPENAME),                                 /* [1] */    \
	__STC_TYPE_TO_OBJ_CNV_CLAUSE(struct, sockaddr, DST_TYPENAME),                    /* [2] */    \
	__STC_TYPE_TO_OBJ_CNV_CLAUSE(struct, sockaddr_storage, DST_TYPENAME),            /* [3] */    \
    ##__VA_ARGS__                                                                    /* [4] */    \
)((EXPR))


/*
 * Generic const cast for sockaddr subtypes.
 *
 * Defines a const cast expression that, given the expression EXPR
 * and the destination type DST_TYPENAME will:
 * 0. If EXPR is compatible with `const struct DST_TYPENAME *':
 *    deconst EXPR and return the result.
 * 1. If EXPR is compatible with `const struct sockaddr  s*':
 *    convert EXPR to `const struct DST_TYPENAME *' and return deconsted result.
 * 2. If EXPR is compatible with `const struct sockaddr_storage *':
 *    convert EXPR to `const struct DST_TYPENAME* ' and return deconsted result.
 * 3. If additional conversions are enabled, attempt to apply those
 *    to the EXPR, and if successful, return the result of conversion.
 *
 * NOTE: The static cast preserves the CV qualifiers.
 */
#define __SA_UTILS_DECONST_CAST(EXPR, DST_TYPENAME, ...)  _Generic((EXPR),                        \
	__STC_CONST_IDENTITY_CNV_CLAUSE(struct, DST_TYPENAME),                           /* [0] */    \
	__STC_CONST_TYPE_TO_OBJ_CNV_CLAUSE(struct, sockaddr, DST_TYPENAME),              /* [1] */    \
	__STC_CONST_TYPE_TO_OBJ_CNV_CLAUSE(struct, sockaddr_storage, DST_TYPENAME),      /* [2] */    \
    ##__VA_ARGS__                                                                    /* [3] */    \
)((EXPR))


/*
 * Strict replacement for struct sockaddr
 */

/* Register the base types: struct sockaddr and struct sockaddr_storage */
__STC_DEFINE_SELF_CONVERTERS(struct, sockaddr);
__STC_DEFINE_OBJECT_CONVERTERS(struct, sockaddr, struct, sockaddr_storage);
__STC_DEFINE_OBJECT_CONVERTERS(struct, sockaddr, union, sockaddr_in_4_6);
__STC_DEFINE_OBJECT_CONVERTERS(struct, sockaddr, union, necp_sockaddr_union);
__STC_DEFINE_BYTE_TO_OBJ_CNVS(struct, sockaddr, sizeof(struct sockaddr), 255);

__STC_DEFINE_SELF_CONVERTERS(struct, sockaddr_storage);
__STC_DEFINE_BYTE_TO_OBJ_CNVS(struct, sockaddr_storage,
    sizeof(struct sockaddr_storage), sizeof(struct sockaddr_storage));
__STC_DEFINE_BYTE_TO_OBJ_CNVS(union, sockaddr_in_4_6,
    sizeof(union sockaddr_in_4_6), sizeof(union sockaddr_in_4_6));
__STC_DEFINE_BYTE_TO_OBJ_CNVS(union, necp_sockaddr_union,
    sizeof(union necp_sockaddr_union), sizeof(union necp_sockaddr_union));


/*************************************************************************************************
 *  Generic converter to bytes.
 */
#define __SA_UTILS_CONV_TO_BYTES(X) _Generic((X),                                                 \
	        __STC_OBJ_TO_BYTES_CNV_CLAUSE(struct, sockaddr),                                      \
	        __STC_OBJ_TO_BYTES_CNV_CLAUSE(struct, sockaddr_storage),                              \
	        __STC_OBJ_TO_BYTES_CNV_CLAUSE(union, sockaddr_in_4_6),                                \
	        __STC_OBJ_TO_BYTES_CNV_CLAUSE(union, necp_sockaddr_union),                            \
	        __STC_OBJ_TO_BYTES_CNV_CLAUSE(struct, sockaddr_ctl),                                  \
	        __STC_OBJ_TO_BYTES_CNV_CLAUSE(struct, sockaddr_dl),                                   \
	        __STC_OBJ_TO_BYTES_CNV_CLAUSE(struct, sockaddr_in),                                   \
	        __STC_OBJ_TO_BYTES_CNV_CLAUSE(struct, sockaddr_in6),                                  \
	        __STC_OBJ_TO_BYTES_CNV_CLAUSE(struct, sockaddr_inarp),                                \
	        __STC_OBJ_TO_BYTES_CNV_CLAUSE(struct, sockaddr_inifscope),                            \
	        __STC_OBJ_TO_BYTES_CNV_CLAUSE(struct, sockaddr_ndrv),                                 \
	        __STC_OBJ_TO_BYTES_CNV_CLAUSE(struct, sockaddr_sys),                                  \
	        __STC_OBJ_TO_BYTES_CNV_CLAUSE(struct, sockaddr_un),                                   \
	        __STC_BYTES_TO_BYTES_CNV_CLAUSE()                                                     \
	)((X))


/*************************************************************************************************
 * Converters to `struct sockaddr *'
 */
#define __SA_UTILS_CONV_TO_SOCKADDR(X) _Generic((X),                                              \
	        __STC_BYTES_TO_OBJ_CNV_CLAUSE(sockaddr),                                              \
	        __STC_TYPE_TO_OBJ_CNV_CLAUSE(struct, sockaddr_storage, sockaddr),                     \
	        __STC_TYPE_TO_OBJ_CNV_CLAUSE(union, sockaddr_in_4_6, sockaddr),                       \
	        __STC_TYPE_TO_OBJ_CNV_CLAUSE(union, necp_sockaddr_union, sockaddr),                   \
	        __STC_TYPE_TO_OBJ_CNV_CLAUSE(struct, sockaddr_ctl, sockaddr),                         \
	        __STC_TYPE_TO_OBJ_CNV_CLAUSE(struct, sockaddr_dl, sockaddr),                          \
	        __STC_TYPE_TO_OBJ_CNV_CLAUSE(struct, sockaddr_in, sockaddr),                          \
	        __STC_TYPE_TO_OBJ_CNV_CLAUSE(struct, sockaddr_in6, sockaddr),                         \
	        __STC_TYPE_TO_OBJ_CNV_CLAUSE(struct, sockaddr_inarp, sockaddr),                       \
	        __STC_TYPE_TO_OBJ_CNV_CLAUSE(struct, sockaddr_inifscope, sockaddr),                   \
	        __STC_TYPE_TO_OBJ_CNV_CLAUSE(struct, sockaddr_ndrv, sockaddr),                        \
	        __STC_TYPE_TO_OBJ_CNV_CLAUSE(struct, sockaddr_sys, sockaddr),                         \
	        __STC_TYPE_TO_OBJ_CNV_CLAUSE(struct, sockaddr_un, sockaddr),                          \
	        __STC_IDENTITY_CNV_CLAUSE(struct, sockaddr)                                           \
	)((X))

#define __SA_UTILS_DECONST_AND_CONV_TO_SOCKADDR(X) _Generic((X),                                  \
	        __STC_CONST_TYPE_TO_OBJ_CNV_CLAUSE(struct, sockaddr_storage, sockaddr),               \
	        __STC_CONST_TYPE_TO_OBJ_CNV_CLAUSE(union, sockaddr_in_4_6, sockaddr),                 \
	        __STC_CONST_TYPE_TO_OBJ_CNV_CLAUSE(union, necp_sockaddr_union, sockaddr),             \
	        __STC_CONST_TYPE_TO_OBJ_CNV_CLAUSE(struct, sockaddr_ctl, sockaddr),                   \
	        __STC_CONST_TYPE_TO_OBJ_CNV_CLAUSE(struct, sockaddr_dl, sockaddr),                    \
	        __STC_CONST_TYPE_TO_OBJ_CNV_CLAUSE(struct, sockaddr_in, sockaddr),                    \
	        __STC_CONST_TYPE_TO_OBJ_CNV_CLAUSE(struct, sockaddr_in6, sockaddr),                   \
	        __STC_CONST_TYPE_TO_OBJ_CNV_CLAUSE(struct, sockaddr_inarp, sockaddr),                 \
	        __STC_CONST_TYPE_TO_OBJ_CNV_CLAUSE(struct, sockaddr_inifscope, sockaddr),             \
	        __STC_CONST_TYPE_TO_OBJ_CNV_CLAUSE(struct, sockaddr_ndrv, sockaddr),                  \
	        __STC_CONST_TYPE_TO_OBJ_CNV_CLAUSE(struct, sockaddr_sys, sockaddr),                   \
	        __STC_CONST_TYPE_TO_OBJ_CNV_CLAUSE(struct, sockaddr_un, sockaddr),                    \
	        __STC_CONST_IDENTITY_CNV_CLAUSE(struct, sockaddr)                                     \
	)((X))


#if defined(SA)
#undef SA
#endif /* defined(SA) */
#define SA(s)                          __SA_UTILS_CONV_TO_SOCKADDR((s))
#define __DECONST_SA(s)                __SA_UTILS_DECONST_AND_CONV_TO_SOCKADDR((s))

#define SA_BYTES(s) __SA_UTILS_CONV_TO_BYTES(s)

/*************************************************************************************************
 * Replacements for `bcopy', `bcmp' and `bzero'.
 */
#define SOCKADDR_COPY(SRC, DST, LEN)  do {                                                        \
	const uint8_t* __sau_sbytes = __SA_UTILS_CONV_TO_BYTES((SRC));                                \
	uint8_t* __sau_dbytes = __SA_UTILS_CONV_TO_BYTES((DST));                                      \
	bcopy(__sau_sbytes, __sau_dbytes, (LEN));                                                     \
} while(0)


#define SOCKADDR_ZERO(SRC, LEN)  do {                                                             \
	uint8_t* __sau_src_bytes = __SA_UTILS_CONV_TO_BYTES((SRC));                                   \
	bzero(__sau_src_bytes, (LEN));                                                                \
} while(0)


#define SOCKADDR_CMP(LH, RH, LEN)  ({                                                             \
	int __sac_rv = 0;                                                                             \
	const uint8_t* __sau_lhb = __SA_UTILS_CONV_TO_BYTES((LH));                                    \
	const uint8_t* __sau_rhb = __SA_UTILS_CONV_TO_BYTES((RH));                                    \
	__sac_rv = bcmp(__sau_lhb, __sau_rhb, (LEN));                                                 \
	__sac_rv;                                                                                     \
})

/*************************************************************************************************
 * Strict replacement for `struct sockaddr_ctl *'
 */
__SA_UTILS_DEFINE_FIXED_SIZE_SUBTYPE(struct, sockaddr_ctl)

#define __SA_UTILS_CONV_TO_SOCKADDR_CTL(X)              __SA_UTILS_STATIC_CAST(X, sockaddr_ctl)
#define __SA_UTILS_DECONST_AND_CONV_TO_SOCKADDR_CTL(X)  __SA_UTILS_DECONST_CAST(X, sockaddr_ctl)

#define SCTL(s)                        __SA_UTILS_CONV_TO_SOCKADDR_CTL((s))
#define __DECONST_SCTL(s)              __SA_UTILS_DECONST_AND_CONV_TO_SOCKADDR_CTL((s))


/*************************************************************************************************
 * Strict replacement for `struct sockaddr_dl *'
 */
__SA_UTILS_DEFINE_VARIABLE_SIZE_SUBTYPE(struct, sockaddr_dl)


#define __SA_UTILS_CONV_TO_SOCKADDR_DL(X)             __SA_UTILS_STATIC_CAST(X, sockaddr_dl)
#define __SA_UTILS_DECONST_AND_CONV_TO_SOCKADDR_DL(X) __SA_UTILS_DECONST_CAST (X, sockaddr_dl)

#if defined(SDL)
#undef SDL
#endif /* defined(SDL) */
#define SDL(s)                         __SA_UTILS_CONV_TO_SOCKADDR_DL((s))
#define __DECONST_SDL(s)               __SA_UTILS_DECONST_AND_CONV_TO_SOCKADDR_DL((s))


/*************************************************************************************************
 * Strict replacement for `struct sockaddr_in *'
 */
__SA_UTILS_DEFINE_FIXED_SIZE_SUBTYPE(struct, sockaddr_in,                                         \
        union, sockaddr_in_4_6,                                                                   \
        union, necp_sockaddr_union)

#define __SA_UTILS_CONV_TO_SOCKADDR_IN(X)                                                         \
    __SA_UTILS_STATIC_CAST(X, sockaddr_in,                                                        \
	__STC_ENABLE_STATIC_CAST(union, sockaddr_in_4_6, sockaddr_in),                                \
	__STC_ENABLE_STATIC_CAST(union, necp_sockaddr_union, sockaddr_in))


#define __SA_UTILS_DECONST_AND_CONV_TO_SOCKADDR_IN(X)                                             \
    __SA_UTILS_DECONST_CAST (X, sockaddr_in,                                                      \
	    __STC_ENABLE_DECONST_CAST(union, sockaddr_in_4_6, sockaddr_in),                           \
	    __STC_ENABLE_DECONST_CAST(union, necp_sockaddr_union, sockaddr_in))

#if defined(SIN)
#undef SIN
#endif /* defined(SIN) */
#define SIN(s)                   __SA_UTILS_CONV_TO_SOCKADDR_IN((s))
#define __DECONST_SIN(s)         __SA_UTILS_DECONST_AND_CONV_TO_SOCKADDR_IN((s))

#if defined(satosin)
#undef satosin
#endif /* defined(satosin) */
#define satosin(sa)     SIN(sa)

#if defined(sintosa)
#undef sintosa
#endif /* defined(sintosa) */
#define sintosa(sin)     SA(sin)


/*************************************************************************************************
 * Strict replacement for `struct sockaddr_inarp *'
 */
__SA_UTILS_DEFINE_FIXED_SIZE_SUBTYPE(struct, sockaddr_inarp)

#define __SA_UTILS_CONV_TO_SOCKADDR_INARP(X)                                                      \
    __SA_UTILS_STATIC_CAST(X, sockaddr_inarp)

#define __SA_UTILS_DECONST_AND_CONV_TO_SOCKADDR_INARP(X)                                          \
    __SA_UTILS_DECONST_CAST(X, sockaddr_inarp)

#define SINARP(s)                __SA_UTILS_CONV_TO_SOCKADDR_INARP((s))
#define __DECONST_SINARP(s)      __SA_UTILS_DECONST_AND_CONV_TO_SOCKADDR_INARP((s))


/*************************************************************************************************
 * Strict replacement for `struct sockaddr_inifscope *'
 */
__SA_UTILS_DEFINE_FIXED_SIZE_SUBTYPE(struct, sockaddr_inifscope,                                  \
        union, sockaddr_in_4_6,                                                                   \
        union, necp_sockaddr_union)

#define __SA_UTILS_CONV_TO_SOCKADDR_INIFSCOPE(X)                                                  \
    __SA_UTILS_STATIC_CAST(X, sockaddr_inifscope,                                                 \
	   __STC_ENABLE_STATIC_CAST(union, sockaddr_in_4_6, sockaddr_inifscope),                      \
	   __STC_ENABLE_STATIC_CAST(union, necp_sockaddr_union, sockaddr_inifscope))

#define __SA_UTILS_DECONST_AND_CONV_TO_SOCKADDR_INIFSCOPE(X)                                      \
    __SA_UTILS_DECONST_CAST(X, sockaddr_inifscope,                                                \
	    __STC_ENABLE_DECONST_CAST(union, sockaddr_in_4_6, sockaddr_inifscope),                    \
	    __STC_ENABLE_DECONST_CAST(union, necp_sockaddr_union, sockaddr_inifscope))

#if defined(SINIFSCOPE)
#undef SINIFSCOPE
#endif /* defined(SINIFSCOPE) */
#define SINIFSCOPE(s)            __SA_UTILS_CONV_TO_SOCKADDR_INIFSCOPE((s))
#define __DECONST_SINIFSCOPE(s)  __SA_UTILS_DECONST_AND_CONV_TO_SOCKADDR_INIFSCOPE((s))


/*************************************************************************************************
 * Strict replacement for `struct sockaddr_in6 *'
 */
__SA_UTILS_DEFINE_FIXED_SIZE_SUBTYPE(struct, sockaddr_in6,                                        \
        union, sockaddr_in_4_6,                                                                   \
        union, necp_sockaddr_union)

#define __SA_UTILS_CONV_TO_SOCKADDR_IN6(X)                                                        \
    __SA_UTILS_STATIC_CAST(X, sockaddr_in6,                                                       \
	__STC_ENABLE_STATIC_CAST(union, sockaddr_in_4_6, sockaddr_in6),                               \
	__STC_ENABLE_STATIC_CAST(union, necp_sockaddr_union, sockaddr_in6))

#define __SA_UTILS_DECONST_AND_CONV_TO_SOCKADDR_IN6(X)                                            \
    __SA_UTILS_DECONST_CAST(X, sockaddr_in6,                                                      \
	    __STC_ENABLE_DECONST_CAST(union, sockaddr_in_4_6, sockaddr_in6),                          \
	    __STC_ENABLE_DECONST_CAST(union, necp_sockaddr_union, sockaddr_in6))

#if defined(SIN6)
#undef SIN6
#endif /* defined(SIN6) */
#define SIN6(s)                  __SA_UTILS_CONV_TO_SOCKADDR_IN6((s))
#define __DECONST_SIN6(s)        __SA_UTILS_DECONST_AND_CONV_TO_SOCKADDR_IN6((s))

#if defined(satosin6)
#undef satosin6
#endif /* defined(satosin6) */
#define satosin6(sa)    SIN6(sa)

#if defined(sin6tosa)
#undef sin6tosa
#endif /* defined(sin6tosa) */
#define sin6tosa(sin6)   SA((sin6))

#if defined(SIN6IFSCOPE)
#undef SIN6IFSCOPE
#endif /* defined(SIN6IFSCOPE) */
#define SIN6IFSCOPE(s)  SIN6(s)


/*************************************************************************************************
 * Strict replacement for `struct sockaddr_ndrv *'
 */
__SA_UTILS_DEFINE_FIXED_SIZE_SUBTYPE(struct, sockaddr_ndrv)

#define __SA_UTILS_CONV_TO_SOCKADDR_NDRV(X)                                                       \
    __SA_UTILS_STATIC_CAST(X, sockaddr_ndrv)

#define __SA_UTILS_DECONST_AND_CONV_TO_SOCKADDR_NDRV(X)                                           \
    __SA_UTILS_DECONST_CAST(X, sockaddr_ndrv)

#define SNDRV(s)                 __SA_UTILS_CONV_TO_SOCKADDR_NDRV((s))
#define __DECONST_SNDRV(s)       __SA_UTILS_DECONST_AND_CONV_TO_SOCKADDR_NDRV((s))


/*************************************************************************************************
 * Strict replacement for `struct sockaddr_sys *'
 */
__SA_UTILS_DEFINE_FIXED_SIZE_SUBTYPE(struct, sockaddr_sys)

#define __SA_UTILS_CONV_TO_SOCKADDR_SYS(X)                                                        \
    __SA_UTILS_STATIC_CAST(X, sockaddr_sys)

#define __SA_UTILS_DECONST_AND_CONV_TO_SOCKADDR_SYS(X)                                            \
    __SA_UTILS_DECONST_CAST(X, sockaddr_sys)

#define SSYS(s)                  __SA_UTILS_CONV_TO_SOCKADDR_SYS((s))
#define __DECONST_SSYS(s)        __SA_UTILS_DECONST_AND_CONV_TO_SOCKADDR_SYS((s))


/*************************************************************************************************
 * Strict replacement for `struct sockaddr_un *'
 */
__SA_UTILS_DEFINE_VARIABLE_SIZE_SUBTYPE(struct, sockaddr_un)

#define __SA_UTILS_CONV_TO_SOCKADDR_UN(X)                                                         \
    __SA_UTILS_STATIC_CAST(X, sockaddr_un)

#define __SA_UTILS_DECONST_AND_CONV_TO_SOCKADDR_UN(X)                                             \
    __SA_UTILS_DECONST_CAST(X, sockaddr_un)

#define SUN(s)                   __SA_UTILS_CONV_TO_SOCKADDR_UN((s))
#define __DECONST_SUN(s)         __SA_UTILS_DECONST_AND_CONV_TO_SOCKADDR_UN((s))


#endif /* XNU_KERNEL_PRIVATE */

#endif /* _NET_SOCKADDR_UTILS_H_ */
