/* Copyright (c) (2010-2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCZP_H_
#define _CORECRYPTO_CCZP_H_

#include <corecrypto/ccn.h>

CC_PTRCHECK_CAPABLE_HEADER()

struct cczp;

typedef struct cczp *cczp_t;
typedef const struct cczp *cczp_const_t;

struct cczp_funcs;
typedef const struct cczp_funcs *cczp_funcs_t;

// keep cczp_hd and cczp structures consistent
// cczp_hd is typecasted to cczp to read EC curve params
// make sure n is the first element see ccrsa_ctx_n macro
#define __CCZP_HEADER_ELEMENTS_DEFINITIONS(pre) \
    cc_size pre##n;                             \
    cc_unit pre##bitlen;                        \
    cczp_funcs_t pre##funcs;

#define __CCZP_ELEMENTS_DEFINITIONS(pre)    \
    __CCZP_HEADER_ELEMENTS_DEFINITIONS(pre) \
    cc_unit pre##ccn[];

struct cczp {
    __CCZP_ELEMENTS_DEFINITIONS()
} CC_ALIGNED(CCN_UNIT_SIZE);

#define CCZP_N(ZP) ((ZP)->n)
#define CCZP_PRIME(ZP) ((ZP)->ccn)
#define CCZP_BITLEN(ZP) ((ZP)->bitlen)

CC_NONNULL((1))
cc_size cczp_n(cczp_const_t zp);

CC_NONNULL((1))
const cc_unit * cc_indexable cczp_prime(cczp_const_t zp);

CC_NONNULL((1))
size_t cczp_bitlen(cczp_const_t zp);

#endif /* _CORECRYPTO_CCZP_H_ */
