/* Copyright (c) (2010-2012,2014-2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
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

#ifndef _CORECRYPTO_CCMODE_INTERNAL_H_
#define _CORECRYPTO_CCMODE_INTERNAL_H_

#include <corecrypto/ccmode.h>
#include <corecrypto/ccmode_factory.h>
#include <corecrypto/cc_priv.h>
#include "cc_memory.h"
#include "cc_macros.h"

#include "ccmode_gcm_internal.h"

/* Macros defined in this file are only to be used
 *  within corecrypto files.
 */

/* For CBC, direction of underlying ecb is the same as the cbc direction */
#define CCMODE_CBC_FACTORY(_cipher_, _dir_)                                     \
static CC_READ_ONLY_LATE(struct ccmode_cbc) cbc_##_cipher_##_##_dir_;           \
                                                                                \
const struct ccmode_cbc *cc##_cipher_##_cbc_##_dir_##_mode(void)                \
{                                                                               \
    if (!CC_CACHE_DESCRIPTORS || NULL == cbc_##_cipher_##_##_dir_.init) {        \
	const struct ccmode_ecb *ecb=cc##_cipher_##_ecb_##_dir_##_mode();       \
	ccmode_factory_cbc_##_dir_(&cbc_##_cipher_##_##_dir_, ecb);             \
    }                                                                           \
    return &cbc_##_cipher_##_##_dir_;                                           \
}

/* For CTR, only one direction, underlying ecb is always encrypt */
#define CCMODE_CTR_FACTORY(_cipher_)                                            \
static struct ccmode_ctr ctr_##_cipher_;                                        \
                                                                                \
const struct ccmode_ctr *cc##_cipher_##_ctr_crypt_mode(void)                    \
{                                                                               \
    const struct ccmode_ecb *ecb=cc##_cipher_##_ecb_encrypt_mode();             \
    ccmode_factory_ctr_crypt(&ctr_##_cipher_, ecb);                             \
    return &ctr_##_cipher_;                                                     \
}

/* OFB, same as CTR */
#define CCMODE_OFB_FACTORY(_cipher_)                                            \
static struct ccmode_ofb ofb_##_cipher_;                                        \
                                                                                \
const struct ccmode_ofb *cc##_cipher_##_ofb_crypt_mode(void)                    \
{                                                                               \
    const struct ccmode_ecb *ecb=cc##_cipher_##_ecb_encrypt_mode();             \
    ccmode_factory_ofb_crypt(&ofb_##_cipher_, ecb);                             \
    return &ofb_##_cipher_;                                                     \
}


/* For CFB, the underlying ecb operation is encrypt for both directions */
#define CCMODE_CFB_FACTORY(_cipher_, _mode_, _dir_)                             \
static CC_READ_ONLY_LATE(struct ccmode_##_mode_) _mode_##_##_cipher_##_##_dir_; \
                                                                                \
const struct ccmode_##_mode_ *cc##_cipher_##_##_mode_##_##_dir_##_mode(void)    \
{                                                                               \
    if (!CC_CACHE_DESCRIPTORS || NULL == _mode_##_##_cipher_##_##_dir_.init) {   \
	const struct ccmode_ecb *ecb=cc##_cipher_##_ecb_encrypt_mode();         \
	ccmode_factory_##_mode_##_##_dir_(&_mode_##_##_cipher_##_##_dir_, ecb); \
    }                                                                           \
    return &_mode_##_##_cipher_##_##_dir_;                                      \
}

void ccmode_xts_mult_alpha(cc_unit *tweak);

int ccmode_cbc_init(const struct ccmode_cbc *cbc, cccbc_ctx *ctx,
    size_t rawkey_len, const void *rawkey);
int ccmode_cbc_decrypt(const cccbc_ctx *ctx, cccbc_iv *iv, size_t nblocks,
    const void *in, void *out);
int ccmode_cbc_encrypt(const cccbc_ctx *ctx, cccbc_iv *iv, size_t nblocks,
    const void *in, void *out);

/* Use this to statically initialize a ccmode_cbc object for decryption. */
#define CCMODE_FACTORY_CBC_DECRYPT(ECB) { \
.size = ccn_sizeof_size(sizeof(struct _ccmode_cbc_key)) + ccn_sizeof_size((ECB)->block_size) + ccn_sizeof_size((ECB)->size), \
.block_size = (ECB)->block_size, \
.init = ccmode_cbc_init, \
.cbc = ccmode_cbc_decrypt, \
.custom = (ECB) \
}

/* Use this to statically initialize a ccmode_cbc object for encryption. */
#define CCMODE_FACTORY_CBC_ENCRYPT(ECB) { \
.size = ccn_sizeof_size(sizeof(struct _ccmode_cbc_key)) + ccn_sizeof_size((ECB)->block_size) + ccn_sizeof_size((ECB)->size), \
.block_size = (ECB)->block_size, \
.init = ccmode_cbc_init, \
.cbc = ccmode_cbc_encrypt, \
.custom = (ECB) \
}

struct _ccmode_cbc_key {
	const struct ccmode_ecb *ecb;
	cc_unit u[];
};

/* Macros for accessing a CCMODE_CBC_KEY.
 *  {
 *  const struct ccmode_ecb *ecb
 *  ccn_unit ecb_key[ecb->n]
 *  } */
#define _CCMODE_CBC_KEY(K)       ((struct _ccmode_cbc_key *)(K))
#define _CCMODE_CBC_KEY_CONST(K) ((const struct _ccmode_cbc_key *)(K))
#define CCMODE_CBC_KEY_ECB(K) (_CCMODE_CBC_KEY(K)->ecb)
#define CCMODE_CBC_KEY_ECB_KEY(K) ((ccecb_ctx *)&_CCMODE_CBC_KEY(K)->u[0])

CC_INLINE
const struct ccmode_ecb *
ccmode_cbc_key_ecb(const cccbc_ctx *K)
{
	return ((const struct _ccmode_cbc_key *)K)->ecb;
}

CC_INLINE
const ccecb_ctx *
ccmode_cbc_key_ecb_key(const cccbc_ctx *K)
{
	return (const ccecb_ctx *)&((const struct _ccmode_cbc_key *)K)->u[0];
}

int ccmode_cfb_init(const struct ccmode_cfb *cfb, cccfb_ctx *ctx,
    size_t rawkey_len, const void *rawkey,
    const void *iv);
int ccmode_cfb_decrypt(cccfb_ctx *ctx, size_t nbytes,
    const void *in, void *out);
int ccmode_cfb_encrypt(cccfb_ctx *ctx, size_t nbytes,
    const void *in, void *out);

/* Use this to statically initialize a ccmode_cfb object for decryption. */
#define CCMODE_FACTORY_CFB_DECRYPT(ECB) { \
.size = ccn_sizeof_size(sizeof(struct _ccmode_cfb_key)) + 2 * ccn_sizeof_size((ECB)->block_size) + ccn_sizeof_size((ECB)->size), \
.block_size = 1, \
.init = ccmode_cfb_init, \
.cfb = ccmode_cfb_decrypt, \
.custom = (ECB) \
}

/* Use this to statically initialize a ccmode_cfb object for encryption. */
#define CCMODE_FACTORY_CFB_ENCRYPT(ECB) { \
.size = ccn_sizeof_size(sizeof(struct _ccmode_cfb_key)) + 2 * ccn_sizeof_size((ECB)->block_size) + ccn_sizeof_size((ECB)->size), \
.block_size = 1, \
.init = ccmode_cfb_init, \
.cfb = ccmode_cfb_encrypt, \
.custom = (ECB) \
}

struct _ccmode_cfb_key {
	const struct ccmode_ecb *ecb;
	size_t pad_len;
	cc_unit u[];
};
/* Macros for accessing a CCMODE_CFB_KEY.
 *  {
 *   const struct ccmode_ecb *ecb
 *   cc_size pad_len;
 *   ccn_unit pad[ecb->block_size / CCN_UNIT_SIZE];
 *   ccn_unit iv[ecb->block_size / CCN_UNIT_SIZE];
 *   ccn_unit ecb_key[ecb->n]
 *  } */
#define _CCMODE_CFB_KEY(K) ((struct _ccmode_cfb_key *)(K))
#define CCMODE_CFB_KEY_ECB(K) (_CCMODE_CFB_KEY(K)->ecb)
#define CCMODE_CFB_KEY_PAD_LEN(K) (_CCMODE_CFB_KEY(K)->pad_len)
#define CCMODE_CFB_KEY_PAD(K) (&_CCMODE_CFB_KEY(K)->u[0])
#define CCMODE_CFB_KEY_IV(K) (&_CCMODE_CFB_KEY(K)->u[ccn_nof_size(CCMODE_CFB_KEY_ECB(K)->block_size)])
#define CCMODE_CFB_KEY_ECB_KEY(K) ((ccecb_ctx *)&_CCMODE_CFB_KEY(K)->u[2 * ccn_nof_size(CCMODE_CFB_KEY_ECB(K)->block_size)])

int ccmode_cfb8_init(const struct ccmode_cfb8 *cfb8, cccfb8_ctx *ctx,
    size_t rawkey_len, const void *rawkey, const void *iv);
int ccmode_cfb8_decrypt(cccfb8_ctx *ctx, size_t nbytes,
    const void *in, void *out);
int ccmode_cfb8_encrypt(cccfb8_ctx *ctx, size_t nbytes,
    const void *in, void *out);

/* Use this to statically initialize a ccmode_cfb8 object for decryption. */
#define CCMODE_FACTORY_CFB8_DECRYPT(ECB) { \
.size = ccn_sizeof_size(sizeof(struct _ccmode_cfb8_key)) + 2 * ccn_sizeof_size((ECB)->block_size) + ccn_sizeof_size((ECB)->size), \
.block_size = 1, \
.init = ccmode_cfb8_init, \
.cfb8 = ccmode_cfb8_decrypt, \
.custom = (ECB) \
}

/* Use this to statically initialize a ccmode_cfb8 object for encryption. */
#define CCMODE_FACTORY_CFB8_ENCRYPT(ECB) { \
.size = ccn_sizeof_size(sizeof(struct _ccmode_cfb8_key)) + 2 * ccn_sizeof_size((ECB)->block_size) + ccn_sizeof_size((ECB)->size), \
.block_size = 1, \
.init = ccmode_cfb8_init, \
.cfb8 = ccmode_cfb8_encrypt, \
.custom = (ECB) \
}

struct _ccmode_cfb8_key {
	const struct ccmode_ecb *ecb;
	cc_unit u[];
};

/* Macros for accessing a CCMODE_CFB8_KEY.
 *  {
 *   const struct ccmode_ecb *ecb
 *   ccn_unit pad[ecb->block_size / CCN_UNIT_SIZE];
 *   ccn_unit iv[ecb->block_size / CCN_UNIT_SIZE];
 *   ccn_unit ecb_key[ecb->n]
 *  } */
#define _CCMODE_CFB8_KEY(K) ((struct _ccmode_cfb8_key *)(K))
#define CCMODE_CFB8_KEY_ECB(K) (_CCMODE_CFB8_KEY(K)->ecb)
#define CCMODE_CFB8_KEY_PAD(K) (&_CCMODE_CFB8_KEY(K)->u[0])
#define CCMODE_CFB8_KEY_IV(K) (&_CCMODE_CFB8_KEY(K)->u[ccn_nof_size(CCMODE_CFB8_KEY_ECB(K)->block_size)])
#define CCMODE_CFB8_KEY_ECB_KEY(K) ((ccecb_ctx *)&_CCMODE_CFB8_KEY(K)->u[2 * ccn_nof_size(CCMODE_CFB8_KEY_ECB(K)->block_size)])

int ccmode_ctr_init(const struct ccmode_ctr *ctr, ccctr_ctx *ctx,
    size_t rawkey_len, const void *rawkey, const void *iv);
int ccmode_ctr_setctr(const struct ccmode_ctr *mode, ccctr_ctx *ctx, const void *ctr);
int ccmode_ctr_crypt(ccctr_ctx *ctx, size_t nbytes,
    const void *in, void *out);

/* Use this to statically initialize a ccmode_ctr object for decryption. */
#define CCMODE_FACTORY_CTR_CRYPT(ECB_ENCRYPT) { \
.size = ccn_sizeof_size(sizeof(struct _ccmode_ctr_key)) + 2 * ccn_sizeof_size((ECB_ENCRYPT)->block_size) + ccn_sizeof_size((ECB_ENCRYPT)->size), \
.block_size = 1, \
.ecb_block_size = (ECB_ENCRYPT)->block_size, \
.init = ccmode_ctr_init, \
.setctr = ccmode_ctr_setctr, \
.ctr = ccmode_ctr_crypt, \
.custom = (ECB_ENCRYPT) \
}

struct _ccmode_ctr_key {
	const struct ccmode_ecb *ecb;
	size_t pad_offset;
	cc_unit u[];
};

/* Macros for accessing a CCMODE_CTR_KEY.
 *  {
 *   const struct ccmode_ecb *ecb
 *   cc_size pad_offset;
 *   ccn_unit pad[ecb->block_size / CCN_UNIT_SIZE];
 *   ccn_unit ctr[ecb->block_size / CCN_UNIT_SIZE];
 *   ccn_unit ecb_key[ecb->n]
 *  } */
#define _CCMODE_CTR_KEY(K) ((struct _ccmode_ctr_key *)(K))
#define CCMODE_CTR_KEY_ECB(K) (_CCMODE_CTR_KEY(K)->ecb)
#define CCMODE_CTR_KEY_PAD_OFFSET(K) (_CCMODE_CTR_KEY(K)->pad_offset)
#define CCMODE_CTR_KEY_PAD(K) (&_CCMODE_CTR_KEY(K)->u[0])
#define CCMODE_CTR_KEY_CTR(K) (&_CCMODE_CTR_KEY(K)->u[ccn_nof_size(CCMODE_CTR_KEY_ECB(K)->block_size)])
#define CCMODE_CTR_KEY_ECB_KEY(K) ((ccecb_ctx *)&_CCMODE_CTR_KEY(K)->u[2 * ccn_nof_size(CCMODE_CTR_KEY_ECB(K)->block_size)])

CC_INLINE int
ccctr_setctr(const struct ccmode_ctr *mode, ccctr_ctx *ctx, const void *ctr)
{
	return mode->setctr(mode, ctx, ctr);
}

int ccmode_ofb_init(const struct ccmode_ofb *ofb, ccofb_ctx *ctx,
    size_t rawkey_len, const void *rawkey,
    const void *iv);
int ccmode_ofb_crypt(ccofb_ctx *ctx, size_t nbytes,
    const void *in, void *out);

/* Use this to statically initialize a ccmode_ofb object. */
#define CCMODE_FACTORY_OFB_CRYPT(ECB) { \
.size = ccn_sizeof_size(sizeof(struct _ccmode_ofb_key)) + ccn_sizeof_size((ECB)->block_size) + ccn_sizeof_size((ECB)->size), \
.block_size = 1, \
.init = ccmode_ofb_init, \
.ofb = ccmode_ofb_crypt, \
.custom = (ECB) \
}

struct _ccmode_ofb_key {
	const struct ccmode_ecb *ecb;
	size_t pad_len;
	cc_unit u[];
};

/* Macros for accessing a CCMODE_OFB_KEY.
 *  {
 *   const struct ccmode_ecb *ecb
 *   cc_size pad_len;
 *   ccn_unit iv[ecb->block_size / CCN_UNIT_SIZE];
 *   ccn_unit ecb_key[ecb->n]
 *  } */
#define _CCMODE_OFB_KEY(K) ((struct _ccmode_ofb_key *)(K))
#define CCMODE_OFB_KEY_ECB(K) (_CCMODE_OFB_KEY(K)->ecb)
#define CCMODE_OFB_KEY_PAD_LEN(K) (_CCMODE_OFB_KEY(K)->pad_len)
#define CCMODE_OFB_KEY_IV(K) (&_CCMODE_OFB_KEY(K)->u[0])
#define CCMODE_OFB_KEY_ECB_KEY(K) ((ccecb_ctx *)&_CCMODE_OFB_KEY(K)->u[ccn_nof_size(CCMODE_OFB_KEY_ECB(K)->block_size)])


int ccmode_xts_init(const struct ccmode_xts *xts, ccxts_ctx *ctx,
    size_t key_nbytes, const void *data_key,
    const void *tweak_key);
void ccmode_xts_key_sched(const struct ccmode_xts *xts, ccxts_ctx *ctx,
    size_t key_nbytes, const void *data_key,
    const void *tweak_key);
void *ccmode_xts_crypt(const ccxts_ctx *ctx, ccxts_tweak *tweak,
    size_t nblocks, const void *in, void *out);
int ccmode_xts_set_tweak(const ccxts_ctx *ctx, ccxts_tweak *tweak,
    const void *iv);

/* Use this to statically initialize a ccmode_xts object for decryption. */
#define CCMODE_FACTORY_XTS_DECRYPT(ECB, ECB_ENCRYPT) { \
.size = ccn_sizeof_size(sizeof(struct _ccmode_xts_key)) + 2 * ccn_sizeof_size((ECB)->size), \
.tweak_size = ccn_sizeof_size(sizeof(struct _ccmode_xts_tweak)) + ccn_sizeof_size(ecb->block_size), \
.block_size = ecb->block_size, \
.init = ccmode_xts_init, \
.key_sched = ccmode_xts_key_sched, \
.set_tweak = ccmode_xts_set_tweak, \
.xts = ccmode_xts_crypt, \
.custom = (ECB), \
.custom1 = (ECB_ENCRYPT), \
.impl = CC_IMPL_AES_XTS_GENERIC, \
}

/* Use this to statically initialize a ccmode_xts object for encryption. */
#define CCMODE_FACTORY_XTS_ENCRYPT(ECB, ECB_ENCRYPT) { \
.size = ccn_sizeof_size(sizeof(struct _ccmode_xts_key)) + 2 * ccn_sizeof_size((ECB)->size), \
.tweak_size = ccn_sizeof_size(sizeof(struct _ccmode_xts_tweak)) + ccn_sizeof_size(ecb->block_size), \
.block_size = ecb->block_size, \
.init = ccmode_xts_init, \
.key_sched = ccmode_xts_key_sched, \
.set_tweak = ccmode_xts_set_tweak, \
.xts = ccmode_xts_crypt, \
.custom = (ECB), \
.custom1 = (ECB_ENCRYPT), \
.impl = CC_IMPL_AES_XTS_GENERIC, \
}

struct _ccmode_xts_key {
	const struct ccmode_ecb *ecb;
	const struct ccmode_ecb *ecb_encrypt;
	cc_unit u[];
};

struct _ccmode_xts_tweak {
	// FIPS requires that for XTS that no more that 2^20 AES blocks may be processed for any given
	// Key, Tweak Key, and tweak combination
	// the bytes_processed field in the context will accumuate the number of blocks processed and
	// will fail the encrypt/decrypt if the size is violated.  This counter will be reset to 0
	// when set_tweak is called.
	size_t  blocks_processed;
	cc_unit u[];
};

/* Macros for accessing a CCMODE_XTS_KEY.
 *  {
 *   const struct ccmode_ecb *ecb
 *   const struct ccmode_ecb *ecb_encrypt
 *   ccn_unit data_key[ecb->size]
 *   ccn_unit tweak_key[ecb_encrypt->size]
 *  } */
#define _CCMODE_XTS_KEY(K) ((struct _ccmode_xts_key *)(K))
#define CCMODE_XTS_KEY_ECB(K) (_CCMODE_XTS_KEY(K)->ecb)
#define CCMODE_XTS_KEY_ECB_ENCRYPT(K) (_CCMODE_XTS_KEY(K)->ecb_encrypt)
#define CCMODE_XTS_KEY_DATA_KEY(K) ((ccecb_ctx *)&_CCMODE_XTS_KEY(K)->u[0])
#define CCMODE_XTS_KEY_TWEAK_KEY(K) ((ccecb_ctx *)&_CCMODE_XTS_KEY(K)->u[ccn_nof_size(CCMODE_XTS_KEY_ECB(K)->size)])

CC_INLINE
const struct ccmode_ecb *
ccmode_xts_key_ecb(const ccxts_ctx *K)
{
	return ((const struct _ccmode_xts_key *)K)->ecb;
}

CC_INLINE
const struct ccmode_ecb *
ccmode_xts_key_ecb_encrypt(const ccxts_ctx *K)
{
	return ((const struct _ccmode_xts_key *)K)->ecb_encrypt;
}

CC_INLINE
const ccecb_ctx *
ccmode_xts_key_data_key(const ccxts_ctx *K)
{
	return (const ccecb_ctx *)&((const struct _ccmode_xts_key *)K)->u[0];
}

CC_INLINE
const ccecb_ctx *
ccmode_xts_key_tweak_key(const ccxts_ctx *K)
{
	return (const ccecb_ctx *)&((const struct _ccmode_xts_key *)K)->u[ccn_nof_size(ccmode_xts_key_ecb(K)->size)];
}

/* Macros for accessing a CCMODE_XTS_TWEAK.
 *  {
 *  size_t  blocks_processed;
 *  uint8_t value[16];
 *  } */
#define _CCMODE_XTS_TWEAK(T) ((struct _ccmode_xts_tweak *)(T))
#define CCMODE_XTS_TWEAK_BLOCK_PROCESSED(T)(_CCMODE_XTS_TWEAK(T)->blocks_processed)
#define CCMODE_XTS_TWEAK_VALUE(T) (_CCMODE_XTS_TWEAK(T)->u)

#define CCMODE_STATE_INIT 2     //first call to init
#define CCMODE_STATE_IV_START 3 //first call to set_iv

#define CCMODE_STATE_IV_CONT CCMODE_STATE_IV_START

#define CCMODE_STATE_AAD     4
#define CCMODE_STATE_TEXT    5
#define CCMODE_STATE_NONCE   6
#define CCMODE_STATE_NONCE_NOADD 7

#define CCMODE_CCM_STATE_IV 1
#define CCMODE_STATE_INVALID 255

/* CCM (only NIST approved with AES) */
int ccmode_ccm_init(const struct ccmode_ccm *ccm, ccccm_ctx *ctx,
    size_t rawkey_len, const void *rawkey);
int ccmode_ccm_set_iv(ccccm_ctx *ctx, ccccm_nonce *nonce_ctx, size_t nonce_len, const void *nonce,
    size_t mac_size, size_t auth_len, size_t data_len);
/* internal function */
void ccmode_ccm_macdata(ccccm_ctx *key, ccccm_nonce *nonce_ctx, unsigned new_block, size_t nbytes, const void *in);
/* api function - disallows only mac'd data after data to encrypt was sent */
int ccmode_ccm_cbcmac(ccccm_ctx *ctx, ccccm_nonce *nonce_ctx, size_t nbytes, const void *in);
/* internal function */
void ccmode_ccm_crypt(ccccm_ctx *key, ccccm_nonce *nonce_ctx, size_t nbytes, const void *in, void *out);
int ccmode_ccm_decrypt(ccccm_ctx *ctx, ccccm_nonce *nonce_ctx, size_t nbytes, const void *in,
    void *out);
int ccmode_ccm_encrypt(ccccm_ctx *ctx, ccccm_nonce *nonce_ctx, size_t nbytes, const void *in,
    void *out);
int ccmode_ccm_finalize(ccccm_ctx *key, ccccm_nonce *nonce_ctx, void *mac);
int ccmode_ccm_finalize_and_verify(ccccm_ctx *ctx, ccccm_nonce *nonce_ctx, void *mac);
int ccmode_ccm_reset(ccccm_ctx *key, ccccm_nonce *nonce_ctx);

/* Use this to statically initialize a ccmode_ccm object for decryption. */
#define CCMODE_FACTORY_CCM_DECRYPT(ECB_ENCRYPT) { \
.size = ccn_sizeof_size(sizeof(struct _ccmode_ccm_key)) + ccn_sizeof_size((ECB_ENCRYPT)->block_size) + ccn_sizeof_size((ECB_ENCRYPT)->size), \
.nonce_size = ccn_sizeof_size(sizeof(struct _ccmode_ccm_nonce)), \
.block_size = 1, \
.init = ccmode_ccm_init, \
.set_iv = ccmode_ccm_set_iv, \
.cbcmac = ccmode_ccm_cbcmac, \
.ccm = ccmode_ccm_decrypt, \
.finalize = ccmode_ccm_finalize, \
.reset = ccmode_ccm_reset, \
.custom = (ECB_ENCRYPT), \
.enc_mode = false, \
}

/* Use this to statically initialize a ccmode_ccm object for encryption. */
#define CCMODE_FACTORY_CCM_ENCRYPT(ECB_ENCRYPT) { \
.size = ccn_sizeof_size(sizeof(struct _ccmode_ccm_key)) + ccn_sizeof_size((ECB_ENCRYPT)->block_size) + ccn_sizeof_size((ECB_ENCRYPT)->size), \
.nonce_size = ccn_sizeof_size(sizeof(struct _ccmode_ccm_nonce)), \
.block_size = 1, \
.init = ccmode_ccm_init, \
.set_iv = ccmode_ccm_set_iv, \
.cbcmac = ccmode_ccm_cbcmac, \
.ccm = ccmode_ccm_encrypt, \
.finalize = ccmode_ccm_finalize, \
.reset = ccmode_ccm_reset, \
.custom = (ECB_ENCRYPT), \
.enc_mode = true, \
}

struct _ccmode_ccm_key {
	const struct ccmode_ecb *ecb;
	cc_unit u[];
};

/* Macros for accessing a CCMODE_CCM_KEY. */
#define _CCMODE_CCM_KEY(K) ((struct _ccmode_ccm_key *)(K))
#define CCMODE_CCM_KEY_ECB(K) (_CCMODE_CCM_KEY(K)->ecb)
#define CCMODE_CCM_KEY_ECB_KEY(K) ((ccecb_ctx *)&_CCMODE_CCM_KEY(K)->u[0])

#define _CCMODE_CCM_NONCE(N) ((struct _ccmode_ccm_nonce *)(N))
#define CCMODE_CCM_KEY_MAC(N) (_CCMODE_CCM_NONCE(N)->MAC)
#define CCMODE_CCM_KEY_A_I(N) (_CCMODE_CCM_NONCE(N)->A_i)
#define CCMODE_CCM_KEY_B_I(N) (_CCMODE_CCM_NONCE(N)->B_i)
#define CCMODE_CCM_KEY_PAD_LEN(N) (_CCMODE_CCM_NONCE(N)->buflen)
#define CCMODE_CCM_KEY_PAD(N) (_CCMODE_CCM_NONCE(N)->buf)
#define CCMODE_CCM_KEY_MAC_LEN(N) (_CCMODE_CCM_NONCE(N)->mac_size)
#define CCMODE_CCM_KEY_NONCE_LEN(N) (_CCMODE_CCM_NONCE(N)->nonce_size)
#define CCMODE_CCM_KEY_AUTH_LEN(N) (_CCMODE_CCM_NONCE(N)->b_i_len)

int ccmode_omac_decrypt(ccomac_ctx *ctx, size_t nblocks,
    const void *tweak, const void *in, void *out);
int ccmode_omac_encrypt(ccomac_ctx *ctx, size_t nblocks,
    const void *tweak, const void *in, void *out);

/* Create a omac key from a omac mode object.  The tweak_len here
 *  determines how long the tweak is in bytes, for each subsequent call to
 *  ccmode_omac->omac().
 *  key must point to at least sizeof(CCMODE_OMAC_KEY(ecb)) bytes of free
 *  storage. */
int ccmode_omac_init(const struct ccmode_omac *omac, ccomac_ctx *ctx,
    size_t tweak_len, size_t rawkey_len,
    const void *rawkey);

/* Use this to statically initialize a ccmode_omac object for decryption. */
#define CCMODE_FACTORY_OMAC_DECRYPT(ECB) { \
.size = ccn_sizeof_size(sizeof(struct _ccmode_omac_key)) + 2 * ccn_sizeof_size((ECB)->size), \
.block_size = (ECB)->block_size, \
.init = ccmode_omac_init, \
.omac = ccmode_omac_decrypt, \
.custom = (ECB) \
}

/* Use this to statically initialize a ccmode_omac object for encryption. */
#define CCMODE_FACTORY_OMAC_ENCRYPT(ECB) { \
.size = ccn_sizeof_size(sizeof(struct _ccmode_omac_key)) + 2 * ccn_sizeof_size((ECB)->size), \
.block_size = (ECB)->block_size, \
.init = ccmode_omac_init, \
.omac = ccmode_omac_encrypt, \
.custom = (ECB) \
}

struct _ccmode_omac_key {
	const struct ccmode_ecb *ecb;
	size_t tweak_len;
	cc_unit u[];
};

/* Macros for accessing a CCMODE_OMAC_KEY.
 *  {
 *   const struct ccmode_ecb *ecb
 *   cc_size tweak_size;
 *   ccn_unit ecb_key1[ecb->n]
 *   ccn_unit ecb_key2[ecb->n]
 *  } */
#define _CCMODE_OMAC_KEY(K) ((struct _ccmode_omac_key *)(K))
#define CCMODE_OMAC_KEY_ECB(K) (_CCMODE_OMAC_KEY(K)->ecb)
#define CCMODE_OMAC_KEY_TWEAK_LEN(K) (_CCMODE_OMAC_KEY(K)->tweak_len)
#define CCMODE_OMAC_KEY_ECB_KEY(K) ((ccecb_ctx *)&_CCMODE_OMAC_KEY(K)->u[0])

#endif /* _CORECRYPTO_CCMODE_INTERNAL_H_ */
