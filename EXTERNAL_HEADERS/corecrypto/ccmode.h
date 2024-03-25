/* Copyright (c) (2010-2012,2014-2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCMODE_H_
#define _CORECRYPTO_CCMODE_H_

#include <corecrypto/cc_config.h>
#include <corecrypto/cc_priv.h>
#include <corecrypto/ccmode_impl.h>
#include <corecrypto/ccmode_siv.h>
#include <corecrypto/ccmode_siv_hmac.h>

CC_PTRCHECK_CAPABLE_HEADER()

/* ECB mode. */

/* Declare a ecb key named _name_.  Pass the size field of a struct ccmode_ecb
   for _size_. */
#define ccecb_ctx_decl(_size_, _name_) cc_ctx_decl_vla(ccecb_ctx, _size_, _name_)
#define ccecb_ctx_clear(_size_, _name_) cc_clear(_size_, _name_)

size_t ccecb_context_size(const struct ccmode_ecb *mode);

size_t ccecb_block_size(const struct ccmode_ecb *mode);

int ccecb_init(const struct ccmode_ecb *mode, ccecb_ctx *ctx, size_t key_len, const void *cc_sized_by(key_len) key);

int ccecb_update(const struct ccmode_ecb *mode, const ccecb_ctx *ctx, size_t nblocks, const void *cc_indexable in, void *cc_indexable out);

cc_ptrcheck_unavailable_r(ccecb_one_shot_explicit)
int ccecb_one_shot(const struct ccmode_ecb *mode,
                   size_t key_len,
                   const void *cc_sized_by(key_len) key,
                   size_t nblocks,
                   const void *cc_unsafe_indexable in,
                   void *cc_unsafe_indexable out);

int ccecb_one_shot_explicit(const struct ccmode_ecb *mode,
                            size_t key_len,
                            size_t block_size,
                            size_t nblocks,
                            const void *cc_sized_by(key_len) key,
                            const void *cc_sized_by(block_size * nblocks) in,
                            void *cc_sized_by(block_size * nblocks) out);

/* CBC mode. */

/* Declare a cbc key named _name_.  Pass the size field of a struct ccmode_cbc
   for _size_. */
#define cccbc_ctx_decl(_size_, _name_) cc_ctx_decl_vla(cccbc_ctx, _size_, _name_)
#define cccbc_ctx_clear(_size_, _name_) cc_clear(_size_, _name_)

/* Declare a cbc iv tweak named _name_.  Pass the blocksize field of a
   struct ccmode_cbc for _size_. */
#define cccbc_iv_decl(_size_, _name_) cc_ctx_decl_vla(cccbc_iv, _size_, _name_)
#define cccbc_iv_clear(_size_, _name_) cc_clear(_size_, _name_)

/* Actual symmetric algorithm implementation can provide you one of these.

   Alternatively you can create a ccmode_cbc instance from any ccmode_ecb
   cipher.  To do so, statically initialize a struct ccmode_cbc using the
   CCMODE_FACTORY_CBC_DECRYPT or CCMODE_FACTORY_CBC_ENCRYPT macros.
   Alternatively you can dynamically initialize a struct ccmode_cbc
   ccmode_factory_cbc_decrypt() or ccmode_factory_cbc_encrypt(). */

size_t cccbc_context_size(const struct ccmode_cbc *mode);

size_t cccbc_block_size(const struct ccmode_cbc *mode);

int cccbc_init(const struct ccmode_cbc *mode, cccbc_ctx *ctx, size_t key_len, const void *cc_sized_by(key_len) key);

int cccbc_copy_iv(cccbc_iv *cc_sized_by(len) iv_ctx, const void *cc_sized_by(len) iv, size_t len);
int cccbc_clear_iv(cccbc_iv *cc_sized_by(len) iv_ctx, size_t len);

cc_ptrcheck_unavailable() // Use cccbc_copy_iv() or cccbc_clear_iv() directly.
int cccbc_set_iv(const struct ccmode_cbc *mode, cccbc_iv *iv_ctx, const void *iv);

int cccbc_update(const struct ccmode_cbc *mode, const cccbc_ctx *ctx, cccbc_iv *iv, size_t nblocks, const void *cc_indexable in, void *cc_indexable out);

cc_ptrcheck_unavailable_r(cccbc_one_shot_explicit)
int cccbc_one_shot(const struct ccmode_cbc *mode,
                   size_t key_len,
                   const void *cc_sized_by(key_len) key,
                   const void *iv,
                   size_t nblocks,
                   const void *cc_unsafe_indexable in,
                   void *cc_unsafe_indexable out);

int cccbc_one_shot_explicit(const struct ccmode_cbc *mode,
                            size_t key_len,
                            size_t iv_len,
                            size_t block_size,
                            size_t nblocks,
                            const void *cc_sized_by(key_len) key,
                            const void *cc_sized_by(iv_len) iv,
                            const void *cc_sized_by(block_size * nblocks) in,
                            void *cc_sized_by(block_size * nblocks) out);

/* CFB mode. */

/* Declare a cfb key named _name_.  Pass the size field of a struct ccmode_cfb
   for _size_. */
#define cccfb_ctx_decl(_size_, _name_) cc_ctx_decl_vla(cccfb_ctx, _size_, _name_)
#define cccfb_ctx_clear(_size_, _name_) cc_clear(_size_, _name_)

size_t cccfb_context_size(const struct ccmode_cfb *mode);

size_t cccfb_block_size(const struct ccmode_cfb *mode);

int cccfb_init(const struct ccmode_cfb *mode, cccfb_ctx *ctx, size_t key_len, const void *cc_sized_by(key_len) key, const void *cc_indexable iv);

int cccfb_update(const struct ccmode_cfb *mode, cccfb_ctx *ctx, size_t nbytes, const void *cc_sized_by(nbytes) in, void *cc_sized_by(nbytes) out);

int cccfb_one_shot(const struct ccmode_cfb *mode,
                   size_t key_len,
                   const void *cc_sized_by(key_len) key,
                   const void *cc_indexable iv,
                   size_t nbytes,
                   const void *cc_sized_by(nbytes) in,
                   void *cc_sized_by(nbytes) out);

/* CFB8 mode. */

/* Declare a cfb8 key named _name_.  Pass the size field of a struct ccmode_cfb8
 for _size_. */
#define cccfb8_ctx_decl(_size_, _name_) cc_ctx_decl_vla(cccfb8_ctx, _size_, _name_)
#define cccfb8_ctx_clear(_size_, _name_) cc_clear(_size_, _name_)

size_t cccfb8_context_size(const struct ccmode_cfb8 *mode);

size_t cccfb8_block_size(const struct ccmode_cfb8 *mode);

int cccfb8_init(const struct ccmode_cfb8 *mode, cccfb8_ctx *ctx, size_t key_len, const void *cc_sized_by(key_len) key, const void *cc_indexable iv);

int cccfb8_update(const struct ccmode_cfb8 *mode, cccfb8_ctx *ctx, size_t nbytes, const void *cc_sized_by(nbytes) in, void *cc_sized_by(nbytes) out);

int cccfb8_one_shot(const struct ccmode_cfb8 *mode,
                    size_t key_len,
                    const void *cc_sized_by(key_len) key,
                    const void *cc_indexable iv,
                    size_t nbytes,
                    const void *cc_sized_by(nbytes) in,
                    void *cc_sized_by(nbytes) out);

/* CTR mode. */

/* Declare a ctr key named _name_.  Pass the size field of a struct ccmode_ctr
 for _size_. */
#define ccctr_ctx_decl(_size_, _name_) cc_ctx_decl_vla(ccctr_ctx, _size_, _name_)
#define ccctr_ctx_clear(_size_, _name_) cc_clear(_size_, _name_)

/* This is Integer Counter Mode: The IV is the initial value of the counter
 that is incremented by 1 for each new block. Use the mode flags to select
 if the IV/Counter is stored in big or little endian. */

size_t ccctr_context_size(const struct ccmode_ctr *mode);

size_t ccctr_block_size(const struct ccmode_ctr *mode);

int ccctr_init(const struct ccmode_ctr *mode, ccctr_ctx *ctx, size_t key_len, const void *cc_sized_by(key_len) key, const void *cc_indexable iv);

int ccctr_update(const struct ccmode_ctr *mode, ccctr_ctx *ctx, size_t nbytes, const void *cc_sized_by(nbytes) in, void *cc_sized_by(nbytes) out);

int ccctr_one_shot(const struct ccmode_ctr *mode,
                   size_t key_len,
                   const void *cc_sized_by(key_len) key,
                   const void *cc_indexable iv,
                   size_t nbytes,
                   const void *cc_sized_by(nbytes) in,
                   void *cc_sized_by(nbytes) out);

/* OFB mode. */

/* Declare a ofb key named _name_.  Pass the size field of a struct ccmode_ofb
 for _size_. */
#define ccofb_ctx_decl(_size_, _name_) cc_ctx_decl_vla(ccofb_ctx, _size_, _name_)
#define ccofb_ctx_clear(_size_, _name_) cc_clear(_size_, _name_)

size_t ccofb_context_size(const struct ccmode_ofb *mode);

size_t ccofb_block_size(const struct ccmode_ofb *mode);

int ccofb_init(const struct ccmode_ofb *mode, ccofb_ctx *ctx, size_t key_len, const void *cc_sized_by(key_len) key, const void *cc_indexable iv);

int ccofb_update(const struct ccmode_ofb *mode, ccofb_ctx *ctx, size_t nbytes, const void *cc_sized_by(nbytes) in, void *cc_sized_by(nbytes) out);

int ccofb_one_shot(const struct ccmode_ofb *mode,
                   size_t key_len,
                   const void *cc_sized_by(key_len) key,
                   const void *cc_indexable iv,
                   size_t nbytes,
                   const void *cc_sized_by(nbytes) in,
                   void *cc_sized_by(nbytes) out);

/* XTS mode. */

/* Declare a xts key named _name_.  Pass the size field of a struct ccmode_xts
 for _size_. */
#define ccxts_ctx_decl(_size_, _name_) cc_ctx_decl_vla(ccxts_ctx, _size_, _name_)
#define ccxts_ctx_clear(_size_, _name_) cc_clear(_size_, _name_)

/* Declare a xts tweak named _name_.  Pass the tweak_size field of a
   struct ccmode_xts for _size_. */
#define ccxts_tweak_decl(_size_, _name_) cc_ctx_decl_vla(ccxts_tweak, _size_, _name_)
#define ccxts_tweak_clear(_size_, _name_) cc_clear(_size_, _name_)

/* Actual symmetric algorithm implementation can provide you one of these.

 Alternatively you can create a ccmode_xts instance from any ccmode_ecb
 cipher.  To do so, statically initialize a struct ccmode_xts using the
 CCMODE_FACTORY_XTS_DECRYPT or CCMODE_FACTORY_XTS_ENCRYPT macros. Alternatively
 you can dynamically initialize a struct ccmode_xts
 ccmode_factory_xts_decrypt() or ccmode_factory_xts_encrypt(). */

/* NOTE that xts mode does not do cts padding.  It's really an xex mode.
   If you need cts padding use the ccpad_xts_encrypt and ccpad_xts_decrypt
   functions.   Also note that xts only works for ecb modes with a block_size
   of 16.  */

size_t ccxts_context_size(const struct ccmode_xts *mode);

size_t ccxts_block_size(const struct ccmode_xts *mode);

/*!
 @function   ccxts_init
 @abstract   Initialize an XTS context.

 @param      mode       Descriptor for the mode
 @param      ctx        Context for this instance
 @param      key_nbytes Length of the key arguments in bytes
 @param      data_key   Key for data encryption
 @param      tweak_key  Key for tweak generation

 @result     0 iff successful.

 @discussion For security reasons, the two keys must be different.
 */
int ccxts_init(const struct ccmode_xts *mode, ccxts_ctx *ctx, size_t key_nbytes, const void *cc_sized_by(key_nbytes) data_key, const void *cc_sized_by(key_nbytes) tweak_key);

/*!
 @function   ccxts_set_tweak
 @abstract   Initialize the tweak for a sector.

 @param      mode       Descriptor for the mode
 @param      ctx        Context for this instance
 @param      tweak      Context for the tweak for this sector
 @param      iv         Data used to generate the tweak

 @discussion The IV must be exactly one block in length.
 */
int ccxts_set_tweak(const struct ccmode_xts *mode, ccxts_ctx *ctx, ccxts_tweak *tweak, const void *cc_indexable iv);

/*!
 @function   ccxts_update
 @abstract   Encrypt or decrypt data.

 @param      mode       Descriptor for the mode
 @param      ctx        Context for an instance
 @param      tweak      Context for the tweak for this sector
 @param      nblocks    Length of the data in blocks
 @param      in         Input data
 @param      out        Output buffer

 @result     The updated internal buffer of the tweak context. May be ignored.
  */
void *cc_unsafe_indexable
ccxts_update(const struct ccmode_xts *mode, ccxts_ctx *ctx, ccxts_tweak *tweak, size_t nblocks, const void *cc_indexable in, void *cc_indexable out);

/*!
 @function   ccxts_one_shot
 @abstract   Encrypt or decrypt data in XTS mode.

 @param      mode       Descriptor for the mode
 @param      key_nbytes Length of the key arguments in bytes
 @param      data_key   Key for data encryption
 @param      tweak_key  Key for tweak generation
 @param      iv         Data used to generate the tweak
 @param      nblocks    Length of the data in blocks
 @param      in         Input data
 @param      out        Output buffer

 @result     0 iff successful.

 @discussion For security reasons, the two keys must be different.
 */
int ccxts_one_shot(const struct ccmode_xts *mode,
                   size_t key_nbytes,
                   const void *cc_sized_by(key_nbytes) data_key,
                   const void *cc_sized_by(key_nbytes) tweak_key,
                   const void *cc_unsafe_indexable iv,
                   size_t nblocks,
                   const void *cc_unsafe_indexable in,
                   void *cc_unsafe_indexable out);

/* Authenticated cipher modes. */

/* GCM mode. */

/* Declare a gcm key named _name_.  Pass the size field of a struct ccmode_gcm
 for _size_. */
#define ccgcm_ctx_decl(_size_, _name_) cc_ctx_decl_vla(ccgcm_ctx, _size_, _name_)
#define ccgcm_ctx_clear(_size_, _name_) cc_clear(_size_, _name_)

#define CCGCM_IV_NBYTES 12
#define CCGCM_BLOCK_NBYTES 16

/* (2^32 - 2) blocks */
/* (2^36 - 32) bytes */
/* (2^39 - 256) bits */
/* Exceeding this figure breaks confidentiality and authenticity. */
#define CCGCM_TEXT_MAX_NBYTES ((1ULL << 36) - 32ULL)

size_t ccgcm_context_size(const struct ccmode_gcm *mode);

size_t ccgcm_block_size(const struct ccmode_gcm *mode);

/*!
 @function   ccgcm_init
 @abstract   Initialize a GCM context.

 @param      mode       Descriptor for the mode
 @param      ctx        Context for this instance
 @param      key_nbytes Length of the key in bytes
 @param      key        Key for the underlying blockcipher (AES)

 @result     0 iff successful.

 @discussion The correct sequence of calls is:

 @code ccgcm_init(...)
 ccgcm_set_iv(...)
 ccgcm_aad(...)       (may be called zero or more times)
 ccgcm_update(...)    (may be called zero or more times)
 ccgcm_finalize(...)

 To reuse the context for additional encryptions, follow this sequence:

 @code ccgcm_reset(...)
 ccgcm_set_iv(...)
 ccgcm_aad(...)       (may be called zero or more times)
 ccgcm_update(...)    (may be called zero or more times)
 ccgcm_finalize(...)

 @warning The key-IV pair must be unique per encryption. The IV must be nonzero in length.

 @warning It is not permitted to call @p ccgcm_inc_iv after initializing the cipher via the @p ccgcm_init interface. Nonzero is
 returned in the event of an improper call sequence.

 @warning This function is not FIPS-compliant. Use @p ccgcm_init_with_iv instead.
 */
int ccgcm_init(const struct ccmode_gcm *mode, ccgcm_ctx *ctx, size_t key_nbytes, const void *cc_sized_by(key_nbytes) key);

/*!
 @function   ccgcm_init_with_iv
 @abstract   Initialize a GCM context to manage IVs internally.

 @param      mode       Descriptor for the mode
 @param      ctx        Context for this instance
 @param      key_nbytes Length of the key in bytes
 @param      key        Key for the underlying blockcipher (AES)
 @param      iv         IV for the first encryption

 @result     0 iff successful.

 @discussion The correct sequence of calls is:

 @code ccgcm_init_with_iv(...)
 ccgcm_aad(...)       (may be called zero or more times)
 ccgcm_update(...)    (may be called zero or more times)
 ccgcm_finalize(...)

 To reuse the context for additional encryptions, follow this sequence:

 @code ccgcm_reset(...)
 ccgcm_inc_iv(...)
 ccgcm_aad(...)       (may be called zero or more times)
 ccgcm_update(...)    (may be called zero or more times)
 ccgcm_finalize(...)

 The IV must be exactly 12 bytes in length.

 Internally, the IV is treated as a four-byte salt followed by an eight-byte counter. This is to match the behavior of certain
 protocols (e.g. TLS). In the call to @p ccgcm_inc_iv, the counter component will be interpreted as a big-endian, unsigned value
 and incremented in place.

 @warning It is not permitted to call @p ccgcm_set_iv after initializing the cipher via the @p ccgcm_init_with_iv interface.
 Nonzero is returned in the event of an improper call sequence.

 @warning The security of GCM depends on the uniqueness of key-IV pairs. To avoid key-IV repetition, callers should not initialize
 multiple contexts with the same key material via the @p ccgcm_init_with_iv interface.
 */
int ccgcm_init_with_iv(const struct ccmode_gcm *mode, ccgcm_ctx *ctx, size_t key_nbytes, const void *cc_sized_by(key_nbytes) key, const void *cc_unsafe_indexable iv);

/*!
 @function   ccgcm_set_iv
 @abstract   Set the IV for encryption.

 @param      mode       Descriptor for the mode
 @param      ctx        Context for this instance
 @param      iv_nbytes  Length of the IV in bytes
 @param      iv         Initialization vector

 @result     0 iff successful.

 @discussion Set the initialization vector for encryption.

 @warning The key-IV pair must be unique per encryption. The IV must be nonzero in length.

 In stateful protocols, if each packet exposes a guaranteed-unique value, it is recommended to format this as a 12-byte value for
 use as the IV.

 In stateless protocols, it is recommended to choose a 16-byte value using a cryptographically-secure pseudorandom number
 generator (e.g. @p ccrng).

 @warning This function may not be used after initializing the cipher via @p ccgcm_init_with_iv. Nonzero is returned in the event
 of an improper call sequence.

 @warning This function is not FIPS-compliant. Use @p ccgcm_init_with_iv instead.
 */
int ccgcm_set_iv(const struct ccmode_gcm *mode, ccgcm_ctx *ctx, size_t iv_nbytes, const void *cc_sized_by(iv_nbytes) iv);

/*!
 @function   ccgcm_set_iv_legacy
 @abstract   Set the IV for encryption.

 @param      mode       Descriptor for the mode
 @param      ctx        Context for this instance
 @param      iv_nbytes  Length of the IV in bytes
 @param      iv         Initialization vector

 @result     0 iff successful.

 @discussion Identical to @p ccgcm_set_iv except that it allows zero-length IVs.

 @warning Zero-length IVs nullify the authenticity guarantees of GCM.

 @warning Do not use this function in new applications.
 */
int ccgcm_set_iv_legacy(const struct ccmode_gcm *mode, ccgcm_ctx *ctx, size_t iv_nbytes, const void *cc_sized_by(iv_nbytes) iv);

/*!
 @function   ccgcm_inc_iv
 @abstract   Increment the IV for another encryption.

 @param      mode       Descriptor for the mode
 @param      ctx        Context for this instance
 @param      iv         Updated initialization vector

 @result     0 iff successful.

 @discussion Updates the IV internally for another encryption.

 Internally, the IV is treated as a four-byte salt followed by an eight-byte counter. This is to match the behavior of certain
 protocols (e.g. TLS). The counter component is interpreted as a big-endian, unsigned value and incremented in place.

 The updated IV is copied to @p iv. This is to support protocols that require part of the IV to be specified explicitly in each
 packet (e.g. TLS).

 @warning This function may be used only after initializing the cipher via @p ccgcm_init_with_iv.
 */
int ccgcm_inc_iv(const struct ccmode_gcm *mode, ccgcm_ctx *ctx, void *cc_unsafe_indexable iv);

/*!
 @function   ccgcm_aad
 @abstract   Authenticate additional data.

 @param      mode               Descriptor for the mode
 @param      ctx                Context for this instance
 @param      nbytes             Length of the additional data in bytes
 @param      additional_data    Additional data to authenticate

 @result     0 iff successful.

 @discussion This is typically used to authenticate data that cannot be encrypted (e.g. packet headers).

 This function may be called zero or more times.
 */
int ccgcm_aad(const struct ccmode_gcm *mode, ccgcm_ctx *ctx, size_t nbytes, const void *cc_sized_by(nbytes) additional_data);

/*!
 @function   ccgcm_gmac

 @discussion ccgcm_gmac is deprecated. Use the drop-in replacement 'ccgcm_aad' instead.
 */
int ccgcm_gmac(const struct ccmode_gcm *mode, ccgcm_ctx *ctx, size_t nbytes, const void *cc_sized_by(nbytes) in)
cc_deprecate_with_replacement("ccgcm_aad", 13.0, 10.15, 13.0, 6.0, 4.0);

/*!
 @function   ccgcm_update
 @abstract   Encrypt or decrypt data.

 @param      mode       Descriptor for the mode
 @param      ctx        Context for this instance
 @param      nbytes     Length of the data in bytes
 @param      in         Input plaintext or ciphertext
 @param      out        Output ciphertext or plaintext

 @result     0 iff successful.

 @discussion In-place processing is supported.

 This function may be called zero or more times.
 */
int ccgcm_update(const struct ccmode_gcm *mode, ccgcm_ctx *ctx, size_t nbytes, const void *cc_sized_by(nbytes) in, void *cc_sized_by(nbytes) out);

/*!
 @function   ccgcm_finalize
 @abstract   Finish processing and authenticate.

 @param      mode       Descriptor for the mode
 @param      ctx        Context for this instance
 @param      tag_nbytes Length of the tag in bytes
 @param      tag        Authentication tag

 @result     0 iff successful.

 @discussion Finish processing a packet and generate the authentication tag.

 On encryption, @p tag is purely an output parameter. The generated tag is written to @p tag.

 On decryption, @p tag is both an input and an output parameter. Well-behaved callers should provide the authentication tag
 generated during encryption. The function will return nonzero if the input tag does not match the generated tag. The generated
 tag will be written into the @p tag buffer whether authentication succeeds or fails.

 @warning The generated tag is written to @p tag to support legacy applications that perform authentication manually. Do not
 follow this usage pattern in new applications. Rely on the function's error code to verify authenticity.
 */
int ccgcm_finalize(const struct ccmode_gcm *mode, ccgcm_ctx *ctx, size_t tag_nbytes, void *cc_sized_by(tag_nbytes) tag);

/*!
 @function   ccgcm_reset
 @abstract   Reset the context for another encryption.

 @param      mode       Descriptor for the mode
 @param      ctx        Context for this instance

 @result     0 iff successful.

 @discussion Refer to @p ccgcm_init for correct usage.
 */
int ccgcm_reset(const struct ccmode_gcm *mode, ccgcm_ctx *ctx);

/*!
 @function   ccgcm_one_shot
 @abstract   Encrypt or decrypt with GCM.

 @param      mode           Descriptor for the mode
 @param      key_nbytes     Length of the key in bytes
 @param      key            Key for the underlying blockcipher (AES)
 @param      iv_nbytes      Length of the IV in bytes
 @param      iv             Initialization vector
 @param      adata_nbytes   Length of the additional data in bytes
 @param      adata          Additional data to authenticate
 @param      nbytes         Length of the data in bytes
 @param      in             Input plaintext or ciphertext
 @param      out            Output ciphertext or plaintext
 @param      tag_nbytes     Length of the tag in bytes
 @param      tag            Authentication tag

 @result     0 iff successful.

 @discussion Perform GCM encryption or decryption.

 @warning The key-IV pair must be unique per encryption. The IV must be nonzero in length.

 In stateful protocols, if each packet exposes a guaranteed-unique value, it is recommended to format this as a 12-byte value for
 use as the IV.

 In stateless protocols, it is recommended to choose a 16-byte value using a cryptographically-secure pseudorandom number
 generator (e.g. @p ccrng).

 In-place processing is supported.

 On encryption, @p tag is purely an output parameter. The generated tag is written to @p tag.

 On decryption, @p tag is primarily an input parameter. The caller should provide the authentication tag generated during
 encryption. The function will return nonzero if the input tag does not match the generated tag.

 @warning To support legacy applications, @p tag is also an output parameter during decryption. The generated tag is written to @p
 tag. Legacy callers may choose to compare this to the tag generated during encryption. Do not follow this usage pattern in new
 applications.
 */
int ccgcm_one_shot(const struct ccmode_gcm *mode,
                   size_t key_nbytes,
                   const void *cc_sized_by(key_nbytes) key,
                   size_t iv_nbytes,
                   const void *cc_sized_by(iv_nbytes) iv,
                   size_t adata_nbytes,
                   const void *cc_sized_by(adata_nbytes) adata,
                   size_t nbytes,
                   const void *cc_sized_by(nbytes) in,
                   void *cc_sized_by(nbytes) out,
                   size_t tag_nbytes,
                   void *cc_sized_by(tag_nbytes) tag);

/*!
 @function   ccgcm_one_shot_legacy
 @abstract   Encrypt or decrypt with GCM.

 @param      mode           Descriptor for the mode
 @param      key_nbytes     Length of the key in bytes
 @param      key            Key for the underlying blockcipher (AES)
 @param      iv_nbytes      Length of the IV in bytes
 @param      iv             Initialization vector
 @param      adata_nbytes   Length of the additional data in bytes
 @param      adata          Additional data to authenticate
 @param      nbytes         Length of the data in bytes
 @param      in             Input plaintext or ciphertext
 @param      out            Output ciphertext or plaintext
 @param      tag_nbytes     Length of the tag in bytes
 @param      tag            Authentication tag

 @result     0 iff successful.

 @discussion Identical to @p ccgcm_one_shot except that it allows zero-length IVs.

 @warning Zero-length IVs nullify the authenticity guarantees of GCM.

 @warning Do not use this function in new applications.
 */
int ccgcm_one_shot_legacy(const struct ccmode_gcm *mode,
                          size_t key_nbytes,
                          const void *cc_sized_by(key_nbytes) key,
                          size_t iv_nbytes,
                          const void *cc_sized_by(iv_nbytes) iv,
                          size_t adata_nbytes,
                          const void *cc_sized_by(adata_nbytes) adata,
                          size_t nbytes,
                          const void *cc_sized_by(nbytes) in,
                          void *cc_sized_by(nbytes) out,
                          size_t tag_nbytes,
                          void *cc_sized_by(tag_nbytes) tag);

/* CCM */
#define CCM_MAX_TAG_SIZE 16
#define ccccm_ctx_decl(_size_, _name_) cc_ctx_decl_vla(ccccm_ctx, _size_, _name_)
#define ccccm_ctx_clear(_size_, _name_) cc_clear(_size_, _name_)

/* Declare a ccm nonce named _name_.  Pass the mode->nonce_ctx_size for _size_. */
#define ccccm_nonce_decl(_size_, _name_) cc_ctx_decl_vla(ccccm_nonce, _size_, _name_)
#define ccccm_nonce_clear(_size_, _name_) cc_clear(_size_, _name_)

size_t ccccm_context_size(const struct ccmode_ccm *mode);

size_t ccccm_block_size(const struct ccmode_ccm *mode);

/// Initialize a ccm authenticated encryption/decryption mode
/// @param mode mode descriptor
/// @param ctx  context for this instance
/// @param key_len length in bytes of key provided
/// @param key bytes defining key
int ccccm_init(const struct ccmode_ccm *mode, ccccm_ctx *ctx, size_t key_len, const void *cc_sized_by(key_len) key);

/// Set the initialization value/nonce for the ccm authenticated encryption/decryption
/// @param mode mode descriptor
/// @param ctx context for this ccm instance
/// @param nonce_ctx  context for this nonce
/// @param nonce_len length in bytes of cmac nonce/iv
/// @param nonce bytes defining none
/// @param mac_size length in bytes of mac tag
/// @param auth_len length in bytes of authenticating data
/// @param data_len length in bytes of plaintext
int ccccm_set_iv(const struct ccmode_ccm *mode,
                 ccccm_ctx *ctx,
                 ccccm_nonce *nonce_ctx,
                 size_t nonce_len,
                 const void *cc_sized_by(nonce_len) nonce,
                 size_t mac_size,
                 size_t auth_len,
                 size_t data_len);

/// (Deprecated) Add associated data to the ccm authenticated encryption/decryption
/// @param mode mode descriptor
/// @param ctx context for this ccm instance
/// @param nonce_ctx  context for this nonce
/// @param nbytes nbytes length in bytes of associated data being provided in this invocation
/// @param in authenticated data being provided in this invocation
int ccccm_cbcmac(const struct ccmode_ccm *mode, ccccm_ctx *ctx, ccccm_nonce *nonce_ctx, size_t nbytes, const void *cc_sized_by(nbytes) in);

///Add associated data to the ccm authenticated encryption/decryption
/// @param mode mode descriptor
/// @param ctx context for this ccm instance
/// @param nonce_ctx  context for this nonce
/// @param ad_nbytes nbytes length in bytes of associated data being provided in this invocation
/// @param ad authenticated data being provided in this invocation
int ccccm_aad(const struct ccmode_ccm *mode, ccccm_ctx *ctx, ccccm_nonce *nonce_ctx, size_t ad_nbytes, const uint8_t *cc_sized_by(ad_nbytes) ad);

/// Add plaintext data to the ccm authenticated encryption/decryption
/// @param mode mode descriptor
/// @param ctx context for this ccm instance
/// @param nonce_ctx  context for this nonce
/// @param nbytes length in bytes of both plaintext and encrypted plaintext
/// @param in In encryption mode plaintext data, in decryption mode encrypted plaintext data.
/// @param out in encryption mode resulting encrypted plaintext data. In decryption mode resulting plaintext data
int ccccm_update(const struct ccmode_ccm *mode, ccccm_ctx *ctx, ccccm_nonce *nonce_ctx, size_t nbytes, const void *cc_sized_by(nbytes) in, void *cc_sized_by(nbytes) out);

/// Add plaintext data to the ccm authenticated encryption
/// @param mode mode descriptor
/// @param ctx context for this ccm instance
/// @param nonce_ctx  context for this nonce
/// @param nbytes length in bytes of both plaintext and encrypted plaintext
/// @param plaintext In encryption mode plaintext data, in decryption mode encrypted plaintext data.
/// @param encrypted_plaintext in encryption mode resulting encrypted plaintext data. In decryption mode resulting plaintext data
int ccccm_encrypt(const struct ccmode_ccm *mode, ccccm_ctx *ctx, ccccm_nonce *nonce_ctx, size_t nbytes, const uint8_t *cc_sized_by(nbytes) plaintext, uint8_t *cc_sized_by(nbytes) encrypted_plaintext);

/// Add ciphertext data to the ccm authenticated decryption
/// @param mode mode descriptor
/// @param ctx context for this ccm instance
/// @param nonce_ctx  context for this nonce
/// @param nbytes length in bytes of both plaintext and encrypted plaintext
/// @param encrypted_plaintext In encryption mode plaintext data, in decryption mode encrypted plaintext data.
/// @param plaintext in encryption mode resulting encrypted plaintext data. In decryption mode resulting plaintext data
int ccccm_decrypt(const struct ccmode_ccm *mode, ccccm_ctx *ctx, ccccm_nonce *nonce_ctx, size_t nbytes, const uint8_t *cc_sized_by(nbytes) encrypted_plaintext, uint8_t *cc_sized_by(nbytes) plaintext);


/// (Deprecated) Compute tag for ccm
/// @param mode mode descriptor
/// @param ctx context for this ccm instance
/// @param nonce_ctx  context for this nonce
/// @param mac tag portion of ciphertext that is computed from ccm MAC.
/// @discussion This is being deprecated, as it requires the caller to manually verify that the returned mac tag is correct when decrypting. Please use ccccm_finalize_and_verify instead.
int ccccm_finalize(const struct ccmode_ccm *mode, ccccm_ctx *ctx, ccccm_nonce *nonce_ctx, void *cc_indexable mac);

/// Ends encryption and computes tag when in encryption mode
/// @param mode mode descriptor
/// @param ctx context for this ccm instance
/// @param nonce_ctx  context for this nonce
/// @param mac For encryption mode the resulting mac tag portion of the ciphertext is copied to this buffer. For decryption mode, it provides an input of the expected tag in the ciphertext
/// @return For decryption returns CCERR_OK if the provided mac matches the computed mac, and otherwise returns CCMODE_INTEGRITY_FAILURE.
int ccccm_finalize_and_generate_tag(const struct ccmode_ccm *mode, ccccm_ctx *ctx, ccccm_nonce *nonce_ctx, uint8_t *cc_indexable mac);

/// Ends decryption and verifies tag when in decryption mode
/// @param mode mode descriptor
/// @param ctx context for this ccm instance
/// @param nonce_ctx  context for this nonce
/// @param mac It provides an input of the expected tag in the ciphertext
/// @return Returns CCERR_OK if the provided mac matches the computed mac, and otherwise returns CCMODE_INTEGRITY_FAILURE.
int ccccm_finalize_and_verify_tag(const struct ccmode_ccm *mode, ccccm_ctx *ctx, ccccm_nonce *nonce_ctx, const uint8_t *cc_indexable mac);

/// Resets the state of the encryptor/decryptor, maintaining the key, but clearing the nonce/iv, allowing for a new encryption or decryption
/// @param mode mode descriptor
/// @param ctx context for this ccm instance
/// @param nonce_ctx  context for this nonce
int ccccm_reset(const struct ccmode_ccm *mode, ccccm_ctx *ctx, ccccm_nonce *nonce_ctx);

/// (Deprecated) Encrypts/Decrypts a plaintext/ciphertext using the AEAD CCM mode.
/// @param mode mode descriptor
/// @param key_len key length in bytes
/// @param key buffer holding key
/// @param nonce_len nonce length in bytes
/// @param nonce buffer holding nonce
/// @param nbytes the length of the plaintext and encrypted-plaintext
/// @param in buffer holding plaintext in encryption mode, and encrypted plaintext portion of ciphertext in decryption mode
/// @param out buffer receiving resulting encrypted plaintext in encryption mode, and resulting plaintext in decryption mode
/// @param adata_len length in bytes of associated data
/// @param adata authenticated data being provided in this invocation.
/// @param mac_size length in bytes of CCM mac tag
/// @param mac portion of ciphertext that is computed from ccm MAC.
/// @return This is being deprecated, as it requires the caller to manually  verify that the returned mac tag is correct when decrypting. Please use ccccm_one_shot_with_verify instead
int ccccm_one_shot(const struct ccmode_ccm *mode,
                   size_t key_len,
                   const void *cc_sized_by(key_len) key,
                   size_t nonce_len,
                   const void *cc_sized_by(nonce_len) nonce,
                   size_t nbytes,
                   const void *cc_sized_by(nbytes) in,
                   void *cc_sized_by(nbytes) out,
                   size_t adata_len,
                   const void *cc_sized_by(adata_len) adata,
                   size_t mac_size,
                   void *cc_sized_by(mac_size) mac);

/// Encrypts a plaintext using the AEAD CCM mode, and provides corresponding  mac tag. The encrypted plaintext and tag together are the AEAD ciphertext
/// @param mode mode descriptor
/// @param key_nbytes key length in bytes
/// @param key buffer holding key
/// @param nonce_nbytes nonce length in bytes
/// @param nonce buffer holding nonce
/// @param nbytes  the length of the plaintext and encrypted-plaintext
/// @param plaintext buffer holding plaintext in encryption mode, and encrypted plaintext portion of ciphertext in decryption mode
/// @param encrypted_plaintext buffer receiving resulting encrypted plaintext in encryption mode
/// @param adata_nbytes length in bytes of associated data
/// @param adata authenticated data being provided in this invocation.
/// @param mac_tag_nbytes length in bytes of CCM mac tag
/// @param mac_tag portion of ciphertext that is computed from ccm MAC.
/// @return CERR_OK on successful encryption
int ccccm_one_shot_encrypt(const struct ccmode_ccm *mode,
                             size_t key_nbytes,
                             const uint8_t *cc_sized_by(key_nbytes) key,
                             size_t nonce_nbytes,
                             const uint8_t *cc_sized_by(nonce_nbytes) nonce,
                             size_t nbytes,
                             const uint8_t *cc_sized_by(nbytes) plaintext,
                             uint8_t *cc_sized_by(nbytes) encrypted_plaintext,
                             size_t adata_nbytes,
                             const uint8_t *cc_sized_by(adata_nbytes) adata,
                             size_t mac_tag_nbytes,
                             uint8_t *cc_sized_by(mac_tag_nbytes) mac_tag);

/// Decrypts a ciphertext using the AEAD CCM mode and ensures authenticity of the ciphertext. An AEAD CCM ciphertext consists of encrypted plaintext and mac tag
/// @param mode mode descriptor
/// @param key_nbytes key length in bytes
/// @param key buffer holding key
/// @param nonce_nbytes nonce length in bytes
/// @param nonce buffer holding nonce
/// @param nbytes  the length of the plaintext and encrypted-plaintext
/// @param encrypted_plaintext buffer holding the encrypted plaintext portion of ciphertext
/// @param plaintext buffer receiving resulting plaintext
/// @param adata_nbytes length in bytes of associated data
/// @param adata authenticated data being provided in this invocation.
/// @param mac_tag_nbytes length in bytes of CCM mac tag
/// @param mac_tag portion of ciphertext that is computed from ccm MAC.
/// @return For decryption returns CCERR_OK if the provided mac matches the computed mac, and otherwise returns CCMODE_INTEGRITY_FAILURE.
int ccccm_one_shot_decrypt(const struct ccmode_ccm *mode,
                             size_t key_nbytes,
                             const uint8_t *cc_sized_by(key_nbytes) key,
                             size_t nonce_nbytes,
                             const uint8_t *cc_sized_by(nonce_nbytes) nonce,
                             size_t nbytes,
                             const uint8_t *cc_sized_by(nbytes) encrypted_plaintext,
                             uint8_t *cc_sized_by(nbytes) plaintext,
                             size_t adata_nbytes,
                             const uint8_t *cc_sized_by(adata_nbytes) adata,
                             size_t mac_tag_nbytes,
                             const uint8_t *cc_sized_by(mac_tag_nbytes) mac_tag);

/* OMAC mode. */

/* Declare a omac key named _name_.  Pass the size field of a struct ccmode_omac
 for _size_. */
#define ccomac_ctx_decl(_size_, _name_) cc_ctx_decl_vla(ccomac_ctx, _size_, _name_)
#define ccomac_ctx_clear(_size_, _name_) cc_clear(_size_, _name_)

size_t ccomac_context_size(const struct ccmode_omac *mode);

size_t ccomac_block_size(const struct ccmode_omac *mode);

int ccomac_init(const struct ccmode_omac *mode, ccomac_ctx *ctx, size_t tweak_len, size_t key_len, const void *cc_sized_by(key_len) key);

int ccomac_update(const struct ccmode_omac *mode, ccomac_ctx *ctx, size_t nblocks, const void *tweak, const void *cc_indexable in, void *cc_indexable out);

int ccomac_one_shot(const struct ccmode_omac *mode,
                    size_t tweak_len,
                    size_t key_len,
                    const void *cc_sized_by(key_len) key,
                    const void *cc_sized_by(tweak_len) tweak,
                    size_t nblocks,
                    const void *cc_indexable in,
                    void *cc_indexable out);

#endif /* _CORECRYPTO_CCMODE_H_ */
