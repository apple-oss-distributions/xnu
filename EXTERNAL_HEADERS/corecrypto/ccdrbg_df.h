/* Copyright (c) (2021,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCDRBG_DF_H_
#define _CORECRYPTO_CCDRBG_DF_H_

#include <corecrypto/cc.h>
#include <corecrypto/ccmode_impl.h>

// This is an interface for derivation functions for DRBGs to convert
// high-entropy inputs into key material. Because this interface is
// intended for internal usage, we declare only the type names and
// initialization functions here.

typedef struct ccdrbg_df_ctx ccdrbg_df_ctx_t;

struct ccdrbg_df_ctx {
    int (*derive_keys)(const ccdrbg_df_ctx_t *ctx,
                       size_t inputs_count,
                       const cc_iovec_t *inputs,
                       size_t keys_nbytes,
                       void *keys);
};

// This is a block-cipher-based instantiation of the derivation
// function for use in the CTR-DRBG.

typedef struct ccdrbg_df_bc_ctx ccdrbg_df_bc_ctx_t;

struct ccdrbg_df_bc_ctx {
    ccdrbg_df_ctx_t df_ctx;
    const struct ccmode_cbc *cbc_info;
    size_t key_nbytes;

    // See ccmode_impl.h.
    cc_ctx_decl_field(cccbc_ctx, CCCBC_MAX_CTX_SIZE, cbc_ctx);
};

/*!
  @function ccdrbg_df_bc_init
  @abstract Initialize a block-cipher-based derivation function
  @param ctx The derivation function context
  @param cbc_info A descriptor for a CBC mode of a block cipher
  @param key_nbytes The length of the key to use in the derivation function

  @discussion Note that a fixed key is used internally, so only the
  key length needs to be specified.
  @return 0 if successful; negative otherwise
*/
CC_WARN_RESULT
CC_NONNULL_ALL
int ccdrbg_df_bc_init(ccdrbg_df_bc_ctx_t *ctx,
                      const struct ccmode_cbc *cbc_info,
                      size_t key_nbytes);

#endif /* _CORECRYPTO_CCDRBG_DF_H_ */
