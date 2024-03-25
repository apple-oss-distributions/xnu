/* Copyright (c) (2010-2012,2014-2019,2021,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

/*!
 @header corecrypto/ccdrbg.h
 @abstract The functions provided in ccdrbg.h implement high-level accessors
 to cryptographically secure random numbers.

 */

#ifndef _CORECRYPTO_CCDRBG_H_
#define _CORECRYPTO_CCDRBG_H_

#include <corecrypto/cc.h>
#include <corecrypto/ccdrbg_impl.h>
#include <corecrypto/ccdrbg_df.h>

/*
 * The maximum length of the entropy_input,  additional_input (max_additional_input_length) , personalization string
 * (max_personalization_string_length) and max_number_of_bits_per_request  are implementation dependent
 * but shall fit in a 32 bit register and be be less than or equal to the specified maximum length for the
 * selected DRBG mechanism (NIST 800-90A Section 10).
 */

#define CCDRBG_MAX_ENTROPY_SIZE         ((uint32_t)1<<16)
#define CCDRBG_MAX_ADDITIONALINPUT_SIZE ((uint32_t)1<<16)
#define CCDRBG_MAX_PSINPUT_SIZE         ((uint32_t)1<<16)
#define CCDRBG_MAX_REQUEST_SIZE         ((uint32_t)1<<16) //this is the absolute maximum in NIST 800-90A
#define CCDRBG_RESEED_INTERVAL          ((uint64_t)1<<48) // must be able to fit the NIST maximum of 2^48


/*
 * The entropyLength is forced to be greater or equal than the security strength.
 * Nonce is not forced. It either needs to have 0.5*security strength entropy. Or, a vale that is repeated
 * less than a 0.5*security strength bit random string.
 * see below or NIST  800-90A for the definition of security strength
 */

int ccdrbg_init(const struct ccdrbg_info *info,
                struct ccdrbg_state *drbg,
                size_t entropyLength, const void* entropy,
                size_t nonceLength, const void* nonce,
                size_t psLength, const void* ps);

/*
 *  The entropyLength is forced to be greater or equal than the security strength.
 */
int ccdrbg_reseed(const struct ccdrbg_info *info,
                  struct ccdrbg_state *drbg,
                  size_t entropyLength, const void *entropy,
                  size_t additionalLength, const void *additional);


int ccdrbg_generate(const struct ccdrbg_info *info,
                    struct ccdrbg_state *drbg,
                    size_t dataOutLength, void *dataOut,
                    size_t additionalLength, const void *additional);

void ccdrbg_done(const struct ccdrbg_info *info,
                 struct ccdrbg_state *drbg);

size_t ccdrbg_context_size(const struct ccdrbg_info *info);

/*!
  @function ccdrbg_must_reseed
  @abstract Whether the DRBG requires a reseed to continue generation
  @param info The DRBG implementation descriptor
  @param drbg The DRBG state
  @return true if the DRBG requires reseed; false otherwise

  @discussion In strict FIPS mode, this returns true after a count of
  requests exceeding the DRBG reseed interval of 2^48. When strict
  FIPS mode is disabled, this function always returns false.
*/
bool ccdrbg_must_reseed(const struct ccdrbg_info *info,
                        const struct ccdrbg_state *drbg);


/*
 * NIST SP 800-90 CTR_DRBG
 * the maximum security strengh of drbg equals to the block size of the corresponding ECB.
 */
struct ccdrbg_nistctr_custom {
    const struct ccmode_ctr *ctr_info;
    size_t keylen;
    int strictFIPS;
    const ccdrbg_df_ctx_t *df_ctx;
};

void ccdrbg_factory_nistctr(struct ccdrbg_info *info, const struct ccdrbg_nistctr_custom *custom);

/*
 * NIST SP 800-90 HMAC_DRBG
 * the maximum security strengh of drbg is half of output size of the input hash function and it internally is limited to 256 bits
 */
struct ccdrbg_nisthmac_custom {
    const struct ccdigest_info *di;
    int strictFIPS;
};

void ccdrbg_factory_nisthmac(struct ccdrbg_info *info, const struct ccdrbg_nisthmac_custom *custom);

#endif /* _CORECRYPTO_CCDRBG_H_ */
