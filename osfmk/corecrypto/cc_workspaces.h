/* Copyright (c) (2021-2023) Apple Inc. All rights reserved.
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

#ifndef _CORECRYPTO_CC_WORKSPACES_H_
#define _CORECRYPTO_CC_WORKSPACES_H_

CC_PURE size_t sizeof_cc_unit(void);

CC_PURE size_t sizeof_struct_ccbfv_cipher_plain_ctx(void);

CC_PURE size_t sizeof_struct_ccbfv_ciphertext(void);

CC_PURE size_t sizeof_struct_ccbfv_dcrt_plaintext(void);

CC_PURE size_t sizeof_struct_ccbfv_decrypt_ctx(void);

CC_PURE size_t sizeof_struct_ccbfv_encrypt_params(void);

CC_PURE size_t sizeof_struct_ccbfv_galois_key(void);

CC_PURE size_t sizeof_struct_ccbfv_param_ctx(void);

CC_PURE size_t sizeof_struct_ccbfv_plaintext(void);

CC_PURE size_t sizeof_struct_ccbfv_relin_key(void);

CC_PURE size_t sizeof_struct_ccdh_full_ctx(void);

CC_PURE size_t sizeof_struct_ccdh_pub_ctx(void);

CC_PURE size_t sizeof_struct_ccec_full_ctx(void);

CC_PURE size_t sizeof_struct_ccec_pub_ctx(void);

CC_PURE size_t sizeof_struct_ccpolyzp_po2cyc(void);

CC_PURE size_t sizeof_struct_ccpolyzp_po2cyc_base_convert(void);

CC_PURE size_t sizeof_struct_ccpolyzp_po2cyc_block_rng_state(void);

CC_PURE size_t sizeof_struct_ccpolyzp_po2cyc_ctx(void);

CC_PURE size_t sizeof_struct_ccpolyzp_po2cyc_ctx_chain(void);

CC_PURE size_t sizeof_struct_ccrns_mul_modulus(void);

CC_PURE size_t sizeof_struct_ccrsa_full_ctx(void);

CC_PURE size_t sizeof_struct_ccrsa_pub_ctx(void);

CC_PURE size_t sizeof_struct_cczp(void);

CC_PURE cc_size CCBFV_CIPHERTEXT_APPLY_GALOIS_WORKSPACE_N(cc_size degree, cc_size num_ctext_moduli);

CC_PURE cc_size CCBFV_CIPHERTEXT_GALOIS_KEY_SWITCH_WORKSPACE_N(cc_size degree, cc_size num_galois_key_moduli);

CC_PURE cc_size CCBFV_CIPHERTEXT_PLAINTEXT_ADD_WORKSPACE_N(cc_size degree);

CC_PURE cc_size CCBFV_CIPHERTEXT_COEFF_PLAINTEXT_MUL_WORKSPACE_N(cc_size degree, cc_size num_moduli);

CC_PURE cc_size CCBFV_CIPHERTEXT_EVAL_PLAINTEXT_MUL_WORKSPACE_N(cc_size degree, cc_size num_moduli);

CC_PURE cc_size CCBFV_CIPHERTEXT_ROTATE_ROWS_LEFT_WORKSPACE_N(cc_size degree, cc_size num_ctext_moduli);

CC_PURE cc_size CCBFV_CIPHERTEXT_ROTATE_ROWS_RIGHT_WORKSPACE_N(cc_size degree, cc_size num_ctext_moduli);

CC_PURE cc_size CCBFV_CIPHERTEXT_SWAP_COLUMNS_WORKSPACE_N(cc_size degree, cc_size num_ctext_moduli);

CC_PURE cc_size CCBFV_CIPHER_PLAIN_CTX_INIT_WORKSPACE_N(cc_size num_moduli);

CC_PURE cc_size CCBFV_DECODE_SIMD_INT64_WORKSPACE_N(cc_size degree, cc_size num_moduli);

CC_PURE cc_size CCBFV_DECODE_SIMD_UINT64_WORKSPACE_N(cc_size degree, cc_size num_moduli);

CC_PURE cc_size CCBFV_DECRYPT_WORKSPACE_N(cc_size degree, cc_size num_moduli);

CC_PURE cc_size CCBFV_DESERIALIZE_SEEDED_CIPHERTEXT_EVAL_WORKSPACE_N(cc_size degree);

CC_PURE cc_size CCBFV_ENCRYPT_SYMMETRIC_WORKSPACE_N(cc_size degree, cc_size num_moduli);

CC_PURE cc_size CCBFV_ENCRYPT_ZERO_SYMMETRIC_COEFF_WORKSPACE_N(cc_size degree, cc_size num_moduli);

CC_PURE cc_size CCBFV_ENCRYPT_ZERO_SYMMETRIC_EVAL_WORKSPACE_N(cc_size degree, cc_size num_moduli);

CC_PURE cc_size CCBFV_ENCRYPT_ZERO_SYMMETRIC_HELPER_WORKSPACE_N(cc_size degree, cc_size nmoduli);

CC_PURE cc_size CCBFV_GALOIS_KEY_GENERATE_SINGLE_WORKSPACE_N(cc_size degree, cc_size num_moduli);

CC_PURE cc_size CCBFV_GALOIS_KEY_GENERATE_WORKSPACE_N(cc_size degree, cc_size num_moduli);

CC_PURE cc_size CCBFV_RELIN_KEY_GENERATE_WORKSPACE_N(cc_size degree, cc_size num_moduli);

CC_PURE cc_size CCDH_POWER_BLINDED_WORKSPACE_N(cc_size n);

CC_PURE cc_size CCEC_AFFINIFY_POINTS_WORKSPACE_N(cc_size n, cc_size npoints);

CC_PURE cc_size CCN_P224_INV_ASM_WORKSPACE_N(cc_size n);

CC_PURE cc_size CCN_P256_INV_ASM_WORKSPACE_N(cc_size n);

CC_PURE cc_size CCN_P384_INV_ASM_WORKSPACE_N(cc_size n);

CC_PURE cc_size CCN_SQR_WORKSPACE_N(cc_size n);

CC_PURE cc_size CCPOLYZP_PO2CYC_BASE_CONVERT_DIVIDE_AND_ROUND_WORKSPACE_N(cc_size degree, cc_size num_moduli);

CC_PURE cc_size CCPOLYZP_PO2CYC_BASE_CONVERT_INIT_PUNC_PROD_WORKSPACE_N(cc_size num_moduli);

CC_PURE cc_size CCPOLYZP_PO2CYC_BASE_CONVERT_INIT_WORKSPACE_N(cc_size num_moduli);

CC_PURE cc_size CCPOLYZP_PO2CYC_CTX_Q_PROD_WORKSPACE_N(cc_size num_moduli);

CC_PURE cc_size CCPOLYZP_PO2CYC_CTX_WORKSPACE_N(cc_size degree);

CC_PURE cc_size CCPOLYZP_PO2CYC_CTX_INIT_WORKSPACE_N(cc_size n);

CC_PURE cc_size CCPOLYZP_PO2CYC_DESERIALIZE_POLY_WORKSPACE_N(cc_size degree);

CC_PURE cc_size CCPOLYZP_PO2CYC_RANDOM_TERNARY_WORKSPACE_N(cc_size degree);

CC_PURE cc_size CCPOLYZP_PO2CYC_RANDOM_UNIFORM_WORKSPACE_N(cc_size degree);

CC_PURE cc_size CCPOLYZP_PO2CYC_RANDOM_CBD_WORKSPACE_N(cc_size degree);

CC_PURE cc_size CCPOLYZP_PO2CYC_SERIALIZE_POLY_WORKSPACE_N(cc_size degree);

CC_PURE cc_size CCPOLYZP_PO2CYC_WORKSPACE_N(cc_size degree, cc_size num_moduli);

CC_PURE cc_size CCRSA_CRT_POWER_BLINDED_WORKSPACE_N(cc_size n);

#include "cc_workspaces_generated.h"

#endif // _CORECRYPTO_CC_WORKSPACES_H_
