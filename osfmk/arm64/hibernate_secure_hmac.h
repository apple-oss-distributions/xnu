/*
 * Copyright (c) 2019-2023 Apple Inc. All rights reserved.
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
#pragma once

#include <sys/cdefs.h>
#include <stdint.h>
#include <stdbool.h>
#include <libkern/crypto/sha2.h>
#include <mach/vm_types.h>
#include <pexpert/arm64/board_config.h>
#if CONFIG_SPTM
#include <arm64/sptm/sptm.h>
#else
#include <arm64/ppl/ppl_hib.h>
#endif /* CONFIG_SPTM */
#include <IOKit/IOHibernatePrivate.h>

__BEGIN_DECLS

/**
 * State representing where in the hibernation process a specific secure HMAC
 * call is taking place.
 */
typedef enum {
	SECURE_HMAC_HIB_NOT_STARTED  = 0x1,
	SECURE_HMAC_HIB_SETUP        = 0x2,
	SECURE_HMAC_HIB_WRITE_IMAGE  = 0x4,
	SECURE_HMAC_HIB_RESTORE      = 0x8
} secure_hmac_hib_state_t;

void secure_hmac_init(void);
vm_address_t secure_hmac_get_reg_base(void);
vm_address_t secure_hmac_get_aes_reg_base(void);
vm_address_t secure_hmac_get_aes_offset(void);

void secure_hmac_hibernate_begin(
	secure_hmac_hib_state_t state,
	uint64_t *io_buffer_pages,
	uint32_t num_io_buffer_pages);
void secure_hmac_hibernate_end(void);

void secure_hmac_reset(secure_hmac_hib_state_t state, bool wired_pages);
int secure_hmac_update_and_compress_page(
	secure_hmac_hib_state_t state,
	ppnum_t page_number,
	const void **uncompressed,
	const void **encrypted,
	void *compressed);
void secure_hmac_final(secure_hmac_hib_state_t state, uint8_t *output, size_t output_len);
uint64_t secure_hmac_fetch_hibseg_and_info(
	/* out */ void *buffer,
	/* in */ uint64_t buffer_len,
	/* out */ IOHibernateHibSegInfo *info);
void secure_hmac_compute_rorgn_hmac(void);
void secure_hmac_fetch_rorgn_sha(uint8_t *output, size_t output_len);
void secure_hmac_fetch_rorgn_hmac(uint8_t *output, size_t output_len);
void secure_hmac_finalize_image(
	const void *image_hash,
	size_t image_hash_len,
	uint8_t *hmac,
	size_t hmac_len);
void secure_hmac_get_io_ranges(const hib_phys_range_t **io_ranges, size_t *num_io_ranges);
#if CONFIG_SPTM
bool hmac_is_io_buffer_page(uint64_t paddr);
#endif

__END_DECLS
