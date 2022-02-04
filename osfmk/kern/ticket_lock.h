/*
 * Copyright (c) 2020 Apple Inc. All rights reserved.
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

#ifndef _KERN_TICKET_LOCK_H_
#define _KERN_TICKET_LOCK_H_

#ifndef __ASSEMBLER__
#include <kern/lock_types.h>
#include <kern/lock_group.h>
#endif /* __ASSEMBLER__ */

/*
 * TODO <rdar://problem/72157773>. We do not need to make
 * the header available only to KERNEL_PRIVATE.
 */
#if KERNEL_PRIVATE
#ifndef __ASSEMBLER__

__BEGIN_DECLS

#ifdef MACH_KERNEL_PRIVATE

/*!
 * @typedef hw_lck_ticket_t
 *
 * @discussion
 * This type describes the low level type for a ticket lock.
 * @c lck_ticket_t provides a higher level abstraction
 * that also provides thread ownership information.
 *
 * This lock is meant to be exactly 32bits to be able to replace
 * hw_lock_bit_t locks when needed.
 *
 * This lower level interface supports an @c *_allow_invalid()
 * to implement advanced memory reclamation schemes using sequestering.
 *
 * @c hw_lck_ticket_invalidate() must be used on locks
 * that will be used this way: in addition to make subsequent calls to
 * @c hw_lck_ticket_lock_allow_invalid() to fail, it allows for
 * @c hw_lck_ticket_destroy() to synchronize with callers to
 * @c hw_lck_ticket_lock_allow_invalid() who successfully reserved
 * a ticket but will fail, ensuring the memory can't be freed too early.
 *
 * @note:
 * At the moment, this construct only supports up to 255 CPUs.
 * Supporting more CPUs requires losing the `lck_type` field,
 * and burning the low bit of the cticket/nticket
 * for the "invalidation" feature.
 */
typedef union {
	struct {
		uint8_t lck_type;
		uint8_t lck_valid;
		union {
			struct {
				uint8_t cticket;
				uint8_t nticket;
			};
			uint16_t tcurnext;
		};
	};
	uint32_t lck_value;
} hw_lck_ticket_t;

/*!
 * @typedef lck_ticket_t
 *
 * @discussion
 * A higher level construct than hw_lck_ticket_t in 2 words
 * like other kernel locks, which admits thread ownership information.
 */
typedef struct {
	union {
		uintptr_t lck_owner __kernel_data_semantics;
		uintptr_t lck_tag __kernel_data_semantics;
	};
	hw_lck_ticket_t tu;
} lck_ticket_t;

#define LCK_TICKET_TYPE                 0x44
#define LCK_TICKET_TAG_DESTROYED        0xdead

#pragma GCC visibility push(hidden)

void hw_lck_ticket_init(hw_lck_ticket_t * tlock LCK_GRP_ARG(lck_grp_t *grp));
void hw_lck_ticket_init_locked(hw_lck_ticket_t * tlock LCK_GRP_ARG(lck_grp_t *grp));
void hw_lck_ticket_destroy(hw_lck_ticket_t * tlock, bool keep_type LCK_GRP_ARG(lck_grp_t *grp));

bool hw_lck_ticket_held(hw_lck_ticket_t *tlock) __result_use_check;
void hw_lck_ticket_lock(hw_lck_ticket_t * tlock LCK_GRP_ARG(lck_grp_t *grp));
hw_lock_status_t hw_lck_ticket_lock_to(hw_lck_ticket_t * tlock, uint64_t timeout,
    hw_lock_timeout_handler_t handler LCK_GRP_ARG(lck_grp_t *grp));
int  hw_lck_ticket_lock_try(hw_lck_ticket_t * tlock LCK_GRP_ARG(lck_grp_t *grp));
void hw_lck_ticket_unlock(hw_lck_ticket_t *tlock);

hw_lock_status_t hw_lck_ticket_lock_allow_invalid(hw_lck_ticket_t * tlock,
    uint64_t timeout, hw_lock_timeout_handler_t handler LCK_GRP_ARG(lck_grp_t *grp));
void hw_lck_ticket_invalidate(hw_lck_ticket_t *tlock);

#if !LOCK_STATS
#define hw_lck_ticket_init(lck, grp)             hw_lck_ticket_init(lck)
#define hw_lck_ticket_init_locked(lck, grp)      hw_lck_ticket_init_locked(lck)
#define hw_lck_ticket_destroy(lck, kt, grp)      hw_lck_ticket_destroy(lck,kt)
#define hw_lck_ticket_lock(lck, grp)             hw_lck_ticket_lock(lck)
#define hw_lck_ticket_lock_to(lck, to, cb, grp)  hw_lck_ticket_lock_to(lck, to, cb)
#define hw_lck_ticket_lock_try(lck, grp)         hw_lck_ticket_lock_try(lck)
#define hw_lck_ticket_lock_allow_invalid(lck, to, cb, grp) \
	hw_lck_ticket_lock_allow_invalid(lck, to, cb)
#endif /* !LOCK_STATS */

#pragma GCC visibility pop
#else /* MACH_KERNEL_PRIVATE */

typedef struct {
	uintptr_t       opaque1 __kernel_data_semantics;
	uint32_t        opaque2;
} lck_ticket_t;

#endif /* MACH_KERNEL_PRIVATE */

void lck_ticket_init(lck_ticket_t *tlock, lck_grp_t *grp);
void lck_ticket_destroy(lck_ticket_t *tlock, lck_grp_t *grp);
void lck_ticket_lock(lck_ticket_t *tlock, lck_grp_t *grp);
void lck_ticket_unlock(lck_ticket_t *tlock);
void lck_ticket_assert_owned(lck_ticket_t *tlock);
#if MACH_ASSERT
#define LCK_TICKET_ASSERT_OWNED(tlock) lck_ticket_assert_owned(tlock)
#else
#define LCK_TICKET_ASSERT_OWNED(tlock) (void)(tlock)
#endif

#if XNU_KERNEL_PRIVATE
int  lck_ticket_lock_try(lck_ticket_t *tlock, lck_grp_t *grp) __result_use_check;
bool kdp_lck_ticket_is_acquired(lck_ticket_t *lck) __result_use_check;
#endif

__END_DECLS

#endif /* __ASSEMBLER__ */

#define HW_LCK_TICKET_LOCK_INCREMENT  0x01000000
#define HW_LCK_TICKET_LOCK_VALID_BIT  8

#else /* KERNEL_PRIVATE */
#error header not supported
#endif /* KERNEL_PRIVATE */

#endif /* _KERN_TICKET_LOCK_H_ */
