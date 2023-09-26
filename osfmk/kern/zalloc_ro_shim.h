/*
 * Copyright (c) 2021 Apple Inc. All rights reserved.
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

#ifdef  KERNEL_PRIVATE
#ifndef _KERN_ZALLOC_RO_SHIM_
#define _KERN_ZALLOC_RO_SHIM_

#include <os/atomic_private.h>
#include <kern/zalloc.h>

/*
 * This file is provided as a help to shim adoption of read only zones
 * to provide an A/B driven by a boot-arg.
 *
 * In affected files:
 *
 * 1. define ALLOW_ZALLOC_RO_SHIM to allow selective RO/non-RO shimming,
 *    and #include <kern/zalloc_ro_shim.h>
 *
 * 2. based on typically a boot-arg, decide to pass ZC_READONLY to
 *    zone_create_ro():
 *
 *    - if ZC_READONLY is absent, then a regular zone is made,
 *    - if ZC_READONLY is passed, then the zone will be read-only and used as
 *      such.
 *
 *    if ALLOW_ZALLOC_RO_SHIM is not defined, then even when ZC_READONLY
 *    isn't passed, the zone will be forcefully read only.
 *
 * 3. in your code, use zone_id_shim_t instead of `zone_id_t` while you still
 *    want to use the RO/non-RO shim.
 *
 *
 * In practice this means that the shimmed code when creating the zone
 * will look a little like this, and nothing else is otherwise affected
 * in source:
 *
 * <code>
 *      // do this is any translation unit using {zalloc,zfree}_ro_* APIS
 *      #if ALLOW_ZALLOC_RO_SHIM
 *      #include <kern/zalloc_ro_shim.h>
 *      #endif
 *
 *      SECURITY_READ_ONLY_LATE(zone_id_shim_t) my_zone_id;
 *
 *      void
 *      some_init_code(void)
 *      {
 *          zone_create_flags_t flags = ZC_NONE;
 *
 *      #if ALLOW_ZALLOC_RO_SHIM
 *          int use_ro = 0;
 *          PE_parse_boot_arg("my_zone_make_ro", &use_ro, sizeof(use_ro));
 *          if (use_ro) {
 *              flags |= ZC_READONLY;
 *          }
 *      #endif
 *
 *          my_zone_id = zone_create_ro("my zone", sizeof(struct my_type),
 *              flags, ZC_RO_MY_ZONE_ID);
 *
 *          // ... more code ...
 *      }
 * </code>
 */

#ifndef ALLOW_ZALLOC_RO_SHIM
typedef zone_id_t zone_id_shim_t;
#else
typedef union {
	zone_t                  zone;
	zone_id_t               zid;
	unsigned long           zval;
} zone_id_shim_t;

static inline bool
zone_id_shim_is_ro(zone_id_shim_t z)
{
	return z.zval <= UINT16_MAX;
}

static inline zone_id_shim_t
zone_create_ro_shimmed(
	const char             *name,
	vm_size_t               size,
	zone_create_flags_t     flags,
	zone_create_ro_id_t     zc_ro_id)
{
	zone_id_shim_t z = {};

	if (flags & ZC_READONLY) {
		z.zid = zone_create_ro(name, size, flags, zc_ro_id);
	} else {
		z.zone = zone_create(name, size, flags);
	}

	return z;
}
#define zone_create_ro(name, size, flags, zc_ro_id) \
	zone_create_ro_shimmed(name, size, flags, zc_ro_id)

static inline void
zalloc_ro_mut_shimmed(
	zone_id_shim_t          zone_id,
	void                   *elem,
	vm_offset_t             offset,
	const void             *new_data,
	vm_size_t               new_data_size)
{
	if (zone_id_shim_is_ro(zone_id)) {
		zalloc_ro_mut(zone_id.zid, elem, offset, new_data, new_data_size);
	} else {
		memcpy((void *)((vm_offset_t)elem + offset), new_data, new_data_size);
	}
}
#define zalloc_ro_mut(zone_id, elem, offset, new_data, new_data_size) \
	zalloc_ro_mut_shimmed(zone_id, elem, offset, new_data, new_data_size)

static inline void
zalloc_ro_clear_shimmed(
	zone_id_shim_t          zone_id,
	void                   *elem,
	vm_offset_t             offset,
	vm_size_t               size)
{
	if (zone_id_shim_is_ro(zone_id)) {
		zalloc_ro_clear(zone_id.zid, elem, offset, size);
	} else {
		bzero((void *)((vm_offset_t)elem + offset), size);
	}
}
#define zalloc_ro_clear(zone_id, elem, offset, size) \
	zalloc_ro_clear_shimmed(zone_id, elem, offset, size)

static inline void *
zalloc_ro_shimmed(
	zone_id_shim_t          zone_id,
	zalloc_flags_t          flags)
{
	if (zone_id_shim_is_ro(zone_id)) {
		return (zalloc_ro)(zone_id.zid, flags);
	} else {
		return (zalloc_flags)(zone_id.zone, flags);
	}
}
#undef zalloc_ro
#define zalloc_ro(zid, flags) \
	zalloc_ro_shimmed(zid, flags)

static inline void
zfree_ro_shimmed(
	zone_id_shim_t          zone_id,
	void                   *addr)
{
	if (zone_id_shim_is_ro(zone_id)) {
		(zfree_ro)(zone_id.zid, addr);
	} else {
		(zfree)(zone_id.zone, addr);
	}
}
#undef zfree_ro
#define zfree_ro(zid, elem) ({ \
	zone_id_shim_t __zfree_zid = (zid); \
	zfree_ro_shimmed(__zfree_zid, (void *)os_ptr_load_and_erase(elem)); \
})

static inline uint64_t
__zalloc_ro_mut_atomic_shimmed(
	vm_offset_t             dst,
	zro_atomic_op_t         op,
	uint64_t                value)
{
#define __ZALLOC_RO_MUT_ATOMIC_SHIMMED_OP(op, op2) \
	case ZRO_ATOMIC_##op##_8: \
	        return os_atomic_##op2((uint8_t *)dst, (uint8_t)value, seq_cst); \
	case ZRO_ATOMIC_##op##_16: \
	        return os_atomic_##op2((uint16_t *)dst, (uint16_t)value, seq_cst); \
	case ZRO_ATOMIC_##op##_32: \
	        return os_atomic_##op2((uint32_t *)dst, (uint32_t)value, seq_cst); \
	case ZRO_ATOMIC_##op##_64: \
	        return os_atomic_##op2((uint64_t *)dst, (uint64_t)value, seq_cst)

	switch (op) {
		__ZALLOC_RO_MUT_ATOMIC_SHIMMED_OP(OR, or_orig);
		__ZALLOC_RO_MUT_ATOMIC_SHIMMED_OP(XOR, xor_orig);
		__ZALLOC_RO_MUT_ATOMIC_SHIMMED_OP(AND, and_orig);
		__ZALLOC_RO_MUT_ATOMIC_SHIMMED_OP(ADD, add_orig);
		__ZALLOC_RO_MUT_ATOMIC_SHIMMED_OP(XCHG, xchg);
	default:
		panic("%s: Invalid atomic operation: %d", __func__, op);
	}

#undef __ZALLOC_RO_MUT_ATOMIC_SHIMMED_OP
}

static inline uint64_t
zalloc_ro_mut_atomic_shimmed(
	zone_id_shim_t  zone_id,
	void           *elem,
	vm_offset_t     offset,
	zro_atomic_op_t op,
	uint64_t        value)
{
	if (zone_id_shim_is_ro(zone_id)) {
		return zalloc_ro_mut_atomic(zone_id.zid, elem, offset, op, value);
	} else {
		vm_offset_t ptr = (vm_offset_t)elem + offset;
		return __zalloc_ro_mut_atomic_shimmed((void *)ptr, op, value);
	}
}
#define zalloc_ro_mut_atomic(zone_id, elem, offset, op, value) \
	zalloc_ro_mut_atomic_shimmed(zone_id, elem, offset, op, value)

/*
 * Those are macros/wrappers that will be shimmed naturally:
 * - zalloc_ro_update_elem,
 * - zalloc_ro_update_field,
 * - zalloc_ro_clear_field
 * - zalloc_ro_update_field_atomic
 */
#endif
#endif /* _KERN_ZALLOC_RO_SHIM_ */
#endif /* KERNEL_PRIVATE */
