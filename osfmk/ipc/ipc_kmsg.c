/*
 * Copyright (c) 2000-2020 Apple Inc. All rights reserved.
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
/*
 * @OSF_COPYRIGHT@
 */
/*
 * Mach Operating System
 * Copyright (c) 1991,1990,1989 Carnegie Mellon University
 * All Rights Reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */
/*
 * NOTICE: This file was modified by McAfee Research in 2004 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 * Copyright (c) 2005 SPARTA, Inc.
 */
/*
 */
/*
 *	File:	ipc/ipc_kmsg.c
 *	Author:	Rich Draves
 *	Date:	1989
 *
 *	Operations on kernel messages.
 */

#include <mach/mach_types.h>
#include <mach/boolean.h>
#include <mach/kern_return.h>
#include <mach/message.h>
#include <mach/port.h>
#include <mach/vm_map.h>
#include <mach/mach_vm.h>
#include <mach/vm_statistics.h>

#include <kern/kern_types.h>
#include <kern/assert.h>
#include <kern/debug.h>
#include <kern/ipc_kobject.h>
#include <kern/kalloc.h>
#include <kern/zalloc.h>
#include <kern/processor.h>
#include <kern/thread.h>
#include <kern/thread_group.h>
#include <kern/sched_prim.h>
#include <kern/misc_protos.h>
#include <kern/cpu_data.h>
#include <kern/policy_internal.h>
#include <kern/mach_filter.h>

#include <pthread/priority_private.h>

#include <machine/limits.h>

#include <vm/vm_map_xnu.h>
#include <vm/vm_object_xnu.h>
#include <vm/vm_kern_xnu.h>
#include <vm/vm_protos.h>

#include <ipc/port.h>
#include <ipc/ipc_types.h>
#include <ipc/ipc_entry.h>
#include <ipc/ipc_kmsg.h>
#include <ipc/ipc_notify.h>
#include <ipc/ipc_object.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_policy.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_right.h>
#include <ipc/ipc_hash.h>
#include <ipc/ipc_importance.h>
#include <ipc/ipc_service_port.h>

#if MACH_FLIPC
#include <kern/mach_node.h>
#include <ipc/flipc.h>
#endif

#include <os/overflow.h>

#include <security/mac_mach_internal.h>

#include <device/device_server.h>

#include <string.h>

#include <sys/kdebug.h>
#include <libkern/OSAtomic.h>

#include <ptrauth.h>
#if __has_feature(ptrauth_calls)
#include <libkern/ptrauth_utils.h>
#endif


/*
 * In kernel, complex mach msg have a simpler representation than userspace:
 *
 * <header>
 * <desc-count>
 * <descriptors> * desc-count
 * <body>
 *
 * And the descriptors are of type `mach_msg_kdescriptor_t`,
 * that is large enough to accommodate for any possible representation.
 *
 * The `type` field of any descriptor is always at the same offset,
 * and the smallest possible descriptor is of size USER_DESC_SIZE_MIN.
 *
 * Note:
 * - KERN_DESC_SIZE is 16 on all kernels
 * - USER_DESC_SIZE_MIN is 12 on all kernels
 */

#define KERNEL_DESC_SIZE        sizeof(mach_msg_kdescriptor_t)
#define USER_DESC_SIZE_MIN      sizeof(mach_msg_type_descriptor_t)
#define USER_DESC_SIZE_MAX      KERNEL_DESC_SIZE
#define USER_DESC_MAX_DELTA     (KERNEL_DESC_SIZE - USER_DESC_SIZE_MIN)
#define USER_HEADER_SIZE_DELTA  (sizeof(mach_msg_header_t) - sizeof(mach_msg_user_header_t))


#define mach_validate_desc_type(t, size) \
	static_assert(sizeof(t) == (size))

mach_validate_desc_type(mach_msg_descriptor_t, KERNEL_DESC_SIZE);
mach_validate_desc_type(mach_msg_kdescriptor_t, KERNEL_DESC_SIZE);
mach_validate_desc_type(mach_msg_port_descriptor_t, KERNEL_DESC_SIZE);
mach_validate_desc_type(mach_msg_ool_descriptor_t, KERNEL_DESC_SIZE);
mach_validate_desc_type(mach_msg_ool_ports_descriptor_t, KERNEL_DESC_SIZE);
mach_validate_desc_type(mach_msg_guarded_port_descriptor_t, KERNEL_DESC_SIZE);

extern vm_map_t         ipc_kernel_copy_map;
extern const vm_size_t  msg_ool_size_small;

/* zone for cached ipc_kmsg_t structures */
ZONE_DEFINE_ID(ZONE_ID_IPC_KMSG, "ipc kmsgs", struct ipc_kmsg,
    ZC_CACHING | ZC_ZFREE_CLEARMEM);
#define ikm_require(kmsg) \
	zone_id_require(ZONE_ID_IPC_KMSG, sizeof(struct ipc_kmsg), kmsg)
#define ikm_require_aligned(kmsg) \
	zone_id_require_aligned(ZONE_ID_IPC_KMSG, kmsg)

KALLOC_TYPE_VAR_DEFINE(KT_IPC_KMSG_KDATA_OOL,
    mach_msg_base_t, mach_msg_kdescriptor_t, KT_DEFAULT);

static TUNABLE(bool, enforce_strict_reply, "ipc_strict_reply", false);


#pragma mark ipc_kmsg layout and accessors

/* Whether header, body, content and trailer occupy contiguous memory space */
static inline bool
ikm_is_linear(ipc_kmsg_t kmsg)
{
	return kmsg->ikm_type == IKM_TYPE_ALL_INLINED ||
	       kmsg->ikm_type == IKM_TYPE_KDATA_OOL;
}

/* Size of kmsg header (plus body and descriptors for complex messages) */
__attribute__((always_inline, overloadable))
static mach_msg_size_t
ikm_kdata_size(
	mach_msg_size_t dsc_count,
	bool            complex)
{
	if (complex) {
		return sizeof(mach_msg_kbase_t) + dsc_count * KERNEL_DESC_SIZE;
	} else {
		return sizeof(mach_msg_header_t);
	}
}

__attribute__((always_inline, overloadable))
static mach_msg_size_t
ikm_kdata_size(
	mach_msg_header_t *hdr)
{
	if (hdr->msgh_bits & MACH_MSGH_BITS_COMPLEX) {
		mach_msg_kbase_t *kbase = mach_msg_header_to_kbase(hdr);

		return ikm_kdata_size(kbase->msgb_dsc_count, true);
	}
	return ikm_kdata_size(0, false);
}

/*
 * Returns start address of user data for kmsg.
 *
 * Caller is responsible for checking the size of udata buffer before attempting
 * to write to the address returned.
 *
 * Condition:
 *   1. kmsg descriptors must have been validated and expanded, or is a message
 *      originated from kernel.
 *   2. ikm_header() content may or may not be populated
 */
void *
ikm_udata(
	ipc_kmsg_t      kmsg,
	mach_msg_size_t dsc_count,
	bool            complex)
{
	if (ikm_is_linear(kmsg)) {
		mach_msg_header_t *hdr = ikm_header(kmsg);

		return (char *)hdr + ikm_kdata_size(dsc_count, complex);
	}
	return kmsg->ikm_udata;
}

/*
 * Returns start address of user data for kmsg, given a populated kmsg.
 *
 * Caller is responsible for checking the size of udata buffer before attempting
 * to write to the address returned.
 *
 * Condition:
 *   kmsg must have a populated header.
 */
void *
ikm_udata_from_header(ipc_kmsg_t kmsg)
{
	if (ikm_is_linear(kmsg)) {
		mach_msg_header_t *hdr = ikm_header(kmsg);

		return (char *)hdr + ikm_kdata_size(hdr);
	}
	return kmsg->ikm_udata;
}

#if (DEVELOPMENT || DEBUG)
/* Returns end of kdata buffer (may contain extra space) */
vm_offset_t
ikm_kdata_end(ipc_kmsg_t kmsg)
{
	switch (kmsg->ikm_type) {
	case IKM_TYPE_ALL_INLINED:
		return (vm_offset_t)kmsg->ikm_big_data + IKM_BIG_MSG_SIZE;
	case IKM_TYPE_UDATA_OOL:
		return (vm_offset_t)kmsg->ikm_small_data + IKM_SMALL_MSG_SIZE;
	default:
		return (vm_offset_t)kmsg->ikm_kdata + kmsg->ikm_kdata_size;
	}
}
#endif

/*
 * Returns message header address.
 */
inline mach_msg_header_t *
ikm_header(
	ipc_kmsg_t         kmsg)
{
	switch (kmsg->ikm_type) {
	case IKM_TYPE_ALL_INLINED:
		return (mach_msg_header_t *)kmsg->ikm_big_data;
	case IKM_TYPE_UDATA_OOL:
		return (mach_msg_header_t *)kmsg->ikm_small_data;
	default:
		return (mach_msg_header_t *)kmsg->ikm_kdata;
	}
}

static inline mach_msg_aux_header_t *
ikm_aux_header(
	ipc_kmsg_t         kmsg)
{
	if (!kmsg->ikm_aux_size) {
		return NULL;
	}

	assert(kmsg->ikm_aux_size >= sizeof(mach_msg_aux_header_t));

	if (kmsg->ikm_type == IKM_TYPE_ALL_INLINED) {
		return (mach_msg_aux_header_t *)((vm_offset_t)(kmsg + 1) -
		       kmsg->ikm_aux_size);
	} else {
		assert(kmsg->ikm_type != IKM_TYPE_KDATA_OOL);
		return (mach_msg_aux_header_t *)((vm_offset_t)kmsg->ikm_udata +
		       kmsg->ikm_udata_size - kmsg->ikm_aux_size);
	}
}

/*!
 * @brief
 * Returns the size of a user descriptor for a given type
 */
static inline mach_msg_size_t
ikm_user_desc_size(mach_msg_descriptor_type_t type, bool is_task_64bit)
{
	/*
	 * User descriptors come in two sizes:
	 * - USER_DESC_SIZE_MIN (12)
	 * - USER_DESC_SIZE_MAX (16)
	 *
	 * Ideally this function would be implemented as a "switch",
	 * unfortunately this produces terrible codegen, so we instead write
	 * the optimal code by hand with tons of static asserts.
	 *
	 * As of now there are only two cases:
	 * - port descriptors are always 12 bytes
	 * - other descriptors are 12 bytes on 32bits, and 16 on 64bits.
	 *
	 * If one of the static asserts break because you are adding a new
	 * descriptor type, make sure to update this function properly.
	 */
	static_assert(MACH_MSG_DESCRIPTOR_MAX == MACH_MSG_GUARDED_PORT_DESCRIPTOR);

	if (type == MACH_MSG_PORT_DESCRIPTOR) {
		mach_validate_desc_type(mach_msg_user_port_descriptor_t, USER_DESC_SIZE_MIN);
		return USER_DESC_SIZE_MIN;
	}
	if (is_task_64bit) {
		mach_validate_desc_type(mach_msg_ool_descriptor64_t, USER_DESC_SIZE_MAX);
		mach_validate_desc_type(mach_msg_ool_ports_descriptor64_t, USER_DESC_SIZE_MAX);
		mach_validate_desc_type(mach_msg_guarded_port_descriptor64_t, USER_DESC_SIZE_MAX);
		return USER_DESC_SIZE_MAX;
	} else {
		mach_validate_desc_type(mach_msg_ool_descriptor32_t, USER_DESC_SIZE_MIN);
		mach_validate_desc_type(mach_msg_ool_ports_descriptor32_t, USER_DESC_SIZE_MIN);
		mach_validate_desc_type(mach_msg_guarded_port_descriptor32_t, USER_DESC_SIZE_MIN);
		return USER_DESC_SIZE_MIN;
	}
}

__abortlike
static void
__ipc_kmsg_descriptor_invalid_type_panic(
	const mach_msg_kdescriptor_t *kdesc)
{
	panic("Invalid descriptor type (%p: %d)",
	    kdesc, mach_msg_kdescriptor_type(kdesc));
}

mach_msg_trailer_size_t
ipc_kmsg_trailer_size(mach_msg_option64_t option, vm_map_t map __unused)
{
	return REQUESTED_TRAILER_SIZE(map->max_offset > VM_MAX_ADDRESS, option);
}


/*
 * Get the trailer address of kmsg.
 */
mach_msg_max_trailer_t *
ipc_kmsg_get_trailer(
	ipc_kmsg_t              kmsg)
{
	mach_msg_header_t *hdr = ikm_header(kmsg);
	mach_msg_size_t    trailer_pos = hdr->msgh_size;
	vm_offset_t        base;

	if (ikm_is_linear(kmsg)) {
		base = (vm_offset_t)hdr;
	} else {
		base = (vm_offset_t)kmsg->ikm_udata;
		trailer_pos -= ikm_kdata_size(hdr);
	}

	return (mach_msg_max_trailer_t *)(base + trailer_pos);
}

void
ipc_kmsg_set_voucher_port(
	ipc_kmsg_t           kmsg,
	ipc_port_t           voucher_port,
	mach_msg_type_name_t type)
{
	if (IP_VALID(voucher_port)) {
		assert(ip_kotype(voucher_port) == IKOT_VOUCHER);
	}
	kmsg->ikm_voucher_port = voucher_port;
	kmsg->ikm_voucher_type = type;
}

ipc_port_t
ipc_kmsg_get_voucher_port(ipc_kmsg_t kmsg)
{
	return kmsg->ikm_voucher_port;
}

void
ipc_kmsg_clear_voucher_port(ipc_kmsg_t kmsg)
{
	kmsg->ikm_voucher_port = IP_NULL;
	kmsg->ikm_voucher_type = MACH_MSGH_BITS_ZERO;
}

/*
 * Caller has a reference to the kmsg and the mqueue lock held.
 *
 * As such, we can safely return a pointer to the thread group in the kmsg and
 * not an additional reference. It is up to the caller to decide to take an
 * additional reference on the thread group while still holding the mqueue lock,
 * if needed.
 */
#if CONFIG_PREADOPT_TG
struct thread_group *
ipc_kmsg_get_thread_group(ipc_kmsg_t kmsg)
{
	struct thread_group *tg = NULL;
	kern_return_t __assert_only kr;

	ipc_voucher_t voucher = convert_port_to_voucher(ipc_kmsg_get_voucher_port(kmsg));
	kr = bank_get_preadopt_thread_group(voucher, &tg);
	ipc_voucher_release(voucher);

	return tg;
}
#endif

#pragma mark ipc_kmsg signing

__abortlike
static void
__ikm_signature_check_panic(ipc_kmsg_t kmsg, uint32_t sig)
{
	mach_msg_header_t *hdr = ikm_header(kmsg);

	panic("IPC kmsg header signature mismatch: "
	    "kmsg=%p, hdr=%p, id=%d, sig=0x%08x (expected 0x%08x)",
	    kmsg, hdr, hdr->msgh_id, sig, kmsg->ikm_signature);
}

static uint32_t
__ipc_kmsg_sign(
	ipc_kmsg_t              kmsg,
	mach_msg_max_trailer_t *trailer,
	mach_msg_size_t        *dsc_count)
{
	uint32_t           signature = 0;
	mach_msg_header_t *hdr  = ikm_header(kmsg);
	mach_msg_base_t    base;

	if (hdr->msgh_bits & MACH_MSGH_BITS_COMPLEX) {
		mach_msg_kbase_t *kbase = mach_msg_header_to_kbase(hdr);

		/*
		 * the "atomic" load will also be volatile which prevents the
		 * compiler from re-fetching that value after optimization.
		 */
		base.header = kbase->msgb_header;
		base.body.msgh_descriptor_count =
		    os_atomic_load(&kbase->msgb_dsc_count, relaxed);
	} else {
		base.header = *hdr;
		base.body.msgh_descriptor_count = 0;
	}

	/* compute sig of a copy of the header with all varying bits masked off */
	base.header.msgh_bits &= MACH_MSGH_BITS_USER;
	base.header.msgh_bits &= ~MACH_MSGH_BITS_VOUCHER_MASK;

#if __has_feature(ptrauth_calls)
	{
		uintptr_t data = (uintptr_t)kmsg;

		data &= ~(0xffffLL << 48); /* clear upper 16 bits */
		data |= OS_PTRAUTH_DISCRIMINATOR("kmsg.ikm_signature") << 48;

		data  = ptrauth_utils_sign_blob_generic(&base, sizeof(base), data, 0);
		data  = ptrauth_utils_sign_blob_generic(trailer,
		    MAX_TRAILER_SIZE, data, PTRAUTH_ADDR_DIVERSIFY);
		signature = (uint32_t)(data >> 32);
	}
#else
	(void)kmsg;
	(void)trailer;
#endif

	if (dsc_count) {
		*dsc_count = base.body.msgh_descriptor_count;
	}
	return signature;
}

static void
ipc_kmsg_sign(ipc_kmsg_t kmsg, mach_msg_max_trailer_t *trailer)
{
	kmsg->ikm_signature = __ipc_kmsg_sign(kmsg, trailer, NULL);
}

/*
 *	Routine:	ipc_kmsg_init_trailer_and_sign
 *	Purpose:
 *		Initiailizes a trailer in a message safely,
 *		and sign its header and trailer.
 */
static void
ipc_kmsg_init_trailer_and_sign(
	ipc_kmsg_t          kmsg,
	task_t              sender)
{
	static const mach_msg_max_trailer_t KERNEL_TRAILER_TEMPLATE = {
		.msgh_trailer_type = MACH_MSG_TRAILER_FORMAT_0,
		.msgh_trailer_size = MACH_MSG_TRAILER_MINIMUM_SIZE,
		.msgh_sender = KERNEL_SECURITY_TOKEN_VALUE,
		.msgh_audit = KERNEL_AUDIT_TOKEN_VALUE
	};

	mach_msg_max_trailer_t *trailer = ipc_kmsg_get_trailer(kmsg);

	if (sender == TASK_NULL) {
		memcpy(trailer, &KERNEL_TRAILER_TEMPLATE, sizeof(*trailer));
	} else {
		bzero(trailer, sizeof(*trailer));
		trailer->msgh_trailer_type = MACH_MSG_TRAILER_FORMAT_0;
		trailer->msgh_trailer_size = MACH_MSG_TRAILER_MINIMUM_SIZE;
		trailer->msgh_sender = *task_get_sec_token(sender);
		trailer->msgh_audit = *task_get_audit_token(sender);
	}

	ipc_kmsg_sign(kmsg, trailer);
}

/*
 * Purpose:
 *       Validate kmsg signature.
 */
mach_msg_size_t
ipc_kmsg_validate_signature(
	ipc_kmsg_t kmsg)
{
	uint32_t         sig;
	mach_msg_size_t  dsc_count;

	ikm_require_aligned(kmsg);
	sig = __ipc_kmsg_sign(kmsg, ipc_kmsg_get_trailer(kmsg), &dsc_count);
	if (sig != kmsg->ikm_signature) {
		__ikm_signature_check_panic(kmsg, sig);
	}

	return dsc_count;
}

void
ipc_kmsg_sign_descriptors(
	mach_msg_kdescriptor_t *kdesc,
	mach_msg_size_t         dsc_count)
{
#if __has_feature(ptrauth_calls)
	for (mach_msg_size_t i = 0; i < dsc_count; i++, kdesc++) {
		switch (mach_msg_kdescriptor_type(kdesc)) {
		case MACH_MSG_PORT_DESCRIPTOR:
			kdesc->kdesc_port.name =
			    kdesc->kdesc_port.kext_name;
			break;
		case MACH_MSG_OOL_VOLATILE_DESCRIPTOR:
		case MACH_MSG_OOL_DESCRIPTOR:
			kdesc->kdesc_memory.address =
			    kdesc->kdesc_memory.kext_address;
			break;
		case MACH_MSG_OOL_PORTS_DESCRIPTOR: {
			mach_msg_ool_ports_descriptor_t *dsc = &kdesc->kdesc_port_array;
			ipc_port_t          *ports = dsc->kext_address;
			mach_port_array_t    array = dsc->kext_address;

			for (mach_msg_size_t j = 0; j < dsc->count; j++) {
				array[i].port = ports[i];
			}
			dsc->address = array;
			break;
		}
		case MACH_MSG_GUARDED_PORT_DESCRIPTOR:
			kdesc->kdesc_guarded_port.name =
			    kdesc->kdesc_guarded_port.kext_name;
			break;
		default:
			__ipc_kmsg_descriptor_invalid_type_panic(kdesc);
		}
	}
#else
#pragma unused(kdesc, dsc_count)
#endif /* __has_feature(ptrauth_calls) */
}

static void
ipc_kmsg_relocate_descriptors(
	mach_msg_kdescriptor_t *dst_dsc,
	const mach_msg_kdescriptor_t *src_dsc,
	mach_msg_size_t         dsc_count)
{
#if __has_feature(ptrauth_calls)
	for (mach_msg_size_t i = 0; i < dsc_count; i++, dst_dsc++, src_dsc++) {
		switch (mach_msg_kdescriptor_type(src_dsc)) {
		case MACH_MSG_PORT_DESCRIPTOR:
			dst_dsc->kdesc_port.name =
			    src_dsc->kdesc_port.name;
			break;
		case MACH_MSG_OOL_VOLATILE_DESCRIPTOR:
		case MACH_MSG_OOL_DESCRIPTOR:
			dst_dsc->kdesc_memory.address =
			    src_dsc->kdesc_memory.address;
			break;
		case MACH_MSG_OOL_PORTS_DESCRIPTOR:
			dst_dsc->kdesc_port_array.address =
			    src_dsc->kdesc_port_array.address;
			break;
		case MACH_MSG_GUARDED_PORT_DESCRIPTOR:
			dst_dsc->kdesc_guarded_port.name =
			    src_dsc->kdesc_guarded_port.name;
			break;
		default:
			__ipc_kmsg_descriptor_invalid_type_panic(src_dsc);
		}
	}
#else
#pragma unused(dst_dsc, src_dsc, dsc_count)
#endif /* __has_feature(ptrauth_calls) */
}

static void
ipc_kmsg_strip_descriptors(
	mach_msg_kdescriptor_t *dst_dsc,
	const mach_msg_kdescriptor_t *src_dsc,
	mach_msg_size_t         dsc_count)
{
#if __has_feature(ptrauth_calls)
	for (mach_msg_size_t i = 0; i < dsc_count; i++, dst_dsc++, src_dsc++) {
		switch (mach_msg_kdescriptor_type(src_dsc)) {
		case MACH_MSG_PORT_DESCRIPTOR:
			dst_dsc->kdesc_port.kext_name =
			    src_dsc->kdesc_port.name;
			break;
		case MACH_MSG_OOL_VOLATILE_DESCRIPTOR:
		case MACH_MSG_OOL_DESCRIPTOR:
			dst_dsc->kdesc_memory.kext_address =
			    src_dsc->kdesc_memory.address;
			break;
		case MACH_MSG_OOL_PORTS_DESCRIPTOR: {
			mach_msg_ool_ports_descriptor_t *dsc = &dst_dsc->kdesc_port_array;
			ipc_port_t          *ports = dsc->address;
			mach_port_array_t    array = dsc->address;

			for (mach_msg_size_t j = 0; j < dsc->count; j++) {
				ports[i] = array[i].port;
			}
			dsc->kext_address = array;
			break;
		}
		case MACH_MSG_GUARDED_PORT_DESCRIPTOR:
			dst_dsc->kdesc_guarded_port.kext_name =
			    src_dsc->kdesc_guarded_port.name;
			break;
		default:
			__ipc_kmsg_descriptor_invalid_type_panic(src_dsc);
		}
	}
#else
#pragma unused(dst_dsc, src_dsc, dsc_count)
#endif /* __has_feature(ptrauth_calls) */
}


#pragma mark ipc_kmsg alloc/clean/free

static inline void *
ikm_alloc_kdata_ool(size_t size, zalloc_flags_t flags)
{
	return kalloc_type_var_impl(KT_IPC_KMSG_KDATA_OOL,
	           size, flags, NULL);
}

static inline void
ikm_free_kdata_ool(void *ptr, size_t size)
{
	kfree_type_var_impl(KT_IPC_KMSG_KDATA_OOL, ptr, size);
}

/*
 *	Routine:	ipc_kmsg_alloc
 *	Purpose:
 *		Allocate a kernel message structure.  If the
 *		message is scalar and all the data resides inline, that is best.
 *      Otherwise, allocate out of line buffers to fit the message and
 *      the optional auxiliary data.
 *
 *	Conditions:
 *		Nothing locked.
 *
 *      kmsg_size doesn't take the trailer or descriptor
 *		inflation into account, but already accounts for the mach
 *		message header expansion.
 */
ipc_kmsg_t
ipc_kmsg_alloc(
	mach_msg_size_t         kmsg_size,
	mach_msg_size_t         aux_size,
	mach_msg_size_t         desc_count,
	ipc_kmsg_alloc_flags_t  flags)
{
	mach_msg_size_t max_kmsg_size, max_delta, max_kdata_size,
	    max_udata_size, max_kmsg_and_aux_size;
	ipc_kmsg_t kmsg;

	void *msg_kdata = NULL, *msg_udata = NULL;
	zalloc_flags_t alloc_flags = Z_WAITOK;
	ipc_kmsg_type_t kmsg_type;

	/*
	 * In kernel descriptors, are of the same size (KERNEL_DESC_SIZE),
	 * but in userspace, depending on 64-bitness, descriptors might be
	 * smaller.
	 *
	 * When handling a userspace message however, we know how many
	 * descriptors have been declared, and we pad for the maximum expansion.
	 *
	 * During descriptor expansion, message header stays at the same place
	 * while everything after it gets shifted to higher address.
	 */
	if (flags & IPC_KMSG_ALLOC_KERNEL) {
		assert(aux_size == 0);
		max_delta = 0;
	} else if (os_mul_and_add_overflow(desc_count, USER_DESC_MAX_DELTA,
	    USER_HEADER_SIZE_DELTA, &max_delta)) {
		return IKM_NULL;
	}

	if (os_add3_overflow(kmsg_size, MAX_TRAILER_SIZE, max_delta, &max_kmsg_size)) {
		return IKM_NULL;
	}
	if (os_add_overflow(max_kmsg_size, aux_size, &max_kmsg_and_aux_size)) {
		return IKM_NULL;
	}

	/* First, determine the layout of the kmsg to allocate */
	if (max_kmsg_and_aux_size <= IKM_BIG_MSG_SIZE) {
		kmsg_type = IKM_TYPE_ALL_INLINED;
		max_udata_size = 0;
		max_kdata_size = 0;
	} else if (flags & IPC_KMSG_ALLOC_ALL_INLINE) {
		panic("size too large for the fast kmsg zone (%d)", kmsg_size);
	} else if (flags & IPC_KMSG_ALLOC_LINEAR) {
		/*
		 * Caller sets MACH64_SEND_KOBJECT_CALL or MACH64_SEND_ANY, or that
		 * the call originates from kernel, or it's a mach_msg() call.
		 * In any case, message does not carry aux data.
		 * We have validated mach_msg2() call options in mach_msg2_trap().
		 */
		if (aux_size != 0) {
			panic("non-zero aux size for kmsg type IKM_TYPE_KDATA_OOL.");
		}
		kmsg_type = IKM_TYPE_KDATA_OOL;
		max_udata_size = 0;
		max_kdata_size = max_kmsg_size;
	} else {
		mach_msg_size_t min_kdata_size;

		/*
		 * If message can be splitted from the middle, IOW does not need to
		 * occupy contiguous memory space, sequester (header + descriptors)
		 * from (content + trailer + aux) for memory security.
		 */
		assert(max_kmsg_and_aux_size > IKM_BIG_MSG_SIZE);

		/*
		 * max_kdata_size: Maximum combined size of header plus (optional) descriptors.
		 * This is _base_ size + descriptor count * kernel descriptor size.
		 */
		if (os_mul_and_add_overflow(desc_count, KERNEL_DESC_SIZE,
		    sizeof(mach_msg_base_t), &max_kdata_size)) {
			return IKM_NULL;
		}

		/*
		 * min_kdata_size: Minimum combined size of header plus (optional) descriptors.
		 * This is _header_ size + descriptor count * minimal descriptor size.
		 */
		mach_msg_size_t min_size = (flags & IPC_KMSG_ALLOC_KERNEL) ?
		    KERNEL_DESC_SIZE : USER_DESC_SIZE_MIN;
		if (os_mul_and_add_overflow(desc_count, min_size,
		    sizeof(mach_msg_header_t), &min_kdata_size)) {
			return IKM_NULL;
		}

		/*
		 * max_udata_size: Maximum combined size of message content, trailer and aux.
		 * This is total kmsg and aux size (already accounts for max trailer size) minus
		 * _minimum_ (header + descs) size.
		 */
		if (os_sub_overflow(max_kmsg_and_aux_size, min_kdata_size, &max_udata_size)) {
			return IKM_NULL;
		}

		if (max_kdata_size <= IKM_SMALL_MSG_SIZE) {
			kmsg_type = IKM_TYPE_UDATA_OOL;
		} else {
			kmsg_type = IKM_TYPE_ALL_OOL;
		}
	}

	if (flags & IPC_KMSG_ALLOC_ZERO) {
		alloc_flags |= Z_ZERO;
	}
	if (flags & IPC_KMSG_ALLOC_NOFAIL) {
		alloc_flags |= Z_NOFAIL;
	}

	/* Then, allocate memory for both udata and kdata if needed, as well as kmsg */
	if (max_udata_size > 0) {
		msg_udata = kalloc_data(max_udata_size, alloc_flags);
		if (__improbable(msg_udata == NULL)) {
			return IKM_NULL;
		}
	}

	if (kmsg_type == IKM_TYPE_ALL_OOL || kmsg_type == IKM_TYPE_KDATA_OOL) {
		if (kmsg_type == IKM_TYPE_ALL_OOL) {
			msg_kdata = kalloc_type(mach_msg_base_t, mach_msg_kdescriptor_t,
			    desc_count, alloc_flags | Z_SPRAYQTN);
		} else {
			msg_kdata = ikm_alloc_kdata_ool(max_kdata_size, alloc_flags);
		}

		if (__improbable(msg_kdata == NULL)) {
			kfree_data(msg_udata, max_udata_size);
			return IKM_NULL;
		}
	}

	static_assert(IPC_KMSG_MAX_AUX_DATA_SPACE <= UINT16_MAX,
	    "casting aux_size won't truncate");

	kmsg = zalloc_id(ZONE_ID_IPC_KMSG, Z_WAITOK | Z_ZERO | Z_NOFAIL);
	kmsg->ikm_type = kmsg_type;
	kmsg->ikm_aux_size = (uint16_t)aux_size;

	if (flags & IPC_KMSG_ALLOC_USE_KEEP_ALIVE) {
		assert(kmsg_type == IKM_TYPE_ALL_INLINED);
		kmsg->ikm_keep_alive = IKM_KEEP_ALIVE_OWNED;
	}

	/* Finally, set up pointers properly */
	if (kmsg_type == IKM_TYPE_ALL_INLINED) {
		assert(msg_udata == NULL && msg_kdata == NULL);
	} else {
		if (kmsg_type == IKM_TYPE_UDATA_OOL) {
			kmsg->ikm_kdata = kmsg->ikm_small_data;
		} else {
			kmsg->ikm_kdata = msg_kdata;
		}
		kmsg->ikm_udata = msg_udata;
		kmsg->ikm_kdata_size = max_kdata_size;
		kmsg->ikm_udata_size = max_udata_size;
	}

	return kmsg;
}

/* re-export for IOKit's c++ */
extern ipc_kmsg_t ipc_kmsg_alloc_uext_reply(mach_msg_size_t);

ipc_kmsg_t
ipc_kmsg_alloc_uext_reply(
	mach_msg_size_t         size)
{
	return ipc_kmsg_alloc(size, 0, 0, IPC_KMSG_ALLOC_KERNEL | IPC_KMSG_ALLOC_LINEAR |
	           IPC_KMSG_ALLOC_ZERO | IPC_KMSG_ALLOC_NOFAIL);
}

/*
 *	Routine:	ipc_kmsg_keep_alive_try_reusing()
 *	Purpose:
 *		Attempt to mark a preallocated message in-use.
 *		Returns true on success, false on failure.
 */
bool
ipc_kmsg_keep_alive_try_reusing(ipc_kmsg_t kmsg)
{
	uintptr_t v;

	v = os_atomic_or_orig(&kmsg->ikm_keep_alive,
	    IKM_KEEP_ALIVE_IN_USE, relaxed);

	/* if the message isn't owned, it can't use keep-alive */
	ipc_release_assert(v & IKM_KEEP_ALIVE_OWNED);

	return (v & IKM_KEEP_ALIVE_IN_USE) == 0;
}

/*
 *	Routine:	ipc_kmsg_keep_alive_done_using
 *	Purpose:
 *		Marks an ipc kmsg as no longer in flight.
 *		Returns true if the message is also no longer owned.
 */
static bool
ipc_kmsg_keep_alive_done_using(ipc_kmsg_t kmsg)
{
	uintptr_t v = os_atomic_load(&kmsg->ikm_keep_alive, relaxed);

	if (v == IKM_KEEP_ALIVE_NONE) {
		/* fastpath for most messages not using the facility */
		return true;
	}

	v = os_atomic_andnot_orig(&kmsg->ikm_keep_alive,
	    IKM_KEEP_ALIVE_IN_USE, release);

	/* if the message wasn't in-use, something is wrong */
	ipc_release_assert(v & IKM_KEEP_ALIVE_IN_USE);

	if (v & IKM_KEEP_ALIVE_OWNED) {
		return false;
	}
	os_atomic_thread_fence(acquire);
	return true;
}

/*
 *	Routine:	ipc_kmsg_keep_alive_abandon()
 *	Purpose:
 *		Abandons a message that was marked as OWNED
 *		as part of allocating it with IPC_KMSG_ALLOC_USE_KEEP_ALIVE.
 */
void
ipc_kmsg_keep_alive_abandon(
	ipc_kmsg_t              kmsg)
{
	uintptr_t v;

	v = os_atomic_andnot_orig(&kmsg->ikm_keep_alive,
	    IKM_KEEP_ALIVE_OWNED, release);

	/* if the message wasn't owned, something is wrong */
	ipc_release_assert(v & IKM_KEEP_ALIVE_OWNED);

	if ((v & IKM_KEEP_ALIVE_IN_USE) == 0) {
		os_atomic_thread_fence(acquire);
		ipc_kmsg_free(kmsg);
	}
}

/*
 *	Routine:	ipc_kmsg_free_allocations
 *	Purpose:
 *		Free external allocations of a kmsg.
 *	Conditions:
 *		Nothing locked.
 */
static void
ipc_kmsg_free_allocations(
	ipc_kmsg_t              kmsg)
{
	mach_msg_size_t dsc_count = 0;

	switch (kmsg->ikm_type) {
	case IKM_TYPE_ALL_INLINED:
		break;
	case IKM_TYPE_UDATA_OOL:
		kfree_data(kmsg->ikm_udata, kmsg->ikm_udata_size);
		/* kdata is inlined, udata freed */
		break;
	case IKM_TYPE_KDATA_OOL:
		ikm_free_kdata_ool(kmsg->ikm_kdata, kmsg->ikm_kdata_size);
		/* kdata freed, no udata */
		break;
	case IKM_TYPE_ALL_OOL:
		dsc_count = (kmsg->ikm_kdata_size - sizeof(mach_msg_base_t)) /
		    KERNEL_DESC_SIZE;
		kfree_type(mach_msg_base_t, mach_msg_kdescriptor_t, dsc_count,
		    kmsg->ikm_kdata);
		/* kdata freed */
		kfree_data(kmsg->ikm_udata, kmsg->ikm_udata_size);
		/* udata freed */
		break;
	default:
		panic("strange kmsg type");
	}
	kmsg->ikm_type = IKM_TYPE_ALL_INLINED;

	/* leave nothing dangling or causing out of bounds */
	kmsg->ikm_udata = NULL;
	kmsg->ikm_kdata = NULL;
	kmsg->ikm_udata_size = 0;
	kmsg->ikm_kdata_size = 0;
	kmsg->ikm_aux_size = 0;
}

/*
 *	Routine:	ipc_kmsg_free
 *	Purpose:
 *		Free a kernel message (and udata) buffer.
 *	Conditions:
 *		Nothing locked.
 */
void
ipc_kmsg_free(
	ipc_kmsg_t      kmsg)
{
	assert(!IP_VALID(ipc_kmsg_get_voucher_port(kmsg)));

	KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_FREE) | DBG_FUNC_NONE,
	    VM_KERNEL_ADDRPERM((uintptr_t)kmsg),
	    0, 0, 0, 0);

	/*
	 * Check to see if an mk_timer asked for this message to stay
	 * alive.
	 */
	if (kmsg->ikm_type == IKM_TYPE_ALL_INLINED &&
	    !ipc_kmsg_keep_alive_done_using(kmsg)) {
		return;
	}

	ipc_kmsg_free_allocations(kmsg);
	zfree_id(ZONE_ID_IPC_KMSG, kmsg);
	/* kmsg struct freed */
}

/*
 *	Routine:	ipc_kmsg_clean_header
 *	Purpose:
 *		Cleans the header of a kmsg.
 *	Conditions:
 *		Nothing locked.
 */
static void
ipc_kmsg_clean_header(
	ipc_kmsg_t              kmsg)
{
	ipc_port_t port;
	mach_msg_header_t *hdr = ikm_header(kmsg);
	mach_msg_bits_t mbits = hdr->msgh_bits;

	/* deal with importance chain while we still have dest and voucher references */
	ipc_importance_clean(kmsg);

	port = hdr->msgh_remote_port;
	if (IP_VALID(port)) {
		ipc_object_destroy_dest(port, MACH_MSGH_BITS_REMOTE(mbits));
	}

	port = hdr->msgh_local_port;
	if (IP_VALID(port)) {
		ipc_object_destroy(port, MACH_MSGH_BITS_LOCAL(mbits));
	}

	port = ipc_kmsg_get_voucher_port(kmsg);
	if (IP_VALID(port)) {
		assert(MACH_MSGH_BITS_VOUCHER(mbits) == MACH_MSG_TYPE_MOVE_SEND);
		ipc_object_destroy(port, MACH_MSG_TYPE_PORT_SEND);
		ipc_kmsg_clear_voucher_port(kmsg);
	}
}

/*
 *	Routine:	ipc_kmsg_clean_descriptors
 *	Purpose:
 *		Cleans the body of a kernel message.
 *		Releases all rights, references, and memory.
 *
 *	Conditions:
 *		No locks held.
 */
void
ipc_kmsg_clean_descriptors(
	mach_msg_kdescriptor_t *kdesc __counted_by(number),
	mach_msg_type_number_t  number)
{
	for (mach_msg_type_number_t i = 0; i < number; i++, kdesc++) {
		switch (mach_msg_kdescriptor_type(kdesc)) {
		case MACH_MSG_PORT_DESCRIPTOR: {
			mach_msg_port_descriptor_t *dsc = &kdesc->kdesc_port;

			/*
			 * Destroy port rights carried in the message
			 */
			if (IP_VALID(dsc->name)) {
				ipc_object_destroy(dsc->name, dsc->disposition);
				dsc->name = IP_NULL;
			}
			break;
		}
		case MACH_MSG_OOL_VOLATILE_DESCRIPTOR:
		case MACH_MSG_OOL_DESCRIPTOR: {
			mach_msg_ool_descriptor_t *dsc = &kdesc->kdesc_memory;
			vm_map_copy_t copy = dsc->address;

			/*
			 * Destroy memory carried in the message
			 */
			if (copy) {
				vm_map_copy_discard(copy);
				dsc->address = NULL;
			} else {
				assert(dsc->size == 0);
			}
			break;
		}
		case MACH_MSG_OOL_PORTS_DESCRIPTOR: {
			mach_msg_ool_ports_descriptor_t *dsc = &kdesc->kdesc_port_array;
			mach_port_array_t array = dsc->address;

			for (mach_msg_size_t j = 0; j < dsc->count; j++) {
				ipc_port_t port = array[j].port;

				if (IP_VALID(port)) {
					ipc_object_destroy(port, dsc->disposition);
				}
			}
			if (array) {
				mach_port_array_free(array, dsc->count);
				dsc->address = NULL;
			} else {
				assert(dsc->count == 0);
			}
			break;
		}
		case MACH_MSG_GUARDED_PORT_DESCRIPTOR: {
			mach_msg_guarded_port_descriptor_t *dsc = &kdesc->kdesc_guarded_port;

			/*
			 * Destroy port rights carried in the message
			 */
			if (IP_VALID(dsc->name)) {
				ipc_object_destroy(dsc->name, dsc->disposition);
				dsc->name = IP_NULL;
			}
			break;
		}
		default:
			__ipc_kmsg_descriptor_invalid_type_panic(kdesc);
		}
	}
}

/*
 *	Routine:	ipc_kmsg_clean
 *	Purpose:
 *		Cleans a kernel message.  Releases all rights,
 *		references, and memory held by the message.
 *	Conditions:
 *		No locks held.
 */

static void
ipc_kmsg_clean(ipc_kmsg_t kmsg, mach_msg_size_t dsc_count)
{
	ipc_kmsg_clean_header(kmsg);

	if (dsc_count) {
		mach_msg_kbase_t *kbase = mach_msg_header_to_kbase(ikm_header(kmsg));

		ipc_kmsg_clean_descriptors(kbase->msgb_dsc_array, dsc_count);
	}
}


#pragma mark ipc_kmsg enqueue/destroy, qos, priority, voucher, ...

/* we can't include the BSD <sys/persona.h> header here... */
#ifndef PERSONA_ID_NONE
#define PERSONA_ID_NONE ((uint32_t)-1)
#endif

/*
 *	Routine:	ipc_kmsg_enqueue_qos
 *	Purpose:
 *		Enqueue a kmsg, propagating qos
 *		overrides towards the head of the queue.
 *
 *	Returns:
 *		whether the head of the queue had
 *		it's override-qos adjusted because
 *		of this insertion.
 */

bool
ipc_kmsg_enqueue_qos(
	ipc_kmsg_queue_t        queue,
	ipc_kmsg_t              kmsg)
{
	mach_msg_qos_t qos_ovr = kmsg->ikm_qos_override;
	ipc_kmsg_t     prev;

	if (ipc_kmsg_enqueue(queue, kmsg)) {
		return true;
	}

	/* apply QoS overrides towards the head */
	prev = ipc_kmsg_queue_element(kmsg->ikm_link.prev);
	while (prev != kmsg) {
		if (qos_ovr <= prev->ikm_qos_override) {
			return false;
		}
		prev->ikm_qos_override = qos_ovr;
		prev = ipc_kmsg_queue_element(prev->ikm_link.prev);
	}

	return true;
}

/*
 *	Routine:	ipc_kmsg_override_qos
 *	Purpose:
 *		Update the override for a given kmsg already
 *		enqueued, propagating qos override adjustments
 *		towards	the head of the queue.
 *
 *	Returns:
 *		whether the head of the queue had
 *		it's override-qos adjusted because
 *		of this insertion.
 */

bool
ipc_kmsg_override_qos(
	ipc_kmsg_queue_t    queue,
	ipc_kmsg_t          kmsg,
	mach_msg_qos_t      qos_ovr)
{
	ipc_kmsg_t first = ipc_kmsg_queue_first(queue);
	ipc_kmsg_t cur = kmsg;

	/* apply QoS overrides towards the head */
	while (qos_ovr > cur->ikm_qos_override) {
		cur->ikm_qos_override = qos_ovr;
		if (cur == first) {
			return true;
		}
		cur = ipc_kmsg_queue_element(cur->ikm_link.prev);
	}

	return false;
}

/*
 *	Routine:	ipc_kmsg_destroy
 *	Purpose:
 *		Destroys a kernel message.  Releases all rights,
 *		references, and memory held by the message.
 *		Frees the message.
 *	Conditions:
 *		No locks held.
 */

void
ipc_kmsg_destroy(
	ipc_kmsg_t                     kmsg,
	ipc_kmsg_destroy_flags_t       flags)
{
	/* sign the msg if it has not been signed */
	boolean_t sign_msg = (flags & IPC_KMSG_DESTROY_NOT_SIGNED);
	mach_msg_header_t *hdr = ikm_header(kmsg);

	if (flags & IPC_KMSG_DESTROY_SKIP_REMOTE) {
		hdr->msgh_remote_port = MACH_PORT_NULL;
		/* re-sign the msg since content changed */
		sign_msg = true;
	}

	if (flags & IPC_KMSG_DESTROY_SKIP_LOCAL) {
		hdr->msgh_local_port = MACH_PORT_NULL;
		/* re-sign the msg since content changed */
		sign_msg = true;
	}

	if (sign_msg) {
		ipc_kmsg_sign(kmsg, ipc_kmsg_get_trailer(kmsg));
	}

	/*
	 *	Destroying a message can cause more messages to be destroyed.
	 *	Curtail recursion by putting messages on the deferred
	 *	destruction queue.  If this was the first message on the
	 *	queue, this instance must process the full queue.
	 */
	if (ipc_kmsg_delayed_destroy(kmsg)) {
		ipc_kmsg_reap_delayed();
	}
}

/*
 *	Routine:	ipc_kmsg_delayed_destroy
 *	Purpose:
 *		Enqueues a kernel message for deferred destruction.
 *	Returns:
 *		Boolean indicator that the caller is responsible to reap
 *		deferred messages.
 */

bool
ipc_kmsg_delayed_destroy(
	ipc_kmsg_t kmsg)
{
	return ipc_kmsg_enqueue(&current_thread()->ith_messages, kmsg);
}

/*
 *	Routine:	ipc_kmsg_delayed_destroy_queue
 *	Purpose:
 *		Enqueues a queue of kernel messages for deferred destruction.
 *	Returns:
 *		Boolean indicator that the caller is responsible to reap
 *		deferred messages.
 */

bool
ipc_kmsg_delayed_destroy_queue(
	ipc_kmsg_queue_t        queue)
{
	return circle_queue_concat_tail(&current_thread()->ith_messages, queue);
}

/*
 *	Routine:	ipc_kmsg_reap_delayed
 *	Purpose:
 *		Destroys messages from the per-thread
 *		deferred reaping queue.
 *	Conditions:
 *		No locks held. kmsgs on queue must be signed.
 */

void
ipc_kmsg_reap_delayed(void)
{
	ipc_kmsg_queue_t queue = &(current_thread()->ith_messages);
	ipc_kmsg_t kmsg;

	/*
	 * must leave kmsg in queue while cleaning it to assure
	 * no nested calls recurse into here.
	 */
	while ((kmsg = ipc_kmsg_queue_first(queue)) != IKM_NULL) {
		/*
		 * Kmsgs queued for delayed destruction either come from
		 * ipc_kmsg_destroy() or ipc_kmsg_delayed_destroy_queue(),
		 * where we handover all kmsgs enqueued on port to destruction
		 * queue in O(1). In either case, all kmsgs must have been
		 * signed.
		 *
		 * For each unreceived msg, validate its signature before freeing.
		 */
		ipc_kmsg_clean(kmsg, ipc_kmsg_validate_signature(kmsg));
		ipc_kmsg_rmqueue(queue, kmsg);
		ipc_kmsg_free(kmsg);
	}
}

static pthread_priority_compact_t
ipc_get_current_thread_priority(void)
{
	thread_t thread = current_thread();
	thread_qos_t qos;
	int relpri;

	qos = thread_get_requested_qos(thread, &relpri);
	if (!qos) {
		qos = thread_user_promotion_qos_for_pri(thread->base_pri);
		relpri = 0;
	}
	return _pthread_priority_make_from_thread_qos(qos, relpri, 0);
}

static kern_return_t
ipc_kmsg_set_qos(
	ipc_kmsg_t kmsg,
	mach_msg_option64_t options,
	mach_msg_priority_t priority)
{
	kern_return_t kr;
	mach_msg_header_t *hdr = ikm_header(kmsg);
	ipc_port_t special_reply_port = hdr->msgh_local_port;
	ipc_port_t dest_port = hdr->msgh_remote_port;

	if ((options & MACH_SEND_OVERRIDE) &&
	    !mach_msg_priority_is_pthread_priority(priority)) {
		mach_msg_qos_t qos = mach_msg_priority_qos(priority);
		int relpri = mach_msg_priority_relpri(priority);
		mach_msg_qos_t ovr = mach_msg_priority_overide_qos(priority);

		kmsg->ikm_ppriority = _pthread_priority_make_from_thread_qos(qos, relpri, 0);
		kmsg->ikm_qos_override = MAX(qos, ovr);
	} else {
#if CONFIG_VOUCHER_DEPRECATED
		kr = ipc_get_pthpriority_from_kmsg_voucher(kmsg, &kmsg->ikm_ppriority);
#else
		kr = KERN_FAILURE;
#endif /* CONFIG_VOUCHER_DEPRECATED */
		if (kr != KERN_SUCCESS) {
			if (options & MACH_SEND_PROPAGATE_QOS) {
				kmsg->ikm_ppriority = ipc_get_current_thread_priority();
			} else {
				kmsg->ikm_ppriority = MACH_MSG_PRIORITY_UNSPECIFIED;
			}
		}

		if (options & MACH_SEND_OVERRIDE) {
			mach_msg_qos_t qos = _pthread_priority_thread_qos(kmsg->ikm_ppriority);
			mach_msg_qos_t ovr = _pthread_priority_thread_qos(priority);
			kmsg->ikm_qos_override = MAX(qos, ovr);
		} else {
			kmsg->ikm_qos_override = _pthread_priority_thread_qos(kmsg->ikm_ppriority);
		}
	}

	kr = KERN_SUCCESS;

	if (IP_VALID(special_reply_port) &&
	    special_reply_port->ip_specialreply &&
	    !ip_is_kobject(dest_port) &&
	    MACH_MSGH_BITS_LOCAL(hdr->msgh_bits) == MACH_MSG_TYPE_PORT_SEND_ONCE) {
		boolean_t sync_bootstrap_checkin = !!(options & MACH_SEND_SYNC_BOOTSTRAP_CHECKIN);
		/*
		 * Link the destination port to special reply port and make sure that
		 * dest port has a send turnstile, else allocate one.
		 */
		ipc_port_link_special_reply_port(special_reply_port, dest_port, sync_bootstrap_checkin);
	}
	return kr;
}

static kern_return_t
ipc_kmsg_set_qos_kernel(
	ipc_kmsg_t kmsg)
{
	ipc_port_t dest_port = ikm_header(kmsg)->msgh_remote_port;
	kmsg->ikm_qos_override = dest_port->ip_kernel_qos_override;
	kmsg->ikm_ppriority = _pthread_priority_make_from_thread_qos(kmsg->ikm_qos_override, 0, 0);
	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_kmsg_link_reply_context_locked
 *	Purpose:
 *		Link any required context from the sending voucher
 *		to the reply port. The ipc_kmsg_copyin_from_user function will
 *		enforce that the sender calls mach_msg in this context.
 *	Conditions:
 *		reply port is locked
 */
static void
ipc_kmsg_link_reply_context_locked(
	ipc_port_t reply_port,
	ipc_port_t voucher_port)
{
	kern_return_t __assert_only kr;
	uint32_t persona_id = 0;
	ipc_voucher_t voucher;

	ip_mq_lock_held(reply_port);

	if (!ip_active(reply_port)) {
		return;
	}

	voucher = convert_port_to_voucher(voucher_port);

	kr = bank_get_bank_ledger_thread_group_and_persona(voucher, NULL, NULL, &persona_id);
	assert(kr == KERN_SUCCESS);
	ipc_voucher_release(voucher);

	if (persona_id == 0 || persona_id == PERSONA_ID_NONE) {
		/* there was no persona context to record */
		return;
	}

	/*
	 * Set the persona_id as the context on the reply port.
	 * This will force the thread that replies to have adopted a voucher
	 * with a matching persona.
	 */
	reply_port->ip_reply_context = persona_id;

	return;
}

static kern_return_t
ipc_kmsg_validate_reply_port_locked(
	ipc_port_t              reply_port,
	mach_msg_option64_t     options)
{
	ip_mq_lock_held(reply_port);

	if (!ip_active(reply_port)) {
		/*
		 * Ideally, we would enforce that the reply receive right is
		 * active, but asynchronous XPC cancellation destroys the
		 * receive right, so we just have to return success here.
		 */
		return KERN_SUCCESS;
	}

	if (options & MACH_SEND_MSG) {
		/*
		 * If the rely port is active, then it should not be
		 * in-transit, and the receive right should be in the caller's
		 * IPC space.
		 */
		if (!ip_in_space(reply_port, current_task()->itk_space)) {
			return KERN_INVALID_CAPABILITY;
		}

		/*
		 * A port used as a reply port in an RPC should have exactly 1
		 * extant send-once right which we either just made or are
		 * moving as part of the IPC.
		 */
		if (reply_port->ip_sorights != 1) {
			return KERN_INVALID_CAPABILITY;
		}
		/*
		 * XPC uses an extra send-right to keep the name of the reply
		 * right around through cancellation.  That makes it harder to
		 * enforce a particular semantic kere, so for now, we say that
		 * you can have a maximum of 1 send right (in addition to your
		 * send once right). In the future, it would be great to lock
		 * this down even further.
		 */
		if (reply_port->ip_srights > 1) {
			return KERN_INVALID_CAPABILITY;
		}

		/*
		 * The sender can also specify that the receive right should
		 * be immovable. Note that this check only applies to
		 * send-only operations. Combined send/receive or rcv-only
		 * operations can specify an immovable receive right by
		 * opt-ing into guarded descriptors (MACH_RCV_GUARDED_DESC)
		 * and using the MACH_MSG_STRICT_REPLY options flag.
		 */
		if (MACH_SEND_REPLY_IS_IMMOVABLE(options)) {
			if (!reply_port->ip_immovable_receive) {
				return KERN_INVALID_CAPABILITY;
			}
		}
	}

	/*
	 * don't enforce this yet: need a better way of indicating the
	 * receiver wants this...
	 */
#if 0
	if (MACH_RCV_WITH_IMMOVABLE_REPLY(options)) {
		if (!reply_port->ip_immovable_receive) {
			return KERN_INVALID_CAPABILITY;
		}
	}
#endif /* 0  */

	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_kmsg_validate_reply_context_locked
 *	Purpose:
 *		Validate that the current thread is running in the context
 *		required by the destination port.
 *	Conditions:
 *		dest_port is locked
 *	Returns:
 *		MACH_MSG_SUCCESS on success.
 *		On error, an EXC_GUARD exception is also raised.
 *		This function *always* resets the port reply context.
 */
static mach_msg_return_t
ipc_kmsg_validate_reply_context_locked(
	mach_msg_option64_t option,
	ipc_port_t dest_port,
	ipc_voucher_t voucher,
	mach_port_name_t voucher_name)
{
	uint32_t dest_ctx = dest_port->ip_reply_context;
	dest_port->ip_reply_context = 0;

	if (!ip_active(dest_port)) {
		return MACH_MSG_SUCCESS;
	}

	if (voucher == IPC_VOUCHER_NULL || !MACH_PORT_VALID(voucher_name)) {
		if ((option & MACH_SEND_KERNEL) == 0) {
			mach_port_guard_exception(voucher_name,
			    (MPG_FLAGS_STRICT_REPLY_INVALID_VOUCHER | dest_ctx),
			    kGUARD_EXC_STRICT_REPLY);
		}
		return MACH_SEND_INVALID_CONTEXT;
	}

	kern_return_t __assert_only kr;
	uint32_t persona_id = 0;
	kr = bank_get_bank_ledger_thread_group_and_persona(voucher, NULL, NULL, &persona_id);
	assert(kr == KERN_SUCCESS);

	if (dest_ctx != persona_id) {
		if ((option & MACH_SEND_KERNEL) == 0) {
			mach_port_guard_exception(voucher_name,
			    (MPG_FLAGS_STRICT_REPLY_MISMATCHED_PERSONA | ((((uint64_t)persona_id << 32) & MPG_FLAGS_STRICT_REPLY_MASK) | dest_ctx)),
			    kGUARD_EXC_STRICT_REPLY);
		}
		return MACH_SEND_INVALID_CONTEXT;
	}

	return MACH_MSG_SUCCESS;
}


#pragma mark ipc_kmsg copyin and inflate (from user)
/*!
 * @defgroup IPC kmsg copyin and inflate functions
 * @{
 *
 * IPC kmsg inflate
 * ~~~~~~~~~~~~~~~~
 *
 * This is the operation that turns the user representation of a message,
 * into a message in kernel representation, without any rights.
 *
 * This is driven by @c ipc_kmsg_get_and_inflate_from_user() which will:
 * - convert the message header into kernel layout (mach_msg_header_t),
 * - convert the descriptors into kernel layout,
 * - copy the body bytes.
 *
 *
 * IPC (right) copyin
 * ~~~~~~~~~~~~~~~~~~
 *
 * This is the operation that turns the userspace port names and VM addresses
 * in to actual IPC ports and vm_map_copy_t objects.
 *
 * This is done on an IPC kmsg in "kernel representation" and just replace
 * userspace scalar values with kernel pointers in place.
 *
 * @c ipc_kmsg_copyin_from_user() is the function that drives the entire
 * inflate and copyin logic, applying various filtering at each stage.
 */


/*
 * Macros to help inflate descriptors in place.
 *
 * the `addr` parameters must be of type `char *` so that the compiler
 * must assume these addresses alias (and they do).
 */
#define ikm_udsc_type(addr)         __IGNORE_WCASTALIGN(((const mach_msg_type_descriptor_t *)(addr))->type)
#define ikm_udsc_get(dst, addr)     __IGNORE_WCASTALIGN(*(dst) = *(const typeof(*(dst)) *)(addr))
#define ikm_kdsc_zero(addr, type)   ((type *)memset(addr, 0, sizeof(type)))

typedef struct {
	mach_msg_header_t      *msg;

	mach_port_name_t        dest_name;
	mach_msg_type_name_t    dest_type;
	ipc_port_t              dest_port;
	ipc_copyin_cleanup_t    dest_cleanup;

	mach_port_name_t        reply_name;
	mach_msg_type_name_t    reply_type;
	ipc_port_t              reply_port;
	ipc_copyin_cleanup_t    reply_cleanup;

	mach_port_name_t        voucher_name;
	mach_msg_type_name_t    voucher_type;
	ipc_port_t              voucher_port;
	ipc_copyin_cleanup_t    voucher_cleanup;

	ipc_table_index_t       dest_request;
	ipc_policy_violation_id_t reply_port_semantics_violation;
} ikm_copyinhdr_state_t;

/*
 *     Routine:        ipc_kmsg_copyin_header_validate
 *     Purpose:
 *             Perform various preflights on an IPC kmsg
 *     Conditions:
 *             Nothing locked.
 */
static mach_msg_return_t
ipc_kmsg_copyin_header_validate(
	ipc_kmsg_t              kmsg,
	mach_msg_option64_t     options,
	ikm_copyinhdr_state_t  *st)
{
	mach_msg_header_t *msg = ikm_header(kmsg);

	if (msg->msgh_bits & ~MACH_MSGH_BITS_USER) {
		return MACH_SEND_INVALID_HEADER;
	}

	st->msg = msg;

	/*
	 *	Validate the reply port and its disposition.
	 */
	st->reply_name = CAST_MACH_PORT_TO_NAME(msg->msgh_local_port);
	st->reply_type = MACH_MSGH_BITS_LOCAL(msg->msgh_bits);
	if (st->reply_type == MACH_MSG_TYPE_NONE) {
		if (st->reply_name != MACH_PORT_NULL) {
			return MACH_SEND_INVALID_HEADER;
		}
	} else if (!MACH_MSG_TYPE_PORT_ANY_SEND(st->reply_type)) {
		return MACH_SEND_INVALID_HEADER;
	}

	/*
	 *	Validate the voucher and its disposition.
	 *
	 *      The validation is a little nuanced for backward compatbility
	 *      reasons: once upon a time, the "msgh_voucher_port" field was
	 *      reserved, and some clients were expecting it to round-trip.
	 *
	 *      However, for that case, the voucher_type would always be 0
	 *      (because the MACH_MSGH_BITS_USER mask check would reject non
	 *      zero bits), so when it is, we're careful to have the
	 *      msgh_voucher_port value round trip unmodified.
	 */
	st->voucher_name = MACH_PORT_NULL;
	st->voucher_type = MACH_MSGH_BITS_VOUCHER(msg->msgh_bits);
	switch (st->voucher_type) {
	case MACH_MSG_TYPE_NONE:
		break;
	case MACH_MSG_TYPE_MOVE_SEND:
	case MACH_MSG_TYPE_COPY_SEND:
		st->voucher_name = msg->msgh_voucher_port;
		if (st->voucher_name != MACH_PORT_DEAD) {
			break;
		}
		OS_FALLTHROUGH;
	default:
		return MACH_SEND_INVALID_VOUCHER;
	}

	/*
	 *	Validate the destination and its disposition.
	 */
	st->dest_name = CAST_MACH_PORT_TO_NAME(msg->msgh_remote_port);
	st->dest_type = MACH_MSGH_BITS_REMOTE(msg->msgh_bits);

	if (!MACH_MSG_TYPE_PORT_ANY_SEND(st->dest_type)) {
		return MACH_SEND_INVALID_HEADER;
	}

	if (!MACH_PORT_VALID(st->dest_name)) {
		return MACH_SEND_INVALID_DEST;
	}

	if (st->dest_name == st->voucher_name) {
		/*
		 * If the voucher and destination are the same,
		 * then the disposition for the destination
		 * must be a valid disposition for a voucher!
		 */
		if (st->dest_type != MACH_MSG_TYPE_MOVE_SEND &&
		    st->dest_type != MACH_MSG_TYPE_COPY_SEND) {
			return MACH_SEND_INVALID_DEST;
		}
	}

	if (st->dest_name == st->reply_name) {
		/*
		 * If the destination and reply port are the same,
		 * no disposition can be a move-send-once.
		 */
		if (st->dest_type == MACH_MSG_TYPE_MOVE_SEND_ONCE ||
		    st->reply_type == MACH_MSG_TYPE_MOVE_SEND_ONCE) {
			return MACH_SEND_INVALID_DEST;
		}
	}

	if (enforce_strict_reply &&
	    MACH_SEND_WITH_STRICT_REPLY(options) &&
	    (!MACH_PORT_VALID(st->reply_name) ||
	    !MACH_MSG_TYPE_PORT_ANY_SEND_ONCE(st->reply_type))) {
		/*
		 * The caller cannot enforce a reply context with an invalid
		 * reply port name, or a non-send_once reply disposition.
		 */
		mach_port_guard_exception(st->reply_name,
		    (MPG_FLAGS_STRICT_REPLY_INVALID_REPLY_DISP | st->reply_type),
		    kGUARD_EXC_STRICT_REPLY);
		return MACH_SEND_INVALID_REPLY;
	}

	if (MACH_PORT_VALID(st->reply_name) && st->reply_name == st->voucher_name) {
		return MACH_SEND_INVALID_REPLY;
	}

	return MACH_MSG_SUCCESS;
}

/*
 *     Routine:        ipc_kmsg_copyin_header_cleanup
 *     Purpose:
 *             Cleans up the state used for an IPC kmsg header copyin
 *     Conditions:
 *             Nothing locked.
 */
static void
ipc_kmsg_copyin_header_cleanup(ikm_copyinhdr_state_t *st)
{
	/* the caller must take care of these */
	assert(st->dest_port == IP_NULL);
	assert(st->reply_port == IP_NULL);
	assert(st->voucher_port == IP_NULL);

	ipc_right_copyin_cleanup_destroy(&st->dest_cleanup, st->dest_name);
	ipc_right_copyin_cleanup_destroy(&st->reply_cleanup, st->reply_name);
	ipc_right_copyin_cleanup_destroy(&st->voucher_cleanup, st->voucher_name);
}

static inline mach_msg_type_name_t
ipc_kmsg_copyin_dest_disposition(
	ikm_copyinhdr_state_t  *st,
	ipc_object_copyin_flags_t *xtra)
{
	mach_msg_type_name_t disp1;
	mach_msg_type_name_t disp2;

	if (st->dest_name == st->voucher_name) {
		/*
		 *	Do the joint copyin of the dest disposition and
		 *	voucher disposition from the one entry/port.
		 *
		 *	We already validated that the voucher copyin would
		 *	succeed (above), and that the destination port
		 *	disposition is valid for a voucher.
		 */

		disp1 = st->dest_type;
		disp2 = st->voucher_type;
	} else if (st->dest_name == st->reply_name) {
		/*
		 *	Destination and reply ports are the same!
		 *	This is very similar to the case where the
		 *	destination and voucher ports were the same.
		 *
		 *	ipc_kmsg_copyin_header_validate() tells us that
		 *	neither dest_type nor reply_type is a move-send-once.
		 *
		 *	We need to consider any pair of these:
		 *	{make-send, make-send-once, move-send, copy-send}
		 *
		 *	1. If any is a make-send, then it means one of the
		 *	   dispositions requires a receive right:
		 *
		 *	   If the destination port disposition needs
		 *	   a receive right, its copyin succeeding
		 *	   means the receive right is there.
		 *
		 *	   If the reply port disposition needs a receive
		 *	   right, then it was validated by
		 *	   ipc_right_copyin_check_reply() and we know the
		 *	   receive right is there too.
		 *
		 *	   Hence the port is not in danger of dying
		 *	   while we hold the space lock, we can go
		 *	   one at a time.
		 *
		 *	2. otherwise, we do the joint copyin dance.
		 */

		if ((st->dest_type == MACH_MSG_TYPE_MAKE_SEND) ||
		    (st->dest_type == MACH_MSG_TYPE_MAKE_SEND_ONCE) ||
		    (st->reply_type == MACH_MSG_TYPE_MAKE_SEND) ||
		    (st->reply_type == MACH_MSG_TYPE_MAKE_SEND_ONCE)) {
			*xtra = IPC_OBJECT_COPYIN_FLAGS_NONE;
			return st->dest_type;
		}

		disp1 = st->dest_type;
		disp2 = st->reply_type;
	} else {
		/*
		 *	Handle destination and reply independently, as
		 *	they are independent entries (even if the entries
		 *	refer to the same port).
		 *
		 *	This can be the tough case to make atomic.
		 *
		 *	The difficult problem is serializing with port death.
		 *	The bad case is when dest_port dies after its copyin,
		 *	reply_port dies before its copyin, and dest_port dies before
		 *	reply_port.  Then the copyins operated as if dest_port was
		 *	alive and reply_port was dead, which shouldn't have happened
		 *	because they died in the other order.
		 *
		 *	Note that it is easy for a user task to tell if
		 *	a copyin happened before or after a port died.
		 *	If a port dies before copyin, a dead-name notification
		 *	is generated and the dead name's urefs are incremented,
		 *	and if the copyin happens first, a port-deleted
		 *	notification is generated.
		 *
		 *	Even so, avoiding that potentially detectable race is too
		 *	expensive - and no known code cares about it.  So, we just
		 *	do the expedient thing and copy them in one after the other.
		 */

		*xtra = IPC_OBJECT_COPYIN_FLAGS_NONE;
		return st->dest_type;
	}

	if (disp1 == MACH_MSG_TYPE_MOVE_SEND && disp2 == MACH_MSG_TYPE_MOVE_SEND) {
		*xtra |= IPC_OBJECT_COPYIN_FLAGS_DEST_EXTRA_MOVE;
		return MACH_MSG_TYPE_MOVE_SEND;
	}

	if (disp1 == MACH_MSG_TYPE_MOVE_SEND && disp2 == MACH_MSG_TYPE_COPY_SEND) {
		*xtra |= IPC_OBJECT_COPYIN_FLAGS_DEST_EXTRA_COPY;
		return MACH_MSG_TYPE_MOVE_SEND;
	}
	if (disp1 == MACH_MSG_TYPE_COPY_SEND && disp2 == MACH_MSG_TYPE_MOVE_SEND) {
		*xtra |= IPC_OBJECT_COPYIN_FLAGS_DEST_EXTRA_COPY;
		return MACH_MSG_TYPE_MOVE_SEND;
	}

	if (disp1 == MACH_MSG_TYPE_COPY_SEND && disp2 == MACH_MSG_TYPE_COPY_SEND) {
		*xtra |= IPC_OBJECT_COPYIN_FLAGS_DEST_EXTRA_COPY;
		return MACH_MSG_TYPE_COPY_SEND;
	}

	ipc_unreachable("not a pair of copy/move-send");
}

/*
 *	Routine:	ipc_kmsg_copyin_header_rights
 *	Purpose:
 *		Core implementation of ipc_kmsg_copyin_header()
 *
 *	Conditions:
 *		Nothing locked.
 *		Returns with the destination port locked on success.
 */
static mach_msg_return_t
ipc_kmsg_copyin_header_rights(
	ipc_space_t             space,
	ikm_copyinhdr_state_t  *st)
{
	ipc_entry_t dest_entry = IE_NULL;
	ipc_entry_t reply_entry = IE_NULL;
	ipc_entry_t voucher_entry = IE_NULL;
	mach_msg_type_name_t dest_type;
	ipc_object_copyin_flags_t dest_xtra;
	kern_return_t kr;

	is_write_lock(space);
	if (__improbable(!is_active(space))) {
		is_write_unlock(space);
		return MACH_SEND_INVALID_DEST;
	}

	/* space locked and active */

	/*
	 *      Step 1: lookup the various entries
	 *
	 *      Validate that copyins of the voucher and reply ports
	 *      will always succeed.
	 *
	 *      Once we haved copied in the destination port,
	 *      we can't back out.
	 */

	if (st->voucher_name != MACH_PORT_NULL) {
		voucher_entry = ipc_entry_lookup(space, st->voucher_name);

		if (voucher_entry == IE_NULL ||
		    (voucher_entry->ie_bits & MACH_PORT_TYPE_SEND) == 0 ||
		    ip_kotype(voucher_entry->ie_port) != IKOT_VOUCHER) {
			is_write_unlock(space);
			return MACH_SEND_INVALID_VOUCHER;
		}
	}

	if (st->dest_name == st->voucher_name) {
		dest_entry = voucher_entry;
	} else {
		dest_entry = ipc_entry_lookup(space, st->dest_name);
	}
	if (__improbable(dest_entry == IE_NULL ||
	    (dest_entry->ie_bits & MACH_PORT_TYPE_PORT_RIGHTS) == 0)) {
		is_write_unlock(space);
		return MACH_SEND_INVALID_DEST;
	}

	if (MACH_PORT_VALID(st->reply_name)) {
		assert(st->reply_name != st->voucher_name);
		if (st->reply_name == st->dest_name) {
			reply_entry = dest_entry;
		} else {
			reply_entry = ipc_entry_lookup(space, st->reply_name);
		}
		if (__improbable(reply_entry == IE_NULL ||
		    (reply_entry->ie_bits & MACH_PORT_TYPE_PORT_RIGHTS) == 0)) {
			is_write_unlock(space);
			return MACH_SEND_INVALID_REPLY;
		}

		if (__improbable(!ipc_right_copyin_check_reply(space,
		    st->reply_name, reply_entry, st->reply_type, dest_entry,
		    &st->reply_port_semantics_violation))) {
			is_write_unlock(space);
			return MACH_SEND_INVALID_REPLY;
		}
	}


	/*
	 *      Step 2: copyin the destination port
	 *
	 *      Handle combinations as required in order to respect
	 *      atomicity with respect to MOVE_{SEND,SEND_ONCE,RECEIVE}
	 *      (COPY/MAKE disposition cause no such headaches).
	 */

	dest_type = ipc_kmsg_copyin_dest_disposition(st, &dest_xtra);

	kr = ipc_right_copyin(space, st->dest_name, dest_type,
	    IPC_OBJECT_COPYIN_FLAGS_ALLOW_REPLY_MAKE_SEND_ONCE |
	    IPC_OBJECT_COPYIN_FLAGS_ALLOW_REPLY_MOVE_SEND_ONCE |
	    IPC_OBJECT_COPYIN_FLAGS_ALLOW_IMMOVABLE_SEND |
	    IPC_OBJECT_COPYIN_FLAGS_ALLOW_DEAD_SEND_ONCE |
	    dest_xtra, dest_entry,
	    &st->dest_port, &st->dest_cleanup, NULL);
	if (kr == KERN_SUCCESS) {
		assert(IP_VALID(st->dest_port));
		assert(!IP_VALID(st->dest_cleanup.icc_release_port));
	} else {
		ipc_space_unlock(space);
		return MACH_SEND_INVALID_DEST;
	}

	/*
	 *      Step 3: copyin the voucher and reply ports if needed.
	 */
	if (st->voucher_name == st->dest_name && dest_xtra) {
		st->voucher_port = st->dest_port;
	} else if (st->voucher_name) {
		kr = ipc_right_copyin(space, st->voucher_name, st->voucher_type,
		    IPC_OBJECT_COPYIN_FLAGS_NONE, voucher_entry,
		    &st->voucher_port, &st->voucher_cleanup, NULL);

		ipc_release_assert(kr == KERN_SUCCESS);
		assert(IP_VALID(st->voucher_port));
	}

	if (st->reply_name == st->dest_name && dest_xtra) {
		st->reply_port = st->dest_port;
	} else if (MACH_PORT_VALID(st->reply_name)) {
		kr = ipc_right_copyin(space, st->reply_name, st->reply_type,
		    IPC_OBJECT_COPYIN_FLAGS_ALLOW_REPLY_MAKE_SEND_ONCE |
		    IPC_OBJECT_COPYIN_FLAGS_DEADOK, reply_entry,
		    &st->reply_port, &st->reply_cleanup, NULL);

		/*
		 * ipc_right_copyin_check_reply() succeding means the
		 * copyin above should work.
		 */
		ipc_release_assert(kr == KERN_SUCCESS);
	} else {
		/* convert invalid name to equivalent ipc_object type */
		st->reply_port = CAST_MACH_NAME_TO_PORT(st->reply_name);
	}


	/*
	 *      Step 4: wrap up
	 *
	 *      unlock the space, lock the dest port.
	 *      capture the destination entry "ie_request"
	 */

	ip_mq_lock(st->dest_port);

	st->dest_request = dest_entry->ie_request;

	is_write_unlock(space);

	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_kmsg_copyin_header
 *	Purpose:
 *		"Copy-in" port rights in the header of a message.
 *		Operates atomically; if it doesn't succeed the
 *		message header and the space are left untouched.
 *		If it does succeed the remote/local port fields
 *		contain object pointers instead of port names,
 *		and the bits field is updated.  The destination port
 *		will be a valid port pointer.
 *
 *	Conditions:
 *		Nothing locked. May add MACH64_SEND_ALWAYS option.
 *	Returns:
 *		MACH_MSG_SUCCESS	Successful copyin.
 *		MACH_SEND_INVALID_HEADER
 *			Illegal value in the message header bits.
 *		MACH_SEND_INVALID_DEST	The space is dead.
 *		MACH_SEND_INVALID_DEST	Can't copyin destination port.
 *			(Either KERN_INVALID_NAME or KERN_INVALID_RIGHT.)
 *		MACH_SEND_INVALID_REPLY	Can't copyin reply port.
 *			(Either KERN_INVALID_NAME or KERN_INVALID_RIGHT.)
 */

static mach_msg_return_t
ipc_kmsg_copyin_header(
	ipc_kmsg_t              kmsg,
	ipc_space_t             space,
	mach_msg_priority_t     priority,
	mach_msg_option64_t     *option64p)
{
	mach_msg_option64_t options = *option64p;
	ikm_copyinhdr_state_t st = { };
	struct mach_service_port_info sp_info = {};
	bool needboost = false;
	kern_return_t kr;

	kr = ipc_kmsg_copyin_header_validate(kmsg, options, &st);
	if (kr == KERN_SUCCESS) {
		kr = ipc_kmsg_copyin_header_rights(space, &st);
	}

	if (__improbable(kr != KERN_SUCCESS)) {
		if (kr == MACH_SEND_INVALID_VOUCHER) {
			mach_port_guard_exception(st.voucher_name, 0,
			    kGUARD_EXC_SEND_INVALID_VOUCHER);
		}
		if (kr == MACH_SEND_INVALID_REPLY) {
			mach_port_guard_exception(st.reply_name, 0,
			    kGUARD_EXC_SEND_INVALID_REPLY);
		}
		ipc_kmsg_copyin_header_cleanup(&st);
		return kr;
	}

	/*
	 *  Point of no return: past this point, the send won't fail,
	 *  the message will be swallowed instead
	 *
	 *  The destination port is locked and active.
	 */
	ip_mq_lock_held(st.dest_port);

	if (IP_VALID(st.voucher_port)) {
		/*
		 * No room to store voucher port in in-kernel msg header,
		 * so we store it back in the kmsg itself.
		 *
		 * Store original voucher type there as well before the bits
		 * are set to the post-copyin type.
		 */
		ipc_kmsg_set_voucher_port(kmsg, st.voucher_port, st.voucher_type);
		st.voucher_port = IP_NULL; /* transfered to the kmsg */
		st.voucher_type = MACH_MSG_TYPE_MOVE_SEND;
	}
	st.dest_type = ipc_object_copyin_type(st.dest_type);
	st.reply_type = ipc_object_copyin_type(st.reply_type);

#if CONFIG_SERVICE_PORT_INFO
	/*
	 * Service name is later used in CA telemetry in case of reply port security semantics violations.
	 */
	if (ip_active(st.dest_port) && st.dest_port->ip_service_port) {
		assert(st.dest_port->ip_splabel);
		ipc_service_port_label_get_info(st.dest_port->ip_splabel, &sp_info);
	}
#endif /* CONFIG_SERVICE_PORT_INFO */

	if (!ip_active(st.dest_port) ||
	    (ip_is_kobject(st.dest_port) &&
	    ip_in_space(st.dest_port, ipc_space_kernel))) {
		/*
		 * If the dest port died, or is a kobject AND its receive right
		 * belongs to kernel, allow copyin of immovable send rights
		 * in the message body (port descriptor) to succeed since
		 * those send rights are simply "moved" or "copied" into kernel.
		 *
		 * See: ipc_object_copyin().
		 */
		assert(ip_kotype(st.dest_port) != IKOT_TIMER);
		kmsg->ikm_flags |= IPC_OBJECT_COPYIN_FLAGS_ALLOW_IMMOVABLE_SEND;
	}

	/*
	 * JMM - Without rdar://problem/6275821, this is the last place we can
	 * re-arm the send-possible notifications.  It may trigger unexpectedly
	 * early (send may NOT have failed), but better than missing.  We assure
	 * we won't miss by forcing MACH_SEND_ALWAYS if we got past arming.
	 */
	if (((options & MACH64_SEND_NOTIFY) != 0) &&
	    st.dest_type != MACH_MSG_TYPE_PORT_SEND_ONCE &&
	    st.dest_request != IE_REQ_NONE &&
	    ip_active(st.dest_port) &&
	    !ip_in_space(st.dest_port, ipc_space_kernel)) {
		/* st.dest_port could be in-transit, or in an ipc space */
		if (ip_full(st.dest_port)) {
			needboost = ipc_port_request_sparm(st.dest_port,
			    st.dest_name, st.dest_request, options, priority);
		} else {
			*option64p |= MACH64_SEND_ALWAYS;
		}
	}

	/*
	 * If our request is the first boosting send-possible
	 * notification this cycle, push the boost down the
	 * destination port.
	 */
	if (!needboost) {
		ip_mq_unlock(st.dest_port);
#if IMPORTANCE_INHERITANCE
	} else if (!ipc_port_importance_delta(st.dest_port,
	    IPID_OPTION_SENDPOSSIBLE, 1)) {
		ip_mq_unlock(st.dest_port);
#endif /* IMPORTANCE_INHERITANCE */
	}

	/* st.dest_port is unlocked */

	st.msg->msgh_bits = MACH_MSGH_BITS_SET(st.dest_type, st.reply_type,
	    st.voucher_type, st.msg->msgh_bits);
	st.msg->msgh_remote_port = st.dest_port;
	st.msg->msgh_local_port = st.reply_port;
	st.dest_port = st.reply_port = IP_NULL; /* transferred to the message */

	/*
	 * capture the qos value(s) for the kmsg qos,
	 * and apply any override before we enqueue the kmsg.
	 */
	ipc_kmsg_set_qos(kmsg, options, priority);

	/* then sign the header and trailer as soon as possible */
	ipc_kmsg_init_trailer_and_sign(kmsg, current_task());

	ipc_kmsg_copyin_header_cleanup(&st);

	if (enforce_strict_reply && MACH_SEND_WITH_STRICT_REPLY(options) &&
	    IP_VALID(st.msg->msgh_local_port)) {
		/*
		 * We've already validated that the reply disposition is a
		 * [make/move] send-once. Ideally, we should enforce that the
		 * reply port is also not dead, but XPC asynchronous
		 * cancellation can make the reply port dead before we
		 * actually make it to the mach_msg send.
		 *
		 * Here, we ensure that if we have a non-dead reply port, then
		 * the reply port's receive right should not be in-transit,
		 * and should live in the caller's IPC space.
		 */
		ipc_port_t rport = st.msg->msgh_local_port;
		ip_mq_lock(rport);
		kr = ipc_kmsg_validate_reply_port_locked(rport, options);
		ip_mq_unlock(rport);
		if (kr != KERN_SUCCESS) {
			/*
			 * no descriptors have been copied in yet, but the
			 * full header has been copied in: clean it up
			 */
			ipc_kmsg_clean_header(kmsg);
			if ((options & MACH_SEND_KERNEL) == 0) {
				mach_port_guard_exception(st.reply_name,
				    (MPG_FLAGS_STRICT_REPLY_INVALID_REPLY_PORT | kr),
				    kGUARD_EXC_STRICT_REPLY);
			}
			return MACH_SEND_INVALID_REPLY;
		}
	}

	if (st.reply_port_semantics_violation) {
		/* Currently rate limiting it to sucess paths only. */
		task_t task = current_task_early();
		if (task && st.reply_port_semantics_violation == IPCPV_REPLY_PORT_SEMANTICS) {
			task_lock(task);
			if (!task_has_reply_port_telemetry(task)) {
				/* Crash report rate limited to once per task per host. */
				mach_port_guard_exception(st.reply_name, 0,
				    kGUARD_EXC_REQUIRE_REPLY_PORT_SEMANTICS);
				task_set_reply_port_telemetry(task);
			}
			task_unlock(task);
		}

		ipc_stash_policy_violations_telemetry(st.reply_port_semantics_violation,
		    &sp_info, st.msg->msgh_id);
	}

	return MACH_MSG_SUCCESS;
}


static mach_msg_return_t
ipc_kmsg_inflate_port_descriptor(
	char                   *kdesc_addr,
	const char             *udesc_addr,
	mach_msg_send_uctx_t   *send_uctx)
{
	mach_msg_user_port_descriptor_t udesc;
	mach_msg_port_descriptor_t *kdesc;

	ikm_udsc_get(&udesc, udesc_addr);
	if (os_add_overflow(send_uctx->send_dsc_port_count, 1,
	    &send_uctx->send_dsc_port_count)) {
		return MACH_SEND_TOO_LARGE;
	}

	kdesc = ikm_kdsc_zero(kdesc_addr, mach_msg_port_descriptor_t);
	kdesc->u_name      = CAST_MACH_NAME_TO_PORT(udesc.name);
	kdesc->disposition = udesc.disposition;
	kdesc->type        = udesc.type;
	return MACH_MSG_SUCCESS;
}

static mach_msg_return_t
ipc_kmsg_copyin_port_descriptor(
	mach_msg_port_descriptor_t *dsc,
	ipc_space_t             space,
	ipc_port_t              dest_port,
	ipc_kmsg_t              kmsg)
{
	mach_msg_type_name_t user_disp = dsc->disposition;
	mach_port_name_t     name = CAST_MACH_PORT_TO_NAME(dsc->u_name);
	mach_msg_type_name_t result_disp;
	ipc_port_t           port;
	kern_return_t        kr;

	result_disp = ipc_object_copyin_type(user_disp);
	if (MACH_PORT_VALID(name)) {
		kr = ipc_object_copyin(space, name, user_disp,
		    kmsg->ikm_flags, NULL, &port);
		if (kr != KERN_SUCCESS) {
			if (kr == KERN_INVALID_RIGHT) {
				mach_port_guard_exception(name, 0, kGUARD_EXC_SEND_INVALID_RIGHT);
			}
			return MACH_SEND_INVALID_RIGHT;
		}

		if (result_disp == MACH_MSG_TYPE_PORT_RECEIVE &&
		    ipc_port_check_circularity(port, dest_port)) {
			ikm_header(kmsg)->msgh_bits |= MACH_MSGH_BITS_CIRCULAR;
		}
		dsc->name = port;
	} else {
		dsc->name = CAST_MACH_NAME_TO_PORT(name);
	}

	dsc->disposition = result_disp;
	return MACH_MSG_SUCCESS;
}


static mach_msg_return_t
ipc_kmsg_inflate_ool_descriptor(
	char                   *kdesc_addr,
	const char             *udesc_addr,
	mach_msg_send_uctx_t   *send_uctx,
	bool                    isU64)
{
	mach_msg_ool_descriptor64_t udesc;
	mach_msg_ool_descriptor_t *kdesc;

	if (isU64) {
		ikm_udsc_get(&udesc, udesc_addr);
	} else {
		mach_msg_ool_descriptor32_t udesc32;

		ikm_udsc_get(&udesc32, udesc_addr);
		udesc = (mach_msg_ool_descriptor64_t){
			.address     = udesc32.address,
			.size        = udesc32.size,
			.deallocate  = udesc32.deallocate,
			.copy        = udesc32.copy,
			.type        = udesc32.type,
		};
	}

	switch (udesc.copy) {
	case MACH_MSG_PHYSICAL_COPY:
	case MACH_MSG_VIRTUAL_COPY:
		break;
	default:
		return MACH_SEND_INVALID_TYPE;
	}

	if (udesc.size > msg_ool_size_small &&
	    udesc.copy == MACH_MSG_PHYSICAL_COPY &&
	    !udesc.deallocate) {
		vm_size_t size;

		if (round_page_overflow(udesc.size, &size) ||
		    os_add_overflow(send_uctx->send_dsc_vm_size, size,
		    &send_uctx->send_dsc_vm_size)) {
			return MACH_MSG_VM_KERNEL;
		}
	}

	kdesc = ikm_kdsc_zero(kdesc_addr, mach_msg_ool_descriptor_t);
	kdesc->u_address  = udesc.address;
	kdesc->size       = udesc.size;
	kdesc->deallocate = udesc.deallocate;
	kdesc->copy       = udesc.copy;
	kdesc->type       = udesc.type;
	return MACH_MSG_SUCCESS;
}

static mach_msg_return_t
ipc_kmsg_copyin_ool_descriptor(
	mach_msg_ool_descriptor_t *dsc,
	mach_vm_address_t      *paddr,
	vm_size_t              *space_needed,
	vm_map_t                map)
{
	mach_vm_size_t length = dsc->size;
	vm_map_copy_t  copy = VM_MAP_COPY_NULL;

	if (length == 0) {
		/* nothing to do */
	} else if (length > msg_ool_size_small &&
	    (dsc->copy == MACH_MSG_PHYSICAL_COPY) && !dsc->deallocate) {
		mach_vm_size_t    length_aligned = round_page(length);
		mach_vm_address_t addr = *paddr;

		/*
		 * If the request is a physical copy and the source
		 * is not being deallocated, then allocate space
		 * in the kernel's pageable ipc copy map and copy
		 * the data in.  The semantics guarantee that the
		 * data will have been physically copied before
		 * the send operation terminates.  Thus if the data
		 * is not being deallocated, we must be prepared
		 * to page if the region is sufficiently large.
		 */
		if (mach_copyin(dsc->u_address, (char *)addr, length)) {
			return MACH_SEND_INVALID_MEMORY;
		}

		/*
		 * The kernel ipc copy map is marked no_zero_fill.
		 * If the transfer is not a page multiple, we need
		 * to zero fill the balance.
		 */
		if (!page_aligned(length)) {
			bzero((char *)addr + length, length_aligned - length);
		}

		if (vm_map_copyin(ipc_kernel_copy_map, addr, length,
		    true, &copy) != KERN_SUCCESS) {
			return MACH_MSG_VM_KERNEL;
		}

		*paddr        += length_aligned;
		*space_needed -= length_aligned;
	} else {
		/*
		 * Make a vm_map_copy_t of the of the data.  If the
		 * data is small, this will do an optimized physical
		 * copy.  Otherwise, it will do a virtual copy.
		 *
		 * NOTE: A virtual copy is OK if the original is being
		 * deallocted, even if a physical copy was requested.
		 */
		switch (vm_map_copyin(map, dsc->u_address, length,
		    dsc->deallocate, &copy)) {
		case KERN_SUCCESS:
			break;
		case KERN_RESOURCE_SHORTAGE:
			return MACH_MSG_VM_KERNEL;
		default:
			return MACH_SEND_INVALID_MEMORY;
		}
	}

	dsc->address = copy;
	return MACH_MSG_SUCCESS;
}


static mach_msg_return_t
ipc_kmsg_inflate_ool_ports_descriptor(
	char                   *kdesc_addr,
	const char             *udesc_addr,
	mach_msg_send_uctx_t   *send_uctx,
	bool                    isU64)
{
	mach_msg_ool_ports_descriptor64_t udesc;
	mach_msg_ool_ports_descriptor_t *kdesc;

	if (isU64) {
		ikm_udsc_get(&udesc, udesc_addr);
	} else {
		mach_msg_ool_ports_descriptor32_t udesc32;

		ikm_udsc_get(&udesc32, udesc_addr);
		udesc = (mach_msg_ool_ports_descriptor64_t){
			.address     = udesc32.address,
			.deallocate  = udesc32.deallocate,
			.copy        = udesc32.copy,
			.disposition = udesc32.disposition,
			.type        = udesc32.type,
			.count       = udesc32.count,
		};
	}

	if (os_add_overflow(send_uctx->send_dsc_port_count, udesc.count,
	    &send_uctx->send_dsc_port_count)) {
		return MACH_SEND_TOO_LARGE;
	}

	kdesc = ikm_kdsc_zero(kdesc_addr, mach_msg_ool_ports_descriptor_t);
	kdesc->u_address   = udesc.address;
	kdesc->deallocate  = udesc.deallocate;
	kdesc->copy        = udesc.copy;
	kdesc->disposition = udesc.disposition;
	kdesc->type        = udesc.type;
	kdesc->count       = udesc.count;
	return MACH_MSG_SUCCESS;
}

static mach_msg_return_t
ipc_kmsg_copyin_ool_ports_descriptor(
	mach_msg_ool_ports_descriptor_t *dsc,
	vm_map_t                map,
	ipc_space_t             space,
	ipc_port_t              dest_port,
	ipc_kmsg_t              kmsg)
{
	mach_msg_type_name_t user_disp = dsc->disposition;
	mach_msg_size_t      count = dsc->count;
	mach_msg_type_name_t result_disp;
	mach_port_array_t    array = NULL;
	mach_port_name_t    *names;
	mach_vm_size_t       names_size;

	result_disp = ipc_object_copyin_type(user_disp);
	names_size  = count * sizeof(mach_port_name_t);

	if (count) {
		array = mach_port_array_alloc(count, Z_WAITOK | Z_SPRAYQTN);

		/* use the end of the array to store names we will copy in */
		names = (mach_port_name_t *)(array + count) - count;

		if (mach_copyin(dsc->u_address, names, names_size)) {
			mach_port_array_free(array, count);
			return MACH_SEND_INVALID_MEMORY;
		}
	}

	if (dsc->deallocate) {
		(void)mach_vm_deallocate(map, dsc->u_address, names_size);
	}

	for (mach_msg_size_t i = 0; i < count; i++) {
		mach_port_name_t name = names[i];
		ipc_port_t       port;
		kern_return_t    kr;

		if (!MACH_PORT_VALID(name)) {
			array[i].port = CAST_MACH_NAME_TO_PORT(name);
			continue;
		}

		kr = ipc_object_copyin(space, name, user_disp,
		    kmsg->ikm_flags, NULL, &port);

		if (kr != KERN_SUCCESS) {
			for (mach_msg_size_t j = 0; j < i; j++) {
				port = array[j].port;
				if (IP_VALID(port)) {
					ipc_object_destroy(port, result_disp);
				}
			}
			mach_port_array_free(array, count);

			if (kr == KERN_INVALID_RIGHT) {
				mach_port_guard_exception(name, 0, kGUARD_EXC_SEND_INVALID_RIGHT);
			}
			return MACH_SEND_INVALID_RIGHT;
		}

		if (result_disp == MACH_MSG_TYPE_PORT_RECEIVE &&
		    ipc_port_check_circularity(port, dest_port)) {
			ikm_header(kmsg)->msgh_bits |= MACH_MSGH_BITS_CIRCULAR;
		}

		array[i].port = port;
	}

	dsc->disposition = result_disp;
	dsc->address     = array;
	return MACH_MSG_SUCCESS;
}


static mach_msg_return_t
ipc_kmsg_inflate_guarded_port_descriptor(
	char                   *kdesc_addr,
	const char             *udesc_addr,
	mach_msg_send_uctx_t   *send_uctx,
	bool                    isU64)
{
	mach_msg_guarded_port_descriptor64_t udesc;
	mach_msg_guarded_port_descriptor_t *kdesc;

	if (isU64) {
		ikm_udsc_get(&udesc, udesc_addr);
	} else {
		mach_msg_guarded_port_descriptor32_t udesc32;

		ikm_udsc_get(&udesc32, udesc_addr);
		udesc = (mach_msg_guarded_port_descriptor64_t){
			.context     = udesc32.context,
			.flags       = udesc32.flags,
			.disposition = udesc32.disposition,
			.type        = udesc32.type,
			.name        = udesc32.name,
		};
	}

	if (os_add_overflow(send_uctx->send_dsc_port_count, 1,
	    &send_uctx->send_dsc_port_count)) {
		return MACH_SEND_TOO_LARGE;
	}

	/* Only MACH_MSG_TYPE_MOVE_RECEIVE is supported for now */
	if (udesc.disposition != MACH_MSG_TYPE_MOVE_RECEIVE) {
		return MACH_SEND_INVALID_TYPE;
	}

	if (!udesc.flags ||
	    ((udesc.flags & ~MACH_MSG_GUARD_FLAGS_MASK) != 0) ||
	    ((udesc.flags & MACH_MSG_GUARD_FLAGS_UNGUARDED_ON_SEND) && (udesc.context != 0))) {
		return MACH_SEND_INVALID_TYPE;
	}

	kdesc = ikm_kdsc_zero(kdesc_addr, mach_msg_guarded_port_descriptor_t);
	kdesc->u_context   = udesc.context;
	kdesc->flags       = udesc.flags;
	kdesc->disposition = udesc.disposition;
	kdesc->type        = udesc.type;
	kdesc->u_name      = udesc.name;
	return MACH_MSG_SUCCESS;
}

static mach_msg_return_t
ipc_kmsg_copyin_guarded_port_descriptor(
	mach_msg_guarded_port_descriptor_t *dsc,
	ipc_space_t             space,
	ipc_port_t              dest_port,
	ipc_kmsg_t              kmsg)
{
	mach_msg_type_name_t   user_disp = dsc->disposition;
	mach_port_name_t       name = dsc->u_name;
	mach_msg_type_name_t   result_disp;
	ipc_port_t             port;
	kern_return_t          kr;

	result_disp = ipc_object_copyin_type(user_disp);
	if (MACH_PORT_VALID(name)) {
		kr = ipc_object_copyin(space, name, user_disp,
		    kmsg->ikm_flags, dsc, &port);
		if (kr != KERN_SUCCESS) {
			if (kr == KERN_INVALID_RIGHT) {
				mach_port_guard_exception(name, 0, kGUARD_EXC_SEND_INVALID_RIGHT);
			}
			return MACH_SEND_INVALID_RIGHT;
		}

		if (result_disp == MACH_MSG_TYPE_PORT_RECEIVE &&
		    ipc_port_check_circularity(port, dest_port)) {
			ikm_header(kmsg)->msgh_bits |= MACH_MSGH_BITS_CIRCULAR;
		}
		dsc->name = port;
	} else {
		dsc->name = CAST_MACH_NAME_TO_PORT(name);
	}

	/* dsc->flags were possibly modified by ipc_object_copyin() */
	dsc->disposition = result_disp;
	dsc->u_name      = 0;
	return MACH_MSG_SUCCESS;
}


static mach_msg_return_t
ipc_kmsg_inflate_descriptor(
	char                   *kdesc,
	const char             *udesc,
	mach_msg_send_uctx_t   *send_uctx,
	bool                    isU64)
{
	switch (ikm_udsc_type(udesc)) {
	case MACH_MSG_PORT_DESCRIPTOR:
		return ipc_kmsg_inflate_port_descriptor(kdesc, udesc, send_uctx);
	case MACH_MSG_OOL_VOLATILE_DESCRIPTOR:
	case MACH_MSG_OOL_DESCRIPTOR:
		return ipc_kmsg_inflate_ool_descriptor(kdesc, udesc, send_uctx, isU64);
	case MACH_MSG_OOL_PORTS_DESCRIPTOR:
		return ipc_kmsg_inflate_ool_ports_descriptor(kdesc, udesc, send_uctx, isU64);
	case MACH_MSG_GUARDED_PORT_DESCRIPTOR:
		return ipc_kmsg_inflate_guarded_port_descriptor(kdesc, udesc, send_uctx, isU64);
	default:
		/* verified by ipc_kmsg_measure_descriptors_from_user() */
		__builtin_unreachable();
	}
}

static mach_msg_return_t
ipc_kmsg_inflate_descriptors(
	char             *const descs,
	mach_msg_send_uctx_t   *send_uctx,
	bool                    isU64)
{
	const mach_msg_size_t   desc_count = send_uctx->send_dsc_count;
	const mach_msg_size_t   desc_ksize = desc_count * KERNEL_DESC_SIZE;
	const mach_msg_size_t   desc_usize = send_uctx->send_dsc_usize;
	char                   *kdesc      = descs;
	char                   *udesc      = descs;
	mach_msg_return_t       mr         = MACH_MSG_SUCCESS;

	if (__probable(desc_count <= 64)) {
		/*
		 * If there are less than 64 descriptors, then we can use
		 * the udesc_mask to know by how much to shift data,
		 * and inflate right to left.
		 */
		kdesc += desc_ksize;
		udesc += desc_usize;

		for (uint64_t bit = 1ull << (desc_count - 1); bit; bit >>= 1) {
			kdesc -= KERNEL_DESC_SIZE;
			if (send_uctx->send_dsc_mask & bit) {
				udesc -= USER_DESC_SIZE_MAX;
			} else {
				udesc -= USER_DESC_SIZE_MIN;
			}
			mr = ipc_kmsg_inflate_descriptor(kdesc, udesc,
			    send_uctx, isU64);
			if (mr != MACH_MSG_SUCCESS) {
				return mr;
			}
		}
	} else {
		/*
		 * Else, move all descriptors at the end of the buffer,
		 * and inflate them left to right.
		 */

		udesc += desc_ksize - desc_usize;
		memmove(udesc, kdesc, desc_usize);

		for (mach_msg_size_t i = 0; i < desc_count; i++) {
			mach_msg_size_t dsize;

			dsize = ikm_user_desc_size(ikm_udsc_type(udesc), isU64);
			mr = ipc_kmsg_inflate_descriptor(kdesc, udesc,
			    send_uctx, isU64);
			if (mr != MACH_MSG_SUCCESS) {
				return mr;
			}
			udesc += dsize;
			kdesc += KERNEL_DESC_SIZE;
		}
	}

	return MACH_MSG_SUCCESS;
}

static inline bool
ipc_kmsg_user_desc_type_is_valid(
	mach_msg_descriptor_type_t type,
	mach_msg_option64_t        options)
{
	switch (type) {
	case MACH_MSG_PORT_DESCRIPTOR:
	case MACH_MSG_OOL_DESCRIPTOR:
	case MACH_MSG_OOL_PORTS_DESCRIPTOR:
		return true;
	case MACH_MSG_OOL_VOLATILE_DESCRIPTOR:
	case MACH_MSG_GUARDED_PORT_DESCRIPTOR:
		/*
		 * only allow port and memory descriptors for kobjects and
		 * driverkit.
		 */
		return !(options & (MACH64_SEND_KOBJECT_CALL | MACH64_SEND_DK_CALL));
	default:
		return false;
	}
}

/*!
 * @brief
 * Quickly validate and measure the layout of user descriptors.
 *
 * @description
 * This function fills:
 * - the send_dsc_usize field with the size of user descriptors,
 * - the send_dsc_mask field representing which of the first 64
 *   first descriptors whose size is 12 (bit is 0) or 16 (bit is 1).
 *
 * @param addr          the address of where user descriptors start.
 * @param size          the size of the data to parse (descriptors might
 *                      be less, but can't be more).
 * @param send_uctx     the context used for this MACH_SEND_MSG operation.
 * @param options       the options for this MACH_SEND_MSG operation.
 * @param isU64         whether the current user task is 64 bit.
 * @returns
 * - MACH_MSG_SUCCESS   if parsing was successful.
 * - MACH_SEND_MSG_TOO_SMALL
 *                      if there wasn't enough data to parse
 *                      send_dsc_count descriptors
 * - MACH_SEND_INVALID_TYPE
 *                      if descriptors types parsed aren't valid
 *                      or allowed by policy.
 */
__result_use_check
static mach_msg_return_t
ipc_kmsg_measure_descriptors_from_user(
	vm_address_t            addr,
	mach_msg_size_t         size,
	mach_msg_send_uctx_t   *send_uctx,
	mach_msg_option64_t     options,
	bool                    isU64)
{
	mach_msg_size_t dcnt = send_uctx->send_dsc_count;
	mach_msg_size_t dpos = 0;
	uint64_t        mask = 0;
	uint64_t        bit  = 1;

	for (mach_msg_size_t i = 0; i < dcnt; i++, bit <<= 1) {
		mach_msg_descriptor_type_t dtype;
		mach_msg_size_t dsize;

		if (dpos + USER_DESC_SIZE_MIN > size) {
			return MACH_SEND_MSG_TOO_SMALL;
		}
		dtype = ikm_udsc_type(addr + dpos);
		if (!ipc_kmsg_user_desc_type_is_valid(dtype, options)) {
			return MACH_SEND_INVALID_TYPE;
		}
		dsize = ikm_user_desc_size(dtype, isU64);
		if (dsize == USER_DESC_SIZE_MAX) {
			mask |= bit;
		}
		dpos += dsize;
		if (dpos > size) {
			return MACH_SEND_MSG_TOO_SMALL;
		}
	}

	send_uctx->send_dsc_usize = dpos;
	send_uctx->send_dsc_mask  = mask;
	return MACH_MSG_SUCCESS;
}

/*
 *	Routine:	ipc_kmsg_copyin_body
 *	Purpose:
 *		"Copy-in" port rights and out-of-line memory
 *		in the message body.
 *
 *		In all failure cases, the message is left holding
 *		no rights or memory.  However, the message buffer
 *		is not deallocated.  If successful, the message
 *		contains a valid destination port.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		MACH_MSG_SUCCESS	Successful copyin.
 *		MACH_SEND_INVALID_MEMORY	Can't grab out-of-line memory.
 *		MACH_SEND_INVALID_RIGHT	Can't copyin port right in body.
 *		MACH_SEND_INVALID_TYPE	Bad type specification.
 *		MACH_SEND_MSG_TOO_SMALL	Body is too small for types/data.
 *		MACH_SEND_INVALID_RT_OOL_SIZE OOL Buffer too large for RT
 *		MACH_MSG_INVALID_RT_DESCRIPTOR Dealloc and RT are incompatible
 *		MACH_SEND_NO_GRANT_DEST	Dest port doesn't accept ports in body
 */

static mach_msg_return_t
ipc_kmsg_copyin_body(
	ipc_kmsg_t              kmsg,
	mach_msg_send_uctx_t   *send_uctx,
	ipc_space_t             space,
	vm_map_t                map)
{
	mach_msg_type_number_t  dsc_count = send_uctx->send_dsc_count;
	vm_size_t               psize = send_uctx->send_dsc_vm_size;
	mach_vm_address_t       paddr = 0;
	mach_msg_header_t      *hdr   = ikm_header(kmsg);
	mach_msg_kbase_t       *kbase = mach_msg_header_to_kbase(hdr);
	ipc_port_t              dest_port = hdr->msgh_remote_port;

	assert(hdr->msgh_bits & MACH_MSGH_BITS_COMPLEX);

	/*
	 * Allocate space in the pageable kernel ipc copy map for all the
	 * ool data that is to be physically copied.  Map is marked wait for
	 * space.
	 */
	if (psize) {
		kern_return_t kr;

		kr  = mach_vm_allocate_kernel(ipc_kernel_copy_map, &paddr, psize,
		    VM_MAP_KERNEL_FLAGS_ANYWHERE(.vm_tag = VM_KERN_MEMORY_IPC));
		if (kr != KERN_SUCCESS) {
			ipc_kmsg_clean_header(kmsg);
			return MACH_MSG_VM_KERNEL;
		}
	}

	/*
	 * Receive right of a libxpc connection port is moved as a part of kmsg's body
	 * 1. from a client to a service during connection etsablishment.
	 * 2. back to the client on service's death or port deallocation.
	 *
	 * Any other attempt to move this receive right is not allowed.
	 */
	kmsg->ikm_flags |= IPC_OBJECT_COPYIN_FLAGS_ALLOW_CONN_IMMOVABLE_RECEIVE;

	for (mach_msg_size_t copied_in_dscs = 0; copied_in_dscs < dsc_count; copied_in_dscs++) {
		mach_msg_kdescriptor_t *kdesc = &kbase->msgb_dsc_array[copied_in_dscs];
		mach_msg_return_t mr;

		switch (mach_msg_kdescriptor_type(kdesc)) {
		case MACH_MSG_PORT_DESCRIPTOR:
			mr = ipc_kmsg_copyin_port_descriptor(&kdesc->kdesc_port,
			    space, dest_port, kmsg);
			break;
		case MACH_MSG_OOL_VOLATILE_DESCRIPTOR:
		case MACH_MSG_OOL_DESCRIPTOR:
			mr = ipc_kmsg_copyin_ool_descriptor(&kdesc->kdesc_memory,
			    &paddr, &psize, map);
			break;
		case MACH_MSG_OOL_PORTS_DESCRIPTOR:
			mr = ipc_kmsg_copyin_ool_ports_descriptor(&kdesc->kdesc_port_array,
			    map, space, dest_port, kmsg);
			break;
		case MACH_MSG_GUARDED_PORT_DESCRIPTOR:
			mr = ipc_kmsg_copyin_guarded_port_descriptor(&kdesc->kdesc_guarded_port,
			    space, dest_port, kmsg);
			break;
		default:
			__builtin_unreachable();
		}

		if (MACH_MSG_SUCCESS != mr) {
			/* clean from start of message descriptors to copied_in_dscs */
			ipc_kmsg_clean_header(kmsg);
			ipc_kmsg_clean_descriptors(kbase->msgb_dsc_array,
			    copied_in_dscs);
			if (psize) {
				kmem_free(ipc_kernel_copy_map, paddr, psize);
			}
			return mr;
		}
	}

	assert(psize == 0);
	return MACH_MSG_SUCCESS;
}

/*
 *	Routine:	ipc_kmsg_get_and_inflate_from_user()
 *	Purpose:
 *		Copies in user message (and aux) to the allocated
 *		kernel message buffer, and expands header and descriptor
 *		into "kernel" format.
 *
 *	Conditions:
 *		msg up to sizeof(mach_msg_user_header_t) has been previously
 *		copied in, and number of descriptors has been made known.
 *
 *		if send_aux_size is not 0, mach_msg_validate_data_vectors()
 *		guarantees that aux_size must be larger than
 *		mach_msg_aux_header_t.
 */
static mach_msg_return_t
ipc_kmsg_get_and_inflate_from_user(
	ipc_kmsg_t              kmsg,
	mach_msg_send_uctx_t   *send_uctx,
	mach_msg_header_t      *khdr,
	vm_map_t                map,
	mach_msg_option64_t     options)
{
	bool                    isU64 = (map->max_offset > VM_MAX_ADDRESS);
	mach_msg_user_header_t *uhdr  = &send_uctx->send_header;
	char                   *kdesc = (char *)khdr; /* where descriptors start */
	char                   *kbody = NULL;         /* where the body starts   */
	mach_msg_size_t         upos  = 0;            /* copyin cursor so far    */
	mach_msg_size_t         usize = send_uctx->send_msg_size;
	mach_msg_return_t       mr    = MACH_MSG_SUCCESS;

	/*
	 * Step 1: inflate the header in kernel representation
	 *
	 * Notable steps:
	 * - the msgh_bits are normalized
	 * - the msgh_size is incorrect until we measure descriptors
	 */
	*khdr = (mach_msg_header_t){
		.msgh_bits         = uhdr->msgh_bits & MACH_MSGH_BITS_USER,
		.msgh_size         = usize + USER_HEADER_SIZE_DELTA,
		.msgh_remote_port  = CAST_MACH_NAME_TO_PORT(uhdr->msgh_remote_port),
		.msgh_local_port   = CAST_MACH_NAME_TO_PORT(uhdr->msgh_local_port),
		.msgh_voucher_port = uhdr->msgh_voucher_port,
		.msgh_id           = uhdr->msgh_id,
	};

	if (uhdr->msgh_bits & MACH_MSGH_BITS_COMPLEX) {
		mach_msg_kbase_t *kbase = mach_msg_header_to_kbase(khdr);

		kbase->msgb_dsc_count = send_uctx->send_dsc_count;
		kdesc = (char *)(kbase + 1);
		upos  = sizeof(mach_msg_user_base_t);
	} else {
		kdesc = (char *)(khdr + 1);
		upos  = sizeof(mach_msg_user_header_t);
	}
	if (ikm_is_linear(kmsg)) {
		kbody = (char *)kdesc +
		    send_uctx->send_dsc_count * KERNEL_DESC_SIZE;
	} else {
		kbody = kmsg->ikm_udata;
	}

	/*
	 * Step 2: inflate descriptors in kernel representation
	 *
	 * Notable steps:
	 * - for linear messages we will copy the entire body too at once.
	 * - the msgh_size will be updated for the inflated size of descriptors.
	 */
	if (send_uctx->send_dsc_count) {
		mach_msg_size_t desc_count = send_uctx->send_dsc_count;
		mach_msg_size_t desc_ksize = desc_count * KERNEL_DESC_SIZE;
		mach_msg_size_t copyin_size;

		/*
		 * If kmsg is linear, copy in all data in the buffer.
		 * Otherwise, first copyin until the end of descriptors
		 * or the message, whichever comes first.
		 */
		if (ikm_is_linear(kmsg)) {
			copyin_size = usize - upos;
		} else {
			copyin_size = MIN(desc_ksize, usize - upos);
		}
		assert((vm_offset_t)kdesc + copyin_size <= ikm_kdata_end(kmsg));

		if (copyinmsg(send_uctx->send_msg_addr + upos, kdesc, copyin_size)) {
			return MACH_SEND_INVALID_DATA;
		}
		upos += copyin_size;

		/*
		 * pre-validate and measure the descriptors user claims
		 * to have by checking their size and type.
		 */
		mr = ipc_kmsg_measure_descriptors_from_user((vm_address_t)kdesc,
		    copyin_size, send_uctx, options, isU64);
		if (mr != MACH_MSG_SUCCESS) {
			return mr;
		}
		khdr->msgh_size += desc_ksize - send_uctx->send_dsc_usize;

		/*
		 * If the descriptors user size is smaller than their
		 * kernel size, we copied in some piece of body that we need to
		 * relocate, and we need to inflate descriptors.
		 */
		if (send_uctx->send_dsc_usize != desc_ksize) {
			memmove(kbody, kdesc + send_uctx->send_dsc_usize,
			    copyin_size - send_uctx->send_dsc_usize);
			kbody += copyin_size - send_uctx->send_dsc_usize;
		}

		mr = ipc_kmsg_inflate_descriptors(kdesc, send_uctx,
		    map->max_offset > VM_MAX_ADDRESS);
		if (mr != MACH_MSG_SUCCESS) {
			return mr;
		}
	}

	/*
	 * Step 3: copy pure user data remaining.
	 */
	if (upos < usize &&
	    copyinmsg(send_uctx->send_msg_addr + upos, kbody, usize - upos)) {
		return MACH_SEND_INVALID_DATA;
	}
	kbody += usize - upos;

	/*
	 * Step 4: copy auxiliary data if any
	 */
	if (send_uctx->send_aux_size) {
		mach_msg_aux_header_t *aux_hdr  = ikm_aux_header(kmsg);
		mach_msg_size_t        aux_size = send_uctx->send_aux_size;

		assert((vm_offset_t)kbody <= (vm_offset_t)aux_hdr);
		assert(aux_size >= sizeof(aux_hdr[0]));

		/* initialize aux data header */
		aux_hdr->msgdh_size = send_uctx->send_aux_size;
		aux_hdr->msgdh_reserved = 0;

		/* copyin aux data after the header */
		if (aux_size > sizeof(aux_hdr[0]) &&
		    copyinmsg(send_uctx->send_aux_addr + sizeof(*aux_hdr),
		    aux_hdr + 1, aux_size - sizeof(*aux_hdr))) {
			return MACH_SEND_INVALID_DATA;
		}
	}

	return MACH_MSG_SUCCESS;
}

/*
 *	Routine:	ipc_kmsg_copyin_from_user
 *	Purpose:
 *		"Copy-in" port rights and out-of-line memory
 *		in the message.
 *
 *		In all failure cases, the message is left holding
 *		no rights or memory.  However, the message buffer
 *		is not deallocated.  If successful, the message
 *		contains a valid destination port.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		MACH_MSG_SUCCESS	Successful copyin.
 *		MACH_SEND_INVALID_HEADER Illegal value in the message header bits.
 *		MACH_SEND_INVALID_DEST	Can't copyin destination port.
 *		MACH_SEND_INVALID_REPLY	Can't copyin reply port.
 *		MACH_SEND_INVALID_MEMORY	Can't grab out-of-line memory.
 *		MACH_SEND_INVALID_RIGHT	Can't copyin port right in body.
 *		MACH_SEND_INVALID_TYPE	Bad type specification.
 *		MACH_SEND_MSG_TOO_SMALL	Body is too small for types/data.
 */

mach_msg_return_t
ipc_kmsg_copyin_from_user(
	ipc_kmsg_t              kmsg,
	mach_msg_send_uctx_t   *send_uctx,
	ipc_space_t             space,
	vm_map_t                map,
	mach_msg_priority_t     priority,
	mach_msg_option64_t    *option64p)
{
	mach_msg_option64_t options = *option64p;
	mach_msg_header_t  *hdr = ikm_header(kmsg);
	mach_msg_return_t   mr;

	mr = ipc_validate_kmsg_header_schema_from_user(&send_uctx->send_header,
	    send_uctx->send_dsc_count, options);
	if (mr != MACH_MSG_SUCCESS) {
		return mr;
	}

	mr = ipc_kmsg_get_and_inflate_from_user(kmsg, send_uctx,
	    hdr, map, options);
	if (mr != MACH_MSG_SUCCESS) {
		return mr;
	}

	mr = ipc_validate_kmsg_schema_from_user(hdr, send_uctx, options);
	if (mr != MACH_MSG_SUCCESS) {
		return mr;
	}

	/* copyin_header may add MACH64_SEND_ALWAYS option */
	mr = ipc_kmsg_copyin_header(kmsg, space, priority, option64p);
	if (mr != MACH_MSG_SUCCESS) {
		return mr;
	}
	options = *option64p;

	mr = ipc_validate_kmsg_header_from_user(hdr, send_uctx, options);
	if (mr != MACH_MSG_SUCCESS) {
		/* no descriptors have been copied in yet */
		ipc_kmsg_clean_header(kmsg);
		return mr;
	}

	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_MSG_SEND) | DBG_FUNC_NONE,
	    VM_KERNEL_ADDRPERM((uintptr_t)kmsg),
	    (uintptr_t)hdr->msgh_bits,
	    (uintptr_t)hdr->msgh_id,
	    VM_KERNEL_ADDRPERM((uintptr_t)unsafe_convert_port_to_voucher(ipc_kmsg_get_voucher_port(kmsg))),
	    0);

	DEBUG_KPRINT_SYSCALL_IPC("ipc_kmsg_copyin_from_user header:\n%.8x\n%.8x\n%p\n%p\n%p\n%.8x\n",
	    hdr->msgh_size,
	    hdr->msgh_bits,
	    hdr->msgh_remote_port,
	    hdr->msgh_local_port,
	    ipc_kmsg_get_voucher_port(kmsg),
	    hdr->msgh_id);

	if (hdr->msgh_bits & MACH_MSGH_BITS_COMPLEX) {
		mr = ipc_kmsg_copyin_body(kmsg, send_uctx, space, map);
	}

	return mr;
}

/** @} */
#pragma mark ipc_kmsg copyout and deflate (to user)
/*!
 * @defgroup IPC kmsg copyout and deflate functions
 * @{
 *
 * IPC (right) copyout
 * ~~~~~~~~~~~~~~~~~~~
 *
 * This is the operation that turns kernel objects like IPC ports or
 * vm_map_copy_t and turns them into port names or userspace VM addresses.
 *
 * This is done on an IPC kmsg in "kernel representation" and just replace
 * kernel pointers with scalar values only meaningful to userspace in place.
 *
 * There are several copyout machineries that will drive this operation:
 * - @c ipc_kmsg_copyout() for the regular case,
 * - @c ipc_kmsg_copyout_pseudo() for pseud-receive,
 * - @c ipc_kmsg_copyout_dest_to_user() for receive error cases
 *   where the actual message is destroyed and a minimal message
 *   is received instead.
 *
 * Copied out messages do not hold any "right" in the "kdata" part of the
 * message anymore.
 *
 *
 * IPC kmsg deflate
 * ~~~~~~~~~~~~~~~~
 *
 * This is the operation that turns a message in kernel representation,
 * but with rights copied out, into user representation.
 *
 * This is driven by @c ipc_kmsg_deflate() which will:
 * - convert the message header into user layout (mach_msg_user_header_t),
 * - convert the descriptors into user layout,
 * - generate receive time parts of the trailer and convert it to user layout.
 *
 * This operation mangles the payload of the kmsg, making most of the kmsg
 * functions have undefined behavior. The only valid things to do with
 * a deflated message is to copy the bytes back to userspace and destroy
 * the message with @c ipc_kmsg_free().
 *
 *
 * Note that deflation will maintain the position of the pure data bodies
 * trailers and auxiliary data payloads. The deflation causes the header
 * desscriptors to contract by moving the start of the message rather
 * than by shortening it.
 *
 * As a result, it means that deflation works left-to-right (end toward start),
 * starting with the trailer, then descriptors and header last.
 * (@see @c ipc_kmsg_deflate() and @c ipc_kmsg_deflate_descriptors()).
 *
 *
 * IPC kmsg "put"
 * ~~~~~~~~~~~~~~
 *
 * This denotes the operation that copies the paylaod of an IPC kmsg into the
 * provided buffer, ending with the IPC kmsg being freed.
 *
 * There are two possible variants of this operation:
 *
 * - @c ipc_kmsg_put_to_kernel() which uses a kernel provided buffer,
 *   and performs no transformation. It is used for kernel upcall replies
 *   (see kernel_mach_msg_rpc()).
 *
 * - @c ipc_kmsg_put_to_user() which uses a user provided buffer.
 *   The message will undergo copyout and deflation before the put to user
 *   actually happens. This is used by the user mach_msg() receive paths.
 */

/*!
 * @typedef ikm_deflate_context_t
 *
 * @brief
 * Data structure holding the various parameters during a deflate operation.
 *
 * @field dctx_uhdr             the pointer to the start of the user header
 * @field dctx_udata            the pointer to the pure data parts or NULL
 * @field dctx_trailer          the pointer to the trailer,
 *                              or NULL if doing a pseudo-receive.
 * @field dctx_aux_hdr          the pointer to the auxiliary data or NULL.
 *
 * @field dctx_uhdr_size        the number of bytes to copyout from dctx_uhdr.
 * @field dctx_udata_size       the number of bytes to copyout from dctx_udata,
 *                              or 0 if dctx_udata is NULL.
 * @field dctx_trailer_size     the size of the trailer,
 *                              or 0 if dctx_trailer is NULL.
 * @field dctx_aux_size         the size of the auxiliary data payload,
 *                              or 0 if dctx_aux_hdr is NULL.
 * @field dctx_isU64            whether the user process receiving the message
 *                              is 32 or 64bits.
 */
typedef struct {
	char                   *dctx_uhdr;
	char                   *dctx_udata;
	mach_msg_max_trailer_t *dctx_trailer;
	mach_msg_aux_header_t  *dctx_aux_hdr;
	mach_msg_size_t         dctx_uhdr_size;
	mach_msg_size_t         dctx_udata_size;
	mach_msg_size_t         dctx_trailer_size;
	mach_msg_size_t         dctx_aux_size;
	bool                    dctx_isU64;
} ikm_deflate_context_t;

#define ipc_kmsg_deflate_put(udesc_end, value) \
	memcpy((udesc_end) - sizeof(*(value)), (value), sizeof(*(value)))

/*
 *	Routine:	ipc_kmsg_copyout_header
 *	Purpose:
 *		"Copy-out" port rights in the header of a message.
 *		Operates atomically; if it doesn't succeed the
 *		message header and the space are left untouched.
 *		If it does succeed the remote/local port fields
 *		contain port names instead of object pointers,
 *		and the bits field is updated.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		MACH_MSG_SUCCESS	Copied out port rights.
 *		MACH_RCV_INVALID_NOTIFY
 *			Notify is non-null and doesn't name a receive right.
 *			(Either KERN_INVALID_NAME or KERN_INVALID_RIGHT.)
 *		MACH_RCV_HEADER_ERROR|MACH_MSG_IPC_SPACE
 *			The space is dead.
 *		MACH_RCV_HEADER_ERROR|MACH_MSG_IPC_SPACE
 *			No room in space for another name.
 *		MACH_RCV_HEADER_ERROR|MACH_MSG_IPC_KERNEL
 *			Couldn't allocate memory for the reply port.
 *		MACH_RCV_HEADER_ERROR|MACH_MSG_IPC_KERNEL
 *			Couldn't allocate memory for the dead-name request.
 */
static mach_msg_return_t
ipc_kmsg_copyout_header(
	ipc_kmsg_t              kmsg,
	mach_msg_header_t      *msg,
	ipc_space_t             space,
	mach_msg_option64_t     option)
{
	mach_msg_bits_t mbits = msg->msgh_bits;
	ipc_port_t dest = msg->msgh_remote_port;

	mach_msg_type_name_t dest_type = MACH_MSGH_BITS_REMOTE(mbits);
	mach_msg_type_name_t reply_type = MACH_MSGH_BITS_LOCAL(mbits);
	mach_msg_type_name_t voucher_type = MACH_MSGH_BITS_VOUCHER(mbits);
	ipc_port_t reply = msg->msgh_local_port;
	ipc_port_t release_reply_port = IP_NULL;
	mach_port_name_t dest_name, reply_name;

	ipc_port_t voucher = ipc_kmsg_get_voucher_port(kmsg);
	uintptr_t voucher_addr = 0;
	ipc_port_t release_voucher_port = IP_NULL;
	mach_port_name_t voucher_name;

	uint32_t entries_held = 0;
	boolean_t need_write_lock = FALSE;
	ipc_object_copyout_flags_t reply_copyout_options = IPC_OBJECT_COPYOUT_FLAGS_NONE;
	kern_return_t kr;

	assert(IP_VALID(dest));

	/*
	 * While we still hold a reference on the received-from port,
	 * process all send-possible notfications we received along with
	 * the message.
	 */
	ipc_port_spnotify(dest);

	/*
	 * Reserve any potentially needed entries in the target space.
	 * We'll free any unused before unlocking the space.
	 */
	if (IP_VALID(reply)) {
		entries_held++;
		need_write_lock = TRUE;
	}
	if (IP_VALID(voucher)) {
		assert(voucher_type == MACH_MSG_TYPE_MOVE_SEND);

		if ((option & MACH_RCV_VOUCHER) != 0) {
			entries_held++;
		}
		need_write_lock = TRUE;
		voucher_addr = unsafe_convert_port_to_voucher(voucher);
	}

	if (need_write_lock) {
handle_reply_again:
		is_write_lock(space);

		while (entries_held) {
			if (!is_active(space)) {
				is_write_unlock(space);
				return MACH_RCV_HEADER_ERROR |
				       MACH_MSG_IPC_SPACE;
			}

			kr = ipc_entries_hold(space, entries_held);
			if (KERN_SUCCESS == kr) {
				break;
			}

			kr = ipc_entry_grow_table(space, ITS_SIZE_NONE);
			if (KERN_SUCCESS != kr) {
				return MACH_RCV_HEADER_ERROR |
				       MACH_MSG_IPC_SPACE;
			}
			/* space was unlocked and relocked - retry */
		}

		/* Handle reply port. */
		if (IP_VALID(reply)) {
			ipc_port_t reply_subst = IP_NULL;
			ipc_entry_t entry;

			ip_mq_lock_check_aligned(reply);

			/* Is the reply port still active and allowed to be copied out? */
			if (!ip_active(reply) ||
			    !ip_label_check(space, reply, reply_type,
			    &reply_copyout_options, &reply_subst)) {
				/* clear the context value */
				reply->ip_reply_context = 0;
				ip_mq_unlock(reply);

				assert(reply_subst == IP_NULL);
				release_reply_port = reply;
				reply = IP_DEAD;
				reply_name = MACH_PORT_DEAD;
				goto done_with_reply;
			}

			/* is the kolabel requesting a substitution */
			if (reply_subst != IP_NULL) {
				/*
				 * port is unlocked, its right consumed
				 * space is unlocked
				 */
				assert(reply_type == MACH_MSG_TYPE_PORT_SEND);
				msg->msgh_local_port = reply = reply_subst;
				goto handle_reply_again;
			}


			/* Is there already an entry we can use? */
			if ((reply_type != MACH_MSG_TYPE_PORT_SEND_ONCE) &&
			    ipc_right_reverse(space, reply, &reply_name, &entry)) {
				assert(entry->ie_bits & MACH_PORT_TYPE_SEND_RECEIVE);
			} else {
				/* claim a held entry for the reply port */
				assert(entries_held > 0);
				entries_held--;
				ipc_entry_claim(space, ip_to_object(reply),
				    &reply_name, &entry);
			}

			/* space and reply port are locked and active */
			ip_reference(reply);         /* hold onto the reply port */

			/*
			 * If the receiver would like to enforce strict reply
			 * semantics, and the message looks like it expects a reply,
			 * and contains a voucher, then link the context in the
			 * voucher with the reply port so that the next message sent
			 * to the reply port must come from a thread that has a
			 * matching context (voucher).
			 */
			if (enforce_strict_reply && MACH_RCV_WITH_STRICT_REPLY(option) && IP_VALID(voucher)) {
				if (ipc_kmsg_validate_reply_port_locked(reply, option) != KERN_SUCCESS) {
					/* if the receiver isn't happy with the reply port: fail the receive. */
					assert(!ip_is_pinned(reply));
					ipc_entry_dealloc(space, ip_to_object(reply),
					    reply_name, entry);
					ip_mq_unlock(reply);
					is_write_unlock(space);
					ip_release(reply);
					return MACH_RCV_INVALID_REPLY;
				}
				ipc_kmsg_link_reply_context_locked(reply, voucher);
			} else {
				/*
				 * if the receive did not choose to participate
				 * in the strict reply/RPC, then don't enforce
				 * anything (as this could lead to booby-trapped
				 * messages that kill the server).
				 */
				reply->ip_reply_context = 0;
			}

			kr = ipc_right_copyout(space, reply, reply_type,
			    IPC_OBJECT_COPYOUT_FLAGS_NONE, reply_name, entry,
			    NULL);
			assert(kr == KERN_SUCCESS);
			/* reply port is unlocked */
		} else {
			reply_name = CAST_MACH_PORT_TO_NAME(reply);
		}

done_with_reply:

		/* Handle voucher port. */
		if (voucher_type != MACH_MSGH_BITS_ZERO) {
			assert(voucher_type == MACH_MSG_TYPE_MOVE_SEND);

			if (!IP_VALID(voucher)) {
				if ((option & MACH_RCV_VOUCHER) == 0) {
					voucher_type = MACH_MSGH_BITS_ZERO;
				}
				voucher_name = MACH_PORT_NULL;
				goto done_with_voucher;
			}

#if CONFIG_PREADOPT_TG
			struct knote *kn = current_thread()->ith_knote;
			if (kn == ITH_KNOTE_NULL || kn == ITH_KNOTE_PSEUDO) {
				/*
				 * We are not in this path of voucher copyout because of
				 * kevent - we cannot expect a voucher preadopt happening on
				 * this thread for this message later on
				 */
				KDBG_DEBUG(MACHDBG_CODE(DBG_MACH_THREAD_GROUP, MACH_THREAD_GROUP_PREADOPT_NA),
				    thread_tid(current_thread()), 0, 0, 0);
			}
#endif

			/* clear voucher from its hiding place back in the kmsg */
			ipc_kmsg_clear_voucher_port(kmsg);

			if ((option & MACH_RCV_VOUCHER) != 0) {
				ipc_entry_t entry;

				ip_mq_lock_check_aligned(voucher);

				if (ipc_right_reverse(space, voucher,
				    &voucher_name, &entry)) {
					assert(entry->ie_bits & MACH_PORT_TYPE_SEND);
				} else {
					assert(entries_held > 0);
					entries_held--;
					ipc_entry_claim(space, ip_to_object(voucher), &voucher_name, &entry);
				}
				/* space is locked and active */

				assert(ip_kotype(voucher) == IKOT_VOUCHER);
				kr = ipc_right_copyout(space, voucher,
				    MACH_MSG_TYPE_MOVE_SEND, IPC_OBJECT_COPYOUT_FLAGS_NONE,
				    voucher_name, entry, NULL);
				/* voucher port is unlocked */
			} else {
				voucher_type = MACH_MSGH_BITS_ZERO;
				release_voucher_port = voucher;
				voucher_name = MACH_PORT_NULL;
			}
		} else {
			voucher_name = msg->msgh_voucher_port;
		}

done_with_voucher:

		ip_mq_lock(dest);
		is_write_unlock(space);
	} else {
		/*
		 *	No reply or voucher port!  This is an easy case.
		 *
		 *	We only need to check that the space is still
		 *	active once we locked the destination:
		 *
		 *	- if the space holds a receive right for `dest`,
		 *	  then holding the port lock means we can't fail
		 *	  to notice if the space went dead because
		 *	  the is_write_unlock() will pair with
		 *	  os_atomic_barrier_before_lock_acquire() + ip_mq_lock().
		 *
		 *	- if this space doesn't hold a receive right
		 *	  for `dest`, then `dest->ip_receiver` points
		 *	  elsewhere, and ipc_object_copyout_dest() will
		 *	  handle this situation, and failing to notice
		 *	  that the space was dead is accetable.
		 */

		os_atomic_barrier_before_lock_acquire();
		ip_mq_lock(dest);
		if (!is_active(space)) {
			ip_mq_unlock(dest);
			return MACH_RCV_HEADER_ERROR | MACH_MSG_IPC_SPACE;
		}

		reply_name = CAST_MACH_PORT_TO_NAME(reply);

		if (voucher_type != MACH_MSGH_BITS_ZERO) {
			assert(voucher_type == MACH_MSG_TYPE_MOVE_SEND);
			if ((option & MACH_RCV_VOUCHER) == 0) {
				voucher_type = MACH_MSGH_BITS_ZERO;
			}
			voucher_name = MACH_PORT_NULL;
		} else {
			voucher_name = msg->msgh_voucher_port;
		}
	}

	/*
	 *	At this point, the space is unlocked and the destination
	 *	port is locked.
	 *	reply_name is taken care of; we still need dest_name.
	 *	We still hold a ref for reply (if it is valid).
	 *
	 *	If the space holds receive rights for the destination,
	 *	we return its name for the right.  Otherwise the task
	 *	managed to destroy or give away the receive right between
	 *	receiving the message and this copyout.  If the destination
	 *	is dead, return MACH_PORT_DEAD, and if the receive right
	 *	exists somewhere else (another space, in transit)
	 *	return MACH_PORT_NULL.
	 *
	 *	Making this copyout operation atomic with the previous
	 *	copyout of the reply port is a bit tricky.  If there was
	 *	no real reply port (it wasn't IP_VALID) then this isn't
	 *	an issue.  If the reply port was dead at copyout time,
	 *	then we are OK, because if dest is dead we serialize
	 *	after the death of both ports and if dest is alive
	 *	we serialize after reply died but before dest's (later) death.
	 *	So assume reply was alive when we copied it out.  If dest
	 *	is alive, then we are OK because we serialize before
	 *	the ports' deaths.  So assume dest is dead when we look at it.
	 *	If reply dies/died after dest, then we are OK because
	 *	we serialize after dest died but before reply dies.
	 *	So the hard case is when reply is alive at copyout,
	 *	dest is dead at copyout, and reply died before dest died.
	 *	In this case pretend that dest is still alive, so
	 *	we serialize while both ports are alive.
	 *
	 *	Because the space lock is held across the copyout of reply
	 *	and locking dest, the receive right for dest can't move
	 *	in or out of the space while the copyouts happen, so
	 *	that isn't an atomicity problem.  In the last hard case
	 *	above, this implies that when dest is dead that the
	 *	space couldn't have had receive rights for dest at
	 *	the time reply was copied-out, so when we pretend
	 *	that dest is still alive, we can return MACH_PORT_NULL.
	 *
	 *	If dest == reply, then we have to make it look like
	 *	either both copyouts happened before the port died,
	 *	or both happened after the port died.  This special
	 *	case works naturally if the timestamp comparison
	 *	is done correctly.
	 */

	if (ip_active(dest)) {
		ipc_object_copyout_dest(space, dest, dest_type, &dest_name);
		/* dest is unlocked */
	} else {
		ipc_port_timestamp_t timestamp;

		timestamp = ip_get_death_time(dest);
		ip_mq_unlock(dest);
		ip_release(dest);

		if (IP_VALID(reply)) {
			ip_mq_lock(reply);
			if (ip_active(reply) ||
			    IP_TIMESTAMP_ORDER(timestamp,
			    ip_get_death_time(reply))) {
				dest_name = MACH_PORT_DEAD;
			} else {
				dest_name = MACH_PORT_NULL;
			}
			ip_mq_unlock(reply);
		} else {
			dest_name = MACH_PORT_DEAD;
		}
	}

	if (IP_VALID(reply)) {
		ip_release(reply);
	}

	if (IP_VALID(release_reply_port)) {
		if (reply_type == MACH_MSG_TYPE_PORT_SEND_ONCE) {
			ipc_port_release_sonce(release_reply_port);
		} else {
			ipc_port_release_send(release_reply_port);
		}
	}

	if ((option & MACH_RCV_VOUCHER) != 0) {
		KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_MSG_RECV) | DBG_FUNC_NONE,
		    VM_KERNEL_ADDRPERM((uintptr_t)kmsg),
		    (uintptr_t)msg->msgh_bits,
		    (uintptr_t)msg->msgh_id,
		    VM_KERNEL_ADDRPERM(voucher_addr), 0);
	} else {
		KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_MSG_RECV_VOUCHER_REFUSED) | DBG_FUNC_NONE,
		    VM_KERNEL_ADDRPERM((uintptr_t)kmsg),
		    (uintptr_t)msg->msgh_bits,
		    (uintptr_t)msg->msgh_id,
		    VM_KERNEL_ADDRPERM(voucher_addr), 0);
	}

	if (IP_VALID(release_voucher_port)) {
		ipc_port_release_send(release_voucher_port);
	}

	msg->msgh_bits = MACH_MSGH_BITS_SET(reply_type, dest_type,
	    voucher_type, mbits);
	msg->msgh_local_port = CAST_MACH_NAME_TO_PORT(dest_name);
	msg->msgh_remote_port = CAST_MACH_NAME_TO_PORT(reply_name);
	msg->msgh_voucher_port = voucher_name;

	return MACH_MSG_SUCCESS;
}

/*
 *	Routine:	ipc_kmsg_copyout_port
 *	Purpose:
 *		Copy-out a port right.  Always returns a name,
 *		even for unsuccessful return codes.  Always
 *		consumes the supplied port.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		MACH_MSG_SUCCESS	The space acquired the right
 *			(name is valid) or the port is dead (MACH_PORT_DEAD).
 *		MACH_MSG_IPC_SPACE	No room in space for the right,
 *			or the space is dead.  (Name is MACH_PORT_NULL.)
 *		MACH_MSG_IPC_KERNEL	Kernel resource shortage.
 *			(Name is MACH_PORT_NULL.)
 */
static mach_msg_return_t
ipc_kmsg_copyout_port(
	ipc_space_t             space,
	ipc_port_t              port,
	mach_msg_type_name_t    msgt_name,
	mach_msg_guarded_port_descriptor_t *gdesc,
	mach_port_name_t       *namep)
{
	kern_return_t kr;

	if (!IP_VALID(port)) {
		*namep = CAST_MACH_PORT_TO_NAME(port);
		return MACH_MSG_SUCCESS;
	}

	kr = ipc_object_copyout(space, port, msgt_name,
	    IPC_OBJECT_COPYOUT_FLAGS_NONE, gdesc, namep);
	if (kr != KERN_SUCCESS) {
		if (kr == KERN_INVALID_CAPABILITY) {
			*namep = MACH_PORT_DEAD;
		} else {
			*namep = MACH_PORT_NULL;

			if (kr == KERN_RESOURCE_SHORTAGE) {
				return MACH_MSG_IPC_KERNEL;
			} else {
				return MACH_MSG_IPC_SPACE;
			}
		}
	}

	return MACH_MSG_SUCCESS;
}

/*
 *	Routine:	ipc_kmsg_copyout_reply_port
 *	Purpose:
 *      Kernel swallows the send-once right associated with reply port.
 *      Always returns a name, even for unsuccessful return codes.
 *      Returns
 *          MACH_MSG_SUCCESS Returns name of receive right for reply port.
 *              Name is valid if the space acquired the right and msgt_name would be changed from MOVE_SO to MAKE_SO.
 *              Name is MACH_PORT_DEAD if the port is dead.
 *              Name is MACH_PORT_NULL if its entry could not be found in task's ipc space.
 *          MACH_MSG_IPC_SPACE
 *              The space is dead.  (Name is MACH_PORT_NULL.)
 *	Conditions:
 *      Nothing locked.
 */
static mach_msg_return_t
ipc_kmsg_copyout_reply_port(
	ipc_space_t             space,
	ipc_port_t              port,
	mach_msg_type_name_t   *msgt_name,
	mach_port_name_t       *namep)
{
	ipc_entry_t entry;
	kern_return_t kr;

	if (!IP_VALID(port)) {
		*namep = CAST_MACH_PORT_TO_NAME(port);
		return MACH_MSG_SUCCESS;
	}

	assert(ip_is_reply_port(port));
	assert(*msgt_name == MACH_MSG_TYPE_PORT_SEND_ONCE);

	is_write_lock(space);

	if (!is_active(space)) {
		ipc_port_release_sonce(port);
		is_write_unlock(space);
		*namep = MACH_PORT_NULL;
		return MACH_MSG_IPC_SPACE;
	}

	ip_mq_lock(port);

	if (!ip_active(port)) {
		*namep = MACH_PORT_DEAD;
		kr = MACH_MSG_SUCCESS;
		goto out;
	}

	/* space is locked and active. port is locked and active. */
	if (!ipc_right_reverse(space, port, namep, &entry)) {
		*namep = MACH_PORT_NULL;
		kr = MACH_MSG_SUCCESS;
		goto out;
	}

	assert(entry->ie_bits & MACH_PORT_TYPE_RECEIVE);

	*msgt_name = MACH_MSG_TYPE_MAKE_SEND_ONCE;
	ipc_port_release_sonce_and_unlock(port);
	/* port is unlocked. */

	is_write_unlock(space);

	return MACH_MSG_SUCCESS;

out:

	/* space and object are locked. */
	ipc_port_release_sonce_and_unlock(port);

	is_write_unlock(space);

	return kr;
}


static mach_msg_return_t
ipc_kmsg_copyout_port_descriptor(
	mach_msg_port_descriptor_t *dsc,
	ipc_space_t             space)
{
	mach_port_name_t  name;
	mach_msg_return_t mr;

	/* Copyout port right carried in the message */
	mr = ipc_kmsg_copyout_port(space, dsc->name, dsc->disposition,
	    NULL, &name);
	dsc->u_name = CAST_MACH_NAME_TO_PORT(name);
	return mr;
}

static char *
ipc_kmsg_deflate_port_descriptor(
	char                   *udesc_end,
	const mach_msg_port_descriptor_t *kdesc)
{
	mach_msg_user_port_descriptor_t udesc = {
		.name        = CAST_MACH_PORT_TO_NAME(kdesc->u_name),
		.disposition = kdesc->disposition,
		.type        = kdesc->type,
	};

	return ipc_kmsg_deflate_put(udesc_end, &udesc);
}
#if 0 /* done to avoid merge conflicts, will be cleaned up with RDAR_91262248 */
}

extern const char *proc_best_name(struct proc *proc);
static mach_msg_descriptor_t *

#endif
static mach_msg_return_t
ipc_kmsg_copyout_ool_descriptor(
	mach_msg_ool_descriptor_t  *dsc,
	vm_map_t                    map)
{
	vm_map_copy_t               copy = dsc->address;
	vm_map_size_t               size = dsc->size;
	vm_map_address_t            rcv_addr;
	boolean_t                   misaligned = FALSE;
	mach_msg_return_t           mr  = MACH_MSG_SUCCESS;

	if (copy != VM_MAP_COPY_NULL) {
		kern_return_t kr;

		rcv_addr = 0;
		if (vm_map_copy_validate_size(map, copy, &size) == FALSE) {
			panic("Inconsistent OOL/copyout size on %p: expected %d, got %lld @%p",
			    dsc, dsc->size, (unsigned long long)copy->size, copy);
		}

		if ((copy->type == VM_MAP_COPY_ENTRY_LIST) &&
		    (trunc_page(copy->offset) != copy->offset ||
		    round_page(dsc->size) != dsc->size)) {
			misaligned = TRUE;
		}

		if (misaligned) {
			mach_vm_offset_t rounded_addr;
			vm_map_size_t   rounded_size;
			vm_map_offset_t effective_page_mask, effective_page_size;

			effective_page_mask = VM_MAP_PAGE_MASK(map);
			effective_page_size = effective_page_mask + 1;

			rounded_size = vm_map_round_page(copy->offset + size, effective_page_mask) - vm_map_trunc_page(copy->offset, effective_page_mask);

			kr = mach_vm_allocate_kernel(map, &rounded_addr, rounded_size,
			    VM_MAP_KERNEL_FLAGS_ANYWHERE(.vm_tag = VM_MEMORY_MACH_MSG));

			if (kr == KERN_SUCCESS) {
				/*
				 * vm_map_copy_overwrite does a full copy
				 * if size is too small to optimize.
				 * So we tried skipping the offset adjustment
				 * if we fail the 'size' test.
				 *
				 * if (size >= VM_MAP_COPY_OVERWRITE_OPTIMIZATION_THRESHOLD_PAGES * effective_page_size)
				 *
				 * This resulted in leaked memory especially on the
				 * older watches (16k user - 4k kernel) because we
				 * would do a physical copy into the start of this
				 * rounded range but could leak part of it
				 * on deallocation if the 'size' being deallocated
				 * does not cover the full range. So instead we do
				 * the misalignment adjustment always so that on
				 * deallocation we will remove the full range.
				 */
				if ((rounded_addr & effective_page_mask) !=
				    (copy->offset & effective_page_mask)) {
					/*
					 * Need similar mis-alignment of source and destination...
					 */
					rounded_addr += (copy->offset & effective_page_mask);

					assert((rounded_addr & effective_page_mask) == (copy->offset & effective_page_mask));
				}
				rcv_addr = rounded_addr;

				kr = vm_map_copy_overwrite(map, rcv_addr, copy, size, FALSE);
			}
		} else {
			kr = vm_map_copyout_size(map, &rcv_addr, copy, size);
		}
		if (kr != KERN_SUCCESS) {
			if (kr == KERN_RESOURCE_SHORTAGE) {
				mr = MACH_MSG_VM_KERNEL;
			} else {
				mr = MACH_MSG_VM_SPACE;
			}
			vm_map_copy_discard(copy);
			rcv_addr = 0;
			size = 0;
		}
	} else {
		rcv_addr = 0;
		size = 0;
	}

	dsc->u_address = rcv_addr;
	dsc->size      = size;
	return mr;
}

static char *
ipc_kmsg_deflate_memory_descriptor(
	char                   *udesc_end,
	const mach_msg_ool_descriptor_t *kdesc,
	bool                    isU64)
{
	bool deallocate = (kdesc->copy == MACH_MSG_VIRTUAL_COPY);

	if (isU64) {
		mach_msg_ool_descriptor64_t udesc = {
			.address     = kdesc->u_address,
			.size        = kdesc->size,
			.deallocate  = deallocate,
			.copy        = kdesc->copy,
			.type        = kdesc->type,
		};

		return ipc_kmsg_deflate_put(udesc_end, &udesc);
	} else {
		mach_msg_ool_descriptor32_t udesc = {
			.address     = (uint32_t)kdesc->u_address,
			.size        = kdesc->size,
			.deallocate  = deallocate,
			.copy        = kdesc->copy,
			.type        = kdesc->type,
		};

		return ipc_kmsg_deflate_put(udesc_end, &udesc);
	}
}


static mach_msg_return_t
ipc_kmsg_copyout_ool_ports_descriptor(
	mach_msg_kdescriptor_t *kdesc,
	vm_map_t                map,
	ipc_space_t             space)
{
	mach_msg_ool_ports_descriptor_t *dsc = &kdesc->kdesc_port_array;
	mach_msg_type_name_t    disp  = dsc->disposition;
	mach_msg_type_number_t  count = dsc->count;
	mach_port_array_t       array = dsc->address;
	mach_port_name_t       *names = dsc->address;

	vm_size_t               names_length = count * sizeof(mach_port_name_t);
	mach_vm_offset_t        rcv_addr = 0;
	mach_msg_return_t       mr = MACH_MSG_SUCCESS;

	if (count != 0 && array != NULL) {
		kern_return_t kr;
		vm_tag_t tag;

		/*
		 * Dynamically allocate the region
		 */
		if (vm_kernel_map_is_kernel(map)) {
			tag = VM_KERN_MEMORY_IPC;
		} else {
			tag = VM_MEMORY_MACH_MSG;
		}

		kr = mach_vm_allocate_kernel(map, &rcv_addr, names_length,
		    VM_MAP_KERNEL_FLAGS_ANYWHERE(.vm_tag = tag));

		/*
		 * Handle the port rights and copy out the names
		 * for those rights out to user-space.
		 */
		if (kr == MACH_MSG_SUCCESS) {
			for (mach_msg_size_t i = 0; i < count; i++) {
				mr |= ipc_kmsg_copyout_port(space,
				    array[i].port, disp, NULL, &names[i]);
			}
			if (copyoutmap(map, names, rcv_addr, names_length)) {
				mr |= MACH_MSG_VM_SPACE;
			}
			mach_port_array_free(array, count);
		} else {
			ipc_kmsg_clean_descriptors(kdesc, 1);
			if (kr == KERN_RESOURCE_SHORTAGE) {
				mr = MACH_MSG_VM_KERNEL;
			} else {
				mr = MACH_MSG_VM_SPACE;
			}
			rcv_addr = 0;
		}
	}

	dsc->u_address = rcv_addr;
	return mr;
}

static char *
ipc_kmsg_deflate_port_array_descriptor(
	char                   *udesc_end,
	const mach_msg_ool_ports_descriptor_t *kdesc,
	bool                    isU64)
{
	if (isU64) {
		mach_msg_ool_ports_descriptor64_t udesc = {
			.address     = kdesc->u_address,
			.count       = kdesc->count,
			.deallocate  = true,
			.copy        = MACH_MSG_VIRTUAL_COPY,
			.disposition = kdesc->disposition,
			.type        = kdesc->type,
		};

		return ipc_kmsg_deflate_put(udesc_end, &udesc);
	} else {
		mach_msg_ool_ports_descriptor32_t udesc = {
			.address     = (uint32_t)kdesc->u_address,
			.count       = kdesc->count,
			.deallocate  = true,
			.copy        = MACH_MSG_VIRTUAL_COPY,
			.disposition = kdesc->disposition,
			.type        = kdesc->type,
		};

		return ipc_kmsg_deflate_put(udesc_end, &udesc);
	}
}


static mach_msg_return_t
ipc_kmsg_copyout_guarded_port_descriptor(
	mach_msg_guarded_port_descriptor_t *dsc,
	ipc_space_t             space,
	mach_msg_option64_t     option)
{
	mach_port_t             port    = dsc->name;
	mach_msg_type_name_t    disp    = dsc->disposition;
	mach_msg_return_t       mr      = MACH_MSG_SUCCESS;

	/* Currently kernel_task doesnt support receiving guarded port descriptors */
	struct knote *kn = current_thread()->ith_knote;
	if ((kn != ITH_KNOTE_PSEUDO) && ((option & MACH_RCV_GUARDED_DESC) == 0)) {
#if DEVELOPMENT || DEBUG
		/*
		 * Simulated crash needed for debugging, notifies the receiver to opt into receiving
		 * guarded descriptors.
		 */
		mach_port_guard_exception(current_thread()->ith_receiver_name,
		    0, kGUARD_EXC_RCV_GUARDED_DESC);
#endif
		KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_DESTROY_GUARDED_DESC),
		    current_thread()->ith_receiver_name,
		    VM_KERNEL_ADDRPERM(port), disp, dsc->flags);

		ipc_object_destroy(port, disp);
		dsc->u_context = 0;
		dsc->u_name    = MACH_PORT_NULL;
	} else {
		mr = ipc_kmsg_copyout_port(space, port, disp, dsc,
		    &dsc->u_name);
	}

	return mr;
}

static char *
ipc_kmsg_deflate_guarded_port_descriptor(
	char                   *udesc_end,
	const mach_msg_guarded_port_descriptor_t *kdesc,
	bool                    isU64)
{
	if (isU64) {
		mach_msg_guarded_port_descriptor64_t udesc = {
			.context     = kdesc->u_context,
			.flags       = kdesc->flags,
			.disposition = kdesc->disposition,
			.type        = kdesc->type,
			.name        = kdesc->u_name,
		};

		return ipc_kmsg_deflate_put(udesc_end, &udesc);
	} else {
		mach_msg_guarded_port_descriptor32_t udesc = {
			.context     = (uint32_t)kdesc->u_context,
			.flags       = kdesc->flags,
			.disposition = kdesc->disposition,
			.type        = kdesc->type,
			.name        = kdesc->u_name,
		};

		return ipc_kmsg_deflate_put(udesc_end, &udesc);
	}
}


/*
 *	Routine:	ipc_kmsg_copyout_descriptors
 *	Purpose:
 *		"Copy-out" port rights and out-of-line memory
 *		in the body of a message.
 *
 *		The error codes are a combination of special bits.
 *		The copyout proceeds despite errors.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		MACH_MSG_SUCCESS	Successful copyout.
 *		MACH_MSG_IPC_SPACE	No room for port right in name space.
 *		MACH_MSG_VM_SPACE	No room for memory in address space.
 *		MACH_MSG_IPC_KERNEL	Resource shortage handling port right.
 *		MACH_MSG_VM_KERNEL	Resource shortage handling memory.
 *		MACH_MSG_INVALID_RT_DESCRIPTOR Descriptor incompatible with RT
 */

static mach_msg_return_t
ipc_kmsg_copyout_descriptors(
	mach_msg_kdescriptor_t *kdesc,
	mach_msg_size_t         dsc_count,
	ipc_space_t             space,
	vm_map_t                map,
	mach_msg_option64_t     option)
{
	mach_msg_return_t mr = MACH_MSG_SUCCESS;

	assert(current_task() != kernel_task);

	for (mach_msg_size_t i = 0; i < dsc_count; i++, kdesc++) {
		switch (mach_msg_kdescriptor_type(kdesc)) {
		case MACH_MSG_PORT_DESCRIPTOR:
			mr |= ipc_kmsg_copyout_port_descriptor(&kdesc->kdesc_port,
			    space);
			break;
		case MACH_MSG_OOL_VOLATILE_DESCRIPTOR:
		case MACH_MSG_OOL_DESCRIPTOR:
			mr |= ipc_kmsg_copyout_ool_descriptor(&kdesc->kdesc_memory,
			    map);
			break;
		case MACH_MSG_OOL_PORTS_DESCRIPTOR:
			mr |= ipc_kmsg_copyout_ool_ports_descriptor(kdesc,
			    map, space);
			break;
		case MACH_MSG_GUARDED_PORT_DESCRIPTOR:
			mr |= ipc_kmsg_copyout_guarded_port_descriptor(&kdesc->kdesc_guarded_port,
			    space, option);
			break;
		default:
			__ipc_kmsg_descriptor_invalid_type_panic(kdesc);
		}
	}

	if (mr != MACH_MSG_SUCCESS) {
		mr |= MACH_RCV_BODY_ERROR;
	}
	return mr;
}

static void
ipc_kmsg_deflate_descriptors(
	ikm_deflate_context_t  *dctx,
	mach_msg_kdescriptor_t *desc_array,
	mach_msg_size_t         desc_count)
{
	char           *udesc = (char *)(desc_array + desc_count);
	mach_msg_body_t body  = {
		.msgh_descriptor_count = desc_count,
	};

	for (mach_msg_size_t i = desc_count; i-- > 0;) {
		const mach_msg_kdescriptor_t *kdesc = &desc_array[i];

		switch (mach_msg_kdescriptor_type(kdesc)) {
		case MACH_MSG_PORT_DESCRIPTOR:
			udesc = ipc_kmsg_deflate_port_descriptor(udesc,
			    &kdesc->kdesc_port);
			break;
		case MACH_MSG_OOL_VOLATILE_DESCRIPTOR:
		case MACH_MSG_OOL_DESCRIPTOR:
			udesc = ipc_kmsg_deflate_memory_descriptor(udesc,
			    &kdesc->kdesc_memory, dctx->dctx_isU64);
			break;
		case MACH_MSG_OOL_PORTS_DESCRIPTOR:
			udesc = ipc_kmsg_deflate_port_array_descriptor(udesc,
			    &kdesc->kdesc_port_array, dctx->dctx_isU64);
			break;
		case MACH_MSG_GUARDED_PORT_DESCRIPTOR:
			udesc = ipc_kmsg_deflate_guarded_port_descriptor(udesc,
			    &kdesc->kdesc_guarded_port, dctx->dctx_isU64);
			break;
		default:
			__ipc_kmsg_descriptor_invalid_type_panic(kdesc);
		}
	}

	/* adjust the context with how much the descriptors contracted */
	dctx->dctx_uhdr      += udesc - (char *)desc_array;
	dctx->dctx_uhdr_size -= udesc - (char *)desc_array;

	/* update the descriptor count right before the array */
	udesc = ipc_kmsg_deflate_put(udesc, &body);
}

static mach_msg_size_t
ipc_kmsg_descriptors_copyout_size(
	mach_msg_kdescriptor_t *kdesc,
	mach_msg_size_t         count,
	vm_map_t                map)
{
	bool isU64 = (map->max_offset > VM_MAX_ADDRESS);
	mach_msg_size_t size = 0;

	for (mach_msg_size_t i = 0; i < count; i++) {
		size += ikm_user_desc_size(kdesc[i].kdesc_header.type, isU64);
	}

	return size;
}

/*
 *	Routine:	ipc_kmsg_copyout_size
 *	Purpose:
 *		Compute the size of the message as copied out to the given
 *		map. If the destination map's pointers are a different size
 *		than the kernel's, we have to allow for expansion/
 *		contraction of the descriptors as appropriate.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		size of the message as it would be received.
 */

mach_msg_size_t
ipc_kmsg_copyout_size(
	ipc_kmsg_t              kmsg,
	vm_map_t                map)
{
	mach_msg_header_t *hdr   = ikm_header(kmsg);
	mach_msg_size_t    size  = hdr->msgh_size - USER_HEADER_SIZE_DELTA;

	if (hdr->msgh_bits & MACH_MSGH_BITS_COMPLEX) {
		mach_msg_kbase_t *kbase = mach_msg_header_to_kbase(hdr);

		size -= KERNEL_DESC_SIZE * kbase->msgb_dsc_count;
		size += ipc_kmsg_descriptors_copyout_size(kbase->msgb_dsc_array,
		    kbase->msgb_dsc_count, map);
	}

	return size;
}

/*
 *	Routine:	ipc_kmsg_copyout
 *	Purpose:
 *		"Copy-out" port rights and out-of-line memory
 *		in the message.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		MACH_MSG_SUCCESS	Copied out all rights and memory.
 *		MACH_RCV_HEADER_ERROR + special bits
 *			Rights and memory in the message are intact.
 *		MACH_RCV_BODY_ERROR + special bits
 *			The message header was successfully copied out.
 *			As much of the body was handled as possible.
 */

mach_msg_return_t
ipc_kmsg_copyout(
	ipc_kmsg_t              kmsg,
	ipc_space_t             space,
	vm_map_t                map,
	mach_msg_option64_t     option)
{
	mach_msg_header_t *hdr = ikm_header(kmsg);
	mach_msg_size_t    dsc_count;
	mach_msg_return_t  mr;

	dsc_count = ipc_kmsg_validate_signature(kmsg);

	mr = ipc_kmsg_copyout_header(kmsg, hdr, space, option);
	if (mr != MACH_MSG_SUCCESS) {
		return mr;
	}

	if (dsc_count) {
		mach_msg_kbase_t *kbase = mach_msg_header_to_kbase(hdr);

		mr = ipc_kmsg_copyout_descriptors(kbase->msgb_dsc_array,
		    dsc_count, space, map, option);
	}

	return mr;
}

/*
 *	Routine:	ipc_kmsg_copyout_pseudo
 *	Purpose:
 *		Does a pseudo-copyout of the message.
 *		This is like a regular copyout, except
 *		that the ports in the header are handled
 *		as if they are in the body.  They aren't reversed.
 *
 *		The error codes are a combination of special bits.
 *		The copyout proceeds despite errors.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		MACH_MSG_SUCCESS	Successful copyout.
 *		MACH_MSG_IPC_SPACE	No room for port right in name space.
 *		MACH_MSG_VM_SPACE	No room for memory in address space.
 *		MACH_MSG_IPC_KERNEL	Resource shortage handling port right.
 *		MACH_MSG_VM_KERNEL	Resource shortage handling memory.
 */

mach_msg_return_t
ipc_kmsg_copyout_pseudo(
	ipc_kmsg_t              kmsg,
	ipc_space_t             space,
	vm_map_t                map)
{
	mach_msg_header_t *hdr = ikm_header(kmsg);
	mach_msg_bits_t mbits = hdr->msgh_bits;
	ipc_port_t dest = hdr->msgh_remote_port;
	ipc_port_t reply = hdr->msgh_local_port;
	ipc_port_t voucher = ipc_kmsg_get_voucher_port(kmsg);
	mach_msg_type_name_t dest_type = MACH_MSGH_BITS_REMOTE(mbits);
	mach_msg_type_name_t reply_type = MACH_MSGH_BITS_LOCAL(mbits);
	mach_msg_type_name_t voucher_type = MACH_MSGH_BITS_VOUCHER(mbits);
	mach_port_name_t voucher_name = hdr->msgh_voucher_port;
	mach_port_name_t dest_name, reply_name;
	mach_msg_return_t mr;
	mach_msg_size_t dsc_count;

	/* Set ith_knote to ITH_KNOTE_PSEUDO */
	current_thread()->ith_knote = ITH_KNOTE_PSEUDO;

	dsc_count = ipc_kmsg_validate_signature(kmsg);

	assert(IP_VALID(dest));

#if 0
	/*
	 * If we did this here, it looks like we wouldn't need the undo logic
	 * at the end of ipc_kmsg_send() in the error cases.  Not sure which
	 * would be more elegant to keep.
	 */
	ipc_importance_clean(kmsg);
#else
	/* just assert it is already clean */
	ipc_importance_assert_clean(kmsg);
#endif

	mr = ipc_kmsg_copyout_port(space, dest, dest_type, NULL, &dest_name);

	if (!IP_VALID(reply)) {
		reply_name = CAST_MACH_PORT_TO_NAME(reply);
	} else if (ip_is_reply_port(reply)) {
		mach_msg_return_t reply_mr;
		reply_mr = ipc_kmsg_copyout_reply_port(space, reply, &reply_type, &reply_name);
		mr = mr | reply_mr;
		if (reply_mr == MACH_MSG_SUCCESS) {
			mbits = MACH_MSGH_BITS_SET(dest_type, reply_type, voucher_type, MACH_MSGH_BITS_OTHER(mbits));
		}
	} else {
		mr = mr | ipc_kmsg_copyout_port(space, reply, reply_type, NULL, &reply_name);
	}

	hdr->msgh_bits = mbits & MACH_MSGH_BITS_USER;
	hdr->msgh_remote_port = CAST_MACH_NAME_TO_PORT(dest_name);
	hdr->msgh_local_port = CAST_MACH_NAME_TO_PORT(reply_name);

	/* restore the voucher:
	 * If it was copied in via move-send, have to put back a voucher send right.
	 *
	 * If it was copied in via copy-send, the header still contains the old voucher name.
	 * Restore the type and discard the copied-in/pre-processed voucher.
	 */
	if (IP_VALID(voucher)) {
		assert(voucher_type == MACH_MSG_TYPE_MOVE_SEND);
		if (kmsg->ikm_voucher_type == MACH_MSG_TYPE_MOVE_SEND) {
			mr |= ipc_kmsg_copyout_port(space, voucher, voucher_type, NULL, &voucher_name);
			hdr->msgh_voucher_port = voucher_name;
		} else {
			assert(kmsg->ikm_voucher_type == MACH_MSG_TYPE_COPY_SEND);
			hdr->msgh_bits = MACH_MSGH_BITS_SET(dest_type, reply_type, MACH_MSG_TYPE_COPY_SEND,
			    MACH_MSGH_BITS_OTHER(hdr->msgh_bits));
			ipc_object_destroy(voucher, voucher_type);
		}
		ipc_kmsg_clear_voucher_port(kmsg);
	}

	if (dsc_count) {
		mach_msg_kbase_t *kbase = mach_msg_header_to_kbase(hdr);

		/* rdar://120614480 this MACH64_MSG_OPTION_NONE is wrong */
		mr |= ipc_kmsg_copyout_descriptors(kbase->msgb_dsc_array,
		    dsc_count, space, map, MACH64_MSG_OPTION_NONE);
	}

	current_thread()->ith_knote = ITH_KNOTE_NULL;

	return mr;
}

/*
 *	Routine:	ipc_kmsg_copyout_dest_to_user
 *	Purpose:
 *		Copies out the destination port in the message.
 *		Destroys all other rights and memory in the message.
 *		Transforms the message into a bare header with trailer.
 *	Conditions:
 *		Nothing locked.
 */

void
ipc_kmsg_copyout_dest_to_user(
	ipc_kmsg_t      kmsg,
	ipc_space_t     space)
{
	mach_msg_bits_t mbits;
	ipc_port_t dest;
	ipc_port_t reply;
	ipc_port_t voucher;
	mach_msg_type_name_t dest_type;
	mach_msg_type_name_t reply_type;
	mach_msg_type_name_t voucher_type;
	mach_port_name_t dest_name, reply_name, voucher_name;
	mach_msg_header_t *hdr;
	mach_msg_id_t msg_id;
	mach_msg_size_t aux_size;
	mach_msg_size_t dsc_count;

	dsc_count = ipc_kmsg_validate_signature(kmsg);

	hdr = ikm_header(kmsg);
	mbits = hdr->msgh_bits;
	dest = hdr->msgh_remote_port;
	reply = hdr->msgh_local_port;
	voucher = ipc_kmsg_get_voucher_port(kmsg);
	voucher_name = hdr->msgh_voucher_port;
	msg_id = hdr->msgh_id;
	dest_type = MACH_MSGH_BITS_REMOTE(mbits);
	reply_type = MACH_MSGH_BITS_LOCAL(mbits);
	voucher_type = MACH_MSGH_BITS_VOUCHER(mbits);
	aux_size = kmsg->ikm_aux_size;

	assert(IP_VALID(dest));

	ipc_importance_assert_clean(kmsg);

	ip_mq_lock(dest);
	if (ip_active(dest)) {
		ipc_object_copyout_dest(space, dest, dest_type, &dest_name);
		/* dest is unlocked */
	} else {
		ip_mq_unlock(dest);
		ip_release(dest);
		dest_name = MACH_PORT_DEAD;
	}

	if (IP_VALID(reply)) {
		ipc_object_destroy(reply, reply_type);
		reply_name = MACH_PORT_NULL;
	} else {
		reply_name = CAST_MACH_PORT_TO_NAME(reply);
	}

	if (IP_VALID(voucher)) {
		assert(voucher_type == MACH_MSG_TYPE_MOVE_SEND);
		ipc_object_destroy(voucher, voucher_type);
		ipc_kmsg_clear_voucher_port(kmsg);
		voucher_name = MACH_PORT_NULL;
	}

	if (mbits & MACH_MSGH_BITS_COMPLEX) {
		mach_msg_kbase_t *kbase = mach_msg_header_to_kbase(hdr);

		ipc_kmsg_clean_descriptors(kbase->msgb_dsc_array, dsc_count);
	}

	ipc_kmsg_free_allocations(kmsg);

	/* and now reconstruct a message anew */

	mbits = MACH_MSGH_BITS_SET(reply_type, dest_type, voucher_type, mbits);
	*ikm_header(kmsg) = (mach_msg_header_t){
		.msgh_bits         = mbits,
		.msgh_size         = sizeof(mach_msg_header_t),
		.msgh_local_port   = CAST_MACH_NAME_TO_PORT(dest_name),
		.msgh_remote_port  = CAST_MACH_NAME_TO_PORT(reply_name),
		.msgh_voucher_port = voucher_name,
		.msgh_id           = msg_id,
	};
	ipc_kmsg_init_trailer_and_sign(kmsg, TASK_NULL);

	/* put a minimal aux header if there was one */
	if (aux_size) {
		kmsg->ikm_aux_size = sizeof(mach_msg_aux_header_t);
		*ikm_aux_header(kmsg) = (mach_msg_aux_header_t){
			.msgdh_size = sizeof(mach_msg_aux_header_t),
		};
	}
}

/*
 *	Routine:	ipc_kmsg_copyout_dest_to_kernel
 *	Purpose:
 *		Copies out the destination and reply ports in the message.
 *		Leaves all other rights and memory in the message alone.
 *	Conditions:
 *		Nothing locked.
 *
 *	Derived from ipc_kmsg_copyout_dest_to_user.
 *	Use by mach_msg_rpc_from_kernel (which used to use copyout_dest).
 *	We really do want to save rights and memory.
 */

void
ipc_kmsg_copyout_dest_to_kernel(
	ipc_kmsg_t      kmsg,
	ipc_space_t     space)
{
	ipc_port_t dest;
	mach_port_t reply;
	mach_msg_type_name_t dest_type;
	mach_msg_type_name_t reply_type;
	mach_port_name_t dest_name;
	mach_msg_header_t *hdr;

	(void)ipc_kmsg_validate_signature(kmsg);

	hdr = ikm_header(kmsg);
	dest = hdr->msgh_remote_port;
	reply = hdr->msgh_local_port;
	dest_type = MACH_MSGH_BITS_REMOTE(hdr->msgh_bits);
	reply_type = MACH_MSGH_BITS_LOCAL(hdr->msgh_bits);

	assert(IP_VALID(dest));

	ip_mq_lock(dest);
	if (ip_active(dest)) {
		ipc_object_copyout_dest(space, dest, dest_type, &dest_name);
		/* dest is unlocked */
	} else {
		ip_mq_unlock(dest);
		ip_release(dest);
		dest_name = MACH_PORT_DEAD;
	}

	/*
	 * While MIG kernel users don't receive vouchers, the
	 * msgh_voucher_port field is intended to be round-tripped through the
	 * kernel if there is no voucher disposition set. Here we check for a
	 * non-zero voucher disposition, and consume the voucher send right as
	 * there is no possible way to specify MACH_RCV_VOUCHER semantics.
	 */
	mach_msg_type_name_t voucher_type;
	voucher_type = MACH_MSGH_BITS_VOUCHER(hdr->msgh_bits);
	if (voucher_type != MACH_MSGH_BITS_ZERO) {
		ipc_port_t voucher = ipc_kmsg_get_voucher_port(kmsg);

		assert(voucher_type == MACH_MSG_TYPE_MOVE_SEND);
		/*
		 * someone managed to send this kernel routine a message with
		 * a voucher in it. Cleanup the reference in
		 * kmsg->ikm_voucher.
		 */
		if (IP_VALID(voucher)) {
			ipc_port_release_send(voucher);
		}
		hdr->msgh_voucher_port = 0;
		ipc_kmsg_clear_voucher_port(kmsg);
	}

	hdr->msgh_bits =
	    (MACH_MSGH_BITS_OTHER(hdr->msgh_bits) |
	    MACH_MSGH_BITS(reply_type, dest_type));
	hdr->msgh_local_port =  CAST_MACH_NAME_TO_PORT(dest_name);
	hdr->msgh_remote_port = reply;
}

static void
ipc_kmsg_deflate_header(
	ikm_deflate_context_t  *dctx,
	mach_msg_header_t      *hdr)
{
	mach_msg_user_header_t uhdr = {
		.msgh_bits         = hdr->msgh_bits,
		.msgh_size         = dctx->dctx_uhdr_size + dctx->dctx_udata_size,
		.msgh_remote_port  = CAST_MACH_PORT_TO_NAME(hdr->msgh_remote_port),
		.msgh_local_port   = CAST_MACH_PORT_TO_NAME(hdr->msgh_local_port),
		.msgh_voucher_port = hdr->msgh_voucher_port,
		.msgh_id           = hdr->msgh_id,
	};

	/* the header will contract, take it into account */
	dctx->dctx_uhdr      += USER_HEADER_SIZE_DELTA;
	dctx->dctx_uhdr_size -= USER_HEADER_SIZE_DELTA;
	uhdr.msgh_size       -= USER_HEADER_SIZE_DELTA;
	memcpy(dctx->dctx_uhdr, &uhdr, sizeof(uhdr));
}

static void
ipc_kmsg_deflate_trailer(
	ikm_deflate_context_t  *dctx,
	mach_msg_recv_result_t *msgr)
{
	mach_msg_max_trailer_t   *trailer = dctx->dctx_trailer;
#ifdef __arm64__
	mach_msg_max_trailer32_t *out32  = (mach_msg_max_trailer32_t *)trailer;
	mach_msg_max_trailer64_t *out64  = (mach_msg_max_trailer64_t *)trailer;
#else
	mach_msg_max_trailer_t   *out32  = trailer;
	mach_msg_max_trailer_t   *out64  = trailer;
#endif /* __arm64__ */

#define trailer_assert_same_field(field) \
	static_assert(offsetof(typeof(*out32), field) == \
	    offsetof(typeof(*out64), field)); \
	static_assert(sizeof(out32->field) == sizeof(out64->field))

	/*
	 * These fields have been set by ipc_kmsg_init_trailer_and_sign(),
	 * but alias in both 32 and 64 bit forms and need no munging:
	 *
	 *   msgh_trailer_type, msgh_trailer_size, msgh_sender, msgh_audit
	 *
	 * Update the size with the user requested one,
	 * and update the message seqno.
	 *
	 * These cover:
	 * - mach_msg_trailer_t           (msgh_trailer_type + msgh_trailer_size)
	 * - mach_msg_seqno_trailer_t     (the above + msgh_seqno)
	 * - mach_msg_security_trailer_t  (the above + msgh_sender)
	 * - mach_msg_audit_trailer_t     (the above + msgh_audit)
	 */
	trailer_assert_same_field(msgh_trailer_type);
	trailer_assert_same_field(msgh_trailer_size);
	trailer_assert_same_field(msgh_seqno);
	trailer_assert_same_field(msgh_sender);
	trailer_assert_same_field(msgh_audit);

	trailer->msgh_trailer_size = dctx->dctx_trailer_size;
	trailer->msgh_seqno        = msgr->msgr_seqno;

	/*
	 * Lastly update fields that are 32bit versus 64bit dependent,
	 * which are all after msgh_context (including this field).
	 *
	 * These cover:
	 * - mach_msg_context_trailer_t   (the above + msgh_context)
	 * - mach_msg_mac_trailer_t       (the above + msg_ad + msgh_labels)
	 */

	bzero((char *)trailer + sizeof(mach_msg_audit_trailer_t),
	    MAX_TRAILER_SIZE - sizeof(mach_msg_audit_trailer_t));

	if (dctx->dctx_isU64) {
		out64->msgh_context = msgr->msgr_context;
	} else {
		out32->msgh_context = (typeof(out32->msgh_context))msgr->msgr_context;
	}
#undef trailer_assert_same_field
}

static ikm_deflate_context_t
ipc_kmsg_deflate(
	ipc_kmsg_t              kmsg,     /* scalar or vector */
	mach_msg_recv_result_t *msgr,
	mach_msg_option64_t     options,
	vm_map_t                map)
{
	mach_msg_header_t      *hdr  = ikm_header(kmsg);
	ikm_deflate_context_t   dctx = {
		.dctx_uhdr       = (char *)hdr,
		.dctx_uhdr_size  = hdr->msgh_size,

		.dctx_aux_hdr    = ikm_aux_header(kmsg),
		.dctx_aux_size   = kmsg->ikm_aux_size,

		.dctx_isU64      = (map->max_offset > VM_MAX_ADDRESS),
	};

	/*
	 * If we aren't pseudo-receiving, deflate the trailer
	 * before where it is is mangled beyond recognition.
	 */
	if (msgr->msgr_recv_name != MSGR_PSEUDO_RECEIVE) {
		dctx.dctx_trailer      = ipc_kmsg_get_trailer(kmsg);
		dctx.dctx_trailer_size = ipc_kmsg_trailer_size(options, map);
	}

	/*
	 * If the message isn't linear,
	 * split into uhdr=header+descriptors and udata=body+trailer
	 */
	if (!ikm_is_linear(kmsg)) {
		mach_msg_size_t kdata_size = ikm_kdata_size(hdr);

		dctx.dctx_udata_size = dctx.dctx_uhdr_size - kdata_size;
		if (dctx.dctx_udata_size || dctx.dctx_trailer_size) {
			dctx.dctx_udata      = kmsg->ikm_udata;
			dctx.dctx_uhdr_size  = kdata_size;
		}
	}

	/*
	 * /!\ past this point, very few ipc_kmsg methods are allowed /!\
	 *
	 * The kmsg layout will be mangled in order to copy the bytes out,
	 * and once that is done, destroying the message is the only thing
	 * allowed.
	 */

	if (msgr->msgr_recv_name != MSGR_PSEUDO_RECEIVE) {
		ipc_kmsg_deflate_trailer(&dctx, msgr);
	}

	if (hdr->msgh_bits & MACH_MSGH_BITS_COMPLEX) {
		mach_msg_kbase_t *kbase = mach_msg_header_to_kbase(hdr);

		ipc_kmsg_deflate_descriptors(&dctx,
		    kbase->msgb_dsc_array, kbase->msgb_dsc_count);
	}

	ipc_kmsg_deflate_header(&dctx, hdr);

	return dctx;
}


/*
 *	Routine:	ipc_kmsg_put_to_user
 *	Purpose:
 *		Copies a scalar or vector message buffer to a user message.
 *		Frees the message buffer.
 *
 *		1. If user has allocated space for aux data,
 *		   mach_msg_validate_data_vectors() guarantees that
 *		   recv_aux_addr is non-zero, and recv_aux_size
 *		   is at least sizeof(mach_msg_aux_header_t).
 *
 *		   In case the kmsg is a scalar or a vector without auxiliary
 *		   data, copy out an empty aux header to recv_aux_addr
 *		   which serves as EOF.
 *
 *		2. If the user has not allocated space for aux data,
 *		   silently drop the aux payload on reception.
 *
 *		3. If MACH64_RCV_LINEAR_VECTOR is set, use recv_msg_addr as
 *		   the combined buffer for message proper and aux data.
 *		   recv_aux_addr and recv_aux_size must be passed as
 *		   zeros and are ignored.
 *
 *	Conditions:
 *		Nothing locked. kmsg is freed upon return.
 *
 *	Returns:
 *		MACH_RCV_INVALID_DATA    Couldn't copy to user message.
 *		the incoming "mr"        Copied data out of message buffer.
 */
mach_msg_return_t
ipc_kmsg_put_to_user(
	ipc_kmsg_t              kmsg,     /* scalar or vector */
	mach_msg_recv_bufs_t   *recv_bufs,
	mach_msg_recv_result_t *msgr,
	mach_msg_option64_t     options,
	vm_map_t                map,
	mach_msg_return_t       mr)
{
	mach_msg_aux_header_t   eof_aux = { .msgdh_size = 0 };
	mach_vm_address_t       msg_rcv_addr = recv_bufs->recv_msg_addr;
	mach_vm_address_t       aux_rcv_addr = recv_bufs->recv_aux_addr;
	mach_msg_size_t         usize = 0;
	ikm_deflate_context_t   dctx;

	/*
	 * After this, the kmsg() is mangled beyond recognition,
	 * and calling things like ikm_header() etc.. will have
	 * undefined behavior.
	 */
	dctx = ipc_kmsg_deflate(kmsg, msgr, options, map);

	msgr->msgr_msg_size     = dctx.dctx_uhdr_size + dctx.dctx_udata_size;
	msgr->msgr_trailer_size = dctx.dctx_trailer_size;
	msgr->msgr_aux_size     = dctx.dctx_aux_size;

	usize = msgr->msgr_msg_size + msgr->msgr_trailer_size;

	/*
	 * Validate our parameters, and compute the actual copy out addresses
	 */

	if (options & MACH64_RCV_LINEAR_VECTOR) {
		assert(options & MACH64_MSG_VECTOR);

		if (usize + dctx.dctx_aux_size > recv_bufs->recv_msg_size) {
			mr = MACH_RCV_INVALID_DATA;
			goto out;
		}
		if (options & MACH64_RCV_STACK) {
			msg_rcv_addr += recv_bufs->recv_msg_size -
			    (usize + dctx.dctx_aux_size);
		}
		aux_rcv_addr = msg_rcv_addr + usize;
	} else {
		assert(!(options & MACH64_RCV_STACK));

		if (msgr->msgr_msg_size > recv_bufs->recv_msg_size) {
			mr = MACH_RCV_INVALID_DATA;
			goto out;
		}

		/*
		 * (81193887) some clients stomp their own stack due to mis-sized
		 * combined send/receives where the receive buffer didn't account
		 * for the trailer size.
		 *
		 * At the very least, avoid smashing their stack
		 */
		if (usize > recv_bufs->recv_msg_size) {
			dctx.dctx_trailer_size -= recv_bufs->recv_msg_size - usize;
			usize = recv_bufs->recv_msg_size;
		}

		/*
		 * If user has a buffer for aux data, at least copy out
		 * an empty header which serves as an EOF.
		 *
		 * We don't need to do so for linear vector because
		 * it's used in kevent context and we will return
		 * msgr_aux_size as 0 on ext[3] to signify empty aux data.
		 *
		 * See: filt_machportprocess().
		 */
		if (aux_rcv_addr && !dctx.dctx_aux_hdr) {
			dctx.dctx_aux_hdr  = &eof_aux;
			dctx.dctx_aux_size = sizeof(eof_aux);
			msgr->msgr_aux_size  = sizeof(eof_aux);
		}

		/*
		 * If a receiver tries to receive a message with an aux vector,
		 * but didn't provide one, we silently drop it for backward
		 * compatibility reasons.
		 */
		if (dctx.dctx_aux_size > recv_bufs->recv_aux_size) {
			dctx.dctx_aux_hdr  = NULL;
			dctx.dctx_aux_size = 0;
			msgr->msgr_aux_size  = 0;
			aux_rcv_addr         = 0;
		}
	}


	/*
	 * Now that we measured twice, time to copyout all pieces.
	 */

	if (dctx.dctx_udata) {
		mach_msg_size_t uhdr_size = dctx.dctx_uhdr_size;

		if (copyoutmsg(dctx.dctx_uhdr, msg_rcv_addr, uhdr_size) ||
		    copyoutmsg(dctx.dctx_udata, msg_rcv_addr + uhdr_size,
		    usize - uhdr_size)) {
			mr = MACH_RCV_INVALID_DATA;
			goto out;
		}
	} else {
		if (copyoutmsg(dctx.dctx_uhdr, msg_rcv_addr, usize)) {
			mr = MACH_RCV_INVALID_DATA;
			goto out;
		}
	}

	if (dctx.dctx_aux_size &&
	    copyoutmsg(dctx.dctx_aux_hdr, aux_rcv_addr, dctx.dctx_aux_size)) {
		mr = MACH_RCV_INVALID_DATA;
		goto out;
	}

out:
	if (mr == MACH_RCV_INVALID_DATA) {
		msgr->msgr_msg_size     = 0;
		msgr->msgr_trailer_size = 0;
		msgr->msgr_aux_size     = 0;
	}

	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_LINK) | DBG_FUNC_NONE,
	    recv_bufs->recv_msg_addr, VM_KERNEL_ADDRPERM((uintptr_t)kmsg),
	    /* this is on the receive/copyout path */ 1, 0, 0);

	ipc_kmsg_free(kmsg);

	return mr;
}

/** @} */
#pragma mark ipc_kmsg kernel interfaces (get/put, copyin_from_kernel, send)

/*
 *	Routine:	ipc_kmsg_get_from_kernel
 *	Purpose:
 *		Allocates a new kernel message buffer.
 *		Copies a kernel message to the message buffer.
 *		Only resource errors are allowed.
 *	Conditions:
 *		Nothing locked.
 *		Ports in header are ipc_port_t.
 *	Returns:
 *		MACH_MSG_SUCCESS	Acquired a message buffer.
 *		MACH_SEND_NO_BUFFER	Couldn't allocate a message buffer.
 */

mach_msg_return_t
ipc_kmsg_get_from_kernel(
	mach_msg_header_t      *msg,
	mach_msg_size_t         size,
	mach_msg_option64_t     options,
	ipc_kmsg_t             *kmsgp)
{
	mach_msg_kbase_t  *src_base;
	ipc_kmsg_t         kmsg;
	mach_msg_header_t *hdr;
	mach_msg_size_t    desc_count, kdata_sz;

	assert(size >= sizeof(mach_msg_header_t));
	assert((size & 3) == 0);

	if (msg->msgh_bits & MACH_MSGH_BITS_COMPLEX) {
		src_base   = mach_msg_header_to_kbase(msg);
		desc_count = src_base->msgb_dsc_count;
		kdata_sz   = ikm_kdata_size(desc_count, true);
	} else {
		desc_count = 0;
		kdata_sz   = ikm_kdata_size(desc_count, false);
	}

	assert(size >= kdata_sz);
	if (size < kdata_sz) {
		return MACH_SEND_TOO_LARGE;
	}

	kmsg = ipc_kmsg_alloc(size, 0, desc_count, IPC_KMSG_ALLOC_KERNEL);
	/* kmsg can be non-linear */

	if (kmsg == IKM_NULL) {
		return MACH_SEND_NO_BUFFER;
	}

	hdr = ikm_header(kmsg);
	if (ikm_is_linear(kmsg)) {
		memcpy(hdr, msg, size);
	} else {
		memcpy(hdr, msg, kdata_sz);
		memcpy(kmsg->ikm_udata, (char *)msg + kdata_sz, size - kdata_sz);
	}
	hdr->msgh_size = size;

	if (desc_count) {
		mach_msg_kbase_t *dst_base = mach_msg_header_to_kbase(hdr);

		if (options & MACH64_POLICY_KERNEL_EXTENSION) {
			ipc_kmsg_sign_descriptors(dst_base->msgb_dsc_array,
			    desc_count);
		} else {
			ipc_kmsg_relocate_descriptors(dst_base->msgb_dsc_array,
			    src_base->msgb_dsc_array, desc_count);
		}
	}

	*kmsgp = kmsg;
	return MACH_MSG_SUCCESS;
}

static void
ipc_kmsg_copyin_port_from_kernel(
	mach_msg_header_t      *hdr,
	ipc_port_t              port,
	ipc_port_t              remote,
	mach_msg_type_name_t    disp)
{
	ipc_object_copyin_from_kernel(port, disp);
	/*
	 * avoid circularity when the destination is also
	 * the kernel.  This check should be changed into an
	 * assert when the new kobject model is in place since
	 * ports will not be used in kernel to kernel chats
	 */

	/* do not lock remote port, use raw pointer comparison */
	if (!ip_in_space_noauth(remote, ipc_space_kernel)) {
		/* remote port could be dead, in-transit or in an ipc space */
		if (disp == MACH_MSG_TYPE_MOVE_RECEIVE &&
		    ipc_port_check_circularity(port, remote)) {
			hdr->msgh_bits |= MACH_MSGH_BITS_CIRCULAR;
		}
	}
}

/*
 *	Routine:	ipc_kmsg_copyin_from_kernel
 *	Purpose:
 *		"Copy-in" port rights and out-of-line memory
 *		in a message sent from the kernel.
 *
 *		Because the message comes from the kernel,
 *		the implementation assumes there are no errors
 *		or peculiarities in the message.
 *	Conditions:
 *		Nothing locked.
 */

mach_msg_return_t
ipc_kmsg_copyin_from_kernel(
	ipc_kmsg_t      kmsg)
{
	mach_msg_header_t   *hdr = ikm_header(kmsg);
	mach_msg_bits_t      bits = hdr->msgh_bits;
	mach_msg_type_name_t rname = MACH_MSGH_BITS_REMOTE(bits);
	mach_msg_type_name_t lname = MACH_MSGH_BITS_LOCAL(bits);
	mach_msg_type_name_t vname = MACH_MSGH_BITS_VOUCHER(bits);
	ipc_port_t           remote = hdr->msgh_remote_port;
	ipc_port_t           local = hdr->msgh_local_port;
	ipc_port_t           voucher = ipc_kmsg_get_voucher_port(kmsg);

	/* translate the destination and reply ports */
	if (!IP_VALID(remote)) {
		return MACH_SEND_INVALID_DEST;
	}

	ipc_object_copyin_from_kernel(remote, rname);
	if (IP_VALID(local)) {
		ipc_object_copyin_from_kernel(local, lname);
	}

	if (IP_VALID(voucher)) {
		ipc_object_copyin_from_kernel(voucher, vname);
	}

	/*
	 *	The common case is a complex message with no reply port,
	 *	because that is what the memory_object interface uses.
	 */

	if (bits == (MACH_MSGH_BITS_COMPLEX |
	    MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0))) {
		bits = (MACH_MSGH_BITS_COMPLEX |
		    MACH_MSGH_BITS(MACH_MSG_TYPE_PORT_SEND, 0));

		hdr->msgh_bits = bits;
	} else {
		bits = (MACH_MSGH_BITS_OTHER(bits) |
		    MACH_MSGH_BITS_SET_PORTS(ipc_object_copyin_type(rname),
		    ipc_object_copyin_type(lname), ipc_object_copyin_type(vname)));

		hdr->msgh_bits = bits;
	}

	ipc_kmsg_set_qos_kernel(kmsg);

	/* Add trailer and signature to the message */
	ipc_kmsg_init_trailer_and_sign(kmsg, TASK_NULL);

	if (bits & MACH_MSGH_BITS_COMPLEX) {
		mach_msg_kbase_t *kbase = mach_msg_header_to_kbase(hdr);
		mach_msg_size_t   count = kbase->msgb_dsc_count;
		mach_msg_kdescriptor_t *kdesc = kbase->msgb_dsc_array;

		/*
		 * Check if the remote port accepts ports in the body.
		 */
		if (remote->ip_no_grant) {
			for (mach_msg_size_t i = 0; i < count; i++) {
				switch (mach_msg_kdescriptor_type(&kdesc[i])) {
				case MACH_MSG_PORT_DESCRIPTOR:
				case MACH_MSG_OOL_PORTS_DESCRIPTOR:
				case MACH_MSG_GUARDED_PORT_DESCRIPTOR:
					/* no descriptors have been copied in yet */
					ipc_kmsg_clean_header(kmsg);
					return MACH_SEND_NO_GRANT_DEST;
				}
			}
		}

		for (mach_msg_size_t i = 0; i < count; i++) {
			switch (mach_msg_kdescriptor_type(&kdesc[i])) {
			case MACH_MSG_PORT_DESCRIPTOR: {
				mach_msg_port_descriptor_t *dsc = &kdesc[i].kdesc_port;
				mach_msg_type_name_t disp = dsc->disposition;
				ipc_port_t           port = dsc->name;

				dsc->disposition = ipc_object_copyin_type(disp);
				if (IP_VALID(port)) {
					ipc_kmsg_copyin_port_from_kernel(hdr,
					    port, remote, disp);
				}
				break;
			}
			case MACH_MSG_OOL_VOLATILE_DESCRIPTOR:
			case MACH_MSG_OOL_DESCRIPTOR: {
				/*
				 * The sender should supply ready-made memory, i.e.
				 * a vm_map_copy_t, so we don't need to do anything.
				 */
				break;
			}
			case MACH_MSG_OOL_PORTS_DESCRIPTOR: {
				mach_msg_ool_ports_descriptor_t *dsc = &kdesc[i].kdesc_port_array;
				mach_msg_type_name_t disp  = dsc->disposition;
				mach_port_array_t    array = dsc->address;

				dsc->disposition = ipc_object_copyin_type(disp);

				for (mach_msg_size_t j = 0; j < dsc->count; j++) {
					ipc_port_t port = array[j].port;

					if (IP_VALID(port)) {
						ipc_kmsg_copyin_port_from_kernel(hdr,
						    port, remote, disp);
					}
				}
				break;
			}
			case MACH_MSG_GUARDED_PORT_DESCRIPTOR: {
				mach_msg_guarded_port_descriptor_t *dsc = &kdesc[i].kdesc_guarded_port;
				mach_msg_type_name_t disp = dsc->disposition;
				ipc_port_t           port = dsc->name;

				dsc->disposition = ipc_object_copyin_type(disp);
				assert(dsc->flags == 0);

				if (IP_VALID(port)) {
					ipc_kmsg_copyin_port_from_kernel(hdr,
					    port, remote, disp);
				}
				break;
			}
			default:
				__ipc_kmsg_descriptor_invalid_type_panic(kdesc);
			}
		}
	}

	return MACH_MSG_SUCCESS;
}

/*
 *	Routine:	ipc_kmsg_send
 *	Purpose:
 *		Send a message.  The message holds a reference
 *		for the destination port in the msgh_remote_port field.
 *
 *		If unsuccessful, the caller still has possession of
 *		the message and must do something with it.  If successful,
 *		the message is queued, given to a receiver, destroyed,
 *		or handled directly by the kernel via mach_msg.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		MACH_MSG_SUCCESS	       The message was accepted.
 *		MACH_SEND_TIMED_OUT	       Caller still has message.
 *		MACH_SEND_INTERRUPTED	   Caller still has message.
 *		MACH_SEND_INVALID_DEST	   Caller still has message.
 *      MACH_SEND_INVALID_OPTIONS  Caller still has message.
 */
mach_msg_return_t
ipc_kmsg_send(
	ipc_kmsg_t              kmsg,
	mach_msg_option64_t     options,
	mach_msg_timeout_t      send_timeout)
{
	ipc_port_t port;
	thread_t th = current_thread();
	mach_msg_return_t error = MACH_MSG_SUCCESS;
	boolean_t kernel_reply = FALSE;
	mach_msg_header_t *hdr;

	/* Check if honor qlimit flag is set on thread. */
	if ((th->options & TH_OPT_HONOR_QLIMIT) == TH_OPT_HONOR_QLIMIT) {
		/* Remove the MACH_SEND_ALWAYS flag to honor queue limit. */
		options &= (~MACH64_SEND_ALWAYS);
		/* Add the timeout flag since the message queue might be full. */
		options |= MACH64_SEND_TIMEOUT;
		th->options &= (~TH_OPT_HONOR_QLIMIT);
	}

#if IMPORTANCE_INHERITANCE
	bool did_importance = false;
#if IMPORTANCE_TRACE
	mach_msg_id_t imp_msgh_id = -1;
	int           sender_pid  = -1;
#endif /* IMPORTANCE_TRACE */
#endif /* IMPORTANCE_INHERITANCE */

	hdr = ikm_header(kmsg);
	/* don't allow the creation of a circular loop */
	if (hdr->msgh_bits & MACH_MSGH_BITS_CIRCULAR) {
		ipc_kmsg_destroy(kmsg, IPC_KMSG_DESTROY_ALL);
		KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_END, MACH_MSGH_BITS_CIRCULAR);
		return MACH_MSG_SUCCESS;
	}

	ipc_voucher_send_preprocessing(kmsg);

	port = hdr->msgh_remote_port;
	assert(IP_VALID(port));
	ip_mq_lock(port);

	/*
	 * If the destination has been guarded with a reply context, and the
	 * sender is consuming a send-once right, then assume this is a reply
	 * to an RPC and we need to validate that this sender is currently in
	 * the correct context.
	 */
	if (enforce_strict_reply && port->ip_reply_context != 0 &&
	    ((options & MACH64_SEND_KERNEL) == 0) &&
	    MACH_MSGH_BITS_REMOTE(hdr->msgh_bits) == MACH_MSG_TYPE_PORT_SEND_ONCE) {
		error = ipc_kmsg_validate_reply_context_locked(options,
		    port, th->ith_voucher, th->ith_voucher_name);
		if (error != MACH_MSG_SUCCESS) {
			ip_mq_unlock(port);
			return error;
		}
	}

#if IMPORTANCE_INHERITANCE
retry:
#endif /* IMPORTANCE_INHERITANCE */
	/*
	 *	Can't deliver to a dead port.
	 *	However, we can pretend it got sent
	 *	and was then immediately destroyed.
	 */
	if (!ip_active(port)) {
		ip_mq_unlock(port);
#if MACH_FLIPC
		if (MACH_NODE_VALID(kmsg->ikm_node) && FPORT_VALID(port->ip_messages.imq_fport)) {
			flipc_msg_ack(kmsg->ikm_node, &port->ip_messages, FALSE);
		}
#endif
		if (did_importance) {
			/*
			 * We're going to pretend we delivered this message
			 * successfully, and just eat the kmsg. However, the
			 * kmsg is actually visible via the importance_task!
			 * We need to cleanup this linkage before we destroy
			 * the message, and more importantly before we set the
			 * msgh_remote_port to NULL. See: 34302571
			 */
			ipc_importance_clean(kmsg);
		}
		ip_release(port);  /* JMM - Future: release right, not just ref */
		ipc_kmsg_destroy(kmsg, IPC_KMSG_DESTROY_SKIP_REMOTE);
		KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_END, MACH_SEND_INVALID_DEST);
		return MACH_MSG_SUCCESS;
	}

	if (ip_in_space(port, ipc_space_kernel)) {
		require_ip_active(port);
		port->ip_messages.imq_seqno++;
		ip_mq_unlock(port);

		counter_inc(&current_task()->messages_sent);

		/*
		 * Call the server routine, and get the reply message to send.
		 */
		kmsg = ipc_kobject_server(port, kmsg, options);
		if (kmsg == IKM_NULL) {
			return MACH_MSG_SUCCESS;
		}
		/* reload hdr since kmsg changed */
		hdr = ikm_header(kmsg);

		ipc_kmsg_init_trailer_and_sign(kmsg, TASK_NULL);

		/* restart the KMSG_INFO tracing for the reply message */
		KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_START);
		port = hdr->msgh_remote_port;
		assert(IP_VALID(port));
		ip_mq_lock(port);
		/* fall thru with reply - same options */
		kernel_reply = TRUE;
		if (!ip_active(port)) {
			error = MACH_SEND_INVALID_DEST;
		}
	}

#if IMPORTANCE_INHERITANCE
	/*
	 * Need to see if this message needs importance donation and/or
	 * propagation.  That routine can drop the port lock temporarily.
	 * If it does we'll have to revalidate the destination.
	 */
	if (!did_importance) {
		did_importance = true;
		if (ipc_importance_send(kmsg, options)) {
			goto retry;
		}
	}
#endif /* IMPORTANCE_INHERITANCE */

	if (error != MACH_MSG_SUCCESS) {
		ip_mq_unlock(port);
	} else {
		/*
		 * We have a valid message and a valid reference on the port.
		 * call mqueue_send() on its message queue.
		 */
		ipc_special_reply_port_msg_sent(port);

		error = ipc_mqueue_send_locked(&port->ip_messages, kmsg,
		    options, send_timeout);
		/* port unlocked */
	}

#if IMPORTANCE_INHERITANCE
	if (did_importance) {
		__unused int importance_cleared = 0;
		switch (error) {
		case MACH_SEND_TIMED_OUT:
		case MACH_SEND_NO_BUFFER:
		case MACH_SEND_INTERRUPTED:
		case MACH_SEND_INVALID_DEST:
			/*
			 * We still have the kmsg and its
			 * reference on the port.  But we
			 * have to back out the importance
			 * boost.
			 *
			 * The port could have changed hands,
			 * be inflight to another destination,
			 * etc...  But in those cases our
			 * back-out will find the new owner
			 * (and all the operations that
			 * transferred the right should have
			 * applied their own boost adjustments
			 * to the old owner(s)).
			 */
			importance_cleared = 1;
			ipc_importance_clean(kmsg);
			break;

		case MACH_MSG_SUCCESS:
		default:
			break;
		}
#if IMPORTANCE_TRACE
		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE, (IMPORTANCE_CODE(IMP_MSG, IMP_MSG_SEND)) | DBG_FUNC_END,
		    task_pid(current_task()), sender_pid, imp_msgh_id, importance_cleared, 0);
#endif /* IMPORTANCE_TRACE */
	}
#endif /* IMPORTANCE_INHERITANCE */

	/*
	 * If the port has been destroyed while we wait, treat the message
	 * as a successful delivery (like we do for an inactive port).
	 */
	if (error == MACH_SEND_INVALID_DEST) {
#if MACH_FLIPC
		if (MACH_NODE_VALID(kmsg->ikm_node) && FPORT_VALID(port->ip_messages.imq_fport)) {
			flipc_msg_ack(kmsg->ikm_node, &port->ip_messages, FALSE);
		}
#endif
		ip_release(port); /* JMM - Future: release right, not just ref */
		ipc_kmsg_destroy(kmsg, IPC_KMSG_DESTROY_SKIP_REMOTE);
		KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_END, MACH_SEND_INVALID_DEST);
		return MACH_MSG_SUCCESS;
	}

	if (error != MACH_MSG_SUCCESS && kernel_reply) {
		/*
		 * Kernel reply messages that fail can't be allowed to
		 * pseudo-receive on error conditions. We need to just treat
		 * the message as a successful delivery.
		 */
#if MACH_FLIPC
		if (MACH_NODE_VALID(kmsg->ikm_node) && FPORT_VALID(port->ip_messages.imq_fport)) {
			flipc_msg_ack(kmsg->ikm_node, &port->ip_messages, FALSE);
		}
#endif
		ip_release(port); /* JMM - Future: release right, not just ref */
		ipc_kmsg_destroy(kmsg, IPC_KMSG_DESTROY_SKIP_REMOTE);
		KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_END, error);
		return MACH_MSG_SUCCESS;
	}
	return error;
}

/*
 *	Routine:	ipc_kmsg_put_to_kernel
 *	Purpose:
 *		Copies a message buffer to a kernel message.
 *		Frees the message buffer.
 *		No errors allowed.
 *	Conditions:
 *		Nothing locked.
 */
void
ipc_kmsg_put_to_kernel(
	mach_msg_header_t      *msg,
	mach_msg_option64_t     options,
	ipc_kmsg_t              kmsg,
	mach_msg_size_t         rcv_size) /* includes trailer size */
{
	mach_msg_header_t *hdr = ikm_header(kmsg);
	mach_msg_kbase_t  *src_base;
	mach_msg_size_t    desc_count, kdata_sz;

	assert(kmsg->ikm_aux_size == 0);
	assert(rcv_size >= hdr->msgh_size);

	if (hdr->msgh_bits & MACH_MSGH_BITS_COMPLEX) {
		src_base   = mach_msg_header_to_kbase(hdr);
		desc_count = src_base->msgb_dsc_count;
		kdata_sz   = ikm_kdata_size(desc_count, true);
	} else {
		desc_count = 0;
		kdata_sz   = ikm_kdata_size(desc_count, false);
	}

	if (ikm_is_linear(kmsg)) {
		memcpy(msg, hdr, rcv_size);
	} else {
		memcpy(msg, hdr, kdata_sz);
		memcpy((char *)msg + kdata_sz,
		    kmsg->ikm_udata, rcv_size - kdata_sz);
	}

	if (desc_count) {
		mach_msg_kbase_t *dst_base = mach_msg_header_to_kbase(msg);

		if (options & MACH64_POLICY_KERNEL_EXTENSION) {
			ipc_kmsg_strip_descriptors(dst_base->msgb_dsc_array,
			    src_base->msgb_dsc_array, desc_count);
		} else {
			ipc_kmsg_relocate_descriptors(dst_base->msgb_dsc_array,
			    src_base->msgb_dsc_array, desc_count);
		}
	}

	ipc_kmsg_free(kmsg);
}

/** @} */
#pragma mark ipc_kmsg tracing

#define KMSG_TRACE_FLAG_TRACED     0x000001
#define KMSG_TRACE_FLAG_COMPLEX    0x000002
#define KMSG_TRACE_FLAG_OOLMEM     0x000004
#define KMSG_TRACE_FLAG_VCPY       0x000008
#define KMSG_TRACE_FLAG_PCPY       0x000010
#define KMSG_TRACE_FLAG_SND64      0x000020
#define KMSG_TRACE_FLAG_RAISEIMP   0x000040
#define KMSG_TRACE_FLAG_APP_SRC    0x000080
#define KMSG_TRACE_FLAG_APP_DST    0x000100
#define KMSG_TRACE_FLAG_DAEMON_SRC 0x000200
#define KMSG_TRACE_FLAG_DAEMON_DST 0x000400
#define KMSG_TRACE_FLAG_DST_NDFLTQ 0x000800
#define KMSG_TRACE_FLAG_SRC_NDFLTQ 0x001000
#define KMSG_TRACE_FLAG_DST_SONCE  0x002000
#define KMSG_TRACE_FLAG_SRC_SONCE  0x004000
#define KMSG_TRACE_FLAG_CHECKIN    0x008000
#define KMSG_TRACE_FLAG_ONEWAY     0x010000
#define KMSG_TRACE_FLAG_IOKIT      0x020000
#define KMSG_TRACE_FLAG_SNDRCV     0x040000
#define KMSG_TRACE_FLAG_DSTQFULL   0x080000
#define KMSG_TRACE_FLAG_VOUCHER    0x100000
#define KMSG_TRACE_FLAG_TIMER      0x200000
#define KMSG_TRACE_FLAG_SEMA       0x400000
#define KMSG_TRACE_FLAG_DTMPOWNER  0x800000
#define KMSG_TRACE_FLAG_GUARDED_DESC 0x1000000

#define KMSG_TRACE_FLAGS_MASK      0x1ffffff
#define KMSG_TRACE_FLAGS_SHIFT     8

#define KMSG_TRACE_ID_SHIFT        32

#define KMSG_TRACE_PORTS_MASK      0xff
#define KMSG_TRACE_PORTS_SHIFT     0

#if (KDEBUG_LEVEL >= KDEBUG_LEVEL_STANDARD)

void
ipc_kmsg_trace_send(ipc_kmsg_t kmsg, mach_msg_option64_t option)
{
	task_t send_task = TASK_NULL;
	ipc_port_t dst_port, src_port;
	boolean_t is_task_64bit;
	mach_msg_header_t *msg;
	mach_msg_trailer_t *trailer;

	int kotype = 0;
	uint32_t msg_size = 0;
	uint64_t msg_flags = KMSG_TRACE_FLAG_TRACED;
	uint32_t num_ports = 0;
	uint32_t send_pid, dst_pid;

	/*
	 * check to see not only if ktracing is enabled, but if we will
	 * _actually_ emit the KMSG_INFO tracepoint. This saves us a
	 * significant amount of processing (and a port lock hold) in
	 * the non-tracing case.
	 */
	if (__probable((kdebug_enable & KDEBUG_TRACE) == 0)) {
		return;
	}
	if (!kdebug_debugid_enabled(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO))) {
		return;
	}

	msg = ikm_header(kmsg);

	dst_port = msg->msgh_remote_port;
	if (!IPC_PORT_VALID(dst_port)) {
		return;
	}

	/*
	 * Message properties / options
	 */
	if ((option & (MACH_SEND_MSG | MACH_RCV_MSG)) == (MACH_SEND_MSG | MACH_RCV_MSG)) {
		msg_flags |= KMSG_TRACE_FLAG_SNDRCV;
	}

	if (msg->msgh_id >= is_iokit_subsystem.start &&
	    msg->msgh_id < is_iokit_subsystem.end + 100) {
		msg_flags |= KMSG_TRACE_FLAG_IOKIT;
	}
	/* magic XPC checkin message id (XPC_MESSAGE_ID_CHECKIN) from libxpc */
	else if (msg->msgh_id == 0x77303074u /* w00t */) {
		msg_flags |= KMSG_TRACE_FLAG_CHECKIN;
	}

	if (msg->msgh_bits & MACH_MSGH_BITS_RAISEIMP) {
		msg_flags |= KMSG_TRACE_FLAG_RAISEIMP;
	}

	if (unsafe_convert_port_to_voucher(ipc_kmsg_get_voucher_port(kmsg))) {
		msg_flags |= KMSG_TRACE_FLAG_VOUCHER;
	}

	/*
	 * Sending task / port
	 */
	send_task = current_task();
	send_pid = task_pid(send_task);

	if (send_pid != 0) {
		if (task_is_daemon(send_task)) {
			msg_flags |= KMSG_TRACE_FLAG_DAEMON_SRC;
		} else if (task_is_app(send_task)) {
			msg_flags |= KMSG_TRACE_FLAG_APP_SRC;
		}
	}

	is_task_64bit = (send_task->map->max_offset > VM_MAX_ADDRESS);
	if (is_task_64bit) {
		msg_flags |= KMSG_TRACE_FLAG_SND64;
	}

	src_port = msg->msgh_local_port;
	if (src_port) {
		if (src_port->ip_messages.imq_qlimit != MACH_PORT_QLIMIT_DEFAULT) {
			msg_flags |= KMSG_TRACE_FLAG_SRC_NDFLTQ;
		}
		switch (MACH_MSGH_BITS_LOCAL(msg->msgh_bits)) {
		case MACH_MSG_TYPE_MOVE_SEND_ONCE:
			msg_flags |= KMSG_TRACE_FLAG_SRC_SONCE;
			break;
		default:
			break;
		}
	} else {
		msg_flags |= KMSG_TRACE_FLAG_ONEWAY;
	}


	/*
	 * Destination task / port
	 */
	ip_mq_lock(dst_port);
	if (!ip_active(dst_port)) {
		/* dst port is being torn down */
		dst_pid = (uint32_t)0xfffffff0;
	} else if (dst_port->ip_tempowner) {
		msg_flags |= KMSG_TRACE_FLAG_DTMPOWNER;
		if (IIT_NULL != ip_get_imp_task(dst_port)) {
			dst_pid = task_pid(dst_port->ip_imp_task->iit_task);
		} else {
			dst_pid = (uint32_t)0xfffffff1;
		}
	} else if (!ip_in_a_space(dst_port)) {
		/* dst_port is otherwise in-transit */
		dst_pid = (uint32_t)0xfffffff2;
	} else {
		if (ip_in_space(dst_port, ipc_space_kernel)) {
			dst_pid = 0;
		} else {
			ipc_space_t dst_space;
			dst_space = ip_get_receiver(dst_port);
			if (dst_space && is_active(dst_space)) {
				dst_pid = task_pid(dst_space->is_task);
				if (task_is_daemon(dst_space->is_task)) {
					msg_flags |= KMSG_TRACE_FLAG_DAEMON_DST;
				} else if (task_is_app(dst_space->is_task)) {
					msg_flags |= KMSG_TRACE_FLAG_APP_DST;
				}
			} else {
				/* receiving task is being torn down */
				dst_pid = (uint32_t)0xfffffff3;
			}
		}
	}

	if (dst_port->ip_messages.imq_qlimit != MACH_PORT_QLIMIT_DEFAULT) {
		msg_flags |= KMSG_TRACE_FLAG_DST_NDFLTQ;
	}
	if (imq_full(&dst_port->ip_messages)) {
		msg_flags |= KMSG_TRACE_FLAG_DSTQFULL;
	}

	kotype = ip_kotype(dst_port);

	ip_mq_unlock(dst_port);

	switch (kotype) {
	case IKOT_SEMAPHORE:
		msg_flags |= KMSG_TRACE_FLAG_SEMA;
		break;
	case IKOT_TIMER:
	case IKOT_CLOCK:
		msg_flags |= KMSG_TRACE_FLAG_TIMER;
		break;
	case IKOT_MAIN_DEVICE:
	case IKOT_IOKIT_CONNECT:
	case IKOT_IOKIT_OBJECT:
	case IKOT_IOKIT_IDENT:
	case IKOT_UEXT_OBJECT:
		msg_flags |= KMSG_TRACE_FLAG_IOKIT;
		break;
	default:
		break;
	}

	switch (MACH_MSGH_BITS_REMOTE(msg->msgh_bits)) {
	case MACH_MSG_TYPE_PORT_SEND_ONCE:
		msg_flags |= KMSG_TRACE_FLAG_DST_SONCE;
		break;
	default:
		break;
	}


	/*
	 * Message size / content
	 */
	msg_size = msg->msgh_size - sizeof(mach_msg_header_t);

	if (msg->msgh_bits & MACH_MSGH_BITS_COMPLEX) {
		mach_msg_kbase_t *kbase = mach_msg_header_to_kbase(msg);
		mach_msg_kdescriptor_t *kdesc;
		mach_msg_descriptor_type_t dtype;

		msg_flags |= KMSG_TRACE_FLAG_COMPLEX;

		for (mach_msg_size_t i = 0; i < kbase->msgb_dsc_count; i++) {
			kdesc = &kbase->msgb_dsc_array[i];
			dtype = mach_msg_kdescriptor_type(kdesc);

			switch (dtype) {
			case MACH_MSG_PORT_DESCRIPTOR:
				num_ports++;
				break;
			case MACH_MSG_OOL_VOLATILE_DESCRIPTOR:
			case MACH_MSG_OOL_DESCRIPTOR: {
				mach_msg_ool_descriptor_t *dsc = &kdesc->kdesc_memory;

				msg_flags |= KMSG_TRACE_FLAG_OOLMEM;
				msg_size += dsc->size;
				if (dsc->size > msg_ool_size_small &&
				    (dsc->copy == MACH_MSG_PHYSICAL_COPY) &&
				    !dsc->deallocate) {
					msg_flags |= KMSG_TRACE_FLAG_PCPY;
				} else if (dsc->size <= msg_ool_size_small) {
					msg_flags |= KMSG_TRACE_FLAG_PCPY;
				} else {
					msg_flags |= KMSG_TRACE_FLAG_VCPY;
				}
			} break;
			case MACH_MSG_OOL_PORTS_DESCRIPTOR:
				num_ports += kdesc->kdesc_port_array.count;
				break;
			case MACH_MSG_GUARDED_PORT_DESCRIPTOR:
				num_ports++;
				msg_flags |= KMSG_TRACE_FLAG_GUARDED_DESC;
				break;
			default:
				break;
			}
			msg_size -= ikm_user_desc_size(dtype, is_task_64bit);
		}
	}

	/*
	 * Trailer contents
	 */
	trailer = (mach_msg_trailer_t *)ipc_kmsg_get_trailer(kmsg);
	if (trailer->msgh_trailer_size <= sizeof(mach_msg_security_trailer_t)) {
		mach_msg_security_trailer_t *strailer;
		strailer = (mach_msg_security_trailer_t *)trailer;
		/*
		 * verify the sender PID: replies from the kernel often look
		 * like self-talk because the sending port is not reset.
		 */
		if (memcmp(&strailer->msgh_sender,
		    &KERNEL_SECURITY_TOKEN,
		    sizeof(KERNEL_SECURITY_TOKEN)) == 0) {
			send_pid = 0;
			msg_flags &= ~(KMSG_TRACE_FLAG_APP_SRC | KMSG_TRACE_FLAG_DAEMON_SRC);
		}
	}

	KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_END,
	    (uintptr_t)send_pid,
	    (uintptr_t)dst_pid,
	    (uintptr_t)(((uint64_t)msg->msgh_id << KMSG_TRACE_ID_SHIFT) | msg_size),
	    (uintptr_t)(
		    ((msg_flags & KMSG_TRACE_FLAGS_MASK) << KMSG_TRACE_FLAGS_SHIFT) |
		    ((num_ports & KMSG_TRACE_PORTS_MASK) << KMSG_TRACE_PORTS_SHIFT)
		    )
	    );
}

#endif
