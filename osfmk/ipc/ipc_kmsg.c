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

#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_kern.h>

#include <ipc/port.h>
#include <ipc/ipc_types.h>
#include <ipc/ipc_entry.h>
#include <ipc/ipc_kmsg.h>
#include <ipc/ipc_notify.h>
#include <ipc/ipc_object.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_right.h>
#include <ipc/ipc_hash.h>
#include <ipc/ipc_importance.h>
#include <ipc/ipc_service_port.h>
#include <libkern/coreanalytics/coreanalytics.h>

#if MACH_FLIPC
#include <kern/mach_node.h>
#include <ipc/flipc.h>
#endif

#include <os/overflow.h>

#include <security/mac_mach_internal.h>

#include <device/device_server.h>

#include <string.h>

#if DEBUG
#define DEBUG_MSGS_K64 1
#endif

#include <sys/kdebug.h>
#include <sys/proc_ro.h>
#include <sys/codesign.h>
#include <libkern/OSAtomic.h>

#include <libkern/crypto/sha2.h>

#include <ptrauth.h>
#if __has_feature(ptrauth_calls)
#include <libkern/ptrauth_utils.h>
#endif

#if CONFIG_CSR
#include <sys/csr.h>
#endif

/*
 * In kernel, complex mach msg have a simpler representation than userspace:
 *
 * <header>
 * <desc-count>
 * <descriptors> * desc-count
 * <body>
 *
 * And the descriptors are of a fake type `mach_msg_descriptor_t`,
 * that is large enough to accommodate for any possible representation.
 *
 * The `type` field of any desciptor is always at the same offset,
 * and the smallest possible descriptor is of size MACH_MSG_DESC_MIN_SIZE.
 *
 * Note:
 * - KERN_DESC_SIZE is 16 on all kernels
 * - MACH_MSG_DESC_MIN_SIZE is 12 on all kernels
 */

#define KERNEL_DESC_SIZE             sizeof(mach_msg_descriptor_t)
#define MACH_MSG_DESC_MIN_SIZE       sizeof(mach_msg_type_descriptor_t)

#define USER_HEADER_SIZE_DELTA \
	((mach_msg_size_t)(sizeof(mach_msg_header_t) - sizeof(mach_msg_user_header_t)))

#define USER_DESC_MAX_DELTA \
	(KERNEL_DESC_SIZE - MACH_MSG_DESC_MIN_SIZE)

#define mach_validate_desc_type(t) \
	static_assert(MACH_MSG_DESC_MIN_SIZE <= sizeof(t) && \
	sizeof(t) <= sizeof(mach_msg_descriptor_t))

mach_validate_desc_type(mach_msg_descriptor_t);
mach_validate_desc_type(mach_msg_port_descriptor_t);
mach_validate_desc_type(mach_msg_user_port_descriptor_t);
mach_validate_desc_type(mach_msg_type_descriptor_t);
mach_validate_desc_type(mach_msg_ool_descriptor32_t);
mach_validate_desc_type(mach_msg_ool_descriptor64_t);
mach_validate_desc_type(mach_msg_ool_ports_descriptor32_t);
mach_validate_desc_type(mach_msg_ool_ports_descriptor64_t);
mach_validate_desc_type(mach_msg_guarded_port_descriptor32_t);
mach_validate_desc_type(mach_msg_guarded_port_descriptor64_t);

extern char *proc_name_address(struct proc *p);
static mach_msg_return_t ipc_kmsg_option_check(ipc_port_t port, mach_msg_option64_t option64);

/*
 * As CA framework replies on successfully allocating zalloc memory,
 * we maintain a small buffer that gets flushed when full. This helps us avoid taking spinlocks when working with CA.
 */
#define REPLY_PORT_SEMANTICS_VIOLATIONS_RB_SIZE         2

/*
 * Stripped down version of service port's string name. This is to avoid overwhelming CA's dynamic memory allocation.
 */
#define CA_MACH_SERVICE_PORT_NAME_LEN                   86

struct reply_port_semantics_violations_rb_entry {
	char proc_name[CA_PROCNAME_LEN];
	char service_name[CA_MACH_SERVICE_PORT_NAME_LEN];
	char team_id[CA_TEAMID_MAX_LEN];
	char signing_id[CA_SIGNINGID_MAX_LEN];
	int  reply_port_semantics_violation;
	int  sw_platform;
	int  msgh_id;
	int  sdk;
};
struct reply_port_semantics_violations_rb_entry reply_port_semantics_violations_rb[REPLY_PORT_SEMANTICS_VIOLATIONS_RB_SIZE];
static uint8_t reply_port_semantics_violations_rb_index = 0;

LCK_GRP_DECLARE(reply_port_telemetry_lock_grp, "reply_port_telemetry_lock_grp");
LCK_SPIN_DECLARE(reply_port_telemetry_lock, &reply_port_telemetry_lock_grp);

/* Telemetry: report back the process name violating reply port semantics */
CA_EVENT(reply_port_semantics_violations,
    CA_STATIC_STRING(CA_PROCNAME_LEN), proc_name,
    CA_STATIC_STRING(CA_MACH_SERVICE_PORT_NAME_LEN), service_name,
    CA_STATIC_STRING(CA_TEAMID_MAX_LEN), team_id,
    CA_STATIC_STRING(CA_SIGNINGID_MAX_LEN), signing_id,
    CA_INT, reply_port_semantics_violation);

static void
send_reply_port_telemetry(const struct reply_port_semantics_violations_rb_entry *entry)
{
	ca_event_t ca_event = CA_EVENT_ALLOCATE_FLAGS(reply_port_semantics_violations, Z_NOWAIT);
	if (ca_event) {
		CA_EVENT_TYPE(reply_port_semantics_violations) * event = ca_event->data;

		strlcpy(event->service_name, entry->service_name, CA_MACH_SERVICE_PORT_NAME_LEN);
		strlcpy(event->proc_name, entry->proc_name, CA_PROCNAME_LEN);
		strlcpy(event->team_id, entry->team_id, CA_TEAMID_MAX_LEN);
		strlcpy(event->signing_id, entry->signing_id, CA_SIGNINGID_MAX_LEN);
		event->reply_port_semantics_violation = entry->reply_port_semantics_violation;

		CA_EVENT_SEND(ca_event);
	}
}

/* Routine: flush_reply_port_semantics_violations_telemetry
 * Conditions:
 *              Assumes the reply_port_telemetry_lock is held.
 *              Unlocks it before returning.
 */
static void
flush_reply_port_semantics_violations_telemetry()
{
	struct reply_port_semantics_violations_rb_entry local_rb[REPLY_PORT_SEMANTICS_VIOLATIONS_RB_SIZE];
	uint8_t local_rb_index = 0;

	if (__improbable(reply_port_semantics_violations_rb_index > REPLY_PORT_SEMANTICS_VIOLATIONS_RB_SIZE)) {
		panic("Invalid reply port semantics violations buffer index %d > %d",
		    reply_port_semantics_violations_rb_index, REPLY_PORT_SEMANTICS_VIOLATIONS_RB_SIZE);
	}

	/*
	 * We operate on local copy of telemetry buffer because CA framework relies on successfully
	 * allocating zalloc memory. It can not do that if we are accessing the shared buffer
	 * with spin locks held.
	 */
	while (local_rb_index != reply_port_semantics_violations_rb_index) {
		local_rb[local_rb_index] = reply_port_semantics_violations_rb[local_rb_index];
		local_rb_index++;
	}

	lck_spin_unlock(&reply_port_telemetry_lock);

	while (local_rb_index > 0) {
		struct reply_port_semantics_violations_rb_entry *entry = &local_rb[--local_rb_index];

		send_reply_port_telemetry(entry);
	}

	/*
	 * Finally call out the buffer as empty. This is also a sort of rate limiting mechanisms for the events.
	 * Events will get dropped until the buffer is not fully flushed.
	 */
	lck_spin_lock(&reply_port_telemetry_lock);
	reply_port_semantics_violations_rb_index = 0;
}

static void
stash_reply_port_semantics_violations_telemetry(mach_service_port_info_t sp_info, int reply_port_semantics_violation, int msgh_id)
{
	struct reply_port_semantics_violations_rb_entry *entry;

	task_t task = current_task_early();
	if (task) {
		struct proc_ro *pro = current_thread_ro()->tro_proc_ro;
		uint32_t platform = pro->p_platform_data.p_platform;
		uint32_t sdk = pro->p_platform_data.p_sdk;
		char *proc_name = (char *) "unknown";
#ifdef MACH_BSD
		proc_name = proc_name_address(get_bsdtask_info(task));
#endif /* MACH_BSD */
		const char *team_id = csproc_get_identity(current_proc());
		const char *signing_id = csproc_get_teamid(current_proc());
		char *service_name = (char *) "unknown";
		if (sp_info) {
			service_name = sp_info->mspi_string_name;
		}

		lck_spin_lock(&reply_port_telemetry_lock);

		if (reply_port_semantics_violations_rb_index >= REPLY_PORT_SEMANTICS_VIOLATIONS_RB_SIZE) {
			/* Dropping the event since buffer is full. */
			lck_spin_unlock(&reply_port_telemetry_lock);
			return;
		}
		entry = &reply_port_semantics_violations_rb[reply_port_semantics_violations_rb_index++];
		strlcpy(entry->proc_name, proc_name, CA_PROCNAME_LEN);

		strlcpy(entry->service_name, service_name, CA_MACH_SERVICE_PORT_NAME_LEN);
		entry->reply_port_semantics_violation = reply_port_semantics_violation;
		if (team_id) {
			strlcpy(entry->team_id, team_id, CA_TEAMID_MAX_LEN);
		}

		if (signing_id) {
			strlcpy(entry->signing_id, signing_id, CA_SIGNINGID_MAX_LEN);
		}
		entry->msgh_id = msgh_id;
		entry->sw_platform = platform;
		entry->sdk = sdk;
	}

	if (reply_port_semantics_violations_rb_index == REPLY_PORT_SEMANTICS_VIOLATIONS_RB_SIZE) {
		flush_reply_port_semantics_violations_telemetry();
	}

	lck_spin_unlock(&reply_port_telemetry_lock);
}

/* Update following two helpers if new descriptor type is added */
static_assert(MACH_MSG_DESCRIPTOR_MAX == MACH_MSG_GUARDED_PORT_DESCRIPTOR);

static inline mach_msg_size_t
ikm_user_desc_size(
	mach_msg_descriptor_type_t type,
	bool                       is_task_64bit)
{
	if (is_task_64bit) {
		switch (type) {
		case MACH_MSG_OOL_VOLATILE_DESCRIPTOR:
		case MACH_MSG_OOL_DESCRIPTOR:
			return sizeof(mach_msg_ool_descriptor64_t);
		case MACH_MSG_OOL_PORTS_DESCRIPTOR:
			return sizeof(mach_msg_ool_ports_descriptor64_t);
		case MACH_MSG_GUARDED_PORT_DESCRIPTOR:
			return sizeof(mach_msg_guarded_port_descriptor64_t);
		default: /* MACH_MSG_PORT_DESCRIPTOR */
			return sizeof(mach_msg_user_port_descriptor_t);
		}
	} else {
		switch (type) {
		case MACH_MSG_OOL_VOLATILE_DESCRIPTOR:
		case MACH_MSG_OOL_DESCRIPTOR:
			return sizeof(mach_msg_ool_descriptor32_t);
		case MACH_MSG_OOL_PORTS_DESCRIPTOR:
			return sizeof(mach_msg_ool_ports_descriptor32_t);
		case MACH_MSG_GUARDED_PORT_DESCRIPTOR:
			return sizeof(mach_msg_guarded_port_descriptor32_t);
		default: /* MACH_MSG_PORT_DESCRIPTOR */
			return sizeof(mach_msg_user_port_descriptor_t);
		}
	}
}

static inline bool
ikm_user_desc_type_valid(
	mach_msg_descriptor_type_t type)
{
	return type <= MACH_MSG_DESCRIPTOR_MAX;
}

/*
 * Measure the total descriptor size in a kmsg.
 *
 * Condition:
 *     Descriptors must have valid type and message is well-formed.
 *     See ikm_check_descriptors().
 */
static mach_msg_size_t
ikm_total_desc_size(
	ipc_kmsg_t      kmsg,
	vm_map_t        map,
	mach_msg_size_t body_adj,    /* gap formed during copyout_body memmove */
	mach_msg_size_t header_adj,  /* gap formed during put_to_user */
	bool            user_descs)  /* are descriptors user sized */
{
	mach_msg_size_t total = 0;
	bool is_task_64bit = (map->max_offset > VM_MAX_ADDRESS);
	mach_msg_size_t hdr_size = sizeof(mach_msg_header_t) - header_adj;
	/*
	 * hdr can be of type (mach_msg_user_header_t *) or (mach_msg_header_t *).
	 * following code relies on the fact that both structs share the same
	 * first two fields. (msgh_bits and msgh_size)
	 */
	static_assert(offsetof(mach_msg_user_header_t, msgh_bits) ==
	    offsetof(mach_msg_header_t, msgh_bits));
	static_assert(offsetof(mach_msg_user_header_t, msgh_size) ==
	    offsetof(mach_msg_header_t, msgh_size));

	mach_msg_header_t *hdr = (mach_msg_header_t *)((vm_offset_t)ikm_header(kmsg) + header_adj);

	if (hdr->msgh_bits & MACH_MSGH_BITS_COMPLEX) {
		mach_msg_body_t *body;
		mach_msg_type_number_t dsc_count;
		mach_msg_size_t dsize;
		mach_msg_descriptor_t *daddr;

		body = (mach_msg_body_t *)((vm_offset_t)hdr + hdr_size);
		dsc_count = body->msgh_descriptor_count;

		if (!user_descs) {
			return dsc_count * KERNEL_DESC_SIZE;
		}

		daddr = (mach_msg_descriptor_t *)((vm_offset_t)(body + 1) + body_adj);
		for (uint32_t i = 0; i < dsc_count; i++) {
			dsize = ikm_user_desc_size(daddr->type.type, is_task_64bit);
			daddr = (mach_msg_descriptor_t *)((vm_offset_t)daddr + dsize);
			total += dsize;
		}
	}

	return total;
}

/* Pre-validate descriptors and message size during copyin */
__result_use_check
static mach_msg_return_t
ikm_check_descriptors(
	ipc_kmsg_t      kmsg, /* a complex message */
	vm_map_t        map,
	mach_msg_size_t copied_in)
{
	mach_msg_body_t *body;
	mach_msg_type_number_t dsc_count;
	mach_msg_size_t dsize;
	vm_offset_t end;
	mach_msg_descriptor_t *daddr;

	bool is_task_64bit = (map->max_offset > VM_MAX_ADDRESS);
	mach_msg_size_t hdr_size = sizeof(mach_msg_header_t);
	mach_msg_size_t base_size = sizeof(mach_msg_base_t);
	mach_msg_header_t *hdr = ikm_header(kmsg);

	assert(hdr->msgh_bits & MACH_MSGH_BITS_COMPLEX);

	body = (mach_msg_body_t *)((vm_offset_t)hdr + hdr_size);
	dsc_count = body->msgh_descriptor_count;
	daddr = (mach_msg_descriptor_t *)(vm_offset_t)(body + 1);
	/* Maximum possible descriptor end address */
	end = (vm_offset_t)hdr + base_size + copied_in;

	for (uint32_t i = 0; i < dsc_count; i++) {
		if ((vm_offset_t)daddr + MACH_MSG_DESC_MIN_SIZE > end) {
			return MACH_SEND_MSG_TOO_SMALL;
		}
		/* Now we can access daddr->type safely */
		if (!ikm_user_desc_type_valid(daddr->type.type)) {
			return MACH_SEND_INVALID_TYPE;
		}
		dsize = ikm_user_desc_size(daddr->type.type, is_task_64bit);

		if ((vm_offset_t)daddr + dsize > end) {
			return MACH_SEND_MSG_TOO_SMALL;
		}
		daddr = (mach_msg_descriptor_t *)((vm_offset_t)daddr + dsize);
	}

	return MACH_MSG_SUCCESS;
}

/* Measure the size of user data content carried in kmsg. */
static mach_msg_size_t
ikm_content_size(
	ipc_kmsg_t      kmsg,
	vm_map_t        map,
	mach_msg_size_t header_adj,  /* gap formed during put_to_user */
	bool            user_descs)  /* are descriptors user sized */
{
	mach_msg_size_t hdr_size = sizeof(mach_msg_header_t) - header_adj;
	mach_msg_size_t base_size = hdr_size + sizeof(mach_msg_body_t);
	/*
	 * hdr can be of type (mach_msg_user_header_t *) or (mach_msg_header_t *).
	 * following code relies on the fact that both structs share the same
	 * first two fields. (msgh_bits and msgh_size)
	 */
	mach_msg_header_t *hdr = (mach_msg_header_t *)((vm_offset_t)ikm_header(kmsg) + header_adj);

	assert(hdr->msgh_size >= hdr_size);
	if (hdr->msgh_size <= hdr_size) {
		return 0;
	}

	if (hdr->msgh_bits & MACH_MSGH_BITS_COMPLEX) {
		assert(hdr->msgh_size >= base_size +
		    ikm_total_desc_size(kmsg, map, 0, header_adj, user_descs));
		return hdr->msgh_size - base_size -
		       ikm_total_desc_size(kmsg, map, 0, header_adj, user_descs);
	} else {
		assert(hdr->msgh_size > hdr_size);
		return hdr->msgh_size - hdr_size;
	}
}

/* Size of kmsg header (plus body and descriptors for complex messages) */
static mach_msg_size_t
ikm_kdata_size(
	ipc_kmsg_t      kmsg,
	vm_map_t        map,
	mach_msg_size_t header_adj,
	bool            user_descs)
{
	mach_msg_size_t content_size = ikm_content_size(kmsg, map, header_adj, user_descs);
	/*
	 * hdr can be of type (mach_msg_user_header_t *) or (mach_msg_header_t *).
	 * following code relies on the fact that both structs share the same
	 * first two fields. (msgh_bits and msgh_size)
	 */
	mach_msg_header_t *hdr = (mach_msg_header_t *)((vm_offset_t)ikm_header(kmsg) + header_adj);

	assert(hdr->msgh_size > content_size);
	return hdr->msgh_size - content_size;
}

#if __has_feature(ptrauth_calls)
typedef uintptr_t ikm_sig_scratch_t;

static void
ikm_init_sig(
	__unused ipc_kmsg_t kmsg,
	ikm_sig_scratch_t *scratchp)
{
	*scratchp = OS_PTRAUTH_DISCRIMINATOR("kmsg.ikm_signature");
}

static void
ikm_chunk_sig(
	ipc_kmsg_t kmsg,
	void *data,
	size_t len,
	ikm_sig_scratch_t *scratchp)
{
	int ptrauth_flags;
	void *trailerp;

	/*
	 * if we happen to be doing the trailer chunk,
	 * diversify with the ptrauth-ed trailer pointer -
	 * as that is unchanging for the kmsg
	 */
	trailerp = (void *)ipc_kmsg_get_trailer(kmsg, false);

	ptrauth_flags = (data == trailerp) ? PTRAUTH_ADDR_DIVERSIFY : 0;
	*scratchp = ptrauth_utils_sign_blob_generic(data, len, *scratchp, ptrauth_flags);
}

static uintptr_t
ikm_finalize_sig(
	__unused ipc_kmsg_t kmsg,
	ikm_sig_scratch_t *scratchp)
{
	return *scratchp;
}

#elif defined(CRYPTO_SHA2) && !defined(__x86_64__)

typedef SHA256_CTX ikm_sig_scratch_t;

static void
ikm_init_sig(
	__unused ipc_kmsg_t kmsg,
	ikm_sig_scratch_t *scratchp)
{
	SHA256_Init(scratchp);
	SHA256_Update(scratchp, &vm_kernel_addrhash_salt_ext, sizeof(uint64_t));
}

static void
ikm_chunk_sig(
	__unused ipc_kmsg_t kmsg,
	void *data,
	size_t len,
	ikm_sig_scratch_t *scratchp)
{
	SHA256_Update(scratchp, data, len);
}

static uintptr_t
ikm_finalize_sig(
	__unused ipc_kmsg_t kmsg,
	ikm_sig_scratch_t *scratchp)
{
	uintptr_t sha_digest[SHA256_DIGEST_LENGTH / sizeof(uintptr_t)];

	SHA256_Final((uint8_t *)sha_digest, scratchp);

	/*
	 * Only use one uintptr_t sized part of result for space and compat reasons.
	 * Truncation is better than XOR'ing the chunks together in hopes of higher
	 * entropy - because of its lower risk of collisions.
	 */
	return *sha_digest;
}

#else
/* Stubbed out implementation (for __x86_64__ for now) */

typedef uintptr_t ikm_sig_scratch_t;

static void
ikm_init_sig(
	__unused ipc_kmsg_t kmsg,
	ikm_sig_scratch_t *scratchp)
{
	*scratchp = 0;
}

static void
ikm_chunk_sig(
	__unused ipc_kmsg_t kmsg,
	__unused void *data,
	__unused size_t len,
	__unused ikm_sig_scratch_t *scratchp)
{
	return;
}

static uintptr_t
ikm_finalize_sig(
	__unused ipc_kmsg_t kmsg,
	ikm_sig_scratch_t *scratchp)
{
	return *scratchp;
}

#endif

static void
ikm_header_sig(
	ipc_kmsg_t kmsg,
	ikm_sig_scratch_t *scratchp)
{
	mach_msg_size_t dsc_count;
	mach_msg_base_t base;
	boolean_t complex;

	mach_msg_header_t *hdr = ikm_header(kmsg);
	/* take a snapshot of the message header/body-count */
	base.header = *hdr;
	complex = ((base.header.msgh_bits & MACH_MSGH_BITS_COMPLEX) != 0);
	if (complex) {
		dsc_count = ((mach_msg_body_t *)(hdr + 1))->msgh_descriptor_count;
	} else {
		dsc_count = 0;
	}
	base.body.msgh_descriptor_count = dsc_count;

	/* compute sig of a copy of the header with all varying bits masked off */
	base.header.msgh_bits &= MACH_MSGH_BITS_USER;
	base.header.msgh_bits &= ~MACH_MSGH_BITS_VOUCHER_MASK;
	ikm_chunk_sig(kmsg, &base, sizeof(mach_msg_base_t), scratchp);
}

static void
ikm_trailer_sig(
	ipc_kmsg_t kmsg,
	ikm_sig_scratch_t *scratchp)
{
	mach_msg_max_trailer_t *trailerp;

	/* Add sig of the trailer contents */
	trailerp = ipc_kmsg_get_trailer(kmsg, false);
	ikm_chunk_sig(kmsg, trailerp, sizeof(*trailerp), scratchp);
}

/* Compute the signature for the body bits of a message */
static void
ikm_body_sig(
	ipc_kmsg_t        kmsg,
	ikm_sig_scratch_t *scratchp)
{
	mach_msg_descriptor_t *kern_dsc;
	mach_msg_size_t dsc_count;
	mach_msg_body_t *body;
	mach_msg_size_t i;

	mach_msg_header_t *hdr = ikm_header(kmsg);

	if ((hdr->msgh_bits & MACH_MSGH_BITS_COMPLEX) == 0) {
		return;
	}
	body = (mach_msg_body_t *) (hdr + 1);
	dsc_count = body->msgh_descriptor_count;

	if (dsc_count == 0) {
		return;
	}

	kern_dsc = (mach_msg_descriptor_t *) (body + 1);

	/* Compute the signature for the whole descriptor array */
	ikm_chunk_sig(kmsg, kern_dsc, sizeof(*kern_dsc) * dsc_count, scratchp);

	/* look for descriptor contents that need a signature */
	for (i = 0; i < dsc_count; i++) {
		switch (kern_dsc[i].type.type) {
		case MACH_MSG_PORT_DESCRIPTOR:
		case MACH_MSG_GUARDED_PORT_DESCRIPTOR:
		case MACH_MSG_OOL_VOLATILE_DESCRIPTOR:
		case MACH_MSG_OOL_DESCRIPTOR:
			break;

		case MACH_MSG_OOL_PORTS_DESCRIPTOR: {
			mach_msg_ool_ports_descriptor_t *ports_dsc;

			/* Compute sig for the port/object pointers */
			ports_dsc = (mach_msg_ool_ports_descriptor_t *)&kern_dsc[i];
			ikm_chunk_sig(kmsg, ports_dsc->address, ports_dsc->count * sizeof(ipc_object_t), scratchp);
			break;
		}
		default: {
			panic("ipc_kmsg_body_sig: invalid message descriptor");
		}
		}
	}
}

static void
ikm_sign(ipc_kmsg_t kmsg)
{
	ikm_sig_scratch_t scratch;
	uintptr_t sig;

	zone_require(ipc_kmsg_zone, kmsg);

	ikm_init_sig(kmsg, &scratch);

	/* First sign header and trailer and store a partial sig */
	ikm_header_sig(kmsg, &scratch);
	ikm_trailer_sig(kmsg, &scratch);

#if __has_feature(ptrauth_calls)
	/*
	 * On PAC devices lower 32 bits of the signature generated by G Key are
	 * always zeros. Use that space to store header + trailer partial sig.
	 *
	 * See: ptrauth_utils_sign_blob_generic()
	 */
	kmsg->ikm_sig_partial = (uint32_t)(ikm_finalize_sig(kmsg, &scratch) >> 32);
#endif

	/* Then sign body, which may be large: ~ BigO(# descriptors) */
	ikm_body_sig(kmsg, &scratch);

	sig = ikm_finalize_sig(kmsg, &scratch);
#if __has_feature(ptrauth_calls)
	kmsg->ikm_sig_full = (uint32_t)(sig >> 32);
#else
	kmsg->ikm_signature = sig;
#endif
}

unsigned int ikm_signature_failures;
unsigned int ikm_signature_failure_id;
#if (DEVELOPMENT || DEBUG)
unsigned int ikm_signature_panic_disable;
unsigned int ikm_signature_header_failures;
unsigned int ikm_signature_trailer_failures;
#endif

/*
 * Purpose:
 *       Validate kmsg signature.
 *       partial:  Only validate header + trailer.
 *
 * Condition:
 *       On non-PAC devices, `partial` must be set to false.
 */
static void
ikm_validate_sig_internal(
	ipc_kmsg_t kmsg,
	bool       partial)
{
	ikm_sig_scratch_t scratch;
	uintptr_t expected;
	uintptr_t sig;
	char *str;

	zone_require(ipc_kmsg_zone, kmsg);

	ikm_init_sig(kmsg, &scratch);

	ikm_header_sig(kmsg, &scratch);

	ikm_trailer_sig(kmsg, &scratch);

	if (partial) {
#if __has_feature(ptrauth_calls)
		/* Do partial evaluation of header + trailer signature */
		sig = ikm_finalize_sig(kmsg, &scratch);
		expected = (uintptr_t)kmsg->ikm_sig_partial << 32;
		if (sig != expected) {
#if (DEVELOPMENT || DEBUG)
			ikm_signature_trailer_failures++;
#endif
			str = "header trailer";
			goto failure;
		}
		return;
#else
		panic("Partial kmsg signature validation only supported on PAC devices.");
#endif
	}

	ikm_body_sig(kmsg, &scratch);
	sig = ikm_finalize_sig(kmsg, &scratch);

#if __has_feature(ptrauth_calls)
	expected = (uintptr_t)kmsg->ikm_sig_full << 32;
#else
	expected = kmsg->ikm_signature;
#endif

	if (sig != expected) {
		ikm_signature_failures++;
		str = "full";

#if __has_feature(ptrauth_calls)
		failure:
#endif
		{
			mach_msg_id_t id = ikm_header(kmsg)->msgh_id;

			ikm_signature_failure_id = id;
#if (DEVELOPMENT || DEBUG)
			if (ikm_signature_panic_disable) {
				return;
			}
#endif
			panic("ikm_validate_sig: %s signature mismatch: kmsg=0x%p, id=%d, sig=0x%zx (expected 0x%zx)",
			    str, kmsg, id, sig, expected);
		}
	}
}

static void
ikm_validate_sig(
	ipc_kmsg_t kmsg)
{
	ikm_validate_sig_internal(kmsg, false);
}

/*
 * Purpose:
 *       Validate kmsg signature. [Exported in header]
 *       partial:  Only validate header + trailer.
 *
 * Condition:
 *       On non-PAC devices, `partial` must be set to false.
 */
void
ipc_kmsg_validate_sig(
	ipc_kmsg_t kmsg,
	bool       partial)
{
	ikm_validate_sig_internal(kmsg, partial);
}

#if DEBUG_MSGS_K64
extern void ipc_pset_print64(
	ipc_pset_t      pset);

extern void     ipc_kmsg_print64(
	ipc_kmsg_t      kmsg,
	const char      *str);

extern void     ipc_msg_print64(
	mach_msg_header_t       *msgh);

extern ipc_port_t ipc_name_to_data64(
	task_t                  task,
	mach_port_name_t        name);

/*
 * Forward declarations
 */
void ipc_msg_print_untyped64(
	mach_msg_body_t         *body);

const char * ipc_type_name64(
	int             type_name,
	boolean_t       received);

void ipc_print_type_name64(
	int     type_name);

const char *
msgh_bit_decode64(
	mach_msg_bits_t bit);

const char *
mm_copy_options_string64(
	mach_msg_copy_options_t option);

void db_print_msg_uid64(mach_msg_header_t *);

static void
ipc_msg_body_print64(void *body, int size)
{
	uint32_t        *word = (uint32_t *) body;
	uint32_t        *end  = (uint32_t *)(((uintptr_t) body) + size
	    - sizeof(mach_msg_header_t));
	int             i;

	kprintf("  body(%p-%p):\n    %p: ", body, end, word);
	for (;;) {
		for (i = 0; i < 8; i++, word++) {
			if (word >= end) {
				kprintf("\n");
				return;
			}
			kprintf("%08x ", *word);
		}
		kprintf("\n    %p: ", word);
	}
}


const char *
ipc_type_name64(
	int             type_name,
	boolean_t       received)
{
	switch (type_name) {
	case MACH_MSG_TYPE_PORT_NAME:
		return "port_name";

	case MACH_MSG_TYPE_MOVE_RECEIVE:
		if (received) {
			return "port_receive";
		} else {
			return "move_receive";
		}

	case MACH_MSG_TYPE_MOVE_SEND:
		if (received) {
			return "port_send";
		} else {
			return "move_send";
		}

	case MACH_MSG_TYPE_MOVE_SEND_ONCE:
		if (received) {
			return "port_send_once";
		} else {
			return "move_send_once";
		}

	case MACH_MSG_TYPE_COPY_SEND:
		return "copy_send";

	case MACH_MSG_TYPE_MAKE_SEND:
		return "make_send";

	case MACH_MSG_TYPE_MAKE_SEND_ONCE:
		return "make_send_once";

	default:
		return (char *) 0;
	}
}

void
ipc_print_type_name64(
	int     type_name)
{
	const char *name = ipc_type_name64(type_name, TRUE);
	if (name) {
		kprintf("%s", name);
	} else {
		kprintf("type%d", type_name);
	}
}

/*
 * ipc_kmsg_print64	[ debug ]
 */
void
ipc_kmsg_print64(
	ipc_kmsg_t      kmsg,
	const char      *str)
{
	kprintf("%s kmsg=%p:\n", str, kmsg);
	kprintf("  next=%p, prev=%p",
	    kmsg->ikm_link.next,
	    kmsg->ikm_link.prev);
	kprintf("\n");
	ipc_msg_print64(ikm_header(kmsg));
}

const char *
msgh_bit_decode64(
	mach_msg_bits_t bit)
{
	switch (bit) {
	case MACH_MSGH_BITS_COMPLEX:        return "complex";
	case MACH_MSGH_BITS_CIRCULAR:       return "circular";
	default:                            return (char *) 0;
	}
}

/*
 * ipc_msg_print64	[ debug ]
 */
void
ipc_msg_print64(
	mach_msg_header_t       *msgh)
{
	mach_msg_bits_t mbits;
	unsigned int    bit, i;
	const char      *bit_name;
	int             needs_comma;

	mbits = msgh->msgh_bits;
	kprintf("  msgh_bits=0x%x: l=0x%x,r=0x%x\n",
	    mbits,
	    MACH_MSGH_BITS_LOCAL(msgh->msgh_bits),
	    MACH_MSGH_BITS_REMOTE(msgh->msgh_bits));

	mbits = MACH_MSGH_BITS_OTHER(mbits) & MACH_MSGH_BITS_USED;
	kprintf("  decoded bits:  ");
	needs_comma = 0;
	for (i = 0, bit = 1; i < sizeof(mbits) * 8; ++i, bit <<= 1) {
		if ((mbits & bit) == 0) {
			continue;
		}
		bit_name = msgh_bit_decode64((mach_msg_bits_t)bit);
		if (bit_name) {
			kprintf("%s%s", needs_comma ? "," : "", bit_name);
		} else {
			kprintf("%sunknown(0x%x),", needs_comma ? "," : "", bit);
		}
		++needs_comma;
	}
	if (msgh->msgh_bits & ~MACH_MSGH_BITS_USED) {
		kprintf("%sunused=0x%x,", needs_comma ? "," : "",
		    msgh->msgh_bits & ~MACH_MSGH_BITS_USED);
	}
	kprintf("\n");

	needs_comma = 1;
	if (msgh->msgh_remote_port) {
		kprintf("  remote=%p(", msgh->msgh_remote_port);
		ipc_print_type_name64(MACH_MSGH_BITS_REMOTE(msgh->msgh_bits));
		kprintf(")");
	} else {
		kprintf("  remote=null");
	}

	if (msgh->msgh_local_port) {
		kprintf("%slocal=%p(", needs_comma ? "," : "",
		    msgh->msgh_local_port);
		ipc_print_type_name64(MACH_MSGH_BITS_LOCAL(msgh->msgh_bits));
		kprintf(")\n");
	} else {
		kprintf("local=null\n");
	}

	kprintf("  msgh_id=%d, size=%d\n",
	    msgh->msgh_id,
	    msgh->msgh_size);

	if (mbits & MACH_MSGH_BITS_COMPLEX) {
		ipc_msg_print_untyped64((mach_msg_body_t *) (msgh + 1));
	}

	ipc_msg_body_print64((void *)(msgh + 1), msgh->msgh_size);
}


const char *
mm_copy_options_string64(
	mach_msg_copy_options_t option)
{
	const char      *name;

	switch (option) {
	case MACH_MSG_PHYSICAL_COPY:
		name = "PHYSICAL";
		break;
	case MACH_MSG_VIRTUAL_COPY:
		name = "VIRTUAL";
		break;
	case MACH_MSG_OVERWRITE:
		name = "OVERWRITE(DEPRECATED)";
		break;
	case MACH_MSG_ALLOCATE:
		name = "ALLOCATE";
		break;
	case MACH_MSG_KALLOC_COPY_T:
		name = "KALLOC_COPY_T";
		break;
	default:
		name = "unknown";
		break;
	}
	return name;
}

void
ipc_msg_print_untyped64(
	mach_msg_body_t         *body)
{
	mach_msg_descriptor_t       *saddr, *send;
	mach_msg_descriptor_type_t  type;

	kprintf("  %d descriptors: \n", body->msgh_descriptor_count);

	saddr = (mach_msg_descriptor_t *) (body + 1);
	send = saddr + body->msgh_descriptor_count;

	for (; saddr < send; saddr++) {
		type = saddr->type.type;

		switch (type) {
		case MACH_MSG_PORT_DESCRIPTOR: {
			mach_msg_port_descriptor_t *dsc;

			dsc = &saddr->port;
			kprintf("    PORT name = %p disp = ", dsc->name);
			ipc_print_type_name64(dsc->disposition);
			kprintf("\n");
			break;
		}
		case MACH_MSG_OOL_VOLATILE_DESCRIPTOR:
		case MACH_MSG_OOL_DESCRIPTOR: {
			mach_msg_ool_descriptor_t *dsc;

			dsc = (mach_msg_ool_descriptor_t *) &saddr->out_of_line;
			kprintf("    OOL%s addr = %p size = 0x%x copy = %s %s\n",
			    type == MACH_MSG_OOL_DESCRIPTOR ? "" : " VOLATILE",
			    dsc->address, dsc->size,
			    mm_copy_options_string64(dsc->copy),
			    dsc->deallocate ? "DEALLOC" : "");
			break;
		}
		case MACH_MSG_OOL_PORTS_DESCRIPTOR: {
			mach_msg_ool_ports_descriptor_t *dsc;

			dsc = (mach_msg_ool_ports_descriptor_t *) &saddr->ool_ports;

			kprintf("    OOL_PORTS addr = %p count = 0x%x ",
			    dsc->address, dsc->count);
			kprintf("disp = ");
			ipc_print_type_name64(dsc->disposition);
			kprintf(" copy = %s %s\n",
			    mm_copy_options_string64(dsc->copy),
			    dsc->deallocate ? "DEALLOC" : "");
			break;
		}
		case MACH_MSG_GUARDED_PORT_DESCRIPTOR: {
			mach_msg_guarded_port_descriptor_t *dsc;

			dsc = (mach_msg_guarded_port_descriptor_t *)&saddr->guarded_port;
			kprintf("    GUARDED_PORT name = %p flags = 0x%x disp = ", dsc->name, dsc->flags);
			ipc_print_type_name64(dsc->disposition);
			kprintf("\n");
			break;
		}
		default: {
			kprintf("    UNKNOWN DESCRIPTOR 0x%x\n", type);
			break;
		}
		}
	}
}

#define DEBUG_IPC_KMSG_PRINT(kmsg, string)       \
	__unreachable_ok_push   \
	if (DEBUG_KPRINT_SYSCALL_PREDICATE(DEBUG_KPRINT_SYSCALL_IPC_MASK)) {    \
	        ipc_kmsg_print64(kmsg, string); \
	}       \
	__unreachable_ok_pop

#define DEBUG_IPC_MSG_BODY_PRINT(body, size)     \
	__unreachable_ok_push   \
	if (DEBUG_KPRINT_SYSCALL_PREDICATE(DEBUG_KPRINT_SYSCALL_IPC_MASK)) {    \
	        ipc_msg_body_print64(body,size);\
	}       \
	__unreachable_ok_pop
#else /* !DEBUG_MSGS_K64 */
#define DEBUG_IPC_KMSG_PRINT(kmsg, string)
#define DEBUG_IPC_MSG_BODY_PRINT(body, size)
#endif  /* !DEBUG_MSGS_K64 */

extern vm_map_t         ipc_kernel_copy_map;
extern vm_size_t        ipc_kmsg_max_space;
extern const vm_size_t  ipc_kmsg_max_vm_space;
extern const vm_size_t  msg_ool_size_small;

#define MSG_OOL_SIZE_SMALL      msg_ool_size_small

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
#include <stdint.h>

void
ipc_kmsg_trace_send(ipc_kmsg_t kmsg,
    mach_msg_option_t option)
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
		mach_msg_body_t *msg_body;
		mach_msg_descriptor_t *kern_dsc;
		mach_msg_size_t dsc_count;

		msg_flags |= KMSG_TRACE_FLAG_COMPLEX;

		msg_body = (mach_msg_body_t *)(msg + 1);
		dsc_count = msg_body->msgh_descriptor_count;
		kern_dsc = (mach_msg_descriptor_t *)(msg_body + 1);

		for (mach_msg_size_t i = 0; i < dsc_count; i++) {
			switch (kern_dsc[i].type.type) {
			case MACH_MSG_PORT_DESCRIPTOR:
				num_ports++;
				break;
			case MACH_MSG_OOL_VOLATILE_DESCRIPTOR:
			case MACH_MSG_OOL_DESCRIPTOR: {
				mach_msg_ool_descriptor_t *dsc;
				dsc = (mach_msg_ool_descriptor_t *)&kern_dsc[i];
				msg_flags |= KMSG_TRACE_FLAG_OOLMEM;
				msg_size += dsc->size;
				if (dsc->size > MSG_OOL_SIZE_SMALL &&
				    (dsc->copy == MACH_MSG_PHYSICAL_COPY) &&
				    !dsc->deallocate) {
					msg_flags |= KMSG_TRACE_FLAG_PCPY;
				} else if (dsc->size <= MSG_OOL_SIZE_SMALL) {
					msg_flags |= KMSG_TRACE_FLAG_PCPY;
				} else {
					msg_flags |= KMSG_TRACE_FLAG_VCPY;
				}
			} break;
			case MACH_MSG_OOL_PORTS_DESCRIPTOR: {
				mach_msg_ool_ports_descriptor_t *dsc;
				dsc = (mach_msg_ool_ports_descriptor_t *)&kern_dsc[i];
				num_ports += dsc->count;
			} break;
			case MACH_MSG_GUARDED_PORT_DESCRIPTOR:
				num_ports++;
				msg_flags |= KMSG_TRACE_FLAG_GUARDED_DESC;
				break;
			default:
				break;
			}
			msg_size -= ikm_user_desc_size(kern_dsc[i].type.type, is_task_64bit);
		}
	}

	/*
	 * Trailer contents
	 */
	trailer = (mach_msg_trailer_t *)ipc_kmsg_get_trailer(kmsg, false);
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

/* zone for cached ipc_kmsg_t structures */
ZONE_DEFINE(ipc_kmsg_zone, "ipc kmsgs", IKM_SAVED_KMSG_SIZE,
    ZC_CACHING | ZC_ZFREE_CLEARMEM);
static TUNABLE(bool, enforce_strict_reply, "ipc_strict_reply", false);

/*
 * Forward declarations
 */

static void ipc_kmsg_clean(
	ipc_kmsg_t      kmsg);

static void
ipc_kmsg_link_reply_context_locked(
	ipc_port_t reply_port,
	ipc_port_t voucher_port);

static kern_return_t
ipc_kmsg_validate_reply_port_locked(
	ipc_port_t reply_port,
	mach_msg_option_t options);

static mach_msg_return_t
ipc_kmsg_validate_reply_context_locked(
	mach_msg_option_t option,
	ipc_port_t dest_port,
	ipc_voucher_t voucher,
	mach_port_name_t voucher_name);

/* we can't include the BSD <sys/persona.h> header here... */
#ifndef PERSONA_ID_NONE
#define PERSONA_ID_NONE ((uint32_t)-1)
#endif

static inline void *
ikm_inline_data(
	ipc_kmsg_t         kmsg)
{
	return (void *)(kmsg + 1);
}

/* Whether header, body, content and trailer occupy contiguous memory space */
static inline bool
ikm_is_linear(ipc_kmsg_t kmsg)
{
	return kmsg->ikm_type == IKM_TYPE_ALL_INLINED ||
	       kmsg->ikm_type == IKM_TYPE_KDATA_OOL;
}

static inline bool
ikm_header_inlined(ipc_kmsg_t kmsg)
{
	/* ikm_type must not be reordered */
	static_assert(IKM_TYPE_UDATA_OOL == 1);
	static_assert(IKM_TYPE_ALL_INLINED == 0);
	return kmsg->ikm_type <= IKM_TYPE_UDATA_OOL;
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
	mach_msg_size_t desc_count,
	bool            complex)
{
	if (!ikm_is_linear(kmsg)) {
		return kmsg->ikm_udata;
	} else if (complex) {
		return (void *)((vm_offset_t)ikm_header(kmsg) + sizeof(mach_msg_base_t) +
		       desc_count * KERNEL_DESC_SIZE);
	} else {
		return (void *)((vm_offset_t)ikm_header(kmsg) + sizeof(mach_msg_header_t));
	}
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
	mach_msg_header_t *hdr = ikm_header(kmsg);
	bool complex = (hdr->msgh_bits & MACH_MSGH_BITS_COMPLEX);
	mach_msg_size_t desc_count = 0;

	if (complex) {
		desc_count = ((mach_msg_base_t *)hdr)->body.msgh_descriptor_count;
	}

	return ikm_udata(kmsg, desc_count, complex);
}

#if (DEVELOPMENT || DEBUG)
/* Returns end of kdata buffer (may contain extra space) */
vm_offset_t
ikm_kdata_end(ipc_kmsg_t kmsg)
{
	if (ikm_header_inlined(kmsg)) {
		/* round up to total kmsg buffer size */
		return (vm_offset_t)kmsg + IKM_SAVED_KMSG_SIZE;
	} else if (ikm_is_linear(kmsg)) {
		/* round up to total kmsg buffer size */
		ipc_kmsg_vector_t *vec = ikm_inline_data(kmsg);
		return (vm_offset_t)vec->kmsgv_data + vec->kmsgv_size;
	} else {
		assert(kmsg->ikm_type == IKM_TYPE_ALL_OOL);
		ipc_kmsg_vector_t *vec = ikm_inline_data(kmsg);
		return (vm_offset_t)vec->kmsgv_data + sizeof(mach_msg_base_t) +
		       vec->kmsgv_size * KERNEL_DESC_SIZE;
	}
}

/* Returns end of udata buffer (may contain extra space) */
vm_offset_t
ikm_udata_end(ipc_kmsg_t kmsg)
{
	assert(kmsg->ikm_type != IKM_TYPE_ALL_INLINED);
	assert(kmsg->ikm_udata != NULL);

	return (vm_offset_t)kmsg->ikm_udata + kmsg->ikm_udata_size;
}
#endif

/*
 * Returns message header address.
 *
 * /!\ WARNING /!\
 * Need to shift the return value after call to ipc_kmsg_convert_header_to_user().
 */
inline mach_msg_header_t *
ikm_header(
	ipc_kmsg_t         kmsg)
{
	return ikm_header_inlined(kmsg) ? (mach_msg_header_t *)ikm_inline_data(kmsg) :
	       (mach_msg_header_t *)(((ipc_kmsg_vector_t *)ikm_inline_data(kmsg))->kmsgv_data);
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
		return (mach_msg_aux_header_t *)((vm_offset_t)kmsg + IKM_SAVED_KMSG_SIZE -
		       kmsg->ikm_aux_size);
	} else {
		assert(kmsg->ikm_type != IKM_TYPE_KDATA_OOL);
		return (mach_msg_aux_header_t *)((vm_offset_t)kmsg->ikm_udata +
		       kmsg->ikm_udata_size - kmsg->ikm_aux_size);
	}
}

/* Return real size of kmsg aux data */
inline mach_msg_size_t
ipc_kmsg_aux_data_size(
	ipc_kmsg_t         kmsg)
{
	mach_msg_aux_header_t *aux;

	aux = ikm_aux_header(kmsg);
	if (aux == NULL) {
		return 0;
	}

#if (DEVELOPMENT || DEBUG)
	if (kmsg->ikm_type == IKM_TYPE_ALL_INLINED) {
		assert((vm_offset_t)aux + aux->msgdh_size <= (vm_offset_t)kmsg + IKM_SAVED_KMSG_SIZE);
	} else {
		assert((vm_offset_t)aux + aux->msgdh_size <= ikm_udata_end(kmsg));
	}

	assert3u(aux->msgdh_size, <=, kmsg->ikm_aux_size);
	assert3u(aux->msgdh_size, >=, sizeof(mach_msg_aux_header_t));
#endif

	return aux->msgdh_size;
}

void
ipc_kmsg_set_aux_data_header(
	ipc_kmsg_t            kmsg,
	mach_msg_aux_header_t *new_hdr)
{
	mach_msg_aux_header_t *cur_hdr;

	assert3u(new_hdr->msgdh_size, >=, sizeof(mach_msg_aux_header_t));

	cur_hdr = ikm_aux_header(kmsg);
	if (cur_hdr == NULL) {
		return;
	}

	/*
	 * New header size must not exceed the space allocated for aux.
	 */
	assert3u(kmsg->ikm_aux_size, >=, new_hdr->msgdh_size);
	assert3u(kmsg->ikm_aux_size, >=, sizeof(mach_msg_aux_header_t));

	*cur_hdr = *new_hdr;
}

KALLOC_TYPE_VAR_DEFINE(KT_IPC_KMSG_KDATA_OOL,
    mach_msg_base_t, mach_msg_descriptor_t, KT_DEFAULT);

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
	    min_kdata_size, max_udata_size, max_kmsg_and_aux_size;
	ipc_kmsg_t kmsg;

	void *msg_data = NULL, *user_data = NULL;
	zalloc_flags_t alloc_flags = Z_WAITOK;
	ipc_kmsg_type_t kmsg_type;
	ipc_kmsg_vector_t *vec;

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
	} else if (os_mul_overflow(desc_count, USER_DESC_MAX_DELTA, &max_delta)) {
		return IKM_NULL;
	}

	if (os_add3_overflow(kmsg_size, MAX_TRAILER_SIZE, max_delta, &max_kmsg_size)) {
		return IKM_NULL;
	}
	if (os_add_overflow(max_kmsg_size, aux_size, &max_kmsg_and_aux_size)) {
		return IKM_NULL;
	}

	if (flags & IPC_KMSG_ALLOC_ZERO) {
		alloc_flags |= Z_ZERO;
	}
	if (flags & IPC_KMSG_ALLOC_NOFAIL) {
		alloc_flags |= Z_NOFAIL;
	}

	/* First, determine the layout of the kmsg to allocate */
	if (max_kmsg_and_aux_size <= IKM_SAVED_MSG_SIZE) {
		kmsg_type = IKM_TYPE_ALL_INLINED;
		max_udata_size = 0;
		max_kdata_size = 0;
	} else if (flags & IPC_KMSG_ALLOC_SAVED) {
		panic("size too large for the fast kmsg zone (%d)", kmsg_size);
	} else if (flags & IPC_KMSG_ALLOC_LINEAR) {
		kmsg_type = IKM_TYPE_KDATA_OOL;
		/*
		 * Caller sets MACH64_SEND_KOBJECT_CALL or MACH64_SEND_ANY, or that
		 * the call originates from kernel, or it's a mach_msg() call.
		 * In any case, message does not carry aux data.
		 * We have validated mach_msg2() call options in mach_msg2_trap().
		 */
		if (aux_size != 0) {
			panic("non-zero aux size for kmsg type IKM_TYPE_KDATA_OOL.");
		}
		max_udata_size = aux_size;
		max_kdata_size = max_kmsg_size;
	} else {
		/*
		 * If message can be splitted from the middle, IOW does not need to
		 * occupy contiguous memory space, sequester (header + descriptors)
		 * from (content + trailer + aux) for memory security.
		 */
		assert(max_kmsg_and_aux_size > IKM_SAVED_MSG_SIZE);

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
		    KERNEL_DESC_SIZE : MACH_MSG_DESC_MIN_SIZE;
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

		if (max_kdata_size <= IKM_SAVED_MSG_SIZE) {
			max_kdata_size = 0; /* no need to allocate kdata */
			kmsg_type = IKM_TYPE_UDATA_OOL;
		} else {
			kmsg_type = IKM_TYPE_ALL_OOL;
		}
	}

	/* Then, allocate memory for both udata and kdata if needed, as well as kmsg */
	if (max_udata_size > 0) {
		user_data = kalloc_data(max_udata_size, alloc_flags);
		if (user_data == NULL) {
			return IKM_NULL;
		}
	}

	if (max_kdata_size > 0) {
		if (kmsg_type == IKM_TYPE_ALL_OOL) {
			msg_data = kalloc_type(mach_msg_base_t, mach_msg_descriptor_t,
			    desc_count, alloc_flags | Z_SPRAYQTN);
		} else {
			assert(kmsg_type == IKM_TYPE_KDATA_OOL);
			msg_data = ikm_alloc_kdata_ool(max_kdata_size, alloc_flags);
		}

		if (__improbable(msg_data == NULL)) {
			kfree_data(user_data, max_udata_size);
			return IKM_NULL;
		}
	}

	kmsg = zalloc_flags(ipc_kmsg_zone, Z_WAITOK | Z_ZERO | Z_NOFAIL);
	kmsg->ikm_type = kmsg_type;
	kmsg->ikm_aux_size = aux_size;

	/* Finally, set up pointers properly */
	if (user_data) {
		assert(kmsg_type != IKM_TYPE_ALL_INLINED);
		kmsg->ikm_udata = user_data;
		kmsg->ikm_udata_size = max_udata_size; /* buffer size */
	}
	if (msg_data) {
		assert(kmsg_type == IKM_TYPE_ALL_OOL || kmsg_type == IKM_TYPE_KDATA_OOL);
		vec = (ipc_kmsg_vector_t *)ikm_inline_data(kmsg);
		vec->kmsgv_data = msg_data;
		vec->kmsgv_size = (kmsg_type == IKM_TYPE_ALL_OOL) ?
		    desc_count :     /* save descriptor count on kmsgv_size */
		    max_kdata_size;  /* buffer size */
	}

	/* inline kmsg space at least can fit a vector */
	static_assert(IKM_SAVED_MSG_SIZE > sizeof(ipc_kmsg_vector_t));

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
 *	Routine:	ipc_kmsg_free
 *	Purpose:
 *		Free a kernel message (and udata) buffer.  If the kmg is preallocated
 *		to a port, just "put it back (marked unused)."  We have to
 *		do this with the port locked. The port may have its hold
 *		on our message released.  In that case, we have to just
 *		revert the message to a traditional one and free it normally.
 *	Conditions:
 *		Nothing locked.
 */
void
ipc_kmsg_free(
	ipc_kmsg_t      kmsg)
{
	mach_msg_size_t msg_buf_size = 0, udata_buf_size = 0, dsc_count = 0;
	void *msg_buf = NULL, *udata_buf = NULL;
	ipc_kmsg_vector_t *vec = NULL;
	ipc_port_t inuse_port = IP_NULL;
	mach_msg_header_t *hdr;

	assert(!IP_VALID(ipc_kmsg_get_voucher_port(kmsg)));

	KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_FREE) | DBG_FUNC_NONE,
	    VM_KERNEL_ADDRPERM((uintptr_t)kmsg),
	    0, 0, 0, 0);

	switch (kmsg->ikm_type) {
	case IKM_TYPE_ALL_INLINED:
	case IKM_TYPE_UDATA_OOL:
		msg_buf = ikm_inline_data(kmsg);
		msg_buf_size = IKM_SAVED_MSG_SIZE;
		break;
	case IKM_TYPE_KDATA_OOL:
		vec = ikm_inline_data(kmsg);
		msg_buf = vec->kmsgv_data;
		msg_buf_size = vec->kmsgv_size;
		break;
	case IKM_TYPE_ALL_OOL:
		vec = ikm_inline_data(kmsg);
		msg_buf = vec->kmsgv_data;
		dsc_count = vec->kmsgv_size;
		msg_buf_size = sizeof(mach_msg_base_t) + dsc_count * KERNEL_DESC_SIZE;
		break;
	default:
		panic("strange kmsg type");
	}

	hdr = ikm_header(kmsg);
	if ((void *)hdr < msg_buf ||
	    (void *)hdr >= (void *)((uintptr_t)msg_buf + msg_buf_size)) {
		panic("ipc_kmsg_free: invalid kmsg (%p) header", kmsg);
	}

	if (kmsg->ikm_type != IKM_TYPE_ALL_INLINED) {
		udata_buf = kmsg->ikm_udata;
		udata_buf_size = kmsg->ikm_udata_size;
	}

	switch (kmsg->ikm_type) {
	case IKM_TYPE_ALL_INLINED:
		/*
		 * Check to see if the message is bound to the port.
		 * If so, mark it not in use.
		 */
		inuse_port = ikm_prealloc_inuse_port(kmsg);
		if (inuse_port != IP_NULL) {
			ip_mq_lock(inuse_port);
			ikm_prealloc_clear_inuse(kmsg);
			assert(inuse_port->ip_premsg == kmsg);
			assert(IP_PREALLOC(inuse_port));
			ip_mq_unlock(inuse_port);
			ip_release(inuse_port); /* May be last reference */
			return;
		}
		/* all data inlined, nothing to do */
		break;
	case IKM_TYPE_UDATA_OOL:
		assert(udata_buf != NULL);
		kfree_data(udata_buf, udata_buf_size);
		/* kdata is inlined, udata freed */
		break;
	case IKM_TYPE_KDATA_OOL:
		ikm_free_kdata_ool(msg_buf, msg_buf_size);
		assert(udata_buf == NULL);
		assert(udata_buf_size == 0);
		/* kdata freed, no udata */
		break;
	case IKM_TYPE_ALL_OOL:
		kfree_type(mach_msg_base_t, mach_msg_descriptor_t, dsc_count, msg_buf);
		/* kdata freed */
		assert(udata_buf != NULL);
		kfree_data(udata_buf, udata_buf_size);
		/* udata freed */
		break;
	default:
		panic("strange kmsg type");
	}

	zfree(ipc_kmsg_zone, kmsg);
	/* kmsg struct freed */
}


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
		ikm_sign(kmsg);
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
		ikm_validate_sig(kmsg);

		ipc_kmsg_clean(kmsg);
		ipc_kmsg_rmqueue(queue, kmsg);
		ipc_kmsg_free(kmsg);
	}
}

/*
 *	Routine:	ipc_kmsg_clean_body
 *	Purpose:
 *		Cleans the body of a kernel message.
 *		Releases all rights, references, and memory.
 *
 *	Conditions:
 *		No locks held.
 */
static void
ipc_kmsg_clean_body(
	__unused ipc_kmsg_t     kmsg,
	mach_msg_type_number_t  number,
	mach_msg_descriptor_t   *saddr)
{
	mach_msg_type_number_t      i;

	if (number == 0) {
		return;
	}

	for (i = 0; i < number; i++, saddr++) {
		switch (saddr->type.type) {
		case MACH_MSG_PORT_DESCRIPTOR: {
			mach_msg_port_descriptor_t *dsc;

			dsc = &saddr->port;

			/*
			 * Destroy port rights carried in the message
			 */
			if (!IP_VALID(dsc->name)) {
				continue;
			}
			ipc_object_destroy(ip_to_object(dsc->name), dsc->disposition);
			break;
		}
		case MACH_MSG_OOL_VOLATILE_DESCRIPTOR:
		case MACH_MSG_OOL_DESCRIPTOR: {
			mach_msg_ool_descriptor_t *dsc;

			dsc = (mach_msg_ool_descriptor_t *)&saddr->out_of_line;

			/*
			 * Destroy memory carried in the message
			 */
			if (dsc->size == 0) {
				assert(dsc->address == (void *) 0);
			} else {
				vm_map_copy_discard((vm_map_copy_t) dsc->address);
			}
			break;
		}
		case MACH_MSG_OOL_PORTS_DESCRIPTOR: {
			ipc_object_t                    *objects;
			mach_msg_type_number_t          j;
			mach_msg_ool_ports_descriptor_t *dsc;

			dsc = (mach_msg_ool_ports_descriptor_t  *)&saddr->ool_ports;
			objects = (ipc_object_t *) dsc->address;

			if (dsc->count == 0) {
				break;
			}

			assert(objects != (ipc_object_t *) 0);

			/* destroy port rights carried in the message */

			for (j = 0; j < dsc->count; j++) {
				ipc_object_t object = objects[j];

				if (!IO_VALID(object)) {
					continue;
				}

				ipc_object_destroy(object, dsc->disposition);
			}

			/* destroy memory carried in the message */

			assert(dsc->count != 0);

			kfree_type(mach_port_t, dsc->count, dsc->address);
			break;
		}
		case MACH_MSG_GUARDED_PORT_DESCRIPTOR: {
			mach_msg_guarded_port_descriptor_t *dsc = (typeof(dsc)) & saddr->guarded_port;

			/*
			 * Destroy port rights carried in the message
			 */
			if (!IP_VALID(dsc->name)) {
				continue;
			}
			ipc_object_destroy(ip_to_object(dsc->name), dsc->disposition);
			break;
		}
		default:
			panic("invalid descriptor type: (%p: %d)",
			    saddr, saddr->type.type);
		}
	}
}

/*
 *	Routine:	ipc_kmsg_clean_partial
 *	Purpose:
 *		Cleans a partially-acquired kernel message.
 *		number is the index of the type descriptor
 *		in the body of the message that contained the error.
 *		If dolast, the memory and port rights in this last
 *		type spec are also cleaned.  In that case, number
 *		specifies the number of port rights to clean.
 *	Conditions:
 *		Nothing locked.
 */

static void
ipc_kmsg_clean_partial(
	ipc_kmsg_t              kmsg,
	mach_msg_type_number_t  number,
	mach_msg_descriptor_t   *desc,
	vm_offset_t             paddr,
	vm_size_t               length)
{
	ipc_object_t object;
	mach_msg_header_t *hdr = ikm_header(kmsg);
	mach_msg_bits_t mbits = hdr->msgh_bits;

	/* deal with importance chain while we still have dest and voucher references */
	ipc_importance_clean(kmsg);

	object = ip_to_object(hdr->msgh_remote_port);
	assert(IO_VALID(object));
	ipc_object_destroy_dest(object, MACH_MSGH_BITS_REMOTE(mbits));

	object = ip_to_object(hdr->msgh_local_port);
	if (IO_VALID(object)) {
		ipc_object_destroy(object, MACH_MSGH_BITS_LOCAL(mbits));
	}

	object = ip_to_object(ipc_kmsg_get_voucher_port(kmsg));
	if (IO_VALID(object)) {
		assert(MACH_MSGH_BITS_VOUCHER(mbits) == MACH_MSG_TYPE_MOVE_SEND);
		ipc_object_destroy(object, MACH_MSG_TYPE_PORT_SEND);
		ipc_kmsg_clear_voucher_port(kmsg);
	}

	if (paddr) {
		kmem_free(ipc_kernel_copy_map, paddr, length);
	}

	ipc_kmsg_clean_body(kmsg, number, desc);
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
ipc_kmsg_clean(
	ipc_kmsg_t      kmsg)
{
	ipc_object_t object;
	mach_msg_bits_t mbits;
	mach_msg_header_t *hdr;

	/* deal with importance chain while we still have dest and voucher references */
	ipc_importance_clean(kmsg);

	hdr = ikm_header(kmsg);
	mbits = hdr->msgh_bits;
	object = ip_to_object(hdr->msgh_remote_port);
	if (IO_VALID(object)) {
		ipc_object_destroy_dest(object, MACH_MSGH_BITS_REMOTE(mbits));
	}

	object = ip_to_object(hdr->msgh_local_port);
	if (IO_VALID(object)) {
		ipc_object_destroy(object, MACH_MSGH_BITS_LOCAL(mbits));
	}

	object = ip_to_object(ipc_kmsg_get_voucher_port(kmsg));
	if (IO_VALID(object)) {
		assert(MACH_MSGH_BITS_VOUCHER(mbits) == MACH_MSG_TYPE_MOVE_SEND);
		ipc_object_destroy(object, MACH_MSG_TYPE_PORT_SEND);
		ipc_kmsg_clear_voucher_port(kmsg);
	}

	if (mbits & MACH_MSGH_BITS_COMPLEX) {
		mach_msg_body_t *body;

		body = (mach_msg_body_t *) (hdr + 1);
		ipc_kmsg_clean_body(kmsg, body->msgh_descriptor_count,
		    (mach_msg_descriptor_t *)(body + 1));
	}
}

/*
 *	Routine:	ipc_kmsg_set_prealloc
 *	Purpose:
 *		Assign a kmsg as a preallocated message buffer to a port.
 *	Conditions:
 *		port locked.
 */
void
ipc_kmsg_set_prealloc(
	ipc_kmsg_t              kmsg,
	ipc_port_t              port)
{
	assert(kmsg->ikm_prealloc == IP_NULL);
	assert(kmsg->ikm_type == IKM_TYPE_ALL_INLINED);
	kmsg->ikm_prealloc = IP_NULL;

	IP_SET_PREALLOC(port, kmsg);
}

/*
 *	Routine:	ipc_kmsg_too_large
 *	Purpose:
 *		Return true if kmsg is too large to be received:
 *
 *      If MACH64_RCV_LINEAR_VECTOR:
 *          - combined message buffer is not large enough
 *            to fit both the message (plus trailer) and
 *            auxiliary data.
 *      Otherwise:
 *          - message buffer is not large enough
 *          - auxiliary buffer is not large enough:
 *			  (1) kmsg is a vector with aux, but user expects
 *                a scalar kmsg (ith_max_asize is 0)
 *            (2) kmsg is a vector with aux, but user aux
 *                buffer is not large enough.
 */
bool
ipc_kmsg_too_large(
	mach_msg_size_t     msg_size,
	mach_msg_size_t     aux_size,
	mach_msg_option64_t option64,
	mach_msg_size_t     max_msg_size,
	mach_msg_size_t     max_aux_size,
	thread_t            receiver)
{
	mach_msg_size_t tsize = REQUESTED_TRAILER_SIZE(thread_is_64bit_addr(receiver),
	    receiver->ith_option);

	if (max_aux_size != 0) {
		assert(option64 & MACH64_MSG_VECTOR);
	}

	if (option64 & MACH64_RCV_LINEAR_VECTOR) {
		assert(receiver->ith_max_asize == 0);
		assert(receiver->ith_aux_addr == 0);
		assert(option64 & MACH64_MSG_VECTOR);

		if (max_msg_size < msg_size + tsize + aux_size) {
			return true;
		}
	} else {
		if (max_msg_size < msg_size + tsize) {
			return true;
		}

		/*
		 * only return too large if MACH64_MSG_VECTOR.
		 *
		 * silently drop aux data when receiver is not expecting it for compat
		 * reasons.
		 */
		if ((option64 & MACH64_MSG_VECTOR) && max_aux_size < aux_size) {
			return true;
		}
	}

	return false;
}

/*
 *	Routine:	ipc_kmsg_get_body_and_aux_from_user
 *	Purpose:
 *		Copies in user message (and aux) to allocated kernel message buffer.
 *	Conditions:
 *		msg_addr and msg_size must be valid. aux_addr and aux_size can
 *      be NULL if kmsg is not vectorized, or vector kmsg does not carry
 *      auxiliary data.
 *
 *      msg up to sizeof(mach_msg_user_header_t) has been previously copied in,
 *      and number of descriptors has been made known.
 *
 *      kmsg_size already accounts for message header expansion.
 *
 *      if aux_size is not 0, mach_msg_validate_data_vectors() guarantees that
 *      aux_size must be larger than mach_msg_aux_header_t.
 */
static mach_msg_return_t
ipc_kmsg_get_body_and_aux_from_user(
	ipc_kmsg_t             kmsg,
	mach_vm_address_t      msg_addr,
	mach_msg_size_t        kmsg_size,
	mach_vm_address_t      aux_addr,      /* Nullable */
	mach_msg_size_t        aux_size,      /* Nullable */
	mach_msg_size_t        desc_count,
	mach_msg_user_header_t user_header)
{
	mach_msg_header_t *hdr     = ikm_header(kmsg);
	hdr->msgh_size             = kmsg_size;
	hdr->msgh_bits             = user_header.msgh_bits;
	hdr->msgh_remote_port      = CAST_MACH_NAME_TO_PORT(user_header.msgh_remote_port);
	hdr->msgh_local_port       = CAST_MACH_NAME_TO_PORT(user_header.msgh_local_port);
	hdr->msgh_voucher_port     = user_header.msgh_voucher_port;
	hdr->msgh_id               = user_header.msgh_id;

	if (user_header.msgh_bits & MACH_MSGH_BITS_COMPLEX) {
		mach_msg_base_t *kbase = (mach_msg_base_t *)hdr;

		assert(kmsg_size >= sizeof(mach_msg_base_t));
		kbase->body.msgh_descriptor_count = desc_count;

		/* copy in the rest of the message, after user_base */
		if (kmsg_size > sizeof(mach_msg_base_t)) {
			/*
			 * if kmsg is linear, just copyin the remaining msg after base
			 * and we are done. Otherwise, first copyin until the end of descriptors
			 * or the message, whichever comes first.
			 */
			mach_msg_size_t copyin_size = kmsg_size - sizeof(mach_msg_base_t);
			if (!ikm_is_linear(kmsg) && (desc_count * KERNEL_DESC_SIZE < copyin_size)) {
				copyin_size = desc_count * KERNEL_DESC_SIZE;
			}

			assert((vm_offset_t)hdr + sizeof(mach_msg_base_t) +
			    copyin_size <= ikm_kdata_end(kmsg));

			if (copyinmsg(msg_addr + sizeof(mach_msg_user_base_t),
			    (char *)hdr + sizeof(mach_msg_base_t),
			    copyin_size)) {
				return MACH_SEND_INVALID_DATA;
			}

			/*
			 * next, pre-validate the descriptors user claims to have by checking
			 * their size and type, instead of doing it at body copyin time.
			 */
			mach_msg_return_t mr = ikm_check_descriptors(kmsg, current_map(), copyin_size);
			if (mr != MACH_MSG_SUCCESS) {
				return mr;
			}

			/*
			 * for non-linear kmsg, since we have copied in all data that can
			 * possibly be a descriptor and pre-validated them, we can now measure
			 * the actual descriptor size and copyin the remaining user data
			 * following the descriptors, if there is any.
			 */
			if (!ikm_is_linear(kmsg)) {
				mach_msg_size_t dsc_size = ikm_total_desc_size(kmsg, current_map(), 0, 0, true);
				assert(desc_count * KERNEL_DESC_SIZE >= dsc_size);

				/* if there is user data after descriptors, copy it into data heap */
				if (kmsg_size > sizeof(mach_msg_base_t) + dsc_size) {
					copyin_size = kmsg_size - sizeof(mach_msg_base_t) - dsc_size;

					assert(kmsg->ikm_udata != NULL);
					assert((vm_offset_t)kmsg->ikm_udata + copyin_size <= ikm_udata_end(kmsg));
					if (copyinmsg(msg_addr + sizeof(mach_msg_user_base_t) + dsc_size,
					    (char *)kmsg->ikm_udata,
					    copyin_size)) {
						return MACH_SEND_INVALID_DATA;
					}
				}

				/* finally, nil out the extra user data we copied into kdata */
				if (desc_count * KERNEL_DESC_SIZE > dsc_size) {
					bzero((void *)((vm_offset_t)hdr + sizeof(mach_msg_base_t) + dsc_size),
					    desc_count * KERNEL_DESC_SIZE - dsc_size);
				}
			}
		}
	} else {
		assert(desc_count == 0);
		/* copy in the rest of the message, after user_header */
		if (kmsg_size > sizeof(mach_msg_header_t)) {
			char *msg_content = ikm_is_linear(kmsg) ?
			    (char *)hdr + sizeof(mach_msg_header_t) :
			    (char *)kmsg->ikm_udata;

			if (ikm_is_linear(kmsg)) {
				assert((vm_offset_t)hdr + kmsg_size <= ikm_kdata_end(kmsg));
			} else {
				assert((vm_offset_t)kmsg->ikm_udata + kmsg_size - sizeof(mach_msg_header_t) <= ikm_udata_end(kmsg));
			}

			if (copyinmsg(msg_addr + sizeof(mach_msg_user_header_t), msg_content,
			    kmsg_size - sizeof(mach_msg_header_t))) {
				return MACH_SEND_INVALID_DATA;
			}
		}
	}

	if (aux_size > 0) {
		assert(aux_addr != 0);
		mach_msg_aux_header_t *aux_header = ikm_aux_header(kmsg);

		assert(kmsg->ikm_aux_size == aux_size);
		assert(aux_header != NULL);

		/* initialize aux data header */
		aux_header->msgdh_size = aux_size;
		aux_header->msgdh_reserved = 0;

		/* copyin aux data after the header */
		assert(aux_size >= sizeof(mach_msg_aux_header_t));
		if (aux_size > sizeof(mach_msg_aux_header_t)) {
			if (kmsg->ikm_type != IKM_TYPE_ALL_INLINED) {
				assert((vm_offset_t)aux_header + aux_size <= ikm_udata_end(kmsg));
			} else {
				assert((vm_offset_t)aux_header + aux_size <= ikm_kdata_end(kmsg));
			}
			if (copyinmsg(aux_addr + sizeof(mach_msg_aux_header_t),
			    (char *)aux_header + sizeof(mach_msg_aux_header_t),
			    aux_size - sizeof(mach_msg_aux_header_t))) {
				return MACH_SEND_INVALID_DATA;
			}
		}
	}

	return MACH_MSG_SUCCESS;
}

/*
 *	Routine:	ipc_kmsg_get_from_user
 *	Purpose:
 *		Allocates a scalar or vector kernel message buffer.
 *		Copies user message (and optional aux data) to the message buffer.
 *  Conditions:
 *      user_msg_size must have been bound checked. aux_{addr, size} are
 *      0 if not MACH64_MSG_VECTOR.
 *  Returns:
 *      Produces a kmsg reference on success.
 *
 *		MACH_MSG_SUCCESS	Acquired a message buffer.
 *		MACH_SEND_MSG_TOO_SMALL	Message smaller than a header.
 *		MACH_SEND_MSG_TOO_SMALL	Message size not long-word multiple.
 *		MACH_SEND_TOO_LARGE	Message too large to ever be sent.
 *		MACH_SEND_NO_BUFFER	Couldn't allocate a message buffer.
 *		MACH_SEND_INVALID_DATA	Couldn't copy message data.
 */
mach_msg_return_t
ipc_kmsg_get_from_user(
	mach_vm_address_t      msg_addr,
	mach_msg_size_t        user_msg_size,
	mach_vm_address_t      aux_addr,
	mach_msg_size_t        aux_size,
	mach_msg_user_header_t user_header,
	mach_msg_size_t        desc_count,
	mach_msg_option64_t    option64,
	ipc_kmsg_t             *kmsgp)
{
	mach_msg_size_t kmsg_size = 0;
	ipc_kmsg_t kmsg;
	kern_return_t kr;
	ipc_kmsg_alloc_flags_t flags = IPC_KMSG_ALLOC_USER;
	kmsg_size = user_msg_size + USER_HEADER_SIZE_DELTA;

	if (aux_size == 0) {
		assert(aux_addr == 0);
	} else {
		assert(aux_size >= sizeof(mach_msg_aux_header_t));
	}

	if (!(option64 & MACH64_MSG_VECTOR)) {
		assert(aux_addr == 0);
		assert(aux_size == 0);
	}

	/* Keep DriverKit messages linear for now */
	if (option64 & MACH64_SEND_DK_CALL) {
		flags |= IPC_KMSG_ALLOC_LINEAR;
	}

	kmsg = ipc_kmsg_alloc(kmsg_size, aux_size, desc_count, flags);
	/* Can fail if msg size is too large */
	if (kmsg == IKM_NULL) {
		return MACH_SEND_NO_BUFFER;
	}

	kr = ipc_kmsg_get_body_and_aux_from_user(kmsg, msg_addr, kmsg_size,
	    aux_addr, aux_size, desc_count, user_header);
	if (kr != MACH_MSG_SUCCESS) {
		ipc_kmsg_free(kmsg);
		return kr;
	}

	*kmsgp = kmsg;
	return MACH_MSG_SUCCESS;
}

/*
 *	Routine:	ipc_kmsg_get_from_kernel
 *	Purpose:
 *		First checks for a preallocated message
 *		reserved for kernel clients.  If not found or size is too large -
 *		allocates a new kernel message buffer.
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
	mach_msg_header_t       *msg,
	mach_msg_size_t         size, /* can be larger than prealloc space */
	ipc_kmsg_t              *kmsgp)
{
	ipc_kmsg_t        kmsg;
	mach_msg_header_t *hdr;
	void              *udata;

	ipc_port_t        dest_port;
	bool              complex;
	mach_msg_size_t   desc_count, kdata_sz;

	assert(size >= sizeof(mach_msg_header_t));
	assert((size & 3) == 0);

	dest_port = msg->msgh_remote_port; /* Nullable */
	complex = (msg->msgh_bits & MACH_MSGH_BITS_COMPLEX);

	/*
	 * See if the port has a pre-allocated kmsg for kernel
	 * clients.  These are set up for those kernel clients
	 * which cannot afford to wait.
	 */
	if (IP_VALID(dest_port) && IP_PREALLOC(dest_port)) {
		ip_mq_lock(dest_port);

		if (!ip_active(dest_port)) {
			ip_mq_unlock(dest_port);
			return MACH_SEND_NO_BUFFER;
		}

		assert(IP_PREALLOC(dest_port));
		kmsg = dest_port->ip_premsg;

		if (ikm_prealloc_inuse(kmsg)) {
			ip_mq_unlock(dest_port);
			return MACH_SEND_NO_BUFFER;
		}

		assert(kmsg->ikm_type == IKM_TYPE_ALL_INLINED);
		assert(kmsg->ikm_aux_size == 0);

		if (size + MAX_TRAILER_SIZE > IKM_SAVED_MSG_SIZE) {
			ip_mq_unlock(dest_port);
			return MACH_SEND_TOO_LARGE;
		}
		ikm_prealloc_set_inuse(kmsg, dest_port);

		ip_mq_unlock(dest_port);
	} else {
		desc_count = 0;
		kdata_sz = sizeof(mach_msg_header_t);

		if (complex) {
			desc_count = ((mach_msg_base_t *)msg)->body.msgh_descriptor_count;
			kdata_sz = sizeof(mach_msg_base_t) + desc_count * KERNEL_DESC_SIZE;
		}

		assert(size >= kdata_sz);
		if (size < kdata_sz) {
			return MACH_SEND_TOO_LARGE;
		}

		kmsg = ipc_kmsg_alloc(size, 0, desc_count, IPC_KMSG_ALLOC_KERNEL);
		/* kmsg can be non-linear */
	}

	if (kmsg == IKM_NULL) {
		return MACH_SEND_NO_BUFFER;
	}

	hdr = ikm_header(kmsg);
	if (ikm_is_linear(kmsg)) {
		memcpy(hdr, msg, size);
	} else {
		/* copy kdata to kernel allocation chunk */
		memcpy(hdr, msg, kdata_sz);
		/* copy udata to user allocation chunk */
		udata = ikm_udata(kmsg, desc_count, complex);
		memcpy(udata, (char *)msg + kdata_sz, size - kdata_sz);
	}
	hdr->msgh_size = size;

	*kmsgp = kmsg;
	return MACH_MSG_SUCCESS;
}

/*
 *	Routine:	ipc_kmsg_option_check
 *	Purpose:
 *		Check the option passed by mach_msg2 that works with
 *		the passed destination port.
 *	Conditions:
 *		Space locked.
 *	Returns:
 *		MACH_MSG_SUCCESS		On Success.
 *		MACH_SEND_INVALID_OPTIONS	On Failure.
 */
static mach_msg_return_t
ipc_kmsg_option_check(
	ipc_port_t              port,
	mach_msg_option64_t     option64)
{
	if (option64 & MACH64_MACH_MSG2) {
		/*
		 * This is a _user_ message via mach_msg2_trap()。
		 *
		 * To curb kobject port/message queue confusion and improve control flow
		 * integrity, mach_msg2_trap() invocations mandate the use of either
		 * MACH64_SEND_KOBJECT_CALL or MACH64_SEND_MQ_CALL and that the flag
		 * matches the underlying port type. (unless the call is from a simulator,
		 * since old simulators keep using mach_msg() in all cases indiscriminatingly.)
		 *
		 * Since:
		 *     (1) We make sure to always pass either MACH64_SEND_MQ_CALL or
		 *         MACH64_SEND_KOBJECT_CALL bit at all sites outside simulators
		 *         (checked by mach_msg2_trap());
		 *     (2) We checked in mach_msg2_trap() that _exactly_ one of the three bits is set.
		 *
		 * CFI check cannot be bypassed by simply setting MACH64_SEND_ANY.
		 */
#if XNU_TARGET_OS_OSX
		if (option64 & MACH64_SEND_ANY) {
			return MACH_MSG_SUCCESS;
		}
#endif /* XNU_TARGET_OS_OSX */

		if (ip_is_kobject(port)) {
			natural_t kotype = ip_kotype(port);

			if (__improbable(kotype == IKOT_TIMER)) {
				/*
				 * For bincompat, let's still allow user messages to timer port, but
				 * force MACH64_SEND_MQ_CALL flag for memory segregation.
				 */
				if (__improbable(!(option64 & MACH64_SEND_MQ_CALL))) {
					return MACH_SEND_INVALID_OPTIONS;
				}
			} else if (kotype == IKOT_UEXT_OBJECT) {
				if (__improbable(!(option64 & MACH64_SEND_KOBJECT_CALL || option64 & MACH64_SEND_DK_CALL))) {
					return MACH_SEND_INVALID_OPTIONS;
				}
			} else {
				/* Otherwise, caller must set MACH64_SEND_KOBJECT_CALL. */
				if (__improbable(!(option64 & MACH64_SEND_KOBJECT_CALL))) {
					return MACH_SEND_INVALID_OPTIONS;
				}
			}
		}

#if CONFIG_CSR
		if (csr_check(CSR_ALLOW_KERNEL_DEBUGGER) == 0) {
			/*
			 * Allow MACH64_SEND_KOBJECT_CALL flag to message queues when SIP
			 * is off (for Mach-on-Mach emulation). The other direction is still
			 * not allowed (MIG KernelServer assumes a linear kmsg).
			 */
			return MACH_MSG_SUCCESS;
		}
#endif /* CONFIG_CSR */

		/* If destination is a message queue, caller must set MACH64_SEND_MQ_CALL */
		if (__improbable((!ip_is_kobject(port) &&
		    !(option64 & MACH64_SEND_MQ_CALL)))) {
			return MACH_SEND_INVALID_OPTIONS;
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
	mach_msg_option64_t     option64,
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
		option64 &= (~MACH64_SEND_ALWAYS);
		/* Add the timeout flag since the message queue might be full. */
		option64 |= MACH64_SEND_TIMEOUT;
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
	    ((option64 & MACH64_SEND_KERNEL) == 0) &&
	    MACH_MSGH_BITS_REMOTE(hdr->msgh_bits) == MACH_MSG_TYPE_PORT_SEND_ONCE) {
		error = ipc_kmsg_validate_reply_context_locked((mach_msg_option_t)option64,
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
		kmsg = ipc_kobject_server(port, kmsg, (mach_msg_option_t)option64);
		if (kmsg == IKM_NULL) {
			return MACH_MSG_SUCCESS;
		}
		/* reload hdr since kmsg changed */
		hdr = ikm_header(kmsg);

		/* sign the reply message */
		ipc_kmsg_init_trailer(kmsg, TASK_NULL);
		ikm_sign(kmsg);

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
		if (ipc_importance_send(kmsg, (mach_msg_option_t)option64)) {
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
		    (mach_msg_option_t)option64, send_timeout);
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
 *	Routine:	ipc_kmsg_convert_header_to_user
 *	Purpose:
 *		Convert a kmsg header back to user header.
 */
static mach_msg_user_header_t *
ipc_kmsg_convert_header_to_user(
	ipc_kmsg_t              kmsg)
{
	assert(current_task() != kernel_task);
	mach_msg_header_t *hdr = ikm_header(kmsg);

	/* user_header is kernel header shifted in place */
	mach_msg_user_header_t *user_header =
	    (mach_msg_user_header_t *)((vm_offset_t)(hdr) + USER_HEADER_SIZE_DELTA);

	mach_msg_bits_t         bits            = hdr->msgh_bits;
	mach_msg_size_t         kmsg_size       = hdr->msgh_size;
	mach_port_name_t        remote_port     = CAST_MACH_PORT_TO_NAME(hdr->msgh_remote_port);
	mach_port_name_t        local_port      = CAST_MACH_PORT_TO_NAME(hdr->msgh_local_port);
	mach_port_name_t        voucher_port    = hdr->msgh_voucher_port;
	mach_msg_id_t           id              = hdr->msgh_id;

	user_header->msgh_id                    = id;
	user_header->msgh_local_port            = local_port;
	user_header->msgh_remote_port           = remote_port;
	user_header->msgh_voucher_port          = voucher_port;
	user_header->msgh_size                  = kmsg_size - USER_HEADER_SIZE_DELTA;
	user_header->msgh_bits                  = bits;

	return user_header;
}

/*
 *	Routine:	ipc_kmsg_put_vector_to_user
 *	Purpose:
 *		Copies a scalar or vector message buffer to a user message.
 *		Frees the message buffer.
 *	Conditions:
 *		Nothing locked. kmsg is freed upon return.
 *
 *      1. If user has allocated space for aux data, mach_msg_validate_data_vectors
 *      guarantees that rcv_aux_addr is non-zero, and max_aux_size must be at least
 *      sizeof(mach_msg_aux_header_t). In case the kmsg is a scalar or a vector
 *      without auxiliary data, copy out an empty aux header to rcv_aux_addr which
 *      serves as EOF.
 *
 *      2. If kmsg is a vector without aux, copy out the message as if it's scalar
 *
 *      3. If an aux buffer is provided by user, max_aux_size must be large enough
 *      to at least fit the minimum aux header built by msg_receive_error().
 *
 *      4. If MACH64_RCV_LINEAR_VECTOR is set, use rcv_msg_addr as the combined
 *      buffer for message proper and aux data. rcv_aux_addr and max_aux_size
 *      must be passed as zeros and are ignored.
 *
 *  Returns:
 *		MACH_MSG_SUCCESS	    Copied data out of message buffer.
 *		MACH_RCV_INVALID_DATA	Couldn't copy to user message.
 */
static mach_msg_return_t
ipc_kmsg_put_vector_to_user(
	ipc_kmsg_t              kmsg,     /* scalar or vector */
	mach_msg_option64_t     option64,
	mach_vm_address_t       rcv_msg_addr,
	mach_msg_size_t         max_msg_size,
	mach_vm_address_t       rcv_aux_addr,    /* Nullable */
	mach_msg_size_t         max_aux_size,    /* Nullable */
	mach_msg_size_t         trailer_size,
	mach_msg_size_t         *msg_sizep,  /* size of msg copied out */
	mach_msg_size_t         *aux_sizep)  /* size of aux copied out */
{
	mach_msg_size_t cpout_msg_size, cpout_aux_size;
	mach_msg_user_header_t *user_hdr;
	mach_msg_return_t mr = MACH_MSG_SUCCESS;

	DEBUG_IPC_KMSG_PRINT(kmsg, "ipc_kmsg_put_vector_to_user()");

	assert(option64 & MACH64_MSG_VECTOR);
	user_hdr = ipc_kmsg_convert_header_to_user(kmsg);
	/* ikm_header->msgh_size is now user msg size */

	/* msg and aux size might be updated by msg_receive_error() */
	cpout_msg_size = user_hdr->msgh_size + trailer_size;
	cpout_aux_size = ipc_kmsg_aux_data_size(kmsg);

	/*
	 * For ipc_kmsg_put_scalar_to_user() we try to receive up to
	 * msg buffer size for backward-compatibility. (See below).
	 *
	 * For mach_msg2(), we just error out here.
	 */
	if (option64 & MACH64_RCV_LINEAR_VECTOR) {
		if (cpout_msg_size + cpout_aux_size > max_msg_size) {
			mr = MACH_RCV_INVALID_DATA;
			cpout_msg_size = 0;
			cpout_aux_size = 0;
			goto failed;
		}
		assert(rcv_aux_addr == 0);
		assert(max_aux_size == 0);

		if (option64 & MACH64_RCV_STACK) {
			rcv_msg_addr += max_msg_size - cpout_msg_size - cpout_aux_size;
		}
		rcv_aux_addr = rcv_msg_addr + cpout_msg_size;
		max_aux_size = cpout_aux_size;
	} else {
		/*
		 * (81193887) some clients stomp their own stack due to mis-sized
		 * combined send/receives where the receive buffer didn't account
		 * for the trailer size.
		 *
		 * At the very least, avoid smashing their stack.
		 */
		if (cpout_msg_size > max_msg_size) {
			cpout_msg_size = max_msg_size;

			/* just copy out the partial message for compatibility */
			cpout_aux_size = 0;
			goto copyout_msg;
		}

		if (cpout_aux_size > max_aux_size) {
			/*
			 * mach_msg_validate_data_vectors() guarantees
			 * that max_aux_size is at least what msg_receive_error() builds
			 * during MACH_RCV_TOO_LARGE, if an aux buffer is provided.
			 *
			 * So this can only happen if caller is trying to receive a vector
			 * kmsg with aux, but did not provide aux buffer. And we must be
			 * coming from msg_receive_error().
			 */
			assert(rcv_aux_addr == 0);

			/* just copy out the minimal message header and trailer */
			cpout_aux_size = 0;
			goto copyout_msg;
		}
	}

	/*
	 * at this point, we are certain that receiver has enough space for both msg
	 * proper and aux data.
	 */
	assert(max_aux_size >= cpout_aux_size);
	if (option64 & MACH64_RCV_LINEAR_VECTOR) {
		assert(max_msg_size >= cpout_msg_size + cpout_aux_size);
	} else {
		assert(max_msg_size >= cpout_msg_size);
	}

	/* receive the aux data to user space */
	if (cpout_aux_size) {
		mach_msg_aux_header_t *aux_header;

		if ((aux_header = ikm_aux_header(kmsg)) != NULL) {
			/* user expecting aux data, and kmsg has it */
			assert(rcv_aux_addr != 0);
			if (copyoutmsg((const char *)aux_header, rcv_aux_addr, cpout_aux_size)) {
				mr = MACH_RCV_INVALID_DATA;
				cpout_aux_size = 0;
				cpout_msg_size = 0;
				goto failed;
			}
			/* success, copy out the msg next */
			goto copyout_msg;
		}
	}

	/* we only reach here if have not copied out any aux data */
	if (!(option64 & MACH64_RCV_LINEAR_VECTOR) && rcv_aux_addr != 0) {
		/*
		 * If user has a buffer for aux data, at least copy out an empty header
		 * which serves as an EOF. We don't need to do so for linear vector
		 * because it's used in kevent context and we will return cpout_aux_size
		 * as 0 on ext[3] to signify empty aux data.
		 *
		 * See: filt_machportprocess().
		 */
		mach_msg_aux_header_t header = {.msgdh_size = 0};
		cpout_aux_size = sizeof(header);
		assert(max_aux_size >= cpout_aux_size);
		if (copyoutmsg((const char *)&header, rcv_aux_addr, cpout_aux_size)) {
			mr = MACH_RCV_INVALID_DATA;
			cpout_aux_size = 0;
			cpout_msg_size = 0;
			goto failed;
		}
	}

copyout_msg:
	/* receive the message proper to user space */
	if (ikm_is_linear(kmsg)) {
		if (copyoutmsg((const char *)user_hdr, rcv_msg_addr, cpout_msg_size)) {
			mr = MACH_RCV_INVALID_DATA;
			cpout_msg_size = 0;
			goto failed;
		}
	} else {
		mach_msg_size_t kdata_size = ikm_kdata_size(kmsg, current_map(),
		    USER_HEADER_SIZE_DELTA, true);
		mach_msg_size_t udata_size = ikm_content_size(kmsg, current_map(),
		    USER_HEADER_SIZE_DELTA, true) + trailer_size;

		mach_msg_size_t kdata_copyout_size = MIN(kdata_size, cpout_msg_size);
		mach_msg_size_t udata_copyout_size = MIN(udata_size, cpout_msg_size - kdata_copyout_size);

		/* First copy out kdata */
		if (copyoutmsg((const char *)user_hdr, rcv_msg_addr, kdata_copyout_size)) {
			mr = MACH_RCV_INVALID_DATA;
			cpout_msg_size = 0;
			goto failed;
		}

		/* Then copy out udata */
		if (copyoutmsg((const char *)kmsg->ikm_udata, rcv_msg_addr + kdata_copyout_size,
		    udata_copyout_size)) {
			mr = MACH_RCV_INVALID_DATA;
			cpout_msg_size = 0;
			goto failed;
		}
	}

	/* at this point, we have copied out the message proper */
	assert(cpout_msg_size > 0);

failed:

	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_LINK) | DBG_FUNC_NONE,
	    (rcv_msg_addr >= VM_MIN_KERNEL_AND_KEXT_ADDRESS ||
	    rcv_msg_addr + cpout_msg_size >= VM_MIN_KERNEL_AND_KEXT_ADDRESS) ? (uintptr_t)0 : (uintptr_t)rcv_msg_addr,
	    VM_KERNEL_ADDRPERM((uintptr_t)kmsg),
	    1, /* this is on the receive/copyout path */
	    0, 0);

	ipc_kmsg_free(kmsg);

	if (msg_sizep) {
		*msg_sizep = cpout_msg_size;
	}

	if (aux_sizep) {
		*aux_sizep = cpout_aux_size;
	}

	return mr;
}

/*
 *	Routine:	ipc_kmsg_put_scalar_to_user
 *	Purpose:
 *		Copies a scalar message buffer to a user message.
 *		Frees the message buffer.
 *	Conditions:
 *		Nothing locked. kmsg is freed upon return.
 *
 *	Returns:
 *		MACH_MSG_SUCCESS	    Copied data out of message buffer.
 *		MACH_RCV_INVALID_DATA	Couldn't copy to user message.
 */
static mach_msg_return_t
ipc_kmsg_put_scalar_to_user(
	ipc_kmsg_t              kmsg,
	__unused mach_msg_option64_t     option64,
	mach_vm_address_t       rcv_addr,
	mach_msg_size_t         rcv_size,
	mach_msg_size_t         trailer_size,
	mach_msg_size_t         *sizep)  /* size of msg copied out */
{
	mach_msg_size_t copyout_size;
	mach_msg_user_header_t *user_hdr;
	mach_msg_return_t mr = MACH_MSG_SUCCESS;

	DEBUG_IPC_KMSG_PRINT(kmsg, "ipc_kmsg_put_scalar_to_user()");

	assert(!(option64 & MACH64_MSG_VECTOR));
	/* stack-based receive must be vectorized */
	assert(!(option64 & MACH64_RCV_STACK));
	/*
	 * We will reach here in one of the following cases, kmsg size
	 * may have been updated by msg_receive_error();
	 *
	 *	1. kmsg is scalar: OK to copy out as scalar
	 *  2. kmsg is vector without aux: OK to copy out as scalar
	 *  3. kmsg is vector with aux: silently dropping aux data
	 */
	user_hdr = ipc_kmsg_convert_header_to_user(kmsg);
	/* ikm_header->msgh_size is now user msg size */

	copyout_size = user_hdr->msgh_size + trailer_size;

	/*
	 * (81193887) some clients stomp their own stack due to mis-sized
	 * combined send/receives where the receive buffer didn't account
	 * for the trailer size.
	 *
	 * At the very least, avoid smashing their stack.
	 */
	if (copyout_size > rcv_size) {
		copyout_size = rcv_size;
	}

	if (ikm_is_linear(kmsg)) {
		if (copyoutmsg((const char *)user_hdr, rcv_addr, copyout_size)) {
			mr = MACH_RCV_INVALID_DATA;
			copyout_size = 0;
		}
	} else {
		mach_msg_size_t kdata_size = ikm_kdata_size(kmsg, current_map(),
		    USER_HEADER_SIZE_DELTA, true);
		mach_msg_size_t udata_size = ikm_content_size(kmsg, current_map(),
		    USER_HEADER_SIZE_DELTA, true) + trailer_size;

		mach_msg_size_t kdata_copyout_size = MIN(kdata_size, copyout_size);
		mach_msg_size_t udata_copyout_size = MIN(udata_size, copyout_size - kdata_copyout_size);

		/* First copy out kdata */
		if (copyoutmsg((const char *)user_hdr, rcv_addr, kdata_copyout_size)) {
			mr = MACH_RCV_INVALID_DATA;
			copyout_size = 0;
		}

		/* Then copy out udata */
		if (copyoutmsg((const char *)kmsg->ikm_udata, rcv_addr + kdata_copyout_size,
		    udata_copyout_size)) {
			mr = MACH_RCV_INVALID_DATA;
			copyout_size = 0;
		}
	}

	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_LINK) | DBG_FUNC_NONE,
	    (rcv_addr >= VM_MIN_KERNEL_AND_KEXT_ADDRESS ||
	    rcv_addr + copyout_size >= VM_MIN_KERNEL_AND_KEXT_ADDRESS) ? (uintptr_t)0 : (uintptr_t)rcv_addr,
	    VM_KERNEL_ADDRPERM((uintptr_t)kmsg),
	    1, /* this is on the receive/copyout path */
	    0, 0);

	ipc_kmsg_free(kmsg);

	if (sizep) {
		*sizep = copyout_size;
	}
	return mr;
}

/*
 *	Routine:	ipc_kmsg_put_to_user
 *	Purpose:
 *		Copies a scalar or vector message buffer to a user message.
 *		Frees the message buffer.
 *      See comments above ipc_kmsg_put_{scalar, vector}_to_user().
 *	Conditions:
 *		Nothing locked. kmsg is freed upon return.
 *
 *	Returns:
 *		MACH_MSG_SUCCESS	    Copied data out of message buffer.
 *		MACH_RCV_INVALID_DATA	Couldn't copy to user message.
 */
mach_msg_return_t
ipc_kmsg_put_to_user(
	ipc_kmsg_t              kmsg,     /* scalar or vector */
	mach_msg_option64_t     option64,
	mach_vm_address_t       rcv_msg_addr,
	mach_msg_size_t         max_msg_size,
	mach_vm_address_t       rcv_aux_addr,    /* Nullable */
	mach_msg_size_t         max_aux_size,    /* Nullable */
	mach_msg_size_t         trailer_size,
	mach_msg_size_t         *msg_sizep,  /* size of msg copied out */
	mach_msg_size_t         *aux_sizep)  /* size of aux copied out */
{
	mach_msg_return_t mr;

	if (option64 & MACH64_MSG_VECTOR) {
		mr = ipc_kmsg_put_vector_to_user(kmsg, option64, rcv_msg_addr,
		    max_msg_size, rcv_aux_addr, max_aux_size, trailer_size,
		    msg_sizep, aux_sizep);
	} else {
		mr = ipc_kmsg_put_scalar_to_user(kmsg, option64, rcv_msg_addr,
		    max_msg_size, trailer_size, msg_sizep);
		if (mr == MACH_MSG_SUCCESS && aux_sizep != NULL) {
			*aux_sizep = 0;
		}
	}

	/*
	 * During message copyout, MACH_RCV_INVALID_DATA takes precedence
	 * over all other errors. Other error code will be treated as
	 * MACH_MSG_SUCCESS by mach_msg_receive_results().
	 *
	 * See: msg_receive_error().
	 */
	assert(mr == MACH_RCV_INVALID_DATA || mr == MACH_MSG_SUCCESS);
	return mr;
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
	mach_msg_header_t       *msg,
	ipc_kmsg_t              kmsg,
	mach_msg_size_t         rcv_size) /* includes trailer size */
{
	mach_msg_header_t *hdr = ikm_header(kmsg);

	assert(kmsg->ikm_aux_size == 0);
	assert(rcv_size >= hdr->msgh_size);

	if (ikm_is_linear(kmsg)) {
		(void)memcpy((void *)msg, (const void *)hdr, rcv_size);
	} else {
		mach_msg_size_t kdata_size = ikm_kdata_size(kmsg, current_map(), 0, false);

		/* First memcpy kdata */
		assert(rcv_size >= kdata_size);
		(void)memcpy((void *)msg, (const void *)hdr, kdata_size);

		/* Fill the remaining space with udata */
		(void)memcpy((void *)((vm_offset_t)msg + kdata_size),
		    (const void *)kmsg->ikm_udata, rcv_size - kdata_size);
	}

	ipc_kmsg_free(kmsg);
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
	mach_msg_option_t options,
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
ipc_kmsg_validate_reply_port_locked(ipc_port_t reply_port, mach_msg_option_t options)
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
	mach_msg_option_t option,
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
			mach_port_guard_exception(voucher_name, 0,
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
			mach_port_guard_exception(voucher_name, 0,
			    (MPG_FLAGS_STRICT_REPLY_MISMATCHED_PERSONA | ((((uint64_t)persona_id << 32) & MPG_FLAGS_STRICT_REPLY_MASK) | dest_ctx)),
			    kGUARD_EXC_STRICT_REPLY);
		}
		return MACH_SEND_INVALID_CONTEXT;
	}

	return MACH_MSG_SUCCESS;
}


#define moved_provisional_reply_ports() \
	(moved_provisional_reply_port(dest_type, dest_soright) \
	|| moved_provisional_reply_port(reply_type, reply_soright) \
	|| moved_provisional_reply_port(voucher_type, voucher_soright)) \

void
send_prp_telemetry(int msgh_id)
{
	if (csproc_hardened_runtime(current_proc())) {
		stash_reply_port_semantics_violations_telemetry(NULL, MRP_HARDENED_RUNTIME_VIOLATOR, msgh_id);
	} else {
		stash_reply_port_semantics_violations_telemetry(NULL, MRP_3P_VIOLATOR, msgh_id);
	}
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
	mach_msg_header_t *msg = ikm_header(kmsg);
	mach_msg_bits_t mbits = msg->msgh_bits & MACH_MSGH_BITS_USER;
	mach_port_name_t dest_name = CAST_MACH_PORT_TO_NAME(msg->msgh_remote_port);
	mach_port_name_t reply_name = CAST_MACH_PORT_TO_NAME(msg->msgh_local_port);
	mach_port_name_t voucher_name = MACH_PORT_NULL;
	kern_return_t kr;

	mach_msg_type_name_t dest_type = MACH_MSGH_BITS_REMOTE(mbits);
	mach_msg_type_name_t reply_type = MACH_MSGH_BITS_LOCAL(mbits);
	mach_msg_type_name_t voucher_type = MACH_MSGH_BITS_VOUCHER(mbits);
	ipc_object_t dest_port = IO_NULL;
	ipc_object_t reply_port = IO_NULL;
	ipc_port_t dest_soright = IP_NULL;
	ipc_port_t dport = IP_NULL;
	ipc_port_t reply_soright = IP_NULL;
	ipc_port_t voucher_soright = IP_NULL;
	ipc_port_t release_port = IP_NULL;
	ipc_port_t voucher_port = IP_NULL;
	ipc_port_t voucher_release_port = IP_NULL;
	ipc_entry_t dest_entry = IE_NULL;
	ipc_entry_t reply_entry = IE_NULL;
	ipc_entry_t voucher_entry = IE_NULL;
	ipc_object_copyin_flags_t dest_flags = IPC_OBJECT_COPYIN_FLAGS_ALLOW_REPLY_MAKE_SEND_ONCE | IPC_OBJECT_COPYIN_FLAGS_ALLOW_REPLY_MOVE_SEND_ONCE;
	ipc_object_copyin_flags_t reply_flags = IPC_OBJECT_COPYIN_FLAGS_ALLOW_REPLY_MAKE_SEND_ONCE;
	int reply_port_semantics_violation = 0;

	int assertcnt = 0;
	mach_msg_option_t option32 = (mach_msg_option_t)*option64p;
#if IMPORTANCE_INHERITANCE
	boolean_t needboost = FALSE;
#endif /* IMPORTANCE_INHERITANCE */

	if ((mbits != msg->msgh_bits) ||
	    (!MACH_MSG_TYPE_PORT_ANY_SEND(dest_type)) ||
	    ((reply_type == 0) ?
	    (reply_name != MACH_PORT_NULL) :
	    !MACH_MSG_TYPE_PORT_ANY_SEND(reply_type))) {
		return MACH_SEND_INVALID_HEADER;
	}

	if (!MACH_PORT_VALID(dest_name)) {
		return MACH_SEND_INVALID_DEST;
	}

	is_write_lock(space);
	if (!is_active(space)) {
		is_write_unlock(space);
		return MACH_SEND_INVALID_DEST;
	}
	/* space locked and active */

	/*
	 *	If there is a voucher specified, make sure the disposition is
	 *	valid and the entry actually refers to a voucher port.  Don't
	 *	actually copy in until we validate destination and reply.
	 */
	if (voucher_type != MACH_MSGH_BITS_ZERO) {
		voucher_name = msg->msgh_voucher_port;

		if (voucher_name == MACH_PORT_DEAD ||
		    (voucher_type != MACH_MSG_TYPE_MOVE_SEND &&
		    voucher_type != MACH_MSG_TYPE_COPY_SEND)) {
			is_write_unlock(space);
			if ((option32 & MACH_SEND_KERNEL) == 0) {
				mach_port_guard_exception(voucher_name, 0, 0, kGUARD_EXC_SEND_INVALID_VOUCHER);
			}
			return MACH_SEND_INVALID_VOUCHER;
		}

		if (voucher_name != MACH_PORT_NULL) {
			voucher_entry = ipc_entry_lookup(space, voucher_name);
			if (voucher_entry == IE_NULL ||
			    (voucher_entry->ie_bits & MACH_PORT_TYPE_SEND) == 0 ||
			    io_kotype(voucher_entry->ie_object) != IKOT_VOUCHER) {
				is_write_unlock(space);
				if ((option32 & MACH_SEND_KERNEL) == 0) {
					mach_port_guard_exception(voucher_name, 0, 0, kGUARD_EXC_SEND_INVALID_VOUCHER);
				}
				return MACH_SEND_INVALID_VOUCHER;
			}
		} else {
			voucher_type = MACH_MSG_TYPE_MOVE_SEND;
		}
	}

	if (enforce_strict_reply && MACH_SEND_WITH_STRICT_REPLY(option32) &&
	    (!MACH_PORT_VALID(reply_name) ||
	    ((reply_type != MACH_MSG_TYPE_MAKE_SEND_ONCE) && (reply_type != MACH_MSG_TYPE_MOVE_SEND_ONCE))
	    )) {
		/*
		 * The caller cannot enforce a reply context with an invalid
		 * reply port name, or a non-send_once reply disposition.
		 */
		is_write_unlock(space);
		if ((option32 & MACH_SEND_KERNEL) == 0) {
			mach_port_guard_exception(reply_name, 0,
			    (MPG_FLAGS_STRICT_REPLY_INVALID_REPLY_DISP | reply_type),
			    kGUARD_EXC_STRICT_REPLY);
		}
		return MACH_SEND_INVALID_REPLY;
	}

	/*
	 *	Handle combinations of validating destination and reply; along
	 *	with copying in destination, reply, and voucher in an atomic way.
	 */

	if (dest_name == voucher_name) {
		/*
		 *	If the destination name is the same as the voucher name,
		 *	the voucher_entry must already be known.  Either that or
		 *	the destination name is MACH_PORT_NULL (i.e. invalid).
		 */
		dest_entry = voucher_entry;
		if (dest_entry == IE_NULL) {
			goto invalid_dest;
		}

		/*
		 *	Make sure a future copyin of the reply port will succeed.
		 *	Once we start copying in the dest/voucher pair, we can't
		 *	back out.
		 */
		if (MACH_PORT_VALID(reply_name)) {
			assert(reply_type != 0); /* because reply_name not null */

			/* It is just WRONG if dest, voucher, and reply are all the same. */
			if (voucher_name == reply_name) {
				goto invalid_reply;
			}
			reply_entry = ipc_entry_lookup(space, reply_name);
			if (reply_entry == IE_NULL) {
				goto invalid_reply;
			}
			assert(dest_entry != reply_entry); /* names are not equal */
			if (!ipc_right_copyin_check_reply(space, reply_name, reply_entry, reply_type, dest_entry, &reply_port_semantics_violation)) {
				goto invalid_reply;
			}
		}

		/*
		 *	Do the joint copyin of the dest disposition and
		 *	voucher disposition from the one entry/port.  We
		 *	already validated that the voucher copyin would
		 *	succeed (above).  So, any failure in combining
		 *	the copyins can be blamed on the destination.
		 */
		kr = ipc_right_copyin_two(space, dest_name, dest_entry,
		    dest_type, voucher_type, IPC_OBJECT_COPYIN_FLAGS_NONE, IPC_OBJECT_COPYIN_FLAGS_NONE,
		    &dest_port, &dest_soright, &release_port);
		if (kr != KERN_SUCCESS) {
			assert(kr != KERN_INVALID_CAPABILITY);
			goto invalid_dest;
		}
		voucher_port = ip_object_to_port(dest_port);

		/*
		 * could not have been one of these dispositions,
		 * validated the port was a true kernel voucher port above,
		 * AND was successfully able to copyin both dest and voucher.
		 */
		assert(dest_type != MACH_MSG_TYPE_MAKE_SEND);
		assert(dest_type != MACH_MSG_TYPE_MAKE_SEND_ONCE);
		assert(dest_type != MACH_MSG_TYPE_MOVE_SEND_ONCE);

		/*
		 *	Perform the delayed reply right copyin (guaranteed success).
		 */
		if (reply_entry != IE_NULL) {
			kr = ipc_right_copyin(space, reply_name, reply_entry,
			    reply_type, IPC_OBJECT_COPYIN_FLAGS_DEADOK | reply_flags,
			    &reply_port, &reply_soright,
			    &release_port, &assertcnt, 0, NULL);
			assert(assertcnt == 0);
			assert(kr == KERN_SUCCESS);
		}
	} else {
		if (dest_name == reply_name) {
			/*
			 *	Destination and reply ports are the same!
			 *	This is very similar to the case where the
			 *	destination and voucher ports were the same
			 *	(except the reply port disposition is not
			 *	previously validated).
			 */
			dest_entry = ipc_entry_lookup(space, dest_name);
			if (dest_entry == IE_NULL) {
				goto invalid_dest;
			}

			reply_entry = dest_entry;
			assert(reply_type != 0); /* because name not null */

			/*
			 *	Pre-validate that the reply right can be copied in by itself.
			 *  Fail if reply port is marked as immovable send.
			 */
			if (!ipc_right_copyin_check_reply(space, reply_name, reply_entry, reply_type, dest_entry, &reply_port_semantics_violation)) {
				goto invalid_reply;
			}

			/*
			 *	Do the joint copyin of the dest disposition and
			 *	reply disposition from the one entry/port.
			 */
			kr = ipc_right_copyin_two(space, dest_name, dest_entry, dest_type, reply_type,
			    dest_flags, reply_flags, &dest_port, &dest_soright, &release_port);
			if (kr == KERN_INVALID_CAPABILITY) {
				goto invalid_reply;
			} else if (kr != KERN_SUCCESS) {
				goto invalid_dest;
			}
			reply_port = dest_port;
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

			dest_entry = ipc_entry_lookup(space, dest_name);
			if (dest_entry == IE_NULL) {
				goto invalid_dest;
			}
			assert(dest_entry != voucher_entry);

			/*
			 *	Make sure reply port entry is valid before dest copyin.
			 */
			if (MACH_PORT_VALID(reply_name)) {
				if (reply_name == voucher_name) {
					goto invalid_reply;
				}
				reply_entry = ipc_entry_lookup(space, reply_name);
				if (reply_entry == IE_NULL) {
					goto invalid_reply;
				}
				assert(dest_entry != reply_entry); /* names are not equal */
				assert(reply_type != 0); /* because reply_name not null */

				if (!ipc_right_copyin_check_reply(space, reply_name, reply_entry, reply_type, dest_entry, &reply_port_semantics_violation)) {
					goto invalid_reply;
				}
			}

			/*
			 *	copyin the destination.
			 */
			kr = ipc_right_copyin(space, dest_name, dest_entry, dest_type,
			    (IPC_OBJECT_COPYIN_FLAGS_ALLOW_IMMOVABLE_SEND | IPC_OBJECT_COPYIN_FLAGS_ALLOW_DEAD_SEND_ONCE | dest_flags),
			    &dest_port, &dest_soright,
			    &release_port, &assertcnt, 0, NULL);
			assert(assertcnt == 0);
			if (kr != KERN_SUCCESS) {
				goto invalid_dest;
			}
			assert(IO_VALID(dest_port));
			assert(!IP_VALID(release_port));

			/*
			 *	Copyin the pre-validated reply right.
			 *	It's OK if the reply right has gone dead in the meantime.
			 */
			if (MACH_PORT_VALID(reply_name)) {
				kr = ipc_right_copyin(space, reply_name, reply_entry,
				    reply_type, IPC_OBJECT_COPYIN_FLAGS_DEADOK | reply_flags,
				    &reply_port, &reply_soright,
				    &release_port, &assertcnt, 0, NULL);
				assert(assertcnt == 0);
				assert(kr == KERN_SUCCESS);
			} else {
				/* convert invalid name to equivalent ipc_object type */
				reply_port = ip_to_object(CAST_MACH_NAME_TO_PORT(reply_name));
			}
		}

		/*
		 * Finally can copyin the voucher right now that dest and reply
		 * are fully copied in (guaranteed success).
		 */
		if (IE_NULL != voucher_entry) {
			kr = ipc_right_copyin(space, voucher_name, voucher_entry,
			    voucher_type, IPC_OBJECT_COPYIN_FLAGS_NONE,
			    (ipc_object_t *)&voucher_port,
			    &voucher_soright,
			    &voucher_release_port,
			    &assertcnt, 0, NULL);
			assert(assertcnt == 0);
			assert(KERN_SUCCESS == kr);
			assert(IP_VALID(voucher_port));
			require_ip_active(voucher_port);
		}
	}

	dest_type = ipc_object_copyin_type(dest_type);
	reply_type = ipc_object_copyin_type(reply_type);

	dport = ip_object_to_port(dest_port);
	/*
	 *	If the dest port died, or is a kobject AND its receive right belongs to kernel,
	 *  allow copyin of immovable send rights in the message body (port descriptor) to
	 *  succeed since those send rights are simply "moved" or "copied" into kernel.
	 *
	 *  See: ipc_object_copyin().
	 */

	ip_mq_lock(dport);

#if CONFIG_SERVICE_PORT_INFO
	/*
	 * Service name is later used in CA telemetry in case of reply port security semantics violations.
	 */
	mach_service_port_info_t sp_info = NULL;
	struct mach_service_port_info sp_info_filled = {};
	if (ip_active(dport) && (dport->ip_service_port) && (dport->ip_splabel)) {
		ipc_service_port_label_get_info((ipc_service_port_label_t)dport->ip_splabel, &sp_info_filled);
		sp_info = &sp_info_filled;
	}
#endif /* CONFIG_SERVICE_PORT_INFO */

	if (!ip_active(dport) || (ip_is_kobject(dport) &&
	    ip_in_space(dport, ipc_space_kernel))) {
		assert(ip_kotype(dport) != IKOT_TIMER);
		kmsg->ikm_flags |= IPC_OBJECT_COPYIN_FLAGS_ALLOW_IMMOVABLE_SEND;
	}

	/*
	 * JMM - Without rdar://problem/6275821, this is the last place we can
	 * re-arm the send-possible notifications.  It may trigger unexpectedly
	 * early (send may NOT have failed), but better than missing.  We assure
	 * we won't miss by forcing MACH_SEND_ALWAYS if we got past arming.
	 */
	if (((option32 & MACH_SEND_NOTIFY) != 0) &&
	    dest_type != MACH_MSG_TYPE_PORT_SEND_ONCE &&
	    dest_entry != IE_NULL && dest_entry->ie_request != IE_REQ_NONE) {
		/* dport still locked from above */
		if (ip_active(dport) && !ip_in_space(dport, ipc_space_kernel)) {
			/* dport could be in-transit, or in an ipc space */
			if (ip_full(dport)) {
#if IMPORTANCE_INHERITANCE
				needboost = ipc_port_request_sparm(dport, dest_name,
				    dest_entry->ie_request,
				    option32,
				    priority);
				if (needboost == FALSE) {
					ip_mq_unlock(dport);
				}
#else
				ipc_port_request_sparm(dport, dest_name,
				    dest_entry->ie_request,
				    option32,
				    priority);
				ip_mq_unlock(dport);
#endif /* IMPORTANCE_INHERITANCE */
			} else {
				*option64p |= MACH64_SEND_ALWAYS;
				ip_mq_unlock(dport);
			}
		} else {
			ip_mq_unlock(dport);
		}
	} else {
		ip_mq_unlock(dport);
	}
	/* dport is unlocked, unless needboost == TRUE */

	is_write_unlock(space);

#if IMPORTANCE_INHERITANCE
	/*
	 * If our request is the first boosting send-possible
	 * notification this cycle, push the boost down the
	 * destination port.
	 */
	if (needboost == TRUE) {
		/* dport still locked from above */
		if (ipc_port_importance_delta(dport, IPID_OPTION_SENDPOSSIBLE, 1) == FALSE) {
			ip_mq_unlock(dport);
		}
	}
#endif /* IMPORTANCE_INHERITANCE */

	/* dport is unlocked */

	if (dest_soright != IP_NULL) {
		ipc_notify_port_deleted(dest_soright, dest_name);
	}
	if (reply_soright != IP_NULL) {
		ipc_notify_port_deleted(reply_soright, reply_name);
	}
	if (voucher_soright != IP_NULL) {
		ipc_notify_port_deleted(voucher_soright, voucher_name);
	}

	/*
	 * No room to store voucher port in in-kernel msg header,
	 * so we store it back in the kmsg itself. Store original voucher
	 * type there as well, but set the bits to the post-copyin type.
	 */
	if (IP_VALID(voucher_port)) {
		ipc_kmsg_set_voucher_port(kmsg, voucher_port, voucher_type);
		voucher_type = MACH_MSG_TYPE_MOVE_SEND;
	}

	msg->msgh_bits = MACH_MSGH_BITS_SET(dest_type, reply_type, voucher_type, mbits);
	msg->msgh_remote_port = ip_object_to_port(dest_port);
	msg->msgh_local_port = ip_object_to_port(reply_port);

	/*
	 * capture the qos value(s) for the kmsg qos,
	 * and apply any override before we enqueue the kmsg.
	 */
	ipc_kmsg_set_qos(kmsg, option32, priority);

	if (release_port != IP_NULL) {
		ip_release(release_port);
	}

	if (voucher_release_port != IP_NULL) {
		ip_release(voucher_release_port);
	}

	if (ipc_kmsg_option_check(ip_object_to_port(dest_port), *option64p) !=
	    MACH_MSG_SUCCESS) {
		/*
		 * no descriptors have been copied in yet, but the
		 * full header has been copied in: clean it up
		 */
		ipc_kmsg_clean_partial(kmsg, 0, NULL, 0, 0);
		mach_port_guard_exception(0, 0, 0, kGUARD_EXC_INVALID_OPTIONS);
		return MACH_SEND_INVALID_OPTIONS;
	}

	if (enforce_strict_reply && MACH_SEND_WITH_STRICT_REPLY(option32) &&
	    IP_VALID(msg->msgh_local_port)) {
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
		ipc_port_t rport = msg->msgh_local_port;
		ip_mq_lock(rport);
		kr = ipc_kmsg_validate_reply_port_locked(rport, option32);
		ip_mq_unlock(rport);
		if (kr != KERN_SUCCESS) {
			/*
			 * no descriptors have been copied in yet, but the
			 * full header has been copied in: clean it up
			 */
			ipc_kmsg_clean_partial(kmsg, 0, NULL, 0, 0);
			if ((option32 & MACH_SEND_KERNEL) == 0) {
				mach_port_guard_exception(reply_name, 0,
				    (MPG_FLAGS_STRICT_REPLY_INVALID_REPLY_PORT | kr),
				    kGUARD_EXC_STRICT_REPLY);
			}
			return MACH_SEND_INVALID_REPLY;
		}
	}

	if (moved_provisional_reply_ports()) {
		send_prp_telemetry(msg->msgh_id);
	}

	if (reply_port_semantics_violation) {
		/* Currently rate limiting it to sucess paths only. */
		task_t task = current_task_early();
		if (task && reply_port_semantics_violation == REPLY_PORT_SEMANTICS_VIOLATOR) {
			task_lock(task);
			if (!task_has_reply_port_telemetry(task)) {
				/* Crash report rate limited to once per task per host. */
				mach_port_guard_exception(reply_name, 0, 0, kGUARD_EXC_REQUIRE_REPLY_PORT_SEMANTICS);
				task_set_reply_port_telemetry(task);
			}
			task_unlock(task);
		}
#if CONFIG_SERVICE_PORT_INFO
		stash_reply_port_semantics_violations_telemetry(sp_info, reply_port_semantics_violation, msg->msgh_id);
#else
		stash_reply_port_semantics_violations_telemetry(NULL, reply_port_semantics_violation, msg->msgh_id);
#endif
	}
	return MACH_MSG_SUCCESS;

invalid_reply:
	is_write_unlock(space);

	if (release_port != IP_NULL) {
		ip_release(release_port);
	}

	assert(voucher_port == IP_NULL);
	assert(voucher_soright == IP_NULL);

	if ((option32 & MACH_SEND_KERNEL) == 0) {
		mach_port_guard_exception(reply_name, 0, 0, kGUARD_EXC_SEND_INVALID_REPLY);
	}
	return MACH_SEND_INVALID_REPLY;

invalid_dest:
	is_write_unlock(space);

	if (release_port != IP_NULL) {
		ip_release(release_port);
	}

	if (reply_soright != IP_NULL) {
		ipc_notify_port_deleted(reply_soright, reply_name);
	}

	assert(voucher_port == IP_NULL);
	assert(voucher_soright == IP_NULL);

	return MACH_SEND_INVALID_DEST;
}

static mach_msg_descriptor_t *
ipc_kmsg_copyin_port_descriptor(
	mach_msg_port_descriptor_t *dsc,
	mach_msg_user_port_descriptor_t *user_dsc_in,
	ipc_space_t space,
	ipc_object_t dest,
	ipc_kmsg_t kmsg,
	mach_msg_option_t options,
	mach_msg_return_t *mr)
{
	mach_msg_user_port_descriptor_t user_dsc = *user_dsc_in;
	mach_msg_type_name_t        user_disp;
	mach_msg_type_name_t        result_disp;
	mach_port_name_t            name;
	ipc_object_t                object;

	user_disp = user_dsc.disposition;
	result_disp = ipc_object_copyin_type(user_disp);

	name = (mach_port_name_t)user_dsc.name;
	if (MACH_PORT_VALID(name)) {
		kern_return_t kr = ipc_object_copyin(space, name, user_disp, &object, 0, NULL, kmsg->ikm_flags);
		if (kr != KERN_SUCCESS) {
			if (((options & MACH_SEND_KERNEL) == 0) && (kr == KERN_INVALID_RIGHT)) {
				mach_port_guard_exception(name, 0, 0, kGUARD_EXC_SEND_INVALID_RIGHT);
			}
			*mr = MACH_SEND_INVALID_RIGHT;
			return NULL;
		}

		if ((result_disp == MACH_MSG_TYPE_PORT_RECEIVE) &&
		    ipc_port_check_circularity(ip_object_to_port(object),
		    ip_object_to_port(dest))) {
			ikm_header(kmsg)->msgh_bits |= MACH_MSGH_BITS_CIRCULAR;
		}
		dsc->name = ip_object_to_port(object);
	} else {
		dsc->name = CAST_MACH_NAME_TO_PORT(name);
	}
	dsc->disposition = result_disp;
	dsc->type = MACH_MSG_PORT_DESCRIPTOR;

	dsc->pad_end = 0;         // debug, unnecessary

	return (mach_msg_descriptor_t *)(user_dsc_in + 1);
}

static mach_msg_descriptor_t *
ipc_kmsg_copyin_ool_descriptor(
	mach_msg_ool_descriptor_t *dsc,
	mach_msg_descriptor_t *user_dsc,
	int is_64bit,
	mach_vm_address_t *paddr,
	vm_map_copy_t *copy,
	vm_size_t *space_needed,
	vm_map_t map,
	mach_msg_return_t *mr)
{
	vm_size_t                           length;
	boolean_t                           dealloc;
	mach_msg_copy_options_t             copy_options;
	mach_vm_offset_t            addr;
	mach_msg_descriptor_type_t  dsc_type;

	if (is_64bit) {
		mach_msg_ool_descriptor64_t *user_ool_dsc = (typeof(user_ool_dsc))user_dsc;

		addr = (mach_vm_offset_t) user_ool_dsc->address;
		length = user_ool_dsc->size;
		dealloc = user_ool_dsc->deallocate;
		copy_options = user_ool_dsc->copy;
		dsc_type = user_ool_dsc->type;

		user_dsc = (typeof(user_dsc))(user_ool_dsc + 1);
	} else {
		mach_msg_ool_descriptor32_t *user_ool_dsc = (typeof(user_ool_dsc))user_dsc;

		addr = CAST_USER_ADDR_T(user_ool_dsc->address);
		dealloc = user_ool_dsc->deallocate;
		copy_options = user_ool_dsc->copy;
		dsc_type = user_ool_dsc->type;
		length = user_ool_dsc->size;

		user_dsc = (typeof(user_dsc))(user_ool_dsc + 1);
	}

	dsc->size = (mach_msg_size_t)length;
	dsc->deallocate = dealloc;
	dsc->copy = copy_options;
	dsc->type = dsc_type;

	if (length == 0) {
		dsc->address = NULL;
	} else if (length > MSG_OOL_SIZE_SMALL &&
	    (copy_options == MACH_MSG_PHYSICAL_COPY) && !dealloc) {
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
		if (copyin(addr, (char *)*paddr, length)) {
			*mr = MACH_SEND_INVALID_MEMORY;
			return NULL;
		}

		/*
		 * The kernel ipc copy map is marked no_zero_fill.
		 * If the transfer is not a page multiple, we need
		 * to zero fill the balance.
		 */
		if (!page_aligned(length)) {
			(void) memset((void *) (*paddr + length), 0,
			    round_page(length) - length);
		}
		if (vm_map_copyin(ipc_kernel_copy_map, (vm_map_address_t)*paddr,
		    (vm_map_size_t)length, TRUE, copy) != KERN_SUCCESS) {
			*mr = MACH_MSG_VM_KERNEL;
			return NULL;
		}
		dsc->address = (void *)*copy;
		*paddr += round_page(length);
		*space_needed -= round_page(length);
	} else {
		/*
		 * Make a vm_map_copy_t of the of the data.  If the
		 * data is small, this will do an optimized physical
		 * copy.  Otherwise, it will do a virtual copy.
		 *
		 * NOTE: A virtual copy is OK if the original is being
		 * deallocted, even if a physical copy was requested.
		 */
		kern_return_t kr = vm_map_copyin(map, addr,
		    (vm_map_size_t)length, dealloc, copy);
		if (kr != KERN_SUCCESS) {
			*mr = (kr == KERN_RESOURCE_SHORTAGE) ?
			    MACH_MSG_VM_KERNEL :
			    MACH_SEND_INVALID_MEMORY;
			return NULL;
		}
		dsc->address = (void *)*copy;
	}

	return user_dsc;
}

static mach_msg_descriptor_t *
ipc_kmsg_copyin_ool_ports_descriptor(
	mach_msg_ool_ports_descriptor_t *dsc,
	mach_msg_descriptor_t *user_dsc,
	int is_64bit,
	vm_map_t map,
	ipc_space_t space,
	ipc_object_t dest,
	ipc_kmsg_t kmsg,
	mach_msg_option_t options,
	mach_msg_return_t *mr)
{
	void *data;
	ipc_object_t *objects;
	unsigned int i;
	mach_vm_offset_t addr;
	mach_msg_type_name_t user_disp;
	mach_msg_type_name_t result_disp;
	mach_msg_type_number_t count;
	mach_msg_copy_options_t copy_option;
	boolean_t deallocate;
	mach_msg_descriptor_type_t type;
	vm_size_t ports_length, names_length;

	if (is_64bit) {
		mach_msg_ool_ports_descriptor64_t *user_ool_dsc = (typeof(user_ool_dsc))user_dsc;

		addr = (mach_vm_offset_t)user_ool_dsc->address;
		count = user_ool_dsc->count;
		deallocate = user_ool_dsc->deallocate;
		copy_option = user_ool_dsc->copy;
		user_disp = user_ool_dsc->disposition;
		type = user_ool_dsc->type;

		user_dsc = (typeof(user_dsc))(user_ool_dsc + 1);
	} else {
		mach_msg_ool_ports_descriptor32_t *user_ool_dsc = (typeof(user_ool_dsc))user_dsc;

		addr = CAST_USER_ADDR_T(user_ool_dsc->address);
		count = user_ool_dsc->count;
		deallocate = user_ool_dsc->deallocate;
		copy_option = user_ool_dsc->copy;
		user_disp = user_ool_dsc->disposition;
		type = user_ool_dsc->type;

		user_dsc = (typeof(user_dsc))(user_ool_dsc + 1);
	}

	dsc->deallocate = deallocate;
	dsc->copy = copy_option;
	dsc->type = type;
	dsc->count = count;
	dsc->address = NULL; /* for now */

	result_disp = ipc_object_copyin_type(user_disp);
	dsc->disposition = result_disp;

	/* We always do a 'physical copy', but you have to specify something valid */
	if (copy_option != MACH_MSG_PHYSICAL_COPY &&
	    copy_option != MACH_MSG_VIRTUAL_COPY) {
		*mr = MACH_SEND_INVALID_TYPE;
		return NULL;
	}

	/* calculate length of data in bytes, rounding up */

	if (os_mul_overflow(count, sizeof(mach_port_t), &ports_length)) {
		*mr = MACH_SEND_TOO_LARGE;
		return NULL;
	}

	if (os_mul_overflow(count, sizeof(mach_port_name_t), &names_length)) {
		*mr = MACH_SEND_TOO_LARGE;
		return NULL;
	}

	if (ports_length == 0) {
		return user_dsc;
	}

	data = kalloc_type(mach_port_t, count, Z_WAITOK | Z_SPRAYQTN);

	if (data == NULL) {
		*mr = MACH_SEND_NO_BUFFER;
		return NULL;
	}

#ifdef __LP64__
	mach_port_name_t *names = &((mach_port_name_t *)data)[count];
#else
	mach_port_name_t *names = ((mach_port_name_t *)data);
#endif

	if (copyinmap(map, addr, names, names_length) != KERN_SUCCESS) {
		kfree_type(mach_port_t, count, data);
		*mr = MACH_SEND_INVALID_MEMORY;
		return NULL;
	}

	if (deallocate) {
		(void) mach_vm_deallocate(map, addr, (mach_vm_size_t)names_length);
	}

	objects = (ipc_object_t *) data;
	dsc->address = data;

	for (i = 0; i < count; i++) {
		mach_port_name_t name = names[i];
		ipc_object_t object;

		if (!MACH_PORT_VALID(name)) {
			objects[i] = ip_to_object(CAST_MACH_NAME_TO_PORT(name));
			continue;
		}

		kern_return_t kr = ipc_object_copyin(space, name, user_disp, &object, 0, NULL, kmsg->ikm_flags);

		if (kr != KERN_SUCCESS) {
			unsigned int j;

			for (j = 0; j < i; j++) {
				object = objects[j];
				if (IPC_OBJECT_VALID(object)) {
					ipc_object_destroy(object, result_disp);
				}
			}
			kfree_type(mach_port_t, count, data);
			dsc->address = NULL;
			if (((options & MACH_SEND_KERNEL) == 0) && (kr == KERN_INVALID_RIGHT)) {
				mach_port_guard_exception(name, 0, 0, kGUARD_EXC_SEND_INVALID_RIGHT);
			}
			*mr = MACH_SEND_INVALID_RIGHT;
			return NULL;
		}

		if ((dsc->disposition == MACH_MSG_TYPE_PORT_RECEIVE) &&
		    ipc_port_check_circularity(ip_object_to_port(object),
		    ip_object_to_port(dest))) {
			ikm_header(kmsg)->msgh_bits |= MACH_MSGH_BITS_CIRCULAR;
		}

		objects[i] = object;
	}

	return user_dsc;
}

static mach_msg_descriptor_t *
ipc_kmsg_copyin_guarded_port_descriptor(
	mach_msg_guarded_port_descriptor_t *dsc,
	mach_msg_descriptor_t *user_addr,
	int is_64bit,
	ipc_space_t space,
	ipc_object_t dest,
	ipc_kmsg_t kmsg,
	mach_msg_option_t options,
	mach_msg_return_t *mr)
{
	mach_msg_descriptor_t       *user_dsc;
	mach_msg_type_name_t        disp;
	mach_msg_type_name_t        result_disp;
	mach_port_name_t            name;
	mach_msg_guard_flags_t      guard_flags;
	ipc_object_t                object;
	mach_port_context_t         context;

	if (!is_64bit) {
		mach_msg_guarded_port_descriptor32_t *user_gp_dsc = (typeof(user_gp_dsc))user_addr;
		name = user_gp_dsc->name;
		guard_flags = user_gp_dsc->flags;
		disp = user_gp_dsc->disposition;
		context = user_gp_dsc->context;
		user_dsc = (mach_msg_descriptor_t *)(user_gp_dsc + 1);
	} else {
		mach_msg_guarded_port_descriptor64_t *user_gp_dsc = (typeof(user_gp_dsc))user_addr;
		name = user_gp_dsc->name;
		guard_flags = user_gp_dsc->flags;
		disp = user_gp_dsc->disposition;
		context = user_gp_dsc->context;
		user_dsc = (mach_msg_descriptor_t *)(user_gp_dsc + 1);
	}

	guard_flags &= MACH_MSG_GUARD_FLAGS_MASK;
	result_disp = ipc_object_copyin_type(disp);

	if (MACH_PORT_VALID(name)) {
		kern_return_t kr = ipc_object_copyin(space, name, disp, &object, context, &guard_flags, kmsg->ikm_flags);
		if (kr != KERN_SUCCESS) {
			if (((options & MACH_SEND_KERNEL) == 0) && (kr == KERN_INVALID_RIGHT)) {
				mach_port_guard_exception(name, 0, 0, kGUARD_EXC_SEND_INVALID_RIGHT);
			}
			*mr = MACH_SEND_INVALID_RIGHT;
			return NULL;
		}

		if ((result_disp == MACH_MSG_TYPE_PORT_RECEIVE) &&
		    ipc_port_check_circularity(ip_object_to_port(object),
		    ip_object_to_port(dest))) {
			ikm_header(kmsg)->msgh_bits |= MACH_MSGH_BITS_CIRCULAR;
		}
		dsc->name = ip_object_to_port(object);
	} else {
		dsc->name = CAST_MACH_NAME_TO_PORT(name);
	}
	dsc->flags = guard_flags;
	dsc->disposition = result_disp;
	dsc->type = MACH_MSG_GUARDED_PORT_DESCRIPTOR;

#if __LP64__
	dsc->pad_end = 0;         // debug, unnecessary
#endif

	return user_dsc;
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
	ipc_kmsg_t      kmsg,
	ipc_space_t     space,
	vm_map_t        map,
	mach_msg_option_t options)
{
	ipc_object_t                dest;
	mach_msg_body_t             *body;
	mach_msg_descriptor_t       *daddr;
	mach_msg_descriptor_t       *user_addr, *kern_addr;
	mach_msg_type_number_t      dsc_count;
	boolean_t                   is_task_64bit = (map->max_offset > VM_MAX_ADDRESS);
	boolean_t                   contains_port_desc = FALSE;
	vm_size_t                   space_needed = 0;
	mach_vm_address_t           paddr = 0;
	__assert_only vm_offset_t   end;
	vm_map_copy_t               copy = VM_MAP_COPY_NULL;
	mach_msg_return_t           mr = MACH_MSG_SUCCESS;
	mach_msg_header_t           *hdr = ikm_header(kmsg);

	ipc_port_t                  remote_port = hdr->msgh_remote_port;

	vm_size_t           descriptor_size = 0;

	mach_msg_type_number_t total_ool_port_count = 0;
	mach_msg_guard_flags_t guard_flags = 0;
	mach_port_context_t context;
	mach_msg_type_name_t disp;

	/*
	 * Determine if the target is a kernel port.
	 */
	dest = ip_to_object(remote_port);
	body = (mach_msg_body_t *) (hdr + 1);
	daddr = (mach_msg_descriptor_t *) (body + 1);

	dsc_count = body->msgh_descriptor_count;
	if (dsc_count == 0) {
		return MACH_MSG_SUCCESS;
	}

	assert(hdr->msgh_bits & MACH_MSGH_BITS_COMPLEX);
	end = (vm_offset_t)hdr + sizeof(mach_msg_base_t) +
	    dsc_count * KERNEL_DESC_SIZE;

	/*
	 * Make an initial pass to determine kernal VM space requirements for
	 * physical copies and possible contraction of the descriptors from
	 * processes with pointers larger than the kernel's.
	 */
	for (mach_msg_type_number_t i = 0; i < dsc_count; i++) {
		mach_msg_size_t dsize;
		mach_msg_size_t size;
		mach_msg_type_number_t ool_port_count = 0;

		dsize = ikm_user_desc_size(daddr->type.type, is_task_64bit);
		/* descriptor size check has been hoisted to ikm_check_descriptors() */
		assert((vm_offset_t)daddr + dsize <= end);

		switch (daddr->type.type) {
		case MACH_MSG_OOL_DESCRIPTOR:
		case MACH_MSG_OOL_VOLATILE_DESCRIPTOR:
			size = (is_task_64bit) ?
			    ((mach_msg_ool_descriptor64_t *)daddr)->size :
			    daddr->out_of_line.size;

			if (daddr->out_of_line.copy != MACH_MSG_PHYSICAL_COPY &&
			    daddr->out_of_line.copy != MACH_MSG_VIRTUAL_COPY) {
				/*
				 * Invalid copy option
				 */
				mr = MACH_SEND_INVALID_TYPE;
				goto clean_message;
			}

			if (size > MSG_OOL_SIZE_SMALL &&
			    (daddr->out_of_line.copy == MACH_MSG_PHYSICAL_COPY) &&
			    !(daddr->out_of_line.deallocate)) {
				/*
				 * Out-of-line memory descriptor, accumulate kernel
				 * memory requirements
				 */
				if (space_needed + round_page(size) <= space_needed) {
					/* Overflow dectected */
					mr = MACH_MSG_VM_KERNEL;
					goto clean_message;
				}

				space_needed += round_page(size);
				if (space_needed > ipc_kmsg_max_vm_space) {
					/* Per message kernel memory limit exceeded */
					mr = MACH_MSG_VM_KERNEL;
					goto clean_message;
				}
			}
			break;
		case MACH_MSG_PORT_DESCRIPTOR:
			if (os_add_overflow(total_ool_port_count, 1, &total_ool_port_count)) {
				/* Overflow detected */
				mr = MACH_SEND_TOO_LARGE;
				goto clean_message;
			}
			contains_port_desc = TRUE;
			break;
		case MACH_MSG_OOL_PORTS_DESCRIPTOR:
			ool_port_count = (is_task_64bit) ?
			    ((mach_msg_ool_ports_descriptor64_t *)daddr)->count :
			    daddr->ool_ports.count;

			if (os_add_overflow(total_ool_port_count, ool_port_count, &total_ool_port_count)) {
				/* Overflow detected */
				mr = MACH_SEND_TOO_LARGE;
				goto clean_message;
			}

			if (ool_port_count > (ipc_kmsg_max_vm_space / sizeof(mach_port_t))) {
				/* Per message kernel memory limit exceeded */
				mr = MACH_SEND_TOO_LARGE;
				goto clean_message;
			}
			contains_port_desc = TRUE;
			break;
		case MACH_MSG_GUARDED_PORT_DESCRIPTOR:
			guard_flags = (is_task_64bit) ?
			    ((mach_msg_guarded_port_descriptor64_t *)daddr)->flags :
			    ((mach_msg_guarded_port_descriptor32_t *)daddr)->flags;
			context = (is_task_64bit) ?
			    ((mach_msg_guarded_port_descriptor64_t *)daddr)->context :
			    ((mach_msg_guarded_port_descriptor32_t *)daddr)->context;
			disp = (is_task_64bit) ?
			    ((mach_msg_guarded_port_descriptor64_t *)daddr)->disposition :
			    ((mach_msg_guarded_port_descriptor32_t *)daddr)->disposition;

			/* Only MACH_MSG_TYPE_MOVE_RECEIVE is supported for now */
			if (!guard_flags || ((guard_flags & ~MACH_MSG_GUARD_FLAGS_MASK) != 0) ||
			    ((guard_flags & MACH_MSG_GUARD_FLAGS_UNGUARDED_ON_SEND) && (context != 0)) ||
			    (disp != MACH_MSG_TYPE_MOVE_RECEIVE)) {
				/*
				 * Invalid guard flags, context or disposition
				 */
				mr = MACH_SEND_INVALID_TYPE;
				goto clean_message;
			}
			if (os_add_overflow(total_ool_port_count, 1, &total_ool_port_count)) {
				/* Overflow detected */
				mr = MACH_SEND_TOO_LARGE;
				goto clean_message;
			}
			contains_port_desc = TRUE;
			break;
		default:
			/* descriptor type check has been hoisted to ikm_check_descriptors() */
			panic("invalid descriptor type");
		}

		descriptor_size += dsize;
		daddr = (typeof(daddr))((vm_offset_t)daddr + dsize);
	}

	/* Sending more than 16383 rights in one message seems crazy */
	if (total_ool_port_count >= (MACH_PORT_UREFS_MAX / 4)) {
		mr = MACH_SEND_TOO_LARGE;
		goto clean_message;
	}

	/*
	 * Check if dest is a no-grant port; Since this bit is set only on
	 * port construction and cannot be unset later, we can peek at the
	 * bit without paying the cost of locking the port.
	 */
	if (contains_port_desc && remote_port->ip_no_grant) {
		mr = MACH_SEND_NO_GRANT_DEST;
		goto clean_message;
	}

	/*
	 * Allocate space in the pageable kernel ipc copy map for all the
	 * ool data that is to be physically copied.  Map is marked wait for
	 * space.
	 */
	if (space_needed) {
		if (mach_vm_allocate_kernel(ipc_kernel_copy_map, &paddr, space_needed,
		    VM_FLAGS_ANYWHERE, VM_KERN_MEMORY_IPC) != KERN_SUCCESS) {
			mr = MACH_MSG_VM_KERNEL;
			goto clean_message;
		}
	}

	/* kern_addr = just after base as it was copied in */
	kern_addr = (mach_msg_descriptor_t *)((vm_offset_t)hdr +
	    sizeof(mach_msg_base_t));

	/*
	 * Shift memory after mach_msg_base_t to make room for dsc_count * 16bytes
	 * of descriptors on 64 bit kernels
	 */
	vm_offset_t dsc_adjust = KERNEL_DESC_SIZE * dsc_count - descriptor_size;

	if (descriptor_size != KERNEL_DESC_SIZE * dsc_count) {
		if (ikm_is_linear(kmsg)) {
			memmove((char *)(((vm_offset_t)hdr) + sizeof(mach_msg_base_t) + dsc_adjust),
			    (void *)((vm_offset_t)hdr + sizeof(mach_msg_base_t)),
			    hdr->msgh_size - sizeof(mach_msg_base_t));
		} else {
			/* just memmove the descriptors following the header */
			memmove((char *)(((vm_offset_t)hdr) + sizeof(mach_msg_base_t) + dsc_adjust),
			    (void *)((vm_offset_t)hdr + sizeof(mach_msg_base_t)),
			    ikm_total_desc_size(kmsg, current_map(), 0, 0, true));
		}

		/* Update the message size for the larger in-kernel representation */
		hdr->msgh_size += (mach_msg_size_t)dsc_adjust;
	}


	/* user_addr = just after base after it has been (conditionally) moved */
	user_addr = (mach_msg_descriptor_t *)((vm_offset_t)hdr +
	    sizeof(mach_msg_base_t) + dsc_adjust);

	/*
	 * Receive right of a libxpc connection port is moved as a part of kmsg's body
	 * 1. from a client to a service during connection etsablishment.
	 * 2. back to the client on service's death or port deallocation.
	 *
	 * Any other attempt to move this receive right is not allowed.
	 */
	kmsg->ikm_flags |= IPC_OBJECT_COPYIN_FLAGS_ALLOW_CONN_IMMOVABLE_RECEIVE;

	/* handle the OOL regions and port descriptors. */
	for (mach_msg_type_number_t copied_in_dscs = 0;
	    copied_in_dscs < dsc_count; copied_in_dscs++) {
		switch (user_addr->type.type) {
		case MACH_MSG_PORT_DESCRIPTOR:
			user_addr = ipc_kmsg_copyin_port_descriptor((mach_msg_port_descriptor_t *)kern_addr,
			    (mach_msg_user_port_descriptor_t *)user_addr, space, dest, kmsg, options, &mr);
			kern_addr++;
			break;
		case MACH_MSG_OOL_VOLATILE_DESCRIPTOR:
		case MACH_MSG_OOL_DESCRIPTOR:
			user_addr = ipc_kmsg_copyin_ool_descriptor((mach_msg_ool_descriptor_t *)kern_addr,
			    user_addr, is_task_64bit, &paddr, &copy, &space_needed, map, &mr);
			kern_addr++;
			break;
		case MACH_MSG_OOL_PORTS_DESCRIPTOR:
			user_addr = ipc_kmsg_copyin_ool_ports_descriptor((mach_msg_ool_ports_descriptor_t *)kern_addr,
			    user_addr, is_task_64bit, map, space, dest, kmsg, options, &mr);
			kern_addr++;
			break;
		case MACH_MSG_GUARDED_PORT_DESCRIPTOR:
			user_addr = ipc_kmsg_copyin_guarded_port_descriptor((mach_msg_guarded_port_descriptor_t *)kern_addr,
			    user_addr, is_task_64bit, space, dest, kmsg, options, &mr);
			kern_addr++;
			break;
		default:
			panic("invalid descriptor type %d", user_addr->type.type);
		}

		if (MACH_MSG_SUCCESS != mr) {
			/* clean from start of message descriptors to copied_in_dscs */
			ipc_kmsg_clean_partial(kmsg, copied_in_dscs,
			    (mach_msg_descriptor_t *)((mach_msg_base_t *)hdr + 1),
			    paddr, space_needed);
			goto out;
		}
	} /* End of loop */

out:
	return mr;

clean_message:
	/* no descriptors have been copied in yet */
	ipc_kmsg_clean_partial(kmsg, 0, NULL, 0, 0);
	return mr;
}

#define MACH_BOOTSTRAP_PORT_MSG_ID_MASK ((1ul << 24) - 1)

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
	ipc_space_t             space,
	vm_map_t                map,
	mach_msg_priority_t     priority,
	mach_msg_option64_t     *option64p,
	bool                    filter_nonfatal)
{
	mach_msg_return_t           mr;
	mach_msg_header_t           *hdr = ikm_header(kmsg);
	mach_port_name_t dest_name = CAST_MACH_PORT_TO_NAME(hdr->msgh_remote_port);

	hdr->msgh_bits &= MACH_MSGH_BITS_USER;

	mr = ipc_kmsg_copyin_header(kmsg, space, priority, option64p);
	/* copyin_header may add MACH64_SEND_ALWAYS option */

	if (mr != MACH_MSG_SUCCESS) {
		return mr;
	}

	/* Get the message filter policy if the task and port support filtering */
	mach_msg_filter_id fid = 0;
	mach_port_t remote_port = hdr->msgh_remote_port;
	mach_msg_id_t msg_id = hdr->msgh_id;
	void * sblabel = NULL;

	if (mach_msg_filter_at_least(MACH_MSG_FILTER_CALLBACKS_VERSION_1) &&
	    task_get_filter_msg_flag(current_task()) &&
	    ip_enforce_msg_filtering(remote_port)) {
		ip_mq_lock(remote_port);
		if (ip_active(remote_port)) {
			if (remote_port->ip_service_port) {
				ipc_service_port_label_t label = remote_port->ip_splabel;
				sblabel = label->ispl_sblabel;
				if (label && ipc_service_port_label_is_bootstrap_port(label)) {
					/*
					 * Mask the top byte for messages sent to launchd's bootstrap port.
					 * Filter any messages with domain 0 (as they correspond to MIG
					 * based messages)
					 */
					unsigned msg_protocol = msg_id & ~MACH_BOOTSTRAP_PORT_MSG_ID_MASK;
					if (!msg_protocol) {
						ip_mq_unlock(remote_port);
						goto filtered_msg;
					}
					msg_id = msg_id & MACH_BOOTSTRAP_PORT_MSG_ID_MASK;
				}
			} else {
				assert(!ip_is_kolabeled(remote_port));
				/* Connection ports can also have send-side message filters */
				sblabel = remote_port->ip_splabel;
			}
			if (sblabel) {
				mach_msg_filter_retain_sblabel_callback(sblabel);
			}
		}
		ip_mq_unlock(remote_port);

		if (sblabel && !mach_msg_fetch_filter_policy(sblabel, msg_id, &fid)) {
			goto filtered_msg;
		}
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
		mr = ipc_kmsg_copyin_body(kmsg, space, map, (mach_msg_option_t)*option64p);
	}

	/* Sign the message contents */
	if (mr == MACH_MSG_SUCCESS) {
		ipc_kmsg_init_trailer(kmsg, current_task());
		ikm_sign(kmsg);
	}

	return mr;

filtered_msg:
	if (!filter_nonfatal) {
		mach_port_guard_exception(dest_name, 0, 0, kGUARD_EXC_MSG_FILTERED);
	}
	/* no descriptors have been copied in yet */
	ipc_kmsg_clean_partial(kmsg, 0, NULL, 0, 0);
	return MACH_SEND_MSG_FILTERED;
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
	mach_msg_header_t *hdr = ikm_header(kmsg);
	mach_msg_bits_t bits = hdr->msgh_bits;
	mach_msg_type_name_t rname = MACH_MSGH_BITS_REMOTE(bits);
	mach_msg_type_name_t lname = MACH_MSGH_BITS_LOCAL(bits);
	mach_msg_type_name_t vname = MACH_MSGH_BITS_VOUCHER(bits);
	ipc_object_t remote = ip_to_object(hdr->msgh_remote_port);
	ipc_object_t local = ip_to_object(hdr->msgh_local_port);
	ipc_object_t voucher = ip_to_object(ipc_kmsg_get_voucher_port(kmsg));
	ipc_port_t dest = hdr->msgh_remote_port;

	/* translate the destination and reply ports */
	if (!IO_VALID(remote)) {
		return MACH_SEND_INVALID_DEST;
	}

	ipc_object_copyin_from_kernel(remote, rname);
	if (IO_VALID(local)) {
		ipc_object_copyin_from_kernel(local, lname);
	}

	if (IO_VALID(voucher)) {
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

	if (bits & MACH_MSGH_BITS_COMPLEX) {
		/*
		 * Check if the remote port accepts ports in the body.
		 */
		if (dest->ip_no_grant) {
			mach_msg_descriptor_t   *saddr;
			mach_msg_body_t         *body;
			mach_msg_type_number_t  i, count;

			body = (mach_msg_body_t *) (hdr + 1);
			saddr = (mach_msg_descriptor_t *) (body + 1);
			count = body->msgh_descriptor_count;

			for (i = 0; i < count; i++, saddr++) {
				switch (saddr->type.type) {
				case MACH_MSG_PORT_DESCRIPTOR:
				case MACH_MSG_OOL_PORTS_DESCRIPTOR:
				case MACH_MSG_GUARDED_PORT_DESCRIPTOR:
					/* no descriptors have been copied in yet */
					ipc_kmsg_clean_partial(kmsg, 0, NULL, 0, 0);
					return MACH_SEND_NO_GRANT_DEST;
				}
			}
		}

		mach_msg_descriptor_t   *saddr;
		mach_msg_body_t         *body;
		mach_msg_type_number_t  i, count;

		body = (mach_msg_body_t *) (hdr + 1);
		saddr = (mach_msg_descriptor_t *) (body + 1);
		count = body->msgh_descriptor_count;

		for (i = 0; i < count; i++, saddr++) {
			switch (saddr->type.type) {
			case MACH_MSG_PORT_DESCRIPTOR: {
				mach_msg_type_name_t        name;
				ipc_object_t                object;
				mach_msg_port_descriptor_t  *dsc;

				dsc = &saddr->port;

				/* this is really the type SEND, SEND_ONCE, etc. */
				name = dsc->disposition;
				object = ip_to_object(dsc->name);
				dsc->disposition = ipc_object_copyin_type(name);

				if (!IO_VALID(object)) {
					break;
				}

				ipc_object_copyin_from_kernel(object, name);

				/* CDY avoid circularity when the destination is also */
				/* the kernel.  This check should be changed into an  */
				/* assert when the new kobject model is in place since*/
				/* ports will not be used in kernel to kernel chats   */

				/* do not lock remote port, use raw pointer comparison */
				if (!ip_in_space_noauth(ip_object_to_port(remote), ipc_space_kernel)) {
					/* remote port could be dead, in-transit or in an ipc space */
					if ((dsc->disposition == MACH_MSG_TYPE_PORT_RECEIVE) &&
					    ipc_port_check_circularity(ip_object_to_port(object),
					    ip_object_to_port(remote))) {
						hdr->msgh_bits |= MACH_MSGH_BITS_CIRCULAR;
					}
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
				ipc_object_t                        *objects;
				unsigned int                        j;
				mach_msg_type_name_t                name;
				mach_msg_ool_ports_descriptor_t     *dsc;

				dsc = (mach_msg_ool_ports_descriptor_t *)&saddr->ool_ports;

				/* this is really the type SEND, SEND_ONCE, etc. */
				name = dsc->disposition;
				dsc->disposition = ipc_object_copyin_type(name);

				objects = (ipc_object_t *) dsc->address;

				for (j = 0; j < dsc->count; j++) {
					ipc_object_t object = objects[j];

					if (!IO_VALID(object)) {
						continue;
					}

					ipc_object_copyin_from_kernel(object, name);

					if ((dsc->disposition == MACH_MSG_TYPE_PORT_RECEIVE) &&
					    ipc_port_check_circularity(ip_object_to_port(object),
					    ip_object_to_port(remote))) {
						hdr->msgh_bits |= MACH_MSGH_BITS_CIRCULAR;
					}
				}
				break;
			}
			case MACH_MSG_GUARDED_PORT_DESCRIPTOR: {
				mach_msg_guarded_port_descriptor_t *dsc = (typeof(dsc)) & saddr->guarded_port;
				mach_msg_type_name_t disp = dsc->disposition;
				ipc_object_t object = ip_to_object(dsc->name);
				dsc->disposition = ipc_object_copyin_type(disp);
				assert(dsc->flags == 0);

				if (!IO_VALID(object)) {
					break;
				}

				ipc_object_copyin_from_kernel(object, disp);
				/*
				 * avoid circularity when the destination is also
				 * the kernel.  This check should be changed into an
				 * assert when the new kobject model is in place since
				 * ports will not be used in kernel to kernel chats
				 */

				/* do not lock remote port, use raw pointer comparison */
				if (!ip_in_space_noauth(ip_object_to_port(remote), ipc_space_kernel)) {
					/* remote port could be dead, in-transit or in an ipc space */
					if ((dsc->disposition == MACH_MSG_TYPE_PORT_RECEIVE) &&
					    ipc_port_check_circularity(ip_object_to_port(object),
					    ip_object_to_port(remote))) {
						hdr->msgh_bits |= MACH_MSGH_BITS_CIRCULAR;
					}
				}
				break;
			}
			default: {
#if     MACH_ASSERT
				panic("ipc_kmsg_copyin_from_kernel:  bad descriptor");
#endif  /* MACH_ASSERT */
			}
			}
		}
	}

	/* Add trailer and signature to the message */
	ipc_kmsg_init_trailer(kmsg, TASK_NULL);
	ikm_sign(kmsg);

	return MACH_MSG_SUCCESS;
}

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
	ipc_space_t             space,
	mach_msg_option_t       option)
{
	mach_msg_header_t *msg = ikm_header(kmsg);
	mach_msg_bits_t mbits = msg->msgh_bits;
	ipc_port_t dest = msg->msgh_remote_port;

	assert(IP_VALID(dest));

	/*
	 * While we still hold a reference on the received-from port,
	 * process all send-possible notfications we received along with
	 * the message.
	 */
	ipc_port_spnotify(dest);

	{
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

				ip_mq_lock(reply);

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
				    ipc_right_reverse(space, ip_to_object(reply), &reply_name, &entry)) {
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

				kr = ipc_right_copyout(space, reply_name, entry,
				    reply_type, IPC_OBJECT_COPYOUT_FLAGS_NONE, NULL, NULL,
				    ip_to_object(reply));
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

					ip_mq_lock(voucher);

					if (ipc_right_reverse(space, ip_to_object(voucher),
					    &voucher_name, &entry)) {
						assert(entry->ie_bits & MACH_PORT_TYPE_SEND);
					} else {
						assert(entries_held > 0);
						entries_held--;
						ipc_entry_claim(space, ip_to_object(voucher), &voucher_name, &entry);
					}
					/* space is locked and active */

					assert(ip_kotype(voucher) == IKOT_VOUCHER);
					kr = ipc_right_copyout(space, voucher_name, entry,
					    MACH_MSG_TYPE_MOVE_SEND, IPC_OBJECT_COPYOUT_FLAGS_NONE,
					    NULL, NULL, ip_to_object(voucher));
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
			ipc_object_copyout_dest(space, ip_to_object(dest),
			    dest_type, &dest_name);
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
	}

	return MACH_MSG_SUCCESS;
}

/*
 *	Routine:	ipc_kmsg_copyout_object
 *	Purpose:
 *		Copy-out a port right.  Always returns a name,
 *		even for unsuccessful return codes.  Always
 *		consumes the supplied object.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		MACH_MSG_SUCCESS	The space acquired the right
 *			(name is valid) or the object is dead (MACH_PORT_DEAD).
 *		MACH_MSG_IPC_SPACE	No room in space for the right,
 *			or the space is dead.  (Name is MACH_PORT_NULL.)
 *		MACH_MSG_IPC_KERNEL	Kernel resource shortage.
 *			(Name is MACH_PORT_NULL.)
 */
static mach_msg_return_t
ipc_kmsg_copyout_object(
	ipc_space_t             space,
	ipc_object_t            object,
	mach_msg_type_name_t    msgt_name,
	mach_port_context_t     *context,
	mach_msg_guard_flags_t  *guard_flags,
	mach_port_name_t        *namep)
{
	kern_return_t kr;

	if (!IO_VALID(object)) {
		*namep = CAST_MACH_PORT_TO_NAME(object);
		return MACH_MSG_SUCCESS;
	}

	kr = ipc_object_copyout(space, object, msgt_name, IPC_OBJECT_COPYOUT_FLAGS_NONE,
	    context, guard_flags, namep);
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
 *	Routine:	ipc_kmsg_copyout_reply_object
 *	Purpose:
 *      Kernel swallows the send-once right associated with reply port.
 *      Always returns a name, even for unsuccessful return codes.
 *      Returns
 *          MACH_MSG_SUCCESS Returns name of receive right for reply port.
 *              Name is valid if the space acquired the right and msgt_name would be changed from MOVE_SO to MAKE_SO.
 *              Name is MACH_PORT_DEAD if the object is dead.
 *              Name is MACH_PORT_NULL if its entry could not be found in task's ipc space.
 *          MACH_MSG_IPC_SPACE
 *              The space is dead.  (Name is MACH_PORT_NULL.)
 *	Conditions:
 *      Nothing locked.
 */
static mach_msg_return_t
ipc_kmsg_copyout_reply_object(
	ipc_space_t             space,
	ipc_object_t            object,
	mach_msg_type_name_t    *msgt_name,
	mach_port_name_t        *namep)
{
	ipc_port_t port;
	ipc_entry_t entry;
	kern_return_t kr;

	if (!IO_VALID(object)) {
		*namep = CAST_MACH_PORT_TO_NAME(object);
		return MACH_MSG_SUCCESS;
	}

	port = ip_object_to_port(object);

	assert(ip_is_reply_port(port));
	assert(*msgt_name == MACH_MSG_TYPE_PORT_SEND_ONCE);

	is_write_lock(space);

	if (!is_active(space)) {
		ipc_port_release_sonce(port);
		is_write_unlock(space);
		*namep = MACH_PORT_NULL;
		return MACH_MSG_IPC_SPACE;
	}

	io_lock(object);

	if (!io_active(object)) {
		*namep = MACH_PORT_DEAD;
		kr = MACH_MSG_SUCCESS;
		goto out;
	}

	/* space is locked and active. object is locked and active. */
	if (!ipc_right_reverse(space, object, namep, &entry)) {
		*namep = MACH_PORT_NULL;
		kr = MACH_MSG_SUCCESS;
		goto out;
	}

	assert(entry->ie_bits & MACH_PORT_TYPE_RECEIVE);

	*msgt_name = MACH_MSG_TYPE_MAKE_SEND_ONCE;
	ipc_port_release_sonce_and_unlock(port);
	/* object is unlocked. */

	is_write_unlock(space);

	return MACH_MSG_SUCCESS;

out:

	/* space and object are locked. */
	ipc_port_release_sonce_and_unlock(port);

	is_write_unlock(space);

	return kr;
}

static mach_msg_descriptor_t *
ipc_kmsg_copyout_port_descriptor(
	mach_msg_descriptor_t   *dsc,
	mach_msg_descriptor_t   *dest_dsc,
	ipc_space_t             space,
	kern_return_t           *mr)
{
	mach_msg_user_port_descriptor_t *user_dsc;
	mach_port_t             port;
	mach_port_name_t        name;
	mach_msg_type_name_t    disp;

	/* Copyout port right carried in the message */
	port = dsc->port.name;
	disp = dsc->port.disposition;
	*mr |= ipc_kmsg_copyout_object(space,
	    ip_to_object(port), disp, NULL, NULL, &name);

	// point to the start of this port descriptor
	user_dsc = ((mach_msg_user_port_descriptor_t *)dest_dsc - 1);
	bzero((void *)user_dsc, sizeof(*user_dsc));
	user_dsc->name = CAST_MACH_PORT_TO_NAME(name);
	user_dsc->disposition = disp;
	user_dsc->type = MACH_MSG_PORT_DESCRIPTOR;

	return (mach_msg_descriptor_t *)user_dsc;
}

extern char *proc_best_name(struct proc *proc);
static mach_msg_descriptor_t *
ipc_kmsg_copyout_ool_descriptor(
	mach_msg_ool_descriptor_t   *dsc,
	mach_msg_descriptor_t       *user_dsc,
	int                         is_64bit,
	vm_map_t                    map,
	mach_msg_return_t           *mr)
{
	vm_map_copy_t               copy;
	vm_map_address_t            rcv_addr;
	mach_msg_copy_options_t     copy_options;
	vm_map_size_t               size;
	mach_msg_descriptor_type_t  dsc_type;
	boolean_t                   misaligned = FALSE;

	copy = (vm_map_copy_t)dsc->address;
	size = (vm_map_size_t)dsc->size;
	copy_options = dsc->copy;
	assert(copy_options != MACH_MSG_KALLOC_COPY_T);
	dsc_type = dsc->type;

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

			kr = mach_vm_allocate_kernel(map, &rounded_addr,
			    rounded_size, VM_FLAGS_ANYWHERE, VM_MEMORY_MACH_MSG);

			if (kr == KERN_SUCCESS) {
				/*
				 * vm_map_copy_overwrite does a full copy
				 * if size is too small to optimize.
				 * So we tried skipping the offset adjustment
				 * if we fail the 'size' test.
				 *
				 * if (size >= VM_MAP_COPY_OVERWRITE_OPTIMIZATION_THRESHOLD_PAGES * effective_page_size) {
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
				*mr |= MACH_MSG_VM_KERNEL;
			} else {
				*mr |= MACH_MSG_VM_SPACE;
			}
			vm_map_copy_discard(copy);
			rcv_addr = 0;
			size = 0;
		}
	} else {
		rcv_addr = 0;
		size = 0;
	}

	/*
	 * Now update the descriptor as the user would see it.
	 * This may require expanding the descriptor to the user
	 * visible size.  There is already space allocated for
	 * this in what naddr points to.
	 */
	if (is_64bit) {
		mach_msg_ool_descriptor64_t *user_ool_dsc = (typeof(user_ool_dsc))user_dsc;
		user_ool_dsc--;
		bzero((void *)user_ool_dsc, sizeof(*user_ool_dsc));

		user_ool_dsc->address = rcv_addr;
		user_ool_dsc->deallocate = (copy_options == MACH_MSG_VIRTUAL_COPY) ?
		    TRUE : FALSE;
		user_ool_dsc->copy = copy_options;
		user_ool_dsc->type = dsc_type;
		user_ool_dsc->size = (mach_msg_size_t)size;

		user_dsc = (typeof(user_dsc))user_ool_dsc;
	} else {
		mach_msg_ool_descriptor32_t *user_ool_dsc = (typeof(user_ool_dsc))user_dsc;
		user_ool_dsc--;
		bzero((void *)user_ool_dsc, sizeof(*user_ool_dsc));

		user_ool_dsc->address = CAST_DOWN_EXPLICIT(uint32_t, rcv_addr);
		user_ool_dsc->size = (mach_msg_size_t)size;
		user_ool_dsc->deallocate = (copy_options == MACH_MSG_VIRTUAL_COPY) ?
		    TRUE : FALSE;
		user_ool_dsc->copy = copy_options;
		user_ool_dsc->type = dsc_type;

		user_dsc = (typeof(user_dsc))user_ool_dsc;
	}
	return user_dsc;
}

static mach_msg_descriptor_t *
ipc_kmsg_copyout_ool_ports_descriptor(mach_msg_ool_ports_descriptor_t *dsc,
    mach_msg_descriptor_t *user_dsc,
    int is_64bit,
    vm_map_t map,
    ipc_space_t space,
    ipc_kmsg_t kmsg,
    mach_msg_return_t *mr)
{
	mach_vm_offset_t        rcv_addr = 0;
	mach_msg_type_name_t    disp;
	mach_msg_type_number_t  count, i;
	vm_size_t               ports_length, names_length;
	mach_msg_copy_options_t copy_options = MACH_MSG_VIRTUAL_COPY;

	count = dsc->count;
	disp = dsc->disposition;
	ports_length = count * sizeof(mach_port_t);
	names_length = count * sizeof(mach_port_name_t);

	if (ports_length != 0 && dsc->address != 0) {
		if (copy_options == MACH_MSG_VIRTUAL_COPY) {
			/*
			 * Dynamically allocate the region
			 */
			vm_tag_t tag;
			if (vm_kernel_map_is_kernel(map)) {
				tag = VM_KERN_MEMORY_IPC;
			} else {
				tag = VM_MEMORY_MACH_MSG;
			}

			kern_return_t kr;
			if ((kr = mach_vm_allocate_kernel(map, &rcv_addr,
			    (mach_vm_size_t)names_length,
			    VM_FLAGS_ANYWHERE, tag)) != KERN_SUCCESS) {
				ipc_kmsg_clean_body(kmsg, 1, (mach_msg_descriptor_t *)dsc);
				rcv_addr = 0;

				if (kr == KERN_RESOURCE_SHORTAGE) {
					*mr |= MACH_MSG_VM_KERNEL;
				} else {
					*mr |= MACH_MSG_VM_SPACE;
				}
			}
		}

		/*
		 * Handle the port rights and copy out the names
		 * for those rights out to user-space.
		 */
		if (rcv_addr != 0) {
			ipc_object_t *objects = (ipc_object_t *) dsc->address;
			mach_port_name_t *names = (mach_port_name_t *) dsc->address;

			/* copyout port rights carried in the message */

			for (i = 0; i < count; i++) {
				ipc_object_t object = objects[i];

				*mr |= ipc_kmsg_copyout_object(space, object,
				    disp, NULL, NULL, &names[i]);
			}

			/* copyout to memory allocated above */
			void *data = dsc->address;
			if (copyoutmap(map, data, rcv_addr, names_length) != KERN_SUCCESS) {
				*mr |= MACH_MSG_VM_SPACE;
			}
			kfree_type(mach_port_t, count, data);
		}
	} else {
		rcv_addr = 0;
	}

	/*
	 * Now update the descriptor based on the information
	 * calculated above.
	 */
	if (is_64bit) {
		mach_msg_ool_ports_descriptor64_t *user_ool_dsc = (typeof(user_ool_dsc))user_dsc;
		user_ool_dsc--;
		bzero((void *)user_ool_dsc, sizeof(*user_ool_dsc));

		user_ool_dsc->address = rcv_addr;
		user_ool_dsc->deallocate = (copy_options == MACH_MSG_VIRTUAL_COPY) ?
		    TRUE : FALSE;
		user_ool_dsc->copy = copy_options;
		user_ool_dsc->disposition = disp;
		user_ool_dsc->type = MACH_MSG_OOL_PORTS_DESCRIPTOR;
		user_ool_dsc->count = count;

		user_dsc = (typeof(user_dsc))user_ool_dsc;
	} else {
		mach_msg_ool_ports_descriptor32_t *user_ool_dsc = (typeof(user_ool_dsc))user_dsc;
		user_ool_dsc--;
		bzero((void *)user_ool_dsc, sizeof(*user_ool_dsc));

		user_ool_dsc->address = CAST_DOWN_EXPLICIT(uint32_t, rcv_addr);
		user_ool_dsc->count = count;
		user_ool_dsc->deallocate = (copy_options == MACH_MSG_VIRTUAL_COPY) ?
		    TRUE : FALSE;
		user_ool_dsc->copy = copy_options;
		user_ool_dsc->disposition = disp;
		user_ool_dsc->type = MACH_MSG_OOL_PORTS_DESCRIPTOR;

		user_dsc = (typeof(user_dsc))user_ool_dsc;
	}
	return user_dsc;
}

static mach_msg_descriptor_t *
ipc_kmsg_copyout_guarded_port_descriptor(
	mach_msg_guarded_port_descriptor_t *dsc,
	mach_msg_descriptor_t *dest_dsc,
	int is_64bit,
	__unused ipc_kmsg_t  kmsg,
	ipc_space_t space,
	mach_msg_option_t option,
	kern_return_t *mr)
{
	mach_port_t                 port;
	mach_port_name_t            name = MACH_PORT_NULL;
	mach_msg_type_name_t        disp;
	mach_msg_guard_flags_t      guard_flags;
	mach_port_context_t         context;

	/* Copyout port right carried in the message */
	port = dsc->name;
	disp = dsc->disposition;
	guard_flags = dsc->flags;
	context = 0;

	/* Currently kernel_task doesnt support receiving guarded port descriptors */
	struct knote *kn = current_thread()->ith_knote;
	if ((kn != ITH_KNOTE_PSEUDO) && ((option & MACH_RCV_GUARDED_DESC) == 0)) {
#if DEVELOPMENT || DEBUG
		/*
		 * Simulated crash needed for debugging, notifies the receiver to opt into receiving
		 * guarded descriptors.
		 */
		mach_port_guard_exception(current_thread()->ith_receiver_name,
		    0, 0, kGUARD_EXC_RCV_GUARDED_DESC);
#endif
		KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_DESTROY_GUARDED_DESC), current_thread()->ith_receiver_name,
		    VM_KERNEL_ADDRPERM(port), disp, guard_flags);
		ipc_object_destroy(ip_to_object(port), disp);
		mach_msg_user_port_descriptor_t *user_dsc = (typeof(user_dsc))dest_dsc;
		user_dsc--;         // point to the start of this port descriptor
		bzero((void *)user_dsc, sizeof(*user_dsc));
		user_dsc->name = name;
		user_dsc->disposition = disp;
		user_dsc->type = MACH_MSG_PORT_DESCRIPTOR;
		dest_dsc = (typeof(dest_dsc))user_dsc;
	} else {
		*mr |= ipc_kmsg_copyout_object(space,
		    ip_to_object(port), disp, &context, &guard_flags, &name);

		if (!is_64bit) {
			mach_msg_guarded_port_descriptor32_t *user_dsc = (typeof(user_dsc))dest_dsc;
			user_dsc--;         // point to the start of this port descriptor
			bzero((void *)user_dsc, sizeof(*user_dsc));
			user_dsc->name = name;
			user_dsc->flags = guard_flags;
			user_dsc->disposition = disp;
			user_dsc->type = MACH_MSG_GUARDED_PORT_DESCRIPTOR;
			user_dsc->context = CAST_DOWN_EXPLICIT(uint32_t, context);
			dest_dsc = (typeof(dest_dsc))user_dsc;
		} else {
			mach_msg_guarded_port_descriptor64_t *user_dsc = (typeof(user_dsc))dest_dsc;
			user_dsc--;         // point to the start of this port descriptor
			bzero((void *)user_dsc, sizeof(*user_dsc));
			user_dsc->name = name;
			user_dsc->flags = guard_flags;
			user_dsc->disposition = disp;
			user_dsc->type = MACH_MSG_GUARDED_PORT_DESCRIPTOR;
			user_dsc->context = context;
			dest_dsc = (typeof(dest_dsc))user_dsc;
		}
	}

	return (mach_msg_descriptor_t *)dest_dsc;
}


/*
 *	Routine:	ipc_kmsg_copyout_body
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
ipc_kmsg_copyout_body(
	ipc_kmsg_t              kmsg,
	ipc_space_t             space,
	vm_map_t                map,
	mach_msg_option_t       option)
{
	mach_msg_body_t             *body;
	mach_msg_descriptor_t       *kern_dsc, *user_dsc;
	mach_msg_type_number_t      dsc_count;
	mach_msg_return_t           mr = MACH_MSG_SUCCESS;
	boolean_t                   is_task_64bit = (map->max_offset > VM_MAX_ADDRESS);
	mach_msg_header_t           *hdr = ikm_header(kmsg);

	body = (mach_msg_body_t *) (hdr + 1);
	dsc_count = body->msgh_descriptor_count;
	kern_dsc = (mach_msg_descriptor_t *) (body + 1);
	/* Point user_dsc just after the end of all the descriptors */
	user_dsc = &kern_dsc[dsc_count];

	assert(current_task() != kernel_task);

	/* Now process the descriptors - in reverse order */
	for (mach_msg_type_number_t i = dsc_count; i-- > 0;) {
		switch (kern_dsc[i].type.type) {
		case MACH_MSG_PORT_DESCRIPTOR:
			user_dsc = ipc_kmsg_copyout_port_descriptor(&kern_dsc[i],
			    user_dsc, space, &mr);
			break;
		case MACH_MSG_OOL_VOLATILE_DESCRIPTOR:
		case MACH_MSG_OOL_DESCRIPTOR:
			user_dsc = ipc_kmsg_copyout_ool_descriptor(
				(mach_msg_ool_descriptor_t *)&kern_dsc[i],
				user_dsc, is_task_64bit, map, &mr);
			break;
		case MACH_MSG_OOL_PORTS_DESCRIPTOR:
			user_dsc = ipc_kmsg_copyout_ool_ports_descriptor(
				(mach_msg_ool_ports_descriptor_t *)&kern_dsc[i],
				user_dsc, is_task_64bit, map, space, kmsg, &mr);
			break;
		case MACH_MSG_GUARDED_PORT_DESCRIPTOR:
			user_dsc = ipc_kmsg_copyout_guarded_port_descriptor(
				(mach_msg_guarded_port_descriptor_t *)&kern_dsc[i],
				user_dsc, is_task_64bit, kmsg, space, option, &mr);
			break;
		default:
			panic("untyped IPC copyout body: invalid message descriptor");
		}
	}

	assert((vm_offset_t)kern_dsc == (vm_offset_t)hdr + sizeof(mach_msg_base_t));

	if (user_dsc != kern_dsc) {
		vm_offset_t dsc_adjust = (vm_offset_t)user_dsc - (vm_offset_t)kern_dsc;
		/* update the message size for the smaller user representation */
		hdr->msgh_size -= (mach_msg_size_t)dsc_adjust;

		if (ikm_is_linear(kmsg)) {
			/* trailer has been initialized during send - memmove it too. */
			memmove((char *)kern_dsc,
			    user_dsc, hdr->msgh_size - sizeof(mach_msg_base_t) + MAX_TRAILER_SIZE);
		} else {
			/* just memmove the descriptors following the header */
			memmove((char *)kern_dsc,
			    user_dsc, ikm_total_desc_size(kmsg, current_map(), dsc_adjust, 0, true));
		}
	}

	return mr;
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
	mach_msg_size_t         send_size;
	mach_msg_header_t       *hdr;

	hdr = ikm_header(kmsg);
	send_size = hdr->msgh_size - USER_HEADER_SIZE_DELTA;

	boolean_t is_task_64bit = (map->max_offset > VM_MAX_ADDRESS);

	if (hdr->msgh_bits & MACH_MSGH_BITS_COMPLEX) {
		mach_msg_body_t *body;
		mach_msg_descriptor_t *saddr, *eaddr;

		body = (mach_msg_body_t *) (hdr + 1);
		saddr = (mach_msg_descriptor_t *) (body + 1);
		eaddr = saddr + body->msgh_descriptor_count;

		send_size -= KERNEL_DESC_SIZE * body->msgh_descriptor_count;
		for (; saddr < eaddr; saddr++) {
			send_size += ikm_user_desc_size(saddr->type.type, is_task_64bit);
		}
	}
	return send_size;
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
	mach_msg_option_t      option)
{
	mach_msg_return_t mr;

	ikm_validate_sig(kmsg);

	mr = ipc_kmsg_copyout_header(kmsg, space, option);
	if (mr != MACH_MSG_SUCCESS) {
		return mr;
	}

	if (ikm_header(kmsg)->msgh_bits & MACH_MSGH_BITS_COMPLEX) {
		mr = ipc_kmsg_copyout_body(kmsg, space, map, option);

		if (mr != MACH_MSG_SUCCESS) {
			mr |= MACH_RCV_BODY_ERROR;
		}
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
	ipc_object_t dest = ip_to_object(hdr->msgh_remote_port);
	ipc_object_t reply = ip_to_object(hdr->msgh_local_port);
	ipc_object_t voucher = ip_to_object(ipc_kmsg_get_voucher_port(kmsg));
	mach_msg_type_name_t dest_type = MACH_MSGH_BITS_REMOTE(mbits);
	mach_msg_type_name_t reply_type = MACH_MSGH_BITS_LOCAL(mbits);
	mach_msg_type_name_t voucher_type = MACH_MSGH_BITS_VOUCHER(mbits);
	mach_port_name_t voucher_name = hdr->msgh_voucher_port;
	mach_port_name_t dest_name, reply_name;
	mach_msg_return_t mr;

	/* Set ith_knote to ITH_KNOTE_PSEUDO */
	current_thread()->ith_knote = ITH_KNOTE_PSEUDO;

	ikm_validate_sig(kmsg);

	assert(IO_VALID(dest));

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

	mr = ipc_kmsg_copyout_object(space, dest, dest_type, NULL, NULL, &dest_name);

	if (!IO_VALID(reply)) {
		reply_name = CAST_MACH_PORT_TO_NAME(reply);
	} else if (ip_is_reply_port(ip_object_to_port(reply))) {
		mach_msg_return_t reply_mr;
		reply_mr = ipc_kmsg_copyout_reply_object(space, reply, &reply_type, &reply_name);
		mr = mr | reply_mr;
		if (reply_mr == MACH_MSG_SUCCESS) {
			mbits = MACH_MSGH_BITS_SET(dest_type, reply_type, voucher_type, MACH_MSGH_BITS_OTHER(mbits));
		}
	} else {
		mr = mr | ipc_kmsg_copyout_object(space, reply, reply_type, NULL, NULL, &reply_name);
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
	if (IO_VALID(voucher)) {
		assert(voucher_type == MACH_MSG_TYPE_MOVE_SEND);
		if (kmsg->ikm_voucher_type == MACH_MSG_TYPE_MOVE_SEND) {
			mr |= ipc_kmsg_copyout_object(space, voucher, voucher_type, NULL, NULL, &voucher_name);
			hdr->msgh_voucher_port = voucher_name;
		} else {
			assert(kmsg->ikm_voucher_type == MACH_MSG_TYPE_COPY_SEND);
			hdr->msgh_bits = MACH_MSGH_BITS_SET(dest_type, reply_type, MACH_MSG_TYPE_COPY_SEND,
			    MACH_MSGH_BITS_OTHER(hdr->msgh_bits));
			ipc_object_destroy(voucher, voucher_type);
		}
		ipc_kmsg_clear_voucher_port(kmsg);
	}

	if (mbits & MACH_MSGH_BITS_COMPLEX) {
		mr |= ipc_kmsg_copyout_body(kmsg, space, map, 0);
	}

	current_thread()->ith_knote = ITH_KNOTE_NULL;

	return mr;
}

/*
 *	Routine:	ipc_kmsg_copyout_dest_to_user
 *	Purpose:
 *		Copies out the destination port in the message.
 *		Destroys all other rights and memory in the message.
 *	Conditions:
 *		Nothing locked.
 */

void
ipc_kmsg_copyout_dest_to_user(
	ipc_kmsg_t      kmsg,
	ipc_space_t     space)
{
	mach_msg_bits_t mbits;
	ipc_object_t dest;
	ipc_object_t reply;
	ipc_object_t voucher;
	mach_msg_type_name_t dest_type;
	mach_msg_type_name_t reply_type;
	mach_msg_type_name_t voucher_type;
	mach_port_name_t dest_name, reply_name, voucher_name;
	mach_msg_header_t *hdr;

	ikm_validate_sig(kmsg);

	hdr = ikm_header(kmsg);
	mbits = hdr->msgh_bits;
	dest = ip_to_object(hdr->msgh_remote_port);
	reply = ip_to_object(hdr->msgh_local_port);
	voucher = ip_to_object(ipc_kmsg_get_voucher_port(kmsg));
	voucher_name = hdr->msgh_voucher_port;
	dest_type = MACH_MSGH_BITS_REMOTE(mbits);
	reply_type = MACH_MSGH_BITS_LOCAL(mbits);
	voucher_type = MACH_MSGH_BITS_VOUCHER(mbits);

	assert(IO_VALID(dest));

	ipc_importance_assert_clean(kmsg);

	io_lock(dest);
	if (io_active(dest)) {
		ipc_object_copyout_dest(space, dest, dest_type, &dest_name);
		/* dest is unlocked */
	} else {
		io_unlock(dest);
		io_release(dest);
		dest_name = MACH_PORT_DEAD;
	}

	if (IO_VALID(reply)) {
		ipc_object_destroy(reply, reply_type);
		reply_name = MACH_PORT_NULL;
	} else {
		reply_name = CAST_MACH_PORT_TO_NAME(reply);
	}

	if (IO_VALID(voucher)) {
		assert(voucher_type == MACH_MSG_TYPE_MOVE_SEND);
		ipc_object_destroy(voucher, voucher_type);
		ipc_kmsg_clear_voucher_port(kmsg);
		voucher_name = MACH_PORT_NULL;
	}

	hdr->msgh_bits = MACH_MSGH_BITS_SET(reply_type, dest_type,
	    voucher_type, mbits);
	hdr->msgh_local_port = CAST_MACH_NAME_TO_PORT(dest_name);
	hdr->msgh_remote_port = CAST_MACH_NAME_TO_PORT(reply_name);
	hdr->msgh_voucher_port = voucher_name;

	if (mbits & MACH_MSGH_BITS_COMPLEX) {
		mach_msg_body_t *body;

		body = (mach_msg_body_t *) (hdr + 1);
		ipc_kmsg_clean_body(kmsg, body->msgh_descriptor_count,
		    (mach_msg_descriptor_t *)(body + 1));
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
	ipc_object_t dest;
	mach_port_t reply;
	mach_msg_type_name_t dest_type;
	mach_msg_type_name_t reply_type;
	mach_port_name_t dest_name;
	mach_msg_header_t *hdr;

	ikm_validate_sig(kmsg);

	hdr = ikm_header(kmsg);
	dest = ip_to_object(hdr->msgh_remote_port);
	reply = hdr->msgh_local_port;
	dest_type = MACH_MSGH_BITS_REMOTE(hdr->msgh_bits);
	reply_type = MACH_MSGH_BITS_LOCAL(hdr->msgh_bits);

	assert(IO_VALID(dest));

	io_lock(dest);
	if (io_active(dest)) {
		ipc_object_copyout_dest(space, dest, dest_type, &dest_name);
		/* dest is unlocked */
	} else {
		io_unlock(dest);
		io_release(dest);
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

#ifdef __arm64__
/*
 * Just sets those parts of the trailer that aren't set up at allocation time.
 */
static void
ipc_kmsg_munge_trailer(mach_msg_max_trailer_t *in, void *_out, boolean_t is64bit)
{
	if (is64bit) {
		mach_msg_max_trailer64_t *out = (mach_msg_max_trailer64_t*)_out;
		out->msgh_seqno = in->msgh_seqno;
		out->msgh_context = in->msgh_context;
		out->msgh_trailer_size = in->msgh_trailer_size;
		out->msgh_ad = in->msgh_ad;
	} else {
		mach_msg_max_trailer32_t *out = (mach_msg_max_trailer32_t*)_out;
		out->msgh_seqno = in->msgh_seqno;
		out->msgh_context = (mach_port_context32_t)in->msgh_context;
		out->msgh_trailer_size = in->msgh_trailer_size;
		out->msgh_ad = in->msgh_ad;
	}
}
#endif /* __arm64__ */

mach_msg_trailer_size_t
ipc_kmsg_trailer_size(
	mach_msg_option_t option,
	__unused thread_t thread)
{
	if (!(option & MACH_RCV_TRAILER_MASK)) {
		return MACH_MSG_TRAILER_MINIMUM_SIZE;
	} else {
		return REQUESTED_TRAILER_SIZE(thread_is_64bit_addr(thread), option);
	}
}

/*
 *	Routine:	ipc_kmsg_init_trailer
 *	Purpose:
 *		Initiailizes a trailer in a message safely.
 */
void
ipc_kmsg_init_trailer(
	ipc_kmsg_t          kmsg,
	task_t              sender)
{
	static const mach_msg_max_trailer_t KERNEL_TRAILER_TEMPLATE = {
		.msgh_trailer_type = MACH_MSG_TRAILER_FORMAT_0,
		.msgh_trailer_size = MACH_MSG_TRAILER_MINIMUM_SIZE,
		.msgh_sender = KERNEL_SECURITY_TOKEN_VALUE,
		.msgh_audit = KERNEL_AUDIT_TOKEN_VALUE
	};

	mach_msg_max_trailer_t *trailer;

	/*
	 * I reserve for the trailer the largest space (MAX_TRAILER_SIZE)
	 * However, the internal size field of the trailer (msgh_trailer_size)
	 * is initialized to the minimum (sizeof(mach_msg_trailer_t)), to optimize
	 * the cases where no implicit data is requested.
	 */
	trailer = ipc_kmsg_get_trailer(kmsg, false);
	if (sender == TASK_NULL) {
		memcpy(trailer, &KERNEL_TRAILER_TEMPLATE, sizeof(*trailer));
	} else {
		bzero(trailer, sizeof(*trailer));
		trailer->msgh_trailer_type = MACH_MSG_TRAILER_FORMAT_0;
		trailer->msgh_trailer_size = MACH_MSG_TRAILER_MINIMUM_SIZE;
		trailer->msgh_sender = *task_get_sec_token(sender);
		trailer->msgh_audit = *task_get_audit_token(sender);
	}
}


void
ipc_kmsg_add_trailer(ipc_kmsg_t kmsg, ipc_space_t space __unused,
    mach_msg_option_t option, __unused thread_t thread,
    mach_port_seqno_t seqno, boolean_t minimal_trailer,
    mach_vm_offset_t context)
{
	mach_msg_max_trailer_t *trailer;

#ifdef __arm64__
	mach_msg_max_trailer_t tmp_trailer; /* This accommodates U64, and we'll munge */

	/*
	 * If we are building a minimal_trailer, that means we have not attempted to
	 * copy out message body (which converts descriptors to user sizes) because
	 * we are coming from msg_receive_error().
	 *
	 * Adjust trailer calculation accordingly.
	 */
	void *real_trailer_out = (void*)ipc_kmsg_get_trailer(kmsg, !minimal_trailer);

	/*
	 * Populate scratch with initial values set up at message allocation time.
	 * After, we reinterpret the space in the message as the right type
	 * of trailer for the address space in question.
	 */
	bcopy(real_trailer_out, &tmp_trailer, MAX_TRAILER_SIZE);
	trailer = &tmp_trailer;
#else /* __arm64__ */
	(void)thread;
	trailer = ipc_kmsg_get_trailer(kmsg, !minimal_trailer);
#endif /* __arm64__ */

	if (!(option & MACH_RCV_TRAILER_MASK)) {
		return;
	}

	trailer->msgh_seqno = seqno;
	trailer->msgh_context = context;
	trailer->msgh_trailer_size = REQUESTED_TRAILER_SIZE(thread_is_64bit_addr(thread), option);

	if (minimal_trailer) {
		goto done;
	}

	if (GET_RCV_ELEMENTS(option) >= MACH_RCV_TRAILER_AV) {
		trailer->msgh_ad = 0;
	}

	/*
	 * The ipc_kmsg_t holds a reference to the label of a label
	 * handle, not the port. We must get a reference to the port
	 * and a send right to copyout to the receiver.
	 */

	if (option & MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_LABELS)) {
		trailer->msgh_labels.sender = 0;
	}

done:
#ifdef __arm64__
	ipc_kmsg_munge_trailer(trailer, real_trailer_out, thread_is_64bit_addr(thread));
#endif /* __arm64__ */
	return;
}

/*
 * Get the trailer address of kmsg.
 *
 *     - body_copied_out: Whether ipc_kmsg_copyout_body() has been called.
 *     If true, descriptors in kmsg has been converted to user size.
 *
 * /!\ WARNING /!\
 *     Should not be used after ipc_kmsg_convert_header_to_user() is called.
 */
mach_msg_max_trailer_t *
ipc_kmsg_get_trailer(
	ipc_kmsg_t              kmsg,
	bool                    body_copied_out) /* is kmsg body copyout attempted */
{
	mach_msg_header_t *hdr = ikm_header(kmsg);

	if (ikm_is_linear(kmsg)) {
		return (mach_msg_max_trailer_t *)((vm_offset_t)hdr +
		       mach_round_msg(hdr->msgh_size));
	} else {
		assert(kmsg->ikm_udata != NULL);
		return (mach_msg_max_trailer_t *)((vm_offset_t)kmsg->ikm_udata +
		       ikm_content_size(kmsg, current_map(), 0, body_copied_out));
	}
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
