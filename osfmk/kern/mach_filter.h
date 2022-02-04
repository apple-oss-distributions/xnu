/*
 * Copyright (c) 2020 Apple Computer, Inc. All rights reserved.
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

#ifndef _KERN_MACH_FILTER_H_
#define _KERN_MACH_FILTER_H_

#if KERNEL_PRIVATE

#include <sys/cdefs.h>
#include <mach/message.h>
#include <mach/port.h>

/* Sandbox-specific calls for task based message filtering */
typedef boolean_t (*mach_msg_fetch_filter_policy_cbfunc_t) (struct task *task, void *portlabel,
    mach_msg_id_t msgid, mach_msg_filter_id *fpid);

typedef kern_return_t (*mach_msg_filter_alloc_service_port_sblabel_cbfunc_t) (mach_service_port_info_t service_port_info,
    void **sblabel);

typedef void (*mach_msg_filter_dealloc_service_port_sblabel_cbfunc_t) (void *sblabel);

typedef void* (*mach_msg_filter_derive_sblabel_from_service_port_cbfunc_t) (void *service_port_sblabel,
    boolean_t *send_side_filtering);

typedef kern_return_t (*mach_msg_filter_get_connection_port_filter_policy_cbfunc_t) (void *service_port_sblabel,
    void *connection_port_sblabel, uint64_t *fpid);

/* Will be called with the port lock held */
typedef void (*mach_msg_filter_retain_sblabel_cbfunc_t) (void * sblabel);

struct mach_msg_filter_callbacks {
	unsigned int version;
	/* v0 */
	const mach_msg_fetch_filter_policy_cbfunc_t fetch_filter_policy;

	/* v1 */
	const mach_msg_filter_alloc_service_port_sblabel_cbfunc_t alloc_service_port_sblabel;
	const mach_msg_filter_dealloc_service_port_sblabel_cbfunc_t dealloc_service_port_sblabel;
	const mach_msg_filter_derive_sblabel_from_service_port_cbfunc_t derive_sblabel_from_service_port;
	const mach_msg_filter_get_connection_port_filter_policy_cbfunc_t get_connection_port_filter_policy;
	const mach_msg_filter_retain_sblabel_cbfunc_t retain_sblabel;
};

#define MACH_MSG_FILTER_CALLBACKS_VERSION_0 (0) /* up-to fetch_filter_policy */
#define MACH_MSG_FILTER_CALLBACKS_VERSION_1 (1) /* up-to derive_sblabel_from_service_port */
#define MACH_MSG_FILTER_CALLBACKS_CURRENT MACH_MSG_FILTER_CALLBACKS_VERSION_1

__BEGIN_DECLS

int mach_msg_filter_register_callback(const struct mach_msg_filter_callbacks *callbacks);

__END_DECLS

#endif /* KERNEL_PRIVATE */

#if XNU_KERNEL_PRIVATE
extern struct mach_msg_filter_callbacks mach_msg_filter_callbacks;

static inline bool __pure2
mach_msg_filter_at_least(unsigned int version)
{
	if (version == 0) {
		/*
		 * a non initialized cb struct looks the same as v0
		 * so we need a null check for that one
		 */
		return mach_msg_filter_callbacks.fetch_filter_policy != NULL;
	}
	return mach_msg_filter_callbacks.version >= version;
}

/* v0 */
#define mach_msg_fetch_filter_policy_callback \
	(mach_msg_filter_callbacks.fetch_filter_policy)

/* v1 */
#define mach_msg_filter_alloc_service_port_sblabel_callback \
	(mach_msg_filter_callbacks.alloc_service_port_sblabel)
#define mach_msg_filter_dealloc_service_port_sblabel_callback \
	(mach_msg_filter_callbacks.dealloc_service_port_sblabel)
#define mach_msg_filter_derive_sblabel_from_service_port_callback \
	(mach_msg_filter_callbacks.derive_sblabel_from_service_port)
#define mach_msg_filter_get_connection_port_filter_policy_callback \
	(mach_msg_filter_callbacks.get_connection_port_filter_policy)
#define mach_msg_filter_retain_sblabel_callback \
	(mach_msg_filter_callbacks.retain_sblabel)

extern
boolean_t mach_msg_fetch_filter_policy(void *portlabel, mach_msg_id_t msgh_id, mach_msg_filter_id *fid);
#endif /* XNU_KERNEL_PRIVATE */

#endif /* _KERN_MACH_FILTER_H_ */
