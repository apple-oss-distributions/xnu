/*
 * Copyright (c) 2018-2021 Apple Inc. All rights reserved.
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
#include <skywalk/os_skywalk_private.h>

__attribute__((always_inline))
static inline struct sysctl_oid *
_skoid_oid_alloc(void)
{
	return sk_alloc_type(struct sysctl_oid, Z_WAITOK | Z_NOFAIL, skmem_tag_oid);
}

__attribute__((always_inline))
static inline void
_skoid_oid_free(struct sysctl_oid *oid)
{
	sk_free_type(struct sysctl_oid, oid);
}

__attribute__((always_inline))
static inline void
_skoid_oid_init(struct skoid *skoid, struct sysctl_oid *oid,
    struct sysctl_oid_list *parent, int kind, void *arg1, int arg2,
    const char *name, int (*handler)SYSCTL_HANDLER_ARGS, const char *fmt)
{
	ASSERT(oid != NULL);
	/*
	 * Note here we use OID2 for current varsion, which does oid alloc/free
	 * ourselves with mcache
	 */
	oid->oid_link.sle_next = NULL;
	oid->oid_parent = parent;
	oid->oid_number = OID_AUTO;
	oid->oid_kind = CTLFLAG_OID2 | kind;
	oid->oid_arg1 = arg1;
	oid->oid_arg2 = arg2;
	if (&skoid->sko_oid == oid) {
		/* for DNODE, store its name inside skoid */
		(void) snprintf(skoid->sko_name, sizeof(skoid->sko_name), "%s",
		    name);
		oid->oid_name = skoid->sko_name;
	} else {
		/* for leaf property, use static name string */
		oid->oid_name = name;
	}
	oid->oid_handler = handler;
	oid->oid_fmt = fmt;
	oid->oid_descr = "";    /* unused for current SYSCTL_OID_VERSION */
	oid->oid_version = SYSCTL_OID_VERSION;
	oid->oid_refcnt = 0;
}

/*
 * Create the skoid and register its sysctl_oid.
 */
void
skoid_create(struct skoid *skoid, struct sysctl_oid_list *parent,
    const char *name, int kind)
{
	struct sysctl_oid *oid = &skoid->sko_oid;

	_skoid_oid_init(skoid, oid, parent,
	    CTLTYPE_NODE | CTLFLAG_LOCKED | kind,
	    &skoid->sko_oid_list, 0, name, NULL, "N");
	sysctl_register_oid(oid);
}

__attribute__((always_inline))
static inline void
_skoid_add_property(struct skoid *skoid, const char *name, int kind, char *fmt,
    void *arg1, int arg2, int (*handler)SYSCTL_HANDLER_ARGS)
{
	struct sysctl_oid *oid;

	oid = _skoid_oid_alloc();
	_skoid_oid_init(skoid, oid, &skoid->sko_oid_list, CTLFLAG_LOCKED | kind,
	    arg1, arg2, name, handler, fmt);
	sysctl_register_oid(oid);
}

/*
 * Add int property to skoid.
 */
void
skoid_add_int(struct skoid *skoid, const char *name, int kind,
    int *int_ptr)
{
	_skoid_add_property(skoid, name, CTLTYPE_INT | kind, "I", int_ptr, 0,
	    sysctl_handle_int);
}

/*
 * Add unsigned int property to skoid.
 */
void
skoid_add_uint(struct skoid *skoid, const char *name, int kind,
    unsigned int *uint_ptr)
{
	_skoid_add_property(skoid, name, CTLTYPE_INT | kind, "IU", uint_ptr, 0,
	    sysctl_handle_int);
}

/*
 * Add procedure handler property to skoid.
 */
void
skoid_add_handler(struct skoid *skoid, const char *name, int kind,
    int (*proc)SYSCTL_HANDLER_ARGS, void *proc_arg1, int proc_arg2)
{
	_skoid_add_property(skoid, name, CTLTYPE_INT | kind, "I", proc_arg1,
	    proc_arg2, proc);
}

/*
 * Destroy skoid and its associated properties
 *
 * @discussion This functions only handles properties associated with it and
 * the unregistration of the sysctl_oid. If skoid itself is dynamically
 * allocated, it's the caller who should release skoid object.
 */
void
skoid_destroy(struct skoid *skoid)
{
	/*
	 * first take down parent sysctl node, which internally deletes it from
	 * sko_oid_list, so we don't free it below
	 */
	sysctl_unregister_oid(&skoid->sko_oid);

	/* then destroy all properties sysctl nodes */
	struct sysctl_oid *oid, *oid_tmp;
	SLIST_FOREACH_SAFE(oid, &skoid->sko_oid_list, oid_link, oid_tmp) {
		/* sub dynamic node must be destroyed first */
		if ((oid->oid_kind & CTLTYPE) == CTLTYPE_NODE) {
			panic("leaked skoid sub-node detected %p %s",
			    oid, oid->oid_name);
			__builtin_unreachable();
		}
		sysctl_unregister_oid(oid);
		ASSERT(oid != &skoid->sko_oid);
		_skoid_oid_free(oid);
	}
}
