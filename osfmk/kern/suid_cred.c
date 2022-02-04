/*
 * Copyright (c) 2019-2020 Apple Inc. All rights reserved.
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
 *
 * An SUID credential is a port type which allows a process to create a new
 * process with a specific user id. It provides an alternative means to acheive
 * this to the more traditional SUID bit file permission.
 *
 * To create a new SUID credential the process must be running as root and must
 * have a special entitlement. When created, the credential is associated with a
 * specific vnode and UID so the unprivileged owner of the credential may only
 * create a new process from the file associated with that vnode and the
 * resulting effective UID will be that of the UID in the credential.
 */

#include <kern/ipc_kobject.h>
#include <kern/queue.h>
#include <kern/suid_cred.h>

#include <mach/mach_types.h>
#include <mach/task.h>

#include <IOKit/IOBSD.h>

/* Declarations necessary to call vnode_lookup()/vnode_put(). */
struct vnode;
struct vfs_context;
extern int vnode_lookup(const char *, int, struct vnode **,
    struct vfs_context *);
extern struct vfs_context * vfs_context_current(void);
extern int vnode_put(struct vnode *);

/* Declarations necessary to call kauth_cred_issuser(). */
struct ucred;
extern int kauth_cred_issuser(struct ucred *);
extern struct ucred *kauth_cred_get(void);

/* Data associated with the suid cred port. Consumed during posix_spawn(). */
struct suid_cred {
	ipc_port_t port;
	struct vnode *vnode;
	uint32_t uid;
};

static ZONE_DECLARE(suid_cred_zone, "suid_cred",
    sizeof(struct suid_cred), ZC_ZFREE_CLEARMEM);

static void suid_cred_no_senders(ipc_port_t port, mach_port_mscount_t mscount);
static void suid_cred_destroy(ipc_port_t port);

IPC_KOBJECT_DEFINE(IKOT_SUID_CRED,
    .iko_op_no_senders = suid_cred_no_senders,
    .iko_op_destroy    = suid_cred_destroy);


/* Allocs a new suid credential. The vnode reference will be owned by the newly
 * created suid_cred_t. */
static suid_cred_t
suid_cred_alloc(struct vnode *vnode, uint32_t uid)
{
	suid_cred_t sc;

	assert(vnode != NULL);

	sc = zalloc_flags(suid_cred_zone, Z_WAITOK | Z_ZERO | Z_NOFAIL);
	sc->vnode = vnode;
	sc->uid = uid;
	sc->port = ipc_kobject_alloc_port(sc, IKOT_SUID_CRED,
	    IPC_KOBJECT_ALLOC_MAKE_SEND | IPC_KOBJECT_ALLOC_NSREQUEST);
	return sc;
}

static void
suid_cred_free(suid_cred_t sc)
{
	vnode_put(sc->vnode);
	zfree(suid_cred_zone, sc);
}

static void
suid_cred_destroy(ipc_port_t port)
{
	suid_cred_t sc = ipc_kobject_disable(port, IKOT_SUID_CRED);

	assert(sc->port == port);

	suid_cred_free(sc);
}

static void
suid_cred_no_senders(ipc_port_t port, mach_port_mscount_t mscount)
{
	ipc_kobject_dealloc_port(port, mscount, IKOT_SUID_CRED);
}

ipc_port_t
convert_suid_cred_to_port(suid_cred_t sc)
{
	if (sc) {
		zone_require(suid_cred_zone, sc);
		return sc->port;
	}
	return IP_NULL;
}

/*
 * Verify the suid cred port. The cached vnode should match the passed vnode.
 * The uid to be used to spawn the new process is returned in 'uid'.
 */
int
suid_cred_verify(ipc_port_t port, struct vnode *vnode, uint32_t *uid)
{
	suid_cred_t sc;

	if (!IP_VALID(port)) {
		return -1;
	}

	ip_mq_lock(port);
	sc = ipc_kobject_get_locked(port, IKOT_SUID_CRED);

	if (sc && sc->vnode == vnode) {
		*uid = sc->uid;
		ipc_port_destroy(port);
		/* port unlocked */
		return 0;
	}

	ip_mq_unlock(port);
	return -1;
}

kern_return_t
task_create_suid_cred(
	task_t task,
	suid_cred_path_t path,
	suid_cred_uid_t uid,
	suid_cred_t *sc_p)
{
	struct vnode *vnode;
	int  err = -1;

	if (task == TASK_NULL || task != current_task()) {
		return KERN_INVALID_ARGUMENT;
	}

	// Task must have entitlement.
	if (!IOTaskHasEntitlement(task, "com.apple.private.suid_cred")) {
		return KERN_NO_ACCESS;
	}

	// Thread must be root owned.
	if (!kauth_cred_issuser(kauth_cred_get())) {
		return KERN_NO_ACCESS;
	}

	// Find the vnode for the path.
	err = vnode_lookup(path, 0, &vnode, vfs_context_current());
	if (err != 0) {
		return KERN_INVALID_ARGUMENT;
	}

	*sc_p = suid_cred_alloc(vnode, uid);
	return KERN_SUCCESS;
}
