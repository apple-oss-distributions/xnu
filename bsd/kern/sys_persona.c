/*
 * Copyright (c) 2015 Apple Inc. All rights reserved.
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
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/kernel_types.h>
#include <sys/sysproto.h>

#include <sys/kauth.h>
#include <sys/malloc.h>
#include <sys/persona.h>
#include <sys/proc.h>

#include <kern/task.h>
#include <kern/thread.h>
#include <mach/thread_act.h>
#include <mach/mach_types.h>

#include <libkern/libkern.h>
#include <IOKit/IOBSD.h>

#define PERSONA_INFO_V1_SIZE offsetof(struct kpersona_info, persona_uid)
#define PERSONA_INFO_V2_SIZE sizeof(struct kpersona_info)

extern kern_return_t bank_get_bank_ledger_thread_group_and_persona(void *voucher,
    void *bankledger, void **banktg, uint32_t *persona_id);

static int
kpersona_copyin(user_addr_t infop, struct kpersona_info *kinfo)
{
	uint32_t info_v = 0;
	int error;
	size_t kinfo_size;

	memset(kinfo, 0, sizeof(struct kpersona_info));
	/* Initialize fields introduced in newer versions. They won't be covered by
	 * the copyin() if the caller passed an old version.
	 */
	kinfo->persona_uid = KAUTH_UID_NONE;

	error = copyin(infop, &info_v, sizeof(info_v));
	if (error) {
		return error;
	}

	switch (info_v) {
	case PERSONA_INFO_V1:
		kinfo_size = PERSONA_INFO_V1_SIZE;
		break;
	case PERSONA_INFO_V2:
		kinfo_size = PERSONA_INFO_V2_SIZE;
		break;
	default:
		return EINVAL;
	}
	error = copyin(infop, kinfo, kinfo_size);

	/* enforce NULL termination on strings */
	kinfo->persona_name[MAXLOGNAME] = 0;

	return error;
}

static int
kpersona_copyout(struct kpersona_info *kinfo, user_addr_t infop)
{
	uint32_t info_v;
	int error;
	size_t kinfo_size;

	error = copyin(infop, &info_v, sizeof(info_v));
	if (error) {
		return error;
	}

	switch (info_v) {
	case PERSONA_INFO_V1:
		kinfo_size = PERSONA_INFO_V1_SIZE;
		break;
	case PERSONA_INFO_V2:
		kinfo_size = PERSONA_INFO_V2_SIZE;
		break;
	default:
		return EINVAL;
	}

	/* preserve version field specified by the caller */
	uint32_t original_version = kinfo->persona_info_version;
	kinfo->persona_info_version = info_v;

	error = copyout(kinfo, infop, kinfo_size);

	kinfo->persona_info_version = original_version;

	return error;
}


static int
kpersona_alloc_syscall(user_addr_t infop, user_addr_t idp, user_addr_t path)
{
	int error;
	struct kpersona_info kinfo;
	struct persona *persona = NULL;
	uid_t id = PERSONA_ID_NONE;
	const char *login;
	char *pna_path = NULL;

	if (!IOCurrentTaskHasEntitlement(PERSONA_MGMT_ENTITLEMENT)) {
		return EPERM;
	}

	error = kpersona_copyin(infop, &kinfo);
	if (error) {
		return error;
	}

	login = kinfo.persona_name[0] ? kinfo.persona_name : NULL;
	if (kinfo.persona_id != PERSONA_ID_NONE && kinfo.persona_id != (uid_t)0) {
		id = kinfo.persona_id;
	}

	if (path) {
		pna_path = zalloc_flags(ZV_NAMEI, Z_WAITOK | Z_ZERO);

		size_t pathlen;
		error = copyinstr(path, (void *)pna_path, MAXPATHLEN, &pathlen);
		if (error) {
			zfree(ZV_NAMEI, pna_path);
			return error;
		}
	}

	error = 0;
	persona = persona_alloc(id, login, kinfo.persona_type, pna_path, kinfo.persona_uid, &error);
	if (!persona) {
		if (pna_path != NULL) {
			zfree(ZV_NAMEI, pna_path);
		}
		return error;
	}

	/* persona struct contains a reference to pna_path */
	pna_path = NULL;

	error = persona_init_begin(persona);
	if (error) {
		goto out_persona_err;
	}

	error = copyout(&persona->pna_id, idp, sizeof(persona->pna_id));
	if (error) {
		goto out_persona_err;
	}

	kinfo.persona_id = persona->pna_id;
	error = kpersona_copyout(&kinfo, infop);
	if (error) {
		goto out_persona_err;
	}

	persona_init_end(persona, error);

	/*
	 * On success, we have a persona structure in the global list with a
	 * single reference count on it. The corresponding _dealloc() call
	 * will release this reference.
	 */
	return error;

out_persona_err:
	assert(error != 0);
	persona_init_end(persona, error);

#if PERSONA_DEBUG
	printf("%s:  ERROR:%d\n", __func__, error);
#endif
	if (persona) {
		persona_put(persona);
	}
	return error;
}

static int
kpersona_dealloc_syscall(user_addr_t idp)
{
	int error = 0;
	uid_t persona_id;
	struct persona *persona;

	if (!IOCurrentTaskHasEntitlement(PERSONA_MGMT_ENTITLEMENT)) {
		return EPERM;
	}

	error = copyin(idp, &persona_id, sizeof(persona_id));
	if (error) {
		return error;
	}

	/* invalidate the persona (deny subsequent spawn/fork) */
	persona = persona_lookup_and_invalidate(persona_id);

	if (!persona) {
		return ESRCH;
	}

	/* one reference from the _lookup() */
	persona_put(persona);

	/* one reference from the _alloc() */
	persona_put(persona);

	return error;
}

static int
kpersona_get_syscall(user_addr_t idp)
{
	int error;
	uid_t current_persona_id;
	struct persona *persona;

	current_persona_id = current_persona_get_id();

	/* Make sure the persona is still valid */
	persona = persona_lookup(current_persona_id);
	if (!persona) {
		return ESRCH;
	}

	error = copyout(&persona->pna_id, idp, sizeof(persona->pna_id));
	persona_put(persona);

	return error;
}

static int
kpersona_getpath_syscall(user_addr_t idp, user_addr_t path)
{
	int error;
	uid_t persona_id;
	struct persona *persona;
	size_t pathlen;
	uid_t lookup_persona_id = PERSONA_ID_NONE;

	if (!path) {
		return EINVAL;
	}

	error = copyin(idp, &persona_id, sizeof(persona_id));
	if (error) {
		return error;
	}

	/* Get current thread's persona id to compare if the
	 * input persona_id matches the current persona id
	 */
	lookup_persona_id = current_persona_get_id();

	if (persona_id && persona_id != lookup_persona_id) {
		if (!kauth_cred_issuser(kauth_cred_get()) &&
		    !IOCurrentTaskHasEntitlement(PERSONA_MGMT_ENTITLEMENT)) {
			return EPERM;
		}
		lookup_persona_id = persona_id;
	}

	persona = persona_lookup(lookup_persona_id);
	if (!persona) {
		return ESRCH;
	}

	if (persona->pna_path) {
		error = copyoutstr((void *)persona->pna_path, path, MAXPATHLEN, &pathlen);
	}

	persona_put(persona);

	return error;
}

static void
kpersona_populate(struct kpersona_info *kinfo, struct persona *persona)
{
	memset(kinfo, 0, sizeof(struct kpersona_info));

	kinfo->persona_info_version = PERSONA_INFO_V2;
	kinfo->persona_id = persona->pna_id;
	kinfo->persona_type = persona->pna_type;
	kinfo->persona_uid = persona->pna_uid;

	/*
	 * NULL termination is assured b/c persona_name is
	 * exactly MAXLOGNAME + 1 bytes (and has been memset to 0)
	 */
	strncpy(kinfo->persona_name, persona->pna_login, MAXLOGNAME);
}

static int
kpersona_info_syscall(user_addr_t idp, user_addr_t infop)
{
	int error;
	uid_t persona_id;
	struct persona *persona;
	struct kpersona_info kinfo;
	uid_t lookup_persona_id = PERSONA_ID_NONE;

	error = copyin(idp, &persona_id, sizeof(persona_id));
	if (error) {
		return error;
	}

	/* Get current thread's persona id to compare if the
	 * input persona_id matches the current persona id
	 */
	lookup_persona_id = current_persona_get_id();

	if (persona_id && persona_id != lookup_persona_id) {
		if (!kauth_cred_issuser(kauth_cred_get()) &&
		    !IOCurrentTaskHasEntitlement(PERSONA_MGMT_ENTITLEMENT)) {
			return EPERM;
		}
		lookup_persona_id = persona_id;
	}

	persona = persona_lookup(lookup_persona_id);
	if (!persona) {
		return ESRCH;
	}

	persona_dbg("FOUND: persona: id:%d, login:\"%s\"",
	    persona->pna_id, persona->pna_login);

	kpersona_populate(&kinfo, persona);

	persona_put(persona);

	error = kpersona_copyout(&kinfo, infop);

	return error;
}

static int
kpersona_pidinfo_syscall(user_addr_t idp, user_addr_t infop)
{
	int error;
	pid_t pid;
	struct persona *persona;
	struct kpersona_info kinfo;

	error = copyin(idp, &pid, sizeof(pid));
	if (error) {
		return error;
	}

	if (!kauth_cred_issuser(kauth_cred_get())
	    && (pid != proc_getpid(current_proc()))) {
		return EPERM;
	}

	persona = persona_proc_get(pid);
	if (!persona) {
		return ESRCH;
	}

	kpersona_populate(&kinfo, persona);

	persona_put(persona);

	error = kpersona_copyout(&kinfo, infop);

	return error;
}

static int
kpersona_find_syscall(user_addr_t infop, user_addr_t idp, user_addr_t idlenp)
{
	int error;
	struct kpersona_info kinfo;
	const char *login;
	size_t u_idlen, k_idlen = 0;
	struct persona **persona = NULL;

	error = copyin(idlenp, &u_idlen, sizeof(u_idlen));
	if (error) {
		return error;
	}

	if (u_idlen > g_max_personas) {
		u_idlen = g_max_personas;
	}

	error = kpersona_copyin(infop, &kinfo);
	if (error) {
		goto out;
	}

	login = kinfo.persona_name[0] ? kinfo.persona_name : NULL;

	if (u_idlen > 0) {
		persona = kalloc_type(struct persona *, u_idlen, Z_WAITOK | Z_ZERO);
		if (!persona) {
			error = ENOMEM;
			goto out;
		}
	}

	k_idlen = u_idlen;
	error = persona_find_all(login, kinfo.persona_id, (persona_type_t)kinfo.persona_type, persona, &k_idlen);
	if (error) {
		goto out;
	}

	/* copyout all the IDs of each persona we found */
	for (size_t i = 0; i < k_idlen; i++) {
		if (i >= u_idlen) {
			break;
		}
		error = copyout(&persona[i]->pna_id,
		    idp + (i * sizeof(persona[i]->pna_id)),
		    sizeof(persona[i]->pna_id));
		if (error) {
			goto out;
		}
	}

out:
	if (persona) {
		for (size_t i = 0; i < u_idlen; i++) {
			persona_put(persona[i]);
		}
		kfree_type(struct persona *, u_idlen, persona);
	}

	(void)copyout(&k_idlen, idlenp, sizeof(u_idlen));

	return error;
}

/*
 * Syscall entry point / demux.
 */
int
persona(__unused proc_t p, struct persona_args *pargs, __unused int32_t *retval)
{
	int error;
	uint32_t op = pargs->operation;
	/* uint32_t flags = pargs->flags; */
	user_addr_t infop = pargs->info;
	user_addr_t idp = pargs->id;
	user_addr_t path = pargs->path;

	switch (op) {
	case PERSONA_OP_ALLOC:
		error = kpersona_alloc_syscall(infop, idp, USER_ADDR_NULL);
		break;
	case PERSONA_OP_PALLOC:
		error = kpersona_alloc_syscall(infop, idp, path);
		break;
	case PERSONA_OP_DEALLOC:
		error = kpersona_dealloc_syscall(idp);
		break;
	case PERSONA_OP_GET:
		error = kpersona_get_syscall(idp);
		break;
	case PERSONA_OP_GETPATH:
		error = kpersona_getpath_syscall(idp, path);
		break;
	case PERSONA_OP_INFO:
		error = kpersona_info_syscall(idp, infop);
		break;
	case PERSONA_OP_PIDINFO:
		error = kpersona_pidinfo_syscall(idp, infop);
		break;
	case PERSONA_OP_FIND:
	case PERSONA_OP_FIND_BY_TYPE:
		error = kpersona_find_syscall(infop, idp, pargs->idlen);
		break;
	default:
		error = ENOSYS;
		break;
	}

	return error;
}
