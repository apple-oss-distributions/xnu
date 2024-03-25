/*
 * Copyright (c) 2000-2009 Apple Inc. All rights reserved.
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
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1982, 1986, 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)kern_xxx.c	8.2 (Berkeley) 11/14/93
 */
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/reboot.h>
#include <sys/vm.h>
#include <sys/sysctl.h>
#include <sys/buf.h>

#include <security/audit/audit.h>

#include <sys/mount_internal.h>
#include <sys/sysproto.h>
#if CONFIG_MACF
#include <security/mac_framework.h>
#endif
#if CONFIG_ATM
#include <atm/atm_internal.h>
#endif

#include <kern/kalloc.h>
#include <kern/ext_paniclog.h>

#include <IOKit/IOBSD.h>

/* Max panic string length */
#define kPanicStringMaxLen 1024

extern int psem_cache_purge_all(void);
extern int pshm_cache_purge_all(void);
extern int pshm_cache_purge_uid(uid_t uid);
extern void reset_osvariant_status(void);
extern void reset_osreleasetype(void);

int
reboot(struct proc *p, struct reboot_args *uap, __unused int32_t *retval)
{
	char *message = NULL;
	int error = 0;
	size_t dummy = 0;

	AUDIT_ARG(cmd, uap->opt);

	if ((error = suser(kauth_cred_get(), &p->p_acflag))) {
#if (DEVELOPMENT || DEBUG)
		if (uap->opt & RB_PANIC) {
			/* clear 'error' to allow non-root users to call panic on dev/debug kernels */
			error = 0;
		} else {
			return error;
		}
#else
		return error;
#endif
	}

	if (uap->opt & RB_PANIC && uap->msg != USER_ADDR_NULL) {
		message = (char *)kalloc_data(kPanicStringMaxLen, Z_WAITOK | Z_ZERO);
		if (!message) {
			return ENOMEM;
		}
		int copy_error = copyinstr(uap->msg, (void *)message, kPanicStringMaxLen, (size_t *)&dummy);
		if (copy_error != 0 && copy_error != ENAMETOOLONG) {
			strncpy(message, "user space RB_PANIC message copyin failed", kPanicStringMaxLen - 1);
		} else {
			message[kPanicStringMaxLen - 1] = '\0';
		}
	}

#if CONFIG_MACF
#if (DEVELOPMENT || DEBUG)
	if (uap->opt & RB_PANIC) {
		/* on dev/debug kernels: allow anyone to call panic */
		goto skip_cred_check;
	}
#endif

	error = mac_system_check_reboot(current_cached_proc_cred(p), uap->opt);
#if (DEVELOPMENT || DEBUG)
skip_cred_check:
#endif
#endif
	if (!error) {
		OSBitOrAtomic(P_REBOOT, &p->p_flag);  /* No more signals for this proc */
		error = reboot_kernel(uap->opt, message);
	}

	kfree_data(message, kPanicStringMaxLen);
	return error;
}

int
sys_panic_with_data(struct proc *p,
    struct panic_with_data_args *uap,
    __unused int32_t *retval)
{
	char *message = NULL;
	void *data = NULL;
	int copy_len = 0;
	size_t dummy = 0;
	uuid_t uuid = {0};

	AUDIT_ARG(addr, uap->addr);
	AUDIT_ARG(value32, uap->len);
	AUDIT_ARG(addr, uap->uuid);

	if (!IOCurrentTaskHasEntitlement(EXTPANICLOG_ENTITLEMENT)) {
		return EPERM;
	}

	char *proc_name = proc_best_name(p);

	if (uap->msg != USER_ADDR_NULL) {
		message = (char *)kalloc_data(kPanicStringMaxLen, Z_WAITOK | Z_ZERO);
		if (!message) {
			goto finish;
		}
		int copy_error = copyinstr(uap->msg, (void *)message, kPanicStringMaxLen, (size_t *)&dummy);
		if (copy_error != 0 && copy_error != ENAMETOOLONG) {
			strlcpy(message, "user space panic_with_data message copyin failed", kPanicStringMaxLen - 1);
		} else {
			message[kPanicStringMaxLen - 1] = '\0';
		}
	}

	if (uap->addr != USER_ADDR_NULL) {
		copy_len = MIN(uap->len, PANIC_WITH_DATA_MAX_LEN);

		data = kalloc_data(copy_len, Z_WAITOK | Z_ZERO);
		if (!data) {
			goto finish;
		}

		int copy_error = copyin(uap->addr, data, copy_len);
		if (copy_error != 0) {
			kfree_data(data, copy_len);
			data = NULL;
		}
	}

	if (uap->uuid != USER_ADDR_NULL) {
		int copyerror = copyin(uap->uuid, &uuid[0], sizeof(uuid_t));
		if (copyerror != 0) {
			goto finish;
		}
	}

finish:
	panic_with_data(uuid, data, copy_len,
	    "Panic called from Process: %s Message: %s", proc_name, message);
}

extern void OSKextResetAfterUserspaceReboot(void);
extern void zone_gc_drain(void);
extern uint64_t pmap_release_pages_fast(void);

static int
usrctl_full(void)
{
	reset_osvariant_status();
	reset_osreleasetype();

#if CONFIG_ATM
	atm_reset();
#endif

#if CONFIG_EXT_RESOLVER
	/*
	 * We're doing a user space reboot.  We are guaranteed that the
	 * external identity resolver is gone, so ensure that everything
	 * comes back up as with fresh-boot just in case it didn't go
	 * down cleanly.
	 */
	kauth_resolver_identity_reset();
#endif /* CONFIG_EXT_RESOLVER */

	OSKextResetAfterUserspaceReboot();
	int shm_error = pshm_cache_purge_all();
	int sem_error = psem_cache_purge_all();

	zone_gc_drain();
	pmap_release_pages_fast();

	return shm_error != 0 ? shm_error : sem_error;
}

static int
usrctl_logout(uid_t uid)
{
	int shm_error = pshm_cache_purge_uid(uid);
	/*
	 * Currently there is a requirement to purge some root-owned semaphores,
	 * and no use-case for preserving any. Just purge all of them.
	 */
	int sem_error = psem_cache_purge_all();

	/*
	 * Until rdar://78965143, kern.willuserspacereboot is set when logout begins
	 * so its effects need to be reset here, when logout completes.
	 */
	OSKextResetAfterUserspaceReboot();

	return shm_error != 0 ? shm_error : sem_error;
}

int
usrctl(struct proc *p, struct usrctl_args *uap, __unused int32_t *retval)
{
	if (p != initproc) {
		return EPERM;
	}

	if (uap->flags == 0) {
		return usrctl_full();
	} else {
		return usrctl_logout((uid_t)uap->flags);
	}
}
