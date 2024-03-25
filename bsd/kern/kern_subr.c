/*
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
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
 * Copyright (c) 1982, 1986, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
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
 *	@(#)kern_subr.c	8.3 (Berkeley) 1/21/94
 */

#include <machine/atomic.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc_internal.h>
#include <sys/malloc.h>
#include <sys/queue.h>
#include <vm/pmap.h>
#include <sys/uio_internal.h>
#include <kern/kalloc.h>

#include <kdebug.h>

#include <sys/kdebug.h>
#define DBG_UIO_COPYOUT 16
#define DBG_UIO_COPYIN  17

#if DEBUG
#include <kern/simple_lock.h>

static uint32_t                         uio_t_count = 0;
#endif /* DEBUG */

#define IS_VALID_UIO_SEGFLG(segflg)  \
	( (1 << segflg) & (UIOF_USERSPACE | \
	                   UIOF_SYSSPACE | \
	                   UIOF_USERSPACE32 | \
	                   UIOF_USERSPACE64 | \
	                   UIOF_SYSSPACE32 | \
	                   UIOF_USERISPACE | \
	                   UIOF_PHYS_USERSPACE | \
	                   UIOF_PHYS_SYSSPACE | \
	                   UIOF_USERISPACE32 | \
	                   UIOF_PHYS_USERSPACE32 | \
	                   UIOF_USERISPACE64 | \
	                   UIOF_PHYS_USERSPACE64))

#define IS_SYS_OR_PHYS_SPACE_SEGFLG(segflg) \
	( (1 << segflg) & (UIOF_SYSSPACE | \
	                   UIOF_PHYS_SYSSPACE | \
	                   UIOF_SYSSPACE32 | \
	                   UIOF_PHYS_USERSPACE | \
	                   UIOF_PHYS_SYSSPACE | \
	                   UIOF_PHYS_USERSPACE64 | \
	                   UIOF_PHYS_USERSPACE32))

#define IS_PURE_USER_SPACE_SEGFLG(segflg) \
	( (1 << segflg) & (UIOF_USERSPACE | \
	                   UIOF_USERSPACE32 | \
	                   UIOF_USERSPACE64 | \
	                   UIOF_USERISPACE | \
	                   UIOF_USERISPACE32 | \
	                   UIOF_USERISPACE64))

#define IS_SYS_SPACE_SEGFLG(segflg) \
	( (1 << segflg) & (UIOF_SYSSPACE | \
	                   UIOF_SYSSPACE32))

#define IS_PHYS_USER_SPACE_SEGFLG(segflg) \
	( (1 << segflg) & (UIOF_PHYS_USERSPACE | \
	                   UIOF_PHYS_USERSPACE64 | \
	                   UIOF_PHYS_USERSPACE32))

#define IS_PHYS_SYS_SPACE_SEGFLG(segflg) \
	( (1 << segflg) & (UIOF_PHYS_SYSSPACE))

static void uio_update_user(uio_t __attribute__((nonnull)) a_uio, user_size_t a_count);
static void uio_update_sys(uio_t __attribute__((nonnull)) a_uio, user_size_t a_count);
static user_size_t uio_curriovlen_user(const uio_t __attribute__((nonnull)) a_uio);
static user_size_t uio_curriovlen_sys(const uio_t __attribute__((nonnull)) a_uio);

#if __has_feature(ptrauth_calls)
__attribute__((always_inline))
static u_int64_t
blend_iov_components(const struct kern_iovec *kiovp)
{
	return ptrauth_blend_discriminator(
		(void *)((u_int64_t)&kiovp->iov_base ^ kiovp->iov_len),
		ptrauth_string_discriminator("kiovp"));
}
#endif

__attribute__((always_inline))
static u_int64_t
kiovp_get_base(const struct kern_iovec *kiovp)
{
#if __has_feature(ptrauth_calls)
	if (kiovp->iov_base == 0) {
		return 0;
	} else {
		return (u_int64_t)ptrauth_auth_data((void *)kiovp->iov_base,
		           ptrauth_key_process_independent_data,
		           blend_iov_components(kiovp));
	}
#else
	return kiovp->iov_base;
#endif
}

__attribute__((always_inline))
static void
kiovp_set_base(struct kern_iovec *kiovp, u_int64_t addr)
{
#if __has_feature(ptrauth_calls)
	if (addr == 0) {
		kiovp->iov_base = 0;
	} else {
		kiovp->iov_base = (u_int64_t)ptrauth_sign_unauthenticated(
			(void *)addr, ptrauth_key_process_independent_data,
			blend_iov_components(kiovp));
	}
#else
	kiovp->iov_base = addr;
#endif
}

static struct kern_iovec *
uio_kiovp(uio_t uio)
{
#if DEBUG
	if (__improbable(!UIO_IS_SYS_SPACE(uio))) {
		panic("%s: uio is not sys space", __func__);
	}
#endif

	return (struct kern_iovec *)uio->uio_iovs;
}

static struct user_iovec *
uio_uiovp(uio_t uio)
{
	return (struct user_iovec *)uio->uio_iovs;
}

static void *
uio_advance_user(uio_t uio)
{
	uio->uio_iovs = (void *)((uintptr_t)uio->uio_iovs + sizeof(struct user_iovec));

	return uio->uio_iovs;
}

static void *
uio_advance_sys(uio_t uio)
{
	uio->uio_iovs = (void *)((uintptr_t)uio->uio_iovs + sizeof(struct kern_iovec));

	return uio->uio_iovs;
}

/*
 * Returns:	0			Success
 *	uiomove64:EFAULT
 *
 * Notes:	The first argument should be a caddr_t, but const poisoning
 *		for typedef'ed types doesn't work in gcc.
 */
int
uiomove(const char * cp, int n, uio_t uio)
{
	return uiomove64((const addr64_t)(uintptr_t)cp, n, uio);
}

/*
 * Returns:	0			Success
 *		EFAULT
 *	copyout:EFAULT
 *	copyin:EFAULT
 *	copywithin:EFAULT
 *	copypv:EFAULT
 */
int
uiomove64(const addr64_t c_cp, int n, struct uio *uio)
{
	if (IS_PURE_USER_SPACE_SEGFLG(uio->uio_segflg)) {
		if (uio->uio_rw == UIO_READ) {
			return uio_copyout_user((const char *)c_cp, n, uio);
		} else {
			return uio_copyin_user((const char *)c_cp, n, uio);
		}
	} else if (IS_SYS_SPACE_SEGFLG(uio->uio_segflg)) {
		if (uio->uio_rw == UIO_READ) {
			return uio_copyout_sys((const char *)c_cp, n, uio);
		} else {
			return uio_copyin_sys((const char *)c_cp, n, uio);
		}
	} else if (IS_PHYS_USER_SPACE_SEGFLG(uio->uio_segflg)) {
		if (uio->uio_rw == UIO_READ) {
			return uio_copyout_phys_user((const char *)c_cp, n, uio);
		} else {
			return uio_copyin_phys_user((const char *)c_cp, n, uio);
		}
	} else if (IS_PHYS_SYS_SPACE_SEGFLG(uio->uio_segflg)) {
		if (uio->uio_rw == UIO_READ) {
			return uio_copyout_phys_sys((const char *)c_cp, n, uio);
		} else {
			return uio_copyin_phys_sys((const char *)c_cp, n, uio);
		}
	} else {
		return EINVAL;
	}
}

int
uio_copyout_user(const char *c_cp, int n, uio_t uio)
{
	addr64_t cp = (const addr64_t)(uintptr_t)c_cp;

	while (n > 0 && uio->uio_iovcnt > 0 && uio_resid(uio)) {
		struct user_iovec *uiovp;
		uint64_t acnt;
		int error;

		uio_update_user(uio, 0);
		acnt = uio_curriovlen_user(uio);
		if (acnt == 0) {
			continue;
		}
		if (n > 0 && acnt > (uint64_t)n) {
			acnt = n;
		}

		uiovp = uio_uiovp(uio);

		KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, DBG_UIO_COPYOUT)) | DBG_FUNC_START,
		    (int)cp, (uintptr_t)uiovp->iov_base, acnt, 0, 0);

		error = copyout(CAST_DOWN(caddr_t, cp), uiovp->iov_base, (size_t)acnt);

		KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, DBG_UIO_COPYOUT)) | DBG_FUNC_END,
		    (int)cp, (uintptr_t)uiovp->iov_base, acnt, 0, 0);

		if (error) {
			return error;
		}

		uio_update_user(uio, (user_size_t)acnt);
		cp += acnt;
		n -= acnt;
	}
	return 0;
}

int
uio_copyin_user(const char *c_cp, int n, uio_t uio)
{
	addr64_t cp = (const addr64_t)(uintptr_t)c_cp;

	while (n > 0 && uio->uio_iovcnt > 0 && uio_resid(uio)) {
		struct user_iovec *uiovp;
		uint64_t acnt;
		int error;

		uio_update_user(uio, 0);
		acnt = uio_curriovlen_user(uio);
		if (acnt == 0) {
			continue;
		}
		if (n > 0 && acnt > (uint64_t)n) {
			acnt = n;
		}

		uiovp = uio_uiovp(uio);

		KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, DBG_UIO_COPYIN)) | DBG_FUNC_START,
		    (uintptr_t)uiovp->iov_base, (int)cp, acnt, 0, 0);

		error = copyin(uiovp->iov_base, CAST_DOWN(caddr_t, cp), (size_t)acnt);

		KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, DBG_UIO_COPYIN)) | DBG_FUNC_END,
		    (uintptr_t)uiovp->iov_base, (int)cp, acnt, 0, 0);

		if (error) {
			return error;
		}

		uio_update_user(uio, (user_size_t)acnt);
		cp += acnt;
		n -= acnt;
	}
	return 0;
}

int
uio_copyout_sys(const char *c_cp, int n, uio_t uio)
{
	addr64_t cp = (const addr64_t)(uintptr_t)c_cp;

	while (n > 0 && uio->uio_iovcnt > 0 && uio_resid(uio)) {
		struct kern_iovec *kiovp;
		uint64_t acnt;

		uio_update_sys(uio, 0);
		acnt = uio_curriovlen_sys(uio);
		if (acnt == 0) {
			continue;
		}
		if (n > 0 && acnt > (uint64_t)n) {
			acnt = n;
		}

		kiovp = uio_kiovp(uio);

		copywithin(CAST_DOWN(caddr_t, cp), CAST_DOWN(caddr_t, kiovp_get_base(kiovp)),
		    (size_t)acnt);

		uio_update_sys(uio, (user_size_t)acnt);
		cp += acnt;
		n -= acnt;
	}
	return 0;
}

int
uio_copyin_sys(const char *c_cp, int n, uio_t uio)
{
	addr64_t cp = (const addr64_t)(uintptr_t)c_cp;

	while (n > 0 && uio->uio_iovcnt > 0 && uio_resid(uio)) {
		struct kern_iovec *kiovp;
		uint64_t acnt;

		uio_update_sys(uio, 0);
		acnt = uio_curriovlen_sys(uio);
		if (acnt == 0) {
			continue;
		}
		if (n > 0 && acnt > (uint64_t)n) {
			acnt = n;
		}

		kiovp = uio_kiovp(uio);

		copywithin(CAST_DOWN(caddr_t, kiovp_get_base(kiovp)), CAST_DOWN(caddr_t, cp),
		    (size_t)acnt);

		uio_update_sys(uio, (user_size_t)acnt);
		cp += acnt;
		n -= acnt;
	}
	return 0;
}

int
uio_copyout_phys_user(const char *c_cp, int n, uio_t uio)
{
	addr64_t cp = (const addr64_t)(uintptr_t)c_cp;

	while (n > 0 && uio->uio_iovcnt > 0 && uio_resid(uio)) {
		struct user_iovec *uiovp;
		uint64_t acnt;
		int error;

		uio_update_user(uio, 0);
		acnt = uio_curriovlen_user(uio);
		if (acnt == 0) {
			continue;
		}
		if (n > 0 && acnt > (uint64_t)n) {
			acnt = n;
		}

		acnt = MIN(acnt, UINT_MAX);
		uiovp = uio_uiovp(uio);

		KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, DBG_UIO_COPYOUT)) | DBG_FUNC_START,
		    (int)cp, (uintptr_t)uiovp->iov_base, acnt, 1, 0);

		error = copypv((addr64_t)cp, uiovp->iov_base, (unsigned int)acnt, cppvPsrc | cppvNoRefSrc);

		KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, DBG_UIO_COPYOUT)) | DBG_FUNC_END,
		    (int)cp, (uintptr_t)uiovp->iov_base, acnt, 1, 0);

		if (error) {    /* Copy virtual to physical */
			return EFAULT;
		}

		uio_update_user(uio, (user_size_t)acnt);
		cp += acnt;
		n -= acnt;
	}
	return 0;
}

int
uio_copyin_phys_user(const char *c_cp, int n, uio_t uio)
{
	addr64_t cp = (const addr64_t)(uintptr_t)c_cp;

	while (n > 0 && uio->uio_iovcnt > 0 && uio_resid(uio)) {
		struct user_iovec *uiovp;
		uint64_t acnt;
		int error;

		uio_update_user(uio, 0);
		acnt = uio_curriovlen_user(uio);
		if (acnt == 0) {
			continue;
		}
		if (n > 0 && acnt > (uint64_t)n) {
			acnt = n;
		}

		acnt = MIN(acnt, UINT_MAX);
		uiovp = uio_uiovp(uio);

		KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, DBG_UIO_COPYIN)) | DBG_FUNC_START,
		    (uintptr_t)uiovp->iov_base, (int)cp, acnt, 1, 0);

		error = copypv(uiovp->iov_base, (addr64_t)cp, (unsigned int)acnt, cppvPsnk | cppvNoRefSrc | cppvNoModSnk);

		KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, DBG_UIO_COPYIN)) | DBG_FUNC_END,
		    (uintptr_t)uiovp->iov_base, (int)cp, acnt, 1, 0);

		if (error) {    /* Copy virtual to physical */
			return EFAULT;
		}

		uio_update_user(uio, (user_size_t)acnt);
		cp += acnt;
		n -= acnt;
	}
	return 0;
}

int
uio_copyout_phys_sys(const char *c_cp, int n, uio_t uio)
{
	addr64_t cp = (const addr64_t)(uintptr_t)c_cp;

	while (n > 0 && uio->uio_iovcnt > 0 && uio_resid(uio)) {
		struct kern_iovec *kiovp;
		uint64_t acnt;
		int error;

		uio_update_sys(uio, 0);
		acnt = uio_curriovlen_sys(uio);
		if (acnt == 0) {
			continue;
		}
		if (n > 0 && acnt > (uint64_t)n) {
			acnt = n;
		}

		acnt = MIN(acnt, UINT_MAX);
		kiovp = uio_kiovp(uio);

		KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, DBG_UIO_COPYOUT)) | DBG_FUNC_START,
		    (int)cp, (uintptr_t)kiovp_get_base(kiovp), acnt, 2, 0);

		error = copypv((addr64_t)cp, (addr64_t)kiovp_get_base(kiovp), (unsigned int)acnt, cppvKmap | cppvPsrc | cppvNoRefSrc);

		KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, DBG_UIO_COPYOUT)) | DBG_FUNC_END,
		    (int)cp, (uintptr_t)kiovp_get_base(kiovp), acnt, 2, 0);

		if (error) {    /* Copy virtual to physical */
			return EFAULT;
		}

		uio_update_sys(uio, (user_size_t)acnt);
		cp += acnt;
		n -= acnt;
	}
	return 0;
}

int
uio_copyin_phys_sys(const char *c_cp, int n, uio_t uio)
{
	addr64_t cp = (const addr64_t)(uintptr_t)c_cp;

	while (n > 0 && uio->uio_iovcnt > 0 && uio_resid(uio)) {
		struct kern_iovec *kiovp;
		uint64_t acnt;
		int error;

		uio_update_sys(uio, 0);
		acnt = uio_curriovlen_sys(uio);
		if (acnt == 0) {
			continue;
		}
		if (n > 0 && acnt > (uint64_t)n) {
			acnt = n;
		}

		acnt = MIN(acnt, UINT_MAX);
		kiovp = uio_kiovp(uio);

		KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, DBG_UIO_COPYIN)) | DBG_FUNC_START,
		    (uintptr_t)kiovp_get_base(kiovp), (int)cp, acnt, 2, 0);

		error = copypv((addr64_t)kiovp_get_base(kiovp), (addr64_t)cp, (unsigned int)acnt, cppvKmap | cppvPsnk | cppvNoRefSrc | cppvNoModSnk);

		KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, DBG_UIO_COPYIN)) | DBG_FUNC_END,
		    (uintptr_t)kiovp_get_base(kiovp), (int)cp, acnt, 2, 0);

		if (error) {    /* Copy virtual to physical */
			return EFAULT;
		}

		uio_update_sys(uio, (user_size_t)acnt);
		cp += acnt;
		n -= acnt;
	}
	return 0;
}

/*
 * Give next character to user as result of read.
 */
int
ureadc(int c, struct uio *uio)
{
	struct kern_iovec *kiovp;
	struct user_iovec *uiovp;

	if (__improbable(uio_resid(uio) <= 0)) {
		panic("ureadc: non-positive resid");
	}

	if (IS_PURE_USER_SPACE_SEGFLG(uio->uio_segflg)) {
		uio_update_user(uio, 0);

		uiovp = uio_uiovp(uio);

		if (subyte((user_addr_t)uiovp->iov_base, c) < 0) {
			return EFAULT;
		}

		uio_update_user(uio, 1);
	} else if (IS_SYS_SPACE_SEGFLG(uio->uio_segflg)) {
		uio_update_sys(uio, 0);

		kiovp = uio_kiovp(uio);
		*(CAST_DOWN(caddr_t, kiovp_get_base(kiovp))) = (char)c;

		uio_update_sys(uio, 1);
	}
	return 0;
}

LIST_HEAD(generic_hash_head, generic);

/*
 * General routine to allocate a hash table.
 */
void *
hashinit(int elements, int type __unused, u_long *hashmask)
{
	struct generic_hash_head *hashtbl;
	vm_size_t hashsize;

	if (__improbable(elements <= 0)) {
		panic("hashinit: bad cnt");
	}

	hashsize = 1UL << (fls(elements) - 1);
	hashtbl = kalloc_type(struct generic_hash_head, hashsize, Z_WAITOK | Z_ZERO);
	if (hashtbl != NULL) {
		*hashmask = hashsize - 1;
	}
	return hashtbl;
}

void
hashdestroy(void *hash, int type __unused, u_long hashmask)
{
	assert(powerof2(hashmask + 1));
	kfree_type(struct generic_hash_head, hashmask + 1, hash);
}

/*
 * uio_resid - return the residual IO value for the given uio_t
 */
user_ssize_t
uio_resid( uio_t a_uio )
{
#if DEBUG
	if (a_uio == NULL) {
		printf("%s :%d - invalid uio_t\n", __FILE__, __LINE__);
	}
#endif /* DEBUG */

	/* return 0 if there are no active iovecs */
	if (a_uio == NULL) {
		return 0;
	}

	return a_uio->uio_resid_64;
}

/*
 * uio_setresid - set the residual IO value for the given uio_t
 */
void
uio_setresid( uio_t a_uio, user_ssize_t a_value )
{
#if DEBUG
	if (__improbable(a_uio == NULL)) {
		panic("invalid uio_t");
	}
#endif /* DEBUG */

	if (a_uio == NULL) {
		return;
	}

	a_uio->uio_resid_64 = a_value;
	return;
}

/*
 * uio_curriovbase - return the base address of the current iovec associated
 *	with the given uio_t.  May return 0.
 */
user_addr_t
uio_curriovbase( uio_t a_uio )
{
	struct kern_iovec *kiovp;
	struct user_iovec *uiovp;

	if (a_uio == NULL || a_uio->uio_iovcnt < 1) {
		return 0;
	}

	if (UIO_IS_USER_SPACE(a_uio)) {
		uiovp = uio_uiovp(a_uio);
		return uiovp->iov_base;
	}

	kiovp = uio_kiovp(a_uio);
	return (user_addr_t)kiovp_get_base(kiovp);
}

/*
 * uio_curriovlen_user - return the length value of the current iovec associated
 *	with the given uio_t.
 */
static user_size_t
uio_curriovlen_user(const uio_t __attribute__((nonnull)) a_uio)
{
	return uio_uiovp(a_uio)->iov_len;
}

/*
 * uio_curriovlen_sys - return the length value of the current iovec associated
 *	with the given uio_t.
 */
static user_size_t
uio_curriovlen_sys(const uio_t __attribute__((nonnull)) a_uio )
{
	return (user_size_t)uio_kiovp(a_uio)->iov_len;
}

/*
 * uio_curriovlen - return the length value of the current iovec associated
 *	with the given uio_t.
 */
user_size_t
uio_curriovlen( uio_t a_uio )
{
	if (a_uio == NULL || a_uio->uio_iovcnt < 1) {
		return 0;
	}

	if (UIO_IS_USER_SPACE(a_uio)) {
		return uio_curriovlen_user(a_uio);
	}

	return uio_curriovlen_sys(a_uio);
}

/*
 * uio_iovcnt - return count of active iovecs for the given uio_t
 */
int
uio_iovcnt( uio_t a_uio )
{
	if (a_uio == NULL) {
		return 0;
	}

	return a_uio->uio_iovcnt;
}

/*
 * uio_offset - return the current offset value for the given uio_t
 */
off_t
uio_offset( uio_t a_uio )
{
	if (a_uio == NULL) {
		return 0;
	}
	return a_uio->uio_offset;
}

/*
 * uio_setoffset - set the current offset value for the given uio_t
 */
void
uio_setoffset( uio_t a_uio, off_t a_offset )
{
	if (a_uio == NULL) {
		return;
	}
	a_uio->uio_offset = a_offset;
	return;
}

/*
 * uio_rw - return the read / write flag for the given uio_t
 */
int
uio_rw( uio_t a_uio )
{
	if (a_uio == NULL) {
		return -1;
	}
	return a_uio->uio_rw;
}

/*
 * uio_setrw - set the read / write flag for the given uio_t
 */
void
uio_setrw( uio_t a_uio, int a_value )
{
	if (a_uio == NULL) {
		return;
	}

	if (a_value == UIO_READ || a_value == UIO_WRITE) {
		a_uio->uio_rw = a_value;
	}
	return;
}

/*
 * uio_isuserspace - return non zero value if the address space
 * flag is for a user address space (could be 32 or 64 bit).
 */
int
uio_isuserspace( uio_t a_uio )
{
	if (a_uio == NULL) {
		return 0;
	}

	if (UIO_SEG_IS_USER_SPACE(a_uio->uio_segflg)) {
		return 1;
	}
	return 0;
}

static void
uio_init(uio_t uio,
    int a_iovcount,                   /* number of iovecs */
    off_t a_offset,                   /* current offset */
    int a_spacetype,                  /* type of address space */
    int a_iodirection,                /* read or write flag */
    void *iovecs)                     /* pointer to iovec array */
{
	assert(a_iovcount >= 0 && a_iovcount <= UIO_MAXIOV);
	assert(IS_VALID_UIO_SEGFLG(a_spacetype));
	assert(a_iodirection == UIO_READ || a_iodirection == UIO_WRITE);

	/*
	 * we use uio_segflg to indicate if the uio_t is the new format or
	 * old (pre LP64 support) legacy format
	 * This if-statement should canonicalize incoming space type
	 * to one of UIO_USERSPACE32/64, UIO_PHYS_USERSPACE32/64, or
	 * UIO_SYSSPACE/UIO_PHYS_SYSSPACE
	 */
	if (__improbable((1 << a_spacetype) & (UIOF_USERSPACE | UIOF_SYSSPACE32 | UIOF_PHYS_USERSPACE))) {
		if (a_spacetype == UIO_USERSPACE) {
			uio->uio_segflg = UIO_USERSPACE32;
		} else if (a_spacetype == UIO_SYSSPACE32) {
			uio->uio_segflg = UIO_SYSSPACE;
		} else if (a_spacetype == UIO_PHYS_USERSPACE) {
			uio->uio_segflg = UIO_PHYS_USERSPACE32;
		}
	} else {
		uio->uio_segflg = a_spacetype;
	}

	uio->uio_iovbase = iovecs;
	uio->uio_iovs = iovecs;
	uio->uio_max_iovs = a_iovcount;
	uio->uio_offset = a_offset;
	uio->uio_rw = a_iodirection;
	uio->uio_flags = UIO_FLAGS_INITED;
}

static void *
uio_alloc_iov_array(int a_spacetype, size_t a_iovcount)
{
	if (IS_SYS_OR_PHYS_SPACE_SEGFLG(a_spacetype)) {
		return kalloc_type(struct kern_iovec, a_iovcount, Z_WAITOK | Z_ZERO);
	}

	size_t bytes = UIO_SIZEOF_IOVS(a_iovcount);
	return kalloc_data(bytes, Z_WAITOK | Z_ZERO);
}

static void
uio_free_iov_array(int a_spacetype, void *iovs, size_t a_iovcount)
{
	if (IS_SYS_OR_PHYS_SPACE_SEGFLG(a_spacetype)) {
		kfree_type(struct kern_iovec, a_iovcount, iovs);
	} else {
		size_t bytes = UIO_SIZEOF_IOVS(a_iovcount);
		kfree_data(iovs, bytes);
	}
}

/*
 * uio_create - create an uio_t.
 *      Space is allocated to hold up to a_iovcount number of iovecs.  The uio_t
 *	is not fully initialized until all iovecs are added using uio_addiov calls.
 *	a_iovcount is the maximum number of iovecs you may add.
 */
uio_t
uio_create( int a_iovcount,                     /* number of iovecs */
    off_t a_offset,                                             /* current offset */
    int a_spacetype,                                            /* type of address space */
    int a_iodirection )                                 /* read or write flag */
{
	uio_t uio;
	void *iovecs;

	if (a_iovcount < 0 || a_iovcount > UIO_MAXIOV) {
		return NULL;
	}

	uio = kalloc_type(struct uio, Z_WAITOK | Z_ZERO | Z_NOFAIL);
	iovecs = uio_alloc_iov_array(a_spacetype, (size_t)a_iovcount);

	uio_init(uio, a_iovcount, a_offset, a_spacetype, a_iodirection, iovecs);

	/* leave a note that we allocated this uio_t */
	uio->uio_flags |= UIO_FLAGS_WE_ALLOCED;
#if DEBUG
	os_atomic_inc(&uio_t_count, relaxed);
#endif

	return uio;
}


/*
 * uio_createwithbuffer - create an uio_t.
 *      Create a uio_t using the given buffer.  The uio_t
 *	is not fully initialized until all iovecs are added using uio_addiov calls.
 *	a_iovcount is the maximum number of iovecs you may add.
 *	This call may fail if the given buffer is not large enough.
 */
__private_extern__ uio_t
uio_createwithbuffer( int a_iovcount,                   /* number of iovecs */
    off_t a_offset,                                                             /* current offset */
    int a_spacetype,                                                            /* type of address space */
    int a_iodirection,                                                          /* read or write flag */
    void *a_buf_p,                                                              /* pointer to a uio_t buffer */
    size_t a_buffer_size )                                                      /* size of uio_t buffer */
{
	uio_t uio = (uio_t) a_buf_p;
	void *iovecs = NULL;

	if (a_iovcount < 0 || a_iovcount > UIO_MAXIOV) {
		return NULL;
	}

	if (a_buffer_size < UIO_SIZEOF(a_iovcount)) {
		return NULL;
	}

	if (a_iovcount > 0) {
		iovecs = (uint8_t *)uio + sizeof(struct uio);
	}

	bzero(a_buf_p, a_buffer_size);
	uio_init(uio, a_iovcount, a_offset, a_spacetype, a_iodirection, iovecs);

	return uio;
}

/*
 * uio_iovsaddr_user - get the address of the iovec array for the given uio_t.
 * This returns the location of the iovecs within the uio.
 * NOTE - for compatibility mode we just return the current value in uio_iovs
 * which will increase as the IO is completed and is NOT embedded within the
 * uio, it is a seperate array of one or more iovecs.
 */
__private_extern__ struct user_iovec *
uio_iovsaddr_user( uio_t a_uio )
{
	if (a_uio == NULL) {
		return NULL;
	}

	return uio_uiovp(a_uio);
}

static void
_uio_reset(uio_t a_uio,
    off_t a_offset,                                             /* current offset */
    int a_iodirection)                                         /* read or write flag */
{
	void *my_iovs = a_uio->uio_iovbase;
	int my_max_iovs = a_uio->uio_max_iovs;

	if (my_iovs != NULL) {
		bzero(my_iovs, UIO_SIZEOF_IOVS(my_max_iovs));
	}

	a_uio->uio_iovs = my_iovs;
	a_uio->uio_iovcnt = 0;
	a_uio->uio_offset = a_offset;
	a_uio->uio_segflg = 0;
	a_uio->uio_rw = a_iodirection;
	a_uio->uio_resid_64 = 0;
}

void
uio_reset_fast( uio_t a_uio,
    off_t a_offset,                                             /* current offset */
    int a_spacetype,                                            /* type of address space */
    int a_iodirection )                                         /* read or write flag */
{
	_uio_reset(a_uio, a_offset, a_iodirection);

	a_uio->uio_segflg = a_spacetype;
}

/*
 * uio_reset - reset an uio_t.
 *      Reset the given uio_t to initial values.  The uio_t is not fully initialized
 *      until all iovecs are added using uio_addiov calls.
 *	The a_iovcount value passed in the uio_create is the maximum number of
 *	iovecs you may add.
 */
void
uio_reset( uio_t a_uio,
    off_t a_offset,                                             /* current offset */
    int a_spacetype,                                            /* type of address space */
    int a_iodirection )                                         /* read or write flag */
{
	if (a_uio == NULL) {
		return;
	}

	_uio_reset(a_uio, a_offset, a_iodirection);

	/*
	 * we use uio_segflg to indicate if the uio_t is the new format or
	 * old (pre LP64 support) legacy format
	 * This switch statement should canonicalize incoming space type
	 * to one of UIO_USERSPACE32/64, UIO_PHYS_USERSPACE32/64, or
	 * UIO_SYSSPACE/UIO_PHYS_SYSSPACE
	 */
	switch (a_spacetype) {
	case UIO_USERSPACE:
		a_uio->uio_segflg = UIO_USERSPACE32;
		break;
	case UIO_SYSSPACE32:
		a_uio->uio_segflg = UIO_SYSSPACE;
		break;
	case UIO_PHYS_USERSPACE:
		a_uio->uio_segflg = UIO_PHYS_USERSPACE32;
		break;
	default:
		a_uio->uio_segflg = a_spacetype;
		break;
	}
}

/*
 * uio_free - free a uio_t allocated via uio_init.  this also frees all
 *      associated iovecs.
 */
void
uio_free( uio_t a_uio )
{
#if DEBUG
	if (__improbable(a_uio == NULL)) {
		panic("passing NULL uio_t");
	}
#endif

	if (a_uio != NULL && (a_uio->uio_flags & UIO_FLAGS_WE_ALLOCED) != 0) {
#if DEBUG
		if (__improbable(os_atomic_dec_orig(&uio_t_count, relaxed) == 0)) {
			panic("uio_t_count underflow");
		}
#endif
		if (__improbable(a_uio->uio_max_iovs < 0 || a_uio->uio_max_iovs > UIO_MAXIOV)) {
			panic("%s: bad uio_max_iovs", __func__);
		}

		uio_free_iov_array(a_uio->uio_segflg, a_uio->uio_iovbase,
		    (size_t)a_uio->uio_max_iovs);

		kfree_type(struct uio, a_uio);
	}
}

/*
 * uio_addiov - add an iovec to the given uio_t.  You may call this up to
 *      the a_iovcount number that was passed to uio_create.  This call will
 *      increment the residual IO count as iovecs are added to the uio_t.
 *	returns 0 if add was successful else non zero.
 */
int
uio_addiov( uio_t a_uio, user_addr_t a_baseaddr, user_size_t a_length )
{
	int i;
	user_size_t resid;
	struct kern_iovec *kiovp;
	struct user_iovec *uiovp;

	if (__improbable(a_uio == NULL)) {
#if DEBUG
		panic("invalid uio_t");
#endif
		return -1;
	}

	if (__improbable(os_add_overflow(a_length, a_uio->uio_resid_64, &resid))) {
#if DEBUG
		panic("invalid length %lu", (unsigned long)a_length);
#endif
		return -1;
	}

	if (UIO_IS_USER_SPACE(a_uio)) {
		uiovp = uio_uiovp(a_uio);
		for (i = 0; i < a_uio->uio_max_iovs; i++) {
			if (uiovp[i].iov_len == 0 &&
			    uiovp[i].iov_base == 0) {
				uiovp[i].iov_len = a_length;
				uiovp[i].iov_base = a_baseaddr;
				a_uio->uio_iovcnt++;
				a_uio->uio_resid_64 = resid;
				return 0;
			}
		}
	} else {
		kiovp = uio_kiovp(a_uio);
		for (i = 0; i < a_uio->uio_max_iovs; i++) {
			if (kiovp[i].iov_len == 0 &&
			    kiovp_get_base(&kiovp[i]) == 0) {
				kiovp[i].iov_len = (u_int64_t)a_length;
				kiovp_set_base(&kiovp[i], (u_int64_t)a_baseaddr);
				a_uio->uio_iovcnt++;
				a_uio->uio_resid_64 = resid;
				return 0;
			}
		}
	}

	return -1;
}

/*
 * uio_getiov - get iovec data associated with the given uio_t.  Use
 *  a_index to iterate over each iovec (0 to (uio_iovcnt(uio_t) - 1)).
 *  a_baseaddr_p and a_length_p may be NULL.
 *      returns -1 when a_index is >= uio_t.uio_iovcnt or invalid uio_t.
 *	returns 0 when data is returned.
 */
int
uio_getiov( uio_t a_uio,
    int a_index,
    user_addr_t * a_baseaddr_p,
    user_size_t * a_length_p )
{
	struct kern_iovec *kiovp;
	struct user_iovec *uiovp;

	if (a_uio == NULL) {
#if DEBUG
		panic("invalid uio_t");
#endif /* DEBUG */
		return -1;
	}
	if (a_index < 0 || a_index >= a_uio->uio_iovcnt) {
		return -1;
	}

	if (UIO_IS_USER_SPACE(a_uio)) {
		uiovp = uio_uiovp(a_uio);

		if (a_baseaddr_p != NULL) {
			*a_baseaddr_p = uiovp[a_index].iov_base;
		}
		if (a_length_p != NULL) {
			*a_length_p = uiovp[a_index].iov_len;
		}
	} else {
		kiovp = uio_kiovp(a_uio);

		if (a_baseaddr_p != NULL) {
			*a_baseaddr_p = (user_addr_t)kiovp_get_base(&kiovp[a_index]);
		}
		if (a_length_p != NULL) {
			*a_length_p = (user_size_t)kiovp[a_index].iov_len;
		}
	}

	return 0;
}

/*
 * uio_calculateresid_user - runs through all iovecs associated with this
 *	uio_t and calculates (and sets) the residual IO count.
 */
__private_extern__ int
uio_calculateresid_user(uio_t __attribute((nonnull))a_uio)
{
	int                     i;
	u_int64_t               resid = 0;
	struct user_iovec *uiovp;

	a_uio->uio_iovcnt = a_uio->uio_max_iovs;
	uiovp = uio_uiovp(a_uio);
	a_uio->uio_resid_64 = 0;
	for (i = 0; i < a_uio->uio_max_iovs; i++) {
		if (uiovp[i].iov_len != 0) {
			if (uiovp[i].iov_len > LONG_MAX) {
				return EINVAL;
			}
			resid += uiovp[i].iov_len;
			if (resid > LONG_MAX) {
				return EINVAL;
			}
		}
	}
	a_uio->uio_resid_64 = (user_size_t)resid;

	/* position to first non zero length iovec (4235922) */
	while (a_uio->uio_iovcnt > 0 && uiovp->iov_len == 0) {
		a_uio->uio_iovcnt--;
		if (a_uio->uio_iovcnt > 0) {
			uiovp = uio_advance_user(a_uio);
		}
	}

	return 0;
}

/*
 * uio_update_user - update the given uio_t for a_count of completed IO.
 *	This call decrements the current iovec length and residual IO value
 *	and increments the current iovec base address and offset value.
 *	If the current iovec length is 0 then advance to the next
 *	iovec (if any).
 *      If the a_count passed in is 0, than only do the advancement
 *	over any 0 length iovec's.
 */
static void
uio_update_user(uio_t __attribute__((nonnull)) a_uio, user_size_t a_count)
{
	struct user_iovec *uiovp;

	uiovp = uio_uiovp(a_uio);

	/*
	 * if a_count == 0, then we are asking to skip over
	 * any empty iovs
	 */
	if (a_count) {
		if (a_count > uiovp->iov_len) {
			uiovp->iov_base += uiovp->iov_len;
			uiovp->iov_len = 0;
		} else {
			uiovp->iov_base += a_count;
			uiovp->iov_len -= a_count;
		}
		if (a_count > (user_size_t)a_uio->uio_resid_64) {
			a_uio->uio_offset += a_uio->uio_resid_64;
			a_uio->uio_resid_64 = 0;
		} else {
			a_uio->uio_offset += a_count;
			a_uio->uio_resid_64 -= a_count;
		}
	}
	/*
	 * advance to next iovec if current one is totally consumed
	 */
	while (a_uio->uio_iovcnt > 0 && uiovp->iov_len == 0) {
		a_uio->uio_iovcnt--;
		if (a_uio->uio_iovcnt > 0) {
			uiovp = uio_advance_user(a_uio);
		}
	}
}

/*
 * uio_update_sys - update the given uio_t for a_count of completed IO.
 *	This call decrements the current iovec length and residual IO value
 *	and increments the current iovec base address and offset value.
 *	If the current iovec length is 0 then advance to the next
 *	iovec (if any).
 *      If the a_count passed in is 0, than only do the advancement
 *	over any 0 length iovec's.
 */
static void
uio_update_sys(uio_t __attribute__((nonnull)) a_uio, user_size_t a_count)
{
	struct kern_iovec *kiovp;

	kiovp = uio_kiovp(a_uio);

	/*
	 * if a_count == 0, then we are asking to skip over
	 * any empty iovs
	 */
	if (a_count) {
		u_int64_t prev_base = kiovp_get_base(kiovp);
		if (a_count > kiovp->iov_len) {
			u_int64_t len = kiovp->iov_len;
			kiovp->iov_len = 0;
			kiovp_set_base(kiovp, prev_base + len);
		} else {
			kiovp->iov_len -= a_count;
			kiovp_set_base(kiovp, prev_base + a_count);
		}
		if (a_count > (user_size_t)a_uio->uio_resid_64) {
			a_uio->uio_offset += a_uio->uio_resid_64;
			a_uio->uio_resid_64 = 0;
		} else {
			a_uio->uio_offset += a_count;
			a_uio->uio_resid_64 -= a_count;
		}
	}
	/*
	 * advance to next iovec if current one is totally consumed
	 */
	while (a_uio->uio_iovcnt > 0 && kiovp->iov_len == 0) {
		a_uio->uio_iovcnt--;
		if (a_uio->uio_iovcnt > 0) {
			kiovp = uio_advance_sys(a_uio);
		}
	}
}

/*
 * uio_update - update the given uio_t for a_count of completed IO.
 *	This call decrements the current iovec length and residual IO value
 *	and increments the current iovec base address and offset value.
 *	If the current iovec length is 0 then advance to the next
 *	iovec (if any).
 *      If the a_count passed in is 0, than only do the advancement
 *	over any 0 length iovec's.
 */
void
uio_update(uio_t a_uio, user_size_t a_count)
{
	if (a_uio == NULL || a_uio->uio_iovcnt < 1) {
		return;
	}

	if (UIO_IS_USER_SPACE(a_uio)) {
		uio_update_user(a_uio, a_count);
	} else {
		uio_update_sys(a_uio, a_count);
	}
}

/*
 * uio_duplicate - allocate a new uio and make a copy of the given uio_t.
 *	may return NULL.
 */
uio_t
uio_duplicate(uio_t uio)
{
	uio_t new_uio;
	size_t n;
	struct kern_iovec *kiovp;
	struct user_iovec *uiovp;

	if (uio->uio_max_iovs < 0 || uio->uio_max_iovs > UIO_MAXIOV) {
		return NULL;
	}

	new_uio = kalloc_type(struct uio, Z_WAITOK | Z_ZERO | Z_NOFAIL);
	*new_uio = *uio;

	if (new_uio->uio_max_iovs > 0) {
		new_uio->uio_iovbase = uio_alloc_iov_array(new_uio->uio_segflg,
		    (size_t)new_uio->uio_max_iovs);
		new_uio->uio_iovs = new_uio->uio_iovbase;

		n = UIO_SIZEOF_IOVS(new_uio->uio_iovcnt);
		bcopy((const void *)uio->uio_iovs, (void *)new_uio->uio_iovs, n);
		if (UIO_IS_SYS_SPACE(new_uio)) {
			struct kern_iovec *kiovp_old = uio_kiovp(uio);

			kiovp = uio_kiovp(new_uio);

			for (n = 0; n < new_uio->uio_max_iovs; ++n) {
				kiovp_set_base(&kiovp[n],
				    kiovp_get_base(&kiovp_old[n]));
			}
		} else {
			uiovp = uio_uiovp(new_uio);
		}

		/* advance to first nonzero iovec */
		for (n = 0; n < new_uio->uio_max_iovs; ++n) {
			if (UIO_IS_USER_SPACE(new_uio)) {
				if (uiovp->iov_len != 0) {
					break;
				}

				uiovp = uio_advance_user(new_uio);
			} else {
				if (kiovp->iov_len != 0) {
					break;
				}

				kiovp = uio_advance_sys(new_uio);
			}
		}
	} else {
		new_uio->uio_iovs = NULL;
	}

	new_uio->uio_flags = UIO_FLAGS_WE_ALLOCED | UIO_FLAGS_INITED;
#if DEBUG
	os_atomic_inc(&uio_t_count, relaxed);
#endif

	return new_uio;
}

int
copyin_user_iovec_array(user_addr_t uaddr, int spacetype, int count, struct user_iovec *dst)
{
	size_t size_of_iovec = (spacetype == UIO_USERSPACE64 ? sizeof(struct user64_iovec) : sizeof(struct user32_iovec));
	int error;
	int i;

	// copyin to the front of "dst", without regard for putting records in the right places
	error = copyin(uaddr, dst, count * size_of_iovec);
	if (error) {
		return error;
	}

	// now, unpack the entries in reverse order, so we don't overwrite anything
	for (i = count - 1; i >= 0; i--) {
		if (spacetype == UIO_USERSPACE64) {
			struct user64_iovec iovec = ((struct user64_iovec *)dst)[i];
			dst[i].iov_base = (user_addr_t)iovec.iov_base;
			dst[i].iov_len = (user_size_t)iovec.iov_len;
		} else {
			struct user32_iovec iovec = ((struct user32_iovec *)dst)[i];
			dst[i].iov_base = iovec.iov_base;
			dst[i].iov_len = iovec.iov_len;
		}
	}

	return 0;
}
