/*
 * Copyright (c) 2015-2022 Apple Inc. All rights reserved.
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
#include <sys/systm.h>
#include <sys/filedesc.h>
#include <sys/proc_internal.h>
#include <sys/file_internal.h>
#include <sys/vnode_internal.h>
#include <sys/sysproto.h>
#include <security/audit/audit.h>
#include <skywalk/os_skywalk_private.h>

static int nxop_ioctl(struct fileproc *, u_long, caddr_t, vfs_context_t);
static int nxop_close(struct fileglob *, vfs_context_t);

static const struct fileops nexus_ctl_ops = {
	.fo_type     = DTYPE_NEXUS,
	.fo_read     = fo_no_read,
	.fo_write    = fo_no_write,
	.fo_ioctl    = nxop_ioctl,
	.fo_select   = fo_no_select,
	.fo_close    = nxop_close,
	.fo_drain    = fo_no_drain,
	.fo_kqfilter = fo_no_kqfilter,
};

static int
nxop_ioctl(struct fileproc *fp, u_long cmd, caddr_t data, vfs_context_t ctx)
{
	struct nxctl *nxctl;
	proc_t procp = vfs_context_proc(ctx);

	if ((nxctl = (struct nxctl *)fp_get_data(fp)) == NULL) {
		/* This is not a valid open file descriptor */
		return EBADF;
	}
	return nxioctl(nxctl, cmd, data, procp);
}

static int
nxop_close(struct fileglob *fg, vfs_context_t ctx)
{
#pragma unused(ctx)
	struct nxctl *nxctl;
	int error = 0;

	nxctl = (struct nxctl *)fg_get_data(fg);
	fg_set_data(fg, NULL);
	if (nxctl != NULL) {
		nxctl_dtor(nxctl);
	}

	return error;
}

int
__nexus_open(struct proc *p, struct __nexus_open_args *uap, int *retval)
{
	struct nxctl *nxctl = NULL;
	struct fileproc *fp = NULL;
	struct nxctl_init init;
	uuid_t nxctl_uuid;
	int fd = -1, err = 0;
	guardid_t guard;

	if (__improbable(uap->init == USER_ADDR_NULL ||
	    uap->init_len < sizeof(init))) {
		SK_DSC(p, "EINVAL: init %p, init_len %u", uap->init,
		    uap->init_len);
		err = EINVAL;
		goto done;
	}

	err = copyin(uap->init, (caddr_t)&init, sizeof(init));
	if (__improbable(err != 0)) {
		SK_DSC(p, "copyin err %d, init 0x%llx", err, SK_KVA(uap->init));
		goto done;
	}

	if (__improbable(init.ni_version != NEXUSCTL_INIT_CURRENT_VERSION)) {
		SK_DSC(p, "ENOTSUP: version %u != %u", init.ni_version,
		    NEXUSCTL_INIT_CURRENT_VERSION);
		err = ENOTSUP;
		goto done;
	}

	/* generate guard ID based on nexus controller UUID */
	uuid_generate_random(nxctl_uuid);
	sk_gen_guard_id(FALSE, nxctl_uuid, &guard);

	err = falloc_guarded(p, &fp, &fd, vfs_context_current(), &guard,
	    GUARD_CLOSE | GUARD_DUP | GUARD_SOCKET_IPC | GUARD_FILEPORT | GUARD_WRITE);
	if (__improbable(err != 0)) {
		SK_DSC(p, "falloc_guarded err %d", err);
		goto done;
	}

	nxctl = nxctl_create(p, fp, nxctl_uuid, &err);
	if (__improbable(nxctl == NULL)) {
		ASSERT(err != 0);
		SK_DSC(p, "nxctl_create err %d", err);
		goto done;
	}

	/* update userland with respect to guard ID, etc. */
	init.ni_guard = guard;
	err = copyout(&init, uap->init, sizeof(init));
	if (__improbable(err != 0)) {
		SK_DSC(p, "copyout err %d, init 0x%llx", err,
		    SK_KVA(uap->init));
		goto done;
	}

	fp->fp_flags |= FP_CLOEXEC | FP_CLOFORK;
	fp->fp_glob->fg_flag |= (FREAD | FWRITE);
	fp->fp_glob->fg_ops = &nexus_ctl_ops;
	fp_set_data(fp, nxctl);   /* ref from nxctl_create */

	proc_fdlock(p);
	procfdtbl_releasefd(p, fd, NULL);
	fp_drop(p, fd, fp, 1);
	proc_fdunlock(p);

	*retval = fd;

	SK_D("%s(%d) fd %d guard 0x%llx",
	    sk_proc_name_address(p), sk_proc_pid(p), fd, guard);

done:
	if (__improbable(err != 0)) {
		if (nxctl != NULL) {
			nxctl_dtor(nxctl);
			nxctl = NULL;
		}
		if (fp != NULL) {
			fp_free(p, fd, fp);
			fp = NULL;
		}
	}

	return err;
}

int
__nexus_register(struct proc *p, struct __nexus_register_args *uap, int *retval)
{
#pragma unused(retval)
	struct fileproc *fp;
	struct kern_nexus_provider *nxprov = NULL;
	struct nxctl *nxctl;
	struct nxprov_reg reg;
	int err = 0;

	AUDIT_ARG(fd, uap->ctl);

	if (__improbable(uap->reg == USER_ADDR_NULL ||
	    uap->reg_len < sizeof(reg) || uap->prov_uuid == USER_ADDR_NULL ||
	    uap->prov_uuid_len < sizeof(uuid_t))) {
		SK_DSC(p, "EINVAL: reg 0x%llx, reg_len %u, prov_uuid 0x%llx, "
		    "prov_uuid_len %u", SK_KVA(uap->reg), uap->reg_len,
		    SK_KVA(uap->prov_uuid), uap->prov_uuid_len);
		return EINVAL;
	}

	err = copyin(uap->reg, (caddr_t)&reg, sizeof(reg));
	if (err != 0) {
		SK_DSC(p, "copyin err %d, reg 0x%llx", err, SK_KVA(uap->reg));
		return err;
	}

	if (__improbable(reg.nxpreg_version != NXPROV_REG_CURRENT_VERSION)) {
		SK_DSC(p, "EINVAL: version %u != %u", reg.nxpreg_version,
		    NXPROV_REG_CURRENT_VERSION);
		return EINVAL;
	}

	if (__improbable(reg.nxpreg_params.nxp_namelen == 0 ||
	    reg.nxpreg_params.nxp_namelen > sizeof(nexus_name_t))) {
		SK_DSC(p, "EINVAL: namelen %u", reg.nxpreg_params.nxp_namelen);
		return EINVAL;
	}

	err = fp_get_ftype(p, uap->ctl, DTYPE_NEXUS, ENODEV, &fp);
	if (__improbable(err != 0)) {
		SK_DSC(p, "fp_get_ftype: %d", err);
		return err;
	}
	nxctl = (struct nxctl *)fp_get_data(fp);

	lck_mtx_lock(&nxctl->nxctl_lock);
	nxprov = nxprov_create(p, nxctl, &reg, &err);
	lck_mtx_unlock(&nxctl->nxctl_lock);
	if (__improbable(nxprov == NULL)) {
		ASSERT(err != 0);
		SK_DSC(p, "nxprov_create: %d", err);
		goto done;
	}

	err = copyout(&nxprov->nxprov_uuid, uap->prov_uuid, sizeof(uuid_t));
	if (__improbable(err != 0)) {
		SK_DSC(p, "copyout err %d, prov_uuid 0x%llx", err,
		    SK_KVA(uap->prov_uuid));
		goto done;
	}

done:
	fp_drop(p, uap->ctl, fp, 0);

	if (__improbable(err != 0 && nxprov != NULL)) {
		err = nxprov_close(nxprov, FALSE);
	}

	/* release extra ref from nxprov_create */
	if (nxprov != NULL) {
		nxprov_release(nxprov);
	}

	return err;
}

int
__nexus_deregister(struct proc *p, struct __nexus_deregister_args *uap,
    int *retval)
{
#pragma unused(retval)
	struct fileproc *fp;
	struct nxctl *nxctl = NULL;
	uuid_t nxprov_uuid;
	int err = 0;

	AUDIT_ARG(fd, uap->ctl);

	if (__improbable(uap->prov_uuid_len < sizeof(uuid_t))) {
		SK_DSC(p, "EINVAL: prov_len %u < %u", uap->prov_uuid_len,
		    sizeof(uuid_t));
		return EINVAL;
	}

	err = copyin(uap->prov_uuid, (caddr_t)&nxprov_uuid, sizeof(uuid_t));
	if (__improbable(err != 0)) {
		SK_DSC(p, "copyin err %d, prov_uuid 0x%llx", err,
		    SK_KVA(uap->prov_uuid));
		return err;
	}

	if (__improbable(uuid_is_null(nxprov_uuid))) {
		SK_DSC(p, "EINVAL: uuid_is_null");
		return EINVAL;
	}

	err = fp_get_ftype(p, uap->ctl, DTYPE_NEXUS, ENODEV, &fp);
	if (__improbable(err != 0)) {
		SK_DSC(p, "fp_get_ftype: %d", err);
		return err;
	}
	nxctl = (struct nxctl *)fp_get_data(fp);

	lck_mtx_lock(&nxctl->nxctl_lock);
	err = nxprov_destroy(nxctl, nxprov_uuid);
	lck_mtx_unlock(&nxctl->nxctl_lock);

	fp_drop(p, uap->ctl, fp, 0);

	return err;
}

int
__nexus_create(struct proc *p, struct __nexus_create_args *uap, int *retval)
{
#pragma unused(retval)
	struct fileproc *fp;
	struct kern_nexus *nx = NULL;
	struct nxctl *nxctl = NULL;
	uuid_t nxprov_uuid;
	int err = 0;

	AUDIT_ARG(fd, uap->ctl);

	if (__improbable(uap->prov_uuid_len < sizeof(uuid_t) ||
	    uap->nx_uuid_len < sizeof(uuid_t) ||
	    uap->nx_uuid == USER_ADDR_NULL)) {
		SK_DSC(p, "EINVAL: prov_uuid_len %u, nx_uuid_len %u, "
		    "nx_uuid 0x%llx", uap->prov_uuid_len, uap->nx_uuid_len,
		    SK_KVA(uap->nx_uuid));
		return EINVAL;
	}

	err = copyin(uap->prov_uuid, (caddr_t)&nxprov_uuid, sizeof(uuid_t));
	if (__improbable(err != 0)) {
		SK_DSC(p, "copyin err %d, prov_uuid 0x%llx", err,
		    SK_KVA(uap->prov_uuid));
		return err;
	}

	if (__improbable(uuid_is_null(nxprov_uuid))) {
		SK_DSC(p, "EINVAL: uuid_is_null");
		return EINVAL;
	}

	err = fp_get_ftype(p, uap->ctl, DTYPE_NEXUS, ENODEV, &fp);
	if (__improbable(err != 0)) {
		SK_DSC(p, "fp_get_ftype: %d", err);
		return err;
	}
	nxctl = (struct nxctl *)fp_get_data(fp);

	lck_mtx_lock(&nxctl->nxctl_lock);
	nx = nx_create(nxctl, nxprov_uuid, NEXUS_TYPE_UNDEFINED, NULL, NULL,
	    NULL, NULL, &err);
	lck_mtx_unlock(&nxctl->nxctl_lock);
	if (__improbable(nx == NULL)) {
		ASSERT(err != 0);
		SK_DSC(p, "nx_create: %d", err);
		goto done;
	}
	err = copyout(&nx->nx_uuid, uap->nx_uuid, sizeof(uuid_t));
	if (__improbable(err != 0)) {
		SK_DSC(p, "copyout err %d, nx_uuid 0x%llx", err,
		    SK_KVA(uap->nx_uuid));
		goto done;
	}

done:
	fp_drop(p, uap->ctl, fp, 0);

	/* release extra ref from nx_create */
	if (nx != NULL) {
		(void) nx_release(nx);
	}

	return err;
}

int
__nexus_destroy(struct proc *p, struct __nexus_destroy_args *uap, int *retval)
{
#pragma unused(retval)
	struct fileproc *fp;
	struct nxctl *nxctl = NULL;
	int err = 0;
	uuid_t nx_uuid;

	AUDIT_ARG(fd, uap->ctl);

	if (__improbable(uap->nx_uuid == USER_ADDR_NULL ||
	    uap->nx_uuid_len < sizeof(uuid_t))) {
		SK_DSC(p, "EINVAL: nx_uuid 0x%llx, nx_uuid_len %u",
		    SK_KVA(uap->nx_uuid), uap->nx_uuid_len);
		return EINVAL;
	}

	err = copyin(uap->nx_uuid, (caddr_t)&nx_uuid, sizeof(uuid_t));
	if (__improbable(err != 0)) {
		SK_DSC(p, "copyin err %d, nx_uuid 0x%llx", err,
		    SK_KVA(uap->nx_uuid));
		return err;
	}

	if (__improbable(uuid_is_null(nx_uuid))) {
		SK_DSC(p, "EINVAL: uuid_is_null");
		return EINVAL;
	}

	err = fp_get_ftype(p, uap->ctl, DTYPE_NEXUS, ENODEV, &fp);
	if (__improbable(err != 0)) {
		SK_DSC(p, "fp_get_ftype: %d", err);
		return err;
	}
	nxctl = (struct nxctl *)fp_get_data(fp);

	lck_mtx_lock(&nxctl->nxctl_lock);
	err = nx_destroy(nxctl, nx_uuid);
	lck_mtx_unlock(&nxctl->nxctl_lock);

	fp_drop(p, uap->ctl, fp, 0);

	return err;
}

int
__nexus_get_opt(struct proc *p, struct __nexus_get_opt_args *uap, int *retval)
{
#pragma unused(retval)
	struct fileproc *fp;
	struct nxctl *nxctl = NULL;
	struct sockopt sopt;
	uint32_t optlen;
	int err = 0;

	AUDIT_ARG(fd, uap->ctl);

	err = fp_get_ftype(p, uap->ctl, DTYPE_NEXUS, ENODEV, &fp);
	if (__improbable(err != 0)) {
		SK_DSC(p, "fp_get_ftype: %d", err);
		return err;
	}
	nxctl = (struct nxctl *)fp_get_data(fp);

	if (__improbable(uap->aoptlen == USER_ADDR_NULL)) {
		SK_DSC(p, "EINVAL: aoptlen == USER_ADDR_NULL");
		err = EINVAL;
		goto done;
	}

	if (uap->aoptval != USER_ADDR_NULL) {
		err = copyin(uap->aoptlen, &optlen, sizeof(optlen));
		if (__improbable(err != 0)) {
			SK_DSC(p, "copyin err %d, aoptlen 0x%llx", err,
			    SK_KVA(uap->aoptlen));
			goto done;
		}
	} else {
		optlen = 0;
	}

	bzero(&sopt, sizeof(sopt));
	sopt.sopt_dir = SOPT_GET;
	sopt.sopt_name = uap->opt;
	sopt.sopt_val = uap->aoptval;
	sopt.sopt_valsize = optlen;
	sopt.sopt_p = p;

	lck_mtx_lock(&nxctl->nxctl_lock);
	err = nxctl_get_opt(nxctl, &sopt);
	lck_mtx_unlock(&nxctl->nxctl_lock);
	if (__probable(err == 0)) {
		optlen = (uint32_t)sopt.sopt_valsize;
		err = copyout(&optlen, uap->aoptlen, sizeof(optlen));
#if SK_LOG
		if (__improbable(err != 0)) {
			SK_DSC(p, "copyout err %d, aoptlen 0x%llx", err,
			    SK_KVA(uap->aoptlen));
		}
#endif /* SK_LOG */
	}

done:
	fp_drop(p, uap->ctl, fp, 0);

	return err;
}

int
__nexus_set_opt(struct proc *p, struct __nexus_set_opt_args *uap, int *retval)
{
#pragma unused(retval)
	struct fileproc *fp;
	struct nxctl *nxctl = NULL;
	struct sockopt sopt;
	int err = 0;

	bzero(&sopt, sizeof(sopt));
	sopt.sopt_dir = SOPT_SET;
	sopt.sopt_name = uap->opt;
	sopt.sopt_val = uap->aoptval;
	sopt.sopt_valsize = uap->optlen;
	sopt.sopt_p = p;

	if (uap->ctl != __OS_NEXUS_SHARED_USER_CONTROLLER_FD) {
		AUDIT_ARG(fd, uap->ctl);

		err = fp_get_ftype(p, uap->ctl, DTYPE_NEXUS, ENODEV, &fp);
		if (__improbable(err != 0)) {
			SK_DSC(p, "fp_get_ftype: %d", err);
			return err;
		}
		nxctl = (struct nxctl *)fp_get_data(fp);

		lck_mtx_lock(&nxctl->nxctl_lock);
		err = nxctl_set_opt(nxctl, &sopt);
		lck_mtx_unlock(&nxctl->nxctl_lock);

		fp_drop(p, uap->ctl, fp, 0);
	} else {
		/* opt that don't have nxctl uses shared user nxctl */
		nxctl = usernxctl.ncd_nxctl;

		lck_mtx_lock(&nxctl->nxctl_lock);
		err = nxctl_set_opt(nxctl, &sopt);
		lck_mtx_unlock(&nxctl->nxctl_lock);
	}
	return err;
}
