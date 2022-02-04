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
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Rick Macklem at The University of Guelph.
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
 *	@(#)nfs_syscalls.c	8.5 (Berkeley) 3/30/95
 * FreeBSD-Id: nfs_syscalls.c,v 1.32 1997/11/07 08:53:25 phk Exp $
 */

#include <nfs/nfs_conf.h>

/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/file_internal.h>
#include <sys/filedesc.h>
#include <sys/stat.h>
#include <sys/vnode_internal.h>
#include <sys/mount_internal.h>
#include <sys/proc_internal.h> /* for fdflags */
#include <sys/uio_internal.h>
#include <sys/kauth.h>
#include <sys/sysctl.h>
#include <sys/ubc.h>
#include <sys/uio.h>
#include <sys/malloc.h>
#include <sys/kpi_mbuf.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/fcntl.h>
#include <sys/lockf.h>
#include <sys/syslog.h>
#include <sys/user.h>
#include <sys/sysproto.h>
#include <sys/kpi_socket.h>
#include <sys/fsevents.h>
#include <libkern/OSAtomic.h>
#include <kern/thread_call.h>
#include <kern/task.h>

#include <security/audit/audit.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <nfs/xdr_subs.h>
#include <nfs/rpcv2.h>
#include <nfs/nfsproto.h>
#include <nfs/nfs.h>
#include <nfs/nfsm_subs.h>
#include <nfs/nfsrvcache.h>
#include <nfs/nfs_gss.h>
#include <nfs/nfsmount.h>
#include <nfs/nfsnode.h>
#include <nfs/nfs_lock.h>
#if CONFIG_MACF
#include <security/mac_framework.h>
#endif

kern_return_t   thread_terminate(thread_t); /* XXX */

#if CONFIG_NFS_SERVER

extern const nfsrv_proc_t nfsrv_procs[NFS_NPROCS];

extern int nfsrv_wg_delay;
extern int nfsrv_wg_delay_v3;

static int nfsrv_require_resv_port = 0;
static time_t  nfsrv_idlesock_timer_on = 0;
static int nfsrv_sock_tcp_cnt = 0;
#define NFSD_MIN_IDLE_TIMEOUT 30
static int nfsrv_sock_idle_timeout = 3600; /* One hour */

int     nfssvc_export(user_addr_t argp);
int     nfssvc_exportstats(proc_t p, user_addr_t argp);
int     nfssvc_userstats(proc_t p, user_addr_t argp);
int     nfssvc_usercount(proc_t p, user_addr_t argp);
int     nfssvc_zerostats(void);
int     nfssvc_srvstats(proc_t p, user_addr_t argp);
int     nfssvc_nfsd(void);
int     nfssvc_addsock(socket_t, mbuf_t);
void    nfsrv_zapsock(struct nfsrv_sock *);
void    nfsrv_slpderef(struct nfsrv_sock *);
void    nfsrv_slpfree(struct nfsrv_sock *);

#endif /* CONFIG_NFS_SERVER */

/*
 * sysctl stuff
 */
SYSCTL_DECL(_vfs_generic);
SYSCTL_EXTENSIBLE_NODE(_vfs_generic, OID_AUTO, nfs, CTLFLAG_RW | CTLFLAG_LOCKED, 0, "nfs hinge");

#if CONFIG_NFS_CLIENT
SYSCTL_NODE(_vfs_generic_nfs, OID_AUTO, client, CTLFLAG_RW | CTLFLAG_LOCKED, 0, "nfs client hinge");
SYSCTL_INT(_vfs_generic_nfs_client, OID_AUTO, initialdowndelay, CTLFLAG_RW | CTLFLAG_LOCKED, &nfs_tprintf_initial_delay, 0, "");
SYSCTL_INT(_vfs_generic_nfs_client, OID_AUTO, nextdowndelay, CTLFLAG_RW | CTLFLAG_LOCKED, &nfs_tprintf_delay, 0, "");
SYSCTL_INT(_vfs_generic_nfs_client, OID_AUTO, iosize, CTLFLAG_RW | CTLFLAG_LOCKED, &nfs_iosize, 0, "");
SYSCTL_INT(_vfs_generic_nfs_client, OID_AUTO, access_cache_timeout, CTLFLAG_RW | CTLFLAG_LOCKED, &nfs_access_cache_timeout, 0, "");
SYSCTL_INT(_vfs_generic_nfs_client, OID_AUTO, allow_async, CTLFLAG_RW | CTLFLAG_LOCKED, &nfs_allow_async, 0, "");
SYSCTL_INT(_vfs_generic_nfs_client, OID_AUTO, statfs_rate_limit, CTLFLAG_RW | CTLFLAG_LOCKED, &nfs_statfs_rate_limit, 0, "");
SYSCTL_INT(_vfs_generic_nfs_client, OID_AUTO, nfsiod_thread_max, CTLFLAG_RW | CTLFLAG_LOCKED, &nfsiod_thread_max, 0, "");
SYSCTL_INT(_vfs_generic_nfs_client, OID_AUTO, nfsiod_thread_count, CTLFLAG_RD | CTLFLAG_LOCKED, &nfsiod_thread_count, 0, "");
SYSCTL_INT(_vfs_generic_nfs_client, OID_AUTO, lockd_mounts, CTLFLAG_RD | CTLFLAG_LOCKED, &nfs_lockd_mounts, 0, "");
SYSCTL_INT(_vfs_generic_nfs_client, OID_AUTO, max_async_writes, CTLFLAG_RW | CTLFLAG_LOCKED, &nfs_max_async_writes, 0, "");
SYSCTL_INT(_vfs_generic_nfs_client, OID_AUTO, access_delete, CTLFLAG_RW | CTLFLAG_LOCKED, &nfs_access_delete, 0, "");
SYSCTL_INT(_vfs_generic_nfs_client, OID_AUTO, access_dotzfs, CTLFLAG_RW | CTLFLAG_LOCKED, &nfs_access_dotzfs, 0, "");
SYSCTL_INT(_vfs_generic_nfs_client, OID_AUTO, access_for_getattr, CTLFLAG_RW | CTLFLAG_LOCKED, &nfs_access_for_getattr, 0, "");
SYSCTL_INT(_vfs_generic_nfs_client, OID_AUTO, idmap_ctrl, CTLFLAG_RW | CTLFLAG_LOCKED, &nfs_idmap_ctrl, 0, "");
SYSCTL_INT(_vfs_generic_nfs_client, OID_AUTO, callback_port, CTLFLAG_RW | CTLFLAG_LOCKED, &nfs_callback_port, 0, "");
SYSCTL_INT(_vfs_generic_nfs_client, OID_AUTO, is_mobile, CTLFLAG_RW | CTLFLAG_LOCKED, &nfs_is_mobile, 0, "");
SYSCTL_INT(_vfs_generic_nfs_client, OID_AUTO, squishy_flags, CTLFLAG_RW | CTLFLAG_LOCKED, &nfs_squishy_flags, 0, "");
SYSCTL_INT(_vfs_generic_nfs_client, OID_AUTO, mount_timeout, CTLFLAG_RW | CTLFLAG_LOCKED, &nfs_mount_timeout, 0, "");
SYSCTL_INT(_vfs_generic_nfs_client, OID_AUTO, mount_quick_timeout, CTLFLAG_RW | CTLFLAG_LOCKED, &nfs_mount_quick_timeout, 0, "");
SYSCTL_INT(_vfs_generic_nfs_client, OID_AUTO, split_open_owner, CTLFLAG_RW | CTLFLAG_LOCKED, &nfs_split_open_owner, 0, "");
SYSCTL_UINT(_vfs_generic_nfs_client, OID_AUTO, tcp_sockbuf, CTLFLAG_RW | CTLFLAG_LOCKED, &nfs_tcp_sockbuf, 0, "");
SYSCTL_UINT(_vfs_generic_nfs_client, OID_AUTO, debug_ctl, CTLFLAG_RW | CTLFLAG_LOCKED, &nfsclnt_debug_ctl, 0, "");
SYSCTL_INT(_vfs_generic_nfs_client, OID_AUTO, readlink_nocache, CTLFLAG_RW | CTLFLAG_LOCKED, &nfs_readlink_nocache, 0, "");
#if CONFIG_NFS_GSS
SYSCTL_INT(_vfs_generic_nfs_client, OID_AUTO, root_steals_gss_context, CTLFLAG_RW | CTLFLAG_LOCKED, &nfs_root_steals_ctx, 0, "");
#endif
#if CONFIG_NFS4
SYSCTL_STRING(_vfs_generic_nfs_client, OID_AUTO, default_nfs4domain, CTLFLAG_RW | CTLFLAG_LOCKED, nfs4_default_domain, sizeof(nfs4_default_domain), "");
#endif
#endif /* CONFIG_NFS_CLIENT */

#if CONFIG_NFS_SERVER
SYSCTL_NODE(_vfs_generic_nfs, OID_AUTO, server, CTLFLAG_RW | CTLFLAG_LOCKED, 0, "nfs server hinge");
SYSCTL_INT(_vfs_generic_nfs_server, OID_AUTO, wg_delay, CTLFLAG_RW | CTLFLAG_LOCKED, &nfsrv_wg_delay, 0, "");
SYSCTL_INT(_vfs_generic_nfs_server, OID_AUTO, wg_delay_v3, CTLFLAG_RW | CTLFLAG_LOCKED, &nfsrv_wg_delay_v3, 0, "");
SYSCTL_INT(_vfs_generic_nfs_server, OID_AUTO, require_resv_port, CTLFLAG_RW | CTLFLAG_LOCKED, &nfsrv_require_resv_port, 0, "");
SYSCTL_INT(_vfs_generic_nfs_server, OID_AUTO, async, CTLFLAG_RW | CTLFLAG_LOCKED, &nfsrv_async, 0, "");
SYSCTL_INT(_vfs_generic_nfs_server, OID_AUTO, export_hash_size, CTLFLAG_RW | CTLFLAG_LOCKED, &nfsrv_export_hash_size, 0, "");
SYSCTL_INT(_vfs_generic_nfs_server, OID_AUTO, reqcache_size, CTLFLAG_RW | CTLFLAG_LOCKED, &nfsrv_reqcache_size, 0, "");
SYSCTL_INT(_vfs_generic_nfs_server, OID_AUTO, request_queue_length, CTLFLAG_RW | CTLFLAG_LOCKED, &nfsrv_sock_max_rec_queue_length, 0, "");
SYSCTL_INT(_vfs_generic_nfs_server, OID_AUTO, user_stats, CTLFLAG_RW | CTLFLAG_LOCKED, &nfsrv_user_stat_enabled, 0, "");
SYSCTL_UINT(_vfs_generic_nfs_server, OID_AUTO, gss_context_ttl, CTLFLAG_RW | CTLFLAG_LOCKED, &nfsrv_gss_context_ttl, 0, "");
SYSCTL_UINT(_vfs_generic_nfs_server, OID_AUTO, debug_ctl, CTLFLAG_RW | CTLFLAG_LOCKED, &nfsrv_debug_ctl, 0, "");
#if CONFIG_FSE
SYSCTL_INT(_vfs_generic_nfs_server, OID_AUTO, fsevents, CTLFLAG_RW | CTLFLAG_LOCKED, &nfsrv_fsevents_enabled, 0, "");
#endif
SYSCTL_INT(_vfs_generic_nfs_server, OID_AUTO, nfsd_thread_max, CTLFLAG_RW | CTLFLAG_LOCKED, &nfsd_thread_max, 0, "");
SYSCTL_INT(_vfs_generic_nfs_server, OID_AUTO, nfsd_thread_count, CTLFLAG_RD | CTLFLAG_LOCKED, &nfsd_thread_count, 0, "");
SYSCTL_INT(_vfs_generic_nfs_server, OID_AUTO, nfsd_sock_idle_timeout, CTLFLAG_RW | CTLFLAG_LOCKED, &nfsrv_sock_idle_timeout, 0, "");
SYSCTL_INT(_vfs_generic_nfs_server, OID_AUTO, nfsd_tcp_connections, CTLFLAG_RD | CTLFLAG_LOCKED, &nfsrv_sock_tcp_cnt, 0, "");
#ifdef NFS_UC_Q_DEBUG
SYSCTL_INT(_vfs_generic_nfs_server, OID_AUTO, use_upcall_svc, CTLFLAG_RW | CTLFLAG_LOCKED, &nfsrv_uc_use_proxy, 0, "");
SYSCTL_INT(_vfs_generic_nfs_server, OID_AUTO, upcall_queue_limit, CTLFLAG_RW | CTLFLAG_LOCKED, &nfsrv_uc_queue_limit, 0, "");
SYSCTL_INT(_vfs_generic_nfs_server, OID_AUTO, upcall_queue_max_seen, CTLFLAG_RW | CTLFLAG_LOCKED, &nfsrv_uc_queue_max_seen, 0, "");
SYSCTL_INT(_vfs_generic_nfs_server, OID_AUTO, upcall_queue_count, CTLFLAG_RD | CTLFLAG_LOCKED, __DECONST(int *, &nfsrv_uc_queue_count), 0, "");
#endif
#endif /* CONFIG_NFS_SERVER */

#if !CONFIG_NFS_CLIENT
#define __no_nfs_client_unused      __unused
#else
#define __no_nfs_client_unused      /* nothing */
#endif

int
nfsclnt(
	__unused proc_t p,
	struct nfsclnt_args *uap __no_nfs_client_unused,
	__unused int *retval)
{
#if CONFIG_NFS_CLIENT
	int error;
	vnode_t vp;
	vfs_context_t ctx = vfs_context_current();

	if (nfsclnt_device_add()) {
		printf("nfsclnt: unable to open chardev /dev/%s\n", NFSCLNT_DEVICE);
	}

	if ((error = vnode_lookup("/dev/" NFSCLNT_DEVICE, 0, &vp, ctx))) {
		printf("nfsclnt: unable to find /dev/%s, err %d\n", NFSCLNT_DEVICE, error);
		return ENOSYS;
	}

	if ((error = VNOP_IOCTL(vp, uap->flag, (caddr_t)uap->argp, 0, ctx))) {
		printf("nfsclnt: ioctl of /dev/%s returned %d\n", NFSCLNT_DEVICE, error);
		vnode_put(vp);
		return error;
	}

	vnode_put(vp);
	return 0;
#else
	return ENOSYS;
#endif /* CONFIG_NFS_CLIENT */
}

#if CONFIG_NFS_CLIENT

/*
 * Asynchronous I/O threads for client NFS.
 * They do read-ahead and write-behind operations on the block I/O cache.
 *
 * The pool of up to nfsiod_thread_max threads is launched on demand and exit
 * when unused for a while.  There are as many nfsiod structs as there are
 * nfsiod threads; however there's no strict tie between a thread and a struct.
 * Each thread puts an nfsiod on the free list and sleeps on it.  When it wakes
 * up, it removes the next struct nfsiod from the queue and services it.  Then
 * it will put the struct at the head of free list and sleep on it.
 * Async requests will pull the next struct nfsiod from the head of the free list,
 * put it on the work queue, and wake whatever thread is waiting on that struct.
 */

/*
 * nfsiod thread exit routine
 *
 * Must be called with nfsiod_mutex held so that the
 * decision to terminate is atomic with the termination.
 */
void
nfsiod_terminate(struct nfsiod *niod)
{
	nfsiod_thread_count--;
	lck_mtx_unlock(&nfsiod_mutex);
	if (niod) {
		kfree_type(struct nfsiod, niod);
	} else {
		printf("nfsiod: terminating without niod\n");
	}
	thread_terminate(current_thread());
	/*NOTREACHED*/
}

/* nfsiod thread startup routine */
void
nfsiod_thread(void)
{
	struct nfsiod *niod;
	int error;

	niod = kalloc_type(struct nfsiod, Z_WAITOK | Z_ZERO | Z_NOFAIL);
	lck_mtx_lock(&nfsiod_mutex);
	TAILQ_INSERT_HEAD(&nfsiodfree, niod, niod_link);
	wakeup(current_thread());
	error = msleep0(niod, &nfsiod_mutex, PWAIT | PDROP, "nfsiod", NFS_ASYNCTHREADMAXIDLE * hz, nfsiod_continue);
	/* shouldn't return... so we have an error */
	/* remove an old nfsiod struct and terminate */
	lck_mtx_lock(&nfsiod_mutex);
	if ((niod = TAILQ_LAST(&nfsiodfree, nfsiodlist))) {
		TAILQ_REMOVE(&nfsiodfree, niod, niod_link);
	}
	nfsiod_terminate(niod);
	/*NOTREACHED*/
}

/*
 * Start up another nfsiod thread.
 * (unless we're already maxed out and there are nfsiods running)
 */
int
nfsiod_start(void)
{
	thread_t thd = THREAD_NULL;

	lck_mtx_lock(&nfsiod_mutex);
	if ((nfsiod_thread_count >= NFSIOD_MAX) && (nfsiod_thread_count > 0)) {
		lck_mtx_unlock(&nfsiod_mutex);
		return EBUSY;
	}
	nfsiod_thread_count++;
	if (kernel_thread_start((thread_continue_t)nfsiod_thread, NULL, &thd) != KERN_SUCCESS) {
		lck_mtx_unlock(&nfsiod_mutex);
		return EBUSY;
	}
	/* wait for the thread to complete startup */
	msleep(thd, &nfsiod_mutex, PWAIT | PDROP, "nfsiodw", NULL);
	thread_deallocate(thd);
	return 0;
}

/*
 * Continuation for Asynchronous I/O threads for NFS client.
 *
 * Grab an nfsiod struct to work on, do some work, then drop it
 */
int
nfsiod_continue(int error)
{
	struct nfsiod *niod;
	struct nfsmount *nmp;
	struct nfsreq *req, *treq;
	struct nfs_reqqhead iodq;
	int morework;

	lck_mtx_lock(&nfsiod_mutex);
	niod = TAILQ_FIRST(&nfsiodwork);
	if (!niod) {
		/* there's no work queued up */
		/* remove an old nfsiod struct and terminate */
		if ((niod = TAILQ_LAST(&nfsiodfree, nfsiodlist))) {
			TAILQ_REMOVE(&nfsiodfree, niod, niod_link);
		}
		nfsiod_terminate(niod);
		/*NOTREACHED*/
	}
	TAILQ_REMOVE(&nfsiodwork, niod, niod_link);

worktodo:
	while ((nmp = niod->niod_nmp)) {
		if (nmp == NULL) {
			niod->niod_nmp = NULL;
			break;
		}

		/*
		 * Service this mount's async I/O queue.
		 *
		 * In order to ensure some level of fairness between mounts,
		 * we grab all the work up front before processing it so any
		 * new work that arrives will be serviced on a subsequent
		 * iteration - and we have a chance to see if other work needs
		 * to be done (e.g. the delayed write queue needs to be pushed
		 * or other mounts are waiting for an nfsiod).
		 */
		/* grab the current contents of the queue */
		TAILQ_INIT(&iodq);
		TAILQ_CONCAT(&iodq, &nmp->nm_iodq, r_achain);
		/* Mark each iod request as being managed by an iod */
		TAILQ_FOREACH(req, &iodq, r_achain) {
			lck_mtx_lock(&req->r_mtx);
			assert(!(req->r_flags & R_IOD));
			req->r_flags |= R_IOD;
			lck_mtx_unlock(&req->r_mtx);
		}
		lck_mtx_unlock(&nfsiod_mutex);

		/* process the queue */
		TAILQ_FOREACH_SAFE(req, &iodq, r_achain, treq) {
			TAILQ_REMOVE(&iodq, req, r_achain);
			req->r_achain.tqe_next = NFSREQNOLIST;
			req->r_callback.rcb_func(req);
		}

		/* now check if there's more/other work to be done */
		lck_mtx_lock(&nfsiod_mutex);
		morework = !TAILQ_EMPTY(&nmp->nm_iodq);
		if (!morework || !TAILQ_EMPTY(&nfsiodmounts)) {
			/*
			 * we're going to stop working on this mount but if the
			 * mount still needs more work so queue it up
			 */
			if (morework && nmp->nm_iodlink.tqe_next == NFSNOLIST) {
				TAILQ_INSERT_TAIL(&nfsiodmounts, nmp, nm_iodlink);
			}
			nmp->nm_niod = NULL;
			niod->niod_nmp = NULL;
		}
	}

	/* loop if there's still a mount to work on */
	if (!niod->niod_nmp && !TAILQ_EMPTY(&nfsiodmounts)) {
		niod->niod_nmp = TAILQ_FIRST(&nfsiodmounts);
		TAILQ_REMOVE(&nfsiodmounts, niod->niod_nmp, nm_iodlink);
		niod->niod_nmp->nm_iodlink.tqe_next = NFSNOLIST;
	}
	if (niod->niod_nmp) {
		goto worktodo;
	}

	/* queue ourselves back up - if there aren't too many threads running */
	if (nfsiod_thread_count <= NFSIOD_MAX) {
		TAILQ_INSERT_HEAD(&nfsiodfree, niod, niod_link);
		error = msleep0(niod, &nfsiod_mutex, PWAIT | PDROP, "nfsiod", NFS_ASYNCTHREADMAXIDLE * hz, nfsiod_continue);
		/* shouldn't return... so we have an error */
		/* remove an old nfsiod struct and terminate */
		lck_mtx_lock(&nfsiod_mutex);
		if ((niod = TAILQ_LAST(&nfsiodfree, nfsiodlist))) {
			TAILQ_REMOVE(&nfsiodfree, niod, niod_link);
		}
	}
	nfsiod_terminate(niod);
	/*NOTREACHED*/
	return 0;
}

#endif /* CONFIG_NFS_CLIENT */

/* NFS hooks */

/* NFS hooks variable */
struct nfs_hooks nfsh = {
	.f_vinvalbuf      = NULL,
	.f_buf_page_inval = NULL
};

/* NFS hooks registration functions */
void
nfs_register_hooks(struct nfs_hooks *hooks)
{
	nfsh.f_vinvalbuf = hooks->f_vinvalbuf;
	nfsh.f_buf_page_inval = hooks->f_buf_page_inval;
}

void
nfs_unregister_hooks(void)
{
	memset(&nfsh, 0, sizeof(nfsh));
}

/* NFS hooks wrappers */
int
nfs_vinvalbuf(vnode_t vp, int flags, vfs_context_t ctx, int intrflg)
{
	if (nfsh.f_vinvalbuf == NULL) {
		return 0;
	}

	return nfsh.f_vinvalbuf(vp, flags, ctx, intrflg);
}

int
nfs_buf_page_inval(vnode_t vp, off_t offset)
{
	if (nfsh.f_buf_page_inval == NULL) {
		return 0;
	}

	return nfsh.f_buf_page_inval(vp, offset);
}

#if !CONFIG_NFS_SERVER
#define __no_nfs_server_unused      __unused
#else
#define __no_nfs_server_unused      /* nothing */
#endif

/*
 * NFS server system calls
 * getfh() lives here too, but maybe should move to kern/vfs_syscalls.c
 */

#if CONFIG_NFS_SERVER
static struct nfs_exportfs *
nfsrv_find_exportfs(const char *ptr)
{
	struct nfs_exportfs *nxfs;

	LIST_FOREACH(nxfs, &nfsrv_exports, nxfs_next) {
		if (!strncmp(nxfs->nxfs_path, ptr, MAXPATHLEN)) {
			break;
		}
	}
	if (nxfs && strncmp(nxfs->nxfs_path, ptr, strlen(nxfs->nxfs_path))) {
		nxfs = NULL;
	}

	return nxfs;
}

#define DATA_VOLUME_MP "/System/Volumes/Data" // PLATFORM_DATA_VOLUME_MOUNT_POINT

/*
 * Get file handle system call
 */
int
getfh(
	proc_t p __no_nfs_server_unused,
	struct getfh_args *uap __no_nfs_server_unused,
	__unused int *retval)
{
	vnode_t vp;
	struct nfs_filehandle nfh;
	int error, fhlen = 0, fidlen;
	struct nameidata nd;
	char path[MAXPATHLEN], real_mntonname[MAXPATHLEN], *ptr;
	size_t datavol_len = strlen(DATA_VOLUME_MP);
	size_t pathlen;
	struct nfs_exportfs *nxfs;
	struct nfs_export *nx;

	/*
	 * Must be super user
	 */
	error = proc_suser(p);
	if (error) {
		return error;
	}

	error = copyinstr(uap->fname, path, MAXPATHLEN, &pathlen);
	if (!error) {
		error = copyin(uap->fhp, &fhlen, sizeof(fhlen));
	}
	if (error) {
		return error;
	}
	/* limit fh size to length specified (or v3 size by default) */
	if ((fhlen != NFSV2_MAX_FH_SIZE) && (fhlen != NFSV3_MAX_FH_SIZE)) {
		fhlen = NFSV3_MAX_FH_SIZE;
	}
	fidlen = fhlen - sizeof(struct nfs_exphandle);

	if (!nfsrv_is_initialized()) {
		return EINVAL;
	}

	NDINIT(&nd, LOOKUP, OP_LOOKUP, FOLLOW | LOCKLEAF | AUDITVNPATH1,
	    UIO_SYSSPACE, CAST_USER_ADDR_T(path), vfs_context_current());
	error = namei(&nd);
	if (error) {
		return error;
	}
	nameidone(&nd);

	vp = nd.ni_vp;

	// find exportfs that matches f_mntonname
	lck_rw_lock_shared(&nfsrv_export_rwlock);
	ptr = vfs_statfs(vnode_mount(vp))->f_mntonname;
	if ((nxfs = nfsrv_find_exportfs(ptr)) == NULL) {
		/*
		 * The f_mntonname might be a firmlink path.  Resolve
		 * it into a physical path and try again.
		 */
		int pathbuflen = MAXPATHLEN;
		vnode_t rvp;

		error = VFS_ROOT(vnode_mount(vp), &rvp, vfs_context_current());
		if (error) {
			goto out;
		}
		error = vn_getpath_ext(rvp, NULLVP, real_mntonname, &pathbuflen,
		    VN_GETPATH_FSENTER | VN_GETPATH_NO_FIRMLINK);
		vnode_put(rvp);
		if (error) {
			goto out;
		}
		ptr = real_mntonname;
		nxfs = nfsrv_find_exportfs(ptr);
	}
	if (nxfs == NULL) {
		error = EINVAL;
		goto out;
	}
	// find export that best matches remainder of path
	if (!strncmp(path, nxfs->nxfs_path, strlen(nxfs->nxfs_path))) {
		ptr = path + strlen(nxfs->nxfs_path);
	} else if (!strncmp(path, DATA_VOLUME_MP, datavol_len) && !strncmp(path + datavol_len, nxfs->nxfs_path, strlen(nxfs->nxfs_path))) {
		ptr = path + datavol_len + strlen(nxfs->nxfs_path);
	} else {
		error = EINVAL;
		goto out;
	}

	while (*ptr && (*ptr == '/')) {
		ptr++;
	}
	LIST_FOREACH(nx, &nxfs->nxfs_exports, nx_next) {
		size_t len = strlen(nx->nx_path);
		if (len == 0) { // we've hit the export entry for the root directory
			break;
		}
		if (!strncmp(nx->nx_path, ptr, len)) {
			break;
		}
	}
	if (!nx) {
		error = EINVAL;
		goto out;
	}

	bzero(&nfh, sizeof(nfh));
	nfh.nfh_xh.nxh_version = htonl(NFS_FH_VERSION);
	nfh.nfh_xh.nxh_fsid = htonl(nxfs->nxfs_id);
	nfh.nfh_xh.nxh_expid = htonl(nx->nx_id);
	nfh.nfh_xh.nxh_flags = 0;
	nfh.nfh_xh.nxh_reserved = 0;
	nfh.nfh_len = fidlen;
	error = VFS_VPTOFH(vp, (int*)&nfh.nfh_len, &nfh.nfh_fid[0], NULL);
	if (nfh.nfh_len > (uint32_t)fidlen) {
		error = EOVERFLOW;
	}
	nfh.nfh_xh.nxh_fidlen = nfh.nfh_len;
	nfh.nfh_len += sizeof(nfh.nfh_xh);
	nfh.nfh_fhp = (u_char*)&nfh.nfh_xh;

out:
	lck_rw_done(&nfsrv_export_rwlock);
	vnode_put(vp);
	if (error) {
		return error;
	}
	/*
	 * At first blush, this may appear to leak a kernel stack
	 * address, but the copyout() never reaches &nfh.nfh_fhp
	 * (sizeof(fhandle_t) < sizeof(nfh)).
	 */
	error = copyout((caddr_t)&nfh, uap->fhp, sizeof(fhandle_t));
	return error;
}
#endif /* CONFIG_NFS_SERVER */

#if CONFIG_NFS_SERVER
extern const struct fileops vnops;

/*
 * syscall for the rpc.lockd to use to translate a NFS file handle into
 * an open descriptor.
 *
 * warning: do not remove the suser() call or this becomes one giant
 * security hole.
 */
int
fhopen(proc_t p __no_nfs_server_unused,
    struct fhopen_args *uap __no_nfs_server_unused,
    int32_t *retval __no_nfs_server_unused)
{
	vnode_t vp;
	struct nfs_filehandle nfh;
	struct nfs_export *nx;
	struct nfs_export_options *nxo;
	struct flock lf;
	struct fileproc *fp, *nfp;
	int fmode, error, type;
	int indx;
	vfs_context_t ctx = vfs_context_current();
	kauth_action_t action;

	/*
	 * Must be super user
	 */
	error = suser(vfs_context_ucred(ctx), 0);
	if (error) {
		return error;
	}

	if (!nfsrv_is_initialized()) {
		return EINVAL;
	}

	fmode = FFLAGS(uap->flags);
	/* why not allow a non-read/write open for our lockd? */
	if (((fmode & (FREAD | FWRITE)) == 0) || (fmode & O_CREAT)) {
		return EINVAL;
	}

	error = copyin(uap->u_fhp, &nfh.nfh_len, sizeof(nfh.nfh_len));
	if (error) {
		return error;
	}
	if ((nfh.nfh_len < (int)sizeof(struct nfs_exphandle)) ||
	    (nfh.nfh_len > (int)NFSV3_MAX_FH_SIZE)) {
		return EINVAL;
	}
	error = copyin(uap->u_fhp, &nfh, sizeof(nfh.nfh_len) + nfh.nfh_len);
	if (error) {
		return error;
	}
	nfh.nfh_fhp = (u_char*)&nfh.nfh_xh;

	lck_rw_lock_shared(&nfsrv_export_rwlock);
	/* now give me my vnode, it gets returned to me with a reference */
	error = nfsrv_fhtovp(&nfh, NULL, &vp, &nx, &nxo);
	lck_rw_done(&nfsrv_export_rwlock);
	if (error) {
		if (error == NFSERR_TRYLATER) {
			error = EAGAIN; // XXX EBUSY? Or just leave as TRYLATER?
		}
		return error;
	}

	/*
	 * From now on we have to make sure not
	 * to forget about the vnode.
	 * Any error that causes an abort must vnode_put(vp).
	 * Just set error = err and 'goto bad;'.
	 */

	/*
	 * from vn_open
	 */
	if (vnode_vtype(vp) == VSOCK) {
		error = EOPNOTSUPP;
		goto bad;
	}

	/* disallow write operations on directories */
	if (vnode_isdir(vp) && (fmode & (FWRITE | O_TRUNC))) {
		error = EISDIR;
		goto bad;
	}

#if CONFIG_MACF
	if ((error = mac_vnode_check_open(ctx, vp, fmode))) {
		goto bad;
	}
#endif

	/* compute action to be authorized */
	action = 0;
	if (fmode & FREAD) {
		action |= KAUTH_VNODE_READ_DATA;
	}
	if (fmode & (FWRITE | O_TRUNC)) {
		action |= KAUTH_VNODE_WRITE_DATA;
	}
	if ((error = vnode_authorize(vp, NULL, action, ctx)) != 0) {
		goto bad;
	}

	if ((error = VNOP_OPEN(vp, fmode, ctx))) {
		goto bad;
	}
	if ((error = vnode_ref_ext(vp, fmode, 0))) {
		goto bad;
	}

	/*
	 * end of vn_open code
	 */

	// starting here... error paths should call vn_close/vnode_put
	if ((error = falloc(p, &nfp, &indx, ctx)) != 0) {
		vn_close(vp, fmode & FMASK, ctx);
		goto bad;
	}
	fp = nfp;

	fp->fp_glob->fg_flag = fmode & FMASK;
	fp->fp_glob->fg_ops = &vnops;
	fp->fp_glob->fg_data = (caddr_t)vp;

	// XXX do we really need to support this with fhopen()?
	if (fmode & (O_EXLOCK | O_SHLOCK)) {
		lf.l_whence = SEEK_SET;
		lf.l_start = 0;
		lf.l_len = 0;
		if (fmode & O_EXLOCK) {
			lf.l_type = F_WRLCK;
		} else {
			lf.l_type = F_RDLCK;
		}
		type = F_FLOCK;
		if ((fmode & FNONBLOCK) == 0) {
			type |= F_WAIT;
		}
		if ((error = VNOP_ADVLOCK(vp, (caddr_t)fp->fp_glob, F_SETLK, &lf, type, ctx, NULL))) {
			struct vfs_context context = *vfs_context_current();
			/* Modify local copy (to not damage thread copy) */
			context.vc_ucred = fp->fp_glob->fg_cred;

			vn_close(vp, fp->fp_glob->fg_flag, &context);
			fp_free(p, indx, fp);
			goto bad;
		}
		fp->fp_glob->fg_flag |= FWASLOCKED;
	}

	vnode_put(vp);

	proc_fdlock(p);
	procfdtbl_releasefd(p, indx, NULL);
	fp_drop(p, indx, fp, 1);
	proc_fdunlock(p);

	*retval = indx;
	return 0;

bad:
	vnode_put(vp);
	return error;
}
#endif /* CONFIG_NFS_SERVER */

#if CONFIG_NFS_SERVER
/*
 * NFS server pseudo system call
 */
int
nfssvc(proc_t p __no_nfs_server_unused,
    struct nfssvc_args *uap __no_nfs_server_unused,
    __unused int *retval)
{
	mbuf_t nam;
	struct user_nfsd_args user_nfsdarg;
	socket_t so;
	int error;

	AUDIT_ARG(cmd, uap->flag);

	/*
	 * Must be super user for NFSSVC_NFSD and NFSSVC_ADDSOCK operations.
	 */
	if (((uap->flag == NFSSVC_NFSD) || (uap->flag == NFSSVC_ADDSOCK)) && ((error = proc_suser(p)))) {
		return error;
	}
#if CONFIG_MACF
	error = mac_system_check_nfsd(kauth_cred_get());
	if (error) {
		return error;
	}
#endif

	/* make sure NFS server data structures have been initialized */
	nfsrv_init();

	if (uap->flag & NFSSVC_ADDSOCK) {
		if (IS_64BIT_PROCESS(p)) {
			error = copyin(uap->argp, (caddr_t)&user_nfsdarg, sizeof(user_nfsdarg));
		} else {
			struct nfsd_args    tmp_args;
			error = copyin(uap->argp, (caddr_t)&tmp_args, sizeof(tmp_args));
			if (error == 0) {
				user_nfsdarg.sock = tmp_args.sock;
				user_nfsdarg.name = CAST_USER_ADDR_T(tmp_args.name);
				user_nfsdarg.namelen = tmp_args.namelen;
			}
		}
		if (error) {
			return error;
		}
		/* get the socket */
		error = file_socket(user_nfsdarg.sock, &so);
		if (error) {
			return error;
		}
		/* Get the client address for connected sockets. */
		if (user_nfsdarg.name == USER_ADDR_NULL || user_nfsdarg.namelen == 0) {
			nam = NULL;
		} else {
			error = sockargs(&nam, user_nfsdarg.name, user_nfsdarg.namelen, MBUF_TYPE_SONAME);
			if (error) {
				/* drop the iocount file_socket() grabbed on the file descriptor */
				file_drop(user_nfsdarg.sock);
				return error;
			}
		}
		/*
		 * nfssvc_addsock() will grab a retain count on the socket
		 * to keep the socket from being closed when nfsd closes its
		 * file descriptor for it.
		 */
		error = nfssvc_addsock(so, nam);
		/* drop the iocount file_socket() grabbed on the file descriptor */
		file_drop(user_nfsdarg.sock);
	} else if (uap->flag & NFSSVC_NFSD) {
		error = nfssvc_nfsd();
	} else if (uap->flag & NFSSVC_EXPORT) {
		error = nfssvc_export(uap->argp);
	} else if (uap->flag & NFSSVC_EXPORTSTATS) {
		error = nfssvc_exportstats(p, uap->argp);
	} else if (uap->flag & NFSSVC_USERSTATS) {
		error = nfssvc_userstats(p, uap->argp);
	} else if (uap->flag & NFSSVC_USERCOUNT) {
		error = nfssvc_usercount(p, uap->argp);
	} else if (uap->flag & NFSSVC_ZEROSTATS) {
		error = nfssvc_zerostats();
	} else if (uap->flag & NFSSVC_SRVSTATS) {
		error = nfssvc_srvstats(p, uap->argp);
	} else {
		error = EINVAL;
	}
	if (error == EINTR || error == ERESTART) {
		error = 0;
	}
	return error;
}
#endif /* CONFIG_NFS_SERVER */

#if CONFIG_NFS_SERVER

/*
 * Adds a socket to the list for servicing by nfsds.
 */
int
nfssvc_addsock(socket_t so, mbuf_t mynam)
{
	struct nfsrv_sock *slp;
	int error = 0, sodomain, sotype, soprotocol, on = 1;
	int first, sobufsize;
	struct timeval timeo;
	u_quad_t sbmaxsize;

	/* make sure mbuf constants are set up */
	if (!nfs_mbuf_mhlen) {
		nfs_mbuf_init();
	}

	sock_gettype(so, &sodomain, &sotype, &soprotocol);

	/* There should be only one UDP socket for each of IPv4 and IPv6 */
	if ((sodomain == AF_INET) && (soprotocol == IPPROTO_UDP) && nfsrv_udpsock) {
		mbuf_freem(mynam);
		return EEXIST;
	}
	if ((sodomain == AF_INET6) && (soprotocol == IPPROTO_UDP) && nfsrv_udp6sock) {
		mbuf_freem(mynam);
		return EEXIST;
	}

	/* Set protocol options and reserve some space (for UDP). */
	if (sotype == SOCK_STREAM) {
		error = nfsrv_check_exports_allow_address(mynam);
		if (error) {
			log(LOG_INFO, "nfsvc_addsock:: nfsrv_check_exports_allow_address(myname) returned %d\n", error);
			mbuf_freem(mynam);
			return error;
		}
		sock_setsockopt(so, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on));
	}
	if ((sodomain == AF_INET) && (soprotocol == IPPROTO_TCP)) {
		sock_setsockopt(so, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
	}

	/* Calculate maximum supported socket buffers sizes */
	sbmaxsize = (u_quad_t)sb_max * MCLBYTES / (MSIZE + MCLBYTES);

	/* Set socket buffer sizes for UDP/TCP */
	sobufsize = min(sbmaxsize, (sotype == SOCK_DGRAM) ? NFS_UDPSOCKBUF : NFSRV_TCPSOCKBUF);
	error |= sock_setsockopt(so, SOL_SOCKET, SO_SNDBUF, &sobufsize, sizeof(sobufsize));
	error |= sock_setsockopt(so, SOL_SOCKET, SO_RCVBUF, &sobufsize, sizeof(sobufsize));

	if (error) {
		log(LOG_INFO, "nfssvc_addsock: socket buffer setting error(s) %d\n", error);
		error = 0;
	}
	sock_nointerrupt(so, 0);

	/*
	 * Set socket send/receive timeouts.
	 * Receive timeout shouldn't matter, but setting the send timeout
	 * will make sure that an unresponsive client can't hang the server.
	 */
	timeo.tv_usec = 0;
	timeo.tv_sec = 1;
	error |= sock_setsockopt(so, SOL_SOCKET, SO_RCVTIMEO, &timeo, sizeof(timeo));
	timeo.tv_sec = 30;
	error |= sock_setsockopt(so, SOL_SOCKET, SO_SNDTIMEO, &timeo, sizeof(timeo));
	if (error) {
		log(LOG_INFO, "nfssvc_addsock: socket timeout setting error(s) %d\n", error);
		error = 0;
	}

	slp = kalloc_type(struct nfsrv_sock, Z_WAITOK | Z_ZERO | Z_NOFAIL);
	lck_rw_init(&slp->ns_rwlock, &nfsrv_slp_rwlock_group, LCK_ATTR_NULL);
	lck_mtx_init(&slp->ns_wgmutex, &nfsrv_slp_mutex_group, LCK_ATTR_NULL);

	lck_mtx_lock(&nfsd_mutex);

	if (soprotocol == IPPROTO_UDP) {
		if (sodomain == AF_INET) {
			/* There should be only one UDP/IPv4 socket */
			if (nfsrv_udpsock) {
				lck_mtx_unlock(&nfsd_mutex);
				nfsrv_slpfree(slp);
				mbuf_freem(mynam);
				return EEXIST;
			}
			nfsrv_udpsock = slp;
		}
		if (sodomain == AF_INET6) {
			/* There should be only one UDP/IPv6 socket */
			if (nfsrv_udp6sock) {
				lck_mtx_unlock(&nfsd_mutex);
				nfsrv_slpfree(slp);
				mbuf_freem(mynam);
				return EEXIST;
			}
			nfsrv_udp6sock = slp;
		}
	}

	/* add the socket to the list */
	first = TAILQ_EMPTY(&nfsrv_socklist);
	TAILQ_INSERT_TAIL(&nfsrv_socklist, slp, ns_chain);
	if (sotype == SOCK_STREAM) {
		nfsrv_sock_tcp_cnt++;
		if (nfsrv_sock_idle_timeout < 0) {
			nfsrv_sock_idle_timeout = 0;
		}
		if (nfsrv_sock_idle_timeout && (nfsrv_sock_idle_timeout < NFSD_MIN_IDLE_TIMEOUT)) {
			nfsrv_sock_idle_timeout = NFSD_MIN_IDLE_TIMEOUT;
		}
		/*
		 * Possibly start or stop the idle timer. We only start the idle timer when
		 * we have more than 2 * nfsd_thread_max connections. If the idle timer is
		 * on then we may need to turn it off based on the nvsrv_sock_idle_timeout or
		 * the number of connections.
		 */
		if ((nfsrv_sock_tcp_cnt > 2 * nfsd_thread_max) || nfsrv_idlesock_timer_on) {
			if (nfsrv_sock_idle_timeout == 0 || nfsrv_sock_tcp_cnt <= 2 * nfsd_thread_max) {
				if (nfsrv_idlesock_timer_on) {
					thread_call_cancel(nfsrv_idlesock_timer_call);
					nfsrv_idlesock_timer_on = 0;
				}
			} else {
				struct nfsrv_sock *old_slp;
				struct timeval now;
				time_t time_to_wait = nfsrv_sock_idle_timeout;
				/*
				 * Get the oldest tcp socket and calculate the
				 * earliest time for the next idle timer to fire
				 * based on the possibly updated nfsrv_sock_idle_timeout
				 */
				TAILQ_FOREACH(old_slp, &nfsrv_socklist, ns_chain) {
					if (old_slp->ns_sotype == SOCK_STREAM) {
						microuptime(&now);
						time_to_wait -= now.tv_sec - old_slp->ns_timestamp;
						if (time_to_wait < 1) {
							time_to_wait = 1;
						}
						break;
					}
				}
				/*
				 * If we have a timer scheduled, but if its going to fire too late,
				 * turn it off.
				 */
				if (nfsrv_idlesock_timer_on > now.tv_sec + time_to_wait) {
					thread_call_cancel(nfsrv_idlesock_timer_call);
					nfsrv_idlesock_timer_on = 0;
				}
				/* Schedule the idle thread if it isn't already */
				if (!nfsrv_idlesock_timer_on) {
					nfs_interval_timer_start(nfsrv_idlesock_timer_call, time_to_wait * 1000);
					nfsrv_idlesock_timer_on = now.tv_sec + time_to_wait;
				}
			}
		}
	}

	sock_retain(so); /* grab a retain count on the socket */
	slp->ns_so = so;
	slp->ns_sotype = sotype;
	slp->ns_nam = mynam;
	slp->ns_sobufsize = sobufsize;

	/* set up the socket up-call */
	nfsrv_uc_addsock(slp, first);

	/* mark that the socket is not in the nfsrv_sockwg list */
	slp->ns_wgq.tqe_next = SLPNOLIST;

	slp->ns_flag = SLP_VALID | SLP_NEEDQ;

	nfsrv_wakenfsd(slp);
	lck_mtx_unlock(&nfsd_mutex);

	return 0;
}

/*
 * nfssvc_nfsd()
 *
 * nfsd theory of operation:
 *
 * The first nfsd thread stays in user mode accepting new TCP connections
 * which are then added via the "addsock" call.  The rest of the nfsd threads
 * simply call into the kernel and remain there in a loop handling NFS
 * requests until killed by a signal.
 *
 * There's a list of nfsd threads (nfsd_head).
 * There's an nfsd queue that contains only those nfsds that are
 *   waiting for work to do (nfsd_queue).
 *
 * There's a list of all NFS sockets (nfsrv_socklist) and two queues for
 *   managing the work on the sockets:
 *   nfsrv_sockwait - sockets w/new data waiting to be worked on
 *   nfsrv_sockwork - sockets being worked on which may have more work to do
 *   nfsrv_sockwg -- sockets which have pending write gather data
 * When a socket receives data, if it is not currently queued, it
 *   will be placed at the end of the "wait" queue.
 * Whenever a socket needs servicing we make sure it is queued and
 *   wake up a waiting nfsd (if there is one).
 *
 * nfsds will service at most 8 requests from the same socket before
 *   defecting to work on another socket.
 * nfsds will defect immediately if there are any sockets in the "wait" queue
 * nfsds looking for a socket to work on check the "wait" queue first and
 *   then check the "work" queue.
 * When an nfsd starts working on a socket, it removes it from the head of
 *   the queue it's currently on and moves it to the end of the "work" queue.
 * When nfsds are checking the queues for work, any sockets found not to
 *   have any work are simply dropped from the queue.
 *
 */
int
nfssvc_nfsd(void)
{
	mbuf_t m, mrep = NULL;
	struct nfsrv_sock *slp;
	struct nfsd *nfsd;
	struct nfsrv_descript *nd = NULL;
	int error = 0, cacherep, writes_todo;
	int siz, procrastinate, opcnt = 0;
	time_t cur_usec;
	struct timeval now;
	struct vfs_context context;
	struct timespec to;

#ifndef nolint
	cacherep = RC_DOIT;
	writes_todo = 0;
#endif

	nfsd = kalloc_type(struct nfsd, Z_WAITOK | Z_ZERO | Z_NOFAIL);
	lck_mtx_lock(&nfsd_mutex);
	if (nfsd_thread_count++ == 0) {
		nfsrv_initcache();              /* Init the server request cache */
	}
	TAILQ_INSERT_TAIL(&nfsd_head, nfsd, nfsd_chain);
	lck_mtx_unlock(&nfsd_mutex);

	context.vc_thread = current_thread();

	/* Set time out so that nfsd threads can wake up a see if they are still needed. */
	to.tv_sec = 5;
	to.tv_nsec = 0;

	/*
	 * Loop getting rpc requests until SIGKILL.
	 */
	for (;;) {
		if (nfsd_thread_max <= 0) {
			/* NFS server shutting down, get out ASAP */
			error = EINTR;
			slp = nfsd->nfsd_slp;
		} else if (nfsd->nfsd_flag & NFSD_REQINPROG) {
			/* already have some work to do */
			error = 0;
			slp = nfsd->nfsd_slp;
		} else {
			/* need to find work to do */
			error = 0;
			lck_mtx_lock(&nfsd_mutex);
			while (!nfsd->nfsd_slp && TAILQ_EMPTY(&nfsrv_sockwait) && TAILQ_EMPTY(&nfsrv_sockwork)) {
				if (nfsd_thread_count > nfsd_thread_max) {
					/*
					 * If we have no socket and there are more
					 * nfsd threads than configured, let's exit.
					 */
					error = 0;
					goto done;
				}
				nfsd->nfsd_flag |= NFSD_WAITING;
				TAILQ_INSERT_HEAD(&nfsd_queue, nfsd, nfsd_queue);
				error = msleep(nfsd, &nfsd_mutex, PSOCK | PCATCH, "nfsd", &to);
				if (error) {
					if (nfsd->nfsd_flag & NFSD_WAITING) {
						TAILQ_REMOVE(&nfsd_queue, nfsd, nfsd_queue);
						nfsd->nfsd_flag &= ~NFSD_WAITING;
					}
					if (error == EWOULDBLOCK) {
						continue;
					}
					goto done;
				}
			}
			slp = nfsd->nfsd_slp;
			if (!slp && !TAILQ_EMPTY(&nfsrv_sockwait)) {
				/* look for a socket to work on in the wait queue */
				while ((slp = TAILQ_FIRST(&nfsrv_sockwait))) {
					lck_rw_lock_exclusive(&slp->ns_rwlock);
					/* remove from the head of the queue */
					TAILQ_REMOVE(&nfsrv_sockwait, slp, ns_svcq);
					slp->ns_flag &= ~SLP_WAITQ;
					if ((slp->ns_flag & SLP_VALID) && (slp->ns_flag & SLP_WORKTODO)) {
						break;
					}
					/* nothing to do, so skip this socket */
					lck_rw_done(&slp->ns_rwlock);
				}
			}
			if (!slp && !TAILQ_EMPTY(&nfsrv_sockwork)) {
				/* look for a socket to work on in the work queue */
				while ((slp = TAILQ_FIRST(&nfsrv_sockwork))) {
					lck_rw_lock_exclusive(&slp->ns_rwlock);
					/* remove from the head of the queue */
					TAILQ_REMOVE(&nfsrv_sockwork, slp, ns_svcq);
					slp->ns_flag &= ~SLP_WORKQ;
					if ((slp->ns_flag & SLP_VALID) && (slp->ns_flag & SLP_WORKTODO)) {
						break;
					}
					/* nothing to do, so skip this socket */
					lck_rw_done(&slp->ns_rwlock);
				}
			}
			if (!nfsd->nfsd_slp && slp) {
				/* we found a socket to work on, grab a reference */
				slp->ns_sref++;
				microuptime(&now);
				slp->ns_timestamp = now.tv_sec;
				/* We keep the socket list in least recently used order for reaping idle sockets */
				TAILQ_REMOVE(&nfsrv_socklist, slp, ns_chain);
				TAILQ_INSERT_TAIL(&nfsrv_socklist, slp, ns_chain);
				nfsd->nfsd_slp = slp;
				opcnt = 0;
				/* and put it at the back of the work queue */
				TAILQ_INSERT_TAIL(&nfsrv_sockwork, slp, ns_svcq);
				slp->ns_flag |= SLP_WORKQ;
				lck_rw_done(&slp->ns_rwlock);
			}
			lck_mtx_unlock(&nfsd_mutex);
			if (!slp) {
				continue;
			}
			lck_rw_lock_exclusive(&slp->ns_rwlock);
			if (slp->ns_flag & SLP_VALID) {
				if ((slp->ns_flag & (SLP_NEEDQ | SLP_DISCONN)) == SLP_NEEDQ) {
					slp->ns_flag &= ~SLP_NEEDQ;
					nfsrv_rcv_locked(slp->ns_so, slp, MBUF_WAITOK);
				}
				if (slp->ns_flag & SLP_DISCONN) {
					nfsrv_zapsock(slp);
				}
				error = nfsrv_dorec(slp, nfsd, &nd);
				if (error == EINVAL) {  // RPCSEC_GSS drop
					if (slp->ns_sotype == SOCK_STREAM) {
						nfsrv_zapsock(slp); // drop connection
					}
				}
				writes_todo = 0;
				if (error && (slp->ns_wgtime || (slp->ns_flag & SLP_DOWRITES))) {
					microuptime(&now);
					cur_usec = (now.tv_sec * 1000000) + now.tv_usec;
					if (slp->ns_wgtime <= cur_usec) {
						error = 0;
						cacherep = RC_DOIT;
						writes_todo = 1;
					}
					slp->ns_flag &= ~SLP_DOWRITES;
				}
				nfsd->nfsd_flag |= NFSD_REQINPROG;
			}
			lck_rw_done(&slp->ns_rwlock);
		}
		if (error || (slp && !(slp->ns_flag & SLP_VALID))) {
			if (nd) {
				nfsm_chain_cleanup(&nd->nd_nmreq);
				if (nd->nd_nam2) {
					mbuf_freem(nd->nd_nam2);
				}
				if (IS_VALID_CRED(nd->nd_cr)) {
					kauth_cred_unref(&nd->nd_cr);
				}
				if (nd->nd_gss_context) {
					nfs_gss_svc_ctx_deref(nd->nd_gss_context);
				}
				NFS_ZFREE(nfsrv_descript_zone, nd);
			}
			nfsd->nfsd_slp = NULL;
			nfsd->nfsd_flag &= ~NFSD_REQINPROG;
			if (slp) {
				nfsrv_slpderef(slp);
			}
			if (nfsd_thread_max <= 0) {
				break;
			}
			continue;
		}
		if (nd) {
			microuptime(&nd->nd_starttime);
			if (nd->nd_nam2) {
				nd->nd_nam = nd->nd_nam2;
			} else {
				nd->nd_nam = slp->ns_nam;
			}

			cacherep = nfsrv_getcache(nd, slp, &mrep);

			if (nfsrv_require_resv_port) {
				/* Check if source port is a reserved port */
				in_port_t port = 0;
				struct sockaddr *saddr = mbuf_data(nd->nd_nam);

				if (saddr->sa_family == AF_INET) {
					port = ntohs(((struct sockaddr_in*)saddr)->sin_port);
				} else if (saddr->sa_family == AF_INET6) {
					port = ntohs(((struct sockaddr_in6*)saddr)->sin6_port);
				}
				if ((port >= IPPORT_RESERVED) && (nd->nd_procnum != NFSPROC_NULL)) {
					nd->nd_procnum = NFSPROC_NOOP;
					nd->nd_repstat = (NFSERR_AUTHERR | AUTH_TOOWEAK);
					cacherep = RC_DOIT;
				}
			}
		}

		/*
		 * Loop to get all the write RPC replies that have been
		 * gathered together.
		 */
		do {
			switch (cacherep) {
			case RC_DOIT:
				if (nd && (nd->nd_vers == NFS_VER3)) {
					procrastinate = nfsrv_wg_delay_v3;
				} else {
					procrastinate = nfsrv_wg_delay;
				}
				lck_rw_lock_shared(&nfsrv_export_rwlock);
				context.vc_ucred = NULL;
				if (writes_todo || ((nd->nd_procnum == NFSPROC_WRITE) && (procrastinate > 0))) {
					error = nfsrv_writegather(&nd, slp, &context, &mrep);
				} else {
					error = (*(nfsrv_procs[nd->nd_procnum]))(nd, slp, &context, &mrep);
				}
				lck_rw_done(&nfsrv_export_rwlock);
				if (mrep == NULL) {
					/*
					 * If this is a stream socket and we are not going
					 * to send a reply we better close the connection
					 * so the client doesn't hang.
					 */
					if (error && slp->ns_sotype == SOCK_STREAM) {
						lck_rw_lock_exclusive(&slp->ns_rwlock);
						nfsrv_zapsock(slp);
						lck_rw_done(&slp->ns_rwlock);
						printf("NFS server: NULL reply from proc = %d error = %d\n",
						    nd->nd_procnum, error);
					}
					break;
				}
				if (error) {
					OSAddAtomic64(1, &nfsrvstats.srv_errs);
					nfsrv_updatecache(nd, FALSE, mrep);
					if (nd->nd_nam2) {
						mbuf_freem(nd->nd_nam2);
						nd->nd_nam2 = NULL;
					}
					break;
				}
				OSAddAtomic64(1, &nfsrvstats.srvrpccntv3[nd->nd_procnum]);
				nfsrv_updatecache(nd, TRUE, mrep);
				OS_FALLTHROUGH;

			case RC_REPLY:
				if (nd->nd_gss_mb != NULL) { // It's RPCSEC_GSS
					/*
					 * Need to checksum or encrypt the reply
					 */
					error = nfs_gss_svc_protect_reply(nd, mrep);
					if (error) {
						mbuf_freem(mrep);
						break;
					}
				}

				/*
				 * Get the total size of the reply
				 */
				m = mrep;
				siz = 0;
				while (m) {
					siz += mbuf_len(m);
					m = mbuf_next(m);
				}
				if (siz <= 0 || siz > NFS_MAXPACKET) {
					printf("mbuf siz=%d\n", siz);
					panic("Bad nfs svc reply");
				}
				m = mrep;
				mbuf_pkthdr_setlen(m, siz);
				error = mbuf_pkthdr_setrcvif(m, NULL);
				if (error) {
					panic("nfsd setrcvif failed: %d", error);
				}
				/*
				 * For stream protocols, prepend a Sun RPC
				 * Record Mark.
				 */
				if (slp->ns_sotype == SOCK_STREAM) {
					error = mbuf_prepend(&m, NFSX_UNSIGNED, MBUF_WAITOK);
					if (!error) {
						*(u_int32_t*)mbuf_data(m) = htonl(0x80000000 | siz);
					}
				}
				if (!error) {
					if (slp->ns_flag & SLP_VALID) {
						error = nfsrv_send(slp, nd->nd_nam2, m);
					} else {
						error = EPIPE;
						mbuf_freem(m);
					}
				} else {
					mbuf_freem(m);
				}
				mrep = NULL;
				if (nd->nd_nam2) {
					mbuf_freem(nd->nd_nam2);
					nd->nd_nam2 = NULL;
				}
				if (error == EPIPE) {
					lck_rw_lock_exclusive(&slp->ns_rwlock);
					nfsrv_zapsock(slp);
					lck_rw_done(&slp->ns_rwlock);
				}
				if (error == EINTR || error == ERESTART) {
					nfsm_chain_cleanup(&nd->nd_nmreq);
					if (IS_VALID_CRED(nd->nd_cr)) {
						kauth_cred_unref(&nd->nd_cr);
					}
					if (nd->nd_gss_context) {
						nfs_gss_svc_ctx_deref(nd->nd_gss_context);
					}
					NFS_ZFREE(nfsrv_descript_zone, nd);
					nfsrv_slpderef(slp);
					lck_mtx_lock(&nfsd_mutex);
					goto done;
				}
				break;
			case RC_DROPIT:
				mbuf_freem(nd->nd_nam2);
				nd->nd_nam2 = NULL;
				break;
			}
			;
			opcnt++;
			if (nd) {
				nfsm_chain_cleanup(&nd->nd_nmreq);
				if (nd->nd_nam2) {
					mbuf_freem(nd->nd_nam2);
				}
				if (IS_VALID_CRED(nd->nd_cr)) {
					kauth_cred_unref(&nd->nd_cr);
				}
				if (nd->nd_gss_context) {
					nfs_gss_svc_ctx_deref(nd->nd_gss_context);
				}
				NFS_ZFREE(nfsrv_descript_zone, nd);
			}

			/*
			 * Check to see if there are outstanding writes that
			 * need to be serviced.
			 */
			writes_todo = 0;
			if (slp->ns_wgtime) {
				microuptime(&now);
				cur_usec = (now.tv_sec * 1000000) + now.tv_usec;
				if (slp->ns_wgtime <= cur_usec) {
					cacherep = RC_DOIT;
					writes_todo = 1;
				}
			}
		} while (writes_todo);

		nd = NULL;
		if (TAILQ_EMPTY(&nfsrv_sockwait) && (opcnt < 8)) {
			lck_rw_lock_exclusive(&slp->ns_rwlock);
			error = nfsrv_dorec(slp, nfsd, &nd);
			if (error == EINVAL) {  // RPCSEC_GSS drop
				if (slp->ns_sotype == SOCK_STREAM) {
					nfsrv_zapsock(slp); // drop connection
				}
			}
			lck_rw_done(&slp->ns_rwlock);
		}
		if (!nd) {
			/* drop our reference on the socket */
			nfsd->nfsd_flag &= ~NFSD_REQINPROG;
			nfsd->nfsd_slp = NULL;
			nfsrv_slpderef(slp);
		}
	}
	lck_mtx_lock(&nfsd_mutex);
done:
	TAILQ_REMOVE(&nfsd_head, nfsd, nfsd_chain);
	kfree_type(struct nfsd, nfsd);
	if (--nfsd_thread_count == 0) {
		nfsrv_cleanup();
	}
	lck_mtx_unlock(&nfsd_mutex);
	return error;
}

int
nfssvc_export(user_addr_t argp)
{
	int error = 0, is_64bit;
	struct user_nfs_export_args unxa;
	vfs_context_t ctx = vfs_context_current();

	is_64bit = IS_64BIT_PROCESS(vfs_context_proc(ctx));

	/* copy in pointers to path and export args */
	if (is_64bit) {
		error = copyin(argp, (caddr_t)&unxa, sizeof(unxa));
	} else {
		struct nfs_export_args tnxa;
		error = copyin(argp, (caddr_t)&tnxa, sizeof(tnxa));
		if (error == 0) {
			/* munge into LP64 version of nfs_export_args structure */
			unxa.nxa_fsid = tnxa.nxa_fsid;
			unxa.nxa_expid = tnxa.nxa_expid;
			unxa.nxa_fspath = CAST_USER_ADDR_T(tnxa.nxa_fspath);
			unxa.nxa_exppath = CAST_USER_ADDR_T(tnxa.nxa_exppath);
			unxa.nxa_flags = tnxa.nxa_flags;
			unxa.nxa_netcount = tnxa.nxa_netcount;
			unxa.nxa_nets = CAST_USER_ADDR_T(tnxa.nxa_nets);
		}
	}
	if (error) {
		return error;
	}

	error = nfsrv_export(&unxa, ctx);

	return error;
}

int
nfssvc_exportstats(proc_t p, user_addr_t argp)
{
	int error = 0;
	uint pos;
	struct nfs_exportfs *nxfs;
	struct nfs_export *nx;
	struct nfs_export_stat_desc stat_desc = {};
	struct nfs_export_stat_rec statrec;
	uint numExports, totlen, count;
	size_t numRecs;
	user_addr_t oldp, newlenp;
	user_size_t oldlen, newlen;
	struct user_iovec iov[2];

	error = copyin_user_iovec_array(argp, IS_64BIT_PROCESS(p) ? UIO_USERSPACE64 : UIO_USERSPACE32, 2, iov);
	if (error) {
		return error;
	}

	oldp = iov[0].iov_base;
	oldlen = iov[0].iov_len;
	newlenp = iov[1].iov_base;
	newlen = iov[1].iov_len;

	/* setup export stat descriptor */
	stat_desc.rec_vers = NFS_EXPORT_STAT_REC_VERSION;

	if (!nfsrv_is_initialized()) {
		stat_desc.rec_count = 0;
		if (oldp && (oldlen >= sizeof(struct nfs_export_stat_desc))) {
			error = copyout(&stat_desc, oldp, sizeof(struct nfs_export_stat_desc));
		}
		size_t stat_desc_size = sizeof(struct nfs_export_stat_desc);
		if (!error && newlenp && newlen >= sizeof(stat_desc_size)) {
			error = copyout(&stat_desc_size, newlenp, sizeof(stat_desc_size));
		}
		return error;
	}

	/* Count the number of exported directories */
	lck_rw_lock_shared(&nfsrv_export_rwlock);
	numExports = 0;
	LIST_FOREACH(nxfs, &nfsrv_exports, nxfs_next)
	LIST_FOREACH(nx, &nxfs->nxfs_exports, nx_next)
	numExports += 1;

	/* update stat descriptor's export record count */
	stat_desc.rec_count = numExports;

	/* calculate total size of required buffer */
	totlen = sizeof(struct nfs_export_stat_desc) + (numExports * sizeof(struct nfs_export_stat_rec));

	/* Check caller's buffer */
	if (oldp == 0 || newlenp == 0) {
		lck_rw_done(&nfsrv_export_rwlock);
		/* indicate required buffer len */
		if (newlenp && newlen >= sizeof(totlen)) {
			error = copyout(&totlen, newlenp, sizeof(totlen));
		}
		return error;
	}

	/* We require the caller's buffer to be at least large enough to hold the descriptor */
	if (oldlen < sizeof(struct nfs_export_stat_desc) || newlen < sizeof(totlen)) {
		lck_rw_done(&nfsrv_export_rwlock);
		/* indicate required buffer len */
		if (newlenp && newlen >= sizeof(totlen)) {
			(void)copyout(&totlen, newlenp, sizeof(totlen));
		}
		return ENOMEM;
	}

	/* indicate required buffer len */
	error = copyout(&totlen, newlenp, sizeof(totlen));
	if (error) {
		lck_rw_done(&nfsrv_export_rwlock);
		return error;
	}

	/* check if export table is empty */
	if (!numExports) {
		lck_rw_done(&nfsrv_export_rwlock);
		error = copyout(&stat_desc, oldp, sizeof(struct nfs_export_stat_desc));
		return error;
	}

	/* calculate how many actual export stat records fit into caller's buffer */
	numRecs = (totlen - sizeof(struct nfs_export_stat_desc)) / sizeof(struct nfs_export_stat_rec);

	if (!numRecs) {
		/* caller's buffer can only accomodate descriptor */
		lck_rw_done(&nfsrv_export_rwlock);
		stat_desc.rec_count = 0;
		error = copyout(&stat_desc, oldp, sizeof(struct nfs_export_stat_desc));
		return error;
	}

	/* adjust to actual number of records to copyout to caller's buffer */
	if (numRecs > numExports) {
		numRecs = numExports;
	}

	/* set actual number of records we are returning */
	stat_desc.rec_count = numRecs;

	/* first copy out the stat descriptor */
	pos = 0;
	error = copyout(&stat_desc, oldp + pos, sizeof(struct nfs_export_stat_desc));
	if (error) {
		lck_rw_done(&nfsrv_export_rwlock);
		return error;
	}
	pos += sizeof(struct nfs_export_stat_desc);

	/* Loop through exported directories */
	count = 0;
	LIST_FOREACH(nxfs, &nfsrv_exports, nxfs_next) {
		LIST_FOREACH(nx, &nxfs->nxfs_exports, nx_next) {
			if (count >= numRecs) {
				break;
			}

			/* build exported filesystem path */
			memset(statrec.path, 0, sizeof(statrec.path));
			snprintf(statrec.path, sizeof(statrec.path), "%s%s%s",
			    nxfs->nxfs_path, ((nxfs->nxfs_path[1] && nx->nx_path[0]) ? "/" : ""),
			    nx->nx_path);

			/* build the 64-bit export stat counters */
			statrec.ops = ((uint64_t)nx->nx_stats.ops.hi << 32) |
			    nx->nx_stats.ops.lo;
			statrec.bytes_read = ((uint64_t)nx->nx_stats.bytes_read.hi << 32) |
			    nx->nx_stats.bytes_read.lo;
			statrec.bytes_written = ((uint64_t)nx->nx_stats.bytes_written.hi << 32) |
			    nx->nx_stats.bytes_written.lo;
			error = copyout(&statrec, oldp + pos, sizeof(statrec));
			if (error) {
				lck_rw_done(&nfsrv_export_rwlock);
				return error;
			}
			/* advance buffer position */
			pos += sizeof(statrec);
		}
	}
	lck_rw_done(&nfsrv_export_rwlock);

	return error;
}

int
nfssvc_userstats(proc_t p, user_addr_t argp)
{
	int error = 0;
	struct nfs_exportfs *nxfs;
	struct nfs_export *nx;
	struct nfs_active_user_list *ulist;
	struct nfs_user_stat_desc ustat_desc = {};
	struct nfs_user_stat_node *unode, *unode_next;
	struct nfs_user_stat_user_rec ustat_rec;
	struct nfs_user_stat_path_rec upath_rec;
	uint bytes_total, recs_copied, pos;
	size_t bytes_avail;
	user_addr_t oldp, newlenp;
	user_size_t oldlen, newlen;
	struct user_iovec iov[2];

	error = copyin_user_iovec_array(argp, IS_64BIT_PROCESS(p) ? UIO_USERSPACE64 : UIO_USERSPACE32, 2, iov);
	if (error) {
		return error;
	}

	oldp = iov[0].iov_base;
	oldlen = iov[0].iov_len;
	newlenp = iov[1].iov_base;
	newlen = iov[1].iov_len;

	/* init structures used for copying out of kernel */
	ustat_desc.rec_vers = NFS_USER_STAT_REC_VERSION;
	ustat_rec.rec_type = NFS_USER_STAT_USER_REC;
	upath_rec.rec_type = NFS_USER_STAT_PATH_REC;

	/* initialize counters */
	bytes_total = sizeof(struct nfs_user_stat_desc);
	bytes_avail  = oldlen;
	recs_copied = 0;

	if (!nfsrv_is_initialized()) { /* NFS server not initialized, so no stats */
		goto ustat_skip;
	}

	/* reclaim old expired user nodes */
	nfsrv_active_user_list_reclaim();

	/* reserve space for the buffer descriptor */
	if (bytes_avail >= sizeof(struct nfs_user_stat_desc)) {
		bytes_avail -= sizeof(struct nfs_user_stat_desc);
	} else {
		bytes_avail = 0;
	}

	/* put buffer position past the buffer descriptor */
	pos = sizeof(struct nfs_user_stat_desc);

	/* Loop through exported directories */
	lck_rw_lock_shared(&nfsrv_export_rwlock);
	LIST_FOREACH(nxfs, &nfsrv_exports, nxfs_next) {
		LIST_FOREACH(nx, &nxfs->nxfs_exports, nx_next) {
			/* copy out path */
			if (bytes_avail >= sizeof(struct nfs_user_stat_path_rec)) {
				memset(upath_rec.path, 0, sizeof(upath_rec.path));
				snprintf(upath_rec.path, sizeof(upath_rec.path), "%s%s%s",
				    nxfs->nxfs_path, ((nxfs->nxfs_path[1] && nx->nx_path[0]) ? "/" : ""),
				    nx->nx_path);

				error = copyout(&upath_rec, oldp + pos, sizeof(struct nfs_user_stat_path_rec));
				if (error) {
					/* punt */
					goto ustat_done;
				}

				pos += sizeof(struct nfs_user_stat_path_rec);
				bytes_avail -= sizeof(struct nfs_user_stat_path_rec);
				recs_copied++;
			} else {
				/* Caller's buffer is exhausted */
				bytes_avail = 0;
			}

			bytes_total += sizeof(struct nfs_user_stat_path_rec);

			/* Scan through all user nodes of this export */
			ulist = &nx->nx_user_list;
			lck_mtx_lock(&ulist->user_mutex);
			for (unode = TAILQ_FIRST(&ulist->user_lru); unode; unode = unode_next) {
				unode_next = TAILQ_NEXT(unode, lru_link);

				/* copy out node if there is space */
				if (bytes_avail >= sizeof(struct nfs_user_stat_user_rec)) {
					/* prepare a user stat rec for copying out */
					ustat_rec.uid = unode->uid;
					memset(&ustat_rec.sock, 0, sizeof(ustat_rec.sock));
					bcopy(&unode->sock, &ustat_rec.sock, unode->sock.ss_len);
					ustat_rec.ops = unode->ops;
					ustat_rec.bytes_read = unode->bytes_read;
					ustat_rec.bytes_written = unode->bytes_written;
					ustat_rec.tm_start = unode->tm_start;
					ustat_rec.tm_last = unode->tm_last;

					error = copyout(&ustat_rec, oldp + pos, sizeof(struct nfs_user_stat_user_rec));

					if (error) {
						/* punt */
						lck_mtx_unlock(&ulist->user_mutex);
						goto ustat_done;
					}

					pos += sizeof(struct nfs_user_stat_user_rec);
					bytes_avail -= sizeof(struct nfs_user_stat_user_rec);
					recs_copied++;
				} else {
					/* Caller's buffer is exhausted */
					bytes_avail = 0;
				}
				bytes_total += sizeof(struct nfs_user_stat_user_rec);
			}
			/* can unlock this export's list now */
			lck_mtx_unlock(&ulist->user_mutex);
		}
	}

ustat_done:
	/* unlock the export table */
	lck_rw_done(&nfsrv_export_rwlock);

ustat_skip:
	/* indicate number of actual records copied */
	ustat_desc.rec_count = recs_copied;

	if (!error) {
		/* check if there was enough room for the buffer descriptor */
		if (oldlen >= sizeof(struct nfs_user_stat_desc)) {
			error = copyout(&ustat_desc, oldp, sizeof(struct nfs_user_stat_desc));
		} else {
			error = ENOMEM;
		}

		/* always indicate required buffer size */
		if (!error && newlenp && newlen >= sizeof(bytes_total)) {
			error = copyout(&bytes_total, newlenp, sizeof(bytes_total));
		}
	}
	return error;
}

int
nfssvc_usercount(proc_t p, user_addr_t argp)
{
	int error;
	user_addr_t oldp, newlenp;
	user_size_t oldlen, newlen;
	struct user_iovec iov[2];
	size_t stat_size = sizeof(nfsrv_user_stat_node_count);

	error = copyin_user_iovec_array(argp, IS_64BIT_PROCESS(p) ? UIO_USERSPACE64 : UIO_USERSPACE32, 2, iov);
	if (error) {
		return error;
	}

	oldp = iov[0].iov_base;
	oldlen = iov[0].iov_len;
	newlenp = iov[1].iov_base;
	newlen = iov[1].iov_len;

	if (!oldp) {
		if (newlenp && newlen >= sizeof(stat_size)) {
			error = copyout(&stat_size, newlenp, sizeof(stat_size));
		}
		return error;
	}

	if (oldlen < stat_size) {
		if (newlenp && newlen >= sizeof(stat_size)) {
			(void)copyout(&stat_size, newlenp, sizeof(stat_size));
		}
		return ENOMEM;
	}

	if (nfsrv_is_initialized()) {
		/* reclaim old expired user nodes */
		nfsrv_active_user_list_reclaim();
	}

	error = copyout(&nfsrv_user_stat_node_count, oldp, sizeof(nfsrv_user_stat_node_count));

	return error;
}

int
nfssvc_zerostats(void)
{
	bzero(&nfsrvstats, sizeof nfsrvstats);
	return 0;
}

int
nfssvc_srvstats(proc_t p, user_addr_t argp)
{
	int error;
	user_addr_t oldp, newlenp;
	user_size_t oldlen, newlen;
	struct user_iovec iov[2];
	size_t stat_size = sizeof(nfsrvstats);

	error = copyin_user_iovec_array(argp, IS_64BIT_PROCESS(p) ? UIO_USERSPACE64 : UIO_USERSPACE32, 2, iov);
	if (error) {
		return error;
	}

	oldp = iov[0].iov_base;
	oldlen = iov[0].iov_len;
	newlenp = iov[1].iov_base;
	newlen = iov[1].iov_len;

	if (!oldp) {
		if (newlenp && newlen >= sizeof(stat_size)) {
			error = copyout(&stat_size, newlenp, sizeof(stat_size));
		}
		return error;
	}

	if (oldlen < stat_size) {
		if (newlenp && newlen >= sizeof(stat_size)) {
			(void)copyout(&stat_size, newlenp, sizeof(stat_size));
		}
		return ENOMEM;
	}

	error = copyout(&nfsrvstats, oldp, stat_size);
	if (error) {
		return error;
	}

	return 0;
}

/*
 * Shut down a socket associated with an nfsrv_sock structure.
 * Should be called with the send lock set, if required.
 * The trick here is to increment the sref at the start, so that the nfsds
 * will stop using it and clear ns_flag at the end so that it will not be
 * reassigned during cleanup.
 */
void
nfsrv_zapsock(struct nfsrv_sock *slp)
{
	socket_t so;

	if ((slp->ns_flag & SLP_VALID) == 0) {
		return;
	}
	slp->ns_flag &= ~SLP_ALLFLAGS;

	so = slp->ns_so;
	if (so == NULL) {
		return;
	}

	sock_setupcall(so, NULL, NULL);
	sock_shutdown(so, SHUT_RDWR);

	/*
	 * Remove from the up-call queue
	 */
	nfsrv_uc_dequeue(slp);
}

/*
 * cleanup and release a server socket structure.
 */
void
nfsrv_slpfree(struct nfsrv_sock *slp)
{
	struct nfsrv_descript *nwp, *nnwp;

	if (slp->ns_so) {
		sock_release(slp->ns_so);
		slp->ns_so = NULL;
	}
	if (slp->ns_nam) {
		mbuf_free(slp->ns_nam);
	}
	if (slp->ns_raw) {
		mbuf_freem(slp->ns_raw);
	}
	if (slp->ns_rec) {
		mbuf_freem(slp->ns_rec);
	}
	if (slp->ns_frag) {
		mbuf_freem(slp->ns_frag);
	}
	slp->ns_nam = slp->ns_raw = slp->ns_rec = slp->ns_frag = NULL;
	slp->ns_reccnt = 0;

	for (nwp = slp->ns_tq.lh_first; nwp; nwp = nnwp) {
		nnwp = nwp->nd_tq.le_next;
		LIST_REMOVE(nwp, nd_tq);
		nfsm_chain_cleanup(&nwp->nd_nmreq);
		if (nwp->nd_mrep) {
			mbuf_freem(nwp->nd_mrep);
		}
		if (nwp->nd_nam2) {
			mbuf_freem(nwp->nd_nam2);
		}
		if (IS_VALID_CRED(nwp->nd_cr)) {
			kauth_cred_unref(&nwp->nd_cr);
		}
		if (nwp->nd_gss_context) {
			nfs_gss_svc_ctx_deref(nwp->nd_gss_context);
		}
		NFS_ZFREE(nfsrv_descript_zone, nwp);
	}
	LIST_INIT(&slp->ns_tq);

	lck_rw_destroy(&slp->ns_rwlock, &nfsrv_slp_rwlock_group);
	lck_mtx_destroy(&slp->ns_wgmutex, &nfsrv_slp_mutex_group);
	kfree_type(struct nfsrv_sock, slp);
}

/*
 * Derefence a server socket structure. If it has no more references and
 * is no longer valid, you can throw it away.
 */
static void
nfsrv_slpderef_locked(struct nfsrv_sock *slp)
{
	lck_rw_lock_exclusive(&slp->ns_rwlock);
	slp->ns_sref--;

	if (slp->ns_sref || (slp->ns_flag & SLP_VALID)) {
		if ((slp->ns_flag & SLP_QUEUED) && !(slp->ns_flag & SLP_WORKTODO)) {
			/* remove socket from queue since there's no work */
			if (slp->ns_flag & SLP_WAITQ) {
				TAILQ_REMOVE(&nfsrv_sockwait, slp, ns_svcq);
			} else {
				TAILQ_REMOVE(&nfsrv_sockwork, slp, ns_svcq);
			}
			slp->ns_flag &= ~SLP_QUEUED;
		}
		lck_rw_done(&slp->ns_rwlock);
		return;
	}

	/* This socket is no longer valid, so we'll get rid of it */

	if (slp->ns_flag & SLP_QUEUED) {
		if (slp->ns_flag & SLP_WAITQ) {
			TAILQ_REMOVE(&nfsrv_sockwait, slp, ns_svcq);
		} else {
			TAILQ_REMOVE(&nfsrv_sockwork, slp, ns_svcq);
		}
		slp->ns_flag &= ~SLP_QUEUED;
	}
	lck_rw_done(&slp->ns_rwlock);

	TAILQ_REMOVE(&nfsrv_socklist, slp, ns_chain);
	if (slp->ns_sotype == SOCK_STREAM) {
		nfsrv_sock_tcp_cnt--;
	}

	/* now remove from the write gather socket list */
	if (slp->ns_wgq.tqe_next != SLPNOLIST) {
		TAILQ_REMOVE(&nfsrv_sockwg, slp, ns_wgq);
		slp->ns_wgq.tqe_next = SLPNOLIST;
	}
	nfsrv_slpfree(slp);
}

void
nfsrv_slpderef(struct nfsrv_sock *slp)
{
	lck_mtx_lock(&nfsd_mutex);
	nfsrv_slpderef_locked(slp);
	lck_mtx_unlock(&nfsd_mutex);
}

/*
 * Check periodically for idle sockest if needed and
 * zap them.
 */
void
nfsrv_idlesock_timer(__unused void *param0, __unused void *param1)
{
	struct nfsrv_sock *slp, *tslp;
	struct timeval now;
	time_t time_to_wait = nfsrv_sock_idle_timeout;

	microuptime(&now);
	lck_mtx_lock(&nfsd_mutex);

	/* Turn off the timer if we're suppose to and get out */
	if (nfsrv_sock_idle_timeout < NFSD_MIN_IDLE_TIMEOUT) {
		nfsrv_sock_idle_timeout = 0;
	}
	if ((nfsrv_sock_tcp_cnt <= 2 * nfsd_thread_max) || (nfsrv_sock_idle_timeout == 0)) {
		nfsrv_idlesock_timer_on = 0;
		lck_mtx_unlock(&nfsd_mutex);
		return;
	}

	TAILQ_FOREACH_SAFE(slp, &nfsrv_socklist, ns_chain, tslp) {
		lck_rw_lock_exclusive(&slp->ns_rwlock);
		/* Skip udp and referenced sockets */
		if (slp->ns_sotype == SOCK_DGRAM || slp->ns_sref) {
			lck_rw_done(&slp->ns_rwlock);
			continue;
		}
		/*
		 * If this is the first non-referenced socket that hasn't idle out,
		 * use its time stamp to calculate the earlist time in the future
		 * to start the next invocation of the timer. Since the nfsrv_socklist
		 * is sorted oldest access to newest. Once we find the first one,
		 * we're done and break out of the loop.
		 */
		if (((slp->ns_timestamp + nfsrv_sock_idle_timeout) > now.tv_sec) ||
		    nfsrv_sock_tcp_cnt <= 2 * nfsd_thread_max) {
			time_to_wait -= now.tv_sec - slp->ns_timestamp;
			if (time_to_wait < 1) {
				time_to_wait = 1;
			}
			lck_rw_done(&slp->ns_rwlock);
			break;
		}
		/*
		 * Bump the ref count. nfsrv_slpderef below will destroy
		 * the socket, since nfsrv_zapsock has closed it.
		 */
		slp->ns_sref++;
		nfsrv_zapsock(slp);
		lck_rw_done(&slp->ns_rwlock);
		nfsrv_slpderef_locked(slp);
	}

	/* Start ourself back up */
	nfs_interval_timer_start(nfsrv_idlesock_timer_call, time_to_wait * 1000);
	/* Remember when the next timer will fire for nfssvc_addsock. */
	nfsrv_idlesock_timer_on = now.tv_sec + time_to_wait;
	lck_mtx_unlock(&nfsd_mutex);
}

/*
 * Clean up the data structures for the server.
 */
void
nfsrv_cleanup(void)
{
	struct nfsrv_sock *slp, *nslp;
	struct timeval now;
#if CONFIG_FSE
	struct nfsrv_fmod *fp, *nfp;
	int i;
#endif

	microuptime(&now);
	for (slp = TAILQ_FIRST(&nfsrv_socklist); slp != 0; slp = nslp) {
		nslp = TAILQ_NEXT(slp, ns_chain);
		lck_rw_lock_exclusive(&slp->ns_rwlock);
		slp->ns_sref++;
		if (slp->ns_flag & SLP_VALID) {
			nfsrv_zapsock(slp);
		}
		lck_rw_done(&slp->ns_rwlock);
		nfsrv_slpderef_locked(slp);
	}
#
#if CONFIG_FSE
	/*
	 * Flush pending file write fsevents
	 */
	lck_mtx_lock(&nfsrv_fmod_mutex);
	for (i = 0; i < NFSRVFMODHASHSZ; i++) {
		for (fp = LIST_FIRST(&nfsrv_fmod_hashtbl[i]); fp; fp = nfp) {
			/*
			 * Fire off the content modified fsevent for each
			 * entry, remove it from the list, and free it.
			 */
			if (nfsrv_fsevents_enabled) {
				fp->fm_context.vc_thread = current_thread();
				add_fsevent(FSE_CONTENT_MODIFIED, &fp->fm_context,
				    FSE_ARG_VNODE, fp->fm_vp,
				    FSE_ARG_DONE);
			}
			vnode_put(fp->fm_vp);
			kauth_cred_unref(&fp->fm_context.vc_ucred);
			nfp = LIST_NEXT(fp, fm_link);
			LIST_REMOVE(fp, fm_link);
			kfree_type(struct nfsrv_fmod, fp);
		}
	}
	nfsrv_fmod_pending = 0;
	lck_mtx_unlock(&nfsrv_fmod_mutex);
#endif

	nfsrv_uc_cleanup();     /* Stop nfs socket up-call threads */

	nfs_gss_svc_cleanup();  /* Remove any RPCSEC_GSS contexts */

	nfsrv_cleancache();     /* And clear out server cache */

	nfsrv_udpsock = NULL;
	nfsrv_udp6sock = NULL;
}

#endif /* CONFIG_NFS_SERVER */
