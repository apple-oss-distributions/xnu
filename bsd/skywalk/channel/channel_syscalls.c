/*
 * Copyright (c) 2015-2023 Apple Inc. All rights reserved.
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
#include <sys/sdt.h>
#include <sys/systm.h>
#include <sys/filedesc.h>
#include <sys/proc_internal.h>
#include <sys/file_internal.h>
#include <sys/vnode_internal.h>
#include <sys/sysproto.h>
#include <security/audit/audit.h>
#include <skywalk/os_skywalk_private.h>

static int chop_select(struct fileproc *, int, void *, vfs_context_t);
static int chop_close(struct fileglob *, vfs_context_t);
static int chop_kqfilter(struct fileproc *, struct knote *, struct kevent_qos_s *);

static const struct fileops channel_ops = {
	.fo_type     = DTYPE_CHANNEL,
	.fo_read     = fo_no_read,
	.fo_write    = fo_no_write,
	.fo_ioctl    = fo_no_ioctl,
	.fo_select   = chop_select,
	.fo_close    = chop_close,
	.fo_drain    = fo_no_drain,
	.fo_kqfilter = chop_kqfilter,
};

#if (DEVELOPMENT || DEBUG)
static uint32_t ch_force_defunct = 0;
SYSCTL_UINT(_kern_skywalk_channel, OID_AUTO, force_defunct,
    CTLFLAG_RW | CTLFLAG_LOCKED, &ch_force_defunct, 0, "");
#endif /* !DEVELOPMENT && !DEBUG */

static int
chop_select(struct fileproc *fp, int which, void *wql, vfs_context_t ctx)
{
	int revents = 0, events = 0;
	struct kern_channel *ch;

	ch = (struct kern_channel *)fp_get_data(fp);
	if (ch == NULL) {
		return 0;
	}

	switch (which) {
	case FREAD:
		events = POLLIN;
		break;

	case FWRITE:
		events = POLLOUT;
		break;

	case 0:
		events = POLLERR;
		break;

	default:
		return 1;
	}

	/* caller will lock channel */
	revents = ch_select(ch, events, wql, vfs_context_proc(ctx));
	return (events & revents) ? 1 : 0;
}

static int
chop_close(struct fileglob *fg, vfs_context_t ctx)
{
#pragma unused(ctx)
	struct kern_channel *ch;

	ch = (struct kern_channel *)fg_get_data(fg);
	fg_set_data(fg, NULL);
	if (ch != NULL) {
		ch_dtor(ch);
	}

	return 0;
}

/*
 * This is called when a thread invokes kevent() to record
 * a change in the configuration of the kqueue().
 */
static int
chop_kqfilter(struct fileproc *fp, struct knote *kn, struct kevent_qos_s *kev)
{
	struct kern_channel *ch = (struct kern_channel *)fp_get_data(fp);

	/* caller will lock channel */
	return ch_kqfilter(ch, kn, kev);
}

int
__channel_open(struct proc *p, struct __channel_open_args *uap, int *retval)
{
	struct fileproc *fp = NULL;
	struct kern_channel *ch = NULL;
	struct ch_init init;
	int fd = -1, err = 0;
	void *key = NULL;
	uint32_t keylen;
	guardid_t guard;

	if (__improbable(uap->init == USER_ADDR_NULL ||
	    uap->init_len < sizeof(init))) {
		SK_DSC(p, "EINVAL: init 0x%llx, init_len %u", SK_KVA(uap->init),
		    uap->init_len);
		err = EINVAL;
		goto done;
	}

	err = copyin(uap->init, (caddr_t)&init, sizeof(init));
	if (__improbable(err != 0)) {
		SK_DSC(p, "copyin err %u: init 0x%llx", err, SK_KVA(uap->init));
		goto done;
	}

	if (__improbable(init.ci_version != CHANNEL_INIT_CURRENT_VERSION)) {
		SK_DSC(p, "ENOTSUP: init.ci_version %u != %u", init.ci_version,
		    CHANNEL_INIT_CURRENT_VERSION);
		err = ENOTSUP;
		goto done;
	} else if (__improbable(uuid_is_null(init.ci_nx_uuid))) {
		SK_DSC(p, "EINVAL: uuid_is_null");
		err = EINVAL;
		goto done;
	} else if (__improbable((init.ci_key_len != 0 &&
	    init.ci_key == USER_ADDR_NULL) ||
	    (init.ci_key_len == 0 && init.ci_key != USER_ADDR_NULL))) {
		SK_DSC(p, "EINVAL: ci_key_len %i, ci_key 0x%llx",
		    init.ci_key_len, SK_KVA(init.ci_key));
		err = EINVAL;
		goto done;
	}

	if ((init.ci_ch_mode & CHMODE_MONITOR) != 0) {
		if (__improbable((init.ci_ch_mode & CHMODE_USER_PACKET_POOL) != 0)) {
			SK_DSC(p, "EINVAL: PACKET_POOL not supported for MONITOR mode");
			err = EINVAL;
			goto done;
		}
		if (__improbable((init.ci_ch_mode & CHMODE_EVENT_RING) != 0)) {
			SK_DSC(p, "EINVAL: EVENT ring not supported for MONITOR mode");
			err = EINVAL;
			goto done;
		}
		if (__improbable((init.ci_ch_mode & CHMODE_LOW_LATENCY) != 0)) {
			SK_DSC(p, "EINVAL: low latency not supported for MONITOR mode");
			err = EINVAL;
			goto done;
		}
	}

	if ((init.ci_ch_mode & CHMODE_EVENT_RING) != 0) {
		if ((init.ci_ch_mode & CHMODE_USER_PACKET_POOL) == 0) {
			SK_DSC(p, "EINVAL: PACKET_POOL is required for EVENT ring");
			err = EINVAL;
			goto done;
		}
	}

#if (DEVELOPMENT || DEBUG)
	if (__improbable(ch_force_defunct)) {
		init.ci_ch_mode |= CHMODE_DEFUNCT_OK;
	}
#endif /* !DEVELOPMENT && !DEBUG */

	/* generate guard ID based on nexus instance UUID */
	sk_gen_guard_id(TRUE, init.ci_nx_uuid, &guard);

	err = falloc_guarded(p, &fp, &fd, vfs_context_current(), &guard,
	    GUARD_CLOSE | GUARD_DUP | GUARD_SOCKET_IPC | GUARD_FILEPORT | GUARD_WRITE);
	if (__improbable(err != 0)) {
		SK_DSC(p, "falloc_guarded: %u", err);
		goto done;
	}

	keylen = init.ci_key_len;
	if (keylen != 0) {
		if (__improbable(keylen > NEXUS_MAX_KEY_LEN)) {
			SK_DSC(p, "EINVAL: ci_key_len %u", keylen);
			err = EINVAL;
			goto done;
		}

		key = sk_alloc_data(keylen, Z_WAITOK, skmem_tag_ch_key);
		if (__improbable(key == NULL)) {
			SK_DSC(p, "ENOMEM: ci_key_len %u", keylen);
			err = ENOMEM;
			goto done;
		}

		err = copyin(init.ci_key, (caddr_t)key, keylen);
		if (__improbable(err != 0)) {
			SK_DSC(p, "copyin err %u: ci_key 0x%llx, ci_key_len %u",
			    err, SK_KVA(init.ci_key), keylen);
			goto done;
		}
	}

	/* let ch_open() take over this key upon success */
	init.ci_key = (user_addr_t)key;
	key = NULL;

	if (__improbable((ch = ch_open(&init, p, fd, &err)) == NULL)) {
		/* in case not processed */
		key = (void *)init.ci_key;
		ASSERT(err != 0);
		SK_DSC(p, "ch_open nx_port %d err %u",
		    (int)init.ci_nx_port, err);
		goto done;
	}
	/* in case not processed */
	key = (void *)init.ci_key;

	/* update userland with respect to guard ID, etc. */
	init.ci_guard = guard;
	init.ci_key = USER_ADDR_NULL;
	err = copyout(&init, uap->init, sizeof(init));
	if (__improbable(err != 0)) {
		SK_DSC(p, "copyout err %u: init 0x%llx", err,
		    SK_KVA(uap->init));
		goto done;
	}

	fp->fp_flags |= FP_CLOEXEC | FP_CLOFORK;
	fp->fp_glob->fg_flag &= ~(FREAD | FWRITE);
	fp->fp_glob->fg_ops = &channel_ops;
	fp_set_data(fp, ch);              /* ref from ch_open */

	proc_fdlock(p);
	procfdtbl_releasefd(p, fd, NULL);
	fp_drop(p, fd, fp, 1);
	proc_fdunlock(p);

	*retval = fd;

	SK_D("%s(%d) nx_port %d fd %d guard 0x%llx",
	    sk_proc_name_address(p), sk_proc_pid(p), (int)init.ci_nx_port,
	    fd, guard);

done:
	if (key != NULL) {
		sk_free_data(key, keylen);
		key = NULL;
	}
	if (__improbable(err != 0)) {
		if (ch != NULL) {
			ch_dtor(ch);
			ch = NULL;
		}
		if (fp != NULL) {
			fp_free(p, fd, fp);
			fp = NULL;
		}
	}

	return err;
}

int
__channel_get_info(struct proc *p, struct __channel_get_info_args *uap,
    int *retval)
{
#pragma unused(retval)
	struct fileproc *fp;
	struct kern_channel *ch = NULL;
	int err = 0;

	AUDIT_ARG(fd, uap->c);

	err = fp_get_ftype(p, uap->c, DTYPE_CHANNEL, ENODEV, &fp);
	if (__improbable(err != 0)) {
		SK_DSC(p, "fp_get_ftype err %u", err);
		return err;
	}
	ch = fp_get_data(fp);

	if (__improbable(uap->cinfo == USER_ADDR_NULL ||
	    uap->cinfolen < sizeof(struct ch_info))) {
		SK_DSC(p, "EINVAL: cinfo 0x%llx, cinfolen %u",
		    SK_KVA(uap->cinfo), uap->cinfolen);
		err = EINVAL;
		goto done;
	}

	lck_mtx_lock(&ch->ch_lock);
	err = copyout(ch->ch_info, uap->cinfo, sizeof(struct ch_info));
	lck_mtx_unlock(&ch->ch_lock);
	if (__improbable(err != 0)) {
		SK_DSC(p, "copyout err %u: cinfo 0x%llx", err,
		    SK_KVA(uap->cinfo));
		goto done;
	}

done:
	fp_drop(p, uap->c, fp, 0);

	return err;
}

#if SK_LOG
/* Hoisted out of line to reduce kernel stack footprint */
SK_LOG_ATTRIBUTE
static void
channel_sync_log1(uint64_t verb, const char *sync, struct proc *p,
    const struct nexus_adapter *na, const struct kern_channel *ch,
    const struct __kern_channel_ring *kring, ring_id_t i)
{
	verb |= SK_VERB_SYNC;
	SK_DF(verb, "%s(%d) pre: %s ring %u na \"%s\" (0x%llx) ch 0x%llx "
	    "th 0x%llx h %u kh %u", sk_proc_name_address(p), sk_proc_pid(p),
	    sync, i, na->na_name, SK_KVA(na), SK_KVA(ch),
	    SK_KVA(current_thread()), kring->ckr_ring->ring_head,
	    kring->ckr_khead);
}

SK_LOG_ATTRIBUTE
static void
channel_sync_log2(uint64_t verb, const char *sync, struct proc *p,
    const struct nexus_adapter *na, const struct __kern_channel_ring *kring,
    ring_id_t i)
{
	verb |= SK_VERB_SYNC;
	SK_DF(verb, "%s(%d) post: %s ring %u na \"%s\" h %u kh %u",
	    sk_proc_name_address(p), sk_proc_pid(p), sync, i, na->na_name,
	    kring->ckr_ring->ring_head, kring->ckr_khead);
}
#endif /* SK_LOG */

int
__channel_sync(struct proc *p, struct __channel_sync_args *uap, int *retval)
{
#pragma unused(retval)
	struct fileproc *fp;
	sk_protect_t protect = NULL;
	struct nexus_adapter *na;
	struct __kern_channel_ring *krings, *kring;
	struct kern_channel *ch;
	sync_mode_t mode;
	ring_id_t i, qfirst, qlast;
	sync_flags_t flags, upp_sync_flags = 0;
	enum txrx t;
	int err;
	int s;

	net_update_uptime();

	AUDIT_ARG(fd, uap->c);

	err = fp_get_ftype(p, uap->c, DTYPE_CHANNEL, ENODEV, &fp);
	if (__improbable(err != 0)) {
		SK_DSC(p, "fp_get_ftype err %u", err);
		return err;
	}
	ch = fp_get_data(fp);

	lck_mtx_lock(&ch->ch_lock);
	ASSERT(!(ch->ch_flags & CHANF_KERNEL));

	mode = uap->mode;
	flags = uap->flags;
	if (__improbable(mode != CHANNEL_SYNC_TX && mode != CHANNEL_SYNC_RX &&
	    mode != CHANNEL_SYNC_UPP)) {
		SK_DSC(p, "EINVAL: mode %u", mode);
		err = EINVAL;
		goto done;
	}

	if (__improbable((ch->ch_flags & CHANF_USER_PACKET_POOL) == 0 &&
	    (flags & (CHANNEL_SYNCF_ALLOC | CHANNEL_SYNCF_FREE |
	    CHANNEL_SYNCF_ALLOC_BUF)) != 0)) {
		SK_DSC(p, "EINVAL: !CHANF_USER_PACKET_POOL with "
		    "SYNCF_ALLOC/FREE");
		err = EINVAL;
		goto done;
	}

	if (__improbable(ch->ch_flags & CHANF_DEFUNCT)) {
		SK_DSC(p, "channel is defunct");
		err = ENXIO;
		goto done;
	}

	/* clear CHANF_DEFUNCT_SKIP if it was set during defunct last time */
	if (__improbable(ch->ch_flags & CHANF_DEFUNCT_SKIP)) {
		os_atomic_andnot(&ch->ch_flags, CHANF_DEFUNCT_SKIP, relaxed);
	}

	na = ch->ch_na; /* we have a reference */
	ASSERT(na != NULL);
	ASSERT(NA_IS_ACTIVE(na));

	if (__improbable(na_reject_channel(ch, na))) {
		SK_DSC(p, "channel is non-permissive");
		err = ENXIO;
		goto done;
	}

	/* mark thread with sync-in-progress flag */
	protect = sk_sync_protect();

	/* update our work timestamp */
	na->na_work_ts = _net_uptime;

	/* and make this channel eligible for draining again */
	if (na->na_flags & NAF_DRAINING) {
		os_atomic_andnot(&na->na_flags, NAF_DRAINING, relaxed);
	}

	if (mode == CHANNEL_SYNC_UPP) {
		upp_sync_flags = NA_SYNCF_FORCE_UPP_SYNC;
		if (flags & CHANNEL_SYNCF_PURGE) {
			upp_sync_flags |= NA_SYNCF_UPP_PURGE;
		}
		goto packet_pool_sync;
	}

	t = (mode == CHANNEL_SYNC_TX ? NR_TX : NR_RX);
	krings = NAKR(na, t);
	qfirst = ch->ch_first[t];
	qlast = ch->ch_last[t];

	for (i = qfirst; i < qlast; i++) {
		kring = krings + i;
		s = kr_enter(kring, TRUE);
		ASSERT(s == 0);
#if SK_LOG
		if (__improbable((sk_verbose & SK_VERB_SYNC) != 0)) {
			channel_sync_log1((mode == CHANNEL_SYNC_TX) ?
			    SK_VERB_TX : SK_VERB_RX, (mode == CHANNEL_SYNC_TX) ?
			    "txsync" : "rxsync", p, na, ch, kring, i);
		}
#endif /* SK_LOG */

		switch (mode) {
		case CHANNEL_SYNC_TX: {
			int error = 0;

			DTRACE_SKYWALK2(pretxprologue, struct kern_channel *,
			    ch, struct __kern_channel_ring *, kring);

			if (kr_txsync_prologue(ch, kring, p) >=
			    kring->ckr_num_slots) {
				kr_log_bad_ring(kring);
				error = EFAULT;
				if (!err) {
					SK_DSC(p, "EFAULT: "
					    "kr_txsync_prologue()");
					err = EFAULT;
				}
			} else if (kring->ckr_na_sync(kring, p,
			    NA_SYNCF_FORCE_RECLAIM) == 0) {
				kr_txsync_finalize(ch, kring, p);
			} else {
				error = EIO;
				if (!err) {
					SK_DSC(p, "EIO: TX "
					    "kring->ckr_na_sync()");
					err = EIO;
				}
			}

			DTRACE_SKYWALK3(posttxfinalize, struct kern_channel *,
			    ch, struct __kern_channel_ring *, kring, int,
			    error);
		}
		break;

		case CHANNEL_SYNC_RX: {
			int error = 0;

			DTRACE_SKYWALK2(prerxprologue, struct kern_channel *,
			    ch, struct __kern_channel_ring *, kring);

			if (kr_rxsync_prologue(ch, kring, p) >=
			    kring->ckr_num_slots) {
				kr_log_bad_ring(kring);
				error = EFAULT;
				if (!err) {
					SK_DSC(p, "EFAULT: "
					    "kr_rxsync_prologue()");
					err = EFAULT;
				}
			} else if (kring->ckr_na_sync(kring, p,
			    NA_SYNCF_FORCE_READ) == 0) {
				kr_rxsync_finalize(ch, kring, p);
			} else {
				error = EIO;
				if (!err) {
					SK_DSC(p, "EIO: " "RX "
					    "kring->ckr_na_sync()");
					err = EIO;
				}
			}

			DTRACE_SKYWALK3(postrxfinalize, struct kern_channel *,
			    ch, struct __kern_channel_ring *, kring, int,
			    error);
		}
		break;

		default:
			VERIFY(0);
			/* NOTREACHED */
			__builtin_unreachable();
		}

#if SK_LOG
		if (__improbable((sk_verbose & SK_VERB_SYNC) != 0)) {
			channel_sync_log2((mode == CHANNEL_SYNC_TX) ?
			    SK_VERB_TX : SK_VERB_RX, (mode == CHANNEL_SYNC_TX) ?
			    "txsync" : "rxsync", p, na, kring, i);
		}
#endif /* SK_LOG */

		kr_exit(kring);
	}

packet_pool_sync:
	if (flags & (CHANNEL_SYNCF_ALLOC |
	    CHANNEL_SYNCF_LARGE_ALLOC | CHANNEL_SYNCF_ALLOC_BUF)) {
		enum txrx type;

		if (flags & CHANNEL_SYNCF_LARGE_ALLOC) {
			ASSERT(!(flags & CHANNEL_SYNCF_ALLOC));
			ASSERT(!(flags & CHANNEL_SYNCF_ALLOC_BUF));
			type = NR_LBA;
			qfirst = ch->ch_first[type];
			qlast = ch->ch_last[type];
		} else {
			type = NR_A;
			qfirst = ch->ch_first[type];
			qlast = ch->ch_last[type];
			if (!(flags & CHANNEL_SYNCF_ALLOC)) {
				qfirst++;
			} else if ((qlast - qfirst) > 1 &&
			    !(flags & CHANNEL_SYNCF_ALLOC_BUF)) {
				qlast--;
			}
		}
		ASSERT(qfirst != qlast);
		krings = NAKR(na, type);

		for (i = qfirst; i < qlast; i++) {
			kring = krings + i;
			s = kr_enter(kring, TRUE);
			ASSERT(s == 0);
#if SK_LOG
			if (__improbable((sk_verbose & SK_VERB_SYNC) != 0)) {
				channel_sync_log1(0, "alloc-sync", p, na, ch,
				    kring, i);
			}
#endif /* SK_LOG */
			if (__improbable(kr_alloc_sync_prologue(kring, p) >=
			    kring->ckr_num_slots)) {
				kr_log_bad_ring(kring);
				if (!err) {
					SK_DSC(p,
					    "EFAULT: kr_alloc_sync_prologue()");
					err = EFAULT;
				}
			} else if (kring->ckr_na_sync(kring, p,
			    upp_sync_flags) == 0) {
				kr_alloc_sync_finalize(kring, p);
			} else {
				if (!err) {
					SK_DSC(p,
					    "EIO: ALLOC: ring->ckr_na_sync()");
					err = EIO;
				}
				skywalk_kill_process(p,
				    SKYWALK_KILL_REASON_SYNC_FAILED |
				    SKYWALK_KILL_REASON_ALLOC_SYNC);
			}
#if SK_LOG
			if (__improbable((sk_verbose & SK_VERB_SYNC) != 0)) {
				channel_sync_log2(0, "alloc-sync", p, na,
				    kring, i);
			}
#endif /* SK_LOG */
			kr_exit(kring);
		}
	} /* CHANNEL_SYNCF_ALLOC */

	if (flags & CHANNEL_SYNCF_FREE) {
		qfirst = ch->ch_first[NR_F];
		qlast = ch->ch_last[NR_F];
		ASSERT(qfirst != qlast);
		krings = NAKR(na, NR_F);

		for (i = qfirst; i < qlast; i++) {
			kring = krings + i;
			s = kr_enter(kring, TRUE);
			ASSERT(s == 0);
#if SK_LOG
			if (__improbable((sk_verbose & SK_VERB_SYNC) != 0)) {
				channel_sync_log1(0, "free-sync", p, na, ch,
				    kring, i);
			}
#endif /* SK_LOG */
			if (__improbable(kr_free_sync_prologue(kring, p) >=
			    kring->ckr_num_slots)) {
				kr_log_bad_ring(kring);
				if (!err) {
					SK_DSC(p,
					    "EFAULT: kr_free_sync_prologue()");
					err = EFAULT;
				}
			} else if (kring->ckr_na_sync(kring, p,
			    upp_sync_flags) == 0) {
				kr_free_sync_finalize(kring, p);
			} else {
				if (!err) {
					SK_DSC(p,
					    "EIO: FREE: ring->ckr_na_sync()");
					err = EIO;
				}
				skywalk_kill_process(p,
				    SKYWALK_KILL_REASON_SYNC_FAILED |
				    SKYWALK_KILL_REASON_FREE_SYNC);
			}
#if SK_LOG
			if (__improbable((sk_verbose & SK_VERB_SYNC) != 0)) {
				channel_sync_log2(0, "free-sync", p, na,
				    kring, i);
			}
#endif /* SK_LOG */
			kr_exit(kring);
		}
	} /* CHANNEL_SYNCF_FREE */

	/* unmark thread with sync-in-progress flag */
	sk_sync_unprotect(protect);

done:
	lck_mtx_unlock(&ch->ch_lock);
	fp_drop(p, uap->c, fp, 0);

	VERIFY(!sk_is_sync_protected());

	return err;
}

int
__channel_get_opt(struct proc *p, struct __channel_get_opt_args *uap,
    int *retval)
{
#pragma unused(retval)
	struct fileproc *fp;
	struct kern_channel *ch = NULL;
	struct sockopt sopt;
	uint32_t optlen;
	int err = 0;

	AUDIT_ARG(fd, uap->c);

	err = fp_get_ftype(p, uap->c, DTYPE_CHANNEL, ENODEV, &fp);
	if (err != 0) {
		SK_DSC(p, "fp_get_ftype err %u", err);
		return err;
	}
	ch = fp_get_data(fp);

	if (uap->aoptlen == USER_ADDR_NULL) {
		SK_DSC(p, "EINVAL: uap->aoptlen == USER_ADDR_NULL");
		err = EINVAL;
		goto done;
	}

	if (uap->aoptval != USER_ADDR_NULL) {
		err = copyin(uap->aoptlen, &optlen, sizeof(optlen));
		if (err != 0) {
			SK_DSC(p, "copyin err %u: aoptlen 0x%llx", err,
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

	lck_mtx_lock(&ch->ch_lock);
	err = ch_get_opt(ch, &sopt);
	lck_mtx_unlock(&ch->ch_lock);
	if (err == 0) {
		optlen = (uint32_t)sopt.sopt_valsize;
		err = copyout(&optlen, uap->aoptlen, sizeof(optlen));
#if SK_LOG
		if (err != 0) {
			SK_DSC(p, "copyout err %u: aoptlen 0x%llx", err,
			    SK_KVA(uap->aoptlen));
		}
#endif
	}

done:
	fp_drop(p, uap->c, fp, 0);

	return err;
}

int
__channel_set_opt(struct proc *p, struct __channel_set_opt_args *uap,
    int *retval)
{
#pragma unused(retval)
	struct fileproc *fp;
	struct kern_channel *ch = NULL;
	struct sockopt sopt;
	int err = 0;

	AUDIT_ARG(fd, uap->c);

	err = fp_get_ftype(p, uap->c, DTYPE_CHANNEL, ENODEV, &fp);
	if (err != 0) {
		SK_DSC(p, "fp_get_ftype err %u", err);
		return err;
	}
	ch = fp_get_data(fp);

	bzero(&sopt, sizeof(sopt));
	sopt.sopt_dir = SOPT_SET;
	sopt.sopt_name = uap->opt;
	sopt.sopt_val = uap->aoptval;
	sopt.sopt_valsize = uap->optlen;
	sopt.sopt_p = p;

	lck_mtx_lock(&ch->ch_lock);
	if (__improbable(ch->ch_flags & (CHANF_CLOSING | CHANF_DEFUNCT))) {
		SK_DSC(p, "channel is closing/defunct");
		err = ENXIO;
	} else if (__improbable(ch->ch_na == NULL ||
	    !NA_IS_ACTIVE(ch->ch_na) || na_reject_channel(ch, ch->ch_na))) {
		SK_DSC(p, "channel is non-permissive");
		err = ENXIO;
	} else {
		err = ch_set_opt(ch, &sopt);
	}
	lck_mtx_unlock(&ch->ch_lock);

	fp_drop(p, uap->c, fp, 0);

#if SK_LOG
	if (err != 0) {
		SK_DSC(p, "ch_set_opt() err %u", err);
	}
#endif

	return err;
}
