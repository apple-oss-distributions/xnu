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
 * Copyright (c) 1989, 1991, 1993, 1995
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
 *	@(#)nfs_socket.c	8.5 (Berkeley) 3/30/95
 * FreeBSD-Id: nfs_socket.c,v 1.30 1997/10/28 15:59:07 bde Exp $
 */

#include <nfs/nfs_conf.h>
#if CONFIG_NFS_SERVER

/*
 * Socket operations for use by nfs
 */

#include <sys/systm.h>
#include <sys/kauth.h>
#include <sys/mount_internal.h>
#include <sys/kpi_mbuf.h>
#include <IOKit/IOLib.h>

#include <netinet/in.h>

#include <nfs/rpcv2.h>
#include <nfs/nfsproto.h>
#include <nfs/nfs.h>
#include <nfs/xdr_subs.h>
#include <nfs/nfsm_subs.h>
#include <nfs/nfs_gss.h>

ZONE_DEFINE(nfsrv_descript_zone, "NFSV3 srvdesc",
    sizeof(struct nfsrv_descript), ZC_NONE);

int nfsrv_sock_max_rec_queue_length = 128; /* max # RPC records queued on (UDP) socket */

int nfsrv_getstream(struct nfsrv_sock *, int);
int nfsrv_getreq(struct nfsrv_descript *);
extern int nfsv3_procid[NFS_NPROCS];

#define NFS_TRYLOCK_MSEC_SLEEP 1

/*
 * compare two sockaddr structures
 */
int
nfs_sockaddr_cmp(struct sockaddr *sa1, struct sockaddr *sa2)
{
	if (!sa1) {
		return -1;
	}
	if (!sa2) {
		return 1;
	}
	if (sa1->sa_family != sa2->sa_family) {
		return (sa1->sa_family < sa2->sa_family) ? -1 : 1;
	}
	if (sa1->sa_len != sa2->sa_len) {
		return (sa1->sa_len < sa2->sa_len) ? -1 : 1;
	}
	if (sa1->sa_family == AF_INET) {
		return bcmp(&((struct sockaddr_in*)sa1)->sin_addr,
		           &((struct sockaddr_in*)sa2)->sin_addr, sizeof(((struct sockaddr_in*)sa1)->sin_addr));
	}
	if (sa1->sa_family == AF_INET6) {
		return bcmp(&((struct sockaddr_in6*)sa1)->sin6_addr,
		           &((struct sockaddr_in6*)sa2)->sin6_addr, sizeof(((struct sockaddr_in6*)sa1)->sin6_addr));
	}
	return -1;
}

/*
 * Generate the rpc reply header
 * siz arg. is used to decide if adding a cluster is worthwhile
 */
int
nfsrv_rephead(
	struct nfsrv_descript *nd,
	__unused struct nfsrv_sock *slp,
	struct nfsm_chain *nmrepp,
	size_t siz)
{
	mbuf_t mrep;
	u_int32_t *tl;
	struct nfsm_chain nmrep;
	int err, error;

	err = nd->nd_repstat;
	if (err && (nd->nd_vers == NFS_VER2)) {
		siz = 0;
	}

	/*
	 * If this is a big reply, use a cluster else
	 * try and leave leading space for the lower level headers.
	 */
	siz += RPC_REPLYSIZ;
	if (siz >= nfs_mbuf_minclsize) {
		error = mbuf_getpacket(MBUF_WAITOK, &mrep);
	} else {
		error = mbuf_gethdr(MBUF_WAITOK, MBUF_TYPE_DATA, &mrep);
	}
	if (error) {
		/* unable to allocate packet */
		/* XXX should we keep statistics for these errors? */
		return error;
	}
	if (siz < nfs_mbuf_minclsize) {
		/* leave space for lower level headers */
		tl = mbuf_data(mrep);
		tl += 80 / sizeof(*tl);  /* XXX max_hdr? XXX */
		mbuf_setdata(mrep, tl, 6 * NFSX_UNSIGNED);
	}
	nfsm_chain_init(&nmrep, mrep);
	nfsm_chain_add_32(error, &nmrep, nd->nd_retxid);
	nfsm_chain_add_32(error, &nmrep, RPC_REPLY);
	if (err == ERPCMISMATCH || (err & NFSERR_AUTHERR)) {
		nfsm_chain_add_32(error, &nmrep, RPC_MSGDENIED);
		if (err & NFSERR_AUTHERR) {
			nfsm_chain_add_32(error, &nmrep, RPC_AUTHERR);
			nfsm_chain_add_32(error, &nmrep, (err & ~NFSERR_AUTHERR));
		} else {
			nfsm_chain_add_32(error, &nmrep, RPC_MISMATCH);
			nfsm_chain_add_32(error, &nmrep, RPC_VER2);
			nfsm_chain_add_32(error, &nmrep, RPC_VER2);
		}
	} else {
		/* reply status */
		nfsm_chain_add_32(error, &nmrep, RPC_MSGACCEPTED);
		if (nd->nd_gss_context != NULL) {
			/* RPCSEC_GSS verifier */
			error = nfs_gss_svc_verf_put(nd, &nmrep);
			if (error) {
				nfsm_chain_add_32(error, &nmrep, RPC_SYSTEM_ERR);
				goto done;
			}
		} else {
			/* RPCAUTH_NULL verifier */
			nfsm_chain_add_32(error, &nmrep, RPCAUTH_NULL);
			nfsm_chain_add_32(error, &nmrep, 0);
		}
		/* accepted status */
		switch (err) {
		case EPROGUNAVAIL:
			nfsm_chain_add_32(error, &nmrep, RPC_PROGUNAVAIL);
			break;
		case EPROGMISMATCH:
			nfsm_chain_add_32(error, &nmrep, RPC_PROGMISMATCH);
			/* XXX hard coded versions? */
			nfsm_chain_add_32(error, &nmrep, NFS_VER2);
			nfsm_chain_add_32(error, &nmrep, NFS_VER3);
			break;
		case EPROCUNAVAIL:
			nfsm_chain_add_32(error, &nmrep, RPC_PROCUNAVAIL);
			break;
		case EBADRPC:
			nfsm_chain_add_32(error, &nmrep, RPC_GARBAGE);
			break;
		default:
			nfsm_chain_add_32(error, &nmrep, RPC_SUCCESS);
			if (nd->nd_gss_context != NULL) {
				error = nfs_gss_svc_prepare_reply(nd, &nmrep);
			}
			if (err != NFSERR_RETVOID) {
				nfsm_chain_add_32(error, &nmrep,
				    (err ? nfsrv_errmap(nd, err) : 0));
			}
			break;
		}
	}

done:
	nfsm_chain_build_done(error, &nmrep);
	if (error) {
		/* error composing reply header */
		/* XXX should we keep statistics for these errors? */
		mbuf_freem(mrep);
		return error;
	}

	*nmrepp = nmrep;
	if ((err != 0) && (err != NFSERR_RETVOID)) {
		OSAddAtomic64(1, &nfsrvstats.srvrpc_errs);
	}
	return 0;
}

/*
 * The nfs server send routine.
 *
 * - return EINTR or ERESTART if interrupted by a signal
 * - return EPIPE if a connection is lost for connection based sockets (TCP...)
 * - do any cleanup required by recoverable socket errors (???)
 */
int
nfsrv_send(struct nfsrv_sock *slp, mbuf_t nam, mbuf_t top)
{
	int error;
	socket_t so = slp->ns_so;
	struct sockaddr *sendnam;
	struct msghdr msg;

	bzero(&msg, sizeof(msg));
	if (nam && !sock_isconnected(so) && (slp->ns_sotype != SOCK_STREAM)) {
		if ((sendnam = mbuf_data(nam))) {
			msg.msg_name = (caddr_t)sendnam;
			msg.msg_namelen = sendnam->sa_len;
		}
	}
	if (NFSRV_IS_DBG(NFSRV_FAC_SRV, 15)) {
		nfs_dump_mbuf(__func__, __LINE__, "nfsrv_send\n", top);
	}
	error = sock_sendmbuf(so, &msg, top, 0, NULL);
	if (!error) {
		return 0;
	}
	log(LOG_INFO, "nfsd send error %d\n", error);

	if ((error == EWOULDBLOCK) && (slp->ns_sotype == SOCK_STREAM)) {
		error = EPIPE;  /* zap TCP sockets if they time out on send */
	}
	/* Handle any recoverable (soft) socket errors here. (???) */
	if (error != EINTR && error != ERESTART && error != EIO &&
	    error != EWOULDBLOCK && error != EPIPE) {
		error = 0;
	}

	return error;
}

/*
 * Socket upcall routine for the nfsd sockets.
 * The caddr_t arg is a pointer to the "struct nfsrv_sock".
 * Essentially do as much as possible non-blocking, else punt and it will
 * be called with MBUF_WAITOK from an nfsd.
 */
void
nfsrv_rcv(socket_t so, void *arg, int waitflag)
{
	struct nfsrv_sock *slp = arg;

	while (1) {
		if (!nfsd_thread_count || !(slp->ns_flag & SLP_VALID)) {
			return;
		}
		if (lck_rw_try_lock_exclusive(&slp->ns_rwlock)) {
			/* Exclusive lock acquired */
			break;
		}
		IOSleep(NFS_TRYLOCK_MSEC_SLEEP);
	}

	nfsrv_rcv_locked(so, slp, waitflag);
	/* Note: ns_rwlock gets dropped when called with MBUF_DONTWAIT */
}
void
nfsrv_rcv_locked(socket_t so, struct nfsrv_sock *slp, int waitflag)
{
	mbuf_t m, mp, mhck, m2;
	int ns_flag = 0, error;
	struct msghdr   msg;
	size_t bytes_read;

	if ((slp->ns_flag & SLP_VALID) == 0) {
		if (waitflag == MBUF_DONTWAIT) {
			lck_rw_done(&slp->ns_rwlock);
		}
		return;
	}

#ifdef notdef
	/*
	 * Define this to test for nfsds handling this under heavy load.
	 */
	if (waitflag == MBUF_DONTWAIT) {
		ns_flag = SLP_NEEDQ;
		goto dorecs;
	}
#endif
	if (slp->ns_sotype == SOCK_STREAM) {
		/*
		 * If there are already records on the queue, defer soreceive()
		 * to an(other) nfsd so that there is feedback to the TCP layer that
		 * the nfs servers are heavily loaded.
		 */
		if (slp->ns_rec) {
			ns_flag = SLP_NEEDQ;
			goto dorecs;
		}

		/*
		 * Do soreceive().
		 */
		bytes_read = 1000000000;
		error = sock_receivembuf(so, NULL, &mp, MSG_DONTWAIT, &bytes_read);
		if (error || mp == NULL) {
			if (error == EWOULDBLOCK) {
				ns_flag = (waitflag == MBUF_DONTWAIT) ? SLP_NEEDQ : 0;
			} else {
				ns_flag = SLP_DISCONN;
			}
			goto dorecs;
		}
		m = mp;
		if (slp->ns_rawend) {
			if ((error = mbuf_setnext(slp->ns_rawend, m))) {
				panic("nfsrv_rcv: mbuf_setnext failed %d", error);
			}
			slp->ns_cc += bytes_read;
		} else {
			slp->ns_raw = m;
			slp->ns_cc = bytes_read;
		}
		while ((m2 = mbuf_next(m))) {
			m = m2;
		}
		slp->ns_rawend = m;

		/*
		 * Now try and parse record(s) out of the raw stream data.
		 */
		error = nfsrv_getstream(slp, waitflag);
		if (error) {
			if (error == EPERM) {
				ns_flag = SLP_DISCONN;
			} else {
				ns_flag = SLP_NEEDQ;
			}
		}
	} else {
		struct sockaddr_storage nam;

		if (slp->ns_reccnt >= nfsrv_sock_max_rec_queue_length) {
			/* already have max # RPC records queued on this socket */
			ns_flag = SLP_NEEDQ;
			goto dorecs;
		}

		bzero(&msg, sizeof(msg));
		msg.msg_name = (caddr_t)&nam;
		msg.msg_namelen = sizeof(nam);

		do {
			bytes_read = 1000000000;
			error = sock_receivembuf(so, &msg, &mp, MSG_DONTWAIT | MSG_NEEDSA, &bytes_read);
			if (mp) {
				if (msg.msg_name && (mbuf_get(MBUF_WAITOK, MBUF_TYPE_SONAME, &mhck) == 0)) {
					mbuf_setlen(mhck, nam.ss_len);
					bcopy(&nam, mbuf_data(mhck), nam.ss_len);
					m = mhck;
					if (mbuf_setnext(m, mp)) {
						/* trouble... just drop it */
						printf("nfsrv_rcv: mbuf_setnext failed\n");
						mbuf_free(mhck);
						m = mp;
					}
				} else {
					m = mp;
				}
				if (slp->ns_recend) {
					mbuf_setnextpkt(slp->ns_recend, m);
				} else {
					slp->ns_rec = m;
					slp->ns_flag |= SLP_DOREC;
				}
				slp->ns_recend = m;
				mbuf_setnextpkt(m, NULL);
				slp->ns_reccnt++;
			}
		} while (mp);
	}

	/*
	 * Now try and process the request records, non-blocking.
	 */
dorecs:
	if (ns_flag) {
		slp->ns_flag |= ns_flag;
	}
	if (waitflag == MBUF_DONTWAIT) {
		int wake = (slp->ns_flag & SLP_WORKTODO);
		lck_rw_done(&slp->ns_rwlock);
		if (wake && nfsd_thread_count) {
			while (1) {
				if ((slp->ns_flag & SLP_VALID) == 0) {
					break;
				}
				if (lck_mtx_try_lock(&nfsd_mutex)) {
					/* Mutex acquired */
					nfsrv_wakenfsd(slp);
					lck_mtx_unlock(&nfsd_mutex);
					break;
				}
				IOSleep(NFS_TRYLOCK_MSEC_SLEEP);
			}
		}
	}
}

/*
 * Try and extract an RPC request from the mbuf data list received on a
 * stream socket. The "waitflag" argument indicates whether or not it
 * can sleep.
 */
int
nfsrv_getstream(struct nfsrv_sock *slp, int waitflag)
{
	mbuf_t m;
	char *cp1, *cp2, *mdata;
	int error;
	size_t len, mlen;
	mbuf_t om, m2, recm;
	u_int32_t recmark;

	if (slp->ns_flag & SLP_GETSTREAM) {
		panic("nfs getstream");
	}
	slp->ns_flag |= SLP_GETSTREAM;
	for (;;) {
		if (slp->ns_reclen == 0) {
			if (slp->ns_cc < NFSX_UNSIGNED) {
				slp->ns_flag &= ~SLP_GETSTREAM;
				return 0;
			}
			m = slp->ns_raw;
			mdata = mbuf_data(m);
			mlen = mbuf_len(m);
			if (mlen >= NFSX_UNSIGNED) {
				bcopy(mdata, (caddr_t)&recmark, NFSX_UNSIGNED);
				mdata += NFSX_UNSIGNED;
				mlen -= NFSX_UNSIGNED;
				mbuf_setdata(m, mdata, mlen);
			} else {
				cp1 = (caddr_t)&recmark;
				cp2 = mdata;
				while (cp1 < ((caddr_t)&recmark) + NFSX_UNSIGNED) {
					while (mlen == 0) {
						m = mbuf_next(m);
						cp2 = mbuf_data(m);
						mlen = mbuf_len(m);
					}
					*cp1++ = *cp2++;
					mlen--;
					mbuf_setdata(m, cp2, mlen);
				}
			}
			slp->ns_cc -= NFSX_UNSIGNED;
			recmark = ntohl(recmark);
			slp->ns_reclen = recmark & ~0x80000000;
			if (recmark & 0x80000000) {
				slp->ns_flag |= SLP_LASTFRAG;
			} else {
				slp->ns_flag &= ~SLP_LASTFRAG;
			}
			if (slp->ns_reclen <= 0 || slp->ns_reclen > NFS_MAXPACKET) {
				slp->ns_flag &= ~SLP_GETSTREAM;
				return EPERM;
			}
		}

		/*
		 * Now get the record part.
		 *
		 * Note that slp->ns_reclen may be 0.  Linux sometimes
		 * generates 0-length RPCs
		 */
		recm = NULL;
		if (slp->ns_cc == slp->ns_reclen) {
			recm = slp->ns_raw;
			slp->ns_raw = slp->ns_rawend = NULL;
			slp->ns_cc = slp->ns_reclen = 0;
		} else if (slp->ns_cc > slp->ns_reclen) {
			len = 0;
			m = slp->ns_raw;
			mlen = mbuf_len(m);
			mdata = mbuf_data(m);
			om = NULL;
			while (len < slp->ns_reclen) {
				if ((len + mlen) > slp->ns_reclen) {
					if (mbuf_copym(m, 0, slp->ns_reclen - len, waitflag, &m2)) {
						slp->ns_flag &= ~SLP_GETSTREAM;
						return EWOULDBLOCK;
					}
					if (om) {
						if (mbuf_setnext(om, m2)) {
							/* trouble... just drop it */
							printf("nfsrv_getstream: mbuf_setnext failed\n");
							mbuf_freem(m2);
							slp->ns_flag &= ~SLP_GETSTREAM;
							return EWOULDBLOCK;
						}
						recm = slp->ns_raw;
					} else {
						recm = m2;
					}
					mdata += slp->ns_reclen - len;
					mlen -= slp->ns_reclen - len;
					mbuf_setdata(m, mdata, mlen);
					len = slp->ns_reclen;
				} else if ((len + mlen) == slp->ns_reclen) {
					om = m;
					len += mlen;
					m = mbuf_next(m);
					recm = slp->ns_raw;
					if (mbuf_setnext(om, NULL)) {
						printf("nfsrv_getstream: mbuf_setnext failed 2\n");
						slp->ns_flag &= ~SLP_GETSTREAM;
						return EWOULDBLOCK;
					}
					mlen = mbuf_len(m);
					mdata = mbuf_data(m);
				} else {
					om = m;
					len += mlen;
					m = mbuf_next(m);
					mlen = mbuf_len(m);
					mdata = mbuf_data(m);
				}
			}
			slp->ns_raw = m;
			slp->ns_cc -= len;
			slp->ns_reclen = 0;
		} else {
			slp->ns_flag &= ~SLP_GETSTREAM;
			return 0;
		}

		/*
		 * Accumulate the fragments into a record.
		 */
		if (slp->ns_frag == NULL) {
			slp->ns_frag = recm;
		} else {
			m = slp->ns_frag;
			while ((m2 = mbuf_next(m))) {
				m = m2;
			}
			if ((error = mbuf_setnext(m, recm))) {
				panic("nfsrv_getstream: mbuf_setnext failed 3, %d", error);
			}
		}
		if (slp->ns_flag & SLP_LASTFRAG) {
			if (slp->ns_recend) {
				mbuf_setnextpkt(slp->ns_recend, slp->ns_frag);
			} else {
				slp->ns_rec = slp->ns_frag;
				slp->ns_flag |= SLP_DOREC;
			}
			slp->ns_recend = slp->ns_frag;
			slp->ns_frag = NULL;
		}
	}
}

/*
 * Parse an RPC header.
 */
int
nfsrv_dorec(
	struct nfsrv_sock *slp,
	struct nfsd *nfsd,
	struct nfsrv_descript **ndp)
{
	mbuf_t m;
	mbuf_t nam;
	struct nfsrv_descript *nd;
	int error = 0;

	*ndp = NULL;
	if (!(slp->ns_flag & (SLP_VALID | SLP_DOREC)) || (slp->ns_rec == NULL)) {
		return ENOBUFS;
	}
	nd = zalloc(nfsrv_descript_zone);
	m = slp->ns_rec;
	slp->ns_rec = mbuf_nextpkt(m);
	if (slp->ns_rec) {
		mbuf_setnextpkt(m, NULL);
	} else {
		slp->ns_flag &= ~SLP_DOREC;
		slp->ns_recend = NULL;
	}
	slp->ns_reccnt--;
	if (mbuf_type(m) == MBUF_TYPE_SONAME) {
		nam = m;
		m = mbuf_next(m);
		if ((error = mbuf_setnext(nam, NULL))) {
			panic("nfsrv_dorec: mbuf_setnext failed %d", error);
		}
	} else {
		nam = NULL;
	}
	nd->nd_nam2 = nam;
	nfsm_chain_dissect_init(error, &nd->nd_nmreq, m);
	if (!error) {
		error = nfsrv_getreq(nd);
	}
	if (error) {
		if (nam) {
			mbuf_freem(nam);
		}
		if (nd->nd_gss_context) {
			nfs_gss_svc_ctx_deref(nd->nd_gss_context);
		}
		NFS_ZFREE(nfsrv_descript_zone, nd);
		return error;
	}
	nd->nd_mrep = NULL;
	*ndp = nd;
	nfsd->nfsd_nd = nd;
	return 0;
}

/*
 * Parse an RPC request
 * - verify it
 * - fill in the cred struct.
 */
int
nfsrv_getreq(struct nfsrv_descript *nd)
{
	struct nfsm_chain *nmreq;
	int len, i;
	u_int32_t nfsvers, auth_type;
	int error = 0;
	uid_t user_id;
	gid_t group_id;
	short ngroups;
	uint32_t val;

	nd->nd_cr = NULL;
	nd->nd_gss_context = NULL;
	nd->nd_gss_seqnum = 0;
	nd->nd_gss_mb = NULL;

	user_id = group_id = -2;
	val = auth_type = len = 0;

	nmreq = &nd->nd_nmreq;
	nfsm_chain_get_32(error, nmreq, nd->nd_retxid); // XID
	nfsm_chain_get_32(error, nmreq, val);           // RPC Call
	if (!error && (val != RPC_CALL)) {
		error = EBADRPC;
	}
	nfsmout_if(error);
	nd->nd_repstat = 0;
	nfsm_chain_get_32(error, nmreq, val);   // RPC Version
	nfsmout_if(error);
	if (val != RPC_VER2) {
		nd->nd_repstat = ERPCMISMATCH;
		nd->nd_procnum = NFSPROC_NOOP;
		return 0;
	}
	nfsm_chain_get_32(error, nmreq, val);   // RPC Program Number
	nfsmout_if(error);
	if (val != NFS_PROG) {
		nd->nd_repstat = EPROGUNAVAIL;
		nd->nd_procnum = NFSPROC_NOOP;
		return 0;
	}
	nfsm_chain_get_32(error, nmreq, nfsvers);// NFS Version Number
	nfsmout_if(error);
	if ((nfsvers < NFS_VER2) || (nfsvers > NFS_VER3)) {
		nd->nd_repstat = EPROGMISMATCH;
		nd->nd_procnum = NFSPROC_NOOP;
		return 0;
	}
	nd->nd_vers = nfsvers;
	nfsm_chain_get_32(error, nmreq, nd->nd_procnum);// NFS Procedure Number
	nfsmout_if(error);
	if ((nd->nd_procnum >= NFS_NPROCS) ||
	    ((nd->nd_vers == NFS_VER2) && (nd->nd_procnum > NFSV2PROC_STATFS))) {
		nd->nd_repstat = EPROCUNAVAIL;
		nd->nd_procnum = NFSPROC_NOOP;
		return 0;
	}
	if (nfsvers != NFS_VER3) {
		nd->nd_procnum = nfsv3_procid[nd->nd_procnum];
	}
	nfsm_chain_get_32(error, nmreq, auth_type);     // Auth Flavor
	nfsm_chain_get_32(error, nmreq, len);           // Auth Length
	if (!error && (len < 0 || len > RPCAUTH_MAXSIZ)) {
		error = EBADRPC;
	}
	nfsmout_if(error);

	/* Handle authentication */
	if (auth_type == RPCAUTH_SYS) {
		struct posix_cred temp_pcred;
		if (nd->nd_procnum == NFSPROC_NULL) {
			return 0;
		}
		nd->nd_sec = RPCAUTH_SYS;
		nfsm_chain_adv(error, nmreq, NFSX_UNSIGNED);    // skip stamp
		nfsm_chain_get_32(error, nmreq, len);           // hostname length
		if (len < 0 || len > NFS_MAXNAMLEN) {
			error = EBADRPC;
		}
		nfsm_chain_adv(error, nmreq, nfsm_rndup(len));  // skip hostname
		nfsmout_if(error);

		/* create a temporary credential using the bits from the wire */
		bzero(&temp_pcred, sizeof(temp_pcred));
		nfsm_chain_get_32(error, nmreq, user_id);
		nfsm_chain_get_32(error, nmreq, group_id);
		temp_pcred.cr_groups[0] = group_id;
		nfsm_chain_get_32(error, nmreq, len);           // extra GID count
		if ((len < 0) || (len > RPCAUTH_UNIXGIDS)) {
			error = EBADRPC;
		}
		nfsmout_if(error);
		for (i = 1; i <= len; i++) {
			if (i < NGROUPS) {
				nfsm_chain_get_32(error, nmreq, temp_pcred.cr_groups[i]);
			} else {
				nfsm_chain_adv(error, nmreq, NFSX_UNSIGNED);
			}
		}
		nfsmout_if(error);
		ngroups = (len >= NGROUPS) ? NGROUPS : (short)(len + 1);
		if (ngroups > 1) {
			nfsrv_group_sort(&temp_pcred.cr_groups[0], ngroups);
		}
		nfsm_chain_adv(error, nmreq, NFSX_UNSIGNED);    // verifier flavor (should be AUTH_NONE)
		nfsm_chain_get_32(error, nmreq, len);           // verifier length
		if (len < 0 || len > RPCAUTH_MAXSIZ) {
			error = EBADRPC;
		}
		if (len > 0) {
			nfsm_chain_adv(error, nmreq, nfsm_rndup(len));
		}

		/* request creation of a real credential */
		temp_pcred.cr_uid = user_id;
		temp_pcred.cr_ngroups = ngroups;
		nd->nd_cr = posix_cred_create(&temp_pcred);
		if (nd->nd_cr == NULL) {
			nd->nd_repstat = ENOMEM;
			nd->nd_procnum = NFSPROC_NOOP;
			return 0;
		}
	} else if (auth_type == RPCSEC_GSS) {
		error = nfs_gss_svc_cred_get(nd, nmreq);
		if (error) {
			if (error == EINVAL) {
				goto nfsmout;   // drop the request
			}
			nd->nd_repstat = error;
			nd->nd_procnum = NFSPROC_NOOP;
			return 0;
		}
	} else {
		if (nd->nd_procnum == NFSPROC_NULL) {   // assume it's AUTH_NONE
			return 0;
		}
		nd->nd_repstat = (NFSERR_AUTHERR | AUTH_REJECTCRED);
		nd->nd_procnum = NFSPROC_NOOP;
		return 0;
	}
	return 0;
nfsmout:
	if (IS_VALID_CRED(nd->nd_cr)) {
		kauth_cred_unref(&nd->nd_cr);
	}
	nfsm_chain_cleanup(nmreq);
	return error;
}

/*
 * Search for a sleeping nfsd and wake it up.
 * SIDE EFFECT: If none found, make sure the socket is queued up so that one
 * of the running nfsds will go look for the work in the nfsrv_sockwait list.
 * Note: Must be called with nfsd_mutex held.
 */
void
nfsrv_wakenfsd(struct nfsrv_sock *slp)
{
	struct nfsd *nd;

	while (1) {
		if ((slp->ns_flag & SLP_VALID) == 0) {
			return;
		}
		if (lck_rw_try_lock_exclusive(&slp->ns_rwlock)) {
			/* Exclusive lock acquired */
			break;
		}
		IOSleep(NFS_TRYLOCK_MSEC_SLEEP);
	}

	/* if there's work to do on this socket, make sure it's queued up */
	if ((slp->ns_flag & SLP_WORKTODO) && !(slp->ns_flag & SLP_QUEUED)) {
		TAILQ_INSERT_TAIL(&nfsrv_sockwait, slp, ns_svcq);
		slp->ns_flag |= SLP_WAITQ;
	}
	lck_rw_done(&slp->ns_rwlock);

	/* wake up a waiting nfsd, if possible */
	nd = TAILQ_FIRST(&nfsd_queue);
	if (!nd) {
		return;
	}

	TAILQ_REMOVE(&nfsd_queue, nd, nfsd_queue);
	nd->nfsd_flag &= ~NFSD_WAITING;
	wakeup(nd);
}

#endif /* CONFIG_NFS_SERVER */
