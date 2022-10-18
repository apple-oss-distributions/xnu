/*
 * Copyright (c) 2007-2015 Apple Inc. All rights reserved.
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

#ifndef _NFS_NFS_GSS_H_
#define _NFS_NFS_GSS_H_

#include "gss/gss_krb5_mech.h"
#include <gssd/gssd_mach.h>
#include <sys/param.h>

#define RPCSEC_GSS                      6
#define RPCSEC_GSS_VERS_1               1

enum rpcsec_gss_proc {
	RPCSEC_GSS_DATA                 = 0,
	RPCSEC_GSS_INIT                 = 1,
	RPCSEC_GSS_CONTINUE_INIT        = 2,
	RPCSEC_GSS_DESTROY              = 3
};

enum rpcsec_gss_service {
	RPCSEC_GSS_SVC_NONE             = 1,    // sec=krb5
	RPCSEC_GSS_SVC_INTEGRITY        = 2,    // sec=krb5i
	RPCSEC_GSS_SVC_PRIVACY          = 3,    // sec=krb5p
};

/*
 * RFC 2203 and friends don't define maximums for token lengths
 * and context handles. We try to pick reasonable values here.
 *
 * N.B. Kerberos mech tokens can be quite large from the output
 * of a gss_init_sec_context if it includes a large PAC.
 */

#define GSS_MAX_TOKEN_LEN               64*1024

/*
 * Put a "reasonable" bound on MIC lengths
 */
#define GSS_MAX_MIC_LEN                 2048

#define GSS_MAXSEQ                      0x80000000      // The biggest sequence number
#define GSS_SVC_MAXCONTEXTS             500000          // Max contexts supported
#define GSS_SVC_SEQWINDOW               256             // Server's sequence window

#define MAX_SKEYLEN     32
#define MAX_LUCIDLEN    (sizeof (lucid_context) + MAX_SKEYLEN)

/*
 * The server's RPCSEC_GSS context information
 */
struct nfs_gss_svc_ctx {
	lck_mtx_t               gss_svc_mtx;
	LIST_ENTRY(nfs_gss_svc_ctx)     gss_svc_entries;
	uint32_t                gss_svc_handle;         // Identifies server context to client
	uint32_t                gss_svc_refcnt;         // Reference count
	uint32_t                gss_svc_proc;           // Current GSS proc from cred
	uid_t                   gss_svc_uid;            // UID of this user
	gid_t                   gss_svc_gids[NGROUPS];  // GIDs of this user
	uint32_t                gss_svc_ngroups;        // Count of gids
	uint64_t                gss_svc_incarnation;    // Delete ctx if we exceed this + ttl value
	uint32_t                gss_svc_seqmax;         // Current max GSS sequence number
	uint32_t                gss_svc_seqwin;         // GSS sequence number window
	uint32_t                *gss_svc_seqbits;       // Bitmap to track seq numbers
	gssd_cred               gss_svc_cred_handle;    // Opaque cred handle from gssd
	gssd_ctx                gss_svc_context;        // Opaque context handle from gssd
	gss_ctx_id_t            gss_svc_ctx_id;         // Underlying gss context
	u_char                  *gss_svc_token;         // GSS token exchanged via gssd & client
	uint32_t                gss_svc_tokenlen;       // Length of token
	uint32_t                gss_svc_major;          // GSS major result from gssd
	uint32_t                gss_svc_minor;          // GSS minor result from gssd
};

#define SVC_CTX_HASHSZ  64
#define SVC_CTX_HASH(handle)    ((handle) % SVC_CTX_HASHSZ)
LIST_HEAD(nfs_gss_svc_ctx_hashhead, nfs_gss_svc_ctx);

/*
 * Macros to manipulate bits in the sequence window
 */
#define win_getbit(bits, bit)      ((bits[(bit) / 32] &   (1 << (bit) % 32)) != 0)
#define win_setbit(bits, bit)   do { bits[(bit) / 32] |=  (1 << (bit) % 32); } while (0)
#define win_resetbit(bits, bit) do { bits[(bit) / 32] &= ~(1 << (bit) % 32); } while (0)

/*
 * Server context stale times
 */
#define GSS_CTX_PEND            5               // seconds
#define GSS_CTX_EXPIRE          (8 * 3600)      // seconds
#define GSS_CTX_TTL_MIN         1               // seconds
#define GSS_TIMER_PERIOD        300             // seconds
#define MSECS_PER_SEC           1000

__BEGIN_DECLS

void    nfs_gss_svc_init(void);
int     nfs_gss_svc_cred_get(struct nfsrv_descript *, struct nfsm_chain *);
int     nfs_gss_svc_verf_put(struct nfsrv_descript *, struct nfsm_chain *);
int     nfs_gss_svc_ctx_init(struct nfsrv_descript *, struct nfsrv_sock *, mbuf_t *);
int     nfs_gss_svc_prepare_reply(struct nfsrv_descript *, struct nfsm_chain *);
int     nfs_gss_svc_protect_reply(struct nfsrv_descript *, mbuf_t);
void    nfs_gss_svc_ctx_deref(struct nfs_gss_svc_ctx *);
void    nfs_gss_svc_cleanup(void);

__END_DECLS
#endif /* _NFS_NFS_GSS_H_ */
