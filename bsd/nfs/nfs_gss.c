/*
 * Copyright (c) 2007-2020 Apple Inc. All rights reserved.
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

#include <nfs/nfs_conf.h>
#if CONFIG_NFS_SERVER

/*************
 * These functions implement RPCSEC_GSS security for the NFS client and server.
 * The code is specific to the use of Kerberos v5 and the use of DES MAC MD5
 * protection as described in Internet RFC 2203 and 2623.
 *
 * In contrast to the original AUTH_SYS authentication, RPCSEC_GSS is stateful.
 * It requires the client and server negotiate a secure connection as part of a
 * security context. The context state is maintained in client and server structures.
 * On the client side, each user of an NFS mount is assigned their own context,
 * identified by UID, on their first use of the mount, and it persists until the
 * unmount or until the context is renewed.  Each user context has a corresponding
 * server context which the server maintains until the client destroys it, or
 * until the context expires.
 *
 * The client and server contexts are set up dynamically.  When a user attempts
 * to send an NFS request, if there is no context for the user, then one is
 * set up via an exchange of NFS null procedure calls as described in RFC 2203.
 * During this exchange, the client and server pass a security token that is
 * forwarded via Mach upcall to the gssd, which invokes the GSS-API to authenticate
 * the user to the server (and vice-versa). The client and server also receive
 * a unique session key that can be used to digitally sign the credentials and
 * verifier or optionally to provide data integrity and/or privacy.
 *
 * Once the context is complete, the client and server enter a normal data
 * exchange phase - beginning with the NFS request that prompted the context
 * creation. During this phase, the client's RPC header contains an RPCSEC_GSS
 * credential and verifier, and the server returns a verifier as well.
 * For simple authentication, the verifier contains a signed checksum of the
 * RPC header, including the credential.  The server's verifier has a signed
 * checksum of the current sequence number.
 *
 * Each client call contains a sequence number that nominally increases by one
 * on each request.  The sequence number is intended to prevent replay attacks.
 * Since the protocol can be used over UDP, there is some allowance for
 * out-of-sequence requests, so the server checks whether the sequence numbers
 * are within a sequence "window". If a sequence number is outside the lower
 * bound of the window, the server silently drops the request. This has some
 * implications for retransmission. If a request needs to be retransmitted, the
 * client must bump the sequence number even if the request XID is unchanged.
 *
 * When the NFS mount is unmounted, the client sends a "destroy" credential
 * to delete the server's context for each user of the mount. Since it's
 * possible for the client to crash or disconnect without sending the destroy
 * message, the server has a thread that reaps contexts that have been idle
 * too long.
 */

#include <sys/systm.h>
#include <sys/kauth.h>
#include <sys/mount_internal.h>
#include <sys/kpi_mbuf.h>

#include <kern/host.h>

#include <mach/host_priv.h>
#include <mach/vm_map.h>
#include <vm/vm_map.h>
#include <gssd/gssd_mach.h>

#include <nfs/rpcv2.h>
#include <nfs/nfsproto.h>
#include <nfs/nfs.h>
#include <nfs/nfs_gss.h>
#include <nfs/xdr_subs.h>
#include <nfs/nfsm_subs.h>
#include <nfs/nfs_gss.h>

#define NFS_GSS_MACH_MAX_RETRIES 3

#define NFSRV_GSS_DBG(...) NFSRV_DBG(NFSRV_FAC_GSS, 7, ## __VA_ARGS__)

u_long nfs_gss_svc_ctx_hash;
struct nfs_gss_svc_ctx_hashhead *nfs_gss_svc_ctx_hashtbl;
static LCK_GRP_DECLARE(nfs_gss_svc_grp, "rpcsec_gss_svc");
static LCK_MTX_DECLARE(nfs_gss_svc_ctx_mutex, &nfs_gss_svc_grp);
uint32_t nfsrv_gss_context_ttl = GSS_CTX_EXPIRE;
#define GSS_SVC_CTX_TTL ((uint64_t)max(2*GSS_CTX_PEND, nfsrv_gss_context_ttl) * NSEC_PER_SEC)

#define KRB5_MAX_MIC_SIZE 128
static uint8_t xdrpad[] = { 0x00, 0x00, 0x00, 0x00};

static struct nfs_gss_svc_ctx *nfs_gss_svc_ctx_find(uint32_t);
static void     nfs_gss_svc_ctx_insert(struct nfs_gss_svc_ctx *);
static void     nfs_gss_svc_ctx_timer(void *, void *);
static int      nfs_gss_svc_gssd_upcall(struct nfs_gss_svc_ctx *);
static int      nfs_gss_svc_seqnum_valid(struct nfs_gss_svc_ctx *, uint32_t);

/* This is only used by server code */
static void     nfs_gss_nfsm_chain(struct nfsm_chain *, mbuf_t);

static void     host_release_special_port(mach_port_t);
static void     nfs_gss_mach_alloc_buffer(u_char *, size_t, vm_map_copy_t *);
static int      nfs_gss_mach_vmcopyout(vm_map_copy_t, uint32_t, u_char *);

static int      nfs_gss_mchain_length(mbuf_t);
static int      nfs_gss_append_chain(struct nfsm_chain *, mbuf_t);
static int      nfs_gss_seqbits_size(uint32_t);

thread_call_t nfs_gss_svc_ctx_timer_call;
int nfs_gss_timer_on = 0;
uint32_t nfs_gss_ctx_count = 0;
const uint32_t nfs_gss_ctx_max = GSS_SVC_MAXCONTEXTS;

/*
 * Common RPCSEC_GSS support routines
 */

static errno_t
rpc_gss_prepend_32(mbuf_t *mb, uint32_t value)
{
	int error;
	uint32_t *data;

#if 0
	data = mbuf_data(*mb);
	/*
	 * If a wap token comes back and is not aligned
	 * get a new buffer (which should be aligned) to put the
	 * length in.
	 */
	if ((uintptr_t)data & 0x3) {
		mbuf_t nmb;

		error = mbuf_get(MBUF_WAITOK, MBUF_TYPE_DATA, &nmb);
		if (error) {
			return error;
		}
		mbuf_setnext(nmb, *mb);
		*mb = nmb;
	}
#endif
	error = mbuf_prepend(mb, sizeof(uint32_t), MBUF_WAITOK);
	if (error) {
		return error;
	}

	data = mbuf_data(*mb);
	*data = txdr_unsigned(value);

	return 0;
}

/*
 * Prepend the sequence number to the xdr encode argumen or result
 * Sequence number is prepended in its own mbuf.
 *
 * On successful return mbp_head will point to the old mbuf chain
 * prepended  with a new mbuf that has the sequence number.
 */

static errno_t
rpc_gss_data_create(mbuf_t *mbp_head, uint32_t seqnum)
{
	int error;
	mbuf_t mb;
	struct nfsm_chain nmc;
	struct nfsm_chain *nmcp = &nmc;
	uint8_t *data;

	error = mbuf_get(MBUF_WAITOK, MBUF_TYPE_DATA, &mb);
	if (error) {
		return error;
	}
	data = mbuf_data(mb);
#if 0
	/* Reserve space for prepending */
	len = mbuf_maxlen(mb);
	len = (len & ~0x3) - NFSX_UNSIGNED;
	printf("%s: data = %p, len = %d\n", __func__, data, (int)len);
	error = mbuf_setdata(mb, data + len, 0);
	if (error || mbuf_trailingspace(mb)) {
		printf("%s: data = %p trailingspace = %d error = %d\n", __func__, mbuf_data(mb), (int)mbuf_trailingspace(mb), error);
	}
#endif
	/* Reserve 16 words for prepending */
	error = mbuf_setdata(mb, data + 16 * sizeof(uint32_t), 0);
	nfsm_chain_init(nmcp, mb);
	nfsm_chain_add_32(error, nmcp, seqnum);
	nfsm_chain_build_done(error, nmcp);
	if (error) {
		return EINVAL;
	}
	mbuf_setnext(nmcp->nmc_mcur, *mbp_head);
	*mbp_head = nmcp->nmc_mhead;

	return 0;
}

/*
 * Create an rpc_gss_integ_data_t given an argument or result in mb_head.
 * On successful return mb_head will point to the rpc_gss_integ_data_t of length len.
 *      Note mb_head will now point to a 4 byte sequence number. len does not include
 *	any extra xdr padding.
 * Returns 0 on success, else an errno_t
 */

static errno_t
rpc_gss_integ_data_create(gss_ctx_id_t ctx, mbuf_t *mb_head, uint32_t seqnum, uint32_t *len)
{
	uint32_t error;
	uint32_t major;
	uint32_t length;
	gss_buffer_desc mic;
	struct nfsm_chain nmc = {};

	/* Length of the argument or result */
	length = nfs_gss_mchain_length(*mb_head);
	if (len) {
		*len = length;
	}
	error = rpc_gss_data_create(mb_head, seqnum);
	if (error) {
		return error;
	}

	/*
	 * length is the length of the rpc_gss_data
	 */
	length += NFSX_UNSIGNED;  /* Add the sequence number to the length */
	major = gss_krb5_get_mic_mbuf(&error, ctx, 0, *mb_head, 0, length, &mic);
	if (major != GSS_S_COMPLETE) {
		printf("gss_krb5_get_mic_mbuf failed %d\n", error);
		return error;
	}

	error = rpc_gss_prepend_32(mb_head, length);
	if (error) {
		return error;
	}

	nfsm_chain_dissect_init(error, &nmc, *mb_head);
	/* Append GSS mic token by advancing rpc_gss_data_t length + NFSX_UNSIGNED (size of the length field) */
	nfsm_chain_adv(error, &nmc, length + NFSX_UNSIGNED);
	nfsm_chain_finish_mbuf(error, &nmc); // Force the mic into its own sub chain.
	nfsm_chain_add_32(error, &nmc, mic.length);
	nfsm_chain_add_opaque(error, &nmc, mic.value, mic.length);
	nfsm_chain_build_done(error, &nmc);
	gss_release_buffer(NULL, &mic);

//	printmbuf("rpc_gss_integ_data_create done", *mb_head, 0, 0);
	assert(nmc.nmc_mhead == *mb_head);

	return error;
}

/*
 * Create an rpc_gss_priv_data_t out of the supplied raw arguments or results in mb_head.
 * On successful return mb_head will point to a wrap token of lenght len.
 *	Note len does not include any xdr padding
 * Returns 0 on success, else an errno_t
 */
static errno_t
rpc_gss_priv_data_create(gss_ctx_id_t ctx, mbuf_t *mb_head, uint32_t seqnum, uint32_t *len)
{
	uint32_t error;
	uint32_t major;
	struct nfsm_chain nmc;
	uint32_t pad;
	uint32_t length;

	error = rpc_gss_data_create(mb_head, seqnum);
	if (error) {
		return error;
	}

	length = nfs_gss_mchain_length(*mb_head);
	major = gss_krb5_wrap_mbuf(&error, ctx, 1, 0, mb_head, 0, length, NULL);
	if (major != GSS_S_COMPLETE) {
		return error;
	}

	length = nfs_gss_mchain_length(*mb_head);
	if (len) {
		*len = length;
	}
	pad = nfsm_pad(length);

	/* Prepend the opaque length of rep rpc_gss_priv_data */
	error = rpc_gss_prepend_32(mb_head, length);

	if (error) {
		return error;
	}
	if (pad) {
		nfsm_chain_dissect_init(error, &nmc, *mb_head);
		/* Advance the opauque size of length and length data */
		nfsm_chain_adv(error, &nmc, NFSX_UNSIGNED + length);
		nfsm_chain_finish_mbuf(error, &nmc);
		nfsm_chain_add_opaque_nopad(error, &nmc, xdrpad, pad);
		nfsm_chain_build_done(error, &nmc);
	}

	return error;
}

/*************
 *
 * Server functions
 */

/*
 * Initialization when NFS starts
 */
void
nfs_gss_svc_init(void)
{
	nfs_gss_svc_ctx_hashtbl = hashinit(SVC_CTX_HASHSZ, M_TEMP, &nfs_gss_svc_ctx_hash);

	nfs_gss_svc_ctx_timer_call = thread_call_allocate(nfs_gss_svc_ctx_timer, NULL);
}

/*
 * Find a server context based on a handle value received
 * in an RPCSEC_GSS credential.
 */
static struct nfs_gss_svc_ctx *
nfs_gss_svc_ctx_find(uint32_t handle)
{
	struct nfs_gss_svc_ctx_hashhead *head;
	struct nfs_gss_svc_ctx *cp;
	uint64_t timenow;

	if (handle == 0) {
		return NULL;
	}

	head = &nfs_gss_svc_ctx_hashtbl[SVC_CTX_HASH(handle)];
	/*
	 * Don't return a context that is going to expire in GSS_CTX_PEND seconds
	 */
	clock_interval_to_deadline(GSS_CTX_PEND, NSEC_PER_SEC, &timenow);

	lck_mtx_lock(&nfs_gss_svc_ctx_mutex);

	LIST_FOREACH(cp, head, gss_svc_entries) {
		if (cp->gss_svc_handle == handle) {
			if (timenow > cp->gss_svc_incarnation + GSS_SVC_CTX_TTL) {
				/*
				 * Context has or is about to expire. Don't use.
				 * We'll return null and the client will have to create
				 * a new context.
				 */
				cp->gss_svc_handle = 0;
				/*
				 * Make sure though that we stay around for GSS_CTX_PEND seconds
				 * for other threads that might be using the context.
				 */
				cp->gss_svc_incarnation = timenow;

				cp = NULL;
				break;
			}
			lck_mtx_lock(&cp->gss_svc_mtx);
			cp->gss_svc_refcnt++;
			lck_mtx_unlock(&cp->gss_svc_mtx);
			break;
		}
	}

	lck_mtx_unlock(&nfs_gss_svc_ctx_mutex);

	return cp;
}

/*
 * Insert a new server context into the hash table
 * and start the context reap thread if necessary.
 */
static void
nfs_gss_svc_ctx_insert(struct nfs_gss_svc_ctx *cp)
{
	struct nfs_gss_svc_ctx_hashhead *head;
	struct nfs_gss_svc_ctx *p;

	lck_mtx_lock(&nfs_gss_svc_ctx_mutex);

	/*
	 * Give the client a random handle so that if we reboot
	 * it's unlikely the client will get a bad context match.
	 * Make sure it's not zero or already assigned.
	 */
retry:
	cp->gss_svc_handle = random();
	if (cp->gss_svc_handle == 0) {
		goto retry;
	}
	head = &nfs_gss_svc_ctx_hashtbl[SVC_CTX_HASH(cp->gss_svc_handle)];
	LIST_FOREACH(p, head, gss_svc_entries)
	if (p->gss_svc_handle == cp->gss_svc_handle) {
		goto retry;
	}

	clock_interval_to_deadline(GSS_CTX_PEND, NSEC_PER_SEC,
	    &cp->gss_svc_incarnation);
	LIST_INSERT_HEAD(head, cp, gss_svc_entries);
	nfs_gss_ctx_count++;

	if (!nfs_gss_timer_on) {
		nfs_gss_timer_on = 1;

		nfs_interval_timer_start(nfs_gss_svc_ctx_timer_call,
		    min(GSS_TIMER_PERIOD, max(GSS_CTX_TTL_MIN, nfsrv_gss_context_ttl)) * MSECS_PER_SEC);
	}

	lck_mtx_unlock(&nfs_gss_svc_ctx_mutex);
}

/*
 * This function is called via the kernel's callout
 * mechanism.  It runs only when there are
 * cached RPCSEC_GSS contexts.
 */
void
nfs_gss_svc_ctx_timer(__unused void *param1, __unused void *param2)
{
	struct nfs_gss_svc_ctx *cp, *next;
	uint64_t timenow;
	int contexts = 0;
	int i;

	lck_mtx_lock(&nfs_gss_svc_ctx_mutex);
	clock_get_uptime(&timenow);

	NFSRV_GSS_DBG("is running\n");

	/*
	 * Scan all the hash chains
	 */
	for (i = 0; i < SVC_CTX_HASHSZ; i++) {
		/*
		 * For each hash chain, look for entries
		 * that haven't been used in a while.
		 */
		LIST_FOREACH_SAFE(cp, &nfs_gss_svc_ctx_hashtbl[i], gss_svc_entries, next) {
			contexts++;
			if (timenow > cp->gss_svc_incarnation +
			    (cp->gss_svc_handle ? GSS_SVC_CTX_TTL : 0)
			    && cp->gss_svc_refcnt == 0) {
				/*
				 * A stale context - remove it
				 */
				LIST_REMOVE(cp, gss_svc_entries);
				NFSRV_GSS_DBG("Removing contex for %d\n", cp->gss_svc_uid);
				if (cp->gss_svc_seqbits) {
					kfree_data(cp->gss_svc_seqbits, nfs_gss_seqbits_size(cp->gss_svc_seqwin));
				}
				lck_mtx_destroy(&cp->gss_svc_mtx, &nfs_gss_svc_grp);
				kfree_type(struct nfs_gss_svc_ctx, cp);
				contexts--;
			}
		}
	}

	nfs_gss_ctx_count = contexts;

	/*
	 * If there are still some cached contexts left,
	 * set up another callout to check on them later.
	 */
	nfs_gss_timer_on = nfs_gss_ctx_count > 0;
	if (nfs_gss_timer_on) {
		nfs_interval_timer_start(nfs_gss_svc_ctx_timer_call,
		    min(GSS_TIMER_PERIOD, max(GSS_CTX_TTL_MIN, nfsrv_gss_context_ttl)) * MSECS_PER_SEC);
	}

	lck_mtx_unlock(&nfs_gss_svc_ctx_mutex);
}

/*
 * Here the server receives an RPCSEC_GSS credential in an
 * RPC call header.  First there's some checking to make sure
 * the credential is appropriate - whether the context is still
 * being set up, or is complete.  Then we use the handle to find
 * the server's context and validate the verifier, which contains
 * a signed checksum of the RPC header. If the verifier checks
 * out, we extract the user's UID and groups from the context
 * and use it to set up a UNIX credential for the user's request.
 */
int
nfs_gss_svc_cred_get(struct nfsrv_descript *nd, struct nfsm_chain *nmc)
{
	uint32_t vers, proc, seqnum, service;
	uint32_t handle, handle_len;
	uint32_t major;
	struct nfs_gss_svc_ctx *cp = NULL;
	uint32_t flavor = 0;
	int error = 0;
	uint32_t arglen;
	size_t argsize, start, header_len;
	gss_buffer_desc cksum;
	struct nfsm_chain nmc_tmp;
	mbuf_t reply_mbuf, prev_mbuf, pad_mbuf;

	vers = proc = seqnum = service = handle_len = 0;
	arglen = 0;

	nfsm_chain_get_32(error, nmc, vers);
	if (vers != RPCSEC_GSS_VERS_1) {
		error = NFSERR_AUTHERR | AUTH_REJECTCRED;
		goto nfsmout;
	}

	nfsm_chain_get_32(error, nmc, proc);
	nfsm_chain_get_32(error, nmc, seqnum);
	nfsm_chain_get_32(error, nmc, service);
	nfsm_chain_get_32(error, nmc, handle_len);
	if (error) {
		goto nfsmout;
	}

	/*
	 * Make sure context setup/destroy is being done with a nullproc
	 */
	if (proc != RPCSEC_GSS_DATA && nd->nd_procnum != NFSPROC_NULL) {
		error = NFSERR_AUTHERR | RPCSEC_GSS_CREDPROBLEM;
		goto nfsmout;
	}

	/*
	 * If the sequence number is greater than the max
	 * allowable, reject and have the client init a
	 * new context.
	 */
	if (seqnum > GSS_MAXSEQ) {
		error = NFSERR_AUTHERR | RPCSEC_GSS_CTXPROBLEM;
		goto nfsmout;
	}

	nd->nd_sec =
	    service == RPCSEC_GSS_SVC_NONE ?      RPCAUTH_KRB5 :
	    service == RPCSEC_GSS_SVC_INTEGRITY ? RPCAUTH_KRB5I :
	    service == RPCSEC_GSS_SVC_PRIVACY ?   RPCAUTH_KRB5P : 0;

	if (proc == RPCSEC_GSS_INIT) {
		/*
		 * Limit the total number of contexts
		 */
		if (nfs_gss_ctx_count > nfs_gss_ctx_max) {
			error = NFSERR_AUTHERR | RPCSEC_GSS_CTXPROBLEM;
			goto nfsmout;
		}

		/*
		 * Set up a new context
		 */
		cp = kalloc_type(struct nfs_gss_svc_ctx,
		    Z_WAITOK | Z_ZERO | Z_NOFAIL);
		lck_mtx_init(&cp->gss_svc_mtx, &nfs_gss_svc_grp, LCK_ATTR_NULL);
		cp->gss_svc_refcnt = 1;
	} else {
		/*
		 * Use the handle to find the context
		 */
		if (handle_len != sizeof(handle)) {
			error = NFSERR_AUTHERR | RPCSEC_GSS_CREDPROBLEM;
			goto nfsmout;
		}
		nfsm_chain_get_32(error, nmc, handle);
		if (error) {
			goto nfsmout;
		}
		cp = nfs_gss_svc_ctx_find(handle);
		if (cp == NULL) {
			error = NFSERR_AUTHERR | RPCSEC_GSS_CTXPROBLEM;
			goto nfsmout;
		}
	}

	cp->gss_svc_proc = proc;

	if (proc == RPCSEC_GSS_DATA || proc == RPCSEC_GSS_DESTROY) {
		struct posix_cred temp_pcred;

		if (cp->gss_svc_seqwin == 0) {
			/*
			 * Context isn't complete
			 */
			error = NFSERR_AUTHERR | RPCSEC_GSS_CTXPROBLEM;
			goto nfsmout;
		}

		if (!nfs_gss_svc_seqnum_valid(cp, seqnum)) {
			/*
			 * Sequence number is bad
			 */
			error = EINVAL; // drop the request
			goto nfsmout;
		}

		/*
		 * Validate the verifier.
		 * The verifier contains an encrypted checksum
		 * of the call header from the XID up to and
		 * including the credential.  We compute the
		 * checksum and compare it with what came in
		 * the verifier.
		 */
		header_len = nfsm_chain_offset(nmc);
		nfsm_chain_get_32(error, nmc, flavor);
		nfsm_chain_get_32(error, nmc, cksum.length);
		if (error) {
			goto nfsmout;
		}
		if (flavor != RPCSEC_GSS || cksum.length > KRB5_MAX_MIC_SIZE) {
			error = NFSERR_AUTHERR | AUTH_BADVERF;
		} else {
			cksum.value = kalloc_data(cksum.length, Z_WAITOK | Z_NOFAIL);
			nfsm_chain_get_opaque(error, nmc, cksum.length, cksum.value);
		}
		if (error) {
			goto nfsmout;
		}

		/* Now verify the client's call header checksum */
		major = gss_krb5_verify_mic_mbuf((uint32_t *)&error, cp->gss_svc_ctx_id, nmc->nmc_mhead, 0, header_len, &cksum, NULL);
		(void)gss_release_buffer(NULL, &cksum);
		if (major != GSS_S_COMPLETE) {
			printf("Server header: gss_krb5_verify_mic_mbuf failed %d\n", error);
			error = NFSERR_AUTHERR | RPCSEC_GSS_CTXPROBLEM;
			goto nfsmout;
		}

		nd->nd_gss_seqnum = seqnum;

		/*
		 * Set up the user's cred
		 */
		bzero(&temp_pcred, sizeof(temp_pcred));
		temp_pcred.cr_uid = cp->gss_svc_uid;
		bcopy(cp->gss_svc_gids, temp_pcred.cr_groups,
		    sizeof(gid_t) * cp->gss_svc_ngroups);
		temp_pcred.cr_ngroups = (short)cp->gss_svc_ngroups;

		nd->nd_cr = posix_cred_create(&temp_pcred);
		if (nd->nd_cr == NULL) {
			error = ENOMEM;
			goto nfsmout;
		}
		clock_get_uptime(&cp->gss_svc_incarnation);

		/*
		 * If the call arguments are integrity or privacy protected
		 * then we need to check them here.
		 */
		switch (service) {
		case RPCSEC_GSS_SVC_NONE:
			/* nothing to do */
			break;
		case RPCSEC_GSS_SVC_INTEGRITY:
			/*
			 * Here's what we expect in the integrity call args:
			 *
			 * - length of seq num + call args (4 bytes)
			 * - sequence number (4 bytes)
			 * - call args (variable bytes)
			 * - length of checksum token
			 * - checksum of seqnum + call args
			 */
			nfsm_chain_get_32(error, nmc, arglen);          // length of args
			if (arglen > NFS_MAXPACKET) {
				error = EBADRPC;
				goto nfsmout;
			}

			nmc_tmp = *nmc;
			nfsm_chain_adv(error, &nmc_tmp, arglen);
			nfsm_chain_get_32(error, &nmc_tmp, cksum.length);
			cksum.value = NULL;
			if (cksum.length > 0 && cksum.length < GSS_MAX_MIC_LEN) {
				cksum.value = kalloc_data(cksum.length, Z_WAITOK | Z_NOFAIL);
			} else {
				error = EBADRPC;
				goto nfsmout;
			}
			nfsm_chain_get_opaque(error, &nmc_tmp, cksum.length, cksum.value);

			/* Verify the checksum over the call args */
			start = nfsm_chain_offset(nmc);

			major = gss_krb5_verify_mic_mbuf((uint32_t *)&error, cp->gss_svc_ctx_id,
			    nmc->nmc_mhead, start, arglen, &cksum, NULL);
			kfree_data(cksum.value, cksum.length);
			if (major != GSS_S_COMPLETE) {
				printf("Server args: gss_krb5_verify_mic_mbuf failed %d\n", error);
				error = EBADRPC;
				goto nfsmout;
			}

			/*
			 * Get the sequence number prepended to the args
			 * and compare it against the one sent in the
			 * call credential.
			 */
			nfsm_chain_get_32(error, nmc, seqnum);
			if (seqnum != nd->nd_gss_seqnum) {
				error = EBADRPC;                        // returns as GARBAGEARGS
				goto nfsmout;
			}
			break;
		case RPCSEC_GSS_SVC_PRIVACY:
			/*
			 * Here's what we expect in the privacy call args:
			 *
			 * - length of wrap token
			 * - wrap token (37-40 bytes)
			 */
			prev_mbuf = nmc->nmc_mcur;
			nfsm_chain_get_32(error, nmc, arglen);          // length of args
			if (arglen > NFS_MAXPACKET) {
				error = EBADRPC;
				goto nfsmout;
			}

			/* Get the wrap token (current mbuf in the chain starting at the current offset) */
			start = nmc->nmc_ptr - (caddr_t)mbuf_data(nmc->nmc_mcur);

			/* split out the wrap token */
			argsize = arglen;
			error = gss_normalize_mbuf(nmc->nmc_mcur, start, &argsize, &reply_mbuf, &pad_mbuf, 0);
			if (error) {
				goto nfsmout;
			}

			assert(argsize == arglen);
			if (pad_mbuf) {
				assert(nfsm_pad(arglen) == mbuf_len(pad_mbuf));
				mbuf_free(pad_mbuf);
			} else {
				assert(nfsm_pad(arglen) == 0);
			}

			major = gss_krb5_unwrap_mbuf((uint32_t *)&error, cp->gss_svc_ctx_id, &reply_mbuf, 0, arglen, NULL, NULL);
			if (major != GSS_S_COMPLETE) {
				printf("%s: gss_krb5_unwrap_mbuf failes %d\n", __func__, error);
				goto nfsmout;
			}

			/* Now replace the wrapped arguments with the unwrapped ones */
			mbuf_setnext(prev_mbuf, reply_mbuf);
			nmc->nmc_mcur = reply_mbuf;
			nmc->nmc_ptr = mbuf_data(reply_mbuf);
			nmc->nmc_left = mbuf_len(reply_mbuf);

			/*
			 * - sequence number (4 bytes)
			 * - call args
			 */

			// nfsm_chain_reverse(nmc, nfsm_pad(toklen));

			/*
			 * Get the sequence number prepended to the args
			 * and compare it against the one sent in the
			 * call credential.
			 */
			nfsm_chain_get_32(error, nmc, seqnum);
			if (seqnum != nd->nd_gss_seqnum) {
				printf("%s: Sequence number mismatch seqnum = %d nd->nd_gss_seqnum = %d\n",
				    __func__, seqnum, nd->nd_gss_seqnum);
				printmbuf("reply_mbuf", nmc->nmc_mhead, 0, 0);
				printf("reply_mbuf %p nmc_head %p\n", reply_mbuf, nmc->nmc_mhead);
				error = EBADRPC;                        // returns as GARBAGEARGS
				goto nfsmout;
			}
			break;
		}
	} else {
		uint32_t verflen;
		/*
		 * If the proc is RPCSEC_GSS_INIT or RPCSEC_GSS_CONTINUE_INIT
		 * then we expect a null verifier.
		 */
		nfsm_chain_get_32(error, nmc, flavor);
		nfsm_chain_get_32(error, nmc, verflen);
		if (error || flavor != RPCAUTH_NULL || verflen > 0) {
			error = NFSERR_AUTHERR | RPCSEC_GSS_CREDPROBLEM;
		}
		if (error) {
			if (proc == RPCSEC_GSS_INIT) {
				lck_mtx_destroy(&cp->gss_svc_mtx, &nfs_gss_svc_grp);
				kfree_type(struct nfs_gss_svc_ctx, cp);
				cp = NULL;
			}
			goto nfsmout;
		}
	}

	nd->nd_gss_context = cp;
	return 0;
nfsmout:
	if (cp) {
		nfs_gss_svc_ctx_deref(cp);
	}
	return error;
}

/*
 * Insert the server's verifier into the RPC reply header.
 * It contains a signed checksum of the sequence number that
 * was received in the RPC call.
 * Then go on to add integrity or privacy if necessary.
 */
int
nfs_gss_svc_verf_put(struct nfsrv_descript *nd, struct nfsm_chain *nmc)
{
	struct nfs_gss_svc_ctx *cp;
	int error = 0;
	gss_buffer_desc cksum, seqbuf;
	uint32_t network_seqnum;
	cp = nd->nd_gss_context;
	uint32_t major;

	if (cp->gss_svc_major != GSS_S_COMPLETE) {
		/*
		 * If the context isn't yet complete
		 * then return a null verifier.
		 */
		nfsm_chain_add_32(error, nmc, RPCAUTH_NULL);
		nfsm_chain_add_32(error, nmc, 0);
		return error;
	}

	/*
	 * Compute checksum of the request seq number
	 * If it's the final reply of context setup
	 * then return the checksum of the context
	 * window size.
	 */
	seqbuf.length = NFSX_UNSIGNED;
	if (cp->gss_svc_proc == RPCSEC_GSS_INIT ||
	    cp->gss_svc_proc == RPCSEC_GSS_CONTINUE_INIT) {
		network_seqnum = htonl(cp->gss_svc_seqwin);
	} else {
		network_seqnum = htonl(nd->nd_gss_seqnum);
	}
	seqbuf.value = &network_seqnum;

	major = gss_krb5_get_mic((uint32_t *)&error, cp->gss_svc_ctx_id, 0, &seqbuf, &cksum);
	if (major != GSS_S_COMPLETE) {
		return error;
	}

	/*
	 * Now wrap it in a token and add
	 * the verifier to the reply.
	 */
	nfsm_chain_add_32(error, nmc, RPCSEC_GSS);
	nfsm_chain_add_32(error, nmc, cksum.length);
	nfsm_chain_add_opaque(error, nmc, cksum.value, cksum.length);
	gss_release_buffer(NULL, &cksum);

	return error;
}

/*
 * The results aren't available yet, but if they need to be
 * checksummed for integrity protection or encrypted, then
 * we can record the start offset here, insert a place-holder
 * for the results length, as well as the sequence number.
 * The rest of the work is done later by nfs_gss_svc_protect_reply()
 * when the results are available.
 */
int
nfs_gss_svc_prepare_reply(struct nfsrv_descript *nd, struct nfsm_chain *nmc)
{
	struct nfs_gss_svc_ctx *cp = nd->nd_gss_context;
	int error = 0;

	if (cp->gss_svc_proc == RPCSEC_GSS_INIT ||
	    cp->gss_svc_proc == RPCSEC_GSS_CONTINUE_INIT) {
		return 0;
	}

	switch (nd->nd_sec) {
	case RPCAUTH_KRB5:
		/* Nothing to do */
		break;
	case RPCAUTH_KRB5I:
	case RPCAUTH_KRB5P:
		nd->nd_gss_mb = nmc->nmc_mcur;                  // record current mbuf
		nfsm_chain_finish_mbuf(error, nmc);             // split the chain here
		break;
	}

	return error;
}

/*
 * The results are checksummed or encrypted for return to the client
 */
int
nfs_gss_svc_protect_reply(struct nfsrv_descript *nd, mbuf_t mrep __unused)
{
	struct nfs_gss_svc_ctx *cp = nd->nd_gss_context;
	struct nfsm_chain nmrep_res, *nmc_res = &nmrep_res;
	mbuf_t mb, results;
	uint32_t reslen;
	int error = 0;

	/* XXX
	 * Using a reference to the mbuf where we previously split the reply
	 * mbuf chain, we split the mbuf chain argument into two mbuf chains,
	 * one that allows us to prepend a length field or token, (nmc_pre)
	 * and the second which holds just the results that we're going to
	 * checksum and/or encrypt.  When we're done, we join the chains back
	 * together.
	 */

	mb = nd->nd_gss_mb;                             // the mbuf where we split
	results = mbuf_next(mb);                        // first mbuf in the results
	error = mbuf_setnext(mb, NULL);                 // disconnect the chains
	if (error) {
		return error;
	}
	nfs_gss_nfsm_chain(nmc_res, mb);                // set up the prepend chain
	nfsm_chain_build_done(error, nmc_res);
	if (error) {
		return error;
	}

	if (nd->nd_sec == RPCAUTH_KRB5I) {
		error = rpc_gss_integ_data_create(cp->gss_svc_ctx_id, &results, nd->nd_gss_seqnum, &reslen);
	} else {
		/* RPCAUTH_KRB5P */
		error = rpc_gss_priv_data_create(cp->gss_svc_ctx_id, &results, nd->nd_gss_seqnum, &reslen);
	}
	nfs_gss_append_chain(nmc_res, results); // Append the results mbufs
	nfsm_chain_build_done(error, nmc_res);

	return error;
}

/*
 * This function handles the context setup calls from the client.
 * Essentially, it implements the NFS null procedure calls when
 * an RPCSEC_GSS credential is used.
 * This is the context maintenance function.  It creates and
 * destroys server contexts at the whim of the client.
 * During context creation, it receives GSS-API tokens from the
 * client, passes them up to gssd, and returns a received token
 * back to the client in the null procedure reply.
 */
int
nfs_gss_svc_ctx_init(struct nfsrv_descript *nd, struct nfsrv_sock *slp, mbuf_t *mrepp)
{
	struct nfs_gss_svc_ctx *cp = NULL;
	int error = 0;
	int autherr = 0;
	struct nfsm_chain *nmreq, nmrep;
	int sz;

	nmreq = &nd->nd_nmreq;
	nfsm_chain_null(&nmrep);
	*mrepp = NULL;
	cp = nd->nd_gss_context;
	nd->nd_repstat = 0;

	switch (cp->gss_svc_proc) {
	case RPCSEC_GSS_INIT:
		nfs_gss_svc_ctx_insert(cp);
		OS_FALLTHROUGH;

	case RPCSEC_GSS_CONTINUE_INIT:
		/* Get the token from the request */
		nfsm_chain_get_32(error, nmreq, cp->gss_svc_tokenlen);
		cp->gss_svc_token = NULL;
		if (cp->gss_svc_tokenlen > 0 && cp->gss_svc_tokenlen < GSS_MAX_TOKEN_LEN) {
			cp->gss_svc_token = kalloc_data(cp->gss_svc_tokenlen, Z_WAITOK);
		}
		if (cp->gss_svc_token == NULL) {
			autherr = RPCSEC_GSS_CREDPROBLEM;
			break;
		}
		nfsm_chain_get_opaque(error, nmreq, cp->gss_svc_tokenlen, cp->gss_svc_token);

		/* Use the token in a gss_accept_sec_context upcall */
		error = nfs_gss_svc_gssd_upcall(cp);
		if (error) {
			autherr = RPCSEC_GSS_CREDPROBLEM;
			if (error == NFSERR_EAUTH) {
				error = 0;
			}
			break;
		}

		/*
		 * If the context isn't complete, pass the new token
		 * back to the client for another round.
		 */
		if (cp->gss_svc_major != GSS_S_COMPLETE) {
			break;
		}

		/*
		 * Now the server context is complete.
		 * Finish setup.
		 */
		clock_get_uptime(&cp->gss_svc_incarnation);

		cp->gss_svc_seqwin = GSS_SVC_SEQWINDOW;
		cp->gss_svc_seqbits = kalloc_data(nfs_gss_seqbits_size(cp->gss_svc_seqwin), Z_WAITOK | Z_ZERO);
		if (cp->gss_svc_seqbits == NULL) {
			autherr = RPCSEC_GSS_CREDPROBLEM;
			break;
		}
		break;

	case RPCSEC_GSS_DATA:
		/* Just a nullproc ping - do nothing */
		break;

	case RPCSEC_GSS_DESTROY:
		/*
		 * Don't destroy the context immediately because
		 * other active requests might still be using it.
		 * Instead, schedule it for destruction after
		 * GSS_CTX_PEND time has elapsed.
		 */
		cp = nfs_gss_svc_ctx_find(cp->gss_svc_handle);
		if (cp != NULL) {
			cp->gss_svc_handle = 0; // so it can't be found
			lck_mtx_lock(&cp->gss_svc_mtx);
			clock_interval_to_deadline(GSS_CTX_PEND, NSEC_PER_SEC,
			    &cp->gss_svc_incarnation);
			lck_mtx_unlock(&cp->gss_svc_mtx);
		}
		break;
	default:
		autherr = RPCSEC_GSS_CREDPROBLEM;
		break;
	}

	/* Now build the reply  */

	if (nd->nd_repstat == 0) {
		nd->nd_repstat = autherr ? (NFSERR_AUTHERR | autherr) : NFSERR_RETVOID;
	}
	sz = 7 * NFSX_UNSIGNED + nfsm_rndup(cp->gss_svc_tokenlen); // size of results
	error = nfsrv_rephead(nd, slp, &nmrep, sz);
	*mrepp = nmrep.nmc_mhead;
	if (error || autherr) {
		goto nfsmout;
	}

	if (cp->gss_svc_proc == RPCSEC_GSS_INIT ||
	    cp->gss_svc_proc == RPCSEC_GSS_CONTINUE_INIT) {
		nfsm_chain_add_32(error, &nmrep, sizeof(cp->gss_svc_handle));
		nfsm_chain_add_32(error, &nmrep, cp->gss_svc_handle);

		nfsm_chain_add_32(error, &nmrep, cp->gss_svc_major);
		nfsm_chain_add_32(error, &nmrep, cp->gss_svc_minor);
		nfsm_chain_add_32(error, &nmrep, cp->gss_svc_seqwin);

		nfsm_chain_add_32(error, &nmrep, cp->gss_svc_tokenlen);
		if (cp->gss_svc_token != NULL) {
			nfsm_chain_add_opaque(error, &nmrep, cp->gss_svc_token, cp->gss_svc_tokenlen);
			kfree_data_addr(cp->gss_svc_token);
		}
	}

nfsmout:
	if (autherr != 0) {
		nd->nd_gss_context = NULL;
		LIST_REMOVE(cp, gss_svc_entries);
		if (cp->gss_svc_seqbits != NULL) {
			kfree_data(cp->gss_svc_seqbits, nfs_gss_seqbits_size(cp->gss_svc_seqwin));
		}
		if (cp->gss_svc_token != NULL) {
			kfree_data_addr(cp->gss_svc_token);
		}
		lck_mtx_destroy(&cp->gss_svc_mtx, &nfs_gss_svc_grp);
		kfree_type(struct nfs_gss_svc_ctx, cp);
	}

	nfsm_chain_build_done(error, &nmrep);
	if (error) {
		nfsm_chain_cleanup(&nmrep);
		*mrepp = NULL;
	}
	return error;
}

/*
 * This is almost a mirror-image of the client side upcall.
 * It passes and receives a token, but invokes gss_accept_sec_context.
 * If it's the final call of the context setup, then gssd also returns
 * the session key and the user's UID.
 */
static int
nfs_gss_svc_gssd_upcall(struct nfs_gss_svc_ctx *cp)
{
	kern_return_t kr;
	mach_port_t mp;
	int retry_cnt = 0;
	gssd_byte_buffer octx = NULL;
	uint32_t lucidlen = 0;
	void *lucid_ctx_buffer;
	uint32_t ret_flags;
	vm_map_copy_t itoken = NULL;
	gssd_byte_buffer otoken = NULL;
	mach_msg_type_number_t otokenlen;
	int error = 0;
	char svcname[] = "nfs";

	kr = host_get_gssd_port(host_priv_self(), &mp);
	if (kr != KERN_SUCCESS) {
		printf("nfs_gss_svc_gssd_upcall: can't get gssd port, status %x (%d)\n", kr, kr);
		goto out;
	}
	if (!IPC_PORT_VALID(mp)) {
		printf("nfs_gss_svc_gssd_upcall: gssd port not valid\n");
		goto out;
	}

	if (cp->gss_svc_tokenlen > 0) {
		nfs_gss_mach_alloc_buffer(cp->gss_svc_token, cp->gss_svc_tokenlen, &itoken);
	}

retry:
	printf("Calling mach_gss_accept_sec_context\n");
	kr = mach_gss_accept_sec_context(
		mp,
		(gssd_byte_buffer) itoken, (mach_msg_type_number_t) cp->gss_svc_tokenlen,
		svcname,
		0,
		&cp->gss_svc_context,
		&cp->gss_svc_cred_handle,
		&ret_flags,
		&cp->gss_svc_uid,
		cp->gss_svc_gids,
		&cp->gss_svc_ngroups,
		&octx, (mach_msg_type_number_t *) &lucidlen,
		&otoken, &otokenlen,
		&cp->gss_svc_major,
		&cp->gss_svc_minor);

	printf("mach_gss_accept_sec_context returned %d\n", kr);
	if (kr != KERN_SUCCESS) {
		printf("nfs_gss_svc_gssd_upcall failed: %x (%d)\n", kr, kr);
		if (kr == MIG_SERVER_DIED && cp->gss_svc_context == 0 &&
		    retry_cnt++ < NFS_GSS_MACH_MAX_RETRIES) {
			if (cp->gss_svc_tokenlen > 0) {
				nfs_gss_mach_alloc_buffer(cp->gss_svc_token, cp->gss_svc_tokenlen, &itoken);
			}
			goto retry;
		}
		host_release_special_port(mp);
		goto out;
	}

	host_release_special_port(mp);

	if (lucidlen > 0) {
		if (lucidlen > MAX_LUCIDLEN) {
			printf("nfs_gss_svc_gssd_upcall: bad context length (%d)\n", lucidlen);
			vm_map_copy_discard((vm_map_copy_t) octx);
			vm_map_copy_discard((vm_map_copy_t) otoken);
			goto out;
		}
		lucid_ctx_buffer = kalloc_data(lucidlen, Z_WAITOK | Z_ZERO);
		error = nfs_gss_mach_vmcopyout((vm_map_copy_t) octx, lucidlen, lucid_ctx_buffer);
		if (error) {
			vm_map_copy_discard((vm_map_copy_t) octx);
			vm_map_copy_discard((vm_map_copy_t) otoken);
			kfree_data(lucid_ctx_buffer, lucidlen);
			goto out;
		}
		if (cp->gss_svc_ctx_id) {
			gss_krb5_destroy_context(cp->gss_svc_ctx_id);
		}
		cp->gss_svc_ctx_id = gss_krb5_make_context(lucid_ctx_buffer, lucidlen);
		kfree_data(lucid_ctx_buffer, lucidlen);
		if (cp->gss_svc_ctx_id == NULL) {
			printf("Failed to make context from lucid_ctx_buffer\n");
			goto out;
		}
	}

	/* Free context token used as input */
	if (cp->gss_svc_token) {
		kfree_data(cp->gss_svc_token, cp->gss_svc_tokenlen);
	}
	cp->gss_svc_token = NULL;
	cp->gss_svc_tokenlen = 0;

	if (otokenlen > 0) {
		/* Set context token to gss output token */
		cp->gss_svc_token = kalloc_data(otokenlen, Z_WAITOK);
		if (cp->gss_svc_token == NULL) {
			printf("nfs_gss_svc_gssd_upcall: could not allocate %d bytes\n", otokenlen);
			vm_map_copy_discard((vm_map_copy_t) otoken);
			return ENOMEM;
		}
		error = nfs_gss_mach_vmcopyout((vm_map_copy_t) otoken, otokenlen, cp->gss_svc_token);
		if (error) {
			vm_map_copy_discard((vm_map_copy_t) otoken);
			kfree_data(cp->gss_svc_token, otokenlen);
			return NFSERR_EAUTH;
		}
		cp->gss_svc_tokenlen = otokenlen;
	}

	return 0;

out:
	kfree_data(cp->gss_svc_token, cp->gss_svc_tokenlen);
	cp->gss_svc_tokenlen = 0;

	return NFSERR_EAUTH;
}

/*
 * Validate the sequence number in the credential as described
 * in RFC 2203 Section 5.3.3.1
 *
 * Here the window of valid sequence numbers is represented by
 * a bitmap.  As each sequence number is received, its bit is
 * set in the bitmap.  An invalid sequence number lies below
 * the lower bound of the window, or is within the window but
 * has its bit already set.
 */
static int
nfs_gss_svc_seqnum_valid(struct nfs_gss_svc_ctx *cp, uint32_t seq)
{
	uint32_t *bits = cp->gss_svc_seqbits;
	uint32_t win = cp->gss_svc_seqwin;
	uint32_t i;

	lck_mtx_lock(&cp->gss_svc_mtx);

	/*
	 * If greater than the window upper bound,
	 * move the window up, and set the bit.
	 */
	if (seq > cp->gss_svc_seqmax) {
		if (seq - cp->gss_svc_seqmax > win) {
			bzero(bits, nfs_gss_seqbits_size(win));
		} else {
			for (i = cp->gss_svc_seqmax + 1; i < seq; i++) {
				win_resetbit(bits, i % win);
			}
		}
		win_setbit(bits, seq % win);
		cp->gss_svc_seqmax = seq;
		lck_mtx_unlock(&cp->gss_svc_mtx);
		return 1;
	}

	/*
	 * Invalid if below the lower bound of the window
	 */
	if (seq <= cp->gss_svc_seqmax - win) {
		lck_mtx_unlock(&cp->gss_svc_mtx);
		return 0;
	}

	/*
	 * In the window, invalid if the bit is already set
	 */
	if (win_getbit(bits, seq % win)) {
		lck_mtx_unlock(&cp->gss_svc_mtx);
		return 0;
	}
	win_setbit(bits, seq % win);
	lck_mtx_unlock(&cp->gss_svc_mtx);
	return 1;
}

/*
 * Drop a reference to a context
 *
 * Note that it's OK for the context to exist
 * with a refcount of zero.  The refcount isn't
 * checked until we're about to reap an expired one.
 */
void
nfs_gss_svc_ctx_deref(struct nfs_gss_svc_ctx *cp)
{
	lck_mtx_lock(&cp->gss_svc_mtx);
	if (cp->gss_svc_refcnt > 0) {
		cp->gss_svc_refcnt--;
	} else {
		printf("nfs_gss_ctx_deref: zero refcount\n");
	}
	lck_mtx_unlock(&cp->gss_svc_mtx);
}

/*
 * Called at NFS server shutdown - destroy all contexts
 */
void
nfs_gss_svc_cleanup(void)
{
	struct nfs_gss_svc_ctx_hashhead *head;
	struct nfs_gss_svc_ctx *cp, *ncp;
	int i;

	lck_mtx_lock(&nfs_gss_svc_ctx_mutex);

	/*
	 * Run through all the buckets
	 */
	for (i = 0; i < SVC_CTX_HASHSZ; i++) {
		/*
		 * Remove and free all entries in the bucket
		 */
		head = &nfs_gss_svc_ctx_hashtbl[i];
		LIST_FOREACH_SAFE(cp, head, gss_svc_entries, ncp) {
			LIST_REMOVE(cp, gss_svc_entries);
			if (cp->gss_svc_seqbits) {
				kfree_data(cp->gss_svc_seqbits, nfs_gss_seqbits_size(cp->gss_svc_seqwin));
			}
			lck_mtx_destroy(&cp->gss_svc_mtx, &nfs_gss_svc_grp);
			kfree_type(struct nfs_gss_svc_ctx, cp);
		}
	}

	lck_mtx_unlock(&nfs_gss_svc_ctx_mutex);
}

/*************
 * The following functions are used by both client and server.
 */

/*
 * Release a host special port that was obtained by host_get_special_port
 * or one of its macros (host_get_gssd_port in this case).
 * This really should be in a public kpi.
 */

/* This should be in a public header if this routine is not */
static void
host_release_special_port(mach_port_t mp)
{
	if (IPC_PORT_VALID(mp)) {
		ipc_port_release_send(mp);
	}
}

/*
 * The token that is sent and received in the gssd upcall
 * has unbounded variable length.  Mach RPC does not pass
 * the token in-line.  Instead it uses page mapping to handle
 * these parameters.  This function allocates a VM buffer
 * to hold the token for an upcall and copies the token
 * (received from the client) into it.  The VM buffer is
 * marked with a src_destroy flag so that the upcall will
 * automatically de-allocate the buffer when the upcall is
 * complete.
 */
static void
nfs_gss_mach_alloc_buffer(u_char *buf, size_t buflen, vm_map_copy_t *addr)
{
	kern_return_t kr;
	vm_offset_t kmem_buf;
	vm_size_t tbuflen;

	*addr = NULL;
	if (buf == NULL || buflen == 0) {
		return;
	}

	tbuflen = vm_map_round_page(buflen, vm_map_page_mask(ipc_kernel_map));

	if (tbuflen < buflen) {
		printf("nfs_gss_mach_alloc_buffer: vm_map_round_page failed\n");
		return;
	}

	kr = kmem_alloc(ipc_kernel_map, &kmem_buf, tbuflen,
	    KMA_DATA, VM_KERN_MEMORY_FILE);
	if (kr != 0) {
		printf("nfs_gss_mach_alloc_buffer: vm_allocate failed\n");
		return;
	}

	bcopy(buf, (char *)kmem_buf, buflen);
	bzero((char *)kmem_buf + buflen, tbuflen - buflen);

	kr = vm_map_unwire(ipc_kernel_map, kmem_buf, kmem_buf + tbuflen, FALSE);
	if (kr != 0) {
		printf("nfs_gss_mach_alloc_buffer: vm_map_unwire failed\n");
		return;
	}

	kr = vm_map_copyin(ipc_kernel_map, (vm_map_address_t) kmem_buf,
	    (vm_map_size_t) buflen, TRUE, addr);
	if (kr != 0) {
		printf("nfs_gss_mach_alloc_buffer: vm_map_copyin failed\n");
		return;
	}
}

/*
 * Here we handle a token received from the gssd via an upcall.
 * The received token resides in an allocate VM buffer.
 * We copy the token out of this buffer to a chunk of malloc'ed
 * memory of the right size, then de-allocate the VM buffer.
 */
static int
nfs_gss_mach_vmcopyout(vm_map_copy_t in, uint32_t len, u_char *out)
{
	vm_map_offset_t map_data;
	vm_offset_t data;
	int error;

	error = vm_map_copyout(ipc_kernel_map, &map_data, in);
	if (error) {
		return error;
	}

	data = CAST_DOWN(vm_offset_t, map_data);
	bcopy((void *) data, out, len);
	vm_deallocate(ipc_kernel_map, data, len);

	return 0;
}

/*
 * Return the number of bytes in an mbuf chain.
 */
static int
nfs_gss_mchain_length(mbuf_t mhead)
{
	mbuf_t mb;
	int len = 0;

	for (mb = mhead; mb; mb = mbuf_next(mb)) {
		len += mbuf_len(mb);
	}

	return len;
}

/*
 * Return the size for the sequence numbers bitmap.
 */
static int
nfs_gss_seqbits_size(uint32_t win)
{
	return nfsm_rndup((win + 7) / 8);
}

/*
 * Append an args or results mbuf chain to the header chain
 */
static int
nfs_gss_append_chain(struct nfsm_chain *nmc, mbuf_t mc)
{
	int error = 0;
	mbuf_t mb, tail;

	/* Connect the mbuf chains */
	error = mbuf_setnext(nmc->nmc_mcur, mc);
	if (error) {
		return error;
	}

	/* Find the last mbuf in the chain */
	tail = NULL;
	for (mb = mc; mb; mb = mbuf_next(mb)) {
		tail = mb;
	}

	nmc->nmc_mcur = tail;
	nmc->nmc_ptr = (caddr_t) mbuf_data(tail) + mbuf_len(tail);
	nmc->nmc_left = mbuf_trailingspace(tail);

	return 0;
}

/*
 * Convert an mbuf chain to an NFS mbuf chain
 */
static void
nfs_gss_nfsm_chain(struct nfsm_chain *nmc, mbuf_t mc)
{
	mbuf_t mb, tail;

	/* Find the last mbuf in the chain */
	tail = NULL;
	for (mb = mc; mb; mb = mbuf_next(mb)) {
		tail = mb;
	}

	nmc->nmc_mhead = mc;
	nmc->nmc_mcur = tail;
	nmc->nmc_ptr = (caddr_t) mbuf_data(tail) + mbuf_len(tail);
	nmc->nmc_left = mbuf_trailingspace(tail);
	nmc->nmc_flags = 0;
}

#if 0
#define DISPLAYLEN 16
#define MAXDISPLAYLEN 256

static void
hexdump(const char *msg, void *data, size_t len)
{
	size_t i, j;
	u_char *d = data;
	char *p, disbuf[3 * DISPLAYLEN + 1];

	printf("NFS DEBUG %s len=%d:\n", msg, (uint32_t)len);
	if (len > MAXDISPLAYLEN) {
		len = MAXDISPLAYLEN;
	}

	for (i = 0; i < len; i += DISPLAYLEN) {
		for (p = disbuf, j = 0; (j + i) < len && j < DISPLAYLEN; j++, p += 3) {
			snprintf(p, 4, "%02x ", d[i + j]);
		}
		printf("\t%s\n", disbuf);
	}
}
#endif

#endif /* CONFIG_NFS_SERVER */
