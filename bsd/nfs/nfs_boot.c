/*
 * Copyright (c) 2000-2019 Apple Inc. All rights reserved.
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
/* Copyright (c) 1995, 1997 NeXT Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1994 Adam Glass, Gordon Ross
 * All rights reserved.
 *
 * This software was developed by the Computer Systems Engineering group
 * at Lawrence Berkeley Laboratory under DARPA contract BG 91-66 and
 * contributed to Berkeley.
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
 *      This product includes software developed by the University of
 *      California, Lawrence Berkeley Laboratory and its contributors.
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
 *  History:
 *  14-March-97	Dieter Siegmund (dieter@next.com)
 *	- Use BOOTP instead of RARP to get the IP address at boot time
 *
 *  23-May-97  Umesh Vaishampayan  (umeshv@apple.com)
 *	- Added the ability to mount "/private" separately.
 *
 *  30-May-97	Dieter Siegmund	(dieter@next.com)
 *	- Clear out the ireq structure before using it to prevent
 *	  our sending using a bogus source IP address, we should use
 *	  an IP address of all zeroes
 *	- Right after BOOTP, get the correct netmask using AUTONETMASK
 *  18-Jul-97	Dieter Siegmund	(dieter@apple.com)
 *	- we can't restrict the netmask until we have a default route,
 *	  removed AUTONETMASK call (ifdef'd out)
 *  5-Aug-97	Dieter Siegmund (dieter@apple.com)
 *	- use the default route from the bpwhoami call, enabled autonetmask
 *	  again
 *  19-Feb-1999	Dieter Siegmund (dieter@apple.com)
 *	- use new BOOTP routine to get the subnet mask and router
 *        and stop using SIOCAUTOADDR
 *      - don't bother mounting private separately if it's not
 *        specified or not required because they are substrings of
 *        one another ie. root=host:/A and private=host:/A/private
 *      - allow the root path to be specified in the boot variable
 *	  "rp" (AKA "rootpath")
 *  19-Jul-1999 Dieter Siegmund (dieter@apple.com)
 *	- replaced big automatic arrays with MALLOC'd data
 */

#include <nfs/nfs_conf.h>
#if CONFIG_NFS_CLIENT

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/conf.h>
#include <sys/ioctl.h>
#include <sys/proc.h>
#include <sys/mount_internal.h>
#include <sys/vnode_internal.h>
#include <sys/kpi_mbuf.h>

#include <sys/malloc.h>
#include <sys/socket.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <nfs/rpcv2.h>
#include <nfs/nfsproto.h>
#include <nfs/nfs.h>
#include <nfs/nfsdiskless.h>
#include <nfs/krpc.h>
#include <nfs/xdr_subs.h>

#if CONFIG_MACF
#include <security/mac_framework.h>
#endif

#include <pexpert/pexpert.h>

#include "ether.h"

#include <libkern/libkern.h>

#if CONFIG_NETBOOT
static int      nfs_mount_diskless(struct nfs_dlmount *, const char *, int, vnode_t *, mount_t *, vfs_context_t);
#if !defined(NO_MOUNT_PRIVATE)
static int      nfs_mount_diskless_private(struct nfs_dlmount *, const char *, int, vnode_t *, mount_t *, vfs_context_t);
#endif /* NO_MOUNT_PRIVATE */
#endif

#if NETHER == 0

int
nfs_boot_init(__unused struct nfs_diskless *nd)
{
	panic("nfs_boot_init: no ether");
}

int
nfs_boot_getfh(__unused struct nfs_diskless *nd, __unused int v3, __unused int sotype)
{
	panic("nfs_boot_getfh: no ether");
}

#else /* NETHER */

/*
 * Support for NFS diskless booting, specifically getting information
 * about where to boot from, what pathnames, etc.
 *
 * This implememtation uses RARP and the bootparam RPC.
 * We are forced to implement RPC anyway (to get file handles)
 * so we might as well take advantage of it for bootparam too.
 *
 * The diskless boot sequence goes as follows:
 * (1) Use RARP to get our interface address
 * (2) Use RPC/bootparam/whoami to get our hostname,
 *     our IP address, and the server's IP address.
 * (3) Use RPC/bootparam/getfile to get the root path
 * (4) Use RPC/mountd to get the root file handle
 * (5) Use RPC/bootparam/getfile to get the swap path
 * (6) Use RPC/mountd to get the swap file handle
 *
 * (This happens to be the way Sun does it too.)
 */

/* bootparam RPC */
static int bp_whoami(struct sockaddr_in *bpsin,
    struct in_addr *my_ip, struct in_addr *gw_ip);
static int bp_getfile(struct sockaddr_in *bpsin, const char *key,
    struct sockaddr_in *mdsin, char *servname, char *path);

/* mountd RPC */
static int md_mount(struct sockaddr_in *mdsin, char *path, int v3, int sotype,
    u_char *fhp, u_int32_t *fhlenp);

/* other helpers */
static int get_file_handle(struct nfs_dlmount *ndmntp);


#define IP_FORMAT       "%d.%d.%d.%d"
#define IP_CH(ip)       ((u_char *)ip)
#define IP_LIST(ip)     IP_CH(ip)[0],IP_CH(ip)[1],IP_CH(ip)[2],IP_CH(ip)[3]

#include <sys/netboot.h>

/*
 * Called with an empty nfs_diskless struct to be filled in.
 */
int
nfs_boot_init(struct nfs_diskless *nd)
{
	struct sockaddr_in      bp_sin;
	boolean_t               do_bpwhoami = TRUE;
	boolean_t               do_bpgetfile = TRUE;
	int                     error = 0;
	struct in_addr          my_ip;
	struct sockaddr_in *    sin_p;

	/* make sure mbuf constants are set up */
	if (!nfs_mbuf_mhlen) {
		nfs_mbuf_init();
	}

	/* by this point, networking must already have been configured */
	if (netboot_iaddr(&my_ip) == FALSE) {
		printf("nfs_boot: networking is not initialized\n");
		error = ENXIO;
		goto failed;
	}

	/* get the root path information */
	nd->nd_root.ndm_path = zalloc(ZV_NAMEI);
	nd->nd_root.ndm_mntfrom = zalloc(ZV_NAMEI);

	sin_p = &nd->nd_root.ndm_saddr;
	bzero((caddr_t)sin_p, sizeof(*sin_p));
	sin_p->sin_len = sizeof(*sin_p);
	sin_p->sin_family = AF_INET;
	if (netboot_rootpath(&sin_p->sin_addr, nd->nd_root.ndm_host,
	    sizeof(nd->nd_root.ndm_host),
	    nd->nd_root.ndm_path, MAXPATHLEN) == TRUE) {
		do_bpgetfile = FALSE;
		do_bpwhoami = FALSE;
	}
	nd->nd_private.ndm_saddr.sin_addr.s_addr = 0;

	if (do_bpwhoami) {
		struct in_addr router;
		/*
		 * Get client name and gateway address.
		 * RPC: bootparam/whoami
		 * Use the old broadcast address for the WHOAMI
		 * call because we do not yet know our netmask.
		 * The server address returned by the WHOAMI call
		 * is used for all subsequent booptaram RPCs.
		 */
		bzero((caddr_t)&bp_sin, sizeof(bp_sin));
		bp_sin.sin_len = sizeof(bp_sin);
		bp_sin.sin_family = AF_INET;
		bp_sin.sin_addr.s_addr = INADDR_BROADCAST;
		router.s_addr = 0;
		error = bp_whoami(&bp_sin, &my_ip, &router);
		if (error) {
			printf("nfs_boot: bootparam whoami, error=%d", error);
			goto failed;
		}
		printf("nfs_boot: BOOTPARAMS server " IP_FORMAT "\n",
		    IP_LIST(&bp_sin.sin_addr));
		lck_mtx_lock(&hostname_lock);
		printf("nfs_boot: hostname %s\n", hostname);
		lck_mtx_unlock(&hostname_lock);
	}
	if (do_bpgetfile) {
		error = bp_getfile(&bp_sin, "root", &nd->nd_root.ndm_saddr,
		    nd->nd_root.ndm_host, nd->nd_root.ndm_path);
		if (error) {
			printf("nfs_boot: bootparam get root: %d\n", error);
			goto failed;
		}
	}

#if !defined(NO_MOUNT_PRIVATE)
	if (do_bpgetfile) { /* get private path */
		nd->nd_private.ndm_path = zalloc(ZV_NAMEI);
		nd->nd_private.ndm_mntfrom = zalloc(ZV_NAMEI);
		error = bp_getfile(&bp_sin, "private",
		    &nd->nd_private.ndm_saddr,
		    nd->nd_private.ndm_host,
		    nd->nd_private.ndm_path);
		if (!error) {
			char * check_path = NULL;

			check_path = zalloc(ZV_NAMEI);
			snprintf(check_path, MAXPATHLEN, "%s/private", nd->nd_root.ndm_path);
			if ((nd->nd_root.ndm_saddr.sin_addr.s_addr
			    == nd->nd_private.ndm_saddr.sin_addr.s_addr)
			    && (strncmp(check_path, nd->nd_private.ndm_path, MAXPATHLEN) == 0)) {
				/* private path is prefix of root path, don't mount */
				nd->nd_private.ndm_saddr.sin_addr.s_addr = 0;
			}
			NFS_ZFREE(ZV_NAMEI, check_path);
		} else {
			/* private key not defined, don't mount */
			nd->nd_private.ndm_saddr.sin_addr.s_addr = 0;
		}
	} else {
		error = 0;
	}
#endif /* NO_MOUNT_PRIVATE */
failed:
	return error;
}

/*
 * Called with a partially initialized nfs_diskless struct
 * with file handles to be filled in.
 */
int
nfs_boot_getfh(struct nfs_diskless *nd, int v3, int sotype)
{
	int error = 0;

	nd->nd_root.ndm_nfsv3 = v3;
	nd->nd_root.ndm_sotype = sotype;
	error = get_file_handle(&nd->nd_root);
	if (error) {
		printf("nfs_boot: get_file_handle(v%d) root failed, %d\n",
		    v3 ? 3 : 2, error);
		goto failed;
	}

#if !defined(NO_MOUNT_PRIVATE)
	if (nd->nd_private.ndm_saddr.sin_addr.s_addr) {
		/* get private file handle */
		nd->nd_private.ndm_nfsv3 = v3;
		nd->nd_private.ndm_sotype = sotype;
		error = get_file_handle(&nd->nd_private);
		if (error) {
			printf("nfs_boot: get_file_handle(v%d) private failed, %d\n",
			    v3 ? 3 : 2, error);
			goto failed;
		}
	}
#endif /* NO_MOUNT_PRIVATE */
failed:
	return error;
}

static int
get_file_handle(struct nfs_dlmount *ndmntp)
{
	char *sp, *dp, *endp;
	int error;

	/*
	 * Get file handle for "key" (root or swap)
	 * using RPC to mountd/mount
	 */
	error = md_mount(&ndmntp->ndm_saddr, ndmntp->ndm_path, ndmntp->ndm_nfsv3,
	    ndmntp->ndm_sotype, ndmntp->ndm_fh, &ndmntp->ndm_fhlen);
	if (error) {
		return error;
	}

	/* Construct remote path (for getmntinfo(3)) */
	dp = ndmntp->ndm_mntfrom;
	endp = dp + MAXPATHLEN - 1;
	for (sp = ndmntp->ndm_host; *sp && dp < endp;) {
		*dp++ = *sp++;
	}
	if (dp < endp) {
		*dp++ = ':';
	}
	for (sp = ndmntp->ndm_path; *sp && dp < endp;) {
		*dp++ = *sp++;
	}
	*dp = '\0';
	return 0;
}


/*
 * Get an mbuf with the given length, and
 * initialize the pkthdr length field.
 */
static int
mbuf_get_with_len(size_t msg_len, mbuf_t *m)
{
	int error;
	error = mbuf_gethdr(MBUF_WAITOK, MBUF_TYPE_DATA, m);
	if (error) {
		return error;
	}
	if (msg_len > mbuf_maxlen(*m)) {
		error = mbuf_mclget(MBUF_WAITOK, MBUF_TYPE_DATA, m);
		if (error) {
			mbuf_freem(*m);
			return error;
		}
		if (msg_len > mbuf_maxlen(*m)) {
			panic("nfs_boot: msg_len > MCLBYTES");
		}
	}
	mbuf_setlen(*m, msg_len);
	mbuf_pkthdr_setlen(*m, msg_len);
	return 0;
}


/*
 * String representation for RPC.
 */
struct rpc_string {
	size_t len;     /* length without null or padding */
	u_char data[4]; /* data (longer, of course) */
	/* data is padded to a long-word boundary */
};
/* Compute space used given string length. */
#define RPC_STR_SIZE(slen) (4 + ((slen + 3) & ~3))

/*
 * Inet address in RPC messages
 * (Note, really four 32-bit ints, NOT chars.  Blech.)
 */
struct bp_inaddr {
	u_int32_t  atype;
	int32_t addr[4];
};


/*
 * RPC: bootparam/whoami
 * Given client IP address, get:
 *	client name	(hostname)
 *	domain name (domainname)
 *	gateway address
 *
 * The hostname and domainname are set here for convenience.
 *
 * Note - bpsin is initialized to the broadcast address,
 * and will be replaced with the bootparam server address
 * after this call is complete.  Have to use PMAP_PROC_CALL
 * to make sure we get responses only from a servers that
 * know about us (don't want to broadcast a getport call).
 */
static int
bp_whoami(struct sockaddr_in *bpsin,
    struct in_addr *my_ip,
    struct in_addr *gw_ip)
{
	/* RPC structures for PMAPPROC_CALLIT */
	struct whoami_call {
		u_int32_t call_prog;
		u_int32_t call_vers;
		u_int32_t call_proc;
		u_int32_t call_arglen;
		struct bp_inaddr call_ia;
	} *call;

	struct rpc_string *str;
	struct bp_inaddr *bia;
	mbuf_t m;
	struct sockaddr_in sin;
	int error;
	size_t msg_len, cn_len, dn_len;
	u_char *p;
	int32_t *lp;
	size_t encapsulated_size;

	/*
	 * Get message buffer of sufficient size.
	 */
	msg_len = sizeof(*call);
	error = mbuf_get_with_len(msg_len, &m);
	if (error) {
		return error;
	}

	/*
	 * Build request message for PMAPPROC_CALLIT.
	 */
	call = mbuf_data(m);
	call->call_prog = htonl(BOOTPARAM_PROG);
	call->call_vers = htonl(BOOTPARAM_VERS);
	call->call_proc = htonl(BOOTPARAM_WHOAMI);
	call->call_arglen = htonl(sizeof(struct bp_inaddr));

	/* client IP address */
	call->call_ia.atype = htonl(1);
	p = (u_char*)my_ip;
	lp = call->call_ia.addr;
	*lp++ = htonl(*p); p++;
	*lp++ = htonl(*p); p++;
	*lp++ = htonl(*p); p++;
	*lp++ = htonl(*p); p++;

	/* RPC: portmap/callit */
	bpsin->sin_port = htons(PMAPPORT);

	error = krpc_call(bpsin, SOCK_DGRAM, PMAPPROG, PMAPVERS, PMAPPROC_CALLIT, &m, &sin);
	if (error) {
		return error;
	}

	/*
	 * Parse result message.
	 */
	msg_len = mbuf_len(m);
	lp = mbuf_data(m);

	/* bootparam server port (also grab from address). */
	if (msg_len < sizeof(*lp)) {
		goto bad;
	}
	msg_len -= sizeof(*lp);
	bpsin->sin_port = htons((short)ntohl(*lp++));
	bpsin->sin_addr.s_addr = sin.sin_addr.s_addr;

	/* length of encapsulated results */
	if (os_add_overflow((size_t) ntohl(*lp), sizeof(*lp), &encapsulated_size)
	    || msg_len < encapsulated_size) {
		goto bad;
	}
	msg_len = ntohl(*lp++);
	p = (u_char*)lp;

	/* client name */
	if (msg_len < sizeof(*str)) {
		goto bad;
	}
	str = (struct rpc_string *)p;
	cn_len = ntohll(str->len);
	if ((msg_len - 4) < cn_len) {
		goto bad;
	}
	if (cn_len >= MAXHOSTNAMELEN) {
		goto bad;
	}
	lck_mtx_lock(&hostname_lock);
	bcopy(str->data, hostname, cn_len);
	hostname[cn_len] = '\0';
	lck_mtx_unlock(&hostname_lock);
	p += RPC_STR_SIZE(cn_len);
	msg_len -= RPC_STR_SIZE(cn_len);

	/* domain name */
	if (msg_len < sizeof(*str)) {
		goto bad;
	}
	str = (struct rpc_string *)p;
	dn_len = ntohll(str->len);
	if ((msg_len - 4) < dn_len) {
		goto bad;
	}
	if (dn_len >= MAXHOSTNAMELEN) {
		goto bad;
	}
	lck_mtx_lock(&domainname_lock);
	bcopy(str->data, domainname, dn_len);
	domainname[dn_len] = '\0';
	lck_mtx_unlock(&domainname_lock);
	p += RPC_STR_SIZE(dn_len);
	msg_len -= RPC_STR_SIZE(dn_len);

	/* gateway address */
	if (msg_len < sizeof(*bia)) {
		goto bad;
	}
	bia = (struct bp_inaddr *)p;
	if (bia->atype != htonl(1)) {
		goto bad;
	}
	p = (u_char*)gw_ip;
	*p++ = ntohl(bia->addr[0]) & 0xff;
	*p++ = ntohl(bia->addr[1]) & 0xff;
	*p++ = ntohl(bia->addr[2]) & 0xff;
	*p++ = ntohl(bia->addr[3]) & 0xff;
	goto out;

bad:
	printf("nfs_boot: bootparam_whoami: bad reply\n");
	error = EBADRPC;

out:
	mbuf_freem(m);
	return error;
}


/*
 * RPC: bootparam/getfile
 * Given client name and file "key", get:
 *	server name
 *	server IP address
 *	server pathname
 */
static int
bp_getfile(struct sockaddr_in *bpsin,
    const char *key,
    struct sockaddr_in *md_sin,
    char *serv_name,
    char *pathname)
{
	struct rpc_string *str;
	mbuf_t m;
	struct bp_inaddr *bia;
	struct sockaddr_in *sin;
	u_char *p, *q;
	int error;
	size_t msg_len, cn_len, key_len, sn_len, path_len;

	/*
	 * Get message buffer of sufficient size.
	 */
	lck_mtx_lock(&hostname_lock);
	cn_len = strlen(hostname);
	lck_mtx_unlock(&hostname_lock);
	key_len = strlen(key);
	msg_len = 0;
	msg_len += RPC_STR_SIZE(cn_len);
	msg_len += RPC_STR_SIZE(key_len);
	error = mbuf_get_with_len(msg_len, &m);
	if (error) {
		return error;
	}

	/*
	 * Build request message.
	 */
	p = mbuf_data(m);
	bzero(p, msg_len);
	/* client name (hostname) */
	str = (struct rpc_string *)p;
	str->len = htonll(cn_len);
	lck_mtx_lock(&hostname_lock);
	bcopy(hostname, str->data, cn_len);
	lck_mtx_unlock(&hostname_lock);
	p += RPC_STR_SIZE(cn_len);
	/* key name (root or swap) */
	str = (struct rpc_string *)p;
	str->len = htonll(key_len);
	bcopy(key, str->data, key_len);

	/* RPC: bootparam/getfile */
	error = krpc_call(bpsin, SOCK_DGRAM, BOOTPARAM_PROG, BOOTPARAM_VERS,
	    BOOTPARAM_GETFILE, &m, NULL);
	if (error) {
		return error;
	}

	/*
	 * Parse result message.
	 */
	p = mbuf_data(m);
	msg_len = mbuf_len(m);

	/* server name */
	if (msg_len < sizeof(*str)) {
		goto bad;
	}
	str = (struct rpc_string *)p;
	sn_len = ntohll(str->len);
	if ((msg_len - 4) < sn_len) {
		goto bad;
	}
	if (sn_len >= MAXHOSTNAMELEN) {
		goto bad;
	}
	bcopy(str->data, serv_name, sn_len);
	serv_name[sn_len] = '\0';
	p += RPC_STR_SIZE(sn_len);
	msg_len -= RPC_STR_SIZE(sn_len);

	/* server IP address (mountd) */
	if (msg_len < sizeof(*bia)) {
		goto bad;
	}
	bia = (struct bp_inaddr *)p;
	if (bia->atype != htonl(1)) {
		goto bad;
	}
	sin = md_sin;
	bzero((caddr_t)sin, sizeof(*sin));
	sin->sin_len = sizeof(*sin);
	sin->sin_family = AF_INET;
	q = (u_char*) &sin->sin_addr;
	*q++ = ntohl(bia->addr[0]) & 0xff;
	*q++ = ntohl(bia->addr[1]) & 0xff;
	*q++ = ntohl(bia->addr[2]) & 0xff;
	*q++ = ntohl(bia->addr[3]) & 0xff;
	p += sizeof(*bia);
	msg_len -= sizeof(*bia);

	/* server pathname */
	if (msg_len < sizeof(*str)) {
		goto bad;
	}
	str = (struct rpc_string *)p;
	path_len = ntohll(str->len);
	if ((msg_len - 4) < path_len) {
		goto bad;
	}
	if (path_len >= MAXPATHLEN) {
		goto bad;
	}
	bcopy(str->data, pathname, path_len);
	pathname[path_len] = '\0';
	goto out;

bad:
	printf("nfs_boot: bootparam_getfile: bad reply\n");
	error = EBADRPC;

out:
	mbuf_freem(m);
	return 0;
}


/*
 * RPC: mountd/mount
 * Given a server pathname, get an NFS file handle.
 * Also, sets sin->sin_port to the NFS service port.
 */
static int
md_mount(struct sockaddr_in *mdsin,             /* mountd server address */
    char *path,
    int v3,
    int sotype,
    u_char *fhp,
    u_int32_t *fhlenp)
{
	/* The RPC structures */
	struct rpc_string *str;
	struct rdata {
		u_int32_t       errno;
		u_char  data[NFSX_V3FHMAX + sizeof(u_int32_t)];
	} *rdata;
	mbuf_t m;
	size_t mlen, slen;
	int error;
	int mntversion = v3 ? RPCMNT_VER3 : RPCMNT_VER1;
	int proto = (sotype == SOCK_STREAM) ? IPPROTO_TCP : IPPROTO_UDP;
	in_port_t mntport, nfsport;

	/* Get port number for MOUNTD. */
	error = krpc_portmap(mdsin, RPCPROG_MNT, mntversion, proto, &mntport);
	if (error) {
		return error;
	}

	/* Get port number for NFS use. */
	/* (If NFS/proto unavailable, don't bother with the mount call) */
	error = krpc_portmap(mdsin, NFS_PROG, v3 ? NFS_VER3 : NFS_VER2, proto, &nfsport);
	if (error) {
		return error;
	}

	/* Set port number for MOUNTD */
	mdsin->sin_port = mntport;

	slen = strlen(path);
	mlen = RPC_STR_SIZE(slen);

	error = mbuf_get_with_len(mlen, &m);
	if (error) {
		return error;
	}
	str = mbuf_data(m);
	str->len = htonll(slen);
	bcopy(path, str->data, slen);

	/* Do RPC to mountd. */
	error = krpc_call(mdsin, sotype, RPCPROG_MNT, mntversion, RPCMNT_MOUNT, &m, NULL);
	if (error) {
		return error;   /* message already freed */
	}
	/*
	 * the reply must be long enough to hold the errno plus either of:
	 * + a v2 filehandle
	 * + a v3 filehandle length + a v3 filehandle
	 */
	mlen = mbuf_len(m);
	if (mlen < sizeof(u_int32_t)) {
		goto bad;
	}
	rdata = mbuf_data(m);
	error = ntohl(rdata->errno);
	if (error) {
		goto out;
	}
	if (v3) {
		u_int32_t fhlen;
		u_char *fh;
		if (mlen < sizeof(u_int32_t) * 2) {
			goto bad;
		}
		fhlen = ntohl(*(u_int32_t*)rdata->data);
		fh = rdata->data + sizeof(u_int32_t);
		if (mlen < (sizeof(u_int32_t) * 2 + fhlen)
		    || fhlen >= (NFSX_V3FHMAX + sizeof(u_int32_t))) {
			goto bad;
		}
		bcopy(fh, fhp, fhlen);
		*fhlenp = fhlen;
	} else {
		if (mlen < (sizeof(u_int32_t) + NFSX_V2FH)) {
			goto bad;
		}
		bcopy(rdata->data, fhp, NFSX_V2FH);
		*fhlenp = NFSX_V2FH;
	}

	/* Set port number for NFS use. */
	mdsin->sin_port = nfsport;
	goto out;

bad:
	error = EBADRPC;

out:
	mbuf_freem(m);
	return error;
}

#endif /* NETHER */

/*
 * Mount a remote root fs via. nfs. This depends on the info in the
 * nfs_diskless structure that has been filled in properly by some primary
 * bootstrap.
 * It goes something like this:
 * - do enough of "ifconfig" by calling ifioctl() so that the system
 *   can talk to the server
 * - If nfs_diskless.mygateway is filled in, use that address as
 *   a default gateway.
 * - hand craft the swap nfs vnode hanging off a fake mount point
 *	if swdevt[0].sw_dev == NODEV
 * - build the rootfs mount point and call mountnfs() to do the rest.
 */
#if CONFIG_NETBOOT
int
nfs_mountroot(void)
{
	struct nfs_diskless nd;
	mount_t mp = NULL;
	vnode_t vp = NULL;
	vfs_context_t ctx;
	int error;
#if !defined(NO_MOUNT_PRIVATE)
	mount_t mppriv = NULL;
	vnode_t vppriv = NULL;
#endif /* NO_MOUNT_PRIVATE */
	int v3, sotype;

	/*
	 * Call nfs_boot_init() to fill in the nfs_diskless struct.
	 * Note: networking must already have been configured before
	 * we're called.
	 */
	bzero((caddr_t) &nd, sizeof(nd));
	error = nfs_boot_init(&nd);
	if (error) {
		panic("nfs_boot_init: unable to initialize NFS root system information, "
		    "error %d, check configuration: %s\n", error, PE_boot_args());
	}

	/*
	 * Try NFSv3 first, then fallback to NFSv2.
	 * Likewise, try TCP first, then fall back to UDP.
	 */
	v3 = 1;
	sotype = SOCK_STREAM;

tryagain:
	error = nfs_boot_getfh(&nd, v3, sotype);
	if (error) {
		if (error == EHOSTDOWN || error == EHOSTUNREACH) {
			if (nd.nd_root.ndm_mntfrom) {
				NFS_ZFREE(ZV_NAMEI, nd.nd_root.ndm_mntfrom);
			}
			if (nd.nd_root.ndm_path) {
				NFS_ZFREE(ZV_NAMEI, nd.nd_root.ndm_path);
			}
			if (nd.nd_private.ndm_mntfrom) {
				NFS_ZFREE(ZV_NAMEI, nd.nd_private.ndm_mntfrom);
			}
			if (nd.nd_private.ndm_path) {
				NFS_ZFREE(ZV_NAMEI, nd.nd_private.ndm_path);
			}
			return error;
		}
		if (v3) {
			if (sotype == SOCK_STREAM) {
				printf("NFS mount (v3,TCP) failed with error %d, trying UDP...\n", error);
				sotype = SOCK_DGRAM;
				goto tryagain;
			}
			printf("NFS mount (v3,UDP) failed with error %d, trying v2...\n", error);
			v3 = 0;
			sotype = SOCK_STREAM;
			goto tryagain;
		} else if (sotype == SOCK_STREAM) {
			printf("NFS mount (v2,TCP) failed with error %d, trying UDP...\n", error);
			sotype = SOCK_DGRAM;
			goto tryagain;
		} else {
			printf("NFS mount (v2,UDP) failed with error %d, giving up...\n", error);
		}
		switch (error) {
		case EPROGUNAVAIL:
			panic("NFS mount failed: NFS server mountd not responding, check server configuration: %s", PE_boot_args());
		case EACCES:
		case EPERM:
			panic("NFS mount failed: NFS server refused mount, check server configuration: %s", PE_boot_args());
		default:
			panic("NFS mount failed with error %d, check configuration: %s", error, PE_boot_args());
		}
	}

	ctx = vfs_context_kernel();

	/*
	 * Create the root mount point.
	 */
#if !defined(NO_MOUNT_PRIVATE)
	{
		//PWC hack until we have a real "mount" tool to remount root rw
		int rw_root = 0;
		int flags = MNT_ROOTFS | MNT_RDONLY;
		PE_parse_boot_argn("-rwroot_hack", &rw_root, sizeof(rw_root));
		if (rw_root) {
			flags = MNT_ROOTFS;
			kprintf("-rwroot_hack in effect: mounting root fs read/write\n");
		}

		if ((error = nfs_mount_diskless(&nd.nd_root, "/", flags, &vp, &mp, ctx)))
#else
	if ((error = nfs_mount_diskless(&nd.nd_root, "/", MNT_ROOTFS, &vp, &mp, ctx)))
#endif /* NO_MOUNT_PRIVATE */
		{
			if (v3) {
				if (sotype == SOCK_STREAM) {
					printf("NFS root mount (v3,TCP) failed with %d, trying UDP...\n", error);
					sotype = SOCK_DGRAM;
					goto tryagain;
				}
				printf("NFS root mount (v3,UDP) failed with %d, trying v2...\n", error);
				v3 = 0;
				sotype = SOCK_STREAM;
				goto tryagain;
			} else if (sotype == SOCK_STREAM) {
				printf("NFS root mount (v2,TCP) failed with %d, trying UDP...\n", error);
				sotype = SOCK_DGRAM;
				goto tryagain;
			} else {
				printf("NFS root mount (v2,UDP) failed with error %d, giving up...\n", error);
			}
			panic("NFS root mount failed with error %d, check configuration: %s", error, PE_boot_args());
		}
	}
	printf("root on %s\n", nd.nd_root.ndm_mntfrom);

	vfs_unbusy(mp);
	mount_list_add(mp);
	rootvp = vp;

#if !defined(NO_MOUNT_PRIVATE)
	if (nd.nd_private.ndm_saddr.sin_addr.s_addr) {
		error = nfs_mount_diskless_private(&nd.nd_private, "/private",
		    0, &vppriv, &mppriv, ctx);
		if (error) {
			panic("NFS /private mount failed with error %d, check configuration: %s", error, PE_boot_args());
		}
		printf("private on %s\n", nd.nd_private.ndm_mntfrom);

		vfs_unbusy(mppriv);
		mount_list_add(mppriv);
	}

#endif /* NO_MOUNT_PRIVATE */

	if (nd.nd_root.ndm_mntfrom) {
		NFS_ZFREE(ZV_NAMEI, nd.nd_root.ndm_mntfrom);
	}
	if (nd.nd_root.ndm_path) {
		NFS_ZFREE(ZV_NAMEI, nd.nd_root.ndm_path);
	}
	if (nd.nd_private.ndm_mntfrom) {
		NFS_ZFREE(ZV_NAMEI, nd.nd_private.ndm_mntfrom);
	}
	if (nd.nd_private.ndm_path) {
		NFS_ZFREE(ZV_NAMEI, nd.nd_private.ndm_path);
	}

	return 0;
}

/*
 * Internal version of mount system call for diskless setup.
 */
static int
nfs_mount_diskless(
	struct nfs_dlmount *ndmntp,
	const char *mntname,
	int mntflag,
	vnode_t *vpp,
	mount_t *mpp,
	vfs_context_t ctx)
{
	mount_t mp;
	vnode_t vp = NULLVP;
	int error, numcomps;
	char *xdrbuf, *p, *cp, *frompath, *endserverp;
	char uaddr[MAX_IPv4_STR_LEN];
	struct xdrbuf xb;
	uint32_t mattrs[NFS_MATTR_BITMAP_LEN];
	uint32_t mflags_mask[NFS_MFLAG_BITMAP_LEN];
	uint32_t mflags[NFS_MFLAG_BITMAP_LEN];
	uint64_t argslength_offset, attrslength_offset, end_offset;

	if ((error = vfs_rootmountalloc("nfs", ndmntp->ndm_mntfrom, &mp))) {
		printf("nfs_mount_diskless: NFS not configured\n");
		return error;
	}

	mp->mnt_kern_flag |= MNTK_KERNEL_MOUNT; /* mark as kernel mount */
	vfs_setflags(mp, mntflag);
	if (!vfs_isrdonly(mp)) {
		vfs_clearflags(mp, MNT_RDONLY);
	}

	/* find the server-side path being mounted */
	frompath = ndmntp->ndm_mntfrom;
	if (*frompath == '[') {  /* skip IPv6 literal address */
		while (*frompath && (*frompath != ']')) {
			frompath++;
		}
		if (*frompath == ']') {
			frompath++;
		}
	}
	while (*frompath && (*frompath != ':')) {
		frompath++;
	}
	endserverp = frompath;
	while (*frompath && (*frompath == ':')) {
		frompath++;
	}
	/* count fs location path components */
	p = frompath;
	while (*p && (*p == '/')) {
		p++;
	}
	numcomps = 0;
	while (*p) {
		numcomps++;
		while (*p && (*p != '/')) {
			p++;
		}
		while (*p && (*p == '/')) {
			p++;
		}
	}

	/* convert address to universal address string */
	if (inet_ntop(AF_INET, &ndmntp->ndm_saddr.sin_addr, uaddr, sizeof(uaddr)) != uaddr) {
		printf("nfs_mount_diskless: bad address\n");
		return EINVAL;
	}

	/* prepare mount attributes */
	NFS_BITMAP_ZERO(mattrs, NFS_MATTR_BITMAP_LEN);
	NFS_BITMAP_SET(mattrs, NFS_MATTR_NFS_VERSION);
	NFS_BITMAP_SET(mattrs, NFS_MATTR_SOCKET_TYPE);
	NFS_BITMAP_SET(mattrs, NFS_MATTR_NFS_PORT);
	NFS_BITMAP_SET(mattrs, NFS_MATTR_FH);
	NFS_BITMAP_SET(mattrs, NFS_MATTR_FS_LOCATIONS);
	NFS_BITMAP_SET(mattrs, NFS_MATTR_MNTFLAGS);

	/* prepare mount flags */
	NFS_BITMAP_ZERO(mflags_mask, NFS_MFLAG_BITMAP_LEN);
	NFS_BITMAP_ZERO(mflags, NFS_MFLAG_BITMAP_LEN);
	NFS_BITMAP_SET(mflags_mask, NFS_MFLAG_RESVPORT);
	NFS_BITMAP_SET(mflags, NFS_MFLAG_RESVPORT);

	/* build xdr buffer */
	xb_init_buffer(&xb, NULL, 0);
	xb_add_32(error, &xb, NFS_ARGSVERSION_XDR);
	argslength_offset = xb_offset(&xb);
	xb_add_32(error, &xb, 0); // args length
	xb_add_32(error, &xb, NFS_XDRARGS_VERSION_0);
	xb_add_bitmap(error, &xb, mattrs, NFS_MATTR_BITMAP_LEN);
	attrslength_offset = xb_offset(&xb);
	xb_add_32(error, &xb, 0); // attrs length
	xb_add_32(error, &xb, ndmntp->ndm_nfsv3 ? 3 : 2); // NFS version
	xb_add_string(error, &xb, ((ndmntp->ndm_sotype == SOCK_DGRAM) ? "udp" : "tcp"), 3);
	xb_add_32(error, &xb, ntohs(ndmntp->ndm_saddr.sin_port)); // NFS port
	xb_add_fh(error, &xb, &ndmntp->ndm_fh[0], ndmntp->ndm_fhlen);
	/* fs location */
	xb_add_32(error, &xb, 1); /* fs location count */
	xb_add_32(error, &xb, 1); /* server count */
	xb_add_string(error, &xb, ndmntp->ndm_mntfrom, (endserverp - ndmntp->ndm_mntfrom)); /* server name */
	xb_add_32(error, &xb, 1); /* address count */
	xb_add_string(error, &xb, uaddr, strlen(uaddr)); /* address */
	xb_add_32(error, &xb, 0); /* empty server info */
	xb_add_32(error, &xb, numcomps); /* pathname component count */
	p = frompath;
	while (*p && (*p == '/')) {
		p++;
	}
	while (*p) {
		cp = p;
		while (*p && (*p != '/')) {
			p++;
		}
		xb_add_string(error, &xb, cp, (p - cp)); /* component */
		if (error) {
			break;
		}
		while (*p && (*p == '/')) {
			p++;
		}
	}
	xb_add_32(error, &xb, 0); /* empty fsl info */
	xb_add_32(error, &xb, mntflag); /* MNT flags */
	xb_build_done(error, &xb);

	/* update opaque counts */
	end_offset = xb_offset(&xb);
	if (!error) {
		error = xb_seek(&xb, argslength_offset);
		xb_add_32(error, &xb, end_offset - argslength_offset + XDRWORD /*version*/);
	}
	if (!error) {
		error = xb_seek(&xb, attrslength_offset);
		xb_add_32(error, &xb, end_offset - attrslength_offset - XDRWORD /*don't include length field*/);
	}
	if (error) {
		printf("nfs_mount_diskless: error %d assembling mount args\n", error);
		xb_cleanup(&xb);
		return error;
	}
	/* grab the assembled buffer */
	xdrbuf = xb_buffer_base(&xb);

	/* do the mount */
	if ((error = VFS_MOUNT(mp, vp, CAST_USER_ADDR_T(xdrbuf), ctx))) {
		printf("nfs_mountroot: mount %s failed: %d\n", mntname, error);
		// XXX vfs_rootmountfailed(mp);
		mount_list_lock();
		mp->mnt_vtable->vfc_refcount--;
		mount_list_unlock();
		vfs_unbusy(mp);
		mount_lock_destroy(mp);
#if CONFIG_MACF
		mac_mount_label_destroy(mp);
#endif
		NFS_ZFREE(mount_zone, mp);
	} else {
		*mpp = mp;
		error = VFS_ROOT(mp, vpp, ctx);
	}
	xb_cleanup(&xb);
	return error;
}

#if !defined(NO_MOUNT_PRIVATE)
/*
 * Internal version of mount system call to mount "/private"
 * separately in diskless setup
 */
static int
nfs_mount_diskless_private(
	struct nfs_dlmount *ndmntp,
	const char *mntname,
	int mntflag,
	vnode_t *vpp,
	mount_t *mpp,
	vfs_context_t ctx)
{
	mount_t mp;
	vnode_t vp = NULLVP;
	int error, numcomps;
	proc_t procp;
	struct vfstable *vfsp;
	struct nameidata nd;
	char *xdrbuf = NULL, *p, *cp, *frompath, *endserverp;
	char uaddr[MAX_IPv4_STR_LEN];
	struct xdrbuf xb;
	uint32_t mattrs[NFS_MATTR_BITMAP_LEN];
	uint32_t mflags_mask[NFS_MFLAG_BITMAP_LEN], mflags[NFS_MFLAG_BITMAP_LEN];
	uint64_t argslength_offset, attrslength_offset, end_offset;
	struct vfsioattr ioattr;

	procp = current_proc(); /* XXX */
	xb_init(&xb, XDRBUF_NONE);

	{
		/*
		 * mimic main()!. Temporarily set up rootvnode and other stuff so
		 * that namei works. Need to undo this because main() does it, too
		 */
		struct filedesc *fdp = &procp->p_fd;
		vfs_setflags(mountlist.tqh_first, MNT_ROOTFS);

		/* Get the vnode for '/'. Set fdp->fd_cdir to reference it. */
		if (VFS_ROOT(mountlist.tqh_first, &rootvnode, NULL)) {
			panic("cannot find root vnode");
		}
		error = vnode_ref(rootvnode);
		if (error) {
			printf("nfs_mountroot: vnode_ref() failed on root vnode!\n");
			goto out;
		}
		fdp->fd_cdir = rootvnode;
		fdp->fd_rdir = NULL;
	}

	/*
	 * Get vnode to be covered
	 */
	NDINIT(&nd, LOOKUP, OP_LOOKUP, FOLLOW | LOCKLEAF, UIO_SYSSPACE,
	    CAST_USER_ADDR_T(mntname), ctx);
	error = namei(&nd);
	{
		/* undo vnode_ref() in mimic main()! */
		vnode_rele(rootvnode);
	}
	if (error) {
		printf("nfs_mountroot: private namei failed!\n");
		goto out;
	}
	nameidone(&nd);
	vp = nd.ni_vp;

	if ((error = VNOP_FSYNC(vp, MNT_WAIT, ctx)) ||
	    (error = buf_invalidateblks(vp, BUF_WRITE_DATA, 0, 0))) {
		vnode_put(vp);
		goto out;
	}
	if (vnode_vtype(vp) != VDIR) {
		vnode_put(vp);
		error = ENOTDIR;
		goto out;
	}
	for (vfsp = vfsconf; vfsp; vfsp = vfsp->vfc_next) {
		if (!strncmp(vfsp->vfc_name, "nfs", sizeof(vfsp->vfc_name))) {
			break;
		}
	}
	if (vfsp == NULL) {
		printf("nfs_mountroot: private NFS not configured\n");
		vnode_put(vp);
		error = ENODEV;
		goto out;
	}
	if (vnode_mountedhere(vp) != NULL) {
		vnode_put(vp);
		error = EBUSY;
		goto out;
	}

	/*
	 * Allocate and initialize the filesystem.
	 */
	mp = zalloc_flags(mount_zone, Z_WAITOK | Z_ZERO);
	/* Initialize the default IO constraints */
	bzero(&ioattr, sizeof(ioattr));
	ioattr.io_maxreadcnt = ioattr.io_maxwritecnt = MAXPHYS;
	ioattr.io_segreadcnt = ioattr.io_segwritecnt = 32;
	vfs_setioattr(mp, &ioattr);
	mp->mnt_realrootvp = NULLVP;
	vfs_setauthcache_ttl(mp, 0); /* Allways go to our lookup */
	mp->mnt_kern_flag |= MNTK_KERNEL_MOUNT; /* mark as kernel mount */

	mount_lock_init(mp);
	TAILQ_INIT(&mp->mnt_vnodelist);
	TAILQ_INIT(&mp->mnt_workerqueue);
	TAILQ_INIT(&mp->mnt_newvnodes);
	(void)vfs_busy(mp, LK_NOWAIT);
	TAILQ_INIT(&mp->mnt_vnodelist);
	mount_list_lock();
	vfsp->vfc_refcount++;
	mount_list_unlock();
	mp->mnt_vtable = vfsp;
	mp->mnt_op = vfsp->vfc_vfsops;
	vfs_setflags(mp, mntflag);
	vfs_setflags(mp, vfsp->vfc_flags);
	strncpy(vfs_statfs(mp)->f_fstypename, vfsp->vfc_name, MFSNAMELEN - 1);
	vp->v_mountedhere = mp;
	mp->mnt_vnodecovered = vp;
	vp = NULLVP;
	vfs_statfs(mp)->f_owner = kauth_cred_getuid(kauth_cred_get());
	(void) copystr(mntname, vfs_statfs(mp)->f_mntonname, MAXPATHLEN - 1, 0);
	(void) copystr(ndmntp->ndm_mntfrom, vfs_statfs(mp)->f_mntfromname, MAXPATHLEN - 1, 0);
#if CONFIG_MACF
	mac_mount_label_init(mp);
	mac_mount_label_associate(ctx, mp);
#endif

	/* find the server-side path being mounted */
	frompath = ndmntp->ndm_mntfrom;
	if (*frompath == '[') {  /* skip IPv6 literal address */
		while (*frompath && (*frompath != ']')) {
			frompath++;
		}
		if (*frompath == ']') {
			frompath++;
		}
	}
	while (*frompath && (*frompath != ':')) {
		frompath++;
	}
	endserverp = frompath;
	while (*frompath && (*frompath == ':')) {
		frompath++;
	}
	/* count fs location path components */
	p = frompath;
	while (*p && (*p == '/')) {
		p++;
	}
	numcomps = 0;
	while (*p) {
		numcomps++;
		while (*p && (*p != '/')) {
			p++;
		}
		while (*p && (*p == '/')) {
			p++;
		}
	}

	/* convert address to universal address string */
	if (inet_ntop(AF_INET, &ndmntp->ndm_saddr.sin_addr, uaddr, sizeof(uaddr)) != uaddr) {
		printf("nfs_mountroot: bad address\n");
		error = EINVAL;
		goto out;
	}

	/* prepare mount attributes */
	NFS_BITMAP_ZERO(mattrs, NFS_MATTR_BITMAP_LEN);
	NFS_BITMAP_SET(mattrs, NFS_MATTR_NFS_VERSION);
	NFS_BITMAP_SET(mattrs, NFS_MATTR_SOCKET_TYPE);
	NFS_BITMAP_SET(mattrs, NFS_MATTR_NFS_PORT);
	NFS_BITMAP_SET(mattrs, NFS_MATTR_FH);
	NFS_BITMAP_SET(mattrs, NFS_MATTR_FS_LOCATIONS);
	NFS_BITMAP_SET(mattrs, NFS_MATTR_MNTFLAGS);

	/* prepare mount flags */
	NFS_BITMAP_ZERO(mflags_mask, NFS_MFLAG_BITMAP_LEN);
	NFS_BITMAP_ZERO(mflags, NFS_MFLAG_BITMAP_LEN);
	NFS_BITMAP_SET(mflags_mask, NFS_MFLAG_RESVPORT);
	NFS_BITMAP_SET(mflags, NFS_MFLAG_RESVPORT);

	/* build xdr buffer */
	xb_init_buffer(&xb, NULL, 0);
	xb_add_32(error, &xb, NFS_ARGSVERSION_XDR);
	argslength_offset = xb_offset(&xb);
	xb_add_32(error, &xb, 0); // args length
	xb_add_32(error, &xb, NFS_XDRARGS_VERSION_0);
	xb_add_bitmap(error, &xb, mattrs, NFS_MATTR_BITMAP_LEN);
	attrslength_offset = xb_offset(&xb);
	xb_add_32(error, &xb, 0); // attrs length
	xb_add_32(error, &xb, ndmntp->ndm_nfsv3 ? 3 : 2); // NFS version
	xb_add_string(error, &xb, ((ndmntp->ndm_sotype == SOCK_DGRAM) ? "udp" : "tcp"), 3);
	xb_add_32(error, &xb, ntohs(ndmntp->ndm_saddr.sin_port)); // NFS port
	xb_add_fh(error, &xb, &ndmntp->ndm_fh[0], ndmntp->ndm_fhlen);
	/* fs location */
	xb_add_32(error, &xb, 1); /* fs location count */
	xb_add_32(error, &xb, 1); /* server count */
	xb_add_string(error, &xb, ndmntp->ndm_mntfrom, (endserverp - ndmntp->ndm_mntfrom)); /* server name */
	xb_add_32(error, &xb, 1); /* address count */
	xb_add_string(error, &xb, uaddr, strlen(uaddr)); /* address */
	xb_add_32(error, &xb, 0); /* empty server info */
	xb_add_32(error, &xb, numcomps); /* pathname component count */
	p = frompath;
	while (*p && (*p == '/')) {
		p++;
	}
	while (*p) {
		cp = p;
		while (*p && (*p != '/')) {
			p++;
		}
		xb_add_string(error, &xb, cp, (p - cp)); /* component */
		if (error) {
			break;
		}
		while (*p && (*p == '/')) {
			p++;
		}
	}
	xb_add_32(error, &xb, 0); /* empty fsl info */
	xb_add_32(error, &xb, mntflag); /* MNT flags */
	xb_build_done(error, &xb);

	/* update opaque counts */
	end_offset = xb_offset(&xb);
	if (!error) {
		error = xb_seek(&xb, argslength_offset);
		xb_add_32(error, &xb, end_offset - argslength_offset + XDRWORD /*version*/);
	}
	if (!error) {
		error = xb_seek(&xb, attrslength_offset);
		xb_add_32(error, &xb, end_offset - attrslength_offset - XDRWORD /*don't include length field*/);
	}
	if (error) {
		printf("nfs_mountroot: error %d assembling mount args\n", error);
		goto out;
	}
	/* grab the assembled buffer */
	xdrbuf = xb_buffer_base(&xb);

	/* do the mount */
	if ((error = VFS_MOUNT(mp, vp, CAST_USER_ADDR_T(xdrbuf), ctx))) {
		printf("nfs_mountroot: mount %s failed: %d\n", mntname, error);
		vnode_put(mp->mnt_vnodecovered);
		mount_list_lock();
		vfsp->vfc_refcount--;
		mount_list_unlock();
		vfs_unbusy(mp);
		mount_lock_destroy(mp);
#if CONFIG_MACF
		mac_mount_label_destroy(mp);
#endif
		NFS_ZFREE(mount_zone, mp);
		goto out;
	} else {
		*mpp = mp;
		error = VFS_ROOT(mp, vpp, ctx);
	}
out:
	xb_cleanup(&xb);
	return error;
}
#endif /* NO_MOUNT_PRIVATE */

#endif /* CONFIG_NETBOOT */

#endif /* CONFIG_NFS_CLIENT */
