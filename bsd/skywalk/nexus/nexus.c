/*
 * Copyright (c) 2015-2021 Apple Inc. All rights reserved.
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

#include <skywalk/os_skywalk_private.h>
#include <skywalk/nexus/netif/nx_netif.h>
#include <skywalk/nexus/flowswitch/nx_flowswitch.h>
#include <sys/sdt.h>

static uint32_t disable_nxctl_check = 0;
#if (DEVELOPMENT || DEBUG)
SYSCTL_UINT(_kern_skywalk, OID_AUTO, disable_nxctl_check,
    CTLFLAG_RW | CTLFLAG_LOCKED, &disable_nxctl_check, 0, "");
#endif

LCK_GRP_DECLARE(nexus_lock_group, "sk_nx_lock");
LCK_GRP_DECLARE(nexus_mbq_lock_group, "sk_nx_mbq_lock");
LCK_GRP_DECLARE(nexus_pktq_lock_group, "sk_nx_pktq_lock");
LCK_ATTR_DECLARE(nexus_lock_attr, 0, 0);

static STAILQ_HEAD(, nxctl) nxctl_head =
    STAILQ_HEAD_INITIALIZER(nxctl_head);
static STAILQ_HEAD(, kern_nexus_provider) nxprov_head =
    STAILQ_HEAD_INITIALIZER(nxprov_head);

static int nx_cmp(const struct kern_nexus *, const struct kern_nexus *);
RB_HEAD(kern_nexus_tree, kern_nexus);
RB_PROTOTYPE_SC(static, kern_nexus_tree, kern_nexus, nx_link, nx_cmp);
RB_GENERATE(kern_nexus_tree, kern_nexus, nx_link, nx_cmp);
static struct kern_nexus_tree   nx_head;

static int nxctl_get_nexus_prov_list(struct nxctl *, struct sockopt *);
static int nxctl_get_nexus_prov_entry(struct nxctl *, struct sockopt *);
static int nxctl_get_nexus_list(struct nxctl *, struct sockopt *);
static int nxctl_nexus_bind(struct nxctl *, struct sockopt *);
static int nxctl_nexus_unbind(struct nxctl *, struct sockopt *);
static int nxctl_nexus_config(struct nxctl *, struct sockopt *);
static int nxctl_get_channel_list(struct nxctl *, struct sockopt *);
static void nxctl_retain_locked(struct nxctl *);
static int nxctl_release_locked(struct nxctl *);
static void nxctl_init(struct nxctl *, struct proc *, struct fileproc *);
static struct nxctl *nxctl_alloc(struct proc *, struct fileproc *, zalloc_flags_t);
static void nxctl_free(struct nxctl *);

static struct kern_nexus_provider *nxprov_create_common(struct nxctl *,
    struct kern_nexus_domain_provider *, struct nxprov_reg *,
    const struct kern_nexus_provider_init *init, int *);
static void nxprov_detach(struct kern_nexus_provider *, boolean_t);
static void nxprov_retain_locked(struct kern_nexus_provider *);
static int nxprov_release_locked(struct kern_nexus_provider *);
static struct kern_nexus_provider *nxprov_alloc(
	struct kern_nexus_domain_provider *, zalloc_flags_t);
static void nxprov_free(struct kern_nexus_provider *);

static int nx_init_rings(struct kern_nexus *, struct kern_channel *);
static void nx_fini_rings(struct kern_nexus *, struct kern_channel *);
static int nx_init_slots(struct kern_nexus *, struct __kern_channel_ring *);
static void nx_fini_slots(struct kern_nexus *, struct __kern_channel_ring *);
static struct kern_nexus *nx_alloc(zalloc_flags_t);
static void nx_free(struct kern_nexus *);

static ZONE_DEFINE(nxctl_zone, SKMEM_ZONE_PREFIX ".nx.ctl",
    sizeof(struct nxctl), ZC_ZFREE_CLEARMEM);

static ZONE_DEFINE(nxbind_zone, SKMEM_ZONE_PREFIX ".nx.bind",
    sizeof(struct nxbind), ZC_ZFREE_CLEARMEM);

static ZONE_DEFINE(nxprov_zone, SKMEM_ZONE_PREFIX ".nx.kern.prov",
    sizeof(struct kern_nexus_provider), ZC_ZFREE_CLEARMEM);

static ZONE_DEFINE(nxprov_params_zone, SKMEM_ZONE_PREFIX ".nx.kern.prov.params",
    sizeof(struct nxprov_params), ZC_ZFREE_CLEARMEM);

static ZONE_DEFINE(nx_zone, SKMEM_ZONE_PREFIX ".nx",
    sizeof(struct kern_nexus), ZC_ZFREE_CLEARMEM);

static int __nx_inited = 0;

#define SKMEM_TAG_NX_KEY        "com.apple.skywalk.nexus.key"
kern_allocation_name_t skmem_tag_nx_key;

#define SKMEM_TAG_NX_MIB        "com.apple.skywalk.nexus.mib"
static kern_allocation_name_t skmem_tag_nx_mib;

#define SKMEM_TAG_NX_PORT        "com.apple.skywalk.nexus.port"
kern_allocation_name_t skmem_tag_nx_port;

#define SKMEM_TAG_NX_PORT_INFO        "com.apple.skywalk.nexus.port.info"
kern_allocation_name_t skmem_tag_nx_port_info;

/*
 * Special nexus controller handle for Skywalk internal use.  Unlike all
 * other nexus controller handles that are created by userland or kernel
 * clients, this one never gets closed or freed.  It is also not part of
 * the global nxctl_head list.
 */
static struct nxctl _kernnxctl;
struct nexus_controller kernnxctl = { .ncd_nxctl = &_kernnxctl };

int
nexus_init(void)
{
	SK_LOCK_ASSERT_HELD();
	ASSERT(!__nx_inited);

	RB_INIT(&nx_head);

	na_init();

	/* attach system built-in domains and domain providers */
	nxdom_attach_all();

	/*
	 * Initialize private kernel nexus controller handle; this is used
	 * internally for creating nexus providers and nexus instances from
	 * within the Skywalk code (e.g. netif_compat).
	 */
	nxctl_init(&_kernnxctl, kernproc, NULL);
	nxctl_retain_locked(&_kernnxctl);       /* one for us */

	ASSERT(skmem_tag_nx_key == NULL);
	skmem_tag_nx_key = kern_allocation_name_allocate(SKMEM_TAG_NX_KEY, 0);
	ASSERT(skmem_tag_nx_key != NULL);

	ASSERT(skmem_tag_nx_mib == NULL);
	skmem_tag_nx_mib = kern_allocation_name_allocate(SKMEM_TAG_NX_MIB, 0);
	ASSERT(skmem_tag_nx_mib != NULL);

	ASSERT(skmem_tag_nx_port == NULL);
	skmem_tag_nx_port = kern_allocation_name_allocate(SKMEM_TAG_NX_PORT, 0);
	ASSERT(skmem_tag_nx_port != NULL);

	ASSERT(skmem_tag_nx_port_info == NULL);
	skmem_tag_nx_port_info = kern_allocation_name_allocate(
		SKMEM_TAG_NX_PORT_INFO, 0);
	ASSERT(skmem_tag_nx_port_info != NULL);

	__nx_inited = 1;

	return 0;
}

void
nexus_fini(void)
{
	SK_LOCK_ASSERT_HELD();

	if (__nx_inited) {
		nxctl_release_locked(&_kernnxctl);

		/* tell all domains they're going away */
		nxdom_detach_all();

		ASSERT(RB_EMPTY(&nx_head));

		if (skmem_tag_nx_key != NULL) {
			kern_allocation_name_release(skmem_tag_nx_key);
			skmem_tag_nx_key = NULL;
		}
		if (skmem_tag_nx_mib != NULL) {
			kern_allocation_name_release(skmem_tag_nx_mib);
			skmem_tag_nx_mib = NULL;
		}
		if (skmem_tag_nx_port != NULL) {
			kern_allocation_name_release(skmem_tag_nx_port);
			skmem_tag_nx_port = NULL;
		}
		if (skmem_tag_nx_port_info != NULL) {
			kern_allocation_name_release(skmem_tag_nx_port_info);
			skmem_tag_nx_port_info = NULL;
		}
		na_fini();

		__nx_inited = 0;
	}
}

struct nxctl *
nxctl_create(struct proc *p, struct fileproc *fp, const uuid_t nxctl_uuid,
    int *err)
{
	struct nxctl *nxctl = NULL;

	ASSERT(!uuid_is_null(nxctl_uuid));

	/* privilege checks would be done when performing nxctl operations */

	SK_LOCK();

	nxctl = nxctl_alloc(p, fp, Z_WAITOK);

	STAILQ_INSERT_TAIL(&nxctl_head, nxctl, nxctl_link);
	nxctl->nxctl_flags |= NEXUSCTLF_ATTACHED;
	uuid_copy(nxctl->nxctl_uuid, nxctl_uuid);

	nxctl_retain_locked(nxctl);     /* one for being in the list */
	nxctl_retain_locked(nxctl);     /* one for the caller */

#if SK_LOG
	uuid_string_t uuidstr;
	SK_D("nxctl 0x%llx UUID %s", SK_KVA(nxctl),
	    sk_uuid_unparse(nxctl->nxctl_uuid, uuidstr));
#endif /* SK_LOG */

	SK_UNLOCK();

	if (*err != 0) {
		nxctl_free(nxctl);
		nxctl = NULL;
	}
	return nxctl;
}

void
nxctl_close(struct nxctl *nxctl)
{
	struct kern_nexus_provider *nxprov = NULL, *tnxprov;

	lck_mtx_lock(&nxctl->nxctl_lock);
	SK_LOCK();

	ASSERT(!(nxctl->nxctl_flags & NEXUSCTLF_KERNEL));

#if SK_LOG
	uuid_string_t uuidstr;
	SK_D("nxctl 0x%llx UUID %s flags 0x%b", SK_KVA(nxctl),
	    sk_uuid_unparse(nxctl->nxctl_uuid, uuidstr),
	    nxctl->nxctl_flags, NEXUSCTLF_BITS);
#endif /* SK_LOG */

	if (!(nxctl->nxctl_flags & NEXUSCTLF_NOFDREF)) {
		nxctl->nxctl_flags |= NEXUSCTLF_NOFDREF;
		nxctl->nxctl_fp = NULL;
	}

	/* may be called as part of failure cleanup, so check */
	if (nxctl->nxctl_flags & NEXUSCTLF_ATTACHED) {
		/* caller must hold an extra ref */
		ASSERT(nxctl->nxctl_refcnt > 1);
		(void) nxctl_release_locked(nxctl);

		STAILQ_REMOVE(&nxctl_head, nxctl, nxctl, nxctl_link);
		nxctl->nxctl_flags &= ~NEXUSCTLF_ATTACHED;
	}

repeat:
	STAILQ_FOREACH_SAFE(nxprov, &nxprov_head, nxprov_link, tnxprov) {
		/*
		 * Close provider only for those which are owned by
		 * this control instance.  Note that if we close the
		 * provider, we need to repeat this search as the
		 * list might have been changed by another thread.
		 * That's possible since SK_UNLOCK() may be called
		 * as a result of calling nxprov_close().
		 */
		if (!(nxprov->nxprov_flags & NXPROVF_CLOSED) &&
		    nxprov->nxprov_ctl == nxctl) {
			nxprov_retain_locked(nxprov);
			(void) nxprov_close(nxprov, TRUE);
			(void) nxprov_release_locked(nxprov);
			goto repeat;
		}
	}

	SK_UNLOCK();
	lck_mtx_unlock(&nxctl->nxctl_lock);
}

int
nxctl_set_opt(struct nxctl *nxctl, struct sockopt *sopt)
{
#pragma unused(nxctl)
	int err = 0;

	NXCTL_LOCK_ASSERT_HELD(nxctl);

	if (sopt->sopt_dir != SOPT_SET) {
		sopt->sopt_dir = SOPT_SET;
	}

	switch (sopt->sopt_name) {
	case NXOPT_NEXUS_BIND:
		err = nxctl_nexus_bind(nxctl, sopt);
		break;

	case NXOPT_NEXUS_UNBIND:
		err = nxctl_nexus_unbind(nxctl, sopt);
		break;

	case NXOPT_NEXUS_CONFIG:
		err = nxctl_nexus_config(nxctl, sopt);
		break;

	default:
		err = ENOPROTOOPT;
		break;
	}

	return err;
}

int
nxctl_get_opt(struct nxctl *nxctl, struct sockopt *sopt)
{
#pragma unused(nxctl)
	int err = 0;

	NXCTL_LOCK_ASSERT_HELD(nxctl);

	if (sopt->sopt_dir != SOPT_GET) {
		sopt->sopt_dir = SOPT_GET;
	}

	switch (sopt->sopt_name) {
	case NXOPT_NEXUS_PROV_LIST:
		err = nxctl_get_nexus_prov_list(nxctl, sopt);
		break;

	case NXOPT_NEXUS_PROV_ENTRY:
		err = nxctl_get_nexus_prov_entry(nxctl, sopt);
		break;

	case NXOPT_NEXUS_LIST:
		err = nxctl_get_nexus_list(nxctl, sopt);
		break;

	case NXOPT_CHANNEL_LIST:
		err = nxctl_get_channel_list(nxctl, sopt);
		break;

	default:
		err = ENOPROTOOPT;
		break;
	}

	return err;
}

/* Upper bound on # of nrl_num_regs that we'd return to user space */
#define MAX_NUM_REG_ENTRIES     256

/* Hoisted out of line to reduce kernel stack footprint */
SK_NO_INLINE_ATTRIBUTE
static int
nxctl_get_nexus_prov_list(struct nxctl *nxctl, struct sockopt *sopt)
{
	user_addr_t tmp_ptr = USER_ADDR_NULL;
	struct nxprov_reg_ent *pnre, *nres = NULL;
	struct nxprov_list_req nrlr;
	struct kern_nexus_provider *nxprov = NULL;
	uint32_t nregs = 0, ncregs = 0;
	int err = 0, observeall;
	size_t nres_sz;

	NXCTL_LOCK_ASSERT_HELD(nxctl);

	ASSERT(sopt->sopt_p != NULL);
	if (sopt->sopt_val == USER_ADDR_NULL) {
		return EINVAL;
	}

	err = sooptcopyin(sopt, &nrlr, sizeof(nrlr), sizeof(nrlr));
	if (err != 0) {
		return err;
	}

	if ((size_t)nrlr.nrl_num_regs > MAX_NUM_REG_ENTRIES) {
		nrlr.nrl_num_regs = MAX_NUM_REG_ENTRIES;
	}

	/*
	 * If the caller specified a buffer, copy out the Nexus provider
	 * entries to caller gracefully.  We only copy out the number of
	 * entries which caller has asked for, but we always tell caller
	 * how big the buffer really needs to be.
	 */
	tmp_ptr = nrlr.nrl_regs;
	if (tmp_ptr != USER_ADDR_NULL && nrlr.nrl_num_regs > 0) {
		nres_sz = (size_t)nrlr.nrl_num_regs * sizeof(*nres);
		nres = sk_alloc_data(nres_sz, Z_WAITOK, skmem_tag_sysctl_buf);
		if (__improbable(nres == NULL)) {
			return ENOBUFS;
		}
	}

	observeall = (skywalk_priv_check_cred(sopt->sopt_p, nxctl->nxctl_cred,
	    PRIV_SKYWALK_OBSERVE_ALL) == 0);

	SK_LOCK();
	/*
	 * Count number of providers.  If buffer space exists and
	 * remains, copy out provider entries.
	 */
	nregs = nrlr.nrl_num_regs;
	pnre = nres;

	STAILQ_FOREACH(nxprov, &nxprov_head, nxprov_link) {
		/*
		 * Return only entries that are visible to the caller,
		 * unless it has PRIV_SKYWALK_OBSERVE_ALL.
		 */
		if (nxprov->nxprov_ctl != nxctl && !observeall) {
			continue;
		}

		if (nres != NULL && nregs > 0) {
			uuid_copy(pnre->npre_prov_uuid, nxprov->nxprov_uuid);
			bcopy(nxprov->nxprov_params, &pnre->npre_prov_params,
			    sizeof(struct nxprov_params));
			--nregs;
			++pnre;
			++ncregs;
		}
	}
	SK_UNLOCK();

	if (ncregs == 0) {
		err = ENOENT;
	}

	if (nres != NULL) {
		if (err == 0 && tmp_ptr != USER_ADDR_NULL) {
			if (sopt->sopt_p != kernproc) {
				err = copyout(nres, tmp_ptr,
				    ncregs * sizeof(*nres));
			} else {
				bcopy(nres, CAST_DOWN(caddr_t, tmp_ptr),
				    ncregs * sizeof(*nres));
			}
		}
		sk_free_data(nres, nres_sz);
		nres = NULL;
	}

	if (err == 0) {
		nrlr.nrl_num_regs = ncregs;
		err = sooptcopyout(sopt, &nrlr, sizeof(nrlr));
	}

	return err;
}

/* Hoisted out of line to reduce kernel stack footprint */
SK_NO_INLINE_ATTRIBUTE
static int
nxctl_get_nexus_prov_entry(struct nxctl *nxctl, struct sockopt *sopt)
{
	struct nxprov_reg_ent nre;
	struct kern_nexus_provider *nxprov = NULL;
	int err = 0;

	NXCTL_LOCK_ASSERT_HELD(nxctl);

	ASSERT(sopt->sopt_p != NULL);
	if (sopt->sopt_val == USER_ADDR_NULL) {
		return EINVAL;
	}

	bzero(&nre, sizeof(nre));
	err = sooptcopyin(sopt, &nre, sizeof(nre), sizeof(nre));
	if (err != 0) {
		return err;
	}

	if (uuid_is_null(nre.npre_prov_uuid)) {
		return EINVAL;
	}

	SK_LOCK();
	STAILQ_FOREACH(nxprov, &nxprov_head, nxprov_link) {
		if (uuid_compare(nxprov->nxprov_uuid,
		    nre.npre_prov_uuid) == 0) {
			/*
			 * Return only entries that are visible to the caller,
			 * unless it has PRIV_SKYWALK_OBSERVE_ALL.
			 */
			if (nxprov->nxprov_ctl != nxctl) {
				if (skywalk_priv_check_cred(sopt->sopt_p,
				    nxctl->nxctl_cred,
				    PRIV_SKYWALK_OBSERVE_ALL) != 0) {
					nxprov = NULL;
					break;
				}
			}

			bcopy(nxprov->nxprov_params, &nre.npre_prov_params,
			    sizeof(struct nxprov_params));
			break;
		}
	}
	SK_UNLOCK();

	if (nxprov != NULL) {
		err = sooptcopyout(sopt, &nre, sizeof(nre));
	} else {
		err = ENOENT;
	}

	return err;
}

/* Upper bound on # of nl_num_nx_uuids that we'd return to user space */
#define MAX_NUM_NX_UUIDS        4096

/* Hoisted out of line to reduce kernel stack footprint */
SK_NO_INLINE_ATTRIBUTE
static int
nxctl_get_nexus_list(struct nxctl *nxctl, struct sockopt *sopt)
{
	user_addr_t tmp_ptr = USER_ADDR_NULL;
	uint32_t nuuids = 0, ncuuids = 0;
	uuid_t *puuid, *uuids = NULL;
	size_t uuids_sz;
	struct nx_list_req nlr;
	struct kern_nexus_provider *nxprov = NULL;
	struct kern_nexus *nx = NULL;
	int err = 0, observeall;

	NXCTL_LOCK_ASSERT_HELD(nxctl);

	ASSERT(sopt->sopt_p != NULL);
	if (sopt->sopt_val == USER_ADDR_NULL) {
		return EINVAL;
	}

	err = sooptcopyin(sopt, &nlr, sizeof(nlr), sizeof(nlr));
	if (err != 0) {
		return err;
	}

	if (uuid_is_null(nlr.nl_prov_uuid)) {
		return EINVAL;
	} else if ((size_t)nlr.nl_num_nx_uuids > MAX_NUM_NX_UUIDS) {
		nlr.nl_num_nx_uuids = MAX_NUM_NX_UUIDS;
	}

	/*
	 * If the caller specified a buffer, copy out the Nexus UUIDs to
	 * caller gracefully.  We only copy out the number of UUIDs which
	 * caller has asked for, but we always tell caller how big the
	 * buffer really needs to be.
	 */
	tmp_ptr = nlr.nl_nx_uuids;
	if (tmp_ptr != USER_ADDR_NULL && nlr.nl_num_nx_uuids > 0) {
		uuids_sz = (size_t)nlr.nl_num_nx_uuids * sizeof(uuid_t);
		uuids = sk_alloc_data(uuids_sz, Z_WAITOK, skmem_tag_sysctl_buf);
		if (__improbable(uuids == NULL)) {
			return ENOBUFS;
		}
	}

	observeall = (skywalk_priv_check_cred(sopt->sopt_p, nxctl->nxctl_cred,
	    PRIV_SKYWALK_OBSERVE_ALL) == 0);

	SK_LOCK();
	STAILQ_FOREACH(nxprov, &nxprov_head, nxprov_link) {
		/*
		 * Return only entries that are visible to the caller,
		 * unless it has PRIV_SKYWALK_OBSERVE_ALL.
		 */
		if (nxprov->nxprov_ctl != nxctl && !observeall) {
			continue;
		}

		if (uuid_compare(nxprov->nxprov_uuid, nlr.nl_prov_uuid) == 0) {
			break;
		}
	}

	if (nxprov != NULL) {
		/*
		 * Count number of Nexus.  If buffer space exists
		 * and remains, copy out the Nexus UUIDs.
		 */
		nuuids = nlr.nl_num_nx_uuids;
		puuid = uuids;

		STAILQ_FOREACH(nx, &nxprov->nxprov_nx_head, nx_prov_link) {
			++ncuuids;
			if (uuids != NULL && nuuids > 0) {
				uuid_copy(*puuid, nx->nx_uuid);
				--nuuids;
				++puuid;
			}
		}
	} else {
		err = ENOENT;
	}
	SK_UNLOCK();

	if (uuids != NULL) {
		if (err == 0 && nxprov != NULL && tmp_ptr != USER_ADDR_NULL) {
			uintptr_t cnt_uuid;

			/* Note: Pointer arithmetic */
			cnt_uuid = (uintptr_t)(puuid - uuids);
			if (cnt_uuid > 0) {
				if (sopt->sopt_p != kernproc) {
					err = copyout(uuids, tmp_ptr,
					    cnt_uuid * sizeof(uuid_t));
				} else {
					bcopy(uuids,
					    CAST_DOWN(caddr_t, tmp_ptr),
					    cnt_uuid * sizeof(uuid_t));
				}
			}
		}
		sk_free_data(uuids, uuids_sz);
		uuids = NULL;
	}

	if (err == 0) {
		nlr.nl_num_nx_uuids = ncuuids;
		err = sooptcopyout(sopt, &nlr, sizeof(nlr));
	}

	return err;
}

/* Hoisted out of line to reduce kernel stack footprint */
SK_NO_INLINE_ATTRIBUTE
static int
nxctl_nexus_bind(struct nxctl *nxctl, struct sockopt *sopt)
{
	boolean_t m_pid, m_exec_uuid, m_key;
	struct nx_bind_req nbr;
	struct proc *p = PROC_NULL;
	struct nxbind *nxb = NULL;
	uint64_t p_uniqueid = -1;
	pid_t p_pid = -1;
	struct kern_nexus *nx = NULL;
#if SK_LOG
	uuid_string_t exec_uuidstr;
#endif /* SK_LOG */
	uuid_t p_uuid;
	void *key = NULL;
	int err = 0;

	NXCTL_LOCK_ASSERT_HELD(nxctl);

	if (sopt->sopt_val == USER_ADDR_NULL) {
		return EINVAL;
	}

	uuid_clear(p_uuid);
	bzero(&nbr, sizeof(nbr));
	err = sooptcopyin(sopt, &nbr, sizeof(nbr), sizeof(nbr));
	if (err != 0) {
		return err;
	}

	if (uuid_is_null(nbr.nb_nx_uuid)) {
		err = EINVAL;
		goto done_unlocked;
	}

	nbr.nb_flags &= NBR_MATCH_MASK;
	if (nbr.nb_flags == 0) {
		/* must choose one of the match criteria */
		err = EINVAL;
		goto done_unlocked;
	}
	m_pid = !!(nbr.nb_flags & NBR_MATCH_PID);
	m_exec_uuid = !!(nbr.nb_flags & NBR_MATCH_EXEC_UUID);
	m_key = !!(nbr.nb_flags & NBR_MATCH_KEY);

	if (m_pid || m_exec_uuid) {
		/*
		 * Validate process ID.  A valid PID is needed when we're
		 * asked to match by PID, or if asked to match by executable
		 * UUID with a NULL nb_exec_uuid supplied.  The latter is
		 * to support the case when a userland Nexus provider isn't
		 * able to acquire its client's executable UUID, but is
		 * able to identify it via PID.
		 */
		if ((m_pid || uuid_is_null(nbr.nb_exec_uuid)) &&
		    (p = proc_find(nbr.nb_pid)) == PROC_NULL) {
			err = ESRCH;
			goto done_unlocked;
		}
		/* exclude kernel from the match criteria */
		if (p == kernproc) {
			err = EACCES;
			goto done_unlocked;
		} else if (p != PROC_NULL) {
			proc_getexecutableuuid(p, p_uuid, sizeof(p_uuid));
			p_uniqueid = proc_uniqueid(p);
			p_pid = proc_pid(p);
		} else {
			uuid_copy(p_uuid, nbr.nb_exec_uuid);
		}
	}

	if (m_key) {
		if (nbr.nb_key_len == 0 || nbr.nb_key_len > NEXUS_MAX_KEY_LEN ||
		    nbr.nb_key == USER_ADDR_NULL) {
			err = EINVAL;
			goto done_unlocked;
		}

		key = sk_alloc_data(nbr.nb_key_len, Z_WAITOK, skmem_tag_nx_key);
		if (__improbable(key == NULL)) {
			err = ENOMEM;
			goto done_unlocked;
		}

		if (sopt->sopt_p != kernproc) {
			err = copyin(nbr.nb_key, key, nbr.nb_key_len);
			if (err != 0) {
				goto done_unlocked;
			}
		} else {
			bcopy((void *)nbr.nb_key, key, nbr.nb_key_len);
		}
	}

	SK_LOCK();
	nx = nx_find(nbr.nb_nx_uuid, TRUE);
	if (nx == NULL || (nx->nx_prov->nxprov_ctl != nxctl &&
	    nxctl != &_kernnxctl)) {    /* make exception for kernnxctl */
		err = ENOENT;
		goto done;
	}

	/* bind isn't applicable on anonymous nexus provider */
	if (NX_ANONYMOUS_PROV(nx)) {
		err = ENXIO;
		goto done;
	}

	/* port must be within the domain's range */
	if (nbr.nb_port != NEXUS_PORT_ANY &&
	    nbr.nb_port >= NXDOM_MAX(NX_DOM(nx), ports)) {
		err = EDOM;
		goto done;
	} else if (nbr.nb_port == NEXUS_PORT_ANY) {
		/* for now, this is allowed only for kernel clients */
		if (sopt->sopt_p != kernproc) {
			err = EPERM;
			goto done;
		}
	}

	nxb = nxb_alloc(Z_WAITOK);

	if (m_pid) {
		nxb->nxb_flags |= NXBF_MATCH_UNIQUEID;
		nxb->nxb_uniqueid = p_uniqueid;
		nxb->nxb_pid = p_pid;
	}
	if (m_exec_uuid) {
		nxb->nxb_flags |= NXBF_MATCH_EXEC_UUID;
		ASSERT(!uuid_is_null(p_uuid));
		uuid_copy(nxb->nxb_exec_uuid, p_uuid);
	}
	if (m_key) {
		nxb->nxb_flags |= NXBF_MATCH_KEY;
		ASSERT(key != NULL);
		nxb->nxb_key = key;
		key = NULL;     /* let nxb_free() free it */
		ASSERT(nbr.nb_key_len != 0 &&
		    nbr.nb_key_len <= NEXUS_MAX_KEY_LEN);
		nxb->nxb_key_len = nbr.nb_key_len;
	}

	/*
	 * Bind the creds to the nexus port.  If client doesn't have a port,
	 * find one, claim it, and associate the creds to it.  Upon success,
	 * the nexus may move the nxbind contents (including the key) to
	 * its own nxbind instance; in that case, nxb_free() below will not
	 * be freeing the key within.
	 */
	err = NX_DOM(nx)->nxdom_bind_port(nx, &nbr.nb_port, nxb, NULL);
	if (err != 0) {
		goto done;
	}

	ASSERT(nbr.nb_port != NEXUS_PORT_ANY);
	(void) sooptcopyout(sopt, &nbr, sizeof(nbr));

	SK_D("nexus 0x%llx nxb 0x%llx port %u flags 0x%b pid %d "
	    "(uniqueid %llu) exec_uuid %s key 0x%llx key_len %u",
	    SK_KVA(nx), SK_KVA(nxb), nbr.nb_port, nxb->nxb_flags,
	    NXBF_BITS, nxb->nxb_pid, nxb->nxb_uniqueid,
	    sk_uuid_unparse(nxb->nxb_exec_uuid, exec_uuidstr),
	    (nxb->nxb_key != NULL) ? SK_KVA(nxb->nxb_key) : 0,
	    nxb->nxb_key_len);

done:
	if (nx != NULL) {
		(void) nx_release_locked(nx);
		nx = NULL;
	}
	SK_UNLOCK();

done_unlocked:
	ASSERT(nx == NULL);

	if (nxb != NULL) {
		nxb_free(nxb);
		nxb = NULL;
	}
	if (key != NULL) {
		sk_free_data(key, nbr.nb_key_len);
		key = NULL;
	}
	if (p != PROC_NULL) {
		proc_rele(p);
	}

	return err;
}

/* Hoisted out of line to reduce kernel stack footprint */
SK_NO_INLINE_ATTRIBUTE
static int
nxctl_nexus_unbind(struct nxctl *nxctl, struct sockopt *sopt)
{
	struct nx_unbind_req nur;
	struct kern_nexus *nx = NULL;
	int err = 0;

	NXCTL_LOCK_ASSERT_HELD(nxctl);

	if (sopt->sopt_val == USER_ADDR_NULL) {
		return EINVAL;
	}

	bzero(&nur, sizeof(nur));
	err = sooptcopyin(sopt, &nur, sizeof(nur), sizeof(nur));
	if (err != 0) {
		return err;
	}

	if (uuid_is_null(nur.nu_nx_uuid)) {
		return EINVAL;
	}

	SK_LOCK();
	nx = nx_find(nur.nu_nx_uuid, TRUE);
	if (nx == NULL || (nx->nx_prov->nxprov_ctl != nxctl &&
	    nxctl != &_kernnxctl)) {    /* make exception for kernnxctl */
		err = ENOENT;
		goto done;
	}

	/* unbind isn't applicable on anonymous nexus provider */
	if (NX_ANONYMOUS_PROV(nx)) {
		err = ENXIO;
		goto done;
	}

	if (nur.nu_port == NEXUS_PORT_ANY) {
		err = EINVAL;
		goto done;
	}

	err = NX_DOM(nx)->nxdom_unbind_port(nx, nur.nu_port);

done:
	if (nx != NULL) {
		(void) nx_release_locked(nx);
		nx = NULL;
	}
	SK_UNLOCK();

	return err;
}

/* Hoisted out of line to reduce kernel stack footprint */
SK_NO_INLINE_ATTRIBUTE
static int
nxctl_nexus_config(struct nxctl *nxctl, struct sockopt *sopt)
{
	struct kern_nexus *nx = NULL;
	struct nx_cfg_req ncr;
	int err = 0;

	NXCTL_LOCK_ASSERT_HELD(nxctl);

	if (sopt->sopt_val == USER_ADDR_NULL) {
		return EINVAL;
	}

	bzero(&ncr, sizeof(ncr));
	err = sooptcopyin(sopt, &ncr, sizeof(ncr), sizeof(ncr));
	if (err != 0) {
		return err;
	}

	if (uuid_is_null(ncr.nc_nx_uuid)) {
		return EINVAL;
	}

	SK_LOCK();
	nx = nx_find(ncr.nc_nx_uuid, TRUE);
	if (nx == NULL || (disable_nxctl_check == 0 &&
	    nx->nx_prov->nxprov_ctl != nxctl &&
	    nxctl != &_kernnxctl)) {    /* make exception for kernnxctl */
		err = ENOENT;
		goto done;
	}

	if (NX_DOM_PROV(nx)->nxdom_prov_config != NULL) {
		err = NX_DOM_PROV(nx)->nxdom_prov_config(NX_DOM_PROV(nx),
		    nx, &ncr, sopt->sopt_dir, sopt->sopt_p, nxctl->nxctl_cred);
	} else {
		err = EPERM;
	}

	if (err == 0) {
		(void) sooptcopyout(sopt, &ncr, sizeof(ncr));
	}
done:
	if (nx != NULL) {
		(void) nx_release_locked(nx);
		nx = NULL;
	}
	SK_UNLOCK();

	return err;
}

struct nxbind *
nxb_alloc(zalloc_flags_t how)
{
	struct nxbind *nxb = zalloc_flags(nxbind_zone, how | Z_ZERO);

	if (nxb) {
		SK_DF(SK_VERB_MEM, "nxb 0x%llx ALLOC", SK_KVA(nxb));
	}
	return nxb;
}

void
nxb_free(struct nxbind *nxb)
{
	SK_DF(SK_VERB_MEM, "nxb 0x%llx key 0x%llx FREE", SK_KVA(nxb),
	    (nxb->nxb_key != NULL) ? SK_KVA(nxb->nxb_key) : 0);

	if (nxb->nxb_key != NULL) {
		sk_free_data(nxb->nxb_key, nxb->nxb_key_len);
		nxb->nxb_key = NULL;
	}
	zfree(nxbind_zone, nxb);
}

/*
 * nxb0 is assumed to possess the truth, compare nxb1 against it.
 */
boolean_t
nxb_is_equal(struct nxbind *nxb0, struct nxbind *nxb1)
{
	ASSERT(nxb0 != NULL && nxb1 != NULL);
	ASSERT(nxb0 != nxb1);

	/* we always compare using uniqueid and not pid */
	if ((nxb0->nxb_flags & NXBF_MATCH_UNIQUEID) &&
	    nxb1->nxb_uniqueid != nxb0->nxb_uniqueid) {
		return FALSE;
	}

	if ((nxb0->nxb_flags & NXBF_MATCH_EXEC_UUID) &&
	    uuid_compare(nxb1->nxb_exec_uuid, nxb0->nxb_exec_uuid) != 0) {
		return FALSE;
	}

	ASSERT(!(nxb0->nxb_flags & NXBF_MATCH_KEY) ||
	    (nxb0->nxb_key_len != 0 && nxb0->nxb_key != NULL));

	if ((nxb0->nxb_flags & NXBF_MATCH_KEY) &&
	    (nxb0->nxb_key_len != nxb1->nxb_key_len ||
	    nxb1->nxb_key == NULL || timingsafe_bcmp(nxb1->nxb_key, nxb0->nxb_key,
	    nxb1->nxb_key_len) != 0)) {
		return FALSE;
	}

	return TRUE;
}

void
nxb_move(struct nxbind *snxb, struct nxbind *dnxb)
{
	ASSERT(!(snxb->nxb_flags & NXBF_MATCH_KEY) ||
	    (snxb->nxb_key_len != 0 && snxb->nxb_key != NULL));

	/* in case the destination has a key attached, free it first */
	if (dnxb->nxb_key != NULL) {
		sk_free_data(dnxb->nxb_key, dnxb->nxb_key_len);
		dnxb->nxb_key = NULL;
	}

	/* move everything from src to dst, and then wipe out src */
	bcopy(snxb, dnxb, sizeof(*dnxb));
	bzero(snxb, sizeof(*snxb));
}

/* Upper bound on # of cl_num_ch_uuids that we'd return to user space */
#define MAX_NUM_CH_UUIDS        4096

/* Hoisted out of line to reduce kernel stack footprint */
SK_NO_INLINE_ATTRIBUTE
static int
nxctl_get_channel_list(struct nxctl *nxctl, struct sockopt *sopt)
{
	user_addr_t tmp_ptr = USER_ADDR_NULL;
	uint32_t nuuids = 0, ncuuids = 0;
	uuid_t *puuid, *uuids = NULL;
	size_t uuids_sz;
	struct ch_list_req clr;
	struct kern_channel *ch = NULL;
	struct kern_nexus *nx = NULL;
	struct kern_nexus find;
	int err = 0, observeall;

	NXCTL_LOCK_ASSERT_HELD(nxctl);

	ASSERT(sopt->sopt_p != NULL);
	if (sopt->sopt_val == USER_ADDR_NULL) {
		return EINVAL;
	}

	err = sooptcopyin(sopt, &clr, sizeof(clr), sizeof(clr));
	if (err != 0) {
		return err;
	}

	if (uuid_is_null(clr.cl_nx_uuid)) {
		return EINVAL;
	} else if ((size_t)clr.cl_num_ch_uuids > MAX_NUM_CH_UUIDS) {
		clr.cl_num_ch_uuids = MAX_NUM_CH_UUIDS;
	}

	/*
	 * If the caller specified a buffer, copy out the Channel UUIDs to
	 * caller gracefully.  We only copy out the number of UUIDs which
	 * caller has asked for, but we always tell caller how big the
	 * buffer really needs to be.
	 */
	tmp_ptr = clr.cl_ch_uuids;
	if (tmp_ptr != USER_ADDR_NULL && clr.cl_num_ch_uuids > 0) {
		uuids_sz = (size_t)clr.cl_num_ch_uuids * sizeof(uuid_t);
		uuids = sk_alloc_data(uuids_sz, Z_WAITOK, skmem_tag_sysctl_buf);
		if (uuids == NULL) {
			return ENOBUFS;
		}
	}

	observeall = (skywalk_priv_check_cred(sopt->sopt_p, nxctl->nxctl_cred,
	    PRIV_SKYWALK_OBSERVE_ALL) == 0);

	SK_LOCK();
	uuid_copy(find.nx_uuid, clr.cl_nx_uuid);
	nx = RB_FIND(kern_nexus_tree, &nx_head, &find);
	if (nx != NULL && NX_PROV(nx)->nxprov_ctl != nxctl && !observeall) {
		/*
		 * Return only entries that are visible to the caller,
		 * unless it has PRIV_SKYWALK_OBSERVE_ALL.
		 */
		nx = NULL;
	}
	if (nx != NULL) {
		/*
		 * Count number of Channels.  If buffer space exists
		 * and remains, copy out the Channel UUIDs.
		 */
		nuuids = clr.cl_num_ch_uuids;
		puuid = uuids;

		STAILQ_FOREACH(ch, &nx->nx_ch_head, ch_link) {
			++ncuuids;
			if (uuids != NULL && nuuids > 0) {
				uuid_copy(*puuid, ch->ch_info->cinfo_ch_id);
				--nuuids;
				++puuid;
			}
		}
	} else {
		err = ENOENT;
	}
	SK_UNLOCK();

	if (uuids != NULL) {
		if (err == 0 && nx != NULL && tmp_ptr != USER_ADDR_NULL) {
			uintptr_t cnt_uuid;

			/* Note: Pointer arithmetic */
			cnt_uuid = (uintptr_t)(puuid - uuids);
			ASSERT(cnt_uuid > 0);

			if (sopt->sopt_p != kernproc) {
				err = copyout(uuids, tmp_ptr,
				    cnt_uuid * sizeof(uuid_t));
			} else {
				bcopy(uuids, CAST_DOWN(caddr_t, tmp_ptr),
				    cnt_uuid * sizeof(uuid_t));
			}
		}
		sk_free_data(uuids, uuids_sz);
		uuids = NULL;
	}

	if (err == 0) {
		clr.cl_num_ch_uuids = ncuuids;
		err = sooptcopyout(sopt, &clr, sizeof(clr));
	}

	return err;
}

static void
nxctl_init(struct nxctl *nxctl, struct proc *p, struct fileproc *fp)
{
	uuid_t p_uuid;

	bzero(nxctl, sizeof(*nxctl));

	proc_getexecutableuuid(p, p_uuid, sizeof(p_uuid));

	lck_mtx_init(&nxctl->nxctl_lock, &nexus_lock_group, &nexus_lock_attr);
	uuid_copy(nxctl->nxctl_proc_uuid, p_uuid);
	nxctl->nxctl_proc_uniqueid = proc_uniqueid(p);
	nxctl->nxctl_cred = kauth_cred_proc_ref(p);
	nxctl->nxctl_fp = fp;
	if (nxctl == &_kernnxctl) {
		ASSERT(p == kernproc);
		nxctl->nxctl_flags |= NEXUSCTLF_KERNEL;
	}
	if (fp == NULL) {
		nxctl->nxctl_flags |= NEXUSCTLF_NOFDREF;
	}
}

static struct nxctl *
nxctl_alloc(struct proc *p, struct fileproc *fp, zalloc_flags_t how)
{
	struct nxctl *nxctl = zalloc_flags(nxctl_zone, how);

	if (nxctl != NULL) {
		nxctl_init(nxctl, p, fp);
	}
	return nxctl;
}

static void
nxctl_free(struct nxctl *nxctl)
{
	ASSERT(nxctl->nxctl_refcnt == 0);
	ASSERT(!(nxctl->nxctl_flags & NEXUSCTLF_ATTACHED));
	kauth_cred_unref(&nxctl->nxctl_cred);
	lck_mtx_destroy(&nxctl->nxctl_lock, &nexus_lock_group);
	SK_D("nxctl 0x%llx FREE", SK_KVA(nxctl));
	if (!(nxctl->nxctl_flags & NEXUSCTLF_KERNEL)) {
		zfree(nxctl_zone, nxctl);
	}
}

static void
nxctl_retain_locked(struct nxctl *nxctl)
{
	SK_LOCK_ASSERT_HELD();

	nxctl->nxctl_refcnt++;
	ASSERT(nxctl->nxctl_refcnt != 0);
}

void
nxctl_retain(struct nxctl *nxctl)
{
	SK_LOCK();
	nxctl_retain_locked(nxctl);
	SK_UNLOCK();
}

static int
nxctl_release_locked(struct nxctl *nxctl)
{
	int oldref = nxctl->nxctl_refcnt;

	SK_LOCK_ASSERT_HELD();

	ASSERT(nxctl->nxctl_refcnt != 0);
	if (--nxctl->nxctl_refcnt == 0) {
		nxctl_free(nxctl);
	}

	return oldref == 1;
}

int
nxctl_release(struct nxctl *nxctl)
{
	int lastref;

	SK_LOCK();
	lastref = nxctl_release_locked(nxctl);
	SK_UNLOCK();

	return lastref;
}

void
nxctl_dtor(void *arg)
{
	struct nxctl *nxctl = arg;

	nxctl_close(nxctl);
	SK_LOCK();
	(void) nxctl_release_locked(nxctl);
	SK_UNLOCK();
}

int
nxprov_advise_connect(struct kern_nexus *nx, struct kern_channel *ch,
    struct proc *p)
{
	struct kern_nexus_provider *nxprov = NX_PROV(nx);
	int err = 0;

	ASSERT(!(ch->ch_flags & (CHANF_EXT_PRECONNECT | CHANF_EXT_CONNECTED)));
	ASSERT(ch->ch_ctx == NULL);

	SK_LOCK_ASSERT_HELD();
	LCK_MTX_ASSERT(&ch->ch_lock, LCK_MTX_ASSERT_OWNED);

	/* monitor channels aren't externally visible/usable, so ignore */
	if ((ch->ch_info->cinfo_ch_mode & CHMODE_MONITOR) ||
	    (ch->ch_flags & CHANF_EXT_SKIP) ||
	    (nxprov->nxprov_ext.nxpi_pre_connect == NULL ||
	    nxprov->nxprov_ext.nxpi_connected == NULL)) {
		return 0;
	}

	ch_retain_locked(ch);
	lck_mtx_unlock(&ch->ch_lock);
	SK_UNLOCK();
	lck_mtx_lock(&ch->ch_lock);

	err = nxprov->nxprov_ext.nxpi_pre_connect(nxprov, p, nx,
	    ch->ch_info->cinfo_nx_port, ch, &ch->ch_ctx);
	if (err != 0) {
		SK_D("ch 0x%llx flags %b nx 0x%llx pre_connect "
		    "error %d", SK_KVA(ch), ch->ch_flags,
		    CHANF_BITS, SK_KVA(nx), err);
		ch->ch_ctx = NULL;
		goto done;
	}
	/*
	 * Upon ring/slot init failure, this is cleared
	 * by nxprov_advise_disconnect() below.
	 */
	atomic_bitset_32(&ch->ch_flags, CHANF_EXT_PRECONNECT);
	if (NXPROV_LLINK(nxprov)) {
		err = nx_netif_llink_ext_init_default_queues(nx);
	} else {
		err = nx_init_rings(nx, ch);
	}
	if (err != 0) {
		goto done;
	}
	ASSERT(err == 0);
	ASSERT((ch->ch_flags & (CHANF_EXT_PRECONNECT |
	    CHANF_EXT_CONNECTED)) == CHANF_EXT_PRECONNECT);

	err = nxprov->nxprov_ext.nxpi_connected(nxprov, nx, ch);
	if (err != 0) {
		SK_D("ch 0x%llx flags %b nx 0x%llx connected error %d",
		    SK_KVA(ch), ch->ch_flags, CHANF_BITS, SK_KVA(nx), err);
		goto done;
	}
	atomic_bitset_32(&ch->ch_flags, CHANF_EXT_CONNECTED);
	SK_D("ch 0x%llx flags %b nx 0x%llx connected",
	    SK_KVA(ch), ch->ch_flags, CHANF_BITS, SK_KVA(nx));


done:
	lck_mtx_unlock(&ch->ch_lock);
	SK_LOCK();
	lck_mtx_lock(&ch->ch_lock);
	if ((err != 0) &&
	    (ch->ch_flags & (CHANF_EXT_CONNECTED | CHANF_EXT_PRECONNECT))) {
		nxprov_advise_disconnect(nx, ch);
	}
	/* caller is expected to hold one, in addition to ourselves */
	VERIFY(ch->ch_refcnt >= 2);
	ch_release_locked(ch);

	return err;
}

void
nxprov_advise_disconnect(struct kern_nexus *nx, struct kern_channel *ch)
{
	struct kern_nexus_provider *nxprov = NX_PROV(nx);

	SK_LOCK_ASSERT_HELD();
	LCK_MTX_ASSERT(&ch->ch_lock, LCK_MTX_ASSERT_OWNED);

	/* check as we might be called in the error handling path */
	if (ch->ch_flags & (CHANF_EXT_CONNECTED | CHANF_EXT_PRECONNECT)) {
		ch_retain_locked(ch);
		lck_mtx_unlock(&ch->ch_lock);
		SK_UNLOCK();
		lck_mtx_lock(&ch->ch_lock);

		ASSERT(!(ch->ch_flags & CHANF_EXT_SKIP));
		if (ch->ch_flags & CHANF_EXT_CONNECTED) {
			nxprov->nxprov_ext.nxpi_pre_disconnect(nxprov, nx, ch);
			atomic_bitclear_32(&ch->ch_flags, CHANF_EXT_CONNECTED);
		}

		/*
		 * Inform the external domain provider that the rings
		 * and slots for this channel are no longer valid.
		 */
		if (NXPROV_LLINK(nxprov)) {
			nx_netif_llink_ext_fini_default_queues(nx);
		} else {
			nx_fini_rings(nx, ch);
		}

		ASSERT(ch->ch_flags & CHANF_EXT_PRECONNECT);
		nxprov->nxprov_ext.nxpi_disconnected(nxprov, nx, ch);
		atomic_bitclear_32(&ch->ch_flags, CHANF_EXT_PRECONNECT);

		SK_D("ch 0x%llx flags %b nx 0x%llx disconnected",
		    SK_KVA(ch), ch->ch_flags, CHANF_BITS, SK_KVA(nx));

		/* We're done with this channel */
		ch->ch_ctx = NULL;

		lck_mtx_unlock(&ch->ch_lock);
		SK_LOCK();
		lck_mtx_lock(&ch->ch_lock);
		/* caller is expected to hold one, in addition to ourselves */
		VERIFY(ch->ch_refcnt >= 2);
		ch_release_locked(ch);
	}
	ASSERT(!(ch->ch_flags & (CHANF_EXT_CONNECTED | CHANF_EXT_PRECONNECT)));
	ASSERT(ch->ch_ctx == NULL);
}

static struct kern_nexus_provider *
nxprov_create_common(struct nxctl *nxctl,
    struct kern_nexus_domain_provider *nxdom_prov, struct nxprov_reg *reg,
    const struct kern_nexus_provider_init *init, int *err)
{
	struct skmem_region_params srp[SKMEM_REGIONS];
	struct kern_nexus_provider *nxprov = NULL;
	struct skmem_region_params *bsrp;
	struct nxprov_params nxp;
	uint32_t override = 0;
	int i;

	_CASSERT(sizeof(*init) == sizeof(nxprov->nxprov_ext));
	_CASSERT(sizeof(*init) >=
	    sizeof(struct kern_nexus_netif_provider_init));

	SK_LOCK_ASSERT_HELD();
	ASSERT(nxctl != NULL && reg != NULL && nxdom_prov != NULL);

	/* process and validate provider parameters */
	if ((*err = nxdom_prov_validate_params(nxdom_prov, reg,
	    &nxp, srp, override)) != 0) {
		goto done;
	}

	nxprov = nxprov_alloc(nxdom_prov, Z_WAITOK);
	ASSERT(nxprov->nxprov_dom_prov == nxdom_prov);

	STAILQ_INIT(&nxprov->nxprov_nx_head);
	STAILQ_INSERT_TAIL(&nxprov_head, nxprov, nxprov_link);
	nxprov->nxprov_flags |= NXPROVF_ATTACHED;
	nxprov->nxprov_ctl = nxctl;
	uuid_generate_random(nxprov->nxprov_uuid);
	bcopy(&nxp, nxprov->nxprov_params, sizeof(struct nxprov_params));

	if (init != NULL) {
		if (init->nxpi_version == KERN_NEXUS_PROVIDER_VERSION_NETIF) {
			ASSERT(NXPROV_LLINK(nxprov));
			bcopy(init, &nxprov->nxprov_netif_ext,
			    sizeof(nxprov->nxprov_netif_ext));
		} else {
			ASSERT(!NXPROV_LLINK(nxprov));
			ASSERT(init->nxpi_version ==
			    KERN_NEXUS_PROVIDER_CURRENT_VERSION);
			bcopy(init, &nxprov->nxprov_ext, sizeof(*init));
		}
		nxprov->nxprov_flags |= NXPROVF_EXTERNAL;
	}

	/* store validated region parameters to the provider */
	for (i = 0; i < SKMEM_REGIONS; i++) {
		nxprov->nxprov_region_params[i] = srp[i];
	}

	bsrp = &nxprov->nxprov_region_params[SKMEM_REGION_BUF];
	/*
	 * Special handling for external nexus providers; similar
	 * logic to what's done in kern_pbufpool_create().
	 */
	if (nxprov->nxprov_flags & NXPROVF_EXTERNAL) {
		uint32_t nxpi_flags = nxprov->nxprov_ext.nxpi_flags;
		/*
		 * Set SKMEM_REGION_CR_MONOLITHIC if the provider does
		 * not want more than a single segment for entire region.
		 */
		if (nxpi_flags & NXPIF_MONOLITHIC) {
			bsrp->srp_cflags |= SKMEM_REGION_CR_MONOLITHIC;
		} else {
			bsrp->srp_cflags &= ~SKMEM_REGION_CR_MONOLITHIC;
		}

		if (nxpi_flags & NXPIF_INHIBIT_CACHE) {
			bsrp->srp_cflags |= SKMEM_REGION_CR_NOCACHE;
		} else {
			bsrp->srp_cflags &= ~SKMEM_REGION_CR_NOCACHE;
		}

		/* recalculate what's done by nxprov_params_adjust() earlier */
		skmem_region_params_config(bsrp);

		if (nxpi_flags & NXPIF_VIRTUAL_DEVICE) {
			nxprov->nxprov_flags |= NXPROVF_VIRTUAL_DEVICE;
		}
	} else if (nxdom_prov->nxdom_prov_dom->nxdom_type !=
	    NEXUS_TYPE_NET_IF) {
		/*
		 * Treat non-netif built-in nexus providers as those
		 * meant for inter-process communications, i.e. there
		 * is no actual networking hardware involved.
		 */
		nxprov->nxprov_flags |= NXPROVF_VIRTUAL_DEVICE;
	}

	if (nxdom_prov->nxdom_prov_dom->nxdom_type == NEXUS_TYPE_NET_IF) {
		struct skmem_region_params *kmd_srp =
		    &nxprov->nxprov_region_params[SKMEM_REGION_KMD];
		struct skmem_region_params *umd_srp =
		    &nxprov->nxprov_region_params[SKMEM_REGION_UMD];

		kmd_srp->srp_cflags |= SKMEM_REGION_CR_PERSISTENT;
		umd_srp->srp_cflags |= SKMEM_REGION_CR_PERSISTENT;
		skmem_region_params_config(kmd_srp);
		skmem_region_params_config(umd_srp);
	}

	nxprov_retain_locked(nxprov);   /* one for being in the list */
	nxprov_retain_locked(nxprov);   /* one for the caller */

#if SK_LOG
	uuid_string_t uuidstr;
	SK_D("nxprov 0x%llx UUID %s", SK_KVA(nxprov),
	    sk_uuid_unparse(nxprov->nxprov_uuid, uuidstr));
#endif /* SK_LOG */

done:
	return nxprov;
}

struct kern_nexus_provider *
nxprov_create(struct proc *p, struct nxctl *nxctl, struct nxprov_reg *reg,
    int *err)
{
	struct nxprov_params *nxp = &reg->nxpreg_params;
	struct kern_nexus_domain_provider *nxdom_prov = NULL;
	struct kern_nexus_provider *nxprov = NULL;

	NXCTL_LOCK_ASSERT_HELD(nxctl);

	ASSERT(nxctl->nxctl_cred != proc_ucred(kernproc));
	*err = 0;

	switch (nxp->nxp_type) {
	case NEXUS_TYPE_USER_PIPE:      /* only for userland */
		*err = skywalk_priv_check_cred(p, nxctl->nxctl_cred,
		    PRIV_SKYWALK_REGISTER_USER_PIPE);
		break;

	case NEXUS_TYPE_FLOW_SWITCH:    /* allowed for userland */
		*err = skywalk_priv_check_cred(p, nxctl->nxctl_cred,
		    PRIV_SKYWALK_REGISTER_FLOW_SWITCH);
		break;

	case NEXUS_TYPE_NET_IF:         /* allowed for userland */
		*err = skywalk_priv_check_cred(p, nxctl->nxctl_cred,
		    PRIV_SKYWALK_REGISTER_NET_IF);
		break;

	case NEXUS_TYPE_KERNEL_PIPE:    /* only for kernel */
	case NEXUS_TYPE_MONITOR:        /* invalid */
	default:
		*err = EINVAL;
		goto done;
	}

	if (*err != 0) {
		goto done;
	}

	ASSERT(nxp->nxp_type < NEXUS_TYPE_MAX);
	if ((nxdom_prov = nxdom_prov_default[nxp->nxp_type]) == NULL) {
		*err = ENXIO;
		goto done;
	}

#if CONFIG_NEXUS_NETIF
	/* make sure netif_compat is the default here */
	ASSERT(nxp->nxp_type != NEXUS_TYPE_NET_IF ||
	    strcmp(nxdom_prov->nxdom_prov_name,
	    NEXUS_PROVIDER_NET_IF_COMPAT) == 0);
#endif /* CONFIG_NEXUS_NETIF */

	SK_LOCK();
	/* callee holds a reference for our caller upon success */
	nxprov = nxprov_create_common(nxctl, nxdom_prov, reg, NULL, err);
	SK_UNLOCK();
done:
	return nxprov;
}

struct kern_nexus_provider *
nxprov_create_kern(struct nxctl *nxctl,
    struct kern_nexus_domain_provider *nxdom_prov, struct nxprov_reg *reg,
    const struct kern_nexus_provider_init *init, int *err)
{
	struct nxprov_params *nxp = &reg->nxpreg_params;
	struct kern_nexus_provider *nxprov = NULL;

	NXCTL_LOCK_ASSERT_HELD(nxctl);
	SK_LOCK_ASSERT_HELD();

	ASSERT(nxctl->nxctl_cred == proc_ucred(kernproc));
	ASSERT(nxp->nxp_type == nxdom_prov->nxdom_prov_dom->nxdom_type);
	ASSERT(init == NULL ||
	    init->nxpi_version == KERN_NEXUS_PROVIDER_CURRENT_VERSION ||
	    init->nxpi_version == KERN_NEXUS_PROVIDER_VERSION_NETIF);

	*err = 0;

	switch (nxp->nxp_type) {
	case NEXUS_TYPE_NET_IF:
		break;
	case NEXUS_TYPE_KERNEL_PIPE:
		if (init == NULL) {
			*err = EINVAL;
			goto done;
		}
		break;
	case NEXUS_TYPE_FLOW_SWITCH:
		if (init != NULL) {
			*err = EINVAL;
			goto done;
		}
		break;

	case NEXUS_TYPE_USER_PIPE:      /* only for userland */
	case NEXUS_TYPE_MONITOR:        /* invalid */
	default:
		*err = EINVAL;
		goto done;
	}

	/* callee holds a reference for our caller upon success */
	nxprov = nxprov_create_common(nxctl, nxdom_prov, reg, init, err);

done:
	return nxprov;
}

int
nxprov_destroy(struct nxctl *nxctl, const uuid_t nxprov_uuid)
{
	struct kern_nexus_provider *nxprov = NULL;
	int err = 0;

	NXCTL_LOCK_ASSERT_HELD(nxctl);

	SK_LOCK();

	STAILQ_FOREACH(nxprov, &nxprov_head, nxprov_link) {
		if (nxctl == nxprov->nxprov_ctl &&
		    uuid_compare(nxprov_uuid, nxprov->nxprov_uuid) == 0) {
			nxprov_retain_locked(nxprov);
			break;
		}
	}

	if (nxprov == NULL) {
		err = ENOENT;
	} else {
		err = nxprov_close(nxprov, TRUE);
	}

	if (nxprov != NULL) {
		(void) nxprov_release_locked(nxprov);
	}

	SK_UNLOCK();

	return err;
}

int
nxprov_close(struct kern_nexus_provider *nxprov, boolean_t locked)
{
	int err = 0;

	if (!locked) {
		SK_LOCK();
	}

	SK_LOCK_ASSERT_HELD();

#if SK_LOG
	uuid_string_t uuidstr;
	SK_D("nxprov 0x%llx UUID %s flags 0x%b", SK_KVA(nxprov),
	    sk_uuid_unparse(nxprov->nxprov_uuid, uuidstr),
	    nxprov->nxprov_flags, NXPROVF_BITS);
#endif /* SK_LOG */

	if (nxprov->nxprov_flags & NXPROVF_CLOSED) {
		err = EALREADY;
	} else {
		struct kern_nexus *nx, *tnx;

		nxprov->nxprov_ctl = NULL;

		STAILQ_FOREACH_SAFE(nx, &nxprov->nxprov_nx_head,
		    nx_prov_link, tnx) {
			nx_retain_locked(nx);
			(void) nx_close(nx, TRUE);
			(void) nx_release_locked(nx);
		}

		if (STAILQ_EMPTY(&nxprov->nxprov_nx_head)) {
			/* no nexus created on this, so detach now */
			nxprov_detach(nxprov, TRUE);
		} else {
			/* detach when last nexus is destroyed */
			ASSERT(nxprov->nxprov_refcnt > 1);
			nxprov->nxprov_flags |= NXPROVF_CLOSED;
		}
	}

	if (!locked) {
		SK_UNLOCK();
	}

	return err;
}

static void
nxprov_detach(struct kern_nexus_provider *nxprov, boolean_t locked)
{
	if (!locked) {
		SK_LOCK();
	}

	SK_LOCK_ASSERT_HELD();

#if SK_LOG
	uuid_string_t uuidstr;
	SK_D("nxprov 0x%llx UUID %s flags 0x%b", SK_KVA(nxprov),
	    sk_uuid_unparse(nxprov->nxprov_uuid, uuidstr),
	    nxprov->nxprov_flags, NXPROVF_BITS);
#endif /* SK_LOG */

	ASSERT(nxprov->nxprov_flags & NXPROVF_ATTACHED);
	STAILQ_REMOVE(&nxprov_head, nxprov, kern_nexus_provider, nxprov_link);
	nxprov->nxprov_flags &= ~NXPROVF_ATTACHED;

	/* caller must hold an extra ref */
	ASSERT(nxprov->nxprov_refcnt > 1);
	(void) nxprov_release_locked(nxprov);

	if (!locked) {
		SK_UNLOCK();
	}
}

static struct kern_nexus_provider *
nxprov_alloc(struct kern_nexus_domain_provider *nxdom_prov, zalloc_flags_t how)
{
	struct kern_nexus_provider *nxprov;
	struct nxprov_params *nxp;

	ASSERT(nxdom_prov != NULL);

	nxp = nxprov_params_alloc(how);
	if (nxp == NULL) {
		SK_ERR("Failed to allocate nxprov_params");
		return NULL;
	}

	nxprov = zalloc_flags(nxprov_zone, how | Z_ZERO);
	if (nxprov == NULL) {
		SK_ERR("Failed to allocate nxprov");
		nxprov_params_free(nxp);
		return NULL;
	}

	nxprov->nxprov_dom_prov = nxdom_prov;
	nxprov->nxprov_params = nxp;
	/* hold a reference for nxprov */
	nxdom_prov_retain_locked(nxdom_prov);

	return nxprov;
}

static void
nxprov_free(struct kern_nexus_provider *nxprov)
{
	struct kern_nexus_domain_provider *nxdom_prov =
	    nxprov->nxprov_dom_prov;

	SK_LOCK_ASSERT_HELD();

	ASSERT(nxdom_prov != NULL);
	(void) nxdom_prov_release_locked(nxdom_prov);
	nxprov->nxprov_dom_prov = NULL;
	ASSERT(nxprov->nxprov_params != NULL);
	nxprov_params_free(nxprov->nxprov_params);
	nxprov->nxprov_params = NULL;
	ASSERT(!(nxprov->nxprov_flags & NXPROVF_ATTACHED));
	SK_DF(SK_VERB_MEM, "nxprov 0x%llx FREE", SK_KVA(nxprov));
	zfree(nxprov_zone, nxprov);
}

static void
nxprov_retain_locked(struct kern_nexus_provider *nxprov)
{
	SK_LOCK_ASSERT_HELD();

	nxprov->nxprov_refcnt++;
	ASSERT(nxprov->nxprov_refcnt != 0);
}

void
nxprov_retain(struct kern_nexus_provider *nxprov)
{
	SK_LOCK();
	nxprov_retain_locked(nxprov);
	SK_UNLOCK();
}

static int
nxprov_release_locked(struct kern_nexus_provider *nxprov)
{
	int oldref = nxprov->nxprov_refcnt;

	SK_LOCK_ASSERT_HELD();

	ASSERT(nxprov->nxprov_refcnt != 0);
	if (--nxprov->nxprov_refcnt == 0) {
		nxprov_free(nxprov);
	}

	return oldref == 1;
}

int
nxprov_release(struct kern_nexus_provider *nxprov)
{
	int lastref;

	SK_LOCK();
	lastref = nxprov_release_locked(nxprov);
	SK_UNLOCK();

	return lastref;
}

struct nxprov_params *
nxprov_params_alloc(zalloc_flags_t how)
{
	return zalloc_flags(nxprov_params_zone, how | Z_ZERO);
}

void
nxprov_params_free(struct nxprov_params *nxp)
{
	SK_DF(SK_VERB_MEM, "nxp 0x%llx FREE", SK_KVA(nxp));
	zfree(nxprov_params_zone, nxp);
}

static int
nx_check_pp(struct kern_nexus_provider *nxprov, struct kern_pbufpool *pp)
{
	struct kern_nexus_domain_provider *nxdom_prov = nxprov->nxprov_dom_prov;

	if ((pp->pp_flags & (PPF_EXTERNAL | PPF_CLOSED)) != PPF_EXTERNAL) {
		SK_ERR("Rejecting \"%s\" built-in pp", pp->pp_name);
		return ENOTSUP;
	}

	/*
	 * Require that the nexus domain metadata type and the
	 * metadata type of the caller-provided pbufpool match.
	 */
	if (nxdom_prov->nxdom_prov_dom->nxdom_md_type !=
	    pp->pp_md_type ||
	    nxdom_prov->nxdom_prov_dom->nxdom_md_subtype !=
	    pp->pp_md_subtype) {
		SK_ERR("Mismatch in metadata type/subtype "
		    "(%u/%u != %u/%u)", pp->pp_md_type,
		    nxdom_prov->nxdom_prov_dom->nxdom_md_type,
		    pp->pp_md_subtype,
		    nxdom_prov->nxdom_prov_dom->nxdom_md_subtype);
		return EINVAL;
	}

	/*
	 * Require that the nexus provider memory configuration
	 * has the same impedance as the caller-provided one.
	 * Both need to be lacking or present; if one of them
	 * is set and the other isn't, then we bail.
	 */
	if (!!(pp->pp_buf_region->skr_mode & SKR_MODE_MONOLITHIC) ^
	    !!(nxprov->nxprov_ext.nxpi_flags & NXPIF_MONOLITHIC)) {
		SK_ERR("Memory config mismatch: monolithic mode");
		return EINVAL;
	}

	return 0;
}

struct kern_nexus *
nx_create(struct nxctl *nxctl, const uuid_t nxprov_uuid,
    const nexus_type_t dom_type, const void *nx_ctx,
    nexus_ctx_release_fn_t nx_ctx_release, struct kern_pbufpool *tx_pp,
    struct kern_pbufpool *rx_pp, int *err)
{
	struct kern_nexus_domain_provider *nxdom_prov;
	struct kern_nexus_provider *nxprov = NULL;
	struct kern_nexus *nx = NULL;
#if SK_LOG
	uuid_string_t uuidstr;
#endif /* SK_LOG */

	NXCTL_LOCK_ASSERT_HELD(nxctl);

	ASSERT(dom_type < NEXUS_TYPE_MAX);
	ASSERT(!uuid_is_null(nxprov_uuid));
	*err = 0;

	SK_LOCK();

	STAILQ_FOREACH(nxprov, &nxprov_head, nxprov_link) {
		if (nxctl == nxprov->nxprov_ctl &&
		    uuid_compare(nxprov_uuid, nxprov->nxprov_uuid) == 0) {
			break;
		}
	}

	if (nxprov == NULL || (nxprov->nxprov_flags & NXPROVF_CLOSED)) {
		SK_ERR("Provider not found or has been closed");
		*err = ENOENT;
		goto done;
	}

	nxdom_prov = nxprov->nxprov_dom_prov;
	if (dom_type != NEXUS_TYPE_UNDEFINED &&
	    (nxdom_prov->nxdom_prov_dom->nxdom_type != dom_type)) {
		SK_ERR("Mismatch in domain type (0x%u != 0x%u)",
		    dom_type, nxdom_prov->nxdom_prov_dom->nxdom_type);
		nxdom_prov = NULL;
		nxprov = NULL;
		*err = ENODEV;
		goto done;
	}

	if ((dom_type == NEXUS_TYPE_NET_IF) && NXPROV_LLINK(nxprov) &&
	    (!tx_pp || !rx_pp)) {
#if SK_LOG
		SK_ERR("TX/RX packet pool is required for netif logical link "
		    "nexus provider UUID: %s",
		    sk_uuid_unparse(nxprov_uuid, uuidstr));
#endif /* SK_LOG */
		nxdom_prov = NULL;
		nxprov = NULL;
		*err = EINVAL;
		goto done;
	}

	if ((tx_pp != NULL && (*err = nx_check_pp(nxprov, tx_pp)) != 0) ||
	    (rx_pp != NULL && (*err = nx_check_pp(nxprov, rx_pp)) != 0)) {
		goto done;
	}

	nx = nx_alloc(Z_WAITOK);

	STAILQ_INIT(&nx->nx_ch_head);
	STAILQ_INIT(&nx->nx_ch_nonxref_head);
	lck_rw_init(&nx->nx_ch_if_adv_lock, &nexus_lock_group,
	    &nexus_lock_attr);
	STAILQ_INIT(&nx->nx_ch_if_adv_head);
	uuid_generate_random(nx->nx_uuid);
	nx->nx_prov = nxprov;
	nx->nx_ctx = (void *)(uintptr_t)nx_ctx;
	nx->nx_ctx_release = nx_ctx_release;
	nx->nx_id = nxdom_prov->nxdom_prov_gencnt++;

	if (tx_pp != NULL) {
		nx->nx_tx_pp = tx_pp;
		pp_retain(tx_pp);       /* released by nx_free */
	}

	if (rx_pp != NULL) {
		nx->nx_rx_pp = rx_pp;
		pp_retain(rx_pp);       /* released by nx_free */
	}

	/* this nexus is alive; tell the nexus constructor to set it up */
	if (nxprov->nxprov_dom_prov->nxdom_prov_nx_ctor != NULL) {
		*err = nxprov->nxprov_dom_prov->nxdom_prov_nx_ctor(nx);
		if (*err != 0) {
			nx->nx_prov = NULL;
			goto done;
		}
	}

	nxprov_retain_locked(nxprov);   /* hold a ref on the nexus reg */

	STAILQ_INSERT_TAIL(&nxprov->nxprov_nx_head, nx, nx_prov_link);
	nxprov->nxprov_nx_count++;
	RB_INSERT(kern_nexus_tree, &nx_head, nx);
	atomic_bitset_32(&nx->nx_flags, NXF_ATTACHED);

	nx_retain_locked(nx);   /* one for the provider list */
	nx_retain_locked(nx);   /* one for the global list */
	nx_retain_locked(nx);   /* one for the caller */

#if SK_LOG
	SK_D("nexus 0x%llx (%s:%s) UUID %s", SK_KVA(nx),
	    nxdom_prov->nxdom_prov_dom->nxdom_name,
	    nxdom_prov->nxdom_prov_name, sk_uuid_unparse(nx->nx_uuid, uuidstr));
#endif /* SK_LOG */
done:
	SK_UNLOCK();

	if (*err != 0) {
		if (nx != NULL) {
			nx_free(nx);
			nx = NULL;
		}
	}
	return nx;
}

int
nx_destroy(struct nxctl *nxctl, const uuid_t nx_uuid)
{
	struct kern_nexus *nx = NULL;
	struct kern_nexus find;
	int err = 0;

	NXCTL_LOCK_ASSERT_HELD(nxctl);

	SK_LOCK();

	uuid_copy(find.nx_uuid, nx_uuid);
	nx = RB_FIND(kern_nexus_tree, &nx_head, &find);
	if (nx != NULL && nxctl != NX_PROV(nx)->nxprov_ctl) {
		nx = NULL;
	}

	if (nx != NULL) {
		nx_retain_locked(nx);
	}

	if (nx == NULL) {
		err = ENOENT;
	} else {
		err = nx_close(nx, TRUE);
		(void) nx_release_locked(nx);
	}

	SK_UNLOCK();

	return err;
}

static inline int
nx_cmp(const struct kern_nexus *a, const struct kern_nexus *b)
{
	return uuid_compare(a->nx_uuid, b->nx_uuid);
}

struct kern_nexus *
nx_find(const uuid_t nx_uuid, boolean_t locked)
{
	struct kern_nexus *nx = NULL;
	struct kern_nexus find;

	if (!locked) {
		SK_LOCK();
	}

	SK_LOCK_ASSERT_HELD();

	uuid_copy(find.nx_uuid, nx_uuid);
	nx = RB_FIND(kern_nexus_tree, &nx_head, &find);
	if (nx != NULL && (nx->nx_flags & NXF_CLOSED)) {
		nx = NULL;
	}

	/* return reference to caller */
	if (nx != NULL) {
		nx_retain_locked(nx);
	}

	if (!locked) {
		SK_UNLOCK();
	}

	return nx;
}

int
nx_close(struct kern_nexus *nx, boolean_t locked)
{
	int err = 0;

	if (!locked) {
		SK_LOCK();
	}

	SK_LOCK_ASSERT_HELD();


	if (nx->nx_flags & NXF_CLOSED) {
		err = EALREADY;
	} else {
#if SK_LOG
		uuid_string_t uuidstr;
		SK_D("nexus 0x%llx (%s:%s) UUID %s flags 0x%b", SK_KVA(nx),
		    NX_DOM(nx)->nxdom_name, NX_DOM_PROV(nx)->nxdom_prov_name,
		    sk_uuid_unparse(nx->nx_uuid, uuidstr), nx->nx_flags,
		    NXF_BITS);
#endif /* SK_LOG */

		if (STAILQ_EMPTY(&nx->nx_ch_head)) {
			/* no regular channels open to it, so detach now */
			nx_detach(nx);
		} else {
			/* detach when the last channel closes */
			ASSERT(nx->nx_refcnt > 3);
			atomic_bitset_32(&nx->nx_flags, NXF_CLOSED);
		}
	}

	if (!locked) {
		SK_UNLOCK();
	}

	return err;
}

void
nx_stop(struct kern_nexus *nx)
{
	struct kern_nexus_provider *nxprov = nx->nx_prov;

	SK_LOCK_ASSERT_HELD();

	/* send a stop message */
	if (nxprov->nxprov_dom_prov->nxdom_prov_nx_stop != NULL) {
		nxprov->nxprov_dom_prov->nxdom_prov_nx_stop(nx);
	}
}

void
nx_detach(struct kern_nexus *nx)
{
	struct kern_nexus_provider *nxprov = nx->nx_prov;

	SK_LOCK_ASSERT_HELD();

#if SK_LOG
	uuid_string_t uuidstr;
	SK_D("nexus 0x%llx UUID %s flags 0x%b", SK_KVA(nx),
	    sk_uuid_unparse(nx->nx_uuid, uuidstr), nx->nx_flags, NXF_BITS);
#endif /* SK_LOG */

	/* Caller must hold extra refs, on top of the two in reg/global lists */
	ASSERT(nx->nx_refcnt >= 3);
	ASSERT(nx->nx_flags & NXF_ATTACHED);

	/* this nexus is done; let the nexus destructor do final cleanups */
	if (nxprov->nxprov_dom_prov->nxdom_prov_nx_dtor != NULL) {
		nxprov->nxprov_dom_prov->nxdom_prov_nx_dtor(nx);
	}

	ASSERT(STAILQ_EMPTY(&nx->nx_ch_head));
	ASSERT(STAILQ_EMPTY(&nx->nx_ch_nonxref_head));

	STAILQ_REMOVE(&nxprov->nxprov_nx_head, nx, kern_nexus, nx_prov_link);
	nxprov->nxprov_nx_count--;
	RB_REMOVE(kern_nexus_tree, &nx_head, nx);
	atomic_bitclear_32(&nx->nx_flags, NXF_ATTACHED);
	nx->nx_prov = NULL;
	if (nx->nx_ctx_release != NULL) {
		nx->nx_ctx_release(nx->nx_ctx);
	}
	nx->nx_ctx = NULL;

	(void) nx_release_locked(nx);   /* one for the reg list */
	(void) nx_release_locked(nx);   /* one for the global list */

	/*
	 * If this was the last nexus and the provider has been closed,
	 * detach the provider and and finish up the postponed job.
	 */
	if (STAILQ_EMPTY(&nxprov->nxprov_nx_head) &&
	    (nxprov->nxprov_flags & NXPROVF_CLOSED)) {
		nxprov_detach(nxprov, TRUE);
	}
	(void) nxprov_release_locked(nxprov);
}

int
nx_advisory_alloc(struct kern_nexus *nx, const char *name,
    struct skmem_region_params *srp_nexusadv, nexus_advisory_type_t type)
{
	struct __kern_nexus_adv_metadata *adv_md;

	_CASSERT(sizeof(struct __kern_nexus_adv_metadata) == sizeof(uint64_t));
	_CASSERT((sizeof(struct sk_nexusadv) +
	    sizeof(struct __kern_nexus_adv_metadata)) <= NX_NEXUSADV_MAX_SZ);
	_CASSERT((sizeof(struct netif_nexus_advisory) +
	    sizeof(struct __kern_nexus_adv_metadata)) <= NX_NEXUSADV_MAX_SZ);
	ASSERT(nx->nx_adv.nxv_reg == NULL);
	ASSERT(nx->nx_adv.nxv_adv == NULL);
	ASSERT(type == NEXUS_ADVISORY_TYPE_FLOWSWITCH ||
	    type == NEXUS_ADVISORY_TYPE_NETIF);

	if ((nx->nx_adv.nxv_reg = skmem_region_create(name, srp_nexusadv,
	    NULL, NULL, NULL)) == NULL) {
		return ENOMEM;
	}

	nx->nx_adv.nxv_adv = skmem_region_alloc(nx->nx_adv.nxv_reg, NULL,
	    NULL, NULL, (SKMEM_NOSLEEP | SKMEM_PANIC));
	adv_md = nx->nx_adv.nxv_adv;
	adv_md->knam_version = NX_ADVISORY_MD_CURRENT_VERSION;
	adv_md->knam_type = type;
	adv_md->__reserved = 0;
	nx->nx_adv.nxv_adv_type = type;
	nx->nx_adv.flowswitch_nxv_adv = (void *)(adv_md + 1);
	if (type == NEXUS_ADVISORY_TYPE_FLOWSWITCH) {
		nx->nx_adv.flowswitch_nxv_adv->nxadv_ver =
		    NX_FLOWSWITCH_ADVISORY_CURRENT_VERSION;
	} else {
		nx->nx_adv.netif_nxv_adv->nna_version =
		    NX_NETIF_ADVISORY_CURRENT_VERSION;
	}
	return 0;
}

void
nx_advisory_free(struct kern_nexus *nx)
{
	if (nx->nx_adv.nxv_reg != NULL) {
		ASSERT(nx->nx_adv.nxv_adv != NULL);
		skmem_region_free(nx->nx_adv.nxv_reg,
		    nx->nx_adv.nxv_adv, NULL);
		nx->nx_adv.nxv_adv = NULL;
		nx->nx_adv.nxv_adv_type = NEXUS_ADVISORY_TYPE_INVALID;
		nx->nx_adv.flowswitch_nxv_adv = NULL;
		skmem_region_release(nx->nx_adv.nxv_reg);
		nx->nx_adv.nxv_reg = NULL;
	}

	ASSERT(nx->nx_adv.nxv_reg == NULL);
	ASSERT(nx->nx_adv.nxv_adv == NULL);
	ASSERT(nx->nx_adv.nxv_adv_type == NEXUS_ADVISORY_TYPE_INVALID);
	ASSERT(nx->nx_adv.flowswitch_nxv_adv == NULL);
}

static struct kern_nexus *
nx_alloc(zalloc_flags_t how)
{
	SK_LOCK_ASSERT_HELD();

	return zalloc_flags(nx_zone, how | Z_ZERO);
}

static void
nx_free(struct kern_nexus *nx)
{
	ASSERT(!(nx->nx_flags & NXF_ATTACHED) && nx->nx_prov == NULL);
	ASSERT(STAILQ_EMPTY(&nx->nx_ch_head));
	ASSERT(STAILQ_EMPTY(&nx->nx_ch_nonxref_head));

	nx_port_free_all(nx);

	if (nx->nx_tx_pp != NULL) {
		pp_release(nx->nx_tx_pp);
		nx->nx_tx_pp = NULL;
	}
	if (nx->nx_rx_pp != NULL) {
		pp_release(nx->nx_rx_pp);
		nx->nx_rx_pp = NULL;
	}

	ASSERT(STAILQ_EMPTY(&nx->nx_ch_if_adv_head));
	lck_rw_destroy(&nx->nx_ch_if_adv_lock, &nexus_lock_group);

	SK_DF(SK_VERB_MEM, "nexus 0x%llx FREE", SK_KVA(nx));
	zfree(nx_zone, nx);
}

void
nx_retain_locked(struct kern_nexus *nx)
{
	SK_LOCK_ASSERT_HELD();

	nx->nx_refcnt++;
	VERIFY(nx->nx_refcnt > 0);
}

void
nx_retain(struct kern_nexus *nx)
{
	SK_LOCK();
	nx_retain_locked(nx);
	SK_UNLOCK();
}

int
nx_release_locked(struct kern_nexus *nx)
{
	int oldref = nx->nx_refcnt;

	SK_LOCK_ASSERT_HELD();

	VERIFY(nx->nx_refcnt > 0);
	if (--nx->nx_refcnt == 0) {
		nx_free(nx);
	}

	return oldref == 1;
}

int
nx_release(struct kern_nexus *nx)
{
	int lastref;

	SK_LOCK_ASSERT_NOTHELD();

	SK_LOCK();
	lastref = nx_release_locked(nx);
	SK_UNLOCK();

	return lastref;
}

static int
nx_init_rings(struct kern_nexus *nx, struct kern_channel *ch)
{
	struct kern_nexus_provider *nxprov = NX_PROV(nx);
	struct nexus_adapter *na = ch->ch_na;
	boolean_t undo = FALSE;
	int ksd_retains = 0;
	enum txrx t;
	int err = 0;

	ASSERT((ch->ch_flags & (CHANF_EXT_PRECONNECT | CHANF_EXT_CONNECTED)) ==
	    CHANF_EXT_PRECONNECT);

	if (nxprov->nxprov_ext.nxpi_ring_init == NULL) {
		return 0;
	}

	for_rx_tx(t) {
		uint32_t i;

		for (i = 0; i < na_get_nrings(na, t); i++) {
			struct __kern_channel_ring *kring = &NAKR(na, t)[i];

			/* skip host rings */
			if (kring->ckr_flags & CKRF_HOST) {
				continue;
			}

			if ((err = nxprov->nxprov_ext.nxpi_ring_init(
				    nxprov, nx, ch, kring, (kring->ckr_tx == NR_TX),
				    &kring->ckr_ctx)) != 0) {
				SK_D("ch 0x%llx flags %b nx 0x%llx kr \"%s\" "
				    "(0x%llx) krflags %b ring_init error %d",
				    SK_KVA(ch), ch->ch_flags, CHANF_BITS,
				    SK_KVA(nx), kring->ckr_name, SK_KVA(kring),
				    kring->ckr_flags, CKRF_BITS, err);
				kring->ckr_ctx = NULL;
				undo = TRUE;
				break;
			}
			kring->ckr_flags |= CKRF_EXT_RING_INITED;

			if ((err = nx_init_slots(nx, kring)) != 0) {
				undo = TRUE;
				break;
			}

			if (kring->ckr_flags & CKRF_EXT_SLOTS_INITED) {
				++ksd_retains;
			}
		}
		if (undo) {
			break;
		}
	}

	/*
	 * Note: retain KSD even in case of error, as we have set
	 * CKRF_EXT_SLOTS_INITED flag for some of the rings
	 * nx_fini_rings would take care of release based on it.
	 */
	if (ksd_retains != 0) {
		/*
		 * Mark the kernel slot descriptor region as busy; this
		 * prevents it from being torn-down at channel defunct
		 * time, as we need to invoke the slot_fini() callback
		 * for each slot and we need the descriptors until then.
		 */
		skmem_arena_nexus_sd_set_noidle(skmem_arena_nexus(na->na_arena),
		    ksd_retains);
	}

	if (err != 0) {
		ASSERT(undo);
		nx_fini_rings(nx, ch);
	}

	return err;
}

static void
nx_fini_rings(struct kern_nexus *nx, struct kern_channel *ch)
{
	struct kern_nexus_provider *nxprov = NX_PROV(nx);
	struct nexus_adapter *na = ch->ch_na;
	int ksd_releases = 0;
	enum txrx t;

	for_rx_tx(t) {
		uint32_t i;

		for (i = 0; i < na_get_nrings(na, t); i++) {
			struct __kern_channel_ring *kring = &NAKR(na, t)[i];

			if (!(kring->ckr_flags & CKRF_EXT_RING_INITED)) {
				continue;
			}

			ASSERT(!(kring->ckr_flags & CKRF_HOST));
			ASSERT(nxprov->nxprov_ext.nxpi_ring_fini != NULL);
			nxprov->nxprov_ext.nxpi_ring_fini(nxprov, nx, kring);
			kring->ckr_flags &= ~CKRF_EXT_RING_INITED;

			if (kring->ckr_flags & CKRF_EXT_SLOTS_INITED) {
				++ksd_releases;
			}

			/*
			 * Undo the work done in nx_init_slots() and inform
			 * the external domain provider, if applicable, that
			 * the slots for this ring are no longer valid.
			 */
			nx_fini_slots(nx, kring);
			kring->ckr_ctx = NULL;
		}
	}

	if (ksd_releases != 0) {
		/*
		 * Now that we've finished invoking the slot_fini()
		 * callbacks, release the busy retain counts held
		 * earlier in nx_init_rings().  This will allow the
		 * kernel slot descriptor region to be torn down.
		 */
		skmem_arena_nexus_sd_set_noidle(
			skmem_arena_nexus(na->na_arena), -ksd_releases);
	}
}

static int
nx_init_slots(struct kern_nexus *nx, struct __kern_channel_ring *kring)
{
	struct kern_nexus_provider *nxprov = NX_PROV(nx);
	struct __slot_desc *slot = kring->ckr_ksds;
	int err = 0;
	uint32_t i;

	/*
	 * If the slot init callback was not provided, or if the
	 * kring was not created to hold any slot contexts, don't
	 * go any further.
	 */
	if (nxprov->nxprov_ext.nxpi_slot_init == NULL ||
	    kring->ckr_slot_ctxs == NULL) {
		return 0;
	}

	ASSERT(kring->ckr_slot_ctxs_set == 0);
	ASSERT(slot != NULL);

	for (i = 0; i < kring->ckr_num_slots; i++) {
		struct kern_slot_prop *slot_ctx_prop = NULL;
		void *slot_ctx_arg = NULL;

		ASSERT(&slot[i] <= kring->ckr_ksds_last);
		if ((err = nxprov->nxprov_ext.nxpi_slot_init(nxprov, nx, kring,
		    &slot[i], i, &slot_ctx_prop, &slot_ctx_arg)) != 0) {
			SK_D("nx 0x%llx kr \"%s\" (0x%llx) krflags %b slot %u "
			    "slot_init error %d", SK_KVA(nx), kring->ckr_name,
			    SK_KVA(kring), kring->ckr_flags, CKRF_BITS, i, err);
			break;
		}
		/* we don't want this to be used by client, so verify here */
		ASSERT(slot_ctx_prop == NULL);
		kring->ckr_slot_ctxs[i].slot_ctx_arg =
		    (mach_vm_address_t)slot_ctx_arg;
		kring->ckr_slot_ctxs_set++;
	}

	if (err != 0) {
		nx_fini_slots(nx, kring);
	} else {
		kring->ckr_flags |= CKRF_EXT_SLOTS_INITED;
	}

	return err;
}

static void
nx_fini_slots(struct kern_nexus *nx, struct __kern_channel_ring *kring)
{
	struct kern_nexus_provider *nxprov = NX_PROV(nx);
	struct __slot_desc *slot = kring->ckr_ksds;
	uint32_t i;

	ASSERT(!(kring->ckr_flags & CKRF_EXT_SLOTS_INITED) ||
	    nxprov->nxprov_ext.nxpi_slot_fini != NULL);
	ASSERT(slot != NULL || !(kring->ckr_flags & CKRF_EXT_SLOTS_INITED));

	for (i = 0; i < kring->ckr_slot_ctxs_set; i++) {
		ASSERT(slot != NULL && &slot[i] <= kring->ckr_ksds_last);
		if (nxprov->nxprov_ext.nxpi_slot_fini != NULL) {
			nxprov->nxprov_ext.nxpi_slot_fini(nxprov, nx,
			    kring, &slot[i], i);
		}
		if (kring->ckr_slot_ctxs != NULL) {
			kring->ckr_slot_ctxs[i].slot_ctx_arg = 0;
		}
	}
	kring->ckr_slot_ctxs_set = 0;

	/* We're done with this kring */
	kring->ckr_flags &= ~CKRF_EXT_SLOTS_INITED;
}


/* 64-bit mask with range */
#define BMASK64(_beg, _end)     \
	((NX_PORT_CHUNK_FREE >> (63 - (_end))) & ~((1ULL << (_beg)) - 1))

int
nx_port_find(struct kern_nexus *nx, nexus_port_t first,
    nexus_port_t last, nexus_port_t *nx_port)
{
	int err = 0;

	ASSERT(first < last);
	*nx_port = NEXUS_PORT_ANY;

	if (nx->nx_num_ports == 0 || (first + 1) >= nx->nx_num_ports) {
		/*
		 * Left edge of the range is beyond the current map;
		 * let nx_port_alloc() handle the growing later.
		 */
		*nx_port = first;
	} else {
		uint32_t fc = (first / NX_PORT_CHUNK);
		uint32_t lc = (MIN(last, nx->nx_num_ports) / NX_PORT_CHUNK);
		uint32_t lim = (nx->nx_num_ports / NX_PORT_CHUNK);
		uint32_t i, j;
		bitmap_t *bmap;

		/*
		 * The right edge of the range is either within or
		 * beyond the current map; scan thru the current
		 * map and find the first available port.
		 */
		for (i = fc; i <= lc; i++) {
			bitmap_t mask;
			uint32_t beg = 0, end = 63;

			if (i == fc) {
				beg = (first % NX_PORT_CHUNK);
			}
			if (i == (last / NX_PORT_CHUNK)) {
				end = (last % NX_PORT_CHUNK);
			}

			if (i < lim) {
				bmap = &nx->nx_ports_bmap[i];
				mask = BMASK64(beg, end);

				j = ffsll((*bmap) & mask);
				if (j == 0) {
					continue;
				}

				--j;
				*nx_port = (i * NX_PORT_CHUNK) + j;
			}
			break;
		}

		/*
		 * If the requested range is within the current map and we
		 * couldn't find a port, return an err.  Otherwise, return
		 * the next port index to trigger growing later.
		 */
		if (*nx_port == NEXUS_PORT_ANY) {
			if (lc == (last / NX_PORT_CHUNK)) {
				err = EBUSY;
				SK_ERR("port unavail in [%u, %u)", first, last);
			} else {
				*nx_port = nx->nx_num_ports;
			}
		}
	}

	SK_DF(SK_VERB_NXPORT, "nx 0x%llx nx_port %d (err %d)", SK_KVA(nx),
	    (int)*nx_port, err);

	return err;
}

static int
nx_port_grow(struct kern_nexus *nx, uint32_t grow)
{
	nexus_port_t dom_port_max = NXDOM_MAX(NX_DOM(nx), ports);
	struct nx_port_info *ports;
	size_t limit;
	uint32_t i, num_ports, old_num_ports;
	bitmap_t *bmap;

	ASSERT(grow > 0 && (grow % NX_PORT_CHUNK) == 0);
	ASSERT((nx->nx_num_ports % NX_PORT_CHUNK) == 0);
	_CASSERT((sizeof(*bmap) * 8) == NX_PORT_CHUNK);
	ASSERT(powerof2(dom_port_max));
	ASSERT(dom_port_max % NX_PORT_CHUNK == 0);

	old_num_ports = nx->nx_num_ports;
	num_ports = nx->nx_num_ports + grow;
	limit = P2ROUNDUP(dom_port_max, NX_PORT_CHUNK);
	if (num_ports > limit) {
		SK_ERR("can't grow, total %u grow %u (new %u > dom_max %u)",
		    nx->nx_num_ports, grow, num_ports, limit);
		return EDOM;
	}

	if ((bmap = sk_realloc_data(nx->nx_ports_bmap,
	    (old_num_ports / NX_PORT_CHUNK) * sizeof(*bmap),
	    (num_ports / NX_PORT_CHUNK) * sizeof(*bmap),
	    Z_WAITOK, skmem_tag_nx_port)) == NULL) {
		SK_ERR("bmap alloc failed, num_port %u", num_ports);
		return ENOMEM;
	}
	nx->nx_ports_bmap = bmap;

	if ((ports = sk_realloc_data(nx->nx_ports, old_num_ports * sizeof(*ports),
	    num_ports * sizeof(*ports), Z_WAITOK, skmem_tag_nx_port)) == NULL) {
		/* can't free bmap here, otherwise nexus won't work */
		SK_ERR("nx_ports alloc failed, num_port %u", num_ports);
		return ENOMEM;
	}

	/* initialize the additional new ports */
	bzero(&ports[nx->nx_num_ports], (grow * sizeof(*ports)));
	nx->nx_ports = ports;

	/* initialize new bitmaps (set all bits) */
	for (i = (nx->nx_num_ports / NX_PORT_CHUNK);
	    i < (num_ports / NX_PORT_CHUNK); i++) {
		bmap[i] = NX_PORT_CHUNK_FREE;
	}

	nx->nx_num_ports = num_ports;

	SK_DF(SK_VERB_NXPORT, "!!! nx 0x%llx ports %u/%u, %u ports added",
	    SK_KVA(nx), nx->nx_active_ports, nx->nx_num_ports, grow);

	return 0;
}

int
nx_port_alloc(struct kern_nexus *nx, nexus_port_t nx_port, struct nxbind *nxb,
    struct nexus_adapter **na, struct proc *p)
{
	struct nx_port_info *npi = NULL;
	struct nxbind *nxb0;
	size_t g;
	uint32_t i, j;
	bitmap_t *bmap;
	bool refonly = false;
	int err = 0;

	ASSERT(nx_port != NEXUS_PORT_ANY);
	ASSERT((nx->nx_num_ports % NX_PORT_CHUNK) == 0);

	/* port is zero-based, so adjust here */
	if ((nx_port + 1) > nx->nx_num_ports) {
		g = P2ROUNDUP((nx_port + 1) - nx->nx_num_ports, NX_PORT_CHUNK);
		VERIFY(g <= UINT32_MAX);
		if ((err = nx_port_grow(nx, (uint32_t)g)) != 0) {
			goto done;
		}
	}
	ASSERT(err == 0);
	ASSERT(nx_port < nx->nx_num_ports);
	npi = &nx->nx_ports[nx_port];
	nxb0 = npi->npi_nxb;
	i = nx_port / NX_PORT_CHUNK;
	j = nx_port % NX_PORT_CHUNK;
	bmap = &nx->nx_ports_bmap[i];

	if (bit_test(*bmap, j)) {
		/* port is not (yet) bound or allocated */
		ASSERT(npi->npi_nah == 0 && npi->npi_nxb == NULL);
		if (p != kernproc && !NX_ANONYMOUS_PROV(nx)) {
			/*
			 * If the port allocation is requested by userland
			 * and the nexus is non-anonymous, then fail the
			 * request.
			 */
			err = EACCES;
			SK_ERR("user proc alloc on named nexus needs binding");
		} else if (na != NULL && *na != NULL) {
			/*
			 * Otherwise claim it (clear bit) if the caller
			 * supplied an adapter for this port; else, it
			 * is just an existential check and so there's
			 * no action needed at this point (we'll skip
			 * the init below since vpna is NULL).
			 */
			bit_clear(*bmap, j);
		}
	} else {
		/* if port is bound, check if credentials match */
		if (nxb0 != NULL && p != kernproc && !NX_ANONYMOUS_PROV(nx) &&
		    (nxb == NULL || !nxb_is_equal(nxb0, nxb))) {
			SK_ERR("nexus binding mismatch");
			err = EACCES;
		} else {
			/*
			 * If port is already occupied by an adapter,
			 * see if the client is requesting a reference
			 * to it; if so, return the adapter.  Otherwise,
			 * if unoccupied and vpna is non-NULL, associate
			 * it with this nexus port via the below init.
			 */
			if (NPI_NA(npi) != NULL) {
				if (na != NULL && *na == NULL) {
					*na = NPI_NA(npi);
					na_retain_locked(*na);
					/* skip the init below */
					refonly = true;
				} else {
					/*
					 * If the client supplied an adapter
					 * (regardless of its value) for a
					 * nexus port that's already occupied,
					 * then we fail the request.
					 */
					SK_ERR("nexus adapted exits");
					err = EEXIST;
				}
			}
		}
	}

done:
	/* initialize the nexus port and the adapter occupying it */
	if (err == 0 && na != NULL && *na != NULL && !refonly) {
		ASSERT(nx_port < nx->nx_num_ports);
		ASSERT(npi->npi_nah == 0);
		ASSERT(nx->nx_active_ports < nx->nx_num_ports);
		ASSERT(!bit_test(nx->nx_ports_bmap[nx_port / NX_PORT_CHUNK],
		    (nx_port % NX_PORT_CHUNK)));

		nx->nx_active_ports++;
		npi->npi_nah = NPI_NA_ENCODE(*na, NEXUS_PORT_STATE_WORKING);
		(*na)->na_nx_port = nx_port;
	}

	SK_DF(SK_VERB_NXPORT, "nx 0x%llx nx_port %d, ports %u/%u (err %d)",
	    SK_KVA(nx), (int)nx_port, nx->nx_active_ports, nx->nx_num_ports,
	    err);

	return err;
}

void
nx_port_defunct(struct kern_nexus *nx, nexus_port_t nx_port)
{
	struct nx_port_info *npi = &nx->nx_ports[nx_port];

	npi->npi_nah = NPI_NA_ENCODE(npi->npi_nah,
	    NEXUS_PORT_STATE_DEFUNCT);
}

void
nx_port_free(struct kern_nexus *nx, nexus_port_t nx_port)
{
	struct nx_port_info *npi = NULL;
	bitmap_t *bmap;
	uint32_t i, j;

	ASSERT((nx->nx_num_ports % NX_PORT_CHUNK) == 0);
	ASSERT(nx_port != NEXUS_PORT_ANY && nx_port < nx->nx_num_ports);
	ASSERT(nx->nx_active_ports != 0);

	i = nx_port / NX_PORT_CHUNK;
	j = nx_port % NX_PORT_CHUNK;
	bmap = &nx->nx_ports_bmap[i];
	ASSERT(!bit_test(*bmap, j));

	npi = &nx->nx_ports[nx_port];
	npi->npi_nah = 0;
	if (npi->npi_nxb == NULL) {
		/* it's vacant, release it (set bit) */
		bit_set(*bmap, j);
	}

	nx->nx_active_ports--;

	//XXX wshen0123@apple.com --- try to shrink bitmap & nx_ports ???

	SK_DF(SK_VERB_NXPORT, "--- nx 0x%llx nx_port %d, ports %u/%u",
	    SK_KVA(nx), (int)nx_port, nx->nx_active_ports, nx->nx_num_ports);
}

int
nx_port_bind_info(struct kern_nexus *nx, nexus_port_t nx_port,
    struct nxbind *nxb0, void *info)
{
	struct nx_port_info *npi = NULL;
	size_t g;
	uint32_t i, j;
	bitmap_t *bmap;
	int err = 0;

	ASSERT(nx_port != NEXUS_PORT_ANY);
	ASSERT(nx_port < NXDOM_MAX(NX_DOM(nx), ports));
	ASSERT((nx->nx_num_ports % NX_PORT_CHUNK) == 0);
	ASSERT(nxb0 != NULL);

	if ((nx_port) + 1 > nx->nx_num_ports) {
		g = P2ROUNDUP((nx_port + 1) - nx->nx_num_ports, NX_PORT_CHUNK);
		VERIFY(g <= UINT32_MAX);
		if ((err = nx_port_grow(nx, (uint32_t)g)) != 0) {
			goto done;
		}
	}
	ASSERT(err == 0);

	npi = &nx->nx_ports[nx_port];
	i = nx_port / NX_PORT_CHUNK;
	j = nx_port % NX_PORT_CHUNK;
	bmap = &nx->nx_ports_bmap[i];
	if (bit_test(*bmap, j)) {
		/* port is not (yet) bound or allocated */
		ASSERT(npi->npi_nah == 0 && npi->npi_nxb == NULL);

		bit_clear(*bmap, j);
		struct nxbind *nxb = nxb_alloc(Z_WAITOK);
		nxb_move(nxb0, nxb);
		npi->npi_nxb = nxb;
		npi->npi_info = info;
		/* claim it (clear bit) */
		bit_clear(*bmap, j);
		ASSERT(err == 0);
	} else {
		/* port is already taken */
		ASSERT(NPI_NA(npi) != NULL || npi->npi_nxb != NULL);
		err = EEXIST;
	}
done:

	SK_DF(err ? SK_VERB_ERROR : SK_VERB_NXPORT,
	    "+++ nx 0x%llx nx_port %d, ports %u/%u (err %d)", SK_KVA(nx),
	    (int)nx_port, nx->nx_active_ports, nx->nx_num_ports, err);

	return err;
}

int
nx_port_bind(struct kern_nexus *nx, nexus_port_t nx_port, struct nxbind *nxb0)
{
	return nx_port_bind_info(nx, nx_port, nxb0, NULL);
}

static int
nx_port_info_size(void *info, size_t *sz)
{
	struct nx_port_info_header *hdr = info;

	switch (hdr->ih_type) {
	case NX_PORT_INFO_TYPE_NETIF:
		break;
	default:
		return EINVAL;
	}
	*sz = hdr->ih_size;
	return 0;
}

int
nx_port_unbind(struct kern_nexus *nx, nexus_port_t nx_port)
{
	struct nx_port_info *npi = NULL;
	struct nxbind *nxb;
	uint32_t i, j;
	bitmap_t *bmap;
	int err = 0;

	ASSERT(nx_port != NEXUS_PORT_ANY);

	if (nx_port >= nx->nx_num_ports) {
		err = EDOM;
		goto done;
	}

	npi = &nx->nx_ports[nx_port];
	i = nx_port / NX_PORT_CHUNK;
	j = nx_port % NX_PORT_CHUNK;
	bmap = &nx->nx_ports_bmap[i];

	if ((nxb = npi->npi_nxb) == NULL) {
		/* must be either free or allocated */
		ASSERT(NPI_NA(npi) == NULL ||
		    (!bit_test(*bmap, j) && nx->nx_active_ports > 0));
		err = ENOENT;
	} else {
		nxb_free(nxb);
		npi->npi_nxb = NULL;
		if (npi->npi_info != NULL) {
			size_t sz;

			VERIFY(nx_port_info_size(npi->npi_info, &sz) == 0);
			sk_free_data(npi->npi_info, sz);
			npi->npi_info = NULL;
		}
		ASSERT(!bit_test(*bmap, j));
		if (NPI_NA(npi) == NULL) {
			/* it's vacant, release it (set bit) */
			bit_set(*bmap, j);
		}
	}

done:
	SK_DF(err ? SK_VERB_ERROR : SK_VERB_NXPORT,
	    "--- nx 0x%llx nx_port %d, ports %u/%u (err %d)", SK_KVA(nx),
	    (int)nx_port, nx->nx_active_ports, nx->nx_num_ports, err);

	return err;
}

struct nexus_adapter *
nx_port_get_na(struct kern_nexus *nx, nexus_port_t nx_port)
{
	if (nx->nx_ports != NULL && nx->nx_num_ports > nx_port) {
		return NPI_NA(&nx->nx_ports[nx_port]);
	} else {
		return NULL;
	}
}

int
nx_port_get_info(struct kern_nexus *nx, nexus_port_t port,
    nx_port_info_type_t type, void *info, uint32_t len)
{
	struct nx_port_info *npi;
	struct nx_port_info_header *hdr;

	if (nx->nx_ports == NULL || port >= nx->nx_num_ports) {
		return ENXIO;
	}
	npi = &nx->nx_ports[port];
	hdr = npi->npi_info;
	if (hdr == NULL) {
		return ENOENT;
	}

	if (hdr->ih_type != type) {
		return EINVAL;
	}

	bcopy(npi->npi_info, info, len);
	return 0;
}

bool
nx_port_is_valid(struct kern_nexus *nx, nexus_port_t nx_port)
{
	return nx_port < nx->nx_num_ports;
}

bool
nx_port_is_defunct(struct kern_nexus *nx, nexus_port_t nx_port)
{
	ASSERT(nx_port_is_valid(nx, nx_port));

	return NPI_IS_DEFUNCT(&nx->nx_ports[nx_port]);
}

void
nx_port_free_all(struct kern_nexus *nx)
{
	uint32_t num_ports;

	/* uncrustify doesn't handle C blocks properly */
	/* BEGIN IGNORE CODESTYLE */
	nx_port_foreach(nx, ^(nexus_port_t p) {
		struct nxbind *nxb;
		void *info;
		nxb = nx->nx_ports[p].npi_nxb;
		info = nx->nx_ports[p].npi_info;
		if (nxb != NULL) {
			nxb_free(nxb);
			nx->nx_ports[p].npi_nxb = NULL;
		}
		if (info != NULL) {
			size_t sz;

			VERIFY(nx_port_info_size(info, &sz) == 0);
			skn_free_data(info, info, sz);
			nx->nx_ports[p].npi_info = NULL;
		}
	});
	/* END IGNORE CODESTYLE */

	num_ports = nx->nx_num_ports;
	nx->nx_num_ports = 0;
	nx->nx_active_ports = 0;
	skn_free_data(ports_bmap,
	    nx->nx_ports_bmap, (num_ports / NX_PORT_CHUNK) * sizeof(bitmap_t));
	nx->nx_ports_bmap = NULL;
	skn_free_data(ports,
	    nx->nx_ports, num_ports * sizeof(struct nx_port_info));
	nx->nx_ports = NULL;
}

void
nx_port_foreach(struct kern_nexus *nx,
    void (^port_handle)(nexus_port_t nx_port))
{
	for (uint32_t i = 0; i < (nx->nx_num_ports / NX_PORT_CHUNK); i++) {
		bitmap_t bmap = nx->nx_ports_bmap[i];

		if (bmap == NX_PORT_CHUNK_FREE) {
			continue;
		}

		for (uint32_t j = 0; j < NX_PORT_CHUNK; j++) {
			if (bit_test(bmap, j)) {
				continue;
			}
			port_handle((i * NX_PORT_CHUNK) + j);
		}
	}
}

/*
 * sysctl interfaces
 */
static int nexus_provider_list_sysctl SYSCTL_HANDLER_ARGS;
static int nexus_channel_list_sysctl SYSCTL_HANDLER_ARGS;
static int nexus_mib_get_sysctl SYSCTL_HANDLER_ARGS;

SYSCTL_PROC(_kern_skywalk, OID_AUTO, nexus_provider_list,
    CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_LOCKED,
    0, 0, nexus_provider_list_sysctl, "S,nexus_provider_info_t", "");

SYSCTL_PROC(_kern_skywalk, OID_AUTO, nexus_channel_list,
    CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_LOCKED,
    0, 0, nexus_channel_list_sysctl, "S,nexus_channel_entry_t", "");

SYSCTL_PROC(_kern_skywalk, OID_AUTO, llink_list,
    CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_LOCKED,
    0, NXMIB_LLINK_LIST, nexus_mib_get_sysctl, "S,nx_llink_info",
    "A list of logical links");

SYSCTL_PROC(_kern_skywalk_stats, OID_AUTO, flow,
    CTLTYPE_STRUCT | CTLFLAG_RW | CTLFLAG_LOCKED | CTLFLAG_ANYBODY | CTLFLAG_KERN,
    0, NXMIB_FLOW, nexus_mib_get_sysctl, "S,sk_stats_flow",
    "Nexus inet flows with stats collected in kernel");

SYSCTL_PROC(_kern_skywalk_stats, OID_AUTO, flow_owner,
    CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_LOCKED,
    0, NXMIB_FLOW_OWNER, nexus_mib_get_sysctl, "S,sk_stats_flow_owner",
    "Nexus flow owners");

SYSCTL_PROC(_kern_skywalk_stats, OID_AUTO, flow_route,
    CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_LOCKED,
    0, NXMIB_FLOW_ROUTE, nexus_mib_get_sysctl, "S,sk_stats_flow_route",
    "Nexus flow routes");

SYSCTL_PROC(_kern_skywalk_stats, OID_AUTO, net_if,
    CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_LOCKED,
    0, NXMIB_NETIF_STATS, nexus_mib_get_sysctl, "S,sk_stats_net_if",
    "Nexus netif statistics collected in kernel");

SYSCTL_PROC(_kern_skywalk_stats, OID_AUTO, flow_switch,
    CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_LOCKED,
    0, NXMIB_FSW_STATS, nexus_mib_get_sysctl, "S,sk_stats_flow_switch",
    "Nexus flowswitch statistics collected in kernel");

SYSCTL_PROC(_kern_skywalk_stats, OID_AUTO, userstack,
    CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_LOCKED,
    0, NXMIB_USERSTACK_STATS, nexus_mib_get_sysctl, "S,sk_stats_userstack",
    "Nexus userstack statistics counter");

SYSCTL_PROC(_kern_skywalk_stats, OID_AUTO, flow_adv,
    CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_LOCKED,
    0, NXMIB_FLOW_ADV, nexus_mib_get_sysctl, "S,sk_stats_flow_adv",
    "Nexus flow advisory dump");

/*
 * Provider list sysctl
 */
static void
nexus_provider_info_populate(struct kern_nexus_provider *nxprov,
    nexus_provider_info_t info)
{
	struct kern_nexus *nx;
	uuid_t *uuids;

	SK_LOCK_ASSERT_HELD();

	/* provider UUID + params */
	uuid_copy(info->npi_prov_uuid, nxprov->nxprov_uuid);
	bcopy(nxprov->nxprov_params, &info->npi_prov_params,
	    sizeof(struct nxprov_params));
	info->npi_instance_uuids_count = nxprov->nxprov_nx_count;

	/* instance UUID list */
	uuids = info->npi_instance_uuids;
	STAILQ_FOREACH(nx, &nxprov->nxprov_nx_head, nx_prov_link) {
		uuid_copy(*uuids, nx->nx_uuid);
		uuids++;
	}
}

static int
nexus_provider_list_sysctl SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2, oidp)
	size_t actual_space;
	caddr_t buffer = NULL;
	size_t buffer_space;
	size_t allocated_space;
	int out_error;
	int error = 0;
	struct kern_nexus_provider *nxprov;
	caddr_t scan;

	if (!kauth_cred_issuser(kauth_cred_get())) {
		return EPERM;
	}

	net_update_uptime();
	buffer_space = req->oldlen;
	if (req->oldptr != USER_ADDR_NULL && buffer_space != 0) {
		if (buffer_space > SK_SYSCTL_ALLOC_MAX) {
			buffer_space = SK_SYSCTL_ALLOC_MAX;
		}
		allocated_space = buffer_space;
		buffer = sk_alloc_data(allocated_space, Z_WAITOK, skmem_tag_sysctl_buf);
		if (__improbable(buffer == NULL)) {
			return ENOBUFS;
		}
	} else if (req->oldptr == USER_ADDR_NULL) {
		buffer_space = 0;
	}
	actual_space = 0;
	scan = buffer;
	SK_LOCK();
	STAILQ_FOREACH(nxprov, &nxprov_head, nxprov_link) {
		size_t                  info_size;

		info_size
		        = NEXUS_PROVIDER_INFO_SIZE(nxprov->nxprov_nx_count);
		if (scan != NULL) {
			if (buffer_space < info_size) {
				/* supplied buffer too small, stop copying */
				error = ENOMEM;
				break;
			}
			nexus_provider_info_populate(nxprov, (void *)scan);
			scan += info_size;
			buffer_space -= info_size;
		}
		actual_space += info_size;
	}
	SK_UNLOCK();

	out_error = SYSCTL_OUT(req, buffer, actual_space);
	if (out_error != 0) {
		error = out_error;
	}

	if (buffer != NULL) {
		sk_free_data(buffer, allocated_space);
	}

	return error;
}

/*
 * Channel list sysctl
 */
static uint32_t
channel_ring_count(struct kern_channel *ch, enum txrx which)
{
	return ch->ch_last[which] - ch->ch_first[which];
}

static void
populate_ring_entries(struct __kern_channel_ring *kring,
    ring_id_t first, ring_id_t last, nexus_channel_ring_entry_t entries)
{
	ring_id_t i;
	nexus_channel_ring_entry_t scan;
	struct __kern_channel_ring *ring;

	scan = entries;
	for (i = first; i < last; i++, scan++) {
		ring = &kring[i];

		DTRACE_SKYWALK1(populate__ring, struct __kern_channel_ring *,
		    ring);
		if (kr_stat_enable == 0) {
			bzero(&scan->ncre_stats, sizeof(scan->ncre_stats));
			bzero(&scan->ncre_user_stats,
			    sizeof(scan->ncre_user_stats));
		} else {
			scan->ncre_stats = ring->ckr_stats;
			scan->ncre_user_stats = ring->ckr_usr_stats;
		}
		scan->ncre_error_stats = ring->ckr_err_stats;
		scan->ncre_ring_id = i;
	}
}

/* combine/convert ch_mode/ch_flags into nexus_channel_entry flags */
static uint32_t
nexus_channel_get_flags(uint32_t ch_mode, uint32_t ch_flags)
{
	uint32_t flags = 0;

	flags |= (ch_mode & CHMODE_MONITOR_TX) ? SCHF_MONITOR_TX : 0;
	flags |= (ch_mode & CHMODE_MONITOR_RX) ? SCHF_MONITOR_RX : 0;
	flags |= (ch_mode & CHMODE_MONITOR_NO_COPY) ? SCHF_MONITOR_NO_COPY : 0;
	flags |= (ch_mode & CHMODE_USER_PACKET_POOL) ? SCHF_USER_PACKET_POOL : 0;
	flags |= (ch_mode & CHMODE_DEFUNCT_OK) ? SCHF_DEFUNCT_OK : 0;
	flags |= (ch_mode & CHMODE_FILTER) ? SCHF_FILTER : 0;
	flags |= (ch_mode & CHMODE_EVENT_RING) ? SCHF_EVENT_RING : 0;
	flags |= (ch_mode & CHMODE_EXCLUSIVE) ? SCHF_EXCLUSIVE : 0;
	flags |= (ch_flags & CHANF_IF_ADV) ? SCHF_IF_ADV : 0;
	flags |= (ch_flags & CHANF_DEFUNCT_SKIP) ? SCHF_DEFUNCT_SKIP : 0;
	flags |= (ch_flags & CHANF_CLOSING) ? SCHF_CLOSING : 0;
	flags |= (ch_flags & CHANF_DEFUNCT) ? SCHF_DEFUNCT : 0;
	flags |= (ch_mode & CHMODE_LOW_LATENCY) ? SCHF_LOW_LATENCY : 0;

	return flags;
}

SK_NO_INLINE_ATTRIBUTE
static void
nexus_channel_entry_populate(struct kern_channel *ch,
    nexus_channel_entry_t entry)
{
	uint32_t ch_mode = ch->ch_info->cinfo_ch_mode;
	uint32_t ch_flags = ch->ch_flags;
	ring_id_t rx_first = ch->ch_first[NR_RX];
	ring_id_t rx_last = ch->ch_last[NR_RX];
	ring_id_t tx_last = ch->ch_last[NR_TX];
	ring_id_t tx_first = ch->ch_first[NR_TX];

	uuid_copy(entry->nce_uuid, ch->ch_info->cinfo_ch_id);
	entry->nce_flags = nexus_channel_get_flags(ch_mode, ch_flags);
	entry->nce_port = ch->ch_info->cinfo_nx_port;
	entry->nce_pid = ch->ch_pid;
	entry->nce_fd = ch->ch_fd;
	entry->nce_tx_rings = tx_last - tx_first;
	entry->nce_rx_rings = rx_last - rx_first;
	populate_ring_entries(ch->ch_na->na_tx_rings, tx_first, tx_last,
	    entry->nce_ring_entries);
	populate_ring_entries(ch->ch_na->na_rx_rings, rx_first, rx_last,
	    entry->nce_ring_entries + entry->nce_tx_rings);
}

SK_NO_INLINE_ATTRIBUTE
static size_t
nexus_channel_info_populate(struct kern_nexus *nx,
    nexus_channel_info_t info, size_t buffer_size)
{
	struct kern_channel *ch = NULL;
	size_t info_size;
	caddr_t scan = NULL;

	SK_LOCK_ASSERT_HELD();

	info_size = sizeof(*info);

	/* channel list */
	if (info != NULL) {
		if (buffer_size < info_size) {
			return info_size;
		}

		/* instance UUID */
		uuid_copy(info->nci_instance_uuid, nx->nx_uuid);
		info->nci_channel_entries_count = nx->nx_ch_count;
		scan = (caddr_t)info->nci_channel_entries;
	}
	STAILQ_FOREACH(ch, &nx->nx_ch_head, ch_link) {
		size_t          entry_size;
		uint32_t        ring_count;

		ring_count = channel_ring_count(ch, NR_TX) +
		    channel_ring_count(ch, NR_RX);
		entry_size = NEXUS_CHANNEL_ENTRY_SIZE(ring_count);
		info_size += entry_size;
		if (scan != NULL) {
			if (buffer_size < info_size) {
				return info_size;
			}

			nexus_channel_entry_populate(ch, (void *)scan);
			scan += entry_size;
		}
	}
	return info_size;
}

static int
nexus_channel_list_sysctl SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2, oidp)
	size_t actual_space;
	caddr_t buffer = NULL;
	size_t buffer_space;
	size_t allocated_space;
	int out_error;
	struct kern_nexus *nx;
	int error = 0;
	caddr_t scan;

	if (!kauth_cred_issuser(kauth_cred_get())) {
		return EPERM;
	}

	net_update_uptime();
	buffer_space = req->oldlen;
	if (req->oldptr != USER_ADDR_NULL && buffer_space != 0) {
		if (buffer_space > SK_SYSCTL_ALLOC_MAX) {
			buffer_space = SK_SYSCTL_ALLOC_MAX;
		}
		allocated_space = buffer_space;
		buffer = sk_alloc_data(allocated_space, Z_WAITOK, skmem_tag_sysctl_buf);
		if (__improbable(buffer == NULL)) {
			return ENOBUFS;
		}
	} else if (req->oldptr == USER_ADDR_NULL) {
		buffer_space = 0;
	}
	actual_space = 0;
	scan = buffer;
	SK_LOCK();
	RB_FOREACH(nx, kern_nexus_tree, &nx_head) {
		size_t info_size;

		info_size = nexus_channel_info_populate(nx, (void *)scan,
		    buffer_space);
		if (scan != NULL) {
			if (buffer_space < info_size) {
				/* supplied buffer too small, stop copying */
				error = ENOMEM;
				break;
			}
			scan += info_size;
			buffer_space -= info_size;
		}
		actual_space += info_size;
	}
	SK_UNLOCK();

	if (actual_space != 0) {
		out_error = SYSCTL_OUT(req, buffer, actual_space);
		if (out_error != 0) {
			error = out_error;
		}
	}
	if (buffer != NULL) {
		sk_free_data(buffer, allocated_space);
	}

	return error;
}

static int
nexus_mib_get_sysctl SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	struct proc *p = req->p;
	struct nexus_mib_filter filter;
	int error = 0;
	size_t actual_space;
	caddr_t buffer = NULL;
	size_t buffer_space;
	size_t allocated_space;
	int out_error;
	struct kern_nexus *nx;
	caddr_t scan;

	/* Restrict protocol stats access to root user only (like netstat). */
	if (oidp->oid_arg2 == NXMIB_USERSTACK_STATS &&
	    !kauth_cred_issuser(kauth_cred_get())) {
		SK_ERR("mib request rejected, EPERM");
		return EPERM;
	}

	if (req->newptr == USER_ADDR_NULL) {
		/* use subcommand for multiple nodes */
		filter.nmf_type = oidp->oid_arg2;
		filter.nmf_bitmap = 0x0;
	} else if (req->newlen != sizeof(struct nexus_mib_filter)) {
		SK_ERR("mis-matching newlen");
		return EINVAL;
	} else {
		error = SYSCTL_IN(req, &filter, sizeof(struct nexus_mib_filter));
		if (error != 0) {
			SK_ERR("SYSCTL_IN err %d", error);
			return error;
		}
		if (filter.nmf_type != oidp->oid_arg2) {
			SK_ERR("mis-matching nmf_type");
			return EINVAL;
		}
	}

	net_update_uptime();
	buffer_space = req->oldlen;
	if (req->oldptr != USER_ADDR_NULL && buffer_space != 0) {
		if (buffer_space > SK_SYSCTL_ALLOC_MAX) {
			buffer_space = SK_SYSCTL_ALLOC_MAX;
		}
		allocated_space = buffer_space;
		buffer = sk_alloc_data(allocated_space, Z_WAITOK, skmem_tag_sysctl_buf);
		if (__improbable(buffer == NULL)) {
			return ENOBUFS;
		}
	} else if (req->oldptr == USER_ADDR_NULL) {
		buffer_space = 0;
	}
	actual_space = 0;
	scan = buffer;

	SK_LOCK();
	RB_FOREACH(nx, kern_nexus_tree, &nx_head) {
		if (NX_DOM_PROV(nx)->nxdom_prov_nx_mib_get == NULL) {
			continue;
		}

		size_t size;
		struct kern_nexus_domain_provider *nx_dp = NX_DOM_PROV(nx);

		size = nx_dp->nxdom_prov_nx_mib_get(nx, &filter, scan,
		    buffer_space, p);

		if (scan != NULL) {
			if (buffer_space < size) {
				/* supplied buffer too small, stop copying */
				error = ENOMEM;
				break;
			}
			scan += size;
			buffer_space -= size;
		}
		actual_space += size;
	}
	SK_UNLOCK();

	if (actual_space != 0) {
		out_error = SYSCTL_OUT(req, buffer, actual_space);
		if (out_error != 0) {
			error = out_error;
		}
	}
	if (buffer != NULL) {
		sk_free_data(buffer, allocated_space);
	}

	return error;
}

void
kern_nexus_walktree(kern_nexus_walktree_f_t *f, void *arg0,
    boolean_t is_sk_locked)
{
	struct kern_nexus *nx = NULL;

	if (!is_sk_locked) {
		SK_LOCK();
	} else {
		SK_LOCK_ASSERT_HELD();
	}

	RB_FOREACH(nx, kern_nexus_tree, &nx_head) {
		(*f)(nx, arg0);
	}

	if (!is_sk_locked) {
		SK_UNLOCK();
	}
}

errno_t
kern_nexus_get_pbufpool_info(const uuid_t nx_uuid,
    struct kern_pbufpool_memory_info *rx_pool_info,
    struct kern_pbufpool_memory_info *tx_pool_info)
{
	struct kern_pbufpool *tpp, *rpp;
	struct kern_nexus *nx;
	errno_t err = 0;

	nx = nx_find(nx_uuid, FALSE);
	if (nx == NULL) {
		err = ENOENT;
		goto done;
	}

	if (nx->nx_prov->nxprov_params->nxp_type != NEXUS_TYPE_NET_IF) {
		err = ENOTSUP;
		goto done;
	}

	err = nx_netif_prov_nx_mem_info(nx, &tpp, &rpp);
	if (err != 0) {
		goto done;
	}

	if ((tpp == NULL) && (rpp == NULL)) {
		err = ENOENT;
		goto done;
	}

	if (tx_pool_info != NULL) {
		bzero(tx_pool_info, sizeof(*tx_pool_info));
	}
	if (rx_pool_info != NULL) {
		bzero(rx_pool_info, sizeof(*rx_pool_info));
	}

	if ((tx_pool_info != NULL) && (tpp != NULL)) {
		err = kern_pbufpool_get_memory_info(tpp, tx_pool_info);
		if (err != 0) {
			goto done;
		}
	}

	if ((rx_pool_info != NULL) && (rpp != NULL)) {
		err = kern_pbufpool_get_memory_info(rpp, rx_pool_info);
	}

done:
	if (nx != NULL) {
		(void) nx_release(nx);
		nx = NULL;
	}
	return err;
}

void
nx_interface_advisory_notify(struct kern_nexus *nx)
{
	struct kern_channel *ch;
	struct netif_stats *nifs;
	struct fsw_stats *fsw_stats;
	nexus_type_t nxdom_type = NX_DOM(nx)->nxdom_type;

	if (nxdom_type == NEXUS_TYPE_NET_IF) {
		nifs = &NX_NETIF_PRIVATE(nx)->nif_stats;
	} else if (nxdom_type == NEXUS_TYPE_FLOW_SWITCH) {
		fsw_stats = &NX_FSW_PRIVATE(nx)->fsw_stats;
	} else {
		VERIFY(0);
		__builtin_unreachable();
	}
	if (!lck_rw_try_lock_shared(&nx->nx_ch_if_adv_lock)) {
		if (nxdom_type == NEXUS_TYPE_NET_IF) {
			STATS_INC(nifs, NETIF_STATS_IF_ADV_UPD_DROP);
		} else {
			STATS_INC(fsw_stats, FSW_STATS_IF_ADV_UPD_DROP);
		}
		return;
	}
	/*
	 * if the channel is in "nx_ch_if_adv_head" list, then we can
	 * safely assume that the channel is not closed yet.
	 * In ch_close_common(), the channel is removed from the
	 * "nx_ch_if_adv_head" list holding the "nx_ch_if_adv_lock" in
	 * exclusive mode, prior to closing the channel.
	 */
	STAILQ_FOREACH(ch, &nx->nx_ch_if_adv_head, ch_link_if_adv) {
		struct nexus_adapter *na = ch->ch_na;

		ASSERT(na != NULL);
		na_post_event(&na->na_tx_rings[ch->ch_first[NR_TX]],
		    TRUE, FALSE, FALSE, CHAN_FILT_HINT_IF_ADV_UPD);
		if (nxdom_type == NEXUS_TYPE_NET_IF) {
			STATS_INC(nifs, NETIF_STATS_IF_ADV_UPD_SENT);
		} else {
			STATS_INC(fsw_stats, FSW_STATS_IF_ADV_UPD_SENT);
		}
	}
	lck_rw_done(&nx->nx_ch_if_adv_lock);
}
