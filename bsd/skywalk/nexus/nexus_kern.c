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
#include <skywalk/nexus/upipe/nx_user_pipe.h>
#include <skywalk/nexus/kpipe/nx_kernel_pipe.h>
#include <skywalk/nexus/flowswitch/nx_flowswitch.h>
#include <skywalk/nexus/netif/nx_netif.h>
#include <skywalk/nexus/monitor/nx_monitor.h>

static STAILQ_HEAD(, nxdom) nexus_domains =
    STAILQ_HEAD_INITIALIZER(nexus_domains);

static void nxdom_attach(struct nxdom *);
static void nxdom_detach(struct nxdom *);
static void nxdom_init(struct nxdom *);
static void nxdom_terminate(struct nxdom *);
static void nxdom_fini(struct nxdom *);
static void nxdom_del_provider_final(struct kern_nexus_domain_provider *);

static int nxdom_prov_ext_init(struct kern_nexus_domain_provider *);
static void nxdom_prov_ext_fini(struct kern_nexus_domain_provider *);
static struct kern_nexus_domain_provider *nxdom_prov_alloc(zalloc_flags_t);
static void nxdom_prov_free(struct kern_nexus_domain_provider *);

static uint32_t nxprov_bound_var(uint32_t *, uint32_t, uint32_t, uint32_t,
    const char *);
static void nxprov_detaching_enqueue(struct kern_nexus_domain_provider *);
static struct kern_nexus_domain_provider *nxprov_detaching_dequeue(void);
static void nxprov_detacher(void *, wait_result_t);
static int nxprov_detacher_cont(int);

static struct nexus_controller *ncd_alloc(zalloc_flags_t);
static void ncd_free(struct nexus_controller *);

static struct nexus_attr *nxa_alloc(zalloc_flags_t);
static void nxa_free(struct nexus_attr *);

static int _kern_nexus_ifattach(struct nxctl *nxctl, const uuid_t nx_uuid,
    struct ifnet *ifp, const uuid_t nx_uuid_attachee, boolean_t host,
    uuid_t *nx_if_uuid);

static ZONE_DECLARE(ncd_zone, SKMEM_ZONE_PREFIX ".nx.kern.ctl.desc",
    sizeof(struct nexus_controller), ZC_ZFREE_CLEARMEM);

static ZONE_DECLARE(nxdom_prov_zone, SKMEM_ZONE_PREFIX ".nx.kern.dom.prov",
    sizeof(struct kern_nexus_domain_provider), ZC_ZFREE_CLEARMEM);

static ZONE_DECLARE(nxa_zone, SKMEM_ZONE_PREFIX ".nx.kern.attr",
    sizeof(struct nexus_attr), ZC_ZFREE_CLEARMEM);

static int __nxdom_inited = 0;
static STAILQ_HEAD(, kern_nexus_domain_provider) nxprov_detaching_head =
    STAILQ_HEAD_INITIALIZER(nxprov_detaching_head);
static uint32_t nxprov_detaching_cnt;
static void *nxprov_detach_wchan;       /* wait channel for detacher */

/*
 * Array of default nexus domain providers.  Initialized once during
 * domain attach time; no lock is needed to read as they can be treated
 * as immutables, since default providers imply built-in ones and they
 * never detach in practice.
 */
struct kern_nexus_domain_provider *nxdom_prov_default[NEXUS_TYPE_MAX];

void
nxdom_attach_all(void)
{
	struct nxdom *nxdom;
	thread_t tp = THREAD_NULL;

	SK_LOCK_ASSERT_HELD();
	ASSERT(!__nxdom_inited);
	ASSERT(STAILQ_EMPTY(&nexus_domains));

#if CONFIG_NEXUS_FLOWSWITCH
	nxdom_attach(&nx_flowswitch_dom_s);
#endif /* CONFIG_NEXUS_FLOWSWITCH */
#if CONFIG_NEXUS_USER_PIPE
	nxdom_attach(&nx_upipe_dom_s);
#endif /* CONFIG_NEXUS_USER_PIPE */
#if CONFIG_NEXUS_KERNEL_PIPE
	nxdom_attach(&nx_kpipe_dom_s);
#endif /* CONFIG_NEXUS_KERNEL_PIPE */
#if CONFIG_NEXUS_NETIF
	nxdom_attach(&nx_netif_dom_s);
#endif /* CONFIG_NEXUS_NETIF */
#if CONFIG_NEXUS_MONITOR
	nxdom_attach(&nx_monitor_dom_s);
#endif /* CONFIG_NEXUS_MONITOR */

	/* ask domains to initialize */
	STAILQ_FOREACH(nxdom, &nexus_domains, nxdom_link)
	nxdom_init(nxdom);

	if (kernel_thread_start(nxprov_detacher, NULL, &tp) != KERN_SUCCESS) {
		panic_plain("%s: couldn't create detacher thread", __func__);
		/* NOTREACHED */
		__builtin_unreachable();
	}
	thread_deallocate(tp);

	__nxdom_inited = 1;
}

void
nxdom_detach_all(void)
{
	struct nxdom *nxdom, *tnxdom;

	SK_LOCK_ASSERT_HELD();

	if (__nxdom_inited) {
		STAILQ_FOREACH_SAFE(nxdom, &nexus_domains, nxdom_link, tnxdom) {
			nxdom_terminate(nxdom);
			nxdom_fini(nxdom);
			nxdom_detach(nxdom);
		}

		/*
		 * TODO: adi@apple.com -- terminate detacher thread.
		 */

		__nxdom_inited = 0;
	}
	ASSERT(STAILQ_EMPTY(&nexus_domains));
}

#define ASSERT_NXDOM_PARAMS(_dom, _var) do {                            \
	ASSERT(NXDOM_MIN(_dom, _var) <= NXDOM_MAX(_dom, _var));         \
	ASSERT(NXDOM_DEF(_dom, _var) >= NXDOM_MIN(_dom, _var));         \
	ASSERT(NXDOM_DEF(_dom, _var) <= NXDOM_MAX(_dom, _var));         \
} while (0)

static void
nxdom_attach(struct nxdom *nxdom)
{
	struct nxdom *nxdom1;

	SK_LOCK_ASSERT_HELD();
	ASSERT(!(nxdom->nxdom_flags & NEXUSDOMF_ATTACHED));

	STAILQ_FOREACH(nxdom1, &nexus_domains, nxdom_link) {
		if (nxdom1->nxdom_type == nxdom->nxdom_type) {
			/* type must be unique; this is a programming error */
			VERIFY(0);
			/* NOTREACHED */
			__builtin_unreachable();
		}
	}

	/* verify this is a valid type */
	switch (nxdom->nxdom_type) {
	case NEXUS_TYPE_USER_PIPE:
	case NEXUS_TYPE_KERNEL_PIPE:
	case NEXUS_TYPE_NET_IF:
	case NEXUS_TYPE_FLOW_SWITCH:
	case NEXUS_TYPE_MONITOR:
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	/* verify this is a valid metadata type */
	switch (nxdom->nxdom_md_type) {
	case NEXUS_META_TYPE_QUANTUM:
	case NEXUS_META_TYPE_PACKET:
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	/* verify this is a valid metadata subtype */
	switch (nxdom->nxdom_md_subtype) {
	case NEXUS_META_SUBTYPE_PAYLOAD:
	case NEXUS_META_SUBTYPE_RAW:
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}

#if (DEVELOPMENT || DEBUG)
	/*
	 * Override the default ring sizes for flowswitch if configured
	 * via boot-args.  Each nexus provider instance can still change
	 * the values if so desired.
	 */
	if (nxdom->nxdom_type == NEXUS_TYPE_FLOW_SWITCH) {
		if (sk_txring_sz != 0) {
			if (sk_txring_sz < NXDOM_MIN(nxdom, tx_slots)) {
				sk_txring_sz = NXDOM_MIN(nxdom, tx_slots);
			} else if (sk_txring_sz > NXDOM_MAX(nxdom, tx_slots)) {
				sk_txring_sz = NXDOM_MAX(nxdom, tx_slots);
			}
			NXDOM_DEF(nxdom, tx_slots) = sk_txring_sz;
		}
		if (sk_rxring_sz != 0) {
			if (sk_rxring_sz < NXDOM_MIN(nxdom, rx_slots)) {
				sk_rxring_sz = NXDOM_MIN(nxdom, rx_slots);
			} else if (sk_rxring_sz > NXDOM_MAX(nxdom, rx_slots)) {
				sk_rxring_sz = NXDOM_MAX(nxdom, rx_slots);
			}
			NXDOM_DEF(nxdom, rx_slots) = sk_rxring_sz;
		}
	}
	/*
	 * Override the default ring sizes for netif if configured
	 * via boot-args.  Each nexus provider instance can still change
	 * the values if so desired.
	 */
	if (nxdom->nxdom_type == NEXUS_TYPE_NET_IF) {
		if (sk_net_txring_sz != 0) {
			if (sk_net_txring_sz < NXDOM_MIN(nxdom, tx_slots)) {
				sk_net_txring_sz = NXDOM_MIN(nxdom, tx_slots);
			} else if (sk_net_txring_sz > NXDOM_MAX(nxdom, tx_slots)) {
				sk_net_txring_sz = NXDOM_MAX(nxdom, tx_slots);
			}
			NXDOM_DEF(nxdom, tx_slots) = sk_net_txring_sz;
		}
		if (sk_net_rxring_sz != 0) {
			if (sk_net_rxring_sz < NXDOM_MIN(nxdom, rx_slots)) {
				sk_net_rxring_sz = NXDOM_MIN(nxdom, rx_slots);
			} else if (sk_net_rxring_sz > NXDOM_MAX(nxdom, rx_slots)) {
				sk_net_rxring_sz = NXDOM_MAX(nxdom, rx_slots);
			}
			NXDOM_DEF(nxdom, rx_slots) = sk_net_rxring_sz;
		}
	}

#endif /* DEVELOPMENT || DEBUG */

	/* verify that parameters are sane */
	ASSERT(NXDOM_MAX(nxdom, ports) > 0);
	ASSERT_NXDOM_PARAMS(nxdom, ports);
	ASSERT_NXDOM_PARAMS(nxdom, tx_rings);
	ASSERT_NXDOM_PARAMS(nxdom, rx_rings);
	ASSERT(NXDOM_MAX(nxdom, tx_slots) > 0);
	ASSERT_NXDOM_PARAMS(nxdom, tx_slots);
	ASSERT(NXDOM_MAX(nxdom, rx_slots) > 0);
	ASSERT_NXDOM_PARAMS(nxdom, rx_slots);
	ASSERT_NXDOM_PARAMS(nxdom, buf_size);
	ASSERT_NXDOM_PARAMS(nxdom, meta_size);
	ASSERT_NXDOM_PARAMS(nxdom, pipes);
	ASSERT_NXDOM_PARAMS(nxdom, extensions);

	/* these must exist */
	ASSERT(nxdom->nxdom_bind_port != NULL);
	ASSERT(nxdom->nxdom_unbind_port != NULL);
	ASSERT(nxdom->nxdom_connect != NULL);
	ASSERT(nxdom->nxdom_disconnect != NULL);
	ASSERT(nxdom->nxdom_defunct != NULL);
	ASSERT(nxdom->nxdom_defunct_finalize != NULL);

	STAILQ_INSERT_TAIL(&nexus_domains, nxdom, nxdom_link);
	nxdom->nxdom_flags |= NEXUSDOMF_ATTACHED;
}

#undef VERIFY_NXDOM_PARAMS

static void
nxdom_detach(struct nxdom *nxdom)
{
	SK_LOCK_ASSERT_HELD();
	ASSERT(nxdom->nxdom_flags & NEXUSDOMF_ATTACHED);

	STAILQ_REMOVE(&nexus_domains, nxdom, nxdom, nxdom_link);
	nxdom->nxdom_flags &= ~NEXUSDOMF_ATTACHED;
}

static void
nxdom_init(struct nxdom *nxdom)
{
	ASSERT(nxdom->nxdom_flags & NEXUSDOMF_ATTACHED);

	SK_LOCK_ASSERT_HELD();

	if (!(nxdom->nxdom_flags & NEXUSDOMF_INITIALIZED)) {
		if (nxdom->nxdom_init != NULL) {
			nxdom->nxdom_init(nxdom);
		}
		nxdom->nxdom_flags |= NEXUSDOMF_INITIALIZED;
	}
}

static void
nxdom_terminate(struct nxdom *nxdom)
{
	ASSERT(nxdom->nxdom_flags & NEXUSDOMF_ATTACHED);

	SK_LOCK_ASSERT_HELD();

	if ((nxdom->nxdom_flags & NEXUSDOMF_INITIALIZED) &&
	    !(nxdom->nxdom_flags & NEXUSDOMF_TERMINATED)) {
		if (nxdom->nxdom_terminate != NULL) {
			nxdom->nxdom_terminate(nxdom);
		}
		nxdom->nxdom_flags |= NEXUSDOMF_TERMINATED;
	}
}

static void
nxdom_fini(struct nxdom *nxdom)
{
	ASSERT(nxdom->nxdom_flags & NEXUSDOMF_ATTACHED);

	if (nxdom->nxdom_flags & NEXUSDOMF_INITIALIZED) {
		if (nxdom->nxdom_fini != NULL) {
			nxdom->nxdom_fini(nxdom);
		}
		nxdom->nxdom_flags &= ~NEXUSDOMF_INITIALIZED;
	}
}

int
nxdom_prov_add(struct nxdom *nxdom,
    struct kern_nexus_domain_provider *nxdom_prov)
{
	struct kern_nexus_domain_provider *nxprov1;
	nexus_type_t type = nxdom->nxdom_type;
	boolean_t builtin;
	int err = 0;

	SK_LOCK_ASSERT_HELD();
	ASSERT(type < NEXUS_TYPE_MAX);

	builtin = !(nxdom_prov->nxdom_prov_flags & NXDOMPROVF_EXT);

	STAILQ_FOREACH(nxprov1, &nxdom->nxdom_prov_head, nxdom_prov_link) {
		/*
		 * We can be a little more strict in the kernel and
		 * avoid namespace collision (even though each domain
		 * provider has UUID; this also guarantees that external
		 * providers won't conflict with the builtin ones.
		 */
		if (strcmp(nxprov1->nxdom_prov_name,
		    nxdom_prov->nxdom_prov_name) == 0) {
			return EEXIST;
		}
	}

	VERIFY(!(nxdom_prov->nxdom_prov_flags & NXDOMPROVF_ATTACHED));
	VERIFY(!(nxdom_prov->nxdom_prov_flags & NXDOMPROVF_INITIALIZED));

	uuid_generate_random(nxdom_prov->nxdom_prov_uuid);
	nxdom_prov->nxdom_prov_dom = nxdom;
	if (nxdom_prov->nxdom_prov_init != NULL) {
		err = nxdom_prov->nxdom_prov_init(nxdom_prov);
	}

	if (err == 0) {
		nxdom_prov->nxdom_prov_flags |=
		    (NXDOMPROVF_ATTACHED | NXDOMPROVF_INITIALIZED);
		STAILQ_INSERT_TAIL(&nxdom->nxdom_prov_head, nxdom_prov,
		    nxdom_prov_link);
		/* for being in the list */
		nxdom_prov_retain_locked(nxdom_prov);

		if (nxdom_prov->nxdom_prov_flags & NXDOMPROVF_DEFAULT) {
			VERIFY(builtin && nxdom_prov_default[type] == NULL);
			nxdom_prov_default[type] = nxdom_prov;
			/* for being in the array */
			nxdom_prov_retain_locked(nxdom_prov);
		}

		SK_D("nxdom_prov 0x%llx (%s) dom %s",
		    SK_KVA(nxdom_prov), nxdom_prov->nxdom_prov_name,
		    nxdom->nxdom_name);
	} else {
		uuid_clear(nxdom_prov->nxdom_prov_uuid);
		nxdom_prov->nxdom_prov_dom = NULL;
	}

	return err;
}

void
nxdom_prov_del(struct kern_nexus_domain_provider *nxdom_prov)
{
	struct nxdom *nxdom = nxdom_prov->nxdom_prov_dom;
	nexus_type_t type = nxdom->nxdom_type;

	SK_LOCK_ASSERT_HELD();
	ASSERT(type < NEXUS_TYPE_MAX);
	ASSERT(nxdom_prov->nxdom_prov_flags & NXDOMPROVF_ATTACHED);

	if (nxdom_prov->nxdom_prov_flags & NXDOMPROVF_DETACHING) {
		return;
	}

	SK_D("nxdom_prov 0x%llx (%s:%s)", SK_KVA(nxdom_prov), nxdom->nxdom_name,
	    nxdom_prov->nxdom_prov_name);

	/* keep the reference around for the detaching list (see below) */
	STAILQ_REMOVE(&nxdom->nxdom_prov_head, nxdom_prov,
	    kern_nexus_domain_provider, nxdom_prov_link);
	nxdom_prov->nxdom_prov_flags &= ~NXDOMPROVF_ATTACHED;
	nxdom_prov->nxdom_prov_flags |= NXDOMPROVF_DETACHING;

	/* there can only be one default and it must match this one */
	if (nxdom_prov->nxdom_prov_flags & NXDOMPROVF_DEFAULT) {
		ASSERT(!(nxdom_prov->nxdom_prov_flags & NXDOMPROVF_EXT));
		VERIFY(nxdom_prov_default[type] == nxdom_prov);
		nxdom_prov_default[type] = NULL;
		/*
		 * Release reference held for the array; this must
		 * not be the last reference, as there is still at
		 * least one which we kept for the detaching list.
		 */
		VERIFY(!nxdom_prov_release_locked(nxdom_prov));
	}

	/* add to detaching list and wake up detacher */
	nxprov_detaching_enqueue(nxdom_prov);
}

static void
nxdom_del_provider_final(struct kern_nexus_domain_provider *nxdom_prov)
{
#if (DEBUG || DEVELOPMENT)
	struct nxdom *nxdom = nxdom_prov->nxdom_prov_dom;
#endif /* DEBUG || DEVELOPMENT */

	SK_LOCK_ASSERT_HELD();

	ASSERT((nxdom_prov->nxdom_prov_flags & (NXDOMPROVF_ATTACHED |
	    NXDOMPROVF_DETACHING)) == NXDOMPROVF_DETACHING);
	ASSERT(nxdom != NULL);

	SK_D("nxdom_prov 0x%llx (%s:%s)", SK_KVA(nxdom_prov), nxdom->nxdom_name,
	    nxdom_prov->nxdom_prov_name);

	nxdom_prov->nxdom_prov_flags &= ~NXDOMPROVF_DETACHING;

	/*
	 * Release reference held for detaching list; if this is the last
	 * reference, the domain provider's nxdom_prov_fini() callback will
	 * be called (if applicable) within the detacher thread's context.
	 * Otherwise, this will occur when the last nexus provider for that
	 * domain provider has been released.
	 */
	(void) nxdom_prov_release_locked(nxdom_prov);
}

struct nxdom *
nxdom_find(nexus_type_t type)
{
	struct nxdom *nxdom;

	SK_LOCK_ASSERT_HELD();
	ASSERT(type < NEXUS_TYPE_MAX);

	STAILQ_FOREACH(nxdom, &nexus_domains, nxdom_link) {
		if (nxdom->nxdom_type == type) {
			break;
		}
	}

	return nxdom;
}

struct kern_nexus_domain_provider *
nxdom_prov_find(const struct nxdom *nxdom, const char *name)
{
	struct kern_nexus_domain_provider *nxdom_prov = NULL;

	SK_LOCK_ASSERT_HELD();

	if (name != NULL) {
		STAILQ_FOREACH(nxdom_prov, &nxdom->nxdom_prov_head,
		    nxdom_prov_link) {
			if (strcmp(nxdom_prov->nxdom_prov_name, name) == 0) {
				break;
			}
		}
	}

	if (nxdom_prov != NULL) {
		nxdom_prov_retain_locked(nxdom_prov);   /* for caller */
	}
	return nxdom_prov;
}

struct kern_nexus_domain_provider *
nxdom_prov_find_uuid(const uuid_t dom_prov_uuid)
{
	struct kern_nexus_domain_provider *nxdom_prov = NULL;
	struct nxdom *nxdom;

	SK_LOCK_ASSERT_HELD();
	ASSERT(dom_prov_uuid != NULL && !uuid_is_null(dom_prov_uuid));

	STAILQ_FOREACH(nxdom, &nexus_domains, nxdom_link) {
		STAILQ_FOREACH(nxdom_prov, &nxdom->nxdom_prov_head,
		    nxdom_prov_link) {
			ASSERT(!uuid_is_null(nxdom_prov->nxdom_prov_uuid));
			if (uuid_compare(nxdom_prov->nxdom_prov_uuid,
			    dom_prov_uuid) == 0) {
				break;
			}
		}
		if (nxdom_prov != NULL) {
			nxdom_prov_retain_locked(nxdom_prov);   /* for caller */
			break;
		}
	}

	return nxdom_prov;
}

errno_t
kern_nexus_register_domain_provider(const nexus_type_t type,
    const nexus_domain_provider_name_t name,
    const struct kern_nexus_domain_provider_init *init,
    const uint32_t init_len, uuid_t *dom_prov_uuid)
{
	struct kern_nexus_domain_provider *nxdom_prov = NULL;
	struct nxdom *nxdom;
	errno_t err = 0;

	_CASSERT(sizeof(*init) == sizeof(nxdom_prov->nxdom_prov_ext));

	if (type >= NEXUS_TYPE_MAX || dom_prov_uuid == NULL) {
		return EINVAL;
	}

	uuid_clear(*dom_prov_uuid);

	if (name == NULL || init == NULL || init_len < sizeof(*init) ||
	    init->nxdpi_version != KERN_NEXUS_DOMAIN_PROVIDER_CURRENT_VERSION) {
		return EINVAL;
	}

	/*
	 * init, fini are required.
	 */
	if (init->nxdpi_init == NULL || init->nxdpi_fini == NULL) {
		return EINVAL;
	}

	SK_LOCK();
	if (nxdom_prov_default[type] == NULL) {
		err = ENXIO;
		goto done;
	}

	nxdom = nxdom_find(type);
	if (nxdom == NULL) {
		err = ENXIO;
		goto done;
	}

	/*
	 * Allow only kernel pipe and netif external domain providers for
	 * now, until we understand the implications and requirements for
	 * supporting other domain types.  For all other types, using
	 * the built-in domain providers and registering nexus should
	 * suffice.
	 */
	if (nxdom->nxdom_type != NEXUS_TYPE_KERNEL_PIPE &&
	    nxdom->nxdom_type != NEXUS_TYPE_NET_IF) {
		err = EINVAL;
		goto done;
	}

	nxdom_prov = nxdom_prov_alloc(Z_WAITOK);

	/*
	 * Point all callback routines to the default provider for this
	 * domain; for nxdom_prov{init,fini}, refer to externally-provided
	 * callback routines, if applicable.
	 */
	bcopy(init, &nxdom_prov->nxdom_prov_ext, sizeof(*init));
	bcopy(&nxdom_prov_default[type]->nxdom_prov_cb,
	    &nxdom_prov->nxdom_prov_cb, sizeof(struct nxdom_prov_cb));
	nxdom_prov->nxdom_prov_flags |= NXDOMPROVF_EXT;
	nxdom_prov->nxdom_prov_init = nxdom_prov_ext_init;
	nxdom_prov->nxdom_prov_fini = nxdom_prov_ext_fini;
	(void) snprintf(nxdom_prov->nxdom_prov_name,
	    sizeof(nxdom_prov->nxdom_prov_name), "%s", name);

	ASSERT(!(nxdom_prov->nxdom_prov_flags & NXDOMPROVF_DEFAULT));
	err = nxdom_prov_add(nxdom, nxdom_prov);
	if (err != 0) {
		nxdom_prov_free(nxdom_prov);
		nxdom_prov = NULL;
	}

done:
	if (nxdom_prov != NULL) {
		ASSERT(err == 0 && !uuid_is_null(nxdom_prov->nxdom_prov_uuid));
		uuid_copy(*dom_prov_uuid, nxdom_prov->nxdom_prov_uuid);
	}
	SK_UNLOCK();

	return err;
}

errno_t
kern_nexus_deregister_domain_provider(const uuid_t dom_prov_uuid)
{
	struct kern_nexus_domain_provider *nxdom_prov = NULL;
	errno_t err = 0;

	if (dom_prov_uuid == NULL || uuid_is_null(dom_prov_uuid)) {
		return EINVAL;
	}

	SK_LOCK();
	nxdom_prov = nxdom_prov_find_uuid(dom_prov_uuid);
	if (nxdom_prov == NULL) {
		err = ENXIO;
		goto done;
	}

	/* don't allow external request for built-in domain providers */
	if (!(nxdom_prov->nxdom_prov_flags & NXDOMPROVF_EXT)) {
		err = EINVAL;
		goto done;
	}

	/* schedule this to be deleted */
	nxdom_prov_del(nxdom_prov);
done:
	/* release reference from nxdom_prov_find_uuid */
	if (nxdom_prov != NULL) {
		(void) nxdom_prov_release_locked(nxdom_prov);
	}
	SK_UNLOCK();

	return err;
}

errno_t
kern_nexus_get_default_domain_provider(const nexus_type_t type,
    uuid_t *dom_prov_uuid)
{
	struct kern_nexus_domain_provider *nxdom_prov;

	if (type >= NEXUS_TYPE_MAX || dom_prov_uuid == NULL) {
		return EINVAL;
	}

	uuid_clear(*dom_prov_uuid);

	/* no lock is needed; array is immutable */
	if ((nxdom_prov = nxdom_prov_default[type]) == NULL) {
		return ENXIO;
	}

	uuid_copy(*dom_prov_uuid, nxdom_prov->nxdom_prov_uuid);

	return 0;
}

static int
nxdom_prov_ext_init(struct kern_nexus_domain_provider *nxdom_prov)
{
	int err = 0;

	SK_D("initializing %s", nxdom_prov->nxdom_prov_name);

	ASSERT(nxdom_prov->nxdom_prov_ext.nxdpi_init != NULL);
	if ((err = nxdom_prov->nxdom_prov_ext.nxdpi_init(nxdom_prov)) == 0) {
		nxdom_prov->nxdom_prov_flags |= NXDOMPROVF_EXT_INITED;
	}

	return err;
}

static void
nxdom_prov_ext_fini(struct kern_nexus_domain_provider *nxdom_prov)
{
	SK_D("destroying %s", nxdom_prov->nxdom_prov_name);

	if (nxdom_prov->nxdom_prov_flags & NXDOMPROVF_EXT_INITED) {
		ASSERT(nxdom_prov->nxdom_prov_ext.nxdpi_fini != NULL);
		nxdom_prov->nxdom_prov_ext.nxdpi_fini(nxdom_prov);
		nxdom_prov->nxdom_prov_flags &= ~NXDOMPROVF_EXT_INITED;
	}
}

static struct nexus_attr *
nxa_alloc(zalloc_flags_t how)
{
	return zalloc_flags(nxa_zone, how | Z_ZERO);
}

static void
nxa_free(struct nexus_attr *nxa)
{
	SK_DF(SK_VERB_MEM, "nxa 0x%llx FREE", SK_KVA(nxa));
	zfree(nxa_zone, nxa);
}

errno_t
kern_nexus_attr_create(nexus_attr_t *nxa)
{
	errno_t err = 0;

	if (nxa == NULL) {
		err = EINVAL;
	} else {
		*nxa = nxa_alloc(Z_WAITOK);
	}
	return err;
}

errno_t
kern_nexus_attr_clone(const nexus_attr_t nxa, nexus_attr_t *nnxa)
{
	errno_t err = 0;

	if (nnxa == NULL) {
		err = EINVAL;
	} else {
		err = kern_nexus_attr_create(nnxa);
		if (err == 0 && nxa != NULL) {
			ASSERT(*nnxa != NULL);
			bcopy(nxa, *nnxa, sizeof(**nnxa));
		}
	}
	return err;
}

errno_t
kern_nexus_attr_set(const nexus_attr_t nxa,
    const nexus_attr_type_t type, const uint64_t value)
{
	return __nexus_attr_set(nxa, type, value);
}

errno_t
kern_nexus_attr_get(nexus_attr_t nxa, const nexus_attr_type_t type,
    uint64_t *value)
{
	return __nexus_attr_get(nxa, type, value);
}

void
kern_nexus_attr_destroy(nexus_attr_t nxa)
{
	nxa_free(nxa);
}

static struct nexus_controller *
ncd_alloc(zalloc_flags_t how)
{
	return zalloc_flags(ncd_zone, how | Z_ZERO);
}

static void
ncd_free(struct nexus_controller *ncd)
{
	SK_DF(SK_VERB_MEM, "ncd 0x%llx FREE", SK_KVA(ncd));
	zfree(ncd_zone, ncd);
}

nexus_controller_t
kern_nexus_shared_controller(void)
{
	return &kernnxctl;
}

errno_t
kern_nexus_controller_create(nexus_controller_t *ncd)
{
	struct nxctl *nxctl = NULL;
	uuid_t nxctl_uuid;
	errno_t err = 0;

	uuid_generate_random(nxctl_uuid);

	if (ncd == NULL) {
		err = EINVAL;
		goto done;
	} else {
		*ncd = NULL;
	}

	nxctl = nxctl_create(kernproc, NULL, nxctl_uuid, &err);
	if (nxctl == NULL) {
		ASSERT(err != 0);
		goto done;
	}

	*ncd = ncd_alloc(Z_WAITOK);
	(*ncd)->ncd_nxctl = nxctl;      /* ref from nxctl_create */

done:
	if (err != 0) {
		if (nxctl != NULL) {
			nxctl_dtor(nxctl);
			nxctl = NULL;
		}
		if (ncd != NULL && *ncd != NULL) {
			ncd_free(*ncd);
			*ncd = NULL;
		}
	}

	return err;
}

#define NXPI_INVALID_CB_PAIRS(cb1, cb2)                                 \
	(!(init->nxpi_##cb1 == NULL && init->nxpi_##cb2 == NULL) &&     \
	((init->nxpi_##cb1 == NULL) ^ (init->nxpi_##cb2 == NULL)))

static errno_t
nexus_controller_register_provider_validate_init_params(
	const struct kern_nexus_provider_init *init, uint32_t init_len,
	nexus_type_t nxdom_type)
{
	errno_t err = 0;
	struct kern_nexus_netif_provider_init *netif_init;

	_CASSERT(__builtin_offsetof(struct kern_nexus_provider_init,
	    nxpi_version) == 0);
	_CASSERT(sizeof(init->nxpi_version) == sizeof(uint32_t));

	if (init == NULL) {
		return 0;
	}

	if (init_len < sizeof(uint32_t)) {
		return EINVAL;
	}

	switch (init->nxpi_version) {
	case KERN_NEXUS_PROVIDER_VERSION_1:
		if (init_len != sizeof(struct kern_nexus_provider_init)) {
			err = EINVAL;
			break;
		}
		/*
		 * sync_{tx,rx} callbacks are required; the rest of the
		 * callback pairs are optional, but must be symmetrical.
		 */
		if (init->nxpi_sync_tx == NULL || init->nxpi_sync_rx == NULL ||
		    init->nxpi_pre_connect == NULL ||
		    init->nxpi_connected == NULL ||
		    init->nxpi_pre_disconnect == NULL ||
		    init->nxpi_disconnected == NULL ||
		    NXPI_INVALID_CB_PAIRS(ring_init, ring_fini) ||
		    NXPI_INVALID_CB_PAIRS(slot_init, slot_fini)) {
			err = EINVAL;
			break;
		}
		/*
		 * Tx doorbell interface is only supported for netif and
		 * Tx doorbell is mandatory for netif
		 */
		if (((init->nxpi_tx_doorbell != NULL) &&
		    (nxdom_type != NEXUS_TYPE_NET_IF)) ||
		    ((nxdom_type == NEXUS_TYPE_NET_IF) &&
		    (init->nxpi_tx_doorbell == NULL))) {
			err = EINVAL;
			break;
		}
		/*
		 * Capabilities configuration interface is only supported for
		 * netif.
		 */
		if ((init->nxpi_config_capab != NULL) &&
		    (nxdom_type != NEXUS_TYPE_NET_IF)) {
			err = EINVAL;
			break;
		}
		break;

	case KERN_NEXUS_PROVIDER_VERSION_NETIF:
		if (init_len != sizeof(struct kern_nexus_netif_provider_init)) {
			err = EINVAL;
			break;
		}
		if (nxdom_type != NEXUS_TYPE_NET_IF) {
			err = EINVAL;
			break;
		}
		netif_init =
		    __DECONST(struct kern_nexus_netif_provider_init *, init);
		if (netif_init->nxnpi_pre_connect == NULL ||
		    netif_init->nxnpi_connected == NULL ||
		    netif_init->nxnpi_pre_disconnect == NULL ||
		    netif_init->nxnpi_disconnected == NULL ||
		    netif_init->nxnpi_qset_init == NULL ||
		    netif_init->nxnpi_qset_fini == NULL ||
		    netif_init->nxnpi_queue_init == NULL ||
		    netif_init->nxnpi_queue_fini == NULL ||
		    netif_init->nxnpi_tx_qset_notify == NULL ||
		    netif_init->nxnpi_config_capab == NULL) {
			err = EINVAL;
			break;
		}
		break;

	default:
		err = EINVAL;
		break;
	}
	return err;
}

errno_t
kern_nexus_controller_register_provider(const nexus_controller_t ncd,
    const uuid_t dom_prov_uuid, const nexus_name_t name,
    const struct kern_nexus_provider_init *init, uint32_t init_len,
    const nexus_attr_t nxa, uuid_t *prov_uuid)
{
	struct kern_nexus_domain_provider *nxdom_prov = NULL;
	struct kern_nexus_provider *nxprov = NULL;
	nexus_type_t nxdom_type;
	struct nxprov_reg reg;
	struct nxctl *nxctl;
	errno_t err = 0;

	if (prov_uuid == NULL) {
		return EINVAL;
	}

	uuid_clear(*prov_uuid);

	if (ncd == NULL ||
	    dom_prov_uuid == NULL || uuid_is_null(dom_prov_uuid)) {
		return EINVAL;
	}

	nxctl = ncd->ncd_nxctl;
	NXCTL_LOCK(nxctl);
	SK_LOCK();
	nxdom_prov = nxdom_prov_find_uuid(dom_prov_uuid);
	if (nxdom_prov == NULL) {
		SK_UNLOCK();
		err = ENXIO;
		goto done;
	}

	nxdom_type = nxdom_prov->nxdom_prov_dom->nxdom_type;
	ASSERT(nxdom_type < NEXUS_TYPE_MAX);

	err = nexus_controller_register_provider_validate_init_params(init,
	    init_len, nxdom_type);
	if (err != 0) {
		SK_UNLOCK();
		err = EINVAL;
		goto done;
	}

	if ((err = __nexus_provider_reg_prepare(&reg, name,
	    nxdom_type, nxa)) != 0) {
		SK_UNLOCK();
		goto done;
	}

	if (init && init->nxpi_version == KERN_NEXUS_PROVIDER_VERSION_NETIF) {
		reg.nxpreg_params.nxp_flags |= NXPF_NETIF_LLINK;
	}

	/* callee will hold reference on nxdom_prov upon success */
	if ((nxprov = nxprov_create_kern(nxctl, nxdom_prov, &reg,
	    init, &err)) == NULL) {
		SK_UNLOCK();
		ASSERT(err != 0);
		goto done;
	}
	SK_UNLOCK();

	uuid_copy(*prov_uuid, nxprov->nxprov_uuid);

done:
	SK_LOCK_ASSERT_NOTHELD();
	NXCTL_UNLOCK(nxctl);

	if (err != 0 && nxprov != NULL) {
		err = nxprov_close(nxprov, FALSE);
	}

	/* release extra ref from nxprov_create_kern */
	if (nxprov != NULL) {
		nxprov_release(nxprov);
	}
	/* release extra ref from nxdom_prov_find_uuid */
	if (nxdom_prov != NULL) {
		(void) nxdom_prov_release(nxdom_prov);
	}

	return err;
}

#undef NXPI_INVALID_CB_PAIRS

errno_t
kern_nexus_controller_deregister_provider(const nexus_controller_t ncd,
    const uuid_t prov_uuid)
{
	errno_t err;

	if (ncd == NULL || prov_uuid == NULL || uuid_is_null(prov_uuid)) {
		err = EINVAL;
	} else {
		struct nxctl *nxctl = ncd->ncd_nxctl;
		NXCTL_LOCK(nxctl);
		err = nxprov_destroy(nxctl, prov_uuid);
		NXCTL_UNLOCK(nxctl);
	}
	return err;
}

errno_t
kern_nexus_controller_alloc_provider_instance(const nexus_controller_t ncd,
    const uuid_t prov_uuid, const void *nx_ctx,
    nexus_ctx_release_fn_t nx_ctx_release, uuid_t *nx_uuid,
    const struct kern_nexus_init *init)
{
	struct kern_nexus *nx = NULL;
	struct nxctl *nxctl;
	errno_t err = 0;

	if (ncd == NULL || prov_uuid == NULL || uuid_is_null(prov_uuid) ||
	    nx_uuid == NULL || init == NULL ||
	    init->nxi_version != KERN_NEXUS_CURRENT_VERSION ||
	    (init->nxi_rx_pbufpool != NULL &&
	    init->nxi_rx_pbufpool != init->nxi_tx_pbufpool)) {
		err = EINVAL;
		goto done;
	}

	nxctl = ncd->ncd_nxctl;
	NXCTL_LOCK(nxctl);
	nx = nx_create(nxctl, prov_uuid, NEXUS_TYPE_UNDEFINED, nx_ctx,
	    nx_ctx_release, init->nxi_tx_pbufpool, init->nxi_rx_pbufpool, &err);
	NXCTL_UNLOCK(nxctl);
	if (nx == NULL) {
		ASSERT(err != 0);
		goto done;
	}
	ASSERT(err == 0);
	uuid_copy(*nx_uuid, nx->nx_uuid);

done:
	/* release extra ref from nx_create */
	if (nx != NULL) {
		(void) nx_release(nx);
	}

	return err;
}

errno_t
kern_nexus_controller_alloc_net_provider_instance(
	const nexus_controller_t ncd, const uuid_t prov_uuid, const void *nx_ctx,
	nexus_ctx_release_fn_t nx_ctx_release, uuid_t *nx_uuid,
	const struct kern_nexus_net_init *init, struct ifnet **pifp)
{
	struct kern_nexus *nx = NULL;
	struct ifnet *ifp = NULL;
	struct nxctl *nxctl;
	boolean_t nxctl_locked = FALSE;
	errno_t err = 0;

	if (ncd == NULL || prov_uuid == NULL || uuid_is_null(prov_uuid) ||
	    nx_uuid == NULL || init == NULL ||
	    init->nxneti_version != KERN_NEXUS_NET_CURRENT_VERSION ||
	    init->nxneti_eparams == NULL || pifp == NULL) {
		err = EINVAL;
		goto done;
	}

	/*
	 * Skywalk native interface doesn't support legacy model.
	 */
	if ((init->nxneti_eparams->start != NULL) ||
	    (init->nxneti_eparams->flags & IFNET_INIT_LEGACY) ||
	    (init->nxneti_eparams->flags & IFNET_INIT_INPUT_POLL)) {
		err = EINVAL;
		goto done;
	}

	/* create an embryonic ifnet */
	err = ifnet_allocate_extended(init->nxneti_eparams, &ifp);
	if (err != 0) {
		goto done;
	}

	nxctl = ncd->ncd_nxctl;
	NXCTL_LOCK(nxctl);
	nxctl_locked = TRUE;

	nx = nx_create(nxctl, prov_uuid, NEXUS_TYPE_NET_IF, nx_ctx,
	    nx_ctx_release, init->nxneti_tx_pbufpool, init->nxneti_rx_pbufpool,
	    &err);
	if (nx == NULL) {
		ASSERT(err != 0);
		goto done;
	}

	if (NX_LLINK_PROV(nx)) {
		if (init->nxneti_llink == NULL) {
			SK_ERR("logical link configuration required");
			err = EINVAL;
			goto done;
		}
		err = nx_netif_default_llink_config(NX_NETIF_PRIVATE(nx),
		    init->nxneti_llink);
		if (err != 0) {
			goto done;
		}
	}

	/* prepare this ifnet instance if needed */
	if (init->nxneti_prepare != NULL) {
		err = init->nxneti_prepare(nx, ifp);
		if (err != 0) {
			goto done;
		}
	}

	/* attach embryonic ifnet to nexus */
	err = _kern_nexus_ifattach(nxctl, nx->nx_uuid, ifp, NULL, FALSE, NULL);

	if (err != 0) {
		goto done;
	}

	/* and finalize the ifnet attach */
	ASSERT(nxctl_locked);
	NXCTL_UNLOCK(nxctl);
	nxctl_locked = FALSE;

	err = ifnet_attach(ifp, init->nxneti_lladdr);
	if (err != 0) {
		goto done;
	}

	ASSERT(err == 0);
	/*
	 * Return ifnet reference held by ifnet_allocate_extended();
	 * caller is expected to retain this reference until its ifnet
	 * detach callback is called.
	 */
	*pifp = ifp;
	uuid_copy(*nx_uuid, nx->nx_uuid);

done:
	if (nxctl_locked) {
		NXCTL_UNLOCK(nxctl);
	}

	/* release extra ref from nx_create */
	if (nx != NULL) {
		SK_LOCK();
		if (err != 0) {
			(void) nx_close(nx, TRUE);
		}
		(void) nx_release_locked(nx);
		SK_UNLOCK();
	}
	if (err != 0 && ifp != NULL) {
		ifnet_release(ifp);
	}

	return err;
}

errno_t
kern_nexus_controller_free_provider_instance(const nexus_controller_t ncd,
    const uuid_t nx_uuid)
{
	errno_t err;

	if (ncd == NULL || nx_uuid == NULL || uuid_is_null(nx_uuid)) {
		err = EINVAL;
	} else {
		struct nxctl *nxctl = ncd->ncd_nxctl;
		NXCTL_LOCK(nxctl);
		err = nx_destroy(nxctl, nx_uuid);
		NXCTL_UNLOCK(nxctl);
	}
	return err;
}

errno_t
kern_nexus_controller_bind_provider_instance(const nexus_controller_t ncd,
    const uuid_t nx_uuid, nexus_port_t *port, const pid_t pid,
    const uuid_t exec_uuid, const void *key, const uint32_t key_len,
    const uint32_t bind_flags)
{
	struct nx_bind_req nbr;
	struct sockopt sopt;
	struct nxctl *nxctl;
	int err = 0;

	if (ncd == NULL || nx_uuid == NULL || uuid_is_null(nx_uuid) ||
	    port == NULL) {
		return EINVAL;
	}

	__nexus_bind_req_prepare(&nbr, nx_uuid, *port, pid, exec_uuid,
	    key, key_len, bind_flags);

	bzero(&sopt, sizeof(sopt));
	sopt.sopt_dir = SOPT_SET;
	sopt.sopt_name = NXOPT_NEXUS_BIND;
	sopt.sopt_val = (user_addr_t)&nbr;
	sopt.sopt_valsize = sizeof(nbr);
	sopt.sopt_p = kernproc;

	nxctl = ncd->ncd_nxctl;
	NXCTL_LOCK(nxctl);
	err = nxctl_set_opt(nxctl, &sopt);
	NXCTL_UNLOCK(nxctl);

	if (err == 0) {
		*port = nbr.nb_port;
	}

	return err;
}

errno_t
kern_nexus_controller_unbind_provider_instance(const nexus_controller_t ncd,
    const uuid_t nx_uuid, const nexus_port_t port)
{
	struct nx_unbind_req nbu;
	struct sockopt sopt;
	struct nxctl *nxctl;
	int err = 0;

	if (ncd == NULL || nx_uuid == NULL || uuid_is_null(nx_uuid)) {
		return EINVAL;
	}

	__nexus_unbind_req_prepare(&nbu, nx_uuid, port);

	bzero(&sopt, sizeof(sopt));
	sopt.sopt_dir = SOPT_SET;
	sopt.sopt_name = NXOPT_NEXUS_UNBIND;
	sopt.sopt_val = (user_addr_t)&nbu;
	sopt.sopt_valsize = sizeof(nbu);
	sopt.sopt_p = kernproc;

	nxctl = ncd->ncd_nxctl;
	NXCTL_LOCK(nxctl);
	err = nxctl_set_opt(nxctl, &sopt);
	NXCTL_UNLOCK(nxctl);

	return err;
}

errno_t
kern_nexus_controller_read_provider_attr(const nexus_controller_t ncd,
    const uuid_t prov_uuid, nexus_attr_t nxa)
{
	struct nxprov_reg_ent nre;
	struct nxprov_params *p = &nre.npre_prov_params;
	struct sockopt sopt;
	struct nxctl *nxctl;
	int err = 0;

	if (ncd == NULL || prov_uuid == NULL || uuid_is_null(prov_uuid) ||
	    nxa == NULL) {
		return EINVAL;
	}

	bzero(&nre, sizeof(nre));
	bcopy(prov_uuid, nre.npre_prov_uuid, sizeof(uuid_t));

	bzero(&sopt, sizeof(sopt));
	sopt.sopt_dir = SOPT_GET;
	sopt.sopt_name = NXOPT_NEXUS_PROV_ENTRY;
	sopt.sopt_val = (user_addr_t)&nre;
	sopt.sopt_valsize = sizeof(nre);
	sopt.sopt_p = kernproc;

	nxctl = ncd->ncd_nxctl;
	NXCTL_LOCK(nxctl);
	err = nxctl_get_opt(nxctl, &sopt);
	NXCTL_UNLOCK(nxctl);

	if (err == 0) {
		__nexus_attr_from_params(nxa, p);
	}

	return err;
}

void
kern_nexus_controller_destroy(nexus_controller_t ncd)
{
	struct nxctl *nxctl;

	if (ncd == NULL) {
		return;
	}

	nxctl = ncd->ncd_nxctl;
	ASSERT(nxctl != NULL);
	ncd->ncd_nxctl = NULL;
	nxctl_dtor(nxctl);

	ncd_free(ncd);
}

void *
kern_nexus_get_context(const kern_nexus_t nx)
{
	return nx->nx_ctx;
}

void
kern_nexus_stop(const kern_nexus_t nx)
{
	SK_LOCK();
	nx_stop(nx);
	SK_UNLOCK();
}

errno_t
kern_nexus_get_pbufpool(const kern_nexus_t nx, kern_pbufpool_t *ptx_pp,
    kern_pbufpool_t *prx_pp)
{
	kern_pbufpool_t tpp = NULL, rpp = NULL;
	int err = 0;

	if (ptx_pp == NULL && prx_pp == NULL) {
		return EINVAL;
	}

	if (NX_DOM_PROV(nx)->nxdom_prov_nx_mem_info == NULL) {
		err = ENOTSUP;
	} else {
		err = NX_DOM_PROV(nx)->nxdom_prov_nx_mem_info(nx, &tpp, &rpp);
	}

	if (ptx_pp != NULL) {
		*ptx_pp = tpp;
	}
	if (prx_pp != NULL) {
		*prx_pp = rpp;
	}

	return err;
}

static int
_kern_nexus_ifattach(struct nxctl *nxctl, const uuid_t nx_uuid,
    struct ifnet *ifp, const uuid_t nx_uuid_attachee, boolean_t host,
    uuid_t *nx_if_uuid)
{
	struct nx_cfg_req ncr;
	struct nx_spec_req nsr;
	struct sockopt sopt;
	int err = 0;

	NXCTL_LOCK_ASSERT_HELD(nxctl);

	if (nx_uuid == NULL || uuid_is_null(nx_uuid)) {
		return EINVAL;
	}

	bzero(&nsr, sizeof(nsr));
	if (ifp != NULL) {
		if (nx_uuid_attachee != NULL) {
			return EINVAL;
		}

		nsr.nsr_flags = NXSPECREQ_IFP;
		nsr.nsr_ifp = ifp;
	} else {
		if (nx_uuid_attachee == NULL) {
			return EINVAL;
		}

		nsr.nsr_flags = NXSPECREQ_UUID;
		if (host) {
			nsr.nsr_flags |= NXSPECREQ_HOST;
		}

		uuid_copy(nsr.nsr_uuid, nx_uuid_attachee);
	}
	__nexus_config_req_prepare(&ncr, nx_uuid, NXCFG_CMD_ATTACH,
	    &nsr, sizeof(nsr));

	bzero(&sopt, sizeof(sopt));
	sopt.sopt_dir = SOPT_SET;
	sopt.sopt_name = NXOPT_NEXUS_CONFIG;
	sopt.sopt_val = (user_addr_t)&ncr;
	sopt.sopt_valsize = sizeof(ncr);
	sopt.sopt_p = kernproc;

	err = nxctl_set_opt(nxctl, &sopt);
	if (err == 0 && nx_if_uuid != NULL) {
		uuid_copy(*nx_if_uuid, nsr.nsr_if_uuid);
	}

	return err;
}

int
kern_nexus_ifattach(nexus_controller_t ncd, const uuid_t nx_uuid,
    struct ifnet *ifp, const uuid_t nx_uuid_attachee, boolean_t host,
    uuid_t *nx_if_uuid)
{
	struct nxctl *nxctl;
	int err = 0;

	if (ncd == NULL) {
		return EINVAL;
	}

	nxctl = ncd->ncd_nxctl;
	ASSERT(nxctl != NULL);
	NXCTL_LOCK(nxctl);
	err = _kern_nexus_ifattach(nxctl, nx_uuid, ifp, nx_uuid_attachee,
	    host, nx_if_uuid);
	NXCTL_UNLOCK(nxctl);

	return err;
}

int
kern_nexus_ifdetach(const nexus_controller_t ncd,
    const uuid_t nx_uuid, const uuid_t nx_if_uuid)
{
	struct nx_cfg_req ncr;
	struct nx_spec_req nsr;
	struct sockopt sopt;
	struct nxctl *nxctl;
	int err = 0;

	if (ncd == NULL || nx_uuid == NULL || uuid_is_null(nx_uuid) ||
	    nx_if_uuid == NULL || uuid_is_null(nx_if_uuid)) {
		return EINVAL;
	}

	bzero(&nsr, sizeof(nsr));
	uuid_copy(nsr.nsr_if_uuid, nx_if_uuid);

	__nexus_config_req_prepare(&ncr, nx_uuid, NXCFG_CMD_DETACH,
	    &nsr, sizeof(nsr));

	bzero(&sopt, sizeof(sopt));
	sopt.sopt_dir = SOPT_SET;
	sopt.sopt_name = NXOPT_NEXUS_CONFIG;
	sopt.sopt_val = (user_addr_t)&ncr;
	sopt.sopt_valsize = sizeof(ncr);
	sopt.sopt_p = kernproc;

	nxctl = ncd->ncd_nxctl;
	NXCTL_LOCK(nxctl);
	err = nxctl_set_opt(nxctl, &sopt);
	NXCTL_UNLOCK(nxctl);

	return err;
}

int
kern_nexus_get_netif_instance(struct ifnet *ifp, uuid_t nx_uuid)
{
	struct nexus_netif_adapter *if_na;
	int err = 0;

	SK_LOCK();
	if_na = ifp->if_na;
	if (if_na != NULL) {
		uuid_copy(nx_uuid, if_na->nifna_up.na_nx->nx_uuid);
	} else {
		err = ENXIO;
	}
	SK_UNLOCK();
	if (err != 0) {
		uuid_clear(nx_uuid);
	}

	return err;
}

int
kern_nexus_get_flowswitch_instance(struct ifnet *ifp, uuid_t nx_uuid)
{
	struct nexus_netif_adapter *if_na;
	struct nx_flowswitch *fsw = NULL;
	int err = 0;

	SK_LOCK();
	if_na = ifp->if_na;
	if (if_na != NULL) {
		fsw = ifp->if_na->nifna_netif->nif_fsw;
	}
	if (fsw != NULL) {
		uuid_copy(nx_uuid, fsw->fsw_nx->nx_uuid);
	} else {
		err = ENXIO;
	}
	SK_UNLOCK();
	if (err != 0) {
		uuid_clear(nx_uuid);
	}

	return err;
}

static void
kern_nexus_netagent_add(struct kern_nexus *nx, void *arg0)
{
#pragma unused(arg0)
	nx_fsw_netagent_add(nx);
}

static void
kern_nexus_netagent_remove(struct kern_nexus *nx, void *arg0)
{
#pragma unused(arg0)
	nx_fsw_netagent_remove(nx);
}

static void
kern_nexus_netagent_update(struct kern_nexus *nx, void *arg0)
{
#pragma unused(arg0)
	nx_fsw_netagent_update(nx);
}

void
kern_nexus_register_netagents(void)
{
	kern_nexus_walktree(kern_nexus_netagent_add, NULL, FALSE);
}

void
kern_nexus_deregister_netagents(void)
{
	kern_nexus_walktree(kern_nexus_netagent_remove, NULL, FALSE);
}

void
kern_nexus_update_netagents(void)
{
	kern_nexus_walktree(kern_nexus_netagent_update, NULL, FALSE);
}

static int
_interface_add_remove_netagent(struct ifnet *ifp, bool add)
{
	struct nexus_netif_adapter *if_na;
	int err = ENXIO;

	SK_LOCK();
	if_na = ifp->if_na;
	if (if_na != NULL) {
		struct nx_flowswitch *fsw;

		fsw = if_na->nifna_netif->nif_fsw;
		if (fsw != NULL) {
			if (add) {
				err = nx_fsw_netagent_add(fsw->fsw_nx);
			} else {
				err = nx_fsw_netagent_remove(fsw->fsw_nx);
			}
		}
	}
	SK_UNLOCK();
	return err;
}

int
kern_nexus_interface_add_netagent(struct ifnet *ifp)
{
	return _interface_add_remove_netagent(ifp, true);
}

int
kern_nexus_interface_remove_netagent(struct ifnet *ifp)
{
	return _interface_add_remove_netagent(ifp, false);
}

int
kern_nexus_set_netif_input_tbr_rate(struct ifnet *ifp, uint64_t rate)
{
	/* input tbr is only functional with active netif attachment */
	if (ifp->if_na == NULL) {
		if (rate != 0) {
			return EINVAL;
		} else {
			return 0;
		}
	}

	ifp->if_na->nifna_netif->nif_input_rate = rate;
	return 0;
}

int
kern_nexus_set_if_netem_params(const nexus_controller_t ncd,
    const uuid_t nx_uuid, void *data, size_t data_len)
{
	struct nx_cfg_req ncr;
	struct sockopt sopt;
	struct nxctl *nxctl;
	int err = 0;

	if (nx_uuid == NULL || uuid_is_null(nx_uuid) ||
	    data_len < sizeof(struct if_netem_params)) {
		return EINVAL;
	}

	__nexus_config_req_prepare(&ncr, nx_uuid, NXCFG_CMD_NETEM,
	    data, data_len);
	bzero(&sopt, sizeof(sopt));
	sopt.sopt_dir = SOPT_SET;
	sopt.sopt_name = NXOPT_NEXUS_CONFIG;
	sopt.sopt_val = (user_addr_t)&ncr;
	sopt.sopt_valsize = sizeof(ncr);
	sopt.sopt_p = kernproc;

	nxctl = ncd->ncd_nxctl;
	NXCTL_LOCK(nxctl);
	err = nxctl_set_opt(nxctl, &sopt);
	NXCTL_UNLOCK(nxctl);

	return err;
}

static int
_kern_nexus_flow_config(const nexus_controller_t ncd, const uuid_t nx_uuid,
    const nxcfg_cmd_t cmd, void *data, size_t data_len)
{
	struct nx_cfg_req ncr;
	struct sockopt sopt;
	struct nxctl *nxctl;
	int err = 0;

	if (nx_uuid == NULL || uuid_is_null(nx_uuid) ||
	    data_len < sizeof(struct nx_flow_req)) {
		return EINVAL;
	}

	__nexus_config_req_prepare(&ncr, nx_uuid, cmd, data, data_len);

	bzero(&sopt, sizeof(sopt));
	sopt.sopt_dir = SOPT_SET;
	sopt.sopt_name = NXOPT_NEXUS_CONFIG;
	sopt.sopt_val = (user_addr_t)&ncr;
	sopt.sopt_valsize = sizeof(ncr);
	sopt.sopt_p = kernproc;

	nxctl = ncd->ncd_nxctl;
	NXCTL_LOCK(nxctl);
	err = nxctl_set_opt(nxctl, &sopt);
	NXCTL_UNLOCK(nxctl);

	return err;
}

int
kern_nexus_flow_add(const nexus_controller_t ncd, const uuid_t nx_uuid,
    void *data, size_t data_len)
{
	return _kern_nexus_flow_config(ncd, nx_uuid, NXCFG_CMD_FLOW_ADD, data,
	           data_len);
}

int
kern_nexus_flow_del(const nexus_controller_t ncd, const uuid_t nx_uuid,
    void *data, size_t data_len)
{
	return _kern_nexus_flow_config(ncd, nx_uuid, NXCFG_CMD_FLOW_DEL, data,
	           data_len);
}

static struct kern_nexus_domain_provider *
nxdom_prov_alloc(zalloc_flags_t how)
{
	SK_LOCK_ASSERT_HELD();

	return zalloc_flags(nxdom_prov_zone, how | Z_ZERO);
}

static void
nxdom_prov_free(struct kern_nexus_domain_provider *nxdom_prov)
{
	SK_LOCK_ASSERT_HELD();

	ASSERT(nxdom_prov->nxdom_prov_refcnt == 0);
	ASSERT(!(nxdom_prov->nxdom_prov_flags &
	    (NXDOMPROVF_ATTACHED | NXDOMPROVF_DETACHING)));

	if (nxdom_prov->nxdom_prov_flags & NXDOMPROVF_INITIALIZED) {
		/*
		 * Tell the domain provider that we're done with this
		 * instance, and it is now free to go away.
		 */
		if (nxdom_prov->nxdom_prov_fini != NULL) {
			nxdom_prov->nxdom_prov_fini(nxdom_prov);
		}
		nxdom_prov->nxdom_prov_flags &= ~NXDOMPROVF_INITIALIZED;
	}
	uuid_clear(nxdom_prov->nxdom_prov_uuid);
	nxdom_prov->nxdom_prov_dom = NULL;

	SK_DF(SK_VERB_MEM, "nxdom_prov 0x%llx %s", SK_KVA(nxdom_prov),
	    ((nxdom_prov->nxdom_prov_flags & NXDOMPROVF_EXT) ?
	    "FREE" : "DESTROY"));
	if (nxdom_prov->nxdom_prov_flags & NXDOMPROVF_EXT) {
		zfree(nxdom_prov_zone, nxdom_prov);
	}
}

void
nxdom_prov_retain_locked(struct kern_nexus_domain_provider *nxdom_prov)
{
	SK_LOCK_ASSERT_HELD();

	nxdom_prov->nxdom_prov_refcnt++;
	ASSERT(nxdom_prov->nxdom_prov_refcnt != 0);
}

void
nxdom_prov_retain(struct kern_nexus_domain_provider *nxdom_prov)
{
	SK_LOCK();
	nxdom_prov_retain_locked(nxdom_prov);
	SK_UNLOCK();
}

static int
nxdom_prov_params_default(struct kern_nexus_domain_provider *nxdom_prov,
    const uint32_t req, const struct nxprov_params *nxp0,
    struct nxprov_params *nxp, struct skmem_region_params srp[SKMEM_REGIONS])
{
	struct nxdom *nxdom = nxdom_prov->nxdom_prov_dom;

	return nxprov_params_adjust(nxdom_prov, req, nxp0, nxp, srp,
	           nxdom, nxdom, nxdom, NULL);
}

int
nxdom_prov_validate_params(struct kern_nexus_domain_provider *nxdom_prov,
    const struct nxprov_reg *reg, struct nxprov_params *nxp,
    struct skmem_region_params srp[SKMEM_REGIONS], const uint32_t oflags)
{
	const struct nxprov_params *nxp0 = &reg->nxpreg_params;
	const uint32_t req = reg->nxpreg_requested;
	int i, err = 0;

	ASSERT(reg->nxpreg_version == NXPROV_REG_CURRENT_VERSION &&
	    nxp0->nxp_namelen != 0 &&
	    nxp0->nxp_namelen <= sizeof(nexus_name_t));

	/* fill in with default values and let the nexus override them */
	bzero(nxp, sizeof(*nxp));
	bcopy(&nxp0->nxp_name, &nxp->nxp_name, sizeof(nxp->nxp_name));
	nxp->nxp_name[sizeof(nxp->nxp_name) - 1] = '\0';
	nxp->nxp_namelen = nxp0->nxp_namelen;
	nxp->nxp_type = nxp0->nxp_type;
	nxp->nxp_md_type = nxdom_prov->nxdom_prov_dom->nxdom_md_type;
	nxp->nxp_md_subtype = nxdom_prov->nxdom_prov_dom->nxdom_md_subtype;
	nxp->nxp_flags = (nxp0->nxp_flags & NXPF_MASK);
	nxp->nxp_flags |= oflags;       /* override */
	nxp->nxp_format = nxp0->nxp_format;
	nxp->nxp_ifindex = nxp0->nxp_ifindex;
	nxp->nxp_reject_on_close = nxp0->nxp_reject_on_close;

	/* inherit default region parameters */
	for (i = 0; i < SKMEM_REGIONS; i++) {
		srp[i] = *skmem_get_default(i);
	}

	if (nxdom_prov->nxdom_prov_params != NULL) {
		err = nxdom_prov->nxdom_prov_params(nxdom_prov, req, nxp0,
		    nxp, srp);
	} else {
		err = nxdom_prov_params_default(nxdom_prov, req, nxp0,
		    nxp, srp);
	}
	return err;
}

boolean_t
nxdom_prov_release_locked(struct kern_nexus_domain_provider *nxdom_prov)
{
	int oldref = nxdom_prov->nxdom_prov_refcnt;

	SK_LOCK_ASSERT_HELD();

	ASSERT(nxdom_prov->nxdom_prov_refcnt != 0);
	if (--nxdom_prov->nxdom_prov_refcnt == 0) {
		nxdom_prov_free(nxdom_prov);
	}

	return oldref == 1;
}

boolean_t
nxdom_prov_release(struct kern_nexus_domain_provider *nxdom_prov)
{
	boolean_t lastref;

	SK_LOCK();
	lastref = nxdom_prov_release_locked(nxdom_prov);
	SK_UNLOCK();

	return lastref;
}

static uint32_t
nxprov_bound_var(uint32_t *v, uint32_t dflt, uint32_t lo, uint32_t hi,
    const char *msg)
{
#pragma unused(msg)
	uint32_t oldv = *v;
	const char *op = NULL;

	if (dflt < lo) {
		dflt = lo;
	}
	if (dflt > hi) {
		dflt = hi;
	}
	if (oldv < lo) {
		*v = dflt;
		op = "bump";
	} else if (oldv > hi) {
		*v = hi;
		op = "clamp";
	}
#if SK_LOG
	if (op != NULL && msg != NULL) {
		SK_ERR("%s %s to %u (was %u)", op, msg, *v, oldv);
	}
#endif /* SK_LOG */
	return *v;
}

#define NXPROV_PARAMS_ADJUST(flag, param) do {                          \
	uint32_t _v0, _v;                                               \
	if (req & (flag))                                               \
	        _v = nxp0->nxp_##param;                                 \
	else                                                            \
	        _v = NXDOM_DEF(nxdom_def, param);                       \
	_v0 = _v;                                                       \
	if (nxprov_bound_var(&_v, NXDOM_DEF(nxdom_def, param),          \
	    NXDOM_MIN(nxdom_min, param), NXDOM_MAX(nxdom_max, param),   \
	    "nxp_" #param) < _v0) {                                     \
	        err = ENOMEM;                                           \
	        goto error;                                             \
	}                                                               \
	nxp->nxp_##param = _v;                                          \
} while (0)

#define MUL(x, y, z) do {                                               \
	if (__builtin_mul_overflow((x), (y), (z))) {                    \
	        overflowline = __LINE__;                                \
	        goto error;                                             \
	}                                                               \
} while (0)

#define ADD(x, y, z) do {                                               \
	if (__builtin_add_overflow((x), (y), (z))) {                    \
	        overflowline = __LINE__;                                \
	        goto error;                                             \
	}                                                               \
} while (0)

int
nxprov_params_adjust(struct kern_nexus_domain_provider *nxdom_prov,
    const uint32_t req, const struct nxprov_params *nxp0,
    struct nxprov_params *nxp, struct skmem_region_params srp[SKMEM_REGIONS],
    const struct nxdom *nxdom_def, const struct nxdom *nxdom_min,
    const struct nxdom *nxdom_max,
    int (*adjust_fn)(const struct kern_nexus_domain_provider *,
    const struct nxprov_params *, struct nxprov_adjusted_params *))
{
	uint32_t buf_cnt;
	uint32_t stats_size;
	uint32_t flowadv_max;
	uint32_t nexusadv_size;
	uint32_t capabs;
	uint32_t tx_rings, rx_rings, alloc_rings = 0, free_rings = 0, ev_rings = 0;
	uint32_t tx_slots, rx_slots, alloc_slots = 0, free_slots = 0, ev_slots = 0;
	uint32_t buf_size, max_buffers = 0;
	uint32_t tmp1, tmp2, tmp3, tmp4xpipes, tmpsumrings;
	uint32_t tmpsumall, tmp4xpipesplusrings;
	boolean_t md_magazines;
	int overflowline = 0;
	struct skmem_region_params *ubft_srp = NULL;
	struct skmem_region_params *kbft_srp = NULL;
	int err = 0;

	NXPROV_PARAMS_ADJUST(NXPREQ_TX_RINGS, tx_rings);
	NXPROV_PARAMS_ADJUST(NXPREQ_RX_RINGS, rx_rings);
	NXPROV_PARAMS_ADJUST(NXPREQ_TX_SLOTS, tx_slots);
	NXPROV_PARAMS_ADJUST(NXPREQ_RX_SLOTS, rx_slots);
	NXPROV_PARAMS_ADJUST(NXPREQ_BUF_SIZE, buf_size);
	NXPROV_PARAMS_ADJUST(NXPREQ_STATS_SIZE, stats_size);
	NXPROV_PARAMS_ADJUST(NXPREQ_FLOWADV_MAX, flowadv_max);
	NXPROV_PARAMS_ADJUST(NXPREQ_NEXUSADV_SIZE, nexusadv_size);
	NXPROV_PARAMS_ADJUST(NXPREQ_PIPES, pipes);
	NXPROV_PARAMS_ADJUST(NXPREQ_EXTENSIONS, extensions);
	NXPROV_PARAMS_ADJUST(NXPREQ_MHINTS, mhints);
	NXPROV_PARAMS_ADJUST(NXPREQ_CAPABILITIES, capabilities);
	NXPROV_PARAMS_ADJUST(NXPREQ_QMAP, qmap);
	NXPROV_PARAMS_ADJUST(NXPREQ_MAX_FRAGS, max_frags);

	capabs = NXDOM_DEF(nxdom_def, capabilities);
	if (req & NXPREQ_USER_CHANNEL) {
		if (nxp->nxp_flags & NXPF_USER_CHANNEL) {
			capabs |= NXPCAP_USER_CHANNEL;
		} else {
			capabs &= ~NXPCAP_USER_CHANNEL;
		}
	} else {
		if (capabs & NXPCAP_USER_CHANNEL) {
			nxp->nxp_flags |= NXPF_USER_CHANNEL;
		} else {
			nxp->nxp_flags &= ~NXPF_USER_CHANNEL;
		}
	}

	if (NXDOM_MIN(nxdom_min, capabilities) != 0 &&
	    !(capabs & NXDOM_MIN(nxdom_min, capabilities))) {
		SK_ERR("%s: caps 0x%b < min 0x%b",
		    nxdom_prov->nxdom_prov_name, capabs, NXPCAP_BITS,
		    NXDOM_MIN(nxdom_min, capabilities), NXPCAP_BITS);
		err = EINVAL;
		goto error;
	} else if (NXDOM_MAX(nxdom_max, capabilities) != 0 &&
	    (capabs & ~NXDOM_MAX(nxdom_max, capabilities))) {
		SK_ERR("%s: caps 0x%b > max 0x%b",
		    nxdom_prov->nxdom_prov_name, capabs, NXPCAP_BITS,
		    NXDOM_MAX(nxdom_max, capabilities), NXPCAP_BITS);
		err = EINVAL;
		goto error;
	}

	stats_size = nxp->nxp_stats_size;
	flowadv_max = nxp->nxp_flowadv_max;
	nexusadv_size = nxp->nxp_nexusadv_size;
	tx_rings = nxp->nxp_tx_rings;
	rx_rings = nxp->nxp_rx_rings;
	tx_slots = nxp->nxp_tx_slots;
	rx_slots = nxp->nxp_rx_slots;
	buf_size = nxp->nxp_buf_size;

	ASSERT((srp[SKMEM_REGION_UMD].srp_cflags & SKMEM_REGION_CR_NOMAGAZINES) ==
	    (srp[SKMEM_REGION_RXKMD].srp_cflags & SKMEM_REGION_CR_NOMAGAZINES));
	md_magazines = !(srp[SKMEM_REGION_UMD].srp_cflags &
	    SKMEM_REGION_CR_NOMAGAZINES);

	if (adjust_fn != NULL) {
		struct nxprov_adjusted_params adj = {
			.adj_md_subtype = &nxp->nxp_md_subtype,
			.adj_md_magazines = &md_magazines,
			.adj_stats_size = &stats_size,
			.adj_flowadv_max = &flowadv_max,
			.adj_nexusadv_size = &nexusadv_size,
			.adj_caps = &capabs,
			.adj_tx_rings = &tx_rings,
			.adj_rx_rings = &rx_rings,
			.adj_tx_slots = &tx_slots,
			.adj_rx_slots = &rx_slots,
			.adj_alloc_rings = &alloc_rings,
			.adj_free_rings = &free_rings,
			.adj_alloc_slots = &alloc_slots,
			.adj_free_slots = &free_slots,
			.adj_buf_size = &buf_size,
			.adj_buf_srp = &srp[SKMEM_REGION_BUF],
			.adj_max_frags = &nxp->nxp_max_frags,
			.adj_event_rings = &ev_rings,
			.adj_event_slots = &ev_slots,
			.adj_max_buffers = &max_buffers,
		};
		err = adjust_fn(nxdom_prov, nxp, &adj);
		if (err != 0) {
			goto error;
		}

		ASSERT(capabs >= NXDOM_MIN(nxdom_min, capabilities));
		ASSERT(capabs <= NXDOM_MAX(nxdom_max, capabilities));
	}

	if (nxp->nxp_max_frags > UINT16_MAX) {
		SK_ERR("invalid configuration for max frags %d",
		    nxp->nxp_max_frags);
		err = EINVAL;
	}

	if (nxp->nxp_type == NEXUS_TYPE_USER_PIPE) {
		if (tx_rings != rx_rings) {
			SK_ERR("invalid configuration: {rx,tx} rings must be"
			    "in pairs for user pipe rx_rings(%d) tx_rings(%d)",
			    rx_rings, tx_rings);
			err = EINVAL;
		}
	} else {
		if (nxp->nxp_pipes != 0) {
			SK_ERR("invalid configuration: pipe configuration is"
			    "only valid for user pipe nexus, type %d, pipes %d",
			    nxp->nxp_type, nxp->nxp_pipes);
			err = EINVAL;
		}
	}
	if (err != 0) {
		goto error;
	}

	/* leading and trailing guard pages (if applicable) */
	if (sk_guard) {
		srp[SKMEM_REGION_GUARD_HEAD].srp_r_obj_size = SKMEM_PAGE_SIZE;
		srp[SKMEM_REGION_GUARD_HEAD].srp_r_obj_cnt = sk_headguard_sz;
		skmem_region_params_config(&srp[SKMEM_REGION_GUARD_HEAD]);
		srp[SKMEM_REGION_GUARD_TAIL].srp_r_obj_size = SKMEM_PAGE_SIZE;
		srp[SKMEM_REGION_GUARD_TAIL].srp_r_obj_cnt = sk_tailguard_sz;
		skmem_region_params_config(&srp[SKMEM_REGION_GUARD_TAIL]);
	} else {
		srp[SKMEM_REGION_GUARD_HEAD].srp_r_obj_size = 0;
		srp[SKMEM_REGION_GUARD_HEAD].srp_r_obj_cnt = 0;
		srp[SKMEM_REGION_GUARD_TAIL].srp_r_obj_size = 0;
		srp[SKMEM_REGION_GUARD_TAIL].srp_r_obj_cnt = 0;
	}

	/* update to the adjusted/configured values */
	nxp->nxp_buf_size = buf_size;
	nxp->nxp_tx_slots = tx_slots;
	nxp->nxp_rx_slots = rx_slots;

	SK_D("nxdom \"%s\" (0x%llx) type %d",
	    nxdom_prov->nxdom_prov_dom->nxdom_name,
	    SK_KVA(nxdom_prov->nxdom_prov_dom),
	    nxdom_prov->nxdom_prov_dom->nxdom_type);
	SK_D("nxp \"%s\" (0x%llx) flags 0x%b",
	    nxp->nxp_name, SK_KVA(nxp), nxp->nxp_flags, NXPF_BITS);
	SK_D("  req 0x%b rings %u/%u/%u/%u/%u slots %u/%u/%u/%u/%u buf %u "
	    "type %u subtype %u stats %u flowadv_max %u nexusadv_size %u "
	    "capabs 0x%b pipes %u extensions %u max_frags %u headguard %u "
	    "tailguard %u", req, NXPREQ_BITS, tx_rings, rx_rings, alloc_rings,
	    free_rings, ev_rings, tx_slots, rx_slots, alloc_slots, free_slots,
	    ev_slots, nxp->nxp_buf_size, nxp->nxp_md_type, nxp->nxp_md_subtype,
	    stats_size, flowadv_max, nexusadv_size, capabs, NXPCAP_BITS,
	    nxp->nxp_pipes, nxp->nxp_extensions, nxp->nxp_max_frags,
	    srp[SKMEM_REGION_GUARD_HEAD].srp_r_obj_size *
	    srp[SKMEM_REGION_GUARD_HEAD].srp_r_obj_cnt,
	    srp[SKMEM_REGION_GUARD_TAIL].srp_r_obj_size *
	    srp[SKMEM_REGION_GUARD_TAIL].srp_r_obj_cnt);

	/*
	 * tmp4xpipes = 4 * nxp->nxp_pipes
	 */
	MUL(4, nxp->nxp_pipes, &tmp4xpipes);

	/*
	 * tmp4xpipesplusrings = tx_rings + (4 * nxp->nxp_pipes)
	 */
	VERIFY((tmp4xpipes == 0) || (rx_rings == tx_rings));
	ADD(tx_rings, tmp4xpipes, &tmp4xpipesplusrings);

	/*
	 * tmpsumrings = tx_rings + rx_rings + alloc_rings + free_rings + ev_rings
	 */
	ADD(tx_rings, rx_rings, &tmpsumrings);
	ADD(tmpsumrings, alloc_rings, &tmpsumrings);
	ADD(tmpsumrings, free_rings, &tmpsumrings);
	ADD(tmpsumrings, ev_rings, &tmpsumrings);

	/*
	 * tmpsumall = (tx_rings + rx_rings +
	 *	alloc_rings + free_rings + ev_rings + (4 * nxp->nxp_pipes))
	 */
	ADD(tmpsumrings, tmp4xpipes, &tmpsumall);

	/* possibly increase them to fit user request */
	VERIFY(CHANNEL_SCHEMA_SIZE(tmpsumrings) <= UINT32_MAX);
	srp[SKMEM_REGION_SCHEMA].srp_r_obj_size =
	    (uint32_t)CHANNEL_SCHEMA_SIZE(tmpsumrings);
	/* worst case is one channel bound to each ring pair */
	srp[SKMEM_REGION_SCHEMA].srp_r_obj_cnt = tmp4xpipesplusrings;

	skmem_region_params_config(&srp[SKMEM_REGION_SCHEMA]);

	srp[SKMEM_REGION_RING].srp_r_obj_size =
	    sizeof(struct __user_channel_ring);
	/* each pipe endpoint needs two tx rings and two rx rings */
	srp[SKMEM_REGION_RING].srp_r_obj_cnt = tmpsumall;
	skmem_region_params_config(&srp[SKMEM_REGION_RING]);

	/*
	 * For each pipe we only need the buffers for the "real" rings.
	 * On the other end, the pipe ring dimension may be different from
	 * the parent port ring dimension. As a compromise, we allocate twice
	 * the space actually needed if the pipe rings were the same size as
	 * the parent rings.
	 *
	 * buf_cnt = ((4 * nxp->nxp_pipes) + rx_rings) * rx_slots +
	 *	((4 * nxp->nxp_pipes) + tx_rings) * tx_slots +
	 *	(ev_rings * ev_slots);
	 */
	if (nxp->nxp_type == NEXUS_TYPE_USER_PIPE) {
		MUL(tmp4xpipesplusrings, rx_slots, &tmp1);
		MUL(tmp4xpipesplusrings, tx_slots, &tmp2);
		ASSERT(ev_rings == 0);
		tmp3 = 0;
	} else {
		MUL(rx_rings, rx_slots, &tmp1);
		MUL(tx_rings, tx_slots, &tmp2);
		MUL(ev_rings, ev_slots, &tmp3);
	}
	ADD(tmp1, tmp2, &buf_cnt);
	ADD(tmp3, buf_cnt, &buf_cnt);

	if (nxp->nxp_max_frags > 1) {
		buf_cnt = MIN((((uint32_t)P2ROUNDUP(NX_MAX_AGGR_PKT_SIZE,
		    nxp->nxp_buf_size) / nxp->nxp_buf_size) * buf_cnt),
		    (buf_cnt * nxp->nxp_max_frags));
	}

	if (max_buffers != 0) {
		buf_cnt = MIN(max_buffers, buf_cnt);
	}

	/* enable/disable magazines layer on metadata regions */
	if (md_magazines) {
		srp[SKMEM_REGION_UMD].srp_cflags &=
		    ~SKMEM_REGION_CR_NOMAGAZINES;
		srp[SKMEM_REGION_KMD].srp_cflags &=
		    ~SKMEM_REGION_CR_NOMAGAZINES;
	} else {
		srp[SKMEM_REGION_UMD].srp_cflags |=
		    SKMEM_REGION_CR_NOMAGAZINES;
		srp[SKMEM_REGION_KMD].srp_cflags |=
		    SKMEM_REGION_CR_NOMAGAZINES;
	}

	if (nxp->nxp_max_frags > 1) {
		kbft_srp = &srp[SKMEM_REGION_KBFT];
		kbft_srp->srp_cflags &= ~SKMEM_REGION_CR_NOMAGAZINES;
	}
	if ((kbft_srp != NULL) && (nxp->nxp_flags & NXPF_USER_CHANNEL)) {
		ubft_srp = &srp[SKMEM_REGION_UBFT];
		ubft_srp->srp_cflags &= ~SKMEM_REGION_CR_NOMAGAZINES;
	}

	/* # of metadata objects is same as the # of buffer objects */
	pp_regions_params_adjust(&srp[SKMEM_REGION_BUF], &srp[SKMEM_REGION_KMD],
	    &srp[SKMEM_REGION_UMD], kbft_srp, ubft_srp, nxp->nxp_md_type,
	    nxp->nxp_md_subtype, buf_cnt, (uint16_t)nxp->nxp_max_frags,
	    nxp->nxp_buf_size, buf_cnt);

	/* statistics region size */
	if (stats_size != 0) {
		srp[SKMEM_REGION_USTATS].srp_r_obj_size = stats_size;
		srp[SKMEM_REGION_USTATS].srp_r_obj_cnt = 1;
		skmem_region_params_config(&srp[SKMEM_REGION_USTATS]);
	} else {
		srp[SKMEM_REGION_USTATS].srp_r_obj_size = 0;
		srp[SKMEM_REGION_USTATS].srp_r_obj_cnt = 0;
		srp[SKMEM_REGION_USTATS].srp_c_obj_size = 0;
		srp[SKMEM_REGION_USTATS].srp_c_obj_cnt = 0;
	}

	/* flow advisory region size */
	if (flowadv_max != 0) {
		MUL(sizeof(struct __flowadv_entry), flowadv_max, &tmp1);
		srp[SKMEM_REGION_FLOWADV].srp_r_obj_size = tmp1;
		srp[SKMEM_REGION_FLOWADV].srp_r_obj_cnt = 1;
		skmem_region_params_config(&srp[SKMEM_REGION_FLOWADV]);
	} else {
		srp[SKMEM_REGION_FLOWADV].srp_r_obj_size = 0;
		srp[SKMEM_REGION_FLOWADV].srp_r_obj_cnt = 0;
		srp[SKMEM_REGION_FLOWADV].srp_c_obj_size = 0;
		srp[SKMEM_REGION_FLOWADV].srp_c_obj_cnt = 0;
	}

	/* nexus advisory region size */
	if (nexusadv_size != 0) {
		srp[SKMEM_REGION_NEXUSADV].srp_r_obj_size = nexusadv_size +
		    sizeof(struct __kern_nexus_adv_metadata);
		srp[SKMEM_REGION_NEXUSADV].srp_r_obj_cnt = 1;
		skmem_region_params_config(&srp[SKMEM_REGION_NEXUSADV]);
	} else {
		srp[SKMEM_REGION_NEXUSADV].srp_r_obj_size = 0;
		srp[SKMEM_REGION_NEXUSADV].srp_r_obj_cnt = 0;
		srp[SKMEM_REGION_NEXUSADV].srp_c_obj_size = 0;
		srp[SKMEM_REGION_NEXUSADV].srp_c_obj_cnt = 0;
	}

	/* sysctls region is not applicable to nexus */
	srp[SKMEM_REGION_SYSCTLS].srp_r_obj_size = 0;
	srp[SKMEM_REGION_SYSCTLS].srp_r_obj_cnt = 0;
	srp[SKMEM_REGION_SYSCTLS].srp_c_obj_size = 0;
	srp[SKMEM_REGION_SYSCTLS].srp_c_obj_cnt = 0;

	/*
	 * Since the tx/alloc/event slots share the same region and cache,
	 * we will use the same object size for both types of slots.
	 */
	srp[SKMEM_REGION_TXAKSD].srp_r_obj_size =
	    (MAX(MAX(tx_slots, alloc_slots), ev_slots)) * SLOT_DESC_SZ;
	srp[SKMEM_REGION_TXAKSD].srp_r_obj_cnt = tx_rings + alloc_rings + ev_rings;
	skmem_region_params_config(&srp[SKMEM_REGION_TXAKSD]);

	/* USD and KSD objects share the same size and count */
	srp[SKMEM_REGION_TXAUSD].srp_r_obj_size =
	    srp[SKMEM_REGION_TXAKSD].srp_r_obj_size;
	srp[SKMEM_REGION_TXAUSD].srp_r_obj_cnt =
	    srp[SKMEM_REGION_TXAKSD].srp_r_obj_cnt;
	skmem_region_params_config(&srp[SKMEM_REGION_TXAUSD]);

	/*
	 * Since the rx/free slots share the same region and cache,
	 * we will use the same object size for both types of slots.
	 */
	srp[SKMEM_REGION_RXFKSD].srp_r_obj_size =
	    MAX(rx_slots, free_slots) * SLOT_DESC_SZ;
	srp[SKMEM_REGION_RXFKSD].srp_r_obj_cnt = rx_rings + free_rings;
	skmem_region_params_config(&srp[SKMEM_REGION_RXFKSD]);

	/* USD and KSD objects share the same size and count */
	srp[SKMEM_REGION_RXFUSD].srp_r_obj_size =
	    srp[SKMEM_REGION_RXFKSD].srp_r_obj_size;
	srp[SKMEM_REGION_RXFUSD].srp_r_obj_cnt =
	    srp[SKMEM_REGION_RXFKSD].srp_r_obj_cnt;
	skmem_region_params_config(&srp[SKMEM_REGION_RXFUSD]);

	/* update these based on the adjusted/configured values */
	nxp->nxp_meta_size = srp[SKMEM_REGION_KMD].srp_c_obj_size;
	nxp->nxp_stats_size = stats_size;
	nxp->nxp_flowadv_max = flowadv_max;
	nxp->nxp_nexusadv_size = nexusadv_size;
	nxp->nxp_capabilities = capabs;

error:
	if (overflowline) {
		err = EOVERFLOW;
		SK_ERR("math overflow in %s on line %d",
		    __func__, overflowline);
	}
	return err;
}

#undef ADD
#undef MUL
#undef NXPROV_PARAMS_ADJUST

static void
nxprov_detaching_enqueue(struct kern_nexus_domain_provider *nxdom_prov)
{
	SK_LOCK_ASSERT_HELD();

	ASSERT((nxdom_prov->nxdom_prov_flags & (NXDOMPROVF_ATTACHED |
	    NXDOMPROVF_DETACHING)) == NXDOMPROVF_DETACHING);

	++nxprov_detaching_cnt;
	ASSERT(nxprov_detaching_cnt != 0);
	/*
	 * Insert this to the detaching list; caller is expected to
	 * have held a reference, most likely the same one that was
	 * used for the per-domain provider list.
	 */
	STAILQ_INSERT_TAIL(&nxprov_detaching_head, nxdom_prov,
	    nxdom_prov_detaching_link);
	wakeup((caddr_t)&nxprov_detach_wchan);
}

static struct kern_nexus_domain_provider *
nxprov_detaching_dequeue(void)
{
	struct kern_nexus_domain_provider *nxdom_prov;

	SK_LOCK_ASSERT_HELD();

	nxdom_prov = STAILQ_FIRST(&nxprov_detaching_head);
	ASSERT(nxprov_detaching_cnt != 0 || nxdom_prov == NULL);
	if (nxdom_prov != NULL) {
		ASSERT((nxdom_prov->nxdom_prov_flags & (NXDOMPROVF_ATTACHED |
		    NXDOMPROVF_DETACHING)) == NXDOMPROVF_DETACHING);
		ASSERT(nxprov_detaching_cnt != 0);
		--nxprov_detaching_cnt;
		STAILQ_REMOVE(&nxprov_detaching_head, nxdom_prov,
		    kern_nexus_domain_provider, nxdom_prov_detaching_link);
	}
	return nxdom_prov;
}

__attribute__((noreturn))
static void
nxprov_detacher(void *v, wait_result_t w)
{
#pragma unused(v, w)
	SK_LOCK();
	(void) msleep0(&nxprov_detach_wchan, &sk_lock, (PZERO - 1),
	    __func__, 0, nxprov_detacher_cont);
	/*
	 * msleep0() shouldn't have returned as PCATCH was not set;
	 * therefore assert in this case.
	 */
	SK_UNLOCK();
	VERIFY(0);
	/* NOTREACHED */
	__builtin_unreachable();
}

static int
nxprov_detacher_cont(int err)
{
#pragma unused(err)
	struct kern_nexus_domain_provider *nxdom_prov;

	for (;;) {
		SK_LOCK_ASSERT_HELD();
		while (nxprov_detaching_cnt == 0) {
			(void) msleep0(&nxprov_detach_wchan, &sk_lock,
			    (PZERO - 1), __func__, 0, nxprov_detacher_cont);
			/* NOTREACHED */
		}

		ASSERT(STAILQ_FIRST(&nxprov_detaching_head) != NULL);

		nxdom_prov = nxprov_detaching_dequeue();
		if (nxdom_prov != NULL) {
			nxdom_del_provider_final(nxdom_prov);
		}
	}
}
