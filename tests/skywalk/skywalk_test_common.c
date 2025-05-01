/*
 * Copyright (c) 2016-2024 Apple Inc. All rights reserved.
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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <ifaddrs.h>
#include <netdb.h>

#include <sys/event.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/sysctl.h>

#include <mach/mach_time.h>
#include <net/if.h>
#include <net/if_fake_var.h>
#include <net/if_redirect.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/route.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>
#include <arpa/inet.h>
#include <net/pktsched/pktsched.h>
#include <net/classq/if_classq.h>
#include <os/log.h>

#include <err.h>
#include <TargetConditionals.h>

#include <darwintest.h>

#include <skywalk/os_skywalk_private.h>
#include <skywalk/os_channel_event.h>

#include "skywalk_test_driver.h"
#include "skywalk_test_utils.h"
#include "skywalk_test_common.h"

//#define SKT_COMMON_DEBUG 1

static int
sktc_ifnet_add_addr_with_socket(int s, char *ifname, struct in_addr *addr,
    struct in_addr *mask, struct in_addr *broadaddr);

const char *BOLD =              "\033[1m";
const char *BOLD_RED =          "\033[91;1m";
const char *BOLD_GREEN =        "\033[92;1m";
const char *BOLD_YELLOW =       "\033[93;1m";
const char *BOLD_BLUE =         "\033[94;1m";
const char *BOLD_MAGENTA =      "\033[95;1m";
const char *BOLD_CYAN =         "\033[96;1m";
const char *BOLD_WHITE =        "\033[97;1m";
const char *NORMAL =            "\033[0m";

int sktc_verbose = 1;
nexus_controller_t sktc_nexus_controller;
uuid_t sktc_provider_uuid;
uuid_t sktc_instance_uuid;

uuid_string_t sktc_instance_uuid_string;

uint64_t sktc_nexus_ntxrings;
uint64_t sktc_nexus_nrxrings;
uint64_t sktc_nexus_ntxslots;
uint64_t sktc_nexus_nrxslots;
uint64_t sktc_nexus_slotsize;
uint64_t sktc_nexus_metasize;
uint64_t sktc_nexus_anonymous;
uint64_t sktc_nexus_max_frags;
uint64_t sktc_rejectonclose;

static void sktc_feth_set_flags(uint32_t flags);
static void sktc_feth_restore_flags(void);

static int expire_time, flags;

#ifndef SA_SIZE
#define SA_SIZE(sa)                                             \
    (  (!(sa) || ((struct sockaddr *)(sa))->sa_len == 0) ?      \
	sizeof(uint32_t)            :                               \
	1 + ( (((struct sockaddr *)(sa))->sa_len - 1) | (sizeof(uint32_t) - 1) ) )
#endif
#define AVGN_MAX        8

struct queue_stats {
	int                      avgn;
	double                   avg_bytes;
	double                   avg_packets;
	u_int64_t                prev_bytes;
	u_int64_t                prev_packets;
	unsigned int             handle;
};

static void print_fq_codel_stats(int slot, struct fq_codel_classstats *,
    struct queue_stats *);

int qflag;
struct queue_stats qstats[IFCQ_SC_MAX];

static void arp_stats(uint32_t off, char *name, int af);

struct protox protox[] = {
	{ NULL, arp_stats, NULL, "arp", 0 }
};


void
sktc_setup_nexus(struct sktc_nexus_attr *sktc_attr)
{
	nexus_attr_t attr;
	int error;

	assert(sktc_nexus_controller == NULL);
	assert(uuid_is_null(sktc_provider_uuid));
	assert(uuid_is_null(sktc_instance_uuid));

	sktc_nexus_controller = os_nexus_controller_create();
	assert(sktc_nexus_controller);

	sktc_build_nexus(sktc_nexus_controller, sktc_attr, &sktc_provider_uuid,
	    &sktc_instance_uuid);

	uuid_unparse_upper(sktc_instance_uuid, sktc_instance_uuid_string);

	attr = os_nexus_attr_create();
	assert(attr);

	/* Clear the parameters to make sure they are being read */
	os_nexus_attr_set(attr, NEXUS_ATTR_ANONYMOUS, -1);
	os_nexus_attr_set(attr, NEXUS_ATTR_TX_RINGS, -1);
	os_nexus_attr_set(attr, NEXUS_ATTR_RX_RINGS, -1);
	os_nexus_attr_set(attr, NEXUS_ATTR_TX_SLOTS, -1);
	os_nexus_attr_set(attr, NEXUS_ATTR_RX_SLOTS, -1);
	os_nexus_attr_set(attr, NEXUS_ATTR_SLOT_BUF_SIZE, -1);
	os_nexus_attr_set(attr, NEXUS_ATTR_MAX_FRAGS, -1);
	os_nexus_attr_set(attr, NEXUS_ATTR_REJECT_ON_CLOSE, -1);

	/* The following are not settable */
	error = os_nexus_attr_set(attr, NEXUS_ATTR_SLOT_META_SIZE, -1);
	SKTC_ASSERT_ERR(error == ENOTSUP);
	error = os_nexus_attr_set(attr, NEXUS_ATTR_IFINDEX, -1);
	SKTC_ASSERT_ERR(error == ENOTSUP);

	error = os_nexus_controller_read_provider_attr(sktc_nexus_controller,
	    sktc_provider_uuid, attr);
	SKTC_ASSERT_ERR(!error);

	error = os_nexus_attr_get(attr, NEXUS_ATTR_ANONYMOUS,
	    &sktc_nexus_anonymous);
	SKTC_ASSERT_ERR(!error);
	assert(sktc_nexus_anonymous != -1);
	assert(sktc_attr->anonymous == -1 ||
	    sktc_attr->anonymous == sktc_nexus_anonymous);

	error = os_nexus_attr_get(attr, NEXUS_ATTR_TX_RINGS,
	    &sktc_nexus_ntxrings);
	SKTC_ASSERT_ERR(!error);
	assert(sktc_nexus_ntxrings != -1);
	assert(sktc_attr->ntxrings == -1 ||
	    sktc_attr->ntxrings == sktc_nexus_ntxrings);

	error = os_nexus_attr_get(attr, NEXUS_ATTR_RX_RINGS,
	    &sktc_nexus_nrxrings);
	SKTC_ASSERT_ERR(!error);
	assert(sktc_nexus_nrxrings != -1);
	assert(sktc_attr->nrxrings == -1 ||
	    sktc_attr->nrxrings == sktc_nexus_nrxrings);

	error = os_nexus_attr_get(attr, NEXUS_ATTR_TX_SLOTS,
	    &sktc_nexus_ntxslots);
	SKTC_ASSERT_ERR(!error);
	assert(sktc_nexus_ntxslots != -1);
	assert(sktc_attr->ntxslots == -1 ||
	    sktc_attr->ntxslots == sktc_nexus_ntxslots);

	error = os_nexus_attr_get(attr, NEXUS_ATTR_RX_SLOTS,
	    &sktc_nexus_nrxslots);
	SKTC_ASSERT_ERR(!error);
	assert(sktc_nexus_nrxslots != -1);
	assert(sktc_attr->nrxslots == -1 ||
	    sktc_attr->nrxslots == sktc_nexus_nrxslots);

	error = os_nexus_attr_get(attr, NEXUS_ATTR_SLOT_BUF_SIZE,
	    &sktc_nexus_slotsize);
	SKTC_ASSERT_ERR(!error);
	assert(sktc_nexus_slotsize != -1);
	assert(sktc_attr->slotsize == -1 ||
	    sktc_attr->slotsize == sktc_nexus_slotsize);

	error = os_nexus_attr_get(attr, NEXUS_ATTR_SLOT_META_SIZE,
	    &sktc_nexus_metasize);
	SKTC_ASSERT_ERR(!error);
	assert(sktc_nexus_metasize != -1);
	assert(sktc_attr->metasize == -1 ||
	    sktc_attr->metasize == sktc_nexus_metasize);

	error = os_nexus_attr_get(attr, NEXUS_ATTR_MAX_FRAGS,
	    &sktc_nexus_max_frags);
	SKTC_ASSERT_ERR(!error);
	assert(sktc_nexus_max_frags != -1);
	assert(sktc_attr->maxfrags == -1 ||
	    sktc_attr->maxfrags == sktc_nexus_max_frags);

	error = os_nexus_attr_get(attr, NEXUS_ATTR_REJECT_ON_CLOSE,
	    &sktc_rejectonclose);
	SKTC_ASSERT_ERR(!error);
	assert(sktc_rejectonclose != -1);
	assert(sktc_attr->rejectonclose == -1 ||
	    sktc_attr->rejectonclose == sktc_rejectonclose);

	os_nexus_attr_destroy(attr);
}

void
sktc_cleanup_nexus(void)
{
	int error;

	assert(sktc_nexus_controller);
	assert(!uuid_is_null(sktc_provider_uuid));
	assert(!uuid_is_null(sktc_instance_uuid));

	error = os_nexus_controller_free_provider_instance(sktc_nexus_controller,
	    sktc_instance_uuid);
	SKTC_ASSERT_ERR(!error);
	uuid_clear(sktc_instance_uuid);
	memset(sktc_instance_uuid_string, 0, sizeof(sktc_instance_uuid_string));

	error = os_nexus_controller_deregister_provider(sktc_nexus_controller,
	    sktc_provider_uuid);
	SKTC_ASSERT_ERR(!error);
	uuid_clear(sktc_provider_uuid);

	os_nexus_controller_destroy(sktc_nexus_controller);
	sktc_nexus_controller = NULL;
}



int
sktc_bind_nexus_key(nexus_port_t port, const void *key, size_t keylen)
{
	return os_nexus_controller_bind_provider_instance(sktc_nexus_controller,
	           sktc_instance_uuid, port, -1, NULL, key, keylen, NEXUS_BIND_KEY);
}

int
sktc_unbind_nexus_key(nexus_port_t port)
{
	return os_nexus_controller_unbind_provider_instance(sktc_nexus_controller,
	           sktc_instance_uuid, port);
}

channel_t sktc_channel;

static volatile int sktc_channel_worker_die;
static size_t sktc_nrings;
static pthread_t *sktc_threads;
static pthread_t *sktc_threads2;
static int *sktc_rxkqs;
static int *sktc_txkqs;

static void *
sktc_channel_worker_echo(void *arg)
{
	int index = (pthread_t *)arg - sktc_threads;
	ring_id_t ringid;
	channel_ring_t rxring, txring;
	struct kevent kev;
	int error;
	uint64_t ntxrings, nrxrings, ntxslots, nrxslots,
	    slotsize, metasize;

	channel_attr_t attr = os_channel_attr_create();
	assert(attr);

	error = os_channel_read_attr(sktc_channel, attr);
	SKTC_ASSERT_ERR(!error);

	ntxrings = -1;
	error = os_channel_attr_get(attr, CHANNEL_ATTR_TX_RINGS, &ntxrings);
	SKTC_ASSERT_ERR(!error);
	assert(ntxrings != -1);
	assert(ntxrings == sktc_nexus_ntxrings);

	nrxrings = -1;
	error = os_channel_attr_get(attr, CHANNEL_ATTR_RX_RINGS, &nrxrings);
	SKTC_ASSERT_ERR(!error);
	assert(nrxrings != -1);
	assert(nrxrings == sktc_nexus_nrxrings);

	ntxslots = -1;
	error = os_channel_attr_get(attr, CHANNEL_ATTR_TX_SLOTS, &ntxslots);
	SKTC_ASSERT_ERR(!error);
	assert(ntxslots != -1);
	assert(ntxslots == sktc_nexus_ntxslots);

	nrxslots = -1;
	error = os_channel_attr_get(attr, CHANNEL_ATTR_RX_SLOTS, &nrxslots);
	SKTC_ASSERT_ERR(!error);
	assert(nrxslots != -1);
	assert(nrxslots == sktc_nexus_nrxslots);

	slotsize = -1;
	error = os_channel_attr_get(attr, CHANNEL_ATTR_SLOT_BUF_SIZE, &slotsize);
	SKTC_ASSERT_ERR(!error);
	assert(slotsize != -1);
	assert(slotsize == sktc_nexus_slotsize);

	metasize = -1;
	error = os_channel_attr_get(attr, CHANNEL_ATTR_SLOT_META_SIZE, &metasize);
	SKTC_ASSERT_ERR(!error);
	assert(metasize != -1);
	assert(metasize == sktc_nexus_metasize);

	os_channel_attr_destroy(attr);

	ringid = os_channel_ring_id(sktc_channel, CHANNEL_FIRST_RX_RING);
	ringid += index;
	rxring = os_channel_rx_ring(sktc_channel, ringid);
	assert(rxring);

	ringid = os_channel_ring_id(sktc_channel, CHANNEL_FIRST_TX_RING);
	ringid += index;
	txring = os_channel_tx_ring(sktc_channel, ringid);
	assert(txring);

	while (!sktc_channel_worker_die) {
		slot_prop_t rxprop, txprop;
		channel_slot_t rxprev, rxslot, txprev, txslot;
		uint32_t rxavail, txavail;

		rxavail = os_channel_available_slot_count(rxring);

		/* Wait for incoming data */
		if (!rxavail) {
			error = kevent(sktc_rxkqs[index], NULL, 0, &kev, 1, NULL);
			SKTC_ASSERT_ERR(error != -1);
			SKTC_ASSERT_ERR(error == 1);

			if (kev.filter == EVFILT_USER) {
				assert(kev.ident == (uintptr_t)&sktc_channel_worker_die);
				assert(sktc_channel_worker_die);
				break;
			}

			assert(kev.filter == EVFILT_READ);
			assert(kev.ident == os_channel_get_fd(sktc_channel));
			assert(kev.udata == NULL);

			rxavail = os_channel_available_slot_count(rxring);
			if (!rxavail && skywalk_in_driver) {
				T_LOG("%s: no rx slots available\n", __func__);
				continue;
			} else {
				assert(rxavail);
			}
		}

		txavail = os_channel_available_slot_count(txring);

		/* Wait for outgoing space */
		if (!txavail) {
			error = kevent(sktc_txkqs[index], NULL, 0, &kev, 1, NULL);
			SKTC_ASSERT_ERR(error != -1);
			SKTC_ASSERT_ERR(error == 1);

			if (kev.filter == EVFILT_USER) {
				assert(kev.ident == (uintptr_t)&sktc_channel_worker_die);
				assert(sktc_channel_worker_die);
				break;
			}

			assert(kev.filter == EVFILT_WRITE);
			assert(kev.ident == os_channel_get_fd(sktc_channel));
			assert(kev.udata == NULL);

			txavail = os_channel_available_slot_count(txring);
			if (!txavail && skywalk_in_driver) {
				T_LOG("%s: no tx slots available\n", __func__);
				continue;
			} else {
				assert(txavail);
			}
		}

		rxprev = NULL;
		rxslot = os_channel_get_next_slot(rxring, NULL, &rxprop);
		assert(rxslot);
		txprev = NULL;
		txslot = os_channel_get_next_slot(txring, NULL, &txprop);
		assert(txslot);

		do {
			assert(txprop.sp_len == slotsize);
			assert(txprop.sp_len >= rxprop.sp_len);
			memcpy((void *)txprop.sp_buf_ptr, (void *)rxprop.sp_buf_ptr, rxprop.sp_len);
			txprop.sp_len = rxprop.sp_len;
			/* XXX: can't do this since it'll corrupt __user_quantum */
			//memcpy((void *)txprop.sp_mdata_ptr, (void *)rxprop.sp_mdata_ptr, metasize);
			os_channel_set_slot_properties(txring, txslot, &txprop);

			rxprev = rxslot;
			rxslot = os_channel_get_next_slot(rxring, rxslot, &rxprop);
			txprev = txslot;
			txslot = os_channel_get_next_slot(txring, txslot, &txprop);
		} while (rxslot && txslot);

		assert(txprev);
		error = os_channel_advance_slot(txring, txprev);
		SKTC_ASSERT_ERR(!error);
		error = os_channel_sync(sktc_channel, CHANNEL_SYNC_TX);
		if (error && skywalk_in_driver) {
			SKT_LOG("%s: sync fail error %d errno %d: %s\n", __func__, error, errno, strerror(errno));
		} else {
			SKTC_ASSERT_ERR(!error);
		}

		assert(rxprev);
		error = os_channel_advance_slot(rxring, rxprev);
		SKTC_ASSERT_ERR(!error);
	}

	T_LOG("exiting %s", __func__);

	return NULL;
}

static void *
sktc_channel_worker_sink(void *arg)
{
	int index = (pthread_t *)arg - sktc_threads;
	ring_id_t ringid;
	channel_ring_t rxring;
	struct kevent kev;
	int error;

	/* Only validate the attributes if we are the nexus creator */
	if (sktc_nexus_controller) {
		uint64_t nrxrings, nrxslots, slotsize;

		channel_attr_t attr = os_channel_attr_create();
		assert(attr);

		error = os_channel_read_attr(sktc_channel, attr);
		SKTC_ASSERT_ERR(!error);

		nrxrings = -1;
		error = os_channel_attr_get(attr, CHANNEL_ATTR_RX_RINGS, &nrxrings);
		SKTC_ASSERT_ERR(!error);
		assert(nrxrings != -1);
		assert(nrxrings == sktc_nexus_nrxrings);

		nrxslots = -1;
		error = os_channel_attr_get(attr, CHANNEL_ATTR_RX_SLOTS, &nrxslots);
		SKTC_ASSERT_ERR(!error);
		assert(nrxslots != -1);
		assert(nrxslots == sktc_nexus_nrxslots);

		slotsize = -1;
		error = os_channel_attr_get(attr, CHANNEL_ATTR_SLOT_BUF_SIZE, &slotsize);
		SKTC_ASSERT_ERR(!error);
		assert(slotsize != -1);
		assert(slotsize == sktc_nexus_slotsize);

		os_channel_attr_destroy(attr);
	}

	ringid = os_channel_ring_id(sktc_channel, CHANNEL_FIRST_RX_RING);
	ringid += index;
	rxring = os_channel_rx_ring(sktc_channel, ringid);
	assert(rxring);

	while (!sktc_channel_worker_die) {
		uint32_t rxavail;

		rxavail = os_channel_available_slot_count(rxring);

		/* Wait for incoming data */
		if (!rxavail) {
			error = kevent(sktc_rxkqs[index], NULL, 0, &kev, 1, NULL);
			SKTC_ASSERT_ERR(error != -1);
			SKTC_ASSERT_ERR(error == 1);

			if (kev.filter == EVFILT_USER) {
				assert(kev.ident == (uintptr_t)&sktc_channel_worker_die);
				assert(sktc_channel_worker_die);
				break;
			}

			assert(kev.filter == EVFILT_READ);
			assert(kev.ident == os_channel_get_fd(sktc_channel));
			assert(kev.udata == NULL);

			rxavail = os_channel_available_slot_count(rxring);
			if (!rxavail && skywalk_in_driver) {
				T_LOG("%s: no rx slots available\n", __func__);
				continue;
			} else {
				assert(rxavail);
			}
		}

		sktc_chew_random(sktc_channel, rxring, CHANNEL_SYNC_RX, false, rxavail);
	}

	return NULL;
}

static void *
sktc_channel_worker_source(void *arg)
{
	int index = (pthread_t *)arg - sktc_threads;
	ring_id_t ringid;
	channel_ring_t txring;
	struct kevent kev;
	int error;

	/* Only validate the attributes if we are the nexus creator */
	if (sktc_nexus_controller) {
		uint64_t ntxrings, ntxslots, slotsize;

		channel_attr_t attr = os_channel_attr_create();
		assert(attr);

		error = os_channel_read_attr(sktc_channel, attr);
		SKTC_ASSERT_ERR(!error);

		ntxrings = -1;
		error = os_channel_attr_get(attr, CHANNEL_ATTR_TX_RINGS, &ntxrings);
		SKTC_ASSERT_ERR(!error);
		assert(ntxrings != -1);
		assert(ntxrings == sktc_nexus_ntxrings);

		ntxslots = -1;
		error = os_channel_attr_get(attr, CHANNEL_ATTR_TX_SLOTS, &ntxslots);
		SKTC_ASSERT_ERR(!error);
		assert(ntxslots != -1);
		assert(ntxslots == sktc_nexus_ntxslots);

		slotsize = -1;
		error = os_channel_attr_get(attr, CHANNEL_ATTR_SLOT_BUF_SIZE, &slotsize);
		SKTC_ASSERT_ERR(!error);
		assert(slotsize != -1);
		assert(slotsize == sktc_nexus_slotsize);

		os_channel_attr_destroy(attr);
	}

	ringid = os_channel_ring_id(sktc_channel, CHANNEL_FIRST_TX_RING);
	ringid += index;
	txring = os_channel_tx_ring(sktc_channel, ringid);
	assert(txring);

	while (!sktc_channel_worker_die) {
		uint32_t txavail;

		txavail = os_channel_available_slot_count(txring);

		/* Wait for outgoing space */
		if (!txavail) {
			error = kevent(sktc_txkqs[index], NULL, 0, &kev, 1, NULL);
			SKTC_ASSERT_ERR(error != -1);
			SKTC_ASSERT_ERR(error == 1);

			if (kev.filter == EVFILT_USER) {
				assert(kev.ident == (uintptr_t)&sktc_channel_worker_die);
				assert(sktc_channel_worker_die);
				break;
			}

			assert(kev.filter == EVFILT_WRITE);
			assert(kev.ident == os_channel_get_fd(sktc_channel));
			assert(kev.udata == NULL);

			txavail = os_channel_available_slot_count(txring);
			if (!txavail && skywalk_in_driver) {
				T_LOG("%s: no tx slots available\n", __func__);
				continue;
			} else {
				assert(txavail);
			}
		}

		sktc_chew_random(sktc_channel, txring, CHANNEL_SYNC_TX, true, txavail);
	}

	return NULL;
}

void
sktc_setup_channel_worker(uuid_t instance_uuid, nexus_port_t channel_port,
    ring_id_t ringid, char *key, size_t keylen, bool echo, bool defunct_ok)
{
	channel_attr_t attr = NULL;

	if (key) {
		attr = os_channel_attr_create();
		assert(attr);
		os_channel_attr_set_key(attr, key, keylen);
	}

	sktc_channel = sktu_channel_create_extended(instance_uuid, channel_port,
	    CHANNEL_DIR_TX_RX, ringid, attr,
	    -1, -1, -1, -1, -1, -1, -1, defunct_ok ? 1 : -1, -1, -1);
	assert(sktc_channel);

	if (attr) {
		os_channel_attr_destroy(attr);
	}

	ring_id_t fringid = os_channel_ring_id(sktc_channel, CHANNEL_FIRST_TX_RING);
	ring_id_t lringid = os_channel_ring_id(sktc_channel, CHANNEL_LAST_TX_RING);

	assert(!sktc_nrings);
	sktc_nrings = lringid - fringid + 1;

	assert(!sktc_threads);
	sktc_threads = malloc(sktc_nrings * sizeof(sktc_threads[0]));
	assert(sktc_threads);

	assert(!sktc_threads2);
	if (!echo) {
		sktc_threads2 = malloc(sktc_nrings * sizeof(sktc_threads[0]));
		assert(sktc_threads2);
	}

	// Double check the rx rings are the same
	assert(fringid == os_channel_ring_id(sktc_channel, CHANNEL_FIRST_RX_RING));
	assert(lringid == os_channel_ring_id(sktc_channel, CHANNEL_LAST_RX_RING));

	sktc_rxkqs = malloc(sktc_nrings * sizeof(sktc_rxkqs[0]));
	assert(sktc_rxkqs);
	sktc_txkqs = malloc(sktc_nrings * sizeof(sktc_txkqs[0]));
	assert(sktc_txkqs);

	for (size_t i = 0; i < sktc_nrings; i++) {
		struct kevent kev;
		int error;
		int channelfd = os_channel_get_fd(sktc_channel);
		assert(channelfd != -1);

		sktc_rxkqs[i] = kqueue();
		assert(sktc_rxkqs[i] != -1);
		EV_SET(&kev, channelfd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, NULL);
		error = kevent(sktc_rxkqs[i], &kev, 1, NULL, 0, NULL);
		SKTC_ASSERT_ERR(!error);

		EV_SET(&kev, (uintptr_t)&sktc_channel_worker_die,
		    EVFILT_USER, EV_ADD | EV_ENABLE, 0, 0, NULL);
		error = kevent(sktc_rxkqs[i], &kev, 1, NULL, 0, NULL);
		SKTC_ASSERT_ERR(!error);

		sktc_txkqs[i] = kqueue();
		assert(sktc_txkqs[i] != -1);
		EV_SET(&kev, channelfd, EVFILT_WRITE, EV_ADD | EV_ENABLE, 0, 0, NULL);
		error = kevent(sktc_txkqs[i], &kev, 1, NULL, 0, NULL);
		SKTC_ASSERT_ERR(!error);

		EV_SET(&kev, (uintptr_t)&sktc_channel_worker_die,
		    EVFILT_USER, EV_ADD | EV_ENABLE, 0, 0, NULL);
		error = kevent(sktc_txkqs[i], &kev, 1, NULL, 0, NULL);
		SKTC_ASSERT_ERR(!error);

		if (echo) {
			error = pthread_create(&sktc_threads[i], NULL, sktc_channel_worker_echo, &sktc_threads[i]);
			SKTC_ASSERT_ERR(!error);
		} else {
			error = pthread_create(&sktc_threads[i], NULL, sktc_channel_worker_source, &sktc_threads[i]);
			SKTC_ASSERT_ERR(!error);
			error = pthread_create(&sktc_threads2[i], NULL, sktc_channel_worker_sink, &sktc_threads[i]);
			SKTC_ASSERT_ERR(!error);
		}
	}
}

void
sktc_cleanup_channel_worker(void)
{
	sktc_channel_worker_die = 1;

	for (size_t i = 0; i < sktc_nrings; i++) {
		struct kevent kev;
		int error;

		EV_SET(&kev, (uintptr_t)&sktc_channel_worker_die,
		    EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
		error = kevent(sktc_rxkqs[i], &kev, 1, NULL, 0, NULL);
		SKTC_ASSERT_ERR(!error);
		error = kevent(sktc_txkqs[i], &kev, 1, NULL, 0, NULL);
		SKTC_ASSERT_ERR(!error);

		error = pthread_join(sktc_threads[i], NULL);
		SKTC_ASSERT_ERR(!error);
		if (sktc_threads2) {
			error = pthread_join(sktc_threads2[i], NULL);
			SKTC_ASSERT_ERR(!error);
		}

		error = close(sktc_rxkqs[i]);
		SKTC_ASSERT_ERR(!error);
		error = close(sktc_txkqs[i]);
		SKTC_ASSERT_ERR(!error);
	}

	sktc_channel_worker_die = 0;

	free(sktc_rxkqs);
	sktc_rxkqs = NULL;
	free(sktc_txkqs);
	sktc_txkqs = NULL;

	sktc_nrings = 0;
	free(sktc_threads);
	sktc_threads = NULL;

	if (sktc_threads2) {
		free(sktc_threads2);
		sktc_threads2 = NULL;
	}

	os_channel_destroy(sktc_channel);
	sktc_channel = NULL;
}


void
sktc_generic_upipe_nexus_init(void)
{
	struct sktc_nexus_attr attr = SKTC_NEXUS_ATTR_INIT();

	strncpy((char *)attr.name, "skywalk_test_generic_upipe",
	    sizeof(nexus_name_t) - 1);
	attr.type = NEXUS_TYPE_USER_PIPE;
	attr.anonymous = 1;

	sktc_setup_nexus(&attr);
}

void
sktc_generic_upipe_echo_init(void)
{
	sktc_generic_upipe_nexus_init();
	sktc_setup_channel_worker(sktc_instance_uuid, 1, CHANNEL_RING_ID_ANY,
	    NULL, 0, true, true);
}

void
sktc_generic_upipe_null_init(void)
{
	sktc_generic_upipe_nexus_init();
	sktc_setup_channel_worker(sktc_instance_uuid, 1, CHANNEL_RING_ID_ANY,
	    NULL, 0, false, true);
}

void
sktc_generic_upipe_fini(void)
{
	sktc_cleanup_channel_worker();
	sktc_cleanup_nexus();
}


static int sktc_kpipe_loopback_was_enabled;

void
sktc_generic_kpipe_init(void)
{
	int enabled = 1;
	size_t len = sizeof(sktc_kpipe_loopback_was_enabled);

	assert(uuid_is_null(sktc_instance_uuid));
	sysctlbyname("kern.skywalk.kpipe.loopback.enabled",
	    &sktc_kpipe_loopback_was_enabled, &len, &enabled, sizeof(enabled));

	len = sizeof(sktc_instance_uuid_string);
	sysctlbyname("kern.skywalk.kpipe.loopback.nx_uuid",
	    sktc_instance_uuid_string, &len, NULL, 0);

	if (uuid_parse(sktc_instance_uuid_string, sktc_instance_uuid) ||
	    uuid_is_null(sktc_instance_uuid)) {
		T_LOG("loopback kpipe failed to start\n");
	}
}

void
sktc_generic_kpipe_fini(void)
{
	uuid_clear(sktc_instance_uuid);
	memset(sktc_instance_uuid_string, 0, sizeof(sktc_instance_uuid_string));
	sysctlbyname("kern.skywalk.kpipe.loopback.enabled",
	    NULL, 0, &sktc_kpipe_loopback_was_enabled, sizeof(sktc_kpipe_loopback_was_enabled));
}

static int sktc_memory_test_was_enabled;

void
sktc_generic_memory_init(void)
{
	size_t len = sizeof(sktc_memory_test_was_enabled);
	int enabled = 1;

	sysctlbyname("kern.skywalk.mem.test", &sktc_memory_test_was_enabled,
	    &len, &enabled, sizeof(enabled));
}

void
sktc_generic_memory_fini(void)
{
	sysctlbyname("kern.skywalk.mem.test", NULL, 0,
	    &sktc_memory_test_was_enabled,
	    sizeof(sktc_memory_test_was_enabled));
}

channel_slot_t
send_bytes(channel_ring_t txring, uint32_t count)
{
	int error;

	assert(txring);

	slot_prop_t prop;
	channel_slot_t slot = os_channel_get_next_slot(txring, NULL, &prop);
	assert(slot);

	assert(prop.sp_buf_ptr);
	assert(prop.sp_len == txring->chrd_ring->ring_def_buf_size);

	memset((void *)prop.sp_buf_ptr, 0x55, count);
	prop.sp_len = count;
	os_channel_set_slot_properties(txring, slot, &prop);

	error = os_channel_advance_slot(txring, slot);
	SKTC_ASSERT_ERR(!error);

	return slot;
}

int
chew_slots(channel_ring_t rxring, uint32_t max)
{
	channel_slot_t pslot, slot;
	struct slot_prop prop;
	int count = 0;
	int error;

	assert(rxring);

	slot = os_channel_get_next_slot(rxring, NULL, &prop);
	assert(slot);

	do {
		pslot = slot;
		slot = os_channel_get_next_slot(rxring, slot, &prop);
		count++;
		if (max > 0 && count >= max) {
			break;
		}
	} while (slot != NULL);

	error = os_channel_advance_slot(rxring, pslot);
	SKTC_ASSERT_ERR(!error);

	return count;
}

void
set_watermark(channel_t channel, bool is_tx,
    channel_threshold_unit_t unit, uint32_t value)
{
	channel_attr_t ch_attr = os_channel_attr_create();
	os_channel_read_attr(channel, ch_attr);
	if (is_tx) {
		os_channel_attr_set(ch_attr, CHANNEL_ATTR_TX_LOWAT_UNIT, unit);
		os_channel_attr_set(ch_attr, CHANNEL_ATTR_TX_LOWAT_VALUE, value);
	} else {
		os_channel_attr_set(ch_attr, CHANNEL_ATTR_RX_LOWAT_UNIT, unit);
		os_channel_attr_set(ch_attr, CHANNEL_ATTR_RX_LOWAT_VALUE, value);
	}
	os_channel_write_attr(channel, ch_attr);
	os_channel_attr_destroy(ch_attr);
}

int
wait_on_fd(int kq, int16_t filter,
    channel_t channel, uint32_t lowat, enum timeout_behavior b)
{
	const char *filt_name = (filter == EVFILT_READ) ? "READ" : "WRITE";
	struct kevent kev, evlist;
	int triggered_events;
	struct timespec time_100ms = { .tv_sec = 0, .tv_nsec = 100000000 };
	struct timespec *timeout;

	bzero(&kev, sizeof(kev));
	bzero(&evlist, sizeof(evlist));

	EV_SET(
		&kev, 0, filter, EV_ADD | EV_ENABLE | EV_ONESHOT,
		(lowat > 0) ? NOTE_LOWAT : 0, lowat,
		NULL
		);

	if (b != TIMEOUT_DISABLE) {
		timeout = &time_100ms;
	} else {
		timeout = NULL;
	}

	T_LOG("Sleeping with kevent (%s)...", filt_name);
	fflush(stdout);

	kev.ident = os_channel_get_fd(channel);
	triggered_events = kevent(kq, &kev, 1, &evlist, 1, timeout);
	T_LOG("...kevent (%s) woke up with return=%i, data=%li\n",
	    filt_name, triggered_events, evlist.data);

	if (evlist.flags & EV_ERROR) {
		T_LOG("kevent (%s) encountered error %li\n", filt_name, evlist.data);
		assert(0);
	}

	if (b == TIMEOUT_EXPECT) {
		assert(triggered_events == 0);
	} else if (b == TIMEOUT_FAIL) {
		assert(triggered_events == 1);
	}

	return evlist.data;
}

void
test_stage_init(struct stage_ctx *stage, uint32_t start)
{
	int error;
	stage->test_stage = start;
	error = pthread_mutex_init(&stage->change_mtx, NULL);
	SKTC_ASSERT_ERR(error == 0);
	error = pthread_cond_init(&stage->change_cond, NULL);
	SKTC_ASSERT_ERR(error == 0);
}

void
test_stage_wait(struct stage_ctx *stage, uint32_t target)
{
	pthread_mutex_lock(&stage->change_mtx);

	while (stage->test_stage != target) {
		pthread_cond_wait(&stage->change_cond, &stage->change_mtx);
	}

	pthread_mutex_unlock(&stage->change_mtx);
}

void
test_stage_change(struct stage_ctx *stage, uint32_t new)
{
	pthread_mutex_lock(&stage->change_mtx);

	T_LOG("Test stage changed from %u to %u\n", stage->test_stage, new);
	stage->test_stage = new;
	pthread_cond_signal(&stage->change_cond);

	pthread_mutex_unlock(&stage->change_mtx);
}

void
test_stage_destroy(struct stage_ctx *stage)
{
	int error;
	error = pthread_mutex_destroy(&stage->change_mtx);
	SKTC_ASSERT_ERR(error == 0);
	error = pthread_cond_destroy(&stage->change_cond);
	SKTC_ASSERT_ERR(error == 0);
}

static int
inet_dgram_socket(void)
{
	int     s;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		SKT_LOG("socket: %s\n", strerror(errno));
	}
	return s;
}

static int
inet6_dgram_socket(void)
{
	int     s;

	s = socket(AF_INET6, SOCK_DGRAM, 0);
	if (s < 0) {
		SKT_LOG("socket: %s\n", strerror(errno));
	}
	return s;
}

bool
sktc_get_netif_nexus(const char *ifname, uuid_t netif)
{
	bool                    found = FALSE;
	struct if_nexusreq      ifnr;
	int                     s;

	s = inet_dgram_socket();
	if (s >= 0) {
		bzero((char *)&ifnr, sizeof(ifnr));
		strlcpy(ifnr.ifnr_name, ifname, sizeof(ifnr.ifnr_name));
		if (ioctl(s, SIOCGIFNEXUS, &ifnr) >= 0) {
			uuid_copy(netif, ifnr.ifnr_netif);
			found = TRUE;
		}
		close(s);
	}
	return found;
}

bool
sktc_get_flowswitch_nexus(const char *ifname, uuid_t netif)
{
	bool                    found = FALSE;
	struct if_nexusreq      ifnr;
	int                     s;

	s = inet_dgram_socket();
	if (s >= 0) {
		bzero((char *)&ifnr, sizeof(ifnr));
		strlcpy(ifnr.ifnr_name, ifname, sizeof(ifnr.ifnr_name));
		if (ioctl(s, SIOCGIFNEXUS, &ifnr) >= 0) {
			uuid_copy(netif, ifnr.ifnr_flowswitch);
			found = TRUE;
		}
		close(s);
	}
	return found;
}

int
sktc_get_mac_addr(const char *ifname, uint8_t *addr)
{
	int s, err = 0;
	struct ifreq ifr;

	s = inet_dgram_socket();
	if (s < 0) {
		return errno;
	}
	bzero(&ifr, sizeof(ifr));
	(void) strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	ifr.ifr_addr.sa_family = AF_LINK;
	ifr.ifr_addr.sa_len = ETHER_ADDR_LEN;
	err = ioctl(s, SIOCGIFLLADDR, &ifr);
	if (err < 0) {
		(void) close(s);
		return errno;
	}
	bcopy(ifr.ifr_addr.sa_data, addr, ETHER_ADDR_LEN);
	(void) close(s);
	return 0;
}

static int
sktc_ifnet_destroy(int s, const char * ifname)
{
	int             error = 0;
	struct ifreq    ifr;

	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(s, SIOCIFDESTROY, &ifr) < 0) {
		error = errno;
		SKT_LOG("SIOCSIFDESTROY %s: %s\n", ifr.ifr_name,
		    strerror(errno));
	}
	return error;
}

static int
sktc_ifnet_set_flags(int s, const char * ifname,
    uint16_t flags_set, uint16_t flags_clear)
{
	uint16_t        flags_after;
	uint16_t        flags_before;
	struct ifreq    ifr;
	int             ret;

	bzero(&ifr, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	ret = ioctl(s, SIOCGIFFLAGS, (caddr_t)&ifr);
	if (ret != 0) {
		SKT_LOG("SIOCGIFFLAGS %s: %s\n",
		    ifr.ifr_name, strerror(errno));
		return ret;
	}
	flags_before = ifr.ifr_flags;
	ifr.ifr_flags |= flags_set;
	ifr.ifr_flags &= ~(flags_clear);
	flags_after = ifr.ifr_flags;
	if (flags_before == flags_after) {
		/* nothing to do */
		ret = 0;
	} else {
		/* issue the ioctl */
		ret = ioctl(s, SIOCSIFFLAGS, &ifr);
		if (ret != 0) {
			SKT_LOG("SIOCSIFFLAGS %s 0x%x: %s\n",
			    ifr.ifr_name, (uint16_t)ifr.ifr_flags,
			    strerror(errno));
		} else {
			T_LOG(
				"setflags(%s set 0x%x clear 0x%x) "
				"0x%x => 0x%x\n",
				ifr.ifr_name, flags_set, flags_clear,
				flags_before, flags_after);
		}
	}
	return ret;
}

/* On some platforms with DEBUG kernel, we need to wait a while */
#define SIFCREATE_RETRY 100

static int
sktc_ifnet_create(int s, const char * ifname)
{
	int             error = 0;
	struct ifreq    ifr;

	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	for (int i = 0; i < SIFCREATE_RETRY; i++) {
		if (ioctl(s, SIOCIFCREATE, &ifr) < 0) {
			error = errno;
			T_LOG("SIOCSIFCREATE %s: %s\n", ifname,
			    strerror(error));
			if (error == EBUSY) {
				/* interface is tearing down, try again */
				usleep(100000);
			} else if (error == EEXIST) {
				/* interface exists, try destroying it */
				(void)sktc_ifnet_destroy(s, ifname);
			} else {
				/* unexpected failure */
				break;
			}
		} else {
			error = 0;
			break;
		}
	}
	if (error == 0) {
		error = sktc_ifnet_set_flags(s, ifname, IFF_UP, 0);
	}
	return error;
}

static int
sktc_ifnet_create_with_type(int s, const char * ifname, uint8_t type)
{
	int             error = 0;
	struct if_redirect_create_params ircp = {};
	struct ifreq ifr = {};

	bzero(&ircp, sizeof(ircp));
	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	ircp.ircp_type = RD_CREATE_PARAMS_TYPE_NOATTACH;
	ircp.ircp_len = sizeof(ircp);

	switch (type) {
	case RD_IF_TYPE_ETHERNET:
		ircp.ircp_ftype = IFRTYPE_FAMILY_ETHERNET;
		break;
	case RD_IF_TYPE_CELLULAR:
		ircp.ircp_ftype = IFRTYPE_FAMILY_CELLULAR;
		break;
	default:
		ircp.ircp_ftype = IFRTYPE_FAMILY_ETHERNET;
	}

	ifr.ifr_data = (caddr_t)&ircp;

	for (int i = 0; i < SIFCREATE_RETRY; i++) {
		if (ioctl(s, SIOCIFCREATE2, &ifr) < 0) {
			error = errno;
			T_LOG("SIOCSIFCREATE2 %s: %s\n", ifname,
			    strerror(error));
			if (error == EBUSY) {
				/* interface is tearing down, try again */
				usleep(100000);
			} else if (error == EEXIST) {
				/* interface exists, try destroying it */
				(void)sktc_ifnet_destroy(s, ifname);
			} else {
				/* unexpected failure */
				break;
			}
		} else {
			error = 0;
			break;
		}
	}
	if (error == 0) {
		error = sktc_ifnet_set_flags(s, ifname, IFF_UP, 0);
	}
	return error;
}

int
sktc_ifnet_feth_create(int unit)
{
	int             error = 0;
	int             s;

	s = inet_dgram_socket();
	if (s < 0) {
		error = errno;
	} else {
		char    ifname[IFNAMSIZ];

		sktc_feth_name_for_unit(ifname, sizeof(ifname), unit);
		error = sktc_ifnet_create(s, ifname);
		close(s);
	}
	SKTC_ASSERT_ERR(error == 0);
	return error;
}

int
sktc_ifnet_feth_destroy(int unit)
{
	int             error = 0;
	int             s;

	s = inet_dgram_socket();
	if (s < 0) {
		error = errno;
	} else {
		char    ifname[IFNAMSIZ];

		sktc_feth_name_for_unit(ifname, sizeof(ifname), unit);
		error = sktc_ifnet_destroy(s, ifname);
		close(s);
	}
	return error;
}

void
sktc_ifnet_feth0_create(void)
{
	sktc_feth_set_flags(FETH_FLAGS_TXSTART);
	sktc_ifnet_feth_create(0);
	sktc_feth_restore_flags();
}

void
sktc_ifnet_feth0_destroy(void)
{
	sktc_ifnet_feth_destroy(0);
}

void
sktc_ifnet_feth1_create(void)
{
	sktc_feth_set_flags(FETH_FLAGS_TXSTART);
	sktc_ifnet_feth_create(1);
	sktc_feth_restore_flags();
}

void
sktc_ifnet_feth1_destroy(void)
{
	sktc_ifnet_feth_destroy(1);
}

void
sktc_ifnet_feth0_1_create(void)
{
	sktc_feth_set_flags(FETH_FLAGS_TXSTART);
	sktc_ifnet_feth_create(0);
	sktc_ifnet_feth_create(1);
	sktc_feth_restore_flags();
}

void
sktc_ifnet_feth0_1_destroy(void)
{
	sktc_ifnet_feth_destroy(0);
	sktc_ifnet_feth_destroy(1);
}

static int
fake_set_dequeue_stall(const char *feth, boolean_t enable)
{
	struct ifdrv                    ifd;
	struct if_fake_request          iffr;
	int                             ret = 0;
	int                             s;

	s = inet_dgram_socket();
	if (s < 0) {
		return errno;
	}

	bzero((char *)&ifd, sizeof(ifd));
	bzero((char *)&iffr, sizeof(iffr));
	strlcpy(ifd.ifd_name, feth, sizeof(ifd.ifd_name));
	ifd.ifd_cmd = IF_FAKE_S_CMD_SET_DEQUEUE_STALL;
	ifd.ifd_len = sizeof(iffr);
	ifd.ifd_data = &iffr;
	iffr.iffr_dequeue_stall = enable ? 1 : 0;

	if (ioctl(s, SIOCSDRVSPEC, &ifd) < 0) {
		SKT_LOG("SIOCDRVSPEC set dequeue stall %s %d failed, "
		    "%s\n", feth, iffr.iffr_dequeue_stall, strerror(errno));
		ret = errno;
	}
	close(s);
	return ret;
}

int
sktc_ifnet_feth0_set_dequeue_stall(boolean_t enable)
{
	return fake_set_dequeue_stall(FETH0_NAME, enable);
}

int
sktc_ifnet_feth1_set_dequeue_stall(boolean_t enable)
{
	return fake_set_dequeue_stall(FETH1_NAME, enable);
}

static void
fake_set_peer(int s, const char * feth, const char * feth_peer)
{
	struct ifdrv                    ifd;
	struct if_fake_request          iffr;

	bzero((char *)&ifd, sizeof(ifd));
	bzero((char *)&iffr, sizeof(iffr));
	strlcpy(ifd.ifd_name, feth, sizeof(ifd.ifd_name));
	ifd.ifd_cmd = IF_FAKE_S_CMD_SET_PEER;
	ifd.ifd_len = sizeof(iffr);
	ifd.ifd_data = &iffr;
	if (feth_peer != NULL) {
		strlcpy(iffr.iffr_peer_name, feth_peer,
		    sizeof(iffr.iffr_peer_name));
	}
	if (ioctl(s, SIOCSDRVSPEC, &ifd) < 0) {
		SKT_LOG("SIOCDRVSPEC set peer %s %s failed, %s\n",
		    feth, (feth_peer != NULL) ? feth_peer : "<none>",
		    strerror(errno));
	}
	return;
}

static int fake_txstart_value;
static int fake_bsd_mode_value;
static int fake_llink_cnt_value;
static int fake_wmm_mode_value;
static int fake_multi_buflet_value;
static int fake_pktpool_mode_value;
static int fake_tx_headroom_value;
static int fake_nxattach_value;
static int fake_user_access_value;
static char fake_sk_ll_prefix[IFNAMSIZ - 1] = {'\0'};
static int fake_fcs_value;
static int fake_trailer_length_value;

static void
sktc_feth_set_flags(uint32_t flags)
{
	int     bsd_mode;
	int     llink_cnt;
	int     wmm_mode;
	int     pp_mode;
	int     multi_buflet;
	int     error;
	size_t  len = sizeof(fake_txstart_value);
	int     nxattach;
	int     txstart;
	uint32_t tx_headroom;
	int     user_access;
	int     fcs;
	int     trailer_length;
	char    ifname[IFNAMSIZ - 1] = "feth";

	/* make sure bsd mode is set correctly */
	bsd_mode = ((flags & FETH_FLAGS_NATIVE) == 0);
	error = sysctlbyname("net.link.fake.bsd_mode",
	    &fake_bsd_mode_value, &len,
	    &bsd_mode, sizeof(bsd_mode));
	if (error != 0) {
		SKT_LOG(
			"sysctlbyname(net.link.fake.bsd_mode) failed, %s\n",
			strerror(errno));
	}
	SKTC_ASSERT_ERR(error == 0);

	/* set the number of logical links */
	if ((flags & FETH_FLAGS_LLINK) != 0) {
		llink_cnt = 1;
	} else if ((flags & FETH_FLAGS_MULTI_LLINK) != 0) {
		llink_cnt = 4;
	} else {
		llink_cnt = 0;
	}
	error = sysctlbyname("net.link.fake.llink_cnt",
	    &fake_llink_cnt_value, &len,
	    &llink_cnt, sizeof(llink_cnt));
	if (error != 0) {
		SKT_LOG(
			"sysctlbyname(net.link.fake.llink_cnt) failed, %s\n",
			strerror(errno));
	}
	SKTC_ASSERT_ERR(error == 0);

	/* make sure feth TXSTART is set correctly */
	txstart = ((flags & FETH_FLAGS_TXSTART) != 0) ? 1 : 0;
	error = sysctlbyname("net.link.fake.txstart",
	    &fake_txstart_value, &len,
	    &txstart, sizeof(txstart));
	if (error != 0) {
		SKT_LOG(
			"sysctlbyname(net.link.fake.txstart) failed, %s\n",
			strerror(errno));
	}
	SKTC_ASSERT_ERR(error == 0);

	/* make sure wmm mode is set correctly */
	wmm_mode = ((flags & FETH_FLAGS_WMM) != 0) ? 1 : 0;
	error = sysctlbyname("net.link.fake.wmm_mode",
	    &fake_wmm_mode_value, &len,
	    &wmm_mode, sizeof(wmm_mode));
	if (error != 0) {
		SKT_LOG(
			"sysctlbyname(net.link.fake.wmm_mode) failed, %s\n",
			strerror(errno));
	}
	SKTC_ASSERT_ERR(error == 0);

	/* enable multi-buflet mode if requested */
	multi_buflet = ((flags & FETH_FLAGS_MULTI_BUFLET) != 0) ? 1 : 0;
	error = sysctlbyname("net.link.fake.multibuflet",
	    &fake_multi_buflet_value, &len,
	    &multi_buflet, sizeof(multi_buflet));
	if (error != 0) {
		SKT_LOG(
			"sysctlbyname(net.link.fake.multibuflet) failed, %s\n",
			strerror(errno));
	}
	SKTC_ASSERT_ERR(error == 0);

	/* enable user-acess mode if requested */
	user_access = ((flags & FETH_FLAGS_USER_ACCESS) != 0) ? 1 : 0;
	error = sysctlbyname("net.link.fake.user_access",
	    &fake_user_access_value, &len,
	    &user_access, sizeof(user_access));
	if (error != 0) {
		SKT_LOG(
			"sysctlbyname(net.link.fake.user_access) failed, %s\n",
			strerror(errno));
	}
	SKTC_ASSERT_ERR(error == 0);

	/* change netif IPv6 ULA ifname prefix if requested */
	if ((flags & FETH_FLAGS_LOW_LATENCY) != 0) {
		len = sizeof(fake_sk_ll_prefix);
		error =
		    sysctlbyname("kern.skywalk.netif.sk_ll_prefix",
		    fake_sk_ll_prefix, &len, ifname, sizeof(ifname));
		if (error != 0) {
			SKT_LOG("sysctlbyname failed "
			    "for (sk_ll_prefix) %s\n",
			    strerror(errno));
		}
	}
	SKTC_ASSERT_ERR(error == 0);

	/* enable copy mode if requested */
	assert((flags & (FETH_FLAGS_NONSHAREDPOOL |
	    FETH_FLAGS_NONSHAREDSPLITPOOLS)) != (FETH_FLAGS_NONSHAREDPOOL |
	    FETH_FLAGS_NONSHAREDSPLITPOOLS));
	pp_mode = ((flags & FETH_FLAGS_NONSHAREDPOOL) != 0) ? 1 : 0;
	pp_mode = ((flags & FETH_FLAGS_NONSHAREDSPLITPOOLS) != 0) ? 2 : pp_mode;
	len = sizeof(fake_pktpool_mode_value);
	error = sysctlbyname("net.link.fake.pktpool_mode",
	    &fake_pktpool_mode_value, &len, &pp_mode, sizeof(pp_mode));
	if (error != 0) {
		SKT_LOG(
			"sysctlbyname(net.link.fake.pktpool_mode) failed, %s\n",
			strerror(errno));
	}
	if ((flags & FETH_FLAGS_TX_HEADROOM) != 0) {
#define FETH_HEADROOM_MUL_8_MAX         4
		srand(time(NULL));
		tx_headroom = (rand() % FETH_HEADROOM_MUL_8_MAX) * 8;
		T_LOG("Using TX headroom %u\n", tx_headroom);
	} else {
		tx_headroom = 0;
	}
	SKTC_ASSERT_ERR(error == 0);
	len = sizeof(fake_tx_headroom_value);
	error = sysctlbyname("net.link.fake.tx_headroom",
	    &fake_tx_headroom_value, &len,
	    &tx_headroom, sizeof(tx_headroom));
	SKTC_ASSERT_ERR(error == 0);

	nxattach = ((flags & FETH_FLAGS_NXATTACH) != 0) ? 1 : 0;
	len = sizeof(fake_nxattach_value);
	error = sysctlbyname("net.link.fake.nxattach",
	    &fake_nxattach_value, &len,
	    &nxattach, sizeof(nxattach));
	SKTC_ASSERT_ERR(error == 0);

	fcs = ((flags & FETH_FLAGS_FCS) != 0) ? 1 : 0;
	len = sizeof(fake_fcs_value);
	error = sysctlbyname("net.link.fake.fcs",
	    &fake_fcs_value, &len,
	    &fcs, sizeof(fcs));
	SKTC_ASSERT_ERR(error == 0);

	trailer_length = ((flags & FETH_FLAGS_TRAILER) != 0) ? 2 : 0;
	len = sizeof(fake_trailer_length_value);
	error = sysctlbyname("net.link.fake.trailer_length",
	    &fake_trailer_length_value, &len,
	    &trailer_length, sizeof(trailer_length));
	SKTC_ASSERT_ERR(error == 0);
}

static void
sktc_feth_restore_flags(void)
{
	int error;

	error = sysctlbyname("net.link.fake.txstart",
	    NULL, 0,
	    &fake_txstart_value, sizeof(fake_txstart_value));
	if (error != 0) {
		SKT_LOG(
			"sysctlbyname(net.link.fake.txstart) failed, %s\n",
			strerror(errno));
	}
	error = sysctlbyname("net.link.fake.bsd_mode",
	    NULL, 0,
	    &fake_bsd_mode_value, sizeof(fake_bsd_mode_value));
	if (error != 0) {
		SKT_LOG(
			"sysctlbyname(net.link.fake.bsd_mode) failed, %s\n",
			strerror(errno));
	}
	error = sysctlbyname("net.link.fake.llink_cnt",
	    NULL, 0,
	    &fake_llink_cnt_value, sizeof(fake_llink_cnt_value));
	if (error != 0) {
		SKT_LOG(
			"sysctlbyname(net.link.fake.llink) failed, %s\n",
			strerror(errno));
	}
	error = sysctlbyname("net.link.fake.wmm_mode",
	    NULL, 0,
	    &fake_wmm_mode_value, sizeof(fake_wmm_mode_value));
	if (error != 0) {
		SKT_LOG(
			"sysctlbyname(net.link.fake.wmm_mode) failed, %s\n",
			strerror(errno));
	}
	error = sysctlbyname("net.link.fake.multibuflet", NULL, 0,
	    &fake_multi_buflet_value, sizeof(fake_multi_buflet_value));
	if (error != 0) {
		SKT_LOG(
			"sysctlbyname(net.link.fake.multibuflet) failed, %s\n",
			strerror(errno));
	}
	error = sysctlbyname("net.link.fake.pktpool_mode", NULL, 0,
	    &fake_pktpool_mode_value, sizeof(fake_pktpool_mode_value));
	if (error != 0) {
		SKT_LOG(
			"sysctlbyname(net.link.fake.pktpool_mode) failed, %s\n",
			strerror(errno));
	}
	error = sysctlbyname("net.link.fake.tx_headroom",
	    NULL, 0,
	    &fake_tx_headroom_value, sizeof(fake_tx_headroom_value));
	if (error != 0) {
		SKT_LOG(
			"sysctlbyname(net.link.fake.tx_headroom) failed, %s\n",
			strerror(errno));
	}
	error = sysctlbyname("net.link.fake.user_access", NULL, 0,
	    &fake_user_access_value, sizeof(fake_user_access_value));
	if (error != 0) {
		SKT_LOG(
			"sysctlbyname(net.link.fake.user_access) failed, %s\n",
			strerror(errno));
	}
	if (strlen(fake_sk_ll_prefix) != 0) {
		error =
		    sysctlbyname("kern.skywalk.netif.sk_ll_prefix",
		    NULL, 0, &fake_sk_ll_prefix,
		    sizeof(fake_sk_ll_prefix));
		if (error != 0) {
			SKT_LOG(
				"sysctlbyname(sk_ll_prefix) failed, %s\n",
				strerror(errno));
		}
	}
	error = sysctlbyname("net.link.fake.nxattach",
	    NULL, 0,
	    &fake_nxattach_value, sizeof(fake_nxattach_value));
	SKTC_ASSERT_ERR(error == 0);
	error = sysctlbyname("net.link.fake.fcs",
	    NULL, 0,
	    &fake_fcs_value, sizeof(fake_fcs_value));
	SKTC_ASSERT_ERR(error == 0);
	error = sysctlbyname("net.link.fake.trailer_length",
	    NULL, 0,
	    &fake_trailer_length_value, sizeof(fake_trailer_length_value));
	SKTC_ASSERT_ERR(error == 0);
}

void
sktc_ifnet_feth_pair_create(uint32_t flags)
{
	int             error;
	struct in_addr  feth0_addr;
	struct in_addr  feth1_addr;
	struct in_addr  mask;
	int             s;

	s = inet_dgram_socket();
	if (s < 0) {
		return;
	}

	/* create feth0, feth1 using flags */
	sktc_feth_set_flags(flags);
	error = sktc_ifnet_create(s, FETH0_NAME);
	if (error == 0) {
		error = sktc_ifnet_create(s, FETH1_NAME);
	}
	sktc_feth_restore_flags();
	if (error != 0) {
		return;
	}

	/* set them as peers */
	fake_set_peer(s, FETH0_NAME, FETH1_NAME);

	/* subnet mask 255.255.255.0 */
	mask.s_addr = htonl(IN_CLASSC_NET);

	/* assign feth0 IP */
	feth0_addr = sktc_feth0_in_addr();
	error = sktc_ifnet_add_addr_with_socket(s, FETH0_NAME, &feth0_addr,
	    &mask, NULL);
	if (error != 0) {
		return;
	}

	/* assign feth1 IP */
	feth1_addr = sktc_feth1_in_addr();
	error = sktc_ifnet_add_addr_with_socket(s, FETH1_NAME, &feth1_addr,
	    &mask, NULL);
	if (error != 0) {
		return;
	}

	/* add feth0 scoped default route */
	error = sktc_ifnet_add_scoped_default_route(FETH0_NAME, feth0_addr);
	if (error != 0) {
		T_LOG("Failed to add default route for feth0, %s\n",
		    strerror(error));
		return;
	}

	/* add feth1 scoped default route */
	error = sktc_ifnet_add_scoped_default_route(FETH1_NAME, feth1_addr);
	if (error != 0) {
		T_LOG("Failed to add default route for feth1, %s\n",
		    strerror(error));
		return;
	}
}

void
sktc_ifnet_feth_pair_destroy(void)
{
	sktc_feth_restore_flags();
	sktc_ifnet_feth0_1_destroy();
}

static void
redirect_set_delegate(int s, const char *redirect, const char *delegate)
{
	struct ifdrv                    ifd;
	struct if_redirect_request      iffr;

	bzero((char *)&ifd, sizeof(ifd));
	bzero((char *)&iffr, sizeof(iffr));

	strlcpy(ifd.ifd_name, redirect, sizeof(ifd.ifd_name));
	ifd.ifd_cmd = RD_S_CMD_SET_DELEGATE;
	ifd.ifd_len = sizeof(iffr);
	ifd.ifd_data = &iffr;
	if (delegate != NULL) {
		strlcpy(iffr.ifrr_delegate_name, delegate,
		    sizeof(iffr.ifrr_delegate_name));
	}
	if (ioctl(s, SIOCSDRVSPEC, &ifd) < 0) {
		SKT_LOG("SIOCDRVSPEC set delegate %s %s failed, %s\n",
		    redirect, (delegate != NULL) ? delegate : "<none>",
		    strerror(errno));
	}
	return;
}

void
sktc_ifnet_rd_create(void)
{
	int             error;
	struct in_addr  rd_addr;
	struct in_addr  mask;
	int             s;

	s = inet_dgram_socket();
	if (s < 0) {
		return;
	}

	/* create rd0 using flags */
	error = sktc_ifnet_create_with_type(s, RD0_NAME, RD_IF_TYPE_ETHERNET);
	if (error != 0) {
		return;
	}

	/* subnet mask 255.255.255.0 */
	mask.s_addr = htonl(IN_CLASSC_NET);

	/* assign rd0 IP */
	rd_addr = sktc_rd0_in_addr();
	error = sktc_ifnet_add_addr_with_socket(s, RD0_NAME, &rd_addr,
	    &mask, NULL);
	if (error != 0) {
		return;
	}

	/* add rd0 scoped default route */
	error = sktc_ifnet_add_scoped_default_route(RD0_NAME, rd_addr);
	if (error != 0) {
		T_LOG("Failed to add default route for rd0, %s\n",
		    strerror(error));
		return;
	}

	/* set feth0 as delegate for rd0 */
	redirect_set_delegate(s, RD0_NAME, FETH0_NAME);
}

void
sktc_ifnet_rd_destroy(void)
{
	int             error = 0;
	int             s;

	s = inet_dgram_socket();
	if (s < 0) {
		error = errno;
	} else {
		error = sktc_ifnet_destroy(s, RD0_NAME);
		close(s);
	}
	return;
}

static short
sktc_ifnet_get_flags(int s, char * ifname)
{
	struct ifreq    ifr;
	u_int           flags;

	flags = 0;
	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(s, SIOCGIFFLAGS, (caddr_t)&ifr) < 0) {
		SKT_LOG("SIOCIFFLAGS(%s) failed, %s\n", ifname,
		    strerror(errno));
	} else {
		flags = ifr.ifr_flags;
	}
	return flags;
}

#define SIOCAIFADDR_RETRY 100
static int
sktc_ifnet_add_addr_with_socket(int s, char *ifname, struct in_addr *addr,
    struct in_addr *mask, struct in_addr *broadaddr)
{
	struct sockaddr_in *sin;
	struct ifaliasreq ifra;
	int err = 0, tries = 0;

	bzero(&ifra, sizeof(ifra));
	(void) strncpy(ifra.ifra_name, ifname, sizeof(ifra.ifra_name));

	if (addr != NULL) {
		sin = (struct sockaddr_in *)&ifra.ifra_addr;
		sin->sin_len = sizeof(*sin);
		sin->sin_family = AF_INET;
		sin->sin_addr = *addr;
	}

	if (mask != NULL) {
		sin = (struct sockaddr_in *)&ifra.ifra_mask;
		sin->sin_len = sizeof(*sin);
		sin->sin_family = AF_INET;
		sin->sin_addr = *mask;
	}

	if (broadaddr != NULL || (addr != NULL &&
	    (sktc_ifnet_get_flags(s, ifname) & IFF_POINTOPOINT) != 0)) {
		sin = (struct sockaddr_in *)&ifra.ifra_broadaddr;
		sin->sin_len = sizeof(*sin);
		sin->sin_family = AF_INET;
		sin->sin_addr = (broadaddr != NULL) ? *broadaddr : *addr;
	}

retry:
	if ((err = ioctl(s, SIOCAIFADDR, &ifra)) == -1) {
		err = errno;
		SKT_LOG("SIOCAIFADDR: %s\n", strerror(errno));
		if (++tries < SIOCAIFADDR_RETRY) {
			usleep(100000);
			goto retry;
		}
	}
	assert(err || sktu_check_interface_ipv4_address(ifname, addr->s_addr));
	return err;
}

int
sktc_ifnet_add_addr(char *ifname, struct in_addr *addr, struct in_addr *mask,
    struct in_addr *broadaddr)
{
	int     s;
	int     err;

	s = inet_dgram_socket();
	if (s < 0) {
		return errno;
	}
	err = sktc_ifnet_add_addr_with_socket(s, ifname, addr, mask, broadaddr);
	(void) close(s);
	return err;
}

static void
in6_len2mask(struct in6_addr * mask, int len)
{
	int i;
	bzero(mask, sizeof(*mask));
	for (i = 0; i < len / 8; i++) {
		mask->s6_addr[i] = 0xff;
	}
	if (len % 8) {
		mask->s6_addr[i] = (0xff00 >> (len % 8)) & 0xff;
	}
}

static int
sktc_ifnet_add_addr6_with_socket(int s, char *ifname, struct in6_addr *addr,
    struct in6_addr *dstaddr, int prefix_len, int flags)
{
	struct sockaddr_in6 *sin;
	struct in6_aliasreq ifra;
	int err = 0, tries = 0;

	bzero(&ifra, sizeof(ifra));
	(void) strncpy(ifra.ifra_name, ifname, sizeof(ifra.ifra_name));

	if (addr != NULL) {
		sin = (struct sockaddr_in6 *)(&ifra.ifra_addr);
		sin->sin6_family = AF_INET6;
		sin->sin6_len = sizeof(*sin);
		sin->sin6_addr = *addr;
	}

	if (dstaddr != NULL) {
		sin = (struct sockaddr_in6 *)(&ifra.ifra_dstaddr);
		sin->sin6_family = AF_INET6;
		sin->sin6_len = sizeof(*sin);
		sin->sin6_addr = *dstaddr;
	}

	if (prefix_len != 0) {
		struct in6_addr prefixmask;
		in6_len2mask(&prefixmask, prefix_len);

		sin = (struct sockaddr_in6 *)&ifra.ifra_prefixmask;
		sin->sin6_family = AF_INET6;
		sin->sin6_len = sizeof(*sin);
		sin->sin6_addr = prefixmask;
	}

	ifra.ifra_flags = flags;
	ifra.ifra_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME;
	ifra.ifra_lifetime.ia6t_pltime = ND6_INFINITE_LIFETIME;

retry:
	if ((err = ioctl(s, SIOCAIFADDR_IN6, &ifra)) == -1) {
		err = errno;
		SKT_LOG("SIOCAIFADDR_IN6: %s\n", strerror(errno));
		if (++tries < SIOCAIFADDR_RETRY) {
			usleep(100000);
			goto retry;
		}
	}
	return err;
}

int
sktc_ifnet_add_addr6(char *ifname, struct in6_addr *addr,
    struct in6_addr *dstaddr, int prefix_len, int flags)
{
	int     s;
	int     err;

	s = inet6_dgram_socket();
	if (s < 0) {
		return errno;
	}
	err = sktc_ifnet_add_addr6_with_socket(s, ifname, addr, dstaddr,
	    prefix_len, flags);
	(void) close(s);
	return err;
}

int
sktc_ifnet_del_addr(char *ifname, struct in_addr *addr)
{
	struct sockaddr_in *sin;
	struct ifreq ifr;
	int s, err = 0;

	s = inet_dgram_socket();
	if (s < 0) {
		return errno;
	}

	bzero(&ifr, sizeof(ifr));
	(void) strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	if (addr != NULL) {
		sin = (struct sockaddr_in *)&ifr.ifr_addr;
		sin->sin_len = sizeof(*sin);
		sin->sin_family = AF_INET;
		sin->sin_addr = *addr;
	}

	if (ioctl(s, SIOCDIFADDR, &ifr) == -1) {
		err = errno;
		SKT_LOG("SIOCDIFADDR: %s\n", strerror(errno));
	}
	(void) close(s);
	return err;
}

int
sktc_ifnet_del_addr6(char *ifname, struct in6_addr *addr)
{
	struct sockaddr_in6 *sin6;
	struct ifreq ifr;
	int s, err = 0;

	s = inet_dgram_socket();
	if (s < 0) {
		return errno;
	}

	bzero(&ifr, sizeof(ifr));
	(void) strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	if (addr != NULL) {
		sin6 = (struct sockaddr_in6 *)&ifr.ifr_addr;
		sin6->sin6_len = sizeof(*sin6);
		sin6->sin6_family = AF_INET6;
		sin6->sin6_addr = *addr;
	}

	if (ioctl(s, SIOCDIFADDR_IN6, &ifr) == -1) {
		err = errno;
		SKT_LOG("SIOCDIFADDR: %s\n", strerror(errno));
	}
	(void) close(s);
	return err;
}

/*
 * Stolen/modified from IPMonitor/ip_plugin.c
 */
/*
 * Define: ROUTE_MSG_ADDRS_SPACE
 * Purpose:
 *   Since sizeof(sockaddr_dl) > sizeof(sockaddr_in), we need space for
 *   3 sockaddr_in's and 2 sockaddr_dl's, but pad it just in case
 *   someone changes the code and doesn't think to modify this.
 */
#define ROUTE_MSG_ADDRS_SPACE   (3 * sizeof(struct sockaddr_in) \
	                         + 2 * sizeof(struct sockaddr_dl) \
	                         + 128)
typedef struct {
	struct rt_msghdr    hdr;
	char                addrs[ROUTE_MSG_ADDRS_SPACE];
} route_msg;

typedef unsigned int    IFIndex;

typedef enum {
	kRouteFlagsIsScoped         = 0x0001,
	kRouteFlagsHasGateway       = 0x0002,
	kRouteFlagsIsHost           = 0x0004,
} RouteFlags;

typedef struct {
	IFIndex         ifindex;
	RouteFlags      flags;
	struct in_addr  dest;
	struct in_addr  mask;
	struct in_addr  gateway;
	struct in_addr  ifa;
} IPv4Route, * IPv4RouteRef;

/*
 * Function: IPv4RouteApply
 * Purpose:
 *   Add or remove the specified route to/from the kernel routing table.
 */
static int
IPv4RouteApply(IPv4RouteRef route, int cmd, int sockfd)
{
	size_t          len;
	int             ret = 0;
	route_msg       rtmsg;
	union {
		struct sockaddr_in *    in_p;
		struct sockaddr_dl *    dl_p;
		void *                  ptr;
	} rtaddr;
	static int      rtm_seq;
	static int      rtm_seq_inited;

	if (rtm_seq_inited == 0) {
		rtm_seq_inited = 1;
		rtm_seq = arc4random();
		T_LOG("pid %d: rtm start seq %d\n", getpid(), rtm_seq);
	}

	if (route->ifindex == 0) {
		T_LOG(
			"no interface specified, ignoring %s\n",
			inet_ntoa(route->dest));
		return ENXIO;
	}
	if (sockfd == -1) {
		return EBADF;
	}
	memset(&rtmsg, 0, sizeof(rtmsg));
	rtmsg.hdr.rtm_type = cmd;
	rtmsg.hdr.rtm_version = RTM_VERSION;
	rtmsg.hdr.rtm_seq = rtm_seq++;
	rtmsg.hdr.rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_IFP;
	if (route->ifa.s_addr != 0) {
		rtmsg.hdr.rtm_addrs |= RTA_IFA;
	}
	rtmsg.hdr.rtm_flags = RTF_UP | RTF_STATIC;
	if ((route->flags & kRouteFlagsIsHost) != 0) {
		rtmsg.hdr.rtm_flags |= RTF_HOST;
	} else {
		rtmsg.hdr.rtm_addrs |= RTA_NETMASK;
		if ((route->flags & kRouteFlagsHasGateway) == 0) {
			rtmsg.hdr.rtm_flags |= RTF_CLONING;
		}
	}
	if ((route->flags & kRouteFlagsHasGateway) != 0) {
		rtmsg.hdr.rtm_flags |= RTF_GATEWAY;
	}
	if ((route->flags & kRouteFlagsIsScoped) != 0) {
		rtmsg.hdr.rtm_index = route->ifindex;
		rtmsg.hdr.rtm_flags |= RTF_IFSCOPE;
	}

	rtaddr.ptr = rtmsg.addrs;

	/* dest */
	rtaddr.in_p->sin_len = sizeof(*rtaddr.in_p);
	rtaddr.in_p->sin_family = AF_INET;
	rtaddr.in_p->sin_addr = route->dest;
	rtaddr.ptr += sizeof(*rtaddr.in_p);

	/* gateway */
	if ((rtmsg.hdr.rtm_flags & RTF_GATEWAY) != 0) {
		/* gateway is an IP address */
		rtaddr.in_p->sin_len = sizeof(*rtaddr.in_p);
		rtaddr.in_p->sin_family = AF_INET;
		rtaddr.in_p->sin_addr = route->gateway;
		rtaddr.ptr += sizeof(*rtaddr.in_p);
	} else {
		/* gateway is the interface itself */
		rtaddr.dl_p->sdl_len = sizeof(*rtaddr.dl_p);
		rtaddr.dl_p->sdl_family = AF_LINK;
		rtaddr.dl_p->sdl_index = route->ifindex;
		rtaddr.ptr += sizeof(*rtaddr.dl_p);
	}

	/* mask */
	if ((rtmsg.hdr.rtm_addrs & RTA_NETMASK) != 0) {
		rtaddr.in_p->sin_len = sizeof(*rtaddr.in_p);
		rtaddr.in_p->sin_family = AF_INET;
		rtaddr.in_p->sin_addr = route->mask;
		rtaddr.ptr += sizeof(*rtaddr.in_p);
	}

	/* interface */
	if ((rtmsg.hdr.rtm_addrs & RTA_IFP) != 0) {
		rtaddr.dl_p->sdl_len = sizeof(*rtaddr.dl_p);
		rtaddr.dl_p->sdl_family = AF_LINK;
		rtaddr.dl_p->sdl_index = route->ifindex;
		rtaddr.ptr += sizeof(*rtaddr.dl_p);
	}
	/* interface address */
	if ((rtmsg.hdr.rtm_addrs & RTA_IFA) != 0) {
		rtaddr.in_p->sin_len = sizeof(*rtaddr.in_p);
		rtaddr.in_p->sin_family = AF_INET;
		rtaddr.in_p->sin_addr = route->ifa;
		rtaddr.ptr += sizeof(*rtaddr.in_p);
	}

	/* apply the route */
	len = (int)(sizeof(rtmsg.hdr) + (rtaddr.ptr - (void *)rtmsg.addrs));
	rtmsg.hdr.rtm_msglen = len;
	if (write(sockfd, &rtmsg, len) == -1) {
		ret = errno;
	}
	return ret;
}

static int
open_routing_socket(void)
{
	int sockfd;

	if ((sockfd = socket(PF_ROUTE, SOCK_RAW, PF_ROUTE)) == -1) {
		perror("socket");
	}
	return sockfd;
}


int
sktc_ifnet_add_scoped_default_route(char * ifname, struct in_addr ifa)
{
	int             error;
	IPv4Route       route;
	int             sockfd;

	bzero(&route, sizeof(route));
	route.flags |= kRouteFlagsIsScoped;
	route.ifa = ifa;
	route.ifindex = if_nametoindex(ifname);
	if (route.ifindex == 0) {
		return ENOENT;
	}
	sockfd = open_routing_socket();
	error = IPv4RouteApply(&route, RTM_ADD, sockfd);
	if (sockfd >= 0) {
		close(sockfd);
	}
	return error;
}

/* interval in nanoseconds */
int
sktc_set_classq_update_interval(uint64_t ns, sktc_classq_type_t type)
{
	int     error;
	char    *sysctl_name;

	switch (type) {
	case SKTC_CLASSQ_DEF_C:
		sysctl_name = "net.classq.def_c_update_interval";
		break;
	case SKTC_CLASSQ_DEF_L4S:
		sysctl_name = "net.classq.def_l4s_update_interval";
		break;
	case SKTC_CLASSQ_LL_C:
		sysctl_name = "net.classq.ll_c_update_interval";
		break;
	case SKTC_CLASSQ_LL_L4S:
		sysctl_name = "net.classq.ll_l4s_update_interval";
		break;

	default:
		assert(0);
		__builtin_unreachable();
		break;
	}

	error = sysctlbyname(sysctl_name,
	    NULL, NULL, &ns, sizeof(ns));

	if (error != 0) {
		SKT_LOG(
			"sysctlbyname(%s) failed, %s\n", sysctl_name,
			strerror(errno));
	}
	return error;
}

/* interval in nanoseconds */
int
sktc_set_classq_update_intervals(uint64_t ns)
{
	int     error;

	error = sktc_set_classq_update_interval(ns, SKTC_CLASSQ_DEF_C);
	assert(error == 0);
	error = sktc_set_classq_update_interval(ns, SKTC_CLASSQ_DEF_L4S);
	assert(error == 0);
	error = sktc_set_classq_update_interval(ns, SKTC_CLASSQ_LL_C);
	assert(error == 0);
	error = sktc_set_classq_update_interval(ns, SKTC_CLASSQ_LL_L4S);
	assert(error == 0);

	return 0;
}

int
sktc_reset_classq_update_interval(sktc_classq_type_t type)
{
	return sktc_set_classq_update_interval(0, type);
}

int
sktc_reset_classq_update_intervals(void)
{
	return sktc_set_classq_update_intervals(0);
}

/* interval in nanoseconds */
int
sktc_set_classq_target_qdelay(uint64_t ns, sktc_classq_type_t type)
{
	int     error;
	char    *sysctl_name;

	switch (type) {
	case SKTC_CLASSQ_DEF_C:
		sysctl_name = "net.classq.def_c_target_qdelay";
		break;
	case SKTC_CLASSQ_DEF_L4S:
		sysctl_name = "net.classq.def_l4s_target_qdelay";
		break;
	case SKTC_CLASSQ_LL_C:
		sysctl_name = "net.classq.ll_c_target_qdelay";
		break;
	case SKTC_CLASSQ_LL_L4S:
		sysctl_name = "net.classq.ll_l4s_target_qdelay";
		break;

	default:
		assert(0);
		__builtin_unreachable();
		break;
	}

	error = sysctlbyname(sysctl_name, NULL, NULL,
	    &ns, sizeof(ns));

	if (error != 0) {
		SKT_LOG(
			"sysctlbyname(%s) failed, %s\n", sysctl_name,
			strerror(errno));
	}
	return error;
}

/* interval in nanoseconds */
int
sktc_set_classq_target_qdelays(uint64_t ns)
{
	int     error;

	error = sktc_set_classq_target_qdelay(ns, SKTC_CLASSQ_DEF_C);
	assert(error == 0);
	error = sktc_set_classq_target_qdelay(ns, SKTC_CLASSQ_DEF_L4S);
	assert(error == 0);
	error = sktc_set_classq_target_qdelay(ns, SKTC_CLASSQ_LL_C);
	assert(error == 0);
	error = sktc_set_classq_target_qdelay(ns, SKTC_CLASSQ_LL_L4S);
	assert(error == 0);

	return 0;
}

int
sktc_reset_classq_target_qdelay(sktc_classq_type_t type)
{
	return sktc_set_classq_target_qdelay(0, type);
}

int
sktc_reset_classq_target_qdelays(void)
{
	return sktc_set_classq_target_qdelays(0);
}

static int sktc_tcp_msl;
/* interval in milliseconds */
void
sktc_set_tcp_msl(int ms)
{
	int     error;
	size_t  len = sizeof(sktc_tcp_msl);

	error = sysctlbyname("net.inet.tcp.msl",
	    &sktc_tcp_msl, &len, &ms, sizeof(ms));

	if (error != 0) {
		SKT_LOG(
			"sysctlbyname(net.inet.tcp.msl) failed, %s\n",
			strerror(errno));
	}
	SKTC_ASSERT_ERR(!error);
}

void
sktc_restore_tcp_msl(void)
{
	int             error;

	error = sysctlbyname("net.inet.tcp.msl",
	    NULL, 0, &sktc_tcp_msl, sizeof(sktc_tcp_msl));

	if (error != 0) {
		SKT_LOG(
			"sysctlbyname(net.inet.tcp.msl) failed, %s\n",
			strerror(errno));
	}
	SKTC_ASSERT_ERR(!error);
}

static int old_ip_reass_sysctl_value = -1;
static void
sktc_toggle_ip_reass(int new_value, int *old_value)
{
	size_t old_value_size = sizeof(*old_value);
	const char *ip_reass_sysctl = "kern.skywalk.flowswitch.ip_reass";
	int error;

	error = sysctlbyname(ip_reass_sysctl,
	    old_value, old_value != NULL ? &old_value_size : NULL,
	    &new_value, sizeof(new_value));
	if (error) {
		SKT_LOG("sysctlbyname(%s) failed,%s\n", ip_reass_sysctl,
		    strerror(errno));
	}
	SKTC_ASSERT_ERR(!error);
}

void
sktc_enable_ip_reass()
{
	sktc_toggle_ip_reass(1, &old_ip_reass_sysctl_value);
}

void
sktc_restore_ip_reass()
{
	assert(old_ip_reass_sysctl_value != -1);
	sktc_toggle_ip_reass(old_ip_reass_sysctl_value, NULL);
}

bool
sktc_is_ip_reass_enabled()
{
	int enabled;
	size_t len = sizeof(enabled);
	const char *ip_reass_sysctl = "kern.skywalk.flowswitch.ip_reass";
	int error;

	error = sysctlbyname(ip_reass_sysctl, &enabled, &len, NULL, 0);
	if (error) {
		SKT_LOG("sysctlbyname(%s) failed,%s\n", ip_reass_sysctl,
		    strerror(errno));
	}
	SKTC_ASSERT_ERR(!error);

	return enabled != 0; // 0 force off, 1 force on, 2 no force.
}

bool
sktc_is_netagent_enabled(void)
{
	int enabled = 0;
	size_t len = sizeof(enabled);
	const char *enable_netagent_sysctl = "net.link.generic.system.enable_netagent";
	int error;

	error = sysctlbyname(enable_netagent_sysctl, &enabled, &len, NULL, 0);
	if (error) {
		SKT_LOG("sysctlbyname(%s) failed,%s\n", enable_netagent_sysctl,
		    strerror(errno));
	}
	SKTC_ASSERT_ERR(!error);
	return enabled == 1;
}

uint64_t
sktc_get_channel_attr(const channel_t chd, channel_attr_type_t type)
{
	channel_attr_t attr;
	uint64_t attrval = -1;
	int error;

	attr = os_channel_attr_create();
	error = os_channel_read_attr(chd, attr);
	SKTC_ASSERT_ERR(!error);
	error = os_channel_attr_get(attr, type, &attrval);
	SKTC_ASSERT_ERR(!error);
	assert(attrval != -1);
	return attrval;
}

static uint32_t sktc_fsw_rx_agg_tcp = (uint32_t)-1;
void
sktc_config_fsw_rx_agg_tcp(uint32_t agg)
{
	int error;
	size_t len = sizeof(sktc_fsw_rx_agg_tcp);

	error = sysctlbyname("kern.skywalk.flowswitch.rx_agg_tcp",
	    &sktc_fsw_rx_agg_tcp, &len, &agg, sizeof(agg));

	if (error != 0) {
		SKT_LOG("sysctlbyname(kern.skywalk.flowswitch."
		    "rx_agg_tcp) failed, %s\n", strerror(errno));
	}
	SKTC_ASSERT_ERR(!error);
}

void
sktc_restore_fsw_rx_agg_tcp(void)
{
	int error;

	if (sktc_fsw_rx_agg_tcp == (uint32_t)-1) {
		return;
	}
	error = sysctlbyname("kern.skywalk.flowswitch.rx_agg_tcp",
	    NULL, 0, &sktc_fsw_rx_agg_tcp, sizeof(sktc_fsw_rx_agg_tcp));

	if (error != 0) {
		SKT_LOG("sysctlbyname(kern.skywalk.flowswitch."
		    "rx_agg_tcp) failed, %s\n", strerror(errno));
	}
	SKTC_ASSERT_ERR(!error);
}

static uint32_t sktc_channel_buflet_alloc = (uint32_t)-1;
void
sktc_enable_channel_buflet_alloc(void)
{
	int error;
	uint32_t enable = 1;
	size_t len = sizeof(sktc_channel_buflet_alloc);

	error = sysctlbyname("kern.skywalk.chan_buf_alloc",
	    &sktc_channel_buflet_alloc, &len, &enable, sizeof(enable));

	if (error != 0) {
		SKT_LOG("sysctlbyname(kern.skywalk.chan_buf_alloc "
		    "failed, %s\n", strerror(errno));
	}
	SKTC_ASSERT_ERR(!error);
}

void
sktc_restore_channel_buflet_alloc(void)
{
	int error;

	if (sktc_channel_buflet_alloc == (uint32_t)-1) {
		return;
	}
	error = sysctlbyname("kern.skywalk.chan_buf_alloc",
	    NULL, 0, &sktc_channel_buflet_alloc,
	    sizeof(sktc_channel_buflet_alloc));

	if (error != 0) {
		SKT_LOG("sysctlbyname(kern.skywalk.chan_buf_alloc "
		    "failed, %s\n", strerror(errno));
	}
	SKTC_ASSERT_ERR(!error);
}

void
skt_process_if_adv(nexus_port_t port, channel_t chan)
{
	int error;
	struct ifnet_interface_advisory ifadv;

	error = os_channel_get_interface_advisory(chan, &ifadv);
	if (error == EAGAIN) {
		T_LOG("retrying interface advisory get\n");
		error = os_channel_get_interface_advisory(chan, &ifadv);
	}
#if SKT_COMMON_DEBUG
	if (error == 0) {
		T_LOG("Interface Advisory on port %u:\n", port);
		T_LOG("\t version: %u\n", ifadv.header.version);
		T_LOG("\t direction: %u\n", ifadv.header.direction);
		T_LOG("\t rate trend: %d\n",
		    ifadv.capacity.rate_trend_suggestion);
		T_LOG("\t timestamp: 0x%llx\n",
		    ifadv.capacity.timestamp);
		T_LOG("\t max_bandwidth: 0x%llx\n",
		    ifadv.capacity.max_bandwidth);
		T_LOG("\t total_byte_count: 0x%llx\n",
		    ifadv.capacity.total_byte_count);
		T_LOG("\t average_throughput: 0x%llx\n",
		    ifadv.capacity.average_throughput);
		T_LOG("\t flushable_queue_size: %u\n",
		    ifadv.capacity.flushable_queue_size);
		T_LOG("\t non_flushable_queue_size: %u\n",
		    ifadv.capacity.non_flushable_queue_size);
		T_LOG("\t average_delay: %u\n",
		    ifadv.capacity.average_delay);
	}
#endif /* SKT_COMMON_DEBUG */
	SKTC_ASSERT_ERR(error == 0);
}

static void
skt_process_chan_event_common(channel_t chan, uint8_t payload_type,
    uint32_t stream_id, os_channel_event_type_t *captured_event_type,
    uint8_t *captured_event_data, size_t *captured_event_dlen, size_t max_event_dlen)
{
	int error;
	uint32_t nevents;
	os_channel_event_t ev;
	os_channel_event_handle_t eh;
	os_channel_event_type_t etype;
	packet_id_t *packet_id;
	struct os_channel_event_data ed;

	error = os_channel_get_next_event_handle(chan, &eh, &etype,
	    &nevents);
	SKTC_ASSERT_ERR(error == 0);
	error = os_channel_event_get_next_event(eh, 0, &ev);
	SKTC_ASSERT_ERR(error == 0);
	error = os_channel_event_get_event_data(ev, &ed);
	SKTC_ASSERT_ERR(error == 0);
	assert(sizeof(*packet_id) <= ed.event_data_length);
	packet_id = (packet_id_t*)ed.event_data;

 #if SKT_COMMON_DEBUG
	T_LOG("chan event: packet: [%03hhu-%03hhu-%05hu-%05u-%05u-(%05u)] [%03hhu-%03hhu-xxxxx-xxxxx-%05u-(xxxxx)] event [%1u %03hu] [%1u %03hu]\n",
	    packet_id->pktid_version,
	    packet_id->pktid_payload_type,
	    packet_id->pktid_sequence_number,
	    packet_id->pktid_timestamp,
	    packet_id->pktid_stream_identifier,
	    packet_id->_reserved,

	    (uint8_t)OS_PACKET_PKTID_VERSION_CURRENT,
	    payload_type,
	    stream_id,

	    ed.event_type,
	    ed.event_data_length,
	    etype,
	    (uint16_t)max_event_dlen
	    );
#endif /* SKT_COMMON_DEBUG */
	assert(nevents == 1);
	assert(etype == ed.event_type);
	assert(packet_id->pktid_payload_type == payload_type);
	assert(packet_id->pktid_stream_identifier == stream_id);
	assert(packet_id->pktid_version == OS_PACKET_PKTID_VERSION_CURRENT);
	assert(!ed.event_more);
	assert(ed.event_data_length <= max_event_dlen);

	memcpy(captured_event_data, ed.event_data, ed.event_data_length);
	*captured_event_dlen = ed.event_data_length;
	*captured_event_type = etype;

	error = os_channel_event_free(chan, eh);
	SKTC_ASSERT_ERR(error == 0);
}

void
skt_process_channel_event(channel_t chan, uint8_t payload_type, uint32_t stream_id,
    transmit_status_event_handler_t transmit_status_handler,
    transmit_expired_event_handler_t transmit_expired_handler,
    wildcard_event_handler_t wildcard_handler)
{
	os_channel_event_type_t event_type;
	uint8_t event_data[CHANNEL_EVENT_MAX_PAYLOAD_LEN];
	size_t event_dlen;
	skt_process_chan_event_common(chan, payload_type, stream_id,
	    &event_type, event_data, &event_dlen, sizeof(event_data));

#if SKT_COMMON_DEBUG
	T_LOG("expiry_event=%p len=%lu [%lu]\n",
	    event_data, event_dlen, sizeof(event_data));
#endif /* SKT_COMMON_DEBUG */

	switch (event_type) {
	case CHANNEL_EVENT_PACKET_TRANSMIT_STATUS:
		assert(event_dlen == sizeof(os_channel_event_packet_transmit_status_t));
		assert(transmit_status_handler != NULL || wildcard_handler != NULL);
		if (transmit_status_handler != NULL) {
			transmit_status_handler(
				(os_channel_event_packet_transmit_status_t*)event_data);
		} else {
			assert(wildcard_handler != NULL);
			wildcard_handler(event_type, event_data, event_dlen);
		}
		break;
	case CHANNEL_EVENT_PACKET_TRANSMIT_EXPIRED:
		assert(event_dlen == sizeof(os_channel_event_packet_transmit_expired_t));
		assert(transmit_expired_handler != NULL || wildcard_handler != NULL);
		if (transmit_expired_handler != NULL) {
			transmit_expired_handler(
				(os_channel_event_packet_transmit_expired_t*)event_data);
		} else {
			assert(wildcard_handler != NULL);
			wildcard_handler(event_type, event_data, event_dlen);
		}
		break;
	default:
		assert(wildcard_handler != NULL);
		wildcard_handler(event_type, event_data, event_dlen);
		break;
	}
}

static struct sockaddr_inarp *
getaddr(struct in_addr host)
{
	static struct sockaddr_inarp reply;

	bzero(&reply, sizeof(reply));
	reply.sin_len = sizeof(reply);
	reply.sin_family = AF_INET;
	reply.sin_addr = host;
	return &reply;
}

/*
 * Returns true if the type is a valid one for ARP.
 */
static int
valid_type(int type)
{
	switch (type) {
	case IFT_ETHER:
	case IFT_FDDI:
	case IFT_ISO88023:
	case IFT_ISO88024:
	case IFT_L2VLAN:
#ifdef IFT_BRIDGE
	case IFT_BRIDGE:
#endif
		return 1;
	default:
		return 0;
	}
}

static struct rt_msghdr *
rtmsg(int cmd, struct sockaddr_inarp *dst, struct sockaddr_dl *sdl)
{
	static int seq;
	int rlen;
	int l;
	struct sockaddr_in so_mask, *so_mask_ptr = &so_mask;
	static int s = -1;
	static pid_t pid;

	static struct {
		struct  rt_msghdr m_rtm;
		char    m_space[512];
	} m_rtmsg;

	struct rt_msghdr *rtm = &m_rtmsg.m_rtm;
	char *cp = m_rtmsg.m_space;

	if (s < 0) {    /* first time: open socket, get pid */
		s = socket(PF_ROUTE, SOCK_RAW, 0);
		if (s < 0) {
			err(1, "socket() failed\n");
		}
		pid = getpid();
	}
	bzero(&so_mask, sizeof(so_mask));
	so_mask.sin_len = 8;
	so_mask.sin_addr.s_addr = 0xffffffff;

	errno = 0;
	/*
	 * XXX RTM_DELETE relies on a previous RTM_GET to fill the buffer
	 * appropriately (except for the mask set just above).
	 */
	if (cmd == RTM_DELETE) {
		goto doit;
	}
	bzero((char *)&m_rtmsg, sizeof(m_rtmsg));
	rtm->rtm_flags = flags;
	rtm->rtm_version = RTM_VERSION;

	switch (cmd) {
	default:
		errx(1, "internal wrong cmd");
	case RTM_ADD:
		rtm->rtm_addrs |= RTA_GATEWAY;
		rtm->rtm_rmx.rmx_expire = expire_time;
		rtm->rtm_inits = RTV_EXPIRE;
		rtm->rtm_flags |= (RTF_HOST | RTF_STATIC);
		dst->sin_other = 0;
	/* FALLTHROUGH */
	case RTM_GET:
		rtm->rtm_addrs |= RTA_DST;
	}

#define NEXTADDR(w, s) \
	if ((s) != NULL && rtm->rtm_addrs & (w)) { \
	        bcopy((s), cp, sizeof(*(s))); cp += SA_SIZE(s);}

	NEXTADDR(RTA_DST, dst);
	NEXTADDR(RTA_GATEWAY, sdl);
	NEXTADDR(RTA_NETMASK, so_mask_ptr);

	rtm->rtm_msglen = cp - (char *)&m_rtmsg;
doit:
	l = rtm->rtm_msglen;
	rtm->rtm_seq = ++seq;
	rtm->rtm_type = cmd;
	if ((rlen = write(s, (char *)&m_rtmsg, l)) < 0) {
		if (errno != ESRCH || cmd != RTM_DELETE) {
			warn("writing to routing socket");
			return NULL;
		}
	}
	do {
		l = read(s, (char *)&m_rtmsg, sizeof(m_rtmsg));
	} while (l > 0 && (rtm->rtm_seq != seq || rtm->rtm_pid != pid));
	if (l < 0) {
		warn("read from routing socket");
	}
	return rtm;
}

int
skt_add_arp_entry(struct in_addr host, struct ether_addr *eaddr)
{
	struct sockaddr_inarp *addr;
	struct sockaddr_inarp *dst;     /* what are we looking for */
	struct sockaddr_dl *sdl;
	struct rt_msghdr *rtm;
	struct ether_addr *ea;
	struct sockaddr_dl sdl_m;

	bzero(&sdl_m, sizeof(sdl_m));
	sdl_m.sdl_len = sizeof(sdl_m);
	sdl_m.sdl_family = AF_LINK;

	dst = getaddr(host);
	if (dst == NULL) {
		return 1;
	}
	flags = expire_time = 0;

	ea = (struct ether_addr *)LLADDR(&sdl_m);
	*ea = *eaddr;
	sdl_m.sdl_alen = ETHER_ADDR_LEN;

	for (;;) {      /* try at most twice */
		rtm = rtmsg(RTM_GET, dst, &sdl_m);
		if (rtm == NULL) {
			warn("%s", inet_ntoa(host));
			return 1;
		}
		addr = (struct sockaddr_inarp *)(rtm + 1);
		sdl = (struct sockaddr_dl *)(SA_SIZE(addr) + (char *)addr);
		if (addr->sin_addr.s_addr != dst->sin_addr.s_addr) {
			break;
		}
		if (sdl->sdl_family == AF_LINK &&
		    (rtm->rtm_flags & RTF_LLINFO) &&
		    !(rtm->rtm_flags & RTF_GATEWAY) &&
		    valid_type(sdl->sdl_type)) {
			break;
		}
	}

	if (sdl->sdl_family != AF_LINK) {
		T_LOG("cannot intuit interface index and type for %s\n",
		    inet_ntoa(host));
		return 1;
	}
	sdl_m.sdl_type = sdl->sdl_type;
	sdl_m.sdl_index = sdl->sdl_index;
	return rtmsg(RTM_ADD, dst, &sdl_m) == NULL;
}

static void
update_avg(struct if_ifclassq_stats *ifcqs, struct queue_stats *qs)
{
	u_int64_t                b, p;
	int                      n;

	n = qs->avgn;

	switch (ifcqs->ifqs_scheduler) {
	case PKTSCHEDT_FQ_CODEL:
		b = ifcqs->ifqs_fq_codel_stats.fcls_dequeue_bytes;
		p = ifcqs->ifqs_fq_codel_stats.fcls_dequeue;
		break;
	default:
		b = 0;
		p = 0;
		break;
	}

	if (n == 0) {
		qs->prev_bytes = b;
		qs->prev_packets = p;
		qs->avgn++;
		return;
	}

	if (b >= qs->prev_bytes) {
		qs->avg_bytes = ((qs->avg_bytes * (n - 1)) +
		    (b - qs->prev_bytes)) / n;
	}

	if (p >= qs->prev_packets) {
		qs->avg_packets = ((qs->avg_packets * (n - 1)) +
		    (p - qs->prev_packets)) / n;
	}

	qs->prev_bytes = b;
	qs->prev_packets = p;
	if (n < AVGN_MAX) {
		qs->avgn++;
	}
}


static char *
nsec_to_str(unsigned long long nsec)
{
	static char buf[32];
	const char *u;
	long double n = nsec, t;

	if (nsec >= NSEC_PER_SEC) {
		t = n / NSEC_PER_SEC;
		u = "sec ";
	} else if (n >= USEC_PER_SEC) {
		t = n / USEC_PER_SEC;
		u = "msec";
	} else if (n >= MSEC_PER_SEC) {
		t = n / MSEC_PER_SEC;
		u = "usec";
	} else {
		t = n;
		u = "nsec";
	}

	snprintf(buf, sizeof(buf), "%-4.2Lf %4s", t, u);
	return buf;
}

static char *
sched2str(unsigned int s)
{
	char *c;

	switch (s) {
	case PKTSCHEDT_NONE:
		c = "NONE";
		break;
	case PKTSCHEDT_FQ_CODEL:
		c = "FQ_CODEL";
		break;
	default:
		c = "UNKNOWN";
		break;
	}

	return c;
}

static char *
pri2str(unsigned int i)
{
	char *c;
	switch (i) {
	case 9:
		c = "BK_SYS";
		break;
	case 8:
		c = "BK";
		break;
	case 7:
		c = "BE";
		break;
	case 6:
		c = "RD";
		break;
	case 5:
		c = "OAM";
		break;
	case 4:
		c = "AV";
		break;
	case 3:
		c = "RV";
		break;
	case 2:
		c = "VI";
		break;
	case 1:
		c = "VO";
		break;
	case 0:
		c = "CTL";
		break;
	default:
		c = "?";
		break;
	}
	return c;
}

void
skt_aqstatpr(const char *interface)
{
	unsigned int ifindex;
	struct if_qstatsreq ifqr;
	struct if_ifclassq_stats *ifcqs;
	u_int32_t scheduler;
	int s, n;

	qflag = 2;  /* The 2 comes from the # of q's in netstat -qq */

	ifindex = if_nametoindex(interface);
	if (ifindex == 0) {
		T_LOG("Invalid interface name\n");
		return;
	}

	ifcqs = malloc(sizeof(*ifcqs));
	if (ifcqs == NULL) {
		T_LOG("Unable to allocate memory\n");
		return;
	}

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("Warning: socket(AF_INET)");
		free(ifcqs);
		return;
	}

	bzero(&ifqr, sizeof(ifqr));
	strlcpy(ifqr.ifqr_name, interface, sizeof(ifqr.ifqr_name));
	ifqr.ifqr_buf = ifcqs;
	ifqr.ifqr_len = sizeof(*ifcqs);

	ifqr.ifqr_slot = 0;
	if (ioctl(s, SIOCGIFQUEUESTATS, (char *)&ifqr) < 0) {
		if (errno == ENXIO) {
			os_log(OS_LOG_DEFAULT, "Queue statistics are not available on %s\n",
			    interface);
		} else {
			perror("Warning: ioctl(SIOCGIFQUEUESTATS)");
		}
		goto done;
	}
	scheduler = ifcqs->ifqs_scheduler;

	os_log(OS_LOG_DEFAULT, "%s:"
	    "     [ sched: %18s  qlength:  %3u/%3u ]\n",
	    interface, sched2str(ifcqs->ifqs_scheduler),
	    ifcqs->ifqs_len, ifcqs->ifqs_maxlen);
	os_log(OS_LOG_DEFAULT, "     [ dequeued pkts: %10llu  bytes: %10llu "
	    " dropped pkts: %6llu bytes: %6llu ]\n",
	    ifcqs->ifqs_xmitcnt.packets, ifcqs->ifqs_xmitcnt.bytes,
	    ifcqs->ifqs_dropcnt.packets, ifcqs->ifqs_dropcnt.bytes);

	for (n = 0; n < IFCQ_SC_MAX && scheduler != PKTSCHEDT_NONE; n++) {
		ifqr.ifqr_slot = n;
		if (ioctl(s, SIOCGIFQUEUESTATS, (char *)&ifqr) < 0) {
			perror("Warning: ioctl(SIOCGIFQUEUESTATS)");
			goto done;
		}

		update_avg(ifcqs, &qstats[n]);

		switch (scheduler) {
		case PKTSCHEDT_FQ_CODEL:
			print_fq_codel_stats(n,
			    &ifcqs->ifqs_fq_codel_stats,
			    &qstats[n]);
			break;
		case PKTSCHEDT_NONE:
		default:
			break;
		}
	}

done:
	free(ifcqs);
	close(s);
}

static void
print_fq_codel_stats(int pri, struct fq_codel_classstats *fqst,
    struct queue_stats *qs)
{
	int i = 0;

	if (fqst->fcls_service_class == 0 && fqst->fcls_pri == 0) {
		return;
	}
	os_log(OS_LOG_DEFAULT, "=====================================================\n");
	os_log(OS_LOG_DEFAULT, "     [ pri: %s (%u)\tsrv_cl: 0x%x\tquantum: %u\tdrr_max: %u ]\n",
	    pri2str(fqst->fcls_pri), fqst->fcls_pri,
	    fqst->fcls_service_class, fqst->fcls_quantum,
	    fqst->fcls_drr_max);
	os_log(OS_LOG_DEFAULT, "     [ queued pkts: %llu\tbytes: %llu ]\n",
	    fqst->fcls_pkt_cnt, fqst->fcls_byte_cnt);
	os_log(OS_LOG_DEFAULT, "     [ dequeued pkts: %llu\tbytes: %llu ]\n",
	    fqst->fcls_dequeue, fqst->fcls_dequeue_bytes);
	os_log(OS_LOG_DEFAULT, "     [ budget: %lld\ttarget qdelay: %10s\tupdate interval:%10s ]\n",
	    fqst->fcls_budget, nsec_to_str(fqst->fcls_target_qdelay), nsec_to_str(fqst->fcls_update_interval));
	os_log(OS_LOG_DEFAULT, "     [ flow control: %u\tfeedback: %u\tstalls: %u\tfailed: %u \toverwhelming: %u ]\n",
	    fqst->fcls_flow_control, fqst->fcls_flow_feedback,
	    fqst->fcls_dequeue_stall, fqst->fcls_flow_control_fail, fqst->fcls_overwhelming);
	os_log(OS_LOG_DEFAULT, "     [ drop overflow: %llu\tearly: %llu\tmemfail: %u\tduprexmt:%u ]\n",
	    fqst->fcls_drop_overflow, fqst->fcls_drop_early,
	    fqst->fcls_drop_memfailure, fqst->fcls_dup_rexmts);
	os_log(OS_LOG_DEFAULT, "     [ l4s target qdelay: %10s ]\n", nsec_to_str(fqst->fcls_l4s_target_qdelay));
	os_log(OS_LOG_DEFAULT, "     [ ce marked:%llu\tce mark failures:%llu\tce reported:%llu\tL4S pkts:%llu   ]\n",
	    fqst->fcls_ce_marked, fqst->fcls_ce_mark_failures, fqst->fcls_ce_reported, fqst->fcls_l4s_pkts);
	os_log(OS_LOG_DEFAULT, "     [ flows total: %u\tnew: %u\told: %u ]\n",
	    fqst->fcls_flows_cnt,
	    fqst->fcls_newflows_cnt, fqst->fcls_oldflows_cnt);
	os_log(OS_LOG_DEFAULT, "     [ throttle on: %u\toff: %u\tdrop: %u ]\n",
	    fqst->fcls_throttle_on, fqst->fcls_throttle_off,
	    fqst->fcls_throttle_drops);
	os_log(OS_LOG_DEFAULT, "     [ compressible pkts: %u compressed pkts: %u]\n",
	    fqst->fcls_pkts_compressible, fqst->fcls_pkts_compressed);

	if (qflag < 2) {
		return;
	}

	if (fqst->fcls_flowstats_cnt > 0) {
		os_log(OS_LOG_DEFAULT, "Flowhash\tBytes\tMin qdelay\tFlags\t\n");
		for (i = 0; i < fqst->fcls_flowstats_cnt; i++) {
			os_log(OS_LOG_DEFAULT, "%u\t%u\t%14s\t",
			    fqst->fcls_flowstats[i].fqst_flowhash,
			    fqst->fcls_flowstats[i].fqst_bytes,
			    nsec_to_str(fqst->fcls_flowstats[i].fqst_min_qdelay));
			if (fqst->fcls_flowstats[i].fqst_flags &
			    FQ_FLOWSTATS_OLD_FLOW) {
				os_log(OS_LOG_DEFAULT, "O");
			}
			if (fqst->fcls_flowstats[i].fqst_flags &
			    FQ_FLOWSTATS_NEW_FLOW) {
				os_log(OS_LOG_DEFAULT, "N");
			}
			if (fqst->fcls_flowstats[i].fqst_flags &
			    FQ_FLOWSTATS_LARGE_FLOW) {
				os_log(OS_LOG_DEFAULT, "L");
			}
			if (fqst->fcls_flowstats[i].fqst_flags &
			    FQ_FLOWSTATS_DELAY_HIGH) {
				os_log(OS_LOG_DEFAULT, "D");
			}
			if (fqst->fcls_flowstats[i].fqst_flags &
			    FQ_FLOWSTATS_FLOWCTL_ON) {
				os_log(OS_LOG_DEFAULT, "F");
			}
			os_log(OS_LOG_DEFAULT, "\n");
		}
	}
}



char *
plural(int n)
{
	return n > 1 ? "s" : "";
}

char *
plurales(int n)
{
	return n > 1 ? "es" : "";
}

char *
pluralies(int n)
{
	return n > 1 ? "ies" : "y";
}

/*
 * Dump ARP statistics structure.
 */
static void
arp_stats(uint32_t off, char *name, int af)
{
	static struct arpstat parpstat;
	struct arpstat arpstat;
	size_t len = sizeof(arpstat);

	if (sysctlbyname("net.link.ether.inet.stats", &arpstat,
	    &len, 0, 0) < 0) {
		warn("sysctl: net.link.ether.inet.stats");
		return;
	}

	os_log(OS_LOG_DEFAULT, "%s:\n", name);

#define ARPDIFF(f) (arpstat.f - parpstat.f)
#define p(f, m) \
os_log(OS_LOG_DEFAULT, m, ARPDIFF(f), plural(ARPDIFF(f)))
#define p2(f, m) \
os_log(OS_LOG_DEFAULT, m, ARPDIFF(f), pluralies(ARPDIFF(f)))
#define p3(f, m) \
os_log(OS_LOG_DEFAULT, m, ARPDIFF(f), plural(ARPDIFF(f)), pluralies(ARPDIFF(f)))

	p(txrequests, "\t%u broadast ARP request%s sent\n");
	p(txurequests, "\t%u unicast ARP request%s sent\n");
	p2(txreplies, "\t%u ARP repl%s sent\n");
	p(txannounces, "\t%u ARP announcement%s sent\n");
	p(rxrequests, "\t%u ARP request%s received\n");
	p2(rxreplies, "\t%u ARP repl%s received\n");
	p(received, "\t%u total ARP packet%s received\n");
	p(txconflicts, "\t%u ARP conflict probe%s sent\n");
	p(invalidreqs, "\t%u invalid ARP resolve request%s\n");
	p(reqnobufs, "\t%u total packet%s dropped due to lack of memory\n");
	p3(held, "\t%u total packet%s held awaiting ARP repl%s\n");
	p(dropped, "\t%u total packet%s dropped due to no ARP entry\n");
	p(purged, "\t%u total packet%s dropped during ARP entry removal\n");
	p2(timeouts, "\t%u ARP entr%s timed out\n");
	p(dupips, "\t%u Duplicate IP%s seen\n");

#undef ARPDIFF
#undef p
#undef p2
}

/*
 * Print out protocol statistics or control blocks (per sflag).
 * If the interface was not specifically requested, and the symbol
 * is not in the namelist, ignore this one.
 */
void
skt_printproto(register struct protox *tp, char *name)
{
	void (*pr)(uint32_t, char *, int);
	uint32_t off;
	int af = AF_UNSPEC;

	pr = tp->pr_stats;
	if (!pr) {
		return;
	}
	off = tp->pr_protocol;
	if (pr != NULL) {
		(*pr)(off, name, af);
	} else {
		T_LOG("### no stats for %s\n", name);
	}
}
