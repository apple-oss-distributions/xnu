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

/* This file contains useful utility routines, but contrary to skywalk_test_common
 * Do not operate on a single set of static objects
 */

/*
 * Copyright (c) 1988, 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 *	@(#)in_cksum.c	8.1 (Berkeley) 6/10/93
 */


#include <err.h>
#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <sys/event.h>
#include <uuid/uuid.h>
#include <arpa/inet.h>
#include <stddef.h>
#include <sysexits.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <net/if_utun.h>
#include <net/if_ipsec.h>
#include <netinet/ip6.h>
#include <sys/kern_control.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <ifaddrs.h>
#include <sys/fcntl.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <net/if_utun.h>
#include <os/log.h>

#include <net/pfkeyv2.h>
#include <netinet6/ipsec.h>
#include <darwintest.h>

#include "skywalk_test_driver.h"
#include "skywalk_test_common.h" // XXX remove this
#include "skywalk_test_utils.h"

#define SIN(s)          ((struct sockaddr_in *)(void *)s)
#define SIN6(s)          ((struct sockaddr_in6 *)(void *)s)

void
sktc_build_nexus(nexus_controller_t ncd, struct sktc_nexus_attr *sktc_attr,
    uuid_t *providerp, uuid_t *instancep)
{
	nexus_attr_t attr;
	int error;
	uint64_t scratch;

	attr = os_nexus_attr_create();
	assert(attr);

	if (sktc_attr->anonymous != -1) {
		error = os_nexus_attr_set(attr, NEXUS_ATTR_ANONYMOUS,
		    sktc_attr->anonymous);
		SKTC_ASSERT_ERR(!error);
	}
	if (sktc_attr->userchannel != -1) {
		error = os_nexus_attr_set(attr, NEXUS_ATTR_USER_CHANNEL,
		    sktc_attr->userchannel);
		SKTC_ASSERT_ERR(!error);
	}
	if (sktc_attr->ntxrings != -1) {
		error = os_nexus_attr_set(attr, NEXUS_ATTR_TX_RINGS,
		    sktc_attr->ntxrings);
		SKTC_ASSERT_ERR(!error);
	}
	if (sktc_attr->nrxrings != -1) {
		error = os_nexus_attr_set(attr, NEXUS_ATTR_RX_RINGS,
		    sktc_attr->nrxrings);
		SKTC_ASSERT_ERR(!error);
	}
	if (sktc_attr->ntxslots != -1) {
		error = os_nexus_attr_set(attr, NEXUS_ATTR_TX_SLOTS,
		    sktc_attr->ntxslots);
		SKTC_ASSERT_ERR(!error);
	}
	if (sktc_attr->nrxslots != -1) {
		error = os_nexus_attr_set(attr, NEXUS_ATTR_RX_SLOTS,
		    sktc_attr->nrxslots);
		SKTC_ASSERT_ERR(!error);
	}
	if (sktc_attr->slotsize != -1) {
		error = os_nexus_attr_set(attr, NEXUS_ATTR_SLOT_BUF_SIZE,
		    sktc_attr->slotsize);
		SKTC_ASSERT_ERR(!error);
	}
	if (sktc_attr->metasize != -1) {
		error = os_nexus_attr_set(attr, NEXUS_ATTR_SLOT_META_SIZE,
		    sktc_attr->metasize);
		SKTC_ASSERT_ERR(error == ENOTSUP);
	}
	if (sktc_attr->maxfrags != -1) {
		error = os_nexus_attr_set(attr, NEXUS_ATTR_MAX_FRAGS,
		    sktc_attr->maxfrags);
		SKTC_ASSERT_ERR(!error);
	}
	if (sktc_attr->rejectonclose != -1) {
		error = os_nexus_attr_set(attr, NEXUS_ATTR_REJECT_ON_CLOSE,
		    sktc_attr->rejectonclose);
		SKTC_ASSERT_ERR(!error);
	}

	uuid_clear(*providerp);
	error = os_nexus_controller_register_provider(ncd,
	    sktc_attr->name, sktc_attr->type, attr, providerp);
	SKTC_ASSERT_ERR(!error);
	assert(!uuid_is_null(*providerp));

	/* Clear the parameters to make sure they are being read */
	error = os_nexus_attr_set(attr, NEXUS_ATTR_ANONYMOUS, -1);
	SKTC_ASSERT_ERR(!error);
	error = os_nexus_attr_set(attr, NEXUS_ATTR_TX_RINGS, -1);
	SKTC_ASSERT_ERR(!error);
	error = os_nexus_attr_set(attr, NEXUS_ATTR_RX_RINGS, -1);
	SKTC_ASSERT_ERR(!error);
	error = os_nexus_attr_set(attr, NEXUS_ATTR_TX_SLOTS, -1);
	SKTC_ASSERT_ERR(!error);
	error = os_nexus_attr_set(attr, NEXUS_ATTR_RX_SLOTS, -1);
	SKTC_ASSERT_ERR(!error);
	error = os_nexus_attr_set(attr, NEXUS_ATTR_SLOT_BUF_SIZE, -1);
	SKTC_ASSERT_ERR(!error);
	error = os_nexus_attr_set(attr, NEXUS_ATTR_SLOT_META_SIZE, -1);
	SKTC_ASSERT_ERR(error == ENOTSUP);
	error = os_nexus_attr_set(attr, NEXUS_ATTR_EXTENSIONS, -1);
	SKTC_ASSERT_ERR(!error);
	error = os_nexus_attr_set(attr, NEXUS_ATTR_MAX_FRAGS, -1);
	SKTC_ASSERT_ERR(!error);
	error = os_nexus_attr_set(attr, NEXUS_ATTR_REJECT_ON_CLOSE, -1);
	SKTC_ASSERT_ERR(!error);

	error = os_nexus_controller_read_provider_attr(ncd,
	    *providerp, attr);
	SKTC_ASSERT_ERR(!error);

	scratch = -1;
	error = os_nexus_attr_get(attr, NEXUS_ATTR_ANONYMOUS, &scratch);
	SKTC_ASSERT_ERR(!error);
	assert(scratch != -1);
	assert(sktc_attr->anonymous == -1 || sktc_attr->anonymous == scratch);

	scratch = -1;
	error = os_nexus_attr_get(attr, NEXUS_ATTR_USER_CHANNEL, &scratch);
	SKTC_ASSERT_ERR(!error);
	assert(scratch != -1);
	assert(sktc_attr->userchannel == -1 ||
	    sktc_attr->userchannel == scratch);

	scratch = -1;
	error = os_nexus_attr_get(attr, NEXUS_ATTR_TX_RINGS, &scratch);
	SKTC_ASSERT_ERR(!error);
	assert(scratch != -1);
	assert(sktc_attr->ntxrings == -1 || sktc_attr->ntxrings == scratch);

	scratch = -1;
	error = os_nexus_attr_get(attr, NEXUS_ATTR_RX_RINGS, &scratch);
	SKTC_ASSERT_ERR(!error);
	assert(scratch != -1);
	assert(sktc_attr->nrxrings == -1 || sktc_attr->nrxrings == scratch);

	scratch = -1;
	error = os_nexus_attr_get(attr, NEXUS_ATTR_TX_SLOTS, &scratch);
	SKTC_ASSERT_ERR(!error);
	assert(scratch != -1);
	assert(sktc_attr->ntxslots == -1 || sktc_attr->ntxslots == scratch);

	scratch = -1;
	error = os_nexus_attr_get(attr, NEXUS_ATTR_RX_SLOTS, &scratch);
	SKTC_ASSERT_ERR(!error);
	assert(scratch != -1);
	assert(sktc_attr->nrxslots == -1 || sktc_attr->nrxslots == scratch);

	scratch = -1;
	error = os_nexus_attr_get(attr, NEXUS_ATTR_SLOT_BUF_SIZE, &scratch);
	SKTC_ASSERT_ERR(!error);
	assert(scratch != -1);
	assert(sktc_attr->slotsize == -1 || sktc_attr->slotsize == scratch);

	scratch = -1;
	error = os_nexus_attr_get(attr, NEXUS_ATTR_SLOT_META_SIZE, &scratch);
	SKTC_ASSERT_ERR(!error);
	assert(scratch != -1);
	assert(sktc_attr->metasize == -1 || sktc_attr->metasize == scratch);

	scratch = -1;
	error = os_nexus_attr_get(attr, NEXUS_ATTR_MAX_FRAGS, &scratch);
	SKTC_ASSERT_ERR(!error);
	assert(scratch != -1);
	assert(sktc_attr->maxfrags == -1 || sktc_attr->maxfrags == scratch);

	scratch = -1;
	error = os_nexus_attr_get(attr, NEXUS_ATTR_REJECT_ON_CLOSE, &scratch);
	SKTC_ASSERT_ERR(!error);
	assert(scratch != -1);
	assert(sktc_attr->rejectonclose == -1 ||
	    sktc_attr->rejectonclose == scratch);

	os_nexus_attr_destroy(attr);

	if (instancep) {
		uuid_clear(*instancep);
		error = os_nexus_controller_alloc_provider_instance(ncd,
		    *providerp, instancep);
		SKTC_ASSERT_ERR(!error);
		assert(!uuid_is_null(*instancep));
	}
}

/* up to 4 seconds of retries (250ms delay per retry) */
#define SKTU_CHANNEL_CREATE_NOMEM_RETRIES       16

channel_t
sktu_channel_create_extended(const uuid_t uuid,
    const nexus_port_t port, const ring_dir_t dir,
    const ring_id_t rid, const channel_attr_t attr,
    uint64_t exclusive, uint64_t monitor,
    uint64_t txlowatunit, uint64_t txlowatval,
    uint64_t rxlowatunit, uint64_t rxlowatval,
    uint64_t userpacketpool, uint64_t defunctok,
    uint64_t event_ring, uint64_t low_latency)
{
	channel_attr_t tmpattr;
	int error;
	uint64_t scratch;
	static struct timespec delay250ms = { .tv_sec = 0, .tv_nsec = 250000000 };
	uint32_t retries = 0;
	channel_t ret = NULL;

	if (!attr) {
		tmpattr = os_channel_attr_create();
	} else {
		tmpattr = attr;
	}

	if (exclusive != -1) {
		error = os_channel_attr_set(tmpattr, CHANNEL_ATTR_EXCLUSIVE, exclusive);
		SKTC_ASSERT_ERR(!error);
	}

	if (monitor != -1) {
		error = os_channel_attr_set(tmpattr, CHANNEL_ATTR_MONITOR, monitor);
		SKTC_ASSERT_ERR(!error);
	}

	if (txlowatunit != -1) {
		error = os_channel_attr_set(tmpattr, CHANNEL_ATTR_TX_LOWAT_UNIT, txlowatunit);
		SKTC_ASSERT_ERR(!error);
	}

	if (txlowatval != -1) {
		error = os_channel_attr_set(tmpattr, CHANNEL_ATTR_TX_LOWAT_VALUE, txlowatval);
		SKTC_ASSERT_ERR(!error);
	}

	if (rxlowatunit != -1) {
		error = os_channel_attr_set(tmpattr, CHANNEL_ATTR_RX_LOWAT_UNIT, rxlowatunit);
		SKTC_ASSERT_ERR(!error);
	}

	if (rxlowatval != -1) {
		error = os_channel_attr_set(tmpattr, CHANNEL_ATTR_RX_LOWAT_VALUE, rxlowatval);
		SKTC_ASSERT_ERR(!error);
	}

	if (userpacketpool != -1) {
		error = os_channel_attr_set(tmpattr, CHANNEL_ATTR_USER_PACKET_POOL, userpacketpool);
		SKTC_ASSERT_ERR(!error);
	}

	if (defunctok != -1) {
		error = os_channel_attr_set(tmpattr, CHANNEL_ATTR_NEXUS_DEFUNCT_OK, defunctok);
		SKTC_ASSERT_ERR(!error);
	}

	if (event_ring != -1) {
		error = os_channel_attr_set(tmpattr, CHANNEL_ATTR_EVENT_RING, event_ring);
		SKTC_ASSERT_ERR(!error);
	}

	if (low_latency != -1) {
		error = os_channel_attr_set(tmpattr, CHANNEL_ATTR_LOW_LATENCY, low_latency);
		SKTC_ASSERT_ERR(!error);
	}

retry:
	ret = os_channel_create_extended(uuid, port, dir, rid, tmpattr);
	if (ret == NULL) {
		if (errno == ENOMEM && ++retries < SKTU_CHANNEL_CREATE_NOMEM_RETRIES) {
			nanosleep(&delay250ms, NULL);
			goto retry;
		}
		goto out;
	}

	scratch = -1;
	error = os_channel_attr_get(tmpattr, CHANNEL_ATTR_EXCLUSIVE, &scratch);
	SKTC_ASSERT_ERR(!error);
	assert(scratch != 1);
	assert(exclusive == -1 || exclusive == scratch);

	scratch = -1;
	error = os_channel_attr_get(tmpattr, CHANNEL_ATTR_MONITOR, &scratch);
	SKTC_ASSERT_ERR(!error);
	assert(scratch != -1);
	assert(exclusive == -1 || monitor == scratch);

	scratch = -1;
	error = os_channel_attr_get(tmpattr, CHANNEL_ATTR_TX_LOWAT_UNIT, &scratch);
	SKTC_ASSERT_ERR(!error);
	assert(scratch != -1);
	assert(exclusive == -1 || txlowatunit == scratch);

	scratch = -1;
	error = os_channel_attr_get(tmpattr, CHANNEL_ATTR_TX_LOWAT_VALUE, &scratch);
	SKTC_ASSERT_ERR(!error);
	assert(scratch != -1);
	assert(exclusive == -1 || txlowatval == scratch);

	scratch = -1;
	error = os_channel_attr_get(tmpattr, CHANNEL_ATTR_RX_LOWAT_UNIT, &scratch);
	SKTC_ASSERT_ERR(!error);
	assert(scratch != -1);
	assert(exclusive == -1 || rxlowatunit == scratch);

	scratch = -1;
	error = os_channel_attr_get(tmpattr, CHANNEL_ATTR_RX_LOWAT_VALUE, &scratch);
	SKTC_ASSERT_ERR(!error);
	assert(scratch != -1);
	assert(exclusive == -1 || rxlowatval == scratch);

	scratch = -1;
	error = os_channel_attr_get(tmpattr, CHANNEL_ATTR_USER_PACKET_POOL, &scratch);
	SKTC_ASSERT_ERR(!error);
	assert(scratch != -1);
	assert(exclusive == -1 || userpacketpool == scratch);

	scratch = -1;
	error = os_channel_attr_get(tmpattr, CHANNEL_ATTR_NEXUS_DEFUNCT_OK, &scratch);
	SKTC_ASSERT_ERR(!error);
	assert(scratch != -1);
	assert(exclusive == -1 || defunctok == scratch);

	scratch = -1;
	error = os_channel_attr_get(tmpattr, CHANNEL_ATTR_EVENT_RING, &scratch);
	SKTC_ASSERT_ERR(!error);
	assert(scratch != -1);
	assert(exclusive == -1 || event_ring == scratch);

	scratch = -1;
	error = os_channel_attr_get(tmpattr, CHANNEL_ATTR_LOW_LATENCY, &scratch);
	SKTC_ASSERT_ERR(!error);
	assert(scratch != -1);
	assert(exclusive == -1 || low_latency == scratch);

out:
	if (!attr) {
		os_channel_attr_destroy(tmpattr);
	}

	return ret;
}

/****************************************************************/

static inline void
swap(int *permute, int i, int j)
{
	int tmp = permute[i];
	permute[i] = permute[j];
	permute[j] = tmp;
}


/* Plain changes, see Knuth (7.2.1.2) "Algorithm P"
 * has advantage of only swapping adjacent pairs
 * This could be cleaned up to be more "C" like, but
 * this literal translation works without fanfare.
 */
void
permutefuncP(int n, int *permute, void (*func)(int, int *permute))
{
	int j, s, q;
	int c[n], o[n];
	/* P1 Initialize. */
	for (j = 0; j < n; j++) {
		c[j] = 0;
		o[j] = 1;
	}
p2:
	/* P2 Visit. */
	func(n, permute);
	/* P3 Prepare for change. */
	j = n;
	s = 0;
p4:
	/* P4 Ready to change? */
	q = c[j - 1] + o[j - 1];
	if (q < 0) {
		goto p7;
	}
	if (q == j) {
		goto p6;
	}
	/* P5 Change. */
	{
		//T_LOG("Swapping %d with %d\n", j-c[j-1]+s-1, j-q+s-1);
		swap(permute, j - c[j - 1] + s - 1, j - q + s - 1);
	}
	c[j - 1] = q;
	goto p2;
p6:     /* P6 Increase s */
	if (j == 1) {
		return;
	}
	s++;
p7:     /* P7 Switch Direction */
	o[j - 1] = -o[j - 1];
	j--;
	goto p4;
}

/* Heap's algorithm */
void
permutefuncH(int n, int *permute, void (*func)(int, int *permute))
{
	time_t start = time(NULL);
	time_t now, then = start;
	int count = 0;
	int total = 1;
	int i = 0;
	int c[n];
	memset(c, 0, sizeof(c));
	for (int f = 2; f <= n; f++) {
		total *= f;
	}
	count++;
	func(n, permute);
	while (i < n) {
		if (c[i] < i) {
			if (!(i & 1)) { /* Even */
				swap(permute, i, 0);
			} else { /* Odd */
				swap(permute, i, c[i]);
			}
			count++;
			{
				now = time(NULL);
				if (now > then) {
					T_LOG("time %ld on %d of %d (%2.2f%%, est %ld secs left)\n",
					    now - start, count, total,
					    (double)count * 100 / total,
					    (long)((double)(now - start) * total / count) - (now - start));
					then = now;
				}
			}
			func(n, permute);
			c[i] += 1;
			i = 0;
		} else {
			c[i] = 0;
			i++;
		}
	}
	now = time(NULL);
	T_LOG("total time %ld for %d permutations (rate %.2f)\n",
	    now - start, total, (double)total / (now - start));
}

/* Random permutations, knuth's shuffle */

void
permutefuncR(int n, int *permute, void (*func)(int, int *permute), int total, unsigned seed)
{
	time_t start = time(NULL);
	time_t now, then = start;
	int count = 0;
	T_LOG("Starting %d random permutations with seed %u\n", total, seed);
	srandom(seed);
	while (count < total) {
		for (int i = n - 1; i > 0; i--) {
			int j = random() % i; // XXX modulo bias.
			swap(permute, i, j);
		}
		count++;
		{
			now = time(NULL);
			if (now > then) {
				T_LOG("time %ld on %d of %d (%2.2f%%, est %ld secs left)\n",
				    now - start, count, total,
				    (double)count * 100 / total,
				    (long)((double)(now - start) * total / count) - (now - start));
				then = now;
			}
		}
		func(n, permute);
	}
	now = time(NULL);
	T_LOG("total time %ld for %d permutations (rate %.2f)\n",
	    now - start, total, (double)total / (now - start));
}


/*
 * rakes each element across all other elements.
 */
void
permutefuncZ(int n, int *permute, void (*func)(int, int *permute))
{
	int save[n];
	memcpy(save, permute, sizeof(save));
	func(n, permute);
	for (int i = 0; i < n; i++) {
		//T_LOG("raking %d left\n", i);
		memcpy(permute, save, sizeof(save));
		for (int j = i; j > 0; j--) {
			swap(permute, j, j - 1);
			func(n, permute);
		}
		//T_LOG("raking %d right\n", i);
		memcpy(permute, save, sizeof(save));
		for (int j = i; j < n - 1; j++) {
			swap(permute, j, j + 1);
			/* The first right is the same as the last left, so skip it */
			if (j != i) {
				func(n, permute);
			}
		}
	}
}

/****************************************************************/

void
sktc_create_flowswitch_no_address(struct sktc_nexus_handles *handles,
    uint64_t ntxslots, uint64_t nrxslots, uint64_t buf_size, uint64_t max_frags,
    uint64_t anonymous)
{
	char buf[256];
	int error;
	struct sktc_nexus_attr attr = SKTC_NEXUS_ATTR_INIT();

	attr.ntxslots = ntxslots;
	attr.nrxslots = nrxslots;
	attr.slotsize = buf_size;
	attr.anonymous = anonymous;
	attr.maxfrags = max_frags;

	if (handles->netif_ifname[0] == '\0') {
		T_LOG("%s: no interface name specified\n",
		    __func__);
		return;
	}
	if (strlen(handles->netif_ifname) >= IFNAMSIZ) {
		T_LOG("%s: invalid interface name specified %s\n",
		    __func__, handles->netif_ifname);
		return;
	}
	handles->controller = os_nexus_controller_create();
	if (handles->controller == NULL) {
		SKT_LOG(
			"%s: os_nexus_controller_create failed, %s (%d)\n",
			__func__, strerror(errno), errno);
		return;
	}

	snprintf(buf, sizeof(buf), "ms_fsw_%s", handles->netif_ifname);
	strncpy((char *)attr.name, buf, sizeof(nexus_name_t) - 1);
	attr.type = NEXUS_TYPE_FLOW_SWITCH;
	sktc_build_nexus(handles->controller, &attr, &handles->fsw_prov_uuid,
	    &handles->fsw_nx_uuid);

	/* if the netif is already present, don't bother creating/attaching */
	if (!sktc_get_netif_nexus(handles->netif_ifname,
	    handles->netif_nx_uuid)) {
		snprintf(buf, sizeof(buf), "netif_%s", handles->netif_ifname);
		strncpy((char *)attr.name, buf, sizeof(nexus_name_t) - 1);
		attr.type = NEXUS_TYPE_NET_IF;
		attr.ntxslots = -1;
		attr.nrxslots = -1;
		sktc_build_nexus(handles->controller, &attr,
		    &handles->netif_prov_uuid, &handles->netif_nx_uuid);
		error = __os_nexus_ifattach(handles->controller,
		    handles->netif_nx_uuid,
		    handles->netif_ifname, NULL,
		    false,
		    &handles->netif_nx_attach_uuid);
		if (error != 0) {
			SKT_LOG(
				"__os_nexus_ifattach(%s) failed, %s (%d)\n",
				buf, strerror(errno), errno);
			return;
		}
	}
	error = __os_nexus_ifattach(handles->controller, handles->fsw_nx_uuid,
	    NULL, handles->netif_nx_uuid, false, &handles->fsw_nx_dev_attach_uuid);
	if (error != 0) {
		SKT_LOG("__os_nexus_ifattach() failed, %s (%d)\n",
		    strerror(errno), errno);
		return;
	}
}


void
sktc_nexus_handles_assign_address(struct sktc_nexus_handles *handles)
{
	int             error;

	error = sktc_ifnet_add_addr(handles->netif_ifname,
	    &handles->netif_addr,
	    &handles->netif_mask, NULL);
	SKTC_ASSERT_ERR(!error);
}

void
sktc_create_flowswitch(struct sktc_nexus_handles *handles, int i)
{
	uint16_t        val;

	/* assign the name */
	snprintf(handles->netif_ifname, sizeof(handles->netif_ifname),
	    FETH_FORMAT, i);

	/* pick/assign a random IPv4LL address */
	val = random() % 0xffff;
	/* avoid subnet broadcast and host address 0 */
	if (((val & 0xff) == 0) || ((val & 0xff) == 0xff)) {
		val = (val & 0xfff0) | 0x2;
	}
	handles->netif_addr = sktc_make_in_addr(IN_LINKLOCALNETNUM | val);
	handles->netif_mask = sktc_make_in_addr(IN_CLASSC_NET);
	sktc_nexus_handles_assign_address(handles);

	/* create the flowswitch */
	sktc_create_flowswitch_no_address(handles, -1, -1, -1, -1, 1);
}

void
sktc_cleanup_flowswitch(struct sktc_nexus_handles *handles)
{
	int error;

	assert(handles->controller);
	assert(!uuid_is_null(handles->fsw_prov_uuid));
	assert(!uuid_is_null(handles->fsw_nx_uuid));

	error = os_nexus_controller_free_provider_instance(handles->controller,
	    handles->fsw_nx_uuid);
	SKTC_ASSERT_ERR(!error);

	error = os_nexus_controller_deregister_provider(handles->controller,
	    handles->fsw_prov_uuid);
	SKTC_ASSERT_ERR(!error);

	os_nexus_controller_destroy(handles->controller);

	error = sktc_ifnet_del_addr(handles->netif_ifname, &handles->netif_addr);
	SKTC_ASSERT_ERR(!error);
}

/****************************************************************/

int
sktc_bind_tcp4_flow(nexus_controller_t ncd, const uuid_t fsw, in_port_t in_port, nexus_port_t nx_port, const uuid_t flow)
{
	struct nx_flow_req nfr;
	int error;

	memset(&nfr, 0, sizeof(nfr));
	nfr.nfr_ip_protocol = IPPROTO_TCP;
	nfr.nfr_nx_port = nx_port;
	nfr.nfr_saddr.sa.sa_len = sizeof(struct sockaddr_in);
	nfr.nfr_saddr.sa.sa_family = AF_INET;
	nfr.nfr_saddr.sin.sin_port = htons(in_port);
	nfr.nfr_saddr.sin.sin_addr.s_addr = htonl(INADDR_ANY);
	uuid_copy(nfr.nfr_flow_uuid, flow);

#if 0
	char buf[31];
	uuid_string_t uuidstr;
	uuid_unparse(nfr.nfr_flow_uuid, uuidstr);
	inet_ntop(AF_INET, &nfr.nfr_saddr.sin.sin_addr.s_addr, buf, sizeof(buf));
	T_LOG("before: nx_port %3d Flow %s %s addr %s port %d\n",
	    nfr.nfr_nx_port, uuidstr, (nfr.nfr_ip_protocol == IPPROTO_TCP) ? "tcp" : "udp",
	    buf, ntohs(nfr.nfr_saddr.sin.sin_port));
#endif

	error = __os_nexus_flow_add(ncd, fsw, &nfr);
#if 0
	if (error) {
		T_LOG("__os_nexus_flow_add returned %d, errno %d\n", error, errno);
	}
#endif

#if 0
	uuid_unparse(nfr.nfr_flow_uuid, uuidstr);
	inet_ntop(AF_INET, &nfr.nfr_saddr.sin.sin_addr.s_addr, buf, sizeof(buf));
	T_LOG("after:  nx_port %3d Flow %s %s addr %s port %d\n",
	    nfr.nfr_nx_port, uuidstr, (nfr.nfr_ip_protocol == IPPROTO_TCP) ? "tcp" : "udp",
	    buf, ntohs(nfr.nfr_saddr.sin.sin_port));
#endif

	// XXX fails, see the fswbind25 for standalone test for this
	assert(nfr.nfr_nx_port == nx_port);
	T_LOG("got ephemeral port %d\n", ntohs(nfr.nfr_saddr.sin.sin_port));

	/* Validate the ephemeral ports */
	if (!error && !in_port) {
		static int first, last;
		if (!first && !last) {
			size_t size;

			size = sizeof(first);
			error = sysctlbyname("net.inet.ip.portrange.first", &first, &size, NULL, 0);
			SKTC_ASSERT_ERR(!error);
			assert(size == sizeof(first));

			size = sizeof(last);
			error = sysctlbyname("net.inet.ip.portrange.last", &last, &size, NULL, 0);
			SKTC_ASSERT_ERR(!error);
			assert(size == sizeof(last));

			T_LOG("ephemeral port range first %d last %d\n", first, last);

			if (last < first) {
				int tmp = first;
				first = last;
				last = tmp;
			}
			assert(first <= last);
		}
		assert(ntohs(nfr.nfr_saddr.sin.sin_port) >= first);
		assert(ntohs(nfr.nfr_saddr.sin.sin_port) <= last);
	}

	return error;
}

int
sktc_unbind_flow(nexus_controller_t ncd, const uuid_t fsw, const uuid_t flow)
{
	struct nx_flow_req nfr;
	int error;

	memset(&nfr, 0, sizeof(nfr));
	uuid_copy(nfr.nfr_flow_uuid, flow);

	error = __os_nexus_flow_del(ncd, fsw, &nfr);
	if (error) {
		SKT_LOG("__os_nexus_flow_add returned %d, errno %d\n", error, errno);
	}
	return error;
}

/****************************************************************/

uint32_t
sktc_chew_random(channel_t channel, channel_ring_t ring, sync_mode_t mode, bool dosync, uint32_t nslots)
{
	uint64_t count = 0;
	int error;
	channel_slot_t slot;

	/* Chew a random number of slots */
	nslots = random() % (nslots + 1);

	slot = NULL;
	while (count < nslots) {
		slot_prop_t prop;

		slot = os_channel_get_next_slot(ring, slot, &prop);
		assert(slot);
		if (mode == CHANNEL_SYNC_TX) {
			packet_t pkt = os_channel_slot_get_packet(ring, slot);
			buflet_t buf = os_packet_get_next_buflet(pkt, NULL);
			assert(buf != NULL);
			uint16_t bdlim = os_buflet_get_data_limit(buf);
			assert(bdlim != 0);
			prop.sp_len = random() % bdlim;
			os_channel_set_slot_properties(ring, slot, &prop);
		}
		count++;
	}

	if (slot) {
		error = os_channel_advance_slot(ring, slot);
		SKTC_ASSERT_ERR(!error);
	}

	if (dosync) {
		error = os_channel_sync(channel, mode);
		if (skywalk_in_driver && error) {
			SKT_LOG("%s: sync fail error %d errno %d: %s\n", __func__, error, errno, strerror(errno));
		} else {
			SKTC_ASSERT_ERR(!error);
		}
	}

	return count;
}

/* This pumps slots on a ring until count slots have been tranferred */
void
sktc_pump_ring_nslots_kq(channel_t channel, channel_ring_t ring, sync_mode_t mode, bool dosync, uint64_t nslots, bool verbose)
{
	uint64_t count = 0;
	int channelfd;
	int kq;
	struct kevent kev;
	int error;
	time_t start, then;

	channelfd = os_channel_get_fd(channel);
	assert(channelfd != -1);

	kq = kqueue();
	assert(kq != -1);
	EV_SET(&kev, channelfd,
	    mode == CHANNEL_SYNC_TX ? EVFILT_WRITE : EVFILT_READ,
	    EV_ADD | EV_ENABLE, 0, 0, NULL);
	error = kevent(kq, &kev, 1, NULL, 0, NULL);
	SKTC_ASSERT_ERR(!error);

	if (verbose) {
		then = start = time(NULL);
	}

	while (count < nslots) {
		uint32_t avail;

		if (verbose) {
			time_t now = time(NULL);
			if (now > then) {
				T_LOG("time %ld pump %"PRId64" of %"PRId64" (%2.2f%%, est %ld secs left)\n",
				    now - start, count, nslots,
				    (double)count * 100 / nslots,
				    (long)((double)(now - start) * nslots / count) - (now - start));
				then = now;
			}
		}

		avail = os_channel_available_slot_count(ring);

		if (!avail) {
			int error;

			memset(&kev, 0, sizeof(kev));
			error = kevent(kq, NULL, 0, &kev, 1, NULL);
			SKTC_ASSERT_ERR(error != -1);
			SKTC_ASSERT_ERR(error == 1);

			assert(kev.ident == channelfd);
			if (mode == CHANNEL_SYNC_TX) {
				assert(kev.filter == EVFILT_WRITE);
			} else {
				assert(kev.filter == EVFILT_READ);
			}

			avail = os_channel_available_slot_count(ring);
			assert(avail);
		}

		count += sktc_chew_random(channel, ring, mode, dosync, MIN(nslots - count, avail));
	}

	if (verbose) {
		time_t now = time(NULL);
		T_LOG("total time %ld for %"PRId64" slots (rate %.2f)\n",
		    now - start, nslots, (double)nslots / (now - start));
	}

	error = close(kq);
	SKTC_ASSERT_ERR(!error);
}

void
sktc_pump_ring_nslots_select(channel_t channel, channel_ring_t ring, sync_mode_t mode, bool dosync, uint64_t nslots, bool verbose)
{
	uint64_t count = 0;
	int channelfd;
	fd_set readfds, writefds, errorfds, zerofds;
	time_t start, then;

	channelfd = os_channel_get_fd(channel);
	assert(channelfd != -1);

	FD_ZERO(&zerofds);
	FD_ZERO(&readfds);
	FD_ZERO(&writefds);
	FD_ZERO(&errorfds);
	if (mode == CHANNEL_SYNC_TX) {
		FD_SET(channelfd, &writefds);
	} else {
		FD_SET(channelfd, &readfds);
	}

	if (verbose) {
		then = start = time(NULL);
	}

	while (count < nslots) {
		uint32_t avail;

		if (verbose) {
			time_t now = time(NULL);
			if (now > then) {
				T_LOG("time %ld pump %"PRId64" of %"PRId64" (%2.2f%%, est %ld secs left)\n",
				    now - start, count, nslots,
				    (double)count * 100 / nslots,
				    (long)((double)(now - start) * nslots / count) - (now - start));
				then = now;
			}
		}

		avail = os_channel_available_slot_count(ring);

		if (!avail) {
			int error;

			FD_SET(channelfd, &errorfds);
			error = select(channelfd + 1, &readfds, &writefds, &errorfds, NULL);
			SKTC_ASSERT_ERR(error != -1);
			assert(!memcmp(&zerofds, &errorfds, sizeof(zerofds)));
			if (mode == CHANNEL_SYNC_TX) {
				assert(FD_ISSET(channelfd, &writefds));
				assert(!memcmp(&zerofds, &readfds, sizeof(zerofds)));
			} else {
				assert(FD_ISSET(channelfd, &readfds));
				assert(!memcmp(&zerofds, &writefds, sizeof(zerofds)));
			}
			SKTC_ASSERT_ERR(error == 1);

			avail = os_channel_available_slot_count(ring);
			assert(avail);
		}

		count += sktc_chew_random(channel, ring, mode, dosync, MIN(nslots - count, avail));
	}

	if (verbose) {
		time_t now = time(NULL);
		T_LOG("total time %ld for %"PRId64" slots (rate %.2f)\n",
		    now - start, nslots, (double)nslots / (now - start));
	}
}

void
sktc_pump_ring_nslots_poll(channel_t channel, channel_ring_t ring, sync_mode_t mode, bool dosync, uint64_t nslots, bool verbose)
{
	uint64_t count = 0;
	int channelfd;
	struct pollfd fds;
	time_t start, then;

	channelfd = os_channel_get_fd(channel);
	assert(channelfd != -1);

	fds.fd = channelfd;
	if (mode == CHANNEL_SYNC_TX) {
		fds.events = POLLWRNORM;
	} else {
		fds.events = POLLRDNORM;
	}

	if (verbose) {
		then = start = time(NULL);
	}

	while (count < nslots) {
		uint32_t avail;

		if (verbose) {
			time_t now = time(NULL);
			if (now > then) {
				T_LOG("time %ld pump %"PRId64" of %"PRId64" (%2.2f%%, est %ld secs left)\n",
				    now - start, count, nslots,
				    (double)count * 100 / nslots,
				    (long)((double)(now - start) * nslots / count) - (now - start));
				then = now;
			}
		}

		avail = os_channel_available_slot_count(ring);

		if (!avail) {
			int error;

			error = poll(&fds, 1, -1);
			SKTC_ASSERT_ERR(error != -1);
			SKTC_ASSERT_ERR(error == 1);
			assert(fds.fd == channelfd);
			if (mode == CHANNEL_SYNC_TX) {
				assert(fds.events == POLLWRNORM);
				assert(fds.revents == POLLWRNORM);
			} else {
				assert(fds.events == POLLRDNORM);
				assert(fds.revents == POLLRDNORM);
			}

			avail = os_channel_available_slot_count(ring);
			assert(avail);
		}

		count += sktc_chew_random(channel, ring, mode, dosync, MIN(nslots - count, avail));
	}

	if (verbose) {
		time_t now = time(NULL);
		T_LOG("total time %ld for %"PRId64" slots (rate %.2f)\n",
		    now - start, nslots, (double)nslots / (now - start));
	}
}

/****************************************************************/

void
sktc_raise_file_limit(int new)
{
	int error;
	struct rlimit rl;

	error = getrlimit(RLIMIT_NOFILE, &rl);
	SKTC_ASSERT_ERR(!error);

	if (rl.rlim_cur < new) {
		T_LOG("raising file open limit from %llu (max %llu) to %d\n",
		    rl.rlim_cur, rl.rlim_max, new);
		rl.rlim_cur = new;
		rl.rlim_max = new;
		error = setrlimit(RLIMIT_NOFILE, &rl);
		SKTC_ASSERT_ERR(!error);
	}
}


/****************************************************************/

int
sktu_create_interface(sktu_if_type_t type, sktu_if_flag_t flags)
{
	struct ctl_info kernctl_info;
	struct sockaddr_ctl kernctl_addr;
	int error;
	int tunsock;
	const char *CONTROL_NAME;
	int OPT_ENABLE_NETIF, OPT_ATTACH_FSW;
	int enable_netif, attach_fsw;
	int scratch;

	assert(type == SKTU_IFT_UTUN || type == SKTU_IFT_IPSEC);
	if (type == SKTU_IFT_UTUN) {
		CONTROL_NAME = UTUN_CONTROL_NAME;
		OPT_ENABLE_NETIF = UTUN_OPT_ENABLE_NETIF;
		OPT_ATTACH_FSW = UTUN_OPT_ATTACH_FLOWSWITCH;
	} else {
		CONTROL_NAME = IPSEC_CONTROL_NAME;
		OPT_ENABLE_NETIF = IPSEC_OPT_ENABLE_NETIF;
		OPT_ATTACH_FSW = 0;
	}

	enable_netif = ((flags & SKTU_IFF_ENABLE_NETIF) != 0) ? 1 : 0;
	attach_fsw = ((flags & SKTU_IFF_NO_ATTACH_FSW) != 0) ? 0 : 1;

	/* XXX Remove this retry nonsense when this is fixed:
	 * <rdar://problem/37340313> creating an interface without specifying specific interface name should not return EBUSY
	 */

	for (int i = 0; i < 10; i++) {
		if (i > 0) {
			T_LOG("%s: sleeping 1ms before retrying\n", __func__);
			usleep(1000);
		}

		tunsock = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
		assert(tunsock != -1);

		memset(&kernctl_info, 0, sizeof(kernctl_info));
		strlcpy(kernctl_info.ctl_name, CONTROL_NAME, sizeof(kernctl_info.ctl_name));
		error = ioctl(tunsock, CTLIOCGINFO, &kernctl_info);
		SKTC_ASSERT_ERR(error == 0);

		memset(&kernctl_addr, 0, sizeof(kernctl_addr));
		kernctl_addr.sc_len = sizeof(kernctl_addr);
		kernctl_addr.sc_family = AF_SYSTEM;
		kernctl_addr.ss_sysaddr = AF_SYS_CONTROL;
		kernctl_addr.sc_id = kernctl_info.ctl_id;
		kernctl_addr.sc_unit = 0;

		/* If this is being called to reinstantiate a device that was just detached,
		 * then this may return busy while the asynchronous detach completes.
		 * This only occurs when this is being called in a tight loop
		 * as per the utun27646755 test below
		 */

		error = bind(tunsock, (struct sockaddr *)&kernctl_addr, sizeof(kernctl_addr));
		if (error == -1 && errno == EBUSY) {
			close(tunsock);
			tunsock = -1;
			T_LOG("%s: i = %d bind returned EBUSY\n", __func__, i);
			continue;
		}

		/* can only be set before connecting */
		error = setsockopt(tunsock, SYSPROTO_CONTROL, OPT_ENABLE_NETIF, &enable_netif, sizeof(enable_netif));
		SKTC_ASSERT_ERR(!error);
		socklen_t scratchlen = sizeof(scratch);
		error = getsockopt(tunsock, SYSPROTO_CONTROL, OPT_ENABLE_NETIF, &scratch, &scratchlen);
		SKTC_ASSERT_ERR(!error);
		assert(scratchlen == sizeof(scratch));
		assert(enable_netif == scratch);

		/* only applicable for utun */
		if (type == SKTU_IFT_UTUN) {
			error = setsockopt(tunsock, SYSPROTO_CONTROL, OPT_ATTACH_FSW, &attach_fsw, sizeof(attach_fsw));
			SKTC_ASSERT_ERR(!error);
		}

		error = connect(tunsock, (struct sockaddr *)&kernctl_addr, sizeof(kernctl_addr));
		if (error == -1 && errno == EBUSY) {
			T_LOG("%s: i = %d connect returned EBUSY\n", __func__, i);
			close(tunsock);
			tunsock = -1;
			continue;
		}

		error = fcntl(tunsock, F_SETFD, FD_CLOEXEC);
		if (error != 0) {
			warn("FD_CLOEXEC");
		}

		break;
	}

	if (error == -1) {
		warn("Failed to create utun errno %d", errno);
		close(tunsock);
		tunsock = -1;
	}

	return tunsock;
}

channel_t
sktu_create_interface_channel(sktu_if_type_t type, int tunsock)
{
	uuid_t uuid;
	channel_attr_t attr;
	channel_t channel;
	socklen_t uuidlen;
	int error;
	int OPT_ENABLE_CHANNEL;
	int OPT_GET_CHANNEL_UUID;

	if (type == SKTU_IFT_UTUN) {
		OPT_ENABLE_CHANNEL = UTUN_OPT_ENABLE_CHANNEL;
		OPT_GET_CHANNEL_UUID = UTUN_OPT_GET_CHANNEL_UUID;
	} else {
		assert(type == SKTU_IFT_IPSEC);
		OPT_ENABLE_CHANNEL = IPSEC_OPT_ENABLE_CHANNEL;
		OPT_GET_CHANNEL_UUID = IPSEC_OPT_GET_CHANNEL_UUID;
	}

	if (type == SKTU_IFT_UTUN) {
		int enable = 1;
		error = setsockopt(tunsock, SYSPROTO_CONTROL, OPT_ENABLE_CHANNEL, &enable, sizeof(enable));
		if (error != 0) {
			SKT_LOG("setsockopt returned error %d, errno %d\n", error, errno);
		}
		SKTC_ASSERT_ERR(error == 0);
	}

	int scratch;
	socklen_t scratchlen = sizeof(scratch);
	error = getsockopt(tunsock, SYSPROTO_CONTROL, OPT_ENABLE_CHANNEL, &scratch, &scratchlen);
	SKTC_ASSERT_ERR(!error);
	assert(scratchlen == sizeof(scratch));
	assert(1 == scratch);

	uuidlen = sizeof(uuid);
	error = getsockopt(tunsock, SYSPROTO_CONTROL, OPT_GET_CHANNEL_UUID, uuid, &uuidlen);
	SKTC_ASSERT_ERR(error == 0);
	assert(uuidlen == sizeof(uuid));

	attr = NULL;
	channel = sktu_channel_create_extended(uuid,
	    NEXUS_PORT_KERNEL_PIPE_CLIENT,
	    CHANNEL_DIR_TX_RX, CHANNEL_RING_ID_ANY, attr,
	    -1, -1, -1, -1, -1, -1, -1, 1, -1, -1);
	assert(channel);

	return channel;
}

void
sktu_get_interface_name(sktu_if_type_t type, int s, char name[IFNAMSIZ])
{
	int error;
	socklen_t  optlen = IFNAMSIZ;
	if (type == SKTU_IFT_UTUN) {
		error = getsockopt(s, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, name, &optlen);
	} else {
		error = getsockopt(s, SYSPROTO_CONTROL, IPSEC_OPT_IFNAME, name, &optlen);
	}
	SKTC_ASSERT_ERR(!error);
}

void
sktu_dump_buffer(FILE *f, const char *desc, const void *buf, size_t len)
{
	int i;
	unsigned char buff[17];
	unsigned char *pc = (unsigned char*)buf;

	if (desc != NULL) {
		fprintf(f, "%s:\n", desc);
	}

	if (len == 0) {
		fprintf(f, "  ZERO LENGTH\n");
		return;
	}

	for (i = 0; i < len; i++) {
		if ((i % 16) == 0) {
			if (i != 0) {
				fprintf(f, "  %s\n", buff);
			}

			fprintf(f, "  %04x ", i); // offset
		}

		fprintf(f, " %02x", pc[i]);

		// prepare ascii
		if ((pc[i] < 0x20) || (pc[i] > 0x7e)) {
			buff[i % 16] = '.';
		} else {
			buff[i % 16] = pc[i];
		}
		buff[(i % 16) + 1] = '\0';
	}

	// pad last line to for ascii
	while ((i % 16) != 0) {
		fprintf(f, "   ");
		i++;
	}

	fprintf(f, "  %s\n", buff);
}

int
sysctl_buf(char *oid_name, void **buffer, size_t *len, void *newp,
    size_t newlen)
{
	int ret, err;
	int try = 0;

	*buffer = NULL;
#define RETRY_COUNT 10
try_again:
	ret = sysctlbyname(oid_name, NULL, len, newp, newlen);
	if (ret != 0) {
		if (ret == ENOMEM) {
			try++;
			if (try <= RETRY_COUNT) {
				goto try_again;
			}
		}
		err = errno;
		SKT_LOG("sysctl for len failed, %s\n", strerror(errno));
		return err;
	}
	if (*len == 0) {
		T_LOG("sysctl for len returned zero! No stats?\n");
		*buffer = NULL;
		return 0;
	}
	*buffer = malloc(*len);
	if (*buffer == NULL) {
		T_LOG("sysctl malloc for %ld bytes failed\n", *len);
		return ENOMEM;
	}

	ret = sysctlbyname(oid_name, *buffer, len, newp, newlen);
	if (ret != 0) {
		err = errno;
		if (ret == ENOMEM) {
			free(*buffer);
			*buffer = NULL;
			try++;
			if (try <= RETRY_COUNT) {
				goto try_again;
			}
		}
		SKT_LOG("sysctl for buf failed, %s\n", strerror(errno));
		free(*buffer);
		return err;
	}

	return 0;
}

uint32_t
sktu_set_inject_error_rmask(uint32_t *mask)
{
	uint32_t old_mask;
	size_t size = sizeof(old_mask);
	int error;

	error = sysctlbyname("kern.skywalk.inject_error_rmask",
	    &old_mask, &size, mask, mask ? sizeof(*mask) : 0);

	SKTC_ASSERT_ERR(!error);
	return old_mask;
}

/* returns TRUE if a matching IPv4 address is found */
boolean_t
sktu_check_interface_ipv4_address(char *ifname, uint32_t ipaddr)
{
	struct ifaddrs *ifaddr, *ifa;
	boolean_t match = FALSE;
	int error;

	error = getifaddrs(&ifaddr);
	SKTC_ASSERT_ERR(!error);

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		struct sockaddr_in *sin =
		    (struct sockaddr_in *)(void *)ifa->ifa_addr;
		if (ifa->ifa_addr == NULL) {
			continue;
		}
		if ((strncmp(ifa->ifa_name, ifname, IFNAMSIZ) == 0) &&
		    (ifa->ifa_addr->sa_family == AF_INET) &&
		    (sin->sin_addr.s_addr == ipaddr)) {
			match = TRUE;
		}
	}
	freeifaddrs(ifaddr);
	return match;
}

/****************************************************************/

int
sktu_create_pfkeysock(void)
{
	int keysock = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
	assert(keysock != -1);
	return keysock;
}

void
sktu_create_sa(int keysock, const char ifname[IFXNAMSIZ], uint32_t spi, struct in_addr *src, struct in_addr *dst)
{
	/*
	 *       <base, SA, (lifetime(HS),) address(SD), (address(P),)
	 *       key(AE), (identity(SD),) (sensitivity)>
	 */

	struct {
		struct sadb_msg msg __attribute((aligned(sizeof(uint64_t))));
		struct sadb_key key      __attribute((aligned(sizeof(uint64_t))));
		struct sadb_sa sa        __attribute((aligned(sizeof(uint64_t))));
		struct sadb_x_sa2 sa2    __attribute((aligned(sizeof(uint64_t))));
		struct sadb_x_ipsecif ipsecif __attribute((aligned(sizeof(uint64_t))));
		struct {
			struct sadb_address addr __attribute((aligned(sizeof(uint64_t))));
			struct sockaddr_in saddr __attribute((aligned(sizeof(uint64_t))));
		} src;
		struct {
			struct sadb_address addr __attribute((aligned(sizeof(uint64_t))));
			struct sockaddr_in saddr __attribute((aligned(sizeof(uint64_t))));
		} dst;
	} addcmd;

	memset(&addcmd, 0, sizeof(addcmd));

	addcmd.msg.sadb_msg_version = PF_KEY_V2;
	addcmd.msg.sadb_msg_type = SADB_ADD;
	addcmd.msg.sadb_msg_errno = 0;
	addcmd.msg.sadb_msg_satype = SADB_SATYPE_ESP;
	addcmd.msg.sadb_msg_len = PFKEY_UNIT64(sizeof(addcmd));
	addcmd.msg.sadb_msg_reserved = 0;
	addcmd.msg.sadb_msg_seq = 0;
	addcmd.msg.sadb_msg_pid = (unsigned)getpid();

	addcmd.key.sadb_key_len = PFKEY_UNIT64(sizeof(addcmd.key));
	addcmd.key.sadb_key_exttype = SADB_EXT_KEY_ENCRYPT;
	addcmd.key.sadb_key_bits = 0;
	addcmd.key.sadb_key_reserved = 0;

	addcmd.sa.sadb_sa_len = PFKEY_UNIT64(sizeof(addcmd.sa));
	addcmd.sa.sadb_sa_exttype = SADB_EXT_SA;
	addcmd.sa.sadb_sa_spi = htonl(spi);
	addcmd.sa.sadb_sa_replay = 0;
	addcmd.sa.sadb_sa_state = 0;
	addcmd.sa.sadb_sa_auth = SADB_AALG_NONE;
	addcmd.sa.sadb_sa_encrypt = SADB_EALG_NULL;
	addcmd.sa.sadb_sa_flags = 0;

	addcmd.sa2.sadb_x_sa2_len = PFKEY_UNIT64(sizeof(addcmd.sa2));
	addcmd.sa2.sadb_x_sa2_exttype = SADB_X_EXT_SA2;
	addcmd.sa2.sadb_x_sa2_mode = IPSEC_MODE_TRANSPORT;
	addcmd.sa2.sadb_x_sa2_alwaysexpire = 1;
	addcmd.sa2.sadb_x_sa2_flags = SADB_X_EXT_SA2_DELETE_ON_DETACH;
	addcmd.sa2.sadb_x_sa2_sequence = 0;
	addcmd.sa2.sadb_x_sa2_reqid = 0;

	addcmd.ipsecif.sadb_x_ipsecif_len = PFKEY_UNIT64(sizeof(addcmd.ipsecif));
	addcmd.ipsecif.sadb_x_ipsecif_exttype = SADB_X_EXT_IPSECIF;
	memset(addcmd.ipsecif.sadb_x_ipsecif_internal_if, 0, sizeof(addcmd.ipsecif.sadb_x_ipsecif_internal_if));
	memset(addcmd.ipsecif.sadb_x_ipsecif_outgoing_if, 0, sizeof(addcmd.ipsecif.sadb_x_ipsecif_outgoing_if));
	strlcpy(addcmd.ipsecif.sadb_x_ipsecif_ipsec_if, ifname, sizeof(addcmd.ipsecif.sadb_x_ipsecif_ipsec_if));
	addcmd.ipsecif.sadb_x_ipsecif_init_disabled = 0;
	addcmd.ipsecif.reserved = 0;

	addcmd.src.addr.sadb_address_len = PFKEY_UNIT64(sizeof(addcmd.src));
	addcmd.src.addr.sadb_address_exttype = SADB_EXT_ADDRESS_SRC;
	addcmd.src.addr.sadb_address_proto = IPSEC_ULPROTO_ANY;
	addcmd.src.addr.sadb_address_prefixlen = sizeof(struct in_addr) << 3; //XXX Why?
	addcmd.src.addr.sadb_address_reserved = 0;
	addcmd.src.saddr.sin_len = sizeof(addcmd.src.saddr);
	addcmd.src.saddr.sin_family = AF_INET;
	addcmd.src.saddr.sin_port = htons(0);
	addcmd.src.saddr.sin_addr = *src;

	addcmd.dst.addr.sadb_address_len = PFKEY_UNIT64(sizeof(addcmd.dst));
	addcmd.dst.addr.sadb_address_exttype = SADB_EXT_ADDRESS_DST;
	addcmd.dst.addr.sadb_address_proto = IPSEC_ULPROTO_ANY;
	addcmd.dst.addr.sadb_address_prefixlen = sizeof(struct in_addr) << 3; //XXX Why?
	addcmd.dst.addr.sadb_address_reserved = 0;
	addcmd.dst.saddr.sin_len = sizeof(addcmd.dst.saddr);
	addcmd.dst.saddr.sin_family = AF_INET;
	addcmd.dst.saddr.sin_port = htons(0);
	addcmd.dst.saddr.sin_addr = *dst;

	//log_hexdump(&addcmd, sizeof(addcmd));

	ssize_t slen;
	slen = send(keysock, &addcmd, sizeof(addcmd), 0);
	assert(slen == sizeof(addcmd));
}

typedef union {
	char        c[2];
	u_short     s;
} short_union_t;

typedef union {
	u_short     s[2];
	long        l;
} long_union_t;

static __inline__ void
reduce(int * sum)
{
	long_union_t l_util;

	l_util.l = *sum;
	*sum = l_util.s[0] + l_util.s[1];
	if (*sum > 65535) {
		*sum -= 65535;
	}
	return;
}

unsigned short
in_cksum(void * pkt, int len, int sum0)
{
	u_short * w;
	int sum = sum0;

	w = (u_short *)pkt;
	while ((len -= 32) >= 0) {
		sum += w[0]; sum += w[1];
		sum += w[2]; sum += w[3];
		sum += w[4]; sum += w[5];
		sum += w[6]; sum += w[7];
		sum += w[8]; sum += w[9];
		sum += w[10]; sum += w[11];
		sum += w[12]; sum += w[13];
		sum += w[14]; sum += w[15];
		w += 16;
	}
	len += 32;
	while ((len -= 8) >= 0) {
		sum += w[0]; sum += w[1];
		sum += w[2]; sum += w[3];
		w += 4;
	}
	len += 8;
	if (len) {
		reduce(&sum);
		while ((len -= 2) >= 0) {
			sum += *w++;
		}
	}
	if (len == -1) { /* odd-length packet */
		short_union_t s_util;

		s_util.s = 0;
		s_util.c[0] = *((char *)w);
		s_util.c[1] = 0;
		sum += s_util.s;
	}
	reduce(&sum);
	return ~sum & 0xffff;
}

#define ADDCARRY(_x)  do {                                              \
	while (((_x) >> 16) != 0)                                       \
	        (_x) = ((_x) >> 16) + ((_x) & 0xffff);                  \
} while (0)

/*
 * Checksum routine for Internet Protocol family headers (Portable Version).
 *
 * This routine is very heavily used in the network
 * code and should be modified for each CPU to be as fast as possible.
 */
#define REDUCE16 {                                                        \
	q_util.q = sum;                                                   \
	l_util.l = q_util.s[0] + q_util.s[1] + q_util.s[2] + q_util.s[3]; \
	sum = l_util.s[0] + l_util.s[1];                                  \
	ADDCARRY(sum);                                                    \
}

union l_util {
	uint16_t s[2];
	uint32_t l;
};

union q_util {
	uint16_t s[4];
	uint32_t l[2];
	uint64_t q;
};

uint16_t
in_pseudo(uint32_t a, uint32_t b, uint32_t c)
{
	uint64_t sum;
	union q_util q_util;
	union l_util l_util;

	sum = (uint64_t)a + b + c;
	REDUCE16;
	return sum;
}

uint16_t
in6_pseudo(const struct in6_addr *src, const struct in6_addr *dst, uint32_t x)
{
	uint32_t sum = 0;
	const uint16_t *w;

	/*
	 * IPv6 source address
	 */
	w = (const uint16_t *)src;
	sum += w[0]; sum += w[1];
	sum += w[2]; sum += w[3]; sum += w[4]; sum += w[5];
	sum += w[6]; sum += w[7];

	/*
	 * IPv6 destination address
	 */
	w = (const uint16_t *)dst;
	sum += w[0]; sum += w[1];
	sum += w[2]; sum += w[3]; sum += w[4]; sum += w[5];
	sum += w[6]; sum += w[7];

	/*
	 * Caller-supplied value; 'x' could be one of:
	 *
	 *	htonl(proto + length), or
	 *	htonl(proto + length + sum)
	 **/
	sum += x;

	/* fold in carry bits */
	ADDCARRY(sum);

	return sum;
}

uint16_t
sktu_ip_id()
{
	static int sktu_ip_id;
	return sktu_ip_id++;
}

void
sktu_channel_port_init(channel_port_t ch_port, uuid_t instance,
    nexus_port_t nx_port, bool enable_upp, bool enable_event_ring,
    bool low_latency)
{
	channel_t       chan;
	nexus_port_t    port = nx_port;
	ring_id_t       ringid;

	bzero(ch_port, sizeof(*ch_port));
	chan = sktu_channel_create_extended(instance, port,
	    CHANNEL_DIR_TX_RX, CHANNEL_RING_ID_ANY, NULL,
	    -1, -1, -1, -1, -1, -1, enable_upp ? 1 : -1, 1,
	    enable_event_ring ? 1 : -1, low_latency ? 1 : -1);
	if (chan == NULL) {
		SKT_LOG("Can't open channel on port %d, %s\n", port,
		    strerror(errno));
		return;
	}

	T_LOG("Opened port %d\n", port);

	ch_port->chan = chan;
	ch_port->fd = os_channel_get_fd(chan);
	ch_port->port = port;
	ch_port->user_packet_pool = enable_upp;

	/* tx ring */
	ringid = os_channel_ring_id(chan, CHANNEL_FIRST_TX_RING);
	ch_port->tx_ring = os_channel_tx_ring(ch_port->chan, ringid);
	assert(ch_port->tx_ring != NULL);
	/* rx ring */
	ringid = os_channel_ring_id(chan, CHANNEL_FIRST_RX_RING);
	ch_port->rx_ring = os_channel_rx_ring(ch_port->chan, ringid);
	assert(ch_port->rx_ring != NULL);
}

static inline uint16_t
sktu_fold_sum_final(uint32_t sum)
{
	sum = (sum >> 16) + (sum & 0xffff);     /* 17-bit */
	sum = (sum >> 16) + (sum & 0xffff);     /* 16-bit + carry */
	sum = (sum >> 16) + (sum & 0xffff);     /* final carry */
	return ~sum & 0xffff;
}

packet_t
sktu_channel_port_frame_to_pkt(channel_port_t port, struct sktu_frame *frame)
{
	int error;
	packet_t pkt;
	void *baddr, *bytes = &frame->bytes[0];
	size_t len = frame->len;
	buflet_t buf, pbuf = NULL;
	uint16_t clen, bdlim, blen, bcnt;

	assert(port->user_packet_pool);

	error = os_channel_packet_alloc(port->chan, &pkt);
	SKTC_ASSERT_ERR(error == 0);
	assert(pkt != 0);

	buf = os_packet_get_next_buflet(pkt, NULL);
	assert(buf != NULL);
	error = os_buflet_set_data_offset(buf, 0);
	SKTC_ASSERT_ERR(error == 0);
	bdlim = blen = os_buflet_get_data_limit(buf);
	assert(bdlim != 0);
	bcnt = os_packet_get_buflet_count(pkt);
	assert(blen * bcnt >= len);
	baddr = os_buflet_get_object_address(buf);
	assert(baddr != NULL);

	error = os_packet_set_link_header_length(pkt, 0);
	SKTC_ASSERT_ERR(error == 0);

	/* copy the frame bytes */
	while (len != 0) {
		if (blen == 0) {
			error = os_buflet_set_data_length(buf, bdlim);
			SKTC_ASSERT_ERR(error == 0);
			pbuf = buf;
			buf = os_packet_get_next_buflet(pkt, pbuf);
			assert(buf != NULL);
			error = os_buflet_set_data_offset(buf, 0);
			SKTC_ASSERT_ERR(error == 0);
			baddr = os_buflet_get_object_address(buf);
			assert(baddr != NULL);
			bdlim = blen = os_buflet_get_data_limit(buf);
		}
		clen = MIN(blen, len);
		memcpy(baddr, bytes, clen);
		len -= clen;
		blen -= clen;
		bytes += clen;
		baddr += clen;
		assert(len == 0 || blen == 0);
	}
	if (frame->csum_flags != 0) {
		os_packet_set_inet_checksum(pkt, frame->csum_flags,
		    frame->csum_start, frame->csum_stuff);
	}
	if (pbuf == NULL) {
		error = os_buflet_set_data_length(buf, frame->len);
	} else {
		error = os_buflet_set_data_length(buf, clen);
	}
	SKTC_ASSERT_ERR(error == 0);

	os_packet_set_flow_uuid(pkt, frame->flow_uuid);
	error = os_packet_finalize(pkt);
	SKTC_ASSERT_ERR(error == 0);
	return pkt;
}

int
sktu_channel_port_tx(channel_port_t port, packet_t pkt)
{
	int error;
	slot_prop_t prop;
	channel_slot_t slot;

	slot = os_channel_get_next_slot(port->tx_ring, NULL, &prop);
	if (slot == NULL) {
		return ENOENT;
	}
	error = os_channel_slot_attach_packet(port->tx_ring, slot, pkt);
	SKTC_ASSERT_ERR(error == 0);
	error = os_channel_advance_slot(port->tx_ring, slot);
	SKTC_ASSERT_ERR(error == 0);
	return 0;
}

/*
 * Burst Tx tries to tx as many it can in one shot.
 *
 * Returns number of actually completed Tx.
 */
uint32_t
sktu_channel_port_tx_burst_pkt(channel_port_t port, packet_t *pkts,
    uint32_t n)
{
	struct timespec timeout = {
		.tv_sec = 10,
		.tv_nsec = 0,
	};
	struct kevent evlist, kev;
	int kq;
	int error;
	uint32_t i;

	kq = kqueue();
	assert(kq != -1);

	EV_SET(&kev, port->fd, EVFILT_WRITE, EV_ADD | EV_ENABLE, 0, 0, NULL);
	error = kevent(kq, &kev, 1, NULL, 0, NULL);
	SKTC_ASSERT_ERR(error == 0);

	/* wait for Tx to become available */
	error = kevent(kq, NULL, 0, &evlist, 1, &timeout);
	if (error <= 0) {
		if (errno == EAGAIN) {
			return 0;
		}
		SKTC_ASSERT_ERR(error == 0);
	}
	if (error == 0) {
		T_LOG("kevent timeout\n");
		return 0;
	}
	if (evlist.flags & EV_ERROR) {
		int err = evlist.data;
		if (err == EAGAIN) {
			return 0;
		}
		SKTC_ASSERT_ERR(err == 0);
	}

	if (evlist.filter != EVFILT_WRITE) {
		err(EX_OSERR, "%lu event %d?\n", evlist.ident, evlist.filter);
	}

	for (i = 0; i < n; i++) {
		error = sktu_channel_port_tx(port, pkts[i]);
		if (error != 0) {
			break;
		}
	}

	if (i != 0) {
		error = os_channel_sync(port->chan, CHANNEL_SYNC_TX);
		SKTC_ASSERT_ERR(error == 0);
	}

	return i;
}

/*
 * Burst Tx tries to tx as many it can in one shot.
 *
 * Returns number of actually completed Tx.
 */
uint32_t
sktu_channel_port_tx_burst(channel_port_t port, struct sktu_frame **frames,
    uint32_t n)
{
	struct timespec timeout = {
		.tv_sec = 10,
		.tv_nsec = 0,
	};
	struct kevent evlist, kev;
	int kq;
	int error;
	uint32_t i;
	packet_t pkt;

	kq = kqueue();
	assert(kq != -1);

	EV_SET(&kev, port->fd, EVFILT_WRITE, EV_ADD | EV_ENABLE, 0, 0, NULL);
	error = kevent(kq, &kev, 1, NULL, 0, NULL);
	SKTC_ASSERT_ERR(error == 0);

	/* wait for Tx to become available */
	error = kevent(kq, NULL, 0, &evlist, 1, &timeout);
	if (error <= 0) {
		if (errno == EAGAIN) {
			return 0;
		}
		SKTC_ASSERT_ERR(error == 0);
	}
	if (error == 0) {
		T_LOG("kevent timeout\n");
		return 0;
	}
	if (evlist.flags & EV_ERROR) {
		int err = evlist.data;
		if (err == EAGAIN) {
			return 0;
		}
		SKTC_ASSERT_ERR(err == 0);
	}

	if (evlist.filter != EVFILT_WRITE) {
		err(EX_OSERR, "%lu event %d?\n", evlist.ident, evlist.filter);
	}

	for (i = 0; i < n; i++) {
		pkt = sktu_channel_port_frame_to_pkt(port, frames[i]);
		error = sktu_channel_port_tx(port, pkt);
		if (error != 0) {
			break;
		}
	}

	if (i != 0) {
		error = os_channel_sync(port->chan, CHANNEL_SYNC_TX);
		SKTC_ASSERT_ERR(error == 0);
	}

	return i;
}

/*
 * Bulk Tx makes sure all Tx operations are completed; otherwise fails the test.
 */
void
sktu_channel_port_tx_bulk(channel_port_t port, struct sktu_frame **frames,
    uint32_t n)
{
	uint32_t ret = 0;
	ret = sktu_channel_port_tx_burst(port, frames, n);
	assert(ret < n);
	if (ret != n) {
		errx(EX_OSERR, "tx bulk failed %u/%u", n, ret);
	}
}

int
sktu_parse_ipv4_frame(struct sktu_frame *frame, void *ip_payload,
    uint32_t *ip_payload_len)
{
	size_t pkt_len, payload_len;
	void *buf;
	struct ip *ip;
	uint16_t csum;

	buf = &frame->bytes[0];
	ip = (struct ip*)buf;
	pkt_len = frame->len;
	assert(pkt_len == ntohs(ip->ip_len));
	payload_len = pkt_len - sizeof(*ip);
	assert(payload_len <= SKTU_FRAME_BUF_SIZE);

	/* verify ip header checksum */
	csum = in_cksum(ip, sizeof(*ip), 0);
	if (csum != 0) {
		sktu_dump_buffer(stderr, __func__, buf, pkt_len);
		errx(EX_PROTOCOL, "IP header checksum invalid");
	}

	if (ip_payload != NULL) {     /* copy the data */
		memcpy(ip_payload, buf + sizeof(*ip), pkt_len - sizeof(*ip));
	}

	*ip_payload_len = payload_len;
	return 0;
}

int
sktu_parse_tcp4_frame(struct sktu_frame *frame, void *tcp_payload,
    uint32_t *tcp_payload_len)
{
	uint32_t pkt_len, payload_len;
	void *buf;
	struct ip *ip;
	ip_tcp_header_t *ip_tcp;
	uint16_t csum;

	buf = &frame->bytes[0];
	ip = buf;
	ip_tcp = buf;
	pkt_len = frame->len;
	if (ip->ip_p != IPPROTO_TCP) {
		sktu_dump_buffer(stderr, "non-TCP packet", buf, pkt_len);
		return EINVAL;
	}
	assert(pkt_len == ntohs(ip_tcp->ip.ip_len));
	payload_len = pkt_len - sizeof(ip_tcp_header_t);
	assert(payload_len <= SKTU_FRAME_BUF_SIZE);

	csum = in_cksum(ip, sizeof(*ip), 0);
	if (csum != 0) {
		sktu_dump_buffer(stderr, __func__, buf, pkt_len);
		errx(EX_PROTOCOL, "IP header checksum invalid");
	}

	csum = os_inet_checksum(&ip_tcp->tcp, pkt_len - sizeof(struct ip), 0);
	csum = in_pseudo(ip->ip_src.s_addr, ip->ip_dst.s_addr,
	    csum + htonl(payload_len + sizeof(struct tcphdr) + IPPROTO_TCP));
	csum ^= 0xffff;
	if (csum != 0) {
		sktu_dump_buffer(stderr, "invalid TCP csum", buf, pkt_len);
		return -1;
	}

	if (tcp_payload != NULL) {     /* copy the data */
		memcpy(tcp_payload, buf + sizeof(*ip_tcp), payload_len);
	}

	*tcp_payload_len = payload_len;

	return 0;
}

int
sktu_parse_udp4_frame(struct sktu_frame *frame, void *udp_payload,
    uint32_t *udp_payload_len)
{
	size_t pkt_len, payload_len;
	void *buf;
	struct ip *ip;
	ip_udp_header_t *ip_udp;
	uint16_t csum;

	buf = &frame->bytes[0];
	ip = buf;
	ip_udp = buf;
	pkt_len = frame->len;
	if (ip->ip_p != IPPROTO_UDP) {
		sktu_dump_buffer(stderr,
		    "sktu_parse_udp4_frame: non-UDP packet", buf, pkt_len);
		return EINVAL;
	}
	assert(pkt_len == ntohs(ip_udp->ip.ip_len));
	payload_len = pkt_len - sizeof(ip_udp_header_t);
	assert(payload_len <= SKTU_FRAME_BUF_SIZE);

	csum = in_cksum(ip, sizeof(*ip), 0);
	if (csum != 0) {
		sktu_dump_buffer(stderr, __func__, buf, pkt_len);
		errx(EX_PROTOCOL, "IP header checksum invalid");
	}

	if (ip_udp->udp.uh_sum == 0) {
		goto skip_udp_checksum;
	}

	csum = os_inet_checksum(&ip_udp->udp, pkt_len - sizeof(struct ip), 0);
	csum += htons(payload_len + sizeof(struct udphdr) + IPPROTO_UDP);
	csum = in_pseudo(ip->ip_src.s_addr, ip->ip_dst.s_addr, csum);
	csum ^= 0xffff;
	if (csum != 0) {
		sktu_dump_buffer(stderr, __func__, buf, pkt_len);
		return -1;
	}

skip_udp_checksum:
	if (udp_payload != NULL) {
		memcpy(udp_payload, buf + sizeof(*ip_udp), payload_len);
	}

	*udp_payload_len = payload_len;

	return 0;
}

/*
 * Rx once from an available ring;
 * Return 0, if successful; non-zero, otherwise.
 */
struct sktu_frame *
sktu_channel_port_rx(channel_port_t port)
{
	int error;
	slot_prop_t prop;
	channel_slot_t slot;
	struct sktu_frame *frame;
	packet_t pkt;
	void *addr, *buf;
	size_t buf_len;
	size_t frame_length;
	buflet_t buflet;

	slot = os_channel_get_next_slot(port->rx_ring, NULL, &prop);
	if (slot == NULL) {
		return NULL;
	}
	assert(prop.sp_buf_ptr != 0);

	frame = sktu_frame_alloc();

	pkt = os_channel_slot_get_packet(port->rx_ring, slot);
	assert(pkt != 0);
	if (port->user_packet_pool) {
		error = os_channel_slot_detach_packet(port->rx_ring,
		    slot, pkt);
		SKTC_ASSERT_ERR(error == 0);
	}

	buflet = os_packet_get_next_buflet(pkt, NULL);
	assert(buflet != NULL);
	buf = os_buflet_get_object_address(buflet) +
	    os_buflet_get_data_offset(buflet);
	frame_length = os_packet_get_data_length(pkt);

	buflet = os_packet_get_next_buflet(pkt, NULL);
	assert(buflet != NULL);
	buf = os_buflet_get_object_address(buflet) +
	    os_buflet_get_data_offset(buflet);
	buf_len = os_buflet_get_data_length(buflet);
	assert(buf_len < SKTU_FRAME_BUF_SIZE);

	frame->len = os_packet_get_data_length(pkt);

	addr = &frame->bytes[0];
	memcpy(addr, buf, buf_len);
	frame_length -= buf_len;

	while (frame_length != 0) {
		buflet = os_packet_get_next_buflet(pkt, buflet);
		assert(buflet != NULL);
		buf = os_buflet_get_object_address(buflet) +
		    os_buflet_get_data_offset(buflet);
		assert(buf != 0);
		buf_len = os_buflet_get_data_length(buflet);
		assert(buf_len != 0);
		memcpy(addr, buf, buf_len);
		addr += buf_len;
		frame_length -= buf_len;
	}

	os_packet_get_flow_uuid(pkt, &frame->flow_uuid);
	error = os_channel_packet_free(port->chan, pkt);

	error = os_channel_advance_slot(port->rx_ring, slot);
	SKTC_ASSERT_ERR(error == 0);

	return frame;
}

uint32_t
sktu_channel_port_rx_burst(channel_port_t port, struct sktu_frame **frames,
    uint32_t n)
{
	struct timespec timeout = {
		.tv_sec = 10,
		.tv_nsec = 0,
	};

	int error;
	struct kevent evlist, kev;
	int kq;
	uint32_t i;

	kq = kqueue();
	assert(kq != -1);

	EV_SET(&kev, port->fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, NULL);
	error = kevent(kq, &kev, 1, NULL, 0, NULL);
	SKTC_ASSERT_ERR(error == 0);

	/* wait for RX to become available */
	error = kevent(kq, NULL, 0, &evlist, 1, &timeout);
	if (error <= 0) {
		if (errno == EAGAIN) {
			return 0;
		}
		SKTC_ASSERT_ERR(error == 0);
	}
	if (error == 0) {
		T_LOG("kevent timeout\n");
		return 0;
	}
	if (evlist.flags & EV_ERROR) {
		int err = evlist.data;
		if (err == EAGAIN) {
			return 0;
		}
		SKTC_ASSERT_ERR(err == 0);
	}

	if (evlist.filter != EVFILT_READ) {
		err(EX_OSERR, "%lu event %d?\n", evlist.ident, evlist.filter);
	}

	for (i = 0; i < n; i++) {
		frames[i] = sktu_channel_port_rx(port);
		if (frames[i] == NULL) {
			break;
		}
	}

	if (i != 0) {
		error = os_channel_sync(port->chan, CHANNEL_SYNC_RX);
		SKTC_ASSERT_ERR(error == 0);
	}

	close(kq);

	return i;
}

void
sktu_channel_port_rx_bulk(channel_port_t port, struct sktu_frame **frames,
    uint32_t n)
{
	uint32_t ret = 0;
	ret = sktu_channel_port_rx_burst(port, frames, n);
	assert(ret < n);
	if (ret != n) {
		errx(EX_OSERR, "rx bulk failed, %u/%u packets", n, ret);
	}
}

/*
 * Received batch of frames from utun file descriptor.
 *
 * Returns number of frames actually received.
 */
uint32_t
sktu_utun_fd_rx_burst(int utun_fd, struct sktu_frame **frames, uint32_t n)
{
	struct timeval timeout = {
		.tv_sec = 10,
		.tv_usec = 0,
	};

	fd_set readfds, errorfds;
	int retval;

	FD_ZERO(&readfds);
	FD_ZERO(&errorfds);
	FD_SET(utun_fd, &readfds);
	FD_SET(utun_fd, &errorfds);

	retval = select(utun_fd + 1, &readfds, NULL, &errorfds, &timeout);
	if (retval == -1) {
		err(EX_OSERR, "select()");
	}

	if (!FD_ISSET(utun_fd, &readfds) && retval == 0) { // timeout
		T_LOG("recv timeout\n");
		return 0;
	}
	assert(!FD_ISSET(utun_fd, &errorfds));
	assert(retval == 1);

	if (!FD_ISSET(utun_fd, &readfds)) {
		errx(EX_OSERR, "fd selected but no read fd available");
	}

	uint32_t i = 0;
	for (i = 0; i < n; i++) {
		struct {
			uint32_t af;
			char bytes[SKTU_FRAME_BUF_SIZE];
		} utun_packet;
		ssize_t len;
		len = read(utun_fd, &utun_packet, sizeof(utun_packet));
		if (len < 1) {
			errx(EX_OSERR, "utun read 0 len");
		}
		struct sktu_frame *frame = frames[i] = sktu_frame_alloc();
		memcpy(frame->bytes, &utun_packet.bytes, len - sizeof(uint32_t));
		frame->len = len - sizeof(uint32_t);
	}

	return i;
}

void
sktu_utun_fd_tx_burst(int utun_fd, struct sktu_frame **frames, uint32_t n)
{
	struct timeval timeout = {
		.tv_sec = 10,
		.tv_usec = 0,
	};
	fd_set writefds, errorfds;
	int retval;

	FD_ZERO(&writefds);
	FD_ZERO(&errorfds);
	FD_SET(utun_fd, &writefds);
	FD_SET(utun_fd, &errorfds);

	retval = select(utun_fd + 1, NULL, &writefds, &errorfds, &timeout);
	if (retval == -1) {
		err(EX_OSERR, "select()");
	}

	if (!FD_ISSET(utun_fd, &writefds) && retval == 0) { // timeout
		err(EX_OSERR, "recv timeout\n");
	}

	assert(!FD_ISSET(utun_fd, &errorfds));
	assert(retval == 1);

	if (!FD_ISSET(utun_fd, &writefds)) {
		errx(EX_OSERR, "fd selected but no write fd available");
	}

	uint32_t i = 0;
	for (i = 0; i < n; i++) {
		struct sktu_frame *frame = frames[i];
		struct ip *ip = (void *)&frame->bytes[0];
		uint32_t af;
		switch (ip->ip_v) {
		case IPVERSION:
			af = htonl(AF_INET);
			break;
		case IPV6_VERSION:
			af = htonl(AF_INET6);
			break;
		default:
			assert("unrecoginzed IP version");
			__builtin_unreachable();
			break;
		}
		struct {
			uint32_t af;
			char bytes[SKTU_FRAME_BUF_SIZE];
		} utun_packet;
		memcpy(&utun_packet.af, &af, sizeof(af));
		memcpy(&utun_packet.bytes, &frame->bytes[0], frame->len);
		ssize_t write_len = frame->len + sizeof(uint32_t);
		T_LOG("%s writing frame len %zu\n", __func__, write_len);
		ssize_t len = write(utun_fd, &utun_packet, write_len);
		if (len != write_len) {
			err(EX_OSERR, "utun write error\n");
		}
	}
}

struct sktu_frame *
sktu_frame_alloc()
{
	return malloc(sizeof(struct sktu_frame));
}

#define sktu_frame_free(frame) \
do { \
	free(frame); \
	frame = NULL; \
} while (0)

void
sktu_frames_free(struct sktu_frame **frames, size_t n)
{
	for (size_t i = 0; i < n; i++) {
		sktu_frame_free(frames[i]);
		frames[i] = NULL;
	}
}

size_t
sktu_create_ip_frames(struct sktu_frame **frames, size_t n,
    void *src_ip, void *dst_ip, uint8_t proto, const void *sdu, size_t sdu_len,
    size_t mtu, uint16_t csum_flags, uint16_t csum_start, uint16_t csum_stuff)
{
	size_t off = 0, remaining_sdu_len = sdu_len;
	size_t i = 0;
	uint16_t ip_id = sktu_ip_id();
	bool needs_frag = false;

	while (remaining_sdu_len > 0) {
		assert(i < n);

		struct sktu_frame *frame = frames[i] = sktu_frame_alloc();
		char *baddr = &frame->bytes[0];
		struct ip *ip = (struct ip *)baddr;
		size_t dlen;
		bool more_frag = false;

		dlen = mtu - sizeof(*ip);
		if (dlen >= remaining_sdu_len) {
			dlen = remaining_sdu_len;
			needs_frag = false;
			more_frag = false;
		} else {
			dlen = dlen & ~0x7; // round down to 8-byte multiple
			needs_frag = true;
			more_frag = true;
		}

		// can't handle fragmented csum offload
		assert(!(needs_frag && csum_flags != 0));

		memset(ip, 0, sizeof(*ip));
		ip->ip_v = IPVERSION;
		ip->ip_hl = sizeof(struct ip) >> 2;
		ip->ip_ttl = MAXTTL;
		ip->ip_p = proto;
		memcpy(&ip->ip_src, src_ip, sizeof(struct in_addr));
		memcpy(&ip->ip_dst, dst_ip, sizeof(struct in_addr));
		ip->ip_len = htons(sizeof(*ip) + dlen);
		ip->ip_id = htons(ip_id);
		ip->ip_off = ((off >> 3) & IP_OFFMASK);
		if (more_frag) {
			ip->ip_off |= IP_MF;
		}
		ip->ip_off = htons(ip->ip_off);

		/* compute the IP header checksum */
		ip->ip_sum = in_cksum(ip, sizeof(*ip), 0);
		baddr += sizeof(*ip);

		memcpy(baddr, sdu + off, dlen);

		frame->csum_flags = csum_flags;
		frame->csum_start = sizeof(*ip) + csum_start;
		frame->csum_stuff = sizeof(*ip) + csum_stuff;

		frame->len = sizeof(*ip) + dlen;

		off += dlen;
		remaining_sdu_len -= dlen;
		i++;
	}

	return i;
}

size_t
sktu_create_ip6_frames(struct sktu_frame **frames, size_t n,
    void *src_ip, void *dst_ip, uint8_t proto, const void *sdu, size_t sdu_len,
    size_t mtu, uint16_t csum_flags, uint16_t csum_start, uint16_t csum_stuff)
{
	size_t off = 0, remaining_sdu_len = sdu_len;
	size_t i = 0;
	uint16_t ip_id = sktu_ip_id();
	bool needs_frag = false;

	while (remaining_sdu_len > 0) {
		assert(i < n);

		struct sktu_frame *frame = frames[i] = sktu_frame_alloc();
		char *baddr = &frame->bytes[0];
		struct ip6_hdr *ip6 = (struct ip6_hdr *)baddr;
		size_t hlen = sizeof(*ip6);
		size_t plen, dlen;
		bool more_frag = false;

		dlen = mtu - hlen;
		if (dlen >= remaining_sdu_len) {
			// fits in one packet
			dlen = plen = remaining_sdu_len;
			remaining_sdu_len = 0;
			more_frag = false;
		} else {
			// need to fragment
			dlen -= sizeof(struct ip6_frag);
			dlen = dlen & ~0x7; // round down to 8-byte multiple
			plen = sizeof(struct ip6_frag) + dlen;
			remaining_sdu_len -= dlen;
			needs_frag = true;
			more_frag = true;
		}

		// can't handle fragmented csum offload
		assert(!(needs_frag && csum_flags != 0));

		// insert ipv6 header
		memset(ip6, 0, sizeof(*ip6));
		ip6->ip6_vfc = (IPV6_VERSION & IPV6_VERSION_MASK);
		ip6->ip6_plen = htons(plen);
		ip6->ip6_nxt = needs_frag ? IPPROTO_FRAGMENT : proto;
		ip6->ip6_hlim = IPV6_DEFHLIM;
		memcpy(&ip6->ip6_src, src_ip, sizeof(struct in6_addr));
		memcpy(&ip6->ip6_dst, dst_ip, sizeof(struct in6_addr));

		baddr += sizeof(*ip6);

		// insert ipv6 frag header
		if (needs_frag) {
			struct ip6_frag *ip6f = (struct ip6_frag *)baddr;
			ip6f->ip6f_nxt = proto;
			ip6f->ip6f_reserved = 0;
			ip6f->ip6f_offlg = htons(off);
			if (more_frag) {
				ip6f->ip6f_offlg |= IP6F_MORE_FRAG;
			}
			ip6f->ip6f_ident = htonl(ip_id);

			hlen += sizeof(*ip6f);
			baddr += sizeof(*ip6f);
		}

		memcpy(baddr, sdu + off, dlen);

		frame->csum_flags = csum_flags;
		frame->csum_start = sizeof(*ip6) + csum_start;
		frame->csum_stuff = sizeof(*ip6) + csum_stuff;
		frame->len = hlen + dlen;

		off += dlen;
		i++;
	}

	return i;
}

size_t
sktu_create_tcp_frames(struct sktu_frame **frames, size_t n,
    uint8_t ipver, void *src_ip, void *dst_ip, uint16_t sport, uint16_t dport,
    const void *data, size_t data_len, size_t mtu, bool csum_offload)
{
	uint32_t n_frames;
	size_t sdu_len = data_len + sizeof(struct tcphdr);
	void *sdu = malloc(sdu_len);

	// populate header
	struct tcphdr *tcp = (struct tcphdr *)sdu;
	tcp->th_sport = htons(sport);
	tcp->th_dport = htons(dport);
	tcp->th_flags |= 0; //FIXME (connect ? TH_SYN : TH_RST);
	tcp->th_off = (sizeof(struct tcphdr)) >> 2;

	// copy payload
	memcpy(sdu + sizeof(*tcp), data, data_len);

	// compute checksum
	uint16_t sum = 0;

	if (ipver == IPVERSION) {
		sum = in_pseudo(*(uint32_t*)src_ip, *(uint32_t*)dst_ip,
		    htons(data_len + sizeof(struct tcphdr) + IPPROTO_TCP));
	} else {
		sum = in6_pseudo(src_ip, dst_ip,
		    htonl(data_len + sizeof(struct tcphdr) + IPPROTO_TCP));
	}
	tcp->th_sum = sum;

	uint16_t csum_flags = 0, csum_start = 0, csum_stuff = 0;
	if (csum_offload) {
		csum_flags = PACKET_CSUM_PARTIAL;
		csum_start = 0;
		csum_stuff = offsetof(struct tcphdr, th_sum);
	} else {
		sum = os_inet_checksum(sdu, sdu_len, 0);
		tcp->th_sum = sktu_fold_sum_final(sum);
	}

	// IP framing
	if (ipver == IPVERSION) {
		n_frames = sktu_create_ip_frames(frames, n, src_ip, dst_ip,
		    IPPROTO_TCP, sdu, sdu_len, mtu, csum_flags, csum_start,
		    csum_stuff);
	} else {
		n_frames = sktu_create_ip6_frames(frames, n, src_ip, dst_ip,
		    IPPROTO_TCP, sdu, sdu_len, mtu, csum_flags, csum_start,
		    csum_stuff);
	}

	free(sdu);

	return n_frames;
}

size_t
sktu_create_udp_frames(struct sktu_frame **frames, size_t n,
    uint8_t ipver, void *src_ip, void *dst_ip, uint16_t sport, uint16_t dport,
    const void *data, size_t data_len, size_t mtu, bool csum_offload)
{
	uint32_t n_frames;
	size_t sdu_len = data_len + sizeof(struct udphdr);
	void *sdu = malloc(sdu_len);

	// populate header
	struct udphdr *udp = (struct udphdr *)sdu;
	udp->uh_sport = htons(sport);
	udp->uh_dport = htons(dport);
	udp->uh_ulen = htons(sizeof(*udp) + data_len);

	// compute payload checksum
	uint32_t payload_sum = 0, pseudo_sum = 0;
	if (ipver == IPVERSION) {
		struct ipv4_udp_pseudo_hdr udp_pseudo = {};
		memcpy(&udp_pseudo.src_ip, src_ip, sizeof(struct in_addr));
		memcpy(&udp_pseudo.dst_ip, dst_ip, sizeof(struct in_addr));
		udp_pseudo.proto = IPPROTO_UDP;
		udp_pseudo.length = htons(sizeof(struct udphdr) + data_len);
		pseudo_sum = os_inet_checksum(&udp_pseudo, sizeof(udp_pseudo)
		    + sizeof(struct udphdr), 0);
	} else {
		struct ipv6_udp_pseudo_hdr udp_pseudo = {};
		memcpy(&udp_pseudo.src_ip, src_ip, sizeof(struct in6_addr));
		memcpy(&udp_pseudo.dst_ip, dst_ip, sizeof(struct in6_addr));
		udp_pseudo.proto = IPPROTO_UDP;
		udp_pseudo.length = htons(sizeof(struct udphdr) + data_len);
		pseudo_sum = os_inet_checksum(&udp_pseudo, sizeof(udp_pseudo)
		    + sizeof(struct udphdr), 0);
	}

	uint16_t csum_flags = 0, csum_start = 0, csum_stuff = 0;
	if (csum_offload) {
		csum_flags = PACKET_CSUM_PARTIAL | PACKET_CSUM_ZERO_INVERT;
		csum_start = 0;
		csum_stuff = offsetof(struct udphdr, uh_sum);
		udp->uh_sum = sktu_fold_sum_final(pseudo_sum);
	} else {
		payload_sum = os_inet_checksum(data, data_len, 0);
		udp->uh_sum = ~sktu_fold_sum_final(pseudo_sum + payload_sum);
	}

	// copy payload
	memcpy(sdu + sizeof(*udp), data, data_len);

	// IP framing
	if (ipver == IPVERSION) {
		n_frames = sktu_create_ip_frames(frames, n, src_ip, dst_ip,
		    IPPROTO_UDP, sdu, sdu_len, mtu, csum_flags, csum_start,
		    csum_stuff);
	} else {
		n_frames = sktu_create_ip6_frames(frames, n, src_ip, dst_ip,
		    IPPROTO_UDP, sdu, sdu_len, mtu, csum_flags, csum_start,
		    csum_stuff);
	}

	free(sdu);

	return n_frames;
}

void
sktu_attach_flow_metadata_to_frames(struct sktu_flow *flow,
    struct sktu_frame **frames, size_t n_frames)
{
	for (uint32_t i = 0; i < n_frames; i++) {
		struct sktu_frame *frame = frames[i];
		uuid_copy(frame->flow_uuid, flow->uuid);
	}
}

static size_t
_sktu_create_udp_flow_input_frames(struct sktu_flow *flow,
    struct sktu_frame **frames, size_t n, const void *data, size_t data_len)
{
	n = sktu_create_udp_frames(frames, n, flow->ipver, flow->dst_ip,
	    flow->src_ip, flow->dport, flow->sport, data, data_len, flow->mtu,
	    NO_CSUM_OFFLOAD);
	sktu_attach_flow_metadata_to_frames(flow, frames, n);
	return n;
}

static size_t
_sktu_create_udp_flow_output_frames(struct sktu_flow *flow,
    struct sktu_frame **frames, size_t n, const void *data, size_t data_len,
    bool csum_offload)
{
	n = sktu_create_udp_frames(frames, n, flow->ipver, flow->src_ip,
	    flow->dst_ip, flow->sport, flow->dport, data, data_len, flow->mtu,
	    csum_offload);
	sktu_attach_flow_metadata_to_frames(flow, frames, n);
	return n;
}

static size_t
_sktu_create_tcp_flow_input_frames(struct sktu_flow *flow,
    struct sktu_frame **frames, size_t n, const void *data, size_t data_len)
{
	n = sktu_create_tcp_frames(frames, n, flow->ipver, flow->dst_ip,
	    flow->src_ip, flow->dport, flow->sport, data, data_len, flow->mtu,
	    NO_CSUM_OFFLOAD);
	sktu_attach_flow_metadata_to_frames(flow, frames, n);
	return n;
}

static size_t
_sktu_create_tcp_flow_output_frames(struct sktu_flow *flow,
    struct sktu_frame **frames, size_t n, const void *data, size_t data_len,
    bool csum_offload)
{
	n = sktu_create_tcp_frames(frames, n, flow->ipver, flow->src_ip,
	    flow->dst_ip, flow->sport, flow->dport, data, data_len, flow->mtu,
	    csum_offload);
	sktu_attach_flow_metadata_to_frames(flow, frames, n);
	return n;
}

static size_t
_sktu_create_ip_flow_input_frames(struct sktu_flow *flow,
    struct sktu_frame **frames, size_t n, const void *data, size_t data_len)
{
	n = sktu_create_ip_frames(frames, n, flow->dst_ip, flow->src_ip,
	    flow->ip_protocol, data, data_len, flow->mtu, 0, 0, 0);
	sktu_attach_flow_metadata_to_frames(flow, frames, n);
	return n;
}

static size_t
_sktu_create_ip_flow_output_frames(struct sktu_flow *flow,
    struct sktu_frame **frames, size_t n, const void *data,
    size_t data_len, bool csum_offload)
{
	n = sktu_create_ip_frames(frames, n, flow->src_ip, flow->dst_ip,
	    flow->ip_protocol, data, data_len, flow->mtu, 0, 0, 0);
	sktu_attach_flow_metadata_to_frames(flow, frames, n);
	return n;
}

#define SKTU_STRING_BUF_MAX 2048
char *
sktu_nfr_to_string(struct nx_flow_req *nfr)
{
	static char buf[SKTU_STRING_BUF_MAX];
	uuid_string_t uuidstr;
	char sa_buf[31];
	char da_buf[31];

	uuid_unparse(nfr->nfr_flow_uuid, uuidstr);
	if (nfr->nfr_saddr.sa.sa_family == AF_INET) {
		inet_ntop(AF_INET, &nfr->nfr_saddr.sin.sin_addr.s_addr, sa_buf,
		    sizeof(sa_buf));
		inet_ntop(AF_INET, &nfr->nfr_daddr.sin.sin_addr.s_addr, da_buf,
		    sizeof(da_buf));
	} else {
		inet_ntop(AF_INET6, &nfr->nfr_saddr.sin6.sin6_addr, sa_buf,
		    sizeof(sa_buf));
		inet_ntop(AF_INET6, &nfr->nfr_daddr.sin6.sin6_addr, da_buf,
		    sizeof(da_buf));
	}
	snprintf(buf, sizeof(buf),
	    "nx_port[%d] %s src=%s,dst=%s,proto=%d,sport=%d,dport=%d, flags=0x%x",
	    nfr->nfr_nx_port, uuidstr, sa_buf, da_buf, nfr->nfr_ip_protocol,
	    ntohs(nfr->nfr_saddr.sin.sin_port),
	    ntohs(nfr->nfr_daddr.sin.sin_port), nfr->nfr_flags);

	return buf;
}

char *
sktu_flow_to_string(struct sktu_flow *flow)
{
	return sktu_nfr_to_string(&flow->nfr);
}

struct sktu_flow *
_sktu_create_nexus_flow(sktu_nexus_t nexus, nexus_port_t nx_port,
    uint8_t af, void *src, void *dst, uint8_t proto, uint16_t sport,
    uint16_t dport, uint32_t flags)
{
	struct sktu_flow *flow = malloc(sizeof(*flow));

	memset(flow, 0, sizeof(*flow));
	flow->nexus = nexus;
	flow->mtu = 1500;

	flow->nx_port = nx_port;

	struct nx_flow_req *nfr = &flow->nfr;
	union sockaddr_in_4_6 *saddr = &nfr->nfr_saddr;
	union sockaddr_in_4_6 *daddr = &nfr->nfr_daddr;
	nfr->nfr_nx_port = nx_port;
	if (af == AF_INET) {
		// initialize flow
		flow->ipver = IPVERSION;
		// fill in nfr (stuff in network order :)
		SIN(saddr)->sin_len = sizeof(struct sockaddr_in);
		SIN(daddr)->sin_len = sizeof(struct sockaddr_in);
		SIN(saddr)->sin_family = AF_INET;
		SIN(daddr)->sin_family = AF_INET;
		SIN(saddr)->sin_addr = *(struct in_addr *)src;
		SIN(daddr)->sin_addr = *(struct in_addr *)dst;
		nfr->nfr_ip_protocol = proto;
		SIN(saddr)->sin_port = htons(sport);
		SIN(daddr)->sin_port = htons(dport);
	} else {
		flow->ipver = IPV6_VERSION;
		SIN6(saddr)->sin6_len = sizeof(struct sockaddr_in6);
		SIN6(daddr)->sin6_len = sizeof(struct sockaddr_in6);
		SIN6(saddr)->sin6_family = AF_INET6;
		SIN6(daddr)->sin6_family = AF_INET6;
		SIN6(saddr)->sin6_addr = *(struct in6_addr *)src;
		SIN6(daddr)->sin6_addr = *(struct in6_addr *)dst;
		nfr->nfr_ip_protocol = proto;
		SIN6(saddr)->sin6_port = htons(sport);
		SIN6(daddr)->sin6_port = htons(dport);
	}

	uuid_generate_random(nfr->nfr_flow_uuid);
	nfr->nfr_flags = flags;

	errno = 0;
	int error = __os_nexus_flow_add(nexus->controller, nexus->fsw_nx_uuid, nfr);
	if (error) {
		T_LOG("Failed flow %s\n", sktu_nfr_to_string(nfr));
		free(flow);
		return NULL;
	}

	if (af == AF_INET) {
		flow->src_ip = &SIN(saddr)->sin_addr;
		flow->dst_ip = &SIN(daddr)->sin_addr;
		flow->sport = ntohs(SIN(saddr)->sin_port);
		flow->dport = ntohs(SIN(daddr)->sin_port);
	} else {
		flow->src_ip = &SIN6(saddr)->sin6_addr;
		flow->dst_ip = &SIN6(daddr)->sin6_addr;
		flow->sport = ntohs(SIN6(saddr)->sin6_port);
		flow->dport = ntohs(SIN6(daddr)->sin6_port);
	}

	flow->ip_protocol = proto;
	uuid_copy(flow->uuid, nfr->nfr_flow_uuid);

	switch (proto) {
	case IPPROTO_UDP:
		flow->create_input_frames = _sktu_create_udp_flow_input_frames;
		flow->create_output_frames = _sktu_create_udp_flow_output_frames;
		break;
	case IPPROTO_TCP:
		flow->create_input_frames = _sktu_create_tcp_flow_input_frames;
		flow->create_output_frames = _sktu_create_tcp_flow_output_frames;
		break;
	default:
		flow->create_input_frames = _sktu_create_ip_flow_input_frames;
		flow->create_output_frames = _sktu_create_ip_flow_output_frames;
	}

	assert(nfr->nfr_nx_port != NEXUS_PORT_ANY);

	T_LOG("Created flow %s\n", sktu_nfr_to_string(nfr));

	return flow;
}

struct sktu_flow *
sktu_create_nexus_flow(sktu_nexus_t nexus, uint8_t af, void *src, void *dst,
    uint8_t proto, uint16_t sport, uint16_t dport)
{
	return _sktu_create_nexus_flow(nexus, NEXUS_PORT_ANY, af, src, dst, proto, sport, dport, 0);
}

struct sktu_flow *
sktu_create_nexus_flow_with_nx_port(sktu_nexus_t nexus, nexus_port_t nx_port,
    uint8_t af, void *src, void *dst, uint8_t proto, uint16_t sport,
    uint16_t dport)
{
	return _sktu_create_nexus_flow(nexus, nx_port, af, src, dst, proto, sport, dport, 0);
}

struct sktu_flow *
sktu_create_nexus_low_latency_flow(sktu_nexus_t nexus, uint8_t af, void *src, void *dst,
    uint8_t proto, uint16_t sport, uint16_t dport)
{
	return _sktu_create_nexus_flow(nexus, NEXUS_PORT_ANY, af, src, dst, proto, sport, dport, NXFLOWREQF_LOW_LATENCY);
}

void
_sktu_destroy_nexus_flow(struct sktu_flow *flow)
{
	sktu_nexus_t nexus = flow->nexus;
	struct nx_flow_req *nfr = &flow->nfr;

	int error = __os_nexus_flow_del(nexus->controller, nexus->fsw_nx_uuid, nfr);
	SKTC_ASSERT_ERR(!error);
	if (error) {
		T_LOG("failed to deling flow %s", sktu_nfr_to_string(nfr));
	}

	free(flow);
}

int
sktu_get_nexus_flow_stats(uuid_t flow_uuid, struct sk_stats_flow *sf)
{
	size_t length = 0;
	void *buffer = NULL;
	int ret = sysctl_buf(SK_STATS_FLOW, &buffer, &length, NULL, 0);
	assert(ret == 0);
	assert(buffer != NULL && length != 0);

	assert((length % sizeof(*sf)) == 0);

	struct sk_stats_flow *iter;
	for (iter = buffer; (void *)iter < buffer + length; iter++) {
		if (uuid_compare(iter->sf_uuid, flow_uuid) == 0) {
			*sf = *iter;
			return 0;
		}
	}
	return ENOENT;
}

int
sktu_get_nexus_flowswitch_stats(struct sk_stats_flow_switch **sfsw, size_t *len)
{
	int ret;
	void *buffer = NULL;
	size_t length = 0;
	size_t width = sizeof(struct sk_stats_flow_switch);

	ret = sysctl_buf(SK_STATS_FLOW_SWITCH, &buffer, &length, NULL, 0);
	if (ret != 0 || buffer == NULL || length == 0) {
		return ret;
	}
	if ((length % width) != 0) {
		T_LOG("Error, mismatching sk_stats_flow_switch, quit\n");
		exit(EX_OSERR);
	}

	*sfsw = (struct sk_stats_flow_switch *)buffer;
	*len = length;

	return 0;
}

void
__fsw_stats_print(struct fsw_stats *s)
{
	int i;

	for (i = 0; i < __FSW_STATS_MAX; i++) {
		if (STATS_VAL(s, i) == 0) {
			continue;
		}
		os_log(OS_LOG_DEFAULT, "\t%-24s: %llu\n",
		    fsw_stats_str(i), STATS_VAL(s, i));
	}
}
