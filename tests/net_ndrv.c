/*
 * Copyright (c) 2022 Apple Inc. All rights reserved.
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

/*
 * net_ndrv.c
 * - test ndrv socket
 */

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_media.h>
#include <net/if_types.h>
#include <net/if_dl.h>
#include <net/dlil.h>
#include <net/ndrv.h>
#include <net/ethernet.h>
#include <sys/sockio.h>
#include <fcntl.h>
#include <stdbool.h>
#include <TargetConditionals.h>
#include <darwintest_utils.h>

static const struct ether_addr multicast_one = {
	{ 0x01, 0x80, 0xc2, 0x00, 0x00, 0x01 }
};

static const struct ether_addr multicast_two = {
	{ 0x01, 0x80, 0xc2, 0x00, 0x00, 0x02 }
};

static void
ndrv_socket_do_multicast(int s, const struct ether_addr * multiaddr,
    bool add)
{
	struct sockaddr_dl      dl;
	int                     status;


	bzero(&dl, sizeof(dl));
	dl.sdl_len = sizeof(dl);
	dl.sdl_family = AF_LINK;
	dl.sdl_type = IFT_ETHER;
	dl.sdl_nlen = 0;
	dl.sdl_alen = sizeof(*multiaddr);
	bcopy(multiaddr, dl.sdl_data, sizeof(*multiaddr));
	status = setsockopt(s, SOL_NDRVPROTO,
	    add ? NDRV_ADDMULTICAST : NDRV_DELMULTICAST,
	    &dl, dl.sdl_len);
	T_ASSERT_POSIX_SUCCESS(status,
	    "setsockopt(NDRV_%sMULTICAST)",
	    add ? "ADD" : "DEL");
}

static void
ndrv_socket_add_multicast(int s, const struct ether_addr * multiaddr)
{
	ndrv_socket_do_multicast(s, multiaddr, true);
}

static void
ndrv_socket_remove_multicast(int s, const struct ether_addr * multiaddr)
{
	ndrv_socket_do_multicast(s, multiaddr, false);
}

static int
ndrv_socket_open(const char * ifname)
{
	struct sockaddr_ndrv    ndrv;
	int                     s;
	int                     status;

	s = socket(AF_NDRV, SOCK_RAW, 0);
	T_ASSERT_POSIX_SUCCESS(s, "socket(AF_NDRV, SOCK_RAW, 0)");
	bzero(&ndrv, sizeof(ndrv));
	strlcpy((char *)ndrv.snd_name, ifname, sizeof(ndrv.snd_name));
	ndrv.snd_len = sizeof(ndrv);
	ndrv.snd_family = AF_NDRV;
	status = bind(s, (struct sockaddr *)&ndrv, sizeof(ndrv));
	T_ASSERT_POSIX_SUCCESS(status, "bind ndrv socket");
	return s;
}

static void
ndrv_socket_multicast_add_remove(const char * ifname)
{
	int                     s;

	/* test for rdar://99667160 */
	s = ndrv_socket_open(ifname);
	ndrv_socket_add_multicast(s, &multicast_one);
	ndrv_socket_add_multicast(s, &multicast_two);
	ndrv_socket_remove_multicast(s, &multicast_one);
	close(s);
}

T_DECL(ndrv_socket_multicast_add_remove,
    "ndrv socket multicast add remove",
    T_META_ASROOT(true))
{
	ndrv_socket_multicast_add_remove("lo0");
}
