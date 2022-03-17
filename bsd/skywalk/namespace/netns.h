/*
 * Copyright (c) 2016-2018 Apple Inc. All rights reserved.
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
#ifndef _SKYWALK_NAMESPACE_NETNS_H_
#define _SKYWALK_NAMESPACE_NETNS_H_

#include <sys/param.h>
#include <net/if_var.h>

/*
 * The netns module arbitrates local L4 port number usage across Skywalk
 * and the BSD networking stack. Its aim is to be lightweight and keep as
 * little state as possible; as such, it can't tell you WHO is using port X
 * so much as that port X is being used.
 *
 * NOTE: This API expects port numbers and IP addresses to be passed in
 *	 network byte order.
 */


/*
 * netns_token is a structure passed back to port registrants used to keep
 * track of what they registered and what flags they passed at the time.
 *
 * These tokens are intended to be opaque to users and should never be
 * modified by external code.
 *
 * Token memory is managed by netns; they are created as the result of a call
 * to netns_reserve(), and remain valid until passed into netns_release().
 */
typedef struct ns_token *netns_token;

extern int netns_init(void);
extern void netns_uninit(void);
extern void netns_reap_caches(boolean_t);
extern boolean_t netns_is_enabled(void);

/*
 * Metadata about a flow
 */
struct ns_flow_info {
	/* rule (flow) UUID */
	uuid_t                  nfi_flow_uuid
	__attribute((aligned(sizeof(uint64_t))));

	struct ifnet            *nfi_ifp;       /* interface index */
	union sockaddr_in_4_6   nfi_laddr;      /* local IP address */
	union sockaddr_in_4_6   nfi_faddr;      /* foreign IP address */
	uint8_t                 nfi_protocol;   /* protocol */
	uint8_t                 nfi_pad[3];     /* for future */
	pid_t                   nfi_owner_pid;
	pid_t                   nfi_effective_pid;
	char                    nfi_owner_name[MAXCOMLEN + 1];
	char                    nfi_effective_name[MAXCOMLEN + 1];
};

/*
 * Reserve a port in the namespace of the provided <addr, proto> tuple. The
 * return code indicates whether the reservation succeeded or failed (if the
 * port was already reserved by another protocol stack).
 *
 * The function will create a new netns_token and set the token argument to
 * point to it. This token should be held for the lifetime of the port
 * reservation and passed to future netns calls to modify or release
 * the reservation.
 *
 * If a preexisting token is passed in, the call will either panic (if the
 * NETNS_PRERESERVED flag is not set) or assert that the function arguments
 * match the reservation pointed to by the token, returning with no further
 * action (if NETNS_PRERESERVED is set).
 *
 * Either NETNS_SKYWALK, NETNS_LISTENER, NETNS_BSD or NETNS_PF must be passed
 * in through the flags parameter depending on the caller as this is what the
 * reservation logic uses to determine if a given port is already in use:
 *    - BSD and PF can reserve a port only if it has no Skywalk or Listener
 *      reservations
 *    - Listeners can reserve a port only if it has no Listener, BSD or PF
 *      reservations
 *    - Skywalk can reserve a port only if it has no Skywalk, BSD or PF
 *      reservations, UNLESS there is also a Listener reservation, in which
 *      case the presence of prexisting Skywalk reservations are ignored
 */
extern int netns_reserve(netns_token *token, uint32_t *addr, uint8_t addr_len,
    uint8_t proto, in_port_t port, uint32_t flags, struct ns_flow_info *nfi);

/*
 * Reserve a port in the namespace of the provided <addr, proto> tuple, letting
 * netns pick the port for the caller and saving its value into the port
 * argument. Aside from this behavior, this function behaves identically to
 * netns_reserve().
 */
extern int netns_reserve_ephemeral(netns_token *token, uint32_t *addr,
    uint8_t addr_len, uint8_t proto, in_port_t *port, uint32_t flags,
    struct ns_flow_info *nfi);

/*
 * Release a port reservation recorded by the provided token.
 *
 * After calling, the token passed into the function becomes valid and the
 * pointer to it will be set to NULL.
 */
extern void netns_release(netns_token *token);

/*
 * Mark a port reservation recorded by the provided token as half closed.
 * The half closed port will not be included in the list of ports returned
 * by netns_get_local_ports() when IFNET_GET_LOCAL_PORTS_ACTIVEONLY flag is set.
 */
extern void netns_half_close(netns_token *token);

/*
 * Mark a port reservation recorded by the provided token as withdrawn.
 * The withdrawn port will not be included in the list of ports returned
 * by netns_get_local_ports().
 */
extern void netns_withdraw(netns_token *token);

/*
 * Access the flow info associated with a token, by filling out the local struct.
 * Returns 0 on success, or an error otherwise.
 */
extern int netns_get_flow_info(netns_token *token, struct ns_flow_info *nfi);

/*
 * Update the IP address a port reservation is assigned to - mostly used by
 * the TCP subsystem of the BSD stack, but technically whenever a pcb element
 * gets rehashed.
 *
 * This operation is atomic - it may fail if the port is already reserved on
 * the new address and the appropriate reuse flags aren't present, but in this
 * case the old reservation is kept.
 *
 * The passed in token will be updated to reflect this new reservation.
 */
extern int netns_change_addr(netns_token *token, uint32_t *new_addr,
    uint8_t new_addr_len);

/*
 * Update which network interface a given port reservation corresponds to.
 * Passing NULL for the ifp argument clears the reservation from all
 * interfaces.
 *
 * Note that a port reservation holds across ALL interfaces in the system,
 * not just the one set by this function - the ifnet here is primarily used
 * by netns_get_local_ports() to identify which L4 ports are active on a given
 * interface.
 */
extern void netns_set_ifnet(netns_token *token, ifnet_t ifp);

/*
 * Unrelate all port reservations to the specified interface (effectively
 * iterates over all tokens pointed to ifp with netns_set_ifnet, and sets their
 * ifp to null)
 */
extern void netns_ifnet_detach(ifnet_t ifp);

/*
 * Change flags related to the port reservation, primarily to provide
 * information about connection state to drivers looking for port offload
 * lists.
 *
 * Cannot be used to change flags related to the initial reservation, like
 * NETNS_SKYWALK/NETNS_BSD/etc.
 */
extern void netns_change_flags(netns_token *token, uint32_t set_flags,
    uint32_t clear_flags);

/*
 * Fill in the provided bitfield with the active ports corresponding to the
 * ifnet specified by ifp. Additional filters can be applied to this bitmap
 * with the protocol and flags arguments, which behave identically to their
 * corresponding arguments in ifnet_get_local_ports_extended().
 */
extern errno_t
netns_get_local_ports(ifnet_t ifp, protocol_family_t protocol,
    u_int32_t flags, u_int8_t *bitfield);

/*
 * Return 1 if the parent ifnet of the specified ifaddr has any reservations
 * for the specified protocol, 0 otherwise.
 */
extern uint32_t
netns_find_anyres_byaddr(struct ifaddr *ifa, uint8_t proto);

/*
 * Return count of existing port reservations in the coresponding namespace, IPv4.
 */
extern uint32_t
netns_lookup_reservations_count_in(struct in_addr addr, uint8_t proto);

/*
 * Return count of existing port reservations in the coresponding namespace, IPv6.
 */
extern uint32_t
netns_lookup_reservations_count_in6(struct in6_addr addr, uint8_t proto);

/*
 * Address-family-specific versions of netns_reserve and netns_change_addr.
 */
__attribute__((always_inline))
static inline int
netns_reserve_in(netns_token *token, struct in_addr addr, uint8_t proto,
    in_port_t port, uint32_t flags, struct ns_flow_info *nfi)
{
	return netns_reserve(token, &addr.s_addr, sizeof(struct in_addr),
	           proto, port, flags, nfi);
}

__attribute__((always_inline))
static inline int
netns_reserve_in6(netns_token *token, struct in6_addr addr, uint8_t proto,
    in_port_t port, uint32_t flags, struct ns_flow_info *nfi)
{
	if (IN6_IS_SCOPE_EMBED(&addr)) {
		addr.s6_addr16[1] = 0;
	}
	return netns_reserve(token, &addr.s6_addr32[0],
	           sizeof(struct in6_addr), proto, port, flags, nfi);
}

__attribute__((always_inline))
static inline int
netns_change_addr_in(netns_token *token, struct in_addr addr)
{
	return netns_change_addr(token, &addr.s_addr,
	           sizeof(struct in_addr));
}

__attribute__((always_inline))
static inline int
netns_change_addr_in6(netns_token *token, struct in6_addr addr)
{
	if (IN6_IS_SCOPE_EMBED(&addr)) {
		addr.s6_addr16[1] = 0;
	}
	return netns_change_addr(token, &addr.s6_addr32[0],
	           sizeof(struct in6_addr));
}

#define NETNS_TOKEN_VALID(token_ptr) ((*token_ptr) != NULL)
#define NETNS_AF_SIZE(af)       \
	(((af) == AF_INET) ? sizeof (struct in_addr) : sizeof (struct in6_addr))

/* Flags for reserve */

/* The caller is reserving a port on behalf of skywalk, but for a listener */
#define NETNS_LISTENER          0x00
/* The caller is reserving a port on behalf of skywalk. */
#define NETNS_SKYWALK           0x01
/* The caller is reserving a port on behalf of the BSD stack. */
#define NETNS_BSD               0x02
/* The caller is reserving a port on behalf of the Packet Filter (PF). */
#define NETNS_PF                0x03

#define NETNS_OWNER_MAX         NETNS_PF
#define NETNS_OWNER_MASK        0x07
/* Danger Will Robinson: This uses the above as a bitmap. */
#define NETNS_IS_SKYWALK(flags) ((flags & NETNS_BSD) == 0)

/* 0x08 is reserved */

/*
 * When passing an already-valid token to netns_reserve, behave as a no-op.
 * Used by the BSD stack which may speculatively create reservations and then
 * "finalize" them later by calling netns_reserve again.
 */
#define NETNS_PRERESERVED       0x10

#define NETNS_RESERVATION_FLAGS (NETNS_PRERESERVED | NETNS_OWNER_MASK)

/* Flags for change_flags */

/*
 * Set when the reservation backs a socket with the SO_NOWAKEFROMSLEEP option
 * set
 */
#define NETNS_NOWAKEFROMSLEEP   0x20

/* Set when the reservation backs a socket with the SO_RECV_ANYIF option set */
#define NETNS_RECVANYIF         0x40

/*
 * Set when the reservation backs a socket with the SO_EXTENDED_BK_IDLE option
 * set
 */
#define NETNS_EXTBGIDLE         0x80

#define NETNS_CONFIGURATION_FLAGS (NETNS_NOWAKEFROMSLEEP | NETNS_RECVANYIF | \
	                        NETNS_EXTBGIDLE)

#endif /* !_SKYWALK_NAMESPACE_NETNS_H_ */
