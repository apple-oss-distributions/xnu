/*
 * Copyright (c) 2022-2025 Apple Inc. All rights reserved.
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

#include <sys/param.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>

#include <netinet/in_var.h>
#include <netinet/inp_log.h>

SYSCTL_NODE(_net_inet_ip, OID_AUTO, log, CTLFLAG_RW | CTLFLAG_LOCKED, 0,
    "TCP/IP + UDP logs");

#if (DEVELOPMENT || DEBUG)
#define INP_LOG_PRIVACY_DEFAULT 0
#else
#define INP_LOG_PRIVACY_DEFAULT 1
#endif /* (DEVELOPMENT || DEBUG) */

int inp_log_privacy = INP_LOG_PRIVACY_DEFAULT;
SYSCTL_INT(_net_inet_ip_log, OID_AUTO, privacy,
    CTLFLAG_RW | CTLFLAG_LOCKED, &inp_log_privacy, 0, "");

struct inp_log_args {
	struct inpcb *inp;
	struct socket *so;
	struct ifnet *ifp;
	struct sockaddr *from;
	struct sockaddr *to;
	in_port_t local_port;
	in_port_t foreign_port;
};

#define INP_LOG_COMMON_FMT \
	"[%s:%u<->%s:%u] " \
	"interface: %s \n"

#define INP_LOG_COMMON_ARGS(inp_log_args, laddr_buf, faddr_buf) \
	laddr_buf, ntohs(inp_log_args.local_port), faddr_buf, ntohs(inp_log_args.foreign_port), \
	inp_log_args.ifp != NULL ? if_name(inp_log_args.ifp) : ""

#define INP_LOG_COMMON_PCB_FMT \
	INP_LOG_COMMON_FMT \
	"so_gencnt: %llu " \
	"so_state: 0x%04x " \
	"process: %s:%u "

#define INP_LOG_COMMON_PCB_ARGS(inp_log_args, laddr_buf, faddr_buf) \
	INP_LOG_COMMON_ARGS(inp_log_args, laddr_buf, faddr_buf), \
	inp_log_args.so != NULL ? inp_log_args.so->so_gencnt : 0, \
	inp_log_args.so != NULL ? inp_log_args.so->so_state : 0, \
	inp_log_args.inp->inp_last_proc_name, inp_log_args.so != NULL ? inp_log_args.so->last_pid : 0

os_log_t inp_log_handle = OS_LOG_DEFAULT;

void
inp_log_init(void)
{
	static bool inp_log_initialized = false;

	if (inp_log_initialized == false) {
		inp_log_initialized = true;
		inp_log_handle = os_log_create("com.apple.xnu.net.inp", "");
	}
}

static void
fill_inp_log_args(struct inpcb *inp, struct sockaddr *from, struct sockaddr *to,
    struct inp_log_args *inp_log_args)
{
	inp_log_args->inp = inp;
	inp_log_args->so = inp->inp_socket;

	inp_log_args->local_port = inp->inp_lport;
	inp_log_args->foreign_port = inp->inp_fport;

	inp_log_args->ifp = inp->inp_last_outifp != NULL ? inp->inp_last_outifp :
	    inp->inp_boundifp != NULL ? inp->inp_boundifp : NULL;

	inp_log_args->from = from;
	if (from != NULL) {
		if (from->sa_family == AF_INET) {
			inp_log_args->local_port = SIN(from)->sin_port;
		} else if (from->sa_family == AF_INET6) {
			inp_log_args->local_port = SIN6(from)->sin6_port;
		}
	}
	inp_log_args->to = to;
	if (to != NULL) {
		if (to->sa_family == AF_INET) {
			inp_log_args->foreign_port = SIN(to)->sin_port;
		} else if (to->sa_family == AF_INET6) {
			inp_log_args->foreign_port = SIN6(to)->sin6_port;
		}
	}
}

static void
inp_log_addresses_common(struct inp_log_args *inp_log_args, char *__sized_by(lbuflen) lbuf,
    socklen_t lbuflen, char *__sized_by(fbuflen) fbuf,
    socklen_t fbuflen)
{
	/*
	 * Ugly but %{private} does not work in the kernel version of os_log()
	 */
	if (inp_log_privacy != 0) {
		if (inp_log_args->inp->inp_vflag & INP_IPV6) {
			strlcpy(lbuf, "<IPv6-redacted>", lbuflen);
			strlcpy(fbuf, "<IPv6-redacted>", fbuflen);
		} else {
			strlcpy(lbuf, "<IPv4-redacted>", lbuflen);
			strlcpy(fbuf, "<IPv4-redacted>", fbuflen);
		}
	} else if (inp_log_args->inp->inp_vflag & INP_IPV6) {
		struct in6_addr addr6;

		if (inp_log_args->from != NULL && inp_log_args->from->sa_family == AF_INET6) {
			memcpy(&addr6, &SIN6(inp_log_args->from)->sin6_addr, sizeof(struct in6_addr));
		} else {
			addr6 = inp_log_args->inp->in6p_laddr;
		}
		if (IN6_IS_ADDR_LINKLOCAL(&addr6)) {
			addr6.s6_addr16[1] = 0;
		}
		inet_ntop(AF_INET6, (void *)&addr6, lbuf, lbuflen);

		if (inp_log_args->to != NULL && inp_log_args->to->sa_family == AF_INET6) {
			memcpy(&addr6, &SIN6(inp_log_args->to)->sin6_addr, sizeof(struct in6_addr));
		} else {
			addr6 = inp_log_args->inp->in6p_faddr;
		}
		if (IN6_IS_ADDR_LINKLOCAL(&addr6)) {
			addr6.s6_addr16[1] = 0;
		}
		inet_ntop(AF_INET6, (void *)&addr6, fbuf, fbuflen);
	} else {
		inet_ntop(AF_INET, (void *)&inp_log_args->inp->inp_laddr.s_addr, lbuf, lbuflen);
		inet_ntop(AF_INET, (void *)&inp_log_args->inp->inp_faddr.s_addr, fbuf, fbuflen);
	}
}

void
inp_log_addresses(struct inpcb *inp, char *__sized_by(lbuflen) lbuf,
    socklen_t lbuflen, char *__sized_by(fbuflen) fbuf,
    socklen_t fbuflen)
{
	struct inp_log_args inp_log_args;

	fill_inp_log_args(inp, NULL, NULL, &inp_log_args);

	inp_log_addresses_common(&inp_log_args, lbuf, lbuflen, fbuf, fbuflen);
}

int
sysctl_inp_log_port SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int error;
	int new_value = *(unsigned int *)oidp->oid_arg1;

	error = sysctl_handle_int(oidp, &new_value, 0, req);
	if (error != 0 || req->newptr == USER_ADDR_NULL) {
		return error;
	}
	if (new_value < 0 || new_value > UINT16_MAX) {
		return EINVAL;
	}
	*(unsigned int *)oidp->oid_arg1 = new_value;
	return 0;
}

__attribute__((noinline))
void
inp_log_message(const char *func_name, int line_no,
    struct inpcb *inp, struct sockaddr *from, struct sockaddr *to,
    const char *format, ...)
{
	struct inp_log_args inp_log_args;
	char message[128];
	char proto_str[12];
	char laddr_buf[ADDRESS_STR_LEN];
	char faddr_buf[ADDRESS_STR_LEN];
	__single os_log_t log_handle = OS_LOG_DEFAULT;

	if (inp == NULL || inp->inp_socket == NULL) {
		return;
	}

	switch (SOCK_PROTO(inp->inp_socket)) {
	case IPPROTO_TCP:
		log_handle = tcp_log_handle;
		strbufcpy(proto_str, "tcp");
		break;
	case IPPROTO_UDP:
		log_handle = udp_log_handle;
		strbufcpy(proto_str, "udp");
		break;
	default:
		log_handle = inp_log_handle;
		snprintf(proto_str, sizeof(proto_str), "proto %u", SOCK_PROTO(inp->inp_socket));
	}

	fill_inp_log_args(inp, from, to, &inp_log_args);
	inp_log_addresses_common(&inp_log_args, laddr_buf, sizeof(laddr_buf), faddr_buf, sizeof(faddr_buf));

	va_list ap;
	va_start(ap, format);
	vsnprintf(message, sizeof(message), format, ap);
	va_end(ap);

#define INP_LOG_MESSAGE_FMT \
	    "%s (%s:%d): " \
	    INP_LOG_COMMON_PCB_FMT \
	    "%s"

#define INP_LOG_MESSAGE_ARGS(inp_log_args, laddr_buf, faddr_buf) \
	    proto_str, func_name, line_no, \
	    INP_LOG_COMMON_PCB_ARGS(inp_log_args, laddr_buf, faddr_buf), \
	    message

	os_log(log_handle, INP_LOG_MESSAGE_FMT,
	    INP_LOG_MESSAGE_ARGS(inp_log_args, laddr_buf, faddr_buf));

#undef INP_LOG_MESSAGE_FMT
#undef INP_LOG_MESSAGE_ARGS
}

__attribute__((noinline))
void
inp_log_pair_message(const char *func_name, int line_no,
    struct inpcb *inp1, struct sockaddr *from, struct sockaddr *to,
    struct inpcb *inp2, const char *format, ...)
{
	struct inp_log_args inp_log_args1;
	struct inp_log_args inp_log_args2;
	char message[128];
	char laddr_buf1[ADDRESS_STR_LEN];
	char faddr_buf1[ADDRESS_STR_LEN];
	char laddr_buf2[ADDRESS_STR_LEN];
	char faddr_buf2[ADDRESS_STR_LEN];
	char proto_str[12];
	__single os_log_t log_handle = OS_LOG_DEFAULT;

	if (inp1 == NULL || inp1->inp_socket == NULL) {
		return;
	}
	if (inp2 == NULL || inp2->inp_socket == NULL) {
		return;
	}

	assert3u(SOCK_PROTO(inp1->inp_socket), ==, SOCK_PROTO(inp2->inp_socket));

	switch (SOCK_PROTO(inp1->inp_socket)) {
	case IPPROTO_TCP:
		log_handle = tcp_log_handle;
		strbufcpy(proto_str, "tcp");
		break;
	case IPPROTO_UDP:
		log_handle = udp_log_handle;
		strbufcpy(proto_str, "udp");
		break;
	default:
		log_handle = inp_log_handle;
		snprintf(proto_str, sizeof(proto_str), "proto %u", SOCK_PROTO(inp1->inp_socket));
	}

	fill_inp_log_args(inp1, from, to, &inp_log_args1);
	inp_log_addresses_common(&inp_log_args1, laddr_buf1, sizeof(laddr_buf1), faddr_buf1, sizeof(faddr_buf1));

	fill_inp_log_args(inp2, NULL, NULL, &inp_log_args2);
	inp_log_addresses_common(&inp_log_args2, laddr_buf2, sizeof(laddr_buf2), faddr_buf2, sizeof(faddr_buf2));

	va_list ap;
	va_start(ap, format);
	vsnprintf(message, sizeof(message), format, ap);
	va_end(ap);

#define INP_LOG_MESSAGE_FMT \
	    "%s (%s:%d): " \
	    INP_LOG_COMMON_PCB_FMT \
	    "%s\n" \
	    INP_LOG_COMMON_PCB_FMT

#define INP_LOG_MESSAGE_ARGS(inp_log_args1, laddr_buf1, faddr_buf1, inp_log_args2, laddr_buf2, faddr_buf2) \
	    proto_str, func_name, line_no, \
	    INP_LOG_COMMON_PCB_ARGS(inp_log_args1, laddr_buf1, faddr_buf1), \
	    message, \
	    INP_LOG_COMMON_PCB_ARGS(inp_log_args2, laddr_buf2, faddr_buf2)

	os_log(log_handle, INP_LOG_MESSAGE_FMT,
	    INP_LOG_MESSAGE_ARGS(inp_log_args1, laddr_buf1, faddr_buf1, inp_log_args2, laddr_buf2, faddr_buf2));

#undef INP_LOG_MESSAGE_FMT
#undef INP_LOG_MESSAGE_ARGS
}
