/*
 * Copyright (c) 2022-2024 Apple Inc. All rights reserved.
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

#ifndef _NETINET_INP_LOG_H_
#define _NETINET_INP_LOG_H_

#ifdef BSD_KERNEL_PRIVATE

#include <sys/sysctl.h>

#include <netinet/in_pcb.h>

#include <os/log.h>

#define ADDRESS_STR_LEN (MAX_IPv6_STR_LEN + 6)

extern int sysctl_inp_log_port SYSCTL_HANDLER_ARGS;

extern int inp_log_privacy;

extern os_log_t inp_log_handle;
extern os_log_t tcp_log_handle;
extern os_log_t udp_log_handle;

extern void inp_log_init(void);

extern void inp_log_addresses(struct inpcb *inp, char *__sized_by(lbuflen) lbuf,
    socklen_t lbuflen, char *__sized_by(fbuflen) fbuf,
    socklen_t fbuflen);

extern void inp_log_message(const char *func_name, int line_no,
    struct inpcb *inp, struct sockaddr *from, struct sockaddr *to,
    const char *format, ...) __printflike(6, 7);

void inp_log_pair_message(const char *func_name, int line_no,
    struct inpcb *inp1, struct sockaddr *from, struct sockaddr *to,
    struct inpcb *inp2, const char *format, ...) __printflike(7, 8);

#define INP_LOG(inp, from, to, format, ...) \
    inp_log_message(__func__, __LINE__, (inp), (from), (to), format, ## __VA_ARGS__)

#define INP_LOG_PAIR(inp1, from, to, inp2, format, ...) \
    inp_log_pair_message(__func__, __LINE__, (inp1), (from), (to), (inp2), format, ## __VA_ARGS__)

#endif /* BSD_KERNEL_PRIVATE */

#endif /* _NETINET_INP_LOG_H_ */
