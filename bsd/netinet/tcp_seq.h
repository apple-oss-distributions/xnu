/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
 * Copyright (c) 1982, 1986, 1993, 1995
 *	The Regents of the University of California.  All rights reserved.
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
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
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
 *	@(#)tcp_seq.h	8.3 (Berkeley) 6/21/95
 * $FreeBSD: src/sys/netinet/tcp_seq.h,v 1.11.2.5 2001/08/22 00:59:12 silby Exp $
 */

#ifndef _NETINET_TCP_SEQ_H_
#define _NETINET_TCP_SEQ_H_
#include <sys/appleapiopts.h>
/*
 * TCP sequence numbers are 32 bit integers operated
 * on with modular arithmetic.  These macros can be
 * used to compare such integers.
 */
#define SEQ_LT(a, b)     ((int)((a)-(b)) < 0)
#define SEQ_LEQ(a, b)    ((int)((a)-(b)) <= 0)
#define SEQ_GT(a, b)     ((int)((a)-(b)) > 0)
#define SEQ_GEQ(a, b)    ((int)((a)-(b)) >= 0)

#define SEQ_MIN(a, b)   ((SEQ_LT(a, b)) ? (a) : (b))
#define SEQ_MAX(a, b)   ((SEQ_GT(a, b)) ? (a) : (b))

/* for modulo comparisons of timestamps */
#define TSTMP_LT(a, b)   ((int)((a)-(b)) < 0)
#define TSTMP_GT(a, b)   ((int)((a)-(b)) > 0)
#define TSTMP_LEQ(a, b)  ((int)((a)-(b)) <= 0)
#define TSTMP_GEQ(a, b)  ((int)((a)-(b)) >= 0)

/*
 * TCP connection counts are 32 bit integers operated
 * on with modular arithmetic.  These macros can be
 * used to compare such integers.
 */
#define CC_LT(a, b)      ((int)((a)-(b)) < 0)
#define CC_LEQ(a, b)     ((int)((a)-(b)) <= 0)
#define CC_GT(a, b)      ((int)((a)-(b)) > 0)
#define CC_GEQ(a, b)     ((int)((a)-(b)) >= 0)

/* Macro to increment a CC: skip 0 which has a special meaning */
#define CC_INC(c)       (++(c) == 0 ? ++(c) : (c))

#ifdef KERNEL_PRIVATE
/*
 * Macros to initialize tcp sequence numbers for
 * send and receive from initial send and receive
 * sequence numbers.
 */
#define tcp_rcvseqinit(tp) \
	(tp)->rcv_adv = (tp)->rcv_nxt = (tp)->rcv_high = (tp)->irs + 1

#define tcp_sendseqinit(tp) \
	(tp)->snd_una = (tp)->snd_nxt = (tp)->snd_max = (tp)->snd_up = \
	(tp)->snd_recover = (tp)->iss

#define TCP_PAWS_IDLE   (24 * 24 * 60 * 60 * TCP_RETRANSHZ)
/* timestamp wrap-around time */
#endif /* KERNEL_PRIVATE */
#endif /* _NETINET_TCP_SEQ_H_ */
