/*
 * Copyright (c) 2019 Apple Inc. All rights reserved.
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
#ifndef _SKYWALK_NAMESPACE_PROTONS_H_
#define _SKYWALK_NAMESPACE_PROTONS_H_


/*
 * The protons module arbitrates IP protocol number usage across Skywalk and
 * the BSD networking stack. The IP protocol number is managed globally
 * regardless of interface or IP address.
 */

extern int protons_init(void);
extern void protons_fini(void);

/* opaque token representing a protocol namespace reservation. */
struct protons_token;

/*
 * Reserve a IP protocol number globally.
 * Reserved protocol namespace token is return via @ptp.
 */
extern int protons_reserve(struct protons_token **ptp, pid_t pid, pid_t epid,
    uint8_t proto);

/*
 * Release a IP protocol reservation recorded by the provided token.
 * *ptp will be reset to NULL after release.
 */
extern void protons_release(struct protons_token **ptp);

extern int protons_token_get_use_count(struct protons_token *pt);
extern bool protons_token_is_valid(struct protons_token *pt);
extern bool protons_token_has_matching_pid(struct protons_token *pt, pid_t pid,
    pid_t epid);

#endif /* !_SKYWALK_NAMESPACE_PROTONS_H_ */
