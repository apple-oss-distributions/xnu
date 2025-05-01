/*
 * Copyright (c) 2024 Apple Computer, Inc. All rights reserved.
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

#ifndef _PEXPERT_ARM64_APT_MSG_H
#define _PEXPERT_ARM64_APT_MSG_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <stdint.h>

#define APT_MSG_NS_KERN 0
#define APT_MSG_KERN_CSWITCH_TIME 0

void apt_msg_init(void);
uint8_t apt_msg_policy(void);
void apt_msg_init_cpu(void);
void apt_msg_emit(int ns, int type, int num_payloads, uint64_t *payloads);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* _PEXPERT_ARM64_APT_MSG_H */
