/*
 * Copyright (c) 2022 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 *
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */

#ifndef _KERN_LOCKDOWN_MODE_H_
#define _KERN_LOCKDOWN_MODE_H_

#include <sys/cdefs.h>
__BEGIN_DECLS

#if KERNEL_PRIVATE
/* XNU and Kernel extensions */

#if XNU_KERNEL_PRIVATE

// Whether Lockdown Mode is enabled via the "ldm" nvram variable
extern int lockdown_mode_state;

/**
 * Initalizes Lockdown Mode
 */
void lockdown_mode_init(void);

#endif /* XNU_KERNEL_PRIVATE */

/**
 * Returns the Lockdown Mode enablement state
 */
int get_lockdown_mode_state(void);

/**
 * Enable Lockdown Mode by setting the nvram variable
 */
void enable_lockdown_mode(void);

/**
 * Disable Lockdown Mode by setting the nvram variable
 */
void disable_lockdown_mode(void);

#endif /* KERNEL_PRIVATE */
__END_DECLS

#endif /* _KERN_LOCKDOWN_MODE_H_ */
