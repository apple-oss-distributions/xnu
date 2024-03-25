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

#include <libkern/libkern.h>
#include <sys/sysctl.h>
#include <sys/lockdown_mode.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IOKitKeysPrivate.h>

static const char * kLockdownModeNVRAMVariableKey = kIOKitSystemGUID ":ldm";

#pragma mark Initialization

static LCK_GRP_DECLARE(lockdown_mode_init_lck_grp, "lockdown_mode_init_lock");
static LCK_MTX_DECLARE(lockdown_mode_init_mtx, &lockdown_mode_init_lck_grp);

static int lockdown_mode_init_done = 0;

int lockdown_mode_state = 0;

SYSCTL_DECL(_security_mac);
SYSCTL_INT(_security_mac, OID_AUTO, lockdown_mode_state, CTLFLAG_RD | CTLFLAG_LOCKED, &lockdown_mode_state, 0, "Lockdown Mode state");

__startup_func
void
lockdown_mode_init(void)
{
	if (!PEReadNVRAMBooleanProperty(kLockdownModeNVRAMVariableKey, &lockdown_mode_state)) {
		printf("lockdown_mode: error getting state from nvram\n");
	}
	printf("lockdown_mode: lockdown mode in nvram is %s\n", lockdown_mode_state ? "on" : "off");

	lck_mtx_lock(&lockdown_mode_init_mtx);
	lockdown_mode_init_done = 1;
	wakeup(&lockdown_mode_init_done);
	lck_mtx_unlock(&lockdown_mode_init_mtx);
}

#if defined (__i386__) || defined (__x86_64__)
extern boolean_t IOServiceWaitForMatchingResource( const char * property, uint64_t timeout );

__startup_func
static void
lockdown_mode_init_async_thread(void)
{
	if (!IOServiceWaitForMatchingResource("IONVRAM", UINT64_MAX)) {
		panic("lockdown_mode: error acquiring nvram service");
	}
	lockdown_mode_init();
}

__startup_func
static void
lockdown_mode_init_async(void)
{
	thread_t thread;
	kern_return_t ret = kernel_thread_start((thread_continue_t)lockdown_mode_init_async_thread, 0, &thread);
	if (ret == KERN_SUCCESS) {
		thread_deallocate(thread);
	}
}
STARTUP(EARLY_BOOT, STARTUP_RANK_LAST, lockdown_mode_init_async);
#else
STARTUP(EARLY_BOOT, STARTUP_RANK_LAST, lockdown_mode_init);
#endif

int
get_lockdown_mode_state(void)
{
	lck_mtx_lock(&lockdown_mode_init_mtx);
	if (!lockdown_mode_init_done) {
		msleep(&lockdown_mode_init_done, &lockdown_mode_init_mtx, 0, "get_lockdown_mode_state", NULL);
	}
	lck_mtx_unlock(&lockdown_mode_init_mtx);


	return lockdown_mode_state;
}

void
enable_lockdown_mode(void)
{
	lockdown_mode_state = 1;
	PEWriteNVRAMBooleanProperty(kLockdownModeNVRAMVariableKey, TRUE);
}

void
disable_lockdown_mode(void)
{
	lockdown_mode_state = 0;
	PERemoveNVRAMProperty(kLockdownModeNVRAMVariableKey);
}
