/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
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

#ifndef _IOKIT_IOKITKEYSPRIVATE_H
#define _IOKIT_IOKITKEYSPRIVATE_H

#include <IOKit/IOKitKeys.h>
#include <libkern/OSTypes.h>

// properties found in the registry root
#define kIOConsoleLockedKey                     "IOConsoleLocked"               /* value is OSBoolean */
#define kIOConsoleUsersKey                      "IOConsoleUsers"                /* value is OSArray */
#define kIOMaximumMappedIOByteCountKey          "IOMaximumMappedIOByteCount"    /* value is OSNumber */

// properties found in the console user dict
#define kIOConsoleSessionAuditIDKey             "kCGSSessionAuditIDKey"        /* value is OSNumber */

#define kIOConsoleSessionUserNameKey            "kCGSSessionUserNameKey"       /* value is OSString */
#define kIOConsoleSessionUIDKey                 "kCGSSessionUserIDKey"         /* value is OSNumber */
#define kIOConsoleSessionConsoleSetKey          "kCGSSessionConsoleSetKey"     /* value is OSNumber */
#define kIOConsoleSessionOnConsoleKey           "kCGSSessionOnConsoleKey"      /* value is OSBoolean */
#define kIOConsoleSessionLoginDoneKey           "kCGSessionLoginDoneKey"       /* value is OSBoolean */
#define kIOConsoleSessionSecureInputPIDKey      "kCGSSessionSecureInputPID"    /* value is OSNumber */
#define kIOConsoleSessionScreenLockedTimeKey    "CGSSessionScreenLockedTime"   /* value is OSNumber, secs - 1970 */
#define kIOConsoleSessionScreenIsLockedKey      "CGSSessionScreenIsLocked"     /* value is OSBoolean */

// IOResources property
#define kIOConsoleUsersSeedKey                  "IOConsoleUsersSeed"           /* value is OSNumber */

// IODeviceTree:chosen properties
#define kIOProgressBackbufferKey                "IOProgressBackbuffer"           /* value is OSData   */
#define kIOProgressColorThemeKey                "IOProgressColorTheme"           /* value is OSNumber */
#define kIOBridgeBootSessionUUIDKey             "bridge-boot-session-uuid"       /* value is OSData   */

// interest type
#define kIOConsoleSecurityInterest              "IOConsoleSecurityInterest"


// private keys for clientHasPrivilege
#define kIOClientPrivilegeConsoleUser           "console"
#define kIOClientPrivilegeSecureConsoleProcess  "secureprocess"
#define kIOClientPrivilegeConsoleSession        "consolesession"


// Embedded still throttles NVRAM commits via kIONVRAMSyncNowPropertyKey, but
// some clients still need a stricter NVRAM commit contract. Please use this with
// care.
#define kIONVRAMForceSyncNowPropertyKey         "IONVRAM-FORCESYNCNOW-PROPERTY"

// GUID to address variables for the system NVRAM region
#define kIOKitSystemGUID                        "40A0DDD2-77F8-4392-B4A3-1E7304206516"
#define kIOKitSystemGUIDPrefix                  (kIOKitSystemGUID ":")
// Internal only key to give access to system region on internal builds
#define kIONVRAMSystemInternalAllowKey          "com.apple.private.iokit.system-nvram-internal-allow"
// Internal only key to give access to hidden system region variables
#define kIONVRAMSystemHiddenAllowKey            "com.apple.private.iokit.system-nvram-hidden-allow"

// clientHasPrivilege security token for kIOClientPrivilegeSecureConsoleProcess
typedef struct _IOUCProcessToken {
	void *  token;
	UInt32  pid;
} IOUCProcessToken;

#define kIOKernelHasSafeSleep        1

#define kIOPlatformSleepActionKey                    "IOPlatformSleepAction"         /* value is OSNumber (priority) */
#define kIOPlatformWakeActionKey                     "IOPlatformWakeAction"          /* value is OSNumber (priority) */
#define kIOPlatformQuiesceActionKey                  "IOPlatformQuiesceAction"       /* value is OSNumber (priority) */
#define kIOPlatformActiveActionKey                   "IOPlatformActiveAction"        /* value is OSNumber (priority) */
#define kIOPlatformHaltRestartActionKey              "IOPlatformHaltRestartAction"   /* value is OSNumber (priority) */
#define kIOPlatformPanicActionKey                    "IOPlatformPanicAction"         /* value is OSNumber (priority) */

#define kIOPlatformFunctionHandlerSet                "IOPlatformFunctionHandlerSet"

#define kIOPlatformFunctionHandlerMaxBusDelay        "IOPlatformFunctionHandlerMaxBusDelay"
#define kIOPlatformMaxBusDelay                       "IOPlatformMaxBusDelay"

#if defined(__i386__) || defined(__x86_64__)

#define kIOPlatformFunctionHandlerMaxInterruptDelay  "IOPlatformFunctionHandlerMaxInterruptDelay"
#define kIOPlatformMaxInterruptDelay                 "IOPlatformMaxInterruptDelay"

#endif /* defined(__i386__) || defined(__x86_64__) */

enum {
	// these flags are valid for the prepare() method only
	kIODirectionPrepareNoZeroFill = 0x00000010,
};

enum {
	kIOServiceTerminateNeedWillTerminate = 0x00000100,
};

#define kIOClassNameOverrideKey "IOClassNameOverride"

enum {
	kIOClassNameOverrideNone = 0x00000001,
};

#define kIOWaitQuietPanicsEntitlement "com.apple.private.security.waitquiet-panics"
#define kIOSystemStateEntitlement "com.apple.private.iokit.systemstate"

// Entitlement allows a DK driver to publish services to other dexts, using the
// standard IOKit registerService() or DriverKit RegisterService() api.
// Those client dexts must have an entitlement specified by the
// kIODriverKitPublishEntitlementsKey property in the IOService being published,
// and subscribed in the client dext with IOServiceNotificationDispatchSource.
#define kIODriverKitAllowsPublishEntitlementsKey "com.apple.private.driverkit.allows-publish"
// Property is an array of strings containing entitlements, one of which needs to be present
// in the dext looking up the service with this property
#define kIODriverKitPublishEntitlementsKey      "IODriverKitPublishEntitlementsKey"

enum {
	kIOWaitQuietPanicOnFailure = 0x00000001,
};
#define kIOServiceBusyTimeoutExtensionsKey      "IOServiceBusyTimeoutExtensions"

#define kIOServiceLegacyMatchingRegistryIDKey "IOServiceLegacyMatchingRegistryID"

#define kIOServiceMatchDeferredKey      "IOServiceMatchDeferred"

#define kIOMatchedAtBootKey                                     "IOMatchedAtBoot"

#define kIOPrimaryDriverTerminateOptionsKey "IOPrimaryDriverTerminateOptions"

#define kIOServiceNotificationUserKey   "IOServiceNotificationUser"

#define kIOExclaveAssignedKey    "exclave-assigned"
#define kIOExclaveProxyKey       "IOExclaveProxy"


// IONVRAMSystemVariableList:
// "one-time-boot-command" - Needed for diags customer install flows
// "prevent-restores" - Keep for factory <rdar://problem/70476321>
// "sep-debug-args" - Needed to simplify debug flows for SEP
// "StartupMute" - Set by customers via nvram tool

#define IONVRAMSystemVariableList "allow-root-hash-mismatch", \
	                          "auto-boot", \
	                          "auto-boot-halt-stage", \
	                          "base-system-path", \
	                          "boot-args", \
	                          "boot-command", \
	                          "boot-image", \
	                          "bootdelay", \
	                          "com.apple.System.boot-nonce", \
	                          "darkboot", \
	                          "emu", \
	                          "one-time-boot-command", \
	                          "policy-nonce-digests", \
	                          "prevent-restores", \
	                          "prev-lang:kbd", \
	                          "root-live-fs", \
	                          "sep-debug-args", \
	                          "StartupMute", \
	                          "SystemAudioVolume", \
	                          "SystemAudioVolumeExtension", \
	                          "SystemAudioVolumeSaved"


#endif /* ! _IOKIT_IOKITKEYSPRIVATE_H */
