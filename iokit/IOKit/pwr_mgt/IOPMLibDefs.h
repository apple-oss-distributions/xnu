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


#define kPMSetAggressiveness            0
#define kPMGetAggressiveness            1
#define kPMSleepSystem                  2
#define kPMAllowPowerChange             3
#define kPMCancelPowerChange            4
#define kPMShutdownSystem               5
#define kPMRestartSystem                6
#define kPMSleepSystemOptions           7
#define kPMSetMaintenanceWakeCalendar   8
#define kPMSetUserAssertionLevels       9
#define kPMActivityTickle               10
#define kPMGetSystemSleepType           11
#define kPMSetClamshellSleepState       12
#define kPMSleepWakeWatchdogEnable      13
#define kPMSleepWakeDebugTrig           14
#define kPMSetDisplayPowerOn            15
#define kPMSetDisplayState              16
#define kPMRequestIdleSleepRevert       17

#define kNumPMMethods                   18
