/*
 * Copyright (c) 2021, 2025 Apple Inc. All rights reserved.
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

#pragma once

/* Function Identifiers. */
#define HVC_FID_FAST_CALL            0x80000000
#define HVC_FID_HVC64                0x40000000
#define HVC_FID_CPU                  0x01000000
#define HVC_FID_OEM                  0x03000000
/* Defined in ARM DEN 0028F */
#define HVC_FID_HYPERVISOR_VENDOR    0x06000000

#define HVC_FID_SC_MASK      0xff000000
#define HVC_FID_NUM_MASK     0x0000ffff

#define HVC_FID_UID          0xff01
#define HVC_FID_REVISION     0xff03
#define HVC_FID_FEATURES     0xfeff

#define HVC32_FI(rng, num) (HVC_FID_FAST_CALL | (rng) | (num))

/* CPU */
#define HVC_CPU_SERVICE    (HVC_FID_FAST_CALL | HVC_FID_HVC64 | HVC_FID_CPU)
#define HVC32_CPU_SERVICE  (HVC_FID_FAST_CALL | HVC_FID_CPU)

/* Apple CPU Service */
#define VMAPPLE_PAC_SET_INITIAL_STATE          (HVC_CPU_SERVICE | 0x0)
#define VMAPPLE_PAC_GET_DEFAULT_KEYS           (HVC_CPU_SERVICE | 0x1)
#define VMAPPLE_PAC_SET_A_KEYS                 (HVC_CPU_SERVICE | 0x2)
#define VMAPPLE_PAC_SET_B_KEYS                 (HVC_CPU_SERVICE | 0x3)
#define VMAPPLE_PAC_SET_EL0_DIVERSIFIER        (HVC_CPU_SERVICE | 0x4)
#define VMAPPLE_PAC_SET_EL0_DIVERSIFIER_AT_EL1 (HVC_CPU_SERVICE | 0x5)
#define VMAPPLE_PAC_SET_G_KEY                  (HVC_CPU_SERVICE | 0x6)
#define VMAPPLE_PAC_NOP                        (HVC_CPU_SERVICE | 0xf0)

/* OEM */
#define HVC_OEM_SERVICE    (HVC_FID_FAST_CALL | HVC_FID_HVC64 | HVC_FID_OEM)
#define HVC32_OEM_SERVICE  (HVC_FID_FAST_CALL | HVC_FID_OEM)

/* Apple OEM Service */
#define VMAPPLE_GET_MABS_OFFSET                (HVC_OEM_SERVICE | 0x3)
#define VMAPPLE_GET_BOOTSESSIONUUID            (HVC_OEM_SERVICE | 0x4)
#define VMAPPLE_VCPU_WFK                       (HVC_OEM_SERVICE | 0x5)
#define VMAPPLE_VCPU_KICK                      (HVC_OEM_SERVICE | 0x6)

/* Apple OEM Version 1.0 */
#define HVC32_OEM_MAJOR_VER 1
#define HVC32_OEM_MINOR_VER 0

/* Common UUID identifying Apple as the implementor. */
#define VMAPPLE_HVC_UID "3B878185-AA62-4E1F-9DC9-D6799CBB6EBB"

/* Apple Para-nested Hypervisor Service */
#define HVC_NESTED_SERVICE    (HVC_FID_FAST_CALL | HVC_FID_HVC64 | HVC_FID_HYPERVISOR_VENDOR)

/* Maximum number of nested services. Power of 2 */
#define USER_PARAVIRTUALIZED_NESTED_SERVICE_COUNT (1<<4)
#define KERNEL_PARAVIRTUALIZED_NESTED_SERVICE_COUNT (1<<5)
// User originated calls
#define VMAPPLE_NESTED_CAPABILITIES    (HVC_NESTED_SERVICE | 0x0)

// Kernel originated calls
#define VMAPPLE_NESTED_VCPU_RUN        (HVC_NESTED_SERVICE | 0x10)
#define VMAPPLE_NESTED_VCPU_INIT       (HVC_NESTED_SERVICE | 0x11)
#define VMAPPLE_NESTED_VCPU_DESTROY    (HVC_NESTED_SERVICE | 0x12)
#define VMAPPLE_NESTED_VCPU_RUN_CANCEL (HVC_NESTED_SERVICE | 0x13)
#define VMAPPLE_NESTED_VM_INIT         (HVC_NESTED_SERVICE | 0x14)
#define VMAPPLE_NESTED_SPACE_MAP       (HVC_NESTED_SERVICE | 0x15)
#define VMAPPLE_NESTED_SPACE_UNMAP     (HVC_NESTED_SERVICE | 0x16)
#define VMAPPLE_NESTED_SPACE_PROTECT   (HVC_NESTED_SERVICE | 0x17)
#define VMAPPLE_NESTED_VM_DESTROY      (HVC_NESTED_SERVICE | 0x18)
#define VMAPPLE_NESTED_INIT            (HVC_NESTED_SERVICE | 0x19)
#define VMAPPLE_NESTED_CONTEXT_VERSION (HVC_NESTED_SERVICE | 0x1A)
