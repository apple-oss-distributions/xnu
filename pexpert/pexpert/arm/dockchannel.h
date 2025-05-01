/*
 * Copyright (c) 2024 Apple Inc. All rights reserved.
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
#ifndef _PEXPERT_ARM_DOCKCHANNEL_H
#define _PEXPERT_ARM_DOCKCHANNEL_H

#define DOCKCHANNEL_UART                        (1)
#define DOCKCHANNEL_STRIDE                      (0x10000)

// Channel index
#define DOCKCHANNEL_UART_CHANNEL                (0)

/* Dock Agent Interrupt Control Register */
#define rDOCKCHANNELS_AGENT_AP_INTR_CTRL(_agent_base)        ((uintptr_t) ((_agent_base) + 0x00))

/* When this bit is set, the write watermark interrupt of Dock Channel 0 on the device side is enabled */
#define DC0_WR_DEVICE_EN        (1U << 0)
/* When this bit is set, the read watermark interrupt of Dock Channel 0 on the device side is enabled */
#define DC0_RD_DEVICE_EN        (1U << 1)

/* Dock Agent Interrupt Status Register */
#define rDOCKCHANNELS_AGENT_AP_INTR_STATUS(_agent_base)      ((uintptr_t) ((_agent_base) + 0x04))

/**
 * This bit is set when the write watermark interrupt of Dock Channel 0 on the device side is
 * asserted. This bit remains set until cleared by SW by writing a 1.
 */
#define DC0_WR_DEVICE_STAT      (1U << 0)
/**
 * This bit is set when the read watermark interrupt of Dock Channel 0 on the device side is
 * asserted. This bit remains set until cleared by SW by writing a 1.
 */
#define DC0_RD_DEVICE_STAT      (1U << 1)

/* Dock Agent Error Interrupt Control Register */
#define rDOCKCHANNELS_AGENT_AP_ERR_INTR_CTRL(_agent_base)    ((uintptr_t) ((_agent_base) + 0x08))

/* When this bit is set, the error interrupt of Dock Channel 0 on the device side is enabled */
#define DC0_ERROR_DEVICE_EN     (1U << 0)
/* When this bit is set, the error interrupt of Dock Channel 0 on the dock side is enabled */
#define DC0_ERROR_DOCK_EN       (1U << 1)

/* Dock Agent Error Interrupt Status Register */
#define rDOCKCHANNELS_AGENT_AP_ERR_INTR_STATUS(_agent_base)  ((uintptr_t) ((_agent_base) + 0x0c))
/**
 * This bit is set when the error interrupt of Dock Channel 0 on the device side is asserted.
 * This bit remains set until cleared by SW by writing a 1.
 */
#define DC0_ERR_DEVICE_STAT     (1U << 0)
/**
 * This bit is set when the error interrupt of Dock Channel 0 on the dock side is asserted.
 * This bit remains set until cleared by SW by writing a 1.
 */
#define DC0_ERR_DOCK_STAT       (1U << 1)

#define rDOCKCHANNELS_DEV_WR_WATERMARK(_base, _ch)     ((uintptr_t) ((_base) + ((_ch) * DOCKCHANNEL_STRIDE) + 0x0000))
#define rDOCKCHANNELS_DEV_RD_WATERMARK(_base, _ch)     ((uintptr_t) ((_base) + ((_ch) * DOCKCHANNEL_STRIDE) + 0x0004))
#define rDOCKCHANNELS_DEV_DRAIN_CFG(_base, _ch)        ((uintptr_t) ((_base) + ((_ch) * DOCKCHANNEL_STRIDE) + 0x0008))

#define rDOCKCHANNELS_DEV_WDATA1(_base, _ch)           ((uintptr_t) ((_base) + ((_ch) * DOCKCHANNEL_STRIDE) + 0x4004))
#define rDOCKCHANNELS_DEV_WSTAT(_base, _ch)            ((uintptr_t) ((_base) + ((_ch) * DOCKCHANNEL_STRIDE) + 0x4014))
#define rDOCKCHANNELS_DEV_RDATA0(_base, _ch)           ((uintptr_t) ((_base) + ((_ch) * DOCKCHANNEL_STRIDE) + 0x4018))
#define rDOCKCHANNELS_DEV_RDATA1(_base, _ch)           ((uintptr_t) ((_base) + ((_ch) * DOCKCHANNEL_STRIDE) + 0x401c))

#define rDOCKCHANNELS_DOCK_RDATA1(_base, _ch)          ((uintptr_t) ((_base) + ((_ch) * DOCKCHANNEL_STRIDE) + 0xc01c))
#define rDOCKCHANNELS_DOCK_RDATA3(_base, _ch)          ((uintptr_t) ((_base) + ((_ch) * DOCKCHANNEL_STRIDE) + 0xc024))

#endif  /* !_PEXPERT_ARM_DOCKCHANNEL_H */
