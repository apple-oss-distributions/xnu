/*
 * Copyright (c) 2023 Apple Inc. All rights reserved.
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

#if CONFIG_EXCLAVES

#if __has_include(<Tightbeam/tightbeam.h>)

#include <stdint.h>

#include <Tightbeam/tightbeam.h>
#include <Tightbeam/tightbeam_private.h>

#include "kern/exclaves.tightbeam.h"

__BEGIN_DECLS

extern tb_error_t
    exclaves_driverkit_upcall_irq_register(const uint64_t id, const int32_t index,
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_irq_register__result_s));

extern tb_error_t
    exclaves_driverkit_upcall_irq_remove(const uint64_t id, const int32_t index,
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_irq_remove__result_s));

extern tb_error_t
    exclaves_driverkit_upcall_irq_enable(const uint64_t id, const int32_t index,
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_irq_enable__result_s));

extern tb_error_t
    exclaves_driverkit_upcall_irq_disable(const uint64_t id, const int32_t index,
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_irq_disable__result_s));

extern tb_error_t
    exclaves_driverkit_upcall_timer_register(const uint64_t id,
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_timer_register__result_s));

extern tb_error_t
    exclaves_driverkit_upcall_timer_remove(const uint64_t id, const uint32_t timer_id,
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_timer_remove__result_s));

extern tb_error_t
    exclaves_driverkit_upcall_timer_enable(const uint64_t id, const uint32_t timer_id,
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_timer_enable__result_s));

extern tb_error_t
    exclaves_driverkit_upcall_timer_disable(const uint64_t id, const uint32_t timer_id,
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_timer_disable__result_s));

extern tb_error_t
    exclaves_driverkit_upcall_timer_set_timeout(const uint64_t id,
    const uint32_t timer_id,
    const struct xnuupcalls_drivertimerspecification_s *duration,
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_timer_set_timeout__result_s));

extern tb_error_t
    exclaves_driverkit_upcall_timer_cancel_timeout(const uint64_t id,
    const uint32_t timer_id,
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_timer_cancel_timeout__result_s));

extern tb_error_t
    exclaves_driverkit_upcall_lock_wl(const uint64_t id,
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_lock_wl__result_s));

extern tb_error_t
    exclaves_driverkit_upcall_unlock_wl(const uint64_t id,
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_unlock_wl__result_s));

extern tb_error_t
    exclaves_driverkit_upcall_async_notification_signal(const uint64_t id,
    const uint32_t notificationID,
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_async_notification_signal__result_s));

extern tb_error_t
    exclaves_driverkit_upcall_mapper_activate(const uint64_t id,
    const uint32_t mapperIndex,
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_mapper_activate__result_s));

extern tb_error_t
    exclaves_driverkit_upcall_mapper_deactivate(const uint64_t id,
    const uint32_t mapperIndex,
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_mapper_deactivate__result_s));

extern tb_error_t
    exclaves_driverkit_upcall_notification_signal(const uint64_t id,
    const uint32_t mask,
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_notification_signal__result_s));

extern tb_error_t
    exclaves_driverkit_upcall_ane_setpowerstate(const uint64_t id,
    const uint32_t desiredState,
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_ane_setpowerstate__result_s));

extern tb_error_t
    exclaves_driverkit_upcall_ane_worksubmit(const uint64_t id, const uint64_t requestID,
    const uint32_t taskDescriptorCount, const uint64_t submitTimestamp,
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_ane_worksubmit__result_s));

extern tb_error_t
    exclaves_driverkit_upcall_ane_workbegin(const uint64_t id, const uint64_t requestID,
    const uint64_t beginTimestamp,
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_ane_workbegin__result_s));

extern tb_error_t
    exclaves_driverkit_upcall_ane_workend(const uint64_t id, const uint64_t requestID,
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_ane_workend__result_s));

__END_DECLS

#endif /* __has_include(<Tightbeam/tightbeam.h>) */

#endif /* CONFIG_EXCLAVES */
