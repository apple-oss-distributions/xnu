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

#if CONFIG_EXCLAVES

#if __has_include(<Tightbeam/tightbeam.h>)

#include <stdint.h>

#include <Tightbeam/tightbeam.h>
#include <Tightbeam/tightbeam_private.h>

#include <Exclaves/Exclaves.h>
#include <IOKit/IOTypes.h>
#include <mach/exclaves.h>
#include <kern/startup.h>
#include <stdint.h>
#include <kern/startup.h>

#include "kern/exclaves.tightbeam.h"
#include "exclaves_debug.h"
#include "exclaves_driverkit.h"
#include "exclaves_resource.h"

/* Registry ID of service being used in HelloDriverInterrupts */
static uint64_t exclaves_hello_driverkit_interrupts_service_id = -1ull;


/* -------------------------------------------------------------------------- */
#pragma mark Upcalls

tb_error_t
exclaves_driverkit_upcall_irq_register(const uint64_t id, const int32_t index,
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_irq_register__result_s))
{
	exclaves_debug_printf(show_iokit_upcalls,
	    "[iokit_upcalls] register_irq %d from id %llu \n", index, id);
	struct IOExclaveInterruptUpcallArgs args;
	args.index = index;
	args.type = kIOExclaveInterruptUpcallTypeRegister;
	// If upcall is from HelloDriverInterrupts test, create detached IOIES
	args.data.register_args.test_irq =
	    (id == exclaves_hello_driverkit_interrupts_service_id);

	xnuupcalls_xnuupcalls_irq_register__result_s result = {};
	if (!IOExclaveInterruptUpcallHandler(id, &args)) {
		xnuupcalls_xnuupcalls_irq_register__result_init_failure(&result,
		    XNUUPCALLS_DRIVERUPCALLERROR_FAILURE);
	} else {
		xnuupcalls_xnuupcalls_irq_register__result_init_success(&result);
	}

	return completion(result);
}

tb_error_t
exclaves_driverkit_upcall_irq_remove(const uint64_t id, const int32_t index,
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_irq_remove__result_s))
{
	exclaves_debug_printf(show_iokit_upcalls,
	    "[iokit_upcalls] remove_irq %d from id %llu \n", index, id);
	struct IOExclaveInterruptUpcallArgs args;
	args.index = index;
	args.type = kIOExclaveInterruptUpcallTypeRemove;

	xnuupcalls_xnuupcalls_irq_remove__result_s result = {};
	if (!IOExclaveInterruptUpcallHandler(id, &args)) {
		xnuupcalls_xnuupcalls_irq_remove__result_init_failure(&result,
		    XNUUPCALLS_DRIVERUPCALLERROR_FAILURE);
	} else {
		xnuupcalls_xnuupcalls_irq_remove__result_init_success(&result);
	}

	return completion(result);
}


tb_error_t
exclaves_driverkit_upcall_irq_enable(const uint64_t id, const int32_t index,
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_irq_enable__result_s))
{
	exclaves_debug_printf(show_iokit_upcalls,
	    "[iokit_upcalls] enable_irq %d from id %llu \n", index, id);
	struct IOExclaveInterruptUpcallArgs args;
	args.index = index;
	args.type = kIOExclaveInterruptUpcallTypeEnable;
	args.data.enable_args.enable = true;

	xnuupcalls_xnuupcalls_irq_enable__result_s result = {};
	if (!IOExclaveInterruptUpcallHandler(id, &args)) {
		xnuupcalls_xnuupcalls_irq_enable__result_init_failure(&result,
		    XNUUPCALLS_DRIVERUPCALLERROR_FAILURE);
	} else {
		xnuupcalls_xnuupcalls_irq_enable__result_init_success(&result);
	}

	return completion(result);
}

tb_error_t
exclaves_driverkit_upcall_irq_disable(const uint64_t id, const int32_t index,
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_irq_disable__result_s))
{
	exclaves_debug_printf(show_iokit_upcalls,
	    "[iokit_upcalls] disable_irq %d from id %llu \n", index, id);
	struct IOExclaveInterruptUpcallArgs args;
	args.index = index;
	args.type = kIOExclaveInterruptUpcallTypeEnable;
	args.data.enable_args.enable = false;

	xnuupcalls_xnuupcalls_irq_disable__result_s result = {};
	if (!IOExclaveInterruptUpcallHandler(id, &args)) {
		xnuupcalls_xnuupcalls_irq_disable__result_init_failure(&result,
		    XNUUPCALLS_DRIVERUPCALLERROR_FAILURE);
	} else {
		xnuupcalls_xnuupcalls_irq_disable__result_init_success(&result);
	}

	return completion(result);
}

tb_error_t
exclaves_driverkit_upcall_timer_register(const uint64_t id,
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_timer_register__result_s))
{
	exclaves_debug_printf(show_iokit_upcalls,
	    "[iokit_upcalls] %s from id %llu\n", __func__, id);
	struct IOExclaveTimerUpcallArgs args;
	args.type = kIOExclaveTimerUpcallTypeRegister;

	xnuupcalls_xnuupcalls_timer_register__result_s result = {};
	if (!IOExclaveTimerUpcallHandler(id, &args)) {
		xnuupcalls_xnuupcalls_timer_register__result_init_failure(&result,
		    XNUUPCALLS_DRIVERUPCALLERROR_FAILURE);
	} else {
		xnuupcalls_xnuupcalls_timer_register__result_init_success(&result,
		    args.timer_id);
	}

	return completion(result);
}

tb_error_t
exclaves_driverkit_upcall_timer_remove(const uint64_t id, const uint32_t timer_id,
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_timer_remove__result_s))
{
	exclaves_debug_printf(show_iokit_upcalls,
	    "[iokit_upcalls] %s from id %llu\n", __func__, id);
	struct IOExclaveTimerUpcallArgs args;
	args.timer_id = timer_id;
	args.type = kIOExclaveTimerUpcallTypeRemove;

	xnuupcalls_xnuupcalls_timer_remove__result_s result = {};
	if (!IOExclaveTimerUpcallHandler(id, &args)) {
		xnuupcalls_xnuupcalls_timer_remove__result_init_failure(&result,
		    XNUUPCALLS_DRIVERUPCALLERROR_FAILURE);
	} else {
		xnuupcalls_xnuupcalls_timer_remove__result_init_success(&result);
	}

	return completion(result);
}

extern tb_error_t
exclaves_driverkit_upcall_timer_enable(const uint64_t id, const uint32_t timer_id,
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_timer_enable__result_s))
{
	exclaves_debug_printf(show_iokit_upcalls,
	    "[iokit_upcalls] %s from id %llu\n", __func__, id);
	struct IOExclaveTimerUpcallArgs args;
	args.timer_id = timer_id;
	args.type = kIOExclaveTimerUpcallTypeEnable;
	args.data.enable_args.enable = true;

	xnuupcalls_xnuupcalls_timer_enable__result_s result = {};
	if (!IOExclaveTimerUpcallHandler(id, &args)) {
		xnuupcalls_xnuupcalls_timer_enable__result_init_failure(&result,
		    XNUUPCALLS_DRIVERUPCALLERROR_FAILURE);
	} else {
		xnuupcalls_xnuupcalls_timer_enable__result_init_success(&result);
	}

	return completion(result);
}

tb_error_t
exclaves_driverkit_upcall_timer_disable(const uint64_t id, const uint32_t timer_id,
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_timer_disable__result_s))
{
	exclaves_debug_printf(show_iokit_upcalls,
	    "[iokit_upcalls] %s from id %llu\n", __func__, id);
	struct IOExclaveTimerUpcallArgs args;
	args.timer_id = timer_id;
	args.type = kIOExclaveTimerUpcallTypeEnable;
	args.data.enable_args.enable = false;

	xnuupcalls_xnuupcalls_timer_disable__result_s result = {};
	if (!IOExclaveTimerUpcallHandler(id, &args)) {
		xnuupcalls_xnuupcalls_timer_disable__result_init_failure(&result,
		    XNUUPCALLS_DRIVERUPCALLERROR_FAILURE);
	} else {
		xnuupcalls_xnuupcalls_timer_disable__result_init_success(&result);
	}

	return completion(result);
}

tb_error_t
exclaves_driverkit_upcall_timer_set_timeout(const uint64_t id,
    const uint32_t timer_id,
    const struct xnuupcalls_drivertimerspecification_s *duration,
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_timer_set_timeout__result_s))
{
	exclaves_debug_printf(show_iokit_upcalls,
	    "[iokit_upcalls] %s from id %llu\n", __func__, id);

	xnuupcalls_xnuupcalls_timer_set_timeout__result_s result = {};

	if (!duration) {
		exclaves_debug_printf(show_iokit_upcalls,
		    "[iokit_upcalls] %s invalid duration\n", __func__);
		xnuupcalls_xnuupcalls_timer_set_timeout__result_init_failure(&result,
		    XNUUPCALLS_DRIVERUPCALLERROR_FAILURE);
		return completion(result);
	}

	struct IOExclaveTimerUpcallArgs args;
	args.timer_id = timer_id;
	args.type = kIOExclaveTimerUpcallTypeSetTimeout;

	switch (duration->type) {
	case XNUUPCALLS_DRIVERTIMERTYPE_ABSOLUTE:
		args.data.set_timeout_args.clock_continuous = false;
		break;
	case XNUUPCALLS_DRIVERTIMERTYPE_CONTINUOUS:
		args.data.set_timeout_args.clock_continuous = true;
		break;
	default:
		exclaves_debug_printf(show_iokit_upcalls,
		    "[iokit_upcalls] %s unknown clock type %u\n",
		    __func__, duration->type);
		xnuupcalls_xnuupcalls_timer_set_timeout__result_init_failure(&result,
		    XNUUPCALLS_DRIVERUPCALLERROR_FAILURE);
		return completion(result);
	}

	// Convert to abs time
	AbsoluteTime end, nsecs;
	clock_interval_to_absolutetime_interval(duration->tv_nsec,
	    kNanosecondScale, &nsecs);
	clock_interval_to_absolutetime_interval(duration->tv_sec,
	    kSecondScale, &end);
	ADD_ABSOLUTETIME(&end, &nsecs);
	args.data.set_timeout_args.duration = end;

	if (!IOExclaveTimerUpcallHandler(id, &args)) {
		xnuupcalls_xnuupcalls_timer_set_timeout__result_init_failure(&result,
		    XNUUPCALLS_DRIVERUPCALLERROR_FAILURE);
	} else {
		xnuupcalls_xnuupcalls_timer_set_timeout__result_init_success(&result,
		    args.data.set_timeout_args.kr == kIOReturnSuccess);
	}

	return completion(result);
}

tb_error_t
exclaves_driverkit_upcall_timer_cancel_timeout(const uint64_t id,
    const uint32_t timer_id,
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_timer_cancel_timeout__result_s))
{
	exclaves_debug_printf(show_iokit_upcalls,
	    "[iokit_upcalls] %s from id %llu\n", __func__, id);
	struct IOExclaveTimerUpcallArgs args;
	args.timer_id = timer_id;
	args.type = kIOExclaveTimerUpcallTypeCancelTimeout;

	xnuupcalls_xnuupcalls_timer_cancel_timeout__result_s result = {};
	if (!IOExclaveTimerUpcallHandler(id, &args)) {
		xnuupcalls_xnuupcalls_timer_cancel_timeout__result_init_failure(&result,
		    XNUUPCALLS_DRIVERUPCALLERROR_FAILURE);
	} else {
		xnuupcalls_xnuupcalls_timer_cancel_timeout__result_init_success(&result);
	}

	return completion(result);
}

tb_error_t
exclaves_driverkit_upcall_lock_wl(const uint64_t id,
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_lock_wl__result_s))
{
	exclaves_debug_printf(show_iokit_upcalls,
	    "[iokit_upcalls] lock_wl from id %llu\n", id);

	xnuupcalls_xnuupcalls_lock_wl__result_s result = {};
	if (!IOExclaveLockWorkloop(id, true)) {
		xnuupcalls_xnuupcalls_lock_wl__result_init_failure(&result,
		    XNUUPCALLS_DRIVERUPCALLERROR_FAILURE);
	} else {
		xnuupcalls_xnuupcalls_lock_wl__result_init_success(&result);
	}

	return completion(result);
}

tb_error_t
exclaves_driverkit_upcall_unlock_wl(const uint64_t id,
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_unlock_wl__result_s))
{
	exclaves_debug_printf(show_iokit_upcalls,
	    "[iokit_upcalls] unlock_wl from id %llu\n", id);

	xnuupcalls_xnuupcalls_unlock_wl__result_s result = {};
	if (!IOExclaveLockWorkloop(id, false)) {
		xnuupcalls_xnuupcalls_unlock_wl__result_init_failure(&result,
		    XNUUPCALLS_DRIVERUPCALLERROR_FAILURE);
	} else {
		xnuupcalls_xnuupcalls_unlock_wl__result_init_success(&result);
	}

	return completion(result);
}

extern tb_error_t
exclaves_driverkit_upcall_async_notification_signal(const uint64_t id,
    const uint32_t notificationID,
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_async_notification_signal__result_s))
{
	exclaves_debug_printf(show_iokit_upcalls,
	    "[iokit_upcalls] async_notification_signal from id %llu\n", id);
	struct IOExclaveAsyncNotificationUpcallArgs args;
	args.type = AsyncNotificationUpcallTypeSignal;
	args.notificationID = notificationID;

	xnuupcalls_xnuupcalls_async_notification_signal__result_s result = {};
	if (!IOExclaveAsyncNotificationUpcallHandler(id, &args)) {
		xnuupcalls_xnuupcalls_async_notification_signal__result_init_failure(&result,
		    XNUUPCALLS_DRIVERUPCALLERROR_FAILURE);
	} else {
		xnuupcalls_xnuupcalls_async_notification_signal__result_init_success(&result);
	}

	return completion(result);
}

tb_error_t
exclaves_driverkit_upcall_mapper_activate(const uint64_t id,
    const uint32_t mapperIndex,
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_mapper_activate__result_s))
{
	exclaves_debug_printf(show_iokit_upcalls,
	    "[iokit_upcalls] mapper_activate from id %llu\n", id);
	struct IOExclaveMapperOperationUpcallArgs args;
	args.type = MapperActivate;
	args.mapperIndex = mapperIndex;

	xnuupcalls_xnuupcalls_mapper_activate__result_s result = {};
	if (!IOExclaveMapperOperationUpcallHandler(id, &args)) {
		xnuupcalls_xnuupcalls_mapper_activate__result_init_failure(&result,
		    XNUUPCALLS_DRIVERUPCALLERROR_FAILURE);
	} else {
		xnuupcalls_xnuupcalls_mapper_activate__result_init_success(&result);
	}

	return completion(result);
}

tb_error_t
exclaves_driverkit_upcall_mapper_deactivate(const uint64_t id,
    const uint32_t mapperIndex,
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_mapper_deactivate__result_s))
{
	exclaves_debug_printf(show_iokit_upcalls,
	    "[iokit_upcalls] mapper_deactivate from id %llu\n", id);
	struct IOExclaveMapperOperationUpcallArgs args;
	args.type = MapperDeactivate;
	args.mapperIndex = mapperIndex;

	xnuupcalls_xnuupcalls_mapper_deactivate__result_s result = {};
	if (!IOExclaveMapperOperationUpcallHandler(id, &args)) {
		xnuupcalls_xnuupcalls_mapper_deactivate__result_init_failure(&result,
		    XNUUPCALLS_DRIVERUPCALLERROR_FAILURE);
	} else {
		xnuupcalls_xnuupcalls_mapper_deactivate__result_init_success(&result);
	}

	return completion(result);
}

extern tb_error_t
exclaves_driverkit_upcall_ane_setpowerstate(const uint64_t id,
    const uint32_t desiredState,
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_ane_setpowerstate__result_s))
{
	exclaves_debug_printf(show_iokit_upcalls,
	    "[iokit_upcalls] ane_setpowerstate from id %llu\n", id);
	struct IOExclaveANEUpcallArgs args;
	bool ret = false;
	args.type = kIOExclaveANEUpcallTypeSetPowerState;
	args.setpowerstate_args.desired_state = desiredState;

	xnuupcalls_xnuupcalls_ane_setpowerstate__result_s result = {};
	if (!IOExclaveANEUpcallHandler(id, &args, &ret)) {
		xnuupcalls_xnuupcalls_ane_setpowerstate__result_init_failure(&result,
		    XNUUPCALLS_DRIVERUPCALLERROR_FAILURE);
	} else {
		xnuupcalls_xnuupcalls_ane_setpowerstate__result_init_success(&result,
		    ret);
	}
	return completion(result);
}

tb_error_t
exclaves_driverkit_upcall_ane_worksubmit(const uint64_t id, const uint64_t requestID,
    const uint32_t taskDescriptorCount, const uint64_t submitTimestamp,
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_ane_worksubmit__result_s))
{
	exclaves_debug_printf(show_iokit_upcalls,
	    "[iokit_upcalls] ane_worksubmit from id %llu\n", id);
	struct IOExclaveANEUpcallArgs args;
	bool ret = false;
	args.type = kIOExclaveANEUpcallTypeWorkSubmit;
	args.work_args.arg0 = requestID;
	args.work_args.arg1 = taskDescriptorCount;
	args.work_args.arg2 = submitTimestamp;

	xnuupcalls_xnuupcalls_ane_worksubmit__result_s result = {};
	if (!IOExclaveANEUpcallHandler(id, &args, &ret)) {
		xnuupcalls_xnuupcalls_ane_worksubmit__result_init_failure(&result,
		    XNUUPCALLS_DRIVERUPCALLERROR_FAILURE);
	} else {
		xnuupcalls_xnuupcalls_ane_worksubmit__result_init_success(&result,
		    ret);
	}
	return completion(result);
}

tb_error_t
exclaves_driverkit_upcall_ane_workbegin(const uint64_t id, const uint64_t requestID,
    const uint64_t beginTimestamp,
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_ane_workbegin__result_s))
{
	exclaves_debug_printf(show_iokit_upcalls,
	    "[iokit_upcalls] ane_workbegin from id %llu\n", id);
	struct IOExclaveANEUpcallArgs args;
	bool ret = false;
	args.type = kIOExclaveANEUpcallTypeWorkBegin;
	args.work_args.arg0 = requestID;
	args.work_args.arg1 = beginTimestamp;
	args.work_args.arg2 = 0;

	xnuupcalls_xnuupcalls_ane_workbegin__result_s result = {};
	if (!IOExclaveANEUpcallHandler(id, &args, &ret)) {
		xnuupcalls_xnuupcalls_ane_workbegin__result_init_failure(&result,
		    XNUUPCALLS_DRIVERUPCALLERROR_FAILURE);
	} else {
		xnuupcalls_xnuupcalls_ane_workbegin__result_init_success(&result,
		    ret);
	}
	return completion(result);
}

tb_error_t
exclaves_driverkit_upcall_ane_workend(const uint64_t id, const uint64_t requestID,
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_ane_workend__result_s))
{
	exclaves_debug_printf(show_iokit_upcalls,
	    "[iokit_upcalls] ane_workend from id %llu\n", id);
	struct IOExclaveANEUpcallArgs args;
	bool ret = false;
	args.type = kIOExclaveANEUpcallTypeWorkEnd;
	args.work_args.arg0 = requestID;
	args.work_args.arg1 = 0;
	args.work_args.arg2 = 0;

	xnuupcalls_xnuupcalls_ane_workend__result_s result = {};
	if (!IOExclaveANEUpcallHandler(id, &args, &ret)) {
		xnuupcalls_xnuupcalls_ane_workend__result_init_failure(&result,
		    XNUUPCALLS_DRIVERUPCALLERROR_FAILURE);
	} else {
		xnuupcalls_xnuupcalls_ane_workend__result_init_success(&result,
		    ret);
	}
	return completion(result);
}

tb_error_t
exclaves_driverkit_upcall_notification_signal(const uint64_t id,
    const uint32_t mask,
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_notification_signal__result_s))
{
	exclaves_debug_printf(show_notification_upcalls,
	    "[notification_upcalls] notification_signal "
	    "id %llx mask %x\n", id, mask);
	exclaves_resource_t *notification_resource =
	    exclaves_notification_lookup_by_id(EXCLAVES_DOMAIN_KERNEL, id);

	xnuupcalls_xnuupcalls_notification_signal__result_s result = {};

	if (notification_resource != NULL) {
		exclaves_debug_printf(show_notification_upcalls,
		    "[notification_upcalls] notification_signal "
		    "id %llx mask %x -> found resource\n", id, mask);
		exclaves_notification_signal(notification_resource, mask);
		xnuupcalls_xnuupcalls_notification_signal__result_init_success(&result);
	} else {
		exclaves_debug_printf(show_notification_upcalls,
		    "[notification_upcalls] notification_signal "
		    "id %llx mask %x -> no notification resource found\n",
		    id, mask);
		xnuupcalls_xnuupcalls_notification_signal__result_init_failure(&result,
		    XNUUPCALLS_NOTIFICATIONERROR_NOTFOUND);
	}

	return completion(result);
}

/* -------------------------------------------------------------------------- */
#pragma mark Tests

#if DEVELOPMENT || DEBUG

#define EXCLAVES_HELLO_DRIVER_INTERRUPTS_INDEX 0
#define EXCLAVES_HELLO_DRIVER_INTERRUPTS_CHECK_RET(test) if (test) { break; }

#define EXCLAVES_ID_HELLO_INTERRUPTS_EP \
    (exclaves_endpoint_lookup("com.apple.service.HelloDriverInterrupts"))

typedef enum hello_driverkit_interrupts_test_type {
	TEST_IRQ_REGISTER,
	TEST_IRQ_REMOVE,
	TEST_IRQ_ENABLE,
	TEST_IRQ_CHECK,
	TEST_IRQ_DISABLE,
	TEST_TIMER_REGISTER,
	TEST_TIMER_REMOVE,
	TEST_TIMER_ENABLE,
	TEST_TIMER_DISABLE,
	TEST_TIMER_SETTIMEOUT,
	TEST_TIMER_CHECK,
	TEST_TIMER_CANCELTIMEOUT,
	TEST_MULTI_TIMER_SETUP,
	TEST_MULTI_TIMER_CLEANUP,
	HELLO_DRIVER_INTERRUPTS_NUM_TESTS
} hello_driverkit_interrupts_test_type_t;
static const char *hello_driverkit_interrupts_test_string[] = {
	"IRQ_REGISTER",
	"IRQ_REMOVE",
	"IRQ_ENABLE",
	"IRQ_CHECK",
	"IRQ_DISABLE",
	"TIMER_REGISTER",
	"TIMER_REMOVE",
	"TIMER_ENABLE",
	"TIMER_DISABLE",
	"TIMER_SETTIMEOUT",
	"TIMER_CHECK",
	"TIMER_CANCELTIMEOUT",
	"MULTI_TIMER_SETUP",
	"MULTI_TIMER_CLEANUP"
};

static int
hello_driverkit_interrupts(hello_driverkit_interrupts_test_type_t test_type)
{
	printf("****** START: %s ******\n",
	    hello_driverkit_interrupts_test_string[test_type]);

	int err = 0;
	assert(test_type < HELLO_DRIVER_INTERRUPTS_NUM_TESTS);

	tb_endpoint_t ep = tb_endpoint_create_with_value(
		TB_TRANSPORT_TYPE_XNU, EXCLAVES_ID_HELLO_INTERRUPTS_EP, 0);

	tb_client_connection_t client =
	    tb_client_connection_create_with_endpoint(ep);

	tb_client_connection_activate(client);

	tb_message_t message = NULL;
	tb_transport_message_buffer_t tpt_buf = NULL;

	message = kalloc_type(struct tb_message_s, Z_WAITOK | Z_ZERO | Z_NOFAIL);
	tpt_buf = kalloc_type(struct tb_transport_message_buffer_s,
	    Z_WAITOK | Z_ZERO | Z_NOFAIL);

	// Encode TB buffer with test_type
	tb_error_t tb_err = TB_ERROR_SUCCESS;
	tb_err = tb_client_connection_message_construct(client, message,
	    tpt_buf, sizeof(uint8_t), 0);
	if (tb_err != TB_ERROR_SUCCESS) {
		err = 1;
		goto out;
	}
	exclaves_debug_printf(show_test_output, "%s: Tightbeam constructing message: %u\n", __func__,
	    (uint8_t) test_type);
	tb_message_encode_u8(message, (uint8_t) test_type);

	tb_message_complete(message);
	exclaves_debug_printf(show_test_output, "%s: Tightbeam message completed\n", __func__);

	tb_message_t response = NULL;

	// Perform downcall
	tb_err = tb_connection_send_query(client, message, &response,
	    TB_CONNECTION_WAIT_FOR_REPLY);
	if (tb_err != TB_ERROR_SUCCESS) {
		err = 2;
		goto out;
	}
	exclaves_debug_printf(show_test_output, "%s: Tightbeam message send success, reply: ", __func__);

	// Decode downcall reply
	uint8_t reply = 0;
	tb_message_decode_u8(response, &reply);
	exclaves_debug_printf(show_test_output, "%u\n", reply);

	if (reply != 0) {
		err = 3;
		goto out;
	}
	tb_client_connection_message_destruct(client, message);

out:
	if (err == 0) {
		exclaves_debug_printf(show_test_output, "****** SUCCESS: %s ******\n",
		    hello_driverkit_interrupts_test_string[test_type]);
	} else {
		exclaves_debug_printf(show_test_output, "****** FAILURE: %s (%d) ******\n",
		    hello_driverkit_interrupts_test_string[test_type], err);
	}

	kfree_type(struct tb_message_s, message);
	kfree_type(struct tb_transport_message_buffer_s, tpt_buf);

	return err;
}


static int
exclaves_hello_driverkit_interrupts(uint64_t registryID, int64_t *out)
{
	if (exclaves_get_status() != EXCLAVES_STATUS_AVAILABLE) {
		exclaves_debug_printf(show_test_output,
		    "%s: SKIPPED: Exclaves not available\n", __func__);
		*out = -1;
		return 0;
	}

	bool success = false;
	exclaves_debug_printf(show_test_output, "%s: STARTING\n", __func__);

	// Interrupts
	struct IOExclaveTestSignalInterruptParam *signal_param = kalloc_type(
		struct IOExclaveTestSignalInterruptParam, Z_WAITOK | Z_ZERO | Z_NOFAIL);
	thread_call_t signal_thread = thread_call_allocate(
		(thread_call_func_t) &IOExclaveTestSignalInterrupt, signal_param);

	do {
		/* Interrupt tests */

		// Set AppleExclaveExampleKext registryID as service under test
		exclaves_hello_driverkit_interrupts_service_id = registryID;
		signal_param->id = registryID;
		signal_param->index = EXCLAVES_HELLO_DRIVER_INTERRUPTS_INDEX;

		printf("%s: SKIPPING INTERRUPT TESTS (rdar://107842497)\n", __func__);

		/* Timer tests */

		printf("%s: TIMER TESTS\n", __func__);
		EXCLAVES_HELLO_DRIVER_INTERRUPTS_CHECK_RET(
			hello_driverkit_interrupts(TEST_TIMER_REGISTER))
		EXCLAVES_HELLO_DRIVER_INTERRUPTS_CHECK_RET(
			hello_driverkit_interrupts(TEST_TIMER_ENABLE))
		EXCLAVES_HELLO_DRIVER_INTERRUPTS_CHECK_RET(
			hello_driverkit_interrupts(TEST_TIMER_SETTIMEOUT))
		// Wait for timer to fire
		delay_for_interval(2000, 1000 * 1000 /* kMilliSecondScale */);
		// Check timer was recieved by exclave
		EXCLAVES_HELLO_DRIVER_INTERRUPTS_CHECK_RET(
			hello_driverkit_interrupts(TEST_TIMER_CHECK))
		EXCLAVES_HELLO_DRIVER_INTERRUPTS_CHECK_RET(
			hello_driverkit_interrupts(TEST_TIMER_DISABLE))
		EXCLAVES_HELLO_DRIVER_INTERRUPTS_CHECK_RET(
			hello_driverkit_interrupts(TEST_TIMER_REMOVE))

		success = true;
	} while (false);

	// Cleanup
	exclaves_hello_driverkit_interrupts_service_id = -1ull;
	thread_call_free(signal_thread);
	signal_thread = NULL;
	kfree_type(struct IOExclaveTestSignalInterruptParam, signal_param);

	if (success) {
		exclaves_debug_printf(show_test_output, "%s: SUCCESS\n", __func__);
		*out = 1;
	} else {
		exclaves_debug_printf(show_errors, "%s: FAILED\n", __func__);
		*out = 0;
	}
	return 0;
}

static int
exclaves_hello_driverkit_interrupts_test(int64_t in, int64_t *out)
{
	// in should be AppleExclaveExampleKext's registry ID
	return exclaves_hello_driverkit_interrupts((uint64_t)in, out);
}


SYSCTL_TEST_REGISTER(exclaves_hello_driver_interrupts_test,
    exclaves_hello_driverkit_interrupts_test);


static int
exclaves_hello_driverkit_multi_timers(int64_t *out)
{
	if (exclaves_get_status() != EXCLAVES_STATUS_AVAILABLE) {
		exclaves_debug_printf(show_test_output,
		    "%s: SKIPPED: Exclaves not available\n", __func__);
		*out = -1;
		return 0;
	}

	bool success = false;
	exclaves_debug_printf(show_test_output, "%s: STARTING\n", __func__);

	do {
		printf("%s: TIMER TESTS\n", __func__);
		EXCLAVES_HELLO_DRIVER_INTERRUPTS_CHECK_RET(
			hello_driverkit_interrupts(TEST_MULTI_TIMER_SETUP))
		// Multiple timers are setup with the same timeout
		EXCLAVES_HELLO_DRIVER_INTERRUPTS_CHECK_RET(
			hello_driverkit_interrupts(TEST_TIMER_SETTIMEOUT))
		// Wait for timers to fire
		delay_for_interval(2000, 1000 * 1000 /* kMilliSecondScale */);
		// Check if all timer interrupts were recieved by exclave
		EXCLAVES_HELLO_DRIVER_INTERRUPTS_CHECK_RET(
			hello_driverkit_interrupts(TEST_TIMER_CHECK))
		EXCLAVES_HELLO_DRIVER_INTERRUPTS_CHECK_RET(
			hello_driverkit_interrupts(TEST_MULTI_TIMER_CLEANUP))

		success = true;
	} while (false);

	if (success) {
		exclaves_debug_printf(show_test_output, "%s: SUCCESS\n", __func__);
		*out = 1;
	} else {
		exclaves_debug_printf(show_errors, "%s: FAILED\n", __func__);
		*out = 0;
	}
	return 0;
}


static int
exclaves_hello_driverkit_multi_timers_test(__unused int64_t in, int64_t *out)
{
	return exclaves_hello_driverkit_multi_timers(out);
}


SYSCTL_TEST_REGISTER(exclaves_hello_driver_multi_timers_test,
    exclaves_hello_driverkit_multi_timers_test);

#endif /* DEVELOPMENT || DEBUG */

#endif  /* __has_include(<Tightbeam/tightbeam.h>) */

#endif /* CONFIG_EXCLAVES */
