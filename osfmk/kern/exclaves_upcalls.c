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

#include <mach/exclaves.h>
#include "exclaves_upcalls.h"

#if CONFIG_EXCLAVES

#if __has_include(<Tightbeam/tightbeam.h>)

#include <mach/exclaves_l4.h>

#include <stdint.h>

#include <Tightbeam/tightbeam.h>
#include <Tightbeam/tightbeam_private.h>

#include <kern/kalloc.h>
#include <kern/locks.h>
#include <kern/task.h>

#include <xnuproxy/exclaves.h>
#include <xnuproxy/messages.h>

#include "kern/exclaves.tightbeam.h"

#include "exclaves_boot.h"
#include "exclaves_conclave.h"
#include "exclaves_debug.h"
#include "exclaves_driverkit.h"
#include "exclaves_memory.h"
#include "exclaves_stackshot.h"
#include "exclaves_storage.h"
#include "exclaves_test_stackshot.h"
#include "exclaves_xnuproxy.h"

#include <sys/errno.h>

#define EXCLAVES_ID_HELLO_EXCLAVE_EP                 \
    (exclaves_service_lookup(EXCLAVES_DOMAIN_KERNEL, \
    "com.apple.service.ExclavesCHelloServer"))

#define EXCLAVES_ID_TIGHTBEAM_UPCALL \
    ((exclaves_id_t)XNUPROXY_UPCALL_TIGHTBEAM)

#define EXCLAVES_ID_TIGHTBEAM_UPCALL_V2 \
    ((exclaves_id_t)XNUPROXY_UPCALL_TIGHTBEAM_V2)

extern lck_mtx_t exclaves_boot_lock;

typedef struct exclaves_upcall_handler_registration {
	exclaves_upcall_handler_t handler;
	void *context;
} exclaves_upcall_handler_registration_t;

static exclaves_upcall_handler_registration_t
    exclaves_upcall_handlers[NUM_XNUPROXY_UPCALLS];

#define EXCLAVES_OBSOLETE_UPCALL_TESTING 1 // TODO: delete (rdar://123929546)
#ifdef EXCLAVES_OBSOLETE_UPCALL_TESTING
#if DEVELOPMENT || DEBUG
static kern_return_t
exclaves_test_hello_upcall_handler(void *, exclaves_tag_t *, exclaves_badge_t);
#endif /* DEVELOPMENT || DEBUG */
#endif // EXCLAVES_OBSOLETE_UPCALL_TESTING


/* -------------------------------------------------------------------------- */
#pragma mark Upcall Callouts

static tb_error_t
exclaves_helloupcall(const uint64_t arg, tb_error_t (^completion)(uint64_t));

/*
 * Tightbeam upcall callout table.
 * Don't add inline functionality here, instead call directly into your
 * sub-system.
 */

static const xnuupcalls_xnuupcalls__server_s exclaves_tightbeam_upcalls = {
	/* BEGIN IGNORE CODESTYLE */
	/* Uncrustify doesn't deal well with Blocks. */
	.helloupcall = ^(const uint64_t arg, tb_error_t (^completion)(uint64_t)) {
		return exclaves_helloupcall(arg, completion);
	},

	.alloc = ^(const uint32_t npages, xnuupcalls_pagekind_s kind,
	    tb_error_t (^completion)(xnuupcalls_pagelist_s)) {
		return exclaves_memory_upcall_legacy_alloc(npages, kind, completion);
	},

	.alloc_ext = ^(const uint32_t npages, xnuupcalls_pageallocflags_s flags,
	    tb_error_t (^completion)(xnuupcalls_pagelist_s)) {
		return exclaves_memory_upcall_legacy_alloc_ext(npages, flags, completion);
	},

	.free = ^(const uint32_t pages[_Nonnull EXCLAVES_MEMORY_MAX_REQUEST],
	    const uint32_t npages, const xnuupcalls_pagekind_s kind,
	    tb_error_t (^completion)(void)) {
		return exclaves_memory_upcall_legacy_free(pages, npages, kind, completion);
	},

	.free_ext = ^(const uint32_t pages[_Nonnull EXCLAVES_MEMORY_MAX_REQUEST],
		const uint32_t npages, xnuupcalls_pagefreeflags_s flags, tb_error_t (^completion)(void)) {
		return exclaves_memory_upcall_legacy_free_ext(pages, npages, flags, completion);
	},

	.root = ^(const uint8_t exclaveid[_Nonnull 32],
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_root__result_s)) {
		return exclaves_storage_upcall_legacy_root(exclaveid, completion);
	},

	.open = ^(const enum xnuupcalls_fstag_s fstag, const uint64_t rootid,
	    const uint8_t name[_Nonnull 256],
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_open__result_s)) {
		return exclaves_storage_upcall_legacy_open(fstag, rootid, name, completion);
	},

	.close = ^(const enum xnuupcalls_fstag_s fstag, const uint64_t fileid,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_close__result_s)) {
		return exclaves_storage_upcall_legacy_close(fstag, fileid, completion);
	},

	.create = ^(const enum xnuupcalls_fstag_s fstag, const uint64_t rootid,
	    const uint8_t name[_Nonnull 256],
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_create__result_s)) {
		return exclaves_storage_upcall_legacy_create(fstag, rootid, name, completion);
	},

	.read = ^(const enum xnuupcalls_fstag_s fstag, const uint64_t fileid,
	    const struct xnuupcalls_iodesc_s *descriptor,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_read__result_s)) {
		return exclaves_storage_upcall_legacy_read(fstag, fileid, descriptor, completion);
	},

	.write = ^(const enum xnuupcalls_fstag_s fstag, const uint64_t fileid,
	    const struct xnuupcalls_iodesc_s *descriptor,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_write__result_s)) {
		return exclaves_storage_upcall_legacy_write(fstag, fileid, descriptor, completion);
	},

	.remove = ^(const enum xnuupcalls_fstag_s fstag, const uint64_t rootid,
	    const uint8_t name[_Nonnull 256],
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_remove__result_s)) {
		return exclaves_storage_upcall_legacy_remove(fstag, rootid, name, completion);
	},

	.sync = ^(const enum xnuupcalls_fstag_s fstag,
	    const enum xnuupcalls_syncop_s op,
	    const uint64_t fileid,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_sync__result_s)) {
		return exclaves_storage_upcall_legacy_sync(fstag, op, fileid, completion);
	},

	.readdir = ^(const enum xnuupcalls_fstag_s fstag,
	    const uint64_t fileid, const uint64_t buf,
	    const uint32_t length,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_readdir__result_s)) {
		return exclaves_storage_upcall_legacy_readdir(fstag, fileid, buf, length, completion);
	},

	.getsize = ^(const enum xnuupcalls_fstag_s fstag, const uint64_t fileid,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_getsize__result_s)) {
		return exclaves_storage_upcall_legacy_getsize(fstag, fileid, completion);
	},

	.sealstate = ^(const enum xnuupcalls_fstag_s fstag,
		tb_error_t (^completion)(xnuupcalls_xnuupcalls_sealstate__result_s)) {
		return exclaves_storage_upcall_legacy_sealstate(fstag, completion);
	},

	.irq_register = ^(const uint64_t id, const int32_t index,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_irq_register__result_s)) {
		return exclaves_driverkit_upcall_legacy_irq_register(id, index, completion);
	},

	.irq_remove = ^(const uint64_t id, const int32_t index,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_irq_remove__result_s)) {
		return exclaves_driverkit_upcall_legacy_irq_remove(id, index, completion);
	},

	.irq_enable = ^(const uint64_t id, const int32_t index,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_irq_enable__result_s)) {
		return exclaves_driverkit_upcall_legacy_irq_enable(id, index, completion);
	},

	.irq_disable = ^(const uint64_t id, const int32_t index,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_irq_disable__result_s)) {
		return exclaves_driverkit_upcall_legacy_irq_disable(id, index, completion);
	},

	.timer_register = ^(const uint64_t id,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_timer_register__result_s)) {
		return exclaves_driverkit_upcall_legacy_timer_register(id, completion);
	},

	.timer_remove = ^(const uint64_t id, const uint32_t timer_id,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_timer_remove__result_s)) {
		return exclaves_driverkit_upcall_legacy_timer_remove(id, timer_id, completion);
	},

	.timer_enable = ^(const uint64_t id, const uint32_t timer_id,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_timer_enable__result_s)) {
		return exclaves_driverkit_upcall_legacy_timer_enable(id, timer_id, completion);
	},

	.timer_disable = ^(const uint64_t id, const uint32_t timer_id,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_timer_disable__result_s)) {
		return exclaves_driverkit_upcall_legacy_timer_disable(id, timer_id, completion);
	},

	.timer_set_timeout = ^(const uint64_t id, const uint32_t timer_id,
	    const struct xnuupcalls_drivertimerspecification_s *duration,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_timer_set_timeout__result_s)) {
		return exclaves_driverkit_upcall_legacy_timer_set_timeout(id, timer_id, duration, completion);
	},

	.timer_cancel_timeout = ^(const uint64_t id, const uint32_t timer_id,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_timer_cancel_timeout__result_s)) {
		return exclaves_driverkit_upcall_legacy_timer_cancel_timeout(id, timer_id, completion);
	},

	.lock_wl = ^(const uint64_t id,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_lock_wl__result_s)) {
		return exclaves_driverkit_upcall_legacy_lock_wl(id, completion);
	},

	.unlock_wl = ^(const uint64_t id,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_unlock_wl__result_s)) {
		return exclaves_driverkit_upcall_legacy_unlock_wl(id, completion);
	},

	.async_notification_signal = ^(const uint64_t id,
	    const uint32_t notificationID,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_async_notification_signal__result_s)) {
		return exclaves_driverkit_upcall_legacy_async_notification_signal(id,
		    notificationID, completion);
	},

	.mapper_activate = ^(const uint64_t id, const uint32_t mapperIndex,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_mapper_activate__result_s)) {
		return exclaves_driverkit_upcall_legacy_mapper_activate(id,
		    mapperIndex, completion);
	},

	.mapper_deactivate = ^(const uint64_t id, const uint32_t mapperIndex,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_mapper_deactivate__result_s)) {
		return exclaves_driverkit_upcall_legacy_mapper_deactivate(id,
		    mapperIndex, completion);
	},

	.notification_signal = ^(const uint64_t id, const uint32_t mask,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_notification_signal__result_s)) {
		return exclaves_driverkit_upcall_legacy_notification_signal(id, mask,
		    completion);
	},

	.ane_setpowerstate = ^(const uint64_t id, const uint32_t desiredState,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_ane_setpowerstate__result_s)) {
		return exclaves_driverkit_upcall_legacy_ane_setpowerstate(id, desiredState,
			completion);
	},

	.ane_worksubmit = ^(const uint64_t id, const uint64_t requestID,
	    const uint32_t taskDescriptorCount, const uint64_t submitTimestamp,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_ane_worksubmit__result_s)) {
		return exclaves_driverkit_upcall_legacy_ane_worksubmit(id, requestID,
			taskDescriptorCount, submitTimestamp, completion);
	},

	.ane_workbegin = ^(const uint64_t id, const uint64_t requestID,
	    const uint64_t beginTimestamp,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_ane_workbegin__result_s)) {
		return exclaves_driverkit_upcall_legacy_ane_workbegin(id, requestID,
			beginTimestamp, completion);
	},

	.ane_workend = ^(const uint64_t id, const uint64_t requestID,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_ane_workend__result_s)) {
		return exclaves_driverkit_upcall_legacy_ane_workend(id, requestID, completion);
	},

	.conclave_suspend = ^(const uint32_t flags,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_conclave_suspend__result_s)) {
		return exclaves_conclave_upcall_legacy_suspend(flags, completion);
	},

	.conclave_stop = ^(const uint32_t flags,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_conclave_stop__result_s)) {
		return exclaves_conclave_upcall_legacy_stop(flags, completion);
	},
	.conclave_crash_info = ^(const xnuupcalls_conclavesharedbuffer_s *shared_buf,
	    const uint32_t length,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_conclave_crash_info__result_s)) {
		return exclaves_conclave_upcall_legacy_crash_info(shared_buf, length, completion);
	},
	/* END IGNORE CODESTYLE */
};

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"
static const xnuupcallsv2_xnuupcalls__server_s exclaves_tightbeam_upcalls_v2 = {
	/* BEGIN IGNORE CODESTYLE */
	/* Uncrustify doesn't deal well with Blocks. */
	.helloupcall = ^(const uint64_t arg, tb_error_t (^completion)(uint64_t)) {
		return exclaves_helloupcall(arg, completion);
	},

	.alloc = ^(const uint32_t npages, xnuupcallsv2_pagekind_s kind,
	    tb_error_t (^completion)(xnuupcallsv2_pagelist_s)) {
		return exclaves_memory_upcall_alloc(npages, kind, completion);
	},

	.alloc_ext = ^(const uint32_t npages, xnuupcallsv2_pageallocflagsv2_s flags, tb_error_t (^completion)(xnuupcallsv2_pagelist_s)) {
		return exclaves_memory_upcall_alloc_ext(npages, flags, completion);
	},

	.free = ^(const xnuupcallsv2_pagelist_s pages, const xnuupcallsv2_pagekind_s kind,
	    tb_error_t (^completion)(void)) {
		return exclaves_memory_upcall_free(pages, kind, completion);
	},

	.free_ext = ^(const xnuupcallsv2_pagelist_s pages, xnuupcallsv2_pagefreeflagsv2_s flags, tb_error_t (^completion)(void)) {
		return exclaves_memory_upcall_free_ext(pages, flags, completion);
	},

	.root = ^(const uint8_t exclaveid[_Nonnull 32],
	    tb_error_t (^completion)(xnuupcallsv2_storageupcallsprivate_root__result_s)) {
		return exclaves_storage_upcall_root(exclaveid, completion);
	},

	.rootex = ^(const uint32_t fstag, const uint8_t exclaveid[_Nonnull 32],
	    tb_error_t (^completion)(xnuupcallsv2_storageupcallsprivate_rootex__result_s)) {
		return exclaves_storage_upcall_rootex(fstag, exclaveid, completion);
	},

	.open = ^(const uint32_t fstag, const uint64_t rootid,
	    const uint8_t name[_Nonnull 256],
	    tb_error_t (^completion)(xnuupcallsv2_storageupcallsprivate_open__result_s)) {
		return exclaves_storage_upcall_open(fstag, rootid, name, completion);
	},

	.close = ^(const uint32_t fstag, const uint64_t fileid,
	    tb_error_t (^completion)(xnuupcallsv2_storageupcallsprivate_close__result_s)) {
		return exclaves_storage_upcall_close(fstag, fileid, completion);
	},

	.create = ^(const uint32_t fstag, const uint64_t rootid,
	    const uint8_t name[_Nonnull 256],
	    tb_error_t (^completion)(xnuupcallsv2_storageupcallsprivate_create__result_s)) {
		return exclaves_storage_upcall_create(fstag, rootid, name, completion);
	},

	.read = ^(const uint32_t fstag, const uint64_t fileid,
	    const struct xnuupcallsv2_iodesc_s *descriptor,
	    tb_error_t (^completion)(xnuupcallsv2_storageupcallsprivate_read__result_s)) {
		return exclaves_storage_upcall_read(fstag, fileid, descriptor, completion);
	},

	.write = ^(const uint32_t fstag, const uint64_t fileid,
	    const struct xnuupcallsv2_iodesc_s *descriptor,
	    tb_error_t (^completion)(xnuupcallsv2_storageupcallsprivate_write__result_s)) {
		return exclaves_storage_upcall_write(fstag, fileid, descriptor, completion);
	},

	.remove = ^(const uint32_t fstag, const uint64_t rootid,
	    const uint8_t name[_Nonnull 256],
	    tb_error_t (^completion)(xnuupcallsv2_storageupcallsprivate_remove__result_s)) {
		return exclaves_storage_upcall_remove(fstag, rootid, name, completion);
	},

	.sync = ^(const uint32_t fstag,
	    const xnuupcallsv2_syncop_s * _Nonnull op,
	    const uint64_t fileid,
	    tb_error_t (^completion)(xnuupcallsv2_storageupcallsprivate_sync__result_s)) {
		return exclaves_storage_upcall_sync(fstag, op, fileid, completion);
	},

	.readdir = ^(const uint32_t fstag,
	    const uint64_t fileid, const uint64_t buf,
	    const uint32_t length,
	    tb_error_t (^completion)(xnuupcallsv2_storageupcallsprivate_readdir__result_s)) {
		return exclaves_storage_upcall_readdir(fstag, fileid, buf, length, completion);
	},

	.getsize = ^(const uint32_t fstag, const uint64_t fileid,
	    tb_error_t (^completion)(xnuupcallsv2_storageupcallsprivate_getsize__result_s)) {
		return exclaves_storage_upcall_getsize(fstag, fileid, completion);
	},

	.sealstate = ^(const uint32_t fstag,
		tb_error_t (^completion)(xnuupcallsv2_storageupcallsprivate_sealstate__result_s)) {
		return exclaves_storage_upcall_sealstate(fstag, completion);
	},

	.queryvolumegroup = ^(const uint8_t vguuid[_Nonnull 37],
		tb_error_t (^completion)(xnuupcallsv2_storageupcallsprivate_queryvolumegroup__result_s)) {
		return exclaves_storage_upcall_queryvolumegroup(vguuid, completion);
	},

	.irqregister = ^(const uint64_t id, const int32_t index,
	    tb_error_t (^completion)(xnuupcallsv2_driverupcallsprivate_irqregister__result_s)) {
		return exclaves_driverkit_upcall_irq_register(id, index, completion);
	},

	.irqremove = ^(const uint64_t id, const int32_t index,
	    tb_error_t (^completion)(xnuupcallsv2_driverupcallsprivate_irqremove__result_s)) {
		return exclaves_driverkit_upcall_irq_remove(id, index, completion);
	},

	.irqenable = ^(const uint64_t id, const int32_t index,
	    tb_error_t (^completion)(xnuupcallsv2_driverupcallsprivate_irqenable__result_s)) {
		return exclaves_driverkit_upcall_irq_enable(id, index, completion);
	},

	.irqdisable = ^(const uint64_t id, const int32_t index,
	    tb_error_t (^completion)(xnuupcallsv2_driverupcallsprivate_irqdisable__result_s)) {
		return exclaves_driverkit_upcall_irq_disable(id, index, completion);
	},

	.timerregister = ^(const uint64_t id,
	    tb_error_t (^completion)(xnuupcallsv2_driverupcallsprivate_timerregister__result_s)) {
		return exclaves_driverkit_upcall_timer_register(id, completion);
	},

	.timerremove = ^(const uint64_t id, const uint32_t timerid,
	    tb_error_t (^completion)(xnuupcallsv2_driverupcallsprivate_timerremove__result_s)) {
		return exclaves_driverkit_upcall_timer_remove(id, timerid, completion);
	},

	.timerenable = ^(const uint64_t id, const uint32_t timerid,
	    tb_error_t (^completion)(xnuupcallsv2_driverupcallsprivate_timerenable__result_s)) {
		return exclaves_driverkit_upcall_timer_enable(id, timerid, completion);
	},

	.timerdisable = ^(const uint64_t id, const uint32_t timerid,
	    tb_error_t (^completion)(xnuupcallsv2_driverupcallsprivate_timerdisable__result_s)) {
		return exclaves_driverkit_upcall_timer_disable(id, timerid, completion);
	},

	.timersettimeout = ^(const uint64_t id, const uint32_t timerid,
	    const struct xnuupcallsv2_drivertimerspecification_s *duration,
	    tb_error_t (^completion)(xnuupcallsv2_driverupcallsprivate_timersettimeout__result_s)) {
		return exclaves_driverkit_upcall_timer_set_timeout(id, timerid, duration, completion);
	},

	.timercanceltimeout = ^(const uint64_t id, const uint32_t timerid,
	    tb_error_t (^completion)(xnuupcallsv2_driverupcallsprivate_timercanceltimeout__result_s)) {
		return exclaves_driverkit_upcall_timer_cancel_timeout(id, timerid, completion);
	},

	.lockworkloop = ^(const uint64_t id,
	    tb_error_t (^completion)(xnuupcallsv2_driverupcallsprivate_lockworkloop__result_s)) {
		return exclaves_driverkit_upcall_lock_workloop(id, completion);
	},

	.unlockworkloop = ^(const uint64_t id,
	    tb_error_t (^completion)(xnuupcallsv2_driverupcallsprivate_unlockworkloop__result_s)) {
		return exclaves_driverkit_upcall_unlock_workloop(id, completion);
	},

	.asyncnotificationsignal = ^(const uint64_t id,
	    const uint32_t notificationID,
	    tb_error_t (^completion)(xnuupcallsv2_driverupcallsprivate_asyncnotificationsignal__result_s)) {
		return exclaves_driverkit_upcall_async_notification_signal(id,
		    notificationID, completion);
	},

	.mapperactivate = ^(const uint64_t id, const uint32_t mapperIndex,
	    tb_error_t (^completion)(xnuupcallsv2_driverupcallsprivate_mapperactivate__result_s)) {
		return exclaves_driverkit_upcall_mapper_activate(id,
		    mapperIndex, completion);
	},

	.mapperdeactivate = ^(const uint64_t id, const uint32_t mapperIndex,
	    tb_error_t (^completion)(xnuupcallsv2_driverupcallsprivate_mapperdeactivate__result_s)) {
		return exclaves_driverkit_upcall_mapper_deactivate(id,
		    mapperIndex, completion);
	},

	.anesetpowerstate = ^(const uint64_t id, const uint32_t desiredState,
	    tb_error_t (^completion)(xnuupcallsv2_aneupcallsprivate_anesetpowerstate__result_s)) {
		return exclaves_driverkit_upcall_ane_setpowerstate(id, desiredState,
			completion);
	},

	.aneworksubmit = ^(const uint64_t id, const uint64_t requestID,
	    const uint32_t taskDescriptorCount, const uint64_t submitTimestamp,
	    tb_error_t (^completion)(xnuupcallsv2_aneupcallsprivate_aneworksubmit__result_s)) {
		return exclaves_driverkit_upcall_ane_worksubmit(id, requestID,
			taskDescriptorCount, submitTimestamp, completion);
	},

	.aneworkbegin = ^(const uint64_t id, const uint64_t requestID,
	    const uint64_t beginTimestamp,
	    tb_error_t (^completion)(xnuupcallsv2_aneupcallsprivate_aneworkbegin__result_s)) {
		return exclaves_driverkit_upcall_ane_workbegin(id, requestID,
			beginTimestamp, completion);
	},

	.aneworkend = ^(const uint64_t id, const uint64_t requestID,
	    tb_error_t (^completion)(xnuupcallsv2_aneupcallsprivate_aneworkend__result_s)) {
		return exclaves_driverkit_upcall_ane_workend(id, requestID, completion);
	},

	.notificationsignal = ^(const uint64_t id, const uint32_t mask,
	    tb_error_t (^completion)(xnuupcallsv2_notificationupcallsprivate_notificationsignal__result_s)) {
		return exclaves_driverkit_upcall_notification_signal(id, mask,
		    completion);
	},

	.suspend = ^(const uint32_t flags,
	    tb_error_t (^completion)(xnuupcallsv2_conclaveupcallsprivate_suspend__result_s)) {
		return exclaves_conclave_upcall_suspend(flags, completion);
	},

	.stop = ^(const uint32_t flags,
	    tb_error_t (^completion)(xnuupcallsv2_conclaveupcallsprivate_stop__result_s)) {
		return exclaves_conclave_upcall_stop(flags, completion);
	},
	.crashinfo = ^(const xnuupcallsv2_conclavesharedbuffer_s *shared_buf,
	    const uint32_t length,
	    tb_error_t (^completion)(xnuupcallsv2_conclaveupcallsprivate_crashinfo__result_s)) {
		return exclaves_conclave_upcall_crash_info(shared_buf, length, completion);
	},
	/* END IGNORE CODESTYLE */
};
#pragma clang diagnostic pop

kern_return_t
exclaves_register_upcall_handler(exclaves_id_t upcall_id, void *upcall_context,
    exclaves_upcall_handler_t upcall_handler)
{
	assert3u(upcall_id, <, NUM_XNUPROXY_UPCALLS);
	assert(upcall_handler != NULL);

	lck_mtx_assert(&exclaves_boot_lock, LCK_MTX_ASSERT_OWNED);
	assert(exclaves_upcall_handlers[upcall_id].handler == NULL);

	exclaves_upcall_handlers[upcall_id] =
	    (exclaves_upcall_handler_registration_t){
		.handler = upcall_handler,
		.context = upcall_context,
	};

	return KERN_SUCCESS;
}

kern_return_t
exclaves_upcall_init(void)
{
	lck_mtx_assert(&exclaves_boot_lock, LCK_MTX_ASSERT_OWNED);

#ifdef EXCLAVES_OBSOLETE_UPCALL_TESTING
#if DEVELOPMENT || DEBUG
	kern_return_t kr;
	kr = exclaves_register_upcall_handler(
		XNUPROXY_UPCALL_HELLOUPCALL, NULL,
		exclaves_test_hello_upcall_handler);
	assert3u(kr, ==, KERN_SUCCESS);
#endif /* DEVELOPMENT || DEBUG */
#endif // EXCLAVES_OBSOLETE_UPCALL_TESTING

	tb_endpoint_t tb_upcall_ep = tb_endpoint_create_with_value(
		TB_TRANSPORT_TYPE_XNU, EXCLAVES_ID_TIGHTBEAM_UPCALL,
		TB_ENDPOINT_OPTIONS_NONE);

	tb_endpoint_t tb_upcall_v2_ep = tb_endpoint_create_with_value(
		TB_TRANSPORT_TYPE_XNU, EXCLAVES_ID_TIGHTBEAM_UPCALL_V2,
		TB_ENDPOINT_OPTIONS_NONE);

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-qual" /* FIXME: rdar://103647654 */
	tb_error_t error = xnuupcalls_xnuupcalls__server_start(tb_upcall_ep,
	    (xnuupcalls_xnuupcalls__server_s *)&exclaves_tightbeam_upcalls);
	tb_error_t error2 = xnuupcallsv2_xnuupcalls__server_start(tb_upcall_v2_ep,
	    (xnuupcallsv2_xnuupcalls__server_s *)&exclaves_tightbeam_upcalls_v2);
#pragma clang diagnostic pop

	return (error == TB_ERROR_SUCCESS && error2 == TB_ERROR_SUCCESS) ? KERN_SUCCESS : KERN_FAILURE;
}

/* Unslid pointers defining the range of code which triggers upcall handlers */
uintptr_t exclaves_upcall_range_start;
uintptr_t exclaves_upcall_range_end;

__startup_func
static void
initialize_exclaves_upcall_range(void)
{
	exclaves_upcall_range_start = VM_KERNEL_UNSLIDE(&exclaves_upcall_start_label);
	assert3u(exclaves_upcall_range_start, !=, 0);
	exclaves_upcall_range_end = VM_KERNEL_UNSLIDE(&exclaves_upcall_end_label);
	assert3u(exclaves_upcall_range_end, !=, 0);
}
STARTUP(EARLY_BOOT, STARTUP_RANK_MIDDLE, initialize_exclaves_upcall_range);

bool
exclaves_upcall_in_range(uintptr_t addr, bool slid)
{
	return slid ?
	       exclaves_in_range(addr, (uintptr_t)&exclaves_upcall_start_label, (uintptr_t)&exclaves_upcall_end_label) :
	       exclaves_in_range(addr, exclaves_upcall_range_start, exclaves_upcall_range_end);
}

OS_NOINLINE
kern_return_t
exclaves_call_upcall_handler(exclaves_id_t upcall_id)
{
	kern_return_t kr = KERN_INVALID_CAPABILITY;

	__assert_only thread_t thread = current_thread();
	assert3u(thread->th_exclaves_state & TH_EXCLAVES_UPCALL, !=, 0);

	exclaves_tag_t tag = Exclaves_L4_GetMessageTag();

	Exclaves_L4_IpcBuffer_t *ipcb = Exclaves_L4_IpcBuffer();
	exclaves_badge_t badge = XNUPROXY_CR_UPCALL_BADGE(ipcb);

	exclaves_upcall_handler_registration_t upcall_handler = {};

	if (upcall_id < NUM_XNUPROXY_UPCALLS) {
		upcall_handler = exclaves_upcall_handlers[upcall_id];
	}
	if (upcall_handler.handler) {
		__asm__ volatile ( "EXCLAVES_UPCALL_START:\n\t");
		kr = upcall_handler.handler(upcall_handler.context, &tag, badge);
		__asm__ volatile ("EXCLAVES_UPCALL_END:\n\t");
		Exclaves_L4_SetMessageTag(tag);
	}

	return kr;
}

/* -------------------------------------------------------------------------- */
#pragma mark Testing


static tb_error_t
exclaves_helloupcall(const uint64_t arg, tb_error_t (^completion)(uint64_t))
{
#if DEVELOPMENT || DEBUG
	exclaves_debug_printf(show_test_output,
	    "%s: Hello Tightbeam Upcall!\n", __func__);
	tb_error_t ret = completion(~arg);
	task_stop_conclave_upcall();
	STACKSHOT_TESTPOINT(TP_UPCALL);
	/* Emit kdebug event for kperf sampling testing */
	KDBG(BSDDBG_CODE(DBG_BSD_KDEBUG_TEST, 0xaa));
	return ret;
#else
	(void)arg;
	(void)completion;

	return TB_ERROR_SUCCESS;
#endif /* DEVELOPMENT || DEBUG */
}

#if DEVELOPMENT || DEBUG

#ifdef EXCLAVES_OBSOLETE_UPCALL_TESTING
static kern_return_t
exclaves_test_upcall_handler(void *context, exclaves_tag_t *tag,
    exclaves_badge_t badge)
{
#pragma unused(context, badge)
	Exclaves_L4_IpcBuffer_t *ipcb = Exclaves_L4_IpcBuffer();
	assert(ipcb != NULL);

	Exclaves_L4_Word_t mrs = Exclaves_L4_MessageTag_Mrs(*tag);
	assert(mrs < Exclaves_L4_IpcBuffer_Mrs);
	Exclaves_L4_Word_t crs = Exclaves_L4_MessageTag_Crs(*tag);
	assert(crs == 0);
	Exclaves_L4_Word_t label = Exclaves_L4_MessageTag_Label(*tag);

	/* setup test reply message */
	*tag = Exclaves_L4_MessageTag(mrs, 0, ~label, Exclaves_L4_False);
	for (int i = 0; i < mrs; i++) {
		Exclaves_L4_SetMessageMr(i, ~Exclaves_L4_GetMessageMr(i));
	}

	return KERN_SUCCESS;
}
#endif // EXCLAVES_OBSOLETE_UPCALL_TESTING

static int
exclaves_hello_upcall_test(__unused int64_t in, int64_t *out)
{
	tb_error_t tb_result;
	exclaveschelloserver_tests_s client;
	const unsigned long request = 0xdecafbadfeedfaceul;

	if (exclaves_get_status() != EXCLAVES_STATUS_AVAILABLE) {
		exclaves_debug_printf(show_test_output,
		    "%s: SKIPPED: Exclaves not available\n", __func__);
		*out = -1;
		return 0;
	}

	exclaves_debug_printf(show_test_output, "%s: STARTING\n", __func__);

	tb_endpoint_t ep = tb_endpoint_create_with_value(TB_TRANSPORT_TYPE_XNU,
	    EXCLAVES_ID_HELLO_EXCLAVE_EP, TB_ENDPOINT_OPTIONS_NONE);

	tb_result = exclaveschelloserver_tests__init(&client, ep);
	assert3u(tb_result, ==, TB_ERROR_SUCCESS);

	tb_result = exclaveschelloserver_tests_default_upcall(&client, request, ^(exclaveschelloserver_result_s result) {
		assert3u(tb_result, ==, TB_ERROR_SUCCESS);
		assert3u(result.result, ==, 1);
		assert3u(result.reply, ==, ((request >> 32) | (request << 32)));
	});

	exclaves_debug_printf(show_test_output, "%s: SUCCESS\n", __func__);
	*out = 1;

	return KERN_SUCCESS;
}
SYSCTL_TEST_REGISTER(exclaves_hello_upcall_test, exclaves_hello_upcall_test);

#ifdef EXCLAVES_OBSOLETE_UPCALL_TESTING
static kern_return_t
exclaves_test_hello_upcall_handler(void *context, exclaves_tag_t *tag,
    exclaves_badge_t badge)
{
	/* HelloUpcall test handler */
	assert(context == NULL);
	exclaves_debug_printf(show_test_output, "%s: Hello Upcall!\n", __func__);
	task_stop_conclave_upcall();
	STACKSHOT_TESTPOINT(TP_UPCALL);
	/* Emit kdebug event for kperf sampling testing */
	KDBG(BSDDBG_CODE(DBG_BSD_KDEBUG_TEST, 0xaa));
	return exclaves_test_upcall_handler(context, tag, badge);
}
#endif // EXCLAVES_OBSOLETE_UPCALL_TESTING

#endif /* DEVELOPMENT || DEBUG */

#endif /* __has_include(<Tightbeam/tightbeam.h>) */

#else /* CONFIG_EXCLAVES */

kern_return_t
exclaves_call_upcall_handler(exclaves_id_t upcall_id)
{
	(void)upcall_id;
	return KERN_NOT_SUPPORTED;
}

kern_return_t
exclaves_register_upcall_handler(exclaves_id_t upcall_id, void *upcall_context,
    exclaves_upcall_handler_t upcall_handler)
{
	(void)upcall_id;
	(void)upcall_context;
	(void)upcall_handler;

	return KERN_NOT_SUPPORTED;
}

#endif /* CONFIG_EXCLAVES */
