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
#include <vm/vm_page.h>
#include <vm/vm_pageout.h>

#include <xnuproxy/exclaves.h>

#include "kern/exclaves.tightbeam.h"

#include "exclaves_boot.h"
#include "exclaves_debug.h"
#include "exclaves_driverkit.h"
#include "exclaves_storage.h"
#include "exclaves_test_stackshot.h"
#include "exclaves_conclave.h"

#include <sys/errno.h>

#define EXCLAVES_ID_HELLO_EXCLAVE_EP \
    (exclaves_endpoint_lookup("com.apple.service.HelloExclave"))

#define EXCLAVES_ID_SWIFT_HELLO_EXCLAVE_EP \
    (exclaves_endpoint_lookup("com.apple.service.HelloTightbeam"))

#define EXCLAVES_ID_TIGHTBEAM_UPCALL \
    ((exclaves_id_t)XNUPROXY_UPCALL_TIGHTBEAM)

extern lck_mtx_t exclaves_boot_lock;

typedef struct exclaves_upcall_handler_registration {
	exclaves_upcall_handler_t handler;
	void *context;
} exclaves_upcall_handler_registration_t;

static exclaves_upcall_handler_registration_t
    exclaves_upcall_handlers[NUM_XNUPROXY_UPCALLS];

#if DEVELOPMENT || DEBUG
static kern_return_t
exclaves_test_hello_upcall_handler(void *, exclaves_tag_t *, exclaves_badge_t);
#endif /* DEVELOPMENT || DEBUG */

#define EXCLAVES_MAX_PAGES_REQUEST (64)
static tb_error_t
exclaves_alloc_pages(uint32_t npages, xnuupcalls_pagekind_s kind,
    tb_error_t (^completion)(xnuupcalls_pagelist_s));
static tb_error_t
exclaves_free_pages(const uint32_t pages[EXCLAVES_MAX_PAGES_REQUEST],
    uint32_t npages, const xnuupcalls_pagekind_s kind,
    tb_error_t (^completion)(void));

extern kern_return_t exclaves_xnu_proxy_send(xnuproxy_msg_t *,
    Exclaves_L4_Word_t *);

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
		return exclaves_alloc_pages(npages, kind, completion);
	},

	.free = ^(const uint32_t pages[_Nonnull EXCLAVES_MAX_PAGES_REQUEST],
	    const uint32_t npages, const xnuupcalls_pagekind_s kind,
	    tb_error_t (^completion)(void)) {
		return exclaves_free_pages(pages, npages, kind, completion);
	},

	.root = ^(const uint8_t exclaveid[_Nonnull 32],
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_root__result_s)) {
		return exclaves_storage_upcall_root(exclaveid, completion);
	},

	.open = ^(const enum xnuupcalls_fstag_s fstag, const uint64_t rootid,
	    const uint8_t name[_Nonnull 256],
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_open__result_s)) {
		return exclaves_storage_upcall_open(fstag, rootid, name, completion);
	},

	.close = ^(const enum xnuupcalls_fstag_s fstag, const uint64_t fileid,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_close__result_s)) {
		return exclaves_storage_upcall_close(fstag, fileid, completion);
	},

	.create = ^(const enum xnuupcalls_fstag_s fstag, const uint64_t rootid,
	    const uint8_t name[_Nonnull 256],
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_create__result_s)) {
		return exclaves_storage_upcall_create(fstag, rootid, name, completion);
	},

	.read = ^(const enum xnuupcalls_fstag_s fstag, const uint64_t fileid,
	    const struct xnuupcalls_iodesc_s *descriptor,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_read__result_s)) {
		return exclaves_storage_upcall_read(fstag, fileid, descriptor, completion);
	},

	.write = ^(const enum xnuupcalls_fstag_s fstag, const uint64_t fileid,
	    const struct xnuupcalls_iodesc_s *descriptor,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_write__result_s)) {
		return exclaves_storage_upcall_write(fstag, fileid, descriptor, completion);
	},

	.remove = ^(const enum xnuupcalls_fstag_s fstag, const uint64_t rootid,
	    const uint8_t name[_Nonnull 256],
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_remove__result_s)) {
		return exclaves_storage_upcall_remove(fstag, rootid, name, completion);
	},

	.sync = ^(const enum xnuupcalls_fstag_s fstag,
	    const enum xnuupcalls_syncop_s op,
	    const uint64_t fileid,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_sync__result_s)) {
		return exclaves_storage_upcall_sync(fstag, op, fileid, completion);
	},

	.readdir = ^(const enum xnuupcalls_fstag_s fstag,
	    const uint64_t fileid, const uint64_t buf,
	    const uint32_t length,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_readdir__result_s)) {
		return exclaves_storage_upcall_readdir(fstag, fileid, buf, length, completion);
	},

	.getsize = ^(const enum xnuupcalls_fstag_s fstag, const uint64_t fileid,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_getsize__result_s)) {
		return exclaves_storage_upcall_getsize(fstag, fileid, completion);
	},

	.irq_register = ^(const uint64_t id, const int32_t index,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_irq_register__result_s)) {
		return exclaves_driverkit_upcall_irq_register(id, index, completion);
	},

	.irq_remove = ^(const uint64_t id, const int32_t index,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_irq_remove__result_s)) {
		return exclaves_driverkit_upcall_irq_remove(id, index, completion);
	},

	.irq_enable = ^(const uint64_t id, const int32_t index,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_irq_enable__result_s)) {
		return exclaves_driverkit_upcall_irq_enable(id, index, completion);
	},

	.irq_disable = ^(const uint64_t id, const int32_t index,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_irq_disable__result_s)) {
		return exclaves_driverkit_upcall_irq_disable(id, index, completion);
	},

	.timer_register = ^(const uint64_t id,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_timer_register__result_s)) {
		return exclaves_driverkit_upcall_timer_register(id, completion);
	},

	.timer_remove = ^(const uint64_t id, const uint32_t timer_id,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_timer_remove__result_s)) {
		return exclaves_driverkit_upcall_timer_remove(id, timer_id, completion);
	},

	.timer_enable = ^(const uint64_t id, const uint32_t timer_id,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_timer_enable__result_s)) {
		return exclaves_driverkit_upcall_timer_enable(id, timer_id, completion);
	},

	.timer_disable = ^(const uint64_t id, const uint32_t timer_id,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_timer_disable__result_s)) {
		return exclaves_driverkit_upcall_timer_disable(id, timer_id, completion);
	},

	.timer_set_timeout = ^(const uint64_t id, const uint32_t timer_id,
	    const struct xnuupcalls_drivertimerspecification_s *duration,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_timer_set_timeout__result_s)) {
		return exclaves_driverkit_upcall_timer_set_timeout(id, timer_id, duration, completion);
	},

	.timer_cancel_timeout = ^(const uint64_t id, const uint32_t timer_id,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_timer_cancel_timeout__result_s)) {
		return exclaves_driverkit_upcall_timer_cancel_timeout(id, timer_id, completion);
	},

	.lock_wl = ^(const uint64_t id,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_lock_wl__result_s)) {
		return exclaves_driverkit_upcall_lock_wl(id, completion);
	},

	.unlock_wl = ^(const uint64_t id,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_unlock_wl__result_s)) {
		return exclaves_driverkit_upcall_unlock_wl(id, completion);
	},

	.async_notification_signal = ^(const uint64_t id,
	    const uint32_t notificationID,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_async_notification_signal__result_s)) {
		return exclaves_driverkit_upcall_async_notification_signal(id,
		    notificationID, completion);
	},

	.mapper_activate = ^(const uint64_t id, const uint32_t mapperIndex,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_mapper_activate__result_s)) {
		return exclaves_driverkit_upcall_mapper_activate(id,
		    mapperIndex, completion);
	},

	.mapper_deactivate = ^(const uint64_t id, const uint32_t mapperIndex,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_mapper_deactivate__result_s)) {
		return exclaves_driverkit_upcall_mapper_deactivate(id,
		    mapperIndex, completion);
	},

	.notification_signal = ^(const uint64_t id, const uint32_t mask,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_notification_signal__result_s)) {
		return exclaves_driverkit_upcall_notification_signal(id, mask,
		    completion);
	},

	.ane_setpowerstate = ^(const uint64_t id, const uint32_t desiredState,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_ane_setpowerstate__result_s)) {
		return exclaves_driverkit_upcall_ane_setpowerstate(id, desiredState,
			completion);
	},

	.ane_worksubmit = ^(const uint64_t id, const uint64_t requestID,
	    const uint32_t taskDescriptorCount, const uint64_t submitTimestamp,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_ane_worksubmit__result_s)) {
		return exclaves_driverkit_upcall_ane_worksubmit(id, requestID,
			taskDescriptorCount, submitTimestamp, completion);
	},

	.ane_workbegin = ^(const uint64_t id, const uint64_t requestID,
	    const uint64_t beginTimestamp,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_ane_workbegin__result_s)) {
		return exclaves_driverkit_upcall_ane_workbegin(id, requestID,
			beginTimestamp, completion);
	},

	.ane_workend = ^(const uint64_t id, const uint64_t requestID,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_ane_workend__result_s)) {
		return exclaves_driverkit_upcall_ane_workend(id, requestID, completion);
	},

	.conclave_suspend = ^(const uint32_t flags,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_conclave_suspend__result_s)) {
		return exclaves_conclave_upcall_suspend(flags, completion);
	},

	.conclave_stop = ^(const uint32_t flags,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_conclave_stop__result_s)) {
		return exclaves_conclave_upcall_stop(flags, completion);
	},
	.conclave_crash_info = ^(const xnuupcalls_conclavesharedbuffer_s *shared_buf,
	    const uint32_t length,
	    tb_error_t (^completion)(xnuupcalls_xnuupcalls_conclave_crash_info__result_s)) {
		return exclaves_conclave_upcall_crash_info(shared_buf, length, completion);
	},
	/* END IGNORE CODESTYLE */
};

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

static kern_return_t
exclaves_upcall_init(void)
{
	lck_mtx_assert(&exclaves_boot_lock, LCK_MTX_ASSERT_OWNED);

#if DEVELOPMENT || DEBUG
	kern_return_t kr;
	kr = exclaves_register_upcall_handler(
		XNUPROXY_UPCALL_HELLOUPCALL, NULL,
		exclaves_test_hello_upcall_handler);
	assert3u(kr, ==, KERN_SUCCESS);
#endif /* DEVELOPMENT || DEBUG */

	tb_endpoint_t tb_upcall_ep = tb_endpoint_create_with_value(
		TB_TRANSPORT_TYPE_XNU, EXCLAVES_ID_TIGHTBEAM_UPCALL,
		TB_ENDPOINT_OPTIONS_NONE);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-qual" /* FIXME: rdar://103647654 */
	tb_error_t error = xnuupcalls_xnuupcalls__server_start(tb_upcall_ep,
	    (xnuupcalls_xnuupcalls__server_s *)&exclaves_tightbeam_upcalls);
#pragma clang diagnostic pop

#if XNUPROXY_MSG_VERSION >= 2
	if (error == TB_ERROR_SUCCESS) {
		kern_return_t kkr;
		xnuproxy_msg_t msg = {
			.cmd = XNUPROXY_CMD_UPCALL_READY,
		};
		kkr = exclaves_xnu_proxy_send(&msg, NULL);
		assert3u(kkr, ==, KERN_SUCCESS);
	}
#endif /* XNUPROXY_MSG_VERSION >= 2 */

	return error == TB_ERROR_SUCCESS ? KERN_SUCCESS : KERN_FAILURE;
}

EXCLAVES_BOOT_TASK(exclaves_upcall_init, EXCLAVES_BOOT_RANK_FIRST);

OS_NOINLINE
kern_return_t
exclaves_call_upcall_handler(exclaves_id_t upcall_id)
{
	kern_return_t kr = KERN_INVALID_CAPABILITY;

	exclaves_tag_t tag = Exclaves_L4_GetMessageTag();

	Exclaves_L4_IpcBuffer_t *ipcb = Exclaves_L4_IpcBuffer();
	exclaves_badge_t badge = XNUPROXY_CR_UPCALL_BADGE(ipcb);

	exclaves_upcall_handler_registration_t upcall_handler = {};

	if (upcall_id < NUM_XNUPROXY_UPCALLS) {
		upcall_handler = exclaves_upcall_handlers[upcall_id];
	}
	if (upcall_handler.handler) {
		kr = upcall_handler.handler(upcall_handler.context, &tag, badge);
		Exclaves_L4_SetMessageTag(tag);
	}

	return kr;
}

/* -------------------------------------------------------------------------- */

#pragma mark exclaves allocation

#if CONFIG_EXCLAVES

static tb_error_t
exclaves_alloc_pages(uint32_t npages, xnuupcalls_pagekind_s kind __unused,
    tb_error_t (^completion)(xnuupcalls_pagelist_s))
{
	vm_page_t page_list = NULL;
	vm_page_t sequestered = NULL;
	unsigned p = 0;

	xnuupcalls_pagelist_s pagelist = {};

	assert3u(npages, <=, ARRAY_COUNT(pagelist.pages));
	if (npages > ARRAY_COUNT(pagelist.pages)) {
		panic("npages");
	}

	while (npages) {
		vm_page_t next;
		vm_page_alloc_list(npages, KMA_ZERO | KMA_NOFAIL, &page_list);

		vm_object_lock(exclaves_object);
		for (vm_page_t mem = page_list; mem != VM_PAGE_NULL; mem = next) {
			next = mem->vmp_snext;
			if (vm_page_created(mem)) {
				// avoid ml_static_mfree() pages due to 117505258
				mem->vmp_snext = sequestered;
				sequestered = mem;
				continue;
			}

			vm_page_lock_queues();
			vm_page_wire(mem, VM_KERN_MEMORY_EXCLAVES, FALSE);
			vm_page_unlock_queues();
			/* Insert the page into the exclaves object */
			vm_page_insert_wired(mem, exclaves_object,
			    ptoa(VM_PAGE_GET_PHYS_PAGE(mem)),
			    VM_KERN_MEMORY_EXCLAVES);

			/* Retype via SPTM to SK owned */
			sptm_retype_params_t retype_params = {
				.raw = SPTM_RETYPE_PARAMS_NULL
			};
			sptm_retype(ptoa(VM_PAGE_GET_PHYS_PAGE(mem)),
			    XNU_DEFAULT, SK_DEFAULT, retype_params);

			pagelist.pages[p++] = VM_PAGE_GET_PHYS_PAGE(mem);
			npages--;
		}
		vm_object_unlock(exclaves_object);
	}

	vm_page_free_list(sequestered, FALSE);

	return completion(pagelist);
}

static tb_error_t
exclaves_free_pages(const uint32_t pages[EXCLAVES_MAX_PAGES_REQUEST],
    uint32_t npages, __unused const xnuupcalls_pagekind_s kind,
    tb_error_t (^completion)(void))
{
	/* Get pointer for page list paddr */
	assert(npages <= EXCLAVES_MAX_PAGES_REQUEST);
	if (npages > EXCLAVES_MAX_PAGES_REQUEST) {
		panic("npages");
	}

	vm_object_lock(exclaves_object);
	for (size_t p = 0; p < npages; p++) {
		/* Find the page in the exclaves object. */
		vm_page_t m;
		m = vm_page_lookup(exclaves_object, ptoa(pages[p]));

		/* Assert we found the page */
		assert(m != VM_PAGE_NULL);

		/* Via SPTM, verify the page type is something ownable by xnu. */
		assert3u(sptm_get_frame_type(ptoa(VM_PAGE_GET_PHYS_PAGE(m))),
		    ==, XNU_DEFAULT);

		/* Free the page */
		vm_page_lock_queues();
		vm_page_free(m);
		vm_page_unlock_queues();
	}
	vm_object_unlock(exclaves_object);

	return completion();
}
#endif /* CONFIG_EXCLAVES */

/* -------------------------------------------------------------------------- */

/* -------------------------------------------------------------------------- */
#pragma mark Testing


static tb_error_t
exclaves_helloupcall(const uint64_t arg, tb_error_t (^completion)(uint64_t))
{
#if DEVELOPMENT || DEBUG
	exclaves_debug_printf(show_test_output,
	    "%s: Hello Tightbeam Upcall!\n", __func__);
	tb_error_t ret = completion(~arg);
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

static int
exclaves_hello_upcall_test(__unused int64_t in, int64_t *out)
{
	kern_return_t kr = KERN_SUCCESS;

	if (exclaves_get_status() != EXCLAVES_STATUS_AVAILABLE) {
		exclaves_debug_printf(show_test_output,
		    "%s: SKIPPED: Exclaves not available\n", __func__);
		*out = -1;
		return 0;
	}

	exclaves_debug_printf(show_test_output, "%s: STARTING\n", __func__);

	Exclaves_L4_IpcBuffer_t *ipcb;
	kr = exclaves_allocate_ipc_buffer((void**)&ipcb);
	assert(kr == KERN_SUCCESS);
	assert(ipcb != NULL);

	const Exclaves_L4_Word_t request = 0xdecafbadfeedfaceul;
	Exclaves_L4_SetMessageMr(0, request);
	exclaves_tag_t tag = Exclaves_L4_MessageTag(1, 0, 0x1330ul,
	    Exclaves_L4_False);

	exclaves_debug_printf(show_test_output,
	    "exclaves: exclaves_endpoint_call() sending request 0x%lx, "
	    "tag 0x%llx, label 0x%lx\n", request, tag,
	    Exclaves_L4_MessageTag_Label(tag));

	exclaves_error_t error;
	kr = exclaves_endpoint_call(IPC_PORT_NULL, EXCLAVES_ID_HELLO_EXCLAVE_EP,
	    &tag, &error);
	assert(kr == KERN_SUCCESS);

	Exclaves_L4_Word_t reply = Exclaves_L4_GetMessageMr(0);
	exclaves_debug_printf(show_test_output,
	    "exclaves: exclaves_endpoint_call() returned reply 0x%lx, "
	    "tag 0x%llx, label 0x%lx, error 0x%llx\n", reply, tag,
	    Exclaves_L4_MessageTag_Label(tag), error);

	assert(error == Exclaves_L4_Success);
	assert(Exclaves_L4_MessageTag_Mrs(tag) == 1);
	assert(reply == ((request >> 32) | (request << 32)));
	assert((uint16_t)Exclaves_L4_MessageTag_Label(tag) == (uint16_t)0x1331ul);

	kr = exclaves_free_ipc_buffer();
	assert(kr == KERN_SUCCESS);

	exclaves_debug_printf(show_test_output, "%s: SUCCESS\n", __func__);
	*out = 1;

	return 0;
}
SYSCTL_TEST_REGISTER(exclaves_hello_upcall_test, exclaves_hello_upcall_test);

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
