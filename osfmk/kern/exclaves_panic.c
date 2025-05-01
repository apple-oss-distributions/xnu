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

#include <kern/assert.h>
#include <kern/misc_protos.h>
#include <kern/thread.h>

#include <mach/exclaves_l4.h>

#include <uuid/uuid.h>

#include <xnuproxy/panic.h>

#include "exclaves_boot.h"
#include "exclaves_debug.h"
#include "exclaves_internal.h"
#include "exclaves_panic.h"
#include "exclaves_resource.h"
#include "exclaves_xnuproxy.h"

#include "kern/exclaves.tightbeam.h"

#define EXCLAVES_PANIC_FOUR_CC_FORMAT   "%c%c%c%c"
#define EXCLAVES_PANIC_FOUR_CC_CHARS(c) \
    (((c) >> 24) & 0xFF),               \
    (((c) >> 16) & 0xFF),               \
    (((c) >>  8) & 0xFF),               \
    (((c) >>  0) & 0xFF)
#define EXCLAVE_PANIC_MESSAGE_MARKER    "[Exclaves]"

// Adding 64 bytes here to accommodate the PC and LR in the panic string
#define EXCLAVES_PANIC_STRING_SIZE     \
    (sizeof(EXCLAVE_PANIC_MESSAGE_MARKER) + XNUPROXY_PANIC_MESSAGE_LEN + XNUPROXY_PANIC_NAME_BYTES + 64)

#define P2ROUNDUP(x, align) (-(-(x) & -(align)))
#define PANIC_BUFFER_PAGE_COUNT  (P2ROUNDUP(sizeof (xnuproxy_panic_buffer_t), PAGE_SIZE) / PAGE_SIZE)

static char exclaves_panic_string[EXCLAVES_PANIC_STRING_SIZE];
static char *exclaves_panic_buffer_pages[PANIC_BUFFER_PAGE_COUNT];
static xnuproxy_panic_buffer_t exclaves_panic_buffer;
static int exclaves_panic_thread_wait_forever;

static void
copy_panic_buffer_pages(pmap_paddr_t addr)
{
	uint64_t *pages = (uint64_t *)phystokv(addr);

	for (int i = 0; i < PANIC_BUFFER_PAGE_COUNT; i++) {
		exclaves_panic_buffer_pages[i] = (char *)phystokv(pages[i]);
	}

	/*
	 * For backwards compat always use the base page even if not listed
	 * explicitly.
	 */
	exclaves_panic_buffer_pages[0] = (char *)pages;

	return;
}

static void
exclaves_xnuproxy_panic_thread(void *arg __unused, wait_result_t wr __unused)
{
	assert3u(current_thread()->th_exclaves_ipc_ctx.scid, ==, 0);

	kern_return_t kr = KERN_SUCCESS;
	thread_t thread = current_thread();

	uint64_t endpoint = exclaves_service_lookup(EXCLAVES_DOMAIN_KERNEL,
	    "com.apple.service.PanicInit");
	if (endpoint == EXCLAVES_INVALID_ID) {
		exclaves_debug_printf(show_errors,
		    "exclaves: panic thread init: "
		    "failed to find stackshot service");
		return;
	}

	tb_endpoint_t setup_ep = tb_endpoint_create_with_value(
		TB_TRANSPORT_TYPE_XNU, endpoint, TB_ENDPOINT_OPTIONS_NONE);
	stackshotpanicsetup_panicinit_s client;
	tb_error_t ret = stackshotpanicsetup_panicinit__init(&client, setup_ep);
	if (ret != TB_ERROR_SUCCESS) {
		exclaves_debug_printf(show_errors,
		    "exclaves: panic thread init: "
		    "failed to initialize connection");
		return;
	}

	thread->th_exclaves_state |= TH_EXCLAVES_SPAWN_EXPECTED;

	__block uint64_t panic_scid = 0;
	stackshotpanicsetup_panicinit_panic_init(&client, ^void (uint64_t scid) {
		panic_scid = scid;
	});

	assert3u(panic_scid, !=, 0);
	thread->th_exclaves_ipc_ctx.scid = panic_scid;

	thread->th_exclaves_state &= ~TH_EXCLAVES_SPAWN_EXPECTED;

	assert3u(thread->th_exclaves_state & TH_EXCLAVES_STATE_ANY, ==, 0);
	thread->th_exclaves_state |= TH_EXCLAVES_RESUME_PANIC_THREAD;

	while (1) {
		kr = exclaves_run(thread, false);
		assert3u(kr, ==, KERN_SUCCESS);
	}
}

static bool
exclaves_panic_buffer_sync(void)
{
	char *panic_buffer = (char *)&exclaves_panic_buffer;
	size_t len = sizeof(exclaves_panic_buffer);

	/* Just return if the panic buffer initialisation hasn't happened yet.  */
	if (exclaves_panic_buffer_pages[0] == 0) {
		return KERN_NOT_SUPPORTED;
	}

	/*
	 * Initialize next page to the first page. This is for the backwards
	 * compatibility case.
	 */
	char *next_page = exclaves_panic_buffer_pages[0];
	for (int i = 0; i < PANIC_BUFFER_PAGE_COUNT; i++) {
		size_t nbytes = MIN(len, PAGE_SIZE);

		next_page = exclaves_panic_buffer_pages[i] != 0 ?
		    exclaves_panic_buffer_pages[i] : next_page + PAGE_SIZE;

		(void)memcpy(panic_buffer, next_page, nbytes);

		panic_buffer += nbytes;
		len -= nbytes;

		if (len == 0) {
			break;
		}
	}

	return KERN_SUCCESS;
}

static void
exclaves_append_panic_backtrace(void)
{
	uuid_string_t uuid_string;
	xnuproxy_panic_backtrace_word_t *words;

	assert3p(exclaves_panic_buffer_pages[0], !=, NULL);

	if ((exclaves_panic_buffer.panicked_thread.backtrace.frames >
	    XNUPROXY__PANIC_BACKTRACE_WORDS)) {
		return;
	}

	words = exclaves_panic_buffer.backtrace.words;
	paniclog_append_noflush("Exclaves backtrace:\n");
	for (size_t i = 0; i < exclaves_panic_buffer.panicked_thread.backtrace.frames; i++) {
		uuid_unparse_upper(
			(const unsigned char *)exclaves_panic_buffer.backtrace.images[words[i].image].uuid,
			uuid_string);
		paniclog_append_noflush("\t\t%s 0x%016zx\n", uuid_string,
		    exclaves_panic_buffer.backtrace.words[i].offset);
	}

	paniclog_append_noflush("\n");
	return;
}

static void
exclaves_append_panic_addl_info(xnuproxy_panicked_thread_t *ex_thread)
{
	char component_name[XNUPROXY_PANIC_NAME_BYTES] = {0};

	strlcpy(component_name, ex_thread->component.name, sizeof(component_name));

	paniclog_append_noflush(
		"\t\tAddress space ID: 0x%llx\n"
		"\t\tComponent:\n"
		"\t\t\tName: %s\n"
		"\t\t\tID: 0x%llx\n"
		"\t\t\tSelector: 0x%llx\n"
		"\t\tspace.component.endpoint.thread: " EXCLAVES_PANIC_FOUR_CC_FORMAT "."
		EXCLAVES_PANIC_FOUR_CC_FORMAT "."
		EXCLAVES_PANIC_FOUR_CC_FORMAT "."
		EXCLAVES_PANIC_FOUR_CC_FORMAT "\n"
		"\t\tThread Context:\n"
		"\t\t\tAddress: 0x%zx\n"
		"\t\t\tTSS Base: 0x%zx\n"
		"\t\t\tIPC Buffer 0x%zx\n"
		"\t\t\tSCID 0x%zx\n"
		"\t\t\tECID: 0x%zx\n"
		"\t\t\tEPID: 0x%zx\n"
		"\t\t\tStack:\n"
		"\t\t\t\tStart: 0x%zx\n"
		"\t\t\t\tSize: 0x%zx\n"
		"\t\t\t\tCall base: 0x%zx\n"
		"\t\t\tRegisters:\n"
		"\t\t\t\tLR: 0x%zx\n"
		"\t\t\t\tPC: 0x%zx\n"
		"\t\t\t\tSP: 0x%zx\n"
		"\t\t\t\tCPSR: 0x%zx\n",
		ex_thread->address_space_id, component_name,
		ex_thread->component.numeric_id, ex_thread->component.selector,
		EXCLAVES_PANIC_FOUR_CC_CHARS(ex_thread->four_cc.space),
		EXCLAVES_PANIC_FOUR_CC_CHARS(ex_thread->four_cc.component),
		EXCLAVES_PANIC_FOUR_CC_CHARS(ex_thread->four_cc.endpoint),
		EXCLAVES_PANIC_FOUR_CC_CHARS(ex_thread->four_cc.thread),
		ex_thread->thread.address, ex_thread->thread.tss_base,
		ex_thread->thread.ipc_buffer, ex_thread->thread.scheduling_context_id,
		ex_thread->thread.execution_context_id, ex_thread->thread.endpoint_id,
		ex_thread->thread.stack.start, ex_thread->thread.stack.size,
		ex_thread->thread.stack.call_base, ex_thread->thread.registers.lr,
		ex_thread->thread.registers.pc, ex_thread->thread.registers.sp,
		ex_thread->thread.registers.cpsr);
}

kern_return_t
exclaves_panic_get_string(char **string)
{
	uint32_t status = 0;
	char component_name[XNUPROXY_PANIC_NAME_BYTES] = {0};

	kern_return_t kr = exclaves_panic_buffer_sync();
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	xnuproxy_panicked_thread_t *ex_thread =
	    &exclaves_panic_buffer.panicked_thread;

	strlcpy(component_name, ex_thread->component.name, sizeof(component_name));

	status = os_atomic_load(&ex_thread->status, seq_cst);
	if (status == XNUPROXY_PANIC_UNSET) {
		return KERN_FAILURE;
	}

	snprintf(exclaves_panic_string, sizeof(exclaves_panic_string),
	    "%s %s:%s at PC: 0x%zx, LR: 0x%zx", EXCLAVE_PANIC_MESSAGE_MARKER,
	    component_name, exclaves_panic_buffer.message,
	    ex_thread->thread.registers.pc, ex_thread->thread.registers.lr);
	exclaves_panic_string[sizeof(exclaves_panic_string) - 1] = '\0';
	*string = exclaves_panic_string;

	return KERN_SUCCESS;
}

void
exclaves_panic_append_info(void)
{
	uint32_t status = 0;
	kern_return_t kr = 0;
	char *status_str;

	paniclog_append_noflush("Exclaves boot status: %s\n", exclaves_get_boot_status_string());

	kr = exclaves_panic_buffer_sync();
	if (kr != KERN_SUCCESS) {
		return;
	}

	xnuproxy_panicked_thread_t *ex_thread =
	    &exclaves_panic_buffer.panicked_thread;

	status = os_atomic_load(&ex_thread->status, seq_cst);

	switch (status) {
	case XNUPROXY_PANIC_PARTIAL:
		status_str = "PARTIAL";
		break;
	case XNUPROXY_PANIC_COMPLETE:
		status_str = "COMPLETE";
		break;
	default:
		return;
	}

	panic_info->eph_panic_flags |= EMBEDDED_PANIC_HEADER_FLAG_EXCLAVE_PANIC;

	paniclog_append_noflush("Exclaves additional info: STATUS: %s\n", status_str);
	exclaves_append_panic_addl_info(ex_thread);

	exclaves_append_panic_backtrace();
}

__attribute__((noinline, noreturn))
void
exclaves_panic_thread_wait(void)
{
	assert_wait((event_t)&exclaves_panic_thread_wait_forever, THREAD_UNINT);
	(void) thread_block(THREAD_CONTINUE_NULL);

	/* NOT REACHABLE */
	panic("Exclaves panic thread woken up");
}

void
handle_response_panic_buffer_address(pmap_paddr_t addr)
{
	return copy_panic_buffer_pages(addr);
}

kern_return_t
exclaves_panic_thread_setup(void)
{
	thread_t thread = THREAD_NULL;
	kern_return_t kr = KERN_FAILURE;

	kr = kernel_thread_start_priority(exclaves_xnuproxy_panic_thread, NULL,
	    BASEPRI_DEFAULT, &thread);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	thread_set_thread_name(thread, "EXCLAVES_PANIC_WAIT_THREAD");
	thread_deallocate(thread);

	return KERN_SUCCESS;
}

#endif /* CONFIG_ EXCLAVES */
