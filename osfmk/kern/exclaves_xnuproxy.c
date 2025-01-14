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

#if CONFIG_EXCLAVES

#include <stdint.h>
#include <mach/kern_return.h>
#include <kern/assert.h>
#include <kern/misc_protos.h>
#include <kern/locks.h>
#include <kern/thread.h>
#include <vm/pmap.h>
#include <mach/exclaves_l4.h>

#include "exclaves_debug.h"
#include "exclaves_xnuproxy.h"
#include "exclaves_resource.h"
#include "exclaves_upcalls.h"
#include "exclaves_internal.h"
#include "exclaves_inspection.h"

#include "kern/exclaves.tightbeam.h"

#include <xnuproxy/messages.h>

/* -------------------------------------------------------------------------- */
#pragma mark IPC bootstrap

/* Lock protecting the use of the bootstrap scheduling context */
static LCK_MTX_DECLARE(exclaves_xnuproxy_lock, &exclaves_lck_grp);

/*
 * Bootstrap context. Used for context allocate/free. Initialized in
 * exclaves_xnuproxy_init().
 */
static exclaves_ctx_t exclaves_bootstrap_ctx = {};

/*
 * Switch the current thread to use the bootstrap context. Stash the old context
 * into the supplied arguments.
 * Returns with exclaves_xnuproxy_lock held.
 */
static void
exclaves_bootstrap_context_acquire(exclaves_ctx_t *save_ctx)
{
	assert3p(exclaves_bootstrap_ctx.ipcb, !=, NULL);
	assert3u(save_ctx->scid, !=, exclaves_bootstrap_ctx.scid);

	lck_mtx_lock(&exclaves_xnuproxy_lock);

	thread_t thread = current_thread();

	*save_ctx = thread->th_exclaves_ipc_ctx;

	thread->th_exclaves_ipc_ctx = exclaves_bootstrap_ctx;

	LCK_MTX_ASSERT(&exclaves_xnuproxy_lock, LCK_MTX_ASSERT_OWNED);
}

/*
 * Restore the scheduling context of the current thread.
 * Returns with exclaves_xnuproxy_lock released.
 */
static void
exclaves_bootstrap_context_release(const exclaves_ctx_t *restore_ctx)
{
	assert3u(restore_ctx->scid, !=, exclaves_bootstrap_ctx.scid);

	LCK_MTX_ASSERT(&exclaves_xnuproxy_lock, LCK_MTX_ASSERT_OWNED);

	thread_t thread = current_thread();
	assert3p(thread->th_exclaves_ipc_ctx.ipcb, ==, exclaves_bootstrap_ctx.ipcb);

	/* Reset */
	thread->th_exclaves_ipc_ctx = *restore_ctx;

	lck_mtx_unlock(&exclaves_xnuproxy_lock);
}

/* -------------------------------------------------------------------------- */
#pragma mark IPC buffer count

/*
 * Number of allocated ipcb buffers. Estimates the number of active exclave
 * threads.
 */
static _Atomic size_t exclaves_ipcb_cnt;

size_t
exclaves_ipc_buffer_count(void)
{
	return os_atomic_load(&exclaves_ipcb_cnt, relaxed);
}

static void
exclaves_ipc_buffer_count_inc(void)
{
	os_atomic_inc(&exclaves_ipcb_cnt, relaxed);
}

static void
exclaves_ipc_buffer_count_dec(void)
{
	__assert_only size_t orig_ipcb_cnt =
	    os_atomic_dec_orig(&exclaves_ipcb_cnt, relaxed);
	assert3u(orig_ipcb_cnt, >=, 1);
}

/* -------------------------------------------------------------------------- */
#pragma mark IPC buffer cache

/*
 * A (simple, for now...) cache of IPC buffers for communicating with XNU-Proxy.
 * The cache itself is realtime safe and relies on a spin lock for
 * synchronization. However, if there's no cached buffer available, the calling
 * code will fallback to doing a full IPC buffer allocation with xnu-proxy. This
 * involves taking a mutex and is not realtime safe.
 */

/*
 * Determines the maximum size of the buffer cache. Can be overriden via an EDT
 * entry or boot-arg.
 */
TUNABLE_DEV_WRITEABLE(unsigned int, exclaves_ipc_buffer_cache_max,
    "exclaves_ipcb_cache", 16);

/* Current count of entries in the buffer cache. */
static unsigned int exclaves_ipc_buffer_cache_count = 0;

/* Intrusive linked list within the unused IPC buffer */
typedef struct exclaves_ipc_buffer_cache_item {
	struct exclaves_ipc_buffer_cache_item *next;
	Exclaves_L4_Word_t scid;
}__attribute__((__packed__)) exclaves_ipc_buffer_cache_item_t;

static_assert(Exclaves_L4_IpcBuffer_Size >=
    sizeof(exclaves_ipc_buffer_cache_item_t),
    "Invalid Exclaves_L4_IpcBuffer_Size");

static LCK_SPIN_DECLARE(exclaves_ipc_buffer_cache_lock, &exclaves_lck_grp);
static exclaves_ipc_buffer_cache_item_t *exclaves_ipc_buffer_cache;

static bool
exclaves_ipc_buffer_cache_alloc(exclaves_ctx_t *ctx)
{
	lck_spin_lock(&exclaves_ipc_buffer_cache_lock);

	if (exclaves_ipc_buffer_cache_count == 0) {
		lck_spin_unlock(&exclaves_ipc_buffer_cache_lock);
		return false;
	}

	assert3p(exclaves_ipc_buffer_cache, !=, NULL);

	exclaves_ipc_buffer_cache_item_t *cached_buffer = exclaves_ipc_buffer_cache;
	exclaves_ipc_buffer_cache = cached_buffer->next;

	exclaves_ipc_buffer_cache_count--;

	lck_spin_unlock(&exclaves_ipc_buffer_cache_lock);

	ctx->ipcb = (void *)cached_buffer;
	ctx->scid = cached_buffer->scid;
	ctx->usecnt = 0;

	/*
	 * Zero out this usage of the buffer to avoid any confusion in
	 * xnu-proxy.
	 */
	cached_buffer->next = NULL;
	cached_buffer->scid = 0;

	return true;
}

static bool
exclaves_ipc_buffer_cache_free(exclaves_ctx_t *ctx)
{
	assert3u(ctx->scid, !=, exclaves_bootstrap_ctx.scid);

	/* Zero out the IPC buffer to avoid having old IPC data lying around. */
	bzero(ctx->ipcb, Exclaves_L4_IpcBuffer_Size);

	lck_spin_lock(&exclaves_ipc_buffer_cache_lock);

#if 0 /* Removed with the fix for rdar://126257712 */
	/* Don't free into the cache if the cache has hit its limit. */
	if (exclaves_ipc_buffer_cache_count == exclaves_ipc_buffer_cache_max) {
		lck_spin_unlock(&exclaves_ipc_buffer_cache_lock);
		return false;
	}
#endif

	exclaves_ipc_buffer_cache_item_t *cached_buffer = NULL;

	cached_buffer = (void *)ctx->ipcb;
	cached_buffer->scid = ctx->scid;

	ctx->ipcb = NULL;
	ctx->scid = 0;
	ctx->usecnt = 0;

	cached_buffer->next = exclaves_ipc_buffer_cache;
	exclaves_ipc_buffer_cache = cached_buffer;

	exclaves_ipc_buffer_cache_count++;

	lck_spin_unlock(&exclaves_ipc_buffer_cache_lock);

	return true;
}

static kern_return_t
exclaves_ipc_buffer_cache_init(void)
{
	if (exclaves_ipc_buffer_cache_max == 0) {
		return KERN_SUCCESS;
	}

	kern_return_t kr = KERN_FAILURE;

	assert3p(exclaves_ipc_buffer_cache, ==, NULL);

	exclaves_ctx_t *ctx = kalloc_type(exclaves_ctx_t,
	    exclaves_ipc_buffer_cache_max, Z_WAITOK | Z_ZERO | Z_NOFAIL);

	/*
	 * Pre-warm the cache by allocating up to cache_max and then releasing
	 * the allocated contexts back into the cache.
	 */
	for (unsigned int i = 0; i < exclaves_ipc_buffer_cache_max; i++) {
		kr = exclaves_xnuproxy_ctx_alloc(&ctx[i]);
		if (kr != KERN_SUCCESS) {
			kfree_type(exclaves_ctx_t,
			    exclaves_ipc_buffer_cache_max, ctx);
			return kr;
		}
	}

	/*
	 * Release the newly allocated contexts so they ends up in the cache. We
	 * know this will succeed because the only failure modes of
	 * exclaves_xnuproxy_ctx_free are if the downcall fails. The downcall
	 * won't be used here as we *know* that the buffer cache is active.
	 */
	for (unsigned int i = 0; i < exclaves_ipc_buffer_cache_max; i++) {
		kr = exclaves_xnuproxy_ctx_free(&ctx[i]);
		assert3u(kr, ==, KERN_SUCCESS);
	}

	kfree_type(exclaves_ctx_t, exclaves_ipc_buffer_cache_max, ctx);

	return KERN_SUCCESS;
}


/* -------------------------------------------------------------------------- */
#pragma mark xnu-proxy calls

static xnuproxy_cmd_s xnuproxy_cmd_client = {0};

kern_return_t
exclaves_xnuproxy_ctx_alloc(exclaves_ctx_t *ctx)
{
	assert3p(ctx, !=, NULL);

	/* Try to allocate it from the cache. */
	if (exclaves_ipc_buffer_cache_alloc(ctx)) {
		assert(ctx->usecnt == 0);
		return KERN_SUCCESS;
	}

	/*
	 * Fallback to a full allocation with xnuproxy. This must be done in the
	 * context of the bootstrap scheduling context.
	 */
	exclaves_ctx_t stash_ctx = {};
	__block exclaves_ctx_t local_ctx = {};

	exclaves_bootstrap_context_acquire(&stash_ctx);

	/* This may spawn a new exclaves thread. */
	thread_exclaves_state_flags_t state = current_thread()->th_exclaves_state;
	current_thread()->th_exclaves_state |= TH_EXCLAVES_SPAWN_EXPECTED;

	tb_error_t ret = xnuproxy_cmd_ipccontextallocate(&xnuproxy_cmd_client,
	    ^(xnuproxy_ipccontext_s c) {
		local_ctx.ipcb = (Exclaves_L4_IpcBuffer_t *)phystokv(c.buffer);
		local_ctx.scid = c.scid;
	});

	/* Restore the old state (which itself may have set the SPAWN flag).  */
	current_thread()->th_exclaves_state = state;

	exclaves_bootstrap_context_release(&stash_ctx);

	if (ret != TB_ERROR_SUCCESS) {
		exclaves_debug_printf(show_errors,
		    "allocate context: failure %u\n", ret);
		return KERN_FAILURE;
	}

	/* Update count. */
	exclaves_ipc_buffer_count_inc();

	*ctx = local_ctx;

	assert(ctx->usecnt == 0);
	return KERN_SUCCESS;
}

kern_return_t
exclaves_xnuproxy_ctx_free(exclaves_ctx_t *ctx)
{
	assert3p(ctx, !=, NULL);

	/* exclaves_bootstrap_ctx.scid should never be freed. */
	if (ctx->scid == exclaves_bootstrap_ctx.scid) {
		return KERN_SUCCESS;
	}

	assert(ctx->usecnt == 0);
	/* Try to free it back to the cache. */
	if (exclaves_ipc_buffer_cache_free(ctx)) {
		return KERN_SUCCESS;
	}

	/*
	 * Fallback to a full free with xnuproxy. This must be done in the
	 * context of the bootstrap scheduling context.
	 */
	exclaves_ctx_t stash_ctx = {};
	__block exclaves_ctx_t local_ctx = *ctx;

	exclaves_bootstrap_context_acquire(&stash_ctx);

	xnuproxy_ipccontext_s c = {
		.scid = local_ctx.scid,
	};

	tb_error_t ret = xnuproxy_cmd_ipccontextfree(&xnuproxy_cmd_client, &c);

	exclaves_bootstrap_context_release(&stash_ctx);

	if (ret != TB_ERROR_SUCCESS) {
		exclaves_debug_printf(show_errors,
		    "free context: failure %u\n", ret);
		return KERN_FAILURE;
	}

	ctx->ipcb = NULL;
	ctx->scid = 0;
	ctx->usecnt = 0;

	/* Update count. */
	exclaves_ipc_buffer_count_dec();

	return KERN_SUCCESS;
}

static size_t
countof_char_v(const char_v_s *cv)
{
	assert3p(cv, !=, NULL);

	__block size_t count = 0;

	char__v_visit(cv,
	    ^( __unused size_t i, __unused const xnuproxy_char_s item) {
		count++;
	});

	return count;
}

static void
copy_char_v(const char_v_s *src, char *dst)
{
	assert3p(src, !=, NULL);
	assert3p(dst, !=, NULL);

	char__v_visit(src,
	    ^(size_t i, const xnuproxy_char_s item) {
		dst[i] = item;
	});
}

/*
 * Iterate over all the resources calling cb for each one.
 */
kern_return_t
exclaves_xnuproxy_resource_info(void (^cb)(const char *name, const char *domain,
    xnuproxy_resourcetype_s, uint64_t id, bool))
{
	/* BEGIN IGNORE CODESTYLE */
	tb_error_t ret = xnuproxy_cmd_resourceinfo(&xnuproxy_cmd_client,
	    ^(xnuproxy_resourceinfo_v_s ri) {
		xnuproxy_resourceinfo__v_visit(&ri,
		    ^(__unused size_t i, const xnuproxy_resourceinfo_s *item) {
			char name_copy[countof_char_v(&item->name)];
			copy_char_v(&item->name, name_copy);

			char domain_copy[countof_char_v(&item->domain)];
			copy_char_v(&item->domain, domain_copy);

			cb(name_copy, domain_copy,
			    (xnuproxy_resourcetype_s)item->type, item->id,
			    item->connected);
		});
	});
	/* END IGNORE CODESTYLE */

	if (ret != TB_ERROR_SUCCESS) {
		exclaves_debug_printf(show_errors,
		    "resource info: failure %u\n", ret);
		return KERN_FAILURE;
	}

	return KERN_SUCCESS;
}

kern_return_t
exclaves_xnuproxy_pmm_usage(void)
{
	tb_error_t ret = xnuproxy_cmd_pmmmemusage(&xnuproxy_cmd_client);
	if (ret != TB_ERROR_SUCCESS) {
		exclaves_debug_printf(show_errors,
		    "pmm usage: failure %u\n", ret);
		return KERN_FAILURE;
	}

	return KERN_SUCCESS;
}

/* -------------------------------------------------------------------------- */
#pragma mark exclaves xnu-proxy downcall

#define exclaves_xnuproxy_endpoint_call_show_progress(operation, step, \
	    eid, scid, status) \
	exclaves_debug_printf(show_progress, \
	    "exclaves: xnu proxy endpoint " #operation " " #step ":\t" \
	    "endpoint id %ld scid 0x%lx status %u\n", \
	    (eid), (scid), (status))
OS_NOINLINE
kern_return_t
exclaves_xnuproxy_endpoint_call(Exclaves_L4_Word_t endpoint_id)
{
	kern_return_t kr = KERN_SUCCESS;
	thread_t thread = current_thread();
	bool interrupted = false;

	Exclaves_L4_Word_t scid = thread->th_exclaves_ipc_ctx.scid;
	Exclaves_L4_IpcBuffer_t *ipcb = thread->th_exclaves_ipc_ctx.ipcb;
	xnuproxy_msg_status_t status =
	    XNUPROXY_MSG_STATUS_PROCESSING;

	XNUPROXY_CR_ENDPOINT_ID(ipcb) = endpoint_id;
	XNUPROXY_CR_STATUS(ipcb) = status;

	exclaves_xnuproxy_endpoint_call_show_progress(call, entry,
	    endpoint_id, scid, status);

	assert3u(thread->th_exclaves_state & TH_EXCLAVES_STATE_ANY, ==, 0);
	thread->th_exclaves_state |= TH_EXCLAVES_RPC;
	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EXCLAVES, MACH_EXCLAVES_RPC)
	    | DBG_FUNC_START, scid, endpoint_id);

	while (1) {
		kr = exclaves_run(thread, interrupted);
		assert(kr == KERN_SUCCESS || kr == KERN_ABORTED);

		/* A wait was interrupted. */
		interrupted = kr == KERN_ABORTED;

		status = (xnuproxy_msg_status_t)
		    XNUPROXY_CR_STATUS(ipcb);

		switch (status) {
		case XNUPROXY_MSG_STATUS_PROCESSING:
			exclaves_xnuproxy_endpoint_call_show_progress(call, yielded,
			    endpoint_id, scid, status);
			continue;

		case XNUPROXY_MSG_STATUS_REPLY:
			exclaves_xnuproxy_endpoint_call_show_progress(call, returned,
			    endpoint_id, scid, status);
			kr = KERN_SUCCESS;
			break;

		case XNUPROXY_MSG_STATUS_UPCALL:
			thread->th_exclaves_state |= TH_EXCLAVES_UPCALL;
			endpoint_id = XNUPROXY_CR_ENDPOINT_ID(ipcb);
			KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EXCLAVES, MACH_EXCLAVES_UPCALL)
			    | DBG_FUNC_START, scid, endpoint_id);
			exclaves_xnuproxy_endpoint_call_show_progress(upcall, entry,
			    endpoint_id, scid, status);
			kr = exclaves_call_upcall_handler(endpoint_id);
			XNUPROXY_CR_STATUS(ipcb) =
			    XNUPROXY_MSG_STATUS_PROCESSING;
			/* TODO: More state returned than Success or OperationInvalid? */
			XNUPROXY_CR_RETVAL(ipcb) =
			    (kr == KERN_SUCCESS) ? Exclaves_L4_Success :
			    Exclaves_L4_ErrorOperationInvalid;
			KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EXCLAVES, MACH_EXCLAVES_UPCALL)
			    | DBG_FUNC_END);
			thread->th_exclaves_state &= ~TH_EXCLAVES_UPCALL;
			exclaves_xnuproxy_endpoint_call_show_progress(upcall, returned,
			    endpoint_id, scid,
			    (unsigned int)XNUPROXY_CR_RETVAL(ipcb));
			continue;

		default:
			// Should we have an assert(valid return) here?
			exclaves_xnuproxy_endpoint_call_show_progress(call, failed,
			    endpoint_id, scid, status);
			kr = KERN_FAILURE;
			break;
		}
		break;
	}

	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EXCLAVES, MACH_EXCLAVES_RPC)
	    | DBG_FUNC_END);
	thread->th_exclaves_state &= ~TH_EXCLAVES_RPC;

	/* This condition provides fast path and also ensures that collection
	 * thread will never block on AST (it does have only
	 * TH_EXCLAVES_INSPECTION_NOINSPECT flag).
	 *
	 * The th_exclaves_inspection_state condition below has to be done after
	 * cleanup of TH_EXCLAVES_RPC. Compiler must not reorder it.
	 * With opposite order, Stackshot could put the thread with RPC flag on collection
	 * list but the thread would be free to continue and to release its SCID.
	 */
	os_compiler_barrier();
	if ((os_atomic_load(&thread->th_exclaves_inspection_state,
	    relaxed) & ~TH_EXCLAVES_INSPECTION_NOINSPECT) != 0) {
		exclaves_inspection_check_ast();
	}

	return kr;
}


/* -------------------------------------------------------------------------- */
#pragma mark exclaves xnu-proxy initialisation

kern_return_t
exclaves_xnuproxy_init(uint64_t bootinfo_pa)
{
	assert3u(bootinfo_pa, !=, 0);

	kern_return_t kr = KERN_FAILURE;

	void *bootinfo_va = (void *)phystokv(bootinfo_pa);
	assert3p(bootinfo_va, !=, NULL);
	const size_t bootinfo_size =
	    xnuproxy_bootinfo__marshal_sizeof(&(xnuproxy_bootinfo_s){});

	__block uint64_t endpoint = 0;

	/* BEGIN IGNORE CODESTYLE */
	tb_error_t ret = xnuproxy_bootinfo__unmarshal(bootinfo_va,
	    bootinfo_size, ^(xnuproxy_bootinfo_s bootinfo) {

		/* Do the version check. */
		if (bootinfo.version != XNUPROXY_VERSION_CURRENT) {
			exclaves_debug_printf(show_errors,
			    "exclaves: mismatched xnuproxy message version, "
			    "xnuproxy: %u, xnu: %u\n", bootinfo.version,
			    XNUPROXY_VERSION_CURRENT);
			return;
		}

		exclaves_debug_printf(show_progress,
		    "exclaves: xnuproxy message version: 0x%u\n",
		    XNUPROXY_VERSION_CURRENT);


		if (!pmap_valid_address(bootinfo.buffer)) {
			exclaves_debug_printf(show_errors,
			    "exclaves: invalid bootstrap IPC buffer address: "
			    "0x%llx\n", bootinfo.buffer);
			return;
		}

		exclaves_bootstrap_ctx.scid = bootinfo.scid;
		exclaves_bootstrap_ctx.ipcb =
		    (Exclaves_L4_IpcBuffer_t *)phystokv(bootinfo.buffer);
		assert3p(exclaves_bootstrap_ctx.ipcb, !=, NULL);
		exclaves_bootstrap_ctx.usecnt = 1;

		endpoint = bootinfo.endpointid;
	});

	/* END IGNORE CODESTYLE */
	if (ret != TB_ERROR_SUCCESS) {
		exclaves_debug_printf(show_errors,
		    "failed to unmarshal bootinfo\n");
		return KERN_FAILURE;
	}

	/*
	 * Check to see if we bailed out of the unmarshal block early which
	 * would indicate a failure (for example the version check may have
	 * failed).
	 */
	if (endpoint == 0) {
		return KERN_FAILURE;
	}

	if (exclaves_bootstrap_ctx.ipcb == NULL) {
		return KERN_FAILURE;
	}

	/* BEGIN IGNORE CODESTYLE */
	tb_endpoint_t ep = tb_endpoint_create_with_value(
	    TB_TRANSPORT_TYPE_XNU, endpoint, TB_ENDPOINT_OPTIONS_NONE);
	/* END IGNORE CODESTYLE */
	ret = xnuproxy_cmd__init(&xnuproxy_cmd_client, ep);
	if (ret != TB_ERROR_SUCCESS) {
		exclaves_debug_printf(show_errors,
		    "failed to create xnuproxy endpoint\n");
		return KERN_FAILURE;
	}
	/* Downcalls to xnu-proxy now supported. */

	kr = exclaves_ipc_buffer_cache_init();
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	return KERN_SUCCESS;
}

#endif /* CONFIG_EXCLAVES */
