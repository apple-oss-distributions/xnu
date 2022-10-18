/*
 * Copyright (c) 2021 Apple Inc. All rights reserved.
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

#include <kern/assert.h>
#include <kern/kalloc.h>
#include <kern/locks.h>
#include <kern/work_interval.h>
#include <kern/workload_config.h>

#include <mach/kern_return.h>

#include <os/hash.h>

#include <sys/queue.h>
#include <sys/work_interval.h>

#include <stdint.h>

#define WORKLOAD_CONFIG_PHASE_NAME_MAX 32

static const int max_workload_config_entry_count = 1024;
static const int workload_config_hash_size = 64;

static LCK_GRP_DECLARE(workload_config_lck_grp, "workload_config_lck_grp");

/*
 * Per-phase workload configuration.
 */
typedef struct workload_phase_entry {
	LIST_ENTRY(workload_phase_entry)   wpe_link;
	char                               wpe_phase[WORKLOAD_CONFIG_PHASE_NAME_MAX];
	workload_config_t                  wpe_config;
} workload_phase_entry_t;

/*
 * Workload configuration. As well as global information about the workload, it
 * also contains a list of per-phase configuration.
 */
typedef struct workload_config_entry {
	LIST_ENTRY(workload_config_entry)  wce_link;
	char                               wce_id[WORKLOAD_CONFIG_ID_NAME_MAX];
	const workload_phase_entry_t      *wce_default;
	LIST_HEAD(, workload_phase_entry)  wce_phases;
} workload_config_entry_t;

struct workload_config_ctx {
	workload_config_flags_t            wlcc_flags;
	int32_t                            wlcc_count;
	u_long                             wlcc_hash_mask;
	lck_mtx_t                          wlcc_mtx;
	LIST_HEAD(workload_config_hashhead, workload_config_entry) * wlcc_hashtbl;
};

struct workload_config_ctx workload_config_boot;
#if DEVELOPMENT || DEBUG
struct workload_config_ctx workload_config_devel;
#endif

__startup_func
static void
workload_config_setup(void)
{
	lck_mtx_init(&workload_config_boot.wlcc_mtx, &workload_config_lck_grp,
	    LCK_ATTR_NULL);
#if DEVELOPMENT || DEBUG
	lck_mtx_init(&workload_config_devel.wlcc_mtx, &workload_config_lck_grp,
	    LCK_ATTR_NULL);
#endif
}
STARTUP(LOCKS, STARTUP_RANK_MIDDLE, workload_config_setup);

static struct workload_config_hashhead *
workload_config_hash(workload_config_ctx_t *ctx, const char *id)
{
	const uint32_t hash = os_hash_jenkins(id, strlen(id));
	return &ctx->wlcc_hashtbl[hash & ctx->wlcc_hash_mask];
}

kern_return_t
workload_config_init(workload_config_ctx_t *ctx)
{
	extern void *hashinit(int, int, u_long *);

	lck_mtx_lock(&ctx->wlcc_mtx);

	if (ctx->wlcc_hashtbl != NULL) {
		lck_mtx_unlock(&ctx->wlcc_mtx);
		return KERN_FAILURE;
	}

	ctx->wlcc_hashtbl = hashinit(workload_config_hash_size, 0,
	    &ctx->wlcc_hash_mask);
	if (ctx->wlcc_hashtbl == NULL) {
		lck_mtx_unlock(&ctx->wlcc_mtx);
		return KERN_FAILURE;
	}

	ctx->wlcc_count = 0;

	/* By default, the configuration can enable a thread scheduling policy. */
	ctx->wlcc_flags = WLC_F_THREAD_POLICY;

	lck_mtx_unlock(&ctx->wlcc_mtx);

	return KERN_SUCCESS;
}

bool
workload_config_initialized(const workload_config_ctx_t *ctx)
{
	return ctx->wlcc_hashtbl != NULL;
}

void
workload_config_free(workload_config_ctx_t *ctx)
{
	extern void hashdestroy(void *, int, u_long);

	lck_mtx_lock(&ctx->wlcc_mtx);

	if (ctx->wlcc_hashtbl == NULL) {
		lck_mtx_unlock(&ctx->wlcc_mtx);
		return;
	}

	for (int i = 0; i < workload_config_hash_size; i++) {
		struct workload_config_hashhead *head =
		    &ctx->wlcc_hashtbl[i];
		workload_config_entry_t *entry = NULL;
		workload_config_entry_t *tmp = NULL;

		LIST_FOREACH_SAFE(entry, head, wce_link, tmp) {
			workload_phase_entry_t *phase_entry = NULL;
			workload_phase_entry_t *phase_tmp = NULL;

			LIST_FOREACH_SAFE(phase_entry, &entry->wce_phases,
			    wpe_link, phase_tmp) {
				LIST_REMOVE(phase_entry, wpe_link);
				kfree_type(workload_phase_entry_t, phase_entry);
			}

			LIST_REMOVE(entry, wce_link);
			kfree_type(workload_config_entry_t, entry);
		}
	}


	hashdestroy(ctx->wlcc_hashtbl, 0, ctx->wlcc_hash_mask);
	ctx->wlcc_hashtbl = NULL;
	ctx->wlcc_count = 0;

	lck_mtx_unlock(&ctx->wlcc_mtx);
}

/*
 * Lookup workload data by id.
 */
static workload_config_entry_t *
lookup_entry(workload_config_ctx_t *ctx, const char *id)
{
	assert(id != NULL);
	assert(ctx->wlcc_hashtbl != NULL);
	LCK_MTX_ASSERT(&ctx->wlcc_mtx, LCK_MTX_ASSERT_OWNED);

	workload_config_entry_t *entry = NULL;
	LIST_FOREACH(entry, workload_config_hash(ctx, id), wce_link) {
		if (strncmp(entry->wce_id, id, sizeof(entry->wce_id)) == 0) {
			return entry;
		}
	}

	return NULL;
}

/*
 * Given an entry for a workload, find the configuration associated with the
 * specified phase.
 */
static const workload_phase_entry_t *
lookup_config(__assert_only workload_config_ctx_t *ctx,
    const workload_config_entry_t *entry, const char *phase)
{
	assert(entry != NULL);
	assert(phase != NULL);
	LCK_MTX_ASSERT(&ctx->wlcc_mtx, LCK_MTX_ASSERT_OWNED);

	const workload_phase_entry_t *phase_entry = NULL;
	LIST_FOREACH(phase_entry, &entry->wce_phases, wpe_link) {
		if (strncmp(phase_entry->wpe_phase, phase,
		    sizeof(phase_entry->wpe_phase)) == 0) {
			return phase_entry;
		}
	}

	return NULL;
}

/*
 * Add new phase configuration for the specified workload.
 */
static kern_return_t
insert_config(workload_config_ctx_t *ctx, workload_config_entry_t *entry,
    const char *phase, const workload_config_t *new_config)
{
	assert(entry != NULL);
	assert(phase != NULL);
	assert(new_config != NULL);
	LCK_MTX_ASSERT(&ctx->wlcc_mtx, LCK_MTX_ASSERT_OWNED);

	if (lookup_config(ctx, entry, phase) != NULL) {
		return KERN_FAILURE;
	}

	workload_phase_entry_t *config =
	    kalloc_type(workload_phase_entry_t, Z_WAITOK | Z_ZERO);
	if (entry == NULL) {
		return KERN_NO_SPACE;
	}

	config->wpe_config = *new_config;

	(void) strlcpy(config->wpe_phase, phase, sizeof(config->wpe_phase));

	LIST_INSERT_HEAD(&entry->wce_phases, config, wpe_link);

	return KERN_SUCCESS;
}

/*
 * Add a new workload config for a previously unseen workload id.
 */
static kern_return_t
insert_entry(workload_config_ctx_t *ctx, const char *id, const char *phase,
    const workload_config_t *config)
{
	assert(id != NULL);
	assert(phase != NULL);
	assert(config != NULL);
	LCK_MTX_ASSERT(&ctx->wlcc_mtx, LCK_MTX_ASSERT_OWNED);

	workload_config_entry_t *entry =
	    kalloc_type(workload_config_entry_t, Z_WAITOK | Z_ZERO);
	if (entry == NULL) {
		return KERN_NO_SPACE;
	}

	if (ctx->wlcc_count == (max_workload_config_entry_count - 1)) {
		kfree_type(workload_config_entry_t, entry);
		return KERN_FAILURE;
	}

	(void) strlcpy(entry->wce_id, id, sizeof(entry->wce_id));
	if (insert_config(ctx, entry, phase, config) != KERN_SUCCESS) {
		kfree_type(workload_config_entry_t, entry);
		return KERN_FAILURE;
	}

	LIST_INSERT_HEAD(workload_config_hash(ctx, entry->wce_id), entry, wce_link);
	ctx->wlcc_count++;

	return KERN_SUCCESS;
}

/*
 * Add new workload configuration.
 */
kern_return_t
workload_config_insert(workload_config_ctx_t *ctx, const char *id,
    const char *phase, const workload_config_t *config)
{
	assert(id != NULL);
	assert(phase != NULL);
	assert(config != NULL);

	kern_return_t ret = KERN_FAILURE;

	if (strlen(id) == 0 || strlen(phase) == 0) {
		return KERN_INVALID_ARGUMENT;
	}

	lck_mtx_lock(&ctx->wlcc_mtx);

	if (ctx->wlcc_hashtbl == NULL) {
		lck_mtx_unlock(&ctx->wlcc_mtx);
		return KERN_FAILURE;
	}

	workload_config_entry_t *entry = lookup_entry(ctx, id);
	ret = (entry == NULL) ?
	    insert_entry(ctx, id, phase, config) :
	    insert_config(ctx, entry, phase, config);

	lck_mtx_unlock(&ctx->wlcc_mtx);

	return ret;
}

/*
 * Generally 'workload_config_boot' is used. 'workload_config_boot' is
 * initialized by launchd early in boot and is never loaded again.
 * 'workload_config_devel' can be loaded/unloaded at any time and if loaded,
 * overrides 'workload_config_boot' for lookups. This is useful for testing or
 * development.
 */
static workload_config_ctx_t *
get_ctx_locked(void)
{
#if DEVELOPMENT || DEBUG
	/*
	 * If a devel context has been setup, use that.
	 */
	lck_mtx_lock(&workload_config_devel.wlcc_mtx);
	if (workload_config_devel.wlcc_hashtbl != NULL) {
		return &workload_config_devel;
	}

	lck_mtx_unlock(&workload_config_devel.wlcc_mtx);

#endif /* DEVELOPMENT || DEBUG */

	lck_mtx_lock(&workload_config_boot.wlcc_mtx);
	return &workload_config_boot;
}

/*
 * Lookup the workload config for the specified phase.
 */
kern_return_t
workload_config_lookup(const char *id, const char *phase,
    workload_config_t *config)
{
	assert(id != NULL);
	assert(phase != NULL);
	assert(config != NULL);

	workload_config_ctx_t *ctx = get_ctx_locked();

	if (ctx->wlcc_hashtbl == NULL) {
		lck_mtx_unlock(&ctx->wlcc_mtx);
		return KERN_FAILURE;
	}

	const workload_config_entry_t *entry = lookup_entry(ctx, id);
	if (entry == NULL) {
		lck_mtx_unlock(&ctx->wlcc_mtx);
		return KERN_NOT_FOUND;
	}

	const workload_phase_entry_t *pe = lookup_config(ctx, entry, phase);
	if (pe == NULL) {
		lck_mtx_unlock(&ctx->wlcc_mtx);
		return KERN_NOT_FOUND;
	}

	*config = pe->wpe_config;

	lck_mtx_unlock(&ctx->wlcc_mtx);

	return KERN_SUCCESS;
}

/*
 * Lookup the workload config for the default phase.
 */
kern_return_t
workload_config_lookup_default(const char *id, workload_config_t *config)
{
	assert(id != NULL);
	assert(config != NULL);

	workload_config_ctx_t *ctx = get_ctx_locked();

	if (ctx->wlcc_hashtbl == NULL) {
		lck_mtx_unlock(&ctx->wlcc_mtx);
		return KERN_FAILURE;
	}

	const workload_config_entry_t *entry = lookup_entry(ctx, id);
	if (entry == NULL) {
		lck_mtx_unlock(&ctx->wlcc_mtx);
		return KERN_NOT_FOUND;
	}

	if (entry->wce_default == NULL) {
		lck_mtx_unlock(&ctx->wlcc_mtx);
		return KERN_FAILURE;
	}

	*config = entry->wce_default->wpe_config;

	lck_mtx_unlock(&ctx->wlcc_mtx);

	return KERN_SUCCESS;
}

/* Make the specified phase the new default phase. */
kern_return_t
workload_config_set_default(workload_config_ctx_t *ctx, const char *id,
    const char *phase)
{
	assert(id != NULL);
	assert(phase != NULL);

	lck_mtx_lock(&ctx->wlcc_mtx);

	if (ctx->wlcc_hashtbl == NULL) {
		lck_mtx_unlock(&ctx->wlcc_mtx);
		return KERN_FAILURE;
	}

	workload_config_entry_t *entry = lookup_entry(ctx, id);
	if (entry == NULL) {
		lck_mtx_unlock(&ctx->wlcc_mtx);
		return KERN_NOT_FOUND;
	}

	const workload_phase_entry_t *pe = lookup_config(ctx, entry, phase);
	if (pe == NULL) {
		lck_mtx_unlock(&ctx->wlcc_mtx);
		return KERN_NOT_FOUND;
	}

	entry->wce_default = pe;

	lck_mtx_unlock(&ctx->wlcc_mtx);

	return KERN_SUCCESS;
}

/* Iterate over configurations. */
void
workload_config_iterate(bool (^cb)(const char *, const void *))
{
	workload_config_ctx_t *ctx = get_ctx_locked();

	if (ctx->wlcc_hashtbl == NULL) {
		lck_mtx_unlock(&ctx->wlcc_mtx);
		return;
	}

	for (int i = 0; i < workload_config_hash_size; i++) {
		struct workload_config_hashhead *head = &ctx->wlcc_hashtbl[i];
		workload_config_entry_t *entry = NULL;

		LIST_FOREACH(entry, head, wce_link) {
			if (cb(entry->wce_id, entry)) {
				lck_mtx_unlock(&ctx->wlcc_mtx);
				return;
			}
		}
	}

	lck_mtx_unlock(&ctx->wlcc_mtx);
}

/* Iterate over phases. */
void
workload_config_phases_iterate(const void *config,
    bool (^cb)(const char *phase, const bool is_default,
    const workload_config_t *))
{
	const workload_config_entry_t *entry = config;

	workload_phase_entry_t *phase_entry = NULL;
	LIST_FOREACH(phase_entry, &entry->wce_phases, wpe_link) {
		const bool is_default = entry->wce_default == phase_entry;
		if (cb(phase_entry->wpe_phase, is_default,
		    &phase_entry->wpe_config)) {
			return;
		}
	}
}

kern_return_t
workload_config_get_flags(workload_config_flags_t *flags)
{
	assert(flags != NULL);

	workload_config_ctx_t *ctx = get_ctx_locked();

	if (ctx->wlcc_hashtbl == NULL) {
		lck_mtx_unlock(&ctx->wlcc_mtx);
		return KERN_FAILURE;
	}

	*flags = ctx->wlcc_flags;

	lck_mtx_unlock(&ctx->wlcc_mtx);

	return KERN_SUCCESS;
}

kern_return_t
workload_config_clear_flag(workload_config_ctx_t *ctx, workload_config_flags_t flag)
{
	/* Only one flag should be cleared at a time. */
	assert3u(((flag - 1) & flag), ==, 0);

	lck_mtx_lock(&ctx->wlcc_mtx);

	if (ctx->wlcc_hashtbl == NULL) {
		lck_mtx_unlock(&ctx->wlcc_mtx);
		return KERN_FAILURE;
	}

	ctx->wlcc_flags &= ~flag;

	lck_mtx_unlock(&ctx->wlcc_mtx);

	return KERN_SUCCESS;
}

bool
workload_config_available(void)
{
	workload_config_ctx_t *ctx = get_ctx_locked();

	bool available = ctx->wlcc_hashtbl != NULL;

	lck_mtx_unlock(&ctx->wlcc_mtx);

	return available;
}
