/*
 * Copyright (c) 2019 Apple Inc. All rights reserved.
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

#include <string.h>
#include <stdbool.h>

#include <kern/assert.h>
#include <kern/cpu_data.h>
#include <kern/debug.h>
#include <kern/locks.h>
#include <kern/kalloc.h>
#include <kern/startup.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/zalloc.h>

#include <vm/vm_kern.h>
#include <vm/vm_protos.h>
#include <vm/pmap.h>

#include <mach/mach_vm.h>
#include <mach/mach_types.h>
#include <mach/mach_port.h>
#include <mach/vm_map.h>
#include <mach/vm_param.h>
#include <mach/machine/vm_param.h>

#include <sys/stat.h> /* dev_t */
#include <miscfs/devfs/devfs.h> /* must come after sys/stat.h */
#include <sys/conf.h> /* must come after sys/stat.h */
#include <sys/sysctl.h>

#include <pexpert/pexpert.h> /* PE_parse_boot_argn */

#include <libkern/libkern.h>
#include <libkern/OSKextLibPrivate.h>
#include <libkern/kernel_mach_header.h>
#include <os/atomic_private.h>
#include <os/log.h>
#include <os/overflow.h>

#include <san/kcov_data.h>
#include <san/kcov_ksancov.h>

/* header mess... */
struct uthread;
typedef struct uthread * uthread_t;

#include <sys/sysproto.h>
#include <sys/queue.h>
#include <sys/sysctl.h>
#include <sys/kdebug.h>

#define USE_PC_TABLE 0
#define KSANCOV_MAX_DEV 64
#define KSANCOV_MAX_PCS (1024U * 64)  /* default to 256k buffer => 64k pcs */

extern boolean_t ml_at_interrupt_context(void);
extern boolean_t ml_get_interrupts_enabled(void);

static void ksancov_detach(ksancov_dev_t);

static int dev_major;
static size_t nedges = 0;
static uint32_t __unused npcs = 0;

static LCK_GRP_DECLARE(ksancov_lck_grp, "ksancov_lck_grp");
static LCK_RW_DECLARE(ksancov_devs_lck, &ksancov_lck_grp);

/* array of devices indexed by devnode minor */
static ksancov_dev_t ksancov_devs[KSANCOV_MAX_DEV];
static struct ksancov_edgemap *ksancov_edgemap;

/* Global flag that enables the sanitizer hook. */
static _Atomic unsigned int ksancov_enabled = 0;

/* Toggled after ksancov_init() */
static boolean_t ksancov_initialized = false;


/* Support for gated callbacks (referred to as "on demand", "od") */
static void kcov_ksancov_bookmark_on_demand_module(uint32_t *start, uint32_t *stop);

static LCK_MTX_DECLARE(ksancov_od_lck, &ksancov_lck_grp);

/* Bookkeeping structures for gated sancov instrumentation */
struct ksancov_od_module_entry {
	char     bundle[KMOD_MAX_NAME]; /* module bundle */
	uint32_t idx; /* index into entries/handles arrays */
};

struct ksancov_od_module_handle {
	uint32_t *start; /* guards boundaries */
	uint32_t *stop;
	uint64_t *gate; /* pointer to __DATA,__sancov_gate*/
};

static struct ksancov_od_module_entry *ksancov_od_module_entries = NULL;
static struct ksancov_od_module_handle *ksancov_od_module_handles = NULL;

/* number of entries/handles allocated */
static unsigned int ksancov_od_allocated_count = 0;

/* number of registered modules */
static unsigned int ksancov_od_modules_count = 0;
/* number of modules whose callbacks are currently enabled */
static unsigned int ksancov_od_enabled_count = 0;

/* Valid values for ksancov.on_demand= boot-arg */
#define KSANCOV_OD_SUPPORT  0x0010 // Enable runtime support
#define KSANCOV_OD_LOGGING  0x0020 // Enable logging (via os_log)

__options_decl(ksancov_od_config_t, uint32_t, {
	KSANCOV_OD_NONE = 0,
	KSANCOV_OD_ENABLE_SUPPORT = 0x0010,
	KSANCOV_OD_ENABLE_LOGGING = 0x0020,
});

/* configurable at boot; enabled by default */
static ksancov_od_config_t ksancov_od_config = KSANCOV_OD_ENABLE_SUPPORT;

static unsigned ksancov_od_support_enabled = 1;
static unsigned ksancov_od_logging_enabled = 0;

SYSCTL_DECL(_kern_kcov);
SYSCTL_ULONG(_kern_kcov, OID_AUTO, nedges, CTLFLAG_RD, &nedges, "");

SYSCTL_NODE(_kern_kcov, OID_AUTO, od, CTLFLAG_RD, 0, "od");
SYSCTL_UINT(_kern_kcov_od, OID_AUTO, config, CTLFLAG_RD, &ksancov_od_config, 0, "");
SYSCTL_UINT(_kern_kcov_od, OID_AUTO, allocated_entries, CTLFLAG_RD, &ksancov_od_allocated_count, 0, "");
SYSCTL_UINT(_kern_kcov_od, OID_AUTO, modules_count, CTLFLAG_RD, &ksancov_od_modules_count, 0, "");
SYSCTL_UINT(_kern_kcov_od, OID_AUTO, enabled_count, CTLFLAG_RD, &ksancov_od_enabled_count, 0, "");
SYSCTL_UINT(_kern_kcov_od, OID_AUTO, support_enabled, CTLFLAG_RD, &ksancov_od_support_enabled, 0, "");
SYSCTL_UINT(_kern_kcov_od, OID_AUTO, logging_enabled, CTLFLAG_RW, &ksancov_od_logging_enabled, 0, "");

#define ksancov_od_log(...) do { \
	        if (ksancov_od_logging_enabled) { \
	                os_log_debug(OS_LOG_DEFAULT, __VA_ARGS__); \
	        } \
	} while (0)

__startup_func
void
ksancov_init(void)
{
	unsigned arg;

	/* handle ksancov boot-args */
	if (PE_parse_boot_argn("ksancov.on_demand", &arg, sizeof(arg))) {
		ksancov_od_config = (ksancov_od_config_t)arg;
	}

	if (ksancov_od_config & KSANCOV_OD_ENABLE_SUPPORT) {
		/* enable the runtime support for on-demand instrumentation */
		ksancov_od_support_enabled = 1;
		ksancov_od_allocated_count = 64;
		ksancov_od_module_entries = kalloc_type_tag(struct ksancov_od_module_entry,
		    ksancov_od_allocated_count, Z_WAITOK_ZERO_NOFAIL, VM_KERN_MEMORY_DIAG);
		ksancov_od_module_handles = kalloc_type_tag(struct ksancov_od_module_handle,
		    ksancov_od_allocated_count, Z_WAITOK_ZERO_NOFAIL, VM_KERN_MEMORY_DIAG);
	} else {
		ksancov_od_support_enabled = 0;
	}

	if (ksancov_od_config & KSANCOV_OD_ENABLE_LOGGING) {
		ksancov_od_logging_enabled = 1;
	} else {
		ksancov_od_logging_enabled = 0;
	}

	ksancov_initialized = true;
}

/*
 * Coverage sanitizer per-thread routines.
 */

/* Initialize per-thread sanitizer data for each new kernel thread. */
void
kcov_ksancov_init_thread(ksancov_dev_t *dev)
{
	*dev = NULL;
}


#define GUARD_SEEN     (uint32_t)0x80000000
#define GUARD_IDX_MASK (uint32_t)0x0fffffff

static void
trace_pc_guard_pcs(struct ksancov_dev *dev, uintptr_t pc)
{
	if (os_atomic_load(&dev->trace->kt_head, relaxed) >= dev->maxpcs) {
		return; /* overflow */
	}

	uint32_t idx = os_atomic_inc_orig(&dev->trace->kt_head, relaxed);
	if (__improbable(idx >= dev->maxpcs)) {
		return;
	}

	ksancov_trace_pc_ent_t *entries = (ksancov_trace_pc_ent_t *)dev->trace->kt_entries;
	entries[idx] = pc;
}

#if CONFIG_STKSZ
static void
trace_pc_guard_pcs_stk(struct ksancov_dev *dev, uintptr_t pc, uint32_t stksize)
{
	if (os_atomic_load(&dev->trace->kt_head, relaxed) >= dev->maxpcs) {
		return; /* overflow */
	}

	uint32_t idx = os_atomic_inc_orig(&dev->trace->kt_head, relaxed);
	if (__improbable(idx >= dev->maxpcs)) {
		return;
	}

	ksancov_trace_stksize_ent_t *entries = (ksancov_trace_stksize_ent_t *)dev->trace->kt_entries;
	entries[idx] = {
		.pc = pc,
		.stksize = stksize
	};
}
#endif

static void
trace_pc_guard_counter(struct ksancov_dev *dev, uint32_t *guardp)
{
	size_t idx = *guardp & GUARD_IDX_MASK;
	ksancov_counters_t *counters = dev->counters;

	/* saturating 8bit add */
	if (counters->kc_hits[idx] < KSANCOV_MAX_HITS) {
		counters->kc_hits[idx]++;
	}
}

void
kcov_ksancov_trace_guard(uint32_t *guardp, void *caller)
{
	uintptr_t pc = (uintptr_t)(VM_KERNEL_UNSLIDE(caller) - 1);

	if (guardp == NULL) {
		return;
	}

	if (__probable(ksancov_edgemap == NULL)) {
		return;
	}

	uint32_t gd = *guardp;
	if (__improbable(gd && !(gd & GUARD_SEEN))) {
		size_t idx = gd & GUARD_IDX_MASK;
		if (idx < ksancov_edgemap->ke_nedges) {
			ksancov_edgemap->ke_addrs[idx] = pc;
			*guardp |= GUARD_SEEN;
		}
	}
}

void
kcov_ksancov_trace_pc(kcov_thread_data_t *data, uint32_t *guardp, void *caller, uintptr_t sp)
{
#pragma unused(sp)
	uintptr_t pc = (uintptr_t)(VM_KERNEL_UNSLIDE(caller) - 1);
	ksancov_dev_t dev = data->ktd_device;

	/* Check that we have coverage recording enabled for a thread. */
	if (__probable(dev == NULL)) {
		return;
	}

	if (os_atomic_load(&dev->hdr->kh_enabled, relaxed) == 0) {
		return;
	}

	/*
	 * Coverage sanitizer is disabled in the code called below. This allows calling back to the kernel without
	 * the risk of killing machine with recursive calls.
	 */
	switch (dev->mode) {
	case KS_MODE_TRACE:
		trace_pc_guard_pcs(dev, pc);
		break;
#if CONFIG_STKSZ
	case KS_MODE_STKSIZE:
		trace_pc_guard_pcs_stk(dev, pc, data->ktd_stksz.kst_stksz);
		break;
#endif
	case KS_MODE_COUNTERS:
		trace_pc_guard_counter(dev, guardp);
		break;
	default:
		/*
		 * Treat all unsupported tracing modes as no-op. It is not destructive for the kernel itself just
		 * coverage sanitiser will not record anything in such case.
		 */
		;
	}
}

void
kcov_ksancov_trace_pc_guard_init(uint32_t *start, uint32_t *stop)
{
	const size_t orig_nedges = nedges;

	/* assign a unique number to each guard */
	for (uint32_t *cur = start; cur != stop; cur++) {
		/* zero means that the guard has not been assigned */
		if (*cur == 0) {
			if (nedges < KSANCOV_MAX_EDGES) {
				*cur = (uint32_t)++nedges;
			}
		}
	}

	/* only invoke kcov_ksancov_bookmark_on_demand_module if we assigned new guards */
	if (nedges > orig_nedges) {
		kcov_ksancov_bookmark_on_demand_module(start, stop);
	}
}

void
kcov_ksancov_pcs_init(uintptr_t *start, uintptr_t *stop)
{
#if USE_PC_TABLE
	static const uintptr_t pc_table_seen_flag = 0x100;

	for (; start < stop; start += 2) {
		uintptr_t pc = start[0];
		uintptr_t flags = start[1];

		/*
		 * This function gets called multiple times on the same range, so mark the
		 * ones we've seen using unused bits in the flags field.
		 */
		if (flags & pc_table_seen_flag) {
			continue;
		}

		start[1] |= pc_table_seen_flag;
		assert(npcs < KSANCOV_MAX_EDGES - 1);
		edge_addrs[++npcs] = pc;
	}
#else
	(void)start;
	(void)stop;
#endif
}

static void
kcov_ksancov_bookmark_on_demand_module(uint32_t *start, uint32_t *stop)
{
	OSKextLoadedKextSummary summary = {};
	struct ksancov_od_module_entry *entry = NULL;
	struct ksancov_od_module_handle *handle = NULL;
	uint64_t *gate_section = NULL;
	unsigned long gate_sz = 0;
	uint32_t idx = 0;

	if (!ksancov_od_support_enabled) {
		return;
	}

	if (OSKextGetLoadedKextSummaryForAddress(start, &summary) != KERN_SUCCESS) {
		return;
	}

	if (!ksancov_initialized) {
		ksancov_od_log("ksancov: Dropping %s pre-initialization\n", summary.name);
		return;
	}

	if (nedges >= KSANCOV_MAX_EDGES) {
		ksancov_od_log("ksancov: Dropping %s: maximum number of edges reached\n",
		    summary.name);
		return;
	}

	/*
	 * The __DATA,__sancov_gate section is where the compiler stores the 64-bit
	 * global variable that is used by the inline instrumentation to decide
	 * whether it should call into the runtime or not.
	 */
	gate_section = getsectdatafromheader((kernel_mach_header_t *)summary.address,
	    "__DATA", "__sancov_gate", &gate_sz);
	if (gate_sz == 0) {
		ksancov_od_log("ksancov: Dropping %s: not instrumented with gated callbacks\n",
		    summary.name);
		return;
	}

	lck_mtx_lock(&ksancov_od_lck);

	/* reallocate the bookkeeping structures if needed */
	if (ksancov_od_modules_count >= ksancov_od_allocated_count) {
		unsigned int old_ksancov_od_allocated_count = ksancov_od_allocated_count;
		ksancov_od_allocated_count += (ksancov_od_allocated_count / 2);

		ksancov_od_log("ksancov: Reallocating entries: %u -> %u\n",
		    old_ksancov_od_allocated_count,
		    ksancov_od_allocated_count);

		ksancov_od_module_entries = krealloc_type_tag(struct ksancov_od_module_entry,
		    old_ksancov_od_allocated_count,
		    ksancov_od_allocated_count,
		    ksancov_od_module_entries, Z_WAITOK_ZERO | Z_REALLOCF, VM_KERN_MEMORY_DIAG);

		ksancov_od_module_handles = krealloc_type_tag(struct ksancov_od_module_handle,
		    old_ksancov_od_allocated_count,
		    ksancov_od_allocated_count,
		    ksancov_od_module_handles, Z_WAITOK_ZERO | Z_REALLOCF, VM_KERN_MEMORY_DIAG);
	}

	/* this is the index of the entry we're going to fill in both arrays */
	idx = ksancov_od_modules_count++;

	entry = &ksancov_od_module_entries[idx];
	handle = &ksancov_od_module_handles[idx];

	handle->start = start;
	handle->stop = stop;
	handle->gate = gate_section;

	strlcpy(entry->bundle, summary.name, sizeof(entry->bundle));
	entry->idx = (uint32_t)idx;

	ksancov_od_log("ksancov: Bookmarked module %s (0x%lx - 0x%lx, %lu guards) [idx: %u]\n",
	    entry->bundle, (uintptr_t)handle->start, (uintptr_t)handle->stop,
	    handle->stop - handle->start, entry->idx);
	lck_mtx_unlock(&ksancov_od_lck);
}

/*
 * Coverage sanitizer pseudo-device code.
 */

static ksancov_dev_t
create_dev(dev_t dev)
{
	ksancov_dev_t d;

	d = kalloc_type_tag(struct ksancov_dev, Z_WAITOK_ZERO_NOFAIL, VM_KERN_MEMORY_DIAG);
	d->mode = KS_MODE_NONE;
	d->maxpcs = KSANCOV_MAX_PCS;
	d->dev = dev;
	lck_mtx_init(&d->lock, &ksancov_lck_grp, LCK_ATTR_NULL);

	return d;
}

static void
free_dev(ksancov_dev_t d)
{
	if (d->mode == KS_MODE_TRACE && d->trace) {
		kmem_free(kernel_map, (uintptr_t)d->trace, d->sz);
	} else if (d->mode == KS_MODE_COUNTERS && d->counters) {
		kmem_free(kernel_map, (uintptr_t)d->counters, d->sz);
	}
	lck_mtx_destroy(&d->lock, &ksancov_lck_grp);
	kfree_type(struct ksancov_dev, d);
}

static void *
ksancov_do_map(uintptr_t base, size_t sz, vm_prot_t prot)
{
	kern_return_t kr;
	mach_port_t mem_entry = MACH_PORT_NULL;
	mach_vm_address_t user_addr = 0;
	memory_object_size_t size = sz;

	kr = mach_make_memory_entry_64(kernel_map,
	    &size,
	    (mach_vm_offset_t)base,
	    MAP_MEM_VM_SHARE | prot,
	    &mem_entry,
	    MACH_PORT_NULL);
	if (kr != KERN_SUCCESS) {
		return NULL;
	}

	kr = mach_vm_map_kernel(get_task_map(current_task()),
	    &user_addr,
	    size,
	    0,
	    VM_MAP_KERNEL_FLAGS_ANYWHERE(),
	    mem_entry,
	    0,
	    FALSE,
	    prot,
	    prot,
	    VM_INHERIT_SHARE);

	/*
	 * At this point, either vm_map() has taken a reference on the memory entry
	 * and we can release our local reference, or the map failed and the entry
	 * needs to be freed.
	 */
	mach_memory_entry_port_release(mem_entry);

	if (kr != KERN_SUCCESS) {
		return NULL;
	}

	return (void *)user_addr;
}

/*
 * map the sancov buffer into the current process
 */
static int
ksancov_map(ksancov_dev_t d, uintptr_t *bufp, size_t *sizep)
{
	uintptr_t addr;
	size_t size = d->sz;

	switch (d->mode) {
	case KS_MODE_STKSIZE:
	case KS_MODE_TRACE:
		if (!d->trace) {
			return EINVAL;
		}
		addr = (uintptr_t)d->trace;
		break;
	case KS_MODE_COUNTERS:
		if (!d->counters) {
			return EINVAL;
		}
		addr = (uintptr_t)d->counters;
		break;
	default:
		return EINVAL; /* not configured */
	}

	void *buf = ksancov_do_map(addr, size, VM_PROT_READ | VM_PROT_WRITE);
	if (buf == NULL) {
		return ENOMEM;
	}

	*bufp = (uintptr_t)buf;
	*sizep = size;

	return 0;
}

/*
 * map the edge -> pc mapping as read-only
 */
static int
ksancov_map_edgemap(uintptr_t *bufp, size_t *sizep)
{
	uintptr_t addr;
	size_t size;

	if (ksancov_edgemap == NULL) {
		return EINVAL;
	}

	addr = (uintptr_t)ksancov_edgemap;
	size = sizeof(ksancov_edgemap_t) + ksancov_edgemap->ke_nedges * sizeof(uintptr_t);

	void *buf = ksancov_do_map(addr, size, VM_PROT_READ);
	if (buf == NULL) {
		return ENOMEM;
	}

	*bufp = (uintptr_t)buf;
	*sizep = size;
	return 0;
}

/*
 * Device node management
 */

static int
ksancov_open(dev_t dev, int flags, int devtype, proc_t p)
{
#pragma unused(flags,devtype,p)
	const int minor_num = minor(dev);

	if (minor_num < 0 || minor_num >= KSANCOV_MAX_DEV) {
		return ENXIO;
	}

	lck_rw_lock_exclusive(&ksancov_devs_lck);

	if (ksancov_devs[minor_num]) {
		lck_rw_unlock_exclusive(&ksancov_devs_lck);
		return EBUSY;
	}

	ksancov_dev_t d = create_dev(dev);
	if (!d) {
		lck_rw_unlock_exclusive(&ksancov_devs_lck);
		return ENOMEM;
	}
	ksancov_devs[minor_num] = d;

	if (ksancov_edgemap == NULL) {
		uintptr_t buf;
		size_t sz = sizeof(struct ksancov_edgemap) + nedges * sizeof(uintptr_t);

		kern_return_t kr = kmem_alloc(kernel_map, &buf, sz,
		    KMA_DATA | KMA_ZERO | KMA_PERMANENT, VM_KERN_MEMORY_DIAG);
		if (kr) {
			printf("ksancov: failed to allocate edge addr map\n");
			lck_rw_unlock_exclusive(&ksancov_devs_lck);
			return ENOMEM;
		}

		ksancov_edgemap = (void *)buf;
		ksancov_edgemap->ke_magic = KSANCOV_EDGEMAP_MAGIC;
		ksancov_edgemap->ke_nedges = (uint32_t)nedges;
	}

	lck_rw_unlock_exclusive(&ksancov_devs_lck);

	return 0;
}

static int
ksancov_trace_alloc(ksancov_dev_t d, ksancov_mode_t mode, size_t maxpcs)
{
	if (d->mode != KS_MODE_NONE) {
		return EBUSY; /* trace/counters already created */
	}
	assert(d->trace == NULL);

	uintptr_t buf;
	size_t sz;

	if (mode == KS_MODE_TRACE) {
		if (os_mul_and_add_overflow(maxpcs, sizeof(ksancov_trace_pc_ent_t),
		    sizeof(struct ksancov_trace), &sz)) {
			return EINVAL;
		}
	} else if (mode == KS_MODE_STKSIZE) {
		if (os_mul_and_add_overflow(maxpcs, sizeof(ksancov_trace_stksize_ent_t),
		    sizeof(struct ksancov_trace), &sz)) {
			return EINVAL;
		}
	} else {
		return EINVAL;
	}

	/* allocate the shared memory buffer */
	kern_return_t kr = kmem_alloc(kernel_map, &buf, sz, KMA_DATA | KMA_ZERO,
	    VM_KERN_MEMORY_DIAG);
	if (kr != KERN_SUCCESS) {
		return ENOMEM;
	}

	struct ksancov_trace *trace = (struct ksancov_trace *)buf;
	trace->kt_hdr.kh_magic = (mode == KS_MODE_TRACE) ? KSANCOV_TRACE_MAGIC : KSANCOV_STKSIZE_MAGIC;
	os_atomic_init(&trace->kt_head, 0);
	os_atomic_init(&trace->kt_hdr.kh_enabled, 0);
	trace->kt_maxent = (uint32_t)maxpcs;

	d->trace = trace;
	d->sz = sz;
	d->maxpcs = maxpcs;
	d->mode = mode;

	return 0;
}

static int
ksancov_counters_alloc(ksancov_dev_t d)
{
	if (d->mode != KS_MODE_NONE) {
		return EBUSY; /* trace/counters already created */
	}
	assert(d->counters == NULL);

	uintptr_t buf;
	size_t sz = sizeof(struct ksancov_counters) + ksancov_edgemap->ke_nedges * sizeof(uint8_t);

	/* allocate the shared memory buffer */
	kern_return_t kr = kmem_alloc(kernel_map, &buf, sz, KMA_DATA | KMA_ZERO,
	    VM_KERN_MEMORY_DIAG);
	if (kr != KERN_SUCCESS) {
		return ENOMEM;
	}

	ksancov_counters_t *counters = (ksancov_counters_t *)buf;
	counters->kc_hdr.kh_magic = KSANCOV_COUNTERS_MAGIC;
	counters->kc_nedges = ksancov_edgemap->ke_nedges;
	os_atomic_init(&counters->kc_hdr.kh_enabled, 0);

	d->counters = counters;
	d->sz = sz;
	d->mode = KS_MODE_COUNTERS;

	return 0;
}

/*
 * attach a thread to a ksancov dev instance
 */
static int
ksancov_attach(ksancov_dev_t d, thread_t th)
{
	if (d->mode == KS_MODE_NONE) {
		return EINVAL; /* not configured */
	}

	if (th != current_thread()) {
		/* can only attach to self presently */
		return EINVAL;
	}

	kcov_thread_data_t *data = kcov_get_thread_data(th);
	if (data->ktd_device) {
		return EBUSY; /* one dev per thread */
	}

	if (d->thread != THREAD_NULL) {
		ksancov_detach(d);
	}

	d->thread = th;
	thread_reference(d->thread);

	os_atomic_store(&data->ktd_device, d, relaxed);
	os_atomic_add(&ksancov_enabled, 1, relaxed);
	kcov_enable();

	return 0;
}

extern void
thread_wait(
	thread_t        thread,
	boolean_t       until_not_runnable);


/*
 * disconnect thread from ksancov dev
 */
static void
ksancov_detach(ksancov_dev_t d)
{
	if (d->thread == THREAD_NULL) {
		/* no thread attached */
		return;
	}

	/* disconnect dev from thread */
	kcov_thread_data_t *data = kcov_get_thread_data(d->thread);
	if (data->ktd_device != NULL) {
		assert(data->ktd_device == d);
		os_atomic_store(&data->ktd_device, NULL, relaxed);
	}

	if (d->thread != current_thread()) {
		/* wait until it's safe to yank */
		thread_wait(d->thread, TRUE);
	}

	assert(ksancov_enabled >= 1);
	os_atomic_sub(&ksancov_enabled, 1, relaxed);
	kcov_disable();

	/* drop our thread reference */
	thread_deallocate(d->thread);
	d->thread = THREAD_NULL;
}

static int
ksancov_close(dev_t dev, int flags, int devtype, proc_t p)
{
#pragma unused(flags,devtype,p)
	const int minor_num = minor(dev);

	if (minor_num < 0 || minor_num >= KSANCOV_MAX_DEV) {
		return ENXIO;
	}

	lck_rw_lock_exclusive(&ksancov_devs_lck);
	ksancov_dev_t d = ksancov_devs[minor_num];
	ksancov_devs[minor_num] = NULL; /* dev no longer discoverable */
	lck_rw_unlock_exclusive(&ksancov_devs_lck);

	/*
	 * No need to lock d here as there is and will be no one having its
	 * reference except for this thread and the one which is going to
	 * be detached below.
	 */

	if (!d) {
		return ENXIO;
	}

	if (d->mode != KS_MODE_NONE && d->hdr != NULL) {
		os_atomic_store(&d->hdr->kh_enabled, 0, relaxed); /* stop tracing */
	}

	ksancov_detach(d);
	free_dev(d);

	return 0;
}

static void
ksancov_testpanic(volatile uint64_t guess)
{
	const uint64_t tgt = 0xf85de3b12891c817UL;

#define X(n) ((tgt & (0xfUL << (4*n))) == (guess & (0xfUL << (4*n))))

	if (X(0)) {
		if (X(1)) {
			if (X(2)) {
				if (X(3)) {
					if (X(4)) {
						if (X(5)) {
							if (X(6)) {
								if (X(7)) {
									if (X(8)) {
										if (X(9)) {
											if (X(10)) {
												if (X(11)) {
													if (X(12)) {
														if (X(13)) {
															if (X(14)) {
																if (X(15)) {
																	panic("ksancov: found test value");
																}
															}
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
}

static int
ksancov_handle_on_demand_cmd(struct ksancov_on_demand_msg *kmsg)
{
	struct ksancov_od_module_entry *entry = NULL;
	struct ksancov_od_module_handle *handle = NULL;
	ksancov_on_demand_operation_t op = kmsg->operation;
	int ret = 0;

	lck_mtx_lock(&ksancov_od_lck);

	/* find the entry/handle to the module */
	for (unsigned int idx = 0; idx < ksancov_od_modules_count; idx++) {
		entry = &ksancov_od_module_entries[idx];
		if (strncmp(entry->bundle, kmsg->bundle, sizeof(entry->bundle)) == 0) {
			handle = &ksancov_od_module_handles[idx];
			break;
		}
	}

	if (handle == NULL) {
		ksancov_od_log("ksancov: Could not find module '%s'\n", kmsg->bundle);
		lck_mtx_unlock(&ksancov_od_lck);
		return EINVAL;
	}

	switch (op) {
	case KS_OD_GET_GATE:
		/* Get whether on-demand instrumentation is enabled in a given module */
		if (handle->gate) {
			kmsg->gate = *handle->gate;
		} else {
			ret = EINVAL;
		}
		break;
	case KS_OD_SET_GATE:
		/* Toggle callback invocation for a given module */
		if (handle->gate) {
			ksancov_od_log("ksancov: Setting gate for '%s': %llu\n",
			    kmsg->bundle, kmsg->gate);
			if (kmsg->gate != *handle->gate) {
				if (kmsg->gate) {
					ksancov_od_enabled_count++;
				} else {
					ksancov_od_enabled_count--;
				}
				*handle->gate = kmsg->gate;
			}
		} else {
			ret = EINVAL;
		}
		break;
	case KS_OD_GET_RANGE:
		/* Get which range of the guards table covers the given module */
		ksancov_od_log("ksancov: Range for '%s': %u, %u\n",
		    kmsg->bundle, *handle->start, *(handle->stop - 1));
		kmsg->range.start = *handle->start;
		kmsg->range.stop = *(handle->stop - 1);
		break;
	default:
		ret = EINVAL;
		break;
	}

	lck_mtx_unlock(&ksancov_od_lck);
	return ret;
}

static int
ksancov_ioctl(dev_t dev, unsigned long cmd, caddr_t _data, int fflag, proc_t p)
{
#pragma unused(fflag,p)
	const int minor_num = minor(dev);

	if (minor_num < 0 || minor_num >= KSANCOV_MAX_DEV) {
		return ENXIO;
	}

	struct ksancov_buf_desc *mcmd;
	void *data = (void *)_data;

	lck_rw_lock_shared(&ksancov_devs_lck);
	ksancov_dev_t d = ksancov_devs[minor_num];
	if (!d) {
		lck_rw_unlock_shared(&ksancov_devs_lck);
		return EINVAL;         /* dev not open */
	}

	int ret = 0;

	switch (cmd) {
	case KSANCOV_IOC_TRACE:
	case KSANCOV_IOC_STKSIZE:
		lck_mtx_lock(&d->lock);
		ksancov_mode_t mode = (cmd == KSANCOV_IOC_TRACE) ? KS_MODE_TRACE : KS_MODE_STKSIZE;
		ret = ksancov_trace_alloc(d, mode, *(size_t *)data);
		lck_mtx_unlock(&d->lock);
		break;
	case KSANCOV_IOC_COUNTERS:
		lck_mtx_lock(&d->lock);
		ret = ksancov_counters_alloc(d);
		lck_mtx_unlock(&d->lock);
		break;
	case KSANCOV_IOC_MAP:
		mcmd = (struct ksancov_buf_desc *)data;
		lck_mtx_lock(&d->lock);
		ret = ksancov_map(d, &mcmd->ptr, &mcmd->sz);
		lck_mtx_unlock(&d->lock);
		break;
	case KSANCOV_IOC_MAP_EDGEMAP:
		mcmd = (struct ksancov_buf_desc *)data;
		ret = ksancov_map_edgemap(&mcmd->ptr, &mcmd->sz);
		break;
	case KSANCOV_IOC_START:
		lck_mtx_lock(&d->lock);
		ret = ksancov_attach(d, current_thread());
		lck_mtx_unlock(&d->lock);
		break;
	case KSANCOV_IOC_NEDGES:
		*(size_t *)data = nedges;
		break;
	case KSANCOV_IOC_ON_DEMAND:
		ret = ksancov_handle_on_demand_cmd((struct ksancov_on_demand_msg *)data);
		break;
	case KSANCOV_IOC_TESTPANIC:
		ksancov_testpanic(*(uint64_t *)data);
		break;
	default:
		ret = EINVAL;
		break;
	}

	lck_rw_unlock_shared(&ksancov_devs_lck);

	return ret;
}

static int
ksancov_dev_clone(dev_t dev, int action)
{
#pragma unused(dev)
	if (action == DEVFS_CLONE_ALLOC) {
		for (int i = 0; i < KSANCOV_MAX_DEV; i++) {
			if (ksancov_devs[i] == NULL) {
				return i;
			}
		}
	} else if (action == DEVFS_CLONE_FREE) {
		return 0;
	}

	return -1;
}

static const struct cdevsw
    ksancov_cdev = {
	.d_open =  ksancov_open,
	.d_close = ksancov_close,
	.d_ioctl = ksancov_ioctl,

	.d_read = eno_rdwrt,
	.d_write = eno_rdwrt,
	.d_stop = eno_stop,
	.d_reset = eno_reset,
	.d_select = eno_select,
	.d_mmap = eno_mmap,
	.d_strategy = eno_strat,
	.d_type = 0
};

int
ksancov_init_dev(void)
{
	dev_major = cdevsw_add(-1, &ksancov_cdev);
	if (dev_major < 0) {
		printf("ksancov: failed to allocate major device node\n");
		return -1;
	}

	dev_t dev = makedev(dev_major, 0);
	void *node = devfs_make_node_clone(dev, DEVFS_CHAR, UID_ROOT, GID_WHEEL, 0666,
	    ksancov_dev_clone, KSANCOV_DEVNODE);
	if (!node) {
		printf("ksancov: failed to create device node\n");
		return -1;
	}

	return 0;
}
