/*
 * Copyright (c) 2016-2021 Apple Inc. All rights reserved.
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

#include <skywalk/os_skywalk_private.h>
#include <machine/limits.h>
#include <machine/machine_routines.h>
#include <vm/vm_pageout.h>

/*
 * Region templates.
 *
 * Regions that are not eligible for user task mapping must never be
 * marked with the SKMEM_REGION_CR_MMAPOK flag.  Such regions will
 * automatically be excluded from the mappable region array at arena
 * creation time.
 *
 * Regions that allow their objects to be shared among other objects
 * must be marked with SKMEM_REGION_CR_SHAREOK.  This permits calls
 * to skmem_bufctl_{use,unuse}() on the bufctls for the objects.
 *
 * Read-only regions must be marked with SKMEM_REGION_CR_UREADONLY.
 * This will affect the protection property of the segments in those
 * regions.  This flag has no effect when the region is not mappable
 * to a user task.
 *
 * The SKMEM_REGION_CR_NOMAGAZINES flag marks the region as unsupportive
 * of the magazines layer when used by a skmem_cache.  When this flag is
 * not set, the number of objects in the region will be adjusted to
 * include the worst-case number of objects cached at the CPU layer.
 * By default, all regions have this flag set; this may be overridden
 * by each client (after making a copy).
 *
 * Regions that don't support multi-segments can be marked with the
 * SKMEM_REGION_CR_MONOLITHIC flag.  This forces exactly one segment
 * to cover all objects in the region.  This also effectively caps
 * the skmem_cache slab layer to have only a single slab.
 *
 * The correctness of the region templates is enforced at arena
 * creation time.
 */
static const struct skmem_region_params skmem_regions[SKMEM_REGIONS] = {
	/*
	 * Leading guard page(s): {mappable, no-read-write, no-cache}
	 */
	[SKMEM_REGION_GUARD_HEAD] = {
		.srp_name       = "headguard",
		.srp_id         = SKMEM_REGION_GUARD_HEAD,
		.srp_cflags     = SKMEM_REGION_CR_MMAPOK |
    SKMEM_REGION_CR_GUARD | SKMEM_REGION_CR_NOMAGAZINES |
    SKMEM_REGION_CR_NOREDIRECT,
		.srp_md_type    = NEXUS_META_TYPE_INVALID,
		.srp_md_subtype = NEXUS_META_SUBTYPE_INVALID,
	},

	/*
	 * Schema: {mappable, read-only, no-cache}
	 */
	[SKMEM_REGION_SCHEMA] = {
		.srp_name       = "schema",
		.srp_id         = SKMEM_REGION_SCHEMA,
		.srp_cflags     = SKMEM_REGION_CR_MMAPOK |
    SKMEM_REGION_CR_UREADONLY | SKMEM_REGION_CR_NOMAGAZINES |
    SKMEM_REGION_CR_NOREDIRECT | SKMEM_REGION_CR_PUREDATA,
		.srp_md_type    = NEXUS_META_TYPE_INVALID,
		.srp_md_subtype = NEXUS_META_SUBTYPE_INVALID,
	},

	/*
	 * Rings: {mappable, no-cache}
	 */
	[SKMEM_REGION_RING] = {
		.srp_name       = "ring",
		.srp_id         = SKMEM_REGION_RING,
		.srp_cflags     = SKMEM_REGION_CR_MMAPOK |
    SKMEM_REGION_CR_NOMAGAZINES | SKMEM_REGION_CR_PUREDATA,
		.srp_md_type    = NEXUS_META_TYPE_INVALID,
		.srp_md_subtype = NEXUS_META_SUBTYPE_INVALID,
	},

	/*
	 * Buffers: {mappable, shareable}
	 */
	[SKMEM_REGION_BUF] = {
		.srp_name       = "buf",
		.srp_id         = SKMEM_REGION_BUF,
		.srp_cflags     = SKMEM_REGION_CR_MMAPOK |
    SKMEM_REGION_CR_NOMAGAZINES | SKMEM_REGION_CR_IODIR_IN |
    SKMEM_REGION_CR_IODIR_OUT | SKMEM_REGION_CR_SHAREOK |
    SKMEM_REGION_CR_PUREDATA,
		.srp_md_type    = NEXUS_META_TYPE_INVALID,
		.srp_md_subtype = NEXUS_META_SUBTYPE_INVALID,
	},
	[SKMEM_REGION_RXBUF] = {
		.srp_name       = "rxbuf",
		.srp_id         = SKMEM_REGION_RXBUF,
		.srp_cflags     = SKMEM_REGION_CR_MMAPOK |
    SKMEM_REGION_CR_NOMAGAZINES | SKMEM_REGION_CR_IODIR_IN |
    SKMEM_REGION_CR_SHAREOK | SKMEM_REGION_CR_PUREDATA,
		.srp_r_obj_cnt  = 0,
		.srp_md_type    = NEXUS_META_TYPE_INVALID,
		.srp_md_subtype = NEXUS_META_SUBTYPE_INVALID,
	},
	[SKMEM_REGION_TXBUF] = {
		.srp_name       = "txbuf",
		.srp_id         = SKMEM_REGION_TXBUF,
		.srp_cflags     = SKMEM_REGION_CR_MMAPOK |
    SKMEM_REGION_CR_NOMAGAZINES | SKMEM_REGION_CR_IODIR_OUT |
    SKMEM_REGION_CR_SHAREOK | SKMEM_REGION_CR_PUREDATA,
		.srp_r_obj_cnt  = 0,
		.srp_md_type    = NEXUS_META_TYPE_INVALID,
		.srp_md_subtype = NEXUS_META_SUBTYPE_INVALID,
	},

	/*
	 * Userspace metadata: {mappable}
	 */
	[SKMEM_REGION_UMD] = {
		.srp_name       = "umd",
		.srp_id         = SKMEM_REGION_UMD,
		.srp_cflags     = SKMEM_REGION_CR_MMAPOK |
    SKMEM_REGION_CR_NOMAGAZINES,
		.srp_md_type    = NEXUS_META_TYPE_QUANTUM,
		.srp_md_subtype = NEXUS_META_SUBTYPE_PAYLOAD,
		.srp_max_frags  = 1,
	},

	/*
	 * Userspace buflet metadata: {mappable}
	 */
	[SKMEM_REGION_UBFT] = {
		.srp_name       = "ubft",
		.srp_id         = SKMEM_REGION_UBFT,
		.srp_cflags     = SKMEM_REGION_CR_MMAPOK |
    SKMEM_REGION_CR_NOMAGAZINES,
		.srp_r_obj_cnt  = 0,
		.srp_md_type    = NEXUS_META_TYPE_INVALID,
		.srp_md_subtype = NEXUS_META_SUBTYPE_INVALID,
		.srp_max_frags  = 1,
	},

	/*
	 * Tx/alloc userspace slot descriptors: {mappable, read-only, no-cache}
	 */
	[SKMEM_REGION_TXAUSD] = {
		.srp_name       = "txausd",
		.srp_id         = SKMEM_REGION_TXAUSD,
		.srp_cflags     = SKMEM_REGION_CR_MMAPOK |
    SKMEM_REGION_CR_UREADONLY | SKMEM_REGION_CR_NOMAGAZINES,
		.srp_md_type    = NEXUS_META_TYPE_INVALID,
		.srp_md_subtype = NEXUS_META_SUBTYPE_INVALID,
	},

	/*
	 * Rx/free userspace slot descriptors: {mappable, read-only, no-cache}
	 */
	[SKMEM_REGION_RXFUSD] = {
		.srp_name       = "rxfusd",
		.srp_id         = SKMEM_REGION_RXFUSD,
		.srp_cflags     = SKMEM_REGION_CR_MMAPOK |
    SKMEM_REGION_CR_UREADONLY | SKMEM_REGION_CR_NOMAGAZINES,
		.srp_md_type    = NEXUS_META_TYPE_INVALID,
		.srp_md_subtype = NEXUS_META_SUBTYPE_INVALID,
	},

	/*
	 * Shared statistics: {mappable, monolithic, no-cache}
	 */
	[SKMEM_REGION_USTATS] = {
		.srp_name       = "ustats",
		.srp_id         = SKMEM_REGION_USTATS,
		.srp_cflags     = SKMEM_REGION_CR_MMAPOK |
    SKMEM_REGION_CR_MONOLITHIC | SKMEM_REGION_CR_NOMAGAZINES |
    SKMEM_REGION_CR_PUREDATA,
		.srp_md_type    = NEXUS_META_TYPE_INVALID,
		.srp_md_subtype = NEXUS_META_SUBTYPE_INVALID,
	},

	/*
	 * Flow advisories: {mappable, read-only, monolithic, no-cache}
	 */
	[SKMEM_REGION_FLOWADV] = {
		.srp_name       = "flowadv",
		.srp_id         = SKMEM_REGION_FLOWADV,
		.srp_cflags     = SKMEM_REGION_CR_MMAPOK |
    SKMEM_REGION_CR_UREADONLY | SKMEM_REGION_CR_MONOLITHIC |
    SKMEM_REGION_CR_NOMAGAZINES | SKMEM_REGION_CR_PUREDATA,
		.srp_md_type    = NEXUS_META_TYPE_INVALID,
		.srp_md_subtype = NEXUS_META_SUBTYPE_INVALID,
	},

	/*
	 * Nexus advisories: {mappable, read-only, monolithic, no-cache}
	 */
	[SKMEM_REGION_NEXUSADV] = {
		.srp_name       = "nexusadv",
		.srp_id         = SKMEM_REGION_NEXUSADV,
		.srp_cflags     = SKMEM_REGION_CR_MMAPOK |
    SKMEM_REGION_CR_UREADONLY | SKMEM_REGION_CR_MONOLITHIC |
    SKMEM_REGION_CR_NOMAGAZINES | SKMEM_REGION_CR_PERSISTENT |
    SKMEM_REGION_CR_PUREDATA,
		.srp_md_type    = NEXUS_META_TYPE_INVALID,
		.srp_md_subtype = NEXUS_META_SUBTYPE_INVALID,
	},

	/*
	 * sysctls: {mappable, monolithic, no-cache}
	 */
	[SKMEM_REGION_SYSCTLS] = {
		.srp_name       = "sysctls",
		.srp_id         = SKMEM_REGION_SYSCTLS,
		.srp_cflags     = SKMEM_REGION_CR_MMAPOK |
    SKMEM_REGION_CR_UREADONLY | SKMEM_REGION_CR_MONOLITHIC |
    SKMEM_REGION_CR_NOMAGAZINES | SKMEM_REGION_CR_NOREDIRECT |
    SKMEM_REGION_CR_PUREDATA,
		.srp_md_type    = NEXUS_META_TYPE_INVALID,
		.srp_md_subtype = NEXUS_META_SUBTYPE_INVALID,
	},

	/*
	 * Trailing guard page(s): {mappable, no-read-write, no-cache}
	 */
	[SKMEM_REGION_GUARD_TAIL] = {
		.srp_name       = "tailguard",
		.srp_id         = SKMEM_REGION_GUARD_TAIL,
		.srp_cflags     = SKMEM_REGION_CR_MMAPOK |
    SKMEM_REGION_CR_GUARD | SKMEM_REGION_CR_NOMAGAZINES |
    SKMEM_REGION_CR_NOREDIRECT,
		.srp_md_type    = NEXUS_META_TYPE_INVALID,
		.srp_md_subtype = NEXUS_META_SUBTYPE_INVALID,
	},

	/*
	 * Kernel metadata.
	 */
	[SKMEM_REGION_KMD] = {
		.srp_name       = "kmd",
		.srp_id         = SKMEM_REGION_KMD,
		.srp_cflags     = SKMEM_REGION_CR_NOMAGAZINES,
		.srp_md_type    = NEXUS_META_TYPE_QUANTUM,
		.srp_md_subtype = NEXUS_META_SUBTYPE_PAYLOAD,
		.srp_max_frags  = 1,
	},
	[SKMEM_REGION_RXKMD] = {
		.srp_name       = "rxkmd",
		.srp_id         = SKMEM_REGION_RXKMD,
		.srp_cflags     = SKMEM_REGION_CR_NOMAGAZINES,
		.srp_r_obj_cnt  = 0,
		.srp_md_type    = NEXUS_META_TYPE_QUANTUM,
		.srp_md_subtype = NEXUS_META_SUBTYPE_PAYLOAD,
		.srp_max_frags  = 1,
	},
	[SKMEM_REGION_TXKMD] = {
		.srp_name       = "txkmd",
		.srp_id         = SKMEM_REGION_TXKMD,
		.srp_cflags     = SKMEM_REGION_CR_NOMAGAZINES,
		.srp_r_obj_cnt  = 0,
		.srp_md_type    = NEXUS_META_TYPE_QUANTUM,
		.srp_md_subtype = NEXUS_META_SUBTYPE_PAYLOAD,
		.srp_max_frags  = 1,
	},

	/*
	 * kernel buflet metadata.
	 */
	[SKMEM_REGION_KBFT] = {
		.srp_name       = "kbft",
		.srp_id         = SKMEM_REGION_KBFT,
		.srp_cflags     = SKMEM_REGION_CR_NOMAGAZINES,
		.srp_r_obj_cnt  = 0,
		.srp_md_type    = NEXUS_META_TYPE_INVALID,
		.srp_md_subtype = NEXUS_META_SUBTYPE_INVALID,
	},
	[SKMEM_REGION_RXKBFT] = {
		.srp_name       = "rxkbft",
		.srp_id         = SKMEM_REGION_RXKBFT,
		.srp_cflags     = SKMEM_REGION_CR_NOMAGAZINES,
		.srp_r_obj_cnt  = 0,
		.srp_md_type    = NEXUS_META_TYPE_INVALID,
		.srp_md_subtype = NEXUS_META_SUBTYPE_INVALID,
	},
	[SKMEM_REGION_TXKBFT] = {
		.srp_name       = "txkbft",
		.srp_id         = SKMEM_REGION_TXKBFT,
		.srp_cflags     = SKMEM_REGION_CR_NOMAGAZINES,
		.srp_r_obj_cnt  = 0,
		.srp_md_type    = NEXUS_META_TYPE_INVALID,
		.srp_md_subtype = NEXUS_META_SUBTYPE_INVALID,
	},

	/*
	 * Tx/alloc kernel slot descriptors: {no-cache}
	 */
	[SKMEM_REGION_TXAKSD] = {
		.srp_name       = "txaksd",
		.srp_id         = SKMEM_REGION_TXAKSD,
		.srp_cflags     = SKMEM_REGION_CR_NOMAGAZINES,
		.srp_md_type    = NEXUS_META_TYPE_INVALID,
		.srp_md_subtype = NEXUS_META_SUBTYPE_INVALID,
	},

	/*
	 * Rx/free kernel slot descriptors: {no-cache}
	 */
	[SKMEM_REGION_RXFKSD] = {
		.srp_name       = "rxfksd",
		.srp_id         = SKMEM_REGION_RXFKSD,
		.srp_cflags     = SKMEM_REGION_CR_NOMAGAZINES,
		.srp_md_type    = NEXUS_META_TYPE_INVALID,
		.srp_md_subtype = NEXUS_META_SUBTYPE_INVALID,
	},

	/*
	 * Statistics kernel snapshot: {no-cache}
	 */
	[SKMEM_REGION_KSTATS] = {
		.srp_name       = "kstats",
		.srp_id         = SKMEM_REGION_KSTATS,
		.srp_cflags     = SKMEM_REGION_CR_MONOLITHIC |
    SKMEM_REGION_CR_NOMAGAZINES | SKMEM_REGION_CR_PUREDATA,
		.srp_md_type    = NEXUS_META_TYPE_INVALID,
		.srp_md_subtype = NEXUS_META_SUBTYPE_INVALID,
	},

	/*
	 * Intrinsic objects.
	 */
	[SKMEM_REGION_INTRINSIC] = {
		.srp_name       = "intrinsic",
		.srp_id         = SKMEM_REGION_INTRINSIC,
		.srp_cflags     = SKMEM_REGION_CR_PSEUDO,
		.srp_md_type    = NEXUS_META_TYPE_INVALID,
		.srp_md_subtype = NEXUS_META_SUBTYPE_INVALID,
	},
};

const skmem_region_id_t skmem_pp_region_ids[SKMEM_PP_REGIONS] = {
	SKMEM_REGION_BUF,
	SKMEM_REGION_RXBUF,
	SKMEM_REGION_TXBUF,
	SKMEM_REGION_KMD,
	SKMEM_REGION_RXKMD,
	SKMEM_REGION_TXKMD,
	SKMEM_REGION_UMD,
	SKMEM_REGION_KBFT,
	SKMEM_REGION_RXKBFT,
	SKMEM_REGION_TXKBFT,
	SKMEM_REGION_UBFT
};

/* CPU cache line (determined at runtime) */
static unsigned int cpu_cache_line_size;

LCK_ATTR_DECLARE(skmem_lock_attr, 0, 0);
LCK_GRP_DECLARE(skmem_lock_grp, "skmem");

#if (DEVELOPMENT || DEBUG)
SYSCTL_NODE(_kern_skywalk, OID_AUTO, mem, CTLFLAG_RW | CTLFLAG_LOCKED,
    0, "Skywalk kmem");
#endif /* (DEVELOPMENT || DEBUG) */

#define SK_SYS_OBJSIZE_DEFAULT  (16 * 1024)

/* system-wide sysctls region */
static struct skmem_region *sk_sys_region;
static void             *sk_sys_obj;
static uint32_t         sk_sys_objsize;

static void skmem_sys_region_init(void);
static void skmem_sys_region_fini(void);

static char *skmem_dump_buf;
#define SKMEM_DUMP_BUF_SIZE         2048        /* size of dump buffer */

static int __skmem_inited = 0;

void
skmem_init(void)
{
	ASSERT(!__skmem_inited);

	/* get CPU cache line size */
	(void) skmem_cpu_cache_line_size();

	skmem_cache_pre_init();
	skmem_region_init();
	skmem_cache_init();
	pp_init();

	__skmem_inited = 1;

	/* set up system-wide region for sysctls */
	skmem_sys_region_init();
}

void
skmem_fini(void)
{
	if (__skmem_inited) {
		skmem_sys_region_fini();

		pp_fini();
		skmem_cache_fini();
		skmem_region_fini();

		__skmem_inited = 0;
	}
}

/*
 * Return the default region parameters (template).  Callers must never
 * modify the returned region, and should treat it as invariant.
 */
const struct skmem_region_params *
skmem_get_default(skmem_region_id_t id)
{
	ASSERT(id < SKMEM_REGIONS);
	return &skmem_regions[id];
}

/*
 * Return the CPU cache line size.
 */
uint32_t
skmem_cpu_cache_line_size(void)
{
	if (__improbable(cpu_cache_line_size == 0)) {
		ml_cpu_info_t cpu_info;
		ml_cpu_get_info(&cpu_info);
		cpu_cache_line_size = (uint32_t)cpu_info.cache_line_size;
		ASSERT((SKMEM_PAGE_SIZE % cpu_cache_line_size) == 0);
	}
	return cpu_cache_line_size;
}

/*
 * Dispatch a function to execute in a thread call.
 */
void
skmem_dispatch(thread_call_t tcall, void (*func)(void), uint64_t delay)
{
	uint64_t now = mach_absolute_time();
	uint64_t ival, deadline = now;

	ASSERT(tcall != NULL);

	if (delay == 0) {
		delay = (10 * NSEC_PER_USEC); /* "immediately", 10 usec */
	}
	nanoseconds_to_absolutetime(delay, &ival);
	clock_deadline_for_periodic_event(ival, now, &deadline);
	(void) thread_call_enter1_delayed(tcall, func, deadline);
}

static void
skmem_sys_region_init(void)
{
	struct skmem_region_params srp;

	VERIFY(__skmem_inited);
	VERIFY(sk_sys_region == NULL);

	srp = *skmem_get_default(SKMEM_REGION_SYSCTLS);
	ASSERT((srp.srp_cflags & (SKMEM_REGION_CR_MMAPOK |
	    SKMEM_REGION_CR_UREADONLY | SKMEM_REGION_CR_MONOLITHIC |
	    SKMEM_REGION_CR_NOMAGAZINES | SKMEM_REGION_CR_NOREDIRECT)) ==
	    (SKMEM_REGION_CR_MMAPOK | SKMEM_REGION_CR_UREADONLY |
	    SKMEM_REGION_CR_MONOLITHIC | SKMEM_REGION_CR_NOMAGAZINES |
	    SKMEM_REGION_CR_NOREDIRECT));

	srp.srp_r_obj_cnt = 1;
	srp.srp_r_obj_size = sk_sys_objsize = SK_SYS_OBJSIZE_DEFAULT;
	skmem_region_params_config(&srp);

	_CASSERT(SK_SYS_OBJSIZE_DEFAULT >= sizeof(skmem_sysctl));
	sk_sys_region = skmem_region_create("global", &srp, NULL, NULL, NULL);
	if (sk_sys_region == NULL) {
		panic("failed to allocate global sysctls region");
		/* NOTREACHED */
		__builtin_unreachable();
	}

	sk_sys_obj = skmem_region_alloc(sk_sys_region, NULL, NULL,
	    NULL, SKMEM_SLEEP);
	if (sk_sys_obj == NULL) {
		panic("failed to allocate global sysctls object (%u bytes)",
		    sk_sys_objsize);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	skmem_sysctl_init();
}

static void
skmem_sys_region_fini(void)
{
	if (sk_sys_region != NULL) {
		skmem_region_free(sk_sys_region, sk_sys_obj, NULL);
		sk_sys_obj = NULL;
		skmem_region_release(sk_sys_region);
		sk_sys_region = NULL;
	}
	VERIFY(sk_sys_obj == NULL);
}

struct skmem_region *
skmem_get_sysctls_region(void)
{
	return sk_sys_region;
}

void *
skmem_get_sysctls_obj(size_t *size)
{
	if (size != NULL) {
		*size = sk_sys_objsize;
	}

	return sk_sys_obj;
}

/* for VM stats */
extern unsigned int vm_page_free_count, vm_page_speculative_count,
    vm_page_active_count, vm_page_inactive_count, vm_page_inactive_count,
    vm_page_wire_count, vm_page_throttled_count, vm_lopage_free_count,
    vm_page_purgeable_count, vm_page_purged_count;

#define SKMEM_WDT_DUMP_BUF_CHK() do {                           \
	clen -= k;                                              \
	if (clen < 1)                                           \
	        goto done;                                      \
	c += k;                                                 \
} while (0)

/*
 * The compiler doesn't know that snprintf() supports %b format
 * specifier, so use our own wrapper to vsnprintf() here instead.
 */
#define skmem_snprintf(str, size, format, ...)  ({ \
	_Pragma("clang diagnostic push")                                   \
	_Pragma("clang diagnostic ignored \"-Wformat-invalid-specifier\"") \
	_Pragma("clang diagnostic ignored \"-Wformat-extra-args\"")        \
	_Pragma("clang diagnostic ignored \"-Wformat\"")                   \
	snprintf(str, size, format, ## __VA_ARGS__)                        \
	_Pragma("clang diagnostic pop");                                   \
})

__attribute__((noinline, cold, not_tail_called))
char *
skmem_dump(struct skmem_region *skr)
{
	int k, clen = SKMEM_DUMP_BUF_SIZE;
	struct skmem_cache *skm;
	char *c;

	/* allocate space for skmem_dump_buf */
	if (skmem_dump_buf == NULL) {
		skmem_dump_buf = (char *) kalloc_data(SKMEM_DUMP_BUF_SIZE,
		    (Z_ZERO | Z_WAITOK));
		VERIFY(skmem_dump_buf != NULL);
	} else {
		bzero(skmem_dump_buf, SKMEM_DUMP_BUF_SIZE);
	}
	c = skmem_dump_buf;

	k = skmem_snprintf(c, clen,
	    "Region %p\n"
	    "  | Mode         : 0x%b\n"
	    "  | Memory       : [%llu in use [%llu wired]] / [%llu total]\n"
	    "  | Transactions : [%llu segment allocs, %llu frees]\n\n",
	    skr, skr->skr_mode, SKR_MODE_BITS, skr->skr_meminuse,
	    skr->skr_w_meminuse, skr->skr_memtotal, skr->skr_alloc,
	    skr->skr_free);
	SKMEM_WDT_DUMP_BUF_CHK();

	if ((skr->skr_mode & SKR_MODE_SLAB) && (skm = skr->skr_cache) != NULL) {
		k = skmem_snprintf(c, clen,
		    "Cache %p\n"
		    "  | Mode         : 0x%b\n"
		    "  | Memory       : [%llu in use] / [%llu total]\n"
		    "  | Transactions : [%llu alloc failures]\n"
		    "  |                [%llu slab creates, %llu destroys]\n"
		    "  |                [%llu slab allocs,  %llu frees]\n\n",
		    skm, skm->skm_mode, SKM_MODE_BITS, skm->skm_sl_bufinuse,
		    skm->skm_sl_bufmax, skm->skm_sl_alloc_fail,
		    skm->skm_sl_create, skm->skm_sl_destroy, skm->skm_sl_alloc,
		    skm->skm_sl_free);
		SKMEM_WDT_DUMP_BUF_CHK();
	}

	k = skmem_snprintf(c, clen,
	    "VM Pages\n"
	    "  | Free         : %u [%u speculative]\n"
	    "  | Active       : %u\n"
	    "  | Inactive     : %u\n"
	    "  | Wired        : %u [%u throttled, %u lopage_free]\n"
	    "  | Purgeable    : %u [%u purged]\n",
	    vm_page_free_count, vm_page_speculative_count,
	    vm_page_active_count, vm_page_inactive_count,
	    vm_page_wire_count, vm_page_throttled_count, vm_lopage_free_count,
	    vm_page_purgeable_count, vm_page_purged_count);
	SKMEM_WDT_DUMP_BUF_CHK();

done:
	return skmem_dump_buf;
}

boolean_t
skmem_lowmem_check(void)
{
	unsigned int plevel = kVMPressureNormal;
	kern_return_t ret;

	ret = mach_vm_pressure_level_monitor(false, &plevel);
	if (ret == KERN_SUCCESS) {
		/* kVMPressureCritical is the stage below jetsam */
		if (plevel >= kVMPressureCritical) {
			/*
			 * If we are in a low-memory situation, then we
			 * might want to start purging our caches.
			 */
			return TRUE;
		}
	}
	return FALSE;
}
