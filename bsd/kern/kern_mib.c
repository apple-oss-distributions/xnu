/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
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
/*-
 * Copyright (c) 1982, 1986, 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Mike Karels at Berkeley Software Design, Inc.
 *
 * Quite extensively rewritten by Poul-Henning Kamp of the FreeBSD
 * project, to make these variables more userfriendly.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)kern_sysctl.c	8.4 (Berkeley) 4/14/94
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/sysctl.h>
#include <sys/proc_internal.h>
#include <sys/unistd.h>

#if defined(SMP)
#include <machine/smp.h>
#endif

#include <sys/param.h>  /* XXX prune includes */
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/file_internal.h>
#include <sys/vnode.h>
#include <sys/unistd.h>
#include <sys/ioctl.h>
#include <sys/namei.h>
#include <sys/tty.h>
#include <sys/disklabel.h>
#include <sys/vm.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <mach/machine.h>
#include <mach/mach_types.h>
#include <mach/vm_param.h>
#include <kern/task.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <vm/vm_protos.h>
#include <mach/host_info.h>
#include <kern/pms.h>
#include <pexpert/device_tree.h>
#include <pexpert/pexpert.h>
#include <kern/sched_prim.h>
#include <console/serial_protos.h>

extern vm_map_t bsd_pageable_map;

#include <sys/mount_internal.h>
#include <sys/kdebug.h>

#include <IOKit/IOPlatformExpert.h>
#include <pexpert/pexpert.h>

#include <machine/config.h>
#include <machine/machine_routines.h>
#include <machine/cpu_capabilities.h>

#include <mach/mach_host.h>             /* for host_info() */

#if defined(__i386__) || defined(__x86_64__)
#include <i386/cpuid.h> /* for cpuid_info() */
#endif

#if defined(__arm64__)
#include <arm/cpuid.h>          /* for cpuid_info() & cache_info() */
#endif

#if defined(CONFIG_XNUPOST)
#include <tests/ktest.h>
#endif

/**
 * Prevents an issue with creating the sysctl node hw.optional.arm on some
 * platforms. If the 'arm' macro is defined, then the word "arm" is preprocessed
 * to 1. As the 'arm' macro is not used in this file, we do not need to redefine
 * after we are done.
 */
#if defined(arm)
#undef arm
#endif /* defined(arm) */

#ifndef MAX
#define MAX(a, b) (a >= b ? a : b)
#endif

#if defined(__arm64__) && defined(CONFIG_XNUPOST)
kern_return_t arm_cpu_capabilities_legacy_test(void);
#endif /* defined(__arm64__) && defined(CONFIG_XNUPOST) */

/* XXX This should be in a BSD accessible Mach header, but isn't. */
extern unsigned int vm_page_wire_count;

static int      cputhreadtype, cpu64bit;
static uint64_t cacheconfig[10];
static int      packages;

static char *   osenvironment = NULL;
static uint32_t osenvironment_size = 0;
static int      osenvironment_initialized = 0;

static uint32_t ephemeral_storage = 0;
static uint32_t use_recovery_securityd = 0;

static struct {
	uint32_t ephemeral_storage:1;
	uint32_t use_recovery_securityd:1;
} property_existence = {0, 0};

SYSCTL_EXTENSIBLE_NODE(, 0, sysctl, CTLFLAG_RW | CTLFLAG_LOCKED, 0,
    "Sysctl internal magic");
SYSCTL_EXTENSIBLE_NODE(, CTL_KERN, kern, CTLFLAG_RW | CTLFLAG_LOCKED, 0,
    "High kernel, proc, limits &c");
SYSCTL_EXTENSIBLE_NODE(, CTL_VM, vm, CTLFLAG_RW | CTLFLAG_LOCKED, 0,
    "Virtual memory");
SYSCTL_EXTENSIBLE_NODE(, CTL_VFS, vfs, CTLFLAG_RW | CTLFLAG_LOCKED, 0,
    "File system");
SYSCTL_EXTENSIBLE_NODE(, CTL_NET, net, CTLFLAG_RW | CTLFLAG_LOCKED, 0,
    "Network, (see socket.h)");
SYSCTL_EXTENSIBLE_NODE(, CTL_DEBUG, debug, CTLFLAG_RW | CTLFLAG_LOCKED, 0,
    "Debugging");
#if DEBUG || DEVELOPMENT
SYSCTL_NODE(_debug, OID_AUTO, test,
    CTLFLAG_RW | CTLFLAG_LOCKED | CTLFLAG_MASKED, 0, "tests");
#endif
SYSCTL_NODE(, CTL_HW, hw, CTLFLAG_RW | CTLFLAG_LOCKED, 0,
    "hardware");
SYSCTL_EXTENSIBLE_NODE(, CTL_MACHDEP, machdep, CTLFLAG_RW | CTLFLAG_LOCKED, 0,
    "machine dependent");
SYSCTL_NODE(, CTL_USER, user, CTLFLAG_RW | CTLFLAG_LOCKED, 0,
    "user-level");

SYSCTL_NODE(_kern, OID_AUTO, bridge, CTLFLAG_RW | CTLFLAG_LOCKED, 0,
    "bridge");

#define SYSCTL_RETURN(r, x)     SYSCTL_OUT(r, &x, sizeof(x))

/******************************************************************************
 * hw.* MIB
 */

#define CTLHW_RETQUAD   (1U << 31)
#define CTLHW_LOCAL     (1U << 30)
#define CTLHW_PERFLEVEL (1U << 29)

#define HW_LOCAL_CPUTHREADTYPE        (1 | CTLHW_LOCAL)
#define HW_LOCAL_PHYSICALCPU          (2 | CTLHW_LOCAL)
#define HW_LOCAL_PHYSICALCPUMAX       (3 | CTLHW_LOCAL)
#define HW_LOCAL_LOGICALCPU           (4 | CTLHW_LOCAL)
#define HW_LOCAL_LOGICALCPUMAX        (5 | CTLHW_LOCAL)
#define HW_LOCAL_CPUTYPE              (6 | CTLHW_LOCAL)
#define HW_LOCAL_CPUSUBTYPE           (7 | CTLHW_LOCAL)
#define HW_LOCAL_CPUFAMILY            (8 | CTLHW_LOCAL)
#define HW_LOCAL_CPUSUBFAMILY         (9 | CTLHW_LOCAL)
#define HW_NPERFLEVELS                (10 | CTLHW_LOCAL)
#define HW_PERFLEVEL_PHYSICALCPU      (11 | CTLHW_PERFLEVEL)
#define HW_PERFLEVEL_PHYSICALCPUMAX   (12 | CTLHW_PERFLEVEL)
#define HW_PERFLEVEL_LOGICALCPU       (13 | CTLHW_PERFLEVEL)
#define HW_PERFLEVEL_LOGICALCPUMAX    (14 | CTLHW_PERFLEVEL)
#define HW_PERFLEVEL_L1ICACHESIZE     (15 | CTLHW_PERFLEVEL)
#define HW_PERFLEVEL_L1DCACHESIZE     (16 | CTLHW_PERFLEVEL)
#define HW_PERFLEVEL_L2CACHESIZE      (17 | CTLHW_PERFLEVEL)
#define HW_PERFLEVEL_CPUSPERL2        (18 | CTLHW_PERFLEVEL)
#define HW_PERFLEVEL_L3CACHESIZE      (19 | CTLHW_PERFLEVEL)
#define HW_PERFLEVEL_CPUSPERL3        (20 | CTLHW_PERFLEVEL)
#define HW_PERFLEVEL_NAME             (21 | CTLHW_PERFLEVEL)


/*
 * For a given perflevel, return the corresponding CPU type.
 */
cluster_type_t cpu_type_for_perflevel(int perflevel);
cluster_type_t
cpu_type_for_perflevel(int perflevel)
{
	unsigned int cpu_types = ml_get_cpu_types();
	unsigned int n_perflevels = __builtin_popcount(cpu_types);

	assert((perflevel >= 0) && (perflevel < n_perflevels));

	int current_idx = 0, current_perflevel = -1;

	while (cpu_types) {
		current_perflevel += cpu_types & 1;
		if (current_perflevel == (n_perflevels - (perflevel + 1))) {
			return current_idx;
		}

		cpu_types >>= 1;
		current_idx++;
	}

	return 0;
}

static ml_cpu_info_t
sysctl_hw_generic_cpu_info(int perflevel, int arg2 __unused)
{
	bool ignore_perflevel = false;
#if APPLE_ARM64_ARCH_FAMILY
	if (arg2 == HW_CACHELINE) {
		/* Apple SoCs have a uniform cacheline size across all clusters */
		ignore_perflevel = true;
	}
#endif

	ml_cpu_info_t cpu_info;
	if (ignore_perflevel) {
		ml_cpu_get_info(&cpu_info);
	} else {
		ml_cpu_get_info_type(&cpu_info, cpu_type_for_perflevel(perflevel));
	}
	return cpu_info;
}

/*
 * Supporting some variables requires us to do "real" work.  We
 * gather some of that here.
 */
static int
sysctl_hw_generic(__unused struct sysctl_oid *oidp, void *arg1,
    int arg2, struct sysctl_req *req)
{
	char dummy[65];
	int  epochTemp;
	int val, doquad;
	long long qval;
	unsigned int cpu_count;
	host_basic_info_data_t hinfo;
	kern_return_t kret;
	mach_msg_type_number_t count = HOST_BASIC_INFO_COUNT;

	/*
	 * If we are using one of the perflevel sysctls, return early if the perflevel
	 * does not exist in this system.
	 */
	int perflevel = (int)arg1;
	int n_perflevels = __builtin_popcount(ml_get_cpu_types());

	if (arg2 & CTLHW_PERFLEVEL) {
		if ((perflevel < 0) || (perflevel >= n_perflevels)) {
			return ENOENT;
		}
	} else {
		perflevel = n_perflevels - 1;
	}

	/*
	 * Test and mask off the 'return quad' flag.
	 * Note that only some things here support it.
	 */
	doquad = arg2 & CTLHW_RETQUAD;
	arg2 &= ~CTLHW_RETQUAD;

#define BSD_HOST 1
	kret = host_info((host_t)BSD_HOST, HOST_BASIC_INFO, (host_info_t)&hinfo, &count);

	/*
	 * Handle various OIDs.
	 *
	 * OIDs that can return int or quad set val and qval and then break.
	 * Errors and int-only values return inline.
	 */
	switch (arg2) {
	case HW_NCPU:
		if (kret == KERN_SUCCESS) {
			return SYSCTL_RETURN(req, hinfo.max_cpus);
		} else {
			return EINVAL;
		}
	case HW_AVAILCPU:
		if (kret == KERN_SUCCESS) {
			return SYSCTL_RETURN(req, hinfo.avail_cpus);
		} else {
			return EINVAL;
		}
	case HW_LOCAL_PHYSICALCPU:
		if (kret == KERN_SUCCESS) {
			return SYSCTL_RETURN(req, hinfo.physical_cpu);
		} else {
			return EINVAL;
		}
	case HW_LOCAL_PHYSICALCPUMAX:
		if (kret == KERN_SUCCESS) {
			return SYSCTL_RETURN(req, hinfo.physical_cpu_max);
		} else {
			return EINVAL;
		}
	case HW_LOCAL_LOGICALCPU:
		if (kret == KERN_SUCCESS) {
			return SYSCTL_RETURN(req, hinfo.logical_cpu);
		} else {
			return EINVAL;
		}
	case HW_LOCAL_LOGICALCPUMAX:
		if (kret == KERN_SUCCESS) {
			return SYSCTL_RETURN(req, hinfo.logical_cpu_max);
		} else {
			return EINVAL;
		}
	case HW_NPERFLEVELS:
		return SYSCTL_RETURN(req, n_perflevels);
	case HW_PERFLEVEL_PHYSICALCPU:
		cpu_count = ml_get_cpu_number_type(cpu_type_for_perflevel(perflevel), false, true);
		return SYSCTL_RETURN(req, cpu_count);
	case HW_PERFLEVEL_PHYSICALCPUMAX:
		cpu_count = ml_get_cpu_number_type(cpu_type_for_perflevel(perflevel), false, false);
		return SYSCTL_RETURN(req, cpu_count);
	case HW_PERFLEVEL_LOGICALCPU:
		cpu_count = ml_get_cpu_number_type(cpu_type_for_perflevel(perflevel), true, true);
		return SYSCTL_RETURN(req, cpu_count);
	case HW_PERFLEVEL_LOGICALCPUMAX:
		cpu_count = ml_get_cpu_number_type(cpu_type_for_perflevel(perflevel), true, false);
		return SYSCTL_RETURN(req, cpu_count);
	case HW_PERFLEVEL_L1ICACHESIZE: {
		ml_cpu_info_t cpu_info = sysctl_hw_generic_cpu_info(perflevel, arg2);
		val = (int)cpu_info.l1_icache_size;
		qval = (long long)cpu_info.l1_icache_size;
		break;
	}
	case HW_PERFLEVEL_L1DCACHESIZE: {
		ml_cpu_info_t cpu_info = sysctl_hw_generic_cpu_info(perflevel, arg2);
		val = (int)cpu_info.l1_dcache_size;
		qval = (long long)cpu_info.l1_dcache_size;
		break;
	}
	case HW_PERFLEVEL_L2CACHESIZE: {
		ml_cpu_info_t cpu_info = sysctl_hw_generic_cpu_info(perflevel, arg2);
		val = (int)cpu_info.l2_cache_size;
		qval = (long long)cpu_info.l2_cache_size;
		break;
	}
	case HW_PERFLEVEL_CPUSPERL2:
		cpu_count = ml_cpu_cache_sharing(2, cpu_type_for_perflevel(perflevel), false);
		return SYSCTL_RETURN(req, cpu_count);
	case HW_PERFLEVEL_L3CACHESIZE: {
		ml_cpu_info_t cpu_info = sysctl_hw_generic_cpu_info(perflevel, arg2);
		if (cpu_info.l3_cache_size == UINT32_MAX) {
			return EINVAL;
		}
		val = (int)cpu_info.l3_cache_size;
		qval = (long long)cpu_info.l3_cache_size;
		break;
	}
	case HW_PERFLEVEL_CPUSPERL3: {
		ml_cpu_info_t cpu_info = sysctl_hw_generic_cpu_info(perflevel, arg2);
		if (cpu_info.l3_cache_size == UINT32_MAX) {
			return EINVAL;
		}
		cpu_count = ml_cpu_cache_sharing(3, cpu_type_for_perflevel(perflevel), false);
		return SYSCTL_RETURN(req, cpu_count);
	}
	case HW_PERFLEVEL_NAME:
		bzero(dummy, sizeof(dummy));
		ml_get_cluster_type_name(cpu_type_for_perflevel(perflevel), dummy, sizeof(dummy));
		return SYSCTL_OUT(req, dummy, strlen(dummy) + 1);
	case HW_LOCAL_CPUTYPE:
		if (kret == KERN_SUCCESS) {
			return SYSCTL_RETURN(req, hinfo.cpu_type);
		} else {
			return EINVAL;
		}
	case HW_LOCAL_CPUSUBTYPE:
		if (kret == KERN_SUCCESS) {
			return SYSCTL_RETURN(req, hinfo.cpu_subtype);
		} else {
			return EINVAL;
		}
	case HW_LOCAL_CPUFAMILY:
	{
		int cpufamily = 0;
#if defined (__i386__) || defined (__x86_64__)
		cpufamily = cpuid_cpufamily();
#elif defined(__arm64__)
		{
			cpufamily = cpuid_get_cpufamily();
		}
#else
#error unknown architecture
#endif
		return SYSCTL_RETURN(req, cpufamily);
	}
	case HW_LOCAL_CPUSUBFAMILY:
	{
		int cpusubfamily = 0;
#if defined (__i386__) || defined (__x86_64__)
		cpusubfamily = CPUSUBFAMILY_UNKNOWN;
#elif defined(__arm64__)
		{
			cpusubfamily = cpuid_get_cpusubfamily();
		}
#else
#error unknown architecture
#endif
		return SYSCTL_RETURN(req, cpusubfamily);
	}
	case HW_PAGESIZE:
	{
		vm_map_t map = get_task_map(current_task());
		val = vm_map_page_size(map);
		qval = (long long)val;
		break;
	}
	case HW_CACHELINE: {
		ml_cpu_info_t cpu_info = sysctl_hw_generic_cpu_info(perflevel, arg2);
		val = (int)cpu_info.cache_line_size;
		qval = (long long)val;
		break;
	}
	case HW_L1ICACHESIZE: {
		ml_cpu_info_t cpu_info = sysctl_hw_generic_cpu_info(perflevel, arg2);
		val = (int)cpu_info.l1_icache_size;
		qval = (long long)cpu_info.l1_icache_size;
		break;
	}
	case HW_L1DCACHESIZE: {
		ml_cpu_info_t cpu_info = sysctl_hw_generic_cpu_info(perflevel, arg2);
		val = (int)cpu_info.l1_dcache_size;
		qval = (long long)cpu_info.l1_dcache_size;
		break;
	}
	case HW_L2CACHESIZE: {
		ml_cpu_info_t cpu_info = sysctl_hw_generic_cpu_info(perflevel, arg2);
		if (cpu_info.l2_cache_size == UINT32_MAX) {
			return EINVAL;
		}
		val = (int)cpu_info.l2_cache_size;
		qval = (long long)cpu_info.l2_cache_size;
		break;
	}
	case HW_L3CACHESIZE: {
		ml_cpu_info_t cpu_info = sysctl_hw_generic_cpu_info(perflevel, arg2);
		if (cpu_info.l3_cache_size == UINT32_MAX) {
			return EINVAL;
		}
		val = (int)cpu_info.l3_cache_size;
		qval = (long long)cpu_info.l3_cache_size;
		break;
	}
	case HW_TARGET:
		bzero(dummy, sizeof(dummy));
		if (!PEGetTargetName(dummy, 64)) {
			return EINVAL;
		}
		dummy[64] = 0;
		return SYSCTL_OUT(req, dummy, strlen(dummy) + 1);
	case HW_PRODUCT:
		bzero(dummy, sizeof(dummy));
		if (!PEGetProductName(dummy, 64)) {
			return EINVAL;
		}
		dummy[64] = 0;
		return SYSCTL_OUT(req, dummy, strlen(dummy) + 1);

		/*
		 * Deprecated variables.  We still support these for
		 * backwards compatibility purposes only.
		 */
#if XNU_TARGET_OS_OSX && defined(__arm64__)
	/* The following two are kludged for backward
	 * compatibility. Use hw.product/hw.target for something
	 * consistent instead. */

	case HW_MACHINE:
		bzero(dummy, sizeof(dummy));
		if (proc_platform(req->p) == PLATFORM_IOS) {
			/* iOS-on-Mac processes don't expect the macOS kind of
			 * hw.machine, e.g. "arm64", but are used to seeing
			 * a product string on iOS, which we here hardcode
			 * to return as "iPad8,6" for compatibility.
			 *
			 * Another reason why hw.machine and hw.model are
			 * trouble and hw.target+hw.product should be used
			 * instead.
			 */

			strlcpy(dummy, "iPad8,6", sizeof(dummy));
		}
		else {
			strlcpy(dummy, "arm64", sizeof(dummy));
		}
		dummy[64] = 0;
		return SYSCTL_OUT(req, dummy, strlen(dummy) + 1);
	case HW_MODEL:
		bzero(dummy, sizeof(dummy));
		if (!PEGetProductName(dummy, 64)) {
			return EINVAL;
		}
		dummy[64] = 0;
		return SYSCTL_OUT(req, dummy, strlen(dummy) + 1);
#else
	case HW_MACHINE:
		bzero(dummy, sizeof(dummy));
		if (!PEGetMachineName(dummy, 64)) {
			return EINVAL;
		}
		dummy[64] = 0;
		return SYSCTL_OUT(req, dummy, strlen(dummy) + 1);
	case HW_MODEL:
		bzero(dummy, sizeof(dummy));
		if (!PEGetModelName(dummy, 64)) {
			return EINVAL;
		}
		dummy[64] = 0;
		return SYSCTL_OUT(req, dummy, strlen(dummy) + 1);
#endif
	case HW_USERMEM:
	{
		int usermem = (int)(mem_size - vm_page_wire_count * page_size);

		return SYSCTL_RETURN(req, usermem);
	}
	case HW_EPOCH:
		epochTemp = PEGetPlatformEpoch();
		if (epochTemp == -1) {
			return EINVAL;
		}
		return SYSCTL_RETURN(req, epochTemp);
	case HW_VECTORUNIT: {
		ml_cpu_info_t cpu_info = sysctl_hw_generic_cpu_info(perflevel, arg2);
		int vector = cpu_info.vector_unit == 0? 0 : 1;
		return SYSCTL_RETURN(req, vector);
	}
	case HW_L2SETTINGS: {
		ml_cpu_info_t cpu_info = sysctl_hw_generic_cpu_info(perflevel, arg2);
		if (cpu_info.l2_cache_size == UINT32_MAX) {
			return EINVAL;
		}
		return SYSCTL_RETURN(req, cpu_info.l2_settings);
	}
	case HW_L3SETTINGS: {
		ml_cpu_info_t cpu_info = sysctl_hw_generic_cpu_info(perflevel, arg2);
		if (cpu_info.l3_cache_size == UINT32_MAX) {
			return EINVAL;
		}
		return SYSCTL_RETURN(req, cpu_info.l3_settings);
	}
	default:
		return ENOTSUP;
	}
	/*
	 * Callers may come to us with either int or quad buffers.
	 */
	if (doquad) {
		return SYSCTL_RETURN(req, qval);
	}
	return SYSCTL_RETURN(req, val);
}

static int
sysctl_hw_cachesize(struct sysctl_oid *oidp __unused, void *arg1 __unused,
    int arg2 __unused, struct sysctl_req *req)
{
	uint64_t cachesize[10] = {};

#if __x86_64__
	cachesize[0] = ml_cpu_cache_size(0);
	cachesize[1] = ml_cpu_cache_size(1);
	cachesize[2] = ml_cpu_cache_size(2);
	cachesize[3] = ml_cpu_cache_size(3);
#elif __arm64__
	cluster_type_t min_perflevel_cluster_type = cpu_type_for_perflevel(__builtin_popcount(ml_get_cpu_types()) - 1);

	cachesize[0] = ml_get_machine_mem();
	cachesize[1] = cache_info_type(min_perflevel_cluster_type)->c_dsize; /* Using the DCache */
	cachesize[2] = cache_info_type(min_perflevel_cluster_type)->c_l2size;
#else
#error unknown architecture
#endif

	return SYSCTL_RETURN(req, cachesize);
}

/* hw.pagesize and hw.tbfrequency are expected as 64 bit values */
static int
sysctl_pagesize
(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	vm_map_t map = get_task_map(current_task());
	long long l = vm_map_page_size(map);
	return sysctl_io_number(req, l, sizeof(l), NULL, NULL);
}

static int
sysctl_pagesize32
(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	long long l;
#if __arm64__
	l = (long long) (1 << page_shift_user32);
#else /* __arm64__ */
	l = (long long) PAGE_SIZE;
#endif /* __arm64__ */
	return sysctl_io_number(req, l, sizeof(l), NULL, NULL);
}

static int
sysctl_tbfrequency
(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	long long l = gPEClockFrequencyInfo.timebase_frequency_hz;
	return sysctl_io_number(req, l, sizeof(l), NULL, NULL);
}

/*
 * Called by IOKit on Intel, or by sysctl_load_devicetree_entries()
 */
void
sysctl_set_osenvironment(unsigned int size, const void* value)
{
	if (osenvironment_size == 0 && size > 0) {
		osenvironment = zalloc_permanent(size, ZALIGN_NONE);
		if (osenvironment) {
			memcpy(osenvironment, value, size);
			osenvironment_size = size;
		}
	}
}

void
sysctl_unblock_osenvironment(void)
{
	os_atomic_inc(&osenvironment_initialized, relaxed);
	thread_wakeup((event_t) &osenvironment_initialized);
}

/*
 * Create sysctl entries coming from device tree.
 *
 * Entries from device tree are loaded here because SecureDTLookupEntry() only works before
 * PE_init_iokit(). Doing this also avoids the extern-C hackery to access these entries
 * from IORegistry (which requires C++).
 */
__startup_func
static void
sysctl_load_devicetree_entries(void)
{
	DTEntry chosen;
	void const *value;
	unsigned int size;

	if (kSuccess != SecureDTLookupEntry(0, "/chosen", &chosen)) {
		return;
	}

	/* load osenvironment */
	if (kSuccess == SecureDTGetProperty(chosen, "osenvironment", (void const **) &value, &size)) {
		sysctl_set_osenvironment(size, value);
	}

	/* load ephemeral_storage */
	if (kSuccess == SecureDTGetProperty(chosen, "ephemeral-storage", (void const **) &value, &size)) {
		if (size == sizeof(uint32_t)) {
			ephemeral_storage = *(uint32_t const *)value;
			property_existence.ephemeral_storage = 1;
		}
	}

	/* load use_recovery_securityd */
	if (kSuccess == SecureDTGetProperty(chosen, "use-recovery-securityd", (void const **) &value, &size)) {
		if (size == sizeof(uint32_t)) {
			use_recovery_securityd = *(uint32_t const *)value;
			property_existence.use_recovery_securityd = 1;
		}
	}
}
STARTUP(SYSCTL, STARTUP_RANK_MIDDLE, sysctl_load_devicetree_entries);

static int
sysctl_osenvironment
(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
#if defined(__x86_64__)
#if (DEVELOPMENT || DEBUG)
	if (os_atomic_load(&osenvironment_initialized, relaxed) == 0) {
		assert_wait((event_t) &osenvironment_initialized, THREAD_UNINT);
		if (os_atomic_load(&osenvironment_initialized, relaxed) != 0) {
			clear_wait(current_thread(), THREAD_AWAKENED);
		} else {
			(void) thread_block(THREAD_CONTINUE_NULL);
		}
	}
#endif
#endif
	if (osenvironment_size > 0) {
		return SYSCTL_OUT(req, osenvironment, osenvironment_size);
	} else {
		return EINVAL;
	}
}

static int
sysctl_ephemeral_storage
(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	if (property_existence.ephemeral_storage) {
		return SYSCTL_OUT(req, &ephemeral_storage, sizeof(ephemeral_storage));
	} else {
		return EINVAL;
	}
}

static int
sysctl_use_recovery_securityd
(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	if (property_existence.use_recovery_securityd) {
		return SYSCTL_OUT(req, &use_recovery_securityd, sizeof(use_recovery_securityd));
	} else {
		return EINVAL;
	}
}

static int
sysctl_use_kernelmanagerd
(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
#if XNU_TARGET_OS_OSX
	static int use_kernelmanagerd = 1;
	static bool once = false;

	if (!once) {
		kc_format_t kc_format;
		PE_get_primary_kc_format(&kc_format);
		if (kc_format == KCFormatFileset) {
			use_kernelmanagerd = 1;
		} else {
			PE_parse_boot_argn("kernelmanagerd", &use_kernelmanagerd, sizeof(use_kernelmanagerd));
		}
		once = true;
	}
#else
	static int use_kernelmanagerd = 0;
#endif
	return SYSCTL_OUT(req, &use_kernelmanagerd, sizeof(use_kernelmanagerd));
}

#define HW_LOCAL_FREQUENCY             1
#define HW_LOCAL_FREQUENCY_MIN         2
#define HW_LOCAL_FREQUENCY_MAX         3
#define HW_LOCAL_FREQUENCY_CLOCK_RATE  4

static int
sysctl_bus_frequency
(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, __unused struct sysctl_req *req)
{

#if DEBUG || DEVELOPMENT || !defined(__arm64__)
	switch (arg2) {
	case HW_LOCAL_FREQUENCY:
		return SYSCTL_RETURN(req, gPEClockFrequencyInfo.bus_frequency_hz);
	case HW_LOCAL_FREQUENCY_MIN:
		return SYSCTL_RETURN(req, gPEClockFrequencyInfo.bus_frequency_min_hz);
	case HW_LOCAL_FREQUENCY_MAX:
		return SYSCTL_RETURN(req, gPEClockFrequencyInfo.bus_frequency_max_hz);
	case HW_LOCAL_FREQUENCY_CLOCK_RATE:
		return SYSCTL_OUT(req, &gPEClockFrequencyInfo.bus_clock_rate_hz, sizeof(int));
	default:
		return EINVAL;
	}
#else
	return ENOENT;
#endif
}

static int
sysctl_cpu_frequency
(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, __unused struct sysctl_req *req)
{

#if DEBUG || DEVELOPMENT || !defined(__arm64__)
	switch (arg2) {
	case HW_LOCAL_FREQUENCY:
		return SYSCTL_RETURN(req, gPEClockFrequencyInfo.cpu_frequency_hz);
	case HW_LOCAL_FREQUENCY_MIN:
		return SYSCTL_RETURN(req, gPEClockFrequencyInfo.cpu_frequency_min_hz);
	case HW_LOCAL_FREQUENCY_MAX:
		return SYSCTL_RETURN(req, gPEClockFrequencyInfo.cpu_frequency_max_hz);
	case HW_LOCAL_FREQUENCY_CLOCK_RATE:
		return SYSCTL_OUT(req, &gPEClockFrequencyInfo.cpu_clock_rate_hz, sizeof(int));
	default:
		return EINVAL;
	}
#else
	return ENOENT;
#endif
}

/*
 *  This sysctl will signal to userspace that a serial console is desired:
 *
 *    hw.serialdebugmode = 1 will load the serial console job in the multi-user session;
 *    hw.serialdebugmode = 2 will load the serial console job in the base system as well
 */
static int
sysctl_serialdebugmode
(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	uint32_t serial_boot_arg;
	int serialdebugmode = 0;

	if (PE_parse_boot_argn("serial", &serial_boot_arg, sizeof(serial_boot_arg)) &&
	    (serial_boot_arg & SERIALMODE_OUTPUT) && (serial_boot_arg & SERIALMODE_INPUT)) {
		serialdebugmode = (serial_boot_arg & SERIALMODE_BASE_TTY) ? 2 : 1;
	}

	return sysctl_io_number(req, serialdebugmode, sizeof(serialdebugmode), NULL, NULL);
}

/*
 * hw.* MIB variables.
 */
SYSCTL_PROC(_hw, HW_NCPU, ncpu, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, 0, HW_NCPU, sysctl_hw_generic, "I", "");
SYSCTL_PROC(_hw, HW_AVAILCPU, activecpu, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, 0, HW_AVAILCPU, sysctl_hw_generic, "I", "");
SYSCTL_PROC(_hw, OID_AUTO, physicalcpu, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, 0, HW_LOCAL_PHYSICALCPU, sysctl_hw_generic, "I", "");
SYSCTL_PROC(_hw, OID_AUTO, physicalcpu_max, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, 0, HW_LOCAL_PHYSICALCPUMAX, sysctl_hw_generic, "I", "");
SYSCTL_PROC(_hw, OID_AUTO, logicalcpu, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, 0, HW_LOCAL_LOGICALCPU, sysctl_hw_generic, "I", "");
SYSCTL_PROC(_hw, OID_AUTO, logicalcpu_max, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, 0, HW_LOCAL_LOGICALCPUMAX, sysctl_hw_generic, "I", "");
SYSCTL_INT(_hw, HW_BYTEORDER, byteorder, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (int *)NULL, BYTE_ORDER, "");
SYSCTL_PROC(_hw, OID_AUTO, cputype, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, 0, HW_LOCAL_CPUTYPE, sysctl_hw_generic, "I", "");
SYSCTL_PROC(_hw, OID_AUTO, cpusubtype, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, 0, HW_LOCAL_CPUSUBTYPE, sysctl_hw_generic, "I", "");
SYSCTL_INT(_hw, OID_AUTO, cpu64bit_capable, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &cpu64bit, 0, "");
SYSCTL_PROC(_hw, OID_AUTO, cpufamily, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, 0, HW_LOCAL_CPUFAMILY, sysctl_hw_generic, "I", "");
SYSCTL_PROC(_hw, OID_AUTO, cpusubfamily, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, 0, HW_LOCAL_CPUSUBFAMILY, sysctl_hw_generic, "I", "");
SYSCTL_OPAQUE(_hw, OID_AUTO, cacheconfig, CTLFLAG_RD | CTLFLAG_LOCKED, &cacheconfig, sizeof(cacheconfig), "Q", "");
SYSCTL_PROC(_hw, OID_AUTO, cachesize, CTLTYPE_OPAQUE | CTLFLAG_RD | CTLFLAG_LOCKED, 0, 0, sysctl_hw_cachesize, "Q", "");
SYSCTL_PROC(_hw, OID_AUTO, pagesize, CTLTYPE_QUAD | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, 0, 0, sysctl_pagesize, "Q", "");
SYSCTL_PROC(_hw, OID_AUTO, pagesize32, CTLTYPE_QUAD | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, 0, 0, sysctl_pagesize32, "Q", "");
SYSCTL_PROC(_hw, OID_AUTO, busfrequency, CTLTYPE_QUAD | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, 0, HW_LOCAL_FREQUENCY, sysctl_bus_frequency, "Q", "");
SYSCTL_PROC(_hw, OID_AUTO, busfrequency_min, CTLTYPE_QUAD | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, 0, HW_LOCAL_FREQUENCY_MIN, sysctl_bus_frequency, "Q", "");
SYSCTL_PROC(_hw, OID_AUTO, busfrequency_max, CTLTYPE_QUAD | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, 0, HW_LOCAL_FREQUENCY_MAX, sysctl_bus_frequency, "Q", "");
SYSCTL_PROC(_hw, OID_AUTO, cpufrequency, CTLTYPE_QUAD | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, 0, HW_LOCAL_FREQUENCY, sysctl_cpu_frequency, "Q", "");
SYSCTL_PROC(_hw, OID_AUTO, cpufrequency_min, CTLTYPE_QUAD | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, 0, HW_LOCAL_FREQUENCY_MIN, sysctl_cpu_frequency, "Q", "");
SYSCTL_PROC(_hw, OID_AUTO, cpufrequency_max, CTLTYPE_QUAD | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, 0, HW_LOCAL_FREQUENCY_MAX, sysctl_cpu_frequency, "Q", "");
SYSCTL_PROC(_hw, OID_AUTO, cachelinesize, CTLTYPE_QUAD | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, 0, HW_CACHELINE | CTLHW_RETQUAD, sysctl_hw_generic, "Q", "");
SYSCTL_PROC(_hw, OID_AUTO, l1icachesize, CTLTYPE_QUAD | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, 0, HW_L1ICACHESIZE | CTLHW_RETQUAD, sysctl_hw_generic, "Q", "");
SYSCTL_PROC(_hw, OID_AUTO, l1dcachesize, CTLTYPE_QUAD | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, 0, HW_L1DCACHESIZE | CTLHW_RETQUAD, sysctl_hw_generic, "Q", "");
SYSCTL_PROC(_hw, OID_AUTO, l2cachesize, CTLTYPE_QUAD | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, 0, HW_L2CACHESIZE | CTLHW_RETQUAD, sysctl_hw_generic, "Q", "");
SYSCTL_PROC(_hw, OID_AUTO, l3cachesize, CTLTYPE_QUAD | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, 0, HW_L3CACHESIZE | CTLHW_RETQUAD, sysctl_hw_generic, "Q", "");
#if defined(__arm64__) && (DEBUG || DEVELOPMENT)
SYSCTL_QUAD(_hw, OID_AUTO, memfrequency, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gPEClockFrequencyInfo.mem_frequency_hz, "");
SYSCTL_QUAD(_hw, OID_AUTO, memfrequency_min, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gPEClockFrequencyInfo.mem_frequency_min_hz, "");
SYSCTL_QUAD(_hw, OID_AUTO, memfrequency_max, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gPEClockFrequencyInfo.mem_frequency_max_hz, "");
SYSCTL_QUAD(_hw, OID_AUTO, prffrequency, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gPEClockFrequencyInfo.prf_frequency_hz, "");
SYSCTL_QUAD(_hw, OID_AUTO, prffrequency_min, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gPEClockFrequencyInfo.prf_frequency_min_hz, "");
SYSCTL_QUAD(_hw, OID_AUTO, prffrequency_max, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gPEClockFrequencyInfo.prf_frequency_max_hz, "");
SYSCTL_QUAD(_hw, OID_AUTO, fixfrequency, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gPEClockFrequencyInfo.fix_frequency_hz, "");
#endif /* __arm64__ */
SYSCTL_PROC(_hw, OID_AUTO, tbfrequency, CTLTYPE_QUAD | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, 0, 0, sysctl_tbfrequency, "Q", "");
/**
 * The naming around the sysctls for max_mem and max_mem_actual are different between macOS and
 * non-macOS platforms because historically macOS's hw.memsize provided the value of the actual
 * physical memory size, whereas on non-macOS it is the memory size minus any carveouts.
 */
#if XNU_TARGET_OS_OSX
SYSCTL_QUAD(_hw, HW_MEMSIZE, memsize, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &max_mem_actual, "");
SYSCTL_QUAD(_hw, OID_AUTO, memsize_usable, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &max_mem, "");
#else
SYSCTL_QUAD(_hw, HW_MEMSIZE, memsize, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &max_mem, "");
SYSCTL_QUAD(_hw, OID_AUTO, memsize_physical, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &max_mem_actual, "");
#endif /* XNU_TARGET_OS_OSX */
SYSCTL_INT(_hw, OID_AUTO, packages, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &packages, 0, "");
SYSCTL_PROC(_hw, OID_AUTO, osenvironment, CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, 0, 0, sysctl_osenvironment, "A", "");
SYSCTL_PROC(_hw, OID_AUTO, ephemeral_storage, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, 0, 0, sysctl_ephemeral_storage, "I", "");
SYSCTL_PROC(_hw, OID_AUTO, use_recovery_securityd, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, 0, 0, sysctl_use_recovery_securityd, "I", "");
SYSCTL_PROC(_hw, OID_AUTO, use_kernelmanagerd, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, 0, 0, sysctl_use_kernelmanagerd, "I", "");
SYSCTL_PROC(_hw, OID_AUTO, serialdebugmode, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED, 0, 0, sysctl_serialdebugmode, "I", "");

/*
 * hw.perflevelN.* variables.
 * Users may check these to determine properties that vary across different CPU types, such as number of CPUs,
 * or cache sizes. Perflevel 0 corresponds to the highest performance one.
 */
SYSCTL_NODE(_hw, OID_AUTO, perflevel0, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, NULL, "Perf level 0 topology and cache geometry paramaters");
SYSCTL_NODE(_hw, OID_AUTO, perflevel1, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, NULL, "Perf level 1 topology and cache geometry paramaters");
SYSCTL_PROC(_hw, OID_AUTO, nperflevels, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (void *)0, HW_NPERFLEVELS, sysctl_hw_generic, "I", "Number of performance levels supported by this system");

SYSCTL_PROC(_hw_perflevel0, OID_AUTO, physicalcpu, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (void *)0, HW_PERFLEVEL_PHYSICALCPU, sysctl_hw_generic, "I", "");
SYSCTL_PROC(_hw_perflevel0, OID_AUTO, physicalcpu_max, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (void *)0, HW_PERFLEVEL_PHYSICALCPUMAX, sysctl_hw_generic, "I", "");
SYSCTL_PROC(_hw_perflevel0, OID_AUTO, logicalcpu, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (void *)0, HW_PERFLEVEL_LOGICALCPU, sysctl_hw_generic, "I", "");
SYSCTL_PROC(_hw_perflevel0, OID_AUTO, logicalcpu_max, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (void *)0, HW_PERFLEVEL_LOGICALCPUMAX, sysctl_hw_generic, "I", "");
SYSCTL_PROC(_hw_perflevel0, OID_AUTO, l1icachesize, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (void *)0, HW_PERFLEVEL_L1ICACHESIZE, sysctl_hw_generic, "I", "");
SYSCTL_PROC(_hw_perflevel0, OID_AUTO, l1dcachesize, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (void *)0, HW_PERFLEVEL_L1DCACHESIZE, sysctl_hw_generic, "I", "");
SYSCTL_PROC(_hw_perflevel0, OID_AUTO, l2cachesize, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (void *)0, HW_PERFLEVEL_L2CACHESIZE, sysctl_hw_generic, "I", "");
SYSCTL_PROC(_hw_perflevel0, OID_AUTO, cpusperl2, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (void *)0, HW_PERFLEVEL_CPUSPERL2, sysctl_hw_generic, "I", "");
SYSCTL_PROC(_hw_perflevel0, OID_AUTO, l3cachesize, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (void *)0, HW_PERFLEVEL_L3CACHESIZE, sysctl_hw_generic, "I", "");
SYSCTL_PROC(_hw_perflevel0, OID_AUTO, cpusperl3, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (void *)0, HW_PERFLEVEL_CPUSPERL3, sysctl_hw_generic, "I", "");
SYSCTL_PROC(_hw_perflevel0, OID_AUTO, name, CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (void *)0, HW_PERFLEVEL_NAME, sysctl_hw_generic, "A", "");

SYSCTL_PROC(_hw_perflevel1, OID_AUTO, physicalcpu, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (void *)1, HW_PERFLEVEL_PHYSICALCPU, sysctl_hw_generic, "I", "");
SYSCTL_PROC(_hw_perflevel1, OID_AUTO, physicalcpu_max, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (void *)1, HW_PERFLEVEL_PHYSICALCPUMAX, sysctl_hw_generic, "I", "");
SYSCTL_PROC(_hw_perflevel1, OID_AUTO, logicalcpu, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (void *)1, HW_PERFLEVEL_LOGICALCPU, sysctl_hw_generic, "I", "");
SYSCTL_PROC(_hw_perflevel1, OID_AUTO, logicalcpu_max, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (void *)1, HW_PERFLEVEL_LOGICALCPUMAX, sysctl_hw_generic, "I", "");
SYSCTL_PROC(_hw_perflevel1, OID_AUTO, l1icachesize, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (void *)1, HW_PERFLEVEL_L1ICACHESIZE, sysctl_hw_generic, "I", "");
SYSCTL_PROC(_hw_perflevel1, OID_AUTO, l1dcachesize, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (void *)1, HW_PERFLEVEL_L1DCACHESIZE, sysctl_hw_generic, "I", "");
SYSCTL_PROC(_hw_perflevel1, OID_AUTO, l2cachesize, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (void *)1, HW_PERFLEVEL_L2CACHESIZE, sysctl_hw_generic, "I", "");
SYSCTL_PROC(_hw_perflevel1, OID_AUTO, cpusperl2, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (void *)1, HW_PERFLEVEL_CPUSPERL2, sysctl_hw_generic, "I", "");
SYSCTL_PROC(_hw_perflevel1, OID_AUTO, l3cachesize, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (void *)1, HW_PERFLEVEL_L3CACHESIZE, sysctl_hw_generic, "I", "");
SYSCTL_PROC(_hw_perflevel1, OID_AUTO, cpusperl3, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (void *)1, HW_PERFLEVEL_CPUSPERL3, sysctl_hw_generic, "I", "");
SYSCTL_PROC(_hw_perflevel1, OID_AUTO, name, CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (void *)1, HW_PERFLEVEL_NAME, sysctl_hw_generic, "A", "");

/*
 * Optional CPU features can register nodes below hw.optional.
 *
 * If the feature is not present, the node should either not be registered,
 * or it should return 0.  If the feature is present, the node should return
 * 1.
 */
SYSCTL_NODE(_hw, OID_AUTO, optional, CTLFLAG_RW | CTLFLAG_LOCKED, NULL, "optional features");
SYSCTL_NODE(_hw_optional, OID_AUTO, arm, CTLFLAG_RW | CTLFLAG_LOCKED, NULL, "optional features for ARM processors");

SYSCTL_INT(_hw_optional, OID_AUTO, floatingpoint, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (int *)NULL, 1, "");      /* always set */

/*
 * Optional device hardware features can be registered by drivers below hw.features
 */
SYSCTL_EXTENSIBLE_NODE(_hw, OID_AUTO, features, CTLFLAG_RD | CTLFLAG_LOCKED, NULL, "hardware features");

/*
 * Deprecated variables.  These are supported for backwards compatibility
 * purposes only.  The MASKED flag requests that the variables not be
 * printed by sysctl(8) and similar utilities.
 *
 * The variables named *_compat here are int-sized versions of variables
 * that are now exported as quads.  The int-sized versions are normally
 * looked up only by number, wheras the quad-sized versions should be
 * looked up by name.
 *
 * The *_compat nodes are *NOT* visible within the kernel.
 */

SYSCTL_PROC(_hw, HW_PAGESIZE, pagesize_compat, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_MASKED | CTLFLAG_LOCKED, 0, HW_PAGESIZE, sysctl_hw_generic, "I", "");
SYSCTL_PROC(_hw, HW_BUS_FREQ, busfrequency_compat, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_MASKED | CTLFLAG_LOCKED, 0, HW_LOCAL_FREQUENCY_CLOCK_RATE, sysctl_bus_frequency, "I", "");
SYSCTL_PROC(_hw, HW_CPU_FREQ, cpufrequency_compat, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_MASKED | CTLFLAG_LOCKED, 0, HW_LOCAL_FREQUENCY_CLOCK_RATE, sysctl_cpu_frequency, "I", "");
SYSCTL_PROC(_hw, HW_CACHELINE, cachelinesize_compat, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_MASKED | CTLFLAG_LOCKED, 0, HW_CACHELINE, sysctl_hw_generic, "I", "");
SYSCTL_PROC(_hw, HW_L1ICACHESIZE, l1icachesize_compat, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_MASKED | CTLFLAG_LOCKED, 0, HW_L1ICACHESIZE, sysctl_hw_generic, "I", "");
SYSCTL_PROC(_hw, HW_L1DCACHESIZE, l1dcachesize_compat, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_MASKED | CTLFLAG_LOCKED, 0, HW_L1DCACHESIZE, sysctl_hw_generic, "I", "");
SYSCTL_PROC(_hw, HW_L2CACHESIZE, l2cachesize_compat, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_MASKED | CTLFLAG_LOCKED, 0, HW_L2CACHESIZE, sysctl_hw_generic, "I", "");
SYSCTL_PROC(_hw, HW_L3CACHESIZE, l3cachesize_compat, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_MASKED | CTLFLAG_LOCKED, 0, HW_L3CACHESIZE, sysctl_hw_generic, "I", "");
SYSCTL_COMPAT_INT(_hw, HW_TB_FREQ, tbfrequency_compat, CTLFLAG_RD | CTLFLAG_MASKED | CTLFLAG_LOCKED, &gPEClockFrequencyInfo.timebase_frequency_hz, 0, "");
SYSCTL_PROC(_hw, HW_MACHINE, machine, CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_MASKED | CTLFLAG_LOCKED, 0, HW_MACHINE, sysctl_hw_generic, "A", "");
SYSCTL_PROC(_hw, HW_MODEL, model, CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_MASKED | CTLFLAG_LOCKED, 0, HW_MODEL, sysctl_hw_generic, "A", "");
SYSCTL_PROC(_hw, HW_TARGET, target, CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_MASKED | CTLFLAG_LOCKED, 0, HW_TARGET, sysctl_hw_generic, "A", "");
SYSCTL_PROC(_hw, HW_PRODUCT, product, CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_MASKED | CTLFLAG_LOCKED, 0, HW_PRODUCT, sysctl_hw_generic, "A", "");
SYSCTL_COMPAT_UINT(_hw, HW_PHYSMEM, physmem, CTLFLAG_RD | CTLFLAG_MASKED | CTLFLAG_LOCKED, &mem_size, 0, "");
SYSCTL_PROC(_hw, HW_USERMEM, usermem, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_MASKED | CTLFLAG_LOCKED, 0, HW_USERMEM, sysctl_hw_generic, "I", "");
SYSCTL_PROC(_hw, HW_EPOCH, epoch, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_MASKED | CTLFLAG_LOCKED, 0, HW_EPOCH, sysctl_hw_generic, "I", "");
SYSCTL_PROC(_hw, HW_VECTORUNIT, vectorunit, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_MASKED | CTLFLAG_LOCKED, 0, HW_VECTORUNIT, sysctl_hw_generic, "I", "");
SYSCTL_PROC(_hw, HW_L2SETTINGS, l2settings, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_MASKED | CTLFLAG_LOCKED, 0, HW_L2SETTINGS, sysctl_hw_generic, "I", "");
SYSCTL_PROC(_hw, HW_L3SETTINGS, l3settings, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_MASKED | CTLFLAG_LOCKED, 0, HW_L3SETTINGS, sysctl_hw_generic, "I", "");
SYSCTL_INT(_hw, OID_AUTO, cputhreadtype, CTLFLAG_RD | CTLFLAG_NOAUTO | CTLFLAG_KERN | CTLFLAG_LOCKED, &cputhreadtype, 0, "");

#if defined(__i386__) || defined(__x86_64__) || CONFIG_X86_64_COMPAT
static int
sysctl_cpu_capability
(__unused struct sysctl_oid *oidp, void *arg1, __unused int arg2, struct sysctl_req *req)
{
	uint64_t    caps;
	caps = _get_cpu_capabilities();

	uint64_t        mask = (uint64_t) (uintptr_t) arg1;
	boolean_t       is_capable = (caps & mask) != 0;

	return SYSCTL_OUT(req, &is_capable, sizeof(is_capable));
}
#define capability(name) name


SYSCTL_PROC(_hw_optional, OID_AUTO, mmx, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (void *) capability(kHasMMX), 0, sysctl_cpu_capability, "I", "");
SYSCTL_PROC(_hw_optional, OID_AUTO, sse, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (void *) capability(kHasSSE), 0, sysctl_cpu_capability, "I", "");
SYSCTL_PROC(_hw_optional, OID_AUTO, sse2, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (void *) capability(kHasSSE2), 0, sysctl_cpu_capability, "I", "");
SYSCTL_PROC(_hw_optional, OID_AUTO, sse3, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (void *) capability(kHasSSE3), 0, sysctl_cpu_capability, "I", "");
SYSCTL_PROC(_hw_optional, OID_AUTO, supplementalsse3, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (void *) capability(kHasSupplementalSSE3), 0, sysctl_cpu_capability, "I", "");
SYSCTL_PROC(_hw_optional, OID_AUTO, sse4_1, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (void *) capability(kHasSSE4_1), 0, sysctl_cpu_capability, "I", "");
SYSCTL_PROC(_hw_optional, OID_AUTO, sse4_2, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (void *) capability(kHasSSE4_2), 0, sysctl_cpu_capability, "I", "");
/* "x86_64" is actually a preprocessor symbol on the x86_64 kernel, so we have to hack this */
#undef x86_64
SYSCTL_PROC(_hw_optional, OID_AUTO, x86_64, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (void *) capability(k64Bit), 0, sysctl_cpu_capability, "I", "");
SYSCTL_PROC(_hw_optional, OID_AUTO, aes, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (void *) capability(kHasAES), 0, sysctl_cpu_capability, "I", "");
SYSCTL_PROC(_hw_optional, OID_AUTO, avx1_0, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (void *) capability(kHasAVX1_0), 0, sysctl_cpu_capability, "I", "");
SYSCTL_PROC(_hw_optional, OID_AUTO, rdrand, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (void *) capability(kHasRDRAND), 0, sysctl_cpu_capability, "I", "");
SYSCTL_PROC(_hw_optional, OID_AUTO, f16c, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (void *) capability(kHasF16C), 0, sysctl_cpu_capability, "I", "");
SYSCTL_PROC(_hw_optional, OID_AUTO, enfstrg, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (void *) capability(kHasENFSTRG), 0, sysctl_cpu_capability, "I", "");
SYSCTL_PROC(_hw_optional, OID_AUTO, fma, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (void *) capability(kHasFMA), 0, sysctl_cpu_capability, "I", "");
SYSCTL_PROC(_hw_optional, OID_AUTO, avx2_0, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (void *) capability(kHasAVX2_0), 0, sysctl_cpu_capability, "I", "");
SYSCTL_PROC(_hw_optional, OID_AUTO, bmi1, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (void *) capability(kHasBMI1), 0, sysctl_cpu_capability, "I", "");
SYSCTL_PROC(_hw_optional, OID_AUTO, bmi2, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (void *) capability(kHasBMI2), 0, sysctl_cpu_capability, "I", "");
SYSCTL_PROC(_hw_optional, OID_AUTO, rtm, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (void *) capability(kHasRTM), 0, sysctl_cpu_capability, "I", "");
SYSCTL_PROC(_hw_optional, OID_AUTO, hle, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (void *) capability(kHasHLE), 0, sysctl_cpu_capability, "I", "");
SYSCTL_PROC(_hw_optional, OID_AUTO, adx, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (void *) capability(kHasADX), 0, sysctl_cpu_capability, "I", "");
SYSCTL_PROC(_hw_optional, OID_AUTO, mpx, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (void *) capability(kHasMPX), 0, sysctl_cpu_capability, "I", "");
SYSCTL_PROC(_hw_optional, OID_AUTO, sgx, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (void *) capability(kHasSGX), 0, sysctl_cpu_capability, "I", "");
SYSCTL_PROC(_hw_optional, OID_AUTO, avx512f, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (void *) capability(kHasAVX512F), 0, sysctl_cpu_capability, "I", "");
SYSCTL_PROC(_hw_optional, OID_AUTO, avx512cd, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (void *) capability(kHasAVX512CD), 0, sysctl_cpu_capability, "I", "");
SYSCTL_PROC(_hw_optional, OID_AUTO, avx512dq, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (void *) capability(kHasAVX512DQ), 0, sysctl_cpu_capability, "I", "");
SYSCTL_PROC(_hw_optional, OID_AUTO, avx512bw, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (void *) capability(kHasAVX512BW), 0, sysctl_cpu_capability, "I", "");
SYSCTL_PROC(_hw_optional, OID_AUTO, avx512vl, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (void *) capability(kHasAVX512VL), 0, sysctl_cpu_capability, "I", "");
SYSCTL_PROC(_hw_optional, OID_AUTO, avx512ifma, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (void *) capability(kHasAVX512IFMA), 0, sysctl_cpu_capability, "I", "");
SYSCTL_PROC(_hw_optional, OID_AUTO, avx512vbmi, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, (void *) capability(kHasAVX512VBMI), 0, sysctl_cpu_capability, "I", "");
#undef capability
#endif /* !__i386__ && !__x86_64 && !CONFIG_X86_64_COMPAT */

#if defined (__arm64__)
int watchpoint_flag = 0;
int breakpoint_flag = 0;
SECURITY_READ_ONLY_LATE(int) gARMv8Crc32 = 0;

/* Features from: ID_AA64ISAR0_EL1 */
SECURITY_READ_ONLY_LATE(int) gARM_FEAT_FlagM = 0;
SECURITY_READ_ONLY_LATE(int) gARM_FEAT_FlagM2 = 0;
SECURITY_READ_ONLY_LATE(int) gARM_FEAT_FHM = 0;
SECURITY_READ_ONLY_LATE(int) gARM_FEAT_DotProd = 0;
SECURITY_READ_ONLY_LATE(int) gARM_FEAT_SHA3 = 0;
SECURITY_READ_ONLY_LATE(int) gARM_FEAT_RDM = 0;
SECURITY_READ_ONLY_LATE(int) gARM_FEAT_LSE = 0;
SECURITY_READ_ONLY_LATE(int) gARM_FEAT_SHA256 = 0;
SECURITY_READ_ONLY_LATE(int) gARM_FEAT_SHA512 = 0;
SECURITY_READ_ONLY_LATE(int) gARM_FEAT_SHA1 = 0;
SECURITY_READ_ONLY_LATE(int) gARM_FEAT_AES = 0;
SECURITY_READ_ONLY_LATE(int) gARM_FEAT_PMULL = 0;

/* Features from: ID_AA64ISAR1_EL1 */
SECURITY_READ_ONLY_LATE(int) gARM_FEAT_SPECRES = 0;
SECURITY_READ_ONLY_LATE(int) gARM_FEAT_SB = 0;
SECURITY_READ_ONLY_LATE(int) gARM_FEAT_FRINTTS = 0;
SECURITY_READ_ONLY_LATE(int) gARMv8Gpi = 0;
SECURITY_READ_ONLY_LATE(int) gARM_FEAT_LRCPC = 0;
SECURITY_READ_ONLY_LATE(int) gARM_FEAT_LRCPC2 = 0;
SECURITY_READ_ONLY_LATE(int) gARM_FEAT_FCMA = 0;
SECURITY_READ_ONLY_LATE(int) gARM_FEAT_JSCVT = 0;
SECURITY_READ_ONLY_LATE(int) gARM_FEAT_PAuth = 0;
SECURITY_READ_ONLY_LATE(int) gARM_FEAT_PAuth2 = 0;
SECURITY_READ_ONLY_LATE(int) gARM_FEAT_FPAC = 0;
SECURITY_READ_ONLY_LATE(int) gARM_FEAT_DPB = 0;
SECURITY_READ_ONLY_LATE(int) gARM_FEAT_DPB2 = 0;
SECURITY_READ_ONLY_LATE(int) gARM_FEAT_BF16 = 0;
SECURITY_READ_ONLY_LATE(int) gARM_FEAT_I8MM = 0;

/* Features from: ID_AA64MMFR0_EL1 */
SECURITY_READ_ONLY_LATE(int) gARM_FEAT_ECV = 0;

/* Features from: ID_AA64MMFR2_EL1 */
SECURITY_READ_ONLY_LATE(int) gARM_FEAT_LSE2 = 0;

/* Features from: ID_AA64PFR0_EL1 */
SECURITY_READ_ONLY_LATE(int) gARM_FEAT_CSV2 = 0;
SECURITY_READ_ONLY_LATE(int) gARM_FEAT_CSV3 = 0;
SECURITY_READ_ONLY_LATE(int) gARM_FEAT_DIT = 0;
SECURITY_READ_ONLY_LATE(int) gARM_AdvSIMD = 0;
SECURITY_READ_ONLY_LATE(int) gARM_AdvSIMD_HPFPCvt = 0;
SECURITY_READ_ONLY_LATE(int) gARM_FEAT_FP16 = 0;

/* Features from: ID_AA64PFR1_EL1 */
SECURITY_READ_ONLY_LATE(int) gARM_FEAT_SSBS = 0;
SECURITY_READ_ONLY_LATE(int) gARM_FEAT_BTI = 0;

SECURITY_READ_ONLY_LATE(int) gUCNormalMem = 0;

#if defined (__arm64__)
SECURITY_READ_ONLY_LATE(int) arm64_flag = 1;
#else /* end __arm64__*/
SECURITY_READ_ONLY_LATE(int) arm64_flag = 0;
#endif

/* Legacy Names ARM Optional Feature Sysctls */
SYSCTL_INT(_hw_optional, OID_AUTO, neon, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gARM_AdvSIMD, 0, "");
SYSCTL_INT(_hw_optional, OID_AUTO, neon_hpfp, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gARM_AdvSIMD_HPFPCvt, 0, "");
SYSCTL_INT(_hw_optional, OID_AUTO, neon_fp16, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gARM_FEAT_FP16, 0, "");
SYSCTL_INT(_hw_optional, OID_AUTO, armv8_1_atomics, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gARM_FEAT_LSE, 0, "");
SYSCTL_INT(_hw_optional, OID_AUTO, armv8_2_fhm, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gARM_FEAT_FHM, 0, "");
SYSCTL_INT(_hw_optional, OID_AUTO, armv8_2_sha512, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gARM_FEAT_SHA512, 0, "");
SYSCTL_INT(_hw_optional, OID_AUTO, armv8_2_sha3, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gARM_FEAT_SHA3, 0, "");
SYSCTL_INT(_hw_optional, OID_AUTO, armv8_3_compnum, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gARM_FEAT_FCMA, 0, "");

/* Misc ARM Optional Feature Sysctls */
SYSCTL_INT(_hw_optional, OID_AUTO, watchpoint, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &watchpoint_flag, 0, "");
SYSCTL_INT(_hw_optional, OID_AUTO, breakpoint, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &breakpoint_flag, 0, "");

/**
 * Enumerated syscalls for every ARM optional feature to be exported to
 * userspace. These are to be enumerated using the official feature name from
 * the ARM ARM. They are grouped below based on the MSR that will be used to populate the data.
 */

/* Features from: ID_AA64ISAR0_EL1 */
SYSCTL_INT(_hw_optional, OID_AUTO, armv8_crc32, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gARMv8Crc32, 0, "");
SYSCTL_INT(_hw_optional_arm, OID_AUTO, FEAT_FlagM, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gARM_FEAT_FlagM, 0, "");
SYSCTL_INT(_hw_optional_arm, OID_AUTO, FEAT_FlagM2, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gARM_FEAT_FlagM2, 0, "");
SYSCTL_INT(_hw_optional_arm, OID_AUTO, FEAT_FHM, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gARM_FEAT_FHM, 0, "");
SYSCTL_INT(_hw_optional_arm, OID_AUTO, FEAT_DotProd, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gARM_FEAT_DotProd, 0, "");
SYSCTL_INT(_hw_optional_arm, OID_AUTO, FEAT_SHA3, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gARM_FEAT_SHA3, 0, "");
SYSCTL_INT(_hw_optional_arm, OID_AUTO, FEAT_RDM, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gARM_FEAT_RDM, 0, "");
SYSCTL_INT(_hw_optional_arm, OID_AUTO, FEAT_LSE, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gARM_FEAT_LSE, 0, "");
SYSCTL_INT(_hw_optional_arm, OID_AUTO, FEAT_SHA256, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gARM_FEAT_SHA256, 0, "");
SYSCTL_INT(_hw_optional_arm, OID_AUTO, FEAT_SHA512, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gARM_FEAT_SHA512, 0, "");
SYSCTL_INT(_hw_optional_arm, OID_AUTO, FEAT_SHA1, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gARM_FEAT_SHA1, 0, "");
SYSCTL_INT(_hw_optional_arm, OID_AUTO, FEAT_AES, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gARM_FEAT_AES, 0, "");
SYSCTL_INT(_hw_optional_arm, OID_AUTO, FEAT_PMULL, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gARM_FEAT_PMULL, 0, "");

/* Features from: ID_AA64ISAR1_EL1 */
SYSCTL_INT(_hw_optional, OID_AUTO, armv8_gpi, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gARMv8Gpi, 0, "");
SYSCTL_INT(_hw_optional_arm, OID_AUTO, FEAT_SPECRES, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gARM_FEAT_SPECRES, 0, "");
SYSCTL_INT(_hw_optional_arm, OID_AUTO, FEAT_SB, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gARM_FEAT_SB, 0, "");
SYSCTL_INT(_hw_optional_arm, OID_AUTO, FEAT_FRINTTS, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gARM_FEAT_FRINTTS, 0, "");
SYSCTL_INT(_hw_optional_arm, OID_AUTO, FEAT_LRCPC, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gARM_FEAT_LRCPC, 0, "");
SYSCTL_INT(_hw_optional_arm, OID_AUTO, FEAT_LRCPC2, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gARM_FEAT_LRCPC2, 0, "");
SYSCTL_INT(_hw_optional_arm, OID_AUTO, FEAT_FCMA, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gARM_FEAT_FCMA, 0, "");
SYSCTL_INT(_hw_optional_arm, OID_AUTO, FEAT_JSCVT, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gARM_FEAT_JSCVT, 0, "");
SYSCTL_INT(_hw_optional_arm, OID_AUTO, FEAT_PAuth, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gARM_FEAT_PAuth, 0, "");
SYSCTL_INT(_hw_optional_arm, OID_AUTO, FEAT_PAuth2, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gARM_FEAT_PAuth2, 0, "");
SYSCTL_INT(_hw_optional_arm, OID_AUTO, FEAT_FPAC, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gARM_FEAT_FPAC, 0, "");
SYSCTL_INT(_hw_optional_arm, OID_AUTO, FEAT_DPB, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gARM_FEAT_DPB, 0, "");
SYSCTL_INT(_hw_optional_arm, OID_AUTO, FEAT_DPB2, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gARM_FEAT_DPB2, 0, "");
SYSCTL_INT(_hw_optional_arm, OID_AUTO, FEAT_BF16, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gARM_FEAT_BF16, 0, "");
SYSCTL_INT(_hw_optional_arm, OID_AUTO, FEAT_I8MM, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gARM_FEAT_I8MM, 0, "");

/* Features from: ID_AA64MMFR0_EL1 */
SYSCTL_INT(_hw_optional_arm, OID_AUTO, FEAT_ECV, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gARM_FEAT_ECV, 0, "");

/* Features from: ID_AA64MMFR2_EL1 */
SYSCTL_INT(_hw_optional_arm, OID_AUTO, FEAT_LSE2, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gARM_FEAT_LSE2, 0, "");

/* Features from: ID_AA64PFR0_EL1 */
SYSCTL_INT(_hw_optional, OID_AUTO, AdvSIMD, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gARM_AdvSIMD, 0, "");
SYSCTL_INT(_hw_optional, OID_AUTO, AdvSIMD_HPFPCvt, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gARM_AdvSIMD_HPFPCvt, 0, "");
SYSCTL_INT(_hw_optional_arm, OID_AUTO, FEAT_CSV2, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gARM_FEAT_CSV2, 0, "");
SYSCTL_INT(_hw_optional_arm, OID_AUTO, FEAT_CSV3, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gARM_FEAT_CSV3, 0, "");
SYSCTL_INT(_hw_optional_arm, OID_AUTO, FEAT_DIT, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gARM_FEAT_DIT, 0, "");
SYSCTL_INT(_hw_optional_arm, OID_AUTO, FEAT_FP16, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gARM_FEAT_FP16, 0, "");

/* Features from: FPCR */
SECURITY_READ_ONLY_LATE(int) gARM_FP_SyncExceptions = 0;

/* Features from: ID_AA64PFR1_EL1 */
SYSCTL_INT(_hw_optional_arm, OID_AUTO, FEAT_SSBS, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gARM_FEAT_SSBS, 0, "");
SYSCTL_INT(_hw_optional_arm, OID_AUTO, FEAT_BTI, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gARM_FEAT_BTI, 0, "");

/* Features from FPCR. */
SYSCTL_INT(_hw_optional_arm, OID_AUTO, FP_SyncExceptions, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gARM_FP_SyncExceptions, 0, "");

SYSCTL_INT(_hw_optional, OID_AUTO, ucnormal_mem, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &gUCNormalMem, 0, "");

#if DEBUG || DEVELOPMENT
#if __ARM_KERNEL_PROTECT__
static SECURITY_READ_ONLY_LATE(int) arm_kernel_protect = 1;
#else
static SECURITY_READ_ONLY_LATE(int) arm_kernel_protect = 0;
#endif
SYSCTL_INT(_hw_optional, OID_AUTO, arm_kernel_protect, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &arm_kernel_protect, 0, "");
#endif

#if DEBUG || DEVELOPMENT
static int ic_inval_filters = 0;
SYSCTL_INT(_hw_optional, OID_AUTO, ic_inval_filters, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &ic_inval_filters, 0, "");
#endif

#if DEBUG || DEVELOPMENT
static SECURITY_READ_ONLY_LATE(int) wkdm_popcount = 0;
SYSCTL_INT(_hw_optional, OID_AUTO, wkdm_popcount, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &wkdm_popcount, 0, "");
#endif

#if DEBUG || DEVELOPMENT
#if __has_feature(ptrauth_calls)
static SECURITY_READ_ONLY_LATE(int) ptrauth = 1;
#else
static SECURITY_READ_ONLY_LATE(int) ptrauth = 0;
#endif
SYSCTL_INT(_hw_optional, OID_AUTO, ptrauth, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &ptrauth, 0, "");
#endif

/*
 * Without this little ifdef dance, the preprocessor replaces "arm64" with "1",
 * leaving us with a less-than-helpful sysctl.hwoptional.1.
 */
#ifdef arm64
#undef arm64
SYSCTL_INT(_hw_optional, OID_AUTO, arm64, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &arm64_flag, 0, "");
#define arm64 1
#else
SYSCTL_INT(_hw_optional, OID_AUTO, arm64, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &arm64_flag, 0, "");
#endif
#endif /* ! __arm64__ */


#if defined(__arm64__) && defined(CONFIG_XNUPOST)
/**
 * Test whether the new values for a few hw.optional sysctls matches the legacy
 * way of obtaining that information.
 *
 * Specifically, hw.optional.neon_fp16 has been used to indicate both FEAT_FP16
 * and FEAT_FHM, as we are now grabbing the information directly from the ISA
 * status registers instead of from the arm_mvfp_info, we need to check that
 * this new source won't break any existing usecases of the sysctl and assert
 * that hw.optional.neon_fp16 will return the same value as it used to for all
 * devices.
 */
kern_return_t
arm_cpu_capabilities_legacy_test(void)
{
	T_SETUPBEGIN;
	arm_mvfp_info_t *mvfp_info = arm_mvfp_info();
	T_ASSERT_NOTNULL(mvfp_info, "arm_mvfp_info returned null pointer.");
	T_SETUPEND;


	T_EXPECT_EQ_INT(mvfp_info->neon, gARM_AdvSIMD, "neon value should match legacy");
	T_EXPECT_EQ_INT(mvfp_info->neon_hpfp, gARM_AdvSIMD_HPFPCvt, "neon hpfp cvt value should match legacy");
	T_EXPECT_EQ_INT(mvfp_info->neon_fp16, gARM_FEAT_FP16, "neon fp16 value should match legacy");

	T_LOG("Completed arm cpu capabalities legacy compliance test.");
	return KERN_SUCCESS;
}
#endif /* defined(__arm64__) && defined(CONFIG_XNUPOST) */

/******************************************************************************
 * Generic MIB initialisation.
 *
 * This is a hack, and should be replaced with SYSINITs
 * at some point.
 */
void
sysctl_mib_init(void)
{
#if defined(__i386__) || defined (__x86_64__)
	cpu64bit = (_get_cpu_capabilities() & k64Bit) == k64Bit;
#elif defined (__arm64__)
	cpu64bit = (cpu_type() & CPU_ARCH_ABI64) == CPU_ARCH_ABI64;
#else
#error Unsupported arch
#endif
#if defined (__i386__) || defined (__x86_64__)
	/* hw.cacheconfig */
	cacheconfig[0] = ml_cpu_cache_sharing(0, CLUSTER_TYPE_SMP, true);
	cacheconfig[1] = ml_cpu_cache_sharing(1, CLUSTER_TYPE_SMP, true);
	cacheconfig[2] = ml_cpu_cache_sharing(2, CLUSTER_TYPE_SMP, true);
	cacheconfig[3] = ml_cpu_cache_sharing(3, CLUSTER_TYPE_SMP, true);
	cacheconfig[4] = 0;

	/* hw.packages */
	packages = (int)(roundup(ml_cpu_cache_sharing(0, CLUSTER_TYPE_SMP, true), cpuid_info()->thread_count)
	    / cpuid_info()->thread_count);

#elif defined(__arm64__) /* end __i386 */
	watchpoint_flag = arm_debug_info()->num_watchpoint_pairs;
	breakpoint_flag = arm_debug_info()->num_breakpoint_pairs;

	cluster_type_t min_perflevel_cluster_type = cpu_type_for_perflevel(__builtin_popcount(ml_get_cpu_types()) - 1);

	cacheconfig[0] = ml_wait_max_cpus();
	cacheconfig[1] = ml_cpu_cache_sharing(1, min_perflevel_cluster_type, true);
	cacheconfig[2] = ml_cpu_cache_sharing(2, min_perflevel_cluster_type, true);
	cacheconfig[3] = 0;
	cacheconfig[4] = 0;
	cacheconfig[5] = 0;
	cacheconfig[6] = 0;

	packages = 1;
#else
#error unknown architecture
#endif /* !__i386__ && !__x86_64 && !__arm64__ */
}

__startup_func
static void
sysctl_mib_startup(void)
{
	cputhreadtype = cpu_threadtype();

	/*
	 * Populate the optional portion of the hw.* MIB.
	 *
	 * XXX This could be broken out into parts of the code
	 *     that actually directly relate to the functions in
	 *     question.
	 */

	if (cputhreadtype != CPU_THREADTYPE_NONE) {
		sysctl_register_oid_early(&sysctl__hw_cputhreadtype);
	}

}
STARTUP(SYSCTL, STARTUP_RANK_MIDDLE, sysctl_mib_startup);
