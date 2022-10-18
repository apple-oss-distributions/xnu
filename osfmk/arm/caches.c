/*
 * Copyright (c) 2010 Apple Inc. All rights reserved.
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
#include <mach_assert.h>
#include <mach/vm_types.h>
#include <mach/mach_time.h>
#include <kern/timer.h>
#include <kern/clock.h>
#include <kern/machine.h>
#include <mach/machine.h>
#include <mach/machine/vm_param.h>
#include <mach_kdp.h>
#include <kdp/kdp_udp.h>
#include <arm/caches_internal.h>
#include <arm/cpuid.h>
#include <arm/cpu_data.h>
#include <arm/cpu_data_internal.h>
#include <arm/cpu_internal.h>

#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <vm/pmap.h>

#include <arm/misc_protos.h>

/*
 * dcache_incoherent_io_flush64() dcache_incoherent_io_store64() result info
 */
#define LWOpDone 1
#define BWOpDone 3

#ifndef __ARM_COHERENT_IO__

TUNABLE(bool, up_style_idle_exit, "up_style_idle_exit", false);

void
flush_dcache(
	vm_offset_t addr,
	unsigned length,
	boolean_t phys)
{
	cpu_data_t      *cpu_data_ptr = getCpuDatap();
	vm_offset_t     vaddr;
	addr64_t        paddr;
	vm_size_t       count;

	while (length > 0) {
		if (phys) {
			count = length;
			paddr = CAST_DOWN(pmap_paddr_t, addr);
			vaddr = phystokv_range(paddr, &count);
		} else {
			paddr = kvtophys(addr);
			vaddr = addr;
			count = PAGE_SIZE - (addr & PAGE_MASK);
			if (count > length) {
				count = length;
			}
		}
		FlushPoC_DcacheRegion(vaddr, (unsigned)count);
		if (paddr && (cpu_data_ptr->cpu_cache_dispatch != NULL)) {
			cpu_data_ptr->cpu_cache_dispatch(cpu_data_ptr->cpu_id, CacheCleanFlushRegion, (unsigned int) paddr, (unsigned)count);
		}
		addr += count;
		length -= count;
	}
	return;
}

void
clean_dcache(
	vm_offset_t addr,
	unsigned length,
	boolean_t phys)
{
	cpu_data_t      *cpu_data_ptr = getCpuDatap();
	vm_offset_t     vaddr;
	addr64_t        paddr;
	vm_size_t       count;

	while (length > 0) {
		if (phys) {
			count = length;
			paddr = CAST_DOWN(pmap_paddr_t, addr);
			vaddr = phystokv_range(paddr, &count);
		} else {
			paddr = kvtophys(addr);
			vaddr = addr;
			count = PAGE_SIZE - (addr & PAGE_MASK);
			if (count > length) {
				count = length;
			}
		}
		CleanPoC_DcacheRegion(vaddr, (unsigned)count);
		if (paddr && (cpu_data_ptr->cpu_cache_dispatch != NULL)) {
			cpu_data_ptr->cpu_cache_dispatch(cpu_data_ptr->cpu_id, CacheCleanRegion, (unsigned int) paddr, (unsigned)count);
		}
		addr += count;
		length -= count;
	}
	return;
}

void
flush_dcache_syscall(
	vm_offset_t va,
	unsigned length)
{
	if ((cache_info()->c_bulksize_op != 0) && (length >= (cache_info()->c_bulksize_op))) {
		FlushPoC_Dcache();
		if (getCpuDatap()->cpu_cache_dispatch != NULL) {
			getCpuDatap()->cpu_cache_dispatch(getCpuDatap()->cpu_id, CacheCleanFlush, 0x0UL, 0x0UL);
		}
	} else {
		FlushPoC_DcacheRegion((vm_offset_t) va, length);
	}
	return;
}

void
dcache_incoherent_io_flush64(
	addr64_t pa,
	unsigned int size,
	unsigned int remaining,
	unsigned int *res)
{
	cpu_data_t *cpu_data_ptr = getCpuDatap();

	if ((cache_info()->c_bulksize_op != 0) && (remaining >= (cache_info()->c_bulksize_op))) {
		FlushPoC_Dcache();
		if (cpu_data_ptr->cpu_cache_dispatch != NULL) {
			cpu_data_ptr->cpu_cache_dispatch(cpu_data_ptr->cpu_id, CacheCleanFlush, 0x0UL, 0x0UL);
		}
		*res = BWOpDone;
	} else {
		vm_offset_t     vaddr;
		pmap_paddr_t    paddr = CAST_DOWN(pmap_paddr_t, pa);
		vm_size_t       count;
		unsigned int    wimg_bits, index;

		while (size > 0) {
			if (isphysmem(paddr)) {
				count = size;
				vaddr = phystokv_range(paddr, &count);
			} else {
				count = PAGE_SIZE - (paddr & PAGE_MASK);
				if (count > size) {
					count = size;
				}

				wimg_bits = pmap_cache_attributes((ppnum_t) (paddr >> PAGE_SHIFT));
				mp_disable_preemption();
				index = pmap_map_cpu_windows_copy((ppnum_t) (paddr >> PAGE_SHIFT), VM_PROT_READ | VM_PROT_WRITE, wimg_bits);
				vaddr = pmap_cpu_windows_copy_addr(cpu_number(), index) | (paddr & PAGE_MASK);
			}
			FlushPoC_DcacheRegion(vaddr, (unsigned)count);
			if (isphysmem(paddr)) {
				if (cpu_data_ptr->cpu_cache_dispatch != NULL) {
					cpu_data_ptr->cpu_cache_dispatch(cpu_data_ptr->cpu_id, CacheCleanFlushRegion, (unsigned int) paddr, (unsigned)count);
				}
			} else {
				pmap_unmap_cpu_windows_copy(index);
				mp_enable_preemption();
			}
			paddr += count;
			size -= count;
		}
	}

	return;
}

void
dcache_incoherent_io_store64(
	addr64_t pa,
	unsigned int size,
	unsigned int remaining,
	unsigned int *res)
{
	pmap_paddr_t paddr = CAST_DOWN(pmap_paddr_t, pa);
	cpu_data_t *cpu_data_ptr = getCpuDatap();

	if (isphysmem(paddr)) {
		unsigned int wimg_bits = pmap_cache_attributes((ppnum_t) (paddr >> PAGE_SHIFT));
		if ((wimg_bits == VM_WIMG_IO) || (wimg_bits == VM_WIMG_WCOMB) || (wimg_bits == VM_WIMG_RT)) {
			return;
		}
	}

	if ((cache_info()->c_bulksize_op != 0) && (remaining >= (cache_info()->c_bulksize_op))) {
		CleanPoC_Dcache();
		if (cpu_data_ptr->cpu_cache_dispatch != NULL) {
			cpu_data_ptr->cpu_cache_dispatch(cpu_data_ptr->cpu_id, CacheClean, 0x0UL, 0x0UL);
		}
		*res = BWOpDone;
	} else {
		vm_offset_t     vaddr;
		vm_size_t       count;
		unsigned int    wimg_bits, index;

		while (size > 0) {
			if (isphysmem(paddr)) {
				count = size;
				vaddr = phystokv_range(paddr, &count);
			} else {
				count = PAGE_SIZE - (paddr & PAGE_MASK);
				if (count > size) {
					count = size;
				}
				wimg_bits = pmap_cache_attributes((ppnum_t) (paddr >> PAGE_SHIFT));
				mp_disable_preemption();
				index = pmap_map_cpu_windows_copy((ppnum_t) (paddr >> PAGE_SHIFT), VM_PROT_READ | VM_PROT_WRITE, wimg_bits);
				vaddr = pmap_cpu_windows_copy_addr(cpu_number(), index) | (paddr & PAGE_MASK);
			}
			CleanPoC_DcacheRegion(vaddr, (unsigned)count);
			if (isphysmem(paddr)) {
				if (cpu_data_ptr->cpu_cache_dispatch != NULL) {
					cpu_data_ptr->cpu_cache_dispatch(cpu_data_ptr->cpu_id, CacheCleanRegion, (unsigned int) paddr, (unsigned)count);
				}
			} else {
				pmap_unmap_cpu_windows_copy(index);
				mp_enable_preemption();
			}
			paddr += count;
			size -= count;
		}
	}

	return;
}

void
cache_sync_page(
	ppnum_t pp
	)
{
	pmap_paddr_t    paddr = ptoa(pp);

	if (isphysmem(paddr)) {
		vm_offset_t     vaddr = phystokv(paddr);
		InvalidatePoU_IcacheRegion(vaddr, PAGE_SIZE);
	} else {
		FlushPoC_Dcache();
		InvalidatePoU_Icache();
	};
}

void
platform_cache_init(
	void)
{
	cache_info_t   *cpuid_cache_info;
	unsigned int cache_size = 0x0UL;
	cpu_data_t      *cpu_data_ptr = getCpuDatap();

	cpuid_cache_info = cache_info();

	if (cpu_data_ptr->cpu_cache_dispatch != NULL) {
		cpu_data_ptr->cpu_cache_dispatch(cpu_data_ptr->cpu_id, CacheControl, CacheControlEnable, 0x0UL);

		if (cpuid_cache_info->c_l2size == 0x0) {
			cpu_data_ptr->cpu_cache_dispatch(cpu_data_ptr->cpu_id, CacheConfig, CacheConfigSize, (unsigned int)&cache_size);
			cpuid_cache_info->c_l2size = cache_size;
		}
	}
}

void
platform_cache_flush(
	void)
{
	cpu_data_t      *cpu_data_ptr = getCpuDatap();

	FlushPoC_Dcache();

	if (cpu_data_ptr->cpu_cache_dispatch != NULL) {
		cpu_data_ptr->cpu_cache_dispatch(cpu_data_ptr->cpu_id, CacheCleanFlush, 0x0UL, 0x0UL);
	}
}

void
platform_cache_clean(
	void)
{
	cpu_data_t      *cpu_data_ptr = getCpuDatap();

	CleanPoC_Dcache();

	if (cpu_data_ptr->cpu_cache_dispatch != NULL) {
		cpu_data_ptr->cpu_cache_dispatch(cpu_data_ptr->cpu_id, CacheClean, 0x0UL, 0x0UL);
	}
}

void
platform_cache_shutdown(
	void)
{
	cpu_data_t      *cpu_data_ptr = getCpuDatap();

	CleanPoC_Dcache();

	if (cpu_data_ptr->cpu_cache_dispatch != NULL) {
		cpu_data_ptr->cpu_cache_dispatch(cpu_data_ptr->cpu_id, CacheShutdown, 0x0UL, 0x0UL);
	}
}

void
platform_cache_disable(void)
{
}

void
platform_cache_idle_enter(
	void)
{
	platform_cache_disable();

	/*
	 * If we're only using a single CPU, just write back any
	 * dirty cachelines.  We can avoid doing housekeeping
	 * on CPU data that would normally be modified by other
	 * CPUs.
	 */
	if (up_style_idle_exit && (real_ncpus == 1)) {
		CleanPoU_Dcache();
	} else {
		FlushPoU_Dcache();
	}
}

boolean_t
platform_cache_batch_wimg(
	__unused unsigned int new_wimg,
	__unused unsigned int size
	)
{
	boolean_t       do_cache_op = FALSE;

	if ((cache_info()->c_bulksize_op != 0) && (size >= (cache_info()->c_bulksize_op))) {
		do_cache_op = TRUE;
	}

	return do_cache_op;
}

void
platform_cache_flush_wimg(
	__unused unsigned int new_wimg
	)
{
	FlushPoC_Dcache();
	if (getCpuDatap()->cpu_cache_dispatch != NULL) {
		getCpuDatap()->cpu_cache_dispatch(getCpuDatap()->cpu_id, CacheCleanFlush, 0x0UL, 0x0UL);
	}
}



#else   /* __ARM_COHERENT_IO__ */

void
flush_dcache(
	__unused vm_offset_t addr,
	__unused unsigned length,
	__unused boolean_t phys)
{
	__builtin_arm_dsb(DSB_SY);
}

void
clean_dcache(
	__unused vm_offset_t addr,
	__unused unsigned length,
	__unused boolean_t phys)
{
	__builtin_arm_dsb(DSB_SY);
}

void
flush_dcache_syscall(
	__unused vm_offset_t va,
	__unused unsigned length)
{
	__builtin_arm_dsb(DSB_SY);
}

void
dcache_incoherent_io_flush64(
	__unused addr64_t pa,
	__unused unsigned int size,
	__unused unsigned int remaining,
	__unused unsigned int *res)
{
	__builtin_arm_dsb(DSB_SY);
	*res = LWOpDone;
	return;
}

void
dcache_incoherent_io_store64(
	__unused addr64_t pa,
	__unused unsigned int size,
	__unused unsigned int remaining,
	__unused unsigned int *res)
{
	__builtin_arm_dsb(DSB_SY);
	*res = LWOpDone;
	return;
}

void
cache_sync_page(
	ppnum_t pp
	)
{
	pmap_paddr_t    paddr = ptoa(pp);

	if (isphysmem(paddr)) {
		vm_offset_t     vaddr = phystokv(paddr);
		InvalidatePoU_IcacheRegion(vaddr, PAGE_SIZE);
	}
}

void
platform_cache_init(
	void)
{
}

void
platform_cache_flush(
	void)
{
}

void
platform_cache_clean(
	void)
{
}

void
platform_cache_shutdown(
	void)
{
}

void
platform_cache_idle_enter(
	void)
{
}

boolean_t
platform_cache_batch_wimg(
	__unused unsigned int new_wimg,
	__unused unsigned int size
	)
{
	return TRUE;
}

void
platform_cache_flush_wimg(
	__unused unsigned int new_wimg)
{
}

#endif  /* __ARM_COHERENT_IO__ */
