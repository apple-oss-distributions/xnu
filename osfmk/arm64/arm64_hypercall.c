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

#include <kern/hvg_hypercall.h>
#include <pexpert/pexpert.h>
#include <arm/machine_routines.h>

#include "hv_hvc.h"

#if APPLEVIRTUALPLATFORM

static inline void
regs_to_uuid(const uint32_t (*const regs)[4], uuid_string_t uuid_str)
{
#define countof(array)  (sizeof (array) / sizeof ((array)[0]))

	uuid_t uuid = {};

	for (int i = 0; i < countof(*regs); i++) {
		for (int j = 0; j < 4; j++) {
			uuid[15 - (i * 4) - j] = ((*regs)[i] >> (j * 8)) & 0xff;
		}
	}
	uuid_unparse(uuid, uuid_str);
#undef countof
}

static inline bool
hvc_5(uint64_t *x0, uint64_t *x1, uint64_t *x2, uint64_t *x3, uint64_t *x4)
{
	asm volatile (
                "mov   x0, %[i0]"    "\n"
                "mov   x1, %[i1]"    "\n"
                "mov   x2, %[i2]"    "\n"
                "mov   x3, %[i3]"    "\n"
                "mov   x4, %[i4]"    "\n"
                "hvc   #0"           "\n"
                "str   x0, %[o0]"    "\n"
                "str   x1, %[o1]"    "\n"
                "str   x2, %[o2]"    "\n"
                "str   x3, %[o3]"    "\n"
                "str   x4, %[o4]"    "\n"
                : [o0]  "=m" (*x0),
                  [o1]  "=m" (*x1),
                  [o2]  "=m" (*x2),
                  [o3]  "=m" (*x3),
                  [o4]  "=m" (*x4)
                : [i0]   "r" (*x0),
                  [i1]   "r" (*x1),
                  [i2]   "r" (*x2),
                  [i3]   "r" (*x3),
                  [i4]   "r" (*x4)
                : "x0", "x1", "x2", "x3", "x4"
        );
	return *(int64_t *)x0 >= 0;
}

static inline bool
hvc_2(uint64_t *x0, uint64_t *x1)
{
	uint64_t x = 0;
	return hvc_5(x0, x1, &x, &x, &x);
}

static inline bool
hvc_1(uint64_t *x0)
{
	uint64_t x = 0;
	return hvc_5(x0, &x, &x, &x, &x);
}

static inline bool
hvc32_4(uint32_t *w0, uint32_t *w1, uint32_t *w2, uint32_t *w3)
{
	asm volatile (
                "mov   w0, %w[i0]"   "\n"
                "mov   w1, %w[i1]"   "\n"
                "mov   w2, %w[i2]"   "\n"
                "mov   w3, %w[i3]"   "\n"
                "hvc   #0"           "\n"
                "str   w0, %[o0]"    "\n"
                "str   w1, %[o1]"    "\n"
                "str   w2, %[o2]"    "\n"
                "str   w3, %[o3]"    "\n"
                : [o0]  "=m" (*w0),
                  [o1]  "=m" (*w1),
                  [o2]  "=m" (*w2),
                  [o3]  "=m" (*w3)
                : [i0]   "r" (*w0),
                  [i1]   "r" (*w1),
                  [i2]   "r" (*w2),
                  [i3]   "r" (*w3)
                : "w0", "w1", "w2", "w3"
        );
	return *(int32_t *)w0 >= 0;
}

static inline bool
hvc32_2(uint32_t *w0, uint32_t *w1)
{
	uint32_t w = 0;
	return hvc32_4(w0, w1, &w, &w);
}

/* Unique identification */
static bool
hvg_get_uid(uint32_t range, uuid_string_t uuid)
{
	assert(range == HVC_FID_CPU || range == HVC_FID_OEM);

	uint32_t reg[4] = {
		[0] = HVC32_FI(range, HVC_FID_UID)
	};
	(void) hvc32_4(&reg[0], &reg[1], &reg[2], &reg[3]);
	if (reg[0] == 0xffffffffu) {
		/*
		 * The only illegal %x0 value for a UID is 0xffffffff,
		 * thus cannot rely on "%x0 < 0 => failure" here.
		 */
		return false;
	}
	regs_to_uuid(&reg, uuid);
	return true;
}

/* Revision information */
static bool
hvg_get_revision(uint32_t range, uint32_t *major, uint32_t *minor)
{
	assert(range == HVC_FID_CPU || range == HVC_FID_OEM);

	*major = HVC32_FI(range, HVC_FID_REVISION);
	return hvc32_2(major, minor);
}

/*
 * Hypercall feature information
 *
 * Similar semantics to SMCCC_ARCH_FEATURES i.e. return < 0 if not
 * supported, with the negative value potentially providing more info.
 * Returns >= 0 if supported, with the value indicating feature flags.
 */
static bool
hvg_get_features(uint32_t range, uint32_t fid, int32_t *features)
{
	assert(range == HVC_FID_CPU || range == HVC_FID_OEM);

	*features = HVC32_FI(range, HVC_FID_FEATURES);
	return hvc32_2((uint32_t *)features, &fid);
}

bool
hvg_is_hcall_available(hvg_hcall_code_t hcall)
{
	int32_t features = 0;
	uint32_t major = 0, minor = 0;
	uuid_string_t uuids = {};

	/*
	 * This is a workaround for older hosts which exited when unknown
	 * hypercalls (including those querying the UID and revision)
	 * were issued.
	 * The PAC_NOP call was added in Sydro along with the OEM UID,
	 * REVISION and FEATURES calls; before then, this hypercall was
	 * accepted by Hypervisor framework code, but (despite being a
	 * 64-bit hypercall) returned 0xffffffff for unknown values.
	 */
	uint64_t x0 = VMAPPLE_PAC_NOP;
	(void) hvc_1(&x0);

	if (x0 == 0xffffffff || *(int64_t *)&x0 < 0) {
		return false; // Pre-Sydro host or unknown hypercall
	}

	static const uint32_t hcall_oem_table[HVG_HCALL_COUNT] = {
		[HVG_HCALL_GET_MABS_OFFSET]     = VMAPPLE_GET_MABS_OFFSET,
		[HVG_HCALL_GET_BOOTSESSIONUUID] = VMAPPLE_GET_BOOTSESSIONUUID,
		[HVG_HCALL_VCPU_WFK]            = VMAPPLE_VCPU_WFK,
		[HVG_HCALL_VCPU_KICK]           = VMAPPLE_VCPU_KICK,
	};

	uint32_t fastcall = 0;
	if (hcall >= HVG_HCALL_COUNT ||
	    (fastcall = hcall_oem_table[hcall]) == 0) {
		return false;
	}
	assert(fastcall & HVC_OEM_SERVICE);

	/*
	 * Verify that the host OEM hypercalls are implemented as
	 * specified by Apple.
	 */
	if (!hvg_get_uid(HVC_FID_OEM, uuids) ||
	    strcmp(uuids, VMAPPLE_HVC_UID) != 0) {
		return false;
	}

	/*
	 * Verify that the host implements the OEM "features" hypercall
	 */
	if (!hvg_get_revision(HVC_FID_OEM, &major, &minor) && major == 1) {
		return false;
	}

	/*
	 * Does the host support this OEM hypercall?
	 */
	return hvg_get_features(HVC_FID_OEM, fastcall, &features);
}

hvg_hcall_return_t
hvg_hcall_get_bootsessionuuid(uuid_string_t uuid_str)
{
	uint64_t fn = VMAPPLE_GET_BOOTSESSIONUUID;
	uint64_t reg[5] = {};

	if (!hvc_5(&fn, &reg[0], &reg[1], &reg[2], &reg[3])) {
		return HVG_HCALL_UNSUPPORTED;
	}

	regs_to_uuid(&(uint32_t[4])
	    {(uint32_t)reg[0], (uint32_t)reg[1],
	     (uint32_t)reg[2], (uint32_t)reg[3]},
	    uuid_str);

	return HVG_HCALL_SUCCESS;
}

hvg_hcall_return_t
hvg_hcall_get_mabs_offset(uint64_t *mabs_offset)
{
	uint64_t fn = VMAPPLE_GET_MABS_OFFSET;
	uint64_t x1 = ml_get_abstime_offset();

	if (!hvc_2(&fn, &x1)) {
		return HVG_HCALL_UNSUPPORTED;
	}
	*mabs_offset = x1;

	return HVG_HCALL_SUCCESS;
}


__attribute__((noinline))
void
hvg_hc_kick_cpu(unsigned int cpu_id)
{
	const ml_topology_info_t *tip = ml_get_topology_info();
	assert(cpu_id < tip->num_cpus);

	const uint32_t phys_id = tip->cpus[cpu_id].phys_id;
	uint64_t x0 = VMAPPLE_VCPU_KICK;
	uint64_t x1 = phys_id;
	__assert_only const bool success = hvc_2(&x0, &x1);
	assert(success);
}

__attribute__((noinline))
void
hvg_hc_wait_for_kick(unsigned int ien)
{
	uint64_t x0 = VMAPPLE_VCPU_WFK;
	uint64_t x1 = ien;
	__assert_only const bool success = hvc_2(&x0, &x1);
	assert(success);
}

#else /* APPLEVIRTUALPLATFORM */

bool
hvg_is_hcall_available(__unused hvg_hcall_code_t hcall)
{
	return false;
}

hvg_hcall_return_t
hvg_hcall_get_mabs_offset(__attribute__((unused)) uint64_t *mabs_offset)
{
	return HVG_HCALL_UNSUPPORTED;
}

hvg_hcall_return_t
hvg_hcall_get_bootsessionuuid(__attribute__((unused)) uuid_string_t uuid)
{
	return HVG_HCALL_UNSUPPORTED;
}

#endif /* APPLEVIRTUALPLATFORM */

hvg_hcall_return_t
hvg_hcall_trigger_dump(__unused hvg_hcall_vmcore_file_t *vmcore,
    __unused const hvg_hcall_dump_option_t dump_option)
{
	return HVG_HCALL_UNSUPPORTED;
}

/* Unsupported. */
void
hvg_hcall_set_coredump_data(void)
{
}
