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

#include <sys/sysctl.h>
#include <libkern/libkern.h>
#include <kern/hvg_hypercall.h>
#include <stdbool.h>

/* Translate hypercall error code to syscall error code */
static int
hv_ret_to_errno(hvg_hcall_return_t ret)
{
	switch (ret) {
	case HVG_HCALL_ACCESS_DENIED:
		return EPERM;
	case HVG_HCALL_INVALID_CODE:
	case HVG_HCALL_INVALID_PARAMETER:
		return EINVAL;
	case HVG_HCALL_IO_FAILED:
		return EIO;
	case HVG_HCALL_FEAT_DISABLED:
	case HVG_HCALL_UNSUPPORTED:
		return ENOTSUP;
	default:
		return ENODEV;
	}
}

/*
 * Trigger a guest kernel core dump (Intel macOS VM only)
 * Usage: sysctl kern.hvg.trigger_kernel_coredump = 1
 * (option selector must be 1, other values reserved).
 */
static int
sysctl_trigger_kernel_coredump(__unused struct sysctl_oid *oidp,
    __unused void *arg1, __unused int arg2, __unused struct sysctl_req *req)
{
	/*
	 * Static because it retains the filename of the last core dump
	 * (returned when the sysctl is read).
	 */
	static hvg_hcall_vmcore_file_t sysctl_vmcore;

	int error = 0;
	hvg_hcall_return_t hv_ret;
	char buf[3]; // 1 digit for dump option + 1 '\0' from userspace sysctl + 1 '\0'

	if (req->newptr) {
		// Write request
		// single digit (1 byte) + 1 terminating byte added by system_cmd sysctl
		if (req->newlen > 2) {
			return EINVAL;
		}
		error = SYSCTL_IN(req, buf, req->newlen);
		buf[req->newlen] = '\0';
		if (!error) {
			if (strcmp(buf, "1") != 0) {
				return EINVAL;
			}

			/* Issue hypercall to trigger a dump */
			hv_ret = hvg_hcall_trigger_dump(&sysctl_vmcore, HVG_HCALL_DUMP_OPTION_REGULAR);
			if (hv_ret == HVG_HCALL_SUCCESS) {
				error = SYSCTL_OUT(req, &sysctl_vmcore, sizeof(sysctl_vmcore));
			} else {
				error = hv_ret_to_errno(hv_ret);
			}
		}
	} else {
		// Read request
		error = SYSCTL_OUT(req, &sysctl_vmcore, sizeof(sysctl_vmcore));
	}
	return error;
}

/*
 * Get offset from the host's mach_absolute_time.
 */
static int
sysctl_get_mabs_offset(__unused struct sysctl_oid *oidp, __unused void *arg1,
    __unused int arg2, struct sysctl_req *req)
{
	uint64_t offset = 0;

	const hvg_hcall_return_t ret = hvg_hcall_get_mabs_offset(&offset);
	if (ret != HVG_HCALL_SUCCESS) {
		return hv_ret_to_errno(ret);
	}

	return SYSCTL_OUT(req, &offset, sizeof(offset));
}

/*
 * Get the host's boot session UUID.
 */
static int
sysctl_get_bootsessionuuid(__unused struct sysctl_oid *oidp,
    __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	uuid_string_t uuid = {0};

	const hvg_hcall_return_t ret = hvg_hcall_get_bootsessionuuid(uuid);
	if (ret != HVG_HCALL_SUCCESS) {
		return hv_ret_to_errno(ret);
	}

	return SYSCTL_OUT(req, &uuid, sizeof(uuid));
}

static int
sysctl_vmm_present(__unused struct sysctl_oid *oidp,
    __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	int vmm_present = 0;

#if defined(__arm64__)
	extern int IODTGetDefault(const char *key, void *infoAddr, unsigned int infoSize );
	(void) IODTGetDefault("vmm-present", &vmm_present, sizeof(vmm_present));
#elif defined(__x86_64__)
	extern boolean_t cpuid_vmm_present(void);
	vmm_present = cpuid_vmm_present();
#endif

	vmm_present = !!vmm_present;
	return SYSCTL_OUT(req, &vmm_present, sizeof(vmm_present));
}

static SYSCTL_NODE(_kern, OID_AUTO, hvg,
    CTLFLAG_RW | CTLFLAG_LOCKED | CTLFLAG_ANYBODY, 0,
    "hypervisor guest");

static SYSCTL_PROC(_kern_hvg, OID_AUTO, trigger_kernel_coredump,
    CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_NOAUTO,
    NULL, 0,
    sysctl_trigger_kernel_coredump, "A",
    "Request that the hypervisor take a live kernel dump");

static SYSCTL_PROC(_kern_hvg, OID_AUTO, mabs_offset,
    CTLTYPE_QUAD | CTLFLAG_RD | CTLFLAG_NOAUTO | CTLFLAG_LOCKED,
    NULL, 0,
    sysctl_get_mabs_offset, "Q",
    "host time offset");

static SYSCTL_PROC(_kern_hvg, OID_AUTO, host_bootsessionuuid,
    CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_NOAUTO | CTLFLAG_LOCKED,
    NULL, 0,
    sysctl_get_bootsessionuuid, "A",
    "host boot session UUID");

/* Not dynamic, no need to manually register. */
static SYSCTL_PROC(_kern, OID_AUTO, hv_vmm_present,
    CTLTYPE_INT | CTLFLAG_ANYBODY | CTLFLAG_KERN | CTLFLAG_LOCKED,
    NULL, 0,
    sysctl_vmm_present, "I",
    "running on a vmm");

__startup_func
static void
hvg_sysctl_init(void)
{
	struct {
		hvg_hcall_code_t hcall;
		struct sysctl_oid *oid;
	} hvg_sysctl[] = {
		{
			.hcall = HVG_HCALL_TRIGGER_DUMP,
			.oid = &sysctl__kern_hvg_trigger_kernel_coredump,
		},
		{
			.hcall = HVG_HCALL_GET_MABS_OFFSET,
			.oid = &sysctl__kern_hvg_mabs_offset,
		},
		{
			.hcall = HVG_HCALL_GET_BOOTSESSIONUUID,
			.oid = &sysctl__kern_hvg_host_bootsessionuuid,
		},
	};

#define countof(x) (sizeof(x) / sizeof(x[0]))
	for (int i = 0; i < countof(hvg_sysctl); i++) {
		if (hvg_is_hcall_available(hvg_sysctl[i].hcall)) {
			sysctl_register_oid_early(hvg_sysctl[i].oid);
		}
	}
}

STARTUP(SYSCTL, STARTUP_RANK_MIDDLE, hvg_sysctl_init);
