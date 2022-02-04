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
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#include <sys/kdebug.h>
#include <sys/sysctl.h>
#include <san/kcov.h>
#include <san/kcov_data.h>
#include <san/kcov_stksz.h>

#include <mach/vm_param.h>

#ifdef CONFIG_DTRACE
#include <mach/sdt.h>
#endif


/* Enables stack size recording. */
static uint32_t stksz_enabled = 0;

/* Stack size that represents the watermark. */
static uint32_t stksz_threshold = KERNEL_STACK_SIZE + 1; /* Larger than stack == disabled. */

/* Stack size increment to trigger delta event. */
static uint32_t stksz_delta = 0;


/*
 * Sysctl interface for stack size monitoring.
 */

SYSCTL_DECL(_kern_kcov);
SYSCTL_NODE(_kern_kcov, OID_AUTO, stksz, CTLFLAG_RW | CTLFLAG_LOCKED, 0, "stksz");
SYSCTL_INT(_kern_kcov_stksz, OID_AUTO, threshold, CTLFLAG_RW | CTLFLAG_LOCKED, &stksz_threshold,
    KERNEL_STACK_SIZE + 1, "stack size threshold");
SYSCTL_INT(_kern_kcov_stksz, OID_AUTO, delta, CTLFLAG_RW | CTLFLAG_LOCKED, &stksz_delta,
    KERNEL_STACK_SIZE + 1, "stack delta");

static int
sysctl_kcov_stksz_enabled SYSCTL_HANDLER_ARGS
{
	int err;
	int value = *(int *)arg1;

	err = sysctl_io_number(req, value, sizeof(value), &value, NULL);
	if (err) {
		return err;
	}

	if (req->newptr) {
		if (!(value == 0 || value == 1)) {
			return ERANGE;
		}

		/* No change. */
		if (value == stksz_enabled) {
			return 0;
		}

		/* enable/disable ksancov global switch when required. */
		if (stksz_enabled) {
			kcov_disable();
		} else {
			kcov_enable();
		}
		stksz_enabled = value;
	}

	return 0;
}

SYSCTL_PROC(_kern_kcov_stksz, OID_AUTO, enabled, CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    &stksz_enabled, 0, sysctl_kcov_stksz_enabled, "I", "stack size recording enabled");


/* Constants to make code below simpler. */
const uint32_t debugid_above = MACHDBG_CODE(DBG_MACH_KCOV, KCOV_STKSZ_THRESHOLD_ABOVE);
const uint32_t debugid_below = MACHDBG_CODE(DBG_MACH_KCOV, KCOV_STKSZ_THRESHOLD_BELOW);
const uint32_t debugid_delta = MACHDBG_CODE(DBG_MACH_KCOV, KCOV_STKSZ_DELTA);


void
kcov_stksz_init_thread(kcov_stksz_thread_t *data)
{
	data->kst_pc = 0;
	data->kst_stksz = 0;
	data->kst_stksz_prev = 0;
	data->kst_stack = 0;
	data->kst_th_above = 0;
}


void
kcov_stksz_update_stack_size(thread_t th, kcov_thread_data_t *kcdata, void *caller, uintptr_t sp)
{
	if (!stksz_enabled) {
		return;
	}

	vm_offset_t stack_base = kcov_stksz_get_thread_stkbase(th);
	vm_offset_t stack_size = kcov_stksz_get_thread_stksize(th);

	/* Ensure that we are in thread's stack. */
	if (sp < stack_base || sp >= stack_base + stack_size) {
		return;
	}

	/* Update kernel thread statistics. */
	kcov_stksz_thread_t *data = &kcdata->ktd_stksz;
	data->kst_pc = (uintptr_t)caller;
	data->kst_stksz_prev = data->kst_stksz;
	data->kst_stksz = (uint32_t)(stack_base + stack_size - sp);

	/* Fire threshold related events. */
	if (!data->kst_th_above && data->kst_stksz > stksz_threshold) {
		data->kst_th_above = true;

#if CONFIG_DTRACE
		if (dtrace_get_thread_inprobe(th) == 0) {
			DTRACE_KCOV1(stksz__threshold__above, uint32_t, data->kst_stksz);
		}
#endif
		if (kdebug_enable && kdebug_debugid_enabled(debugid_above)) {
			KDBG(debugid_above, caller, data->kst_stksz);
		}
	} else if (data->kst_th_above && data->kst_stksz < stksz_threshold) {
		data->kst_th_above = false;

#if CONFIG_DTRACE
		if (dtrace_get_thread_inprobe(th) == 0) {
			DTRACE_KCOV1(stksz__threshold__below, uint32_t, data->kst_stksz);
		}
#endif
		if (kdebug_enable && kdebug_debugid_enabled(debugid_below)) {
			KDBG(debugid_below, caller, data->kst_stksz);
		}
	}

	/* Fire delta related events. */
	if (stksz_delta > 0 && data->kst_stksz > data->kst_stksz_prev) {
		uint32_t delta = data->kst_stksz - data->kst_stksz_prev;
		if (delta > stksz_delta) {
#if CONFIG_DTRACE
			if (dtrace_get_thread_inprobe(th) == 0) {
				DTRACE_KCOV1(stksz__delta, uint32_t, delta);
			}
#endif /* CONFIG_DTRACE */
			if (kdebug_enable && kdebug_debugid_enabled(debugid_delta)) {
				KDBG(debugid_delta, caller, delta);
			}
		}
	}
}
