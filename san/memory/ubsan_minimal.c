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

/*
 * UBSan minimal runtime for production environments
 * This runtime emulates an inlined trap model, but gated through the
 * logging functions, so that fix and continue is always possible just by
 * advancing the program counter.
 * NOTE: this file is regularly instrumented, since all helpers must inline
 * correctly to a trap.
 */
#include <sys/sysctl.h>
#include <libkern/libkern.h>
#include <libkern/coreanalytics/coreanalytics.h>
#include <kern/backtrace.h>
#include <kern/kalloc.h>
#include <kern/thread_call.h>
#include <kern/percpu.h>
#include <machine/machine_routines.h>
#include <san/ubsan_minimal.h>

#define UBSAN_M_PANIC           (0x0001)
#define UBSAN_M_TELEMETRY       (0x0002)

struct ubsan_minimal_trap_desc {
	uint16_t        id;
	uint32_t        flags;
	char            str[16];
};

#if RELEASE
static __security_const_late
#endif /* RELEASE */
struct ubsan_minimal_trap_desc ubsan_traps[] = {
	{ UBSAN_MINIMAL_SIGNED_OVERFLOW, UBSAN_M_TELEMETRY, "signed-overflow" },
};

static SECURITY_READ_ONLY_LATE(bool) ubsan_minimal_enabled = false;
static SECURITY_READ_ONLY_LATE(bool) ubsan_minimal_reporting_enabled = false;

#define UBSAN_M_BT_FRAMES                       (5)
#define UBSAN_M_FRAMES_BUF                      (((UBSAN_M_BT_FRAMES) * 17) + 1)

_Static_assert(CA_UBSANBUF_LEN == UBSAN_M_FRAMES_BUF, "Mismatching size between CA_UBSANBUF_LEN and UBSAN internal expected size");

/*
 * Telemetry reporting is unsafe in interrupt context, since the CA framework
 * relies on being able to successfully zalloc some memory for the event.
 * Therefore we maintain a small buffer that is then flushed by an helper thread.
 */
#define UBSAN_MINIMAL_RB_SIZE                    2

struct ubsan_minimal_rb_entry {
	uint32_t        num_frames;
	uintptr_t       faulting_address;
	uintptr_t       frames[UBSAN_M_BT_FRAMES];
};

LCK_GRP_DECLARE(ubsan_minimal_lock_grp, "ubsan_minimal_rb_lock");
LCK_SPIN_DECLARE(ubsan_minimal_lck, &ubsan_minimal_lock_grp);

static struct ubsan_minimal_rb_entry ubsan_minimal_rb[UBSAN_MINIMAL_RB_SIZE];
static uint8_t ubsan_minimal_rb_index;
static struct thread_call *ubsan_minimal_callout;

/* Telemetry: report back the faulting address and the associated backtrace */
CA_EVENT(ubsan_minimal_trap,
    CA_INT, faulting_address,
    CA_STATIC_STRING(CA_UBSANBUF_LEN), backtrace,
    CA_STATIC_STRING(CA_UUID_LEN), uuid);

/* Rate-limit telemetry on last seen faulting address */
static uintptr_t PERCPU_DATA(ubsan_minimal_cache_address);
/* Get out from the brk handler if the CPU is already servicing one */
static bool PERCPU_DATA(ubsan_minimal_in_handler);

/* Helper counters for fixup/drop operations */
static uint32_t ubsan_minimal_fixup_events;
static uint32_t ubsan_minimal_drop_events;

static char *
ubsan_minimal_trap_to_str(uint16_t trap)
{
	return ubsan_traps[trap - UBSAN_MINIMAL_TRAPS_START].str;
}

static void
ubsan_minimal_backtrace_to_string(char *buf, size_t buflen, uint32_t tot, uintptr_t *frames)
{
	size_t l = 0;

	for (uint32_t i = 0; i < tot; i++) {
		l += scnprintf(buf + l, buflen - l, "%lx\n", VM_KERNEL_UNSLIDE(frames[i]));
	}
}

static void
ubsan_minimal_send_telemetry(struct ubsan_minimal_rb_entry *list, uint8_t num_entry)
{
	assert(num_entry <= UBSAN_MINIMAL_RB_SIZE);

	while (num_entry-- > 0) {
		ca_event_t ca_event = CA_EVENT_ALLOCATE(ubsan_minimal_trap);
		CA_EVENT_TYPE(ubsan_minimal_trap) * event = ca_event->data;

		event->faulting_address = list[num_entry].faulting_address;
		ubsan_minimal_backtrace_to_string(event->backtrace, UBSAN_M_FRAMES_BUF,
		    list[num_entry].num_frames, list[num_entry].frames);
		strlcpy(event->uuid, kernel_uuid_string, CA_UUID_LEN);

		CA_EVENT_SEND(ca_event);
	}
}

static void
ubsan_minimal_stash_telemetry(uint32_t total_frames, uintptr_t *backtrace,
    uintptr_t faulting_address)
{
	if (__improbable(!ubsan_minimal_reporting_enabled)) {
		return;
	}

	/* Skip telemetry if we accidentally took a fault while handling telemetry */
	bool *in_handler = PERCPU_GET(ubsan_minimal_in_handler);
	if (*in_handler) {
		ubsan_minimal_drop_events++;
#if DEVELOPMENT
		panic("UBSan minimal runtime re-entered from within a spinlock");
#endif /* DEVELOPMENT */
		return;
	}

	/* Rate limit on repeatedly seeing the same address */
	uintptr_t *cache_address = PERCPU_GET(ubsan_minimal_cache_address);
	if (*cache_address == faulting_address) {
		ubsan_minimal_drop_events++;
		return;
	}

	*cache_address = faulting_address;

	lck_spin_lock(&ubsan_minimal_lck);
	*in_handler = true;

	if (__improbable(ubsan_minimal_rb_index > UBSAN_MINIMAL_RB_SIZE)) {
		panic("Invalid ubsan interrupt buffer index %d >= %d",
		    ubsan_minimal_rb_index, UBSAN_MINIMAL_RB_SIZE);
	}

	/* We're full, just drop the event */
	if (ubsan_minimal_rb_index == UBSAN_MINIMAL_RB_SIZE) {
		ubsan_minimal_drop_events++;
		*in_handler = false;
		lck_spin_unlock(&ubsan_minimal_lck);
		return;
	}

	ubsan_minimal_rb[ubsan_minimal_rb_index].faulting_address = faulting_address;
	ubsan_minimal_rb[ubsan_minimal_rb_index].num_frames = total_frames;
	memcpy(ubsan_minimal_rb[ubsan_minimal_rb_index].frames, backtrace,
	    UBSAN_M_BT_FRAMES * sizeof(uintptr_t *));
	ubsan_minimal_rb_index++;

	*in_handler = false;
	lck_spin_unlock(&ubsan_minimal_lck);

	thread_call_enter(ubsan_minimal_callout);
}

static void
ubsan_minimal_flush_entries(__unused thread_call_param_t p0, __unused thread_call_param_t p1)
{
	struct ubsan_minimal_rb_entry local_rb[UBSAN_MINIMAL_RB_SIZE] = {0};
	uint8_t local_index = 0;
	bool *in_handler = PERCPU_GET(ubsan_minimal_in_handler);

	lck_spin_lock(&ubsan_minimal_lck);
	*in_handler = true;

	if (__improbable(ubsan_minimal_rb_index > UBSAN_MINIMAL_RB_SIZE)) {
		panic("Invalid ubsan interrupt buffer index %d > %d", ubsan_minimal_rb_index,
		    UBSAN_MINIMAL_RB_SIZE);
	}

	if (ubsan_minimal_rb_index == 0) {
		*in_handler = false;
		lck_spin_unlock(&ubsan_minimal_lck);
		return;
	}

	while (ubsan_minimal_rb_index > 0) {
		local_rb[local_index++] = ubsan_minimal_rb[--ubsan_minimal_rb_index];
	}

	*in_handler = false;
	lck_spin_unlock(&ubsan_minimal_lck);

	ubsan_minimal_send_telemetry(local_rb, local_index);
}

void
ubsan_handle_brk_trap(uint16_t trap, uintptr_t faulting_address, uintptr_t saved_fp)
{
	if (!ubsan_minimal_enabled) {
#if DEVELOPMENT
		/* We want to know about those sooner than later... */
		panic("UBSAN trap taken in early startup code");
#endif /* DEVELOPMENT */
		return;
	}

	uintptr_t frames[UBSAN_M_BT_FRAMES];

	struct backtrace_control ctl = {
		.btc_frame_addr = (uintptr_t)saved_fp,
	};

	uint32_t total_frames = backtrace(frames, UBSAN_M_BT_FRAMES, &ctl, NULL);
	uint32_t trap_idx = trap - UBSAN_MINIMAL_TRAPS_START;

	if (ubsan_traps[trap_idx].flags & UBSAN_M_TELEMETRY) {
		ubsan_minimal_stash_telemetry(total_frames, frames, VM_KERNEL_UNSLIDE(faulting_address));
	}

	if (ubsan_traps[trap_idx].flags & UBSAN_M_PANIC) {
		panic("UBSAN trap for %s detected\n", ubsan_minimal_trap_to_str(trap));
		__builtin_unreachable();
	}

	ubsan_minimal_fixup_events++;
}

__startup_func
void
ubsan_minimal_init(void)
{
	ubsan_minimal_callout = thread_call_allocate_with_options(
		ubsan_minimal_flush_entries, NULL, THREAD_CALL_PRIORITY_KERNEL,
		THREAD_CALL_OPTIONS_ONCE);

	if (ubsan_minimal_callout == NULL) {
		ubsan_minimal_reporting_enabled = false;
	}

#if DEVELOPMENT || DEBUG
	bool force_panic = false;
	PE_parse_boot_argn("-ubsan_force_panic", &force_panic, sizeof(force_panic));
	if (force_panic) {
		for (int i = UBSAN_MINIMAL_TRAPS_START; i < UBSAN_MINIMAL_TRAPS_END; i++) {
			size_t idx = i - UBSAN_MINIMAL_TRAPS_START;
			ubsan_traps[idx].flags |= UBSAN_M_PANIC;
		}
	}
#endif /* DEVELOPMENT || DEBUG */

	ubsan_minimal_reporting_enabled = true;
	ubsan_minimal_enabled = true;
}

#if DEVELOPMENT || DEBUG

/* Add a simple testing path that explicitly triggers a signed int overflow */
static int
sysctl_ubsan_test SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	int err, incr = 0;
	err = sysctl_io_number(req, 0, sizeof(int), &incr, NULL);

	int k = 0x7fffffff;

	for (int i = 0; i < UBSAN_MINIMAL_RB_SIZE + 1; i++) {
		int a = k;
		if (incr != 0) {
			k += incr;
		}

		k = a;
	}

	return err;
}

SYSCTL_DECL(kern_ubsan);
SYSCTL_NODE(_kern, OID_AUTO, ubsan, CTLFLAG_RW | CTLFLAG_LOCKED, 0, "ubsan");
SYSCTL_NODE(_kern_ubsan, OID_AUTO, minimal, CTLFLAG_RW | CTLFLAG_LOCKED, 0, "minimal runtime");
SYSCTL_INT(_kern_ubsan_minimal, OID_AUTO, fixups, CTLFLAG_RW | CTLFLAG_LOCKED, &ubsan_minimal_fixup_events, 0, "");
SYSCTL_INT(_kern_ubsan_minimal, OID_AUTO, drops, CTLFLAG_RW | CTLFLAG_LOCKED, &ubsan_minimal_drop_events, 0, "");
SYSCTL_INT(_kern_ubsan_minimal, OID_AUTO, signed_ovf_flags, CTLFLAG_RW | CTLFLAG_LOCKED, &(ubsan_traps[0].flags), 0, "");
SYSCTL_PROC(_kern_ubsan_minimal, OID_AUTO, test, CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, sysctl_ubsan_test, "I", "Test signed overflow detection");

#endif /* DEVELOPMENT || DEBUG */

#define UBSAN_M_ATTR    __attribute__((always_inline, cold))

UBSAN_M_ATTR void
__ubsan_handle_divrem_overflow_minimal(void)
{
	asm volatile ("brk #%0" : : "i"(UBSAN_MINIMAL_SIGNED_OVERFLOW));
}

UBSAN_M_ATTR void
__ubsan_handle_negate_overflow_minimal(void)
{
	asm volatile ("brk #%0" : : "i"(UBSAN_MINIMAL_SIGNED_OVERFLOW));
}

UBSAN_M_ATTR void
__ubsan_handle_mul_overflow_minimal(void)
{
	asm volatile ("brk #%0" : : "i"(UBSAN_MINIMAL_SIGNED_OVERFLOW));
}

UBSAN_M_ATTR void
__ubsan_handle_sub_overflow_minimal(void)
{
	asm volatile ("brk #%0" : : "i"(UBSAN_MINIMAL_SIGNED_OVERFLOW));
}

UBSAN_M_ATTR void
__ubsan_handle_add_overflow_minimal(void)
{
	asm volatile ("brk #%0" : : "i"(UBSAN_MINIMAL_SIGNED_OVERFLOW));
}
