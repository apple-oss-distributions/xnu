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

#include <kern/trap_telemetry.h>
#include <libkern/coreanalytics/coreanalytics.h>
#include <kern/percpu.h>
#include <libkern/tree.h>
#include <kern/locks.h>
#include <kern/thread_call.h>
#include <kern/kalloc.h>
#include <kern/cpu_data.h>
#include <kern/telemetry.h>
#include <kern/assert.h>
#include <kern/backtrace.h>
#include <machine/machine_routines.h>
#include <libkern/OSKextLibPrivate.h>
#include <libkern/kernel_mach_header.h>

#define TAG "[trap_telemetry] "

/* ~* Module Configuration *~ */

/**
 * Maximum number of backtrace frames to attempt to report.
 *
 * Some reporting destinations may use fewer frames than this due to
 * encoding/space restrictions.
 */
#define TRAP_TELEMETRY_BT_FRAMES  (15)

/** Static length of various CA telemetry event's backtrace string */
#define TRAP_TELEMETRY_BT_STR_LEN CA_UBSANBUF_LEN

/**
 * Entry count of the RSB.
 *
 * Larger sizes support a higher event volume/can help avoid dropping events
 * under load.
 */
#define RECORD_SUBMISSION_BUFFER_LENGTH (16)

/** Number of last events per-CPU to remember and reject. */
#define DEBOUNCE_RECORD_COUNT (2)

/**
 * When true, trap telemetry will not report events to CoreAnalytics.
 *
 * Local reporting (via trap_telemetry_dump_event) is not impacted.
 */
static TUNABLE(bool, trap_telemetry_disable_ca, "trap_telemetry_disable_ca", false);

/**
 * Disable all trap telemetry reporting (including local reporting)
 */
static TUNABLE(bool, trap_telemetry_disable_all, "trap_telemetry_disable_all", false);

/**
 * Print matching events to the console. Set to -1 to disable.
 * Setting type but disabling code will match all codes of the given type.
 */
static TUNABLE(uint32_t, trap_telemetry_dump_type, "trap_telemetry_dump_type",
    -1);
static TUNABLE(uint64_t, trap_telemetry_dump_code, "trap_telemetry_dump_code",
    -1);

/* ~* Data Structures *~ */

typedef struct match_record {
	/** Slid address at which the exception was thrown */
	uintptr_t fault_pc;

	/** The trap type or "class" for the record. */
	trap_telemetry_type_t trap_type;

	/** The trap code disambiguates traps within a class. */
	uint64_t trap_code;
} match_record_s;

typedef struct rsb_entry {
	match_record_s record;
	trap_telemetry_options_s options;
	size_t bt_frames_count;
	uintptr_t bt_frames[TRAP_TELEMETRY_BT_FRAMES];
} rsb_entry_s;

typedef struct trap_telemetry_tree_entry {
	SPLAY_ENTRY(trap_telemetry_tree_entry) link;
	match_record_s record;
} trap_telemetry_tree_entry_s;

typedef struct trap_debounce_buffer {
	/**
	 * Storage array for trap records used to debounce.
	 *
	 * We don't have valid bits for entries but rather use zero to implicitly
	 * indicate an invalid entry (as they should never naturally match any real
	 * trap).
	 */
	match_record_s records[DEBOUNCE_RECORD_COUNT];

	/** The index of the entry to replace next (LIFO) */
	size_t tail;
} trap_debounce_buffer_s;

/* ~* Core Analytics *~ */
CA_EVENT(kernel_breakpoint_event,
    CA_INT, brk_type,
    CA_INT, brk_code,
    CA_INT, faulting_address,
    CA_STATIC_STRING(TRAP_TELEMETRY_BT_STR_LEN), backtrace,
    CA_STATIC_STRING(CA_UUID_LEN), uuid);

CA_EVENT(trap_telemetry_internal,
    CA_STATIC_STRING(TRAP_TELEMETRY_BT_STR_LEN), backtrace,
    CA_INT, trap_code,
    CA_INT, trap_offset,
    CA_INT, trap_type,
    CA_STATIC_STRING(CA_UUID_LEN), trap_uuid);

/* ~* Splay tree *~ */
static int
match_record_compare(match_record_s *r1,
    match_record_s *r2)
{
	if (r1->fault_pc < r2->fault_pc) {
		return 1;
	} else if (r1->fault_pc > r2->fault_pc) {
		return -1;
	}

	if (r1->trap_type < r2->trap_type) {
		return 1;
	} else if (r1->trap_type > r2->trap_type) {
		return -1;
	}

	if (r1->trap_code < r2->trap_code) {
		return 1;
	} else if (r1->trap_code > r2->trap_code) {
		return -1;
	}

	/* Records match */
	return 0;
}

static int
trap_telemetry_tree_entry_compare(trap_telemetry_tree_entry_s *r1,
    trap_telemetry_tree_entry_s *r2)
{
	return match_record_compare(&r1->record, &r2->record);
}

SPLAY_HEAD(trap_telemetry_tree, trap_telemetry_tree_entry);
/* These functions generated by SPLAY_PROTOTYPE but are currently unused */
__unused static struct trap_telemetry_tree_entry *
trap_telemetry_tree_SPLAY_NEXT(struct trap_telemetry_tree *head,
    struct trap_telemetry_tree_entry *elm);
__unused static struct trap_telemetry_tree_entry *
trap_telemetry_tree_SPLAY_SEARCH(struct trap_telemetry_tree *head,
    struct trap_telemetry_tree_entry *elm);
__unused static struct trap_telemetry_tree_entry *
trap_telemetry_tree_SPLAY_MIN_MAX(struct trap_telemetry_tree *head, int val);
SPLAY_PROTOTYPE(trap_telemetry_tree,
    trap_telemetry_tree_entry,
    link,
    trap_telemetry_tree_entry_compare);
SPLAY_GENERATE(trap_telemetry_tree,
    trap_telemetry_tree_entry,
    link,
    trap_telemetry_tree_entry_compare);

/* ~* Globals *~ */
/* Lock which protects the event submission queue */
static LCK_GRP_DECLARE(trap_telemetry_lock_grp, "trap_telemetry_lock");
static LCK_SPIN_DECLARE(trap_telemetry_lock, &trap_telemetry_lock_grp);

/*
 * Since traps are, naturally, caught in an exception context, it is not safe to
 * allocate. To solve this, we use a short submission ring buffer which collects
 * records for processing on a submission thread (which can allocate).
 *
 * This ring buffer and all its associated control fields are locked by
 * TRAP_TELEMETRY_LOCK.
 */
static rsb_entry_s record_submission_buffer[RECORD_SUBMISSION_BUFFER_LENGTH];
static size_t rsb_rd_idx;
static size_t rsb_wr_idx;
static size_t rsb_count;
static bool rsb_is_draining;

/**
 * For deduplication, we store hit records in a splay tree.
 * We use a splay here for performance reasons since traps tend to exhibit a
 * degree of temporal locality.
 */
static struct trap_telemetry_tree telemetry_splay_tree;

/**
 * Flag indicating whether this CPU is currently trying to acquire the telemetry
 * lock or has already acquired the lock.
 * This is used as a deadlock avoidance mechanism.
 */
static uint8_t PERCPU_DATA(per_cpu_telemetry_lock_blocked);

/**
 * In order to avoid reporting the same event many times in quick succession
 * (especially when report_once_per_site=false) and overwhelming both the trap
 * telemetry module and CoreAnalytics, we "debounce" all events on a per-CPU
 * basis. This is done through a buffer which tracks the LIFO
 * DEBOUNCE_ENTRY_COUNT trap PCs.
 */
static trap_debounce_buffer_s PERCPU_DATA(per_cpu_trap_debounce_buffer);

/**
 * Thread which is responsible for clearing the submission buffer by submitting
 * to CoreAnalytics and the local tree.
 */
static struct thread_call *drain_record_submission_buffer_callout;

#if DEVELOPMENT || DEBUG
/**
 * sysctl debug.trap_telemetry_reported_events
 *
 * Counts the number of events which were successfully reported (either locally
 * or to CoreAnalytics). This does not include events which were ignored,
 * debounced, or discarded as a duplicate.
 */
unsigned long trap_telemetry_reported_events = 0;

/**
 * sysctl debug.trap_telemetry_capacity_dropped_events
 *
 * Counts the number of events which, if not for the RSB being full, would have
 * been reported successfully. Events in this count indicate telemetry loss.
 */
unsigned long trap_telemetry_capacity_dropped_events = 0;
#endif /* DEVELOPMENT || DEBUG */

/* ~* Implementation *~ */

/**
 * Try and acquire a spin lock in an interrupt-deadlock safe way.
 *
 * This function differs from the standard lck_spin_try_lock function in that it
 * will block if the lock is expected to be acquired *eventually* but will not
 * block if it detects that the lock will never be acquired (such as when the
 * current CPU owns the lock, which can happen if a trap is taken while handling
 * a telemetry operation under the lock).
 */
static inline bool OS_WARN_RESULT
safe_telemetry_lock_try_lock(void)
{
	uint8_t *telemetry_lock_blocked = NULL;

	/*
	 * Disable preemption to ensure that our block signal always corresponds
	 * to the CPU we're actually running on.
	 *
	 * If we didn't disable preemption, there is a case where we may mark that
	 * we are trying to acquire the lock on core A, get approved, get preempted,
	 * get rescheduled on core B, and then take the lock there. If we then take
	 * another exception on core B while handling the original exception (ex. we
	 * take an IRQ and a telemetry exception is generated there), we may
	 * re-enter on core B, (incorrectly) see that we are not blocked, try to
	 * acquire the lock, and ultimately deadlock.
	 */
	disable_preemption();

	/*
	 * Since we are preemption disabled, we'll get the desired behavior even if
	 * we take a telemetry trap in the middle of this sequence because the
	 * interrupting context will never return here while holding the telemetry
	 * lock.
	 */
	telemetry_lock_blocked = PERCPU_GET(per_cpu_telemetry_lock_blocked);
	if (*telemetry_lock_blocked) {
		/*
		 * This CPU has already acquired/is blocked on the telemetry lock.
		 * Attempting to acquire again on this CPU will deadlock. Refuse the
		 * operation.
		 */
		enable_preemption();
		return false;
	}

	*telemetry_lock_blocked = 1;

	/* We've been approved to acquire the lock on this core! */
	lck_spin_lock(&trap_telemetry_lock);
	return true;
}

/**
 * Attempts to acquire the telemetry lock and panic if it cannot be acquired.
 */
static void
safe_telemetry_lock_lock(void)
{
	if (!safe_telemetry_lock_try_lock()) {
		panic("Unexpectedly could not acquire telemetry lock "
		    "(nested acquire will deadlock)");
	}
}

/**
 * Unlock telemetry lock after being locked with safe_telemetry_lock_try_lock
 */
static inline void
safe_telemetry_lock_unlock(void)
{
	uint8_t *telemetry_lock_blocked = NULL;

	lck_spin_unlock(&trap_telemetry_lock);

	/*
	 * Clear the block only AFTER having dropped the lock so that we can't
	 * hit a really narrow deadlock race where we get interrupted between
	 * clearing the block and dropping the lock.
	 */
	telemetry_lock_blocked = PERCPU_GET(per_cpu_telemetry_lock_blocked);
	os_atomic_store(telemetry_lock_blocked, (uint8_t)0, relaxed);

	/* Finally, reenable preemption as this thread is now safe to move */
	enable_preemption();
}

/**
 * Enqueue SRC into the record submission buffer.
 * Returns TRUE if successful, false otherwise.
 * TRAP_TELEMETRY_LOCK must be held during this operation.
 */
static bool
rsb_enqueue_locked(rsb_entry_s *rsb_e)
{
	if (rsb_count == RECORD_SUBMISSION_BUFFER_LENGTH) {
		/* We're full. */
		return false;
	}

	/* Write the new entry at the write head */
	rsb_entry_s *dst = record_submission_buffer + rsb_wr_idx;
	*dst = *rsb_e;

	/* Update pointers */
	rsb_count += 1;
	rsb_wr_idx = (rsb_wr_idx + 1) % RECORD_SUBMISSION_BUFFER_LENGTH;

	return true;
}

/**
 * Enter RECORD into this CPU's debounce buffer, thereby preventing it from
 * being reported again until it falls off. Records are removed from the
 * debounce buffer automatically as newer records are inserted.
 */
static bool
trap_debounce_buffer_enter(match_record_s *record)
{
	trap_debounce_buffer_s *debounce = NULL;
	bool match = false;

	/*
	 * Since we don't lock the debounce buffers and instead rely on them being
	 * per-CPU for synchronization, we need to disable preemption to ensure that
	 * we only access the correct debounce buffer.
	 */
	disable_preemption();
	debounce = PERCPU_GET(per_cpu_trap_debounce_buffer);

	/*
	 * Enter the record.
	 * We do this by overwriting the oldest entry, which naturally gives us a
	 * LIFO replacement policy.
	 */
	debounce->records[debounce->tail] = *record;
	debounce->tail = (debounce->tail + 1) % DEBOUNCE_RECORD_COUNT;

	enable_preemption();

	return match;
}


/**
 * Search for RECORD in the per-CPU debounce buffer.
 *
 * This is useful for determining if a trap has triggered recently.
 */
static bool
trap_debounce_buffer_has_match(match_record_s *record)
{
	trap_debounce_buffer_s *debounce = NULL;
	bool match = false;

	disable_preemption();
	debounce = PERCPU_GET(per_cpu_trap_debounce_buffer);

	for (size_t i = 0; i < DEBOUNCE_RECORD_COUNT; i++) {
		if (match_record_compare(debounce->records + i, record) == 0) {
			match = true;
			break;
		}
	}

	enable_preemption();

	return match;
}

/**
 * Should the given trap be dumped to the console for debug?
 */
static inline bool
should_dump_trap(
	trap_telemetry_type_t trap_type,
	uint64_t trap_code)
{
	if (trap_telemetry_dump_type == -1 /* type match disabled */ ||
	    trap_telemetry_dump_type != (uint32_t)trap_type) {
		/* No match on type */
		return false;
	}

	if (trap_telemetry_dump_code != -1 /* code match is enabled */ &&
	    /* but it doesn't match the trap code */
	    trap_telemetry_dump_code != trap_code) {
		return false;
	}

	/* Matching type and, if applicable, code. */
	return true;
}

/**
 * Get the UUID and __TEXT_EXEC based offset of ADDR into its respective binary
 * image. Caller is not responsible for managing the the UUID
 * memory (i.e. it is not owned by the caller).
 *
 * Returns negative on error.
 *
 * Acquires a sleeping lock, do not call while interrupts are disabled.
 */
static int
get_uuid_and_text_offset_for_addr(
	uintptr_t addr, uuid_t **uuid_out, uint64_t *offset_out)
{
	kernel_mach_header_t *mh = NULL;
	kernel_segment_command_t *seg_text = NULL;
	void *mh_uuid = NULL;
	unsigned long mh_uuid_len = 0;
#if __arm64__
	const char *text_segment_label = "__TEXT_EXEC";
#else
	const char *text_segment_label = "__TEXT";
#endif

	if (!(mh = OSKextKextForAddress((void *)addr))) {
		return -1;
	}

	if (!(seg_text = getsegbynamefromheader(mh, text_segment_label))) {
		return -2;
	}

	if (!(mh_uuid = getuuidfromheader(mh, &mh_uuid_len))) {
		return -3;
	}

	if (mh_uuid_len != sizeof(**uuid_out)) {
		return -4;
	}

	*uuid_out = (uuid_t *)(mh_uuid);
	*offset_out = addr - seg_text->vmaddr;

	return 0;
}

/**
 * If it does not already exist, inserts UUID into UUID_CACHE (described by
 * CACHE_LEN). In either case, return the index of the UUID in the cache through
 * *IDX_OUT and set *IS_NEW_OUT if UUID was inserted.
 *
 */
static void
uuid_cache_get_or_insert(uuid_t *uuid, uuid_t **uuid_cache, size_t cache_len,
    uint32_t *idx_out, bool *is_new_out)
{
	for (uint32_t i = 0; i < cache_len; i++) {
		if (uuid_cache[i] == uuid) {
			/* Hit on existing entry */
			*idx_out = i;
			*is_new_out = false;
			return;
		} else if (uuid_cache[i] == NULL) {
			/*
			 * Reached the end of the valid entries without finding our UUID.
			 * Insert it now.
			 */
			uuid_cache[i] = uuid;
			*idx_out = i;
			*is_new_out = true;
			return;
		}

		/* No match yet, but there might be more entries. Keep going. */
	}

	/*
	 * We didn't find the UUID but we also couldn't insert it because we never
	 * found a free space. This shouldn't happen if the UUID cache is correctly
	 * sized.
	 */
	panic("Could not find UUID in cache but cache was full");
}

/**
 * Convert an array of backtrace addresses in FRAMES into an offset backtrace
 * string in BUF.
 *
 * This backtrace scheme has records deliminated by newline characters. Each
 * record is either a backtrace entry or a UUID entry. A backtrace entry is
 * identified by the presence of an `@` character in the record. Any other
 * record is a UUID entry.
 *
 * Example:
 *
 * 14760@0\n
 * 2B417DFA-7964-3EBF-97EE-FC94D26FFABD\n
 * 9f18@1\n
 * F9EFB7CA-8F23-3990-8E57-A7DAD698D494\n
 * 87c974@2\n
 * 8686ED81-CAA9-358D-B162-1F2F97334C65\n
 * 87cce4@2\n
 * 874f64@2\n
 *
 * Structurally, this example is equivalent to:
 *
 * <text offset>@<uuid entry idx=0>\n
 * <uuid entry 0>\n
 * <text offset>@<uuid entry idx=1>\n
 * <uuid entry 1>\n
 * <text offset>@<uuid entry idx=2>\n
 * <uuid entry 2>\n
 * <text offset>@<uuid entry idx=2>\n
 * <text offset>@<uuid entry idx=2>\n
 *
 * The first record here is a backtrace entry. Backtrace entries encode program
 * location as a hex offset into the __TEXT/__TEXT_EXEC segment of the enclosing
 * binary. The enclosing binary is identified by a hex encoded, zero-indexed
 * UUID entry ID which follows after the `@` in a backtrace entry.
 *
 * The second record is a UUID entry. UUID entries are simply records which
 * contain nothing but the UUID. UUID entries are implicitly assigned IDs,
 * starting from zero, in the order they appear in the record stream. Entries
 * may be referenced before they are used.
 *
 * Given a 256 byte buffer, we can fit up to ten backtrace entries (assuming
 * each binary is no larger than 256MB and we have no more than four unique
 * UUIDs in the backtrace).
 *
 * If the encoder runs out of space (for example, because we have more than four
 * unique UUIDs), the later records will truncate abruptly. In order to provide
 * as much information as possible, UUIDs are encoded immediately after they are
 * used. This means that if the encoder does run out of space, all backtrace
 * entries but the last will always decode correctly.
 */
static void
backtrace_to_offset_bt_string(
	char *buf,
	size_t buf_len,
	const uintptr_t *frames,
	size_t frames_len)
{
	size_t written = 0;
	const size_t uuid_cache_count = TRAP_TELEMETRY_BT_FRAMES;
	/*
	 * The UUID cache relies on NULL entries to represent free slots, so clear
	 * it before use.
	 */
	uuid_t *uuid_cache[uuid_cache_count] = {0};
	assert(frames_len <= uuid_cache_count);

	/* Add all frames and store unique UUIDs into the cache */
	for (size_t frame_i = 0; frame_i < frames_len; frame_i++) {
		uuid_t *uuid = NULL;
		uint64_t offset = 0;

		if (get_uuid_and_text_offset_for_addr(
			    frames[frame_i], &uuid, &offset) == 0) {
			/* Success! Insert (or reuse) the UUID and then print the entry. */
			uint32_t uuid_i;
			bool is_new;
			uuid_cache_get_or_insert(
				uuid, uuid_cache, uuid_cache_count,
				&uuid_i, &is_new);

			/* Write backtrace record */
			written += scnprintf(buf + written, buf_len - written,
			    "%llx@%x\n",
			    offset, uuid_i);

			/* Write UUID record, if needed. */
			if (is_new) {
				uuid_string_t uuid_str;
				uuid_unparse(*uuid, uuid_str);

				written += scnprintf(buf + written, buf_len - written,
				    "%s\n",
				    uuid_str);
			}
		} else {
			/*
			 * Could not find an image for the target?
			 * Just return the offset into the executable region with an error
			 * UUID ref as it's better than nothing.
			 */
			written += scnprintf(buf + written, buf_len - written,
			    "%lx@!\n",
			    frames[frame_i] - vm_kernel_stext);
		}
	}
}


/**
 * Print RSB_E to the console in a human friendly way.
 */
static void
rsb_entry_dump(rsb_entry_s *rsb_e)
{
	printf(TAG "Triggered trap at PC=0x%08lx "
	    "(type=%u, code=0x%04llx). Backtrace:\n",
	    rsb_e->record.fault_pc,
	    (uint32_t)rsb_e->record.trap_type, rsb_e->record.trap_code);

	for (size_t frame_i = 0; frame_i < rsb_e->bt_frames_count; frame_i++) {
		printf(TAG "\t0x%08lx\n", rsb_e->bt_frames[frame_i]);
	}
}

/**
 * Submit RSB_E to CoreAnalytics (or another backing event provider as
 * appropriate).
 */
static void
rsb_entry_submit(rsb_entry_s *rsb_e)
{
	trap_telemetry_options_s options = rsb_e->options;

	bool matched_dump_bootarg = should_dump_trap(
		rsb_e->record.trap_type, rsb_e->record.trap_code);
	if (matched_dump_bootarg) {
		rsb_entry_dump(rsb_e);
	}

	ca_event_t ca_event = NULL;
	switch (options.telemetry_ca_event) {
	case TRAP_TELEMETRY_CA_EVENT_NONE: {
		/*
		 * Unless the event matches the dump boot-arg, we should never see
		 * unreported events in the backend. Instead, we expect these events
		 * to be dropped in the frontend without ever being submitted.
		 */
		assert(matched_dump_bootarg);
		break;
	}

	case TRAP_TELEMETRY_CA_EVENT_KERNEL_BRK: {
		ca_event = CA_EVENT_ALLOCATE(kernel_breakpoint_event);
		CA_EVENT_TYPE(kernel_breakpoint_event) * event = ca_event->data;

		/*
		 * The BRK telemetry format is somewhat less dense, so to avoid
		 * truncating (and to maintain the historical backtrace count) report
		 * five or fewer frames.
		 */
		uint32_t reported_bt_count =
		    MIN((uint32_t)rsb_e->bt_frames_count, 5);
		telemetry_backtrace_to_string(
			/* buf      */ event->backtrace,
			/* buf_size */ TRAP_TELEMETRY_BT_STR_LEN,
			/* tot      */ reported_bt_count,
			/* frames   */ rsb_e->bt_frames);

		event->brk_type = (uint32_t)rsb_e->record.trap_type;
		event->brk_code = (uint64_t)rsb_e->record.trap_code;
		event->faulting_address = rsb_e->record.fault_pc - vm_kernel_stext;
		strlcpy(event->uuid, kernel_uuid_string, CA_UUID_LEN);
		break;
	}

	case TRAP_TELEMETRY_CA_EVENT_INTERNAL: {
		int result;
		uuid_t *uuid = NULL;
		uint64_t offset = 0;

		ca_event = CA_EVENT_ALLOCATE(trap_telemetry_internal);
		CA_EVENT_TYPE(trap_telemetry_internal) * event = ca_event->data;

		backtrace_to_offset_bt_string(
			/* buf */ event->backtrace,
			/* buf_len */ TRAP_TELEMETRY_BT_STR_LEN,
			rsb_e->bt_frames,
			rsb_e->bt_frames_count);

		/*
		 * Internal events report the UUID of the binary containing the
		 * fault PC and offset of the fault PC into the executable region of
		 * that binary (__TEXT_EXEC).
		 */
		if ((result = get_uuid_and_text_offset_for_addr(
			    rsb_e->record.fault_pc, &uuid, &offset)) == 0) {
			/* Success! */
			event->trap_offset = offset;
			uuid_unparse(*uuid, event->trap_uuid);
		} else {
			/*
			 * We couldn't get the required data for symbolication for some
			 * odd reason.
			 * Report the offset into the executable region and the error as
			 * the UUID instead.
			 */
			event->trap_offset = rsb_e->record.fault_pc - vm_kernel_stext;
			(void)scnprintf(event->trap_uuid, CA_UUID_LEN, "error:%d\n",
			    result);
		}

		event->trap_type = (uint32_t)rsb_e->record.trap_type;
		event->trap_code = rsb_e->record.trap_code;
		break;
	}

	default: {
		panic("Unexpected telemetry CA event: %u\n",
		    options.telemetry_ca_event);
	}
	}

	if (ca_event) {
		CA_EVENT_SEND(ca_event);
	}
}

/**
 * Thread call which drains the record submission buffer.
 * There must be no more than one instance of this thread running at a time.
 */
static void
drain_record_submission_buffer_thread_call(__unused thread_call_param_t p0,
    __unused thread_call_param_t p1)
{
	size_t drain_count = 0;
	size_t drain_rd_idx = 0;
	trap_telemetry_tree_entry_s *tree_records[RECORD_SUBMISSION_BUFFER_LENGTH];

	/*
	 * We never expect for the submission thread to be scheduled while another
	 * thread which is attempting to enqueue is suspended above it (acquiring
	 * disables preemption) or while another submission thread is suspended
	 * above it (only one submission thread should ever be running).
	 *
	 * Thus, failing to acquire the lock anywhere in this function indicates
	 * that something is seriously wrong.
	 */
	safe_telemetry_lock_lock();

	/*
	 * If we're already draining, that means we either forgot to update
	 * rsb_is_draining or we have another thread draining (which should never
	 * happen).
	 */
	assert(!rsb_is_draining);
	rsb_is_draining = true;

	/*
	 * Iteratively drain the submission queue until no entries remain.
	 * Drops and reacquires the telemetry lock.
	 */
	while ((drain_count = rsb_count)) {
		/* LOCKED IN */
		drain_rd_idx = rsb_rd_idx;
		safe_telemetry_lock_unlock();

		/*
		 * It is safe to read these entries based on snapshots of DRAIN_COUNT
		 * and DRAIN_RD_IDX without holding the lock because all of the records'
		 * writes will have already become visible due to the lock's store
		 * release on the enqueue side. RSB entries are guaranteed to survive
		 * even when we aren't holding the lock so long as DRAIN_RD_IDX doesn't
		 * pass them. Since we are the only agent updating it, if we sequence
		 * the DRAIN_RD_IDX write after, we're fine.
		 *
		 * We may miss some records in this pass if other CPUs enqueue after the
		 * snapshot but we'll just pick them up in the next loop iteration.
		 * Additionally, since only one instance of this function will be
		 * running at a time, we don't need to worry about duplicate
		 * allocations/work.
		 */

		for (size_t i = 0; i < drain_count; i++) {
			size_t rsb_i = (drain_rd_idx + i) % RECORD_SUBMISSION_BUFFER_LENGTH;
			rsb_entry_s *rsb_e = record_submission_buffer + rsb_i;

			/* Finish processing the entry and submit it as needed. */
			rsb_entry_submit(rsb_e);

			if (rsb_e->options.report_once_per_site) {
				/*
				 * Though we don't insert it yet since we aren't holding the
				 * lock, create our tree record from the RSB entry.
				 */
				trap_telemetry_tree_entry_s *new_tree_record = kalloc_type(
					trap_telemetry_tree_entry_s, Z_WAITOK | Z_NOFAIL);

				new_tree_record->record = rsb_e->record;
				tree_records[i] = new_tree_record;
			} else {
				tree_records[i] = NULL;
			}
		}

		safe_telemetry_lock_lock();
		/* Insert draining entries into the splay as needed */
		for (size_t i = 0; i < drain_count; i++) {
			size_t rsb_i = (drain_rd_idx + i) % RECORD_SUBMISSION_BUFFER_LENGTH;
			rsb_entry_s *rsb_e = record_submission_buffer + rsb_i;

			if (rsb_e->options.report_once_per_site) {
				trap_telemetry_tree_entry_s *duplicate = SPLAY_INSERT(
					trap_telemetry_tree,
					&telemetry_splay_tree,
					tree_records[i]);

				/*
				 * Since we scan both the RSB and the splay tree before
				 * submitting a report once record, we structurally should never
				 * have multiple instances of any such record.
				 */
				(void)duplicate;
				assert(!duplicate);
			}
		}

		/* Dequeue the submitted entries from the RSB */
		rsb_rd_idx =
		    (rsb_rd_idx + drain_count) % RECORD_SUBMISSION_BUFFER_LENGTH;
		rsb_count -= drain_count;
		/* LOCKED OUT */
	}

	/* Done for now, if submitters have entries they'll need to call again. */
	rsb_is_draining = false;
	safe_telemetry_lock_unlock();
}

__startup_func
void
trap_telemetry_init(void)
{
	printf(TAG "trap_telemetry_init\n");
	SPLAY_INIT(&telemetry_splay_tree);

	drain_record_submission_buffer_callout = thread_call_allocate_with_options(
		drain_record_submission_buffer_thread_call, NULL,
		THREAD_CALL_PRIORITY_KERNEL, THREAD_CALL_OPTIONS_ONCE);

	if (!drain_record_submission_buffer_callout) {
		panic("Failed to allocate drain callout!");
	}

	{
		/* Ensure that all telemetry events can be encoded in the bitfield */
		trap_telemetry_options_s opt = (trap_telemetry_options_s) {0};
		uint8_t last_event = TRAP_TELEMETRY_CA_EVENT_COUNT - 1;
		opt.telemetry_ca_event = last_event;
		assert(opt.telemetry_ca_event == last_event);
	}
}

/**
 * Submit RSB_E to the record submission queue if it needs to be submitted.
 * Returns TRUE if the record was accepted (either enqueued or dupe'd), FALSE
 * otherwise.
 */
static bool
rsb_enqueue_if_needed(rsb_entry_s *rsb_e)
{
	bool record_accepted = true;
	bool should_flush_submission_buffer = false;
	trap_telemetry_tree_entry_s *splay_found_entry = NULL;
	trap_telemetry_tree_entry_s find_tree_e = {0};

	if (trap_debounce_buffer_has_match(&rsb_e->record)) {
		/* debounce dupe */
		return true;
	}

	if (!safe_telemetry_lock_try_lock()) {
		/*
		 * Failed to acquire the lock!
		 * We're likely in a nested exception. Since we can't safely do anything
		 * else with the record, just drop it.
		 */
		return false;
	}

	if (rsb_e->options.report_once_per_site) {
		/* First, scan the submission queue for matching, queued records */
		for (size_t i = 0; i < rsb_count; i++) {
			size_t rsb_i = (rsb_rd_idx + i) % RECORD_SUBMISSION_BUFFER_LENGTH;
			rsb_entry_s *rsb_e_i = record_submission_buffer + rsb_i;
			if (match_record_compare(&rsb_e->record, &rsb_e_i->record) == 0) {
				/* Match, no need to report again. */
				goto DONE_LOCKED;
			}
		}

		/* Next, try for a record in the splay */
		find_tree_e.record = rsb_e->record;
		splay_found_entry = SPLAY_FIND(trap_telemetry_tree,
		    &telemetry_splay_tree,
		    &find_tree_e);
		if (splay_found_entry) {
			/* Match, no need to report again. */
			goto DONE_LOCKED;
		}
	}


	/*
	 * If we haven't hit any disqualifying conditions, this means we have a new
	 * entry which needs to be enqueued for reporting.
	 */
	record_accepted = rsb_enqueue_locked(rsb_e);
	should_flush_submission_buffer = record_accepted && !rsb_is_draining;

	if (record_accepted) {
		/* We've handled the record, so mark it for debouncing */
		trap_debounce_buffer_enter(&rsb_e->record);
#if DEVELOPMENT || DEBUG
		os_atomic_inc(&trap_telemetry_reported_events, relaxed);
#endif /* DEVELOPMENT || DEBUG */
	} else {
		/*
		 * Failed to enqueue. Since we have no better options, drop the event.
		 */
#if DEVELOPMENT || DEBUG
		os_atomic_inc(&trap_telemetry_capacity_dropped_events, relaxed);
#endif /* DEVELOPMENT || DEBUG */
	}

DONE_LOCKED:
	safe_telemetry_lock_unlock();

	if (should_flush_submission_buffer &&
	    startup_phase >= STARTUP_SUB_THREAD_CALL) {
		/*
		 * We submitted a new entry while the drain thread was either exiting or
		 * not running. Queue a new flush. Multiple calls here before the drain
		 * starts running will not result in multiple calls being queued due to
		 * THREAD_CALL_OPTIONS_ONCE.
		 */
		thread_call_enter(drain_record_submission_buffer_callout);
	}

	return record_accepted;
}

/**
 * Should a given trap be ignored/not reported?
 */
static bool
should_ignore_trap(
	trap_telemetry_type_t trap_type,
	uint64_t trap_code,
	trap_telemetry_options_s options)
{
	if (trap_telemetry_disable_all) {
		/* Telemetry is disabled, drop all events. */
		return true;
	}

	if ((options.telemetry_ca_event == TRAP_TELEMETRY_CA_EVENT_NONE ||
	    trap_telemetry_disable_ca) &&
	    !should_dump_trap(trap_type, trap_code)) {
		/* Trap won't be reported anywhere, so it can be dropped. */
		return true;
	}

	return false;
}

bool
trap_telemetry_report_exception(
	trap_telemetry_type_t trap_type,
	uint64_t trap_code,
	trap_telemetry_options_s options,
	void *saved_state)
{
	if (should_ignore_trap(trap_type, trap_code, options)) {
		/*
		 * Don't bother reporting the trap. Since this is not an error, report
		 * that we handled the trap as expected.
		 */
		return true;
	}

#if __arm64__
	arm_saved_state_t *state = (arm_saved_state_t *)saved_state;

	uintptr_t faulting_address = get_saved_state_pc(state);
	uintptr_t saved_fp = get_saved_state_fp(state);
#else
	x86_saved_state64_t *state = (x86_saved_state64_t *)saved_state;

	uintptr_t faulting_address = state->isf.rip;
	uintptr_t saved_fp = state->rbp;
#endif

	struct backtrace_control ctl = {
		.btc_frame_addr = (uintptr_t)saved_fp,
	};

	rsb_entry_s submission_e = { 0 };
	submission_e.record.trap_type = trap_type;
	submission_e.record.trap_code = trap_code;
	submission_e.record.fault_pc = faulting_address;
	submission_e.options = options;
	submission_e.bt_frames_count = backtrace(
		submission_e.bt_frames, TRAP_TELEMETRY_BT_FRAMES, &ctl, NULL);

	return rsb_enqueue_if_needed(&submission_e);
}

__attribute__((noinline))
bool
trap_telemetry_report_simulated_trap(
	trap_telemetry_type_t trap_type,
	uint64_t trap_code,
	trap_telemetry_options_s options)
{
	if (should_ignore_trap(trap_type, trap_code, options)) {
		/*
		 * Don't bother reporting the trap. Since this is not an error, report
		 * that we did handle the trap as expected.
		 */
		return true;
	}

	/*
	 * We want to provide a backtrace as if a trap ocurred at the callsite of
	 * the simulated trap. Doing this safely is somewhat awkward as
	 * __builtin_frame_address with a non-zero argument can itself fault (if our
	 * callers frame pointer is invalid) so instead we take a backtrace starting
	 * in our own frame and chop it up as expected.
	 */

	const size_t frames_count = TRAP_TELEMETRY_BT_FRAMES + 1;
	uintptr_t frames[frames_count];

	struct backtrace_control ctl = {
		.btc_frame_addr = (uintptr_t)__builtin_frame_address(0),
	};

	size_t frames_valid_count = backtrace(frames, frames_count, &ctl, NULL);
	if (frames_valid_count) {
		/*
		 * Take the first backtrace entry as the fault address and then place
		 * all other entries into the backtrace. The first backtrace is our
		 * caller (due to the noinline attribute), which gives us the fault
		 * address as the call site (as desired).
		 */
		return trap_telemetry_report_simulated_trap_with_backtrace(
			trap_type,
			trap_code,
			options,
			/* fault_pc */ frames[0],
			/* frames */ frames + 1,
			/* frames_valid_count */ frames_valid_count - 1);
	} else {
		/* Failed to take a backtrace? Report just the return address then. */
		return trap_telemetry_report_simulated_trap_with_backtrace(
			trap_type,
			trap_code,
			options,
			/* fault_pc */ (uintptr_t)__builtin_return_address(0),
			/* frames */ NULL,
			/* frames_valid_count */ 0);
	}
}

bool
trap_telemetry_report_simulated_trap_with_backtrace(
	trap_telemetry_type_t trap_type,
	uint64_t trap_code,
	trap_telemetry_options_s options,
	uintptr_t fault_pc,
	uintptr_t *frames,
	size_t frames_valid_count)
{
	if (should_ignore_trap(trap_type, trap_code, options)) {
		/*
		 * Don't bother reporting the trap. Since this is not an error, report
		 * that we did handle the trap as expected.
		 */
		return true;
	}

	rsb_entry_s submission_e = { 0 };
	submission_e.record.trap_type = trap_type;
	submission_e.record.trap_code = trap_code;
	submission_e.options = options;

	// only copy up to TRAP_TELEMETRY_BT_FRAMES frames
	if (frames_valid_count >= TRAP_TELEMETRY_BT_FRAMES) {
		frames_valid_count = TRAP_TELEMETRY_BT_FRAMES;
	}

	submission_e.bt_frames_count = frames_valid_count;
	submission_e.record.fault_pc = fault_pc;

	memcpy(submission_e.bt_frames, frames, frames_valid_count * sizeof(*frames));

	return rsb_enqueue_if_needed(&submission_e);
}
