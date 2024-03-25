/*
 * Copyright (c) 2019-2023 Apple Inc. All rights reserved.
 */

#undef offset

#include <kern/cpu_data.h>
#include <os/base.h>
#include <os/hash.h>
#include <os/object.h>
#include <os/log.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <vm/vm_kern.h>
#include <mach/vm_statistics.h>
#include <kern/debug.h>
#include <libkern/libkern.h>
#include <libkern/kernel_mach_header.h>
#include <pexpert/pexpert.h>
#include <uuid/uuid.h>
#include <sys/msgbuf.h>

#include <mach/mach_time.h>
#include <kern/thread.h>
#include <kern/simple_lock.h>
#include <kern/kalloc.h>
#include <kern/clock.h>
#include <kern/assert.h>
#include <kern/smr_hash.h>
#include <kern/startup.h>
#include <kern/task.h>

#include <firehose/firehose_types_private.h>
#include <firehose/tracepoint_private.h>
#include <firehose/chunk_private.h>
#include <os/firehose_buffer_private.h>
#include <os/firehose.h>
#include <os/log_private.h>

#include "log_encode.h"
#include "log_internal.h"
#include "log_mem.h"
#include "log_queue.h"
#include "trace_internal.h"

#define OS_LOGMEM_BUF_ORDER 14
#define OS_LOGMEM_MIN_LOG_ORDER 9
#define OS_LOGMEM_MAX_LOG_ORDER (OS_LOG_MAX_SIZE_ORDER)

#define OS_LOG_SUBSYSTEM_MAX_CNT 1024
#define OS_LOG_SUBSYSTEM_NONE 0xffff
#define OS_LOG_SUBSYSTEM_BASE 0x0001 // OS_LOG_DEFAULT takes 0 by definition
#define OS_LOG_SUBSYSTEM_LAST (OS_LOG_SUBSYSTEM_BASE + OS_LOG_SUBSYSTEM_MAX_CNT)
#define OS_LOG_SUBSYSTEM_NAME_MAX_LEN 128

/*
 * OSLog subsystem type. The struct layout matches its libtrace counterpart
 * and also matches what libtrace (logd) expects from subsystem registration
 * metadata payload.
 */
struct os_log_subsystem_s {
	uint16_t ols_id;
	union {
		struct {
			uint8_t ols_sub_size;
			uint8_t ols_cat_size;
		};
		uint16_t ols_sizes;
	};
	char ols_name[2 * OS_LOG_SUBSYSTEM_NAME_MAX_LEN];
};

struct os_log_s {
	struct os_log_subsystem_s   ol_subsystem;
	struct smrq_slink           ol_hash_link;
};

struct os_log_s _os_log_default;
struct os_log_s _os_log_replay;

/* Counters for persistence mode */
SCALABLE_COUNTER_DEFINE(oslog_p_total_msgcount);
SCALABLE_COUNTER_DEFINE(oslog_p_metadata_saved_msgcount);
SCALABLE_COUNTER_DEFINE(oslog_p_metadata_dropped_msgcount);
SCALABLE_COUNTER_DEFINE(oslog_p_signpost_saved_msgcount);
SCALABLE_COUNTER_DEFINE(oslog_p_signpost_dropped_msgcount);
SCALABLE_COUNTER_DEFINE(oslog_p_error_count);
SCALABLE_COUNTER_DEFINE(oslog_p_saved_msgcount);
SCALABLE_COUNTER_DEFINE(oslog_p_dropped_msgcount);
SCALABLE_COUNTER_DEFINE(oslog_p_boot_dropped_msgcount);
SCALABLE_COUNTER_DEFINE(oslog_p_coprocessor_total_msgcount);
SCALABLE_COUNTER_DEFINE(oslog_p_coprocessor_dropped_msgcount);
SCALABLE_COUNTER_DEFINE(oslog_p_unresolved_kc_msgcount);

/* Counters for msgbuf logging */
SCALABLE_COUNTER_DEFINE(oslog_msgbuf_msgcount)
SCALABLE_COUNTER_DEFINE(oslog_msgbuf_dropped_msgcount)

/* Log subsystem counters */
SCALABLE_COUNTER_DEFINE(oslog_subsystem_count);
SCALABLE_COUNTER_DEFINE(oslog_subsystem_found);
SCALABLE_COUNTER_DEFINE(oslog_subsystem_dropped);

LCK_GRP_DECLARE(oslog_cache_lock_grp, "oslog_cache_lock_grp");
LCK_TICKET_DECLARE(oslog_cache_lock, &oslog_cache_lock_grp);

static bool oslog_boot_done = false;
static SECURITY_READ_ONLY_LATE(bool) oslog_disabled = false;

static uint16_t os_log_subsystem_id = OS_LOG_SUBSYSTEM_BASE;

static struct logmem_s os_log_mem;
static struct smr_hash os_log_cache;

static struct firehose_chunk_s firehose_boot_chunk = {
	.fc_pos = {
		.fcp_next_entry_offs = offsetof(struct firehose_chunk_s, fc_data),
		.fcp_private_offs = FIREHOSE_CHUNK_SIZE,
		.fcp_refcnt = 1, // Indicate that there is a writer to this chunk
		.fcp_stream = firehose_stream_persist,
		.fcp_flag_io = 1, // Lets assume this is coming from the io bank
	},
};

bool os_log_disabled(void);

extern vm_offset_t kernel_firehose_addr;
extern bool bsd_log_lock(bool);
extern void bsd_log_unlock(void);
extern void logwakeup(void);
extern void oslog_stream(bool, firehose_tracepoint_id_u, uint64_t, const void *, size_t);
extern void *OSKextKextForAddress(const void *);

static bool
os_log_safe(void)
{
	return oslog_is_safe() || startup_phase < STARTUP_SUB_EARLY_BOOT;
}

static bool
os_log_turned_off(void)
{
	return oslog_disabled || (atm_get_diagnostic_config() & ATM_TRACE_OFF);
}

bool
os_log_info_enabled(os_log_t log __unused)
{
	return !os_log_turned_off();
}

bool
os_log_debug_enabled(os_log_t log __unused)
{
	return !os_log_turned_off();
}

bool
os_log_disabled(void)
{
	return oslog_disabled;
}

static inline size_t
log_payload_priv_data_size(const log_payload_s *lp)
{
	assert3u(lp->lp_pub_data_size, <=, lp->lp_data_size);
	return lp->lp_data_size - lp->lp_pub_data_size;
}

static inline const uint8_t *
log_payload_priv_data(const log_payload_s *lp, const uint8_t *lp_data)
{
	if (log_payload_priv_data_size(lp) == 0) {
		return NULL;
	}
	return &lp_data[lp->lp_pub_data_size];
}

static void
log_payload_init(log_payload_t lp, firehose_stream_t stream, firehose_tracepoint_id_u ftid,
    uint64_t timestamp, size_t data_size, size_t pub_data_size)
{
	assert3u(pub_data_size, <=, data_size);
	assert3u(data_size, <, UINT16_MAX);

	lp->lp_stream = stream;
	lp->lp_ftid = ftid;
	lp->lp_timestamp = timestamp;
	lp->lp_pub_data_size = (uint16_t)pub_data_size;
	lp->lp_data_size = (uint16_t)data_size;
}

static firehose_stream_t
firehose_stream(os_log_type_t type)
{
	return (type == OS_LOG_TYPE_INFO || type == OS_LOG_TYPE_DEBUG) ?
	       firehose_stream_memory : firehose_stream_persist;
}

static firehose_tracepoint_id_t
firehose_ftid(os_log_type_t type, const char *fmt, firehose_tracepoint_flags_t flags,
    void *dso, void *addr, bool driverKit)
{
	uint32_t off;

	if (driverKit) {
		/*
		 * Set FIREHOSE_TRACEPOINT_PC_DYNAMIC_BIT so logd will not try
		 * to find the format string in the executable text.
		 */
		off = (uint32_t)((uintptr_t)addr | FIREHOSE_TRACEPOINT_PC_DYNAMIC_BIT);
	} else {
		off = _os_trace_offset(dso, fmt, (_firehose_tracepoint_flags_activity_t)flags);
	}

	return FIREHOSE_TRACE_ID_MAKE(firehose_tracepoint_namespace_log, type, flags, off);
}

static firehose_tracepoint_flags_t
firehose_ftid_flags(const void *dso, bool driverKit)
{
	kc_format_t kcformat = KCFormatUnknown;
	__assert_only bool result = PE_get_primary_kc_format(&kcformat);
	assert(result);

	if (kcformat == KCFormatStatic || kcformat == KCFormatKCGEN) {
		return _firehose_tracepoint_flags_pc_style_shared_cache;
	}

	/*
	 * driverKit will have the dso set as MH_EXECUTE (it is logging from a
	 * syscall in the kernel) but needs logd to parse the address as an
	 * absolute pc.
	 */
	const kernel_mach_header_t *mh = dso;
	if (mh->filetype == MH_EXECUTE && !driverKit) {
		return _firehose_tracepoint_flags_pc_style_main_exe;
	}

	return _firehose_tracepoint_flags_pc_style_absolute;
}

static void *
resolve_dso(const char *fmt, void *dso, void *addr, bool driverKit)
{
	kc_format_t kcformat = KCFormatUnknown;

	if (!addr || !PE_get_primary_kc_format(&kcformat)) {
		return NULL;
	}

	switch (kcformat) {
	case KCFormatStatic:
	case KCFormatKCGEN:
		dso = PE_get_kc_baseaddress(KCKindPrimary);
		break;
	case KCFormatDynamic:
	case KCFormatFileset:
		if (!dso && (dso = (void *)OSKextKextForAddress(fmt)) == NULL) {
			return NULL;
		}
		if (!_os_trace_addr_in_text_segment(dso, fmt)) {
			return NULL;
		}
		if (!driverKit && (dso != (void *)OSKextKextForAddress(addr))) {
			return NULL;
		}
		break;
	default:
		panic("unknown KC format type");
	}

	return dso;
}

static inline uintptr_t
resolve_location(firehose_tracepoint_flags_t flags, uintptr_t dso, uintptr_t addr,
    bool driverKit, size_t *loc_size)
{
	switch (flags & _firehose_tracepoint_flags_pc_style_mask) {
	case _firehose_tracepoint_flags_pc_style_shared_cache:
	case _firehose_tracepoint_flags_pc_style_main_exe:
		*loc_size = sizeof(uint32_t);
		return addr - dso;
	case _firehose_tracepoint_flags_pc_style_absolute:
		*loc_size = sizeof(uintptr_t);
		return driverKit ? addr : VM_KERNEL_UNSLIDE(addr);
	default:
		panic("Unknown firehose tracepoint flags %x", flags);
	}
}

__startup_func
static void
oslog_init(void)
{
	/*
	 * Disable kernel logging if ATM_TRACE_DISABLE set. ATM_TRACE_DISABLE
	 * bit is not supposed to change during a system run but nothing really
	 * prevents userspace from unintentionally doing so => we stash initial
	 * value in a dedicated variable for a later reference, just in case.
	 */
	oslog_disabled = atm_get_diagnostic_config() & ATM_TRACE_DISABLE;

	if (!oslog_disabled) {
		smr_hash_init(&os_log_cache, OS_LOG_SUBSYSTEM_MAX_CNT / 4);
	}
}
STARTUP(OSLOG, STARTUP_RANK_FIRST, oslog_init);

__startup_func
static void
oslog_init_logmem(void)
{
	if (os_log_disabled()) {
		printf("Long logs support disabled: Logging disabled by ATM\n");
		return;
	}

	const size_t logmem_size = logmem_required_size(OS_LOGMEM_BUF_ORDER, OS_LOGMEM_MIN_LOG_ORDER);
	vm_offset_t addr;

	if (kmem_alloc(kernel_map, &addr, logmem_size + ptoa(2),
	    KMA_KOBJECT | KMA_PERMANENT | KMA_ZERO | KMA_GUARD_FIRST | KMA_GUARD_LAST,
	    VM_KERN_MEMORY_LOG) == KERN_SUCCESS) {
		logmem_init(&os_log_mem, (void *)(addr + PAGE_SIZE), logmem_size,
		    OS_LOGMEM_BUF_ORDER, OS_LOGMEM_MIN_LOG_ORDER, OS_LOGMEM_MAX_LOG_ORDER);
		printf("Long logs support configured: size: %u\n", os_log_mem.lm_cnt_free);
	} else {
		printf("Long logs support disabled: Not enough memory\n");
	}
}
STARTUP(OSLOG, STARTUP_RANK_SECOND, oslog_init_logmem);

bool
os_log_encoded_metadata(firehose_tracepoint_id_u ftid, uint64_t ts, const void *msg,
    size_t msg_size)
{
	assert(ftid.ftid._namespace == firehose_tracepoint_namespace_metadata);
	counter_inc(&oslog_p_total_msgcount);

	if (!os_log_safe() || os_log_disabled()) {
		counter_inc(&oslog_p_metadata_dropped_msgcount);
		return false;
	}

	log_payload_s log;
	log_payload_init(&log, firehose_stream_metadata, ftid, ts, msg_size, msg_size);

	if (log_queue_log(&log, msg, true)) {
		return true;
	}

	counter_inc(&oslog_p_metadata_dropped_msgcount);
	return false;
}

bool
os_log_encoded_log(firehose_tracepoint_id_u ftid, uint64_t ts, const void *msg,
    size_t msg_size, size_t pub_data_size)
{
	assert(ftid.ftid._namespace == firehose_tracepoint_namespace_log);
	counter_inc(&oslog_p_total_msgcount);

	if (!os_log_safe() || os_log_disabled()) {
		counter_inc(&oslog_p_dropped_msgcount);
		return false;
	}

	firehose_stream_t stream = firehose_stream(ftid.ftid._type);

	log_payload_s log;
	log_payload_init(&log, stream, ftid, ts, msg_size, pub_data_size);

	if (log_queue_log(&log, msg, true)) {
		return true;
	}

	counter_inc(&oslog_p_dropped_msgcount);
	return false;
}

bool
os_log_encoded_signpost(firehose_tracepoint_id_u ftid, uint64_t ts, const void *msg,
    size_t msg_size, size_t pub_data_size)
{
	assert(ftid.ftid._namespace == firehose_tracepoint_namespace_signpost);
	counter_inc(&oslog_p_total_msgcount);

	if (!os_log_safe() || os_log_disabled()) {
		counter_inc(&oslog_p_signpost_dropped_msgcount);
		return false;
	}

	log_payload_s log;
	log_payload_init(&log, firehose_stream_signpost, ftid, ts, msg_size, pub_data_size);

	if (log_queue_log(&log, msg, true)) {
		return true;
	}

	counter_inc(&oslog_p_signpost_dropped_msgcount);
	return false;
}

static inline size_t
os_log_subsystem_name_size(const char *name)
{
	return MIN(strlen(name) + 1, OS_LOG_SUBSYSTEM_NAME_MAX_LEN);
}

bool
os_log_subsystem_id_valid(uint16_t sid)
{
	return sid >= OS_LOG_SUBSYSTEM_BASE && sid <= os_log_subsystem_id;
}

static inline size_t
os_log_subsystem_id_length(const struct os_log_subsystem_s *sub)
{
	return sub->ols_sub_size + sub->ols_cat_size;
}

static inline size_t
os_log_subsystem_size(const struct os_log_subsystem_s *tbs)
{
	assert(tbs->ols_sub_size <= OS_LOG_SUBSYSTEM_NAME_MAX_LEN);
	assert(tbs->ols_cat_size <= OS_LOG_SUBSYSTEM_NAME_MAX_LEN);
	return sizeof(*tbs) - sizeof(tbs->ols_name) + os_log_subsystem_id_length(tbs);
}

static void
os_log_subsystem_init(struct os_log_subsystem_s *ols, uint16_t sid, const char *sub, const char *cat)
{
	ols->ols_sub_size = os_log_subsystem_name_size(sub);
	ols->ols_cat_size = os_log_subsystem_name_size(cat);
	strlcpy(&ols->ols_name[0], sub, OS_LOG_SUBSYSTEM_NAME_MAX_LEN);
	strlcpy(&ols->ols_name[ols->ols_sub_size], cat, OS_LOG_SUBSYSTEM_NAME_MAX_LEN);
	ols->ols_id = sid;
}

static void
os_log_subsystem_register(const struct os_log_subsystem_s *ols, uint64_t stamp)
{
	assert(os_log_subsystem_id_valid(ols->ols_id));

	firehose_tracepoint_id_u trace_id;
	trace_id.ftid_value = FIREHOSE_TRACE_ID_MAKE(firehose_tracepoint_namespace_metadata,
	    _firehose_tracepoint_type_metadata_subsystem, 0, ols->ols_id);

	os_log_encoded_metadata(trace_id, stamp, ols, os_log_subsystem_size(ols));
}

#if DEVELOPMENT || DEBUG
static bool
os_log_valid(const struct os_log_s *log)
{
	return os_log_subsystem_id_valid(log->ol_subsystem.ols_id);
}
#endif // DEVELOPMENT || DEBUG

static smrh_key_t
os_log_key(const struct os_log_subsystem_s *sub)
{
	return (smrh_key_t) {
		       .smrk_opaque = sub->ols_name,
		       .smrk_len    = os_log_subsystem_id_length(sub)
	};
}

static uint32_t
os_log_key_hash(smrh_key_t key, uint32_t seed)
{
	return smrh_key_hash_mem(key, seed);
}

static bool
os_log_key_equ(smrh_key_t k1, smrh_key_t k2)
{
	return k1.smrk_len == k2.smrk_len ? smrh_key_equ_mem(k1, k2) : false;
}

static uint32_t
os_log_hash(const struct smrq_slink *link, uint32_t seed)
{
	const os_log_t log = __container_of(link, struct os_log_s, ol_hash_link);
	return os_log_key_hash(os_log_key(&log->ol_subsystem), seed);
}

static bool
os_log_equ(const struct smrq_slink *link, smrh_key_t key)
{
	const os_log_t h = __container_of(link, struct os_log_s, ol_hash_link);
	return os_log_key_equ(os_log_key(&h->ol_subsystem), key);
}

static bool
oslog_try_get(void *oslog __unused)
{
	return true;
}

SMRH_TRAITS_DEFINE(os_log_cache_traits, struct os_log_s, ol_hash_link,
    .domain         = &smr_oslog,
    .key_hash       = os_log_key_hash,
    .key_equ        = os_log_key_equ,
    .obj_hash       = os_log_hash,
    .obj_equ        = os_log_equ,
    .obj_try_get    = oslog_try_get
    );

static os_log_t
os_log_cache_find_by_sub(const struct os_log_subsystem_s *sub)
{
	os_log_t log = smr_hash_get(&os_log_cache, os_log_key(sub), &os_log_cache_traits);
	assert(!log || os_log_valid(log));
	return log;
}

static os_log_t
os_log_cache_insert(os_log_t log)
{
	assert(os_log_subsystem_id_valid(log->ol_subsystem.ols_id));

	os_log_t found = smr_hash_serialized_get_or_insert(&os_log_cache,
	    os_log_key(&log->ol_subsystem), &log->ol_hash_link,
	    &os_log_cache_traits);
	assert(!found || os_log_valid(found));
	return found;
}

static os_log_t
os_log_allocate(const struct os_log_subsystem_s *subsystem)
{
	os_log_t new = kalloc_type(struct os_log_s, Z_WAITOK_ZERO);
	if (new) {
		new->ol_subsystem = *subsystem;
	}
	return new;
}

static uint16_t
os_log_subsystem_id_next(void)
{
	assert(os_log_subsystem_id_valid(os_log_subsystem_id));

	if (__improbable(os_log_subsystem_id == OS_LOG_SUBSYSTEM_LAST)) {
		return OS_LOG_SUBSYSTEM_NONE;
	}
	return os_log_subsystem_id++;
}

static void
os_log_subsystem_id_revert(uint16_t __assert_only sid)
{
	assert(os_log_subsystem_id_valid(os_log_subsystem_id));
	assert3u(os_log_subsystem_id, ==, sid + 1);
	os_log_subsystem_id--;
}

static os_log_t
os_log_create_impl(const char *subsystem, const char *category, uint64_t stamp)
{
	if (os_log_disabled()) {
		return OS_LOG_DISABLED;
	}

	struct os_log_subsystem_s new_sub;
	os_log_subsystem_init(&new_sub, OS_LOG_SUBSYSTEM_NONE, subsystem, category);

	os_log_t log = os_log_cache_find_by_sub(&new_sub);
	if (log) {
		counter_inc(&oslog_subsystem_found);
		return log;
	}

	if (!(log = os_log_allocate(&new_sub))) {
		counter_inc(&oslog_subsystem_dropped);
		return OS_LOG_DEFAULT;
	}

	lck_ticket_lock(&oslog_cache_lock, &oslog_cache_lock_grp);

	log->ol_subsystem.ols_id = os_log_subsystem_id_next();
	if (__improbable(log->ol_subsystem.ols_id == OS_LOG_SUBSYSTEM_NONE)) {
		lck_ticket_unlock(&oslog_cache_lock);
		kfree_type(struct os_log_s, log);
		counter_inc(&oslog_subsystem_dropped);
		return OS_LOG_DEFAULT;
	}

	os_log_t found = os_log_cache_insert(log);
	if (__improbable(found)) {
		os_log_subsystem_id_revert(log->ol_subsystem.ols_id);
		lck_ticket_unlock(&oslog_cache_lock);
		kfree_type(struct os_log_s, log);
		counter_inc(&oslog_subsystem_found);
		return found;
	}

	lck_ticket_unlock(&oslog_cache_lock);

	os_log_subsystem_register(&log->ol_subsystem, stamp);
	counter_inc(&oslog_subsystem_count);

	return log;
}

os_log_t
os_log_create(const char *subsystem, const char *category)
{
	uint64_t stamp = firehose_tracepoint_time(firehose_activity_flags_default);
	return os_log_create_impl(subsystem, category, stamp);
}

static void
_os_log_to_msgbuf_internal(const char *format, va_list args, uint64_t timestamp,
    bool safe, bool logging, bool addcr)
{
	/*
	 * The following threshold was determined empirically as the point where
	 * it would be more advantageous to be able to fit in more log lines than
	 * to know exactly when a log line was printed out. We don't want to use up
	 * a large percentage of the log buffer on timestamps in a memory-constricted
	 * environment.
	 */
	const int MSGBUF_TIMESTAMP_THRESHOLD = 4096;
	static int msgbufreplay = -1;
	static bool newlogline = true;
	va_list args_copy;

	if (!bsd_log_lock(safe)) {
		counter_inc(&oslog_msgbuf_dropped_msgcount);
		return;
	}

	if (!safe) {
		if (-1 == msgbufreplay) {
			msgbufreplay = msgbufp->msg_bufx;
		}
	} else if (logging && (-1 != msgbufreplay)) {
		uint32_t i;
		uint32_t localbuff_size;
		int newl, position;
		char *localbuff, *p, *s, *next, ch;

		position = msgbufreplay;
		msgbufreplay = -1;
		localbuff_size = (msgbufp->msg_size + 2); /* + '\n' + '\0' */
		/* Size for non-blocking */
		if (localbuff_size > 4096) {
			localbuff_size = 4096;
		}
		bsd_log_unlock();
		/* Allocate a temporary non-circular buffer */
		localbuff = kalloc_data(localbuff_size, Z_NOWAIT);
		if (localbuff != NULL) {
			/* in between here, the log could become bigger, but that's fine */
			bsd_log_lock(true);
			/*
			 * The message buffer is circular; start at the replay pointer, and
			 * make one loop up to write pointer - 1.
			 */
			p = msgbufp->msg_bufc + position;
			for (i = newl = 0; p != msgbufp->msg_bufc + msgbufp->msg_bufx - 1; ++p) {
				if (p >= msgbufp->msg_bufc + msgbufp->msg_size) {
					p = msgbufp->msg_bufc;
				}
				ch = *p;
				if (ch == '\0') {
					continue;
				}
				newl = (ch == '\n');
				localbuff[i++] = ch;
				if (i >= (localbuff_size - 2)) {
					break;
				}
			}
			bsd_log_unlock();

			if (!newl) {
				localbuff[i++] = '\n';
			}
			localbuff[i++] = 0;

			s = localbuff;
			while ((next = strchr(s, '\n'))) {
				next++;
				ch = next[0];
				next[0] = 0;
				os_log(&_os_log_replay, "%s", s);
				next[0] = ch;
				s = next;
			}
			kfree_data(localbuff, localbuff_size);
		}
		bsd_log_lock(true);
	}

	/* Do not prepend timestamps when we are memory-constricted */
	if (newlogline && (msgbufp->msg_size > MSGBUF_TIMESTAMP_THRESHOLD)) {
		clock_sec_t secs;
		clock_usec_t microsecs;
		absolutetime_to_microtime(timestamp, &secs, &microsecs);
		printf_log_locked(FALSE, "[%5lu.%06u]: ", (unsigned long)secs, microsecs);
	}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
	va_copy(args_copy, args);
	newlogline = vprintf_log_locked(format, args_copy, addcr);
	va_end(args_copy);
#pragma clang diagnostic pop

	bsd_log_unlock();
	logwakeup();
	counter_inc(&oslog_msgbuf_msgcount);
}

static void
_os_log_to_log_internal(uint16_t sid, os_log_type_t type, const char *fmt, va_list args,
    uint64_t ts, void *addr, void *dso, bool driverKit)
{
	dso = resolve_dso(fmt, dso, addr, driverKit);
	if (__improbable(!dso)) {
		counter_inc(&oslog_p_unresolved_kc_msgcount);
		return;
	}

	firehose_tracepoint_flags_t flags = firehose_ftid_flags(dso, driverKit);
	if (sid != 0) {
		flags |= _firehose_tracepoint_flags_log_has_subsystem;
	}

	size_t loc_sz = 0;
	uintptr_t loc = resolve_location(flags, (uintptr_t)dso, (uintptr_t)addr,
	    driverKit, &loc_sz);

	firehose_tracepoint_id_u ftid = {
		.ftid_value = firehose_ftid(type, fmt, flags, dso, addr, driverKit)
	};

	__attribute__((uninitialized, aligned(8)))
	uint8_t buffer[OS_LOG_BUFFER_MAX_SIZE];
	struct os_log_context_s ctx;

	os_log_context_init(&ctx, &os_log_mem, buffer, sizeof(buffer));

	if (!os_log_context_encode(&ctx, fmt, args, loc, loc_sz, sid)) {
		counter_inc(&oslog_p_error_count);
		os_log_context_free(&ctx);
		return;
	}

	log_payload_s log;
	log_payload_init(&log, firehose_stream(type), ftid, ts, ctx.ctx_content_sz, ctx.ctx_content_sz);

	if (!log_queue_log(&log, ctx.ctx_buffer, true)) {
		counter_inc(&oslog_p_dropped_msgcount);
	}

	os_log_context_free(&ctx);
}

static void
_os_log_with_args_internal(os_log_t oslog, os_log_type_t type, const char *fmt,
    va_list args, uint64_t ts, void *addr, void *dso, bool driverKit, bool addcr)
{
	counter_inc(&oslog_p_total_msgcount);

	if (oslog == OS_LOG_DISABLED) {
		counter_inc(&oslog_p_dropped_msgcount);
		return;
	}

	if (__improbable(fmt[0] == '\0')) {
		counter_inc(&oslog_p_error_count);
		return;
	}

	/* early boot can log to dmesg for later replay (27307943) */
	bool safe = os_log_safe();
	bool logging = !os_log_turned_off();

	if (oslog != &_os_log_replay) {
		_os_log_to_msgbuf_internal(fmt, args, ts, safe, logging, addcr);
	}

	if (safe && logging) {
		const uint16_t sid = oslog->ol_subsystem.ols_id;
		_os_log_to_log_internal(sid, type, fmt, args, ts, addr, dso, driverKit);
	}
}

__attribute__((noinline, not_tail_called)) void
_os_log_internal(void *dso, os_log_t log, uint8_t type, const char *fmt, ...)
{
	uint64_t ts = firehose_tracepoint_time(firehose_activity_flags_default);
	void *addr = __builtin_return_address(0);
	va_list args;

	va_start(args, fmt);
	_os_log_with_args_internal(log, type, fmt, args, ts, addr, dso, FALSE, FALSE);
	va_end(args);
}

__attribute__((noinline, not_tail_called)) void
_os_log_at_time(void *dso, os_log_t log, uint8_t type, uint64_t ts, const char *fmt, ...)
{
	void *addr = __builtin_return_address(0);
	va_list args;

	va_start(args, fmt);
	_os_log_with_args_internal(log, type, fmt, args, ts, addr, dso, FALSE, FALSE);
	va_end(args);
}

__attribute__((noinline, not_tail_called)) int
_os_log_internal_driverKit(void *dso, os_log_t log, uint8_t type, const char *fmt, ...)
{
	uint64_t ts = firehose_tracepoint_time(firehose_activity_flags_default);
	void *addr = __builtin_return_address(0);
	bool driverKitLog = FALSE;
	va_list args;

	/*
	 * We want to be able to identify dexts from the logs.
	 *
	 * Usually the addr is used to understand if the log line
	 * was generated by a kext or the kernel main executable.
	 * Logd uses copyKextUUIDForAddress with the addr specified
	 * in the log line to retrieve the kext UUID of the sender.
	 *
	 * Dext however are not loaded in kernel space so they do not
	 * have a kernel range of addresses.
	 *
	 * To make the same mechanism work, OSKext fakes a kernel
	 * address range for dexts using the loadTag,
	 * so we just need to use the loadTag as addr here
	 * to allow logd to retrieve the correct UUID.
	 *
	 * NOTE: loadTag is populated in the task when the dext is matching,
	 * so if log lines are generated before the matching they will be
	 * identified as kernel main executable.
	 */
	task_t self_task = current_task();

	/*
	 * Only dexts are supposed to use this log path. Verified in log_data()
	 * but worth of another check here in case this function gets called
	 * directly.
	 */
	if (!task_is_driver(self_task)) {
		return EPERM;
	}

	uint64_t loadTag = get_task_loadTag(self_task);
	if (loadTag != 0) {
		driverKitLog = TRUE;
		addr = (void *)loadTag;
	}

	va_start(args, fmt);
	_os_log_with_args_internal(log, type, fmt, args, ts, addr, dso, driverKitLog, true);
	va_end(args);

	return 0;
}

__attribute__((noinline, not_tail_called)) void
os_log_with_args(os_log_t oslog, os_log_type_t type, const char *fmt,
    va_list args, void *addr)
{
	uint64_t ts = firehose_tracepoint_time(firehose_activity_flags_default);

	// if no address passed, look it up
	if (addr == NULL) {
		addr = __builtin_return_address(0);
	}

	_os_log_with_args_internal(oslog, type, fmt, args, ts, addr, NULL, FALSE, FALSE);
}

bool
os_log_coprocessor(void *buff, uint64_t buff_len, os_log_type_t type,
    const char *uuid, uint64_t timestamp, uint32_t offset, bool stream_log)
{
	counter_inc(&oslog_p_coprocessor_total_msgcount);

	if (os_log_turned_off() || !os_log_safe()) {
		counter_inc(&oslog_p_coprocessor_dropped_msgcount);
		return false;
	}

	if (buff_len + 16 + sizeof(uint32_t) > OS_LOG_BUFFER_MAX_SIZE) {
		counter_inc(&oslog_p_coprocessor_dropped_msgcount);
		return false;
	}

	__attribute__((uninitialized))
	uint8_t pubdata[OS_LOG_BUFFER_MAX_SIZE];
	size_t wr_pos = 0;

	memcpy(pubdata, &offset, sizeof(uint32_t));
	wr_pos += sizeof(uint32_t);
	memcpy(pubdata + wr_pos, uuid, 16);
	wr_pos += 16;

	memcpy(pubdata + wr_pos, buff, buff_len);
	wr_pos += buff_len;

	/*
	 * Unlike KEXTs, where PC is used to find UUID, in coprocessor logs the UUID
	 * is passed as part of the tracepoint.
	 */
	firehose_tracepoint_namespace_t ns = firehose_tracepoint_namespace_log;
	firehose_tracepoint_flags_t flags = _firehose_tracepoint_flags_pc_style_uuid_relative;
	firehose_tracepoint_id_u trace_id = {
		.ftid_value = FIREHOSE_TRACE_ID_MAKE(ns, type, flags, offset)
	};

	log_payload_s log;
	log_payload_init(&log, firehose_stream(type), trace_id, timestamp, wr_pos, wr_pos);

	if (!log_queue_log(&log, pubdata, stream_log)) {
		counter_inc(&oslog_p_coprocessor_dropped_msgcount);
		return false;
	}

	return true;
}

static inline firehose_tracepoint_t
firehose_trace_start(const log_payload_s *lp, uint8_t **ft_priv_data)
{
	uint16_t priv_data_size = (uint16_t)log_payload_priv_data_size(lp);
	uint16_t pub_data_size = (uint16_t)lp->lp_pub_data_size;

	if (priv_data_size > 0) {
		pub_data_size += sizeof(struct firehose_buffer_range_s);
	}

	assert3u(offsetof(struct firehose_tracepoint_s, ft_data) +
	    pub_data_size + priv_data_size, <=, sizeof(((firehose_chunk_t)0)->fc_data));

	firehose_tracepoint_t ft = __firehose_buffer_tracepoint_reserve(lp->lp_timestamp,
	    lp->lp_stream, pub_data_size, priv_data_size, ft_priv_data);

	if (fastpath(ft)) {
		oslog_boot_done = true;
		return ft;
	}

	if (fastpath(oslog_boot_done)) {
		return 0;
	}

	/*
	 * Early boot logging when kernel logging is up and running but logd is
	 * not yet ready. Only the persist firehose stream is available.
	 */

	long offset = firehose_chunk_tracepoint_try_reserve(&firehose_boot_chunk,
	    lp->lp_timestamp, firehose_stream_persist, 0, pub_data_size,
	    priv_data_size, ft_priv_data);
	if (offset <= 0) {
		counter_inc(&oslog_p_boot_dropped_msgcount);
		return 0;
	}

	return firehose_chunk_tracepoint_begin(&firehose_boot_chunk,
	           lp->lp_timestamp, pub_data_size, thread_tid(current_thread()),
	           offset);
}

static inline void
firehose_trace_finish(firehose_tracepoint_t ft, firehose_tracepoint_id_u ftid)
{
	if (__probable(oslog_boot_done)) {
		__firehose_buffer_tracepoint_flush(ft, ftid);
	} else {
		firehose_chunk_tracepoint_end(&firehose_boot_chunk, ft, ftid);
	}
}

static inline void
firehose_trace_save_payload(const log_payload_s *lp, const uint8_t *lp_data,
    firehose_tracepoint_t ft, uint8_t *ft_priv_data)
{
	const size_t priv_data_size = log_payload_priv_data_size(lp);
	uint8_t *ft_data = ft->ft_data;

	if (priv_data_size > 0) {
		assert(FIREHOSE_TRACE_ID_HAS_FLAG(lp->lp_ftid, log, has_private_data));
		memcpy(ft_priv_data, log_payload_priv_data(lp, lp_data), priv_data_size);

		firehose_chunk_t fc = firehose_chunk_for_address(ft);
		struct firehose_buffer_range_s range = {
			.fbr_offset = (uint16_t)(ft_priv_data - fc->fc_start),
			.fbr_length = (uint16_t)priv_data_size
		};
		memcpy(ft_data, &range, sizeof(range));
		ft_data += sizeof(range);
	}
	memcpy(ft_data, lp_data, lp->lp_pub_data_size);
}

static inline void
log_stats_update_saved(firehose_stream_t stream)
{
	if (__improbable(!oslog_boot_done)) {
		stream = firehose_stream_persist;
	}

	switch (stream) {
	case firehose_stream_metadata:
		counter_inc(&oslog_p_metadata_saved_msgcount);
		break;
	case firehose_stream_persist:
	case firehose_stream_memory:
		counter_inc(&oslog_p_saved_msgcount);
		break;
	case firehose_stream_signpost:
		counter_inc(&oslog_p_signpost_saved_msgcount);
		break;
	default:
		panic("Unexpected firehose stream type %u", stream);
	}
}

static inline firehose_tracepoint_id_t
firehose_trace(const log_payload_s *lp, const uint8_t *lp_data)
{
	uint8_t *ft_priv_data = NULL;
	firehose_tracepoint_t ft = firehose_trace_start(lp, &ft_priv_data);

	if (fastpath(ft)) {
		firehose_trace_save_payload(lp, lp_data, ft, ft_priv_data);
		firehose_trace_finish(ft, lp->lp_ftid);
		log_stats_update_saved(lp->lp_stream);
		return lp->lp_ftid.ftid_value;
	}
	return 0;
}

static firehose_tracepoint_code_t
coproc_reg_type_to_firehost_code(os_log_coproc_reg_t reg_type)
{
	switch (reg_type) {
	case os_log_coproc_register_memory:
		return firehose_tracepoint_code_load_memory;
	case os_log_coproc_register_harvest_fs_ftab:
		return firehose_tracepoint_code_load_filesystem_ftab;
	default:
		return firehose_tracepoint_code_invalid;
	}
}

void
os_log_coprocessor_register_with_type(const char *uuid, const char *file_path, os_log_coproc_reg_t reg_type)
{
	size_t path_size = strlen(file_path) + 1;
	size_t uuid_info_len = sizeof(struct firehose_trace_uuid_info_s) + path_size;

	if (os_log_disabled() || path_size > PATH_MAX) {
		return;
	}

	__attribute__((uninitialized))
	union {
		struct firehose_trace_uuid_info_s uuid_info;
		char path[PATH_MAX + sizeof(struct firehose_trace_uuid_info_s)];
	} buf;

	// write metadata to uuid_info
	memcpy(buf.uuid_info.ftui_uuid, uuid, sizeof(uuid_t));
	buf.uuid_info.ftui_size    = 1;
	buf.uuid_info.ftui_address = 1;

	uint64_t stamp = firehose_tracepoint_time(firehose_activity_flags_default);

	// create tracepoint id
	firehose_tracepoint_id_u trace_id;
	trace_id.ftid_value = FIREHOSE_TRACE_ID_MAKE(firehose_tracepoint_namespace_metadata,
	    _firehose_tracepoint_type_metadata_coprocessor, (firehose_tracepoint_flags_t)0,
	    coproc_reg_type_to_firehost_code(reg_type));

	// write path to buffer
	memcpy(buf.uuid_info.ftui_path, file_path, path_size);

	// send metadata tracepoint to firehose for coprocessor registration in logd
	os_log_encoded_metadata(trace_id, stamp, (void *)&buf, uuid_info_len);
}

bool
log_payload_send(log_payload_t lp, const void *lp_data, bool use_stream)
{
	if (use_stream) {
		bool is_metadata = (lp->lp_stream == firehose_stream_metadata);
		oslog_stream(is_metadata, lp->lp_ftid, lp->lp_timestamp, lp_data, lp->lp_data_size);
	}
	return firehose_trace(lp, lp_data) != 0;
}

void
__firehose_buffer_push_to_logd(firehose_buffer_t fb __unused, bool for_io __unused)
{
	oslogwakeup();
	return;
}

void
__firehose_allocate(vm_offset_t *addr, vm_size_t size __unused)
{
	firehose_chunk_t kernel_buffer = (firehose_chunk_t)kernel_firehose_addr;

	if (kernel_firehose_addr) {
		*addr = kernel_firehose_addr;
	} else {
		*addr = 0;
		return;
	}
	// Now that we are done adding logs to this chunk, set the number of writers to 0
	// Without this, logd won't flush when the page is full
	firehose_boot_chunk.fc_pos.fcp_refcnt = 0;
	memcpy(&kernel_buffer[FIREHOSE_BUFFER_KERNEL_CHUNK_COUNT - 1], (const void *)&firehose_boot_chunk, FIREHOSE_CHUNK_SIZE);
	return;
}
// There isnt a lock held in this case.
void
__firehose_critical_region_enter(void)
{
	disable_preemption();
	return;
}

void
__firehose_critical_region_leave(void)
{
	enable_preemption();
	return;
}

#ifdef CONFIG_XNUPOST

static_assert(&_os_log_default == OS_LOG_DEFAULT,
    "OS_LOG_DEFAULT is an alias to _os_log_default");
static_assert(OS_LOG_DISABLED == NULL,
    "OS_LOG_DISABLED handle is defined as NULL");

#include <dev/random/randomdev.h>
#include <tests/xnupost.h>

typedef struct {
	size_t total;
	size_t saved;
	size_t dropped;
	size_t truncated;
	size_t errors;
	size_t errors_kc;
	size_t errors_fmt;
	size_t errors_max_args;
} log_stats_t;

#define TESTBUFLEN              256
#define TESTOSLOGFMT(fn_name)   "%u^%llu/%llu^kernel^0^test^" fn_name
#define TESTOSLOGPFX            "TESTLOG:%u#"
#define TESTOSLOG(fn_name)      TESTOSLOGPFX TESTOSLOGFMT(fn_name "#")

#define LOG_STAT_CMP(cmp, b, a, e, stat, msg, test) \
    { \
	size_t n##stat = (a)->stat - (b)->stat; \
	size_t n##expected = (e)->stat; \
	cmp(n##stat, n##expected, (msg), (test), n##expected); \
    }
#define LOG_STAT_EQ(b, a, e, stat, msg, test) \
    LOG_STAT_CMP(T_EXPECT_EQ_UINT, b, a, e, stat, msg, test)
#define LOG_STAT_GE(b, a, e, stat, msg, test) \
    LOG_STAT_CMP(T_EXPECT_GE_UINT, b, a, e, stat, msg, test)

#define GENOSLOGHELPER(fname, ident, callout_f) \
    static void \
    fname(uint32_t uniqid, uint64_t count, log_stats_t *before, log_stats_t *after) \
    { \
	uint32_t checksum = 0; \
	char pattern[TESTBUFLEN]; \
	T_LOG("Testing " ident "() with %d logs", count); \
	log_stats_get(before); \
	for (uint64_t i = 0; i < count; i++) { \
	    (void) save_pattern(pattern, &checksum, TESTOSLOGFMT(ident), uniqid, i + 1, count); \
	    callout_f(OS_LOG_DEFAULT, TESTOSLOG(ident), checksum, uniqid, i + 1, count); \
	} \
	log_stats_get(after); \
    }

extern size_t find_pattern_in_buffer(const char *, size_t, size_t);

void test_oslog_handleOSLogCtl(int32_t *, int32_t *, int32_t);
kern_return_t test_printf(void);
kern_return_t test_os_log(void);
kern_return_t test_os_log_handles(void);
kern_return_t test_os_log_parallel(void);

SCALABLE_COUNTER_DECLARE(oslog_p_fmt_invalid_msgcount);
SCALABLE_COUNTER_DECLARE(oslog_p_fmt_max_args_msgcount);
SCALABLE_COUNTER_DECLARE(oslog_p_truncated_msgcount);
SCALABLE_COUNTER_DECLARE(log_queue_cnt_received);

static void
log_stats_get(log_stats_t *stats)
{
	if (!stats) {
		return;
	}
	stats->total = counter_load(&oslog_p_total_msgcount);
	stats->saved = counter_load(&log_queue_cnt_received);
	stats->dropped = counter_load(&oslog_p_dropped_msgcount);
	stats->truncated = counter_load(&oslog_p_truncated_msgcount);
	stats->errors = counter_load(&oslog_p_error_count);
	stats->errors_kc = counter_load(&oslog_p_unresolved_kc_msgcount);
	stats->errors_fmt = counter_load(&oslog_p_fmt_invalid_msgcount);
	stats->errors_max_args = counter_load(&oslog_p_fmt_max_args_msgcount);
}

static void
log_stats_diff(const log_stats_t *before, const log_stats_t *after, log_stats_t *diff)
{
	log_stats_t d = {};

	if (before) {
		d = *before;
	}
	if (after) {
		d.total = after->total - d.total;
		d.saved = after->saved - d.saved;
		d.dropped = after->dropped - d.dropped;
		d.truncated = after->truncated - d.truncated;
		d.errors = after->errors - d.errors;
		d.errors_kc = after->errors_kc - d.errors_kc;
		d.errors_fmt = after->errors_fmt - d.errors_fmt;
		d.errors_max_args = after->errors_max_args - d.errors_max_args;
	}
	*diff = d;
}

static void
log_stats_check_errors(const log_stats_t *before, const log_stats_t *after, const log_stats_t *expected,
    const char *test)
{
	LOG_STAT_EQ(before, after, expected, errors, "%s: Expected %lu encoding errors", test);
	LOG_STAT_EQ(before, after, expected, errors_kc, "%s: Expected %lu DSO errors", test);
	LOG_STAT_EQ(before, after, expected, errors_fmt, "%s: Expected %lu bad format errors", test);
	LOG_STAT_EQ(before, after, expected, errors_max_args, "%s: Expected %lu max arguments errors", test);
}

static void
log_stats_check(const log_stats_t *before, const log_stats_t *after, const log_stats_t *expected,
    const char *test)
{
	/*
	 * The comparison is >= (_GE) for total and saved counters because tests
	 * are running while the system is up and potentially logging. Test and
	 * regular logs interfere rather rarely but can make the test flaky
	 * which is not desired.
	 */
	LOG_STAT_GE(before, after, expected, total, "%s: Expected %lu logs total", test);
	LOG_STAT_GE(before, after, expected, saved, "%s: Expected %lu saved logs", test);
	LOG_STAT_EQ(before, after, expected, dropped, "%s: Expected %lu logs dropped", test);
	log_stats_check_errors(before, after, expected, test);
}

static void
log_stats_report(const log_stats_t *before, const log_stats_t *after, const char *test)
{
	log_stats_t diff = {};
	log_stats_diff(before, after, &diff);

	T_LOG("\n%s: Logging stats:\n\ttotal: %u\n\tsaved: %u\n\tdropped: %u\n"
	    "\terrors: %u\n\terrors_kc: %u\n\terrors_fmt: %u\n\terrors_max_args: %u",
	    test, diff.total, diff.saved, diff.dropped,
	    diff.errors, diff.errors_kc, diff.errors_fmt, diff.errors_max_args);
}

static int
save_pattern(char buf[static TESTBUFLEN], uint32_t *crc, const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
	int n = vscnprintf(buf, TESTBUFLEN, fmt, va);
#pragma clang diagnostic pop
	va_end(va);
	if (crc) {
		*crc = crc32(0, buf, n);
	}
	return n;
}

/*
 * Actual GENOSLOGHELPER() 2nd argument values below are expected by libtrace
 * test_kern_oslog test suite and shall not be changed without updating given
 * test suite.
 */
GENOSLOGHELPER(test_oslog_info, "oslog_info_helper", os_log_info);
GENOSLOGHELPER(test_oslog_fault, "oslog_fault_helper", os_log_fault);
GENOSLOGHELPER(test_oslog_debug, "oslog_debug_helper", os_log_debug);
GENOSLOGHELPER(test_oslog_error, "oslog_error_helper", os_log_error);
GENOSLOGHELPER(test_oslog_default, "oslog_default_helper", os_log);

kern_return_t
test_printf(void)
{
	const uint32_t uniqid = RandomULong();
	T_ASSERT_NE_UINT(0, uniqid, "Random number should not be zero");

	uint64_t stamp = mach_absolute_time();
	T_ASSERT_NE_ULLONG(0, stamp, "Absolute time should not be zero");

	T_LOG("Validating with atm_diagnostic_config=%#x uniqid=%u stamp=%llu",
	    atm_get_diagnostic_config(), uniqid, stamp);

	__attribute__((uninitialized))
	char pattern[TESTBUFLEN];
	log_stats_t before = {}, after = {};
	uint32_t checksum = 0;

	log_stats_get(&before);

	(void) save_pattern(pattern, &checksum, TESTOSLOGFMT("printf_only"), uniqid, 1LL, 2LL);
	printf(TESTOSLOG("printf_only") "mat%llu\n", checksum, uniqid, 1LL, 2LL, stamp);

	(void) save_pattern(pattern, &checksum, TESTOSLOGFMT("printf_only"), uniqid, 2LL, 2LL);
	printf(TESTOSLOG("printf_only") "mat%llu\n", checksum, uniqid, 2LL, 2LL, stamp);

	size_t saved = save_pattern(pattern, NULL, "kernel^0^test^printf_only#mat%llu", stamp);
	size_t match_count = find_pattern_in_buffer(pattern, saved, 2LL);
	T_EXPECT_EQ_ULONG(match_count, 2LL, "printf() logs to msgbuf");

	log_stats_get(&after);

	if (!os_log_turned_off()) {
		// printf() should log to OSLog with OSLog enabled.
		log_stats_t expected = { .total = 2, .saved = 2 };
		log_stats_check(&before, &after, &expected, "printf() logs to oslog");
	}

	log_stats_report(&before, &after, __FUNCTION__);

	return KERN_SUCCESS;
}

static void
verify_os_log(struct os_log_s *h, char *sub, char *cat)
{
	const size_t sub_len = os_log_subsystem_name_size(sub);
	const size_t cat_len = os_log_subsystem_name_size(cat);

	struct os_log_subsystem_s *s = &h->ol_subsystem;

	T_ASSERT_EQ_STR(s->ols_name, sub, "Log subsystem name is %s", sub);
	T_ASSERT_EQ_ULONG(s->ols_sub_size, sub_len, "Log subsystem size is %lu", sub_len);
	T_ASSERT_EQ_ULONG(strlen(s->ols_name), sub_len - 1, "Log subsystem length is %lu", sub_len - 1);

	T_ASSERT_EQ_STR(&s->ols_name[sub_len], cat, "Log category name is %s", cat);
	T_ASSERT_EQ_ULONG(s->ols_cat_size, cat_len, "Log category length is %lu", cat_len);
	T_ASSERT_EQ_ULONG(strlen(&s->ols_name[sub_len]), cat_len - 1, "Log category size is %lu", cat_len - 1);
}

static os_log_t
create_verified_os_log(char *sub, char *cat)
{
	os_log_t h = os_log_create(sub, cat);
	verify_os_log(h, sub, cat);
	return h;
}

kern_return_t
test_os_log_handles(void)
{
	os_log_t h1 = create_verified_os_log("xnu_post_subsystem1", "xnu_post_category1");
	if (os_log_disabled()) {
		T_ASSERT_EQ_PTR(h1, OS_LOG_DISABLED, "Disabled logging uses OS_LOG_DISABLED");
		return KERN_SUCCESS;
	}
	T_ASSERT_NE_PTR(h1, OS_LOG_DEFAULT, "Custom log handle is not OS_LOG_DEFAULT");

	os_log_t h2 = create_verified_os_log("xnu_post_subsystem1", "xnu_post_category1");
	T_ASSERT_EQ_PTR(h1, h2, "os_log_create() finds an existing log handle in the cache");

	h2 = create_verified_os_log("xnu_post_subsystem1", "xnu_post_category2");
	T_ASSERT_NE_PTR(h1, h2, "Subsystem is not enough to identify a log handle");

	h2 = create_verified_os_log("xnu_post_subsystem2", "xnu_post_category1");
	T_ASSERT_NE_PTR(h1, h2, "Category is not enough to identify a log handle");

	h2 = create_verified_os_log("xnu_post_subsystem3", "xnu_post_category3");
	T_ASSERT_NE_PTR(h1, h2, "Different subsystem and category yield a different handle");

	h1 = h2;
	h2 = create_verified_os_log("xnu_post", "_subsystem3xnu_post_category3");
	T_ASSERT_NE_PTR(h1, h2, "Subsystem and category cannot be mixed");

	const size_t name_size = sizeof(h1->ol_subsystem.ols_name) / 2;

	char super_long_sub[name_size] = {
		[0 ... sizeof(super_long_sub) - 1] = 'X'
	};

	char super_long_cat[name_size] = {
		[0 ... sizeof(super_long_sub) - 1] = 'Y'
	};

	h1 = os_log_create(super_long_sub, super_long_cat);
	T_ASSERT_NE_PTR(h1, OS_LOG_DEFAULT, "Custom log handle is not OS_LOG_DEFAULT");

	super_long_sub[name_size - 1] = '\0';
	super_long_cat[name_size - 1] = '\0';

	verify_os_log(h1, super_long_sub, super_long_cat);

	return KERN_SUCCESS;
}

kern_return_t
test_os_log(void)
{
	const uint32_t uniqid = RandomULong();
	T_ASSERT_NE_UINT(0, uniqid, "Random number should not be zero");

	uint64_t stamp = mach_absolute_time();
	T_ASSERT_NE_ULLONG(0, stamp, "Absolute time should not be zero");

	T_LOG("Validating with atm_diagnostic_config=%#x uniqid=%u stamp=%llu",
	    atm_get_diagnostic_config(), uniqid, stamp);

	os_log_t log_handle = os_log_create("com.apple.xnu.test.t1", "kpost");
	T_ASSERT_NE_PTR(OS_LOG_DEFAULT, log_handle, "Log handle is not OS_LOG_DEFAULT");

	const bool enabled = !os_log_turned_off();
	T_ASSERT_EQ_INT(enabled, os_log_info_enabled(log_handle), "Info log level is enabled");
	T_ASSERT_EQ_INT(enabled, os_log_debug_enabled(log_handle), "Debug log level is enabled");

	__attribute__((uninitialized))
	char pattern[TESTBUFLEN];
	uint32_t checksum = 0;

	(void) save_pattern(pattern, &checksum, TESTOSLOGFMT("oslog_info"), uniqid, 1LL, 1LL);
	os_log_info(log_handle, TESTOSLOG("oslog_info") "mat%llu", checksum, uniqid, 1LL, 1LL, stamp);
	size_t saved = save_pattern(pattern, NULL, "kernel^0^test^oslog_info#mat%llu", stamp);
	size_t match_count = find_pattern_in_buffer(pattern, saved, 1LL);
	T_EXPECT_EQ_ULONG(match_count, 1LL, "oslog_info() logs to system message buffer");

	const size_t n = 10;

	log_stats_t expected = {
		.total = enabled ? n : 0,
		.saved = enabled ? n : 0
	};

	log_stats_t before = {}, after = {};

	test_oslog_info(uniqid, n, &before, &after);
	log_stats_check(&before, &after, &expected, "test_oslog_info");

	test_oslog_debug(uniqid, n, &before, &after);
	log_stats_check(&before, &after, &expected, "test_oslog_debug");

	test_oslog_error(uniqid, n, &before, &after);
	log_stats_check(&before, &after, &expected, "test_oslog_error");

	test_oslog_default(uniqid, n, &before, &after);
	log_stats_check(&before, &after, &expected, "test_oslog_default");

	test_oslog_fault(uniqid, n, &before, &after);
	log_stats_check(&before, &after, &expected, "test_oslog_fault");

	log_stats_report(&before, &after, __FUNCTION__);

	return KERN_SUCCESS;
}

static size_t _test_log_loop_count = 0;

static void
_test_log_loop(void *arg __unused, wait_result_t wres __unused)
{
	test_oslog_debug(RandomULong(), 100, NULL, NULL);
	os_atomic_add(&_test_log_loop_count, 100, relaxed);
}

kern_return_t
test_os_log_parallel(void)
{
	if (os_log_turned_off()) {
		T_LOG("Logging disabled, skipping tests.");
		return KERN_SUCCESS;
	}

	thread_t thread[2];
	kern_return_t kr;
	log_stats_t after, before, expected = {};

	log_stats_get(&before);

	kr = kernel_thread_start(_test_log_loop, NULL, &thread[0]);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "kernel_thread_start returned successfully");

	kr = kernel_thread_start(_test_log_loop, NULL, &thread[1]);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "kernel_thread_start returned successfully");

	test_oslog_info(RandomULong(), 100, NULL, NULL);

	/* wait until other thread has also finished */
	while (_test_log_loop_count < 200) {
		delay(1000);
	}

	thread_deallocate(thread[0]);
	thread_deallocate(thread[1]);

	log_stats_get(&after);
	log_stats_check_errors(&before, &after, &expected, __FUNCTION__);
	log_stats_report(&before, &after, __FUNCTION__);

	return KERN_SUCCESS;
}

static kern_return_t
test_stresslog_dropmsg(const uint32_t uniqid)
{
	if (os_log_turned_off()) {
		T_LOG("Logging disabled, skipping tests.");
		return KERN_SUCCESS;
	}

	log_stats_t after, before, expected = {};

	test_oslog_debug(uniqid, 100, &before, &after);
	while ((after.dropped - before.dropped) == 0) {
		test_oslog_debug(uniqid, 100, NULL, &after);
	}

	log_stats_check_errors(&before, &after, &expected, __FUNCTION__);
	log_stats_report(&before, &after, __FUNCTION__);

	return KERN_SUCCESS;
}

void
test_oslog_handleOSLogCtl(int32_t *in, int32_t *out, int32_t len)
{
	if (!in || !out || len != 4) {
		return;
	}
	switch (in[0]) {
	case 1:
	{
		/* send out counters */
		out[1] = counter_load(&oslog_p_total_msgcount);
		out[2] = counter_load(&oslog_p_saved_msgcount);
		out[3] = counter_load(&oslog_p_dropped_msgcount);
		out[0] = KERN_SUCCESS;
		break;
	}
	case 2:
	{
		/* mini stress run */
		out[0] = test_os_log_parallel();
		break;
	}
	case 3:
	{
		/* drop msg tests */
		out[1] = RandomULong();
		out[0] = test_stresslog_dropmsg(out[1]);
		break;
	}
	case 4:
	{
		/* invoke log helpers */
		uint32_t uniqid = in[3];
		int32_t msgcount = in[2];
		if (uniqid == 0 || msgcount == 0) {
			out[0] = KERN_INVALID_VALUE;
			return;
		}

		switch (in[1]) {
		case OS_LOG_TYPE_INFO:
			test_oslog_info(uniqid, msgcount, NULL, NULL);
			break;
		case OS_LOG_TYPE_DEBUG:
			test_oslog_debug(uniqid, msgcount, NULL, NULL);
			break;
		case OS_LOG_TYPE_ERROR:
			test_oslog_error(uniqid, msgcount, NULL, NULL);
			break;
		case OS_LOG_TYPE_FAULT:
			test_oslog_fault(uniqid, msgcount, NULL, NULL);
			break;
		case OS_LOG_TYPE_DEFAULT:
		default:
			test_oslog_default(uniqid, msgcount, NULL, NULL);
			break;
		}
		out[0] = KERN_SUCCESS;
		break;
		/* end of case 4 */
	}
	default:
	{
		out[0] = KERN_INVALID_VALUE;
		break;
	}
	}
	return;
}

#endif /* CONFIG_XNUPOST */
