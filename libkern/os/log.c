/* * Copyright (c) 2019 Apple Inc. All rights reserved. */

#include <stddef.h>
#undef offset

#include <kern/cpu_data.h>
#include <os/base.h>
#include <os/object.h>
#include <os/log.h>
#include <stdbool.h>
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
#include <kern/startup.h>
#include <kern/task.h>

#include <firehose/tracepoint_private.h>
#include <firehose/chunk_private.h>
#include <os/firehose_buffer_private.h>
#include <os/firehose.h>

#include <os/log_private.h>
#include "trace_internal.h"

#include "log_encode.h"
#include "log_internal.h"
#include "log_mem.h"
#include "log_queue.h"

#define OS_LOGMEM_BUF_ORDER 14
#define OS_LOGMEM_MIN_LOG_ORDER 9
#define OS_LOGMEM_MAX_LOG_ORDER (OS_LOG_MAX_SIZE_ORDER)

struct os_log_s {
	int a;
};

struct os_log_s _os_log_default;
struct os_log_s _os_log_replay;
struct logmem_s os_log_mem;

extern vm_offset_t kernel_firehose_addr;
extern firehose_chunk_t firehose_boot_chunk;

extern bool bsd_log_lock(bool);
extern void bsd_log_unlock(void);
extern void logwakeup(struct msgbuf *);

extern void oslog_stream(bool, firehose_tracepoint_id_u, uint64_t, const void *, size_t);
extern void *OSKextKextForAddress(const void *);

/* Counters for persistence mode */
SCALABLE_COUNTER_DEFINE(oslog_p_total_msgcount);
SCALABLE_COUNTER_DEFINE(oslog_p_metadata_saved_msgcount);
SCALABLE_COUNTER_DEFINE(oslog_p_metadata_dropped_msgcount);
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

static bool oslog_boot_done = false;
static bool oslog_disabled = false;

#ifdef XNU_KERNEL_PRIVATE
bool startup_serial_logging_active = true;
uint64_t startup_serial_num_procs = 300;
#endif /* XNU_KERNEL_PRIVATE */

bool os_log_disabled(void);

__osloglike(3, 0)
static void
_os_log_with_args_internal(os_log_t, os_log_type_t, const char *, va_list,
    uint64_t, void *, void *, bool, bool);

__osloglike(1, 0)
static void
_os_log_to_msgbuf_internal(const char *, va_list, uint64_t, bool, bool, bool);

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

os_log_t
os_log_create(const char *subsystem __unused, const char *category __unused)
{
	return &_os_log_default;
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
	 * Only dextis are supposed to use this log path. Verified in log_data()
	 * but worth of another check here in case this function gets called
	 * directly.
	 */
	if (!task_is_driver(self_task)) {
		return EPERM;
	}

	uint64_t loadTag = get_task_loadTag(self_task);
	if (loadTag != 0) {
		driverKitLog = TRUE;
		addr = (void*) loadTag;
	}

	va_start(args, fmt);
	_os_log_with_args_internal(log, type, fmt, args, ts, addr, dso, driverKitLog, true);
	va_end(args);

	return 0;
}

#pragma mark - shim functions

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
	switch (flags) {
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

static void
log_payload_init(log_payload_t lp, firehose_stream_t stream, firehose_tracepoint_id_u ftid,
    uint64_t timestamp, size_t data_size)
{
	lp->lp_stream = stream;
	lp->lp_ftid = ftid;
	lp->lp_timestamp = timestamp;
	lp->lp_data_size = (uint16_t)data_size;
}

static void
_os_log_to_log_internal(os_log_type_t type, const char *fmt, va_list args,
    uint64_t ts, void *addr, void *dso, bool driverKit)
{
	counter_inc(&oslog_p_total_msgcount);

	dso = resolve_dso(fmt, dso, addr, driverKit);
	if (__improbable(!dso)) {
		counter_inc(&oslog_p_unresolved_kc_msgcount);
		return;
	}

	firehose_tracepoint_flags_t flags = firehose_ftid_flags(dso, driverKit);

	size_t loc_sz = 0;
	uintptr_t loc = resolve_location(flags, (uintptr_t)dso, (uintptr_t)addr,
	    driverKit, &loc_sz);

	firehose_tracepoint_id_u ftid;
	ftid.ftid_value = firehose_ftid(type, fmt, flags, dso, addr, driverKit);

	__attribute__((uninitialized, aligned(8)))
	uint8_t buffer[OS_LOG_BUFFER_MAX_SIZE];
	struct os_log_context_s ctx;

	os_log_context_init(&ctx, &os_log_mem, buffer, sizeof(buffer));

	if (!os_log_context_encode(&ctx, fmt, args, loc, loc_sz)) {
		counter_inc(&oslog_p_error_count);
		os_log_context_free(&ctx);
		return;
	}

	log_payload_s log;
	log_payload_init(&log, firehose_stream(type), ftid, ts, ctx.ctx_content_sz);

	if (!log_queue_log(&log, ctx.ctx_buffer, true)) {
		counter_inc(&oslog_p_dropped_msgcount);
	}

	os_log_context_free(&ctx);
}

static void
_os_log_with_args_internal(os_log_t oslog, os_log_type_t type, const char *fmt,
    va_list args, uint64_t ts, void *addr, void *dso, bool driverKit, bool addcr)
{
	if (fmt[0] == '\0') {
		return;
	}

	/* early boot can log to dmesg for later replay (27307943) */
	bool safe = os_log_safe();
	bool logging = !os_log_turned_off();

	if (oslog != &_os_log_replay) {
		_os_log_to_msgbuf_internal(fmt, args, ts, safe, logging, addcr);
	}

	if (safe && logging) {
		_os_log_to_log_internal(type, fmt, args, ts, addr, dso, driverKit);
	}
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
	logwakeup(msgbufp);
	counter_inc(&oslog_msgbuf_msgcount);
}

bool
os_log_coprocessor(void *buff, uint64_t buff_len, os_log_type_t type,
    const char *uuid, uint64_t timestamp, uint32_t offset, bool stream_log)
{
	if (os_log_turned_off()) {
		return false;
	}

	if (!os_log_safe()) {
		counter_inc(&oslog_p_coprocessor_dropped_msgcount);
		return false;
	}

	if (buff_len + 16 + sizeof(uint32_t) > OS_LOG_BUFFER_MAX_SIZE) {
		counter_inc(&oslog_p_coprocessor_dropped_msgcount);
		return false;
	}

	firehose_stream_t stream = firehose_stream(type);
	// unlike kext, where pc is used to find uuid, in coprocessor logs the uuid is passed as part of the tracepoint
	firehose_tracepoint_flags_t flags = _firehose_tracepoint_flags_pc_style_uuid_relative;

	__attribute__((uninitialized))
	uint8_t pubdata[OS_LOG_BUFFER_MAX_SIZE];
	size_t wr_pos = 0;

	memcpy(pubdata, &offset, sizeof(uint32_t));
	wr_pos += sizeof(uint32_t);
	memcpy(pubdata + wr_pos, uuid, 16);
	wr_pos += 16;

	memcpy(pubdata + wr_pos, buff, buff_len);

	// create firehose trace id
	firehose_tracepoint_id_u trace_id;
	trace_id.ftid_value = FIREHOSE_TRACE_ID_MAKE(firehose_tracepoint_namespace_log,
	    type, flags, offset);

	counter_inc(&oslog_p_coprocessor_total_msgcount);

	log_payload_s log;
	log_payload_init(&log, stream, trace_id, timestamp, buff_len + wr_pos);

	if (!log_queue_log(&log, pubdata, stream_log)) {
		counter_inc(&oslog_p_coprocessor_dropped_msgcount);
		return false;
	}

	return true;
}

static firehose_tracepoint_id_t
_firehose_trace_early_boot(firehose_tracepoint_id_u ftid, uint64_t stamp, const void *pubdata, size_t publen)
{
	firehose_chunk_t fbc = firehose_boot_chunk;

	//only stream available during boot is persist
	long offset = firehose_chunk_tracepoint_try_reserve(fbc, stamp,
	    firehose_stream_persist, 0, (uint16_t)publen, 0, NULL);
	if (offset <= 0) {
		counter_inc(&oslog_p_boot_dropped_msgcount);
		return 0;
	}

	firehose_tracepoint_t ft = firehose_chunk_tracepoint_begin(fbc, stamp, (uint16_t)publen,
	    thread_tid(current_thread()), offset);
	memcpy(ft->ft_data, pubdata, publen);
	firehose_chunk_tracepoint_end(fbc, ft, ftid);

	counter_inc(&oslog_p_saved_msgcount);

	return ftid.ftid_value;
}

static inline firehose_tracepoint_id_t
_firehose_trace(firehose_stream_t stream, firehose_tracepoint_id_u ftid,
    uint64_t stamp, const void *data, size_t datalen)
{
	const uint16_t __assert_only ft_size = offsetof(struct firehose_tracepoint_s, ft_data);
	const size_t __assert_only _firehose_chunk_payload_size = sizeof(((struct firehose_chunk_s *)0)->fc_data);
	assert((ft_size + datalen) <= _firehose_chunk_payload_size);

	firehose_tracepoint_t ft = __firehose_buffer_tracepoint_reserve(stamp, stream, (uint16_t)datalen, 0, NULL);

	if (fastpath(ft)) {
		oslog_boot_done = true;

		memcpy(ft->ft_data, data, datalen);
		__firehose_buffer_tracepoint_flush(ft, ftid);

		if (stream == firehose_stream_metadata) {
			counter_inc(&oslog_p_metadata_saved_msgcount);
		} else {
			counter_inc(&oslog_p_saved_msgcount);
		}

		return ftid.ftid_value;
	}

	if (!oslog_boot_done) {
		return _firehose_trace_early_boot(ftid, stamp, data, datalen);
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
	trace_id.ftid_value = FIREHOSE_TRACE_ID_MAKE(firehose_tracepoint_namespace_metadata, _firehose_tracepoint_type_metadata_coprocessor,
	    (firehose_tracepoint_flags_t)0, coproc_reg_type_to_firehost_code(reg_type));

	// write path to buffer
	memcpy(buf.uuid_info.ftui_path, file_path, path_size);

	// send metadata tracepoint to firehose for coprocessor registration in logd
	firehose_trace_metadata(firehose_stream_metadata, trace_id, stamp, (void *)&buf, uuid_info_len);
	return;
}

#ifdef KERNEL
void
firehose_trace_metadata(firehose_stream_t stream, firehose_tracepoint_id_u ftid,
    uint64_t stamp, const void *pubdata, size_t publen)
{
	if (os_log_disabled()) {
		return;
	}

	if (!os_log_safe()) {
		counter_inc(&oslog_p_metadata_dropped_msgcount);
		return;
	}

	log_payload_s log;
	log_payload_init(&log, stream, ftid, stamp, publen);

	if (!log_queue_log(&log, pubdata, true)) {
		counter_inc(&oslog_p_metadata_dropped_msgcount);
	}
}
#endif

bool
log_payload_send(log_payload_t lp, const void *lp_data, bool use_stream)
{
	if (use_stream) {
		bool is_metadata = (lp->lp_stream == firehose_stream_metadata);
		oslog_stream(is_metadata, lp->lp_ftid, lp->lp_timestamp, lp_data, lp->lp_data_size);
	}

	return _firehose_trace(lp->lp_stream, lp->lp_ftid, lp->lp_timestamp,
	           lp_data, lp->lp_data_size);
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
	firehose_boot_chunk->fc_pos.fcp_refcnt = 0;
	memcpy(&kernel_buffer[FIREHOSE_BUFFER_KERNEL_CHUNK_COUNT - 1], (const void *)firehose_boot_chunk, FIREHOSE_CHUNK_SIZE);
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

#include <tests/xnupost.h>
#define TESTOSLOGFMT(fn_name) "%u^%llu/%llu^kernel^0^test^" fn_name
#define TESTOSLOGPFX "TESTLOG:%u#"
#define TESTOSLOG(fn_name) TESTOSLOGPFX TESTOSLOGFMT(fn_name "#")

extern u_int32_t RandomULong(void);
extern size_t find_pattern_in_buffer(const char *pattern, size_t len, size_t expected_count);
void test_oslog_default_helper(uint32_t uniqid, uint64_t count);
void test_oslog_info_helper(uint32_t uniqid, uint64_t count);
void test_oslog_debug_helper(uint32_t uniqid, uint64_t count);
void test_oslog_error_helper(uint32_t uniqid, uint64_t count);
void test_oslog_fault_helper(uint32_t uniqid, uint64_t count);
void _test_log_loop(void * arg __unused, wait_result_t wres __unused);
void test_oslog_handleOSLogCtl(int32_t * in, int32_t * out, int32_t len);
kern_return_t test_stresslog_dropmsg(uint32_t uniqid);

kern_return_t test_os_log(void);
kern_return_t test_os_log_parallel(void);

#define GENOSLOGHELPER(fname, ident, callout_f)                                                            \
    void fname(uint32_t uniqid, uint64_t count)                                                            \
    {                                                                                                      \
	int32_t datalen = 0;                                                                               \
	uint32_t checksum = 0;                                                                             \
	char databuffer[256];                                                                              \
	T_LOG("Doing os_log of %llu TESTLOG msgs for fn " ident, count);                                   \
	for (uint64_t i = 0; i < count; i++)                                                               \
	{                                                                                                  \
	    datalen = scnprintf(databuffer, sizeof(databuffer), TESTOSLOGFMT(ident), uniqid, i + 1, count); \
	    checksum = crc32(0, databuffer, datalen);                                                      \
	    callout_f(OS_LOG_DEFAULT, TESTOSLOG(ident), checksum, uniqid, i + 1, count);                   \
	/*T_LOG(TESTOSLOG(ident), checksum, uniqid, i + 1, count);*/                                   \
	}                                                                                                  \
    }

GENOSLOGHELPER(test_oslog_info_helper, "oslog_info_helper", os_log_info);
GENOSLOGHELPER(test_oslog_fault_helper, "oslog_fault_helper", os_log_fault);
GENOSLOGHELPER(test_oslog_debug_helper, "oslog_debug_helper", os_log_debug);
GENOSLOGHELPER(test_oslog_error_helper, "oslog_error_helper", os_log_error);
GENOSLOGHELPER(test_oslog_default_helper, "oslog_default_helper", os_log);

kern_return_t
test_os_log()
{
	__attribute__((uninitialized))
	char databuffer[256];
	uint32_t uniqid = RandomULong();
	size_t match_count = 0;
	uint32_t checksum = 0;
	uint32_t total_msg = 0;
	uint32_t saved_msg = 0;
	uint32_t dropped_msg = 0;
	size_t datalen = 0;
	uint64_t a = mach_absolute_time();
	uint64_t seqno = 1;
	uint64_t total_seqno = 2;

	os_log_t log_handle = os_log_create("com.apple.xnu.test.t1", "kpost");

	T_ASSERT_EQ_PTR(&_os_log_default, log_handle, "os_log_create returns valid value.");
	T_ASSERT_EQ_INT(TRUE, os_log_info_enabled(log_handle), "os_log_info is enabled");
	T_ASSERT_EQ_INT(TRUE, os_log_debug_enabled(log_handle), "os_log_debug is enabled");
	T_ASSERT_EQ_PTR(&_os_log_default, OS_LOG_DEFAULT, "ensure OS_LOG_DEFAULT is _os_log_default");

	total_msg = counter_load(&oslog_p_total_msgcount);
	saved_msg = counter_load(&oslog_p_saved_msgcount);
	dropped_msg = counter_load(&oslog_p_dropped_msgcount);
	T_LOG("oslog internal counters total %u , saved %u, dropped %u", total_msg, saved_msg, dropped_msg);

	T_LOG("Validating with uniqid %u u64 %llu", uniqid, a);
	T_ASSERT_NE_UINT(0, uniqid, "random number should not be zero");
	T_ASSERT_NE_ULLONG(0, a, "absolute time should not be zero");

	datalen = scnprintf(databuffer, sizeof(databuffer), TESTOSLOGFMT("printf_only"), uniqid, seqno, total_seqno);
	checksum = crc32(0, databuffer, datalen);
	printf(TESTOSLOG("printf_only") "mat%llu\n", checksum, uniqid, seqno, total_seqno, a);

	seqno += 1;
	datalen = scnprintf(databuffer, sizeof(databuffer), TESTOSLOGFMT("printf_only"), uniqid, seqno, total_seqno);
	checksum = crc32(0, databuffer, datalen);
	printf(TESTOSLOG("printf_only") "mat%llu\n", checksum, uniqid, seqno, total_seqno, a);

	datalen = scnprintf(databuffer, sizeof(databuffer), "kernel^0^test^printf_only#mat%llu", a);
	match_count = find_pattern_in_buffer(databuffer, datalen, total_seqno);
	T_EXPECT_EQ_ULONG(match_count, total_seqno, "verify printf_only goes to systemlog buffer");

	uint32_t logging_config = atm_get_diagnostic_config();
	T_LOG("checking atm_diagnostic_config 0x%X", logging_config);

	if ((logging_config & ATM_TRACE_OFF) || (logging_config & ATM_TRACE_DISABLE)) {
		T_LOG("ATM_TRACE_OFF / ATM_TRACE_DISABLE is set. Would not see oslog messages. skipping the rest of test.");
		return KERN_SUCCESS;
	}

	/* for enabled logging printfs should be saved in oslog as well */
	T_EXPECT_GE_UINT((counter_load(&oslog_p_total_msgcount) - total_msg), 2, "atleast 2 msgs should be seen by oslog system");

	a = mach_absolute_time();
	total_seqno = 1;
	seqno = 1;
	total_msg = counter_load(&oslog_p_total_msgcount);
	saved_msg = counter_load(&oslog_p_saved_msgcount);
	dropped_msg = counter_load(&oslog_p_dropped_msgcount);
	datalen = scnprintf(databuffer, sizeof(databuffer), TESTOSLOGFMT("oslog_info"), uniqid, seqno, total_seqno);
	checksum = crc32(0, databuffer, datalen);
	os_log_info(log_handle, TESTOSLOG("oslog_info") "mat%llu", checksum, uniqid, seqno, total_seqno, a);
	T_EXPECT_GE_UINT((counter_load(&oslog_p_total_msgcount) - total_msg), 1, "total message count in buffer");

	datalen = scnprintf(databuffer, sizeof(databuffer), "kernel^0^test^oslog_info#mat%llu", a);
	match_count = find_pattern_in_buffer(databuffer, datalen, total_seqno);
	T_EXPECT_EQ_ULONG(match_count, total_seqno, "verify oslog_info does not go to systemlog buffer");

	total_msg = counter_load(&oslog_p_total_msgcount);
	test_oslog_info_helper(uniqid, 10);
	T_EXPECT_GE_UINT(counter_load(&oslog_p_total_msgcount) - total_msg, 10, "test_oslog_info_helper: Should have seen 10 msgs");

	total_msg = counter_load(&oslog_p_total_msgcount);
	test_oslog_debug_helper(uniqid, 10);
	T_EXPECT_GE_UINT(counter_load(&oslog_p_total_msgcount) - total_msg, 10, "test_oslog_debug_helper:Should have seen 10 msgs");

	total_msg = counter_load(&oslog_p_total_msgcount);
	test_oslog_error_helper(uniqid, 10);
	T_EXPECT_GE_UINT(counter_load(&oslog_p_total_msgcount) - total_msg, 10, "test_oslog_error_helper:Should have seen 10 msgs");

	total_msg = counter_load(&oslog_p_total_msgcount);
	test_oslog_default_helper(uniqid, 10);
	T_EXPECT_GE_UINT(counter_load(&oslog_p_total_msgcount) - total_msg, 10, "test_oslog_default_helper:Should have seen 10 msgs");

	total_msg = counter_load(&oslog_p_total_msgcount);
	test_oslog_fault_helper(uniqid, 10);
	T_EXPECT_GE_UINT(counter_load(&oslog_p_total_msgcount) - total_msg, 10, "test_oslog_fault_helper:Should have seen 10 msgs");

	T_LOG("oslog internal counters total %u , saved %u, dropped %u", counter_load(&oslog_p_total_msgcount), counter_load(&oslog_p_saved_msgcount),
	    counter_load(&oslog_p_dropped_msgcount));

	return KERN_SUCCESS;
}

static uint32_t _test_log_loop_count = 0;
void
_test_log_loop(void * arg __unused, wait_result_t wres __unused)
{
	uint32_t uniqid = RandomULong();
	test_oslog_debug_helper(uniqid, 100);
	os_atomic_add(&_test_log_loop_count, 100, relaxed);
}

kern_return_t
test_os_log_parallel(void)
{
	thread_t thread[2];
	kern_return_t kr;
	uint32_t uniqid = RandomULong();

	printf("oslog internal counters total %lld , saved %lld, dropped %lld", counter_load(&oslog_p_total_msgcount), counter_load(&oslog_p_saved_msgcount),
	    counter_load(&oslog_p_dropped_msgcount));

	kr = kernel_thread_start(_test_log_loop, NULL, &thread[0]);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "kernel_thread_start returned successfully");

	kr = kernel_thread_start(_test_log_loop, NULL, &thread[1]);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "kernel_thread_start returned successfully");

	test_oslog_info_helper(uniqid, 100);

	/* wait until other thread has also finished */
	while (_test_log_loop_count < 200) {
		delay(1000);
	}

	thread_deallocate(thread[0]);
	thread_deallocate(thread[1]);

	T_LOG("oslog internal counters total %lld , saved %lld, dropped %lld", counter_load(&oslog_p_total_msgcount), counter_load(&oslog_p_saved_msgcount),
	    counter_load(&oslog_p_dropped_msgcount));
	T_PASS("parallel_logging tests is now complete");

	return KERN_SUCCESS;
}

void
test_oslog_handleOSLogCtl(int32_t * in, int32_t * out, int32_t len)
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
		case OS_LOG_TYPE_INFO: test_oslog_info_helper(uniqid, msgcount); break;
		case OS_LOG_TYPE_DEBUG: test_oslog_debug_helper(uniqid, msgcount); break;
		case OS_LOG_TYPE_ERROR: test_oslog_error_helper(uniqid, msgcount); break;
		case OS_LOG_TYPE_FAULT: test_oslog_fault_helper(uniqid, msgcount); break;
		case OS_LOG_TYPE_DEFAULT:
		default: test_oslog_default_helper(uniqid, msgcount); break;
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

kern_return_t
test_stresslog_dropmsg(uint32_t uniqid)
{
	uint32_t total, saved, dropped;
	total = counter_load(&oslog_p_total_msgcount);
	saved = counter_load(&oslog_p_saved_msgcount);
	dropped = counter_load(&oslog_p_dropped_msgcount);
	uniqid = RandomULong();
	test_oslog_debug_helper(uniqid, 100);
	while ((counter_load(&oslog_p_dropped_msgcount) - dropped) == 0) {
		test_oslog_debug_helper(uniqid, 100);
	}
	printf("test_stresslog_dropmsg: logged %lld msgs, saved %lld and caused a drop of %lld msgs. \n", counter_load(&oslog_p_total_msgcount) - total,
	    counter_load(&oslog_p_saved_msgcount) - saved, counter_load(&oslog_p_dropped_msgcount) - dropped);
	return KERN_SUCCESS;
}

#endif
