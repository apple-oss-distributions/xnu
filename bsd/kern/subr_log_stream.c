/*
 * Copyright (c) 2022 Apple Inc. All rights reserved.
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

#include <kern/assert.h>
#include <kern/bits.h>
#include <kern/clock.h>
#include <kern/counter.h>
#include <kern/cpu_data.h>
#include <kern/kalloc.h>
#include <kern/locks.h>
#include <kern/sched_prim.h>
#include <kern/simple_lock.h>
#include <libkern/libkern.h>
#include <machine/atomic.h>
#include <machine/simple_lock.h>
#include <os/log_private.h>
#include <pexpert/pexpert.h>
#include <sys/conf.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/vnode.h>
#include <firehose/chunk_private.h>
#include <firehose/tracepoint_private.h>

#if DEVELOPMENT || DEBUG
#define LOG_STREAM_VERIFY
#endif /* DEVELOPMENT || DEBUG */

#define LOG_MAX_SIZE            (1 << OS_LOG_MAX_SIZE_ORDER)
#define LOG_SIZE_VALID(v)       ((v) > 0 && (v) <= LOG_MAX_SIZE)
#define LOG_BLK_EXP             (6) // stream/cache block size order (64 bytes)
#define LOG_BLK_SIZE            (1 << LOG_BLK_EXP) // block size
#define LOG_BLK_HEADER          (1) // log header block map indicator
#define LOG_BLK_BODY            (0) // log body block map indicator
#define LOG_STREAM_MIN_SIZE     (8 * LOG_MAX_SIZE)
#define LOG_STREAM_MAX_SIZE     (1024 * 1024)
#define LOG_CACHE_MIN_SIZE      (2 * LOG_MAX_SIZE + LOG_BLK_SIZE)
#define LOG_CACHE_MAX_SIZE      (8 * 1024)
#define LOG_CACHE_EMPTY         (SIZE_MAX)
#define ls_atomic(T)            union { T v; _Atomic(T) av; }

__options_decl(log_stream_siopts_t, uint32_t, {
	LOG_STREAM_OPT_NBIO     = 0x01,
	LOG_STREAM_OPT_ASYNC    = 0x02,
	LOG_STREAM_OPT_RDWAIT   = 0x04,
});

typedef struct {
	lck_spin_t          lsi_lock;
	log_stream_siopts_t lsi_opts;
	struct selinfo      lsi_selinfo;
	void                *lsi_channel;
} log_stream_si_t;

typedef union log_stream_ticket {
	struct {
		uint64_t lst_size  : 16;
		uint64_t lst_loc   : 48;
	};
	uint64_t lst_value;
} log_stream_ticket_t;

typedef struct {
	uint64_t                        lsm_ts;
	struct firehose_tracepoint_s    lsm_ft;
} __attribute__((packed)) log_stream_msg_t;

typedef struct {
	bool                ls_enabled;
	bool                ls_snapshot;
	uint8_t             *ls_buf;
	uint8_t             *ls_blk;
	size_t              ls_blk_count;
	_Atomic(size_t)     ls_reserved;
	ls_atomic(size_t)   ls_commited;
	size_t              ls_commited_wraps;
} log_stream_t;

typedef struct {
	log_stream_ticket_t lss_ticket;
	log_stream_t        *lss_stream;
	log_stream_t        lss_snapshot;
} log_stream_session_t;

typedef struct {
	uint8_t         *lc_buf;
	uint8_t         *lc_blk;
	size_t          lc_blk_count;
	size_t          lc_blk_pos;
	log_stream_t    *lc_stream;
	size_t          lc_stream_pos;
} log_cache_t;

TUNABLE(size_t, log_stream_size, "oslog_stream_size", LOG_STREAM_MIN_SIZE);
TUNABLE(size_t, log_stream_cache_size, "oslog_stream_csize", LOG_CACHE_MIN_SIZE);
#ifdef LOG_STREAM_VERIFY
TUNABLE(bool, log_stream_verify, "-oslog_stream_verify", false);
#endif /* LOG_STREAM_VERIFY */

LCK_GRP_DECLARE(log_stream_lock_grp, "oslog_stream");
LCK_MTX_DECLARE(log_stream_lock, &log_stream_lock_grp);

#define log_stream_lock()       lck_mtx_lock(&log_stream_lock)
#define log_stream_unlock()     lck_mtx_unlock(&log_stream_lock)
#define log_stream_si_lock(s)   lck_spin_lock(&(s)->lsi_lock)
#define log_stream_si_unlock(s) lck_spin_unlock(&(s)->lsi_lock)

SCALABLE_COUNTER_DEFINE(oslog_s_total_msgcount);
SCALABLE_COUNTER_DEFINE(oslog_s_metadata_msgcount);
SCALABLE_COUNTER_DEFINE(oslog_s_streamed_msgcount);
SCALABLE_COUNTER_DEFINE(oslog_s_dropped_msgcount);
SCALABLE_COUNTER_DEFINE(oslog_s_error_count);

extern d_open_t     oslog_streamopen;
extern d_close_t    oslog_streamclose;
extern d_read_t     oslog_streamread;
extern d_ioctl_t    oslog_streamioctl;
extern d_select_t   oslog_streamselect;
extern bool         os_log_disabled(void);

// This should really go to a suitable internal header file.
extern void oslog_stream(bool, firehose_tracepoint_id_u, uint64_t, const void *, size_t);

static log_stream_t     log_stream;
static log_cache_t      log_stream_cache;
static log_stream_si_t  log_stream_si;

#ifdef LOG_STREAM_VERIFY
static const uint64_t log_stream_msg_tag = 0xaabbccddeeff7788;
#endif /* LOG_STREAM_VERIFY */

/*
 * OSLog Streaming
 *
 * OSLog streaming has two parts, a log stream buffer and a log stream cache.
 *
 * Both, the stream and the cache, are evenly divided into LOG_BLK_SIZE bytes
 * sized blocks.
 *
 * The stream cache allows the reader to access logs quickly without interfering
 * with writers which log into the stream directly without locking. The reader
 * refills the cache once it consumes all logs in the cache. Current
 * implementation supports one reader only (diagnosticd effectively).
 *
 * In order to enable/disable the log stream or to access the cache, a log
 * stream lock (log_stream_lock) has to be taken. This is only for stream
 * open/close and read syscalls respectively to do.
 *
 * OSLog Streaming supports following boot arguments:
 *
 * 1) oslog_stream_size=N
 *    Specifies a log stream buffer size with LOG_STREAM_MIN_SIZE as default and
 *    [LOG_STREAM_MIN_SIZE, LOG_STREAM_MAX_SIZE] allowed range.
 *
 * 2) oslog_stream_csize=N
 *    Specifies a log stream cache size with LOG_CACHE_MIN_SIZE as minimum and
 *    default. LOG_STREAM_MAX_SIZE or 1/2 log stream size is maximum, whichever
 *    is smaller.
 *
 * 3) -oslog_stream_verify
 *    Alters each log timestamp with a tag. This allows to verify that internal
 *    logic properly stores and retrieves log messages to/from the log stream
 *    and the cache. Available only on DEBUG/DEVELOPMENT builds.
 */

_Static_assert(LOG_BLK_SIZE > sizeof(log_stream_msg_t),
    "Invalid log stream block size");

/*
 * An absolute stream cache size minimum, counted in blocks, must accomodate two
 * complete max sized logs (each 17 blocks large) minus one block. This assert
 * has to be kept in sync with a stream cache logic, not with LOG_CACHE_MIN_SIZE
 * definition which can be any number matching assert conditions.
 */
_Static_assert(LOG_CACHE_MIN_SIZE >= (2 * LOG_MAX_SIZE + LOG_BLK_SIZE),
    "Invalid minimum log stream cache size");

_Static_assert(LOG_CACHE_MIN_SIZE < LOG_STREAM_MIN_SIZE / 2,
    "Minimum log stream cache size is larger than 1/2 of log stream minimum size");

static inline size_t
blocks_size(size_t nblocks)
{
	return nblocks << LOG_BLK_EXP;
}

static inline size_t
blocks_count(size_t amount)
{
	return amount >> LOG_BLK_EXP;
}

static inline size_t
blocks_needed(size_t amount)
{
	if (amount % LOG_BLK_SIZE == 0) {
		return blocks_count(amount);
	}
	return blocks_count(amount) + 1;
}

static inline size_t
log_stream_block(const log_stream_t *ls, uint64_t block_seq)
{
	return block_seq % ls->ls_blk_count;
}

static inline size_t
log_stream_offset(const log_stream_t *ls, uint64_t block_seq)
{
	return blocks_size(log_stream_block(ls, block_seq));
}

static size_t
log_stream_bytes(const log_stream_t *ls, size_t pos)
{
	assert(pos >= ls->ls_commited_wraps);
	return pos - ls->ls_commited_wraps;
}

static size_t
log_stream_written(const log_stream_t *ls, size_t pos)
{
	assert(log_stream_bytes(ls, ls->ls_commited.v) >= pos);
	return log_stream_bytes(ls, ls->ls_commited.v) - pos;
}

/*
 * Makes a reservation for a given amount of the log stream space. The ticket
 * allows to determine starting offset (lst_loc) and reserved size (lst_size).
 * Calling log_stream_reserve() disables preemption and must be paired with
 * log_stream_commit() once done.
 */
static log_stream_ticket_t
log_stream_reserve(log_stream_t *ls, size_t amount)
{
	assert(!ls->ls_snapshot);
	assert(amount > 0 && amount <= ls->ls_blk_count);

	disable_preemption();

	log_stream_ticket_t t = {
		.lst_size = amount,
		.lst_loc = os_atomic_add_orig(&ls->ls_reserved, amount, relaxed)
	};
	return t;
}

/*
 * Finishes the reservation once log stream data are written/read as needed.
 * Counterpart to log_stream_reserve(), enables preemption.
 */
static void
log_stream_commit(log_stream_t *ls, log_stream_ticket_t ticket)
{
	assert(!ls->ls_snapshot);
	assert(ticket.lst_size > 0 && ticket.lst_size <= ls->ls_blk_count);

	if (ticket.lst_size == ls->ls_blk_count) {
		ls->ls_commited_wraps += ls->ls_blk_count;
	}
	os_atomic_add(&ls->ls_commited.av, ticket.lst_size, release);

	enable_preemption();
}

static void
log_stream_snapshot(const log_stream_t *ls, log_stream_t *snap)
{
	size_t commited = os_atomic_load(&ls->ls_commited.av, acquire);
	*snap = *ls;
	snap->ls_commited.v = commited;
	snap->ls_snapshot = true;
}

static uint64_t
log_stream_waitpoint(const log_stream_t *ls, log_stream_ticket_t ticket)
{
	const uint64_t block = log_stream_block(ls, ticket.lst_loc);

	if (block + ticket.lst_size > ls->ls_blk_count) {
		return ticket.lst_loc;
	}
	return ticket.lst_loc - block;
}

static void
log_stream_wait(log_stream_t *ls, log_stream_ticket_t ticket)
{
	const uint64_t waitpoint = log_stream_waitpoint(ls, ticket);

	size_t commited = os_atomic_load(&ls->ls_commited.av, relaxed);
	while (waitpoint > commited) {
		commited = hw_wait_while_equals_long(&ls->ls_commited.av, commited);
	}
}

static inline void
log_stream_msg_alter(log_stream_msg_t __unused *msg)
{
#ifdef LOG_STREAM_VERIFY
	if (__improbable(log_stream_verify)) {
		msg->lsm_ts = log_stream_msg_tag; // alignment tag
	}
#endif /* LOG_STREAM_VERIFY */
}

static inline void
log_stream_msg_verify(const log_stream_msg_t __unused *msg)
{
#ifdef LOG_STREAM_VERIFY
	if (__improbable(log_stream_verify)) {
		if (msg->lsm_ts != log_stream_msg_tag) {
			panic("missing log stream message tag at %p\n", msg);
		}
	}
#endif /* LOG_STREAM_VERIFY */
}

static size_t
log_stream_msg_size(const log_stream_msg_t *m)
{
	assert(LOG_SIZE_VALID(m->lsm_ft.ft_length));
	return sizeof(*m) + m->lsm_ft.ft_length;
}

static size_t
log_stream_msg_make(log_stream_msg_t *msg, firehose_tracepoint_id_u ftid,
    uint64_t stamp, size_t data_len)
{
	msg->lsm_ts = stamp;
	msg->lsm_ft.ft_thread = thread_tid(current_thread());
	msg->lsm_ft.ft_id.ftid_value = ftid.ftid_value;
	msg->lsm_ft.ft_length = data_len;
	log_stream_msg_alter(msg);
	return blocks_needed(log_stream_msg_size(msg));
}

static void
log_session_make(log_stream_session_t *session, log_stream_t *ls, log_stream_ticket_t t)
{
	session->lss_ticket = t;
	session->lss_stream = ls;
	log_stream_snapshot(session->lss_stream, &session->lss_snapshot);
}

#define log_session_stream(s)   (&(s)->lss_snapshot)
#define log_session_loc(s)      ((s)->lss_ticket.lst_loc)
#define log_session_size(s)     ((s)->lss_ticket.lst_size)

static void
log_session_start(log_stream_t *ls, size_t size, log_stream_session_t *session)
{
	assert(!ls->ls_snapshot);

	log_stream_ticket_t ticket = log_stream_reserve(ls, size);
	log_stream_wait(ls, ticket);
	log_session_make(session, ls, ticket);
}

static void
log_session_finish(log_stream_session_t *session)
{
	log_stream_commit(session->lss_stream, session->lss_ticket);
	bzero(session, sizeof(*session));
}

static size_t
log_stream_avail(log_stream_t *ls, size_t pos)
{
	log_stream_t snap;
	log_stream_snapshot(ls, &snap);
	return log_stream_written(&snap, pos);
}

static size_t
rbuf_copy(uint8_t *rb, size_t rb_size, size_t offset, size_t n, const uint8_t *d)
{
	const size_t remains = MIN(n, rb_size - offset);
	assert(remains > 0);

	(void) memcpy(rb + offset, d, remains);
	if (remains < n) {
		(void) memcpy(rb, d + remains, n - remains);
	}

	return (offset + n) % rb_size;
}

static void
rbuf_set(uint8_t *rb, size_t rb_size, size_t offset, size_t n, uint8_t v)
{
	const size_t remains = MIN(n, rb_size - offset);
	assert(remains > 0);

	(void) memset(rb + offset, v, remains);
	if (remains < n) {
		(void) memset(rb, v, n - remains);
	}
}

static void
rbuf_read(const uint8_t *rb, size_t rb_size, size_t offset, size_t n, uint8_t *b)
{
	assert(offset < rb_size);
	assert(n <= rb_size);

	const size_t remains = MIN(n, rb_size - offset);
	assert(remains > 0);

	memcpy(b, rb + offset, remains);
	if (remains < n) {
		memcpy(b + remains, rb, n - remains);
	}
}

static size_t
log_stream_write(log_stream_t *ls, size_t offset, size_t n, const uint8_t *buf)
{
	return rbuf_copy(ls->ls_buf, blocks_size(ls->ls_blk_count), offset, n, buf);
}

static void
log_stream_read(log_stream_t *ls, size_t blk_seq, size_t blk_cnt, uint8_t *buf)
{
	rbuf_read(ls->ls_buf, blocks_size(ls->ls_blk_count),
	    log_stream_offset(ls, blk_seq), blocks_size(blk_cnt), buf);
}

static void
log_stream_write_blocks(log_stream_t *ls, size_t blk_seq, size_t blk_count)
{
	const size_t blk_id = log_stream_block(ls, blk_seq);
	rbuf_set(ls->ls_blk, ls->ls_blk_count, blk_id, blk_count, LOG_BLK_BODY);
	ls->ls_blk[blk_id] = LOG_BLK_HEADER;
}

static void
log_stream_read_blocks(log_stream_t *ls, size_t blk_seq, size_t blk_cnt, uint8_t *buf)
{
	const size_t blk_id = log_stream_block(ls, blk_seq);
	rbuf_read(ls->ls_blk, ls->ls_blk_count, blk_id, blk_cnt, buf);
}

static void
log_session_store(log_stream_session_t *lss, log_stream_msg_t *msg, const void *msg_data)
{
	log_stream_t *ls = log_session_stream(lss);
	size_t blk_seq = log_session_loc(lss);
	size_t offset = log_stream_offset(ls, blk_seq);

	offset = log_stream_write(ls, offset, sizeof(*msg), (uint8_t *)msg);
	(void) log_stream_write(ls, offset, msg->lsm_ft.ft_length, msg_data);
	log_stream_write_blocks(ls, blk_seq, log_session_size(lss));
}

static size_t
log_stream_sync(const log_stream_t *ls, size_t pos)
{
	assert(ls->ls_snapshot);

	const size_t logged = log_stream_written(ls, 0);
	assert(pos <= logged);

	if (pos + ls->ls_blk_count >= logged) {
		return 0;
	}
	if (__improbable(ls->ls_commited.v < ls->ls_blk_count)) {
		return logged - pos;
	}
	return logged - ls->ls_blk_count - pos;
}

static bool
log_cache_refill(log_cache_t *lc)
{
	log_stream_t *ls = lc->lc_stream;
	assert(ls->ls_enabled);

	if (log_stream_avail(ls, lc->lc_stream_pos) == 0) {
		return false;
	}

	log_stream_session_t session;
	log_session_start(ls, ls->ls_blk_count, &session);

	ls = log_session_stream(&session);
	assert(ls->ls_enabled);

	if (log_stream_written(ls, lc->lc_stream_pos) == 0) {
		log_session_finish(&session);
		return false;
	}

	lc->lc_stream_pos += log_stream_sync(ls, lc->lc_stream_pos);

	size_t blk_avail = MIN(log_stream_written(ls, lc->lc_stream_pos),
	    lc->lc_blk_count);
	assert(blk_avail > 0);

	log_stream_read_blocks(ls, lc->lc_stream_pos, blk_avail, lc->lc_blk);
	log_stream_read(ls, lc->lc_stream_pos, blk_avail, lc->lc_buf);

	log_session_finish(&session);
	lc->lc_stream_pos += blk_avail;

	return true;
}

static void
log_stream_si_wakeup_locked(log_stream_si_t *lsi)
{
	LCK_SPIN_ASSERT(&lsi->lsi_lock, LCK_ASSERT_OWNED);

	if (lsi->lsi_channel) {
		selwakeup(&lsi->lsi_selinfo);
		if (lsi->lsi_opts & LOG_STREAM_OPT_RDWAIT) {
			wakeup(lsi->lsi_channel);
			lsi->lsi_opts &= ~LOG_STREAM_OPT_RDWAIT;
		}
	}
}

static void
log_stream_si_wakeup(log_stream_si_t *lsi)
{
	static size_t _Atomic delayed_wakeups = 0;

	if (!lck_spin_try_lock(&lsi->lsi_lock)) {
		os_atomic_inc(&delayed_wakeups, relaxed);
		return;
	}

	log_stream_si_wakeup_locked(lsi);

	if (atomic_load(&delayed_wakeups) > 0) {
		log_stream_si_wakeup_locked(lsi);
		os_atomic_dec(&delayed_wakeups, relaxed);
	}

	log_stream_si_unlock(lsi);
}

static void
log_stream_si_record(log_stream_si_t *lsi, void *wql, proc_t p)
{
	log_stream_si_lock(lsi);
	assert(lsi->lsi_channel);
	selrecord(p, &lsi->lsi_selinfo, wql);
	log_stream_si_unlock(lsi);
}

static void
log_stream_si_enable(log_stream_si_t *lsi, log_stream_t *ls)
{
	log_stream_si_lock(lsi);
	assert(!lsi->lsi_channel);
	lsi->lsi_channel = (caddr_t)ls;
	log_stream_si_unlock(lsi);
}

static void
log_stream_si_disable(log_stream_si_t *lsi)
{
	log_stream_si_lock(lsi);
	log_stream_si_wakeup_locked(lsi);
	lsi->lsi_opts &= ~(LOG_STREAM_OPT_NBIO | LOG_STREAM_OPT_ASYNC);
	selthreadclear(&lsi->lsi_selinfo);
	assert(lsi->lsi_channel);
	lsi->lsi_channel = (caddr_t)NULL;
	log_stream_si_unlock(lsi);
}

static bool
log_stream_make(log_stream_t *ls, size_t stream_size)
{
	assert(stream_size >= LOG_STREAM_MIN_SIZE);
	assert(stream_size <= LOG_STREAM_MAX_SIZE);

	bzero(ls, sizeof(*ls));

	ls->ls_blk_count = blocks_count(stream_size);
	ls->ls_blk = kalloc_data(ls->ls_blk_count, Z_WAITOK | Z_ZERO);
	if (!ls->ls_blk) {
		return false;
	}

	ls->ls_buf = kalloc_data(blocks_size(ls->ls_blk_count),
	    Z_WAITOK | Z_ZERO);
	if (!ls->ls_buf) {
		kfree_data(ls->ls_blk, ls->ls_blk_count);
		return false;
	}

	return true;
}

static void
log_stream_enable(log_stream_t *tgt, log_stream_t *src)
{
	/*
	 * Never overwrite reservation and commited sequences. Preserving values
	 * allows to avoid races between threads when the device gets opened and
	 * closed multiple times.
	 */
	tgt->ls_buf = src->ls_buf;
	tgt->ls_blk = src->ls_blk;
	bzero(src, sizeof(*src));
	tgt->ls_enabled = true;
}

static void
log_stream_disable(log_stream_t *src, log_stream_t *tgt)
{
	*tgt = *src;
	src->ls_buf = NULL;
	src->ls_blk = NULL;
	src->ls_enabled = false;
}

static void
log_stream_teardown(log_stream_t *ls)
{
	if (ls->ls_buf) {
		const size_t buf_size = blocks_size(ls->ls_blk_count);
		bzero(ls->ls_buf, buf_size);
		kfree_data(ls->ls_buf, buf_size);
	}
	if (ls->ls_blk) {
		kfree_type(uint8_t, ls->ls_blk_count, ls->ls_blk);
	}
	bzero(ls, sizeof(*ls));
}

static bool
log_cache_make(log_cache_t *lc, size_t lc_size, log_stream_t *ls)
{
	bzero(lc, sizeof(*lc));

	lc->lc_blk_count = blocks_count(lc_size);
	lc->lc_blk = kalloc_data(lc->lc_blk_count, Z_WAITOK | Z_ZERO);
	if (!lc->lc_blk) {
		return false;
	}

	lc->lc_buf = kalloc_data(blocks_size(lc->lc_blk_count), Z_WAITOK | Z_ZERO);
	if (!lc->lc_buf) {
		kfree_data(lc->lc_blk, lc->lc_blk_count);
		return false;
	}

	lc->lc_stream = ls;
	lc->lc_stream_pos = log_stream_written(ls, 0);

	return true;
}

static void
log_cache_move(log_cache_t *src, log_cache_t *tgt)
{
	*tgt = *src;
	bzero(src, sizeof(*src));
}

static void
log_cache_teardown(log_cache_t *lc)
{
	if (lc->lc_blk) {
		kfree_data(lc->lc_blk, lc->lc_blk_count);
	}
	if (lc->lc_buf) {
		kfree_data(lc->lc_buf, blocks_size(lc->lc_blk_count));
	}
	bzero(lc, sizeof(*lc));
}

static void
log_cache_rewind(log_cache_t *lc)
{
	bzero(lc->lc_blk, lc->lc_blk_count);
	bzero(lc->lc_buf, blocks_size(lc->lc_blk_count));
	lc->lc_blk_pos = 0;
}

static void
log_cache_consume(log_cache_t *lc, size_t amount)
{
	lc->lc_blk_pos += blocks_needed(amount);
}

static size_t
log_cache_next_msg(log_cache_t *lc)
{
	assert(lc->lc_blk_pos <= lc->lc_blk_count);

	for (size_t n = lc->lc_blk_pos; n < lc->lc_blk_count; n++) {
		if (lc->lc_blk[n] == LOG_BLK_HEADER) {
			lc->lc_blk_pos = n;
			return lc->lc_blk_pos;
		}
	}
	return LOG_CACHE_EMPTY;
}

static log_stream_msg_t *
log_cache_msg(const log_cache_t *lc, size_t blk_id, size_t *msg_size)
{
	assert(blk_id != LOG_CACHE_EMPTY);
	assert(blk_id < lc->lc_blk_count);

	log_stream_msg_t *msg =
	    (log_stream_msg_t *)&lc->lc_buf[blocks_size(blk_id)];

	if (!LOG_SIZE_VALID(msg->lsm_ft.ft_length)) {
		*msg_size = 0;
		return NULL;
	}

	*msg_size = log_stream_msg_size(msg);
	return msg;
}

static bool
log_cache_get(log_cache_t *lc, log_stream_msg_t **log, size_t *log_size)
{
	size_t log_index = log_cache_next_msg(lc);

	/*
	 * Find a next message. If the message is cached partially, seek the
	 * cursor back to the message beginning and refill the cache. Refill if
	 * the cache is empty.
	 */
	if (log_index != LOG_CACHE_EMPTY) {
		*log = log_cache_msg(lc, log_index, log_size);
		assert(*log && *log_size > 0);
		size_t remains = lc->lc_blk_count - log_index;
		if (*log_size <= blocks_size(remains)) {
			return true;
		}
		lc->lc_stream_pos -= remains;
	}
	log_cache_rewind(lc);

	if (log_cache_refill(lc)) {
		*log = log_cache_msg(lc, log_cache_next_msg(lc), log_size);
		return true;
	}
	return false;
}

static int
handle_no_logs(log_stream_t *ls, int flag)
{
	if (flag & IO_NDELAY) {
		return EWOULDBLOCK;
	}

	log_stream_si_lock(&log_stream_si);
	if (log_stream_si.lsi_opts & LOG_STREAM_OPT_NBIO) {
		log_stream_si_unlock(&log_stream_si);
		return EWOULDBLOCK;
	}
	log_stream_si.lsi_opts |= LOG_STREAM_OPT_RDWAIT;
	log_stream_si_unlock(&log_stream_si);

	wait_result_t wr = assert_wait((event_t)ls, THREAD_INTERRUPTIBLE);
	if (wr == THREAD_WAITING) {
		wr = thread_block(THREAD_CONTINUE_NULL);
	}

	return wr == THREAD_AWAKENED || wr == THREAD_TIMED_OUT ? 0 : EINTR;
}

void
oslog_stream(bool is_metadata, firehose_tracepoint_id_u ftid, uint64_t stamp,
    const void *data, size_t datalen)
{
	if (!log_stream.ls_enabled) {
		counter_inc(&oslog_s_dropped_msgcount);
		return;
	}

	if (__improbable(!oslog_is_safe())) {
		counter_inc(&oslog_s_dropped_msgcount);
		return;
	}

	if (__improbable(is_metadata)) {
		counter_inc(&oslog_s_metadata_msgcount);
	} else {
		counter_inc(&oslog_s_total_msgcount);
	}

	if (__improbable(!LOG_SIZE_VALID(datalen))) {
		counter_inc(&oslog_s_error_count);
		return;
	}

	log_stream_msg_t msg;
	size_t msg_size = log_stream_msg_make(&msg, ftid, stamp, datalen);

	log_stream_session_t session;
	log_session_start(&log_stream, msg_size, &session);

	// Check again, the state may have changed.
	if (!log_session_stream(&session)->ls_enabled) {
		log_session_finish(&session);
		counter_inc(&oslog_s_dropped_msgcount);
		return;
	}

	log_session_store(&session, &msg, data);
	log_session_finish(&session);
	log_stream_si_wakeup(&log_stream_si);
}

int
oslog_streamread(dev_t dev, struct uio *uio, int flag)
{
	log_stream_msg_t *log = NULL;
	size_t log_size = 0;
	int error;

	if (minor(dev) != 0) {
		return ENXIO;
	}

	log_stream_lock();

	if (!log_stream.ls_enabled) {
		log_stream_unlock();
		return ENXIO;
	}

	while (!log_cache_get(&log_stream_cache, &log, &log_size)) {
		log_stream_unlock();
		if ((error = handle_no_logs(&log_stream, flag))) {
			return error;
		}
		log_stream_lock();
		if (!log_stream.ls_enabled) {
			log_stream_unlock();
			return ENXIO;
		}
	}
	assert(log);
	assert(log_size > 0);

	log_stream_msg_verify(log);

	if (log_size > MIN(uio_resid(uio), INT_MAX)) {
		log_stream_unlock();
		counter_inc(&oslog_s_error_count);
		return ENOBUFS;
	}

	error = uiomove((caddr_t)log, (int)log_size, uio);
	if (!error) {
		log_cache_consume(&log_stream_cache, log_size);
		counter_inc(&oslog_s_streamed_msgcount);
	} else {
		counter_inc(&oslog_s_error_count);
	}

	log_stream_unlock();

	return error;
}

int
oslog_streamselect(dev_t dev, int rw, void *wql, proc_t p)
{
	if (minor(dev) != 0 || rw != FREAD) {
		return 0;
	}

	bool new_logs = true;

	log_stream_lock();
	if (log_cache_next_msg(&log_stream_cache) == LOG_CACHE_EMPTY &&
	    log_stream_avail(&log_stream, log_stream_cache.lc_stream_pos) == 0) {
		log_stream_si_record(&log_stream_si, wql, p);
		new_logs = false;
	}
	log_stream_unlock();

	return new_logs;
}

int
oslog_streamioctl(dev_t dev, u_long com, caddr_t data, __unused int flag,
    __unused struct proc *p)
{
	if (minor(dev) != 0) {
		return ENXIO;
	}

	log_stream_siopts_t opt = 0;

	switch (com) {
	case FIOASYNC:
		opt = LOG_STREAM_OPT_ASYNC;
		break;
	case FIONBIO:
		opt = LOG_STREAM_OPT_NBIO;
		break;
	default:
		return ENOTTY;
	}

	int data_value = 0;
	if (data) {
		bcopy(data, &data_value, sizeof(data_value));
	}

	log_stream_lock();
	log_stream_si_lock(&log_stream_si);
	assert(log_stream.ls_enabled);

	if (data_value) {
		log_stream_si.lsi_opts |= opt;
	} else {
		log_stream_si.lsi_opts &= ~opt;
	}

	log_stream_si_unlock(&log_stream_si);
	log_stream_unlock();

	return 0;
}

int
oslog_streamopen(dev_t dev, __unused int flags, __unused int mode,
    __unused struct proc *p)
{
	if (minor(dev) != 0) {
		return ENXIO;
	}

	log_stream_t bringup_ls;
	if (!log_stream_make(&bringup_ls, log_stream_size)) {
		return ENOMEM;
	}

	log_cache_t bringup_lsc;
	if (!log_cache_make(&bringup_lsc, log_stream_cache_size, &log_stream)) {
		log_stream_teardown(&bringup_ls);
		return ENOMEM;
	}

	log_stream_lock();

	if (log_stream.ls_enabled) {
		log_stream_unlock();
		log_stream_teardown(&bringup_ls);
		log_cache_teardown(&bringup_lsc);
		return EBUSY;
	}

	log_stream_session_t session;
	log_session_start(&log_stream, log_stream.ls_blk_count, &session);

	log_stream_enable(&log_stream, &bringup_ls);
	log_session_finish(&session);

	log_cache_move(&bringup_lsc, &log_stream_cache);
	log_stream_si_enable(&log_stream_si, &log_stream);
	log_stream_unlock();

	return 0;
}

int
oslog_streamclose(dev_t dev, __unused int flag, __unused int devtype, __unused struct proc *p)
{
	if (minor(dev) != 0) {
		return ENXIO;
	}

	log_stream_lock();

	if (!log_stream.ls_enabled) {
		log_stream_unlock();
		return ENXIO;
	}

	log_stream_si_disable(&log_stream_si);

	log_stream_session_t session;
	log_session_start(&log_stream, log_stream.ls_blk_count, &session);

	log_stream_t teardown_ls;
	log_stream_disable(&log_stream, &teardown_ls);
	log_session_finish(&session);

	log_cache_t teardown_lsc;
	log_cache_move(&log_stream_cache, &teardown_lsc);
	log_stream_unlock();

	log_stream_teardown(&teardown_ls);
	log_cache_teardown(&teardown_lsc);

	return 0;
}

__startup_func
static void
oslog_stream_init(void)
{
	if (os_log_disabled()) {
		printf("OSLog stream disabled: Logging disabled by ATM\n");
		return;
	}

	log_stream_size = MAX(log_stream_size, LOG_STREAM_MIN_SIZE);
	log_stream_size = MIN(log_stream_size, LOG_STREAM_MAX_SIZE);

	log_stream_cache_size = MAX(log_stream_cache_size, LOG_CACHE_MIN_SIZE);
	log_stream_cache_size = MIN(log_stream_cache_size, LOG_CACHE_MAX_SIZE);
	log_stream_cache_size = MIN(log_stream_cache_size, log_stream_size / 2);

	log_stream.ls_blk_count = blocks_count(log_stream_size);
	lck_spin_init(&log_stream_si.lsi_lock, &log_stream_lock_grp,
	    LCK_ATTR_NULL);

	printf("OSLog stream configured: stream: %lu bytes, cache: %lu bytes\n",
	    log_stream_size, log_stream_cache_size);
#ifdef LOG_STREAM_VERIFY
	printf("OSLog stream verification: %d\n", log_stream_verify);
#endif /* LOG_STREAM_VERIFY */
}
STARTUP(OSLOG, STARTUP_RANK_SECOND, oslog_stream_init);
