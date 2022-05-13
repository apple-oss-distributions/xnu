/*
 * Copyright (c) 2015-2021 Apple Inc. All rights reserved.
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
 * Copyright (C) 2012-2014 Matteo Landi, Luigi Rizzo, Giuseppe Lettieri.
 * All rights reserved.
 * Copyright (C) 2013-2014 Universita` di Pisa. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/eventvar.h>
#include <sys/kdebug.h>
#include <sys/sdt.h>
#include <skywalk/os_skywalk_private.h>
#include <skywalk/nexus/netif/nx_netif.h>

#define KEV_EVTID(code) BSDDBG_CODE(DBG_BSD_KEVENT, (code))

struct ch_event_result {
	uint32_t tx_data;
	uint32_t rx_data;
};

static LCK_GRP_DECLARE(channel_lock_group, "sk_ch_lock");
static LCK_GRP_DECLARE(channel_kn_lock_group, "sk_ch_kn_lock");
LCK_ATTR_DECLARE(channel_lock_attr, 0, 0);

static void csi_selrecord(struct ch_selinfo *, struct proc *, void *);
static void csi_selwakeup(struct ch_selinfo *, boolean_t, boolean_t, uint32_t);
static inline void csi_selwakeup_delayed(struct ch_selinfo *);
static inline void csi_selwakeup_common(struct ch_selinfo *, boolean_t,
    boolean_t, boolean_t, uint32_t);
static boolean_t csi_tcall_start(struct ch_selinfo *);
static void csi_tcall(thread_call_param_t, thread_call_param_t);
static uint64_t csi_tcall_update_interval(struct ch_selinfo *);

static void ch_redzone_init(void);
static void ch_close_common(struct kern_channel *, boolean_t, boolean_t);
static struct kern_channel *ch_find(struct kern_nexus *, nexus_port_t,
    ring_id_t);
static int ch_ev_thresh_validate(struct kern_nexus *, enum txrx,
    struct ch_ev_thresh *);
static struct kern_channel *ch_connect(struct kern_nexus *, struct chreq *,
    struct kern_channel *, struct nxbind *, struct proc *, int, int *);
static void ch_disconnect(struct kern_channel *);
static int ch_set_lowat_thresh(struct kern_channel *, enum txrx,
    struct sockopt *);
static int ch_get_lowat_thresh(struct kern_channel *, enum txrx,
    struct sockopt *);
static struct kern_channel *ch_alloc(zalloc_flags_t);
static void ch_free(struct kern_channel *);
static int ch_configure_interface_advisory_event(struct kern_channel *ch,
    struct sockopt *sopt);

static int filt_chrwattach(struct knote *, struct kevent_qos_s *kev);
static void filt_chrwdetach(struct knote *, boolean_t);
static void filt_chrdetach(struct knote *);
static void filt_chwdetach(struct knote *);
static int filt_chrw(struct knote *, long, int);
static int filt_chread(struct knote *, long);
static int filt_chwrite(struct knote *, long);

static int filt_chtouch(struct knote *, struct kevent_qos_s *, int);
static int filt_chrtouch(struct knote *, struct kevent_qos_s *);
static int filt_chwtouch(struct knote *, struct kevent_qos_s *);
static int filt_chprocess(struct knote *, struct kevent_qos_s *, int);
static int filt_chrprocess(struct knote *, struct kevent_qos_s *);
static int filt_chwprocess(struct knote *, struct kevent_qos_s *);
static int filt_che_attach(struct knote *, struct kevent_qos_s *kev);
static void filt_che_detach(struct knote *);
static int filt_che_event(struct knote *, long);
static int filt_che_touch(struct knote *, struct kevent_qos_s *);
static int filt_che_process(struct knote *, struct kevent_qos_s *);
static int filt_chan_extended_common(struct knote *, long);

static int ch_event(struct kern_channel *ch, int events,
    void *wql, struct proc *p, struct ch_event_result *,
    const boolean_t is_kevent, int *errno, const boolean_t);

const struct filterops skywalk_channel_rfiltops = {
	.f_isfd =       1,
	.f_attach =     filt_chrwattach,
	.f_detach =     filt_chrdetach,
	.f_event =      filt_chread,
	.f_touch =      filt_chrtouch,
	.f_process =    filt_chrprocess,
};

const struct filterops skywalk_channel_wfiltops = {
	.f_isfd =       1,
	.f_attach =     filt_chrwattach,
	.f_detach =     filt_chwdetach,
	.f_event =      filt_chwrite,
	.f_touch =      filt_chwtouch,
	.f_process =    filt_chwprocess,
};

const struct filterops skywalk_channel_efiltops = {
	.f_isfd =       1,
	.f_attach =     filt_che_attach,
	.f_detach =     filt_che_detach,
	.f_event =      filt_che_event,
	.f_touch =      filt_che_touch,
	.f_process =    filt_che_process,
};

/* mitigation intervals in ns */
#define CH_MIT_IVAL_MIN         NSEC_PER_USEC

static uint64_t ch_mit_ival = CH_MIT_IVAL_DEFAULT;

#if (DEVELOPMENT || DEBUG)
SYSCTL_NODE(_kern_skywalk, OID_AUTO, channel,
    CTLFLAG_RW | CTLFLAG_LOCKED, 0, "Skywalk channel parameters");
SYSCTL_QUAD(_kern_skywalk_channel, OID_AUTO, mit_ival,
    CTLFLAG_RW | CTLFLAG_LOCKED, &ch_mit_ival, "");
#endif /* !DEVELOPMENT && !DEBUG */

static ZONE_DEFINE(ch_zone, SKMEM_ZONE_PREFIX ".ch",
    sizeof(struct kern_channel), ZC_ZFREE_CLEARMEM);

static ZONE_DEFINE(ch_info_zone, SKMEM_ZONE_PREFIX ".ch.info",
    sizeof(struct ch_info), ZC_ZFREE_CLEARMEM);

static int __ch_inited = 0;

/*
 * Global cookies to hold the random numbers used for verifying
 * user metadata red zone violations.
 */
uint64_t __ch_umd_redzone_cookie = 0;

#define SKMEM_TAG_CH_KEY        "com.apple.skywalk.channel.key"
SKMEM_TAG_DEFINE(skmem_tag_ch_key, SKMEM_TAG_CH_KEY);

static void
ch_redzone_init(void)
{
	_CASSERT(sizeof(__ch_umd_redzone_cookie) ==
	    sizeof(((struct __metadata_preamble *)0)->mdp_redzone));
	_CASSERT(METADATA_PREAMBLE_SZ == sizeof(struct __metadata_preamble));
	_CASSERT(sizeof(struct __slot_desc) == 8);

	/* Initialize random user red zone cookie values */
	do {
		read_random(&__ch_umd_redzone_cookie,
		    sizeof(__ch_umd_redzone_cookie));
	} while (__ch_umd_redzone_cookie == 0);

	SK_D("__ch_umd_redzone_cookie: 0x%llx", __ch_umd_redzone_cookie);
}

int
channel_init(void)
{
	int error = 0;

	SK_LOCK_ASSERT_HELD();
	ASSERT(!__ch_inited);

	_CASSERT(offsetof(struct __user_packet, pkt_qum) == 0);
	_CASSERT(offsetof(struct __kern_packet, pkt_qum) == 0);

	ch_redzone_init();

	__ch_inited = 1;

	return error;
}

void
channel_fini(void)
{
	SK_LOCK_ASSERT_HELD();

	if (__ch_inited) {
		__ch_umd_redzone_cookie = 0;
		__ch_inited = 0;
	}
}

void
csi_init(struct ch_selinfo *csi, boolean_t mitigation, uint64_t mit_ival)
{
	csi->csi_flags = 0;
	csi->csi_pending = 0;
	if (mitigation) {
		csi->csi_interval = mit_ival;
		csi->csi_eff_interval = ch_mit_ival;    /* global override */
		atomic_bitset_32(&csi->csi_flags, CSI_MITIGATION);
		csi->csi_tcall = thread_call_allocate_with_options(csi_tcall,
		    csi, THREAD_CALL_PRIORITY_KERNEL, THREAD_CALL_OPTIONS_ONCE);
		/* this must not fail */
		VERIFY(csi->csi_tcall != NULL);
	} else {
		csi->csi_interval = 0;
		csi->csi_eff_interval = 0;
		csi->csi_tcall = NULL;
	}
	lck_mtx_init(&csi->csi_lock, &channel_kn_lock_group, &channel_lock_attr);
	klist_init(&csi->csi_si.si_note);
}

void
csi_destroy(struct ch_selinfo *csi)
{
	/* check if not already destroyed, else do it now */
	if ((atomic_bitset_32_ov(&csi->csi_flags, CSI_DESTROYED) &
	    CSI_DESTROYED) == 0) {
		CSI_LOCK(csi);
		/* must have been set by above atomic op */
		VERIFY(csi->csi_flags & CSI_DESTROYED);
		if (csi->csi_flags & CSI_MITIGATION) {
			thread_call_t tcall = csi->csi_tcall;
			VERIFY(tcall != NULL);
			CSI_UNLOCK(csi);

			(void) thread_call_cancel_wait(tcall);
			if (!thread_call_free(tcall)) {
				boolean_t freed;
				(void) thread_call_cancel_wait(tcall);
				freed = thread_call_free(tcall);
				VERIFY(freed);
			}

			CSI_LOCK(csi);
			csi->csi_tcall = NULL;
			atomic_bitclear_32(&csi->csi_flags, CSI_MITIGATION);
		}
		csi->csi_pending = 0;
		CSI_UNLOCK(csi);

		selthreadclear(&csi->csi_si);
		/* now we don't need the mutex anymore */
		lck_mtx_destroy(&csi->csi_lock, &channel_kn_lock_group);
	}
}

/*
 * Called only for select(2).
 */
__attribute__((always_inline))
static inline void
csi_selrecord(struct ch_selinfo *csi, struct proc *p, void *wql)
{
	struct selinfo *si = &csi->csi_si;

	CSI_LOCK_ASSERT_HELD(csi);
	selrecord(p, si, wql);
}

void
csi_selrecord_one(struct __kern_channel_ring *kring, struct proc *p, void *wql)
{
	struct ch_selinfo *csi = &kring->ckr_si;

	CSI_LOCK(csi);
	SK_DF(SK_VERB_EVENTS, "[%s] na \"%s\" (0x%llx) kr %s (0x%llx) "
	    "si 0x%llx si_flags 0x%x", (kring->ckr_tx == NR_TX) ? "W" : "R",
	    KRNA(kring)->na_name, SK_KVA(KRNA(kring)), kring->ckr_name,
	    SK_KVA(kring), SK_KVA(&csi->csi_si), csi->csi_si.si_flags);

	csi_selrecord(csi, p, wql);
	CSI_UNLOCK(csi);
}

void
csi_selrecord_all(struct nexus_adapter *na, enum txrx t, struct proc *p,
    void *wql)
{
	struct ch_selinfo *csi = &na->na_si[t];

	CSI_LOCK(csi);
	SK_DF(SK_VERB_EVENTS, "[%s] na \"%s\" (0x%llx) si 0x%llx si_flags 0x%x",
	    (t == NR_TX) ? "W" : "R", na->na_name, SK_KVA(na),
	    SK_KVA(&csi->csi_si), csi->csi_si.si_flags);

	csi_selrecord(csi, p, wql);
	CSI_UNLOCK(csi);
}

/*
 * Called from na_post_event().
 */
__attribute__((always_inline))
static inline void
csi_selwakeup(struct ch_selinfo *csi, boolean_t within_kevent,
    boolean_t selwake, uint32_t hint)
{
	struct selinfo *si = &csi->csi_si;

	CSI_LOCK_ASSERT_HELD(csi);
	csi->csi_pending = 0;
	if (selwake) {
		selwakeup(si);
	}
	if ((csi->csi_flags & CSI_KNOTE) && !within_kevent) {
		KNOTE(&si->si_note, hint);
	}
}

__attribute__((always_inline))
static inline void
csi_selwakeup_delayed(struct ch_selinfo *csi)
{
	CSI_LOCK_ASSERT_HELD(csi);
	ASSERT(csi->csi_flags & CSI_MITIGATION);
	ASSERT(csi->csi_tcall != NULL);

	if (thread_call_isactive(csi->csi_tcall)) {
		csi->csi_pending++;
	} else if (!csi_tcall_start(csi)) {
		csi_selwakeup(csi, FALSE, FALSE, 0);
	}
}

__attribute__((always_inline))
static inline void
csi_selwakeup_common(struct ch_selinfo *csi, boolean_t nodelay,
    boolean_t within_kevent, boolean_t selwake, uint32_t hint)
{
	CSI_LOCK_ASSERT_HELD(csi);

	if (nodelay || within_kevent || !selwake || hint != 0 ||
	    !(csi->csi_flags & CSI_MITIGATION)) {
		csi_selwakeup(csi, within_kevent, selwake, hint);
	} else {
		csi_selwakeup_delayed(csi);
	}
}

void
csi_selwakeup_one(struct __kern_channel_ring *kring, boolean_t nodelay,
    boolean_t within_kevent, boolean_t selwake, uint32_t hint)
{
	struct ch_selinfo *csi = &kring->ckr_si;

	CSI_LOCK(csi);
	SK_DF(SK_VERB_EVENTS, "[%s] na \"%s\" (0x%llx) kr %s (0x%llx) "
	    "si 0x%llx si_flags 0x%x nodelay %u kev %u sel %u hint 0x%b",
	    (kring->ckr_tx == NR_TX) ? "W" : "R", KRNA(kring)->na_name,
	    SK_KVA(KRNA(kring)), kring->ckr_name, SK_KVA(kring),
	    SK_KVA(&csi->csi_si), csi->csi_si.si_flags, nodelay,
	    within_kevent, selwake, hint, CHAN_FILT_HINT_BITS);

	csi_selwakeup_common(csi, nodelay, within_kevent, selwake, hint);
	CSI_UNLOCK(csi);
}

void
csi_selwakeup_all(struct nexus_adapter *na, enum txrx t, boolean_t nodelay,
    boolean_t within_kevent, boolean_t selwake, uint32_t hint)
{
	struct ch_selinfo *csi = &na->na_si[t];

	CSI_LOCK(csi);
	SK_DF(SK_VERB_EVENTS, "[%s] na \"%s\" (0x%llx) si 0x%llx "
	    "si_flags 0x%x nodelay %u kev %u sel %u hint 0x%b",
	    (t == NR_TX) ? "W" : "R", na->na_name, SK_KVA(na),
	    SK_KVA(&csi->csi_si), csi->csi_si.si_flags, nodelay,
	    within_kevent, selwake, hint, CHAN_FILT_HINT_BITS);

	switch (t) {
	case NR_RX:
		if (!(na->na_flags & NAF_RX_MITIGATION)) {
			nodelay = TRUE;
		}
		break;

	case NR_TX:
		if (!(na->na_flags & NAF_TX_MITIGATION)) {
			nodelay = TRUE;
		}
		break;

	default:
		nodelay = TRUE;
		break;
	}
	csi_selwakeup_common(csi, nodelay, within_kevent, selwake, hint);
	CSI_UNLOCK(csi);
}

static boolean_t
csi_tcall_start(struct ch_selinfo *csi)
{
	uint64_t now, ival, deadline;

	CSI_LOCK_ASSERT_HELD(csi);
	ASSERT(csi->csi_flags & CSI_MITIGATION);
	ASSERT(csi->csi_tcall != NULL);

	/* pick up latest value */
	ival = csi_tcall_update_interval(csi);

	/* if no mitigation, pass notification up now */
	if (__improbable(ival == 0)) {
		return FALSE;
	}

	deadline = now = mach_absolute_time();
	clock_deadline_for_periodic_event(ival, now, &deadline);
	(void) thread_call_enter_delayed(csi->csi_tcall, deadline);

	return TRUE;
}

static void
csi_tcall(thread_call_param_t arg0, thread_call_param_t arg1)
{
#pragma unused(arg1)
	struct ch_selinfo *csi = arg0;

	CSI_LOCK(csi);
	csi_selwakeup(csi, FALSE, FALSE, 0);
	CSI_UNLOCK(csi);

	CSI_LOCK(csi);
	if (__improbable((csi->csi_flags & CSI_DESTROYED) == 0 &&
	    csi->csi_pending != 0 && !csi_tcall_start(csi))) {
		csi_selwakeup(csi, FALSE, FALSE, 0);
	}
	CSI_UNLOCK(csi);
}

__attribute__((always_inline))
static inline uint64_t
csi_tcall_update_interval(struct ch_selinfo *csi)
{
	uint64_t i = ch_mit_ival;

	/* if global override was adjusted, update local copies */
	if (__improbable(csi->csi_eff_interval != i)) {
		ASSERT(csi->csi_flags & CSI_MITIGATION);
		csi->csi_interval = csi->csi_eff_interval =
		    ((i == 0) ? 0 : MAX(i, CH_MIT_IVAL_MIN));
	}

	return csi->csi_interval;
}

/* return EV_EOF if the channel is defunct */
static inline boolean_t
ch_filt_check_defunct(struct kern_channel *ch, struct knote *kn)
{
	if (__improbable((ch->ch_flags & CHANF_DEFUNCT) != 0)) {
		if (kn) {
			kn->kn_flags |= EV_EOF;
		}
		return TRUE;
	}
	return FALSE;
}

static void
filt_chrwdetach(struct knote *kn, boolean_t write)
{
	struct kern_channel *ch = (struct kern_channel *)kn->kn_hook;
	struct ch_selinfo *csi;
	struct selinfo *si;

	lck_mtx_lock(&ch->ch_lock);
	csi = ch->ch_si[write ? NR_TX : NR_RX];
	si = &csi->csi_si;

	CSI_LOCK(csi);
	SK_DF(SK_VERB_EVENTS, "na \"%s\" (0x%llx) ch 0x%llx kn 0x%llx (%s%s) "
	    "si_flags 0x%x", ch->ch_na->na_name, SK_KVA(ch->ch_na),
	    SK_KVA(ch), SK_KVA(kn), (kn->kn_flags & EV_POLL) ? "poll," : "",
	    write ? "write" : "read", si->si_flags);

	if (KNOTE_DETACH(&si->si_note, kn)) {
		atomic_bitclear_32(&csi->csi_flags, CSI_KNOTE);
	}

	CSI_UNLOCK(csi);
	lck_mtx_unlock(&ch->ch_lock);
}

static void
filt_chrdetach(struct knote *kn)
{
	ASSERT(kn->kn_filter == EVFILT_READ);
	filt_chrwdetach(kn, FALSE);
}

static void
filt_chwdetach(struct knote *kn)
{
	ASSERT(kn->kn_filter == EVFILT_WRITE);
	filt_chrwdetach(kn, TRUE);
}

/*
 * callback from notifies (generated externally).
 * This always marks the knote activated, so always
 * return 1.
 */
static int
filt_chrw(struct knote *kn, long hint, int events)
{
#if SK_LOG
	struct kern_channel *ch = kn->kn_hook;
#else
#pragma unused(kn)
#pragma unused(hint)
#pragma unused(events)
#endif
	SK_DF(SK_VERB_EVENTS, "na \"%s\" (0x%llx) ch 0x%llx "
	    "kn 0x%llx (%s%s) hint 0x%x", ch->ch_na->na_name,
	    SK_KVA(ch->ch_na), SK_KVA(ch), SK_KVA(kn),
	    (kn->kn_flags & EV_POLL) ? "poll," : "",
	    (events == POLLOUT) ?  "write" : "read",
	    (uint32_t)hint);

	/* assume we are ready */
	return 1;
}

static int
filt_chread(struct knote *kn, long hint)
{
	ASSERT(kn->kn_filter == EVFILT_READ);
	/* There is no hint for read/write event */
	if (hint != 0) {
		return 0;
	}
	return filt_chrw(kn, hint, POLLIN);
}

static int
filt_chwrite(struct knote *kn, long hint)
{
	ASSERT(kn->kn_filter == EVFILT_WRITE);
	/* There is no hint for read/write event */
	if (hint != 0) {
		return 0;
	}
	return filt_chrw(kn, hint, POLLOUT);
}

static int
filt_chtouch(struct knote *kn, struct kevent_qos_s *kev, int events)
{
#pragma unused(kev)
	struct kern_channel *ch = kn->kn_hook;
	int ev = kn->kn_filter;
	enum txrx dir = (ev == EVFILT_WRITE) ? NR_TX : NR_RX;
	int event_error = 0;
	int revents;

	/* save off the new input fflags and data */
	kn->kn_sfflags = kev->fflags;
	kn->kn_sdata = kev->data;

	lck_mtx_lock(&ch->ch_lock);
	if (__improbable(ch_filt_check_defunct(ch, kn))) {
		lck_mtx_unlock(&ch->ch_lock);
		return 1;
	}

	/* if a note-specific low watermark is given, validate it */
	if (kn->kn_sfflags & NOTE_LOWAT) {
		struct ch_ev_thresh note_thresh = {
			.cet_unit = (dir == NR_TX) ?
		    ch->ch_info->cinfo_tx_lowat.cet_unit :
		    ch->ch_info->cinfo_rx_lowat.cet_unit,
			.cet_value = (uint32_t)kn->kn_sdata
		};
		if (ch_ev_thresh_validate(ch->ch_na->na_nx, dir,
		    &note_thresh) != 0) {
			SK_ERR("invalid NOTE_LOWAT threshold %u",
			    note_thresh.cet_value);
			knote_set_error(kn, EINVAL);
			lck_mtx_unlock(&ch->ch_lock);
			return 1;
		}
	}

	/* capture new state just so we can return it */
	revents = ch_event(ch, events, NULL, knote_get_kq(kn)->kq_p, NULL, TRUE,
	    &event_error, FALSE);
	lck_mtx_unlock(&ch->ch_lock);

	if (revents & POLLERR) {
		ASSERT(event_error != 0);
		/*
		 * Setting a knote error here will confuse libdispatch, so we
		 * use EV_EOF instead.
		 */
		kn->kn_flags |= EV_EOF;
		return 1;
	} else {
		return (events & revents) != 0;
	}
}

static int
filt_chrtouch(struct knote *kn, struct kevent_qos_s *kev)
{
	ASSERT(kn->kn_filter == EVFILT_READ);

	if (kev->flags & EV_ENABLE) {
		KDBG_DEBUG(KEV_EVTID(BSD_KEVENT_KNOTE_ENABLE),
		    kn->kn_udata, kn->kn_status | (kn->kn_id << 32),
		    kn->kn_filtid, VM_KERNEL_UNSLIDE_OR_PERM(
			    ((struct kern_channel *)kn->kn_hook)->ch_na));
	}

	return filt_chtouch(kn, kev, POLLIN);
}

static int
filt_chwtouch(struct knote *kn, struct kevent_qos_s *kev)
{
	ASSERT(kn->kn_filter == EVFILT_WRITE);
	return filt_chtouch(kn, kev, POLLOUT);
}


/*
 * Called from kevent.  We call ch_event(POLL[IN|OUT]) and
 * return 0/1 accordingly.
 */
static int
filt_chprocess(struct knote *kn, struct kevent_qos_s *kev, int events)
{
	struct kern_channel *ch = kn->kn_hook;
	struct ch_event_result result;
	uint32_t lowat;
	int trigger_event = 1;
	int revents;
	int event_error;
	int64_t data;

	lck_mtx_lock(&ch->ch_lock);
	if (__improbable(ch_filt_check_defunct(ch, kn))) {
		knote_fill_kevent(kn, kev, 0);
		lck_mtx_unlock(&ch->ch_lock);
		return 1;
	}

	revents = ch_event(ch, events, NULL, knote_get_kq(kn)->kq_p, &result,
	    TRUE, &event_error, FALSE);

	if (revents & POLLERR) {
		ASSERT(event_error != 0);
		lck_mtx_unlock(&ch->ch_lock);
		/*
		 * Setting a knote error here will confuse libdispatch, so we
		 * use EV_EOF instead.
		 */
		kn->kn_flags |= EV_EOF;
		knote_fill_kevent_with_sdata(kn, kev);
		return 1;
	}

	trigger_event = (events & revents) != 0;

	if (events == POLLOUT) {
		lowat = ch->ch_info->cinfo_tx_lowat.cet_value;
		if ((kn->kn_sfflags & NOTE_LOWAT) &&
		    kn->kn_sdata > lowat) {
			lowat = (uint32_t)kn->kn_sdata;
		}

		data = result.tx_data;

		if (result.tx_data < lowat) {
			trigger_event = 0;
		}
	} else {
		lowat = ch->ch_info->cinfo_rx_lowat.cet_value;
		if ((kn->kn_sfflags & NOTE_LOWAT) &&
		    kn->kn_sdata > lowat) {
			lowat = (uint32_t)kn->kn_sdata;
		}

		data = result.rx_data;

		if (result.rx_data < lowat) {
			trigger_event = 0;
		}
	}

	if (trigger_event) {
		knote_fill_kevent(kn, kev, data);
	}

	lck_mtx_unlock(&ch->ch_lock);

	return trigger_event;
}

static int
filt_chrprocess(struct knote *kn, struct kevent_qos_s *kev)
{
	ASSERT(kn->kn_filter == EVFILT_READ);
	return filt_chprocess(kn, kev, POLLIN);
}

static int
filt_chwprocess(struct knote *kn, struct kevent_qos_s *kev)
{
	ASSERT(kn->kn_filter == EVFILT_WRITE);
	return filt_chprocess(kn, kev, POLLOUT);
}

static int
filt_chrwattach(struct knote *kn, __unused struct kevent_qos_s *kev)
{
	struct kern_channel *ch = (struct kern_channel *)kn->kn_hook;
	struct nexus_adapter *na;
	struct ch_selinfo *csi;
	int ev = kn->kn_filter;
	enum txrx dir = (ev == EVFILT_WRITE) ? NR_TX : NR_RX;
	int revents;
	int events;
	int event_error = 0;

	ASSERT((kn->kn_filter == EVFILT_READ) ||
	    (kn->kn_filter == EVFILT_WRITE));

	/* ch_kqfilter() should have acquired the lock */
	LCK_MTX_ASSERT(&ch->ch_lock, LCK_MTX_ASSERT_OWNED);

	na = ch->ch_na;
	/* if a note-specific low watermark is given, validate it */
	if (kn->kn_sfflags & NOTE_LOWAT) {
		struct ch_ev_thresh note_thresh = {
			.cet_unit = (dir == NR_TX) ?
		    ch->ch_info->cinfo_tx_lowat.cet_unit :
		    ch->ch_info->cinfo_rx_lowat.cet_unit,
			.cet_value = (uint32_t)kn->kn_sdata
		};
		if (ch_ev_thresh_validate(ch->ch_na->na_nx, dir,
		    &note_thresh) != 0) {
			SK_ERR("invalid NOTE_LOWAT threshold %u",
			    note_thresh.cet_value);
			knote_set_error(kn, EINVAL);
			return 0;
		}
	}

	/* the si is indicated in the channel */
	csi = ch->ch_si[dir];
	CSI_LOCK(csi);

	if (KNOTE_ATTACH(&csi->csi_si.si_note, kn)) {
		atomic_bitset_32(&csi->csi_flags, CSI_KNOTE);
	}

	CSI_UNLOCK(csi);

	SK_DF(SK_VERB_EVENTS, "na \"%s\" (0x%llx) ch 0x%llx kn 0x%llx (%s%s)",
	    na->na_name, SK_KVA(na), SK_KVA(ch), SK_KVA(kn),
	    (kn->kn_flags & EV_POLL) ? "poll," : "",
	    (ev == EVFILT_WRITE) ?  "write" : "read");

	/* capture current state */
	events = (ev == EVFILT_WRITE) ? POLLOUT : POLLIN;

	if (__improbable(ch_filt_check_defunct(ch, kn))) {
		revents = events;
	} else {
		/* filt_chprocess() will fill in the kn_sdata field */
		revents = ch_event(ch, events, NULL, knote_get_kq(kn)->kq_p,
		    NULL, TRUE, &event_error, FALSE);
	}

	if (revents & POLLERR) {
		ASSERT(event_error != 0);
		kn->kn_flags |= EV_EOF;
		return 1;
	} else {
		return (events & revents) != 0;
	}
}

static int
filt_chan_extended_common(struct knote *kn, long ev_hint)
{
	/*
	 * This function is not always called with the same set of locks held,
	 * hence it is only allowed to manipulate kn_fflags, with atomics.
	 *
	 * the f_event / f_process functions may run concurrently.
	 */
	uint32_t add_fflags = 0;

	if ((ev_hint & CHAN_FILT_HINT_FLOW_ADV_UPD) != 0) {
		add_fflags |= NOTE_FLOW_ADV_UPDATE;
	}
	if ((ev_hint & CHAN_FILT_HINT_CHANNEL_EVENT) != 0) {
		add_fflags |= NOTE_CHANNEL_EVENT;
	}
	if ((ev_hint & CHAN_FILT_HINT_IF_ADV_UPD) != 0) {
		add_fflags |= NOTE_IF_ADV_UPD;
	}
	if (add_fflags) {
		/* Reset any events that are not requested on this knote */
		add_fflags &= (kn->kn_sfflags & EVFILT_NW_CHANNEL_ALL_MASK);
		os_atomic_or(&kn->kn_fflags, add_fflags, relaxed);
		return add_fflags != 0;
	}
	return os_atomic_load(&kn->kn_fflags, relaxed) != 0;
}

static inline void
che_process_channel_event(struct kern_channel *ch, struct knote *kn,
    uint32_t fflags, long *hint)
{
	int revents, event_error = 0;

	LCK_MTX_ASSERT(&ch->ch_lock, LCK_MTX_ASSERT_OWNED);
	*hint &= ~CHAN_FILT_HINT_CHANNEL_EVENT;

	if (((ch->ch_flags & CHANF_EVENT_RING) != 0) &&
	    ((fflags & NOTE_CHANNEL_EVENT) != 0)) {
		/* capture new state to return */
		revents = ch_event(ch, POLLIN, NULL, knote_get_kq(kn)->kq_p,
		    NULL, TRUE, &event_error, TRUE);
		if (revents & POLLERR) {
			ASSERT(event_error != 0);
			/*
			 * Setting a knote error here will confuse libdispatch,
			 * so we use EV_EOF instead.
			 */
			kn->kn_flags |= EV_EOF;
		} else if ((revents & POLLIN) != 0) {
			*hint |= CHAN_FILT_HINT_CHANNEL_EVENT;
		}
	}
	/*
	 * if the sync operation on event ring didn't find any events
	 * then indicate that the channel event is not active.
	 */
	if ((*hint & CHAN_FILT_HINT_CHANNEL_EVENT) == 0) {
		/*
		 * Avoid a costly atomic when the bit is already cleared.
		 */
		uint32_t knfflags = os_atomic_load(&kn->kn_fflags, relaxed);
		if (knfflags & CHAN_FILT_HINT_CHANNEL_EVENT) {
			os_atomic_andnot(&kn->kn_fflags,
			    CHAN_FILT_HINT_CHANNEL_EVENT, relaxed);
		}
	}
}

static int
filt_che_attach(struct knote *kn, __unused struct kevent_qos_s *kev)
{
	struct kern_channel *ch = (struct kern_channel *)kn->kn_hook;
	struct ch_selinfo *csi;
	long hint = 0;

	_CASSERT(CHAN_FILT_HINT_FLOW_ADV_UPD == NOTE_FLOW_ADV_UPDATE);
	_CASSERT(CHAN_FILT_HINT_CHANNEL_EVENT == NOTE_CHANNEL_EVENT);
	_CASSERT(CHAN_FILT_HINT_IF_ADV_UPD == NOTE_IF_ADV_UPD);

	ASSERT(kn->kn_filter == EVFILT_NW_CHANNEL);

	/* ch_kqfilter() should have acquired the lock */
	LCK_MTX_ASSERT(&ch->ch_lock, LCK_MTX_ASSERT_OWNED);

	csi = ch->ch_si[NR_TX];
	CSI_LOCK(csi);
	if (KNOTE_ATTACH(&csi->csi_si.si_note, kn)) {
		atomic_bitset_32(&csi->csi_flags, CSI_KNOTE);
	}
	CSI_UNLOCK(csi);

	if (__improbable(ch_filt_check_defunct(ch, kn))) {
		return 1;
	}
	if ((kn->kn_sfflags & NOTE_CHANNEL_EVENT) != 0) {
		atomic_bitset_32(&ch->ch_na->na_flags,
		    NAF_CHANNEL_EVENT_ATTACHED);
	}
	che_process_channel_event(ch, kn, kn->kn_sfflags, &hint);
	if ((kn->kn_sfflags & NOTE_FLOW_ADV_UPDATE) != 0) {
		/* on registration force an event */
		hint |= CHAN_FILT_HINT_FLOW_ADV_UPD;
	}
	SK_DF(SK_VERB_EVENTS, "na \"%s\" (0x%llx) ch 0x%llx kn 0x%llx (%s)",
	    ch->ch_na->na_name, SK_KVA(ch->ch_na), SK_KVA(ch), SK_KVA(kn),
	    "EVFILT_NW_CHANNEL");
	return filt_chan_extended_common(kn, hint);
}

static void
filt_che_detach(struct knote *kn)
{
	struct kern_channel *ch = (struct kern_channel *)kn->kn_hook;
	struct ch_selinfo *csi;

	ASSERT(kn->kn_filter == EVFILT_NW_CHANNEL);

	lck_mtx_lock(&ch->ch_lock);
	if ((kn->kn_sfflags & NOTE_CHANNEL_EVENT) != 0) {
		atomic_bitclear_32(&ch->ch_na->na_flags,
		    NAF_CHANNEL_EVENT_ATTACHED);
	}
	csi = ch->ch_si[NR_TX];
	CSI_LOCK(csi);
	if (KNOTE_DETACH(&csi->csi_si.si_note, kn)) {
		atomic_bitclear_32(&csi->csi_flags, CSI_KNOTE);
	}
	CSI_UNLOCK(csi);
	lck_mtx_unlock(&ch->ch_lock);

	SK_DF(SK_VERB_EVENTS, "na \"%s\" (0x%llx) ch 0x%llx kn 0x%llx (%s)",
	    ch->ch_na->na_name, SK_KVA(ch->ch_na), SK_KVA(ch), SK_KVA(kn),
	    "EVFILT_NW_CHANNEL");
}

static int
filt_che_event(struct knote *kn, long hint)
{
	struct kern_channel *ch = (struct kern_channel *)kn->kn_hook;

	ASSERT(kn->kn_filter == EVFILT_NW_CHANNEL);
	if (hint == 0) {
		return 0;
	}
	if (__improbable(ch_filt_check_defunct(ch, NULL))) {
		return 1;
	}
	if ((hint & CHAN_FILT_HINT_CHANNEL_EVENT) != 0) {
		VERIFY((ch->ch_flags & CHANF_EVENT_RING) != 0);
	}
	SK_DF(SK_VERB_EVENTS, "na \"%s\" (0x%llx) ch 0x%llx hint 0x%b)",
	    ch->ch_na->na_name, SK_KVA(ch->ch_na), SK_KVA(ch), hint,
	    CHAN_FILT_HINT_BITS);
	return filt_chan_extended_common(kn, hint);
}

static int
filt_che_touch(struct knote *kn, struct kevent_qos_s *kev)
{
	int ret;
	long hint = 0;
	struct kern_channel *ch = (struct kern_channel *)kn->kn_hook;

	ASSERT(kn->kn_filter == EVFILT_NW_CHANNEL);
	/* save off the new input fflags and data */
	kn->kn_sfflags = kev->fflags;
	kn->kn_sdata = kev->data;

	lck_mtx_lock(&ch->ch_lock);
	if (__improbable(ch_filt_check_defunct(ch, kn))) {
		ret = 1;
		goto done;
	}
	if ((kn->kn_sfflags & NOTE_CHANNEL_EVENT) != 0) {
		if (kev->flags & EV_ENABLE) {
			atomic_bitset_32(&ch->ch_na->na_flags,
			    NAF_CHANNEL_EVENT_ATTACHED);
		} else if (kev->flags & EV_DISABLE) {
			atomic_bitclear_32(&ch->ch_na->na_flags,
			    NAF_CHANNEL_EVENT_ATTACHED);
		}
	}
	che_process_channel_event(ch, kn, kn->kn_sfflags, &hint);
	ret = filt_chan_extended_common(kn, hint);
done:
	lck_mtx_unlock(&ch->ch_lock);
	return ret;
}

static int
filt_che_process(struct knote *kn, struct kevent_qos_s *kev)
{
	int ret;
	long hint = 0;
	struct kern_channel *ch = kn->kn_hook;

	ASSERT(kn->kn_filter == EVFILT_NW_CHANNEL);
	lck_mtx_lock(&ch->ch_lock);
	if (__improbable(ch_filt_check_defunct(ch, kn))) {
		ret = 1;
		goto done;
	}
	che_process_channel_event(ch, kn, kn->kn_sfflags, &hint);
	ret = filt_chan_extended_common(kn, hint);
done:
	lck_mtx_unlock(&ch->ch_lock);
	if (ret != 0) {
		/*
		 * This filter historically behaves like EV_CLEAR,
		 * even when EV_CLEAR wasn't set.
		 */
		knote_fill_kevent(kn, kev, 0);
		kn->kn_fflags = 0;
	}
	return ret;
}

int
ch_kqfilter(struct kern_channel *ch, struct knote *kn,
    struct kevent_qos_s *kev)
{
	int result;

	lck_mtx_lock(&ch->ch_lock);
	VERIFY(!(ch->ch_flags & CHANF_KERNEL));

	if (__improbable(ch->ch_na == NULL || !NA_IS_ACTIVE(ch->ch_na) ||
	    na_reject_channel(ch, ch->ch_na))) {
		SK_ERR("%s(%d): channel is non-permissive, flags 0x%b", ch->ch_name,
		    ch->ch_pid, ch->ch_flags, CHANF_BITS);
		knote_set_error(kn, ENXIO);
		lck_mtx_unlock(&ch->ch_lock);
		return 0;
	}

	switch (kn->kn_filter) {
	case EVFILT_READ:
		kn->kn_filtid = EVFILTID_SKYWALK_CHANNEL_R;
		break;

	case EVFILT_WRITE:
		kn->kn_filtid = EVFILTID_SKYWALK_CHANNEL_W;
		break;

	case EVFILT_NW_CHANNEL:
		kn->kn_filtid = EVFILTID_SKYWALK_CHANNEL_E;
		break;

	default:
		lck_mtx_unlock(&ch->ch_lock);
		SK_ERR("%s(%d): bad filter request %d", ch->ch_name,
		    ch->ch_pid, kn->kn_filter);
		knote_set_error(kn, EINVAL);
		return 0;
	}

	kn->kn_hook = ch;
	/* call the appropriate sub-filter attach with the channel lock held */
	result = knote_fops(kn)->f_attach(kn, kev);
	lck_mtx_unlock(&ch->ch_lock);
	return result;
}

boolean_t
ch_is_multiplex(struct kern_channel *ch, enum txrx t)
{
	return ch->ch_na != NULL && (ch->ch_last[t] - ch->ch_first[t] > 1);
}

int
ch_select(struct kern_channel *ch, int events, void *wql, struct proc *p)
{
	int revents;
	int event_error = 0;

	lck_mtx_lock(&ch->ch_lock);
	revents = ch_event(ch, events, wql, p, NULL, FALSE, &event_error,
	    FALSE);
	lck_mtx_unlock(&ch->ch_lock);

	ASSERT((revents & POLLERR) == 0 || event_error != 0);

	return revents;
}

#if SK_LOG
/* Hoisted out of line to reduce kernel stack footprint */
SK_LOG_ATTRIBUTE
static void
ch_event_log(const char *prefix, const struct kern_channel *ch,
    struct proc *p, const struct nexus_adapter *na,
    int events, int revents)
{
	SK_DF(SK_VERB_EVENTS, "%s: na \"%s\" (0x%llx) ch 0x%llx %s(%d) "
	    "th 0x%llx ev 0x%x rev 0x%x", prefix, na->na_name, SK_KVA(na),
	    SK_KVA(ch), sk_proc_name_address(p), sk_proc_pid(p),
	    SK_KVA(current_thread()), events, revents);
}
#endif /* SK_LOG */

/*
 * select(2), poll(2) and kevent(2) handlers for channels.
 *
 * Can be called for one or more rings.  Return true the event mask
 * corresponding to ready events.  If there are no ready events, do
 * a selrecord on either individual selinfo or on the global one.
 * Device-dependent parts (locking and sync of tx/rx rings)
 * are done through callbacks.
 */
static int
ch_event(struct kern_channel *ch, int events, void *wql,
    struct proc *p, struct ch_event_result *result,
    const boolean_t is_kevent, int *errno, const boolean_t is_ch_event)
{
	struct nexus_adapter *na;
	struct __kern_channel_ring *kring;
	uint32_t i, check_all_tx, check_all_rx, want[NR_TXRX], revents = 0;
	uint32_t ready_tx_data = 0, ready_rx_data = 0;
	sk_protect_t protect = NULL;

#define want_tx want[NR_TX]
#define want_rx want[NR_RX]
	/*
	 * In order to avoid nested locks, we need to "double check"
	 * txsync and rxsync if we decide to do a selrecord().
	 * retry_tx (and retry_rx, later) prevent looping forever.
	 */
	boolean_t retry_tx = TRUE, retry_rx = TRUE;
	int found, error = 0;
	int s;

	net_update_uptime();

	LCK_MTX_ASSERT(&ch->ch_lock, LCK_MTX_ASSERT_OWNED);
	ASSERT(!(ch->ch_flags & CHANF_KERNEL));

	*errno = 0;

	if (__improbable((ch->ch_flags & CHANF_DEFUNCT) ||
	    ch->ch_schema == NULL)) {
		SK_ERR("%s(%d): channel is defunct or no longer bound",
		    ch->ch_name, ch->ch_pid);
		revents = POLLERR;
		*errno = ENXIO;
		goto done;
	}

	/* clear CHANF_DEFUNCT_SKIP if it was set during defunct last time */
	if (__improbable(ch->ch_flags & CHANF_DEFUNCT_SKIP)) {
		atomic_bitclear_32(&ch->ch_flags, CHANF_DEFUNCT_SKIP);
	}

	na = ch->ch_na;
	if (__improbable(na == NULL ||
	    !NA_IS_ACTIVE(na) || na_reject_channel(ch, na))) {
		SK_ERR("%s(%d): channel is non-permissive",
		    ch->ch_name, ch->ch_pid);
		revents = POLLERR;
		*errno = ENXIO;
		goto done;
	}

	/* mark thread with sync-in-progress flag */
	protect = sk_sync_protect();

	/* update our work timestamp */
	na->na_work_ts = _net_uptime;

	/* and make this channel eligible for draining again */
	if (na->na_flags & NAF_DRAINING) {
		atomic_bitclear_32(&na->na_flags, NAF_DRAINING);
	}

#if SK_LOG
	if (__improbable((sk_verbose & SK_VERB_EVENTS) != 0)) {
		ch_event_log("enter", ch, p, na, events, revents);
	}
#endif
	if (is_ch_event) {
		goto process_channel_event;
	}

	want_tx = (events & (POLLOUT | POLLWRNORM));
	want_rx = (events & (POLLIN | POLLRDNORM));

	/*
	 * check_all_{tx|rx} are set if the channel has more than one ring
	 * AND the file descriptor is bound to all of them.  If so, we sleep
	 * on the "global" selinfo, otherwise we sleep on individual selinfo
	 * The interrupt routine in the driver wake one or the other (or both)
	 * depending on which clients are active.
	 *
	 * rxsync() is only called if we run out of buffers on a POLLIN.
	 * txsync() is called if we run out of buffers on POLLOUT.
	 */
	check_all_tx = ch_is_multiplex(ch, NR_TX);
	check_all_rx = ch_is_multiplex(ch, NR_RX);

	/*
	 * If want_tx is still set, we must issue txsync calls
	 * (on all rings, to avoid that the tx rings stall).
	 * XXX should also check head != khead on the tx rings.
	 */
	if (want_tx) {
		ring_id_t first_tx = ch->ch_first[NR_TX];
		ring_id_t last_tx = ch->ch_last[NR_TX];

		channel_threshold_unit_t tx_unit =
		    ch->ch_info->cinfo_tx_lowat.cet_unit;

		/*
		 * The first round checks if anyone is ready, if not
		 * do a selrecord and another round to handle races.
		 * want_tx goes to 0 if any space is found, and is
		 * used to skip rings with no pending transmissions.
		 */
flush_tx:
		for (i = first_tx, ready_tx_data = 0; i < last_tx; i++) {
			kring = &na->na_tx_rings[i];
			if (!want_tx &&
			    kring->ckr_ring->ring_head == kring->ckr_khead) {
				continue;
			}

			/* only one thread does txsync */
			s = kr_enter(kring, TRUE);
			ASSERT(s == 0);

			error = 0;
			DTRACE_SKYWALK2(pretxprologue, struct kern_channel *,
			    ch, struct __kern_channel_ring *, kring);
			if (kr_txsync_prologue(ch, kring, p) >=
			    kring->ckr_num_slots) {
				kr_log_bad_ring(kring);
				revents |= POLLERR;
				error = EFAULT;
				if (*errno == 0) {
					*errno = EFAULT;
				}
			} else {
				if (kring->ckr_na_sync(kring, p, 0)) {
					revents |= POLLERR;
					error = EIO;
					if (*errno == 0) {
						*errno = EIO;
					}
				} else {
					kr_txsync_finalize(ch, kring, p);
				}
			}
			DTRACE_SKYWALK3(posttxfinalize, struct kern_channel *,
			    ch, struct __kern_channel_ring *, kring, int,
			    error);

			/*
			 * If we found new slots, notify potential listeners on
			 * the same ring. Since we just did a txsync, look at
			 * the copies of cur,tail in the kring.
			 */
			found = kring->ckr_rhead != kring->ckr_rtail;
			kr_exit(kring);
			if (found) { /* notify other listeners */
				revents |= want_tx;
				want_tx = 0;
				(void) kring->ckr_na_notify(kring, p,
				    (is_kevent ? NA_NOTEF_IN_KEVENT : 0));
			}

			/*
			 * Add this ring's free data to our running
			 * tally for userspace.
			 */
			if (result != NULL) {
				switch (tx_unit) {
				case CHANNEL_THRESHOLD_UNIT_BYTES:
					ready_tx_data += kring->ckr_ready_bytes;
					break;
				case CHANNEL_THRESHOLD_UNIT_SLOTS:
					ready_tx_data += kring->ckr_ready_slots;
					break;
				}
			}
		}
		if (want_tx && retry_tx && !is_kevent) {
			if (check_all_tx) {
				csi_selrecord_all(na, NR_TX, p, wql);
			} else {
				csi_selrecord_one(&na->na_tx_rings[first_tx],
				    p, wql);
			}
			retry_tx = FALSE;
			goto flush_tx;
		}
	}

	/*
	 * If want_rx is still set scan receive rings.
	 * Do it on all rings because otherwise we starve.
	 */
	if (want_rx) {
		ring_id_t first_rx = ch->ch_first[NR_RX];
		ring_id_t last_rx = ch->ch_last[NR_RX];
		channel_threshold_unit_t rx_unit =
		    ch->ch_info->cinfo_rx_lowat.cet_unit;

		/* two rounds here for race avoidance */
do_retry_rx:
		for (i = first_rx, ready_rx_data = 0; i < last_rx; i++) {
			kring = &na->na_rx_rings[i];

			/* only one thread does rxsync */
			s = kr_enter(kring, TRUE);
			ASSERT(s == 0);

			error = 0;
			DTRACE_SKYWALK2(prerxprologue, struct kern_channel *,
			    ch, struct __kern_channel_ring *, kring);
			if (kr_rxsync_prologue(ch, kring, p) >=
			    kring->ckr_num_slots) {
				kr_log_bad_ring(kring);
				revents |= POLLERR;
				error = EFAULT;
				if (*errno == 0) {
					*errno = EFAULT;
				}
			} else {
				/* now we can use kring->rhead, rtail */
				if (kring->ckr_na_sync(kring, p, 0)) {
					revents |= POLLERR;
					error = EIO;
					if (*errno == 0) {
						*errno = EIO;
					}
				} else {
					kr_rxsync_finalize(ch, kring, p);
				}
			}

			DTRACE_SKYWALK3(postrxfinalize, struct kern_channel *,
			    ch, struct __kern_channel_ring *, kring, int,
			    error);

			found = kring->ckr_rhead != kring->ckr_rtail;
			kr_exit(kring);
			if (found) {
				revents |= want_rx;
				retry_rx = FALSE;
				(void) kring->ckr_na_notify(kring, p,
				    (is_kevent ? NA_NOTEF_IN_KEVENT : 0));
			}

			/*
			 * Add this ring's readable data to our running
			 * tally for userspace.
			 */
			if (result != NULL) {
				switch (rx_unit) {
				case CHANNEL_THRESHOLD_UNIT_BYTES:
					ready_rx_data += kring->ckr_ready_bytes;
					break;
				case CHANNEL_THRESHOLD_UNIT_SLOTS:
					ready_rx_data += kring->ckr_ready_slots;
					break;
				}
			}
		}

		if (retry_rx && !is_kevent) {
			if (check_all_rx) {
				csi_selrecord_all(na, NR_RX, p, wql);
			} else {
				csi_selrecord_one(&na->na_rx_rings[first_rx],
				    p, wql);
			}
		}
		if (retry_rx) {
			retry_rx = FALSE;
			goto do_retry_rx;
		}
	}

	if (result != NULL) {
		result->tx_data = ready_tx_data;
		result->rx_data = ready_rx_data;
	}
	goto skip_channel_event;

process_channel_event:
	/*
	 * perform sync operation on the event ring to make the channel
	 * events enqueued in the ring visible to user-space.
	 */

	/* select() and poll() not supported for event ring */
	ASSERT(is_kevent);
	VERIFY((ch->ch_last[NR_EV] - ch->ch_first[NR_EV]) == 1);
	kring = &na->na_event_rings[ch->ch_first[NR_EV]];

	/* only one thread does the sync */
	s = kr_enter(kring, TRUE);
	ASSERT(s == 0);
	if (kr_event_sync_prologue(kring, p) >= kring->ckr_num_slots) {
		kr_log_bad_ring(kring);
		revents |= POLLERR;
		if (*errno == 0) {
			*errno = EFAULT;
		}
	} else {
		if (kring->ckr_na_sync(kring, p, 0)) {
			revents |= POLLERR;
			if (*errno == 0) {
				*errno = EIO;
			}
		} else {
			kr_event_sync_finalize(ch, kring, p);
		}
	}
	found = (kring->ckr_rhead != kring->ckr_rtail);
	kr_exit(kring);
	if (found) {
		revents |= (events & POLLIN);
	}

skip_channel_event:
#if SK_LOG
	if (__improbable((sk_verbose & SK_VERB_EVENTS) != 0)) {
		ch_event_log("exit", ch, p, na, events, revents);
	}
#endif /* SK_LOG */

	/* unmark thread with sync-in-progress flag */
	sk_sync_unprotect(protect);

done:
	ASSERT(!sk_is_sync_protected());

	return revents;
#undef want_tx
#undef want_rx
}

static struct kern_channel *
ch_find(struct kern_nexus *nx, nexus_port_t port, ring_id_t ring_id)
{
	struct kern_channel *ch;

	SK_LOCK_ASSERT_HELD();

	STAILQ_FOREACH(ch, &nx->nx_ch_head, ch_link) {
		struct ch_info *cinfo = ch->ch_info;

		/* see comments in ch_open() */
		if (cinfo->cinfo_nx_port != port) {
			continue;
		} else if (cinfo->cinfo_ch_mode & CHMODE_MONITOR) {
			continue;
		} else if (cinfo->cinfo_ch_ring_id != CHANNEL_RING_ID_ANY &&
		    ring_id != cinfo->cinfo_ch_ring_id &&
		    ring_id != CHANNEL_RING_ID_ANY) {
			continue;
		}

		/* found a match */
		break;
	}

	if (ch != NULL) {
		ch_retain_locked(ch);
	}

	return ch;
}

#if SK_LOG
/* Hoisted out of line to reduce kernel stack footprint */
SK_LOG_ATTRIBUTE
static void
ch_open_log1(const uuid_t p_uuid, struct proc *p, nexus_port_t port)
{
	uuid_string_t uuidstr;

	SK_D("%s(%d) uniqueid %llu exec_uuid %s port %u",
	    sk_proc_name_address(p), sk_proc_pid(p), proc_uniqueid(p),
	    sk_uuid_unparse(p_uuid, uuidstr), port);
}

SK_LOG_ATTRIBUTE
static void
ch_open_log2(struct proc *p, nexus_port_t port, ring_id_t ring,
    uint32_t mode, const char *mode_bits, int err)
{
	SK_D("%s(%d) port %u ring %d mode 0x%b err %d",
	    sk_proc_name_address(p), sk_proc_pid(p), port, (int)ring,
	    mode, mode_bits, err);
}
#endif /* SK_LOG */

struct kern_channel *
ch_open(struct ch_init *init, struct proc *p, int fd, int *err)
{
	uint32_t mode = init->ci_ch_mode;
	nexus_port_t port = init->ci_nx_port;
	ring_id_t ring = init->ci_ch_ring_id;
	struct kern_channel *ch = NULL, *ch0 = NULL;
	struct nxbind *nxb = NULL;
	struct kern_nexus *nx;
	struct chreq chr;
	uuid_t p_uuid;
	kauth_cred_t cred;

	cred = kauth_cred_get();
	ASSERT(!uuid_is_null(init->ci_nx_uuid));
	proc_getexecutableuuid(p, p_uuid, sizeof(p_uuid));
	*err = 0;

	/* make sure we don't allow userland to set kernel-only flags */
	mode &= CHMODE_MASK;

	SK_LOCK();

	nx = nx_find(init->ci_nx_uuid, TRUE);
	if (nx == NULL) {
		*err = ENOENT;
		goto done;
	}

	/* port (zero-based) must be within the domain's range */
	if (port >= NXDOM_MAX(NX_DOM(nx), ports)) {
		*err = EDOM;
		goto done;
	}
	VERIFY(port != NEXUS_PORT_ANY);

	if (mode & CHMODE_LOW_LATENCY) {
		if ((*err = skywalk_priv_check_cred(p, cred,
		    PRIV_SKYWALK_LOW_LATENCY_CHANNEL)) != 0) {
			goto done;
		}
	}

	/* "no copy" is valid only when at least one tx/rx mon flag is set */
	if (!(mode & CHMODE_MONITOR) && (mode & CHMODE_MONITOR_NO_COPY)) {
		mode &= ~CHMODE_MONITOR_NO_COPY;
	}

	if (mode & CHMODE_MONITOR) {
		if ((*err = skywalk_priv_check_cred(p, cred,
		    PRIV_SKYWALK_OBSERVE_ALL)) != 0) {
			goto done;
		}
		/* Don't allow non-root processes to monitor channels. */
		if (kauth_cred_issuser(cred) == 0) {
			*err = EPERM;
			goto done;
		}
	}

	/*
	 * Check with the nexus to see if the port is bound; if so, prepare
	 * our nxbind structure that we'll need to pass down to the nexus
	 * for it compare.  If the caller provides a key, we take it over
	 * and will free it ourselves (as part of freeing nxbind.)
	 *
	 * If this is a monitor channel, skip this altogether since the check
	 * for PRIV_SKYWALK_OBSERVE_ALL privilege has been done above.
	 */
	if (!(mode & CHMODE_MONITOR) && !NX_ANONYMOUS_PROV(nx)) {
		void *key = (void *)(init->ci_key);

#if SK_LOG
		if (__improbable(sk_verbose != 0)) {
			ch_open_log1(p_uuid, p, port);
		}
#endif /* SK_LOG */

		nxb = nxb_alloc(Z_WAITOK);
		nxb->nxb_flags |= NXBF_MATCH_UNIQUEID;
		nxb->nxb_uniqueid = proc_uniqueid(p);
		nxb->nxb_pid = proc_pid(p);
		nxb->nxb_flags |= NXBF_MATCH_EXEC_UUID;
		uuid_copy(nxb->nxb_exec_uuid, p_uuid);
		if (key != NULL) {
			nxb->nxb_flags |= NXBF_MATCH_KEY;
			nxb->nxb_key_len = init->ci_key_len;
			nxb->nxb_key = key;
			init->ci_key = USER_ADDR_NULL;  /* take over */
		}
	}

	/*
	 * There can only be one owner of {port,ring_id} tuple.  Once
	 * owned, this can be made available among multiple monitors.
	 * CHANNEL_RING_ID_ANY (-1) ring_id gives exclusive rights over
	 * all rings.  Further attempts to own any or all of the rings
	 * will be declined.
	 *
	 * Multiple monitors are allowed to exist.  If a channel has been
	 * bound to CHANNEL_RING_ID_ANY, any or all of its rings can be
	 * monitored.  If an owning channel has been bound to an individual
	 * ring, only that ring can be monitored, either by specifying the
	 * equivalent ring_id or CHANNEL_RING_ID_ANY at monitor open time.
	 *
	 * For example, assuming a 2-rings setup for port 'p':
	 *
	 * owner{p,-1}
	 *      will allow:
	 *              monitor{p,-1}, monitor{p,0}, monitor{p,1}
	 *      will not allow:
	 *              owner{p,-1}, owner{p,0}, owner{p,1}
	 *
	 * owner{p,0}
	 *      will allow:
	 *		owner{p,1}, monitor{p,-1}, monitor{p,0}
	 *	will not allow:
	 *		owner{p,-1}, owner{p,0}, monitor{p,1}
	 */
	if ((ch0 = ch_find(nx, port, ring)) != NULL) {
		SK_D("found ch0 0x%llx", SK_KVA(ch0));
		/*
		 * Unless this is a monitor channel, allow only at
		 * most one owner of the {port,ring_id} tuple.
		 */
		if (!(mode & CHMODE_MONITOR)) {
#if SK_LOG
			uuid_string_t uuidstr;
			char *na_name = (ch0->ch_na != NULL) ?
			    ch0->ch_na->na_name : "";

			SK_DSC(p, "ch %s flags (0x%x) exists on port %d on "
			    "nx %s, owner %s(%d)", na_name, ch0->ch_flags, port,
			    sk_uuid_unparse(nx->nx_uuid, uuidstr),
			    ch0->ch_name, ch0->ch_pid);
#endif /* SK_LOG */
			*err = EBUSY;
			goto done;
		}
	} else if (mode & CHMODE_MONITOR) {
		*err = ENXIO;
		goto done;
	}

	bzero(&chr, sizeof(chr));
	chr.cr_tx_lowat = init->ci_tx_lowat;
	chr.cr_rx_lowat = init->ci_rx_lowat;
	chr.cr_port = port;
	chr.cr_mode = mode;
	chr.cr_ring_id = ring;

	/* upon success, returns a channel with reference held */
	ch = ch_connect(nx, &chr, ch0, nxb, p, fd, err);

done:

#if SK_LOG
	if (__improbable(sk_verbose != 0)) {
		ch_open_log2(p, port, ring, mode, CHMODE_BITS, *err);
	}
#endif /* SK_LOG */

	if (ch0 != NULL) {
		(void) ch_release_locked(ch0);
	}

	if (nx != NULL) {
		(void) nx_release_locked(nx);
	}

	if (nxb != NULL) {
		nxb_free(nxb);
	}

	SK_UNLOCK();

	return ch;
}

struct kern_channel *
ch_open_special(struct kern_nexus *nx, struct chreq *chr, boolean_t nonxref,
    int *err)
{
	struct kern_channel *ch = NULL;

	SK_LOCK_ASSERT_HELD();
	*err = 0;

	ASSERT((chr->cr_mode & CHMODE_USER_PACKET_POOL) == 0);
	ASSERT((chr->cr_mode & CHMODE_EVENT_RING) == 0);
	ASSERT((chr->cr_mode & CHMODE_LOW_LATENCY) == 0);
	ASSERT(!uuid_is_null(chr->cr_spec_uuid));
	chr->cr_mode |= CHMODE_KERNEL;
	if (nonxref) {
		chr->cr_mode |= CHMODE_NO_NXREF;
	} else {
		chr->cr_mode &= ~CHMODE_NO_NXREF;
	}

	/* upon success, returns a channel with reference held */
	ch = ch_connect(nx, chr, NULL, NULL, kernproc, -1, err);
	if (ch != NULL) {
		/*
		 * nonxref channels don't hold any reference to the nexus,
		 * since otherwise we'll never be able to close them when
		 * the last regular channel of the nexus is closed, as part
		 * of the nexus's destructor operation.  Release the nonxref
		 * channel reference now, but make sure the nexus has at
		 * least 3 refs: global list, provider list and the nonxref
		 * channel itself, before doing that.
		 */
		if (nonxref) {
			ASSERT(ch->ch_flags & (CHANF_KERNEL | CHANF_NONXREF));
			ASSERT(nx->nx_refcnt > 3);
			(void) nx_release_locked(nx);
		}
	}

#if SK_LOG
	uuid_string_t uuidstr;
	SK_D("nx 0x%llx (%s:\"%s\":%d:%d) spec_uuid \"%s\" mode 0x%b err %d",
	    SK_KVA(nx), NX_DOM_PROV(nx)->nxdom_prov_name, (ch != NULL ?
	    ch->ch_na->na_name : ""), (int)chr->cr_port, (int)chr->cr_ring_id,
	    sk_uuid_unparse(chr->cr_spec_uuid, uuidstr), chr->cr_mode,
	    CHMODE_BITS, *err);
#endif /* SK_LOG */

	return ch;
}

static void
ch_close_common(struct kern_channel *ch, boolean_t locked, boolean_t special)
{
#pragma unused(special)
#if SK_LOG
	uuid_string_t uuidstr;
	const char *na_name = (ch->ch_na != NULL) ?
	    ch->ch_na->na_name : "";
	const char *nxdom_name = (ch->ch_nexus != NULL) ?
	    NX_DOM(ch->ch_nexus)->nxdom_name : "";
	const char *nxdom_prov_name = (ch->ch_nexus != NULL) ?
	    NX_DOM_PROV(ch->ch_nexus)->nxdom_prov_name : "";

	SK_D("ch 0x%llx (%s:%s:\"%s\":%u:%d)",
	    SK_KVA(ch), nxdom_name, nxdom_prov_name, na_name,
	    ch->ch_info->cinfo_nx_port, (int)ch->ch_info->cinfo_ch_ring_id);
	SK_D("  UUID:    %s", sk_uuid_unparse(ch->ch_info->cinfo_ch_id,
	    uuidstr));
	SK_D("  flags:   0x%b", ch->ch_flags, CHANF_BITS);
#endif /* SK_LOG */
	struct kern_nexus *nx = ch->ch_nexus;

	if (!locked) {
		SK_LOCK();
	}

	SK_LOCK_ASSERT_HELD();
	/*
	 * If the channel is participating in the interface advisory
	 * notification, remove it from the nexus.
	 * CHANF_IF_ADV is set and cleared only when nx_ch_if_adv_lock
	 * is held in exclusive mode.
	 */
	lck_rw_lock_exclusive(&nx->nx_ch_if_adv_lock);
	if ((ch->ch_flags & CHANF_IF_ADV) != 0) {
		STAILQ_REMOVE(&nx->nx_ch_if_adv_head, ch,
		    kern_channel, ch_link_if_adv);
		atomic_bitclear_32(&ch->ch_flags, CHANF_IF_ADV);
		if (STAILQ_EMPTY(&nx->nx_ch_if_adv_head)) {
			nx_netif_config_interface_advisory(nx, false);
		}
		lck_rw_done(&nx->nx_ch_if_adv_lock);
		lck_mtx_lock(&ch->ch_lock);
		(void) ch_release_locked(ch);
	} else {
		lck_rw_done(&nx->nx_ch_if_adv_lock);
		lck_mtx_lock(&ch->ch_lock);
	}
	LCK_MTX_ASSERT(&ch->ch_lock, LCK_MTX_ASSERT_OWNED);
	/*
	 * Mark the channel as closing to prevent further setopt requests;
	 * this flag is set once here and never gets cleared.
	 */
	ASSERT(!(ch->ch_flags & CHANF_CLOSING));
	atomic_bitset_32(&ch->ch_flags, CHANF_CLOSING);

	if (special) {
		VERIFY(ch->ch_flags & CHANF_KERNEL);
	} else {
		VERIFY(!(ch->ch_flags & CHANF_KERNEL));
	}

	ch->ch_fd = -1;

	/* may be called as part of failure cleanup, so check */
	if (ch->ch_flags & CHANF_ATTACHED) {
		boolean_t nonxref = !!(ch->ch_flags & CHANF_NONXREF);

		/* caller must hold an extra ref */
		ASSERT(ch->ch_refcnt > 1);

		/* disconnect from nexus */
		ch_disconnect(ch);

		/*
		 * If this was the last regular channel and the nexus
		 * has been closed, detach it and finish up the job.
		 * If this was a nonxref channel, there is nothing
		 * left to do; see comments in ch_open_special().
		 */
		if (!nonxref) {
			STAILQ_REMOVE(&nx->nx_ch_head, ch,
			    kern_channel, ch_link);
			nx->nx_ch_count--;
			if (STAILQ_EMPTY(&nx->nx_ch_head) &&
			    (nx->nx_flags & NXF_CLOSED)) {
				ASSERT(STAILQ_EMPTY(&nx->nx_ch_if_adv_head));
				nx_detach(nx);
			}
			(void) nx_release_locked(nx);
		} else {
			ASSERT(ch->ch_flags & CHANF_KERNEL);
			STAILQ_REMOVE(&nx->nx_ch_nonxref_head, ch,
			    kern_channel, ch_link);
		}

		atomic_bitclear_32(&ch->ch_flags, CHANF_ATTACHED);
		ch->ch_nexus = NULL;

		(void) ch_release_locked(ch);   /* for the list */
	}

	lck_mtx_unlock(&ch->ch_lock);
	if (!locked) {
		SK_UNLOCK();
	}
}

void
ch_close(struct kern_channel *ch, boolean_t locked)
{
	ch_close_common(ch, locked, FALSE);
}

void
ch_close_special(struct kern_channel *ch)
{
	ch_close_common(ch, TRUE, TRUE);
}

static int
ch_ev_thresh_validate(struct kern_nexus *nx, enum txrx t,
    struct ch_ev_thresh *cet)
{
	struct nxprov_params *nxp = NX_PROV(nx)->nxprov_params;
	uint32_t bmin, bmax, smin, smax;
	int err = 0;

	if (cet->cet_unit != CHANNEL_THRESHOLD_UNIT_BYTES &&
	    cet->cet_unit != CHANNEL_THRESHOLD_UNIT_SLOTS) {
		err = EINVAL;
		goto done;
	}

	smin = 1;       /* minimum 1 slot */
	bmin = 1;       /* minimum 1 byte */

	if (t == NR_TX) {
		ASSERT(nxp->nxp_tx_slots > 0);
		smax = (nxp->nxp_tx_slots - 1);
	} else {
		ASSERT(nxp->nxp_rx_slots > 0);
		smax = (nxp->nxp_rx_slots - 1);
	}
	bmax = (smax * nxp->nxp_buf_size);

	switch (cet->cet_unit) {
	case CHANNEL_THRESHOLD_UNIT_BYTES:
		if (cet->cet_value < bmin) {
			cet->cet_value = bmin;
		} else if (cet->cet_value > bmax) {
			cet->cet_value = bmax;
		}
		break;

	case CHANNEL_THRESHOLD_UNIT_SLOTS:
		if (cet->cet_value < smin) {
			cet->cet_value = smin;
		} else if (cet->cet_value > smax) {
			cet->cet_value = smax;
		}
		break;
	}

done:
	return err;
}

#if SK_LOG
/* Hoisted out of line to reduce kernel stack footprint */
SK_LOG_ATTRIBUTE
static void
ch_connect_log1(const struct kern_nexus *nx, const struct ch_info *cinfo,
    const struct chreq *chr, const struct kern_channel *ch,
    const struct kern_nexus_domain_provider *nxdom_prov,
    struct proc *p)
{
	struct __user_channel_schema *ch_schema = ch->ch_schema;
	uuid_string_t uuidstr;
	unsigned int n;
	ring_id_t i, j;

	ASSERT(ch_schema != NULL || (ch->ch_flags & CHANF_KERNEL));
	if (ch_schema != NULL) {
		SK_D("channel_schema at 0x%llx", SK_KVA(ch_schema));
		SK_D("  kern_name:     \"%s\"", ch_schema->csm_kern_name);
		SK_D("  kern_uuid:     %s",
		    sk_uuid_unparse(ch_schema->csm_kern_uuid, uuidstr));
		SK_D("  flags:         0x%b", ch_schema->csm_flags, CSM_BITS);
		SK_D("  tx_rings:      %u [%u,%u]", ch_schema->csm_tx_rings,
		    cinfo->cinfo_first_tx_ring, cinfo->cinfo_last_tx_ring);
		SK_D("  rx_rings:      %u [%u,%u]", ch_schema->csm_rx_rings,
		    cinfo->cinfo_first_rx_ring, cinfo->cinfo_last_rx_ring);

		j = ch->ch_last[NR_TX];
		for (n = 0, i = ch->ch_first[NR_TX]; i < j; n++, i++) {
			SK_D("  tx_ring_%u_off: 0x%llx", i,
			    (uint64_t)ch_schema->csm_ring_ofs[n].ring_off);
			SK_D("  tx_sd_%u_off:   0x%llx", i,
			    (uint64_t)ch_schema->csm_ring_ofs[n].sd_off);
		}
		j = n;
		for (n = 0, i = ch->ch_first[NR_RX];
		    i < ch->ch_last[NR_RX]; n++, i++) {
			SK_D("  rx_ring_%u_off: 0x%llx", i,
			    (uint64_t)ch_schema->csm_ring_ofs[n + j].ring_off);
			SK_D("  rx_sd_%u_off:   0x%llx", i,
			    (uint64_t)ch_schema->csm_ring_ofs[n + j].sd_off);
		}
		SK_D("  md_type:       %u", ch_schema->csm_md_type);
		SK_D("  md_subtype:    %u", ch_schema->csm_md_subtype);
		SK_D("  stats_ofs:     0x%llx", ch_schema->csm_stats_ofs);
		SK_D("  stats_type:    %u", ch_schema->csm_stats_type);
		SK_D("  flowadv_ofs:   0x%llx", ch_schema->csm_flowadv_ofs);
		SK_D("  flowadv_max:   %u", ch_schema->csm_flowadv_max);
		SK_D("  nexusadv_ofs:  0x%llx", ch_schema->csm_nexusadv_ofs);
	}

	SK_D("ch 0x%llx (%s:%s:\"%s\":%u:%d)",
	    SK_KVA(ch), nxdom_prov->nxdom_prov_dom->nxdom_name,
	    nxdom_prov->nxdom_prov_name, ch->ch_na->na_name,
	    cinfo->cinfo_nx_port, (int)cinfo->cinfo_ch_ring_id);
	SK_D("  ch UUID: %s", sk_uuid_unparse(cinfo->cinfo_ch_id, uuidstr));
	SK_D("  nx UUID: %s", sk_uuid_unparse(nx->nx_uuid, uuidstr));
	SK_D("  flags:   0x%b", ch->ch_flags, CHANF_BITS);
	SK_D("  task:    0x%llx %s(%d)", SK_KVA(ch->ch_mmap.ami_maptask),
	    sk_proc_name_address(p), sk_proc_pid(p));
	SK_D("  txlowat: %u (%s)", cinfo->cinfo_tx_lowat.cet_value,
	    ((cinfo->cinfo_tx_lowat.cet_unit == CHANNEL_THRESHOLD_UNIT_BYTES) ?
	    "bytes" : "slots"));
	SK_D("  rxlowat: %u (%s)", cinfo->cinfo_rx_lowat.cet_value,
	    ((cinfo->cinfo_rx_lowat.cet_unit == CHANNEL_THRESHOLD_UNIT_BYTES) ?
	    "bytes" : "slots"));
	SK_D("  mmapref: 0x%llx", SK_KVA(ch->ch_mmap.ami_mapref));
	SK_D("  mapaddr: 0x%llx", (uint64_t)cinfo->cinfo_mem_base);
	SK_D("  mapsize: 0x%llx (%llu KB)",
	    (uint64_t)cinfo->cinfo_mem_map_size,
	    (uint64_t)cinfo->cinfo_mem_map_size >> 10);
	SK_D("  memsize: 0x%llx (%llu KB)",
	    (uint64_t)chr->cr_memsize, (uint64_t)chr->cr_memsize >> 10);
	SK_D("  offset:  0x%llx", (uint64_t)cinfo->cinfo_schema_offset);
}

SK_LOG_ATTRIBUTE
static void
ch_connect_log2(const struct kern_nexus *nx, int err)
{
	uuid_string_t nx_uuidstr;

	SK_ERR("Error connecting to nexus UUID %s: %d",
	    sk_uuid_unparse(nx->nx_uuid, nx_uuidstr), err);
}
#endif /* SK_LOG */

static struct kern_channel *
ch_connect(struct kern_nexus *nx, struct chreq *chr, struct kern_channel *ch0,
    struct nxbind *nxb, struct proc *p, int fd, int *err)
{
	struct kern_nexus_domain_provider *nxdom_prov;
	struct kern_channel *ch = NULL;
	struct ch_info *cinfo = NULL;
	uint32_t ch_mode = chr->cr_mode;
	boolean_t config = FALSE;
	struct nxdom *nxdom;
	boolean_t reserved_port = FALSE;

	ASSERT(!(ch_mode & CHMODE_KERNEL) || p == kernproc);
	ASSERT(chr->cr_port != NEXUS_PORT_ANY || (ch_mode & CHMODE_KERNEL));
	SK_LOCK_ASSERT_HELD();

	/* validate thresholds before we proceed any further */
	if ((*err = ch_ev_thresh_validate(nx, NR_TX, &chr->cr_tx_lowat)) != 0 ||
	    (*err = ch_ev_thresh_validate(nx, NR_RX, &chr->cr_rx_lowat)) != 0) {
		goto done;
	}

	if (!(ch_mode & CHMODE_KERNEL) && !NX_USER_CHANNEL_PROV(nx)) {
		*err = ENOTSUP;
		goto done;
	}

	ch = ch_alloc(Z_WAITOK);

	lck_mtx_lock(&ch->ch_lock);

	uuid_generate_random(ch->ch_info->cinfo_ch_id);
	ch->ch_fd = fd;
	ch->ch_pid = proc_pid(p);
	(void) snprintf(ch->ch_name, sizeof(ch->ch_name), "%s",
	    proc_name_address(p));

	nxdom_prov = NX_DOM_PROV(nx);
	nxdom = NX_DOM(nx);

	if (ch_mode & (CHMODE_KERNEL | CHMODE_NO_NXREF)) {
		/*
		 * CHANF_KERNEL implies a channel opened by a kernel
		 * subsystem, and is triggered by the CHMODE_KERNEL
		 * flag which (only ever) set by ch_open_special().
		 *
		 * CHANF_NONXREF can be optionally set based on the
		 * CHMODE_NO_NXREF request flag.  This must only be
		 * set by ch_open_special() as well, hence we verify.
		 */
		ASSERT(p == kernproc);
		ASSERT(ch_mode & CHMODE_KERNEL);
		atomic_bitset_32(&ch->ch_flags, CHANF_KERNEL);
		if (ch_mode & CHMODE_NO_NXREF) {
			atomic_bitset_32(&ch->ch_flags, CHANF_NONXREF);
		}

		config = (ch_mode & CHMODE_CONFIG) != 0;
		if (chr->cr_port == NEXUS_PORT_ANY) {
			if (nxdom->nxdom_find_port == NULL) {
				*err = ENOTSUP;
				goto done;
			}

			/*
			 * If ephemeral port request, find one for client;
			 * we ask for the reserved port range if this is
			 * a configuration request (CHMODE_CONFIG).
			 */
			if ((*err = nxdom->nxdom_find_port(nx,
			    config, &chr->cr_port)) != 0) {
				goto done;
			}
		}
	}

	if (skywalk_check_platform_binary(p)) {
		atomic_bitset_32(&ch->ch_flags, CHANF_PLATFORM);
	}

	ASSERT(chr->cr_port != NEXUS_PORT_ANY);

	reserved_port = (nxdom->nxdom_port_is_reserved != NULL &&
	    (*nxdom->nxdom_port_is_reserved)(nx, chr->cr_port));
	if (!config && reserved_port) {
		*err = EDOM;
		goto done;
	}

	SK_D("%s(%d) %snexus port %u requested", sk_proc_name_address(p),
	    sk_proc_pid(p), reserved_port ? "[reserved] " : "", chr->cr_port);

	if ((*err = nxdom_prov->nxdom_prov_dom->nxdom_connect(nxdom_prov,
	    nx, ch, chr, ch0, nxb, p)) != 0) {
		goto done;
	}

	cinfo = ch->ch_info;
	uuid_copy(cinfo->cinfo_nx_uuid, nx->nx_uuid);
	/* for easy access to immutables */
	bcopy((void *)nx->nx_prov->nxprov_params,
	    (void *)&cinfo->cinfo_nxprov_params, sizeof(struct nxprov_params));
	cinfo->cinfo_ch_mode = ch_mode;
	cinfo->cinfo_ch_ring_id = chr->cr_ring_id;
	cinfo->cinfo_nx_port = chr->cr_port;
	cinfo->cinfo_mem_base = ch->ch_mmap.ami_mapaddr;
	cinfo->cinfo_mem_map_size = ch->ch_mmap.ami_mapsize;
	cinfo->cinfo_schema_offset = chr->cr_memoffset;
	cinfo->cinfo_num_bufs =
	    skmem_arena_nexus(ch->ch_na->na_arena)->
	    arn_rx_pp->pp_buf_region->skr_params.srp_c_obj_cnt;
	/*
	 * ch_last is really the number of rings, but we need to return
	 * the actual zero-based ring ID to the client.  Make sure that
	 * is the case here and adjust last_{tx,rx}_ring accordingly.
	 */
	ASSERT((ch->ch_last[NR_TX] > 0) ||
	    (ch->ch_na->na_type == NA_NETIF_COMPAT_DEV));
	ASSERT((ch->ch_last[NR_RX] > 0) ||
	    (ch->ch_na->na_type == NA_NETIF_COMPAT_HOST));
	cinfo->cinfo_first_tx_ring = ch->ch_first[NR_TX];
	cinfo->cinfo_last_tx_ring = ch->ch_last[NR_TX] - 1;
	cinfo->cinfo_first_rx_ring = ch->ch_first[NR_RX];
	cinfo->cinfo_last_rx_ring = ch->ch_last[NR_RX] - 1;
	cinfo->cinfo_tx_lowat = chr->cr_tx_lowat;
	cinfo->cinfo_rx_lowat = chr->cr_rx_lowat;

	if (ch_mode & CHMODE_NO_NXREF) {
		ASSERT(ch_mode & CHMODE_KERNEL);
		STAILQ_INSERT_TAIL(&nx->nx_ch_nonxref_head, ch, ch_link);
	} else {
		STAILQ_INSERT_TAIL(&nx->nx_ch_head, ch, ch_link);
		nx->nx_ch_count++;
	}
	atomic_bitset_32(&ch->ch_flags, CHANF_ATTACHED);
	ch->ch_nexus = nx;
	nx_retain_locked(nx);   /* hold a ref on the nexus */

	ch_retain_locked(ch);   /* one for being in the list */
	ch_retain_locked(ch);   /* one for the caller */

	/*
	 * Now that we've successfully created the nexus adapter, inform the
	 * nexus provider about the rings and the slots within each ring.
	 * This is a no-op for internal nexus providers.
	 */
	if ((*err = nxprov_advise_connect(nx, ch, p)) != 0) {
		lck_mtx_unlock(&ch->ch_lock);

		/* gracefully close this fully-formed channel */
		if (ch->ch_flags & CHANF_KERNEL) {
			ch_close_special(ch);
		} else {
			ch_close(ch, TRUE);
		}
		(void) ch_release_locked(ch);
		ch = NULL;
		goto done;
	}

	ASSERT(ch->ch_schema == NULL ||
	    (ch->ch_schema->csm_flags & CSM_ACTIVE));

#if SK_LOG
	if (__improbable(sk_verbose != 0)) {
		ch_connect_log1(nx, cinfo, chr, ch, nxdom_prov, p);
	}
#endif /* SK_LOG */

done:
	if (ch != NULL) {
		lck_mtx_unlock(&ch->ch_lock);
	}
	if (*err != 0) {
#if SK_LOG
		if (__improbable(sk_verbose != 0)) {
			ch_connect_log2(nx, *err);
		}
#endif /* SK_LOG */
		if (ch != NULL) {
			ch_free(ch);
			ch = NULL;
		}
	}
	return ch;
}

static void
ch_disconnect(struct kern_channel *ch)
{
	struct kern_nexus *nx = ch->ch_nexus;
	struct kern_nexus_domain_provider *nxdom_prov = NX_DOM_PROV(nx);

	SK_LOCK_ASSERT_HELD();
	LCK_MTX_ASSERT(&ch->ch_lock, LCK_MTX_ASSERT_OWNED);

	/*
	 * Inform the nexus provider that the channel has been quiesced
	 * and disconnected from the nexus port.  This is a no-op for
	 * internal nexus providers.
	 */
	nxprov_advise_disconnect(nx, ch);

	/* Finally, let the domain provider tear down the instance */
	nxdom_prov->nxdom_prov_dom->nxdom_disconnect(nxdom_prov, nx, ch);
}

void
ch_deactivate(struct kern_channel *ch)
{
	/*
	 * This is a trapdoor flag; once CSM_ACTIVE is cleared,
	 * it will never be set again.  Doing this will cause
	 * os_channel_is_defunct() to indicate that the channel
	 * is defunct and is no longer usable (thus should be
	 * immediately closed).
	 */
	if (ch->ch_schema != NULL &&
	    (ch->ch_schema->csm_flags & CSM_ACTIVE)) {
		atomic_bitclear_32(__DECONST(uint32_t *,
		    &ch->ch_schema->csm_flags), CSM_ACTIVE);
		/* make this globally visible */
		membar_sync();
	}
}

int
ch_set_opt(struct kern_channel *ch, struct sockopt *sopt)
{
#pragma unused(ch)
	int err = 0;

	if (sopt->sopt_dir != SOPT_SET) {
		sopt->sopt_dir = SOPT_SET;
	}

	switch (sopt->sopt_name) {
	case CHOPT_TX_LOWAT_THRESH:
		err = ch_set_lowat_thresh(ch, NR_TX, sopt);
		break;

	case CHOPT_RX_LOWAT_THRESH:
		err = ch_set_lowat_thresh(ch, NR_RX, sopt);
		break;

	case CHOPT_IF_ADV_CONF:
		err = ch_configure_interface_advisory_event(ch, sopt);
		break;

	default:
		err = ENOPROTOOPT;
		break;
	}

	return err;
}

int
ch_get_opt(struct kern_channel *ch, struct sockopt *sopt)
{
#pragma unused(ch)
	int err = 0;

	if (sopt->sopt_dir != SOPT_GET) {
		sopt->sopt_dir = SOPT_GET;
	}

	switch (sopt->sopt_name) {
	case CHOPT_TX_LOWAT_THRESH:
		err = ch_get_lowat_thresh(ch, NR_TX, sopt);
		break;

	case CHOPT_RX_LOWAT_THRESH:
		err = ch_get_lowat_thresh(ch, NR_RX, sopt);
		break;

	default:
		err = ENOPROTOOPT;
		break;
	}

	return err;
}

static int
ch_configure_interface_advisory_event(struct kern_channel *ch,
    struct sockopt *sopt)
{
	int err = 0;
	boolean_t enable = 0;
	struct kern_nexus *nx = ch->ch_nexus;

	LCK_MTX_ASSERT(&ch->ch_lock, LCK_MTX_ASSERT_OWNED);
	SK_LOCK_ASSERT_NOTHELD();

	if (sopt->sopt_val == USER_ADDR_NULL) {
		return EINVAL;
	}
	if (nx->nx_adv.nxv_adv == NULL) {
		return ENOTSUP;
	}
	err = sooptcopyin(sopt, &enable, sizeof(enable), sizeof(enable));
	if (err != 0) {
		return err;
	}

	/*
	 * Drop ch_lock to acquire sk_lock and nx_ch_if_adv_lock due to lock
	 * ordering requirement; check if the channel is closing once ch_lock
	 * is reacquired and bail if so.
	 */
	lck_mtx_unlock(&ch->ch_lock);
	SK_LOCK();
	lck_rw_lock_exclusive(&nx->nx_ch_if_adv_lock);
	lck_mtx_lock(&ch->ch_lock);
	if (ch->ch_flags & CHANF_CLOSING) {
		err = ENXIO;
		goto done;
	}

	/*
	 * if interface advisory reporting is enabled on the channel then
	 * add the channel to the list of channels eligible for interface
	 * advisory update on the nexus. If disabled, remove from the list.
	 */
	if (enable) {
		if ((ch->ch_flags & CHANF_IF_ADV) != 0) {
			ASSERT(err == 0);
			goto done;
		}
		bool enable_adv = STAILQ_EMPTY(&nx->nx_ch_if_adv_head);
		atomic_bitset_32(&ch->ch_flags, CHANF_IF_ADV);
		STAILQ_INSERT_TAIL(&nx->nx_ch_if_adv_head, ch, ch_link_if_adv);
		if (enable_adv) {
			nx_netif_config_interface_advisory(nx, true);
		}
		ch_retain_locked(ch);   /* for being in the IF ADV list */
	} else {
		if ((ch->ch_flags & CHANF_IF_ADV) == 0) {
			ASSERT(err == 0);
			goto done;
		}
		STAILQ_REMOVE(&nx->nx_ch_if_adv_head, ch, kern_channel,
		    ch_link_if_adv);
		atomic_bitclear_32(&ch->ch_flags, CHANF_IF_ADV);
		if (STAILQ_EMPTY(&nx->nx_ch_if_adv_head)) {
			nx_netif_config_interface_advisory(nx, false);
		}
		(void) ch_release_locked(ch);
	}

done:
	lck_mtx_unlock(&ch->ch_lock);
	lck_rw_done(&nx->nx_ch_if_adv_lock);
	SK_UNLOCK();
	lck_mtx_lock(&ch->ch_lock);

	return err;
}

static int
ch_set_lowat_thresh(struct kern_channel *ch, enum txrx t,
    struct sockopt *sopt)
{
	struct ch_ev_thresh cet, *ocet;
	int err = 0;

	LCK_MTX_ASSERT(&ch->ch_lock, LCK_MTX_ASSERT_OWNED);

	if (sopt->sopt_val == USER_ADDR_NULL) {
		return EINVAL;
	}

	bzero(&cet, sizeof(cet));
	err = sooptcopyin(sopt, &cet, sizeof(cet), sizeof(cet));
	if (err == 0) {
		err = ch_ev_thresh_validate(ch->ch_nexus, t, &cet);
		if (err == 0) {
			if (t == NR_TX) {
				ocet = &ch->ch_info->cinfo_tx_lowat;
			} else {
				ocet = &ch->ch_info->cinfo_rx_lowat;
			}

			/* if there is no change, we're done */
			if (ocet->cet_unit == cet.cet_unit &&
			    ocet->cet_value == cet.cet_value) {
				return 0;
			}

			*ocet = cet;

			for_rx_tx(t) {
				ring_id_t qfirst = ch->ch_first[t];
				ring_id_t qlast = ch->ch_last[t];
				uint32_t i;

				for (i = qfirst; i < qlast; i++) {
					struct __kern_channel_ring *kring =
					    &NAKR(ch->ch_na, t)[i];

					(void) kring->ckr_na_notify(kring,
					    sopt->sopt_p, 0);
				}
			}

			(void) sooptcopyout(sopt, &cet, sizeof(cet));
		}
	}

	return err;
}

static int
ch_get_lowat_thresh(struct kern_channel *ch, enum txrx t,
    struct sockopt *sopt)
{
	struct ch_ev_thresh cet;

	LCK_MTX_ASSERT(&ch->ch_lock, LCK_MTX_ASSERT_OWNED);

	if (sopt->sopt_val == USER_ADDR_NULL) {
		return EINVAL;
	}

	if (t == NR_TX) {
		cet = ch->ch_info->cinfo_tx_lowat;
	} else {
		cet = ch->ch_info->cinfo_rx_lowat;
	}

	return sooptcopyout(sopt, &cet, sizeof(cet));
}

static struct kern_channel *
ch_alloc(zalloc_flags_t how)
{
	struct kern_channel *ch;

	ch = zalloc_flags(ch_zone, how | Z_ZERO);
	if (ch) {
		lck_mtx_init(&ch->ch_lock, &channel_lock_group, &channel_lock_attr);
		ch->ch_info = zalloc_flags(ch_info_zone, how | Z_ZERO);
	}
	return ch;
}

static void
ch_free(struct kern_channel *ch)
{
	ASSERT(ch->ch_refcnt == 0);
	ASSERT(ch->ch_pp == NULL);
	ASSERT(!(ch->ch_flags & (CHANF_ATTACHED | CHANF_EXT_CONNECTED |
	    CHANF_EXT_PRECONNECT | CHANF_IF_ADV)));
	lck_mtx_destroy(&ch->ch_lock, &channel_lock_group);
	SK_DF(SK_VERB_MEM, "ch 0x%llx FREE", SK_KVA(ch));
	ASSERT(ch->ch_info != NULL);
	zfree(ch_info_zone, ch->ch_info);
	ch->ch_info = NULL;
	zfree(ch_zone, ch);
}

void
ch_retain_locked(struct kern_channel *ch)
{
	SK_LOCK_ASSERT_HELD();

	ch->ch_refcnt++;
	VERIFY(ch->ch_refcnt != 0);
}

void
ch_retain(struct kern_channel *ch)
{
	SK_LOCK();
	ch_retain_locked(ch);
	SK_UNLOCK();
}

int
ch_release_locked(struct kern_channel *ch)
{
	int oldref = ch->ch_refcnt;

	SK_LOCK_ASSERT_HELD();

	VERIFY(ch->ch_refcnt != 0);
	if (--ch->ch_refcnt == 0) {
		ch_free(ch);
	}

	return oldref == 1;
}

int
ch_release(struct kern_channel *ch)
{
	int lastref;

	SK_LOCK();
	lastref = ch_release_locked(ch);
	SK_UNLOCK();

	return lastref;
}

void
ch_dtor(void *arg)
{
	struct kern_channel *ch = arg;

	SK_LOCK();
	ch_close(ch, TRUE);
	(void) ch_release_locked(ch);
	SK_UNLOCK();
}
