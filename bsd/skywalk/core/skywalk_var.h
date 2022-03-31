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
 *    documentation and/or other materials provided with the distribution.
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

#ifndef _SKYWALK_VAR_H_
#define _SKYWALK_VAR_H_

#ifdef BSD_KERNEL_PRIVATE
#include <stdint.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/cdefs.h>
#include <sys/errno.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/sysctl.h>
#include <sys/poll.h>
#include <sys/priv.h>
#include <sys/random.h>
#include <sys/kernel.h>
#include <sys/guarded.h>
#include <uuid/uuid.h>
#include <kern/bits.h>
#include <kern/locks.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/zalloc.h>
#include <mach/boolean.h>
#include <machine/atomic.h>
#include <machine/endian.h>
#include <netinet/ip.h>
#include <net/dlil.h>
#include <net/pfvar.h>
#include <libkern/libkern.h>
#include <libkern/OSAtomic.h>
#include <libkern/OSByteOrder.h>
#include <IOKit/skywalk/IOSkywalkSupport.h>
#include <skywalk/os_nexus_private.h>
#include <skywalk/os_channel_private.h>
#include <skywalk/namespace/netns.h>
#include <skywalk/namespace/protons.h>
#include <vm/vm_kern.h>
#include <san/kasan.h>

/*
 * General byte order swapping functions.
 */
#define bswap16(x)      OSSwapInt16(x)
#define bswap32(x)      OSSwapInt32(x)
#define bswap64(x)      OSSwapInt64(x)

/*
 * Atomic operations.
 */
#define SK_ATOMIC_TEST_AND_SET(p)       (!atomic_test_set_32((p), 0, 1))
#define SK_ATOMIC_CLEAR(p)              atomic_set_32((p), 0)

extern uint32_t sk_debug;

/*
 * feature bits defined in os_skywalk_private.h
 */
extern uint64_t sk_features;

SYSCTL_DECL(_kern_skywalk);
SYSCTL_DECL(_kern_skywalk_stats);

#define SK_LOCK()                       \
	lck_mtx_lock(&sk_lock)
#define SK_LOCK_TRY()                   \
	lck_mtx_try_lock(&sk_lock)
#define SK_LOCK_ASSERT_HELD()           \
	LCK_MTX_ASSERT(&sk_lock, LCK_MTX_ASSERT_OWNED)
#define SK_LOCK_ASSERT_NOTHELD()        \
	LCK_MTX_ASSERT(&sk_lock, LCK_MTX_ASSERT_NOTOWNED)
#define SK_UNLOCK()                     \
	lck_mtx_unlock(&sk_lock)

decl_lck_mtx_data(extern, sk_lock);
extern lck_grp_t        sk_lock_group;
extern lck_attr_t       sk_lock_attr;

/*
 * Ring Types.
 */
enum txrx {
	NR_RX = 0,              /* RX only */
	NR_TX = 1,              /* TX only */
	NR_TXRX,                /* RX+TX (alias) */
	NR_A = NR_TXRX,         /* alloc only */
	NR_F,                   /* free only */
	NR_TXRXAF,              /* alloc+free (alias) */
	NR_EV = NR_TXRXAF,      /* event only */
	NR_ALL                  /* all of the above */
};

__attribute__((always_inline))
static inline const char *
sk_ring2str(enum txrx t)
{
	switch (t) {
	case NR_TX:
		return "TX";
	case NR_RX:
		return "RX";
	case NR_A:
		return "ALLOC";
	case NR_F:
		return "FREE";
	case NR_EV:
		return "EVENT";
	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}
}

__attribute__((always_inline))
static inline enum txrx
sk_txrx_swap(enum txrx t)
{
	return t == NR_RX ? NR_TX : NR_RX;
}

#define for_rx_tx(t)    for ((t) = 0; (t) < NR_TXRX; (t)++)
#define for_a_f(t)      for ((t) = NR_A; (t) <= NR_F; (t)++)
#define for_all_rings(t)    for ((t) = 0; (t) < NR_ALL; (t)++)

/* return the next index, with wraparound */
__attribute__((always_inline))
static inline uint32_t
SLOT_NEXT(uint32_t i, uint32_t lim)
{
	return __improbable(i == lim) ? 0 : i + 1;
}

/* return the previous index, with wraparound */
__attribute__((always_inline))
static inline uint32_t
SLOT_PREV(uint32_t i, uint32_t lim)
{
	return __improbable(i == 0) ? lim : i - 1;
}

/* return the incremented index, with wraparound */
static inline uint32_t
SLOT_INCREMENT(uint32_t i, uint32_t n, uint32_t lim)
{
	i += n;
	return __improbable(i > lim) ? i - lim - 1 : i;
}

/*
 * Nexus metadata.
 */
#define NX_METADATA_QUANTUM_SZ          \
	(MAX(sizeof (struct __user_quantum), sizeof (struct __kern_quantum)))
#define NX_METADATA_PACKET_SZ(_n)       \
	(MAX(_USER_PACKET_SIZE(_n), _KERN_PACKET_SIZE(_n)))

/* {min,max} internal user metadata object size */
#define NX_METADATA_OBJ_MIN_SZ  \
	(METADATA_PREAMBLE_SZ + NX_METADATA_QUANTUM_SZ)
#define NX_METADATA_OBJ_MAX_SZ  512

/* {min,max} client metadata size */
#define NX_METADATA_USR_MIN_SZ  0
#define NX_METADATA_USR_MAX_SZ  \
	(NX_METADATA_OBJ_MAX_SZ - NX_METADATA_OBJ_MIN_SZ)

/*
 * User-visible statistics.
 */
#define NX_STATS_MIN_SZ         0
#define NX_STATS_MAX_SZ         (16 * 1024)

/*
 * Flow advisory entries.
 */
#define NX_FLOWADV_DEFAULT      682
#define NX_FLOWADV_MAX          (64 * 1024)
#define FO_FLOWADV_CHUNK        64

/*
 * Nexus advisory.
 */
#define NX_NEXUSADV_MAX_SZ      (16 * 1024)

/* {min,max} number of ring pairs in a nexus */
#define NX_MIN_NUM_RING_PAIR    1
#define NX_MAX_NUM_RING_PAIR    8 /* xxx unclear how many */
#define NX_MIN_NUM_RING         (NX_MIN_NUM_RING_PAIR * 2)
#define NX_MAX_NUM_RING         (NX_MAX_NUM_RING_PAIR * 2)

#define NX_MIN_NUM_SLOT_PER_RING        2
#define NX_MAX_NUM_SLOT_PER_RING        (16 * 1024)

#define NX_MIN_BUF_OBJ_SIZE     64
#define NX_MAX_BUF_OBJ_SIZE     (64 * 1024)

#define NX_PBUF_FRAGS_MIN       1
#define NX_PBUF_FRAGS_DEFAULT   NX_PBUF_FRAGS_MIN
#define NX_PBUF_FRAGS_MAX       64

#define NX_MAX_AGGR_PKT_SIZE IP_MAXPACKET /* max aggregated pkt size */

/*
 * Compat netif transmit models.
 */
/* uses default parameters as set by driver */
#define NETIF_COMPAT_TXMODEL_DEFAULT            0
/* override driver parameters and force IFEF_ENQUEUE_MULTI */
#define NETIF_COMPAT_TXMODEL_ENQUEUE_MULTI      1

/*
 * Native netif transmit models.
 */
/* uses default parameters as set by driver */
#define NETIF_NATIVE_TXMODEL_DEFAULT            0
/* override driver parameters and force IFEF_ENQUEUE_MULTI */
#define NETIF_NATIVE_TXMODEL_ENQUEUE_MULTI      1

#define _timerisset(tvp)        ((tvp)->tv_sec || (tvp)->tv_nsec)
#define _timersub(tvp, uvp, vvp) do {                                   \
	        (vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;          \
	        (vvp)->tv_nsec = (tvp)->tv_nsec - (uvp)->tv_nsec;       \
	        if ((vvp)->tv_nsec < 0) {                               \
	                (vvp)->tv_sec--;                                \
	                (vvp)->tv_nsec += NSEC_PER_SEC;                 \
	        }                                                       \
} while (0)
#define _timernsec(tvp, nsp) do {                                       \
	        *(nsp) = (tvp)->tv_nsec;                                \
	        if ((tvp)->tv_sec > 0)                                  \
	                *(nsp) += ((tvp)->tv_sec * NSEC_PER_SEC);       \
} while (0)

struct nexus_adapter;
struct kern_pbufpool;

extern uint32_t sk_opp_defunct;
extern uint32_t sk_cksum_tx;
extern uint32_t sk_cksum_rx;
extern uint32_t sk_guard;
extern uint32_t sk_headguard_sz;
extern uint32_t sk_tailguard_sz;

#if (DEVELOPMENT || DEBUG)
extern uint32_t sk_txring_sz;
extern uint32_t sk_rxring_sz;
extern uint32_t sk_net_txring_sz;
extern uint32_t sk_net_rxring_sz;
#endif /* !DEVELOPMENT && !DEBUG */

extern uint32_t sk_max_flows;
extern uint32_t sk_fadv_nchunks;
extern uint32_t sk_netif_compat_txmodel;
extern uint32_t sk_netif_native_txmodel;
extern uint16_t sk_tx_delay_qlen;
extern uint16_t sk_tx_delay_timeout;
extern uint32_t sk_netif_compat_aux_cell_tx_ring_sz;
extern uint32_t sk_netif_compat_aux_cell_rx_ring_sz;
extern uint32_t sk_netif_compat_wap_tx_ring_sz;
extern uint32_t sk_netif_compat_wap_rx_ring_sz;
extern uint32_t sk_netif_compat_awdl_tx_ring_sz;
extern uint32_t sk_netif_compat_awdl_rx_ring_sz;
extern uint32_t sk_netif_compat_wif_tx_ring_sz;
extern uint32_t sk_netif_compat_wif_rx_ring_sz;
extern uint32_t sk_netif_compat_usb_eth_tx_ring_sz;
extern uint32_t sk_netif_compat_usb_eth_rx_ring_sz;
extern int sk_netif_compat_rx_mbq_limit;
extern char sk_ll_prefix[IFNAMSIZ];
extern uint32_t sk_fsw_rx_agg_tcp;
extern uint32_t sk_fsw_tx_agg_tcp;

typedef enum fsw_rx_agg_tcp_host {
	SK_FSW_RX_AGG_TCP_HOST_OFF = 0,
	SK_FSW_RX_AGG_TCP_HOST_ON = 1,
	SK_FSW_RX_AGG_TCP_HOST_AUTO
} fsw_rx_agg_tcp_host_t;
extern uint32_t sk_fsw_rx_agg_tcp_host;
extern uint32_t sk_fsw_max_bufs;

typedef enum netif_mit_cfg {
	SK_NETIF_MIT_FORCE_OFF = 0,     /* force mitigation OFF */
	SK_NETIF_MIT_FORCE_SIMPLE,      /* force mitigation ON (simple) */
	SK_NETIF_MIT_FORCE_ADVANCED,    /* force mitigation ON (advanced) */
	SK_NETIF_MIT_AUTO,              /* automatic (default) */
	SK_NETIF_MIT_MAX = SK_NETIF_MIT_AUTO,
} netif_mit_cfg_t;
extern uint32_t sk_netif_tx_mit;
extern uint32_t sk_netif_rx_mit;
extern uint32_t sk_rx_sync_packets;
extern uint32_t sk_channel_buflet_alloc;
extern uint32_t sk_min_pool_size;

struct sk_protect;
typedef const struct sk_protect *sk_protect_t;

__attribute__((always_inline))
static inline boolean_t
sk_is_sync_protected(void)
{
	return net_thread_is_marked(NET_THREAD_CHANNEL_SYNC) != 0;
}

__attribute__((always_inline))
static inline sk_protect_t
sk_sync_protect(void)
{
	return (sk_protect_t)(const void *)
	       net_thread_marks_push(NET_THREAD_CHANNEL_SYNC);
}


__attribute__((always_inline))
static inline boolean_t
sk_is_rx_notify_protected(void)
{
	return net_thread_is_marked(NET_THREAD_RX_NOTIFY) != 0;
}

__attribute__((always_inline))
static inline sk_protect_t
sk_rx_notify_protect(void)
{
	return (sk_protect_t)(const void *)
	       net_thread_marks_push(NET_THREAD_RX_NOTIFY);
}

__attribute__((always_inline))
static inline sk_protect_t
sk_tx_notify_protect(void)
{
	return (sk_protect_t)(const void *)
	       net_thread_marks_push(NET_THREAD_TX_NOTIFY);
}

__attribute__((always_inline))
static inline boolean_t
sk_is_tx_notify_protected(void)
{
	return net_thread_is_marked(NET_THREAD_TX_NOTIFY) != 0;
}

__attribute__((always_inline))
static inline boolean_t
sk_is_cache_update_protected(void)
{
	return net_thread_is_marked(NET_THREAD_CACHE_UPDATE) != 0;
}

__attribute__((always_inline))
static inline sk_protect_t
sk_cache_update_protect(void)
{
	return (sk_protect_t)(const void *)
	       net_thread_marks_push(NET_THREAD_CACHE_UPDATE);
}

__attribute__((always_inline))
static inline boolean_t
sk_is_region_update_protected(void)
{
	return net_thread_is_marked(NET_THREAD_REGION_UPDATE) != 0;
}

__attribute__((always_inline))
static inline sk_protect_t
sk_region_update_protect(void)
{
	return (sk_protect_t)(const void *)
	       net_thread_marks_push(NET_THREAD_REGION_UPDATE);
}

__attribute__((always_inline))
static inline boolean_t
sk_is_async_transmit_protected(void)
{
	return net_thread_is_marked(NET_THREAD_AYSYNC_TX) != 0;
}

__attribute__((always_inline))
static inline sk_protect_t
sk_async_transmit_protect(void)
{
	return (sk_protect_t)(const void *)
	       net_thread_marks_push(NET_THREAD_AYSYNC_TX);
}

#define sk_sync_unprotect sk_unprotect
#define sk_cache_update_unprotect sk_unprotect
#define sk_region_update_unprotect sk_unprotect
#define sk_tx_notify_unprotect sk_unprotect
#define sk_async_transmit_unprotect sk_unprotect

__attribute__((always_inline))
static inline void
sk_unprotect(sk_protect_t protect)
{
	net_thread_marks_pop((net_thread_marks_t)(const void*)protect);
}



/*
 * For sysctls that allocate a buffer to fill then copyout at completion,
 * set an upper bound on the size of the buffer we'll allocate.
 */
#define SK_SYSCTL_ALLOC_MAX             ((size_t)(100 * 1024 * 1024))

#if (DEVELOPMENT || DEBUG)
typedef void (*_null_func_t)(void);
#define null_func       ((_null_func_t)NULL)

extern uint32_t sk_inject_error_rmask;
#define _SK_INJECT_ERROR(_ie, _en, _ev, _ec, _ej, _f, ...) do {         \
	if (__improbable(((_ie) & (1ULL << (_en))) != 0)) {             \
	        if ((random() & sk_inject_error_rmask) !=               \
	            sk_inject_error_rmask)                              \
	                break;                                          \
	        if ((_ej) != NULL) (*(_ej))++;                          \
	        SK_DF(SK_VERB_ERROR_INJECT, "injecting error %d", (_en));\
	        if ((_f) != NULL)                                       \
	                (_f)(__VA_ARGS__);                              \
	        (_ev) = (_ec);                                          \
	}                                                               \
} while (0)
#else
#define _SK_INJECT_ERROR(_en, _ev, _ec, _f, ...)
#endif /* DEVELOPMENT || DEBUG */

__BEGIN_DECLS
extern int skywalk_init(void);
extern int skywalk_priv_check_cred(proc_t, kauth_cred_t, int);
extern int skywalk_priv_check_proc_cred(proc_t, int);
#if CONFIG_MACF
extern int skywalk_mac_system_check_proc_cred(proc_t, const char *);
#endif /* CONFIG_MACF */
extern int skywalk_nxctl_check_privileges(proc_t, kauth_cred_t);
extern boolean_t skywalk_check_platform_binary(proc_t);
extern boolean_t skywalk_netif_direct_allowed(const char *);
extern boolean_t skywalk_netif_direct_enabled(void);
extern void sk_gen_guard_id(boolean_t, const uuid_t, guardid_t *);
extern const char *sk_uuid_unparse(const uuid_t, uuid_string_t);
#if SK_LOG
extern const char *sk_dump(const char *, const void *, int, int,
    char *, int);
extern const char *sk_proc_name_address(struct proc *);
extern int sk_proc_pid(struct proc *);
extern const char *sk_sa_ntop(struct sockaddr *, char *, size_t);
extern const char *sk_memstatus2str(uint32_t);
#endif /* SK_LOG */

extern bool sk_sa_has_addr(struct sockaddr *sa);
extern bool sk_sa_has_port(struct sockaddr *sa);
extern uint16_t sk_sa_get_port(struct sockaddr *sa);

extern void skywalk_kill_process(struct proc *, uint64_t);

enum skywalk_kill_reason {
	SKYWALK_KILL_REASON_GENERIC = 0,
	SKYWALK_KILL_REASON_HEAD_OOB,
	SKYWALK_KILL_REASON_HEAD_OOB_WRAPPED,
	SKYWALK_KILL_REASON_CUR_OOB,
	SKYWALK_KILL_REASON_CUR_OOB_WRAPPED_1,
	SKYWALK_KILL_REASON_CUR_OOB_WRAPPED_2,
	SKYWALK_KILL_REASON_TAIL_MISMATCH,
	SKYWALK_KILL_REASON_BASIC_SANITY,
	SKYWALK_KILL_REASON_UNALLOCATED_PKT,
	SKYWALK_KILL_REASON_SLOT_NOT_DETACHED,
	SKYWALK_KILL_REASON_QUM_IDX_MISMATCH,
	SKYWALK_KILL_REASON_SYNC_FAILED,
	SKYWALK_KILL_REASON_INCONSISTENT_READY_BYTES,
	SKYWALK_KILL_REASON_BAD_BUFLET_CHAIN,
	SKYWALK_KILL_REASON_INTERNALIZE_FAILED,
};

#define SKYWALK_KILL_REASON_TX_SYNC             0x0000000000000000ULL
#define SKYWALK_KILL_REASON_EVENT_SYNC          0x1000000000000000ULL
#define SKYWALK_KILL_REASON_FREE_SYNC           0x2000000000000000ULL
#define SKYWALK_KILL_REASON_ALLOC_SYNC          0x4000000000000000ULL
#define SKYWALK_KILL_REASON_RX_SYNC             0x8000000000000000ULL

/* for convenience */
extern char *proc_name_address(void *p);

/*
 * skoid is the glue that holds the Skywalk struct model and sysctl properties
 * together. It's supposed to be embedded in other Skywalk struct, for instance
 * channel, nexus, etc. skoid can holds variable number of properties, which
 * is automatically made available to the sysctl interface under the parent
 * skoid sysctl node.
 *
 * The embedding struct should call skoid_create, which does the initialization
 * and registration of the associated sysctl_oid under the parent node. All
 * first level dynamic skoid nodes must hang under static sysctl nodes defined
 * with traditional SYSCTL_NODE macro in linker set.
 *     skoid_create(1st_level_skoid, skoid_SNODE(_linker_sysctl), name, kind)
 *
 * The fields in embedding skoid can be expressed as properties of the skoid,
 * or separate skoid, depending on the model. If the field is of primitive
 * types, then properties should be used. If the field is of compound types
 * (e.g. struct), another layer of skoid might be created under the parent.
 *
 * To add properties to the skoid, call one of the skoid_add_* functions.
 *     skoid_add_int(&skoid, name, flags, int_ptr)
 * To add another skoid as child of a skoid, allocate and call skoid_create
 * with the skoid_DNODE(parent_skoid) as parent argument.
 *     skoid_create(2+_level_skoid, skoid_DNODE(parent_skoid), name, kind)
 *
 * About life cycle: the embedding struct of skoid must outlive the skoid.
 * skoid itself store a cached name, so there is no restriction of the name
 * buffer life cycle. Property name should be a const string or string with
 * longer life cycle than the skoid. Most often, the skoid has a variable name
 * reflecting the Skywalk struct name (e.g. "ms.en0", while the properties has
 * a fixed name same as the struct member variable name.
 *
 * Please use caution regarding access control of skoid properties.
 */
#define SKOID_SNODE(static_parent)      (&(sysctl_##static_parent##_children))
#define SKOID_DNODE(dynamic_parent)     (&(dynamic_parent.sko_oid_list))
#define SKOID_NAME_SIZE 32

struct skoid {
	struct sysctl_oid_list  sko_oid_list;   /* self sko_oid & properties */
	struct sysctl_oid       sko_oid;        /* self sysctl oid storage */
	char                    sko_name[SKOID_NAME_SIZE];      /* skoid name */
};

extern void skoid_init(void);
extern void skoid_create(struct skoid *skoid, struct sysctl_oid_list *parent,
    const char *name, int kind);
extern void skoid_add_int(struct skoid *skoid, const char *name, int flags,
    int *ptr);
extern void skoid_add_uint(struct skoid *skoid, const char *name, int flags,
    unsigned int *ptr);
extern void skoid_add_handler(struct skoid *skoid, const char *name, int kind,
    int (*handler)SYSCTL_HANDLER_ARGS, void *arg1, int arg2);
extern void skoid_destroy(struct skoid *skoid);

/*
 * To avoid accidentally invoking skoid procedure by `sysctl` tool, use this
 * macro as guard, so proc is only called with a parameter, e.g.
 *     sysctl <skoid_proc_name>=1
 */
#define SKOID_PROC_CALL_GUARD do {                      \
	if (req->newptr == USER_ADDR_NULL)              \
	        return (0);                             \
} while (0)

extern kern_allocation_name_t skmem_tag_oid;
extern kern_allocation_name_t skmem_tag_sysctl_buf;

__END_DECLS
#endif /* BSD_KERNEL_PRIVATE */
#endif /* _SKYWALK_VAR_H_ */
