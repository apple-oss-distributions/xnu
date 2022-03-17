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


#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <skywalk/os_skywalk_private.h>
#include <skywalk/os_packet_private.h>

#ifndef LIBSYSCALL_INTERFACE
#error "LIBSYSCALL_INTERFACE not defined"
#endif /* !LIBSYSCALL_INTERFACE */

/*
 * Defined here as we don't have Libc
 */
extern int __getpid(void);
extern int __kill(int pid, int signum, int posix);
extern int __exit(int) __attribute__((noreturn));

static ring_id_t _ring_id(struct ch_info *cinfo, const ring_id_type_t type);
static void os_channel_info2attr(struct channel *chd, channel_attr_t cha);
static int _flowadv_id_equal(struct __flowadv_entry *, uuid_t);

#if defined(__arm__) || defined(__arm64__)
__attribute__((always_inline, visibility("hidden")))
static inline void
membar_sync(void)
{
	__asm__ volatile ("dmb ish" ::: "memory");
}
#elif defined(__i386__) || defined(__x86_64__)
__attribute__((always_inline, visibility("hidden")))
static inline void
membar_sync(void)
{
	__asm__ volatile ("mfence" ::: "memory");
}
#else /* !__arm__ && !__arm64__ && !__i386__ && !__x86_64__ */
#error "Unknown platform; membar_sync() not available"
#endif /* !__arm__ && !__arm64__ && !__i386__ && !__x86_64__ */

/*
 * This is pretty much what an inlined memcmp() would do for UUID
 * comparison; since we don't have access to memcmp() here, we
 * manually handle it ourselves.
 */
#define UUID_COMPARE(a, b)                                                  \
	(a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3] &&    \
	a[4] == b[4] && a[5] == b[5] && a[6] == b[6] && a[7] == b[7] &&     \
	a[8] == b[8] && a[9] == b[9] && a[10] == b[10] && a[11] == b[11] && \
	a[12] == b[12] && a[13] == b[13] && a[14] == b[14] && a[15] == b[15])

#define _SLOT_INDEX(_chrd, _slot)                                       \
	((slot_idx_t)((_slot - (_chrd)->chrd_slot_desc)))

#define _SLOT_DESC(_chrd, _idx)                                         \
	(SLOT_DESC_USD(&(_chrd)->chrd_slot_desc[_idx]))

#define _METADATA(_chrd, _ring, _midx)                                  \
	((void *)((_chrd)->chrd_md_base_addr +                          \
	((_midx) * (_ring)->ring_md_size) + METADATA_PREAMBLE_SZ))

#define _SLOT_METADATA(_chrd, _ring, _idx)                              \
	_METADATA(_chrd, _ring, _SLOT_DESC(_chrd, _idx)->sd_md_idx)

#define _SLOT_METADATA_IDX_VERIFY(_chrd, _md, _midx)    do {            \
	if (__improbable((_md) != _METADATA((_chrd), (_chrd)->chrd_ring, \
	    (_midx))) && !_CHANNEL_RING_IS_DEFUNCT(_chrd)) {            \
	        SK_ABORT_WITH_CAUSE("bad packet handle", (_midx));      \
	/* NOTREACHED */                                                \
	        __builtin_unreachable();                                \
	}                                                               \
} while (0)

#define _BFT_INDEX(_chrd, _bft) (_bft)->buf_bft_idx_reg

#define _SLOT_BFT_METADATA(_chrd, _ring, _idx)                          \
	_CHANNEL_RING_BFT(_chrd, _ring, _SLOT_DESC(_chrd, _idx)->sd_md_idx)

#define _SLOT_BFT_METADATA_IDX_VERIFY(_chrd, _md, _midx)    do {        \
	if (__improbable((mach_vm_address_t)(_md) !=                    \
	    _CHANNEL_RING_BFT((_chrd), (_chrd)->chrd_ring, (_midx))) && \
	    !_CHANNEL_RING_IS_DEFUNCT(_chrd)) {                         \
	        SK_ABORT_WITH_CAUSE("bad buflet handle", (_midx));      \
	/* NOTREACHED */                                                \
	        __builtin_unreachable();                                \
	}                                                               \
} while (0)

#define _SLOT_DESC_VERIFY(_chrd, _sdp) do {                             \
	if (__improbable(!SD_VALID_METADATA(_sdp)) &&                   \
	    !_CHANNEL_RING_IS_DEFUNCT(_chrd)) {                         \
	        SK_ABORT("Slot descriptor has no metadata");            \
	/* NOTREACHED */                                        \
	        __builtin_unreachable();                                \
	}                                                               \
} while (0)

#define _METADATA_VERIFY(_chrd, _md) do {                               \
	if (__improbable(METADATA_PREAMBLE(_md)->mdp_redzone !=         \
	    (((mach_vm_address_t)(_md) - (_chrd)->chrd_md_base_addr) ^  \
	    __os_ch_md_redzone_cookie)) &&                              \
	    !_CHANNEL_RING_IS_DEFUNCT(_chrd)) {                         \
	        SK_ABORT_WITH_CAUSE("Metadata redzone corrupted",       \
	            METADATA_PREAMBLE(_md)->mdp_redzone);               \
	/* NOTREACHED */                                        \
	        __builtin_unreachable();                                \
	}                                                               \
} while (0)

#define _PKT_BUFCNT_VERIFY(_chrd, _bcnt, _bmax) do {                    \
	if (__improbable((_chrd)->chrd_max_bufs < (_bmax))) {           \
	        SK_ABORT_WITH_CAUSE("Invalid max bufcnt", (_bmax));     \
	/* NOTREACHED */                                                \
	        __builtin_unreachable();                                \
	}                                                               \
	if (__improbable((_bcnt) > (_bmax))) {                          \
	        SK_ABORT_WITH_CAUSE("Invalid bufcnt", (_bcnt));         \
	/* NOTREACHED */                                                \
	        __builtin_unreachable();                                \
	}                                                               \
} while (0)

#define _ABORT_MSGSZ    1024

#define _SCHEMA_VER_VERIFY(_chd) do {                                   \
	/* ensure all stores are globally visible */                    \
	membar_sync();                                                  \
	if (CHD_SCHEMA(_chd)->csm_ver != CSM_CURRENT_VERSION)	{       \
	        char *_msg = malloc(_ABORT_MSGSZ);                      \
	        uint32_t _ver = (uint32_t)CHD_SCHEMA(_chd)->csm_ver;    \
	/* we're stuck with %x and %s formatters */             \
	        (void) _mach_snprintf(_msg, _ABORT_MSGSZ,               \
	            "Schema region version mismatch: 0x%x != 0x%x\n"    \
	            "Kernel version: %s - did you forget to install "   \
	            "a matching libsystem_kernel.dylib?\n"              \
	            "Kernel UUID: %x%x%x%x-%x%x-%x%x-%x%x-%x%x%x%x%x%x", \
	            _ver, (uint32_t)CSM_CURRENT_VERSION,                \
	            CHD_SCHEMA(_chd)->csm_kern_name,                    \
	            CHD_SCHEMA(_chd)->csm_kern_uuid[0],                 \
	            CHD_SCHEMA(_chd)->csm_kern_uuid[1],                 \
	            CHD_SCHEMA(_chd)->csm_kern_uuid[2],                 \
	            CHD_SCHEMA(_chd)->csm_kern_uuid[3],                 \
	            CHD_SCHEMA(_chd)->csm_kern_uuid[4],                 \
	            CHD_SCHEMA(_chd)->csm_kern_uuid[5],                 \
	            CHD_SCHEMA(_chd)->csm_kern_uuid[6],                 \
	            CHD_SCHEMA(_chd)->csm_kern_uuid[7],                 \
	            CHD_SCHEMA(_chd)->csm_kern_uuid[8],                 \
	            CHD_SCHEMA(_chd)->csm_kern_uuid[9],                 \
	            CHD_SCHEMA(_chd)->csm_kern_uuid[10],                \
	            CHD_SCHEMA(_chd)->csm_kern_uuid[11],                \
	            CHD_SCHEMA(_chd)->csm_kern_uuid[12],                \
	            CHD_SCHEMA(_chd)->csm_kern_uuid[13],                \
	            CHD_SCHEMA(_chd)->csm_kern_uuid[14],                \
	            CHD_SCHEMA(_chd)->csm_kern_uuid[15]);               \
	        SK_ABORT_DYNAMIC(_msg);                                 \
	/* NOTREACHED */                                        \
	        __builtin_unreachable();                                \
	}                                                               \
} while (0)

#define _SLOT_ATTACH_METADATA(_usd, _md_idx) do {                       \
	(_usd)->sd_md_idx = (_md_idx);                                  \
	(_usd)->sd_flags |= SD_IDX_VALID;                               \
} while (0)

#define _SLOT_DETACH_METADATA(_usd) do	{                               \
	(_usd)->sd_md_idx = OBJ_IDX_NONE;                               \
	(_usd)->sd_flags &= ~SD_IDX_VALID;                              \
} while (0)

#define _CHANNEL_OFFSET(_type, _ptr, _offset)                           \
	((_type)(void *)((uintptr_t)(_ptr) + (_offset)))

#define _CHANNEL_SCHEMA(_base, _off)                                    \
	_CHANNEL_OFFSET(struct __user_channel_schema *, _base, _off)

#define _CHANNEL_RING_BUF(_chrd, _ring, _idx)                           \
	((_chrd)->chrd_buf_base_addr + ((_idx) * (_ring)->ring_buf_size))

#define _CHANNEL_RING_BFT(_chrd, _ring, _idx)                           \
	((_chrd)->chrd_bft_base_addr + ((_idx) * (_ring)->ring_bft_size))

#define _CHANNEL_RING_NEXT(_ring, _cur)                                 \
	(__improbable((_cur) + 1 == (_ring)->ring_num_slots) ? 0 : (_cur) + 1)

#define _CHANNEL_RING_IS_DEFUNCT(_chrd)                                 \
	(!(*(_chrd)->chrd_csm_flags & CSM_ACTIVE))

#define _CHANNEL_IS_DEFUNCT(_chd)                                       \
	(!(CHD_SCHEMA(_chd)->csm_flags & CSM_ACTIVE))

#define _CH_PKT_GET_FIRST_BUFLET(_pkt, _bft, _chrd, _ring) do {         \
	if (__probable((_pkt)->pkt_qum_buf.buf_idx != OBJ_IDX_NONE)) {  \
	        (_bft) = &(_pkt)->pkt_qum_buf;                          \
	} else if ((_pkt)->pkt_qum_buf.buf_nbft_idx != OBJ_IDX_NONE) {  \
	        (_bft) = _CHANNEL_RING_BFT(_chrd, _ring,                \
	            (_pkt)->pkt_qum_buf.buf_nbft_idx);                  \
	} else {                                                        \
	        (_bft) = NULL;                                          \
	}                                                               \
} while (0)

/*
 * A per process copy of the channel metadata redzone cookie.
 */
__attribute__((visibility("hidden")))
static uint64_t __os_ch_md_redzone_cookie = 0;

__attribute__((always_inline, visibility("hidden")))
static inline uint32_t
_num_tx_rings(struct ch_info *ci)
{
	ring_id_t first, last;

	first = _ring_id(ci, CHANNEL_FIRST_TX_RING);
	last = _ring_id(ci, CHANNEL_LAST_TX_RING);

	return (last - first) + 1;
}

__attribute__((always_inline, visibility("hidden")))
static inline uint32_t
_num_rx_rings(struct ch_info *ci)
{
	ring_id_t first, last;

	first = _ring_id(ci, CHANNEL_FIRST_RX_RING);
	last = _ring_id(ci, CHANNEL_LAST_RX_RING);

	return (last - first) + 1;
}

__attribute__((always_inline, visibility("hidden")))
static inline uint32_t
_num_allocator_rings(const struct __user_channel_schema *csm)
{
	return csm->csm_allocator_ring_pairs << 1;
}

__attribute__((visibility("hidden")))
static void
os_channel_init_ring(struct channel_ring_desc *chrd,
    struct channel *chd, uint32_t ring_index)
{
	struct __user_channel_schema *csm = CHD_SCHEMA(chd);
	struct __user_channel_ring *ring = NULL;
	struct __slot_desc *sd = NULL;
	nexus_meta_type_t md_type;
	nexus_meta_subtype_t md_subtype;

	ring = _CHANNEL_OFFSET(struct __user_channel_ring *, csm,
	    csm->csm_ring_ofs[ring_index].ring_off);
	sd = _CHANNEL_OFFSET(struct __slot_desc *, csm,
	    csm->csm_ring_ofs[ring_index].sd_off);
	md_type = csm->csm_md_type;
	md_subtype = csm->csm_md_subtype;

	if (ring == NULL || sd == NULL) {
		SK_ABORT("Channel schema not valid");
		/* NOTREACHED */
		__builtin_unreachable();
	} else if (!(md_type == NEXUS_META_TYPE_QUANTUM ||
	    md_type == NEXUS_META_TYPE_PACKET)) {
		SK_ABORT_WITH_CAUSE("Metadata type unknown", md_type);
		/* NOTREACHED */
		__builtin_unreachable();
	} else if (!(md_subtype == NEXUS_META_SUBTYPE_PAYLOAD ||
	    md_subtype == NEXUS_META_SUBTYPE_RAW)) {
		SK_ABORT_WITH_CAUSE("Metadata subtype unknown", md_subtype);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	chrd->chrd_slot_desc = sd;
	chrd->chrd_csm_flags = &chd->chd_schema->csm_flags;
	/* const overrides */
	*(struct channel **)(uintptr_t)&chrd->chrd_channel = chd;
	*(struct __user_channel_ring **)(uintptr_t)&chrd->chrd_ring = ring;
	*(nexus_meta_type_t *)(uintptr_t)&chrd->chrd_md_type = md_type;
	*(nexus_meta_subtype_t *)(uintptr_t)&chrd->chrd_md_subtype = md_subtype;
	*(mach_vm_address_t *)(uintptr_t)&chrd->chrd_shmem_base_addr =
	    CHD_INFO(chd)->cinfo_mem_base;
	*(mach_vm_address_t *)(uintptr_t)&chrd->chrd_buf_base_addr =
	    (mach_vm_address_t)((uintptr_t)ring + ring->ring_buf_base);
	*(mach_vm_address_t *)(uintptr_t)&chrd->chrd_md_base_addr =
	    (mach_vm_address_t)((uintptr_t)ring + ring->ring_md_base);
	*(mach_vm_address_t *)(uintptr_t)&chrd->chrd_sd_base_addr =
	    (mach_vm_address_t)((uintptr_t)ring + ring->ring_sd_base);
	*(mach_vm_address_t *)(uintptr_t)&chrd->chrd_bft_base_addr =
	    (mach_vm_address_t)((uintptr_t)ring + ring->ring_bft_base);
	*(uint32_t *)(uintptr_t)&chrd->chrd_max_bufs =
	    CHD_PARAMS(chd)->nxp_max_frags;
}

__attribute__((always_inline, visibility("hidden")))
static inline mach_vm_address_t
_initialize_metadata_address(const channel_ring_t chrd,
    struct __user_quantum *q, uint16_t *bdoff)
{
	int i;
	struct __user_buflet *ubft0;
	const struct __user_channel_ring *ring = chrd->chrd_ring;

	switch (chrd->chrd_md_type) {
	case NEXUS_META_TYPE_PACKET: {
		struct __user_buflet *ubft, *pbft;
		struct __user_packet *p = (struct __user_packet *)q;
		uint16_t bcnt = p->pkt_bufs_cnt;
		uint16_t bmax = p->pkt_bufs_max;

		_CASSERT(sizeof(p->pkt_qum_buf.buf_addr) ==
		    sizeof(mach_vm_address_t));
		/*
		 * In the event of a defunct, we'd be accessing zero-filled
		 * memory and end up with 0 for bcnt or bmax.
		 */
		if (__improbable((bcnt == 0) || (bmax == 0))) {
			if (!_CHANNEL_RING_IS_DEFUNCT(chrd)) {
				SK_ABORT("bad bufcnt");
				/* NOTREACHED */
				__builtin_unreachable();
			}
			return 0;
		}
		_PKT_BUFCNT_VERIFY(chrd, bcnt, bmax);
		_CH_PKT_GET_FIRST_BUFLET(p, ubft, chrd, ring);
		if (__improbable(ubft == NULL)) {
			SK_ABORT("bad packet: no buflet");
			/* NOTREACHED */
			__builtin_unreachable();
		}
		/*
		 * special handling for empty packet buflet.
		 */
		if (__improbable(p->pkt_qum_buf.buf_idx == OBJ_IDX_NONE)) {
			*__DECONST(mach_vm_address_t *,
			    &p->pkt_qum_buf.buf_addr) = 0;
			*__DECONST(mach_vm_address_t *,
			    &p->pkt_qum_buf.buf_nbft_addr) =
			    (mach_vm_address_t)ubft;
		}
		ubft0 = ubft;
		for (i = 0; (i < bcnt) && (ubft != NULL); i++) {
			pbft = ubft;
			if (__probable(pbft->buf_idx != OBJ_IDX_NONE)) {
				*(mach_vm_address_t *)(uintptr_t)
				&(pbft->buf_addr) = _CHANNEL_RING_BUF(chrd,
				    ring, pbft->buf_idx);
			} else {
				*(mach_vm_address_t *)(uintptr_t)
				&(pbft->buf_addr) = NULL;
			}
			if (pbft->buf_nbft_idx != OBJ_IDX_NONE) {
				ubft = _CHANNEL_RING_BFT(chrd, ring,
				    pbft->buf_nbft_idx);
			} else {
				ubft = NULL;
			}
			*__DECONST(mach_vm_address_t *, &pbft->buf_nbft_addr) =
			    (mach_vm_address_t)ubft;
		}
		if (__improbable(pbft->buf_nbft_idx != OBJ_IDX_NONE)) {
			if (!_CHANNEL_RING_IS_DEFUNCT(chrd)) {
				SK_ABORT("non terminating buflet chain");
				/* NOTREACHED */
				__builtin_unreachable();
			}
			return 0;
		}
		if (__improbable(i != bcnt)) {
			SK_ABORT_WITH_CAUSE("invalid buflet count", bcnt);
			/* NOTREACHED */
			__builtin_unreachable();
		}
		break;
	}
	default:
		ubft0 = &q->qum_buf[0];
		_CASSERT(sizeof(q->qum_buf[0].buf_addr) ==
		    sizeof(mach_vm_address_t));
		/* immutable: compute pointers from the index */
		*(mach_vm_address_t *)(uintptr_t)&ubft0->buf_addr =
		    _CHANNEL_RING_BUF(chrd, ring, ubft0->buf_idx);
		break;
	}

	/* return address and offset of the first buffer */
	*bdoff = ubft0->buf_doff;
	return ubft0->buf_addr;
}

/*
 * _slot_index_is_valid
 * - verify that the slot index is within valid bounds
 * - if the head is less than (or equal to) the tail (case A below)
 *	head <= valid < tail
 * - if the head is greater than the tail (case B below)
 *      valid < tail
 *    or
 *	head <= valid < num_slots
 *
 * case A: x x x x x x x H o o o o o T x x x x x x
 * case B: o o o o o T x x x x H o o o o o o o o o
 *
 * 'H' - head
 * 'T' - tail
 * 'x' - invalid
 * 'o' - valid
 */
__attribute__((always_inline, visibility("hidden")))
static inline int
_slot_index_is_valid(const struct __user_channel_ring *ring, slot_idx_t idx)
{
	int     is_valid = 0;

	if (ring->ring_head <= ring->ring_tail) {
		if (__probable(idx >= ring->ring_head && idx < ring->ring_tail)) {
			is_valid = 1;
		}
	} else {
		if (__probable(idx < ring->ring_tail ||
		    (idx >= ring->ring_head && idx < ring->ring_num_slots))) {
			is_valid = 1;
		}
	}

	return is_valid;
}

channel_t
os_channel_create_extended(const uuid_t uuid, const nexus_port_t port,
    const ring_dir_t dir, const ring_id_t ring, const channel_attr_t cha)
{
	uint32_t num_tx_rings, num_rx_rings, num_allocator_rings;
	uint32_t ring_offset, ring_index, num_event_rings;
	struct __user_channel_schema *ucs;
	struct channel *chd = NULL;
	struct ch_info *ci = NULL;
	struct ch_init init;
	int i, fd = -1;
	int err = 0;
	size_t chd_sz;

	SK_ALIGN64_CASSERT(struct ch_info, cinfo_mem_map_size);

	switch (dir) {
	case CHANNEL_DIR_TX_RX:
	case CHANNEL_DIR_TX:
	case CHANNEL_DIR_RX:
		break;
	default:
		err = EINVAL;
		goto done;
	}

	ci = malloc(CHD_INFO_SIZE);
	if (ci == NULL) {
		err = errno = ENOMEM;
		goto done;
	}
	bzero(ci, CHD_INFO_SIZE);

	bzero(&init, sizeof(init));
	init.ci_version = CHANNEL_INIT_CURRENT_VERSION;
	if (cha != NULL) {
		if (cha->cha_exclusive != 0) {
			init.ci_ch_mode |= CHMODE_EXCLUSIVE;
		}
		if (cha->cha_user_packet_pool != 0) {
			init.ci_ch_mode |= CHMODE_USER_PACKET_POOL;
		}
		if (cha->cha_nexus_defunct_ok != 0) {
			init.ci_ch_mode |= CHMODE_DEFUNCT_OK;
		}
		if (cha->cha_enable_event_ring != 0) {
			/* User packet pool is required for event rings */
			if (cha->cha_user_packet_pool == 0) {
				err = EINVAL;
				goto done;
			}
			init.ci_ch_mode |= CHMODE_EVENT_RING;
		}
		if (cha->cha_monitor != 0) {
			if (dir == CHANNEL_DIR_TX_RX) {
				init.ci_ch_mode |= CHMODE_MONITOR;
			} else if (dir == CHANNEL_DIR_TX) {
				init.ci_ch_mode |= CHMODE_MONITOR_TX;
			} else if (dir == CHANNEL_DIR_RX) {
				init.ci_ch_mode |= CHMODE_MONITOR_RX;
			}
			if (cha->cha_monitor == CHANNEL_MONITOR_NO_COPY) {
				init.ci_ch_mode |= CHMODE_MONITOR_NO_COPY;
			}
		}
		if (cha->cha_filter != 0) {
			init.ci_ch_mode |= CHMODE_FILTER;
		}
		if (cha->cha_low_latency != 0) {
			init.ci_ch_mode |= CHMODE_LOW_LATENCY;
		}
		init.ci_key_len = cha->cha_key_len;
		init.ci_key = cha->cha_key;
		init.ci_tx_lowat = cha->cha_tx_lowat;
		init.ci_rx_lowat = cha->cha_rx_lowat;
	}
	init.ci_ch_ring_id = ring;
	init.ci_nx_port = port;
	bcopy(uuid, init.ci_nx_uuid, sizeof(uuid_t));

	fd = __channel_open(&init, sizeof(init));
	if (fd == -1) {
		err = errno;
		goto done;
	}

	err = __channel_get_info(fd, ci, CHD_INFO_SIZE);
	if (err != 0) {
		err = errno;
		goto done;
	}

	ucs = _CHANNEL_SCHEMA(ci->cinfo_mem_base, ci->cinfo_schema_offset);
	num_tx_rings = _num_tx_rings(ci);       /* # of channel tx rings */
	num_rx_rings = _num_rx_rings(ci);       /* # of channel rx rings */
	num_allocator_rings = _num_allocator_rings(ucs);
	num_event_rings = ucs->csm_num_event_rings;

	/*
	 * if the user requested packet allocation mode for channel, then
	 * check that channel was opened in packet allocation mode and
	 * allocator rings were created.
	 */
	if ((init.ci_ch_mode & CHMODE_USER_PACKET_POOL) &&
	    ((num_allocator_rings < 2) ||
	    !(ci->cinfo_ch_mode & CHMODE_USER_PACKET_POOL))) {
		err = errno = ENXIO;
		goto done;
	}

	if ((init.ci_ch_mode & CHMODE_EVENT_RING) && ((num_event_rings == 0) ||
	    !(ci->cinfo_ch_mode & CHMODE_EVENT_RING))) {
		err = errno = ENXIO;
		goto done;
	}

	chd_sz = CHD_SIZE(num_tx_rings + num_rx_rings + num_allocator_rings +
	    num_event_rings);
	chd = malloc(chd_sz);
	if (chd == NULL) {
		err = errno = ENOMEM;
		goto done;
	}

	bzero(chd, chd_sz);
	chd->chd_fd = fd;
	chd->chd_guard = init.ci_guard;

	/* claim ch_info (will be freed along with the channel itself) */
	CHD_INFO(chd) = ci;
	ci = NULL;

	/* const override */
	*(struct __user_channel_schema **)(uintptr_t)&chd->chd_schema = ucs;

	/* make sure we're running on the right kernel */
	_SCHEMA_VER_VERIFY(chd);

	*(nexus_meta_type_t *)&chd->chd_md_type = CHD_SCHEMA(chd)->csm_md_type;
	*(nexus_meta_subtype_t *)&chd->chd_md_subtype =
	    CHD_SCHEMA(chd)->csm_md_subtype;

	if (CHD_SCHEMA(chd)->csm_stats_ofs != 0) {
		*(void **)(uintptr_t)&chd->chd_nx_stats =
		    _CHANNEL_OFFSET(void *, CHD_INFO(chd)->cinfo_mem_base,
		    CHD_SCHEMA(chd)->csm_stats_ofs);
	}

	if (CHD_SCHEMA(chd)->csm_flowadv_ofs != 0) {
		*(struct __flowadv_entry **)(uintptr_t)&chd->chd_nx_flowadv =
		    _CHANNEL_OFFSET(struct __flowadv_entry *,
		    CHD_INFO(chd)->cinfo_mem_base,
		    CHD_SCHEMA(chd)->csm_flowadv_ofs);
	}

	if (CHD_SCHEMA(chd)->csm_nexusadv_ofs != 0) {
		struct __kern_nexus_adv_metadata *adv_md;

		*(struct __kern_nexus_adv_metadata **)
		(uintptr_t)&chd->chd_nx_adv =
		    _CHANNEL_OFFSET(struct __kern_nexus_adv_metadata *,
		    CHD_INFO(chd)->cinfo_mem_base,
		    CHD_SCHEMA(chd)->csm_nexusadv_ofs);
		adv_md = CHD_NX_ADV_MD(chd);
		if (adv_md->knam_version != NX_ADVISORY_MD_CURRENT_VERSION &&
		    !_CHANNEL_IS_DEFUNCT(chd)) {
			SK_ABORT_WITH_CAUSE("nexus advisory metadata version"
			    " mismatch", NX_ADVISORY_MD_CURRENT_VERSION);
			/* NOTREACHED */
			__builtin_unreachable();
		}
		if (chd->chd_nx_adv->knam_type == NEXUS_ADVISORY_TYPE_NETIF) {
			struct netif_nexus_advisory *netif_adv;
			netif_adv = CHD_NX_ADV_NETIF(adv_md);
			if (netif_adv->nna_version !=
			    NX_NETIF_ADVISORY_CURRENT_VERSION &&
			    !_CHANNEL_IS_DEFUNCT(chd)) {
				SK_ABORT_WITH_CAUSE("nexus advisory "
				    "version mismatch for netif",
				    NX_NETIF_ADVISORY_CURRENT_VERSION);
				/* NOTREACHED */
				__builtin_unreachable();
			}
		} else if (chd->chd_nx_adv->knam_type ==
		    NEXUS_ADVISORY_TYPE_FLOWSWITCH) {
			struct sk_nexusadv *fsw_adv;
			fsw_adv = CHD_NX_ADV_FSW(adv_md);
			if (fsw_adv->nxadv_ver !=
			    NX_FLOWSWITCH_ADVISORY_CURRENT_VERSION &&
			    !_CHANNEL_IS_DEFUNCT(chd)) {
				SK_ABORT_WITH_CAUSE("nexus advisory "
				    "version mismatch for flowswitch",
				    NX_FLOWSWITCH_ADVISORY_CURRENT_VERSION);
				/* NOTREACHED */
				__builtin_unreachable();
			}
		} else if (!_CHANNEL_IS_DEFUNCT(chd)) {
			SK_ABORT_WITH_CAUSE("nexus advisory metadata type"
			    " unknown", NX_ADVISORY_MD_CURRENT_VERSION);
			/* NOTREACHED */
			__builtin_unreachable();
		}
	}

	if (cha != NULL) {
		os_channel_info2attr(chd, cha);
	}

	ring_offset = 0;
	for (i = 0; i < num_tx_rings; i++) {
		ring_index = ring_offset + i;
		os_channel_init_ring(&chd->chd_rings[ring_index], chd,
		    ring_index);
	}

	ring_offset += num_tx_rings;
	for (i = 0; i < num_rx_rings; i++) {
		ring_index = ring_offset + i;
		os_channel_init_ring(&chd->chd_rings[ring_index], chd,
		    ring_index);
	}

	ring_offset += num_rx_rings;
	for (i = 0; i < num_allocator_rings; i++) {
		ring_index = ring_offset + i;
		os_channel_init_ring(&chd->chd_rings[ring_index], chd,
		    ring_index);
	}

	ring_offset += num_allocator_rings;
	for (i = 0; i < num_event_rings; i++) {
		ring_index = ring_offset + i;
		os_channel_init_ring(&chd->chd_rings[ring_index], chd,
		    ring_index);
	}

	if (init.ci_ch_mode & CHMODE_USER_PACKET_POOL) {
		chd->chd_sync_flags = CHANNEL_SYNCF_ALLOC | CHANNEL_SYNCF_FREE;
		*__DECONST(uint8_t *, &chd->chd_alloc_ring_idx) =
		    num_tx_rings + num_rx_rings;
		if (num_allocator_rings > 2) {
			chd->chd_sync_flags |= CHANNEL_SYNCF_ALLOC_BUF;
			*__DECONST(uint8_t *, &chd->chd_buf_alloc_ring_idx) =
			    chd->chd_alloc_ring_idx + 1;
			*__DECONST(uint8_t *, &chd->chd_free_ring_idx) =
			    chd->chd_buf_alloc_ring_idx + 1;
			*__DECONST(uint8_t *, &chd->chd_buf_free_ring_idx) =
			    chd->chd_free_ring_idx + 1;
		} else {
			*__DECONST(uint8_t *, &chd->chd_buf_alloc_ring_idx) =
			    CHD_RING_IDX_NONE;
			*__DECONST(uint8_t *, &chd->chd_buf_free_ring_idx) =
			    CHD_RING_IDX_NONE;
			*__DECONST(uint8_t *, &chd->chd_free_ring_idx) =
			    chd->chd_alloc_ring_idx + 1;
		}
	} else {
		*__DECONST(uint8_t *, &chd->chd_alloc_ring_idx) =
		    CHD_RING_IDX_NONE;
		*__DECONST(uint8_t *, &chd->chd_free_ring_idx) =
		    CHD_RING_IDX_NONE;
		*__DECONST(uint8_t *, &chd->chd_buf_alloc_ring_idx) =
		    CHD_RING_IDX_NONE;
		*__DECONST(uint8_t *, &chd->chd_buf_free_ring_idx) =
		    CHD_RING_IDX_NONE;
	}

	if (__os_ch_md_redzone_cookie == 0) {
		__os_ch_md_redzone_cookie =
		    CHD_SCHEMA(chd)->csm_md_redzone_cookie;
	}

	/* ensure all stores are globally visible */
	membar_sync();

done:
	if (err != 0) {
		if (fd != -1) {
			(void) guarded_close_np(fd, &init.ci_guard);
		}
		if (chd != NULL) {
			if (CHD_INFO(chd) != NULL) {
				free(CHD_INFO(chd));
				CHD_INFO(chd) = NULL;
			}
			free(chd);
			chd = NULL;
		}
		if (ci != NULL) {
			free(ci);
			ci = NULL;
		}
		errno = err;
	}
	return chd;
}

channel_t
os_channel_create(const uuid_t uuid, const nexus_port_t port)
{
	return os_channel_create_extended(uuid, port, CHANNEL_DIR_TX_RX,
	           CHANNEL_RING_ID_ANY, NULL);
}

int
os_channel_get_fd(const channel_t chd)
{
	return chd->chd_fd;
}

int
os_channel_read_attr(const channel_t chd, channel_attr_t cha)
{
	int err;

	if ((err = __channel_get_info(chd->chd_fd, CHD_INFO(chd),
	    CHD_INFO_SIZE)) == 0) {
		os_channel_info2attr(chd, cha);
	}

	return err;
}

int
os_channel_write_attr(const channel_t chd, channel_attr_t cha)
{
	int err = 0;

	if (CHD_INFO(chd)->cinfo_tx_lowat.cet_unit !=
	    cha->cha_tx_lowat.cet_unit ||
	    CHD_INFO(chd)->cinfo_tx_lowat.cet_value !=
	    cha->cha_tx_lowat.cet_value) {
		if ((err = __channel_set_opt(chd->chd_fd, CHOPT_TX_LOWAT_THRESH,
		    &cha->cha_tx_lowat, sizeof(cha->cha_tx_lowat))) != 0) {
			goto done;
		}

		/* update local copy */
		CHD_INFO(chd)->cinfo_tx_lowat = cha->cha_tx_lowat;
	}

	if (CHD_INFO(chd)->cinfo_rx_lowat.cet_unit !=
	    cha->cha_rx_lowat.cet_unit ||
	    CHD_INFO(chd)->cinfo_rx_lowat.cet_value !=
	    cha->cha_rx_lowat.cet_value) {
		if ((err = __channel_set_opt(chd->chd_fd, CHOPT_RX_LOWAT_THRESH,
		    &cha->cha_rx_lowat, sizeof(cha->cha_rx_lowat))) != 0) {
			goto done;
		}

		/* update local copy */
		CHD_INFO(chd)->cinfo_rx_lowat = cha->cha_rx_lowat;
	}
done:
	return err;
}

int
os_channel_read_nexus_extension_info(const channel_t chd, nexus_type_t *nt,
    uint64_t *ext)
{
	struct nxprov_params *nxp;

	nxp = &CHD_INFO(chd)->cinfo_nxprov_params;
	if (nt != NULL) {
		*nt = nxp->nxp_type;
	}
	if (ext != NULL) {
		*ext = (uint64_t)nxp->nxp_extensions;
	}

	return 0;
}

int
os_channel_sync(const channel_t chd, const sync_mode_t mode)
{
	if (__improbable(mode != CHANNEL_SYNC_TX && mode != CHANNEL_SYNC_RX)) {
		return EINVAL;
	}

	return __channel_sync(chd->chd_fd, mode,
	           (mode == CHANNEL_SYNC_TX) ? chd->chd_sync_flags :
	           (chd->chd_sync_flags &
	           ~(CHANNEL_SYNCF_ALLOC | CHANNEL_SYNCF_ALLOC_BUF)));
}

void
os_channel_destroy(channel_t chd)
{
	if (chd->chd_fd != -1) {
		(void) guarded_close_np(chd->chd_fd, &chd->chd_guard);
	}

	if (CHD_INFO(chd) != NULL) {
		free(CHD_INFO(chd));
		CHD_INFO(chd) = NULL;
	}

	free(chd);
}

int
os_channel_is_defunct(channel_t chd)
{
	return _CHANNEL_IS_DEFUNCT(chd);
}

__attribute__((always_inline, visibility("hidden")))
static inline ring_id_t
_ring_id(struct ch_info *cinfo, const ring_id_type_t type)
{
	ring_id_t rid = CHANNEL_RING_ID_ANY;    /* make it crash */

	switch (type) {
	case CHANNEL_FIRST_TX_RING:
		rid = cinfo->cinfo_first_tx_ring;
		break;

	case CHANNEL_LAST_TX_RING:
		rid = cinfo->cinfo_last_tx_ring;
		break;

	case CHANNEL_FIRST_RX_RING:
		rid = cinfo->cinfo_first_rx_ring;
		break;

	case CHANNEL_LAST_RX_RING:
		rid = cinfo->cinfo_last_rx_ring;
		break;
	}

	return rid;
}

ring_id_t
os_channel_ring_id(const channel_t chd, const ring_id_type_t type)
{
	return _ring_id(CHD_INFO(chd), type);
}

channel_ring_t
os_channel_tx_ring(const channel_t chd, const ring_id_t rid)
{
	struct ch_info *ci = CHD_INFO(chd);

	if (__improbable((ci->cinfo_ch_ring_id != CHANNEL_RING_ID_ANY &&
	    ci->cinfo_ch_ring_id != rid) ||
	    rid < _ring_id(ci, CHANNEL_FIRST_TX_RING) ||
	    rid > _ring_id(ci, CHANNEL_LAST_TX_RING))) {
		return NULL;
	}

	return &chd->chd_rings[rid - _ring_id(ci, CHANNEL_FIRST_TX_RING)];
}

channel_ring_t
os_channel_rx_ring(const channel_t chd, const ring_id_t rid)
{
	struct ch_info *ci = CHD_INFO(chd);

	if (__improbable((ci->cinfo_ch_ring_id != CHANNEL_RING_ID_ANY &&
	    ci->cinfo_ch_ring_id != rid) ||
	    rid < _ring_id(ci, CHANNEL_FIRST_RX_RING) ||
	    rid > _ring_id(ci, CHANNEL_LAST_RX_RING))) {
		return NULL;
	}

	return &chd->chd_rings[_num_tx_rings(ci) +      /* add tx rings */
	       (rid - _ring_id(ci, CHANNEL_FIRST_RX_RING))];
}

/*
 * Return 1 if we have pending transmissions in the tx ring. When everything
 * is complete ring->ring_head == ring->ring_khead.
 */
int
os_channel_pending(const channel_ring_t chrd)
{
	struct __user_channel_ring *ring =
	    __DECONST(struct __user_channel_ring *, chrd->chrd_ring);
	return ring->ring_head != ring->ring_khead;
}

uint64_t
os_channel_ring_sync_time(const channel_ring_t chrd)
{
	return chrd->chrd_ring->ring_sync_time;
}

uint64_t
os_channel_ring_notify_time(const channel_ring_t chrd)
{
	return chrd->chrd_ring->ring_notify_time;
}

uint32_t
os_channel_available_slot_count(const channel_ring_t chrd)
{
	const struct __user_channel_ring *ring = chrd->chrd_ring;
	uint32_t count;
	int n;

	if (ring->ring_kind == CR_KIND_TX) {
		n = ring->ring_head - ring->ring_khead;
		if (n < 0) {
			n += ring->ring_num_slots;
		}
		count = (ring->ring_num_slots - n - 1);
	} else {
		n = ring->ring_tail - ring->ring_head;
		if (n < 0) {
			n += ring->ring_num_slots;
		}
		count = n;
	}
	return __improbable(_CHANNEL_RING_IS_DEFUNCT(chrd)) ? 0 : count;
}

int
os_channel_advance_slot(channel_ring_t chrd, const channel_slot_t slot)
{
	struct __user_channel_ring *ring =
	    __DECONST(struct __user_channel_ring *, chrd->chrd_ring);
	slot_idx_t idx;
	int err;

	idx = _SLOT_INDEX(chrd, slot);
	if (__probable(_slot_index_is_valid(ring, idx))) {
		ring->ring_head = _CHANNEL_RING_NEXT(ring, idx);
		err = 0;
	} else {
		err = (_CHANNEL_RING_IS_DEFUNCT(chrd) ? ENXIO : EINVAL);
	}
	return err;
}

channel_slot_t
os_channel_get_next_slot(const channel_ring_t chrd, const channel_slot_t slot0,
    slot_prop_t *prop)
{
	const struct __user_channel_ring *ring = chrd->chrd_ring;
	const struct __slot_desc *slot;
	slot_idx_t idx;

	if (__probable(slot0 != NULL)) {
		idx = _SLOT_INDEX(chrd, slot0);
		if (__probable(_slot_index_is_valid(ring, idx))) {
			idx = _CHANNEL_RING_NEXT(ring, idx);
		} else if (!_CHANNEL_RING_IS_DEFUNCT(chrd)) {
			/* slot is out of bounds */
			SK_ABORT_WITH_CAUSE("Index out of bounds in gns", idx);
			/* NOTREACHED */
			__builtin_unreachable();
		} else {
			/*
			 * In case of a defunct, pretend as if we've
			 * advanced to the last slot; this will result
			 * in a NULL slot below.
			 */
			idx = ring->ring_tail;
		}
	} else {
		idx = ring->ring_head;
	}

	if (__probable(idx != ring->ring_tail)) {
		slot = &chrd->chrd_slot_desc[idx];
	} else {
		/* we just advanced to the last slot */
		slot = NULL;
	}

	if (__probable(slot != NULL)) {
		uint16_t ring_kind = ring->ring_kind;
		struct __user_quantum *q;
		mach_vm_address_t baddr;
		uint16_t bdoff;

		if (__improbable((ring_kind == CR_KIND_TX) &&
		    (CHD_INFO(chrd->chrd_channel)->cinfo_ch_mode &
		    CHMODE_USER_PACKET_POOL))) {
			if (SD_VALID_METADATA(SLOT_DESC_USD(slot))) {
				SK_ABORT_WITH_CAUSE("Tx slot has attached "
				    "metadata", idx);
				/* NOTREACHED */
				__builtin_unreachable();
			}
			if (prop != NULL) {
				prop->sp_len = 0;
				prop->sp_flags = 0;
				prop->sp_buf_ptr = 0;
				prop->sp_mdata_ptr = 0;
			}
			return __improbable(_CHANNEL_RING_IS_DEFUNCT(chrd)) ?
			       NULL : (channel_slot_t)slot;
		}

		_SLOT_DESC_VERIFY(chrd, SLOT_DESC_USD(slot));
		q = _SLOT_METADATA(chrd, ring, idx);
		_METADATA_VERIFY(chrd, q);

		baddr = _initialize_metadata_address(chrd, q, &bdoff);
		if (__improbable(baddr == 0)) {
			return NULL;
		}
		/* No multi-buflet support for slot based interface */
		if (__probable(prop != NULL)) {
			/* immutable: slot index */
			prop->sp_idx = idx;
			prop->sp_flags = 0;
			prop->sp_buf_ptr = baddr + bdoff;
			prop->sp_mdata_ptr = q;
			/* reset slot length if this is to be used for tx */
			prop->sp_len = (ring_kind == CR_KIND_TX) ?
			    ring->ring_buf_size : q->qum_len;
		}
	}

	return __improbable(_CHANNEL_RING_IS_DEFUNCT(chrd)) ?
	       NULL : (channel_slot_t)slot;
}

void
os_channel_set_slot_properties(const channel_ring_t chrd,
    const channel_slot_t slot, const slot_prop_t *prop)
{
	const struct __user_channel_ring *ring = chrd->chrd_ring;
	slot_idx_t idx = _SLOT_INDEX(chrd, slot);

	if (__probable(_slot_index_is_valid(ring, idx))) {
		struct __user_quantum *q;

		_METADATA_VERIFY(chrd, prop->sp_mdata_ptr);
		_SLOT_DESC_VERIFY(chrd, _SLOT_DESC(chrd, idx));

		/*
		 * In the event of a defunct, we'd be accessing zero-filled
		 * memory; this is fine we ignore all changes made to the
		 * region at that time.
		 */
		q = _SLOT_METADATA(chrd, ring, idx);
		q->qum_len = prop->sp_len;
		switch (chrd->chrd_md_type) {
		case NEXUS_META_TYPE_PACKET: {
			struct __user_packet *p = (struct __user_packet *)q;
			/* No multi-buflet support for slot based interface */
			p->pkt_qum_buf.buf_dlen = prop->sp_len;
			p->pkt_qum_buf.buf_doff = 0;
			break;
		}
		default:
			q->qum_buf[0].buf_dlen = prop->sp_len;
			q->qum_buf[0].buf_doff = 0;
			break;
		}
	} else if (!_CHANNEL_RING_IS_DEFUNCT(chrd)) {
		/* slot is out of bounds */
		SK_ABORT_WITH_CAUSE("Index out of bounds in ssp", idx);
		/* NOTREACHED */
		__builtin_unreachable();
	}
}

packet_t
os_channel_slot_get_packet(const channel_ring_t chrd, const channel_slot_t slot)
{
	const struct __user_channel_ring *ring = chrd->chrd_ring;
	struct __user_quantum *q = NULL;

	if (__probable(slot != NULL)) {
		slot_idx_t idx = _SLOT_INDEX(chrd, slot);
		if (__improbable(!_slot_index_is_valid(ring, idx)) &&
		    !_CHANNEL_RING_IS_DEFUNCT(chrd)) {
			/* slot is out of bounds */
			SK_ABORT_WITH_CAUSE("Index out of bounds in sgp", idx);
			/* NOTREACHED */
			__builtin_unreachable();
		}

		if (__probable(SD_VALID_METADATA(_SLOT_DESC(chrd, idx)))) {
			obj_idx_t midx;
			q = _SLOT_METADATA(chrd, ring, idx);
			_METADATA_VERIFY(chrd, q);
			/*
			 * In the event of a defunct, we'd be accessing
			 * zero-filed memory and end up with 0 for midx;
			 * this is fine since we ignore all changes made
			 * to the region at that time.
			 */
			midx = METADATA_IDX(q);
			_SLOT_METADATA_IDX_VERIFY(chrd, q, midx);
		}
	}

	return (q == NULL) ? 0 :
	       SK_PTR_ENCODE(q, chrd->chrd_md_type, chrd->chrd_md_subtype);
}

void *
os_channel_get_stats_region(const channel_t chd, const channel_stats_id_t id)
{
	void *sp = CHD_NX_STATS(chd);
	struct __nx_stats_fsw *nxs_fsw;
	void *ptr = NULL;

	/* we currently deal only with flowswitch */
	if (sp == NULL ||
	    CHD_SCHEMA(chd)->csm_stats_type != NEXUS_STATS_TYPE_FSW) {
		return NULL;
	}

	nxs_fsw = sp;

	switch (id) {
	case CHANNEL_STATS_ID_IP:
		ptr = &nxs_fsw->nxs_ipstat;
		break;

	case CHANNEL_STATS_ID_IP6:
		ptr = &nxs_fsw->nxs_ip6stat;
		break;

	case CHANNEL_STATS_ID_TCP:
		ptr = &nxs_fsw->nxs_tcpstat;
		break;

	case CHANNEL_STATS_ID_UDP:
		ptr = &nxs_fsw->nxs_udpstat;
		break;

	case CHANNEL_STATS_ID_QUIC:
		ptr = &nxs_fsw->nxs_quicstat;
		break;

	default:
		ptr = NULL;
		break;
	}

	return ptr;
}

void *
os_channel_get_advisory_region(const channel_t chd)
{
	struct __kern_nexus_adv_metadata *adv_md;
	/*
	 * To be backward compatible this API will only return
	 * the advisory region for flowswitch.
	 */
	adv_md = CHD_NX_ADV_MD(chd);
	if (adv_md == NULL ||
	    adv_md->knam_type != NEXUS_ADVISORY_TYPE_FLOWSWITCH) {
		return NULL;
	}
	return CHD_NX_ADV_FSW(adv_md);
}

__attribute__((always_inline, visibility("hidden")))
static inline int
_flowadv_id_equal(struct __flowadv_entry *fe, uuid_t id)
{
	/*
	 * Anticipate a nicely (8-bytes) aligned UUID from
	 * caller; the one in fae_id is always 8-byte aligned.
	 */
	if (__probable(IS_P2ALIGNED(id, sizeof(uint64_t)))) {
		uint64_t *id_64 = (uint64_t *)(uintptr_t)id;
		return fe->fae_id_64[0] == id_64[0] &&
		       fe->fae_id_64[1] == id_64[1];
	} else if (__probable(IS_P2ALIGNED(id, sizeof(uint32_t)))) {
		uint32_t *id_32 = (uint32_t *)(uintptr_t)id;
		return fe->fae_id_32[0] == id_32[0] &&
		       fe->fae_id_32[1] == id_32[1] &&
		       fe->fae_id_32[2] == id_32[2] &&
		       fe->fae_id_32[3] == id_32[3];
	}

	return UUID_COMPARE(fe->fae_id, id);
}

int
os_channel_flow_admissible(const channel_ring_t chrd, uuid_t flow_id,
    const flowadv_idx_t flow_index)
{
	const struct __user_channel_ring *ring = chrd->chrd_ring;
	const struct channel *chd = chrd->chrd_channel;
	struct __flowadv_entry *fe = CHD_NX_FLOWADV(chd);

	/*
	 * Currently, flow advisory is on a per-nexus port basis.
	 * To anticipate for future requirements, we use the ring
	 * as parameter instead, even though we use it only to
	 * check if this is a TX ring for now.
	 */
	if (__improbable(CHD_NX_FLOWADV(chd) == NULL)) {
		return ENXIO;
	} else if (__improbable(ring->ring_kind != CR_KIND_TX ||
	    flow_index >= CHD_PARAMS(chd)->nxp_flowadv_max)) {
		return EINVAL;
	}

	/*
	 * Rather than checking if the UUID is all zeroes, check
	 * against fae_flags since the presence of FLOWADV_VALID
	 * means fae_id is non-zero.  This avoids another round of
	 * comparison against zeroes.
	 */
	fe = &CHD_NX_FLOWADV(chd)[flow_index];
	if (__improbable(fe->fae_flags == 0 || !_flowadv_id_equal(fe, flow_id))) {
		return ENOENT;
	}

	return __improbable((fe->fae_flags & FLOWADVF_SUSPENDED) != 0) ?
	       ENOBUFS: 0;
}

channel_attr_t
os_channel_attr_create(void)
{
	struct channel_attr *cha;

	cha = malloc(sizeof(*cha));
	if (cha != NULL) {
		bzero(cha, sizeof(*cha));
	}
	return cha;
}

channel_attr_t
os_channel_attr_clone(const channel_attr_t cha)
{
	struct channel_attr *ncha;

	ncha = os_channel_attr_create();
	if (ncha != NULL && cha != NULL) {
		bcopy(cha, ncha, sizeof(*ncha));
		ncha->cha_key = NULL;
		ncha->cha_key_len = 0;
		if (cha->cha_key != NULL && cha->cha_key_len != 0 &&
		    os_channel_attr_set_key(ncha, cha->cha_key,
		    cha->cha_key_len) != 0) {
			os_channel_attr_destroy(ncha);
			ncha = NULL;
		}
	}

	return ncha;
}

int
os_channel_attr_set(const channel_attr_t cha, const channel_attr_type_t type,
    const uint64_t value)
{
	int err = 0;

	switch (type) {
	case CHANNEL_ATTR_TX_RINGS:
	case CHANNEL_ATTR_RX_RINGS:
	case CHANNEL_ATTR_TX_SLOTS:
	case CHANNEL_ATTR_RX_SLOTS:
	case CHANNEL_ATTR_SLOT_BUF_SIZE:
	case CHANNEL_ATTR_SLOT_META_SIZE:
	case CHANNEL_ATTR_NEXUS_EXTENSIONS:
	case CHANNEL_ATTR_NEXUS_MHINTS:
	case CHANNEL_ATTR_NEXUS_IFINDEX:
	case CHANNEL_ATTR_NEXUS_STATS_SIZE:
	case CHANNEL_ATTR_NEXUS_FLOWADV_MAX:
	case CHANNEL_ATTR_NEXUS_META_TYPE:
	case CHANNEL_ATTR_NEXUS_META_SUBTYPE:
	case CHANNEL_ATTR_NEXUS_CHECKSUM_OFFLOAD:
	case CHANNEL_ATTR_NEXUS_ADV_SIZE:
	case CHANNEL_ATTR_MAX_FRAGS:
	case CHANNEL_ATTR_NUM_BUFFERS:
		err = ENOTSUP;
		break;

	case CHANNEL_ATTR_EXCLUSIVE:
		cha->cha_exclusive = (uint32_t)value;
		break;

	case CHANNEL_ATTR_NO_AUTO_SYNC:
		if (value == 0) {
			err = ENOTSUP;
		}
		break;

	case CHANNEL_ATTR_MONITOR:
		switch (value) {
		case CHANNEL_MONITOR_OFF:
		case CHANNEL_MONITOR_NO_COPY:
		case CHANNEL_MONITOR_COPY:
			cha->cha_monitor = (uint32_t)value;
			goto done;
		}
		err = EINVAL;
		break;

	case CHANNEL_ATTR_TX_LOWAT_UNIT:
	case CHANNEL_ATTR_RX_LOWAT_UNIT:
		switch (value) {
		case CHANNEL_THRESHOLD_UNIT_BYTES:
		case CHANNEL_THRESHOLD_UNIT_SLOTS:
			if (type == CHANNEL_ATTR_TX_LOWAT_UNIT) {
				cha->cha_tx_lowat.cet_unit =
				    (channel_threshold_unit_t)value;
			} else {
				cha->cha_rx_lowat.cet_unit =
				    (channel_threshold_unit_t)value;
			}
			goto done;
		}
		err = EINVAL;
		break;

	case CHANNEL_ATTR_TX_LOWAT_VALUE:
		cha->cha_tx_lowat.cet_value = (uint32_t)value;
		break;

	case CHANNEL_ATTR_RX_LOWAT_VALUE:
		cha->cha_rx_lowat.cet_value = (uint32_t)value;
		break;

	case CHANNEL_ATTR_USER_PACKET_POOL:
		cha->cha_user_packet_pool = (value != 0);
		break;

	case CHANNEL_ATTR_NEXUS_DEFUNCT_OK:
		cha->cha_nexus_defunct_ok = (value != 0);
		break;

	case CHANNEL_ATTR_FILTER:
		cha->cha_filter = (uint32_t)value;
		break;

	case CHANNEL_ATTR_EVENT_RING:
		cha->cha_enable_event_ring = (value != 0);
		break;

	case CHANNEL_ATTR_LOW_LATENCY:
		cha->cha_low_latency = (value != 0);
		break;

	default:
		err = EINVAL;
		break;
	}
done:
	return err;
}

int
os_channel_attr_set_key(const channel_attr_t cha, const void *key,
    const uint32_t key_len)
{
	int err = 0;

	if ((key == NULL && key_len != 0) || (key != NULL && key_len == 0) ||
	    (key_len != 0 && key_len > NEXUS_MAX_KEY_LEN)) {
		err = EINVAL;
		goto done;
	}
	cha->cha_key_len = 0;
	if (key_len == 0 && cha->cha_key != NULL) {
		free(cha->cha_key);
		cha->cha_key = NULL;
	} else if (key != NULL && key_len != 0) {
		if (cha->cha_key != NULL) {
			free(cha->cha_key);
		}
		if ((cha->cha_key = malloc(key_len)) == NULL) {
			err = ENOMEM;
			goto done;
		}
		cha->cha_key_len = key_len;
		bcopy(key, cha->cha_key, key_len);
	}
done:
	return err;
}

int
os_channel_attr_get(const channel_attr_t cha, const channel_attr_type_t type,
    uint64_t *value)
{
	int err = 0;

	switch (type) {
	case CHANNEL_ATTR_TX_RINGS:
		*value = cha->cha_tx_rings;
		break;

	case CHANNEL_ATTR_RX_RINGS:
		*value = cha->cha_rx_rings;
		break;

	case CHANNEL_ATTR_TX_SLOTS:
		*value = cha->cha_tx_slots;
		break;

	case CHANNEL_ATTR_RX_SLOTS:
		*value = cha->cha_rx_slots;
		break;

	case CHANNEL_ATTR_SLOT_BUF_SIZE:
		*value = cha->cha_buf_size;
		break;

	case CHANNEL_ATTR_SLOT_META_SIZE:
		*value = cha->cha_meta_size;
		break;

	case CHANNEL_ATTR_NEXUS_STATS_SIZE:
		*value = cha->cha_stats_size;
		break;

	case CHANNEL_ATTR_NEXUS_FLOWADV_MAX:
		*value = cha->cha_flowadv_max;
		break;

	case CHANNEL_ATTR_EXCLUSIVE:
		*value = cha->cha_exclusive;
		break;

	case CHANNEL_ATTR_NO_AUTO_SYNC:
		*value = 1;
		break;

	case CHANNEL_ATTR_MONITOR:
		*value = cha->cha_monitor;
		break;

	case CHANNEL_ATTR_TX_LOWAT_UNIT:
		*value = cha->cha_tx_lowat.cet_unit;
		break;

	case CHANNEL_ATTR_TX_LOWAT_VALUE:
		*value = cha->cha_tx_lowat.cet_value;
		break;

	case CHANNEL_ATTR_RX_LOWAT_UNIT:
		*value = cha->cha_rx_lowat.cet_unit;
		break;

	case CHANNEL_ATTR_RX_LOWAT_VALUE:
		*value = cha->cha_rx_lowat.cet_value;
		break;

	case CHANNEL_ATTR_NEXUS_TYPE:
		*value = cha->cha_nexus_type;
		break;

	case CHANNEL_ATTR_NEXUS_EXTENSIONS:
		*value = cha->cha_nexus_extensions;
		break;

	case CHANNEL_ATTR_NEXUS_MHINTS:
		*value = cha->cha_nexus_mhints;
		break;

	case CHANNEL_ATTR_NEXUS_IFINDEX:
		*value = cha->cha_nexus_ifindex;
		break;

	case CHANNEL_ATTR_NEXUS_META_TYPE:
		*value = cha->cha_nexus_meta_type;
		break;

	case CHANNEL_ATTR_NEXUS_META_SUBTYPE:
		*value = cha->cha_nexus_meta_subtype;
		break;

	case CHANNEL_ATTR_NEXUS_CHECKSUM_OFFLOAD:
		*value = cha->cha_nexus_checksum_offload;
		break;

	case CHANNEL_ATTR_USER_PACKET_POOL:
		*value = (cha->cha_user_packet_pool != 0);
		break;

	case CHANNEL_ATTR_NEXUS_ADV_SIZE:
		*value = cha->cha_nexusadv_size;
		break;

	case CHANNEL_ATTR_NEXUS_DEFUNCT_OK:
		*value = cha->cha_nexus_defunct_ok;
		break;

	case CHANNEL_ATTR_EVENT_RING:
		*value = (cha->cha_enable_event_ring != 0);
		break;

	case CHANNEL_ATTR_MAX_FRAGS:
		*value = cha->cha_max_frags;
		break;

	case CHANNEL_ATTR_NUM_BUFFERS:
		*value = cha->cha_num_buffers;
		break;

	case CHANNEL_ATTR_LOW_LATENCY:
		*value = (cha->cha_low_latency != 0);
		break;

	default:
		err = EINVAL;
		break;
	}

	return err;
}

int
os_channel_attr_get_key(const channel_attr_t cha, void *key,
    uint32_t *key_len)
{
	int err = 0;

	if (key_len == NULL) {
		err = EINVAL;
		goto done;
	} else if (key == NULL || cha->cha_key == NULL) {
		*key_len = (cha->cha_key != NULL) ? cha->cha_key_len : 0;
		goto done;
	}

	if (*key_len >= cha->cha_key_len) {
		bcopy(cha->cha_key, key, cha->cha_key_len);
		*key_len = cha->cha_key_len;
	} else {
		err = ENOMEM;
	}
done:
	return err;
}

__attribute__((visibility("hidden")))
static void
os_channel_info2attr(struct channel *chd, channel_attr_t cha)
{
	struct ch_info *cinfo = CHD_INFO(chd);
	/* Save these first before we wipe out the attribute */
	uint32_t cha_key_len = cha->cha_key_len;
	void *cha_key = cha->cha_key;
	uint32_t caps;

	_CASSERT(NEXUS_META_TYPE_INVALID == CHANNEL_NEXUS_META_TYPE_INVALID);
	_CASSERT(NEXUS_META_TYPE_QUANTUM == CHANNEL_NEXUS_META_TYPE_QUANTUM);
	_CASSERT(NEXUS_META_TYPE_PACKET == CHANNEL_NEXUS_META_TYPE_PACKET);
	_CASSERT(NEXUS_META_SUBTYPE_INVALID ==
	    CHANNEL_NEXUS_META_SUBTYPE_INVALID);
	_CASSERT(NEXUS_META_SUBTYPE_PAYLOAD ==
	    CHANNEL_NEXUS_META_SUBTYPE_PAYLOAD);
	_CASSERT(NEXUS_META_SUBTYPE_RAW == CHANNEL_NEXUS_META_SUBTYPE_RAW);

	bzero(cha, sizeof(*cha));
	cha->cha_tx_rings = CHD_PARAMS(chd)->nxp_tx_rings;
	cha->cha_rx_rings = CHD_PARAMS(chd)->nxp_rx_rings;
	cha->cha_tx_slots = CHD_PARAMS(chd)->nxp_tx_slots;
	cha->cha_rx_slots = CHD_PARAMS(chd)->nxp_rx_slots;
	cha->cha_buf_size = CHD_PARAMS(chd)->nxp_buf_size;
	cha->cha_meta_size = CHD_PARAMS(chd)->nxp_meta_size;
	cha->cha_stats_size = CHD_PARAMS(chd)->nxp_stats_size;
	cha->cha_flowadv_max = CHD_PARAMS(chd)->nxp_flowadv_max;
	cha->cha_exclusive = !!(cinfo->cinfo_ch_mode & CHMODE_EXCLUSIVE);
	cha->cha_user_packet_pool = !!(cinfo->cinfo_ch_mode &
	    CHMODE_USER_PACKET_POOL);
	cha->cha_nexus_defunct_ok = !!(cinfo->cinfo_ch_mode &
	    CHMODE_DEFUNCT_OK);
	cha->cha_nexusadv_size = CHD_PARAMS(chd)->nxp_nexusadv_size;
	if (cinfo->cinfo_ch_mode & CHMODE_MONITOR) {
		cha->cha_monitor =
		    (cinfo->cinfo_ch_mode & CHMODE_MONITOR_NO_COPY) ?
		    CHANNEL_MONITOR_NO_COPY : CHANNEL_MONITOR_COPY;
	} else {
		cha->cha_monitor = CHANNEL_MONITOR_OFF;
	}
	cha->cha_key_len = cha_key_len;
	cha->cha_key = cha_key;
	cha->cha_tx_lowat = cinfo->cinfo_tx_lowat;
	cha->cha_rx_lowat = cinfo->cinfo_rx_lowat;
	cha->cha_nexus_type = CHD_PARAMS(chd)->nxp_type;
	cha->cha_nexus_extensions = CHD_PARAMS(chd)->nxp_extensions;
	cha->cha_nexus_mhints = CHD_PARAMS(chd)->nxp_mhints;
	cha->cha_nexus_ifindex = CHD_PARAMS(chd)->nxp_ifindex;
	cha->cha_nexus_meta_type = chd->chd_md_type;
	cha->cha_nexus_meta_subtype = chd->chd_md_subtype;
	cha->cha_enable_event_ring =
	    (cinfo->cinfo_ch_mode & CHMODE_EVENT_RING) != 0;
	cha->cha_low_latency =
	    (cinfo->cinfo_ch_mode & CHMODE_LOW_LATENCY) != 0;

	caps = CHD_PARAMS(chd)->nxp_capabilities;
	if (caps & NXPCAP_CHECKSUM_PARTIAL) {
		cha->cha_nexus_checksum_offload =
		    CHANNEL_NEXUS_CHECKSUM_PARTIAL;
	} else {
		cha->cha_nexus_checksum_offload = 0;
	}
	cha->cha_max_frags = CHD_PARAMS(chd)->nxp_max_frags;
	cha->cha_num_buffers = cinfo->cinfo_num_bufs;
}

void
os_channel_attr_destroy(channel_attr_t cha)
{
	if (cha->cha_key != NULL) {
		free(cha->cha_key);
		cha->cha_key = NULL;
	}
	free(cha);
}

int
os_channel_packet_alloc(const channel_t chd, packet_t *ph)
{
	struct __user_channel_ring *ring;
	struct channel_ring_desc *chrd;
	struct __user_quantum *q;
	slot_idx_t idx;
	mach_vm_address_t baddr;
	uint16_t bdoff;
	struct ch_info *ci = CHD_INFO(chd);

	if (__improbable((ci->cinfo_ch_mode & CHMODE_USER_PACKET_POOL) == 0)) {
		return ENOTSUP;
	}

	chrd = &chd->chd_rings[chd->chd_alloc_ring_idx];
	ring = __DECONST(struct __user_channel_ring *, chrd->chrd_ring);
	idx = ring->ring_head;

	if (__improbable(idx == ring->ring_tail)) {
		/*
		 * do a sync to get more packets;
		 * since we are paying the cost of a syscall do a sync for
		 * free ring as well.
		 */
		int err;
		err = __channel_sync(chd->chd_fd, CHANNEL_SYNC_UPP,
		    (chd->chd_sync_flags & ~CHANNEL_SYNCF_ALLOC_BUF));
		if (__improbable(err != 0)) {
			if (!_CHANNEL_IS_DEFUNCT(chd)) {
				SK_ABORT_WITH_CAUSE("packet pool alloc "
				    "sync failed", err);
				/* NOTREACHED */
				__builtin_unreachable();
			}
			return err;
		}
	}

	if (__improbable(idx == ring->ring_tail)) {
		return __improbable(_CHANNEL_IS_DEFUNCT(chd)) ?
		       ENXIO : ENOMEM;
	}

	_SLOT_DESC_VERIFY(chrd, _SLOT_DESC(chrd, idx));
	q = _SLOT_METADATA(chrd, ring, idx);
	_METADATA_VERIFY(chrd, q);

	*ph = SK_PTR_ENCODE(q, chrd->chrd_md_type, chrd->chrd_md_subtype);
	_SLOT_DETACH_METADATA(_SLOT_DESC(chrd, idx));

	/*
	 * Initialize the metadata buffer address. In the event of a
	 * defunct, we'd be accessing zero-filled memory; this is fine
	 * since we ignore all changes made to region at that time.
	 */
	baddr = _initialize_metadata_address(chrd, q, &bdoff);
	if (__improbable(baddr == 0)) {
		return ENXIO;
	}
	ring->ring_head = _CHANNEL_RING_NEXT(ring, idx);
	return __improbable(_CHANNEL_IS_DEFUNCT(chd)) ? ENXIO : 0;
}

int
os_channel_packet_free(const channel_t chd, packet_t ph)
{
	struct __user_channel_ring *ring;
	struct channel_ring_desc *chrd;
	slot_idx_t idx;
	obj_idx_t midx;
	struct ch_info *ci = CHD_INFO(chd);

	if (__improbable((ci->cinfo_ch_mode & CHMODE_USER_PACKET_POOL) == 0)) {
		return ENOTSUP;
	}

	chrd = &chd->chd_rings[chd->chd_free_ring_idx];
	ring = __DECONST(struct __user_channel_ring *, chrd->chrd_ring);

	idx = ring->ring_head;
	if (__improbable(idx == ring->ring_tail)) {
		/*
		 * do a sync to reclaim space in free ring;
		 */
		int err;
		err = __channel_sync(chd->chd_fd, CHANNEL_SYNC_UPP,
		    CHANNEL_SYNCF_FREE);
		if (__improbable(err != 0) && !_CHANNEL_IS_DEFUNCT(chd)) {
			SK_ABORT_WITH_CAUSE("packet pool free "
			    "sync failed", err);
			/* NOTREACHED */
			__builtin_unreachable();
		}
	}

	if (__improbable(idx == ring->ring_tail) && !_CHANNEL_IS_DEFUNCT(chd)) {
		SK_ABORT("no free ring space");
		/* NOTREACHED */
		__builtin_unreachable();
	}

	/*
	 * In the event of a defunct, midx will be 0 and we'll end up
	 * attaching it to the slot; this is fine since we ignore all
	 * changes made to the slot descriptors at that time.
	 */
	midx = METADATA_IDX(QUM_ADDR(ph));
	_SLOT_METADATA_IDX_VERIFY(chrd, QUM_ADDR(ph), midx);
	_SLOT_ATTACH_METADATA(_SLOT_DESC(chrd, idx), midx);
	ring->ring_head = _CHANNEL_RING_NEXT(ring, idx);

	return __improbable(_CHANNEL_RING_IS_DEFUNCT(chrd)) ? ENXIO : 0;
}

int
os_channel_slot_attach_packet(const channel_ring_t chrd,
    const channel_slot_t slot, packet_t ph)
{
	slot_idx_t idx;
	obj_idx_t midx;

	if (__improbable((chrd->chrd_channel->chd_info->cinfo_ch_mode &
	    CHMODE_USER_PACKET_POOL) == 0)) {
		return ENOTSUP;
	}

	if (__improbable(!__packet_is_finalized(ph))) {
		if (!_CHANNEL_RING_IS_DEFUNCT(chrd)) {
			SK_ABORT("packet not finalized");
			/* NOTREACHED */
			__builtin_unreachable();
		}
		goto done;
	}

	idx = _SLOT_INDEX(chrd, slot);
	if (__improbable(!_slot_index_is_valid(chrd->chrd_ring, idx))) {
		if (!_CHANNEL_RING_IS_DEFUNCT(chrd)) {
			SK_ABORT_WITH_CAUSE("Invalid slot", slot);
			/* NOTREACHED */
			__builtin_unreachable();
		}
		goto done;
	}

	if (__improbable(SD_VALID_METADATA(SLOT_DESC_USD(slot)))) {
		if (!_CHANNEL_RING_IS_DEFUNCT(chrd)) {
			SK_ABORT_WITH_CAUSE("Slot has attached packet", slot);
			/* NOTREACHED */
			__builtin_unreachable();
		}
		goto done;
	}

	/*
	 * In the event of a defunct, midx will be 0 and we'll end up
	 * attaching it to the slot; this is fine since we ignore all
	 * changes made to the slot descriptors at that time.
	 */
	midx = METADATA_IDX(QUM_ADDR(ph));
	_SLOT_METADATA_IDX_VERIFY(chrd, QUM_ADDR(ph), midx);
	_SLOT_ATTACH_METADATA(SLOT_DESC_USD(slot), midx);

done:
	return __improbable(_CHANNEL_RING_IS_DEFUNCT(chrd)) ? ENXIO : 0;
}

int
os_channel_slot_detach_packet(const channel_ring_t chrd,
    const channel_slot_t slot, packet_t ph)
{
	slot_idx_t idx;

	if (__improbable((chrd->chrd_channel->chd_info->cinfo_ch_mode &
	    CHMODE_USER_PACKET_POOL) == 0)) {
		return ENOTSUP;
	}

	idx = _SLOT_INDEX(chrd, slot);
	if (__improbable(!_slot_index_is_valid(chrd->chrd_ring, idx))) {
		if (!_CHANNEL_RING_IS_DEFUNCT(chrd)) {
			SK_ABORT_WITH_CAUSE("Invalid slot", slot);
			/* NOTREACHED */
			__builtin_unreachable();
		}
		goto done;
	}

	if (__improbable(!SD_VALID_METADATA(SLOT_DESC_USD(slot)))) {
		if (!_CHANNEL_RING_IS_DEFUNCT(chrd)) {
			SK_ABORT_WITH_CAUSE("Slot has no attached packet",
			    slot);
			/* NOTREACHED */
			__builtin_unreachable();
		}
		goto done;
	}

	if (__improbable(ph != SK_PTR_ENCODE(_SLOT_METADATA(chrd,
	    chrd->chrd_ring, idx), chrd->chrd_md_type,
	    chrd->chrd_md_subtype))) {
		if (!_CHANNEL_RING_IS_DEFUNCT(chrd)) {
			SK_ABORT("packet handle mismatch");
			/* NOTREACHED */
			__builtin_unreachable();
		}
		goto done;
	}

	if (__improbable(!__packet_is_finalized(ph))) {
		if (!_CHANNEL_RING_IS_DEFUNCT(chrd)) {
			SK_ABORT("packet not finalized");
			/* NOTREACHED */
			__builtin_unreachable();
		}
		goto done;
	}

	/*
	 * In the event of a defunct, we ignore any changes made to
	 * the slot descriptors, and so doing this is harmless.
	 */
	_SLOT_DETACH_METADATA(SLOT_DESC_USD(slot));

done:
	return __improbable(_CHANNEL_RING_IS_DEFUNCT(chrd)) ? ENXIO : 0;
}

__attribute__((visibility("hidden")))
static inline int
os_channel_purge_packet_alloc_ring(const channel_t chd)
{
	struct __user_channel_ring *ring;
	struct channel_ring_desc *chrd;
	uint32_t curr_ws;
	slot_idx_t idx;
	packet_t ph;
	int npkts, err;

	chrd = &chd->chd_rings[chd->chd_alloc_ring_idx];
	ring = __DECONST(struct __user_channel_ring *, chrd->chrd_ring);
	idx = ring->ring_head;

	/* calculate the number of packets in alloc pool */
	npkts = ring->ring_tail - idx;
	if (npkts < 0) {
		npkts += ring->ring_num_slots;
	}

	curr_ws = ring->ring_alloc_ws;
	while ((uint32_t)npkts-- > curr_ws) {
		struct __user_quantum *q;

		_SLOT_DESC_VERIFY(chrd, _SLOT_DESC(chrd, idx));
		q = _SLOT_METADATA(chrd, ring, idx);
		_METADATA_VERIFY(chrd, q);

		ph = SK_PTR_ENCODE(q, chrd->chrd_md_type,
		    chrd->chrd_md_subtype);
		_SLOT_DETACH_METADATA(_SLOT_DESC(chrd, idx));

		/*
		 * Initialize the metadata buffer address. In the event of a
		 * defunct, we'd be accessing zero-filled memory; this is fine
		 * since we ignore all changes made to region at that time.
		 */
		if (chrd->chrd_md_type == NEXUS_META_TYPE_PACKET) {
			struct __user_packet *p = (struct __user_packet *)q;
			uint16_t bcnt = p->pkt_bufs_cnt;
			uint16_t bmax = p->pkt_bufs_max;

			if (__improbable((bcnt == 0) || (bmax == 0))) {
				if (!_CHANNEL_RING_IS_DEFUNCT(chrd)) {
					SK_ABORT("pkt pool purge, bad bufcnt");
					/* NOTREACHED */
					__builtin_unreachable();
				} else {
					return ENXIO;
				}
			}
			/*
			 * alloc ring will not have multi-buflet packets.
			 */
			_PKT_BUFCNT_VERIFY(chrd, bcnt, 1);
		}
		*(mach_vm_address_t *) (uintptr_t)&q->qum_buf[0].buf_addr =
		    _CHANNEL_RING_BUF(chrd, ring, q->qum_buf[0].buf_idx);
		idx = _CHANNEL_RING_NEXT(ring, idx);
		ring->ring_head = idx;
		err = os_channel_packet_free(chd, ph);
		if (__improbable(err != 0)) {
			if (!_CHANNEL_IS_DEFUNCT(chd)) {
				SK_ABORT_WITH_CAUSE("packet pool purge "
				    "free failed", err);
				/* NOTREACHED */
				__builtin_unreachable();
			}
			return err;
		}
	}

	return 0;
}

__attribute__((visibility("hidden")))
static inline int
os_channel_purge_buflet_alloc_ring(const channel_t chd)
{
	struct __user_channel_ring *ring;
	struct channel_ring_desc *chrd;
	uint32_t curr_ws;
	slot_idx_t idx;
	int nbfts, err;

	chrd = &chd->chd_rings[chd->chd_buf_alloc_ring_idx];
	ring = __DECONST(struct __user_channel_ring *, chrd->chrd_ring);
	idx = ring->ring_head;

	/* calculate the number of packets in alloc pool */
	nbfts = ring->ring_tail - idx;
	if (nbfts < 0) {
		nbfts += ring->ring_num_slots;
	}

	curr_ws = ring->ring_alloc_ws;
	while ((uint32_t)nbfts-- > curr_ws) {
		struct __user_buflet *ubft;
		obj_idx_t nbft_idx;

		_SLOT_DESC_VERIFY(chrd, _SLOT_DESC(chrd, idx));
		ubft = _SLOT_BFT_METADATA(chrd, ring, idx);
		_SLOT_DETACH_METADATA(_SLOT_DESC(chrd, idx));

		/*
		 * Initialize the buflet metadata buffer address.
		 */
		*(mach_vm_address_t *)(uintptr_t)&(ubft->buf_addr) =
		    _CHANNEL_RING_BUF(chrd, ring, ubft->buf_idx);
		if (__improbable(ubft->buf_addr == 0)) {
			SK_ABORT_WITH_CAUSE("buflet with NULL buffer",
			    ubft->buf_idx);
			/* NOTREACHED */
			__builtin_unreachable();
		}

		nbft_idx = ubft->buf_nbft_idx;
		if (__improbable(nbft_idx != OBJ_IDX_NONE)) {
			if (_CHANNEL_IS_DEFUNCT(chd)) {
				return ENXIO;
			} else {
				SK_ABORT_WITH_CAUSE("buflet with invalid nidx",
				    nbft_idx);
				/* NOTREACHED */
				__builtin_unreachable();
			}
		}

		idx = _CHANNEL_RING_NEXT(ring, idx);
		ring->ring_head = idx;
		err = os_channel_buflet_free(chd, ubft);
		if (__improbable(err != 0)) {
			if (!_CHANNEL_IS_DEFUNCT(chd)) {
				SK_ABORT_WITH_CAUSE("buflet pool purge "
				    "free failed", err);
				/* NOTREACHED */
				__builtin_unreachable();
			}
			return err;
		}
	}

	return 0;
}

int
os_channel_packet_pool_purge(const channel_t chd)
{
	struct ch_info *ci = CHD_INFO(chd);
	int err;

	if (__improbable((ci->cinfo_ch_mode & CHMODE_USER_PACKET_POOL) == 0)) {
		return ENOTSUP;
	}

	err = __channel_sync(chd->chd_fd, CHANNEL_SYNC_UPP,
	    (chd->chd_sync_flags | ~CHANNEL_SYNCF_FREE | CHANNEL_SYNCF_PURGE));
	if (__improbable(err != 0)) {
		if (!_CHANNEL_IS_DEFUNCT(chd)) {
			SK_ABORT_WITH_CAUSE("packet pool purge sync failed",
			    err);
			/* NOTREACHED */
			__builtin_unreachable();
		}
		return err;
	}

	err = os_channel_purge_packet_alloc_ring(chd);
	if (__improbable(err != 0)) {
		return err;
	}

	if (_num_allocator_rings(CHD_SCHEMA(chd)) > 2) {
		err = os_channel_purge_buflet_alloc_ring(chd);
		if (__improbable(err != 0)) {
			return err;
		}
	}

	err = __channel_sync(chd->chd_fd, CHANNEL_SYNC_UPP, CHANNEL_SYNCF_FREE);
	if (__improbable(err != 0)) {
		if (!_CHANNEL_IS_DEFUNCT(chd)) {
			SK_ABORT_WITH_CAUSE("packet pool free sync failed",
			    err);
			/* NOTREACHED */
			__builtin_unreachable();
		}
		return err;
	}

	return __improbable(_CHANNEL_IS_DEFUNCT(chd)) ? ENXIO : 0;
}

int
os_channel_get_next_event_handle(const channel_t chd,
    os_channel_event_handle_t *ehandle, os_channel_event_type_t *etype,
    uint32_t *nevents)
{
	struct __kern_channel_event_metadata *emd;
	struct __user_channel_ring *ring;
	struct channel_ring_desc *chrd;
	struct __user_quantum *qum;
	mach_vm_address_t baddr;
	uint16_t bdoff;
	slot_idx_t idx;
	struct __user_channel_schema *csm = CHD_SCHEMA(chd);
	struct ch_info *ci = CHD_INFO(chd);

	if (__improbable((ehandle == NULL) || (etype == NULL) ||
	    (nevents == NULL))) {
		return EINVAL;
	}
	if (__improbable((ci->cinfo_ch_mode & CHMODE_EVENT_RING) == 0)) {
		return ENOTSUP;
	}
	*ehandle = NULL;
	chrd = &chd->chd_rings[_num_tx_rings(ci) + _num_rx_rings(ci) +
	    _num_allocator_rings(csm)];
	ring = __DECONST(struct __user_channel_ring *, chrd->chrd_ring);
	idx = ring->ring_head;

	if (__improbable(idx == ring->ring_tail)) {
		return __improbable(_CHANNEL_IS_DEFUNCT(chd)) ?
		       ENXIO : ENODATA;
	}
	_SLOT_DESC_VERIFY(chrd, _SLOT_DESC(chrd, idx));
	qum = _SLOT_METADATA(chrd, ring, idx);
	_METADATA_VERIFY(chrd, qum);
	_SLOT_DETACH_METADATA(_SLOT_DESC(chrd, idx));

	baddr = _initialize_metadata_address(chrd, qum, &bdoff);
	if (__improbable(baddr == 0)) {
		return ENXIO;
	}
	*ehandle = SK_PTR_ENCODE(qum, chrd->chrd_md_type,
	    chrd->chrd_md_subtype);
	emd = (void *)(baddr + bdoff);
	*etype = emd->emd_etype;
	*nevents = emd->emd_nevents;
	ring->ring_head = _CHANNEL_RING_NEXT(ring, idx);
	return __improbable(_CHANNEL_IS_DEFUNCT(chd)) ? ENXIO : 0;
}

int
os_channel_event_free(const channel_t chd, os_channel_event_handle_t ehandle)
{
	return os_channel_packet_free(chd, (packet_t)ehandle);
}

int
os_channel_get_interface_advisory(const channel_t chd,
    struct ifnet_interface_advisory *advisory)
{
	struct __kern_netif_intf_advisory *intf_adv;
	struct __kern_nexus_adv_metadata *adv_md;
	nexus_advisory_type_t adv_type;

	/*
	 * Interface advisory is only supported for netif and flowswitch.
	 */
	adv_md = CHD_NX_ADV_MD(chd);
	if (adv_md == NULL) {
		return ENOENT;
	}
	adv_type = adv_md->knam_type;
	if (__improbable(adv_type != NEXUS_ADVISORY_TYPE_NETIF &&
	    adv_type != NEXUS_ADVISORY_TYPE_FLOWSWITCH)) {
		return _CHANNEL_IS_DEFUNCT(chd) ? ENXIO : ENOENT;
	}
	if (adv_type == NEXUS_ADVISORY_TYPE_NETIF) {
		intf_adv = &(CHD_NX_ADV_NETIF(adv_md))->__kern_intf_adv;
	} else {
		intf_adv = &(CHD_NX_ADV_FSW(adv_md))->_nxadv_intf_adv;
	}
	if (intf_adv->cksum != os_cpu_copy_in_cksum(&intf_adv->adv, advisory,
	    sizeof(*advisory), 0)) {
		return _CHANNEL_IS_DEFUNCT(chd) ? ENXIO : EAGAIN;
	}
	return 0;
}

int
os_channel_configure_interface_advisory(const channel_t chd, boolean_t enable)
{
	uint32_t value = enable;

	return __channel_set_opt(chd->chd_fd, CHOPT_IF_ADV_CONF,
	           &value, sizeof(value));
}

int
os_channel_buflet_alloc(const channel_t chd, buflet_t *bft)
{
	struct __user_channel_ring *ring;
	struct channel_ring_desc *chrd;
	struct __user_buflet *ubft;
	obj_idx_t nbft_idx;
	slot_idx_t idx;
	struct ch_info *ci = CHD_INFO(chd);

	if (__improbable((ci->cinfo_ch_mode & CHMODE_USER_PACKET_POOL) == 0)) {
		return ENOTSUP;
	}

	if (__improbable(_num_allocator_rings(CHD_SCHEMA(chd)) < 4)) {
		return ENOTSUP;
	}

	chrd = &chd->chd_rings[chd->chd_buf_alloc_ring_idx];
	ring = __DECONST(struct __user_channel_ring *, chrd->chrd_ring);
	idx = ring->ring_head;

	if (__improbable(idx == ring->ring_tail)) {
		/*
		 * do a sync to get more buflets;
		 */
		int err;
		err = __channel_sync(chd->chd_fd, CHANNEL_SYNC_UPP,
		    CHANNEL_SYNCF_ALLOC_BUF | CHANNEL_SYNCF_FREE);
		if (__improbable(err != 0)) {
			if (!_CHANNEL_IS_DEFUNCT(chd)) {
				SK_ABORT_WITH_CAUSE("buflet pool alloc "
				    "sync failed", err);
				/* NOTREACHED */
				__builtin_unreachable();
			}
			return err;
		}
	}

	if (__improbable(idx == ring->ring_tail)) {
		return __improbable(_CHANNEL_IS_DEFUNCT(chd)) ?
		       ENXIO : ENOMEM;
	}

	_SLOT_DESC_VERIFY(chrd, _SLOT_DESC(chrd, idx));
	ubft = _SLOT_BFT_METADATA(chrd, ring, idx);
	_SLOT_DETACH_METADATA(_SLOT_DESC(chrd, idx));

	/*
	 * Initialize the buflet metadata buffer address.
	 */
	*(mach_vm_address_t *)(uintptr_t)&(ubft->buf_addr) =
	    _CHANNEL_RING_BUF(chrd, ring, ubft->buf_idx);
	if (__improbable(ubft->buf_addr == 0)) {
		SK_ABORT_WITH_CAUSE("buflet alloc with NULL buffer",
		    ubft->buf_idx);
		/* NOTREACHED */
		__builtin_unreachable();
	}
	nbft_idx = ubft->buf_nbft_idx;
	if (__improbable(nbft_idx != OBJ_IDX_NONE)) {
		if (_CHANNEL_IS_DEFUNCT(chd)) {
			return ENXIO;
		} else {
			SK_ABORT_WITH_CAUSE("buflet alloc with invalid nidx",
			    nbft_idx);
			/* NOTREACHED */
			__builtin_unreachable();
		}
	}
	ring->ring_head = _CHANNEL_RING_NEXT(ring, idx);
	*bft = ubft;
	return __improbable(_CHANNEL_IS_DEFUNCT(chd)) ? ENXIO : 0;
}

int
os_channel_buflet_free(const channel_t chd, buflet_t ubft)
{
	struct __user_channel_ring *ring;
	struct channel_ring_desc *chrd;
	slot_idx_t idx;
	obj_idx_t midx;
	struct ch_info *ci = CHD_INFO(chd);

	if (__improbable((ci->cinfo_ch_mode & CHMODE_USER_PACKET_POOL) == 0)) {
		return ENOTSUP;
	}

	if (__improbable(_num_allocator_rings(CHD_SCHEMA(chd)) < 4)) {
		return ENOTSUP;
	}

	chrd = &chd->chd_rings[chd->chd_buf_free_ring_idx];
	ring = __DECONST(struct __user_channel_ring *, chrd->chrd_ring);

	idx = ring->ring_head;
	if (__improbable(idx == ring->ring_tail)) {
		/*
		 * do a sync to reclaim space in free ring;
		 */
		int err;
		err = __channel_sync(chd->chd_fd, CHANNEL_SYNC_UPP,
		    CHANNEL_SYNCF_FREE);
		if (__improbable(err != 0) && !_CHANNEL_IS_DEFUNCT(chd)) {
			SK_ABORT_WITH_CAUSE("buflet pool free "
			    "sync failed", err);
			/* NOTREACHED */
			__builtin_unreachable();
		}
	}

	if (__improbable(idx == ring->ring_tail) && !_CHANNEL_IS_DEFUNCT(chd)) {
		SK_ABORT("no ring space in buflet free ring");
		/* NOTREACHED */
		__builtin_unreachable();
	}

	midx = _BFT_INDEX(chrd, ubft);
	_SLOT_BFT_METADATA_IDX_VERIFY(chrd, ubft, midx);
	_SLOT_ATTACH_METADATA(_SLOT_DESC(chrd, idx), midx);
	ring->ring_head = _CHANNEL_RING_NEXT(ring, idx);

	return __improbable(_CHANNEL_RING_IS_DEFUNCT(chrd)) ? ENXIO : 0;
}
