/*
 * Copyright (c) 2017-2023 Apple Inc. All rights reserved.
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

#include <skywalk/os_skywalk_private.h>
#include <machine/endian.h>
#include <net/necp.h>

uint32_t copy_pkt_tx_time = 1;
#if (DEVELOPMENT || DEBUG)
SYSCTL_NODE(_kern_skywalk, OID_AUTO, packet,
    CTLFLAG_RW | CTLFLAG_LOCKED, 0, "Skywalk packet");
int pkt_trailers = 0; /* for testing trailing bytes */
SYSCTL_INT(_kern_skywalk_packet, OID_AUTO, trailers,
    CTLFLAG_RW | CTLFLAG_LOCKED, &pkt_trailers, 0, "");

SYSCTL_UINT(_kern_skywalk_packet, OID_AUTO, copy_pkt_tx_time,
    CTLFLAG_RW | CTLFLAG_LOCKED, &copy_pkt_tx_time, 0,
    "copy tx time from pkt to mbuf");
#endif /* !DEVELOPMENT && !DEBUG */


__attribute__((always_inline))
static inline void
_pkt_copy(void *src, void *dst, size_t len)
{
	if (__probable(IS_P2ALIGNED(src, 8) && IS_P2ALIGNED(dst, 8))) {
		switch (len) {
		case 20:        /* standard IPv4 header */
			sk_copy64_20(src, dst);
			return;

		case 40:        /* IPv6 header */
			sk_copy64_40(src, dst);
			return;

		default:
			if (IS_P2ALIGNED(len, 64)) {
				sk_copy64_64x(src, dst, len);
				return;
			} else if (IS_P2ALIGNED(len, 32)) {
				sk_copy64_32x(src, dst, len);
				return;
			} else if (IS_P2ALIGNED(len, 8)) {
				sk_copy64_8x(src, dst, len);
				return;
			} else if (IS_P2ALIGNED(len, 4)) {
				sk_copy64_4x(src, dst, len);
				return;
			}
			break;
		}
	}
	bcopy(src, dst, len);
}

/*
 * This routine is used for copying data across two kernel packets.
 * Can also optionally compute 16-bit partial inet checksum as the
 * data is copied.
 * This routine is used by flowswitch while copying packet from vp
 * adapter pool to packet in native netif pool and vice-a-versa.
 *
 * start/stuff is relative to soff, within [0, len], such that
 * [ 0 ... soff ... soff + start/stuff ... soff + len ... ]
 */
void
pkt_copy_from_pkt(const enum txrx t, kern_packet_t dph, const uint16_t doff,
    kern_packet_t sph, const uint16_t soff, const uint32_t len,
    const boolean_t copysum, const uint16_t start, const uint16_t stuff,
    const boolean_t invert)
{
	struct __kern_packet *dpkt = SK_PTR_ADDR_KPKT(dph);
	struct __kern_packet *spkt = SK_PTR_ADDR_KPKT(sph);
	uint32_t partial;
	uint16_t csum = 0;
	uint8_t *sbaddr, *dbaddr;
	boolean_t do_sum = copysum && !PACKET_HAS_FULL_CHECKSUM_FLAGS(spkt);

	_CASSERT(sizeof(csum) == sizeof(uint16_t));

	/* get buffer address from packet */
	MD_BUFLET_ADDR_ABS(spkt, sbaddr);
	ASSERT(sbaddr != NULL);
	sbaddr += soff;
	MD_BUFLET_ADDR_ABS(dpkt, dbaddr);
	ASSERT(dbaddr != NULL);
	dbaddr += doff;
	VERIFY((doff + len) <= PP_BUF_SIZE_DEF(dpkt->pkt_qum.qum_pp));

	switch (t) {
	case NR_RX:
		dpkt->pkt_csum_flags = 0;
		if (__probable(do_sum)) {
			/*
			 * Use pkt_copy() to copy the portion up to the
			 * point where we need to start the checksum, and
			 * copy the remainder, checksumming as we go.
			 */
			if (__probable(start != 0)) {
				_pkt_copy(sbaddr, dbaddr, start);
			}
			partial = __packet_copy_and_sum((sbaddr + start),
			    (dbaddr + start), (len - start), 0);
			csum = __packet_fold_sum(partial);

			__packet_set_inet_checksum(dph, PACKET_CSUM_PARTIAL,
			    start, csum, FALSE);
		} else {
			_pkt_copy(sbaddr, dbaddr, len);
			dpkt->pkt_csum_rx_start_off = spkt->pkt_csum_rx_start_off;
			dpkt->pkt_csum_rx_value = spkt->pkt_csum_rx_value;
			dpkt->pkt_csum_flags |= spkt->pkt_csum_flags & PACKET_CSUM_RX_FLAGS;
		}

		SK_DF(SK_VERB_COPY | SK_VERB_RX,
		    "%s(%d) RX len %u, copy+sum %u (csum 0x%04x), start %u",
		    sk_proc_name_address(current_proc()),
		    sk_proc_pid(current_proc()), len,
		    (copysum ? (len - start) : 0), csum, start);
		SK_DF(SK_VERB_COPY | SK_VERB_RX,
		    "   pkt  0x%llx doff %u csumf/rxstart/rxval 0x%x/%u/0x%04x",
		    SK_KVA(dpkt), doff, dpkt->pkt_csum_flags,
		    (uint32_t)dpkt->pkt_csum_rx_start_off,
		    (uint32_t)dpkt->pkt_csum_rx_value);
		break;

	case NR_TX:
		if (copysum) {
			/*
			 * Use pkt_copy() to copy the portion up to the
			 * point where we need to start the checksum, and
			 * copy the remainder, checksumming as we go.
			 */
			if (__probable(start != 0)) {
				_pkt_copy(sbaddr, dbaddr, start);
			}
			partial = __packet_copy_and_sum((sbaddr + start),
			    (dbaddr + start), (len - start), 0);
			csum = __packet_fold_sum_final(partial);

			/* RFC1122 4.1.3.4: Invert 0 to -0 for UDP */
			if (csum == 0 && invert) {
				csum = 0xffff;
			}

			/* Insert checksum into packet */
			ASSERT(stuff <= (len - sizeof(csum)));
			if (IS_P2ALIGNED(dbaddr + stuff, sizeof(csum))) {
				*(uint16_t *)(uintptr_t)(dbaddr + stuff) = csum;
			} else {
				bcopy((void *)&csum, dbaddr + stuff,
				    sizeof(csum));
			}
		} else {
			_pkt_copy(sbaddr, dbaddr, len);
		}
		dpkt->pkt_csum_flags = spkt->pkt_csum_flags &
		    (PACKET_CSUM_TSO_FLAGS | PACKET_TX_CSUM_OFFLOAD_FLAGS);
		dpkt->pkt_csum_tx_start_off = 0;
		dpkt->pkt_csum_tx_stuff_off = 0;

		SK_DF(SK_VERB_COPY | SK_VERB_TX,
		    "%s(%d) TX len %u, copy+sum %u (csum 0x%04x), start %u, flags %u",
		    sk_proc_name_address(current_proc()),
		    sk_proc_pid(current_proc()), len,
		    (copysum ? (len - start) : 0), csum, start, dpkt->pkt_csum_flags);
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}
	METADATA_ADJUST_LEN(dpkt, len, doff);

	SK_DF(SK_VERB_COPY | SK_VERB_DUMP, "%s(%d) %s %s",
	    sk_proc_name_address(current_proc()), sk_proc_pid(current_proc()),
	    (t == NR_RX) ? "RX" : "TX",
	    sk_dump("buf", dbaddr, len, 128, NULL, 0));
}

/*
 * NOTE: soff is the offset within the packet
 * The accumulated partial sum (32-bit) is returned to caller in csum_partial;
 * caller is responsible for further reducing it to 16-bit if needed,
 * as well as to perform the final 1's complement on it.
 */
uint32_t static inline
_pkt_copyaddr_sum(kern_packet_t sph, uint16_t soff, uint8_t *dbaddr,
    uint32_t len, boolean_t do_csum, uint32_t initial_sum, boolean_t *odd_start)
{
	uint8_t odd = 0;
	uint8_t *sbaddr = NULL;
	uint32_t sum = initial_sum, partial;
	uint32_t len0 = len;
	boolean_t needs_swap, started_on_odd = FALSE;
	uint16_t sbcnt, off0 = soff;
	uint32_t clen, sboff, sblen;
	struct __kern_packet *spkt = SK_PTR_ADDR_KPKT(sph);
	kern_buflet_t sbuf = NULL, sbufp = NULL;

	sbcnt = __packet_get_buflet_count(sph);

	if (odd_start) {
		started_on_odd = *odd_start;
	}

	/* fastpath (copy+sum, single buflet, even aligned, even length) */
	if (do_csum && sbcnt == 1 && len != 0) {
		PKT_GET_NEXT_BUFLET(spkt, 1, sbufp, sbuf);
		ASSERT(sbuf != NULL);
		sboff = __buflet_get_data_offset(sbuf);
		sblen = __buflet_get_data_length(sbuf);
		ASSERT(sboff <= soff);
		ASSERT(soff < sboff + sblen);
		sblen -= (soff - sboff);
		sbaddr = (uint8_t *)((uintptr_t)__buflet_get_data_address(sbuf) + soff);

		clen = (uint16_t)MIN(len, sblen);

		if (((uintptr_t)sbaddr & 1) == 0 && clen && (clen & 1) == 0) {
			sum = __packet_copy_and_sum(sbaddr, dbaddr, clen, sum);
			return __packet_fold_sum(sum);
		}

		sbaddr = NULL;
		sbuf = sbufp = NULL;
	}

	while (len != 0) {
		PKT_GET_NEXT_BUFLET(spkt, sbcnt, sbufp, sbuf);
		if (__improbable(sbuf == NULL)) {
			panic("%s: bad packet, 0x%llx [off %d, len %d]",
			    __func__, SK_KVA(spkt), off0, len0);
			/* NOTREACHED */
			__builtin_unreachable();
		}
		sbufp = sbuf;
		sboff = __buflet_get_data_offset(sbuf);
		sblen = __buflet_get_data_length(sbuf);
		ASSERT((sboff <= soff) && (soff < sboff + sblen));
		sblen -= (soff - sboff);
		sbaddr = (uint8_t *)((uintptr_t)__buflet_get_data_address(sbuf) + soff);
		soff = 0;
		clen = (uint16_t)MIN(len, sblen);
		if (__probable(do_csum)) {
			partial = 0;
			if (__improbable((uintptr_t)sbaddr & 1)) {
				/* Align on word boundary */
				started_on_odd = !started_on_odd;
#if BYTE_ORDER == LITTLE_ENDIAN
				partial = (uint8_t)*sbaddr << 8;
#else /* BYTE_ORDER != LITTLE_ENDIAN */
				partial = (uint8_t)*sbaddr;
#endif /* BYTE_ORDER != LITTLE_ENDIAN */
				*dbaddr++ = *sbaddr++;
				sblen -= 1;
				clen -= 1;
				len -= 1;
			}
			needs_swap = started_on_odd;

			odd = clen & 1u;
			clen -= odd;

			if (clen != 0) {
				partial = __packet_copy_and_sum(sbaddr, dbaddr,
				    clen, partial);
			}

			if (__improbable(partial & 0xc0000000)) {
				if (needs_swap) {
					partial = (partial << 8) +
					    (partial >> 24);
				}
				sum += (partial >> 16);
				sum += (partial & 0xffff);
				partial = 0;
			}
		} else {
			_pkt_copy(sbaddr, dbaddr, clen);
		}

		dbaddr += clen;
		sbaddr += clen;

		if (__probable(do_csum)) {
			if (odd != 0) {
#if BYTE_ORDER == LITTLE_ENDIAN
				partial += (uint8_t)*sbaddr;
#else /* BYTE_ORDER != LITTLE_ENDIAN */
				partial += (uint8_t)*sbaddr << 8;
#endif /* BYTE_ORDER != LITTLE_ENDIAN */
				*dbaddr++ = *sbaddr++;
				started_on_odd = !started_on_odd;
			}

			if (needs_swap) {
				partial = (partial << 8) + (partial >> 24);
			}
			sum += (partial >> 16) + (partial & 0xffff);
			/*
			 * Reduce sum to allow potential byte swap
			 * in the next iteration without carry.
			 */
			sum = (sum >> 16) + (sum & 0xffff);
		}

		sblen -= clen + odd;
		len -= clen + odd;
		ASSERT(sblen == 0 || len == 0);
	}

	if (odd_start) {
		*odd_start = started_on_odd;
	}

	if (__probable(do_csum)) {
		/* Final fold (reduce 32-bit to 16-bit) */
		sum = ((sum >> 16) & 0xffff) + (sum & 0xffff);
		sum = (sum >> 16) + (sum & 0xffff);
	}
	return sum;
}

/*
 * NOTE: Caller of this function is responsible to adjust the length and offset
 * of the first buflet of the destination packet if (doff != 0),
 * i.e. additional data is being prependend to the packet.
 * It should also finalize the packet.
 * To simplify & optimize the routine, we have also assumed that soff & doff
 * will lie within the first buffer, which is true for the current use cases
 * where, doff is the offset of the checksum field in the TCP/IP header and
 * soff is the L3 offset.
 * The accumulated partial sum (32-bit) is returned to caller in csum_partial;
 * caller is responsible for further reducing it to 16-bit if needed,
 * as well as to perform the final 1's complement on it.
 */
static inline boolean_t
_pkt_copypkt_sum(kern_packet_t sph, uint16_t soff, kern_packet_t dph,
    uint16_t doff, uint32_t len, uint32_t *csum_partial, boolean_t do_csum)
{
	uint8_t odd = 0;
	uint32_t sum = 0, partial;
	boolean_t needs_swap, started_on_odd = FALSE;
	uint8_t *sbaddr = NULL, *dbaddr = NULL;
	uint16_t sbcnt, dbcnt;
	uint32_t clen, dlen0, sboff, sblen, dlim;
	struct __kern_packet *spkt = SK_PTR_ADDR_KPKT(sph);
	struct __kern_packet *dpkt = SK_PTR_ADDR_KPKT(dph);
	kern_buflet_t sbuf = NULL, sbufp = NULL, dbuf = NULL, dbufp = NULL;

	ASSERT(csum_partial != NULL || !do_csum);
	sbcnt = __packet_get_buflet_count(sph);
	dbcnt = __packet_get_buflet_count(dph);

	while (len != 0) {
		ASSERT(sbaddr == NULL || dbaddr == NULL);
		if (sbaddr == NULL) {
			PKT_GET_NEXT_BUFLET(spkt, sbcnt, sbufp, sbuf);
			if (__improbable(sbuf == NULL)) {
				break;
			}
			sbufp = sbuf;
			sblen = __buflet_get_data_length(sbuf);
			sboff = __buflet_get_data_offset(sbuf);
			ASSERT(soff >= sboff);
			ASSERT(sboff + sblen > soff);
			sblen -= (soff - sboff);
			sbaddr = (uint8_t *)((uintptr_t)__buflet_get_data_address(sbuf) + soff);
			soff = 0;
		}

		if (dbaddr == NULL) {
			if (dbufp != NULL) {
				__buflet_set_data_length(dbufp, dlen0);
			}

			PKT_GET_NEXT_BUFLET(dpkt, dbcnt, dbufp, dbuf);
			if (__improbable(dbuf == NULL)) {
				break;
			}
			dbufp = dbuf;
			dlim = __buflet_get_data_limit(dbuf);
			ASSERT(dlim > doff);
			dlim -= doff;
			if (doff != 0) {
				VERIFY(__buflet_set_data_offset(dbuf, doff) == 0);
			}
			dbaddr = (uint8_t *)((uintptr_t)__buflet_get_data_address(dbuf) + doff);
			dlen0 = dlim;
			doff = 0;
		}

		clen = MIN(len, sblen);
		clen = MIN(clen, dlim);

		if (__probable(do_csum)) {
			partial = 0;
			if (__improbable((uintptr_t)sbaddr & 1)) {
				/* Align on word boundary */
				started_on_odd = !started_on_odd;
#if BYTE_ORDER == LITTLE_ENDIAN
				partial = (uint8_t)*sbaddr << 8;
#else /* BYTE_ORDER != LITTLE_ENDIAN */
				partial = (uint8_t)*sbaddr;
#endif /* BYTE_ORDER != LITTLE_ENDIAN */
				*dbaddr++ = *sbaddr++;
				clen -= 1;
				dlim -= 1;
				len -= 1;
			}
			needs_swap = started_on_odd;

			odd = clen & 1u;
			clen -= odd;

			if (clen != 0) {
				partial = __packet_copy_and_sum(sbaddr, dbaddr,
				    clen, partial);
			}

			if (__improbable(partial & 0xc0000000)) {
				if (needs_swap) {
					partial = (partial << 8) +
					    (partial >> 24);
				}
				sum += (partial >> 16);
				sum += (partial & 0xffff);
				partial = 0;
			}
		} else {
			_pkt_copy(sbaddr, dbaddr, clen);
		}
		sbaddr += clen;
		dbaddr += clen;

		if (__probable(do_csum)) {
			if (odd != 0) {
#if BYTE_ORDER == LITTLE_ENDIAN
				partial += (uint8_t)*sbaddr;
#else /* BYTE_ORDER != LITTLE_ENDIAN */
				partial += (uint8_t)*sbaddr << 8;
#endif /* BYTE_ORDER != LITTLE_ENDIAN */
				*dbaddr++ = *sbaddr++;
				started_on_odd = !started_on_odd;
			}

			if (needs_swap) {
				partial = (partial << 8) + (partial >> 24);
			}
			sum += (partial >> 16) + (partial & 0xffff);
			/*
			 * Reduce sum to allow potential byte swap
			 * in the next iteration without carry.
			 */
			sum = (sum >> 16) + (sum & 0xffff);
		}

		sblen -= clen + odd;
		dlim -= clen + odd;
		len -= clen + odd;

		if (sblen == 0) {
			sbaddr = NULL;
		}

		if (dlim == 0) {
			dbaddr = NULL;
		}
	}

	if (__probable(dbuf != NULL)) {
		__buflet_set_data_length(dbuf, (dlen0 - dlim));
	}
	if (__probable(do_csum)) {
		/* Final fold (reduce 32-bit to 16-bit) */
		sum = ((sum >> 16) & 0xffff) + (sum & 0xffff);
		sum = (sum >> 16) + (sum & 0xffff);
		*csum_partial = (uint32_t)sum;
	}
	return len == 0;
}

uint32_t
pkt_sum(kern_packet_t sph, uint16_t soff, uint16_t len)
{
	uint8_t odd = 0;
	uint32_t sum = 0, partial;
	boolean_t needs_swap, started_on_odd = FALSE;
	uint8_t *sbaddr = NULL;
	uint16_t sbcnt;
	uint32_t clen, sblen, sboff;
	struct __kern_packet *spkt = SK_PTR_ADDR_KPKT(sph);
	kern_buflet_t sbuf = NULL, sbufp = NULL;

	sbcnt = __packet_get_buflet_count(sph);

	/* fastpath (single buflet, even aligned, even length) */
	if (sbcnt == 1 && len != 0) {
		PKT_GET_NEXT_BUFLET(spkt, 1, sbufp, sbuf);
		ASSERT(sbuf != NULL);
		sblen = __buflet_get_data_length(sbuf);
		sboff = __buflet_get_data_offset(sbuf);
		ASSERT(soff >= sboff);
		ASSERT(sboff + sblen > soff);
		sblen -= (soff - sboff);
		sbaddr = (uint8_t *)((uintptr_t)__buflet_get_data_address(sbuf) + soff);

		clen = MIN(len, sblen);

		if (((uintptr_t)sbaddr & 1) == 0 && clen && (clen & 1) == 0) {
			sum = __packet_cksum(sbaddr, clen, 0);
			return __packet_fold_sum(sum);
		}

		sbaddr = NULL;
		sbuf = sbufp = NULL;
	}

	/* slowpath */
	while (len != 0) {
		ASSERT(sbaddr == NULL);
		if (sbaddr == NULL) {
			PKT_GET_NEXT_BUFLET(spkt, sbcnt, sbufp, sbuf);
			if (__improbable(sbuf == NULL)) {
				break;
			}
			sbufp = sbuf;
			sblen = __buflet_get_data_length(sbuf);
			sboff = __buflet_get_data_offset(sbuf);
			ASSERT(soff >= sboff);
			ASSERT(sboff + sblen > soff);
			sblen -= (soff - sboff);
			sbaddr = (uint8_t *)((uintptr_t)__buflet_get_data_address(sbuf) + soff);
			soff = 0;
		}

		clen = MIN(len, sblen);

		partial = 0;
		if (__improbable((uintptr_t)sbaddr & 1)) {
			/* Align on word boundary */
			started_on_odd = !started_on_odd;
#if BYTE_ORDER == LITTLE_ENDIAN
			partial = (uint8_t)*sbaddr << 8;
#else /* BYTE_ORDER != LITTLE_ENDIAN */
			partial = (uint8_t)*sbaddr;
#endif /* BYTE_ORDER != LITTLE_ENDIAN */
			clen -= 1;
			len -= 1;
		}
		needs_swap = started_on_odd;

		odd = clen & 1u;
		clen -= odd;

		if (clen != 0) {
			partial = __packet_cksum(sbaddr,
			    clen, partial);
		}

		if (__improbable(partial & 0xc0000000)) {
			if (needs_swap) {
				partial = (partial << 8) +
				    (partial >> 24);
			}
			sum += (partial >> 16);
			sum += (partial & 0xffff);
			partial = 0;
		}
		sbaddr += clen;

		if (odd != 0) {
#if BYTE_ORDER == LITTLE_ENDIAN
			partial += (uint8_t)*sbaddr;
#else /* BYTE_ORDER != LITTLE_ENDIAN */
			partial += (uint8_t)*sbaddr << 8;
#endif /* BYTE_ORDER != LITTLE_ENDIAN */
			started_on_odd = !started_on_odd;
		}

		if (needs_swap) {
			partial = (partial << 8) + (partial >> 24);
		}
		sum += (partial >> 16) + (partial & 0xffff);
		/*
		 * Reduce sum to allow potential byte swap
		 * in the next iteration without carry.
		 */
		sum = (sum >> 16) + (sum & 0xffff);

		sblen -= clen + odd;
		len -= clen + odd;

		if (sblen == 0) {
			sbaddr = NULL;
		}
	}

	/* Final fold (reduce 32-bit to 16-bit) */
	sum = ((sum >> 16) & 0xffff) + (sum & 0xffff);
	sum = (sum >> 16) + (sum & 0xffff);
	return (uint32_t)sum;
}


/*
 * This is a multi-buflet variant of pkt_copy_from_pkt().
 *
 * start/stuff is relative to soff, within [0, len], such that
 * [ 0 ... soff ... soff + start/stuff ... soff + len ... ]
 */
void
pkt_copy_multi_buflet_from_pkt(const enum txrx t, kern_packet_t dph,
    const uint16_t doff, kern_packet_t sph, const uint16_t soff,
    const uint32_t len, const boolean_t copysum, const uint16_t start,
    const uint16_t stuff, const boolean_t invert)
{
	boolean_t rc;
	uint32_t partial;
	uint16_t csum = 0;
	struct __kern_packet *dpkt = SK_PTR_ADDR_KPKT(dph);
	struct __kern_packet *spkt = SK_PTR_ADDR_KPKT(sph);
	boolean_t do_sum = copysum && !PACKET_HAS_FULL_CHECKSUM_FLAGS(spkt);

	VERIFY((doff + len) <= (PP_BUF_SIZE_DEF(dpkt->pkt_qum.qum_pp) *
	    __packet_get_buflet_count(dph)));

	switch (t) {
	case NR_RX:
		dpkt->pkt_csum_flags = 0;
		if (__probable(do_sum)) {
			/*
			 * copy the portion up to the point where we need to
			 * start the checksum, and copy the remainder,
			 * checksumming as we go.
			 */
			if (__probable(start != 0)) {
				rc = _pkt_copypkt_sum(sph, soff, dph, doff,
				    start, NULL, FALSE);
				ASSERT(rc);
			}
			_pkt_copypkt_sum(sph, (soff + start), dph,
			    (doff + start), (len - start), &partial, TRUE);
			csum = __packet_fold_sum(partial);
			__packet_set_inet_checksum(dph, PACKET_CSUM_PARTIAL,
			    start, csum, FALSE);
			METADATA_ADJUST_LEN(dpkt, start, doff);
		} else {
			rc = _pkt_copypkt_sum(sph, soff, dph, doff, len, NULL,
			    FALSE);
			ASSERT(rc);
			dpkt->pkt_csum_rx_start_off = spkt->pkt_csum_rx_start_off;
			dpkt->pkt_csum_rx_value = spkt->pkt_csum_rx_value;
			dpkt->pkt_csum_flags |= spkt->pkt_csum_flags & PACKET_CSUM_RX_FLAGS;
		}
		break;

	case NR_TX:
		if (copysum) {
			uint8_t *baddr;
			/*
			 * copy the portion up to the point where we need to
			 * start the checksum, and copy the remainder,
			 * checksumming as we go.
			 */
			if (__probable(start != 0)) {
				rc = _pkt_copypkt_sum(sph, soff, dph, doff,
				    start, NULL, FALSE);
				ASSERT(rc);
			}
			rc = _pkt_copypkt_sum(sph, (soff + start), dph,
			    (doff + start), (len - start), &partial, TRUE);
			ASSERT(rc);
			csum = __packet_fold_sum_final(partial);

			/* RFC1122 4.1.3.4: Invert 0 to -0 for UDP */
			if (csum == 0 && invert) {
				csum = 0xffff;
			}

			/*
			 * Insert checksum into packet.
			 * Here we assume that checksum will be in the
			 * first buffer.
			 */
			ASSERT((stuff + doff + sizeof(csum)) <=
			    PP_BUF_SIZE_DEF(dpkt->pkt_qum.qum_pp));
			ASSERT(stuff <= (len - sizeof(csum)));

			/* get first buflet buffer address from packet */
			MD_BUFLET_ADDR_ABS(dpkt, baddr);
			ASSERT(baddr != NULL);
			baddr += doff;
			if (IS_P2ALIGNED(baddr + stuff, sizeof(csum))) {
				*(uint16_t *)(uintptr_t)(baddr + stuff) = csum;
			} else {
				bcopy((void *)&csum, baddr + stuff,
				    sizeof(csum));
			}
			METADATA_ADJUST_LEN(dpkt, start, doff);
		} else {
			rc = _pkt_copypkt_sum(sph, soff, dph, doff, len, NULL,
			    FALSE);
			ASSERT(rc);
		}
		dpkt->pkt_csum_flags = spkt->pkt_csum_flags &
		    (PACKET_CSUM_TSO_FLAGS | PACKET_TX_CSUM_OFFLOAD_FLAGS);
		dpkt->pkt_csum_tx_start_off = 0;
		dpkt->pkt_csum_tx_stuff_off = 0;

		SK_DF(SK_VERB_COPY | SK_VERB_TX,
		    "%s(%d) TX len %u, copy+sum %u (csum 0x%04x), start %u, flags %u",
		    sk_proc_name_address(current_proc()),
		    sk_proc_pid(current_proc()), len,
		    (copysum ? (len - start) : 0), csum, start, dpkt->pkt_csum_flags);
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}
}

static inline uint32_t
_convert_mbuf_csum_flags(uint32_t mbuf_flags)
{
	uint32_t pkt_flags = 0;

	if (mbuf_flags & CSUM_TCP) {
		pkt_flags |= PACKET_CSUM_TCP;
	}
	if (mbuf_flags & CSUM_TCPIPV6) {
		pkt_flags |= PACKET_CSUM_TCPIPV6;
	}
	if (mbuf_flags & CSUM_UDP) {
		pkt_flags |= PACKET_CSUM_UDP;
	}
	if (mbuf_flags & CSUM_UDPIPV6) {
		pkt_flags |= PACKET_CSUM_UDPIPV6;
	}
	if (mbuf_flags & CSUM_IP) {
		pkt_flags |= PACKET_CSUM_IP;
	}
	if (mbuf_flags & CSUM_ZERO_INVERT) {
		pkt_flags |= PACKET_CSUM_ZERO_INVERT;
	}

	return pkt_flags;
}

/*
 * This routine is used for copying an mbuf which originated in the host
 * stack destined to a native skywalk interface (NR_TX), as well as for
 * mbufs originating on compat network interfaces (NR_RX).
 *
 * start/stuff is relative to moff, within [0, len], such that
 * [ 0 ... moff ... moff + start/stuff ... moff + len ... ]
 */
void
pkt_copy_from_mbuf(const enum txrx t, kern_packet_t ph, const uint16_t poff,
    struct mbuf *m, const uint16_t moff, const uint32_t len,
    const boolean_t copysum, const uint16_t start)
{
	struct __kern_packet *pkt = SK_PTR_ADDR_KPKT(ph);
	uint32_t partial;
	uint16_t csum = 0;
	uint8_t *baddr;

	_CASSERT(sizeof(csum) == sizeof(uint16_t));

	/* get buffer address from packet */
	MD_BUFLET_ADDR_ABS(pkt, baddr);
	ASSERT(baddr != NULL);
	baddr += poff;
	VERIFY((poff + len) <= PP_BUF_SIZE_DEF(pkt->pkt_qum.qum_pp));

	switch (t) {
	case NR_RX:
		pkt->pkt_csum_flags = m->m_pkthdr.csum_flags;
		pkt->pkt_csum_rx_start_off = 0;
		pkt->pkt_csum_rx_value = m->m_pkthdr.csum_rx_val;
		pkt->pkt_svc_class = m_get_service_class(m);
		if (__probable(((m->m_pkthdr.csum_flags & CSUM_RX_FULL_FLAGS)
		    != CSUM_RX_FULL_FLAGS) && copysum)) {
			/*
			 * Use m_copydata() to copy the portion up to the
			 * point where we need to start the checksum, and
			 * copy the remainder, checksumming as we go.
			 */
			if (start != 0) {
				m_copydata(m, moff, start, baddr);
			}
			partial = m_copydata_sum(m, start, (len - start),
			    (baddr + start), 0, NULL);
			csum = __packet_fold_sum(partial);

			__packet_set_inet_checksum(ph, PACKET_CSUM_PARTIAL,
			    start, csum, FALSE);
		} else {
			m_copydata(m, moff, len, baddr);
		}
		SK_DF(SK_VERB_COPY_MBUF | SK_VERB_RX,
		    "%s(%d) RX len %u, copy+sum %u (csum 0x%04x), start %u",
		    sk_proc_name_address(current_proc()),
		    sk_proc_pid(current_proc()), len,
		    (copysum ? (len - start) : 0), csum, start);
		SK_DF(SK_VERB_COPY_MBUF | SK_VERB_RX,
		    "   mbuf 0x%llx csumf/rxstart/rxval 0x%x/%u/0x%04x",
		    SK_KVA(m), m->m_pkthdr.csum_flags,
		    (uint32_t)m->m_pkthdr.csum_rx_start,
		    (uint32_t)m->m_pkthdr.csum_rx_val);
		SK_DF(SK_VERB_COPY_MBUF | SK_VERB_RX,
		    "   pkt  0x%llx poff %u csumf/rxstart/rxval 0x%x/%u/0x%04x",
		    SK_KVA(pkt), poff, pkt->pkt_csum_flags,
		    (uint32_t)pkt->pkt_csum_rx_start_off,
		    (uint32_t)pkt->pkt_csum_rx_value);
		break;

	case NR_TX:
		if (copysum) {
			uint16_t stuff = m->m_pkthdr.csum_tx_stuff;
			/*
			 * Use m_copydata() to copy the portion up to the
			 * point where we need to start the checksum, and
			 * copy the remainder, checksumming as we go.
			 */
			if (start != 0) {
				m_copydata(m, moff, start, baddr);
			}
			partial = m_copydata_sum(m, start, (len - start),
			    (baddr + start), 0, NULL);
			csum = __packet_fold_sum_final(partial);

			/*
			 * RFC1122 4.1.3.4: Invert 0 to -0 for UDP;
			 * ideally we'd only test for CSUM_ZERO_INVERT
			 * here, but catch cases where the originator
			 * did not set it for UDP.
			 */
			if (csum == 0 && (m->m_pkthdr.csum_flags &
			    (CSUM_UDP | CSUM_UDPIPV6 | CSUM_ZERO_INVERT))) {
				csum = 0xffff;
			}

			/* Insert checksum into packet */
			ASSERT(stuff <= (len - sizeof(csum)));
			if (IS_P2ALIGNED(baddr + stuff, sizeof(csum))) {
				*(uint16_t *)(uintptr_t)(baddr + stuff) = csum;
			} else {
				bcopy((void *)&csum, baddr + stuff,
				    sizeof(csum));
			}
		} else {
			m_copydata(m, moff, len, baddr);
		}
		pkt->pkt_csum_flags = 0;
		pkt->pkt_csum_tx_start_off = 0;
		pkt->pkt_csum_tx_stuff_off = 0;

		if (m->m_pkthdr.csum_flags & CSUM_TSO_IPV4) {
			pkt->pkt_csum_flags |= PACKET_CSUM_TSO_IPV4;
			pkt->pkt_proto_seg_sz = (uint16_t)m->m_pkthdr.tso_segsz;
			ASSERT((pkt->pkt_csum_flags & PACKET_TSO_IPV6) == 0);
		}
		if (m->m_pkthdr.csum_flags & CSUM_TSO_IPV6) {
			pkt->pkt_csum_flags |= PACKET_CSUM_TSO_IPV6;
			pkt->pkt_proto_seg_sz = (uint16_t)m->m_pkthdr.tso_segsz;
			ASSERT((pkt->pkt_csum_flags & PACKET_TSO_IPV4) == 0);
		}
		if (!copysum) {
			pkt->pkt_csum_flags |= _convert_mbuf_csum_flags(m->m_pkthdr.csum_flags);
		}

		/* translate mbuf metadata */
		pkt->pkt_flowsrc_type = m->m_pkthdr.pkt_flowsrc;
		pkt->pkt_flowsrc_token = m->m_pkthdr.pkt_mpriv_srcid;
		pkt->pkt_flow_token = m->m_pkthdr.pkt_flowid;
		pkt->pkt_comp_gencnt = m->m_pkthdr.comp_gencnt;
		switch (m->m_pkthdr.pkt_proto) {
		case IPPROTO_QUIC:
			pkt->pkt_flow_ip_proto = IPPROTO_UDP;
			pkt->pkt_transport_protocol = IPPROTO_QUIC;
			break;

		default:
			pkt->pkt_flow_ip_proto = m->m_pkthdr.pkt_proto;
			pkt->pkt_transport_protocol = m->m_pkthdr.pkt_proto;
			break;
		}
		(void) mbuf_get_timestamp(m, &pkt->pkt_timestamp, NULL);
		pkt->pkt_svc_class = m_get_service_class(m);
		pkt->pkt_pflags &= ~PKT_F_COMMON_MASK;
		pkt->pkt_pflags |= (m->m_pkthdr.pkt_flags & PKT_F_COMMON_MASK);
		if ((m->m_pkthdr.pkt_flags & PKTF_START_SEQ) != 0) {
			pkt->pkt_flow_tcp_seq = htonl(m->m_pkthdr.tx_start_seq);
		}
		if ((m->m_pkthdr.pkt_ext_flags & PKTF_EXT_L4S) != 0) {
			pkt->pkt_pflags |= PKT_F_L4S;
		}
		necp_get_app_uuid_from_packet(m, pkt->pkt_policy_euuid);
		pkt->pkt_policy_id =
		    (uint32_t)necp_get_policy_id_from_packet(m);
		pkt->pkt_skip_policy_id =
		    (uint32_t)necp_get_skip_policy_id_from_packet(m);

		if ((m->m_pkthdr.pkt_flags & PKTF_TX_COMPL_TS_REQ) != 0) {
			if ((m->m_pkthdr.pkt_flags & PKTF_DRIVER_MTAG) != 0) {
				__packet_set_tx_completion_data(ph,
				    m->m_pkthdr.drv_tx_compl_arg,
				    m->m_pkthdr.drv_tx_compl_data);
			}
			pkt->pkt_tx_compl_context =
			    m->m_pkthdr.pkt_compl_context;
			pkt->pkt_tx_compl_callbacks =
			    m->m_pkthdr.pkt_compl_callbacks;
			/*
			 * Remove PKTF_TX_COMPL_TS_REQ flag so that this
			 * mbuf can no longer trigger a completion callback.
			 * callback will be invoked when the kernel packet is
			 * completed.
			 */
			m->m_pkthdr.pkt_flags &= ~PKTF_TX_COMPL_TS_REQ;

			m_add_crumb(m, PKT_CRUMB_SK_PKT_COPY);
		}

		SK_DF(SK_VERB_COPY_MBUF | SK_VERB_TX,
		    "%s(%d) TX len %u, copy+sum %u (csum 0x%04x), start %u",
		    sk_proc_name_address(current_proc()),
		    sk_proc_pid(current_proc()), len,
		    (copysum ? (len - start) : 0), csum, start);
		SK_DF(SK_VERB_COPY_MBUF | SK_VERB_TX,
		    "   mbuf 0x%llx csumf/txstart/txstuff 0x%x/%u/%u",
		    SK_KVA(m), m->m_pkthdr.csum_flags,
		    (uint32_t)m->m_pkthdr.csum_tx_start,
		    (uint32_t)m->m_pkthdr.csum_tx_stuff);
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}
	METADATA_ADJUST_LEN(pkt, len, poff);

	if (m->m_flags & M_BCAST) {
		__packet_set_link_broadcast(ph);
	} else if (m->m_flags & M_MCAST) {
		__packet_set_link_multicast(ph);
	}

	SK_DF(SK_VERB_COPY_MBUF | SK_VERB_DUMP, "%s(%d) %s %s",
	    sk_proc_name_address(current_proc()), sk_proc_pid(current_proc()),
	    (t == NR_RX) ? "RX" : "TX",
	    sk_dump("buf", baddr, len, 128, NULL, 0));
}

/*
 * Like m_copydata_sum(), but works on a destination kernel packet.
 */
static inline uint32_t
m_copypkt_sum(mbuf_t m, int soff, kern_packet_t dph, uint16_t doff,
    uint32_t len, boolean_t do_cscum)
{
	boolean_t needs_swap, started_on_odd = FALSE;
	int off0 = soff;
	uint32_t len0 = len;
	struct mbuf *m0 = m;
	uint32_t sum = 0, partial;
	unsigned count0, count, odd, mlen_copied;
	uint8_t *sbaddr = NULL, *dbaddr = NULL;
	uint16_t dbcnt = __packet_get_buflet_count(dph);
	uint32_t dlim, dlen0;
	struct __kern_packet *dpkt = SK_PTR_ADDR_KPKT(dph);
	kern_buflet_t dbuf = NULL, dbufp = NULL;

	while (soff > 0) {
		if (__improbable(m == NULL)) {
			panic("%s: invalid mbuf chain %p [off %d, len %d]",
			    __func__, m0, off0, len0);
			/* NOTREACHED */
			__builtin_unreachable();
		}
		if (soff < m->m_len) {
			break;
		}
		soff -= m->m_len;
		m = m->m_next;
	}

	if (__improbable(m == NULL)) {
		panic("%s: invalid mbuf chain %p [off %d, len %d]",
		    __func__, m0, off0, len0);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	sbaddr = mtod(m, uint8_t *) + soff;
	count = m->m_len - soff;
	mlen_copied = 0;

	while (len != 0) {
		ASSERT(sbaddr == NULL || dbaddr == NULL);
		if (sbaddr == NULL) {
			soff = 0;
			m = m->m_next;
			if (__improbable(m == NULL)) {
				panic("%s: invalid mbuf chain %p [off %d, "
				    "len %d]", __func__, m0, off0, len0);
				/* NOTREACHED */
				__builtin_unreachable();
			}
			sbaddr = mtod(m, uint8_t *);
			count = m->m_len;
			mlen_copied = 0;
		}

		if (__improbable(count == 0)) {
			sbaddr = NULL;
			continue;
		}

		if (dbaddr == NULL) {
			if (dbufp != NULL) {
				__buflet_set_data_length(dbufp, dlen0);
			}

			PKT_GET_NEXT_BUFLET(dpkt, dbcnt, dbufp, dbuf);
			if (__improbable(dbuf == NULL)) {
				panic("%s: mbuf too large %p [off %d, "
				    "len %d]", __func__, m0, off0, len0);
				/* NOTREACHED */
				__builtin_unreachable();
			}
			dbufp = dbuf;
			dlim = __buflet_get_data_limit(dbuf) - doff;
			dbaddr = (uint8_t *)((uintptr_t)__buflet_get_data_address(dbuf) + doff);
			dlen0 = dlim;
			doff = 0;
		}

		count = MIN(count, (unsigned)len);
		count0 = count = MIN(count, dlim);

		if (!do_cscum) {
			_pkt_copy(sbaddr, dbaddr, count);
			sbaddr += count;
			dbaddr += count;
			goto skip_csum;
		}

		partial = 0;
		if ((uintptr_t)sbaddr & 1) {
			/* Align on word boundary */
			started_on_odd = !started_on_odd;
#if BYTE_ORDER == LITTLE_ENDIAN
			partial = *sbaddr << 8;
#else /* BYTE_ORDER != LITTLE_ENDIAN */
			partial = *sbaddr;
#endif /* BYTE_ORDER != LITTLE_ENDIAN */
			*dbaddr++ = *sbaddr++;
			count -= 1;
		}

		needs_swap = started_on_odd;
		odd = count & 1u;
		count -= odd;

		if (count) {
			partial = __packet_copy_and_sum(sbaddr,
			    dbaddr, count, partial);
			sbaddr += count;
			dbaddr += count;
			if (__improbable(partial & 0xc0000000)) {
				if (needs_swap) {
					partial = (partial << 8) +
					    (partial >> 24);
				}
				sum += (partial >> 16);
				sum += (partial & 0xffff);
				partial = 0;
			}
		}

		if (odd) {
#if BYTE_ORDER == LITTLE_ENDIAN
			partial += *sbaddr;
#else /* BYTE_ORDER != LITTLE_ENDIAN */
			partial += *sbaddr << 8;
#endif /* BYTE_ORDER != LITTLE_ENDIAN */
			*dbaddr++ = *sbaddr++;
			started_on_odd = !started_on_odd;
		}

		if (needs_swap) {
			partial = (partial << 8) + (partial >> 24);
		}
		sum += (partial >> 16) + (partial & 0xffff);
		/*
		 * Reduce sum to allow potential byte swap
		 * in the next iteration without carry.
		 */
		sum = (sum >> 16) + (sum & 0xffff);

skip_csum:
		dlim -= count0;
		len -= count0;
		mlen_copied += count0;

		if (dlim == 0) {
			dbaddr = NULL;
		}

		count = m->m_len - soff - mlen_copied;
		if (count == 0) {
			sbaddr = NULL;
		}
	}

	ASSERT(len == 0);
	ASSERT(dbuf != NULL);
	__buflet_set_data_length(dbuf, (dlen0 - dlim));

	if (!do_cscum) {
		return 0;
	}

	/* Final fold (reduce 32-bit to 16-bit) */
	sum = ((sum >> 16) & 0xffff) + (sum & 0xffff);
	sum = (sum >> 16) + (sum & 0xffff);
	return sum;
}

/*
 * This is a multi-buflet variant of pkt_copy_from_mbuf().
 *
 * start/stuff is relative to moff, within [0, len], such that
 * [ 0 ... moff ... moff + start/stuff ... moff + len ... ]
 */
void
pkt_copy_multi_buflet_from_mbuf(const enum txrx t, kern_packet_t ph,
    const uint16_t poff, struct mbuf *m, const uint16_t moff,
    const uint32_t len, const boolean_t copysum, const uint16_t start)
{
	struct __kern_packet *pkt = SK_PTR_ADDR_KPKT(ph);
	uint32_t partial;
	uint16_t csum = 0;
	uint8_t *baddr;

	_CASSERT(sizeof(csum) == sizeof(uint16_t));

	/* get buffer address from packet */
	MD_BUFLET_ADDR_ABS(pkt, baddr);
	ASSERT(baddr != NULL);
	baddr += poff;
	VERIFY((poff + len) <= (PP_BUF_SIZE_DEF(pkt->pkt_qum.qum_pp) *
	    __packet_get_buflet_count(ph)));

	switch (t) {
	case NR_RX:
		pkt->pkt_csum_flags = m->m_pkthdr.csum_flags;
		pkt->pkt_csum_rx_start_off = 0;
		pkt->pkt_csum_rx_value = m->m_pkthdr.csum_rx_val;
		pkt->pkt_svc_class = m_get_service_class(m);
		if (__probable(((m->m_pkthdr.csum_flags & CSUM_RX_FULL_FLAGS)
		    != CSUM_RX_FULL_FLAGS) && copysum)) {
			/*
			 * Use m_copydata() to copy the portion up to the
			 * point where we need to start the checksum, and
			 * copy the remainder, checksumming as we go.
			 */
			if (start != 0) {
				m_copydata(m, moff, start, baddr);
			}
			partial = m_copypkt_sum(m, start, ph, (poff + start),
			    (len - start), TRUE);
			csum = __packet_fold_sum(partial);
			__packet_set_inet_checksum(ph, PACKET_CSUM_PARTIAL,
			    start, csum, FALSE);
			METADATA_ADJUST_LEN(pkt, start, poff);
		} else {
			(void) m_copypkt_sum(m, moff, ph, poff, len, FALSE);
		}
		SK_DF(SK_VERB_COPY_MBUF | SK_VERB_RX,
		    "%s(%d) RX len %u, copy+sum %u (csum 0x%04x), start %u",
		    sk_proc_name_address(current_proc()),
		    sk_proc_pid(current_proc()), len,
		    (copysum ? (len - start) : 0), csum, start);
		SK_DF(SK_VERB_COPY_MBUF | SK_VERB_RX,
		    "   mbuf 0x%llx csumf/rxstart/rxval 0x%x/%u/0x%04x",
		    SK_KVA(m), m->m_pkthdr.csum_flags,
		    (uint32_t)m->m_pkthdr.csum_rx_start,
		    (uint32_t)m->m_pkthdr.csum_rx_val);
		SK_DF(SK_VERB_COPY_MBUF | SK_VERB_RX,
		    "   pkt  0x%llx poff %u csumf/rxstart/rxval 0x%x/%u/0x%04x",
		    SK_KVA(pkt), poff, pkt->pkt_csum_flags,
		    (uint32_t)pkt->pkt_csum_rx_start_off,
		    (uint32_t)pkt->pkt_csum_rx_value);
		break;

	case NR_TX:
		if (copysum) {
			uint16_t stuff = m->m_pkthdr.csum_tx_stuff;
			/*
			 * Use m_copydata() to copy the portion up to the
			 * point where we need to start the checksum, and
			 * copy the remainder, checksumming as we go.
			 */
			if (start != 0) {
				m_copydata(m, moff, start, baddr);
			}
			partial = m_copypkt_sum(m, start, ph, (poff + start),
			    (len - start), TRUE);
			csum = __packet_fold_sum_final(partial);

			/*
			 * RFC1122 4.1.3.4: Invert 0 to -0 for UDP;
			 * ideally we'd only test for CSUM_ZERO_INVERT
			 * here, but catch cases where the originator
			 * did not set it for UDP.
			 */
			if (csum == 0 && (m->m_pkthdr.csum_flags &
			    (CSUM_UDP | CSUM_UDPIPV6 | CSUM_ZERO_INVERT))) {
				csum = 0xffff;
			}

			/* Insert checksum into packet */
			ASSERT(stuff <= (len - sizeof(csum)));
			if (IS_P2ALIGNED(baddr + stuff, sizeof(csum))) {
				*(uint16_t *)(uintptr_t)(baddr + stuff) = csum;
			} else {
				bcopy((void *)&csum, baddr + stuff,
				    sizeof(csum));
			}
			METADATA_ADJUST_LEN(pkt, start, poff);
		} else {
			m_copypkt_sum(m, moff, ph, poff, len, FALSE);
		}
		pkt->pkt_csum_flags = 0;
		pkt->pkt_csum_tx_start_off = 0;
		pkt->pkt_csum_tx_stuff_off = 0;

		if (m->m_pkthdr.csum_flags & CSUM_TSO_IPV4) {
			pkt->pkt_csum_flags |= PACKET_CSUM_TSO_IPV4;
			pkt->pkt_proto_seg_sz = (uint16_t)m->m_pkthdr.tso_segsz;
			ASSERT((pkt->pkt_csum_flags & PACKET_TSO_IPV6) == 0);
		}
		if (m->m_pkthdr.csum_flags & CSUM_TSO_IPV6) {
			pkt->pkt_csum_flags |= PACKET_CSUM_TSO_IPV6;
			pkt->pkt_proto_seg_sz = (uint16_t)m->m_pkthdr.tso_segsz;
			ASSERT((pkt->pkt_csum_flags & PACKET_TSO_IPV4) == 0);
		}
		if (!copysum) {
			pkt->pkt_csum_flags |= _convert_mbuf_csum_flags(m->m_pkthdr.csum_flags);
		}

		/* translate mbuf metadata */
		pkt->pkt_flowsrc_type = m->m_pkthdr.pkt_flowsrc;
		pkt->pkt_flowsrc_token = m->m_pkthdr.pkt_mpriv_srcid;
		pkt->pkt_flow_token = m->m_pkthdr.pkt_flowid;
		pkt->pkt_comp_gencnt = m->m_pkthdr.comp_gencnt;
		switch (m->m_pkthdr.pkt_proto) {
		case IPPROTO_QUIC:
			pkt->pkt_flow_ip_proto = IPPROTO_UDP;
			pkt->pkt_transport_protocol = IPPROTO_QUIC;
			break;

		default:
			pkt->pkt_flow_ip_proto = m->m_pkthdr.pkt_proto;
			pkt->pkt_transport_protocol = m->m_pkthdr.pkt_proto;
			break;
		}
		(void) mbuf_get_timestamp(m, &pkt->pkt_timestamp, NULL);
		pkt->pkt_svc_class = m_get_service_class(m);
		pkt->pkt_pflags &= ~PKT_F_COMMON_MASK;
		pkt->pkt_pflags |= (m->m_pkthdr.pkt_flags & PKT_F_COMMON_MASK);
		if ((m->m_pkthdr.pkt_flags & PKTF_START_SEQ) != 0) {
			pkt->pkt_flow_tcp_seq = htonl(m->m_pkthdr.tx_start_seq);
		}
		if ((m->m_pkthdr.pkt_ext_flags & PKTF_EXT_L4S) != 0) {
			pkt->pkt_pflags |= PKT_F_L4S;
		}
		necp_get_app_uuid_from_packet(m, pkt->pkt_policy_euuid);
		pkt->pkt_policy_id =
		    (uint32_t)necp_get_policy_id_from_packet(m);
		pkt->pkt_skip_policy_id =
		    (uint32_t)necp_get_skip_policy_id_from_packet(m);

		if ((m->m_pkthdr.pkt_flags & PKTF_TX_COMPL_TS_REQ) != 0) {
			if ((m->m_pkthdr.pkt_flags & PKTF_DRIVER_MTAG) != 0) {
				__packet_set_tx_completion_data(ph,
				    m->m_pkthdr.drv_tx_compl_arg,
				    m->m_pkthdr.drv_tx_compl_data);
			}
			pkt->pkt_tx_compl_context =
			    m->m_pkthdr.pkt_compl_context;
			pkt->pkt_tx_compl_callbacks =
			    m->m_pkthdr.pkt_compl_callbacks;
			/*
			 * Remove PKTF_TX_COMPL_TS_REQ flag so that this
			 * mbuf can no longer trigger a completion callback.
			 * callback will be invoked when the kernel packet is
			 * completed.
			 */
			m->m_pkthdr.pkt_flags &= ~PKTF_TX_COMPL_TS_REQ;

			m_add_crumb(m, PKT_CRUMB_SK_PKT_COPY);
		}

		SK_DF(SK_VERB_COPY_MBUF | SK_VERB_TX,
		    "%s(%d) TX len %u, copy+sum %u (csum 0x%04x), start %u",
		    sk_proc_name_address(current_proc()),
		    sk_proc_pid(current_proc()), len,
		    (copysum ? (len - start) : 0), csum, start);
		SK_DF(SK_VERB_COPY_MBUF | SK_VERB_TX,
		    "   mbuf 0x%llx csumf/txstart/txstuff 0x%x/%u/%u",
		    SK_KVA(m), m->m_pkthdr.csum_flags,
		    (uint32_t)m->m_pkthdr.csum_tx_start,
		    (uint32_t)m->m_pkthdr.csum_tx_stuff);
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	if (m->m_flags & M_BCAST) {
		__packet_set_link_broadcast(ph);
	} else if (m->m_flags & M_MCAST) {
		__packet_set_link_multicast(ph);
	}

	SK_DF(SK_VERB_COPY_MBUF | SK_VERB_DUMP, "%s(%d) %s %s",
	    sk_proc_name_address(current_proc()), sk_proc_pid(current_proc()),
	    (t == NR_RX) ? "RX" : "TX",
	    sk_dump("buf", baddr, len, 128, NULL, 0));
}

static inline uint32_t
_convert_pkt_csum_flags(uint32_t pkt_flags)
{
	uint32_t mbuf_flags = 0;
	if (pkt_flags & PACKET_CSUM_TCP) {
		mbuf_flags |= CSUM_TCP;
	}
	if (pkt_flags & PACKET_CSUM_TCPIPV6) {
		mbuf_flags |= CSUM_TCPIPV6;
	}
	if (pkt_flags & PACKET_CSUM_UDP) {
		mbuf_flags |= CSUM_UDP;
	}
	if (pkt_flags & PACKET_CSUM_UDPIPV6) {
		mbuf_flags |= CSUM_UDPIPV6;
	}
	if (pkt_flags & PACKET_CSUM_IP) {
		mbuf_flags |= CSUM_IP;
	}
	if (pkt_flags & PACKET_CSUM_ZERO_INVERT) {
		mbuf_flags |= CSUM_ZERO_INVERT;
	}

	return mbuf_flags;
}

/*
 * This routine is used for copying from a packet originating from a native
 * skywalk interface to an mbuf destined for the host legacy stack (NR_RX),
 * as well as for mbufs destined for the compat network interfaces (NR_TX).
 *
 * We do adjust the length to reflect the total data span.
 *
 * This routine supports copying into an mbuf chain for RX but not TX.
 *
 * start/stuff is relative to poff, within [0, len], such that
 * [ 0 ... poff ... poff + start/stuff ... poff + len ... ]
 */
void
pkt_copy_to_mbuf(const enum txrx t, kern_packet_t ph, const uint16_t poff,
    struct mbuf *m, const uint16_t moff, const uint32_t len,
    const boolean_t copysum, const uint16_t start)
{
	struct __kern_packet *pkt = SK_PTR_ADDR_KPKT(ph);
	struct mbuf *curr_m;
	uint32_t partial = 0;
	uint32_t remaining_len = len, copied_len = 0;
	uint16_t csum = 0;
	uint8_t *baddr;
	uint8_t *dp;
	boolean_t do_sum = copysum && !PACKET_HAS_FULL_CHECKSUM_FLAGS(pkt);

	ASSERT(len >= start);
	_CASSERT(sizeof(csum) == sizeof(uint16_t));

	/* get buffer address from packet */
	MD_BUFLET_ADDR_ABS(pkt, baddr);
	ASSERT(baddr != NULL);
	baddr += poff;
	VERIFY((poff + len) <= PP_BUF_SIZE_DEF(pkt->pkt_qum.qum_pp));

	ASSERT((m->m_flags & M_PKTHDR));
	m->m_data += moff;

	switch (t) {
	case NR_RX:
		m->m_pkthdr.csum_flags &= ~CSUM_RX_FLAGS;

		/*
		 * Use pkt_copy() to copy the portion up to the
		 * point where we need to start the checksum, and
		 * copy the remainder, checksumming as we go.
		 */
		if (__probable(do_sum && start != 0)) {
			ASSERT(M_TRAILINGSPACE(m) >= start);
			ASSERT(m->m_len == 0);
			dp = (uint8_t *)m->m_data;
			_pkt_copy(baddr, dp, start);
			remaining_len -= start;
			copied_len += start;
			m->m_len += start;
			m->m_pkthdr.len += start;
		}
		curr_m = m;
		while (curr_m != NULL && remaining_len != 0) {
			uint32_t tmp_len = MIN(remaining_len,
			    (uint32_t)M_TRAILINGSPACE(curr_m));
			dp = (uint8_t *)curr_m->m_data + curr_m->m_len;
			if (__probable(do_sum)) {
				partial = __packet_copy_and_sum((baddr + copied_len),
				    dp, tmp_len, partial);
			} else {
				_pkt_copy((baddr + copied_len), dp, tmp_len);
			}

			curr_m->m_len += tmp_len;
			m->m_pkthdr.len += tmp_len;
			copied_len += tmp_len;
			remaining_len -= tmp_len;
			curr_m = curr_m->m_next;
		}
		ASSERT(remaining_len == 0);

		if (__probable(do_sum)) {
			csum = __packet_fold_sum(partial);

			m->m_pkthdr.csum_flags |=
			    (CSUM_DATA_VALID | CSUM_PARTIAL);
			m->m_pkthdr.csum_rx_start = start;
			m->m_pkthdr.csum_rx_val = csum;
		} else {
			m->m_pkthdr.csum_rx_start = pkt->pkt_csum_rx_start_off;
			m->m_pkthdr.csum_rx_val = pkt->pkt_csum_rx_value;
			_CASSERT(CSUM_RX_FULL_FLAGS == PACKET_CSUM_RX_FULL_FLAGS);
			m->m_pkthdr.csum_flags |= pkt->pkt_csum_flags & PACKET_CSUM_RX_FULL_FLAGS;
			if (__improbable((pkt->pkt_csum_flags & PACKET_CSUM_PARTIAL) != 0)) {
				m->m_pkthdr.csum_flags |= CSUM_PARTIAL;
			}
		}

		/* translate packet metadata */
		mbuf_set_timestamp(m, pkt->pkt_timestamp,
		    ((pkt->pkt_pflags & PKT_F_TS_VALID) != 0));

		SK_DF(SK_VERB_COPY_MBUF | SK_VERB_RX,
		    "%s(%d) RX len %u, copy+sum %u (csum 0x%04x), start %u",
		    sk_proc_name_address(current_proc()),
		    sk_proc_pid(current_proc()), len,
		    (copysum ? (len - start) : 0), csum, start);
		SK_DF(SK_VERB_COPY_MBUF | SK_VERB_RX,
		    "   mbuf 0x%llx moff %u csumf/rxstart/rxval 0x%x/%u/0x%04x",
		    SK_KVA(m), moff, m->m_pkthdr.csum_flags,
		    (uint32_t)m->m_pkthdr.csum_rx_start,
		    (uint32_t)m->m_pkthdr.csum_rx_val);
		SK_DF(SK_VERB_COPY_MBUF | SK_VERB_RX,
		    "   pkt  0x%llx poff %u csumf/rxstart/rxval 0x%x/%u/0x%04x",
		    SK_KVA(pkt), poff, pkt->pkt_csum_flags,
		    (uint32_t)pkt->pkt_csum_rx_start_off,
		    (uint32_t)pkt->pkt_csum_rx_value);
		break;

	case NR_TX:
		dp = (uint8_t *)m->m_data;
		ASSERT(m->m_next == NULL);

		VERIFY(((intptr_t)dp - (intptr_t)mbuf_datastart(m)) + len <=
		    (uint32_t)mbuf_maxlen(m));
		m->m_len += len;
		m->m_pkthdr.len += len;
		VERIFY(m->m_len == m->m_pkthdr.len &&
		    (uint32_t)m->m_len <= (uint32_t)mbuf_maxlen(m));

		if (copysum) {
			uint16_t stuff = pkt->pkt_csum_tx_stuff_off;
			/*
			 * Use pkt_copy() to copy the portion up to the
			 * point where we need to start the checksum, and
			 * copy the remainder, checksumming as we go.
			 */
			if (__probable(start != 0)) {
				_pkt_copy(baddr, dp, start);
			}
			partial = __packet_copy_and_sum((baddr + start),
			    (dp + start), (len - start), 0);
			csum = __packet_fold_sum_final(partial);

			/* RFC1122 4.1.3.4: Invert 0 to -0 (for UDP) */
			if (csum == 0 &&
			    (pkt->pkt_csum_flags & PACKET_CSUM_ZERO_INVERT)) {
				csum = 0xffff;
			}

			/* Insert checksum into packet */
			ASSERT(stuff <= (len - sizeof(csum)));
			if (IS_P2ALIGNED(dp + stuff, sizeof(csum))) {
				*(uint16_t *)(uintptr_t)(dp + stuff) = csum;
			} else {
				bcopy((void *)&csum, dp + stuff, sizeof(csum));
			}
		} else {
			_pkt_copy(baddr, dp, len);
		}
		m->m_pkthdr.csum_flags &= ~CSUM_TX_FLAGS;
		m->m_pkthdr.csum_tx_start = 0;
		m->m_pkthdr.csum_tx_stuff = 0;
		m->m_pkthdr.csum_flags |= _convert_pkt_csum_flags(pkt->pkt_csum_flags);

		/* translate packet metadata */
		m->m_pkthdr.pkt_flowsrc = pkt->pkt_flowsrc_type;
		m->m_pkthdr.pkt_svc = pkt->pkt_svc_class;
		m->m_pkthdr.pkt_mpriv_srcid = pkt->pkt_flowsrc_token;
		m->m_pkthdr.pkt_flowid = pkt->pkt_flow_token;
		m->m_pkthdr.comp_gencnt = pkt->pkt_comp_gencnt;
		m->m_pkthdr.tso_segsz = pkt->pkt_proto_seg_sz;
		m->m_pkthdr.pkt_proto = pkt->pkt_flow->flow_ip_proto;
		mbuf_set_timestamp(m, pkt->pkt_timestamp,
		    ((pkt->pkt_pflags & PKT_F_TS_VALID) != 0));
		m->m_pkthdr.pkt_flags &= ~PKT_F_COMMON_MASK;
		m->m_pkthdr.pkt_flags |= (pkt->pkt_pflags & PKT_F_COMMON_MASK);
		if ((pkt->pkt_pflags & PKT_F_START_SEQ) != 0) {
			m->m_pkthdr.tx_start_seq = ntohl(pkt->pkt_flow_tcp_seq);
		}
		if ((pkt->pkt_pflags & PKT_F_L4S) != 0) {
			m->m_pkthdr.pkt_ext_flags |= PKTF_EXT_L4S;
		}
		if (__improbable(copy_pkt_tx_time != 0 &&
		    (pkt->pkt_pflags & PKT_F_OPT_TX_TIMESTAMP) != 0)) {
			struct m_tag *tag = NULL;
			tag = m_tag_create(KERNEL_MODULE_TAG_ID, KERNEL_TAG_TYPE_AQM,
			    sizeof(uint64_t), M_WAITOK, m);
			if (tag != NULL) {
				m_tag_prepend(m, tag);
				*(uint64_t *)tag->m_tag_data = pkt->pkt_com_opt->__po_pkt_tx_time;
			}
		}
		m->m_pkthdr.necp_mtag.necp_policy_id = pkt->pkt_policy_id;
		m->m_pkthdr.necp_mtag.necp_skip_policy_id = pkt->pkt_skip_policy_id;

		SK_DF(SK_VERB_COPY_MBUF | SK_VERB_TX,
		    "%s(%d) TX len %u, copy+sum %u (csum 0x%04x), start %u",
		    sk_proc_name_address(current_proc()),
		    sk_proc_pid(current_proc()), len,
		    (copysum ? (len - start) : 0), csum, start);
		SK_DF(SK_VERB_COPY_MBUF | SK_VERB_TX,
		    "   pkt  0x%llx poff %u csumf/txstart/txstuff 0x%x/%u/%u",
		    SK_KVA(pkt), poff, pkt->pkt_csum_flags,
		    (uint32_t)pkt->pkt_csum_tx_start_off,
		    (uint32_t)pkt->pkt_csum_tx_stuff_off);
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	if (pkt->pkt_link_flags & PKT_LINKF_BCAST) {
		m->m_flags |= M_BCAST;
	} else if (pkt->pkt_link_flags & PKT_LINKF_MCAST) {
		m->m_flags |= M_MCAST;
	}
	SK_DF(SK_VERB_COPY_MBUF | SK_VERB_DUMP, "%s(%d) %s %s",
	    sk_proc_name_address(current_proc()), sk_proc_pid(current_proc()),
	    (t == NR_RX) ? "RX" : "TX",
	    sk_dump("buf", (uint8_t *)dp, m->m_pkthdr.len, 128, NULL, 0));
}

/*
 * This is a multi-buflet variant of pkt_copy_to_mbuf().
 * NOTE: poff is the offset within the packet.
 *
 * This routine supports copying into an mbuf chain for RX but not TX.
 *
 * start/stuff is relative to poff, within [0, len], such that
 * [ 0 ... poff ... poff + start/stuff ... poff + len ... ]
 */
void
pkt_copy_multi_buflet_to_mbuf(const enum txrx t, kern_packet_t ph,
    const uint16_t poff, struct mbuf *m, const uint16_t moff,
    const uint32_t len, const boolean_t copysum, const uint16_t start)
{
	struct __kern_packet *pkt = SK_PTR_ADDR_KPKT(ph);
	struct mbuf *curr_m;
	uint32_t partial = 0;
	uint32_t remaining_len = len, copied_len = 0;
	uint16_t csum = 0;
	uint8_t *baddr;
	uint8_t *dp;
	boolean_t do_sum = copysum && !PACKET_HAS_FULL_CHECKSUM_FLAGS(pkt);

	ASSERT(len >= start);
	_CASSERT(sizeof(csum) == sizeof(uint16_t));

	/* get buffer address from packet */
	MD_BUFLET_ADDR_ABS(pkt, baddr);
	ASSERT(baddr != NULL);
	baddr += poff;
	VERIFY((poff + len) <= (PP_BUF_SIZE_DEF(pkt->pkt_qum.qum_pp) *
	    __packet_get_buflet_count(ph)));

	ASSERT((m->m_flags & M_PKTHDR));
	m->m_data += moff;

	switch (t) {
	case NR_RX:
		m->m_pkthdr.csum_flags &= ~CSUM_RX_FLAGS;
		if (__probable(do_sum && start != 0)) {
			ASSERT(M_TRAILINGSPACE(m) >= start);
			ASSERT(m->m_len == 0);
			dp = (uint8_t *)m->m_data;
			_pkt_copy(baddr, dp, start);
			remaining_len -= start;
			copied_len += start;
			m->m_len += start;
			m->m_pkthdr.len += start;
		}
		curr_m = m;
		while (curr_m != NULL && remaining_len != 0) {
			uint32_t tmp_len = MIN(remaining_len,
			    (uint32_t)M_TRAILINGSPACE(curr_m));
			uint16_t soff = poff + (uint16_t)copied_len;
			dp = (uint8_t *)curr_m->m_data + curr_m->m_len;

			if (__probable(do_sum)) {
				partial = _pkt_copyaddr_sum(ph, soff,
				    dp, tmp_len, TRUE, partial, NULL);
			} else {
				pkt_copyaddr_sum(ph, soff,
				    dp, tmp_len, FALSE, 0, NULL);
			}

			curr_m->m_len += tmp_len;
			m->m_pkthdr.len += tmp_len;
			copied_len += tmp_len;
			remaining_len -= tmp_len;
			curr_m = curr_m->m_next;
		}
		ASSERT(remaining_len == 0);

		if (__probable(do_sum)) {
			csum = __packet_fold_sum(partial);

			m->m_pkthdr.csum_flags |=
			    (CSUM_DATA_VALID | CSUM_PARTIAL);
			m->m_pkthdr.csum_rx_start = start;
			m->m_pkthdr.csum_rx_val = csum;
		} else {
			m->m_pkthdr.csum_rx_start = pkt->pkt_csum_rx_start_off;
			m->m_pkthdr.csum_rx_val = pkt->pkt_csum_rx_value;
			_CASSERT(CSUM_RX_FULL_FLAGS == PACKET_CSUM_RX_FULL_FLAGS);
			m->m_pkthdr.csum_flags |= pkt->pkt_csum_flags & PACKET_CSUM_RX_FULL_FLAGS;
			if (__improbable((pkt->pkt_csum_flags & PACKET_CSUM_PARTIAL) != 0)) {
				m->m_pkthdr.csum_flags |= CSUM_PARTIAL;
			}
		}

		m->m_pkthdr.necp_mtag.necp_policy_id = pkt->pkt_policy_id;
		m->m_pkthdr.necp_mtag.necp_skip_policy_id = pkt->pkt_skip_policy_id;

		/* translate packet metadata */
		mbuf_set_timestamp(m, pkt->pkt_timestamp,
		    ((pkt->pkt_pflags & PKT_F_TS_VALID) != 0));

		SK_DF(SK_VERB_COPY_MBUF | SK_VERB_RX,
		    "%s(%d) RX len %u, copy+sum %u (csum 0x%04x), start %u",
		    sk_proc_name_address(current_proc()),
		    sk_proc_pid(current_proc()), len,
		    (copysum ? (len - start) : 0), csum, start);
		SK_DF(SK_VERB_COPY_MBUF | SK_VERB_RX,
		    "   mbuf 0x%llx moff %u csumf/rxstart/rxval 0x%x/%u/0x%04x",
		    SK_KVA(m), moff, m->m_pkthdr.csum_flags,
		    (uint32_t)m->m_pkthdr.csum_rx_start,
		    (uint32_t)m->m_pkthdr.csum_rx_val);
		SK_DF(SK_VERB_COPY_MBUF | SK_VERB_RX,
		    "   pkt  0x%llx poff %u csumf/rxstart/rxval 0x%x/%u/0x%04x",
		    SK_KVA(pkt), poff, pkt->pkt_csum_flags,
		    (uint32_t)pkt->pkt_csum_rx_start_off,
		    (uint32_t)pkt->pkt_csum_rx_value);
		break;
	case NR_TX:
		dp = (uint8_t *)m->m_data;
		ASSERT(m->m_next == NULL);
		VERIFY(((intptr_t)dp - (intptr_t)mbuf_datastart(m)) + len <=
		    (uint32_t)mbuf_maxlen(m));
		m->m_len += len;
		m->m_pkthdr.len += len;
		VERIFY(m->m_len == m->m_pkthdr.len &&
		    (uint32_t)m->m_len <= (uint32_t)mbuf_maxlen(m));
		if (copysum) {
			uint16_t stuff = pkt->pkt_csum_tx_stuff_off;
			/*
			 * Use pkt_copy() to copy the portion up to the
			 * point where we need to start the checksum, and
			 * copy the remainder, checksumming as we go.
			 */
			if (__probable(start != 0)) {
				_pkt_copy(baddr, dp, start);
			}
			partial = _pkt_copyaddr_sum(ph, (poff + start),
			    (dp + start), (len - start), TRUE, 0, NULL);
			csum = __packet_fold_sum_final(partial);

			/* RFC1122 4.1.3.4: Invert 0 to -0 (for UDP) */
			if (csum == 0 &&
			    (pkt->pkt_csum_flags & PACKET_CSUM_ZERO_INVERT)) {
				csum = 0xffff;
			}

			/* Insert checksum into packet */
			ASSERT(stuff <= (len - sizeof(csum)));
			if (IS_P2ALIGNED(dp + stuff, sizeof(csum))) {
				*(uint16_t *)(uintptr_t)(dp + stuff) = csum;
			} else {
				bcopy((void *)&csum, dp + stuff, sizeof(csum));
			}
		} else {
			(void) _pkt_copyaddr_sum(ph, poff, dp, len, FALSE, 0, NULL);
		}
		m->m_pkthdr.csum_flags &= ~CSUM_TX_FLAGS;
		m->m_pkthdr.csum_tx_start = 0;
		m->m_pkthdr.csum_tx_stuff = 0;
		m->m_pkthdr.csum_flags |= _convert_pkt_csum_flags(pkt->pkt_csum_flags);

		/* translate packet metadata */
		m->m_pkthdr.pkt_flowsrc = pkt->pkt_flowsrc_type;
		m->m_pkthdr.pkt_svc = pkt->pkt_svc_class;
		m->m_pkthdr.pkt_mpriv_srcid = pkt->pkt_flowsrc_token;
		m->m_pkthdr.pkt_flowid = pkt->pkt_flow_token;
		m->m_pkthdr.comp_gencnt = pkt->pkt_comp_gencnt;
		m->m_pkthdr.tso_segsz = pkt->pkt_proto_seg_sz;
		m->m_pkthdr.pkt_proto = pkt->pkt_flow->flow_ip_proto;
		mbuf_set_timestamp(m, pkt->pkt_timestamp,
		    ((pkt->pkt_pflags & PKT_F_TS_VALID) != 0));
		m->m_pkthdr.pkt_flags &= ~PKT_F_COMMON_MASK;
		m->m_pkthdr.pkt_flags |= (pkt->pkt_pflags & PKT_F_COMMON_MASK);
		if ((pkt->pkt_pflags & PKT_F_START_SEQ) != 0) {
			m->m_pkthdr.tx_start_seq = ntohl(pkt->pkt_flow_tcp_seq);
		}
		if ((pkt->pkt_pflags & PKT_F_L4S) != 0) {
			m->m_pkthdr.pkt_ext_flags |= PKTF_EXT_L4S;
		}
		if (__improbable(copy_pkt_tx_time != 0 &&
		    (pkt->pkt_pflags & PKT_F_OPT_TX_TIMESTAMP) != 0)) {
			struct m_tag *tag = NULL;
			tag = m_tag_create(KERNEL_MODULE_TAG_ID, KERNEL_TAG_TYPE_AQM,
			    sizeof(uint64_t), M_WAITOK, m);
			if (tag != NULL) {
				m_tag_prepend(m, tag);
				*(uint64_t *)tag->m_tag_data = pkt->pkt_com_opt->__po_pkt_tx_time;
			}
		}

		SK_DF(SK_VERB_COPY_MBUF | SK_VERB_TX,
		    "%s(%d) TX len %u, copy+sum %u (csum 0x%04x), start %u",
		    sk_proc_name_address(current_proc()),
		    sk_proc_pid(current_proc()), len,
		    (copysum ? (len - start) : 0), csum, start);
		SK_DF(SK_VERB_COPY_MBUF | SK_VERB_TX,
		    "   pkt  0x%llx poff %u csumf/txstart/txstuff 0x%x/%u/%u",
		    SK_KVA(pkt), poff, pkt->pkt_csum_flags,
		    (uint32_t)pkt->pkt_csum_tx_start_off,
		    (uint32_t)pkt->pkt_csum_tx_stuff_off);
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	if (pkt->pkt_link_flags & PKT_LINKF_BCAST) {
		m->m_flags |= M_BCAST;
	} else if (pkt->pkt_link_flags & PKT_LINKF_MCAST) {
		m->m_flags |= M_MCAST;
	}
	SK_DF(SK_VERB_COPY_MBUF | SK_VERB_DUMP, "%s(%d) %s %s",
	    sk_proc_name_address(current_proc()), sk_proc_pid(current_proc()),
	    (t == NR_RX) ? "RX" : "TX",
	    sk_dump("buf", (uint8_t *)dp, m->m_pkthdr.len, 128, NULL, 0));
}

/*
 * Like m_copydata(), but computes 16-bit sum as the data is copied.
 * Caller can provide an initial sum to be folded into the computed
 * sum.  The accumulated partial sum (32-bit) is returned to caller;
 * caller is responsible for further reducing it to 16-bit if needed,
 * as well as to perform the final 1's complement on it.
 */
uint32_t
m_copydata_sum(struct mbuf *m, int off, int len, void *vp, uint32_t initial_sum,
    boolean_t *odd_start)
{
	boolean_t needs_swap, started_on_odd = FALSE;
	int off0 = off, len0 = len;
	struct mbuf *m0 = m;
	uint64_t sum, partial;
	unsigned count, odd;
	char *cp = vp;

	if (__improbable(off < 0 || len < 0)) {
		panic("%s: invalid offset %d or len %d", __func__, off, len);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	while (off > 0) {
		if (__improbable(m == NULL)) {
			panic("%s: invalid mbuf chain %p [off %d, len %d]",
			    __func__, m0, off0, len0);
			/* NOTREACHED */
			__builtin_unreachable();
		}
		if (off < m->m_len) {
			break;
		}
		off -= m->m_len;
		m = m->m_next;
	}

	if (odd_start) {
		started_on_odd = *odd_start;
	}
	sum = initial_sum;

	for (; len > 0; m = m->m_next) {
		uint8_t *datap;

		if (__improbable(m == NULL)) {
			panic("%s: invalid mbuf chain %p [off %d, len %d]",
			    __func__, m0, off0, len0);
			/* NOTREACHED */
			__builtin_unreachable();
		}

		datap = mtod(m, uint8_t *) + off;
		count = m->m_len;

		if (__improbable(count == 0)) {
			continue;
		}

		count = MIN(count - off, (unsigned)len);
		partial = 0;

		if ((uintptr_t)datap & 1) {
			/* Align on word boundary */
			started_on_odd = !started_on_odd;
#if BYTE_ORDER == LITTLE_ENDIAN
			partial = *datap << 8;
#else /* BYTE_ORDER != LITTLE_ENDIAN */
			partial = *datap;
#endif /* BYTE_ORDER != LITTLE_ENDIAN */
			*cp++ = *datap++;
			count -= 1;
			len -= 1;
		}

		needs_swap = started_on_odd;
		odd = count & 1u;
		count -= odd;

		if (count) {
			partial = __packet_copy_and_sum(datap,
			    cp, count, (uint32_t)partial);
			datap += count;
			cp += count;
			len -= count;
			if (__improbable((partial & (3ULL << 62)) != 0)) {
				if (needs_swap) {
					partial = (partial << 8) +
					    (partial >> 56);
				}
				sum += (partial >> 32);
				sum += (partial & 0xffffffff);
				partial = 0;
			}
		}

		if (odd) {
#if BYTE_ORDER == LITTLE_ENDIAN
			partial += *datap;
#else /* BYTE_ORDER != LITTLE_ENDIAN */
			partial += *datap << 8;
#endif /* BYTE_ORDER != LITTLE_ENDIAN */
			*cp++ = *datap++;
			len -= 1;
			started_on_odd = !started_on_odd;
		}
		off = 0;

		if (needs_swap) {
			partial = (partial << 8) + (partial >> 24);
		}
		sum += (partial >> 32) + (partial & 0xffffffff);
		/*
		 * Reduce sum to allow potential byte swap
		 * in the next iteration without carry.
		 */
		sum = (sum >> 32) + (sum & 0xffffffff);
	}

	if (odd_start) {
		*odd_start = started_on_odd;
	}

	/* Final fold (reduce 64-bit to 32-bit) */
	sum = (sum >> 32) + (sum & 0xffffffff); /* 33-bit */
	sum = (sum >> 16) + (sum & 0xffff);     /* 17-bit + carry */

	/* return 32-bit partial sum to caller */
	return (uint32_t)sum;
}

#if DEBUG || DEVELOPMENT
#define TRAILERS_MAX    16              /* max trailing bytes */
#define TRAILERS_REGEN  (64 * 1024)     /* regeneration threshold */
static uint8_t tb[TRAILERS_MAX];        /* random trailing bytes */
static uint32_t regen = TRAILERS_REGEN; /* regeneration counter */

uint32_t
pkt_add_trailers(kern_packet_t ph, const uint32_t len, const uint16_t start)
{
	struct __kern_packet *pkt = SK_PTR_ADDR_KPKT(ph);
	uint32_t extra;
	uint8_t *baddr;

	/* get buffer address from packet */
	MD_BUFLET_ADDR_ABS(pkt, baddr);
	ASSERT(baddr != NULL);
	ASSERT(len <= PP_BUF_SIZE_DEF(pkt->pkt_qum.qum_pp));

	extra = MIN((uint32_t)pkt_trailers, (uint32_t)TRAILERS_MAX);
	if (extra == 0 || extra > sizeof(tb) ||
	    (len + extra) > PP_BUF_SIZE_DEF(pkt->pkt_qum.qum_pp)) {
		return 0;
	}

	/* generate random bytes once per TRAILERS_REGEN packets (approx.) */
	if (regen++ == TRAILERS_REGEN) {
		read_frandom(&tb[0], sizeof(tb));
		regen = 0;
	}

	bcopy(&tb[0], (baddr + len), extra);

	/* recompute partial sum (also to exercise related logic) */
	pkt->pkt_csum_flags |= PACKET_CSUM_PARTIAL;
	pkt->pkt_csum_rx_value = (uint16_t)__packet_cksum((baddr + start),
	    ((len + extra) - start), 0);
	pkt->pkt_csum_rx_start_off = start;

	return extra;
}

uint32_t
pkt_add_trailers_mbuf(struct mbuf *m, const uint16_t start)
{
	uint32_t extra;

	extra = MIN((uint32_t)pkt_trailers, (uint32_t)TRAILERS_MAX);
	if (extra == 0 || extra > sizeof(tb)) {
		return 0;
	}

	if (mbuf_copyback(m, m_pktlen(m), extra, &tb[0], M_NOWAIT) != 0) {
		return 0;
	}

	/* generate random bytes once per TRAILERS_REGEN packets (approx.) */
	if (regen++ == TRAILERS_REGEN) {
		read_frandom(&tb[0], sizeof(tb));
		regen = 0;
	}

	/* recompute partial sum (also to exercise related logic) */
	m->m_pkthdr.csum_rx_val = m_sum16(m, start, (m_pktlen(m) - start));
	m->m_pkthdr.csum_flags &= ~CSUM_RX_FLAGS;
	m->m_pkthdr.csum_flags |= (CSUM_DATA_VALID | CSUM_PARTIAL);
	m->m_pkthdr.csum_rx_start = start;

	return extra;
}
#endif /* DEBUG || DEVELOPMENT */

void
pkt_copypkt_sum(kern_packet_t sph, uint16_t soff, kern_packet_t dph,
    uint16_t doff, uint16_t len, uint32_t *partial, boolean_t do_csum)
{
	VERIFY(_pkt_copypkt_sum(sph, soff, dph, doff, len, partial, do_csum));
}

uint32_t
pkt_copyaddr_sum(kern_packet_t sph, uint16_t soff, uint8_t *dbaddr,
    uint32_t len, boolean_t do_csum, uint32_t initial_sum, boolean_t *odd_start)
{
	return _pkt_copyaddr_sum(sph, soff, dbaddr, len, do_csum, initial_sum, odd_start);
}

uint32_t
pkt_mcopypkt_sum(mbuf_t m, int soff, kern_packet_t dph, uint16_t doff,
    uint16_t len, boolean_t do_cscum)
{
	return m_copypkt_sum(m, soff, dph, doff, len, do_cscum);
}

void
pkt_copy(void *src, void *dst, size_t len)
{
	return _pkt_copy(src, dst, len);
}
