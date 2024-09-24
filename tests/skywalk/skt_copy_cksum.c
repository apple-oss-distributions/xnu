/*
 * Copyright (c) 2015-2024 Apple Inc. All rights reserved.
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

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <libgen.h>
#include <machine/endian.h>
#include <darwintest.h>

#include "skywalk_test_driver.h"
#include "skywalk_test_common.h"
#include "skywalk_test_utils.h"

#define ST_MAX_OFFSET   128
#define ST_MIN_LEN      20
#define ST_MAX_LEN      (ST_MAX_OFFSET * 2)
#define ST_BUFFER_SIZE  (ST_MAX_LEN + ST_MAX_OFFSET)

static uint8_t st_src_buffer1[ST_BUFFER_SIZE]  __attribute((aligned(1024)));
static uint8_t st_src_buffer2[ST_BUFFER_SIZE / 2]  __attribute((aligned(1024)));
static uint8_t st_dst_buffer[ST_BUFFER_SIZE]  __attribute((aligned(1024)));
static uint8_t st_ref_buffer[ST_BUFFER_SIZE]  __attribute((aligned(1024)));
static time_t the_time;
static u_int verbose;


/*
 * Just enough of struct mbuf for m_copydata_sum()
 */
struct mbuf {
	void *m_data;
	u_int m_len;
	struct mbuf *m_next;
};
#define mtod(m, t)       ((t)((m)->m_data))

static uint32_t
__packet_copy_and_sum(const void *src, void *dst, uint32_t len,
    uint32_t sum0)
{
	uint32_t rv = os_copy_and_inet_checksum(src, dst, len, sum0);

	return (~rv) & 0xffffu;
}

static inline uint16_t
packet_fold_sum_final(uint32_t sum)
{
	sum = (sum >> 16) + (sum & 0xffff);     /* 17-bit */
	sum = (sum >> 16) + (sum & 0xffff);     /* 16-bit + carry */
	sum = (sum >> 16) + (sum & 0xffff);     /* final carry */
	return ~sum & 0xffff;
}

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
		T_LOG("%s: invalid offset %d or len %d", __func__, off, len);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	while (off > 0) {
		if (__improbable(m == NULL)) {
			T_LOG("%s: invalid mbuf chain %p [off %d, len %d]",
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
			T_LOG("%s: invalid mbuf chain %p [off %d, len %d]",
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

/*
 * This is taken from xnu/bsd/netinet/cpu_in_cksum_gen.c and is used to
 * generate reference checksums for the source data.
 */
uint32_t
reference_cksum_mbuf(struct mbuf *m, int len, int off, uint32_t initial_sum)
{
	int mlen;
	uint64_t sum, partial;
	uint32_t final_acc;
	uint8_t *data;
	boolean_t needs_swap, started_on_odd;

	needs_swap = FALSE;
	started_on_odd = FALSE;
	sum = initial_sum;

	for (;;) {
		if (m == NULL) {
			return -1;
		}
		mlen = m->m_len;
		if (mlen > off) {
			mlen -= off;
			data = m->m_data + off;
			goto post_initial_offset;
		}
		off -= mlen;
		if (len == 0) {
			break;
		}
		m = m->m_next;
	}

	for (; len > 0; m = m->m_next) {
		if (m == NULL) {
			return -1;
		}
		mlen = m->m_len;
		data = m->m_data;
post_initial_offset:
		if (mlen == 0) {
			continue;
		}
		if (mlen > len) {
			mlen = len;
		}
		len -= mlen;

		partial = 0;
		if ((uintptr_t)data & 1) {
			/* Align on word boundary */
			started_on_odd = !started_on_odd;
#if BYTE_ORDER == LITTLE_ENDIAN
			partial = *data << 8;
#else
			partial = *data;
#endif
			++data;
			--mlen;
		}
		needs_swap = started_on_odd;
		if ((uintptr_t)data & 2) {
			if (mlen < 2) {
				goto trailing_bytes;
			}
			partial += *(uint16_t *)(void *)data;
			data += 2;
			mlen -= 2;
		}
		while (mlen >= 64) {
			__builtin_prefetch(data + 32);
			__builtin_prefetch(data + 64);
			partial += *(uint32_t *)(void *)data;
			partial += *(uint32_t *)(void *)(data + 4);
			partial += *(uint32_t *)(void *)(data + 8);
			partial += *(uint32_t *)(void *)(data + 12);
			partial += *(uint32_t *)(void *)(data + 16);
			partial += *(uint32_t *)(void *)(data + 20);
			partial += *(uint32_t *)(void *)(data + 24);
			partial += *(uint32_t *)(void *)(data + 28);
			partial += *(uint32_t *)(void *)(data + 32);
			partial += *(uint32_t *)(void *)(data + 36);
			partial += *(uint32_t *)(void *)(data + 40);
			partial += *(uint32_t *)(void *)(data + 44);
			partial += *(uint32_t *)(void *)(data + 48);
			partial += *(uint32_t *)(void *)(data + 52);
			partial += *(uint32_t *)(void *)(data + 56);
			partial += *(uint32_t *)(void *)(data + 60);
			data += 64;
			mlen -= 64;
			if (partial & (3ULL << 62)) {
				if (needs_swap) {
					partial = (partial << 8) +
					    (partial >> 56);
				}
				sum += (partial >> 32);
				sum += (partial & 0xffffffff);
				partial = 0;
			}
		}
		/*
		 * mlen is not updated below as the remaining tests
		 * are using bit masks, which are not affected.
		 */
		if (mlen & 32) {
			partial += *(uint32_t *)(void *)data;
			partial += *(uint32_t *)(void *)(data + 4);
			partial += *(uint32_t *)(void *)(data + 8);
			partial += *(uint32_t *)(void *)(data + 12);
			partial += *(uint32_t *)(void *)(data + 16);
			partial += *(uint32_t *)(void *)(data + 20);
			partial += *(uint32_t *)(void *)(data + 24);
			partial += *(uint32_t *)(void *)(data + 28);
			data += 32;
		}
		if (mlen & 16) {
			partial += *(uint32_t *)(void *)data;
			partial += *(uint32_t *)(void *)(data + 4);
			partial += *(uint32_t *)(void *)(data + 8);
			partial += *(uint32_t *)(void *)(data + 12);
			data += 16;
		}
		if (mlen & 8) {
			partial += *(uint32_t *)(void *)data;
			partial += *(uint32_t *)(void *)(data + 4);
			data += 8;
		}
		if (mlen & 4) {
			partial += *(uint32_t *)(void *)data;
			data += 4;
		}
		if (mlen & 2) {
			partial += *(uint16_t *)(void *)data;
			data += 2;
		}
trailing_bytes:
		if (mlen & 1) {
#if BYTE_ORDER == LITTLE_ENDIAN
			partial += *data;
#else
			partial += *data << 8;
#endif
			started_on_odd = !started_on_odd;
		}

		if (needs_swap) {
			partial = (partial << 8) + (partial >> 56);
		}
		sum += (partial >> 32) + (partial & 0xffffffff);
		/*
		 * Reduce sum to allow potential byte swap
		 * in the next iteration without carry.
		 */
		sum = (sum >> 32) + (sum & 0xffffffff);
	}
	final_acc = (sum >> 48) + ((sum >> 32) & 0xffff) +
	    ((sum >> 16) & 0xffff) + (sum & 0xffff);
	final_acc = (final_acc >> 16) + (final_acc & 0xffff);
	final_acc = (final_acc >> 16) + (final_acc & 0xffff);

	return (~final_acc) & 0xffffu;
}

static void
randomise_buffer(uint8_t *buffer, u_int len)
{
	while (len--) {
		*buffer++ = (uint8_t)rand();
	}
}

static uint32_t
reference_cksum_single(u_int offset, u_int len, uint32_t init_sum)
{
	struct mbuf m;

	m.m_len = len;
	m.m_data = (void *)&st_src_buffer1[offset];
	m.m_next = NULL;

	return reference_cksum_mbuf(&m, len, 0, init_sum);
}

static uint32_t
target_cksum_single(u_int soffset, u_int doffset, u_int len, uint32_t init_sum)
{
	uint32_t rv;

	rv = os_copy_and_inet_checksum(&st_src_buffer1[soffset],
	    &st_dst_buffer[doffset], len, init_sum);

	return rv;
}

static uint32_t
reference_cksum_multi(u_int offset, u_int len, uint32_t init_sum)
{
	struct mbuf m[2];

	if (len > 1) {
		m[0].m_len = len / 2;
		m[0].m_data = (void *)&st_src_buffer1[offset];
		m[0].m_next = &m[1];
		m[1].m_len = len - m[0].m_len;
		m[1].m_data = (void *)&st_src_buffer2[offset];
		m[1].m_next = NULL;
	} else {
		m[0].m_len = 1;
		m[0].m_data = (void *)&st_src_buffer1[offset];
		m[0].m_next = NULL;
	}

	return reference_cksum_mbuf(&m[0], len, 0, init_sum);
}

static uint32_t
target_cksum_multi(u_int soffset, u_int doffset, u_int len, uint32_t init_sum)
{
	struct mbuf m[2];
	uint32_t sum;

	if (len > 1) {
		m[0].m_len = len / 2;
		m[0].m_data = (void *)&st_src_buffer1[soffset];
		m[0].m_next = &m[1];
		m[1].m_len = len - m[0].m_len;
		m[1].m_data = (void *)&st_src_buffer2[soffset];
		m[1].m_next = NULL;
	} else {
		m[0].m_len = 1;
		m[0].m_data = (void *)&st_src_buffer1[soffset];
		m[0].m_next = NULL;
	}

	sum = m_copydata_sum(&m[0], 0, len, &st_dst_buffer[doffset],
	    init_sum, NULL);

	/* Result of m_copydata_sum() requires folding to 16 bits */
	sum = (sum >> 16) + (sum & 0xffff);     /* 17-bit */
	sum = (sum >> 16) + (sum & 0xffff);     /* 16-bit + carry */
	sum = (sum >> 16) + (sum & 0xffff);     /* final carry */

	return (~sum) & 0xffffu;
}

static int
do_test_multi(u_int soffset, u_int doffset, u_int len, uint32_t init_sum)
{
	uint32_t ref_sum, tgt_sum;
	u_int m1_len;
	int rv;

	if (verbose) {
		T_LOG("Source offset 0x%03x, Dest offset 0x%03x, "
		    "Len %u, init_sum 0x%04x\n", soffset, doffset, len,
		    init_sum);
	}

	ref_sum = reference_cksum_multi(soffset, len, init_sum);
	if ((ref_sum & 0xffff0000u) != 0) {
		T_LOG("Multi: Source Offset %u, Dest Offset %u, "
		    "Len %u, ref_sum: Non-zero upper 16-bits: 0x%08x\n",
		    soffset, doffset, len, ref_sum);

		return 1;
	}

	memcpy(st_ref_buffer, st_dst_buffer, sizeof(st_ref_buffer));

	m1_len = len / 2;

	if (len > 1) {
		memcpy(&st_ref_buffer[doffset], &st_src_buffer1[soffset],
		    m1_len);
		memcpy(&st_ref_buffer[doffset + m1_len],
		    &st_src_buffer2[soffset], len - m1_len);
		if (verbose) {
			sktu_dump_buffer(stderr, "Multi Source1", &st_src_buffer1[soffset],
			    m1_len);
			sktu_dump_buffer(stderr, "Multi Source2", &st_src_buffer2[soffset],
			    len - m1_len);
		}
	} else {
		memcpy(&st_ref_buffer[doffset], &st_src_buffer1[soffset], 1);
		if (verbose) {
			sktu_dump_buffer(stderr, "Multi Source1", &st_src_buffer1[soffset],
			    1);
		}
	}

	if (verbose) {
		sktu_dump_buffer(stderr, "Multi Dest, pre-sum", &st_dst_buffer[doffset],
		    len);
	}

	tgt_sum = target_cksum_multi(soffset, doffset, len, init_sum);

	if (verbose) {
		sktu_dump_buffer(stderr, "Multi Dest, post-sum", &st_dst_buffer[doffset],
		    len);
		fputc('\n', stderr);
	}

	rv = 0;

	if ((tgt_sum & 0xffff0000u) != 0) {
		T_LOG("Multi: Source Offset %u, Dest Offset %u, "
		    "Len %u, Target: Non-zero upper 16-bits: 0x%08x\n", soffset,
		    doffset, len, ref_sum);

		rv = 1;
	} else if (ref_sum != tgt_sum) {
		T_LOG("Multi: Source Offset %u, Dest Offset %u, "
		    "Len %u, Checksum mismatch (ref:0x%04x != tgt:0x%04x)\n",
		    soffset, doffset, len, ref_sum, tgt_sum);

		rv = 1;
	}

	if (memcmp(st_dst_buffer, st_ref_buffer, sizeof(st_dst_buffer)) != 0) {
		T_LOG("Multi: Source Offset %u, Dest Offset %u, "
		    "Len %u, Target: Copy failed\n", soffset, doffset, len);

		rv = 1;
	} else if (rv != 0) {
		T_LOG("Multi: Checksum may have failed, but the copy "
		    "succeeded.\n");
	}

	return rv;
}

static int
do_test_single(u_int soffset, u_int doffset, u_int len, uint32_t init_sum)
{
	uint32_t ref_sum, tgt_sum;
	int rv;

	if (verbose) {
		T_LOG("Source offset 0x%03x, Dest offset 0x%03x, "
		    "Len %u, init_sum 0x%04x\n", soffset, doffset, len,
		    init_sum);
	}

	ref_sum = reference_cksum_single(soffset, len, init_sum);
	if ((ref_sum & 0xffff0000u) != 0) {
		T_LOG("Single: Source Offset %u, Dest Offset %u, "
		    "Len %u, ref_sum: Non-zero upper 16-bits: 0x%08x\n",
		    soffset, doffset, len, ref_sum);

		return 1;
	}

	memcpy(st_ref_buffer, st_dst_buffer, sizeof(st_ref_buffer));
	memcpy(&st_ref_buffer[doffset], &st_src_buffer1[soffset], len);

	if (verbose) {
		sktu_dump_buffer(stderr, "Single Source", &st_src_buffer1[soffset], len);
		sktu_dump_buffer(stderr, "Single Dest, pre-sum", &st_dst_buffer[doffset],
		    len);
	}

	tgt_sum = target_cksum_single(soffset, doffset, len, init_sum);

	if (verbose) {
		sktu_dump_buffer(stderr, "Single Dest, post-sum", &st_dst_buffer[doffset],
		    len);
		fputc('\n', stderr);
	}

	rv = 0;

	if ((tgt_sum & 0xffff0000u) != 0) {
		T_LOG("Single: Source Offset %u, Dest Offset %u, "
		    "Len %u, Target: Non-zero upper 16-bits: 0x%08x\n", soffset,
		    doffset, len, ref_sum);

		rv = 1;
	} else if (ref_sum != tgt_sum) {
		T_LOG("Single: Source Offset %u, Dest Offset %u, "
		    "Len %u, Checksum mismatch (ref:0x%04x != tgt:0x%04x)\n",
		    soffset, doffset, len, ref_sum, tgt_sum);

		rv = 1;
	}

	if (memcmp(st_dst_buffer, st_ref_buffer, sizeof(st_dst_buffer)) != 0) {
		T_LOG("Single: Source Offset %u, Dest Offset %u, "
		    "Len %u, Target: Copy failed\n", soffset, doffset, len);

		rv = 1;
	} else if (rv != 0) {
		T_LOG("Single: Checksum may have failed, but the "
		    "copy succeeded.\n");
	}

	return rv;
}

static int
do_test_cksum(u_int soffset, u_int len, uint32_t init_sum)
{
	uint32_t ref_sum, tgt_sum;
	int rv;

	if (verbose) {
		T_LOG("Source offset 0x%03x, "
		    "Len %u, init_sum 0x%04x\n", soffset, len, init_sum);
	}

	ref_sum = reference_cksum_single(soffset, len, init_sum);
	if ((ref_sum & 0xffff0000u) != 0) {
		T_LOG("Single: Source Offset %u, "
		    "Len %u, ref_sum: Non-zero upper 16-bits: 0x%08x\n",
		    soffset, len, ref_sum);

		return 1;
	}

	tgt_sum = os_inet_checksum(&st_src_buffer1[soffset], len, init_sum);
	tgt_sum = packet_fold_sum_final(tgt_sum);

	rv = 0;
	if ((tgt_sum & 0xffff0000u) != 0) {
		T_LOG("Single: Source Offset %u, "
		    "Len %u, Target: Non-zero upper 16-bits: 0x%08x\n",
		    soffset, len, ref_sum);

		rv = 1;
	} else if (ref_sum != tgt_sum) {
		T_LOG("Single: Source Offset %u, "
		    "Len %u, Checksum mismatch (ref:0x%04x != tgt:0x%04x)\n",
		    soffset, len, ref_sum, tgt_sum);

		rv = 1;
	}
	return rv;
}

static int
skt_copy_cksum_common(int argc, char **argv,
    int (*test_func)(u_int, u_int, u_int, uint32_t))
{
	uint32_t init_sum;
	u_int soffset, doffset;
	u_int len;

	if (the_time == 0) {
		(void) time(&the_time);
		srand(the_time);
	}

	verbose = (argc > 1 && strcmp(argv[1], "-v") == 0);

	if (verbose) {
		T_LOG("st_src_buffer1 %p\n", st_src_buffer1);
		T_LOG("st_src_buffer2 %p\n", st_src_buffer2);
		T_LOG("st_dst_buffer %p\n", st_dst_buffer);
		T_LOG("st_ref_buffer %p\n", st_ref_buffer);
	}

	randomise_buffer(st_src_buffer1, sizeof(st_src_buffer1));
	randomise_buffer(st_src_buffer2, sizeof(st_src_buffer2));
	randomise_buffer(st_dst_buffer, sizeof(st_dst_buffer));
	memcpy(st_ref_buffer, st_src_buffer1, sizeof(st_ref_buffer));

	for (len = ST_MIN_LEN; len <= ST_MAX_LEN; len++) {
		for (soffset = 0; soffset < ST_MAX_OFFSET; soffset++) {
			for (doffset = 0; doffset < ST_MAX_OFFSET; doffset++) {
				init_sum = rand() & 0xffffu;

				if (test_func(soffset, doffset, len, init_sum)) {
					goto fail;
				}
			}
		}
	}

	if (verbose) {
		T_LOG("Success\n");
	}
	return 0;

fail:
	if (verbose) {
		T_LOG("Fail\n");
	}

	return 1;
}

static int
skt_cksum_common(int argc, char **argv,
    int (*test_func)(u_int, u_int, uint32_t))
{
	uint32_t init_sum;
	u_int soffset;
	u_int len;

	if (the_time == 0) {
		(void) time(&the_time);
		srand(the_time);
	}

	verbose = (argc > 1 && strcmp(argv[1], "-v") == 0);

	if (verbose) {
		T_LOG("st_src_buffer1 %p\n", st_src_buffer1);
		T_LOG("st_ref_buffer %p\n", st_ref_buffer);
	}

	randomise_buffer(st_src_buffer1, sizeof(st_src_buffer1));
	memcpy(st_ref_buffer, st_src_buffer1, sizeof(st_ref_buffer));

	for (len = ST_MIN_LEN; len <= ST_MAX_LEN; len++) {
		for (soffset = 0; soffset < ST_MAX_OFFSET; soffset++) {
			init_sum = rand() & 0xffffu;
			if (test_func(soffset, len, init_sum)) {
				goto fail;
			}
		}
	}

	if (verbose) {
		T_LOG("Success\n");
	}
	return 0;

fail:
	if (verbose) {
		T_LOG("Fail\n");
	}

	return 1;
}

static int
skt_copy_cksum_single_main(int argc, char **argv)
{
	return skt_copy_cksum_common(argc, argv, do_test_single);
}

static int
skt_copy_cksum_multi_main(int argc, char **argv)
{
	return skt_copy_cksum_common(argc, argv, do_test_multi);
}

static int
skt_cksum_main(int argc, char **argv)
{
	return skt_cksum_common(argc, argv, do_test_cksum);
}

struct skywalk_test skt_copy_cksum_single = {
	"copycksum-single", "test copy/checksum code: single buffer",
	SK_FEATURE_SKYWALK,
	skt_copy_cksum_single_main, { NULL },
	NULL, NULL,
};

struct skywalk_test skt_copy_cksum_multi = {
	"copycksum-multi", "test copy/checksum code: buffer chain",
	SK_FEATURE_SKYWALK,
	skt_copy_cksum_multi_main, { NULL },
	NULL, NULL,
};

struct skywalk_test skt_cksum = {
	"inetcksum", "test checksum code",
	SK_FEATURE_SKYWALK,
	skt_cksum_main, { NULL },
	NULL, NULL,
};
