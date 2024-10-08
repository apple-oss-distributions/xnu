/* <rdar://problem/49479689> arm64 os_cpu_in_cksum_mbuf sometimes incorrect with unaligned input buffer */

#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>

#include <darwintest.h>

T_GLOBAL_META(T_META_RUN_CONCURRENTLY(true));

extern uint32_t os_cpu_in_cksum(const void *, uint32_t, uint32_t);

/****************************************************************/
static void
log_hexdump(const void *inp, size_t len)
{
	unsigned i, off = 0;
	char buf[9 + 16 * 3 + 1];
	for (i = 0; i < len; i++) {
		if (i % 16 == 0) {
			off = (unsigned)snprintf(buf, sizeof(buf), "%08x:", i);
		}
		off += (unsigned)snprintf(buf + off, sizeof(buf) - off, " %02x", (((const uint8_t *)inp)[i]) & 0xff);
		if (i % 16 == 15) {
			T_LOG("%s", buf);
		}
	}
	if (len % 16) {
		T_LOG("%s", buf);
	}
}

/* I was going to use the one from rfc1701 section 4.1
 * but then I saw the errata.  Hopefully this is dumb but
 * correct, even though it is not particularly efficient.
 */
static uint16_t
dumb_in_cksum(const uint8_t *buf, size_t len)
{
	uint32_t partial = 0;
	while (len > 1) {
		uint16_t val = buf[1];
		val <<= 8;
		val |= buf[0];
		len -= 2;
		buf += 2;
		partial += val;
		while ((val = partial >> 16)) {
			partial &= 0xffff;
			partial += val;
		}
	}
	if (len) {
		uint16_t val = buf[0];
		partial += val;
		while ((val = partial >> 16)) {
			partial &= 0xffff;
			partial += val;
		}
	}
	return ~partial & 0xffff;
}

/* Calculate a checksum divided into partial checksums */
static uint16_t
split_in_cksum(const uint8_t *buf, int nsegs, const uint32_t *seglens, const uint8_t *aligns, uint8_t *tmpbuf)
{
	uint32_t partial = 0;

	for (int i = 0; i < nsegs; i++) {
		/* Only the last segment can have an odd length */
		assert((i + 1 == nsegs) || seglens[i] % 2 == 0);

		/* Copy a segment into the tmpbuf with the requested alignment */
		memcpy(tmpbuf + aligns[i], buf, seglens[i]);

		partial = os_cpu_in_cksum(tmpbuf + aligns[i], seglens[i], partial);
		buf += seglens[i];
	}

	return ~partial & 0xffff;
}

static void
test_checksum(const uint8_t *data, uint32_t len)
{
	uint16_t dsum = dumb_in_cksum(data, len);

	const uint8_t MAXALIGN = 8;

	uint8_t tmpbuf[len + MAXALIGN];
	uint32_t seglens[2];
	uint8_t aligns[2];
	for (uint16_t split = 0; split < len; split += 2) {
		seglens[0] = split;
		seglens[1] = len - split;
		for (aligns[0] = 0; aligns[0] < MAXALIGN; aligns[0]++) {
			for (aligns[1] = 0; aligns[1] < MAXALIGN; aligns[1]++) {
				uint16_t osum = split_in_cksum(data, 2, seglens, aligns, tmpbuf);
				if (osum != dsum) {
					/* hexdump packet and alignments for debugging */
					log_hexdump(data, len);
					T_LOG("len %d seg[0] %d seg[1] %d align[0] %d align[1] %d\n", len, seglens[0], seglens[1], aligns[0], aligns[1]);
				}
				T_QUIET; T_ASSERT_EQ(osum, dsum, "checksum mismatch got 0x%04x expecting 0x%04x", htons(osum), htons(dsum));
			}
		}
	}
	T_PASS("OK len %d", len);
}

static void
test_one_random_packet(uint32_t maxlen)
{
	/* Pick a packet length */
	uint32_t len = arc4random_uniform(maxlen);
	uint8_t data[len];
	arc4random_buf(data, len);
	test_checksum(data, len);
}

/*
 * This is the checksummed portion of the first packet in checksum_error.pcap
 * It is known to cause a problem at splits 44 and 46 with second alignment of 1 or 3
 */
static uint8_t pkt49479689[] = {
/*00000000*/ 0xc0, 0xa8, 0x01, 0x06, 0xc0, 0xa8, 0x01, 0x07, 0x00, 0x06, 0x05, 0xc8, 0xcb, 0xf1, 0xc0, 0x24,  // |...............$|
/*00000010*/ 0x2d, 0x23, 0x48, 0xd6, 0x3b, 0x44, 0x96, 0x7f, 0x80, 0x10, 0x20, 0x86, 0x00, 0x00, 0x00, 0x00,  // |-#H.;D.... ..,..|
/*00000020*/ 0x01, 0x01, 0x08, 0x0a, 0x0c, 0xc4, 0x69, 0x3a, 0x31, 0x63, 0xb3, 0x37, 0x55, 0xe1, 0x62, 0x48,  // |......i:1c.7U.bH|
/*00000030*/ 0xa4, 0xff, 0xff, 0xa0, 0xc5, 0xd9, 0x5d, 0xd2, 0x4d, 0xe4, 0xca, 0xd7, 0x83, 0x27, 0xcc, 0x90,  // |......].M....'..|
/*00000040*/ 0x02, 0x26, 0x63, 0xd3, 0x02, 0x3c, 0xf1, 0x20, 0x15, 0xa6, 0x8b, 0xff, 0x98, 0x8d, 0x57, 0x2a,  // |.&c..<. ......W*|
/*00000050*/ 0x06, 0x4b, 0x06, 0x49, 0x5d, 0x8a, 0x28, 0x66, 0xe6, 0x57, 0x71, 0xd9, 0x27, 0xd1, 0xb9, 0xd6,  // |.K.I].(f.Wq.'...|
/*00000060*/ 0x20, 0x48, 0x13, 0x2e, 0xbf, 0x30, 0x8c, 0xce, 0x49, 0x99, 0x2a, 0xb7, 0x94, 0xa4, 0x3a, 0x8e,  // | H...0..I.*...:.|
/*00000070*/ 0x35, 0xcc, 0x48, 0xb2, 0x7f, 0xe1, 0xca, 0x2f, 0x08, 0x49, 0x7f, 0x35, 0x61, 0xcf, 0x59, 0xa2,  // |5.H..../.I.5a.Y.|
/*00000080*/ 0x3a, 0x5e, 0x10, 0x5a, 0x0a, 0xd7, 0xa2, 0x38, 0x64, 0xe1, 0x7c, 0x5d, 0xbd, 0x29, 0x65, 0x5a,  // |:^.Z...8d.|].)eZ|
/*00000090*/ 0xf2, 0x14, 0x30, 0x51, 0x9b, 0x56, 0xbb, 0xe2, 0x04, 0x48, 0x04, 0x23, 0x53, 0x30, 0x3a, 0x0a,  // |..0Q.V...H.#S0:.|
/*000000a0*/ 0x48, 0x5a, 0xdd, 0xe4, 0xd7, 0x5e, 0x5b, 0x5d, 0x90, 0x89, 0x7d, 0xf0, 0xad, 0x24, 0x1a, 0xa8,  // |HZ...^[]..}..$..|
/*000000b0*/ 0x81, 0xc1, 0x6b, 0x11, 0x97, 0x68, 0xc0, 0xbb, 0xe4, 0x5c, 0xba, 0x1a, 0xe8, 0x9c, 0xc9, 0x8b,  // |..k..h...\......|
/*000000c0*/ 0xb8, 0x2b, 0x11, 0x85, 0x7f, 0xbf, 0x19, 0x81, 0xb0, 0xfc, 0xfd, 0x4a, 0xac, 0x7b, 0xd3, 0x60,  // |.+.........J.{.`|
/*000000d0*/ 0x44, 0x1f, 0x5e, 0x8d, 0x05, 0x6e, 0xd7, 0xd1, 0xef, 0x11, 0x84, 0xd3, 0x0d, 0x63, 0xcf, 0x56,  // |D.^..n.......c.V|
/*000000e0*/ 0xf9, 0x27, 0xc4, 0xd0, 0x39, 0x0e, 0xac, 0x7e, 0xba, 0xb3, 0xb8, 0x9c, 0x21, 0x21, 0xc8, 0xa0,  // |.'..9..~....!!..|
/*000000f0*/ 0xbc, 0xd8, 0x82, 0x6f, 0x81, 0xa6, 0xc2, 0xf5, 0xe0, 0xdb, 0x41, 0xd0, 0xd4, 0x18, 0x2a, 0x5b,  // |...o......A...*[|
/*00000100*/ 0x93, 0x3d, 0x5a, 0x08, 0xe2, 0xac, 0x8d, 0xd3, 0x7d, 0xcc, 0x49, 0x33, 0xc9, 0xb8, 0x9e, 0x12,  // |.=Z.....}.I3....|
/*00000110*/ 0x86, 0x63, 0x38, 0x9c, 0xce, 0x4a, 0xb7, 0xcc, 0xe9, 0x4b, 0x5e, 0xb5, 0x24, 0x42, 0x47, 0x28,  // |.c8..J...K^.$BG(|
/*00000120*/ 0x1c, 0x09, 0xe8, 0x84, 0xa6, 0xf0, 0x5f, 0x03, 0x94, 0x6f, 0x6a, 0x18, 0x60, 0xc3, 0x12, 0x58,  // |......_..oj.`..X|
/*00000130*/ 0x6c, 0xbe, 0x13, 0x85, 0xa4, 0xdf, 0xe1, 0x8c, 0x3a, 0x04, 0xe9, 0x56, 0xa3, 0x09, 0x41, 0xf1,  // |l.......:..V..A.|
/*00000140*/ 0x70, 0xf5, 0xc4, 0x27, 0x8e, 0x18, 0x09, 0x56, 0x5f, 0x82, 0x08, 0xec, 0x84, 0x55, 0x3b, 0x58,  // |p..'...V_....U;X|
/*00000150*/ 0x84, 0x7b, 0xc8, 0x63, 0x70, 0x6a, 0x83, 0x04, 0xc8, 0xff, 0xe7, 0x6a, 0xbc, 0xee, 0xc0, 0xfe,  // |.{.cpj.....j....|
/*00000160*/ 0xef, 0x60, 0xb7, 0x04, 0xb5, 0x57, 0x53, 0x5b, 0xeb, 0x4d, 0xec, 0x22, 0xe8, 0x59, 0x22, 0x64,  // |.`...WS[.M.".Y"d|
/*00000170*/ 0x20, 0x5a, 0x61, 0x7d, 0x92, 0x02, 0x80, 0xd0, 0x85, 0x56, 0x98, 0x75, 0xbe, 0x35, 0xaf, 0xe4,  // | Za}.....V.u.5..|
/*00000180*/ 0xc3, 0x06, 0xfa, 0xc2, 0x29, 0xce, 0x80, 0xe2, 0x68, 0xf3, 0xd8, 0x4b, 0x72, 0x46, 0x6e, 0xa3,  // |....)...h..KrFn.|
/*00000190*/ 0x88, 0x57, 0xfb, 0x08, 0xec, 0x60, 0x2f, 0x3c, 0xa4, 0xaf, 0x08, 0x64, 0x45, 0x16, 0xba, 0x7b,  // |.W...`/<...dE..{|
/*000001a0*/ 0xad, 0x24, 0x7a, 0x1f, 0x53, 0x46, 0x0c, 0xe6, 0xe9, 0x99, 0xd7, 0x2b, 0x9d, 0x62, 0xd9, 0x4a,  // |.$z.SF.....+.b.J|
/*000001b0*/ 0x80, 0x2a, 0x43, 0xc2, 0x78, 0xa6, 0x6b, 0x38, 0x8e, 0xc8, 0x40, 0x6b, 0x03, 0xe2, 0x47, 0x04,  // |.*C.x.k8..@k..G.|
/*000001c0*/ 0xda, 0x08, 0x72, 0xf5, 0xbc, 0x66, 0x3f, 0x33, 0x4d, 0xb6, 0x26, 0xd0, 0x66, 0x8c, 0xa0, 0x70,  // |..r..f?3M.&.f..p|
/*000001d0*/ 0x25, 0xbc, 0x68, 0xda, 0x02, 0x79, 0x89, 0xed, 0x0c, 0xfc, 0xe7, 0x3d, 0x15, 0xcf, 0x5e, 0xc9,  // |%.h..y.....=..^.|
/*000001e0*/ 0x63, 0xe0, 0x64, 0xb1, 0xfb, 0x28, 0xf7, 0x29, 0x52, 0xcf, 0x7a, 0xe3, 0x6d, 0x46, 0xc5, 0x1a,  // |c.d..(.)R.z.mF..|
/*000001f0*/ 0x71, 0x24, 0x4e, 0x12, 0x56, 0x86, 0xc7, 0xf5, 0x98, 0x3e, 0xa9, 0xbc, 0x5d, 0xe9, 0x22, 0x88,  // |q$N.V....>..].".|
/*00000200*/ 0x9b, 0x61, 0xc4, 0xa2, 0xcc, 0x27, 0x54, 0x07, 0x88, 0xeb, 0xe1, 0x4e, 0xaa, 0x0a, 0xd6, 0x94,  // |.a...'T....N....|
/*00000210*/ 0x83, 0x32, 0xf8, 0x1d, 0xff, 0x67, 0xe5, 0x63, 0x78, 0x04, 0x11, 0x24, 0x25, 0xd7, 0x22, 0x54,  // |.2...g.cx..$%."T|
/*00000220*/ 0x73, 0x87, 0xc9, 0x53, 0x72, 0x51, 0xda, 0x24, 0x33, 0xd7, 0x5c, 0x40, 0x86, 0x77, 0xf9, 0xc2,  // |s..SrQ.$3.\@.w..|
/*00000230*/ 0xeb, 0x7d, 0x4c, 0x72, 0xeb, 0xc9, 0x8b, 0xcc, 0x79, 0xcd, 0x4a, 0x5a, 0x9e, 0xe2, 0x83, 0x20,  // |.}Lr....y.JZ... |
/*00000240*/ 0x19, 0x5b, 0x4b, 0xe6, 0x5c, 0xe2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x7b, 0x80, 0x69,  // |.[K.\........{.i|
/*00000250*/ 0x29, 0x53, 0x97, 0xc2, 0xc9, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x67, 0x75, 0x81, 0x80, 0x12, 0x6e,  // |)S...L....gu...n|
/*00000260*/ 0x50, 0x66, 0xe9, 0x0a, 0x28, 0x3b, 0x1a, 0xf1, 0xcb, 0x46, 0x72, 0xf7, 0xe9, 0x9f, 0x84, 0x29,  // |Pf..(;...Fr....)|
/*00000270*/ 0xb9, 0x95, 0xf9, 0x6d, 0x5d, 0x04, 0x51, 0x7f, 0x0e, 0xf0, 0xe4, 0x3d, 0x4b, 0xd2, 0xb2, 0xb5,  // |...m].Q....=K...|
/*00000280*/ 0x51, 0xf0, 0x31, 0x8e, 0x55, 0x18, 0x54, 0xf7, 0xee, 0x03, 0x37, 0x07, 0x33, 0x43, 0x8b, 0x5a,  // |Q.1.U.T...7.3C.Z|
/*00000290*/ 0x1d, 0x16, 0xe8, 0xc4, 0x8b, 0x2c, 0x8a, 0x01, 0x5c, 0x45, 0xc6, 0xd1, 0x9d, 0xa9, 0x0a, 0xe2,  // |.....,..\E......|
/*000002a0*/ 0x15, 0x4b, 0x8b, 0x00, 0x84, 0xbf, 0x3d, 0xad, 0xed, 0x86, 0x8e, 0x5c, 0x76, 0xe9, 0xbe, 0x4b,  // |.K....=....\v..K|
/*000002b0*/ 0xd5, 0xb5, 0xb0, 0x08, 0x7f, 0xd7, 0x71, 0x57, 0x44, 0x67, 0x31, 0x8b, 0x43, 0x7d, 0xf8, 0x5a,  // |......qWDg1.C}.Z|
/*000002c0*/ 0xcd, 0xe6, 0x4c, 0xec, 0x89, 0xa5, 0xd1, 0x03, 0x86, 0xfd, 0x01, 0x7d, 0x22, 0x32, 0xf0, 0xc3,  // |..L........}"2..|
/*000002d0*/ 0x23, 0x99, 0x8e, 0x69, 0x14, 0x54, 0x54, 0x03, 0xec, 0x27, 0x6a, 0x7d, 0x13, 0xc7, 0xe2, 0x39,  // |#..i.TT..'j}...9|
/*000002e0*/ 0x2b, 0xc0, 0x1a, 0x70, 0x82, 0xe9, 0x80, 0x73, 0xf4, 0x27, 0x26, 0xca, 0x5c, 0xf6, 0x7f, 0x46,  // |+..p...s.'&.\..F|
/*000002f0*/ 0xf7, 0x00, 0x58, 0x3c, 0x3a, 0xcc, 0x1e, 0x9b, 0xd2, 0x22, 0x78, 0x04, 0x23, 0xc6, 0xfb, 0xdf,  // |..X<:...."x.#...|
/*00000300*/ 0x8b, 0x36, 0xd6, 0xfa, 0xd8, 0x53, 0xbd, 0x0e, 0xaf, 0x1a, 0x04, 0xd1, 0x81, 0xd6, 0x1f, 0x1a,  // |.6...S..........|
/*00000310*/ 0x74, 0x4d, 0xcf, 0xf6, 0xcf, 0x61, 0x6c, 0xd9, 0x7f, 0x1e, 0xb3, 0x1c, 0x2e, 0x74, 0x1a, 0x37,  // |tM...al......t.7|
/*00000320*/ 0xfa, 0x2a, 0x24, 0x6d, 0xc2, 0x6d, 0x54, 0xfb, 0xd7, 0x9b, 0x34, 0x87, 0xeb, 0xac, 0x38, 0xc7,  // |.*$m.mT...4...8.|
/*00000330*/ 0xe3, 0xc9, 0x6a, 0x98, 0x04, 0x2b, 0x33, 0x2d, 0x87, 0xf4, 0x25, 0xd6, 0x64, 0x14, 0xe8, 0xd0,  // |..j..+3-..%.d...|
/*00000340*/ 0x84, 0x18, 0xc0, 0x39, 0x4d, 0xb5, 0xe5, 0xe2, 0xdb, 0x74, 0x59, 0x52, 0xad, 0x91, 0x1a, 0x55,  // |...9M....tYR...U|
/*00000350*/ 0xae, 0xa3, 0xe1, 0x73, 0x4e, 0x76, 0x14, 0x94, 0xab, 0xec, 0x69, 0xb7, 0x0c, 0xa3, 0x71, 0x14,  // |...sNv....i...q.|
/*00000360*/ 0x04, 0xbf, 0xf9, 0x75, 0xca, 0x2b, 0x8a, 0xa4, 0x5b, 0xe6, 0xe8, 0x61, 0x8d, 0xad, 0x1a, 0x62,  // |...u.+..[..a...b|
/*00000370*/ 0x97, 0xaa, 0xfa, 0x3f, 0x88, 0x75, 0xcd, 0xe7, 0x29, 0x66, 0xbd, 0xcf, 0x50, 0xfd, 0x10, 0x09,  // |...?.u..)f..P...|
/*00000380*/ 0x45, 0x2e, 0x97, 0xd5, 0x7c, 0xb4, 0x12, 0x7a, 0x5f, 0xfc, 0x1c, 0x74, 0x02, 0xf0, 0xa7, 0x98,  // |E...|..z_..t....|
/*00000390*/ 0xd2, 0x03, 0x86, 0x19, 0x08, 0x54, 0x3d, 0x4d, 0x88, 0x13, 0x88, 0x87, 0x26, 0x61, 0x3e, 0x88,  // |.....T=M....&a>.|
/*000003a0*/ 0xf8, 0x18, 0xcc, 0xac, 0x6f, 0xec, 0x12, 0x57, 0xfe, 0x80, 0xa3, 0xbe, 0x04, 0x39, 0x52, 0xe0,  // |....o..W.....9R.|
/*000003b0*/ 0xc3, 0xfa, 0xed, 0x4f, 0xf5, 0x07, 0x59, 0x7e, 0xfa, 0xb9, 0x35, 0x36, 0xf2, 0x55, 0x23, 0xab,  // |...O..Y~..56.U#.|
/*000003c0*/ 0x15, 0x65, 0x57, 0xb2, 0xce, 0xdb, 0x63, 0xe0, 0x1f, 0x1f, 0xa5, 0xfa, 0x70, 0x2e, 0x53, 0x76,  // |.eW...c.....p.Sv|
/*000003d0*/ 0x20, 0x5b, 0x54, 0xc2, 0x0f, 0xe9, 0xca, 0x2c, 0x82, 0xf1, 0x30, 0x61, 0xbb, 0x99, 0x1e, 0x2a,  // | [T....,..0a...*|
/*000003e0*/ 0xa2, 0x71, 0x91, 0x39, 0x07, 0xda, 0xcd, 0x50, 0xbb, 0x73, 0x5b, 0xa4, 0x05, 0x26, 0xee, 0x9f,  // |.q.9...P.s[..&..|
/*000003f0*/ 0x5e, 0x88, 0x72, 0x92, 0xc9, 0x60, 0x2b, 0xd7, 0x6a, 0x91, 0x40, 0x52, 0x6b, 0xd1, 0xab, 0x00,  // |^.r..`+.j.@Rk...|
/*00000400*/ 0xcc, 0x60, 0x53, 0x9b, 0x36, 0x40, 0x3b, 0x60, 0x18, 0x7f, 0x5f, 0xc2, 0x8c, 0x44, 0x08, 0xae,  // |.`S.6@;`.._..D..|
/*00000410*/ 0x95, 0xae, 0x8c, 0xd7, 0x8d, 0x68, 0x4a, 0x42, 0x64, 0x1d, 0xdf, 0xdc, 0x17, 0x1a, 0x28, 0xe0,  // |.....hJBd.....(.|
/*00000420*/ 0x55, 0x35, 0x00, 0x65, 0xe4, 0xd4, 0xd7, 0x3e, 0x1c, 0x6a, 0xa1, 0xbf, 0xba, 0xd8, 0x29, 0xce,  // |U5.e...>.j....).|
/*00000430*/ 0xa6, 0x1f, 0xf9, 0x06, 0xff, 0x70, 0x43, 0xc8, 0xa0, 0x49, 0x03, 0xcd, 0x19, 0xf2, 0x16, 0x01,  // |.....pC..I......|
/*00000440*/ 0x46, 0xf0, 0x29, 0xdb, 0xc2, 0x85, 0x89, 0x20, 0x37, 0x91, 0xd3, 0x74, 0x1c, 0x38, 0x08, 0xb3,  // |F.).... 7..t.8..|
/*00000450*/ 0xd5, 0xa3, 0x4c, 0x52, 0x6e, 0xb3, 0x24, 0xc0, 0xbc, 0xd6, 0xc6, 0x64, 0x0b, 0x40, 0x44, 0xc4,  // |..LRn.$....d.@D.|
/*00000460*/ 0xb9, 0x11, 0x10, 0x2a, 0xcd, 0x43, 0x99, 0x47, 0xe9, 0xfb, 0xf0, 0xe0, 0x56, 0x13, 0x40, 0x41,  // |...*.C.G....V.@A|
/*00000470*/ 0x8a, 0x41, 0xcc, 0x92, 0x8d, 0xd5, 0xb9, 0x47, 0x05, 0xc7, 0x72, 0x76, 0x02, 0x09, 0x05, 0xd9,  // |.A.....G..rv....|
/*00000480*/ 0x12, 0xb6, 0xa8, 0x0a, 0x86, 0x28, 0x5c, 0x41, 0x7e, 0xf1, 0xbc, 0xa9, 0x93, 0xae, 0xdf, 0x0b,  // |.....(\A~.......|
/*00000490*/ 0xa1, 0xfc, 0x47, 0xb5, 0xde, 0x1c, 0x25, 0xe9, 0x8b, 0xb2, 0x03, 0x3a, 0xa7, 0x36, 0x4e, 0xcb,  // |..G...%....:.6N.|
/*000004a0*/ 0xfa, 0xcd, 0xe6, 0x4f, 0x67, 0x3f, 0xe2, 0xa3, 0x3d, 0xdb, 0x61, 0x0d, 0x99, 0x05, 0x15, 0x96,  // |...Og?..=.a.....|
/*000004b0*/ 0x14, 0x4e, 0x89, 0xf7, 0x8b, 0xdd, 0x84, 0x48, 0x35, 0xa8, 0x5c, 0x73, 0x67, 0x5d, 0x55, 0x5d,  // |.N.....H5.\sg]U]|
/*000004c0*/ 0xe2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x82, 0x80, 0x69, 0x29, 0x54, 0x97, 0xc2, 0xcd,  // |..........i)T...|
/*000004d0*/ 0x4c, 0x00, 0x00, 0x00, 0x00, 0x44, 0x07, 0x64, 0xa1, 0x66, 0xe3, 0x3c, 0x6e, 0x51, 0x96, 0x6a,  // |L....D.d.f.<nQ.j|
/*000004e0*/ 0x06, 0x8c, 0x08, 0x92, 0x24, 0x03, 0xe1, 0xc2, 0xce, 0x80, 0x56, 0x75, 0x78, 0xd3, 0xc8, 0x1d,  // |....$.....Vux...|
/*000004f0*/ 0x52, 0xc6, 0x32, 0xbf, 0x89, 0x91, 0x1a, 0x81, 0x9f, 0x11, 0x69, 0xd6, 0x9b, 0x27, 0x20, 0x19,  // |R.2.......i..' .|
/*00000500*/ 0x59, 0x12, 0x2d, 0x85, 0x7e, 0x3a, 0xed, 0xa9, 0xd7, 0x92, 0xa4, 0x2d, 0xce, 0x2f, 0xf0, 0xd4,  // |Y.-.~:.....-./..|
/*00000510*/ 0x0e, 0xec, 0xe4, 0xd8, 0x0c, 0xaf, 0x1c, 0x28, 0xe8, 0x47, 0xef, 0x04, 0x61, 0x2a, 0x38, 0x94,  // |.......(.G..a*8.|
/*00000520*/ 0x40, 0x2f, 0x92, 0x3e, 0x8a, 0xcd, 0x24, 0xfc, 0xba, 0xa6, 0x68, 0xa7, 0x2c, 0xbb, 0xc1, 0x67,  // |@/.>..$...h.,..g|
/*00000530*/ 0x5f, 0x0b, 0x85, 0x75, 0x70, 0xa5, 0x03, 0x0e, 0x25, 0xe2, 0x09, 0x34, 0x78, 0x66, 0x6f, 0xe0,  // |_..up...%..4xfo.|
/*00000540*/ 0xf6, 0xac, 0xaf, 0xc6, 0x4a, 0xbc, 0xda, 0xc5, 0x06, 0x9e, 0x53, 0xe8, 0x75, 0x0b, 0x50, 0xde,  // |....J.....S.u.P.|
/*00000550*/ 0xf7, 0xc0, 0x7f, 0x78, 0x97, 0x13, 0x22, 0x76, 0x18, 0x88, 0xf9, 0x99, 0xa1, 0x05, 0x42, 0xee,  // |...x.."v......B.|
/*00000560*/ 0x40, 0xf0, 0xb7, 0x00, 0x0e, 0xf5, 0xac, 0x7c, 0xe5, 0x8b, 0x1f, 0x05, 0xe3, 0xd1, 0x9d, 0x6b,  // |@......|.......k|
/*00000570*/ 0xd4, 0x9c, 0x3d, 0x14, 0x08, 0x21, 0xce, 0x72, 0x8f, 0x91, 0x9c, 0xba, 0xdd, 0x46, 0xcd, 0xef,  // |..=..!.r.....F..|
/*00000580*/ 0x6d, 0x7b, 0x0d, 0x7d, 0x59, 0x91, 0x05, 0xc2, 0xde, 0x6c, 0x8a, 0x65, 0xd0, 0x97, 0xb1, 0x93,  // |m{.}Y....l.e....|
/*00000590*/ 0x9f, 0x51, 0xec, 0x79, 0x30, 0x44, 0xbd, 0xe5, 0xdf, 0x94, 0xed, 0xad, 0x18, 0xd7, 0x24, 0x89,  // |.Q.y0D........$.|
/*000005a0*/ 0x36, 0x65, 0xc5, 0x88, 0xc0, 0x9a, 0xb7, 0xaa, 0x58, 0x60, 0xfe, 0x6c, 0xe8, 0xf3, 0x39, 0x6b,  // |6e......X`.l..9k|
/*000005b0*/ 0x45, 0xe6, 0x34, 0xbc, 0x61, 0x68, 0xa2, 0x70, 0x16, 0x49, 0x8b, 0x7d, 0x78, 0x09, 0x99, 0x21,  // |E.4.ah.p.I.}x..!|
/*000005c0*/ 0x5a, 0xea, 0xfd, 0xbc, 0x69, 0x23, 0xd5, 0x15, 0xd1, 0x5c, 0x32, 0x8b, 0xc0, 0x7b, 0xb2, 0x1e,  // |Z...i#...\2..{..|
/*000005d0*/ 0x56, 0xf1, 0x6b, 0xd0,                                                                          // |V.k.|
};

T_DECL(in_cksum_49479689a, "tests os_cpu_in_cksum with known problem packet in various random segmentation and memory alignment", T_META_TAG_VM_NOT_PREFERRED)
{
	uint16_t dsum = dumb_in_cksum(pkt49479689, sizeof(pkt49479689));
	T_ASSERT_EQ(ntohs(dsum), (uint16_t)0xa32b, "verifying dumb chksum");
	test_checksum(pkt49479689, sizeof(pkt49479689));
}

T_DECL(in_cksum_49479689b, "tests os_cpu_in_cksum with many random packets in various random segmentation and memory alignment", T_META_TAG_VM_NOT_PREFERRED)
{
	for (int i = 0; i < 100; i++) {
		test_one_random_packet(4096);
	}
}
