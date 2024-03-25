/*
 * Copyright (c) 2008-2021, 2023 Apple Inc. All rights reserved.
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

/*	$FreeBSD: src/sys/netinet6/ah_core.c,v 1.2.2.4 2001/07/03 11:01:49 ume Exp $	*/
/*	$KAME: ah_core.c,v 1.44 2001/03/12 11:24:39 itojun Exp $	*/

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * RFC1826/2402 authentication header.
 */

/* TODO: have shared routines  for hmac-* algorithms */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/syslog.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/in_var.h>

#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet/icmp6.h>

#include <netinet6/ipsec.h>
#include <netinet6/ipsec6.h>
#include <netinet6/ah.h>
#include <netinet6/ah6.h>
#if IPSEC_ESP
#include <netinet6/esp.h>
#include <netinet6/esp6.h>
#endif
#include <net/pfkeyv2.h>
#include <netkey/key.h>
#include <netkey/keydb.h>
#include <libkern/crypto/crypto_internal.h>
#include <libkern/crypto/md5.h>
#include <libkern/crypto/sha1.h>
#include <libkern/crypto/sha2.h>

#include <net/net_osdep.h>

static int ah_keyed_md5_mature(struct secasvar *);
static int ah_keyed_md5_init(struct ah_algorithm_state *, struct secasvar *);
static void ah_keyed_md5_loop(struct ah_algorithm_state *, caddr_t, size_t);
static void ah_keyed_md5_result(struct ah_algorithm_state *, caddr_t, size_t);

static int ah_keyed_sha1_mature(struct secasvar *);
static int ah_keyed_sha1_init(struct ah_algorithm_state *, struct secasvar *);
static void ah_keyed_sha1_loop(struct ah_algorithm_state *, caddr_t, size_t);
static void ah_keyed_sha1_result(struct ah_algorithm_state *, caddr_t, size_t);

static int ah_hmac_mature(struct secasvar *);
static int ah_hmac_state_init(struct ah_algorithm_state *, struct secasvar *);
static size_t ah_hmac_schedlen(const struct ah_algorithm *);
static int ah_hmac_schedule(const struct ah_algorithm *, struct secasvar *);
static void ah_hmac_loop(struct ah_algorithm_state *, caddr_t, size_t);
static void ah_hmac_result(struct ah_algorithm_state *, caddr_t, size_t);

static int ah_sumsiz_1216(struct secasvar *);
static const struct ccdigest_info *ah_digest_md5(void);
static const struct ccdigest_info *ah_digest_sha1(void);
#if AH_ALL_CRYPTO
static int ah_sumsiz_sha2_256(struct secasvar *);
static const struct ccdigest_info *ah_digest_sha2_256(void);
static int ah_sumsiz_sha2_384(struct secasvar *);
static const struct ccdigest_info *ah_digest_sha2_384(void);
static int ah_sumsiz_sha2_512(struct secasvar *);
static const struct ccdigest_info *ah_digest_sha2_512(void);
#endif /* AH_ALL_CRYPTO */

static int ah_sumsiz_zero(struct secasvar *);
static int ah_none_mature(struct secasvar *);
static int ah_none_init(struct ah_algorithm_state *, struct secasvar *);
static void ah_none_loop(struct ah_algorithm_state *, caddr_t, size_t);
static void ah_none_result(struct ah_algorithm_state *, caddr_t, size_t);

static void ah_update_mbuf(struct mbuf *, int, int,
    const struct ah_algorithm *, struct ah_algorithm_state *);

/*
 * If any algorithm requires more than 2048 bits (256 bytes) of key material,
 * update IPSEC_KEY_AUTH_MAX_BYTES in ipsec.h
 */
const struct ah_algorithm *
ah_algorithm_lookup(int idx)
{
	/* checksum algorithms */
	static const struct ah_algorithm hmac_md5 =
	{ ah_sumsiz_1216, ah_hmac_mature,
	  128, 128, "hmac-md5", ah_hmac_state_init,
	  ah_hmac_loop, ah_hmac_result, ah_digest_md5,
	  ah_hmac_schedlen, ah_hmac_schedule, };
	static const struct ah_algorithm keyed_md5 =
	{ ah_sumsiz_1216, ah_keyed_md5_mature,
	  128, 128, "keyed-md5", ah_keyed_md5_init,
	  ah_keyed_md5_loop, ah_keyed_md5_result,
	  NULL, NULL, NULL, };
	static const struct ah_algorithm hmac_sha1 =
	{ ah_sumsiz_1216, ah_hmac_mature,
	  160, 160, "hmac-sha1", ah_hmac_state_init,
	  ah_hmac_loop, ah_hmac_result, ah_digest_sha1,
	  ah_hmac_schedlen, ah_hmac_schedule, };
	static const struct ah_algorithm keyed_sha1 =
	{ ah_sumsiz_1216, ah_keyed_sha1_mature,
	  160, 160, "keyed-sha1", ah_keyed_sha1_init,
	  ah_keyed_sha1_loop, ah_keyed_sha1_result,
	  NULL, NULL, NULL, };
	static const struct ah_algorithm ah_none =
	{ ah_sumsiz_zero, ah_none_mature,
	  0, 2048, "none", ah_none_init,
	  ah_none_loop, ah_none_result,
	  NULL, NULL, NULL, };
#if AH_ALL_CRYPTO
	static const struct ah_algorithm hmac_sha2_256 =
	{ ah_sumsiz_sha2_256, ah_hmac_mature,
	  256, 256, "hmac-sha2-256", ah_hmac_state_init,
	  ah_hmac_loop, ah_hmac_result, ah_digest_sha2_256,
	  ah_hmac_schedlen, ah_hmac_schedule, };
	static const struct ah_algorithm hmac_sha2_384 =
	{ ah_sumsiz_sha2_384, ah_hmac_mature,
	  384, 384, "hmac-sha2-384", ah_hmac_state_init,
	  ah_hmac_loop, ah_hmac_result, ah_digest_sha2_384,
	  ah_hmac_schedlen, ah_hmac_schedule, };
	static const struct ah_algorithm hmac_sha2_512 =
	{ ah_sumsiz_sha2_512, ah_hmac_mature,
	  512, 512, "hmac-sha2-512", ah_hmac_state_init,
	  ah_hmac_loop, ah_hmac_result, ah_digest_sha2_512,
	  ah_hmac_schedlen, ah_hmac_schedule, };
#endif /* AH_ALL_CRYPTO */

	switch (idx) {
	case SADB_AALG_MD5HMAC:
		return &hmac_md5;
	case SADB_AALG_SHA1HMAC:
		return &hmac_sha1;
	case SADB_X_AALG_MD5:
		return &keyed_md5;
	case SADB_X_AALG_SHA:
		return &keyed_sha1;
	case SADB_X_AALG_NULL:
		return &ah_none;
#if AH_ALL_CRYPTO
	case SADB_X_AALG_SHA2_256:
		return &hmac_sha2_256;
	case SADB_X_AALG_SHA2_384:
		return &hmac_sha2_384;
	case SADB_X_AALG_SHA2_512:
		return &hmac_sha2_512;
#endif /* AH_ALL_CRYPTO */
	default:
		return NULL;
	}
}


int
ah_schedule(
	const struct ah_algorithm *algo,
	struct secasvar *sav)
{
	void *sched = NULL;
	size_t schedlen = 0;
	int error;

	lck_mtx_lock(sadb_mutex);
	/* already allocated */
	if (sav->sched_auth != NULL && sav->schedlen_auth != 0) {
		lck_mtx_unlock(sadb_mutex);
		return 0;
	}

	/* no schedule necessary */
	if (algo->schedule == NULL || algo->schedlen == NULL) {
		lck_mtx_unlock(sadb_mutex);
		return 0;
	}

	schedlen = (*algo->schedlen)(algo);
	if (__improbable((signed)schedlen < 0)) {
		lck_mtx_unlock(sadb_mutex);
		return EINVAL;
	}

	sched = kalloc_data(schedlen, Z_NOWAIT);
	if (__improbable(sched == NULL)) {
		lck_mtx_unlock(sadb_mutex);
		return ENOBUFS;
	}

	sav->sched_auth = sched;
	sav->schedlen_auth = schedlen;

	error = (*algo->schedule)(algo, sav);
	if (__improbable(error != 0)) {
		ipseclog((LOG_ERR, "ah_schedule %s: error %d\n",
		    algo->name, error));
		memset(sav->sched_auth, 0, sav->schedlen_auth);
		kfree_data(sav->sched_auth, sav->schedlen_auth);
		sav->sched_auth = NULL;
		sav->schedlen_auth = 0;
	}
	lck_mtx_unlock(sadb_mutex);
	return error;
}

static int
ah_keyed_md5_mature(
	__unused struct secasvar *sav)
{
	/* anything is okay */
	return 0;
}

static int
ah_keyed_md5_init(struct ah_algorithm_state *state, struct secasvar *sav)
{
	MD5_CTX *ctxt;
	size_t keybitlen;
	u_int8_t buf[32] __attribute__((aligned(4)));
	unsigned int padlen;

	if (!state) {
		panic("ah_keyed_md5_init: what?");
	}

	state->sav = sav;
	ctxt = &state->md5_ctx;
	MD5Init(ctxt);

	if (state->sav) {
		MD5Update(ctxt,
		    (u_int8_t *)_KEYBUF(state->sav->key_auth),
		    (u_int)_KEYLEN(state->sav->key_auth));

		/*
		 * Pad after the key.
		 * We cannot simply use md5_pad() since the function
		 * won't update the total length.
		 */
		if (_KEYLEN(state->sav->key_auth) < 56) {
			padlen = 64 - 8 - _KEYLEN(state->sav->key_auth);
		} else {
			padlen = 64 + 64 - 8 - _KEYLEN(state->sav->key_auth);
		}
		keybitlen = _KEYLEN(state->sav->key_auth);
		keybitlen *= 8;

		buf[0] = 0x80;
		MD5Update(ctxt, &buf[0], 1);
		padlen--;

		bzero(buf, sizeof(buf));
		while (sizeof(buf) < padlen) {
			MD5Update(ctxt, &buf[0], sizeof(buf));
			padlen -= sizeof(buf);
		}
		if (padlen) {
			MD5Update(ctxt, &buf[0], padlen);
		}

		buf[0] = (keybitlen >> 0) & 0xff;
		buf[1] = (keybitlen >> 8) & 0xff;
		buf[2] = (keybitlen >> 16) & 0xff;
		buf[3] = (keybitlen >> 24) & 0xff;
		MD5Update(ctxt, buf, 8);
	}

	return 0;
}

static void
ah_keyed_md5_loop(struct ah_algorithm_state *state, caddr_t addr, size_t len)
{
	MD5_CTX *ctxt;

	if (!state) {
		panic("ah_keyed_md5_loop: what?");
	}
	ctxt = &state->md5_ctx;

	VERIFY(len <= UINT_MAX);
	MD5Update(ctxt, addr, (uint)len);
}

static void
ah_keyed_md5_result(struct ah_algorithm_state *state, caddr_t addr, size_t len)
{
	u_char digest[16] __attribute__((aligned(4)));
	MD5_CTX *ctxt;

	if (!state) {
		panic("ah_keyed_md5_result: what?");
	}
	ctxt = &state->md5_ctx;

	if (state->sav) {
		MD5Update(ctxt,
		    (u_int8_t *)_KEYBUF(state->sav->key_auth),
		    (u_int)_KEYLEN(state->sav->key_auth));
	}
	MD5Final(&digest[0], ctxt);
	bcopy(&digest[0], (void *)addr, sizeof(digest) > len ? len : sizeof(digest));
}

static int
ah_keyed_sha1_mature(struct secasvar *sav)
{
	const struct ah_algorithm *algo;

	if (!sav->key_auth) {
		ipseclog((LOG_ERR, "ah_keyed_sha1_mature: no key is given.\n"));
		return 1;
	}

	algo = ah_algorithm_lookup(sav->alg_auth);
	if (!algo) {
		ipseclog((LOG_ERR, "ah_keyed_sha1_mature: unsupported algorithm.\n"));
		return 1;
	}

	if (sav->key_auth->sadb_key_bits < algo->keymin
	    || algo->keymax < sav->key_auth->sadb_key_bits) {
		ipseclog((LOG_ERR,
		    "ah_keyed_sha1_mature: invalid key length %d.\n",
		    sav->key_auth->sadb_key_bits));
		return 1;
	}

	return 0;
}

static int
ah_keyed_sha1_init(struct ah_algorithm_state *state, struct secasvar *sav)
{
	SHA1_CTX *ctxt;
	size_t padlen;
	size_t keybitlen;
	u_int8_t buf[32] __attribute__((aligned(4)));

	if (!state) {
		panic("ah_keyed_sha1_init: what?");
	}

	state->sav = sav;
	ctxt = &state->sha1_ctx;
	SHA1Init(ctxt);

	if (state->sav) {
		SHA1Update(ctxt, (u_int8_t *)_KEYBUF(state->sav->key_auth),
		    (u_int)_KEYLEN(state->sav->key_auth));

		/*
		 * Pad after the key.
		 */
		if (_KEYLEN(state->sav->key_auth) < 56) {
			padlen = 64 - 8 - _KEYLEN(state->sav->key_auth);
		} else {
			padlen = 64 + 64 - 8 - _KEYLEN(state->sav->key_auth);
		}
		keybitlen = _KEYLEN(state->sav->key_auth);
		keybitlen *= 8;

		buf[0] = 0x80;
		SHA1Update(ctxt, &buf[0], 1);
		padlen--;

		bzero(buf, sizeof(buf));
		while (sizeof(buf) < padlen) {
			SHA1Update(ctxt, &buf[0], sizeof(buf));
			padlen -= sizeof(buf);
		}
		if (padlen) {
			SHA1Update(ctxt, &buf[0], padlen);
		}

		buf[0] = (keybitlen >> 0) & 0xff;
		buf[1] = (keybitlen >> 8) & 0xff;
		buf[2] = (keybitlen >> 16) & 0xff;
		buf[3] = (keybitlen >> 24) & 0xff;
		SHA1Update(ctxt, buf, 8);
	}

	return 0;
}

static void
ah_keyed_sha1_loop(struct ah_algorithm_state *state, caddr_t addr, size_t len)
{
	SHA1_CTX *ctxt;

	if (!state) {
		panic("ah_keyed_sha1_loop: what?");
	}
	ctxt = &state->sha1_ctx;

	SHA1Update(ctxt, (caddr_t)addr, (size_t)len);
}

static void
ah_keyed_sha1_result(struct ah_algorithm_state *state, caddr_t addr, size_t len)
{
	u_char digest[SHA1_RESULTLEN] __attribute__((aligned(4)));      /* SHA-1 generates 160 bits */
	SHA1_CTX *ctxt;

	if (!state) {
		panic("ah_keyed_sha1_result: what?");
	}
	ctxt = &state->sha1_ctx;

	if (state->sav) {
		SHA1Update(ctxt, (u_int8_t *)_KEYBUF(state->sav->key_auth),
		    (u_int)_KEYLEN(state->sav->key_auth));
	}
	SHA1Final((caddr_t)&digest[0], ctxt);
	bcopy(&digest[0], (void *)addr, sizeof(digest) > len ? len : sizeof(digest));
}

static int
ah_hmac_mature(struct secasvar *sav)
{
	const struct ah_algorithm *algo;

	if (__improbable(sav->key_auth == NULL)) {
		ipseclog((LOG_ERR, "ah_hmac_mature: no key is given.\n"));
		return 1;
	}

	algo = ah_algorithm_lookup(sav->alg_auth);
	if (__improbable(algo == NULL)) {
		ipseclog((LOG_ERR, "ah_hmac_mature: unsupported algorithm.\n"));
		return 1;
	}

	if (sav->key_auth->sadb_key_bits < algo->keymin
	    || algo->keymax < sav->key_auth->sadb_key_bits) {
		ipseclog((LOG_ERR,
		    "ah_hmac_mature: invalid key length %d.\n",
		    sav->key_auth->sadb_key_bits));
		return 1;
	}

	return 0;
}

static int
ah_hmac_state_init(struct ah_algorithm_state *state, struct secasvar *sav)
{
	if (__improbable(state == NULL || sav == NULL)) {
		panic("ah_hmac_state_init: what?");
	}

	const struct ah_algorithm *algo = ah_algorithm_lookup(sav->alg_auth);
	if (__improbable(algo == NULL)) {
		ipseclog((LOG_ERR, "ah_hmac_state_init: unsupported algorithm.\n"));
		return EINVAL;
	}

	const size_t schedlen = sav->schedlen_auth;
	memcpy(state->hmac_ctx, sav->sched_auth, schedlen);
	state->digest = algo->digest();

	return 0;
}

static size_t
ah_hmac_schedlen(const struct ah_algorithm *algo)
{
	return cchmac_di_size(algo->digest());
}

static int
ah_hmac_schedule(
	const struct ah_algorithm *algo,
	struct secasvar *sav)
{
	const struct ccdigest_info *di = algo->digest();
	cchmac_ctx_t ctx = (cchmac_ctx_t)sav->sched_auth;

	g_crypto_funcs->cchmac_init_fn(di, ctx,
	    _KEYLEN(sav->key_auth), _KEYBUF(sav->key_auth));

	return 0;
}

static void
ah_hmac_loop(
	struct ah_algorithm_state *state, caddr_t addr, size_t len)
{
	if (__improbable(state == NULL || state->digest == NULL)) {
		panic("ah_hmac_loop: what?");
	}

	VERIFY(len <= UINT_MAX);

	g_crypto_funcs->cchmac_update_fn(state->digest, state->hmac_ctx, (uint)len, addr);
}

static void
ah_hmac_result(
	struct ah_algorithm_state *state, caddr_t addr, size_t len)
{
	if (__improbable(state == NULL || state->digest == NULL)) {
		panic("ah_hmac_result: what?");
	}

	const size_t output_size = state->digest->output_size;
	u_char digest[output_size] __attribute__((aligned(4)));

	g_crypto_funcs->cchmac_final_fn(state->digest, state->hmac_ctx, &digest[0]);
	cchmac_di_clear(state->digest, state->hmac_ctx);
	memcpy((void *)addr, &digest[0], sizeof(digest) > len ? len : sizeof(digest));
}

static int
ah_sumsiz_1216(struct secasvar *sav)
{
	if (!sav) {
		return -1;
	}
	if (sav->flags & SADB_X_EXT_OLD) {
		return 16;
	} else {
		return 12;
	}
}

static const struct ccdigest_info *
ah_digest_md5(void)
{
	return g_crypto_funcs->ccmd5_di;
}

static const struct ccdigest_info *
ah_digest_sha1(void)
{
	return g_crypto_funcs->ccsha1_di;
}

#if AH_ALL_CRYPTO
static int
ah_sumsiz_sha2_256(struct secasvar *sav)
{
	if (!sav) {
		return -1;
	}
	// return half the output size (in bytes), as per rfc 4868
	return SHA256_DIGEST_LENGTH / 2;
}

static const struct ccdigest_info *
ah_digest_sha2_256(void)
{
	return g_crypto_funcs->ccsha256_di;
}

static int
ah_sumsiz_sha2_384(struct secasvar *sav)
{
	if (!sav) {
		return -1;
	}
	// return half the output size (in bytes), as per rfc 4868
	return SHA384_DIGEST_LENGTH / 2;
}

static const struct ccdigest_info *
ah_digest_sha2_384(void)
{
	return g_crypto_funcs->ccsha384_di;
}

static int
ah_sumsiz_sha2_512(struct secasvar *sav)
{
	if (!sav) {
		return -1;
	}
	// return half the output size (in bytes), as per rfc 4868
	return SHA512_DIGEST_LENGTH / 2;
}

static const struct ccdigest_info *
ah_digest_sha2_512(void)
{
	return g_crypto_funcs->ccsha512_di;
}
#endif /* AH_ALL_CRYPTO */

static int
ah_sumsiz_zero(struct secasvar *sav)
{
	if (!sav) {
		return -1;
	}
	return 0;
}

static int
ah_none_mature(struct secasvar *sav)
{
	if (sav->sah->saidx.proto == IPPROTO_AH) {
		ipseclog((LOG_ERR,
		    "ah_none_mature: protocol and algorithm mismatch.\n"));
		return 1;
	}
	return 0;
}

static int
ah_none_init(
	struct ah_algorithm_state *state,
	struct secasvar *sav)
{
	state->sav = sav;
	return 0;
}

static void
ah_none_loop(
	__unused struct ah_algorithm_state *state,
	__unused caddr_t addr,
	__unused size_t len)
{
}

static void
ah_none_result(
	__unused struct ah_algorithm_state *state,
	__unused caddr_t addr,
	__unused size_t len)
{
}

/*------------------------------------------------------------*/

/*
 * go generate the checksum.
 */
static void
ah_update_mbuf(struct mbuf *m, int off, int len,
    const struct ah_algorithm *algo,
    struct ah_algorithm_state *algos)
{
	struct mbuf *n;
	int tlen;

	/* easy case first */
	if (off + len <= m->m_len) {
		(algo->update)(algos, mtod(m, caddr_t) + off, len);
		return;
	}

	for (n = m; n; n = n->m_next) {
		if (off < n->m_len) {
			break;
		}

		off -= n->m_len;
	}

	if (!n) {
		panic("ah_update_mbuf: wrong offset specified");
	}

	for (/*nothing*/; n && len > 0; n = n->m_next) {
		if (n->m_len == 0) {
			continue;
		}
		if (n->m_len - off < len) {
			tlen = n->m_len - off;
		} else {
			tlen = len;
		}

		(algo->update)(algos, mtod(n, caddr_t) + off, tlen);

		len -= tlen;
		off = 0;
	}
}

#if INET
/*
 * Go generate the checksum. This function won't modify the mbuf chain
 * except AH itself.
 *
 * NOTE: the function does not free mbuf on failure.
 * Don't use m_copy(), it will try to share cluster mbuf by using refcnt.
 */
int
ah4_calccksum(struct mbuf *m, caddr_t ahdat, size_t len,
    const struct ah_algorithm *algo, struct secasvar *sav)
{
	int off;
	int hdrtype;
	size_t advancewidth;
	struct ah_algorithm_state algos;
	u_char sumbuf[AH_MAXSUMSIZE] __attribute__((aligned(4)));
	int error = 0;
	int ahseen;
	struct mbuf *n = NULL;

	if ((m->m_flags & M_PKTHDR) == 0) {
		return EINVAL;
	}

	ahseen = 0;
	hdrtype = -1;   /*dummy, it is called IPPROTO_IP*/

	off = 0;

	/*
	 * pre-compute and cache intermediate key
	 */
	if (__improbable((error = ah_schedule(algo, sav)) != 0)) {
		return error;
	}

	error = (algo->init)(&algos, sav);
	if (error) {
		return error;
	}

	advancewidth = 0;       /*safety*/

again:
	/* gory. */
	switch (hdrtype) {
	case -1:        /*first one only*/
	{
		/*
		 * copy ip hdr, modify to fit the AH checksum rule,
		 * then take a checksum.
		 */
		struct ip iphdr;
		size_t hlen;

		m_copydata(m, off, sizeof(iphdr), (caddr_t)&iphdr);
#if _IP_VHL
		hlen = IP_VHL_HL(iphdr.ip_vhl) << 2;
#else
		hlen = iphdr.ip_hl << 2;
#endif
		iphdr.ip_ttl = 0;
		iphdr.ip_sum = htons(0);
		if (ip4_ah_cleartos) {
			iphdr.ip_tos = 0;
		}
		iphdr.ip_off = htons(ntohs(iphdr.ip_off) & ip4_ah_offsetmask);
		(algo->update)(&algos, (caddr_t)&iphdr, sizeof(struct ip));

		if (hlen != sizeof(struct ip)) {
			u_char *p;
			int i, l, skip;

			if (hlen > MCLBYTES) {
				error = EMSGSIZE;
				goto fail;
			}
			MGET(n, M_DONTWAIT, MT_DATA);
			if (n && hlen > MLEN) {
				MCLGET(n, M_DONTWAIT);
				if ((n->m_flags & M_EXT) == 0) {
					m_free(n);
					n = NULL;
				}
			}
			if (n == NULL) {
				error = ENOBUFS;
				goto fail;
			}
			VERIFY(hlen <= INT_MAX);
			m_copydata(m, off, (int)hlen, mtod(n, caddr_t));

			/*
			 * IP options processing.
			 * See RFC2402 appendix A.
			 */
			p = mtod(n, u_char *);
			i = sizeof(struct ip);
			while (i < hlen) {
				if (i + IPOPT_OPTVAL >= hlen) {
					ipseclog((LOG_ERR, "ah4_calccksum: "
					    "invalid IP option\n"));
					error = EINVAL;
					goto fail;
				}
				if (p[i + IPOPT_OPTVAL] == IPOPT_EOL ||
				    p[i + IPOPT_OPTVAL] == IPOPT_NOP ||
				    i + IPOPT_OLEN < hlen) {
					;
				} else {
					ipseclog((LOG_ERR,
					    "ah4_calccksum: invalid IP option "
					    "(type=%02x)\n",
					    p[i + IPOPT_OPTVAL]));
					error = EINVAL;
					goto fail;
				}

				skip = 1;
				switch (p[i + IPOPT_OPTVAL]) {
				case IPOPT_EOL:
				case IPOPT_NOP:
					l = 1;
					skip = 0;
					break;
				case IPOPT_SECURITY:    /* 0x82 */
				case 0x85:      /* Extended security */
				case 0x86:      /* Commercial security */
				case 0x94:      /* Router alert */
				case 0x95:      /* RFC1770 */
					l = p[i + IPOPT_OLEN];
					if (l < 2) {
						goto invalopt;
					}
					skip = 0;
					break;
				default:
					l = p[i + IPOPT_OLEN];
					if (l < 2) {
						goto invalopt;
					}
					skip = 1;
					break;
				}
				if (l < 1 || hlen - i < l) {
invalopt:
					ipseclog((LOG_ERR,
					    "ah4_calccksum: invalid IP option "
					    "(type=%02x len=%02x)\n",
					    p[i + IPOPT_OPTVAL],
					    p[i + IPOPT_OLEN]));
					error = EINVAL;
					goto fail;
				}
				if (skip) {
					bzero(p + i, l);
				}
				if (p[i + IPOPT_OPTVAL] == IPOPT_EOL) {
					break;
				}
				i += l;
			}

			p = mtod(n, u_char *) + sizeof(struct ip);
			(algo->update)(&algos, (caddr_t)p, hlen - sizeof(struct ip));

			m_free(n);
			n = NULL;
		}

		hdrtype = (iphdr.ip_p) & 0xff;
		advancewidth = hlen;
		break;
	}

	case IPPROTO_AH:
	{
		struct ah ah;
		int siz;
		int hdrsiz;
		int totlen;

		if (m->m_pkthdr.len - off < sizeof(ah)) {
			error = EMSGSIZE;
			goto fail;
		}

		m_copydata(m, off, sizeof(ah), (caddr_t)&ah);
		hdrsiz = (sav->flags & SADB_X_EXT_OLD)
		    ? sizeof(struct ah)
		    : sizeof(struct newah);
		siz = (*algo->sumsiz)(sav);
		totlen = (ah.ah_len + 2) << 2;

		if (totlen > m->m_pkthdr.len - off) {
			error = EMSGSIZE;
			goto fail;
		}

		/*
		 * special treatment is necessary for the first one, not others
		 */
		if (!ahseen) {
			if (totlen > MCLBYTES) {
				error = EMSGSIZE;
				goto fail;
			}
			MGET(n, M_DONTWAIT, MT_DATA);
			if (n && totlen > MLEN) {
				MCLGET(n, M_DONTWAIT);
				if ((n->m_flags & M_EXT) == 0) {
					m_free(n);
					n = NULL;
				}
			}
			if (n == NULL) {
				error = ENOBUFS;
				goto fail;
			}
			m_copydata(m, off, totlen, mtod(n, caddr_t));
			n->m_len = totlen;
			bzero(mtod(n, caddr_t) + hdrsiz, siz);
			(algo->update)(&algos, mtod(n, caddr_t), n->m_len);
			m_free(n);
			n = NULL;
		} else {
			ah_update_mbuf(m, off, totlen, algo, &algos);
		}
		ahseen++;

		hdrtype = ah.ah_nxt;
		advancewidth = totlen;
		break;
	}

	default:
		ah_update_mbuf(m, off, m->m_pkthdr.len - off, algo, &algos);
		advancewidth = m->m_pkthdr.len - off;
		break;
	}

	off += advancewidth;
	if (off < m->m_pkthdr.len) {
		goto again;
	}

	if (len < (*algo->sumsiz)(sav)) {
		error = EINVAL;
		goto fail;
	}

	(algo->result)(&algos, (caddr_t) &sumbuf[0], sizeof(sumbuf));
	bcopy(&sumbuf[0], ahdat, (*algo->sumsiz)(sav));

	if (n) {
		m_free(n);
	}
	return error;

fail:
	if (n) {
		m_free(n);
	}
	return error;
}
#endif

/*
 * Go generate the checksum. This function won't modify the mbuf chain
 * except AH itself.
 *
 * NOTE: the function does not free mbuf on failure.
 * Don't use m_copy(), it will try to share cluster mbuf by using refcnt.
 */
int
ah6_calccksum(struct mbuf *m, caddr_t ahdat, size_t len,
    const struct ah_algorithm *algo, struct secasvar *sav)
{
	int newoff, off;
	int proto, nxt;
	struct mbuf *n = NULL;
	int error;
	int ahseen;
	struct ah_algorithm_state algos;
	u_char sumbuf[AH_MAXSUMSIZE] __attribute__((aligned(4)));

	if ((m->m_flags & M_PKTHDR) == 0) {
		return EINVAL;
	}

	/*
	 * pre-compute and cache intermediate key
	 */
	if (__improbable((error = ah_schedule(algo, sav)) != 0)) {
		return error;
	}

	error = (algo->init)(&algos, sav);
	if (error) {
		return error;
	}

	off = 0;
	proto = IPPROTO_IPV6;
	nxt = -1;
	ahseen = 0;

again:
	newoff = ip6_nexthdr(m, off, proto, &nxt);
	if (newoff < 0) {
		newoff = m->m_pkthdr.len;
	} else if (newoff <= off) {
		error = EINVAL;
		goto fail;
	} else if (m->m_pkthdr.len < newoff) {
		error = EINVAL;
		goto fail;
	}

	switch (proto) {
	case IPPROTO_IPV6:
		/*
		 * special treatment is necessary for the first one, not others
		 */
		if (off == 0) {
			struct ip6_hdr ip6copy;

			if (newoff - off != sizeof(struct ip6_hdr)) {
				error = EINVAL;
				goto fail;
			}

			m_copydata(m, off, newoff - off, (caddr_t)&ip6copy);
			/* RFC2402 */
			ip6copy.ip6_flow = 0;
			ip6copy.ip6_vfc &= ~IPV6_VERSION_MASK;
			ip6copy.ip6_vfc |= IPV6_VERSION;
			ip6copy.ip6_hlim = 0;
			if (IN6_IS_ADDR_LINKLOCAL(&ip6copy.ip6_src)) {
				ip6copy.ip6_src.s6_addr16[1] = 0x0000;
			}
			if (IN6_IS_ADDR_LINKLOCAL(&ip6copy.ip6_dst)) {
				ip6copy.ip6_dst.s6_addr16[1] = 0x0000;
			}
			(algo->update)(&algos, (caddr_t)&ip6copy,
			    sizeof(struct ip6_hdr));
		} else {
			newoff = m->m_pkthdr.len;
			ah_update_mbuf(m, off, m->m_pkthdr.len - off, algo,
			    &algos);
		}
		break;

	case IPPROTO_AH:
	{
		int siz;
		int hdrsiz;

		hdrsiz = (sav->flags & SADB_X_EXT_OLD)
		    ? sizeof(struct ah)
		    : sizeof(struct newah);
		siz = (*algo->sumsiz)(sav);

		/*
		 * special treatment is necessary for the first one, not others
		 */
		if (!ahseen) {
			if (newoff - off > MCLBYTES) {
				error = EMSGSIZE;
				goto fail;
			}
			MGET(n, M_DONTWAIT, MT_DATA);
			if (n && newoff - off > MLEN) {
				MCLGET(n, M_DONTWAIT);
				if ((n->m_flags & M_EXT) == 0) {
					m_free(n);
					n = NULL;
				}
			}
			if (n == NULL) {
				error = ENOBUFS;
				goto fail;
			}
			m_copydata(m, off, newoff - off, mtod(n, caddr_t));
			n->m_len = newoff - off;
			bzero(mtod(n, caddr_t) + hdrsiz, siz);
			(algo->update)(&algos, mtod(n, caddr_t), n->m_len);
			m_free(n);
			n = NULL;
		} else {
			ah_update_mbuf(m, off, newoff - off, algo, &algos);
		}
		ahseen++;
		break;
	}

	case IPPROTO_HOPOPTS:
	case IPPROTO_DSTOPTS:
	{
		struct ip6_ext *ip6e;
		int hdrlen, optlen;
		u_int8_t *p, *optend, *optp;

		if (newoff - off > MCLBYTES) {
			error = EMSGSIZE;
			goto fail;
		}
		MGET(n, M_DONTWAIT, MT_DATA);
		if (n && newoff - off > MLEN) {
			MCLGET(n, M_DONTWAIT);
			if ((n->m_flags & M_EXT) == 0) {
				m_free(n);
				n = NULL;
			}
		}
		if (n == NULL) {
			error = ENOBUFS;
			goto fail;
		}
		m_copydata(m, off, newoff - off, mtod(n, caddr_t));
		n->m_len = newoff - off;

		ip6e = mtod(n, struct ip6_ext *);
		hdrlen = (ip6e->ip6e_len + 1) << 3;
		if (newoff - off < hdrlen) {
			error = EINVAL;
			m_free(n);
			n = NULL;
			goto fail;
		}
		p = mtod(n, u_int8_t *);
		optend = p + hdrlen;

		/*
		 * ICV calculation for the options header including all
		 * options.  This part is a little tricky since there are
		 * two type of options; mutable and immutable.  We try to
		 * null-out mutable ones here.
		 */
		optp = p + 2;
		while (optp < optend) {
			if (optp[0] == IP6OPT_PAD1) {
				optlen = 1;
			} else {
				if (optp + 2 > optend) {
					error = EINVAL;
					m_free(n);
					n = NULL;
					goto fail;
				}
				optlen = optp[1] + 2;
				if (optp + optlen > optend) {
					error = EINVAL;
					m_free(n);
					n = NULL;
					goto fail;
				}

				if (optp[0] & IP6OPT_MUTABLE) {
					bzero(optp + 2, optlen - 2);
				}
			}

			optp += optlen;
		}

		(algo->update)(&algos, mtod(n, caddr_t), n->m_len);
		m_free(n);
		n = NULL;
		break;
	}

	case IPPROTO_ROUTING:
	/*
	 * For an input packet, we can just calculate `as is'.
	 * For an output packet, we assume ip6_output have already
	 * made packet how it will be received at the final
	 * destination.
	 */
	/* FALLTHROUGH */

	default:
		ah_update_mbuf(m, off, newoff - off, algo, &algos);
		break;
	}

	if (newoff < m->m_pkthdr.len) {
		proto = nxt;
		off = newoff;
		goto again;
	}

	if (len < (*algo->sumsiz)(sav)) {
		error = EINVAL;
		goto fail;
	}

	(algo->result)(&algos, (caddr_t) &sumbuf[0], sizeof(sumbuf));
	bcopy(&sumbuf[0], ahdat, (*algo->sumsiz)(sav));

	/* just in case */
	if (n) {
		m_free(n);
	}
	return 0;
fail:
	/* just in case */
	if (n) {
		m_free(n);
	}
	return error;
}
