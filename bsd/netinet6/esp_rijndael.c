/*
 * Copyright (c) 2008-2023 Apple Inc. All rights reserved.
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

/*	$FreeBSD: src/sys/netinet6/esp_rijndael.c,v 1.1.2.1 2001/07/03 11:01:50 ume Exp $	*/
/*	$KAME: esp_rijndael.c,v 1.4 2001/03/02 05:53:05 itojun Exp $	*/

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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/syslog.h>
#include <sys/mbuf.h>
#include <sys/mcache.h>

#include <kern/locks.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet6/ipsec.h>
#include <netinet6/esp.h>
#include <netinet6/esp_rijndael.h>

#include <libkern/crypto/aes.h>

#include <netkey/key.h>

#include <net/net_osdep.h>

#define MAX_REALIGN_LEN 2000
#define AES_BLOCKLEN 16
#define ESP_GCM_SALT_LEN 4   // RFC 4106 Section 4
#define ESP_GCM_IVLEN 8
#define ESP_GCM_ALIGN 16

typedef struct {
	ccgcm_ctx *decrypt;
	ccgcm_ctx *encrypt;
	ccgcm_ctx ctxt[0];
} aes_gcm_ctx;

size_t
esp_aes_schedlen(
	__unused const struct esp_algorithm *algo)
{
	return sizeof(aes_ctx);
}

int
esp_aes_schedule(
	__unused const struct esp_algorithm *algo,
	struct secasvar *sav)
{
	LCK_MTX_ASSERT(sadb_mutex, LCK_MTX_ASSERT_OWNED);
	aes_ctx *ctx = (aes_ctx*)sav->sched;

	aes_decrypt_key((const unsigned char *) _KEYBUF(sav->key_enc), _KEYLEN(sav->key_enc), &ctx->decrypt);
	aes_encrypt_key((const unsigned char *) _KEYBUF(sav->key_enc), _KEYLEN(sav->key_enc), &ctx->encrypt);

	return 0;
}


/* The following 2 functions decrypt or encrypt the contents of
 * the mbuf chain passed in keeping the IP and ESP header's in place,
 * along with the IV.
 * The code attempts to call the crypto code with the largest chunk
 * of data it can based on the amount of source data in
 * the current source mbuf and the space remaining in the current
 * destination mbuf.  The crypto code requires data to be a multiples
 * of 16 bytes.  A separate buffer is used when a 16 byte block spans
 * mbufs.
 *
 * m = mbuf chain
 * off = offset to ESP header
 *
 * local vars for source:
 * soff = offset from beginning of the chain to the head of the
 *			current mbuf.
 * scut = last mbuf that contains headers to be retained
 * scutoff = offset to end of the headers in scut
 * s = the current mbuf
 * sn = current offset to data in s (next source data to process)
 *
 * local vars for dest:
 * d0 = head of chain
 * d = current mbuf
 * dn = current offset in d (next location to store result)
 */


int
esp_cbc_decrypt_aes(
	struct mbuf *m,
	size_t off,
	struct secasvar *sav,
	const struct esp_algorithm *algo,
	int ivlen)
{
	struct mbuf *s;
	struct mbuf *d, *d0, *dp;
	int soff;       /* offset from the head of chain, to head of this mbuf */
	int sn, dn;     /* offset from the head of the mbuf, to meat */
	size_t ivoff, bodyoff;
	u_int8_t iv[AES_BLOCKLEN] __attribute__((aligned(4))), *dptr;
	u_int8_t sbuf[AES_BLOCKLEN] __attribute__((aligned(4))), *sp, *sp_unaligned, *sp_aligned = NULL;
	struct mbuf *scut;
	int scutoff;
	int     i, len;


	if (ivlen != AES_BLOCKLEN) {
		ipseclog((LOG_ERR, "esp_cbc_decrypt %s: "
		    "unsupported ivlen %d\n", algo->name, ivlen));
		m_freem(m);
		return EINVAL;
	}

	if (sav->flags & SADB_X_EXT_OLD) {
		/* RFC 1827 */
		ivoff = off + sizeof(struct esp);
		bodyoff = off + sizeof(struct esp) + ivlen;
	} else {
		ivoff = off + sizeof(struct newesp);
		bodyoff = off + sizeof(struct newesp) + ivlen;
	}

	if (m->m_pkthdr.len < bodyoff) {
		ipseclog((LOG_ERR, "esp_cbc_decrypt %s: bad len %d/%u\n",
		    algo->name, m->m_pkthdr.len, (u_int32_t)bodyoff));
		m_freem(m);
		return EINVAL;
	}
	if ((m->m_pkthdr.len - bodyoff) % AES_BLOCKLEN) {
		ipseclog((LOG_ERR, "esp_cbc_decrypt %s: "
		    "payload length must be multiple of %d\n",
		    algo->name, AES_BLOCKLEN));
		m_freem(m);
		return EINVAL;
	}

	VERIFY(ivoff <= INT_MAX);

	/* grab iv */
	m_copydata(m, (int)ivoff, ivlen, (caddr_t) iv);

	s = m;
	soff = sn = dn = 0;
	d = d0 = dp = NULL;
	sp = dptr = NULL;

	/* skip header/IV offset */
	while (soff < bodyoff) {
		if (soff + s->m_len > bodyoff) {
			sn = (int)(bodyoff - soff);
			break;
		}

		soff += s->m_len;
		s = s->m_next;
	}
	scut = s;
	scutoff = sn;

	/* skip over empty mbuf */
	while (s && s->m_len == 0) {
		s = s->m_next;
	}

	while (soff < m->m_pkthdr.len) {
		/* source */
		if (sn + AES_BLOCKLEN <= s->m_len) {
			/* body is continuous */
			sp = mtod(s, u_int8_t *) + sn;
			len = s->m_len - sn;
			len -= len % AES_BLOCKLEN;      // full blocks only
		} else {
			/* body is non-continuous */
			m_copydata(s, sn, AES_BLOCKLEN, (caddr_t) sbuf);
			sp = sbuf;
			len = AES_BLOCKLEN;                     // 1 block only in sbuf
		}

		/* destination */
		if (!d || dn + AES_BLOCKLEN > d->m_len) {
			if (d) {
				dp = d;
			}
			MGET(d, M_DONTWAIT, MT_DATA);
			i = m->m_pkthdr.len - (soff + sn);
			if (d && i > MLEN) {
				MCLGET(d, M_DONTWAIT);
				if ((d->m_flags & M_EXT) == 0) {
					d = m_mbigget(d, M_DONTWAIT);
					if ((d->m_flags & M_EXT) == 0) {
						m_free(d);
						d = NULL;
					}
				}
			}
			if (!d) {
				m_freem(m);
				if (d0) {
					m_freem(d0);
				}
				return ENOBUFS;
			}
			if (!d0) {
				d0 = d;
			}
			if (dp) {
				dp->m_next = d;
			}

			// try to make mbuf data aligned
			if (!IPSEC_IS_P2ALIGNED(d->m_data)) {
				m_adj(d, IPSEC_GET_P2UNALIGNED_OFS(d->m_data));
			}

			d->m_len = (int)M_TRAILINGSPACE(d);
			d->m_len -= d->m_len % AES_BLOCKLEN;
			if (d->m_len > i) {
				d->m_len = i;
			}
			dptr = mtod(d, u_int8_t *);
			dn = 0;
		}

		/* adjust len if greater than space available in dest */
		if (len > d->m_len - dn) {
			len = d->m_len - dn;
		}

		/* decrypt */
		// check input pointer alignment and use a separate aligned buffer (if sp is unaligned on 4-byte boundary).
		if (IPSEC_IS_P2ALIGNED(sp)) {
			sp_unaligned = NULL;
		} else {
			sp_unaligned = sp;
			if (len > MAX_REALIGN_LEN) {
				m_freem(m);
				if (d0 != NULL) {
					m_freem(d0);
				}
				if (sp_aligned != NULL) {
					kfree_data(sp_aligned, MAX_REALIGN_LEN);
					sp_aligned = NULL;
				}
				return ENOBUFS;
			}
			if (sp_aligned == NULL) {
				sp_aligned = (u_int8_t *)kalloc_data(MAX_REALIGN_LEN, Z_NOWAIT);
				if (sp_aligned == NULL) {
					m_freem(m);
					if (d0 != NULL) {
						m_freem(d0);
					}
					return ENOMEM;
				}
			}
			sp = sp_aligned;
			memcpy(sp, sp_unaligned, len);
		}
		// no need to check output pointer alignment
		aes_decrypt_cbc(sp, iv, len >> 4, dptr + dn,
		    (aes_decrypt_ctx*)(&(((aes_ctx*)sav->sched)->decrypt)));

		// update unaligned pointers
		if (!IPSEC_IS_P2ALIGNED(sp_unaligned)) {
			sp = sp_unaligned;
		}

		/* udpate offsets */
		sn += len;
		dn += len;

		// next iv
		memcpy(iv, sp + len - AES_BLOCKLEN, AES_BLOCKLEN);

		/* find the next source block */
		while (s && sn >= s->m_len) {
			sn -= s->m_len;
			soff += s->m_len;
			s = s->m_next;
		}
	}

	/* free un-needed source mbufs and add dest mbufs to chain */
	m_freem(scut->m_next);
	scut->m_len = scutoff;
	scut->m_next = d0;

	// free memory
	if (sp_aligned != NULL) {
		kfree_data(sp_aligned, MAX_REALIGN_LEN);
		sp_aligned = NULL;
	}

	/* just in case */
	cc_clear(sizeof(iv), iv);
	cc_clear(sizeof(sbuf), sbuf);

	return 0;
}

int
esp_cbc_encrypt_aes(
	struct mbuf *m,
	size_t off,
	__unused size_t plen,
	struct secasvar *sav,
	const struct esp_algorithm *algo,
	int ivlen)
{
	struct mbuf *s;
	struct mbuf *d, *d0, *dp;
	int soff;       /* offset from the head of chain, to head of this mbuf */
	int sn, dn;     /* offset from the head of the mbuf, to meat */
	size_t ivoff, bodyoff;
	u_int8_t *ivp, *dptr, *ivp_unaligned;
	u_int8_t sbuf[AES_BLOCKLEN] __attribute__((aligned(4))), *sp, *sp_unaligned, *sp_aligned = NULL;
	u_int8_t ivp_aligned_buf[AES_BLOCKLEN] __attribute__((aligned(4)));
	struct mbuf *scut;
	int scutoff;
	int i, len;

	if (ivlen != AES_BLOCKLEN) {
		ipseclog((LOG_ERR, "esp_cbc_encrypt %s: "
		    "unsupported ivlen %d\n", algo->name, ivlen));
		m_freem(m);
		return EINVAL;
	}

	if (sav->flags & SADB_X_EXT_OLD) {
		/* RFC 1827 */
		ivoff = off + sizeof(struct esp);
		bodyoff = off + sizeof(struct esp) + ivlen;
	} else {
		ivoff = off + sizeof(struct newesp);
		bodyoff = off + sizeof(struct newesp) + ivlen;
	}

	VERIFY(ivoff <= INT_MAX);

	/* put iv into the packet */
	m_copyback(m, (int)ivoff, ivlen, sav->iv);
	ivp = (u_int8_t *) sav->iv;

	if (m->m_pkthdr.len < bodyoff) {
		ipseclog((LOG_ERR, "esp_cbc_encrypt %s: bad len %d/%u\n",
		    algo->name, m->m_pkthdr.len, (u_int32_t)bodyoff));
		m_freem(m);
		return EINVAL;
	}
	if ((m->m_pkthdr.len - bodyoff) % AES_BLOCKLEN) {
		ipseclog((LOG_ERR, "esp_cbc_encrypt %s: "
		    "payload length must be multiple of %d\n",
		    algo->name, AES_BLOCKLEN));
		m_freem(m);
		return EINVAL;
	}

	s = m;
	soff = sn = dn = 0;
	d = d0 = dp = NULL;
	sp = dptr = NULL;

	/* skip headers/IV */
	while (soff < bodyoff) {
		if (soff + s->m_len > bodyoff) {
			sn = (int)(bodyoff - soff);
			break;
		}

		soff += s->m_len;
		s = s->m_next;
	}
	scut = s;
	scutoff = sn;

	/* skip over empty mbuf */
	while (s && s->m_len == 0) {
		s = s->m_next;
	}

	while (soff < m->m_pkthdr.len) {
		/* source */
		if (sn + AES_BLOCKLEN <= s->m_len) {
			/* body is continuous */
			sp = mtod(s, u_int8_t *) + sn;
			len = s->m_len - sn;
			len -= len % AES_BLOCKLEN;      // full blocks only
		} else {
			/* body is non-continuous */
			m_copydata(s, sn, AES_BLOCKLEN, (caddr_t) sbuf);
			sp = sbuf;
			len = AES_BLOCKLEN;                     // 1 block only in sbuf
		}

		/* destination */
		if (!d || dn + AES_BLOCKLEN > d->m_len) {
			if (d) {
				dp = d;
			}
			MGET(d, M_DONTWAIT, MT_DATA);
			i = m->m_pkthdr.len - (soff + sn);
			if (d && i > MLEN) {
				MCLGET(d, M_DONTWAIT);
				if ((d->m_flags & M_EXT) == 0) {
					d = m_mbigget(d, M_DONTWAIT);
					if ((d->m_flags & M_EXT) == 0) {
						m_free(d);
						d = NULL;
					}
				}
			}
			if (!d) {
				m_freem(m);
				if (d0) {
					m_freem(d0);
				}
				return ENOBUFS;
			}
			if (!d0) {
				d0 = d;
			}
			if (dp) {
				dp->m_next = d;
			}

			// try to make mbuf data aligned
			if (!IPSEC_IS_P2ALIGNED(d->m_data)) {
				m_adj(d, IPSEC_GET_P2UNALIGNED_OFS(d->m_data));
			}

			d->m_len = (int)M_TRAILINGSPACE(d);
			d->m_len -= d->m_len % AES_BLOCKLEN;
			if (d->m_len > i) {
				d->m_len = i;
			}
			dptr = mtod(d, u_int8_t *);
			dn = 0;
		}

		/* adjust len if greater than space available */
		if (len > d->m_len - dn) {
			len = d->m_len - dn;
		}

		/* encrypt */
		// check input pointer alignment and use a separate aligned buffer (if sp is not aligned on 4-byte boundary).
		if (IPSEC_IS_P2ALIGNED(sp)) {
			sp_unaligned = NULL;
		} else {
			sp_unaligned = sp;
			if (len > MAX_REALIGN_LEN) {
				m_freem(m);
				if (d0) {
					m_freem(d0);
				}
				if (sp_aligned != NULL) {
					kfree_data(sp_aligned, MAX_REALIGN_LEN);
					sp_aligned = NULL;
				}
				return ENOBUFS;
			}
			if (sp_aligned == NULL) {
				sp_aligned = (u_int8_t *)kalloc_data(MAX_REALIGN_LEN, Z_NOWAIT);
				if (sp_aligned == NULL) {
					m_freem(m);
					if (d0) {
						m_freem(d0);
					}
					return ENOMEM;
				}
			}
			sp = sp_aligned;
			memcpy(sp, sp_unaligned, len);
		}
		// check ivp pointer alignment and use a separate aligned buffer (if ivp is not aligned on 4-byte boundary).
		if (IPSEC_IS_P2ALIGNED(ivp)) {
			ivp_unaligned = NULL;
		} else {
			ivp_unaligned = ivp;
			ivp = ivp_aligned_buf;
			memcpy(ivp, ivp_unaligned, AES_BLOCKLEN);
		}
		// no need to check output pointer alignment
		aes_encrypt_cbc(sp, ivp, len >> 4, dptr + dn,
		    (aes_encrypt_ctx*)(&(((aes_ctx*)sav->sched)->encrypt)));

		// update unaligned pointers
		if (!IPSEC_IS_P2ALIGNED(sp_unaligned)) {
			sp = sp_unaligned;
		}
		if (!IPSEC_IS_P2ALIGNED(ivp_unaligned)) {
			ivp = ivp_unaligned;
		}

		/* update offsets */
		sn += len;
		dn += len;

		/* next iv */
		ivp = dptr + dn - AES_BLOCKLEN; // last block encrypted

		/* find the next source block and skip empty mbufs */
		while (s && sn >= s->m_len) {
			sn -= s->m_len;
			soff += s->m_len;
			s = s->m_next;
		}
	}

	/* free un-needed source mbufs and add dest mbufs to chain */
	m_freem(scut->m_next);
	scut->m_len = scutoff;
	scut->m_next = d0;

	// free memory
	if (sp_aligned != NULL) {
		kfree_data(sp_aligned, MAX_REALIGN_LEN);
		sp_aligned = NULL;
	}

	/* just in case */
	cc_clear(sizeof(sbuf), sbuf);
	key_sa_stir_iv(sav);

	return 0;
}

int
esp_aes_cbc_encrypt_data(struct secasvar *sav, uint8_t *input_data,
    size_t input_data_len, struct newesp *esp_hdr, uint8_t *out_iv,
    size_t out_ivlen, uint8_t *output_data, size_t output_data_len)
{
	aes_encrypt_ctx *ctx = NULL;
	uint8_t *ivp = NULL;
	aes_rval rc = 0;

	ESP_CHECK_ARG(sav);
	ESP_CHECK_ARG(input_data);
	ESP_CHECK_ARG(esp_hdr);
	ESP_CHECK_ARG(out_iv);
	ESP_CHECK_ARG(output_data);

	VERIFY(input_data_len > 0);
	VERIFY(output_data_len >= input_data_len);

	VERIFY(out_ivlen == AES_BLOCKLEN);
	memcpy(out_iv, sav->iv, out_ivlen);
	ivp = (uint8_t *)sav->iv;

	if (input_data_len % AES_BLOCKLEN) {
		esp_log_err("payload length %zu must be multiple of "
		    "AES_BLOCKLEN, SPI 0x%08x", input_data_len, ntohl(sav->spi));
		return EINVAL;
	}

	ctx = (aes_encrypt_ctx *)(&(((aes_ctx *)sav->sched)->encrypt));

	VERIFY((input_data_len >> 4) <= UINT32_MAX);
	if (__improbable((rc = aes_encrypt_cbc(input_data, ivp,
	    (unsigned int)(input_data_len >> 4), output_data, ctx)) != 0)) {
		esp_log_err("encrypt failed %d, SPI 0x%08x", rc, ntohl(sav->spi));
		return rc;
	}

	key_sa_stir_iv(sav);
	return 0;
}

int
esp_aes_cbc_decrypt_data(struct secasvar *sav, uint8_t *input_data,
    size_t input_data_len, struct newesp *esp_hdr, uint8_t *iv,
    size_t ivlen, uint8_t *output_data, size_t output_data_len)
{
	aes_decrypt_ctx *ctx = NULL;
	aes_rval rc = 0;

	ESP_CHECK_ARG(sav);
	ESP_CHECK_ARG(input_data);
	ESP_CHECK_ARG(esp_hdr);
	ESP_CHECK_ARG(output_data);

	VERIFY(input_data_len > 0);
	VERIFY(output_data_len >= input_data_len);

	if (__improbable(ivlen != AES_BLOCKLEN)) {
		esp_log_err("ivlen(%zu) != AES_BLOCKLEN, SPI 0x%08x",
		    ivlen, ntohl(sav->spi));
		return EINVAL;
	}

	if (__improbable(input_data_len % AES_BLOCKLEN)) {
		esp_packet_log_err("input data length(%zu) must be a multiple of "
		    "AES_BLOCKLEN", input_data_len);
		return EINVAL;
	}

	ctx = (aes_decrypt_ctx *)(&(((aes_ctx *)sav->sched)->decrypt));

	VERIFY((input_data_len >> 4) <= UINT32_MAX);
	if (__improbable((rc = aes_decrypt_cbc(input_data, iv,
	    (unsigned int)(input_data_len >> 4), output_data, ctx)) != 0)) {
		esp_log_err("decrypt failed %d, SPI 0x%08x", rc, ntohl(sav->spi));
		return rc;
	}

	return 0;
}

size_t
esp_gcm_schedlen(
	__unused const struct esp_algorithm *algo)
{
	return sizeof(aes_gcm_ctx) + aes_decrypt_get_ctx_size_gcm() + aes_encrypt_get_ctx_size_gcm() + ESP_GCM_ALIGN;
}

int
esp_gcm_schedule( __unused const struct esp_algorithm *algo,
    struct secasvar *sav)
{
	LCK_MTX_ASSERT(sadb_mutex, LCK_MTX_ASSERT_OWNED);
	aes_gcm_ctx *ctx = (aes_gcm_ctx*)P2ROUNDUP(sav->sched, ESP_GCM_ALIGN);
	const u_int ivlen = sav->ivlen;
	const bool implicit_iv = ((sav->flags & SADB_X_EXT_IIV) != 0);
	const bool gmac_only = (sav->alg_enc == SADB_X_EALG_AES_GMAC);
	unsigned char nonce[ESP_GCM_SALT_LEN + ivlen];
	int rc;

	ctx->decrypt = &ctx->ctxt[0];
	ctx->encrypt = &ctx->ctxt[aes_decrypt_get_ctx_size_gcm() / sizeof(ccgcm_ctx)];

	if (ivlen != (implicit_iv ? 0 : ESP_GCM_IVLEN)) {
		ipseclog((LOG_ERR, "%s: unsupported ivlen %d\n", __FUNCTION__, ivlen));
		return EINVAL;
	}

	if (implicit_iv && gmac_only) {
		ipseclog((LOG_ERR, "%s: IIV and GMAC-only not supported together\n", __FUNCTION__));
		return EINVAL;
	}

	rc = aes_decrypt_key_gcm((const unsigned char *) _KEYBUF(sav->key_enc), _KEYLEN(sav->key_enc) - ESP_GCM_SALT_LEN, ctx->decrypt);
	if (rc) {
		return rc;
	}

	if (!implicit_iv) {
		memset(nonce, 0, ESP_GCM_SALT_LEN + ivlen);
		memcpy(nonce, _KEYBUF(sav->key_enc) + _KEYLEN(sav->key_enc) - ESP_GCM_SALT_LEN, ESP_GCM_SALT_LEN);
		memcpy(nonce + ESP_GCM_SALT_LEN, sav->iv, ivlen);

		rc = aes_encrypt_key_with_iv_gcm((const unsigned char *) _KEYBUF(sav->key_enc), _KEYLEN(sav->key_enc) - ESP_GCM_SALT_LEN, nonce, ctx->encrypt);
		cc_clear(sizeof(nonce), nonce);
		if (rc) {
			return rc;
		}
	} else {
		rc = aes_encrypt_key_gcm((const unsigned char *) _KEYBUF(sav->key_enc), _KEYLEN(sav->key_enc) - ESP_GCM_SALT_LEN, ctx->encrypt);
		if (rc) {
			return rc;
		}
	}

	rc = aes_encrypt_reset_gcm(ctx->encrypt);
	if (rc) {
		return rc;
	}

	return rc;
}

int
esp_gcm_ivlen(const struct esp_algorithm *algo,
    struct secasvar *sav)
{
	if (!algo) {
		panic("esp_gcm_ivlen: unknown algorithm");
	}

	if (sav != NULL && ((sav->flags & SADB_X_EXT_IIV) != 0)) {
		return 0;
	} else {
		return algo->ivlenval;
	}
}

int
esp_gcm_encrypt_finalize(struct secasvar *sav,
    unsigned char *tag, size_t tag_bytes)
{
	aes_gcm_ctx *ctx = (aes_gcm_ctx*)P2ROUNDUP(sav->sched, ESP_GCM_ALIGN);
	return aes_encrypt_finalize_gcm(tag, tag_bytes, ctx->encrypt);
}

int
esp_gcm_decrypt_finalize(struct secasvar *sav,
    unsigned char *tag, size_t tag_bytes)
{
	aes_gcm_ctx *ctx = (aes_gcm_ctx*)P2ROUNDUP(sav->sched, ESP_GCM_ALIGN);
	return aes_decrypt_finalize_gcm(tag, tag_bytes, ctx->decrypt);
}

int
esp_gcm_encrypt_aes(
	struct mbuf *m,
	size_t off,
	__unused size_t plen,
	struct secasvar *sav,
	const struct esp_algorithm *algo __unused,
	int ivlen)
{
	struct mbuf *s = m;
	uint32_t soff = 0;       /* offset from the head of chain, to head of this mbuf */
	uint32_t sn = 0;     /* offset from the head of the mbuf, to meat */
	uint8_t *sp = NULL;
	aes_gcm_ctx *ctx;
	uint32_t len;
	const bool implicit_iv = ((sav->flags & SADB_X_EXT_IIV) != 0);
	const bool gmac_only = (sav->alg_enc == SADB_X_EALG_AES_GMAC);
	struct newesp esp;
	unsigned char nonce[ESP_GCM_SALT_LEN + ESP_GCM_IVLEN];

	VERIFY(off <= INT_MAX);
	const size_t ivoff = off + sizeof(struct newesp);
	VERIFY(ivoff <= INT_MAX);
	const size_t bodyoff = ivoff + ivlen;
	VERIFY(bodyoff <= INT_MAX);

	if (ivlen != (implicit_iv ? 0 : ESP_GCM_IVLEN)) {
		ipseclog((LOG_ERR, "%s: unsupported ivlen %d\n", __FUNCTION__, ivlen));
		m_freem(m);
		return EINVAL;
	}

	if (implicit_iv && gmac_only) {
		ipseclog((LOG_ERR, "%s: IIV and GMAC-only not supported together\n", __FUNCTION__));
		m_freem(m);
		return EINVAL;
	}

	ctx = (aes_gcm_ctx *)P2ROUNDUP(sav->sched, ESP_GCM_ALIGN);

	if (aes_encrypt_reset_gcm(ctx->encrypt)) {
		ipseclog((LOG_ERR, "%s: gcm reset failure\n", __FUNCTION__));
		m_freem(m);
		return EINVAL;
	}

	/* Copy the ESP header */
	m_copydata(m, (int)off, sizeof(esp), (caddr_t) &esp);

	/* Construct the IV */
	memset(nonce, 0, sizeof(nonce));
	if (!implicit_iv) {
		/* generate new iv */
		if (aes_encrypt_inc_iv_gcm((unsigned char *)nonce, ctx->encrypt)) {
			ipseclog((LOG_ERR, "%s: iv generation failure\n", __FUNCTION__));
			m_freem(m);
			return EINVAL;
		}

		/*
		 * The IV is now generated within corecrypto and
		 * is provided to ESP using aes_encrypt_inc_iv_gcm().
		 * This makes the sav->iv redundant and is no longer
		 * used in GCM operations. But we still copy the IV
		 * back to sav->iv to ensure that any future code reading
		 * this value will get the latest IV.
		 */
		memcpy(sav->iv, (nonce + ESP_GCM_SALT_LEN), ivlen);
		m_copyback(m, (int)ivoff, ivlen, sav->iv);
	} else {
		/* Use the ESP sequence number in the header to form the
		 * nonce according to RFC 8750. The first 4 bytes are the
		 * salt value, the next 4 bytes are zeroes, and the final
		 * 4 bytes are the ESP sequence number.
		 */
		memcpy(nonce, _KEYBUF(sav->key_enc) + _KEYLEN(sav->key_enc) - ESP_GCM_SALT_LEN, ESP_GCM_SALT_LEN);
		memcpy(nonce + sizeof(nonce) - sizeof(esp.esp_seq), &esp.esp_seq, sizeof(esp.esp_seq));
		if (aes_encrypt_set_iv_gcm((const unsigned char *)nonce, sizeof(nonce), ctx->encrypt)) {
			ipseclog((LOG_ERR, "%s: iv set failure\n", __FUNCTION__));
			cc_clear(sizeof(nonce), nonce);
			m_freem(m);
			return EINVAL;
		}
	}

	if (m->m_pkthdr.len < bodyoff) {
		ipseclog((LOG_ERR, "%s: bad len %d/%u\n", __FUNCTION__,
		    m->m_pkthdr.len, (u_int32_t)bodyoff));
		cc_clear(sizeof(nonce), nonce);
		m_freem(m);
		return EINVAL;
	}

	/* Add ESP header to Additional Authentication Data */
	if (aes_encrypt_aad_gcm((unsigned char*)&esp, sizeof(esp), ctx->encrypt)) {
		ipseclog((LOG_ERR, "%s: packet encryption ESP header AAD failure\n", __FUNCTION__));
		cc_clear(sizeof(nonce), nonce);
		m_freem(m);
		return EINVAL;
	}
	/* Add IV to Additional Authentication Data for GMAC-only mode */
	if (gmac_only) {
		if (aes_encrypt_aad_gcm(nonce + ESP_GCM_SALT_LEN, ESP_GCM_IVLEN, ctx->encrypt)) {
			ipseclog((LOG_ERR, "%s: packet encryption IV AAD failure\n", __FUNCTION__));
			cc_clear(sizeof(nonce), nonce);
			m_freem(m);
			return EINVAL;
		}
	}

	/* Clear nonce */
	cc_clear(sizeof(nonce), nonce);

	/* skip headers/IV */
	while (s != NULL && soff < bodyoff) {
		if (soff + s->m_len > bodyoff) {
			sn = (uint32_t)bodyoff - soff;
			break;
		}

		soff += s->m_len;
		s = s->m_next;
	}

	/* Encrypt (or add to AAD) payload */
	while (s != NULL && soff < m->m_pkthdr.len) {
		/* skip empty mbufs */
		if ((len = s->m_len - sn) != 0) {
			sp = mtod(s, uint8_t *) + sn;

			if (!gmac_only) {
				if (aes_encrypt_gcm(sp, len, sp, ctx->encrypt)) {
					ipseclog((LOG_ERR, "%s: failed to encrypt\n", __FUNCTION__));
					m_freem(m);
					return EINVAL;
				}
			} else {
				if (aes_encrypt_aad_gcm(sp, len, ctx->encrypt)) {
					ipseclog((LOG_ERR, "%s: failed to add data to AAD\n", __FUNCTION__));
					m_freem(m);
					return EINVAL;
				}
			}
		}

		sn = 0;
		soff += s->m_len;
		s = s->m_next;
	}

	if (s == NULL && soff != m->m_pkthdr.len) {
		ipseclog((LOG_ERR, "%s: not enough mbufs %d %d, SPI 0x%08x",
		    __FUNCTION__, soff, m->m_pkthdr.len, ntohl(sav->spi)));
		m_freem(m);
		return EFBIG;
	}

	return 0;
}

int
esp_gcm_decrypt_aes(
	struct mbuf *m,
	size_t off,
	struct secasvar *sav,
	const struct esp_algorithm *algo __unused,
	int ivlen)
{
	struct mbuf *s = m;
	uint32_t soff = 0;       /* offset from the head of chain, to head of this mbuf */
	uint32_t sn = 0;     /* offset from the head of the mbuf, to meat */
	uint8_t *sp = NULL;
	aes_gcm_ctx *ctx;
	uint32_t len;
	const bool implicit_iv = ((sav->flags & SADB_X_EXT_IIV) != 0);
	const bool gmac_only = (sav->alg_enc == SADB_X_EALG_AES_GMAC);
	struct newesp esp;
	unsigned char nonce[ESP_GCM_SALT_LEN + ESP_GCM_IVLEN];

	VERIFY(off <= INT_MAX);
	const size_t ivoff = off + sizeof(struct newesp);
	VERIFY(ivoff <= INT_MAX);
	const size_t bodyoff = ivoff + ivlen;
	VERIFY(bodyoff <= INT_MAX);

	if (ivlen != (implicit_iv ? 0 : ESP_GCM_IVLEN)) {
		ipseclog((LOG_ERR, "%s: unsupported ivlen %d\n", __FUNCTION__, ivlen));
		m_freem(m);
		return EINVAL;
	}

	if (implicit_iv && gmac_only) {
		ipseclog((LOG_ERR, "%s: IIV and GMAC-only not supported together\n", __FUNCTION__));
		m_freem(m);
		return EINVAL;
	}

	if (m->m_pkthdr.len < bodyoff) {
		ipseclog((LOG_ERR, "%s: bad len %d/%u\n", __FUNCTION__,
		    m->m_pkthdr.len, (u_int32_t)bodyoff));
		m_freem(m);
		return EINVAL;
	}

	/* Copy the ESP header */
	m_copydata(m, (int)off, sizeof(esp), (caddr_t) &esp);

	/* Construct IV starting with salt */
	memset(nonce, 0, sizeof(nonce));
	memcpy(nonce, _KEYBUF(sav->key_enc) + _KEYLEN(sav->key_enc) - ESP_GCM_SALT_LEN, ESP_GCM_SALT_LEN);
	if (!implicit_iv) {
		/* grab IV from packet */
		u_int8_t iv[ESP_GCM_IVLEN] __attribute__((aligned(4)));
		m_copydata(m, (int)ivoff, ivlen, (caddr_t) iv);
		memcpy(nonce + ESP_GCM_SALT_LEN, iv, ivlen);
		/* just in case */
		cc_clear(sizeof(iv), iv);
	} else {
		/* Use the ESP sequence number in the header to form the
		 * rest of the nonce according to RFC 8750.
		 */
		memcpy(nonce + sizeof(nonce) - sizeof(esp.esp_seq), &esp.esp_seq, sizeof(esp.esp_seq));
	}

	ctx = (aes_gcm_ctx *)P2ROUNDUP(sav->sched, ESP_GCM_ALIGN);
	if (aes_decrypt_set_iv_gcm(nonce, sizeof(nonce), ctx->decrypt)) {
		ipseclog((LOG_ERR, "%s: failed to set IV\n", __FUNCTION__));
		cc_clear(sizeof(nonce), nonce);
		m_freem(m);
		return EINVAL;
	}

	/* Add ESP header to Additional Authentication Data */
	if (aes_decrypt_aad_gcm((unsigned char*)&esp, sizeof(esp), ctx->decrypt)) {
		ipseclog((LOG_ERR, "%s: packet decryption ESP header AAD failure\n", __FUNCTION__));
		cc_clear(sizeof(nonce), nonce);
		m_freem(m);
		return EINVAL;
	}

	/* Add IV to Additional Authentication Data for GMAC-only mode */
	if (gmac_only) {
		if (aes_decrypt_aad_gcm(nonce + ESP_GCM_SALT_LEN, ESP_GCM_IVLEN, ctx->decrypt)) {
			ipseclog((LOG_ERR, "%s: packet decryption IV AAD failure\n", __FUNCTION__));
			cc_clear(sizeof(nonce), nonce);
			m_freem(m);
			return EINVAL;
		}
	}

	/* Clear nonce */
	cc_clear(sizeof(nonce), nonce);

	/* skip headers/IV */
	while (s != NULL && soff < bodyoff) {
		if (soff + s->m_len > bodyoff) {
			sn = (uint32_t)bodyoff - soff;
			break;
		}

		soff += s->m_len;
		s = s->m_next;
	}

	/* Decrypt (or just authenticate) payload */
	while (s != NULL && soff < m->m_pkthdr.len) {
		/* skip empty mbufs */
		if ((len = s->m_len - sn) != 0) {
			sp = mtod(s, uint8_t *) + sn;

			if (!gmac_only) {
				if (aes_decrypt_gcm(sp, len, sp, ctx->decrypt)) {
					ipseclog((LOG_ERR, "%s: failed to decrypt\n", __FUNCTION__));
					m_freem(m);
					return EINVAL;
				}
			} else {
				if (aes_decrypt_aad_gcm(sp, len, ctx->decrypt)) {
					ipseclog((LOG_ERR, "%s: failed to add data to AAD\n", __FUNCTION__));
					m_freem(m);
					return EINVAL;
				}
			}
		}

		sn = 0;
		soff += s->m_len;
		s = s->m_next;
	}

	if (s == NULL && soff != m->m_pkthdr.len) {
		ipseclog((LOG_ERR, "%s: not enough mbufs %d %d, SPI 0x%08x",
		    __FUNCTION__, soff, m->m_pkthdr.len, ntohl(sav->spi)));
		m_freem(m);
		return EFBIG;
	}

	return 0;
}

int
esp_aes_gcm_encrypt_data(struct secasvar *sav, uint8_t *input_data,
    size_t input_data_len, struct newesp *esp_hdr, uint8_t *out_iv,
    size_t ivlen, uint8_t *output_data, size_t output_data_len)
{
	unsigned char nonce[ESP_GCM_SALT_LEN + ESP_GCM_IVLEN] = {};
	int rc = 0; // return code of corecrypto operations

	ESP_CHECK_ARG(sav);
	ESP_CHECK_ARG(input_data);
	ESP_CHECK_ARG(esp_hdr);
	ESP_CHECK_ARG(output_data);

	VERIFY(input_data_len > 0);
	VERIFY(output_data_len >= input_data_len);

	const bool implicit_iv = ((sav->flags & SADB_X_EXT_IIV) == SADB_X_EXT_IIV);
	const bool gmac_only = (sav->alg_enc == SADB_X_EALG_AES_GMAC);

	if (__improbable(implicit_iv && gmac_only)) {
		esp_log_err("IIV and GMAC-only not supported together, SPI  0x%08x\n",
		    ntohl(sav->spi));
		return EINVAL;
	}

	aes_gcm_ctx *ctx = (aes_gcm_ctx *)P2ROUNDUP(sav->sched, ESP_GCM_ALIGN);

	if (__improbable((rc = aes_encrypt_reset_gcm(ctx->encrypt)) != 0)) {
		esp_log_err("Context reset failure %d, SPI 0x%08x\n",
		    rc, ntohl(sav->spi));
		return rc;
	}

	if (implicit_iv) {
		VERIFY(out_iv == NULL);
		VERIFY(ivlen == 0);

		/* Use the ESP sequence number in the header to form the
		 * nonce according to RFC 8750. The first 4 bytes are the
		 * salt value, the next 4 bytes are zeroes, and the final
		 * 4 bytes are the ESP sequence number.
		 */
		memcpy(nonce, _KEYBUF(sav->key_enc) + _KEYLEN(sav->key_enc) -
		    ESP_GCM_SALT_LEN, ESP_GCM_SALT_LEN);
		memcpy(nonce + sizeof(nonce) - sizeof(esp_hdr->esp_seq),
		    &esp_hdr->esp_seq, sizeof(esp_hdr->esp_seq));
		if (__improbable((rc = aes_encrypt_set_iv_gcm((const unsigned char *)nonce,
		    sizeof(nonce), ctx->encrypt)) != 0)) {
			esp_log_err("Set IV failure %d, SPI 0x%08x\n",
			    rc, ntohl(sav->spi));
			cc_clear(sizeof(nonce), nonce);
			return rc;
		}
	} else {
		ESP_CHECK_ARG(out_iv);
		VERIFY(ivlen == ESP_GCM_IVLEN);

		/* generate new iv */
		if (__improbable((rc = aes_encrypt_inc_iv_gcm((unsigned char *)nonce,
		    ctx->encrypt)) != 0)) {
			esp_log_err("IV generation failure %d, SPI 0x%08x\n",
			    rc, ntohl(sav->spi));
			cc_clear(sizeof(nonce), nonce);
			return rc;
		}

		memcpy(out_iv, (nonce + ESP_GCM_SALT_LEN), ESP_GCM_IVLEN);
	}

	/* Set Additional Authentication Data */
	if (__improbable((rc = aes_encrypt_aad_gcm((unsigned char*)esp_hdr,
	    sizeof(*esp_hdr), ctx->encrypt)) != 0)) {
		esp_log_err("Set AAD failure %d, SPI 0x%08x\n", rc, ntohl(sav->spi));
		cc_clear(sizeof(nonce), nonce);
		return rc;
	}

	/* Add IV to Additional Authentication Data for GMAC-only mode */
	if (gmac_only) {
		if (__improbable((rc = aes_encrypt_aad_gcm(nonce +
		    ESP_GCM_SALT_LEN, ESP_GCM_IVLEN, ctx->encrypt)) != 0)) {
			esp_log_err("Packet encryption IV AAD failure %d, SPI 0x%08x\n",
			    rc, ntohl(sav->spi));
			cc_clear(sizeof(nonce), nonce);
			return rc;
		}
	}

	cc_clear(sizeof(nonce), nonce);

	if (gmac_only) {
		if (__improbable((rc = aes_encrypt_aad_gcm(input_data, (unsigned int)input_data_len,
		    ctx->encrypt)) != 0)) {
			esp_log_err("set aad failure %d, SPI 0x%08x\n", rc, ntohl(sav->spi));
			return rc;
		}
		memcpy(output_data, input_data, input_data_len);
	} else {
		if (__improbable((rc = aes_encrypt_gcm(input_data, (unsigned int)input_data_len,
		    output_data, ctx->encrypt)) != 0)) {
			esp_log_err("encrypt failure %d, SPI 0x%08x\n", rc, ntohl(sav->spi));
			return rc;
		}
	}

	return 0;
}

int
esp_aes_gcm_decrypt_data(struct secasvar *sav, uint8_t *input_data,
    size_t input_data_len, struct newesp *esp_hdr, uint8_t *iv, size_t ivlen,
    uint8_t *output_data, size_t output_data_len)
{
	unsigned char nonce[ESP_GCM_SALT_LEN + ESP_GCM_IVLEN] = {};
	aes_gcm_ctx *ctx = NULL;
	int rc = 0;

	ESP_CHECK_ARG(sav);
	ESP_CHECK_ARG(input_data);
	ESP_CHECK_ARG(esp_hdr);
	ESP_CHECK_ARG(output_data);

	VERIFY(input_data_len > 0);
	VERIFY(output_data_len >= input_data_len);

	const bool implicit_iv = ((sav->flags & SADB_X_EXT_IIV) == SADB_X_EXT_IIV);
	const bool gmac_only = (sav->alg_enc == SADB_X_EALG_AES_GMAC);

	if (__improbable(implicit_iv && gmac_only)) {
		esp_log_err("IIV and GMAC-only not supported together, SPI  0x%08x\n",
		    ntohl(sav->spi));
		return EINVAL;
	}

	memcpy(nonce, _KEYBUF(sav->key_enc) + _KEYLEN(sav->key_enc) -
	    ESP_GCM_SALT_LEN, ESP_GCM_SALT_LEN);

	if (implicit_iv) {
		VERIFY(iv == NULL);
		VERIFY(ivlen == 0);

		/* Use the ESP sequence number in the header to form the
		 * rest of the nonce according to RFC 8750.
		 */
		memcpy(nonce + sizeof(nonce) - sizeof(esp_hdr->esp_seq), &esp_hdr->esp_seq, sizeof(esp_hdr->esp_seq));
	} else {
		ESP_CHECK_ARG(iv);
		VERIFY(ivlen == ESP_GCM_IVLEN);

		memcpy(nonce + ESP_GCM_SALT_LEN, iv, ESP_GCM_IVLEN);
	}

	ctx = (aes_gcm_ctx *)P2ROUNDUP(sav->sched, ESP_GCM_ALIGN);

	if (__improbable((rc = aes_decrypt_set_iv_gcm(nonce, sizeof(nonce),
	    ctx->decrypt)) != 0)) {
		esp_log_err("set iv failure %d, SPI 0x%08x\n", rc, ntohl(sav->spi));
		cc_clear(sizeof(nonce), nonce);
		return rc;
	}

	/* Set Additional Authentication Data */
	if (__improbable((rc = aes_decrypt_aad_gcm((unsigned char *)esp_hdr, sizeof(*esp_hdr),
	    ctx->decrypt)) != 0)) {
		esp_log_err("AAD failure %d, SPI 0x%08x\n", rc, ntohl(sav->spi));
		cc_clear(sizeof(nonce), nonce);
		return rc;
	}

	/* Add IV to Additional Authentication Data for GMAC-only mode */
	if (gmac_only) {
		if (__improbable((rc = aes_decrypt_aad_gcm(nonce + ESP_GCM_SALT_LEN,
		    ESP_GCM_IVLEN, ctx->decrypt)) != 0)) {
			esp_log_err("AAD failure %d, SPI 0x%08x\n", rc, ntohl(sav->spi));
			cc_clear(sizeof(nonce), nonce);
			return rc;
		}
	}

	cc_clear(sizeof(nonce), nonce);

	if (gmac_only) {
		if (__improbable((rc = aes_decrypt_aad_gcm(input_data, (unsigned int)input_data_len,
		    ctx->decrypt)) != 0)) {
			esp_log_err("AAD failure %d, SPI 0x%08x\n", rc, ntohl(sav->spi));
			return rc;
		}
		memcpy(output_data, input_data, input_data_len);
	} else {
		if (__improbable((rc = aes_decrypt_gcm(input_data, (unsigned int)input_data_len,
		    output_data, ctx->decrypt)) != 0)) {
			esp_log_err("decrypt failure %d, SPI 0x%08x\n", rc, ntohl(sav->spi));
			return rc;
		}
	}

	return 0;
}
