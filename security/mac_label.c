/*-
 * Copyright (c) 2004 Networks Associates Technology, Inc.
 * Copyright (c) 2005 SPARTA, Inc.
 * All rights reserved.
 *
 * This software was developed for the FreeBSD Project in part by Network
 * Associates Laboratories, the Security Research Division of Network
 * Associates, Inc. under DARPA/SPAWAR contract N66001-01-C-8035 ("CBOSS"),
 * as part of the DARPA CHATS research program.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
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

#include <kern/zalloc.h>
#include <security/_label.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/systm.h>
#include <security/mac_internal.h>

ZONE_DEFINE_ID(ZONE_ID_MAC_LABEL, "MAC Labels", struct label,
    ZC_READONLY | ZC_ZFREE_CLEARMEM);

/*
 * Number of initial values matches logic in security/_label.h
 */
const struct label empty_label = {
	.l_perpolicy[0 ... MAC_MAX_SLOTS - 1] = MAC_LABEL_NULL_SLOT,
};

static struct label *
label_alloc_noinit(int flags)
{
	static_assert(MAC_NOWAIT == Z_NOWAIT);
	return zalloc_ro(ZONE_ID_MAC_LABEL, Z_ZERO | (flags & MAC_NOWAIT));
}

struct label *
mac_labelzone_alloc(int flags)
{
	struct label *label;

	label = label_alloc_noinit(flags);
	if (label) {
		zalloc_ro_update_elem(ZONE_ID_MAC_LABEL, label, &empty_label);
	}

	return label;
}

struct label *
mac_labelzone_alloc_for_owner(struct label **labelp, int flags,
    void (^extra_setup)(struct label *))
{
	struct label *label;

	if (labelp) {
		struct label tmp_label = empty_label;

		label = zalloc_ro(ZONE_ID_MAC_LABEL, Z_ZERO | (flags & MAC_NOWAIT));

		tmp_label.l_owner = labelp;
		zalloc_ro_update_elem(ZONE_ID_MAC_LABEL, label, &tmp_label);
	} else {
		label = mac_labelzone_alloc(flags);
	}

	if (label && extra_setup) {
		extra_setup(label);
	}

	return label;
}

struct label *
mac_labelzone_alloc_owned(struct label **labelp, int flags,
    void (^extra_setup)(struct label *))
{
	struct label *label;

	label = mac_labelzone_alloc_for_owner(labelp, flags, extra_setup);

	if (labelp) {
		*labelp = label;
	}

	return label;
}

void
mac_labelzone_free(struct label *label)
{
	if (label == NULL) {
		panic("Free of NULL MAC label");
	}

	zfree_ro(ZONE_ID_MAC_LABEL, label);
}

void
mac_labelzone_free_owned(struct label **labelp,
    void (^extra_deinit)(struct label *))
{
	struct label *label;

	label = mac_label_verify(labelp);
	if (label) {
		if (extra_deinit) {
			extra_deinit(label);
		}

		*labelp = NULL;
		mac_labelzone_free(label);
	}
}

__abortlike
static void
mac_label_verify_panic(struct label **labelp)
{
	panic("label backref mismatch: labelp:%p label:%p l_owner:%p", labelp,
	    *labelp, (*labelp)->l_owner);
}

struct label *
mac_label_verify(struct label **labelp)
{
	struct label *label = *labelp;

	if (label != NULL) {
		zone_require_ro(ZONE_ID_MAC_LABEL, sizeof(struct label), label);

		if (__improbable(label->l_owner != labelp)) {
			mac_label_verify_panic(labelp);
		}
	}

	return label;
}

static intptr_t
mac_label_slot_encode(intptr_t p)
{
	return p ?: MAC_LABEL_NULL_SLOT;
}

static intptr_t
mac_label_slot_decode(intptr_t p)
{
	switch (p) {
	case 0:
		/* make sure 0 doesn't mean NULL and causes crashes */
		return MAC_LABEL_NULL_SLOT;
	case MAC_LABEL_NULL_SLOT:
		return 0l;
	default:
		return p;
	}
}

/*
 * Functions used by policy modules to get and set label values.
 */
intptr_t
mac_label_get(struct label *label, int slot)
{
	KASSERT(label != NULL, ("mac_label_get: NULL label"));

	zone_require_ro(ZONE_ID_MAC_LABEL, sizeof(struct label), label);
	return mac_label_slot_decode((intptr_t) label->l_perpolicy[slot]);
}

__abortlike
static void
panic_label_set_sentinel(void)
{
	panic("cannot set mac label to ~0");
}

void
mac_label_set(struct label *label, int slot, intptr_t v)
{
	KASSERT(label != NULL, ("mac_label_set: NULL label"));

#if DEVELOPMENT || DEBUG
	/* can't modify a sealed label, see mac_cred_label_seal() */
	assertf(label->l_owner != (struct label **)-1,
	    "mac_label_set(%p, %d, 0x%lx) is sealed",
	    label, slot, v);
#endif
	if (v == MAC_LABEL_NULL_SLOT) {
		panic_label_set_sentinel();
	}
	v = mac_label_slot_encode(v);
	zalloc_ro_update_field(ZONE_ID_MAC_LABEL, label, l_perpolicy[slot], &v);
}
