/*
 * Copyright (c) 2025 Apple Inc. All rights reserved.
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

#include <darwintest.h>
#include <mocks/osfmk/unit_test_utils.h>
#include <kern/cpu_data.h>
#include <kern/ledger.h>

#define UT_MODULE osfmk
T_GLOBAL_META(
	T_META_NAMESPACE("xnu.unit.ledgers"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("RM"),
	T_META_RUN_CONCURRENTLY(true)
	);

static SECURITY_READ_ONLY_LATE(struct ledger_entry_template) tl_entries[] = {
	LEDGER_ENTRY("with_max", "", "bytes", LFEAT_MAXIMUM),
	LEDGER_ENTRY("with_scalable", "", "bytes", LFEAT_SCALABLE),
};

LEDGER_TEMPLATE_DEFINE(tl_template, "Per-task ledger", tl_entries);

#define T_LEDGER_CHECK(l, id, c, d)  ({ \
	ledger_amount_t credit, debit;                                          \
	kr = ledger_get_entries(ledger, id, LEO_NO_SETTLE, &credit, &debit);    \
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "ledger_get_entries");               \
	T_QUIET; T_ASSERT_EQ(credit, c, "credit is %lld", c);                   \
	T_QUIET; T_ASSERT_EQ(debit, d, "debit is %lld", d);                     \
})

T_DECL(basic, "basic ledger test")
{
	/* These tests expect preemption to be disabled. */
	disable_preemption();

	ledger_template_finalize(&tl_template, LEDGER_TPL_SCALABLE);
	ledger_entry_id_t id;
	kern_return_t kr;
	ledger_amount_t v;
	ledger_t ledger;

	ledger = ledger_instantiate(&tl_template);

	id = ledger_key_lookup(&tl_template, "with_max", true);
	T_LEDGER_CHECK(ledger, id, 0ll, 0ll);

	ledger_credit(ledger, id, 42);
	T_LEDGER_CHECK(ledger, id, 42ll, 0ll);

	ledger_debit(ledger, id, 30);
	T_LEDGER_CHECK(ledger, id, 12ll, 0ll);

	ledger_get_lifetime_max(ledger, id, LEO_SETTLE, &v);
	T_ASSERT_EQ(v, 42ll, "max is 42");

	id = ledger_key_lookup(&tl_template, "with_scalable", true);
	T_LEDGER_CHECK(ledger, id, 0ll, 0ll);

	ledger_credit(ledger, id, 42);
	T_LEDGER_CHECK(ledger, id, 42ll, 0ll);

	ledger_debit(ledger, id, 30);
	T_LEDGER_CHECK(ledger, id, 12ll, 0ll);

	ledger_tab_open(&tl_template, ledger);
	T_LEDGER_CHECK(ledger, id, 12ll, 0ll);

	ledger_credit(ledger, id, 1);
	T_LEDGER_CHECK(ledger, id, 12ll, 0ll);

	ledger_credit(ledger, id, 100);
	T_LEDGER_CHECK(ledger, id, 12ll, 0ll);

	ledger_tab_settle(&tl_template, ledger);
	T_LEDGER_CHECK(ledger, id, 113ll, 0ll);

	ledger_debit(ledger, id, 100);
	T_LEDGER_CHECK(ledger, id, 113ll, 0ll);

	ledger_tab_open(&tl_template, NULL);
	T_LEDGER_CHECK(ledger, id, 13ll, 0ll);

	ledger_debit(ledger, id, 1);
	T_LEDGER_CHECK(ledger, id, 12ll, 0ll);
}
