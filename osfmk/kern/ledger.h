/*
 * Copyright (c) 2010-2018 Apple Computer, Inc. All rights reserved.
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
 * @OSF_COPYRIGHT@
 */

#ifndef _KERN_LEDGER_H_
#define _KERN_LEDGER_H_

#include <mach/mach_types.h>    /* ledger_t, ledger_entry_id_t */
#ifdef MACH_KERNEL_PRIVATE
#include <kern/zalloc.h>
#endif /* MACH_KERNEL_PRIVATE */

__BEGIN_DECLS

#define LEDGER_INFO             0
#define LEDGER_ENTRY_INFO       1
#define LEDGER_TEMPLATE_INFO    2
#define LEDGER_LIMIT            3
#define LEDGER_ENTRY_INFO_V2    4
/* LEDGER_MAX_CMD always tracks the index of the last ledger command. */
#define LEDGER_MAX_CMD          LEDGER_ENTRY_INFO_V2

#define LEDGER_NAME_MAX 32

struct ledger_info {
	char    li_name[LEDGER_NAME_MAX];
	int64_t li_id;
	int64_t li_entries;
};

struct ledger_template_info {
	char            lti_name[LEDGER_NAME_MAX];
	char            lti_group[LEDGER_NAME_MAX];
	char            lti_units[LEDGER_NAME_MAX];
};

struct ledger_entry_info {
	int64_t         lei_balance;
	int64_t         lei_credit;
	int64_t         lei_debit;
	uint64_t        lei_limit;
	uint64_t        lei_refill_period;      /* In nanoseconds */
	uint64_t        lei_last_refill;        /* Time since last refill */
};

struct ledger_entry_info_v2 {
	int64_t         lei_balance;
	int64_t         lei_credit;
	int64_t         lei_debit;
	uint64_t        lei_limit;
	uint64_t        lei_refill_period;      /* In nanoseconds */
	uint64_t        lei_last_refill;        /* Time since last refill */
	int64_t         lei_lifetime_max;       /* for phys_footprint/neural_nofootprint_lifetime_max */
	uint64_t        lei_reserved[4];
};

struct ledger_limit_args {
	char            lla_name[LEDGER_NAME_MAX];
	uint64_t        lla_limit;
	uint64_t        lla_refill_period;
};

#if KERNEL_PRIVATE

typedef struct ledger_template *ledger_template_t;

#define LEDGER_VALID(ledger)    (ledger != LEDGER_NULL)


#endif /* KERNEL_PRIVATE */
#ifdef MACH_KERNEL_PRIVATE

#if MACH_ASSERT
#define LEDGER_HAS_FEAT_ASSERT_POSITIVE 1
#else
#define LEDGER_HAS_FEAT_ASSERT_POSITIVE 0
#endif

#if DEVELOPMENT || DEBUG
#define LEDGER_HAS_FEAT_DIAG            1
#else
#define LEDGER_HAS_FEAT_DIAG            0
#endif

/*!
 * @abstract
 * Describe the features that will be used on a ledger entry.
 *
 * @discusssion
 * The features are opt-in, and if a given ledger feature is not going
 * to be used, it should not be selected as it allows for the ledger subsystem
 * to chose more performant implementations both in space and CPU.
 *
 * @const LFEAT_SCALABLE
 * Denotes that the backing store for the balance and debit counters
 * should be as scalable as possible.
 *
 * This is not compatible with LFEAT_REFILL.
 *
 * @const LFEAT_ASSERT_POSITIVE
 * Denotes that this ledger balance should never become negative.
 * If MACH_ASSERT is enabled, hitting a negative balance will panic.
 *
 *
 * @const LFEAT_DEBIT
 * Denotes that this entry will remember the historical "debit"
 * of the entry instead of just its balance.
 *
 * Note that not opting into this feature still allows for @c ledger_debit()
 * to be used.
 *
 * @const LFEAT_MAXIMUM
 * Enables the following APIs on this ledger entry:
 * - ledger_get_interval_max(),
 * - ledger_get_lifetime_max().
 *
 * This is not compatible with LFEAT_DEBIT or LFEAT_REFILL.
 *
 * @const LFEAT_REFILL
 * Enables the following APIs on this ledger entry:
 * - ledger_get_remaining(),
 * - ledger_get_interval_remaining().
 * - ledger_get_period(),
 * - ledger_set_period(),
 * - ledger_set_blocking(),
 * - ledger_restart(),
 *
 * This is not compatible LFEAT_MAXIMUM or LFEAT_SCALABLE.
 * It also implies LFEAT_DEBIT.
 *
 * @const LFEAT_CALLBACK
 * Enables the following APIs on this ledger entry:
 * - ledger_disable_callback(),
 * - ledger_enable_callback().
 *
 * @const LFEAT_DIAG
 * Enables the following APIs on this ledger entry:
 * - ledger_set_diag_mem_threshold(),
 * - ledger_get_diag_mem_threshold(),
 * - ledger_diag_mem_threshold_enabled().
 *
 * It also implies LFEAT_CALLBACK.
 * It is only active on development kernels.
 *
 *
 * @const LFEAT_LIMIT_MASK
 * Set of features which enables the following APIs in this ledger entry:
 * - ledger_get_limit(),
 * - ledger_set_limit().
 *
 * @const LFEAT_LARGE_MASK
 * Sets of features which makes the entry large.
 */
__options_closed_decl(ledger_id_flags_t, uint32_t, {
	LFEAT_NONE              = 0x00000000,

	/*
	 * Small ledger options
	 */
	LFEAT_SCALABLE          = 0x00400000,
#if LEDGER_HAS_FEAT_ASSERT_POSITIVE
	LFEAT_ASSERT_POSITIVE   = 0x00800000,
#else
	LFEAT_ASSERT_POSITIVE   = 0x00000000,
#endif

	/*
	 * Large ledger options
	 */
	LFEAT_DEBIT             = 0x08000000,
	LFEAT_MAXIMUM           = 0x10000000,

	/*
	 * "Limit" ledger options
	 */
	LFEAT_REFILL            = 0x20000000,
	LFEAT_CALLBACK          = 0x40000000,
#if LEDGER_HAS_FEAT_DIAG
	LFEAT_DIAG              = 0x80000000,
#else
	LFEAT_DIAG              = 0x00000000,
#endif
});

#define LFEAT_LIMIT_MASK        (LFEAT_REFILL | LFEAT_CALLBACK | LFEAT_DIAG)
#define LFEAT_LARGE_MASK        (LFEAT_DEBIT | LFEAT_MAXIMUM | LFEAT_LIMIT_MASK)

/*
 * Types of warnings that trigger a callback.
 */
__enum_decl(ledger_warning_t, uint16_t, {
	LEDGER_WARNING_LEVEL_CRITICAL,
	LEDGER_WARNING_LEVEL_WARNING,
	LEDGER_WARNING_LEVEL_DIAG,
});

typedef void (*ledger_callback_t)(ledger_warning_t warning, const void *param0);

extern bool pmap_ledgers_panic;
extern int pmap_ledgers_panic_leeway;

#pragma mark ledger templates and lifecycle

#define LEDGER_HEADER_SIZE           32
#define LEDGER_ENTRY_SMALL_SIZE      16
#define LEDGER_ENTRY_SIZE            48
#define LEDGER_SCALABLE_MAX          64

/*
 * Ledger templates describe the meaning of ledgers.
 *
 * These types are constant and immutable after being setup,
 * and define the base properties for all ledgers instantiated from a template.
 */

typedef struct ledger_entry_template {
	char                    et_key[LEDGER_NAME_MAX];
	char                    et_group[LEDGER_NAME_MAX];
	char                    et_units[LEDGER_NAME_MAX];
	ledger_entry_id_t       et_id;
	ledger_callback_t       et_callback;
	const void             *et_cb_param0;
} *ledger_entry_template_t;

typedef struct ledger_tab *ledger_tab_t;

struct ledger_template {
	const char             *lt_name;
	zone_t                  lt_zone;
	ledger_entry_template_t lt_entries;
	uint16_t                lt_cnt;
	uint16_t                lt_size;
	uint16_t                lt_counters;
	ledger_tab_t __zpercpu  lt_tabs;
	ledger_entry_id_t       lt_counter_lut[LEDGER_SCALABLE_MAX];
};


/*!
 * @abstract
 * Well known system ledgers.
 */
extern struct ledger_template coalition_ledger_template;
extern struct ledger_template coalition_task_ledger_template;
extern struct ledger_template task_ledger_template;
extern struct ledger_template thread_ledger_template;

/*!
 * @abstract
 * Defines a ledger template.
 *
 * @discussion
 * A ledger template will need to be further configured and finalized.
 * @see ledger_template_finalize().
 *
 * @param var           The name of the variable to define.
 * @param name          A human readable name for the ledger template.
 * @param entries       An array of ledger template entries for this template.
 */
#define LEDGER_TEMPLATE_DEFINE(var, name, entries) \
	SECURITY_READ_ONLY_LATE(struct ledger_template) var = {                 \
	        .lt_name        = name,                                         \
	        .lt_entries     = entries,                                      \
	        .lt_cnt         = ARRAY_COUNT(entries),                         \
	}

/*!
 * @abstract
 * Defines an empty ledger template.
 *
 * @discussion
 * Such a ledger template is meant to be used with @c ledger_template_copy().
 *
 * @param var           The name of the variable to define.
 * @param name          A human readable name for the ledger template.
 */
#define LEDGER_TEMPLATE_DEFINE_EMPTY(var, name) \
	SECURITY_READ_ONLY_LATE(struct ledger_template) var = {                 \
	        .lt_name        = name,                                         \
	}


/*!
 * @abstract
 * Defines a ledger entry template.
 *
 * @param key           The key name for this entry as a string,
 *                      (this must be a valid C identifier).
 * @param group         A string describing the domain of this key
 *                      (such as "sched", "power", ...)
 * @param units         A string defining the unit for this value
 *                      (such as "bytes", "ns", ...)
 * @param features      A set of @c ledger_features_t.
 */
#define LEDGER_ENTRY(key, group, units, features, ...) \
	{                                                                       \
	        .et_key         = key "\0",                                     \
	        .et_group       = group "\0",                                   \
	        .et_units       = units "\0",                                   \
	        .et_id          = __builtin_choose_expr(                        \
	            __ledger_features_valid(features), (features), "invalid"),  \
	        __VA_ARGS__                                                     \
	}
#define __ledger_features_valid(feat)  (\
	(((feat) & LFEAT_SCALABLE) == 0 || ((feat) & LFEAT_REFILL) == 0) && \
	(((feat) & LFEAT_MAXIMUM) == 0 || ((feat) & LFEAT_REFILL) == 0) && \
	1)

/*!
 * @abstract
 * Defines a ledger entry template (with callback).
 *
 * @param key           The key name for this entry as a string,
 *                      (this must be a valid C identifier).
 * @param group         A string describing the domain of this key
 *                      (such as "sched", "power", ...)
 * @param units         A string defining the unit for this value
 *                      (such as "bytes", "ns", ...)
 * @param features      A set of @c ledger_features_t.
 * @param cb            The callback to program.
 * @param p0            The first parameter to apss back to the callback.
 */
#define LEDGER_ENTRY_CALLBACK(key, group, units, features, cb, p0) \
	LEDGER_ENTRY(key, group, units, features, \
	    .et_callback = (cb), .et_cb_param0 = (p0))

/*!
 * @abstract
 * Macro used to build memoized indices from ledger name to index.
 *
 * @param ledger_tpl    A pointer to a finalized ledger template.
 * @param indices_var   The name of the memoizing structure.
 * @param field         The name of the field to memoize
 *                      (must match the memoized key name when stringified).
 */
#define LEDGER_KEY_MEMOIZE(ledger_tpl, indices_var, field) \
	indices_var.field = ledger_key_lookup(ledger_tpl, #field, true)


/*!
 * @abstract
 * Flags to ledger_template_finalize().
 *
 * @const LEDGER_TPL_NONE
 * No special behavior.
 *
 * @const LEDGER_TPL_SCALABLE
 * The ledger is accessed in a contended way and wants to enable LFEAT_SCALABLE
 * entries (otherwise this behavior is ignored).
 *
 * @const LEDGER_TPL_SECURE_ALLOC
 * On PPL, whether PPL takes over allocation.
 */
__options_closed_decl(ledger_tpl_options_t, uint32_t, {
	LEDGER_TPL_NONE         = 0x00,
	LEDGER_TPL_SCALABLE     = 0x01,
	LEDGER_TPL_SECURE_ALLOC = 0x02,
});

/*!
 * @abstract
 * Finalizes a ledger template after its entries have been configured.
 *
 * @discussion
 * Once a ledger template is finalized:
 * - it can't be configured further and becomes immutable;
 * - ledgers using it can be instantiated.
 *
 * @param ledger_tpl    The template to finalize.
 *                      It must reside in __DATA_CONST, so must its entries.
 * @param options       A combination of @c ledger_tpl_options_t flags.
 */
extern void ledger_template_finalize(
	ledger_template_t       ledger_tpl,
	ledger_tpl_options_t    options);

/*!
 * @abstract
 * Copy a finalized ledger into another template.
 *
 * @discussion
 * This is used to make a carbon copy of a ledger property wise but with
 * a different ledger template name, and it can't be scalable.
 *
 * @param ledger_tpl    The template to copy into.
 *                      It must reside in __DATA_CONST,
 *                      however the resulting entries might not.
 * @param base          The template to copy from.
 *                      It must reside in __DATA_CONST, so must its entries.
 */
extern void ledger_template_copy(
	ledger_template_t       ledger_tpl,
	ledger_template_t       base);

/*!
 * @abstract
 * Lookup a ledger entry template in a ledger template.
 *
 * @param ledger_tpl    The ledger template to search.
 * @param key           The key to lookup.
 * @param required      Whether finding the entry is required.
 *                      If @c required is true and the entry isn't found,
 *                      the function will panic.
 *
 * @returns
 * - LEDGER_ENTRY_INVALID if no entry was found,
 * - the entry ID for this key.
 */
extern ledger_entry_id_t ledger_key_lookup(
	ledger_template_t       ledger_tpl,
	const char             *key,
	bool                    required);

/*!
 * @abstract
 * Allocate a new template using the specified ledger template.
 *
 * @discussion
 * This function never fails.
 */
extern ledger_t ledger_instantiate(
	ledger_template_t       ledger_tpl);


/*!
 * @asbstract
 * Take a new reference on a specified ledger
 */
extern void ledger_reference(
	ledger_t                ledger);


/*!
 * @asbstract
 * Release a reference on the specified ledger.
 */
extern void ledger_dereference(
	ledger_t                ledger);


#pragma mark debit/credit

/*!
 * @abstract
 * Force the credit/debit of a ledger to be the recorded values.
 *
 * @param ledger        The specified ledger.
 * @param entry         The specified ledger entry.
 * @param credit        The amount to put in credit.
 * @param debit         The amount to put in debit.
 */
extern void ledger_reset(
	ledger_t                ledger,
	ledger_entry_id_t       entry,
	ledger_amount_t         credit,
	ledger_amount_t         debit);

/*!
 * @abstract
 * Credit an amount to a ledger entry.
 *
 * @param ledger        The specified ledger.
 * @param entry         The specified ledger entry.
 * @param amount        The amount to credit.
 */
extern void ledger_credit(
	ledger_t                ledger,
	ledger_entry_id_t       entry,
	ledger_amount_t         amount);

/*!
 * @abstract
 * Credit an amount to a ledger entry.
 *
 * @discussion
 * This function can only be called if preemption is disabled.
 *
 * This is useful for sequences of ledger updates when the entries
 * might be scalable, since updating LFEAT_SCALABLE entries requires
 * disabling preemption.
 *
 * @param ledger        The specified ledger.
 * @param entry         The specified ledger entry.
 * @param amount        The amount to credit.
 */
extern void ledger_credit_nopreempt(
	ledger_t                ledger,
	ledger_entry_id_t       entry,
	ledger_amount_t         amount);

/*!
 * @abstract
 * Credit an amount to a ledger entry.
 *
 * @discussion
 * This function can only be called by the scheduler (when @c current_thread()
 * is different from @c thread).
 *
 * @param thread        The thread selected.
 * @param ledger        The ledger to update.
 * @param entry         The specified ledger entry.
 * @param amount        The amount to credit.
 */
extern void ledger_credit_sched(
	thread_t                thread,
	ledger_t                ledger,
	ledger_entry_id_t       entry,
	ledger_amount_t         amount);

/*!
 * @abstract
 * Credit an amount to a scalable ledger entry.
 *
 * @discussion
 * This function can only be called if preemption is disabled.
 *
 * This function allows for bare metal performance for performance critical
 * code which knows it is updating scalable entries from a known template.
 *
 * @param tpl           @c ledger's template
 * @param ledger        The specified ledger.
 * @param entry         The specified ledger entry.
 * @param amount        The amount to credit.
 */
extern void ledger_credit_scalable(
	ledger_template_t       tpl,
	ledger_t                ledger,
	ledger_entry_id_t       entry,
	ledger_amount_t         amount);

/*!
 * @abstract
 * Debit an amount from a ledger entry.
 *
 * @param ledger        The specified ledger.
 * @param entry         The specified ledger entry.
 * @param amount        The amount to debit.
 */
extern void ledger_debit(
	ledger_t                ledger,
	ledger_entry_id_t       entry,
	ledger_amount_t         amount);

/*!
 * @abstract
 * Debit an amount from a ledger entry.
 *
 * @discussion
 * This function can only be called if preemption is disabled.
 *
 * This is useful for sequences of ledger updates when the entries
 * might be scalable, since updating LFEAT_SCALABLE entries requires
 * disabling preemption.
 *
 * @param ledger        The specified ledger.
 * @param entry         The specified ledger entry.
 * @param amount        The amount to credit.
 */
extern void ledger_debit_nopreempt(
	ledger_t                ledger,
	ledger_entry_id_t       entry,
	ledger_amount_t         amount);

/*!
 * @abstract
 * Debit an amount from a scalable ledger entry.
 *
 * @discussion
 * This function can only be called if preemption is disabled.
 *
 * This function allows for bare metal performance for performance critical
 * code which knows it is updating scalable entries from a known template.
 *
 * @param tpl           @c ledger's template
 * @param ledger        The specified ledger.
 * @param entry         The specified ledger entry.
 * @param amount        The amount to credit.
 */
extern void ledger_debit_scalable(
	ledger_template_t       tpl,
	ledger_t                ledger,
	ledger_entry_id_t       entry,
	ledger_amount_t         amount);

#if XNU_MONITOR

/*!
 * @abstract
 * Variant of ledger_credit_scalable() which is safe to call in PPL context.
 *
 * @discussion
 * This function can only be called if preemption is disabled.
 *
 * This function allows for bare metal performance for performance critical
 * code which knows it is updating scalable entries from a known template.
 *
 * ledger_propagate_ast_ppl() must be called once the caller has left PPL
 * context.
 *
 * @param tpl           @c ledger's template
 * @param ledger        The specified ledger.
 * @param entry         The specified ledger entry.
 * @param amount        The amount to credit.
 */
extern void ledger_credit_scalable_ppl(
	ledger_template_t       tpl,
	ledger_t                ledger,
	ledger_entry_id_t       entry,
	ledger_amount_t         amount);

/*!
 * @abstract
 * Variant of ledger_debit_scalable() which is safe to call in PPL context.
 *
 * @discussion
 * This function can only be called if preemption is disabled.
 *
 * This function allows for bare metal performance for performance critical
 * code which knows it is updating scalable entries from a known template.
 *
 * ledger_propagate_ast_ppl() must be called once the caller has left PPL
 * context.
 *
 * @param tpl           @c ledger's template
 * @param ledger        The specified ledger.
 * @param entry         The specified ledger entry.
 * @param amount        The amount to credit.
 */
extern void ledger_debit_scalable_ppl(
	ledger_template_t       tpl,
	ledger_t                ledger,
	ledger_entry_id_t       entry,
	ledger_amount_t         amount);

/*!
 * @abstract
 * Function to call when returning to regular context if
 * @c ledger_credit_scalable_ppl() or @c ledger_debit_scalable_ppl()
 * might have been called while in PPL context.
 */
extern void ledger_propagate_ast_ppl(void);

#endif /* XNU_MONITOR */

/*!
 * @abstract
 * Open a tab for the specified ledger on the current CPU.
 *
 * @discussion
 * This function must be called with preemption disabled.
 *
 * If a tab was open for a different ledger, it is settled and closed.
 * If a tab was already open for the same ledger, this function is a no-op.
 *
 * An open "tab" allows for faster credit/debit with the current CPU,
 * in order to avoid costly atomic updates on the global ledger.
 *
 * A CPU can only have a single open "tab" per ledger template,
 * and the ledger that has an open tab must remain valid while
 * it has an open tab. This function doesn't take a reference
 * to guarantee this for performance reasons.
 *
 * @note The current user of this API is the task/pmap ledger code
 *       which guarantees validity because the ledger is switched
 *       at the same time pmaps are switched.
 *
 * @param tpl           @c ledger's template
 * @param ledger        The new default scalable ledger for @c tpl.
 *                      @c ledger may be NULL in which case any open tab is
 *                      closed but no new tab is open.
 */
extern void ledger_tab_open(
	ledger_template_t       tpl,
	ledger_t                ledger);

/*!
 * @abstract
 * Forces a ledger to be settled.
 *
 * @discussion
 * A ledger can have several open tabs, which can cause its balances to be
 * imprecise. This function forces open tabs to be settled so that balances
 * are accurate.
 *
 * @param tpl           @c ledger's template.
 * @param ledger        The ledger to settle.
 * @param entry         Either @c LEDGER_ENTRY_ID_INVALID, or only settle
 *                      this entry.
 *
 * @note this function causes IPIs to be sent to any CPU for which @c ledger
 *       has an open tab.
 */
extern void ledger_tab_settle(
	ledger_template_t       tpl,
	ledger_t                ledger,
	ledger_entry_id_t       entry);

__attribute__((always_inline, overloadable))
static inline void
ledger_tab_settle(ledger_template_t tpl, ledger_t ledger)
{
	ledger_tab_settle(tpl, ledger, LEDGER_ENTRY_ID_INVALID);
}

/*!
 * @abstract
 * Forces a ledger template to be settled.
 *
 * @discussion
 * This function forces open tabs to be settled for a given template.
 *
 * @param tpl           @c ledger's template.
 */
extern void ledger_tab_settle_all(
	ledger_template_t       tpl);

/*!
 * @abstract
 * AST callback for AST_LEDGER.
 */
extern void ledger_ast(
	thread_t                thread);

/*!
 * @abstract
 * IPI callback for ledger_tab_settle().
 */
extern void ledger_tab_settle_ack_ipi(
	int                     cpu);


#pragma mark unsorted

/*!
 * @abstract
 * Options that alter behavior of @c ledger_get_{entries,balance} and
 * @c ledger_get_*_max() functions.
 *
 * @note One of LEO_SETTLE or LEO_NO_SETTLE must always be passed.
 *
 * @const LEO_SETTLE
 * Ask for the ledger entry to be settled prior to fetching the value
 * if applicable (this is a no-op if the entry isn't scalable).
 *
 * Do not that settling can lead to expensive behaviors scanning all CPUs
 * and causing IPIs, so it is preferred when doing a sequence of getters
 * to use interfaces like @c ledger_tab_settle() and use @c LEO_NO_SETTLE
 * instead to amortize cost.
 *
 * @const LEO_NO_SETTLE
 * Ask for the ledger entry to skip settling prior to fetching the value.
 *
 * It can be used either when a very precise value isn't required,
 * or when it is known to the caller that the entry is already settled
 * (for example because @c ledger_tab_settle() was used right before this call).
 *
 * @const LEO_RESET_INTERVAL_MAX
 * For the @c ledger_get_interval_max(), ask for the interval_max value to be
 * reset to the current balance as a side effect of the call.
 */
__options_decl(ledger_get_options_t, uint16_t, {
	LEO_SETTLE              = 0x0001,
	LEO_NO_SETTLE           = 0x0002,
	LEO_RESET_INTERVAL_MAX  = 0x0004, /* only ledger_get_interval_max() */
});

/* value of entry type */
extern kern_return_t ledger_disable_callback(ledger_t ledger, ledger_entry_id_t entry);
extern kern_return_t ledger_enable_callback(ledger_t ledger, ledger_entry_id_t entry);
extern kern_return_t ledger_get_limit(ledger_t ledger, ledger_entry_id_t entry,
    ledger_amount_t *limit);
extern kern_return_t ledger_set_limit(ledger_t ledger, ledger_entry_id_t entry,
    ledger_amount_t limit, uint8_t warn_level_percentage);
extern kern_return_t ledger_get_interval_max(ledger_t ledger, ledger_entry_id_t entry,
    ledger_get_options_t options, ledger_amount_t *max_interval_balance);
extern kern_return_t ledger_get_lifetime_max(ledger_t ledger, ledger_entry_id_t entry,
    ledger_get_options_t options, ledger_amount_t *max_lifetime_balance);
extern kern_return_t ledger_get_actions(ledger_t ledger, ledger_entry_id_t entry, int *actions);
extern kern_return_t ledger_set_blocking(ledger_t ledger, ledger_entry_id_t entry);
extern kern_return_t ledger_get_period(ledger_t ledger, ledger_entry_id_t entry,
    uint64_t *period);
extern kern_return_t ledger_set_period(ledger_t ledger, ledger_entry_id_t entry,
    uint64_t period);
extern kern_return_t ledger_disable_refill(ledger_t l, ledger_entry_id_t entry);
extern void ledger_check_new_balance(ledger_t ledger, ledger_entry_id_t entry);
extern kern_return_t ledger_get_entries(ledger_t ledger, ledger_entry_id_t entry,
    ledger_get_options_t options, ledger_amount_t *credit, ledger_amount_t *debit);
extern kern_return_t ledger_get_balance(ledger_t ledger, ledger_entry_id_t entry,
    ledger_get_options_t options, ledger_amount_t *balance);
extern kern_return_t ledger_disable_panic_on_negative(ledger_t ledger, ledger_entry_id_t entry);
extern kern_return_t ledger_get_panic_on_negative(ledger_t ledger, ledger_entry_id_t entry, int *panic_on_negative);

extern kern_return_t ledger_rollup(ledger_t to_ledger, ledger_t from_ledger);
extern kern_return_t ledger_rollup_entry(ledger_t to_ledger, ledger_t from_ledger, ledger_entry_id_t entry);

extern ledger_amount_t ledger_get_remaining(ledger_t ledger, ledger_entry_id_t entry);
extern void ledger_restart(ledger_t ledger, ledger_entry_id_t entry, uint64_t now);
extern uint64_t ledger_get_interval_remaining(ledger_t ledger, ledger_entry_id_t entry, uint64_t now);

extern void
ledger_get_entry_info(ledger_t ledger, ledger_entry_id_t entry,
    struct ledger_entry_info *lei);

#if LEDGER_HAS_FEAT_DIAG

extern kern_return_t ledger_get_diag_mem_threshold(ledger_t ledger, ledger_entry_id_t entry,
    ledger_amount_t *limit);

extern kern_return_t ledger_set_diag_mem_threshold(ledger_t ledger, ledger_entry_id_t entry,
    ledger_amount_t limit);
extern kern_return_t ledger_set_diag_mem_threshold_disabled(ledger_t ledger, ledger_entry_id_t entry);
extern kern_return_t ledger_set_diag_mem_threshold_enabled(ledger_t ledger, ledger_entry_id_t entry);
extern kern_return_t ledger_is_diag_threshold_enabled(ledger_t ledger, ledger_entry_id_t entry, bool *status);

#endif /* LEDGER_HAS_FEAT_DIAG */
#endif /* MACH_KERNEL_PRIVATE */
#if XNU_KERNEL_PRIVATE

/*
 * Support for the ledger() syscall
 */

extern int ledger_info(task_t task, struct ledger_info *info);

extern int ledger_get_task_entry_info_multiple(task_t task, void **buf, int *len, bool v2);

extern int ledger_template_info(void **buf, int *len);

#endif /* XNU_KERNEL_PRIVATE */

__END_DECLS

#endif  /* _KERN_LEDGER_H_ */
