#include <mach_ldebug.h>
#include <debug.h>

#include <mach/kern_return.h>
#include <mach/mach_host_server.h>
#include <mach_debug/lockgroup_info.h>

#include <os/atomic.h>

#include <kern/locks.h>
#include <kern/smr_hash.h>
#include <kern/misc_protos.h>
#include <kern/kalloc.h>
#include <kern/thread.h>
#include <kern/processor.h>
#include <kern/sched_prim.h>
#include <kern/debug.h>
#include <libkern/section_keywords.h>
#include <machine/atomic.h>
#include <machine/machine_cpu.h>
#include <machine/atomic.h>
#include <string.h>
#include <kern/kalloc.h>

#include <sys/kdebug.h>
#include <sys/errno.h>

#if SCHED_HYGIENE_DEBUG
static uint64_t
sane_us2abs(uint64_t us)
{
	uint64_t t;
	nanoseconds_to_absolutetime(us * NSEC_PER_USEC, &t);
	return t;
}
#endif

#if !KASAN
static void
hw_lck_ticket_test_wait_for_delta(hw_lck_ticket_t *lck, uint8_t delta, int msec)
{
	hw_lck_ticket_t tmp;

	delta *= HW_LCK_TICKET_LOCK_INCREMENT;
	for (int i = 0; i < msec * 1000; i++) {
		tmp.lck_value = os_atomic_load(&lck->lck_value, relaxed);
#if CONFIG_PV_TICKET
		const uint8_t cticket = tmp.cticket &
		    ~HW_LCK_TICKET_LOCK_PVWAITFLAG;
#else
		const uint8_t cticket = tmp.cticket;
#endif
		if ((uint8_t)(tmp.nticket - cticket) == delta) {
			return;
		}
		delay(1);
	}
	assert(false);
}

__dead2
static void
hw_lck_ticket_allow_invalid_worker(void *arg, wait_result_t __unused wr)
{
	hw_lck_ticket_t *lck = arg;
	hw_lock_status_t rc;

	/* wait until we can observe the test take the lock */
	hw_lck_ticket_test_wait_for_delta(lck, 1, 10);

	rc = hw_lck_ticket_lock_allow_invalid(lck,
	    &hw_lock_test_give_up_policy, NULL);
	assert(rc == HW_LOCK_INVALID); // because the other thread invalidated it
	assert(preemption_enabled());

	thread_terminate_self();
	__builtin_unreachable();
}
#endif /* !KASAN */

static int
hw_lck_ticket_allow_invalid_test(__unused int64_t in, int64_t *out)
{
	vm_offset_t addr = 0;
	hw_lck_ticket_t *lck;
	kern_return_t kr;
	hw_lock_status_t rc;

	printf("%s: STARTING\n", __func__);

	kr = kmem_alloc(kernel_map, &addr, PAGE_SIZE,
	    KMA_ZERO | KMA_KOBJECT, VM_KERN_MEMORY_DIAG);
	if (kr != KERN_SUCCESS) {
		printf("%s: kma failed (%d)\n", __func__, kr);
		return ENOMEM;
	}

	lck = (hw_lck_ticket_t *)addr;
	rc = hw_lck_ticket_lock_allow_invalid(lck,
	    &hw_lock_test_give_up_policy, NULL);
	assert(rc == HW_LOCK_INVALID); // because the lock is 0
	assert(preemption_enabled());

	hw_lck_ticket_init(lck, NULL);

	assert(hw_lck_ticket_lock_try(lck, NULL));
	assert(!hw_lck_ticket_lock_try(lck, NULL));
	hw_lck_ticket_unlock(lck);

	rc = hw_lck_ticket_lock_allow_invalid(lck,
	    &hw_lock_test_give_up_policy, NULL);
	assert(rc == HW_LOCK_ACQUIRED); // because the lock is initialized
	assert(!preemption_enabled());

#if SCHED_HYGIENE_DEBUG
	if (os_atomic_load(&sched_preemption_disable_threshold_mt, relaxed) < sane_us2abs(20 * 1000)) {
		/*
		 * This test currently relies on timeouts that cannot always
		 * be guaranteed (rdar://84691107). Abandon the measurement if
		 * we have a tight timeout.
		 */
		abandon_preemption_disable_measurement();
	}
#endif

	hw_lck_ticket_unlock(lck);
	assert(preemption_enabled());

#if !KASAN
	thread_t th;

	kr = kernel_thread_start_priority(hw_lck_ticket_allow_invalid_worker, lck,
	    BASEPRI_KERNEL, &th);
	assert(kr == KERN_SUCCESS);
	thread_deallocate(th);

	/* invalidate the lock */
	hw_lck_ticket_lock(lck, NULL);

	/* wait for the worker thread to take the reservation */
	hw_lck_ticket_test_wait_for_delta(lck, 2, 20);
	hw_lck_ticket_invalidate(lck);
	hw_lck_ticket_unlock(lck);
	hw_lck_ticket_destroy(lck, NULL);

	hw_lck_ticket_init(lck, NULL);
#endif /* !KASAN */

	kernel_memory_depopulate(addr, PAGE_SIZE, KMA_KOBJECT,
	    VM_KERN_MEMORY_DIAG);

	rc = hw_lck_ticket_lock_allow_invalid(lck,
	    &hw_lock_test_give_up_policy, NULL);
	assert(rc == HW_LOCK_INVALID); // because the memory is unmapped

	kmem_free(kernel_map, addr, PAGE_SIZE);

	printf("%s: SUCCESS\n", __func__);

	*out = 1;
	return 0;
}
SYSCTL_TEST_REGISTER(hw_lck_ticket_allow_invalid, hw_lck_ticket_allow_invalid_test);


struct smrh_elem {
	struct smrq_slink link;
	uintptr_t         val;
};

static bool
smrh_elem_try_get(void *arg __unused)
{
	return true;
}

SMRH_TRAITS_DEFINE_SCALAR(smrh_test_traits, struct smrh_elem, val, link,
    .domain      = &smr_system,
    .obj_try_get = smrh_elem_try_get);

LCK_GRP_DECLARE(smrh_test_grp, "foo");
LCK_MTX_DECLARE(smrh_test_lck, &smrh_test_grp);

static int
smr_hash_basic_test(__unused int64_t in, int64_t *out)
{
	__auto_type T = &smrh_test_traits;
	const size_t nelems = 64;
	struct smrh_elem e_buf[nelems];
	struct smr_hash h_buf;

	struct smrh_elem *elems = e_buf;
	struct smr_hash *h = &h_buf;

	__auto_type check_content = ^{
		struct smrh_elem *e;
		smrh_key_t key;
		bool seen[nelems] = { };

		assert3u(h->smrh_count, ==, nelems / 2);

		for (int i = 0; i < nelems / 2; i++) {
			key = SMRH_SCALAR_KEY(elems[i].val);
			assert(smr_hash_entered_find(h, key, T));

			key = SMRH_SCALAR_KEY(elems[i + nelems / 2].val);
			assert(!smr_hash_entered_find(h, key, T));
		}

		smr_hash_foreach(e, h, T) {
			for (int i = 0; i < nelems / 2; i++) {
				if (e->val == elems[i].val) {
					assert(!seen[i]);
					seen[i] = true;
					break;
				}
			}
		}

		for (int i = 0; i < nelems / 2; i++) {
			assert(seen[i]);
		}
	};

	printf("%s: STARTING\n", __func__);

	smr_hash_init(h, 4);

	printf("%s: populating the hash with unique entries\n", __func__);

	uintptr_t base = early_random();
	for (size_t i = 0; i < nelems; i++) {
		elems[i].val = base + (uint16_t)early_random() + 1;
		base = elems[i].val;
	}

	for (int i = 0; i < nelems / 2; i++) {
		smr_hash_serialized_insert(h, &elems[i].link, T);
	}
	check_content();

	static bool progression[4] = {
		1, 1, 0, 0,
	};

	for (int step = 0; step < ARRAY_COUNT(progression); step++) {
		if (progression[step]) {
			printf("%s: growing the hash\n", __func__);
			lck_mtx_lock(&smrh_test_lck);
			smr_hash_grow_and_unlock(h, &smrh_test_lck, T);
		} else {
			printf("%s: shrinking the hash\n", __func__);
			lck_mtx_lock(&smrh_test_lck);
			smr_hash_shrink_and_unlock(h, &smrh_test_lck, T);
		}
		check_content();
	}

	printf("%s: destroying the hash\n", __func__);
	smr_hash_destroy(h);

	printf("%s: SUCCESS\n", __func__);

	*out = 1;
	return 0;
}
SYSCTL_TEST_REGISTER(smr_hash_basic, smr_hash_basic_test);

static int
smr_shash_basic_test(__unused int64_t in, int64_t *out)
{
	__auto_type T = &smrh_test_traits;
	const size_t nelems = 8192;
	const size_t never  =  512; /* never inserted elements */
	struct smr_shash h_buf;

	struct smrh_elem *elems;
	struct smr_shash *h = &h_buf;

	elems = kalloc_type(struct smrh_elem, nelems, Z_WAITOK | Z_ZERO);
	if (elems == 0) {
		return ENOMEM;
	}

	__auto_type check_content = ^(size_t max_inserted){
		smrh_key_t key;
		size_t n = 0;

		assert3u(counter_load(&h->smrsh_count), ==, max_inserted);

		smrht_enter(T);

		for (size_t i = 0; i < nelems; i++, n++) {
			if (n > 0 && n % 32 == 0) {
				smrht_leave(T);
				smrht_enter(T);
			}
			key = SMRH_SCALAR_KEY(elems[i].val);
			if (i < max_inserted) {
				assert(smr_shash_entered_find(h, key, T));
			} else {
				assert(!smr_shash_entered_find(h, key, T));
			}
		}

		smrht_leave(T);
	};

	printf("%s: STARTING\n", __func__);

	smr_shash_init(h, SMRSH_COMPACT, 8);

	printf("%s: populating the hash with unique entries\n", __func__);

	uintptr_t base = early_random();
	for (size_t i = 0; i < nelems; i++) {
		elems[i].val = base + (uint32_t)early_random();
		base = elems[i].val;
	}

	printf("%s: insert into the hash, triggering several resizes\n", __func__);

	for (size_t i = 0; i < nelems - never; i++) {
		smrh_key_t key = SMRH_SCALAR_KEY(elems[i].val);
		struct smrh_elem *dupe;

		if (i > 0 && i % 32 == 0) {
			check_content(i);
		}

		dupe = smr_shash_get_or_insert(h, key, &elems[i].link, T);
		assert(dupe == NULL);
	}
	check_content(nelems - never);

	printf("%s: remove from the hash, triggering several resizes\n", __func__);

	for (size_t i = nelems - never; i-- > 0;) {
		smr_shash_remove(h, &elems[i].link, T);

		if (i % 32 == 0) {
			check_content(i);
		}
	}

	printf("%s: destroying the hash\n", __func__);
	smr_shash_destroy(h, T, NULL);

	printf("%s: SUCCESS\n", __func__);

	kfree_type(struct smrh_elem, nelems, elems);

	*out = 1;
	return 0;
}
SYSCTL_TEST_REGISTER(smr_shash_basic, smr_shash_basic_test);

struct smr_ctx {
	thread_t        driver;
	smr_t           smr;
	uint32_t        active;
	uint32_t        idx;
	uint64_t        deadline;
	uint32_t        calls_sent;
	uint32_t        calls_done;
	uint32_t        syncs_done;
	uint32_t        barriers_done;
};

struct smr_call_ctx {
	struct smr_node node;
	struct smr_ctx *ctx;
};

static void
smr_sleepable_stress_cb(smr_node_t node)
{
	struct smr_call_ctx *cctx;

	cctx = __container_of(node, struct smr_call_ctx, node);
	os_atomic_inc(&cctx->ctx->calls_done, relaxed);

	kfree_type(struct smr_call_ctx, cctx);
}

static void
smr_sleepable_stress_make_call(struct smr_ctx *ctx)
{
	struct smr_call_ctx *cctx;

	cctx = kalloc_type(struct smr_call_ctx, Z_WAITOK);
	cctx->ctx = ctx;
	os_atomic_inc(&ctx->calls_sent, relaxed);
	smr_call(ctx->smr, &cctx->node, sizeof(*cctx), smr_sleepable_stress_cb);
}

static void
smr_sleepable_stress_log(struct smr_ctx *ctx, uint64_t n)
{
	printf("%s[%lld]: "
	    "%d/%d calls, %d syncs, %d barriers, "
	    "rd-seq: %ld, wr-seq: %ld\n",
	    __func__, n,
	    ctx->calls_done, ctx->calls_sent,
	    ctx->syncs_done,
	    ctx->barriers_done,
	    ctx->smr->smr_clock.s_rd_seq / SMR_SEQ_INC,
	    ctx->smr->smr_clock.s_wr_seq / SMR_SEQ_INC);
}

static uint32_t
smr_sleepable_stress_idx(struct smr_ctx *ctx, thread_t self)
{
	if (ctx->driver == self) {
		return 0;
	}
	return os_atomic_inc(&ctx->idx, relaxed);
}


static void
smr_sleepable_stress_worker(void *arg, wait_result_t wr __unused)
{
	thread_t self = current_thread();
	struct smr_ctx *ctx = arg;
	smr_t smr = ctx->smr;

	const uint64_t step = NSEC_PER_SEC / 4;
	const uint64_t start = mach_absolute_time();
	const uint32_t idx = smr_sleepable_stress_idx(ctx, self);

	uint64_t now, delta, last = 0;

	printf("%s: thread %p starting\n", __func__, self);

	while ((now = mach_absolute_time()) < ctx->deadline) {
		struct smr_tracker smrt;
		uint64_t what;

		if (idx == 0) {
			absolutetime_to_nanoseconds(now - start, &delta);
			if (delta >= (last + 1) * step) {
				last = delta / step;
				smr_sleepable_stress_log(ctx, last);
			}
		}

		smr_enter_sleepable(smr, &smrt);
		assert(smr_entered(smr));

		what = early_random() % 100;
		if (what == 0 && idx == 1) {
			/* 1% of the time, sleep for a long time */
			delay_for_interval(1, NSEC_PER_MSEC);
		} else if (what < 10) {
			/* 9% of the time, just yield */
			thread_block_reason(THREAD_CONTINUE_NULL, NULL, AST_YIELD);
		} else if (what < 30) {
			/* 20% of the time, do some longer work on core */
			uint64_t busy_start = mach_absolute_time();

			do {
				now = mach_absolute_time();
				absolutetime_to_nanoseconds(now - busy_start, &delta);
			} while (delta < (what + 50) * NSEC_PER_USEC);
		}

		assert(smr_entered(smr));
		smr_leave_sleepable(smr, &smrt);

		what = early_random() % 100;
		if (what < 20) {
			/* smr_call 20% of the time */
			smr_sleepable_stress_make_call(ctx);
		} else if (what < 22 && (idx & 1)) {
			/* smr_synchronize 2% of the time for half the threads */
			smr_synchronize(smr);
			os_atomic_inc(&ctx->syncs_done, relaxed);
		} else if (what < 23 && (idx & 1)) {
			/* smr_barrier 1% of the time for half the threads */
			smr_barrier(smr);
			os_atomic_inc(&ctx->barriers_done, relaxed);
		}
	}

	printf("%s: thread %p done\n", __func__, self);

	if (idx != 0) {
		if (os_atomic_dec(&ctx->active, relaxed) == 0) {
			thread_wakeup(ctx);
		}

		thread_terminate_self();
		__builtin_unreachable();
	}
}

static int
smr_sleepable_stress_test(int64_t seconds, int64_t *out)
{
	thread_pri_floor_t token;
	struct smr_ctx ctx = { };
	thread_t th;

	if (seconds > 60) {
		return EINVAL;
	}

	printf("%s: STARTING\n", __func__);

	ctx.active = zpercpu_count() * 2; /* overcommit the system on purpose */
	ctx.driver = current_thread();
	ctx.smr    = smr_domain_create(SMR_SLEEPABLE, "test (sleepable)");
	assert3p(ctx.smr, !=, NULL);

	clock_interval_to_deadline((uint32_t)seconds, NSEC_PER_SEC, &ctx.deadline);

	/*
	 * We will relatively massively hammer the system,
	 * stay above that crowd.
	 */
	token = thread_priority_floor_start();

	for (uint32_t i = 1; i < ctx.active; i++) {
		kernel_thread_start_priority(smr_sleepable_stress_worker,
		    &ctx, BASEPRI_DEFAULT, &th);
		thread_deallocate(th);
	}

	smr_sleepable_stress_worker(&ctx, THREAD_AWAKENED);

	thread_priority_floor_end(&token);

	assert_wait(&ctx, THREAD_UNINT);
	if (os_atomic_dec(&ctx.active, relaxed) == 0) {
		clear_wait(ctx.driver, THREAD_AWAKENED);
	} else {
		thread_block(THREAD_CONTINUE_NULL);
	}

	smr_barrier(ctx.smr); /* to get accurate stats */
	smr_sleepable_stress_log(&ctx, seconds * 4);
	smr_domain_free(ctx.smr);

	assert3u(ctx.calls_done, ==, ctx.calls_sent);

	printf("%s: SUCCESS\n", __func__);

	*out = 1;
	return 0;
}
SYSCTL_TEST_REGISTER(smr_sleepable_stress, smr_sleepable_stress_test);
