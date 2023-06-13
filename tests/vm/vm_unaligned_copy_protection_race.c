#include <darwintest.h>
#include <darwintest_utils.h>

#include <mach/mach_init.h>
#include <mach/vm_map.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"));

struct context1 {
	vm_size_t obj_size;
	vm_address_t e0;
	dispatch_semaphore_t running_sem;
	pthread_mutex_t mtx;
	bool done;
};

static void *
protect_thread(__unused void *arg)
{
	kern_return_t kr;
	struct context1 *ctx;

	ctx = (struct context1 *)arg;
	/* tell main thread we're ready to run */
	dispatch_semaphore_signal(ctx->running_sem);
	while (!ctx->done) {
		/* wait for main thread to be done setting things up */
		pthread_mutex_lock(&ctx->mtx);
		/* make 2nd target mapping (e0) read-only */
		kr = vm_protect(mach_task_self(),
		    ctx->e0,
		    ctx->obj_size,
		    FALSE,             /* set_maximum */
		    VM_PROT_READ);
		T_QUIET; T_EXPECT_MACH_SUCCESS(kr, " vm_protect() RO");
		/* wait a little bit */
		usleep(100);
		/* make it read-write again */
		kr = vm_protect(mach_task_self(),
		    ctx->e0,
		    ctx->obj_size,
		    FALSE,             /* set_maximum */
		    VM_PROT_READ | VM_PROT_WRITE);
		T_QUIET; T_EXPECT_MACH_SUCCESS(kr, " vm_protect() RW");
		/* tell main thread we're done changing protections */
		pthread_mutex_unlock(&ctx->mtx);
		usleep(100);
	}
	return NULL;
}

T_DECL(unaligned_write_to_cow_bypass,
    "Test that unaligned copy respects COW")
{
	pthread_t th = NULL;
	int ret;
	kern_return_t kr;
	time_t start, duration;
	mach_msg_type_number_t cow_read_size;
	vm_size_t copied_size;
	int loops;
	vm_address_t e1, e2, e5;
	struct context1 context1, *ctx;
	int kern_success = 0, kern_protection_failure = 0, kern_other = 0;

	ctx = &context1;
	ctx->obj_size = 256 * 1024;
	ctx->e0 = 0;
	ctx->running_sem = dispatch_semaphore_create(0);
	T_QUIET; T_ASSERT_NE(ctx->running_sem, NULL, "dispatch_semaphore_create");
	ret = pthread_mutex_init(&ctx->mtx, NULL);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "pthread_mutex_init");
	ctx->done = false;

	pthread_mutex_lock(&ctx->mtx);

	/* start racing thread */
	ret = pthread_create(&th, NULL, protect_thread, (void *)ctx);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "pthread_create");

	/* wait for racing thread to be ready to run */
	dispatch_semaphore_wait(ctx->running_sem, DISPATCH_TIME_FOREVER);

	duration = 10; /* 10 seconds */
	T_LOG("Testing for %ld seconds...", duration);
	for (start = time(NULL), loops = 0;
	    time(NULL) < start + duration;
	    loops++) {
		/* reserve space for our 2 contiguous allocations */
		e2 = 0;
		kr = vm_allocate(mach_task_self(),
		    &e2,
		    2 * ctx->obj_size,
		    VM_FLAGS_ANYWHERE);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_allocate to reserve e2+e0");

		/* make 1st allocation in our reserved space */
		kr = vm_allocate(mach_task_self(),
		    &e2,
		    ctx->obj_size,
		    VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE | VM_MAKE_TAG(240));
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_allocate e2");
		/* initialize to 'B' */
		memset((char *)e2, 'B', ctx->obj_size);

		/* make 2nd allocation in our reserved space */
		ctx->e0 = e2 + ctx->obj_size;
		kr = vm_allocate(mach_task_self(),
		    &ctx->e0,
		    ctx->obj_size,
		    VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE | VM_MAKE_TAG(241));
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_allocate e0");
		memset((char *)ctx->e0, 'A', ctx->obj_size);
		/* initialize to 'A' */

		/* make a COW copy of e0 */
		e1 = 0;
		kr = vm_read(mach_task_self(),
		    ctx->e0,
		    ctx->obj_size,
		    &e1,
		    &cow_read_size);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_read e0->e1");

		/* allocate a source buffer */
		kr = vm_allocate(mach_task_self(),
		    &e5,
		    ctx->obj_size,
		    VM_FLAGS_ANYWHERE);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_allocate e5");
		/* initialize to 'C' */
		memset((char *)e5, 'C', ctx->obj_size);

		/* let the racing thread go */
		pthread_mutex_unlock(&ctx->mtx);

		/* trigger copy_unaligned while racing with other thread */
		kr = vm_read_overwrite(mach_task_self(),
		    e5,
		    ctx->obj_size,
		    e2 + 1,
		    &copied_size);
		T_QUIET; T_ASSERT_TRUE(kr == KERN_SUCCESS || kr == KERN_PROTECTION_FAILURE,
		    "vm_read_overwrite kr %d", kr);
		switch (kr) {
		case KERN_SUCCESS:
			/* the target as RW */
			kern_success++;
			break;
		case KERN_PROTECTION_FAILURE:
			/* the target was RO */
			kern_protection_failure++;
			break;
		default:
			/* should not happen */
			kern_other++;
			break;
		}

		/* check that the COW copy of e0 (at e1) was not modified */
		T_QUIET; T_ASSERT_EQ(*(char *)e1, 'A', "COW mapping was modified");

		/* tell racing thread to stop toggling protections */
		pthread_mutex_lock(&ctx->mtx);

		/* clean up before next loop */
		vm_deallocate(mach_task_self(), ctx->e0, ctx->obj_size);
		ctx->e0 = 0;
		vm_deallocate(mach_task_self(), e1, ctx->obj_size);
		e1 = 0;
		vm_deallocate(mach_task_self(), e2, ctx->obj_size);
		e2 = 0;
		vm_deallocate(mach_task_self(), e5, ctx->obj_size);
		e5 = 0;
	}

	ctx->done = true;
	pthread_join(th, NULL);

	T_LOG("vm_read_overwrite: KERN_SUCCESS:%d KERN_PROTECTION_FAILURE:%d other:%d",
	    kern_success, kern_protection_failure, kern_other);
	T_PASS("Ran %d times in %ld seconds with no failure", loops, duration);
}
