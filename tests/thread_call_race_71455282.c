#include <darwintest.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/mk_timer.h>
#include <mach/task.h>

#define die(w) errx(1, (w))
#define edie(w) err(1, (w))
#define expect(e) if (-1 == (e)) edie(#e)

static void *
racer(void *data)
{
	for (;;) {
		mk_timer_destroy(*(mach_port_t *)data);
	}

	return NULL;
}

T_DECL(thread_call_race_71455282,
    "rdar://71455282",
    T_META_IGNORECRASHES(".*thread_call_race_71455282.*"))
{
	mach_port_t timer = MACH_PORT_NULL;
	pthread_t t;
	size_t n;
	kern_return_t kr;

	/* ensure we pass can at least create and destroy a timer once */
	timer = mk_timer_create();
	kr = mk_timer_arm(timer, 1);
	T_ASSERT_MACH_SUCCESS(kr, "timer arm");
	kr = mk_timer_destroy(timer);
	T_ASSERT_MACH_SUCCESS(kr, "timer destroy");
	timer = MACH_PORT_NULL;

	/* we will violate mach rules so ignore crashes here */
	T_ASSERT_MACH_SUCCESS(task_set_exc_guard_behavior(mach_task_self(), 0),
	    "task_set_exc_guard_behavior");

	for (n = 0; n < 4; ++n) {
		T_ASSERT_POSIX_SUCCESS(pthread_create(&t, NULL, racer, &timer),
		    "pthread_create");
	}

	T_LOG("racing");
	for (size_t i = 0; i < 1000; i++) {
		timer = mk_timer_create();
		kr = mk_timer_arm(timer, 1);
		kr = mk_timer_destroy(timer);
		timer = MACH_PORT_NULL;
	}

	T_PASS("didn't panic");
	T_END;
}
