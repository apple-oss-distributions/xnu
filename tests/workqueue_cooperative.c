#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <mach/mach_time.h>
#include <pthread.h>

#include <pthread/tsd_private.h>
#include <pthread/qos_private.h>

#include <dispatch/dispatch.h>
#include <dispatch/private.h>
#include <darwintest.h>
#include <pthread/workqueue_private.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.workq"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("workq"),
	T_META_RUN_CONCURRENTLY(true));

static mach_timebase_info_data_t timebase_info;

static uint64_t
nanos_to_abs(uint64_t nanos)
{
	return nanos * timebase_info.denom / timebase_info.numer;
}

static void
spin_for_duration(uint32_t seconds)
{
	kern_return_t kr = mach_timebase_info(&timebase_info);
	assert(kr == KERN_SUCCESS);

	uint64_t duration       = nanos_to_abs((uint64_t)seconds * NSEC_PER_SEC);
	uint64_t current_time   = mach_absolute_time();
	uint64_t timeout        = duration + current_time;

	uint64_t spin_count = 0;

	while (mach_absolute_time() < timeout) {
		spin_count++;
	}
	return;
}

T_DECL(cooperative_workqueue_and_vfork, "rdar://74489806") {
	dispatch_queue_t dq = dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0);
	T_ASSERT_NE(dq, NULL, "global_queue");

	dispatch_async(dq, ^{
		/* We are a workqueue non-overcommit thread, we should be getting a
		 * quantum */
		spin_for_duration(1);

		pid_t child;
		if ((child = vfork()) == 0) {
		        usleep(100);
		        spin_for_duration(1);
		        _exit(0);
		}

		int status;
		waitpid(child, &status, 0);
		T_ASSERT_EQ(status, 0, "child status");

		T_END;
	});

	dispatch_main();
}

T_DECL(adjust_quantum_nonovercommit_to_overcommit_switch, "rdar://75084197")
{
	dispatch_queue_t dq = dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0);
	T_ASSERT_NE(dq, NULL, "global_queue");

	dispatch_async(dq, ^{
		/* We are a workqueue non-overcommit thread, we should be getting a
		 * quantum that we expire here */
		spin_for_duration(1);

		/* Should not panic when we switch to overcommit */
		pthread_priority_t overcommit = (pthread_priority_t)_pthread_getspecific_direct(_PTHREAD_TSD_SLOT_PTHREAD_QOS_CLASS) |
		_PTHREAD_PRIORITY_OVERCOMMIT_FLAG;
		T_ASSERT_POSIX_ZERO(_pthread_set_properties_self(_PTHREAD_SET_SELF_QOS_FLAG, overcommit, 0), NULL);

		T_END;
	});

	dispatch_main();
}

T_DECL(cooperative_to_overcommit_switch, "Switching from cooperative queue to another type should not panic")
{
	dispatch_queue_t cooperative_dq = dispatch_get_global_queue(QOS_CLASS_UTILITY, DISPATCH_QUEUE_COOPERATIVE);
	T_ASSERT_NE(cooperative_dq, NULL, "global_queue");

	dispatch_queue_attr_t attr = dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL_WITH_AUTORELEASE_POOL, QOS_CLASS_USER_INITIATED, 0);
	dispatch_queue_t dq = dispatch_queue_create("serial IN overcommit queue", attr);

	dispatch_async(cooperative_dq, ^{
		spin_for_duration(1);

		dispatch_async_and_wait(dq, ^{
			spin_for_duration(1);
		});

		dispatch_release(dq);
		T_END;
	});

	dispatch_main();
}

T_DECL(maintenance_bg_coalesced, "BG and MT coalescing should work")
{
	dispatch_queue_t dq = dispatch_get_global_queue(QOS_CLASS_MAINTENANCE, DISPATCH_QUEUE_COOPERATIVE);
	T_ASSERT_NE(dq, NULL, "global_queue");
	dispatch_group_t dg = dispatch_group_create();

	dispatch_group_async(dg, dq, ^{
		spin_for_duration(1);
	});

	dispatch_group_wait(dg, DISPATCH_TIME_FOREVER);
	dispatch_release(dg);
}
