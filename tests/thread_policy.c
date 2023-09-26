#include <darwintest.h>
#include <mach/thread_policy_private.h>
#include <mach/mach.h>
#include <dispatch/dispatch.h>
#include <sys/qos_private.h>

static qos_class_t
thread_qos_to_qos_class(uint32_t thread_qos)
{
	switch (thread_qos) {
	case THREAD_QOS_MAINTENANCE:
		return QOS_CLASS_MAINTENANCE;
	case THREAD_QOS_BACKGROUND:
		return QOS_CLASS_BACKGROUND;
	case THREAD_QOS_UTILITY:
		return QOS_CLASS_UTILITY;
	case THREAD_QOS_LEGACY:
		return QOS_CLASS_DEFAULT;
	case THREAD_QOS_USER_INITIATED:
		return QOS_CLASS_USER_INITIATED;
	case THREAD_QOS_USER_INTERACTIVE:
		return QOS_CLASS_USER_INTERACTIVE;
	default:
		return QOS_CLASS_UNSPECIFIED;
	}
}

static qos_class_t
get_thread_requested_qos(void)
{
	mach_msg_type_number_t count = THREAD_REQUESTED_STATE_POLICY_COUNT;
	struct thread_requested_qos_policy requested_policy;
	boolean_t get_default = FALSE;
	mach_port_t thread_port = pthread_mach_thread_np(pthread_self());

	kern_return_t kr = thread_policy_get(thread_port, THREAD_REQUESTED_STATE_POLICY,
	    (thread_policy_t)&requested_policy, &count, &get_default);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "thread_policy_get");

	return thread_qos_to_qos_class(requested_policy.thrq_base_qos);
}

T_DECL(thread_policy_requested_state, "THREAD_REQUESTED_STATE_POLICY", T_META_ASROOT(NO))
{
	qos_class_t main_thread_qos = get_thread_requested_qos();
	T_ASSERT_EQ(main_thread_qos, qos_class_main(), "main thead requested qos matches");
}
