#include <darwintest.h>
#include <darwintest_utils.h>

#include <mach/mach.h>
#include <mach/mach_types.h>
#include <mach/mach_port.h>
#include <mach/message.h>
#include <mach/mach_error.h>


T_GLOBAL_META(
	T_META_NAMESPACE("xnu.ipc"),
	T_META_RUN_CONCURRENTLY(TRUE),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("IPC"));

T_DECL(mach_port_peek, "Test mach port peeking")
{
	mach_port_t port;
	kern_return_t kr;
	struct msg {
		mach_msg_header_t header;
		char data[512];
		char trailer[128];
	} msg;

	mach_msg_id_t outgoing_id;
	mach_msg_size_t send_size;

	kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "mach_port_allocate");

	outgoing_id = 0x41414141;
	send_size = sizeof(msg) - 128; /* minus trailer space */

	msg.header.msgh_local_port = MACH_PORT_NULL;
	msg.header.msgh_remote_port = port;
	msg.header.msgh_id = outgoing_id;
	msg.header.msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_MAKE_SEND, 0, 0, 0);
	msg.header.msgh_size = send_size;

	kr = mach_msg(&msg.header, MACH_SEND_MSG, msg.header.msgh_size, 0,
	    MACH_PORT_NULL,
	    MACH_MSG_TIMEOUT_NONE,
	    MACH_PORT_NULL);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "Message sent to port");

	mach_port_seqno_t seqno = 0;
	mach_msg_trailer_type_t tlrtype =
	    MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0)
	    | MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT);
	mach_msg_audit_trailer_t audit_trailer;
	mach_msg_type_number_t size = sizeof(audit_trailer);
	mach_msg_type_number_t incoming_size = 0;
	mach_msg_id_t incoming_id;

	kr = mach_port_peek(mach_task_self(), port, tlrtype, &seqno, &incoming_size, &incoming_id, &audit_trailer, &size);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "mach_port_peek");

	T_ASSERT_EQ(incoming_id, outgoing_id, "Peek must return correct msgh_id");

#define USER_HEADER_SIZE_DELTA 8 /* sizeof(mach_msg_header_t) - sizeof(mach_msg_user_header_t) */
	T_ASSERT_EQ(incoming_size, send_size + USER_HEADER_SIZE_DELTA, "Peek must return correct msg size");

	kr = mach_msg(&msg.header, MACH_RCV_MSG, 0,
	    sizeof(msg), port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "Message receive success after peek.");
}
