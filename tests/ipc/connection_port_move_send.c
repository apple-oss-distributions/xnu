#include <darwintest.h>
#include <mach/mach.h>
#include <mach/message.h>
#include <mach/port.h>
#include <mach/mach_port.h>
#include "ipc_utils.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.ipc"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("IPC"),
	T_META_TIMEOUT(10),
	T_META_IGNORECRASHES(".*connection_port_move_send.*"),
	T_META_RUN_CONCURRENTLY(TRUE));

static mach_port_t
create_connection_port(void)
{
	kern_return_t kr;
	mach_port_t conn_port;

	mach_port_options_t opts = {
		.flags = MPO_CONNECTION_PORT | MPO_INSERT_SEND_RIGHT,
		.service_port_name = MPO_ANONYMOUS_SERVICE,
	};

	kr = mach_port_construct(mach_task_self(), &opts, 0x0, &conn_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_construct");

	return conn_port;
}

T_DECL(connection_port_move_send_with_receive,
    "Connection port move_send is allowed if receive right is in space")
{
	kern_return_t kr;
	mach_port_t dest_port, conn_port, recv_port;

	dest_port = ipc_create_receive_port_with_options(MPO_INSERT_SEND_RIGHT);
	T_QUIET; T_ASSERT_NE(dest_port, MACH_PORT_NULL, "dest_port");

	conn_port = create_connection_port();
	T_QUIET; T_ASSERT_NE(conn_port, MACH_PORT_NULL, "conn_port");

	/* connection port MOVE_SEND with receive right should succeed */
	kr = ipc_send_port(dest_port, conn_port, MACH_MSG_TYPE_MOVE_SEND);
	T_ASSERT_MACH_SUCCESS(kr, "MOVE_SEND with receive right should succeed");

	kr = ipc_receive_port(dest_port, &recv_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "ipc_receive_port");
	T_QUIET; T_ASSERT_EQ(conn_port, recv_port, "same name");

	kr = mach_port_destruct(mach_task_self(), dest_port, -1, 0);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_destruct");

	kr = mach_port_destruct(mach_task_self(), conn_port, -1, 0);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_destruct");
}

T_DECL(connection_port_move_send_without_receive,
    "Connection port move_send is not allowed if receive right is not in space")
{
	expect_sigkill(^{
		kern_return_t kr;
		mach_port_t dest_port, conn_port;

		dest_port = ipc_create_receive_port_with_options(MPO_INSERT_SEND_RIGHT);
		T_QUIET; T_ASSERT_NE(dest_port, MACH_PORT_NULL, "dest_port");

		conn_port = create_connection_port();
		T_QUIET; T_ASSERT_NE(conn_port, MACH_PORT_NULL, "conn_port");

		/* move conn port receive right */
		kr = ipc_send_port(dest_port, conn_port, MACH_MSG_TYPE_MOVE_RECEIVE);
		T_ASSERT_MACH_SUCCESS(kr, "ipc_send_port MACH_MSG_TYPE_MOVE_RECEIVE");

		/*
		 * connection port MOVE_SEND without receive right should fail
		 * this should raise kGUARD_EXC_IMMOVABLE
		 */
		kr = ipc_send_port(dest_port, conn_port, MACH_MSG_TYPE_MOVE_SEND);

		/* Unreachable */
	}, "%s move_send fail without receive right", "connection port");
}

#define TIMEOUT_MS 5 /* 5 ms*/

static kern_return_t
ipc_send_port_with_timeout(
	mach_port_t destination,
	mach_port_t port,
	mach_msg_type_name_t disposition,
	ipc_single_port_msg_t *msg)
{
	kern_return_t kr;

	msg->header.msgh_remote_port = destination;
	msg->header.msgh_local_port = MACH_PORT_NULL;
	msg->header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0) | MACH_MSGH_BITS_COMPLEX;
	msg->header.msgh_size = sizeof(ipc_single_port_msg_t);
	msg->header.msgh_id =  0x1001;  /* Single port message ID */
	msg->body.msgh_descriptor_count = 1;
	msg->port.name = port;
	msg->port.disposition = disposition;
	msg->port.type = MACH_MSG_PORT_DESCRIPTOR;

	kr = mach_msg(&msg->header,
	    MACH_SEND_MSG | MACH_SEND_TIMEOUT,
	    msg->header.msgh_size,
	    0,
	    MACH_PORT_NULL,
	    TIMEOUT_MS,
	    MACH_PORT_NULL
	    );
	return kr;
}

T_DECL(connection_port_pusedo_receive,
    "Resending a connection port after pseudo receive should work")
{
	kern_return_t kr;
	mach_port_t dest_port, conn_port, recv_port;
	ipc_single_port_msg_t msg = {};
	const int qlimit = 5;

	dest_port = ipc_create_receive_port_with_options(MPO_INSERT_SEND_RIGHT);
	T_QUIET; T_ASSERT_NE(dest_port, MACH_PORT_NULL, "dest_port");

	conn_port = create_connection_port();
	T_QUIET; T_ASSERT_NE(conn_port, MACH_PORT_NULL, "conn_port");

	for (int i = 0; i < qlimit; i++) {
		kr = ipc_send_port(dest_port, conn_port, MACH_MSG_TYPE_MAKE_SEND);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "sending conn_port with make send");
	}

	/* send another message with timeout should fail */
	kr = ipc_send_port_with_timeout(dest_port, conn_port, MACH_MSG_TYPE_MAKE_SEND, &msg);
	T_ASSERT_MACH_ERROR(kr, MACH_SEND_TIMED_OUT, "send after qlimit should timeout");
	T_ASSERT_EQ((mach_msg_type_name_t)msg.port.disposition,
	    MACH_MSG_TYPE_MOVE_SEND, "pseudo receive converted disp");

	/* receive 1 message to make room */
	kr = ipc_receive_port(dest_port, &recv_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "ipc_receive_port");
	T_QUIET; T_ASSERT_EQ(conn_port, recv_port, "same name");

	/* resending the pseudo received message should succeed */
	kr = mach_msg(&msg.header, MACH_SEND_MSG | MACH_SEND_TIMEOUT, msg.header.msgh_size, 0,
	    MACH_PORT_NULL, TIMEOUT_MS, MACH_PORT_NULL);
	T_ASSERT_MACH_SUCCESS(kr, "pseudo receive resend");

	for (int i = 0; i < qlimit; i++) {
		kr = ipc_receive_port(dest_port, &recv_port);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "ipc_receive_port");
		T_QUIET; T_ASSERT_EQ(conn_port, recv_port, "same name");
	}

	kr = mach_port_destruct(mach_task_self(), dest_port, -1, 0);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_destruct");

	kr = mach_port_destruct(mach_task_self(), conn_port, -(qlimit + 1), 0);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_destruct");
}
