#include <darwintest.h>
#include <darwintest_utils.h>

#include <mach/mach.h>
#include <mach/mach_types.h>
#include <mach/mach_port.h>
#include <mach/message.h>
#include <mach/mach_error.h>
#include <mach/vm_map.h>


T_GLOBAL_META(
	T_META_NAMESPACE("xnu.ipc"),
	T_META_CHECK_LEAKS(false),
	T_META_RUN_CONCURRENTLY(true),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("IPC"));

/*
 * This file checks the basics of the MACH IPC basic transport mechanism
 */

#pragma mark helpers

#define DEFAULT_CONTEXT ((mach_port_context_t)0x42424242)

static mach_port_name_t
t_port_construct_full(
	uint32_t                mpo_flags,
	mach_port_msgcount_t    qlimit)
{
	mach_port_options_t opts = {
		.flags = mpo_flags | MPO_QLIMIT,
		.mpl.mpl_qlimit = qlimit,
	};
	mach_port_name_t name;
	kern_return_t kr;

	kr = mach_port_construct(mach_task_self(), &opts, DEFAULT_CONTEXT, &name);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_construct");

	return name;
}
#define t_port_construct()      t_port_construct_full(MPO_INSERT_SEND_RIGHT, 1)


static void
t_port_destruct_full(
	mach_port_name_t       *name,
	uint16_t                srights,
	mach_port_context_t     ctx)
{
	kern_return_t kr;

	kr = mach_port_destruct(mach_task_self(), *name, -srights, ctx);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_construct");

	*name = MACH_PORT_NULL;
}
#define t_port_destruct(name)   t_port_destruct_full(name, 1, 0)

static mach_port_name_t
t_make_sonce(
	mach_port_name_t        port)
{
	mach_msg_type_name_t disp;
	mach_port_name_t name;
	kern_return_t kr;

	kr = mach_port_extract_right(mach_task_self(), port,
	    MACH_MSG_TYPE_MAKE_SEND_ONCE, &name, &disp);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "make-send-once");
	T_QUIET; T_ASSERT_EQ(disp, MACH_MSG_TYPE_PORT_SEND_ONCE,
	    "check make-sonce");

	return name;
}

static void
t_deallocate_sonce(
	mach_port_name_t        port)
{
	kern_return_t kr;

	kr = mach_port_deallocate(mach_task_self(), port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "dealloc-send-once");
}

static void
t_vm_deallocate(
	void                   *addr,
	vm_size_t               size)
{
	kern_return_t kr;

	kr = vm_deallocate(mach_task_self(), (vm_address_t)addr, size);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_deallocate");
}

static kern_return_t
t_receive(
	mach_port_name_t        name,
	mach_msg_header_t      *msg,
	mach_msg_size_t         size,
	mach_msg_option64_t     opts)
{
	opts |= MACH64_RCV_GUARDED_DESC | MACH64_RCV_MSG;
	return mach_msg2(msg, opts, *msg, 0, size, name, 0, 0);
}

__attribute__((overloadable))
static kern_return_t
t_send(
	mach_port_name_t        dest,
	mach_msg_header_t      *msg,
	void                   *upto,
	mach_msg_option64_t     opts)
{
	mach_msg_size_t    size = (mach_msg_size_t)((char *)upto - (char *)msg);

	opts |= MACH64_SEND_MSG | MACH64_SEND_MQ_CALL;

	msg->msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND, 0, 0, 0);
	msg->msgh_size = size;
	msg->msgh_remote_port = dest;
	msg->msgh_local_port = MACH_PORT_NULL;
	msg->msgh_voucher_port = MACH_PORT_NULL;
	msg->msgh_id = 42;
	return mach_msg2(msg, opts, *msg, size, 0, 0, 0, 0);
}

__attribute__((overloadable))
static kern_return_t
t_send(
	mach_port_name_t        dest,
	mach_msg_base_t        *base,
	void                   *upto,
	mach_msg_option64_t     opts)
{
	mach_msg_header_t *msg = &base->header;
	mach_msg_size_t    size = (mach_msg_size_t)((char *)upto - (char *)msg);

	opts |= MACH64_SEND_MSG | MACH64_SEND_MQ_CALL;

	msg->msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND, 0, 0,
	    MACH_MSGH_BITS_COMPLEX);
	msg->msgh_size = size;
	msg->msgh_remote_port = dest;
	msg->msgh_local_port = MACH_PORT_NULL;
	msg->msgh_voucher_port = MACH_PORT_NULL;
	msg->msgh_id = 42;
	return mach_msg2(msg, opts, *msg, size, 0, 0, 0, 0);
}

static void
t_fill_port(
	mach_port_name_t        dest,
	size_t                  n)
{
	for (size_t i = 0; i < n; i++) {
		mach_msg_header_t hdr;
		kern_return_t kr;

		kr = t_send(dest, &hdr, &hdr + 1, MACH64_SEND_TIMEOUT);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "send to fill");
	}
}

static vm_size_t
t_check_0xff(
	const void             *addr,
	vm_size_t               size)
{
	for (size_t i = 0; i < size; i++) {
		if (((uint8_t *)addr)[i] != 0xff) {
			return i;
		}
	}

	return ~0ul;
}

#pragma mark trailer checks

T_DECL(mach_msg_trailer, "check trailer generation")
{
	mach_port_name_t rcv_name;
	security_token_t sec_token;
	audit_token_t audit_token;
	mach_msg_type_number_t count;
	kern_return_t kr;

	rcv_name = t_port_construct();

	count = TASK_SECURITY_TOKEN_COUNT;
	kr = task_info(mach_task_self(), TASK_SECURITY_TOKEN, (task_info_t)&sec_token, &count);
	T_ASSERT_MACH_SUCCESS(kr, "task_info(TASK_SECURITY_TOKEN)");

	count = TASK_AUDIT_TOKEN_COUNT;
	kr = task_info(mach_task_self(), TASK_AUDIT_TOKEN, (task_info_t)&audit_token, &count);
	T_ASSERT_MACH_SUCCESS(kr, "task_info(TASK_AUDIT_TOKEN)");

	for (int i = 0; i <= MACH_RCV_TRAILER_LABELS; i++) {
		mach_msg_option64_t topts = (mach_msg_option64_t)MACH_RCV_TRAILER_ELEMENTS(i);
		mach_msg_size_t     tsize = REQUESTED_TRAILER_SIZE(topts);
		struct {
			mach_msg_header_t      hdr;
			mach_msg_max_trailer_t trailer;
			uint32_t               sentinel;
		} buf;

		switch (i) {
		case MACH_RCV_TRAILER_NULL:
		case MACH_RCV_TRAILER_SEQNO:
		case MACH_RCV_TRAILER_SENDER:
		case MACH_RCV_TRAILER_AUDIT:
		case MACH_RCV_TRAILER_CTX:
		case MACH_RCV_TRAILER_AV:
			break;
		default:
			continue;
		}

		memset(&buf, 0xff, sizeof(buf));
		kr = t_send(rcv_name, &buf.hdr, &buf.trailer, MACH64_MSG_OPTION_NONE);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "sending message with trailer %d", i);

		kr = t_receive(rcv_name, &buf.hdr, sizeof(buf), topts);
		T_ASSERT_MACH_SUCCESS(kr, "receiving message with trailer %d", i);

		T_EXPECT_EQ(buf.hdr.msgh_size, sizeof(buf.hdr), "msgh_size");
		T_EXPECT_EQ(buf.trailer.msgh_trailer_type, MACH_MSG_TRAILER_FORMAT_0, "msgh_trailer_type");
		T_EXPECT_EQ(buf.trailer.msgh_trailer_size, tsize, "msgh_trailer_size");
		if (tsize > offsetof(mach_msg_max_trailer_t, msgh_sender)) {
			T_EXPECT_EQ(memcmp(&buf.trailer.msgh_sender, &sec_token,
			    sizeof(sec_token)), 0, "msgh_sender");
		}
		if (tsize > offsetof(mach_msg_max_trailer_t, msgh_audit)) {
			T_EXPECT_EQ(memcmp(&buf.trailer.msgh_audit, &audit_token,
			    sizeof(audit_token)), 0, "msgh_audit");
		}
		if (tsize > offsetof(mach_msg_max_trailer_t, msgh_context)) {
			T_EXPECT_EQ(buf.trailer.msgh_context, DEFAULT_CONTEXT,
			    "msgh_context");
		}
		if (tsize > offsetof(mach_msg_max_trailer_t, msgh_ad)) {
			T_EXPECT_EQ(buf.trailer.msgh_ad, 0, "msgh_ad");
		}
		if (tsize > offsetof(mach_msg_max_trailer_t, msgh_labels)) {
			T_EXPECT_EQ(buf.trailer.msgh_labels.sender, 0, "msgh_labels");
		}

		T_QUIET; T_EXPECT_EQ(t_check_0xff((char *)&buf.trailer + tsize,
		    sizeof(buf.trailer) + sizeof(buf.sentinel) - tsize), ~0ul,
		    "should be unmodified");
	}

	t_port_destruct(&rcv_name);
}

#pragma mark descriptor checks

static const mach_msg_type_name_t port_dispositions[] = {
	MACH_MSG_TYPE_MOVE_RECEIVE,
	MACH_MSG_TYPE_MOVE_SEND,
	MACH_MSG_TYPE_MOVE_SEND_ONCE,
	MACH_MSG_TYPE_COPY_SEND,
	MACH_MSG_TYPE_MAKE_SEND,
	MACH_MSG_TYPE_MAKE_SEND_ONCE,
	0,
};

struct msg_complex_port {
	mach_msg_base_t         base;
	mach_msg_port_descriptor_t dsc;
	mach_msg_max_trailer_t  trailer;
};

struct msg_complex_guarded_port {
	mach_msg_base_t         base;
	mach_msg_guarded_port_descriptor_t dsc;
	mach_msg_max_trailer_t  trailer;
};

struct msg_complex_port_array {
	mach_msg_base_t         base;
	mach_msg_ool_ports_descriptor_t dsc;
	mach_msg_max_trailer_t  trailer;
	mach_port_name_t        array[2];
};

struct msg_complex_memory {
	mach_msg_base_t         base;
	mach_msg_ool_descriptor_t dsc;
	mach_msg_max_trailer_t  trailer;
};

static void
t_fill_complex_port_msg(
	struct msg_complex_port *msg,
	mach_msg_type_name_t    disp,
	mach_port_name_t        name)
{
	*msg = (struct msg_complex_port){
		.base.body.msgh_descriptor_count = 1,
		.dsc = {
			.type        = MACH_MSG_PORT_DESCRIPTOR,
			.disposition = disp,
			.name        = name,
		},
	};
}

static void
t_fill_complex_port_guarded_msg(
	struct msg_complex_guarded_port *msg,
	mach_msg_type_name_t    disp,
	mach_port_name_t        name,
	mach_msg_guard_flags_t  flags)
{
	*msg = (struct msg_complex_guarded_port){
		.base.body.msgh_descriptor_count = 1,
		.dsc = {
			.type        = MACH_MSG_GUARDED_PORT_DESCRIPTOR,
			.disposition = disp,
			.name        = name,
			.context     = DEFAULT_CONTEXT,
			.flags       = flags,
		},
	};
	if (flags & MACH_MSG_GUARD_FLAGS_UNGUARDED_ON_SEND) {
		msg->dsc.context = 0;
	}
}

static void
t_fill_complex_memory_msg(
	struct msg_complex_memory *msg,
	vm_address_t            memory,
	mach_msg_size_t         size,
	bool                    move)
{
	*msg = (struct msg_complex_memory){
		.base.body.msgh_descriptor_count = 1,
		.dsc = {
			.type        = MACH_MSG_OOL_DESCRIPTOR,
			.address     = (void *)memory,
			.size        = size,
			.deallocate  = move,
		},
	};
}

static void
t_fill_complex_port_array_msg(
	struct msg_complex_port_array *msg,
	mach_msg_type_name_t    disp,
	mach_port_name_t        name1,
	mach_port_name_t        name2)
{
	*msg = (struct msg_complex_port_array){
		.base.body.msgh_descriptor_count = 1,
		.dsc = {
			.type        = MACH_MSG_OOL_PORTS_DESCRIPTOR,
			.disposition = disp,
			.address     = &msg->array,
			.count       = 2,
			.deallocate  = false,
		},
		.array[0] = name1,
		.array[1] = name2,
	};
}

static void
t_mach_msg_descriptor_port(bool pseudo_receive)
{
	mach_port_name_t rcv_name, port;
	kern_return_t kr;

	rcv_name = t_port_construct();
	port     = t_port_construct();

	if (pseudo_receive) {
		t_fill_port(rcv_name, 1);
	}

	for (size_t i = 0; i < port_dispositions[i]; i++) {
		mach_msg_type_name_t disp = port_dispositions[i];
		mach_port_name_t name = port;
		struct msg_complex_port msg;

		if (disp == MACH_MSG_TYPE_MOVE_SEND_ONCE) {
			name = t_make_sonce(port);
		}

		t_fill_complex_port_msg(&msg, disp, name);

		kr = t_send(rcv_name, &msg.base, &msg.trailer, MACH64_SEND_TIMEOUT);
		if (pseudo_receive) {
			T_ASSERT_MACH_ERROR(kr, MACH_SEND_TIMED_OUT,
			    "pseudo-rcv(disposition:%d)", disp);
		} else {
			T_ASSERT_MACH_SUCCESS(kr, "send(disposition:%d)", disp);

			kr = t_receive(rcv_name, &msg.base.header, sizeof(msg),
			    MACH64_MSG_OPTION_NONE);
			T_ASSERT_MACH_SUCCESS(kr, "recv(disposition:%d)", disp);
		}

		switch (disp) {
		case MACH_MSG_TYPE_MOVE_RECEIVE:
			disp = MACH_MSG_TYPE_PORT_RECEIVE;
			break;
		case MACH_MSG_TYPE_MOVE_SEND:
		case MACH_MSG_TYPE_COPY_SEND:
		case MACH_MSG_TYPE_MAKE_SEND:
			disp = MACH_MSG_TYPE_PORT_SEND;
			break;
		case MACH_MSG_TYPE_MOVE_SEND_ONCE:
		case MACH_MSG_TYPE_MAKE_SEND_ONCE:
			disp = MACH_MSG_TYPE_PORT_SEND_ONCE;
			break;
		}

		T_ASSERT_EQ(msg.base.header.msgh_bits & MACH_MSGH_BITS_COMPLEX,
		    MACH_MSGH_BITS_COMPLEX, "verify complex");
		T_ASSERT_EQ(msg.base.body.msgh_descriptor_count, 1u, "verify dsc count");
		T_ASSERT_EQ((mach_msg_descriptor_type_t)msg.dsc.type, MACH_MSG_PORT_DESCRIPTOR, "verify type");
		T_ASSERT_EQ((mach_msg_type_name_t)msg.dsc.disposition, disp, "verify disposition");
		if (disp == MACH_MSG_TYPE_PORT_RECEIVE ||
		    disp == MACH_PORT_TYPE_SEND) {
			T_ASSERT_EQ(msg.dsc.name, name, "verify name");
		}

		if (disp == MACH_MSG_TYPE_PORT_SEND_ONCE) {
			t_deallocate_sonce(msg.dsc.name);
		}
	}

	t_port_destruct_full(&port, 3, 0); /* did a COPY_SEND and a MAKE_SEND */
	t_port_destruct(&rcv_name);
}

T_DECL(mach_msg_descriptor_port, "check port descriptors")
{
	T_LOG("regular receive");
	t_mach_msg_descriptor_port(false);
	T_LOG("pseudo receive");
	t_mach_msg_descriptor_port(true);
}

static void
t_mach_msg_descriptor_guarded_port(bool pseudo_receive)
{
	mach_port_name_t rcv_name, port;
	kern_return_t kr;

	rcv_name = t_port_construct();

	if (pseudo_receive) {
		t_fill_port(rcv_name, 1);
	}

	static const mach_msg_guard_flags_t test_flags[] = {
		MACH_MSG_GUARD_FLAGS_IMMOVABLE_RECEIVE,
		MACH_MSG_GUARD_FLAGS_IMMOVABLE_RECEIVE | MACH_MSG_GUARD_FLAGS_UNGUARDED_ON_SEND,
		0,
	};

	for (size_t i = 0; test_flags[i]; i++) {
		struct msg_complex_guarded_port msg;
		mach_port_context_t ctx;

		if (test_flags[i] & MACH_MSG_GUARD_FLAGS_UNGUARDED_ON_SEND) {
			port = t_port_construct();
		} else {
			port = t_port_construct_full(MPO_INSERT_SEND_RIGHT | MPO_CONTEXT_AS_GUARD, 1);
		}

		t_fill_complex_port_guarded_msg(&msg, MACH_MSG_TYPE_MOVE_RECEIVE,
		    port, test_flags[i]);

		kr = t_send(rcv_name, &msg.base, &msg.trailer, MACH64_SEND_TIMEOUT);
		if (pseudo_receive) {
			T_ASSERT_MACH_ERROR(kr, MACH_SEND_TIMED_OUT, "pseudo-rcv");
		} else {
			T_ASSERT_MACH_SUCCESS(kr, "send");

			kr = t_receive(rcv_name, &msg.base.header, sizeof(msg),
			    MACH64_MSG_OPTION_NONE);
			T_ASSERT_MACH_SUCCESS(kr, "recv");
		}

		T_ASSERT_EQ(msg.base.header.msgh_bits & MACH_MSGH_BITS_COMPLEX,
		    MACH_MSGH_BITS_COMPLEX, "verify complex");
		T_ASSERT_EQ(msg.base.body.msgh_descriptor_count, 1u, "verify dsc count");
		T_ASSERT_EQ((mach_msg_descriptor_type_t)msg.dsc.type,
		    MACH_MSG_GUARDED_PORT_DESCRIPTOR, "verify type");
		T_ASSERT_EQ((mach_msg_type_name_t)msg.dsc.disposition,
		    MACH_MSG_TYPE_PORT_RECEIVE, "verify disposition");
		T_ASSERT_EQ(msg.dsc.name, port, "verify name");
		ctx = (mach_port_context_t)&msg.base;
		T_ASSERT_EQ(msg.dsc.context, ctx, "verify context");
		t_port_destruct_full(&port, 1, ctx);
	}

	t_port_destruct(&rcv_name);
}

T_DECL(mach_msg_descriptor_guarded_port, "check guarded port descriptors")
{
	T_LOG("regular receive");
	t_mach_msg_descriptor_guarded_port(false);
	T_LOG("pseudo receive");
	t_mach_msg_descriptor_guarded_port(true);
}

static void
t_mach_msg_descriptor_port_array(bool pseudo_receive)
{
	mach_port_name_t rcv_name, port1, port2;
	kern_return_t kr;

	rcv_name = t_port_construct();
	port1    = t_port_construct();
	port2    = t_port_construct();

	if (pseudo_receive) {
		t_fill_port(rcv_name, 1);
	}

	for (size_t i = 0; i < port_dispositions[i]; i++) {
		mach_msg_type_name_t disp = port_dispositions[i];
		mach_port_name_t name1 = port1;
		mach_port_name_t name2 = port2;
		struct msg_complex_port_array msg;
		mach_port_name_t *array;

		if (disp == MACH_MSG_TYPE_MOVE_SEND_ONCE) {
			name1 = t_make_sonce(port1);
			name2 = t_make_sonce(port2);
		}

		t_fill_complex_port_array_msg(&msg, disp, name1, name2);

		kr = t_send(rcv_name, &msg.base, &msg.trailer, MACH64_SEND_TIMEOUT);
		if (pseudo_receive) {
			T_ASSERT_MACH_ERROR(kr, MACH_SEND_TIMED_OUT,
			    "pseudo-rcv(disposition:%d)", disp);
		} else {
			T_ASSERT_MACH_SUCCESS(kr, "send(disposition:%d)", disp);

			kr = t_receive(rcv_name, &msg.base.header, sizeof(msg),
			    MACH64_MSG_OPTION_NONE);
			T_ASSERT_MACH_SUCCESS(kr, "recv(disposition:%d)", disp);
		}

		switch (disp) {
		case MACH_MSG_TYPE_MOVE_RECEIVE:
			disp = MACH_MSG_TYPE_PORT_RECEIVE;
			break;
		case MACH_MSG_TYPE_MOVE_SEND:
		case MACH_MSG_TYPE_COPY_SEND:
		case MACH_MSG_TYPE_MAKE_SEND:
			disp = MACH_MSG_TYPE_PORT_SEND;
			break;
		case MACH_MSG_TYPE_MOVE_SEND_ONCE:
		case MACH_MSG_TYPE_MAKE_SEND_ONCE:
			disp = MACH_MSG_TYPE_PORT_SEND_ONCE;
			break;
		}

		array = msg.dsc.address;

		T_ASSERT_EQ(msg.base.header.msgh_bits & MACH_MSGH_BITS_COMPLEX,
		    MACH_MSGH_BITS_COMPLEX, "verify complex");
		T_ASSERT_EQ(msg.base.body.msgh_descriptor_count, 1u, "verify dsc count");
		T_ASSERT_EQ((mach_msg_descriptor_type_t)msg.dsc.type, MACH_MSG_OOL_PORTS_DESCRIPTOR, "verify type");
		T_ASSERT_EQ((mach_msg_type_name_t)msg.dsc.disposition, disp, "verify disposition");
		T_ASSERT_EQ(msg.dsc.count, 2u, "verify count");
		T_ASSERT_EQ((bool)msg.dsc.deallocate, true, "verify deallocate");

		if (disp == MACH_MSG_TYPE_PORT_RECEIVE ||
		    disp == MACH_PORT_TYPE_SEND) {
			T_ASSERT_EQ(array[0], name1, "verify name");
			T_ASSERT_EQ(array[1], name2, "verify name");
		}

		if (disp == MACH_MSG_TYPE_PORT_SEND_ONCE) {
			t_deallocate_sonce(array[0]);
			t_deallocate_sonce(array[1]);
		}

		t_vm_deallocate(array, sizeof(array[0]) * msg.dsc.count);
	}

	t_port_destruct_full(&port1, 3, 0); /* did a COPY_SEND and a MAKE_SEND */
	t_port_destruct_full(&port2, 3, 0); /* did a COPY_SEND and a MAKE_SEND */
	t_port_destruct(&rcv_name);
}

T_DECL(mach_msg_descriptor_port_array, "check port array descriptors")
{
	T_LOG("regular receive");
	t_mach_msg_descriptor_port_array(false);
	T_LOG("pseudo receive");
	t_mach_msg_descriptor_port_array(true);
}

static void
t_mach_msg_descriptor_memory(bool pseudo_receive)
{
	mach_port_name_t rcv_name;
	struct msg_complex_memory msg;
	kern_return_t kr;
	vm_address_t addr;
	mach_msg_size_t size = 1u << 20;

	rcv_name = t_port_construct();

	if (pseudo_receive) {
		t_fill_port(rcv_name, 1);
	}

	kr = vm_allocate(mach_task_self(), &addr, size, VM_FLAGS_ANYWHERE);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_allocate(1M)");

	memset((void *)addr, 0xff, size);

	for (size_t n = 0; n < 2; n++) {
		t_fill_complex_memory_msg(&msg, addr, size, n > 0);

		kr = t_send(rcv_name, &msg.base, &msg.trailer, MACH64_SEND_TIMEOUT);
		if (pseudo_receive) {
			T_ASSERT_MACH_ERROR(kr, MACH_SEND_TIMED_OUT, "pseudo-rcv");
		} else {
			T_ASSERT_MACH_SUCCESS(kr, "send");

			kr = t_receive(rcv_name, &msg.base.header, sizeof(msg),
			    MACH64_MSG_OPTION_NONE);
			T_ASSERT_MACH_SUCCESS(kr, "recv");
		}

		T_ASSERT_EQ(msg.base.header.msgh_bits & MACH_MSGH_BITS_COMPLEX,
		    MACH_MSGH_BITS_COMPLEX, "verify complex");
		T_ASSERT_EQ(msg.base.body.msgh_descriptor_count, 1u, "verify dsc count");
		T_ASSERT_EQ((mach_msg_descriptor_type_t)msg.dsc.type,
		    MACH_MSG_OOL_DESCRIPTOR, "verify type");
		T_ASSERT_EQ(msg.dsc.size, size, "verify dsc count");
		T_ASSERT_EQ(t_check_0xff(msg.dsc.address, size), ~0ul,
		    "check content");

		if (n == 0) {
			t_vm_deallocate(msg.dsc.address, size);
		} else {
			addr = (vm_address_t)msg.dsc.address;
		}
	}

	t_vm_deallocate((void *)addr, size);
	t_port_destruct(&rcv_name);
}

T_DECL(mach_msg_descriptor_memory, "check memory descriptors")
{
	T_LOG("regular receive");
	t_mach_msg_descriptor_memory(false);
	T_LOG("pseudo receive");
	t_mach_msg_descriptor_memory(true);
}
