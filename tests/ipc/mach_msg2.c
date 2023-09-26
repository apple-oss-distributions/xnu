#include <darwintest.h>
#include <darwintest_utils.h>

#include <mach/mach.h>
#include <mach/mach_types.h>
#include <mach/mach_vm.h>
#include <mach/message.h>
#include <mach/mach_error.h>
#include <mach/task.h>

#include <pthread.h>
#include <pthread/workqueue_private.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.ipc"),
	T_META_RUN_CONCURRENTLY(TRUE),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("IPC"));

/* Skip the whole test on armv7k */
#if defined(__LP64__) || defined (__arm64__)

#define MAX_MESSAGE_SIZE  256
#define MAX_BUFFER_SIZE   256

#define MESSAGE_DATA_BYTES 0xdeadcafedeadface
#define MESSAGE_AUX_STR "Across the Great Wall we can reach every corner of the world"

#define MACH_MSG    1
#define MACH_MSG2   2

#define MACH_MSG2_TEST_COUNT 16

struct msg_rcv_args {
	mach_port_t rcv_port;
};

typedef struct {
	mach_msg_header_t header;
	uint64_t data;
} inline_message_t;

typedef struct {
	inline_message_t msg;
	mach_msg_max_trailer_t trailer;
} msg_rcv_buffer_t;

typedef struct {
	mach_msg_aux_header_t header;
	char string[64];
} aux_buffer_t;

typedef struct {
	uint8_t rcv_mode;
	mach_msg_option64_t rcv_options; /* only used for mach_msg2 */
	mach_msg_size_t rcv_size;
	mach_msg_return_t expected_kr;
	mach_msg_size_t expected_aux_size;
	char *expected_aux;
} rcv_configs_t;

typedef struct {
	uint8_t send_mode;
	mach_msg_size_t send_count;
	mach_msg_option64_t send_options; /* only used for mach_msg2 */
	mach_msg_header_t *msg;
	mach_msg_size_t msg_size;
	void *aux;
	mach_msg_size_t aux_size;
	mach_msg_return_t expected_kr;
} send_configs_t;

static mach_port_t send_port, rcv_port;

static const rcv_configs_t rcv_configs[MACH_MSG2_TEST_COUNT] = {
	/* Test 0: Send a CV and receive as CV */
	{.rcv_mode = MACH_MSG2, .rcv_options = MACH64_MSG_VECTOR,
	 .rcv_size = 2, .expected_kr = MACH_MSG_SUCCESS,
	 .expected_aux_size = sizeof(aux_buffer_t),
	 .expected_aux = MESSAGE_AUX_STR},

	/* Test 1: CV -> S via mach_msg(), just drop aux data */
	{.rcv_mode = MACH_MSG, .rcv_size = MAX_MESSAGE_SIZE,
	 .expected_kr = MACH_MSG_SUCCESS},

	/* Test 2: CV -> S via mach_msg2(), just drop aux data */
	{.rcv_mode = MACH_MSG2, .rcv_size = MAX_MESSAGE_SIZE,
	 .expected_kr = MACH_MSG_SUCCESS},

	/* Test 3: CV -> SV */
	{.rcv_mode = MACH_MSG2, .rcv_options = MACH64_MSG_VECTOR,
	 .rcv_size = 1, .expected_kr = MACH_RCV_TOO_LARGE},

	/* Test 4: SV -> CV */
	{.rcv_mode = MACH_MSG2, .rcv_options = MACH64_MSG_VECTOR,
	 .rcv_size = 2, .expected_kr = MACH_MSG_SUCCESS, /* Also need to check expected_aux_size */
	 .expected_aux_size = 0,
	 .expected_aux = ""},

	/* Test 5: SV -> S via mach_msg() */
	{.rcv_mode = MACH_MSG, .rcv_size = MAX_MESSAGE_SIZE,
	 .expected_kr = MACH_MSG_SUCCESS},

	/* Test 6: SV -> S via mach_msg2() */
	{.rcv_mode = MACH_MSG2, .rcv_size = MAX_MESSAGE_SIZE,
	 .expected_kr = MACH_MSG_SUCCESS},

	/* Test 7: SV -> SV */
	{.rcv_mode = MACH_MSG2, .rcv_options = MACH64_MSG_VECTOR,
	 .rcv_size = 1, .expected_kr = MACH_MSG_SUCCESS},

	/* Test 8: S (mach_msg2) -> CV */
	{.rcv_mode = MACH_MSG2, .rcv_options = MACH64_MSG_VECTOR,
	 .rcv_size = 2, .expected_kr = MACH_MSG_SUCCESS,
	 .expected_aux_size = 0,
	 .expected_aux = ""},

	/* Test 9: S (mach_msg2) -> S (mach_msg)  */
	{.rcv_mode = MACH_MSG, .rcv_size = MAX_MESSAGE_SIZE,
	 .expected_kr = MACH_MSG_SUCCESS},

	/* Test 10: S (mach_msg2) -> S (mach_msg2) */
	{.rcv_mode = MACH_MSG2, .rcv_size = MAX_MESSAGE_SIZE,
	 .expected_kr = MACH_MSG_SUCCESS},

	/* Test 11: S (mach_msg2) -> SV */
	{.rcv_mode = MACH_MSG2, .rcv_options = MACH64_MSG_VECTOR,
	 .rcv_size = 1, .expected_kr = MACH_MSG_SUCCESS},

	/* Test 12: S (mach_msg) -> CV */
	{.rcv_mode = MACH_MSG2, .rcv_options = MACH64_MSG_VECTOR,
	 .rcv_size = 2, .expected_kr = MACH_MSG_SUCCESS,
	 .expected_aux_size = 0,
	 .expected_aux = ""},

	/* Test 13: S (mach_msg) -> S (mach_msg)  */
	{.rcv_mode = MACH_MSG, .rcv_size = MAX_MESSAGE_SIZE,
	 .expected_kr = MACH_MSG_SUCCESS},

	/* Test 14: S (mach_msg) -> S (mach_msg2) */
	{.rcv_mode = MACH_MSG2, .rcv_size = MAX_MESSAGE_SIZE,
	 .expected_kr = MACH_MSG_SUCCESS},

	/* Test 15: S (mach_msg) -> SV */
	{.rcv_mode = MACH_MSG2, .rcv_options = MACH64_MSG_VECTOR,
	 .rcv_size = 1, .expected_kr = MACH_MSG_SUCCESS},

	/* Test 16: CV -> CV (minimum aux size) */
	{.rcv_mode = MACH_MSG2, .rcv_options = MACH64_MSG_VECTOR,
	 .rcv_size = 2, .expected_kr = MACH_MSG_SUCCESS,
	 .expected_aux_size = sizeof(mach_msg_aux_header_t),
	 .expected_aux = ""},
};

static void* _Nullable
do_msg_rcv(void * _Nullable arg)
{
	mach_port_t msg_rcv_port = ((struct msg_rcv_args *)arg)->rcv_port;
	mach_msg_vector_t data_vec[2];
	kern_return_t kr;
	mach_msg_header_t emptry_header = {};
	msg_rcv_buffer_t message_buffer;
	inline_message_t *msg;

	T_LOG("Message receive thread is running..");

	kr = mach_vm_allocate(mach_task_self(), &data_vec[0].msgv_data, MAX_MESSAGE_SIZE, VM_FLAGS_ANYWHERE);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_allocate should succeed");
	data_vec[0].msgv_rcv_size = MAX_MESSAGE_SIZE;

	kr = mach_vm_allocate(mach_task_self(), &data_vec[1].msgv_data, MAX_BUFFER_SIZE, VM_FLAGS_ANYWHERE);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_allocate should succeed");
	data_vec[1].msgv_rcv_size = MAX_BUFFER_SIZE;


	for (unsigned int i = 0; i < MACH_MSG2_TEST_COUNT; i++) {
		if (rcv_configs[i].rcv_mode == MACH_MSG2 && (rcv_configs[i].rcv_options & MACH64_MSG_VECTOR)) {
			msg = (inline_message_t *)data_vec[0].msgv_data;
		} else {
			msg = (inline_message_t *)&message_buffer;
		}

		if (rcv_configs[i].rcv_mode == MACH_MSG2) {
			kr = mach_msg2((rcv_configs[i].rcv_options & MACH64_MSG_VECTOR) ?
			    (void *)data_vec : (void *)&message_buffer,
			    MACH64_RCV_MSG | rcv_configs[i].rcv_options,
			    MACH_MSG_HEADER_EMPTY,
			    0,
			    rcv_configs[i].rcv_size,
			    msg_rcv_port,
			    0,
			    0);
		} else {
			kr = mach_msg(msg,
			    MACH_RCV_MSG, 0, rcv_configs[i].rcv_size, msg_rcv_port, 0, 0);
		}

		T_LOG("[Test %d] Received a message via mach_msg %d, verifying..", i, rcv_configs[i].rcv_mode);

		if (kr != rcv_configs[i].expected_kr) {
			T_FAIL("[Receive] Got unexpected kr %d for test case %d. \
                Expecting: %d", kr, i, rcv_configs[i].expected_kr);
		} else {
			if (kr == KERN_SUCCESS) {
				/* verify message proper carries correct data and port */

				T_QUIET; T_EXPECT_EQ(msg->data, MESSAGE_DATA_BYTES, "message should carry correct value");
				T_QUIET; T_EXPECT_EQ(msg->header.msgh_remote_port, send_port, "port name should match");
				T_QUIET; T_EXPECT_EQ(msg->header.msgh_local_port, msg_rcv_port, "port name should match");
				T_QUIET; T_EXPECT_EQ(msg->header.msgh_id, 4141, "ID should match");

				if (rcv_configs[i].rcv_mode == MACH_MSG2 &&
				    (rcv_configs[i].rcv_options & MACH64_MSG_VECTOR) &&
				    rcv_configs[i].rcv_size > 1) {
					/* verify aux data size and content */
					mach_msg_size_t aux_size = ((aux_buffer_t *)data_vec[1].msgv_data)->header.msgdh_size;
					char *content = ((aux_buffer_t *)data_vec[1].msgv_data)->string;
					mach_msg_size_t expected = rcv_configs[i].expected_aux_size;
					if (aux_size != expected) {
						T_FAIL("[Receive] Got unexpected aux size %d for test case %d. \
                            Expecting: %d", aux_size, i, expected);
					} else {
						if (aux_size > sizeof(mach_msg_aux_header_t)) {
							if (strcmp(content, rcv_configs[i].expected_aux)) {
								T_FAIL("[Receive] Got unexpected aux content %s for test case %d. \
                                    Expecting: %s", content, i, rcv_configs[i].expected_aux);
							}
						}
					}
				}
			}
		}
	}

	mach_vm_deallocate(mach_task_self(), data_vec[0].msgv_data, MAX_MESSAGE_SIZE);
	mach_vm_deallocate(mach_task_self(), data_vec[1].msgv_data, MAX_BUFFER_SIZE);

	T_END;
}

static void
send_msg(send_configs_t configs)
{
	kern_return_t kr;

	for (int i = 0; i < configs.send_count; i++) {
		if (configs.send_mode == MACH_MSG2) {
			if (configs.send_options & MACH64_MSG_VECTOR) {
				mach_msg_vector_t data_vecs[2] = {};
				mach_msg_size_t data_count = 1;

				data_vecs[MACH_MSGV_IDX_MSG].msgv_data = (mach_vm_address_t)configs.msg;
				data_vecs[MACH_MSGV_IDX_MSG].msgv_send_size = configs.msg_size;
				data_vecs[MACH_MSGV_IDX_MSG].msgv_rcv_size = 0;

				if (configs.aux != NULL) {
					data_vecs[MACH_MSGV_IDX_AUX].msgv_data = (mach_vm_address_t)configs.aux;
					data_vecs[MACH_MSGV_IDX_AUX].msgv_send_size = configs.aux_size;
					data_vecs[MACH_MSGV_IDX_AUX].msgv_rcv_size = 0;
					data_count++;
				}

				kr = mach_msg2(data_vecs, MACH64_SEND_MSG | MACH64_SEND_MQ_CALL | configs.send_options,
				    *(configs.msg), data_count, 0, MACH_PORT_NULL,
				    0, 0);
			} else {
				T_QUIET; T_EXPECT_EQ(configs.aux, NULL, "buffer must be NULL for non-vector send");
				kr = mach_msg2(configs.msg, MACH64_SEND_MSG | MACH64_SEND_MQ_CALL | configs.send_options,
				    *(configs.msg), configs.msg_size, 0, MACH_PORT_NULL,
				    0, 0);
			}
		} else {
			kr = mach_msg(configs.msg, MACH_SEND_MSG, configs.msg_size, 0, 0, 0, 0);
		}

		if (kr != configs.expected_kr) {
			T_FAIL("[Send] Got unexpected kr %d. \
                    Expecting: %d", kr, configs.expected_kr);
		}

		if (kr == MACH_MSG_SUCCESS) {
			T_LOG("Sent a message via mach_msg %d", configs.send_mode);
		}
	}
}

T_DECL(mach_msg2_interop, "Test mach_msg2 inter-operability")
{
	inline_message_t msg;
	aux_buffer_t aux;
	mach_msg_option64_t options;
	struct msg_rcv_args args;
	pthread_t servicer;
	kern_return_t kr;
	send_configs_t send_configs = {};
	char buf_string[64] = MESSAGE_AUX_STR;
	int ret;


	kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE,
	    &send_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "port allocation");
	T_LOG("Sending from port 0x%x", send_port);

	kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE,
	    &rcv_port);
	T_LOG("Receiving from port 0x%x", rcv_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "port allocation");
	kr = mach_port_insert_right(mach_task_self(), rcv_port, rcv_port, MACH_MSG_TYPE_MAKE_SEND);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "insert right");

	args.rcv_port = rcv_port;

	ret = pthread_create(&servicer, NULL, &do_msg_rcv, &args);
	T_ASSERT_EQ(ret, 0, "pthread_create");

	msg.header.msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND,
	    MACH_MSG_TYPE_MAKE_SEND, 0, 0);
	msg.header.msgh_size = sizeof(inline_message_t);
	msg.header.msgh_remote_port = rcv_port;
	msg.header.msgh_local_port = send_port;
	msg.header.msgh_id = 4141;
	msg.header.msgh_voucher_port = MACH_PORT_NULL;

	msg.data = MESSAGE_DATA_BYTES;

	aux.header.msgdh_size = sizeof(aux_buffer_t);
	memcpy(aux.string, buf_string, sizeof(aux.string));
	options = MACH64_MSG_VECTOR;

	/*
	 * Simple Vector (SV): Vector message without auxiliary data
	 * Complex Vector (CV): Vector messsage with auxiliary data
	 * Scalar (S): Scalar message
	 */

	/* Test 0: Send a CV and receive as CV */
	/* Test 1: CV -> S via mach_msg() */
	/* Test 2: CV -> S via mach_msg2() */
	/* Test 3: CV -> SV */
	send_configs.send_mode = MACH_MSG2;
	send_configs.send_count = 4;
	send_configs.send_options = MACH64_MSG_VECTOR;
	send_configs.msg = (mach_msg_header_t *)&msg;
	send_configs.msg_size = sizeof(inline_message_t);
	send_configs.aux = &aux;
	send_configs.aux_size = sizeof(aux_buffer_t);
	send_configs.expected_kr = MACH_MSG_SUCCESS;
	send_msg(send_configs);

	bzero(&send_configs, sizeof(send_configs));

	/* Test 4: SV -> CV */
	/* Test 5: SV -> S via mach_msg() */
	/* Test 6: SV -> S via mach_msg2() */
	/* Test 7: SV -> SV */
	send_configs.send_mode = MACH_MSG2;
	send_configs.send_count = 4;
	send_configs.send_options = MACH64_MSG_VECTOR;
	send_configs.msg = (mach_msg_header_t *)&msg;
	send_configs.msg_size = sizeof(inline_message_t);
	send_configs.expected_kr = MACH_MSG_SUCCESS;
	send_msg(send_configs);

	bzero(&send_configs, sizeof(send_configs));

	/* Test 8: S (mach_msg2)  -> CV */
	/* Test 9: S (mach_msg2)  -> S (mach_msg)  */
	/* Test 10: S (mach_msg2) -> S (mach_msg2) */
	/* Test 11: S (mach_msg2) -> SV */
	send_configs.send_mode = MACH_MSG2;
	send_configs.send_count = 4;
	send_configs.msg = (mach_msg_header_t *)&msg;
	send_configs.msg_size = sizeof(inline_message_t);
	send_configs.expected_kr = MACH_MSG_SUCCESS;
	send_msg(send_configs);

	bzero(&send_configs, sizeof(send_configs));

	/* Test 12: S (mach_msg) -> CV */
	/* Test 13: S (mach_msg) -> S (mach_msg)  */
	/* Test 14: S (mach_msg) -> S (mach_msg2) */
	/* Test 15: S (mach_msg) -> SV */
	send_configs.send_mode = MACH_MSG;
	send_configs.send_count = 4;
	send_configs.msg = (mach_msg_header_t *)&msg;
	send_configs.msg_size = sizeof(inline_message_t);
	send_configs.expected_kr = MACH_MSG_SUCCESS;
	send_msg(send_configs);

	/* Test 16: CV -> CV (minimum aux size) */

	/* It's okay to just send an aux header */
	aux.header.msgdh_size = sizeof(mach_msg_aux_header_t);

	send_configs.send_mode = MACH_MSG2;
	send_configs.send_count = 1;
	send_configs.send_options = MACH64_MSG_VECTOR;
	send_configs.msg = (mach_msg_header_t *)&msg;
	send_configs.msg_size = sizeof(inline_message_t);
	send_configs.aux = &aux;
	send_configs.aux_size = sizeof(mach_msg_aux_header_t);
	send_configs.expected_kr = MACH_MSG_SUCCESS;
	send_msg(send_configs);

	/* wait for do_msg_rcv() */
	for (int i = 0; i < 10; i++) {
		sleep(2);
	}

	T_FAIL("mach_msg2_interop timed out");
}

T_DECL(mach_msg2_combined_send_rcv, "Test mach_msg2() combined send/rcv")
{
	msg_rcv_buffer_t buffer;
	aux_buffer_t aux;
	kern_return_t kr;
	mach_port_t sr_port;
	mach_msg_vector_t data_vec[2] = {};

	char buf_string[64] = "One trap to rule them all!";
	int ret;

	kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE,
	    &sr_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "port allocation");
	T_LOG("Sending/Receiving from port 0x%x", sr_port);
	kr = mach_port_insert_right(mach_task_self(), sr_port, sr_port, MACH_MSG_TYPE_MAKE_SEND);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "insert right");

	buffer.msg.header.msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND,
	    MACH_MSG_TYPE_MAKE_SEND, 0, 0);
	buffer.msg.header.msgh_size = sizeof(inline_message_t);
	buffer.msg.header.msgh_remote_port = sr_port;
	buffer.msg.header.msgh_local_port = sr_port;
	buffer.msg.header.msgh_id = 4141;
	buffer.msg.header.msgh_voucher_port = MACH_PORT_NULL;
	buffer.msg.data = MESSAGE_DATA_BYTES;

	aux.header.msgdh_size = sizeof(aux_buffer_t) + 0x10; /* set it to wrong size, ignored */
	memcpy(aux.string, buf_string, sizeof(aux.string));

	data_vec[0].msgv_data = (mach_vm_address_t)&buffer.msg;
	data_vec[0].msgv_send_size = sizeof(inline_message_t);
	data_vec[0].msgv_rcv_size = sizeof(msg_rcv_buffer_t);

	data_vec[1].msgv_data = (mach_vm_address_t)&aux;
	data_vec[1].msgv_send_size = sizeof(aux_buffer_t);
	data_vec[1].msgv_rcv_size = sizeof(aux_buffer_t);

	/* Test 1 1+1 and 2+2 combined send/rcv */
	kr = mach_msg2(data_vec, MACH64_SEND_MSG | MACH64_SEND_MQ_CALL | MACH64_RCV_MSG | MACH64_MSG_VECTOR,
	    buffer.msg.header, 2, 2, sr_port, 0, 0);
	T_EXPECT_EQ(kr, MACH_MSG_SUCCESS, " 2+2 combined send/rcv succeeded");

	kr = mach_msg2(data_vec, MACH64_SEND_MSG | MACH64_SEND_MQ_CALL | MACH64_RCV_MSG | MACH64_MSG_VECTOR,
	    buffer.msg.header, 1, 1, sr_port, 0, 0);
	T_EXPECT_EQ(kr, MACH_MSG_SUCCESS, "1+1 combined send/rcv succeeded");

	/* Verify content */
	T_EXPECT_EQ(((aux_buffer_t *)data_vec[1].msgv_data)->header.msgdh_size,
	    sizeof(aux_buffer_t), "Kernel should reset header to correct size");
	ret = strcmp(buf_string, ((aux_buffer_t *)data_vec[1].msgv_data)->string);
	T_EXPECT_EQ(ret, 0, "aux data string should match after receive");

	buffer.msg.header.msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND,
	    MACH_MSG_TYPE_MAKE_SEND, 0, 0);
	buffer.msg.header.msgh_size = sizeof(inline_message_t);
	buffer.msg.header.msgh_remote_port = sr_port;
	buffer.msg.header.msgh_local_port = sr_port;
	buffer.msg.header.msgh_id = 4141;
	buffer.msg.header.msgh_voucher_port = MACH_PORT_NULL;
	buffer.msg.data = MESSAGE_DATA_BYTES;

	/* Test 2 2+1 too large receive */
	kr = mach_msg2(data_vec, MACH64_SEND_MSG | MACH64_SEND_MQ_CALL | MACH64_RCV_MSG | MACH64_MSG_VECTOR,
	    buffer.msg.header, 2, 1, sr_port, 0, 0);
	T_EXPECT_EQ(kr, MACH_RCV_TOO_LARGE, "need aux data descriptor");

	buffer.msg.header.msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND,
	    MACH_MSG_TYPE_MAKE_SEND, 0, 0);
	buffer.msg.header.msgh_size = sizeof(inline_message_t);
	buffer.msg.header.msgh_remote_port = sr_port;
	buffer.msg.header.msgh_local_port = sr_port;
	buffer.msg.header.msgh_id = 4141;
	buffer.msg.header.msgh_voucher_port = MACH_PORT_NULL;
	buffer.msg.data = MESSAGE_DATA_BYTES;

	/* Test 3 1+2 extra aux space, and via a different rcv buffer */
	msg_rcv_buffer_t rcv_buffer;
	data_vec[0].msgv_rcv_addr = (mach_vm_address_t)&rcv_buffer.msg;

	aux.header.msgdh_size = sizeof(aux_buffer_t) + 0x10; /* set it to wrong size, ignored */
	kr = mach_msg2(data_vec, MACH64_SEND_MSG | MACH64_SEND_MQ_CALL | MACH64_RCV_MSG | MACH64_MSG_VECTOR,
	    buffer.msg.header, 1, 2, sr_port, 0, 0);
	T_EXPECT_EQ(kr, MACH_MSG_SUCCESS, "extra aux buffer is fine");
	T_EXPECT_EQ(((aux_buffer_t *)data_vec[1].msgv_data)->header.msgdh_size,
	    0, "Kernel should reset header to 0");
	T_EXPECT_EQ(rcv_buffer.msg.header.msgh_id, 4141, "msgh_id in rcv_buffer should match");
}

static void
workloop_cb(uint64_t *workloop_id __unused, void **eventslist, int *events __unused)
{
	struct kevent_qos_s *kev = *eventslist;
	mach_msg_header_t *msg = (mach_msg_header_t *)kev->ext[0];
	mach_msg_size_t msg_size = (mach_msg_size_t)kev->ext[1];
	mach_msg_size_t aux_size = (mach_msg_size_t)kev->ext[3];

	T_LOG("workloop is set running..");

	T_EXPECT_NE(msg_size, 0, "msg size should not be zero");
	T_EXPECT_EQ(aux_size, sizeof(aux_buffer_t), "aux size should match");

	aux_buffer_t *aux = (aux_buffer_t *)((uintptr_t)msg + msg_size);
	T_EXPECT_EQ(aux->header.msgdh_size, aux_size, "aux size should match header");

	int ret = strcmp(aux->string, MESSAGE_AUX_STR);
	T_EXPECT_EQ(ret, 0, "aux content should match. Got: %s", aux->string);

	T_END;
}

/* From tests/prioritize_process_launch.c */
static void
register_workloop_for_port(
	mach_port_t port,
	pthread_workqueue_function_workloop_t func)
{
	mach_msg_option_t options = (MACH_RCV_MSG | MACH_RCV_LARGE | MACH_RCV_LARGE_IDENTITY | \
	    MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_CTX) | \
	    MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0));
	int r;

	/* register workloop handler with pthread */
	if (func != NULL) {
		T_QUIET; T_ASSERT_POSIX_ZERO(_pthread_workqueue_init_with_workloop(
			    NULL, NULL,
			    (pthread_workqueue_function_workloop_t)func, 0, 0), NULL);
	}

	/* attach port to workloop */
	struct kevent_qos_s kev[] = {{
					     .ident = port,
					     .filter = EVFILT_MACHPORT,
					     .flags = EV_ADD | EV_UDATA_SPECIFIC | EV_DISPATCH | EV_VANISHED,
					     .fflags = options,
					     .data = 1,
					     .qos = (int32_t)_pthread_qos_class_encode(QOS_CLASS_DEFAULT, 0, 0)
				     }};

	struct kevent_qos_s kev_err[] = {{ 0 }};

	/* Setup workloop for mach msg rcv */
	r = kevent_id(25, kev, 1, kev_err, 1, NULL,
	    NULL, KEVENT_FLAG_WORKLOOP | KEVENT_FLAG_ERROR_EVENTS);

	T_QUIET; T_ASSERT_POSIX_SUCCESS(r, "kevent_id");
	T_QUIET; T_ASSERT_EQ(r, 0, "no errors returned from kevent_id");
}

T_DECL(mach_msg2_kevent_rcv, "Test mach_msg2() receive with kevent workloop")
{
	msg_rcv_buffer_t buffer;
	aux_buffer_t aux;
	kern_return_t kr;
	mach_port_t sr_port;
	mach_msg_vector_t data_vec[2] = {};

	char buf_string[64] = MESSAGE_AUX_STR;

	kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE,
	    &sr_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "port allocation");
	T_LOG("Sending/Receiving from port 0x%x", sr_port);
	kr = mach_port_insert_right(mach_task_self(), sr_port, sr_port, MACH_MSG_TYPE_MAKE_SEND);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "insert right");

	buffer.msg.header.msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND,
	    MACH_MSG_TYPE_MAKE_SEND, 0, 0);
	buffer.msg.header.msgh_size = sizeof(inline_message_t);
	buffer.msg.header.msgh_remote_port = sr_port;
	buffer.msg.header.msgh_local_port = sr_port;
	buffer.msg.header.msgh_id = 4141;
	buffer.msg.header.msgh_voucher_port = MACH_PORT_NULL;
	buffer.msg.data = MESSAGE_DATA_BYTES;

	aux.header.msgdh_size = sizeof(aux_buffer_t) + 0x10; /* set it to wrong size, ignored */
	memcpy(aux.string, buf_string, sizeof(aux.string));

	data_vec[0].msgv_data = (mach_vm_address_t)&buffer.msg;
	data_vec[0].msgv_send_size = sizeof(inline_message_t);
	data_vec[0].msgv_rcv_size = sizeof(msg_rcv_buffer_t);

	data_vec[1].msgv_data = (mach_vm_address_t)&aux;
	data_vec[1].msgv_send_size = sizeof(aux_buffer_t);
	data_vec[1].msgv_rcv_size = sizeof(aux_buffer_t);

	/* Register with workloop */
	register_workloop_for_port(sr_port, workloop_cb);

	/* Send the message */
	kr = mach_msg2(data_vec, MACH64_SEND_MSG | MACH64_SEND_MQ_CALL | MACH64_MSG_VECTOR,
	    buffer.msg.header, 2, 0, sr_port, 0, 0);
	T_EXPECT_EQ(kr, MACH_MSG_SUCCESS, "msg send should succeed");

	/* wait for workloop_cb() */
	for (int i = 0; i < 10; i++) {
		sleep(2);
	}

	T_FAIL("mach_msg2_kevent_rcv timed out");
}
#else
T_DECL(mach_msg2_interop, "Test mach_msg2 inter-operability")
{
	T_SKIP("This test is skipped on armv7k.");
}

T_DECL(mach_msg2_combined_send_rcv, "Test mach_msg2() combined send/rcv")
{
	T_SKIP("This test is skipped on armv7k.");
}

T_DECL(mach_msg2_kevent_rcv, "Test mach_msg2() receive with kevent workloop")
{
	T_SKIP("This test is skipped on armv7k.");
}
#endif /* defined(__LP64__) || defined (__arm64__) */
