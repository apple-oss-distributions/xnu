/*
 * Copyright (c) 2025 Apple Inc. All rights reserved.
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

#include <darwintest.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/tcp_private.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking")
	);

/*
 * Helper function: Create a TCP loopback connection
 * Returns client_fd and server_fd, fills in local and remote sockaddr_in
 */
static int
create_tcp_loopback_connection(int *client_fd, int *server_fd,
    struct sockaddr_in *local_addr, struct sockaddr_in *remote_addr)
{
	int server_listen_fd = -1;
	int client_sock = -1;
	int server_sock = -1;
	struct sockaddr_in server_bind_addr;
	socklen_t addr_len;
	int optval = 1;

	/* Create server listening socket */
	server_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(server_listen_fd, "socket() for server");

	/* Set SO_REUSEADDR */
	T_QUIET; T_ASSERT_POSIX_SUCCESS(
		setsockopt(server_listen_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)),
		"setsockopt(SO_REUSEADDR)");

	/* Bind to loopback with port 0 (let kernel assign port) */
	memset(&server_bind_addr, 0, sizeof(server_bind_addr));
	server_bind_addr.sin_family = AF_INET;
	server_bind_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	server_bind_addr.sin_port = 0;

	T_QUIET; T_ASSERT_POSIX_SUCCESS(
		bind(server_listen_fd, (struct sockaddr *)&server_bind_addr, sizeof(server_bind_addr)),
		"bind() server to loopback");

	/* Get the assigned port */
	addr_len = sizeof(server_bind_addr);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(
		getsockname(server_listen_fd, (struct sockaddr *)&server_bind_addr, &addr_len),
		"getsockname() on server");

	T_LOG("Server listening on 127.0.0.1:%d", ntohs(server_bind_addr.sin_port));

	/* Start listening */
	T_QUIET; T_ASSERT_POSIX_SUCCESS(listen(server_listen_fd, 1), "listen()");

	/* Create client socket and connect */
	client_sock = socket(AF_INET, SOCK_STREAM, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(client_sock, "socket() for client");

	T_QUIET; T_ASSERT_POSIX_SUCCESS(
		connect(client_sock, (struct sockaddr *)&server_bind_addr, sizeof(server_bind_addr)),
		"connect() client to server");

	/* Accept connection on server side */
	addr_len = sizeof(*remote_addr);
	server_sock = accept(server_listen_fd, (struct sockaddr *)remote_addr, &addr_len);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(server_sock, "accept() on server");

	/* Close listening socket, no longer needed */
	close(server_listen_fd);

	/* Get local address of server socket */
	addr_len = sizeof(*local_addr);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(
		getsockname(server_sock, (struct sockaddr *)local_addr, &addr_len),
		"getsockname() on accepted socket");

	/* Exchange some data to ensure ESTABLISHED state */
	char buf[16] = "hello";
	T_QUIET; T_ASSERT_POSIX_SUCCESS(send(client_sock, buf, 5, 0), "send() from client");
	T_QUIET; T_ASSERT_POSIX_SUCCESS(recv(server_sock, buf, 5, 0), "recv() on server");

	*client_fd = client_sock;
	*server_fd = server_sock;

	T_LOG("TCP connection established: 127.0.0.1:%d <-> 127.0.0.1:%d",
	    ntohs(local_addr->sin_port), ntohs(remote_addr->sin_port));

	return 0;
}

/*
 * Helper function: Build info_tuple from local and remote addresses
 */
static void
build_info_tuple(struct sockaddr_in *local, struct sockaddr_in *remote, struct info_tuple *tuple)
{
	memset(tuple, 0, sizeof(*tuple));
	tuple->itpl_proto = IPPROTO_TCP;
	memcpy(&tuple->itpl_local_sin, local, sizeof(struct sockaddr_in));
	memcpy(&tuple->itpl_remote_sin, remote, sizeof(struct sockaddr_in));
}

/*
 * Helper function: Query tcp_info via sysctl
 * Returns 0 on success, errno on failure
 */
static int
query_tcp_info(struct info_tuple *tuple, struct tcp_info *info)
{
	size_t info_len = sizeof(*info);
	int ret;

	memset(info, 0, sizeof(*info));

	ret = sysctlbyname("net.inet.tcp.info", info, &info_len, tuple, sizeof(*tuple));
	if (ret != 0) {
		return errno;
	}

	return 0;
}

/*
 * Helper function: Validate tcp_info structure has reasonable values
 */
static void
validate_tcp_info(struct tcp_info *info)
{
	T_LOG("tcp_info: state=%u, snd_nxt=%u, rcv_nxt=%u, snd_cwnd=%u",
	    info->tcpi_state, info->tcpi_snd_nxt, info->tcpi_rcv_nxt, info->tcpi_snd_cwnd);

	/* Basic sanity checks */
	T_ASSERT_TRUE(info->tcpi_state > 0 && info->tcpi_state <= 11,
	    "tcp_info state should be valid (got %u)", info->tcpi_state);

	/* For an established connection, sequence numbers should be non-zero */
	if (info->tcpi_state == 4) { /* TCPS_ESTABLISHED */
		T_ASSERT_GT(info->tcpi_snd_nxt, 0u, "snd_nxt should be non-zero for established connection");
		T_ASSERT_GT(info->tcpi_rcv_nxt, 0u, "rcv_nxt should be non-zero for established connection");
	}
}

/*
 * Test 1: Root can query any TCP connection
 */
T_DECL(tcp_info_sysctl_as_root,
    "root can query TCP connection via net.inet.tcp.info",
    T_META_ASROOT(true))
{
	int client_fd = -1, server_fd = -1;
	struct sockaddr_in local_addr, remote_addr;
	struct info_tuple tuple;
	struct tcp_info info;
	int ret;

	T_LOG("Testing net.inet.tcp.info sysctl as root");

	/* Create TCP loopback connection */
	T_ASSERT_POSIX_ZERO(
		create_tcp_loopback_connection(&client_fd, &server_fd, &local_addr, &remote_addr),
		"create TCP connection");

	/* Build info_tuple to identify the connection */
	build_info_tuple(&local_addr, &remote_addr, &tuple);

	/* Query sysctl - should succeed as root */
	ret = query_tcp_info(&tuple, &info);
	T_ASSERT_EQ(ret, 0, "root should be able to query tcp_info (got errno %d: %s)",
	    ret, ret ? strerror(ret) : "success");

	/* Validate returned tcp_info */
	validate_tcp_info(&info);

	/* Cleanup */
	close(client_fd);
	close(server_fd);

	T_PASS("Root can query TCP connection info");
}

/*
 * Test 2: Socket owner can query own connection (without root or entitlement)
 */
T_DECL(tcp_info_sysctl_owner,
    "socket owner can query own TCP connection",
    T_META_ASROOT(false))
{
	int client_fd = -1, server_fd = -1;
	struct sockaddr_in local_addr, remote_addr;
	struct info_tuple tuple;
	struct tcp_info info;
	int ret;

	/* Drop privileges if running as root */
	if (geteuid() == 0) {
		T_LOG("Dropping privileges to test as socket owner");
		T_ASSERT_POSIX_ZERO(setuid(getuid()), "setuid");
	}

	T_LOG("Testing net.inet.tcp.info sysctl as socket owner (non-root, no entitlement)");
	T_LOG("Running as uid=%u, euid=%u, pid=%d", getuid(), geteuid(), getpid());

	/* Create TCP loopback connection (we own these sockets) */
	T_ASSERT_POSIX_ZERO(
		create_tcp_loopback_connection(&client_fd, &server_fd, &local_addr, &remote_addr),
		"create TCP connection");

	/* Build info_tuple */
	build_info_tuple(&local_addr, &remote_addr, &tuple);

	/* Query sysctl - should succeed because we own the socket */
	ret = query_tcp_info(&tuple, &info);
	T_ASSERT_EQ(ret, 0, "socket owner should be able to query own connection (got errno %d: %s)",
	    ret, ret ? strerror(ret) : "success");

	/* Validate returned tcp_info */
	validate_tcp_info(&info);

	/* Cleanup */
	close(client_fd);
	close(server_fd);

	T_PASS("Socket owner can query own TCP connection");
}

/*
 * Test 3: Unprivileged process gets ENOENT for foreign connection
 */
T_DECL(tcp_info_sysctl_no_priv,
    "unprivileged process gets ENOENT for foreign connection",
    T_META_ASROOT(false))
{
	int client_fd = -1, server_fd = -1;
	struct sockaddr_in local_addr, remote_addr;
	pid_t child_pid;
	int status;

	/* Verify we're not the entitled binary */
	if (strstr(getprogname(), "entitled") != NULL) {
		T_SKIP("This test must run without entitlement");
	}

	/* Drop privileges if running as root */
	if (geteuid() == 0) {
		T_SKIP("This test must not run as root");
	}

	T_LOG("Testing net.inet.tcp.info sysctl as unprivileged process querying foreign connection");

	/* Create TCP connection as root (parent process owns it) */
	T_ASSERT_POSIX_ZERO(
		create_tcp_loopback_connection(&client_fd, &server_fd, &local_addr, &remote_addr),
		"create TCP connection as root");

	/* Fork child process to test unprivileged access */
	child_pid = fork();
	T_ASSERT_POSIX_SUCCESS(child_pid, "fork()");

	if (child_pid == 0) {
		/* Child process */
		struct info_tuple tuple;
		struct tcp_info info;
		int ret;

		/* Drop to non-root */
		T_ASSERT_POSIX_ZERO(setuid(getuid()), "setuid");
		T_LOG("Child process: uid=%u, euid=%u, pid=%d", getuid(), geteuid(), getpid());

		/* Build info_tuple for parent's connection */
		build_info_tuple(&local_addr, &remote_addr, &tuple);

		/* Try to query parent's connection (different PID, no root, no entitlement) */
		ret = query_tcp_info(&tuple, &info);

		/* Should get ENOENT */
		if (ret == ENOENT) {
			T_LOG("Child: Got expected ENOENT when querying foreign connection");
			exit(0);
		} else {
			T_LOG("Child: Got unexpected result: %d (%s)", ret, ret ? strerror(ret) : "success");
			exit(1);
		}
	}

	/* Parent: wait for child */
	T_ASSERT_POSIX_SUCCESS(waitpid(child_pid, &status, 0), "waitpid()");
	T_ASSERT_TRUE(WIFEXITED(status), "child should exit normally");
	T_ASSERT_EQ(WEXITSTATUS(status), 0, "child test should pass");

	/* Cleanup */
	close(client_fd);
	close(server_fd);

	T_PASS("Unprivileged process gets ENOENT for foreign connection");
}

/*
 * Test 4: Process with entitlement can query foreign connection
 */
T_DECL(tcp_info_sysctl_entitled,
    "process with entitlement can query foreign connection",
    T_META_ASROOT(false))
{
	int pipefd[2];
	pid_t child_pid;
	int status;

	/* Check if we're the entitled binary */
	if (strstr(getprogname(), "entitled") == NULL) {
		T_SKIP("This test requires the entitled binary variant");
	}

	T_LOG("Testing net.inet.tcp.info sysctl as entitled process querying foreign connection");

	/* Create pipe for communication */
	T_ASSERT_POSIX_SUCCESS(pipe(pipefd), "pipe()");

	/* Fork child process to create connection */
	child_pid = fork();
	T_ASSERT_POSIX_SUCCESS(child_pid, "fork()");

	if (child_pid == 0) {
		/* Child process: create connection and send info to parent */
		int client_fd, server_fd;
		struct sockaddr_in local_addr, remote_addr;

		close(pipefd[0]); /* Close read end */

		/* Create TCP connection (child owns it) */
		create_tcp_loopback_connection(&client_fd, &server_fd, &local_addr, &remote_addr);

		/* Send connection info to parent */
		write(pipefd[1], &local_addr, sizeof(local_addr));
		write(pipefd[1], &remote_addr, sizeof(remote_addr));

		T_LOG("Child: Created connection, sleeping to keep it alive");

		/* Keep connection alive while parent queries */
		sleep(5);

		close(client_fd);
		close(server_fd);
		close(pipefd[1]);
		exit(0);
	}

	/* Parent process: query child's connection with entitlement */
	close(pipefd[1]); /* Close write end */

	struct sockaddr_in local_addr, remote_addr;
	struct info_tuple tuple;
	struct tcp_info info;
	int ret;

	/* Read connection info from child */
	T_ASSERT_EQ((int)read(pipefd[0], &local_addr, sizeof(local_addr)),
	    (int)sizeof(local_addr), "read local_addr from child");
	T_ASSERT_EQ((int)read(pipefd[0], &remote_addr, sizeof(remote_addr)),
	    (int)sizeof(remote_addr), "read remote_addr from child");

	close(pipefd[0]);

	T_LOG("Parent: Querying child's connection as entitled non-root process");
	T_LOG("Parent: uid=%u, euid=%u, pid=%d", getuid(), geteuid(), getpid());

	/* Build info_tuple for child's connection */
	build_info_tuple(&local_addr, &remote_addr, &tuple);

	/* Query sysctl - should succeed because we have entitlement */
	ret = query_tcp_info(&tuple, &info);
	T_ASSERT_EQ(ret, 0, "entitled process should be able to query foreign connection (got errno %d: %s)",
	    ret, ret ? strerror(ret) : "success");

	/* Validate returned tcp_info */
	validate_tcp_info(&info);

	/* Wait for child to exit */
	T_ASSERT_POSIX_SUCCESS(waitpid(child_pid, &status, 0), "waitpid()");

	T_PASS("Entitled process can query foreign TCP connection");
}
