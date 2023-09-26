#include <pthread.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <darwintest.h>

#define BASE_PORT 2020

static int port = BASE_PORT;
static bool server_ready = false;

static void
client(void)
{
	int i = 0;
	while (i < 9000) {
		int sock = socket(PF_INET, SOCK_STREAM, 0);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(sock, "socket");
		struct sockaddr_in raddr;
		raddr.sin_family = AF_INET;
		raddr.sin_port = htons(port);
		raddr.sin_addr.s_addr = inet_addr("127.0.0.1");
		int res = connect(sock, (struct sockaddr *)&raddr, sizeof(raddr));
		if (res < 0 && (errno == EADDRNOTAVAIL || errno == ECONNREFUSED)) {
			close(sock);
			return;
		} else if (res < 0 && errno == ECONNREFUSED) {
		} else {
			T_QUIET; T_ASSERT_POSIX_SUCCESS(res, "connect");
		}
		close(sock);
		i++;
	}
}

static void *
server(void *arg __unused)
{
	int sock = socket(PF_INET, SOCK_STREAM, 0);
	T_ASSERT_POSIX_SUCCESS(sock, "socket");

	struct sockaddr_in laddr;
	laddr.sin_family = AF_INET;
	laddr.sin_port = htons(port);
	laddr.sin_addr.s_addr = 0;
	int res = bind(sock, (struct sockaddr *)&laddr, sizeof(laddr));
	if (res == -1 && errno == EADDRNOTAVAIL) {
		port = BASE_PORT;
		port += arc4random_uniform(512);
		res = bind(sock, (struct sockaddr *)&laddr, sizeof(laddr));
	}
	T_ASSERT_POSIX_SUCCESS(res, "bind");
	T_ASSERT_POSIX_SUCCESS(listen(sock, 10), "listen");
	server_ready = true;
	while (1) {
		struct sockaddr_in sin;
		socklen_t slen = sizeof(sin);
		int c = accept(sock, (struct sockaddr *)&sin, &slen);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(c, "accept");
		char buf[1];
		T_QUIET; T_ASSERT_POSIX_SUCCESS(read(c, buf, 1), "read");
		close(c);
	}
	return NULL;
}

T_DECL(accept_race,
    "Exercises a race condition between socantrcvmore() and accept()",
    T_META_CHECK_LEAKS(false))
{
	// Pick a random port
	port += arc4random_uniform(1024);

	pthread_t server_th;
	if (pthread_create(&server_th, 0, server, NULL)) {
		T_FAIL("pthread_create failed");
	}
	while (!server_ready) {
		sleep(1);
	}
	client();
}
