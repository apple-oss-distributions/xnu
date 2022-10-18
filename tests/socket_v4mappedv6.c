#include <darwintest.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

static int
sockv6_open(void)
{
	int     s;

	s = socket(AF_INET6, SOCK_DGRAM, 0);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(s, "socket(AF_INET6, SOCK_DGRAM, 0)");
	return s;
}

T_DECL(v4_mapped_v6_ops,
    "v4 mapped v6 sock operations around bind/connect",
    T_META_ASROOT(false),
    T_META_CHECK_LEAKS(false))
{
	int     s6 = -1;
	int     ret = 0;
	uint16_t port = 12345;
	struct sockaddr_in6 local = {};
	struct sockaddr_in6 remote = {};

	s6 = sockv6_open();

	local.sin6_family = AF_INET;
	local.sin6_len = sizeof(local);
	local.sin6_port = htons(port);

	T_ASSERT_EQ(inet_pton(AF_INET6, "::ffff:c000:201", &local.sin6_addr), 1, NULL);
	T_EXPECT_POSIX_FAILURE((ret = bind(s6, (const struct sockaddr *)&local, sizeof(local))), EADDRNOTAVAIL, NULL);

	remote.sin6_family = AF_INET6;
	remote.sin6_len = sizeof(remote);
	remote.sin6_port = htons(port);

	T_ASSERT_EQ(inet_pton(AF_INET6, "::", &remote.sin6_addr), 1, NULL);
	T_EXPECT_POSIX_SUCCESS(connect(s6, (struct sockaddr *)&remote, sizeof(remote)), NULL);
	T_PASS("System didn't panic!");
}
