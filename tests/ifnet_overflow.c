#include <darwintest.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>

static void __unused
create_interfaces(const char *prefix, int num)
{
	static int fd = -1;

	if (fd == -1) {
		fd = socket(PF_INET, SOCK_STREAM, 0);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(fd, "socket");
	}
	for (int i = 0; i < num; i++) {
		struct ifreq ifr = {};

		sprintf(ifr.ifr_name, "%s%d", prefix, i);
		int ret = ioctl(fd, SIOCIFCREATE, &ifr);
		if (errno == EEXIST) {
			continue;
		}
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "SIOCIFCREATE");
		memset(&ifr, 0, sizeof(ifr));
		sprintf(ifr.ifr_name, "%s%d", prefix, i);
		ret = ioctl(fd, SIOCIFDESTROY, &ifr);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "SIOCIFDESTROY");
		if (i % 100 == 0) {
			printf("created %s%d\n", prefix, i);
		}
	}
}


T_DECL(test_ifnet_overflow,
    "Verify that we don't crash when we create many interfaces",
    T_META_CHECK_LEAKS(false))
{
#if 1
	T_SKIP("Not stable yet");
#else
	create_interfaces("vlan", 32768);
	create_interfaces("feth", 32768);
#endif
}
