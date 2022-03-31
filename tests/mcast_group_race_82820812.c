#include <arpa/inet.h>
#include <pthread.h>
#include <unistd.h>
#include <darwintest.h>
#include <TargetConditionals.h>

volatile static int lock_a;
volatile static int lock_b;

static int fd;
static struct sockaddr_in saddr;

static struct ip_mreq filler_group;
static struct ip_mreq group_a;
static struct ip_mreq group_b;

#define ITERATIONS_LIMIT 1000

static void *
thread_func(__unused void* arg)
{
	lock_a = 1;
	while (lock_b == 0) {
	}

	setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &group_a, sizeof(group_a));

	return NULL;
}

T_DECL(mcast_group_race_82820812, "Race between multicast group join operations.",
    T_META_ASROOT(true),
    T_META_ENABLED(!TARGET_OS_BRIDGE && !TARGET_OS_SIMULATOR))
{
	pthread_t th;
	uint32_t i = 0;
	uint32_t j = 0;

	saddr.sin_family = AF_INET;

	group_a.imr_multiaddr.s_addr = inet_addr("224.0.0.1");
	group_b.imr_multiaddr.s_addr = inet_addr("224.0.0.2");

	for (i = 0; i < ITERATIONS_LIMIT; ++i) {
		T_ASSERT_POSIX_SUCCESS(fd = socket(AF_INET, SOCK_DGRAM, 0), "socket");
		T_ASSERT_POSIX_SUCCESS(bind(fd, (struct sockaddr *) &saddr, sizeof(saddr)), "bind");

		for (j = 0; j < IP_MIN_MEMBERSHIPS - 1; ++j) {
			filler_group.imr_multiaddr.s_addr = htonl(ntohl(inet_addr("224.0.0.3")) + j);
			setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &filler_group, sizeof(filler_group));
		}

		T_ASSERT_POSIX_ZERO(pthread_create(&th, NULL, thread_func, NULL), "pthread_create");

		while (lock_a == 0) {
		}
		lock_b = 1;

		setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &group_b, sizeof(group_b));

		T_ASSERT_POSIX_ZERO(pthread_join(th, NULL), "pthread_join");
		T_ASSERT_POSIX_SUCCESS(close(fd), "close");
	}
}
