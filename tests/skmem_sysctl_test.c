#include <stdlib.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <skywalk/os_skywalk_private.h>

#include <darwintest.h>


/*
 * Get all entries in the kernel oid, by calling sysctlbyname twice.
 */
static int
sysctl_get_all(const char *oid_name, void **buffer, size_t *len, void *newp,
    size_t newlen)
{
	int ret;

	*buffer = NULL;
	T_ASSERT_POSIX_SUCCESS(ret = sysctlbyname(oid_name, NULL, len, NULL, 0),
	    NULL);
	if (*len == 0) {
		/* There's no entry in this oid. */
		*buffer = NULL;
		return 0;
	}
	T_EXPECT_NOTNULL(*buffer = malloc(*len), NULL);
	T_ASSERT_POSIX_SUCCESS(ret = sysctlbyname(oid_name, *buffer, len, newp,
	    newlen), NULL);
	if (ret != 0) {
		if (errno == ENOMEM) {
			free(*buffer);
			*buffer = NULL;
		}
	}
	return 0;
}

/*
 * Get the given amount of data (*len) from the kernel oid, which has total_size
 * amount of data.
 */
static int
sysctl_get(const char *oid_name, void **buffer, size_t *len, size_t total_size)
{
	int ret;

	ret = sysctlbyname(oid_name, *buffer, len, NULL, 0);
	/*
	 * If we ask for less than what the kernel has, sysctlbyname for
	 * SK_STATS_ARENA, SK_STATS_REGION, and SK_STATS_CACHE will return -1
	 * and set errno to ENOMEM.
	 * If we ask for more than what the kernel has, sysctlbyname for the
	 * aforementioned oids will return 0 and set the *len to the size
	 * mantinated by the kernel.
	 */
	if (*len < total_size) {
		T_ASSERT_EQ(ret, -1, NULL);
		T_ASSERT_EQ(errno, ENOMEM, NULL);
	} else {
		T_ASSERT_POSIX_SUCCESS(ret, NULL);
		T_ASSERT_EQ(*len, total_size, NULL);
	}

	return ret;
}

T_DECL(skmem_arena_sysctl_get_all, "Get all entries in kern.skywalk.stats.arena")
{
	void *buffer;
	size_t len;

	(void) sysctl_get_all(SK_STATS_ARENA, &buffer, &len, NULL, 0);
}

T_DECL(skmem_region_sysctl_get_all, "Get all entries in kern.skywalk.stats.region")
{
	void *buffer;
	size_t len;

	(void) sysctl_get_all(SK_STATS_REGION, &buffer, &len, NULL, 0);
}

T_DECL(skmem_cache_sysctl_get_all, "Get all entries in kern.skywalk.stats.cache")
{
	void *buffer;
	size_t len;

	(void) sysctl_get_all(SK_STATS_CACHE, &buffer, &len, NULL, 0);
}

T_DECL(skmem_arena_sysctl_get_single, "Get a single entry in kern.skywalk.stats.arena")
{
	void *buffer;
	size_t len;
	size_t total_size;

	T_ASSERT_POSIX_SUCCESS(sysctlbyname(SK_STATS_ARENA, NULL, &total_size,
	    NULL, 0), NULL);
	len = sizeof(struct sk_stats_arena);
	buffer = malloc(len);

	T_LOG("Total size of %s: %zu\n", SK_STATS_ARENA, total_size);
	T_LOG("Size of single entry: %zu\n", len);
	(void) sysctl_get(SK_STATS_ARENA, &buffer, &len, total_size);
}

T_DECL(skmem_region_sysctl_get_single, "Get a single entry in kern.skywalk.stats.region")
{
	void *buffer;
	size_t len;
	size_t total_size;

	T_ASSERT_POSIX_SUCCESS(sysctlbyname(SK_STATS_REGION, NULL, &total_size,
	    NULL, 0), NULL);
	len = sizeof(struct sk_stats_region);
	buffer = malloc(len);

	T_LOG("Total size of %s: %zu\n", SK_STATS_REGION, total_size);
	T_LOG("Size of single entry: %zu\n", len);
	(void) sysctl_get(SK_STATS_REGION, &buffer, &len, total_size);
}

T_DECL(skmem_cache_sysctl_get_single, "Get a single entry in kern.skywalk.stats.cache")
{
	void *buffer;
	size_t len;
	size_t total_size;

	T_ASSERT_POSIX_SUCCESS(sysctlbyname(SK_STATS_CACHE, NULL, &total_size,
	    NULL, 0), NULL);
	len = sizeof(struct sk_stats_cache);
	buffer = malloc(len);

	T_LOG("Total size of %s: %zu\n", SK_STATS_CACHE, total_size);
	T_LOG("Size of single entry: %zu\n", len);
	(void) sysctl_get(SK_STATS_CACHE, &buffer, &len, total_size);
}

T_DECL(skmem_arena_sysctl_get_over, "Ask for more entries than kern.skywalk.stats.arena")
{
	void *buffer;
	size_t len;
	size_t total_size;

	T_ASSERT_POSIX_SUCCESS(sysctlbyname(SK_STATS_ARENA, NULL, &total_size,
	    NULL, 0), NULL);
	len = total_size + sizeof(struct sk_stats_arena);
	buffer = malloc(len);

	T_LOG("Total size of %s: %zu\n", SK_STATS_ARENA, total_size);
	T_LOG("Total size + single entry: %zu\n", len);
	(void) sysctl_get(SK_STATS_ARENA, &buffer, &len, total_size);
}

T_DECL(skmem_region_sysctl_get_over, "Ask for more entries than kern.skywalk.stats.region")
{
	void *buffer;
	size_t len;
	size_t total_size;

	T_ASSERT_POSIX_SUCCESS(sysctlbyname(SK_STATS_REGION, NULL, &total_size,
	    NULL, 0), NULL);
	len = total_size + sizeof(struct sk_stats_region);
	buffer = malloc(len);

	T_LOG("Total size of %s: %zu\n", SK_STATS_REGION, total_size);
	T_LOG("Total size + single entry: %zu\n", len);
	(void) sysctl_get(SK_STATS_REGION, &buffer, &len, total_size);
}

T_DECL(skmem_cache_sysctl_get_over, "Ask for more entries than kern.skywalk.stats.cache")
{
	void *buffer;
	size_t len;
	size_t total_size;

	T_ASSERT_POSIX_SUCCESS(sysctlbyname(SK_STATS_CACHE, NULL, &total_size,
	    NULL, 0), NULL);
	len = total_size + sizeof(struct sk_stats_cache);
	buffer = malloc(len);

	T_LOG("Total size of %s: %zu\n", SK_STATS_CACHE, total_size);
	T_LOG("Total size + single entry: %zu\n", len);
	(void) sysctl_get(SK_STATS_CACHE, &buffer, &len, total_size);
}
