// Copyright (c) 2020 Apple Computer, Inc. All rights reserved.

#include <darwintest.h>
#include <dirent.h>
#include <inttypes.h>
#include <mach/machine.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/perfmon_private.h>
#include <sys/sysctl.h>
#include <sys/syslimits.h>
#include <unistd.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.perfmon"),
	T_META_CHECK_LEAKS(false),
	T_META_RUN_CONCURRENTLY(false),
	T_META_ASROOT(true));

#define MAX_MONITORS (8)

struct monitor_list {
	int fds[MAX_MONITORS];
	char *names[MAX_MONITORS];
	size_t length;
};

static struct monitor_list
open_monitors(void)
{
	struct monitor_list monitors = { 0 };

	T_SETUPBEGIN;

	struct dirent *entry;
	DIR *dir = opendir("/dev");
	T_WITH_ERRNO; T_QUIET; T_ASSERT_NOTNULL(dir, "opendir /dev");

	while ((entry = readdir(dir)) != NULL) {
		if (strncmp(entry->d_name, "perfmon", strlen("perfmon")) == 0) {
			char path[PATH_MAX] = { 0 };
			snprintf(path, sizeof(path), "/dev/%s", entry->d_name);

			T_SETUPEND;

			monitors.fds[monitors.length] = open(path, O_RDONLY);
			T_QUIET;
			T_ASSERT_POSIX_SUCCESS(monitors.fds[monitors.length],
			    "open %s", entry->d_name);

			T_SETUPBEGIN;

			monitors.names[monitors.length] = strdup(entry->d_name);
			T_QUIET; T_ASSERT_NOTNULL(monitors.names[monitors.length], "strdup");
			monitors.length += 1;
			if (monitors.length > MAX_MONITORS) {
				T_ASSERT_FAIL("exceeded maximum number of monitors");
			}
		}
	}

	T_SETUPEND;

	return monitors;
}

static void
close_monitors(struct monitor_list *monitors)
{
	for (size_t i = 0; i < monitors->length; i++) {
		close(monitors->fds[i]);
		free(monitors->names[i]);
	}
}

T_DECL(layout, "ensure layout can be read from available monitors")
{
	struct monitor_list monitors = open_monitors();
	if (monitors.length == 0) {
		T_SKIP("no monitors present");
	}

	for (size_t i = 0; i < monitors.length; i++) {
		struct perfmon_layout layout = { 0 };
		const char *name = monitors.names[i];
		int ret = ioctl(monitors.fds[i], PERFMON_CTL_GET_LAYOUT, &layout);
		T_ASSERT_POSIX_SUCCESS(ret, "ioctl %s PERFMON_CTL_GET_LAYOUT",
		    monitors.names[i]);

		T_QUIET;
		T_EXPECT_GT(layout.pl_counter_count, (unsigned short)0,
		    "%s: non-zero counters", name);
		T_QUIET;
		T_EXPECT_GT(layout.pl_unit_count, (unsigned short)0,
		    "%s: non-zero monitors", name);
		T_QUIET;
		T_EXPECT_GT(layout.pl_reg_count, (unsigned short)0,
		    "%s: non-zero registers", name);
	}
}

T_DECL(registers, "ensure registers can be read from available monitors")
{
	struct monitor_list monitors = open_monitors();
	if (monitors.length == 0) {
		T_SKIP("no monitors present");
	}

	for (size_t i = 0; i < monitors.length; i++) {
		const char *name = monitors.names[i];

		T_SETUPBEGIN;

		struct perfmon_layout layout = { 0 };
		int ret = ioctl(monitors.fds[i], PERFMON_CTL_GET_LAYOUT, &layout);
		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(ret, "ioctl %s PERFMON_CTL_GET_LAYOUT",
		    monitors.names[i]);

		if (layout.pl_reg_count == 0) {
			T_LOG("skipping %s: no registers", name);
			continue;
		}

		perfmon_name_t *names = calloc(layout.pl_reg_count,
		    sizeof(names[0]));
		T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(names, "calloc");

		uint64_t *values = calloc(
			layout.pl_reg_count * layout.pl_unit_count,
			sizeof(values[0]));
		T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(names, "calloc");

		T_SETUPEND;

		ret = ioctl(monitors.fds[i], PERFMON_CTL_LIST_REGS, names);
		T_ASSERT_POSIX_SUCCESS(ret, "ioctl %s PERFMON_CTL_LIST_REGS", name);
		printf("%s registers:", name);
		for (unsigned short j = 0; j < layout.pl_reg_count; j++) {
			if (j != 0) {
				printf(", ");
			}
			if (j % 4 == 0) {
				printf("\n%4s", "");
			}
			printf("%18s", names[j]);
		}
		printf("\n");

		ret = ioctl(monitors.fds[i], PERFMON_CTL_SAMPLE_REGS, values);
		T_ASSERT_POSIX_SUCCESS(ret, "ioctl %s PERFMON_CTL_SAMPLE_REGS", name);
		for (unsigned short j = 0; j < layout.pl_unit_count; j++) {
			printf("%2d: ", j);
			for (unsigned short k = 0; k < layout.pl_reg_count;
			    k++) {
				if (k != 0) {
					printf(", ");
					if (k % 4 == 0) {
						printf("\n%4s", "");
					}
				}

				uint64_t value = values[j * layout.pl_reg_count + k];
				printf("0x%016" PRIx64, value);
			}
			printf("\n");
		}
	}
}

T_DECL(presence, "ensure perfmon is available on supported hardware")
{
	struct monitor_list monitors = open_monitors();

#if defined(__arm64__)
	T_ASSERT_GT(monitors.length, (size_t)0,
	    "ARM64 devices should have monitors");

	bool found_core = false;
	bool found_uncore = false;
	for (size_t i = 0; i < monitors.length; i++) {
		if (strcmp(monitors.names[i], "perfmon_core") == 0) {
			found_core = true;
		} else if (strcmp(monitors.names[i], "perfmon_uncore") == 0) {
			found_uncore = true;
		}
	}
	T_EXPECT_TRUE(found_core, "all ARM64 devices should expose core PMU");

	T_SETUPBEGIN;

	int subtype = 0;
	size_t subtype_size = sizeof(subtype);
	int ret = sysctlbyname("hw.cpusubtype", &subtype, &subtype_size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "sysctlbyname hw.cpusubtype");

	T_SETUPEND;

	if (access("/dev/monotonic/uncore", O_RDONLY) == 0) {
		T_EXPECT_TRUE(found_uncore,
		    "any device supported by Monotonic devices should have uncore PMU");
	}

#else // defined(__arm64__)
#pragma unused(monitors)
	T_SKIP("non-ARM64 devices unsupported");
#endif // !defined(__arm64__)
}

T_DECL(open_close_stress, "ensure that the files can be opened and closed")
{
	const int n = 100;
	for (int i = 0; i < n; i++) {
		struct monitor_list monitors = open_monitors();
		if (monitors.length == 0) {
			if (i == 0) {
				T_SKIP("no monitors present");
			} else {
				T_ASSERT_FAIL("failed to open monitors");
			}
		}
		close_monitors(&monitors);
	}

	T_PASS("passed %d cycles", n);
}
