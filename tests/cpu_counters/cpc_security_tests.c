// Copyright 2023 (c) Apple Inc.  All rights reserved.

#include <darwintest.h>
#include <darwintest_utils.h>
#include <dirent.h>
#include <kperf/kpc.h>
#include <kperfdata/kpep.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <sys/guarded.h>
#include <sys/ioctl.h>
#include <sys/monotonic.h>

#include "test_utils.h"

#if __arm64__
#define HAS_CPC_SECURITY true
#else // __arm64__
#define HAS_CPC_SECURITY false
#endif // !__arm64__

#define _T_META_REQUIRES_CPC_SUPPORT \
	T_META_REQUIRES_SYSCTL_EQ("kern.monotonic.supported", "1")

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.cpc"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("cpu counters"),
	T_META_OWNER("mwidmann"),
	T_META_CHECK_LEAKS(false),
	XNU_T_META_SOC_SPECIFIC,
	T_META_ENABLED(HAS_CPC_SECURITY),
	_T_META_REQUIRES_CPC_SUPPORT);

// Several of these tests have two variants to support running on development and release kernels.
// Tests prefixed with `secure_` put the development kernel into a secure CPC mode while tests prefixed with `release_` can run on the RELEASE build variant.

// Metadata for running on a development kernel in CPC secure mode.
//
// This should require kern.development to be 1 with XNU_T_META_REQUIRES_DEVELOPMENT_KERNEL,
// but libdarwintest has a bug (rdar://111297938) preventing that.
// In the meantime, manually check in the test whether the kernel is DEVELOPMENT.
#define _T_META_CPC_SECURE_ON_DEV T_META_SYSCTL_INT("kern.cpc.secure=1")

static void
_skip_unless_development(void)
{
	unsigned int dev = 0;
	size_t dev_size = sizeof(dev);
	int ret = sysctlbyname("kern.development", &dev, &dev_size, NULL, 0);
	if (ret < 0 || dev) {
		T_SKIP("test must run on DEVELOPMENT kernel");
	}
}

static void
_assert_kpep_ok(int kpep_err, const char *fmt, ...)
{
	char msg[1024] = "";
	va_list args;
	va_start(args, fmt);
	vsnprintf(msg, sizeof(msg), fmt, args);
	va_end(args);
	T_QUIET;
	T_ASSERT_EQ(kpep_err, KPEP_ERR_NONE, "%s: %s", msg, kpep_strerror(kpep_err));
}

static void
_skip_for_db(const char *kind, int kpep_err)
{
	const char * const public_kpep_path = "/usr/share/kpep";
	const char * const internal_kpep_path = "/usr/local/share/kpep";
	const char * const paths[2] = { public_kpep_path, internal_kpep_path, };
	for (int i = 0; i < 2; i++) {
		const char * const path = paths[i];
		T_LOG("contents of %s:", path);
		DIR *dir = opendir(path);
		if (dir) {
			struct dirent *entry = NULL;
			while ((entry = readdir(dir)) != NULL) {
				T_LOG("    %s", entry->d_name);
			}
			(void)closedir(dir);
		} else {
			T_LOG("failed to open directory: %s", strerror(errno));
		}
	}
	int cpu_family = 0;
	size_t family_size = sizeof(cpu_family);
	int ret = sysctlbyname("hw.cpufamily", &cpu_family, &family_size, NULL, 0);
	if (ret != 0) {
		T_LOG("HW CPU family: 0x%8x", cpu_family);
	} else {
		T_LOG("failed to get hw.cpufamily: %s", strerror(errno));
	}
	T_SKIP("cannot open %s event database: %s", kind, kpep_strerror(kpep_err));
}

// Check that a secure kernel disallows restricted events.

static void
check_secure_cpmu(void)
{
	kpep_db_t public_db = NULL;
	int ret = kpep_db_createx(NULL, KPEP_DB_FLAG_PUBLIC_ONLY, &public_db);
	if (ret != KPEP_ERR_NONE) {
		_skip_for_db("public", ret);
	}
	kpep_db_t internal_db = NULL;
	ret = kpep_db_createx(NULL, KPEP_DB_FLAG_INTERNAL_ONLY, &internal_db);
	if (ret != KPEP_ERR_NONE) {
		_skip_for_db("internal", ret);
	}
	const char *na = NULL;
	kpep_db_name(public_db, &na);

	size_t internal_event_count = 0;
	ret = kpep_db_events_count(internal_db, &internal_event_count);
	_assert_kpep_ok(ret, "getting internal event count");

	kpep_event_t *internal_events = calloc(internal_event_count,
	    sizeof(internal_events[0]));
	T_QUIET; T_WITH_ERRNO;
	T_ASSERT_NOTNULL(internal_events, "allocate space for internal events");

	ret = kpep_db_events(internal_db, internal_events,
	    internal_event_count * sizeof(internal_events[0]));
	_assert_kpep_ok(ret, "getting internal events");

	kpep_config_t config = NULL;
	ret = kpep_config_create(internal_db, &config);
	_assert_kpep_ok(ret, "creating event configuration");
	ret = kpep_config_force_counters(config);
	_assert_kpep_ok(ret, "forcing counters with configuration");

	unsigned int tested = 0;
	unsigned int filtered = 0;
	unsigned int public_tested = 0;
	for (size_t i = 0; i < internal_event_count; i++) {
		kpep_event_t event = internal_events[i];
		const char *name = NULL;
		ret = kpep_event_alias(event, &name);
		if (!name) {
			ret = kpep_event_name(event, &name);
		}
		_assert_kpep_ok(ret, "getting event name");
		if (strncmp(name, "FIXED", strlen("FIXED")) == 0) {
			T_LOG("skipping non-configurable %s event", name);
			continue;
		}
		bool empty_event = strcmp(name, "NO_EVNT") == 0;
		if (empty_event) {
			continue;
		}

		kpep_event_t public_event = NULL;
		ret = kpep_db_event(public_db, name, &public_event);
		bool internal_only = ret == KPEP_ERR_EVENT_NOT_FOUND;
		ret = kpep_config_add_event(config, &event, 0, NULL);
		_assert_kpep_ok(ret, "adding event %s to configuration", name);

		ret = kpep_config_apply(config);
		bool not_permitted = ret == KPEP_ERR_ERRNO && errno == EPERM;
		if (not_permitted) {
			if (!internal_only) {
				T_LOG("failed to configure public event %s", name);
			}
			filtered++;
		} else if (internal_only) {
			T_FAIL("configured internal-only event %s with secure CPC", name);
		} else {
			public_tested++;
		}
		ret = kpep_config_remove_event(config, 0);
		_assert_kpep_ok(ret, "removing event %s from configuration", name);
		tested++;
	}

	T_LOG("tested %u internal/public events", tested);
	T_LOG("correctly permitted to configure %u public events", public_tested);
	T_LOG("correctly not permitted to configure %u internal-only events",
	    filtered);
	kpep_config_free(config);
	kpep_db_free(public_db);
	kpep_db_free(internal_db);
}

T_DECL(secure_cpmu_event_restrictions, "secured CPMU should be restricted to known events",
    _T_META_CPC_SECURE_ON_DEV)
{
	_skip_unless_development();
	check_secure_cpmu();
}

T_DECL(release_cpmu_event_restrictions, "release CPMU should be restricted to known events",
    XNU_T_META_REQUIRES_RELEASE_KERNEL)
{
	check_secure_cpmu();
}

#define UNCORE_DEV_PATH "/dev/monotonic/uncore"
#define UPMU_REF_CYCLES 0x02

static void
check_secure_upmu(void)
{
	guardid_t guard;
	int fd;

	guard = 0xa5adcafe;

	T_SETUPBEGIN;

	fd = guarded_open_np(UNCORE_DEV_PATH, &guard,
	    GUARD_CLOSE | GUARD_DUP | GUARD_WRITE, O_CLOEXEC | O_EXCL);
	if (fd < 0 && errno == ENOENT) {
		T_SKIP("uncore counters are unsupported");
	}

	union monotonic_ctl_add add_ctl = {
		.in.config.event = UPMU_REF_CYCLES,
		.in.config.allowed_ctr_mask = 0xffff,
	};

	T_SETUPEND;

	int ret = ioctl(fd, MT_IOC_ADD, &add_ctl);
	T_EXPECT_POSIX_FAILURE(ret, EPERM,
	    "should not be allowed to count any events on UPMU");
}

T_DECL(secure_upmu_event_restrictions, "secured UPMU should be restricted to no events",
    _T_META_CPC_SECURE_ON_DEV)
{
	_skip_unless_development();
	check_secure_upmu();
}

T_DECL(release_upmu_event_restrictions, "release UPMU should be restricted to no events",
    XNU_T_META_REQUIRES_RELEASE_KERNEL)
{
	check_secure_upmu();
}

// Check that events which are exposed publicly are allowed to be configured.

static void
check_event_coverage(kpep_db_flags_t flag, const char *kind)
{
	kpep_db_t db = NULL;
	int ret = kpep_db_createx(NULL, flag, &db);
	_assert_kpep_ok(ret, "creating %s event database", kind);

	size_t event_count = 0;
	ret = kpep_db_events_count(db, &event_count);
	_assert_kpep_ok(ret, "getting %s event count", kind);

	kpep_event_t *events = calloc(event_count, sizeof(events[0]));
	T_QUIET; T_WITH_ERRNO;
	T_ASSERT_NOTNULL(events, "allocate space for events");

	ret = kpep_db_events(db, events, event_count * sizeof(events[0]));
	_assert_kpep_ok(ret, "getting public events");

	kpep_config_t config = NULL;
	ret = kpep_config_create(db, &config);
	_assert_kpep_ok(ret, "creating event configuration");
	ret = kpep_config_force_counters(config);
	_assert_kpep_ok(ret, "forcing counters with configuration");

	unsigned int tested = 0;
	for (size_t i = 0; i < event_count; i++) {
		kpep_event_t event = events[i];
		const char *name = NULL;
		ret = kpep_event_name(event, &name);
		_assert_kpep_ok(ret, "getting event name");
		if (strncmp(name, "FIXED", strlen("FIXED")) == 0) {
			T_LOG("skipping non-configurable %s event", name);
			continue;
		}

		ret = kpep_config_add_event(config, &event, 0, NULL);
		_assert_kpep_ok(ret, "adding event %s to configuration", name);

		ret = kpep_config_apply(config);
		if (ret == KPEP_ERR_ERRNO && errno == EPERM) {
			T_FAIL("failed to configure %s event %s with secure CPC", kind, name);
		} else {
			_assert_kpep_ok(ret, "applying configuration with event %s", name);
		}
		ret = kpep_config_remove_event(config, 0);
		_assert_kpep_ok(ret, "removing event %s from configuration", name);
		tested++;
	}

	T_LOG("successfully configured %u %s events", tested, kind);
	kpep_config_free(config);
	kpep_db_free(db);
}

T_DECL(secure_public_event_coverage, "all public events in kpep should be allowed",
    _T_META_CPC_SECURE_ON_DEV)
{
	_skip_unless_development();
	check_event_coverage(KPEP_DB_FLAG_PUBLIC_ONLY, "public");
}

T_DECL(release_public_event_coverage, "all public events in kpep should be allowed",
    XNU_T_META_REQUIRES_RELEASE_KERNEL)
{
	check_event_coverage(KPEP_DB_FLAG_PUBLIC_ONLY, "public");
}

// Check for internal development behaviors.

T_DECL(insecure_cpmu_unrestricted, "insecure CPMU should be unrestricted",
    XNU_T_META_REQUIRES_DEVELOPMENT_KERNEL, T_META_SYSCTL_INT("kern.cpc.secure=0"))
{
	check_event_coverage(KPEP_DB_FLAG_INTERNAL_ONLY, "internal");
}
