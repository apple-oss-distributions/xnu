// Copyright (c) 2020 Apple Computer, Inc. All rights reserved.

#include <darwintest.h>
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>

#include "rump.h"

#include <sys/perfmon_private.h>

#define CONFIG_PERFMON 1
#define CPMU_PMC_COUNT 10
#define HAS_UPMU 1
#define UPMU_PMC_COUNT 16

#include "../osfmk/kern/perfmon.h"
#include "../osfmk/arm64/perfmon_arm64_regs.h"
#include "../osfmk/machine/machine_perfmon.h"
#include "../osfmk/kern/kern_perfmon.c"
#include "../osfmk/arm64/perfmon_arm64.c"

T_GLOBAL_META(T_META_NAMESPACE("xnu.perfmon"));

struct perfmon_event test_events[2] = {
	{
		.pe_name = "test",
		.pe_number = 1,
		.pe_counter = 3,
	}, {
		.pe_name = "second",
		.pe_number = 2,
		.pe_counter = 4,
	},
};

T_DECL(config_add_event_spec, "ensure events can be added to a configuration")
{
	T_SETUPBEGIN;
	perfmon_machine_startup();
	perfmon_config_t config = perfmon_config_create(&perfmon_sources[0]);
	T_QUIET; T_ASSERT_NOTNULL(config, "created config");
	T_SETUPEND;

	struct perfmon_event event = test_events[0];

	int error = perfmon_config_add_event(config, &event);
	T_ASSERT_POSIX_ZERO(error, "should add event to config");
	const struct perfmon_spec *spec = perfmon_config_specify(config);
	T_ASSERT_EQ(spec->ps_event_count, (unsigned short)1,
	    "one event added to config");

	error = perfmon_config_add_event(config, &event);
	T_ASSERT_POSIX_ERROR(error, EALREADY,
	    "should not add event to already-used counter");
	T_QUIET; T_ASSERT_EQ(spec->ps_event_count, (unsigned short)1,
	    "still one event added to config");

	event = test_events[1];
	error = perfmon_config_add_event(config, &event);
	T_ASSERT_POSIX_ZERO(error, "should add second event to config");
	T_ASSERT_EQ(spec->ps_event_count, (unsigned short)2,
	    "two events added to config");

	event.pe_counter = 20;
	error = perfmon_config_add_event(config, &event);
	T_ASSERT_POSIX_ERROR(error, ERANGE,
	    "should not add event to counter out of range");
	T_QUIET; T_ASSERT_EQ(spec->ps_event_count, (unsigned short)2,
	    "still two events added to config");

	event.pe_counter = 0;
	error = perfmon_config_add_event(config, &event);
	T_ASSERT_POSIX_ERROR(error, ENODEV,
	    "should not add event to fixed counter, error was %d", error);
	T_QUIET; T_ASSERT_EQ(spec->ps_event_count, (unsigned short)2,
	    "still two events added to config");

	error = perfmon_configure(config);
	T_ASSERT_POSIX_ZERO(error, "configured CPMU");

	event.pe_counter = 4;
	error = perfmon_config_add_event(config, &event);
	T_ASSERT_POSIX_ERROR(error, EBUSY,
	    "should not add event to already-configured config");
	T_QUIET; T_ASSERT_EQ(spec->ps_event_count, (unsigned short)2,
	    "still two events added to config");

	const struct perfmon_event *read_events = spec->ps_events;
	for (unsigned short i = 0; i < spec->ps_event_count; i++) {
		T_QUIET;
		T_ASSERT_EQ_STR(read_events[i].pe_name, test_events[i].pe_name,
		    "event %hu name matches", i);
		T_QUIET;
		T_ASSERT_EQ(read_events[i].pe_number, test_events[i].pe_number,
		    "event %hu number matches", i);
		T_QUIET;
		T_ASSERT_EQ(read_events[i].pe_counter, test_events[i].pe_counter,
		    "event %hu counter matches", i);
		T_PASS("event %hu in config matches what was set", i);
	}

	perfmon_config_destroy(config);
}

struct perfmon_attr test_attrs[2] = {
	{
		.pa_name = "PMCR2",
		.pa_value = 0x123
	}, {
		.pa_name = "OPMAT0",
		.pa_value = 0x123,
	},
};

T_DECL(config_set_attr_spec, "ensure attributes can be set on a configuration")
{
	T_SETUPBEGIN;
	perfmon_machine_startup();
	perfmon_config_t config = perfmon_config_create(&perfmon_sources[0]);
	T_QUIET; T_ASSERT_NOTNULL(config, "created config");
	T_SETUPEND;

	struct perfmon_attr attr = test_attrs[0];

	int error = perfmon_config_set_attr(config, &attr);
	T_ASSERT_POSIX_ZERO(error, "should set attr in config");
	struct perfmon_spec *spec = perfmon_config_specify(config);
	T_QUIET; T_ASSERT_EQ(spec->ps_attr_count, (unsigned short)1,
	    "one attr set in config");

	error = perfmon_config_set_attr(config, &attr);
	T_ASSERT_POSIX_ERROR(error, EALREADY,
	    "should not set same attribute to config");
	T_QUIET; T_ASSERT_EQ(spec->ps_attr_count, (unsigned short)1,
	    "still one attr set in config");

	attr = test_attrs[1];
	error = perfmon_config_set_attr(config, &attr);
	T_ASSERT_POSIX_ZERO(error, "should set second attr in config");
	T_QUIET; T_ASSERT_EQ(spec->ps_attr_count, (unsigned short)2,
	    "two attrs set in config");

	strlcpy(attr.pa_name, "ENOATTR", sizeof(attr.pa_name));
	error = perfmon_config_set_attr(config, &attr);
	T_ASSERT_POSIX_ERROR(error, ENOATTR,
	    "should not set non-existent attr in config");
	T_QUIET; T_ASSERT_EQ(spec->ps_attr_count, (unsigned short)2,
	    "still two attrs set in config");

	error = perfmon_configure(config);
	T_ASSERT_POSIX_ZERO(error, "configured CPMU");

	strlcpy(attr.pa_name, "PMCR3", sizeof(attr.pa_name));
	error = perfmon_config_set_attr(config, &attr);
	T_ASSERT_POSIX_ERROR(error, EBUSY,
	    "should not set attr on already-configured config");
	T_QUIET; T_ASSERT_EQ(spec->ps_attr_count, (unsigned short)2,
	    "still two attrs added to config");

	const struct perfmon_attr *read_attrs = spec->ps_attrs;
	for (unsigned short i = 0; i < spec->ps_attr_count; i++) {
		T_QUIET;
		T_ASSERT_EQ_STR(read_attrs[i].pa_name, test_attrs[i].pa_name,
		    "attr %hu name matches", i);
		T_QUIET;
		T_ASSERT_EQ(read_attrs[i].pa_value, test_attrs[i].pa_value,
		    "attr %hu number matches", i);
		T_PASS("attr %hu in config matches what was set", i);
	}

	perfmon_config_destroy(config);
}

T_DECL(config_arm64_cpmu, "ensure the ARM64 configuration is correct")
{
	T_SETUPBEGIN;
	perfmon_machine_startup();
	struct perfmon_source *cpmu_source = &perfmon_sources[0];
	perfmon_config_t config = perfmon_config_create(cpmu_source);
	T_QUIET; T_ASSERT_NOTNULL(config, "created config");

	for (size_t i = 0; i < ARRAYLEN(test_events); i++) {
		int error = perfmon_config_add_event(config, &test_events[i]);
		T_QUIET; T_ASSERT_POSIX_ZERO(error, "add event %zu to config", i);
	}

	T_SETUPEND;

	int error = perfmon_configure(config);
	T_ASSERT_POSIX_ZERO(error, "configured CPMU");

	T_LOG("PMCR0 = 0x%016" PRIx64 ", PMESR0 = 0x%016" PRIx64 ", PMESR1 = 0x%016"
	    PRIx64, cpmu_reg_state.pcr_pmcr0, cpmu_reg_state.pcr_pmesr[0],
	    cpmu_reg_state.pcr_pmesr[1]);
	unsigned short fixed_count = cpmu_source->ps_layout.pl_fixed_count;
	for (size_t i = 0; i < ARRAYLEN(test_events); i++) {
		T_EXPECT_BITS_SET(cpmu_reg_state.pcr_pmcr0,
		    1ULL << test_events[i].pe_counter, "PMCR0 enabled event %zu", i);
		T_EXPECT_BITS_SET(cpmu_reg_state.pcr_pmcr0,
		    1ULL << (test_events[i].pe_counter + 12),
		        "PMCR0 enabled PMIs for event %zu", i);

		uint64_t event_shift = (test_events[i].pe_counter - fixed_count) * 8;
		T_EXPECT_EQ((cpmu_reg_state.pcr_pmesr[0] >> event_shift) & 0xff,
		    test_events[i].pe_number, "PMESR0 has event %zu set", i);
	}

	perfmon_config_destroy(config);
}

T_DECL(config_lock, "ensure only one config can be active at a time")
{
	T_SETUPBEGIN;
	perfmon_machine_startup();
	struct perfmon_source *cpmu_source = &perfmon_sources[0];
	perfmon_config_t config = perfmon_config_create(cpmu_source);
	T_QUIET; T_ASSERT_NOTNULL(config, "created config");
	perfmon_config_t config_later = perfmon_config_create(cpmu_source);
	T_QUIET; T_ASSERT_NOTNULL(config_later, "created later config");

	int error = perfmon_configure(config);
	T_ASSERT_POSIX_ZERO(error, "configured CPMU");

	T_SETUPEND;

	error = perfmon_configure(config_later);
	T_ASSERT_POSIX_ERROR(error, EBUSY,
	    "later config should be unable to configure CPMU");

	perfmon_config_destroy(config);
	perfmon_config_destroy(config_later);
}

T_DECL(config_release, "ensure the active config releases control")
{
	T_SETUPBEGIN;
	perfmon_machine_startup();
	struct perfmon_source *cpmu_source = &perfmon_sources[0];
	perfmon_config_t config = perfmon_config_create(cpmu_source);
	T_QUIET; T_ASSERT_NOTNULL(config, "created config");
	perfmon_config_t config_later = perfmon_config_create(cpmu_source);
	T_QUIET; T_ASSERT_NOTNULL(config_later, "created later config");

	int error = perfmon_configure(config);
	T_ASSERT_POSIX_ZERO(error, "configured CPMU");

	perfmon_config_destroy(config);
	T_LOG("destroyed first config");

	T_SETUPEND;

	error = perfmon_configure(config_later);
	T_ASSERT_POSIX_ZERO(error, "later config configured CPMU");

	perfmon_config_destroy(config_later);
}
