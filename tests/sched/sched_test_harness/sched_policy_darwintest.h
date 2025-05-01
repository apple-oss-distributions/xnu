// Copyright (c) 2024 Apple Inc.  All rights reserved.

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdlib.h>

#include <darwintest.h>
#include <darwintest_utils.h>

static void
sched_policy_speak(char *message)
{
	char *fun_level = getenv("SCHED_FUN");
	if ((fun_level != NULL) && (strcmp(fun_level, "MAX") == 0)) {
		char *say_args[] = {"/usr/local/bin/say_anything", "-v", "damon", "-r 210", T_NAME, message, NULL};
		pid_t pid;
		dt_launch_tool(&pid, say_args, false, NULL, NULL);
	}
}

static int sched_policy_passed_subtests = 0;

static void
sched_policy_final_pass(void)
{
	if (T_FAILCOUNT == 0) {
		T_PASS("🌈 All %d subtests passed! 🍻 ", sched_policy_passed_subtests);
		sched_policy_speak("Passed! Awesome job!");
	} else {
		sched_policy_speak("Failed, awww.");
	}
}

#define PASTER(a, b) a##_##b
#define SCHED_POLICY_TEST_NAME(policy_name, test_name) PASTER(policy_name, test_name)
#define SCHED_POLICY_T_DECL(test_name, description, ...) T_DECL(SCHED_POLICY_TEST_NAME(TEST_RUNQ_POLICY, test_name), description, ##__VA_ARGS__)

static unsigned int sched_policy_fails_so_far = 0;
static unsigned int sched_policy_passes_so_far = 0;
static bool sched_policy_setup_final_pass = false;
#define SCHED_PASS_MSG "  {🛡️ 🕰️  %d passed expects ✅}"
#define SCHED_FAIL_MSG "  {🧯🧐  %d/%d failed expects ❌}"
/* BEGIN IGNORE CODESTYLE */
#define SCHED_POLICY_PASS(message, ...) ({ \
	char expanded_message[256] = ""; \
	if (T_FAILCOUNT <= sched_policy_fails_so_far) { \
		strcat(expanded_message, message); \
		strcat(expanded_message, SCHED_PASS_MSG); \
		T_PASS(expanded_message, ##__VA_ARGS__, (T_PASSCOUNT - sched_policy_passes_so_far)); \
		sched_policy_passed_subtests++; \
	} else { \
		strcat(expanded_message, message); \
		strcat(expanded_message, SCHED_FAIL_MSG); \
		T_FAIL(expanded_message, ##__VA_ARGS__, (T_FAILCOUNT - sched_policy_fails_so_far), \
		    (T_PASSCOUNT - sched_policy_passes_so_far + T_FAILCOUNT - sched_policy_fails_so_far)); \
	} \
	sched_policy_fails_so_far = T_FAILCOUNT; \
	sched_policy_passes_so_far = T_PASSCOUNT; \
	if (sched_policy_setup_final_pass == false) { \
		T_ATEND(sched_policy_final_pass); \
		sched_policy_setup_final_pass = true; \
	} \
})
/* END IGNORE CODESTYLE */
