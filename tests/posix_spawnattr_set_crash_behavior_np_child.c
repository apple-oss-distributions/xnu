#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/reason.h>
#include <dispatch/dispatch.h>
#include <dispatch/private.h>

#define TEST_REASON_CODE 4

#define countof(x) (sizeof(x) / sizeof(x[0]))

static bool
_should_spin(char *mode)
{
	// These tests are signaled by the parent
	char *spin_modes[] = {
		"spin",
		"reason",
		"clean",
		"dirty",
	};
	for (size_t i = 0; i < countof(spin_modes); i++) {
		if (strcmp(mode, spin_modes[i]) == 0) {
			return true;
		}
	}
	return false;
}

int
main(int argc, char *argv[])
{
	if (argc != 2) {
		printf("Missing arguments\n");
		exit(1);
	}

	if (strcmp(argv[1], "crash") == 0) {
		abort_with_reason(OS_REASON_TEST, TEST_REASON_CODE, "Test forcing crash", OS_REASON_FLAG_CONSISTENT_FAILURE | OS_REASON_FLAG_NO_CRASH_REPORT);
	} else if (strcmp(argv[1], "success") == 0) {
		exit(0);
	} else if (strcmp(argv[1], "exit") == 0) {
		exit(2);
	} else if (strcmp(argv[1], "wait") == 0) {
		signal(SIGUSR1, SIG_IGN);
		dispatch_source_t source = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGUSR1, 0, NULL);
		dispatch_source_set_event_handler(source, ^{
			abort_with_reason(OS_REASON_TEST, TEST_REASON_CODE, "Test forcing crash", OS_REASON_FLAG_CONSISTENT_FAILURE | OS_REASON_FLAG_NO_CRASH_REPORT);
		});
		dispatch_activate(source);
	} else if (_should_spin(argv[1])) {
		while (1) {
			// Do nothing until the parent kills us
			continue;
		}
	} else {
		printf("Unknown argument: %s\n", argv[1]);
		exit(1);
	}
	dispatch_main();
}
