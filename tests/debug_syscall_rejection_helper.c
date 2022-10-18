#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/kern_debug.h>

int
main(int argc, char *argv[])
{
	int opt;

	syscall_rejection_selector_t masks[16] = { 0 };

	int pos = 0;
	unsigned char selector = 0;
	bool next_is_allow = false;

	uint64_t flags = SYSCALL_REJECTION_FLAGS_DEFAULT;

	while ((opt = getopt(argc, argv, "ads:i:OF")) != -1) {
		switch (opt) {
		case 'a':
			next_is_allow = true;
			break;
		case 'd':
			next_is_allow = false;
			break;
		case 's':
			selector = (syscall_rejection_selector_t)atoi(optarg);
			break;
		case 'i':
			pos = atoi(optarg);
			if (next_is_allow) {
				// printf("%i: ALLOW %u\n", pos, (unsigned int)selector);
				masks[pos] = SYSCALL_REJECTION_ALLOW(selector);
			} else {
				// printf("%i: DENY %u\n", pos, (unsigned int)selector);
				masks[pos] = SYSCALL_REJECTION_DENY(selector);
			}
			break;
		case 'O':
			flags |= SYSCALL_REJECTION_FLAGS_ONCE;
			break;
		case 'F':
			flags |= SYSCALL_REJECTION_FLAGS_FORCE_FATAL;
			break;
		default:
			fprintf(stderr, "unknown option '%c'\n", opt);
			exit(2);
		}
	}

	debug_syscall_reject_config(masks, sizeof(masks) / sizeof(masks[0]), flags);

	int __unused ret = chdir("/tmp");

	syscall_rejection_selector_t all_allow_masks[16] = { 0 };
	all_allow_masks[0] = SYSCALL_REJECTION_ALLOW(SYSCALL_REJECTION_ALL);

	debug_syscall_reject_config(all_allow_masks, sizeof(all_allow_masks) / sizeof(all_allow_masks[0]), SYSCALL_REJECTION_FLAGS_DEFAULT);

	return 0;
}
