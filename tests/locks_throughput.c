#include <errno.h>
#include <libgen.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <unistd.h>

/* keep in sync with osfmk/kern/locks.c */

__enum_closed_decl(lck_bench_type_t, uint16_t, {
	LCK_BENCH_TYPE_NONE,
	LCK_BENCH_TYPE_BIT,
	LCK_BENCH_TYPE_SPIN,
	LCK_BENCH_TYPE_TICKET,
	LCK_BENCH_TYPE_MTX,
	LCK_BENCH_TYPE_RW,
	LCK_BENCH_TYPE_RW_LEGACY,
});

static struct lck_bench_spec {
	lck_bench_type_t        lock_type;
	bool                    false_sharing;
	uint16_t                duration_ms;
	uint16_t                num_threads;
	uint32_t                write_ratio;
	uint32_t                iterations_read;
	uint32_t                iterations_write;
	uint32_t                iterations_unlocked;
} spec = {
	.lock_type           = LCK_BENCH_TYPE_NONE,
	.false_sharing       = false,
	.duration_ms         = 3000,
	.num_threads         = 1,
	.write_ratio         = (uint32_t)((UINT32_MAX + 1ull) * 10. / 100),
	.iterations_read     = 10,
	.iterations_write    = 10,
	.iterations_unlocked = 10,
};

static const char *const lock_types[] = {
	[LCK_BENCH_TYPE_BIT]       = "bit",
	[LCK_BENCH_TYPE_SPIN]      = "spin",
	[LCK_BENCH_TYPE_TICKET]    = "ticket",
	[LCK_BENCH_TYPE_MTX]       = "mutex",
	[LCK_BENCH_TYPE_RW]        = "rw",
	[LCK_BENCH_TYPE_RW_LEGACY] = "rwold",
};

static bool stress_test = false;

__dead2
static void
print_help(char *prog)
{
	fprintf(stderr,
	    "%s: [options] <lock_type> <read iterations> <write iterations> <unlocked iterations>\n"
	    "\n"
	    "Valid lock types:\n"
	    "\n"
	    "    bit             hw_lock_bit_t\n"
	    "    spin            lck_spin_t\n"
	    "    ticket          lck_ticket_t\n"
	    "    mutex           lck_mtx_t\n"
	    "    rw              lck_rw_t\n"
	    "    rwold           lck_rw_t (legacy)\n"
	    "\n"
	    "Valid options:\n"
	    "    -s              false share the data with its lock (default: false)\n"
	    "    -S              stress test mode                   (default: false)\n"
	    "    -d <msecs>      specify the test duration in ms    (default 3,000ms)\n"
	    "    -r <percent>    percentage of write operations     (default: 10%%)\n"
	    "    -n <threads>    number of threads                  (default: 1)\n"
	    "\n",
	    basename(prog));
	exit(-1);
}

static lck_bench_type_t
parse_lock_type(const char *arg)
{
	for (int i = 1; i < sizeof(lock_types) / sizeof(lock_types[0]); i++) {
		if (strcmp(arg, lock_types[i]) == 0) {
			return (lck_bench_type_t)i;
		}
	}
	return LCK_BENCH_TYPE_NONE;
}

static void
parse_arguments(int argc, char **argv)
{
	int ch;

	while ((ch = getopt(argc, argv, "d:hn:r:sS")) != -1) {
		switch (ch) {
		case 'd':
			spec.duration_ms = atoi(optarg);
			break;

		case 'h':
			print_help(argv[0]);
			break;

		case 'n':
			spec.num_threads = atoi(optarg);
			break;

		case 'r':
			spec.write_ratio = (uint32_t)(atof(optarg) * (UINT32_MAX + 1ull) / 100.);
			break;

		case 's':
			spec.false_sharing = true;
			break;

		case 'S':
			stress_test = true;
			break;
		}
	}

	if (argc != optind + 4) {
		fprintf(stderr,
		    "error: expects 4 arguments, got %d\n"
		    "\n", argc - optind);
		print_help(argv[0]);
	}

	spec.lock_type = parse_lock_type(argv[optind]);
	spec.iterations_read = atoi(argv[optind + 1]);
	spec.iterations_write = atoi(argv[optind + 2]);
	spec.iterations_unlocked = atoi(argv[optind + 3]);

	if (spec.lock_type == LCK_BENCH_TYPE_NONE) {
		fprintf(stderr,
		    "error: unknown lock type `%s'\n"
		    "\n", argv[optind]);
		print_help(argv[0]);
	}
}

int
main(int argc, char **argv)
{
	uint64_t arg;
	uint64_t ret;
	size_t   retlen = sizeof(ret);
	int rc;

	parse_arguments(argc, argv);
	fprintf(stderr,
	    "========================================\n"
	    "test type:      %s\n"
	    "lock type:      %s\n"
	    "false sharing:  %d\n"
	    "duration:       %'dms\n"
	    "write ratio:    %.2g%%\n"
	    "iterations:\n"
	    " read:          %d\n"
	    " write:         %d\n"
	    " unlocked:      %d\n"
	    " threads:       %d\n"
	    "========================================\n",
	    stress_test ? "stress" : "perf",
	    lock_types[spec.lock_type],
	    spec.false_sharing,
	    spec.duration_ms,
	    spec.write_ratio * 100. / (UINT32_MAX + 1ull),
	    spec.iterations_read,
	    spec.iterations_write,
	    spec.iterations_unlocked,
	    spec.num_threads);

	arg = (uint64_t)&spec;
	if (stress_test) {
		rc = sysctlbyname("debug.test.lck_stress", &ret, &retlen, &arg, sizeof(arg));
	} else {
		rc = sysctlbyname("debug.test.lck_bench", &ret, &retlen, &arg, sizeof(arg));
	}
	if (rc != 0) {
		fprintf(stderr, "error: test failed: %s (error: %d)\n",
		    strerror(errno), errno);
		exit(-1);
	}

	printf("%'lld\n", ret);
	return 0;
}
