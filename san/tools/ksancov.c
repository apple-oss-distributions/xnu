/*
 * Copyright (c) 2019 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <errno.h>

#include <fcntl.h>
#include <sys/ioctl.h>

#include <getopt.h>

#include "ksancov.h"

static void
usage(void)
{
	fprintf(stderr,
	    "usage: ./ksancov [OPTIONS]\n\n"
	    "  -t | --trace        use trace (PC log) mode [default]\n"
	    "  -s | --stksize      use trace (PC log) with stack size mode\n"
	    "  -c | --counters     use edge counter mode\n"
	    "  -n | --entries <n>  override max entries in trace log\n"
	    "  -x | --exec <path>  instrument execution of binary at <path>\n");
	exit(1);
}

/*
 * Structure holds all data required for coverage collection.
 */
typedef struct ksancov_state {
	ksancov_mode_t       ks_mode;
	ksancov_edgemap_t    *ks_edgemap;
	union {
		ksancov_header_t       *ks_header;
		ksancov_trace_t        *ks_trace;
		ksancov_counters_t     *ks_counters;
	};
} ksancov_state_t;

/*
 * Configures ksancov device for selected coverage mode.
 */
static int
ksancov_set_mode(int fd, ksancov_mode_t mode, int max_entries)
{
	int ret = 0;

	switch (mode) {
	case KS_MODE_TRACE:
		ret = ksancov_mode_trace(fd, max_entries);
		break;
	case KS_MODE_STKSIZE:
		ret = ksancov_mode_stksize(fd, max_entries);
		break;
	case KS_MODE_COUNTERS:
		ret = ksancov_mode_counters(fd);
		break;
	default:
		perror("ksancov unsupported mode\n");
		return ENOTSUP;
	}

	return ret;
}

/*
 * Initialize coverage state from provided options. Shared mappings with kernel are established
 * here.
 */
static int
ksancov_init_state(int fd, ksancov_mode_t mode, int max_entries, ksancov_state_t *state)
{
	uintptr_t addr;
	size_t sz;
	int ret = 0;

	/* Map edge map into process address space. */
	ret = ksancov_map_edgemap(fd, &addr, NULL);
	if (ret) {
		perror("ksancov map counters\n");
		return ret;
	}
	state->ks_edgemap = (void *)addr;
	fprintf(stderr, "nedges (edgemap) = %u\n", state->ks_edgemap->ke_nedges);

	/* Setup selected tracing mode. */
	ret = ksancov_set_mode(fd, mode, max_entries);
	if (ret) {
		perror("ksancov set mode\n");
		return ret;
	}

	/* Map buffer for selected mode into process address space. */
	ret = ksancov_map(fd, &addr, &sz);
	if (ret) {
		perror("ksancov map");
		return ret;
	}
	fprintf(stderr, "mapped to 0x%lx + %lu\n", addr, sz);

	/* Finalize state members. */
	state->ks_mode = mode;
	state->ks_header = (void *)addr;

	if (mode == KS_MODE_COUNTERS) {
		fprintf(stderr, "nedges (counters) = %u\n", state->ks_counters->kc_nedges);
	} else {
		fprintf(stderr, "maxpcs = %lu\n", ksancov_trace_max_ent(state->ks_trace));
	}

	return ret;
}

static int
ksancov_print_state(ksancov_state_t *state)
{
	if (state->ks_mode == KS_MODE_COUNTERS) {
		for (size_t i = 0; i < state->ks_counters->kc_nedges; i++) {
			size_t hits = state->ks_counters->kc_hits[i];
			if (hits) {
				fprintf(stderr, "0x%lx: %lu hits [idx %lu]\n",
				    ksancov_edge_addr(state->ks_edgemap, i), hits, i);
			}
		}
	} else {
		size_t head = ksancov_trace_head(state->ks_trace);
		fprintf(stderr, "head = %lu\n", head);

		for (uint32_t i = 0; i < head; i++) {
			if (state->ks_mode == KS_MODE_TRACE) {
				fprintf(stderr, "0x%lx\n", ksancov_trace_entry(state->ks_trace, i));
			} else {
				fprintf(stderr, "0x%lx [size %u]\n", ksancov_stksize_pc(state->ks_trace, i),
				    ksancov_stksize_size(state->ks_trace, i));
			}
		}
	}

	return 0;
}

int
main(int argc, char *argv[])
{
	ksancov_mode_t ksan_mode = KS_MODE_NONE;
	ksancov_state_t ksan_state;

	int ret;
	size_t max_entries = 64UL * 1024;
	char *path = NULL;

	static struct option opts[] = {
		{ "entries", required_argument, NULL, 'n' },
		{ "exec", required_argument, NULL, 'x' },

		{ "trace", no_argument, NULL, 't' },
		{ "counters", no_argument, NULL, 'c' },
		{ "stksize", no_argument, NULL, 's' },

		{ NULL, 0, NULL, 0 }
	};

	int ch;
	while ((ch = getopt_long(argc, argv, "tsn:x:c", opts, NULL)) != -1) {
		switch (ch) {
		case 'n':
			max_entries = strtoul(optarg, NULL, 0);
			break;
		case 'x':
			path = optarg;
			break;
		case 't':
			ksan_mode = KS_MODE_TRACE;
			break;
		case 'c':
			ksan_mode = KS_MODE_COUNTERS;
			break;
		case 's':
			ksan_mode = KS_MODE_STKSIZE;
			break;
		default:
			usage();
		}
	}

	int fd = ksancov_open();
	if (fd < 0) {
		perror("ksancov_open");
		return errno;
	}
	fprintf(stderr, "opened ksancov on fd %i\n", fd);

	/* Initialize ksancov state. */
	ret = ksancov_init_state(fd, ksan_mode, max_entries, &ksan_state);
	if (ret) {
		perror("ksancov init\n");
		return ret;
	}

	/* Execute binary (when provided) with enabled coverage collection. Run getppid() otherwise. */
	if (path) {
		int pid = fork();
		if (pid == 0) {
			/* child */

			ret = ksancov_thread_self(fd);
			if (ret) {
				perror("ksancov thread");
				return ret;
			}

			ksancov_reset(ksan_state.ks_header);
			ksancov_start(ksan_state.ks_header);
			ret = execl(path, path, 0);
			perror("execl");

			exit(1);
		} else {
			/* parent */
			waitpid(pid, NULL, 0);
			ksancov_stop(ksan_state.ks_header);
		}
	} else {
		ret = ksancov_thread_self(fd);
		if (ret) {
			perror("ksancov thread");
			return ret;
		}

		ksancov_reset(ksan_state.ks_header);
		ksancov_start(ksan_state.ks_header);
		int ppid = getppid();
		ksancov_stop(ksan_state.ks_header);
		fprintf(stderr, "ppid = %i\n", ppid);
	}

	/* Print report and cleanup. */
	ksancov_print_state(&ksan_state);
	ret = close(fd);
	fprintf(stderr, "close = %i\n", ret);

	return 0;
}
