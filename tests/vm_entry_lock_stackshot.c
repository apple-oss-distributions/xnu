#include <darwintest.h>
#include <darwintest_utils.h>

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/thread_info.h>
#include <sys/sysctl.h>
#include <sys/stackshot.h>
#include <sys/syscall.h>
#include <signal.h>
#include <kern/debug.h>
#include <kern/block_hint.h>
#include <unistd.h>
#include <mach/mach_time.h>
#include <zlib.h>

#define STACKSHOT_KCTYPE_VMRL_BLOCKING_RELS 0x95bu
#define KCDATA_BUFFER_BEGIN_COMPRESSED 0x434f4d50u

/* Thread state definitions */
#define TH_WAIT                 0x01            /* queued for waiting */
#define TH_SUSP                 0x02            /* stopped or requested to stop */
#define TH_RUN                  0x04            /* running or on runq */
#define TH_UNINT                0x08            /* waiting uninterruptibly */
#define TH_TERMINATE            0x10            /* halted at termination */
#define TH_TERMINATE2           0x20            /* added to termination queue */
#define TH_WAIT_REPORT          0x40            /* the wait is using the sched_call */
#define TH_IDLE                 0x80            /* idling processor */
#define TH_WAKING              0x100            /* between waitq remove and thread_go */

/* Define the struct locally since it's not fully exported to userspace */
struct vmrl_blocking_rel {
	uint64_t waiter_tid;
	uint64_t blocker_tid;
	uint64_t entry_hash;
	uint32_t flags;
} __attribute__((packed));

/* VMRL blocking relationship flags */
#define STACKSHOT_WAITER_VMRL_SHARED                    0x01
#define STACKSHOT_BLOCKER_VMRL_SHARED                   0x02
#define STACKSHOT_WAITER_VMRL_EXCLUSIVE                 0x04
#define STACKSHOT_BLOCKER_VMRL_EXCLUSIVE                0x08

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"),
	T_META_CHECK_LEAKS(false),
	T_META_OWNER("rbernea"),
	T_META_RUN_CONCURRENTLY(false)
	);

#define ERROR_CODE -1
#define SUCCESS_CODE 0
#define STR_SIZE 128
#define THREAD_SYNC_DELAY_US 250000 // 250 ms
#define VM_READ_COUNT_MATCH 1 // Result value when read count matches expected

uint16_t num_threads = 0;
bool first_is_excl = true;
uint64_t stackshot_flags = STACKSHOT_KCDATA_FORMAT |
    STACKSHOT_THREAD_WAITINFO | STACKSHOT_DO_COMPRESS;

static void
kill_threads(pid_t pid)
{
	for (int i = 0; i < num_threads; i++) {
		if (sysctlbyname("vm.dbg_range_lock_wakeup", NULL, 0, &pid, sizeof(pid))) {
			perror("sysctlbyname (dbg_range_lock_wakeup)");
		}
		usleep(THREAD_SYNC_DELAY_US);
	}
}

void
handle_sigint(int sig)
{
	T_LOG("\nCaught signal %d (SIGINT). Exiting cleanly.\n", sig);
	kill_threads(getpid());
	exit(0);
}

typedef enum {
	LCKNG_TYPE_EXCLUSIVE = 0x1,
	LCKNG_TYPE_SHARED = 0x2,
	LCKNG_TYPE_END
} lckng_type_t;

static const char *
lock_type_to_str(lckng_type_t type)
{
	return (type == LCKNG_TYPE_SHARED) ? "read" : "write";
}

typedef struct thread_package {
	pthread_t thread;
	lckng_type_t locktype;
	mach_vm_address_t addr;
	uint64_t size;
	uint64_t tid;
} tpkg;


/* Structures for thread block hint sysctl */
typedef struct {
	uint64_t thread_id;
	pid_t pid;
} thread_block_hint_args;

/* Structures for VM entry lock/block sysctl */
typedef struct {
	mach_vm_address_t address;
	uint64_t size; /* bytes */
	pid_t pid;
	uint32_t flags;
} dbg_vm_entry_lock_args;

/* Structures for VM entry read count check sysctl */
typedef struct {
	mach_vm_address_t address;
	pid_t pid;
	uint16_t expected_readers;
} dbg_vm_entry_read_count_args;

static size_t
get_sysctl_mib(const char* ctl_name, int* mib, size_t mib_sz)
{
	size_t mib_size = mib_sz;
	if (sysctlnametomib(ctl_name, mib, &mib_size)) {
		perror("sysctlnametomib");
	}
	return mib_size;
}


/*
 * Decompress a stackshot buffer if it's compressed.
 * Returns the decompressed buffer and size, or original buffer if not compressed.
 */
static char *
decompress_stackshot_buffer(void *ssbuf, size_t sslen, size_t *decompressed_size)
{
	kcdata_iter_t iter = kcdata_iter(ssbuf, sslen);
	uint32_t buffer_type = kcdata_iter_type(iter);

	if (buffer_type != KCDATA_BUFFER_BEGIN_COMPRESSED) {
		*decompressed_size = sslen;
		return NULL; /* Not compressed, use original buffer */
	}

	iter = kcdata_iter_next(iter);
	uint64_t compression_type = 0, totalout = 0, totalin = 0;

	uint64_t *data;
	char *desc;
	for (int i = 0; i < 3; i++) {
		kcdata_iter_get_data_with_desc(iter, &desc, (void **)&data, NULL);
		if (strcmp(desc, "kcd_c_type") == 0) {
			compression_type = *data;
		} else if (strcmp(desc, "kcd_c_totalout") == 0) {
			totalout = *data;
		} else if (strcmp(desc, "kcd_c_totalin") == 0) {
			totalin = *data;
		}
		iter = kcdata_iter_next(iter);
	}

	/* Get compressed data */
	char *bufferBase = kcdata_iter_payload(iter);

	size_t inflatedBufferSize = totalin + (totalin >> 3);
	char *inflatedBufferBase = malloc(inflatedBufferSize);
	if (!inflatedBufferBase) {
		return NULL;
	}

	z_stream zs;
	memset(&zs, 0, sizeof(zs));
	if (inflateInit(&zs) != Z_OK) {
		free(inflatedBufferBase);
		return NULL;
	}
	zs.next_in = (unsigned char *)bufferBase;
	zs.avail_in = (uInt)totalout;
	zs.next_out = (unsigned char *)inflatedBufferBase;
	zs.avail_out = (uInt)inflatedBufferSize;
	if (inflate(&zs, Z_FINISH) != Z_STREAM_END) {
		inflateEnd(&zs);
		free(inflatedBufferBase);
		return NULL;
	}
	inflateEnd(&zs);

	if ((uint64_t)zs.total_out != totalin) {
		free(inflatedBufferBase);
		return NULL;
	}

	/* Copy data after compressed area */
	size_t header_size = (size_t)(bufferBase - (char *)ssbuf);
	size_t data_after_compressed_size = sslen - totalout - header_size;
	if (data_after_compressed_size > 0) {
		memcpy(inflatedBufferBase + zs.total_out, bufferBase + totalout, data_after_compressed_size);
	}

	*decompressed_size = zs.total_out + data_after_compressed_size;
	return inflatedBufferBase;
}

/*
 * Search for VMRL blocking relationships in the stackshot buffer.
 * Returns true if all expected waiters and blockers are found with correct flags
 * (or for exceeding tests - returns true if at least one is missing).
 */
static bool
validate_vmrl_relationships(void *ssbuf, size_t sslen, tpkg *waiters, tpkg *blockers,
    uint16_t num_waiters, uint16_t num_blockers, bool expect_missing)
{
	size_t decompressed_size;
	char *decompressed_buffer = decompress_stackshot_buffer(ssbuf, sslen, &decompressed_size);
	bool *found_waiters = calloc(num_waiters, sizeof(bool));
	bool *found_blockers = calloc(num_blockers, sizeof(bool));
	bool result = false;

	if (!found_waiters || !found_blockers) {
		goto cleanup;
	}

	void *search_buffer = decompressed_buffer ? decompressed_buffer : ssbuf;
	size_t search_size = decompressed_buffer ? decompressed_size : sslen;

	kcdata_iter_t search_iter = kcdata_iter(search_buffer, search_size);
	int found_waiter_count = 0;
	int found_blocker_count = 0;

	while (kcdata_iter_valid(search_iter)) {
		uint32_t entry_type = kcdata_iter_type(search_iter);

		if (((entry_type & ~0xfu) == KCDATA_TYPE_ARRAY_PAD0 || entry_type == KCDATA_TYPE_ARRAY) &&
		    kcdata_iter_array_valid(search_iter) &&
		    kcdata_iter_array_elem_type(search_iter) == STACKSHOT_KCTYPE_VMRL_BLOCKING_RELS) {
			uint32_t array_elem_count = kcdata_iter_array_elem_count(search_iter);
			void *array_data = kcdata_iter_payload(search_iter);
			struct vmrl_blocking_rel *vmrl_entries = (struct vmrl_blocking_rel *)array_data;

			for (uint32_t i = 0; i < array_elem_count; i++) {
				uint64_t waiter_tid = vmrl_entries[i].waiter_tid;
				uint64_t blocker_tid = vmrl_entries[i].blocker_tid;
				uint32_t flags = vmrl_entries[i].flags;

				/* Check for waiters with correct flags */
				for (int j = 0; j < num_waiters; j++) {
					if (waiters[j].tid == waiter_tid && !found_waiters[j]) {
						/* Validate waiter flags match expected lock type */
						bool waiter_flags_correct = false;
						if (waiters[j].locktype == LCKNG_TYPE_SHARED) {
							waiter_flags_correct = (flags & STACKSHOT_WAITER_VMRL_SHARED) != 0;
						} else if (waiters[j].locktype == LCKNG_TYPE_EXCLUSIVE) {
							waiter_flags_correct = (flags & STACKSHOT_WAITER_VMRL_EXCLUSIVE) != 0;
						}

						if (waiter_flags_correct) {
							found_waiters[j] = true;
							found_waiter_count++;
						}
						break;
					}
				}

				/* Check for blockers with correct flags */
				for (int j = 0; j < num_blockers; j++) {
					if (blockers[j].tid == blocker_tid && !found_blockers[j]) {
						/* Validate blocker flags match expected lock type */
						bool blocker_flags_correct = false;
						if (blockers[j].locktype == LCKNG_TYPE_SHARED) {
							blocker_flags_correct = (flags & STACKSHOT_BLOCKER_VMRL_SHARED) != 0;
						} else if (blockers[j].locktype == LCKNG_TYPE_EXCLUSIVE) {
							blocker_flags_correct = (flags & STACKSHOT_BLOCKER_VMRL_EXCLUSIVE) != 0;
						}

						if (blocker_flags_correct) {
							found_blockers[j] = true;
							found_blocker_count++;
						}
						break;
					}
				}
			}
		}

		search_iter = kcdata_iter_next(search_iter);
	}

	if (expect_missing) {
		result = (found_waiter_count < num_waiters) || (found_blocker_count < num_blockers);
	} else {
		result = (found_waiter_count == num_waiters) && (found_blocker_count == num_blockers);
		T_LOG("found waiters: %d, expected waiters: %u, found blockers: %d, expected blockers: %u", found_waiter_count, num_waiters,
		    found_blocker_count, num_blockers);
	}

cleanup:
	free(found_waiters);
	free(found_blockers);
	free(decompressed_buffer);
	return result;
}

static void
write_stackshot_to_file(void *stackshot_config, char *path_template, size_t path_template_size)
{
	void *buf;
	uint32_t buflen;

	buf = stackshot_config_get_stackshot_buffer(stackshot_config);
	T_QUIET; T_ASSERT_NOTNULL(buf, "stackshot buffer");

	buflen = stackshot_config_get_stackshot_size(stackshot_config);
	T_QUIET; T_ASSERT_GT(buflen, 0, "valid stackshot buffer length");

	T_QUIET; T_ASSERT_NOTNULL(path_template, "path template is not null");

	T_QUIET; T_ASSERT_POSIX_ZERO(dt_resultfile(path_template, path_template_size),
	    "create result file path");

	FILE *f = fopen(path_template, "w");
	T_WITH_ERRNO; T_QUIET; T_ASSERT_NOTNULL(f, "open stackshot output file");

	T_LOG("[Main] Writing stackshot to raw file %s", path_template);

	fwrite(buf, buflen, 1, f);
	fclose(f);
}

static void *
take_stackshot(uint64_t *duration)
{
	void *stackshot_out = NULL;
	int err, retries = 5;
	uint64_t start_ns, end_ns, elapsed_ns;
	int pid = getpid();

	stackshot_out = stackshot_config_create();
	T_QUIET; T_ASSERT_NOTNULL(stackshot_out, "Allocate stackshot config");
	stackshot_config_set_flags(stackshot_out, stackshot_flags);
	stackshot_config_set_pid(stackshot_out, pid);

	while (retries > 0) {
		start_ns = mach_absolute_time();
		err = stackshot_capture_with_config(stackshot_out);
		end_ns = mach_absolute_time();
		if (err == 0) {
			break;
		} else if (err == EBUSY || err == ETIMEDOUT) {
			retries--;
			continue;
		} else {
			goto exit_error;
		}
	}

	mach_timebase_info_data_t info;
	mach_timebase_info(&info);
	elapsed_ns = (end_ns - start_ns) * info.numer / info.denom;
	*duration = elapsed_ns;

	return stackshot_out;

exit_error:
	perror("take_stackshot");
	kill_threads(getpid());
	return NULL;
}

/*
 * Calculate the expected number of reader threads that should be holding the lock.
 * This counts all reader threads that have been started and should have acquired the lock.
 */
static uint16_t
calculate_expected_reader_count(int current_thread_index, tpkg *threads)
{
	uint16_t expected_readers = 0;

	for (int i = 0; i <= current_thread_index; i++) {
		if (threads[i].locktype == LCKNG_TYPE_SHARED) {
			expected_readers++;
		}
	}

	return expected_readers;
}

/*
 * Calculate the total number of reader threads in the test configuration.
 * This is used for setting max_readers to enable range checking.
 */
static uint16_t
calculate_total_reader_count(tpkg *threads)
{
	uint16_t total_readers = 0;

	for (int i = 0; i < num_threads; i++) {
		if (threads[i].locktype == LCKNG_TYPE_SHARED) {
			total_readers++;
		}
	}

	return total_readers;
}

/*
 * Helper function to get the thread state for a given pthread using standard Mach API.
 * Returns the thread state on success, or 0 on failure.
 */
static uint32_t
get_thread_state(pthread_t pthread)
{
	kern_return_t kr;
	mach_port_t thread_port;
	thread_basic_info_data_t basic_info;
	mach_msg_type_number_t info_count = THREAD_BASIC_INFO_COUNT;

	/* Get the mach thread port from pthread */
	thread_port = pthread_mach_thread_np(pthread);
	if (thread_port == MACH_PORT_NULL) {
		return 0;
	}

	/* Get basic thread info */
	kr = thread_info(thread_port, THREAD_BASIC_INFO,
	    (thread_info_t)&basic_info, &info_count);
	if (kr != KERN_SUCCESS) {
		return 0;
	}

	/* Convert Mach thread states to internal thread state flags */
	uint32_t result_state = 0;
	switch (basic_info.run_state) {
	case TH_STATE_RUNNING:
		result_state = TH_RUN;
		break;
	case TH_STATE_UNINTERRUPTIBLE:
		result_state = TH_WAIT | TH_UNINT;
		break;
	case TH_STATE_WAITING:
		result_state = TH_WAIT;
		break;
	case TH_STATE_STOPPED:
		result_state = TH_SUSP;
		break;
	case TH_STATE_HALTED:
		result_state = TH_TERMINATE;
		break;
	default:
		result_state = 0;
		break;
	}

	return result_state;
}

/*
 * Helper function to atomically wait for a thread's TID to be initialized.
 * This prevents the race condition where the main thread tries to use
 * the TID before the worker thread has set it.
 */
static uint64_t
wait_for_thread_tid_init(int thread_index, tpkg *threads)
{
	int retries = 20;
	uint64_t thread_id;

	do {
		thread_id = threads[thread_index].tid;
		if (thread_id != 0) {
			T_LOG("Thread %d TID initialized: %llu", thread_index, thread_id);
			return thread_id;
		}
		usleep(THREAD_SYNC_DELAY_US);
		retries--;
	} while (retries > 0);

	T_LOG("Thread %d TID initialization timed out", thread_index);
	return 0;
}

/*
 * Function to check if a thread has the correct state.
 * Logic:
 * - If this is a reader-on-reader situation: Check thread state (TH_WAIT | TH_UNINT) AND shared lock count
 * - Else: Check that the block hint is as expected
 * Returns true if the verification passes, false otherwise.
 */
static bool
check_thread_status(int thread_index, tpkg *threads, mach_vm_address_t addr)
{
	/* Wait for the thread's TID to be initialized to avoid race condition */
	uint64_t thread_id = wait_for_thread_tid_init(thread_index, threads);
	if (thread_id == 0) {
		return false;
	}

	pid_t pid = getpid();

	/* Skip the first thread (it always gets the lock) */
	if (thread_index == 0) {
		T_LOG("Thread %llu (%s) is the first thread, no verification needed",
		    thread_id, lock_type_to_str(threads[thread_index].locktype));
		return true;
	}

	/* Determine if this is a reader-on-reader blocking scenario */
	bool is_reader_on_reader = (threads[thread_index].locktype == LCKNG_TYPE_SHARED) &&
	    (threads[0].locktype == LCKNG_TYPE_SHARED);

	/* Calculate expected reader count once before the retry loop */
	uint16_t expected_readers = 0;
	if (is_reader_on_reader) {
		expected_readers = calculate_expected_reader_count(thread_index, threads);
	}

	int retries = 20;

	while (retries > 0) {
		if (is_reader_on_reader) {
			/* Reader-on-reader case: Only check thread state (TH_WAIT | TH_UNINT) */
			uint32_t thread_state = get_thread_state(threads[thread_index].thread);
			if (thread_state != 0 && (thread_state & (TH_WAIT | TH_UNINT)) == (TH_WAIT | TH_UNINT)) {
				T_LOG("Thread %llu (%s) reader-on-reader state check passed: 0x%x",
				    thread_id, lock_type_to_str(threads[thread_index].locktype), thread_state);
				return true;
			} else {
				T_LOG("Thread %llu (%s) state: 0x%x (retry %d)",
				    thread_id, lock_type_to_str(threads[thread_index].locktype), thread_state, 21 - retries);
			}
		} else {
			/* All other cases: Check block hint */
			thread_block_hint_args hint_args = { .thread_id = thread_id, .pid = pid };
			uint32_t block_hint;
			size_t hint_result_size = sizeof(block_hint);

			if (sysctlbyname("kern.thread_block_hint", &block_hint, &hint_result_size, &hint_args, sizeof(hint_args)) == 0) {
				/* Check if block_hint matches the expected value based on thread type */
				uint32_t expected_block_hint;
				if (threads[thread_index].locktype == LCKNG_TYPE_SHARED) {
					/* Reader thread should have shared event block hint */
					expected_block_hint = kThreadWaitVMEntrySharedEvent;
				} else {
					/* Writer thread should have exclusive event block hint */
					expected_block_hint = kThreadWaitVMEntryExclEvent;
				}

				if (block_hint == expected_block_hint) {
					T_LOG("Thread %llu (%s) block hint check passed: 0x%x",
					    thread_id, lock_type_to_str(threads[thread_index].locktype), block_hint);
					return true;
				} else {
					T_LOG("Thread %llu (%s) block hint: 0x%x (expected 0x%x, retry %d)",
					    thread_id, lock_type_to_str(threads[thread_index].locktype), block_hint,
					    expected_block_hint, 21 - retries);
				}
			} else {
				T_LOG("Failed to get block hint for thread %llu (retry %d)", thread_id, 21 - retries);
				perror("sysctlbyname (kern.thread_block_hint)");
			}
		}

		usleep(THREAD_SYNC_DELAY_US);
		retries--;
	}

	T_LOG("Thread %llu (%s) failed verification after 20 retries (reader-on-reader: %s)",
	    thread_id, lock_type_to_str(threads[thread_index].locktype),
	    is_reader_on_reader ? "yes" : "no");
	return false;
}

/*
 * Function to verify the reader count once for all reader threads in reader-on-reader scenarios.
 * This is called after all thread status checks are complete to avoid redundant sysctl calls.
 * Returns true if the verification passes, false otherwise.
 */
static bool
verify_reader_count(tpkg *threads, mach_vm_address_t addr)
{
	pid_t pid = getpid();

	/* Check if this is a reader-on-reader scenario */
	bool is_reader_on_reader = (threads[0].locktype == LCKNG_TYPE_SHARED);
	if (!is_reader_on_reader) {
		return true; /* No verification needed for non-reader-on-reader scenarios */
	}

	/* Calculate expected reader count (all reader threads that should have the lock) */
	uint16_t expected_readers = calculate_total_reader_count(threads);

	dbg_vm_entry_read_count_args vm_args = {
		.pid = pid,
		.address = addr,
		.expected_readers = expected_readers
	};

	int retries = 20;
	while (retries > 0) {
		int result;
		size_t vm_result_size = sizeof(result);

		if (sysctlbyname("vm.dbg_vm_entry_read_count", &result, &vm_result_size, &vm_args, sizeof(vm_args)) == 0) {
			/* result is VM_READ_COUNT_MATCH if read count matches expected, 0 otherwise */
			if (result == VM_READ_COUNT_MATCH) {
				T_LOG("Reader count verification passed (expected %u readers)", expected_readers);
				return true;
			} else {
				T_LOG("Reader count mismatch (expected %u, retry %d)", expected_readers, 21 - retries);
			}
		} else {
			T_LOG("Failed to get read count (retry %d)", 21 - retries);
			perror("sysctlbyname (vm.dbg_vm_entry_read_count)");
		}

		usleep(THREAD_SYNC_DELAY_US);
		retries--;
	}

	T_LOG("Reader count verification failed after 20 retries (expected %u readers)", expected_readers);
	return false;
}


/* Worker thread function. It does what the name suggests. */
static void *
lock_entry(void *arg)
{
	tpkg *th_pkg = (tpkg *)arg;
	int mib[CTL_MAXNAME] = {0};
	size_t mib_len = get_sysctl_mib("vm.dbg_vm_entry_lock_block", mib, CTL_MAXNAME);
	pid_t my_pid = getpid();
	uint64_t my_tid = syscall(SYS_thread_selfid);

	/* Set TID - main thread will wait for this via retry logic */
	th_pkg->tid = my_tid;

	dbg_vm_entry_lock_args args = {
		.address = th_pkg->addr,
		.size = th_pkg->size,
		.pid = my_pid,
		.flags = (uint32_t)th_pkg->locktype
	};

	T_LOG("[Thread %llu] starting. rw: %s, address: %llx, size: %llu pages", my_tid, lock_type_to_str(args.flags), args.address, args.size / PAGE_SIZE);
	if (sysctl(mib, mib_len, NULL, NULL, &args, sizeof(args)) != 0) {
		perror("sysctl by mib (vm.dbg_vm_entry_lock_block)");
	}
	return NULL;
}

static void
init_threads_meta(tpkg *threads, lckng_type_t other_threads_locktype, mach_vm_address_t addr, uint64_t size)
{
	if (first_is_excl) {
		threads[0].locktype = LCKNG_TYPE_EXCLUSIVE;
		for (int i = 1; i < num_threads; i++) {
			threads[i].locktype = other_threads_locktype;
		}
	} else { /* means last is exclusive */
		threads[0].locktype = LCKNG_TYPE_SHARED;
		threads[num_threads - 1].locktype = LCKNG_TYPE_EXCLUSIVE;
		for (int i = 1; i < num_threads - 1; i++) {
			threads[i].locktype = other_threads_locktype;
		}
	}
	for (int i = 0; i < num_threads; i++) {
		threads[i].addr = addr;
		threads[i].size = size;
		threads[i].tid = 0;
	}
}

static uint16_t
how_many_blockers(lckng_type_t other_threads_locktype)
{
	if (!first_is_excl && other_threads_locktype == LCKNG_TYPE_SHARED) {
		return num_threads - 1;
	} else {
		return 1;
	}
}


/*
 * Create a setting where threads are waiting on a range held by another thread(s),
 * then take stackshot (and parse it) and look for the right blocking relationships in
 * the ouput. If bool exceed is set, then we only want to make sure that at least one
 * relationship is missing (because we exceeded the maximum fixed-size capacity).
 */
static int
run_test(
	lckng_type_t other_threads_locktype,
	char *test_name,
	bool exceed)
{
	int return_code = SUCCESS_CODE;
	mach_vm_address_t allocated_addr = 0;
	mach_vm_allocate(mach_task_self(), &allocated_addr, PAGE_SIZE, VM_FLAGS_ANYWHERE);
	tpkg *threads = (tpkg *)malloc(sizeof(tpkg) * num_threads);
	uint16_t num_blockers = how_many_blockers(other_threads_locktype);
	uint16_t num_waiters  = num_threads - num_blockers;
	tpkg *blockers = (tpkg *)malloc(sizeof(tpkg) * num_blockers);
	tpkg *waiters  = (tpkg *)malloc(sizeof(tpkg) * num_waiters);
	init_threads_meta(threads, other_threads_locktype, allocated_addr, PAGE_SIZE);
	T_LOG("num_blockers: %d, rw: %s", num_blockers, lock_type_to_str(threads[0].locktype));
	T_LOG("num_waiters: %d, rw: %s", num_waiters, lock_type_to_str(threads[num_threads - 1].locktype));
	pid_t pid = getpid();
	void *stackshot_config = NULL;
	int res = 0;

	char ss_filename_kcdata[MAXPATHLEN];
	strlcpy(ss_filename_kcdata, test_name, sizeof(ss_filename_kcdata));
	strlcat(ss_filename_kcdata, ".kcdata", sizeof(ss_filename_kcdata));

	/* Reset vm_stackshot_test_blocker_tid to 0 before starting test */
	uint64_t reset_value = 0;
	T_ASSERT_POSIX_ZERO(sysctlbyname("kern.stackshot_test_blocker_tid",
	    NULL,
	    0,
	    &reset_value,
	    sizeof(reset_value)),
	    "Reset kern.stackshot_test_blocker_tid");

	T_LOG("allocated_addres = 0x%llx", allocated_addr);
	T_LOG("[Main] Spawning %d threads to create a deadlock before taking stackshot...", num_threads);

	res = pthread_create(&threads[0].thread, NULL, lock_entry, &threads[0]);
	if (res != 0) {
		T_FAIL("Failed to create thread %d, terminating the test", 0);
		return_code = ERROR_CODE;
		goto cleanup;
	}
	/* Check vm_stackshot_test_blocker_tid every THREAD_SYNC_DELAY_US to make sure the first thread managed to lock first */
	uint64_t blocker_tid = 0;
	size_t size = sizeof(blocker_tid);
	int retries = 20;
	bool blocker_tid_ok = false;
	bool thread_state_ok = false;
	while (retries > 0) {
		blocker_tid_ok = (sysctlbyname("kern.stackshot_test_blocker_tid", &blocker_tid, &size, NULL, 0) == 0 && blocker_tid != 0);

		uint32_t thread_state = 0;
		/* Find the pthread_t that corresponds to blocker_tid */
		pthread_t blocker_pthread = NULL;
		for (int i = 0; i < num_threads; i++) {
			if (threads[i].tid == blocker_tid) {
				blocker_pthread = threads[i].thread;
				break;
			}
		}
		if (blocker_pthread != NULL) {
			thread_state = get_thread_state(blocker_pthread);
		}
		thread_state_ok = (thread_state != 0 && (thread_state & (TH_WAIT | TH_UNINT)) == (TH_WAIT | TH_UNINT));

		if (blocker_tid_ok && thread_state_ok) {
			T_LOG("[Main] Detected blocker thread ID: %llu in uninterruptible wait state, starting remaining workers", blocker_tid);
			break;
		} else {
			T_LOG("[Main] Blocker TID: %llu (ok: %d), thread state: 0x%x (ok: %d) (retry %d)",
			    blocker_tid, blocker_tid_ok, thread_state, thread_state_ok, 21 - retries);
		}

		usleep(THREAD_SYNC_DELAY_US);
		retries--;
	}

	if (retries == 0) {
		kill_threads(pid);
		T_FAIL("First blocker failed to acquire entry");
		return_code = ERROR_CODE;
		goto cleanup;
	}

	/* Other threads will now try to take the entry */
	for (int i = 1; i < num_threads; i++) {
		res = pthread_create(&threads[i].thread, NULL, lock_entry, &threads[i]);
		if (res != 0) {
			kill_threads(pid);
			T_FAIL("Failed to create thread %d, terminating the test", i);
			return_code = ERROR_CODE;
			goto cleanup;
		}
		usleep(THREAD_SYNC_DELAY_US);
	}

	/* Check thread status - verify threads are in uninterruptible wait state */
	for (int i = 1; i < num_threads; i++) {
		if (!check_thread_status(i, threads, allocated_addr)) {
			kill_threads(pid);
			T_FAIL("Thread %d status check failed", i);
			return_code = ERROR_CODE;
			goto cleanup;
		}
	}

	/* Verify reader count once for all reader threads in reader-on-reader scenarios */
	bool reader_on_reader = (threads[0].locktype == LCKNG_TYPE_SHARED);
	if (reader_on_reader) {
		if (!verify_reader_count(threads, allocated_addr)) {
			kill_threads(pid);
			T_FAIL("Reader count verification failed");
			return_code = ERROR_CODE;
			goto cleanup;
		}
	}

	signal(SIGINT, handle_sigint);

	allocated_addr = 0;

	uint64_t stackshot_duration_ns = 0;
	stackshot_config = take_stackshot(&stackshot_duration_ns);

	/* Wake up threads so they can finish */
	kill_threads(pid);

	write_stackshot_to_file(stackshot_config, ss_filename_kcdata, sizeof(ss_filename_kcdata));

	for (int i = 0; i < num_threads; i++) {
		pthread_join(threads[i].thread, NULL);
	}

	for (int i = 0; i < num_blockers; i++) {
		blockers[i] = threads[i];
	}
	for (int i = num_blockers; i < num_threads; i++) {
		waiters[i - num_blockers] = threads[i];
	}

	void *buf = stackshot_config_get_stackshot_buffer(stackshot_config);
	size_t buflen = stackshot_config_get_stackshot_size(stackshot_config);

	if (validate_vmrl_relationships(buf, buflen, waiters, blockers, num_waiters, num_blockers, exceed)) {
		T_PASS("%s", exceed ?
		    "At least one waiter/blocker missing, as expected" :
		    "Found expected waiters and blockers in vmrl rels");
	} else {
		T_FAIL("%s", exceed ?
		    "All blockers and waiters found, but we expected to have at least one missing" :
		    "Missing expected waiters or blockers in vmrl rels");
		return_code = ERROR_CODE;
	}

cleanup:
	free(threads);
	free(blockers);
	free(waiters);
	if (return_code == SUCCESS_CODE) {
		T_PASS("Deadlock stackshot test completed. Stackshot took %fms", (double)stackshot_duration_ns / 1000000);
	}
	return return_code;
}


T_DECL(vmel_sh_awaits_excl,
    "one reader waits for one writer",
    T_META_ENABLED(true /* rdar://164536292 */),
    T_META_ASROOT(true))
{
	first_is_excl = true;
	lckng_type_t other_threads_locktype = LCKNG_TYPE_SHARED;
	num_threads = 2;
	run_test(other_threads_locktype, "vmel_sh_awaits_excl", false);
}

T_DECL(vmel_excl_awaits_sh,
    "one writer waits for one reader",
    T_META_ENABLED(true /* rdar://164536292 */),
    T_META_ASROOT(true))
{
	first_is_excl = false;
	lckng_type_t other_threads_locktype = LCKNG_TYPE_EXCLUSIVE;
	num_threads = 2;
	run_test(other_threads_locktype, "vmel_excl_awaits_sh", false);
}

T_DECL(vmel_sh_await_excl,
    "multiple readers wait for one writer",
    T_META_ENABLED(true /* rdar://164536292 */),
    T_META_ASROOT(true))
{
	first_is_excl = true;
	lckng_type_t other_threads_locktype = LCKNG_TYPE_SHARED;
	num_threads = 5;
	run_test(other_threads_locktype, "vmel_sh_await_excl", false);
}

T_DECL(vmel_excl_awaits_mult_sh,
    "one writer waits for multiple readers",
    T_META_ENABLED(true /* rdar://164536292 */),
    T_META_ASROOT(true))
{
	first_is_excl = false;
	lckng_type_t other_threads_locktype = LCKNG_TYPE_SHARED;
	num_threads = 5;
	run_test(other_threads_locktype, "vmel_excl_awaits_mult_sh", false);
}

T_DECL(vmel_excl_await_excl,
    "multiple writers wait for one writer",
    T_META_ENABLED(true /* rdar://164536292 */),
    T_META_ASROOT(true)){
	first_is_excl = true;
	lckng_type_t other_threads_locktype = LCKNG_TYPE_EXCLUSIVE;
	num_threads = 5;
	run_test(other_threads_locktype, "vmel_excl_await_excl", false);
}

T_DECL(vmel_exceed_write,
    "num_rels > 256, we should just see a writer waiting for 256 readers",
    T_META_ENABLED(true /* rdar://164536292 */),
    T_META_ASROOT(true))
{
	first_is_excl = false;
	lckng_type_t other_threads_locktype = LCKNG_TYPE_SHARED;
	num_threads = 258;
	run_test(other_threads_locktype, "vmel_exceed_write", true);
}

T_DECL(vmel_exceed_read,
    "num_rels > 256, we should just see 256 readers waiting for one writer",
    T_META_ENABLED(true /* rdar://164536292 */),
    T_META_ASROOT(true))
{
	first_is_excl = true;
	lckng_type_t other_threads_locktype = LCKNG_TYPE_SHARED;
	num_threads = 258;
	run_test(other_threads_locktype, "vmel_exceed_read", true);
}

/* This is sort of a benchmark for comparison of how long it took to take a system wide stackshot */
T_DECL(vmel_just_do_stackshot,
    "vmel_just_do_stackshot",
    T_META_ASROOT(true))
{
	uint64_t duration;
	take_stackshot(&duration);
	T_PASS("stackshot test completed. Took %fms", (double)duration / 1000000);
}
