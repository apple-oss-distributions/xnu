#include <mach/mach_port.h>
#include <mach/mach_vm.h>
#include <mach/vm_map.h>
#include <sys/sysctl.h>
#include <signal.h>
#include <darwintest.h>
#include <darwintest_utils.h>
#include <string.h>
#include <mach/mach.h>
#include <mach/task.h>
#include <mach/port.h>
#include <pthread.h>
#include <dispatch/dispatch.h>
#include <sys/proc.h>
#include <sys/mman.h>

/*
 * We want to copy_overwrite in the range:
 * we want to randomly take fast or slow path
 * to do that, let's have one thread doing mprotect(RANGE)
 * one thread doing vm_map_inherit (switcheroo)
 * [addr, addr + (32 * 1024) * 5)
 */

#define RANGE_SIZE (32 * 1024) * 5
#define KERNEL_BUFFER_COPY_THRESHOLD (32 * 1024)

bool done;

static mach_vm_address_t
rand_addr_in_range(mach_vm_address_t min, mach_vm_address_t max)
{
	return (rand() % (max - min)) + min;
}

static mach_vm_address_t
rand_page_in_range(mach_vm_address_t min, mach_vm_address_t max)
{
	return mach_vm_trunc_page(rand_addr_in_range(min, max));
}

/* Do a vm_map_protect of the whole range s.t. we do a simplify */
static void *
mprotecter(void * arg)
{
	mach_vm_address_t addr = (mach_vm_address_t) arg;
	while (!done) {
		kern_return_t kr = mach_vm_protect(mach_task_self(), addr, RANGE_SIZE, false, VM_PROT_DEFAULT);
		assert(kr == KERN_SUCCESS);
	}
	return NULL;
}

/* do a vm_map_inherit s.t. we do a clip */
static void *
minheriter(void * arg)
{
	mach_vm_address_t addr = (mach_vm_address_t) arg;
	while (!done) {
		mach_vm_address_t start = rand_page_in_range(addr, addr + RANGE_SIZE - PAGE_SIZE);
		mach_vm_address_t end =   rand_page_in_range(start, addr + RANGE_SIZE);
		kern_return_t kr;

		/* minherit random range */
		kr = mach_vm_inherit(mach_task_self(), start, end - start, VM_INHERIT_COPY);
		assert(kr == KERN_SUCCESS);
		kr = mach_vm_inherit(mach_task_self(), start, end - start, VM_INHERIT_DEFAULT);
		assert(kr == KERN_SUCCESS);
	}
	return NULL;
}


mach_port_t obj1;
mach_port_t obj2;

static void *
mapper(void * arg)
{
	/* Map a diff object over each page */
	mach_vm_address_t addr = (mach_vm_address_t) arg;
	while (!done) {
		mach_port_t object;
		if (rand() % 2 == 0) {
			object = obj1;
		} else {
			object = obj2;
		}
		mach_vm_address_t start = rand_page_in_range(addr, addr + RANGE_SIZE - PAGE_SIZE);
		kern_return_t kr = mach_vm_map(mach_task_self(), &start, PAGE_SIZE, 0,
		    VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, object,
		    start - addr, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
		T_QUIET; T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "mach_vm_map");
	}
	return NULL;
}



mach_vm_address_t src_addr;
mach_vm_address_t dst_addr;

/* Copy overwrite two random addresses within the range. */
static void*
copy_overwrite_thread(void * args)
{
	time_t duration = (time_t) args;
	time_t start;
	for (start = time(NULL); (time(NULL) < start + duration) && !done;) {
		mach_vm_address_t src_start = rand_addr_in_range(src_addr, src_addr + RANGE_SIZE);
		mach_vm_address_t dst_start = rand_addr_in_range(dst_addr, dst_addr + RANGE_SIZE);
		mach_vm_size_t len = RANGE_SIZE - MAX(src_start - src_addr, dst_start - dst_addr);
		if (len < PAGE_SIZE) {
			continue;
		}
		kern_return_t kr = mach_vm_copy(mach_task_self(), src_start, len, dst_start);
		assert(kr == KERN_SUCCESS);
	}

	done = true;
	return NULL;
}


/*
 * Two regions, one src, one dst.
 * Each region is randomly backed by either obj1 (a COPY_NONE object) or obj2
 * a (COPY_DELAY object).
 *
 * We then do fixed overwrite mappings of each object over each page in the region.
 * Concurrently, we do copy_overwrites from the src to the dst. No actual checking
 * is done to make sure the "right" data is written, but just that kr = KERN_SUCCESS.
 * That's probably something valuable to add in the future.
 *
 * In addition, we have one thread doing mprotect(), which will attempt to simplify
 * the range.
 * Along with one thread doing minherit, which will do arbitrary clips for the range.
 *
 * The duration can be specified in seconds. Thenumber of threads doing copy_overwrites
 * can also be changed.
 */

void
copy_overwrite_race_test(time_t duration, uint8_t num_copy_overwrite_threads)
{
	T_LOG("Testing for %ld seconds...", duration);
	done = false;

	pthread_t copy_overwrite_threads[num_copy_overwrite_threads];

	mach_port_t out_handle;
	kern_return_t kr = mach_memory_object_memory_entry_64(mach_host_self(), 1, RANGE_SIZE, VM_PROT_DEFAULT, 0, &out_handle);
	assert(kr == KERN_SUCCESS);
	obj1 = out_handle;

	memory_object_size_t s = (memory_object_size_t)RANGE_SIZE;
	kr = mach_make_memory_entry_64(mach_host_self(), &s, (memory_object_offset_t)0, MAP_MEM_NAMED_CREATE | MAP_MEM_LEDGER_TAGGED  | VM_PROT_DEFAULT, &out_handle, MACH_PORT_NULL);
	assert(kr == KERN_SUCCESS);
	obj2 = out_handle;

	kr = mach_vm_allocate(mach_task_self(), &src_addr, RANGE_SIZE, VM_FLAGS_ANYWHERE);
	assert(kr == KERN_SUCCESS);
	kr = mach_vm_allocate(mach_task_self(), &dst_addr, RANGE_SIZE, VM_FLAGS_ANYWHERE);
	assert(kr == KERN_SUCCESS);

	pthread_t mprotect_thread, mprotect_thread2;
	pthread_create(&mprotect_thread, NULL, mprotecter, (void *) src_addr);
	pthread_create(&mprotect_thread2, NULL, mprotecter, (void *) dst_addr);

	pthread_t minherit_thread, minherit_thread2;
	pthread_create(&minherit_thread, NULL, minheriter, (void *) src_addr);
	pthread_create(&minherit_thread2, NULL, minheriter, (void *) dst_addr);

	pthread_t map_thread, map_thread2;
	pthread_create(&map_thread, NULL, mapper, (void *) src_addr);
	pthread_create(&map_thread2, NULL, mapper, (void *) dst_addr);

	for (uint8_t i = 0; i < num_copy_overwrite_threads; i++) {
		pthread_create(&copy_overwrite_threads[i], NULL, copy_overwrite_thread, (void *) duration);
	}

	void *unused;

	for (uint8_t i = 0; i < num_copy_overwrite_threads; i++) {
		pthread_join(copy_overwrite_threads[i], &unused);
	}

	pthread_join(mprotect_thread, &unused);
	pthread_join(minherit_thread, &unused);
	pthread_join(map_thread, &unused);

	pthread_join(mprotect_thread2, &unused);
	pthread_join(minherit_thread2, &unused);
	pthread_join(map_thread2, &unused);

	T_PASS("Race test passed");
}


T_DECL(copy_overwrite_with_races, "copy_overwrite_with_races")
{
	copy_overwrite_race_test(5, 2);
	copy_overwrite_race_test(5, 1);
}
