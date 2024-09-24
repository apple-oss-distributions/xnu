/**
 *  neural_footprint.c
 *  Neural composite footprint ledger test
 *
 * Test various memory settings to ensure correct accounting
 * Copyright (c) 2023 Apple Inc. All rights reserved.
 */

#include <sys/mman.h>
#include <mach/vm_map.h>
#include <mach/mach_vm.h>
#include <mach/mach_port.h>
#include <mach/mach_init.h>
#include <mach/mach_error.h>
#include <darwintest_utils.h>
#include <libproc_internal.h>
#include <mach/memory_entry.h>
#include <Kernel/kern/ledger.h>


extern int ledger(int cmd, caddr_t arg1, caddr_t arg2, caddr_t arg3);

#define ALLOCATION_SIZE (10 * vm_kernel_page_size)  /* 10 pages */

T_GLOBAL_META(
	T_META_RUN_CONCURRENTLY(true),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"));

static int neural_nofootprint_index = -1;
static int neural_nofootprint_compressed_index = -1;
static int neural_total_index = -1;
static int neural_footprint_index = -1;
static int neural_footprint_compressed_index = -1;

static uint64_t neural_nofootprint_before;
static uint64_t neural_nofootprint_compressed_before;
static uint64_t neural_footprint_before;
static uint64_t neural_footprint_compressed_before;
static uint64_t neural_total_before;
static uint64_t neural_nofootprint_after;
static uint64_t neural_nofootprint_compressed_after;
static uint64_t neural_footprint_after;
static uint64_t neural_footprint_compressed_after;
static uint64_t neural_total_after;

static int64_t  ledger_count = -1;
static struct   ledger_entry_info *lei = NULL;

static uint64_t phys_max_before, phys_max_after;
static struct   rusage_info_v6   ru;
static uint64_t neural_lifetime_max;



static void
ledger_init(void)
{
	kern_return_t                   kr;
	static int                      ledger_inited = 0;
	struct ledger_template_info     *templateInfo;
	int64_t                         templateCnt;
	struct ledger_info              li;
	if (ledger_inited) {
		return;
	}
	ledger_inited = 1;

	T_SETUPBEGIN;

	kr = ledger(LEDGER_INFO,
	    (caddr_t)(uintptr_t)getpid(),
	    (caddr_t)&li,
	    NULL);

	T_ASSERT_MACH_SUCCESS(kr, "ledger() 0x%x (%s)",
	    kr, mach_error_string(kr));

	templateCnt = li.li_entries;
	templateInfo = malloc((size_t)li.li_entries *
	    sizeof(struct ledger_template_info));
	T_QUIET;
	T_WITH_ERRNO;
	T_ASSERT_NOTNULL(templateInfo, "malloc()");

	ledger_count = li.li_entries;

	T_QUIET;
	T_WITH_ERRNO;
	T_ASSERT_POSIX_SUCCESS(ledger(LEDGER_TEMPLATE_INFO,
	    (caddr_t)templateInfo,
	    (caddr_t)&templateCnt,
	    NULL),
	    "ledger(LEDGER_TEMPLATE_INFO)");
	for (int i = 0; i < templateCnt; i++) {
		if (!strncmp(templateInfo[i].lti_name,
		    "neural_nofootprint_compressed",
		    strlen("neural_nofootprint_compressed"))) {
			neural_nofootprint_compressed_index = i;
			T_LOG("Acquired index of neural_nofootprint_compressed");
		} else if (!strncmp(templateInfo[i].lti_name,
		    "neural_footprint_compressed",
		    strlen("neural_footprint_compressed"))) {
			neural_footprint_compressed_index = i;
			T_LOG("Acquired index of neural_footprint_compressed");
		} else if (!strncmp(templateInfo[i].lti_name,
		    "neural_nofootprint_total",
		    strlen("neural_nofootprint_total"))) {
			neural_total_index = i;
			T_LOG("Acquired index of neural_nofootprint_total");
		} else if (!strncmp(templateInfo[i].lti_name,
		    "neural_nofootprint",
		    strlen("neural_nofootprint"))) {
			neural_nofootprint_index = i;
			T_LOG("Acquired index of neural_nofootprint");
		} else if (!strncmp(templateInfo[i].lti_name,
		    "neural_footprint",
		    strlen("neural_footprint"))) {
			neural_footprint_index = i;
			T_LOG("Acquired index of neural_footprint");
		}
	}
	free(templateInfo);

	lei = (struct ledger_entry_info *)
	    malloc((size_t)ledger_count * sizeof(*lei));
	T_QUIET;
	T_WITH_ERRNO;
	T_ASSERT_NE(lei, NULL,
	    "malloc(ledger_entry_info)");

	T_QUIET;
	T_ASSERT_NE(neural_nofootprint_compressed_index, -1,
	    "no nofootprint_compressed_index");
	T_QUIET;
	T_ASSERT_NE(neural_footprint_compressed_index, -1,
	    "no footprint_compressed_index");
	T_QUIET;
	T_ASSERT_NE(neural_total_index, -1,
	    "no nofootprint_total_index");
	T_QUIET;
	T_ASSERT_NE(neural_nofootprint_index, -1,
	    "no nofootprint_index");
	T_QUIET;
	T_ASSERT_NE(neural_footprint_index, -1,
	    "no footprint_index");

	T_SETUPEND;
}

static void
get_ledger_info(
	uint64_t        *neural_nofootprint,
	uint64_t        *neural_nofootprint_compressed,
	uint64_t        *neural_footprint,
	uint64_t        *neural_footprint_compressed,
	uint64_t        *neural_total)
{
	int64_t count;

	count = ledger_count;
	T_QUIET;
	T_WITH_ERRNO;
	T_ASSERT_POSIX_SUCCESS(ledger(LEDGER_ENTRY_INFO,
	    (caddr_t)(uintptr_t)getpid(),
	    (caddr_t)lei,
	    (caddr_t)&count),
	    "ledger(LEDGER_ENTRY_INFO)");
	T_QUIET;
	T_ASSERT_GT(count, (int64_t)neural_nofootprint_index,
	    "no entry for neural_nofootprint");
	T_QUIET;
	T_ASSERT_GT(count, (int64_t)neural_nofootprint_compressed_index,
	    "no entry for neural_nofootprint_compressed");
	T_QUIET;
	T_ASSERT_GT(count, (int64_t)neural_total_index,
	    "no entry for neural_total");
	T_QUIET;
	T_ASSERT_GT(count, (int64_t)neural_footprint_compressed_index,
	    "no entry for neural_footprint_compressed");
	T_QUIET;
	T_ASSERT_GT(count, (int64_t)neural_footprint_index,
	    "no entry for neural_footprint");
	if (neural_footprint_index) {
		*neural_footprint = (uint64_t)(lei[neural_footprint_index].lei_balance);
	}
	if (neural_footprint_compressed_index) {
		*neural_footprint_compressed = (uint64_t)(
			lei[neural_footprint_compressed_index].lei_balance);
	}
	if (neural_nofootprint_index) {
		*neural_nofootprint = (uint64_t)(lei[neural_nofootprint_index].lei_balance);
	}
	if (neural_nofootprint_compressed_index) {
		*neural_nofootprint_compressed = (uint64_t)(
			lei[neural_nofootprint_compressed_index].lei_balance);
	}
	if (neural_total_index) {
		*neural_total = (uint64_t)(lei[neural_total_index].lei_balance);
	}
}

static void
get_ledger_before(void)
{
	get_ledger_info(
		&neural_nofootprint_before,
		&neural_nofootprint_compressed_before,
		&neural_footprint_before,
		&neural_footprint_compressed_before,
		&neural_total_before);
	T_LOG(
		"*** pages before: footprint:%llu compr:%llu nofootprint:%llu nofootprint compr: %llu, total: %llu",
		neural_footprint_before / vm_kernel_page_size,
		neural_footprint_compressed_before / vm_kernel_page_size,
		neural_nofootprint_before / vm_kernel_page_size,
		neural_nofootprint_compressed_before / vm_kernel_page_size,
		neural_total_before / vm_kernel_page_size);
}

static void
get_ledger_after(void)
{
	get_ledger_info(
		&neural_nofootprint_after,
		&neural_nofootprint_compressed_after,
		&neural_footprint_after,
		&neural_footprint_compressed_after,
		&neural_total_after);

	T_LOG(
		"*** pages after: footprint:%llu compr:%llu nofootprint:%llu nofootprint compr: %llu, total: %llu",
		neural_footprint_after / vm_kernel_page_size,
		neural_footprint_compressed_after / vm_kernel_page_size,
		neural_nofootprint_after / vm_kernel_page_size,
		neural_nofootprint_compressed_after / vm_kernel_page_size,
		neural_total_after / vm_kernel_page_size);
}

static void
compress_pages(mach_vm_address_t vm_addr, mach_vm_size_t vm_size)
{
	int ret;
	T_LOG(">>>> Compress all pages");
	unsigned char *cp;
	cp = (unsigned char *)(uintptr_t)vm_addr;
	T_ASSERT_POSIX_SUCCESS(
		madvise(cp,
		(size_t)vm_size,
		MADV_PAGEOUT),
		"page out all with madvise");

	T_LOG("...> Wait for pages to be compressed");
	unsigned char vec;

	for (size_t idx = 0; idx < vm_size; idx += vm_kernel_page_size) {
		do {
			ret = mincore(&cp[idx], 1, (char *)&vec);
			if (ret != 0) {
				T_ASSERT_POSIX_SUCCESS(ret, "failed on mincore check");
			}
		} while (vec & MINCORE_INCORE);
	}
}

static void
uncompress_pages(mach_vm_address_t vm_addr, mach_vm_size_t vm_size)
{
	T_LOG("<<<< Reading pages to bring back from compressor");
	unsigned char *cp;
	cp = (unsigned char *)(uintptr_t)vm_addr;
	memset(cp, 0xff, vm_size);
}

static void
check_phys_footprint_rusage(void)
{
	int ret;
	T_LOG("---? Check phys footprint lifetime max and max interval");

	ret = proc_pid_rusage(getpid(), RUSAGE_INFO_V6, (rusage_info_t *)&ru);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(ret, "proc_pid_rusage");
	phys_max_before = ru.ri_lifetime_max_phys_footprint;
	T_LOG("Phys max: %llu", ru.ri_lifetime_max_phys_footprint);
}

static void
check_phys_footprint_rusage_after(void)
{
	int ret;

	T_LOG("---? Check phys footprint lifetime max and max interval");

	ret = proc_pid_rusage(getpid(), RUSAGE_INFO_V6, (rusage_info_t *)&ru);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(ret, "proc_pid_rusage");
	phys_max_after = ru.ri_lifetime_max_phys_footprint;;
	T_LOG("Phys_footprint max: %llu  before: %llu  diff: %llu",
	    phys_max_after,
	    phys_max_before,
	    phys_max_after - phys_max_before);

	T_ASSERT_EQ(0ULL, phys_max_after - phys_max_before,
	    "Phys footprint lifetime max shouldn't change");
}

static void
make_volatile(mach_vm_address_t vm_addr)
{
	kern_return_t kr;
	vm_purgable_t state;
	char *vm_purgable_state[4] = {
		"nonvolatile",
		"volatile",
		"empty",
		"deny"
	};
	state = VM_PURGABLE_VOLATILE;
	kr = mach_vm_purgable_control(
		mach_task_self(),
		vm_addr,
		VM_PURGABLE_SET_STATE,
		&state);
	T_ASSERT_MACH_SUCCESS(kr, "vm_purgable_control(volatile)");
	T_ASSERT_EQ(state, VM_PURGABLE_NONVOLATILE,
	    "nonvolatile -> volatile: state was %s",
	    vm_purgable_state[state]);
}

static void
make_nonvolatile(mach_vm_address_t vm_addr)
{
	kern_return_t kr;
	vm_purgable_t state;
	char *vm_purgable_state[4] = {
		"nonvolatile",
		"volatile",
		"empty",
		"deny"
	};
	state = VM_PURGABLE_NONVOLATILE;
	kr = mach_vm_purgable_control(
		mach_task_self(),
		vm_addr,
		VM_PURGABLE_SET_STATE,
		&state);
	T_ASSERT_MACH_SUCCESS(kr, "vm_purgable_control(nonvolatile)");
	T_ASSERT_EQ(state, VM_PURGABLE_VOLATILE,
	    "volatile -> nonvolatile: state was %s",
	    vm_purgable_state[state]);
}

static void
reset_max_interval(uint64_t check)
{
	int ret;
	T_LOG("---> Reset interval max");
	ret = proc_reset_footprint_interval(getpid());
	T_ASSERT_POSIX_SUCCESS(ret, "proc_reset_footprint_interval()");

	ret = proc_pid_rusage(getpid(), RUSAGE_INFO_V6, (rusage_info_t *)&ru);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(ret, "proc_pid_rusage");
	T_EXPECT_EQ(check, ru.ri_interval_max_neural_footprint,
	    "Neural max interval footprint is %llu pages", check / vm_kernel_page_size);
}

T_DECL(check_neural_total_ledger,
    "Check neural totall ledger",
    T_META_LTEPHASE(LTE_POSTINIT))
{
	int                     ret;
	kern_return_t           kr;
	mach_vm_size_t          vm_size, me_size;
	mach_port_t             footprint_port, nofootprint_port;
	mach_port_t             footprint_port2, nofootprint_port2;
	mach_port_t             file_mem_entry;
	vm_prot_t               permissions;

	mach_vm_address_t       footprint_vm_addr = 0, nofootprint_vm_addr = 0;
	mach_vm_address_t       footprint_vm_addr2 = 0, nofootprint_vm_addr2 = 0;
	mach_vm_size_t          dirty_size = ALLOCATION_SIZE;

	ledger_init();

	get_ledger_before();

	vm_size = ALLOCATION_SIZE;
	me_size = vm_size;
	footprint_port = MACH_PORT_NULL;
	nofootprint_port = MACH_PORT_NULL;

	permissions = MAP_MEM_NAMED_CREATE |
	    MAP_MEM_PURGABLE |
	    MAP_MEM_LEDGER_TAGGED |
	    VM_PROT_DEFAULT;

	T_LOG("---> Allocate for footprint");
	kr = mach_make_memory_entry_64(
		mach_task_self(),
		&me_size,
		0,
		permissions,
		&footprint_port,
		MACH_PORT_NULL);
	T_ASSERT_MACH_SUCCESS(kr, "make_memory_entry()");
	T_ASSERT_EQ(me_size, vm_size, "checking memory entry size mismatch");

	T_LOG("---> Allocate for nofootprint");
	kr = mach_make_memory_entry_64(
		mach_task_self(),
		&me_size,
		0,
		permissions,
		&nofootprint_port,
		MACH_PORT_NULL);
	T_ASSERT_MACH_SUCCESS(kr, "make_memory_entry()");
	T_ASSERT_EQ(me_size, vm_size, "checking memory entry size mismatch");

	T_LOG("---> Allocate for secondary footprint");
	kr = mach_make_memory_entry_64(
		mach_task_self(),
		&me_size,
		0,
		permissions,
		&footprint_port2,
		MACH_PORT_NULL);
	T_ASSERT_MACH_SUCCESS(kr, "make_memory_entry()");
	T_ASSERT_EQ(me_size, vm_size, "checking memory entry size mismatch");

	T_LOG("---> Allocate for secondary nofootprint");
	kr = mach_make_memory_entry_64(
		mach_task_self(),
		&me_size,
		0,
		permissions,
		&nofootprint_port2,
		MACH_PORT_NULL);
	T_ASSERT_MACH_SUCCESS(kr, "make_memory_entry()");
	T_ASSERT_EQ(me_size, vm_size, "checking memory entry size mismatch");

	T_LOG("---> Allocate for file footprint");
	char const *tmp_dir = dt_tmpdir();
	char filepath[MAXPATHLEN];
	int fd = -1;
	char *file_addr = NULL;
	snprintf(filepath, sizeof(filepath), "%s/file.XXXXXX", tmp_dir);
	T_ASSERT_POSIX_SUCCESS(fd = mkstemp(filepath), NULL);
	T_ASSERT_POSIX_SUCCESS(unlink(filepath), NULL);
	T_ASSERT_POSIX_SUCCESS(ftruncate(fd, (off_t)vm_size), NULL);
	T_ASSERT_POSIX_SUCCESS(file_addr = mmap(NULL, (size_t)vm_size, PROT_READ, MAP_FILE | MAP_SHARED, fd, 0), NULL);
	me_size = vm_size;
	T_ASSERT_MACH_SUCCESS(mach_make_memory_entry_64(
		    mach_task_self(),
		    &me_size,
		    (memory_object_offset_t)(uintptr_t)file_addr,
		    /* MAP_MEM_LEDGER_TAGGED | */ VM_PROT_READ,
		    &file_mem_entry,
		    MACH_PORT_NULL), NULL);
	T_ASSERT_EQ(me_size, vm_size, "checking memory entry size mismatch");
	T_ASSERT_POSIX_SUCCESS(mlock(file_addr, (size_t)vm_size), NULL);


	get_ledger_after();
	T_LOG("Change is not expected on neural ledgers");
	T_ASSERT_EQ(neural_nofootprint_before, neural_nofootprint_after,
	    "neural entry size changed %llu -> %llu",
	    neural_nofootprint_before, neural_nofootprint_after);
	T_ASSERT_EQ(neural_nofootprint_compressed_before, neural_nofootprint_compressed_after,
	    "neural entry size changed %llu -> %llu",
	    neural_nofootprint_compressed_before, neural_nofootprint_compressed_after);
	T_ASSERT_EQ(neural_footprint_before, neural_footprint_after,
	    "neural entry size changed %llu -> %llu",
	    neural_footprint_before, neural_footprint_after);
	T_ASSERT_EQ(neural_footprint_compressed_before, neural_footprint_compressed_after,
	    "neural entry size changed %llu -> %llu",
	    neural_footprint_compressed_before, neural_footprint_compressed_after);
	T_ASSERT_EQ(neural_total_before, neural_total_after,
	    "neural entry size changed %llu -> %llu",
	    neural_total_before, neural_total_after);


	T_ASSERT_MACH_SUCCESS(
		mach_vm_map(
			mach_task_self(),
			&footprint_vm_addr,
			dirty_size,
			0, /* mask */
			VM_FLAGS_ANYWHERE,
			footprint_port,
			0, /* offset */
			false, /* copy */
			VM_PROT_DEFAULT,
			VM_PROT_DEFAULT,
			VM_INHERIT_NONE),
		"mach_vm_map() for primary neural footprint"
		);

	T_ASSERT_MACH_SUCCESS(
		mach_vm_map(
			mach_task_self(),
			&nofootprint_vm_addr,
			dirty_size,
			0, /* mask */
			VM_FLAGS_ANYWHERE,
			nofootprint_port,
			0, /* offset */
			false, /* copy */
			VM_PROT_DEFAULT,
			VM_PROT_DEFAULT,
			VM_INHERIT_NONE),
		"mach_vm_map() for primary neural nofootprint"
		);

	T_ASSERT_MACH_SUCCESS(
		mach_vm_map(
			mach_task_self(),
			&footprint_vm_addr2,
			dirty_size,
			0, /* mask */
			VM_FLAGS_ANYWHERE,
			footprint_port2,
			0, /* offset */
			false, /* copy */
			VM_PROT_DEFAULT,
			VM_PROT_DEFAULT,
			VM_INHERIT_NONE),
		"mach_vm_map() for secondary neural footprint"
		);

	T_ASSERT_MACH_SUCCESS(
		mach_vm_map(
			mach_task_self(),
			&nofootprint_vm_addr2,
			dirty_size,
			0, /* mask */
			VM_FLAGS_ANYWHERE,
			nofootprint_port2,
			0, /* offset */
			false, /* copy */
			VM_PROT_DEFAULT,
			VM_PROT_DEFAULT,
			VM_INHERIT_NONE),
		"mach_vm_map() for secondary neural nofootprint"
		);

	T_LOG("Dirtying pages");
	memset((char *)(uintptr_t)footprint_vm_addr, 0xaa, (size_t)dirty_size);
	memset((char *)(uintptr_t)footprint_vm_addr2, 0xbb, (size_t)dirty_size);
	memset((char *)(uintptr_t)nofootprint_vm_addr, 0xcc, (size_t)dirty_size);
	memset((char *)(uintptr_t)nofootprint_vm_addr2, 0xdd, (size_t)dirty_size);

	T_LOG("Checking if compression works correctly with phys_footprint");
	check_phys_footprint_rusage();

	compress_pages(footprint_vm_addr, vm_size);

	check_phys_footprint_rusage_after();

	uncompress_pages(footprint_vm_addr, vm_size);

	get_ledger_before();

	T_LOG("---> Move primary footprint to neural");
	kr = mach_memory_entry_ownership(
		footprint_port, /* entry port */
		TASK_NULL,  /* owner remains unchanged */
		VM_LEDGER_TAG_NEURAL, /* ledger-tag */
		0); /* ledger flags */
	T_ASSERT_MACH_SUCCESS(kr,
	    "mach_memory_entry_ownership() primary neural footprint 0x%x (%s)",
	    kr, mach_error_string(kr));

	get_ledger_after();

	T_ASSERT_EQ(
		neural_footprint_before + vm_size,
		neural_footprint_after,
		"neural footprint increased  %llu -> %llu pages",
		neural_footprint_before / vm_kernel_page_size,
		neural_footprint_after / vm_kernel_page_size);
	T_ASSERT_EQ(
		0ULL,
		neural_total_after,
		"neural total is zero  %llu -> %llu pages",
		neural_total_before / vm_kernel_page_size,
		neural_total_after / vm_kernel_page_size);

	T_LOG("---> Move secondary footprint to neural");
	get_ledger_before();
	kr = mach_memory_entry_ownership(
		footprint_port2, /* entry port */
		TASK_NULL,  /* owner remains unchanged */
		VM_LEDGER_TAG_NEURAL, /* ledger-tag */
		0); /* ledger flags */
	T_ASSERT_MACH_SUCCESS(kr,
	    "mach_memory_entry_ownership() primary neural footprint 0x%x (%s)",
	    kr, mach_error_string(kr));
	get_ledger_after();

	T_ASSERT_EQ(
		neural_footprint_before + vm_size,
		neural_footprint_after,
		"neural footprint increased  %llu -> %llu pages",
		neural_footprint_before / vm_kernel_page_size,
		neural_footprint_after / vm_kernel_page_size);
	T_ASSERT_EQ(
		0ULL,
		neural_total_after,
		"neural total is zero  %llu -> %llu pages",
		neural_total_before / vm_kernel_page_size,
		neural_total_after / vm_kernel_page_size);

	T_LOG("---> Move primary nofootprint to neural");
	get_ledger_before();
	kr = mach_memory_entry_ownership(
		nofootprint_port, /* entry port */
		TASK_NULL,  /* owner remains unchanged */
		VM_LEDGER_TAG_NEURAL, /* ledger-tag */
		VM_LEDGER_FLAG_NO_FOOTPRINT); /* ledger flags */
	T_ASSERT_MACH_SUCCESS(kr,
	    "mach_memory_entry_ownership() primary neural footprint 0x%x (%s)",
	    kr, mach_error_string(kr));

	get_ledger_after();
	T_ASSERT_EQ(
		neural_nofootprint_before + vm_size,
		neural_nofootprint_after,
		"neural nofootprint increased  %llu -> %llu pages",
		neural_nofootprint_before / vm_kernel_page_size,
		neural_nofootprint_after / vm_kernel_page_size);
	T_ASSERT_EQ(
		neural_total_before + vm_size,
		neural_total_after,
		"neural total increased  %llu -> %llu pages",
		neural_total_before / vm_kernel_page_size,
		neural_total_after / vm_kernel_page_size);

	T_LOG("---> Move secondary nofootprint to neural");
	get_ledger_before();
	kr = mach_memory_entry_ownership(
		nofootprint_port2, /* entry port */
		TASK_NULL,  /* owner remains unchanged */
		VM_LEDGER_TAG_NEURAL, /* ledger-tag */
		VM_LEDGER_FLAG_NO_FOOTPRINT); /* ledger flags */
	T_ASSERT_MACH_SUCCESS(kr,
	    "mach_memory_entry_ownership() primary neural footprint 0x%x (%s)",
	    kr, mach_error_string(kr));

	get_ledger_after();
	T_ASSERT_EQ(
		neural_nofootprint_before + vm_size,
		neural_nofootprint_after,
		"neural nofootprint increased  %llu -> %llu pages",
		neural_nofootprint_before / vm_kernel_page_size,
		neural_nofootprint_after / vm_kernel_page_size);
	T_ASSERT_EQ(
		neural_total_before + vm_size,
		neural_total_after,
		"neural total increased  %llu -> %llu pages",
		neural_total_before / vm_kernel_page_size,
		neural_total_after / vm_kernel_page_size);

	neural_lifetime_max = neural_total_after;

	T_LOG("---? Check neural total lifetime max and max interval");
	ret = proc_pid_rusage(getpid(), RUSAGE_INFO_V6, (rusage_info_t *)&ru);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(ret, "proc_pid_rusage");
	T_EXPECT_EQ(ru.ri_lifetime_max_neural_footprint,
	    neural_total_after,
	    "Neural max footprint is equal to 4 x vm_size (in pages): %llu = %llu",
	    ru.ri_lifetime_max_neural_footprint / vm_kernel_page_size,
	    4 * vm_size / vm_kernel_page_size);
	T_EXPECT_EQ(ru.ri_interval_max_neural_footprint,
	    neural_total_after,
	    "Neural max interval footprint is equal to current neural total: %llu = %llu",
	    ru.ri_interval_max_neural_footprint / vm_kernel_page_size,
	    neural_total_after / vm_kernel_page_size);

	T_LOG("---> compress primary footprint");
	get_ledger_before();
	compress_pages(footprint_vm_addr, vm_size);
	get_ledger_after();
	T_ASSERT_EQ(
		neural_footprint_before - vm_size,
		neural_footprint_after,
		"neural footprint decreased  %llu -> %llu pages",
		neural_footprint_before / vm_kernel_page_size,
		neural_footprint_after / vm_kernel_page_size);
	T_ASSERT_EQ(
		neural_footprint_compressed_before + vm_size,
		neural_footprint_compressed_after,
		"neural footprint compressed increased  %llu -> %llu pages",
		neural_footprint_compressed_before / vm_kernel_page_size,
		neural_footprint_compressed_after / vm_kernel_page_size);
	T_ASSERT_EQ(
		neural_total_before,
		neural_total_after,
		"neural total did not change  %llu -> %llu pages",
		neural_total_before / vm_kernel_page_size,
		neural_total_after / vm_kernel_page_size);


	T_LOG("---> compress primary nofootprint");
	get_ledger_before();
	compress_pages(nofootprint_vm_addr, vm_size);
	get_ledger_after();
	T_ASSERT_EQ(
		neural_nofootprint_before - vm_size,
		neural_nofootprint_after,
		"neural nofootprint decreased  %llu -> %llu pages",
		neural_nofootprint_before / vm_kernel_page_size,
		neural_nofootprint_after / vm_kernel_page_size);
	T_ASSERT_EQ(
		neural_nofootprint_compressed_before + vm_size,
		neural_nofootprint_compressed_after,
		"neural nofootprint compressed increased  %llu -> %llu pages",
		neural_nofootprint_compressed_before / vm_kernel_page_size,
		neural_nofootprint_compressed_after / vm_kernel_page_size);
	T_ASSERT_EQ(
		neural_total_before,
		neural_total_after,
		"neural total did not change  %llu -> %llu pages",
		neural_total_before / vm_kernel_page_size,
		neural_total_after / vm_kernel_page_size);

	T_LOG("---> Decompress primary footprint");
	get_ledger_before();
	uncompress_pages(footprint_vm_addr, vm_size);
	get_ledger_after();
	T_ASSERT_EQ(
		neural_footprint_before + vm_size,
		neural_footprint_after,
		"neural footprint increased  %llu -> %llu pages",
		neural_footprint_before / vm_kernel_page_size,
		neural_footprint_after / vm_kernel_page_size);
	T_ASSERT_EQ(
		neural_footprint_compressed_before - vm_size,
		neural_footprint_compressed_after,
		"neural footprint compressed decreased  %llu -> %llu pages",
		neural_footprint_compressed_before / vm_kernel_page_size,
		neural_footprint_compressed_after / vm_kernel_page_size);
	T_ASSERT_EQ(
		neural_total_before,
		neural_total_after,
		"neural total did not change  %llu -> %llu pages",
		neural_total_before / vm_kernel_page_size,
		neural_total_after / vm_kernel_page_size);

	T_LOG("---> Make primary footprint volatile");
	get_ledger_before();
	make_volatile(footprint_vm_addr);
	get_ledger_after();
	T_ASSERT_EQ(
		neural_footprint_before - vm_size,
		neural_footprint_after,
		"neural footprint decreased  %llu -> %llu pages",
		neural_footprint_before / vm_kernel_page_size,
		neural_footprint_after / vm_kernel_page_size);
	T_ASSERT_EQ(
		neural_nofootprint_before + vm_size,
		neural_nofootprint_after,
		"neural nofootprint increased  %llu -> %llu pages",
		neural_nofootprint_before / vm_kernel_page_size,
		neural_nofootprint_after / vm_kernel_page_size);
	T_ASSERT_EQ(
		neural_total_before,
		neural_total_after,
		"neural total did not change  %llu -> %llu pages",
		neural_total_before / vm_kernel_page_size,
		neural_total_after / vm_kernel_page_size);

	T_LOG("---> Make primary nofootprint (compressed) volatile");
	get_ledger_before();
	make_volatile(nofootprint_vm_addr);
	get_ledger_after();
	T_ASSERT_EQ(
		neural_nofootprint_before,
		neural_nofootprint_after,
		"neural nofootprint did not change %llu -> %llu pages",
		neural_nofootprint_before / vm_kernel_page_size,
		neural_nofootprint_after / vm_kernel_page_size);
	T_ASSERT_EQ(
		neural_nofootprint_compressed_before,
		neural_nofootprint_compressed_after,
		"neural nofootprint_compressed did not change (volatile now) %llu -> %llu pages",
		neural_nofootprint_compressed_before / vm_kernel_page_size,
		neural_nofootprint_compressed_after / vm_kernel_page_size);
	T_ASSERT_EQ(
		neural_footprint_before,
		neural_footprint_after,
		"neural footprint did not change  %llu -> %llu pages",
		neural_footprint_before / vm_kernel_page_size,
		neural_footprint_after / vm_kernel_page_size);
	T_ASSERT_EQ(
		neural_total_before - vm_size,
		neural_total_after,
		"neural total decreased  %llu -> %llu pages",
		neural_total_before / vm_kernel_page_size,
		neural_total_after / vm_kernel_page_size);

	reset_max_interval(neural_total_after);

	T_LOG("---> Make primary footprint non-volatile");
	get_ledger_before();
	make_nonvolatile(footprint_vm_addr);
	get_ledger_after();
	T_ASSERT_EQ(
		neural_footprint_before + vm_size,
		neural_footprint_after,
		"neural footprint increased  %llu -> %llu pages",
		neural_footprint_before / vm_kernel_page_size,
		neural_footprint_after / vm_kernel_page_size);
	T_ASSERT_EQ(
		neural_nofootprint_before - vm_size,
		neural_nofootprint_after,
		"neural nofootprint decreased  %llu -> %llu pages",
		neural_nofootprint_before / vm_kernel_page_size,
		neural_nofootprint_after / vm_kernel_page_size);
	T_ASSERT_EQ(
		neural_total_before,
		neural_total_after,
		"neural total did not change  %llu -> %llu pages",
		neural_total_before / vm_kernel_page_size,
		neural_total_after / vm_kernel_page_size);

	T_LOG("---> Make primary nofootprint (compressed) non-volatile");
	get_ledger_before();
	make_nonvolatile(nofootprint_vm_addr);
	get_ledger_after();
	T_ASSERT_EQ(
		neural_footprint_before,
		neural_footprint_after,
		"neural footprint did not change  %llu -> %llu pages",
		neural_footprint_before / vm_kernel_page_size,
		neural_footprint_after / vm_kernel_page_size);
	T_ASSERT_EQ(
		neural_nofootprint_before,
		neural_nofootprint_after,
		"neural nofootprint did not change  %llu -> %llu pages",
		neural_nofootprint_before / vm_kernel_page_size,
		neural_nofootprint_after / vm_kernel_page_size);
	T_ASSERT_EQ(
		neural_nofootprint_compressed_before,
		neural_nofootprint_compressed_after,
		"neural nofootprint_compressed did not change (now non-volatile)  %llu -> %llu pages",
		neural_nofootprint_compressed_before / vm_kernel_page_size,
		neural_nofootprint_compressed_after / vm_kernel_page_size);
	T_ASSERT_EQ(
		neural_total_before + vm_size,
		neural_total_after,
		"neural total increased  %llu -> %llu pages",
		neural_total_before / vm_kernel_page_size,
		neural_total_after / vm_kernel_page_size);

	T_LOG("---? Check neural total max interval");
	ret = proc_pid_rusage(getpid(), RUSAGE_INFO_V6, (rusage_info_t *)&ru);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(ret, "proc_pid_rusage");
	T_ASSERT_EQ(ru.ri_interval_max_neural_footprint,
	    neural_total_after,
	    "Neural max interval footprint is equal to total: %llu = %llu",
	    ru.ri_interval_max_neural_footprint / vm_kernel_page_size,
	    neural_total_after / vm_kernel_page_size);


	T_LOG("---> Take no-footprint ownership of the file");
	get_ledger_before();
	kr = mach_memory_entry_ownership(
		file_mem_entry, /* entry port */
		mach_task_self(),  /* claim ownership */
		VM_LEDGER_TAG_NEURAL, /* ledger-tag */
		VM_LEDGER_FLAG_NO_FOOTPRINT); /* ledger flags */
	T_ASSERT_MACH_SUCCESS(kr,
	    "mach_memory_entry_ownership() file neural no-footprint 0x%x (%s)",
	    kr, mach_error_string(kr));
	get_ledger_after();
	T_ASSERT_EQ(
		neural_nofootprint_before + vm_size,
		neural_nofootprint_after,
		"neural nofootprint increased  %llu -> %llu pages",
		neural_nofootprint_before / vm_kernel_page_size,
		neural_nofootprint_after / vm_kernel_page_size);
	T_ASSERT_EQ(
		neural_total_before + vm_size,
		neural_total_after,
		"neural total increase  %llu -> %llu pages",
		neural_total_before / vm_kernel_page_size,
		neural_total_after / vm_kernel_page_size);
//	fprintf(stdout, "pausing...\n"); fflush(stdout); getchar();


	T_LOG("---> Take footprint ownership of the file");
	get_ledger_before();
	kr = mach_memory_entry_ownership(
		file_mem_entry, /* entry port */
		MACH_PORT_NULL,  /* owner remains unchanged */
		VM_LEDGER_TAG_NEURAL, /* ledger-tag */
		0); /* ledger flags */
	T_ASSERT_MACH_SUCCESS(kr,
	    "mach_memory_entry_ownership() file neural footprint 0x%x (%s)",
	    kr, mach_error_string(kr));
	get_ledger_after();
	T_ASSERT_EQ(
		neural_nofootprint_before - vm_size,
		neural_nofootprint_after,
		"neural nofootprint decreased  %llu -> %llu pages",
		neural_nofootprint_before / vm_kernel_page_size,
		neural_nofootprint_after / vm_kernel_page_size);
	T_ASSERT_EQ(
		neural_footprint_before + vm_size,
		neural_footprint_after,
		"neural footprint increased  %llu -> %llu pages",
		neural_footprint_before / vm_kernel_page_size,
		neural_footprint_after / vm_kernel_page_size);
	T_ASSERT_EQ(
		neural_total_before - vm_size,
		neural_total_after,
		"neural total decreased  %llu -> %llu pages",
		neural_total_before / vm_kernel_page_size,
		neural_total_after / vm_kernel_page_size);
//	fprintf(stdout, "pausing...\n"); fflush(stdout); getchar();

	T_LOG("---> Unlock the file");
	get_ledger_before();
	T_ASSERT_POSIX_SUCCESS(munlock(file_addr, (size_t)vm_size), NULL);
	get_ledger_after();
	T_ASSERT_EQ(
		neural_nofootprint_before,
		neural_nofootprint_after,
		"neural nofootprint unchanged  %llu -> %llu pages",
		neural_nofootprint_before / vm_kernel_page_size,
		neural_nofootprint_after / vm_kernel_page_size);
	T_ASSERT_EQ(
		neural_footprint_before - vm_size,
		neural_footprint_after,
		"neural footprint decreased  %llu -> %llu pages",
		neural_footprint_before / vm_kernel_page_size,
		neural_footprint_after / vm_kernel_page_size);
	T_ASSERT_EQ(
		neural_total_before,
		neural_total_after,
		"neural total unchanged  %llu -> %llu pages",
		neural_total_before / vm_kernel_page_size,
		neural_total_after / vm_kernel_page_size);
//	fprintf(stdout, "pausing...\n"); fflush(stdout); getchar();

	T_LOG("---> Relock the file");
	get_ledger_before();
	T_ASSERT_POSIX_SUCCESS(mlock(file_addr, (size_t)vm_size), NULL);
	get_ledger_after();
	T_ASSERT_EQ(
		neural_nofootprint_before,
		neural_nofootprint_after,
		"neural nofootprint unchanged  %llu -> %llu pages",
		neural_nofootprint_before / vm_kernel_page_size,
		neural_nofootprint_after / vm_kernel_page_size);
	T_ASSERT_EQ(
		neural_footprint_before + vm_size,
		neural_footprint_after,
		"neural footprint increased  %llu -> %llu pages",
		neural_footprint_before / vm_kernel_page_size,
		neural_footprint_after / vm_kernel_page_size);
	T_ASSERT_EQ(
		neural_total_before,
		neural_total_after,
		"neural total unchanged  %llu -> %llu pages",
		neural_total_before / vm_kernel_page_size,
		neural_total_after / vm_kernel_page_size);
//	fprintf(stdout, "pausing...\n"); fflush(stdout); getchar();
	T_ASSERT_POSIX_SUCCESS(munlock(file_addr, (size_t)vm_size), NULL);
//	fprintf(stdout, "pausing...\n"); fflush(stdout); getchar();

	T_LOG("<--- Deallocate");
	get_ledger_before();
	/* deallocating memory while holding memory entry... */
	kr = mach_vm_deallocate(mach_task_self(), footprint_vm_addr, vm_size);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_deallocate() ");
	kr = mach_vm_deallocate(mach_task_self(), nofootprint_vm_addr, vm_size);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_deallocate() ");
	kr = mach_vm_deallocate(mach_task_self(), footprint_vm_addr2, vm_size);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_deallocate() ");
	kr = mach_vm_deallocate(mach_task_self(), nofootprint_vm_addr2, vm_size);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_deallocate() ");
	/* releasing the memory entry... */
	kr = mach_port_deallocate(mach_task_self(), footprint_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_deallocate() ");
	kr = mach_port_deallocate(mach_task_self(), footprint_port2);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_deallocate() ");
	kr = mach_port_deallocate(mach_task_self(), nofootprint_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_deallocate() ");
	kr = mach_port_deallocate(mach_task_self(), nofootprint_port2);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_deallocate() ");
	get_ledger_after();

	T_ASSERT_EQ(
		0ULL,
		neural_footprint_after,
		"neural footprint zero  %llu -> %llu pages",
		neural_footprint_before / vm_kernel_page_size,
		neural_footprint_after / vm_kernel_page_size);
	T_ASSERT_EQ(
		0ULL,
		neural_footprint_compressed_after,
		"neural footprint compressed zero  %llu -> %llu pages",
		neural_footprint_compressed_before / vm_kernel_page_size,
		neural_footprint_compressed_after / vm_kernel_page_size);
	T_ASSERT_EQ(
		0ULL,
		neural_nofootprint_after,
		"neural nofootprint zero  %llu -> %llu pages",
		neural_nofootprint_before / vm_kernel_page_size,
		neural_nofootprint_after / vm_kernel_page_size);
	T_ASSERT_EQ(
		0ULL,
		neural_nofootprint_compressed_after,
		"neural nofootprint compressed to zero  %llu -> %llu pages",
		neural_nofootprint_compressed_before / vm_kernel_page_size,
		neural_nofootprint_compressed_after / vm_kernel_page_size);
	T_ASSERT_EQ(
		0ULL,
		neural_total_after,
		"neural total zero  %llu -> %llu pages",
		neural_total_before / vm_kernel_page_size,
		neural_total_after / vm_kernel_page_size);
}
