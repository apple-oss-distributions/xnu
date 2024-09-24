/*
 * Created by Jarrad Cisco on 09/28/2022.
 * Copyright © 2022 Apple. All rights reserved.
 *
 * Functional tests for VM compressor/swap.
 */
#include <sys/sysctl.h>
#include <darwintest.h>
#include <darwintest_utils.h>
#include <TargetConditionals.h>

#include <mach/mach.h>
#include <mach/mach_host.h>    /* host_statistics */
#include <vm/vm_compressor_info.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"),
	T_META_ASROOT(NO),
	T_META_RUN_CONCURRENTLY(true));

T_DECL(swap_enabled,
    "Check that Swap is successfully enabled",
    T_META_ENABLED(TARGET_OS_OSX), T_META_TAG_VM_PREFERRED)
{
	int swap_enabled;
	size_t len = sizeof(swap_enabled);
	int rc = sysctlbyname("vm.swap_enabled", &swap_enabled, &len, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rc, "Failed to query sysctl `vm.swap_enabled`");
	T_EXPECT_EQ(swap_enabled, 1, "Check that vm.swap_enabled is set");
}


T_DECL(host_statistics_q_lens, "Check that the compressor queue lens sysctl works",
    T_META_REQUIRES_SYSCTL_EQ("kern.development", 1))
{
	struct vm_compressor_q_lens d;
	mach_msg_type_number_t vm_qlen_count = VM_COMPRESSOR_Q_LENS_COUNT;
	kern_return_t kr = host_statistics64(mach_host_self(), HOST_VM_COMPRESSOR_Q_LENS, (host_info64_t)&d, &vm_qlen_count);
	T_ASSERT_MACH_SUCCESS(kr, "host_statistics64(HOST_VM_COMPRESSOR_Q_LENS)");
	T_EXPECT_EQ(vm_qlen_count, (uint32_t)VM_COMPRESSOR_Q_LENS_COUNT, "check output is the expected length");
}

size_t read_big_sysctl(const int *mib, size_t mib_len, const char* name, char **buf);

size_t
read_big_sysctl(const int *mib, size_t mib_len, const char* name, char **buf)
{
	size_t len = 0;
	int rc = sysctl(mib, mib_len, NULL, &len, NULL, 0);
	T_ASSERT_POSIX_SUCCESS(rc, "query size of sysctl `%s`(%zu)", name, mib_len);
	T_ASSERT_GT(len, (size_t)0, "sysctl got size 0");
	len += 4096; /* allocate a bit extra in case the size changed between the two calls */
	*buf = (char*)malloc(len);
	T_ASSERT_NE_PTR((void*)*buf, NULL, "allocation for sysctl %zu", len);
	rc = sysctl(mib, mib_len, *buf, &len, NULL, 0);
	T_ASSERT_POSIX_SUCCESS(rc, "query of sysctl `%s`", name);
	return len;
}

size_t
get_sysctl_mib(const char* ctl_name, int* mib, size_t mib_sz)
{
	size_t mib_size = mib_sz;
	int rc = sysctlnametomib(ctl_name, mib, &mib_size);
	T_ASSERT_POSIX_SUCCESS(rc, "query name mib `%s` got %zu", ctl_name, mib_size);
	return mib_size;
}

T_DECL(sysctl_c_segments, "Check that the sysctl that dumps all the c_segments works correctly",
    T_META_REQUIRES_SYSCTL_EQ("kern.development", 1))
{
	int mib[CTL_MAXNAME] = {0};
	size_t mib_len = get_sysctl_mib("vm.compressor_segments", mib, CTL_MAXNAME);
	char *buf = NULL;
	size_t sz = read_big_sysctl(mib, mib_len, "vm.compressor_segments", &buf);

	size_t offset = 0;
	T_ASSERT_GE_ULONG(sz, sizeof(uint32_t), "got buffer shorter than the magic value");
	uint32_t hdr_magic = *((uint32_t*)buf);
	T_ASSERT_EQ_UINT(hdr_magic, VM_C_SEGMENT_INFO_MAGIC, "match magic value");
	offset += sizeof(uint32_t);
	while (offset < sz) {
		// read next c_segment
		T_QUIET; T_ASSERT_LE(offset + sizeof(struct c_segment_info), sz, "unexpected offset for c_segment_info");
		const struct c_segment_info* cseg = (const struct c_segment_info*)(buf + offset);
		offset += sizeof(struct c_segment_info);
		// read it's slots
		T_QUIET; T_ASSERT_LE(offset + cseg->csi_slots_len * sizeof(struct c_slot_info), sz, "unexpected offset for c_slot_info");
		offset += cseg->csi_slots_len * sizeof(struct c_slot_info);
	}
}

T_DECL(sysctl_vm_object_dump, "Check that the sysctl that dumps the metadata of a vm_object works correctly",
    T_META_REQUIRES_SYSCTL_EQ("kern.development", 1))
{
	int mib[CTL_MAXNAME] = {0};
	size_t mib_len = get_sysctl_mib("vm.task_vm_objects_slotmap", mib, CTL_MAXNAME);
	mib[mib_len++] = getpid();

	char *buf = NULL;
	size_t sz = read_big_sysctl(mib, mib_len, "vm.compressor_segments.<pid>", &buf);

	size_t offset = 0;
	T_ASSERT_GE_ULONG(sz, sizeof(uint32_t), "got buffer shorter than the magic value");
	uint32_t hdr_magic = *((uint32_t*)buf);
	T_ASSERT_EQ_UINT(hdr_magic, VM_MAP_ENTRY_INFO_MAGIC, "match magic value");
	offset += sizeof(uint32_t);

	T_ASSERT_LE(offset + sizeof(struct vm_map_info_hdr), sz, "vm_map_info_hdr size");
	struct vm_map_info_hdr* hdr = (struct vm_map_info_hdr*)(buf + offset);
	for (int i = 0; i < hdr->vmi_nentries; ++i) {
		T_QUIET; T_ASSERT_LE(offset + sizeof(struct vm_map_entry_info), sz, "vm_map_entry_info size");
		offset += sizeof(struct vm_map_entry_info);
	}
}
