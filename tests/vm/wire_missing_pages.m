#include <_stdlib.h>
#include <_types/_uint32_t.h>
#include <_types/_uint8_t.h>
#include <mach/arm/boolean.h>
#include <mach/arm/kern_return.h>
#include <mach/arm/vm_param.h>
#include <mach/arm/vm_types.h>
#include <mach/mach.h>
#include <mach/mach_init.h>
#include <mach/mach_types.h>
#include <mach/mach_vm.h>
#include <mach/memory_entry.h>
#include <mach/memory_object_types.h>
#include <mach/vm_attributes.h>
#include <mach/vm_inherit.h>
#include <mach/vm_map.h>
#include <mach/vm_page_size.h>
#include <mach/vm_prot.h>
#include <mach/vm_purgable.h>
#include <mach/vm_statistics.h>
#include <mach/vm_sync.h>
#include <sys/mman.h>
#include <stdio.h>
#include <darwintest.h>
#include <TargetConditionals.h>
#include <os/thread_self_restrict.h>


#include <CoreFoundation/CoreFoundation.h>
#include <Foundation/Foundation.h>
#include <IOKit/IOCFSerialize.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/IOTypes.h>
#include <IOSurface/IOSurface.h>
#include <IOSurface/IOSurfacePrivate.h>
#include <machine/cpu_capabilities.h>

T_GLOBAL_META(T_META_RUN_CONCURRENTLY(true),
    T_META_NAMESPACE("xnu.vm"),
    T_META_RADAR_COMPONENT_NAME("xnu"),
    T_META_RADAR_COMPONENT_VERSION("vm"),
    T_META_TAG_VM_PREFERRED,
    T_META_ASROOT(true));
/*
 * This test is based of a fuzzer finding but minimized, as such some of the
 * arguments are arbitrary.
 */

static void *
vm_file_mapping(int fd, size_t size)
{
	void* file_mapping = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_FILE | MAP_PRIVATE, fd, 0);
	if (file_mapping == MAP_FAILED) {
		T_FAIL("vm_file_mapping: failed to map file region\n");
		return 0;
	}
	T_LOG("vm_file_mapping: mapped file region at %p size %lx\n", file_mapping, size);
	return file_mapping;
}


/*
 * Use a pwrite s.t. we create an error page in the vm_object.
 * That should cause the mlock to fail later.
 */
static unsigned long long vm_pwrite(int fd, size_t size, unsigned long long offset)
{
	offset = offset % (size - 0x10);
	char data[0x10] = "0xdeadbeef";
	return pwrite(fd, (void*)data, 0x10, offset);
}

static void * vm_map_physcont(size_t size)
{
	CFMutableDictionaryRef properties = CFDictionaryCreateMutable(0, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFStringRef str = CFStringCreateWithCString(kCFAllocatorDefault, "PurpleGfxMem", 0x8000100);
	CFDictionarySetValue(properties, kIOSurfaceMemoryRegion, str);
	CFRelease(str);

	uint64_t cache_mode = 0x100;
	CFNumberRef num = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongLongType, &cache_mode);
	CFDictionarySetValue(properties, kIOSurfaceCacheMode, num);
	CFRelease(num);

	vm_size_t alloc_size = size;
	num = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongLongType, &alloc_size);
	CFDictionarySetValue(properties, kIOSurfaceAllocSize, num);
	CFRelease(num);

	IOSurfaceRef surface = IOSurfaceCreate(properties);
	CFRelease(properties);
	if (!surface) {
		T_SKIP("vm_map_physcont: failed to map phys cont memory");
		return 0;
	}

	vm_address_t base_addr = (vm_address_t)IOSurfaceGetBaseAddress(surface);
	if (!base_addr || (void*)base_addr == MAP_FAILED) {
		T_SKIP("vm_map_physcont: failed to map phys cont memory");
		return 0;
	}

	alloc_size = IOSurfaceGetAllocSize(surface);
	T_QUIET; T_LOG("vm_map_physcont: allocated phy cont memory at %lx, size %lx\n", base_addr, alloc_size);

	T_ASSERT_EQ(alloc_size, size, "Size alloced is correct");

	return (void *) base_addr;
}



T_DECL(wire_file_mem, "Wire absent memory")
{
	size_t file_size = 0x5c000;
	size_t offset = 0x47269;
	FILE* f = tmpfile();
	T_QUIET; T_ASSERT_NOTNULL(f, "Failed to get tmpfile");

	int fd = fileno(f);
	void * mapping = vm_file_mapping(fd, file_size);
	vm_pwrite(fd, file_size, offset);

	int ret = mlock(mapping, file_size);
	T_ASSERT_EQ(ret, -1, "mlock failed");
	T_PASS("Mlocking file region with absent page doesn't panic");
}

T_DECL(wire_phys_memory, "Wire physically contiguous memory")
{
	void * phys = vm_map_physcont(0xf4000);
	int ret = mlock(phys, 0xf4000);
	T_ASSERT_EQ(ret, 0, "mlock worked");

	ret = mlock(phys, 0xf4000);
	T_ASSERT_EQ(ret, 0, "2nd mlock worked");

	ret = munlock(phys, 0xf4000);
	T_ASSERT_EQ(ret, 0, "munlock worked");

	ret = munlock(phys, 0xf4000);
	T_ASSERT_EQ(ret, 0, "2nd munlock worked");

	ret = munlock(phys, 0xf4000);
	T_ASSERT_EQ(ret, 0, "over-munlock failed");

	T_PASS("Mlocking physically contiguous memory works!");
}