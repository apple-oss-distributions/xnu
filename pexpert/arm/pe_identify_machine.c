/*
 * Copyright (c) 2007-2021 Apple Inc. All rights reserved.
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
 */
#include <pexpert/pexpert.h>
#include <pexpert/boot.h>
#include <pexpert/protos.h>
#include <pexpert/device_tree.h>
#include <pexpert/arm64/board_config.h>

#include <machine/machine_routines.h>

#include <kern/clock.h>
#include <kern/locks.h>

/* Local declarations */
void pe_identify_machine(boot_args * bootArgs);

/* External declarations */
extern void clean_mmu_dcache(void);

static char    *gPESoCDeviceType;
static char     gPESoCDeviceTypeBuffer[SOC_DEVICE_TYPE_BUFFER_SIZE];
static vm_offset_t gPESoCBasePhys;

static uint32_t pe_arm_init_timer(void *args);


/*
 * pe_identify_machine:
 *
 * Sets up platform parameters. Returns:    nothing
 */
void
pe_identify_machine(boot_args * bootArgs)
{
	OpaqueDTEntryIterator iter;
	DTEntry         cpus, cpu;
	void const     *value;
	unsigned int    size;
	int             err;

	(void)bootArgs;

	if (pe_arm_get_soc_base_phys() == 0) {
		return;
	}

	/* Clear the gPEClockFrequencyInfo struct */
	bzero((void *)&gPEClockFrequencyInfo, sizeof(clock_frequency_info_t));

	/* Start with default values. */
	gPEClockFrequencyInfo.timebase_frequency_hz = 24000000;
	gPEClockFrequencyInfo.bus_clock_rate_hz = 100000000;
	gPEClockFrequencyInfo.cpu_clock_rate_hz = 400000000;

	err = SecureDTLookupEntry(NULL, "/cpus", &cpus);
	assert(err == kSuccess);

	err = SecureDTInitEntryIterator(cpus, &iter);
	assert(err == kSuccess);

	while (kSuccess == SecureDTIterateEntries(&iter, &cpu)) {
		if ((kSuccess != SecureDTGetProperty(cpu, "state", &value, &size)) ||
		    (strncmp((char const *)value, "running", size) != 0)) {
			continue;
		}

		/* Find the time base frequency first. */
		if (SecureDTGetProperty(cpu, "timebase-frequency", &value, &size) == kSuccess) {
			/*
			 * timebase_frequency_hz is only 32 bits, and
			 * the device tree should never provide 64
			 * bits so this if should never be taken.
			 */
			if (size == 8) {
				gPEClockFrequencyInfo.timebase_frequency_hz = *(uint64_t const *)value;
			} else {
				gPEClockFrequencyInfo.timebase_frequency_hz = *(uint32_t const *)value;
			}
		}
		gPEClockFrequencyInfo.dec_clock_rate_hz = gPEClockFrequencyInfo.timebase_frequency_hz;

		/* Find the bus frequency next. */
		if (SecureDTGetProperty(cpu, "bus-frequency", &value, &size) == kSuccess) {
			if (size == 8) {
				gPEClockFrequencyInfo.bus_frequency_hz = *(uint64_t const *)value;
			} else {
				gPEClockFrequencyInfo.bus_frequency_hz = *(uint32_t const *)value;
			}
		}
		gPEClockFrequencyInfo.bus_frequency_min_hz = gPEClockFrequencyInfo.bus_frequency_hz;
		gPEClockFrequencyInfo.bus_frequency_max_hz = gPEClockFrequencyInfo.bus_frequency_hz;

		if (gPEClockFrequencyInfo.bus_frequency_hz < 0x100000000ULL) {
			gPEClockFrequencyInfo.bus_clock_rate_hz = gPEClockFrequencyInfo.bus_frequency_hz;
		} else {
			gPEClockFrequencyInfo.bus_clock_rate_hz = 0xFFFFFFFF;
		}

		/* Find the memory frequency next. */
		if (SecureDTGetProperty(cpu, "memory-frequency", &value, &size) == kSuccess) {
			if (size == 8) {
				gPEClockFrequencyInfo.mem_frequency_hz = *(uint64_t const *)value;
			} else {
				gPEClockFrequencyInfo.mem_frequency_hz = *(uint32_t const *)value;
			}
		}
		gPEClockFrequencyInfo.mem_frequency_min_hz = gPEClockFrequencyInfo.mem_frequency_hz;
		gPEClockFrequencyInfo.mem_frequency_max_hz = gPEClockFrequencyInfo.mem_frequency_hz;

		/* Find the peripheral frequency next. */
		if (SecureDTGetProperty(cpu, "peripheral-frequency", &value, &size) == kSuccess) {
			if (size == 8) {
				gPEClockFrequencyInfo.prf_frequency_hz = *(uint64_t const *)value;
			} else {
				gPEClockFrequencyInfo.prf_frequency_hz = *(uint32_t const *)value;
			}
		}
		gPEClockFrequencyInfo.prf_frequency_min_hz = gPEClockFrequencyInfo.prf_frequency_hz;
		gPEClockFrequencyInfo.prf_frequency_max_hz = gPEClockFrequencyInfo.prf_frequency_hz;

		/* Find the fixed frequency next. */
		if (SecureDTGetProperty(cpu, "fixed-frequency", &value, &size) == kSuccess) {
			if (size == 8) {
				gPEClockFrequencyInfo.fix_frequency_hz = *(uint64_t const *)value;
			} else {
				gPEClockFrequencyInfo.fix_frequency_hz = *(uint32_t const *)value;
			}
		}
		/* Find the cpu frequency last. */
		if (SecureDTGetProperty(cpu, "clock-frequency", &value, &size) == kSuccess) {
			if (size == 8) {
				gPEClockFrequencyInfo.cpu_frequency_hz = *(uint64_t const *)value;
			} else {
				gPEClockFrequencyInfo.cpu_frequency_hz = *(uint32_t const *)value;
			}
		}
		gPEClockFrequencyInfo.cpu_frequency_min_hz = gPEClockFrequencyInfo.cpu_frequency_hz;
		gPEClockFrequencyInfo.cpu_frequency_max_hz = gPEClockFrequencyInfo.cpu_frequency_hz;

		if (gPEClockFrequencyInfo.cpu_frequency_hz < 0x100000000ULL) {
			gPEClockFrequencyInfo.cpu_clock_rate_hz = gPEClockFrequencyInfo.cpu_frequency_hz;
		} else {
			gPEClockFrequencyInfo.cpu_clock_rate_hz = 0xFFFFFFFF;
		}
	}

	/* Set the num / den pairs form the hz values. */
	gPEClockFrequencyInfo.bus_clock_rate_num = gPEClockFrequencyInfo.bus_clock_rate_hz;
	gPEClockFrequencyInfo.bus_clock_rate_den = 1;

	gPEClockFrequencyInfo.bus_to_cpu_rate_num =
	    (2 * gPEClockFrequencyInfo.cpu_clock_rate_hz) / gPEClockFrequencyInfo.bus_clock_rate_hz;
	gPEClockFrequencyInfo.bus_to_cpu_rate_den = 2;

	gPEClockFrequencyInfo.bus_to_dec_rate_num = 1;
	gPEClockFrequencyInfo.bus_to_dec_rate_den =
	    gPEClockFrequencyInfo.bus_clock_rate_hz / gPEClockFrequencyInfo.dec_clock_rate_hz;
}

vm_offset_t
pe_arm_get_soc_base_phys(void)
{
	DTEntry         entryP;
	uintptr_t const *ranges_prop;
	uint32_t        prop_size;
	char const      *tmpStr;

	if (SecureDTFindEntry("name", "arm-io", &entryP) == kSuccess) {
		if (gPESoCDeviceType == 0) {
			SecureDTGetProperty(entryP, "device_type", (void const **)&tmpStr, &prop_size);
			strlcpy(gPESoCDeviceTypeBuffer, tmpStr, SOC_DEVICE_TYPE_BUFFER_SIZE);
			gPESoCDeviceType = gPESoCDeviceTypeBuffer;

			SecureDTGetProperty(entryP, "ranges", (void const **)&ranges_prop, &prop_size);
			gPESoCBasePhys = *(ranges_prop + 1);
		}
		return gPESoCBasePhys;
	}
	return 0;
}

extern void     fleh_fiq_generic(void);

vm_offset_t     gPicBase;
vm_offset_t     gTimerBase;
vm_offset_t     gSocPhys;

static uint32_t
pe_arm_map_interrupt_controller(void)
{
	DTEntry         entryP;
	uintptr_t const *reg_prop;
	uint32_t        prop_size;
	vm_offset_t     soc_phys = 0;

	gSocPhys = pe_arm_get_soc_base_phys();

	soc_phys = gSocPhys;
	kprintf("pe_arm_map_interrupt_controller: soc_phys:  0x%lx\n", (unsigned long)soc_phys);
	if (soc_phys == 0) {
		return 0;
	}

	if (SecureDTFindEntry("interrupt-controller", "master", &entryP) == kSuccess) {
		kprintf("pe_arm_map_interrupt_controller: found interrupt-controller\n");
		SecureDTGetProperty(entryP, "reg", (void const **)&reg_prop, &prop_size);
		gPicBase = ml_io_map(soc_phys + *reg_prop, *(reg_prop + 1));
		kprintf("pe_arm_map_interrupt_controller: gPicBase: 0x%lx\n", (unsigned long)gPicBase);
	}
	if (gPicBase == 0) {
		kprintf("pe_arm_map_interrupt_controller: failed to find the interrupt-controller.\n");
		return 0;
	}

	if (SecureDTFindEntry("device_type", "timer", &entryP) == kSuccess) {
		kprintf("pe_arm_map_interrupt_controller: found timer\n");
		SecureDTGetProperty(entryP, "reg", (void const **)&reg_prop, &prop_size);
		gTimerBase = ml_io_map(soc_phys + *reg_prop, *(reg_prop + 1));
		kprintf("pe_arm_map_interrupt_controller: gTimerBase: 0x%lx\n", (unsigned long)gTimerBase);
	}
	if (gTimerBase == 0) {
		kprintf("pe_arm_map_interrupt_controller: failed to find the timer.\n");
		return 0;
	}

	return 1;
}

uint32_t
pe_arm_init_interrupts(void *args)
{
	kprintf("pe_arm_init_interrupts: args: %p\n", args);

	/* Set up mappings for interrupt controller and possibly timers (if they haven't been set up already) */
	if (args != NULL) {
		if (!pe_arm_map_interrupt_controller()) {
			return 0;
		}
	}

	return pe_arm_init_timer(args);
}

static uint32_t
pe_arm_init_timer(void *args)
{
	vm_offset_t     pic_base = 0;
	vm_offset_t     timer_base = 0;
	vm_offset_t     soc_phys;
	vm_offset_t     eoi_addr = 0;
	uint32_t        eoi_value = 0;
	struct tbd_ops  generic_funcs = {&fleh_fiq_generic, NULL, NULL};
	struct tbd_ops  empty_funcs __unused = {NULL, NULL, NULL};
	tbd_ops_t       tbd_funcs = &generic_funcs;

	/* The SoC headers expect to use pic_base, timer_base, etc... */
	pic_base = gPicBase;
	timer_base = gTimerBase;
	soc_phys = gSocPhys;

#if defined(__arm64__)
	tbd_funcs = &empty_funcs;
#else
	return 0;
#endif

	if (args != NULL) {
		ml_init_timebase(args, tbd_funcs, eoi_addr, eoi_value);
	}

	return 1;
}
