/*
 * Copyright (c) 2007-2023 Apple Inc. All rights reserved.
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
 */


/* Required to know if we must compile the file. */
#include <pexpert/arm64/board_config.h>

/* Generic headers. */
#include <pexpert/pexpert.h>
#include <pexpert/device_tree.h>
#include <machine/machine_routines.h>
#include <sys/sysctl.h>
#include <kern/clock.h>

/* Dev headers. */
#if DEVELOPMENT || DEBUG
#include <kern/simple_lock.h>
#include <os/hash.h>
#endif /* DEVELOPMENT || DEBUG */

/* Trace-specific headers. */

/********
* Logs *
********/

#define PANIC_TRACE_LOG 1
#define panic_trace_error(msg, args...) { if (panic_trace_debug == 1) kprintf("panic_trace: " msg "\n", ##args); else if (panic_trace_debug == 2) printf("panic_trace: " msg "\n", ##args); }
#if PANIC_TRACE_LOG
#define panic_trace_log(msg, args...) { if (panic_trace_debug) panic_trace_error(msg, ##args); }
#else
#define panic_trace_log(msg, args...)
#endif /* PANIC_TRACE_LOG */

/************
* Externals *
************/

/*
 * Soc base physical address.
 * Set by pe_identify_machine.c:pe_arm_map_interrupt_controller during
 * early boot, null before.
 */
extern vm_offset_t gSocPhys;

/*******
* Logs *
*******/

#if DEVELOPMENT || DEBUG
#ifndef CT_DFT_LOGS_ON
#define CT_DFT_LOGS_ON 0
#endif /* CT_DFT_LOGS_ON */
#endif /* DEVELOPMENT || DEBUG */

/****************
* Default state *
****************/

#if DEVELOPMENT || DEBUG

/*
 * When supported, panic-trace is enabled by default on some platforms.
 * This section defines on which platform it is enabled..
 */

/* Opensource -> disabled. */
#define DEFAULT_PANIC_TRACE_MODE panic_trace_disabled

#endif /* DEVELOPMENT || DEBUG */

/**********
* Globals *
**********/

#if DEVELOPMENT || DEBUG
boolean_t panic_trace_disabled_for_rdar107003520 = FALSE;
#endif /* DEVELOPMENT || DEBUG */

static boolean_t debug_and_trace_initialized = false;

/************
* Boot-args *
************/

#if DEVELOPMENT || DEBUG
/*
 * Panic trace state.
 * Has a double meaning :
 * - at system init, it gives the expected tracing state.
 *   -> init code uses that to enable tracing.
 * - after system init, used to report the tracing state.
 */
TUNABLE_DT_WRITEABLE(panic_trace_t, panic_trace, "/arm-io/cpu-debug-interface",
    "panic-trace-mode", "panic_trace", DEFAULT_PANIC_TRACE_MODE, TUNABLE_DT_NONE);

/*
 * Panic trace debug state. See 'Logs' section above.
 */
TUNABLE_WRITEABLE(boolean_t, panic_trace_debug, "panic_trace_debug", CT_DFT_LOGS_ON);

#endif /* DEVELOPMENT || DEBUG */

/********
* Locks *
********/

/* Panic trace lock. */

/****************
* Debug command *
****************/

#if DEVELOPMENT || DEBUG

decl_simple_lock_data(, panic_hook_lock);

TUNABLE(unsigned int, bootarg_stop_clocks, "stop_clocks", 0);

// The command buffer contains the converted commands from the device tree for commanding cpu_halt, enable_trace, etc.
#define DEBUG_COMMAND_BUFFER_SIZE 256
typedef struct command_buffer_element {
	uintptr_t address;
	uintptr_t address_pa;
	uintptr_t value;
	union cpu_selector {
		uint16_t mask;
		struct cpu_range {
			uint8_t min_cpu;
			uint8_t max_cpu;
		} range;
	} destination_cpu_selector;
	uint16_t delay_us;
	bool cpu_selector_is_range;
	bool is_32bit;
} command_buffer_element_t;

#define CPU_SELECTOR_SHIFT              (16)
#define CPU_SELECTOR_MASK               (0xFFFF << CPU_SELECTOR_SHIFT)
#define REGISTER_OFFSET_MASK            ((1 << CPU_SELECTOR_SHIFT) - 1)
#define REGISTER_OFFSET(register_prop)  (register_prop & REGISTER_OFFSET_MASK)
#define CPU_SELECTOR(register_offset)   ((register_offset & CPU_SELECTOR_MASK) >> CPU_SELECTOR_SHIFT) // Upper 16bits holds the cpu selector
#define MAX_WINDOW_SIZE                 0xFFFF
#define DELAY_SHIFT                     (32)
#define DELAY_MASK                      (0xFFFFULL << DELAY_SHIFT)
#define DELAY_US(register_offset)       ((register_offset & DELAY_MASK) >> DELAY_SHIFT)
#define CPU_SELECTOR_ISRANGE_MASK       (1ULL << 62)
#define REGISTER_32BIT_MASK             (1ULL << 63)
#define ALL_CPUS                        0x0000
#define RESET_VIRTUAL_ADDRESS_WINDOW    0xFFFFFFFF

#define REGISTER_IS_32BIT(register_offset)      ((register_offset & REGISTER_32BIT_MASK) != 0)
#define REGISTER_SIZE(register_offset)          (REGISTER_IS_32BIT(register_offset) ? sizeof(uint32_t) : sizeof(uintptr_t))
#define CPU_SELECTOR_IS_RANGE(register_offset)  ((register_offset & CPU_SELECTOR_ISRANGE_MASK) != 0)
#define CPU_SELECTOR_MIN_CPU(register_offset)   ((CPU_SELECTOR(register_offset) & 0xff00) >> 8)
#define CPU_SELECTOR_MAX_CPU(register_offset)   (CPU_SELECTOR(register_offset) & 0x00ff)

// Record which CPU is currently running one of our debug commands, so we can trap panic reentrancy to PE_arm_debug_panic_hook.
static int running_debug_command_on_cpu_number = -1;


// Determine whether the current debug command is intended for this CPU.
static inline bool
is_running_cpu_selected(command_buffer_element_t *command)
{
	assert(running_debug_command_on_cpu_number >= 0);
	if (command->cpu_selector_is_range) {
		return running_debug_command_on_cpu_number >= command->destination_cpu_selector.range.min_cpu
		       && running_debug_command_on_cpu_number <= command->destination_cpu_selector.range.max_cpu;
	} else if (command->destination_cpu_selector.mask == ALL_CPUS) {
		return true;
	} else {
		return !!(command->destination_cpu_selector.mask & (1 << running_debug_command_on_cpu_number));
	}
}


// Pointers into debug_command_buffer for each operation. Assumes runtime will init them to zero.
static command_buffer_element_t *cpu_halt;
static command_buffer_element_t *enable_trace;
static command_buffer_element_t *enable_alt_trace;
static command_buffer_element_t *trace_halt;
static command_buffer_element_t *enable_stop_clocks;
static command_buffer_element_t *stop_clocks;

boolean_t
PE_arm_debug_and_trace_initialized(void)
{
	return debug_and_trace_initialized;
}

static void
pe_init_debug_command(DTEntry entryP, command_buffer_element_t **command_buffer, const char* entry_name)
{
	// statically allocate to prevent needing alloc at runtime
	static command_buffer_element_t debug_command_buffer[DEBUG_COMMAND_BUFFER_SIZE];
	static command_buffer_element_t *next_command_buffer_entry = debug_command_buffer;

	// record this pointer but don't assign it to *command_buffer yet, in case we panic while half-initialized
	command_buffer_element_t *command_starting_index = next_command_buffer_entry;

	uintptr_t const *reg_prop;
	uint32_t        prop_size, reg_window_size = 0;
	uintptr_t       base_address_pa = 0, debug_reg_window = 0;

	if (command_buffer == 0) {
		panic_trace_log("%s: %s: no hook to assign this command to\n", __func__, entry_name);
		return;
	}

	if (SecureDTGetProperty(entryP, entry_name, (void const **)&reg_prop, &prop_size) != kSuccess) {
		panic("%s: %s: failed to read property from device tree", __func__, entry_name);
	}

	if (prop_size % (2 * sizeof(*reg_prop))) {
		panic("%s: %s: property size %u bytes is not a multiple of %lu",
		    __func__, entry_name, prop_size, 2 * sizeof(*reg_prop));
	}

	// convert to real virt addresses and stuff commands into debug_command_buffer
	for (; prop_size; reg_prop += 2, prop_size -= 2 * sizeof(*reg_prop)) {
		if (*reg_prop == RESET_VIRTUAL_ADDRESS_WINDOW) {
			debug_reg_window = 0; // Create a new window
		} else if (debug_reg_window == 0) {
			// create a window from virtual address to the specified physical address
			base_address_pa = gSocPhys + *reg_prop;
			reg_window_size = ((uint32_t)*(reg_prop + 1));
			if (reg_window_size > MAX_WINDOW_SIZE) {
				panic("%s: %s: %#x-byte window at #%lx exceeds maximum size of %#x",
				    __func__, entry_name, reg_window_size, base_address_pa, MAX_WINDOW_SIZE );
			}
			debug_reg_window = ml_io_map(base_address_pa, reg_window_size);
			assert(debug_reg_window);
			panic_trace_log("%s: %s: %#x bytes at %#lx mapped to %#lx\n",
			    __func__, entry_name, reg_window_size, base_address_pa, debug_reg_window );
		} else {
			if ((REGISTER_OFFSET(*reg_prop) + REGISTER_SIZE(*reg_prop)) > reg_window_size) {
				panic("%s: %s[%ld]: %#lx(+%lu)-byte offset from %#lx exceeds allocated size of %#x",
				    __func__, entry_name, next_command_buffer_entry - command_starting_index,
				    REGISTER_OFFSET(*reg_prop), REGISTER_SIZE(*reg_prop), base_address_pa, reg_window_size );
			}

			if (next_command_buffer_entry - debug_command_buffer >= DEBUG_COMMAND_BUFFER_SIZE - 1) {
				// can't use the very last entry, since we need it to terminate the command
				panic("%s: %s[%ld]: out of space in command buffer",
				    __func__, entry_name, next_command_buffer_entry - command_starting_index );
			}

			next_command_buffer_entry->address    = debug_reg_window + REGISTER_OFFSET(*reg_prop);
			next_command_buffer_entry->address_pa = base_address_pa  + REGISTER_OFFSET(*reg_prop);
			next_command_buffer_entry->value      = *(reg_prop + 1);
#if defined(__arm64__)
			next_command_buffer_entry->delay_us   = DELAY_US(*reg_prop);
			next_command_buffer_entry->is_32bit   = REGISTER_IS_32BIT(*reg_prop);
#else
			next_command_buffer_entry->delay_us   = 0;
			next_command_buffer_entry->is_32bit   = false;
#endif
			if ((next_command_buffer_entry->cpu_selector_is_range = CPU_SELECTOR_IS_RANGE(*reg_prop))) {
				next_command_buffer_entry->destination_cpu_selector.range.min_cpu = (uint8_t)CPU_SELECTOR_MIN_CPU(*reg_prop);
				next_command_buffer_entry->destination_cpu_selector.range.max_cpu = (uint8_t)CPU_SELECTOR_MAX_CPU(*reg_prop);
			} else {
				next_command_buffer_entry->destination_cpu_selector.mask = (uint16_t)CPU_SELECTOR(*reg_prop);
			}
			next_command_buffer_entry++;
		}
	}

	// null terminate the address field of the command to end it
	(next_command_buffer_entry++)->address = 0;

	// save pointer into table for this command
	*command_buffer = command_starting_index;
}

static void
pe_run_debug_command(command_buffer_element_t *command_buffer)
{
	if (!PE_arm_debug_and_trace_initialized()) {
		/*
		 * In practice this can only happen if we panicked very early,
		 * when only the boot CPU is online and before it has finished
		 * initializing the debug and trace infrastructure. Avoid an
		 * unhelpful nested panic() here and instead resume execution
		 * to handle_debugger_trap(), which logs a user friendly error
		 * message before spinning forever.
		 */
		return;
	}

	// When both the CPUs panic, one will get stuck on the lock and the other CPU will be halted when the first executes the debug command
	simple_lock(&panic_hook_lock, LCK_GRP_NULL);

	running_debug_command_on_cpu_number = cpu_number();

	while (command_buffer && command_buffer->address) {
		if (is_running_cpu_selected(command_buffer)) {
			panic_trace_log("%s: cpu %d: reg write 0x%lx (VA 0x%lx):= 0x%lx",
			    __func__, running_debug_command_on_cpu_number, command_buffer->address_pa,
			    command_buffer->address, command_buffer->value);
			if (command_buffer->is_32bit) {
				*((volatile uint32_t*)(command_buffer->address)) = (uint32_t)(command_buffer->value);
			} else {
				*((volatile uintptr_t*)(command_buffer->address)) = command_buffer->value;      // register = value;
			}
			if (command_buffer->delay_us != 0) {
				uint64_t deadline;
				nanoseconds_to_absolutetime(command_buffer->delay_us * NSEC_PER_USEC, &deadline);
				deadline += ml_get_timebase();
				while (ml_get_timebase() < deadline) {
					os_compiler_barrier();
				}
			}
		}
		command_buffer++;
	}

	running_debug_command_on_cpu_number = -1;
	simple_unlock(&panic_hook_lock);
}

#endif /* DEVELOPMENT || DEBUG */

/*****************
* Partial policy *
*****************/

/* Debug-only section. */
#if DEVELOPMENT || DEBUG

/* Util. */
#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif /* MIN */

/*
 * The % of devices which will have panic_trace enabled when using a partial
 * enablement policy.
 */
static TUNABLE_DT(uint32_t, panic_trace_partial_percent,
    "/arm-io/cpu-debug-interface", "panic-trace-partial-percent",
    "panic_trace_partial_percent", 50, TUNABLE_DT_NONE);

/*
 * Stress racks opt out of panic_trace, unless overridden by the panic_trace boot-arg.
 */
static void
panic_trace_apply_stress_rack_policy(void)
{
	DTEntry ent = NULL;
	DTEntry entryP = NULL;
	const void *propP = NULL;
	unsigned int size = 0;

	if (SecureDTLookupEntry(NULL, "/chosen", &ent) == kSuccess &&
	    SecureDTGetProperty(ent, "stress-rack", &propP, &size) == kSuccess) {
		(void)entryP;
		if (PE_parse_boot_argn("panic_trace", NULL, 0)) {
			// Prefer user specified boot-arg even when running on stress racks.
		} else {
			panic_trace = 0;
		}
	}
}

/*
 * When the `panic_trace_partial_policy` flag is set, not all devices will have
 * the panic_trace settings applied. The actual % is determined by
 * `panic_trace_partial_percent`.
 * By using the ECID instead of a random number the process is made
 * deterministic for any given device.
 * This function disables panic trace if the device falls into the disabled %
 * range. It otherwise leaves the panic_trace value unmodified.
 * Called on the boot path, thus does not lock panic_trace_lock.
 */
static void
panic_trace_apply_partial_policy(void)
{
	assert3u((panic_trace & panic_trace_partial_policy), !=, 0);

	DTEntry ent = NULL;
	unsigned int size = 0;
	const void *ecid = NULL;

	/* Grab the ECID. */
	if (SecureDTLookupEntry(NULL, "/chosen", &ent) != kSuccess ||
	    SecureDTGetProperty(ent, "unique-chip-id", &ecid, &size) != kSuccess) {
		panic_trace = panic_trace_disabled;
		return;
	}

	/*
	 * Use os_hash_jenkins to convert the decidedly non-random ECID into
	 * something resembling a random number. Better (cryptographic) hash
	 * functions are not available at this point in boot.
	 */
	const uint32_t rand = os_hash_jenkins(ecid, size);

	/* Sanitize the percent value. */
	const uint32_t percent = MIN(100, panic_trace_partial_percent);

	/*
	 * Apply the ECID percent value. The bias here should be so tiny as to not
	 * matter for this purpose.
	 */
	if ((rand % 100) >= percent) {
		panic_trace = panic_trace_disabled;
	}
}

#endif /* DEVELOPMENT || DEBUG */

/***************
* External API *
***************/

#if DEVELOPMENT || DEBUG
void
PE_arm_debug_enable_trace(bool should_log)
{
	if (should_log) {
		panic_trace_log("%s enter", __FUNCTION__);
	}
	if (panic_trace & panic_trace_enabled) {
		pe_run_debug_command(enable_trace);
	} else if (panic_trace & panic_trace_alt_enabled) {
		pe_run_debug_command(enable_alt_trace);
	}
	if (should_log) {
		panic_trace_log("%s exit", __FUNCTION__);
	}
}
#endif /* DEVELOPMENT || DEBUG */

#if DEVELOPMENT || DEBUG
static void
PE_arm_panic_hook(const char *str __unused)
{
	(void)str; // not used
#if defined(__arm64__) && !APPLEVIRTUALPLATFORM
	/*
	 * For Fastsim support--inform the simulator that it can dump a
	 * panic trace now (so we don't capture all the panic handling).
	 * This constant is randomly chosen by agreement between xnu and
	 * Fastsim.
	 */
	__asm__ volatile ("hint #0x4f");
#endif /* defined(__arm64__) && !APPLEVIRTUALPLATFORM */
	if (bootarg_stop_clocks) {
		pe_run_debug_command(stop_clocks);
	}
	// disable panic trace to snapshot its ringbuffer
	// note: Not taking panic_trace_lock to avoid delaying cpu halt.
	//       This is known to be racy.
	if (panic_trace) {
		if (running_debug_command_on_cpu_number == cpu_number()) {
			// This is going to end badly if we don't trap, since we'd be panic-ing during our own code
			kprintf("## Panic Trace code caused the panic ##\n");
			return;  // allow the normal panic operation to occur.
		}

		// Stop tracing to freeze the buffer and return to normal panic processing.
		pe_run_debug_command(trace_halt);
	}
}
#endif /* DEVELOPMENT || DEBUG */


#if DEVELOPMENT || DEBUG
void (*PE_arm_debug_panic_hook)(const char *str) = PE_arm_panic_hook;
#else
void(*const PE_arm_debug_panic_hook)(const char *str) = NULL;
#endif  // DEVELOPMENT || DEBUG

void
PE_init_cpu(void)
{
#if DEVELOPMENT || DEBUG
	if (bootarg_stop_clocks) {
		pe_run_debug_command(enable_stop_clocks);
	}
#endif  // DEVELOPMENT || DEBUG

	pe_init_fiq();
}


void
PE_singlestep_hook(void)
{
}

void
PE_panic_hook(const char *str __unused)
{
	if (PE_arm_debug_panic_hook != NULL) {
		PE_arm_debug_panic_hook(str);
	}
}

/*
 * Initialize the trace infrastructure.
 */
void
pe_arm_init_debug(void *args)
{
	DTEntry         entryP;
	uintptr_t const *reg_prop;
	uint32_t        prop_size;

	/*
	 * When args != NULL, this means we're being called from arm_init() on the
	 * boot CPU; this controls one-time init of the panic trace infrastructure.
	 * During one-time init, panic_trace_lock does not need to be held.
	 */
	const bool is_boot_cpu = (args != NULL);

	if (gSocPhys == 0) {
		kprintf("pe_arm_init_debug: failed to initialize gSocPhys == 0\n");
		return;
	}

#if DEVELOPMENT || DEBUG
	if (is_boot_cpu) {
		if (panic_trace != 0) {
			panic_trace_apply_stress_rack_policy();
		}

		if ((panic_trace & panic_trace_partial_policy) != 0) {
			panic_trace_apply_partial_policy();
		}
	}
#endif /* DEVELOPMENT || DEBUG */

	if (SecureDTFindEntry("device_type", "cpu-debug-interface", &entryP) == kSuccess) {
		if (is_boot_cpu) {
			if (SecureDTGetProperty(entryP, "reg", (void const **)&reg_prop, &prop_size) == kSuccess) {
				ml_init_arm_debug_interface(args, ml_io_map(gSocPhys + *reg_prop, *(reg_prop + 1)));
			}
#if DEVELOPMENT || DEBUG
			simple_lock_init(&panic_hook_lock, 0); //assuming single threaded mode

			if (panic_trace) {
				kprintf("pe_arm_init_debug: panic_trace=%d\n", panic_trace);

				// Prepare debug command buffers.
				pe_init_debug_command(entryP, &cpu_halt, "cpu_halt");
				pe_init_debug_command(entryP, &enable_trace, "enable_trace");
				pe_init_debug_command(entryP, &enable_alt_trace, "enable_alt_trace");
				pe_init_debug_command(entryP, &trace_halt, "trace_halt");

				// start tracing now
				PE_arm_debug_enable_trace(true);
			}
			if (bootarg_stop_clocks) {
				pe_init_debug_command(entryP, &enable_stop_clocks, "enable_stop_clocks");
				pe_init_debug_command(entryP, &stop_clocks, "stop_clocks");
			}
#endif
		}
	} else {
#if DEVELOPMENT || DEBUG
		const uint32_t dependent_modes = (panic_trace_enabled | panic_trace_alt_enabled);
		if (is_boot_cpu && (bootarg_stop_clocks || (panic_trace & dependent_modes))) {
			panic("failed to find cpu-debug-interface node in the EDT! "
			    "(required by `panic_trace={0x01, 0x10}` or `stop_clocks=1`)");
		} else
#endif
		{
			kprintf("pe_arm_init_debug: failed to find cpu-debug-interface\n");
		}
	}


	debug_and_trace_initialized = true;
}

/*********************
* Panic-trace sysctl *
*********************/

