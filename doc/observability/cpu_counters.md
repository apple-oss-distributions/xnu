# CPU Counters

How xnu manages CPU performance counters, hardware registers that count events for monitoring CPU efficiency.

This document describes the ARM hardware and interfaces available.

Counters that measure events closely correlated with each CPU's execution pipeline are managed by the Core Performance Monitoring Unit (CPMU).
The CPMU contains fixed instructions and cycles counters,
as well as configurable counters that can be programmed to count any of several hundred possible events.
In addition to the CPMU,
the Last Level Cache (LLC) hosts the Uncore Performance Monitoring Unit (UPMU),
which measures effects that aren't necessarily correlated to a single CPU.
All counters in the UPMU are configurable.

Counters are typically used in one of two ways.
In "counting" mode,
their counts are periodically queried and tallied up for a duration of interest.
In "sampling" mode,
the counters are programmed to generate a Performance Monitor Interrupt (PMI) periodically,
during which the currently running code can be sampled,
like a time profiler.

In xnu,
the CPU Performance Counter (CPC) subsystem manages the CPMU counters and enforces the security policy and ownership for the CPMU and UPMU.

## CPC Kernel Interfaces

See the header documentation in `<kern/cpc.h>` for information about how these interfaces can be called and their expected arguments.

### Configuration

To configure counters,
fill in an array of `struct cpc_event_select` structures to create a `cpc_set_t` with `cpc_set_alloc`.
This can be applied system-wide with `cpc_set_apply`.
This is currently only used by kpc for backwards compatibility.

### Counting

Convenience functions for reading the fixed counters of the current CPU's CPMU are offered because they don't require an expensive cross-call:

- `cpc_cycles` and `cpc_instructions` return the cycles elapsed and instructions retired on the current CPU,
using the CPMU.
- `cpc_cycles_instrs` returns both cycles and instructions together for correlation between the two values as "cycles-per-instruction."
- `cpc_cycles_instrs_spec` does not include a synchronization barrier,
allowing code to execute speculatively around the call.

These functions are used throughout xnu when CPU usage is required,
but predominantly in Recount.

To read the counters of the current unit on either the CPMU or UPMU, use `cpc_hw_counts`.

### Sampling

Repeatedly sampling what is executing when a counter overflows is handled by `cpc_cyclic_t`.
These can be created in one of two ways:

- `cpc_cyclic_alloc` allocates and initializes a repeating call for a well-known `cpc_slot_t`,
like instructions or cycles.
The client can then use `cpc_cyclic_activate` and `cpc_cyclic_cancel` to start and stop the periodic calls.
These are heavyweight operations since they apply to the system as a whole,
requiring a broadcast cross-call.
This is how the telemetry subsystem triggers a microstackshot using the cycle counter.

- `cpc_set_alloc` accepts a list of `struct cpc_cyclic_info` structures,
which turn into `cpc_cyclic_t`s attached to the returned `cpc_set_t`.
When the settings are applied,
each cyclic is also activated.
This is how kpc triggers kperf samples.

The interfaces are relatively basic: aside from the counter slot,
they take three values:

- A function to call.
- A `void *` context pointer for the client.
- The period of (i.e. number of events between) each function call.

If created outside of a `cpc_set_t`,
a cyclic must be activated with `cpc_cyclic_activate`,
which involves an expensive broadcast cross-call,
but only needs to be done once.

Unlike a traditional `timer_call_t`,
these interfaces are repeating and do not need to be re-armed (i.e. with `timer_call_enter`) after each firing.
Use the low-level `cpc_call_t` for a one-shot interface.

### Performance Considerations

- Recount calls `cpc_cycles_instrs_spec` on every user/kernel transition,
a very hot path in xnu.
- ~20 cycles to read a CPMU PMC.
- Currently ~5 cycles to read/write a CPMU control register.
- Broadcast cross-calls to do local MSR reads and writes when applying settings or entering cyclics,
as PIO is unavailable.

### Security Considerations

- No PIO access to CPMU or UPMU counters or control registers.
- Restrict events available to user space with an allow-list.
- Prevent PMIs that fire too quickly to prevent single-stepping interrupts-enabled kernel code.

### Low-level Interfaces

A `cpc_call_t` is the lowest-level interface to configure the counters for sampling.
It operates on hardware counters,
instead of slots,
and should only be used for implementing higher-level constructs like the repeating cyclics,
a quantum timer (local to a given thread),
or a critical section watchdog (temporarily on the same CPU).

- `cpc_call_init` initializes a `cpc_call_t` structure with a function to call and the counter to select.
- `cpc_call_enter` arms the call with a given period.
Unlike `timer_call_t`,
an invocation of the call will re-arm the call after returning from the callback.
- `cpc_call_cancel` disables the call and returns it to its initialized state.

## Other Subsystems

In addition to CPC, several other subsystems provide access to CPU counter hardware:

- kpc: The Kernel Performance Counter system provides backwards-compatible shim interfaces for user space clients of kperf.framework.
It can use PMIs from these counters to trigger kperf samples and counter values can be recorded in kperf samples.

- Monotonic: The UPMU counters are provided by a dev node interface under `/dev/monotonic/uncore`.
Eventually,
CPC will manage the UPMU counters as well,
replacing Monotonic.

- Closed Loop Performance Controller (CLPC): The per-CPU and per-cluster AON counters are managed by CLPC,
which can also use the CPMU and UPMU if necessary and no other client is active.

## Integrations

- The Recount subsystem makes extensive use of the fixed CPMU counters to attribute CPU resources back to threads and processes.

- The kperf profiling system can trigger samples of thread states and call stacks using CPMU PMIs,
allowing it to sample thread states and call stacks.
And CPU counter values can be sampled by kperf on other triggers,
like timers or kdebug events.

- Stackshot includes cycles and instructions for each thread container in its kcdata.

- Microstackshot telemetry is sampled periodically using the CPMU's cycle PMI trigger.

- Scheduler hygiene diagnostics,
which enforce an upper bound on time spent with interrupts or preemption disabled,
include CPMU cycles and instructions in the panic report.

## CPC Internals

Counter hardware,
like the CPMU,
is identified in a `cpc_hw_t` enumeration (e.g. `CPC_HW_CPMU`).
Within each hardware class,
there are multiple `cpc_unit_t` structures that store per-PMU information.
For instance,
the CPMU support uses a `cpc_unit_t` for each CPU on the system.

Each hardware counter has a corresponding `cpc_counter_t` that maintains its state,
like the current total tally of the counter and what the last read value was.
The unit's data structure holds any fixed counters,
while configurable counters are stored inside the active `cpc_set_t`.

The support for sampling the counters mimics the interfaces of `timer_call_t`,
but the internals are significantly more primitive,
as there is a hard-coded maximum of `CPC_MAX_CALLS` (currently 8) active at once.
This avoids needing a priority queue object,
since a linear scan is sufficiently quick to determine the earliest deadline.

Each counter has an array of deadlines with indices that match another array of calls.
When a PMI fires for a counter,
its deadlines are scanned for any that are prior to the current counter's sum.
Any deadlines that have expired have their calls invoked.

Cyclics protect against interrupt storms with a `struct cpc_storm_watch` structure.
This ensures that the number of interrupts within a configurable time window is not excessive.
If it does,
the cyclic is disabled.

### CPU Transitions

CPC needs to preserve the CPMU state in the face of CPUs idling or going offline,
clusters powering down,
and system sleep.
To achieve this,
there are hooks across the machine-dependent code that notify CPC about state transitions.
At each transition, CPC can take the following actions:

#### Actions

These actions are handled in the machine-independent layer of CPC.

- **Configure Full:**
All registers need to be re-synchronized.

	1. Check for any new cyclics that need their calls enqueued and enter them as deferred.
	This is required because an offline CPU will not respond to the broadcast cross-call,
	which sets up each CPU's calls.
	When the CPU comes back online,
	it needs to check the global state of cyclics on the system and enter any calls it missed.

	2. Set the previous values (or values updated for new deadlines) of PMCs in each PMC register.

	3. Set any control registers to their active state to get the counters running.

- **Configure Partial:**
Same as above _except_ skip (1).
Any cyclic activation that occurred would have taken effect on the CPU.

- **Update Counts:**
Save the values of the hardware PMCs to counters.

#### Transitions

These transitions are noticed by the machine-dependent layers of CPC,
which then transforms them to actions to call in the machine-independent layer.

- CPU is booting from a reset vector,
like power off or hibernation/suspend-to-RAM.
Needs to **Configure Full**.

- CPU is going offline.
Needs to **Save PMCs**.

- CPU is being brought back online.
Needs to **Configure Full**.

- CPU is going idle.
Needs to **Save PMCs**.

- CPU is going active after idle.
On systems with architectural state restoration,
do nothing.
Otherwise,
needs to **Configure Partial**,
because CPU idle leaves interrupts enabled.

### Diagnostics

Run `sysctl kern.cpc.state` to return a string that's the current state of the CPC subsystem.
This includes all machine-independent structures,
like the configuration of sets and cyclics,
as well as machine-specific and HW state,
like the reset and live values of registers.

### Tunables

- Maximum number of active calls.

## Defense of Design

- Init, activate, cancel, destroy design:
	- Allows allocator operations to be separated from start/stop,
	so they can happen in allocator-unsafe contexts.

- Front-end vs. backend (`cpc.h` vs. `machine_cpc.h`):
	- Avoiding obvious code duplication in generic interfaces.

### `cpc_counter_t`, `cpc_slot_t`

- Index-based vs. object-based:
	- Referencing an object makes it easier to hold them in sets.
	- Slots offer a way to reference a particular PMC across all units.

- Store configurable counters in set:
	- Need to reset the counter values to zero for each new set anyway.
	- Multiplexing will need this.

### `cpc_event_select_t`, `cpc_set_t`

- Array vs. field with index:
	- kpc uses an array with different offets based on "classes,"
	which has proven to be error-prone and confusing.
	This was probably done to simplify its sysctl interface for user space.
	- An array of just the events requested is potentially less efficient,
	but is much more flexible.

- Flags vs. selector encoding:
	- Flags are explicit and avoids overloading selectors.
	- Selectors are also used for the legacy raw PMU support in kpc.

- Built-in cyclics:
	- Periods and callbacks only make sense for a particular configuration.

- Explicitly apply to system:
	- Eventually applying sets will happen implicitly for multiplexing and during context-switch.

- CPMU-mimicking data structure:
	- Easier debugging.
	- More efficient when applying is common.
	- Reset state can be applied the same way.

### `cpc_call_t`, `cpc_cyclic_t`

- Maximum active calls:
	- Not expected to need more than a half-dozen concurrent calls on each counter.

- Slot-focused repeating cyclics vs. counter-focused one-shot calls:
	- Cyclics are not bound to a particular unit,
	whereas calls are unit-local (like `timer_call_t`).

- Targeting calls at `cpc_counter_t`:
	- Calls target counters and their management metadata is stored there.

- Array vs. priority queue:
	- Overhead of queue management dominates for low number of pending calls.

## CPC Roadmap

- Applying `cpc_set_t` to single processes.
- CPC kobject server for user space configuration.
- Replace Monotonic for UPMU configuration.
- DTrace CPC provider.
- Integration with Recount to count configurable counters for processes and threads.
- Multiplexing arrays of `cpc_event_select_t` in a single `cpc_set_t` based on cycles,
instructions,
or time.
- Support CPMU in VM guests.
- Better interface for CLPC to make use of the counters.
- Support hardware-specific features of the CPMU and UPMU:
	- CPMU: Op-code matching.
	- CPMU: Instruction address matching.
	- CPMU: Watchpoint matching.
	- CPMU: Source matching.
	- UPMU: Latency histogram thresholds.
- Boot-args to configure counters.
- Always-on configurable CPMU and UPMU counting for telemetry.
- Use synchronous data aborts for CPMU PMIs.

## See Also

- <doc:recount>
