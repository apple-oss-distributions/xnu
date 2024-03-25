# Recount

CPU resource accounting interfaces and implementation.

## Overview

Recount is a resource accounting subsystem in the kernel that tracks the CPU resources consumed by threads, tasks, coalitions, and processors.
It supports attributing counts to a specific level of the CPU topology (per-CPU and per-CPU kind).
ARM64 devices with a fast timebase read and Intel devices can track time spent in the kernel (system) separately from user space.
64-bit, non-virtualized (e.g. _not_ running under a hypervisor) devices also accumulate instructions and cycles at each context switch.
These two metrics are abbreviated to cycles-per-instruction, or CPI, for brevity.
ARM64 devices can also track task and thread energy in nanojoules,
but only at the granularity of thread context switch,
not between user and system.


By default, Recount tracks its counters per-CPU kind (e.g. performance or efficiency) for threads, per-CPU for tasks, and per-CPU kind for coalitions.

## High-Level Interfaces

These interfaces report counter data to user space and are backed by Recount.

| Interface                   | Entity      | Target        | Tests | Time | CPI | Energy | Perf Levels | Secure |
| --------------------------: | ----------- | ------------- | :---: | :--: | :-: | :----: | :---------: | :----: |
|                 `getrusage` | task        | self/children |  FP   |  ✓¹  |     |        |             |        |
|           `prod_pid_rusage` | task        | pid           |  FP   |  ✓   |  ✓  |   ✓    |     ✓²      |   ✓²   |
|          `PROC_PIDTASKINFO` | task        | pid           |  FP   |  ✓   |  ✓  |        |     ✓²      |        |
|           `TASK_BASIC_INFO` | task        | task port     |  FP   |  ✓¹  |     |        |             |        |
|    `TASK_ABSOLUTETIME_INFO` | task        | task port     |  FP   |  ✓   |     |        |             |        |
|           `TASK_POWER_INFO` | task        | task port     |  FP   |  ✓   |     |        |             |        |
| `TASK_INSPECT_BASIC_COUNTS` | task        | task inspect  |   P   |      |  ✓  |        |             |        |
|         `THREAD_BASIC_INFO` | thread      | thread port   |   P   |  ✓   |     |        |             |        |
|      `THREAD_EXTENDED_INFO` | thread      | thread port   |       |  ✓   |     |        |             |        |
|           `proc_threadinfo` | thread      | thread ID     |       |  ✓   |     |        |             |        |
|         `proc_threadcounts` | thread      | thread ID     |   F   |  ✓   |  ✓  |   ✓    |      ✓      |        |
|         `thread_selfcounts` | thread      | self          |  FP   |  ✓   |  ✓  |   ✓    |      ✓      |        |
|          `thread_selfusage` | thread      | self          |  FP   |  ✓   |     |        |             |        |
|            `coalition_info` | coalition   | coalition ID  |   F   |  ✓   |  ✓  |   ✓    |     ✓²      |        |
|        `HOST_CPU_LOAD_INFO` | system      | all           |       |  ✓   |     |        |             |        |
|   `PROCESSOR_CPU_LOAD_INFO` | processor   | port          |       |  ✓   |     |        |             |        |
|                 `stackshot` | task/thread | all           |   P   |  ✓   |  ✓  |        |     ✓²      |        |
|                      DTrace | thread      | any           |       |  ✓   |  ✓  |        |             |        |
|                       kperf | task/thread | any           |       |  ✓   |  ✓  |        |     ✓²      |        |

- Under Tests, "F" is functional and "P" is performance.
- ¹ Time precision is microseconds.
- ² These return overall totals and hard-code a separate, P-core-only value.

## LLDB

The `recount` macro inspects counters in an LLDB session and is generally useful for retrospective analysis of CPU usage.
Its subcommands print each metric as a column and then uses rows for the groupings, like per-CPU or per-CPU kind values.
Tables also include formulaic columns that can be derived from two metrics, like CPI or power.
By default, it prints the times in seconds, but the `-M` flag switches the output to Mach time values.

- `recount thread <thread-ptr> [...]` prints a table of per-CPU kind counts for threads.

- `recount task <task-ptr> [...]` prints a table of per-CPU counts for tasks.
	- `-T` prints the task's active thread counters in additional tables.
	- `-F <name>` finds the task matching the provided name instead of using a task pointer.

- `recount coalition <coalition-ptr>` prints a table of per-CPU kind counts for each coalition, not including the currently-active tasks.
Coalition pointers can be found with the `showtaskcoalitions` macro, and should be _resource_ coalitions.

- `recount processor <processor-ptr-or-cpu-id>` prints a table of counts for a processor.
	- `-T` prints the processor's active thread counters in an additional table.
	- `-A` includes all processors in the output.

- `recount diagnose` prints information useful for debugging the Recount subsystem itself.

- `recount triage` is meant to be used by the automated panic debug scripts.

## Internals

Accounting for groups of entities like threads and tasks starts with a `recount_plan_t`, declared using `RECOUNT_PLAN_DECLARE` and defined with `RECOUNT_PLAN_DEFINE`, which takes the topology, or granularity, of the counting.
The plan topology defines how many `recount_usage` structures are needed.
To count CPU resource usage, a `struct recount_usage` has the following fields:

- `ru_metrics[RCT_LVL_COUNT]`: metrics accumulated in each exception level
- `ru_energy_nj`: the energy consumed by a CPU, in nano-Joules with `CONFIG_PERVASIVE_ENERGY`

The metrics are stored in a `recount_metrics` structure with the following fields:

- `ru_time_mach`: the time spent, in Mach time units
- `ru_cycles`: the cycles run by a CPU with `CONFIG_PERVASIVE_CPI`
- `ru_instructions`: the instructions retired by a CPU with `CONFIG_PERVASIVE_CPI`

At context switch, `recount_switch_thread` captures the hardware counters with `recount_snapshot` into a `struct recount_snap`.
The CPU's previous snapshot, stored in the `_snaps_percpu` per-CPU variable, is subtracted from the new one to get a delta to add to the currently-executing entity's usage structure.
The per-CPU variable is then updated with the current snapshot for the next switch.
The user/kernel transition code calls `recount_leave_user` or `recount_enter_user`, which performs the same operation, except with `recount_snapshot_speculative`.
It relies on other synchronization barriers in the transition code to provide keep the snapshot precise.
During preemption, the context switch handler attributes metrics back to the level stored in each thread.
On the boundaries of secure execution handoff, `recount_enter_secure` and `recount_leave_secure` update the current thread's level and attribute metrics back to the previous level.

Processors also track their idle time separately from the usage structure with paired calls to `recount_processor_idle` and `recount_processor_run`.
Idle time has no user component and doesn't consume instructions or cycles, so a full usage structure isn't necessary.
It stores the last update time in a 64-bit value combined with a state stored in the top two bits to determine whether the processor is currently idle or active.

A `struct recount_track` is the primary data structure found in threads, tasks, and processors.
Tracks include a `recount_usage` structure but ensures that each is updated atomically with respect to readers.

### Track Atomicity

To ensure the accuracy of formulas involving multiple metrics, like CPI, all metrics must be updated atomically from the perspective of the reader.
A traditional locking mechanism would prevent the writer from updating the counts while readers are present, so Recount uses a sequence lock instead.
Writers make a generation count odd before updating any of the values and then set it back to even when all values are updated.
Readers wait until the generation count becomes even before trying to read the values, and if the counter changes by the time they're done reading them, it retries the read.
Since three entities need to be updated at once (thread, task, and processor), only the last update has a release barrier to publish the writes.
When reporting just user and system time, taking the sequence lock as a reader introduced unacceptable overhead.
The sequence lock doesn't need to be taken for these metrics since they're never updated simultaneously.

The coalition counters are not updated by threads switching off-CPU and are instead protected by the coalition lock while a task exits and rolls up its counters to the coalition.
Reading the counters requires holding the lock and iterating the constituent tasks, grouping their per-CPU counters into per-CPU kind ones.

### Energy

The energy counters on ARM systems count a custom unit of energy that needs to be scaled to nanojoules.
Because this unit can be very small and may overflow a 64-bit counter, it's scaled to nanojoules during context-switch.

Unlike the other metrics, the energy counters are not sampled directly by Recount so the values cannot be tracked at user/kernel/secure granularity.

## See Also

- <doc:cpu_counters>
