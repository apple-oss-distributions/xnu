# CPU Counters

The xnu subsystems that manage CPU performance counters.

## Overview

CPU performance counters are hardware registers that count events of interest to efficient CPU execution.
Counters that measure events closely correlated with each CPU's execution pipeline are managed by the Core Performance Monitoring Unit (CPMU).
The CPMU contains both fixed instructions and cycles counters, as well as configurable counters that can be programmed to count any of several hundred possible events.
In addition to the CPMU, the Last Level Cache (LLC) hosts the Uncore Performance Monitoring Unit (UPMU), which measures effects that aren't necessarily correlated to a single CPU.
All counters in the UPMU are configurable.

Counters are typically used in one of two ways:

1. In "counting" mode, their counts are periodically queried and tallied up for a duration of interest.
2. In "sampling" mode, the counters are programmed to generate a Performance Monitor Interrupt (PMI) periodically, during which the currently running code can be sampled, like a time profiler.

## Subsystems

There are several subsystems that provide access to CPU counter hardware:

- kpc: The Kernel Performance Counter system is the oldest subsystem and still manages the configurable CPMU counters.
It can use PMIs from these counters to trigger kperf samples and counter values can be recorded in kperf samples.

- Monotonic: The Monotonic system provides access to the fixed CPMU counters with limited support for PMIs.
Additionally, the UPMU is entirely provided by a Monotonic dev node interface.

- cpc: The CPU Performance Counter subsystem provides a policy layer on top of kpc and Monotonic to prevent malicious use of the hardware.

Eventually, cpc will subsume kpc's and Monotonic's roles in the system.

## Integrations

- The Recount subsystem makes extensive use of the fixed CPMU counters to attribute CPU resources back to threads and processes.

- Microstackshot telemetry is sampled periodically using the CPMU's cycle PMI trigger.

- Stackshot includes cycles and instructions for each thread container in its kcdata.

- The kperf profiling system can trigger samples of thread states and call stacks using CPMU PMIs, allowing it to sample thread states and call stacks.
And CPU counter values can be sampled by kperf on other triggers, like timers or kdebug events.

## See Also

- <doc:recount>
