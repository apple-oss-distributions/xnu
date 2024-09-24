# Multithreaded Stackshot

Stackshot has been retrofitted to take advantage of multiple CPUs. This document
details the design of multithreaded stackshot.

## Terminology

- **Initiating / Calling CPU**: The CPU which stackshot was called from.
- **Main CPU**: The CPU which populates workqueues and collects global state.
- **Auxiliary CPU**: A CPU which is not the main CPU.
- **KCData**: The containerized data structure that stackshot outputs. See
  `osfmk/kern/kcdata.h` for more information.

## Overview

When a stackshot is taken, the initiating CPU (the CPU from which stackshot was
called) sets up state. Then, it enters the debugger trap, and IPIs the other
cores into the debugger trap as well. The other CPUs call into stackshot from
the debugger trap instead of spinning, and determine if they are eligible to
work based on perfcontrol's recommendation. (We need to do this because even if
a CPU is derecommended due to thermal limits or otherwise, it will still be
IPI'd into the debugger trap, and we want to avoid overheating the CPU).

On AMP systems, a suitable P-core is chosen to be the “main” CPU, and begins
populating queues of tasks to be put into the stackshot and collecting bits of
global state (On SMP systems, the initiating CPU is always assigned to be the
main CPU).

The other CPUs begin chipping away at the queues, and the main CPU joins
in once it is done populating them. Once all CPUs are finished, they exit the
debugger trap, interrupts are re-enabled, and the kcdata from all of the CPUs
are collated together by the caller CPU. The output is identical to
single-threaded stackshot.

It is important to note that since stackshot happens outside of the context of
the scheduler and with interrupts disabled, it does not use "actual" threads to
do its work - each CPU has its own execution context and no context switching
occurs. Nothing else runs on the system while a stackshot is happening; this
allows for stackshot to grab an atomic snapshot of the entire system's state.

## Work Queues

In order to split up work between CPUs, each task is put into a workqueue for
CPUs to pull from. On SMP systems, there is only one queue. On AMP systems,
there are two, and tasks are sorted between the queues based on their
"difficulty" (i.e. the number of threads they have). E cores will work on the
easier queue first, and P cores will work on the harder queue first. Once a CPU
finishes with its first queue, it will move on to the other.

If latency collection is enabled, each CPU will record information about its run
in a `stackshot_latency_cpu` structure in the KCData. This includes information
such as the amount of time spent waiting for the queue and the number of tasks /
threads processed by the CPU during its run.

## Buffers and Memory

Stackshot is given a fixed-size buffer upfront since it cannot allocate any
memory for itself. The size estimation logic in multithreaded stackshot is
improved from that of singlethreaded stackshot - it uses various heuristics such
as the number of tasks and threads on the system, the flags passed, sizes of
data structures, and a fudge factor to give a reasonable estimate for a buffer
size. Should the buffer be too small, stackshot will try again with a bigger
one. The number of tries is recorded in the `stackshot_latency_collection_v2`
struct if latency collection is enabled.

### Bump Allocator

Stackshot uses a basic per-cluster bump allocator to allocate space within the
buffer. Each cluster gets its own bump allocator to mitigate cache contention,
with space split evenly between each cluster. If a cluster runs out of buffer
space, it can reach into other clusters for more.

Memory that is freed is put into a per-cluster freelist. Even if the data was
originally allocated from a different cluster's buffer, it will be put into the
current cluster's freelist (again, to reduce cache effects). The freelist is a
last resort, and is only used if the current cluster's buffer space fills.

Each CPU will report information about its buffers in its
`stackshot_latency_cpu` struct. This includes the total amount of buffer space
used and the amount of buffer space allocated from other clusters. 

### Linked-List kcdata

Each CPU needs its own kcdata descriptor, but we don't know exactly how big each
one should be ahead of time. Because of this, allocate kcdata buffers in
reasonably-sized chunks as we need them. We also want the output to have each
task in order (to keep the output identical to singlethreaded stackshot), so we
maintain a linked list of these kcdata chunks for each task in the queue.

The chunks are sized such that only one is needed for the average task. If we
have any extra room at the end of the current chunk once we finish with a task,
we can add it to the freelist - but this is not ideal. So, stackshot uses
various heuristics including flags and current task / thread counts to estimate
a good chunk size. The amount of memory added to the freelist is reported by
named uint64 in the KCData (`stackshot_buf_overhead`).

```
 Workqueue

⎡ Task #1 ⎤
⎢  CPU 0  ⎥
⎣ kcdata* ⎦-->[ KCData A ]--[ KCData B ]
⎡ Task #2 ⎤
⎢  CPU 1  ⎥
⎣ kcdata* ⎦-->[ KCData C ]
⎡ Task #3 ⎤
⎢  CPU 2  ⎥
⎣ kcdata* ⎦-->[ KCData D ]--[ KCData E ]--[ KCData F ]
    ...
```

One the stackshot is finished and interrupts are reenabled, this data is woven
back together into a single KCData buffer by the initiating thread, such that it
is indistinguishable from the output of a singlethreaded stackshot (essentially,
we memcpy the contents of each kcdata chunk into a single buffer, stripping off
the headers and footers).

## “Tracing”

In debug and development builds, Stackshot takes a "trace" of itself during
execution. There are circular per-cpu buffers containing a list of tracepoints,
which consist of a timestamp, line number, and an arbitrary uintpr_t-sized piece
of extra data. This allows for basic tracing of stackshot's execution on each
CPU which can be seen from a debugger.

By default, tracepoints are only emitted when stackshot runs into an error (with
the error number as the data), but it's trivial to add more with the
`STACKSHOT_TRACE(data)` macro.

An lldb macro is in the works which will allow this data to be examined more
easily, but for now, it can be examined in lldb with `showpcpu -V
stackshot_trace_buffer`.

## Panics

During a panic stackshot, stackshot handles basically identically to how it did
before (with a single CPU/thread) - with the only difference being that we can
now take a stackshot if the system panicked during a stackshot, since state has
been compartmentalized. If the system panics during a panic stackshot, another
stackshot will not be taken.

Since stackshot takes place entirely from within the debugger trap, if an
auxilliary CPU (i.e. a CPU other than the one which initiated the stackshot)
panics, it will not be able to acquire the debugger lock since it is already
being held by the initiating CPU. To mitigate this, when a CPU panics during a
stackshot, it sets a flag in stackshot's state to indicate there was a panic by
calling into `stackshot_cpu_signal_panic`.

There are checks for this flag at various points in stackshot, and once a CPU
notices it is set, it will spin in place. Before the initiating CPU spins in
place, it will release the debugger lock. Once all CPUs are spinning, the panic
will continue.

## Future Work

- It might be more elegant to give stackshot its own IPI flavor instead of
  piggybacking on the debugger trap.
- The tracing buffer isn't easily inspected - an LLDB macro to walk the circular
  buffer and print a trace would be helpful.
- Chunk size is currently static for the entire stackshot - instead of
  estimating it once, we could estimate it for every task to further eliminate
  overhead.
