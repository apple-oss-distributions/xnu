# Memorystatus Notifications

This document details the notifications published by the memorystatus subsystem to userspace.

## Dispatch Sources

Handlers can be registered for pressure and limit notifications via the
creation of a dispatch source of type `DISPATCH_SOURCE_TYPE_MEMORYPRESSURE`.
See `dispatch_source_create(3)`.

UIKit further exposes handlers for App
developers. See
[Responding to Low Memory Warnings](https://developer.apple.com/documentation/xcode/responding-to-low-memory-warnings).

## Memory Limits

Processes may subscribe to notifications regarding memory limits.

| Type     | Knote Flags                             | Dispatch Source Mask                          | Description                                                                         |
| -------- | --------------------------------------- | --------------------------------------------- | ----------------------------------------------------------------------------------- |
| WARN     | `NOTE_MEMORYSTATUS_PROC_LIMIT_WARN`     | `DISPATCH_MEMORYPRESSURE_PROC_LIMIT_WARN`     | Process is within 100 MB of its memory limit.                                       |
| CRITICAL | `NOTE_MEMORYSTATUS_PROC_LIMIT_CRITICAL` | `DISPATCH_MEMORYPRESSURE_PROC_LIMIT_CRITICAL` | Process has violated memory limit. Only sent if the memory limit is non-fatal/soft. |

## Memory Pressure

The kernel tracks its current "pressure level" via
`memorystatus_vm_pressure_level`. There are 5 distinct levels of pressure:

| Level      | Value | Knote Flags                           | Dispatch Source Mask               | Description                                                                              |
| ---------- | ----- | ------------------------------------- | ---------------------------------- | ---------------------------------------------------------------------------------------- |
| `Normal`   | 0     | `NOTE_MEMORYSTATUS_PRESSURE_NORMAL`   | `DISPATCH_MEMORYPRESSURE_NORMAL`   | Device is operating normally. No action is required.                                     |
| `Warning`  | 1     | `NOTE_MEMORYSTATUS_PRESSURE_WARN`     | `DISPATCH_MEMORYPRESSURE_WARN`     | Device is beginning to experience memory pressure. Consider relaxing caching policy.     |
| `Urgent`   | 2     | N/A                                   | N/A                                | Synonymous with `Warning`.                                                               |
| `Critical` | 3     | `NOTE_MEMORYSTATUS_PRESSURE_CRITICAL` | `DISPATCH_MEMORYPRESSURE_CRITICAL` | Device is in a critical memory state. Expect latencies and consider dropping all caches. |
| `Jetsam`\* | 4     | `NOTE_MEMORYSTATUS_JETSAM_FG_BAND`    | `N/A`                              | Jetsam is approaching the FOREGROUND band.                                               |

\*`Jetsam` is only subscribable by kernel threads.

### Available Memory

The VM monitors the amount of "available memory" , which comprises the following:

```
AVAILABLE_NON_COMPRESSED_MEMORY = (active + inactive + free + speculative)
AVAILABLE_MEMORY = (AVAILABLE_NON_COMPRESSED_MEMORY + compressed)
```

In other words, `AVAILABLE_NON_COMPRESSED_MEMORY` tracks all of the memory on
the system that is either free or reclaimable (everything that is not either
wired, compressed, or stolen). `AVAILABLE_MEMORY` tracks all memory that
is reclaimable, free, or being used to store compressed anonymous memory (i.e.
not wired or stolen). Compressed anonymous memory may be further "reclaimed"
via swapping or compaction, and thus is considered "available".

### Pressure Thresholds

Pressure states are triggered when `AVAILABLE_NON_COMPRESSED_MEMORY` dips
below the following thresholds:

| Level       | Rising Threshold                                     | Falling Threshold                                    | 
| ----------- | ---------------------------------------------------- | ---------------------------------------------------- |
| `Warning`   | `VM_PAGE_COMPRESSOR_COMPACT_THRESHOLD`               | `1.2 * VM_PAGE_COMPRESSOR_COMPACT_THRESHOLD`         |
| `Critical`  | `1.2 * VM_PAGE_COMPRESSOR_SWAP_UNTHROTTLE_THRESHOLD` | `1.4 * VM_PAGE_COMPRESSOR_SWAP_UNTHROTTLE_THRESHOLD` |

These thresholds are described by:

| Threshold                                      | Embedded Value            | macOS Value               | Description                                               |
| ---------------------------------------------- | ------------------------- | ------------------------- | --------------------------------------------------------- |
| `VM_PAGE_COMPRESSOR_COMPACT_THRESHOLD`         | `0.5 * AVAILABLE_MEMORY`  | `0.5 * AVAILABLE_MEMORY`  | Initiate minor-compaction of compressed segments.         |
| `VM_PAGE_COMPRESSOR_SWAP_THRESHOLD`            | `0.3 * AVAILABLE_MEMORY`  | `0.4 * AVAILABLE_MEMORY`  | Begin major-compaction & swapping of compressed segments. |
| `VM_PAGE_COMPRESSOR_SWAP_UNTHROTTLE_THRESHOLD` | `0.25 * AVAILABLE_MEMORY` | `0.29 * AVAILABLE_MEMORY` | Un-throttle the swapper thread.                           |

###  Kernel Monitoring

Kernel/kext threads may monitor the system pressure level via
`mach_vm_pressure_level_monitor()` which allows the current pressure level to
be queried or the calling thread to block until the pressure level changes.

### Differences from Jetsam

The jetsam control loop monitors a different measure of "available" memory
(`memorystatus_available_pages`, see [memorystatus.md](memorystatus.md)).
This available page count is the subset of `AVAILABLE_NON_COMPRESSED_MEMORY`
that is fully-reclaimable -- (file-backed + free + secluded-over-target +
purgeable). Jetsam monitors the ratio of these fully-reclaimable pages to
_all_ pages (max_mem), rather than only "available" pages as monitored for
pressure.

The design goals of jetsam and vm_pressure can be thought of in the following
way. 

Jetsam attempts to maintain a sufficiently large pool of
fully-reclaimable memory to satisfy transient spikes in page demand. This pool
need not be overly large; thus jetsam thresholds are generally on the order of
5%/10%/15% of max_mem.

Conversely, vm_pressure attempts to maintain the amount of memory available to
the working set of processes. On a healthy system, this should be at least a
majority of the memory not otherwise wired down or stolen by the operating
system. If overall memory demand is such that, even with compression, the
working set no longer fits in available memory, then the system begins making
room by notifying processes, dropping caches, defragmenting the compressor pool,
and swapping to disk.

## Low Swap Notifications (macOS only)

When the compressor has exhausted its available space (VA or compressed-pages
limit), it will notify registered process via `NOTE_MEMORYSTATUS_LOW_SWAP` /
`DISPATCH_MEMORYPRESSURE_LOW_SWAP`. This notification is restricted to the
root user.

## MallocStackLogging

MallocStackLogging (MSL) can enabled/disabled via the same memorystatus knote.
The mask is `NOTE_MEMORYSTATUS_MSL_STATUS`/`DISPATCH_MEMORYPRESSURE_MSL_STATUS`.
libdispatch registers a source with this type for all processes with a handler
that calls into libmalloc to enable/disable MSL.
