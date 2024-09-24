# Memorystatus Subsystem

Dealing with memory pressure by forcibly recovering pages.

## Overview
<a name="overview"></a>

The xnu memorystatus subsystem is responsible for recovering the system when we're running dangerously low
certain resources. Currently it monitors the following resources:

- memory
- vnodes
- compressor space
- swap space
- zone map VA

Depending on the resource, there are a variety of actions that memorystatus might take.
One of the most common actions is to kill 1 or more processes in an attempt to recover the system.
In addition to monitoring system level resources, the memorystatus code is also responsible
for killing processes that go over their per-process memory limits.

The memorystatus contains code to perform four actions in response to resource shortages:
- Kill Processes
- Freeze Processes
- Send warning notifications
- Swap memory from apps

Each of these actions are  covered in their own document in this folder.

## Code Layout
<a name="code-layout"></a>

The memorystatus code lives on the BSD side of xnu. It's comprised of the following C files:

- `bsd/kern/kern_memorystatus_policy.c`
  Contains the policy decisions around when to perform which action.
- `bsd/kern/kern_memorystatus_freeze.c`
  Implementation of the freezer. See `doc/memorystatus/freezer.md` for details.
- `bsd/kern/kern_memorystatus.c`
  Contains mechanical code to implement the kill and swap actions. Should not contain any policy
  (that should be in `bsd/kern/kern_memorystatus_policy.c`), but that's a recent refactor so
  is a bit of a WIP.
- `bsd/kern/kern_memorystatus_notify.c`
  Contains both the policy and mechanical bits to send out memory pressure notifications. See `doc/memorystatus/notify.md`

And the following headers:
- `bsd/kern/kern_memorystatus_internal.h`
- `bsd/sys/kern_memorystatus_notify.h`
- `bsd/sys/kern_memorystatus_freeze.h`
- `bsd/sys/kern_memorystatus.h`

## Design
<a name="design"></a>

The memorystatus subsystem is designed around a central health check.
All of the fields in this health check are defined in the `memorystatus_system_health_t` struct. See `bsd/kern/kern_memorystatus_internal.h` for the struct definition. 

Most of the monitoring and actions taken by the memorystatus subsystem happen in the `memorystatus_thread` (`bsd/kern/kern_memorystatus.c`). However, there are some synchronous actions that happen on other threads. See `doc/memorystatus/kill.md` for more documentation on specific kill types.

Whenever it's woken up the memorystatus thread does the following:
1. Fill in the system health state by calling `memorystatus_health_check`)
1. Log this state to the os log (or serial if we're early in boot)
1. Check if the system is healthy via `memorystatus_is_system_healthy`
1. If the system is unhealthy, pick a recovery action and perform it. See `memorystatus_pick_action` (in `bsd/kern/kern_memorystatus_policy.c`) for the conditions that trigger specific actions. Note that we sometimes do pre-emptive actions on a healthy system if we're somewhat low on a specific resource. For example, we'll kill procs over their soft limit if we're under 15% available pages even if the system is otherwise healthy.
1. Go back to step 1 until the system is healthy and the thread can block.

Notice that the memorystatus thread does not explicitly check why it was woken up.
To keep the synchronization simple, anytime a resource shortage is detected the memorystatus
thread is woken up *blindly* and it will do a full system health check.

### Jetsam Bands

The memorystatus subsystem has 210 priority levels. Every process in the system (except launchd) has a jetsam priority level. Higher numbers are more important.

Each priority level is tracked as a TAILQ linked list . There is one global array, `memstat_bucket`, containing all of these TAILQ lists.
A process's priority is tracked in the proc structure (See `bsd/sys/proc_internal.h`). `p_memstat_effective_priority` stores the proc's current jetsam priority, and `p_memstat_list` stores the TAILQ linkage. All lists are protected by the `proc_list_mlock` (Yes this is bad for scalability. Ideally we'd use finer grain locking or at least not share the global lock with the scheduler. See [rdar://36390487](rdar://36390487)) .

Many kill types kill in ascending jetsam priority level. See `doc/memorystatus/kill.md` for more details.
The jetsam band is either asserted by [RunningBoard](https://stashweb.sd.apple.com/projects/COREOS/repos/runningboard/browse) (apps and runningboard managed daemons) or determined by the jetsam priority set in the [JetsamProperties](https://stashweb.sd.apple.com/projects/COREOS/repos/jetsamproperties/browse) database.

For reference, here are some of the band numbers:
| Band Number | Name | Description |
| ----------- | ---- | ----------- |
| 0 | `JETSAM_PRIORITY_IDLE` | Idle processes |
| 30 | `JETSAM_PRIORITY_BACKGROUND` | Docked apps on iOS. Some active daemons on other platforms. |
| 40 | `JETSAM_PRIORITY_MAIL` | Docked apps on watchOS. Some active daemons on other platforms. |
| 75 | `JETSAM_PRIORITY_FREEZER` | Suspended & frozen processes |
| 100 | `JETSAM_PRIORITY_FOREGROUND` | Foreground app processes |
| 140 | - | mediaserverd |
| 160 | `JETSAM_PRIORITY_HOME` | SpringBoard |
| 180 | `JETSAM_PRIORITY_IMPORTANT` | RunningBoard, watchdogd, thermalmonitord, etc.. |
| 190 | `JETSAM_PRIORITY_CRITICAL` | CommCenter |

See the full jetsam band reference on [confluence](https://confluence.sd.apple.com/display/allOSSystemsInternals/Jetsam#Jetsam-JetsamPriorities).

### Daemon lifecycle

The memorystatus subsystem is heavily intertwined with daemon lifecycle. A full discussion of daemon lifecycle is outside the scope of this document. If you're curious, here are some good resources:
- [Daemon Overview](https://confluence.sd.apple.com/display/allOSSystemsInternals/Daemons#)
- [RunningBoard's Process Management Documentation](https://confluence.sd.apple.com/display/allOSSystemsInternals/Process+Management+Paradigms)
- [PressuredExit (A.K.A. activity tracking)](https://confluence.sd.apple.com/display/allOSSystemsInternals/Pressured+Exit) 

From the perspective of memorystatus there are essentially two kinds of processes: managed and unmanaged. Managed processes have their lifecycle managed by RunningBoard and have the `P_MEMSTAT_MANAGED` bit set on the `p_memstat_state` field. RunningBoard moves these processes between different jetsam bands based on their open assertions. 

Unmanaged processes go into their active jetsam band when they take out transactions.

Daemons have different memory limits when they're inactive (in band 0) vs. active (above band 0). The inactive memory limit, active memory limit, and active jetsam band are determined via [JetsamProperties](https://stashweb.sd.apple.com/projects/COREOS/repos/jetsamproperties/browse). [Launchd](https://stashweb.sd.apple.com/projects/COREOS/repos/libxpc/browse) reads the JetsamProperties database and passes these values down to the kernel via posix_spawn(2) attributes. memorystatus stashes these values on the proc structure (`p_memstat_memlimit_active`, `p_memstat_memlimit_inactive`, `p_memstat_requestedpriority`), and applies them as daemons move between states.

### Memory Monitoring

Memorystatus makes most memory decisions based on the `memorystatus_available_pages` metric. This metric reflects the number of pages that memorystatus thinks could quickly be made free. This metric is defined in the `VM_CHECK_MEMORYSTATUS` macro in `osfmk/vm/vm_page.h`.

Currently on non-macOS systems, it's defined as `pageable_external + free + secluded_over_target + purgeable`. Breaking that down:
- `pageable_external`: file backed page count
- `free`: free page count
- `secluded_over_target`: `(vm_page_secluded_count - vm_page_secluded_target)`. This target comes from the device tree `kern.secluded_mem_mb`. Secluded memory is a special pool of memory that's intended for the camera so that it can startup faster on memory constrained systems.
- `purgeable`: The number of purgeable volatile pages in the system. Purgeable memory is an API for clients to specify that the VM can treat the contents of a range of pages as volatile and quickly free the backing pages under pressure. See `osfmk/mach/vm_purgable.h` for the API. Note that the API was accidentally exported with incorrect spelling ("purgable" instead of "purgeable")

Since we purge purgeable memory and trim the secluded pool quickly under memory pressure, this can generally be approximated to `free + file_backed` for a system under pressure.

The `VM_CHECK_MEMORYSTATUS` macro is called whenever a page is allocated, wired, freed, etc... Basically `memorystatus_available_pages` is supposed to always be accurate down to a page level. On our larger memory systems (8 and 16GB iPads in particular) this might be overkill.
And it calls into `memorystatus_pages_update` to actually update `memorystatus_available_pages` and issue the blind wakeup of the memorystatus thread if necessary. `memorystatus_pages_update` is also responsible for waking the freezer and memory pressure notification threads.

The following configurable (EDT) thresholds determine which actions to take when `memorystatus_available_pages` is low. Each action is taken until `memorystatus_available_pages` rises back above the threshold.

- `kern.memstat_pressure_mb`: only processes which have violated their "soft/HWM" memory limits may be killed (see `JETSAM_REASON_MEMORY_HIGHWATER`).\*
- `kern.memstat_idle_mb`: only processes whose priority is `JETSAM_PRIORITY_IDLE` may be killed (see `JETSAM_REASON_MEMORY_IDLE_EXIT`)
- `kern.memstat_critical_mb`: any process may be killed in ascending jetsam priority order (see `JETSAM_REASON_MEMORY_VMPAGESHORTAGE`)

\*Note that the memorystatus pressure threshold does *not* determine the "system memory pressure level" (used to send pressure notifications and trigger sustained-pressure jetsams), which is monitored via a different subsystem.

## Threads
<a name="threads"></a>

This section lists the threads that comprise the memorystatus subsystem. More details on each thread are below.

| Thread name | Main function | wake event |
| ----------- | ------------- | ---------- |
| VM\_memorystatus\_1 | `memorystatus_thread` | `jt_wakeup_cond` in `jetsam_thread_state_t` |
| VM\_freezer | `memorystatus_freeze_thread` | `memorystatus_freeze_wakeup` |
| VM\_pressure | `vm_pressure_thread` | `vm_pressure_thread` |

### VM\_memorystatus\_1

This is the jetsam thread. It's responsible for running the system health check and performing most jetsam kills (see `doc/memorystatus/kill.md` for a kill breakdown).

It's woken up via a call to `memorystatus_thread_wake` whenever any subsystem determines we're running low on a monitored resource. The wakeup is blind and the thread will immediately do a health check to determine what's wrong with the system.

NB: There are technically three memorystatus threads: `VM_memorystatus_1`, `VM_memorystatus_2`, and `VM_memorystatus_3`. But we currently only use `VM_memorystatus_1`. At one point we tried to parallelize jetsam to speed it up, but this effort was unsuccessful. The other threads are just dead code at this point.

### VM\_freezer

This is the freezer thread. It's responsible for freezing processes under memory pressure and demoting processes when the freezer is full. See `doc/memorystatus/freeze.md` for more details on the freezer.

It's woken up by issuing a `thread_wakeup` call to the `memorystatus_freeze_wakeup` global. This is done in `memorystatus_pages_update` if `memorystatus_freeze_thread_should_run` returns true. It's also done whenever `memorystatus_on_inactivity` runs.

Upon wakeup the freezer thread will call `memorystatus_pick_freeze_count_for_wakeup` and attempt
to freeze up to that many processes before blocking. `memorystatus_pick_freeze_count_for_wakeup` returns 1 on most platforms. But if app swap is enabled (M1 and later iPad Pros) it will return the total number of procs in all eligible bands.

### VM\_pressure

This is the memorystatus notification thread. It's woken up by the pageout thread via `vm_pressure_response`. `vm_pressure_response` is also called in `memorystatus_pages_update`.

When awoken it calls `consider_vm_pressure_events` which winds its way to `memorystatus_update_vm_pressure`. This routine checks if the pressure level has changed and issues memory pressure notifications. It also schedules the thread call for sustained pressure kills.

On macOS this thread also does idle exit kills.

## Snapshots
<a name="snapshots"></a>
The memorystatus subsystem provides a snapshot mechanism so that
ReportCrash can generate JetsamEvent.ips files. These files contain
a snapshot of the system at the time that memorystatus performed
some kills. The snapshot data structure is `memorystatus_jetsam_snapshot_t` defined in `bsd/sys/kern_memorystatus.h`. Generally speaking the snapshot contains system level memory statistics along with entries for each process in the system. Since we do not want to wake up ReportCrash while the system is low on memory, we maintain one global snapshot (`memorystatus_jetsam_snapshot` in `bsd/kern/kern_memorystatus.c`) while we're performing kills and only wake up ReportCrash once the system is healthy again. See `memorystatus_post_snapshot` in `bsd/kern/kern_memorystatus.c` which is called right before the jetsam thread blocks.

**NB**: Posting the snapshot just means sending a notification to userspace that the snapshot is ready. Userspace (currently OSAnalytics) must make the `memorystatus_control` syscall with the `MEMORYSTATUS_CMD_GET_JETSAM_SNAPSHOT` subcommand to retrieve the snapshot. See `memorystatus_cmd_get_jetsam_snapshot` in `bsd/kern/kern_memorystatus.c` for details. Since we only have one global snapshot its cleared on read and thus can only have 1 consumer in userspace.

### Freezer Snapshot
The freezer snapshot, `memorystatus_jetsam_snapshot_freezer`, is a second global jetsam snapshot object. It reuses the snapshot struct definition but only contains apps that have been jetsammed.
dasd reads this snapshot and uses it as an input for its freezer recommendation algorithm. However, we're not currently using the dasd recommendation algorithm for the freezer so this snapshot really only serves a diagnostic purpose today.
This snapshot is also reset when dasd reads it. Note that it has to be separate from the OSAnalytics snapshot so that these daemons can read the snapshots independently. 

## Dumping Caches
<a name="dumping-caches"></a>

In general system caches should be cleared before we do higher band jetsams. Userspace entities should do this via purgeable memory if possible, or memory pressure notifications if not. In the kernel, memorystatus calls `memorystatus_approaching_fg_band` when we're about to do a fg band kill. This in turn calls `memorystatus_dump_caches` to clear the PPLs cache and purge all task corpses. This also sends out a notification to other entities to clear their caches (see `memorystatus_issue_fg_band_notify`). To avoid unnecessary corpse forking and purging, memorystatus blocks all additional corpse creation after it purges them until the system returns to a healthy state.
