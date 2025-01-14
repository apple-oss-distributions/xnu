# Memorystatus Kills

The different types of memorystatus kills, when they're necessary, and how they're done.

## Kill Types

<a name="kill-types"></a>

The following table lists all of the kill reasons, their corresponding `memorystatus_action_t`, the kill context (does the kill happen on the memorystatus thread, synchronously from another thread, etc...), and if the kill targets 1 pid or kills up the jetsam bands until the system is recovered.

More information on each kill type is provided below

| Reason                                             | memorystatus\_action\_t                                                  | context               | Marches up jetsam bands? |
| -------------------------------------------------- | ------------------------------------------------------------------------ | --------------------- | ------------------------ |
| `JETSAM_REASON_MEMORY_HIGHWATER`                   | `MEMORYSTATUS_KILL_HIWATER`                                              | `memorystatus_thread` | Yes                      |
| `JETSAM_REASON_VNODE`                              | N/A                                                                      | synchronously on thread that tries to allocate a vnode | Yes |
| `JETSAM_REASON_MEMORY_VMPAGESHORTAGE`              | `MEMORYSTATUS_KILL_TOP_PROCESS`                                          | `memorystatus_thread` | Yes                      |
| `JETSAM_REASON_MEMORY_PROCTHRASHING`               | `MEMORYSTATUS_KILL_AGGRESSIVE`                                           | `memorystatus_thread` | Yes                      |
| `JETSAM_REASON_MEMORY_FCTHRASHING`                 | `MEMORYSTATUS_KILL_TOP_PROCESS`                                          | `memorystatus_thread` | No                       |
| `JETSAM_REASON_MEMORY_PERPROCESSLIMIT`             | N/A                                                                      | thread that went over the process' memory limit | No |
| `JETSAM_REASON_MEMORY_DISK_SPACE_SHORTAGE`         | N/A                                                                      | thread that disabled the freezer | Yes |
| `JETSAM_REASON_MEMORY_IDLE_EXIT`                   | N/A                                                                      | `vm_pressure_thread`  | No                       |
| `JETSAM_REASON_ZONE_MAP_EXHAUSTION`                | `MEMORYSTATUS_KILL_TOP_PROCESS`                                          | `memorystatus_thread` or thread in a zalloc | No |
| `JETSAM_REASON_MEMORY_VMCOMPRESSOR_THRASHING`      | `MEMORYSTATUS_KILL_TOP_PROCESS`                                          | `memorystatus_thread` | No                       |
| `JETSAM_REASON_MEMORY_VMCOMPRESSOR_SPACE_SHORTAGE` | `MEMORYSTATUS_KILL_TOP_PROCESS`                                          | `memorystatus_thread` or thread in swapin | No |
| `JETSAM_REASON_LOWSWAP`                            | `MEMORYSTATUS_KILL_SUSPENDED_SWAPPABLE` or `MEMORYSTATUS_KILL_SWAPPABLE` | `memorystatus_thread` | Yes                      |
| `JETSAM_REASON_MEMORY_SUSTAINED_PRESSURE`          | N/A                                                                      | `vm_pressure_thread`  | No                       |

### JETSAM\_REASON\_MEMORY\_HIGHWATER

These are soft limit kills. When the number of available pages is below `memorystatus_available_pages_pressure`, the `memorystatus_thread` will perform these kills. Any process over its soft memory limit is eligible. Processes are killed in ascending jetsam priority order.

### JETSAM\_REASON\_VNODE

When the system hits the vnode limit, and the VFS subsystem is not able to recycle any vnodes, we kill processes in ascending jetsam priority order to free up vnodes. These kills happen synchronously on the thread that is trying to acquire a vnode.

### JETSAM\_REASON\_MEMORY\_VMPAGESHORTAGE

The number of available pages is below `memorystatus_available_pages_critical`. The `memorystatus_thread` will kill processes in ascending priority order until available pages is above `memorystatus_available_pages_critical`. 

### JETSAM\_REASON\_MEMORY\_PROCTHRASHING

This is also known as aggressive jetsam. If we determine that the idle band contains exclusively false idle daemons, and there are at least 5 daemons in the idle band, we will trigger proc thrashing jetsams. These can kill up to and above the foreground band in an attempt to relieve the false idle problem.

False idle daemons are daemons in the idle band that relaunch very quickly after they're killed. This generally indicates a programming error in the daemon (they're doing work without holding a transaction). Because the daemons re-launch very quickly we can get stuck in jetsam loops where the daemons are re-launching while we're killing other false idle daemons and this monopolizes two cores. Proc thrashing jetsams are a last ditch attempt to fix this by hopefully killing whatever higher band process is talking with the idle daemon.

False idleness is determined based on the relaunch likelihood provided by launchd. launchd tracks the duration between jetsam kill and relaunch for daemons. It passes the last 10 durations to posix_spawn(2) via `posix_spawnattr_set_jetsam_ttr_np`. This function sorts the durations into the following buckets:

1. 0 - 5 seconds
1. 5 - 10 seconds
1. \> 10 seconds

If the majority of durations are in bucket 1 the daemon is marked with `POSIX_SPAWN_JETSAM_RELAUNCH_BEHAVIOR_HIGH`, if the majority of durations are in bucket 2 the daemon is marked with `POSIX_SPAWN_JETSAM_RELAUNCH_BEHAVIOR_MEDIUM`, and if the majority of durations are in bucket the daemon is marked with `POSIX_SPAWN_JETSAM_RELAUNCH_BEHAVIOR_LOW`. Daemons with `POSIX_SPAWN_JETSAM_RELAUNCH_BEHAVIOR_HIGH` are considered false idle by the aggressive jetsam algorithm.

The relaunch likelihood also impacts the amount of time that the daemon gets in the aging band. This is currently band 10 for daemons. Daemons with high relaunch likelihood get 10 seconds in the aging band, medium relaunch likelihood grants 5 seconds, and low relaunch likelihood daemons only get 2 seconds. See `memorystatus_sysprocs_idle_time` in `bsd/kern/kern_memorystatus.c`.

### JETSAM\_REASON\_MEMORY\_FCTHRASHING

The system is causing too much pressure file backed memory. Specifically the phantom cache has detected pressure (based on the rate that we're paging out and reading back in the same data) or the number of old segments (older than 48 hours) in the compressor pool is above our limit and the compressor isn't out of space or thrashing.

In this case the `memorystatus_thread` kills the process with the lowest jetsam priority and resets the phantom cache samples.

### JETSAM\_REASON\_MEMORY\_PERPROCESSLIMIT

The process has gone over its hard limit. The process is immediately killed. This kill happens on the thread that tried to allocate a new page. Specifically every page insertion into a process's pmap increases the `phys_footprint` of the process in its ledger. Memorystatus sets a limit on the `phys_footprint` ledger field based on the value from [JetsamProperties](https://stashweb.sd.apple.com/projects/coreos/repos/jetsamproperties/browse), which was passed in via launchd, and registers a callback when the limit is exceeded.

Note that memorystatus also registers the `phys_footprint` limit when it's a soft limit. In that case the callback does a simulated crash instead of a per process limit kill. This provides crash reports for daemons that go over their soft limit on systems where there's not enough pressure to cause highwatermark kills.

### JETSAM\_REASON\_MEMORY\_DISK\_SPACE\_SHORTAGE

This only happens on platforms with `CONFIG_FREEZE`. Currently this is just iOS. When the system is very low on storage, [CacheDelete](https://stashweb.sd.apple.com/projects/COREOS/repos/cachedelete/browse]), via [CacheDeleteServices](https://stashweb.sd.apple.com/projects/COREOS/repos/cachedeleteservices/browse), sets the `vm.freeze_enabled` sysctl. The thread that performs this sysctl then kills every frozen process so that we can fully reclaim all of the swap files.
Since frozen processes can be in any band <= foreground, we scan the bands for procs with the `P_MEMSTAT_FROZEN` bit set.

See `kill_all_frozen_processes` in `bsd/kern/kern_memorystatus_freeze.c` for the implementation.

### JETSAM\_REASON\_MEMORY\_IDLE\_EXIT

These are idle kills.

On macOS, when the memory pressure level escalates above normal, the memorystatus notification thread calls `memorystatus_idle_exit_from_VM` to kill 1 idle daemon. Note that daemons must opt in to pressured exit on macOS.

### JETSAM\_REASON\_ZONE\_MAP\_EXHAUSTION

Zalloc has run out of VA. If the zone allocator is able to find a good candidate process to kill, it performs a synchronous kill. If not, it asks the `memorystatus_thread` to pick and kill a process. Memorystatus will kill the process with the lowest jetsam priority.

### JETSAM\_REASON\_MEMORY\_VMCOMPRESSOR\_THRASHING

The compressor has detected that we've exceeded a specific number of compressions and decompressions in the last 10 m.s. The `memorystatus_thread` will kill the process with the lowest jetsam priority and reset the compressor thrashing statistics.

NB: These thresholds are very old and have probably not scaled well with current hardware. According to telemetry these kills are very rare.

### JETSAM\_REASON\_MEMORY\_VMCOMPRESSOR\_SPACE\_SHORTAGE

The compressor is at or near either the segment or compressed pages limit. See `vm_compressor_low_on_space` in `osfmk/vm/vm_compressor.c`. The `memorystatus_thread` will kill in ascending jetsam priority order until the space shortage is relieved.

If the compressor hits one of these limits while swapping in a segment, it will perform these kills synchronously on the thread doing the swapin. This can happen on app swap or freezer enabled systems.

### JETSAM\_REASON\_LOWSWAP

We're on an app swap enabled system (currently M1 or later iPads) and we're unable to allocate more swap files (either because we've run out of disk space or we've hit the static swapfile limit).
Memorystatus will kill swap eligible processes (ones in app coalitions) in ascending jetsam priority order. If we're approaching but not yet at the swapfile limit we will limit the kills to suspended apps.

### JETSAM\_REASON\_MEMORY\_SUSTAINED\_PRESSURE

System has been at the kVMPressureWarning level for >= 10 minutes without escalating to critical.
The memorystatus notification thread schedules a thread call to perform these kills. We will only kill idle processes and will pause for 500 m.s. between each kill. If we kill the entire idle band twice and the pressure is not relieved we give up because the pressure is coming from above the idle band.

Many system services (especially dasd) check the pressure level before doing work, so it's not good for the system to be at the warning level indefinitely. 

## Picking an action
<a name="picking-an-action"></a>

`memorystatus_pick_action` in `bsd/kern/kern_memorystatus_policy.c` is responsible for picking an action that the memorystatus thread will perform to recover the system. It does this based on the system health.

The logic is roughly as follows:

If the system is unhealthy, see `memorystatus_is_system_healthy` in `bsd/kern/kern_memorystatus_policy.c`, or the number of available pages is below `memorystatus_available_pages_pressure`, perform high watermark kills.
Once we have no more high watermark kills, check if we should do aggressive jetsam. If not, we do `MEMORYSTATUS_KILL_TOP_PROCESS` and pick the specific kill cause based on the reason that the system is unhealthy.

App swap enabled systems add in `MEMORYSTATUS_KILL_SWAPPABLE` and `MEMORYSTATUS_KILL_SWAPPABLE_SUSPENDED` actions. These happen when the system is under pressure or unhealthy and we see that we're low on swap. We will only kill running swappable processes if we're out of swap space.
