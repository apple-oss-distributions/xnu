# Freezer

Details of how some processes can be swapped out to disk.

## Overview
<a name="overview"></a>

The freezer is a limited form of swap on embedded. Under memory pressure, the freezer picks apps to freeze. For those apps, it compresses and swaps out all of their dirty memory. It then moves them to jetsam band 75 so that they're protected from jetsam.

## Freezing
<a name="freezing"></a>

The freezer thread is responsible for freezing processes. See `memorystatus_freeze_thread_should_run` in `bsd/kern/kern_memorystatus_policy.c` for details on specifically when the freezer thread runs. Generally speaking, we want the freezer to run when the device is under some memory pressure but before we start jetsamming things (so we can save apps from jetsam).

Every time the freezer thread wakes up it will try to freeze up to `memorystatus_pick_freeze_count_for_wakeup()` processes. This is generally 1 process except for app swap enabled devices (M1 and later iPads) which freeze more aggressively.

`memorystatus_freeze_top_process` is responsible for finding and freezing a candidate process. Only suspended apps are eligible. See [app selection](#app-selection) below for details on how a specific app is chosen. Note that applications may contain multiple processes. These processes should all be in the same coalition and will generally get frozen together. See [coalitions](#coalitions) below for details.

Once a process has been selected for freezing, we call `task_freeze` (`osfmk/kern/task.c`) which calls `vm_map_freeze` (`osfmk/vm/vm_map.c`). `vm_map_freeze` walks through the map twice. The first walk is an evaluation pass to determine if the map meets our criteria for freezing. This is basically just looking at the number of dirty shared vs. anonymous pages. See [shared objects](#shared-objects) below for details. If the map meets our criteria, `vm_map_freeze` does a second pass to compress all of the dirty pages. The pages are all compressed into a new set of freezer segments hanging off the `freezer_ctx_chead`. If any already compressed pages are encountered (which is fairly typical), the compressed content is moved into these new freezer segments. The goal is to create a single virtually contiguous range of memory in the compressor for this app, so that we can write it out to storage. Note that these compressions and memcpys happen on the freezer thread and not one of the compressor threads.

Once we have finished creating this contiguous compressor VA range, we put those segments on the swapout queue and wake up the swapout thread. At this point we move the process to the freezer jetsam band (75). The swapout thread is responsible for issuing the I/Os to write those segments out to disk, so the freezer thread can move on to either block or freeze more processes.

### Shared objects
<a name="shared-objects"></a>

The freezer has two limits on "shared memory". `memorystatus_frozen_shared_mb_max` is a global limit on the amount of shared memory that can be in the freezer. `memorystatus_freeze_shared_mb_per_process_max` is the maximum amount of shared memory that can be in a single process. `memorystatus_freeze_private_shared_pages_ratio` is the min ratio of private to shared pages that a process needs to be freezer eligible.

The definition of shared memory here is a bit funky. We look at the `refcnt` for the VM object and call it shared if it's greater than 1. We don't want to count memory that's simply mapped into the same process in multiple places though, so we do a quick forward scan in the map and subtract any other instances o f the object from the refcnt. This is not an exhaustive search of the map so it's possible to count an object as shared even if it's only mapped into a single process.

We assume that shared memory will be accessed by a non frozen process while the frozen process is suspended, and thus impose these limits. However, this is a flawed assumption. Shared memory is either:

1. shared with another process in the same coalition
1. shared with a daemon

For 1, all processes in the coalition should generally get suspended and frozen together. See [coalitions](#coalitions) below and [Safari](#safari) in particular for an exception.
For 2, daemons should not touch memory that is shared with a suspended app while that app is suspended.

So in theory we can get rid of these limits. However, when we tried to remove them we discovered they were masking an interesting bug: wired memory. IOSurface takes out multiple references on the backing VM objects. As a result this memory gets counted as shared and we don't freeze apps that have a lot of wired memory. Of course, apps should not hold onto wired memory when they're suspended. So when we find that a suspended process has a lot of wired memory we should avoid freezing it and report a memory exception ([rdar://65856884](rdar://65856884)). Then we can remove these shared memory heuristics: [rdar://65954405](rdar://65954405).

### App Selection
<a name="app-selection"></a>

Currently, we freeze processes in the idle band in LRU order (apps that have been idle the longest get frozen first). This is very naive. In the past, we've tried predicting which apps will be used in the future and freezing those. However, these algorithms did not outperform LRU in a user A/B test, so they're not currently in use. See [rdar://83112455](rdar://83112455) for details. I suspect this is do the [app dock](#dock).

### Coalitions
<a name="coalitions"></a>

Many apps contain multiple processes which are grouped together in a coalition. Therefore, freezing an app may mean freezing more than 1 process. Every app coalition has a leader which is the main app process. We always freeze the leader process first (we skip coalition members that are not the leader). Once we freeze a coalition leader, we check for any xpc services in that coalition & freeze them one at a time. We do not freeze other types of coalition members.

Some XPC services opt out of freezing by setting `DisableFreezing` to true in the [RunningBoard](https://stashweb.sd.apple.com/projects/COREOS/repos/runningboard/browse)  dictionary section of their info plist.
RunningBoard implements this flag via the `MEMORYSTATUS_CMD_SET_PROCESS_IS_FREEZABLE` subcommand of `memorystatus_control`. This call sets the `P_MEMSTAT_FREEZE_DISABLED` bit on the `p_memstat_state` proc field. This is important for stateless XPC services like `MTLCompilerService`.

### Safari
<a name="safari"></a>

Safari is an interesting case for the freezer. It's also extremely important. Telemetry shows that Safari uses the majority of our freezer write budget daily. Interestingly, it also uses the plurality of swap writes on macOS (although depending on the release Chrome is sometimes above Safari on mac).

The MobileSafari process itself is fairly small. Each tab is a separate WebContent process in the Safari coalition. The WebContent processes are XPC services. [WebKit](https://codesearch.apple.com/result/WebKit-7614.1.20.1/%2Fpvc%2Fsources%2FWebKit-7614.1.20.1%2F_0%2FSource%2FWebKit%2FWebProcess%2Fcocoa%2FWebProcessCocoa.mm?query=MEMORYSTATUS_CMD_SET_PROCESS_IS_FREEZABLE&train=Sydney&resultsFilters=projects%3DWebKit&resultType=results#line-978) is responsible for telling us which tabs to freeze, and it does so through the same `MEMORYSTATUS_CMD_SET_PROCESS_IS_FREEZABLE` SPI as RunningBoard. We will freeze up to 10 coalition members (See `MAX_XPC_SERVICE_PIDS`), so that means up to 10 tabs.

### Thaws

When a frozen process is resumed we call it a thaw. Functionally, this is identical to a regular app resume.  **We do not proactively load any of the dirty memory out of the swap file**. It's read back on demand via the page fault handler just like macOS / iPad swap.

Note that a thawed process, somewhat confusingly, is still considered frozen. This is because it may still have data on NAND. For example, consider a suspended & frozen app with 100MB of dirty memory on NAND. On resume it may only touch 20MB and thus the other 80MB stays on NAND. As a result, when the app is put back in the background it goes to band 75 instead of band 0. Aside from process termination the only way out of the freezer is [demotion](#demotion).

### Refreeze

Once a thawed app goes back into the background, we may re-freeze it. The exact heuristics for re-freeze are determined by the freezer thread. See `memorystatus_freeze_pick_process` in `bsd/kern/kern_memorystatus_policy.c` for the implementation. In general, we try to freeze new processes before doing re-freezes. Once the freezer is full or we have no more candidate processes we will do a re-freeze.

Note that `vm_map_freeze` does **not** read data back in from NAND. It will copy compressed memory from existing in-memory segments to the new freezer segments, but it will skip over data that is already on NAND. See this check in `vm_compressor_relocate` (`osfmk/vm/vm_compressor.c`) for the implementation:

```c
if (C_SEG_IS_ON_DISK_OR_SOQ(c_seg_src) ||
    c_seg_src->c_state == C_IS_FILLING) {
```

## Demotion
<a name="demotion"></a>

Since thawing an app does not remove the frozen bit, processes generally remain in the freezer until they exit. But we have a limited number of slots in the freezer (and a swap file limit), so we don't have to keep processes around forever. Thus, once per day, we demote frozen process. Currently we demote up to 2 processes daily (4 on swap enabled iPads). See `memorystatus_demote_frozen_processes_using_thaw_count` in `bsd/kern/kern_memorystatus_freeze.c` for details on how a frozen process is picked.Only processes that have been thawed fewer than `kern.memorystatus_thaw_count_demotion_threshold` times are eligible.

When a process is demoted, it is **not** killed. It's simply put back into the idle band under the assumption that jetsam will kill it soon. Its dirty memory remains on NAND. It is no longer eligible for re-freeze at this point, but if it is resumed before it is killed it may be chosen again for the freezer.

## Budget
<a name="budget"></a>

NAND writes are a limited resource. The drive can only sustain so many writes before it will start to fail. Therefore, the freezer has a daily write budget. This budget is determined by the storage team. Every 24 hours, the freezer starts a new interval (see `memorystatus_freeze_start_normal_throttle_interval` in `bsd/kern/kern_memorystatus_freeze.c`). This interval tracks the number of writes and ensures we stay under the budget. It also tracks daily telemetry which is reported back via [CoreAnalytics](https://coreanalytics.apple.com).

We get the budget from the storage layer via an IOCTL to the swap device. See `vm_swap_vol_get_budget` in `bsd/vm/vm_compressor_backing_file.c` for details. Note that we call this every day, but currently it does not change throughout the lifetime of the drive.

Unused budget **does** roll over between interval.

## Dock
<a name="dock"></a>

On iOS, Duet maintains an [application dock](https://stashweb.sd.apple.com/projects/COREOS/repos/duet/browse/DuetActivitySchedulerDaemon/DuetActivitySchedulerDaemon/DASDock/_DASDock.m). This dock contains applications which the user is likely to keep using and they are placed in band 30 when idle. Importantly, docked apps are not eligible for the freezer since they're not in the idle band. This was done under the assumption that Duet would choose between putting apps in the freezer or the dock. But in practice these mechanisms have not been unified. This policy should be re-visited before determining if we can go back to using Duet's recommendations. In general, the best freezer candidates are likely in the app dock.

## Tunables
<a name="tunables"></a>

This table lists all of the freezer tunables. All tunables are set via [Trial](https://trial.apple.com). See `doc/trial.md` for information on xnu's trial integration.
On the trial website, the freezer namespace has two versions. "V1" is for iOS, and "V2" is for watchOS.
For local testing, all of these tunables can be set via sysctl(8)

| Name | Description |
| ---- | ----------- |
| kern.memorystatus\_freeze\_pages\_min | The min. number of resident pages that a process needs to be freezer eligible. |
| kern.memorystatus\_freeze\_processes\_max | The max. number of processes that can be frozen. Note that we can go a bit above this limit due to coalition freezing. |
| kern.memorystatus\_freeze\_jetsam\_band | The jetsam band for frozen processes |
| kern.memorystatus\_freeze\_private\_shared\_pages\_ratio | The min. ratio of private to shared pages needed for a process to be freezer eligible. |
| kern.memorystatus\_freeze\_min\_processes | The min. number of suspended processes needed to run the freeer |
| kern.memorystatus\_max\_freeze\_demotions\_daily | The maximum number of demotions that the freezer will do in one day |
| kern.memorystatus\_freeze\_budget\_multiplier | A percentage multiplier applied to the daily NAND budget. 0 -> no budget, 100 -> regular budget, 200 -> double budget, etc... |
| kern.memorystatus\_freezer\_use\_ordered\_list | Should we use the ordered app list? See [app selection](#app-selection) for details |
| kern.memorystatus\_freezer\_use\_demotion\_list | Should we use the ordered demotion list? |
| kern.memorystatus\_thaw\_count\_demotion\_threshold | The min. number of thaws needed for a frozen process to avoid demotion |
| kern.memorystatus\_freeze\_max\_candidate\_band | The maximum jetsam band that a freezer eligible process can be in |
| kern.memorystatus\_min\_thaw\_refreeze\_threshold | The min number of thawed procs that can trigger a re-freeze wakeup |
