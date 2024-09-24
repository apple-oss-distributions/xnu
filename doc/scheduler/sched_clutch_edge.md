# Clutch Scheduler

The intra-cluster thread scheduling design.

## Background

The XNU kernel runs on a variety of platforms with strong requirements for being dynamic and efficient. It needs to deliver on a wide range of requirements; from quick access to CPU for latency sensitive workloads (eg. UI interactions, multimedia recording/playback) to starvation avoidance for lower priority batch workloads (eg. photos sync, source compilation). The traditional Mach scheduler attempts to achieve these goals by expecting all threads in the system to be tagged with a priority number and treating high priority threads as interactive threads and low priority threads as batch threads. It then uses a timesharing model based on priority decay to penalize threads as they use CPU to achieve fairshare and starvation avoidance. This approach however loses the relationship between threads and higher level user workloads, making it impossible for the scheduler to reason about the workload as a whole which is what the end user cares about. One artifact of this thread based timesharing approach is that threads at the same priority level are treated similarly irrespective of which user workload they are servicing, which often leads to non-optimal decisions. It ultimately leads to priority inflation across the platform with individual subsystems raising their priority to avoid starvation and timesharing with other unrelated threads. The traditional thread level scheduling model also suffers from the following issues:

* **Inaccurate accounting**: CPU accounting at the thread level incentivizes creating more threads on the system. Also in the world of GCD and workqueues where threads are created and destroyed rapidly, thread level accounting is inaccurate and allows excessive CPU usage.
* **Poor isolation**: In the Mach scheduler, timesharing is achieved by decaying the priority of threads depending on global system load. This property could lead to a burst of activity at the same or lower priority band causing decay for the App/UI thread leading to poor performance and responsiveness. The scheduler offers very limited isolation between threads working on latency sensitive UI workloads and threads performing bulk non-latency sensitive operations.

The clutch scheduler is the timesharing algorithm for threads on a single cluster. The **Edge scheduler** extends on the clutch scheduler design to support multiple clusters of different performance and efficiency charecterstics. The Edge scheduler uses the clutch timesharing per cluster and adds other multi-cluster features such as thread placement, migration, round-robining etc.

## Clutch Scheduler Design

In order to reason about higher level user workloads, the clutch scheduler schedules groups of threads instead of individual threads. Breaking away from the traditional single-tier scheduling model, it implements a hierarchical scheduler which makes optimal decisions at various thread grouping levels. The hierarchical scheduler, as its implemented today, has 3 levels:

* Scheduling Bucket Level
* Thread Group Level
* Thread Level

### Scheduling Bucket Level

The highest level is the scheduling bucket level which decides which class of threads should be picked for execution. The kernel maintains a notion of scheduling bucket per thread which are defined based on the base/scheduling priority of the threads. These scheduling buckets roughly map to the QoS classes used by the OS runtime to define performance expectations for various pieces of work. All runnable threads with the same scheduling bucket are represented by a single entry at this level. These entries are known as *root buckets* throughout the implementation. The goal of this level is to provide low latency access to the CPU for high QoS classes while ensuring starvation avoidance for the low QoS classes. This level also maintains separate root buckets for threads bounded to this hierarchy and cluster which allows the scheduler to timeshare effectively between bounded and unbounded threads at various QoS levels.

**Implementation**

The scheduling bucket level uses an Earliest Deadline First (EDF) algorithm to decide which root bucket should be selected next for execution. Each root bucket with runnable threads is represented as an entry in a priority queue which is ordered by the bucket's deadline. The bucket selection algorithm simply selects the root bucket with the earliest deadline in the priority queue. The deadline for a root bucket is calculated based on its first-runnable timestamp and its **Worst Case Execution Latency (WCEL)** value which is pre-defined for each bucket. The WCEL values are picked based on the decay curve followed by the Mach timesharing algorithm to allow the system to function similar to the existing scheduler from a higher level perspective.

```
static uint32_t sched_clutch_root_bucket_wcel_us[TH_BUCKET_SCHED_MAX] = {
        SCHED_CLUTCH_INVALID_TIME_32,                   /* FIXPRI */
        0,                                              /* FG */
        37500,                                          /* IN (37.5ms) */
        75000,                                          /* DF (75ms) */
        150000,                                         /* UT (150ms) */
        250000                                          /* BG (250ms) */
};
```

Whenever a root bucket transitions from non-runnable to runnable, its deadline is set to `(now + WCEL[bucket])`. This ensures that the bucket would be scheduled at WCEL[bucket] even in a heavily loaded system. Once the root bucket is picked for execution, its deadline is pushed by WCEL[bucket] into the future. This basic implementation of EDF suffers from one major issue. In a heavily loaded system, it is possible that the higher buckets have used up enough CPU in the recent past such that they slip behind the lower buckets in deadline order. Now, if a small burst of user-critical workload shows up, a high bucket has to wait for the lower buckets to run before it can get CPU which might lead to performance issues. In order to address that, the bucket level scheduler implements a root bucket "warp" mechanism. Each bucket is provided a warp value which is refreshed whenever the bucket is selected due to its deadline expiring.

```
static uint32_t sched_clutch_root_bucket_warp_us[TH_BUCKET_SCHED_MAX] = {
        SCHED_CLUTCH_INVALID_TIME_32,                   /* FIXPRI */
        8000,                                           /* FG (8ms)*/
        4000,                                           /* IN (4ms) */
        2000,                                           /* DF (2ms) */
        1000,                                           /* UT (1ms) */
        0                                               /* BG (0ms) */
};
```
The root bucket selection logic finds the earliest deadline bucket and then checks if there are any higher (in natural priority order) buckets that have warp remaining. If there is such a higher bucket, it would select that bucket and effectively open a warp window. During this warp window the scheduler would continue to select this warping bucket over lower priority buckets. Once the warping bucket is drained or the warp window expires, the scheduler goes back to scheduling buckets in deadline order. This mechanism provides a bounded advantage to higher level buckets to allow them to remain responsive in the presence of bursty workloads.

The `FIXPRI` bucket is special cased since it contains extremely latency sensitive threads. Since the priority range for `FIXPRI (aka AboveUI)` and `FG Timeshare` buckets overlap, it is important to maintain some native priority order between those buckets. The policy implemented here is to compare the highest clutch buckets of both buckets; if the Above UI bucket is higher, schedule it immediately, otherwise fall through to the deadline based scheduling as described above. The implementation allows extremely low latency CPU access for Above UI threads while supporting the use case of high priority timeshare threads contending with lower priority fixed priority threads which is observed in some media workloads. Since the timeshare bucket will eventually drop in priority as it consumes CPU, this model provides the desired behavior for timeshare threads above UI.

When the EDF algorithm selects a low QoS root bucket even when a higher QoS root bucket is runnable due to deadline ordering, the root bucket selection algorithm marks the low root bucket as being in "starvation avoidance mode" and opens a "starvation avoidance window" equal to `thread_quantum[bucket]`. During this window all root bucket selections will pick the starved root bucket. This starvation avoidance window ensures that starved root buckets get a fair shot at draining the lower QoS threads even during heavy contention from higher priority threads.

The EDF algorithm is the best choice for this level due to the following reasons:

* Deadline based scheduling allows the scheduler to define strict bounds on worst case execution latencies for all scheduling buckets.
* The EDF algorithm is dynamic based on bucket runnability and selection. Since all deadline updates are computationally cheap, the algorithm can maintain up-to-date information without measurable overhead.
* It achieves the goals of maintaining low scheduling latency for high buckets and starvation avoidance for low buckets efficiently.
* Since the bucket level scheduler deals with a fixed small number of runnable buckets in the worst case, it is easy to configure in terms of defining deadlines, warps etc.

### Thread Group Level

The second level is the “thread group” level which decides which thread group within a QoS bucket should be selected next for execution. Thread groups  represent a collection of threads working on behalf of a specific workload. The goal of this level is to share the CPU among various user workloads with preference to interactive applications over compute-intensive batch workloads.

**Implementation**

The thread group level implements a variation of the FreeBSD ULE scheduler to decide which thread group should be selected next for execution. Each thread group with runnable threads within a QoS bucket is represented using by `struct sched_clutch_bucket_group`. For multi-cluster platforms, the `sched_clutch_bucket_group` represents threads enqueued on all clusters on the platform. The clutch bucket group maintains the CPU utilization history, runnable history and some timesharing information for the next level scheduler. 

The clutch bucket group has an entry to represent runnable threads for the thread group per cluster on the platform. This entry is the `sched_clutch_bucket` and this level of the algorithm is trying to find the best clutch bucket to schedule on each root hierarchy. Each clutch bucket with runnable threads is represented as an entry in a runqueue which is ordered by clutch bucket priorities. The clutch bucket selection algorithm simply selects the clutch bucket with the highest priority in the clutch bucket runqueue. The priority calculation for the clutch buckets is based on the following factors:

* **Highest runnable thread in the clutch bucket**: The clutch bucket maintains a priority queue which contains threads ordered by their promoted or base priority (whichever property made the thread eligible to be part of that clutch bucket). It uses the highest of these threads to calculate the base priority of the clutch bucket. The use of both base and sched priority allows the scheduler to honor priority differences specified from userspace via SPIs, priority boosts due to priority inheritance mechanisms like turnstiles and other priority affecting mechanisms outside the core scheduler.
* **Interactivity score**: The scheduler calculates an interactivity score based on the ratio of voluntary blocking time and CPU usage time for the clutch bucket group as a whole. This score allows the scheduler to prefer highly interactive thread groups over batch processing compute intensive thread groups.

The clutch bucket group maintains a few metrics to allow calculation of the interactivity score for the thread group:

* **Clutch Bucket Group Blocked Time**: Maintains the amount of time no threads were runnable for the clutch bucket group.
* **Clutch Bucket Group Pending Time**: Maintains the amount of time threads were pending execution for this clutch bucket group. This value is reset as soon as one of the threads of the clutch bucket group is executed.
* **Clutch Bucket Group CPU Time**: Maintains the CPU time used by all threads of this clutch bucket group. 

The interactivity score based algorithm is well suited for this level due to the following reasons:

* It allows for a fair sharing of CPU among thread groups based on their recent behavior. Since the algorithm only looks at recent CPU usage history, it also adapts to changing behavior quickly.
* Since the priority calculation is fairly cheap, the scheduler is able to maintain up-to-date information about all thread groups which leads to more optimal decisions.
* Thread groups provide a convenient abstraction for groups of threads working together for a user workload. Basing scheduling decisions on this abstraction allows the system to make interesting choices such as preferring Apps over daemons which is typically better for system responsiveness.

The clutch bucket runqueue data structure allows the clutch buckets to be inserted at the head of the queue when threads from that clutch bucket are pre-empted. The runqueues also rotate the clutch bucket to the end of the runqueue at the same priority level when a thread is selected for execution from the clutch bucket. This allows the system to round robin efficiently among thread groups at the same priority value especially on highly contended low CPU systems.

### Thread Level

At the lowest level the scheduler decides which thread within a clutch bucket should be selected next for execution. Each runnable thread in the clutch bucket is represented as an entry in a runqueue which is organized based on the `sched_pri` of threads. The thread selection algorithm simply selects the highest priority thread in the runqueue. The `sched_pri` calculation for the threads is based on the traditional Mach scheduling algorithm which uses load & CPU usage to decay priority for a thread. The thread decay model is more suited at this level as compared to the global scheduler because the load calculation only accounts for threads in the same clutch bucket group. Since all threads in the same clutch bucket group belong to the same thread group and scheduling bucket, this algorithm provides quick CPU access for latency sensitive threads within the clutch bucket group without impacting other non-related threads in the system.

**Implementation**

The thread level scheduler implements the Mach timesharing algorithm to decide which thread within the clutch bucket should be selected next for execution. All runnable threads in a clutch bucket are inserted into the runqueue based on the `sched_pri`. The scheduler calculates the `sched_pri` of the threads in a clutch bucket group based on the number of runnable threads in the clutch bucket group and the CPU usage of individual threads. The load information is updated every scheduler tick and the threads use this information for priority decay calculation as they use CPU. The priority decay algorithm attempts to reward bursty interactive threads and penalize CPU intensive threads. Once a thread is selected for running, it is assigned a quantum which is based on the scheduling bucket it belongs to. The quanta for various buckets are defined statically as:

```
static uint32_t sched_clutch_thread_quantum_us[TH_BUCKET_SCHED_MAX] = {
        10000,                                          /* FIXPRI (10ms) */
        10000,                                          /* FG (10ms) */
        8000,                                           /* IN (8ms) */
        6000,                                           /* DF (6ms) */
        4000,                                           /* UT (4ms) */
        2000                                            /* BG (2ms) */
};
```

The per-bucket thread quantum allows the scheduler to bound the worst case execution latency for a low priority thread which has been starved by higher priority threads.

## Scheduler Priority Calculations

### Root Priority Calculation

The scheduler maintains a root level priority for the hierarchy in order to make decisions regarding pre-emptions and thread selection. The root priority is updated as threads are inserted/removed from the hierarchy. The root level also maintains the urgency bits to help with pre-emption decisions. Since the root level priority/urgency is used for pre-emption decisions, it is based on the threads in the hierarchy and is calculated as follows:

```
Root Priority Calculation:
* If AboveUI bucket is runnable, 
*     Compare priority of AboveUI highest clutch bucket (CBUI) with Timeshare FG highest clutch bucket (CBFG)
*     If pri(CBUI) >= pri(CBFG), select CBUI
* Otherwise find the (non-AboveUI) highest priority root bucket that is runnable and select its highest clutch bucket
* Find the highest priority (promoted or base pri) thread within that clutch bucket and assign that as root priority

Root Urgency Calculation:
* On thread insertion into the hierarchy, increment the root level urgency based on thread's sched_pri
* On thread removal from the hierarchy, decrement the root level urgency based on thread's sched_pri

```

### Root Bucket Priority Calculation

The root bucket priority is simply the deadline of the root bucket which is calculated by adding the WCEL of the bucket to the timestamp of the root bucket becoming runnable.

```
root-bucket priority = now + WCEL[bucket]
```

### Clutch Bucket Priority Calculation

As mentioned earlier, the priority value of a clutch bucket is calculated based on the highest runnable thread and interactivity score. The actual calculation algorithm is as follows:

```
* Find the highest runnable thread (promoted or basepri) in the clutch bucket (maxpri)
* Calculate the ratio of CPU blocked and CPU used for the clutch bucket.
*      If blocked > used, assign a score (interactivity_score) in the higher range.
*      Else, assign a score (interactivity_score) in the lower range.
* clutch-bucket priority = maxpri + interactivity_score
```

### Thread Priority Calculation

The thread priority calculation is based on the Mach timesharing algorithm. It is calculated in the following manner:

```
* Every scheduler tick, snapshot the load for the clutch bucket
* Use the load value to calculate the priority shift values for all threads in the clutch bucket
* thread priority = base priority - (thread CPU usage >> priority shift)
```

## Edge Scheduler Design

The Edge scheduler implements all the necessary features needed for scheduling on multi-cluster asymmetric platforms. On each cluster, it uses the clutch scheduler timesharing design described above. In terms of thread placement and load balancing, the Edge scheduler represents the machine as a graph where each node is a compute cluster and the directional edges describe the likelihood of migrating threads from one cluster to another. The Edge scheduler works closely with the performance controller to define 

### Edge Scheduler System Goals

* The system should be **compact**. Limit small-width workload threads to a single cluster as much as possible. A few reasons why this property is essential:
	* Better LLC usage.
	* Improved performance from avoid expensive inter-cluster, inter-die cache fills
	* Power gate or power down unused ACCs
* **Rapidly open up clusters** if the workload can use them (e.g., for parallelism, to mitigate passenger effects) for the following reasons:
	* No dark silicon
	* Efficiency cores offer meaningful performance uplift for benchmarks as well as throughput-oriented workloads.
* Allow **low latency access to CPU** for high QoS work. This property ensures that the high QoS threads experience low scheduling latency under heavy CPU contention as well.
* **Migrate "down" only**. Threads should migrate to clusters where execution efficiency won’t be significantly worse. This might be a reason to open up new clusters (in contrast to the first system goal of keeping the system compact).
* Manage **passenger effects**. When the desired performance of workloads sharing a cluster begins to diverge, some will pay a “passenger tax”. In those cases, it is desirable to split up the workloads to ensure the most efficient execution on the platform.
* Adapt to **rapidly changing workload widths**.

When the scheduler and performance controller for Skye (the first AMP platform) were being designed, much of the emphasis was placed on delineating work across E-cores and P-cores. Concepts such as thread groups, asymmetric spill & steal, etc. were invented to efficiently exploit this performance & energy efficiency heterogeneity in the hardware. However the same concepts largely apply to a platform with several homogenous clusters and heterogenous clusters with independent DVFM domains as well.

### Edge Scheduler Thread Placement Strategy

The Edge scheduler uses **per-thread group recommendations** from the performance controller and **per-cluster runqueues** in the scheduler. The design aims to provide the performance controller with the ability to influence the width of the system (in terms of number of clusters), while retaining the scheduler's ability to go wide in the event of a thread storm.

#### Thread Group Cluster Recommendations

The scheduler expects the performance controller to specify a cluster recommendation for each thread group. To allow finer grained thread placement, the Edge scheduler allows the performance controller to specify a preferred cluster per QoS within the thread group i.e. per sched\_clutch\_bucket\_group. The ability to prefer specific clusters rather than cluster types allows the performance controller to implement passenger tax reduction policies and co-locate workloads which expect similar performance charecterstics. 

When a thread becomes runnable, the scheduler looks at the preferred cluster recommendation of the sched\_clutch\_bucket_group it belongs to and uses that as  the starting decision point for thread placement. If the preferred cluster is idle or running lower QoS workloads, the scheduler simply selects the preferred cluster for enqueing the thread. Otherwise, the scheduler uses the thread migration strategy described in the next section. 

When the performance controller changes the preferred cluster for a sched\_clutch\_bucket\_group, the Edge scheduler also provides an option to migrate the running and runnable threads for that group immediately (as opposed to the next scheduling point where the preferred cluster will be re-evaluated). The performance controller can use this feature to change recommendations for latency sensitive workloads from efficient to performance clusters and ensure that the workload threads get placed on the newly preferred cluster immediately.

#### Thread Migration Strategy

In order to choose a cluster & processor for a runnable thread, the edge scheduler uses the preferred cluster for the thread's sched\_clutch\_bucket_group. If the preferred cluster is idle or running lower QoS workloads, the scheduler simply selects the preferred cluster for enqueing the thread. Otherwise, the scheduler evaluates the outgoing edges from the preferred cluster for migration decisions.

**Edge Scheduler Edge Matrix**

The Edge scheduler maintains a thread migration graph where each node represents a cluster and each directional edge represents the likelihood of migrating threads across that edge. Each graph edge encodes the following attributes:

```
typedef union sched_clutch_edge {
        struct {
                uint32_t
                /* boolean_t */ sce_migration_allowed : 1,
                /* boolean_t */ sce_steal_allowed     : 1,
                                _reserved             : 30;
                uint32_t        sce_migration_weight;
        };
        uint64_t sce_edge_packed;
} sched_clutch_edge;
```
The `sce_migration_allowed` & `sce_steal_allowed` flags indicate if threads are allowed to be migrated & stolen across the edge. The `sce_migration_weight` is a measure of the scheduling latency delta that should exist between the source and destination nodes (i.e. clusters) for the thread to be migrated. The per-cluster scheduling latency metric is described in the next section. 

The performance controller can dynamically update the weights and properties of the edge matrix dynamically to change the width of the system for performance and efficiency reasons. 

**Edge Scheduler Cluster Scheduling Latency Metric**

The Edge scheduler maintains a per-cluster scheduling latency metric which indicates the latency for a thread of a given QoS to get on core on the cluster. The metric has its roots in queueing delay algorithms and calculates the amount of time it would take for a newly runnable thread to get picked by a core on the cluster. The scheduling latency metric is calculated using the following formula:

```
Scheduling-Latency(QoS) = Cumulative Higher QoS Load(QoS) * Avg. Execution Latency(QoS)
```
* Cumulative Higher QoS Load: The cumulative higher QoS load metric calculates the number of runnable and running threads of a higher or equal QoS that are enqueued or running on the cluster. This measures the number of threads that are ahead of the newly made runnable thread in terms of getting a chance to execute on the cluster.
* Avg. Execution Latency: The avg execution latency metric tracks the average execution latency of threads at a particular QoS. This value tracks the amount of work threads at this QoS typically do before blocking or context switching.

Both metrics are maintained as an exponentially moving weighted average to make sure they capture the recent behavior of the threads on the system. The per-cluster scheduling latency metric is used to decide thread placement based on the following algorithm:

```
* On thread becoming runnable, get the scheduling latency metric for the thread's QoS and preferred cluster (as specified by CLPC)
* If preferred cluster scheduling latency is 0, return preferred cluster
* Otherwise, for each cluster which is not the preferred cluster,
*    Calculate the scheduling latency metric for the cluster and the thread's QoS
*    If scheduling latency metric is 0, return cluster
*    Otherwise, calulate the scheduling latency delta between the cluster and the preferred cluster
*    If delta is less than the edge weight between preferred cluster and cluster, continue
*    Otherwise, if delta is greater than largest delta, store delta as largest delta
* Return cluster with largest scheduling latency delta
```

The order of cluster iteration in the algorithm above specifically picks homogeneous clusters before asymmetric clusters to ensure the threads migrate to idle clusters with similar performance characteristics before asymmetric idle clusters.

#### Thread Stealing/Rebalancing Strategy

The `SCHED(steal_thread)` scheduler callout is invoked when the processor does not find any thread for execution in its runqueue. The aim of the steal operation is to find other threads running/runnable in other clusters which should be executed here. If the steal callout does not return a thread, the `thread_select()` logic calls `SCHED(processor_balance)` callout which is supposed to IPI other CPUs to rebalance threads and idle out the current CPU waiting for the IPI'ed thread to reschedule the thread onto this CPU.

**Edge Scheduler Foreign Threads**

The Edge scheduler identifies clutch buckets (and correspondingly the threads in the clutch bucket) as foreign when these clutch buckets are enqueued on a cluster which are asymmetric from the preferred cluster of the thread group. The foreign clutch buckets are part of the regular hierarchy of the clutch root but are also linked in a special "foreign" priority queue maintained at the root. This foreign priority queue allows other clusters to easily rebalance threads from asymmetric clusters when they run out of threads in their local hierarchy runqueue. 

**Edge scheduler steal implementation**

The edge scheduler implements the steal operation via `sched_edge_processor_idle()`. This routine tries to do the following operations in order:

```
* (1) Find foreign runnnable threads in non-native cluster runqueues (sched_edge_foreign_runnable_thread_remove())
* (2) Steal a runnable thread from a native cluster runqueue (sched_edge_steal_thread())
* (3) Check if foreign threads are running on the non-native clusters (sched_edge_foreign_running_thread_available())
*     If available, return THREAD_NULL for the steal callout and perform rebalancing as part of SCHED(processor_balance) i.e. sched_edge_balance()
* (4) Steal a thread from another cluster based on sce_steal_allowed & cluster loads (sched_edge_steal_thread())
```
The policy of doing these operations in this specific order is chosen to ensure that threads are not runnable or executing on cluster types which are different from its preferred cluster type. If no such thread is found, then the scheduler aims to reduce the load on other clusters by stealing threads from them.

**Edge scheduler rebalance operation**

If `SCHED(steal_thread)` did not return a thread for the processor, it indicates that the processor found a thread running on a "foreign" cluster and would like to rebalance it onto itself. The implementation (`sched_edge_balance()`) sends an IPI to the foreign CPU, idles itself and waits for the foreign CPU to rebalance the thread on this idle CPU.

#### Cluster Shared Resource Threads Management

The Edge scheduler attempts to load balance cluster shared resource intensive threads across clusters in order to reduce contention on the shared resources. It achieves that by maintaining the runnable and running shared resource load on each cluster and balancing the load across multiple clusters. The current implementation for cluster shared resource load balancing looks at the per-cluster load at thread runnable time to enqueue the thread in the appropriate cluster.

**Cluster shared resource thread scheduling policy**

The threads for shared resources can be scheduled using one of the two policies:

* EDGE\_SHARED\_RSRC\_SCHED\_POLICY\_RR
This policy distributes the threads so that they spread across all available clusters irrespective of type. The idea is that this scheduling policy will put a shared resource thread on each cluster on the platform before it starts doubling up on clusters.
* EDGE\_SHARED\_RSRC\_SCHED\_POLICY\_NATIVE\_FIRST
This policy distributes threads so that the threads first fill up all the capacity on the preferred cluster and its homogeneous peers before spilling to different core type. The current implementation defines capacity based on the number of CPUs in the cluster; so a cluster's shared resource is considered full if there are "n" runnable + running shared resource threads on the cluster with n cpus. This policy is different from the default scheduling policy of the edge scheduler since this always tries to fill up the native clusters to capacity even when non-native clusters might be idle.

#### Long Running Workload AMP Round Robining

The Edge scheduler implements a policy to round robining long running workload threads across clusters of various types to ensure that all threads of the workload make equal progress aka "stir-the-pot". This is essential for performance of workloads that statically partition work among ncpu threads. The scheduler invokes this mechanism when a thread expires a quantum on a non-preferred cluster (most likely due to migration/spilling from the preferred cluster). The scheduler recognizes this (via `AST_QUANTUM` and `AST_REBALANCE` being set) and enqueues it on a cluster native to the preferred cluster. On the next scheduling event for that cluster, the CPU will pickup this thread and spill/migrate the thread previously running onto the non-preferred cluster. In order to make sure all clusters native to the preferred cluster are euqally subject to this round-robining, the scheduler maintains a `scbg_amp_rebalance_last_chosen` value per sched_clutch_bucket_group (which represents all threads of a workload at the same QoS level).
