XNU startup sequence
====================

Adding code to run during early boot.

### General Principles

XNU Startup sequence is driven by the `<kern/startup.h>` module.

The startup sequence is made of individual subsystems (the `STARTUP_SUB_*`
values of the `startup_subsystem_id_t` type) that get initialized in sequence.

A subsystem can use ranks to order the various initializers that make up its
initialization sequence. Usage of ranks is custom to each subsystem and must be
documented in this file.

The subsystem module will basically run hooks in that order:

```
for (subsystem 0 -> N) {
  for (rank 0 -> N) {
    // run in no particular order for a given rank in the given subsystem
    init(subsystem, rank);
  }
}
```

### Extending the startup sequence

When extending the startup sequence:

1. add a new value to the `startup_subsystem_id_t` enum in the right order
2. document what services this phase provides, and how it uses ranks in this
   file.


When hooking with a given subsystem, consult this documentation to use the
proper rank for your callback.

If a new rank needs to be used, update this documentation in the proper section.

---------------------------------------------------------------------------------


`STARTUP_SUB_TUNABLES`
----------------------

### Description

Initializes various globals that alter the behavior of the kernel, lookup
tables, ... Available hooks are:

- `TUNABLES`: parses a boot arg into a global that will become read-only at
  lockdown time,
- `TUNABLE_WRITEABLE`: same as `TUNABLE` but the global will not be locked down.

### Rank usage

- Rank 1: `TUNABLE`, `TUNABLE_WRITEABLE`
- Middle: globals that require complex initialization (e.g. SFI classes).


`STARTUP_SUB_TIMEOUTS`
----------------------

## Description

Initializes machine timeouts, which are device-tree/boot-args
configurable timeouts for low level machine code.

See the comments for the MACHINE_TIMEOUT macro on how they are used in
detail.

- Rank 1: `MACHINE_TIMEOUT` specifications.
- Rank 2: `ml_io_timeouts_init` for scheduler hygiene.
- Middle: Global lock timeouts that are derived from machine timeouts.

`STARTUP_SUB_LOCKS`
-------------------

### Description

Initializes early locks that do not require any memory allocations to be
initialized. Available hooks are:

- `LCK_GRP_DECLARE*`: automatically initialized lock groups,
- `LCK_ATTR_DECLARE`: automatically initialized lock attributes,
- `LCK_SPIN_DECLARE*`: automatically initialized spinlocks,
- `LCK_RW_DECLARE`: automatically initialized reader/writer lock,
- `LCK_MTX_DECLARE`: automatically initialized mutex,
- `SIMPLE_LOCK_DECLARE*`: automatically initialized simple locks.

### Rank usage

- Rank 1: Initializes the module (`lck_mod_init`),
- Rank 2: `LCK_ATTR_DECLARE`, `LCK_GRP_DECLARE*`
- Rank 3: compact lock group table init
- Rank 4: `LCK_SPIN_DECLARE*`, `LCK_MTX_DECLARE*`,
  `LCK_RW_DECLARE`, `SIMPLE_LOCK_DECLARE*`.


`STARTUP_SUB_KPRINTF`
---------------------

### Description

Initializes the kprintf subsystem.

### Rank usage

- Rank 1: calls the module initializer (`PE_init_kprintf`).


`STARTUP_SUB_PMAP_STEAL`
------------------------

### Description

Allows for subsystems to steal early memory.

### Rank usage

- First rank:
  - `cpu_data_startup_init`: Allocate per-CPU memory that needs to be accessible with MMU disabled
  - `socd_client_init`: Steal memory for SoC diagnostics
  - `vm_map_steal_memory`: Allocate bootstrap VM maps prior to the zone allocator coming up

- Last rank:
  - `init_ecc_bad_pages`: Exclude frames detected as bad from frame allocator

`STARTUP_SUB_KMEM`
------------------

### Description

Denotes that `kmem_alloc` is now usable.

### Rank usage

- First rank:
  - `zone_set_map_sizes`: Select physical limits for zone map
  - `vm_compressor_set_size`: Reserve VA for the compressor submap

- Rank 2:
  - `kmem_range_startup_init`: Initialize data structures associated wiht ranges registered via
    the `KMEM_RANGE_REGISTER_[STATIC|DYNAMIC]` mechanisms.

- Rank 3:
  - `kmem_range_init`: Shuffle and initialize ranges that have been registered up to now

- Last rank:
  - `io_map_init`: Creates an early `kernel_map` carve-out for mapping memory shared with devices

`STARTUP_SUB_ZALLOC`
--------------------

### Description

Initializes the zone allocator.

- `ZONE_DEFINE`, `ZONE_INIT`: automatically initialized permanent zones.
- `ZONE_VIEW_DEFINE`, `KALLOC_HEAP_DEFINE`: zone and kalloc heap views.


### Rank usage

- Rank 1: `zone_init`: setup the zone subsystem, this allows for the already
  created VM/pmap zones to become dynamic.

- Rank 2: `vm_page_module_init`: create the "vm pages" zone.
  The `vm_page_zone` must be created prior to `kalloc_init`; that routine can
  trigger `zalloc()`s (for e.g. mutex statistic structure initialization).

  The `vm_page_zone` must exist to satisfy fictitious page allocations
  (which are used for guard pages by the guard mode zone allocator).

- Rank 3: Initialize kalloc.

- Rank 4: Handle `ZONE_DEFINE` and `ZONE_INIT`.

- Middle:   zone and kalloc heaps (`ZONE_VIEW_DEFINE`, `KALLOC_HEAP_DEFINE`).

`STARTUP_SUB_KTRACE`
--------------------

### Description

Initializes kdebug and kperf and starts tracing if requested with boot-args.

### Rank usage

N/A.

`STARTUP_SUB_PERCPU`
--------------------

### Description

Initializes the percpu subsystem.

### Rank usage

Rank 1: allocates the percpu memory, `percpu_foreach_base` and `percpu_foreach`
        become usable.

Rank 2: sets up static percpu counters.


### Rank usage

- Rank 1: `LCK_MTX_DECLARE`.

`STARTUP_SUB_CODESIGNING`
-------------------------

### Description

Initializes the codesigning subsystem.

### Rank usage

- Rank 1: calls the module initializer (`cs_init`).

`STARTUP_SUB_OSLOG`
-------------------

### Description

Initializes the `os_log` facilities.

### Rank usage

- Rank 1: Calls the module initializer (`oslog_init`).


`STARTUP_SUB_MACH_IPC`
----------------------

### Description

Initializes the Mach IPC subsystem.

### Rank usage

- Rank 1: Initializes IPC submodule globals (ipc tables, voucher hashes, ...)
- Rank last: Final IPC initialization.


`STARTUP_SUB_THREAD_CALL`
-------------------------

### Description

Initializes the Thread call subsystem (and dependent subsystems).

### Rank usage

- Rank 1: Initiailizes the thread call subsystem
- Rank Middle: Initialize modules needing thread calls


`STARTUP_SUB_SYSCTL`
--------------------

### Description

Initializes the sysctl kernel subsystem

### Rank usage

- Rank 1: automatic `SYSCTL_NODE` registration.
- Rank 2: automatic `SYSCTL_OID` registration.
- Middle: other manual early registrations.
- Last: registrations of dummy nodes in the constant nodes to allow extension.


`STARTUP_SUB_EARLY_BOOT`
------------------------

### Description

Denotes that subsystems that expect to operate with
interrupts or preemption enabled may begin enforcement.

### Rank usage

- Rank 1: Initialize some BSD globals
- Middle: Initialize some early BSD subsystems


`STARTUP_SUB_EXCLAVES`
------------------------

### Description

Early exclaves initialization.

### Rank usage

- Rank 1: Determine run-time support for exclaves
- Middle: Initialize tightbeam runtime


`STARTUP_SUB_LOCKDOWN`
----------------------

### Description

Denotes that the kernel is locking down, this phase should never be hooked.
When the kernel locks down:

- data marked `__startup_data` or `__startup_const`, and code marked
  `__startup_func`, is unmapped;
- data marked `__security_const_late` or `SECURITY_READ_ONLY_LATE` becomes
  read-only.

### Rank usage

N/A.
