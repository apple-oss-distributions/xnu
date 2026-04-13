# Shared Regions

Basics of xnu's shared region (a.k.a. "shared cache") support.

## Overview

A shared region is a submap that contains the most common system shared
libraries for a given environment which is defined by:
 * cpu-type
 * 64-bitness
 * root directory
 * Team ID - when we have pointer authentication.

The point of a shared region is to reduce the setup overhead when exec'ing
a new process. A shared region uses a shared VM submap that gets mapped
automatically at `exec()` time (see `vm_map_exec()`).  The first process of a given
environment sets up the shared region and all further processes in that
environment can re-use that shared region without having to re-create
the same mappings in their VM map.  All they need is contained in the shared
region.

The region can also share a pmap (mostly for read-only parts but also for the
initial version of some writable parts), which gets "nested" into the
process's pmap.  This reduces the number of soft faults:  once one process
ings in a page in the shared region, all the other processes can access
it without having to enter it in their own pmap.

When a process is being exec'ed, `vm_map_exec()` calls `vm_shared_region_enter()`
to associate the appropriate shared region with the process's address space.
We look up the appropriate shared region for the process's environment.
If we can't find one, we create a new (empty) one and add it to the list.
Otherwise, we just take an extra reference on the shared region we found.
At this point, the shared region is not actually mapped into the process's
address space, but rather a permanent `VM_PROT_NONE` placeholder covering the
same VA region as the shared region is inserted.

The "dyld" runtime, mapped into the process's address space at exec() time,
will then use the `shared_region_check_np()` and `shared_region_map_and_slide_2_np()`
system calls to validate and/or populate the shared region with the
appropriate `dyld_shared_cache` file.  If the initial call to `shared_region_check_np()`
indicates that the shared region has not been configured, dyld will then call
`shared_region_map_and_slide_2_np()` to configure the shared region.  It's possible
that multiple tasks may simultaneously issue this call sequence for the same shared
region, but the synchronization done by `shared_region_acquire()` will ensure that
only one task will ultimately configure the shared region.  All other tasks will
wait for that task to finish its configuration step, at which point (assuming
successful configuration) they will observe the configured shared region and
re-issue the `shared_region_check_np()` system call to obtain the final shared
region info.

For the task that ends up configuring the shared region, the mapping and
sliding of the shared region is performed against a temporary configuration-only
vm-map, which is temporarily activated for the calling thread using
`vm_map_switch_to()`.  Once mapping and sliding completes successfully, the shared
region will be "sealed" by stabilizing all its map entries using `COPY_DELAY`
objects, which eliminates the need for later modification of shared region map
entries and thus simplifies the shared region's runtime locking requirements.
After this sealing step, the original task vm-map will be restored.  Since this
entire configuration sequence happens within the context of a single system call,
use of the temporary vm-map effectively guarantees that the shared region will
not be visible in the task's address space (either to other threads in the task
or to other tasks attempting to query the address space e.g. for debugging purposes)
until it has been fully configured and sealed.

The shared region is only inserted into a task's address space when the
`shared_region_check_np()` system call detects that the shared region has been fully
configured.  Only at this point will the placeholder entry inserted at `exec()`
time be replaced with the real shared region submap entry.  This step is required
of all tasks; even the task that previously configured the shared region must
issue a final `shared_region_check_np()` system call to obtain the real shared
region mapping.

The shared region is inherited on `fork()` and the child simply takes an extra
reference on its parent's shared region.

When the task terminates, we release the reference on its shared region.
When the last reference is released, we destroy the shared region.

After a `chroot()`, the calling process keeps using its original shared region,
since that's what was mapped when it was started.  But its children
will use a different shared region, because they need to use the shared
cache that's relative to the new root directory.
