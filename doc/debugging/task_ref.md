Task References
===============

Finding the source of task reference count leaks.

Background
----------

Tasks in XNU are reference counted. When a task is created it starts with two
references - one for the caller and one for the task itself. Over the lifetime
of the task this reference count is modified, for example when a thread is
created it increments the reference count and when it exits that count drops.
When a reference count reaches zero, the task is freed.

To grab a reference:
```c
task_reference()
```

To release a reference:
```c
task_deallocate()
```

One of the big problems seen with task references is that difficult to debug
_leaks_ commonly occur. This happens when a reference is taken but never
released. The task is kept around indefinitely and eventually the system runs
out of a finite resource (for example ASIDs). At this point there is very little
information to determine what code was responsible for the leak.


Task Reference Groups
--------------------

Reference groups are a feature which keep track of statistics (and when
configured backtrace information) for a set of references. Reference groups are
hierarchical. To help with debugging the following task reference group
hierarchy is used:

```
task
   -> task_internal
      -> task_local_internal
   -> task_kernel
      -> task_local_internal
   -> task_mig
      -> task_local_internal
   -> task_external
      -> task_local_external
      -> task_com.apple.security.sandbox
          -> task_com.apple.security.sandbox
      -> task_com.apple.driver.AppleHV
          -> task_com.apple.driver.AppleHV
      ...
```

The `task` group contains a count of all task references in the system. The
first-level groups are static and sub-divide task references based on the
sub-system they come from. `task_external` is used for kext references and each
kext will be dynamically assigned a reference group as needed (if there's
one available). At the bottom level, there's a per-task (local) ref group under
each global group.
The exact hierarchy of task references (specifically what per-task reference
groups are created) changes depending on the 'task_refgrp' boot arg.

Task reference groups can be explored in `lldb` as follows:

```
(lldb) showglobaltaskrefgrps
os_refgrp          name                                           count     retain    release   log
0xffffff801ace9250 task_kernel                                    68        367663    367595    0x0
0xffffff801ace9288 task_internal                                  974       4953      3979      0x0
0xffffff801ace92c0 task_mig                                       0         3670      3670      0x0
0xffffff801ace9218 task_external                                  35        108       73        0x0
0xffffff9369dc7b20 task_com.apple.iokit.IOAcceleratorFamily2      29        77        48        0x0
0xffffff936a3f0a20 task_com.apple.iokit.CoreAnalyticsFamily       1         1         0         0x0
0xffffff936a22cb20 task_com.apple.iokit.EndpointSecurity          0         1         1         0x0
0xffffff936a283f60 task_com.apple.iokit.IOSurface                 5         5         0         0x0
0xffffff936a3f08a0 task_com.apple.security.sandbox                0         24        24        0x0

```

Display a task's reference groups:

```
(lldb) showtaskrefgrps kernel_task
os_refgrp          name                                           count     retain    release   log
0xffffff936a4b9200 task_local_kernel                              1         6         5         0x0
0xffffff936a4b9238 task_local_internal                            132       619       487       0x0
```

The reference group hierarchy for a specific group can be displayed as follows:

```
(lldb) showosrefgrphierarchy 0xffffff936a3f08a0
0xffffff801ace9988 all                                            1121      377740    376619    0x0
0xffffff801ace91e0 task                                           1077      376394    375317    0x0
0xffffff801ace9218 task_external                                  35        108       73        0x0
0xffffff936a3f08a0 task_com.apple.security.sandbox                0         24        24        0x0
```

Reference groups are normally disabled, but task reference group statistics
*are* enabled by default (for `RELEASE` builds, reference groups are not available
at all). Backtrace logging for all groups is disabled, including task reference
groups. To enable backtrace logging and reference group statistics, the `rlog`
boot-arg must be used. Backtrace logging for task reference groups is only
enabled when `rlog` has been set to a suitable value.

For example

To enable statistics for all reference groups and backtrace logging for the
*task_external* reference group in particular:

```
nvram boot-args="rlog=task_external ..."
```

```
(lldb) showglobaltaskrefgrps
os_refgrp          name                                           count     retain    release   log
0xffffff801e0e9250 task_kernel                                    1259      132739    131480    0x0
0xffffff801e0e9218 task_external                                  35        100       65        0xffffffa05b3fc000
0xffffff936d117be0 task_com.apple.iokit.IOAcceleratorFamily2      29        77        48        0x0
0xffffff936db9fa20 task_com.apple.iokit.CoreAnalyticsFamily       1         1         0         0x0
0xffffff936d9dbb20 task_com.apple.iokit.EndpointSecurity          0         1         1         0x0
0xffffff936da324e0 task_com.apple.iokit.IOSurface                 5         5         0         0x0
0xffffff936db9f8a0 task_com.apple.security.sandbox                0         16        16        0x0


(lldb) showbtlogrecords 0xffffffa05b3fc000
-------- OP 1 Stack Index 0 with active refs 1 of 165 --------
0xffffff801da7c1cb <kernel.development`ref_log_op at refcnt.c:107>
0xffffff801d27c35d <kernel.development`task_reference_grp at task_ref.c:274>
0xffffff801ecc014e <EndpointSecurity`VMMap::taskSelf()>
0xffffff801eccc845 <EndpointSecurity`EndpointSecurityClient::create(ScopedPointer<MachSendWrapper> const&, proc*, ScopedPointer<EndpointSecurityExternalClient> const&, es_client_config_t const&)>
...
```
