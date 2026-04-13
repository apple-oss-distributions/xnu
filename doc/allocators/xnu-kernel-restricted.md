# Protecting Kernel-Private Memory

## Intro

We can classify all kernel-allocated memory into two high-level categories:

1. *Kernel-private memory*
2. *Kernel-shareable memory*

*Kernel-private memory* covers all the memory used exclusively by the kernel,
that is never meant to be shared with external domains. Therefore, such memory
should never be mapped into different address spaces — neither to userspace nor
to coprocessors via IOMMUs/DARTs. All zone/`kalloc_type()` managed memory which
contains pointers is de facto kernel private — as sharing kernel pointers with
other domains would be a security violation. It is however worth noting that
some data allocations are never going to be shared, and can be considered
kernel-private memory.

*Kernel-shareable memory* covers allocations made by the kernel that are meant
to be shared with external address spaces by-design. Such memory is not allowed
to contain kernel pointers nor any kernel-private information, and as a result
is always pure data allocations.

A lot of work has been done in our type-segregated allocators that we can
leverage so that the kernel can enforce appropriate mapping policies to make
sure that kernel-private memory actually stays private even in the presence of
bugs. Without such enforcement, attackers could attempt exploiting various
kernel interfaces to gain access to kernel-private memory into their address
space, which would bypass most of the state-of-the-art mitigations in the
kernel.

This document covers the problem space, the security boundaries we defend, and
the technical details of the mitigation.

## Problem space

The security boundaries we consider here are:

1. **user → kernel**: we consider attackers that have successfully compromised
a userspace process, and attempt to compromise the kernel via any form of
kernel vulnerability, including Mach VM logic bugs;
2. **coprocessors → kernel**: we consider attackers that have successfully
compromised a coprocessor, and attempt to compromise the kernel via any RPC
interface exposed by kernel extensions to these coprocessors.

These boundaries are special, because they often comprise APIs to map or share
memory between the kernel and userspace or coprocessors, that could be misused:

* The Mach VM subsystem manages virtual address spaces; therefore, bugs in this
subsystem could be abused to create illegal mappings to kernel-private memory.
* Many coprocessors operate on memory shared with the Application Processor, and
need to access memory owned by userspace tasks as well as memory managed by the
kernel. Because of that, some kernel extensions expose RPC interfaces to their
counterpart coprocessor, that allow for mapping memory via their IOMMU/DART.
This exposes a wide — and usually bespoke — attack surface that can lead to
illegal mappings to kernel-private memory to be created.

If attackers could gain the ability to map kernel-private memory into an
address space they control, they effectively defeat the boundary. This allows
them to access kernel pointers freely, which at least gives them a way to guide
attacks — if the mapping is read-only — but could even give them arbitrary
kernel read-write right away. At this point, most kernel mitigations can more
easily be bypassed, and exploitation becomes significantly easier.

## XNU_KERNEL_RESTRICTED

The Secure Page Table Monitor (SPTM) is highly privileged component that
defines and enforces all the policies that govern page table management,
for both the kernel and user applications, on behalf of XNU. Its goal is
to protect the overall system by securing the page tables against bad
actors, even in the presence of a compromised kernel.

The SPTM has a *type system*, which sits at the heart of the SPTM security
policies and primarily comprises the *frame table*, a data structure that
stores metadata associated with every managed physical page in the system,
alongside an immutable security policies that described what is allowed or
disallowed for that specific physical page at any given time. For each frame
type, there is a very clear set of policies that governs the permitted states
for a given physical page and restricts which transitions are allowed.

To address the above, the SPTM introduced a dedicated frame type for
kernel-private memory: `XNU_KERNEL_RESTRICTED` (X_K_R). This type has three
special policies that the SPTM enforces even in the presence of an XNU
compromise:

1. `XNU_KERNEL_RESTRICTED` pages can only be mapped in the kernel address
space — hence never in any user process.
2. `XNU_KERNEL_RESTRICTED` pages are not allowed be mapped via IOMMU/DART.
3. `XNU_KERNEL_RESTRICTED` pages are only allowed a single mapping beyond the
physical aperture static one.

Because all transitions that would affect mappings have to go through the SPTM,
these policies can be enforced, and will lead to a panic if an
`XNU_KERNEL_RESTRICTED` page is being involved in an illegal transition.


```

 ┌──────────────────────────────────────────────────────┐
 │                                                      │
 │                                                      │
 │                     ┌────────────┐   ┌────────────┐  │
 │                     │            │   │            │  │
 │   userspace         │   Task A   │   │   Task B   │  │
 │                     │            │   │            │  │
 │                     └──────▲─────┘   └─────▲──────┘  │
 │                                            │         │
 │                            │               │         │
 │                                            │         │
 │                            │               │         │
 │                                            │         │
 ├────────────────────────────┼───────────────┼─────────┤
 │                                            │         │
 │                   ┌────────┴────────┐      │         │        ┌─────────────┐
 │                   │   X_K_R page    │      │         │        │             │
 │                   │   refcnt == 1   │─ ─ ─ ┼ ─ ─ ─ ─ ┼ ─ ─ ─ ▶│ Coprocessor │
 │                   │                 │      │         │  ┌────▶│      C      │
 │  kernelspace      └─────────────────┘      │         │  │     │             │
 │                                            │         │  │     └─────────────┘
 │                                  ┌─────────┴───────┐ │  │
 │                                  │ non-X_K_R page  │ │  │
 │                                  │   refcnt == 3   │─┼──┘
 │                                  │                 │ │
 │                                  └─────────────────┘ │
 └──────────────────────────────────────────────────────┘


  ─────────▶    Legal mapping


  ─ ─ ─ ─ ─▶   Illegal mapping

```

## Security value

### Deterministic runtime mitigation

This mitigation stops **any** exploitation technique that involves mapping
kernel-private memory outside of the kernel address space, and forces attackers
to go down the path of full classic kernel exploitation. This means facing all
the kernel mitigations, including MTE. On top of mitigating all the attacks that
rely on using sharing/mapping interfaces, there is an immediate impact on
another class of MachVM security bugs: *Physical Use-after-free*.

The Mach VM manages the lifecycle of physical pages on the system. VM maps are
the source of truth of the system, and the pmap and page-tables are a live
cache of that state. The Mach VM has had bugs where the page tables would have
dangling page table entries (PTEs) — where these PTEs represented mappings that
should not exist anymore, and that the VM lost track of.

We call this class of inconsistency bugs *Physical Use-after-free (PUAF)*. When
the VM thinks a page became unused, it adds it to a freelist of physical pages
in order to repurpose it to hold new content, for possibly a completely
different security domain. In the case of a PUAF, the VM leaves a dangling
mapping that an attacker can take abuse to still access the content of a page
after it has been repurposed.

`XNU_KERNEL_RESTRICTED` forms a guarantee around this bug-class. SPTM requires
that a page has no active mappings when it is retyped, and while the VM has
lost track of the dangling mapping, SPTM will not. As a result, it becomes
impossible for an attacker to maintain access via a dangling PTE to a page
that was or would become `XNU_KERNEL_RESTRICTED`: the SPTM would detect the
illegal retyping operation and would panic the system immediately. Gaining
access to `XNU_KERNEL_RESTRICTED` memory via PUAF is hence deterministically
stopped.

However, attackers can try to exploit PUAFs on the same frame type, which
would not go through an SPTM retyping operation. For example, a page that was
used for user data in a task A that gets reused to hold completely different
data into a task B is such a scenario, and leads to an attacker breaking the
process address space isolation the VM is meant to provide. To address that,
we use a runtime check each time the Mach VM moves a physical page into a
“freed” state. We simply utilize SPTM’s precise tracking of mappings and
use it to assert that the page indeed has no active mapping. As a result,
any direct attempt to recycle a physical page with active mappings
deterministically panic the system.

### Protecting MTE

We apply MTE to the kernel to any dynamic memory that contains kernel pointers,
in order to mitigate use-after-free and out-of-bounds bugs. This can also be
extended to all kernel-private memory, not just the part that contains kernel
pointers — but isn’t at this time. The more memory we tag, the larger the
attack surface we protect.

However, if there is any way to access tagged memory without going through tag
checks, MTE is bypassed. Which is why we have to disallow any attempt of
mapping MTE tagged pages outside of the kernel address space, which completely
coincide with the purpose of `XNU_KERNEL_RESTRICTED`. In the end, this is no
different than the motivation described above; it is just that MTE makes it
even more appealing for attackers to reach for said primitives, which makes
`XNU_KERNEL_RESTRICTED` even more important.

## Typing memory

To know what is kernel-private with pointers, kernel-private without pointers
and kernel-shareable, we use the type-based segregation provided by in
[kalloc_type](https://security.apple.com/blog/towards-the-next-generation-of-xnu-memory-safety/).
The zone allocator (*zalloc*) and *kmem* already propagate metadata describing
the allocation, via the `KMEM_DATA`, or `KMEM_DATA_SHARED` flags:

* All *kmem* based allocations, besides `KMEM_COMPRESSOR` and
`KMEM_DATA_SHARED` pages, are typed as `XNU_KERNEL_RESTRICTED`.
* All *zalloc* allocations, besides the shareable data heap and ROAllocator,
are typed `XNU_KERNEL_RESTRICTED`.
