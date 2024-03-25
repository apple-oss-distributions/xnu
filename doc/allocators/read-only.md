# The Read-Only Allocator

Allocating read-only data in xnu.

## Introduction

The Read-Only Allocator is an extension of the zone allocator that facilitates
"read-only" allocations.  Data allocated from a read-only zone can only be
modified programmatically through the `zalloc_ro_mut` function.

Read-only zones are intended for very specific use cases where the data being
managed directly affects runtime security decisions.

## Discussion

The purpose of the Read-Only Allocator is to protect security-
sensitive data from being targeted by memory corruption vulnerabilities.

While, historically, the modus operandi for an advanced attacker is to seize
control of kernel execution, advances in control flow integrity defenses, such
as PAC, means that today's attacker favors data-only attacks to achieve
compromise.  Typically this involves using a controlled write primitive to
target data structures in the kernel's memory that effectively disables or
bypasses obstacles standing in the way of the desired data.

By necessity, we store lots of data on the heap that informs the various
security mechanisms on our platforms.  The heap traditionally dispenses
directly mutable allocations because this fits what we need the memory for:
frequent, fast and easy read/write access to memory.  Unfortunately, these are
also the requirements for an attacker looking to exploit a controllable write
into kernel memory.

For globals, `SECURITY_READ_ONLY_(EARLY|LATE)` provides an elegant protection
mechanism, but unfortunately that doesn't cater for dynamic runtime
allocations.

This is where the Read-Only Allocator provides its defense: we observe that
the majority of security-sensitive data that we allocate on the heap tends to
be written into memory once and seldom changed thereafter.  We can therefore
trade some of this ease of access in exchange for stronger guarantees on the
integrity of the data.

Data under the control of the Read-Only Allocator can be read from just as
cheaply and easily as other data, but writing to it must be done through the
relatively expensive `zalloc_ro_mut` function.  By insisting that data be
written programmatically (i.e. through calling a function), we raise the cost
of targeting that data towards the cost of seizing control of kernel
execution.


## Data Structure Strategies

To make best use of the Read-Only Allocator, some simple advice should be
followed:

1. Pointers to read-only elements should either reside in read-only memory
   themselves, or be protected by PAC.
2. Where there is a 1:1 mapping between read/write and read-only elements, the
   read-only element should include a pointer back to the read/write side (a
   "back reference") that is validated when traversing from read/write to
   read-only.

On Point 1: data structures are typically stored through chains of pointers --
e.g. a thread points to its task, which points to its proc, which points to
its credential.  The principle here is to ensure the integrity of the entire
chain from source pointer (e.g. thread) to destination data (e.g. credential).

On Point 2: by storing a back reference on the read-only side of 1:1
relationships, we can validate the ownership invariant that we expect to hold.
If this is violated, it suggests that a use-after-free has happened -- perhaps
through a genuine bug, or perhaps by an attacker targeting the zone allocator
itself.

## Should I Use the Read-Only Allocator?

The Read-Only Allocator is intended to protect data from very specific
threats.  This means that for most data, it simply doesn't make sense to use
it.  Its use is primarily geared toward allocations supporting security
boundaries such as labels, sandboxing, audit tokens, etc.


## API

Read-only zones cannot be created after lockdown.  To create a new read-only
zone, a new identifier must be added to the `zone_reserved_id_t` enumeration
and it must be created by passing `ZC_READONLY` through either `ZONE_INIT` or
`zone_create_ext`.

We require identifiers for read-only zones for two reasons: firstly to ensure
that we're making conscious, considered choices over which zones are made
read-only, and secondly to allow for more stringent validation at the API
boundary.

Once a read-only zone is created, the API for using it is small and simple.
The key functions are:

- `zalloc_ro`: Allocate an element from a read-only zone.
- `zfree_ro`: Free an element back to a read-only zone.  Note that this is a
  macro that automatically zeroes the pointer after freeing.
- `zone_require_ro`: Verify that an element belongs to a given read-only zone
  and panic if it doesn't.
- `zalloc_ro_mut`: Modify part of an element allocated from a read-only zone.
  Think of this as a special `memcpy` to write into your elements.
- `zalloc_ro_update_elem`: A convenience function for calling `zalloc_ro_mut`
  over the entirety of an element: simply passes an offset of zero and size
  equal to the size of the elements in the zone.

Note that `zfree_ro`, `zalloc_ro_mut` and `zalloc_ro_update_elem` will
perform a `zone_require_ro` on the element themselves; there's no need to do
this manually beforehand.
