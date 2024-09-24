# XNU Allocators best practices

The right way to allocate memory in the kernel.

## Introduction

XNU proposes two ways to allocate memory:

- the VM subsystem that provides allocations at the granularity of pages (with
  `kmem_alloc` and similar interfaces);
- the zone allocator subsystem (`<kern/zalloc.h>`) which is a slab-allocator of
  objects of fixed size.

In addition to that, `<kern/kalloc.h>` provides a variable-size general purpose
allocator implemented as a collection of zones of fixed size, and overflowing to
`kmem_alloc` for allocations larger than a few pages (32KB when this
document was being written but this is subject to change/tuning in the future).


The Core Kernel allocators rely on the following headers:

- `<kern/zalloc.h>` and `<kern/kalloc.h>` for its API surface, which most
  clients should find sufficient,
- `<kern/zalloc_internal.h>` for interfaces that need to be exported
  for introspection and implementation purposes, and is not meant
  for general consumption.

This document will present the best practices to allocate memory
in the kernel, from a security perspective.

## Permanent allocations

The kernel sometimes needs to provide persistent allocations that depend on
parameters that aren't compile time constants, but will not vary over time (NCPU
is an obvious example here).

The zone subsystem provides a `zalloc_permanent*` family of functions that help
allocating memory in such a fashion in a very compact way.

Unlike the typical zone allocators, this allows for arbitrary sizes, in a
similar fashion to `kalloc`. These functions will never fail (if the allocation
fails, the kernel will panic), and always return zeroed memory. Trying to free
these allocations results in a kernel panic.

## Allocation flags

Most `zalloc` or `kalloc` functions take `zalloc_flags_t` typed flags.
When flags are expected, exactly one of `Z_WAITOK`, `Z_NOWAIT` or `Z_NOPAGEWAIT`
is to be passed:

- `Z_WAITOK` means that the zone allocator can wait and block,
- `Z_NOWAIT` can be used to require a fully non blocking behavior, which can be
  used for allocations under spinlock and other preemption disabled contexts;
- `Z_NOPAGEWAIT` allows for the allocator to block (typically on mutexes),
  but not to wait for available pages if there are none, this is only useful
  for the buffer cache, and most client should either use `Z_NOWAIT` or `Z_WAITOK`.

Other important flags:

- `Z_ZERO` if zeroed memory is expected (nowadays most of the allocations will
  be zeroed regardless, but it's always clearer to specify it), note that it is
  often more efficient than calling bzero as the allocator tends to maintain
  freed memory as zeroed in the first place,
- `Z_NOFAIL` if the caller knows the allocation can't fail: allocations that are
   made with `Z_WAITOK` from regular (non exhaustible) zones, or from `kalloc*`
   interfaces with a size smaller than `KALLOC_SAFE_ALLOC_SIZE`,
  will never fail (the kernel will instead panic if no memory can be found).
  `Z_NOFAIL` can be used to denote that the caller knows about this.
  If `Z_NOFAIL` is incorrectly used, then the zone allocator will panic at runtime.

## Zones (`zalloc`)

The first blessed way to allocate memory in the kernel is by using zones.
Zones are mostly meant to be used in Core XNU and some "BSD" kexts.

It is generally recommended to create zones early and to store the `zone_t`
pointer in read-only memory (using `SECURITY_READ_ONLY_LATE` storage).

Zones are more feature-rich than `kalloc`, and some features can only be
used when making a zone:

- the object type being allocated requires extremely strong segregation
  from other types (typically `zone_require` will be used with this zone),
- the object type implements some form of security boundary and wants to adopt
  the read-only allocator (See `ZC_READONLY`),
- the allocation must be per-cpu,
- ...

In the vast majority of cases however, using `kalloc_type` (or `IOMallocType`)
is preferred.


## The Typed allocator

Ignoring VM allocations (or wrappers like `IOMemoryDescriptor`), the only
blessed way to allocate typed memory in XNU is using the typed allocator
`kalloc_type` or one of its variants (like IOKit's `IOMallocType`) and untyped
memory that doesn't contain pointers is using the data API `kalloc_data` or
one of its variants (like IOKit's `IOMallocData`). However, this comes with
additional requirements.

Note that at this time, those interfaces aren't exported to third parties,
as its ABI has not yet converged.

### A word about types

The typed allocators assume that allocated types fit a very precise model.
If the allocations you perform do not fit the model, then your types
must be restructured to fit, for security reasons.

A general theme will be the separation of data/primitive types from pointers,
as attackers tend to use data/pointer overlaps to carry out their exploitations.

The typed allocators use compiler support to infer signatures
of the types being allocated. Because some scalars actually represent
kernel pointers (like `vm_offset_t`,`vm_address_t`, `uintptr_t`, ...),
types or structure members can be decorated with `__kernel_ptr_semantics`
to denote when a data-looking type is actually a pointer.

Do note that `__kernel_data_semantics` and `__kernel_dual_semantics`
are also provided but should typically rarely be used.

#### fixed-sized types

The first case is fixed size types, this is typically a `struct`, `union`
or C++ `class`. Fixed-size types must follow certain rules:

- types should be small enough to fit in the zone allocator:
  smaller than `KALLOC_SAFE_ALLOC_SIZE`. When this is not the case,
  we have typically found that there is a large array of data,
  or some buffer in that type, the solution is to outline this allocation.
  kernel extensions must define `KALLOC_TYPE_STRICT_SIZE_CHECK` to turn
  misuse of `kalloc_type()` relative to size at compile time, it's default in XNU.
- for union types, data/pointer overlaps should be avoided if possible.
  when this isn't possible, a zone should be considered.

#### Variable-sized types

These come in two variants: arrays, and arrays prefixed with a header.
Any other case must be reduced to those, by possibly making more allocations.

An array is simply an allocation of several fixed-size types,
and the rules of "fixed-sized types" above apply to them.

The following rules are expected when dealing with variable sized allocations:

- variable sized allocations should have a single owner and not be refcounted;
- under the header-prefixed form, if the header contains pointers,
  then the array element type **must not** be only data.

If those rules can't be followed, then the allocation must be split with
the header becoming a fixed-sized type becoming the single owner
of an array.

#### Untyped memory

When allocating untyped memory with the data APIs ensure that it doesn't
contain kernel pointers. If your untyped allocation contains kernel pointers
consider splitting the allocation into two: one part that is typed and contains
the kernel pointers and the second that is untyped and data-only.

### API surface

<table>
  <tr>
    <th>Interface</th>
    <th>API</th>
    <th>Notes</th>
  </tr>
  <tr>
    <td>Data/Primitive types</td>
    <td>
      <p>
      <b>Core Kernel</b>:<br/>
      <tt>kalloc_data(size, flags)</tt><br/>
      <tt>krealloc_data(ptr, old_size, new_size, flags)</tt><br/>
      <tt>kfree_data(ptr, size)</tt><br/>
      <tt>kfree_data_counted_by(ptr_var, count_var)</tt><br/>
      <tt>kfree_data_sized_by(ptr_var, byte_count_var)</tt><br/>
      <tt>kfree_data_addr(ptr)</tt>
      </p>
      <p>
      <b>IOKit untyped variant (returns <tt>void *</tt>)</b>:<br/>
      <tt>IOMallocData(size)</tt><br/>
      <tt>IOMallocZeroData(size)</tt><br/>
      <tt>IOFreeData(ptr, size)</tt>
      </p>
      <p>
      <b>IOKit typed variant (returns <tt>type_t *</tt>)</b>:<br/>
      <tt>IONewData(type_t, count)</tt><br/>
      <tt>IONewZeroData(type_t, count)</tt><br/>
      <tt>IODeleteData(ptr, type_t, count)</tt>
      </p>
    </td>
    <td>This should be used when the allocated type contains no kernel pointer only</td>
  </tr>
  <tr>
    <td>Fixed-sized type</td>
    <td>
      <p>
      <b>Core Kernel</b>:<br/>
      <tt>kalloc_type(type_t, flags)</tt><br/>
      <tt>kfree_type(type_t, ptr)</tt>
      </p>
      <p>
      <b>IOKit:</b><br/>
      <tt>IOMallocType(type_t)</tt><br/>
      <tt>IOFreeType(ptr, type_t)</tt>
      </p>
    </td>
    <td>
      <p>
      Note that this is absolutely OK to use this variant
      for data/primitive types, it will be redirected to <tt>kalloc_data</tt>
      (or <tt>IOMallocData</tt>).
      </p>
    </td>
  </tr>
  <tr>
    <td>Arrays of fixed-sized type</td>
    <td>
      <p>
      <b>Core Kernel</b>:<br/>
      <tt>kalloc_type(type_t, count, flags)</tt><br/>
      <tt>kfree_type(type_t, count, ptr)</tt>
      </p>
      <p>
      <b>IOKit:</b><br/>
      <tt>IONew(type_t, count)</tt><br/>
      <tt>IONewZero(type_t, count)</tt><br/>
      <tt>IODelete(ptr, type_t, count)</tt>
      </p>
    </td>
    <td>
      <p>
      <tt>kalloc_type(type_t, ...)</tt> (resp. <tt>IONew(type_t, 1)</tt>)
      <b>isn't</b> equivalent to <tt>kalloc_type(type_t, 1, ...)</tt>
      (resp. <tt>IOMallocType(type_t)</tt>). Mix-and-matching interfaces
      will result in panics.
      </p>
      <p>
      Note that this is absolutely OK to use this variant
      for data/primitive types, it will be redirected to <tt>kalloc_data</tt>.
      </p>
    </td>
  </tr>
  <tr>
    <td>Header-prefixed arrays of fixed-sized type</td>
    <td>
      <p>
      <b>Core Kernel</b>:<br/>
      <tt>kalloc_type(hdr_type_t, type_t, count, flags)</tt><br/>
      <tt>kfree_type(hdr_type_t, type_t, count, ptr)</tt>
      </p>
      <p>
      <b>IOKit:</b><br/>
      <tt>IONew(hdr_type_t, type_t, count)</tt><br/>
      <tt>IONewZero(hdr_type_t, type_t, count)</tt><br/>
      <tt>IODelete(ptr, hdr_type_t, type_t, count)</tt>
      </p>
    </td>
    <td>
      <p>
      <tt>hdr_type_t</tt> can't contain a refcount,
      and <tt>type_t</tt> can't be a primitive type.
      </p>
    </td>
  </tr>
</table>

`kfree_data_counted_by` and `kfree_data_sized_by` are used when working with
-fbounds-safety and pointers with __counted_by and __sized_by modifiers,
respectively. They expect both their pointer and size arguments to be
modifiable, and the pointer and size will be set to 0 together, in accordance
with -fbounds-safety semantics. Please note that arguments are evaluated
multiple times. When -fbounds-safety is enabled, the compiler can help ensuring
correct usage of these macros; with -fbounds-safety disabled, engineers are on
their own to ensure proper usage.

## C++ classes and operator new.

This section covers how typed allocators should be adopted to use
`operator new/delete` in C++. For C++ classes, the approach required
differs based on whether the class inherits from `OSObject` or not.

Most, if not all, C++ objects used in conjuction with IOKit APIs
should probably use OSObject as a base class. C++ operators
and non-POD types should be used seldomly.

### `OSObject` subclasses

All subclasses of `OSObject` must declare and define one of IOKit's
`OSDeclare*` and `OSDefine*` macros. As part of those, an `operator new` and
`operator delete` are injected that force objects to enroll into `kalloc_type`.

Note that idiomatic IOKit is supposed to use `OSTypeAlloc(Class)`.

### Other classes

Unlike `OSObject` subclasses, regular C++ classes must adopt typed allocators
manually. If your struct or class is POD (Plain Old Data), then replacing usage of
`new/delete` (resp. `new[]/delete[]`) with `IOMallocType/IOFreeType` (resp.
`IONew/IODelete`) is safe.

However, if you have non default structors, or members of your class/struct
have non default structors, you will need to manually enroll it into `kalloc_type`.
This can be accomplished through one of the following approaches, and it lets you
to continue to use C++'s new and delete keywords to allocate/deallocate instances.

The first approach is to subclass the IOTypedOperatorsMixin struct. This will
adopt typed allocators for your class/struct by providing the appropriate
implementations for `operator new/delete`:

```cpp
struct Type : public IOTypedOperatorsMixin<Type> {
    ...
};
```

Alternatively, if you cannot use the mixin approach, you can use the
`IOOverrideTypedOperators` macro to override `operator new/delete`
within your class/struct declaration:

```cpp
struct Type {
    IOOverrideTypedOperators(Type);
    ...
};
```

Finally, if you need to decouple the declaration of the operators from
their implementation, you can use `IODeclareTypedOperators` paired with
`IODefineTypedOperators`, to declare the operators within your class/struct
declaration and then provide their definition out of line:

```cpp
// declaration
struct Type {
    IODeclareTypedOperators(Type);
    ...
};

// definition
IODefineTypedOperators(Type)
```

When a class/struct adopts typed allocators through one of those approaches,
all its subclasses must also explicitly adopt typed allocators. It is not
sufficient for a common parent within the class hierarchy to enroll, in order to
automatically provide the implementation of the operators for all of its children:
each and every subclass in the class hierarchy must also explicitly do the same.

### The case of `operator new[]`

The ABI of `operator new[]` is unfortunate, as it denormalizes
data that we prefer to be known by the owning object
(the element sizes and array element count).

It also makes those allocations ripe for abuse in an adversarial
context as this denormalized information is at the begining
of the structure, making it relatively easy to attack with
out-of-bounds bugs.

For this reason, the default variants of the mixin and the macros
presented above will delete the implementation of `operator new[]`
from the class they are applied to.

However, if those must be used, you can add adopt the typed
allocators on your class by using the appropriate variant
which explicitly implements the support for array operators:
- `IOTypedOperatorsMixinSupportingArrayOperators`
- `IOOverrideTypedOperatorsSupportingArrayOperators`
- `IO{Declare, Define}TypedOperatorsSupportingArrayOperators`

### Scalar types

The only accepted ways of using `operator new/delete` and their variants are the ones
described above. You should never use the operators on scalar types. Instead, you
should use the appropriate typed allocator API based on the semantics of the memory
being allocated (i.e. `IOMallocData` for data only buffers, and `IOMallocType`/`IONew`
for any other type).

### Wrapping C++ type allocation in container OSObjects

The blessed way of wrapping and passing a C++ type allocation for use in the
libkern collection is using `OSValueObject`. Please do not use `OSData` for this
purpose as its backing store should not contain kernel pointers.

`OSValueObject<T>` allows you to safely use an `OSData` like API surface
wrapping a structure of type `T`. For each unique `T` being used, the
`OSValueObject<T>` must be instantiated in a module of your kernel extension,
using `OSDefineValueObjectForDependentType(T);`.

