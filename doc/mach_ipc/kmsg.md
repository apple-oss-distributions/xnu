IPC kmsg
========

IPC kmsg is the kernel representation of an in flight Mach IPC
message.

## Layouts

IPC kmsg have a complex in memory layout that is designed to separate kernel
pointers from user controled data. There are 4 layouts that we'll present in
this section.


### Mach messages

IPC kmsg is meant to wrap a Mach message, which is made of 4 different parts,
some of them optional:
- a header (`mach_msg_header_t`) is always present;
- if `msgh_bits` has the `MACH_MSGH_BITS_COMPLEX` bit set, then a descriptor
  count and array of descriptors follows;
- then a body of bytes follows to pad the message up to `msgdh_size` bytes,
  (and can potentially be empty);
- lastly, a free floating "aux" data bag can carry ancilary data next to the
  message (it is used by libdispatch to carry over things like activity IDs
  for logging).

```
           ╭ ┌─[ mach_msg_header_t ]───────────────────────────────────┐ ╮
           │ │ msgh_bits                   (if MACH_MSGH_BITS_COMPLEX) │ │
           │ │ msgh_size                                ╷              │ │
           │ │ msgh_remote_port                         │              │ │
           │ │ msgh_local_port                          │              │ │
           │ │ msgh_voucher_port                        │              │ │
           │ │ msgh_id                                  ▼              │ │
           │ ├────────────────────────────┬────────────────────────────┤ │ contains
           │ │ body (pure data)           │ msgh_descriptor_count (dc) │ │ pointers
           │ ╎                            ├────────────────────────────┤ │ in kernel
           │ ╎                            │ descriptor #1              │ │
 msgh_size │ ╎                            │                            │ │
   bytes   │ ╎                            ├────────────────────────────┤ │
           │ ╎                            ╎                            ╎ │
           │ ╎                            ╎                            ╎ │
           │ ╎                            ├────────────────────────────┤ │
           │ ╎                            │ descriptor #dc             │ │
           │ ╎                            │                            │ │
           │ ╎                            ├────────────────────────────┤ ╯
           │ ╎                            │ body (pure data)           │
           │ ╎                            ╎                            ╎
           │ ╎                            ╎                            ╎
           │ │                            │                            │
           ╰ ├────────────────────────────┴────────────────────────────┤
             │ trailer (various sizes)                                 │
             │                                                         │
             │                                                         │
             │                                                         │
             │                                                         │
             │                                                         │
             └─────────────────────────────────────────────────────────┘

           ╭ ┌─[ mach_msg_aux_header_t ]───────────────────────────────┐
           │ │ msgdh_size                                              │
           │ │ msgdh_reserved                                          │
           │ ├─────────────────────────────────────────────────────────┤
msgdh_size │ │ payload (pure data)                                     │
           │ ╎                                                         ╎
           │ ╎                                                         ╎
           │ │                                                         │
           ╰ └─────────────────────────────────────────────────────────┘
```

Note that subsystems like MIG used to assume that the entire Mach message
from header to trailer was in contiguous memory, but that is no longer true,
and a Mach message in the kernel can be split in 3 separate non contiguous
parts:
- its header + descriptors (which contain kernel pointers in kernel);
- its pure data body and trailer;
- its auxiliary data payload.

### The core IPC kmsg type: `struct ipc_kmsg`

As far as layout is concerned, an IPC kernel message is made of two halves: some
fields are always used and make up the "header" of the kmsg, and then some data
follows that is used in various ways depending on the `ikm_type` field of the
message.

```
             ┌─────────────────────────────────────────────────────────┐ ╮
             │                                                         │ │
             │                  ... header fields ...                  │ │
             │                                                         │ │
             ├─────────────────────────────────────────────────────────┤ │
             │ ikm_aux_size                                            │ │
             ├─────────────────────────────────────────────────────────┤ │ "header"
             │                                                         │ │
             │               ... more header fields ...                │ │
             │                                                         │ │
             ├─────────────────────────────────────────────────────────┤ │
             │ ikm_type                                                │ │
             ├────────────────────────────┬────────────────────────────┤ ┤
             │ ikm_big_data               │ ikm_small_data             │ │
             │                            │                            │ │
             │                            │                            │ │
             │                            │                            │ │
             │                            │                            │ │
             │                            │                            │ │
             │                            │                            │ │  "body"
             │                            │                            │ │
             │                            │                            │ │
             │                            ├────────────────────────────┤ │
             │                            │ ikm_kdata                  │ │
             │                            │ ikm_udata                  │ │
             │                            │ ikm_kdata_size             │ │
             │                            │ ikm_udata_size             │ │
             └────────────────────────────┴────────────────────────────┘ ╯
```

This data structure has 4 configurations, depending on the value of `ikm_type`,
detailed below.

### `IKM_TYPE_ALL_INLINED`: no external allocation

For this kmsg type, there is no external allocation, and the `ikm_big_data`
inline buffer of the kmsg is used to fit all parts of the mach message this way:

```
             ┌─────────────────────────────────────────────────────────┐
             │                                                         │
             │                  ... header fields ...                  │
             │                                                         │
             ├─────────────────────────────────────────────────────────┤
        ╭────┼ ikm_aux_size                                            │
        │    ├─────────────────────────────────────────────────────────┤
        │    │                                                         │
        │    │               ... more header fields ...                │
        │    │                                                         │
        │    ├─────────────────────────────────────────────────────────┤
        │    │ ikm_type                         (IKM_TYPE_ALL_INLINED) │
        │    ├─┬─────────────────────────────────────────────────────┬─┤
        │    │ │                                                     │ │
        │    │ │                                                     │ │
        │    │ │          Mach message header + descriptors          │ │
        │    │ │                                                     │ │
        │    │ │                                                     │ │
        │    │ ├─────────────────────────────────────────────────────┤ │
        │    │ │                                                     │ │
        │    │ │                                                     │ │
        │    │ │                                                     │ │
        │    │ │             Mach message body + trailer             │ │
        │    │ │                                                     │ │
        │    │ │                                                     │ │
        │    │ │                                                     │ │
        │    │ └─────────────────────────────────────────────────────┘ │
        │    │                                                         │
        │    │                     (unused space)                      │
        │    │                                                         │
        │  ╭ │ ┌─────────────────────────────────────────────────────┐ │
        │  │ │ │                                                     │ │
        ╰─▶│ │ │           Mach message auxiliary payload            │ │
           │ │ │                                                     │ │
           ╰ └─┴─────────────────────────────────────────────────────┴─┘
```

### `IKM_TYPE_UDATA_OOL`: external allocation for pure data

In this layout, the "pure" data of the Mach message (its body, trailer, and
auxiliary payload) is allocated out of line. The kmsg uses its `ikm_small_data`
inline buffer to store the Mach message header and descriptors, this way:

```
             ┌─────────────────────────────────────────────────────────┐
             │                                                         │
             │                  ... header fields ...                  │
             │                                                         │
             ├─────────────────────────────────────────────────────────┤
             │ ikm_aux_size                                            ┼────╮
             ├─────────────────────────────────────────────────────────┤    │
             │                                                         │    │
             │               ... more header fields ...                │    │
             │                                                         │    │
             ├─────────────────────────────────────────────────────────┤    │
             │ ikm_type                           (IKM_TYPE_UDATA_OOL) │    │
           ╭ ├─┬─────────────────────────────────────────────────────┬─┤◀─╮ │
           │ │ │                                                     │ │  │ │
           │ │ │                                                     │ │  │ │
        ╭─▶│ │ │          Mach message header + descriptors          │ │  │ │
        │  │ │ │                                                     │ │  │ │
        │  │ │ │                                                     │ │  │ │
        │  ╰ │ └─────────────────────────────────────────────────────┘ │  │ │
        │    │                                                         │  │ │
        │    │                     (unused space)                      │  │ │
        │    │                                                         │  │ │
        │    ├─────────────────────────────────────────────────────────┤  │ │
        │    │ ikm_kdata                                              ─┼──╯ │
        │    │ ikm_udata                                              ─┼──╮ │
        ╰────┼ ikm_kdata_size                                          │  │ │
        ╭────┼ ikm_udata_size                                          │  │ │
        │    └─────────────────────────────────────────────────────────┘  │ │
        │                                                                 │ │
        │                                 ╭───────────────────────────────╯ │
        │                                 │                                 │
        │  ╭ ┌────────────────────────────▼────────────────────────────┐    │
        │  │ │                                                         │    │
        │  │ │                                                         │    │
        │  │ │                                                         │    │
        │  │ │               Mach message body + trailer               │    │
        │  │ │                                                         │    │
        │  │ │                                                         │    │
        ╰─▶│ │                                                         │    │
           │ ├─────────────────────────────────────────────────────────┤    │
           │ │                     (unused space)                      │    │
           │ ├─────────────────────────────────────────────────────────┤ ╮  │
           │ │                                                         │ │  │
           │ │             Mach message auxiliary payload              │ │◀─╯
           │ │                                                         │ │
           ╰ └─────────────────────────────────────────────────────────┘ ╯
```

Note that there can be unused space in the pure data body due to the fact that
the size of user and kernel descriptors aren't the same and the kernel has to
anticipate for the "worse" size change possible.

### `IKM_TYPE_KDATA_OOL`: legacy linear layout

In this layout, the entire Mach message is allocated out of line in a single
linear allocation. This is a legacy representation that is now only used for
DriverKit replies, with a fixed size of 0x17c0 bytes. Note that because of this,
there is never auxiliary data in this form.

This layout should no longer be used otherwise, as it mixes kernel pointers and
user controlled data in the same allocation.

```
             ┌─────────────────────────────────────────────────────────┐
             │                                                         │
             │                  ... header fields ...                  │
             │                                                         │
             ├─────────────────────────────────────────────────────────┤
             │ ikm_aux_size                                        (0) │
             ├─────────────────────────────────────────────────────────┤
             │                                                         │
             │               ... more header fields ...                │
             │                                                         │
             ├─────────────────────────────────────────────────────────┤
             │ ikm_type                           (IKM_TYPE_KDATA_OOL) │
             ├─────────────────────────────────────────────────────────┤
             │                                                         │
             │                                                         │
             │                                                         │
             │                                                         │
             │                     (unused space)                      │
             │                                                         │
             │                                                         │
             │                                                         │
             │                                                         │
             ├─────────────────────────────────────────────────────────┤
             │ ikm_kdata                                              ─┼──╮
             │ ikm_udata                                        (NULL) │  │
        ╭────┼ ikm_kdata_size                                          │  │
        │    │ ikm_udata_size                                      (0) │  │
        │    └─────────────────────────────────────────────────────────┘  │
        │                                                                 │
        │                                 ╭───────────────────────────────╯
        │                                 │
        │  ╭ ┌────────────────────────────▼────────────────────────────┐
        │  │ │                                                         │
        │  │ │                                                         │
        │  │ │            Mach message header + descriptors            │
        │  │ │                                                         │
        │  │ │                                                         │
        │  │ ├─────────────────────────────────────────────────────────┤
        │  │ │                                                         │
        │  │ │                                                         │
        │  │ │                                                         │
        ╰─▶│ │               Mach message body + trailer               │
           │ │                                                         │
           │ │                                                         │
           │ │                                                         │
           │ ├─────────────────────────────────────────────────────────┤
           │ │                     (unused space)                      │
           ╰ └─────────────────────────────────────────────────────────┘
```

### `IKM_TYPE_ALL_OOL`: external allocations for both kernel data and pure data

In this layout, the "pure" data of the Mach message (its body, trailer, and
auxiliary payload) is allocated out of line like for the `IKM_TYPE_UDATA_OOL`
layout, however unlike this layout, the Mach message header and descriptors are
also allocated out of line, this way:

```
             ┌─────────────────────────────────────────────────────────┐
             │                                                         │
             │                  ... header fields ...                  │
             │                                                         │
             ├─────────────────────────────────────────────────────────┤
             │ ikm_aux_size                                            ┼─────╮
             ├─────────────────────────────────────────────────────────┤     │
             │                                                         │     │
             │               ... more header fields ...                │     │
             │                                                         │     │
             ├─────────────────────────────────────────────────────────┤     │
             │ ikm_type                             (IKM_TYPE_ALL_OOL) │     │
             ├─────────────────────────────────────────────────────────┤     │
             │                                                         │     │
             │                                                         │     │
             │                                                         │     │
             │                                                         │     │
             │                     (unused space)                      │     │
             │                                                         │     │
             │                                                         │     │
             │                                                         │     │
             │                                                         │     │
             ├─────────────────────────────────────────────────────────┤     │
             │ ikm_kdata                                              ─┼─╮   │
             │ ikm_udata                                              ─┼─┼─╮ │
        ╭────┼ ikm_kdata_size                                          │ │ │ │
      ╭─┼────┼ ikm_udata_size                                          │ │ │ │
      │ │    └─────────────────────────────────────────────────────────┘ │ │ │
      │ │                                                                │ │ │
      │ │                                 ╭──────────────────────────────╯ │ │
      │ │                                 │                                │ │
      │ │  ╭ ┌────────────────────────────▼────────────────────────────┐   │ │
      │ │  │ │                                                         │   │ │
      │ │  │ │                                                         │   │ │
      │ ╰─▶│ │            Mach message header + descriptors            │   │ │
      │    │ │                                                         │   │ │
      │    │ │                                                         │   │ │
      │    ╰ └─────────────────────────────────────────────────────────┘   │ │
      │                                                                    │ │
      │                                   ╭────────────────────────────────╯ │
      │                                   │                                  │
      │    ╭ ┌────────────────────────────▼────────────────────────────┐     │
      │    │ │                                                         │     │
      │    │ │                                                         │     │
      │    │ │                                                         │     │
      │    │ │               Mach message body + trailer               │     │
      │    │ │                                                         │     │
      │    │ │                                                         │     │
      ╰───▶│ │                                                         │     │
           │ ├─────────────────────────────────────────────────────────┤     │
           │ │                     (unused space)                      │     │
           │ ├─────────────────────────────────────────────────────────┤ ╮   │
           │ │                                                         │ │   │
           │ │             Mach message auxiliary payload              │ │◀──╯
           │ │                                                         │ │
           ╰ └─────────────────────────────────────────────────────────┘ ╯
```

Note that there can be unused space in the pure data body due to the fact that
the size of user and kernel descriptors aren't the same and the kernel has to
anticipate for the "worse" size change possible.

## Signing

IPC Kmsg have been the bread and butter of kernel exploitation for a decade,
due to how reachable it is, and how flexible its state machine is.

In order to reduce how appetizing this is, IPC kmsg inside of the kernel
use PAC in order to check the integrity of kernel messages.

### Descriptor signing (Core XNU)

Inline descriptors are very interesting because an attacker can control their
count, content, and disposition at will, which lets them reach a fairly large
amount of primitives.

While messages are in flight in the kernel, the descriptors contain pointers
to various kernel objects. This has been a target of choice for attackers to
improve their early primitives.

In order to make descriptor pointers unattractive, XNU now signs these
descriptors inside the kernel anywhere it uses descriptors, by expanding
the types to form a union between:
- a user type prefixed with `u_`,
- an unsigned pointer variant prefixed with `kext_`,
- a signed pointer (keeping its current name).

For example, here is how a port descriptor type looks like in kernel:

```c
typedef struct {
        union {
                mach_port_t           __ipc_desc_sign("port") name;
                mach_port_t           kext_name;
                mach_port_t           u_name;
        };
        unsigned int                  pad2 : 16;
        mach_msg_type_name_t          disposition : 8;
        mach_msg_descriptor_type_t    type : 8;
        uint32_t                      pad_end;
} mach_msg_port_descriptor_t;
```

resulting in this type layout:

```
0x0000,[  0x10] (struct mach_msg_port_descriptor_t)) {
    0x0000,[   0x8] (anonymous union)) {
        0x0000,[   0x8] (__ptrauth(2,1,427) mach_port_t) name
        0x0000,[   0x8] (mach_port_t) kext_name
        0x0000,[   0x8] (mach_port_t) u_name
    }
    0x0008,[   0x4] (unsigned int : 0x10) pad2
    0x000a,[   0x4] (mach_msg_type_name_t : 0x08) disposition
    0x000b,[   0x4] (mach_msg_descriptor_type_t : 0x08) type
    0x000c,[   0x4] (uint32_t) pad_end
}
```

### Descriptor signing (kernel extensions)

On macOS where kernel extensions exist and use the arm64e slice,
the ABI is already set and signing kernel pointers would be an ABI break.

Fortunately, IPC kmsgs are not ABI, and the way kernel extensions
interact with Mach is via three calls:
- `mach_msg_send_from_kernel` to perform "one way" messaging,
- `mach_msg_rpc_from_kernel` to perform query/reply messaging,
- `mach_msg_destroy_from_kernel` to dispose of the rights in a message buffer.

In order to hide the PAC ABI that XNU uses, these 3 entry points are specialized
for kernel extensions (using symbol names ending in `_proper` for historical
reasons). These entry points propagate that the caller is a kernel extension
to the `ipc_kmsg_get_from_kernel()` or `ipc_kmsg_put_to_kernel()` functions
who are responsible for moving message data between the kernel extension
provided buffers and the `ipc_kmsg_t` structures.

These kext buffers tend to be short lived, which means that the vast majority
of in flight messages have signed descriptors at rest.

### Header/trailer signing

Unlike descriptors which actually do not really tend to be manipulated by code
a lot but more used as a serialization format, `mach_msg_header_t` is used
pervasively, (mem)copied around, and a very well established ABI. Signing
its port pointers would be extremely desirable, but also an ABI nightmare.

Instead, the header (and trailer) are signed with gPAC as soon as headers
are formed/copied-in. This signature covers the message descriptor count,
and is diversified with the kmsg address.

When a message is about to be used to return information to userspace in any
shape or form, the signature is being validated and the descriptor count
of the message returned as a side effect of checking the signature. This
descriptor count is then used as the source of truth for indexing in
descriptors, which should dramatically reduce tampering risks.

