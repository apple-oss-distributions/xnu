Mach Port Guard exceptions
==========================

Mach Port Guard exceptions are used to denote various misuses of Mach IPC.
This document covers their meaning, as well as hints on how to debug issues.

## Anatomy of a Mach Port Guard Exception

Mach Port Guard Exception is delivered via a Mach exception. These constructs
are described in the `<kern/exc_guard.h>` header:

```
/*
 * Mach port guards use the exception codes like this:
 *
 * code:
 * +-----------------------------+----------------+-----------------+
 * |[63:61] GUARD_TYPE_MACH_PORT | [60:32] flavor | [31:0] target   |
 * +-----------------------------+----------------+-----------------+
 *
 * subcode:
 * +----------------------------------------------------------------+
 * |[63:0] payload                                                  |
 * +----------------------------------------------------------------+
 */

#define GUARD_TYPE_MACH_PORT    0x1      /* guarded mach port */
```

This description is mostly useful to implementors of a Mach exception handler,
most clients will instead receive a crash log where ReportCrash tried its best
to decode the message above, however sometimes it lags behind the introduction
of new guards, and this document helps decoding the matrix.

A properly decoded crashlog will contain information like this:

```
Exception Type: EXC_GUARD (SIGKILL)
Exception Subtype: GUARD_TYPE_MACH_PORT
Exception Message: INVALID_NAME on mach port 9987 (guarded with 0x0000000000000000)
Exception Codes: 0x0000000000002703, 0x0000000000000000
Termination Reason: GUARD 2305845208236959491
```

However, in some cases, the decoding is partial and one needs to decode
these by hand. In all cases, ReportCrash will always recognize Mach Port Guards,
and the `Exception Codes` and `Termination Reason` are the lines we need,
in terms of the kernel defined fields, they follow this template:

```
Exception Codes: $(code.target), $(subcode.payload)
Termination Reason: GUARD $(code)
```

When applying it to the example above, we can see that:

- the code is `2305845208236959491 == 0x2000020000002703` which decodes into
  `{ guard_type: GUARD_TYPE_MACH_PORT, flavor: 0x200, target: 0x2703 }`
- the payload is `0`.


## Typical Mach Port bugs, and how to reason about them

In this section, we will describe the most common cases of Mach IPC issues
that are reported by Mach Port Guard exceptions, and how to reason about them.

### Port right mismanagement

This is by far the most common source of issues with Mach IPC. Unlike file
descriptors which have a really simple lifecycle (you destroy them with
`close()`), Mach ports have several associated rights that must be managed
properly.

Port right mismanagement usually happens when some subsystem has a dangling
reference to a Mach port name that it has already destroyed, and keeps using it.
This is the analogous to a use-after-free for allocated memory.

The most common sources of issues are:

- confusions in accounting of the receive right and send rights, due to the
  arcane `mach_port_mod_refs` API being misused. We recommend using
  `mach_port_destruct()` for receive rights, and `mach_port_deallocate()`
  for send or send-once rights.

- dangling port names: the port name management was correct, but the reference
  to the port wasn't reset to `MACH_PORT_NULL`, leading to eventual over-releases.

- threading safety related issues where the port management isn't properly
  synchronized.


## List of fatal Mach Port Guard Exceptions

Some of the exceptions are always fatal (hitting them will cause the process to
be terminated) regardless of the process kind.


### `kGUARD_EXC_DESTROY` 0x00000001

- **ReportCrash Name**: DESTROY,
- **Target meaning**: the mach port name the incorrect operation targets,
- **Payload meaning**: the correct value of the context guarding the Mach Port.

This exception is thrown when a guarded receive right is being destroyed
with an incorrect or missing context presented by the caller.

Receive rights can be guarded with a caller chosen context via mechanisms such
as:

- `mach_port_guard()` being called,
- the right being made using the `MPO_CONTEXT_AS_GUARD` flag of
  `mach_port_construct()`,
- the usage of a guarded port descriptor in a Mach message.


Examples of such ports are the receive rights used for XPC Connections,
hitting such a bug usually is a sign of port right mismanagement.


### `kGUARD_EXC_MOD_REFS` 0x00000002

- **ReportCrash Name**: `OVER_DEALLOC` or `MOD_REFS`,
- **Target meaning**: the mach port name the incorrect operation targets,
- **Payload meaning**:
   - `0x0100000000000000`: a `deallocate` function,
   - `0x0200000000000000`: a `destroy` function,
   - `0x0300000000000000`: via the side effect of a message send (port copyin).

This exception is thrown when the last send right of a pinned mach port is being
destroyed. Pinned ports must never have a send right count going to zero in a
given IPC space.

Examples of such ports are thread and task control ports.  This is usually a
sign of port-right mismanagement.


### `kGUARD_EXC_INVALID_OPTIONS` 0x00000003

- **ReportCrash Name**: `INVALID_OPTIONS`,
- **Target meaning**: the message ID of a rejected message via the legacy
  `mach_msg_trap()` or zero,
- **Payload meaning**: the kernel sanitized (see `ipc_current_user_policy()`)
  for the rejected `mach_msg2()` call.

There are several policies dictating the shape of options passed to calls of the
`mach_msg()` family. These correspond to programming mistakes.


### `kGUARD_EXC_SET_CONTEXT` 0x00000004

- **ReportCrash Name**: `SET_CONTEXT`,
- **Target meaning**: the mach port name the incorrect operation targets,
- **Payload meaning**: the value of the context guarding the Mach Port.

This exception is thrown when `mach_port_set_context()` or
`mach_port_swap_guard()` is used against a Mach Port using a strict guard (a
Mach Port constructed with the `MPO_STRICT | MPO_CONTEXT_AS_GUARD` flags).

Examples of such ports are the client-side receive right for XPC connections.
This is usually a sign of port right mismanagement.


### `kGUARD_EXC_THREAD_SET_STATE` 0x00000005

- **ReportCrash Name**: N/A,
- **Target meaning**: exception flavor,
- **Payload meaning**:
  - `0x0100000000000000`: tss called from userspace exception handler,
  - `0x0200000000000000`: tss with flavor that modifies cpu registers,
  - `0x0300000000000000`: tss called from fatal PAC exception.

This exception is thrown when a process is trying to use the
`thread_set_state()` interface, or any interface leading to it (such as trying
to change thread state via replying to a Mach exception message), and that this
is disallowed by policy for this process.


### `kGUARD_EXC_EXCEPTION_BEHAVIOR_ENFORCE` 0x00000006

- **ReportCrash Name**: N/A,
- **Target meaning**: the new exception behavior,
- **Payload meaning**: the exception mask.

This exception is thrown when a process is trying to register an exception port
for a behavior not using a task identity port, and that this is disallowed by
policy for this process.


### `kGUARD_EXC_SERVICE_PORT_VIOLATION_FATAL` 0x00000007

- **ReportCrash Name**: N/A,
- **Target meaning**: always zero,
- **Payload meaning**: violator port name.

This exception is thrown when a process copyin a service port receive right
from process other than launchd.

### `kGUARD_EXC_UNGUARDED` 0x00000008

- **ReportCrash Name**: UNGUARDED,
- **Target meaning**: the mach port name the incorrect operation targets,
- **Payload meaning**: always zero.

This exception is thrown when a process is trying to perform an operation (such
as `mach_port_unguard()` on a port that isn't guarded.

This is usually a sign of port right mismanagement.

### `kGUARD_EXC_KOBJECT_REPLY_PORT_SEMANTICS` 0x00000009

- **ReportCrash Name**: KOBJECT\_REPLY\_PORT\_SEMANTICS,
- **Target meaning**: the mach port name the incorrect operation targets,
- **Payload meaning**: always zero.

This exception is thrown when a hardened process is trying to send a message
to a kobject port without using an `IOT_REPLY_PORT` to receive the reply.

### `kGUARD_EXC_REQUIRE_REPLY_PORT_SEMANTICS` 0x0000000a

- **ReportCrash Name**: `REQUIRE_REPLY_PORT_SEMANTICS`,
- **Target meaning**: the mach port name the incorrect operation targets,
- **Payload meaning**: 1 if the port is a bootstrap port, 0 otherwise.

This exception is thrown when a caller is violating the reply port semantics in
a process where this is disallowed by policy. This is used to gather telemetry
around violators pending enforcement in a future release.

This is usually a sign of a programming mistake (violation of the reply port
semantics rules).

### `kGUARD_EXC_INCORRECT_GUARD` 0x00000010

- **ReportCrash Name**: `INCORRECT_GUARD`,
- **Target meaning**: the mach port name the incorrect operation targets,
- **Payload meaning**: the value of the context guarding the Mach Port.

This exception is thrown when a process is attemtping a guarded operation but
passed a context to the call that doesn't match the context actually guarding
this port.

This is usually a sign of port right mismanagement.


### `kGUARD_EXC_IMMOVABLE` 0x00000020

- **ReportCrash Name**: `ILLEGAL_MOVE`,
- **Target meaning**: the mach port name the incorrect operation targets,
- **Payload meaning**: (target port type << 32) | disposition.

This exception is thrown when a process is attempting to move a port right,
and this has been disallowed by policy for this port type and process.

This is usually a programming mistake (or legacy code that hasn't been updated
to the most recent Mach IPC policies).


### `kGUARD_EXC_STRICT_REPLY` 0x00000040

This exception is thrown for reply port semantics mistakes, if the
`enforce_strict_reply` boot-arg is set.  As this is not a default config at this
point, and that this is likely going to be phased out in favor of tracking reply
ports at the port type level, this is left mostly undocumented on purpose.


### `kGUARD_EXC_INVALID_NOTIFICATION_REQ` 0x00000041

- **ReportCrash Name**: INVALID\_NOTIFICATION\_REQ,
- **Target meaning**: IOT_ port type that you are trying to arm the notification on
- **Payload meaning**: The type of notification you were registering for

This exception is thrown when a process is trying to arm a notification
on a port type that disallows such requests.


### `kGUARD_EXC_INVALID_MPO_ENTITLEMENT` 0x00000042

- **ReportCrash Name**: `INVALID_MPO_ENTITLEMENT`,
- **Target meaning**: The `mpo_flags_t` that were passed into `mach_port_construct`

This exception is thrown when you try to construct a mach port type that is disallowed
for your process based on entitlements.

### `kGUARD_EXC_DESCRIPTOR_VIOLATION` 0x00000043

- **ReportCrash Name**: `DESCRIPTOR_VIOLATION`,
- **Target meaning**: The IPC space policy.
- **Payload meaning**:
   - `(violation_type << 56) | aux` : the violation's type, among with associated metadata

This exception is thrown when a process attempts to violate any
Mach message descriptor policies.

### `kGUARD_EXC_MSG_FILTERED` 0x00000080

- **ReportCrash Name**: `MSG_FILTERED`,
- **Target meaning**: the mach port name the incorrect operation targets,
- **Payload meaning**: the message ID of the filtered message.

This exception is thrown when a process is not allowed to send the specified
message due to sandboxing, and that a hard failure has been requested by either
the client or the Sandbox.


## List of optionally fatal Mach Port Guard Exceptions

Some of the exceptions are optionally fatal. Hitting them will only terminate
the process when it is opted for a hardened Mach IPC environment. Such processes
are:

- platform binaries,
- processes with a browser entitlement (`com.apple.developer.web-browser-engine.*`).

The `task_exc_guard_default` boot-arg can be used to change these defaults.

Note: using the `amfi=-1` or similar boot-args will make all processes appear to
be platform binaries, which in turn will turn a lot of bugs in 3p software into
hard crashes. Most notably at this time, electron apps cause several guard
exceptions in the Mach IPC and VM world. This is not a supported configuration.


### `kGUARD_EXC_INVALID_RIGHT` 0x00000100

- **ReportCrash Name**: `INVALID_RIGHT`,
- **Target meaning**: the mach port name the incorrect operation targets,
- **Payload meaning**:
   - `0x01 << 56`                              : `ipc_port_translate_receive` failed,
   - `(0x02 << 56) | (right << 32) | ie_bits`  : `ipc_right_delta` failed,
   - `(0x03 << 56) | ie_bits`                  : `ipc_right_destruct` failed,
   - `(0x04 << 56) | (reason << 32) | ie_bits` : `ipc_right_copyin` failed,
   - `(0x05 << 56) | ie_bits`                  : `ipc_right_dealloc` failed,
   - `(0x06 << 56) | (otype << 32) | io_type`  : `ipc_right_deallocate_kernel` failed,
   - `(0x07 << 56) | ie_bits`                  : invalid port in `ipc_object_translate_port_pset`,
   - `(0x08 << 56) | ie_bits`                  : invalid pset in `ipc_object_translate_port_pset`.

This exception is thrown when an operation is targetting a port which rights do
not match the caller's expectations. Examples of such mistakes are:

- performing an operation expecting a port-set name, but passing a port name
  instead,
- trying to receive a message and not owning the receive right for it.

These correspond to cases leading to the `KERN_INVALID_RIGHT` or
`KERN_INVALID_CAPABILITY` error codes of most Mach IPC interfaces.

This is usually a sign of port right mismanagement.


### `kGUARD_EXC_INVALID_NAME` 0x00000200

- **ReportCrash Name**: `INVALID_NAME`,
- **Target meaning**: the mach port name the incorrect operation targets,
- **Payload meaning**: always zero.

This exception is thrown when an operation is targetting a name for which
the caller holds no right.

These correspond to cases leading to the `KERN_INVALID_NAME` error code of most
Mach IPC interfaces.

This is usually a sign of port right mismanagement.


### `kGUARD_EXC_INVALID_VALUE` 0x00000400

- **ReportCrash Name**: `INVALID_VALUE`,
- **Target meaning**: the mach port name the incorrect operation targets,
- **Payload meaning**:
   - `(0x01 << 56) | (type << 32)  | size`                     : invalid trailer in `mach_port_peek`,
   - `(0x02 << 56) | (right << 32) | (delta << 16) | ie_bits`  : `ipc_right_delta` failed,
   - `(0x03 << 56) | (srdelta << 32) | ie_bits`                : `ipc_right_destruct` failed,

This exception is thrown when:

- the caller is trying to apply a delta to the number of send rights of a port
  name, and this would overflow the send right count, which is usually a sign of
  port right mismanagement,

- the trailer related arguments to `mach_port_peek()` are invalid, which is
  typicaly a programming mistake.

These correspond to cases leading to the `KERN_INVALID_VALUE` error code of most
Mach IPC interfaces.


### `kGUARD_EXC_INVALID_ARGUMENT` 0x00000800

- **ReportCrash Name**: `INVALID_ARGUMENT`,
- **Target meaning**: the mach port name the incorrect operation targets,
- **Payload meaning**: the correct value of the context guarding the Mach Port.

This exception is thrown when a caller is trying to guard an already guarded
port. This should really have been named `kGUARD_EXC_ALREADY_GUARDED`.

This is usually a sign of port right mismanagement.


### `kGUARD_EXC_KERN_FAILURE` 0x00004000

- **ReportCrash Name**: `KERN_FAILURE`,
- **Target meaning**: always zero,
- **Payload meaning**:
   - `0x0100000000000000`: task other than launchd arm pd on service ports,
   - `0x0200000000000000`: not using IOT_NOTIFICATION_PORT for pd notification,
   - `0x0300000000000000`: notification port not owned by launchd,
   - `0x0400000000000000`: register multiple pd notification.

This exception is thrown when a caller is trying to request a port-destroyed
notification that is disallowed by system policy.  This should really have been
named `kGUARD_EXC_INVALID_PDREQUEST`.

This is usually a sign of port right mismanagement.


### `kGUARD_EXC_SEND_INVALID_REPLY` 0x00010000

- **ReportCrash Name**: `SEND_INVALID_REPLY`,
- **Target meaning**: the mach port name the incorrect operation targets,
- **Payload meaning**: (reply port ie bits << 32) | disposition.

This exception is thrown when a caller is trying to send a message whose reply
port (the `msgh_local_port` field of a Mach message) violates policies around
reply ports or its disposition.

This is usually a sign of port right mismanagement.


### `kGUARD_EXC_SEND_INVALID_RIGHT` 0x00020000

- **ReportCrash Name**: `SEND_INVALID_RIGHT`,
- **Target meaning**: the mach port name the incorrect operation targets,
- **Payload meaning**:
   - `(0x01 << 56) | disposition`: copyin port descriptor failed,
   - `(0x02 << 56) | disposition`: copyin ool port descriptor failed,
   - `(0x03 << 56) | disposition`: copyin guarded port descriptor failed,

This exception is thrown when a caller is trying to send a message where one of
the port descriptors denotes a right that doesn't match the requested
disposition (for example, a make-send disposition for a port where the process
doesn't own a receive right).

This is usually a sign of port right mismanagement.


### `kGUARD_EXC_SEND_INVALID_VOUCHER` 0x00040000

- **ReportCrash Name**: `SEND_INVALID_VOUCHER`,
- **Target meaning**: the mach port name the incorrect operation targets,
- **Payload meaning**: disposition of the voucher port.

This exception is thrown when a caller is trying to send a message whose voucher
port (the `msgh_voucher_port` field of a Mach message) violates policies around
voucher ports or its disposition.

This is usually a sign of port right mismanagement.


### `kGUARD_EXC_RCV_INVALID_NAME` 0x00080000

- **ReportCrash Name**: `RCV_INVALID_NAME`,
- **Target meaning**: the mach port name the incorrect operation targets,
- **Payload meaning**: always zero.

This exception is thrown when a caller is trying to receive a message on a mach
port name for which it doesn't hold a port-set or receive right.

This is usually a sign of port right mismanagement.


## List of soft Mach Port Guard Exceptions

Some of the exceptions are never fatal (hitting them will only emit a simulated
crash log, and the process will keep going).


### `kGUARD_EXC_RCV_GUARDED_DESC` 0x00100000

- **ReportCrash Name**: `RCV_GUARDED_DESC`,
- **Target meaning**: the mach port name the incorrect operation targets,
- **Payload meaning**: always zero.

This exception is thrown when a caller is trying to receive a message containing
guarded port descriptors and it hasn't indicated that it knows how to parse them
(by passing the `MACH_RCV_GUARDED_DESC` flag to `mach_msg()`).

The usage of guarded port descriptor is a protocol agreement between the client
and the server, and a disagreement here is a programming mistake.

This guard is only enabled on development kernels at this time.

### `kGUARD_EXC_MOVE_WEAK_REPLY_PORT` 0x00100004

- **ReportCrash Name**: N/A,
- **Target meaning**: the mach port name of the weak reply port,
- **Payload meaning**: always zero.

This exception is thrown when a process opted for enhanced security v2 moves
the receive right of a weak reply port out of its ipc space.

### `kGUARD_EXC_REPLY_PORT_SINGLE_SO_RIGHT` 0x00100005

- **ReportCrash Name**: N/A,
- **Target meaning**: the mach port name of the reply port,
- **Payload meaning**: the copyin reason.

This exception is thrown when a process attempts to create more than
one single send-once right for a reply port. Reply ports are not allowed
to extend more than one single send-once right at any given moment.

### `kGUARD_EXC_INVALID_NOTIFICATION_PORT` 0x00100006

- **ReportCrash Name**: N/A,
- **Target meaning**: port name
- **Payload meaning**: the IOT_ port type of the notification port

This exception is thrown when a process attempts to register for a notification
(such as port-destroyed, dead-name, or no-senders) using a port type that is
not allowed to receive notifications.

This is usually a programming mistake where the wrong port type was used when
requesting notifications via `mach_port_request_notification()`.

### `kGUARD_EXC_CV_NOTIFICATION_PORT_REQ` 0x00100008

- **ReportCrash Name**: N/A,
- **Target meaning**: port name
- **Payload meaning**: the IOT_ port type of the notification port

This exception is thrown when a containment vessel process attempts to register
for a notification (such as port-destroyed, dead-name, or no-senders) without
using the `IOT_NOTIFICATION_PORT` port type.

Containment vessels are hardened processes that must use `IOT_NOTIFICATION_PORT`
for all notification registrations to enforce strict security policies. This is
usually a programming mistake where a containment vessel used a regular port
type instead of `IOT_NOTIFICATION_PORT` when requesting notifications via
`mach_port_request_notification()`.

### `kGUARD_EXC_MACH_EXC_THREAD_SET_STATE` 0x00100007

- **ReportCrash Name**: N/A,
- **Target meaning**: The thread state flavor being set,
- **Payload meaning**: The pid of the process which replied to the mach exception
(0 if audit token was not present)

This exception is thrown when a process attempts to set the thread state
of another process via a reply to a mach exception without proper
entitlements or debugging permissions.

### `kGUARD_EXC_MOD_REFS_NON_FATAL` 0x00200000

- **ReportCrash Name**: `OVERDEALLOC_SOFT`,
- **Target meaning**: the mach port name the incorrect operation targets,
- **Payload meaning**: same as `kGUARD_EXC_MOD_REFS`.

This is the same as `kGUARD_EXC_MOD_REFS`, except that this is delivered as a
soft error.

### `kGUARD_EXC_IMMOVABLE_NON_FATAL` 0x00400000

- **ReportCrash Name**: `ILLEGALMOVE_SOFT`.
- **Target meaning**: the mach port name the incorrect operation targets,
- **Payload meaning**: same as `kGUARD_EXC_IMMOVABLE`.

This is the same as `kGUARD_EXC_IMMOVABLE`, except that this is delivered as a
soft error.

