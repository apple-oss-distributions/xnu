Mach IPC Port Types
==========================

This document is not a tutorial on or encouragement to write new mach code, but
serves as documentation for darwin engineers to map security policies to ports
used in the lower layers of the OS. See the warning/disclaimer at
https://at.apple.com/dont_write_new_mach_code and come talk to us in
#help-darwin before using the knowledge contained here.

# Port Types
A port can have exactly one of the following types, and we describe what each
port means from the userspace perspective, including what you are/aren't allowed
to do with a particular port and how to construct it. The source of truth for
security policies in the kernel is the `ipc_policy_array` in `ipc_policy.c`

### IOT_PORT_SET
#### Creation
- `mach_port_allocate(... MACH_PORT_RIGHT_PORT_SET ...)`
#### Behavior/Usage
- Allows you to monitor an entire set of ports for messages at once, similar to
`select(2)`
#### Security Restrictions
- No special security restrictions on this port

### IOT_PORT
#### Creation
- Your standard port that you obtain through the port allocation APIs if you
don't pass any special flags.
#### Behavior/Usage
- Sends traditional mach messages and is generally associated with "raw mach" -
new code generally should not use these.
#### Security Restrictions
- No special security restrictions on this port

### IOT_SERVICE_PORT
#### Creation
- pass `MPO_SERVICE_PORT` with `MPO_ENFORCE_REPLY_PORT_SEMANTICS` to `mach_port_construct` (or use `MPO_STRICT_SERVICE_PORT`)
#### Behavior/Usage
- Used by `launchd` as the port which drives the launch-on-demand behavior of
services/daemons on the system. Clients lookup the service port for some service
using `bootstrap_lookup` and then can form a connection with that service.  -
`launchd` reclaims these ports when the process owning the service port is
killed so that the service port is always active.
#### Security Restrictions
- This is the "hardened" version of the service port which has various security
policies such as immovabile receive right and enforced reply port semantics.  -
`launchd` enforces that all platform binary services use this version of the
service port (as opposed to the `WEAK` version below), and allows third parties
to opt into this following the completion of rdar://137633308. See the `launchd`
documentation for more details about how to opt into this restriction - The
kernel will enforce that platform restrictions binaries receive this version of the service
port following completion of rdar://133304899.

### IOT_BOOTSTRAP_PORT
#### Creation
- pass `MPO_SERVICE_PORT` to `mach_port_construct` with `mspi_domain_type`
equals `XPC_DOMAIN_PORT`
#### Behavior/Usage
- Should be created by `launchd` only and should be the system-wide bootstrap
port for the `bootstrap_lookup` service.
#### Security Restrictions
- The receive right of this port should be immovable and should always belong to
`launchd`. Port destroy notification is not allowed, and reply port semantics are
enforced for this port.

### IOT_WEAK_SERVICE_PORT
#### Creation
- pass `MPO_SERVICE_PORT` to `mach_port_construct` (without `MPO_ENFORCE_REPLY_PORT_SEMANTICS`)
#### Behavior/Usage
- Same feature set and usage as `IOT_SERVICE_PORT` above, the only difference is
the associated security policy.
#### Security Restrictions
- No security hardening. Launchd entirely controls which processes get the weak
vs. "strong" service ports, and the kernel will eventually enforce that launchd
has created the right kind of port for hardened processes. See `launchd`
documentation for more info.

### IOT_CONNECTION_PORT
#### Creation
- pass `MPO_CONNECTION_PORT` to `mach_port_construct`
#### Behavior/Usage
- A connection port models an established connection between two parties,
commonly between a client and a service, but it's also generalizable to peer
connections.
#### Security Restrictions
- We assume that the handshake mechanism to create the connection between these
two parties is sufficiently hardened, so the security boundary we want to
protect here is that the connection and its replies are contained between the
two parties. To accomplish this the connection port is marked as immovable
receive and requires reply port semantics, both of which combined kills man in
the middle attacks at this layer.

### IOT_CONNECTION_PORT_WITH_PORT_ARRAY
#### Creation
- pass `MPO_CONNECTION_PORT_WITH_PORT_ARRAY` to `mach_port_construct`
#### Behavior/Usage
- Serves as a connection port, however does not have the mechanics/behaviors
of `IOT_CONNECTION_PORT`. Unlike other port types, this type is allowed to
receive out-of-line port array descriptors (`MACH_MSG_OOL_PORTS_DESCRIPTOR`)
in platform binaries. For enhanced security v2, it's the only port type that
is allowed to receive `MACH_MSG_OOL_PORTS_DESCRIPTOR`.
- In addition to that, we enforce the following restrictions on messages with
`MACH_MSG_OOL_PORTS_DESCRIPTOR` descriptor (also, only for platform binaries):
  1. a message cannot carry more than ONE single OOL port array.
  2. the only allowed disposition is `MACH_MSG_TYPE_COPY_SEND`.

#### Security Restrictions
- Can only be created by binaries that have the
`com.apple.developer.allow-connection-port-with-port-array` entitlement.

### IOT_EXCEPTION_PORT
#### Creation
- pass `MPO_EXCEPTION_PORT` to `mach_port_construct`
#### Behavior/Usage
- Used in mach exception handling, if you have the entitlement
`com.apple.security.only-one-exception-port` then you must use the
`task_register_hardened_exception_handler` workflow which only accepts this type
of port. Otherwise the historical, non-hardened exception handling workflow
using `task_set_exception_ports` accepts either a standard `IOT_PORT` or an
`IOT_EXCEPTION_PORT`.
#### Security Restrictions
- This port must be immovable receive when using the hardened exception flow to
ensure that exceptions cannot be diverted and handled/stalled outside of the
process generating them.

## Reply Ports
- If your port type requires reply port semantics, then you must use one of the
following reply port types as the reply field (`msgh_local_port`) when sending a
message to `p`. See [reply port
defense](ipc_security_concepts.md#reply-port-defense) for more details.

### IOT_REPLY_PORT
#### Creation
- pass `MPO_REPLY_PORT` to `mach_port_construct`
#### Behavior/Usage
- A reply port exists in your space, and you use it to receive replies from
clients in response to messages that you send them. It's intended to model
synchronous IPC where you send a message to a peer and expect a single message
in response.
#### Security Restrictions
- Reply ports guarantee that a reply comes back to you from the person you are
messaging - in other words, it counters person-in-the-middle attacks. It
accomplishes this by using send-once rights to ensure that *exactly* one reply
from the destination will come back to your reply port, which is marked as
immovable receive, and the send right must be a make-send-once so that it cannot
be moved after its creation.

### IOT_SPECIAL_REPLY_PORT
#### Creation
- Created by the kernel: libxpc and dispatch call into
`thread_get_special_reply_port` to obtain the send/receive right for this
thread-specific port.
#### Behavior/Usage
- Has the same properties as a reply port above, but this is used by libxpc and
dispatch to provide turnstile/importance inheritance capabilities.
#### Security Restrictions
- same as reply ports above

### IOT_WEAK_REPLY_PORT
#### Creation
- pass `MPO_WEAK_REPLY_PORT` to `mach_port_construct`
#### Behavior/Usage
- This has the mechanics of a normal `IOT_PORT` in that it has no special
behaviors/usage/restrictions, but it counts as reply port for the purposes of
enforced reply port semantics.
#### Security Restrictions
- None, this requires special entitlements in platform restrictions binaries.

# Violations of Port Security Policies

If you violate the security policies outlined above, expect to receive a
`mach_port_exc_guard` exception, which will either emit telemetry or fatally
crash your process depending on the enforcement level of the security violation.
See [List of fatal Mach IPC guard
exceptions](guard_exceptions.md#List-of-fatal-Mach-Port-Guard-Exceptions) or
at.apple.com/exc-guard for more details.
