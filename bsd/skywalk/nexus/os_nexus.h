/*
 * Copyright (c) 2015-2022 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#ifndef _SKYWALK_OS_NEXUS_H_
#define _SKYWALK_OS_NEXUS_H_

#ifdef PRIVATE

#include <stdint.h>
#include <sys/types.h>
#include <sys/cdefs.h>
#include <uuid/uuid.h>
#include <mach/boolean.h>

#ifdef KERNEL_PRIVATE
struct ifnet_interface_advisory;
#endif /* KERNEL_PRIVATE */

struct ifnet_traffic_descriptor_common;
struct ifnet_traffic_rule_action;

/*
 * Nexus terminology and overview.  The relationship between the objects are
 * as follows:
 *
 *	domain --> domain_provider --> nexus_provider --> nexus
 *
 * Skywalk comes with several nexus domains (types).  Each domain has one or
 * more domain providers; the system comes with a built-in (default) domain
 * provider per domain.  Additional domain providers may be attached, but
 * this ability is reserved to kernel subsystems.  The domain specifies the
 * nexus semantics, including the permitted topology, number and definition
 * of ports, memory regions, etc.
 *
 * Each domain provider may have one or more nexus providers registered to it.
 * This allows different parameters (rings, slots, buffer metadata) to be
 * configured on a per-nexus provider basis.
 *
 * Nexus instances can then be allocated based on a registered nexus provider.
 * All instances associated with a given nexus provider share the same set of
 * parameters that are configured for that nexus provider.
 *
 * Channels are then opened to nexus instances.
 */

/*
 * Nexus types.
 *
 * Userland code may only register Nexus providers against the USER_PIPE
 * and FLOW_SWITCH types.  The rest are reserved for kernel subsystems.
 */
typedef enum {
	NEXUS_TYPE_USER_PIPE,           /* pipe (user) */
	NEXUS_TYPE_KERNEL_PIPE,         /* pipe (kernel) */
	NEXUS_TYPE_NET_IF,              /* network interface (kernel) */
	NEXUS_TYPE_FLOW_SWITCH,         /* flow switch (user/kernel) */
#ifdef BSD_KERNEL_PRIVATE
	/*
	 * Monitor nexus isn't directly usable on its own; we just
	 * need a type definition here for it to act as a pseudo
	 * domain provider.
	 */
	NEXUS_TYPE_MONITOR,             /* monitor (user) */
	NEXUS_TYPE_MAX,                 /* this needs to be last */
	NEXUS_TYPE_UNDEFINED = -1,      /* for kernel internal use */
#endif /* BSD_KERNEL_PRIVATE */
} nexus_type_t;

/*
 * Nexus provider name.
 */
typedef uint8_t nexus_name_t[64];

/*
 * Nexus instance port.
 */
typedef uint16_t nexus_port_t;

/*
 * User pipe Nexus has at most two ports: one client and server.
 */
#define NEXUS_PORT_USER_PIPE_CLIENT             0
#define NEXUS_PORT_USER_PIPE_SERVER             1

/*
 * Kernel pipe Nexus has at most one port for the client.
 */
#define NEXUS_PORT_KERNEL_PIPE_CLIENT           0

/*
 * Network Interface Nexus can have any number of ports.
 * Port 0 and 1 are reserved for DEV and HOST. The other ports
 * (2 and above) can be of the types: filter, custom ethertype,
 * or low latency.
 */
#define NEXUS_PORT_NET_IF_DEV                   0
#define NEXUS_PORT_NET_IF_HOST                  1
#define NEXUS_PORT_NET_IF_CLIENT                2

/*
 * Flow switch has its first N ports reserved; the following is the first
 * client usable port.  The last usable depends on the configured number
 * of nexus ports.
 */
#define NEXUS_PORT_FLOW_SWITCH_CLIENT           2

/*
 * Opaque handles.
 */
struct nexus_controller;
struct nexus_attr;

typedef struct nexus_controller         *nexus_controller_t;
typedef struct nexus_attr               *nexus_attr_t;

/*
 * Nexus attribute types.
 */
typedef enum {
	NEXUS_ATTR_TX_RINGS,            /* (g/s) # of transmit rings */
	NEXUS_ATTR_RX_RINGS,            /* (g/s) # of receive rings */
	NEXUS_ATTR_TX_SLOTS,            /* (g/s) # of slots per transmit ring */
	NEXUS_ATTR_RX_SLOTS,            /* (g/s) # of slots per receive ring */
	NEXUS_ATTR_SLOT_BUF_SIZE,       /* (g/s) buffer per slot (bytes) */
	NEXUS_ATTR_SLOT_META_SIZE,      /* (g) metadata per slot (bytes) */
	NEXUS_ATTR_ANONYMOUS,           /* (g/s) allow anonymous clients */
	NEXUS_ATTR_MHINTS,              /* (g/s) memory usage hints */
	NEXUS_ATTR_PIPES,               /* (g/s) # of pipes */
	NEXUS_ATTR_EXTENSIONS,          /* (g/s) extension-specific attr */
	NEXUS_ATTR_IFINDEX,             /* (g) network interface index */
	NEXUS_ATTR_STATS_SIZE,          /* (g) statistics region size (bytes) */
	NEXUS_ATTR_FLOWADV_MAX,         /* (g) max flow advisory entries */
	NEXUS_ATTR_QMAP,                /* (g/s) queue mapping type */
	NEXUS_ATTR_CHECKSUM_OFFLOAD,    /* (g) partial checksum offload */
	NEXUS_ATTR_USER_PACKET_POOL,    /* (g) user packet pool */
	NEXUS_ATTR_ADV_SIZE,            /* (g) nexus advisory region size */
	NEXUS_ATTR_USER_CHANNEL,        /* (g/s) allow user channel open */
	NEXUS_ATTR_MAX_FRAGS,           /* (g/s) max fragments in a packets */
	/*
	 * (g/s) reject channel operations on nexus if the peer has closed
	 * the channel.
	 * The os channel will appear as defunct to the active peer.
	 */
	NEXUS_ATTR_REJECT_ON_CLOSE,
	NEXUS_ATTR_LARGE_BUF_SIZE,     /* (g/s) size of large buffer (bytes) */
} nexus_attr_type_t;

/*
 * XXX: this is temporary and should be removed later.
 */
#define OS_NEXUS_HAS_USER_PACKET_POOL           1

/*
 * Memory usage hint attributes that can be specified for NEXUS_ATTR_MHINTS
 * These can be OR'ed to specified multiple hints
 */
/* No hint, default behaviour */
#define NEXUS_MHINTS_NORMAL     0x0
/* Application expects to access the channels soon */
#define NEXUS_MHINTS_WILLNEED   0x1
/* Application expects low latency for bursty traffic */
#define NEXUS_MHINTS_LOWLATENCY 0x2
/* Application expects high usage of channel memory */
#define NEXUS_MHINTS_HIUSE      0x4

/*
 * Extension attributes.
 */
typedef enum {
	NEXUS_EXTENSION_TYPE_MAXTYPE = 0,
} nexus_extension_t;

/*
 * Nexus queue mapping types.
 */
typedef enum {
	NEXUS_QMAP_TYPE_INVALID = 0,    /* invalid type */
	NEXUS_QMAP_TYPE_DEFAULT,        /* 10:1 mapping */
	NEXUS_QMAP_TYPE_WMM,            /* 802.11 WMM */
} nexus_qmap_type_t;

#define NEXUS_NUM_WMM_QUEUES    4       /* number of WMM access categories */

/*
 * Nexus buffer metadata template.
 *
 * Each Nexus provider implementation will define an overlay of this structure;
 * the top of the structure always begins with this common area.  The contents
 * of this common area, as well as the rest of the per-buffer metadata region
 * are left to the provider to define.
 *
 * This structure is aligned for efficient copy and accesses.
 */
typedef struct nexus_mdata {
	union {
		uuid_t          __uuid;         /* flow UUID */
		uint8_t         __val8[16];
		uint16_t        __val16[8];
		uint32_t        __val32[4];
		uint64_t        __val64[2];
	} __flowid_u;
#define nm_flowid_uuid  __flowid_u.__uuid
#define nm_flowid_val8  __flowid_u.__val8
#define nm_flowid_val16 __flowid_u.__val16
#define nm_flowid_val32 __flowid_u.__val32
#define nm_flowid_val64 __flowid_u.__val64
} nexus_mdata_t __attribute((aligned(8)));

/*
 * Nexus bind flags.
 */
#define NEXUS_BIND_PID          0x1     /* bind to a process ID */
#define NEXUS_BIND_EXEC_UUID    0x2     /* bind to a process exec's UUID */
#define NEXUS_BIND_KEY          0x4     /* bind to a key blob */

/*
 * Maximum length of key blob (in bytes).
 */
#define NEXUS_MAX_KEY_LEN       1024

#ifndef KERNEL
/*
 * User APIs.
 */
#if !defined(_POSIX_C_SOURCE) || defined(_DARWIN_C_SOURCE)
__BEGIN_DECLS
/*
 * Creates a Nexus attribute object.
 *
 * This must be paired with a os_nexus_attr_destroy() on the handle.
 */
extern nexus_attr_t os_nexus_attr_create(void);

/*
 * Clones a Nexus attribute object.  If source attribute is NULL
 * it behaves just like os_nexus_attr_create();
 *
 * This must be paired with a os_nexus_attr_destroy() on the handle.
 */
extern nexus_attr_t os_nexus_attr_clone(const nexus_attr_t attr);

/*
 * Sets a value for a given attribute type on a Nexus attribute object.
 */
extern int os_nexus_attr_set(nexus_attr_t attr,
    const nexus_attr_type_t type, const uint64_t value);

/*
 * Gets a value for a given attribute type on a Nexus attribute object.
 */
extern int os_nexus_attr_get(const nexus_attr_t attr,
    const nexus_attr_type_t type, uint64_t *value);

/*
 * Destroys a Nexus attribute object.
 */
extern void os_nexus_attr_destroy(nexus_attr_t attr);

/*
 * Opens a handle to the Nexus controller.
 *
 * This must be paired with a os_nexus_controller_destroy() on the handle, in
 * order to remove any remaining active providers and free resources.
 */
extern nexus_controller_t os_nexus_controller_create(void);

/*
 * Retrieves the file descriptor associated with the Nexus controller.
 */
extern int os_nexus_controller_get_fd(const nexus_controller_t ctl);

/*
 * Registers a Nexus provider.
 *
 * Anonymous Nexus provider mode implies the freedom to connect to the Nexus
 * instance from any channel client.  Alternatively, named mode requires the
 * Nexus provider to explicitly bind a Nexus instance port to a set of client
 * attributes.  This mode (named) is the default behavior, and is done so to
 * encourage Nexus providers to explicitly know about the clients that it's
 * communicating with.  Specifying anonymous mode can be done via the Nexus
 * attribute NEXUS_ATTR_ANONYMOUS, by setting it to a non-zero value.
 *
 * The client binding attributes include the process ID, the executable UUID,
 * and/or a key blob.  Only a client possessing those will be allowed to open
 * a channel to the Nexus instance port.
 */
extern int os_nexus_controller_register_provider(const nexus_controller_t ctl,
    const nexus_name_t name, const nexus_type_t type, const nexus_attr_t attr,
    uuid_t *prov_uuid);

/*
 * Deregisters a Nexus provider.
 */
extern int os_nexus_controller_deregister_provider(const nexus_controller_t ctl,
    const uuid_t prov_uuid);

/*
 * Creates a Nexus instance of a registered provider.
 */
extern int os_nexus_controller_alloc_provider_instance(
	const nexus_controller_t ctl, const uuid_t prov_uuid, uuid_t *nx_uuid);

/*
 * Destroys a Nexus instance.
 */
extern int os_nexus_controller_free_provider_instance(
	const nexus_controller_t ctl, const uuid_t nx_uuid);

/*
 * Bind a port of a Nexus instance to one or more attributes associated with
 * a channel client: process ID, process executable's UUID, or key blob.
 * This is only applicable to named Nexus provider.
 *
 * Binding to a process ID implies allowing only a channel client with such
 * PID to open the Nexus port.
 *
 * Binding to an executable UUID allows a channel client (regardless of PID
 * or instance) with such executable UUID to open the Nexus port.  When this
 * is requested by a provider that doesn't have the client's executable UUID,
 * a valid client PID must be provided (with the executable UUID zeroed out)
 * in order for the kernel to retrieve the executable UUID from the process
 * and to use that as the bind attribute.  Else, a non-zero executable UUID
 * can be specified (PID is ignored in this case) by the provider.
 *
 * Binding to a key blob allows a channel client possessing the identical
 * key blob to open the Nexus port.  The key blob is opaque to the system,
 * and is left to the Nexus provider to interpret and relay to its client.
 *
 * A Nexus provider must choose to select one or a combination of those
 * attributes for securing access to a port of a named Nexus instance.
 * The provider is also responsible for detecting if the client has gone
 * away, and either to unbind the Nexus instance port indefinitely, or
 * reissue another bind with the new client binding attributes for that
 * same port.  This is to handle cases where the client terminates and
 * is expected to reattach to the same port.
 *
 * All port bindings belonging to a Nexus instance will be automatically
 * removed when the Nexus instance is destroyed.
 */
extern int os_nexus_controller_bind_provider_instance(
	const nexus_controller_t ctl, const uuid_t nx_uuid, const nexus_port_t port,
	const pid_t pid, const uuid_t exec_uuid, const void *key,
	const uint32_t key_len, const uint32_t bind_flags);

/*
 * Unbind a previously-bound port of a Nexus instance.  This is only
 * applicable to named Nexus provider.  A previously-bound Nexus instance
 * port cannot be bound again until this call is issued.
 */
extern int os_nexus_controller_unbind_provider_instance(
	const nexus_controller_t ctl, const uuid_t nx_uuid,
	const nexus_port_t port);

/*
 * Retrieves current Nexus provider attributes into the nexus_attr_t handle.
 */
extern int os_nexus_controller_read_provider_attr(const nexus_controller_t ctl,
    const uuid_t prov_uuid, nexus_attr_t attr);

/*
 * Traffic rules APIs.
 */

/* Persist after controller close. */
#define NXCTL_ADD_TRAFFIC_RULE_FLAG_PERSIST 0x0001
extern int os_nexus_controller_add_traffic_rule(const nexus_controller_t ctl,
    const char *ifname, const struct ifnet_traffic_descriptor_common *td,
    const struct ifnet_traffic_rule_action *ra, const uint32_t flags,
    uuid_t *rule_uuid);

extern int os_nexus_controller_remove_traffic_rule(const nexus_controller_t ctl,
    const uuid_t rule_uuid);

struct nexus_traffic_rule_info {
	uuid_t *nri_rule_uuid;
	char *nri_owner;
	char *nri_ifname;
	struct ifnet_traffic_descriptor_common *nri_td;
	struct ifnet_traffic_rule_action *nri_ra;
	uint32_t nri_flags;
};
/* Return TRUE to continue, FALSE to exit. */
typedef boolean_t (nexus_traffic_rule_iterator_t)(void *,
    const struct nexus_traffic_rule_info *);

extern int os_nexus_controller_iterate_traffic_rules(const nexus_controller_t ctl,
    nexus_traffic_rule_iterator_t itr, void *itr_arg);

/*
 * Destroys a Nexus controller handle.
 */
extern void os_nexus_controller_destroy(nexus_controller_t ctl);
__END_DECLS
#endif  /* (!_POSIX_C_SOURCE || _DARWIN_C_SOURCE) */
#else /* KERNEL */
/*
 * Kernel APIs.
 */
#include <sys/proc.h>
#include <IOKit/skywalk/IOSkywalkSupport.h>

/*
 * Nexus domain provider name.
 */
typedef uint8_t nexus_domain_provider_name_t[64];

/*
 * Opaque handles.
 */
struct nxctl;
struct kern_slot_prop;
struct kern_nexus;
struct kern_nexus_provider;
struct kern_nexus_domain_provider;
struct kern_channel;
struct __kern_channel_ring;
struct __slot_desc;
struct __pbufpool;

typedef struct kern_pbufpool                    *kern_pbufpool_t;
typedef struct kern_nexus                       *kern_nexus_t;
typedef struct kern_nexus_provider              *kern_nexus_provider_t;
typedef struct kern_nexus_domain_provider       *kern_nexus_domain_provider_t;
typedef struct kern_channel                     *kern_channel_t;
typedef struct __kern_channel_ring              *kern_channel_ring_t;
typedef struct __slot_desc                      *kern_channel_slot_t;
typedef struct netif_llink                      *kern_netif_llink_t;
typedef struct netif_qset                       *kern_netif_qset_t;
typedef struct netif_queue                      *kern_netif_queue_t;

/*
 * Domain provider callback routines.
 */

/*
 * @typedef nxdom_prov_init_fn_t
 * @abstract Domain provider initializer callback.
 * @param domprov Domain provider handle.
 * @discussion This will be called after kern_nexus_register_domain_provider().
 * @result Non-zero result will abort the domain provider registration.
 */
typedef errno_t (*nxdom_prov_init_fn_t)(kern_nexus_domain_provider_t domprov);

/*
 * @typedef nxdom_prov_fini_fn_t
 * @abstract Domain provider teardown callback.
 * @param domprov Domain provider handle.
 * @discussion This will happen after kern_nexus_deregister_domain_provider().
 *	A provider must not unload or free resources associated to the domain
 *	provider instance until this callback is invoked.
 */
typedef void (*nxdom_prov_fini_fn_t)(kern_nexus_domain_provider_t domprov);

/*
 * Domain provider init.
 */
struct kern_nexus_domain_provider_init {
	uint32_t                nxdpi_version;          /* current version */
	uint32_t                nxdpi_flags;            /* for future */
	nxdom_prov_init_fn_t    nxdpi_init;             /* required */
	nxdom_prov_fini_fn_t    nxdpi_fini;             /* required */
};

#define KERN_NEXUS_DOMAIN_PROVIDER_VERSION_1            1
#define KERN_NEXUS_DOMAIN_PROVIDER_NETIF                2
#define KERN_NEXUS_DOMAIN_PROVIDER_CURRENT_VERSION      \
	KERN_NEXUS_DOMAIN_PROVIDER_VERSION_1

/*
 * Nexus provider callback routines.
 */

/*
 * @typedef nxprov_pre_connect_fn_t
 * @abstract Nexus provider channel connecting callback.
 * @param nexus_prov Nexus provider handle.
 * @param proc The process associated with the channel.
 * @param nexus The nexus instance.
 * @param channel The channel that has been created and being connected
 *      to the nexus instances's port.
 * @param channel_context Pointer to provider-specific context that can be
 *      associated with the channel.  Upon a successful return, this can
 *      later be retrieved via subsequent calls to kern_channel_get_context().
 * @result Non-zero result will deny the channel from being connected.
 * @discussion This is invoked when a channel is opened to the nexus port.
 *      Upon success, client's ring and slot callbacks will be called.
 *      The channel is not usable until the nxprov_connected_fn_t() is
 *      invoked.  Client must refrain from channel activities until then.
 */
typedef errno_t (*nxprov_pre_connect_fn_t)(kern_nexus_provider_t nexus_prov,
    proc_t proc, kern_nexus_t nexus, nexus_port_t port, kern_channel_t channel,
    void **channel_context);

/*
 * @typedef nxprov_connected_fn_t
 * @abstract Nexus provider channel connected callback.
 * @param nexus_prov Nexus provider handle.
 * @param nexus The nexus instance.
 * @param channel The channel that has been created and fully connected
 *      to the nexus instances's port.
 * @result Non-zero result will deny the channel from being connected.
 * @discussion This is invoked when all ring and slot initializations have
 *      been completed, and that the channel is ready for activities.
 */
typedef errno_t (*nxprov_connected_fn_t)(kern_nexus_provider_t nexus_prov,
    kern_nexus_t nexus, kern_channel_t channel);

/*
 * @typedef nxprov_pre_disconnect_fn_t
 * @abstract Nexus provider channel disconnecting callback.
 * @param nexus_prov Nexus provider handle.
 * @param nexus The nexus instance.
 * @param channel The channel that has been decommissioned.
 * @param channel_context The context that was originally set o the channel
 *      at the time nxprov_pre_connect_fn_t() callback was invoked.
 * @discussion Following this call, all ring and slot finish callbacks will
 *      be invoked.  Client must quiesce all channel activities upon getting
 *      this callback.  The final disconnect completion will be indicated
 *      through a call to the nxprov_disconnected_fn_t() callback.
 */
typedef void (*nxprov_pre_disconnect_fn_t)(kern_nexus_provider_t nexus_prov,
    kern_nexus_t nexus, kern_channel_t channel);

/*
 * @typedef nxprov_disconnected_fn_t
 * @abstract Nexus provider channel disconnect callback.
 * @param nexus_prov Nexus provider handle.
 * @param nexus The nexus instance.
 * @param channel The channel that has been decommissioned.
 * @param channel_context The context that was originally set o the channel
 *      at the time nxprov_pre_connect_fn_t() callback was invoked.
 * @discussion The provider must free any resources associated with the
 *      channel context set at nxprov_pre_connect_fn_t() time, since the channel
 *      instance is no longer valid upon return.
 */
typedef void (*nxprov_disconnected_fn_t)(kern_nexus_provider_t nexus_prov,
    kern_nexus_t nexus, kern_channel_t channel);

/*
 * @typedef nxprov_ring_init_fn_t
 * @abstract Nexus provider ring setup callback.
 * @param nexus_prov Nexus provider handle.
 * @param nexus The nexus instance.
 * @param channel The channel associated with the ring.
 * @param ring The ring that has been prepared.
 * @param is_tx_ring True if ring is used for TX direction, otherwise RX.
 * @param ring_id Ring identification number.
 * @param ring_context Pointer to provider-specific context that can be
 *      associated with the ring.  Upon a successful return, this context
 *      can later be retrieved via subsequent calls to
 *      kern_channel_ring_get_context().
 * @result Non-zero result will abort the ring initialization.
 */
typedef errno_t (*nxprov_ring_init_fn_t)(kern_nexus_provider_t nexus_prov,
    kern_nexus_t nexus, kern_channel_t channel, kern_channel_ring_t ring,
    boolean_t is_tx_ring, void **ring_context);

/*
 * @typedef nxprov_ring_fini_fn_t
 * @abstract Nexus provider ring teardown callback.
 * @param nexus_prov Nexus provider handle.
 * @param nexus The nexus instance.
 * @param channel The channel associated with the ring.
 * @param ring The ring that has been decommissioned.
 * @discussion The provider must free any resources associated with the
 *      ring context set at nxprov_ring_init_fn_t() time, since the ring is
 *      no longer valid upon return.  This call will be issued after all
 *      slots belonging to the ring has been decommisioned, via
 *      nxprov_slot_fini_fn_t().
 */
typedef void (*nxprov_ring_fini_fn_t)(kern_nexus_provider_t nexus_prov,
    kern_nexus_t nexus, kern_channel_ring_t ring);

/*
 * @typedef nxprov_slot_init_fn_t
 * @abstract Nexus provider channel slot setup callback.
 * @param nexus_prov Nexus provider handle.
 * @param nexus The nexus instance.
 * @param ring The ring associated with the slot.
 * @param slot The slot that has been prepared.
 * @param slot_index The index of the slot in the ring.
 * @param slot_prop_addr This has been deprecated; callee must set to NULL.
 * @param slot_context Pointer to provider-specific context that can be
 *      associated with the slot in the given ring.  Upon a successful return,
 *      this context can later be retrieved via subsequent calls to
 *      kern_channel_slot_get_context().
 * @result Non-zero result will abort the slot initialization.
 */
typedef errno_t (*nxprov_slot_init_fn_t)(kern_nexus_provider_t nexus_prov,
    kern_nexus_t nexus, kern_channel_ring_t ring, kern_channel_slot_t slot,
    uint32_t slot_index, struct kern_slot_prop **slot_prop_addr,
    void **slot_context);

/*
 * @typedef nxprov_slot_fini_fn_t
 * @abstract Nexus provider channel slot teardown callback.
 * @param nexus_prov Nexus provider handle.
 * @param nexus The nexus instance.
 * @param ring The ring associated with the slot.
 * @param slot The slot that has been decommissioned.
 * @param slot_index The index of the slot in the ring.
 * @discussion The provider must free any resources associated with the
 *      slot context set at nxprov_slot_init_fn_t() time, since the slot
 *      instance is no longer valid upon return.
 */
typedef void (*nxprov_slot_fini_fn_t)(kern_nexus_provider_t nexus_prov,
    kern_nexus_t nexus, kern_channel_ring_t ring, kern_channel_slot_t slot,
    uint32_t slot_index);

/*
 * @typedef nxprov_sync_tx_fn_t
 * @abstract Nexus provider channel sync (TX) callback.
 * @param nexus_prov Nexus provider handle.
 * @param nexus The nexus instance.
 * @param ring The ring associated with the slot.
 * @param flags See KERN_NEXUS_SYNCF flags.
 */
typedef errno_t (*nxprov_sync_tx_fn_t)(kern_nexus_provider_t nexus_prov,
    kern_nexus_t nexus, kern_channel_ring_t ring, uint32_t flags);

/*
 * @typedef nxprov_sync_rx_fn_t
 * @abstract Nexus provider channel sync (RX) callback.
 * @param nexus_prov Nexus provider handle.
 * @param nexus The nexus instance.
 * @param ring The ring associated with the slot.
 * @param flags See KERN_NEXUS_SYNCF flags.
 */
typedef errno_t (*nxprov_sync_rx_fn_t)(kern_nexus_provider_t nexus_prov,
    kern_nexus_t nexus, kern_channel_ring_t ring, uint32_t flags);

/*
 * Valid flags for {tx,rx}sync callbacks.
 */
#define KERN_NEXUS_SYNCF_COMMIT         0x1     /* force reclaim/update */

/*
 * @typedef nxprov_tx_doorbell_fn_t
 * @abstract Nexus provider TX doorbell callback, required for netif.
 * @param nexus_prov Nexus provider handle.
 * @param nexus The nexus instance.
 * @param ring The ring associated with the doorbell.
 * @param flags See KERN_NEXUS_TXDOORBELLF flags.
 */
typedef errno_t (*nxprov_tx_doorbell_fn_t)(kern_nexus_provider_t nexus_prov,
    kern_nexus_t nexus, kern_channel_ring_t ring, uint32_t flags);

/*
 * Valid flags for tx doorbell callback.
 */
/* call kern_channel_tx_refill() in async context */
#define KERN_NEXUS_TXDOORBELLF_ASYNC_REFILL     0x1

/*
 * @typedef nxprov_sync_packets_fn_t
 * @abstract Nexus provider get packets callback, required for netif.
 * @param nexus_prov Nexus provider handle.
 * @param nexus The nexus instance.
 * @param ring The device ring.
 * @param packets Array of packet chains
 * @param count:
 *      RX: caller sets this to the array size. on return, this count
 *          is set to actual number of packets returned.
 *      TX: not implemented
 * @param flags none for now.
 */
typedef errno_t (*nxprov_sync_packets_fn_t)(kern_nexus_provider_t nexus_prov,
    kern_nexus_t nexus, kern_channel_ring_t ring, uint64_t packets[],
    uint32_t *count, uint32_t flags);


/*
 * @typedef nxprov_capab_config_fn_t
 * @abstract Nexus provider capabilities configuration callback,
 *           required for netif.
 * @param nexus_prov Nexus provider handle.
 * @param nexus The nexus instance.
 * @param capab The capability being queried.
 * @param contents Structure describing the capability.
 * @param len Input: length of buffer for holding contents.
 *            Output: length of actual size of contents.
 */
typedef enum {
	/* periodic interface advisory notifications */
	KERN_NEXUS_CAPAB_INTERFACE_ADVISORY = 1,
	/* extends queue set functionality: e.g. notify steering info */
	KERN_NEXUS_CAPAB_QSET_EXTENSIONS,
} kern_nexus_capab_t;

typedef errno_t (*nxprov_capab_config_fn_t)(kern_nexus_provider_t nexus_prov,
    kern_nexus_t nexus, kern_nexus_capab_t capab, void *contents,
    uint32_t *len);

/*
 * struct kern_nexus_capab_interface_advisory
 * @abstract Interface advisory capability configuration callback.
 * @param kncia_version Version of the capability structure.
 * @param kncia_notify The notification interface provided by kernel.
 * @param kncia_config The configuration interface provided by nexus provider.
 */
#define KERN_NEXUS_CAPAB_INTERFACE_ADVISORY_VERSION_1 1
typedef errno_t (*kern_nexus_capab_interface_advisory_config_fn_t)(
	void *provider_context, bool enable);
typedef errno_t (*kern_nexus_capab_interface_advisory_notify_fn_t)(
	void *kern_context, const struct ifnet_interface_advisory *adv_info);
struct kern_nexus_capab_interface_advisory {
	uint32_t kncia_version;
	void * const kncia_kern_context;
	void *kncia_provider_context;
	const kern_nexus_capab_interface_advisory_notify_fn_t kncia_notify;
	kern_nexus_capab_interface_advisory_config_fn_t kncia_config;
};

/*
 * struct kern_nexus_capab_qset_extensions
 * @abstract qset extensions configuration callback.
 * @param cqe_version Version of the capability structure.
 * @param cqe_notify_steering_info callback provided by nexus provider.
 * @param cqe_prov_ctx provider context for the above callback.
 */
#define KERN_NEXUS_CAPAB_QSET_EXTENSIONS_VERSION_1 1
typedef errno_t (*kern_nexus_capab_qsext_notify_steering_info_fn_t)(
	void *provider_context, void *qset_context,
	struct ifnet_traffic_descriptor_common *td, bool add);
struct kern_nexus_capab_qset_extensions {
	uint32_t cqe_version;
	void *cqe_prov_ctx;
	kern_nexus_capab_qsext_notify_steering_info_fn_t cqe_notify_steering_info;
};

/*
 * Nexus provider init (version 1)
 */
struct kern_nexus_provider_init {
	uint32_t                nxpi_version;           /* current version */
	uint32_t                nxpi_flags;             /* see NXPIF_* */
	nxprov_pre_connect_fn_t nxpi_pre_connect;       /* required */
	nxprov_connected_fn_t   nxpi_connected;         /* required */
	nxprov_pre_disconnect_fn_t nxpi_pre_disconnect; /* required */
	nxprov_disconnected_fn_t nxpi_disconnected;     /* required */
	nxprov_ring_init_fn_t   nxpi_ring_init;         /* optional */
	nxprov_ring_fini_fn_t   nxpi_ring_fini;         /* optional */
	nxprov_slot_init_fn_t   nxpi_slot_init;         /* optional */
	nxprov_slot_fini_fn_t   nxpi_slot_fini;         /* optional */
	nxprov_sync_tx_fn_t     nxpi_sync_tx;           /* required */
	nxprov_sync_rx_fn_t     nxpi_sync_rx;           /* required */
	nxprov_tx_doorbell_fn_t nxpi_tx_doorbell;       /* required (netif) */
	nxprov_sync_packets_fn_t nxpi_rx_sync_packets;  /* optional (netif) */
	nxprov_sync_packets_fn_t nxpi_tx_sync_packets;  /* optional (netif) */
	nxprov_capab_config_fn_t nxpi_config_capab;     /* optional (netif) */
};

/*
 * @typedef nxprov_qset_init_fn_t
 * @abstract Nexus provider netif qset setup callback.
 * @param nexus_prov Nexus provider handle.
 * @param nexus The nexus instance.
 * @param llink_ctx The context associated with the logical link owning this
 *                  qset (provider owned). Retreived during logical link
 *                  creation.
 * @param qset_idx The index of the qset within this logical link.
 * @param qset_id  The encoded id of the qset. Meant to be propagated to userspace
 *                 and passed down later during qset selection.
 * @param qset The netif qset to be initialized (xnu owned). Meant to be
 *             used for upcalls to xnu.
 * @param qset_ctx The qset context (provider owned output arg). Meant to
 *                 be used for downcalls to the provider involving this qset.
 * @result Non-zero result will abort the queue initialization.
 */
typedef errno_t (*nxprov_qset_init_fn_t)(kern_nexus_provider_t nexus_prov,
    kern_nexus_t nexus, void *llink_ctx, uint8_t qset_idx,
    uint64_t qset_id, kern_netif_qset_t qset, void **qset_ctx);

/*
 * @typedef nxprov_qset_fini_fn_t
 * @abstract Nexus provider netif qset teardown callback.
 * @param nexus_prov Nexus provider handle.
 * @param nexus The nexus instance.
 * @param qset_ctx The qset context retrieved from nxprov_qset_init_fn_t
 *                 (provider owned).
 * @discussion The provider must free any resources associated with the
 *      qset context set at nxprov_qset_init_fn_t() time, since the qset is
 *      no longer valid upon return.
 */
typedef void (*nxprov_qset_fini_fn_t)(kern_nexus_provider_t nexus_prov,
    kern_nexus_t nexus, void *qset_ctx);

/*
 * @typedef nxprov_queue_init_fn_t
 * @abstract Nexus provider netif queue setup callback.
 * @param nexus_prov Nexus provider handle.
 * @param nexus The nexus instance.
 * @param qset_ctx The context associated with the qset owning this queue
 *                 (provider owned). Retreived from nxprov_qset_init_fn_t.
 * @param qidx The index of the queue within this qset.
 * @param queue The netif queue to be initialized (xnu owned). Meant to be
 *              used for upcalls to xnu.
 * @param tx True if the queue is used for TX direction, otherwise RX.
 * @param queue_ctx The queue context (provider owned output arg). Meant to
 *                  be used for downcalls to the provider involving this queue.
 * @result Non-zero result will abort the queue initialization.
 */
typedef errno_t (*nxprov_queue_init_fn_t)(kern_nexus_provider_t nexus_prov,
    kern_nexus_t nexus, void *qset_ctx, uint8_t qidx, bool tx,
    kern_netif_queue_t queue, void **queue_ctx);

/*
 * @typedef nxprov_queue_fini_fn_t
 * @abstract Nexus provider netif queue teardown callback.
 * @param nexus_prov Nexus provider handle.
 * @param nexus The nexus instance.
 * @param queue_ctx The queue context retrieved from nxprov_queue_init_fn_t
 *                  (provider owned).
 * @discussion The provider must free any resources associated with the
 *      queue context set at nxprov_queue_init_fn_t() time, since the queue is
 *      no longer valid upon return.
 */
typedef void (*nxprov_queue_fini_fn_t)(kern_nexus_provider_t nexus_prov,
    kern_nexus_t nexus, void *queue_ctx);

/*
 * @typedef nxprov_tx_qset_notify_fn_t
 * @abstract Nexus provider TX notify callback, required for netif.
 * @param nexus_prov Nexus provider handle.
 * @param nexus The nexus instance.
 * @param qset_ctx The qset_ctx owned by the qset to be notified (provider
 *                 owned). Retrieved from nxprov_qset_init_fn_t.
 * @param flags unused for now.
 */
typedef errno_t (*nxprov_tx_qset_notify_fn_t)(kern_nexus_provider_t
    nexus_prov, kern_nexus_t nexus, void *qset_ctx, uint32_t flags);

/*
 * Nexus provider initialization parameters specific to netif (version 2)
 */
struct kern_nexus_netif_provider_init {
	uint32_t                      nxnpi_version;       /* current version */
	uint32_t                      nxnpi_flags;             /* see NXPIF_* */
	nxprov_pre_connect_fn_t       nxnpi_pre_connect;       /* required */
	nxprov_connected_fn_t         nxnpi_connected;         /* required */
	nxprov_pre_disconnect_fn_t    nxnpi_pre_disconnect;    /* required */
	nxprov_disconnected_fn_t      nxnpi_disconnected;      /* required */
	nxprov_qset_init_fn_t         nxnpi_qset_init;         /* required */
	nxprov_qset_fini_fn_t         nxnpi_qset_fini;         /* required */
	nxprov_queue_init_fn_t        nxnpi_queue_init;        /* required */
	nxprov_queue_fini_fn_t        nxnpi_queue_fini;        /* required */
	nxprov_tx_qset_notify_fn_t    nxnpi_tx_qset_notify;    /* required */
	nxprov_capab_config_fn_t      nxnpi_config_capab;      /* required */
};

#define KERN_NEXUS_PROVIDER_VERSION_1         1
#define KERN_NEXUS_PROVIDER_VERSION_NETIF     2 /* specific to netif */
#define KERN_NEXUS_PROVIDER_CURRENT_VERSION   KERN_NEXUS_PROVIDER_VERSION_1

/*
 * Valid values for nxpi_flags.
 */
#define NXPIF_VIRTUAL_DEVICE    0x1     /* device is virtual (no DMA) */
#define NXPIF_MONOLITHIC        0x4     /* single segment mode */
#define NXPIF_INHIBIT_CACHE     0x8     /* caching-inhibited */

/*
 * Network Interface Nexus instance callback routines.
 */

/*
 * @typedef nxnet_prepare_fn_t
 * @abstract Network Interface nexus instance preparer callback.
 * @param nexus The nexus instance.
 * @param ifp The interface associated with the nexus instance.
 * @discussion The prepare callback routine specified by nxneti_prepare will
 *      be invoked on a newly-allocated interface that is not yet attached.
 *      A non-zero value returned by the callback routine will abort the
 *      operation; otherwise, the interface will then be associated with
 *      the nexus prior to being fully attached to the system.
 */
typedef errno_t (*nxnet_prepare_fn_t)(kern_nexus_t nexus, ifnet_t ifp);

/*
 * Nexus (Non-Networking) instance init.
 *
 * If supplied, packet buffer pool must have been created as KBIF_QUANTUM.
 */
struct kern_nexus_init {
	uint32_t                nxi_version;            /* current version */
	uint32_t                nxi_flags;              /* see NXIF_* */
	kern_pbufpool_t         nxi_tx_pbufpool;        /* optional */
	kern_pbufpool_t         nxi_rx_pbufpool;        /* optional */
};

#define KERN_NEXUS_VERSION_1                    1
#define KERN_NEXUS_CURRENT_VERSION              KERN_NEXUS_VERSION_1

/*
 * Network Interface Nexus instance init.
 *
 * If supplied, packet buffer pool must NOT have been created as KBIF_QUANTUM.
 * packet buffer pool is a required parameter if the nexus provider is
 * operating in netif logical link mode.
 */
struct kern_nexus_net_init {
	uint32_t                nxneti_version;         /* current version */
	uint32_t                nxneti_flags;           /* see NXNETF_* */
	struct ifnet_init_eparams *nxneti_eparams;      /* required */
	struct sockaddr_dl      *nxneti_lladdr;         /* optional */
	nxnet_prepare_fn_t      nxneti_prepare;         /* optional */
	kern_pbufpool_t         nxneti_tx_pbufpool;     /* optional */
	kern_pbufpool_t         nxneti_rx_pbufpool;     /* optional */
	struct kern_nexus_netif_llink_init *nxneti_llink; /* optional */
};

#define KERN_NEXUS_NET_VERSION_1                1
#define KERN_NEXUS_NET_VERSION_2                2
#define KERN_NEXUS_NET_CURRENT_VERSION          KERN_NEXUS_NET_VERSION_1

struct kern_nexus_netif_llink_qset_init {
	uint32_t    nlqi_flags;
	uint8_t     nlqi_num_rxqs;
	uint8_t     nlqi_num_txqs;
};

/*
 * nxnetllq_flags values.
 */
/* default qset of the logical link */
#define KERN_NEXUS_NET_LLINK_QSET_DEFAULT        0x1
/* qset needs AQM */
#define KERN_NEXUS_NET_LLINK_QSET_AQM            0x2
/* qset is low latency */
#define KERN_NEXUS_NET_LLINK_QSET_LOW_LATENCY    0x4
/* qset in WMM mode */
#define KERN_NEXUS_NET_LLINK_QSET_WMM_MODE       0x8

typedef uint64_t kern_nexus_netif_llink_id_t;

struct kern_nexus_netif_llink_init {
	uint32_t        nli_flags;
	uint8_t         nli_num_qsets;
	void            *nli_ctx;
	kern_nexus_netif_llink_id_t nli_link_id;
	struct kern_nexus_netif_llink_qset_init *nli_qsets;
};

/*
 * nxnetll_flags values.
 */
/* default logical link */
#define KERN_NEXUS_NET_LLINK_DEFAULT        0x1

__BEGIN_DECLS
/*
 * Attributes.
 */
extern errno_t kern_nexus_attr_create(nexus_attr_t *);
extern errno_t kern_nexus_attr_clone(const nexus_attr_t attr,
    nexus_attr_t *);
extern errno_t kern_nexus_attr_set(nexus_attr_t attr,
    const nexus_attr_type_t type, const uint64_t value);
extern errno_t kern_nexus_attr_get(const nexus_attr_t attr,
    const nexus_attr_type_t type, uint64_t *value);
extern void kern_nexus_attr_destroy(nexus_attr_t attr);

/*
 * Domain provider.
 *
 * At present we allow only NEXUS_TYPE_{KERNEL_PIPE,NET_IF} external
 * providers to be registered.
 */
extern errno_t kern_nexus_register_domain_provider(const nexus_type_t type,
    const nexus_domain_provider_name_t name,
    const struct kern_nexus_domain_provider_init *init,
    const uint32_t init_len, uuid_t *dom_prov_uuid);
extern errno_t kern_nexus_deregister_domain_provider(
	const uuid_t dom_prov_uuid);
extern errno_t kern_nexus_get_default_domain_provider(const nexus_type_t type,
    uuid_t *dom_prov_uuid);

/*
 * Nexus provider.
 */
typedef void (*nexus_ctx_release_fn_t)(void *const ctx);

extern errno_t kern_nexus_controller_create(nexus_controller_t *ctl);
extern errno_t kern_nexus_controller_register_provider(
	const nexus_controller_t ctl, const uuid_t dom_prov_uuid,
	const nexus_name_t, const struct kern_nexus_provider_init *init,
	const uint32_t init_len, const nexus_attr_t nxa, uuid_t *nx_prov_uuid);
extern errno_t kern_nexus_controller_deregister_provider(
	const nexus_controller_t ctl, const uuid_t nx_prov_uuid);
extern errno_t kern_nexus_controller_alloc_provider_instance(
	const nexus_controller_t ctl, const uuid_t nx_prov_uuid,
	const void *nexus_context, nexus_ctx_release_fn_t nexus_context_release,
	uuid_t *nx_uuid, const struct kern_nexus_init *init);
extern errno_t kern_nexus_controller_alloc_net_provider_instance(
	const nexus_controller_t ctl, const uuid_t nx_prov_uuid,
	const void *nexus_context, nexus_ctx_release_fn_t nexus_context_release,
	uuid_t *nx_uuid, const struct kern_nexus_net_init *init, ifnet_t *);
extern errno_t kern_nexus_controller_free_provider_instance(
	const nexus_controller_t ctl, const uuid_t nx_uuid);
extern errno_t kern_nexus_controller_bind_provider_instance(
	const nexus_controller_t ctl, const uuid_t nx_uuid, nexus_port_t *port,
	const pid_t pid, const uuid_t exec_uuid, const void *key,
	const uint32_t key_len, const uint32_t bind_flags);
extern errno_t kern_nexus_controller_unbind_provider_instance(
	const nexus_controller_t ctl, const uuid_t nx_uuid,
	const nexus_port_t port);
extern errno_t kern_nexus_controller_read_provider_attr(
	const nexus_controller_t ctl, const uuid_t nx_prov_uuid,
	nexus_attr_t attr);
extern void kern_nexus_controller_destroy(nexus_controller_t ctl);
extern void kern_nexus_stop(const kern_nexus_t nx);

/*
 * Netif specific.
 */
extern errno_t kern_netif_queue_tx_dequeue(kern_netif_queue_t, uint32_t,
    uint32_t, boolean_t *, uint64_t *);

#define KERN_NETIF_QUEUE_RX_ENQUEUE_FLAG_FLUSH     0x0001
extern void kern_netif_queue_rx_enqueue(kern_netif_queue_t, uint64_t,
    uint32_t, uint32_t);

extern errno_t kern_nexus_netif_llink_add(struct kern_nexus *,
    struct kern_nexus_netif_llink_init *);

extern errno_t kern_nexus_netif_llink_remove(struct kern_nexus *,
    kern_nexus_netif_llink_id_t);

extern errno_t kern_netif_qset_tx_queue_len(kern_netif_qset_t,
    uint32_t, uint32_t *, uint32_t *);

extern void kern_netif_set_qset_combined(kern_netif_qset_t qset);

extern void kern_netif_set_qset_separate(kern_netif_qset_t qset);

/*
 * Misc.
 */
extern void *kern_nexus_get_context(const kern_nexus_t nexus);
extern errno_t kern_nexus_get_pbufpool(const kern_nexus_t nexus,
    kern_pbufpool_t *tx_pbufpool, kern_pbufpool_t *rx_pbufpool);

/*
 * Non-exported KPIs.
 */
extern int kern_nexus_ifattach(nexus_controller_t, const uuid_t nx_uuid,
    struct ifnet *ifp, const uuid_t nx_attachee, boolean_t host,
    uuid_t *nx_if_uuid);
extern int kern_nexus_ifdetach(const nexus_controller_t ctl,
    const uuid_t nx_uuid, const uuid_t nx_if_uuid);
extern int kern_nexus_get_netif_instance(struct ifnet *ifp, uuid_t nx_uuid);
extern int kern_nexus_get_flowswitch_instance(struct ifnet *ifp,
    uuid_t nx_uuid);
extern nexus_controller_t kern_nexus_shared_controller(void);
extern void kern_nexus_register_netagents(void);
extern void kern_nexus_deregister_netagents(void);
extern void kern_nexus_update_netagents(void);
extern int kern_nexus_interface_add_netagent(struct ifnet *);
extern int kern_nexus_interface_remove_netagent(struct ifnet *);
extern int kern_nexus_set_netif_input_tbr_rate(struct ifnet *ifp,
    uint64_t rate);
extern int kern_nexus_set_if_netem_params(
	const nexus_controller_t ctl, const uuid_t nx_uuid,
	void *data, size_t data_len);
extern int kern_nexus_flow_add(const nexus_controller_t ncd,
    const uuid_t nx_uuid, void *data, size_t data_len);
extern int kern_nexus_flow_del(const nexus_controller_t ncd,
    const uuid_t nx_uuid, void *data, size_t data_len);

__END_DECLS
#endif /* KERNEL */
#endif /* PRIVATE */
#endif /* !_SKYWALK_OS_NEXUS_H_ */
