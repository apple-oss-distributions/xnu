/*
 * Copyright (c) 2015-2021 Apple Inc. All rights reserved.
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

#ifndef _SKYWALK_OS_CHANNEL_H_
#define _SKYWALK_OS_CHANNEL_H_

#ifdef PRIVATE

#include <stdint.h>
#include <sys/types.h>
#include <sys/cdefs.h>
#include <uuid/uuid.h>
#include <mach/vm_types.h>
#include <skywalk/os_nexus.h>
#include <skywalk/os_packet.h>
#ifndef KERNEL
#include <skywalk/os_channel_event.h>
#include <net/if_var.h>
#endif /* !KERNEL */

/*
 * Indicates that channel supports "CHANNEL_ATTR_NUM_BUFFERS" attribute.
 * used by Libnetcore.
 */
#define OS_CHANNEL_HAS_NUM_BUFFERS_ATTR 1

/* Flow advisory table index */
typedef uint32_t flowadv_idx_t;
#define FLOWADV_IDX_NONE                ((flowadv_idx_t)-1)

/*
 * Channel ring direction.
 */
typedef enum {
	CHANNEL_DIR_TX_RX,      /* default: TX and RX ring(s) */
	CHANNEL_DIR_TX,         /* (monitor) only TX ring(s) */
	CHANNEL_DIR_RX          /* (monitor) only RX ring(s) */
} ring_dir_t;

/*
 * Channel ring ID.
 */
typedef uint32_t ring_id_t;
#define CHANNEL_RING_ID_ANY             ((ring_id_t)-1)

typedef enum {
	CHANNEL_FIRST_TX_RING,
	CHANNEL_LAST_TX_RING,
	CHANNEL_FIRST_RX_RING,
	CHANNEL_LAST_RX_RING
} ring_id_type_t;

/* Sync mode values */
typedef enum {
	CHANNEL_SYNC_TX,        /* synchronize TX ring(s) */
	CHANNEL_SYNC_RX,        /* synchronize RX ring(s) */
#if defined(LIBSYSCALL_INTERFACE) || defined(BSD_KERNEL_PRIVATE)
	CHANNEL_SYNC_UPP        /* synchronize packet pool rings only */
#endif /* LIBSYSCALL_INTERFACE || BSD_KERNEL_PRIVATE */
} sync_mode_t;

/* Sync flags */
typedef uint32_t sync_flags_t;
#if defined(LIBSYSCALL_INTERFACE) || defined(BSD_KERNEL_PRIVATE)
#define CHANNEL_SYNCF_ALLOC        0x1     /* synchronize alloc ring */
#define CHANNEL_SYNCF_FREE         0x2     /* synchronize free ring */
#define CHANNEL_SYNCF_PURGE        0x4     /* purge user packet pool */
#define CHANNEL_SYNCF_ALLOC_BUF    0x8     /* synchronize buflet alloc ring */
#endif /* LIBSYSCALL_INTERFACE || BSD_KERNEL_PRIVATE */

/*
 * Opaque handles.
 */
struct channel;
struct channel_ring_desc;
struct __slot_desc;
struct channel_attr;

typedef struct channel                  *channel_t;
typedef struct channel_ring_desc        *channel_ring_t;
typedef struct __slot_desc              *channel_slot_t;
typedef struct channel_attr             *channel_attr_t;

/*
 * Channel monitor types.
 */
typedef enum {
	CHANNEL_MONITOR_OFF,            /* default */
	CHANNEL_MONITOR_NO_COPY,        /* zero-copy (delayed) mode */
	CHANNEL_MONITOR_COPY            /* copy (immediate) mode */
} channel_monitor_type_t;

/*
 * Channel threshold unit types.
 */
typedef enum {
	CHANNEL_THRESHOLD_UNIT_SLOTS,   /* unit in slots (default) */
	CHANNEL_THRESHOLD_UNIT_BYTES,   /* unit in bytes */
} channel_threshold_unit_t;

/*
 * Channel attribute types gettable/settable via os_channel_attr_{get,set}.
 *
 *     g: retrievable at any time
 *     s: settable at any time
 *     S: settable once, only at creation time
 */
typedef enum {
	CHANNEL_ATTR_TX_RINGS,          /* (g) # of transmit rings */
	CHANNEL_ATTR_RX_RINGS,          /* (g) # of receive rings */
	CHANNEL_ATTR_TX_SLOTS,          /* (g) # of slots per transmit ring */
	CHANNEL_ATTR_RX_SLOTS,          /* (g) # of slots per receive ring */
	CHANNEL_ATTR_SLOT_BUF_SIZE,     /* (g) buffer per slot (bytes) */
	CHANNEL_ATTR_SLOT_META_SIZE,    /* (g) metadata per slot (bytes) */
	CHANNEL_ATTR_EXCLUSIVE,         /* (g/s) bool: exclusive open */
	CHANNEL_ATTR_NO_AUTO_SYNC,      /* (g/s) bool: will do explicit sync */
	CHANNEL_ATTR_MONITOR,           /* (g/s) see channel_monitor_type_t */
	CHANNEL_ATTR_TX_LOWAT_UNIT,     /* (g/s) see channel_threshold_unit_t */
	CHANNEL_ATTR_TX_LOWAT_VALUE,    /* (g/s) transmit low-watermark */
	CHANNEL_ATTR_RX_LOWAT_UNIT,     /* (g/s) see channel_threshold_unit_t */
	CHANNEL_ATTR_RX_LOWAT_VALUE,    /* (g/s) receive low-watermark */
	CHANNEL_ATTR_NEXUS_TYPE,        /* (g) nexus type */
	CHANNEL_ATTR_NEXUS_EXTENSIONS,  /* (g) nexus extension(s) */
	CHANNEL_ATTR_NEXUS_MHINTS,      /* (g) nexus memory usage hints */
	CHANNEL_ATTR_TX_HOST_RINGS,     /* (g) # of transmit host rings */
	CHANNEL_ATTR_RX_HOST_RINGS,     /* (g) # of receive host rings */
	CHANNEL_ATTR_NEXUS_IFINDEX,     /* (g) nexus network interface index */
	CHANNEL_ATTR_NEXUS_STATS_SIZE,  /* (g) nexus statistics region size */
	CHANNEL_ATTR_NEXUS_FLOWADV_MAX, /* (g) # of flow advisory entries */
	CHANNEL_ATTR_NEXUS_META_TYPE,   /* (g) nexus metadata type */
	CHANNEL_ATTR_NEXUS_META_SUBTYPE, /* (g) nexus metadata subtype */
	CHANNEL_ATTR_NEXUS_CHECKSUM_OFFLOAD, /* (g) nexus checksum offload */
	CHANNEL_ATTR_USER_PACKET_POOL,  /* (g/s) bool: use user packet pool */
	CHANNEL_ATTR_NEXUS_ADV_SIZE,    /* (g) nexus advisory region size */
	CHANNEL_ATTR_NEXUS_DEFUNCT_OK,  /* (g/s) bool: allow defunct */
	CHANNEL_ATTR_FILTER,            /* (g/s) bool: filter mode */
	CHANNEL_ATTR_EVENT_RING,        /* (g/s) bool: enable event ring */
	CHANNEL_ATTR_MAX_FRAGS,         /* (g) max length of buflet chain */
	CHANNEL_ATTR_NUM_BUFFERS,       /* (g) # of buffers in user pool */
	CHANNEL_ATTR_LOW_LATENCY,       /* (g/s) bool: low latency channel */
	CHANNEL_ATTR_LARGE_BUF_SIZE,    /* (g) large buffer size (bytes) */
} channel_attr_type_t;

/*
 * Channel nexus metadata type.
 */
typedef enum {
	CHANNEL_NEXUS_META_TYPE_INVALID = 0,
	CHANNEL_NEXUS_META_TYPE_QUANTUM, /* OK for os_packet quantum APIs */
	CHANNEL_NEXUS_META_TYPE_PACKET,  /* OK for all os_packet APIs */
} channel_nexus_meta_type_t;

/*
 * Channel nexus metadata subtype.
 */
typedef enum {
	CHANNEL_NEXUS_META_SUBTYPE_INVALID = 0,
	CHANNEL_NEXUS_META_SUBTYPE_PAYLOAD,
	CHANNEL_NEXUS_META_SUBTYPE_RAW,
} channel_nexus_meta_subtype_t;

/*
 * Valid values for CHANNEL_ATTR_NEXUS_CHECKSUM_OFFLOAD
 */
#define CHANNEL_NEXUS_CHECKSUM_PARTIAL  0x1     /* partial checksum */

/*
 * Channel statistics ID.
 */
typedef enum {
	CHANNEL_STATS_ID_IP = 0,        /* struct ip_stats */
	CHANNEL_STATS_ID_IP6,           /* struct ip6_stats */
	CHANNEL_STATS_ID_TCP,           /* struct tcp_stats */
	CHANNEL_STATS_ID_UDP,           /* struct udp_stats */
	CHANNEL_STATS_ID_QUIC,          /* struct quic_stats */
} channel_stats_id_t;

/*
 * Slot properties.  Structure is aligned to allow for efficient copy.
 *
 * Fields except for sp_{flags,len} are immutables (I).  The system will
 * verify for correctness during os_channel_put() across the immutable
 * fields, and will abort the process if it detects inconsistencies.
 * This is meant to help with debugging, since it indicates bugs and/or
 * memory corruption.
 */
typedef struct slot_prop {
	uint16_t sp_flags;              /* private flags */
	uint16_t sp_len;                /* length for this slot */
	uint32_t sp_idx;                /* (I) slot index */
	mach_vm_address_t sp_ext_ptr;   /* (I) pointer for indirect buffer */
	mach_vm_address_t sp_buf_ptr;   /* (I) pointer for native buffer */
	mach_vm_address_t sp_mdata_ptr; /* (I) pointer for metadata */
	uint32_t _sp_pad[8];            /* reserved */
} slot_prop_t __attribute__((aligned(sizeof(uint64_t))));

#ifndef KERNEL
/*
 * User APIs.
 */
#if !defined(_POSIX_C_SOURCE) || defined(_DARWIN_C_SOURCE)
__BEGIN_DECLS
/*
 * Creates a Channel attribute object.
 *
 * This must be paired with a os_channel_attr_destroy() on the handle.
 */
extern channel_attr_t os_channel_attr_create(void);

/*
 * Clones a Channel attribute object.  If source attribute is NULL
 * it behaves just like os_channel_attr_create();
 *
 * This must be paired with a os_channel_attr_destroy() on the handle.
 */
extern channel_attr_t os_channel_attr_clone(const channel_attr_t);

/*
 * Sets a value for a given attribute type on a Channel attribute object.
 */
extern int os_channel_attr_set(const channel_attr_t attr,
    const channel_attr_type_t type, const uint64_t value);

/*
 * Sets a key blob on a Channel attribute object.  Existing key blob
 * information in the attribute object will be removed, if any, and
 * replaced with the new key blob.  Specifying 0 for key_len will
 * clear the key stored in the attribute object.  The maximum key
 * length is specified by NEXUS_MAX_KEY_LEN.
 */
extern int os_channel_attr_set_key(const channel_attr_t attr,
    const void *key, const uint32_t key_len);

/*
 * Gets a value for a given attribute type on a Channel attribute object.
 */
extern int os_channel_attr_get(const channel_attr_t attr,
    const channel_attr_type_t type, uint64_t *value);

/*
 * Gets a key blob on a Channel attribute object.  If key is NULL,
 * returns the length of the key blob with key_len, so caller knows
 * how much to allocate space for key blob.
 */
extern int os_channel_attr_get_key(const channel_attr_t attr,
    void *key, uint32_t *key_len);

/*
 * Destroys a Channel attribute object, along with all resources
 * associated with it (e.g. key blob).
 */
extern void os_channel_attr_destroy(const channel_attr_t attr);

/*
 * Opens a Channel to a Nexus provider instance.  Upon success, maps memory
 * region and allocates resources.
 *
 * This must be paired with a os_channel_destroy() on the handle, in order to
 * unmap the memory region and free resources.
 */
extern channel_t os_channel_create(const uuid_t uuid, const nexus_port_t port);

/*
 * Extended version of os_channel_create().
 */
extern channel_t os_channel_create_extended(const uuid_t uuid,
    const nexus_port_t port, const ring_dir_t dir, const ring_id_t rid,
    const channel_attr_t attr);

/*
 * Retrieves the file descriptor associated with the Channel.
 */
extern int os_channel_get_fd(const channel_t channel);

/*
 * Retrieves current channel attributes into the channel_attr_t handle.
 */
extern int os_channel_read_attr(const channel_t channel, channel_attr_t attr);

/*
 * Updates channel attributes based on those referred to by the channel_attr_t
 * handle.  See comments above on channel_attr_type_t; this routine will only
 * update attributes that are marked with 's' but not 'S'.
 */
extern int os_channel_write_attr(const channel_t channel, channel_attr_t attr);

/*
 * Retrieves channel's associated nexus type into *nexus_type, and the
 * provider-specific extension attribute into *ext.
 */
extern int os_channel_read_nexus_extension_info(const channel_t channel,
    nexus_type_t *nexus_type, uint64_t *ext);

/*
 * Non-blocking synchronization.  Channel handle may also be used
 * with kqueue(2), select(2) or poll(2) through the file descriptor.
 */
extern int os_channel_sync(const channel_t channel, const sync_mode_t mode);

/*
 * Destroys a Channel.
 */
extern void os_channel_destroy(const channel_t channel);

/*
 * Checks if a channel is defunct.  Returns non-zero if defunct.
 */
extern int os_channel_is_defunct(const channel_t channel);

/*
 * Data Movement APIs.
 *
 * Obtain channel_ring_t handle via os_channel_{tx,rx}_ring().  You will
 * need to specify the ring_id_t which identifies the ring — this is true
 * even for a single TX/RX ring case.  The Nexus provider can communicate
 * to the client the ID of the TX and RX ring that should be used to
 * communicate to it, through a contract between the two.  For instance,
 * it can tell the client to use first TX ring and first RX ring, etc.
 * through some side-channel.  It should not assume 0 or any other number
 * as ID, however, as the in-kernel Nexus object is the authoritative source
 * of truth.  This is where the os_channel_ring_id() call comes into the
 * picture, as it will return the first and last usable TX and RX ring IDs
 * for the Channel opened to that Nexus object.
 *
 * Once the TX or RX ring handle is obtained above, the client can ask for
 * the first usable slot in the ring through os_channel_get_next_slot()
 * passing NULL for the 'slot' parameter. This returns a channel_slot_t
 * handle that represents the slot, along with the properties of that slot
 * described by the slot_prop_t structure. If no slots are available, this
 * call returns a NULL handle.  It’s important to note that this
 * call does NOT advance the ring’s current slot pointer; calling this
 * multiple times in succession will yield the same result.
 *
 * The client proceeds to use the slot by examining the returned
 * slot_prop_t fields including the pointer to the internal buffer
 * associated with that slot.  Once the client is finished, it updates
 * the relevant slot_prop_t fields (e.g. length) and calls
 * os_channel_set_slot_properties() to apply them to the slot.
 *
 * To get the next slot, the client provides the non-NULL slot value obtained
 * from the previous call to os_channel_get_next_slot() as the 'slot' parameter
 * in its next invocation of that function.
 *
 * To advance the ring’s current pointer, the client invokes
 * os_channel_advance_slot() specifying the slot to advance past. If the slot
 * is invalid, this function returns a non-zero value.
 *
 * Once the client is ready to commit, call os_channel_sync() in
 * either/all directions.
 */
extern ring_id_t os_channel_ring_id(const channel_t channel,
    const ring_id_type_t type);
extern channel_ring_t os_channel_tx_ring(const channel_t channel,
    const ring_id_t rid);
extern channel_ring_t os_channel_rx_ring(const channel_t channel,
    const ring_id_t rid);
extern int os_channel_pending(const channel_ring_t ring);

/*
 * This returns a nexus-specific timestamp in nanoseconds taken at the
 * lasttime os_channel_sync() or its equivalent implicit kevent sync
 * was called
 */
extern uint64_t os_channel_ring_sync_time(const channel_ring_t ring);

/*
 * This returns a nexus-specific timestamp in nanoseconds to indicate
 * the time of last activity on the opposite end of the ring.
 * This is only updated when sync or kevent equivalent is called.
 */
extern uint64_t os_channel_ring_notify_time(const channel_ring_t ring);

/*
 * For TX ring os_channel_available_slot_count() returns the minimum number
 * of slots available availble for TX, and it is possible that
 * os_channel_get_next_slot() will return more slots than the what was
 * returned by an earlier call to os_channel_available_slot_count()
 */
extern uint32_t os_channel_available_slot_count(const channel_ring_t ring);
extern channel_slot_t os_channel_get_next_slot(const channel_ring_t ring,
    const channel_slot_t slot, slot_prop_t *prop);
extern int os_channel_advance_slot(channel_ring_t ring,
    const channel_slot_t slot);
extern void os_channel_set_slot_properties(const channel_ring_t ring,
    const channel_slot_t slot, const slot_prop_t *prop);

/*
 * Return the packet handle associated with a given slot of a ring.
 */
extern packet_t os_channel_slot_get_packet(const channel_ring_t ring,
    const channel_slot_t slot);

/*
 * Each nexus that the channel is connected to determines whether or
 * not there is a shareable statistics region identified by one of
 * the channel_stats_id_t values.  This routine returns a pointer to
 * such a region upon success, or NULL if not supported by the nexus.
 */
extern void *os_channel_get_stats_region(const channel_t channel,
    const channel_stats_id_t id);

/*
 * Each nexus that the channel is connected to determines whether or
 * not there is a nexus-wide advisory region.  This routine returns
 * a pointer to such a region upon success, or NULL if not supported
 * by the nexus.
 */
extern void *os_channel_get_advisory_region(const channel_t channel);

/*
 * Each nexus that supports flow admission control may be queried to
 * advise whether or not the channel is willing to admit more packets
 * for a given flow.  A return value of 0 indicates that the packets
 * for the flow are admissible.  If ENOBUFS is returned, the flow is
 * currently suspended, and further attempts to send more packets on
 * the ring may result in drops.  Any other error values indicate
 * that either the nexus doesn't support admission control, or the
 * arguments aren't valid.
 */
extern int os_channel_flow_admissible(const channel_ring_t ring,
    uuid_t flow_id, const flowadv_idx_t flow_index);

/*
 * Allocate a packet from the channel's packet pool.
 * Returns 0 on success with the packet handle in packet arg.
 * Note: os_channel_packet_alloc() & os_channel_packet_free() should be
 * serialized and should not be called from the different thread context.
 */
extern int
os_channel_packet_alloc(const channel_t chd, packet_t *packet);

/*
 * Free a packet allocated from the channel's packet pool.
 * Returns 0 on success
 * Note: os_channel_packet_alloc() & os_channel_packet_free() should be
 * serialized and should not be called from the different thread context.
 */
extern int
os_channel_packet_free(const channel_t chd, packet_t packet);

/*
 * Attach the given packet to a channel slot
 */
extern int
os_channel_slot_attach_packet(const channel_ring_t chrd,
    const channel_slot_t slot, packet_t packet);

/*
 * Detach a given packet from a channel slot
 */
extern int
os_channel_slot_detach_packet(const channel_ring_t chrd,
    const channel_slot_t slot, packet_t packet);

/*
 * purge packets from the channel's packet pool.
 * This API should be called at regular intervals by application to purge
 * unused packets from the channel's packet pool. Recommended interval is
 * 11 seconds.
 * Returns 0 on success.
 * Note: This call should be serialized with os_channel_packet_alloc() &
 * os_channel_packet_free() and should not be called from different
 * thread context.
 */
extern int
os_channel_packet_pool_purge(const channel_t chd);

/*
 * Retrieve handle to the next available event(s) on the channel.
 * os_event_get_next_event() can then called on the event handle to
 * retrieve the individual events from the handle.
 * Returns 0 on success, ENXIO if the channel is defunct.
 */
extern int
os_channel_get_next_event_handle(const channel_t chd,
    os_channel_event_handle_t *ehandle, os_channel_event_type_t *etype,
    uint32_t *nevents);

/*
 * Free an event retrieved from the channel.
 * Returns 0 on success, ENXIO if the channel is defunct.
 */
extern int
os_channel_event_free(const channel_t chd, os_channel_event_handle_t ehandle);

/*
 * API to retrieve the latest interface advisory report on the channel.
 * Returns 0 on succcess. If the return value is EAGAIN, caller can attempt
 * to retrieve the information again.
 */
extern int
os_channel_get_interface_advisory(const channel_t chd,
    struct ifnet_interface_advisory *advisory);

/*
 * API to configure interface advisory report on the channel.
 * Returns 0 on succcess.
 */
extern int
os_channel_configure_interface_advisory(const channel_t chd, boolean_t enable);

extern int
os_channel_buflet_alloc(const channel_t chd, buflet_t *bft);

extern int
os_channel_buflet_free(const channel_t chd, buflet_t ubft);
__END_DECLS
#endif  /* (!_POSIX_C_SOURCE || _DARWIN_C_SOURCE) */
#else /* KERNEL */
/*
 * Kernel APIs.
 */

/*
 * Opaque handles.
 */
struct kern_channel;
struct __kern_channel_ring;

typedef struct kern_channel             *kern_channel_t;
typedef struct __kern_channel_ring      *kern_channel_ring_t;
typedef struct __slot_desc              *kern_channel_slot_t;

/*
 * Slot properties (deprecated).
 */
struct kern_slot_prop {
	uint32_t _sp_pad[16];           /* reserved */
} __attribute__((aligned(sizeof(uint64_t))));

/*
 * @struct kern_channel_ring_stat_increment
 * @abstract Structure used to increment the per ring statistic counters.
 * @field kcrsi_slots_transferred  number of slots transferred
 * @filed kcrsi_bytes_transferred  number of bytes transferred
 */
struct kern_channel_ring_stat_increment {
	uint32_t        kcrsi_slots_transferred;
	uint32_t        kcrsi_bytes_transferred;
};

/*
 * Data Movement APIs.
 *
 * See block comment above for userland data movement APIs for general
 * concepts.  The main differences here are the kern_channel_notify()
 * and kern_channel_reclaim() calls that aren't available for userland.
 * These calls are typically invoked within the TX and RX sync callbacks
 * implemented by the nexus provider.
 *
 * For TX sync, kern_channel_reclaim() is normally called after the
 * provider has finished reclaiming slots that have been "transmitted".
 * In this case, this call is simply a way to indicate to the system
 * that such condition has happened.
 *
 * For RX sync, kern_channel_reclaim() must be called at the beginning
 * of the callback in order to reclaim user-released slots, and to
 * ensure that subsequent calls to kern_channel_available_slot_count()
 * or kern_channel_get_next_slot() operates on the most recent state.
 *
 * The kern_channel_notify() is used to post notifications to indicate
 * slot availability; this may result in the kernel event subsystem
 * posting readable and writable events.
 */
__BEGIN_DECLS
extern uint32_t kern_channel_notify(const kern_channel_ring_t, uint32_t flags);
extern uint32_t kern_channel_available_slot_count(
	const kern_channel_ring_t ring);
/*
 * NOTE: kern_channel_set_slot_properties(), kern_channel_get_next_slot(),
 * kern_channel_reclaim() and kern_channel_advance_slot() require that the
 * caller invokes them from within the sync callback context; they will
 * assert otherwise.
 */
extern void kern_channel_set_slot_properties(const kern_channel_ring_t,
    const kern_channel_slot_t slot, const struct kern_slot_prop *prop);
extern kern_channel_slot_t kern_channel_get_next_slot(
	const kern_channel_ring_t kring, const kern_channel_slot_t slot,
	struct kern_slot_prop *slot_prop);
extern uint32_t kern_channel_reclaim(const kern_channel_ring_t);
extern void kern_channel_advance_slot(const kern_channel_ring_t kring,
    kern_channel_slot_t slot);

/*
 * Packet.
 */
extern kern_packet_t kern_channel_slot_get_packet(
	const kern_channel_ring_t ring, const kern_channel_slot_t slot);

/*
 * NOTE: kern_channel_slot_attach_packet(), kern_channel_slot_detach_packet()
 * and kern_channel_ring_get_container() require that the caller invokes them
 * from within the sync callback context; they will assert otherwise.
 */
extern errno_t kern_channel_slot_attach_packet(const kern_channel_ring_t ring,
    const kern_channel_slot_t slot, kern_packet_t packet);
extern errno_t kern_channel_slot_detach_packet(const kern_channel_ring_t ring,
    const kern_channel_slot_t slot, kern_packet_t packet);
extern errno_t kern_channel_ring_get_container(const kern_channel_ring_t ring,
    kern_packet_t **array, uint32_t *count);
extern errno_t kern_channel_tx_refill(const kern_channel_ring_t ring,
    uint32_t pkt_limit, uint32_t byte_limit, boolean_t tx_doorbell_ctxt,
    boolean_t *pkts_pending);
extern errno_t kern_channel_get_service_class(const kern_channel_ring_t ring,
    kern_packet_svc_class_t *svc);
extern errno_t kern_netif_queue_get_service_class(kern_netif_queue_t,
    kern_packet_svc_class_t *);

/*
 * Misc.
 */
extern void *kern_channel_get_context(const kern_channel_t channel);
extern void *kern_channel_ring_get_context(const kern_channel_ring_t ring);
extern void *kern_channel_slot_get_context(const kern_channel_ring_t ring,
    const kern_channel_slot_t slot);

/*
 * NOTE: kern_channel_increment_ring_{net}_stats() requires
 * that the caller invokes it from within the sync callback context;
 * it will assert otherwise.
 */
extern void kern_channel_increment_ring_stats(kern_channel_ring_t ring,
    struct kern_channel_ring_stat_increment *stats);
extern void kern_channel_increment_ring_net_stats(kern_channel_ring_t ring,
    ifnet_t, struct kern_channel_ring_stat_increment *stats);

#ifdef BSD_KERNEL_PRIVATE
/* forward declare */
struct flowadv_fcentry;

/* Flow advisory token */
typedef uint32_t flowadv_token_t;

/*
 * Private, unexported KPIs.
 */
__private_extern__ errno_t kern_channel_slot_attach_packet_byidx(
	const kern_channel_ring_t kring, const uint32_t sidx, kern_packet_t ph);
__private_extern__ errno_t kern_channel_slot_detach_packet_byidx(
	const kern_channel_ring_t kring, const uint32_t sidx, kern_packet_t ph);
__private_extern__ void kern_channel_flowadv_clear(struct flowadv_fcentry *);
__private_extern__ void kern_channel_memstatus(struct proc *, uint32_t,
    struct kern_channel *);
__private_extern__ void kern_channel_defunct(struct proc *,
    struct kern_channel *);
__private_extern__ errno_t kern_channel_tx_refill_canblock(
	const kern_channel_ring_t, uint32_t, uint32_t, boolean_t, boolean_t *);
#endif /* BSD_KERNEL_PRIVATE */
__END_DECLS
#endif /* KERNEL */
#endif /* PRIVATE */
#endif /* !_SKYWALK_OS_CHANNEL_H_ */
