/*
 * Copyright (c) 2021 Apple Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */

#include <sys/types.h>
#include <sys/kern_control.h>
#include <sys/queue.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/syslog.h>
#include <sys/systm.h>
#include <sys/sysproto.h>
#include <sys/socketvar.h>
#include <IOKit/IOBSD.h>

#include <kern/sched_prim.h>
#include <kern/locks.h>
#include <kern/zalloc.h>
#include <kern/debug.h>
#include <net/necp.h>

#define _IP_VHL
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <string.h>
#include <libkern/libkern.h>

extern int tcp_tcbhashsize;

int tracker_log_level = LOG_ERR;
static os_log_t tracker_db_log_handle = NULL;

/*
 * Tracker Entry Garbage Collection:
 */
static struct thread *g_tracker_gc_thread;
#define TRACKER_GC_RUN_INTERVAL_NSEC  (10 * NSEC_PER_SEC)   // GC wakes up periodically
#define TRACKER_GC_IDLE_TO            (10)                  // age out entries when not used for a while

static int tracker_db_idle_timeout = TRACKER_GC_IDLE_TO;

/*
 * Sysctls for debug logs control
 */
SYSCTL_NODE(_net, OID_AUTO, tracker, CTLFLAG_RW | CTLFLAG_LOCKED, 0, "tracker");

SYSCTL_INT(_net_tracker, OID_AUTO, log, CTLFLAG_RW | CTLFLAG_LOCKED,
    &tracker_log_level, 0, "");

SYSCTL_INT(_net_tracker, OID_AUTO, idle_timeout, CTLFLAG_RW | CTLFLAG_LOCKED,
    &tracker_db_idle_timeout, 0, "");

#define TRACKER_LOG(level, fmt, ...)                                                                                    \
do {                                                                                                                    \
    if (tracker_log_level >= level && tracker_db_log_handle) {                                                          \
	if (level == LOG_ERR) {                                                                                         \
	    os_log_error(tracker_db_log_handle, "TRACKER - %s:%d " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__);    \
	} else {                                                                                                        \
	    os_log(tracker_db_log_handle, "TRACKER - %s:%d " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__);          \
	}                                                                                                               \
    }                                                                                                                   \
} while (0)

#define TRACKER_ENTRY_LOG(level, msg, entry, hash)                                                                      \
do {                                                                                                                    \
    if (tracker_log_level >= level) {                                                                                   \
	tracker_entry_log(level, msg, entry, hash);                                                                     \
    }                                                                                                                   \
} while (0)

#define TRACKERHASHSIZE tcp_tcbhashsize

#define TRACKER_HASH_UUID_TO_BYTE(uuidptr) \
    ( ((uint8_t *)uuidptr)[0] ^ ((uint8_t *)uuidptr)[1] ^ ((uint8_t *)uuidptr)[2] ^ ((uint8_t *)uuidptr)[3] ^ \
      ((uint8_t *)uuidptr)[4] ^ ((uint8_t *)uuidptr)[5] ^ ((uint8_t *)uuidptr)[6] ^ ((uint8_t *)uuidptr)[7] ^ \
      ((uint8_t *)uuidptr)[8] ^ ((uint8_t *)uuidptr)[9] ^ ((uint8_t *)uuidptr)[10] ^ ((uint8_t *)uuidptr)[11] ^ \
      ((uint8_t *)uuidptr)[12] ^ ((uint8_t *)uuidptr)[13] ^ ((uint8_t *)uuidptr)[14] ^ ((uint8_t *)uuidptr)[15] )

#define TRACKER_HASH_WORD_TO_BYTE(wordptr) \
    ( ((uint8_t *)wordptr)[0] ^ ((uint8_t *)wordptr)[1] ^ ((uint8_t *)wordptr)[2] ^ ((uint8_t *)wordptr)[3] )

#define TRACKER_HASH(uuidptr, wordptr0, wordptr1, wordptr2, wordptr3) \
    ( TRACKER_HASH_WORD_TO_BYTE(wordptr0) ^ TRACKER_HASH_WORD_TO_BYTE(wordptr1) ^ TRACKER_HASH_WORD_TO_BYTE(wordptr2) ^ TRACKER_HASH_WORD_TO_BYTE(wordptr3) ^ \
      TRACKER_HASH_UUID_TO_BYTE(uuidptr) )

#define TRACKER_SCRATCH_PAD_SIZE 200
#define TRACKER_DUMP_SCRATCH_PAD_SIZE 2048
#define TRACKER_TLV_HDR_LEN (sizeof(u_int8_t) + sizeof(u_int32_t))
#define TRACKER_BUFFER_ALLOC_MAX (1024 * 200)

static uint8_t scratch_pad_all[TRACKER_DUMP_SCRATCH_PAD_SIZE];
static uint8_t scratch_pad_entry[TRACKER_SCRATCH_PAD_SIZE];

#define TRACKER_HASH_ENTRY_HEADER_FIELDS                    \
    LIST_ENTRY(tracker_hash_entry)      entry_link;         \
    uuid_t                              app_uuid;           \
    sa_family_t                         address_family;     \
    union {                                                 \
	struct in_addr_4in6 addr46;                             \
	struct in6_addr addr6;                                  \
    }                                   address;            \
    u_int64_t                           lastused;

typedef struct tracker_hash_entry {
	TRACKER_HASH_ENTRY_HEADER_FIELDS
	tracker_metadata_t                  metadata;
} tracker_hash_entry_t;

typedef struct tracker_hash_entry_short {
	TRACKER_HASH_ENTRY_HEADER_FIELDS
	tracker_metadata_short_t            metadata;
} tracker_hash_entry_short_t;

LIST_HEAD(trackerhashhead, tracker_hash_entry);

struct tracker_db {
	struct trackerhashhead              *tracker_hashbase;
	u_long                              tracker_hashmask;
	uint32_t                            tracker_count;
	uint32_t                            tracker_count_short;
	uint32_t                            max_link_count;
};

static KALLOC_TYPE_DEFINE(tracker_hash_entry_zone,
    struct tracker_hash_entry, NET_KT_DEFAULT);

static KALLOC_TYPE_DEFINE(tracker_hash_entry_short_zone,
    struct tracker_hash_entry_short, NET_KT_DEFAULT);

static struct tracker_db g_tracker_db = { };

static LCK_GRP_DECLARE(g_tracker_lck_grp, "tracker");
static LCK_RW_DECLARE(g_tracker_lck_rw, &g_tracker_lck_grp);

#define TRACKER_LOCK_EXCLUSIVE lck_rw_lock_exclusive(&g_tracker_lck_rw);
#define TRACKER_UNLOCK_EXCLUSIVE lck_rw_unlock_exclusive(&g_tracker_lck_rw);
#define TRACKER_LOCK_SHARED lck_rw_lock_shared(&g_tracker_lck_rw);
#define TRACKER_UNLOCK_SHARED lck_rw_unlock_shared(&g_tracker_lck_rw);

static void tracker_gc_thread_func(void *v, wait_result_t w);
static void tracker_entry_expire(void *v, wait_result_t w);

#define ALLOC_ENTRY(flags, entry)                                                                   \
    if (flags & SO_TRACKER_ATTRIBUTE_FLAGS_DOMAIN_SHORT) {                                          \
    tracker_hash_entry_short_t *short_entry = zalloc_flags(tracker_hash_entry_short_zone, Z_WAITOK | Z_ZERO | Z_NOFAIL); \
    if (short_entry == NULL) {                                                                      \
	TRACKER_LOG(LOG_ERR, "Failed to allocate tracker IP entry (Short)");                            \
    } else {                                                                                        \
	entry = (tracker_hash_entry_t *)short_entry;                                                    \
    }                                                                                               \
    } else {                                                                                        \
    entry = zalloc_flags(tracker_hash_entry_zone, Z_WAITOK | Z_ZERO | Z_NOFAIL);                    \
    if (entry == NULL) {                                                                            \
	TRACKER_LOG(LOG_ERR, "Failed to allocate tracker IP entry");                                    \
    }                                                                                               \
    }

#define FREE_ENTRY(entry)                                                                           \
    if (entry) {                                                                                    \
    if (entry->metadata.flags & SO_TRACKER_ATTRIBUTE_FLAGS_DOMAIN_SHORT) {                          \
	zfree(tracker_hash_entry_short_zone, entry);                                                    \
    } else {                                                                                        \
	zfree(tracker_hash_entry_zone, entry);                                                          \
    }                                                                                               \
    }

#define SIZE_OF_ENTRY(entry)                                                                        \
    ((entry && entry->metadata.flags & SO_TRACKER_ATTRIBUTE_FLAGS_DOMAIN_SHORT) ?                   \
	    sizeof(struct tracker_hash_entry_short) : entry ? sizeof(struct tracker_hash_entry) : 0)

#define GET_METADATA_BUFFERS_DST(metadata)                                                          \
    size_t dst_domain_max = 0;                                                                      \
    uint8_t *dst_domain_buffer = NULL;                                                              \
    uint8_t *dst_domain_owner_buffer = NULL;                                                        \
    if (metadata != NULL) {                                                                         \
    if (metadata->flags & SO_TRACKER_ATTRIBUTE_FLAGS_DOMAIN_SHORT) {                                \
	tracker_metadata_short_t *short_metadata = (tracker_metadata_short_t *)metadata;                \
	dst_domain_max = TRACKER_DOMAIN_SHORT_MAX;                                                      \
	dst_domain_buffer = (uint8_t *)(&short_metadata->domain);                                       \
	dst_domain_owner_buffer = (uint8_t *)(&short_metadata->domain_owner);                           \
    } else {                                                                                        \
	dst_domain_max = TRACKER_DOMAIN_MAX;                                                            \
	dst_domain_buffer = (uint8_t *)(&metadata->domain);                                             \
	dst_domain_owner_buffer = (uint8_t *)(&metadata->domain_owner);                                 \
    }                                                                                               \
    }

#define GET_METADATA_BUFFERS_SRC(metadata)                                                          \
    size_t src_domain_max = 0;                                                                      \
    uint8_t *src_domain_buffer = NULL;                                                              \
    uint8_t *src_domain_owner_buffer = NULL;                                                        \
    if (metadata != NULL) {                                                                         \
	if (metadata->flags & SO_TRACKER_ATTRIBUTE_FLAGS_DOMAIN_SHORT) {                                \
tracker_metadata_short_t *short_metadata = (tracker_metadata_short_t *)metadata;                    \
	    src_domain_max = TRACKER_DOMAIN_SHORT_MAX;                                                  \
	    src_domain_buffer = (uint8_t *)(&short_metadata->domain);                                   \
	    src_domain_owner_buffer = (uint8_t *)(&short_metadata->domain_owner);                       \
	} else {                                                                                        \
	    src_domain_max = TRACKER_DOMAIN_MAX;                                                        \
	    src_domain_buffer = (uint8_t *)(&metadata->domain);                                         \
	    src_domain_owner_buffer = (uint8_t *)(&metadata->domain_owner);                             \
	}                                                                                               \
    }

static int
tracker_db_init(void)
{
	tracker_db_log_handle = os_log_create("com.apple.xnu.kern.tracker_db", "tracker_db");

	g_tracker_db.tracker_hashbase = hashinit(TRACKERHASHSIZE, M_TRACKER, &g_tracker_db.tracker_hashmask);
	if (g_tracker_db.tracker_hashbase == NULL) {
		TRACKER_LOG(LOG_ERR, "Failed to initialize");
		return ENOMEM;
	}
	g_tracker_db.tracker_count = 0;

	TRACKER_LOG(LOG_DEBUG, "Initialized: hashsize %d hashmask %lX", TRACKERHASHSIZE, g_tracker_db.tracker_hashmask);

	// Spawn thread for gargage collection
	if (kernel_thread_start(tracker_gc_thread_func, NULL,
	    &g_tracker_gc_thread) != KERN_SUCCESS) {
		panic_plain("%s: Can't create Tracker GC thread", __func__);
		/* NOTREACHED */
	}
	/* this must not fail */
	VERIFY(g_tracker_gc_thread != NULL);

	return 0;
}

static boolean_t
copy_metadata(tracker_metadata_t *dst_metadata, tracker_metadata_t *src_metadata)
{
	bool is_short = false;

	if (dst_metadata == NULL || src_metadata == NULL) {
		return false;
	}

	GET_METADATA_BUFFERS_DST(dst_metadata)
	GET_METADATA_BUFFERS_SRC(src_metadata)
	if (dst_domain_max == 0 || src_domain_max == 0) {
		TRACKER_LOG(LOG_ERR, "Failed to retrieve metadata domain buffers for copy");
		return false;
	}

	size_t src_domain_len = strlen((const char *)src_domain_buffer);
	size_t src_domain_owner_len = strlen((const char *)src_domain_owner_buffer);

	if ((src_domain_len > dst_domain_max) || (src_domain_owner_len > dst_domain_max)) {
		TRACKER_LOG(LOG_ERR, "Failed to copy metadata, dst buffer size too small");
		return false;
	}

	if (src_domain_buffer[0]) {
		size_t dst_domain_len = strlen((const char *)dst_domain_buffer);
		if (dst_domain_len != src_domain_len || strncmp((const char *)dst_domain_buffer, (const char *)src_domain_buffer, src_domain_len)) {
			if (src_domain_len <= dst_domain_max) {
				bcopy(src_domain_buffer, dst_domain_buffer, src_domain_len);
				dst_domain_buffer[src_domain_len] = 0;
			}
		}
	} else {
		dst_domain_buffer[0] = 0;
	}

	if (src_domain_owner_buffer[0]) {
		size_t dst_domain_owner_len = strlen((const char *)dst_domain_owner_buffer);
		if (dst_domain_owner_len != src_domain_owner_len || strncmp((const char *)dst_domain_owner_buffer, (const char *)src_domain_owner_buffer, src_domain_owner_len)) {
			if (src_domain_owner_len <= dst_domain_max) {
				bcopy(src_domain_owner_buffer, dst_domain_owner_buffer, src_domain_owner_len);
				dst_domain_owner_buffer[src_domain_owner_len] = 0;
			}
		}
	} else {
		dst_domain_owner_buffer[0] = 0;
	}

	is_short = (dst_metadata->flags & SO_TRACKER_ATTRIBUTE_FLAGS_DOMAIN_SHORT);
	dst_metadata->flags = src_metadata->flags;
	if (is_short) {
		dst_metadata->flags |= SO_TRACKER_ATTRIBUTE_FLAGS_DOMAIN_SHORT;
	} else {
		dst_metadata->flags &= ~SO_TRACKER_ATTRIBUTE_FLAGS_DOMAIN_SHORT;
	}

	return true;
}

static int
fill_hash_entry(struct tracker_hash_entry *entry, uuid_t appuuid, struct sockaddr *address)
{
	struct sockaddr_in *sin = NULL;
	struct sockaddr_in6 *sin6 = NULL;

	if (uuid_is_null(entry->app_uuid)) {
		if (appuuid == NULL || uuid_is_null(appuuid)) {
			return EINVAL;
		}
		uuid_copy(entry->app_uuid, appuuid);
	}

	if (address == NULL) {
		TRACKER_LOG(LOG_ERR, "Missing remote address");
		return EINVAL;
	}

	entry->lastused = net_uptime();

	switch (address->sa_family) {
	case AF_INET:
		sin = satosin(address);
		if (sin->sin_len < sizeof(*sin)) {
			return EINVAL;
		}
		if (sin->sin_addr.s_addr) {
			entry->address.addr46.ia46_addr4.s_addr = sin->sin_addr.s_addr;
		}
		entry->address_family = AF_INET;
		return 0;
	case AF_INET6:
		sin6 = satosin6(address);
		if (sin6->sin6_len < sizeof(*sin6)) {
			return EINVAL;
		}
		if (!IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr)) {
			entry->address.addr6 = sin6->sin6_addr;
		}
		entry->address_family = AF_INET6;
		return 0;
	default:
		TRACKER_LOG(LOG_ERR, "Invalid address family <%d>", address->sa_family);
		return EINVAL;
	}
}

static inline void
tracker_entry_log(int log_level, char *log_msg, struct tracker_hash_entry *entry, uint32_t hash)
{
	char addr_buffer[MAX_IPv6_STR_LEN + 6];
	const void *addr;

	if (entry == NULL) {
		return;
	}

	switch (entry->address_family) {
	case AF_INET6:
		addr = &entry->address.addr6;
		inet_ntop(AF_INET6, addr, addr_buffer, sizeof(addr_buffer));
		break;
	case AF_INET:
		addr = &entry->address.addr46.ia46_addr4.s_addr;
		inet_ntop(AF_INET, addr, addr_buffer, sizeof(addr_buffer));
		break;
	default:
		return;
	}

	GET_METADATA_BUFFERS_DST((&entry->metadata))

	uint8_t *ptr = (uint8_t *)&entry->app_uuid;
	TRACKER_LOG(log_level, "%s - %s <%s> len %d <%s> len %d <flags %X> %x%x%x%x-%x%x%x%x-%x%x%x%x-%x%x%x%x (hash 0x%X hashsize %d)", log_msg ? log_msg : "n/a",
	    addr_buffer, dst_domain_buffer, (int)strlen((const char *)dst_domain_buffer), dst_domain_owner_buffer, (int)strlen((const char *)dst_domain_owner_buffer),
	    entry->metadata.flags,
	    ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5], ptr[6], ptr[7],
	    ptr[8], ptr[9], ptr[10], ptr[11], ptr[12], ptr[13], ptr[14], ptr[15],
	    hash, TRACKERHASHSIZE);
}

static inline struct tracker_hash_entry *
tracker_search_and_insert(struct tracker_db *db, struct tracker_hash_entry *matchentry, boolean_t insert)
{
	u_int32_t key0 = 0, key1 = 0, key2 = 0, key3 = 0;
	struct trackerhashhead *trackerhash = NULL;
	struct tracker_hash_entry *nextentry = NULL;
	int hash_element = 0;
	int count = 0;

	if (db == NULL || matchentry == NULL) {
		return NULL;
	}

	if (matchentry->address_family == AF_INET6) {
		key0 = matchentry->address.addr6.s6_addr32[0];
		key1 = matchentry->address.addr6.s6_addr32[1];
		key2 = matchentry->address.addr6.s6_addr32[2];
		key3 = matchentry->address.addr6.s6_addr32[3];
	} else {
		key0 = matchentry->address.addr46.ia46_addr4.s_addr;
	}
	hash_element = TRACKER_HASH(&matchentry->app_uuid, &key0, &key1, &key2, &key3) & db->tracker_hashmask;
	trackerhash = &db->tracker_hashbase[hash_element];

	LIST_FOREACH(nextentry, trackerhash, entry_link) {
		count++;

		if (uuid_compare(nextentry->app_uuid, matchentry->app_uuid) != 0) {
			continue;
		}

		if ((nextentry->address_family == AF_INET && matchentry->address_family == AF_INET &&
		    nextentry->address.addr46.ia46_addr4.s_addr == matchentry->address.addr46.ia46_addr4.s_addr) ||
		    (nextentry->address_family == AF_INET6 && matchentry->address_family == AF_INET6 &&
		    IN6_ARE_ADDR_EQUAL(&nextentry->address.addr6, &matchentry->address.addr6))) {
			TRACKER_ENTRY_LOG(LOG_DEBUG, "Matched entry", nextentry, hash_element);
			if (db->max_link_count == 0 || db->max_link_count < count) {
				db->max_link_count = count;
				TRACKER_LOG(LOG_DEBUG, "Max link count %d (hash 0x%X)", db->max_link_count, hash_element);
			}

			// If this is for insert and we found an existing entry, update the metadata if different.
			// Different domain aliases may resolve to the same IP, but we only keep one entry for the same
			// IP address.  Therefore, we update to the last metadata.
			if (insert) {
				if (copy_metadata(&nextentry->metadata, &matchentry->metadata) == true) {
					TRACKER_ENTRY_LOG(LOG_DEBUG, "Updated entry", nextentry, hash_element);
					return nextentry;
				} else {
					// Failed to update found entry, delete it from db and allow insertion of new entry.
					TRACKER_ENTRY_LOG(LOG_ERR, "Failed to Update entry, deleting found entry", nextentry, hash_element);
					g_tracker_db.tracker_count--;
					if (nextentry->metadata.flags & SO_TRACKER_ATTRIBUTE_FLAGS_DOMAIN_SHORT) {
						g_tracker_db.tracker_count_short--;
					}
					LIST_REMOVE(nextentry, entry_link);
					FREE_ENTRY(nextentry);
					break;
				}
			} else {
				return nextentry;
			}
		}
	}
	if (db->max_link_count == 0 || db->max_link_count < count) {
		db->max_link_count = count;
		TRACKER_LOG(LOG_DEBUG, "Max link count %d (hash 0x%X)", db->max_link_count, hash_element);
	}

	// Entry not found, insert it if requested.
	if (insert) {
		LIST_INSERT_HEAD(trackerhash, matchentry, entry_link);

		// Wake gc thread if this is first flow added
		if (db->tracker_count == 0) {
			thread_wakeup((caddr_t)&db->tracker_count);
		}

		db->tracker_count++;
		if (matchentry->metadata.flags & SO_TRACKER_ATTRIBUTE_FLAGS_DOMAIN_SHORT) {
			g_tracker_db.tracker_count_short++;
		}
		TRACKER_ENTRY_LOG(LOG_DEBUG, "Added entry", matchentry, hash_element);
		TRACKER_LOG(LOG_DEBUG, "Total entries %d (hashmask 0x%lX)", db->tracker_count, db->tracker_hashmask);
	}

	return NULL;
}

static int
tracker_retrieve_attribute(u_int8_t *buffer, size_t buffer_length, u_int8_t type, u_int8_t *out_buffer, size_t out_size, size_t out_max_size)
{
	int cursor = 0;
	size_t value_size = 0;
	u_int8_t *value = NULL;

	cursor = necp_buffer_find_tlv(buffer, (u_int32_t)buffer_length, 0, type, NULL, 0);
	if (cursor < 0) {
		TRACKER_LOG(LOG_DEBUG, "No tracker attribute of type %d found in parameters", type);
		return ENOENT;
	}

	value_size = necp_buffer_get_tlv_length(buffer, cursor);
	if (out_size && value_size != out_size) {
		TRACKER_LOG(LOG_ERR, "Wrong size for tracker attribute type %d size %zu <got size %zu>", type, out_size, value_size);
		return EINVAL;
	}
	if (value_size > out_max_size) {
		TRACKER_LOG(LOG_ERR, "Exceeded max size (%zu) - tracker attribute type %d size %zu", out_max_size, type, value_size);
		return EINVAL;
	}

	value = necp_buffer_get_tlv_value(buffer, cursor, NULL);
	if (value == NULL) {
		TRACKER_LOG(LOG_ERR, "Failed to get value for tracker attribute type %d size %zu", type, value_size);
		return EINVAL;
	}

	memcpy(out_buffer, value, value_size);
	return 0;
}

static int
tracker_add(struct proc *p, struct tracker_action_args *uap, int *retval)
{
	uint8_t scratch_pad[TRACKER_SCRATCH_PAD_SIZE] = { };
	struct sockaddr_in6 addrBuffer = { };
	struct sockopt sopt = { };
	struct tracker_hash_entry *entry = NULL;
	struct tracker_db *db = NULL;
	sa_family_t address_family = 0;
	u_int address_size = 0;
	u_int8_t *buffer = scratch_pad;
	size_t buffer_size = 0;
	int error = 0;
	uint32_t flags = 0;

	// Make sure parameter blob is valid
	if (uap->buffer == 0 || uap->buffer_size == 0) {
		*retval = EINVAL;
		return EINVAL;
	}

	// If scratchpad not large enough, allocate memory
	buffer_size = uap->buffer_size;
	if (buffer_size > sizeof(scratch_pad)) {
		if (buffer_size > TRACKER_BUFFER_ALLOC_MAX) {
			TRACKER_LOG(LOG_ERR, "Failed to allocate buffer, size exceeded max allowed");
			*retval = ENOMEM;
			return ENOMEM;
		}
		buffer = (u_int8_t *)kalloc_data(buffer_size, Z_WAITOK | Z_ZERO);
		if (buffer == NULL) {
			*retval = ENOMEM;
			return ENOMEM;
		}
	}
	sopt.sopt_val = uap->buffer;
	sopt.sopt_valsize = uap->buffer_size;
	sopt.sopt_p = p;
	error = sooptcopyin(&sopt, buffer, buffer_size, 0);
	if (error) {
		TRACKER_LOG(LOG_ERR, "Failed to copy parameters");
		goto cleanup;
	}

	// Address Family (Required)
	error = tracker_retrieve_attribute(buffer, buffer_size, SO_TRACKER_ATTRIBUTE_ADDRESS_FAMILY, (u_int8_t *)&address_family, sizeof(address_family), sizeof(address_family));
	if (error) {
		TRACKER_LOG(LOG_ERR, "Could not retrieve address family TLV from parameters");
		goto cleanup;
	}
	if (address_family != AF_INET6 && address_family != AF_INET) {
		error = EINVAL;
		goto cleanup;
	}
	address_size = (address_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);

	// Address (Required)
	error = tracker_retrieve_attribute(buffer, buffer_size, SO_TRACKER_ATTRIBUTE_ADDRESS, (u_int8_t *)&addrBuffer, address_size, address_size);
	if (error) {
		TRACKER_LOG(LOG_ERR, "Could not retrieve address TLV from parameters");
		goto cleanup;
	}
	if (address_family != addrBuffer.sin6_family) {
		TRACKER_LOG(LOG_ERR, "Address family parameter and address parameter family mismatch <%d != %d>",
		    address_family, addrBuffer.sin6_family);
		error = EINVAL;
		goto cleanup;
	}

	// Flags (Optional), so if not present, ignore and proceed.
	error = tracker_retrieve_attribute(buffer, buffer_size, SO_TRACKER_ATTRIBUTE_FLAGS, (u_int8_t *)&flags, sizeof(flags), sizeof(flags));
	if (error == EINVAL) {
		TRACKER_LOG(LOG_INFO, "Could not retrieve flags TLV from parameters");
		goto cleanup;
	}

	ALLOC_ENTRY(flags, entry)
	if (entry == NULL) {
		error = ENOMEM;
		goto cleanup;
	}
	entry->metadata.flags = flags;
	GET_METADATA_BUFFERS_DST((&entry->metadata))

	// APP UUID (Required)
	error = tracker_retrieve_attribute(buffer, buffer_size, SO_TRACKER_ATTRIBUTE_APP_UUID, (u_int8_t *)&entry->app_uuid, sizeof(uuid_t), sizeof(uuid_t));
	if (error) {
		TRACKER_LOG(LOG_ERR, "Could not retrieve APP UUID TLV from parameters");
		error = EINVAL;
		goto cleanup;
	}

	// Domain (Required)
	error = tracker_retrieve_attribute(buffer, buffer_size, SO_TRACKER_ATTRIBUTE_DOMAIN, dst_domain_buffer, 0, dst_domain_max);
	if (error) {
		TRACKER_LOG(LOG_ERR, "Could not retrieve domain TLV from parameters");
		error = EINVAL;
		goto cleanup;
	}

	if (entry->metadata.flags & SO_TRACKER_ATTRIBUTE_FLAGS_TRACKER) {
		// Domain Owner (Required only for tracker flow)
		error = tracker_retrieve_attribute(buffer, buffer_size, SO_TRACKER_ATTRIBUTE_DOMAIN_OWNER, dst_domain_owner_buffer, 0, dst_domain_max);
		if (error) {
			TRACKER_LOG(LOG_ERR, "Could not retrieve domain owner TLV from parameters");
			error = EINVAL;
			goto cleanup;
		}
	}

	if (fill_hash_entry(entry, NULL, (struct sockaddr *)&addrBuffer) != 0) {
		error = EINVAL;
		goto cleanup;
	}

	// If reach here, all required parameter are parsed, clear error.
	error = 0;

	TRACKER_LOCK_EXCLUSIVE

	if (g_tracker_db.tracker_hashbase == NULL) {
		if (tracker_db_init() != 0) {
			error = ENOENT;
			goto done;
		}
	}
	db = &g_tracker_db;

	// Insert if not already in hash.
	if (tracker_search_and_insert(db, entry, true) != NULL) {
		// A match is found, so new entry is not inserted.  Free it.
		FREE_ENTRY(entry);
	}
	entry = NULL;

done:
	TRACKER_UNLOCK_EXCLUSIVE

cleanup:
	if (buffer != scratch_pad) {
		kfree_data(buffer, buffer_size);
	}
	if (error && entry) {
		FREE_ENTRY(entry);
	}

	*retval = error;
	return error;
}

static size_t
tracker_entry_dump_size(struct tracker_hash_entry *entry)
{
	size_t len = 0;
	size_t str_len = 0;

	if (entry == NULL) {
		return 0;
	}

	len += TRACKER_TLV_HDR_LEN + sizeof(entry->address_family);

	switch (entry->address_family) {
	case AF_INET:
		len += TRACKER_TLV_HDR_LEN + sizeof(entry->address.addr46.ia46_addr4.s_addr);
		break;
	case AF_INET6:
		len += TRACKER_TLV_HDR_LEN + sizeof(entry->address.addr6);
		break;
	default:
		TRACKER_LOG(LOG_ERR, "Could not calculate entry dump size - invalid addr family %d",
		    entry->address_family);
		return 0;
	}

	len += TRACKER_TLV_HDR_LEN + sizeof(entry->app_uuid);

	GET_METADATA_BUFFERS_DST((&entry->metadata))
	if (dst_domain_max == 0) {
		TRACKER_LOG(LOG_ERR, "Could not calculate entry dump size - 0 dst_domain_max");
		return 0;
	}

	str_len = strlen((const char *)dst_domain_buffer);
	if (str_len) {
		len += TRACKER_TLV_HDR_LEN + str_len + 1;
	}

	str_len = strlen((const char *)dst_domain_owner_buffer);
	if (str_len) {
		len += TRACKER_TLV_HDR_LEN + str_len + 1;
	}

	if (entry->metadata.flags) {
		len += TRACKER_TLV_HDR_LEN + sizeof(entry->metadata.flags);
	}

	return len;
}

static size_t
tracker_entry_dump(struct tracker_hash_entry *entry, uint8_t *buffer, size_t buffer_size)
{
	u_int8_t *cursor = buffer;
	size_t str_len = 0;

	if (entry == NULL) {
		return 0;
	}
	cursor = necp_buffer_write_tlv(cursor, SO_TRACKER_ATTRIBUTE_APP_UUID, (u_int32_t)sizeof(entry->app_uuid), &entry->app_uuid, buffer, (u_int32_t)buffer_size);
	cursor = necp_buffer_write_tlv(cursor, SO_TRACKER_ATTRIBUTE_ADDRESS_FAMILY, (u_int32_t)sizeof(entry->address_family), &entry->address_family, buffer, (u_int32_t)buffer_size);

	switch (entry->address_family) {
	case AF_INET:
		cursor = necp_buffer_write_tlv(cursor, SO_TRACKER_ATTRIBUTE_ADDRESS,
		    (u_int32_t)sizeof(entry->address.addr46.ia46_addr4.s_addr), &entry->address.addr46.ia46_addr4.s_addr, buffer, (u_int32_t)buffer_size);
		break;
	case AF_INET6:
		cursor = necp_buffer_write_tlv(cursor, SO_TRACKER_ATTRIBUTE_ADDRESS, (u_int32_t)sizeof(entry->address.addr6), &entry->address.addr6, buffer, (u_int32_t)buffer_size);
		break;
	default:
		TRACKER_LOG(LOG_ERR, "Could not dump entry - invalid addr family %d",
		    entry->address_family);
		return 0;
	}

	if (entry->metadata.flags) {
		cursor = necp_buffer_write_tlv(cursor, SO_TRACKER_ATTRIBUTE_FLAGS, (u_int32_t)sizeof(entry->metadata.flags), &entry->metadata.flags, buffer, (u_int32_t)buffer_size);
	}

	GET_METADATA_BUFFERS_DST((&entry->metadata))
	if (dst_domain_max == 0) {
		TRACKER_LOG(LOG_ERR, "Could not dump entry - 0 dst_domain_max");
		return 0;
	}

	str_len = strlen((const char *)dst_domain_buffer);
	TRACKER_LOG(LOG_DEBUG, "Dumping domain <%s> len <%zu>", dst_domain_buffer, str_len);
	if (str_len) {
		str_len++;
		cursor = necp_buffer_write_tlv(cursor, SO_TRACKER_ATTRIBUTE_DOMAIN, (u_int32_t)str_len, dst_domain_buffer, buffer, (u_int32_t)buffer_size);
	}

	str_len = strlen((const char *)dst_domain_owner_buffer);
	TRACKER_LOG(LOG_DEBUG, "Dumping domain owner <%s> len <%zu>", dst_domain_owner_buffer, str_len);
	if (str_len) {
		str_len++;
		cursor = necp_buffer_write_tlv(cursor, SO_TRACKER_ATTRIBUTE_DOMAIN_OWNER, (u_int32_t)str_len, dst_domain_owner_buffer, buffer, (u_int32_t)buffer_size);
	}

	return cursor - buffer;
}

static int
tracker_dump(struct proc *p, struct tracker_action_args *uap, int *retval, bool by_app)
{
#pragma unused(p)
	uint8_t app_uuid_tlv[TRACKER_TLV_HDR_LEN + sizeof(uuid_t)] = { };
	struct sockopt sopt = { };
	struct tracker_hash_entry *entry = NULL;
	struct tracker_hash_entry *temp_entry = NULL;
	struct trackerhashhead *hash = NULL;
	uint8_t *buffer = scratch_pad_all;
	size_t buffer_size = sizeof(scratch_pad_all);
	uint8_t *data_start = NULL;
	uint8_t *cursor = NULL;
	size_t entry_tlv_size = 0;
	size_t total_mem_size = 0;
	size_t total_size_needed = 0;
	size_t total_size = 0;
	int error = 0;
	uuid_t app_uuid;
	bool has_app_uuid = false;

	if (uap->buffer == 0 || uap->buffer_size == 0) {
		TRACKER_LOG(LOG_ERR, "Could not dump entries, null output buffer");
		*retval = EINVAL;
		return EINVAL;
	}

	if (by_app) {
		// Expect a UUID TLV
		sopt.sopt_val = uap->buffer;
		sopt.sopt_valsize = sizeof(app_uuid_tlv);
		sopt.sopt_p = p;
		if (sooptcopyin(&sopt, app_uuid_tlv, sizeof(app_uuid_tlv), sizeof(app_uuid_tlv)) == 0) {
			if (tracker_retrieve_attribute(app_uuid_tlv, sizeof(app_uuid_tlv), SO_TRACKER_ATTRIBUTE_APP_UUID, (u_int8_t *)&app_uuid, sizeof(app_uuid), sizeof(app_uuid)) == 0) {
				has_app_uuid = true;
			}
		}
	}

	TRACKER_LOCK_EXCLUSIVE

	if (g_tracker_db.tracker_hashbase == NULL || g_tracker_db.tracker_count == 0) {
		error = ENOENT;
		goto done;
	}

	for (int i = 0; i < TRACKERHASHSIZE; i++) {
		hash = &g_tracker_db.tracker_hashbase[i];

		LIST_FOREACH_SAFE(entry, hash, entry_link, temp_entry) {
			if (has_app_uuid && uuid_compare(entry->app_uuid, app_uuid) != 0) {
				continue;
			}

			entry_tlv_size = tracker_entry_dump_size(entry);
			if (entry_tlv_size) {
				entry_tlv_size += TRACKER_TLV_HDR_LEN;
				if (os_add_overflow(total_size_needed, entry_tlv_size, &total_size_needed)) {
					TRACKER_LOG(LOG_ERR, "Could not dump entries, failed to calculate total size needed");
					error = EINVAL;
					goto done;
				}
			}
		}
	}

	// Add space for memory usage TLV
	if (os_add_overflow(total_size_needed, TRACKER_TLV_HDR_LEN + sizeof(total_mem_size), &total_size_needed)) {
		TRACKER_LOG(LOG_ERR, "Could not dump entries, failed to calculate total size needed for memory used)");
		error = EINVAL;
		goto done;
	}

	// pre-append 4-bytes size to start of buffer.
	if (total_size_needed + sizeof(uint32_t) > uap->buffer_size) {
		TRACKER_LOG(LOG_ERR, "Could not dump entries, output buffer too small %lu (needed %lu)",
		    (unsigned long)uap->buffer_size, total_size_needed + sizeof(uint32_t));
		error = EINVAL;
		goto done;
	}

	// total tlv length + 4-bytes total size.
	if (total_size_needed + sizeof(uint32_t) > sizeof(scratch_pad_all)) {
		if (total_size_needed + sizeof(uint32_t) > TRACKER_BUFFER_ALLOC_MAX) {
			TRACKER_LOG(LOG_ERR, "Failed to allocate buffer, size exceeded max allowed");
			error = ENOMEM;
			goto done;
		}
		buffer = (u_int8_t *)kalloc_data(total_size_needed + sizeof(uint32_t), Z_ZERO);
		if (buffer == NULL) {
			TRACKER_LOG(LOG_ERR, "Could not dump entries, failed to allocate buffer");
			error = ENOMEM;
			goto done;
		}
		buffer_size = total_size_needed + sizeof(uint32_t);
	}

	data_start = buffer + sizeof(uint32_t);
	cursor = data_start;
	for (int i = 0; i < TRACKERHASHSIZE; i++) {
		hash = &g_tracker_db.tracker_hashbase[i];

		LIST_FOREACH_SAFE(entry, hash, entry_link, temp_entry) {
			if (has_app_uuid && uuid_compare(entry->app_uuid, app_uuid) != 0) {
				continue;
			}

			entry_tlv_size = tracker_entry_dump(entry, scratch_pad_entry, sizeof(scratch_pad_entry));
			if (entry_tlv_size <= 0) {
				TRACKER_LOG(LOG_ERR, "Could not dump entry, exceeded entry tlv buffer size");
				continue;
			} else {
				TRACKER_ENTRY_LOG(LOG_DEBUG, "Dumped entry", entry, 0);
			}
			cursor = necp_buffer_write_tlv(cursor, SO_TRACKER_ATTRIBUTE_DUMP_ENTRY, (u_int32_t)entry_tlv_size, scratch_pad_entry, data_start, (u_int32_t)(buffer_size - sizeof(uint32_t)));

			if (os_add_overflow(total_mem_size, SIZE_OF_ENTRY(entry), &total_mem_size)) {
				TRACKER_LOG(LOG_ERR, "Could not dump entries, failed to calculate total memory used");
				error = EINVAL;
				goto done;
			}
			TRACKER_LOG(LOG_DEBUG, "Total memory size %zu", total_mem_size);
		}
	}

	cursor = necp_buffer_write_tlv(cursor, SO_TRACKER_ATTRIBUTE_MEMORY_USED, sizeof(total_mem_size), &total_mem_size, data_start, (u_int32_t)(buffer_size - sizeof(uint32_t)));

	// Fill in the total length at the start
	total_size = cursor - data_start;
	memcpy(buffer, (uint8_t *)&total_size, sizeof(uint32_t));

	error = copyout(buffer, uap->buffer, total_size + sizeof(u_int32_t));
	if (error) {
		TRACKER_LOG(LOG_DEBUG, "Failed to copy out dump buffer (%lu bytes)", total_size + sizeof(u_int32_t));
	}

done:
	TRACKER_UNLOCK_EXCLUSIVE

	if (buffer != scratch_pad_all) {
		kfree_data(buffer, buffer_size);
	}
	*retval = error;
	return error;
}

int
tracker_action(struct proc *p, struct tracker_action_args *uap, int *retval)
{
	const task_t task = proc_task(p);
	if (task == NULL || !IOTaskHasEntitlement(task, "com.apple.private.ip-domain-table")) {
		TRACKER_LOG(LOG_ERR, "Process (%d) does not hold the necessary entitlement", proc_pid(p));
		*retval = EPERM;
		return EPERM;
	}

	switch (uap->action) {
	case SO_TRACKER_ACTION_ADD:
		return tracker_add(p, uap, retval);
	case SO_TRACKER_ACTION_DUMP_BY_APP:
		return tracker_dump(p, uap, retval, true);
	case SO_TRACKER_ACTION_DUMP_ALL:
		return tracker_dump(p, uap, retval, false);
	default:
		break;
	}
	return 0;
}

int
tracker_lookup(uuid_t app_uuid, struct sockaddr *remote, tracker_metadata_t *metadata)
{
	struct tracker_hash_entry matchentry = { };
	struct tracker_hash_entry *foundentry = NULL;
	struct tracker_db *db = NULL;
	int error = 0;

	if (remote == NULL || uuid_is_null(app_uuid)) {
		TRACKER_LOG(LOG_DEBUG, "Failed lookup - remote %s null, app_uuid %s null",
		    remote ? "is not" : "is", !uuid_is_null(app_uuid) ? "is not" : "is");
		return EINVAL;
	}

	TRACKER_LOCK_SHARED

	if (g_tracker_db.tracker_hashbase == NULL || g_tracker_db.tracker_count == 0) {
		error = ENOENT;
		goto done;
	}
	db = &g_tracker_db;

	if (fill_hash_entry(&matchentry, app_uuid, remote) != 0) {
		error = EINVAL;
		goto done;
	}

	TRACKER_ENTRY_LOG(LOG_DEBUG, "Lookup entry", &matchentry, 0);

	foundentry = tracker_search_and_insert(db, &matchentry, false);
	if (foundentry) {
		if (metadata) {
			if (copy_metadata(metadata, &foundentry->metadata) == false) {
				TRACKER_ENTRY_LOG(LOG_ERR, "Failed to copy metadata", &matchentry, 0);
				error = ENOENT;
			}
		}
		foundentry->lastused = net_uptime();
	}

done:
	TRACKER_UNLOCK_SHARED
	return error;
}

static void
tracker_gc_thread_sleep(bool forever)
{
	if (forever) {
		(void) assert_wait((event_t) &g_tracker_db.tracker_count,
		    THREAD_INTERRUPTIBLE);
	} else {
		uint64_t deadline = 0;
		nanoseconds_to_absolutetime(TRACKER_GC_RUN_INTERVAL_NSEC, &deadline);
		clock_absolutetime_interval_to_deadline(deadline, &deadline);

		(void) assert_wait_deadline(&g_tracker_db.tracker_count,
		    THREAD_INTERRUPTIBLE, deadline);
	}
}

static void
tracker_gc_thread_func(void *v, wait_result_t w)
{
#pragma unused(v, w)

	ASSERT(g_tracker_gc_thread == current_thread());
	thread_set_thread_name(current_thread(), "TRACKER_GC");

	// Kick off gc shortly
	tracker_gc_thread_sleep(false);
	thread_block_parameter((thread_continue_t) tracker_entry_expire, NULL);
	/* NOTREACHED */
}

static bool
tracker_idle_timed_out(struct tracker_hash_entry *entry, u_int64_t timeout, u_int64_t current_time)
{
	if (entry && (current_time - entry->lastused >= timeout)) {
		return true;
	}
	return false;
}

static void
tracker_entry_expire(void *v, wait_result_t w)
{
#pragma unused (v, w)
	struct tracker_hash_entry *entry = NULL;
	struct tracker_hash_entry *temp_entry = NULL;
	struct trackerhashhead *hash = NULL;

	u_int64_t current_time = net_uptime();
	int deleted_count = 0;
	int remaining_count = 0;

	for (int i = 0; i < TRACKERHASHSIZE; i++) {
		TRACKER_LOCK_EXCLUSIVE

		if (g_tracker_db.tracker_hashbase == NULL || g_tracker_db.tracker_count == 0) {
			TRACKER_UNLOCK_EXCLUSIVE
			goto go_sleep;
		}
		hash = &g_tracker_db.tracker_hashbase[i];

		LIST_FOREACH_SAFE(entry, hash, entry_link, temp_entry) {
			if (tracker_idle_timed_out(entry, tracker_db_idle_timeout, current_time)) {
				TRACKER_ENTRY_LOG(LOG_DEBUG, "Deleting entry - IDLE TO", entry, i);
				g_tracker_db.tracker_count--;
				if (entry->metadata.flags & SO_TRACKER_ATTRIBUTE_FLAGS_DOMAIN_SHORT) {
					g_tracker_db.tracker_count_short--;
				}
				LIST_REMOVE(entry, entry_link);
				FREE_ENTRY(entry);
				deleted_count++;
			}
		}

		remaining_count = g_tracker_db.tracker_count;
		TRACKER_UNLOCK_EXCLUSIVE
	}

go_sleep:

	TRACKER_LOG(LOG_DEBUG, "Garbage Collection done...(deleted %d - total count %d)", deleted_count, remaining_count);

	// Sleep forever (until waken up) if no more UDP flow to clean
	TRACKER_LOCK_SHARED
	tracker_gc_thread_sleep(g_tracker_db.tracker_count == 0 ? true : false);
	TRACKER_UNLOCK_SHARED
	thread_block_parameter((thread_continue_t)tracker_entry_expire, NULL);
	/* NOTREACHED */
}
